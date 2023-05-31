use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts, Query, State},
    headers::Cookie,
    http::{header, request::Parts, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
    routing, Json, RequestPartsExt, Router, TypedHeader,
};
use axum_sessions::async_session::{Session, SessionStore};
use cookie::{time::OffsetDateTime, CookieBuilder};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Duration};
use uuid::Uuid;

use crate::{DbPool, ServerState};

#[derive(Debug, Deserialize)]
struct UserPasswordRequest {
    email: String,
    password: String,
    #[serde(default)]
    name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfo {
    id: Uuid,
    google_id: String,
    email: String,
    name: String,
    picture: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserSession {
    id: Uuid,
    user_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenValidationResponse {
    access_token: String,
    id_token: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct GoogleUserInfo {
    id: String,
    email: String,
    verified_email: bool,
    name: String,
    picture: String,
}

#[async_trait]
impl<S> FromRequestParts<S> for UserSession
where
    DbPool: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let db_pool = DbPool::from_ref(state);
        let cookies = parts
            .extract::<TypedHeader<Cookie>>()
            .await
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        let session_id = cookies
            .get("USER_SESSION")
            .ok_or(StatusCode::UNAUTHORIZED)?;
        let session = sqlx::query!(
            "SELECT * FROM sessions WHERE id = $1 AND expires_at > NOW()",
            Uuid::parse_str(session_id).unwrap()
        )
        .fetch_optional(&db_pool)
        .await
        .unwrap()
        .ok_or(StatusCode::UNAUTHORIZED)?;
        Ok(UserSession {
            id: session.id,
            user_id: session.user_id,
        })
    }
}

#[async_trait]
impl<S> FromRequestParts<S> for UserInfo
where
    DbPool: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session =
            <UserSession as FromRequestParts<S>>::from_request_parts(parts, state).await?;
        let db_pool = DbPool::from_ref(state);
        let user_info = sqlx::query!("SELECT * FROM users WHERE id = $1", session.user_id)
            .fetch_one(&db_pool)
            .await
            .unwrap();

        Ok(UserInfo {
            id: user_info.id,
            google_id: user_info.google_id.unwrap_or(String::new()),
            name: user_info.name.unwrap_or(String::new()),
            picture: user_info.picture.unwrap_or(String::new()),
            email: user_info.email.unwrap_or(String::new()),
        })
    }
}

async fn google_login_handler(State(state): State<ServerState>) -> impl IntoResponse {
    // Step 1: Generate a random CRSF token, store it to the session storage
    let security_token: String = Uuid::new_v4().to_string();
    let mut auth_session = Session::new();
    auth_session.expire_in(Duration::from_secs(5 * 60));
    auth_session.insert("security_token", &security_token).ok();
    let cookie_value = state
        .session_store
        .store_session(auth_session)
        .await
        .unwrap()
        .unwrap();
    let mut headers = HeaderMap::new();
    let auth_session_cookie = CookieBuilder::new("AUTH_SESSION", cookie_value)
        .path("/")
        .expires(OffsetDateTime::now_utc() + Duration::from_secs(5 * 60))
        .finish();

    headers.insert(
        header::SET_COOKIE,
        auth_session_cookie.to_string().parse().unwrap(),
    );

    // Step 2: Construct login URL
    let url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&response_type=code&redirect_uri=http://localhost:3030/auth/google/callback&scope=https://www.googleapis.com/auth/userinfo.email%20https://www.googleapis.com/auth/userinfo.profile%20openid&state={}",
        std::env::var("GOOGLE_CLIENT_ID").unwrap(),
        security_token,
    );

    // Step 3: Redirect
    (headers, Redirect::to(&url))
}

async fn google_callback_handler(
    Query(param): Query<HashMap<String, String>>,
    State(state): State<ServerState>,
    TypedHeader(cookie): TypedHeader<Cookie>,
) -> impl IntoResponse {
    // Step 1: Load the security token from the session storage
    let auth_session_cookie = cookie.get("AUTH_SESSION").unwrap();
    let auth_session = state
        .session_store
        .load_session(auth_session_cookie.to_string())
        .await
        .unwrap()
        .unwrap();
    let security_token = auth_session.get::<String>("security_token").unwrap();

    // Step 2: Validate the security token
    if param.get("state").unwrap() != &security_token {
        return (StatusCode::UNAUTHORIZED, "Invalid security token").into_response();
    }

    // Step 3: Validate the authorization code
    let validate = reqwest::Client::new()
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", param.get("code").unwrap().as_str()),
            (
                "client_id",
                std::env::var("GOOGLE_CLIENT_ID").unwrap().as_str(),
            ),
            (
                "client_secret",
                std::env::var("GOOGLE_CLIENT_SECRET").unwrap().as_str(),
            ),
            ("redirect_uri", "http://localhost:3030/auth/google/callback"),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await
        .unwrap();

    if !validate.status().is_success() {
        return (StatusCode::UNAUTHORIZED, "Cannot validate token").into_response();
    }

    let validation_response: TokenValidationResponse =
        serde_json::from_str(&validate.text().await.unwrap()).unwrap();

    // Step 4: Get user information
    let info = reqwest::Client::new()
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(validation_response.access_token)
        .send()
        .await
        .unwrap();

    if !info.status().is_success() {
        return (StatusCode::UNAUTHORIZED, "Cannot get user info").into_response();
    }

    let user_info: GoogleUserInfo = serde_json::from_str(&info.text().await.unwrap()).unwrap();

    let user = sqlx::query!(
        "SELECT * FROM users WHERE email = $1 AND google_id = $2",
        user_info.email,
        user_info.id
    )
    .fetch_optional(&state.db_pool)
    .await
    .unwrap();

    let user_id = if user.is_none() {
        let row = sqlx::query!(
            "INSERT INTO users (email, google_id, name, picture) 
             VALUES ($1, $2, $3, $4)
             RETURNING id",
            user_info.email,
            user_info.id,
            user_info.name,
            user_info.picture
        )
        .fetch_one(&state.db_pool)
        .await
        .unwrap();
        row.id
    } else {
        user.unwrap().id
    };

    let mut response = Redirect::to("/").into_response();

    // Check for existing session
    let session = sqlx::query!(
        "SELECT * FROM sessions WHERE user_id = $1 AND expires_at > NOW()",
        user_id
    )
    .fetch_optional(&state.db_pool)
    .await
    .unwrap();

    let session_id = if session.is_some() {
        // Existing valid session found, reuse it
        let session = session.unwrap();
        session.id.to_string()
    } else {
        // No valid session, create a new one
        let session_id = sqlx::query!(
            "INSERT INTO sessions (user_id, expires_at) 
             VALUES ($1, NOW() + INTERVAL '7 days')
             RETURNING id",
            user_id
        )
        .fetch_one(&state.db_pool)
        .await
        .unwrap()
        .id;
        session_id.to_string()
    };

    let user_session_cookie = CookieBuilder::new("USER_SESSION", session_id)
        .path("/")
        .expires(OffsetDateTime::now_utc() + Duration::from_secs(7 * 24 * 60 * 60))
        .http_only(true)
        .secure(true)
        .same_site(cookie::SameSite::Strict)
        .finish();
    response.headers_mut().insert(
        header::SET_COOKIE,
        user_session_cookie.to_string().parse().unwrap(),
    );

    response
}

async fn logout_handler(
    State(state): State<ServerState>,
    session: UserSession,
) -> impl IntoResponse {
    let _ = sqlx::query!(
        "UPDATE sessions SET expires_at = NOW() WHERE id = $1",
        session.id
    )
    .execute(&state.db_pool)
    .await;

    println!("Redirect");
    let mut response = Redirect::to("/").into_response();
    let delete_user_session_cookie = CookieBuilder::new("USER_SESSION", "")
        .path("/")
        .expires(OffsetDateTime::now_utc() + Duration::from_secs(0))
        .finish();
    response.headers_mut().insert(
        header::SET_COOKIE,
        delete_user_session_cookie.to_string().parse().unwrap(),
    );
    response
}

async fn user_info_handler(user_info: UserInfo) -> impl IntoResponse {
    Json(user_info)
}

async fn validate_user_password_request(payload: &UserPasswordRequest) -> Result<(), StatusCode> {
    if payload.email.is_empty() || payload.password.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(())
}

fn create_password_hasher() -> Result<Argon2<'static>, StatusCode> {
    let pepper = env!("BASE_SECRET_KEY");
    let argon2 = Argon2::new_with_secret(
        pepper.as_bytes(),
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::default(),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(argon2)
}

async fn register_handler(
    State(state): State<ServerState>,
    Json(payload): Json<UserPasswordRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    validate_user_password_request(&payload).await?;

    // Step 1: Check if the user already exists
    let user_count = sqlx::query!("SELECT count(*) FROM users WHERE email = $1", payload.email)
        .fetch_one(&state.db_pool)
        .await
        .unwrap()
        .count
        .unwrap_or(0);
    if user_count != 0 {
        return Err(StatusCode::BAD_REQUEST);
    }
    // Step 2: Hash the password
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = create_password_hasher()?;
    let hash = argon2
        .hash_password(payload.password.as_bytes(), &salt)
        .unwrap();
    // Step 3: Save the user to database
    let _ = sqlx::query!(
        "INSERT INTO users (email, password_hash, name) VALUES ($1, $2, $3)",
        payload.email,
        hash.to_string(),
        payload.name,
    )
    .execute(&state.db_pool)
    .await
    .unwrap();
    Ok(StatusCode::CREATED)
}

async fn login_handler(
    State(state): State<ServerState>,
    Json(payload): Json<UserPasswordRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    validate_user_password_request(&payload).await?;

    let user_record = sqlx::query!("SELECT * FROM users WHERE email = $1", payload.email)
        .fetch_one(&state.db_pool)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let user_password = user_record.password_hash.unwrap_or(String::new());
    let stored_hash = PasswordHash::new(&user_password).map_err(|_| StatusCode::UNAUTHORIZED)?;
    let argon2 = create_password_hasher()?;
    if argon2
        .verify_password(payload.password.as_bytes(), &stored_hash)
        .is_err()
    {
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(StatusCode::OK)
}

// TODO: Password reset flow

pub fn router() -> Router<ServerState> {
    Router::new()
        .route("/me", routing::get(user_info_handler))
        .route("/register", routing::post(register_handler))
        .route("/login", routing::post(login_handler))
        .route("/google/login", routing::get(google_login_handler))
        .route("/google/callback", routing::get(google_callback_handler))
        .route("/logout", routing::get(logout_handler))
}
