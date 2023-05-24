use axum::{
    async_trait,
    extract::{FromRef, FromRequestParts, Query, State},
    headers::Cookie,
    http::{header, request::Parts, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect},
    routing, Json, RequestPartsExt, Router, TypedHeader,
};
use axum_sessions::async_session::{CookieStore, Session, SessionStore};
use cookie::{time::OffsetDateTime, CookieBuilder};
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use std::{collections::HashMap, net::SocketAddr, time::Duration};
use uuid::Uuid;

type DbPool = Pool<Postgres>;

#[derive(Clone)]
struct ServerState {
    session_store: CookieStore,
    db_pool: DbPool,
}

impl FromRef<ServerState> for DbPool {
    fn from_ref(input: &ServerState) -> Self {
        input.db_pool.clone()
    }
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

#[derive(Debug, Serialize, Deserialize)]
struct UserInfo {
    id: Uuid,
    google_id: String,
    email: String,
    name: String,
    picture: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UserSession {
    id: Uuid,
    user_id: Uuid,
}

#[tokio::main]
async fn main() {
    dotenv::dotenv().ok();
    tracing_subscriber::fmt::init();

    let db_pool = sqlx::postgres::PgPool::connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();

    let state = ServerState {
        session_store: CookieStore::new(),
        db_pool,
    };

    let app = Router::new()
        .route("/", routing::get(index_handler))
        .route("/auth/me", routing::get(auth_user_info_handler))
        .route("/auth/google/login", routing::get(auth_login_handler))
        .route("/auth/google/callback", routing::get(auth_callback_handler))
        .route("/auth/logout", routing::get(auth_logout_handler))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3030));
    tracing::debug!("listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
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

async fn index_handler() -> impl IntoResponse {
    "Status: OK"
}

async fn auth_login_handler(State(state): State<ServerState>) -> impl IntoResponse {
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

async fn auth_callback_handler(
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

async fn auth_logout_handler(
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

async fn auth_user_info_handler(user_info: UserInfo) -> impl IntoResponse {
    println!("User {:?}", user_info);
    Json(user_info)
}
