use std::{net::SocketAddr, sync::OnceLock, collections::HashMap};
use axum::{response::{IntoResponse, Redirect}, routing, Router, http::StatusCode, extract::Query, Json, extract::Extension};
use oauth2::GoogleOAuth2Config;
use token::{create_token_store, SharedTokenStore};

mod oauth2;
mod token;

static OAUTH2_CONFIG: OnceLock<GoogleOAuth2Config> = OnceLock::new();

async fn google_login_handler(Extension(token_store): Extension<SharedTokenStore>) -> impl IntoResponse {
    let secret = token::generate_token(64);
    token_store.lock().await.create_token(&secret, std::time::Duration::from_secs(60)).ok();

    match OAUTH2_CONFIG.get() {
        Some(config) => Redirect::to(&oauth2::authorize_url(config, &secret)).into_response(),
        None => StatusCode::INTERNAL_SERVER_ERROR.into_response()
    }
}

async fn google_callback_handler(
    Query(param): Query<HashMap<String, String>>,
    Extension(token_store): Extension<SharedTokenStore>
) -> Result<impl IntoResponse, StatusCode> {
    let secret = param.get("state").unwrap();
    let code = param.get("code").unwrap();

    if !token_store.lock().await.validate_token(secret) {
        return Err(StatusCode::NOT_ACCEPTABLE);
    }

    let token = oauth2::get_access_token(&OAUTH2_CONFIG.get().unwrap(), code)
        .await?;
    let user = oauth2::get_user_info(&token).await?;

    return Ok(Json(user));
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    OAUTH2_CONFIG
        .set(GoogleOAuth2Config::new(
            std::env::var("GOOGLE_CLIENT_ID").unwrap(),
            std::env::var("GOOGLE_CLIENT_SECRET").unwrap(),
            std::env::var("GOOGLE_REDIRECT_URI").unwrap(),
        ))
        .ok();

    let app = Router::new()
        .route("/auth/google/login", routing::get(google_login_handler))
        .route(
            "/auth/google/callback",
            routing::get(google_callback_handler),
        )
        .layer(Extension(create_token_store()));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3030));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
