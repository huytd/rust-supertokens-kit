use auth::{initialize_jwks_keystore, UserPayload, AUTHORIZED_USER_HEADER};
use axum::{
    http::{HeaderMap, StatusCode},
    middleware,
    response::IntoResponse,
    routing, Json, Router,
};
use serde_json::json;
use std::net::SocketAddr;

mod auth;

async fn user_profile_handler(headers: HeaderMap) -> Result<impl IntoResponse, StatusCode> {
    let sub = headers[AUTHORIZED_USER_HEADER]
        .to_str()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(Json::from(json!({ "sub": sub })))
}

async fn user_onboarding_handler(
    headers: HeaderMap,
    Json(payload): Json<UserPayload>,
) -> Result<impl IntoResponse, StatusCode> {
    let sub = headers[AUTHORIZED_USER_HEADER]
        .to_str()
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    Ok(Json::from(json!({
        "sub": sub,
        "registeredId": payload.id,
        "registeredEmail": payload.email
    })))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    initialize_jwks_keystore().await;

    let app = Router::new()
        .route("/user/me", routing::get(user_profile_handler))
        .route("/user/onboarding", routing::post(user_onboarding_handler))
        .route_layer(middleware::from_fn(auth::verify_session));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3001));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
