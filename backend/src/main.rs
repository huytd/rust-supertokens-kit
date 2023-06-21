use auth::initialize_jwks_keystore;
use axum::{
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing, Router,
};
use std::net::SocketAddr;

mod auth;

async fn hello_handler() -> impl IntoResponse {
    "OK"
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenv::dotenv().ok();

    initialize_jwks_keystore().await;

    let app = Router::new()
        .route("/hello", routing::get(hello_handler))
        .route_layer(middleware::from_fn(auth::verify_session));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3001));
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
