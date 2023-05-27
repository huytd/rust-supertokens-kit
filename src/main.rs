use axum::{extract::FromRef, Router};
use axum_sessions::async_session::CookieStore;
use sqlx::{Pool, Postgres};
use std::net::SocketAddr;
use tower_http::services::ServeDir;

mod auth;

pub type DbPool = Pool<Postgres>;

#[derive(Clone)]
pub struct ServerState {
    session_store: CookieStore,
    db_pool: DbPool,
}

impl FromRef<ServerState> for DbPool {
    fn from_ref(input: &ServerState) -> Self {
        input.db_pool.clone()
    }
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
        .nest("/auth", auth::router())
        .nest_service("/", ServeDir::new("public"))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3030));
    tracing::debug!("listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}
