use std::sync::OnceLock;

use axum::http::{header, HeaderValue};
use axum::{
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use jwksclient2::keyset::KeyStore;
use serde_derive::Deserialize;

const JWKS_URL: &'static str = "http://0.0.0.0:3000/api/auth/jwt/jwks.json";
static JWKS_KEYSTORE: OnceLock<KeyStore> = OnceLock::new();

pub static AUTHORIZED_USER_HEADER: &str = "X-Authorized-User";

#[derive(Deserialize)]
pub struct UserPayload {
    pub email: String,
    pub id: String,
}

pub async fn initialize_jwks_keystore() {
    let key_store = KeyStore::new_from(JWKS_URL.to_owned())
        .await
        .expect("Could not get JWKS!");
    JWKS_KEYSTORE
        .set(key_store)
        .ok()
        .expect("Could not initialize JWKS Store!");
}

pub async fn verify_session<B>(mut req: Request<B>, next: Next<B>) -> Result<Response, StatusCode> {
    let auth_token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|header| header.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?
        .replace("Bearer ", "");
    let keystore = JWKS_KEYSTORE
        .get()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    let claim = keystore
        .verify(&auth_token)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let sub = claim.payload().sub().ok_or(StatusCode::UNAUTHORIZED)?;
    req.headers_mut().insert(
        AUTHORIZED_USER_HEADER,
        HeaderValue::from_str(sub).map_err(|_| StatusCode::UNAUTHORIZED)?,
    );
    Ok(next.run(req).await)
}
