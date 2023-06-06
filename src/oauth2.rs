use axum::http::StatusCode;
use serde_derive::{Deserialize, Serialize};
use std::fmt::Display;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleUser {
    pub id: String,
    pub name: String,
    pub email: String,
    pub picture: String,
}

#[derive(Debug)]
pub enum GoogleOAuth2Error {
    UserNotFound,
    TokenValidationFailed,
    RequestFailed,
}

impl From<GoogleOAuth2Error> for StatusCode {
    fn from(error: GoogleOAuth2Error) -> Self {
        match error {
            GoogleOAuth2Error::UserNotFound => StatusCode::UNAUTHORIZED,
            GoogleOAuth2Error::TokenValidationFailed => StatusCode::BAD_REQUEST,
            GoogleOAuth2Error::RequestFailed => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl Display for GoogleOAuth2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserNotFound => write!(f, "User not found"),
            Self::TokenValidationFailed => write!(f, "Token validation failed"),
            Self::RequestFailed => write!(f, "Request failed"),
        }
    }
}

#[derive(Debug, Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
}

pub struct GoogleOAuth2Config {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

impl GoogleOAuth2Config {
    pub fn new(client_id: String, client_secret: String, redirect_uri: String) -> Self {
        Self {
            client_id,
            client_secret,
            redirect_uri,
        }
    }
}

pub fn authorize_url(config: &GoogleOAuth2Config, security_token: &str) -> String {
    let scopes = [
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile",
        "openid",
    ];
    format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
        config.client_id,
        config.redirect_uri,
        scopes.join("%20"),
        security_token
    )
}

pub async fn get_access_token(
    config: &GoogleOAuth2Config,
    code: &str,
) -> Result<String, GoogleOAuth2Error> {
    let params = [
        ("code", code),
        ("client_id", config.client_id.as_str()),
        ("client_secret", config.client_secret.as_str()),
        ("redirect_uri", config.redirect_uri.as_str()),
        ("grant_type", "authorization_code"),
    ];
    let token = reqwest::Client::new()
        .post("https://oauth2.googleapis.com/token")
        .form(&params)
        .send()
        .await
        .map_err(|_| GoogleOAuth2Error::RequestFailed)?
        .json::<OAuthTokenResponse>()
        .await
        .map_err(|_| GoogleOAuth2Error::TokenValidationFailed)?;
    Ok(token.access_token)
}

pub async fn get_user_info(access_token: &str) -> Result<GoogleUser, GoogleOAuth2Error> {
    let user = reqwest::Client::new()
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|_| GoogleOAuth2Error::RequestFailed)?
        .json::<GoogleUser>()
        .await
        .map_err(|_| GoogleOAuth2Error::UserNotFound)?;
    Ok(user)
}
