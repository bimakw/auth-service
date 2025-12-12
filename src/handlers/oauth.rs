use actix_web::{get, web, HttpResponse};
use oauth2::{
    basic::BasicClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use serde::Deserialize;

use crate::config::Config;
use crate::errors::AppError;
use crate::services::{AuthService, TokenService};

#[derive(Debug, Deserialize)]
pub struct GoogleCallbackQuery {
    pub code: String,
    pub state: String,
}

#[derive(Debug, Deserialize)]
pub struct GoogleUserInfo {
    pub id: String,
    pub email: String,
    pub name: String,
    pub picture: Option<String>,
}

fn create_oauth_client(config: &Config) -> Result<BasicClient, AppError> {
    let client = BasicClient::new(
        ClientId::new(config.google_client_id.clone()),
        Some(ClientSecret::new(config.google_client_secret.clone())),
        AuthUrl::new("https://accounts.google.com/o/oauth2/v2/auth".to_string())
            .map_err(|e| AppError::InternalServerError(format!("Invalid auth URL: {}", e)))?,
        Some(
            TokenUrl::new("https://oauth2.googleapis.com/token".to_string())
                .map_err(|e| AppError::InternalServerError(format!("Invalid token URL: {}", e)))?,
        ),
    )
    .set_redirect_uri(
        RedirectUrl::new(config.google_redirect_url.clone())
            .map_err(|e| AppError::InternalServerError(format!("Invalid redirect URL: {}", e)))?,
    );

    Ok(client)
}

#[get("/google")]
pub async fn google_login(config: web::Data<Config>) -> Result<HttpResponse, AppError> {
    let client = create_oauth_client(&config)?;

    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .url();

    Ok(HttpResponse::Found()
        .append_header(("Location", auth_url.to_string()))
        .finish())
}

#[get("/google/callback")]
pub async fn google_callback(
    query: web::Query<GoogleCallbackQuery>,
    config: web::Data<Config>,
    auth_service: web::Data<AuthService>,
    token_service: web::Data<TokenService>,
) -> Result<HttpResponse, AppError> {
    let client = create_oauth_client(&config)?;

    // Exchange code for token
    let token_result = client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(oauth2::reqwest::async_http_client)
        .await
        .map_err(|e| {
            tracing::error!("Failed to exchange code: {:?}", e);
            AppError::InternalServerError("Failed to exchange authorization code".to_string())
        })?;

    let access_token = token_result.access_token().secret();

    // Get user info from Google
    let http_client = reqwest::Client::new();
    let user_info: GoogleUserInfo = http_client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| {
            tracing::error!("Failed to get user info: {:?}", e);
            AppError::InternalServerError("Failed to get user information".to_string())
        })?
        .json()
        .await
        .map_err(|e| {
            tracing::error!("Failed to parse user info: {:?}", e);
            AppError::InternalServerError("Failed to parse user information".to_string())
        })?;

    // Get or create user
    let user = auth_service
        .get_or_create_google_user(&user_info.id, &user_info.email, &user_info.name)
        .await?;

    // Generate tokens
    let jwt_access_token = token_service.generate_access_token(user.id, &user.email, &user.role)?;
    let jwt_refresh_token =
        token_service.generate_refresh_token(user.id, &user.email, &user.role)?;

    // Redirect to frontend with tokens (in production, use a more secure method)
    let redirect_url = format!(
        "{}?access_token={}&refresh_token={}",
        config.frontend_url, jwt_access_token, jwt_refresh_token
    );

    Ok(HttpResponse::Found()
        .append_header(("Location", redirect_url))
        .finish())
}

pub fn oauth_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/api/oauth").service(google_login).service(google_callback));
}
