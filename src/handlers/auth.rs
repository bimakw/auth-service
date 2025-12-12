use actix_web::{get, post, put, web, HttpRequest, HttpResponse};
use serde::Serialize;

use crate::errors::AppError;
use crate::models::{
    AuthResponse, ChangePasswordRequest, ForgotPasswordRequest, LoginRequest, RefreshRequest,
    RegisterRequest, ResetPasswordRequest, TokenResponse, UserResponse,
};
use crate::services::{AuthService, ResetService, TokenService};
use crate::utils::validate_request;

#[derive(Serialize)]
struct MessageResponse {
    status: String,
    message: String,
}

#[post("/register")]
pub async fn register(
    auth_service: web::Data<AuthService>,
    token_service: web::Data<TokenService>,
    body: web::Json<RegisterRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate request
    validate_request(&body.0)?;

    // Register user
    let user = auth_service.register(body.into_inner()).await?;

    // Generate tokens
    let access_token = token_service.generate_access_token(user.id, &user.email, &user.role)?;
    let refresh_tok = token_service.generate_refresh_token(user.id, &user.email, &user.role)?;

    Ok(HttpResponse::Created().json(AuthResponse {
        status: "success".to_string(),
        access_token,
        refresh_token: refresh_tok,
        user: UserResponse::from(user),
    }))
}

#[post("/login")]
pub async fn login(
    auth_service: web::Data<AuthService>,
    token_service: web::Data<TokenService>,
    body: web::Json<LoginRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate request
    validate_request(&body.0)?;

    // Login user
    let user = auth_service.login(body.into_inner()).await?;

    // Generate tokens
    let access_token = token_service.generate_access_token(user.id, &user.email, &user.role)?;
    let refresh_tok = token_service.generate_refresh_token(user.id, &user.email, &user.role)?;

    Ok(HttpResponse::Ok().json(AuthResponse {
        status: "success".to_string(),
        access_token,
        refresh_token: refresh_tok,
        user: UserResponse::from(user),
    }))
}

#[post("/refresh")]
pub async fn refresh_token(
    token_service: web::Data<TokenService>,
    auth_service: web::Data<AuthService>,
    body: web::Json<RefreshRequest>,
) -> Result<HttpResponse, AppError> {
    // Verify refresh token
    let claims = token_service.verify_refresh_token(&body.refresh_token)?;

    // Get user to ensure they still exist
    let user_id = token_service.extract_user_id(&claims)?;
    let user = auth_service.get_user_by_id(user_id).await?;

    // Generate new access token
    let access_token = token_service.generate_access_token(user.id, &user.email, &user.role)?;

    Ok(HttpResponse::Ok().json(TokenResponse {
        status: "success".to_string(),
        access_token,
    }))
}

#[get("/me")]
pub async fn get_me(
    req: HttpRequest,
    auth_service: web::Data<AuthService>,
    token_service: web::Data<TokenService>,
) -> Result<HttpResponse, AppError> {
    // Extract token from Authorization header
    let token = extract_token(&req)?;

    // Verify token
    let claims = token_service.verify_access_token(&token)?;
    let user_id = token_service.extract_user_id(&claims)?;

    // Get user
    let user = auth_service.get_user_by_id(user_id).await?;

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "user": UserResponse::from(user)
    })))
}

#[post("/logout")]
pub async fn logout(req: HttpRequest) -> Result<HttpResponse, AppError> {
    // Extract token from Authorization header
    let _token = extract_token(&req)?;

    // In a production app, you would blacklist the token in Redis here
    // For now, we just return success (client should delete the token)

    Ok(HttpResponse::Ok().json(MessageResponse {
        status: "success".to_string(),
        message: "Logged out successfully".to_string(),
    }))
}

#[put("/change-password")]
pub async fn change_password(
    req: HttpRequest,
    auth_service: web::Data<AuthService>,
    token_service: web::Data<TokenService>,
    body: web::Json<ChangePasswordRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate request
    validate_request(&body.0)?;

    // Extract token
    let token = extract_token(&req)?;

    // Verify token
    let claims = token_service.verify_access_token(&token)?;
    let user_id = token_service.extract_user_id(&claims)?;

    // Change password
    auth_service
        .change_password(user_id, &body.current_password, &body.new_password)
        .await?;

    Ok(HttpResponse::Ok().json(MessageResponse {
        status: "success".to_string(),
        message: "Password changed successfully".to_string(),
    }))
}

#[post("/forgot-password")]
pub async fn forgot_password(
    auth_service: web::Data<AuthService>,
    reset_service: web::Data<ResetService>,
    body: web::Json<ForgotPasswordRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate request
    validate_request(&body.0)?;

    // Check if user exists
    let user = auth_service.get_user_by_email(&body.email).await?;

    if user.is_some() {
        // Generate reset token
        let token = reset_service.create_reset_token(&body.email).await?;

        // In production, send email with reset link
        // For now, log the token (remove in production!)
        tracing::info!("Password reset token for {}: {}", body.email, token);
    }

    // Always return success to prevent email enumeration
    Ok(HttpResponse::Ok().json(MessageResponse {
        status: "success".to_string(),
        message: "If an account with that email exists, a password reset link has been sent".to_string(),
    }))
}

#[post("/reset-password")]
pub async fn reset_password(
    auth_service: web::Data<AuthService>,
    reset_service: web::Data<ResetService>,
    body: web::Json<ResetPasswordRequest>,
) -> Result<HttpResponse, AppError> {
    // Validate request
    validate_request(&body.0)?;

    // Validate token and get email
    let email = reset_service.validate_reset_token(&body.token).await?;

    // Reset the password
    auth_service.reset_password(&email, &body.new_password).await?;

    // Invalidate the token
    reset_service.invalidate_reset_token(&body.token).await?;

    Ok(HttpResponse::Ok().json(MessageResponse {
        status: "success".to_string(),
        message: "Password has been reset successfully".to_string(),
    }))
}

fn extract_token(req: &HttpRequest) -> Result<String, AppError> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .ok_or_else(|| AppError::Unauthorized("Missing Authorization header".to_string()))?
        .to_str()
        .map_err(|_| AppError::Unauthorized("Invalid Authorization header".to_string()))?;

    if !auth_header.starts_with("Bearer ") {
        return Err(AppError::Unauthorized(
            "Invalid Authorization header format".to_string(),
        ));
    }

    Ok(auth_header[7..].to_string())
}

pub fn auth_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/auth")
            .service(register)
            .service(login)
            .service(refresh_token)
            .service(get_me)
            .service(logout)
            .service(change_password)
            .service(forgot_password)
            .service(reset_password),
    );
}
