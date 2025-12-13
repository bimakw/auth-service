use actix_web::{get, post, web, HttpRequest, HttpResponse};

use crate::errors::AppError;
use crate::models::{
    BackupCodesResponse, MessageResponse, TOTPDisableRequest, TOTPLoginVerifyRequest,
    TOTPSetupResponse, TOTPVerifyRequest, AuthResponse, UserResponse,
};
use crate::services::{AuthService, TOTPService, TokenService};
use crate::utils::{password::verify_password, validate_request};

/// Start 2FA setup - generates secret and QR code
#[post("/setup")]
pub async fn setup_totp(
    req: HttpRequest,
    auth_service: web::Data<AuthService>,
    totp_service: web::Data<TOTPService>,
    token_service: web::Data<TokenService>,
) -> Result<HttpResponse, AppError> {
    let token = extract_token(&req)?;
    let claims = token_service.verify_access_token(&token)?;
    let user_id = token_service.extract_user_id(&claims)?;

    let user = auth_service.get_user_by_id(user_id).await?;

    if user.totp_enabled {
        return Err(AppError::BadRequest("2FA is already enabled".to_string()));
    }

    // Generate new secret
    let secret = totp_service.generate_secret()?;

    // Store secret temporarily (not enabled yet)
    totp_service.store_temp_secret(user_id, &secret).await?;

    // Generate QR code
    let qr_code = totp_service.generate_qr_code(&user.email, &secret)?;

    Ok(HttpResponse::Ok().json(TOTPSetupResponse {
        status: "success".to_string(),
        secret,
        qr_code: format!("data:image/png;base64,{}", qr_code),
        message: "Scan the QR code with your authenticator app, then verify with a code".to_string(),
    }))
}

/// Verify setup - confirms 2FA with initial code
#[post("/verify-setup")]
pub async fn verify_setup(
    req: HttpRequest,
    auth_service: web::Data<AuthService>,
    totp_service: web::Data<TOTPService>,
    token_service: web::Data<TokenService>,
    body: web::Json<TOTPVerifyRequest>,
) -> Result<HttpResponse, AppError> {
    validate_request(&body.0)?;

    let token = extract_token(&req)?;
    let claims = token_service.verify_access_token(&token)?;
    let user_id = token_service.extract_user_id(&claims)?;

    let user = auth_service.get_user_by_id(user_id).await?;

    if user.totp_enabled {
        return Err(AppError::BadRequest("2FA is already enabled".to_string()));
    }

    // Get stored secret
    let secret = totp_service
        .get_user_secret(user_id)
        .await?
        .ok_or_else(|| AppError::BadRequest("Please start 2FA setup first".to_string()))?;

    // Verify the code
    if !totp_service.verify_code(&secret, &body.code)? {
        return Err(AppError::Unauthorized("Invalid verification code".to_string()));
    }

    // Enable TOTP
    totp_service.enable_totp(user_id, &secret).await?;

    // Generate backup codes
    let backup_codes = totp_service.generate_backup_codes(user_id).await?;

    Ok(HttpResponse::Ok().json(BackupCodesResponse {
        status: "success".to_string(),
        backup_codes,
        message: "2FA enabled successfully. Save these backup codes in a safe place.".to_string(),
    }))
}

/// Verify TOTP code during login (for users with 2FA enabled)
#[post("/verify")]
pub async fn verify_totp_login(
    auth_service: web::Data<AuthService>,
    totp_service: web::Data<TOTPService>,
    token_service: web::Data<TokenService>,
    body: web::Json<TOTPLoginVerifyRequest>,
) -> Result<HttpResponse, AppError> {
    validate_request(&body.0)?;

    // Verify temp token
    let claims = token_service.verify_temp_token(&body.temp_token)?;
    let user_id = token_service.extract_user_id(&claims)?;

    let user = auth_service.get_user_by_id(user_id).await?;

    if !user.totp_enabled {
        return Err(AppError::BadRequest("2FA is not enabled for this account".to_string()));
    }

    let secret = user
        .totp_secret
        .as_ref()
        .ok_or_else(|| AppError::InternalServerError("TOTP secret not found".to_string()))?;

    // Try TOTP code first
    let is_valid = if body.code.len() == 6 {
        totp_service.verify_code(secret, &body.code)?
    } else {
        // Try backup code
        totp_service.verify_backup_code(user_id, &body.code).await?
    };

    if !is_valid {
        return Err(AppError::Unauthorized("Invalid verification code".to_string()));
    }

    // Generate full tokens
    let access_token = token_service.generate_access_token(user.id, &user.email, &user.role)?;
    let refresh_token = token_service.generate_refresh_token(user.id, &user.email, &user.role)?;

    Ok(HttpResponse::Ok().json(AuthResponse {
        status: "success".to_string(),
        access_token,
        refresh_token,
        user: UserResponse::from(user),
    }))
}

/// Get 2FA status
#[get("/status")]
pub async fn get_totp_status(
    req: HttpRequest,
    auth_service: web::Data<AuthService>,
    totp_service: web::Data<TOTPService>,
    token_service: web::Data<TokenService>,
) -> Result<HttpResponse, AppError> {
    let token = extract_token(&req)?;
    let claims = token_service.verify_access_token(&token)?;
    let user_id = token_service.extract_user_id(&claims)?;

    let user = auth_service.get_user_by_id(user_id).await?;
    let remaining_codes = if user.totp_enabled {
        totp_service.get_remaining_backup_codes(user_id).await?
    } else {
        0
    };

    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "success",
        "totp_enabled": user.totp_enabled,
        "remaining_backup_codes": remaining_codes
    })))
}

/// Disable 2FA
#[post("/disable")]
pub async fn disable_totp(
    req: HttpRequest,
    auth_service: web::Data<AuthService>,
    totp_service: web::Data<TOTPService>,
    token_service: web::Data<TokenService>,
    body: web::Json<TOTPDisableRequest>,
) -> Result<HttpResponse, AppError> {
    validate_request(&body.0)?;

    let token = extract_token(&req)?;
    let claims = token_service.verify_access_token(&token)?;
    let user_id = token_service.extract_user_id(&claims)?;

    let user = auth_service.get_user_by_id(user_id).await?;

    if !user.totp_enabled {
        return Err(AppError::BadRequest("2FA is not enabled".to_string()));
    }

    // Verify password
    let password_hash = user
        .password_hash
        .as_ref()
        .ok_or_else(|| AppError::BadRequest("Cannot disable 2FA for OAuth-only account".to_string()))?;

    if !verify_password(&body.password, password_hash)? {
        return Err(AppError::Unauthorized("Invalid password".to_string()));
    }

    // Verify TOTP code
    let secret = user
        .totp_secret
        .as_ref()
        .ok_or_else(|| AppError::InternalServerError("TOTP secret not found".to_string()))?;

    if !totp_service.verify_code(secret, &body.code)? {
        return Err(AppError::Unauthorized("Invalid verification code".to_string()));
    }

    // Disable TOTP
    totp_service.disable_totp(user_id).await?;

    Ok(HttpResponse::Ok().json(MessageResponse {
        status: "success".to_string(),
        message: "2FA has been disabled".to_string(),
    }))
}

/// Regenerate backup codes
#[post("/backup-codes")]
pub async fn regenerate_backup_codes(
    req: HttpRequest,
    auth_service: web::Data<AuthService>,
    totp_service: web::Data<TOTPService>,
    token_service: web::Data<TokenService>,
    body: web::Json<TOTPVerifyRequest>,
) -> Result<HttpResponse, AppError> {
    validate_request(&body.0)?;

    let token = extract_token(&req)?;
    let claims = token_service.verify_access_token(&token)?;
    let user_id = token_service.extract_user_id(&claims)?;

    let user = auth_service.get_user_by_id(user_id).await?;

    if !user.totp_enabled {
        return Err(AppError::BadRequest("2FA is not enabled".to_string()));
    }

    // Verify TOTP code
    let secret = user
        .totp_secret
        .as_ref()
        .ok_or_else(|| AppError::InternalServerError("TOTP secret not found".to_string()))?;

    if !totp_service.verify_code(secret, &body.code)? {
        return Err(AppError::Unauthorized("Invalid verification code".to_string()));
    }

    // Generate new backup codes
    let backup_codes = totp_service.generate_backup_codes(user_id).await?;

    Ok(HttpResponse::Ok().json(BackupCodesResponse {
        status: "success".to_string(),
        backup_codes,
        message: "New backup codes generated. Previous codes are now invalid.".to_string(),
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

pub fn totp_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/auth/totp")
            .service(setup_totp)
            .service(verify_setup)
            .service(verify_totp_login)
            .service(get_totp_status)
            .service(disable_totp)
            .service(regenerate_backup_codes),
    );
}
