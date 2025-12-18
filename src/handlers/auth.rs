use actix_web::{get, post, put, web, HttpRequest, HttpResponse};
use serde::Serialize;

use crate::errors::AppError;
use crate::models::{
    AuthResponse, ChangePasswordRequest, ForgotPasswordRequest, LoginRequest, RefreshRequest,
    RegisterRequest, ResetPasswordRequest, TokenResponse, TwoFactorRequiredResponse, UserResponse,
};
use crate::services::{AuthService, LockoutService, RateLimiters, ResetService, TokenService};
use crate::utils::validate_request;

fn get_client_ip(req: &HttpRequest) -> String {
    req.connection_info()
        .realip_remote_addr()
        .unwrap_or("unknown")
        .to_string()
}

async fn check_rate_limit(
    rate_limiters: &RateLimiters,
    key: &str,
    limit_type: &str,
) -> Result<(), AppError> {
    let result = match limit_type {
        "login" => rate_limiters.login.check_rate_limit(key).await?,
        "registration" => rate_limiters.registration.check_rate_limit(key).await?,
        "password_reset" => rate_limiters.password_reset.check_rate_limit(key).await?,
        _ => rate_limiters.general.check_rate_limit(key).await?,
    };

    if result.is_limited {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let retry_after = result.reset_at.saturating_sub(now);

        return Err(AppError::TooManyRequests {
            retry_after,
            message: format!(
                "Too many {} attempts. Please try again in {} seconds.",
                limit_type, retry_after
            ),
        });
    }

    Ok(())
}

#[derive(Serialize)]
struct MessageResponse {
    status: String,
    message: String,
}

#[post("/register")]
pub async fn register(
    req: HttpRequest,
    auth_service: web::Data<AuthService>,
    token_service: web::Data<TokenService>,
    rate_limiters: web::Data<RateLimiters>,
    body: web::Json<RegisterRequest>,
) -> Result<HttpResponse, AppError> {
    // Check rate limit by IP
    let client_ip = get_client_ip(&req);
    check_rate_limit(&rate_limiters, &client_ip, "registration").await?;

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
    req: HttpRequest,
    auth_service: web::Data<AuthService>,
    token_service: web::Data<TokenService>,
    rate_limiters: web::Data<RateLimiters>,
    lockout_service: web::Data<LockoutService>,
    body: web::Json<LoginRequest>,
) -> Result<HttpResponse, AppError> {
    // Check rate limit by IP + email combination
    let client_ip = get_client_ip(&req);
    let rate_key = format!("{}:{}", client_ip, body.email);
    check_rate_limit(&rate_limiters, &rate_key, "login").await?;

    // Check if account is locked
    let lockout_status = lockout_service.check_lockout(&body.email).await?;
    if lockout_status.is_locked {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let locked_until = lockout_status.locked_until.unwrap_or(now);
        let seconds_remaining = locked_until.saturating_sub(now);

        return Err(AppError::AccountLocked {
            locked_until,
            message: format!(
                "Account is temporarily locked due to multiple failed login attempts. Please try again in {} minutes.",
                (seconds_remaining / 60) + 1
            ),
        });
    }

    // Validate request
    validate_request(&body.0)?;

    // Login user
    let login_result = auth_service.login(body.0.clone()).await;

    match login_result {
        Ok(user) => {
            // Clear failed attempts on successful login
            lockout_service.clear_failed_attempts(&body.email).await?;

            // Check if 2FA is enabled
            if user.totp_enabled {
                // Generate temporary token for 2FA verification
                let temp_token = token_service.generate_temp_token(user.id, &user.email, &user.role)?;

                return Ok(HttpResponse::Ok().json(TwoFactorRequiredResponse {
                    status: "2fa_required".to_string(),
                    requires_2fa: true,
                    temp_token,
                    message: "Please verify with your authenticator app".to_string(),
                }));
            }

            // Generate tokens (no 2FA)
            let access_token = token_service.generate_access_token(user.id, &user.email, &user.role)?;
            let refresh_tok = token_service.generate_refresh_token(user.id, &user.email, &user.role)?;

            Ok(HttpResponse::Ok().json(AuthResponse {
                status: "success".to_string(),
                access_token,
                refresh_token: refresh_tok,
                user: UserResponse::from(user),
            }))
        }
        Err(e) => {
            // Record failed attempt for auth errors
            if matches!(e, AppError::Unauthorized(_)) {
                let lockout_status = lockout_service.record_failed_attempt(&body.email).await?;

                if lockout_status.is_locked {
                    let locked_until = lockout_status.locked_until.unwrap_or(0);
                    return Err(AppError::AccountLocked {
                        locked_until,
                        message: "Account has been locked due to multiple failed login attempts. Please try again later.".to_string(),
                    });
                }

                // Add remaining attempts to error message
                return Err(AppError::Unauthorized(format!(
                    "Invalid email or password. {} attempts remaining.",
                    lockout_status.remaining_attempts
                )));
            }
            Err(e)
        }
    }
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
    req: HttpRequest,
    auth_service: web::Data<AuthService>,
    reset_service: web::Data<ResetService>,
    rate_limiters: web::Data<RateLimiters>,
    body: web::Json<ForgotPasswordRequest>,
) -> Result<HttpResponse, AppError> {
    // Check rate limit by IP
    let client_ip = get_client_ip(&req);
    check_rate_limit(&rate_limiters, &client_ip, "password_reset").await?;

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
    req: HttpRequest,
    auth_service: web::Data<AuthService>,
    reset_service: web::Data<ResetService>,
    rate_limiters: web::Data<RateLimiters>,
    body: web::Json<ResetPasswordRequest>,
) -> Result<HttpResponse, AppError> {
    // Check rate limit by IP
    let client_ip = get_client_ip(&req);
    check_rate_limit(&rate_limiters, &client_ip, "password_reset").await?;

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
