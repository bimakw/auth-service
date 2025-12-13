use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Serialize)]
pub struct TOTPSetupResponse {
    pub status: String,
    pub secret: String,
    pub qr_code: String,
    pub message: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct TOTPVerifyRequest {
    #[validate(length(equal = 6, message = "TOTP code must be 6 digits"))]
    pub code: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct TOTPLoginVerifyRequest {
    pub temp_token: String,
    #[validate(length(min = 6, max = 8, message = "Code must be 6-8 characters"))]
    pub code: String,
}

#[derive(Debug, Deserialize, Validate)]
pub struct TOTPDisableRequest {
    #[validate(length(min = 1, message = "Password is required"))]
    pub password: String,
    #[validate(length(equal = 6, message = "TOTP code must be 6 digits"))]
    pub code: String,
}

#[derive(Debug, Serialize)]
pub struct TOTPStatusResponse {
    pub status: String,
    pub totp_enabled: bool,
}

#[derive(Debug, Serialize)]
pub struct BackupCodesResponse {
    pub status: String,
    pub backup_codes: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone, FromRow)]
pub struct TOTPBackupCode {
    pub id: Uuid,
    pub user_id: Uuid,
    pub code_hash: String,
    pub used: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub status: String,
    pub message: String,
}
