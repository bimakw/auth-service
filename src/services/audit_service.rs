use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    LoginSuccess,
    LoginFailed,
    Logout,
    Register,
    PasswordChange,
    PasswordResetRequest,
    PasswordResetComplete,
    TotpEnable,
    TotpDisable,
    TotpVerify,
    OauthGoogleLogin,
    OauthGithubLogin,
    AccountLocked,
    TokenRefresh,
}

impl AuditEventType {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditEventType::LoginSuccess => "login_success",
            AuditEventType::LoginFailed => "login_failed",
            AuditEventType::Logout => "logout",
            AuditEventType::Register => "register",
            AuditEventType::PasswordChange => "password_change",
            AuditEventType::PasswordResetRequest => "password_reset_request",
            AuditEventType::PasswordResetComplete => "password_reset_complete",
            AuditEventType::TotpEnable => "totp_enable",
            AuditEventType::TotpDisable => "totp_disable",
            AuditEventType::TotpVerify => "totp_verify",
            AuditEventType::OauthGoogleLogin => "oauth_google_login",
            AuditEventType::OauthGithubLogin => "oauth_github_login",
            AuditEventType::AccountLocked => "account_locked",
            AuditEventType::TokenRefresh => "token_refresh",
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditContext {
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Clone)]
pub struct AuditService {
    pool: PgPool,
}

impl AuditService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn log_event(
        &self,
        user_id: Option<Uuid>,
        event_type: AuditEventType,
        context: &AuditContext,
        details: Option<JsonValue>,
        success: bool,
    ) -> Result<(), AppError> {
        sqlx::query(
            r#"
            INSERT INTO audit_logs (user_id, event_type, ip_address, user_agent, details, success)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(user_id)
        .bind(event_type.as_str())
        .bind(&context.ip_address)
        .bind(&context.user_agent)
        .bind(&details)
        .bind(success)
        .execute(&self.pool)
        .await?;

        // Log to tracing as well for real-time monitoring
        if success {
            tracing::info!(
                event = event_type.as_str(),
                user_id = ?user_id,
                ip = ?context.ip_address,
                "Audit event logged"
            );
        } else {
            tracing::warn!(
                event = event_type.as_str(),
                user_id = ?user_id,
                ip = ?context.ip_address,
                "Failed audit event logged"
            );
        }

        Ok(())
    }

    /// Convenience method for successful events
    pub async fn log_success(
        &self,
        user_id: Option<Uuid>,
        event_type: AuditEventType,
        context: &AuditContext,
        details: Option<JsonValue>,
    ) -> Result<(), AppError> {
        self.log_event(user_id, event_type, context, details, true)
            .await
    }

    /// Convenience method for failed events
    pub async fn log_failure(
        &self,
        user_id: Option<Uuid>,
        event_type: AuditEventType,
        context: &AuditContext,
        details: Option<JsonValue>,
    ) -> Result<(), AppError> {
        self.log_event(user_id, event_type, context, details, false)
            .await
    }

    /// Log login success
    pub async fn log_login_success(
        &self,
        user_id: Uuid,
        context: &AuditContext,
    ) -> Result<(), AppError> {
        self.log_success(Some(user_id), AuditEventType::LoginSuccess, context, None)
            .await
    }

    /// Log login failure
    pub async fn log_login_failed(
        &self,
        email: &str,
        context: &AuditContext,
        reason: &str,
    ) -> Result<(), AppError> {
        let details = serde_json::json!({
            "email": email,
            "reason": reason
        });
        self.log_failure(None, AuditEventType::LoginFailed, context, Some(details))
            .await
    }

    /// Log account lockout
    pub async fn log_account_locked(
        &self,
        email: &str,
        context: &AuditContext,
    ) -> Result<(), AppError> {
        let details = serde_json::json!({
            "email": email
        });
        self.log_failure(None, AuditEventType::AccountLocked, context, Some(details))
            .await
    }

    /// Log registration
    pub async fn log_registration(
        &self,
        user_id: Uuid,
        email: &str,
        context: &AuditContext,
    ) -> Result<(), AppError> {
        let details = serde_json::json!({
            "email": email
        });
        self.log_success(Some(user_id), AuditEventType::Register, context, Some(details))
            .await
    }

    /// Log OAuth login
    pub async fn log_oauth_login(
        &self,
        user_id: Uuid,
        provider: &str,
        context: &AuditContext,
    ) -> Result<(), AppError> {
        let event_type = match provider {
            "google" => AuditEventType::OauthGoogleLogin,
            "github" => AuditEventType::OauthGithubLogin,
            _ => return Ok(()), // Unknown provider, skip logging
        };
        self.log_success(Some(user_id), event_type, context, None)
            .await
    }

    /// Log password change
    pub async fn log_password_change(
        &self,
        user_id: Uuid,
        context: &AuditContext,
    ) -> Result<(), AppError> {
        self.log_success(Some(user_id), AuditEventType::PasswordChange, context, None)
            .await
    }

    /// Log password reset request
    pub async fn log_password_reset_request(
        &self,
        email: &str,
        context: &AuditContext,
    ) -> Result<(), AppError> {
        let details = serde_json::json!({
            "email": email
        });
        self.log_success(None, AuditEventType::PasswordResetRequest, context, Some(details))
            .await
    }

    /// Log password reset complete
    pub async fn log_password_reset_complete(
        &self,
        user_id: Uuid,
        context: &AuditContext,
    ) -> Result<(), AppError> {
        self.log_success(Some(user_id), AuditEventType::PasswordResetComplete, context, None)
            .await
    }

    /// Log TOTP enable
    pub async fn log_totp_enable(
        &self,
        user_id: Uuid,
        context: &AuditContext,
    ) -> Result<(), AppError> {
        self.log_success(Some(user_id), AuditEventType::TotpEnable, context, None)
            .await
    }

    /// Log TOTP disable
    pub async fn log_totp_disable(
        &self,
        user_id: Uuid,
        context: &AuditContext,
    ) -> Result<(), AppError> {
        self.log_success(Some(user_id), AuditEventType::TotpDisable, context, None)
            .await
    }

    /// Log TOTP verification
    pub async fn log_totp_verify(
        &self,
        user_id: Uuid,
        success: bool,
        context: &AuditContext,
    ) -> Result<(), AppError> {
        self.log_event(Some(user_id), AuditEventType::TotpVerify, context, None, success)
            .await
    }

    /// Log logout
    pub async fn log_logout(
        &self,
        user_id: Uuid,
        context: &AuditContext,
    ) -> Result<(), AppError> {
        self.log_success(Some(user_id), AuditEventType::Logout, context, None)
            .await
    }

    /// Log token refresh
    pub async fn log_token_refresh(
        &self,
        user_id: Uuid,
        context: &AuditContext,
    ) -> Result<(), AppError> {
        self.log_success(Some(user_id), AuditEventType::TokenRefresh, context, None)
            .await
    }
}
