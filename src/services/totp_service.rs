use rand::Rng;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use totp_rs::{Algorithm, Secret, TOTP};
use uuid::Uuid;

use crate::config::Config;
use crate::errors::AppError;
use crate::models::TOTPBackupCode;

const BACKUP_CODE_COUNT: usize = 10;
const BACKUP_CODE_LENGTH: usize = 8;

pub struct TOTPService {
    pool: PgPool,
    config: Config,
}

impl TOTPService {
    pub fn new(pool: PgPool, config: Config) -> Self {
        Self { pool, config }
    }

    /// Generate a new TOTP secret
    pub fn generate_secret(&self) -> Result<String, AppError> {
        let secret = Secret::generate_secret();
        Ok(secret.to_encoded().to_string())
    }

    /// Generate QR code data URL for authenticator apps
    pub fn generate_qr_code(&self, email: &str, secret: &str) -> Result<String, AppError> {
        let totp = self.create_totp(email, secret)?;

        totp.get_qr_base64()
            .map_err(|e| AppError::InternalServerError(format!("Failed to generate QR code: {}", e)))
    }

    /// Verify a TOTP code
    pub fn verify_code(&self, secret: &str, code: &str) -> Result<bool, AppError> {
        // Create a temporary TOTP instance for verification
        let secret_bytes = Secret::Encoded(secret.to_string())
            .to_bytes()
            .map_err(|e| AppError::InternalServerError(format!("Invalid secret: {}", e)))?;

        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            Some(self.config.totp_issuer.clone()),
            "user".to_string(),
        ).map_err(|e| AppError::InternalServerError(format!("Failed to create TOTP: {}", e)))?;

        Ok(totp.check_current(code).unwrap_or(false))
    }

    /// Enable TOTP for a user (save secret and set enabled flag)
    pub async fn enable_totp(&self, user_id: Uuid, secret: &str) -> Result<(), AppError> {
        sqlx::query(
            r#"
            UPDATE users
            SET totp_secret = $1, totp_enabled = true, updated_at = NOW()
            WHERE id = $2
            "#
        )
        .bind(secret)
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        tracing::info!("TOTP enabled for user: {}", user_id);
        Ok(())
    }

    /// Disable TOTP for a user
    pub async fn disable_totp(&self, user_id: Uuid) -> Result<(), AppError> {
        // Start transaction to disable TOTP and delete backup codes
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            r#"
            UPDATE users
            SET totp_secret = NULL, totp_enabled = false, updated_at = NOW()
            WHERE id = $1
            "#
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        // Delete all backup codes
        sqlx::query("DELETE FROM totp_backup_codes WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;

        tracing::info!("TOTP disabled for user: {}", user_id);
        Ok(())
    }

    /// Generate backup codes for a user
    pub async fn generate_backup_codes(&self, user_id: Uuid) -> Result<Vec<String>, AppError> {
        // Delete existing backup codes
        sqlx::query("DELETE FROM totp_backup_codes WHERE user_id = $1")
            .bind(user_id)
            .execute(&self.pool)
            .await?;

        let mut codes = Vec::with_capacity(BACKUP_CODE_COUNT);

        for _ in 0..BACKUP_CODE_COUNT {
            let code = self.generate_random_code();
            let code_hash = self.hash_code(&code);

            sqlx::query(
                r#"
                INSERT INTO totp_backup_codes (user_id, code_hash)
                VALUES ($1, $2)
                "#
            )
            .bind(user_id)
            .bind(&code_hash)
            .execute(&self.pool)
            .await?;

            codes.push(code);
        }

        tracing::info!("Generated {} backup codes for user: {}", BACKUP_CODE_COUNT, user_id);
        Ok(codes)
    }

    /// Verify and consume a backup code
    pub async fn verify_backup_code(&self, user_id: Uuid, code: &str) -> Result<bool, AppError> {
        let code_hash = self.hash_code(code);

        // Find unused backup code
        let backup_code = sqlx::query_as::<_, TOTPBackupCode>(
            r#"
            SELECT * FROM totp_backup_codes
            WHERE user_id = $1 AND code_hash = $2 AND used = false
            "#
        )
        .bind(user_id)
        .bind(&code_hash)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(bc) = backup_code {
            // Mark code as used
            sqlx::query("UPDATE totp_backup_codes SET used = true WHERE id = $1")
                .bind(bc.id)
                .execute(&self.pool)
                .await?;

            tracing::info!("Backup code used for user: {}", user_id);
            return Ok(true);
        }

        Ok(false)
    }

    /// Get remaining unused backup codes count
    pub async fn get_remaining_backup_codes(&self, user_id: Uuid) -> Result<i64, AppError> {
        let count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM totp_backup_codes WHERE user_id = $1 AND used = false"
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }

    /// Store temporary TOTP secret during setup (before verification)
    pub async fn store_temp_secret(&self, user_id: Uuid, secret: &str) -> Result<(), AppError> {
        sqlx::query(
            "UPDATE users SET totp_secret = $1, updated_at = NOW() WHERE id = $2"
        )
        .bind(secret)
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get user's TOTP secret
    pub async fn get_user_secret(&self, user_id: Uuid) -> Result<Option<String>, AppError> {
        let secret = sqlx::query_scalar::<_, Option<String>>(
            "SELECT totp_secret FROM users WHERE id = $1"
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(secret)
    }

    // Helper: Create TOTP instance
    fn create_totp(&self, email: &str, secret: &str) -> Result<TOTP, AppError> {
        let secret_bytes = Secret::Encoded(secret.to_string())
            .to_bytes()
            .map_err(|e| AppError::InternalServerError(format!("Invalid secret: {}", e)))?;

        TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            Some(self.config.totp_issuer.clone()),
            email.to_string(),
        )
        .map_err(|e| AppError::InternalServerError(format!("Failed to create TOTP: {}", e)))
    }

    // Helper: Generate random backup code
    fn generate_random_code(&self) -> String {
        let mut rng = rand::thread_rng();
        let chars: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".chars().collect();

        (0..BACKUP_CODE_LENGTH)
            .map(|_| chars[rng.gen_range(0..chars.len())])
            .collect()
    }

    // Helper: Hash a backup code
    fn hash_code(&self, code: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(code.to_uppercase().as_bytes());
        hex::encode(hasher.finalize())
    }
}
