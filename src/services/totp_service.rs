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
        hash_backup_code(code)
    }
}

/// Hash a backup code (public for testing)
pub fn hash_backup_code(code: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code.to_uppercase().as_bytes());
    hex::encode(hasher.finalize())
}

/// Generate a random backup code (public for testing)
pub fn generate_backup_code() -> String {
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".chars().collect();

    (0..BACKUP_CODE_LENGTH)
        .map(|_| chars[rng.gen_range(0..chars.len())])
        .collect()
}

/// Verify TOTP code without needing full service (for testing)
pub fn verify_totp_code(secret: &str, code: &str, issuer: &str) -> Result<bool, AppError> {
    let secret_bytes = Secret::Encoded(secret.to_string())
        .to_bytes()
        .map_err(|e| AppError::InternalServerError(format!("Invalid secret: {}", e)))?;

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some(issuer.to_string()),
        "user".to_string(),
    ).map_err(|e| AppError::InternalServerError(format!("Failed to create TOTP: {}", e)))?;

    Ok(totp.check_current(code).unwrap_or(false))
}

/// Generate a new TOTP secret (public for testing)
pub fn generate_totp_secret() -> Result<String, AppError> {
    let secret = Secret::generate_secret();
    Ok(secret.to_encoded().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ============ Secret Generation Tests ============

    #[test]
    fn test_generate_secret_returns_valid_base32() {
        let secret = generate_totp_secret().unwrap();

        // Should be non-empty
        assert!(!secret.is_empty());

        // Should be valid base32 (can be decoded)
        let decoded = Secret::Encoded(secret.clone()).to_bytes();
        assert!(decoded.is_ok(), "Secret should be valid base32");
    }

    #[test]
    fn test_generate_secret_produces_unique_secrets() {
        let secret1 = generate_totp_secret().unwrap();
        let secret2 = generate_totp_secret().unwrap();

        assert_ne!(secret1, secret2, "Each call should generate unique secret");
    }

    #[test]
    fn test_generate_secret_sufficient_length() {
        let secret = generate_totp_secret().unwrap();

        // TOTP secrets should be at least 16 bytes (128 bits) for security
        // Base32 encoding: 16 bytes = 26 characters (with padding)
        assert!(secret.len() >= 16, "Secret should be at least 16 characters");
    }

    // ============ Backup Code Generation Tests ============

    #[test]
    fn test_generate_backup_code_correct_length() {
        let code = generate_backup_code();
        assert_eq!(code.len(), BACKUP_CODE_LENGTH);
    }

    #[test]
    fn test_generate_backup_code_valid_characters() {
        let code = generate_backup_code();
        let valid_chars: Vec<char> = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789".chars().collect();

        for c in code.chars() {
            assert!(valid_chars.contains(&c), "Invalid character in backup code: {}", c);
        }
    }

    #[test]
    fn test_generate_backup_code_uniqueness() {
        let codes: Vec<String> = (0..100).map(|_| generate_backup_code()).collect();

        // Check for duplicates (statistically very unlikely with proper randomness)
        let unique_codes: std::collections::HashSet<_> = codes.iter().collect();
        assert_eq!(codes.len(), unique_codes.len(), "Backup codes should be unique");
    }

    // ============ Backup Code Hashing Tests ============

    #[test]
    fn test_hash_backup_code_deterministic() {
        let code = "ABCD1234";
        let hash1 = hash_backup_code(code);
        let hash2 = hash_backup_code(code);

        assert_eq!(hash1, hash2, "Same code should produce same hash");
    }

    #[test]
    fn test_hash_backup_code_case_insensitive() {
        let hash_upper = hash_backup_code("ABCD1234");
        let hash_lower = hash_backup_code("abcd1234");
        let hash_mixed = hash_backup_code("AbCd1234");

        assert_eq!(hash_upper, hash_lower, "Hash should be case-insensitive");
        assert_eq!(hash_upper, hash_mixed, "Hash should be case-insensitive");
    }

    #[test]
    fn test_hash_backup_code_different_codes_different_hashes() {
        let hash1 = hash_backup_code("ABCD1234");
        let hash2 = hash_backup_code("EFGH5678");

        assert_ne!(hash1, hash2, "Different codes should produce different hashes");
    }

    #[test]
    fn test_hash_backup_code_sha256_format() {
        let hash = hash_backup_code("ABCD1234");

        // SHA256 produces 64 hex characters
        assert_eq!(hash.len(), 64, "Hash should be 64 hex characters (SHA256)");

        // Should be valid hex
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()), "Hash should be hex");
    }

    // ============ TOTP Verification Tests ============

    #[test]
    fn test_verify_totp_code_with_invalid_secret() {
        let result = verify_totp_code("invalid-secret!!!", "123456", "TestIssuer");

        assert!(result.is_err(), "Invalid secret should return error");
    }

    #[test]
    fn test_verify_totp_code_wrong_code_fails() {
        let secret = generate_totp_secret().unwrap();

        // A random 6-digit code is almost certainly wrong
        let result = verify_totp_code(&secret, "000000", "TestIssuer").unwrap();

        // Note: There's a 1/1000000 chance this could be the actual code
        // but that's acceptable for testing purposes
        assert!(!result, "Random code should not verify (with very high probability)");
    }

    #[test]
    fn test_verify_totp_code_correct_code_succeeds() {
        let secret = generate_totp_secret().unwrap();

        // Generate the actual current code
        let secret_bytes = Secret::Encoded(secret.clone()).to_bytes().unwrap();
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            secret_bytes,
            Some("TestIssuer".to_string()),
            "user".to_string(),
        ).unwrap();

        let current_code = totp.generate_current().unwrap();

        let result = verify_totp_code(&secret, &current_code, "TestIssuer").unwrap();
        assert!(result, "Correct TOTP code should verify");
    }

    #[test]
    fn test_verify_totp_code_empty_code_fails() {
        let secret = generate_totp_secret().unwrap();

        let result = verify_totp_code(&secret, "", "TestIssuer").unwrap();
        assert!(!result, "Empty code should not verify");
    }

    #[test]
    fn test_verify_totp_code_short_code_fails() {
        let secret = generate_totp_secret().unwrap();

        let result = verify_totp_code(&secret, "12345", "TestIssuer").unwrap();
        assert!(!result, "5-digit code should not verify");
    }

    #[test]
    fn test_verify_totp_code_long_code_fails() {
        let secret = generate_totp_secret().unwrap();

        let result = verify_totp_code(&secret, "1234567", "TestIssuer").unwrap();
        assert!(!result, "7-digit code should not verify");
    }

    // ============ Constants Tests ============

    #[test]
    fn test_backup_code_count_is_reasonable() {
        assert!(BACKUP_CODE_COUNT >= 5, "Should have at least 5 backup codes");
        assert!(BACKUP_CODE_COUNT <= 20, "Should have at most 20 backup codes");
    }

    #[test]
    fn test_backup_code_length_is_reasonable() {
        assert!(BACKUP_CODE_LENGTH >= 6, "Backup codes should be at least 6 chars");
        assert!(BACKUP_CODE_LENGTH <= 16, "Backup codes should be at most 16 chars");
    }
}
