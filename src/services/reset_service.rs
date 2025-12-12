use rand::Rng;
use redis::AsyncCommands;
use sha2::{Digest, Sha256};

use crate::errors::AppError;

const RESET_TOKEN_PREFIX: &str = "password_reset:";
const RESET_TOKEN_TTL: u64 = 3600; // 1 hour in seconds

pub struct ResetService {
    redis: redis::Client,
}

impl ResetService {
    pub fn new(redis_url: &str) -> Result<Self, AppError> {
        let client = redis::Client::open(redis_url)
            .map_err(|e| AppError::InternalServerError(format!("Redis connection error: {}", e)))?;

        Ok(Self { redis: client })
    }

    /// Generate a password reset token and store it in Redis
    pub async fn create_reset_token(&self, email: &str) -> Result<String, AppError> {
        let mut conn = self.redis.get_multiplexed_async_connection().await
            .map_err(|e| AppError::InternalServerError(format!("Redis error: {}", e)))?;

        // Generate random token
        let token: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        // Hash the token for storage
        let token_hash = self.hash_token(&token);

        // Store in Redis with TTL
        let key = format!("{}{}", RESET_TOKEN_PREFIX, token_hash);
        conn.set_ex::<_, _, ()>(&key, email, RESET_TOKEN_TTL).await
            .map_err(|e| AppError::InternalServerError(format!("Redis error: {}", e)))?;

        tracing::info!("Password reset token created for: {}", email);
        Ok(token)
    }

    /// Validate a reset token and return the associated email
    pub async fn validate_reset_token(&self, token: &str) -> Result<String, AppError> {
        let mut conn = self.redis.get_multiplexed_async_connection().await
            .map_err(|e| AppError::InternalServerError(format!("Redis error: {}", e)))?;

        let token_hash = self.hash_token(token);
        let key = format!("{}{}", RESET_TOKEN_PREFIX, token_hash);

        let email: Option<String> = conn.get(&key).await
            .map_err(|e| AppError::InternalServerError(format!("Redis error: {}", e)))?;

        email.ok_or_else(|| AppError::BadRequest("Invalid or expired reset token".to_string()))
    }

    /// Invalidate a reset token after successful password reset
    pub async fn invalidate_reset_token(&self, token: &str) -> Result<(), AppError> {
        let mut conn = self.redis.get_multiplexed_async_connection().await
            .map_err(|e| AppError::InternalServerError(format!("Redis error: {}", e)))?;

        let token_hash = self.hash_token(token);
        let key = format!("{}{}", RESET_TOKEN_PREFIX, token_hash);

        conn.del::<_, ()>(&key).await
            .map_err(|e| AppError::InternalServerError(format!("Redis error: {}", e)))?;

        Ok(())
    }

    fn hash_token(&self, token: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        hex::encode(hasher.finalize())
    }
}
