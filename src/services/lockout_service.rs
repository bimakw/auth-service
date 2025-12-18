use redis::{AsyncCommands, Client};
use std::sync::Arc;

use crate::errors::AppError;

const LOCKOUT_PREFIX: &str = "lockout:";
const FAILED_ATTEMPTS_PREFIX: &str = "failed_attempts:";

#[derive(Clone)]
pub struct LockoutService {
    client: Arc<Client>,
    /// Maximum failed attempts before lockout
    max_attempts: u32,
    /// Lockout duration in seconds
    lockout_duration: u64,
    /// Window for counting failed attempts (seconds)
    attempt_window: u64,
}

#[derive(Debug, Clone)]
pub struct LockoutStatus {
    pub is_locked: bool,
    pub failed_attempts: u32,
    pub remaining_attempts: u32,
    pub locked_until: Option<u64>,
}

impl LockoutService {
    pub fn new(
        redis_url: &str,
        max_attempts: u32,
        lockout_duration: u64,
        attempt_window: u64,
    ) -> Result<Self, AppError> {
        let client = Client::open(redis_url)
            .map_err(|e| AppError::InternalServerError(format!("Redis connection error: {}", e)))?;

        Ok(Self {
            client: Arc::new(client),
            max_attempts,
            lockout_duration,
            attempt_window,
        })
    }

    /// Create with default settings: 5 attempts, 15 min lockout, 1 hour window
    pub fn with_defaults(redis_url: &str) -> Result<Self, AppError> {
        Self::new(redis_url, 5, 900, 3600)
    }

    /// Check if an account is locked
    pub async fn check_lockout(&self, identifier: &str) -> Result<LockoutStatus, AppError> {
        let mut conn = self.client.get_async_connection().await?;

        let lockout_key = format!("{}{}", LOCKOUT_PREFIX, identifier);
        let attempts_key = format!("{}{}", FAILED_ATTEMPTS_PREFIX, identifier);

        // Check if locked
        let locked_until: Option<String> = conn.get(&lockout_key).await?;

        if let Some(until) = locked_until {
            let until_ts: u64 = until.parse().unwrap_or(0);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if until_ts > now {
                return Ok(LockoutStatus {
                    is_locked: true,
                    failed_attempts: self.max_attempts,
                    remaining_attempts: 0,
                    locked_until: Some(until_ts),
                });
            } else {
                // Lockout expired, clean up
                let _: () = conn.del(&lockout_key).await?;
                let _: () = conn.del(&attempts_key).await?;
            }
        }

        // Get current failed attempts
        let attempts: Option<u32> = conn.get(&attempts_key).await?;
        let failed_attempts = attempts.unwrap_or(0);

        Ok(LockoutStatus {
            is_locked: false,
            failed_attempts,
            remaining_attempts: self.max_attempts.saturating_sub(failed_attempts),
            locked_until: None,
        })
    }

    /// Record a failed login attempt
    pub async fn record_failed_attempt(&self, identifier: &str) -> Result<LockoutStatus, AppError> {
        let mut conn = self.client.get_async_connection().await?;

        let lockout_key = format!("{}{}", LOCKOUT_PREFIX, identifier);
        let attempts_key = format!("{}{}", FAILED_ATTEMPTS_PREFIX, identifier);

        // Increment failed attempts
        let attempts: u32 = conn.incr(&attempts_key, 1).await?;

        // Set expiration on first attempt
        if attempts == 1 {
            let _: () = conn.expire(&attempts_key, self.attempt_window as i64).await?;
        }

        // Check if should be locked
        if attempts >= self.max_attempts {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let locked_until = now + self.lockout_duration;

            // Set lockout
            let _: () = conn
                .set_ex(&lockout_key, locked_until.to_string(), self.lockout_duration as u64)
                .await?;

            tracing::warn!(
                "Account locked due to {} failed attempts: {}",
                attempts,
                identifier
            );

            return Ok(LockoutStatus {
                is_locked: true,
                failed_attempts: attempts,
                remaining_attempts: 0,
                locked_until: Some(locked_until),
            });
        }

        Ok(LockoutStatus {
            is_locked: false,
            failed_attempts: attempts,
            remaining_attempts: self.max_attempts.saturating_sub(attempts),
            locked_until: None,
        })
    }

    /// Clear failed attempts after successful login
    pub async fn clear_failed_attempts(&self, identifier: &str) -> Result<(), AppError> {
        let mut conn = self.client.get_async_connection().await?;

        let lockout_key = format!("{}{}", LOCKOUT_PREFIX, identifier);
        let attempts_key = format!("{}{}", FAILED_ATTEMPTS_PREFIX, identifier);

        let _: () = conn.del(&lockout_key).await?;
        let _: () = conn.del(&attempts_key).await?;

        Ok(())
    }

    /// Manually unlock an account (admin function)
    pub async fn unlock_account(&self, identifier: &str) -> Result<(), AppError> {
        self.clear_failed_attempts(identifier).await
    }
}
