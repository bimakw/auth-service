use redis::{AsyncCommands, Client};
use std::sync::Arc;

use crate::errors::AppError;

#[derive(Clone)]
pub struct RateLimiter {
    client: Arc<Client>,
    /// Maximum requests allowed in the window
    max_requests: u32,
    /// Window size in seconds
    window_secs: u64,
}

#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    pub remaining: u32,
    pub reset_at: u64,
    pub is_limited: bool,
}

impl RateLimiter {
    pub fn new(redis_url: &str, max_requests: u32, window_secs: u64) -> Result<Self, AppError> {
        let client = Client::open(redis_url)
            .map_err(|e| AppError::InternalServerError(format!("Redis connection error: {}", e)))?;

        Ok(Self {
            client: Arc::new(client),
            max_requests,
            window_secs,
        })
    }

    /// Check if the request should be rate limited
    /// Returns RateLimitInfo with remaining requests and reset time
    pub async fn check_rate_limit(&self, key: &str) -> Result<RateLimitInfo, AppError> {
        let mut conn = self.client.get_async_connection().await?;

        let rate_key = format!("rate_limit:{}", key);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Get current count
        let count: Option<u32> = conn.get(&rate_key).await?;

        let current_count = count.unwrap_or(0);

        if current_count >= self.max_requests {
            // Get TTL to know when the limit resets
            let ttl: i64 = conn.ttl(&rate_key).await.unwrap_or(self.window_secs as i64);
            let reset_at = now + ttl as u64;

            return Ok(RateLimitInfo {
                remaining: 0,
                reset_at,
                is_limited: true,
            });
        }

        // Increment counter
        let new_count: u32 = conn.incr(&rate_key, 1).await?;

        // Set expiration on first request
        if new_count == 1 {
            let _: () = conn.expire(&rate_key, self.window_secs as i64).await?;
        }

        let ttl: i64 = conn.ttl(&rate_key).await.unwrap_or(self.window_secs as i64);
        let reset_at = now + ttl as u64;

        Ok(RateLimitInfo {
            remaining: self.max_requests.saturating_sub(new_count),
            reset_at,
            is_limited: false,
        })
    }

    /// Create a rate limiter for login attempts (stricter limits)
    pub fn for_login(redis_url: &str) -> Result<Self, AppError> {
        // 5 attempts per minute for login
        Self::new(redis_url, 5, 60)
    }

    /// Create a rate limiter for registration (moderate limits)
    pub fn for_registration(redis_url: &str) -> Result<Self, AppError> {
        // 3 registrations per hour per IP
        Self::new(redis_url, 3, 3600)
    }

    /// Create a rate limiter for password reset (strict limits)
    pub fn for_password_reset(redis_url: &str) -> Result<Self, AppError> {
        // 3 reset requests per hour
        Self::new(redis_url, 3, 3600)
    }

    /// Create a rate limiter for general API requests
    pub fn for_general(redis_url: &str) -> Result<Self, AppError> {
        // 100 requests per minute
        Self::new(redis_url, 100, 60)
    }
}

#[derive(Clone)]
pub struct RateLimiters {
    pub login: RateLimiter,
    pub registration: RateLimiter,
    pub password_reset: RateLimiter,
    pub general: RateLimiter,
}

impl RateLimiters {
    pub fn new(redis_url: &str) -> Result<Self, AppError> {
        Ok(Self {
            login: RateLimiter::for_login(redis_url)?,
            registration: RateLimiter::for_registration(redis_url)?,
            password_reset: RateLimiter::for_password_reset(redis_url)?,
            general: RateLimiter::for_general(redis_url)?,
        })
    }
}
