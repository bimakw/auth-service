use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::Config;
use crate::errors::AppError;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,        // User ID
    pub email: String,
    pub role: String,
    pub exp: i64,           // Expiration time
    pub iat: i64,           // Issued at
    pub token_type: String, // "access" or "refresh"
}

pub struct TokenService {
    config: Config,
}

impl TokenService {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub fn generate_access_token(
        &self,
        user_id: Uuid,
        email: &str,
        role: &str,
    ) -> Result<String, AppError> {
        let now = Utc::now();
        let exp = now + Duration::seconds(self.config.jwt_access_expiration);

        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            token_type: "access".to_string(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.jwt_secret.as_bytes()),
        )
        .map_err(|e| AppError::InternalServerError(format!("Failed to generate token: {}", e)))
    }

    pub fn generate_refresh_token(
        &self,
        user_id: Uuid,
        email: &str,
        role: &str,
    ) -> Result<String, AppError> {
        let now = Utc::now();
        let exp = now + Duration::seconds(self.config.jwt_refresh_expiration);

        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            token_type: "refresh".to_string(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.jwt_secret.as_bytes()),
        )
        .map_err(|e| AppError::InternalServerError(format!("Failed to generate token: {}", e)))
    }

    pub fn verify_token(&self, token: &str) -> Result<TokenData<Claims>, AppError> {
        decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.config.jwt_secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|e| {
            tracing::warn!("Token verification failed: {:?}", e);
            AppError::Unauthorized("Invalid or expired token".to_string())
        })
    }

    pub fn verify_access_token(&self, token: &str) -> Result<Claims, AppError> {
        let token_data = self.verify_token(token)?;

        if token_data.claims.token_type != "access" {
            return Err(AppError::Unauthorized("Invalid token type".to_string()));
        }

        Ok(token_data.claims)
    }

    pub fn verify_refresh_token(&self, token: &str) -> Result<Claims, AppError> {
        let token_data = self.verify_token(token)?;

        if token_data.claims.token_type != "refresh" {
            return Err(AppError::Unauthorized("Invalid token type".to_string()));
        }

        Ok(token_data.claims)
    }

    pub fn extract_user_id(&self, claims: &Claims) -> Result<Uuid, AppError> {
        Uuid::parse_str(&claims.sub)
            .map_err(|_| AppError::InternalServerError("Invalid user ID in token".to_string()))
    }

    /// Generate temporary token for 2FA login flow (5 minutes expiration)
    pub fn generate_temp_token(
        &self,
        user_id: Uuid,
        email: &str,
        role: &str,
    ) -> Result<String, AppError> {
        let now = Utc::now();
        let exp = now + Duration::seconds(300); // 5 minutes

        let claims = Claims {
            sub: user_id.to_string(),
            email: email.to_string(),
            role: role.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
            token_type: "temp_2fa".to_string(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.config.jwt_secret.as_bytes()),
        )
        .map_err(|e| AppError::InternalServerError(format!("Failed to generate token: {}", e)))
    }

    pub fn verify_temp_token(&self, token: &str) -> Result<Claims, AppError> {
        let token_data = self.verify_token(token)?;

        if token_data.claims.token_type != "temp_2fa" {
            return Err(AppError::Unauthorized("Invalid token type".to_string()));
        }

        Ok(token_data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    fn setup_config() -> Config {
        Config {
            host: "127.0.0.1".to_string(),
            port: 8080,
            database_url: "postgres://localhost/test".to_string(),
            redis_url: "redis://localhost:6379".to_string(),
            jwt_secret: "test-secret-key-for-testing".to_string(),
            jwt_access_expiration: 900,
            jwt_refresh_expiration: 604800,
            google_client_id: "".to_string(),
            google_client_secret: "".to_string(),
            google_redirect_url: "".to_string(),
            frontend_url: "http://localhost:3000".to_string(),
            totp_issuer: "AuthService".to_string(),
        }
    }

    #[test]
    fn test_generate_and_verify_access_token() {
        let config = setup_config();
        let service = TokenService::new(config);

        let user_id = Uuid::new_v4();
        let email = "test@example.com";
        let role = "user";

        let token = service.generate_access_token(user_id, email, role).unwrap();
        let claims = service.verify_access_token(&token).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.email, email);
        assert_eq!(claims.role, role);
        assert_eq!(claims.token_type, "access");
    }

    #[test]
    fn test_generate_and_verify_refresh_token() {
        let config = setup_config();
        let service = TokenService::new(config);

        let user_id = Uuid::new_v4();
        let email = "test@example.com";
        let role = "user";

        let token = service.generate_refresh_token(user_id, email, role).unwrap();
        let claims = service.verify_refresh_token(&token).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.token_type, "refresh");
    }

    #[test]
    fn test_access_token_as_refresh_fails() {
        let config = setup_config();
        let service = TokenService::new(config);

        let user_id = Uuid::new_v4();
        let token = service.generate_access_token(user_id, "test@example.com", "user").unwrap();

        // Should fail when verifying access token as refresh
        assert!(service.verify_refresh_token(&token).is_err());
    }
}
