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
            github_client_id: "".to_string(),
            github_client_secret: "".to_string(),
            github_redirect_url: "".to_string(),
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

    // ============ Temp Token (2FA) Tests ============

    #[test]
    fn test_generate_and_verify_temp_token() {
        let config = setup_config();
        let service = TokenService::new(config);

        let user_id = Uuid::new_v4();
        let email = "test@example.com";
        let role = "user";

        let token = service.generate_temp_token(user_id, email, role).unwrap();
        let claims = service.verify_temp_token(&token).unwrap();

        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.email, email);
        assert_eq!(claims.token_type, "temp_2fa");
    }

    #[test]
    fn test_temp_token_as_access_fails() {
        let config = setup_config();
        let service = TokenService::new(config);

        let user_id = Uuid::new_v4();
        let token = service.generate_temp_token(user_id, "test@example.com", "user").unwrap();

        // Temp token should not work as access token
        assert!(service.verify_access_token(&token).is_err());
    }

    #[test]
    fn test_access_token_as_temp_fails() {
        let config = setup_config();
        let service = TokenService::new(config);

        let user_id = Uuid::new_v4();
        let token = service.generate_access_token(user_id, "test@example.com", "user").unwrap();

        // Access token should not work as temp token
        assert!(service.verify_temp_token(&token).is_err());
    }

    // ============ Token Verification Edge Cases ============

    #[test]
    fn test_invalid_token_fails() {
        let config = setup_config();
        let service = TokenService::new(config);

        let result = service.verify_token("invalid-token-string");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_token_fails() {
        let config = setup_config();
        let service = TokenService::new(config);

        let result = service.verify_token("");
        assert!(result.is_err());
    }

    #[test]
    fn test_malformed_jwt_fails() {
        let config = setup_config();
        let service = TokenService::new(config);

        // JWT has 3 parts separated by dots
        let result = service.verify_token("header.payload");
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_secret_fails() {
        let config1 = setup_config();
        let mut config2 = setup_config();
        config2.jwt_secret = "different-secret-key".to_string();

        let service1 = TokenService::new(config1);
        let service2 = TokenService::new(config2);

        let user_id = Uuid::new_v4();
        let token = service1.generate_access_token(user_id, "test@example.com", "user").unwrap();

        // Token from service1 should not verify with service2's different secret
        assert!(service2.verify_access_token(&token).is_err());
    }

    // ============ Extract User ID Tests ============

    #[test]
    fn test_extract_user_id_success() {
        let config = setup_config();
        let service = TokenService::new(config);

        let original_user_id = Uuid::new_v4();
        let token = service.generate_access_token(original_user_id, "test@example.com", "user").unwrap();
        let claims = service.verify_access_token(&token).unwrap();

        let extracted_id = service.extract_user_id(&claims).unwrap();
        assert_eq!(extracted_id, original_user_id);
    }

    #[test]
    fn test_extract_user_id_invalid_uuid() {
        let config = setup_config();
        let service = TokenService::new(config);

        let claims = Claims {
            sub: "not-a-valid-uuid".to_string(),
            email: "test@example.com".to_string(),
            role: "user".to_string(),
            exp: 0,
            iat: 0,
            token_type: "access".to_string(),
        };

        let result = service.extract_user_id(&claims);
        assert!(result.is_err());
    }

    // ============ Token Claims Tests ============

    #[test]
    fn test_token_contains_correct_expiration() {
        let config = setup_config();
        let service = TokenService::new(config.clone());

        let user_id = Uuid::new_v4();
        let token = service.generate_access_token(user_id, "test@example.com", "user").unwrap();
        let claims = service.verify_access_token(&token).unwrap();

        // Check that exp is in the future and roughly matches expected expiration
        let now = chrono::Utc::now().timestamp();
        assert!(claims.exp > now);
        assert!(claims.exp <= now + config.jwt_access_expiration + 5); // 5 sec tolerance
    }

    #[test]
    fn test_token_contains_issued_at() {
        let config = setup_config();
        let service = TokenService::new(config);

        let user_id = Uuid::new_v4();
        let token = service.generate_access_token(user_id, "test@example.com", "user").unwrap();
        let claims = service.verify_access_token(&token).unwrap();

        let now = chrono::Utc::now().timestamp();
        // iat should be within last 5 seconds
        assert!(claims.iat <= now);
        assert!(claims.iat >= now - 5);
    }

    #[test]
    fn test_different_roles_preserved() {
        let config = setup_config();
        let service = TokenService::new(config);

        let user_id = Uuid::new_v4();

        let admin_token = service.generate_access_token(user_id, "admin@example.com", "admin").unwrap();
        let user_token = service.generate_access_token(user_id, "user@example.com", "user").unwrap();

        let admin_claims = service.verify_access_token(&admin_token).unwrap();
        let user_claims = service.verify_access_token(&user_token).unwrap();

        assert_eq!(admin_claims.role, "admin");
        assert_eq!(user_claims.role, "user");
    }

    #[test]
    fn test_refresh_token_longer_expiration() {
        let config = setup_config();
        let service = TokenService::new(config.clone());

        let user_id = Uuid::new_v4();
        let access_token = service.generate_access_token(user_id, "test@example.com", "user").unwrap();
        let refresh_token = service.generate_refresh_token(user_id, "test@example.com", "user").unwrap();

        let access_claims = service.verify_access_token(&access_token).unwrap();
        let refresh_claims = service.verify_refresh_token(&refresh_token).unwrap();

        // Refresh token should expire later than access token
        assert!(refresh_claims.exp > access_claims.exp);
    }
}
