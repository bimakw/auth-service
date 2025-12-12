use sqlx::PgPool;
use uuid::Uuid;

use crate::errors::AppError;
use crate::models::{User, RegisterRequest, LoginRequest};
use crate::utils::password::{hash_password, verify_password};

pub struct AuthService {
    pool: PgPool,
}

impl AuthService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub async fn register(&self, req: RegisterRequest) -> Result<User, AppError> {
        // Check if email already exists
        let existing = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM users WHERE email = $1"
        )
        .bind(&req.email)
        .fetch_one(&self.pool)
        .await?;

        if existing > 0 {
            return Err(AppError::Conflict("Email already registered".to_string()));
        }

        // Hash password
        let password_hash = hash_password(&req.password)?;

        // Insert user
        let user = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (email, password_hash, name, role)
            VALUES ($1, $2, $3, 'user')
            RETURNING *
            "#
        )
        .bind(&req.email)
        .bind(&password_hash)
        .bind(&req.name)
        .fetch_one(&self.pool)
        .await?;

        tracing::info!("User registered successfully: {}", user.email);
        Ok(user)
    }

    pub async fn login(&self, req: LoginRequest) -> Result<User, AppError> {
        // Find user by email
        let user = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE email = $1"
        )
        .bind(&req.email)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::Unauthorized("Invalid email or password".to_string()))?;

        // Check if user has password (not OAuth-only)
        let password_hash = user.password_hash.as_ref()
            .ok_or_else(|| AppError::Unauthorized("Please login with Google".to_string()))?;

        // Verify password
        if !verify_password(&req.password, password_hash)? {
            return Err(AppError::Unauthorized("Invalid email or password".to_string()));
        }

        tracing::info!("User logged in successfully: {}", user.email);
        Ok(user)
    }

    pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<User, AppError> {
        sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE id = $1"
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AppError::NotFound("User not found".to_string()))
    }

    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, AppError> {
        sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE email = $1"
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| e.into())
    }

    pub async fn get_or_create_google_user(
        &self,
        google_id: &str,
        email: &str,
        name: &str,
    ) -> Result<User, AppError> {
        // Check if user exists with google_id
        let existing_user = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE google_id = $1"
        )
        .bind(google_id)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(user) = existing_user {
            return Ok(user);
        }

        // Check if user exists with email (link accounts)
        let existing_email_user = sqlx::query_as::<_, User>(
            "SELECT * FROM users WHERE email = $1"
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(user) = existing_email_user {
            // Link Google account to existing user
            let updated_user = sqlx::query_as::<_, User>(
                r#"
                UPDATE users
                SET google_id = $1, email_verified = true, updated_at = NOW()
                WHERE id = $2
                RETURNING *
                "#
            )
            .bind(google_id)
            .bind(user.id)
            .fetch_one(&self.pool)
            .await?;

            tracing::info!("Linked Google account to existing user: {}", email);
            return Ok(updated_user);
        }

        // Create new user with Google account
        let user = sqlx::query_as::<_, User>(
            r#"
            INSERT INTO users (email, name, google_id, email_verified, role)
            VALUES ($1, $2, $3, true, 'user')
            RETURNING *
            "#
        )
        .bind(email)
        .bind(name)
        .bind(google_id)
        .fetch_one(&self.pool)
        .await?;

        tracing::info!("Created new user with Google account: {}", email);
        Ok(user)
    }

    pub async fn change_password(
        &self,
        user_id: Uuid,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), AppError> {
        let user = self.get_user_by_id(user_id).await?;

        // Check if user has password
        let password_hash = user.password_hash.as_ref()
            .ok_or_else(|| AppError::BadRequest("Cannot change password for OAuth-only account".to_string()))?;

        // Verify current password
        if !verify_password(current_password, password_hash)? {
            return Err(AppError::Unauthorized("Current password is incorrect".to_string()));
        }

        // Hash new password
        let new_hash = hash_password(new_password)?;

        // Update password
        sqlx::query(
            "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2"
        )
        .bind(&new_hash)
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        tracing::info!("Password changed for user: {}", user.email);
        Ok(())
    }
}
