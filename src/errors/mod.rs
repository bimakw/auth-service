use actix_web::{http::StatusCode, HttpResponse, ResponseError};
use serde::Serialize;
use std::fmt;

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub status: String,
    pub message: String,
}

#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    Unauthorized(String),
    Forbidden(String),
    NotFound(String),
    Conflict(String),
    InternalServerError(String),
    ValidationError(String),
    TooManyRequests { retry_after: u64, message: String },
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AppError::BadRequest(msg) => write!(f, "Bad Request: {}", msg),
            AppError::Unauthorized(msg) => write!(f, "Unauthorized: {}", msg),
            AppError::Forbidden(msg) => write!(f, "Forbidden: {}", msg),
            AppError::NotFound(msg) => write!(f, "Not Found: {}", msg),
            AppError::Conflict(msg) => write!(f, "Conflict: {}", msg),
            AppError::InternalServerError(msg) => write!(f, "Internal Server Error: {}", msg),
            AppError::ValidationError(msg) => write!(f, "Validation Error: {}", msg),
            AppError::TooManyRequests { message, .. } => write!(f, "Too Many Requests: {}", message),
        }
    }
}

impl ResponseError for AppError {
    fn error_response(&self) -> HttpResponse {
        match self {
            AppError::TooManyRequests { retry_after, message } => {
                HttpResponse::build(StatusCode::TOO_MANY_REQUESTS)
                    .insert_header(("Retry-After", retry_after.to_string()))
                    .json(ErrorResponse {
                        status: "error".to_string(),
                        message: message.clone(),
                    })
            }
            _ => {
                let (status_code, message) = match self {
                    AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
                    AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
                    AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
                    AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
                    AppError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
                    AppError::InternalServerError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
                    AppError::ValidationError(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg.clone()),
                    AppError::TooManyRequests { .. } => unreachable!(),
                };

                HttpResponse::build(status_code).json(ErrorResponse {
                    status: "error".to_string(),
                    message,
                })
            }
        }
    }
}

impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        tracing::error!("Database error: {:?}", err);
        match err {
            sqlx::Error::RowNotFound => AppError::NotFound("Resource not found".to_string()),
            sqlx::Error::Database(db_err) => {
                if db_err.is_unique_violation() {
                    AppError::Conflict("Resource already exists".to_string())
                } else {
                    AppError::InternalServerError("Database error".to_string())
                }
            }
            _ => AppError::InternalServerError("Database error".to_string()),
        }
    }
}

impl From<jsonwebtoken::errors::Error> for AppError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        tracing::error!("JWT error: {:?}", err);
        AppError::Unauthorized("Invalid or expired token".to_string())
    }
}

impl From<argon2::password_hash::Error> for AppError {
    fn from(err: argon2::password_hash::Error) -> Self {
        tracing::error!("Password hash error: {:?}", err);
        AppError::InternalServerError("Password processing error".to_string())
    }
}

impl From<redis::RedisError> for AppError {
    fn from(err: redis::RedisError) -> Self {
        tracing::error!("Redis error: {:?}", err);
        AppError::InternalServerError("Cache error".to_string())
    }
}
