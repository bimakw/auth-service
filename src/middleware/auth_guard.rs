use actix_web::{dev::ServiceRequest, Error, HttpMessage};
use actix_web::error::ErrorUnauthorized;

use crate::services::Claims;

pub fn extract_claims_from_request(req: &ServiceRequest) -> Result<Claims, Error> {
    req.extensions()
        .get::<Claims>()
        .cloned()
        .ok_or_else(|| ErrorUnauthorized("Not authenticated"))
}

pub fn extract_token_from_header(req: &ServiceRequest) -> Option<String> {
    req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| {
            if h.starts_with("Bearer ") {
                Some(h[7..].to_string())
            } else {
                None
            }
        })
}
