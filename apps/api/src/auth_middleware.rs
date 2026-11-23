use crate::auth::Claims;
use crate::services::{get_session, is_session_revoked};
use axum::{
    extract::{FromRequestParts, Request},
    http::{request::Parts, StatusCode},
    middleware::Next,
    response::Response,
};
use jsonwebtoken::{decode, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::env;

/// Claims embedded in a device session access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSessionClaims {
    pub device_id: String,
    pub user_address: String,
    pub expires_at: i64,
    pub session_id: String,
    pub exp: usize,
}

/// Extractor that validates a device session JWT and confirms the
/// referenced session is still active and not revoked.
#[derive(Clone)]
pub struct DeviceSession(pub DeviceSessionClaims);

#[async_trait::async_trait]
impl<S: Send + Sync> FromRequestParts<S> for DeviceSession {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header"))?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or((StatusCode::UNAUTHORIZED, "Invalid Authorization header format"))?;

        let secret = env::var("JWT_SECRET").unwrap_or_default();
        let data = decode::<DeviceSessionClaims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid or expired token"))?;

        let claims = data.claims;

        if is_session_revoked(&claims.session_id) {
            return Err((StatusCode::FORBIDDEN, "Session has been revoked"));
        }

        match get_session(&claims.session_id) {
            Some(session) if session.is_active => Ok(DeviceSession(claims)),
            Some(_) => Err((StatusCode::FORBIDDEN, "Session has ended")),
            None => Err((StatusCode::FORBIDDEN, "Session not found")),
        }
    }
}

/// Extractor that pulls the verified wallet address out of the JWT.
#[derive(Clone)]
pub struct AuthenticatedOwner(pub String);

#[async_trait::async_trait]
impl<S: Send + Sync> FromRequestParts<S> for AuthenticatedOwner {
    type Rejection = (StatusCode, &'static str);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header"))?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or((StatusCode::UNAUTHORIZED, "Invalid Authorization header format"))?;

        let secret = env::var("JWT_SECRET").unwrap_or_default();
        let data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &Validation::default(),
        )
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid or expired token"))?;

        Ok(AuthenticatedOwner(data.claims.sub))
    }
}

/// Axum middleware that rejects requests without a valid JWT.
pub async fn require_auth(
    parts: Request,
    next: Next,
) -> Result<Response, (StatusCode, &'static str)> {
    let (mut p, body) = parts.into_parts();
    AuthenticatedOwner::from_request_parts(&mut p, &()).await?;
    Ok(next.run(Request::from_parts(p, body)).await)
}

/// Axum middleware that rejects device access requests without a valid,
/// active device session JWT.
pub async fn require_device_session(
    parts: Request,
    next: Next,
) -> Result<Response, (StatusCode, &'static str)> {
    let (mut p, body) = parts.into_parts();
    DeviceSession::from_request_parts(&mut p, &()).await?;
    Ok(next.run(Request::from_parts(p, body)).await)
}
