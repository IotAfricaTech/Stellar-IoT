use axum::{extract::Query, http::StatusCode, Json};
use chrono::Utc;
use ed25519_dalek::{Signature, VerifyingKey};
use jsonwebtoken::{
    decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    env,
    sync::Mutex,
};

// ─── Challenge store ──────────────────────────────────────────────────────────

struct ChallengeEntry {
    nonce: String,
    expires_at: i64, // unix seconds
}

lazy_static::lazy_static! {
    static ref CHALLENGES: Mutex<HashMap<String, ChallengeEntry>> = Mutex::new(HashMap::new());
}

const CHALLENGE_TTL_SECS: i64 = 60;

// ─── JWT claims ───────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // wallet address
    pub exp: usize,
}

/// Claims embedded in a device-session access token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceSessionClaims {
    /// Identifier of the device the token grants access to.
    pub device_id: String,
    /// Stellar wallet address of the paying user.
    pub user_address: String,
    /// Identifier of the session this token belongs to.
    pub session_id: String,
    /// Issued-at time (unix seconds).
    pub iat: usize,
    /// Expiry time (unix seconds).
    pub exp: usize,
}

/// Minimal session description needed to mint a device access token.
#[derive(Debug, Clone)]
pub struct Session {
    pub device_id: String,
    pub user_address: String,
    pub session_id: String,
    /// Token lifetime in seconds from now.
    pub ttl_secs: i64,
}

/// Errors that can occur while generating or validating device tokens.
#[derive(Debug)]
pub enum TokenError {
    Encode(jsonwebtoken::errors::Error),
    Decode(jsonwebtoken::errors::Error),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenError::Encode(e) => write!(f, "token encoding failed: {e}"),
            TokenError::Decode(e) => write!(f, "token decoding failed: {e}"),
        }
    }
}

impl std::error::Error for TokenError {}

impl From<TokenError> for (StatusCode, &'static str) {
    fn from(_: TokenError) -> Self {
        (StatusCode::UNAUTHORIZED, "Invalid or expired access token")
    }
}

/// Generate a short-lived JWT access token for a device session (HS256).
pub fn generate_device_token(
    session: &Session,
    secret: &[u8],
) -> Result<String, TokenError> {
    let now = Utc::now().timestamp();
    let claims = DeviceSessionClaims {
        device_id: session.device_id.clone(),
        user_address: session.user_address.clone(),
        session_id: session.session_id.clone(),
        iat: now as usize,
        exp: (now + session.ttl_secs) as usize,
    };

    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(TokenError::Encode)
}

/// Validate a device access token and return its claims.
/// Verifies the signature and that the token has not expired.
pub fn decode_device_token(
    token: &str,
    secret: &[u8],
) -> Result<DeviceSessionClaims, TokenError> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    decode::<DeviceSessionClaims>(
        token,
        &DecodingKey::from_secret(secret),
        &validation,
    )
    .map(|data| data.claims)
    .map_err(TokenError::Decode)
}

fn jwt_secret() -> String {
    env::var("JWT_SECRET").expect("JWT_SECRET must be set")
}

// ─── GET /auth/challenge?address=<wallet> ─────────────────────────────────────

#[derive(Deserialize)]
pub struct ChallengeQuery {
    pub address: String,
}

#[derive(Serialize)]
pub struct ChallengeResponse {
    pub nonce: String,
    pub expires_at: i64,
}

pub async fn get_challenge(
    Query(q): Query<ChallengeQuery>,
) -> Json<ChallengeResponse> {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let nonce = hex::encode(bytes);
    let expires_at = Utc::now().timestamp() + CHALLENGE_TTL_SECS;

    CHALLENGES.lock().unwrap().insert(
        q.address,
        ChallengeEntry { nonce: nonce.clone(), expires_at },
    );

    Json(ChallengeResponse { nonce, expires_at })
}

// ─── POST /auth/verify ────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct VerifyRequest {
    /// Stellar wallet address (Ed25519 public key, base64url or hex, 32 bytes).
    pub address: String,
    /// Hex-encoded Ed25519 signature over the nonce bytes.
    pub signature: String,
}

#[derive(Serialize)]
pub struct TokenResponse {
    pub token: String,
}

pub async fn verify_challenge(
    Json(body): Json<VerifyRequest>,
) -> Result<Json<TokenResponse>, (StatusCode, &'static str)> {
    // 1. Retrieve and validate the challenge
    let nonce = {
        let mut store = CHALLENGES.lock().unwrap();
        let entry = store
            .remove(&body.address)
            .ok_or((StatusCode::NOT_FOUND, "No challenge found for this address"))?;

        if Utc::now().timestamp() > entry.expires_at {
            return Err((StatusCode::GONE, "Challenge expired"));
        }
        entry.nonce
    };

    // 2. Decode public key (32-byte hex or base64)
    let pk_bytes: [u8; 32] = hex::decode(&body.address)
        .or_else(|_| {
            use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
            URL_SAFE_NO_PAD.decode(&body.address)
        })
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid address encoding"))?
        .try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Address must be 32 bytes"))?;

    let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid public key"))?;

    // 3. Decode signature (64-byte hex)
    let sig_bytes: [u8; 64] = hex::decode(&body.signature)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid signature encoding"))?
        .try_into()
        .map_err(|_| (StatusCode::BAD_REQUEST, "Signature must be 64 bytes"))?;

    let signature = Signature::from_bytes(&sig_bytes);

    // 4. Verify: client must have signed the raw nonce bytes
    use ed25519_dalek::Verifier;
    verifying_key
        .verify(nonce.as_bytes(), &signature)
        .map_err(|_| (StatusCode::UNAUTHORIZED, "Signature verification failed"))?;

    // 5. Issue JWT (24h expiry)
    let exp = (Utc::now() + chrono::Duration::hours(24)).timestamp() as usize;
    let claims = Claims { sub: body.address, exp };
    let secret = jwt_secret();
    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Token generation failed"))?;

    Ok(Json(TokenResponse { token }))
}
