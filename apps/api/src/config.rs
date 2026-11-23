use dotenv::dotenv;
use std::env;

#[derive(Clone)]
pub struct StellarConfig {
    pub horizon_url: String,
    #[allow(dead_code)]
    pub network_passphrase: String,
}

impl StellarConfig {
    pub fn from_env() -> Self {
        dotenv().ok();
        let horizon_url = env::var("HORIZON_URL")
            .unwrap_or_else(|_| "https://horizon-testnet.stellar.org".to_string());
        let network_passphrase = env::var("STELLAR_NETWORK_PASSPHRASE")
            .unwrap_or_else(|_| "Test SDF Network ; September 2015".to_string());

        Self {
            horizon_url,
            network_passphrase,
        }
    }
}

#[derive(Clone)]
pub struct JwtConfig {
    pub secret: String,
    pub access_token_ttl_secs: u64,
    pub issuer: String,
}

impl JwtConfig {
    pub fn from_env() -> Self {
        dotenv().ok();
        let secret = env::var("JWT_SECRET")
            .unwrap_or_else(|_| "insecure-default-dev-secret-change-me".to_string());
        let access_token_ttl_secs = env::var("JWT_ACCESS_TOKEN_TTL_SECS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(3600);
        let issuer = env::var("JWT_ISSUER")
            .unwrap_or_else(|_| "iot-access-api".to_string());

        Self {
            secret,
            access_token_ttl_secs,
            issuer,
        }
    }

    pub fn secret_bytes(&self) -> Vec<u8> {
        self.secret.as_bytes().to_vec()
    }
}