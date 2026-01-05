use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::Error;

/// Default token expiration: 24 hours.
const DEFAULT_EXPIRATION_SECS: u64 = 24 * 60 * 60;

/// JWT claims for API authentication.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject (always "api").
    pub sub: String,
    /// Issuer (always "peershark").
    pub iss: String,
    /// Audience (always "peershark-api").
    pub aud: String,
    /// Expiration time (Unix timestamp).
    pub exp: u64,
    /// Issued at (Unix timestamp).
    pub iat: u64,
}

/// Create a JWT token with the given secret.
pub fn create_token(secret: &[u8], expires_in_secs: Option<u64>) -> Result<String, Error> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_secs();

    let exp = now + expires_in_secs.unwrap_or(DEFAULT_EXPIRATION_SECS);

    let claims = Claims {
        sub: "api".to_string(),
        iss: "peershark".to_string(),
        aud: "peershark-api".to_string(),
        exp,
        iat: now,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .map_err(|e| Error::Protocol(format!("failed to create token: {}", e)))
}

/// Validate a JWT token and return the claims.
pub fn validate_token(token: &str, secret: &[u8]) -> Result<Claims, Error> {
    let mut validation = Validation::default();
    validation.set_issuer(&["peershark"]);
    validation.set_audience(&["peershark-api"]);

    let token_data = decode::<Claims>(token, &DecodingKey::from_secret(secret), &validation)
        .map_err(|e| Error::Protocol(format!("invalid token: {}", e)))?;

    Ok(token_data.claims)
}

/// Load JWT secret from a hex file.
/// Expected format: 64 hex characters (32 bytes).
pub fn load_secret_from_file(path: &str) -> Result<Vec<u8>, Error> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| Error::Io(format!("failed to read JWT secret file: {}", e)))?;

    let hex_str = content.trim().trim_start_matches("0x");

    if hex_str.len() != 64 {
        return Err(Error::Protocol(format!(
            "JWT secret must be 32 bytes (64 hex chars), got {}",
            hex_str.len()
        )));
    }

    hex::decode(hex_str).map_err(|e| Error::Protocol(format!("invalid hex in JWT secret: {}", e)))
}

/// Generate a new random JWT secret and save to file.
pub fn generate_secret_file(path: &str) -> Result<Vec<u8>, Error> {
    use rand::RngCore;

    let mut secret = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);

    let hex_content = format!("0x{}\n", hex::encode(&secret));
    std::fs::write(path, hex_content)
        .map_err(|e| Error::Io(format!("failed to write JWT secret file: {}", e)))?;

    // Set restrictive permissions (owner read/write only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)
            .map_err(|e| Error::Io(format!("failed to set JWT secret file permissions: {}", e)))?;
    }

    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_validate_token() {
        let secret = b"test_secret_32_bytes_long_xxxxx";
        let token = create_token(secret, Some(3600)).expect("token creation should succeed");

        let claims = validate_token(&token, secret).expect("token validation should succeed");
        assert_eq!(claims.sub, "api");
        assert_eq!(claims.iss, "peershark");
        assert_eq!(claims.aud, "peershark-api");
    }

    #[test]
    fn invalid_token_fails() {
        let secret = b"test_secret_32_bytes_long_xxxxx";
        let result = validate_token("invalid.token.here", secret);
        assert!(result.is_err());
    }

    #[test]
    fn wrong_secret_fails() {
        let secret1 = b"test_secret_32_bytes_long_xxxxx";
        let secret2 = b"different_secret_32_bytes_xxxxx";

        let token = create_token(secret1, Some(3600)).expect("token creation should succeed");
        let result = validate_token(&token, secret2);
        assert!(result.is_err());
    }
}
