//! Cryptographic utilities for ECDH key agreement and public key manipulation.

use k256::PublicKey;
use k256::ecdh::diffie_hellman;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;

/// Convert a signing key to a 64-byte node ID (uncompressed public key without prefix).
pub fn pubkey_to_node_id(signing_key: &SigningKey) -> [u8; 64] {
    let public_key: PublicKey = signing_key.verifying_key().into();
    let pubkey_point = public_key.to_encoded_point(false);
    let mut node_id = [0u8; 64];
    node_id.copy_from_slice(&pubkey_point.as_bytes()[1..65]);
    node_id
}

/// Perform ECDH key agreement between a private key and a public key.
/// Returns the 32-byte shared secret.
pub fn ecdh(private_key: &SigningKey, public_key: &PublicKey) -> [u8; 32] {
    let shared = diffie_hellman(private_key.as_nonzero_scalar(), public_key.as_affine());
    let bytes: &[u8] = shared.raw_secret_bytes();

    let mut result: [u8; 32] = [0u8; 32];
    result.copy_from_slice(bytes);
    result
}

/// Parse a 64-byte uncompressed public key (without 0x04 prefix) into a PublicKey.
/// Returns an error if the bytes are invalid.
pub fn parse_uncompressed_pubkey(bytes: &[u8; 64]) -> Result<PublicKey, &'static str> {
    let mut uncompressed: [u8; 65] = [0u8; 65];
    uncompressed[0] = 0x04;
    uncompressed[1..].copy_from_slice(bytes);
    PublicKey::from_sec1_bytes(&uncompressed).map_err(|_| "invalid public key")
}

/// Convert a PublicKey to 64-byte uncompressed format (without 0x04 prefix).
pub fn pubkey_to_bytes(pubkey: &PublicKey) -> [u8; 64] {
    let point = pubkey.to_encoded_point(false);
    let bytes: &[u8] = point.as_bytes();
    let mut result: [u8; 64] = [0u8; 64];
    result.copy_from_slice(&bytes[1..65]);
    result
}
