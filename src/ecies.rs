use aes::Aes128;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use k256::PublicKey;
use k256::ecdsa::SigningKey;
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::crypto::ecdh;
use crate::error::Error;

type Aes128Ctr = ctr::Ctr64BE<Aes128>;
type HmacSha256 = Hmac<Sha256>;

/// Encrypt a message using ECIES (Elliptic Curve Integrated Encryption Scheme).
/// Returns the encrypted message with ephemeral public key, IV, ciphertext, and MAC.
pub fn encrypt(
    recipient_pubkey: &PublicKey,
    message: &[u8],
    shared_mac_data: Option<&[u8]>,
) -> Vec<u8> {
    let ephemeral_key: SigningKey = SigningKey::random(&mut rand::thread_rng());
    let ephemeral_pubkey = ephemeral_key.verifying_key();

    let shared_secret: [u8; 32] = ecdh(&ephemeral_key, recipient_pubkey);

    let derived: [u8; 32] = kdf(&shared_secret);
    let aes_key: &[u8] = &derived[0..16];
    let mac_key_raw: &[u8] = &derived[16..32];

    let mut mac_hasher = Sha256::new();
    mac_hasher.update(mac_key_raw);
    let mac_key: [u8; 32] = mac_hasher.finalize().into();

    let mut iv: [u8; 16] = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let ciphertext: Vec<u8> = aes_ctr_encrypt(aes_key, &iv, message);

    let mut hmac_input: Vec<u8> = Vec::new();
    hmac_input.extend_from_slice(&iv);
    hmac_input.extend_from_slice(&ciphertext);
    if let Some(data) = shared_mac_data {
        hmac_input.extend_from_slice(data);
    }
    let tag: [u8; 32] = hmac_sha256(&mac_key, &hmac_input);

    let ephemeral_bytes = ephemeral_pubkey.to_encoded_point(false);

    let mut result: Vec<u8> = Vec::new();
    result.extend_from_slice(ephemeral_bytes.as_bytes());
    result.extend_from_slice(&iv);
    result.extend_from_slice(&ciphertext);
    result.extend_from_slice(&tag);
    result
}

fn kdf(shared_secret: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0u8, 0u8, 0u8, 1u8]);
    hasher.update(shared_secret);
    hasher.finalize().into()
}

fn aes_ctr_encrypt(key: &[u8], iv: &[u8; 16], plaintext: &[u8]) -> Vec<u8> {
    let mut cipher = Aes128Ctr::new(key.into(), iv.into());
    let mut buffer: Vec<u8> = plaintext.to_vec();
    cipher.apply_keystream(&mut buffer);
    buffer
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key size");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Decrypt an ECIES-encrypted message.
/// Returns the decrypted plaintext or an error if decryption fails.
pub fn decrypt(
    private_key: &SigningKey,
    encrypted: &[u8],
    shared_mac_data: Option<&[u8]>,
) -> Result<Vec<u8>, Error> {
    if encrypted.len() < 65 + 16 + 32 {
        return Err(Error::Ecies("encrypted message too short".to_string()));
    }

    let ephemeral_pubkey_bytes: &[u8] = &encrypted[0..65];
    let iv: &[u8] = &encrypted[65..81];
    let ciphertext: &[u8] = &encrypted[81..encrypted.len() - 32];
    let tag: &[u8] = &encrypted[encrypted.len() - 32..];

    let ephemeral_pubkey: PublicKey = PublicKey::from_sec1_bytes(ephemeral_pubkey_bytes)
        .map_err(|_| Error::Ecies("invalid ephemeral public key".to_string()))?;

    let shared_secret: [u8; 32] = ecdh(private_key, &ephemeral_pubkey);

    let derived: [u8; 32] = kdf(&shared_secret);
    let aes_key: &[u8] = &derived[0..16];
    let mac_key_raw: &[u8] = &derived[16..32];

    let mut mac_hasher = Sha256::new();
    mac_hasher.update(mac_key_raw);
    let mac_key: [u8; 32] = mac_hasher.finalize().into();

    let mut hmac_input: Vec<u8> = Vec::new();
    hmac_input.extend_from_slice(iv);
    hmac_input.extend_from_slice(ciphertext);
    if let Some(data) = shared_mac_data {
        hmac_input.extend_from_slice(data);
    }
    let expected_tag: [u8; 32] = hmac_sha256(&mac_key, &hmac_input);

    if tag != expected_tag {
        return Err(Error::Ecies("HMAC verification failed".to_string()));
    }

    let iv_array: [u8; 16] = iv.try_into().expect("IV slice is exactly 16 bytes");
    let plaintext: Vec<u8> = aes_ctr_decrypt(aes_key, &iv_array, ciphertext);

    Ok(plaintext)
}

fn aes_ctr_decrypt(key: &[u8], iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let mut cipher = Aes128Ctr::new(key.into(), iv.into());
    let mut buffer: Vec<u8> = ciphertext.to_vec();
    cipher.apply_keystream(&mut buffer);
    buffer
}
