//! Utilities for encoding and decoding integers to/from big-endian bytes.
//!
//! These functions use minimal encoding (no leading zeros), which is required
//! for RLP-compatible integer representation.

/// Encode a u16 as big-endian bytes with minimal encoding (no leading zeros).
pub fn encode_u16(value: u16) -> Vec<u8> {
    if value == 0 {
        vec![]
    } else if value < 256 {
        vec![value as u8]
    } else {
        value.to_be_bytes().to_vec()
    }
}

/// Decode big-endian bytes to u16 (handles 0-2 bytes).
pub fn decode_u16(bytes: &[u8]) -> u16 {
    match bytes.len() {
        0 => 0,
        1 => bytes[0] as u16,
        _ => ((bytes[0] as u16) << 8) | (bytes[1] as u16),
    }
}

/// Encode a u32 as big-endian bytes with minimal encoding (no leading zeros).
pub fn encode_u32(value: u32) -> Vec<u8> {
    if value == 0 {
        return vec![];
    }
    let bytes: [u8; 4] = value.to_be_bytes();
    let start: usize = bytes.iter().position(|&b| b != 0).unwrap_or(4);
    bytes[start..].to_vec()
}

/// Decode big-endian bytes to u32 (handles 0-4 bytes).
pub fn decode_u32(bytes: &[u8]) -> u32 {
    let mut result: u32 = 0;
    for &b in bytes {
        result = (result << 8) | (b as u32);
    }
    result
}

/// Encode a u64 as big-endian bytes with minimal encoding (no leading zeros).
pub fn encode_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![];
    }
    let bytes: [u8; 8] = value.to_be_bytes();
    let start: usize = bytes.iter().position(|&b| b != 0).unwrap_or(8);
    bytes[start..].to_vec()
}

/// Decode big-endian bytes to u64 (handles 0-8 bytes).
pub fn decode_u64(bytes: &[u8]) -> u64 {
    let mut result: u64 = 0;
    for &b in bytes {
        result = (result << 8) | (b as u64);
    }
    result
}
