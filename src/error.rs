//! Error types for PeerShark.

use std::fmt;

/// Unified error type for all proxy operations.
#[derive(Debug)]
pub enum Error {
    /// RLP encoding/decoding errors.
    Rlp(String),

    /// ECIES encryption/decryption errors.
    Ecies(String),

    /// RLPx frame encoding/decoding errors.
    Frame(String),

    /// RLPx handshake errors.
    Handshake(String),

    /// Frame size exceeds maximum allowed.
    FrameTooLarge(usize),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Rlp(msg) => write!(f, "RLP error: {}", msg),
            Error::Ecies(msg) => write!(f, "ECIES error: {}", msg),
            Error::Frame(msg) => write!(f, "frame error: {}", msg),
            Error::Handshake(msg) => write!(f, "handshake error: {}", msg),
            Error::FrameTooLarge(size) => write!(f, "frame too large: {} bytes", size),
        }
    }
}

impl std::error::Error for Error {}
