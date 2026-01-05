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

    /// Session-level errors (key derivation, message exchange).
    Session(String),

    /// P2P protocol errors (Hello, Disconnect).
    Protocol(String),

    /// Eth subprotocol errors (Status exchange).
    Eth(String),

    /// Discovery protocol errors (discv4).
    Discovery(String),

    /// DNS discovery errors (EIP-1459).
    Dns(String),

    /// Network I/O errors.
    Io(String),

    /// Connection closed by remote peer.
    ConnectionClosed,

    /// Peer disconnected with a reason.
    Disconnected(String),

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
            Error::Session(msg) => write!(f, "session error: {}", msg),
            Error::Protocol(msg) => write!(f, "protocol error: {}", msg),
            Error::Eth(msg) => write!(f, "eth error: {}", msg),
            Error::Discovery(msg) => write!(f, "discovery error: {}", msg),
            Error::Dns(msg) => write!(f, "DNS error: {}", msg),
            Error::Io(msg) => write!(f, "I/O error: {}", msg),
            Error::ConnectionClosed => write!(f, "connection closed"),
            Error::Disconnected(reason) => write!(f, "disconnected: {}", reason),
            Error::FrameTooLarge(size) => write!(f, "frame too large: {} bytes", size),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}
