//! Constants used throughout PeerShark.

use std::time::Duration;

/// Timeout waiting for Status message from peer during handshake.
pub const STATUS_EXCHANGE_TIMEOUT: Duration = Duration::from_millis(500);

/// Maximum length of enode URL to display in logs (truncated for readability).
pub const ENODE_DISPLAY_LEN: usize = 50;

/// Maximum number of peer connection attempts before giving up.
pub const MAX_PEER_RETRIES: usize = 10;

/// Default maximum number of unique clients that can connect.
pub const DEFAULT_MAX_CLIENTS: usize = 10;

/// Size of a node ID (uncompressed public key without prefix).
pub const NODE_ID_LEN: usize = 64;

/// Size of a private key.
pub const PRIVATE_KEY_LEN: usize = 32;

/// Grace period to wait after sending DISCONNECT before closing connections.
pub const SHUTDOWN_GRACE_PERIOD: Duration = Duration::from_millis(500);

// ---- RLPx Frame Constants ----

/// Size of the RLPx frame header (encrypted).
pub const FRAME_HEADER_SIZE: usize = 16;

/// Size of the MAC tag appended to header and body.
pub const FRAME_MAC_SIZE: usize = 16;

/// Total size of frame header with MAC (header + MAC).
pub const FRAME_HEADER_WITH_MAC_SIZE: usize = FRAME_HEADER_SIZE + FRAME_MAC_SIZE;

/// Maximum allowed frame size (4 MB).
/// Prevents memory exhaustion from malicious peers sending huge frame sizes.
pub const MAX_FRAME_SIZE: usize = 4 * 1024 * 1024;

/// Maximum idle time before disconnecting a tunnel (60 seconds).
/// Prevents zombie connections from consuming resources.
pub const TUNNEL_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum time allowed for RLPx handshake (10 seconds).
/// Prevents Slowloris attacks that hold connections open without completing handshake.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// RLP header byte for empty list with 2 elements (capabilities placeholder).
pub const RLP_EMPTY_LIST_2: u8 = 0xc2;

/// RLP header byte for empty bytes.
pub const RLP_EMPTY_BYTES: u8 = 0x80;

// ---- discv4 Protocol Constants ----

/// Expiration time for discovery messages in seconds.
pub const DISCV4_EXPIRATION_SECS: u64 = 60;

/// Maximum UDP packet size for discovery protocol.
pub const DISCV4_MAX_PACKET_SIZE: usize = 1280;

/// Size of hash in discovery packets (Keccak256).
pub const HASH_SIZE: usize = 32;

/// Size of ECDSA signature with recovery id.
pub const SIGNATURE_SIZE: usize = 65;

// ---- ECIES Constants ----

/// ECIES encryption overhead: ephemeral pubkey (65) + IV (16) + MAC (32).
pub const ECIES_OVERHEAD: usize = 65 + 16 + 32;

// ---- Peer Scoring Constants ----

/// Score threshold below which a peer is considered temporarily banned.
/// A peer at or below this score will not be selected for new connections.
pub const PEER_SCORE_THRESHOLD: i32 = -10;

/// Time in seconds to recover 1 point of score.
/// After 5 minutes of not being penalized, a peer recovers 1 point.
pub const PEER_SCORE_RECOVERY_SECS: u64 = 300;
