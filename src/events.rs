use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::peer_pool::FailureKind;

/// Returns current time as Unix milliseconds.
pub fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before Unix epoch")
        .as_millis() as i64
}

/// Direction of a relayed message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    ClientToPeer,
    PeerToClient,
}

/// Protocol that a message belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    P2p,
    Eth,
    Unknown,
}

/// Get the human-readable name for a message ID and protocol.
pub fn msg_name(msg_id: u8, protocol: Protocol) -> String {
    match protocol {
        Protocol::P2p => match msg_id {
            0x00 => "Hello".to_string(),
            0x01 => "Disconnect".to_string(),
            0x02 => "Ping".to_string(),
            0x03 => "Pong".to_string(),
            _ => format!("p2p:0x{:02x}", msg_id),
        },
        Protocol::Eth => match msg_id {
            0x10 => "Status".to_string(),
            0x11 => "NewBlockHashes".to_string(),
            0x12 => "Transactions".to_string(),
            0x13 => "GetBlockHeaders".to_string(),
            0x14 => "BlockHeaders".to_string(),
            0x15 => "GetBlockBodies".to_string(),
            0x16 => "BlockBodies".to_string(),
            0x17 => "NewBlock".to_string(),
            0x18 => "NewPooledTxHashes".to_string(),
            0x19 => "GetPooledTransactions".to_string(),
            0x1a => "PooledTransactions".to_string(),
            0x1f => "GetReceipts".to_string(),
            0x20 => "Receipts".to_string(),
            _ => format!("eth:0x{:02x}", msg_id),
        },
        Protocol::Unknown => format!("0x{:02x}", msg_id),
    }
}

/// Events emitted by the proxy for external consumption.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ProxyEvent {
    /// Client connected and completed Hello (we have identity).
    ClientConnected {
        tunnel_id: String,
        /// Node ID of the client (full 64 bytes hex-encoded).
        client_node_id: String,
        /// Client identifier string (e.g. "besu/v24.1.0").
        client_id: String,
        /// Capabilities announced by the client.
        capabilities: Vec<String>,
        timestamp: i64,
    },

    /// Initiating connection attempt to a real peer.
    PeerConnecting {
        tunnel_id: String,
        /// Node ID of the client (full 64 bytes hex-encoded).
        client_node_id: String,
        /// Node ID of the target peer (full 64 bytes hex-encoded).
        peer_node_id: String,
        /// Address of the target peer ("host:port").
        peer_address: String,
        /// Attempt number (1-based).
        attempt_number: u32,
        timestamp: i64,
    },

    /// Peer rejected or connection failed.
    PeerRejected {
        tunnel_id: String,
        /// Node ID of the client (full 64 bytes hex-encoded).
        client_node_id: String,
        /// Node ID of the peer that rejected (full 64 bytes hex-encoded).
        peer_node_id: String,
        /// Address of the peer ("host:port").
        peer_address: String,
        /// Human-readable failure reason.
        reason: String,
        /// Failure category for filtering and scoring.
        failure_kind: FailureKind,
        /// Attempt number (1-based).
        attempt_number: u32,
        timestamp: i64,
    },

    /// A new tunnel was established between client and remote peer.
    PeerConnected {
        tunnel_id: String,
        /// Node ID of the client (full 64 bytes hex-encoded).
        client_node_id: String,
        /// Node ID of the remote peer (full 64 bytes hex-encoded).
        remote_node_id: String,
        /// Address of the remote peer ("host:port").
        remote_address: String,
        /// Remote peer's client identifier (e.g., "geth/v1.13.0").
        remote_client_id: String,
        network_id: u64,
        /// EIP-2124 fork hash (CRC32 of genesis + past fork blocks), hex encoded.
        fork_hash: String,
        /// EIP-2124 next fork block number, or 0 if none known.
        fork_next: u64,
        capabilities: Vec<String>,
        timestamp: i64,
    },

    /// A tunnel was closed.
    PeerDisconnected {
        tunnel_id: String,
        /// Node ID of the client (full 64 bytes hex-encoded).
        client_node_id: String,
        /// Node ID of the remote peer (full 64 bytes hex-encoded).
        remote_node_id: String,
        reason: String,
        timestamp: i64,
    },

    /// A message was relayed through a tunnel.
    MessageRelayed {
        tunnel_id: String,
        /// Node ID of the client (full 64 bytes hex-encoded).
        client_node_id: String,
        direction: Direction,
        msg_id: u8,
        msg_name: String,
        protocol: Protocol,
        size: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        raw: Option<String>,
        timestamp: i64,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_millis_returns_reasonable_value() {
        let ts = now_millis();
        // Should be after 2024-01-01 (1704067200000 ms)
        assert!(ts > 1_704_067_200_000);
        // Should be before 2100-01-01
        assert!(ts < 4_102_444_800_000);
    }

    #[test]
    fn client_connected_serializes_correctly() {
        let event = ProxyEvent::ClientConnected {
            tunnel_id: "abc123".to_string(),
            client_node_id: "deadbeef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            client_id: "besu/v24.1.0".to_string(),
            capabilities: vec!["eth/68".to_string(), "snap/1".to_string()],
            timestamp: 1704067200000,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"client_connected\""));
        assert!(json.contains("\"tunnel_id\":\"abc123\""));
        assert!(json.contains("\"client_id\":\"besu/v24.1.0\""));
    }

    #[test]
    fn peer_connecting_serializes_correctly() {
        let event = ProxyEvent::PeerConnecting {
            tunnel_id: "abc123".to_string(),
            client_node_id: "deadbeef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            peer_node_id: "1122334400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            peer_address: "192.168.1.100:30303".to_string(),
            attempt_number: 1,
            timestamp: 1704067200000,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"peer_connecting\""));
        assert!(json.contains("\"peer_address\":\"192.168.1.100:30303\""));
        assert!(json.contains("\"attempt_number\":1"));
    }

    #[test]
    fn peer_rejected_serializes_correctly() {
        let event = ProxyEvent::PeerRejected {
            tunnel_id: "abc123".to_string(),
            client_node_id: "deadbeef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            peer_node_id: "1122334400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            peer_address: "192.168.1.100:30303".to_string(),
            reason: "connection refused".to_string(),
            failure_kind: FailureKind::ConnectionRefused,
            attempt_number: 1,
            timestamp: 1704067200000,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"peer_rejected\""));
        assert!(json.contains("\"failure_kind\":\"connection_refused\""));
        assert!(json.contains("\"attempt_number\":1"));
    }

    #[test]
    fn peer_connected_serializes_correctly() {
        let event = ProxyEvent::PeerConnected {
            tunnel_id: "abc123".to_string(),
            client_node_id: "deadbeef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            remote_node_id: "aabbccdd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            remote_address: "1.2.3.4:30303".to_string(),
            remote_client_id: "geth/v1.13.0".to_string(),
            network_id: 1,
            fork_hash: "fc64ec04".to_string(),
            fork_next: 1150000,
            capabilities: vec!["eth/68".to_string(), "snap/1".to_string()],
            timestamp: 1704067200000,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"peer_connected\""));
        assert!(json.contains("\"tunnel_id\":\"abc123\""));
        assert!(json.contains("\"remote_node_id\":\"aabbccdd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\""));
        assert!(json.contains("\"remote_address\":\"1.2.3.4:30303\""));
        assert!(json.contains("\"remote_client_id\":\"geth/v1.13.0\""));
        assert!(json.contains("\"network_id\":1"));
        assert!(json.contains("\"fork_hash\":\"fc64ec04\""));
        assert!(json.contains("\"fork_next\":1150000"));
    }

    #[test]
    fn message_relayed_omits_null_raw() {
        let event = ProxyEvent::MessageRelayed {
            tunnel_id: "abc123".to_string(),
            client_node_id: "deadbeef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            direction: Direction::ClientToPeer,
            msg_id: 0x13,
            msg_name: "GetBlockHeaders".to_string(),
            protocol: Protocol::Eth,
            size: 128,
            raw: None,
            timestamp: 1704067200000,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(!json.contains("\"raw\""));
        assert!(json.contains("\"msg_name\":\"GetBlockHeaders\""));
    }

    #[test]
    fn peer_disconnected_serializes_correctly() {
        let event = ProxyEvent::PeerDisconnected {
            tunnel_id: "abc123".to_string(),
            client_node_id: "deadbeef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            remote_node_id: "aabbccdd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
            reason: "client quit".to_string(),
            timestamp: 1704067200000,
        };

        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"type\":\"peer_disconnected\""));
        assert!(json.contains("\"remote_node_id\":\"aabbccdd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\""));
        assert!(json.contains("\"reason\":\"client quit\""));
    }

    #[test]
    fn msg_name_returns_correct_names() {
        assert_eq!(msg_name(0x00, Protocol::P2p), "Hello");
        assert_eq!(msg_name(0x10, Protocol::Eth), "Status");
        assert_eq!(msg_name(0x13, Protocol::Eth), "GetBlockHeaders");
        assert_eq!(msg_name(0xFF, Protocol::Unknown), "0xff");
    }
}
