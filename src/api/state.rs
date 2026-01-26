use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::sync::RwLock;

use crate::events::now_millis;
use crate::peer_pool::FailureKind;

/// Maximum number of concurrent WebSocket connections.
pub const MAX_WS_CONNECTIONS: usize = 50;

/// Maximum peer attempts to keep per connection (matches MAX_PEER_RETRIES).
pub const MAX_ATTEMPTS_PER_CONNECTION: usize = 10;

/// Global rate counter using dual-buffer approach for stable readings.
/// Reports rate based on the PREVIOUS complete window to avoid
/// unstable values from partial windows.
pub struct RateCounter {
    /// Count of messages in the current (incomplete) window
    current_count: AtomicU64,
    /// Count from the previous complete window
    previous_count: AtomicU64,
    /// Timestamp (epoch millis) when current window started
    window_start_ms: AtomicU64,
    /// Duration of each window in milliseconds
    window_ms: u64,
}

impl RateCounter {
    /// Create a new rate counter with the specified window duration.
    pub fn new(window_secs: u64) -> Self {
        Self {
            current_count: AtomicU64::new(0),
            previous_count: AtomicU64::new(0),
            window_start_ms: AtomicU64::new(now_millis() as u64),
            window_ms: window_secs * 1000,
        }
    }

    /// Record a message. Call this for each MessageRelayed event.
    pub fn record(&self) {
        let now = now_millis() as u64;
        let window_start = self.window_start_ms.load(Ordering::Relaxed);

        if now.saturating_sub(window_start) >= self.window_ms {
            // Window complete: rotate buffers
            let current = self.current_count.swap(1, Ordering::Relaxed);
            self.previous_count.store(current, Ordering::Relaxed);
            self.window_start_ms.store(now, Ordering::Relaxed);
        } else {
            // Within window: just increment
            self.current_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get the current rate in messages per second.
    /// Returns rate based on the last COMPLETE window for stability.
    pub fn rate(&self) -> f64 {
        let prev = self.previous_count.load(Ordering::Relaxed);
        (prev as f64 * 1000.0) / self.window_ms as f64
    }
}

/// Connection status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStatus {
    /// Client connected, looking for real peer.
    Connecting,
    /// Real peer connected, relay active.
    Active,
}

/// Status of a peer connection attempt.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AttemptStatus {
    InProgress,
    Rejected {
        reason: String,
        failure_kind: String,
    },
    Success,
}

/// A single peer connection attempt.
#[derive(Debug, Clone, Serialize)]
pub struct PeerAttempt {
    pub peer_node_id: String,
    pub peer_address: String,
    pub attempt_number: u32,
    pub status: AttemptStatus,
    pub started_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<i64>,
}

/// Information about a single connection through a tunneled peer.
#[derive(Debug)]
pub struct ConnectionInfo {
    pub tunneled_peer_id: String,
    pub status: ConnectionStatus,
    pub connected_at: i64,
    pub attempts: Vec<PeerAttempt>,
    pub remote_node_id: Option<String>,
    pub remote_address: Option<String>,
    /// Remote peer's client identifier (e.g., "geth/v1.13.0").
    pub remote_client_id: Option<String>,
    /// EIP-2124 fork hash (CRC32 of genesis + past fork blocks), hex encoded.
    pub fork_hash: Option<String>,
    /// EIP-2124 next fork block number, or 0 if none known.
    pub fork_next: Option<u64>,
    pub capabilities: Option<Vec<String>>,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub messages_relayed: AtomicU64,
}

impl ConnectionInfo {
    fn new(tunneled_peer_id: String) -> Self {
        Self {
            tunneled_peer_id,
            status: ConnectionStatus::Connecting,
            connected_at: now_millis(),
            attempts: Vec::new(),
            remote_node_id: None,
            remote_address: None,
            remote_client_id: None,
            fork_hash: None,
            fork_next: None,
            capabilities: None,
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            messages_relayed: AtomicU64::new(0),
        }
    }
}

/// Information about a connected client.
#[derive(Debug)]
pub struct ClientInfo {
    pub client_node_id: String,
    pub client_id: String,
    pub first_seen: i64,
    /// Connections keyed by tunnel_id.
    pub connections: HashMap<String, ConnectionInfo>,
}

impl ClientInfo {
    fn new(client_node_id: String, client_id: String) -> Self {
        Self {
            client_node_id,
            client_id,
            first_seen: now_millis(),
            connections: HashMap::new(),
        }
    }
}

/// Shared state for the API server.
#[derive(Clone)]
pub struct ApiState {
    /// Timestamp when the server started collecting events.
    pub collecting_since: i64,
    /// Active clients keyed by client_node_id.
    pub clients: Arc<RwLock<HashMap<String, ClientInfo>>>,
    /// JWT secret for authentication (None if auth disabled).
    pub jwt_secret: Option<Arc<Vec<u8>>>,
    /// Current number of WebSocket connections.
    pub ws_connections: Arc<AtomicUsize>,
    /// Global message rate counter (10-second window).
    pub global_rate: Arc<RateCounter>,
}

impl ApiState {
    /// Create a new API state (authentication disabled).
    pub fn new(_jwt_secret: Vec<u8>) -> Self {
        Self {
            collecting_since: now_millis(),
            clients: Arc::new(RwLock::new(HashMap::new())),
            jwt_secret: None,
            ws_connections: Arc::new(AtomicUsize::new(0)),
            global_rate: Arc::new(RateCounter::new(10)),
        }
    }

    /// Add a client connection when ClientConnected event is received.
    pub async fn add_client_connection(
        &self,
        client_node_id: &str,
        client_id: &str,
        tunnel_id: &str,
    ) {
        let mut clients = self.clients.write().await;
        let client = clients
            .entry(client_node_id.to_string())
            .or_insert_with(|| ClientInfo::new(client_node_id.to_string(), client_id.to_string()));

        // Update client_id if changed
        if client.client_id != client_id {
            client.client_id = client_id.to_string();
        }

        client.connections.insert(
            tunnel_id.to_string(),
            ConnectionInfo::new(tunnel_id.to_string()),
        );
    }

    /// Add a peer attempt when PeerConnecting event is received.
    pub async fn add_peer_attempt(
        &self,
        client_node_id: &str,
        tunnel_id: &str,
        peer_node_id: &str,
        peer_address: &str,
        attempt_number: u32,
    ) {
        let mut clients = self.clients.write().await;
        if let Some(client) = clients.get_mut(client_node_id)
            && let Some(conn) = client.connections.get_mut(tunnel_id)
        {
            // Limit attempts to prevent unbounded growth
            if conn.attempts.len() >= MAX_ATTEMPTS_PER_CONNECTION {
                conn.attempts.remove(0);
            }
            conn.attempts.push(PeerAttempt {
                peer_node_id: peer_node_id.to_string(),
                peer_address: peer_address.to_string(),
                attempt_number,
                status: AttemptStatus::InProgress,
                started_at: now_millis(),
                ended_at: None,
            });
        }
    }

    /// Mark the last attempt as rejected when PeerRejected event is received.
    pub async fn mark_attempt_rejected(
        &self,
        client_node_id: &str,
        tunnel_id: &str,
        reason: &str,
        failure_kind: &FailureKind,
    ) {
        let mut clients = self.clients.write().await;
        if let Some(client) = clients.get_mut(client_node_id)
            && let Some(conn) = client.connections.get_mut(tunnel_id)
            && let Some(attempt) = conn.attempts.last_mut()
        {
            attempt.status = AttemptStatus::Rejected {
                reason: reason.to_string(),
                failure_kind: format!("{:?}", failure_kind),
            };
            attempt.ended_at = Some(now_millis());
        }
    }

    /// Activate connection when PeerConnected event is received.
    #[allow(clippy::too_many_arguments)]
    pub async fn activate_connection(
        &self,
        client_node_id: &str,
        tunnel_id: &str,
        remote_node_id: &str,
        remote_address: &str,
        remote_client_id: &str,
        fork_hash: &str,
        fork_next: u64,
        capabilities: Vec<String>,
    ) {
        let mut clients = self.clients.write().await;
        if let Some(client) = clients.get_mut(client_node_id)
            && let Some(conn) = client.connections.get_mut(tunnel_id)
        {
            conn.status = ConnectionStatus::Active;
            conn.remote_node_id = Some(remote_node_id.to_string());
            conn.remote_address = Some(remote_address.to_string());
            conn.remote_client_id = Some(remote_client_id.to_string());
            conn.fork_hash = Some(fork_hash.to_string());
            conn.fork_next = Some(fork_next);
            conn.capabilities = Some(capabilities);

            // Mark last attempt as successful
            if let Some(attempt) = conn.attempts.last_mut() {
                attempt.status = AttemptStatus::Success;
                attempt.ended_at = Some(now_millis());
            }
        }
    }

    /// Remove connection when PeerDisconnected event is received.
    pub async fn remove_connection(&self, client_node_id: &str, tunnel_id: &str) {
        let mut clients = self.clients.write().await;
        let mut remove_client = false;

        if let Some(client) = clients.get_mut(client_node_id) {
            client.connections.remove(tunnel_id);
            if client.connections.is_empty() {
                remove_client = true;
            }
        }

        if remove_client {
            clients.remove(client_node_id);
        }
    }

    /// Record bytes transferred for a connection.
    pub async fn record_transfer(
        &self,
        client_node_id: &str,
        tunnel_id: &str,
        bytes_in: u64,
        bytes_out: u64,
    ) {
        let clients = self.clients.read().await;
        if let Some(client) = clients.get(client_node_id)
            && let Some(conn) = client.connections.get(tunnel_id)
        {
            conn.bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
            conn.bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
            conn.messages_relayed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get a snapshot of the current state for serialization.
    pub async fn snapshot(&self) -> StateSnapshot {
        let clients = self.clients.read().await;
        let client_snapshots: Vec<ClientSnapshot> = clients
            .values()
            .map(|client| {
                let connections: Vec<ConnectionSnapshot> = client
                    .connections
                    .values()
                    .map(|conn| ConnectionSnapshot {
                        tunneled_peer_id: conn.tunneled_peer_id.clone(),
                        status: conn.status,
                        connected_at: conn.connected_at,
                        attempts: conn.attempts.clone(),
                        remote_node_id: conn.remote_node_id.clone(),
                        remote_address: conn.remote_address.clone(),
                        remote_client_id: conn.remote_client_id.clone(),
                        fork_hash: conn.fork_hash.clone(),
                        fork_next: conn.fork_next,
                        capabilities: conn.capabilities.clone(),
                        bytes_in: conn.bytes_in.load(Ordering::Relaxed),
                        bytes_out: conn.bytes_out.load(Ordering::Relaxed),
                        messages_relayed: conn.messages_relayed.load(Ordering::Relaxed),
                    })
                    .collect();

                ClientSnapshot {
                    client_node_id: client.client_node_id.clone(),
                    client_id: client.client_id.clone(),
                    first_seen: client.first_seen,
                    connections,
                }
            })
            .collect();

        StateSnapshot {
            collecting_since: self.collecting_since,
            clients: client_snapshots,
            msgs_per_sec: self.global_rate.rate(),
        }
    }
}

/// Serializable snapshot of API state.
#[derive(Debug, Clone, Serialize)]
pub struct StateSnapshot {
    pub collecting_since: i64,
    pub clients: Vec<ClientSnapshot>,
    pub msgs_per_sec: f64,
}

/// Serializable snapshot of a client.
#[derive(Debug, Clone, Serialize)]
pub struct ClientSnapshot {
    pub client_node_id: String,
    pub client_id: String,
    pub first_seen: i64,
    pub connections: Vec<ConnectionSnapshot>,
}

/// Serializable snapshot of a connection.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionSnapshot {
    pub tunneled_peer_id: String,
    pub status: ConnectionStatus,
    pub connected_at: i64,
    pub attempts: Vec<PeerAttempt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_node_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_address: Option<String>,
    /// Remote peer's client identifier (e.g., "geth/v1.13.0").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_client_id: Option<String>,
    /// EIP-2124 fork hash (CRC32 of genesis + past fork blocks), hex encoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fork_hash: Option<String>,
    /// EIP-2124 next fork block number, or 0 if none known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fork_next: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub messages_relayed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn add_client_connection_and_snapshot() {
        let state = ApiState::new(vec![0u8; 32]);

        state
            .add_client_connection(
                "deadbeef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
                "besu/v24.1.0",
                "tunnel1",
            )
            .await;

        let snapshot = state.snapshot().await;
        assert_eq!(snapshot.clients.len(), 1);
        assert_eq!(snapshot.clients[0].client_id, "besu/v24.1.0");
        assert_eq!(snapshot.clients[0].connections.len(), 1);
        assert_eq!(
            snapshot.clients[0].connections[0].status,
            ConnectionStatus::Connecting
        );
    }

    #[tokio::test]
    async fn add_peer_attempt_and_mark_rejected() {
        let state = ApiState::new(vec![0u8; 32]);
        let client_id = "deadbeef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

        state
            .add_client_connection(client_id, "besu", "tunnel1")
            .await;

        state
            .add_peer_attempt(client_id, "tunnel1", "peer123", "192.168.1.100:30303", 1)
            .await;

        let snapshot = state.snapshot().await;
        assert_eq!(snapshot.clients[0].connections[0].attempts.len(), 1);
        assert!(matches!(
            snapshot.clients[0].connections[0].attempts[0].status,
            AttemptStatus::InProgress
        ));

        state
            .mark_attempt_rejected(client_id, "tunnel1", "timeout", &FailureKind::Timeout)
            .await;

        let snapshot = state.snapshot().await;
        assert!(matches!(
            snapshot.clients[0].connections[0].attempts[0].status,
            AttemptStatus::Rejected { .. }
        ));
    }

    #[tokio::test]
    async fn activate_connection() {
        let state = ApiState::new(vec![0u8; 32]);
        let client_id = "deadbeef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

        state
            .add_client_connection(client_id, "besu", "tunnel1")
            .await;

        state
            .add_peer_attempt(client_id, "tunnel1", "peer123", "192.168.1.100:30303", 1)
            .await;

        state
            .activate_connection(
                client_id,
                "tunnel1",
                "peer123",
                "192.168.1.100:30303",
                "geth/v1.13.0",
                "fc64ec04",
                1150000,
                vec!["eth/68".to_string()],
            )
            .await;

        let snapshot = state.snapshot().await;
        assert_eq!(
            snapshot.clients[0].connections[0].status,
            ConnectionStatus::Active
        );
        assert_eq!(
            snapshot.clients[0].connections[0].remote_node_id,
            Some("peer123".to_string())
        );
        assert!(matches!(
            snapshot.clients[0].connections[0].attempts[0].status,
            AttemptStatus::Success
        ));
    }

    #[tokio::test]
    async fn remove_connection_cleans_up_empty_client() {
        let state = ApiState::new(vec![0u8; 32]);
        let client_id = "deadbeef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

        state
            .add_client_connection(client_id, "besu", "tunnel1")
            .await;

        let snapshot = state.snapshot().await;
        assert_eq!(snapshot.clients.len(), 1);

        state.remove_connection(client_id, "tunnel1").await;

        let snapshot = state.snapshot().await;
        assert_eq!(snapshot.clients.len(), 0);
    }

    #[tokio::test]
    async fn record_transfer_updates_stats() {
        let state = ApiState::new(vec![0u8; 32]);
        let client_id = "deadbeef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

        state
            .add_client_connection(client_id, "besu", "tunnel1")
            .await;

        state.record_transfer(client_id, "tunnel1", 100, 200).await;
        state.record_transfer(client_id, "tunnel1", 50, 75).await;

        let snapshot = state.snapshot().await;
        assert_eq!(snapshot.clients[0].connections[0].bytes_in, 150);
        assert_eq!(snapshot.clients[0].connections[0].bytes_out, 275);
        assert_eq!(snapshot.clients[0].connections[0].messages_relayed, 2);
    }

    #[test]
    fn rate_counter_initial_zero() {
        let counter = RateCounter::new(10);
        assert_eq!(counter.rate(), 0.0);
    }

    #[test]
    fn rate_counter_records_messages() {
        let counter = RateCounter::new(10);
        for _ in 0..50 {
            counter.record();
        }
        // Rate is still 0 until first window completes
        assert_eq!(counter.rate(), 0.0);
    }

    #[tokio::test]
    async fn multiple_connections_per_client() {
        let state = ApiState::new(vec![0u8; 32]);
        let client_id = "deadbeef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

        state
            .add_client_connection(client_id, "besu", "tunnel1")
            .await;
        state
            .add_client_connection(client_id, "besu", "tunnel2")
            .await;

        let snapshot = state.snapshot().await;
        assert_eq!(snapshot.clients.len(), 1);
        assert_eq!(snapshot.clients[0].connections.len(), 2);
    }
}
