use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::sync::RwLock;

use crate::events::now_millis;

/// Maximum number of concurrent WebSocket connections.
pub const MAX_WS_CONNECTIONS: usize = 50;

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

/// Shared state for the API server.
#[derive(Clone)]
pub struct ApiState {
    /// Timestamp when the server started collecting events.
    pub collecting_since: i64,
    /// Active tunnel information.
    pub tunnels: Arc<RwLock<HashMap<String, TunnelInfo>>>,
    /// JWT secret for authentication (None if auth disabled).
    pub jwt_secret: Option<Arc<Vec<u8>>>,
    /// Current number of WebSocket connections.
    pub ws_connections: Arc<AtomicUsize>,
    /// Global message rate counter (10-second window).
    pub global_rate: Arc<RateCounter>,
}

impl ApiState {
    /// Create a new API state with authentication.
    pub fn new(jwt_secret: Vec<u8>) -> Self {
        Self {
            collecting_since: now_millis(),
            tunnels: Arc::new(RwLock::new(HashMap::new())),
            jwt_secret: Some(Arc::new(jwt_secret)),
            ws_connections: Arc::new(AtomicUsize::new(0)),
            global_rate: Arc::new(RateCounter::new(10)),
        }
    }

    /// Create a new API state without authentication.
    pub fn new_no_auth() -> Self {
        Self {
            collecting_since: now_millis(),
            tunnels: Arc::new(RwLock::new(HashMap::new())),
            jwt_secret: None,
            ws_connections: Arc::new(AtomicUsize::new(0)),
            global_rate: Arc::new(RateCounter::new(10)),
        }
    }

    /// Add a new tunnel.
    ///
    /// Takes individual fields from the PeerConnected event rather than a struct
    /// to avoid an intermediate type that would duplicate TunnelInfo's fields.
    #[allow(clippy::too_many_arguments)]
    pub async fn add_tunnel(
        &self,
        tunnel_id: String,
        client_node_id: String,
        client_id: String,
        remote_enode: String,
        network_id: u64,
        fork_hash: String,
        fork_next: u64,
        capabilities: Vec<String>,
    ) {
        let info = TunnelInfo::new(
            client_node_id,
            client_id,
            remote_enode,
            network_id,
            fork_hash,
            fork_next,
            capabilities,
        );
        self.tunnels.write().await.insert(tunnel_id, info);
    }

    /// Remove a tunnel by ID.
    pub async fn remove_tunnel(&self, tunnel_id: &str) {
        self.tunnels.write().await.remove(tunnel_id);
    }

    /// Record bytes transferred for a tunnel.
    pub async fn record_transfer(&self, tunnel_id: &str, bytes_in: u64, bytes_out: u64) {
        if let Some(tunnel) = self.tunnels.read().await.get(tunnel_id) {
            tunnel.bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
            tunnel.bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
            tunnel.messages_relayed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get a snapshot of the current state for serialization.
    pub async fn snapshot(&self) -> StateSnapshot {
        let tunnels = self.tunnels.read().await;
        let tunnel_snapshots: Vec<TunnelSnapshot> = tunnels
            .iter()
            .map(|(id, info)| TunnelSnapshot {
                tunnel_id: id.clone(),
                client_node_id: info.client_node_id.clone(),
                client_id: info.client_id.clone(),
                remote_enode: info.remote_enode.clone(),
                network_id: info.network_id,
                fork_hash: info.fork_hash.clone(),
                fork_next: info.fork_next,
                capabilities: info.capabilities.clone(),
                connected_at: info.connected_at,
                bytes_in: info.bytes_in.load(Ordering::Relaxed),
                bytes_out: info.bytes_out.load(Ordering::Relaxed),
                messages_relayed: info.messages_relayed.load(Ordering::Relaxed),
            })
            .collect();

        StateSnapshot {
            collecting_since: self.collecting_since,
            tunnels: tunnel_snapshots,
            msgs_per_sec: self.global_rate.rate(),
        }
    }
}

/// Information about an active tunnel.
pub struct TunnelInfo {
    /// Node ID of the client (full 64 bytes hex-encoded).
    pub client_node_id: String,
    pub client_id: String,
    pub remote_enode: String,
    pub network_id: u64,
    /// EIP-2124 fork hash (CRC32 of genesis + past fork blocks), hex encoded.
    pub fork_hash: String,
    /// EIP-2124 next fork block number, or 0 if none known.
    pub fork_next: u64,
    pub capabilities: Vec<String>,
    pub connected_at: i64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub messages_relayed: AtomicU64,
}

impl TunnelInfo {
    fn new(
        client_node_id: String,
        client_id: String,
        remote_enode: String,
        network_id: u64,
        fork_hash: String,
        fork_next: u64,
        capabilities: Vec<String>,
    ) -> Self {
        Self {
            client_node_id,
            client_id,
            remote_enode,
            network_id,
            fork_hash,
            fork_next,
            capabilities,
            connected_at: now_millis(),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            messages_relayed: AtomicU64::new(0),
        }
    }
}

/// Serializable snapshot of API state.
#[derive(Debug, Clone, Serialize)]
pub struct StateSnapshot {
    pub collecting_since: i64,
    pub tunnels: Vec<TunnelSnapshot>,
    pub msgs_per_sec: f64,
}

/// Serializable snapshot of a tunnel.
#[derive(Debug, Clone, Serialize)]
pub struct TunnelSnapshot {
    pub tunnel_id: String,
    /// Node ID of the client (full 64 bytes hex-encoded).
    pub client_node_id: String,
    pub client_id: String,
    pub remote_enode: String,
    pub network_id: u64,
    /// EIP-2124 fork hash (CRC32 of genesis + past fork blocks), hex encoded.
    pub fork_hash: String,
    /// EIP-2124 next fork block number, or 0 if none known.
    pub fork_next: u64,
    pub capabilities: Vec<String>,
    pub connected_at: i64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub messages_relayed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn add_and_remove_tunnel() {
        let state = ApiState::new(vec![0u8; 32]);

        state
            .add_tunnel(
                "t1".to_string(),
                "deadbeef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
                "besu".to_string(),
                "enode://abc".to_string(),
                1,
                "fc64ec04".to_string(),
                1150000,
                vec!["eth/68".to_string()],
            )
            .await;

        let snapshot = state.snapshot().await;
        assert_eq!(snapshot.tunnels.len(), 1);
        assert_eq!(snapshot.tunnels[0].tunnel_id, "t1");
        assert_eq!(snapshot.tunnels[0].fork_hash, "fc64ec04");
        assert_eq!(snapshot.tunnels[0].fork_next, 1150000);
        assert_eq!(snapshot.tunnels[0].capabilities, vec!["eth/68"]);

        state.remove_tunnel("t1").await;
        let snapshot = state.snapshot().await;
        assert_eq!(snapshot.tunnels.len(), 0);
    }

    #[tokio::test]
    async fn record_transfer_updates_stats() {
        let state = ApiState::new(vec![0u8; 32]);

        state
            .add_tunnel(
                "t1".to_string(),
                "deadbeef00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".to_string(),
                "besu".to_string(),
                "enode://abc".to_string(),
                1,
                "fc64ec04".to_string(),
                0,
                vec![],
            )
            .await;

        state.record_transfer("t1", 100, 200).await;
        state.record_transfer("t1", 50, 75).await;

        let snapshot = state.snapshot().await;
        assert_eq!(snapshot.tunnels[0].bytes_in, 150);
        assert_eq!(snapshot.tunnels[0].bytes_out, 275);
        assert_eq!(snapshot.tunnels[0].messages_relayed, 2);
    }

    #[test]
    fn rate_counter_initial_zero() {
        let counter = RateCounter::new(10);
        // Before any complete window, rate is 0
        assert_eq!(counter.rate(), 0.0);
    }

    #[test]
    fn rate_counter_records_messages() {
        let counter = RateCounter::new(10);
        for _ in 0..50 {
            counter.record();
        }
        // Rate is still 0 until first window completes
        // (previous_count starts at 0)
        assert_eq!(counter.rate(), 0.0);
    }
}
