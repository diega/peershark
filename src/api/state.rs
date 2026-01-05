use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use tokio::sync::RwLock;

use crate::events::now_millis;

/// Maximum number of concurrent WebSocket connections.
pub const MAX_WS_CONNECTIONS: usize = 50;

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
}

impl ApiState {
    /// Create a new API state with authentication.
    pub fn new(jwt_secret: Vec<u8>) -> Self {
        Self {
            collecting_since: now_millis(),
            tunnels: Arc::new(RwLock::new(HashMap::new())),
            jwt_secret: Some(Arc::new(jwt_secret)),
            ws_connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Create a new API state without authentication.
    pub fn new_no_auth() -> Self {
        Self {
            collecting_since: now_millis(),
            tunnels: Arc::new(RwLock::new(HashMap::new())),
            jwt_secret: None,
            ws_connections: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Add a new tunnel.
    pub async fn add_tunnel(
        &self,
        tunnel_id: String,
        client_id: String,
        remote_enode: String,
        network_id: u64,
    ) {
        let info = TunnelInfo::new(client_id, remote_enode, network_id);
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
                client_id: info.client_id.clone(),
                remote_enode: info.remote_enode.clone(),
                network_id: info.network_id,
                connected_at: info.connected_at,
                bytes_in: info.bytes_in.load(Ordering::Relaxed),
                bytes_out: info.bytes_out.load(Ordering::Relaxed),
                messages_relayed: info.messages_relayed.load(Ordering::Relaxed),
            })
            .collect();

        StateSnapshot {
            collecting_since: self.collecting_since,
            tunnels: tunnel_snapshots,
        }
    }
}

/// Information about an active tunnel.
pub struct TunnelInfo {
    pub client_id: String,
    pub remote_enode: String,
    pub network_id: u64,
    pub connected_at: i64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub messages_relayed: AtomicU64,
}

impl TunnelInfo {
    fn new(client_id: String, remote_enode: String, network_id: u64) -> Self {
        Self {
            client_id,
            remote_enode,
            network_id,
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
}

/// Serializable snapshot of a tunnel.
#[derive(Debug, Clone, Serialize)]
pub struct TunnelSnapshot {
    pub tunnel_id: String,
    pub client_id: String,
    pub remote_enode: String,
    pub network_id: u64,
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
                "besu".to_string(),
                "enode://abc".to_string(),
                1,
            )
            .await;

        let snapshot = state.snapshot().await;
        assert_eq!(snapshot.tunnels.len(), 1);
        assert_eq!(snapshot.tunnels[0].tunnel_id, "t1");

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
                "besu".to_string(),
                "enode://abc".to_string(),
                1,
            )
            .await;

        state.record_transfer("t1", 100, 200).await;
        state.record_transfer("t1", 50, 75).await;

        let snapshot = state.snapshot().await;
        assert_eq!(snapshot.tunnels[0].bytes_in, 150);
        assert_eq!(snapshot.tunnels[0].bytes_out, 275);
        assert_eq!(snapshot.tunnels[0].messages_relayed, 2);
    }
}
