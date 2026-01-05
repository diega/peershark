//! Registry of tunneled peers with derived cryptographic identities.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use hkdf::Hkdf;
use k256::ecdsa::SigningKey;
use sha2::Sha256;
use tokio::net::{TcpListener, UdpSocket};

use crate::crypto::pubkey_to_node_id;
use crate::discv4::NodeRecord;

/// Cryptographic identity of a tunneled peer.
/// The `node_id` is derived from the signing key to prevent inconsistency.
#[derive(Clone)]
pub struct TunneledPeer {
    signing_key: SigningKey,
    node_id: [u8; 64],
}

impl TunneledPeer {
    /// Create a tunneled peer identity. The node_id is derived from the signing key.
    pub fn new(signing_key: SigningKey) -> Self {
        let node_id = pubkey_to_node_id(&signing_key);
        Self {
            signing_key,
            node_id,
        }
    }

    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    pub fn node_id(&self) -> [u8; 64] {
        self.node_id
    }

    /// Truncated hex identifier for logging (first 8 bytes of node_id).
    pub fn tunnel_id(&self) -> String {
        hex::encode(&self.node_id[..8])
    }
}

/// Information about a tunneled peer.
/// Each tunneled peer has its own port with both TCP and UDP listeners.
/// Tunneled peers no longer have a fixed real_enode - they use a shared pool.
pub struct TunneledPeerInfo {
    peer: TunneledPeer,
    pub port: u16,
    tcp_listener: Option<TcpListener>,
    udp_socket: Option<Arc<UdpSocket>>,
}

/// Registry of tunneled peers.
/// Tunneled peers are virtual identities that tunnel to real peers.
pub struct TunneledPeerRegistry {
    peers: HashMap<[u8; 64], TunneledPeerInfo>,
    port_to_node_id: HashMap<u16, [u8; 64]>,
    master_key: SigningKey,
    max_peers: usize,
}

impl TunneledPeerRegistry {
    /// Create a new registry with the given master key and maximum peer count.
    ///
    /// Tunneled peer keys are derived deterministically from the master key.
    pub fn new(master_key: SigningKey, max_peers: usize) -> Self {
        TunneledPeerRegistry {
            peers: HashMap::new(),
            port_to_node_id: HashMap::new(),
            master_key,
            max_peers,
        }
    }

    /// Register a new tunneled peer.
    /// Creates TCP and UDP listeners on a random available port.
    /// The tunneled peer will use a shared pool of real peers (not a fixed one).
    pub async fn register(&mut self, neighbor_pubkey: &[u8; 64]) -> Option<[u8; 64]> {
        if self.peers.len() >= self.max_peers {
            return None;
        }

        let signing_key = derive_tunneled_key(&self.master_key, neighbor_pubkey);
        let peer = TunneledPeer::new(signing_key);
        let node_id = peer.node_id();

        if self.peers.contains_key(&node_id) {
            return Some(node_id);
        }

        // Bind TCP to localhost first to get a random port
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.ok()?;
        let port = tcp_listener.local_addr().ok()?.port();

        // Bind UDP to localhost on the same port
        let udp_socket = UdpSocket::bind(format!("127.0.0.1:{}", port)).await.ok()?;

        self.port_to_node_id.insert(port, node_id);
        self.peers.insert(
            node_id,
            TunneledPeerInfo {
                peer,
                port,
                tcp_listener: Some(tcp_listener),
                udp_socket: Some(Arc::new(udp_socket)),
            },
        );

        Some(node_id)
    }

    /// Take ownership of the TCP listener for a tunneled peer.
    ///
    /// Returns `None` if the peer doesn't exist or the listener was already taken.
    pub fn take_tcp_listener(&mut self, node_id: &[u8; 64]) -> Option<TcpListener> {
        self.peers
            .get_mut(node_id)
            .and_then(|info| info.tcp_listener.take())
    }

    /// Take ownership of the UDP socket for a tunneled peer.
    ///
    /// Returns `None` if the peer doesn't exist or the socket was already taken.
    pub fn take_udp_socket(&mut self, node_id: &[u8; 64]) -> Option<Arc<UdpSocket>> {
        self.peers
            .get_mut(node_id)
            .and_then(|info| info.udp_socket.take())
    }

    /// Get the tunneled peer identity.
    pub fn get_peer(&self, node_id: &[u8; 64]) -> Option<&TunneledPeer> {
        self.peers.get(node_id).map(|info| &info.peer)
    }

    /// Get the port for a tunneled peer.
    pub fn get_port(&self, node_id: &[u8; 64]) -> Option<u16> {
        self.peers.get(node_id).map(|info| info.port)
    }

    /// Get all node IDs in the registry.
    pub fn get_all_node_ids(&self) -> Vec<[u8; 64]> {
        self.peers.keys().copied().collect()
    }

    /// Get the number of registered tunneled peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Iterate over all tunneled peers.
    pub fn iter(&self) -> impl Iterator<Item = (&[u8; 64], &TunneledPeerInfo)> {
        self.peers.iter()
    }

    /// Convert all tunneled peers to NodeRecords for discovery responses.
    /// All tunneled peers are on localhost.
    pub fn to_node_records(&self) -> Vec<NodeRecord> {
        self.peers
            .values()
            .map(|info| NodeRecord {
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                udp_port: info.port,
                tcp_port: info.port,
                pubkey: info.peer.node_id(),
            })
            .collect()
    }
}

fn derive_tunneled_key(master: &SigningKey, neighbor_pubkey: &[u8; 64]) -> SigningKey {
    let hk = Hkdf::<Sha256>::new(None, &master.to_bytes()[..]);
    let mut okm = [0u8; 32];
    hk.expand(neighbor_pubkey, &mut okm)
        .expect("HKDF expand failed");

    loop {
        if let Ok(key) = SigningKey::from_bytes(&okm.into()) {
            return key;
        }
        let hk2 = Hkdf::<Sha256>::new(None, &okm);
        hk2.expand(b"retry", &mut okm).expect("HKDF expand failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tunneled_key_derivation_is_deterministic() {
        let master = SigningKey::random(&mut rand::thread_rng());
        let neighbor_pubkey = [42u8; 64];

        let key1 = derive_tunneled_key(&master, &neighbor_pubkey);
        let key2 = derive_tunneled_key(&master, &neighbor_pubkey);

        assert_eq!(key1.to_bytes(), key2.to_bytes());
    }

    #[test]
    fn test_different_neighbors_get_different_keys() {
        let master = SigningKey::random(&mut rand::thread_rng());
        let neighbor1 = [1u8; 64];
        let neighbor2 = [2u8; 64];

        let key1 = derive_tunneled_key(&master, &neighbor1);
        let key2 = derive_tunneled_key(&master, &neighbor2);

        assert_ne!(key1.to_bytes(), key2.to_bytes());
    }
}
