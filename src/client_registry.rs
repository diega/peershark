//! Client registry for tracking connected clients and enforcing connection limits.
//!
//! Each client is identified by its node_id (full 64 bytes of the public key).
//! Multiple connections from the same client to different tunneled peers are allowed.

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Registry that tracks connected clients and enforces a maximum client limit.
pub struct ClientRegistry {
    /// Map of node_id prefix (16 bytes) to connection count.
    inner: RwLock<HashMap<[u8; 16], usize>>,
    /// Maximum number of unique clients allowed.
    max_clients: usize,
}

/// RAII guard that decrements the connection count when dropped.
pub struct ClientConnectionGuard {
    registry: Arc<ClientRegistry>,
    key: [u8; 16],
}

/// Error returned when registration fails.
#[derive(Debug)]
pub enum ClientRegistryError {
    /// Maximum number of unique clients has been reached.
    TooManyClients { current: usize, max: usize },
}

impl std::fmt::Display for ClientRegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientRegistryError::TooManyClients { current, max } => {
                write!(f, "too many clients: {} (max {})", current, max)
            }
        }
    }
}

impl std::error::Error for ClientRegistryError {}

impl ClientRegistry {
    /// Create a new registry with the given maximum client limit.
    pub fn new(max_clients: usize) -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            max_clients,
        }
    }

    /// Try to register a client connection.
    ///
    /// Returns a guard that will decrement the count when dropped.
    /// Returns an error if the maximum number of unique clients has been reached
    /// and this is a new client.
    pub fn try_register(
        self: &Arc<Self>,
        node_id: &[u8; 64],
    ) -> Result<ClientConnectionGuard, ClientRegistryError> {
        let key = Self::node_id_to_key(node_id);
        let mut guard = self.inner.write().expect("registry lock poisoned");

        // Check if this is a new client
        if !guard.contains_key(&key) {
            // Check if we've reached the limit
            if guard.len() >= self.max_clients {
                return Err(ClientRegistryError::TooManyClients {
                    current: guard.len(),
                    max: self.max_clients,
                });
            }
        }

        // Increment or insert connection count
        *guard.entry(key).or_insert(0) += 1;

        Ok(ClientConnectionGuard {
            registry: Arc::clone(self),
            key,
        })
    }

    /// Get statistics about the registry. Used for debugging/monitoring.
    ///
    /// Returns (unique_clients, total_connections).
    #[allow(dead_code)]
    pub fn stats(&self) -> (usize, usize) {
        let guard = self.inner.read().expect("registry lock poisoned");
        let unique_clients = guard.len();
        let total_connections: usize = guard.values().sum();
        (unique_clients, total_connections)
    }

    /// Format a node_id for display (full 64 bytes as hex).
    pub fn format_node_id(node_id: &[u8; 64]) -> String {
        hex::encode(node_id)
    }

    /// Extract the key (first 16 bytes) from a node_id.
    fn node_id_to_key(node_id: &[u8; 64]) -> [u8; 16] {
        let mut key = [0u8; 16];
        key.copy_from_slice(&node_id[..16]);
        key
    }

    /// Decrement the connection count for a key.
    /// Removes the entry if the count reaches zero.
    fn decrement(&self, key: &[u8; 16]) {
        let mut guard = self.inner.write().expect("registry lock poisoned");
        if let Some(count) = guard.get_mut(key) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                guard.remove(key);
            }
        }
    }
}

impl Drop for ClientConnectionGuard {
    fn drop(&mut self) {
        self.registry.decrement(&self.key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node_id(prefix: u8) -> [u8; 64] {
        let mut id = [0u8; 64];
        id[0] = prefix;
        id
    }

    #[test]
    fn test_register_and_release() {
        let registry = Arc::new(ClientRegistry::new(10));
        let node_id = make_node_id(1);

        let guard = registry.try_register(&node_id).unwrap();
        assert_eq!(registry.stats(), (1, 1));

        drop(guard);
        assert_eq!(registry.stats(), (0, 0));
    }

    #[test]
    fn test_multiple_connections_same_client() {
        let registry = Arc::new(ClientRegistry::new(10));
        let node_id = make_node_id(1);

        let guard1 = registry.try_register(&node_id).unwrap();
        let guard2 = registry.try_register(&node_id).unwrap();
        assert_eq!(registry.stats(), (1, 2));

        drop(guard1);
        assert_eq!(registry.stats(), (1, 1));

        drop(guard2);
        assert_eq!(registry.stats(), (0, 0));
    }

    #[test]
    fn test_max_clients_limit() {
        let registry = Arc::new(ClientRegistry::new(2));

        let _guard1 = registry.try_register(&make_node_id(1)).unwrap();
        let _guard2 = registry.try_register(&make_node_id(2)).unwrap();

        // Third unique client should fail
        let result = registry.try_register(&make_node_id(3));
        assert!(matches!(
            result,
            Err(ClientRegistryError::TooManyClients { current: 2, max: 2 })
        ));

        // But same client can add more connections
        let _guard3 = registry.try_register(&make_node_id(1)).unwrap();
        assert_eq!(registry.stats(), (2, 3));
    }

    #[test]
    fn test_format_node_id() {
        let mut node_id = [0u8; 64];
        node_id[0] = 0xab;
        node_id[1] = 0xcd;
        let formatted = ClientRegistry::format_node_id(&node_id);
        // Full 64 bytes as hex = 128 characters
        assert_eq!(
            formatted,
            "abcd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        );
    }
}
