use std::num::NonZeroU32;
use std::path::Path;
use std::sync::Arc;

use governor::{Quota, RateLimiter, clock::DefaultClock, state::keyed::DefaultKeyedStateStore};
use tokio::sync::RwLock;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::client_registry::ClientRegistry;
use crate::constants::NODE_ID_LEN;
use crate::discv4::{DiscV4, DiscV4Event};
use crate::dns_discovery::DnsDiscovery;
use crate::error::Error;
use crate::event_bus::EventBus;
use crate::handshake;
use crate::peer_pool::PeerPool;
use crate::tunnel::spawn_tunneled_peer_handlers;
use crate::tunneled_peers::TunneledPeerRegistry;

/// Source of peer discovery.
#[derive(Clone)]
pub enum DiscoverySource {
    /// Static list of enode URLs from CLI.
    Bootnodes(Vec<String>),
    /// DNS discovery (EIP-1459) with cache.
    DnsDiscovery { url: String, cache_path: String },
}

/// Discovery peer UDP handler: responds to PING and FINDNODE from clients.
/// Creates tunneled peers on-demand when first FINDNODE is received.
#[allow(clippy::too_many_arguments)]
pub async fn run_discovery_peer(
    discv4: Arc<DiscV4>,
    registry: Arc<RwLock<TunneledPeerRegistry>>,
    discovery_source: DiscoverySource,
    client_id: String,
    max_tunneled_peers: usize,
    max_clients: usize,
    shutdown_tx: broadcast::Sender<()>,
    event_bus: Arc<EventBus>,
) {
    let mut peers_initialized = false;
    let mut shutdown_rx = shutdown_tx.subscribe();

    // Create client registry for tracking connected clients
    let client_registry = Arc::new(ClientRegistry::new(max_clients));

    // Create peer pool (may start empty for DNS discovery)
    let peer_pool: Arc<PeerPool> = Arc::new(PeerPool::new(Vec::new()));

    // Handle discovery source: either populate immediately or spawn background task
    match &discovery_source {
        DiscoverySource::Bootnodes(urls) => {
            peer_pool.add_peers(urls.clone());
            info!(count = urls.len(), "loaded bootnodes");
        }
        DiscoverySource::DnsDiscovery { url, cache_path } => {
            let pool = peer_pool.clone();
            let url = url.clone();
            let cache_path = cache_path.clone();
            tokio::spawn(async move {
                info!("starting DNS discovery in background");
                match DnsDiscovery::new(&url) {
                    Ok(discovery) => match discovery.discover_nodes(Path::new(&cache_path)).await {
                        Ok(nodes) => {
                            let urls: Vec<String> = nodes.iter().map(|n| n.enode_url()).collect();
                            info!(count = urls.len(), "DNS discovery complete");
                            pool.add_peers(urls);
                        }
                        Err(e) => {
                            warn!(error = %e, "DNS discovery failed");
                        }
                    },
                    Err(e) => {
                        warn!(error = %e, "failed to create DNS discovery");
                    }
                }
            });
        }
    }

    // Rate limiter: 10 packets/sec per IP to prevent UDP flooding
    let rate_limiter: RateLimiter<String, DefaultKeyedStateStore<String>, DefaultClock> =
        RateLimiter::keyed(Quota::per_second(NonZeroU32::new(10).expect("10 > 0")));

    loop {
        tokio::select! {
            result = discv4.recv() => {
                match result {
                    Ok((src, event)) => {
                        // Rate limit check
                        let client_ip = src.ip().to_string();
                        if rate_limiter.check_key(&client_ip).is_err() {
                            debug!(ip = %src.ip(), "UDP rate limited");
                            continue;
                        }

                        match event {
                            DiscV4Event::Ping { hash } => {
                                let _ = discv4.send_pong(src, hash).await;
                            }
                            DiscV4Event::FindNode { target: _ } => {
                                // Check if we have peers yet
                                if peer_pool.total() == 0 {
                                    info!("FINDNODE received but discovery still in progress");
                                    let _ = discv4.send_neighbors(src, vec![]).await;
                                    continue;
                                }

                                // Create tunneled peers on first FINDNODE (when we have peers)
                                if !peers_initialized {
                                    info!("client requested peers, creating tunneled peers");
                                    create_tunneled_peers_from_pool(&peer_pool, &registry, max_tunneled_peers).await;
                                    spawn_tunneled_peer_handlers(
                                        registry.clone(),
                                        peer_pool.clone(),
                                        &client_id,
                                        shutdown_tx.clone(),
                                        event_bus.clone(),
                                        client_registry.clone(),
                                    )
                                    .await;
                                    peers_initialized = true;

                                    let registry_guard = registry.read().await;
                                    info!(
                                        count = registry_guard.len(),
                                        pool_size = peer_pool.total(),
                                        "created tunneled peers"
                                    );
                                    for (node_id, info) in registry_guard.iter() {
                                        debug!(
                                            node_id = %hex::encode(&node_id[..8]),
                                            port = info.port,
                                            "tunneled peer"
                                        );
                                    }
                                }

                                // Respond with tunneled peers
                                let registry_guard = registry.read().await;
                                let nodes = registry_guard.to_node_records();
                                drop(registry_guard);
                                let _ = discv4.send_neighbors(src, nodes).await;
                            }
                            _ => {}
                        }
                    }
                    Err(e) => {
                        debug!(error = %e, "discovery UDP error");
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                debug!("discovery peer received shutdown signal");
                break;
            }
        }
    }
}

/// Create tunneled peers from the peer pool.
async fn create_tunneled_peers_from_pool(
    peer_pool: &Arc<PeerPool>,
    registry: &Arc<RwLock<TunneledPeerRegistry>>,
    max_peers: usize,
) {
    let peer_urls = peer_pool.get_peers();
    let mut created = 0;
    for enode_url in &peer_urls {
        if created >= max_peers {
            break;
        }

        let pubkey_bytes = match parse_enode_pubkey_bytes(enode_url) {
            Some(p) => p,
            None => continue,
        };

        let mut registry_guard = registry.write().await;
        if registry_guard.register(&pubkey_bytes).await.is_some() {
            created += 1;
        }
    }
}

/// Parse enode URL and extract pubkey as bytes.
fn parse_enode_pubkey_bytes(enode_url: &str) -> Option<[u8; 64]> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    let pubkey = handshake::parse_enode_pubkey(enode_url).ok()?;
    let point = pubkey.to_encoded_point(false);
    let bytes = point.as_bytes();
    if bytes.len() < 65 {
        return None;
    }
    let mut result = [0u8; 64];
    result.copy_from_slice(&bytes[1..65]);
    Some(result)
}

/// Validate an enode URL.
/// Returns Ok(()) if valid, Err with description otherwise.
pub fn validate_enode_url(enode_url: &str) -> Result<(), Error> {
    // Must start with enode://
    if !enode_url.starts_with("enode://") {
        return Err(Error::Handshake("must start with enode://".to_string()));
    }

    // Parse as URL
    let parsed =
        url::Url::parse(enode_url).map_err(|e| Error::Handshake(format!("invalid URL: {}", e)))?;

    // Extract and validate pubkey (username part)
    let pubkey_hex = parsed.username();
    if pubkey_hex.is_empty() {
        return Err(Error::Handshake("missing node ID".to_string()));
    }

    // Must be 128 hex characters (64 bytes)
    if pubkey_hex.len() != NODE_ID_LEN * 2 {
        return Err(Error::Handshake(format!(
            "node ID must be {} hex chars, got {}",
            NODE_ID_LEN * 2,
            pubkey_hex.len()
        )));
    }

    // Must be valid hex
    hex::decode(pubkey_hex).map_err(|e| Error::Handshake(format!("invalid node ID hex: {}", e)))?;

    // Must have host
    if parsed.host_str().is_none() {
        return Err(Error::Handshake("missing host".to_string()));
    }

    // Must have port
    if parsed.port().is_none() {
        return Err(Error::Handshake("missing port".to_string()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_enode_url_valid() {
        let valid = "enode://aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd00112233@127.0.0.1:30303";
        assert!(validate_enode_url(valid).is_ok());
    }

    #[test]
    fn test_validate_enode_url_missing_prefix() {
        let invalid = "http://abc@127.0.0.1:30303";
        assert!(validate_enode_url(invalid).is_err());
    }

    #[test]
    fn test_validate_enode_url_short_pubkey() {
        let invalid = "enode://abc@127.0.0.1:30303";
        assert!(validate_enode_url(invalid).is_err());
    }

    #[test]
    fn test_validate_enode_url_missing_port() {
        let invalid = "enode://aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd00112233445566778899aabbccdd00112233@127.0.0.1";
        assert!(validate_enode_url(invalid).is_err());
    }
}
