use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use k256::ecdsa::SigningKey;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

use crate::client_registry::ClientRegistry;
use crate::connection;
use crate::constants::{
    ENODE_DISPLAY_LEN, MAX_PEER_RETRIES, STATUS_EXCHANGE_TIMEOUT, TUNNEL_IDLE_TIMEOUT,
};
use crate::discv4::{DiscV4, DiscV4Event, Endpoint};
use crate::error::Error;
use crate::eth;
use crate::event_bus::EventBus;
use crate::events::{self, Direction, Protocol, ProxyEvent, now_millis};
use crate::handshake;
use crate::p2p;
use crate::peer_pool::{FailureKind, PeerPool};
use crate::session::Session;
use crate::tunneled_peers::{TunneledPeer, TunneledPeerRegistry};

/// Unwrap timeout result, converting timeout to Error::Timeout.
fn unwrap_timeout_result<T>(
    result: Result<Result<T, Error>, tokio::time::error::Elapsed>,
    timeout_msg: &str,
) -> Result<T, Error> {
    match result {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(Error::Timeout(timeout_msg.to_string())),
    }
}

/// Classify an error for peer scoring purposes.
fn classify_failure(e: &Error) -> FailureKind {
    match e {
        Error::Io(_) => FailureKind::ConnectionRefused,
        Error::Timeout(_) => FailureKind::Timeout,
        Error::ConnectionClosed => FailureKind::ConnectionRefused,
        Error::Disconnected(reason_str) => {
            // Try to parse disconnect reason code from the string.
            // Format is typically "description (code N)" from DisconnectReason::description()
            if let Some(code) = reason_str
                .rsplit("code ")
                .next()
                .and_then(|s| s.trim_end_matches(')').parse::<u8>().ok())
            {
                FailureKind::Disconnected(p2p::DisconnectReason::from_code(code))
            } else {
                FailureKind::Disconnected(p2p::DisconnectReason::Unknown(0xff))
            }
        }
        _ => FailureKind::ProtocolError,
    }
}

/// Capabilities we announce to clients (all supported versions).
pub fn proxy_capabilities() -> Vec<p2p::Capability> {
    vec![
        p2p::Capability::new("eth", 68),
        p2p::Capability::new("eth", 67),
        p2p::Capability::new("eth", 66),
        p2p::Capability::new("eth", 65),
        p2p::Capability::new("snap", 1),
    ]
}

/// Filter client capabilities to only include those supported by the proxy.
fn filter_capabilities(client_caps: &[p2p::Capability]) -> Vec<p2p::Capability> {
    let proxy_caps = proxy_capabilities();
    let supported: HashSet<(&str, u8)> = proxy_caps
        .iter()
        .map(|c| (c.name.as_str(), c.version))
        .collect();

    client_caps
        .iter()
        .filter(|c| supported.contains(&(c.name.as_str(), c.version)))
        .cloned()
        .collect()
}

/// Spawn TCP and UDP handlers for each tunneled peer.
pub async fn spawn_tunneled_peer_handlers(
    registry: Arc<RwLock<TunneledPeerRegistry>>,
    peer_pool: Arc<PeerPool>,
    client_id: &str,
    shutdown_tx: broadcast::Sender<()>,
    event_bus: Arc<EventBus>,
    client_registry: Arc<ClientRegistry>,
) {
    let mut registry_guard = registry.write().await;
    let node_ids = registry_guard.get_all_node_ids();

    for node_id in node_ids {
        let tcp_listener = match registry_guard.take_tcp_listener(&node_id) {
            Some(listener) => listener,
            None => continue,
        };
        let udp_socket = match registry_guard.take_udp_socket(&node_id) {
            Some(socket) => socket,
            None => continue,
        };

        let tunneled_peer = registry_guard
            .get_peer(&node_id)
            .expect("peer must exist: node_id from registry")
            .clone();
        let port = registry_guard
            .get_port(&node_id)
            .expect("port must exist: node_id from registry");
        let client_id = client_id.to_string();
        let registry_for_udp = registry.clone();
        let peer_pool_for_tcp = peer_pool.clone();
        let shutdown_tx_for_tcp = shutdown_tx.clone();
        let event_bus_for_tcp = event_bus.clone();

        // Clone signing_key for UDP handler before moving tunneled_peer to TCP handler
        let signing_key_udp = tunneled_peer.signing_key().clone();
        let client_registry_for_tcp = client_registry.clone();

        // Spawn TCP handler
        tokio::spawn(async move {
            run_tunneled_peer_tcp(
                tcp_listener,
                tunneled_peer,
                peer_pool_for_tcp,
                client_id,
                port,
                shutdown_tx_for_tcp,
                event_bus_for_tcp,
                client_registry_for_tcp,
            )
            .await;
        });

        // Spawn UDP handler
        let udp_endpoint = Endpoint::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            port,
            port,
        );
        let tunneled_discv4 = Arc::new(DiscV4::new(udp_socket, signing_key_udp, udp_endpoint));
        let shutdown_rx_for_udp = shutdown_tx.subscribe();

        tokio::spawn(async move {
            run_tunneled_peer_udp(tunneled_discv4, registry_for_udp, port, shutdown_rx_for_udp)
                .await;
        });
    }
}

/// TCP handler for a tunneled peer: accepts connections and tunnels to real peer.
#[allow(clippy::too_many_arguments)]
async fn run_tunneled_peer_tcp(
    listener: TcpListener,
    tunneled_peer: TunneledPeer,
    peer_pool: Arc<PeerPool>,
    client_id: String,
    port: u16,
    shutdown_tx: broadcast::Sender<()>,
    event_bus: Arc<EventBus>,
    client_registry: Arc<ClientRegistry>,
) {
    let mut shutdown_rx = shutdown_tx.subscribe();

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, peer_addr)) => {
                        debug!(peer = %peer_addr, port, "TCP connection accepted");

                        let tunneled_peer = tunneled_peer.clone();
                        let client_id = client_id.clone();
                        let peer_pool = peer_pool.clone();
                        let client_shutdown_rx = shutdown_tx.subscribe();
                        let event_bus = event_bus.clone();
                        let client_registry = client_registry.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_client(
                                stream,
                                &tunneled_peer,
                                &client_id,
                                &peer_pool,
                                client_shutdown_rx,
                                event_bus,
                                client_registry,
                            )
                            .await
                            {
                                debug!(port, error = %e, "client error");
                            }
                        });
                    }
                    Err(e) => {
                        warn!(port, error = %e, "TCP accept error");
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                debug!(port, "TCP handler received shutdown signal");
                break;
            }
        }
    }
}

/// UDP handler for a tunneled peer: responds to discovery messages.
async fn run_tunneled_peer_udp(
    discv4: Arc<DiscV4>,
    registry: Arc<RwLock<TunneledPeerRegistry>>,
    port: u16,
    mut shutdown_rx: broadcast::Receiver<()>,
) {
    loop {
        tokio::select! {
            result = discv4.recv() => {
                match result {
                    Ok((src, event)) => match event {
                        DiscV4Event::Ping { hash } => {
                            let _ = discv4.send_pong(src, hash).await;
                        }
                        DiscV4Event::FindNode { target: _ } => {
                            let registry_guard = registry.read().await;
                            let nodes = registry_guard.to_node_records();
                            drop(registry_guard);
                            let _ = discv4.send_neighbors(src, nodes).await;
                        }
                        _ => {}
                    },
                    Err(e) => {
                        debug!(port, error = %e, "UDP error on tunneled peer");
                    }
                }
            }
            _ = shutdown_rx.recv() => {
                debug!(port, "UDP handler received shutdown signal");
                break;
            }
        }
    }
}

/// Handle a client connection: perform handshake, exchange status, and tunnel to real peer.
pub async fn handle_client(
    stream: tokio::net::TcpStream,
    tunneled_peer: &TunneledPeer,
    client_id: &str,
    peer_pool: &PeerPool,
    shutdown_rx: broadcast::Receiver<()>,
    event_bus: Arc<EventBus>,
    client_registry: Arc<ClientRegistry>,
) -> Result<(), Error> {
    let mut client_session =
        connection::accept_as_responder(stream, tunneled_peer.signing_key()).await?;

    let (msg_id, payload) = client_session.read_message().await?;

    if msg_id != p2p::HELLO_MSG_ID {
        return Err(Error::Protocol(format!(
            "expected Hello, got msg_id {}",
            msg_id
        )));
    }

    let hello = p2p::HelloMessage::from_rlp(&payload)?;

    if hello.node_id != client_session.remote_pubkey {
        return Err(Error::Protocol(
            "Hello node_id does not match handshake pubkey".to_string(),
        ));
    }

    // Try to register this client connection.
    // Returns a guard that decrements the count when dropped.
    let _connection_guard = match client_registry.try_register(&hello.node_id) {
        Ok(guard) => guard,
        Err(e) => {
            warn!(error = %e, "client registration failed");
            let disconnect_payload = p2p::DisconnectReason::TooManyPeers.to_rlp();
            let _ = client_session
                .write_message(p2p::DISCONNECT_MSG_ID, &disconnect_payload)
                .await;
            return Err(Error::Disconnected(e.to_string()));
        }
    };

    // Format client node_id for events (first 16 bytes as hex)
    let client_node_id = ClientRegistry::format_node_id(&hello.node_id);

    let capabilities: Vec<String> = hello
        .capabilities
        .iter()
        .map(|c| format!("{}/{}", c.name, c.version))
        .collect();

    // Filter client capabilities to only those we support
    let filtered_capabilities = filter_capabilities(&hello.capabilities);

    // Validate we have at least one common eth capability
    let _eth_version = filtered_capabilities
        .iter()
        .filter(|c| c.name == "eth")
        .map(|c| c.version)
        .max()
        .ok_or_else(|| Error::Protocol("no common eth capability".to_string()))?;

    info!(client_id = %hello.client_id, capabilities = %capabilities.join(", "), "client connected");

    // Send our Hello with all supported capabilities
    send_hello(
        &mut client_session,
        client_id,
        tunneled_peer.node_id(),
        &proxy_capabilities(),
    )
    .await?;

    let client_status = eth::receive_status(&mut client_session).await?;

    debug!(
        network_id = client_status.network_id,
        genesis = %hex::encode(&client_status.genesis_hash[..4]),
        "client status"
    );

    // Try to connect to a real peer from the pool (with retry)
    // Pool tracks: in_use (no duplicates) and bad (skip failed peers)
    let mut last_error = String::from("no peers available");
    let mut attempts = 0;

    // Random start index to distribute load
    let start_idx = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as usize % peer_pool.total().max(1))
        .unwrap_or(0);

    for attempt in 0..MAX_PEER_RETRIES {
        // Try to reserve an available peer (not in use, not bad)
        let peer_url = match peer_pool.try_reserve(start_idx + attempt) {
            Some(url) => url,
            None => {
                let (available, in_use, bad) = peer_pool.stats();
                last_error = format!(
                    "no peers available (available={}, in_use={}, bad={})",
                    available, in_use, bad
                );
                break;
            }
        };
        attempts += 1;

        let peer_display = truncate_enode(&peer_url);

        let (mut peer_session, peer_status) = match connect_to_peer(
            &peer_url,
            tunneled_peer.signing_key(),
            client_id,
            tunneled_peer.node_id(),
            &client_status,
            &filtered_capabilities,
        )
        .await
        {
            Ok(result) => result,
            Err(e) => {
                // Connection failed, record failure with appropriate penalty
                let failure_kind = classify_failure(&e);
                peer_pool.record_failure(&peer_url, failure_kind);
                last_error = format!("{}: {}", peer_display, e);
                continue;
            }
        };

        // Check genesis BEFORE sending status to client
        if client_status.genesis_hash != peer_status.genesis_hash {
            peer_pool.record_failure(&peer_url, FailureKind::GenesisMismatch);
            last_error = format!("genesis mismatch with {}", peer_display);
            continue;
        }

        // Genesis matches - send peer's status to client
        eth::send_status(&mut client_session, &peer_status).await?;

        // Generate tunnel ID from peer pubkey (first 8 bytes hex)
        let tunnel_id = hex::encode(&peer_session.remote_pubkey[..8]);

        info!(
            peer = %peer_display,
            attempts,
            tunnel_id = %tunnel_id,
            "tunnel established"
        );

        // Format capabilities as strings for the event
        let capability_strings: Vec<String> = filtered_capabilities
            .iter()
            .map(|c| format!("{}/{}", c.name, c.version))
            .collect();

        event_bus.emit(ProxyEvent::PeerConnected {
            tunnel_id: tunnel_id.clone(),
            client_node_id: client_node_id.clone(),
            client_id: hello.client_id.clone(),
            remote_enode: peer_url.clone(),
            network_id: peer_status.network_id,
            fork_hash: hex::encode(peer_status.fork_id.fork_hash),
            fork_next: peer_status.fork_id.fork_next,
            capabilities: capability_strings,
            timestamp: now_millis(),
        });

        // Run relay - peer stays reserved (in_use) while tunnel is active
        let relay_start = Instant::now();
        let result = relay_messages(
            &mut client_session,
            &mut peer_session,
            shutdown_rx,
            &event_bus,
            &tunnel_id,
            &client_node_id,
        )
        .await;
        let tunnel_duration = relay_start.elapsed();

        let disconnect_reason = match &result {
            Ok(()) => "normal_close".to_string(),
            Err(e) => e.to_string(),
        };
        info!(
            tunnel_id = %tunnel_id,
            reason = %disconnect_reason,
            duration_ms = %tunnel_duration.as_millis(),
            "tunnel closed"
        );
        event_bus.emit(ProxyEvent::PeerDisconnected {
            tunnel_id,
            client_node_id,
            reason: disconnect_reason,
            timestamp: now_millis(),
        });

        // Penalize peer if tunnel was very short-lived (< 1 second) and ended in error.
        // This catches unstable peers that disconnect immediately after Status exchange.
        if tunnel_duration < Duration::from_secs(1) && result.is_err() {
            warn!(
                peer = %peer_display,
                duration_ms = %tunnel_duration.as_millis(),
                "penalizing peer for immediate disconnect"
            );
            peer_pool.record_failure(&peer_url, FailureKind::ImmediateDisconnect);
        } else {
            // Normal release - resets score to neutral
            peer_pool.release(&peer_url);
        }
        return result;
    }

    Err(Error::Protocol(format!(
        "failed to connect after {} attempts: {}",
        attempts, last_error
    )))
}

/// Connect to a real peer and perform handshake.
async fn connect_to_peer(
    enode_url: &str,
    signing_key: &SigningKey,
    client_id: &str,
    node_id: [u8; 64],
    client_status: &eth::EthStatus,
    client_capabilities: &[p2p::Capability],
) -> Result<(Session, eth::EthStatus), Error> {
    let remote_pubkey = handshake::parse_enode_pubkey(enode_url)?;

    let parsed: url::Url =
        url::Url::parse(enode_url).map_err(|e| Error::Protocol(e.to_string()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| Error::Protocol("missing host".to_string()))?;
    let port = parsed
        .port()
        .ok_or_else(|| Error::Protocol("missing port".to_string()))?;
    let addr = format!("{}:{}", host, port);

    let mut session = connection::connect_as_initiator(&addr, signing_key, &remote_pubkey).await?;

    // Use client's capabilities so both sides of tunnel use same protocol version
    send_hello(&mut session, client_id, node_id, client_capabilities).await?;

    let (msg_id, payload) = session.read_message().await?;

    if msg_id == p2p::DISCONNECT_MSG_ID {
        let reason = p2p::DisconnectReason::from_rlp(&payload);
        return Err(Error::Disconnected(reason.description().to_string()));
    }

    if msg_id != p2p::HELLO_MSG_ID {
        return Err(Error::Protocol(format!(
            "expected Hello, got msg_id {}",
            msg_id
        )));
    }

    let hello = p2p::HelloMessage::from_rlp(&payload)?;

    if hello.node_id != session.remote_pubkey {
        return Err(Error::Protocol(
            "Hello node_id does not match handshake pubkey".to_string(),
        ));
    }

    // Exchange Status with timeout
    let peer_status = match tokio::time::timeout(
        STATUS_EXCHANGE_TIMEOUT,
        eth::receive_status(&mut session),
    )
    .await
    {
        Ok(Ok(status)) => {
            eth::send_status(&mut session, client_status).await?;
            status
        }
        Ok(Err(e)) => return Err(e),
        Err(_) => {
            eth::send_status(&mut session, client_status).await?;
            eth::receive_status(&mut session).await?
        }
    };

    Ok((session, peer_status))
}

/// Relay messages bidirectionally between client and peer.
/// Sends DISCONNECT to both sides on shutdown signal.
/// Times out after TUNNEL_IDLE_TIMEOUT of inactivity.
async fn relay_messages(
    client: &mut Session,
    peer: &mut Session,
    mut shutdown_rx: broadcast::Receiver<()>,
    event_bus: &EventBus,
    tunnel_id: &str,
    client_node_id: &str,
) -> Result<(), Error> {
    loop {
        tokio::select! {
            result = tokio::time::timeout(TUNNEL_IDLE_TIMEOUT, client.read_message()) => {
                let (msg_id, payload) = unwrap_timeout_result(result, "tunnel idle timeout (no client activity)")?;
                let protocol = classify_protocol(msg_id);

                event_bus.emit(ProxyEvent::MessageRelayed {
                    tunnel_id: tunnel_id.to_string(),
                    client_node_id: client_node_id.to_string(),
                    direction: Direction::ClientToPeer,
                    msg_id,
                    msg_name: events::msg_name(msg_id, protocol),
                    protocol,
                    size: payload.len(),
                    raw: None,
                    timestamp: now_millis(),
                });

                peer.write_message(msg_id, &payload).await?;
            }
            result = tokio::time::timeout(TUNNEL_IDLE_TIMEOUT, peer.read_message()) => {
                let (msg_id, payload) = unwrap_timeout_result(result, "tunnel idle timeout (no peer activity)")?;
                let protocol = classify_protocol(msg_id);

                event_bus.emit(ProxyEvent::MessageRelayed {
                    tunnel_id: tunnel_id.to_string(),
                    client_node_id: client_node_id.to_string(),
                    direction: Direction::PeerToClient,
                    msg_id,
                    msg_name: events::msg_name(msg_id, protocol),
                    protocol,
                    size: payload.len(),
                    raw: None,
                    timestamp: now_millis(),
                });

                client.write_message(msg_id, &payload).await?;
            }
            _ = shutdown_rx.recv() => {
                // Send DISCONNECT to both sides
                let disconnect_payload = p2p::DisconnectReason::ClientQuitting.to_rlp();

                // Best effort - ignore errors since we're shutting down anyway
                let _ = client.write_message(p2p::DISCONNECT_MSG_ID, &disconnect_payload).await;
                let _ = peer.write_message(p2p::DISCONNECT_MSG_ID, &disconnect_payload).await;

                debug!("sent DISCONNECT to client and peer");
                return Ok(());
            }
        }
    }
}

/// Classify message protocol based on msg_id.
fn classify_protocol(msg_id: u8) -> Protocol {
    match msg_id {
        0x00..=0x0F => Protocol::P2p,
        0x10..=0x1F => Protocol::Eth,
        _ => Protocol::Unknown,
    }
}

/// Send a Hello message with the given capabilities.
async fn send_hello(
    session: &mut Session,
    client_id: &str,
    node_id: [u8; 64],
    capabilities: &[p2p::Capability],
) -> Result<(), Error> {
    let hello = p2p::HelloMessage::new(client_id, capabilities.to_vec(), node_id);
    session
        .write_message(p2p::HELLO_MSG_ID, &hello.to_rlp())
        .await
}

/// Truncate enode URL for display in logs.
fn truncate_enode(enode_url: &str) -> &str {
    &enode_url[..ENODE_DISPLAY_LEN.min(enode_url.len())]
}
