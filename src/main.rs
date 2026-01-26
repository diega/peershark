#![allow(dead_code)]

mod api;
mod bytes;
mod client_registry;
mod config;
mod connection;
mod constants;
mod crypto;
mod discv4;
mod dns_discovery;
mod ecies;
mod error;
mod eth;
mod eth_messages;
mod event_bus;
mod events;
mod frame;
mod handshake;
mod p2p;
mod peer_pool;
mod proxy_discovery;
mod rlp;
mod session;
mod snap_messages;
mod tunnel;
mod tunneled_peers;

use std::net::{IpAddr, Ipv4Addr};
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use time::UtcOffset;
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, error, info, warn};
use tracing_subscriber::fmt::time::OffsetTime;

use config::{ApiRuntimeConfig, Cli, RuntimeConfig, load_config_file, load_private_key};
use constants::SHUTDOWN_GRACE_PERIOD;
use crypto::pubkey_to_node_id;
use discv4::{DiscV4, Endpoint};
use error::Error;
use event_bus::EventBus;
use proxy_discovery::{DiscoverySource, run_discovery_peer, validate_enode_url};
use tunneled_peers::TunneledPeerRegistry;

fn main() -> ExitCode {
    init_logging();

    let cli = Cli::parse();

    let config_file = match load_config_file(cli.core.config.as_ref()) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "failed to load config file");
            return ExitCode::from(1);
        }
    };

    let config = match RuntimeConfig::from_cli_and_file(&cli, config_file) {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "configuration error");
            return ExitCode::from(1);
        }
    };

    let master_key = match load_private_key(&config.private_key_path) {
        Ok(k) => k,
        Err(e) => {
            error!(error = %e, "failed to load private key");
            return ExitCode::from(1);
        }
    };

    run_application(config, master_key)
}

fn init_logging() {
    // Get local offset at startup (before spawning threads).
    // This must happen in main thread due to time crate safety requirements.
    let local_offset = UtcOffset::current_local_offset().unwrap_or(UtcOffset::UTC);
    let timer = OffsetTime::new(
        local_offset,
        time::macros::format_description!(
            "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3][offset_hour sign:mandatory][offset_minute]"
        ),
    );

    tracing_subscriber::fmt()
        .with_timer(timer)
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::INFO.into()),
        )
        .init();
}

fn run_application(config: RuntimeConfig, master_key: k256::ecdsa::SigningKey) -> ExitCode {
    let discovery_node_id = pubkey_to_node_id(&master_key);

    // Print enode IMMEDIATELY so client can connect while discovery runs
    info!(
        enode = %format!("enode://{}@<host>:{}", hex::encode(discovery_node_id), config.listen_port),
        "discovery peer"
    );

    let runtime = match Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            error!(error = %e, "failed to create tokio runtime");
            return ExitCode::from(1);
        }
    };

    // Prepare discovery source (either CLI bootnodes or DNS discovery URL)
    let discovery_source = if !config.bootnodes.is_empty() {
        match validate_bootnodes(&config.bootnodes) {
            Ok(urls) => {
                info!(count = urls.len(), "using bootnodes from CLI");
                DiscoverySource::Bootnodes(urls)
            }
            Err(e) => {
                error!(error = %e, "invalid bootnode");
                return ExitCode::from(1);
            }
        }
    } else if let Some(url) = config.enrtree.clone() {
        info!("DNS discovery will run in background");
        DiscoverySource::DnsDiscovery {
            url,
            cache_path: config.dns_cache_path.to_string_lossy().to_string(),
        }
    } else {
        // This shouldn't happen due to validation in RuntimeConfig, but handle it anyway
        error!("either --bootnodes or --enrtree is required");
        return ExitCode::from(1);
    };

    // Log API config status
    if let Some(ref api) = config.api
        && api.jwt_secret.is_none()
    {
        warn!("API authentication disabled (--no-auth)");
    }

    runtime.block_on(async {
        if let Err(e) = run_proxy(
            config.listen_port,
            &master_key,
            &config.client_id,
            discovery_source,
            config.max_tunneled_peers,
            config.max_clients,
            config.api,
        )
        .await
        {
            error!(error = %e, "proxy error");
        }
    });

    ExitCode::from(0)
}

fn validate_bootnodes(nodes: &[String]) -> Result<Vec<String>, Error> {
    for node in nodes {
        validate_enode_url(node)?;
    }
    Ok(nodes.to_vec())
}

async fn run_proxy(
    discovery_port: u16,
    master_key: &k256::ecdsa::SigningKey,
    client_id: &str,
    discovery_source: DiscoverySource,
    max_tunneled_peers: usize,
    max_clients: usize,
    api: Option<ApiRuntimeConfig>,
) -> Result<(), Error> {
    let event_bus = Arc::new(EventBus::new());
    debug!("event bus created");

    // Start API server if configured
    if let Some(api) = api {
        let api_state = match api.jwt_secret {
            Some(secret) => api::ApiState::new(secret),
            None => api::ApiState::new_no_auth(),
        };
        // Subscribe to event bus BEFORE spawning to avoid race condition
        // where events are emitted before the state updater is ready
        let event_rx = event_bus.subscribe();
        let event_bus_for_api = event_bus.clone();

        tokio::spawn(async move {
            if let Err(e) = api::run_server(
                api.port,
                api.bind_address,
                api.cors_origin,
                api_state,
                event_bus_for_api,
                event_rx,
            )
            .await
            {
                error!(error = %e, "API server error");
            }
        });
    }

    let registry = Arc::new(RwLock::new(TunneledPeerRegistry::new(
        master_key.clone(),
        max_tunneled_peers,
    )));

    // Discovery peer: UDP only on the main port
    let discovery_socket = Arc::new(
        UdpSocket::bind(format!("0.0.0.0:{}", discovery_port))
            .await
            .map_err(|e| Error::Io(format!("failed to bind discovery UDP: {}", e)))?,
    );

    let discovery_endpoint = Endpoint::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        discovery_port,
        discovery_port,
    );

    let discv4 = Arc::new(DiscV4::new(
        discovery_socket,
        master_key.clone(),
        discovery_endpoint,
    ));

    info!(port = discovery_port, "discovery peer listening on UDP");
    info!("waiting for client FINDNODE to create tunneled peers");

    // Create shutdown broadcast channel
    // Capacity of 1 is enough since we only send one shutdown signal
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // Run discovery peer with graceful shutdown
    tokio::select! {
        _ = run_discovery_peer(
            discv4,
            registry,
            discovery_source,
            client_id.to_string(),
            max_tunneled_peers,
            max_clients,
            shutdown_tx.clone(),
            event_bus,
        ) => {}
        _ = shutdown_signal() => {
            info!("received shutdown signal, sending DISCONNECT to peers");

            // Broadcast shutdown to all tunnels
            // This will cause each tunnel to send DISCONNECT to client and peer
            let _ = shutdown_tx.send(());

            // Wait for tunnels to send DISCONNECT messages
            debug!("waiting for grace period");
            tokio::time::sleep(SHUTDOWN_GRACE_PERIOD).await;

            info!("shutdown complete");
        }
    }

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
}
