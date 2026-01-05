#![allow(dead_code)]

mod api;
mod bytes;
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

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Arg, ArgGroup, Command};
use k256::ecdsa::SigningKey;
use time::UtcOffset;
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, error, info, warn};
use tracing_subscriber::fmt::time::OffsetTime;

use constants::{PRIVATE_KEY_LEN, SHUTDOWN_GRACE_PERIOD};
use crypto::pubkey_to_node_id;
use discv4::{DiscV4, Endpoint};
use error::Error;
use event_bus::EventBus;
use proxy_discovery::{DiscoverySource, run_discovery_peer, validate_enode_url};
use tunneled_peers::TunneledPeerRegistry;

/// Configuration for the HTTP/WebSocket API server.
pub struct ApiConfig {
    pub port: u16,
    pub bind_address: Option<String>,
    pub cors_origin: Option<String>,
    pub jwt_secret: Option<Vec<u8>>,
}

fn main() -> ExitCode {
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

    let matches = Command::new("peershark")
        .version("0.1.0")
        .about("P2P traffic analyzer for Ethereum devp2p protocol")
        .arg(
            Arg::new("private-key")
                .short('k')
                .long("private-key")
                .required(true)
                .help("Path to private key file (master key for discovery peer)"),
        )
        .arg(
            Arg::new("bootnodes")
                .short('b')
                .long("bootnodes")
                .value_delimiter(',')
                .help("Comma-separated enode URLs for P2P discovery bootstrap"),
        )
        .arg(
            Arg::new("enrtree")
                .short('e')
                .long("enrtree")
                .help("enrtree:// URL for DNS node discovery (EIP-1459)"),
        )
        .arg(
            Arg::new("dns-cache")
                .long("dns-cache")
                .default_value("dns_cache.json")
                .help("Path to DNS discovery cache file"),
        )
        .group(
            ArgGroup::new("node-source")
                .args(["bootnodes", "enrtree"])
                .required(true),
        )
        .arg(
            Arg::new("client-id")
                .short('c')
                .long("client-id")
                .default_value("peershark/0.1.0")
                .help("Client ID string for Hello message"),
        )
        .arg(
            Arg::new("listen")
                .short('l')
                .long("listen")
                .required(true)
                .help("Port for discovery peer (UDP only)"),
        )
        .arg(
            Arg::new("max-tunneled-peers")
                .long("max-tunneled-peers")
                .default_value("10")
                .help("Maximum number of tunneled peers to create"),
        )
        .arg(
            Arg::new("api-port")
                .long("api-port")
                .help("Port for API HTTP/WebSocket server"),
        )
        .arg(
            Arg::new("api-host")
                .long("api-host")
                .default_value("127.0.0.1")
                .help("Address for API server to bind to (default: 127.0.0.1)"),
        )
        .arg(
            Arg::new("api-cors-origin")
                .long("api-cors-origin")
                .help("CORS origin for API (use '*' for any)"),
        )
        .arg(
            Arg::new("jwt-secret-file")
                .long("jwt-secret-file")
                .help("Path to JWT secret file (32 bytes hex). Auto-generates if not specified"),
        )
        .arg(
            Arg::new("no-auth")
                .long("no-auth")
                .action(clap::ArgAction::SetTrue)
                .help("Disable API authentication (for development only)"),
        )
        .get_matches();

    let key_path: &String = matches.get_one("private-key").expect("required arg");
    let bootnodes: Option<Vec<&String>> = matches.get_many("bootnodes").map(|v| v.collect());
    let enrtree_url: Option<&String> = matches.get_one("enrtree");
    let dns_cache_path: &String = matches.get_one("dns-cache").expect("has default");
    let client_id: &String = matches.get_one("client-id").expect("has default");
    let listen_port: &String = matches.get_one("listen").expect("required arg");
    let max_tunneled_peers: usize = matches
        .get_one::<String>("max-tunneled-peers")
        .expect("has default")
        .parse()
        .unwrap_or(10);

    let api_port: Option<u16> = matches
        .get_one::<String>("api-port")
        .and_then(|s| s.parse().ok());
    let api_host: Option<String> = matches.get_one::<String>("api-host").cloned();
    let api_cors_origin: Option<String> = matches.get_one::<String>("api-cors-origin").cloned();
    let jwt_secret_file: Option<&String> = matches.get_one("jwt-secret-file");
    let no_auth = matches.get_flag("no-auth");

    // Require explicit environment variable to disable authentication
    if no_auth && std::env::var("PEERSHARK_ALLOW_NO_AUTH").is_err() {
        error!("--no-auth requires PEERSHARK_ALLOW_NO_AUTH=1 environment variable");
        error!("This flag disables ALL API authentication and should only be used for development");
        return ExitCode::from(1);
    }

    let master_key = match load_private_key(key_path) {
        Ok(key) => key,
        Err(e) => {
            error!(error = %e, "failed to load private key");
            return ExitCode::from(1);
        }
    };

    let discovery_node_id = pubkey_to_node_id(&master_key);

    // Parse port early so we can print enode immediately
    let port: u16 = match listen_port.parse() {
        Ok(p) => p,
        Err(e) => {
            error!(error = %e, "invalid port");
            return ExitCode::from(1);
        }
    };

    // Print enode IMMEDIATELY so client can connect while discovery runs
    info!(
        enode = %format!("enode://{}@<host>:{}", hex::encode(discovery_node_id), port),
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
    let discovery_source = if let Some(nodes) = bootnodes {
        match validate_bootnodes(&nodes) {
            Ok(urls) => {
                info!(count = urls.len(), "using bootnodes from CLI");
                DiscoverySource::Bootnodes(urls)
            }
            Err(e) => {
                error!(error = %e, "invalid bootnode");
                return ExitCode::from(1);
            }
        }
    } else if let Some(url) = enrtree_url {
        info!("DNS discovery will run in background");
        DiscoverySource::DnsDiscovery {
            url: url.clone(),
            cache_path: dns_cache_path.clone(),
        }
    } else {
        error!("either --bootnodes or --enrtree is required");
        return ExitCode::from(1);
    };

    // Load or generate JWT secret if API is enabled (unless --no-auth)
    let jwt_secret = if api_port.is_some() && !no_auth {
        let default_path = "peershark-jwt-secret.hex";
        let secret_path = jwt_secret_file.map(|s| s.as_str()).unwrap_or(default_path);

        if std::path::Path::new(secret_path).exists() {
            match api::auth::load_secret_from_file(secret_path) {
                Ok(s) => {
                    info!(path = %secret_path, "loaded JWT secret");
                    Some(s)
                }
                Err(e) => {
                    error!(error = %e, "failed to load JWT secret");
                    return ExitCode::from(1);
                }
            }
        } else if jwt_secret_file.is_some() {
            error!(path = %secret_path, "JWT secret file not found");
            return ExitCode::from(1);
        } else {
            match api::auth::generate_secret_file(secret_path) {
                Ok(s) => {
                    info!(path = %secret_path, "generated new JWT secret");
                    Some(s)
                }
                Err(e) => {
                    error!(error = %e, "failed to generate JWT secret");
                    return ExitCode::from(1);
                }
            }
        }
    } else if no_auth && api_port.is_some() {
        warn!("API authentication disabled (--no-auth)");
        None
    } else {
        None
    };

    let api_config = api_port.map(|p| ApiConfig {
        port: p,
        bind_address: api_host,
        cors_origin: api_cors_origin,
        jwt_secret,
    });

    runtime.block_on(async {
        if let Err(e) = run_proxy(
            port,
            &master_key,
            client_id,
            discovery_source,
            max_tunneled_peers,
            api_config,
        )
        .await
        {
            error!(error = %e, "proxy error");
        }
    });

    ExitCode::from(0)
}

fn load_private_key(path: &str) -> Result<SigningKey, String> {
    // Check file permissions first (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata =
            fs::metadata(path).map_err(|e| format!("failed to read key file metadata: {}", e))?;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "private key file has insecure permissions {:o}, expected 0600",
                mode & 0o777
            ));
        }
    }

    let key_hex =
        fs::read_to_string(path).map_err(|e| format!("failed to read key file: {}", e))?;
    let key_bytes: Vec<u8> =
        hex::decode(key_hex.trim()).map_err(|e| format!("invalid hex: {}", e))?;

    if key_bytes.len() != PRIVATE_KEY_LEN {
        return Err(format!(
            "private key must be {} bytes, got {}",
            PRIVATE_KEY_LEN,
            key_bytes.len()
        ));
    }

    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "failed to convert to array")?;
    SigningKey::from_bytes(&key_array.into()).map_err(|e| format!("invalid key: {}", e))
}

fn validate_bootnodes(nodes: &[&String]) -> Result<Vec<String>, Error> {
    for node in nodes {
        validate_enode_url(node)?;
    }
    Ok(nodes.iter().map(|s| (*s).clone()).collect())
}

async fn run_proxy(
    discovery_port: u16,
    master_key: &SigningKey,
    client_id: &str,
    discovery_source: DiscoverySource,
    max_tunneled_peers: usize,
    api: Option<ApiConfig>,
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
