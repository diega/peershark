//! Configuration management with CLI parsing and TOML file support.

use std::path::PathBuf;

use clap::{Args, Parser};
use k256::ecdsa::SigningKey;
use serde::Deserialize;

use crate::constants::{DEFAULT_MAX_CLIENTS, PRIVATE_KEY_LEN};

// ============================================================================
// CLI STRUCTS
// ============================================================================

/// P2P traffic analyzer for Ethereum devp2p protocol.
#[derive(Parser, Debug)]
#[command(name = "peershark", version = "0.1.0")]
pub struct Cli {
    #[command(flatten)]
    pub core: CoreArgs,
}

/// Core arguments for the proxy.
#[derive(Args, Debug, Default)]
pub struct CoreArgs {
    /// Path to TOML configuration file.
    #[arg(short = 'C', long)]
    pub config: Option<PathBuf>,

    /// Path to private key file (master key for discovery peer).
    #[arg(short = 'k', long = "private-key")]
    pub private_key: Option<PathBuf>,

    /// Comma-separated enode URLs for P2P discovery bootstrap.
    #[arg(short = 'b', long, value_delimiter = ',')]
    pub bootnodes: Vec<String>,

    /// enrtree:// URL for DNS node discovery (EIP-1459).
    #[arg(short = 'e', long)]
    pub enrtree: Option<String>,

    /// Path to DNS discovery cache file.
    #[arg(long = "dns-cache")]
    pub dns_cache: Option<PathBuf>,

    /// Client ID string for Hello message.
    #[arg(short = 'c', long = "client-id")]
    pub client_id: Option<String>,

    /// Port for discovery peer (UDP only).
    #[arg(short = 'l', long = "listen")]
    pub listen: Option<u16>,

    /// Maximum number of tunneled peers to create.
    #[arg(long = "max-tunneled-peers")]
    pub max_tunneled_peers: Option<usize>,

    /// Maximum number of unique clients that can connect.
    #[arg(long = "max-clients")]
    pub max_clients: Option<usize>,
}

// ============================================================================
// CONFIG FILE STRUCTS
// ============================================================================

/// Configuration loaded from TOML file.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFile {
    pub private_key: Option<String>,
    #[serde(default)]
    pub bootnodes: Vec<String>,
    pub enrtree: Option<String>,
    pub dns_cache: Option<String>,
    pub client_id: Option<String>,
    pub listen_port: Option<u16>,
    pub max_tunneled_peers: Option<usize>,
    pub max_clients: Option<usize>,
}

// ============================================================================
// RUNTIME CONFIG
// ============================================================================

/// Final merged configuration for runtime.
pub struct RuntimeConfig {
    pub private_key_path: PathBuf,
    pub bootnodes: Vec<String>,
    pub enrtree: Option<String>,
    pub dns_cache_path: PathBuf,
    pub client_id: String,
    pub listen_port: u16,
    pub max_tunneled_peers: usize,
    pub max_clients: usize,
}

impl RuntimeConfig {
    /// Merge CLI args with config file. Precedence: CLI > config file > defaults.
    pub fn from_cli_and_file(cli: &Cli, file: ConfigFile) -> Result<Self, ConfigError> {
        let private_key_path = cli
            .core
            .private_key
            .clone()
            .or_else(|| file.private_key.map(PathBuf::from))
            .ok_or(ConfigError::MissingRequired("private-key"))?;

        let bootnodes = if !cli.core.bootnodes.is_empty() {
            cli.core.bootnodes.clone()
        } else {
            file.bootnodes
        };

        let enrtree = cli.core.enrtree.clone().or(file.enrtree);

        if bootnodes.is_empty() && enrtree.is_none() {
            return Err(ConfigError::MissingNodeSource);
        }

        let dns_cache_path = cli
            .core
            .dns_cache
            .clone()
            .or_else(|| file.dns_cache.map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("dns_cache.json"));

        let client_id = cli
            .core
            .client_id
            .clone()
            .or(file.client_id)
            .unwrap_or_else(|| "peershark/0.1.0".to_string());

        let listen_port = cli
            .core
            .listen
            .or(file.listen_port)
            .ok_or(ConfigError::MissingRequired("listen"))?;

        let max_tunneled_peers = cli
            .core
            .max_tunneled_peers
            .or(file.max_tunneled_peers)
            .unwrap_or(10);

        let max_clients = cli
            .core
            .max_clients
            .or(file.max_clients)
            .unwrap_or(DEFAULT_MAX_CLIENTS);

        Ok(RuntimeConfig {
            private_key_path,
            bootnodes,
            enrtree,
            dns_cache_path,
            client_id,
            listen_port,
            max_tunneled_peers,
            max_clients,
        })
    }
}

// ============================================================================
// ERRORS
// ============================================================================

/// Configuration errors.
#[derive(Debug)]
pub enum ConfigError {
    MissingRequired(&'static str),
    MissingNodeSource,
    Io(std::io::Error),
    Toml(toml::de::Error),
    InvalidPrivateKey(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingRequired(field) => {
                write!(f, "--{} is required (via CLI or config file)", field)
            }
            Self::MissingNodeSource => {
                write!(f, "either --bootnodes or --enrtree is required")
            }
            Self::Io(e) => write!(f, "{}", e),
            Self::Toml(e) => write!(f, "config parse error: {}", e),
            Self::InvalidPrivateKey(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ConfigError {}

// ============================================================================
// LOADING FUNCTIONS
// ============================================================================

/// Load TOML config file, returns default if path is None.
pub fn load_config_file(path: Option<&PathBuf>) -> Result<ConfigFile, ConfigError> {
    match path {
        Some(p) => {
            let content = std::fs::read_to_string(p).map_err(ConfigError::Io)?;
            toml::from_str(&content).map_err(ConfigError::Toml)
        }
        None => Ok(ConfigFile::default()),
    }
}

/// Load private key from file with permission checks.
pub fn load_private_key(path: &PathBuf) -> Result<SigningKey, ConfigError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path).map_err(ConfigError::Io)?;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(ConfigError::InvalidPrivateKey(format!(
                "private key file has insecure permissions {:o}, expected 0600",
                mode & 0o777
            )));
        }
    }

    let key_hex = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
    let key_bytes = hex::decode(key_hex.trim())
        .map_err(|e| ConfigError::InvalidPrivateKey(format!("invalid hex: {}", e)))?;

    if key_bytes.len() != PRIVATE_KEY_LEN {
        return Err(ConfigError::InvalidPrivateKey(format!(
            "private key must be {} bytes, got {}",
            PRIVATE_KEY_LEN,
            key_bytes.len()
        )));
    }

    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| ConfigError::InvalidPrivateKey("failed to convert to array".to_string()))?;

    SigningKey::from_bytes(&key_array.into())
        .map_err(|e| ConfigError::InvalidPrivateKey(format!("invalid key: {}", e)))
}
