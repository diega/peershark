# PeerShark

A transparent P2P traffic analyzer for Ethereum networks.

## The Problem

When you run an Ethereum node, you see logs about peers connecting and blocks syncing, but you don't really know:
- Which peers are sending you blocks first?
- How long do connections last before dropping?
- What's the actual latency to each peer?
- Are you getting duplicate messages from multiple peers?

PeerShark sits between your node and the network, decoding all devp2p traffic in real-time.

## How It Works

PeerShark acts as a transparent proxy with multiple tunneled identities:

```
Your Node                    PeerShark                      Network
    |                            |                             |
    +---- connects to -----> [Tunneled Peer 1] ---------> Real Peer A
    |                        [Tunneled Peer 2] ---------> Real Peer B
    |                        [Tunneled Peer N] ---------> Real Peer N
    |                            |
    |                      [Discovery Peer]
    |                       (responds to FINDNODE
    |                        with tunneled peers)
```

Your node thinks it's talking to normal peers. Each "tunneled peer" is PeerShark proxying to a real peer on the network.

## Usage

```bash
# Generate a private key
openssl rand -hex 32 > key.txt

# Run with DNS discovery
cargo run --release -- \
  -k key.txt \
  -e 'enrtree://AKA3AM6LPBYEUDMVNU3BSVQJ5AD45Y7YPOHJLEF6W26QOE4VTUDPE@all.mainnet.ethdisco.net' \
  -l 30306 \
  --max-tunneled-peers 10
```

### Connecting Your Node

Point your Ethereum node to PeerShark as its only bootnode:

```bash
# Besu
besu \
  --bootnodes="enode://<PEERSHARK_ID>@127.0.0.1:30306" \
  --discovery-dns-url="" \
  --discovery-enabled=true
```

### Options

| Flag | Description |
|------|-------------|
| `-C, --config` | Path to TOML configuration file |
| `-k, --private-key` | Path to master key file (required) |
| `-e, --enrtree` | DNS discovery URL (EIP-1459) |
| `-b, --bootnodes` | Static enode URLs (comma-separated) |
| `-l, --listen` | Discovery port (required) |
| `--dns-cache` | Path to DNS discovery cache file |
| `-c, --client-id` | Client ID string for Hello message |
| `--max-tunneled-peers` | Tunneled peers to create (default: 10) |
| `--max-clients` | Maximum unique clients allowed |

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                         PeerShark Proxy                            │
├────────────────────────────────────────────────────────────────────┤
│  Discovery Peer (UDP :30306)     Tunneled Peers (localhost)       │
│  ├─ Responds to FINDNODE         ├─ Peer 1 (derived key #1)       │
│  └─ Returns tunneled peers       ├─ Peer 2 (derived key #2)       │
│                                  └─ Peer N (derived key #N)       │
├────────────────────────────────────────────────────────────────────┤
│  Event Bus (broadcast channel)                                     │
│  ├─ PeerConnected / PeerDisconnected                              │
│  └─ MessageRelayed (direction, protocol, size, timestamp)         │
├────────────────────────────────────────────────────────────────────┤
│  Peer Discovery                                                    │
│  ├─ discv4 UDP (PING/PONG, FINDNODE/NEIGHBORS)                    │
│  └─ DNS EIP-1459 (ENR tree traversal)                             │
├────────────────────────────────────────────────────────────────────┤
│  RLPx Protocol Stack                                               │
│  ├─ eth subprotocol (Status, Blocks, Transactions)                │
│  ├─ P2P base (Hello, Disconnect, Ping, Pong)                      │
│  └─ Encrypted Session (ECIES + AES-256-CTR)                       │
└────────────────────────────────────────────────────────────────────┘
```

## Design Decisions

### HKDF Key Derivation

Each tunneled peer gets a unique identity derived from the master key:

```
derived_key = HKDF-SHA256(master_key, context=neighbor_pubkey)
```

- **Deterministic**: Same master + neighbor -> same derived key (reproducible)
- **Isolated**: Compromising one derived key doesn't expose master or siblings
- **Auditable**: Context includes neighbor pubkey for traceability

### Transparent Relay

- Messages pass through **without modification**
- Full protocol decoding for analysis, but no content alteration
- Bidirectional relay with timeout detection

### Peer Selection

- Random selection from scored peer pool
- Distributes load across available real peers
- Automatic retry on connection failure

### Peer Scoring System

| Failure Type | Penalty | Recovery |
|--------------|---------|----------|
| Connection refused | -3 | Gradual |
| Timeout | -2 | Gradual |
| Genesis mismatch | Permanent ban | Never |
| Invalid identity | Permanent ban | Never |

### Event Bus

- **Tokio broadcast channel**: Multiple subscribers, async-native
- **Drop-on-lag**: If a subscriber can't keep up, events are dropped (acceptable for observability)
- **Structured events**: Each event includes timestamp (ms), direction, protocol classification
- **Decoupled**: Tunnel code emits events without knowing who listens

## Project Structure

```
src/
├── main.rs             CLI and orchestration
├── client_registry.rs  Client connection tracking
├── config.rs           CLI parsing and TOML config
├── eth_messages.rs     ETH protocol message decoding
├── snap_messages.rs    SNAP protocol message decoding
├── event_bus.rs        Broadcast channel for events
├── events.rs           Event types (PeerConnected, MessageRelayed, etc.)
├── tunnel.rs           Bidirectional message relay
├── tunneled_peers.rs   HKDF key derivation, peer registry
├── proxy_discovery.rs  Discovery peer (responds to FINDNODE)
├── discv4.rs           Discovery v4 UDP protocol
├── dns_discovery.rs    EIP-1459 DNS discovery
├── peer_pool.rs        Peer scoring and selection
├── connection.rs       Connection establishment
├── session.rs          Encrypted session (cancellation-safe)
├── p2p.rs              P2P protocol messages
├── eth.rs              eth subprotocol
├── frame.rs            RLPx frame encryption
├── handshake.rs        Auth/Ack structures
├── ecies.rs            ECIES encryption
├── crypto.rs           Cryptographic helpers
├── rlp.rs              RLP encode/decode
├── bytes.rs            Integer encoding
├── constants.rs        Protocol constants
└── error.rs            Error types
```

## Building

```bash
cargo build --release
```

## Security Notes

- Private key files require mode `0600` (validated on startup)
- ECIES uses AES-128-CTR per devp2p spec
- Fresh ephemeral keypair generated for each encryption
- `HANDSHAKE_TIMEOUT` (10s) prevents Slowloris attacks
- `MAX_FRAME_SIZE` (4MB) prevents memory exhaustion
- Cancellation-safe reads prevent state corruption in relay loop
- Discovery messages expire after 60s (prevents replay attacks)
- DNS root records verified against `enrtree://` public key
- Genesis mismatch and invalid identity cause permanent bans
- HKDF key isolation: derived keys don't expose master or siblings
- `TUNNEL_IDLE_TIMEOUT` (60s) closes zombie connections
- Deterministic derivation enables reproducible debugging

## License

Apache-2.0
