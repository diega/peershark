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
| `--api-port` | HTTP API port |
| `--api-host` | Address to bind API server (default: 127.0.0.1) |
| `--api-cors-origin` | CORS origin (use * with caution) |
| `--jwt-secret-file` | Path to JWT secret (32 bytes hex) |
| `--no-auth` | Disable authentication (requires PEERSHARK_ALLOW_NO_AUTH=1) |

## API

PeerShark exposes an HTTP/WebSocket API for external observability.

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/tunnels` | GET | List active tunnels with connection info |
| `/api/stats` | GET | Traffic statistics per tunnel |
| `/ws/events` | WebSocket | Real-time event stream with subscriptions |

### Authentication

- **JWT Bearer token**: `Authorization: Bearer <token>`
- **HttpOnly cookie**: Set automatically after first authenticated request

### Running with API

```bash
openssl rand -hex 32 > jwt_secret.txt

cargo run --release -- \
  -k key.txt \
  -e 'enrtree://...' \
  -l 30306 \
  --api-port 8080 \
  --jwt-secret-file jwt_secret.txt
```

### Generating API Tokens

```bash
# Generate a token valid for 24 hours
cargo run --release -- generate-token \
  --jwt-secret-file jwt_secret.txt \
  --expires-in 24h
```

Expiration formats: `1h`, `24h`, `7d`, `30d`

- **Offline generation**: No running proxy required
- **Stdout output**: Easy to pipe to files or scripts

### WebSocket Event Subscriptions

Connect to `/ws/events` to receive real-time events. The connection flow:

1. **Connect**: Receive initial `state` message with active tunnels
2. **Lifecycle events**: Always receive `peer_connected`, `peer_disconnected`, `connection_attempt_failed`
3. **Traffic ticks**: Always receive lightweight `traffic_tick` events (tunnel_id, direction, size, timestamp)
4. **Subscribe**: Send `subscribe` command to receive full `message_relayed` events with protocol details
5. **Filter**: Use Wireshark-like syntax to filter `message_relayed` events

#### Client Commands

```json
// Subscribe to all MessageRelayed events
{"cmd": "subscribe"}

// Subscribe with filter
{"cmd": "subscribe", "filter": "protocol == \"eth\" && size > 1000"}

// Subscribe with raw bytes included (default: false)
{"cmd": "subscribe", "include_raw": true}

// Subscribe with filter and raw bytes
{"cmd": "subscribe", "filter": "protocol == \"eth\"", "include_raw": true}

// Update filter without resubscribing
{"cmd": "set_filter", "filter": "msg_name in [\"GetBlockHeaders\", \"BlockHeaders\"]"}

// Stop receiving MessageRelayed (keep lifecycle events)
{"cmd": "unsubscribe"}
```

> **Note**: By default, `raw` bytes are omitted from `message_relayed` events to reduce bandwidth.
> Set `include_raw: true` to receive the hex-encoded raw message bytes.

#### Server Messages

```json
// Initial state on connect
{"type": "state", "collecting_since": 1704067200000, "tunnels": [...]}

// Lifecycle events (always sent)
{"type": "event", "data": {"type": "peer_connected", "tunnel_id": "abc123", ...}}

// Traffic ticks (always sent, lightweight)
{"type": "event", "data": {"type": "traffic_tick", "tunnel_id": "abc123", "direction": "client_to_peer", "size": 128, "timestamp": 1704067200000}}

// Full traffic events (after subscribe, filtered)
{"type": "event", "data": {"type": "message_relayed", "msg_name": "GetBlockHeaders", "protocol": "eth", ...}}

// Subscription confirmed
{"type": "subscribed", "filter_description": "protocol == eth", "include_raw": false}

// Filter updated
{"type": "filter_updated", "filter_description": "size > 1000"}

// Error
{"type": "error", "code": "invalid_filter", "message": "Unknown field 'foo'"}

// Gap notification (buffer overflow)
{"type": "gap", "from": 1704067200000, "to": 1704067210000, "reason": "buffer overflow: 15 events dropped"}
```

#### Filter Syntax

Wireshark-like filter expressions for `MessageRelayed` events:

```
# Field comparisons
msg_name == "GetBlockHeaders"
direction == "client_to_peer"
protocol == "eth"

# Numeric comparisons
size > 1000
msg_id == 0x13

# String operations
tunnel_id starts_with "abc"
msg_name contains "Block"

# Logical operators
protocol == "eth" && size > 1000
protocol == "eth" || protocol == "snap"
!(msg_name == "Ping")

# Grouping
(protocol == "eth" || protocol == "snap") && size > 1000

# IN operator
msg_name in ["Status", "GetBlockHeaders", "BlockHeaders"]
protocol in ["eth", "snap"]
```

#### Filterable Fields

| Field | Type | Operators |
|-------|------|-----------|
| `tunnel_id` | String | `==`, `!=`, `starts_with`, `contains` |
| `direction` | Enum | `==`, `!=` (`client_to_peer`, `peer_to_client`) |
| `msg_id` | u8 | `==`, `!=`, `>`, `>=`, `<`, `<=` |
| `msg_name` | String | `==`, `!=`, `contains`, `in` |
| `protocol` | Enum | `==`, `!=`, `in` (`p2p`, `eth`, `snap`, `unknown`) |
| `size` | usize | `==`, `!=`, `>`, `>=`, `<`, `<=` |
| `timestamp` | i64 | `==`, `!=`, `>`, `>=`, `<`, `<=` |

#### Security Limits

| Limit | Value |
|-------|-------|
| Filter length | 4096 bytes |
| AST depth | 16 levels |
| IN list size | 100 items |

## Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                         PeerShark                                  │
├────────────────────────────────────────────────────────────────────┤
│  HTTP/WebSocket API (:8080)                                        │
│  ├─ GET /api/tunnels, /api/stats                                  │
│  ├─ WS /ws/events (real-time stream)                              │
│  └─ JWT + Cookie authentication                                   │
├────────────────────────────────────────────────────────────────────┤
│  Discovery Peer (UDP :30306)     Tunneled Peers (localhost)       │
│  ├─ Responds to FINDNODE         ├─ Peer 1 (derived key #1)       │
│  └─ Returns tunneled peers       ├─ Peer 2 (derived key #2)       │
│                                  └─ Peer N (derived key #N)       │
├────────────────────────────────────────────────────────────────────┤
│  Event Bus (broadcast channel)                                     │
│  ├─ PeerConnected / PeerDisconnected                              │
│  ├─ MessageRelayed (direction, protocol, size, decoded, raw)      │
│  └─ TrafficTick (derived from MessageRelayed, always sent to WS)  │
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

### API Security

- **Rate limiting**: 10 requests/second per IP (token bucket via governor)
- **HttpOnly cookies**: Prevents XSS from accessing tokens
- **CORS**: Configurable origin, credentials require specific origin (not *)
- **Max WebSocket connections**: 50 concurrent (prevents resource exhaustion)

### State Management

- **Atomic counters**: bytes_in/out use AtomicU64 (lock-free on hot path)
- **RwLock for tunnel map**: Occasional writes, frequent reads
- **Event-driven updates**: State derived from event bus, not direct mutation

### Event-Driven State

The API state is updated by subscribing to the event bus:

```
tunnel.rs --> emit(PeerConnected) --> event_bus
                                          |
                                          v
                                  spawn_state_updater()
                                          |
                                          v
                                  state.add_tunnel()
                                          |
                                          v
                                  GET /api/tunnels
```

- **Decoupling**: Tunnel code doesn't import API modules
- **Eventual consistency**: Microsecond lag between event and state update
- **Lag detection**: Warns if updater falls behind event stream

## Project Structure

```
src/
├── main.rs             CLI and orchestration
├── api/
│   ├── mod.rs          API module exports
│   ├── auth.rs         JWT validation and cookie handling
│   ├── filter.rs       Filter expression parser and evaluator
│   ├── server.rs       HTTP/WebSocket server (axum)
│   ├── state.rs        Shared state with atomic counters
│   └── websocket.rs    WebSocket subscriptions and filtering
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
- JWT required for all endpoints (unless `--no-auth`)
- `--no-auth` requires `PEERSHARK_ALLOW_NO_AUTH=1` env var
- Cookies: `HttpOnly`, `Secure`, `SameSite=Strict`
- Rate limit: 10 req/s per IP
- Max 50 concurrent WebSocket connections
- Binds to `127.0.0.1` by default
- CORS `*` requires `PEERSHARK_ALLOW_CORS_ANY=1` env var
- Tokens require explicit expiration (`--expires-in`)
- JWT secret files require mode `0600`

## License

Apache-2.0
