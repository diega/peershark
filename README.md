# PeerShark

Transparent P2P traffic analyzer for Ethereum networks.

## Current State

Full P2P stack with dual discovery mechanisms (discv4 UDP and DNS-based EIP-1459) and peer scoring.

## Features

- Complete RLPx protocol stack (encryption, framing, P2P, eth)
- discv4 protocol: PING/PONG, FINDNODE/NEIGHBORS over UDP
- EIP-1459 DNS node discovery with ENR tree traversal
- Peer pool with scoring and failure categorization
- Signature verification on DNS root records

## Architecture

```
                ┌─────────────────────────────┐
                │       Peer Discovery        │
                ├──────────────┬──────────────┤
                │   discv4     │  DNS (1459)  │
                │  UDP :30303  │   ENR tree   │
                └──────┬───────┴───────┬──────┘
                       │               │
                       └───────┬───────┘
                               ▼
                     ┌─────────────────┐
                     │    Peer Pool    │
                     │ (scoring/retry) │
                     └────────┬────────┘
                              ▼
                    RLPx Connection Stack
```

## Design Decisions

### Peer Scoring System

The peer pool assigns scores to track reliability:

| Failure Type | Penalty | Recovery |
|--------------|---------|----------|
| Connection refused | -3 | Gradual |
| Timeout | -2 | Gradual |
| Genesis mismatch | Permanent ban | Never |
| Invalid identity | Permanent ban | Never |

- **Gradual recovery**: Score increases by 1 point per configured interval (default: 60s)
- **Ban threshold**: Peers with score <= -10 are temporarily excluded
- **Permanent bans**: Protocol-level incompatibilities (wrong chain) never recover

### DNS Discovery

- **Signature verification**: Root record must be signed by pubkey in enrtree:// URL
- **Sequence comparison**: Skip re-crawling if `seq` unchanged from cache
- **Randomization**: Shuffle discovered nodes before returning (load distribution)

### discv4 Protocol

- Packet format: hash (32) + signature (65) + type (1) + RLP payload
- Hash covers signature+type+payload (not itself)

## Project Structure

```
src/
├── main.rs           Entry point
├── discv4.rs         Discovery v4 UDP protocol
├── dns_discovery.rs  EIP-1459 DNS discovery
├── peer_pool.rs      Peer scoring and management
├── connection.rs     Connection establishment
├── session.rs        Encrypted session
├── p2p.rs            P2P protocol messages
├── eth.rs            eth subprotocol
├── frame.rs          RLPx frame encryption
├── handshake.rs      Auth/Ack structures
├── ecies.rs          ECIES encryption
├── crypto.rs         Cryptographic helpers
├── rlp.rs            RLP encode/decode
├── bytes.rs          Integer encoding
├── constants.rs      Protocol constants
└── error.rs          Error types
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

## License

Apache-2.0
