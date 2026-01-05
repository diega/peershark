# PeerShark

Transparent P2P traffic analyzer for Ethereum networks.

## Current State

Functional P2P protocol implementation with encrypted sessions and eth subprotocol support.

## Features

- RLP encoding and decoding as per Ethereum Yellow Paper
- ECIES encryption and RLPx framing
- P2P protocol messages: Hello, Disconnect, Ping, Pong
- eth subprotocol with Status message exchange
- Snappy compression for subprotocol messages
- Cancellation-safe async reads

## Architecture

```
┌─────────────────────────────────────────┐
│            Application Layer            │
│  eth (Status, Blocks, Transactions)     │
├─────────────────────────────────────────┤
│             P2P Base Layer              │
│    Hello, Disconnect, Ping, Pong        │
├─────────────────────────────────────────┤
│          Encrypted Session              │
│   (ECIES handshake + AES-CTR frames)    │
├─────────────────────────────────────────┤
│              RLP Encoding               │
├─────────────────────────────────────────┤
│                  TCP                    │
└─────────────────────────────────────────┘
```

## Design Decisions

- **Cancellation-safe reads**: Session uses a state machine (Header -> Body) that resumes correctly if a tokio::select! cancels mid-read. Critical for proxy relay loops.
- **Two-phase handshake**: Crypto phase (Auth/Ack) establishes encryption, then logical phase (Hello) negotiates capabilities
- **Message framing**: 1-byte message ID + RLP payload, wrapped in encrypted frame
- **Snappy compression**: Applied to subprotocol messages (eth, snap) but not P2P base messages

## Project Structure

```
src/
├── main.rs        Entry point
├── connection.rs  Handshake as initiator/responder
├── session.rs     Encrypted session (cancellation-safe)
├── p2p.rs         P2P protocol messages
├── eth.rs         eth subprotocol (Status)
├── frame.rs       RLPx frame encryption
├── handshake.rs   Auth/Ack structures
├── ecies.rs       ECIES encryption
├── crypto.rs      Cryptographic helpers
├── rlp.rs         RLP encode/decode
├── bytes.rs       Integer encoding
├── constants.rs   Protocol constants
└── error.rs       Error types
```

## Security Notes

- Private key files require mode `0600` (validated on startup)
- ECIES uses AES-128-CTR per devp2p spec
- Fresh ephemeral keypair generated for each encryption
- `HANDSHAKE_TIMEOUT` (10s) prevents Slowloris attacks
- `MAX_FRAME_SIZE` (4MB) prevents memory exhaustion
- Cancellation-safe reads prevent state corruption in relay loop

## License

Apache-2.0
