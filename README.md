# PeerShark

Transparent P2P traffic analyzer for Ethereum networks.

## Current State

Core cryptographic layer implementing ECIES encryption and RLPx handshake for establishing secure Ethereum P2P connections.

## Features

- RLP encoding and decoding as per Ethereum Yellow Paper
- ECIES encryption using secp256k1 curve
- RLPx frame encryption with AES-256-CTR and MAC authentication
- Bidirectional handshake (Auth/Ack) for session establishment
- Enode URL parsing

## Architecture

```
┌─────────────────────────────────────────┐
│              RLPx Session               │
├─────────────────────────────────────────┤
│  Auth ────────────────────────► Ack     │
│  (ECIES encrypted, ephemeral keys)      │
├─────────────────────────────────────────┤
│         Frame Encryption Layer          │
│    AES-256-CTR + Keccak256 MACs         │
├─────────────────────────────────────────┤
│              RLP Encoding               │
└─────────────────────────────────────────┘
```

## Design Decisions

- **Stateful ciphers**: FrameCoder maintains AES counter and MAC state across frames, avoiding re-initialization overhead
- **Ephemeral keys per message**: ECIES generates new key for each Auth/Ack, never reuses
- **Zero IV with stateful counter**: AES-CTR reuses stream position, safe because keys are unique per session
- **Separate key derivation**: ECIES shared secret split into AES key (16 bytes) + MAC key (16 bytes)

## Project Structure

```
src/
├── main.rs        Entry point
├── ecies.rs       ECIES encryption
├── frame.rs       RLPx frame encryption
├── handshake.rs   Auth/Ack structures
├── crypto.rs      Cryptographic helpers
├── constants.rs   Protocol constants
├── rlp.rs         RLP encode/decode
├── bytes.rs       Integer encoding
└── error.rs       Error types
```

## Security Notes

- Private key files require mode `0600` (validated on startup)
- ECIES uses AES-128-CTR per devp2p spec
- Fresh ephemeral keypair generated for each encryption

## License

Apache-2.0
