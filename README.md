# PeerShark

Transparent P2P traffic analyzer for Ethereum networks.

## Current State

Library-only implementation of RLP (Recursive Length Prefix) encoding, the serialization format used throughout Ethereum.

## Features

- RLP encoding and decoding as per Ethereum Yellow Paper
- Support for nested lists with configurable max depth (default: 16)
- Minimal integer encoding (no leading zeros)
- Type-safe parsing with Result-based API

## Design Decisions

- **MAX_RLP_DEPTH = 16**: Prevents stack overflow attacks from maliciously nested lists
- **RlpItem enum**: Two variants (Bytes/List) allow natural representation of RLP's recursive structure
- **Fallible conversions**: `into_list()` and `into_bytes()` return Result instead of panicking

## Project Structure

```
src/
├── main.rs      Entry point
├── rlp.rs       RLP encode/decode
├── bytes.rs     Integer encoding utilities
└── error.rs     Error types
```

## License

Apache-2.0
