use crate::bytes::decode_u64;
use crate::rlp;
use serde::Serialize;

/// SNAP protocol message IDs (relative to capability offset).
/// The actual msg_id depends on the negotiated capability offset.
pub const GET_ACCOUNT_RANGE: u8 = 0x00;
pub const ACCOUNT_RANGE: u8 = 0x01;
pub const GET_STORAGE_RANGES: u8 = 0x02;
pub const STORAGE_RANGES: u8 = 0x03;
pub const GET_BYTECODES: u8 = 0x04;
pub const BYTECODES: u8 = 0x05;
pub const GET_TRIE_NODES: u8 = 0x06;
pub const TRIE_NODES: u8 = 0x07;

/// Decoded SNAP message with relevant fields for display.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "msg_type", rename_all = "snake_case")]
pub enum SnapMessage {
    GetAccountRange {
        request_id: u64,
        root_hash: String,
        response_bytes: u64,
    },
    AccountRange {
        request_id: u64,
        accounts: usize,
        proof_nodes: usize,
    },
    GetStorageRanges {
        request_id: u64,
        root_hash: String,
        accounts: usize,
    },
    StorageRanges {
        request_id: u64,
        slots: usize,
        proof_nodes: usize,
    },
    GetBytecodes {
        request_id: u64,
        hashes: usize,
    },
    Bytecodes {
        request_id: u64,
        codes: usize,
    },
    GetTrieNodes {
        request_id: u64,
        root_hash: String,
        paths: usize,
    },
    TrieNodes {
        request_id: u64,
        nodes: usize,
    },
    Unknown {
        msg_id: u8,
    },
}

/// Decode a SNAP protocol message.
/// msg_id should be the relative ID (0x00-0x07), not the absolute one.
pub fn decode(msg_id: u8, payload: &[u8]) -> SnapMessage {
    let decompressed = match snap::raw::Decoder::new().decompress_vec(payload) {
        Ok(data) => data,
        Err(_) => payload.to_vec(),
    };

    match msg_id {
        GET_ACCOUNT_RANGE => decode_get_account_range(&decompressed),
        ACCOUNT_RANGE => decode_account_range(&decompressed),
        GET_STORAGE_RANGES => decode_get_storage_ranges(&decompressed),
        STORAGE_RANGES => decode_storage_ranges(&decompressed),
        GET_BYTECODES => decode_get_bytecodes(&decompressed),
        BYTECODES => decode_bytecodes(&decompressed),
        GET_TRIE_NODES => decode_get_trie_nodes(&decompressed),
        TRIE_NODES => decode_trie_nodes(&decompressed),
        _ => SnapMessage::Unknown { msg_id },
    }
}

fn decode_get_account_range(data: &[u8]) -> SnapMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => {
            return SnapMessage::Unknown {
                msg_id: GET_ACCOUNT_RANGE,
            };
        }
    };

    // [request_id, root_hash, starting_hash, limit_hash, response_bytes]
    if items.len() < 5 {
        return SnapMessage::Unknown {
            msg_id: GET_ACCOUNT_RANGE,
        };
    }

    let request_id = items[0]
        .clone()
        .into_bytes()
        .map(|b| decode_u64(&b))
        .unwrap_or(0);

    let root_hash = items[1]
        .clone()
        .into_bytes()
        .map(|b| format!("0x{}", hex::encode(&b)))
        .unwrap_or_default();

    let response_bytes = items[4]
        .clone()
        .into_bytes()
        .map(|b| decode_u64(&b))
        .unwrap_or(0);

    SnapMessage::GetAccountRange {
        request_id,
        root_hash,
        response_bytes,
    }
}

fn decode_account_range(data: &[u8]) -> SnapMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => {
            return SnapMessage::Unknown {
                msg_id: ACCOUNT_RANGE,
            };
        }
    };

    // [request_id, accounts, proof]
    if items.len() < 3 {
        return SnapMessage::Unknown {
            msg_id: ACCOUNT_RANGE,
        };
    }

    let request_id = items[0]
        .clone()
        .into_bytes()
        .map(|b| decode_u64(&b))
        .unwrap_or(0);

    let accounts = items[1]
        .clone()
        .into_list()
        .map(|list| list.len())
        .unwrap_or(0);

    let proof_nodes = items[2]
        .clone()
        .into_list()
        .map(|list| list.len())
        .unwrap_or(0);

    SnapMessage::AccountRange {
        request_id,
        accounts,
        proof_nodes,
    }
}

fn decode_get_storage_ranges(data: &[u8]) -> SnapMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => {
            return SnapMessage::Unknown {
                msg_id: GET_STORAGE_RANGES,
            };
        }
    };

    // [request_id, root_hash, account_hashes, starting_hash, limit_hash, response_bytes]
    if items.len() < 3 {
        return SnapMessage::Unknown {
            msg_id: GET_STORAGE_RANGES,
        };
    }

    let request_id = items[0]
        .clone()
        .into_bytes()
        .map(|b| decode_u64(&b))
        .unwrap_or(0);

    let root_hash = items[1]
        .clone()
        .into_bytes()
        .map(|b| format!("0x{}", hex::encode(&b)))
        .unwrap_or_default();

    let accounts = items[2]
        .clone()
        .into_list()
        .map(|list| list.len())
        .unwrap_or(0);

    SnapMessage::GetStorageRanges {
        request_id,
        root_hash,
        accounts,
    }
}

fn decode_storage_ranges(data: &[u8]) -> SnapMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => {
            return SnapMessage::Unknown {
                msg_id: STORAGE_RANGES,
            };
        }
    };

    // [request_id, slots, proof]
    if items.len() < 3 {
        return SnapMessage::Unknown {
            msg_id: STORAGE_RANGES,
        };
    }

    let request_id = items[0]
        .clone()
        .into_bytes()
        .map(|b| decode_u64(&b))
        .unwrap_or(0);

    let slots = items[1]
        .clone()
        .into_list()
        .map(|list| {
            list.iter()
                .map(|item| item.clone().into_list().map(|l| l.len()).unwrap_or(0))
                .sum()
        })
        .unwrap_or(0);

    let proof_nodes = items[2]
        .clone()
        .into_list()
        .map(|list| list.len())
        .unwrap_or(0);

    SnapMessage::StorageRanges {
        request_id,
        slots,
        proof_nodes,
    }
}

fn decode_get_bytecodes(data: &[u8]) -> SnapMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => {
            return SnapMessage::Unknown {
                msg_id: GET_BYTECODES,
            };
        }
    };

    // [request_id, hashes, response_bytes]
    if items.len() < 2 {
        return SnapMessage::Unknown {
            msg_id: GET_BYTECODES,
        };
    }

    let request_id = items[0]
        .clone()
        .into_bytes()
        .map(|b| decode_u64(&b))
        .unwrap_or(0);

    let hashes = items[1]
        .clone()
        .into_list()
        .map(|list| list.len())
        .unwrap_or(0);

    SnapMessage::GetBytecodes { request_id, hashes }
}

fn decode_bytecodes(data: &[u8]) -> SnapMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => return SnapMessage::Unknown { msg_id: BYTECODES },
    };

    // [request_id, codes]
    if items.len() < 2 {
        return SnapMessage::Unknown { msg_id: BYTECODES };
    }

    let request_id = items[0]
        .clone()
        .into_bytes()
        .map(|b| decode_u64(&b))
        .unwrap_or(0);

    let codes = items[1]
        .clone()
        .into_list()
        .map(|list| list.len())
        .unwrap_or(0);

    SnapMessage::Bytecodes { request_id, codes }
}

fn decode_get_trie_nodes(data: &[u8]) -> SnapMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => {
            return SnapMessage::Unknown {
                msg_id: GET_TRIE_NODES,
            };
        }
    };

    // [request_id, root_hash, paths, response_bytes]
    if items.len() < 3 {
        return SnapMessage::Unknown {
            msg_id: GET_TRIE_NODES,
        };
    }

    let request_id = items[0]
        .clone()
        .into_bytes()
        .map(|b| decode_u64(&b))
        .unwrap_or(0);

    let root_hash = items[1]
        .clone()
        .into_bytes()
        .map(|b| format!("0x{}", hex::encode(&b)))
        .unwrap_or_default();

    let paths = items[2]
        .clone()
        .into_list()
        .map(|list| list.len())
        .unwrap_or(0);

    SnapMessage::GetTrieNodes {
        request_id,
        root_hash,
        paths,
    }
}

fn decode_trie_nodes(data: &[u8]) -> SnapMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => return SnapMessage::Unknown { msg_id: TRIE_NODES },
    };

    // [request_id, nodes]
    if items.len() < 2 {
        return SnapMessage::Unknown { msg_id: TRIE_NODES };
    }

    let request_id = items[0]
        .clone()
        .into_bytes()
        .map(|b| decode_u64(&b))
        .unwrap_or(0);

    let nodes = items[1]
        .clone()
        .into_list()
        .map(|list| list.len())
        .unwrap_or(0);

    SnapMessage::TrieNodes { request_id, nodes }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_msg_id_returns_unknown() {
        let result = decode(0xFF, &[]);
        match result {
            SnapMessage::Unknown { msg_id } => assert_eq!(msg_id, 0xFF),
            _ => panic!("expected Unknown"),
        }
    }

    #[test]
    fn malformed_get_account_range_returns_unknown() {
        let result = decode(GET_ACCOUNT_RANGE, &[0x00]);
        match result {
            SnapMessage::Unknown { msg_id } => assert_eq!(msg_id, GET_ACCOUNT_RANGE),
            _ => panic!("expected Unknown for malformed message"),
        }
    }
}
