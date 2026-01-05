use crate::bytes::{decode_u32, decode_u64};
use crate::rlp::{self, RlpItem};
use serde::Serialize;
use sha3::{Digest, Keccak256};

/// ETH protocol message IDs (after adding ETH_MSG_OFFSET = 0x10).
pub const STATUS: u8 = 0x10;
pub const NEW_BLOCK_HASHES: u8 = 0x11;
pub const TRANSACTIONS: u8 = 0x12;
pub const GET_BLOCK_HEADERS: u8 = 0x13;
pub const BLOCK_HEADERS: u8 = 0x14;
pub const GET_BLOCK_BODIES: u8 = 0x15;
pub const BLOCK_BODIES: u8 = 0x16;
pub const NEW_BLOCK: u8 = 0x17;
pub const NEW_POOLED_TX_HASHES: u8 = 0x18;
pub const GET_POOLED_TRANSACTIONS: u8 = 0x19;
pub const POOLED_TRANSACTIONS: u8 = 0x1a;
pub const GET_RECEIPTS: u8 = 0x1f;
pub const RECEIPTS: u8 = 0x20;

/// Function type for ETH message decoding.
pub type EthDecodeFn = fn(u8, &[u8]) -> EthMessage;

/// Returns the appropriate decoder for the negotiated eth version.
/// eth/66+ (EIP-2481) wraps request/response messages with request_id.
pub fn get_decoder(eth_version: u8) -> EthDecodeFn {
    if eth_version >= 66 {
        decode_eth66
    } else {
        decode_eth65
    }
}

/// Decoded ETH message with relevant fields for display.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "msg_type", rename_all = "snake_case")]
pub enum EthMessage {
    Status {
        protocol_version: u32,
        network_id: u64,
        genesis_hash: String,
        best_hash: String,
    },
    NewBlockHashes {
        entries: Vec<BlockHashEntry>,
    },
    Transactions {
        hashes: Vec<String>,
    },
    GetBlockHeaders {
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<u64>,
        #[serde(flatten)]
        request: BlockHeadersRequest,
    },
    BlockHeaders {
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<u64>,
        headers: Vec<HeaderInfo>,
    },
    GetBlockBodies {
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<u64>,
        count: usize,
    },
    BlockBodies {
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<u64>,
        bodies: Vec<BodyInfo>,
    },
    NewBlock {
        block_number: Option<u64>,
        block_hash: Option<String>,
    },
    NewPooledTransactionHashes {
        hashes: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        types: Option<Vec<u8>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        sizes: Option<Vec<u32>>,
    },
    GetPooledTransactions {
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<u64>,
        count: usize,
    },
    PooledTransactions {
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<u64>,
        hashes: Vec<String>,
    },
    GetReceipts {
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<u64>,
        count: usize,
    },
    Receipts {
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<u64>,
        receipts: Vec<ReceiptInfo>,
    },
    Unknown {
        msg_id: u8,
    },
}

/// Request parameters for GetBlockHeaders.
#[derive(Debug, Clone, Serialize)]
pub struct BlockHeadersRequest {
    pub start_block: String,
    pub limit: u64,
    pub skip: u64,
    pub reverse: bool,
}

/// Block header info (hash and number).
#[derive(Debug, Clone, Serialize)]
pub struct HeaderInfo {
    pub hash: String,
    pub number: u64,
}

/// Block body info (transaction and uncle hashes).
#[derive(Debug, Clone, Serialize)]
pub struct BodyInfo {
    pub tx_hashes: Vec<String>,
    pub uncle_hashes: Vec<String>,
}

/// Block hash entry (hash and number).
#[derive(Debug, Clone, Serialize)]
pub struct BlockHashEntry {
    pub hash: String,
    pub number: u64,
}

/// Receipt info.
#[derive(Debug, Clone, Serialize)]
pub struct ReceiptInfo {
    pub status: Option<bool>,
    pub cumulative_gas_used: u64,
    pub log_count: usize,
}

/// Decoder for eth/65 and earlier (no request_id wrapper).
pub fn decode_eth65(msg_id: u8, payload: &[u8]) -> EthMessage {
    let data = decompress_payload(payload);
    match msg_id {
        STATUS => decode_status(&data),
        NEW_BLOCK_HASHES => decode_new_block_hashes(&data),
        TRANSACTIONS => decode_transactions(&data),
        GET_BLOCK_HEADERS => decode_get_block_headers_eth65(&data),
        BLOCK_HEADERS => decode_block_headers(&data),
        GET_BLOCK_BODIES => EthMessage::GetBlockBodies {
            request_id: None,
            count: count_list_items(&data),
        },
        BLOCK_BODIES => decode_block_bodies(&data),
        NEW_BLOCK => decode_new_block(&data),
        NEW_POOLED_TX_HASHES => decode_new_pooled_tx_hashes(&data),
        GET_POOLED_TRANSACTIONS => EthMessage::GetPooledTransactions {
            request_id: None,
            count: count_list_items(&data),
        },
        POOLED_TRANSACTIONS => decode_pooled_transactions(&data),
        GET_RECEIPTS => EthMessage::GetReceipts {
            request_id: None,
            count: count_list_items(&data),
        },
        RECEIPTS => decode_receipts(&data),
        _ => EthMessage::Unknown { msg_id },
    }
}

/// Decoder for eth/66+ (EIP-2481 with request_id wrapper).
pub fn decode_eth66(msg_id: u8, payload: &[u8]) -> EthMessage {
    let data = decompress_payload(payload);
    match msg_id {
        // Broadcast messages: same format in all versions
        STATUS => decode_status(&data),
        NEW_BLOCK_HASHES => decode_new_block_hashes(&data),
        TRANSACTIONS => decode_transactions(&data),
        NEW_BLOCK => decode_new_block(&data),
        NEW_POOLED_TX_HASHES => decode_new_pooled_tx_hashes(&data),
        // Request/response messages: wrapped with request_id
        GET_BLOCK_HEADERS => decode_get_block_headers_eth66(&data),
        BLOCK_HEADERS => decode_block_headers_eth66(&data),
        GET_BLOCK_BODIES => {
            let (request_id, count) = count_list_items_eth66(&data);
            EthMessage::GetBlockBodies { request_id, count }
        }
        BLOCK_BODIES => decode_block_bodies_eth66(&data),
        GET_POOLED_TRANSACTIONS => {
            let (request_id, count) = count_list_items_eth66(&data);
            EthMessage::GetPooledTransactions { request_id, count }
        }
        POOLED_TRANSACTIONS => decode_pooled_transactions_eth66(&data),
        GET_RECEIPTS => {
            let (request_id, count) = count_list_items_eth66(&data);
            EthMessage::GetReceipts { request_id, count }
        }
        RECEIPTS => decode_receipts_eth66(&data),
        _ => EthMessage::Unknown { msg_id },
    }
}

/// Decompress Snappy payload, returning original if decompression fails.
fn decompress_payload(payload: &[u8]) -> Vec<u8> {
    snap::raw::Decoder::new()
        .decompress_vec(payload)
        .unwrap_or_else(|_| payload.to_vec())
}

/// Compute keccak256 hash of data and return as hex string.
fn keccak256_hex(data: &[u8]) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    format!("0x{}", hex::encode(hasher.finalize()))
}

/// Unwrap eth/66+ request format: [request_id, [payload...]] -> inner list.
/// Returns None if format is invalid.
fn unwrap_eth66_request(items: &[RlpItem]) -> Option<(u64, Vec<RlpItem>)> {
    if items.len() != 2 {
        return None;
    }
    let request_id = items[0].clone().into_bytes().ok().map(|b| decode_u64(&b))?;
    let inner = items[1].clone().into_list().ok()?;
    Some((request_id, inner))
}

/// Count items in eth/66+ wrapped format. Returns (request_id, count).
fn count_list_items_eth66(data: &[u8]) -> (Option<u64>, usize) {
    rlp::decode(data)
        .and_then(|item| item.into_list())
        .ok()
        .and_then(|items| unwrap_eth66_request(&items))
        .map(|(request_id, inner)| (Some(request_id), inner.len()))
        .unwrap_or((None, 0))
}

fn decode_status(data: &[u8]) -> EthMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => return EthMessage::Unknown { msg_id: STATUS },
    };

    if items.len() < 5 {
        return EthMessage::Unknown { msg_id: STATUS };
    }

    // Protocol version and network_id are essential - fail if missing
    let protocol_version = match items[0].clone().into_bytes() {
        Ok(b) => decode_u32(&b),
        Err(_) => return EthMessage::Unknown { msg_id: STATUS },
    };

    let network_id = match items[1].clone().into_bytes() {
        Ok(b) => decode_u64(&b),
        Err(_) => return EthMessage::Unknown { msg_id: STATUS },
    };

    // Hashes can default to empty - shows partial parse
    let best_hash = items[3]
        .clone()
        .into_bytes()
        .map(|b| format!("0x{}", hex::encode(&b)))
        .unwrap_or_default();

    let genesis_hash = items[4]
        .clone()
        .into_bytes()
        .map(|b| format!("0x{}", hex::encode(&b)))
        .unwrap_or_default();

    EthMessage::Status {
        protocol_version,
        network_id,
        genesis_hash,
        best_hash,
    }
}

fn decode_new_block_hashes(data: &[u8]) -> EthMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => return EthMessage::NewBlockHashes { entries: vec![] },
    };

    let entries: Vec<BlockHashEntry> = items
        .iter()
        .filter_map(|item| {
            let entry = item.clone().into_list().ok()?;
            if entry.len() < 2 {
                return None;
            }
            let hash = entry[0]
                .clone()
                .into_bytes()
                .ok()
                .map(|b| format!("0x{}", hex::encode(&b)))?;
            let number = entry[1].clone().into_bytes().ok().map(|b| decode_u64(&b))?;
            Some(BlockHashEntry { hash, number })
        })
        .collect();

    EthMessage::NewBlockHashes { entries }
}

fn decode_transactions(data: &[u8]) -> EthMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => return EthMessage::Transactions { hashes: vec![] },
    };

    let hashes: Vec<String> = items.iter().map(compute_tx_hash).collect();

    EthMessage::Transactions { hashes }
}

/// Compute transaction hash from RlpItem.
/// Legacy transactions (RlpItem::List) are encoded to RLP bytes.
/// Typed transactions (RlpItem::Bytes) already contain the type prefix.
fn compute_tx_hash(item: &RlpItem) -> String {
    let bytes = match item {
        RlpItem::Bytes(b) => b.clone(),
        RlpItem::List(_) => item.encode(),
    };
    keccak256_hex(&bytes)
}

/// GetBlockHeaders eth/65: [startblock, limit, skip, reverse]
fn decode_get_block_headers_eth65(data: &[u8]) -> EthMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => {
            return EthMessage::Unknown {
                msg_id: GET_BLOCK_HEADERS,
            };
        }
    };
    match parse_block_headers_request(&items) {
        Some(request) => EthMessage::GetBlockHeaders {
            request_id: None,
            request,
        },
        None => EthMessage::Unknown {
            msg_id: GET_BLOCK_HEADERS,
        },
    }
}

/// GetBlockHeaders eth/66+: [request_id, [startblock, limit, skip, reverse]]
fn decode_get_block_headers_eth66(data: &[u8]) -> EthMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => {
            return EthMessage::Unknown {
                msg_id: GET_BLOCK_HEADERS,
            };
        }
    };
    let (request_id, inner) = match unwrap_eth66_request(&items) {
        Some(tuple) => tuple,
        None => {
            return EthMessage::Unknown {
                msg_id: GET_BLOCK_HEADERS,
            };
        }
    };
    match parse_block_headers_request(&inner) {
        Some(request) => EthMessage::GetBlockHeaders {
            request_id: Some(request_id),
            request,
        },
        None => EthMessage::Unknown {
            msg_id: GET_BLOCK_HEADERS,
        },
    }
}

/// Parse GetBlockHeaders parameters into BlockHeadersRequest.
fn parse_block_headers_request(items: &[RlpItem]) -> Option<BlockHeadersRequest> {
    if items.len() < 4 {
        return None;
    }

    let start_block = match &items[0] {
        RlpItem::Bytes(b) if b.len() == 32 => format!("0x{}", hex::encode(b)),
        RlpItem::Bytes(b) => decode_u64(b).to_string(),
        _ => return None,
    };

    let limit = items[1].clone().into_bytes().ok().map(|b| decode_u64(&b))?;
    let skip = items[2].clone().into_bytes().ok().map(|b| decode_u64(&b))?;
    let reverse = items[3]
        .clone()
        .into_bytes()
        .ok()
        .map(|b| !b.is_empty() && b[0] != 0)?;

    Some(BlockHeadersRequest {
        start_block,
        limit,
        skip,
        reverse,
    })
}

fn decode_new_block(data: &[u8]) -> EthMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => {
            return EthMessage::NewBlock {
                block_number: None,
                block_hash: None,
            };
        }
    };

    if items.is_empty() {
        return EthMessage::NewBlock {
            block_number: None,
            block_hash: None,
        };
    }

    // First item is the block, which is a list [header, txs, uncles]
    let block_items = match items[0].clone().into_list() {
        Ok(list) => list,
        Err(_) => {
            return EthMessage::NewBlock {
                block_number: None,
                block_hash: None,
            };
        }
    };

    if block_items.is_empty() {
        return EthMessage::NewBlock {
            block_number: None,
            block_hash: None,
        };
    }

    // Header is the first item, which is a list
    let header = &block_items[0];
    let header_items = match header.clone().into_list() {
        Ok(list) => list,
        Err(_) => {
            return EthMessage::NewBlock {
                block_number: None,
                block_hash: None,
            };
        }
    };

    // Block hash is keccak256 of RLP-encoded header
    let block_hash = Some(keccak256_hex(&header.encode()));

    // Block number is at index 8
    let block_number = if header_items.len() > 8 {
        header_items[8]
            .clone()
            .into_bytes()
            .map(|b| decode_u64(&b))
            .ok()
    } else {
        None
    };

    EthMessage::NewBlock {
        block_number,
        block_hash,
    }
}

fn decode_new_pooled_tx_hashes(data: &[u8]) -> EthMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => {
            return EthMessage::NewPooledTransactionHashes {
                hashes: vec![],
                types: None,
                sizes: None,
            };
        }
    };

    if items.is_empty() {
        return EthMessage::NewPooledTransactionHashes {
            hashes: vec![],
            types: None,
            sizes: None,
        };
    }

    // Check if this is eth/68 format: [[types], [sizes], [hashes]]
    // In eth/66-67, it's just [hash1, hash2, ...]
    // We detect eth/68 by checking if first item is a list of single-byte values
    if let Ok(first_list) = items[0].clone().into_list() {
        // eth/68 format
        if items.len() >= 3 {
            let types: Vec<u8> = first_list
                .iter()
                .filter_map(|item| {
                    item.clone()
                        .into_bytes()
                        .ok()
                        .and_then(|b| b.first().copied())
                })
                .collect();

            let sizes: Vec<u32> = items[1]
                .clone()
                .into_list()
                .unwrap_or_default()
                .iter()
                .filter_map(|item| item.clone().into_bytes().ok().map(|b| decode_u32(&b)))
                .collect();

            let hashes: Vec<String> = items[2]
                .clone()
                .into_list()
                .unwrap_or_default()
                .iter()
                .filter_map(|item| {
                    item.clone()
                        .into_bytes()
                        .ok()
                        .map(|b| format!("0x{}", hex::encode(&b)))
                })
                .collect();

            return EthMessage::NewPooledTransactionHashes {
                hashes,
                types: Some(types),
                sizes: Some(sizes),
            };
        }
    }

    // eth/66-67 format: just a list of hashes
    let hashes: Vec<String> = items
        .iter()
        .filter_map(|item| {
            item.clone()
                .into_bytes()
                .ok()
                .map(|b| format!("0x{}", hex::encode(&b)))
        })
        .collect();

    EthMessage::NewPooledTransactionHashes {
        hashes,
        types: None,
        sizes: None,
    }
}

fn count_list_items(data: &[u8]) -> usize {
    rlp::decode(data)
        .and_then(|item| item.into_list())
        .map(|list| list.len())
        .unwrap_or(0)
}

/// Decode block headers (eth/65 format).
fn decode_block_headers(data: &[u8]) -> EthMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => {
            return EthMessage::BlockHeaders {
                request_id: None,
                headers: vec![],
            };
        }
    };

    let headers = decode_header_list(&items);
    EthMessage::BlockHeaders {
        request_id: None,
        headers,
    }
}

/// Decode block headers (eth/66+ format with request_id wrapper).
fn decode_block_headers_eth66(data: &[u8]) -> EthMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => {
            return EthMessage::BlockHeaders {
                request_id: None,
                headers: vec![],
            };
        }
    };

    let (request_id, inner) = match unwrap_eth66_request(&items) {
        Some(tuple) => tuple,
        None => {
            return EthMessage::BlockHeaders {
                request_id: None,
                headers: vec![],
            };
        }
    };

    let headers = decode_header_list(&inner);
    EthMessage::BlockHeaders {
        request_id: Some(request_id),
        headers,
    }
}

/// Decode a list of headers into HeaderInfo structs.
fn decode_header_list(items: &[RlpItem]) -> Vec<HeaderInfo> {
    items
        .iter()
        .filter_map(|item| {
            let header_items = item.clone().into_list().ok()?;
            if header_items.len() <= 8 {
                return None;
            }
            // Block hash is keccak256 of RLP-encoded header
            let hash = keccak256_hex(&item.encode());
            // Block number is at index 8
            let number = header_items[8]
                .clone()
                .into_bytes()
                .ok()
                .map(|b| decode_u64(&b))?;
            Some(HeaderInfo { hash, number })
        })
        .collect()
}

/// Decode block bodies (eth/65 format).
fn decode_block_bodies(data: &[u8]) -> EthMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => {
            return EthMessage::BlockBodies {
                request_id: None,
                bodies: vec![],
            };
        }
    };

    let bodies = decode_body_list(&items);
    EthMessage::BlockBodies {
        request_id: None,
        bodies,
    }
}

/// Decode block bodies (eth/66+ format with request_id wrapper).
fn decode_block_bodies_eth66(data: &[u8]) -> EthMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => {
            return EthMessage::BlockBodies {
                request_id: None,
                bodies: vec![],
            };
        }
    };

    let (request_id, inner) = match unwrap_eth66_request(&items) {
        Some(tuple) => tuple,
        None => {
            return EthMessage::BlockBodies {
                request_id: None,
                bodies: vec![],
            };
        }
    };

    let bodies = decode_body_list(&inner);
    EthMessage::BlockBodies {
        request_id: Some(request_id),
        bodies,
    }
}

/// Decode a list of bodies into BodyInfo structs.
fn decode_body_list(items: &[RlpItem]) -> Vec<BodyInfo> {
    items
        .iter()
        .filter_map(|item| {
            let body_items = item.clone().into_list().ok()?;
            if body_items.len() < 2 {
                return None;
            }

            // First item is transactions list
            let tx_hashes: Vec<String> = body_items[0]
                .clone()
                .into_list()
                .unwrap_or_default()
                .iter()
                .map(compute_tx_hash)
                .collect();

            // Second item is uncles (list of headers)
            let uncle_hashes: Vec<String> = body_items[1]
                .clone()
                .into_list()
                .unwrap_or_default()
                .iter()
                .map(|uncle| keccak256_hex(&uncle.encode()))
                .collect();

            Some(BodyInfo {
                tx_hashes,
                uncle_hashes,
            })
        })
        .collect()
}

/// Decode pooled transactions (eth/65 format).
fn decode_pooled_transactions(data: &[u8]) -> EthMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => {
            return EthMessage::PooledTransactions {
                request_id: None,
                hashes: vec![],
            };
        }
    };

    let hashes: Vec<String> = items.iter().map(compute_tx_hash).collect();
    EthMessage::PooledTransactions {
        request_id: None,
        hashes,
    }
}

/// Decode pooled transactions (eth/66+ format with request_id wrapper).
fn decode_pooled_transactions_eth66(data: &[u8]) -> EthMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => {
            return EthMessage::PooledTransactions {
                request_id: None,
                hashes: vec![],
            };
        }
    };

    let (request_id, inner) = match unwrap_eth66_request(&items) {
        Some(tuple) => tuple,
        None => {
            return EthMessage::PooledTransactions {
                request_id: None,
                hashes: vec![],
            };
        }
    };

    let hashes: Vec<String> = inner.iter().map(compute_tx_hash).collect();
    EthMessage::PooledTransactions {
        request_id: Some(request_id),
        hashes,
    }
}

/// Decode receipts (eth/65 format).
fn decode_receipts(data: &[u8]) -> EthMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => {
            return EthMessage::Receipts {
                request_id: None,
                receipts: vec![],
            };
        }
    };

    let receipts = decode_receipt_list(&items);
    EthMessage::Receipts {
        request_id: None,
        receipts,
    }
}

/// Decode receipts (eth/66+ format with request_id wrapper).
fn decode_receipts_eth66(data: &[u8]) -> EthMessage {
    let items = match rlp::decode(data).and_then(|item| item.into_list()) {
        Ok(list) => list,
        Err(_) => {
            return EthMessage::Receipts {
                request_id: None,
                receipts: vec![],
            };
        }
    };

    let (request_id, inner) = match unwrap_eth66_request(&items) {
        Some(tuple) => tuple,
        None => {
            return EthMessage::Receipts {
                request_id: None,
                receipts: vec![],
            };
        }
    };

    let receipts = decode_receipt_list(&inner);
    EthMessage::Receipts {
        request_id: Some(request_id),
        receipts,
    }
}

/// Decode a list of receipts into ReceiptInfo structs.
/// Receipts response contains receipts grouped by block, flattened here.
fn decode_receipt_list(items: &[RlpItem]) -> Vec<ReceiptInfo> {
    let mut receipts = Vec::new();

    for item in items {
        // Each item is a list of receipts for a block
        if let Ok(block_receipts) = item.clone().into_list() {
            for receipt_item in block_receipts {
                if let Some(receipt) = decode_single_receipt(&receipt_item) {
                    receipts.push(receipt);
                }
            }
        }
    }

    receipts
}

/// Decode a single receipt.
fn decode_single_receipt(item: &RlpItem) -> Option<ReceiptInfo> {
    // Receipt can be legacy (RlpItem::List) or typed (RlpItem::Bytes with type prefix)
    let receipt_items = match item {
        RlpItem::List(items) => items.clone(),
        RlpItem::Bytes(bytes) => {
            // Typed receipt: skip type byte and decode the rest
            if bytes.is_empty() {
                return None;
            }
            let receipt_rlp = &bytes[1..];
            rlp::decode(receipt_rlp)
                .and_then(|item| item.into_list())
                .ok()?
        }
    };

    // Receipt format: [status/postState, cumulativeGasUsed, logsBloom, logs]
    if receipt_items.len() < 4 {
        return None;
    }

    // Status (post-Byzantium) or post-state root (pre-Byzantium)
    let status = receipt_items[0].clone().into_bytes().ok().and_then(|b| {
        if b.len() == 1 {
            Some(b[0] == 1)
        } else {
            None // pre-Byzantium, status not available
        }
    });

    // cumulative_gas_used is essential - skip receipt if missing
    let cumulative_gas_used = match receipt_items[1].clone().into_bytes() {
        Ok(b) => decode_u64(&b),
        Err(_) => return None,
    };

    // logs is at index 3 - skip receipt if logs can't be parsed
    let log_count = match receipt_items[3].clone().into_list() {
        Ok(logs) => logs.len(),
        Err(_) => return None,
    };

    Some(ReceiptInfo {
        status,
        cumulative_gas_used,
        log_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_msg_id_returns_unknown() {
        let result = decode_eth66(0xFF, &[]);
        match result {
            EthMessage::Unknown { msg_id } => assert_eq!(msg_id, 0xFF),
            _ => panic!("expected Unknown"),
        }
    }

    #[test]
    fn malformed_status_returns_unknown() {
        let result = decode_eth66(STATUS, &[0x00]);
        match result {
            EthMessage::Unknown { msg_id } => assert_eq!(msg_id, STATUS),
            _ => panic!("expected Unknown for malformed status"),
        }
    }

    #[test]
    fn empty_list_returns_empty_hashes() {
        // RLP for empty list: 0xC0
        let empty_list = vec![0xC0];
        let result = decode_eth66(TRANSACTIONS, &empty_list);
        match result {
            EthMessage::Transactions { hashes } => assert!(hashes.is_empty()),
            _ => panic!("expected Transactions"),
        }
    }

    #[test]
    fn decode_eth66_get_block_headers_by_number() {
        // eth/66 format: [request_id=1, [block=100, limit=10, skip=0, reverse=0]]
        // RLP encoding:
        // - request_id=1: 0x01
        // - inner list [100, 10, 0, 0]: c4 64 0a 80 80
        // - outer list: c6 (0xc0 + 6 bytes) 01 c4 64 0a 80 80
        let payload = vec![0xc6, 0x01, 0xc4, 0x64, 0x0a, 0x80, 0x80];
        let result = decode_eth66(GET_BLOCK_HEADERS, &payload);
        match result {
            EthMessage::GetBlockHeaders {
                request_id,
                request,
            } => {
                assert_eq!(request_id, Some(1)); // request_id = 1
                assert_eq!(request.start_block, "100");
                assert_eq!(request.limit, 10);
                assert_eq!(request.skip, 0);
                assert!(!request.reverse);
            }
            other => panic!("expected GetBlockHeaders, got {:?}", other),
        }
    }

    #[test]
    fn decode_eth65_get_block_headers_by_number() {
        // eth/65 format: [block=100, limit=10, skip=0, reverse=0]
        // RLP encoding:
        // - 100: 0x64
        // - 10: 0x0a
        // - 0 (skip): 0x80 (empty string)
        // - 0 (reverse): 0x80 (empty string)
        // - list: c4 (0xc0 + 4 bytes) 64 0a 80 80
        let payload = vec![0xc4, 0x64, 0x0a, 0x80, 0x80];
        let result = decode_eth65(GET_BLOCK_HEADERS, &payload);
        match result {
            EthMessage::GetBlockHeaders {
                request_id,
                request,
            } => {
                assert_eq!(request_id, None); // eth/65 has no request_id
                assert_eq!(request.start_block, "100");
                assert_eq!(request.limit, 10);
            }
            other => panic!("expected GetBlockHeaders, got {:?}", other),
        }
    }

    #[test]
    fn get_decoder_returns_correct_version() {
        let dec65 = get_decoder(65);
        let dec66 = get_decoder(66);
        let dec67 = get_decoder(67);
        let dec68 = get_decoder(68);

        // eth/65 payload: [100, 10, 0, 0]
        let eth65_payload = vec![0xc4, 0x64, 0x0a, 0x80, 0x80];
        // eth/66 payload: [1, [100, 10, 0, 0]]
        let eth66_payload = vec![0xc6, 0x01, 0xc4, 0x64, 0x0a, 0x80, 0x80];

        // dec65 should decode eth65 format correctly
        assert!(matches!(
            dec65(GET_BLOCK_HEADERS, &eth65_payload),
            EthMessage::GetBlockHeaders { .. }
        ));
        // dec65 should fail on eth66 format
        assert!(matches!(
            dec65(GET_BLOCK_HEADERS, &eth66_payload),
            EthMessage::Unknown { .. }
        ));

        // dec66+ should decode eth66 format correctly
        assert!(matches!(
            dec66(GET_BLOCK_HEADERS, &eth66_payload),
            EthMessage::GetBlockHeaders { .. }
        ));
        assert!(matches!(
            dec67(GET_BLOCK_HEADERS, &eth66_payload),
            EthMessage::GetBlockHeaders { .. }
        ));
        assert!(matches!(
            dec68(GET_BLOCK_HEADERS, &eth66_payload),
            EthMessage::GetBlockHeaders { .. }
        ));
    }

    #[test]
    fn decode_eth66_block_headers_filters_invalid() {
        // eth/66 format: [request_id=1, [item1, item2]]
        // RLP: c4 01 c2 80 80  (request_id=1, list with 2 empty byte strings)
        // Empty byte strings are not valid headers (need 9+ fields), so filtered out
        let payload = vec![0xc4, 0x01, 0xc2, 0x80, 0x80];
        let result = decode_eth66(BLOCK_HEADERS, &payload);
        match result {
            EthMessage::BlockHeaders { headers, .. } => assert!(headers.is_empty()),
            other => panic!("expected BlockHeaders, got {:?}", other),
        }
    }

    #[test]
    fn decode_eth65_block_headers_filters_invalid() {
        // eth/65 format: [item1, item2]
        // RLP: c2 80 80 (list with 2 empty byte strings)
        // Empty byte strings are not valid headers (need 9+ fields), so filtered out
        let payload = vec![0xc2, 0x80, 0x80];
        let result = decode_eth65(BLOCK_HEADERS, &payload);
        match result {
            EthMessage::BlockHeaders { headers, .. } => assert!(headers.is_empty()),
            other => panic!("expected BlockHeaders, got {:?}", other),
        }
    }
}
