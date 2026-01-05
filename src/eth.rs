use crate::bytes::{decode_u32, decode_u64, encode_u32, encode_u64};
use crate::error::Error;
use crate::p2p;
use crate::rlp;
use crate::session::Session;

pub const STATUS_MSG_ID: u8 = 0x00;
pub const ETH_MSG_OFFSET: u8 = 0x10;

pub async fn send_status(session: &mut Session, status: &EthStatus) -> Result<(), Error> {
    let msg_id: u8 = ETH_MSG_OFFSET + STATUS_MSG_ID;
    let payload: Vec<u8> = status.to_rlp();
    let compressed: Vec<u8> = snap::raw::Encoder::new()
        .compress_vec(&payload)
        .map_err(|e| Error::Eth(format!("snappy compress failed: {}", e)))?;
    session.write_message(msg_id, &compressed).await
}

pub async fn receive_status(session: &mut Session) -> Result<EthStatus, Error> {
    let expected_id: u8 = ETH_MSG_OFFSET + STATUS_MSG_ID;

    let (msg_id, payload) = session.read_message().await?;

    if msg_id == p2p::DISCONNECT_MSG_ID {
        let decompressed: Vec<u8> = snap::raw::Decoder::new()
            .decompress_vec(&payload)
            .unwrap_or_else(|_| payload.clone());
        let reason = p2p::DisconnectReason::from_rlp(&decompressed);
        return Err(Error::Disconnected(reason.description()));
    }

    if msg_id != expected_id {
        return Err(Error::Eth(format!(
            "expected Status ({}), got msg_id {}",
            expected_id, msg_id
        )));
    }

    let decompressed: Vec<u8> = snap::raw::Decoder::new()
        .decompress_vec(&payload)
        .map_err(|e| Error::Eth(format!("snappy decompress failed: {}", e)))?;

    EthStatus::from_rlp(&decompressed)
}

pub struct ForkId {
    pub fork_hash: [u8; 4],
    pub fork_next: u64,
}

pub struct EthStatus {
    pub protocol_version: u32,
    pub network_id: u64,
    pub total_difficulty: Vec<u8>,
    pub best_hash: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub fork_id: ForkId,
}

impl ForkId {
    pub fn from_rlp(item: &rlp::RlpItem) -> Result<ForkId, Error> {
        let items: Vec<rlp::RlpItem> = item.clone().into_list()?;

        if items.len() < 2 {
            return Err(Error::Eth("forkId missing fields".to_string()));
        }

        let hash_bytes: Vec<u8> = items[0].clone().into_bytes()?;
        if hash_bytes.len() != 4 {
            return Err(Error::Eth("forkHash must be 4 bytes".to_string()));
        }

        let mut fork_hash: [u8; 4] = [0u8; 4];
        fork_hash.copy_from_slice(&hash_bytes);

        let next_bytes: Vec<u8> = items[1].clone().into_bytes()?;
        let fork_next: u64 = decode_u64(&next_bytes);

        Ok(ForkId {
            fork_hash,
            fork_next,
        })
    }

    pub fn to_rlp(&self) -> Vec<u8> {
        let next_bytes: Vec<u8> = encode_u64(self.fork_next);

        let mut payload: Vec<u8> = Vec::new();
        payload.extend(rlp::encode_bytes(&self.fork_hash));
        payload.extend(rlp::encode_bytes(&next_bytes));

        rlp::encode_list_payload(&payload)
    }
}

impl EthStatus {
    pub fn from_rlp(data: &[u8]) -> Result<EthStatus, Error> {
        let items: Vec<rlp::RlpItem> = rlp::decode(data)?.into_list()?;

        if items.len() < 6 {
            return Err(Error::Eth("status missing fields".to_string()));
        }

        let version_bytes: Vec<u8> = items[0].clone().into_bytes()?;
        let protocol_version: u32 = decode_u32(&version_bytes);

        let network_bytes: Vec<u8> = items[1].clone().into_bytes()?;
        let network_id: u64 = decode_u64(&network_bytes);

        let total_difficulty: Vec<u8> = items[2].clone().into_bytes()?;

        let best_bytes: Vec<u8> = items[3].clone().into_bytes()?;
        if best_bytes.len() != 32 {
            return Err(Error::Eth("bestHash must be 32 bytes".to_string()));
        }
        let mut best_hash: [u8; 32] = [0u8; 32];
        best_hash.copy_from_slice(&best_bytes);

        let genesis_bytes: Vec<u8> = items[4].clone().into_bytes()?;
        if genesis_bytes.len() != 32 {
            return Err(Error::Eth("genesisHash must be 32 bytes".to_string()));
        }
        let mut genesis_hash: [u8; 32] = [0u8; 32];
        genesis_hash.copy_from_slice(&genesis_bytes);

        let fork_id: ForkId = ForkId::from_rlp(&items[5])?;

        Ok(EthStatus {
            protocol_version,
            network_id,
            total_difficulty,
            best_hash,
            genesis_hash,
            fork_id,
        })
    }

    pub fn to_rlp(&self) -> Vec<u8> {
        let version_bytes: Vec<u8> = encode_u32(self.protocol_version);
        let network_bytes: Vec<u8> = encode_u64(self.network_id);

        let mut payload: Vec<u8> = Vec::new();
        payload.extend(rlp::encode_bytes(&version_bytes));
        payload.extend(rlp::encode_bytes(&network_bytes));
        payload.extend(rlp::encode_bytes(&self.total_difficulty));
        payload.extend(rlp::encode_bytes(&self.best_hash));
        payload.extend(rlp::encode_bytes(&self.genesis_hash));
        payload.extend(self.fork_id.to_rlp());

        rlp::encode_list_payload(&payload)
    }
}
