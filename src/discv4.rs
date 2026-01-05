use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha3::{Digest, Keccak256};
use tokio::net::UdpSocket;

use crate::bytes::{decode_u16, decode_u64, encode_u16, encode_u64};
use crate::constants::{
    DISCV4_EXPIRATION_SECS, DISCV4_MAX_PACKET_SIZE, HASH_SIZE, NODE_ID_LEN, SIGNATURE_SIZE,
};
use crate::error::Error;
use crate::rlp::{self, RlpItem};

pub const PING: u8 = 0x01;
pub const PONG: u8 = 0x02;
pub const FIND_NODE: u8 = 0x03;
pub const NEIGHBORS: u8 = 0x04;
pub const ENR_REQUEST: u8 = 0x05;
pub const ENR_RESPONSE: u8 = 0x06;

/// Packet header size: 32 (hash) + 65 (signature) + 1 (type)
const PACKET_HEADER_SIZE: usize = HASH_SIZE + SIGNATURE_SIZE + 1;

#[derive(Debug, Clone)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub udp_port: u16,
    pub tcp_port: u16,
}

impl Endpoint {
    pub fn new(ip: IpAddr, udp_port: u16, tcp_port: u16) -> Self {
        Endpoint {
            ip,
            udp_port,
            tcp_port,
        }
    }

    pub fn to_rlp(&self) -> RlpItem {
        let ip_bytes = match self.ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };

        RlpItem::List(vec![
            RlpItem::Bytes(ip_bytes),
            RlpItem::Bytes(encode_u16(self.udp_port)),
            RlpItem::Bytes(encode_u16(self.tcp_port)),
        ])
    }

    pub fn from_rlp(item: RlpItem) -> Result<Self, Error> {
        let items = item.into_list()?;
        if items.len() < 3 {
            return Err(Error::Discovery("endpoint needs 3 items".to_string()));
        }

        let ip_bytes = items[0].clone().into_bytes()?;
        let ip = if ip_bytes.len() == 4 {
            IpAddr::V4(Ipv4Addr::new(
                ip_bytes[0],
                ip_bytes[1],
                ip_bytes[2],
                ip_bytes[3],
            ))
        } else if ip_bytes.len() == 16 {
            let arr: [u8; 16] = ip_bytes
                .try_into()
                .map_err(|_| Error::Discovery("bad ipv6".to_string()))?;
            IpAddr::V6(arr.into())
        } else {
            return Err(Error::Discovery(format!(
                "invalid ip length: {}",
                ip_bytes.len()
            )));
        };

        let udp_port = decode_u16(&items[1].clone().into_bytes()?);
        let tcp_port = decode_u16(&items[2].clone().into_bytes()?);

        Ok(Endpoint {
            ip,
            udp_port,
            tcp_port,
        })
    }
}

/// PING message for node liveness check.
/// Part of complete discv4 protocol. Unused as proxy only responds to discovery.
#[derive(Debug, Clone)]
pub struct PingMessage {
    pub version: u8,
    pub from: Endpoint,
    pub to: Endpoint,
    pub expiration: u64,
    pub enr_seq: Option<u64>,
}

impl PingMessage {
    /// Create new PING. Unused as proxy only responds to discovery.
    #[allow(dead_code)]
    pub fn new(from: Endpoint, to: Endpoint) -> Self {
        let expiration = current_time() + DISCV4_EXPIRATION_SECS;
        PingMessage {
            version: 4,
            from,
            to,
            expiration,
            enr_seq: None,
        }
    }

    /// Encode to RLP. Unused as proxy only responds to discovery.
    #[allow(dead_code)]
    pub fn to_rlp(&self) -> Vec<u8> {
        let mut items = vec![
            RlpItem::Bytes(vec![self.version]),
            self.from.to_rlp(),
            self.to.to_rlp(),
            RlpItem::Bytes(encode_u64(self.expiration)),
        ];

        if let Some(seq) = self.enr_seq {
            items.push(RlpItem::Bytes(encode_u64(seq)));
        }

        RlpItem::List(items).encode()
    }

    /// Decode from RLP. Unused as proxy only responds to discovery.
    #[allow(dead_code)]
    pub fn from_rlp(data: &[u8]) -> Result<Self, Error> {
        let item = rlp::decode(data)?;
        let items = item.into_list()?;

        if items.len() < 4 {
            return Err(Error::Discovery("ping needs at least 4 items".to_string()));
        }

        let version_bytes = items[0].clone().into_bytes()?;
        let version = if version_bytes.is_empty() {
            0
        } else {
            version_bytes[0]
        };

        let from = Endpoint::from_rlp(items[1].clone())?;
        let to = Endpoint::from_rlp(items[2].clone())?;
        let expiration = decode_u64(&items[3].clone().into_bytes()?);

        let enr_seq = if items.len() > 4 {
            Some(decode_u64(&items[4].clone().into_bytes()?))
        } else {
            None
        };

        Ok(PingMessage {
            version,
            from,
            to,
            expiration,
            enr_seq,
        })
    }

    /// Check if this message has expired.
    pub fn is_expired(&self) -> bool {
        current_time() > self.expiration
    }
}

#[derive(Debug, Clone)]
pub struct PongMessage {
    pub to: Endpoint,
    pub ping_hash: [u8; 32],
    pub expiration: u64,
    pub enr_seq: Option<u64>,
}

impl PongMessage {
    pub fn new(to: Endpoint, ping_hash: [u8; 32]) -> Self {
        let expiration = current_time() + DISCV4_EXPIRATION_SECS;
        PongMessage {
            to,
            ping_hash,
            expiration,
            enr_seq: None,
        }
    }

    pub fn to_rlp(&self) -> Vec<u8> {
        let mut items = vec![
            self.to.to_rlp(),
            RlpItem::Bytes(self.ping_hash.to_vec()),
            RlpItem::Bytes(encode_u64(self.expiration)),
        ];

        if let Some(seq) = self.enr_seq {
            items.push(RlpItem::Bytes(encode_u64(seq)));
        }

        RlpItem::List(items).encode()
    }

    pub fn from_rlp(data: &[u8]) -> Result<Self, Error> {
        let item = rlp::decode(data)?;
        let items = item.into_list()?;

        if items.len() < 3 {
            return Err(Error::Discovery("pong needs at least 3 items".to_string()));
        }

        let to = Endpoint::from_rlp(items[0].clone())?;

        let hash_bytes = items[1].clone().into_bytes()?;
        if hash_bytes.len() != 32 {
            return Err(Error::Discovery(format!(
                "invalid ping_hash length: {}",
                hash_bytes.len()
            )));
        }
        let mut ping_hash = [0u8; 32];
        ping_hash.copy_from_slice(&hash_bytes);

        let expiration = decode_u64(&items[2].clone().into_bytes()?);

        let enr_seq = if items.len() > 3 {
            Some(decode_u64(&items[3].clone().into_bytes()?))
        } else {
            None
        };

        Ok(PongMessage {
            to,
            ping_hash,
            expiration,
            enr_seq,
        })
    }

    /// Check if expired. Unused as proxy only responds to discovery.
    #[allow(dead_code)]
    pub fn is_expired(&self) -> bool {
        current_time() > self.expiration
    }
}

/// FINDNODE message to request neighbors.
/// Part of complete discv4 protocol. Unused as proxy only responds to discovery.
#[derive(Debug, Clone)]
pub struct FindNodeMessage {
    pub target: [u8; 64],
    pub expiration: u64,
}

impl FindNodeMessage {
    /// Create new FINDNODE. Unused as proxy only responds to discovery.
    #[allow(dead_code)]
    pub fn new(target: [u8; NODE_ID_LEN]) -> Self {
        let expiration = current_time() + DISCV4_EXPIRATION_SECS;
        FindNodeMessage { target, expiration }
    }

    /// Encode to RLP. Unused as proxy only responds to discovery.
    #[allow(dead_code)]
    pub fn to_rlp(&self) -> Vec<u8> {
        RlpItem::List(vec![
            RlpItem::Bytes(self.target.to_vec()),
            RlpItem::Bytes(encode_u64(self.expiration)),
        ])
        .encode()
    }

    pub fn from_rlp(data: &[u8]) -> Result<Self, Error> {
        let item = rlp::decode(data)?;
        let items = item.into_list()?;

        if items.len() < 2 {
            return Err(Error::Discovery("findnode needs 2 items".to_string()));
        }

        let target_bytes = items[0].clone().into_bytes()?;
        if target_bytes.len() != 64 {
            return Err(Error::Discovery(format!(
                "invalid target length: {}",
                target_bytes.len()
            )));
        }
        let mut target = [0u8; 64];
        target.copy_from_slice(&target_bytes);

        let expiration = decode_u64(&items[1].clone().into_bytes()?);

        Ok(FindNodeMessage { target, expiration })
    }

    /// Check if this message has expired.
    pub fn is_expired(&self) -> bool {
        current_time() > self.expiration
    }
}

#[derive(Debug, Clone)]
pub struct NodeRecord {
    pub ip: IpAddr,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub pubkey: [u8; 64],
}

impl NodeRecord {
    pub fn to_rlp(&self) -> RlpItem {
        let ip_bytes = match self.ip {
            IpAddr::V4(v4) => v4.octets().to_vec(),
            IpAddr::V6(v6) => v6.octets().to_vec(),
        };

        RlpItem::List(vec![
            RlpItem::Bytes(ip_bytes),
            RlpItem::Bytes(encode_u16(self.udp_port)),
            RlpItem::Bytes(encode_u16(self.tcp_port)),
            RlpItem::Bytes(self.pubkey.to_vec()),
        ])
    }

    pub fn from_rlp(item: RlpItem) -> Result<Self, Error> {
        let items = item.into_list()?;
        if items.len() < 4 {
            return Err(Error::Discovery("node record needs 4 items".to_string()));
        }

        let ip_bytes = items[0].clone().into_bytes()?;
        let ip = if ip_bytes.len() == 4 {
            IpAddr::V4(Ipv4Addr::new(
                ip_bytes[0],
                ip_bytes[1],
                ip_bytes[2],
                ip_bytes[3],
            ))
        } else if ip_bytes.len() == 16 {
            let arr: [u8; 16] = ip_bytes
                .try_into()
                .map_err(|_| Error::Discovery("bad ipv6".to_string()))?;
            IpAddr::V6(arr.into())
        } else {
            return Err(Error::Discovery(format!(
                "invalid ip length: {}",
                ip_bytes.len()
            )));
        };

        let udp_port = decode_u16(&items[1].clone().into_bytes()?);
        let tcp_port = decode_u16(&items[2].clone().into_bytes()?);

        let pubkey_bytes = items[3].clone().into_bytes()?;
        if pubkey_bytes.len() != 64 {
            return Err(Error::Discovery(format!(
                "invalid pubkey length: {}",
                pubkey_bytes.len()
            )));
        }
        let mut pubkey = [0u8; 64];
        pubkey.copy_from_slice(&pubkey_bytes);

        Ok(NodeRecord {
            ip,
            udp_port,
            tcp_port,
            pubkey,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NeighborsMessage {
    pub nodes: Vec<NodeRecord>,
    pub expiration: u64,
}

impl NeighborsMessage {
    pub fn new(nodes: Vec<NodeRecord>) -> Self {
        let expiration = current_time() + DISCV4_EXPIRATION_SECS;
        NeighborsMessage { nodes, expiration }
    }

    pub fn to_rlp(&self) -> Vec<u8> {
        let nodes_rlp: Vec<RlpItem> = self.nodes.iter().map(|n| n.to_rlp()).collect();

        RlpItem::List(vec![
            RlpItem::List(nodes_rlp),
            RlpItem::Bytes(encode_u64(self.expiration)),
        ])
        .encode()
    }

    pub fn from_rlp(data: &[u8]) -> Result<Self, Error> {
        let item = rlp::decode(data)?;
        let items = item.into_list()?;

        if items.len() < 2 {
            return Err(Error::Discovery("neighbors needs 2 items".to_string()));
        }

        let nodes_list = items[0].clone().into_list()?;
        let mut nodes = Vec::new();
        for node_item in nodes_list {
            nodes.push(NodeRecord::from_rlp(node_item)?);
        }

        let expiration = decode_u64(&items[1].clone().into_bytes()?);

        Ok(NeighborsMessage { nodes, expiration })
    }

    /// Check if expired. Unused as proxy only responds to discovery.
    #[allow(dead_code)]
    pub fn is_expired(&self) -> bool {
        current_time() > self.expiration
    }
}

#[derive(Debug, Clone)]
pub struct Packet {
    pub hash: [u8; 32],
    /// Signature. Parsed but unused; kept for protocol completeness.
    #[allow(dead_code)]
    pub signature: [u8; 65],
    pub packet_type: u8,
    pub data: Vec<u8>,
    /// Sender pubkey. Parsed but unused; kept for protocol completeness.
    #[allow(dead_code)]
    pub sender_pubkey: [u8; 64],
}

impl Packet {
    pub fn encode(signing_key: &SigningKey, packet_type: u8, data: &[u8]) -> Vec<u8> {
        let mut type_and_data = vec![packet_type];
        type_and_data.extend_from_slice(data);

        let msg_hash = Keccak256::digest(&type_and_data);
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(&msg_hash)
            .expect("signing failed");

        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        sig_bytes[..NODE_ID_LEN].copy_from_slice(&signature.to_bytes());
        sig_bytes[NODE_ID_LEN] = recovery_id.to_byte();

        let mut sig_and_rest = Vec::with_capacity(SIGNATURE_SIZE + type_and_data.len());
        sig_and_rest.extend_from_slice(&sig_bytes);
        sig_and_rest.extend_from_slice(&type_and_data);

        let hash = Keccak256::digest(&sig_and_rest);

        let mut packet = Vec::with_capacity(HASH_SIZE + sig_and_rest.len());
        packet.extend_from_slice(&hash);
        packet.extend_from_slice(&sig_and_rest);

        packet
    }

    pub fn decode(data: &[u8]) -> Result<Self, Error> {
        if data.len() < PACKET_HEADER_SIZE {
            return Err(Error::Discovery(format!(
                "packet too short: {} < {}",
                data.len(),
                PACKET_HEADER_SIZE
            )));
        }

        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(&data[..HASH_SIZE]);

        let computed_hash = Keccak256::digest(&data[HASH_SIZE..]);
        if hash != computed_hash[..] {
            return Err(Error::Discovery("hash mismatch".to_string()));
        }

        let mut signature = [0u8; SIGNATURE_SIZE];
        signature.copy_from_slice(&data[HASH_SIZE..HASH_SIZE + SIGNATURE_SIZE]);

        let packet_type = data[HASH_SIZE + SIGNATURE_SIZE];
        let payload = data[HASH_SIZE + SIGNATURE_SIZE + 1..].to_vec();

        let mut type_and_data = vec![packet_type];
        type_and_data.extend_from_slice(&payload);
        let msg_hash = Keccak256::digest(&type_and_data);

        let recovery_id = RecoveryId::try_from(signature[NODE_ID_LEN])
            .map_err(|e| Error::Discovery(format!("invalid recovery id: {}", e)))?;

        let sig = Signature::from_slice(&signature[..NODE_ID_LEN])
            .map_err(|e| Error::Discovery(format!("invalid signature: {}", e)))?;

        let recovered_key = VerifyingKey::recover_from_prehash(&msg_hash, &sig, recovery_id)
            .map_err(|e| Error::Discovery(format!("recovery failed: {}", e)))?;

        let pubkey_point = recovered_key.to_encoded_point(false);
        let pubkey_bytes = pubkey_point.as_bytes();
        let mut sender_pubkey = [0u8; NODE_ID_LEN];
        sender_pubkey.copy_from_slice(&pubkey_bytes[1..NODE_ID_LEN + 1]);

        Ok(Packet {
            hash,
            signature,
            packet_type,
            data: payload,
            sender_pubkey,
        })
    }
}

fn current_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Events received from discv4 protocol.
/// Unused as proxy handles events directly. Kept for future event-driven API.
#[derive(Debug)]
#[allow(dead_code)]
pub enum DiscV4Event {
    Ping { hash: [u8; 32] },
    Pong { ping_hash: [u8; 32] },
    FindNode { target: [u8; 64] },
    Neighbors { nodes: Vec<NodeRecord> },
}

/// discv4 protocol handler
pub struct DiscV4 {
    socket: Arc<UdpSocket>,
    signing_key: SigningKey,
    local_endpoint: Endpoint,
}

impl DiscV4 {
    pub fn new(socket: Arc<UdpSocket>, signing_key: SigningKey, local_endpoint: Endpoint) -> Self {
        DiscV4 {
            socket,
            signing_key,
            local_endpoint,
        }
    }

    /// Receive and decode a packet, returning the source address and event.
    /// Silently skips unsupported packet types (ENR_REQUEST, ENR_RESPONSE)
    /// and expired messages.
    pub async fn recv(&self) -> Result<(SocketAddr, DiscV4Event), Error> {
        let mut buf = [0u8; DISCV4_MAX_PACKET_SIZE];
        loop {
            let (len, src) = self
                .socket
                .recv_from(&mut buf)
                .await
                .map_err(|e| Error::Discovery(format!("recv failed: {}", e)))?;

            let packet = Packet::decode(&buf[..len])?;
            let event = match packet.packet_type {
                PING => {
                    let ping = PingMessage::from_rlp(&packet.data)?;
                    if ping.is_expired() {
                        continue; // Silently ignore expired messages
                    }
                    DiscV4Event::Ping { hash: packet.hash }
                }
                PONG => {
                    let pong = PongMessage::from_rlp(&packet.data)?;
                    if pong.is_expired() {
                        continue; // Silently ignore expired messages
                    }
                    DiscV4Event::Pong {
                        ping_hash: pong.ping_hash,
                    }
                }
                FIND_NODE => {
                    let find = FindNodeMessage::from_rlp(&packet.data)?;
                    if find.is_expired() {
                        continue; // Silently ignore expired messages
                    }
                    DiscV4Event::FindNode {
                        target: find.target,
                    }
                }
                NEIGHBORS => {
                    let neighbors = NeighborsMessage::from_rlp(&packet.data)?;
                    if neighbors.is_expired() {
                        continue; // Silently ignore expired messages
                    }
                    DiscV4Event::Neighbors {
                        nodes: neighbors.nodes,
                    }
                }
                ENR_REQUEST | ENR_RESPONSE => continue, // Silently ignore
                _ => {
                    return Err(Error::Discovery(format!(
                        "unknown packet type: {}",
                        packet.packet_type
                    )));
                }
            };

            return Ok((src, event));
        }
    }

    /// Send a PING message. Unused as proxy only responds to discovery.
    #[allow(dead_code)]
    pub async fn send_ping(
        &self,
        to: SocketAddr,
        to_endpoint: &Endpoint,
    ) -> Result<[u8; HASH_SIZE], Error> {
        let ping = PingMessage::new(self.local_endpoint.clone(), to_endpoint.clone());
        let data = Packet::encode(&self.signing_key, PING, &ping.to_rlp());

        let mut hash = [0u8; HASH_SIZE];
        hash.copy_from_slice(&data[..HASH_SIZE]);

        self.socket
            .send_to(&data, to)
            .await
            .map_err(|e| Error::Discovery(format!("send ping failed: {}", e)))?;

        Ok(hash)
    }

    /// Send a PONG message in response to a PING
    pub async fn send_pong(&self, to: SocketAddr, ping_hash: [u8; 32]) -> Result<(), Error> {
        let to_endpoint = Endpoint::new(to.ip(), to.port(), to.port());
        let pong = PongMessage::new(to_endpoint, ping_hash);
        let data = Packet::encode(&self.signing_key, PONG, &pong.to_rlp());

        self.socket
            .send_to(&data, to)
            .await
            .map_err(|e| Error::Discovery(format!("send pong failed: {}", e)))?;

        Ok(())
    }

    /// Send a NEIGHBORS message
    pub async fn send_neighbors(
        &self,
        to: SocketAddr,
        nodes: Vec<NodeRecord>,
    ) -> Result<(), Error> {
        let neighbors = NeighborsMessage::new(nodes);
        let data = Packet::encode(&self.signing_key, NEIGHBORS, &neighbors.to_rlp());

        self.socket
            .send_to(&data, to)
            .await
            .map_err(|e| Error::Discovery(format!("send neighbors failed: {}", e)))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_roundtrip() {
        let endpoint = Endpoint::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 30303, 30303);

        let rlp = endpoint.to_rlp();
        let decoded = Endpoint::from_rlp(rlp).expect("valid endpoint RLP should decode");

        assert_eq!(endpoint.ip, decoded.ip);
        assert_eq!(endpoint.udp_port, decoded.udp_port);
        assert_eq!(endpoint.tcp_port, decoded.tcp_port);
    }

    #[test]
    fn test_ping_roundtrip() {
        let from = Endpoint::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 30303, 30303);
        let to = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 30304, 30304);

        let ping = PingMessage::new(from, to);
        let encoded = ping.to_rlp();
        let decoded = PingMessage::from_rlp(&encoded).expect("valid ping RLP should decode");

        assert_eq!(ping.version, decoded.version);
        assert_eq!(ping.expiration, decoded.expiration);
    }

    #[test]
    fn test_packet_roundtrip() {
        let key = SigningKey::random(&mut rand::thread_rng());
        let ping_data = vec![1, 2, 3, 4];

        let encoded = Packet::encode(&key, PING, &ping_data);
        let decoded = Packet::decode(&encoded).expect("valid packet should decode");

        assert_eq!(decoded.packet_type, PING);
        assert_eq!(decoded.data, ping_data);
    }

    #[test]
    fn test_ping_expiration() {
        let from = Endpoint::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 30303, 30303);
        let to = Endpoint::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 30304, 30304);

        // Fresh ping should not be expired
        let ping = PingMessage::new(from.clone(), to.clone());
        assert!(!ping.is_expired());

        // Manually create an expired ping
        let expired_ping = PingMessage {
            version: 4,
            from,
            to,
            expiration: 0, // Unix epoch = long expired
            enr_seq: None,
        };
        assert!(expired_ping.is_expired());
    }
}
