use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use mutiny_crypto::{domains, sha256_domain};
use mutiny_types::Hash256;
use rand_core::{OsRng, RngCore};
use std::{
    fs,
    io::{Read, Write},
    net::TcpStream,
    path::Path,
};
use thiserror::Error;

pub const P2P_VERSION: u16 = 1;
pub const P2P_MAGIC_MAINNET: u32 = 0x4D55_544D;
pub const P2P_MAGIC_TESTNET: u32 = 0x4D55_5454;
pub const P2P_MAGIC_DEVNET: u32 = 0x4D55_5444;
pub const MAX_P2P_PAYLOAD: u32 = 1 << 20;
pub const MSG_CHALLENGE: u16 = 0x0001;
pub const MSG_HELLO: u16 = 0x0002;
pub const MSG_HELLO_ACK: u16 = 0x0003;
pub const MSG_PING: u16 = 0x0004;
pub const MSG_PONG: u16 = 0x0005;
pub const MSG_GET_ADDR: u16 = 0x0006;
pub const MSG_ADDR: u16 = 0x0007;
// Frozen Pack-H block/header relay registry.
pub const MSG_GET_HEADERS: u16 = 0x0010;
pub const MSG_HEADERS: u16 = 0x0011;
pub const MSG_BLOCK_ANNOUNCE: u16 = 0x0012;
pub const MSG_GET_BLOCK: u16 = 0x0013;
pub const MSG_BLOCK: u16 = 0x0014;
pub const MSG_WINNING_BLOCK: u16 = 0x0015;
// Frozen Pack-H transaction relay registry.
pub const MSG_TX_ANNOUNCE: u16 = 0x0020;
pub const MSG_GET_TX: u16 = 0x0021;
pub const MSG_TX: u16 = 0x0022;
pub const MSG_DEVNET_TX_RESULT: u16 = 0x7F06;
/// Experimental Build-4 acknowledgement only; consensus block transport uses frozen 0x0010..0x0015 messages.
pub const MSG_DEVNET_BLOCK_RESULT: u16 = 0x7F10;
pub const CAP_FULL_NODE: u32 = 1 << 0;
pub const CAP_BLOCK_RELAY: u32 = 1 << 1;
pub const CAP_TX_RELAY: u32 = 1 << 2;
pub const CAP_STATE_PROOFS: u32 = 1 << 3;
pub const CAP_MINER_GATEWAY: u32 = 1 << 4;
pub const CAP_PEER_DISCOVERY: u32 = 1 << 5;
pub const CAP_BUILD4_NODE: u32 =
    CAP_FULL_NODE | CAP_BLOCK_RELAY | CAP_TX_RELAY | CAP_STATE_PROOFS | CAP_MINER_GATEWAY;
pub const CAP_BUILD42_NODE: u32 = CAP_BUILD4_NODE | CAP_PEER_DISCOVERY;
/// Build 4.3 changes transport/session lifetime only; it consumes no new frozen capability bit.
pub const CAP_BUILD43_NODE: u32 = CAP_BUILD42_NODE;
/// Build 4.4 hardens diagnostics/session accounting only; it consumes no new frozen capability bit.
pub const CAP_BUILD44_NODE: u32 = CAP_BUILD43_NODE;
/// Build 4.5 adds asynchronous duplex routing without consuming a new capability bit.
pub const CAP_BUILD45_NODE: u32 = CAP_BUILD44_NODE;
/// Build 4.5.1 cuts the live node over to the proven Build 4.5 duplex engine; no new capability bit.
pub const CAP_BUILD451_NODE: u32 = CAP_BUILD45_NODE;
// Alias retained so older harness code can still compile while Build 4 migrates call sites.
pub const CAP_BUILD3_NODE: u32 = CAP_BUILD4_NODE;

#[derive(Debug, Error)]
pub enum P2pError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("wrong P2P magic")]
    BadMagic,
    #[error("unsupported P2P version")]
    BadVersion,
    #[error("unknown non-zero V1 flags")]
    BadFlags,
    #[error("payload too large")]
    PayloadTooLarge,
    #[error("P2P checksum mismatch")]
    BadChecksum,
    #[error("unexpected message type")]
    UnexpectedMessage,
    #[error("handshake network mismatch")]
    NetworkMismatch,
    #[error("handshake nonce mismatch")]
    NonceMismatch,
    #[error("invalid handshake public key")]
    BadPublicKey,
    #[error("invalid handshake signature")]
    BadSignature,
    #[error("invalid handshake payload length")]
    BadHandshakeLength,
    #[error("invalid node key file")]
    BadNodeKey,
}

#[derive(Debug, Clone)]
pub struct Frame {
    pub magic: u32,
    pub version: u16,
    pub message_type: u16,
    pub flags: u16,
    pub request_id: u64,
    pub payload: Vec<u8>,
}
impl Frame {
    pub fn new(
        magic: u32,
        message_type: u16,
        request_id: u64,
        payload: Vec<u8>,
    ) -> Result<Self, P2pError> {
        if payload.len() > MAX_P2P_PAYLOAD as usize {
            return Err(P2pError::PayloadTooLarge);
        }
        Ok(Self {
            magic,
            version: P2P_VERSION,
            message_type,
            flags: 0,
            request_id,
            payload,
        })
    }
    pub fn encode(&self) -> Result<Vec<u8>, P2pError> {
        if self.payload.len() > MAX_P2P_PAYLOAD as usize {
            return Err(P2pError::PayloadTooLarge);
        }
        let c = checksum4(self.message_type, &self.payload);
        let mut o = Vec::with_capacity(26 + self.payload.len());
        o.extend_from_slice(&self.magic.to_be_bytes());
        o.extend_from_slice(&self.version.to_be_bytes());
        o.extend_from_slice(&self.message_type.to_be_bytes());
        o.extend_from_slice(&self.flags.to_be_bytes());
        o.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        o.extend_from_slice(&self.request_id.to_be_bytes());
        o.extend_from_slice(&c);
        o.extend_from_slice(&self.payload);
        Ok(o)
    }
    pub fn write_to(&self, s: &mut TcpStream) -> Result<(), P2pError> {
        s.write_all(&self.encode()?)?;
        s.flush()?;
        Ok(())
    }
    pub fn read_from(s: &mut TcpStream, expected_magic: u32) -> Result<Self, P2pError> {
        let mut h = [0u8; 26];
        s.read_exact(&mut h)?;
        let magic = u32::from_be_bytes(h[0..4].try_into().unwrap());
        if magic != expected_magic {
            return Err(P2pError::BadMagic);
        }
        let version = u16::from_be_bytes(h[4..6].try_into().unwrap());
        if version != P2P_VERSION {
            return Err(P2pError::BadVersion);
        }
        let message_type = u16::from_be_bytes(h[6..8].try_into().unwrap());
        let flags = u16::from_be_bytes(h[8..10].try_into().unwrap());
        if flags != 0 {
            return Err(P2pError::BadFlags);
        }
        let len = u32::from_be_bytes(h[10..14].try_into().unwrap());
        if len > MAX_P2P_PAYLOAD {
            return Err(P2pError::PayloadTooLarge);
        }
        let request_id = u64::from_be_bytes(h[14..22].try_into().unwrap());
        let expected: [u8; 4] = h[22..26].try_into().unwrap();
        let mut payload = vec![0u8; len as usize];
        s.read_exact(&mut payload)?;
        if checksum4(message_type, &payload) != expected {
            return Err(P2pError::BadChecksum);
        }
        Ok(Self {
            magic,
            version,
            message_type,
            flags,
            request_id,
            payload,
        })
    }
}
pub fn checksum4(message_type: u16, payload: &[u8]) -> [u8; 4] {
    let mt = message_type.to_be_bytes();
    sha256_domain(domains::P2P_CHECKSUM, &[&mt, payload]).0[..4]
        .try_into()
        .unwrap()
}
pub fn node_id(pk: &[u8; 32]) -> Hash256 {
    sha256_domain(domains::NODE_ID, &[pk])
}
pub fn load_or_create_node_key(path: &Path) -> Result<SigningKey, P2pError> {
    if path.exists() {
        let b = fs::read(path)?;
        let seed: [u8; 32] = b.try_into().map_err(|_| P2pError::BadNodeKey)?;
        return Ok(SigningKey::from_bytes(&seed));
    }
    if let Some(p) = path.parent() {
        fs::create_dir_all(p)?;
    }
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    fs::write(path, seed)?;
    Ok(SigningKey::from_bytes(&seed))
}
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub node_public_key: [u8; 32],
    pub node_id: Hash256,
    pub capabilities: u32,
    pub selected_version: u16,
}

fn nonce() -> [u8; 32] {
    let mut n = [0u8; 32];
    OsRng.fill_bytes(&mut n);
    n
}
fn transcript(
    network: u32,
    version: u16,
    ca: u32,
    cb: u32,
    pa: &[u8; 32],
    pb: &[u8; 32],
    na: &[u8; 32],
    nb: &[u8; 32],
) -> Hash256 {
    let n = network.to_be_bytes();
    let v = version.to_be_bytes();
    let a = ca.to_be_bytes();
    let b = cb.to_be_bytes();
    sha256_domain(domains::P2P_HANDSHAKE, &[&n, &v, &a, &b, pa, pb, na, nb])
}
fn verify(pk: &[u8; 32], digest: &[u8; 32], sig: &[u8; 64]) -> Result<(), P2pError> {
    let vk = VerifyingKey::from_bytes(pk).map_err(|_| P2pError::BadPublicKey)?;
    vk.verify_strict(digest, &Signature::from_bytes(sig))
        .map_err(|_| P2pError::BadSignature)
}

pub fn initiator_handshake(
    s: &mut TcpStream,
    key: &SigningKey,
    caps: u32,
    network: u32,
    magic: u32,
) -> Result<PeerInfo, P2pError> {
    let pa = key.verifying_key().to_bytes();
    let na = nonce();
    let mut c = Vec::with_capacity(76);
    c.extend_from_slice(&network.to_be_bytes());
    c.extend_from_slice(&1u16.to_be_bytes());
    c.extend_from_slice(&1u16.to_be_bytes());
    c.extend_from_slice(&caps.to_be_bytes());
    c.extend_from_slice(&pa);
    c.extend_from_slice(&na);
    Frame::new(magic, MSG_CHALLENGE, 1, c)?.write_to(s)?;
    let f = Frame::read_from(s, magic)?;
    if f.message_type != MSG_HELLO || f.payload.len() != 170 {
        return Err(P2pError::UnexpectedMessage);
    }
    let p = &f.payload;
    let net = u32::from_be_bytes(p[0..4].try_into().unwrap());
    if net != network {
        return Err(P2pError::NetworkMismatch);
    }
    let ver = u16::from_be_bytes(p[4..6].try_into().unwrap());
    if ver != 1 {
        return Err(P2pError::BadVersion);
    }
    let cb = u32::from_be_bytes(p[6..10].try_into().unwrap());
    let pb: [u8; 32] = p[10..42].try_into().unwrap();
    let echoed: [u8; 32] = p[42..74].try_into().unwrap();
    if echoed != na {
        return Err(P2pError::NonceMismatch);
    }
    let nb: [u8; 32] = p[74..106].try_into().unwrap();
    let sig: [u8; 64] = p[106..170].try_into().unwrap();
    let t = transcript(network, 1, caps, cb, &pa, &pb, &na, &nb);
    let hd = sha256_domain(domains::P2P_HELLO_SIGN, &[&t.0]);
    verify(&pb, &hd.0, &sig)?;
    let ad = sha256_domain(domains::P2P_ACK_SIGN, &[&t.0]);
    let mut ack = Vec::with_capacity(102);
    ack.extend_from_slice(&network.to_be_bytes());
    ack.extend_from_slice(&1u16.to_be_bytes());
    ack.extend_from_slice(&nb);
    ack.extend_from_slice(&key.sign(&ad.0).to_bytes());
    Frame::new(magic, MSG_HELLO_ACK, 1, ack)?.write_to(s)?;
    Ok(PeerInfo {
        node_public_key: pb,
        node_id: node_id(&pb),
        capabilities: cb,
        selected_version: 1,
    })
}
pub fn responder_handshake(
    s: &mut TcpStream,
    key: &SigningKey,
    caps: u32,
    network: u32,
    magic: u32,
) -> Result<PeerInfo, P2pError> {
    let f = Frame::read_from(s, magic)?;
    if f.message_type != MSG_CHALLENGE || f.payload.len() != 76 {
        return Err(P2pError::UnexpectedMessage);
    }
    let p = &f.payload;
    if u32::from_be_bytes(p[0..4].try_into().unwrap()) != network {
        return Err(P2pError::NetworkMismatch);
    }
    let min = u16::from_be_bytes(p[4..6].try_into().unwrap());
    let max = u16::from_be_bytes(p[6..8].try_into().unwrap());
    if min > 1 || max < 1 {
        return Err(P2pError::BadVersion);
    }
    let ca = u32::from_be_bytes(p[8..12].try_into().unwrap());
    let pa: [u8; 32] = p[12..44].try_into().unwrap();
    VerifyingKey::from_bytes(&pa).map_err(|_| P2pError::BadPublicKey)?;
    let na: [u8; 32] = p[44..76].try_into().unwrap();
    let pb = key.verifying_key().to_bytes();
    let nb = nonce();
    let t = transcript(network, 1, ca, caps, &pa, &pb, &na, &nb);
    let hd = sha256_domain(domains::P2P_HELLO_SIGN, &[&t.0]);
    let mut hello = Vec::with_capacity(170);
    hello.extend_from_slice(&network.to_be_bytes());
    hello.extend_from_slice(&1u16.to_be_bytes());
    hello.extend_from_slice(&caps.to_be_bytes());
    hello.extend_from_slice(&pb);
    hello.extend_from_slice(&na);
    hello.extend_from_slice(&nb);
    hello.extend_from_slice(&key.sign(&hd.0).to_bytes());
    Frame::new(magic, MSG_HELLO, f.request_id, hello)?.write_to(s)?;
    let a = Frame::read_from(s, magic)?;
    if a.message_type != MSG_HELLO_ACK || a.payload.len() != 102 {
        return Err(P2pError::UnexpectedMessage);
    }
    let q = &a.payload;
    if u32::from_be_bytes(q[0..4].try_into().unwrap()) != network {
        return Err(P2pError::NetworkMismatch);
    }
    let echoed: [u8; 32] = q[6..38].try_into().unwrap();
    if echoed != nb {
        return Err(P2pError::NonceMismatch);
    }
    let sig: [u8; 64] = q[38..102].try_into().unwrap();
    let ad = sha256_domain(domains::P2P_ACK_SIGN, &[&t.0]);
    verify(&pa, &ad.0, &sig)?;
    Ok(PeerInfo {
        node_public_key: pa,
        node_id: node_id(&pa),
        capabilities: ca,
        selected_version: 1,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pack_h_peer_discovery_message_ids() {
        assert_eq!(MSG_GET_ADDR, 0x0006);
        assert_eq!(MSG_ADDR, 0x0007);
        assert_eq!(CAP_PEER_DISCOVERY, 1 << 5);
        assert_eq!(CAP_BUILD42_NODE & CAP_PEER_DISCOVERY, CAP_PEER_DISCOVERY);
        assert_eq!(CAP_BUILD43_NODE, CAP_BUILD42_NODE);
        assert_eq!(CAP_BUILD44_NODE, CAP_BUILD43_NODE);
        assert_eq!(CAP_BUILD45_NODE, CAP_BUILD44_NODE);
        assert_eq!(CAP_BUILD451_NODE, CAP_BUILD45_NODE);
    }
    #[test]
    fn pack_h_block_message_ids() {
        assert_eq!(MSG_GET_HEADERS, 0x0010);
        assert_eq!(MSG_HEADERS, 0x0011);
        assert_eq!(MSG_BLOCK_ANNOUNCE, 0x0012);
        assert_eq!(MSG_GET_BLOCK, 0x0013);
        assert_eq!(MSG_BLOCK, 0x0014);
        assert_eq!(MSG_WINNING_BLOCK, 0x0015);
    }
    #[test]
    fn pack_h_transaction_message_ids() {
        assert_eq!(MSG_TX_ANNOUNCE, 0x0020);
        assert_eq!(MSG_GET_TX, 0x0021);
        assert_eq!(MSG_TX, 0x0022);
    }
    #[test]
    fn ping_vector() {
        let p = hex::decode("1122334455667788").unwrap();
        assert_eq!(checksum4(MSG_PING, &p), [0xdb, 0x81, 0xe7, 0xd4]);
        let f = Frame::new(P2P_MAGIC_MAINNET, MSG_PING, 0x0102030405060708, p).unwrap();
        assert_eq!(
            hex::encode(f.encode().unwrap()),
            "4d55544d000100040000000000080102030405060708db81e7d41122334455667788"
        );
    }
    #[test]
    fn node_id_vector() {
        let p: [u8; 32] =
            hex::decode("79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664")
                .unwrap()
                .try_into()
                .unwrap();
        assert_eq!(
            node_id(&p).to_hex(),
            "680724ca9d1d965f1c3ad69273bcc92a1079cf43d35af05dc322f5a1388c2081"
        );
    }
}
