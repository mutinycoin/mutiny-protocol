use std::collections::BTreeSet;
use std::net::TcpStream;

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use thiserror::Error;

use mutiny_p2p::Frame;

use crate::{
    session_id, sign_node_accept, sign_worker_auth, verify_node_accept, verify_worker_auth,
    worker_id, NodeChallengeV1, PackLError, WorkerHelloV1, MSG_NODE_ACCEPT, MSG_NODE_CHALLENGE,
    MSG_WORKER_AUTH, MSG_WORKER_HELLO,
};

#[derive(Debug, Error)]
pub enum EndpointError {
    #[error("Pack-L error: {0}")]
    PackL(#[from] PackLError),
    #[error("P2P frame error: {0}")]
    Frame(String),
    #[error("wrong Pack-L message type")]
    WrongMessageType,
    #[error("request_id must be nonzero")]
    ZeroRequestId,
    #[error("Pack-L request_id mismatch")]
    RequestIdMismatch,
    #[error("worker is not locally authorized")]
    UnauthorizedWorker,
    #[error("node identity does not match local pairing")]
    WrongNode,
    #[error("worker identity already has an active session")]
    DuplicateActiveWorker,
    #[error("handshake payload length is invalid")]
    BadPayloadLength,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedWorkerSession {
    pub worker_id: [u8; 32],
    pub worker_public_key: [u8; 32],
    pub node_id: [u8; 32],
    pub session_id: [u8; 32],
    pub request_id: u64,
}

#[derive(Debug, Default)]
pub struct ActiveWorkerRegistry {
    active: BTreeSet<[u8; 32]>,
}

impl ActiveWorkerRegistry {
    pub fn claim(&mut self, worker_id: [u8; 32]) -> Result<(), EndpointError> {
        if !self.active.insert(worker_id) {
            return Err(EndpointError::DuplicateActiveWorker);
        }
        Ok(())
    }

    pub fn release(&mut self, worker_id: &[u8; 32]) {
        self.active.remove(worker_id);
    }

    pub fn contains(&self, worker_id: &[u8; 32]) -> bool {
        self.active.contains(worker_id)
    }

    pub fn len(&self) -> usize {
        self.active.len()
    }

    pub fn is_empty(&self) -> bool {
        self.active.is_empty()
    }
}

pub fn node_id_from_public_key(node_public_key: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"MUTINY-NODE-ID-V1");
    h.update(node_public_key);
    h.finalize().into()
}

fn read_exact_frame(
    stream: &mut TcpStream,
    expected_magic: u32,
    expected_type: u16,
    expected_request_id: Option<u64>,
) -> Result<Frame, EndpointError> {
    let frame = Frame::read_from(stream, expected_magic)
        .map_err(|e| EndpointError::Frame(format!("{e:?}")))?;
    if frame.message_type != expected_type {
        return Err(EndpointError::WrongMessageType);
    }
    if let Some(request_id) = expected_request_id {
        if frame.request_id != request_id {
            return Err(EndpointError::RequestIdMismatch);
        }
    }
    Ok(frame)
}

fn write_frame(
    stream: &mut TcpStream,
    magic: u32,
    message_type: u16,
    request_id: u64,
    payload: Vec<u8>,
) -> Result<(), EndpointError> {
    let frame = Frame::new(magic, message_type, request_id, payload)
        .map_err(|e| EndpointError::Frame(format!("{e:?}")))?;
    frame
        .write_to(stream)
        .map_err(|e| EndpointError::Frame(format!("{e:?}")))
}

/// Server-side Pack-L V1 mutual authentication.
///
/// The caller supplies a fresh cryptographically random node_nonce for every
/// attempted handshake and a local allowlist. No owner/mining secret is used.
pub fn accept_worker_handshake(
    stream: &mut TcpStream,
    worker_magic: u32,
    network_id: u32,
    node_signing_key: &SigningKey,
    node_nonce: [u8; 32],
    node_capabilities: u64,
    allowed_workers: &BTreeSet<[u8; 32]>,
    active_workers: &mut ActiveWorkerRegistry,
) -> Result<AuthenticatedWorkerSession, EndpointError> {
    let hello_frame = read_exact_frame(stream, worker_magic, MSG_WORKER_HELLO, None)?;
    if hello_frame.request_id == 0 {
        return Err(EndpointError::ZeroRequestId);
    }

    let hello = WorkerHelloV1::decode(&hello_frame.payload)?;
    if hello.network_id != network_id {
        return Err(PackLError::InvalidField("WorkerHello NetworkID mismatch").into());
    }
    let worker_id_value = hello.worker_id();
    if !allowed_workers.contains(&worker_id_value) {
        return Err(EndpointError::UnauthorizedWorker);
    }

    let node_public_key = node_signing_key.verifying_key().to_bytes();
    let node_id = node_id_from_public_key(&node_public_key);
    let challenge = NodeChallengeV1 {
        network_id,
        node_id,
        node_public_key,
        worker_id: worker_id_value,
        worker_nonce: hello.worker_nonce,
        node_nonce,
        capabilities: node_capabilities,
    };

    write_frame(
        stream,
        worker_magic,
        MSG_NODE_CHALLENGE,
        hello_frame.request_id,
        challenge.encode(),
    )?;

    let auth_frame = read_exact_frame(
        stream,
        worker_magic,
        MSG_WORKER_AUTH,
        Some(hello_frame.request_id),
    )?;
    if auth_frame.payload.len() != 64 {
        return Err(EndpointError::BadPayloadLength);
    }
    let worker_signature: [u8; 64] = auth_frame
        .payload
        .as_slice()
        .try_into()
        .map_err(|_| EndpointError::BadPayloadLength)?;

    verify_worker_auth(
        &hello.worker_public_key,
        &hello,
        &challenge,
        &worker_signature,
    )?;

    active_workers.claim(worker_id_value)?;

    let node_signature = sign_node_accept(node_signing_key, &hello, &challenge, &worker_signature);

    let sid = session_id(&hello, &challenge, &worker_signature, &node_signature);

    if let Err(error) = write_frame(
        stream,
        worker_magic,
        MSG_NODE_ACCEPT,
        hello_frame.request_id,
        node_signature.to_vec(),
    ) {
        active_workers.release(&worker_id_value);
        return Err(error);
    }

    Ok(AuthenticatedWorkerSession {
        worker_id: worker_id_value,
        worker_public_key: hello.worker_public_key,
        node_id,
        session_id: sid,
        request_id: hello_frame.request_id,
    })
}

/// Worker-side Pack-L V1 mutual authentication.
///
/// `expected_node_id` comes from explicit local pairing/configuration.
/// The worker never trusts an arbitrary node public key merely because its
/// NODE_ACCEPT signature is self-consistent.
pub fn initiate_worker_handshake(
    stream: &mut TcpStream,
    worker_magic: u32,
    network_id: u32,
    worker_signing_key: &SigningKey,
    worker_nonce: [u8; 32],
    worker_capabilities: u64,
    max_parallelism: u16,
    request_id: u64,
    expected_node_id: [u8; 32],
) -> Result<AuthenticatedWorkerSession, EndpointError> {
    if request_id == 0 {
        return Err(EndpointError::ZeroRequestId);
    }

    let worker_public_key = worker_signing_key.verifying_key().to_bytes();
    let hello = WorkerHelloV1 {
        network_id,
        worker_public_key,
        worker_nonce,
        capabilities: worker_capabilities,
        max_parallelism,
    };

    write_frame(
        stream,
        worker_magic,
        MSG_WORKER_HELLO,
        request_id,
        hello.encode(),
    )?;

    let challenge_frame =
        read_exact_frame(stream, worker_magic, MSG_NODE_CHALLENGE, Some(request_id))?;
    let challenge = NodeChallengeV1::decode(&challenge_frame.payload)?;
    challenge.validate_for_hello(&hello)?;

    let derived_node_id = node_id_from_public_key(&challenge.node_public_key);
    if challenge.node_id != derived_node_id || challenge.node_id != expected_node_id {
        return Err(EndpointError::WrongNode);
    }

    let worker_signature = sign_worker_auth(worker_signing_key, &hello, &challenge);
    write_frame(
        stream,
        worker_magic,
        MSG_WORKER_AUTH,
        request_id,
        worker_signature.to_vec(),
    )?;

    let accept_frame = read_exact_frame(stream, worker_magic, MSG_NODE_ACCEPT, Some(request_id))?;
    if accept_frame.payload.len() != 64 {
        return Err(EndpointError::BadPayloadLength);
    }
    let node_signature: [u8; 64] = accept_frame
        .payload
        .as_slice()
        .try_into()
        .map_err(|_| EndpointError::BadPayloadLength)?;

    verify_node_accept(
        &challenge.node_public_key,
        &hello,
        &challenge,
        &worker_signature,
        &node_signature,
    )?;

    Ok(AuthenticatedWorkerSession {
        worker_id: worker_id(network_id, &worker_public_key),
        worker_public_key,
        node_id: challenge.node_id,
        session_id: session_id(&hello, &challenge, &worker_signature, &node_signature),
        request_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;
    use std::time::Duration;

    use crate::WORKER_MAGIC_DEVNET;

    const NETWORK: u32 = 0x4D55_5403;

    fn worker_key() -> SigningKey {
        SigningKey::from_bytes(&[
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ])
    }

    fn node_key() -> SigningKey {
        SigningKey::from_bytes(&[
            32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
            54, 55, 56, 57, 58, 59, 60, 61, 62, 63,
        ])
    }

    #[test]
    fn real_tcp_mutual_auth_succeeds_and_session_ids_match() {
        let worker = worker_key();
        let node = node_key();
        let expected_node_id = node_id_from_public_key(&node.verifying_key().to_bytes());
        let worker_id_value = worker_id(NETWORK, &worker.verifying_key().to_bytes());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();

            let mut allowed = BTreeSet::new();
            allowed.insert(worker_id_value);
            let mut active = ActiveWorkerRegistry::default();

            let session = accept_worker_handshake(
                &mut socket,
                WORKER_MAGIC_DEVNET,
                NETWORK,
                &node,
                [0x60; 32],
                1,
                &allowed,
                &mut active,
            )
            .unwrap();
            assert!(active.contains(&worker_id_value));
            session
        });

        let mut socket = TcpStream::connect(addr).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();

        let client = initiate_worker_handshake(
            &mut socket,
            WORKER_MAGIC_DEVNET,
            NETWORK,
            &worker,
            [0x40; 32],
            1,
            4,
            0x0102_0304_0506_0708,
            expected_node_id,
        )
        .unwrap();

        let server = server.join().unwrap();
        assert_eq!(client, server);
    }

    #[test]
    fn unauthorized_worker_is_rejected() {
        let worker = worker_key();
        let node = node_key();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut active = ActiveWorkerRegistry::default();
            let allowed = BTreeSet::new();
            matches!(
                accept_worker_handshake(
                    &mut socket,
                    WORKER_MAGIC_DEVNET,
                    NETWORK,
                    &node,
                    [0x61; 32],
                    0,
                    &allowed,
                    &mut active,
                ),
                Err(EndpointError::UnauthorizedWorker)
            )
        });

        let mut socket = TcpStream::connect(addr).unwrap();
        let result = initiate_worker_handshake(
            &mut socket,
            WORKER_MAGIC_DEVNET,
            NETWORK,
            &worker,
            [0x41; 32],
            0,
            1,
            1,
            [0; 32],
        );
        assert!(result.is_err());
        assert!(server.join().unwrap());
    }

    #[test]
    fn wrong_network_is_rejected_before_authentication() {
        let worker = worker_key();
        let node = node_key();
        let worker_id_value = worker_id(NETWORK + 1, &worker.verifying_key().to_bytes());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut active = ActiveWorkerRegistry::default();
            let mut allowed = BTreeSet::new();
            allowed.insert(worker_id_value);
            matches!(
                accept_worker_handshake(
                    &mut socket,
                    WORKER_MAGIC_DEVNET,
                    NETWORK,
                    &node,
                    [0x62; 32],
                    0,
                    &allowed,
                    &mut active,
                ),
                Err(EndpointError::PackL(PackLError::InvalidField(
                    "WorkerHello NetworkID mismatch"
                )))
            )
        });

        let mut socket = TcpStream::connect(addr).unwrap();
        let result = initiate_worker_handshake(
            &mut socket,
            WORKER_MAGIC_DEVNET,
            NETWORK + 1,
            &worker,
            [0x42; 32],
            0,
            1,
            2,
            [0; 32],
        );
        assert!(result.is_err());
        assert!(server.join().unwrap());
    }

    #[test]
    fn active_worker_registry_rejects_duplicate_session() {
        let id = [0xAA; 32];
        let mut active = ActiveWorkerRegistry::default();
        active.claim(id).unwrap();
        assert!(matches!(
            active.claim(id),
            Err(EndpointError::DuplicateActiveWorker)
        ));
        assert_eq!(active.len(), 1);
        active.release(&id);
        assert!(active.is_empty());
    }

    #[test]
    fn zero_request_id_is_never_valid_for_handshake() {
        let worker = worker_key();
        let node = node_key();
        let expected_node_id = node_id_from_public_key(&node.verifying_key().to_bytes());

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (_socket, _) = listener.accept().unwrap();
        });

        let mut socket = TcpStream::connect(addr).unwrap();
        assert!(matches!(
            initiate_worker_handshake(
                &mut socket,
                WORKER_MAGIC_DEVNET,
                NETWORK,
                &worker,
                [0x43; 32],
                0,
                1,
                0,
                expected_node_id,
            ),
            Err(EndpointError::ZeroRequestId)
        ));

        server.join().unwrap();
    }
}
