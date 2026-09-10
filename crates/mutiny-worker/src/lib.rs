pub mod endpoint;
pub mod ledger;
pub mod reference;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PACK_L_VERSION: u16 = 1;

pub const WORKER_MAGIC_MAINNET: u32 = 0x4D55_574D; // MUWM
pub const WORKER_MAGIC_TESTNET: u32 = 0x4D55_5754; // MUWT
pub const WORKER_MAGIC_DEVNET: u32 = 0x4D55_5744; // MUWD

pub const MSG_WORKER_HELLO: u16 = 0x0201;
pub const MSG_NODE_CHALLENGE: u16 = 0x0202;
pub const MSG_WORKER_AUTH: u16 = 0x0203;
pub const MSG_NODE_ACCEPT: u16 = 0x0204;
pub const MSG_WORK_ASSIGNMENT: u16 = 0x0210;
pub const MSG_WORK_RESULT: u16 = 0x0211;
pub const MSG_WORK_CANCEL: u16 = 0x0212;
pub const MSG_WORK_REJECT: u16 = 0x0213;
pub const MSG_WORKER_PING: u16 = 0x0220;
pub const MSG_WORKER_PONG: u16 = 0x0221;

pub const RESULT_NO_WIN: u8 = 0x00;
pub const RESULT_WIN: u8 = 0x01;

pub const ALGORITHM_PACK_A_ARGON2ID: u16 = 0x0001;
pub const ALGORITHM_PACK_A_ARGON2ID_V1: u16 = 0x0001;

pub const WORKER_HELLO_LEN: usize = 80;
pub const NODE_CHALLENGE_LEN: usize = 174;
pub const WORK_ASSIGNMENT_CORE_LEN: usize = 278;
pub const WORK_ASSIGNMENT_LEN: usize = 406;
pub const WORK_RESULT_CORE_LEN: usize = 167;
pub const WORK_RESULT_LEN: usize = 231;
pub const WORK_CANCEL_CORE_LEN: usize = 103;
pub const WORK_CANCEL_LEN: usize = 167;
pub const WORK_REJECT_LEN: usize = 74;

const DOMAIN_WORKER_ID: &[u8] = b"MUTINY-WORKER-ID-V1";
const DOMAIN_WORKER_AUTH: &[u8] = b"MUTINY-WORKER-AUTH-V1";
const DOMAIN_NODE_ACCEPT: &[u8] = b"MUTINY-NODE-WORKER-ACCEPT-V1";
const DOMAIN_SESSION_ID: &[u8] = b"MUTINY-WORKER-SESSION-ID-V1";
const DOMAIN_TICKET_KEY: &[u8] = b"MUTINY-WORK-TICKET-KEY-V1";
const DOMAIN_ASSIGNMENT_ID: &[u8] = b"MUTINY-WORK-ASSIGNMENT-ID-V1";
const DOMAIN_ASSIGNMENT_SIGNATURE: &[u8] = b"MUTINY-WORK-ASSIGNMENT-V1";
const DOMAIN_RESULT_SIGNATURE: &[u8] = b"MUTINY-WORK-RESULT-V1";
const DOMAIN_CANCEL_SIGNATURE: &[u8] = b"MUTINY-WORK-CANCEL-V1";

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PackLError {
    #[error("invalid length: expected {expected}, got {actual}")]
    InvalidLength { expected: usize, actual: usize },
    #[error("invalid version {0}")]
    InvalidVersion(u16),
    #[error("invalid field: {0}")]
    InvalidField(&'static str),
    #[error("invalid signature")]
    InvalidSignature,
    #[error("replay or duplicate assignment")]
    Replay,
    #[error("ticket index is outside the consensus-authorized work budget")]
    OutOfBudget,
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(domain);
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

fn push_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn push_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}
fn push_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }
    fn take<const N: usize>(&mut self) -> Result<[u8; N], PackLError> {
        let end = self
            .pos
            .checked_add(N)
            .ok_or(PackLError::InvalidField("reader overflow"))?;
        if end > self.bytes.len() {
            return Err(PackLError::InvalidLength {
                expected: end,
                actual: self.bytes.len(),
            });
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.bytes[self.pos..end]);
        self.pos = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, PackLError> {
        Ok(self.take::<1>()?[0])
    }
    fn u16(&mut self) -> Result<u16, PackLError> {
        Ok(u16::from_be_bytes(self.take::<2>()?))
    }
    fn u32(&mut self) -> Result<u32, PackLError> {
        Ok(u32::from_be_bytes(self.take::<4>()?))
    }
    fn u64(&mut self) -> Result<u64, PackLError> {
        Ok(u64::from_be_bytes(self.take::<8>()?))
    }
    fn finish(self) -> Result<(), PackLError> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(PackLError::InvalidLength {
                expected: self.pos,
                actual: self.bytes.len(),
            })
        }
    }
}

pub fn is_pack_l_message_type(message_type: u16) -> bool {
    matches!(
        message_type,
        MSG_WORKER_HELLO
            | MSG_NODE_CHALLENGE
            | MSG_WORKER_AUTH
            | MSG_NODE_ACCEPT
            | MSG_WORK_ASSIGNMENT
            | MSG_WORK_RESULT
            | MSG_WORK_CANCEL
            | MSG_WORK_REJECT
            | MSG_WORKER_PING
            | MSG_WORKER_PONG
    )
}

pub fn worker_id(network_id: u32, worker_public_key: &[u8; 32]) -> [u8; 32] {
    let network = network_id.to_be_bytes();
    hash_parts(DOMAIN_WORKER_ID, &[&network, worker_public_key])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerHelloV1 {
    pub network_id: u32,
    pub worker_public_key: [u8; 32],
    pub worker_nonce: [u8; 32],
    pub capabilities: u64,
    pub max_parallelism: u16,
}
impl WorkerHelloV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(WORKER_HELLO_LEN);
        push_u16(&mut out, PACK_L_VERSION);
        push_u32(&mut out, self.network_id);
        out.extend_from_slice(&self.worker_public_key);
        out.extend_from_slice(&self.worker_nonce);
        push_u64(&mut out, self.capabilities);
        push_u16(&mut out, self.max_parallelism);
        debug_assert_eq!(out.len(), WORKER_HELLO_LEN);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, PackLError> {
        if bytes.len() != WORKER_HELLO_LEN {
            return Err(PackLError::InvalidLength {
                expected: WORKER_HELLO_LEN,
                actual: bytes.len(),
            });
        }
        let mut r = Reader::new(bytes);
        let version = r.u16()?;
        if version != PACK_L_VERSION {
            return Err(PackLError::InvalidVersion(version));
        }
        let value = Self {
            network_id: r.u32()?,
            worker_public_key: r.take::<32>()?,
            worker_nonce: r.take::<32>()?,
            capabilities: r.u64()?,
            max_parallelism: r.u16()?,
        };
        r.finish()?;
        Ok(value)
    }
    pub fn worker_id(&self) -> [u8; 32] {
        worker_id(self.network_id, &self.worker_public_key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeChallengeV1 {
    pub network_id: u32,
    pub node_id: [u8; 32],
    pub node_public_key: [u8; 32],
    pub worker_id: [u8; 32],
    pub worker_nonce: [u8; 32],
    pub node_nonce: [u8; 32],
    pub capabilities: u64,
}
impl NodeChallengeV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(NODE_CHALLENGE_LEN);
        push_u16(&mut out, PACK_L_VERSION);
        push_u32(&mut out, self.network_id);
        out.extend_from_slice(&self.node_id);
        out.extend_from_slice(&self.node_public_key);
        out.extend_from_slice(&self.worker_id);
        out.extend_from_slice(&self.worker_nonce);
        out.extend_from_slice(&self.node_nonce);
        push_u64(&mut out, self.capabilities);
        debug_assert_eq!(out.len(), NODE_CHALLENGE_LEN);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, PackLError> {
        if bytes.len() != NODE_CHALLENGE_LEN {
            return Err(PackLError::InvalidLength {
                expected: NODE_CHALLENGE_LEN,
                actual: bytes.len(),
            });
        }
        let mut r = Reader::new(bytes);
        let version = r.u16()?;
        if version != PACK_L_VERSION {
            return Err(PackLError::InvalidVersion(version));
        }
        let value = Self {
            network_id: r.u32()?,
            node_id: r.take::<32>()?,
            node_public_key: r.take::<32>()?,
            worker_id: r.take::<32>()?,
            worker_nonce: r.take::<32>()?,
            node_nonce: r.take::<32>()?,
            capabilities: r.u64()?,
        };
        r.finish()?;
        Ok(value)
    }
    pub fn validate_for_hello(&self, hello: &WorkerHelloV1) -> Result<(), PackLError> {
        if self.network_id != hello.network_id {
            return Err(PackLError::InvalidField("challenge NetworkID mismatch"));
        }
        if self.worker_id != hello.worker_id() {
            return Err(PackLError::InvalidField("challenge WorkerID mismatch"));
        }
        if self.worker_nonce != hello.worker_nonce {
            return Err(PackLError::InvalidField("challenge worker_nonce mismatch"));
        }
        Ok(())
    }
}

pub fn worker_auth_message(hello: &WorkerHelloV1, challenge: &NodeChallengeV1) -> Vec<u8> {
    let hello_bytes = hello.encode();
    let challenge_bytes = challenge.encode();
    let mut msg =
        Vec::with_capacity(DOMAIN_WORKER_AUTH.len() + hello_bytes.len() + challenge_bytes.len());
    msg.extend_from_slice(DOMAIN_WORKER_AUTH);
    msg.extend_from_slice(&hello_bytes);
    msg.extend_from_slice(&challenge_bytes);
    msg
}

pub fn sign_worker_auth(
    signing_key: &SigningKey,
    hello: &WorkerHelloV1,
    challenge: &NodeChallengeV1,
) -> [u8; 64] {
    signing_key
        .sign(&worker_auth_message(hello, challenge))
        .to_bytes()
}

pub fn verify_worker_auth(
    worker_public_key: &[u8; 32],
    hello: &WorkerHelloV1,
    challenge: &NodeChallengeV1,
    signature: &[u8; 64],
) -> Result<(), PackLError> {
    challenge.validate_for_hello(hello)?;
    let key =
        VerifyingKey::from_bytes(worker_public_key).map_err(|_| PackLError::InvalidSignature)?;
    key.verify(
        &worker_auth_message(hello, challenge),
        &Signature::from_bytes(signature),
    )
    .map_err(|_| PackLError::InvalidSignature)
}

pub fn node_accept_message(
    hello: &WorkerHelloV1,
    challenge: &NodeChallengeV1,
    worker_signature: &[u8; 64],
) -> Vec<u8> {
    let hello_bytes = hello.encode();
    let challenge_bytes = challenge.encode();
    let mut msg = Vec::with_capacity(
        DOMAIN_NODE_ACCEPT.len()
            + hello_bytes.len()
            + challenge_bytes.len()
            + worker_signature.len(),
    );
    msg.extend_from_slice(DOMAIN_NODE_ACCEPT);
    msg.extend_from_slice(&hello_bytes);
    msg.extend_from_slice(&challenge_bytes);
    msg.extend_from_slice(worker_signature);
    msg
}

pub fn sign_node_accept(
    signing_key: &SigningKey,
    hello: &WorkerHelloV1,
    challenge: &NodeChallengeV1,
    worker_signature: &[u8; 64],
) -> [u8; 64] {
    signing_key
        .sign(&node_accept_message(hello, challenge, worker_signature))
        .to_bytes()
}

pub fn verify_node_accept(
    node_public_key: &[u8; 32],
    hello: &WorkerHelloV1,
    challenge: &NodeChallengeV1,
    worker_signature: &[u8; 64],
    signature: &[u8; 64],
) -> Result<(), PackLError> {
    let key =
        VerifyingKey::from_bytes(node_public_key).map_err(|_| PackLError::InvalidSignature)?;
    key.verify(
        &node_accept_message(hello, challenge, worker_signature),
        &Signature::from_bytes(signature),
    )
    .map_err(|_| PackLError::InvalidSignature)
}

pub fn session_id(
    hello: &WorkerHelloV1,
    challenge: &NodeChallengeV1,
    worker_signature: &[u8; 64],
    node_signature: &[u8; 64],
) -> [u8; 32] {
    let hello_bytes = hello.encode();
    let challenge_bytes = challenge.encode();
    hash_parts(
        DOMAIN_SESSION_ID,
        &[
            &hello_bytes,
            &challenge_bytes,
            worker_signature,
            node_signature,
        ],
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkAssignmentCoreV1 {
    pub network_id: u32,
    pub session_id: [u8; 32],
    pub assignment_sequence: u64,
    pub worker_id: [u8; 32],
    pub node_id: [u8; 32],
    pub parent_block_hash: [u8; 32],
    pub parent_height: u64,
    pub target_epoch: u64,
    pub license_id: [u8; 32],
    pub ticket_index: u16,
    pub work_units_for_epoch: u16,
    pub eligible_license_count: u64,
    pub anchor_entropy: [u8; 32],
    pub target: [u8; 32],
    pub expires_epoch: u64,
    pub algorithm_id: u16,
    pub algorithm_version: u16,
}
impl WorkAssignmentCoreV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(WORK_ASSIGNMENT_CORE_LEN);
        push_u16(&mut out, PACK_L_VERSION);
        push_u32(&mut out, self.network_id);
        out.extend_from_slice(&self.session_id);
        push_u64(&mut out, self.assignment_sequence);
        out.extend_from_slice(&self.worker_id);
        out.extend_from_slice(&self.node_id);
        out.extend_from_slice(&self.parent_block_hash);
        push_u64(&mut out, self.parent_height);
        push_u64(&mut out, self.target_epoch);
        out.extend_from_slice(&self.license_id);
        push_u16(&mut out, self.ticket_index);
        push_u16(&mut out, self.work_units_for_epoch);
        push_u64(&mut out, self.eligible_license_count);
        out.extend_from_slice(&self.anchor_entropy);
        out.extend_from_slice(&self.target);
        push_u64(&mut out, self.expires_epoch);
        push_u16(&mut out, self.algorithm_id);
        push_u16(&mut out, self.algorithm_version);
        debug_assert_eq!(out.len(), WORK_ASSIGNMENT_CORE_LEN);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, PackLError> {
        if bytes.len() != WORK_ASSIGNMENT_CORE_LEN {
            return Err(PackLError::InvalidLength {
                expected: WORK_ASSIGNMENT_CORE_LEN,
                actual: bytes.len(),
            });
        }
        let mut r = Reader::new(bytes);
        let version = r.u16()?;
        if version != PACK_L_VERSION {
            return Err(PackLError::InvalidVersion(version));
        }
        let value = Self {
            network_id: r.u32()?,
            session_id: r.take::<32>()?,
            assignment_sequence: r.u64()?,
            worker_id: r.take::<32>()?,
            node_id: r.take::<32>()?,
            parent_block_hash: r.take::<32>()?,
            parent_height: r.u64()?,
            target_epoch: r.u64()?,
            license_id: r.take::<32>()?,
            ticket_index: r.u16()?,
            work_units_for_epoch: r.u16()?,
            eligible_license_count: r.u64()?,
            anchor_entropy: r.take::<32>()?,
            target: r.take::<32>()?,
            expires_epoch: r.u64()?,
            algorithm_id: r.u16()?,
            algorithm_version: r.u16()?,
        };
        r.finish()?;
        value.validate_shape()?;
        Ok(value)
    }
    pub fn validate_shape(&self) -> Result<(), PackLError> {
        if self.ticket_index >= self.work_units_for_epoch {
            return Err(PackLError::OutOfBudget);
        }
        if self.expires_epoch != self.target_epoch {
            return Err(PackLError::InvalidField(
                "expires_epoch must equal target_epoch",
            ));
        }
        if self.algorithm_id != ALGORITHM_PACK_A_ARGON2ID {
            return Err(PackLError::InvalidField("unknown algorithm_id"));
        }
        if self.algorithm_version != ALGORITHM_PACK_A_ARGON2ID_V1 {
            return Err(PackLError::InvalidField("unknown algorithm_version"));
        }
        Ok(())
    }
    pub fn ticket_key(&self) -> [u8; 32] {
        ticket_key(
            self.network_id,
            &self.parent_block_hash,
            self.target_epoch,
            &self.license_id,
            self.ticket_index,
        )
    }
    pub fn assignment_id(&self) -> [u8; 32] {
        assignment_id(self)
    }
}

pub fn ticket_key(
    network_id: u32,
    parent_block_hash: &[u8; 32],
    target_epoch: u64,
    license_id: &[u8; 32],
    ticket_index: u16,
) -> [u8; 32] {
    let network = network_id.to_be_bytes();
    let epoch = target_epoch.to_be_bytes();
    let ticket = ticket_index.to_be_bytes();
    hash_parts(
        DOMAIN_TICKET_KEY,
        &[&network, parent_block_hash, &epoch, license_id, &ticket],
    )
}

pub fn assignment_id(core: &WorkAssignmentCoreV1) -> [u8; 32] {
    let bytes = core.encode();
    hash_parts(DOMAIN_ASSIGNMENT_ID, &[&bytes])
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkAssignmentV1 {
    pub core: WorkAssignmentCoreV1,
    pub ticket_key: [u8; 32],
    pub assignment_id: [u8; 32],
    pub node_signature: [u8; 64],
}
impl WorkAssignmentV1 {
    pub fn new_signed(
        core: WorkAssignmentCoreV1,
        signing_key: &SigningKey,
    ) -> Result<Self, PackLError> {
        core.validate_shape()?;
        let ticket_key = core.ticket_key();
        let assignment_id = core.assignment_id();
        let node_signature = sign_assignment(signing_key, &core, &ticket_key, &assignment_id);
        Ok(Self {
            core,
            ticket_key,
            assignment_id,
            node_signature,
        })
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(WORK_ASSIGNMENT_LEN);
        out.extend_from_slice(&self.core.encode());
        out.extend_from_slice(&self.ticket_key);
        out.extend_from_slice(&self.assignment_id);
        out.extend_from_slice(&self.node_signature);
        debug_assert_eq!(out.len(), WORK_ASSIGNMENT_LEN);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, PackLError> {
        if bytes.len() != WORK_ASSIGNMENT_LEN {
            return Err(PackLError::InvalidLength {
                expected: WORK_ASSIGNMENT_LEN,
                actual: bytes.len(),
            });
        }
        let core = WorkAssignmentCoreV1::decode(&bytes[..WORK_ASSIGNMENT_CORE_LEN])?;
        let mut r = Reader::new(&bytes[WORK_ASSIGNMENT_CORE_LEN..]);
        let value = Self {
            core,
            ticket_key: r.take::<32>()?,
            assignment_id: r.take::<32>()?,
            node_signature: r.take::<64>()?,
        };
        r.finish()?;
        value.validate_derived()?;
        Ok(value)
    }
    pub fn validate_derived(&self) -> Result<(), PackLError> {
        self.core.validate_shape()?;
        if self.ticket_key != self.core.ticket_key() {
            return Err(PackLError::InvalidField("TicketKey mismatch"));
        }
        if self.assignment_id != self.core.assignment_id() {
            return Err(PackLError::InvalidField("AssignmentID mismatch"));
        }
        Ok(())
    }
    pub fn verify_node_signature(&self, node_public_key: &[u8; 32]) -> Result<(), PackLError> {
        self.validate_derived()?;
        verify_assignment(
            node_public_key,
            &self.core,
            &self.ticket_key,
            &self.assignment_id,
            &self.node_signature,
        )
    }
}

fn assignment_message(
    core: &WorkAssignmentCoreV1,
    ticket_key: &[u8; 32],
    assignment_id: &[u8; 32],
) -> Vec<u8> {
    let core_bytes = core.encode();
    let mut msg = Vec::with_capacity(
        DOMAIN_ASSIGNMENT_SIGNATURE.len()
            + core_bytes.len()
            + ticket_key.len()
            + assignment_id.len(),
    );
    msg.extend_from_slice(DOMAIN_ASSIGNMENT_SIGNATURE);
    msg.extend_from_slice(&core_bytes);
    msg.extend_from_slice(ticket_key);
    msg.extend_from_slice(assignment_id);
    msg
}
pub fn sign_assignment(
    signing_key: &SigningKey,
    core: &WorkAssignmentCoreV1,
    ticket_key: &[u8; 32],
    assignment_id: &[u8; 32],
) -> [u8; 64] {
    signing_key
        .sign(&assignment_message(core, ticket_key, assignment_id))
        .to_bytes()
}
pub fn verify_assignment(
    node_public_key: &[u8; 32],
    core: &WorkAssignmentCoreV1,
    ticket_key: &[u8; 32],
    assignment_id: &[u8; 32],
    signature: &[u8; 64],
) -> Result<(), PackLError> {
    let key =
        VerifyingKey::from_bytes(node_public_key).map_err(|_| PackLError::InvalidSignature)?;
    key.verify(
        &assignment_message(core, ticket_key, assignment_id),
        &Signature::from_bytes(signature),
    )
    .map_err(|_| PackLError::InvalidSignature)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkResultCoreV1 {
    pub network_id: u32,
    pub session_id: [u8; 32],
    pub assignment_id: [u8; 32],
    pub ticket_key: [u8; 32],
    pub worker_id: [u8; 32],
    pub result_kind: u8,
    pub argon2_proof: [u8; 32],
}
impl WorkResultCoreV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(WORK_RESULT_CORE_LEN);
        push_u16(&mut out, PACK_L_VERSION);
        push_u32(&mut out, self.network_id);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.assignment_id);
        out.extend_from_slice(&self.ticket_key);
        out.extend_from_slice(&self.worker_id);
        out.push(self.result_kind);
        out.extend_from_slice(&self.argon2_proof);
        debug_assert_eq!(out.len(), WORK_RESULT_CORE_LEN);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, PackLError> {
        if bytes.len() != WORK_RESULT_CORE_LEN {
            return Err(PackLError::InvalidLength {
                expected: WORK_RESULT_CORE_LEN,
                actual: bytes.len(),
            });
        }
        let mut r = Reader::new(bytes);
        let version = r.u16()?;
        if version != PACK_L_VERSION {
            return Err(PackLError::InvalidVersion(version));
        }
        let value = Self {
            network_id: r.u32()?,
            session_id: r.take::<32>()?,
            assignment_id: r.take::<32>()?,
            ticket_key: r.take::<32>()?,
            worker_id: r.take::<32>()?,
            result_kind: r.u8()?,
            argon2_proof: r.take::<32>()?,
        };
        r.finish()?;
        value.validate_shape()?;
        Ok(value)
    }
    pub fn validate_shape(&self) -> Result<(), PackLError> {
        match self.result_kind {
            RESULT_NO_WIN => {
                if self.argon2_proof != [0u8; 32] {
                    return Err(PackLError::InvalidField("NO_WIN proof must be zero"));
                }
            }
            RESULT_WIN => {}
            _ => return Err(PackLError::InvalidField("unknown result_kind")),
        }
        Ok(())
    }
}

fn result_message(core: &WorkResultCoreV1) -> Vec<u8> {
    let core_bytes = core.encode();
    let mut msg = Vec::with_capacity(DOMAIN_RESULT_SIGNATURE.len() + core_bytes.len());
    msg.extend_from_slice(DOMAIN_RESULT_SIGNATURE);
    msg.extend_from_slice(&core_bytes);
    msg
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkResultV1 {
    pub core: WorkResultCoreV1,
    pub worker_signature: [u8; 64],
}
impl WorkResultV1 {
    pub fn new_signed(
        core: WorkResultCoreV1,
        signing_key: &SigningKey,
    ) -> Result<Self, PackLError> {
        core.validate_shape()?;
        let worker_signature = signing_key.sign(&result_message(&core)).to_bytes();
        Ok(Self {
            core,
            worker_signature,
        })
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(WORK_RESULT_LEN);
        out.extend_from_slice(&self.core.encode());
        out.extend_from_slice(&self.worker_signature);
        debug_assert_eq!(out.len(), WORK_RESULT_LEN);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, PackLError> {
        if bytes.len() != WORK_RESULT_LEN {
            return Err(PackLError::InvalidLength {
                expected: WORK_RESULT_LEN,
                actual: bytes.len(),
            });
        }
        let core = WorkResultCoreV1::decode(&bytes[..WORK_RESULT_CORE_LEN])?;
        let mut r = Reader::new(&bytes[WORK_RESULT_CORE_LEN..]);
        let value = Self {
            core,
            worker_signature: r.take::<64>()?,
        };
        r.finish()?;
        Ok(value)
    }
    pub fn verify_worker_signature(&self, worker_public_key: &[u8; 32]) -> Result<(), PackLError> {
        self.core.validate_shape()?;
        let key = VerifyingKey::from_bytes(worker_public_key)
            .map_err(|_| PackLError::InvalidSignature)?;
        key.verify(
            &result_message(&self.core),
            &Signature::from_bytes(&self.worker_signature),
        )
        .map_err(|_| PackLError::InvalidSignature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkCancelCoreV1 {
    pub network_id: u32,
    pub session_id: [u8; 32],
    pub assignment_id: [u8; 32],
    pub ticket_key: [u8; 32],
    pub reason: u8,
}
impl WorkCancelCoreV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(WORK_CANCEL_CORE_LEN);
        push_u16(&mut out, PACK_L_VERSION);
        push_u32(&mut out, self.network_id);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.assignment_id);
        out.extend_from_slice(&self.ticket_key);
        out.push(self.reason);
        debug_assert_eq!(out.len(), WORK_CANCEL_CORE_LEN);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, PackLError> {
        if bytes.len() != WORK_CANCEL_CORE_LEN {
            return Err(PackLError::InvalidLength {
                expected: WORK_CANCEL_CORE_LEN,
                actual: bytes.len(),
            });
        }
        let mut r = Reader::new(bytes);
        let version = r.u16()?;
        if version != PACK_L_VERSION {
            return Err(PackLError::InvalidVersion(version));
        }
        let value = Self {
            network_id: r.u32()?,
            session_id: r.take::<32>()?,
            assignment_id: r.take::<32>()?,
            ticket_key: r.take::<32>()?,
            reason: r.u8()?,
        };
        r.finish()?;
        if !(1..=7).contains(&value.reason) {
            return Err(PackLError::InvalidField("unknown cancel reason"));
        }
        Ok(value)
    }
}
fn cancel_message(core: &WorkCancelCoreV1) -> Vec<u8> {
    let core_bytes = core.encode();
    let mut msg = Vec::with_capacity(DOMAIN_CANCEL_SIGNATURE.len() + core_bytes.len());
    msg.extend_from_slice(DOMAIN_CANCEL_SIGNATURE);
    msg.extend_from_slice(&core_bytes);
    msg
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkCancelV1 {
    pub core: WorkCancelCoreV1,
    pub node_signature: [u8; 64],
}
impl WorkCancelV1 {
    pub fn new_signed(
        core: WorkCancelCoreV1,
        signing_key: &SigningKey,
    ) -> Result<Self, PackLError> {
        if !(1..=7).contains(&core.reason) {
            return Err(PackLError::InvalidField("unknown cancel reason"));
        }
        let node_signature = signing_key.sign(&cancel_message(&core)).to_bytes();
        Ok(Self {
            core,
            node_signature,
        })
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(WORK_CANCEL_LEN);
        out.extend_from_slice(&self.core.encode());
        out.extend_from_slice(&self.node_signature);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, PackLError> {
        if bytes.len() != WORK_CANCEL_LEN {
            return Err(PackLError::InvalidLength {
                expected: WORK_CANCEL_LEN,
                actual: bytes.len(),
            });
        }
        let core = WorkCancelCoreV1::decode(&bytes[..WORK_CANCEL_CORE_LEN])?;
        let mut r = Reader::new(&bytes[WORK_CANCEL_CORE_LEN..]);
        let value = Self {
            core,
            node_signature: r.take::<64>()?,
        };
        r.finish()?;
        Ok(value)
    }
    pub fn verify_node_signature(&self, node_public_key: &[u8; 32]) -> Result<(), PackLError> {
        let key =
            VerifyingKey::from_bytes(node_public_key).map_err(|_| PackLError::InvalidSignature)?;
        key.verify(
            &cancel_message(&self.core),
            &Signature::from_bytes(&self.node_signature),
        )
        .map_err(|_| PackLError::InvalidSignature)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkRejectV1 {
    pub network_id: u32,
    pub session_id: [u8; 32],
    pub assignment_id: [u8; 32],
    pub rejected_message_type: u16,
    pub reject_code: u16,
}
impl WorkRejectV1 {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(WORK_REJECT_LEN);
        push_u16(&mut out, PACK_L_VERSION);
        push_u32(&mut out, self.network_id);
        out.extend_from_slice(&self.session_id);
        out.extend_from_slice(&self.assignment_id);
        push_u16(&mut out, self.rejected_message_type);
        push_u16(&mut out, self.reject_code);
        out
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, PackLError> {
        if bytes.len() != WORK_REJECT_LEN {
            return Err(PackLError::InvalidLength {
                expected: WORK_REJECT_LEN,
                actual: bytes.len(),
            });
        }
        let mut r = Reader::new(bytes);
        let version = r.u16()?;
        if version != PACK_L_VERSION {
            return Err(PackLError::InvalidVersion(version));
        }
        let value = Self {
            network_id: r.u32()?,
            session_id: r.take::<32>()?,
            assignment_id: r.take::<32>()?,
            rejected_message_type: r.u16()?,
            reject_code: r.u16()?,
        };
        r.finish()?;
        if !(1..=7).contains(&value.reject_code) {
            return Err(PackLError::InvalidField("unknown reject code"));
        }
        Ok(value)
    }
}

/// Local non-consensus unique-ticket accounting primitive.
/// Redundant assignments of an existing TicketKey are allowed.
/// A new unique TicketKey is legal only when its ticket_index is inside [0, W_E).
#[derive(Debug, Clone, Default)]
pub struct TicketBudget {
    keys: std::collections::BTreeSet<[u8; 32]>,
}
impl TicketBudget {
    pub fn reserve(
        &mut self,
        network_id: u32,
        parent_block_hash: &[u8; 32],
        target_epoch: u64,
        license_id: &[u8; 32],
        ticket_index: u16,
        work_units_for_epoch: u16,
    ) -> Result<([u8; 32], bool), PackLError> {
        if ticket_index >= work_units_for_epoch {
            return Err(PackLError::OutOfBudget);
        }
        let key = ticket_key(
            network_id,
            parent_block_hash,
            target_epoch,
            license_id,
            ticket_index,
        );
        let is_new_unique_ticket = self.keys.insert(key);
        Ok((key, is_new_unique_ticket))
    }
    pub fn contains(&self, key: &[u8; 32]) -> bool {
        self.keys.contains(key)
    }
    pub fn unique_ticket_count(&self) -> usize {
        self.keys.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mutiny_p2p::{Frame, P2P_MAGIC_DEVNET};
    use std::io::Read;
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    fn h32(s: &str) -> [u8; 32] {
        hex::decode(s).unwrap().try_into().unwrap()
    }
    fn h64(s: &str) -> [u8; 64] {
        hex::decode(s).unwrap().try_into().unwrap()
    }
    fn signing(s: &str) -> SigningKey {
        SigningKey::from_bytes(&h32(s))
    }

    const WORKER_SEED: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const NODE_SEED: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";
    const WORKER_PK: &str = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
    const NODE_PK: &str = "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7";
    const WORKER_ID: &str = "886b14b3b1e96293fd6bde029cc51595ab5ae61ec00d463647f5031252e2cbb1";
    const HELLO_HEX: &str = "00014d55540303a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f00000000000000010004";
    const CHALLENGE_HEX: &str = "00014d555403295eb148a491cfcab9c4518312ab06a321750671b53f3d53cd2d7e3f48d06ace29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7886b14b3b1e96293fd6bde029cc51595ab5ae61ec00d463647f5031252e2cbb1404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f0000000000000001";
    const WORKER_SIG_HEX: &str = "7f789faa4eb872e303105303fd1b2d982e43396c915255c8189b1db10c3e7ca55e4336500d7729a0092497e8c11d4579d2bbf482f288300c8b449bef15457506";
    const NODE_SIG_HEX: &str = "7c666bdefa1c0bcbe5334fe21567c3a4fa9e04ed6aaea306c78b6cfee46c340af6dff88d0e158fcbf1b45a4ce6c1c87d8d09e671e98d0fbc5062b61b767d0103";
    const SESSION_HEX: &str = "5d104a7d4dd2cf1c712244ace35555e63408363508699ddc6721e809d7d6f86a";
    const ASSIGNMENT_CORE_HEX: &str = "00014d5554035d104a7d4dd2cf1c712244ace35555e63408363508699ddc6721e809d7d6f86a0000000000000001886b14b3b1e96293fd6bde029cc51595ab5ae61ec00d463647f5031252e2cbb1295eb148a491cfcab9c4518312ab06a321750671b53f3d53cd2d7e3f48d06acee37720a83af0dbfbc8b4c54500fa1bd1a7cdec4f71db18dfca907b48a584a82e00000000000003080000000000020003de1e06240de41436762423c7d937901ccbb01d60e416fa8e0ff61c91b2c8ab2e000000020000000000000001808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff000000000002000300010001";
    const TICKET_KEY_HEX: &str = "04dadb484dc5a343f863218e51fb1ec4b10fb23323accea469db53b2c7ed9f02";
    const ASSIGNMENT_ID_HEX: &str =
        "0b896bfa7fe20e56cbab98cd2a7411aee0881b8024dcd457549f3bd0e64734f6";
    const ASSIGNMENT_SIG_HEX: &str = "548925fc582c80289f8aaa3bab7dee9a1a2f9c195630e398ed65268bb0eb74913233205205c57b852e4f15658e68cd256a2b0e59fecf6d5cf3c1a27d50d6a607";
    const ASSIGNMENT_FULL_HEX: &str = "00014d5554035d104a7d4dd2cf1c712244ace35555e63408363508699ddc6721e809d7d6f86a0000000000000001886b14b3b1e96293fd6bde029cc51595ab5ae61ec00d463647f5031252e2cbb1295eb148a491cfcab9c4518312ab06a321750671b53f3d53cd2d7e3f48d06acee37720a83af0dbfbc8b4c54500fa1bd1a7cdec4f71db18dfca907b48a584a82e00000000000003080000000000020003de1e06240de41436762423c7d937901ccbb01d60e416fa8e0ff61c91b2c8ab2e000000020000000000000001808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff00000000000200030001000104dadb484dc5a343f863218e51fb1ec4b10fb23323accea469db53b2c7ed9f020b896bfa7fe20e56cbab98cd2a7411aee0881b8024dcd457549f3bd0e64734f6548925fc582c80289f8aaa3bab7dee9a1a2f9c195630e398ed65268bb0eb74913233205205c57b852e4f15658e68cd256a2b0e59fecf6d5cf3c1a27d50d6a607";
    const NO_WIN_FULL_HEX: &str = "00014d5554035d104a7d4dd2cf1c712244ace35555e63408363508699ddc6721e809d7d6f86a0b896bfa7fe20e56cbab98cd2a7411aee0881b8024dcd457549f3bd0e64734f604dadb484dc5a343f863218e51fb1ec4b10fb23323accea469db53b2c7ed9f02886b14b3b1e96293fd6bde029cc51595ab5ae61ec00d463647f5031252e2cbb1000000000000000000000000000000000000000000000000000000000000000000e4ba95ce0bf5664650be2e5608ec21274a69264d940e2cf1e8eb1ee9009d80aaf34557d9962d5597c1cc540d11e2d3697d685cb66199d97b9a5ff0eac8928a06";
    const FALSE_WIN_FULL_HEX: &str = "00014d5554035d104a7d4dd2cf1c712244ace35555e63408363508699ddc6721e809d7d6f86a0b896bfa7fe20e56cbab98cd2a7411aee0881b8024dcd457549f3bd0e64734f604dadb484dc5a343f863218e51fb1ec4b10fb23323accea469db53b2c7ed9f02886b14b3b1e96293fd6bde029cc51595ab5ae61ec00d463647f5031252e2cbb101aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa25dc5989c407d259ed36eacf2a97c64a512a2a692143646e1ca7b5dafbf0def3019e068e7376beb4d1361e7a9d7aaf69536e60603b6cbb2d80ccc21c0c411907";
    const CANCEL_PAYLOAD_HEX: &str = "00014d5554035d104a7d4dd2cf1c712244ace35555e63408363508699ddc6721e809d7d6f86a0b896bfa7fe20e56cbab98cd2a7411aee0881b8024dcd457549f3bd0e64734f604dadb484dc5a343f863218e51fb1ec4b10fb23323accea469db53b2c7ed9f02014eb6f812693e3f1cb13409177af300164bf354960be7f3e65cbd5170993eac3a7eef5bee7f24db823ca28b38e4619a7cce76dcea2e6b6880cd1bc8a00e816500";
    const REJECT_PAYLOAD_HEX: &str = "00014d5554035d104a7d4dd2cf1c712244ace35555e63408363508699ddc6721e809d7d6f86a0b896bfa7fe20e56cbab98cd2a7411aee0881b8024dcd457549f3bd0e64734f602110001";
    const HELLO_FRAME_HEX: &str = "4d55574400010201000000000050010203040506070817207c0c00014d55540303a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f00000000000000010004";

    fn capture_frame(frame: &Frame) -> Vec<u8> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let reader = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut bytes = Vec::new();
            socket.read_to_end(&mut bytes).unwrap();
            bytes
        });
        let mut client = TcpStream::connect(addr).unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        frame.write_to(&mut client).unwrap();
        client.shutdown(Shutdown::Write).unwrap();
        drop(client);
        reader.join().unwrap()
    }

    #[test]
    fn r2_worker_hello_and_worker_id_exact() {
        let hello = WorkerHelloV1::decode(&hex::decode(HELLO_HEX).unwrap()).unwrap();
        assert_eq!(hello.encode(), hex::decode(HELLO_HEX).unwrap());
        assert_eq!(hello.worker_public_key, h32(WORKER_PK));
        assert_eq!(hello.worker_id(), h32(WORKER_ID));
    }

    #[test]
    fn r2_mutual_auth_and_session_exact() {
        let hello = WorkerHelloV1::decode(&hex::decode(HELLO_HEX).unwrap()).unwrap();
        let challenge = NodeChallengeV1::decode(&hex::decode(CHALLENGE_HEX).unwrap()).unwrap();
        challenge.validate_for_hello(&hello).unwrap();

        let worker = signing(WORKER_SEED);
        let node = signing(NODE_SEED);
        assert_eq!(worker.verifying_key().to_bytes(), h32(WORKER_PK));
        assert_eq!(node.verifying_key().to_bytes(), h32(NODE_PK));

        let wsig = sign_worker_auth(&worker, &hello, &challenge);
        assert_eq!(wsig, h64(WORKER_SIG_HEX));
        verify_worker_auth(&h32(WORKER_PK), &hello, &challenge, &wsig).unwrap();

        let nsig = sign_node_accept(&node, &hello, &challenge, &wsig);
        assert_eq!(nsig, h64(NODE_SIG_HEX));
        verify_node_accept(&h32(NODE_PK), &hello, &challenge, &wsig, &nsig).unwrap();

        assert_eq!(
            session_id(&hello, &challenge, &wsig, &nsig),
            h32(SESSION_HEX)
        );
    }

    #[test]
    fn r2_assignment_exact() {
        let core =
            WorkAssignmentCoreV1::decode(&hex::decode(ASSIGNMENT_CORE_HEX).unwrap()).unwrap();
        assert_eq!(core.encode(), hex::decode(ASSIGNMENT_CORE_HEX).unwrap());
        assert_eq!(core.ticket_key(), h32(TICKET_KEY_HEX));
        assert_eq!(core.assignment_id(), h32(ASSIGNMENT_ID_HEX));

        let assignment =
            WorkAssignmentV1::decode(&hex::decode(ASSIGNMENT_FULL_HEX).unwrap()).unwrap();
        assert_eq!(assignment.ticket_key, h32(TICKET_KEY_HEX));
        assert_eq!(assignment.assignment_id, h32(ASSIGNMENT_ID_HEX));
        assert_eq!(assignment.node_signature, h64(ASSIGNMENT_SIG_HEX));
        assignment.verify_node_signature(&h32(NODE_PK)).unwrap();
        assert_eq!(
            assignment.encode(),
            hex::decode(ASSIGNMENT_FULL_HEX).unwrap()
        );
    }

    #[test]
    fn r2_results_exact_and_false_win_is_only_wire_valid() {
        let no_win = WorkResultV1::decode(&hex::decode(NO_WIN_FULL_HEX).unwrap()).unwrap();
        no_win.verify_worker_signature(&h32(WORKER_PK)).unwrap();
        assert_eq!(no_win.core.result_kind, RESULT_NO_WIN);
        assert_eq!(no_win.core.argon2_proof, [0u8; 32]);

        let false_win = WorkResultV1::decode(&hex::decode(FALSE_WIN_FULL_HEX).unwrap()).unwrap();
        false_win.verify_worker_signature(&h32(WORKER_PK)).unwrap();
        assert_eq!(false_win.core.result_kind, RESULT_WIN);
        assert_eq!(false_win.core.argon2_proof, [0xAA; 32]);

        // Pack L codec/authentication accepting this structure does NOT authorize a block.
        // Frozen Pack-A node-side Argon2id recomputation remains mandatory for every WIN.
    }

    #[test]
    fn r3_cancel_and_reject_exact() {
        let cancel = WorkCancelV1::decode(&hex::decode(CANCEL_PAYLOAD_HEX).unwrap()).unwrap();
        cancel.verify_node_signature(&h32(NODE_PK)).unwrap();
        assert_eq!(cancel.encode(), hex::decode(CANCEL_PAYLOAD_HEX).unwrap());

        let reject = WorkRejectV1::decode(&hex::decode(REJECT_PAYLOAD_HEX).unwrap()).unwrap();
        assert_eq!(reject.encode(), hex::decode(REJECT_PAYLOAD_HEX).unwrap());
    }

    #[test]
    fn r3_exact_frame_reproduction_uses_frozen_pack_h() {
        let hello = hex::decode(HELLO_HEX).unwrap();
        let frame = Frame::new(
            WORKER_MAGIC_DEVNET,
            MSG_WORKER_HELLO,
            0x0102_0304_0506_0708,
            hello,
        )
        .unwrap();
        assert_eq!(capture_frame(&frame), hex::decode(HELLO_FRAME_HEX).unwrap());
    }

    #[test]
    fn worker_registry_is_closed() {
        let allowed = [
            MSG_WORKER_HELLO,
            MSG_NODE_CHALLENGE,
            MSG_WORKER_AUTH,
            MSG_NODE_ACCEPT,
            MSG_WORK_ASSIGNMENT,
            MSG_WORK_RESULT,
            MSG_WORK_CANCEL,
            MSG_WORK_REJECT,
            MSG_WORKER_PING,
            MSG_WORKER_PONG,
        ];
        for t in allowed {
            assert!(is_pack_l_message_type(t));
        }
        assert!(!is_pack_l_message_type(0x0001));
        assert!(!is_pack_l_message_type(0x0100));
        assert!(!is_pack_l_message_type(0xFFFF));
    }

    #[test]
    fn ticket_budget_allows_redundancy_but_zero_new_chances() {
        let assignment =
            WorkAssignmentV1::decode(&hex::decode(ASSIGNMENT_FULL_HEX).unwrap()).unwrap();
        let c = &assignment.core;
        let mut budget = TicketBudget::default();

        let (k1, first) = budget
            .reserve(
                c.network_id,
                &c.parent_block_hash,
                c.target_epoch,
                &c.license_id,
                c.ticket_index,
                c.work_units_for_epoch,
            )
            .unwrap();
        assert!(first);
        assert_eq!(k1, assignment.ticket_key);
        assert_eq!(budget.unique_ticket_count(), 1);

        let (k2, second) = budget
            .reserve(
                c.network_id,
                &c.parent_block_hash,
                c.target_epoch,
                &c.license_id,
                c.ticket_index,
                c.work_units_for_epoch,
            )
            .unwrap();
        assert!(!second);
        assert_eq!(k2, k1);
        assert_eq!(budget.unique_ticket_count(), 1);

        assert_eq!(
            budget.reserve(
                c.network_id,
                &c.parent_block_hash,
                c.target_epoch,
                &c.license_id,
                c.work_units_for_epoch,
                c.work_units_for_epoch,
            ),
            Err(PackLError::OutOfBudget)
        );
        assert_eq!(budget.unique_ticket_count(), 1);
    }

    #[test]
    fn assignment_tamper_rejected_by_derived_ids_or_signature() {
        let mut bytes = hex::decode(ASSIGNMENT_FULL_HEX).unwrap();
        // Mutate target_epoch inside core.
        let target_epoch_offset = 2 + 4 + 32 + 8 + 32 + 32 + 32 + 8;
        bytes[target_epoch_offset + 7] ^= 0x01;
        assert!(WorkAssignmentV1::decode(&bytes).is_err());
    }

    #[test]
    fn no_win_nonzero_proof_is_rejected() {
        let mut result = WorkResultV1::decode(&hex::decode(NO_WIN_FULL_HEX).unwrap()).unwrap();
        result.core.argon2_proof[31] = 1;
        assert_eq!(
            result.core.validate_shape(),
            Err(PackLError::InvalidField("NO_WIN proof must be zero"))
        );
    }

    #[test]
    fn pack_l_magic_is_disjoint_from_pack_h_devnet() {
        assert_ne!(WORKER_MAGIC_DEVNET, P2P_MAGIC_DEVNET);
    }
}
