//! Worker/coordinator transport authentication. This grants no PoW, quorum,
//! license assignment, or canonical state authority. Callers pin active bindings.
use crate::{Error, Hash, NETWORK_ID, Result, domain_hash, licenses::BindWorker};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
pub const TRANSCRIPT_BYTES: usize = 237;
pub fn transcript(
    binding: &BindWorker,
    worker_nonce: Hash,
    coordinator_nonce: Hash,
) -> Result<[u8; TRANSCRIPT_BYTES]> {
    if worker_nonce == [0; 32]
        || coordinator_nonce == [0; 32]
        || worker_nonce == coordinator_nonce
        || binding.network != NETWORK_ID
        || binding.sequence == 0
        || binding.worker != binding.worker_id()
    {
        return Err(Error::WrongAnchor);
    }
    let mut raw = Vec::with_capacity(TRANSCRIPT_BYTES);
    raw.push(1);
    raw.extend(NETWORK_ID.to_be_bytes());
    for field in [
        binding.genesis,
        binding.fingerprint,
        binding.license,
        binding.worker,
    ] {
        raw.extend(field);
    }
    raw.extend(binding.sequence.to_be_bytes());
    raw.extend(binding.coordinator_public);
    raw.extend(worker_nonce);
    raw.extend(coordinator_nonce);
    raw.try_into().map_err(|_| Error::Codec)
}
pub fn coordinator_digest(raw: &[u8; TRANSCRIPT_BYTES]) -> Hash {
    domain_hash(b"MUTINY-BUILD8-WORKER-SESSION-COORDINATOR-V1", raw)
}
pub fn worker_digest(raw: &[u8; TRANSCRIPT_BYTES]) -> Hash {
    domain_hash(b"MUTINY-BUILD8-WORKER-SESSION-POSSESSION-V1", raw)
}
pub fn session_id(raw: &[u8; TRANSCRIPT_BYTES]) -> Hash {
    domain_hash(b"MUTINY-BUILD8-WORKER-SESSION-ID-V1", raw)
}
pub struct PendingSession {
    binding: BindWorker,
    raw: [u8; TRANSCRIPT_BYTES],
    signature: [u8; 64],
    consumed: bool,
}
#[derive(Debug, Clone)]
pub struct AuthenticatedSession {
    pub id: Hash,
    binding: BindWorker,
}
impl PendingSession {
    /// Nonces must originate from the device and coordinator CSPRNGs. This
    /// deterministic codec cannot substitute for caller entropy or rate limits.
    pub fn issue(
        active: &BindWorker,
        coordinator: &SigningKey,
        worker_nonce: Hash,
        coordinator_nonce: Hash,
    ) -> Result<Self> {
        if coordinator.verifying_key().to_bytes() != active.coordinator_public {
            return Err(Error::UnknownSigner);
        }
        let raw = transcript(active, worker_nonce, coordinator_nonce)?;
        let signature = coordinator.sign(&coordinator_digest(&raw)).to_bytes();
        Ok(Self {
            binding: active.clone(),
            raw,
            signature,
            consumed: false,
        })
    }
    pub fn challenge(&self) -> (&[u8; TRANSCRIPT_BYTES], &[u8; 64]) {
        (&self.raw, &self.signature)
    }
    pub fn finish(
        &mut self,
        current: &BindWorker,
        signature: [u8; 64],
    ) -> Result<AuthenticatedSession> {
        if self.consumed {
            return Err(Error::Duplicate);
        }
        // One attempt per challenge; a new connection must obtain a new nonce.
        self.consumed = true;
        if current != &self.binding {
            return Err(Error::WrongGeneration);
        }
        VerifyingKey::from_bytes(&self.binding.worker_public)
            .map_err(|_| Error::BadSignature)?
            .verify_strict(
                &worker_digest(&self.raw),
                &Signature::from_bytes(&signature),
            )
            .map_err(|_| Error::BadSignature)?;
        Ok(AuthenticatedSession {
            id: session_id(&self.raw),
            binding: self.binding.clone(),
        })
    }
}
impl AuthenticatedSession {
    /// Parent/candidate churn is irrelevant; reassignment/key/context changes
    /// invalidate the session against the latest canonical active binding.
    pub fn authorizes(&self, current: &BindWorker) -> bool {
        current == &self.binding
    }
}

pub const FRAME_HEADER_BYTES: usize = 44;
pub const MAX_FRAME_PAYLOAD: usize = 4096;
pub const MAX_FRAME_BYTES: usize = FRAME_HEADER_BYTES + MAX_FRAME_PAYLOAD + 64;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Role {
    Worker = 0,
    Coordinator = 1,
}
pub fn frame_digest(raw: &[u8]) -> Hash {
    domain_hash(b"MUTINY-BUILD8-WORKER-SESSION-FRAME-V1", raw)
}
/// Per-connection transport state. Any invalid frame poisons this channel;
/// callers reconnect with fresh nonces, retaining operator intent separately.
pub struct FrameChannel {
    session: AuthenticatedSession,
    role: Role,
    send_next: u64,
    receive_next: u64,
    valid: bool,
}
impl FrameChannel {
    pub fn new(session: AuthenticatedSession, role: Role) -> Self {
        Self {
            session,
            role,
            send_next: 1,
            receive_next: 1,
            valid: true,
        }
    }
    pub fn authorizes(&self, current: &BindWorker) -> bool {
        self.valid && self.session.authorizes(current)
    }
    fn key(&self, role: Role) -> Hash {
        match role {
            Role::Worker => self.session.binding.worker_public,
            Role::Coordinator => self.session.binding.coordinator_public,
        }
    }
    pub fn send(&mut self, signer: &SigningKey, payload: &[u8]) -> Result<Vec<u8>> {
        let ready = self.valid;
        self.valid = false;
        if !ready
            || payload.is_empty()
            || payload.len() > MAX_FRAME_PAYLOAD
            || self.send_next == u64::MAX
            || signer.verifying_key().to_bytes() != self.key(self.role)
        {
            return Err(Error::Codec);
        }
        let mut raw = Vec::with_capacity(FRAME_HEADER_BYTES + payload.len() + 64);
        raw.push(1);
        raw.extend(self.session.id);
        raw.push(self.role as u8);
        raw.extend(self.send_next.to_be_bytes());
        raw.extend((payload.len() as u16).to_be_bytes());
        raw.extend(payload);
        raw.extend(signer.sign(&frame_digest(&raw)).to_bytes());
        self.send_next += 1;
        self.valid = true;
        Ok(raw)
    }
    pub fn receive<'a>(&mut self, raw: &'a [u8]) -> Result<&'a [u8]> {
        let ready = self.valid;
        self.valid = false;
        if !ready
            || raw.len() < FRAME_HEADER_BYTES + 65
            || raw.len() > MAX_FRAME_BYTES
            || self.receive_next == u64::MAX
        {
            return Err(Error::Codec);
        }
        let peer = match self.role {
            Role::Worker => Role::Coordinator,
            Role::Coordinator => Role::Worker,
        };
        let length = u16::from_be_bytes(raw[42..44].try_into().map_err(|_| Error::Codec)?) as usize;
        let sequence = u64::from_be_bytes(raw[34..42].try_into().map_err(|_| Error::Codec)?);
        if raw[0] != 1
            || raw[1..33] != self.session.id
            || raw[33] != peer as u8
            || sequence != self.receive_next
            || length == 0
            || length > MAX_FRAME_PAYLOAD
            || raw.len() != FRAME_HEADER_BYTES + length + 64
        {
            return Err(Error::Codec);
        }
        let signed = &raw[..FRAME_HEADER_BYTES + length];
        let signature =
            Signature::from_slice(&raw[signed.len()..]).map_err(|_| Error::BadSignature)?;
        VerifyingKey::from_bytes(&self.key(peer))
            .map_err(|_| Error::BadSignature)?
            .verify_strict(&frame_digest(signed), &signature)
            .map_err(|_| Error::BadSignature)?;
        self.receive_next += 1;
        self.valid = true;
        Ok(&raw[FRAME_HEADER_BYTES..signed.len()])
    }
}
