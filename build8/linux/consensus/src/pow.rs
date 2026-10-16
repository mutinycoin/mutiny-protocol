//! Build8 post-Genesis work codec and integer timing/target rules.
//! These checks do not replace UTXO execution or Continuity certification.
use crate::{Error, Hash, NETWORK_ID, Result, domain_hash};
use ed25519_dalek::{Signature, VerifyingKey};
use minicbor::{Decoder, Encoder};
use primitive_types::{U256, U512};
use sha2::{Digest, Sha256};

pub const WORK_DOMAIN: &[u8] = b"MUTINY-BUILD8-WORK-V1";
pub const AUTH_DOMAIN: &[u8] = b"MUTINY-BUILD8-WORK-AUTHORITY-V1";
pub const BLOCK_DOMAIN: &[u8] = b"MUTINY-BUILD8-BLOCK-V1";
pub const MAX_HEADER_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub network: u32,
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub parent: Hash,
    pub height: u64,
    pub timestamp: u64,
    pub body_root: Hash,
    pub state_root: Hash,
    pub license: Hash,
    pub worker: Hash,
    pub target: Hash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkHeader {
    pub candidate: Candidate,
    pub authority: Hash,
    pub nonce: u64,
}

fn bytes32(d: &mut Decoder<'_>) -> std::result::Result<Hash, minicbor::decode::Error> {
    d.bytes()?
        .try_into()
        .map_err(|_| minicbor::decode::Error::message("32 bytes required"))
}
fn nonce64(d: &mut Decoder<'_>) -> std::result::Result<u64, minicbor::decode::Error> {
    let b: [u8; 8] = d
        .bytes()?
        .try_into()
        .map_err(|_| minicbor::decode::Error::message("8 bytes required"))?;
    Ok(u64::from_be_bytes(b))
}
fn encode_context(e: &mut Encoder<Vec<u8>>, c: &Candidate) {
    e.u8(1)
        .unwrap()
        .u32(c.network)
        .unwrap()
        .bytes(&c.genesis)
        .unwrap()
        .bytes(&c.fingerprint)
        .unwrap()
        .bytes(&c.parent)
        .unwrap()
        .u64(c.height)
        .unwrap()
        .u64(c.timestamp)
        .unwrap()
        .bytes(&c.body_root)
        .unwrap()
        .bytes(&c.state_root)
        .unwrap()
        .bytes(&c.license)
        .unwrap()
        .bytes(&c.worker)
        .unwrap();
}
fn decode_context(d: &mut Decoder<'_>) -> std::result::Result<Candidate, minicbor::decode::Error> {
    if d.u8()? != 1 {
        return Err(minicbor::decode::Error::message("version"));
    }
    Ok(Candidate {
        network: d.u32()?,
        genesis: bytes32(d)?,
        fingerprint: bytes32(d)?,
        parent: bytes32(d)?,
        height: d.u64()?,
        timestamp: d.u64()?,
        body_root: bytes32(d)?,
        state_root: bytes32(d)?,
        license: bytes32(d)?,
        worker: bytes32(d)?,
        target: [0; 32],
    })
}
impl WorkHeader {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(14).unwrap();
        encode_context(&mut e, &self.candidate);
        e.bytes(&self.authority)
            .unwrap()
            .bytes(&self.candidate.target)
            .unwrap()
            .bytes(&self.nonce.to_be_bytes())
            .unwrap();
        e.into_writer()
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_HEADER_BYTES {
            return Err(Error::Oversize);
        }
        let mut d = Decoder::new(raw);
        let h = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            if d.array()? != Some(14) {
                return Err(minicbor::decode::Error::message("header"));
            }
            let mut candidate = decode_context(&mut d)?;
            let authority = bytes32(&mut d)?;
            candidate.target = bytes32(&mut d)?;
            Ok(Self {
                candidate,
                authority,
                nonce: nonce64(&mut d)?,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if d.position() != raw.len() || h.encode() != raw {
            return Err(Error::NonCanonical);
        }
        Ok(h)
    }
    pub fn work_bytes(&self) -> Vec<u8> {
        let mut b = WORK_DOMAIN.to_vec();
        b.push(0);
        b.extend(self.encode());
        b
    }
    pub fn digest(&self) -> Hash {
        sha256d(&self.work_bytes())
    }
    pub fn block_hash(&self) -> Hash {
        domain_hash(BLOCK_DOMAIN, &self.encode())
    }
    pub fn nonce_offset(&self) -> usize {
        self.work_bytes().len() - 8
    }
    /// None is exhaustion: never wrap into a previously searched nonce.
    pub fn next_nonce(&self, end: u64) -> Option<u64> {
        self.nonce.checked_add(1).filter(|n| *n <= end)
    }
}
pub fn sha256d(bytes: &[u8]) -> Hash {
    Sha256::digest(Sha256::digest(bytes)).into()
}
pub fn meets_target(digest: &Hash, target: &Hash) -> bool {
    target.iter().any(|x| *x != 0) && digest <= target // Equal-width BE lexicographic comparison.
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkAuthority {
    pub candidate: Candidate,
    pub assignment_sequence: u64,
    pub ticket_sequence: u64,
    pub coordinator: Hash,
    pub nonce_start: u64,
    pub nonce_end: u64,
    pub epoch: u64,
}
impl WorkAuthority {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(18).unwrap();
        encode_context(&mut e, &self.candidate);
        e.u64(self.assignment_sequence)
            .unwrap()
            .u64(self.ticket_sequence)
            .unwrap()
            .bytes(&self.coordinator)
            .unwrap()
            .bytes(&self.candidate.target)
            .unwrap()
            .bytes(&self.nonce_start.to_be_bytes())
            .unwrap()
            .bytes(&self.nonce_end.to_be_bytes())
            .unwrap()
            .u64(self.epoch)
            .unwrap();
        e.into_writer()
    }
    pub fn id(&self) -> Hash {
        domain_hash(AUTH_DOMAIN, &self.encode())
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 1024 {
            return Err(Error::Oversize);
        }
        let mut d = Decoder::new(raw);
        let a = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            if d.array()? != Some(18) {
                return Err(minicbor::decode::Error::message("authority"));
            }
            let mut candidate = decode_context(&mut d)?;
            let assignment_sequence = d.u64()?;
            let ticket_sequence = d.u64()?;
            let coordinator = bytes32(&mut d)?;
            candidate.target = bytes32(&mut d)?;
            Ok(Self {
                candidate,
                assignment_sequence,
                ticket_sequence,
                coordinator,
                nonce_start: nonce64(&mut d)?,
                nonce_end: nonce64(&mut d)?,
                epoch: d.u64()?,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if d.position() != raw.len() || a.encode() != raw {
            return Err(Error::NonCanonical);
        }
        Ok(a)
    }
    pub fn envelope(&self, signature: &[u8; 64]) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(2)
            .unwrap()
            .bytes(&self.encode())
            .unwrap()
            .bytes(signature)
            .unwrap();
        e.into_writer()
    }
    pub fn from_envelope(raw: &[u8]) -> Result<(Self, [u8; 64])> {
        if raw.len() > 1152 {
            return Err(Error::Oversize);
        }
        let mut d = Decoder::new(raw);
        if d.array().map_err(|_| Error::Codec)? != Some(2) {
            return Err(Error::Codec);
        }
        let a = Self::decode(d.bytes().map_err(|_| Error::Codec)?)?;
        let s: [u8; 64] = d
            .bytes()
            .map_err(|_| Error::Codec)?
            .try_into()
            .map_err(|_| Error::Codec)?;
        if d.position() != raw.len() || a.envelope(&s) != raw {
            return Err(Error::NonCanonical);
        }
        Ok((a, s))
    }
}

/// Derived from a validated committed parent, never from the untrusted ticket.
pub struct WorkContext {
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub parent: Hash,
    pub parent_height: u64,
    pub t0: u64,
    pub target: Hash,
    pub license: Hash,
    pub worker: Hash,
    pub coordinator: Hash,
    pub assignment_sequence: u64,
    pub last_accepted_ticket: u64,
    pub ancestor_timestamps: Vec<u64>,
}
pub fn validate_authority(
    h: &WorkHeader,
    a: &WorkAuthority,
    sig: &[u8; 64],
    ctx: &WorkContext,
) -> Result<()> {
    validate_authority_fields(h, a, a.id(), ctx)?;
    VerifyingKey::from_bytes(&ctx.coordinator)
        .map_err(|_| Error::BadSignature)?
        .verify_strict(&a.id(), &Signature::from_bytes(sig))
        .map_err(|_| Error::BadSignature)
}
/// Shared non-cryptographic work rules. The V2 caller supplies its separately
/// domain-separated authority identity, then verifies its dedicated node suite.
pub(crate) fn validate_authority_fields(
    h: &WorkHeader, a: &WorkAuthority, authority_id: Hash, ctx: &WorkContext,
) -> Result<()> {
    let c = &h.candidate;
    if c.network != NETWORK_ID {
        return Err(Error::WrongNetwork);
    }
    if c.genesis != ctx.genesis {
        return Err(Error::WrongGenesis);
    }
    if c.fingerprint != ctx.fingerprint {
        return Err(Error::WrongFingerprint);
    }
    if c.parent != ctx.parent
        || c.height != ctx.parent_height.checked_add(1).ok_or(Error::Overflow)?
        || c.height == 0
        || c.license != ctx.license
        || c.worker != ctx.worker
        || c.target != ctx.target
        || a.candidate != *c
        || authority_id != h.authority
        || a.coordinator != ctx.coordinator
    {
        return Err(Error::WrongAnchor);
    }
    if a.assignment_sequence != ctx.assignment_sequence
        || a.ticket_sequence <= ctx.last_accepted_ticket
    {
        return Err(Error::StaleSequence);
    }
    if a.nonce_start > a.nonce_end
        || h.nonce < a.nonce_start
        || h.nonce > a.nonce_end
        || a.epoch != mining_epoch(c.timestamp, ctx.t0)?
    {
        return Err(Error::InvalidCounter);
    }
    validate_timestamp(c.height, c.timestamp, ctx.t0, &ctx.ancestor_timestamps)?;
    if c.target == [0; 32] {
        return Err(Error::InvalidCounter);
    }
    Ok(())
}
pub fn mining_epoch(timestamp: u64, t0: u64) -> Result<u64> {
    Ok(timestamp.checked_sub(t0).ok_or(Error::InvalidCounter)? / 60)
}
/// Enforces, at every place a store builds an ancestor window, the condition under which the
/// consensus rule "timestamp >= window maximum" is exactly "timestamp >= parent timestamp": the
/// window must contain the actual parent, whose timestamp the store knows independently from its
/// own parent row, and must not contain anything later. On a chain built under `validate_timestamp`
/// the parent's timestamp is the window maximum regardless of window order. A window whose maximum
/// differs from the parent's timestamp (a missing or wrong parent row, a descendant row, or a
/// chain that contains a regressing timestamp) must fail closed rather than weaken validation.
pub fn window_ends_at_parent(window: &[u64], parent_timestamp: u64) -> bool {
    window.iter().copied().max() == Some(parent_timestamp)
}
/// Consensus timestamp rules, deterministic and clock-independent (no wall-clock input exists).
/// 1. Median-time-past: strictly greater than the median of the ancestor window (the upper
///    middle item for even early-chain counts). Genesis has no MTP check.
/// 2. Nondecreasing: a block's timestamp must not precede its parent's. The window always
///    contains the parent, and every block in it was itself admitted under this rule, so the
///    parent's timestamp is the window maximum and window order is not part of the interface.
/// There is no wall-clock bound in either direction. Whether this validator is willing to SIGN a
/// block vote for a timestamp is a separate local qualified-clock decision (`vote_clock_v1`).
pub fn validate_timestamp(height: u64, timestamp: u64, t0: u64, ancestors: &[u64]) -> Result<()> {
    if height == 0 {
        return if timestamp == t0 && ancestors.is_empty() {
            Ok(())
        } else {
            Err(Error::InvalidCounter)
        };
    }
    mining_epoch(timestamp, t0)?;
    if ancestors.len() != height.min(11) as usize {
        return Err(Error::InvalidCounter);
    }
    let mut sorted = ancestors.to_vec();
    sorted.sort_unstable();
    if timestamp <= sorted[sorted.len() / 2] {
        return Err(Error::InvalidCounter);
    }
    // `sorted` is non-empty here: height >= 1 implies len == min(height, 11) >= 1.
    if timestamp < sorted[sorted.len() - 1] {
        return Err(Error::InvalidCounter);
    }
    Ok(())
}
pub fn retarget(old: Hash, start: u64, end: u64) -> Result<Hash> {
    if old == [0; 32] {
        return Err(Error::InvalidCounter);
    }
    let span = (i128::from(end) - i128::from(start)).clamp(900, 14400) as u64;
    let wide = U512::from(U256::from_big_endian(&old)) * U512::from(span) / U512::from(3600);
    let next = wide
        .max(U512::one())
        .min(U512::from(U256::MAX))
        .to_big_endian();
    Ok(next[32..].try_into().unwrap())
}
pub fn target_after_height(height: u64, old: Hash, start: u64, end: u64) -> Result<Hash> {
    if old == [0; 32] {
        return Err(Error::InvalidCounter);
    }
    if height > 0 && height.is_multiple_of(60) {
        retarget(old, start, end)
    } else {
        Ok(old)
    }
}
