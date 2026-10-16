//! Hybrid Continuity evidence candidate. Trusted parent registry inputs are
//! mandatory; possession of software keys does not establish physical admission.
use crate::{
    Error, Hash, NETWORK_ID, Result, anchors::FinalizedAnchor, certificates::Decision, domain_hash,
};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, PublicKey, Role};
use primitive_types::U256;
use std::collections::{BTreeMap, BTreeSet};
pub const SUITE_ID: u16 = 1;
pub const MAX_VOTERS: usize = 1024;
// Derived conservative upper bound: <=1630 encoded bytes per signer, plus
// <=2048 shared decision/container bytes. Not yet the activated runtime bound.
pub const MAX_CERTIFICATE_BYTES: usize = MAX_VOTERS * 1630 + 2048;
pub const MAX_VOTE_BYTES: usize = 4096;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParentVoter {
    pub lineage: Hash,
    pub admitted: bool,
    pub physical: bool,
    pub eligible: bool,
    pub revoked: bool,
    pub hardware_generation: u64,
    pub key_generation: u64,
    pub tpm_public: [u8; 33],
    pub profile: Hash,
    pub public: PublicKey,
    pub reputation: U256,
}
impl ParentVoter {
    pub fn tpm_identity(&self) -> Hash {
        domain_hash(b"MUTINY-BUILD8-TPM-IDENTITY-V2", &self.tpm_public)
    }
    pub fn weight(&self) -> Result<U256> {
        if !self.admitted || !self.physical || !self.eligible || self.revoked {
            return Ok(U256::zero());
        }
        if self.hardware_generation == 0
            || self.lineage == [0; 32]
            || self.key_generation == 0
            || self.profile == [0; 32]
            || self.public.role != Role::Continuity
        {
            return Err(Error::UnqualifiedPhysical);
        }
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.tpm_public)
            .map_err(|_| Error::UnqualifiedPhysical)?;
        self.public.validate().map_err(|_| Error::BadSignature)?;
        Ok(self.reputation)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vote {
    pub decision: Decision,
    pub nil: bool,
    pub node: Hash,
    pub hardware_generation: u64,
    pub key_generation: u64,
    pub sequence: u64,
    pub tpm_identity: Hash,
    pub profile: Hash,
    pub signature: HybridSignature,
}
impl Vote {
    pub fn unsigned(&self) -> Result<Vec<u8>> {
        if self.sequence == 0
            || self.hardware_generation == 0
            || self.key_generation == 0
            || self.node == [0; 32]
            || self.tpm_identity == [0; 32]
            || self.profile == [0; 32]
        {
            return Err(Error::InvalidCounter);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(10)
            .unwrap()
            .u8(2)
            .unwrap()
            .u16(SUITE_ID)
            .unwrap()
            .bool(self.nil)
            .unwrap()
            .bytes(&self.decision.encode())
            .unwrap()
            .bytes(&self.node)
            .unwrap()
            .u64(self.hardware_generation)
            .unwrap()
            .u64(self.key_generation)
            .unwrap()
            .u64(self.sequence)
            .unwrap()
            .bytes(&self.tpm_identity)
            .unwrap()
            .bytes(&self.profile)
            .unwrap();
        Ok(e.into_writer())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(3)
            .unwrap()
            .bytes(&self.unsigned()?)
            .unwrap()
            .bytes(&self.signature.ed448)
            .unwrap()
            .bytes(&self.signature.fndsa)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_VOTE_BYTES {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn sign(&mut self, key: &HybridKey) -> Result<()> {
        if key.public().role != Role::Continuity {
            return Err(Error::BadSignature);
        }
        self.signature = key
            .sign(Domain::ContinuityVote, &self.unsigned()?)
            .map_err(|_| Error::BadSignature)?;
        Ok(())
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_VOTE_BYTES)?;
        let mut d = Decoder::new(raw);
        array(&mut d, 3)?;
        let body = d.bytes().map_err(|_| Error::Codec)?;
        let signature = HybridSignature {
            ed448: fixed(&mut d)?,
            fndsa: fixed(&mut d)?,
        };
        let mut b = Decoder::new(body);
        array(&mut b, 10)?;
        if b.u8().map_err(|_| Error::Codec)? != 2 || b.u16().map_err(|_| Error::Codec)? != SUITE_ID
        {
            return Err(Error::Codec);
        }
        let vote = Self {
            nil: b.bool().map_err(|_| Error::Codec)?,
            decision: Decision::decode(b.bytes().map_err(|_| Error::Codec)?)?,
            node: fixed(&mut b)?,
            hardware_generation: b.u64().map_err(|_| Error::Codec)?,
            key_generation: b.u64().map_err(|_| Error::Codec)?,
            sequence: b.u64().map_err(|_| Error::Codec)?,
            tpm_identity: fixed(&mut b)?,
            profile: fixed(&mut b)?,
            signature,
        };
        if b.position() != body.len() || d.position() != raw.len() || vote.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(vote)
    }
    /// This validates historical signed context/authority, not candidate execution.
    /// Live BFT ingress must additionally validate executed proposal and locks.
    pub fn verify(
        &self,
        parent: &FinalizedAnchor,
        roots: [Hash; 3],
        registry: &BTreeMap<Hash, ParentVoter>,
    ) -> Result<U256> {
        let weight = self.validate_authority(parent, roots, registry)?;
        registry.get(&self.node).ok_or(Error::UnknownSigner)?.public
            .verify(Domain::ContinuityVote, &self.unsigned()?, &self.signature)
            .map_err(|_| Error::BadSignature)?;
        Ok(weight)
    }
    /// Context validation for an unsigned durable reservation. This is NOT a
    /// signature verifier and cannot supply authenticated BFT input.
    pub(crate) fn validate_authority(
        &self,
        parent: &FinalizedAnchor,
        roots: [Hash; 3],
        registry: &BTreeMap<Hash, ParentVoter>,
    ) -> Result<U256> {
        self.unsigned()?;
        let d = &self.decision;
        d.verify_parent(parent)?;
        if d.network != NETWORK_ID
            || d.purpose != 2
            || !matches!(d.step, 2 | 3)
            || d.continuity_period != (d.height - 1) / 60
            || [d.membership, d.reputation, d.attestation] != roots
        {
            return Err(Error::WrongAnchor);
        }
        if self.nil {
            if d.block != [0; 32] || d.state != [0; 32] || d.mining_epoch != 0 {
                return Err(Error::NonCanonical);
            }
        } else if d.block == [0; 32] || d.state == [0; 32] {
            return Err(Error::NonCanonical);
        }
        let voter = registry.get(&self.node).ok_or(Error::UnknownSigner)?;
        let weight = voter.weight()?;
        if weight.is_zero() {
            return Err(Error::UnqualifiedPhysical);
        }
        if self.hardware_generation != voter.hardware_generation
            || self.key_generation != voter.key_generation
        {
            return Err(Error::WrongGeneration);
        }
        if self.tpm_identity != voter.tpm_identity() || self.profile != voter.profile {
            return Err(Error::UnqualifiedPhysical);
        }
        Ok(weight)
    }
}
fn array(d: &mut Decoder<'_>, n: u64) -> Result<()> {
    if d.array().map_err(|_| Error::Codec)? != Some(n) {
        return Err(Error::Codec);
    }
    Ok(())
}
fn fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N]> {
    d.bytes()
        .map_err(|_| Error::Codec)?
        .try_into()
        .map_err(|_| Error::Codec)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub decision: Decision,
    pub votes: Vec<Vote>,
}
impl Certificate {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.votes.is_empty() || self.votes.len() > MAX_VOTERS {
            return Err(Error::Capacity);
        }
        let decision = self.decision.encode();
        if decision.len() > 1024 {
            return Err(Error::Oversize);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(3)
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(&decision)
            .unwrap()
            .array(self.votes.len() as u64)
            .unwrap();
        let mut prior = None;
        for v in &self.votes {
            if v.nil || v.decision != self.decision {
                return Err(Error::WrongAnchor);
            }
            v.unsigned()?;
            if prior.is_some_and(|p| p >= v.node) {
                return Err(Error::Duplicate);
            }
            prior = Some(v.node);
            e.array(8)
                .unwrap()
                .bytes(&v.node)
                .unwrap()
                .u64(v.hardware_generation)
                .unwrap()
                .u64(v.key_generation)
                .unwrap()
                .u64(v.sequence)
                .unwrap()
                .bytes(&v.tpm_identity)
                .unwrap()
                .bytes(&v.profile)
                .unwrap()
                .bytes(&v.signature.ed448)
                .unwrap()
                .bytes(&v.signature.fndsa)
                .unwrap();
        }
        let raw = e.into_writer();
        if raw.len() > MAX_CERTIFICATE_BYTES {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_CERTIFICATE_BYTES)?;
        let mut d = Decoder::new(raw);
        array(&mut d, 3)?;
        if d.u8().map_err(|_| Error::Codec)? != 2 {
            return Err(Error::Codec);
        }
        let decision = Decision::decode(d.bytes().map_err(|_| Error::Codec)?)?;
        let n = d.array().map_err(|_| Error::Codec)?.ok_or(Error::Codec)?;
        if n == 0 || n > MAX_VOTERS as u64 {
            return Err(Error::Capacity);
        }
        let mut votes = Vec::with_capacity(n as usize);
        for _ in 0..n {
            array(&mut d, 8)?;
            votes.push(Vote {
                decision: decision.clone(),
                nil: false,
                node: fixed(&mut d)?,
                hardware_generation: d.u64().map_err(|_| Error::Codec)?,
                key_generation: d.u64().map_err(|_| Error::Codec)?,
                sequence: d.u64().map_err(|_| Error::Codec)?,
                tpm_identity: fixed(&mut d)?,
                profile: fixed(&mut d)?,
                signature: HybridSignature {
                    ed448: fixed(&mut d)?,
                    fndsa: fixed(&mut d)?,
                },
            });
        }
        let c = Self { decision, votes };
        if d.position() != raw.len() || c.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(c)
    }
    pub fn verify_quorum(
        &self,
        expected: &Decision,
        parent: &FinalizedAnchor,
        registry: &BTreeMap<Hash, ParentVoter>,
    ) -> Result<()> {
        if &self.decision != expected || expected.purpose != 2 || expected.step != 3 {
            return Err(Error::WrongAnchor);
        }
        self.encode()?;
        if registry.len() > MAX_VOTERS {
            return Err(Error::Capacity);
        }
        let mut total = U256::zero();
        let (mut ed, mut pq, mut tpm, mut lineages) = (
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        );
        for v in registry.values() {
            let w = v.weight()?;
            if w.is_zero() {
                continue;
            }
            if !ed.insert(v.public.ed448)
                || !pq.insert(v.public.fndsa)
                || !tpm.insert(v.tpm_public)
                || !lineages.insert(v.lineage)
            {
                return Err(Error::Duplicate);
            }
            total = total.checked_add(w).ok_or(Error::Overflow)?;
        }
        if total.is_zero() {
            return Err(Error::NoQuorum);
        }
        let mut signed = U256::zero();
        for v in &self.votes {
            signed = signed
                .checked_add(v.verify(
                    parent,
                    [
                        expected.membership,
                        expected.reputation,
                        expected.attestation,
                    ],
                    registry,
                )?)
                .ok_or(Error::Overflow)?;
        }
        if signed.checked_mul(U256::from(3)).ok_or(Error::Overflow)?
            <= total.checked_mul(U256::from(2)).ok_or(Error::Overflow)?
        {
            return Err(Error::NoQuorum);
        }
        Ok(())
    }
}
