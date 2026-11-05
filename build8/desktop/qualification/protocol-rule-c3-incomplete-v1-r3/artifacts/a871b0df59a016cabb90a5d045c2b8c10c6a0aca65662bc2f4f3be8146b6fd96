//! Canonical certificate evidence and weighted signature checks.
//! A verified quorum is not a replacement for the durable BFT lock state machine.
use crate::{Error, Hash, Result, domain_hash};
use minicbor::{Decoder, Encoder};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use primitive_types::U256;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub network: u32,
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub purpose: u8,
    pub height: u64,
    pub mining_epoch: u64,
    pub continuity_period: u64,
    pub round: u64,
    pub step: u8,
    pub previous_finalized_anchor: Hash,
    pub parent: Hash,
    pub block: Hash,
    pub state: Hash,
    pub membership: Hash,
    pub reputation: Hash,
    pub attestation: Hash,
}
impl Decision {
    pub fn decode(raw: &[u8]) -> Result<Self> {
        // Reuse the exact field decoder and canonical re-encoding checks. The
        // canonical 17-field prefix is one byte; append an empty signer array.
        if raw.len() > 1024 || raw.first() != Some(&0x91) {
            return Err(Error::Codec);
        }
        let mut certificate = Vec::with_capacity(raw.len() + 1);
        certificate.push(0x92);
        certificate.extend_from_slice(&raw[1..]);
        certificate.push(0x80);
        let decision = Certificate::decode(&certificate)?.decision;
        if decision.encode() != raw {
            return Err(Error::NonCanonical);
        }
        Ok(decision)
    }
    /// Identity only: caller must establish finality through BFT validation.
    pub fn anchor(&self) -> crate::anchors::FinalizedAnchor {
        crate::anchors::FinalizedAnchor {
            network: self.network,
            genesis: self.genesis,
            fingerprint: self.fingerprint,
            height: self.height,
            block: self.block,
        }
    }
    pub fn verify_parent(&self, parent: &crate::anchors::FinalizedAnchor) -> Result<()> {
        parent.validate_context(self.genesis, self.fingerprint)?;
        if self.network != parent.network
            || parent.height.checked_add(1) != Some(self.height)
            || self.parent != parent.block
            || self.previous_finalized_anchor != parent.id()
        {
            return Err(Error::WrongAnchor);
        }
        Ok(())
    }
    fn fields(&self, e: &mut Encoder<Vec<u8>>) {
        e.u8(1)
            .unwrap()
            .u32(self.network)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .u8(self.purpose)
            .unwrap()
            .u64(self.height)
            .unwrap()
            .u64(self.mining_epoch)
            .unwrap()
            .u64(self.continuity_period)
            .unwrap()
            .u64(self.round)
            .unwrap()
            .u8(self.step)
            .unwrap();
        for h in [
            &self.previous_finalized_anchor,
            &self.parent,
            &self.block,
            &self.state,
            &self.membership,
            &self.reputation,
            &self.attestation,
        ] {
            e.bytes(h).unwrap();
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(17).unwrap();
        self.fields(&mut e);
        e.into_writer()
    }
    pub fn id(&self) -> Hash {
        domain_hash(b"MUTINY-BUILD8-CONTINUITY-DECISION-V1", &self.encode())
    }
    pub fn signing_digest(&self, node: Hash, generation: u64) -> Hash {
        let mut e = Encoder::new(Vec::new());
        e.array(3)
            .unwrap()
            .bytes(&self.encode())
            .unwrap()
            .bytes(&node)
            .unwrap()
            .u64(generation)
            .unwrap();
        domain_hash(b"MUTINY-BUILD8-CONTINUITY-VOTE-V1", &e.into_writer())
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signer {
    pub node: Hash,
    pub key_version: u64,
    pub signature: [u8; 64],
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    pub decision: Decision,
    pub signers: Vec<Signer>,
}
impl Certificate {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.signers.len() > 1024 {
            return Err(Error::Capacity);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(18).unwrap();
        self.decision.fields(&mut e);
        e.array(self.signers.len() as u64).unwrap();
        let mut prior = None;
        for s in &self.signers {
            if prior.is_some_and(|p| p >= s.node) {
                return Err(Error::Duplicate);
            }
            prior = Some(s.node);
            e.array(3)
                .unwrap()
                .bytes(&s.node)
                .unwrap()
                .u64(s.key_version)
                .unwrap()
                .bytes(&s.signature)
                .unwrap();
        }
        let b = e.into_writer();
        if b.len() > 256 * 1024 {
            return Err(Error::Oversize);
        }
        Ok(b)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 256 * 1024 {
            return Err(Error::Oversize);
        }
        let mut d = Decoder::new(raw);
        let c = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            fn h(d: &mut Decoder<'_>) -> std::result::Result<Hash, minicbor::decode::Error> {
                d.bytes()?
                    .try_into()
                    .map_err(|_| minicbor::decode::Error::message("hash"))
            }
            if d.array()? != Some(18) || d.u8()? != 1 {
                return Err(minicbor::decode::Error::message("certificate"));
            }
            let decision = Decision {
                network: d.u32()?,
                genesis: h(&mut d)?,
                fingerprint: h(&mut d)?,
                purpose: d.u8()?,
                height: d.u64()?,
                mining_epoch: d.u64()?,
                continuity_period: d.u64()?,
                round: d.u64()?,
                step: d.u8()?,
                previous_finalized_anchor: h(&mut d)?,
                parent: h(&mut d)?,
                block: h(&mut d)?,
                state: h(&mut d)?,
                membership: h(&mut d)?,
                reputation: h(&mut d)?,
                attestation: h(&mut d)?,
            };
            let n = d
                .array()?
                .ok_or(minicbor::decode::Error::message("signers"))?;
            if n > 1024 {
                return Err(minicbor::decode::Error::message("too many signers"));
            }
            let mut signers = Vec::new();
            for _ in 0..n {
                if d.array()? != Some(3) {
                    return Err(minicbor::decode::Error::message("signer"));
                }
                signers.push(Signer {
                    node: h(&mut d)?,
                    key_version: d.u64()?,
                    signature: d
                        .bytes()?
                        .try_into()
                        .map_err(|_| minicbor::decode::Error::message("signature"))?,
                });
            }
            Ok(Self { decision, signers })
        })()
        .map_err(|_| Error::Codec)?;
        if d.position() != raw.len() || c.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(c)
    }
    pub fn verify_quorum(
        &self,
        expected: &Decision,
        registry: &BTreeMap<Hash, Voter>,
    ) -> Result<()> {
        if &self.decision != expected {
            return Err(Error::WrongAnchor);
        }
        self.encode()?;
        if registry.len() > 1024 {
            return Err(Error::Capacity);
        }
        let mut total = U256::zero();
        let mut keys = BTreeSet::new();
        for voter in registry.values() {
            if !voter.weight.is_zero() {
                if !keys.insert(voter.public_key) {
                    return Err(Error::Duplicate);
                }
                total = total.checked_add(voter.weight).ok_or(Error::Overflow)?;
            }
        }
        if total.is_zero() {
            return Err(Error::NoQuorum);
        }
        let mut signed = U256::zero();
        for s in &self.signers {
            let voter = registry.get(&s.node).ok_or(Error::UnknownSigner)?;
            if voter.key_version != s.key_version || voter.weight.is_zero() {
                return Err(Error::WrongGeneration);
            }
            let signature = Signature::from_slice(&s.signature).map_err(|_| Error::BadSignature)?;
            if signature.normalize_s().is_some() {
                return Err(Error::NonCanonical);
            }
            VerifyingKey::from_sec1_bytes(&voter.public_key)
                .map_err(|_| Error::BadSignature)?
                .verify_prehash(&expected.signing_digest(s.node, s.key_version), &signature)
                .map_err(|_| Error::BadSignature)?;
            signed = signed.checked_add(voter.weight).ok_or(Error::Overflow)?;
        }
        if signed.checked_mul(U256::from(3)).ok_or(Error::Overflow)?
            <= total.checked_mul(U256::from(2)).ok_or(Error::Overflow)?
        {
            return Err(Error::NoQuorum);
        }
        Ok(())
    }
}
/// Derived only from the committed physical-admission registry; cloud weight is zero.
#[derive(Clone)]
pub struct Voter {
    pub key_version: u64,
    pub public_key: [u8; 33],
    pub weight: U256,
}
