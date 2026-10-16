//! Hybrid evidence authenticated by historical E-1 authority. Verification does
//! not execute penalties or establish conflicting finalized blocks.
use crate::{
    Error, Hash, Result,
    anchors::FinalizedAnchor,
    continuity_v2::{ParentVoter, Vote},
    domain_hash,
};
use minicbor::{Decoder, Encoder};
use std::collections::BTreeMap;
pub const MAX_EVIDENCE_BYTES: usize = 16 * 1024;
/// Loaded from locally authenticated history, never trusted from evidence bytes.
pub struct HistoricalAuthority<'a> {
    pub parent: &'a FinalizedAnchor,
    pub roots: [Hash; 3],
    pub registry: &'a BTreeMap<Hash, ParentVoter>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub a: Vote,
    pub b: Vote,
}
#[derive(Debug)]
pub struct VerifiedOffense {
    node: Hash,
    lineage: Hash,
    hardware_generation: u64,
    key_generation: u64,
    height: u64,
    evidence_id: Hash,
    historical_anchor: Hash,
}
impl VerifiedOffense {
    pub fn lineage(&self) -> Hash {
        self.lineage
    }
    pub fn node(&self) -> Hash {
        self.node
    }
    pub fn hardware_generation(&self) -> u64 {
        self.hardware_generation
    }
    pub fn key_generation(&self) -> u64 {
        self.key_generation
    }
    pub fn height(&self) -> u64 {
        self.height
    }
    pub fn evidence_id(&self) -> Hash {
        self.evidence_id
    }
    pub fn historical_anchor(&self) -> Hash {
        self.historical_anchor
    }
}
fn identity(v: &Vote) -> Result<Hash> {
    // Randomized FN-DSA representations do not create another offense identity.
    Ok(domain_hash(
        b"MUTINY-BUILD8-EQUIVOCATION-VOTE-ID-V2",
        &v.unsigned()?,
    ))
}
impl Evidence {
    pub fn new(a: Vote, b: Vote) -> Result<Self> {
        let (x, y) = (identity(&a)?, identity(&b)?);
        if x == y {
            return Err(Error::Duplicate);
        }
        Ok(if x < y {
            Self { a, b }
        } else {
            Self { a: b, b: a }
        })
    }
    pub fn id(&self) -> Result<Hash> {
        let (x, y) = (identity(&self.a)?, identity(&self.b)?);
        if x >= y {
            return Err(Error::NonCanonical);
        }
        Ok(domain_hash(
            b"MUTINY-BUILD8-EQUIVOCATION-ID-V2",
            &[x.as_slice(), y.as_slice()].concat(),
        ))
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.id()?;
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(17)
            .unwrap()
            .bytes(&self.a.encode()?)
            .unwrap()
            .bytes(&self.b.encode()?)
            .unwrap();
        let raw = e.into_writer();
        crate::blocks::canonical(&raw, MAX_EVIDENCE_BYTES)?;
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_EVIDENCE_BYTES)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(|_| Error::Codec)? != Some(4)
            || d.u8().map_err(|_| Error::Codec)? != 2
            || d.u8().map_err(|_| Error::Codec)? != 17
        {
            return Err(Error::Codec);
        }
        let value = Self {
            a: Vote::decode(d.bytes().map_err(|_| Error::Codec)?)?,
            b: Vote::decode(d.bytes().map_err(|_| Error::Codec)?)?,
        };
        if d.position() != raw.len() || value.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
    pub fn validate(
        &self,
        inclusion_parent: &FinalizedAnchor,
        historical: &HistoricalAuthority<'_>,
    ) -> Result<VerifiedOffense> {
        self.encode()?;
        let height = inclusion_parent
            .height
            .checked_add(1)
            .ok_or(Error::Overflow)?;
        let offense = self.a.decision.height;
        if !crate::bonds::actionable(offense, height) {
            return Err(Error::InvalidCounter);
        }
        inclusion_parent.validate_context(self.a.decision.genesis, self.a.decision.fingerprint)?;
        historical
            .parent
            .validate_context(inclusion_parent.genesis, inclusion_parent.fingerprint)?;
        if historical.parent.height.checked_add(1) != Some(offense) {
            return Err(Error::WrongAnchor);
        }
        self.a
            .verify(historical.parent, historical.roots, historical.registry)?;
        self.b
            .verify(historical.parent, historical.roots, historical.registry)?;
        let (a, b) = (&self.a, &self.b);
        if a.node != b.node
            || a.hardware_generation != b.hardware_generation
            || a.key_generation != b.key_generation
            || a.decision.round != b.decision.round
            || a.decision.step != b.decision.step
            || (a.nil == b.nil
                && a.decision.block == b.decision.block
                && a.decision.state == b.decision.state
                && a.decision.mining_epoch == b.decision.mining_epoch)
        {
            return Err(Error::WrongOperation);
        }
        Ok(VerifiedOffense {
            node: a.node,
            lineage: historical
                .registry
                .get(&a.node)
                .ok_or(Error::UnknownSigner)?
                .lineage,
            hardware_generation: a.hardware_generation,
            key_generation: a.key_generation,
            height: offense,
            evidence_id: self.id()?,
            historical_anchor: historical.parent.id(),
        })
    }
}
