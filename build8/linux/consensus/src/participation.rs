//! Parent acknowledgements are participation evidence, never voting evidence.
use crate::{Error, Hash, Result, anchors::FinalizedAnchor, domain_hash};
use minicbor::{Decoder, Encoder};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use std::collections::BTreeMap;

pub const MAX_ACKS: usize = 1024;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParticipationAck {
    pub network: u32,
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub node: Hash,
    pub height: u64,
    pub parent: Hash,
    pub generation: u64,
    pub signature: [u8; 64],
}
impl ParticipationAck {
    fn fields(&self, e: &mut Encoder<Vec<u8>>) {
        e.u8(1)
            .unwrap()
            .u8(11)
            .unwrap()
            .u32(self.network)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .bytes(&self.node)
            .unwrap()
            .u64(self.height)
            .unwrap()
            .u64(self.height)
            .unwrap()
            .array(2)
            .unwrap()
            .bytes(&self.parent)
            .unwrap()
            .u64(self.generation)
            .unwrap();
    }
    pub fn signing_digest(&self) -> Hash {
        let mut e = Encoder::new(Vec::new());
        e.array(9).unwrap();
        self.fields(&mut e);
        domain_hash(
            b"MUTINY-BUILD8-CONTINUITY-PARTICIPATION-ACK-V1",
            &e.into_writer(),
        )
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(10).unwrap();
        self.fields(&mut e);
        e.array(1).unwrap().bytes(&self.signature).unwrap();
        e.into_writer()
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 512 {
            return Err(Error::Oversize);
        }
        let mut d = Decoder::new(raw);
        let ack = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            fn h(d: &mut Decoder<'_>) -> std::result::Result<Hash, minicbor::decode::Error> {
                d.bytes()?
                    .try_into()
                    .map_err(|_| minicbor::decode::Error::message("hash"))
            }
            if d.array()? != Some(10) || d.u8()? != 1 || d.u8()? != 11 {
                return Err(minicbor::decode::Error::message("ack"));
            }
            let network = d.u32()?;
            let genesis = h(&mut d)?;
            let fingerprint = h(&mut d)?;
            let node = h(&mut d)?;
            let height = d.u64()?;
            if d.u64()? != height || d.array()? != Some(2) {
                return Err(minicbor::decode::Error::message("slot"));
            }
            let parent = h(&mut d)?;
            let generation = d.u64()?;
            if d.array()? != Some(1) {
                return Err(minicbor::decode::Error::message("signature"));
            }
            let signature = d
                .bytes()?
                .try_into()
                .map_err(|_| minicbor::decode::Error::message("signature"))?;
            Ok(Self {
                network,
                genesis,
                fingerprint,
                node,
                height,
                parent,
                generation,
                signature,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if d.position() != raw.len() || ack.encode() != raw {
            return Err(Error::NonCanonical);
        }
        Ok(ack)
    }
    /// The caller supplies a member and freshness record from authenticated parent
    /// state, after admission/attestation validation. This API cannot admit a node.
    pub fn verify(&self, parent: &FinalizedAnchor, member: &ParentMember) -> Result<()> {
        parent.validate_context(self.genesis, self.fingerprint)?;
        if self.network != parent.network
            || parent.height.checked_add(1) != Some(self.height)
            || self.parent != parent.id()
        {
            return Err(Error::WrongAnchor);
        }
        if self.node != member.node {
            return Err(Error::UnknownSigner);
        }
        if self.generation != member.generation {
            return Err(Error::WrongGeneration);
        }
        if !member.admitted
            || !member.physical
            || member.revoked
            || !member.freshness.as_ref().is_some_and(|record| {
                record.eligible(self.node, self.generation, member.key, self.height)
            })
        {
            return Err(Error::UnqualifiedPhysical);
        }
        let signature = Signature::from_slice(&self.signature).map_err(|_| Error::BadSignature)?;
        if signature.normalize_s().is_some() {
            return Err(Error::NonCanonical);
        }
        VerifyingKey::from_sec1_bytes(&member.key)
            .map_err(|_| Error::BadSignature)?
            .verify_prehash(&self.signing_digest(), &signature)
            .map_err(|_| Error::BadSignature)
    }
}
/// Authenticated parent-state projection; deliberately has no voting weight.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParentMember {
    pub node: Hash,
    pub generation: u64,
    pub key: [u8; 33],
    pub admitted: bool,
    pub physical: bool,
    pub revoked: bool,
    pub freshness: Option<crate::freshness::FreshnessRecord>,
}

/// Normalize transport duplicates before body construction. Conflicts reject the
/// complete set; choosing whichever arrived first would be nondeterministic.
pub fn normalize(acks: &[ParticipationAck]) -> Result<Vec<ParticipationAck>> {
    if acks.len() > MAX_ACKS {
        return Err(Error::Capacity);
    }
    let mut unique = BTreeMap::new();
    for ack in acks {
        if let Some(old) = unique.insert(ack.node, ack.clone())
            && old != *ack
        {
            return Err(Error::Duplicate);
        }
    }
    Ok(unique.into_values().collect())
}

/// A tentative period accumulator. Only persist its result with the corresponding
/// certified canonical block; receipt in a mempool never calls this transition.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeriodSlots {
    pub period: u64,
    pub last_height: u64,
    pub bits: BTreeMap<Hash, u64>,
}
impl PeriodSlots {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let start = self.period.checked_mul(60).ok_or(Error::Overflow)?;
        let completed = self
            .last_height
            .checked_sub(start)
            .ok_or(Error::InvalidCounter)?;
        if completed > 60 || self.bits.len() > MAX_ACKS {
            return Err(Error::InvalidCounter);
        }
        let mask = (1u64 << completed) - 1;
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u8(1)
            .unwrap()
            .u64(self.period)
            .unwrap()
            .u64(self.last_height)
            .unwrap()
            .array(self.bits.len() as u64)
            .unwrap();
        for (node, bits) in &self.bits {
            if *bits == 0 || bits & !mask != 0 {
                return Err(Error::InvalidCounter);
            }
            e.array(2).unwrap().bytes(node).unwrap().u64(*bits).unwrap();
        }
        Ok(e.into_writer())
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 64 * 1024 {
            return Err(Error::Oversize);
        }
        let mut d = Decoder::new(raw);
        let value = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            if d.array()? != Some(4) || d.u8()? != 1 {
                return Err(minicbor::decode::Error::message("slots"));
            }
            let period = d.u64()?;
            let last_height = d.u64()?;
            let n = d
                .array()?
                .ok_or(minicbor::decode::Error::message("count"))?;
            if n > MAX_ACKS as u64 {
                return Err(minicbor::decode::Error::message("count"));
            }
            let mut bits = BTreeMap::new();
            for _ in 0..n {
                if d.array()? != Some(2) {
                    return Err(minicbor::decode::Error::message("entry"));
                }
                let node = d
                    .bytes()?
                    .try_into()
                    .map_err(|_| minicbor::decode::Error::message("node"))?;
                if bits.insert(node, d.u64()?).is_some() {
                    return Err(minicbor::decode::Error::message("duplicate"));
                }
            }
            Ok(Self {
                period,
                last_height,
                bits,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if d.position() != raw.len() || value.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
    pub fn apply(
        &self,
        parent: &FinalizedAnchor,
        acks: &[ParticipationAck],
        registry: &BTreeMap<Hash, ParentMember>,
    ) -> Result<Self> {
        self.encode()?;
        let height = parent.height.checked_add(1).ok_or(Error::Overflow)?;
        if height != self.last_height.checked_add(1).ok_or(Error::Overflow)?
            || self.period != (height - 1) / 60
        {
            return Err(Error::InvalidCounter);
        }
        if registry.len() > MAX_ACKS || self.bits.len() > MAX_ACKS {
            return Err(Error::Capacity);
        }
        let acks = normalize(acks)?;
        let mut next = self.clone();
        for ack in acks {
            ack.verify(parent, registry.get(&ack.node).ok_or(Error::UnknownSigner)?)?;
            *next.bits.entry(ack.node).or_default() |= 1u64 << ((height - 1) % 60);
        }
        if next.bits.len() > MAX_ACKS {
            return Err(Error::Capacity);
        }
        next.last_height = height;
        Ok(next)
    }
    pub fn close(&self) -> Result<(Self, BTreeMap<Hash, bool>)> {
        self.encode()?;
        if self.last_height == 0
            || !self.last_height.is_multiple_of(60)
            || (self.last_height - 1) / 60 != self.period
        {
            return Err(Error::InvalidCounter);
        }
        if self.bits.len() > MAX_ACKS || self.bits.values().any(|b| b >> 60 != 0) {
            return Err(Error::InvalidCounter);
        }
        let qualified = self
            .bits
            .iter()
            .map(|(node, bits)| (*node, bits.count_ones() >= 54))
            .collect();
        Ok((
            Self {
                period: self.period.checked_add(1).ok_or(Error::Overflow)?,
                last_height: self.last_height,
                bits: BTreeMap::new(),
            },
            qualified,
        ))
    }

    /// Produces future authority without touching the parent registry used to
    /// verify the closing block's certificate. Caller installs only on finality.
    pub fn close_reputation(
        &self,
        parent: &crate::recovery::ContinuityState,
    ) -> Result<(Self, crate::recovery::ContinuityState)> {
        parent.weights()?;
        if parent.anchor.height.checked_add(1) != Some(self.last_height) {
            return Err(Error::WrongAnchor);
        }
        let (slots, qualification) = self.close()?;
        let mut next = parent.clone();
        for member in &mut next.members {
            if member.physical && member.eligible {
                member
                    .history
                    .complete_period(qualification.get(&member.node).copied().unwrap_or(false))?;
            }
        }
        next.first_period_committed = true;
        next.weights()?;
        Ok((slots, next))
    }
}
