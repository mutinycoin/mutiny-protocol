//! Tentative parent-state participation and rolling refresh transition. The
//! caller atomically installs the result only after old-weight certification.
use crate::{
    Error, Hash, Result,
    anchors::FinalizedAnchor,
    blocks::{BlockBody, operation_kind},
    domain_hash,
    freshness::{AttestationRefresh, FreshnessRecord, PhysicalAttestationVerifier, PhysicalMember},
    participation::{MAX_ACKS, ParentMember, ParticipationAck, PeriodSlots},
    recovery::ContinuityState,
};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContinuityAccounting {
    pub slots: PeriodSlots,
    pub freshness: BTreeMap<Hash, FreshnessRecord>,
}
impl ContinuityAccounting {
    pub fn records(&self) -> Result<BTreeMap<Hash, Vec<u8>>> {
        if self.freshness.len() > MAX_ACKS {
            return Err(Error::Capacity);
        }
        let mut records = BTreeMap::from([(
            domain_hash(b"MUTINY-BUILD8-PARTICIPATION-STATE-KEY-V1", &[]),
            self.slots.encode()?,
        )]);
        for (node, record) in &self.freshness {
            if node != &record.node || record.committed_height > self.slots.last_height {
                return Err(Error::WrongAnchor);
            }
            records.insert(
                domain_hash(b"MUTINY-BUILD8-FRESHNESS-STATE-KEY-V1", node),
                record.encode(),
            );
        }
        Ok(records)
    }
    /// Decode this component's records, extracted from an independently
    /// authenticated parent StateRoot. Decoding never verifies new evidence.
    pub fn from_records(records: &BTreeMap<Hash, Vec<u8>>) -> Result<Self> {
        if records.len() > MAX_ACKS + 1 {
            return Err(Error::Capacity);
        }
        let key = domain_hash(b"MUTINY-BUILD8-PARTICIPATION-STATE-KEY-V1", &[]);
        let slots = PeriodSlots::decode(records.get(&key).ok_or(Error::Codec)?)?;
        let mut freshness = BTreeMap::new();
        for (k, raw) in records {
            if *k == key {
                continue;
            }
            let record = FreshnessRecord::decode(raw)?;
            if domain_hash(b"MUTINY-BUILD8-FRESHNESS-STATE-KEY-V1", &record.node) != *k {
                return Err(Error::WrongAnchor);
            }
            if freshness.insert(record.node, record).is_some() {
                return Err(Error::Duplicate);
            }
        }
        let value = Self { slots, freshness };
        if &value.records()? != records {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
    pub fn apply<V: PhysicalAttestationVerifier>(
        &self,
        parent: &FinalizedAnchor,
        body: &BlockBody,
        registry: &ContinuityState,
        physical: &BTreeMap<Hash, PhysicalMember>,
        verifier: &V,
    ) -> Result<(Self, ContinuityState)> {
        self.apply_inner(parent,body,registry,physical,verifier,None)
    }
    pub(crate) fn apply_with_capacity<V: PhysicalAttestationVerifier>(
        &self,parent:&FinalizedAnchor,body:&BlockBody,registry:&ContinuityState,
        physical:&BTreeMap<Hash,PhysicalMember>,verifier:&V,
        capacity:&crate::body_capacity_v3::BodyCapacity,
    ) -> Result<(Self,ContinuityState)> {
        if capacity.parent()!=parent { return Err(Error::WrongAnchor); }
        self.apply_inner(parent,body,registry,physical,verifier,Some(capacity))
    }
    fn apply_inner<V: PhysicalAttestationVerifier>(
        &self,parent:&FinalizedAnchor,body:&BlockBody,registry:&ContinuityState,
        physical:&BTreeMap<Hash,PhysicalMember>,verifier:&V,
        capacity:Option<&crate::body_capacity_v3::BodyCapacity>,
    ) -> Result<(Self,ContinuityState)> {
        self.records()?;
        match capacity { Some(c)=>{c.encode(body)?;}, None=>{body.encode()?;} }
        parent.validate_context(registry.genesis, registry.fingerprint)?;
        if registry.anchor.height != parent.height
            || registry.anchor.tip != parent.block
            || parent.height.checked_add(1) != Some(body.height)
        {
            return Err(Error::WrongAnchor);
        }
        registry.weights()?;
        let parent_members = registry
            .members
            .iter()
            .map(|m| {
                (
                    m.node,
                    ParentMember {
                        node: m.node,
                        generation: m.generation,
                        key: m.voting_key,
                        admitted: true,
                        physical: m.physical,
                        revoked: !m.eligible,
                        freshness: self.freshness.get(&m.node).cloned(),
                    },
                )
            })
            .collect();
        let mut acks = Vec::new();
        let mut refreshes = Vec::new();
        let mut seen = BTreeSet::new();
        let mut activation = false;
        for raw in &body.operations {
            match operation_kind(raw)? {
                10 | 14..=22 | 25 => {} // Typed validators run in the same state executor (A2 kind25 included).
                11 => acks.push(ParticipationAck::decode(raw)?),
                12 => {
                    let r = AttestationRefresh::decode(raw)?;
                    if !seen.insert(r.node) {
                        return Err(Error::Duplicate);
                    }
                    refreshes.push(r);
                }
                13 => {
                    if activation {
                        return Err(Error::Duplicate);
                    }
                    crate::activation::DecentralizedActivation::decode(raw)?
                        .validate(parent, registry)?;
                    activation = true;
                }
                _ => return Err(Error::WrongOperation),
            }
        }
        // Critically, process every ACK against the original parent projection,
        // before inserting any new freshness record from this block.
        let mut next = self.clone();
        next.slots = self.slots.apply(parent, &acks, &parent_members)?;
        next.freshness.retain(|node, record| {
            registry.members.iter().any(|m| {
                m.node == *node
                    && m.generation == record.generation
                    && m.voting_key == record.key
                    && m.physical
            })
        });
        for refresh in refreshes {
            let member = registry
                .members
                .iter()
                .find(|m| m.node == refresh.node)
                .ok_or(Error::UnknownSigner)?;
            if !member.physical || !member.eligible {
                return Err(Error::UnqualifiedPhysical);
            }
            let p = physical
                .get(&member.node)
                .ok_or(Error::UnqualifiedPhysical)?;
            if p.node != member.node
                || p.generation != member.generation
                || p.hardware != member.hardware
                || p.continuity_key != member.voting_key
                || p.admission_commitment != member.attestation
            {
                return Err(Error::UnqualifiedPhysical);
            }
            let record = refresh.validate(parent, p, verifier)?;
            next.freshness.insert(record.node, record);
        }
        let mut next_registry = if body.height.is_multiple_of(60) {
            let (slots, updated) = next.slots.close_reputation(registry)?;
            next.slots = slots;
            updated
        } else {
            registry.clone()
        };
        if activation {
            next_registry.stage_activation_from_parent(registry)?;
        }
        next.records()?;
        // Anchor metadata is installed by the chain executor after the candidate
        // block identity is known. Never insert current BlockHash in StateRoot.
        Ok((next, next_registry))
    }
}
