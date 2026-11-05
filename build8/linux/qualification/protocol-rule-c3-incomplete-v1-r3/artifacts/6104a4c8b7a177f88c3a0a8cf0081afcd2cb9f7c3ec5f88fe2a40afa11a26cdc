//! Owner/node-authorized membership lifecycle. These operations are tentative
//! state changes until the enclosing block receives its parent-set certificate.
use crate::{
    Error, Hash, NETWORK_ID, Result, anchors::FinalizedAnchor, domain_hash,
    recovery::ContinuityState,
};
use ed25519_dalek::{Signature, VerifyingKey};
use minicbor::{Decoder, Encoder, data::Type};
use std::collections::BTreeMap;
fn hash(d: &mut Decoder<'_>) -> std::result::Result<Hash, minicbor::decode::Error> {
    d.bytes()?
        .try_into()
        .map_err(|_| minicbor::decode::Error::message("hash"))
}
pub fn control_key(node: Hash) -> Hash {
    domain_hash(b"MUTINY-BUILD8-NODE-CONTROL-KEY-V1", &node)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeControl {
    pub node: Hash,
    pub generation: u64,
    pub owner: Hash,
    pub node_authentication: Hash,
    pub sequence: u64,
    pub exit_boundary: Option<u64>,
    pub admitted_height: u64,
    pub admission_boundary: Option<u64>,
    pub hardware_since_height: u64,
}
impl NodeControl {
    pub fn encode(&self) -> Result<Vec<u8>> {
        VerifyingKey::from_bytes(&self.owner).map_err(|_| Error::BadSignature)?;
        VerifyingKey::from_bytes(&self.node_authentication).map_err(|_| Error::BadSignature)?;
        if self
            .exit_boundary
            .is_some_and(|h| h == 0 || !h.is_multiple_of(60) || h < self.admitted_height)
        {
            return Err(Error::InvalidCounter);
        }
        if self
            .admission_boundary
            .is_some_and(|h| h == 0 || !h.is_multiple_of(60) || h < self.admitted_height)
            || (self.admission_boundary.is_some() && self.exit_boundary.is_some())
        {
            return Err(Error::InvalidCounter);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(10)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&self.node)
            .unwrap()
            .u64(self.generation)
            .unwrap()
            .bytes(&self.owner)
            .unwrap()
            .bytes(&self.node_authentication)
            .unwrap()
            .u64(self.sequence)
            .unwrap();
        if let Some(h) = self.exit_boundary {
            e.u64(h).unwrap();
        } else {
            e.null().unwrap();
        }
        e.u64(self.admitted_height).unwrap();
        if let Some(h) = self.admission_boundary {
            e.u64(h).unwrap();
        } else {
            e.null().unwrap();
        }
        e.u64(self.hardware_since_height).unwrap();
        Ok(e.into_writer())
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, 256)?;
        let mut d = Decoder::new(raw);
        let value = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            if d.array()? != Some(10) || d.u8()? != 1 {
                return Err(minicbor::decode::Error::message("node control"));
            }
            Ok(Self {
                node: hash(&mut d)?,
                generation: d.u64()?,
                owner: hash(&mut d)?,
                node_authentication: hash(&mut d)?,
                sequence: d.u64()?,
                exit_boundary: if d.datatype()? == Type::Null {
                    d.null()?;
                    None
                } else {
                    Some(d.u64()?)
                },
                admitted_height: d.u64()?,
                admission_boundary: if d.datatype()? == Type::Null {
                    d.null()?;
                    None
                } else {
                    Some(d.u64()?)
                },
                hardware_since_height: d.u64()?,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if value.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MembershipBook {
    pub controls: BTreeMap<Hash, NodeControl>,
    pub retired: BTreeMap<(Hash, u64), RetiredGeneration>,
}
impl MembershipBook {
    pub fn records(&self) -> Result<BTreeMap<Hash, Vec<u8>>> {
        if self.controls.len() > crate::participation::MAX_ACKS {
            return Err(Error::Capacity);
        }
        let mut records: BTreeMap<_, _> = self
            .controls
            .iter()
            .map(|(node, control)| {
                if *node != control.node {
                    return Err(Error::WrongAnchor);
                }
                Ok((control_key(*node), control.encode()?))
            })
            .collect::<Result<_>>()?;
        if self.retired.len() > crate::execution::MAX_STATE_RECORDS {
            return Err(Error::Capacity);
        }
        for (id, retired) in &self.retired {
            if *id != (retired.node, retired.generation) {
                return Err(Error::WrongAnchor);
            }
            records.insert(retired.key(), retired.encode()?);
        }
        Ok(records)
    }
    pub fn from_records(records: &BTreeMap<Hash, Vec<u8>>) -> Result<Self> {
        if records.len() > crate::execution::MAX_STATE_RECORDS {
            return Err(Error::Capacity);
        }
        let mut controls = BTreeMap::new();
        let mut retired = BTreeMap::new();
        for (key, raw) in records {
            if let Ok(r) = RetiredGeneration::decode(raw) {
                if *key != r.key() {
                    return Err(Error::WrongAnchor);
                }
                if retired.insert((r.node, r.generation), r).is_some() {
                    return Err(Error::Duplicate);
                }
                continue;
            }
            let control = NodeControl::decode(raw)?;
            if *key != control_key(control.node) {
                return Err(Error::WrongAnchor);
            }
            if controls.insert(control.node, control).is_some() {
                return Err(Error::Duplicate);
            }
        }
        let book = Self { controls, retired };
        if book.records()? != *records {
            return Err(Error::NonCanonical);
        }
        Ok(book)
    }
    /// Run after H participation/reputation, using H-1 for authorization. No
    /// mutation of the parent or the parent-set certificate weights occurs.
    pub fn apply_exits(
        &self,
        parent: &FinalizedAnchor,
        operations: &[Vec<u8>],
        parent_registry: &ContinuityState,
        post_registry: &mut ContinuityState,
    ) -> Result<Self> {
        self.records()?;
        parent.validate_context(parent_registry.genesis, parent_registry.fingerprint)?;
        let height = parent.height.checked_add(1).ok_or(Error::Overflow)?;
        let mut next = self.clone();
        let mut updated_registry = post_registry.clone();
        let mut seen = std::collections::BTreeSet::new();
        for raw in operations {
            if crate::blocks::operation_kind(raw)? != 14 {
                continue;
            }
            let exit = ContinuityExit::decode(raw)?;
            if !seen.insert(exit.node) {
                return Err(Error::Duplicate);
            }
            let control = self.controls.get(&exit.node).ok_or(Error::UnknownSigner)?;
            exit.validate(parent, control)?;
            let member = parent_registry
                .members
                .iter()
                .find(|m| m.node == exit.node)
                .ok_or(Error::UnknownSigner)?;
            if !member.physical
                || !member.eligible
                || member.generation != control.generation
                || control.exit_boundary.is_some()
            {
                return Err(Error::WrongGeneration);
            }
            let updated = next
                .controls
                .get_mut(&exit.node)
                .ok_or(Error::UnknownSigner)?;
            updated.sequence = exit.sequence;
            updated.exit_boundary = Some(height.checked_add(59).ok_or(Error::Overflow)? / 60 * 60);
        }
        if height.is_multiple_of(60) {
            for control in next.controls.values_mut() {
                if control.admission_boundary.is_some_and(|h| h <= height) {
                    let member = updated_registry
                        .members
                        .iter_mut()
                        .find(|m| m.node == control.node)
                        .ok_or(Error::UnknownSigner)?;
                    if member.generation != control.generation
                        || member.eligible
                        || member.genesis_member
                    {
                        return Err(Error::WrongGeneration);
                    }
                    member.eligible = true;
                    control.admission_boundary = None;
                }
                if control.exit_boundary.is_some_and(|h| h <= height) {
                    let member = updated_registry
                        .members
                        .iter_mut()
                        .find(|m| m.node == control.node)
                        .ok_or(Error::UnknownSigner)?;
                    if member.generation != control.generation {
                        return Err(Error::WrongGeneration);
                    }
                    member.eligible = false;
                    control.exit_boundary = None;
                }
            }
        }
        updated_registry.weights()?;
        next.records()?;
        *post_registry = updated_registry;
        Ok(next)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContinuityExit {
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub height: u64,
    pub parent_anchor: Hash,
    pub node: Hash,
    pub generation: u64,
    pub sequence: u64,
    pub authorizer: Hash,
    pub signature: [u8; 64],
}
impl ContinuityExit {
    fn bytes(&self, signed: bool) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(if signed { 12 } else { 11 })
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(14)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .u64(self.height)
            .unwrap()
            .bytes(&self.parent_anchor)
            .unwrap()
            .bytes(&self.node)
            .unwrap()
            .u64(self.generation)
            .unwrap()
            .u64(self.sequence)
            .unwrap()
            .bytes(&self.authorizer)
            .unwrap();
        if signed {
            e.bytes(&self.signature).unwrap();
        }
        e.into_writer()
    }
    pub fn encode(&self) -> Vec<u8> {
        self.bytes(true)
    }
    pub fn signing_digest(&self) -> Hash {
        domain_hash(b"MUTINY-BUILD8-CONTINUITY-EXIT-V1", &self.bytes(false))
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, 512)?;
        let mut d = Decoder::new(raw);
        let value = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("continuity exit");
            if d.array()? != Some(12) || d.u8()? != 1 || d.u8()? != 14 || d.u32()? != NETWORK_ID {
                return Err(bad());
            }
            Ok(Self {
                genesis: hash(&mut d)?,
                fingerprint: hash(&mut d)?,
                height: d.u64()?,
                parent_anchor: hash(&mut d)?,
                node: hash(&mut d)?,
                generation: d.u64()?,
                sequence: d.u64()?,
                authorizer: hash(&mut d)?,
                signature: d.bytes()?.try_into().map_err(|_| bad())?,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if value.encode() != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
    pub fn validate(&self, parent: &FinalizedAnchor, control: &NodeControl) -> Result<()> {
        parent.validate_context(self.genesis, self.fingerprint)?;
        if parent.height.checked_add(1) != Some(self.height)
            || self.parent_anchor != parent.id()
            || self.node != control.node
        {
            return Err(Error::WrongAnchor);
        }
        if self.generation != control.generation {
            return Err(Error::WrongGeneration);
        }
        if control.sequence.checked_add(1) != Some(self.sequence) {
            return Err(Error::StaleSequence);
        }
        if self.authorizer != control.owner && self.authorizer != control.node_authentication {
            return Err(Error::BadSignature);
        }
        VerifyingKey::from_bytes(&self.authorizer)
            .map_err(|_| Error::BadSignature)?
            .verify_strict(
                &self.signing_digest(),
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| Error::BadSignature)
    }
}
pub(crate) fn is_record(key: Hash, raw: &[u8]) -> bool {
    NodeControl::decode(raw).is_ok_and(|c| control_key(c.node) == key)
        || RetiredGeneration::decode(raw).is_ok_and(|r| r.key() == key)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetiredGeneration {
    pub node: Hash,
    pub generation: u64,
    pub hardware: Hash,
    pub voting_key: [u8; 33],
    pub attestation: Hash,
    pub height: u64,
    pub reason: u8,
    pub evidence: Hash,
}
impl RetiredGeneration {
    pub fn key(&self) -> Hash {
        let mut e = Encoder::new(Vec::new());
        e.array(2)
            .unwrap()
            .bytes(&self.node)
            .unwrap()
            .u64(self.generation)
            .unwrap();
        domain_hash(b"MUTINY-BUILD8-RETIRED-GENERATION-KEY-V1", &e.into_writer())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        if (self.height == 0 && self.reason != 3) || !(1..=3).contains(&self.reason) {
            return Err(Error::InvalidCounter);
        }
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.voting_key)
            .map_err(|_| Error::BadSignature)?;
        let mut e = Encoder::new(Vec::new());
        e.array(9)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&self.node)
            .unwrap()
            .u64(self.generation)
            .unwrap()
            .bytes(&self.hardware)
            .unwrap()
            .bytes(&self.voting_key)
            .unwrap()
            .bytes(&self.attestation)
            .unwrap()
            .u64(self.height)
            .unwrap()
            .u8(self.reason)
            .unwrap()
            .bytes(&self.evidence)
            .unwrap();
        Ok(e.into_writer())
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, 256)?;
        let mut d = Decoder::new(raw);
        let r = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("retired generation");
            if d.array()? != Some(9) || d.u8()? != 1 {
                return Err(bad());
            }
            Ok(Self {
                node: hash(&mut d)?,
                generation: d.u64()?,
                hardware: hash(&mut d)?,
                voting_key: d.bytes()?.try_into().map_err(|_| bad())?,
                attestation: hash(&mut d)?,
                height: d.u64()?,
                reason: d.u8()?,
                evidence: hash(&mut d)?,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if r.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(r)
    }
}
