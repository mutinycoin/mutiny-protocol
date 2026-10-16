//! Authenticated-history candidate. Verification is historical evidence only;
//! canonical acceptance must replay full material against its actual parent.
use crate::{recovery_replacement_v2::Replacement, recovery_witness_v2::Witnesses};
use minicbor::{Decoder, Encoder};
use std::collections::BTreeMap;

pub(crate) fn is_record(raw: &[u8]) -> bool {
    let mut d = Decoder::new(raw);
    d.array().ok().flatten().is_some() && d.u8().ok() == Some(2) && d.u8().ok() == Some(58)
}
use crate::{
    Error, Hash, NETWORK_ID, Result,
    admission_v2::Policy,
    blocks, domain_hash,
    recovery_authority_v2::{Authority, Authorization},
    state_tree::StateProof,
};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub material: Replacement,
    pub authorization: Authorization,
    pub witnesses: Witnesses,
    pub policy: Policy,
}
impl Record {
    pub fn key(&self) -> Hash {
        domain_hash(
            b"MUTINY-BUILD8-RECOVERY-HISTORY-KEY-V2",
            &self.material.sequence.to_be_bytes(),
        )
    }
    pub fn verify_history_only(&self, authority: &Authority) -> Result<()> {
        let m = &self.material;
        self.authorization
            .verify_signature_only(authority, &m.intent()?)?;
        if self.policy.genesis != m.parent.genesis
            || self.policy.fingerprint != m.parent.fingerprint
            || !self
                .policy
                .endorsement_roots
                .contains(&m.binding.admission.endorsement_root)
        {
            return Err(Error::WrongAnchor);
        }
        self.policy.encode()?;
        m.verify_retained_evidence(&self.policy.owner_descriptor)?;
        self.witnesses.verify(
            &m.parent,
            m.root,
            m.old_node,
            m.old_hardware_generation,
            m.old_key_generation,
            m.commitment()?,
        )?;
        Ok(())
    }
    pub fn encode(&self, authority: &Authority) -> Result<Vec<u8>> {
        self.verify_history_only(authority)?;
        let mut e = Encoder::new(Vec::new());
        e.array(8)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(58)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.material.encode()?)
            .unwrap()
            .bytes(&self.authorization.encode(authority)?)
            .unwrap()
            .bytes(&self.witnesses.control.encode()?)
            .unwrap()
            .bytes(&self.witnesses.continuity.encode()?)
            .unwrap()
            .bytes(&self.policy.encode()?)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > crate::state_tree::MAX_RECORD {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8], authority: &Authority) -> Result<Self> {
        blocks::canonical(raw, crate::state_tree::MAX_RECORD)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(|_| Error::Codec)? != Some(8)
            || d.u8().map_err(|_| Error::Codec)? != 2
            || d.u8().map_err(|_| Error::Codec)? != 58
            || d.u32().map_err(|_| Error::Codec)? != NETWORK_ID
        {
            return Err(Error::Codec);
        }
        let value = Self {
            material: Replacement::decode(d.bytes().map_err(|_| Error::Codec)?)?,
            authorization: Authorization::decode(d.bytes().map_err(|_| Error::Codec)?, authority)?,
            witnesses: Witnesses {
                control: StateProof::decode(d.bytes().map_err(|_| Error::Codec)?)?,
                continuity: StateProof::decode(d.bytes().map_err(|_| Error::Codec)?)?,
            },
            policy: Policy::decode(d.bytes().map_err(|_| Error::Codec)?)?,
        };
        if d.position() != raw.len() || value.encode(authority)? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Book {
    records: BTreeMap<u64, Record>,
}
pub(crate) struct ArchivedControl {
    pub control: crate::membership_v2::Control,
    pub parent_height: u64,
    pub terminal: crate::retired_continuity_v2::Record,
}
impl Book {
    pub(crate) fn validate_generations(
        &self,
        registry: Option<&crate::recovery::ContinuityState>,
        keys: &crate::continuity_keys_v2::Book,
        retired: &crate::retired_continuity_v2::Book,
        height: u64,
    ) -> Result<()> {
        let current = keys
            .bindings()
            .map(|b| (b.admission().node, b.admission().key_generation))
            .collect();
        if self.is_empty() {
            return retired.validate_generations(&current, height);
        }
        let registry = registry.ok_or(Error::UnknownSigner)?;
        let index = self.index(registry.sequence(), height)?;
        let generations = retired
            .entries()
            .map(|r| {
                (
                    r.binding.admission.node,
                    r.binding.admission.key_generation,
                    r.retired_height,
                )
            })
            .collect::<Vec<_>>();
        retired.records()?;
        crate::recovery_history_index_v2::validate_generations(
            &index,
            &current,
            &generations,
            height,
        )
    }
    pub(crate) fn birth_parent_heights(&self) -> Result<BTreeMap<Hash, u64>> {
        let mut births = BTreeMap::new();
        for record in self.entries() {
            if births
                .insert(
                    record.material.binding.admission.node,
                    record.material.parent.height,
                )
                .is_some()
            {
                return Err(Error::Duplicate);
            }
        }
        Ok(births)
    }
    pub(crate) fn archived_controls(&self) -> Result<BTreeMap<Hash, ArchivedControl>> {
        let mut out = BTreeMap::new();
        for record in self.entries() {
            let m = &record.material;
            let retained = record.witnesses.verify(
                &m.parent,
                m.root,
                m.old_node,
                m.old_hardware_generation,
                m.old_key_generation,
                m.commitment()?,
            )?;
            let control = crate::membership_v2::Control::decode(&retained.control_bytes)?;
            if control.node() != m.old_node
                || out
                    .insert(
                        m.old_node,
                        ArchivedControl {
                            control,
                            parent_height: m.parent.height,
                            terminal: retained.terminal,
                        },
                    )
                    .is_some()
            {
                return Err(Error::Duplicate);
            }
        }
        Ok(out)
    }
    pub(crate) fn validate_state(&self, state: &crate::execution::State) -> Result<()> {
        if self.is_empty() {
            if state.recovery_authority_v2.is_some()
                && state
                    .continuity
                    .as_ref()
                    .is_some_and(|r| r.sequence() != 0 || r.last_recovery().is_some())
            {
                return Err(Error::StaleSequence);
            }
            return Ok(());
        }
        let authority = state
            .recovery_authority_v2
            .as_ref()
            .ok_or(Error::RecoveryDisabled)?;
        let registry = state.continuity.as_ref().ok_or(Error::UnknownSigner)?;
        self.records(authority)?;
        let index = self.index(registry.sequence(), state.accounting.slots.last_height)?;
        let last = self.records.last_key_value().ok_or(Error::StaleSequence)?.1;
        if registry.last_recovery() != Some(last.material.commitment()?) {
            return Err(Error::WrongAnchor);
        }
        for (lineage, node) in &index.current {
            if !registry
                .members
                .iter()
                .any(|m| m.lineage == *lineage && m.node == *node)
            {
                return Err(Error::InvalidLineage);
            }
        }
        if registry
            .members
            .iter()
            .any(|m| index.retired.contains_key(&m.node))
        {
            return Err(Error::WrongGeneration);
        }
        let terminal: BTreeMap<_, _> = state
            .retired_continuity_v2
            .entries()
            .map(|r| {
                (
                    (r.binding.admission.node, r.binding.admission.key_generation),
                    r,
                )
            })
            .collect();
        // The birth generation must be the exact binding authorized by this
        // recovery, whether it is still current or was subsequently retired.
        // An unrelated, otherwise valid admission cannot replace that edge.
        for record in self.entries() {
            let binding = &record.material.binding;
            let a = &binding.admission;
            let retained_birth = terminal
                .get(&(a.node, a.key_generation))
                .map(|r| &r.binding);
            let current_birth = state
                .membership_v2
                .get(a.node)
                .filter(|c| c.binding().admission.key_generation == a.key_generation)
                .map(|c| c.binding());
            match (current_birth, retained_birth) {
                (Some(birth), None) | (None, Some(birth)) if birth == binding => {}
                _ => return Err(Error::WrongGeneration),
            }
        }
        for (node, archive) in self.archived_controls()? {
            if terminal
                .get(&(node, archive.terminal.binding.admission.key_generation))
                .copied()
                != Some(&archive.terminal)
            {
                return Err(Error::WrongGeneration);
            }
        }
        Ok(())
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    pub(crate) fn entries(&self) -> impl Iterator<Item = &Record> {
        self.records.values()
    }
    pub(crate) fn index(
        &self,
        sequence: u64,
        height: u64,
    ) -> Result<crate::recovery_history_index_v2::Index> {
        let edges = self
            .records
            .values()
            .map(|r| {
                let m = &r.material;
                Ok(crate::recovery_history_index_v2::Edge {
                    sequence: m.sequence,
                    lineage: m.lineage,
                    old_node: m.old_node,
                    new_node: m.binding.admission.node,
                    old_hardware: m.old_hardware_generation,
                    new_hardware: m.binding.admission.hardware_generation,
                    old_key: m.old_key_generation,
                    new_key: m.binding.admission.key_generation,
                    committed_height: m.parent.height.checked_add(1).ok_or(Error::Overflow)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        crate::recovery_history_index_v2::index(&edges, sequence, height)
    }
    /// Tentative history only. Caller must still perform and atomically install
    /// the complete prospective transition with canonical conflict exclusion.
    pub fn stage(
        &self,
        record: Record,
        state: &crate::execution::State,
        parent: &crate::anchors::FinalizedAnchor,
        root: Hash,
        existing_valid_descendant: bool,
    ) -> Result<Self> {
        let authority = state
            .recovery_authority_v2
            .as_ref()
            .ok_or(Error::RecoveryDisabled)?;
        if self.records.len() >= crate::execution::MAX_STATE_RECORDS {
            return Err(Error::Capacity);
        }
        if record.policy != state.current_admission_policy_v2(parent.genesis, parent.fingerprint)? {
            return Err(Error::WrongAnchor);
        }
        record.material.verify_material(
            state,
            parent,
            root,
            &record.authorization,
            existing_valid_descendant,
        )?;
        record.verify_history_only(authority)?;
        let sequence = record.material.sequence;
        let mut next = self.clone();
        if next.records.insert(sequence, record).is_some() {
            return Err(Error::Duplicate);
        }
        next.index(
            sequence,
            parent.height.checked_add(1).ok_or(Error::Overflow)?,
        )?;
        next.records(authority)?;
        Ok(next)
    }
    pub fn records(&self, authority: &Authority) -> Result<BTreeMap<Hash, Vec<u8>>> {
        if self.records.len() > crate::execution::MAX_STATE_RECORDS {
            return Err(Error::Capacity);
        }
        let mut out = BTreeMap::new();
        for (sequence, record) in &self.records {
            if *sequence != record.material.sequence
                || out
                    .insert(record.key(), record.encode(authority)?)
                    .is_some()
            {
                return Err(Error::Duplicate);
            }
        }
        let sequence = self.records.keys().next_back().copied().unwrap_or(0);
        let height = self
            .records
            .values()
            .map(|r| {
                r.material
                    .parent
                    .height
                    .checked_add(1)
                    .ok_or(Error::Overflow)
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .max()
            .unwrap_or(0);
        self.index(sequence, height)?;
        Ok(out)
    }
    pub fn from_records(rows: &BTreeMap<Hash, Vec<u8>>, authority: &Authority) -> Result<Self> {
        if rows.len() > crate::execution::MAX_STATE_RECORDS {
            return Err(Error::Capacity);
        }
        let mut book = Self::default();
        for (key, raw) in rows {
            let record = Record::decode(raw, authority)?;
            if record.key() != *key
                || book
                    .records
                    .insert(record.material.sequence, record)
                    .is_some()
            {
                return Err(Error::Duplicate);
            }
        }
        if book.records(authority)? != *rows {
            return Err(Error::NonCanonical);
        }
        Ok(book)
    }
}
