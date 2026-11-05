//! Staged authenticated history. Decoding checks evidence, not parent authority;
//! only stage() validates an operation against independently trusted controls.
use crate::{node_key_rotate_v2::NodeKeyRotate, *};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::PublicKey;
use std::collections::BTreeMap;
pub(crate) fn is_record(raw: &[u8]) -> bool {
    let mut d = Decoder::new(raw);
    d.array().ok().flatten().is_some() && d.u8().ok() == Some(2) && d.u8().ok() == Some(56)
}
const MAX_RECORD: usize = 16 * 1024 + 32;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub operation: NodeKeyRotate,
}
impl Record {
    pub fn key(&self) -> Result<Hash> {
        let (_, g) =
            PublicKey::decode_descriptor(&self.operation.proposed).map_err(|_| Error::Codec)?;
        let mut e = Encoder::new(Vec::new());
        e.array(2)
            .unwrap()
            .bytes(&self.operation.node)
            .unwrap()
            .u64(g)
            .unwrap();
        Ok(domain_hash(
            b"MUTINY-BUILD8-NODE-KEY-HISTORY-V2",
            &e.into_writer(),
        ))
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.operation.verify_signatures()?;
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(56)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.operation.encode()?)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_RECORD {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        blocks::canonical(raw, MAX_RECORD)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(|_| Error::Codec)? != Some(4)
            || d.u8().map_err(|_| Error::Codec)? != 2
            || d.u8().map_err(|_| Error::Codec)? != 56
            || d.u32().map_err(|_| Error::Codec)? != NETWORK_ID
        {
            return Err(Error::Codec);
        }
        let value = Self {
            operation: NodeKeyRotate::decode(d.bytes().map_err(|_| Error::Codec)?)?,
        };
        if d.position() != raw.len() || value.encode() != Ok(raw.to_vec()) {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Book {
    records: BTreeMap<(Hash, u64), Record>,
}
impl Book {
    /// Exact retired authentication material cannot authorize fresh work even
    /// when an older Worker assignment still pins that descriptor.
    pub fn is_retired_descriptor(&self, descriptor: &[u8]) -> bool {
        self.entries().any(|r| r.operation.current == descriptor)
    }
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    pub fn entries(&self) -> impl Iterator<Item = &Record> {
        self.records.values()
    }
    /// Used only after resolve() validates the entire retained chain.
    fn descriptor_at(&self, node: Hash, initial: &[u8], height: u64) -> Result<Vec<u8>> {
        let mut current = initial.to_vec();
        for (_, record) in self.records.range((node, 0)..=(node, u64::MAX)) {
            let inclusion = record
                .operation
                .parent
                .height
                .checked_add(1)
                .ok_or(Error::Overflow)?;
            if inclusion > height {
                break;
            }
            current = record.operation.proposed.clone();
        }
        Ok(current)
    }
    /// Structural replay checks complement, and never replace, canonical
    /// operation validation against each historical parent state.
    pub(crate) fn validate_state(&self, state: &execution::State) -> Result<()> {
        if state.membership_v2.is_empty() {
            return if self.is_empty() {
                Ok(())
            } else {
                Err(Error::UnknownSigner)
            };
        }
        let registry = state.continuity.as_ref().ok_or(Error::UnknownSigner)?;
        let anchor = anchors::FinalizedAnchor {
            network: NETWORK_ID,
            genesis: registry.genesis,
            fingerprint: registry.fingerprint,
            height: state.accounting.slots.last_height,
            block: registry.anchor.tip,
        };
        let archives = state.recovery_history_v2.archived_controls()?;
        let births = state.recovery_history_v2.birth_parent_heights()?;
        let mut controls = state
            .membership_v2
            .controls()
            .map(|c| (c.node(), c))
            .collect::<BTreeMap<_, _>>();
        for (node, archive) in &archives {
            if controls.insert(*node, &archive.control).is_some() {
                return Err(Error::Duplicate);
            }
        }
        for record in self.entries() {
            let control = controls
                .get(&record.operation.node)
                .copied()
                .ok_or(Error::UnknownSigner)?;
            if archives.get(&record.operation.node).is_some_and(|a| {
                record
                    .operation
                    .parent
                    .height
                    .checked_add(1)
                    .is_none_or(|h| h > a.parent_height)
            }) {
                return Err(Error::WrongGeneration);
            }
            if record.operation.sequence > control.sequence()
                || record.operation.hardware_generation > control.generation()
                || record.operation.parent.height < control.admitted_height()
                || births
                    .get(&control.node())
                    .is_some_and(|h| record.operation.parent.height < *h)
            {
                return Err(Error::WrongGeneration);
            }
        }
        let mut node_ed = BTreeMap::new();
        let mut node_pq = BTreeMap::new();
        let descriptors = controls
            .values()
            .map(|c| (c.node(), c.binding().node_descriptor.as_slice()))
            .chain(
                self.entries()
                    .map(|r| (r.operation.node, r.operation.proposed.as_slice())),
            );
        for (node, descriptor) in descriptors {
            let (key, generation) =
                PublicKey::decode_descriptor(descriptor).map_err(|_| Error::Codec)?;
            if node_ed.insert(key.ed448, (node, generation)).is_some()
                || node_pq.insert(key.fndsa, (node, generation)).is_some()
            {
                return Err(Error::Duplicate);
            }
        }
        let other_descriptors = state
            .wallets
            .public_descriptors()
            .chain(state.continuity_keys_v2.bindings().flat_map(|b| {
                [
                    b.owner_descriptor(),
                    b.admission().continuity_descriptor.as_slice(),
                ]
            }))
            .chain(state.retired_continuity_v2.entries().flat_map(|r| {
                [
                    r.owner_descriptor.as_slice(),
                    r.binding.admission.continuity_descriptor.as_slice(),
                ]
            }));
        for descriptor in other_descriptors {
            let (key, _) = PublicKey::decode_descriptor(descriptor).map_err(|_| Error::Codec)?;
            if node_ed.contains_key(&key.ed448) || node_pq.contains_key(&key.fndsa) {
                return Err(Error::Duplicate);
            }
        }
        for control in controls.values() {
            let origin = &control.binding().node_descriptor;
            if self.resolve(control.node(), origin, &anchor)? != control.current_node_descriptor() {
                return Err(Error::WrongGeneration);
            }
            let mut bindings: Vec<_> = state
                .retired_continuity_v2
                .entries()
                .filter(|r| {
                    r.binding.admission.node == control.node()
                        && r.binding.admission.key_generation
                            < control.binding().admission.key_generation
                })
                .collect();
            bindings.sort_by_key(|r| r.binding.admission.key_generation);
            let mut created = control.admitted_height();
            if let Some(birth) = births.get(&control.node()) {
                created = created.max(birth.checked_add(1).ok_or(Error::Overflow)?);
            }
            for record in bindings {
                if record.binding.node_descriptor != *origin
                    || self.descriptor_at(control.node(), origin, created.saturating_sub(1))?
                        != record.binding.signer_descriptor()
                {
                    return Err(Error::WrongGeneration);
                }
                created = record.retired_height;
            }
            if self.descriptor_at(control.node(), origin, created.saturating_sub(1))?
                != control.binding().signer_descriptor()
            {
                return Err(Error::WrongGeneration);
            }
        }
        Ok(())
    }

    pub fn stage(
        &self,
        op: &NodeKeyRotate,
        parent: &anchors::FinalizedAnchor,
        control: &continuity_exit_v2::ParentControl<'_>,
        wallets: &wallet_authority_v1::WalletBook,
        initial: &[u8],
    ) -> Result<Self> {
        op.verify(parent, control, wallets)?;
        if self.resolve(op.node, initial, parent)? != op.current {
            return Err(Error::WrongGeneration);
        }
        let (replacement, g) =
            PublicKey::decode_descriptor(&op.proposed).map_err(|_| Error::Codec)?;
        self.reject_reused(&replacement)?;
        if self.records.len() >= execution::MAX_STATE_RECORDS {
            return Err(Error::Capacity);
        }
        let mut next = self.clone();
        if next
            .records
            .insert(
                (op.node, g),
                Record {
                    operation: op.clone(),
                },
            )
            .is_some()
        {
            return Err(Error::Duplicate);
        }
        next.records()?;
        Ok(next)
    }
    pub fn reject_reused(&self, key: &PublicKey) -> Result<()> {
        for r in self.records.values() {
            for desc in [
                &r.operation.current,
                &r.operation.proposed,
                &r.operation.authorizer,
            ] {
                let (old, _) = PublicKey::decode_descriptor(desc).map_err(|_| Error::Codec)?;
                if key.ed448 == old.ed448 || key.fndsa == old.fndsa {
                    return Err(Error::Duplicate);
                }
            }
        }
        Ok(())
    }
    pub fn resolve(
        &self,
        node: Hash,
        initial: &[u8],
        parent: &anchors::FinalizedAnchor,
    ) -> Result<Vec<u8>> {
        let (_, generation) = PublicKey::decode_descriptor(initial).map_err(|_| Error::Codec)?;
        if generation != 1 || node_admission_v2::node_id(parent.genesis, initial)? != node {
            return Err(Error::WrongAnchor);
        }
        let mut current = initial.to_vec();
        let mut last_height = 0;
        let mut last_sequence = 0;
        let mut last_hardware = 1;
        for ((_, generation), record) in self.records.range((node, 0)..=(node, u64::MAX)) {
            record.encode()?;
            let op = &record.operation;
            op.parent
                .validate_context(parent.genesis, parent.fingerprint)?;
            let height = op.parent.height.checked_add(1).ok_or(Error::Overflow)?;
            let (_, g) = PublicKey::decode_descriptor(&op.proposed).map_err(|_| Error::Codec)?;
            if op.node != node
                || g != *generation
                || op.current != current
                || height > parent.height
                || height <= last_height
                || op.sequence <= last_sequence
                || op.hardware_generation < last_hardware
            {
                return Err(Error::WrongGeneration);
            }
            current = op.proposed.clone();
            last_height = height;
            last_sequence = op.sequence;
            last_hardware = op.hardware_generation;
        }
        Ok(current)
    }
    pub fn records(&self) -> Result<BTreeMap<Hash, Vec<u8>>> {
        if self.records.len() > execution::MAX_STATE_RECORDS {
            return Err(Error::Capacity);
        }
        self.records
            .values()
            .map(|r| Ok((r.key()?, r.encode()?)))
            .collect()
    }
    pub fn from_records(rows: &BTreeMap<Hash, Vec<u8>>) -> Result<Self> {
        if rows.len() > execution::MAX_STATE_RECORDS {
            return Err(Error::Capacity);
        }
        let mut book = Self::default();
        for (key, raw) in rows {
            let r = Record::decode(raw)?;
            if r.key()? != *key {
                return Err(Error::WrongAnchor);
            }
            let (_, g) =
                PublicKey::decode_descriptor(&r.operation.proposed).map_err(|_| Error::Codec)?;
            if book.records.insert((r.operation.node, g), r).is_some() {
                return Err(Error::Duplicate);
            }
        }
        if book.records()? != *rows {
            return Err(Error::NonCanonical);
        }
        Ok(book)
    }
}
