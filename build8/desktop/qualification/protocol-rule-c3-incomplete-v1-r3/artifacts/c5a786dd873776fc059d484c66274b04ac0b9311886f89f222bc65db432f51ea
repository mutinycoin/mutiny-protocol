//! Authenticated retired hybrid binding evidence; retirement is not slashing.
use crate::{Error, Hash, NETWORK_ID, Result, domain_hash, node_admission_v2::Binding};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::{Domain, PublicKey, Role};
use std::collections::BTreeMap;
pub const MAX_RECORD: usize = crate::node_admission_v2::MAX_BINDING_BYTES + 2048 + 128;
pub(crate) fn is_record(raw: &[u8]) -> bool {
    let mut d = Decoder::new(raw);
    d.array().ok().flatten().is_some() && d.u8().ok() == Some(2) && d.u8().ok() == Some(55)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub binding: Binding,
    pub owner_descriptor: Vec<u8>,
    pub retired_height: u64,
    pub rotation: Hash,
}
impl Record {
    pub fn key(&self) -> Hash {
        let mut e = Encoder::new(Vec::new());
        e.array(2)
            .unwrap()
            .bytes(&self.binding.admission.node)
            .unwrap()
            .u64(self.binding.admission.key_generation)
            .unwrap();
        domain_hash(b"MUTINY-BUILD8-RETIRED-CONTINUITY-KEY-V2", &e.into_writer())
    }
    /// Historical cryptographic validity only. The authenticated canonical
    /// transition establishes retirement height and operation identity.
    /// This verifier neither authorizes a new admission nor revives old keys.
    pub fn verify_evidence(&self) -> Result<()> {
        let a = &self.binding.admission;
        if self.retired_height == 0
            || self.rotation == [0; 32]
            || self.owner_descriptor.len() > 2048
        {
            return Err(Error::InvalidCounter);
        }
        self.binding.encode()?;
        let (owner, generation) =
            PublicKey::decode_descriptor(&self.owner_descriptor).map_err(|_| Error::Codec)?;
        let (continuity, _) =
            PublicKey::decode_descriptor(&a.continuity_descriptor).map_err(|_| Error::Codec)?;
        let (node, _) = PublicKey::decode_descriptor(self.binding.signer_descriptor())
            .map_err(|_| Error::Codec)?;
        if owner.role != Role::WalletOwner
            || owner.address_id(generation).map_err(|_| Error::Codec)? != a.owner
        {
            return Err(Error::BadSignature);
        }
        if owner.ed448 == continuity.ed448
            || owner.fndsa == continuity.fndsa
            || owner.ed448 == node.ed448
            || owner.fndsa == node.fndsa
            || continuity.ed448 == node.ed448
            || continuity.fndsa == node.fndsa
        {
            return Err(Error::Duplicate);
        }
        owner
            .verify(
                Domain::PhysicalAdmission,
                &a.owner_payload()?,
                &a.authorization,
            )
            .map_err(|_| Error::BadSignature)?;
        continuity
            .verify(Domain::ContinuityPossession, &a.body()?, &a.possession)
            .map_err(|_| Error::BadSignature)?;
        node.verify(
            Domain::NodeAdmissionPossession,
            &self.binding.body()?,
            &self.binding.possession,
        )
        .map_err(|_| Error::BadSignature)?;
        let profile = crate::tpm::TpmProfile::decode(&a.profile)?;
        if profile.hardware == [0; 32] || profile.admission_trust_manifest == [0; 32] {
            return Err(Error::UnqualifiedPhysical);
        }
        profile.verify_quote(a.challenge()?, &a.quote)?;
        Ok(())
    }
    /// The class rule over retained (retired) evidence; `State::records` applies it to every
    /// retired binding in the Production class (`roots`: immutable V2 policy roots).
    pub(crate) fn check_class(
        &self,
        class: crate::provenance::AdmissionClass,
        roots: &std::collections::BTreeSet<Hash>,
    ) -> Result<()> {
        let a = &self.binding.admission;
        let profile = crate::tpm::TpmProfile::decode(&a.profile)?;
        crate::provenance::check_profile(class, &profile, a.endorsement_root, roots)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.verify_evidence()?;
        let mut e = Encoder::new(Vec::new());
        e.array(7)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(55)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.binding.encode()?)
            .unwrap()
            .bytes(&self.owner_descriptor)
            .unwrap()
            .u64(self.retired_height)
            .unwrap()
            .bytes(&self.rotation)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_RECORD {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_RECORD)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(|_| Error::Codec)? != Some(7)
            || d.u8().map_err(|_| Error::Codec)? != 2
            || d.u8().map_err(|_| Error::Codec)? != 55
            || d.u32().map_err(|_| Error::Codec)? != NETWORK_ID
        {
            return Err(Error::Codec);
        }
        let value = Self {
            binding: Binding::decode(d.bytes().map_err(|_| Error::Codec)?)?,
            owner_descriptor: d.bytes().map_err(|_| Error::Codec)?.to_vec(),
            retired_height: d.u64().map_err(|_| Error::Codec)?,
            rotation: d
                .bytes()
                .map_err(|_| Error::Codec)?
                .try_into()
                .map_err(|_| Error::Codec)?,
        };
        if d.position() != raw.len() || value.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Book {
    retired: BTreeMap<(Hash, u64), Record>,
}
impl Book {
    pub(crate) fn entries(&self) -> impl Iterator<Item = &Record> {
        self.retired.values()
    }
    pub fn is_empty(&self) -> bool {
        self.retired.is_empty()
    }
    /// Caller must derive `record` from the authenticated prior binding after
    /// verifying the rotation. A standalone record is not authorization.
    pub fn stage_retire(&self, record: Record) -> Result<Self> {
        record.verify_evidence()?;
        if self.retired.len() >= crate::execution::MAX_STATE_RECORDS {
            return Err(Error::Capacity);
        }
        let mut next = self.clone();
        let a = &record.binding.admission;
        if next
            .retired
            .insert((a.node, a.key_generation), record)
            .is_some()
        {
            return Err(Error::Duplicate);
        }
        Ok(next)
    }
    pub fn records(&self) -> Result<BTreeMap<Hash, Vec<u8>>> {
        if self.retired.len() > crate::execution::MAX_STATE_RECORDS {
            return Err(Error::Capacity);
        }
        self.retired
            .values()
            .map(|r| Ok((r.key(), r.encode()?)))
            .collect()
    }
    pub fn from_records(records: &BTreeMap<Hash, Vec<u8>>) -> Result<Self> {
        if records.len() > crate::execution::MAX_STATE_RECORDS {
            return Err(Error::Capacity);
        }
        let mut book = Self::default();
        for (key, raw) in records {
            let r = Record::decode(raw)?;
            if r.key() != *key {
                return Err(Error::WrongAnchor);
            }
            let a = &r.binding.admission;
            if book.retired.insert((a.node, a.key_generation), r).is_some() {
                return Err(Error::Duplicate);
            }
        }
        if &book.records()? != records {
            return Err(Error::NonCanonical);
        }
        Ok(book)
    }
    /// Map must be projected from the same authenticated current key book.
    /// No scan up to an attacker-supplied u64: work is bounded by record count.
    pub fn validate_generations(&self, current: &BTreeMap<Hash, u64>, height: u64) -> Result<()> {
        let mut previous = BTreeMap::<Hash, (u64, u64)>::new();
        for ((node, generation), r) in &self.retired {
            if r.binding.admission.node != *node
                || r.binding.admission.key_generation != *generation
                || r.retired_height > height
            {
                return Err(Error::WrongGeneration);
            }
            let (last, last_height) = previous.get(node).copied().unwrap_or((0, 0));
            if last.checked_add(1) != Some(*generation)
                || r.retired_height <= last_height
                || current.get(node).is_none_or(|g| g <= generation)
            {
                return Err(Error::WrongGeneration);
            }
            previous.insert(*node, (*generation, r.retired_height));
        }
        for (node, generation) in current {
            let last = previous.get(node).map_or(0, |v| v.0);
            if last.checked_add(1) != Some(*generation) {
                return Err(Error::WrongGeneration);
            }
        }
        self.records()?;
        Ok(())
    }
    /// New Continuity key halves cannot reuse retained Continuity, owner or
    /// Node authentication public material, even after it leaves current state.
    pub fn reject_reused(&self, replacement: &PublicKey) -> Result<()> {
        for r in self.retired.values() {
            for descriptor in [
                &r.binding.admission.continuity_descriptor,
                &r.owner_descriptor,
                &r.binding.node_descriptor,
                r.binding.signer_descriptor(),
            ] {
                let (old, _) =
                    PublicKey::decode_descriptor(descriptor).map_err(|_| Error::Codec)?;
                if replacement.ed448 == old.ed448 || replacement.fndsa == old.fndsa {
                    return Err(Error::Duplicate);
                }
            }
        }
        Ok(())
    }
    /// A previous physical machine cannot be reassigned to another lineage;
    /// a retired native identity key cannot be revived even within its lineage.
    pub(crate) fn reject_physical_reuse(
        &self,
        node: Hash,
        profile: &crate::tpm::TpmProfile,
    ) -> Result<()> {
        let key = crate::tpm::public_key(&profile.voting_public, false)?;
        for retired in self.entries() {
            let old = crate::tpm::TpmProfile::decode(&retired.binding.admission.profile)?;
            if crate::tpm::public_key(&old.voting_public, false)? == key
                || (retired.binding.admission.node != node && old.hardware == profile.hardware)
            {
                return Err(Error::Duplicate);
            }
            // Order A4: the same rule for every committed endorsement identity.
            if retired.binding.admission.node != node {
                crate::endorsement_identity::reject_shared_identity(profile, [&old])?;
            }
        }
        Ok(())
    }
}
