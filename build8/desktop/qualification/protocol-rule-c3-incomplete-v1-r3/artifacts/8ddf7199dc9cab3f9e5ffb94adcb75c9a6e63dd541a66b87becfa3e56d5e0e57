//! Fresh Build8 license records and owner/Worker-authorized next-epoch binding.
use crate::{Error, Hash, NETWORK_ID, Result, domain_hash, transactions::address};
use ed25519_dalek::{Signature, VerifyingKey};
use minicbor::{Decoder, Encoder, data::Type};
use std::collections::BTreeMap;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseRecord {
    pub id: Hash,
    pub genesis: Hash,
    pub owner: Hash,
    pub issuance: Hash,
    pub index: u64,
    pub issue_height: u64,
    pub active_worker: Option<Hash>,
    pub assignment_sequence: u64,
}
impl LicenseRecord {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(9)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&self.id)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.owner)
            .unwrap()
            .bytes(&self.issuance)
            .unwrap()
            .u64(self.index)
            .unwrap()
            .u64(self.issue_height)
            .unwrap();
        if let Some(w) = self.active_worker {
            e.bytes(&w).unwrap();
        } else {
            e.null().unwrap();
        }
        e.u64(self.assignment_sequence).unwrap();
        e.into_writer()
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, 256)?;
        let mut d = Decoder::new(raw);
        let r = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            if d.array()? != Some(9) || d.u8()? != 1 {
                return Err(minicbor::decode::Error::message("license"));
            }
            Ok(Self {
                id: hash(&mut d)?,
                genesis: hash(&mut d)?,
                owner: hash(&mut d)?,
                issuance: hash(&mut d)?,
                index: d.u64()?,
                issue_height: d.u64()?,
                active_worker: if d.datatype()? == Type::Null {
                    d.null()?;
                    None
                } else {
                    Some(hash(&mut d)?)
                },
                assignment_sequence: d.u64()?,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if r.encode() != raw {
            return Err(Error::NonCanonical);
        }
        Ok(r)
    }
}
fn hash(d: &mut Decoder<'_>) -> std::result::Result<Hash, minicbor::decode::Error> {
    d.bytes()?
        .try_into()
        .map_err(|_| minicbor::decode::Error::message("hash"))
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindWorker {
    pub network: u32,
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub license: Hash,
    pub sequence: u64,
    pub valid_until_height: u64,
    pub owner_public: Hash,
    pub worker: Hash,
    pub worker_public: Hash,
    pub coordinator_public: Hash,
    pub effective_epoch: u64,
    pub owner_signature: [u8; 64],
    pub worker_signature: [u8; 64],
}
impl BindWorker {
    fn bytes(&self, signed: bool) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(if signed { 10 } else { 9 })
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(10)
            .unwrap()
            .u32(self.network)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .bytes(&self.license)
            .unwrap()
            .u64(self.sequence)
            .unwrap()
            .u64(self.valid_until_height)
            .unwrap()
            .array(5)
            .unwrap()
            .bytes(&self.owner_public)
            .unwrap()
            .bytes(&self.worker)
            .unwrap()
            .bytes(&self.worker_public)
            .unwrap()
            .bytes(&self.coordinator_public)
            .unwrap()
            .u64(self.effective_epoch)
            .unwrap();
        if signed {
            e.array(2)
                .unwrap()
                .bytes(&self.owner_signature)
                .unwrap()
                .bytes(&self.worker_signature)
                .unwrap();
        }
        e.into_writer()
    }
    pub fn encode(&self) -> Vec<u8> {
        self.bytes(true)
    }
    pub fn signing_digest(&self, worker: bool) -> Hash {
        domain_hash(
            if worker {
                b"MUTINY-BUILD8-WORKER-POSSESSION-V1"
            } else {
                b"MUTINY-BUILD8-LICENSE-BIND-V1"
            },
            &self.bytes(false),
        )
    }
    pub fn worker_id(&self) -> Hash {
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(1)
            .unwrap()
            .u32(self.network)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.license)
            .unwrap()
            .bytes(&self.worker_public)
            .unwrap();
        domain_hash(b"MUTINY-BUILD8-WORKER-ID-V1", &e.into_writer())
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, 1024)?;
        let mut d = Decoder::new(raw);
        let b = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            if d.array()? != Some(10) || d.u8()? != 1 || d.u8()? != 10 {
                return Err(minicbor::decode::Error::message("bind"));
            }
            let network = d.u32()?;
            let genesis = hash(&mut d)?;
            let fingerprint = hash(&mut d)?;
            let license = hash(&mut d)?;
            let sequence = d.u64()?;
            let valid_until_height = d.u64()?;
            if d.array()? != Some(5) {
                return Err(minicbor::decode::Error::message("payload"));
            }
            let owner_public = hash(&mut d)?;
            let worker = hash(&mut d)?;
            let worker_public = hash(&mut d)?;
            let coordinator_public = hash(&mut d)?;
            let effective_epoch = d.u64()?;
            if d.array()? != Some(2) {
                return Err(minicbor::decode::Error::message("signatures"));
            }
            let owner_signature = d
                .bytes()?
                .try_into()
                .map_err(|_| minicbor::decode::Error::message("signature"))?;
            let worker_signature = d
                .bytes()?
                .try_into()
                .map_err(|_| minicbor::decode::Error::message("signature"))?;
            Ok(Self {
                network,
                genesis,
                fingerprint,
                license,
                sequence,
                valid_until_height,
                owner_public,
                worker,
                worker_public,
                coordinator_public,
                effective_epoch,
                owner_signature,
                worker_signature,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if b.encode() != raw {
            return Err(Error::NonCanonical);
        }
        Ok(b)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveWorker {
    pub binding: BindWorker,
    pub last_accepted_ticket: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LicenseBook {
    pub licenses: BTreeMap<Hash, LicenseRecord>,
    pub workers: BTreeMap<Hash, ActiveWorker>,
    pub pending: BTreeMap<Hash, BindWorker>,
}
impl LicenseBook {
    /// Two-phase Genesis construction: identity is already fixed. All twelve
    /// bindings use normal owner/Worker proof and generation arithmetic. This
    /// pure constructor cannot mutate a sealed chain or substitute a miner.
    /// Physical inventory/enrollment qualification remains a ceremony gate.
    pub fn genesis_bindings(
        genesis: Hash,
        fingerprint: Hash,
        owner: Hash,
        purchase: Hash,
        bindings: &[BindWorker],
    ) -> Result<Self> {
        if bindings.len() != 12 {
            return Err(Error::InvalidCounter);
        }
        let mut book = Self::default();
        for index in 0..12 {
            let id = crate::blocks::genesis_license(genesis, index)?;
            book.licenses.insert(
                id,
                LicenseRecord {
                    id,
                    genesis,
                    owner,
                    issuance: purchase,
                    index,
                    issue_height: 0,
                    active_worker: None,
                    assignment_sequence: 0,
                },
            );
        }
        for b in bindings {
            if b.effective_epoch != 0 || b.valid_until_height != 0 {
                return Err(Error::InvalidCounter);
            }
            book.validate_binding(b, genesis, fingerprint, 0)?;
            book.pending.insert(b.license, b.clone());
        }
        book.activate_due(0)?;
        if book.workers.len() != 12 || book.licenses.values().any(|l| l.active_worker.is_none()) {
            return Err(Error::InvalidCounter);
        }
        book.records()?;
        Ok(book)
    }
    /// Canonical records include pending changes and numeric ticket high-water
    /// marks. They never contain the current AuthorityID/BlockHash: either would
    /// create a cycle through the candidate's post-StateRoot.
    pub fn records(&self) -> Result<BTreeMap<Hash, Vec<u8>>> {
        let mut records = BTreeMap::new();
        for (id, l) in &self.licenses {
            if *id != l.id {
                return Err(Error::WrongAnchor);
            }
            if let Some(worker) = l.active_worker {
                let w = self.workers.get(&worker).ok_or(Error::WrongAnchor)?;
                if w.binding.license != *id || w.binding.sequence != l.assignment_sequence {
                    return Err(Error::WrongAnchor);
                }
            }
            records.insert(
                domain_hash(b"MUTINY-BUILD8-LICENSE-STATE-KEY-V1", id),
                l.encode(),
            );
        }
        for (id, w) in &self.workers {
            if *id != w.binding.worker_id()
                || w.binding.worker != *id
                || !self.licenses.contains_key(&w.binding.license)
            {
                return Err(Error::WrongAnchor);
            }
            let mut e = Encoder::new(Vec::new());
            e.array(3)
                .unwrap()
                .u8(1)
                .unwrap()
                .bytes(&w.binding.encode())
                .unwrap()
                .u64(w.last_accepted_ticket)
                .unwrap();
            if records
                .insert(
                    domain_hash(b"MUTINY-BUILD8-WORKER-STATE-KEY-V1", id),
                    e.into_writer(),
                )
                .is_some()
            {
                return Err(Error::Duplicate);
            }
        }
        for (id, b) in &self.pending {
            if *id != b.license || !self.licenses.contains_key(id) {
                return Err(Error::WrongAnchor);
            }
            if records
                .insert(
                    domain_hash(b"MUTINY-BUILD8-PENDING-BIND-KEY-V1", id),
                    b.encode(),
                )
                .is_some()
            {
                return Err(Error::Duplicate);
            }
        }
        Ok(records)
    }

    pub fn schedule(
        &mut self,
        b: BindWorker,
        genesis: Hash,
        fingerprint: Hash,
        height: u64,
        epoch: u64,
    ) -> Result<()> {
        self.validate_binding(&b, genesis, fingerprint, height)?;
        if b.effective_epoch != epoch.checked_add(1).ok_or(Error::Overflow)? {
            return Err(Error::StaleSequence);
        }
        self.pending.insert(b.license, b);
        Ok(())
    }
    fn validate_binding(
        &self,
        b: &BindWorker,
        genesis: Hash,
        fingerprint: Hash,
        height: u64,
    ) -> Result<()> {
        if b.network != NETWORK_ID {
            return Err(Error::WrongNetwork);
        }
        if b.genesis != genesis {
            return Err(Error::WrongGenesis);
        }
        if b.fingerprint != fingerprint {
            return Err(Error::WrongFingerprint);
        }
        let l = self.licenses.get(&b.license).ok_or(Error::WrongAnchor)?;
        if l.genesis != genesis || l.owner != address(&b.owner_public) || b.worker != b.worker_id()
        {
            return Err(Error::WrongAnchor);
        }
        if b.sequence
            != l.assignment_sequence
                .checked_add(1)
                .ok_or(Error::Overflow)?
            || height > b.valid_until_height
        {
            return Err(Error::StaleSequence);
        }
        if self.pending.contains_key(&b.license)
            || self
                .workers
                .values()
                .any(|w| w.binding.worker_public == b.worker_public)
            || self
                .pending
                .values()
                .any(|w| w.worker_public == b.worker_public)
        {
            return Err(Error::Duplicate);
        }
        for (worker, public, sig) in [
            (false, b.owner_public, b.owner_signature),
            (true, b.worker_public, b.worker_signature),
        ] {
            VerifyingKey::from_bytes(&public)
                .map_err(|_| Error::BadSignature)?
                .verify_strict(&b.signing_digest(worker), &Signature::from_bytes(&sig))
                .map_err(|_| Error::BadSignature)?;
        }
        Ok(())
    }
    /// Apply to a candidate-state copy using its canonical Genesis-relative epoch.
    /// A timestamp moving backward never rolls back an already committed binding.
    pub fn activate_due(&mut self, epoch: u64) -> Result<()> {
        let due: Vec<_> = self
            .pending
            .values()
            .filter(|b| b.effective_epoch <= epoch)
            .cloned()
            .collect();
        for b in &due {
            let l = self.licenses.get(&b.license).ok_or(Error::WrongAnchor)?;
            if l.owner != address(&b.owner_public)
                || l.assignment_sequence.checked_add(1) != Some(b.sequence)
            {
                return Err(Error::StaleSequence);
            }
        }
        for b in due {
            let id = b.worker_id();
            let l = self
                .licenses
                .get_mut(&b.license)
                .ok_or(Error::WrongAnchor)?;
            l.active_worker = Some(id);
            l.assignment_sequence = b.sequence;
            self.pending.remove(&b.license);
            self.workers.insert(
                id,
                ActiveWorker {
                    binding: b,
                    last_accepted_ticket: 0,
                },
            );
        }
        Ok(())
    }
    pub fn active(
        &self,
        license: Hash,
        worker: Hash,
        epoch: u64,
    ) -> Result<(&LicenseRecord, &ActiveWorker)> {
        let l = self.licenses.get(&license).ok_or(Error::WrongAnchor)?;
        let w = self.workers.get(&worker).ok_or(Error::WrongAnchor)?;
        if l.active_worker != Some(worker)
            || w.binding.license != license
            || w.binding.sequence != l.assignment_sequence
            || epoch < w.binding.effective_epoch
        {
            return Err(Error::StaleSequence);
        }
        Ok((l, w))
    }
}
