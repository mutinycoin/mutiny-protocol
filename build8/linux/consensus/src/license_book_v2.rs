//! Canonical V2 assignment state. Callers execute on a tentative copy and commit
//! only after certified finality. Historical Worker keys remain recorded.
use crate::{
    Error, Hash, Result, domain_hash,
    license_assignment_v2::{Assignment, ParentContext, verify_genesis_set},
    licenses::LicenseRecord,
    pow::{WorkContext, WorkHeader},
    wallet_authority_v1::WalletBook,
    work_authority_v2::Authority,
};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::enrollment::Binding;
use std::collections::{BTreeMap, BTreeSet};
const LICENSE_DOMAIN: &[u8] = b"MUTINY-BUILD8-LICENSE-STATE-KEY-V2";
const WORKER_DOMAIN: &[u8] = b"MUTINY-BUILD8-WORKER-STATE-KEY-V2";
const PENDING_DOMAIN: &[u8] = b"MUTINY-BUILD8-PENDING-BIND-KEY-V2";
const MAX_RECORD: usize = 8448;
/// Canonical Worker-assignment id: WP-P0's `op_envelope_v1::assignment_id` (design 9.1).
fn assignment_id(a: &Assignment) -> Result<Hash> {
    crate::op_envelope_v1::assignment_id(a).map_err(|_| Error::Codec)
}
#[cfg(test)]
use crate::op_envelope_v1::ASSIGNMENT_ID_DOMAIN;
/// Reserve V2 typed tags even when a malformed record carries the wrong key or
/// array length; it must not fall through as an opaque protocol record.
pub(crate) fn is_record(raw: &[u8]) -> bool {
    let mut d = Decoder::new(raw);
    d.array().ok().flatten().is_some()
        && d.u8().ok() == Some(2)
        && matches!(d.u8().ok(), Some(40..=42))
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Worker {
    pub assignment: Assignment,
    pub last_accepted_ticket: u64,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Book {
    licenses: BTreeMap<Hash, LicenseRecord>,
    workers: BTreeMap<Hash, Worker>,
    pending: BTreeMap<Hash, Assignment>,
}
/// The verified sale terms `Book::transfer` enforces. Private: production code reaches the
/// transfer only through the capability-typed `transfer_candidate`; the trait lets this
/// module's tests drive exactly the same checks and effects (`license_book_v2_sale_tests.rs`).
trait SaleTerms {
    fn license(&self) -> Hash;
    fn genesis(&self) -> Hash;
    fn from(&self) -> Hash;
    fn to(&self) -> Hash;
    fn expected_assignment_sequence(&self) -> u64;
    fn new_assignment_sequence(&self) -> u64;
    fn inclusion_height(&self) -> u64;
    fn rights_from_height(&self) -> u64;
    fn operation(&self) -> Hash;
    fn trade(&self) -> Hash;
    fn contract(&self) -> Hash;
    fn generation(&self) -> u64;
    fn payment_commitment(&self) -> Hash;
}
impl SaleTerms for crate::trading_v1::VerifiedLicenseTransferCandidate {
    fn license(&self) -> Hash {
        Self::license(self)
    }
    fn genesis(&self) -> Hash {
        Self::genesis(self)
    }
    fn from(&self) -> Hash {
        Self::from(self)
    }
    fn to(&self) -> Hash {
        Self::to(self)
    }
    fn expected_assignment_sequence(&self) -> u64 {
        Self::expected_assignment_sequence(self)
    }
    fn new_assignment_sequence(&self) -> u64 {
        Self::new_assignment_sequence(self)
    }
    fn inclusion_height(&self) -> u64 {
        Self::inclusion_height(self)
    }
    fn rights_from_height(&self) -> u64 {
        Self::rights_from_height(self)
    }
    fn operation(&self) -> Hash {
        Self::operation(self)
    }
    fn trade(&self) -> Hash {
        Self::trade(self)
    }
    fn contract(&self) -> Hash {
        Self::contract(self)
    }
    fn generation(&self) -> u64 {
        Self::generation(self)
    }
    fn payment_commitment(&self) -> Hash {
        Self::payment_commitment(self)
    }
}
impl Book {
    /// Read-only cross-record inspection; this does not authenticate the Book.
    /// State serialization/restoration retains its ordinary Book::records /
    /// Book::validate checks. Avoid re-encoding every signed Worker assignment
    /// merely to inspect already-typed License fields in the empty namespace.
    pub(crate) fn candidate_license_records(&self) -> impl Iterator<Item = &LicenseRecord> {
        self.licenses.values()
    }

    /// Nonproduction DvP hook; called only with native verified capability and
    /// on a tentative State copy. Full-State typed validation is mandatory.
    /// Returns the canonical id (`assignment_id`) of the old-owner pending assignment the
    /// sale cancelled, or `None`; the caller must require it to equal the pending
    /// assignment the sale committed to and reject a mismatch (P-LANE-DESIGN-V1 6.6).
    pub(crate) fn transfer_candidate(
        &mut self,
        r: &crate::trading_v1::VerifiedLicenseTransferCandidate,
    ) -> Result<Option<Hash>> {
        self.transfer(r)
    }
    /// Restart Order L64 (Order Q17): old Worker authority and old-owner pending assignments
    /// become invalid at the sale. The active Worker is detached (its record and key remain as
    /// history), a pending assignment of the sold License is REMOVED so that it never activates,
    /// and the assignment sequence takes the signed next value. Every check precedes any effect.
    fn transfer(&mut self, r: &impl SaleTerms) -> Result<Option<Hash>> {
        self.validate()?;
        let l = self.licenses.get(&r.license()).ok_or(Error::WrongAnchor)?;
        if l.genesis != r.genesis()
            || l.owner != r.from()
            || r.from() == r.to()
            || l.assignment_sequence != r.expected_assignment_sequence()
            || l.assignment_sequence.checked_add(1) != Some(r.new_assignment_sequence())
            || r.inclusion_height().checked_add(1) != Some(r.rights_from_height())
            || r.operation() == [0; 32]
            || r.trade() == [0; 32]
            || r.contract() == [0; 32]
            || r.generation() == 0
            || r.payment_commitment() == [0; 32]
        {
            return Err(Error::WrongAnchor);
        }
        let mut next = self.clone();
        let cancelled = match next.pending.remove(&r.license()) {
            Some(assignment) => Some(assignment_id(&assignment)?),
            None => None,
        };
        let l = next
            .licenses
            .get_mut(&r.license())
            .ok_or(Error::WrongAnchor)?;
        l.owner = r.to();
        l.active_worker = None;
        l.assignment_sequence = r.new_assignment_sequence();
        next.validate()?;
        *self = next;
        Ok(cancelled)
    }
    pub(crate) fn assignments(&self) -> impl Iterator<Item = &Assignment> {
        self.workers
            .values()
            .map(|w| &w.assignment)
            .chain(self.pending.values())
    }

    pub fn is_empty(&self) -> bool {
        self.licenses.is_empty() && self.workers.is_empty() && self.pending.is_empty()
    }
    pub fn genesis(
        assignments: &[Assignment],
        supervised: &[Binding],
        licenses: &[LicenseRecord],
        wallets: &WalletBook,
        genesis: Hash,
        fingerprint: Hash,
    ) -> Result<Self> {
        let verified = verify_genesis_set(
            assignments,
            supervised,
            licenses,
            wallets,
            genesis,
            fingerprint,
        )?;
        let mut book = Self::default();
        for (license, assignment) in licenses.iter().zip(verified) {
            let mut license = license.clone();
            let b = assignment.binding();
            license.active_worker = Some(b.worker_id);
            license.assignment_sequence = 1;
            book.licenses.insert(license.id, license);
            book.workers.insert(
                b.worker_id,
                Worker {
                    assignment: assignment.assignment().clone(),
                    last_accepted_ticket: 0,
                },
            );
        }
        book.records()?;
        Ok(book)
    }
    /// (LicenseID, current owner AddressID) for every License, in canonical order.
    pub(crate) fn license_pairs(&self) -> Vec<(Hash, Hash)> {
        self.licenses.values().map(|l| (l.id, l.owner)).collect()
    }
    /// Dividend activation epoch. Epoch 0 is approved ONLY for the twelve authenticated fresh
    /// Genesis Bootstrap Licenses: issued at height 0, index below 12 and carrying the exact
    /// deterministic Genesis LicenseID. Anything else, including any later issuance, has no
    /// activation here and is never dividend-eligible until its own validated issuance and
    /// activation rules supply one. This is never a default for missing data.
    pub fn dividend_activation_epoch(&self, id: Hash) -> Option<u64> {
        let l = self.licenses.get(&id)?;
        let bootstrap = l.issue_height == 0
            && l.index < 12
            && crate::blocks::genesis_license(l.genesis, l.index).ok() == Some(l.id);
        bootstrap.then_some(0)
    }
    /// (LicenseID, owner, dividend activation) in canonical order.
    pub(crate) fn license_activation_triples(&self) -> Vec<(Hash, Hash, Option<u64>)> {
        self.licenses
            .values()
            .map(|l| (l.id, l.owner, self.dividend_activation_epoch(l.id)))
            .collect()
    }
    pub fn license(&self, id: Hash) -> Option<&LicenseRecord> {
        self.licenses.get(&id)
    }
    /// Every License in canonical (LicenseID ascending) order. Read-only inspection, for example
    /// a wallet looking for the Licenses it controls. Like `license`, this does not authenticate
    /// the Book: the caller authenticates the complete parent StateRoot first.
    pub fn licenses(&self) -> impl Iterator<Item = &LicenseRecord> {
        self.licenses.values()
    }
    /// The Licenses whose recorded owner AddressID is `owner`, in canonical order. Read-only.
    /// Control is a separate question: a wallet that has rotated still controls Licenses recorded
    /// under its older addresses, which `WalletBook::authorize(owner, descriptor)` decides.
    pub fn licenses_of(&self, owner: Hash) -> impl Iterator<Item = &LicenseRecord> {
        self.licenses.values().filter(move |l| l.owner == owner)
    }
    /// The Worker assignment scheduled for `license` that has not yet become active, if any.
    /// A native License sale removes it (`transfer_candidate`); it then never activates. Read-only.
    pub fn pending_assignment(&self, license: Hash) -> Option<&Assignment> {
        self.pending.get(&license)
    }
    pub fn active(
        &self,
        license: Hash,
        worker: Hash,
        epoch: u64,
    ) -> Result<(&LicenseRecord, &Worker)> {
        let l = self.licenses.get(&license).ok_or(Error::WrongAnchor)?;
        let w = self.workers.get(&worker).ok_or(Error::UnknownSigner)?;
        let b = &w.assignment.enrollment.binding;
        if l.active_worker != Some(worker)
            || b.license != license
            || b.assignment_generation != l.assignment_sequence
            || b.effective_epoch > epoch
        {
            return Err(Error::StaleSequence);
        }
        Ok((l, w))
    }
    pub fn schedule(
        &mut self,
        assignment: Assignment,
        genesis: Hash,
        fingerprint: Hash,
        height: u64,
        epoch: u64,
        wallets: &WalletBook,
    ) -> Result<()> {
        self.validate()?;
        let b = &assignment.enrollment.binding;
        let license = self.licenses.get(&b.license).ok_or(Error::WrongAnchor)?;
        assignment.verify_next_epoch(&ParentContext {
            genesis,
            fingerprint,
            height,
            epoch,
            license,
            wallets,
        })?;
        if self.pending.contains_key(&b.license)
            || self
                .workers
                .values()
                .any(|w| w.assignment.enrollment.binding.worker_public == b.worker_public)
            || self
                .pending
                .values()
                .any(|a| a.enrollment.binding.worker_public == b.worker_public)
        {
            return Err(Error::Duplicate);
        }
        if self.licenses.len() + self.workers.len() + self.pending.len()
            >= crate::execution::MAX_STATE_RECORDS
        {
            return Err(Error::Capacity);
        }
        self.pending.insert(b.license, assignment);
        Ok(())
    }
    /// All due changes validate before any mutation. Epoch rollback never undoes
    /// an activated assignment or its numeric ticket high-water mark.
    pub fn activate_due(&mut self, epoch: u64) -> Result<()> {
        self.validate()?;
        let due: Vec<_> = self
            .pending
            .values()
            .filter(|a| a.enrollment.binding.effective_epoch <= epoch)
            .cloned()
            .collect();
        for a in &due {
            let b = &a.enrollment.binding;
            let l = self.licenses.get(&b.license).ok_or(Error::WrongAnchor)?;
            if l.assignment_sequence.checked_add(1) != Some(b.assignment_generation)
                || self.workers.contains_key(&b.worker_id)
            {
                return Err(Error::StaleSequence);
            }
        }
        for a in due {
            let b = &a.enrollment.binding;
            let l = self
                .licenses
                .get_mut(&b.license)
                .ok_or(Error::WrongAnchor)?;
            l.active_worker = Some(b.worker_id);
            l.assignment_sequence = b.assignment_generation;
            self.pending.remove(&b.license);
            self.workers.insert(
                b.worker_id,
                Worker {
                    assignment: a,
                    last_accepted_ticket: 0,
                },
            );
        }
        Ok(())
    }
    /// Context comes from independently validated parent work rules. Assignment
    /// fields must agree with this canonical book. This does not certify a block.
    pub fn verify_and_record_work(
        &mut self,
        header: &WorkHeader,
        authority: &Authority,
        context: &WorkContext,
    ) -> Result<()> {
        let (_, worker) = self.active(context.license, context.worker, authority.work.epoch)?;
        let b = &worker.assignment.enrollment.binding;
        if context.assignment_sequence != b.assignment_generation
            || context.last_accepted_ticket != worker.last_accepted_ticket
            || context.coordinator != b.coordinator
            || context.genesis != b.genesis
            || context.fingerprint != b.fingerprint
        {
            return Err(Error::WrongAnchor);
        }
        authority.verify(header, context, &worker.assignment.node_descriptor)?;
        self.workers
            .get_mut(&context.worker)
            .ok_or(Error::UnknownSigner)?
            .last_accepted_ticket = authority.work.ticket_sequence;
        Ok(())
    }
    /// Tentative proposal construction only. A numeric counter can enter the
    /// StateRoot before the authority signing that root exists. This helper
    /// grants no signature/PoW/finality authority and is not a public API.
    pub(crate) fn prepare_ticket(
        &mut self,
        license: Hash,
        worker: Hash,
        epoch: u64,
        ticket: u64,
    ) -> Result<()> {
        let (_, current) = self.active(license, worker, epoch)?;
        if ticket <= current.last_accepted_ticket {
            return Err(Error::StaleSequence);
        }
        self.workers
            .get_mut(&worker)
            .ok_or(Error::UnknownSigner)?
            .last_accepted_ticket = ticket;
        Ok(())
    }
    fn validate(&self) -> Result<()> {
        if self.licenses.len() + self.workers.len() + self.pending.len()
            > crate::execution::MAX_STATE_RECORDS
        {
            return Err(Error::Capacity);
        }
        let mut keys = BTreeSet::new();
        for (id, l) in &self.licenses {
            if *id != l.id {
                return Err(Error::WrongAnchor);
            }
            if let Some(worker) = l.active_worker {
                let w = self.workers.get(&worker).ok_or(Error::WrongAnchor)?;
                if w.assignment.enrollment.binding.license != *id
                    || w.assignment.enrollment.binding.assignment_generation
                        != l.assignment_sequence
                {
                    return Err(Error::WrongAnchor);
                }
            }
            // A detached License (no active worker) with a non-zero assignment
            // sequence is a valid, DvP-transferred state in every build; its typed
            // transfer record is cross-checked in trading_host_v1::records.
        }
        for (id, w) in &self.workers {
            w.assignment.encode()?;
            let b = &w.assignment.enrollment.binding;
            let l = self.licenses.get(&b.license).ok_or(Error::WrongAnchor)?;
            if *id != b.worker_id
                || b.genesis != l.genesis
                || b.assignment_generation > l.assignment_sequence
                || !keys.insert(b.worker_public)
            {
                return Err(Error::WrongAnchor);
            }
        }
        for (id, a) in &self.pending {
            a.encode()?;
            let b = &a.enrollment.binding;
            let l = self.licenses.get(id).ok_or(Error::WrongAnchor)?;
            if *id != b.license
                || b.genesis != l.genesis
                || l.assignment_sequence.checked_add(1) != Some(b.assignment_generation)
                || !keys.insert(b.worker_public)
            {
                return Err(Error::WrongAnchor);
            }
        }
        Ok(())
    }
    pub fn records(&self) -> Result<BTreeMap<Hash, Vec<u8>>> {
        self.validate()?;
        let mut records = BTreeMap::new();
        for (id, l) in &self.licenses {
            let mut e = Encoder::new(Vec::new());
            e.array(3)
                .unwrap()
                .u8(2)
                .unwrap()
                .u8(40)
                .unwrap()
                .bytes(&l.encode())
                .unwrap();
            records.insert(domain_hash(LICENSE_DOMAIN, id), e.into_writer());
        }
        for (id, w) in &self.workers {
            let mut e = Encoder::new(Vec::new());
            e.array(4)
                .unwrap()
                .u8(2)
                .unwrap()
                .u8(41)
                .unwrap()
                .bytes(&w.assignment.encode()?)
                .unwrap()
                .u64(w.last_accepted_ticket)
                .unwrap();
            records.insert(domain_hash(WORKER_DOMAIN, id), e.into_writer());
        }
        for (id, a) in &self.pending {
            let mut e = Encoder::new(Vec::new());
            e.array(3)
                .unwrap()
                .u8(2)
                .unwrap()
                .u8(42)
                .unwrap()
                .bytes(&a.encode()?)
                .unwrap();
            records.insert(domain_hash(PENDING_DOMAIN, id), e.into_writer());
        }
        Ok(records)
    }
    /// Caller authenticates the complete parent StateRoot before trusting these
    /// records. Historical owner descriptors are not current spending authority.
    pub fn from_records(records: &BTreeMap<Hash, Vec<u8>>) -> Result<Self> {
        if records.len() > crate::execution::MAX_STATE_RECORDS {
            return Err(Error::Capacity);
        }
        let mut book = Self::default();
        for raw in records.values() {
            crate::blocks::canonical(raw, MAX_RECORD)?;
            let mut d = Decoder::new(raw);
            let n = d.array().map_err(|_| Error::Codec)?;
            if d.u8().map_err(|_| Error::Codec)? != 2 {
                return Err(Error::Codec);
            }
            match d.u8().map_err(|_| Error::Codec)? {
                40 if n == Some(3) => {
                    let l = LicenseRecord::decode(d.bytes().map_err(|_| Error::Codec)?)?;
                    if book.licenses.insert(l.id, l).is_some() {
                        return Err(Error::Duplicate);
                    }
                }
                41 if n == Some(4) => {
                    let a = Assignment::decode(d.bytes().map_err(|_| Error::Codec)?)?;
                    let ticket = d.u64().map_err(|_| Error::Codec)?;
                    if book
                        .workers
                        .insert(
                            a.enrollment.binding.worker_id,
                            Worker {
                                assignment: a,
                                last_accepted_ticket: ticket,
                            },
                        )
                        .is_some()
                    {
                        return Err(Error::Duplicate);
                    }
                }
                42 if n == Some(3) => {
                    let a = Assignment::decode(d.bytes().map_err(|_| Error::Codec)?)?;
                    if book
                        .pending
                        .insert(a.enrollment.binding.license, a)
                        .is_some()
                    {
                        return Err(Error::Duplicate);
                    }
                }
                _ => return Err(Error::Codec),
            }
            if d.position() != raw.len() {
                return Err(Error::NonCanonical);
            }
        }
        if &book.records()? != records {
            return Err(Error::WrongAnchor);
        }
        Ok(book)
    }
}

#[cfg(test)]
mod activation_tests {
    use super::*;
    fn record(genesis: Hash, index: u64, issue_height: u64, id: Hash) -> LicenseRecord {
        LicenseRecord {
            id,
            genesis,
            owner: [9; 32],
            issuance: [8; 32],
            index,
            issue_height,
            active_worker: None,
            assignment_sequence: 0,
        }
    }
    #[test]
    fn epoch_zero_activation_is_only_for_authenticated_genesis_bootstrap_licenses() {
        let genesis = [1; 32];
        let mut book = Book::default();
        let boot = crate::blocks::genesis_license(genesis, 3).unwrap();
        book.licenses.insert(boot, record(genesis, 3, 0, boot));
        // Later issuance: right ID derivation is irrelevant, height above zero has no activation.
        let later = [0x51; 32];
        book.licenses.insert(later, record(genesis, 3, 5, later));
        // Index outside the twelve, even at height zero.
        let beyond = [0x54; 32];
        book.licenses.insert(beyond, record(genesis, 12, 0, beyond));
        // Height zero and index below twelve but not the deterministic Genesis identity.
        let forged = [0x52; 32];
        book.licenses.insert(forged, record(genesis, 4, 0, forged));
        assert_eq!(book.dividend_activation_epoch(boot), Some(0));
        assert_eq!(book.dividend_activation_epoch(later), None);
        assert_eq!(book.dividend_activation_epoch(beyond), None);
        assert_eq!(book.dividend_activation_epoch(forged), None);
        assert_eq!(book.dividend_activation_epoch([0x53; 32]), None, "unknown License");
        let triples = book.license_activation_triples();
        assert_eq!(triples.len(), 4);
        assert_eq!(triples.iter().filter(|t| t.2.is_some()).count(), 1);
    }
}

#[cfg(test)]
#[path = "license_book_v2_sale_tests.rs"]
mod sale_tests;
