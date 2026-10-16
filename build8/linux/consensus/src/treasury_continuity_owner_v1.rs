//! Owning TEST-VALUE verifier successor. No raw-store escape hatch or production
//! provider is registered. External current authority is separate from public
//! replay codecs; native path/VFS qualification is still required.
use crate::{
    Hash,
    treasury_admission_v3::AdmissionStore,
    treasury_continuity_provider_v1::{Provider, ProviderError, PublicSnapshot},
    treasury_continuity_v1::{
        self as protocol, Action, HistoryEntry, PublicRecord, Request, Scope,
    },
    treasury_rehearsal_v3::{
        self as native, CeremonyConfig, Denylist, Expect, Refusal, VerifiedProof,
    },
};
use mutiny_crypto_v2::{
    HybridSignature,
    treasury_proof_v1::{self as proof, Challenge},
};
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Frozen,
    Context,
    History,
    ReconciliationRequired,
    Native(Refusal),
    Provider(ProviderError),
    Protocol(protocol::Error),
}

#[cfg(test)]
#[path = "../tests/support/test_dir.rs"]
mod test_dir;
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        treasury_continuity_provider_v1::{AuthenticatedReceipt, ModeledProvider, Snapshot},
        treasury_v1::{Class, Treasury},
    };
    use mutiny_crypto_v2::{NETWORK, rehearsal_keys_v1::Credential};
    use std::{io::Write, path::PathBuf};
    struct Fixture {
        path: PathBuf,
        config: CeremonyConfig,
        scope: Scope,
        expect: Expect,
        key: Credential,
    }
    fn fixture() -> (Fixture, Owner<ModeledProvider>) {
        let key = Credential::from_label("PUBLIC-TREASURY-OWNER-NATIVE-V1", 1).unwrap();
        let descriptor = key.descriptor().unwrap();
        let config = CeremonyConfig::rehearsal(
            NETWORK,
            Treasury::new(Class::TestValue, descriptor).unwrap(),
            "PUBLIC-TREASURY-OWNER-NATIVE-CONTEXT-V1",
        )
        .unwrap();
        let expect = Expect::genesis_key(&config);
        let dir = test_dir::TestDir::new("treasury-continuity-owning-native");
        let path = dir.file("original.sqlite");
        std::mem::forget(dir);
        let id = AdmissionStore::create(&path, &config).unwrap();
        let scope = Scope {
            network: NETWORK,
            genesis: None,
            ceremony_context: config.context().value(),
            treasury_record: native::record_sha256(config.treasury()).unwrap(),
            verifier: [71; 32],
            store: id.store_id(),
            service: [72; 32],
        };
        let store = AdmissionStore::open(&path, &config, id).unwrap();
        let owner = Owner::new(
            store,
            ModeledProvider::new(scope.clone()).unwrap(),
            scope.clone(),
            expect.clone(),
            vec![],
            Denylist::default(),
        )
        .unwrap();
        assert!(!owner.frozen());
        (
            Fixture {
                path,
                config,
                scope,
                expect,
                key,
            },
            owner,
        )
    }
    #[test]
    fn owner_native_proof_checks_precede_service_and_confirmed_restore_is_frozen() {
        let (f, mut owner) = fixture();
        let descriptor = f.key.descriptor().unwrap();
        let challenge = owner.issue(&descriptor).unwrap();
        assert_eq!(owner.sequence(), 2);
        let bytes = challenge.encode().unwrap();
        let snapshot_path = f.path.with_file_name("isolated-issued-snapshot.sqlite");
        let mut snapshot = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&snapshot_path)
            .unwrap();
        snapshot
            .write_all(&std::fs::read(&f.path).unwrap())
            .unwrap();
        snapshot.sync_all().unwrap();
        drop(snapshot);
        let signature = proof::sign_challenge(f.key.key(), &descriptor, &challenge).unwrap();
        let mut forged = signature.clone();
        forged.ed448[0] ^= 1;
        assert!(owner.admit(&descriptor, &bytes, &forged).is_err());
        assert_eq!(owner.sequence(), 2);
        assert!(!owner.frozen());
        owner.admit(&descriptor, &bytes, &signature).unwrap();
        assert_eq!(owner.sequence(), 4);
        assert!(!owner.frozen());
        assert_eq!(
            owner.admit(&descriptor, &bytes, &signature),
            Err(Error::Native(Refusal::Replay))
        );
        assert_eq!(owner.sequence(), 4);
        let external = owner.provider.engine.clone();
        drop(owner);
        let id =
            crate::treasury_admission_v3::StoreIdentity::from_trusted_id(f.scope.store).unwrap();
        let stale_store = AdmissionStore::open(&snapshot_path, &f.config, id).unwrap();
        let mut restarted = Owner::new(
            stale_store,
            ModeledProvider { engine: external },
            f.scope,
            f.expect,
            vec![],
            Denylist::default(),
        )
        .unwrap();
        assert!(restarted.frozen());
        assert_eq!(restarted.sequence(), 4);
        assert_eq!(restarted.issue(&descriptor), Err(Error::Frozen));
        restarted.reconcile().unwrap();
        assert!(!restarted.frozen());
        assert_eq!(restarted.sequence(), 4);
        assert_eq!(
            restarted.admit(&descriptor, &bytes, &signature),
            Err(Error::Native(Refusal::Replay))
        );
        assert_eq!(restarted.store.admissions().unwrap().len(), 1);
        assert_eq!(restarted.sequence(), 4);
    }
    struct LoseAck {
        inner: ModeledProvider,
        lose_next: bool,
    }
    impl Provider for LoseAck {
        fn scope(&self) -> &Scope {
            self.inner.scope()
        }
        fn current(&mut self, nonce: Hash) -> Result<Snapshot, ProviderError> {
            self.inner.current(nonce)
        }
        fn transition(&mut self, r: &Request) -> Result<AuthenticatedReceipt, ProviderError> {
            let response = self.inner.transition(r)?;
            if self.lose_next {
                self.lose_next = false;
                Err(ProviderError::Unknown)
            } else {
                Ok(response)
            }
        }
    }
    #[test]
    fn owner_lost_reservation_ack_freezes_both_paths_until_exact_reconciliation() {
        let (f, owner) = fixture();
        let inner = owner.provider;
        let store = owner.store;
        let mut owner = Owner::new(
            store,
            LoseAck {
                inner,
                lose_next: true,
            },
            f.scope,
            f.expect,
            vec![],
            Denylist::default(),
        )
        .unwrap();
        let descriptor = f.key.descriptor().unwrap();
        assert_eq!(
            owner.issue(&descriptor),
            Err(Error::Provider(ProviderError::Unknown))
        );
        assert!(owner.frozen());
        assert!(owner.store.continuity_records().unwrap().is_empty());
        assert_eq!(owner.provider.inner.engine.sequence(), 1);
        assert_eq!(owner.issue(&descriptor), Err(Error::Frozen));
        owner.reconcile().unwrap();
        assert!(!owner.frozen());
        assert_eq!(owner.sequence(), 2);
        assert_eq!(owner.store.continuity_records().unwrap().len(), 1);
        assert!(!owner.provider.inner.engine.frozen());
    }
    #[test]
    fn orphan_admission_cannot_disappear_from_startup_current_history_comparison() {
        let (f, owner) = fixture();
        let descriptor = f.key.descriptor().unwrap();
        let ch = native::build_challenge(&f.config, &descriptor, [81; 32]).unwrap();
        let signature = proof::sign_challenge(f.key.key(), &descriptor, &ch).unwrap();
        let provider = owner.provider;
        drop(owner.store);
        let db = rusqlite::Connection::open(&f.path).unwrap();
        db.execute(
            "INSERT INTO admissions VALUES(?1,?2,?3,?4)",
            rusqlite::params![
                ch.nonce.as_slice(),
                ch.encode().unwrap(),
                descriptor,
                proof::signature_to_bytes(&signature)
            ],
        )
        .unwrap();
        drop(db);
        let before = std::fs::read(&f.path).unwrap();
        let id =
            crate::treasury_admission_v3::StoreIdentity::from_trusted_id(f.scope.store).unwrap();
        let store = AdmissionStore::open(&f.path, &f.config, id).unwrap();
        let mut restarted = Owner::new(
            store,
            provider,
            f.scope,
            f.expect,
            vec![],
            Denylist::default(),
        )
        .unwrap();
        assert!(restarted.frozen());
        assert_eq!(restarted.sequence(), 0);
        assert_eq!(restarted.issue(&descriptor), Err(Error::Frozen));
        assert_eq!(
            restarted.admit(&descriptor, &ch.encode().unwrap(), &signature),
            Err(Error::Frozen)
        );
        assert!(restarted.reconcile().is_err());
        assert!(restarted.frozen());
        assert_eq!(std::fs::read(&f.path).unwrap(), before);
        assert_eq!(restarted.provider.engine.sequence(), 0);
    }
    #[test]
    fn owner_lost_consumption_ack_never_repeats_a_logical_admission() {
        let (f, owner) = fixture();
        let inner = owner.provider;
        let store = owner.store;
        let mut owner = Owner::new(
            store,
            LoseAck {
                inner,
                lose_next: false,
            },
            f.scope,
            f.expect,
            vec![],
            Denylist::default(),
        )
        .unwrap();
        let descriptor = f.key.descriptor().unwrap();
        let challenge = owner.issue(&descriptor).unwrap();
        let bytes = challenge.encode().unwrap();
        let signature = proof::sign_challenge(f.key.key(), &descriptor, &challenge).unwrap();
        owner.provider.lose_next = true;
        assert_eq!(
            owner.admit(&descriptor, &bytes, &signature),
            Err(Error::Provider(ProviderError::Unknown))
        );
        assert!(owner.frozen());
        assert_eq!(owner.provider.inner.engine.sequence(), 3);
        assert_eq!(owner.store.admissions().unwrap().len(), 0);
        assert_eq!(
            owner.admit(&descriptor, &bytes, &signature),
            Err(Error::Frozen)
        );
        owner.reconcile().unwrap();
        assert!(!owner.frozen());
        assert_eq!(owner.sequence(), 4);
        assert_eq!(owner.store.admissions().unwrap().len(), 1);
        assert_eq!(
            owner.admit(&descriptor, &bytes, &signature),
            Err(Error::Native(Refusal::Replay))
        );
        assert_eq!(owner.sequence(), 4);
    }
}
impl From<Refusal> for Error {
    fn from(e: Refusal) -> Self {
        Self::Native(e)
    }
}
impl From<protocol::Error> for Error {
    fn from(e: protocol::Error) -> Self {
        Self::Protocol(e)
    }
}
impl From<ProviderError> for Error {
    fn from(e: ProviderError) -> Self {
        Self::Provider(e)
    }
}

pub struct Owner<P: Provider> {
    store: AdmissionStore,
    provider: P,
    scope: Scope,
    config: CeremonyConfig,
    current: Expect,
    historical: BTreeMap<u64, Expect>,
    denylist: Denylist,
    history: Vec<HistoryEntry>,
    sequence: u64,
    frozen: bool,
}
fn random_id() -> Result<Hash, Error> {
    let mut value = [0; 32];
    while value == [0; 32] {
        mutiny_crypto_v2::fill_os_random(&mut value).map_err(|_| Error::Native(Refusal::Store))?;
    }
    Ok(value)
}
fn binding_matches(config: &CeremonyConfig, scope: &Scope) -> Result<(), Error> {
    if config.network() != scope.network
        || config.context().value() != scope.ceremony_context
        || native::record_sha256(config.treasury())? != scope.treasury_record
        || config.trusted_chain().map(|chain| chain.genesis) != scope.genesis
    {
        return Err(Error::Context);
    }
    Ok(())
}
fn final_records(history: &[HistoryEntry]) -> Result<Vec<PublicRecord>, Error> {
    let mut records = BTreeMap::new();
    for entry in history {
        match &entry.action {
            Action::Reserve(record) | Action::Consume(record) => {
                records.insert(record.nonce, record.clone());
            }
            Action::ConfirmLocal { .. } => {}
        }
    }
    if records.len() > 2048 {
        return Err(Error::History);
    }
    Ok(records.into_values().collect())
}
impl<P: Provider> Owner<P> {
    /// Expectations are independently authenticated historical lineage snapshots.
    /// Retaining them authorizes exact historical reconstruction, never new
    /// issuance by a retired key. New issue/admit use only `current`.
    pub fn new(
        store: AdmissionStore,
        provider: P,
        scope: Scope,
        current: Expect,
        historical: Vec<Expect>,
        denylist: Denylist,
    ) -> Result<Self, Error> {
        let config = current.config().clone();
        protocol::Engine::new(scope.clone())?;
        binding_matches(&config, &scope)?;
        store.check_binding(&config)?;
        if store.store_id() != scope.store
            || provider.scope() != &scope
            || store.is_read_only()
            || historical.len() > 64
        {
            return Err(Error::Context);
        }
        let mut trusted = BTreeMap::new();
        for expect in historical {
            binding_matches(expect.config(), &scope)?;
            if trusted.insert(expect.generation(), expect).is_some() {
                return Err(Error::History);
            }
        }
        if let Some(old) = trusted.insert(current.generation(), current.clone()) {
            if old != current {
                return Err(Error::History);
            }
        }
        let mut owner = Self {
            store,
            provider,
            scope,
            config,
            current,
            historical: trusted,
            denylist,
            history: Vec::new(),
            sequence: 0,
            frozen: true,
        };
        // A mismatched/unavailable store remains an owning frozen object so the
        // exact reconciliation operation remains possible without a raw-store API.
        if owner.refresh(false).is_ok() {
            owner.frozen = false;
        }
        Ok(owner)
    }
    pub fn frozen(&self) -> bool {
        self.frozen
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    fn checked_records(&self) -> Result<Vec<(Expect, PublicRecord)>, Error> {
        final_records(&self.history)?
            .into_iter()
            .map(|record| {
                let expect = self
                    .historical
                    .get(&record.generation)
                    .ok_or(Error::History)?
                    .clone();
                let ch = Challenge::decode(&record.challenge).map_err(Refusal::from)?;
                if ch.nonce != record.nonce || ch.generation != record.generation {
                    return Err(Error::History);
                }
                if let Some(sig) = &record.signature {
                    let sig = proof::signature_from_bytes(sig).map_err(Refusal::from)?;
                    native::verify_crypto_bound(
                        &expect,
                        &record.descriptor,
                        &record.challenge,
                        &sig,
                        &self.denylist,
                    )?;
                } else {
                    native::check_issuance_descriptor(&expect, &record.descriptor)?;
                    if native::build_challenge(expect.config(), &record.descriptor, record.nonce)?
                        .encode()
                        .map_err(Refusal::from)?
                        != record.challenge
                    {
                        return Err(Error::History);
                    }
                }
                Ok((expect, record))
            })
            .collect()
    }
    fn refresh(&mut self, allow_reconciliation: bool) -> Result<Option<Hash>, Error> {
        self.store.check_binding(&self.config)?;
        let nonce = random_id()?;
        let snapshot = self.provider.current(nonce)?;
        if snapshot.scope() != &self.scope
            || snapshot.request_nonce() != nonce
            || snapshot.sequence() < self.sequence
        {
            return Err(Error::Context);
        }
        PublicSnapshot::new(
            snapshot.scope().clone(),
            snapshot.request_nonce(),
            snapshot.sequence(),
            snapshot.pending_operation(),
            snapshot.operations().to_vec(),
        )?;
        if snapshot.operations().get(..self.history.len()) != Some(self.history.as_slice()) {
            return Err(Error::History);
        }
        self.sequence = snapshot.sequence();
        self.history = snapshot.operations().to_vec();
        let expected: Vec<_> = self
            .checked_records()?
            .into_iter()
            .map(|(_, r)| r)
            .collect();
        let pending = snapshot.pending_operation();
        if !allow_reconciliation
            && (pending.is_some() || self.store.continuity_records()? != expected)
        {
            return Err(Error::ReconciliationRequired);
        }
        Ok(pending)
    }
    fn ready(&mut self) -> Result<(), Error> {
        if self.frozen {
            return Err(Error::Frozen);
        }
        if let Err(error) = self.refresh(false) {
            self.frozen = true;
            return Err(error);
        }
        Ok(())
    }
    fn send(
        provider: &mut P,
        scope: &Scope,
        sequence: &mut u64,
        history: &mut Vec<HistoryEntry>,
        action: Action,
    ) -> Result<Hash, Error> {
        let request = Request {
            scope: scope.clone(),
            operation: random_id()?,
            request_nonce: random_id()?,
            expected_sequence: *sequence,
            action,
        };
        let authenticated = provider.transition(&request)?;
        let receipt = authenticated.receipt();
        protocol::check_receipt(&request, receipt)?;
        if receipt.repeated {
            return Err(Error::History);
        }
        *sequence = receipt.sequence;
        history.push(HistoryEntry {
            operation: request.operation,
            sequence: receipt.operation_sequence,
            action: request.action,
            outcome: receipt.outcome,
        });
        Ok(request.operation)
    }
    fn confirm(&mut self, pending: Hash, record: PublicRecord) -> Result<(), Error> {
        Self::send(
            &mut self.provider,
            &self.scope,
            &mut self.sequence,
            &mut self.history,
            Action::ConfirmLocal {
                pending_operation: pending,
                exact: record,
            },
        )?;
        self.refresh(false)?;
        self.frozen = false;
        Ok(())
    }
    pub fn issue(&mut self, descriptor: &[u8]) -> Result<Challenge, Error> {
        self.ready()?;
        let mut reserved = None;
        let mut service_error = None;
        let result = self.store.issue_with_reservation(
            &self.current,
            descriptor,
            &self.denylist,
            |ch, d| {
                self.frozen = true;
                let record = PublicRecord {
                    generation: ch.generation,
                    nonce: ch.nonce,
                    challenge: ch.encode()?,
                    descriptor: d.to_vec(),
                    signature: None,
                };
                match Self::send(
                    &mut self.provider,
                    &self.scope,
                    &mut self.sequence,
                    &mut self.history,
                    Action::Reserve(record.clone()),
                ) {
                    Ok(operation) => {
                        reserved = Some((operation, record));
                        Ok(())
                    }
                    Err(error) => {
                        service_error = Some(error);
                        Err(Refusal::Store)
                    }
                }
            },
        );
        let challenge = match result {
            Ok(value) => value,
            Err(error) => return Err(service_error.unwrap_or(Error::Native(error))),
        };
        let (operation, record) = reserved.ok_or(Error::History)?;
        let local = self.store.issued(&record.nonce)?.ok_or(Error::History)?;
        if local.challenge != record.challenge
            || local.descriptor != record.descriptor
            || local.consumed
        {
            return Err(Error::History);
        }
        self.confirm(operation, record)?;
        Ok(challenge)
    }
    pub fn admit(
        &mut self,
        descriptor: &[u8],
        challenge: &[u8],
        signature: &HybridSignature,
    ) -> Result<VerifiedProof, Error> {
        self.ready()?;
        if challenge.is_empty()
            || challenge.len() > 512
            || descriptor.is_empty()
            || descriptor.len() > 2048
        {
            return Err(Error::Native(Refusal::Codec));
        }
        let decoded = Challenge::decode(challenge).map_err(Refusal::from)?;
        let record = PublicRecord {
            generation: decoded.generation,
            nonce: decoded.nonce,
            challenge: challenge.to_vec(),
            descriptor: descriptor.to_vec(),
            signature: Some(proof::signature_to_bytes(signature)),
        };
        let mut consumed = None;
        let mut service_error = None;
        let result = self.store.admit_with_consumption(
            &self.current,
            descriptor,
            challenge,
            signature,
            &self.denylist,
            |_| {
                self.frozen = true;
                match Self::send(
                    &mut self.provider,
                    &self.scope,
                    &mut self.sequence,
                    &mut self.history,
                    Action::Consume(record.clone()),
                ) {
                    Ok(operation) => {
                        consumed = Some(operation);
                        Ok(())
                    }
                    Err(error) => {
                        service_error = Some(error);
                        Err(Refusal::Store)
                    }
                }
            },
        );
        let verified = match result {
            Ok(value) => value,
            Err(error) => return Err(service_error.unwrap_or(Error::Native(error))),
        };
        let operation = consumed.ok_or(Error::History)?;
        let local = self.store.recorded(&record.nonce)?.ok_or(Error::History)?;
        if local.challenge != record.challenge
            || local.descriptor != record.descriptor
            || Some(local.signature) != record.signature
        {
            return Err(Error::History);
        }
        self.confirm(operation, record)?;
        Ok(verified)
    }
    /// Explicit repair of already authenticated exact operations. Never an
    /// ordinary retry/new admission; failures leave both workflows frozen.
    pub fn reconcile(&mut self) -> Result<(), Error> {
        self.frozen = true;
        let pending = self.refresh(true)?;
        let records = self.checked_records()?;
        self.store
            .reconcile_continuity_records(&self.config, &records, &self.denylist)?;
        let exact: Vec<_> = records.into_iter().map(|(_, r)| r).collect();
        if self.store.continuity_records()? != exact {
            return Err(Error::History);
        }
        if let Some(operation) = pending {
            let entry = self
                .history
                .iter()
                .find(|entry| entry.operation == operation)
                .ok_or(Error::History)?;
            let record = match &entry.action {
                Action::Reserve(r) | Action::Consume(r) => r.clone(),
                _ => return Err(Error::History),
            };
            self.confirm(operation, record)?;
        } else {
            self.refresh(false)?;
            self.frozen = false;
        }
        Ok(())
    }
}
