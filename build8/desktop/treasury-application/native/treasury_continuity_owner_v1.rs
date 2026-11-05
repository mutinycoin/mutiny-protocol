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
    fn checked_history(&self, history: &[HistoryEntry]) -> Result<Vec<(Expect, PublicRecord)>, Error> {
        final_records(history)?
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
    fn checked_records(&self) -> Result<Vec<(Expect, PublicRecord)>, Error> {
        self.checked_history(&self.history)
    }
    fn refresh(&mut self, allow_reconciliation: bool) -> Result<Option<Hash>, Error> {
        self.store.check_binding(&self.config)?;
        let nonce = random_id()?;
        let snapshot = self.store.guarded_external(Error::from, || {
            self.provider.current(nonce).map_err(Error::from)
        })?;
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
        let candidate = snapshot.operations().to_vec();
        let expected: Vec<_> = self
            .checked_history(&candidate)?
            .into_iter()
            .map(|(_, r)| r)
            .collect();
        let pending = snapshot.pending_operation();
        // Publish only after the complete historical descriptor/proof audit.
        // A locally mismatched store retains this authenticated history for
        // explicit reconciliation, with both workflows frozen.
        self.sequence = snapshot.sequence();
        self.history = candidate;
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
        #[cfg(test)] native_owner_controls::before_confirm();
        self.store.guarded_external(Error::from, || Self::send(
            &mut self.provider,
            &self.scope,
            &mut self.sequence,
            &mut self.history,
            Action::ConfirmLocal {
                pending_operation: pending,
                exact: record,
            },
        ))?;
        self.refresh(false)?;
        self.frozen = false;
        Ok(())
    }
    pub fn issue(&mut self, descriptor: &[u8]) -> Result<Challenge, Error> {
        self.issue_guarded(descriptor, || Ok(()))
    }
    fn issue_guarded(&mut self, descriptor: &[u8], mut current: impl FnMut() -> Result<(), Refusal>) -> Result<Challenge, Error> {
        self.ready()?;
        let mut reserved = None;
        let mut service_error = None;
        let result = self.store.issue_with_reservation(
            &self.current,
            descriptor,
            &self.denylist,
            |ch, d| {
                self.frozen = true;
                // Native transaction is held; check before external reserve.
                current()?;
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
        self.admit_guarded(descriptor, challenge, signature, || Ok(()))
    }
    fn admit_guarded(&mut self, descriptor: &[u8], challenge: &[u8],
        signature: &HybridSignature, mut current: impl FnMut() -> Result<(), Refusal>) -> Result<VerifiedProof, Error> {
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
                // Proof verification completed; check before external consume.
                current()?;
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

#[cfg(test)]
#[path="../controls/native_continuity_owner_controls.rs"]
mod native_owner_controls;

#[path="treasury_canonical_owner_startup_v1.rs"]
pub(crate) mod canonical_startup;
