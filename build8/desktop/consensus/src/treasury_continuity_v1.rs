//! Adopted external Treasury continuity protocol, source draft.
//! This state machine confers no consensus/spending or production authority.
//! No production authenticated/rollback-protected backend exists here. Implementations
//! must establish that boundary independently; an ordinary cloned record is insufficient.
use crate::Hash;
use std::collections::BTreeMap;

/// Fixed public context pinned outside the admission database. Pre-Genesis ceremony
/// uses an independently approved context; Genesis is bound only when already known.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    pub network: u32,
    pub genesis: Option<Hash>,
    pub ceremony_context: Hash,
    pub treasury_record: Hash,
    pub verifier: Hash,
    pub store: Hash,
    pub service: Hash,
}
impl Scope {
    fn valid(&self) -> bool {
        self.network != 0
            && self.genesis != Some([0; 32])
            && [
                self.ceremony_context,
                self.treasury_record,
                self.verifier,
                self.store,
                self.service,
            ]
            .iter()
            .all(|h| *h != [0; 32])
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicRecord {
    pub generation: u64,
    pub nonce: Hash,
    pub challenge: Vec<u8>,
    pub descriptor: Vec<u8>,
    pub signature: Option<Vec<u8>>,
}
impl PublicRecord {
    fn bounded(&self) -> bool {
        self.generation > 0
            && self.nonce != [0; 32]
            && !self.challenge.is_empty()
            && self.challenge.len() <= 512
            && !self.descriptor.is_empty()
            && self.descriptor.len() <= 2048
            && self.signature.as_ref().is_none_or(|s| s.len() == 1394)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    WrongScope,
    Invalid,
    Conflict,
    Stale,
    Replay,
    Frozen,
    Full,
    Unknown,
    CounterExhausted,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    Reserve(PublicRecord),
    Consume(PublicRecord),
    ConfirmLocal {
        pending_operation: Hash,
        exact: PublicRecord,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub scope: Scope,
    /// OS-generated operation ID at the verifier, stable across identical retries.
    pub operation: Hash,
    /// Fresh session request nonce, never recovered from the restorable database.
    pub request_nonce: Hash,
    pub expected_sequence: u64,
    pub action: Action,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Reserved,
    Consumed,
    LocalConfirmed,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    pub scope: Scope,
    pub operation: Hash,
    /// Exact canonical scope, operation identity and action. Session nonce and
    /// expected head are deliberately separate so identical retries keep this.
    pub content_commitment: Hash,
    pub request_nonce: Hash,
    pub sequence: u64,
    pub operation_sequence: u64,
    pub outcome: Outcome,
    /// Repeated operation refers to its original terminal outcome; no new admission.
    pub repeated: bool,
}

#[derive(Clone)]
struct Applied {
    action: Action,
    sequence: u64,
    outcome: Outcome,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum Issuance {
    Reserved(PublicRecord),
    Consumed(PublicRecord),
}
/// Service-side transition engine. Durability/authentication must surround apply:
/// never acknowledge its result until the authoritative protected transaction commits.
/// It owns public evidence only, no private Treasury keys. Its map is bounded and does
/// not evict historical operations to make space. Persist/reopen must preserve all fields.
#[derive(Clone)]
pub struct Engine {
    scope: Scope,
    sequence: u64,
    applied: BTreeMap<Hash, Applied>,
    issued: BTreeMap<Hash, Issuance>,
    pending_local: Option<Hash>,
}
/// Public retained transition, ordered by its original authoritative sequence.
/// Reading or replaying this structure does not authenticate a current service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryEntry {
    pub operation: Hash,
    pub sequence: u64,
    pub action: Action,
    pub outcome: Outcome,
}
impl Engine {
    pub fn new(scope: Scope) -> Result<Self, Error> {
        if !scope.valid() {
            return Err(Error::WrongScope);
        }
        Ok(Self {
            scope,
            sequence: 0,
            applied: BTreeMap::new(),
            issued: BTreeMap::new(),
            pending_local: None,
        })
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn scope(&self) -> &Scope {
        &self.scope
    }
    pub fn pending_operation(&self) -> Option<Hash> {
        self.pending_local
    }
    pub fn history(&self) -> Vec<HistoryEntry> {
        let mut entries: Vec<_> = self
            .applied
            .iter()
            .map(|(operation, applied)| HistoryEntry {
                operation: *operation,
                sequence: applied.sequence,
                action: applied.action.clone(),
                outcome: applied.outcome,
            })
            .collect();
        entries.sort_by_key(|entry| entry.sequence);
        entries
    }
    pub fn frozen(&self) -> bool {
        self.pending_local.is_some()
    }
    /// Caller must authenticate exact context and cryptographically validate a proof
    /// BEFORE invoking Consume. This protocol engine is not a signature verifier.
    pub fn apply(&mut self, r: &Request) -> Result<Receipt, Error> {
        if r.scope != self.scope {
            return Err(Error::WrongScope);
        }
        if r.operation == [0; 32] || r.request_nonce == [0; 32] {
            return Err(Error::Invalid);
        }
        // Validate and commit exact contents before any authoritative mutation.
        let content_commitment = r.content_commitment()?;
        if let Some(old) = self.applied.get(&r.operation) {
            if old.action != r.action {
                return Err(Error::Conflict);
            }
            return Ok(Receipt {
                scope: self.scope.clone(),
                operation: r.operation,
                content_commitment,
                request_nonce: r.request_nonce,
                sequence: self.sequence,
                operation_sequence: old.sequence,
                outcome: old.outcome,
                repeated: true,
            });
        }
        if r.expected_sequence != self.sequence {
            return Err(Error::Stale);
        }
        // A newly acknowledged reservation/consumption must retain room for its
        // required exact local confirmation. Full history is never evicted.
        let required_slots = if matches!(r.action, Action::ConfirmLocal { .. }) {
            1
        } else {
            2
        };
        if self
            .applied
            .len()
            .checked_add(required_slots)
            .is_none_or(|n| n > 4096)
        {
            return Err(Error::Full);
        }
        let next = self
            .sequence
            .checked_add(1)
            .ok_or(Error::CounterExhausted)?;
        let outcome = match &r.action {
            Action::Reserve(v) => {
                if self.pending_local.is_some() {
                    return Err(Error::Frozen);
                }
                if !v.bounded() || v.signature.is_some() {
                    return Err(Error::Invalid);
                }
                if self.issued.contains_key(&v.nonce) {
                    return Err(Error::Replay);
                }
                self.issued.insert(v.nonce, Issuance::Reserved(v.clone()));
                // Reserve acknowledgement precedes local issuance; ambiguity freezes
                // both paths until exact authenticated confirmation/reconciliation.
                self.pending_local = Some(r.operation);
                Outcome::Reserved
            }
            Action::Consume(v) => {
                if self.pending_local.is_some() {
                    return Err(Error::Frozen);
                }
                if !v.bounded() || v.signature.is_none() {
                    return Err(Error::Invalid);
                }
                match self.issued.get(&v.nonce) {
                    Some(Issuance::Reserved(issued)) => {
                        let mut unsigned = v.clone();
                        unsigned.signature = None;
                        if issued != &unsigned {
                            return Err(Error::Conflict);
                        }
                    }
                    Some(Issuance::Consumed(_)) => return Err(Error::Replay),
                    None => return Err(Error::Unknown),
                }
                self.issued.insert(v.nonce, Issuance::Consumed(v.clone()));
                self.pending_local = Some(r.operation);
                Outcome::Consumed
            }
            Action::ConfirmLocal {
                pending_operation,
                exact,
            } => {
                if self.pending_local != Some(*pending_operation) {
                    return Err(Error::Conflict);
                }
                let previous = self.applied.get(pending_operation).ok_or(Error::Unknown)?;
                match &previous.action {
                    Action::Reserve(v) | Action::Consume(v) if v == exact => {}
                    _ => return Err(Error::Conflict),
                }
                self.pending_local = None;
                Outcome::LocalConfirmed
            }
        };
        self.sequence = next;
        self.applied.insert(
            r.operation,
            Applied {
                action: r.action.clone(),
                sequence: next,
                outcome,
            },
        );
        Ok(Receipt {
            scope: self.scope.clone(),
            operation: r.operation,
            content_commitment,
            request_nonce: r.request_nonce,
            sequence: next,
            operation_sequence: next,
            outcome,
            repeated: false,
        })
    }
}

/// Verify application-level context/freshness AFTER authenticated channel verification.
/// This is not authentication by itself and must not turn raw received bytes into trust.
pub fn check_receipt(r: &Request, receipt: &Receipt) -> Result<(), Error> {
    if r.scope != receipt.scope {
        return Err(Error::WrongScope);
    }
    if r.operation != receipt.operation || r.request_nonce != receipt.request_nonce {
        return Err(Error::Stale);
    }
    if r.content_commitment()? != receipt.content_commitment {
        return Err(Error::Conflict);
    }
    if receipt.operation_sequence == 0
        || receipt.operation_sequence > receipt.sequence
        || receipt.sequence < r.expected_sequence
        || (!receipt.repeated
            && (receipt.sequence
                != r.expected_sequence
                    .checked_add(1)
                    .ok_or(Error::CounterExhausted)?
                || receipt.operation_sequence != receipt.sequence))
    {
        return Err(Error::Stale);
    }
    let expected = match &r.action {
        Action::Reserve(_) => Outcome::Reserved,
        Action::Consume(_) => Outcome::Consumed,
        Action::ConfirmLocal { .. } => Outcome::LocalConfirmed,
    };
    if receipt.outcome != expected {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[path = "treasury_continuity_codec_v1.rs"]
mod codec;

#[cfg(test)]
#[path = "../tests/support/test_dir.rs"]
mod test_dir;
#[cfg(test)]
mod tests {
    use super::*;
    fn scope() -> Scope {
        Scope {
            network: 1,
            genesis: None,
            ceremony_context: [1; 32],
            treasury_record: [2; 32],
            verifier: [3; 32],
            store: [4; 32],
            service: [5; 32],
        }
    }
    fn record() -> PublicRecord {
        PublicRecord {
            generation: 1,
            nonce: [7; 32],
            challenge: vec![1; 300],
            descriptor: vec![2; 1900],
            signature: None,
        }
    }
    fn request(e: &Engine, id: u8, action: Action) -> Request {
        Request {
            scope: scope(),
            operation: [id; 32],
            request_nonce: [id + 1; 32],
            expected_sequence: e.sequence(),
            action,
        }
    }
    #[test]
    fn final_reserved_confirmation_slot_settles_without_evicting_history() {
        let mut e = Engine::new(scope()).unwrap();
        for index in 1u64..=2048 {
            let mut nonce = [7; 32];
            nonce[24..].copy_from_slice(&index.to_be_bytes());
            let mut v = record();
            v.nonce = nonce;
            let mut operation = [8; 32];
            operation[24..].copy_from_slice(&(index * 2).to_be_bytes());
            let reserve = Request {
                scope: scope(),
                operation,
                request_nonce: [99; 32],
                expected_sequence: e.sequence(),
                action: Action::Reserve(v.clone()),
            };
            e.apply(&reserve).unwrap();
            assert!(e.frozen());
            let mut confirm_id = operation;
            confirm_id[24..].copy_from_slice(&(index * 2 + 1).to_be_bytes());
            let confirm = Request {
                scope: scope(),
                operation: confirm_id,
                request_nonce: [98; 32],
                expected_sequence: e.sequence(),
                action: Action::ConfirmLocal {
                    pending_operation: operation,
                    exact: v,
                },
            };
            e.apply(&confirm).unwrap();
            assert!(!e.frozen());
        }
        assert_eq!(e.applied.len(), 4096);
        assert_eq!(e.sequence(), 4096);
        let next = request(&e, 50, Action::Reserve(record()));
        assert_eq!(e.apply(&next), Err(Error::Full));
        assert_eq!(e.applied.len(), 4096);
        assert_eq!(e.sequence(), 4096);
        assert!(!e.frozen());
        // Retry still refers to the original exact outcome at the complete head.
        let mut original = record();
        original.nonce[24..].copy_from_slice(&1u64.to_be_bytes());
        let mut op = [8; 32];
        op[24..].copy_from_slice(&2u64.to_be_bytes());
        let retry = Request {
            scope: scope(),
            operation: op,
            request_nonce: [97; 32],
            expected_sequence: e.sequence(),
            action: Action::Reserve(original),
        };
        let receipt = e.apply(&retry).unwrap();
        assert!(receipt.repeated);
        assert_eq!(receipt.operation_sequence, 1);
        assert_eq!(receipt.sequence, 4096);
        check_receipt(&retry, &receipt).unwrap();
        assert!(!e.frozen());
    }
    #[test]
    fn final_consumption_confirmation_settles_and_history_replays_exactly() {
        let mut e = Engine::new(scope()).unwrap();
        for index in 1u64..=1024 {
            let mut v = record();
            v.nonce[24..].copy_from_slice(&index.to_be_bytes());
            let mut signed = v.clone();
            signed.signature = Some(vec![42; 1394]);
            let mut last_pending = [0; 32];
            for offset in 0u64..4 {
                let mut operation = [81; 32];
                operation[24..].copy_from_slice(&(index * 4 + offset).to_be_bytes());
                let action = match offset {
                    0 => Action::Reserve(v.clone()),
                    2 => Action::Consume(signed.clone()),
                    _ => Action::ConfirmLocal {
                        pending_operation: last_pending,
                        exact: if offset == 1 {
                            v.clone()
                        } else {
                            signed.clone()
                        },
                    },
                };
                let r = Request {
                    scope: scope(),
                    operation,
                    request_nonce: [82; 32],
                    expected_sequence: e.sequence(),
                    action,
                };
                check_receipt(&r, &e.apply(&r).unwrap()).unwrap();
                if offset % 2 == 0 {
                    last_pending = operation;
                }
                assert_eq!(e.frozen(), offset % 2 == 0);
            }
        }
        assert_eq!(e.sequence(), 4096);
        let history = e.history();
        assert_eq!(history.len(), 4096);
        let mut reconstructed = Engine::new(e.scope().clone()).unwrap();
        for entry in &history {
            let r = Request {
                scope: scope(),
                operation: entry.operation,
                request_nonce: [83; 32],
                expected_sequence: entry.sequence - 1,
                action: entry.action.clone(),
            };
            let receipt = reconstructed.apply(&r).unwrap();
            assert!(!receipt.repeated);
            assert_eq!(receipt.operation_sequence, entry.sequence);
            assert_eq!(receipt.outcome, entry.outcome);
        }
        assert_eq!(reconstructed.history(), history);
        assert_eq!(reconstructed.pending_operation(), None);
        let before = e.history();
        let next = request(&e, 90, Action::Reserve(record()));
        assert_eq!(e.apply(&next), Err(Error::Full));
        assert_eq!(e.history(), before);
        assert!(!e.frozen());
        let terminal = &history[history.len() - 2];
        let retry = Request {
            scope: scope(),
            operation: terminal.operation,
            request_nonce: [84; 32],
            expected_sequence: e.sequence(),
            action: terminal.action.clone(),
        };
        let receipt = e.apply(&retry).unwrap();
        assert!(receipt.repeated);
        assert_eq!(receipt.outcome, Outcome::Consumed);
        assert_eq!(receipt.operation_sequence, 4095);
        assert_eq!(e.history(), before);
    }
    #[test]
    fn lost_ack_freezes_both_paths_and_conflicting_retry_never_consumes() {
        let mut e = Engine::new(scope()).unwrap();
        let v = record();
        let r = request(&e, 10, Action::Reserve(v.clone()));
        let ack = e.apply(&r).unwrap();
        check_receipt(&r, &ack).unwrap();
        assert!(e.frozen());
        let mut retry = r.clone();
        retry.request_nonce = [99; 32];
        let repeated = e.apply(&retry).unwrap();
        assert!(repeated.repeated);
        check_receipt(&retry, &repeated).unwrap();
        assert_eq!(check_receipt(&retry, &ack), Err(Error::Stale));
        let mut other = v.clone();
        other.nonce = [8; 32];
        assert_eq!(
            e.apply(&request(&e, 11, Action::Reserve(other))),
            Err(Error::Frozen)
        );
        let mut conflict = retry;
        conflict.action = Action::Reserve(PublicRecord {
            generation: 2,
            ..v.clone()
        });
        assert_eq!(e.apply(&conflict), Err(Error::Conflict));
        assert_eq!(e.sequence(), 1);
        let confirm = request(
            &e,
            14,
            Action::ConfirmLocal {
                pending_operation: r.operation,
                exact: v.clone(),
            },
        );
        e.apply(&confirm).unwrap();
        assert!(!e.frozen());
        let mut signed = v;
        signed.signature = Some(vec![3; 1394]);
        let consume = request(&e, 12, Action::Consume(signed.clone()));
        assert!(!e.apply(&consume).unwrap().repeated);
        assert!(e.frozen());
        // Restoring local unconsumed state cannot undo authoritative consumption.
        assert!(e.apply(&consume).unwrap().repeated);
        let confirm = request(
            &e,
            15,
            Action::ConfirmLocal {
                pending_operation: consume.operation,
                exact: signed.clone(),
            },
        );
        e.apply(&confirm).unwrap();
        assert_eq!(
            e.apply(&request(&e, 13, Action::Consume(signed))),
            Err(Error::Replay)
        );
    }
    #[test]
    fn wrong_scope_stale_receipts_and_exact_reconciliation_are_required() {
        let mut e = Engine::new(scope()).unwrap();
        let v = record();
        let r = request(&e, 20, Action::Reserve(v.clone()));
        let mut wrong = r.clone();
        wrong.scope.service = [42; 32];
        assert_eq!(e.apply(&wrong), Err(Error::WrongScope));
        assert_eq!(e.sequence(), 0);
        let mut stale = r.clone();
        stale.expected_sequence = 3;
        assert_eq!(e.apply(&stale), Err(Error::Stale));
        let ack = e.apply(&r).unwrap();
        let mut bad = ack.clone();
        bad.scope.store = [45; 32];
        assert_eq!(check_receipt(&r, &bad), Err(Error::WrongScope));
        let mut altered = v.clone();
        altered.challenge[0] ^= 1;
        let bad = request(
            &e,
            21,
            Action::ConfirmLocal {
                pending_operation: r.operation,
                exact: altered,
            },
        );
        assert_eq!(e.apply(&bad), Err(Error::Conflict));
        assert!(e.frozen());
        let good = request(
            &e,
            21,
            Action::ConfirmLocal {
                pending_operation: r.operation,
                exact: v,
            },
        );
        e.apply(&good).unwrap();
    }
    #[test]
    fn concurrent_identical_requests_resolve_once_and_different_content_conflicts() {
        use std::sync::{Arc, Mutex};
        let mut engine = Engine::new(scope()).unwrap();
        let v = record();
        let reserve = request(&engine, 30, Action::Reserve(v.clone()));
        engine.apply(&reserve).unwrap();
        let confirm = request(
            &engine,
            31,
            Action::ConfirmLocal {
                pending_operation: reserve.operation,
                exact: v.clone(),
            },
        );
        engine.apply(&confirm).unwrap();
        let mut signed = v;
        signed.signature = Some(vec![5; 1394]);
        let consume = request(&engine, 32, Action::Consume(signed));
        let shared = Arc::new(Mutex::new(engine));
        let rows = std::thread::scope(|s| {
            let mut handles = Vec::new();
            for _ in 0..2 {
                let e = shared.clone();
                let r = consume.clone();
                handles.push(s.spawn(move || e.lock().unwrap().apply(&r).unwrap()));
            }
            handles
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert_eq!(rows.iter().filter(|r| !r.repeated).count(), 1);
        assert_eq!(rows.iter().filter(|r| r.repeated).count(), 1);
        assert_eq!(rows[0].operation_sequence, rows[1].operation_sequence);
        let mut changed = consume;
        if let Action::Consume(v) = &mut changed.action {
            v.signature.as_mut().unwrap()[0] ^= 1;
        }
        assert_eq!(shared.lock().unwrap().apply(&changed), Err(Error::Conflict));
        assert!(shared.lock().unwrap().frozen());
    }
    #[test]
    fn native_confirmed_consumption_detects_restored_rows_and_reconciles_only_exact_proof() {
        use crate::{
            treasury_admission_v3::AdmissionStore,
            treasury_rehearsal_v3::{CeremonyConfig, Denylist, Expect},
            treasury_v1::{Class, Treasury},
        };
        use mutiny_crypto_v2::{
            NETWORK, rehearsal_keys_v1::Credential, treasury_proof_v1 as proof,
        };
        use std::io::Write;
        let key = Credential::from_label("PUBLIC-CONTINUITY-RESTORE-V1", 1).unwrap();
        let descriptor = key.descriptor().unwrap();
        let config = CeremonyConfig::rehearsal(
            NETWORK,
            Treasury::new(Class::TestValue, descriptor.clone()).unwrap(),
            "PUBLIC-CONTINUITY-RESTORE-CONTEXT-V1",
        )
        .unwrap();
        let expect = Expect::genesis_key(&config);
        let deny = Denylist::default();
        let dir = super::test_dir::TestDir::new("treasury-continuity-confirmed-restore");
        let path = dir.file("original.sqlite");
        let old_path = dir.file("isolated-old-snapshot.sqlite");
        std::mem::forget(dir);
        let id = AdmissionStore::create(&path, &config).unwrap();
        let mut store = AdmissionStore::open(&path, &config, id).unwrap();
        let ch = store.issue(&expect, &descriptor, &deny).unwrap();
        let unsigned = PublicRecord {
            generation: ch.generation,
            nonce: ch.nonce,
            challenge: ch.encode().unwrap(),
            descriptor: descriptor.clone(),
            signature: None,
        };
        drop(store);
        // Copy only this isolated public TEST database, into a never-existing path.
        let before_consumption = std::fs::read(&path).unwrap();
        let mut old = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&old_path)
            .unwrap();
        old.write_all(&before_consumption).unwrap();
        old.sync_all().unwrap();
        drop(old);
        let sig = proof::sign_challenge(key.key(), &descriptor, &ch).unwrap();
        let mut signed = unsigned.clone();
        signed.signature = Some(proof::signature_to_bytes(&sig));
        let mut service = Engine::new(scope()).unwrap();
        let reserve = request(&service, 10, Action::Reserve(unsigned.clone()));
        service.apply(&reserve).unwrap();
        let confirm_reserve = request(
            &service,
            12,
            Action::ConfirmLocal {
                pending_operation: reserve.operation,
                exact: unsigned.clone(),
            },
        );
        service.apply(&confirm_reserve).unwrap();
        let consume = request(&service, 14, Action::Consume(signed.clone()));
        service.apply(&consume).unwrap();
        let mut original = AdmissionStore::open(&path, &config, id).unwrap();
        original
            .admit(&expect, &descriptor, &unsigned.challenge, &sig, &deny)
            .unwrap();
        let confirm_consume = request(
            &service,
            16,
            Action::ConfirmLocal {
                pending_operation: consume.operation,
                exact: signed.clone(),
            },
        );
        service.apply(&confirm_consume).unwrap();
        assert!(!service.frozen());
        assert_eq!(service.pending_operation(), None);
        assert!(matches!(&service.history()[2].action,Action::Consume(v) if v == &signed));
        let mut restored = AdmissionStore::open(&old_path, &config, id).unwrap();
        assert_eq!(
            restored.continuity_records().unwrap(),
            vec![unsigned.clone()]
        );
        assert_ne!(
            restored.continuity_records().unwrap(),
            vec![signed.clone()],
            "pending=None must not hide already-confirmed external consumption"
        );
        let before = std::fs::read(&old_path).unwrap();
        let mut forged = signed.clone();
        forged.signature.as_mut().unwrap()[0] ^= 1;
        assert!(
            restored
                .reconcile_continuity_records(&config, &[(expect.clone(), forged)], &deny)
                .is_err()
        );
        assert_eq!(std::fs::read(&old_path).unwrap(), before);
        assert_eq!(
            restored.continuity_records().unwrap(),
            vec![unsigned.clone()]
        );
        restored
            .reconcile_continuity_records(&config, &[(expect.clone(), signed.clone())], &deny)
            .unwrap();
        assert_eq!(restored.continuity_records().unwrap(), vec![signed.clone()]);
        restored
            .verify_issued(&expect, &descriptor, &unsigned.challenge, &sig, &deny)
            .unwrap();
        assert!(
            restored
                .admit(&expect, &descriptor, &unsigned.challenge, &sig, &deny)
                .is_err()
        );
        // Terminal history cannot be weakened back to an unconsumed reservation.
        assert!(
            restored
                .reconcile_continuity_records(&config, &[(expect.clone(), unsigned)], &deny)
                .is_err()
        );
        assert_eq!(restored.continuity_records().unwrap(), vec![signed.clone()]);
        restored
            .reconcile_continuity_records(&config, &[(expect, signed.clone())], &deny)
            .unwrap();
        drop(restored);
        assert_eq!(
            AdmissionStore::open(&old_path, &config, id)
                .unwrap()
                .continuity_records()
                .unwrap(),
            vec![signed]
        );
        assert_eq!(service.sequence(), 4);
        assert!(!service.frozen());
    }
    #[test]
    fn native_hybrid_verification_precedes_external_consumption_and_local_failure_freezes() {
        use crate::{
            treasury_admission_v3::AdmissionStore,
            treasury_rehearsal_v3::{CeremonyConfig, Denylist, Expect, Refusal},
            treasury_v1::{Class, Treasury},
        };
        use mutiny_crypto_v2::{
            NETWORK, rehearsal_keys_v1::Credential, treasury_proof_v1 as proof,
        };
        let key = Credential::from_label("PUBLIC-CONTINUITY-NATIVE-V1", 1).unwrap();
        let descriptor = key.descriptor().unwrap();
        let config = CeremonyConfig::rehearsal(
            NETWORK,
            Treasury::new(Class::TestValue, descriptor.clone()).unwrap(),
            "PUBLIC-CONTINUITY-NATIVE-CONTEXT-V1",
        )
        .unwrap();
        let expect = Expect::genesis_key(&config);
        let deny = Denylist::default();
        let dir = super::test_dir::TestDir::new("treasury-continuity-native");
        let path = dir.file("store.sqlite");
        // Retain this task-owned public database even on panic: failed/partial native
        // evidence must survive. The ordinary fixture helper otherwise removes it.
        std::mem::forget(dir);
        let id = AdmissionStore::create(&path, &config).unwrap();
        let mut store = AdmissionStore::open(&path, &config, id).unwrap();
        let protected_scope = Scope {
            network: NETWORK,
            genesis: None,
            ceremony_context: config.context().value(),
            treasury_record: crate::treasury_rehearsal_v3::record_sha256(config.treasury())
                .unwrap(),
            verifier: [51; 32],
            store: id.store_id(),
            service: [52; 32],
        };
        // This engine is an explicitly simulated external service in test memory,
        // outside the SQLite file. No actual protected boundary/authentication claim.
        let mut service = Engine::new(protected_scope.clone()).unwrap();
        let mut reserved = None;
        let challenge = store
            .issue_with_reservation(&expect, &descriptor, &deny, |ch, d| {
                let v = PublicRecord {
                    generation: ch.generation,
                    nonce: ch.nonce,
                    challenge: ch.encode().unwrap(),
                    descriptor: d.to_vec(),
                    signature: None,
                };
                let r = Request {
                    scope: protected_scope.clone(),
                    operation: [53; 32],
                    request_nonce: [54; 32],
                    expected_sequence: service.sequence(),
                    action: Action::Reserve(v.clone()),
                };
                assert!(!service.apply(&r).unwrap().repeated);
                reserved = Some(v);
                Ok(())
            })
            .unwrap();
        let unsigned = reserved.unwrap();
        assert!(service.frozen());
        assert_eq!(
            store.issued(&challenge.nonce).unwrap().unwrap().challenge,
            unsigned.challenge
        );
        let confirmed = Request {
            scope: protected_scope.clone(),
            operation: [55; 32],
            request_nonce: [56; 32],
            expected_sequence: service.sequence(),
            action: Action::ConfirmLocal {
                pending_operation: [53; 32],
                exact: unsigned.clone(),
            },
        };
        service.apply(&confirmed).unwrap();
        let signature = proof::sign_challenge(key.key(), &descriptor, &challenge).unwrap();
        let mut bad = signature.clone();
        bad.ed448[10] ^= 1;
        let mut called = false;
        assert!(
            store
                .admit_with_consumption(
                    &expect,
                    &descriptor,
                    &unsigned.challenge,
                    &bad,
                    &deny,
                    |_| {
                        called = true;
                        Ok(())
                    }
                )
                .is_err()
        );
        assert!(
            !called,
            "invalid real hybrid signature reached external consumption"
        );
        assert!(!service.frozen());
        let mut signed = unsigned.clone();
        signed.signature = Some(proof::signature_to_bytes(&signature));
        let consume = Request {
            scope: protected_scope.clone(),
            operation: [57; 32],
            request_nonce: [58; 32],
            expected_sequence: service.sequence(),
            action: Action::Consume(signed.clone()),
        };
        // Fail exactly after authoritative consumption and before any local consume.
        assert_eq!(
            store.admit_with_consumption(
                &expect,
                &descriptor,
                &unsigned.challenge,
                &signature,
                &deny,
                |_| {
                    assert!(!service.apply(&consume).unwrap().repeated);
                    Err(Refusal::Store)
                }
            ),
            Err(Refusal::Store)
        );
        assert!(service.frozen());
        assert!(!store.issued(&challenge.nonce).unwrap().unwrap().consumed);
        assert_eq!(store.recorded(&challenge.nonce).unwrap(), None);
        drop(store);
        let mut reopened = AdmissionStore::open(&path, &config, id).unwrap();
        let repeated = service.apply(&consume).unwrap();
        assert!(repeated.repeated);
        // The native local row is still unconsumed, but ALREADY external outcome
        // cannot be turned into another ordinary logical admission after restart.
        assert_eq!(
            reopened.admit_with_consumption(
                &expect,
                &descriptor,
                &unsigned.challenge,
                &signature,
                &deny,
                |_| Err(Refusal::Replay)
            ),
            Err(Refusal::Replay)
        );
        assert_eq!(reopened.recorded(&challenge.nonce).unwrap(), None);
        assert!(
            service.frozen(),
            "uncertain local transition was improperly unfrozen"
        );
    }
}
