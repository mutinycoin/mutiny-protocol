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

