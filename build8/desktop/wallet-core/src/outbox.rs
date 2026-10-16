//! The wallet's durable queue of signed operations, with input reservations.
//!
//! Contract (generalised from the payment outbox of the existing desktop wallet):
//!
//!  * The EXACT signed bytes are committed before success is reported. A returned id means
//!    "queued locally", never "delivered" and never "settled".
//!  * Committing independently re-verifies the bytes through consensus code against the current
//!    verified view, so bytes that did not come from a successful authorization (or that were
//!    imported) cannot be queued unchecked. Nothing the caller says about the operation is taken on
//!    trust: the identifier, completeness, signatures still missing, validity window and reserved
//!    coins are DERIVED from the bytes by the kind's handler, and a [`SignedOperation`] whose fields
//!    disagree with its bytes is refused (a wrong `reserved` would let a second plan spend the same
//!    coin; a wrong `validity` would settle the record at the wrong time).
//!  * Every input an operation consumes is RESERVED until the record settles, so a second plan
//!    cannot select a coin that is already committed. Merge [`Outbox::reserved`] with the
//!    transaction pool's reservations when building a `ChainView`. Things that are not coins (a
//!    License on offer, an award account's claim, a bond lot) are reserved through
//!    [`resource_key`], which gives them a key that can never equal a coin's outpoint.
//!  * Reconciliation reads verified state only. A record is `Confirmed` only on verified evidence,
//!    and a view older than the head at which a record was queued says nothing about it.
//!  * There is no "revoke". [`Outbox::forget`] drops the local record and releases its
//!    reservations; it does NOT cancel the signed bytes, which stay valid until they are included
//!    or expire.
//!  * A partial record (a multi-party operation that still lacks signatures) is completed with
//!    [`Outbox::replace_partial`]: the complete operation takes the partial's place and its
//!    reservations in ONE atomic step (forgetting the partial and then committing the complete
//!    operation leaves a window in which neither is queued). `commit` itself is unchanged.
//!  * Only OPEN records count against the capacity limits and hold reservations. Settled records
//!    (confirmed, expired, inputs spent, stranded, forgotten) are history: they never lock anyone out, and are
//!    trimmed to the newest [`DEFAULT_MAX_SETTLED`] by every reconciliation (or on demand with
//!    [`Outbox::prune_settled`]).
//!  * An outbox belongs to one chain (network, Genesis, protocol fingerprint): a view of any other
//!    chain is refused with `WrongContext`.
//!  * Transport is not this module's job, and no delivery is claimed (Q1). [`Outbox::pending`] lists
//!    the open records after re-checking only their unkeyed checksum: it is NOT authentication and
//!    its records are not for delivery. [`Outbox::export_verified`] is the export for delivery: it
//!    re-verifies one record against the verified view before it releases the bytes (the bytes,
//!    every signature, the approval binding recorded by [`Outbox::commit_approved`] and the verified
//!    status; `crate::export`, Order W6).
//!
//! What the checksum is for: every record carries a checksum over its kind, identifier, bytes and
//! metadata, and every read re-checks it. That catches accidental damage and careless edits. It is
//! NOT a defence against someone who can rewrite the file (they can recompute it): the protections
//! that hold against that person are that queued bytes are already signed and cannot be altered
//! into a different valid operation, that `commit` re-verifies them through consensus code, and that
//! the chain rejects anything invalid.
//!
//! [`MemoryOutbox`] is the reference implementation (nothing survives the process).
//! [`SqliteOutbox`](crate::outbox_sqlite::SqliteOutbox) is the durable one: the same trait and the same
//! semantics, with the exact bytes committed in one atomic transaction before success is reported.
//! Any other durable implementation must keep them: commit is atomic and idempotent per id, records
//! carry a checksum over everything but their status, and every read re-verifies it.
use crate::{
    authorize::SignedOperation,
    context::{ChainContext, ChainView},
    export::{ApprovalBinding, VerifiedExport},
    partial::{
        MAX_REQUIREMENTS, MAX_RESERVED, get_points, get_requirements, get_validity, put_points,
        put_requirements, put_validity,
    },
    plan::{Description, OperationKind, Requirement, Validity},
    refusal::{ContextField, Refusal},
    units,
};
use minicbor::{Decoder, Encoder};
use mutiny_consensus_v8::{Hash, domain_hash, transactions::OutPoint};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

/// Largest stored operation in bytes (the container bound of [`crate::partial`]).
pub const MAX_RECORD_BYTES: usize = 64 * 1024;

/// How many settled records an outbox keeps as history by default; older ones are dropped when a
/// reconciliation settles more. Open records are never dropped.
pub const DEFAULT_MAX_SETTLED: usize = 1024;

/// Where a record stands in verified state (the result of a kind's reconciliation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Settlement {
    /// Still waiting.
    Pending,
    /// Included in verified history at this height.
    Confirmed(u64),
    /// Its validity window ended without inclusion.
    Expired,
    /// Its inputs are gone but it is not known to be the spender: another operation consumed them,
    /// or this one was included and its own outputs were spent again.
    InputsSpent,
    /// DIAGNOSTIC of an old or test failure only (Order W9): the funding payment of a bond creation
    /// was included at this height WITHOUT the creation, so the principal is stranded in its escrow
    /// output (`ops::bond::stranded_escrow`). It reports what verified state shows; it does not
    /// replace atomic funding, which is the protocol's job (Lane P), and a host must not treat it as
    /// a recovery path. Before this variant existed such a record settled as `InputsSpent`.
    Stranded(u64),
}

/// Lifecycle of one outbox record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum OutboxStatus {
    /// Queued locally; its inputs are reserved.
    Queued,
    Confirmed(u64),
    Expired,
    InputsSpent,
    /// Dropped locally by the user; the signed bytes may still be valid elsewhere.
    Forgotten,
    /// The diagnostic [`Settlement::Stranded`]: a bond creation's funding was included at this height
    /// without the creation. Settled (it reserves nothing); not a replacement for atomic funding.
    Stranded(u64),
}

impl OutboxStatus {
    /// Whether the record still reserves its inputs.
    pub fn is_open(self) -> bool {
        matches!(self, Self::Queued)
    }
}

/// Everything about a record except its bytes, identity and status, as stored durably.
pub(crate) struct RecordMeta {
    pub complete: bool,
    pub missing: Vec<Requirement>,
    pub validity: Validity,
    pub reserved: Vec<OutPoint>,
    pub queued_at: u64,
    /// The approval binding recorded with the record (W6), if any.
    pub approval: Option<ApprovalBinding>,
}

/// One queued operation.
#[derive(Clone, PartialEq, Eq)]
pub struct OutboxRecord {
    pub id: Hash,
    pub kind: OperationKind,
    /// The exact signed (or partially signed) bytes.
    pub bytes: Vec<u8>,
    pub complete: bool,
    pub missing: Vec<Requirement>,
    pub validity: Validity,
    /// Coins and resources (see [`resource_key`]) this record holds while it is open.
    pub reserved: Vec<OutPoint>,
    /// Height of the verified head when it was queued.
    pub queued_at_height: u64,
    pub status: OutboxStatus,
    /// The binding of the approval the operation was authorized with, when it was queued with
    /// [`Outbox::commit_approved`] (covered by the checksum; see [`Self::approval`]).
    approval: Option<ApprovalBinding>,
    checksum: Hash,
}

impl OutboxRecord {
    /// Canonical encoding of everything about the record except its (mutable) status: whether it is
    /// complete, the signatures still missing, its validity, the coins it reserves and the head it was
    /// queued at. Durable storage keeps exactly these bytes.
    /// A record without an approval binding keeps the five-field encoding it always had (so its
    /// checksum is unchanged); one with a binding (W6) appends it as a sixth field.
    pub(crate) fn meta_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(if self.approval.is_some() { 6 } else { 5 })
            .unwrap();
        e.bool(self.complete).unwrap();
        put_requirements(&mut e, &self.missing);
        put_validity(&mut e, &self.validity);
        put_points(&mut e, &self.reserved);
        e.u64(self.queued_at_height).unwrap();
        if let Some(approval) = &self.approval {
            e.bytes(&approval.encode()).unwrap();
        }
        e.into_writer()
    }

    /// Decode [`Self::meta_bytes`]; any irregularity is an integrity failure.
    pub(crate) fn decode_meta(raw: &[u8]) -> Result<RecordMeta, Refusal> {
        let bad = |_| Refusal::OutboxIntegrity;
        let d = &mut Decoder::new(raw);
        let fields = d.array().map_err(bad)?;
        if fields != Some(5) && fields != Some(6) {
            return Err(Refusal::OutboxIntegrity);
        }
        let complete = d.bool().map_err(bad)?;
        let missing = get_requirements(d).map_err(|_| Refusal::OutboxIntegrity)?;
        let validity = get_validity(d).map_err(|_| Refusal::OutboxIntegrity)?;
        let reserved = get_points(d).map_err(|_| Refusal::OutboxIntegrity)?;
        let queued_at = d.u64().map_err(bad)?;
        let approval = if fields == Some(6) {
            Some(ApprovalBinding::decode(d.bytes().map_err(bad)?)?)
        } else {
            None
        };
        if d.position() != raw.len() {
            return Err(Refusal::OutboxIntegrity);
        }
        Ok(RecordMeta {
            complete,
            missing,
            validity,
            reserved,
            queued_at,
            approval,
        })
    }

    fn compute_checksum(&self) -> Hash {
        let meta = self.meta_bytes();
        let mut body = self.kind.code().to_be_bytes().to_vec();
        body.extend_from_slice(&self.id);
        body.extend_from_slice(&(self.bytes.len() as u32).to_be_bytes());
        body.extend_from_slice(&self.bytes);
        body.extend_from_slice(&meta);
        domain_hash(b"MUTINY-BUILD8-WALLET-OUTBOX-RECORD-V2", &body)
    }

    /// The binding of the approval this operation was authorized with, when it was queued with
    /// [`Outbox::commit_approved`]; `None` for imported bytes, a counterparty's part, or an outbox
    /// that does not keep bindings. Like the checksum it is unkeyed: consistency, not
    /// authentication (`crate::export`).
    pub fn approval(&self) -> Option<&ApprovalBinding> {
        self.approval.as_ref()
    }

    /// The record with the approval binding read back from durable storage (before `verify`).
    pub(crate) fn with_approval(mut self, approval: Option<ApprovalBinding>) -> Self {
        self.approval = approval;
        self
    }

    /// Recompute the checksum after an edit (test hooks that model someone who can rewrite the
    /// store, and therefore the unkeyed checksum).
    #[cfg(any(test, feature = "test-value-signing"))]
    pub(crate) fn rechecksum_for_test(&mut self) {
        self.checksum = self.compute_checksum();
    }

    /// Test builds only: replace the approval binding (a store rewrite; the checksum is NOT
    /// recomputed here).
    #[cfg(any(test, feature = "test-value-signing"))]
    pub fn set_approval_for_test(&mut self, approval: Option<ApprovalBinding>) {
        self.approval = approval;
    }

    /// Re-check the record's checksum. Every read of a durable record must do this.
    pub fn verify(&self) -> Result<(), Refusal> {
        if self.compute_checksum() == self.checksum {
            Ok(())
        } else {
            Err(Refusal::OutboxIntegrity)
        }
    }

    /// Rebuild a record read from durable storage; the stored checksum is kept so `verify` can
    /// detect any change.
    #[allow(clippy::too_many_arguments)]
    pub fn from_stored(
        id: Hash,
        kind: OperationKind,
        bytes: Vec<u8>,
        complete: bool,
        missing: Vec<Requirement>,
        validity: Validity,
        reserved: Vec<OutPoint>,
        queued_at_height: u64,
        status: OutboxStatus,
        checksum: Hash,
    ) -> Self {
        Self {
            id,
            kind,
            bytes,
            complete,
            missing,
            validity,
            reserved,
            queued_at_height,
            status,
            approval: None,
            checksum,
        }
    }

    /// The stored checksum (for durable implementations).
    pub fn checksum(&self) -> Hash {
        self.checksum
    }
}

impl fmt::Debug for OutboxRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboxRecord")
            .field("kind", &self.kind)
            .field("id", &units::short_hex(&self.id))
            .field("bytes", &self.bytes.len())
            .field("complete", &self.complete)
            .field("reserved", &self.reserved.len())
            .field("status", &self.status)
            .finish()
    }
}

/// Result of one reconciliation pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReconcileReport {
    pub confirmed: usize,
    pub expired: usize,
    pub inputs_spent: usize,
    /// Records that settled as the diagnostic [`Settlement::Stranded`].
    pub stranded: usize,
    pub still_pending: usize,
    /// Settled records dropped from the history afterwards (see [`DEFAULT_MAX_SETTLED`]).
    pub pruned: usize,
}

/// A reservation key for something that is not a coin: a License being sold, an award account's
/// claim sequence, a bond lot, a hash-lock output. It has the shape of an [`OutPoint`] in its own
/// hash namespace (the `index` is `u32::MAX`, which no real output has, and the `transaction` is a
/// domain-separated hash that is not the identifier of any transaction), so it can never equal a
/// coin's outpoint and it travels unchanged through `ChainView::reserved`,
/// [`SignedOperation::reserved`], the outbox and its durable storage.
///
/// A handler returns the keys of everything its operation consumes from `OperationHandler::describe`
/// and refuses to plan over anything `ChainView::reserved` already holds. `namespace` names the kind
/// of resource ("license", "claim", ...) and is length-prefixed, so two different namespaces can never
/// collide whatever the identifier.
pub fn resource_key(namespace: &str, id: &Hash) -> OutPoint {
    let mut body = Vec::with_capacity(8 + namespace.len() + id.len());
    body.extend_from_slice(&(namespace.len() as u64).to_be_bytes());
    body.extend_from_slice(namespace.as_bytes());
    body.extend_from_slice(id);
    OutPoint {
        transaction: domain_hash(b"MUTINY-BUILD8-WALLET-RESOURCE-RESERVATION-V1", &body),
        index: u32::MAX,
    }
}

/// Every namespace a handler passes to [`resource_key`], with the one kind of resource it reserves
/// (phase 8 registry; `tests/cross_kind.rs` checks every call site against it and that no two are
/// equal). Two pairs name ids of one consensus table that are disjoint by kind, so they never
/// reserve the same thing: an offer is filled by a hash lock or by a License sale or fiat lock
/// according to its terms ("trade-offer" and "offer"), and a lock is claimed or refunded, or
/// released, according to whether it is a hash lock or a fiat lock ("hash-lock" and "lock").
pub const RESOURCE_NAMESPACES: [(&str, &str); 10] = [
    (
        crate::ops::rotation::ROTATION_RESOURCE,
        "the one pending rotation of a wallet authority",
    ),
    (
        crate::discovery::dividends::CLAIM_SLOT_NAMESPACE,
        "the one outstanding claim of an (award, License) account",
    ),
    (crate::ops::bond::LOT_RESOURCE, "a bond lot"),
    (
        crate::ops::conditional::OFFER_NAMESPACE,
        "the single fill of a hash-linked maker offer (by a hash lock)",
    ),
    (
        crate::ops::conditional::LOCK_NAMESPACE,
        "an open hash lock (spent by its claim or its refund)",
    ),
    (crate::offers::LICENSE_RESOURCE, "a License being sold"),
    (
        crate::offers::OFFER_RESOURCE,
        "the single fill of a License or fiat maker offer (by a sale or a fiat lock)",
    ),
    (
        crate::offers::LOCK_RESOURCE,
        "an open fiat lock (spent by its release)",
    ),
    (
        crate::ops::treasury::ROTATION_NAMESPACE,
        "the one pending destination rotation of a trading Treasury generation",
    ),
    (
        crate::ops::treasury::FREEZE_NAMESPACE,
        "the one pending freeze of a Treasury offer",
    ),
];

/// What `signed` commits to, derived from its BYTES by the kind's handler, after checking that
/// every field the caller supplied agrees with it. No view is needed: this is the part of admission
/// that cannot depend on chain state, so a durable outbox can use it to find a record's identifier
/// before it reads the store.
pub(crate) fn describe_checked(signed: &SignedOperation) -> Result<Description, Refusal> {
    let described = crate::ops::handler(signed.kind())?.describe(signed.bytes())?;
    if !signed.matches(&described) {
        return Err(Refusal::VerificationFailed(
            "the operation's metadata does not match its bytes",
        ));
    }
    Ok(described)
}

/// Independently verify `signed` against the view and build the record to store. Shared by every
/// implementation, so none can skip the check.
///
/// The record's identifier, completeness, missing signatures, validity and reserved coins are
/// DERIVED from the bytes; a `SignedOperation` that disagrees is refused.
pub fn admit_record(
    signed: &SignedOperation,
    view: &ChainView<'_>,
) -> Result<OutboxRecord, Refusal> {
    let described = describe_checked(signed)?;
    admit_described(signed, described, view, None)
}

/// [`admit_record`] for a caller that already ran [`describe_checked`].
pub(crate) fn admit_described(
    signed: &SignedOperation,
    described: Description,
    view: &ChainView<'_>,
    approval: Option<ApprovalBinding>,
) -> Result<OutboxRecord, Refusal> {
    if let Some(binding) = &approval {
        binding.check(signed.kind(), signed.bytes(), view)?;
    }
    crate::ops::handler(signed.kind())?.check_signed(signed, view)?;
    if described
        .reserved
        .iter()
        .any(|point| view.reserved().contains(point))
    {
        return Err(Refusal::ReservedInput);
    }
    queued_record(signed, described, view, approval)
}

/// Independently verify `complete` as the completion of the open partial record `partial` and build
/// the record that replaces it. Shared by every implementation of [`Outbox::replace_partial`], so
/// none can skip a check.
///
/// `partial` must be an open record that still lacks signatures; `complete` must be complete, of the
/// same kind and the same OPERATION (the kind's operation identity, which does not depend on the
/// signatures present), and must reserve exactly the coins and resources the partial holds, with
/// the same validity. Anything else is `OUTBOX_INTEGRITY`, the refusal `commit` gives to other bytes
/// under an existing record. The complete operation is then verified through consensus code
/// against `view`, like every commit. It takes over the partial's reservations and reserves
/// nothing new, so the view's reservations (which include the partial's own when a host merges
/// the outbox into them) are not consulted again.
pub(crate) fn admit_replacement(
    partial: &OutboxRecord,
    complete: &SignedOperation,
    described: Description,
    view: &ChainView<'_>,
) -> Result<OutboxRecord, Refusal> {
    partial.verify()?;
    if !partial.status.is_open()
        || partial.complete
        || !described.complete
        || !complete.is_complete()
        || complete.kind() != partial.kind
    {
        return Err(Refusal::OutboxIntegrity);
    }
    let handler = crate::ops::handler(partial.kind)?;
    if handler.operation_identity(&partial.bytes)?
        != handler.operation_identity(complete.bytes())?
    {
        return Err(Refusal::OutboxIntegrity);
    }
    let held: BTreeSet<&OutPoint> = partial.reserved.iter().collect();
    let wanted: BTreeSet<&OutPoint> = described.reserved.iter().collect();
    if held != wanted || described.validity != partial.validity {
        return Err(Refusal::OutboxIntegrity);
    }
    handler.check_signed(complete, view)?;
    // The partial's approval binding covers the complete operation too (the digest binds the
    // unsigned form, which the signatures do not change); it is checked against the new bytes.
    if let Some(binding) = partial.approval() {
        binding.check(complete.kind(), complete.bytes(), view)?;
    }
    queued_record(complete, described, view, partial.approval.clone())
}

/// [`admit_record`] for a replacement: derive `complete`'s metadata from its bytes, then verify it
/// as the completion of the open partial record `partial` (see `admit_replacement`) and build the
/// record that replaces it. For an outbox implemented outside this crate (the desktop's sealed
/// outbox), so that its [`Outbox::replace_partial`] cannot skip a check either.
pub fn admit_replacement_record(
    partial: &OutboxRecord,
    complete: &SignedOperation,
    view: &ChainView<'_>,
) -> Result<OutboxRecord, Refusal> {
    let described = describe_checked(complete)?;
    admit_replacement(partial, complete, described, view)
}

/// The record to store for `signed`, queued at `view`'s head.
fn queued_record(
    signed: &SignedOperation,
    described: Description,
    view: &ChainView<'_>,
    approval: Option<ApprovalBinding>,
) -> Result<OutboxRecord, Refusal> {
    // Per-record bounds of the durable encoding, enforced for every implementation alike.
    if signed.bytes().len() > MAX_RECORD_BYTES
        || described.reserved.len() > MAX_RESERVED
        || described.missing.len() > MAX_REQUIREMENTS
    {
        return Err(Refusal::OutboxFull);
    }
    let mut record = OutboxRecord {
        id: described.id,
        kind: signed.kind(),
        bytes: signed.bytes().to_vec(),
        complete: described.complete,
        missing: described.missing,
        validity: described.validity,
        reserved: described.reserved,
        queued_at_height: view.anchor().height,
        status: OutboxStatus::Queued,
        approval,
        checksum: [0; 32],
    };
    record.checksum = record.compute_checksum();
    Ok(record)
}

/// Run the kind's reconciliation for one open record. A view older than the head at which the
/// record was queued cannot say anything about it (coins created since would look missing), so the
/// record stays pending.
pub fn settle(record: &OutboxRecord, view: &ChainView<'_>) -> Result<Settlement, Refusal> {
    if view.anchor().height < record.queued_at_height {
        return Ok(Settlement::Pending);
    }
    Ok(crate::ops::handler(record.kind)?.reconcile(record, view))
}

/// The wrong-chain refusal for a view whose context differs from the outbox's.
pub(crate) fn context_refusal(ours: &ChainContext, theirs: &ChainContext) -> Refusal {
    Refusal::WrongContext(if ours.network != theirs.network {
        ContextField::Network
    } else if ours.genesis != theirs.genesis {
        ContextField::Genesis
    } else {
        ContextField::Fingerprint
    })
}

/// The queue of signed operations. See the module documentation for the contract.
pub trait Outbox {
    /// Verify `signed` through consensus code, then durably record it and reserve its inputs.
    /// Idempotent per operation id while the record is open. Returns the id; success means
    /// "queued", never "delivered".
    fn commit(&mut self, signed: &SignedOperation, view: &ChainView<'_>) -> Result<Hash, Refusal>;

    /// Replace the OPEN partial record `partial` (a multi-party operation that still lacks
    /// signatures) by `complete`, the complete form of the same operation, in one atomic step: the
    /// complete record takes over the partial's reservations, and no reader ever sees neither or
    /// both. `complete` is verified through consensus code against `view` like every commit and must
    /// be that very operation (the same kind and operation identity, the same reserved coins and
    /// resources, the same validity); anything else, and a `partial` that is complete or no longer
    /// open, is `OUTBOX_INTEGRITY` and changes nothing. No record `partial` is `UNKNOWN_OPERATION`.
    /// Returns the complete record's identifier, which differs from the partial's for a kind that
    /// identifies a partial by its exact bytes (conditional MUT). Idempotent: once the complete
    /// record is queued, the same call returns its identifier again. `commit` is unchanged: it still
    /// refuses the complete bytes while the partial holds their identifier or their reservations.
    ///
    /// The default implementation, for an outbox written before this method existed, refuses with
    /// `OUTBOX_INTEGRITY` (what `commit` answers for the complete bytes) and changes nothing. Such an
    /// outbox keeps the non-atomic path, which leaves a window with neither record: `forget` the
    /// partial (and prune it when the complete operation has the same identifier), then `commit`.
    fn replace_partial(
        &mut self,
        partial: &Hash,
        complete: &SignedOperation,
        view: &ChainView<'_>,
    ) -> Result<Hash, Refusal> {
        let _ = (partial, complete, view);
        Err(Refusal::OutboxIntegrity)
    }

    /// Every record, oldest id first, each re-verified on read.
    fn records(&self) -> Result<Vec<OutboxRecord>, Refusal>;

    /// One record by operation id.
    fn get(&self, id: &Hash) -> Result<Option<OutboxRecord>, Refusal>;

    /// Update every open record from verified state. A view for another chain is refused. Settled
    /// records beyond the history limit are dropped afterwards.
    fn reconcile(&mut self, view: &ChainView<'_>) -> Result<ReconcileReport, Refusal>;

    /// Drop the local record and release its reservations. Does not cancel the signed bytes.
    fn forget(&mut self, id: &Hash) -> Result<(), Refusal>;

    /// Delete settled records (confirmed, expired, inputs spent, forgotten), keeping the `keep`
    /// most recently queued. Open records are never touched. Returns how many were deleted.
    fn prune_settled(&mut self, keep: usize) -> Result<usize, Refusal>;

    /// Coins and resources reserved by open records.
    fn reserved(&self) -> Result<BTreeSet<OutPoint>, Refusal> {
        let mut out = BTreeSet::new();
        for record in self.records()? {
            if record.status.is_open() {
                out.extend(record.reserved.iter().cloned());
            }
        }
        Ok(out)
    }

    /// [`Self::commit`] for an operation this wallet authorized: `approval` is the binding of the
    /// approval it was authorized with ([`crate::authorize::Approval::binding`], taken before
    /// `Signer::authorize` consumed the approval). The binding is checked against the bytes (their
    /// unsigned form at the approved head has the approved digest, of the same kind, on this chain,
    /// at a head no later than the view's: `APPROVAL_BINDING_MISMATCH` or `WRONG_CONTEXT`
    /// otherwise) and stored with the record, so [`Self::export_verified`] checks it again (W6).
    /// Idempotent like `commit` for the same bytes under the same binding; the same bytes already
    /// queued under another binding (or none) are `APPROVAL_BINDING_MISMATCH`.
    ///
    /// The default implementation, for an outbox that does not store bindings (one written before
    /// this method existed), checks the binding and commits WITHOUT storing it;
    /// `export_verified` then reports the record's approval as `NotRecorded`.
    fn commit_approved(
        &mut self,
        signed: &SignedOperation,
        approval: &ApprovalBinding,
        view: &ChainView<'_>,
    ) -> Result<Hash, Refusal> {
        approval.check(signed.kind(), signed.bytes(), view)?;
        self.commit(signed, view)
    }

    /// Export one record for DELIVERY after verifying it against `view`, the host's current
    /// verified head: its bytes, the approval binding recorded with it, its status from verified
    /// state, and every signature through consensus code (`crate::export::verify_record`). A record
    /// that cannot be delivered now is `NOT_DELIVERABLE` with the reason; the default
    /// implementation reads the record with [`Self::get`]. Unlike [`Self::pending`], this is the
    /// path for handing bytes to a transport.
    fn export_verified(&self, id: &Hash, view: &ChainView<'_>) -> Result<VerifiedExport, Refusal> {
        let record = self.get(id)?.ok_or(Refusal::UnknownOperation)?;
        crate::export::verify_record(&record, view)
    }

    /// Open records, re-checked against their UNKEYED checksum only: accidental damage is caught,
    /// a rewrite of the store is not (it can recompute the checksum). NOT authentication and not
    /// for delivery: use [`Self::export_verified`] to hand bytes to a transport (W6).
    fn pending(&self) -> Result<Vec<OutboxRecord>, Refusal> {
        Ok(self
            .records()?
            .into_iter()
            .filter(|record| record.status.is_open())
            .collect())
    }
}

/// In-memory outbox: the reference implementation of the contract. Nothing survives the process. It
/// is bound to the chain of the first operation committed and refuses views of any other chain.
pub struct MemoryOutbox {
    records: BTreeMap<Hash, OutboxRecord>,
    /// Identifiers in the order their records were queued (oldest first), to trim history.
    order: Vec<Hash>,
    bound: Option<ChainContext>,
    /// Limits on OPEN records only: settled records are history and never lock anyone out.
    max_records: usize,
    max_bytes: usize,
    max_settled: usize,
}

impl MemoryOutbox {
    pub const DEFAULT_MAX_RECORDS: usize = 4096;
    pub const DEFAULT_MAX_BYTES: usize = 16 * 1024 * 1024;

    pub fn new() -> Self {
        Self::with_limits(Self::DEFAULT_MAX_RECORDS, Self::DEFAULT_MAX_BYTES)
    }

    /// Limits on the number and the total size of OPEN records.
    pub fn with_limits(max_records: usize, max_bytes: usize) -> Self {
        Self {
            records: BTreeMap::new(),
            order: Vec::new(),
            bound: None,
            max_records,
            max_bytes,
            max_settled: DEFAULT_MAX_SETTLED,
        }
    }

    /// How many settled records reconciliation keeps as history (default [`DEFAULT_MAX_SETTLED`]).
    pub fn set_max_settled(&mut self, keep: usize) {
        self.max_settled = keep;
    }

    fn check_context(&self, view: &ChainView<'_>) -> Result<(), Refusal> {
        match &self.bound {
            Some(bound) if *bound != view.context() => Err(context_refusal(bound, &view.context())),
            _ => Ok(()),
        }
    }

    fn open(&self) -> impl Iterator<Item = &OutboxRecord> {
        self.records
            .values()
            .filter(|record| record.status.is_open())
    }

    fn open_reserved(&self) -> BTreeSet<OutPoint> {
        self.open()
            .flat_map(|record| record.reserved.iter().cloned())
            .collect()
    }

    /// Test builds only: rewrite a stored record and recompute its (unkeyed) checksum, as someone
    /// who can rewrite the store could (W6 export tests).
    #[cfg(any(test, feature = "test-value-signing"))]
    pub fn rewrite_for_test(&mut self, id: &Hash, edit: impl FnOnce(&mut OutboxRecord)) {
        if let Some(record) = self.records.get_mut(id) {
            edit(record);
            record.rechecksum_for_test();
        }
    }

    /// Test hook: damage a stored record so integrity checks can be exercised.
    #[cfg(any(test, feature = "test-value-signing"))]
    pub fn corrupt_for_test(&mut self, id: &Hash) {
        if let Some(byte) = self
            .records
            .get_mut(id)
            .and_then(|record| record.bytes.first_mut())
        {
            *byte ^= 1;
        }
    }
}

impl fmt::Debug for MemoryOutbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryOutbox")
            .field("records", &self.records.len())
            .field("open", &self.open().count())
            .field("max_records", &self.max_records)
            .field("max_bytes", &self.max_bytes)
            .field("max_settled", &self.max_settled)
            .finish()
    }
}

impl Default for MemoryOutbox {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryOutbox {
    /// `commit` and `commit_approved` in one: `approval` is `None` for a plain commit.
    fn commit_with(
        &mut self,
        signed: &SignedOperation,
        approval: Option<ApprovalBinding>,
        view: &ChainView<'_>,
    ) -> Result<Hash, Refusal> {
        self.check_context(view)?;
        // The identifier is the one the BYTES commit to, never the caller's claim.
        let described = describe_checked(signed)?;
        let id = described.id;
        // Idempotent while the record is open: the same bytes again change nothing (and are not
        // re-checked against reservations that this very record holds). A settled or forgotten
        // record is admitted afresh below, so a confirmed or expired operation is refused rather
        // than reported as queued.
        if let Some(existing) = self.records.get(&id) {
            existing.verify()?;
            if existing.bytes != signed.bytes() {
                return Err(Refusal::OutboxIntegrity);
            }
            if existing.status.is_open() {
                if approval.is_some() && existing.approval != approval {
                    return Err(Refusal::ApprovalBindingMismatch(
                        "the operation is already queued under another approval binding",
                    ));
                }
                return Ok(id);
            }
        }
        let record = admit_described(signed, described, view, approval)?;
        let others = self.open_reserved();
        if record.reserved.iter().any(|point| others.contains(point)) {
            return Err(Refusal::ReservedInput);
        }
        let open_bytes: usize = self.open().map(|r| r.bytes.len()).sum();
        if self.open().count() >= self.max_records
            || open_bytes
                .checked_add(record.bytes.len())
                .is_none_or(|sum| sum > self.max_bytes)
        {
            return Err(Refusal::OutboxFull);
        }
        self.order.retain(|queued| *queued != id);
        self.order.push(id);
        self.records.insert(id, record);
        self.bound.get_or_insert(view.context());
        Ok(id)
    }
}

impl Outbox for MemoryOutbox {
    fn commit(&mut self, signed: &SignedOperation, view: &ChainView<'_>) -> Result<Hash, Refusal> {
        self.commit_with(signed, None, view)
    }

    fn commit_approved(
        &mut self,
        signed: &SignedOperation,
        approval: &ApprovalBinding,
        view: &ChainView<'_>,
    ) -> Result<Hash, Refusal> {
        self.commit_with(signed, Some(approval.clone()), view)
    }

    fn export_verified(&self, id: &Hash, view: &ChainView<'_>) -> Result<VerifiedExport, Refusal> {
        // A view of another chain is refused before anything else.
        self.check_context(view)?;
        let record = self.records.get(id).ok_or(Refusal::UnknownOperation)?;
        crate::export::verify_record(record, view)
    }

    fn replace_partial(
        &mut self,
        partial: &Hash,
        complete: &SignedOperation,
        view: &ChainView<'_>,
    ) -> Result<Hash, Refusal> {
        self.check_context(view)?;
        // The identifier is the one the BYTES commit to, never the caller's claim.
        let described = describe_checked(complete)?;
        let id = described.id;
        // Idempotent: the complete record is already queued (a retry after success). Other bytes
        // under its identifier are refused, unless that record is the partial itself.
        if let Some(existing) = self.records.get(&id) {
            existing.verify()?;
            if existing.bytes == complete.bytes() {
                if existing.status.is_open() {
                    return Ok(id);
                }
            } else if id != *partial {
                return Err(Refusal::OutboxIntegrity);
            }
        }
        let old = self.records.get(partial).ok_or(Refusal::UnknownOperation)?;
        let record = admit_replacement(old, complete, described, view)?;
        // Nothing else may hold what the replacement takes over (the partial held it alone).
        let others: BTreeSet<OutPoint> = self
            .open()
            .filter(|record| record.id != *partial)
            .flat_map(|record| record.reserved.iter().cloned())
            .collect();
        if record.reserved.iter().any(|point| others.contains(point)) {
            return Err(Refusal::ReservedInput);
        }
        // One open record takes the place of another: only the total size can grow.
        let open_bytes: usize = self
            .open()
            .filter(|record| record.id != *partial)
            .map(|record| record.bytes.len())
            .sum();
        if open_bytes
            .checked_add(record.bytes.len())
            .is_none_or(|sum| sum > self.max_bytes)
        {
            return Err(Refusal::OutboxFull);
        }
        // Nothing has changed up to here; the swap cannot fail.
        self.records.remove(partial);
        self.order
            .retain(|queued| queued != partial && *queued != id);
        self.order.push(id);
        self.records.insert(id, record);
        Ok(id)
    }

    fn records(&self) -> Result<Vec<OutboxRecord>, Refusal> {
        self.records
            .values()
            .map(|record| record.verify().map(|()| record.clone()))
            .collect()
    }

    fn get(&self, id: &Hash) -> Result<Option<OutboxRecord>, Refusal> {
        match self.records.get(id) {
            Some(record) => record.verify().map(|()| Some(record.clone())),
            None => Ok(None),
        }
    }

    fn reconcile(&mut self, view: &ChainView<'_>) -> Result<ReconcileReport, Refusal> {
        self.check_context(view)?;
        let mut report = ReconcileReport::default();
        let ids: Vec<Hash> = self.records.keys().copied().collect();
        for id in ids {
            let Some(record) = self.records.get(&id) else {
                continue;
            };
            if !record.status.is_open() {
                continue;
            }
            record.verify()?;
            let settlement = settle(record, view)?;
            let record = self.records.get_mut(&id).ok_or(Refusal::OutboxIntegrity)?;
            match settlement {
                Settlement::Pending => report.still_pending += 1,
                Settlement::Confirmed(height) => {
                    record.status = OutboxStatus::Confirmed(height);
                    report.confirmed += 1;
                }
                Settlement::Expired => {
                    record.status = OutboxStatus::Expired;
                    report.expired += 1;
                }
                Settlement::InputsSpent => {
                    record.status = OutboxStatus::InputsSpent;
                    report.inputs_spent += 1;
                }
                Settlement::Stranded(height) => {
                    record.status = OutboxStatus::Stranded(height);
                    report.stranded += 1;
                }
            }
        }
        report.pruned = self.prune_settled(self.max_settled)?;
        Ok(report)
    }

    fn forget(&mut self, id: &Hash) -> Result<(), Refusal> {
        let record = self.records.get_mut(id).ok_or(Refusal::UnknownOperation)?;
        record.verify()?;
        if record.status.is_open() {
            record.status = OutboxStatus::Forgotten;
        }
        Ok(())
    }

    fn prune_settled(&mut self, keep: usize) -> Result<usize, Refusal> {
        let settled: Vec<Hash> = self
            .order
            .iter()
            .filter(|id| {
                self.records
                    .get(*id)
                    .is_some_and(|record| !record.status.is_open())
            })
            .copied()
            .collect();
        let excess = settled.len().saturating_sub(keep);
        for id in settled.into_iter().take(excess) {
            self.records.remove(&id);
            self.order.retain(|queued| *queued != id);
        }
        Ok(excess)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_keys_are_deterministic_distinct_and_never_a_coin() {
        let id = [7u8; 32];
        let key = resource_key("license", &id);
        assert_eq!(key, resource_key("license", &id));
        assert_eq!(key.index, u32::MAX, "no real output has this index");
        assert_ne!(key, resource_key("claim", &id), "namespaces are separate");
        assert_ne!(key, resource_key("license", &[8u8; 32]));
        assert_ne!(key.transaction, id, "never the identifier itself");
        // The namespace is length-prefixed: shifting a byte between namespace and identifier cannot
        // produce the same key.
        let mut shifted = [7u8; 32];
        shifted[0] = b'x';
        assert_ne!(
            resource_key("license", &id),
            resource_key("licensex", &shifted)
        );
        assert_ne!(resource_key("", &id), resource_key("l", &id));
    }

    #[test]
    fn record_metadata_round_trips_and_any_change_breaks_the_checksum() {
        let mut record = OutboxRecord {
            id: [1; 32],
            kind: OperationKind::Payment,
            bytes: vec![1, 2, 3],
            complete: true,
            missing: Vec::new(),
            validity: Validity {
                created: 5,
                expiry: 9,
                valid_only_at: None,
                bound_to_parent: false,
            },
            reserved: vec![resource_key("license", &[2; 32])],
            queued_at_height: 4,
            status: OutboxStatus::Queued,
            approval: None,
            checksum: [0; 32],
        };
        record.checksum = record.compute_checksum();
        record.verify().unwrap();
        let meta = OutboxRecord::decode_meta(&record.meta_bytes()).unwrap();
        assert_eq!(
            (meta.complete, meta.reserved.clone(), meta.queued_at),
            (true, record.reserved.clone(), 4)
        );
        // Status is not covered (it changes over the record's life); everything else is.
        let mut other = record.clone();
        other.status = OutboxStatus::Expired;
        other.verify().unwrap();
        for edit in [
            |r: &mut OutboxRecord| r.bytes[0] ^= 1,
            |r: &mut OutboxRecord| r.id[0] ^= 1,
            |r: &mut OutboxRecord| r.complete = false,
            |r: &mut OutboxRecord| r.queued_at_height += 1,
            |r: &mut OutboxRecord| r.validity.expiry += 1,
            |r: &mut OutboxRecord| r.reserved.clear(),
        ] {
            let mut damaged = record.clone();
            edit(&mut damaged);
            assert_eq!(damaged.verify().unwrap_err(), Refusal::OutboxIntegrity);
        }
        // Trailing bytes after the metadata are an integrity failure, not ignored.
        let mut raw = record.meta_bytes();
        raw.push(0);
        assert!(OutboxRecord::decode_meta(&raw).is_err());
    }
}
