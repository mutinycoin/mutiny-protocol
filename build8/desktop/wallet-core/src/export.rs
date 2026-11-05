//! View-verified export of queued operations (Order W6).
//!
//! [`Outbox::pending`](crate::outbox::Outbox::pending) returns the open records after re-checking
//! only their UNKEYED checksum. That catches accidental damage, not someone who can rewrite the
//! outbox file (they can recompute the checksum): it is NOT authentication, and its records must not
//! be handed to a transport. [`Outbox::export_verified`](crate::outbox::Outbox::export_verified) is
//! the export for delivery. Before it releases the bytes of one record it checks, against the host's
//! CURRENT verified view ([`verify_record`]), in this order (a record that fails several checks is
//! refused for the first):
//!
//!  1. the BYTES: they decode canonically as an operation of the record's kind, and the identifier,
//!     completeness, signatures still missing, validity and reserved coins and resources they
//!     commit to are exactly the record's (`OUTBOX_INTEGRITY` otherwise). When the record carries
//!     an approval binding, the binding names its chain, and a view of another chain is refused
//!     here (`WRONG_CONTEXT`);
//!  2. the STATUS, from verified state: a record whose stored status is settled or forgotten is
//!     refused as such (the stored status is not covered by the checksum, so it may only refuse,
//!     never release), and an open record is judged afresh by its kind's reconciliation against the
//!     view: a view older than the head the record was queued at says nothing (Stale), an operation
//!     already included (Confirmed), expired (Expired), whose inputs or resources another
//!     operation consumed (Conflicting), or the bond-funding diagnostic (Stranded) is refused with
//!     [`Refusal::NotDeliverable`] naming that [`DeliveryStatus`];
//!  3. the APPROVAL BINDING, when the record carries one (it was queued with
//!     [`Outbox::commit_approved`](crate::outbox::Outbox::commit_approved)): the binding digest of
//!     the bytes' unsigned form at the approved head is the approved review digest, for the same
//!     kind, at a head no later than the view's (`APPROVAL_BINDING_MISMATCH`). A record queued
//!     without one (bytes imported from an offline signer, a counterparty's part, an outbox that
//!     does not keep bindings) reports [`ApprovalEvidence::NotRecorded`]: nothing is claimed about
//!     an approval for it;
//!  4. every SIGNATURE present, through the kind's own consensus verification at the next height
//!     (`check_signed`, the check `commit` runs): a signature that does not verify, or an operation
//!     consensus would not admit now, is refused with that check's typed refusal.
//!
//! A partial record (a multi-party operation still missing signatures) passes when every signature
//! it carries verifies; [`VerifiedExport::missing`] lists what is still missing, so a host exports
//! it to the counterparty, not to the chain.
//!
//! What this cannot do: the binding, like the checksum, is unkeyed. Someone who can rewrite the
//! outbox file can replace a record by OTHER validly signed bytes (an operation this wallet signed
//! earlier, or one it is a party to) together with a matching binding; export then releases bytes
//! that are valid, signed and self-consistent, but not the ones approved for that record, and a
//! forgotten record whose stored status was rewritten to queued is released too. Protection at
//! rest is the host's (the desktop seals its records with DPAPI, Order W10, which does not isolate
//! it from another process of the same user); the chain rejects anything invalid.
use crate::{
    authorize::SignedOperation,
    context::ChainView,
    outbox::{OutboxRecord, OutboxStatus, Settlement},
    plan::{OperationKind, Requirement, Validity},
    refusal::Refusal,
    review::{ReviewDigest, binding_digest},
};
use minicbor::{Decoder, Encoder};
use mutiny_consensus_v8::{Hash, anchors::FinalizedAnchor};
use std::fmt;

/// Version of the stored encoding of an [`ApprovalBinding`].
const BINDING_VERSION: u8 = 1;

/// What one approval was given for: the review digest and scope, the kind and schema, and the
/// verified head (anchor and state root). Public data, not a capability: it comes from
/// [`Approval::binding`](crate::authorize::Approval::binding), taken before `Signer::authorize`
/// consumes the approval, and lets an outbox check later that queued bytes are exactly what that
/// approval was for.
#[derive(Clone, PartialEq, Eq)]
pub struct ApprovalBinding {
    kind: OperationKind,
    schema: u16,
    digest: ReviewDigest,
    scope: Hash,
    anchor: FinalizedAnchor,
    state_root: Hash,
}

impl ApprovalBinding {
    pub(crate) fn new(
        kind: OperationKind,
        schema: u16,
        digest: ReviewDigest,
        scope: Hash,
        anchor: FinalizedAnchor,
        state_root: Hash,
    ) -> Self {
        Self {
            kind,
            schema,
            digest,
            scope,
            anchor,
            state_root,
        }
    }
    pub fn kind(&self) -> OperationKind {
        self.kind
    }
    pub fn schema(&self) -> u16 {
        self.schema
    }
    /// The review digest the approval was given for.
    pub fn digest(&self) -> ReviewDigest {
        self.digest
    }
    /// What was acknowledged, for which wallet (`Review::scope`).
    pub fn scope(&self) -> Hash {
        self.scope
    }
    /// The verified head the review was for.
    pub fn anchor(&self) -> &FinalizedAnchor {
        &self.anchor
    }
    pub fn state_root(&self) -> Hash {
        self.state_root
    }

    /// The approval's chain (network, Genesis, protocol fingerprint) is the view's (`WRONG_CONTEXT`
    /// naming the first field that differs otherwise).
    pub fn require_chain(&self, view: &ChainView<'_>) -> Result<(), Refusal> {
        view.require_context(
            self.anchor.network,
            &self.anchor.genesis,
            &self.anchor.fingerprint,
        )
    }

    /// Whether `bytes` (signed, partial or unsigned bytes of `kind`) are exactly what this approval
    /// was for, on `view`'s chain: the same kind, the anchor's chain context is the view's, the
    /// approved head is no later than the view's, and the binding digest of the bytes' unsigned form
    /// at the approved head is the approved digest.
    pub fn check(
        &self,
        kind: OperationKind,
        bytes: &[u8],
        view: &ChainView<'_>,
    ) -> Result<(), Refusal> {
        if kind != self.kind {
            return Err(Refusal::ApprovalBindingMismatch(
                "the approval was given for another kind of operation",
            ));
        }
        self.require_chain(view)?;
        if self.anchor.height > view.anchor().height {
            return Err(Refusal::ApprovalBindingMismatch(
                "the approval is for a later head than the verified view",
            ));
        }
        let objects = crate::ops::handler(kind)?.unsigned_form(bytes)?;
        let digest = binding_digest(kind, self.schema, &objects, &self.anchor, &self.state_root);
        if digest != self.digest {
            return Err(Refusal::ApprovalBindingMismatch(
                "the bytes are not the operation the approval was given for",
            ));
        }
        Ok(())
    }

    /// The canonical stored encoding: `[1, kind, schema, digest, scope, [network, genesis,
    /// fingerprint, height, block], state root]`.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(7)
            .and_then(|e| e.u8(BINDING_VERSION))
            .and_then(|e| e.u16(self.kind.code()))
            .and_then(|e| e.u16(self.schema))
            .and_then(|e| e.bytes(self.digest.as_bytes()))
            .and_then(|e| e.bytes(&self.scope))
            .and_then(|e| e.array(5))
            .and_then(|e| e.u32(self.anchor.network))
            .and_then(|e| e.bytes(&self.anchor.genesis))
            .and_then(|e| e.bytes(&self.anchor.fingerprint))
            .and_then(|e| e.u64(self.anchor.height))
            .and_then(|e| e.bytes(&self.anchor.block))
            .and_then(|e| e.bytes(&self.state_root))
            .expect("writing to a vector cannot fail");
        e.into_writer()
    }

    /// Strict decoding of [`Self::encode`]; any irregularity is `OUTBOX_INTEGRITY`.
    pub(crate) fn decode(raw: &[u8]) -> Result<Self, Refusal> {
        const BAD: Refusal = Refusal::OutboxIntegrity;
        let d = &mut Decoder::new(raw);
        let fixed = |d: &mut Decoder<'_>| -> Result<Hash, Refusal> {
            d.bytes().map_err(|_| BAD)?.try_into().map_err(|_| BAD)
        };
        if d.array().map_err(|_| BAD)? != Some(7) || d.u8().map_err(|_| BAD)? != BINDING_VERSION {
            return Err(BAD);
        }
        let kind = OperationKind::from_code(d.u16().map_err(|_| BAD)?).ok_or(BAD)?;
        let schema = d.u16().map_err(|_| BAD)?;
        let digest = ReviewDigest::from_bytes(fixed(d)?);
        let scope = fixed(d)?;
        if d.array().map_err(|_| BAD)? != Some(5) {
            return Err(BAD);
        }
        let anchor = FinalizedAnchor {
            network: d.u32().map_err(|_| BAD)?,
            genesis: fixed(d)?,
            fingerprint: fixed(d)?,
            height: d.u64().map_err(|_| BAD)?,
            block: fixed(d)?,
        };
        let state_root = fixed(d)?;
        let binding = Self {
            kind,
            schema,
            digest,
            scope,
            anchor,
            state_root,
        };
        if d.position() != raw.len() || binding.encode() != raw {
            return Err(BAD);
        }
        Ok(binding)
    }
}

impl fmt::Debug for ApprovalBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ApprovalBinding")
            .field("kind", &self.kind)
            .field("digest", &self.digest)
            .field("height", &self.anchor.height)
            .finish()
    }
}

/// What an export can say about the approval of a record.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ApprovalEvidence {
    /// The record was queued with this approval binding, and the bytes still match it.
    Recorded(ApprovalBinding),
    /// The record carries no approval binding (imported bytes, a counterparty's part, or an outbox
    /// that does not keep bindings): nothing is claimed about an approval.
    NotRecorded,
}

/// Why a record cannot be delivered now, judged from verified state (W6). Carried by
/// [`Refusal::NotDeliverable`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DeliveryStatus {
    /// The view is older than the head the record was queued at: it cannot judge the record.
    Stale { queued_at: u64, view_height: u64 },
    /// Included in verified history at this height: there is nothing to deliver.
    Confirmed(u64),
    /// The validity window ended at `expiry`; the next block is `next_height`.
    Expired { expiry: u64, next_height: u64 },
    /// Another operation consumed its inputs or resources (a conflicting operation was included).
    Conflicting,
    /// The diagnostic of an old or test failure: a bond creation's funding was included at this
    /// height without the creation (`Settlement::Stranded`).
    Stranded(u64),
    /// The record was forgotten locally (forgetting does not revoke the signed bytes).
    Forgotten,
}

impl DeliveryStatus {
    /// Stable machine word for logs and tests.
    pub fn code(self) -> &'static str {
        match self {
            Self::Stale { .. } => "STALE",
            Self::Confirmed(_) => "CONFIRMED",
            Self::Expired { .. } => "EXPIRED",
            Self::Conflicting => "CONFLICTING",
            Self::Stranded(_) => "STRANDED",
            Self::Forgotten => "FORGOTTEN",
        }
    }
}

impl fmt::Display for DeliveryStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Stale {
                queued_at,
                view_height,
            } => write!(
                f,
                "the verified view (block {view_height}) is older than the block the operation was queued at ({queued_at})"
            ),
            Self::Confirmed(height) => write!(f, "it was included in verified block {height}"),
            Self::Expired {
                expiry,
                next_height,
            } => write!(
                f,
                "it expired after block {expiry}; the next block is {next_height}"
            ),
            Self::Conflicting => write!(f, "another operation consumed its inputs or resources"),
            Self::Stranded(height) => write!(
                f,
                "its funding was included at block {height} without the bond creation (a diagnostic of a failed old or test operation)"
            ),
            Self::Forgotten => write!(f, "it was forgotten locally"),
        }
    }
}

/// One record, verified for delivery against a view: exactly the bytes to hand to a transport.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct VerifiedExport {
    pub id: Hash,
    pub kind: OperationKind,
    /// The exact signed (or, for a partial record, partially signed) bytes.
    pub bytes: Vec<u8>,
    pub complete: bool,
    /// Signatures still missing (a partial record goes to the counterparty, not to the chain).
    pub missing: Vec<Requirement>,
    pub validity: Validity,
    pub approval: ApprovalEvidence,
    /// The height of the verified view the record was checked against.
    pub verified_at: u64,
}

impl fmt::Debug for VerifiedExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedExport")
            .field("kind", &self.kind)
            .field("id", &crate::units::short_hex(&self.id))
            .field("bytes", &self.bytes.len())
            .field("complete", &self.complete)
            .field(
                "approval",
                &matches!(self.approval, ApprovalEvidence::Recorded(_)),
            )
            .field("verified_at", &self.verified_at)
            .finish()
    }
}

/// The four checks of the module documentation, for one record (shared by every outbox: the
/// default `Outbox::export_verified` and the overrides of `MemoryOutbox` and `SqliteOutbox`, which
/// first refuse a view of another chain).
pub fn verify_record(
    record: &OutboxRecord,
    view: &ChainView<'_>,
) -> Result<VerifiedExport, Refusal> {
    record.verify()?;
    let handler = crate::ops::handler(record.kind)?;
    // 1. The bytes, and what they commit to.
    let described = handler.describe(&record.bytes)?;
    let mut reserved = record.reserved.clone();
    reserved.sort();
    reserved.dedup();
    if described.id != record.id
        || described.complete != record.complete
        || described.missing != record.missing
        || described.validity != record.validity
        || described.reserved != reserved
    {
        return Err(Refusal::OutboxIntegrity);
    }
    // A recorded binding names its chain: a view of another chain is refused before anything is
    // judged against it.
    if let Some(binding) = record.approval() {
        binding.require_chain(view)?;
    }
    // 2. The status: a stored settled status only refuses; an open record is judged afresh.
    let next_height = view.next_height()?;
    let not = |status| Err(Refusal::NotDeliverable(status));
    match record.status {
        OutboxStatus::Queued => {}
        OutboxStatus::Forgotten => return not(DeliveryStatus::Forgotten),
        OutboxStatus::Confirmed(height) => return not(DeliveryStatus::Confirmed(height)),
        OutboxStatus::Expired => {
            return not(DeliveryStatus::Expired {
                expiry: record.validity.expiry,
                next_height,
            });
        }
        OutboxStatus::InputsSpent => return not(DeliveryStatus::Conflicting),
        OutboxStatus::Stranded(height) => return not(DeliveryStatus::Stranded(height)),
    }
    let view_height = view.anchor().height;
    if view_height < record.queued_at_height {
        return not(DeliveryStatus::Stale {
            queued_at: record.queued_at_height,
            view_height,
        });
    }
    match handler.reconcile(record, view) {
        Settlement::Pending => {}
        Settlement::Confirmed(height) => return not(DeliveryStatus::Confirmed(height)),
        Settlement::Expired => {
            return not(DeliveryStatus::Expired {
                expiry: record.validity.expiry,
                next_height,
            });
        }
        Settlement::InputsSpent => return not(DeliveryStatus::Conflicting),
        Settlement::Stranded(height) => return not(DeliveryStatus::Stranded(height)),
    }
    if next_height > record.validity.expiry {
        return not(DeliveryStatus::Expired {
            expiry: record.validity.expiry,
            next_height,
        });
    }
    // 3. The approval binding.
    let approval = match record.approval() {
        Some(binding) => {
            binding.check(record.kind, &record.bytes, view)?;
            ApprovalEvidence::Recorded(binding.clone())
        }
        None => ApprovalEvidence::NotRecorded,
    };
    // 4. Every signature present, through the kind's own consensus verification.
    let signed = if record.complete {
        SignedOperation::Complete {
            kind: record.kind,
            id: record.id,
            bytes: record.bytes.clone(),
            validity: record.validity,
            reserved: record.reserved.clone(),
        }
    } else {
        SignedOperation::Partial {
            kind: record.kind,
            id: record.id,
            bytes: record.bytes.clone(),
            missing: record.missing.clone(),
            validity: record.validity,
            reserved: record.reserved.clone(),
        }
    };
    handler.check_signed(&signed, view)?;
    Ok(VerifiedExport {
        id: record.id,
        kind: record.kind,
        bytes: record.bytes.clone(),
        complete: record.complete,
        missing: record.missing.clone(),
        validity: record.validity,
        approval,
        verified_at: view_height,
    })
}
