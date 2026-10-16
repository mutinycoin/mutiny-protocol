//! Every way the wallet core declines to do something, with a stable machine code.
//!
//! A refusal never changes state and never yields signed bytes. The machine code
//! ([`Refusal::code`]) is part of the frozen interface: it is what logs, tests and a UI key on, so a
//! code is never renamed or reused. The human text ([`std::fmt::Display`]) may be reworded.
//! No refusal carries a secret: payloads are heights, atom counts, enums and static text only.
use crate::{
    address_format::AddressError,
    authorize::Purpose,
    capability::Capability,
    context::ChainClass,
    export::DeliveryStatus,
    plan::{CancelTarget, OperationKind, Slot},
    profile::TreasuryRole,
    review::AckKind,
};
use std::fmt;

/// Which part of the chain context did not match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContextField {
    Network,
    Genesis,
    Fingerprint,
}

/// What expired.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExpiryKind {
    /// A single-use approval was not used in time.
    Approval,
    /// The review on screen was shown too long ago.
    Review,
}

/// A reason an operation was declined. See `Refusal::code` for the stable machine codes.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    // ---- gate and session ----
    /// Production signing is unavailable: crypto-v2 `PRODUCTION_SECURITY_QUALIFIED` is false and
    /// this build has no TEST-VALUE gate.
    GateClosed,
    /// The process hardening check of crypto-v2 failed.
    ProcessProtection,
    /// The signer is locked or its idle limit elapsed.
    Locked,
    /// An approval or a displayed review is too old.
    Expired(ExpiryKind),

    // ---- context and binding ----
    /// Network, Genesis or protocol fingerprint does not match the verified chain.
    WrongContext(ContextField),
    /// The verified head moved since the review; review again.
    StaleHead {
        reviewed: u64,
        current: u64,
    },
    /// The plan is not the one that was reviewed.
    PlanChanged,
    /// The approval was withdrawn by the gate that issued it (the gate was cleared by a lock, an
    /// expiry or a cancel, a different review was put on screen, or a newer approval was issued).
    ApprovalRevoked,
    /// The signing gate and the chain class disagree (TEST-VALUE key on a production chain or the
    /// reverse).
    ChainClassMismatch {
        gate: ChainClass,
        chain: ChainClass,
    },

    // ---- authority ----
    /// This signer is not the one the operation requires for the given slot.
    NotRequiredSigner(Slot),
    /// The signing key is no longer the current authority for the address (rotated away, or an
    /// identity the chain does not corroborate).
    StaleAuthority,
    /// A Treasury-only action was requested without the Treasury profile.
    TreasuryProfileRequired,

    // ---- request validity ----
    InvalidAmount,
    InvalidRecipient,
    InvalidDescriptor,
    /// A request field is out of its permitted range.
    InvalidRequest(&'static str),
    /// Validity window of zero or beyond the protocol horizon.
    InvalidValidity,
    /// Checked arithmetic overflowed.
    Overflow,

    // ---- funds ----
    InsufficientFunds {
        available: u64,
        requested: u64,
    },
    /// No coin is currently spendable (none mature, unreserved and authorised by this key).
    NothingSpendable,
    /// The operation would exceed the 16 KiB transaction limit.
    SizeLimit {
        limit: usize,
    },
    /// More inputs than the protocol allows.
    TooManyInputs {
        limit: usize,
    },
    FeeBelowMinimum {
        fee: u64,
        minimum: u64,
    },
    /// An input is already reserved by another pending operation.
    ReservedInput,
    /// An input is not an unspent coin in the verified state.
    InputUnavailable,
    /// A coinbase input has not matured.
    ImmatureInput,
    /// Inputs do not equal outputs plus fee.
    Conservation,
    /// A Treasury spend would leave less backing than the outstanding dividend reserve.
    ReserveBackingViolation {
        reserved: u64,
        backing_after: u64,
    },

    // ---- timing ----
    WindowNotOpen {
        created: u64,
        next_height: u64,
    },
    WindowClosed {
        expiry: u64,
        next_height: u64,
    },
    /// Allowed only from `height` (refund before its height, withdrawal before its floor, a
    /// License sale at a different height).
    NotYetEligible {
        what: &'static str,
        height: u64,
    },

    // ---- trading and licences ----
    OfferConsumed,
    OfferProofInvalid,
    LicenseNotOwned,
    LicenseGenerationStale,
    PendingAssignmentOrLock,

    // ---- dividends ----
    DividendInactive,
    NotEntitled,
    Overdrawn {
        remaining: u64,
    },
    WrongSequence {
        expected: u64,
    },
    Replay,
    AwardExpired,
    LicenseSuspendedOrRevoked,

    // ---- bonds ----
    NodeNotEligible,
    BelowMinimumBond {
        minimum: u64,
    },
    SameBlockFundingMissing,

    // ---- co-signing ----
    CounterpartyApprovalInvalid,
    PreimageMismatch,

    // ---- registry ----
    /// The bytes or request do not name any operation this core knows.
    UnknownOperation,
    /// A known operation kind with no handler in this build.
    NotImplemented(OperationKind),
    /// The protocol has no such cancellation (everything except the hash-lock refund).
    CancelNotAvailable(CancelTarget),

    // ---- outbox ----
    OutboxFull,
    OutboxIntegrity,
    /// Another process holds the durable outbox right now; nothing was changed. Try again.
    OutboxBusy,
    /// The durable outbox file cannot be opened, or is not a regular file at a real path (not memory,
    /// not a temporary database, not a URI).
    OutboxLocation,

    // ---- review gate ----
    /// No review is on screen for this approval.
    NotPresented,
    AcknowledgementMissing(AckKind),
    UnexpectedAcknowledgement(AckKind),
    DestinationCheckFailed,
    DestinationCheckPending,
    /// A high-risk review needs its typed confirmation phrase before an approval is issued.
    ConfirmationPhraseMissing,
    /// The typed confirmation phrase does not match (or the review asks for none).
    ConfirmationPhraseMismatch,

    // ---- decoding and verification ----
    /// Imported or decoded bytes are not canonical or not valid.
    Malformed(&'static str),
    /// A partial-approval container is invalid.
    PartialInvalid(&'static str),
    /// The key refused to sign.
    SigningFailed,
    /// The independent post-sign verification through consensus code failed.
    VerificationFailed(&'static str),
    /// No signing domain is permitted for this operation kind and purpose.
    DomainNotPermitted {
        kind: OperationKind,
        purpose: Purpose,
    },
    /// Operating-system randomness was unavailable.
    EntropyUnavailable,

    // ---- dedicated codes added in phase 8 (change requests of phases 2 to 6) ----
    /// The award's epoch has not been reached at the verified head. The including block's epoch is at
    /// least the head's, so a later head can open it; until then nothing is signed.
    AwardNotYetOpen {
        award_epoch: u64,
        head_epoch: u64,
    },
    /// No bond lot with this identifier exists in the verified state.
    LotUnknown,
    /// The bond lot was burned by equivocation evidence: it can never be unbonded or withdrawn.
    LotBurned,
    /// An unbond needs an Active lot; the lot is in the named state ("unbonding" or "withdrawn").
    LotNotActive(&'static str),
    /// A withdrawal needs an Unbonding lot; the lot is in the named state ("active" or
    /// "withdrawn").
    LotNotUnbonding(&'static str),
    /// The proposed key of a wallet rotation reuses a component of the current key (the reason
    /// names which).
    RotationKeyReused(&'static str),
    /// The proposed key of a wallet rotation is not exactly one generation after the current key.
    RotationGeneration,
    /// The host's restore evidence for the new key of a wallet rotation is missing, or names
    /// another descriptor than the proposed one (the reason says which).
    RestoreNotVerified(&'static str),
    /// A rotation of this wallet authority is already pending (one at a time per authority).
    RotationPending,
    /// The proposed key's address is already registered in the wallet book.
    RotationAddressTaken,
    /// No lock with this identifier exists in the verified state: never created, or already
    /// claimed, refunded or released.
    LockNotFound,
    /// The maker's offer cannot be filled yet: it opens at block `created`.
    OfferNotYetValid {
        created: u64,
        next_height: u64,
    },
    /// The maker's offer can no longer be filled: its last block was `expiry`.
    OfferExpired {
        expiry: u64,
        next_height: u64,
    },
    /// A Treasury destination address serves one generation only, and this one was used before.
    TreasuryAddressUsed,
    /// The Treasury generation named is not the active one, or the new one is not exactly the
    /// active one plus one (the reason says which).
    TreasuryGeneration(&'static str),
    /// The new Treasury destination does not resolve to the new descriptor in the verified wallet
    /// book, or is not that descriptor's own address (the reason says which).
    TreasuryDestinationUnresolved(&'static str),
    /// Treasury operations need a chain that declares its class; this one (or the declaration)
    /// names none.
    TreasuryClassUndeclared,
    /// The terms of a Treasury offer to freeze are not acceptable (the reason names the rule).
    TreasuryOfferTerms(&'static str),

    // ---- dedicated codes added by the fixes of the independent wallet review ----
    /// The funding transfer of a wallet rotation does more than pay the fee: an output goes to the
    /// zero address or to an address that is neither a funder nor the rotating authority, or this
    /// wallet's net debit exceeds the fee the rotation declares (the reason says which).
    RotationFunding(&'static str),
    /// The identity carries the Treasury profile but `profile::declare` did not check this role for
    /// it: the Genesis Treasury authority (R1, spending its coins) or the active destination of
    /// exactly the trading Treasury the operation acts on (R2, offer freezes).
    TreasuryRoleNotDeclared(TreasuryRole),

    // ---- dedicated codes added by candidate 3 (Order section 6), after every earlier code ----
    /// Text entered or pasted as an address is not a valid checksummed address of the verified
    /// chain's class (`address_format`, W2); the error says exactly which rule failed.
    AddressEncoding(AddressError),
    /// A handler asked for, or used, a typed signing capability that its operation kind may not
    /// have (`capability::capabilities`), or a capability was asked to sign an object of another
    /// kind (W4). Nothing was signed.
    CapabilityNotPermitted {
        kind: OperationKind,
        capability: Capability,
    },
    /// Queued bytes are not what the approval recorded with them was given for, or an approval
    /// binding does not fit the bytes it is committed with (the reason says which; W6).
    ApprovalBindingMismatch(&'static str),
    /// A queued operation cannot be delivered now: verified state says it is stale, confirmed,
    /// expired, conflicting, stranded or forgotten (W6).
    NotDeliverable(DeliveryStatus),
    /// The operation's validity window is not inside the maker offer's window (W19: one code for
    /// every handler that fills an offer; before, `INVALID_REQUEST` or `OFFER_PROOF_INVALID`).
    OfferWindowExceeded {
        offer_created: u64,
        offer_expiry: u64,
        created: u64,
        expiry: u64,
    },
    /// Retained stable refusal for an imported operation format that has no signed window.
    /// Current native License sales support finite signed inclusion windows.
    ValidityWindowUnsupported,
}

/// Every stable machine code with its one-line meaning, in a fixed order. Codes are never
/// renamed or reused.
pub const CATALOG: &[(&str, &str)] = &[
    (
        "GATE_CLOSED",
        "Signing is not available in this build or while production qualification is incomplete.",
    ),
    ("PROCESS_PROTECTION", "The process hardening check failed."),
    ("LOCKED", "The signer is locked or its idle limit elapsed."),
    ("EXPIRED", "An approval or a displayed review expired."),
    (
        "WRONG_CONTEXT",
        "Network, Genesis or protocol fingerprint does not match.",
    ),
    (
        "STALE_HEAD",
        "The verified chain head changed since the review.",
    ),
    ("PLAN_CHANGED", "The plan is not the one that was reviewed."),
    (
        "APPROVAL_REVOKED",
        "The approval was withdrawn by the gate that issued it.",
    ),
    (
        "CHAIN_CLASS_MISMATCH",
        "The signing gate and the chain class disagree.",
    ),
    (
        "NOT_REQUIRED_SIGNER",
        "This signer is not required for that slot.",
    ),
    (
        "STALE_AUTHORITY",
        "The key is no longer the current authority for the address.",
    ),
    ("TREASURY_PROFILE_REQUIRED", "Treasury profile required."),
    (
        "INVALID_AMOUNT",
        "The amount is zero, malformed or out of range.",
    ),
    (
        "INVALID_RECIPIENT",
        "The recipient address is not acceptable.",
    ),
    ("INVALID_DESCRIPTOR", "A wallet descriptor is invalid."),
    ("INVALID_REQUEST", "A request field is out of range."),
    (
        "INVALID_VALIDITY",
        "The validity window is zero or beyond the protocol horizon.",
    ),
    ("OVERFLOW", "Arithmetic overflow."),
    ("INSUFFICIENT_FUNDS", "Not enough spendable funds."),
    ("NOTHING_SPENDABLE", "No coin is currently spendable."),
    (
        "SIZE_LIMIT",
        "The operation would exceed the 16 KiB transaction limit.",
    ),
    ("TOO_MANY_INPUTS", "More inputs than the protocol allows."),
    (
        "FEE_BELOW_MINIMUM",
        "The fee is below the protocol minimum.",
    ),
    (
        "RESERVED_INPUT",
        "An input is reserved by another pending operation.",
    ),
    ("INPUT_UNAVAILABLE", "An input is not an unspent coin."),
    ("IMMATURE_INPUT", "A coinbase input has not matured."),
    ("CONSERVATION", "Inputs do not equal outputs plus fee."),
    (
        "RESERVE_BACKING_VIOLATION",
        "Spending would leave the dividend reserve unbacked.",
    ),
    ("WINDOW_NOT_OPEN", "The validity window has not opened."),
    ("WINDOW_CLOSED", "The validity window has closed."),
    ("NOT_YET_ELIGIBLE", "Not yet eligible at this height."),
    ("OFFER_CONSUMED", "The offer was already consumed."),
    (
        "OFFER_PROOF_INVALID",
        "The maker offer proof does not verify.",
    ),
    (
        "LICENSE_NOT_OWNED",
        "The License is not owned by the expected seller.",
    ),
    (
        "LICENSE_GENERATION_STALE",
        "The License generation changed.",
    ),
    (
        "PENDING_ASSIGNMENT_OR_LOCK",
        "A pending Worker assignment or lock blocks the transfer.",
    ),
    (
        "DIVIDEND_INACTIVE",
        "Dividends are not active on this chain.",
    ),
    ("NOT_ENTITLED", "No entitlement for this License and award."),
    ("OVERDRAWN", "The claim exceeds the remaining entitlement."),
    (
        "WRONG_SEQUENCE",
        "The claim sequence does not match the confirmed claim count.",
    ),
    ("REPLAY", "This operation was already applied."),
    ("AWARD_EXPIRED", "The award claim window has closed."),
    (
        "LICENSE_SUSPENDED_OR_REVOKED",
        "The License is suspended or revoked.",
    ),
    ("NODE_NOT_ELIGIBLE", "The node is not eligible for a bond."),
    ("BELOW_MINIMUM_BOND", "The bond is below the minimum."),
    (
        "SAME_BLOCK_FUNDING_MISSING",
        "The same-block funding output is missing.",
    ),
    (
        "COUNTERPARTY_APPROVAL_INVALID",
        "A counterparty approval does not verify.",
    ),
    (
        "PREIMAGE_MISMATCH",
        "The preimage does not match the condition.",
    ),
    ("UNKNOWN_OPERATION", "Not a recognised operation."),
    (
        "NOT_IMPLEMENTED",
        "Known operation kind without a handler in this build.",
    ),
    (
        "CANCEL_NOT_AVAILABLE",
        "The protocol offers no such cancellation.",
    ),
    ("OUTBOX_FULL", "The outbox is full."),
    (
        "OUTBOX_INTEGRITY",
        "A stored outbox record failed its integrity check.",
    ),
    (
        "OUTBOX_BUSY",
        "The outbox is in use by another process; try again.",
    ),
    (
        "OUTBOX_LOCATION",
        "The outbox file cannot be opened, or is not a regular file at a real path.",
    ),
    ("NOT_PRESENTED", "No review has been presented."),
    (
        "ACKNOWLEDGEMENT_MISSING",
        "A required acknowledgement is missing.",
    ),
    (
        "UNEXPECTED_ACKNOWLEDGEMENT",
        "An acknowledgement that this review does not require.",
    ),
    (
        "DESTINATION_CHECK_FAILED",
        "The typed address check does not match.",
    ),
    (
        "DESTINATION_CHECK_PENDING",
        "A typed address check is still required.",
    ),
    (
        "CONFIRMATION_PHRASE_MISSING",
        "The typed confirmation phrase is still required.",
    ),
    (
        "CONFIRMATION_PHRASE_MISMATCH",
        "The typed confirmation phrase does not match.",
    ),
    ("MALFORMED", "Bytes are not canonical or not valid."),
    (
        "PARTIAL_INVALID",
        "The partial-approval container is invalid.",
    ),
    ("SIGNING_FAILED", "The key refused to sign."),
    (
        "VERIFICATION_FAILED",
        "Independent verification of the signed result failed.",
    ),
    (
        "DOMAIN_NOT_PERMITTED",
        "No signing domain is permitted for this kind and purpose.",
    ),
    (
        "ENTROPY_UNAVAILABLE",
        "Operating-system randomness is unavailable.",
    ),
    // Added in phase 8, after every earlier code (no earlier position changes).
    (
        "AWARD_NOT_YET_OPEN",
        "The award epoch has not been reached at the verified head.",
    ),
    ("LOT_UNKNOWN", "No bond lot with this identifier exists."),
    (
        "LOT_BURNED",
        "The bond lot was burned by equivocation evidence.",
    ),
    ("LOT_NOT_ACTIVE", "An unbond needs an Active bond lot."),
    (
        "LOT_NOT_UNBONDING",
        "A withdrawal needs an Unbonding bond lot.",
    ),
    (
        "ROTATION_KEY_REUSED",
        "The proposed key reuses a component of the current key.",
    ),
    (
        "ROTATION_GENERATION",
        "The proposed key is not exactly one generation after the current key.",
    ),
    (
        "RESTORE_NOT_VERIFIED",
        "No clean restore of the new key's phrase was verified for the proposed descriptor.",
    ),
    (
        "ROTATION_PENDING",
        "A rotation of this wallet authority is already pending.",
    ),
    (
        "ROTATION_ADDRESS_TAKEN",
        "The proposed key's address is already registered.",
    ),
    ("LOCK_NOT_FOUND", "No lock with this identifier exists."),
    (
        "OFFER_NOT_YET_VALID",
        "The maker offer cannot be filled yet.",
    ),
    ("OFFER_EXPIRED", "The maker offer can no longer be filled."),
    (
        "TREASURY_ADDRESS_USED",
        "This Treasury destination address was used before.",
    ),
    (
        "TREASURY_GENERATION",
        "The Treasury generation is not the active one or not the next one.",
    ),
    (
        "TREASURY_DESTINATION_UNRESOLVED",
        "The new Treasury destination does not resolve to its descriptor.",
    ),
    (
        "TREASURY_CLASS_UNDECLARED",
        "The chain declares no class; Treasury operations need one.",
    ),
    (
        "TREASURY_OFFER_TERMS",
        "The Treasury offer terms are not acceptable.",
    ),
    // Added by the fixes of the independent wallet review, after every phase 8 code.
    (
        "ROTATION_FUNDING",
        "The funding of a wallet rotation pays something other than the fee.",
    ),
    (
        "TREASURY_ROLE_NOT_DECLARED",
        "The Treasury declaration does not claim the role this operation needs.",
    ),
    // Added by candidate 3 (Order section 6), after every earlier code.
    (
        "ADDRESS_ENCODING",
        "The address text is not a valid checksummed address of this chain's class.",
    ),
    (
        "CAPABILITY_NOT_PERMITTED",
        "The operation kind may not use that signing capability.",
    ),
    (
        "APPROVAL_BINDING_MISMATCH",
        "The queued bytes are not what their recorded approval was given for.",
    ),
    (
        "NOT_DELIVERABLE",
        "Verified state says the queued operation cannot be delivered now.",
    ),
    (
        "OFFER_WINDOW_EXCEEDED",
        "The operation's validity window is not inside the maker offer's window.",
    ),
    (
        "VALIDITY_WINDOW_UNSUPPORTED",
        "This operation format does not support a signed validity window.",
    ),
];

impl Refusal {
    /// The stable machine code. Total over every variant; each code appears once in [`CATALOG`].
    pub fn code(&self) -> &'static str {
        match self {
            Self::GateClosed => "GATE_CLOSED",
            Self::ProcessProtection => "PROCESS_PROTECTION",
            Self::Locked => "LOCKED",
            Self::Expired(_) => "EXPIRED",
            Self::WrongContext(_) => "WRONG_CONTEXT",
            Self::StaleHead { .. } => "STALE_HEAD",
            Self::PlanChanged => "PLAN_CHANGED",
            Self::ApprovalRevoked => "APPROVAL_REVOKED",
            Self::ChainClassMismatch { .. } => "CHAIN_CLASS_MISMATCH",
            Self::NotRequiredSigner(_) => "NOT_REQUIRED_SIGNER",
            Self::StaleAuthority => "STALE_AUTHORITY",
            Self::TreasuryProfileRequired => "TREASURY_PROFILE_REQUIRED",
            Self::InvalidAmount => "INVALID_AMOUNT",
            Self::InvalidRecipient => "INVALID_RECIPIENT",
            Self::InvalidDescriptor => "INVALID_DESCRIPTOR",
            Self::InvalidRequest(_) => "INVALID_REQUEST",
            Self::InvalidValidity => "INVALID_VALIDITY",
            Self::Overflow => "OVERFLOW",
            Self::InsufficientFunds { .. } => "INSUFFICIENT_FUNDS",
            Self::NothingSpendable => "NOTHING_SPENDABLE",
            Self::SizeLimit { .. } => "SIZE_LIMIT",
            Self::TooManyInputs { .. } => "TOO_MANY_INPUTS",
            Self::FeeBelowMinimum { .. } => "FEE_BELOW_MINIMUM",
            Self::ReservedInput => "RESERVED_INPUT",
            Self::InputUnavailable => "INPUT_UNAVAILABLE",
            Self::ImmatureInput => "IMMATURE_INPUT",
            Self::Conservation => "CONSERVATION",
            Self::ReserveBackingViolation { .. } => "RESERVE_BACKING_VIOLATION",
            Self::WindowNotOpen { .. } => "WINDOW_NOT_OPEN",
            Self::WindowClosed { .. } => "WINDOW_CLOSED",
            Self::NotYetEligible { .. } => "NOT_YET_ELIGIBLE",
            Self::OfferConsumed => "OFFER_CONSUMED",
            Self::OfferProofInvalid => "OFFER_PROOF_INVALID",
            Self::LicenseNotOwned => "LICENSE_NOT_OWNED",
            Self::LicenseGenerationStale => "LICENSE_GENERATION_STALE",
            Self::PendingAssignmentOrLock => "PENDING_ASSIGNMENT_OR_LOCK",
            Self::DividendInactive => "DIVIDEND_INACTIVE",
            Self::NotEntitled => "NOT_ENTITLED",
            Self::Overdrawn { .. } => "OVERDRAWN",
            Self::WrongSequence { .. } => "WRONG_SEQUENCE",
            Self::Replay => "REPLAY",
            Self::AwardExpired => "AWARD_EXPIRED",
            Self::LicenseSuspendedOrRevoked => "LICENSE_SUSPENDED_OR_REVOKED",
            Self::NodeNotEligible => "NODE_NOT_ELIGIBLE",
            Self::BelowMinimumBond { .. } => "BELOW_MINIMUM_BOND",
            Self::SameBlockFundingMissing => "SAME_BLOCK_FUNDING_MISSING",
            Self::CounterpartyApprovalInvalid => "COUNTERPARTY_APPROVAL_INVALID",
            Self::PreimageMismatch => "PREIMAGE_MISMATCH",
            Self::UnknownOperation => "UNKNOWN_OPERATION",
            Self::NotImplemented(_) => "NOT_IMPLEMENTED",
            Self::CancelNotAvailable(_) => "CANCEL_NOT_AVAILABLE",
            Self::OutboxFull => "OUTBOX_FULL",
            Self::OutboxIntegrity => "OUTBOX_INTEGRITY",
            Self::OutboxBusy => "OUTBOX_BUSY",
            Self::OutboxLocation => "OUTBOX_LOCATION",
            Self::NotPresented => "NOT_PRESENTED",
            Self::AcknowledgementMissing(_) => "ACKNOWLEDGEMENT_MISSING",
            Self::UnexpectedAcknowledgement(_) => "UNEXPECTED_ACKNOWLEDGEMENT",
            Self::DestinationCheckFailed => "DESTINATION_CHECK_FAILED",
            Self::DestinationCheckPending => "DESTINATION_CHECK_PENDING",
            Self::ConfirmationPhraseMissing => "CONFIRMATION_PHRASE_MISSING",
            Self::ConfirmationPhraseMismatch => "CONFIRMATION_PHRASE_MISMATCH",
            Self::Malformed(_) => "MALFORMED",
            Self::PartialInvalid(_) => "PARTIAL_INVALID",
            Self::SigningFailed => "SIGNING_FAILED",
            Self::VerificationFailed(_) => "VERIFICATION_FAILED",
            Self::DomainNotPermitted { .. } => "DOMAIN_NOT_PERMITTED",
            Self::EntropyUnavailable => "ENTROPY_UNAVAILABLE",
            Self::AwardNotYetOpen { .. } => "AWARD_NOT_YET_OPEN",
            Self::LotUnknown => "LOT_UNKNOWN",
            Self::LotBurned => "LOT_BURNED",
            Self::LotNotActive(_) => "LOT_NOT_ACTIVE",
            Self::LotNotUnbonding(_) => "LOT_NOT_UNBONDING",
            Self::RotationKeyReused(_) => "ROTATION_KEY_REUSED",
            Self::RotationGeneration => "ROTATION_GENERATION",
            Self::RestoreNotVerified(_) => "RESTORE_NOT_VERIFIED",
            Self::RotationPending => "ROTATION_PENDING",
            Self::RotationAddressTaken => "ROTATION_ADDRESS_TAKEN",
            Self::LockNotFound => "LOCK_NOT_FOUND",
            Self::OfferNotYetValid { .. } => "OFFER_NOT_YET_VALID",
            Self::OfferExpired { .. } => "OFFER_EXPIRED",
            Self::TreasuryAddressUsed => "TREASURY_ADDRESS_USED",
            Self::TreasuryGeneration(_) => "TREASURY_GENERATION",
            Self::TreasuryDestinationUnresolved(_) => "TREASURY_DESTINATION_UNRESOLVED",
            Self::TreasuryClassUndeclared => "TREASURY_CLASS_UNDECLARED",
            Self::TreasuryOfferTerms(_) => "TREASURY_OFFER_TERMS",
            Self::RotationFunding(_) => "ROTATION_FUNDING",
            Self::TreasuryRoleNotDeclared(_) => "TREASURY_ROLE_NOT_DECLARED",
            Self::AddressEncoding(_) => "ADDRESS_ENCODING",
            Self::CapabilityNotPermitted { .. } => "CAPABILITY_NOT_PERMITTED",
            Self::ApprovalBindingMismatch(_) => "APPROVAL_BINDING_MISMATCH",
            Self::NotDeliverable(_) => "NOT_DELIVERABLE",
            Self::OfferWindowExceeded { .. } => "OFFER_WINDOW_EXCEEDED",
            Self::ValidityWindowUnsupported => "VALIDITY_WINDOW_UNSUPPORTED",
        }
    }

    /// One example of every variant. Used by tests to prove the catalog is complete and unique.
    pub fn examples() -> Vec<Refusal> {
        vec![
            Self::GateClosed,
            Self::ProcessProtection,
            Self::Locked,
            Self::Expired(ExpiryKind::Approval),
            Self::WrongContext(ContextField::Network),
            Self::StaleHead {
                reviewed: 1,
                current: 2,
            },
            Self::PlanChanged,
            Self::ApprovalRevoked,
            Self::ChainClassMismatch {
                gate: ChainClass::TestValue,
                chain: ChainClass::Production,
            },
            Self::NotRequiredSigner(Slot::Input(0)),
            Self::StaleAuthority,
            Self::TreasuryProfileRequired,
            Self::InvalidAmount,
            Self::InvalidRecipient,
            Self::InvalidDescriptor,
            Self::InvalidRequest("example"),
            Self::InvalidValidity,
            Self::Overflow,
            Self::InsufficientFunds {
                available: 1,
                requested: 2,
            },
            Self::NothingSpendable,
            Self::SizeLimit { limit: 16 * 1024 },
            Self::TooManyInputs { limit: 128 },
            Self::FeeBelowMinimum { fee: 1, minimum: 2 },
            Self::ReservedInput,
            Self::InputUnavailable,
            Self::ImmatureInput,
            Self::Conservation,
            Self::ReserveBackingViolation {
                reserved: 2,
                backing_after: 1,
            },
            Self::WindowNotOpen {
                created: 2,
                next_height: 1,
            },
            Self::WindowClosed {
                expiry: 1,
                next_height: 2,
            },
            Self::NotYetEligible {
                what: "example",
                height: 9,
            },
            Self::OfferConsumed,
            Self::OfferProofInvalid,
            Self::LicenseNotOwned,
            Self::LicenseGenerationStale,
            Self::PendingAssignmentOrLock,
            Self::DividendInactive,
            Self::NotEntitled,
            Self::Overdrawn { remaining: 1 },
            Self::WrongSequence { expected: 1 },
            Self::Replay,
            Self::AwardExpired,
            Self::LicenseSuspendedOrRevoked,
            Self::NodeNotEligible,
            Self::BelowMinimumBond { minimum: 1 },
            Self::SameBlockFundingMissing,
            Self::CounterpartyApprovalInvalid,
            Self::PreimageMismatch,
            Self::UnknownOperation,
            Self::NotImplemented(OperationKind::Payment),
            Self::CancelNotAvailable(CancelTarget::Offer),
            Self::OutboxFull,
            Self::OutboxIntegrity,
            Self::OutboxBusy,
            Self::OutboxLocation,
            Self::NotPresented,
            Self::AcknowledgementMissing(AckKind::Fee),
            Self::UnexpectedAcknowledgement(AckKind::Fee),
            Self::DestinationCheckFailed,
            Self::DestinationCheckPending,
            Self::ConfirmationPhraseMissing,
            Self::ConfirmationPhraseMismatch,
            Self::Malformed("example"),
            Self::PartialInvalid("example"),
            Self::SigningFailed,
            Self::VerificationFailed("example"),
            Self::DomainNotPermitted {
                kind: OperationKind::Payment,
                purpose: Purpose::BondAction,
            },
            Self::EntropyUnavailable,
            Self::AwardNotYetOpen {
                award_epoch: 2,
                head_epoch: 1,
            },
            Self::LotUnknown,
            Self::LotBurned,
            Self::LotNotActive("unbonding"),
            Self::LotNotUnbonding("active"),
            Self::RotationKeyReused("example"),
            Self::RotationGeneration,
            Self::RestoreNotVerified("example"),
            Self::RotationPending,
            Self::RotationAddressTaken,
            Self::LockNotFound,
            Self::OfferNotYetValid {
                created: 2,
                next_height: 1,
            },
            Self::OfferExpired {
                expiry: 1,
                next_height: 2,
            },
            Self::TreasuryAddressUsed,
            Self::TreasuryGeneration("example"),
            Self::TreasuryDestinationUnresolved("example"),
            Self::TreasuryClassUndeclared,
            Self::TreasuryOfferTerms("example"),
            Self::RotationFunding("example"),
            Self::TreasuryRoleNotDeclared(TreasuryRole::Destination),
            Self::AddressEncoding(AddressError::InvalidChecksum),
            Self::CapabilityNotPermitted {
                kind: OperationKind::Payment,
                capability: Capability::BondAuthorization,
            },
            Self::ApprovalBindingMismatch("example"),
            Self::NotDeliverable(DeliveryStatus::Conflicting),
            Self::OfferWindowExceeded {
                offer_created: 50,
                offer_expiry: 200,
                created: 40,
                expiry: 120,
            },
            Self::ValidityWindowUnsupported,
        ]
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use crate::units::format_mut;
        match self {
            Self::GateClosed => write!(
                f,
                "Signing is not available: production qualification is incomplete and this build has no test-value gate."
            ),
            Self::ProcessProtection => write!(
                f,
                "The process protection check failed, so signing is refused."
            ),
            Self::Locked => write!(f, "The wallet is locked. Unlock it and review again."),
            Self::Expired(ExpiryKind::Approval) => {
                write!(f, "The approval expired. Review and approve again.")
            }
            Self::Expired(ExpiryKind::Review) => write!(f, "The review is too old. Review again."),
            Self::WrongContext(field) => write!(
                f,
                "The {} does not match the verified chain.",
                match field {
                    ContextField::Network => "network",
                    ContextField::Genesis => "Genesis",
                    ContextField::Fingerprint => "protocol fingerprint",
                }
            ),
            Self::StaleHead { reviewed, current } => write!(
                f,
                "The verified chain moved from block {reviewed} to block {current} since the review. Review again."
            ),
            Self::PlanChanged => write!(
                f,
                "This is not the operation that was reviewed. Review again."
            ),
            Self::ApprovalRevoked => write!(
                f,
                "The approval was withdrawn (the wallet was locked, the review was replaced or cleared). Review again."
            ),
            Self::ChainClassMismatch { gate, chain } => write!(
                f,
                "The signing mode ({gate:?}) does not match the chain class ({chain:?})."
            ),
            Self::NotRequiredSigner(slot) => {
                write!(f, "This wallet is not the required signer for {slot}.")
            }
            Self::StaleAuthority => write!(
                f,
                "This key is no longer the current authority for the address (it was rotated, or the chain does not know it)."
            ),
            Self::TreasuryProfileRequired => write!(
                f,
                "This action belongs to the Treasury profile, which is not enabled."
            ),
            Self::InvalidAmount => write!(
                f,
                "Enter a positive MUT amount with at most eight decimal places."
            ),
            Self::InvalidRecipient => write!(f, "The recipient address is not acceptable."),
            Self::InvalidDescriptor => write!(f, "A wallet descriptor is invalid."),
            Self::InvalidRequest(what) => write!(f, "Invalid request: {what}."),
            Self::InvalidValidity => write!(
                f,
                "The validity window must be at least one block and within the protocol horizon."
            ),
            Self::Overflow => write!(f, "An amount or height overflowed."),
            Self::InsufficientFunds {
                available,
                requested,
            } => write!(
                f,
                "Insufficient spendable funds: {} available, {} needed.",
                format_mut(*available),
                format_mut(*requested)
            ),
            Self::NothingSpendable => write!(
                f,
                "No coin is spendable right now (none is mature, unreserved and controlled by this key)."
            ),
            Self::SizeLimit { limit } => write!(
                f,
                "The payment would exceed the {limit} byte transaction limit: it needs more inputs than fit. Send your coins to yourself first to consolidate them."
            ),
            Self::TooManyInputs { limit } => {
                write!(f, "The operation would need more than {limit} inputs.")
            }
            Self::FeeBelowMinimum { fee, minimum } => write!(
                f,
                "The fee of {fee} atoms is below the minimum of {minimum} atoms."
            ),
            Self::ReservedInput => write!(
                f,
                "An input is already committed to another pending operation."
            ),
            Self::InputUnavailable => write!(f, "An input is no longer an unspent coin."),
            Self::ImmatureInput => write!(f, "A coinbase input has not matured yet."),
            Self::Conservation => write!(f, "Inputs do not equal outputs plus fee."),
            Self::ReserveBackingViolation {
                reserved,
                backing_after,
            } => write!(
                f,
                "This Treasury spend would leave {} backing for a {} dividend reserve.",
                format_mut(*backing_after),
                format_mut(*reserved)
            ),
            Self::WindowNotOpen {
                created,
                next_height,
            } => write!(
                f,
                "Not valid before block {created}; the next block is {next_height}."
            ),
            Self::WindowClosed {
                expiry,
                next_height,
            } => write!(
                f,
                "Expired after block {expiry}; the next block is {next_height}."
            ),
            Self::NotYetEligible { what, height } => {
                write!(f, "{what} is not allowed until block {height}.")
            }
            Self::OfferConsumed => write!(f, "The offer was already consumed."),
            Self::OfferProofInvalid => write!(f, "The maker's offer proof does not verify."),
            Self::LicenseNotOwned => write!(f, "The License is not owned by the expected seller."),
            Self::LicenseGenerationStale => write!(f, "The License generation changed."),
            Self::PendingAssignmentOrLock => write!(
                f,
                "A pending Worker assignment or lock blocks this License transfer."
            ),
            Self::DividendInactive => write!(f, "Dividends are not active on this chain."),
            Self::NotEntitled => write!(f, "No entitlement exists for this License and award."),
            Self::Overdrawn { remaining } => write!(
                f,
                "The claim exceeds the remaining entitlement of {}.",
                format_mut(*remaining)
            ),
            Self::WrongSequence { expected } => write!(f, "The claim sequence must be {expected}."),
            Self::Replay => write!(f, "This operation was already applied."),
            Self::AwardExpired => write!(f, "The claim window of this award has closed."),
            Self::LicenseSuspendedOrRevoked => write!(f, "The License is suspended or revoked."),
            Self::NodeNotEligible => write!(f, "The node is not eligible for this bond."),
            Self::BelowMinimumBond { minimum } => write!(
                f,
                "The bond is below the minimum of {}.",
                format_mut(*minimum)
            ),
            Self::SameBlockFundingMissing => write!(
                f,
                "The funding output for this bond is not in the same block."
            ),
            Self::CounterpartyApprovalInvalid => {
                write!(f, "A counterparty approval does not verify.")
            }
            Self::PreimageMismatch => write!(f, "The preimage does not match the lock condition."),
            Self::UnknownOperation => write!(f, "These bytes are not a recognised operation."),
            Self::NotImplemented(kind) => {
                write!(f, "{} is not available in this build.", kind.title())
            }
            Self::CancelNotAvailable(target) => write!(f, "{}", target.explanation()),
            Self::OutboxFull => write!(f, "The outbox is full."),
            Self::OutboxIntegrity => {
                write!(f, "A stored outbox record failed its integrity check.")
            }
            Self::OutboxBusy => write!(f, "The outbox is in use by another process. Try again."),
            Self::OutboxLocation => write!(
                f,
                "The outbox file cannot be opened. It must be a regular file at a real path, not memory, a temporary database or a URI."
            ),
            Self::NotPresented => write!(f, "No review is on screen for approval."),
            Self::AcknowledgementMissing(ack) => {
                write!(f, "Acknowledge first: {}.", ack.statement())
            }
            Self::UnexpectedAcknowledgement(ack) => {
                write!(f, "This review does not ask for: {}.", ack.statement())
            }
            Self::DestinationCheckFailed => write!(f, "The typed address ending does not match."),
            Self::DestinationCheckPending => write!(
                f,
                "Type the last eight characters of each destination address first."
            ),
            Self::ConfirmationPhraseMissing => write!(
                f,
                "Type the confirmation phrase shown with this review first."
            ),
            Self::ConfirmationPhraseMismatch => write!(
                f,
                "The typed confirmation phrase does not match the one shown."
            ),
            Self::Malformed(what) => write!(f, "Invalid data: {what}."),
            Self::PartialInvalid(what) => write!(f, "Invalid partial approval: {what}."),
            Self::SigningFailed => write!(f, "The key could not sign."),
            Self::VerificationFailed(what) => write!(
                f,
                "The signed result failed independent verification: {what}."
            ),
            Self::DomainNotPermitted { kind, purpose } => write!(
                f,
                "No signing domain is permitted for {} / {purpose:?}.",
                kind.name()
            ),
            Self::EntropyUnavailable => write!(f, "Operating-system randomness is unavailable."),
            Self::AwardNotYetOpen {
                award_epoch,
                head_epoch,
            } => write!(
                f,
                "This award opens at epoch {award_epoch}; the verified block is in epoch {head_epoch}."
            ),
            Self::LotUnknown => write!(
                f,
                "No bond lot with this identifier exists in the verified state."
            ),
            Self::LotBurned => write!(
                f,
                "This bond lot was burned by equivocation evidence and can never be unbonded or withdrawn."
            ),
            Self::LotNotActive(state) => write!(
                f,
                "Only an Active bond lot can be unbonded; this lot is {state}."
            ),
            Self::LotNotUnbonding(state) => write!(
                f,
                "Only an unbonding bond lot can be withdrawn; this lot is {state}."
            ),
            Self::RotationKeyReused(reason) => {
                write!(f, "The proposed key cannot be used: {reason}.")
            }
            Self::RotationGeneration => write!(
                f,
                "The proposed key must be exactly one generation after the current key."
            ),
            Self::RestoreNotVerified(reason) => write!(
                f,
                "Verify a clean restore of the new key's phrase first: {reason}."
            ),
            Self::RotationPending => write!(
                f,
                "A rotation of this wallet authority is already pending. It must be included, expire or be forgotten first."
            ),
            Self::RotationAddressTaken => write!(
                f,
                "The proposed key's address is already registered in the wallet book."
            ),
            Self::LockNotFound => write!(
                f,
                "No lock with this identifier exists in the verified chain (never created, or already claimed, refunded or released)."
            ),
            Self::OfferNotYetValid {
                created,
                next_height,
            } => write!(
                f,
                "The maker's offer cannot be filled before block {created}; the next block is {next_height}."
            ),
            Self::OfferExpired {
                expiry,
                next_height,
            } => write!(
                f,
                "The maker's offer expired after block {expiry}; the next block is {next_height}."
            ),
            Self::TreasuryAddressUsed => write!(
                f,
                "A Treasury destination address serves one generation only, and this one was used before."
            ),
            Self::TreasuryGeneration(reason) => {
                write!(f, "Invalid Treasury generation: {reason}.")
            }
            Self::TreasuryDestinationUnresolved(reason) => {
                write!(f, "The new Treasury destination is not usable: {reason}.")
            }
            Self::TreasuryClassUndeclared => write!(
                f,
                "Treasury operations need a chain that declares its class (TEST-VALUE or production); this one declares none."
            ),
            Self::TreasuryOfferTerms(reason) => {
                write!(f, "The Treasury offer is not acceptable: {reason}.")
            }
            Self::RotationFunding(reason) => {
                write!(f, "This rotation's funding is refused: {reason}.")
            }
            Self::TreasuryRoleNotDeclared(role) => write!(
                f,
                "This machine's Treasury declaration does not claim {}, which this operation needs.",
                role.text()
            ),
            Self::AddressEncoding(error) => {
                write!(f, "This is not a valid address for this chain: {error}.")
            }
            Self::CapabilityNotPermitted { kind, capability } => write!(
                f,
                "{} may not use the {capability:?} signing capability; nothing was signed.",
                kind.title()
            ),
            Self::ApprovalBindingMismatch(reason) => {
                write!(
                    f,
                    "The approval recorded with this operation does not fit it: {reason}."
                )
            }
            Self::NotDeliverable(status) => {
                write!(
                    f,
                    "This queued operation cannot be delivered now: {status}."
                )
            }
            Self::OfferWindowExceeded {
                offer_created,
                offer_expiry,
                created,
                expiry,
            } => write!(
                f,
                "The operation is valid for blocks {created} to {expiry}, which is not inside the maker offer's blocks {offer_created} to {offer_expiry}."
            ),
            Self::ValidityWindowUnsupported => write!(
                f,
                "This operation format does not support a signed validity window. Build a current native operation and review its signed inclusion bounds."
            ),
        }
    }
}

impl std::error::Error for Refusal {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn every_variant_has_a_unique_catalogued_code() {
        let examples = Refusal::examples();
        let codes: Vec<&str> = examples.iter().map(Refusal::code).collect();
        let unique: BTreeSet<&str> = codes.iter().copied().collect();
        assert_eq!(unique.len(), codes.len(), "example list repeats a code");
        let catalog: Vec<&str> = CATALOG.iter().map(|(code, _)| *code).collect();
        let catalog_unique: BTreeSet<&str> = catalog.iter().copied().collect();
        assert_eq!(
            catalog_unique.len(),
            catalog.len(),
            "catalog repeats a code"
        );
        assert_eq!(
            unique, catalog_unique,
            "examples and catalog must list exactly the same codes"
        );
        assert_eq!(codes, catalog, "examples follow catalog order");
    }

    #[test]
    fn earlier_codes_keep_their_names_and_positions() {
        // The codes as they stood before phase 8, in catalogue order: later codes are only ever
        // appended, so a host keying on a code (or on its position) keeps working.
        const BEFORE_PHASE_8: [&str; 68] = [
            "GATE_CLOSED",
            "PROCESS_PROTECTION",
            "LOCKED",
            "EXPIRED",
            "WRONG_CONTEXT",
            "STALE_HEAD",
            "PLAN_CHANGED",
            "APPROVAL_REVOKED",
            "CHAIN_CLASS_MISMATCH",
            "NOT_REQUIRED_SIGNER",
            "STALE_AUTHORITY",
            "TREASURY_PROFILE_REQUIRED",
            "INVALID_AMOUNT",
            "INVALID_RECIPIENT",
            "INVALID_DESCRIPTOR",
            "INVALID_REQUEST",
            "INVALID_VALIDITY",
            "OVERFLOW",
            "INSUFFICIENT_FUNDS",
            "NOTHING_SPENDABLE",
            "SIZE_LIMIT",
            "TOO_MANY_INPUTS",
            "FEE_BELOW_MINIMUM",
            "RESERVED_INPUT",
            "INPUT_UNAVAILABLE",
            "IMMATURE_INPUT",
            "CONSERVATION",
            "RESERVE_BACKING_VIOLATION",
            "WINDOW_NOT_OPEN",
            "WINDOW_CLOSED",
            "NOT_YET_ELIGIBLE",
            "OFFER_CONSUMED",
            "OFFER_PROOF_INVALID",
            "LICENSE_NOT_OWNED",
            "LICENSE_GENERATION_STALE",
            "PENDING_ASSIGNMENT_OR_LOCK",
            "DIVIDEND_INACTIVE",
            "NOT_ENTITLED",
            "OVERDRAWN",
            "WRONG_SEQUENCE",
            "REPLAY",
            "AWARD_EXPIRED",
            "LICENSE_SUSPENDED_OR_REVOKED",
            "NODE_NOT_ELIGIBLE",
            "BELOW_MINIMUM_BOND",
            "SAME_BLOCK_FUNDING_MISSING",
            "COUNTERPARTY_APPROVAL_INVALID",
            "PREIMAGE_MISMATCH",
            "UNKNOWN_OPERATION",
            "NOT_IMPLEMENTED",
            "CANCEL_NOT_AVAILABLE",
            "OUTBOX_FULL",
            "OUTBOX_INTEGRITY",
            "OUTBOX_BUSY",
            "OUTBOX_LOCATION",
            "NOT_PRESENTED",
            "ACKNOWLEDGEMENT_MISSING",
            "UNEXPECTED_ACKNOWLEDGEMENT",
            "DESTINATION_CHECK_FAILED",
            "DESTINATION_CHECK_PENDING",
            "CONFIRMATION_PHRASE_MISSING",
            "CONFIRMATION_PHRASE_MISMATCH",
            "MALFORMED",
            "PARTIAL_INVALID",
            "SIGNING_FAILED",
            "VERIFICATION_FAILED",
            "DOMAIN_NOT_PERMITTED",
            "ENTROPY_UNAVAILABLE",
        ];
        // Phase 8 appended these 18, in this order.
        const PHASE_8: [&str; 18] = [
            "AWARD_NOT_YET_OPEN",
            "LOT_UNKNOWN",
            "LOT_BURNED",
            "LOT_NOT_ACTIVE",
            "LOT_NOT_UNBONDING",
            "ROTATION_KEY_REUSED",
            "ROTATION_GENERATION",
            "RESTORE_NOT_VERIFIED",
            "ROTATION_PENDING",
            "ROTATION_ADDRESS_TAKEN",
            "LOCK_NOT_FOUND",
            "OFFER_NOT_YET_VALID",
            "OFFER_EXPIRED",
            "TREASURY_ADDRESS_USED",
            "TREASURY_GENERATION",
            "TREASURY_DESTINATION_UNRESOLVED",
            "TREASURY_CLASS_UNDECLARED",
            "TREASURY_OFFER_TERMS",
        ];
        // The fixes of the independent wallet review appended these, after every phase 8 code.
        const REVIEW_FIXES: [&str; 2] = ["ROTATION_FUNDING", "TREASURY_ROLE_NOT_DECLARED"];
        // Candidate 3 (Order section 6) appended these, after every earlier code.
        const CANDIDATE_3: [&str; 6] = [
            "ADDRESS_ENCODING",
            "CAPABILITY_NOT_PERMITTED",
            "APPROVAL_BINDING_MISMATCH",
            "NOT_DELIVERABLE",
            "OFFER_WINDOW_EXCEEDED",
            "VALIDITY_WINDOW_UNSUPPORTED",
        ];
        let catalog: Vec<&str> = CATALOG.iter().map(|(code, _)| *code).collect();
        assert_eq!(&catalog[..BEFORE_PHASE_8.len()], &BEFORE_PHASE_8[..]);
        let phase_8_end = BEFORE_PHASE_8.len() + PHASE_8.len();
        assert_eq!(&catalog[BEFORE_PHASE_8.len()..phase_8_end], &PHASE_8[..]);
        let review_end = phase_8_end + REVIEW_FIXES.len();
        assert_eq!(&catalog[phase_8_end..review_end], &REVIEW_FIXES[..]);
        assert_eq!(&catalog[review_end..], &CANDIDATE_3[..]);
    }

    #[test]
    fn codes_are_plain_upper_snake_and_display_is_never_empty() {
        for refusal in Refusal::examples() {
            let code = refusal.code();
            assert!(
                code.bytes().all(|b| b.is_ascii_uppercase() || b == b'_'),
                "{code}"
            );
            assert!(!refusal.to_string().is_empty());
            assert!(!format!("{refusal:?}").is_empty());
        }
    }
}
