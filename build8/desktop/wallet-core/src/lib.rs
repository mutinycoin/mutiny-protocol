//! Mutiny Build 8 wallet core: UI-free, network-free, Bitcoin-free.
//!
//! The wallet CONSTRUCTS, REVIEWS and AUTHORIZES operations; it never signs anything a person has
//! not seen. The pipeline (see `README.md` for the frozen interface and how phases add operations):
//!
//! ```text
//!   OperationRequest --plan()--> OperationPlan --review()--> Review --ReviewGate--> Approval
//!                                      \                                               |
//!                                       `------------- Signer::authorize(plan, approval, view)
//!                                                                  |
//!                                                          SignedOperation --Outbox--> export
//! ```
//!
//! * [`plan`](mod@plan): kinds, requests, immutable plans, the planner trait and the plan state machine.
//! * [`review`](mod@review): the review a person reads (a pure function of the unsigned bytes and the verified
//!   chain), its binding digest and text rendering.
//! * [`authorize`]: the signing gate, the single-use approval, the review gate and the signer.
//! * [`capability`]: sealed keys and the typed signing capabilities a handler is lent (W4).
//! * [`partial`]: public containers for operations other parties still have to sign.
//! * [`outbox`]: the durable queue of signed operations, with input reservations.
//! * [`export`]: the view-verified export of a queued operation for delivery (W6).
//! * [`ops`]: one handler per operation kind (phase 1 ships ordinary payments).
//! * [`context`], [`refusal`], [`units`], [`secret`]: shared foundations.
//! * [`address_format`]: the checksummed text form of an address identifier (W2, PROPOSED).
//!
//! Evidence labels: Implemented is not Qualified; offline is not physical; simulated is not
//! physical. Production signing is unavailable while `mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED`
//! is false, and this crate has no path to a private key that bypasses that gate.
#![forbid(unsafe_code)]

// Production exclusion guards for the wallet core, in the style of node/src/lib.rs. Test-fixture
// and qualification-only features must never be compiled into a binary that links this library.
// `wallet-custody` is required here (and only in wallet roots); release custody must never be
// present, because the offline release signer and the wallet are separate custody domains.
const _: () = assert!(
    !mutiny_crypto_v2::RECEIPT_QUALIFICATION_ENABLED,
    "receipt qualification must not be compiled into wallet-core consumers"
);
const _: () = assert!(
    !mutiny_crypto_v2::RELEASE_CUSTODY_ENABLED,
    "release custody must never be linked into the wallet"
);
const _: () = assert!(
    mutiny_crypto_v2::WALLET_CUSTODY_ENABLED,
    "wallet-core requires crypto-v2 wallet-custody (the wallet root is the only place it is allowed)"
);
const _: () = assert!(
    !mutiny_consensus_v8::DIVIDEND_TEST_FIXTURES_ENABLED,
    "dividend test fixtures must not be compiled into wallet-core consumers"
);
const _: () = assert!(
    !mutiny_consensus_v8::LEGACY_V0_TEST_FIXTURES_ENABLED,
    "legacy v0 test fixtures must not be compiled into wallet-core consumers"
);

pub mod address_format;
pub mod authorize;
pub mod capability;
pub mod context;
pub mod discovery;
pub mod export;
pub mod offers;
pub mod ops;
pub mod outbox;
pub mod outbox_sqlite;
pub mod partial;
pub mod plan;
pub mod profile;
pub mod refusal;
pub mod review;
mod rotation_signer;
pub mod secret;
pub mod units;

pub use address_format::AddressError;
pub use authorize::{
    Approval, DEFAULT_IDLE_LIMIT, Freshness, GateMode, KeySigner, MAX_APPROVAL_AGE, MAX_REVIEW_AGE,
    Purpose, ReviewGate, SignedOperation, Signer, SignerIdentity, SigningGate,
    TEST_VALUE_SIGNING_ENABLED, WalletProfile, domain_for,
};
pub use context::{ChainClass, ChainContext, ChainView, ConfirmationSource, HeadInfo};
pub use export::{ApprovalBinding, ApprovalEvidence, DeliveryStatus, VerifiedExport};
pub use outbox::{
    DEFAULT_MAX_SETTLED, MemoryOutbox, Outbox, OutboxRecord, OutboxStatus, ReconcileReport,
    Settlement, resource_key,
};
pub use outbox_sqlite::SqliteOutbox;
pub use partial::PartialApproval;
pub use plan::{
    Blob, BondCreateRequest, BondUnbondRequest, BondWithdrawRequest, CancelRequest, CancelTarget,
    ClaimRequest, DEFAULT_VALIDITY_BLOCKS, DividendClaimRequest, FeeSource, FiatLockRequest,
    FiatReleaseRequest, HashLockRequest, Invalidation, LicenseDvpRequest, MakerOfferRequest,
    OperationKind, OperationPlan, OperationRequest, PaymentRequest, PlanObject, PlanPhase,
    PlanSession, Planner, RefundRequest, RequiredSigner, Requirement, RequirementStatus,
    RotationRequest, Slot, StandardPlanner, TreasuryFreezeOfferRequest, TreasuryRotateRequest,
    Validity, WorkerAssignmentRequest, adopt, plan,
};
pub use profile::{TreasuryRole, TreasuryRoles};
pub use refusal::{ContextField, ExpiryKind, Refusal};
pub use review::{
    AckKind, AddressLabel, ChainSummary, Condition, Destination, DestinationRole, Effect, Emphasis,
    Fee, FeePayer, FeeRule, InputLine, Party, PartyRole, Review, ReviewDigest, Row, Section,
    Severity, SignerSummary, Timing, Warning, binding_digest, explain, review,
};
pub use secret::Preimage;
