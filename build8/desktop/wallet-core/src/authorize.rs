//! Who may sign, what must have happened first, and how a signature is produced and checked.
//!
//! There is NO "sign these bytes" API. The only way to a signature is
//! [`Signer::authorize`]`(plan, approval, view)`, which
//!
//!  1. checks the [`SigningGate`] (production gate = crypto-v2 `PRODUCTION_SECURITY_QUALIFIED`,
//!     closed today; a TEST-VALUE gate exists only under `cfg(test)` or the non-shipping feature
//!     `test-value-signing`),
//!  2. checks the session is not locked or idle-expired,
//!  3. checks the single-use [`Approval`] has not been withdrawn, is fresh, belongs to the current
//!     head and carries the binding digest (and acknowledgement scope) of exactly this plan,
//!     recomputed from the unsigned bytes and the CURRENT view,
//!  4. checks the key is the current authority for every address it must sign for (the same
//!     `WalletBook::authorize` call consensus makes; a rotated-away key is refused),
//!  5. signs through the operation's handler, which is LENT a
//!     [`KindSigner`](crate::capability::KindSigner) for the plan's kind and can only ask it for
//!     the typed capabilities of [`crate::capability`] that the kind permits (Order W4). Each
//!     capability signs one consensus object of that kind through its consensus-owned builder
//!     (`Transfer::sign_input`, bond `Operation::sign`, `SignedClaim::sign`, `Rotation::sign`, a
//!     trading approval over `Operation::signing_payload`, a Treasury freeze body) under the
//!     domain consensus uses or the one [`domain_for`] returns. No handler holds a key, no caller
//!     supplies a domain, and no function signs caller-chosen bytes,
//!  6. verifies the result independently through consensus code, checks that the signed bytes are
//!     exactly the reviewed unsigned bytes plus signatures, and that the metadata attached to the
//!     result is what the bytes say,
//!  7. and only then releases the bytes. The approval is consumed by move whatever the outcome.
//!
//! The approval itself comes only from a [`ReviewGate`], which issues one when a complete,
//! fresh review has been presented and every acknowledgement it requires (including the typed
//! address re-entry check) has been given. A gate has at most one live approval: issuing another,
//! presenting anything new, clearing the gate (lock, expiry, cancel) or moving to a new head
//! withdraws every approval it issued before, even one a caller still holds.
//!
//! # What these gates are, and what they are not
//!
//! They enforce an ORDER and a BINDING: nothing is signed that was not reviewed at the current head,
//! and a user interface that skipped, reordered or confused steps cannot obtain a signature. They are
//! not a proof that a human was present: the typed checks and acknowledgements are ordinary calls,
//! so a malicious HOST PROCESS that holds the key could drive them programmatically, or sign without
//! this crate at all. The boundary against such a process is the host process itself, the vault and
//! the platform, never this library. The 8-hex-character destination check is 32 bits: it defeats
//! carelessness and look-alike addresses, not a determined grinder (Q10 default, pending a real
//! address format). The explicit-clock and explicit-limit entry points (`present_at`, `approve_at`,
//! `authorize_at`, `ReviewGate::with_limits`) exist only in test builds, so a shipping host cannot
//! move time or widen an age limit.

use crate::{
    capability::{KeyRing, KindSigner, SealedKey},
    context::{ChainClass, ChainView},
    plan::{
        OperationKind, OperationPlan, PlanObject, RequiredSigner, Requirement, RequirementStatus,
        Slot, Validity,
    },
    profile::TreasuryRoles,
    refusal::{ExpiryKind, Refusal},
    review::{AckKind, Review, ReviewDigest, SignerSummary},
    units,
};
use mutiny_consensus_v8::{Hash, anchors::FinalizedAnchor, transactions::OutPoint};
use mutiny_crypto_v2::{Domain, HybridKey, PublicKey, Role};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

/// How long a displayed review may stay on screen before it must be shown again.
pub const MAX_REVIEW_AGE: Duration = Duration::from_secs(600);
/// How long an issued approval may wait before it must be used.
pub const MAX_APPROVAL_AGE: Duration = Duration::from_secs(120);
/// Idle time after which a [`KeySigner`] (or a `RotationSigner`) locks itself, and the LONGEST idle
/// limit a host can give one: a shorter limit is honoured, a longer one is clamped to this.
pub const DEFAULT_IDLE_LIMIT: Duration = Duration::from_secs(300);

/// True when this build contains the TEST-VALUE signing gate and the test constructors. Every
/// shipping binary asserts this is `false` at compile time.
pub const TEST_VALUE_SIGNING_ENABLED: bool = cfg!(any(test, feature = "test-value-signing"));

/// A unique marker string that is present in a binary only when the TEST-VALUE gate is compiled
/// in; the production exclusion check forbids it in release artefacts.
#[cfg(any(test, feature = "test-value-signing"))]
pub const TEST_VALUE_GATE_MARKER: &str = "MUTINY-WALLET-CORE-TEST-VALUE-GATE-V1";

// ---------------------------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------------------------

/// Which controls a wallet exposes. The Treasury profile is for the authorised Treasury owner
/// only; an ordinary wallet never reaches Treasury key controls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalletProfile {
    Ordinary,
    Treasury,
}

impl WalletProfile {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary wallet",
            Self::Treasury => "Treasury profile",
        }
    }
}

/// The PUBLIC identity of a signing wallet: its current descriptor, generation, current-generation
/// address and the generation-one address that names its authority. Holds no secret.
#[derive(Clone, PartialEq, Eq)]
pub struct SignerIdentity {
    descriptor: Vec<u8>,
    generation: u64,
    address: Hash,
    authority: Hash,
    profile: WalletProfile,
    /// The Treasury roles `profile::declare` checked (none for an ordinary identity).
    roles: TreasuryRoles,
}

impl SignerIdentity {
    /// Build an identity from a wallet-owner descriptor. `authority` is the generation-one
    /// AddressID of the wallet; omit it for generation one, where it is the address itself.
    pub fn new(descriptor: &[u8], authority: Option<Hash>) -> Result<Self, Refusal> {
        let (public, generation) =
            PublicKey::decode_descriptor(descriptor).map_err(|_| Refusal::InvalidDescriptor)?;
        if public.role != Role::WalletOwner || generation == 0 {
            return Err(Refusal::InvalidDescriptor);
        }
        let address = public
            .address_id(generation)
            .map_err(|_| Refusal::InvalidDescriptor)?;
        let authority = match (generation, authority) {
            (1, None) => address,
            (1, Some(given)) if given == address => given,
            (1, Some(_)) => return Err(Refusal::InvalidDescriptor),
            (_, Some(given)) if given != [0; 32] => given,
            _ => return Err(Refusal::InvalidDescriptor),
        };
        Ok(Self {
            descriptor: descriptor.to_vec(),
            generation,
            address,
            authority,
            profile: WalletProfile::Ordinary,
            roles: TreasuryRoles::default(),
        })
    }

    /// The same from a public key and generation.
    pub fn from_public(
        public: &PublicKey,
        generation: u64,
        authority: Option<Hash>,
    ) -> Result<Self, Refusal> {
        let descriptor = public
            .descriptor(generation)
            .map_err(|_| Refusal::InvalidDescriptor)?;
        Self::new(&descriptor, authority)
    }

    /// The Treasury profile with exactly `roles` (the ordinary profile when `roles` holds none).
    /// CRATE-PRIVATE (fixes of the independent wallet review, CR-6-3): the only public way to a
    /// Treasury-profile identity is `profile::declare`, which checks every role against the
    /// verified chain first. It creates no authority: signing still needs the key, and every
    /// Treasury operation checks the role and the chain's Treasury identity again when used.
    pub(crate) fn with_treasury_roles(mut self, roles: TreasuryRoles) -> Self {
        self.profile = if roles.any() {
            WalletProfile::Treasury
        } else {
            WalletProfile::Ordinary
        };
        self.roles = roles;
        self
    }

    /// TEST-VALUE test constructor (`TestValueGate`): `with_treasury_roles` without
    /// `profile::declare`'s checks against a chain, for tests of the handlers' own use-time
    /// checks. It exists only in test builds and under the non-shipping `test-value-signing`
    /// feature.
    #[cfg(any(test, feature = "test-value-signing"))]
    pub fn with_treasury_roles_for_test(self, roles: TreasuryRoles) -> Self {
        self.with_treasury_roles(roles)
    }

    pub fn descriptor(&self) -> &[u8] {
        &self.descriptor
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// The current-generation address (where change returns).
    pub fn address(&self) -> Hash {
        self.address
    }
    /// The generation-one AddressID that names this wallet authority across rotations.
    pub fn authority(&self) -> Hash {
        self.authority
    }
    pub fn profile(&self) -> WalletProfile {
        self.profile
    }
    /// The Treasury roles `profile::declare` checked for this identity (none when ordinary).
    pub fn treasury_roles(&self) -> TreasuryRoles {
        self.roles
    }
    /// The decoded public key.
    pub fn public(&self) -> PublicKey {
        PublicKey::decode_descriptor(&self.descriptor)
            .expect("descriptor validated at construction")
            .0
    }

    pub(crate) fn summary(&self) -> SignerSummary {
        SignerSummary {
            address: self.address,
            generation: self.generation,
            authority: self.authority,
            profile: self.profile,
        }
    }

    /// Whether this identity is, on the verified chain, the current key of its authority. A key
    /// that was rotated away, or an identity the chain does not corroborate, is `StaleAuthority`.
    pub fn check_current(&self, view: &ChainView<'_>) -> Result<(), Refusal> {
        match view.state().wallets.current(self.authority) {
            Some(current) if current == self.descriptor.as_slice() => Ok(()),
            Some(_) => Err(Refusal::StaleAuthority),
            None if self.generation == 1 && self.address == self.authority => Ok(()),
            None => Err(Refusal::StaleAuthority),
        }
    }
}

impl fmt::Debug for SignerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignerIdentity")
            .field("address", &units::short_hex(&self.address))
            .field("generation", &self.generation)
            .field("authority", &units::short_hex(&self.authority))
            .field("profile", &self.profile)
            .field("roles", &self.roles)
            .finish()
    }
}

// ---------------------------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------------------------

/// Which gate admitted signing. There is deliberately no way to name a test mode in a build that
/// does not contain it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GateMode {
    /// Production signing: open only when crypto-v2 `PRODUCTION_SECURITY_QUALIFIED` is true.
    Production,
    /// TEST-VALUE signing for public test keys; compiled only under `cfg(test)` or the
    /// non-shipping `test-value-signing` feature.
    #[cfg(any(test, feature = "test-value-signing"))]
    TestValue,
}

/// Proof that signing is permitted in this build. Obtainable only through [`Self::production`]
/// (closed while production qualification is incomplete) or, in test builds only,
/// `SigningGate::test_value`.
#[derive(Debug)]
pub struct SigningGate {
    mode: GateMode,
}

impl SigningGate {
    /// The production gate. Refuses with [`Refusal::GateClosed`] while
    /// `mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED` is false, which is its value today.
    pub fn production() -> Result<Self, Refusal> {
        if !mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED {
            return Err(Refusal::GateClosed);
        }
        mutiny_crypto_v2::protect_process().map_err(|_| Refusal::ProcessProtection)?;
        Ok(Self {
            mode: GateMode::Production,
        })
    }

    /// The TEST-VALUE gate for public test keys. Does not exist in a shipping build.
    #[cfg(any(test, feature = "test-value-signing"))]
    pub fn test_value() -> Result<Self, Refusal> {
        mutiny_crypto_v2::protect_process().map_err(|_| Refusal::ProcessProtection)?;
        // Reference the marker so that it is part of every binary that can build this gate.
        std::hint::black_box(TEST_VALUE_GATE_MARKER);
        Ok(Self {
            mode: GateMode::TestValue,
        })
    }

    pub fn mode(&self) -> GateMode {
        self.mode
    }

    /// Re-checked on every authorization.
    pub(crate) fn check(&self, view: &ChainView<'_>) -> Result<(), Refusal> {
        match self.mode {
            GateMode::Production => {
                if !mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED {
                    return Err(Refusal::GateClosed);
                }
                if view.class() == ChainClass::TestValue {
                    return Err(Refusal::ChainClassMismatch {
                        gate: ChainClass::Production,
                        chain: ChainClass::TestValue,
                    });
                }
            }
            #[cfg(any(test, feature = "test-value-signing"))]
            GateMode::TestValue => {
                if view.class() == ChainClass::Production {
                    return Err(Refusal::ChainClassMismatch {
                        gate: ChainClass::TestValue,
                        chain: ChainClass::Production,
                    });
                }
            }
        }
        mutiny_crypto_v2::protect_process().map_err(|_| Refusal::ProcessProtection)
    }
}

// ---------------------------------------------------------------------------------------------
// Domains and key access
// ---------------------------------------------------------------------------------------------

/// What a signature is for. The signing domain is a function of the operation kind and this
/// purpose only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Purpose {
    /// A spend authorization: transaction inputs, trading approvals, a dividend claim, a Treasury
    /// freeze (all `Domain::Transaction`).
    Spend,
    /// The owner signature of a bond operation (`BondCreate`, `BondUnbond` or `BondWithdraw`).
    BondAction,
    /// The current key's authorization of a wallet rotation.
    RotateAuthorization,
    /// The new key's possession proof of a wallet rotation.
    RotatePossession,
    MakerOffer,
    MakerFill,
    /// Current License owner over the exact enrollment binding.
    WorkerAssignment,
}

/// The signing domain for an operation kind and purpose. Total over every combination: anything
/// not listed is [`Refusal::DomainNotPermitted`].
pub fn domain_for(kind: OperationKind, purpose: Purpose) -> Result<Domain, Refusal> {
    use OperationKind as K;
    use Purpose as P;
    let domain = match (kind, purpose) {
        (
            K::Payment
            | K::WalletRotation
            | K::DividendClaim
            | K::LicenseDvp
            | K::HashLock
            | K::ConditionalClaim
            | K::ConditionalRefund
            | K::FiatLock
            | K::FiatRelease
            | K::TreasuryRotate
            | K::TreasuryFreezeOffer
            | K::BondCreate,
            P::Spend,
        ) => Domain::Transaction,
        (K::WorkerAssignment, P::WorkerAssignment) => Domain::MinerEnrollment,
        (K::MakerOffer, P::MakerOffer) => Domain::TradeOffer,
        (K::LicenseDvp | K::HashLock | K::FiatLock, P::MakerFill) => Domain::TradeFill,
        (K::WalletRotation, P::RotateAuthorization) => Domain::WalletRotate,
        (K::WalletRotation, P::RotatePossession) => Domain::WalletRotatePossession,
        (K::BondCreate, P::BondAction) => Domain::BondCreate,
        (K::BondUnbond, P::BondAction) => Domain::BondUnbond,
        (K::BondWithdraw, P::BondAction) => Domain::BondWithdraw,
        _ => return Err(Refusal::DomainNotPermitted { kind, purpose }),
    };
    Ok(domain)
}

// Key access lives in `crate::capability` (Order W4): the sealed keys, the key ring and the
// `KindSigner` a handler is lent, which hands out typed capabilities only.

// ---------------------------------------------------------------------------------------------
// Signed results
// ---------------------------------------------------------------------------------------------

/// The result of an authorization: every required signature is present (`Complete`) or some other
/// party must still sign (`Partial`, public data only). Bytes are released only after independent
/// verification through consensus code.
#[derive(Clone, PartialEq, Eq)]
pub enum SignedOperation {
    Complete {
        kind: OperationKind,
        /// The operation's identifier (transaction id, claim id, operation id ...).
        id: Hash,
        bytes: Vec<u8>,
        validity: Validity,
        /// Coins this operation consumes; the outbox reserves them.
        reserved: Vec<OutPoint>,
    },
    Partial {
        kind: OperationKind,
        id: Hash,
        bytes: Vec<u8>,
        /// Signatures still missing.
        missing: Vec<Requirement>,
        validity: Validity,
        reserved: Vec<OutPoint>,
    },
}

impl SignedOperation {
    pub fn kind(&self) -> OperationKind {
        match self {
            Self::Complete { kind, .. } | Self::Partial { kind, .. } => *kind,
        }
    }
    pub fn id(&self) -> Hash {
        match self {
            Self::Complete { id, .. } | Self::Partial { id, .. } => *id,
        }
    }
    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::Complete { bytes, .. } | Self::Partial { bytes, .. } => bytes,
        }
    }
    pub fn validity(&self) -> &Validity {
        match self {
            Self::Complete { validity, .. } | Self::Partial { validity, .. } => validity,
        }
    }
    pub fn reserved(&self) -> &[OutPoint] {
        match self {
            Self::Complete { reserved, .. } | Self::Partial { reserved, .. } => reserved,
        }
    }
    pub fn is_complete(&self) -> bool {
        matches!(self, Self::Complete { .. })
    }
    /// Signatures still missing (empty for a complete operation).
    pub fn missing(&self) -> &[Requirement] {
        match self {
            Self::Complete { .. } => &[],
            Self::Partial { missing, .. } => missing,
        }
    }

    /// Whether the metadata of this value (identifier, completeness, signatures still missing,
    /// validity, reserved coins and resources) is exactly what its bytes commit to.
    pub(crate) fn matches(&self, described: &crate::plan::Description) -> bool {
        let mut reserved = self.reserved().to_vec();
        reserved.sort();
        reserved.dedup();
        self.id() == described.id
            && self.is_complete() == described.complete
            && self.missing() == described.missing.as_slice()
            && *self.validity() == described.validity
            && reserved == described.reserved
    }

    /// Import signed (or partially signed) bytes produced elsewhere, for example by an offline
    /// signer, so they can be queued and exported. Nothing is taken on trust: the kind is
    /// recognised from the bytes, every metadata field is DERIVED from the bytes, and the result is
    /// verified through consensus code against the current verified view.
    pub fn import(raw: &[u8], view: &ChainView<'_>) -> Result<Self, Refusal> {
        let handler = crate::ops::recognizing(raw).ok_or(Refusal::UnknownOperation)?;
        let described = handler.describe(raw)?;
        let signed = if described.complete {
            Self::Complete {
                kind: handler.kind(),
                id: described.id,
                bytes: raw.to_vec(),
                validity: described.validity,
                reserved: described.reserved,
            }
        } else {
            Self::Partial {
                kind: handler.kind(),
                id: described.id,
                bytes: raw.to_vec(),
                missing: described.missing,
                validity: described.validity,
                reserved: described.reserved,
            }
        };
        handler.check_signed(&signed, view)?;
        Ok(signed)
    }
}

impl fmt::Debug for SignedOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct(if self.is_complete() {
            "SignedOperation::Complete"
        } else {
            "SignedOperation::Partial"
        })
        .field("kind", &self.kind())
        .field("id", &units::short_hex(&self.id()))
        .field("bytes", &self.bytes().len())
        .field("missing", &self.missing().len())
        .finish()
    }
}

// ---------------------------------------------------------------------------------------------
// Approval and the review gate
// ---------------------------------------------------------------------------------------------

/// Single-use permission to authorize one reviewed operation at one verified head.
///
/// Not `Clone` and not `Copy`, with private fields: it is created only by
/// [`ReviewGate::approve`] (or, in test builds, `Approval::for_review_for_test`) and consumed by
/// move in [`Signer::authorize`]. It cannot be reused, edited or carried to another head, and the
/// gate that issued it can withdraw it (see [`ReviewGate`]) even while a caller holds it.
pub struct Approval {
    digest: ReviewDigest,
    /// The review's schema (part of the binding digest).
    schema: u16,
    /// What was acknowledged and for which wallet (see `Review::scope`).
    scope: Hash,
    kind: OperationKind,
    anchor: FinalizedAnchor,
    state_root: Hash,
    issued: Instant,
    max_age: Duration,
    /// The issuing gate's withdrawal counter and its value when this approval was issued: the
    /// approval is live only while they are equal.
    withdrawal: Arc<AtomicU64>,
    epoch: u64,
}

impl Approval {
    /// Whether the gate that issued this approval has withdrawn it.
    fn withdrawn(&self) -> bool {
        self.withdrawal.load(Ordering::SeqCst) != self.epoch
    }

    /// The binding digest of the review this approval was given for.
    pub fn digest(&self) -> ReviewDigest {
        self.digest
    }
    pub fn kind(&self) -> OperationKind {
        self.kind
    }
    /// The verified head the review was for.
    pub fn anchor(&self) -> &FinalizedAnchor {
        &self.anchor
    }
    /// What this approval was given for (public data, not a capability): take it before
    /// [`Signer::authorize`] consumes the approval, and pass it to
    /// [`Outbox::commit_approved`](crate::outbox::Outbox::commit_approved) so that
    /// [`Outbox::export_verified`](crate::outbox::Outbox::export_verified) can check later that
    /// the queued bytes are exactly what was approved (Order W6).
    pub fn binding(&self) -> crate::export::ApprovalBinding {
        crate::export::ApprovalBinding::new(
            self.kind,
            self.schema,
            self.digest,
            self.scope,
            self.anchor.clone(),
            self.state_root,
        )
    }
    pub fn age(&self) -> Duration {
        self.issued.elapsed()
    }

    /// Test constructor: an approval for `review`, issued at `issued`. Does not exist in a
    /// shipping build.
    #[cfg(any(test, feature = "test-value-signing"))]
    pub fn for_review_for_test(review: &Review, issued: Instant) -> Self {
        Self {
            digest: review.binding(),
            schema: review.schema(),
            scope: review.scope(),
            kind: review.kind(),
            anchor: review.anchor().clone(),
            state_root: review.chain().state_root,
            issued,
            max_age: MAX_APPROVAL_AGE,
            withdrawal: Arc::new(AtomicU64::new(0)),
            epoch: 0,
        }
    }
}

impl fmt::Debug for Approval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Approval")
            .field("kind", &self.kind)
            .field("digest", &self.digest)
            .field("height", &self.anchor.height)
            .field("age_ms", &(self.issued.elapsed().as_millis() as u64))
            .finish()
    }
}

struct Shown {
    digest: ReviewDigest,
    schema: u16,
    scope: Hash,
    kind: OperationKind,
    anchor: FinalizedAnchor,
    state_root: Hash,
    required: Vec<AckKind>,
    acked: BTreeSet<AckKind>,
    /// Destination index to (expected typed text, entered correctly).
    checks: BTreeMap<usize, (String, bool)>,
    /// The confirmation phrase of a high-risk review and whether it was typed correctly.
    phrase: Option<(String, bool)>,
    presented_at: Instant,
}

/// Whether the review on screen is still for the current head.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Freshness {
    Fresh,
    Stale,
}

/// UI-free state of the approval step: the review on screen, the acknowledgements collected, the
/// typed address checks entered. It issues the [`Approval`] only when everything the review
/// requires is in and the review is still for the current head, and it forgets everything once it
/// has issued one (single use).
///
/// A gate has at most one live approval. Whenever it drops or replaces what it shows (a new head, a
/// review of a different operation, an expired review, [`Self::clear`] for lock, expiry or cancel) or
/// issues another approval, every approval it issued earlier is WITHDRAWN: it stays in the caller's
/// hands but [`Signer::authorize`] refuses it with `ApprovalRevoked`. Together with the head binding
/// and the age limit that makes "a lock, a new head or an expiry clears the approval" literally
/// true, not just true of the screen.
pub struct ReviewGate {
    shown: Option<Shown>,
    max_review_age: Duration,
    max_approval_age: Duration,
    /// Shared with every approval this gate issues; bumping it withdraws them all.
    withdrawal: Arc<AtomicU64>,
    /// The head the live approval (the one issued last, if nothing withdrew it since) is for.
    approved_head: Option<(FinalizedAnchor, Hash)>,
}

impl Default for ReviewGate {
    fn default() -> Self {
        Self::new()
    }
}

impl ReviewGate {
    pub fn new() -> Self {
        Self {
            shown: None,
            max_review_age: MAX_REVIEW_AGE,
            max_approval_age: MAX_APPROVAL_AGE,
            withdrawal: Arc::new(AtomicU64::new(0)),
            approved_head: None,
        }
    }
    /// Gate with explicit age limits. Test builds only: a shipping gate always uses the fixed
    /// limits, so a host cannot widen them.
    #[cfg(any(test, feature = "test-value-signing"))]
    pub fn with_limits(max_review_age: Duration, max_approval_age: Duration) -> Self {
        Self {
            max_review_age,
            max_approval_age,
            ..Self::new()
        }
    }

    /// Withdraw every approval issued so far.
    fn withdraw_issued(&mut self) {
        self.approved_head = None;
        self.withdrawal.fetch_add(1, Ordering::SeqCst);
    }

    /// Stop showing anything and withdraw every outstanding approval.
    fn drop_shown(&mut self) {
        self.shown = None;
        self.withdraw_issued();
    }

    /// Put `review` on screen. A review for another head is `Stale` and clears everything; a review
    /// whose digest differs from the one on screen replaces it and clears every acknowledgement.
    pub fn present(&mut self, review: &Review, view: &ChainView<'_>) -> Freshness {
        self.present_with(review, view, Instant::now())
    }

    /// [`Self::present`] with an explicit clock. Test builds only: a shipping gate reads the real
    /// monotonic clock itself.
    #[cfg(any(test, feature = "test-value-signing"))]
    pub fn present_at(&mut self, review: &Review, view: &ChainView<'_>, now: Instant) -> Freshness {
        self.present_with(review, view, now)
    }

    fn present_with(&mut self, review: &Review, view: &ChainView<'_>, now: Instant) -> Freshness {
        if !review.is_for(view) {
            self.drop_shown();
            return Freshness::Stale;
        }
        if self.shown.as_ref().map(|shown| shown.digest) != Some(review.binding()) {
            // Anything newly put on screen withdraws what was approved before it.
            self.withdraw_issued();
            let checks = review
                .destinations_needing_check()
                .into_iter()
                .map(|index| (index, (review.destination_check_text(index), false)))
                .collect();
            self.shown = Some(Shown {
                digest: review.binding(),
                schema: review.schema(),
                scope: review.scope(),
                kind: review.kind(),
                anchor: review.anchor().clone(),
                state_root: review.chain().state_root,
                required: review.acknowledgements().to_vec(),
                acked: BTreeSet::new(),
                checks,
                phrase: review.confirmation_phrase().map(|phrase| (phrase, false)),
                presented_at: now,
            });
        }
        Freshness::Fresh
    }

    /// The acknowledgements still outstanding.
    pub fn pending_acknowledgements(&self) -> Vec<AckKind> {
        self.shown
            .as_ref()
            .map(|shown| {
                shown
                    .required
                    .iter()
                    .copied()
                    .filter(|ack| !shown.acked.contains(ack))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Enter the last eight characters of destination `index` (as listed by
    /// `Review::destinations`). The comparison ignores case and surrounding spaces.
    pub fn confirm_destination(&mut self, index: usize, typed: &str) -> Result<(), Refusal> {
        let shown = self.shown.as_mut().ok_or(Refusal::NotPresented)?;
        let entry = shown
            .checks
            .get_mut(&index)
            .ok_or(Refusal::DestinationCheckFailed)?;
        if typed.trim().to_ascii_lowercase() != entry.0 {
            return Err(Refusal::DestinationCheckFailed);
        }
        entry.1 = true;
        Ok(())
    }

    /// Type the confirmation phrase of a high-risk review. Case and surrounding or repeated spaces
    /// do not matter.
    pub fn confirm_phrase(&mut self, typed: &str) -> Result<(), Refusal> {
        let shown = self.shown.as_mut().ok_or(Refusal::NotPresented)?;
        let entry = shown
            .phrase
            .as_mut()
            .ok_or(Refusal::ConfirmationPhraseMismatch)?;
        let normalized = typed
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_uppercase();
        if normalized != entry.0 {
            return Err(Refusal::ConfirmationPhraseMismatch);
        }
        entry.1 = true;
        Ok(())
    }

    /// Give one acknowledgement. Only kinds the review asks for are accepted, and the destination
    /// acknowledgement requires every typed address check first.
    pub fn acknowledge(&mut self, ack: AckKind) -> Result<(), Refusal> {
        let shown = self.shown.as_mut().ok_or(Refusal::NotPresented)?;
        if !shown.required.contains(&ack) {
            return Err(Refusal::UnexpectedAcknowledgement(ack));
        }
        if ack == AckKind::Destination && shown.checks.values().any(|(_, done)| !done) {
            return Err(Refusal::DestinationCheckPending);
        }
        shown.acked.insert(ack);
        Ok(())
    }

    /// Whether `approve` would succeed right now.
    pub fn is_ready(&self, view: &ChainView<'_>) -> bool {
        self.shown.as_ref().is_some_and(|shown| {
            shown.anchor == *view.anchor()
                && shown.state_root == view.state_root()
                && shown.required.iter().all(|ack| shown.acked.contains(ack))
                && shown.checks.values().all(|(_, done)| *done)
                && shown.phrase.as_ref().is_none_or(|(_, done)| *done)
        })
    }

    /// Issue the single-use approval for the review on screen.
    pub fn approve(&mut self, view: &ChainView<'_>) -> Result<Approval, Refusal> {
        self.approve_with(view, Instant::now())
    }

    /// [`Self::approve`] with an explicit clock. Test builds only.
    #[cfg(any(test, feature = "test-value-signing"))]
    pub fn approve_at(&mut self, view: &ChainView<'_>, now: Instant) -> Result<Approval, Refusal> {
        self.approve_with(view, now)
    }

    fn approve_with(&mut self, view: &ChainView<'_>, now: Instant) -> Result<Approval, Refusal> {
        let shown = self.shown.as_ref().ok_or(Refusal::NotPresented)?;
        if shown.anchor != *view.anchor() || shown.state_root != view.state_root() {
            let reviewed = shown.anchor.height;
            self.drop_shown();
            return Err(Refusal::StaleHead {
                reviewed,
                current: view.anchor().height,
            });
        }
        if now.saturating_duration_since(shown.presented_at) > self.max_review_age {
            self.drop_shown();
            return Err(Refusal::Expired(ExpiryKind::Review));
        }
        if let Some(missing) = shown.required.iter().find(|ack| !shown.acked.contains(ack)) {
            return Err(Refusal::AcknowledgementMissing(*missing));
        }
        if shown.checks.values().any(|(_, done)| !done) {
            return Err(Refusal::DestinationCheckPending);
        }
        if shown.phrase.as_ref().is_some_and(|(_, done)| !done) {
            return Err(Refusal::ConfirmationPhraseMissing);
        }
        // Issuing this approval withdraws every earlier one.
        let epoch = self.withdrawal.fetch_add(1, Ordering::SeqCst) + 1;
        let approval = Approval {
            digest: shown.digest,
            schema: shown.schema,
            scope: shown.scope,
            kind: shown.kind,
            anchor: shown.anchor.clone(),
            state_root: shown.state_root,
            issued: now,
            max_age: self.max_approval_age,
            withdrawal: Arc::clone(&self.withdrawal),
            epoch,
        };
        self.approved_head = Some((approval.anchor.clone(), approval.state_root));
        self.shown = None;
        Ok(approval)
    }

    /// A new verified head: drop the review on screen if it is for any other head, and withdraw the
    /// approval issued for any other head.
    pub fn on_head(&mut self, view: &ChainView<'_>) {
        let moved = |anchor: &FinalizedAnchor, root: &Hash| {
            anchor != view.anchor() || *root != view.state_root()
        };
        if self
            .shown
            .as_ref()
            .is_some_and(|shown| moved(&shown.anchor, &shown.state_root))
            || self
                .approved_head
                .as_ref()
                .is_some_and(|(anchor, root)| moved(anchor, root))
        {
            self.drop_shown();
        }
    }

    /// Forget the review and every acknowledgement, and withdraw the approval if one is outstanding
    /// (lock, expiry, cancel).
    pub fn clear(&mut self) {
        self.drop_shown();
    }

    pub fn is_presenting(&self) -> bool {
        self.shown.is_some()
    }
}

impl fmt::Debug for ReviewGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReviewGate")
            .field("presenting", &self.shown.as_ref().map(|shown| shown.digest))
            .field("pending", &self.pending_acknowledgements())
            .finish()
    }
}

// ---------------------------------------------------------------------------------------------
// Signer
// ---------------------------------------------------------------------------------------------

/// The authorization step. Implementations hold key material; this trait has no method that takes
/// bytes to sign.
pub trait Signer {
    /// The public identity this signer signs as.
    fn identity(&self) -> &SignerIdentity;

    /// Authorize `plan` with the single-use `approval`. See the module documentation for the exact
    /// order of checks. Returns signed bytes only after independent verification through
    /// consensus code; on any refusal nothing is returned and no state changes.
    fn authorize(
        &self,
        plan: OperationPlan,
        approval: Approval,
        view: &ChainView<'_>,
    ) -> Result<SignedOperation, Refusal>;
}

/// The default per-slot authority check: every requirement this wallet must satisfy names an address
/// whose CURRENT descriptor, resolved through the wallet book exactly as consensus resolves it, is
/// this signer's. A requirement for a maker's key is never something this wallet can satisfy.
pub(crate) fn check_wallet_requirements(
    plan: &OperationPlan,
    view: &ChainView<'_>,
    identity: &SignerIdentity,
) -> Result<(), Refusal> {
    for requirement in plan.requirements() {
        if requirement.status != RequirementStatus::ThisWallet {
            continue;
        }
        match requirement.signer {
            RequiredSigner::Wallet(address) => view
                .state()
                .wallets
                .authorize(address, identity.descriptor())
                .map_err(|_| Refusal::NotRequiredSigner(requirement.slot))?,
            RequiredSigner::Maker(_) => return Err(Refusal::NotRequiredSigner(requirement.slot)),
        }
    }
    Ok(())
}

/// The one authorization pipeline every signer runs. Crate-internal so a two-key signer (wallet
/// rotation) reuses it with its own [`KeyRing`].
pub(crate) fn run_authorization(
    gate: &SigningGate,
    identity: &SignerIdentity,
    ring: KeyRing<'_>,
    plan: OperationPlan,
    approval: Approval,
    view: &ChainView<'_>,
    now: Instant,
) -> Result<SignedOperation, Refusal> {
    // 1. The gate.
    gate.check(view)?;
    // 3a. The approval was not withdrawn (its gate was cleared or replaced it), is fresh and belongs
    //     to this head. An approval stamped in the future (a manipulated clock) is as unusable as an
    //     old one.
    if approval.withdrawn() {
        return Err(Refusal::ApprovalRevoked);
    }
    match now.checked_duration_since(approval.issued) {
        Some(age) if age <= approval.max_age => {}
        _ => return Err(Refusal::Expired(ExpiryKind::Approval)),
    }
    if approval.anchor != *view.anchor() || approval.state_root != view.state_root() {
        return Err(Refusal::StaleHead {
            reviewed: approval.anchor.height,
            current: view.anchor().height,
        });
    }
    // 4. The signer is the plan's signer and is the current authority on the verified chain.
    if plan.signer() != identity {
        let slot = plan
            .requirements()
            .first()
            .map_or(Slot::Input(0), |requirement| requirement.slot);
        return Err(Refusal::NotRequiredSigner(slot));
    }
    identity.check_current(view)?;
    // 3b. The approval is for exactly this plan: recompute the review from the unsigned bytes and
    //     the CURRENT view (this also re-runs the kind's pre-signing validation).
    let reviewed = crate::review::review(&plan, view)?;
    if approval.kind != plan.kind()
        || approval.digest != reviewed.binding()
        || approval.scope != reviewed.scope()
    {
        return Err(Refusal::PlanChanged);
    }
    // 5. Sign through the kind's handler with kind-selected domains.
    let handler = crate::ops::handler(plan.kind())?;
    // 4b. Every slot this wallet must sign is one this key controls, exactly as consensus resolves
    //     it (a kind that introduces a not-yet-registered key overrides the check).
    handler.check_requirements(&plan, view, identity)?;
    let signer = KindSigner::new(plan.kind(), ring);
    let signed = handler.sign(&plan, &signer, view)?;
    // 6. Independent verification, and the signed bytes are exactly the reviewed bytes.
    if signed.kind() != plan.kind() {
        return Err(Refusal::VerificationFailed(
            "signed result is of another kind",
        ));
    }
    let unsigned: Vec<PlanObject> = handler.unsigned_form(signed.bytes())?;
    if unsigned != handler.reviewed_objects(&plan)? {
        return Err(Refusal::VerificationFailed(
            "signed bytes differ from the reviewed plan",
        ));
    }
    handler.check_signed(&signed, view)?;
    // The metadata the handler attached (identifier, validity, reserved coins) is what the bytes say.
    if !signed.matches(&handler.describe(signed.bytes())?) {
        return Err(Refusal::VerificationFailed(
            "the operation's metadata does not match its bytes",
        ));
    }
    Ok(signed)
}

struct KeyState {
    key: Option<SealedKey>,
    last_activity: Instant,
}

/// A signer that holds one wallet key in memory, sealed (`capability`: no function returns it and
/// it signs only through a typed capability). The key is erased on [`lock`](Self::lock), on
/// idle expiry and on drop. Constructing one needs a [`SigningGate`], which does not exist in a
/// shipping build while production qualification is incomplete.
pub struct KeySigner {
    identity: SignerIdentity,
    gate: SigningGate,
    idle_limit: Duration,
    state: Mutex<KeyState>,
}

impl KeySigner {
    /// A signer for a generation-one wallet key.
    pub fn new_initial(key: HybridKey, gate: SigningGate) -> Result<Self, Refusal> {
        let identity = SignerIdentity::from_public(key.public(), 1, None)?;
        Self::build(key, identity, gate, DEFAULT_IDLE_LIMIT)
    }

    /// A signer for the current key of a rotated authority; `authority` is the generation-one
    /// AddressID taken from verified wallet authority state.
    pub fn new_rotated(
        key: HybridKey,
        generation: u64,
        authority: Hash,
        gate: SigningGate,
    ) -> Result<Self, Refusal> {
        let identity = SignerIdentity::from_public(key.public(), generation, Some(authority))?;
        Self::build(key, identity, gate, DEFAULT_IDLE_LIMIT)
    }

    /// The same with an explicit identity (for example the one `profile::declare` returned) and
    /// idle limit. The key must be the one the identity names. A host may SHORTEN the idle limit,
    /// never lengthen it: anything above [`DEFAULT_IDLE_LIMIT`] is clamped to it (fixes of the
    /// independent wallet review, MINOR-6).
    pub fn with_identity(
        key: HybridKey,
        identity: SignerIdentity,
        gate: SigningGate,
        idle_limit: Duration,
    ) -> Result<Self, Refusal> {
        Self::build(key, identity, gate, idle_limit.min(DEFAULT_IDLE_LIMIT))
    }

    fn build(
        key: HybridKey,
        identity: SignerIdentity,
        gate: SigningGate,
        idle_limit: Duration,
    ) -> Result<Self, Refusal> {
        if key
            .public()
            .descriptor(identity.generation())
            .map_err(|_| Refusal::InvalidDescriptor)?
            != identity.descriptor()
        {
            return Err(Refusal::InvalidDescriptor);
        }
        Ok(Self {
            identity,
            gate,
            idle_limit,
            state: Mutex::new(KeyState {
                key: Some(SealedKey::seal(key)),
                last_activity: Instant::now(),
            }),
        })
    }

    /// Test constructor: a generation-one signer behind the TEST-VALUE gate.
    #[cfg(any(test, feature = "test-value-signing"))]
    pub fn for_test(key: HybridKey) -> Result<Self, Refusal> {
        Self::new_initial(key, SigningGate::test_value()?)
    }

    /// Erase the key now. Every later authorization is `Locked`.
    pub fn lock(&self) {
        self.guard().key = None;
    }

    /// The key state. A poisoned lock (a panic while signing) erases the key and is reported as
    /// locked: fail closed, and the key does not linger in memory (the release profile unwinds).
    fn guard(&self) -> std::sync::MutexGuard<'_, KeyState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                let mut guard = poisoned.into_inner();
                guard.key = None;
                guard
            }
        }
    }

    pub fn is_locked(&self) -> bool {
        let state = self.guard();
        state.key.is_none() || state.last_activity.elapsed() >= self.idle_limit
    }

    /// Record user input. Input at or after the idle limit cannot revive the session.
    pub fn touch(&self) -> Result<(), Refusal> {
        let mut state = self.guard();
        let now = Instant::now();
        if state.key.is_some()
            && now.saturating_duration_since(state.last_activity) >= self.idle_limit
        {
            state.key = None;
        }
        if state.key.is_none() {
            return Err(Refusal::Locked);
        }
        state.last_activity = now;
        Ok(())
    }

    pub fn gate_mode(&self) -> GateMode {
        self.gate.mode()
    }

    /// [`Signer::authorize`] with an explicit clock. Test builds only: a shipping signer always reads
    /// the real monotonic clock itself, so a host cannot move time to keep an approval alive.
    #[cfg(any(test, feature = "test-value-signing"))]
    pub fn authorize_at(
        &self,
        plan: OperationPlan,
        approval: Approval,
        view: &ChainView<'_>,
        now: Instant,
    ) -> Result<SignedOperation, Refusal> {
        self.authorize_with(plan, approval, view, now)
    }

    fn authorize_with(
        &self,
        plan: OperationPlan,
        approval: Approval,
        view: &ChainView<'_>,
        now: Instant,
    ) -> Result<SignedOperation, Refusal> {
        // A poisoned lock erases the key and is treated as locked: fail closed.
        let mut state = self.guard();
        if state.key.is_some()
            && now.saturating_duration_since(state.last_activity) >= self.idle_limit
        {
            state.key = None;
        }
        let KeyState { key, last_activity } = &mut *state;
        let key = key.as_ref().ok_or(Refusal::Locked)?;
        let result = run_authorization(
            &self.gate,
            &self.identity,
            KeyRing::single(key),
            plan,
            approval,
            view,
            now,
        );
        if result.is_ok() {
            *last_activity = now;
        }
        result
    }
}

impl Signer for KeySigner {
    fn identity(&self) -> &SignerIdentity {
        &self.identity
    }

    fn authorize(
        &self,
        plan: OperationPlan,
        approval: Approval,
        view: &ChainView<'_>,
    ) -> Result<SignedOperation, Refusal> {
        self.authorize_with(plan, approval, view, Instant::now())
    }
}

impl fmt::Debug for KeySigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeySigner")
            .field("identity", &self.identity)
            .field("gate", &self.gate.mode())
            .field("locked", &self.is_locked())
            .field("key", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_selection_is_total_and_exact() {
        use OperationKind as K;
        use Purpose as P;
        let mut permitted = 0;
        for kind in K::ALL {
            for purpose in [
                P::Spend,
                P::BondAction,
                P::RotateAuthorization,
                P::RotatePossession,
                P::MakerOffer,
                P::MakerFill,
                P::WorkerAssignment,
            ] {
                match domain_for(kind, purpose) {
                    Ok(domain) => {
                        permitted += 1;
                        let expected = match (kind, purpose) {
                            (K::WorkerAssignment, P::WorkerAssignment) => Domain::MinerEnrollment,
                            (K::MakerOffer, P::MakerOffer) => Domain::TradeOffer,
                            (K::LicenseDvp | K::HashLock | K::FiatLock, P::MakerFill) => {
                                Domain::TradeFill
                            }
                            (K::WalletRotation, P::RotateAuthorization) => Domain::WalletRotate,
                            (K::WalletRotation, P::RotatePossession) => {
                                Domain::WalletRotatePossession
                            }
                            (K::BondCreate, P::BondAction) => Domain::BondCreate,
                            (K::BondUnbond, P::BondAction) => Domain::BondUnbond,
                            (K::BondWithdraw, P::BondAction) => Domain::BondWithdraw,
                            (_, P::Spend) => Domain::Transaction,
                            other => panic!("unexpected permitted pair {other:?}"),
                        };
                        assert_eq!(domain, expected);
                    }
                    Err(refusal) => {
                        assert_eq!(refusal, Refusal::DomainNotPermitted { kind, purpose })
                    }
                }
            }
        }
        // 12 spend kinds (a bond creation spends the coins of its same-block funding output) +
        // 2 rotation proofs + 3 bond actions.
        assert_eq!(permitted, 22);
        // No operation may ever sign in a transport or node domain.
        for kind in K::ALL {
            for purpose in [
                P::Spend,
                P::BondAction,
                P::RotateAuthorization,
                P::RotatePossession,
                P::MakerOffer,
                P::MakerFill,
                P::WorkerAssignment,
            ] {
                if let Ok(domain) = domain_for(kind, purpose) {
                    assert!(!matches!(
                        domain,
                        Domain::TransportInitiator
                            | Domain::TransportResponder
                            | Domain::NodeWork
                            | Domain::ReleaseApproval
                    ));
                }
            }
        }
    }

    fn view_of<'a>(
        state: &'a mutiny_consensus_v8::execution::State,
        reserved: &'a BTreeSet<OutPoint>,
    ) -> ChainView<'a> {
        let anchor = FinalizedAnchor {
            network: mutiny_consensus_v8::NETWORK_ID,
            genesis: [1; 32],
            fingerprint: [2; 32],
            height: 5,
            block: [3; 32],
        };
        ChainView::new(
            crate::context::HeadInfo::new(anchor, 1000, 1000, [9; 32]).unwrap(),
            state,
            reserved,
        )
    }

    #[test]
    fn high_risk_reviews_need_a_typed_confirmation_phrase() {
        let state = mutiny_consensus_v8::execution::State::default();
        let reserved = BTreeSet::new();
        let view = view_of(&state, &reserved);
        let objects = [PlanObject::new("x", vec![1])];
        let review = Review::seal(crate::review::testing::sample_draft(true), &objects, &view);
        assert!(
            review.acknowledgements().is_empty(),
            "only the phrase stands between this review and approval"
        );
        assert!(review.requires_phrase());
        let phrase = review
            .confirmation_phrase()
            .expect("a high-risk review has a phrase");
        assert!(
            phrase.starts_with("CONFIRM ") && phrase.len() == "CONFIRM ".len() + 8,
            "{phrase}"
        );
        assert!(
            review
                .render_text()
                .contains(&format!("Type to confirm: {phrase}"))
        );
        // The phrase belongs to this review: another binding digest gives another phrase.
        let other = Review::seal(
            crate::review::testing::sample_draft(true),
            &[PlanObject::new("x", vec![2])],
            &view,
        );
        assert_ne!(other.confirmation_phrase(), review.confirmation_phrase());

        let mut gate = ReviewGate::new();
        assert_eq!(
            gate.confirm_phrase(&phrase).unwrap_err(),
            Refusal::NotPresented
        );
        gate.present(&review, &view);
        assert_eq!(
            gate.approve(&view).unwrap_err(),
            Refusal::ConfirmationPhraseMissing
        );
        assert!(!gate.is_ready(&view));
        assert_eq!(
            gate.confirm_phrase("CONFIRM 00000000").unwrap_err(),
            Refusal::ConfirmationPhraseMismatch
        );
        assert_eq!(
            gate.confirm_phrase("").unwrap_err(),
            Refusal::ConfirmationPhraseMismatch
        );
        assert!(!gate.is_ready(&view));
        // Case and spacing do not matter.
        gate.confirm_phrase(&format!(
            "  {}  ",
            phrase.to_ascii_lowercase().replace(' ', "   ")
        ))
        .unwrap();
        assert!(gate.is_ready(&view));
        assert!(gate.approve(&view).is_ok());

        // A review that asks for no phrase refuses one.
        let plain = Review::seal(crate::review::testing::sample_draft(false), &objects, &view);
        assert!(plain.confirmation_phrase().is_none() && !plain.requires_phrase());
        gate.present(&plain, &view);
        assert_eq!(
            gate.confirm_phrase("CONFIRM 00000000").unwrap_err(),
            Refusal::ConfirmationPhraseMismatch
        );
        assert!(
            gate.approve(&view).is_ok(),
            "no phrase and no acknowledgement required"
        );
    }

    #[test]
    fn shipping_gate_is_closed_while_production_is_unqualified() {
        if !mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED {
            assert_eq!(SigningGate::production().unwrap_err(), Refusal::GateClosed);
        }
        const {
            assert!(
                TEST_VALUE_SIGNING_ENABLED,
                "this unit-test build contains the test gate"
            )
        };
    }
}
