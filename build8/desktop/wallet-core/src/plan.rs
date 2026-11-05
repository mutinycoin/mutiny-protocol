//! Operation kinds, requests, immutable plans, the planner trait and the plan state machine.
//!
//! FROZEN INTERFACE (phase 1). Later phases add `ops/<kind>.rs` files and register them in
//! `ops/mod.rs`; they do not change the types here, except that each phase owns the field set of
//! its own `*Request` struct (every request struct is `#[non_exhaustive]`, so adding a field is not
//! a breaking change for outside crates).
//!
//! ```text
//!   OperationRequest --plan()--> OperationPlan --review()--> Review --ReviewGate--> Approval
//!                                      \                                               |
//!                                       `------------- Signer::authorize(plan, approval, view)
//!                                                                  |
//!                                                          SignedOperation --Outbox--> export
//! ```
//!
//! An [`OperationPlan`] is immutable and is built only by an operation handler. It holds the
//! UNSIGNED bytes of every object that will be signed. Its review is a pure function of those
//! bytes and the [`ChainView`]; it is never assembled by hand.
use crate::{
    authorize::{Approval, ReviewGate, SignedOperation, Signer, SignerIdentity},
    capability::KindSigner,
    context::ChainView,
    outbox::{OutboxRecord, Settlement},
    refusal::Refusal,
    review::{AckKind, Review, ReviewDraft},
    secret::Preimage,
    units,
};
use mutiny_consensus_v8::{Hash, anchors::FinalizedAnchor, domain_hash, transactions::OutPoint};
use std::fmt;

// ---------------------------------------------------------------------------------------------
// Kinds
// ---------------------------------------------------------------------------------------------

/// Every kind of operation the wallet is meant to construct, review and authorize. The numeric
/// code is part of the frozen interface (it is bound into the review digest).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OperationKind {
    /// (a) Ordinary MUT payment with fee and change.
    Payment,
    /// (f) Native wallet-authority rotation, funded in the same transaction.
    WalletRotation,
    /// (c) Dividend claim (partial claims, per-award sequence).
    DividendClaim,
    /// (b) License purchase or transfer through the approved delivery-versus-payment path.
    LicenseDvp,
    /// (d) Conditional MUT funding: hash lock.
    HashLock,
    /// (d) Claim of a hash lock with the preimage.
    ConditionalClaim,
    /// (d) Refund of a hash lock at or after its refund height.
    ConditionalRefund,
    /// (d) Fiat-settled lock (no unilateral exit).
    FiatLock,
    /// (d) Release of a fiat lock to the buyer.
    FiatRelease,
    /// (e) Bond creation.
    BondCreate,
    /// (e) Start of a bond's notice period.
    BondUnbond,
    /// (e) Withdrawal of a bond after the locked timing rules.
    BondWithdraw,
    /// (f) Treasury destination rotation (`TreasuryRotate`).
    TreasuryRotate,
    /// (f) Treasury offer-freeze authorization.
    TreasuryFreezeOffer,
    /// Wallet-local maker offer; exported to a counterparty, never a block operation.
    MakerOffer,
    /// Existing kind-10 owner/Worker assignment, including post-sale assignment.
    WorkerAssignment,
}

impl OperationKind {
    /// All kinds, in code order.
    pub const ALL: [OperationKind; 16] = [
        Self::Payment,
        Self::WalletRotation,
        Self::DividendClaim,
        Self::LicenseDvp,
        Self::HashLock,
        Self::ConditionalClaim,
        Self::ConditionalRefund,
        Self::FiatLock,
        Self::FiatRelease,
        Self::BondCreate,
        Self::BondUnbond,
        Self::BondWithdraw,
        Self::TreasuryRotate,
        Self::TreasuryFreezeOffer,
        Self::MakerOffer,
        Self::WorkerAssignment,
    ];

    /// Stable numeric code. Never reused.
    pub const fn code(self) -> u16 {
        match self {
            Self::Payment => 1,
            Self::WalletRotation => 2,
            Self::DividendClaim => 3,
            Self::LicenseDvp => 4,
            Self::HashLock => 5,
            Self::ConditionalClaim => 6,
            Self::ConditionalRefund => 7,
            Self::FiatLock => 8,
            Self::FiatRelease => 9,
            Self::BondCreate => 10,
            Self::BondUnbond => 11,
            Self::BondWithdraw => 12,
            Self::TreasuryRotate => 13,
            Self::TreasuryFreezeOffer => 14,
            Self::MakerOffer => 15,
            Self::WorkerAssignment => 16,
        }
    }

    pub fn from_code(code: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.code() == code)
    }

    /// Stable lowercase name for logs and file names.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Payment => "payment",
            Self::WalletRotation => "wallet-rotation",
            Self::DividendClaim => "dividend-claim",
            Self::LicenseDvp => "license-dvp",
            Self::HashLock => "hash-lock",
            Self::ConditionalClaim => "conditional-claim",
            Self::ConditionalRefund => "conditional-refund",
            Self::FiatLock => "fiat-lock",
            Self::FiatRelease => "fiat-release",
            Self::BondCreate => "bond-create",
            Self::BondUnbond => "bond-unbond",
            Self::BondWithdraw => "bond-withdraw",
            Self::TreasuryRotate => "treasury-rotate",
            Self::TreasuryFreezeOffer => "treasury-freeze-offer",
            Self::MakerOffer => "maker-offer",
            Self::WorkerAssignment => "worker-assignment",
        }
    }

    /// Human title.
    pub const fn title(self) -> &'static str {
        match self {
            Self::Payment => "MUT payment",
            Self::WalletRotation => "Wallet key rotation",
            Self::DividendClaim => "Dividend claim",
            Self::LicenseDvp => "License purchase or transfer",
            Self::HashLock => "Conditional MUT funding (hash lock)",
            Self::ConditionalClaim => "Claim of a hash lock",
            Self::ConditionalRefund => "Refund of a hash lock",
            Self::FiatLock => "Fiat-settled lock",
            Self::FiatRelease => "Release of a fiat lock",
            Self::BondCreate => "Bond creation",
            Self::BondUnbond => "Bond unbonding",
            Self::BondWithdraw => "Bond withdrawal",
            Self::TreasuryRotate => "Treasury destination rotation",
            Self::TreasuryFreezeOffer => "Treasury offer-freeze authorization",
            Self::MakerOffer => "Create maker offer",
            Self::WorkerAssignment => "Assign fresh Worker to License",
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Authorization requirements
// ---------------------------------------------------------------------------------------------

/// A signature position inside an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Slot {
    /// The signature of a transaction input (payments, rotation funding).
    Input(u32),
    /// An approval slot of a trading operation (0 = first party, 1 = second party).
    Approval(u8),
    /// The maker's offer signature.
    OfferSignature,
    /// The maker's fill signature over the exact operation body.
    FillSignature,
    /// The current key's authorization of a wallet rotation.
    RotationAuthorization,
    /// The new key's possession proof of a wallet rotation.
    RotationPossession,
    /// The owner's signature of a dividend claim.
    Claim,
    /// The owner's signature of a bond operation.
    BondOwner,
    /// The Treasury wallet's signature over an offer freeze.
    TreasuryFreeze,
    /// Current License owner authorization of the exact Worker possession binding.
    AssignmentOwner,
}

impl fmt::Display for Slot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(index) => write!(f, "input {index}"),
            Self::Approval(slot) => write!(f, "approval slot {slot}"),
            Self::OfferSignature => f.write_str("the maker's offer signature"),
            Self::FillSignature => f.write_str("the maker's fill signature"),
            Self::RotationAuthorization => f.write_str("the rotation authorization (current key)"),
            Self::RotationPossession => f.write_str("the rotation possession proof (new key)"),
            Self::Claim => f.write_str("the claim signature"),
            Self::BondOwner => f.write_str("the bond owner signature"),
            Self::TreasuryFreeze => f.write_str("the Treasury offer-freeze signature"),
            Self::AssignmentOwner => f.write_str("the fresh Worker assignment owner signature"),
        }
    }
}

/// Who must produce a signature.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RequiredSigner {
    /// The wallet key that currently controls this AddressID.
    Wallet(Hash),
    /// The maker's trade identity (`Role::Transport`); imported and verified, never created here.
    Maker(Hash),
}

impl fmt::Debug for RequiredSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wallet(address) => write!(f, "Wallet({})", units::short_hex(address)),
            Self::Maker(identity) => write!(f, "Maker({})", units::short_hex(identity)),
        }
    }
}

/// Whether a required signature is present.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequirementStatus {
    /// This wallet will provide it.
    ThisWallet,
    /// Another wallet must provide it (a counterparty).
    Counterparty,
    /// The maker must provide it.
    Maker,
    /// Already present and verified.
    Provided,
}

/// One required authorization of an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Requirement {
    pub slot: Slot,
    pub signer: RequiredSigner,
    pub status: RequirementStatus,
}

// ---------------------------------------------------------------------------------------------
// Plan data
// ---------------------------------------------------------------------------------------------

/// Opaque bytes that came from outside (an imported offer, a descriptor, a prepared object).
/// Its `Debug` output shows only the length and the ends, never the whole content.
#[derive(Clone, PartialEq, Eq)]
pub struct Blob(Vec<u8>);

impl Blob {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Vec<u8>> for Blob {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Blob {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for Blob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Blob({} bytes, {})",
            self.0.len(),
            units::short_hex(&self.0)
        )
    }
}

/// The unsigned bytes of one object that will be signed, with a short fixed label.
///
/// The bytes are NOT zeroized on drop. A conditional claim's plan holds the hash-lock preimage in
/// clear, but so do the signed claim, its outbox record and the consensus structures that decode it,
/// a plan is `Clone`, and the claim publishes the preimage at inclusion: wiping this one copy would
/// protect nothing (phase 8 documented the limit instead; the preimage's own `secret::Preimage` is
/// zeroized). A host keeps plans as protected as its preimage store until the claim is included.
#[derive(Clone, PartialEq, Eq)]
pub struct PlanObject {
    pub label: &'static str,
    pub bytes: Vec<u8>,
}

impl PlanObject {
    pub fn new(label: &'static str, bytes: Vec<u8>) -> Self {
        Self { label, bytes }
    }
}

impl fmt::Debug for PlanObject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PlanObject({}, {} bytes, {})",
            self.label,
            self.bytes.len(),
            units::short_hex(&self.bytes)
        )
    }
}

/// When an operation may be included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Validity {
    /// First height at which it is valid.
    pub created: u64,
    /// Last height at which it is valid.
    pub expiry: u64,
    /// Valid only when included at exactly this height, for formats that require one height.
    pub valid_only_at: Option<u64>,
    /// Bound to one immediate parent block, for formats without a historical reference window.
    pub bound_to_parent: bool,
}

/// An immutable operation plan: what will be signed, by whom, valid when, built against which
/// verified head. Only operation handlers construct one.
#[derive(Clone, PartialEq, Eq)]
pub struct OperationPlan {
    kind: OperationKind,
    schema: u16,
    signer: SignerIdentity,
    objects: Vec<PlanObject>,
    requirements: Vec<Requirement>,
    inputs: Vec<OutPoint>,
    validity: Validity,
    anchor: FinalizedAnchor,
    state_root: Hash,
}

impl OperationPlan {
    /// Assemble a plan. Crate-internal: a plan can only come from a handler, which has validated
    /// every field against the view it was built from.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn assemble(
        kind: OperationKind,
        schema: u16,
        signer: SignerIdentity,
        objects: Vec<PlanObject>,
        requirements: Vec<Requirement>,
        mut inputs: Vec<OutPoint>,
        validity: Validity,
        view: &ChainView<'_>,
    ) -> Self {
        inputs.sort();
        inputs.dedup();
        Self {
            kind,
            schema,
            signer,
            objects,
            requirements,
            inputs,
            validity,
            anchor: view.anchor().clone(),
            state_root: view.state_root(),
        }
    }
    pub fn kind(&self) -> OperationKind {
        self.kind
    }
    /// Layout version of this kind's objects; bound into the review digest.
    pub fn schema(&self) -> u16 {
        self.schema
    }
    /// The public identity of the wallet that will sign.
    pub fn signer(&self) -> &SignerIdentity {
        &self.signer
    }
    /// The unsigned bytes of every object that will be signed.
    pub fn objects(&self) -> &[PlanObject] {
        &self.objects
    }
    pub fn requirements(&self) -> &[Requirement] {
        &self.requirements
    }
    /// Coins this plan consumes (sorted); the outbox reserves them.
    pub fn inputs(&self) -> &[OutPoint] {
        &self.inputs
    }
    pub fn validity(&self) -> &Validity {
        &self.validity
    }
    /// The verified head the plan was built against.
    pub fn anchor(&self) -> &FinalizedAnchor {
        &self.anchor
    }
    pub fn state_root(&self) -> Hash {
        self.state_root
    }
    /// A stable identifier of this exact content (kind and unsigned bytes).
    pub fn id(&self) -> Hash {
        let mut body = self.kind.code().to_be_bytes().to_vec();
        for object in &self.objects {
            body.push(object.label.len() as u8);
            body.extend_from_slice(object.label.as_bytes());
            body.extend_from_slice(&(object.bytes.len() as u32).to_be_bytes());
            body.extend_from_slice(&object.bytes);
        }
        domain_hash(b"MUTINY-BUILD8-WALLET-PLAN-ID-V1", &body)
    }
}

impl fmt::Debug for OperationPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperationPlan")
            .field("kind", &self.kind)
            .field("id", &units::short_hex(&self.id()))
            .field("objects", &self.objects.len())
            .field("inputs", &self.inputs.len())
            .field("validity", &self.validity)
            .field("planned_at_height", &self.anchor.height)
            .finish()
    }
}

// ---------------------------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------------------------

/// Default `validity_blocks` of a built operation (about two and a half hours at the target
/// interval; the figure is a wallet policy, not a protocol rule).
///
/// Every request's `validity_blocks = N` means: valid in the NEXT block and in the N blocks after
/// it, N + 1 blocks in all; the expiry is next + N, and consensus admits an operation while
/// created <= height <= expiry. N is 1 to 10,080, the protocol's bound on expiry - created (so at
/// most 10,081 blocks); a kind may end the window earlier (an offer's expiry, a hash lock's refund
/// height, a single-block operation).
pub const DEFAULT_VALIDITY_BLOCKS: u64 = 144;

/// How a request field is shown in `Debug` output: compact, and never a secret.
trait ShowField {
    fn show(&self) -> String;
}

impl ShowField for u64 {
    fn show(&self) -> String {
        self.to_string()
    }
}

impl ShowField for bool {
    fn show(&self) -> String {
        self.to_string()
    }
}

impl ShowField for Hash {
    fn show(&self) -> String {
        units::short_hex(self)
    }
}

impl ShowField for Option<Hash> {
    fn show(&self) -> String {
        self.map_or_else(
            || "None".to_string(),
            |hash| format!("Some({})", units::short_hex(&hash)),
        )
    }
}

impl ShowField for Option<u64> {
    fn show(&self) -> String {
        self.map_or_else(|| "None".to_string(), |value| format!("Some({value})"))
    }
}

impl ShowField for Blob {
    fn show(&self) -> String {
        format!("{self:?}")
    }
}

impl ShowField for FeeSource {
    fn show(&self) -> String {
        format!("{self:?}")
    }
}

impl ShowField for Preimage {
    fn show(&self) -> String {
        format!("{self:?}")
    }
}

impl ShowField for CancelTarget {
    fn show(&self) -> String {
        format!("{self:?}")
    }
}

macro_rules! request {
    ($(#[$meta:meta])* $name:ident { $($(#[$fmeta:meta])* $field:ident : $ty:ty),* $(,)? }) => {
        $(#[$meta])*
        #[non_exhaustive]
        pub struct $name { $($(#[$fmeta])* pub $field: $ty),* }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name))
                    $(.field(stringify!($field), &format_args!("{}", ShowField::show(&self.$field))))*
                    .finish()
            }
        }
    };
}

request! {
    /// (a) Pay MUT to an address. The wallet selects coins, computes the minimal fee and returns
    /// the change to its own current address.
    PaymentRequest {
        /// Recipient AddressID.
        recipient: Hash,
        /// Atoms (STRIKES) to send; positive.
        amount_atoms: u64,
        /// Valid in the next block and the `validity_blocks` after it (N + 1 blocks, expiry =
        /// next + N; see [`DEFAULT_VALIDITY_BLOCKS`]).
        validity_blocks: u64,
    }
}

impl PaymentRequest {
    pub fn new(recipient: Hash, amount_atoms: u64) -> Self {
        Self {
            recipient,
            amount_atoms,
            validity_blocks: DEFAULT_VALIDITY_BLOCKS,
        }
    }
    pub fn with_validity_blocks(mut self, blocks: u64) -> Self {
        self.validity_blocks = blocks;
        self
    }
}

/// Who pays the fee of a funded rotation.
#[derive(Debug)]
#[non_exhaustive]
pub enum FeeSource {
    /// Coins of the rotating authority itself (spent by the NEW key).
    RotatingAuthority,
    /// Coins of a different wallet, which signs its own inputs.
    OtherWallet(SignerIdentity),
}

request! {
    /// (f) Rotate a wallet authority to a new key, funded in the same transaction. Phase 2.
    RotationRequest {
        /// Public descriptor of the proposed key (generation = current + 1).
        proposed_descriptor: Blob,
        fee_source: FeeSource,
        /// The new phrase was restored from its backup and verified before this rotation.
        new_key_restore_verified: bool,
        validity_blocks: u64,
        /// The fingerprint (`ops::rotation::descriptor_fingerprint`) of the descriptor that the
        /// host's clean restore of the new phrase produced. Planning refuses unless
        /// `new_key_restore_verified` is set and this is the proposed descriptor's own fingerprint.
        restore_verified_fingerprint: Option<Hash>,
    }
}

impl RotationRequest {
    pub fn new(proposed_descriptor: Blob, fee_source: FeeSource) -> Self {
        Self {
            proposed_descriptor,
            fee_source,
            new_key_restore_verified: false,
            validity_blocks: DEFAULT_VALIDITY_BLOCKS,
            restore_verified_fingerprint: None,
        }
    }
    /// Record the host's statement that a clean restore of the new phrase produced the descriptor
    /// whose fingerprint (`ops::rotation::descriptor_fingerprint`) is `fingerprint`. The restore
    /// itself is the host's job; this crate requires and records the evidence.
    pub fn with_restore_verified(mut self, fingerprint: Hash) -> Self {
        self.new_key_restore_verified = true;
        self.restore_verified_fingerprint = Some(fingerprint);
        self
    }
    pub fn with_validity_blocks(mut self, blocks: u64) -> Self {
        self.validity_blocks = blocks;
        self
    }
}

request! {
    /// (c) Claim part or all of a License's dividend entitlement. Phase 3. The claim sequence is
    /// always derived from verified state, never supplied.
    DividendClaimRequest {
        license: Hash,
        award_epoch: u64,
        amount_atoms: u64,
        /// Where the Treasury pays the claim. Irreversible once included.
        destination: Hash,
        validity_blocks: u64,
    }
}

impl DividendClaimRequest {
    pub fn new(license: Hash, award_epoch: u64, amount_atoms: u64, destination: Hash) -> Self {
        Self {
            license,
            award_epoch,
            amount_atoms,
            destination,
            validity_blocks: DEFAULT_VALIDITY_BLOCKS,
        }
    }
    /// The claim stays valid in the next block and the `blocks` after it (N + 1 blocks; N at most
    /// the protocol's 10,080).
    pub fn with_validity_blocks(mut self, blocks: u64) -> Self {
        self.validity_blocks = blocks;
        self
    }
}

request! {
    /// (b) Buy a License through the approved DvP path. Phase 5B. The offer and the maker's proof
    /// are imported and verified, never created here.
    LicenseDvpRequest {
        /// The imported signed offer.
        offer: Blob,
        license: Hash,
        /// Defaults to the seller's address; any other value is flagged in the review.
        payment_destination: Option<Hash>,
        /// Must stay `None` (Order W22): a License sale is valid in exactly ONE block
        /// (`Validity::valid_only_at`), and a request that sets a window is refused with
        /// `VALIDITY_WINDOW_UNSUPPORTED` until the signed validity windows of P4 exist (stage 2). It is
        /// never silently ignored.
        validity_blocks: Option<u64>,
        /// Opaque TradeID commitment (Q8). Consensus refuses a License sale whose TradeID is zero.
        trade: Hash,
        /// Opaque ContractHash commitment (Q8). Consensus refuses a License sale whose
        /// ContractHash is zero.
        contract: Hash,
        /// The seller's CURRENT public wallet descriptor. Empty (the default) means "read it from
        /// the verified wallet book"; it is needed only when the book cannot name it (an
        /// unregistered generation-one seller address). Public data, checked against the book.
        seller_descriptor: Blob,
    }
}

impl LicenseDvpRequest {
    pub fn new(offer: Blob, license: Hash) -> Self {
        Self {
            offer,
            license,
            payment_destination: None,
            validity_blocks: None,
            trade: [0; 32],
            contract: [0; 32],
            seller_descriptor: Blob::new(Vec::new()),
        }
    }
    /// Pay the price to `destination` instead of the seller's own address (the seller signs this
    /// destination; the review flags any value other than the seller's address).
    pub fn with_payment_destination(mut self, destination: Hash) -> Self {
        self.payment_destination = Some(destination);
        self
    }
    /// The opaque TradeID and ContractHash of the agreed trade (Q8).
    pub fn with_commitments(mut self, trade: Hash, contract: Hash) -> Self {
        self.trade = trade;
        self.contract = contract;
        self
    }
    /// The seller's current public descriptor, for a seller the wallet book cannot name.
    pub fn with_seller_descriptor(mut self, descriptor: Blob) -> Self {
        self.seller_descriptor = descriptor;
        self
    }
}

request! {
    /// (d) Lock MUT to a hash condition and a refund height. Phase 5A.
    HashLockRequest {
        /// The maker's signed offer as imported (Q7: never created here): the canonical container
        /// of `offers::encode_offer` or the zero-fill `trading_v1::OfferProof` encoding. The maker
        /// signs the fill only once the operation exists; see `ops::conditional::complete`.
        offer: Blob,
        recipient: Hash,
        amount_atoms: u64,
        /// `SHA-256(preimage)`.
        condition: Hash,
        refund_height: u64,
        /// Opaque TradeID and ContractHash commitments (Q8): shown as opaque, never interpreted.
        trade: Hash,
        contract: Hash,
        validity_blocks: u64,
        /// The trade's authorized generation (`Meta::generation`, at least 1). A claim or refund of
        /// the lock repeats it.
        generation: u64,
        /// Which address of this wallet funds the lock and receives its change (every input must be
        /// a coin of exactly this address). `None` picks one: the current-generation address first,
        /// then the others by spendable value.
        sender: Option<Hash>,
    }
}

impl HashLockRequest {
    pub fn new(
        offer: Blob,
        recipient: Hash,
        amount_atoms: u64,
        condition: Hash,
        refund_height: u64,
    ) -> Self {
        Self {
            offer,
            recipient,
            amount_atoms,
            condition,
            refund_height,
            trade: [0; 32],
            contract: [0; 32],
            validity_blocks: DEFAULT_VALIDITY_BLOCKS,
            generation: 1,
            sender: None,
        }
    }
    pub fn with_trade(mut self, trade: Hash) -> Self {
        self.trade = trade;
        self
    }
    pub fn with_contract(mut self, contract: Hash) -> Self {
        self.contract = contract;
        self
    }
    pub fn with_generation(mut self, generation: u64) -> Self {
        self.generation = generation;
        self
    }
    pub fn with_validity_blocks(mut self, blocks: u64) -> Self {
        self.validity_blocks = blocks;
        self
    }
    pub fn with_sender(mut self, sender: Hash) -> Self {
        self.sender = Some(sender);
        self
    }
}

request! {
    /// (d) Claim a hash lock with its preimage. Phase 5A. Revealing the preimage is irreversible.
    ClaimRequest {
        /// Identifier of the lock output.
        lock: Hash,
        preimage: Preimage,
        validity_blocks: u64,
    }
}

impl ClaimRequest {
    pub fn new(lock: Hash, preimage: Preimage) -> Self {
        Self {
            lock,
            preimage,
            validity_blocks: DEFAULT_VALIDITY_BLOCKS,
        }
    }
    pub fn with_validity_blocks(mut self, blocks: u64) -> Self {
        self.validity_blocks = blocks;
        self
    }
}

request! {
    /// (d) Refund a hash lock at or after its refund height. Phase 5A. The only cancellation the
    /// protocol permits.
    RefundRequest {
        lock: Hash,
        validity_blocks: u64,
    }
}

impl RefundRequest {
    pub fn new(lock: Hash) -> Self {
        Self {
            lock,
            validity_blocks: DEFAULT_VALIDITY_BLOCKS,
        }
    }
    pub fn with_validity_blocks(mut self, blocks: u64) -> Self {
        self.validity_blocks = blocks;
        self
    }
}

request! {
    /// (d) Fiat-settled lock. Phase 5B.
    FiatLockRequest {
        offer: Blob,
        buyer: Hash,
        amount_atoms: u64,
        /// Opaque payment-terms commitment.
        payment_terms: Hash,
        trade: Hash,
        contract: Hash,
        validity_blocks: u64,
        /// The buyer's CURRENT public wallet descriptor. Empty (the default) means "read it from
        /// the verified wallet book"; needed only for an unregistered generation-one buyer.
        buyer_descriptor: Blob,
    }
}

impl FiatLockRequest {
    pub fn new(offer: Blob, buyer: Hash, amount_atoms: u64, payment_terms: Hash) -> Self {
        Self {
            offer,
            buyer,
            amount_atoms,
            payment_terms,
            trade: [0; 32],
            contract: [0; 32],
            validity_blocks: DEFAULT_VALIDITY_BLOCKS,
            buyer_descriptor: Blob::new(Vec::new()),
        }
    }
    /// The opaque TradeID and ContractHash of the agreed trade (Q8).
    pub fn with_commitments(mut self, trade: Hash, contract: Hash) -> Self {
        self.trade = trade;
        self.contract = contract;
        self
    }
    /// The lock stays valid in the next block and the `blocks` after it (N + 1 blocks, never
    /// beyond the offer's expiry).
    pub fn with_validity_blocks(mut self, blocks: u64) -> Self {
        self.validity_blocks = blocks;
        self
    }
    /// The buyer's current public descriptor, for a buyer the wallet book cannot name.
    pub fn with_buyer_descriptor(mut self, descriptor: Blob) -> Self {
        self.buyer_descriptor = descriptor;
        self
    }
}

request! {
    /// (d) Release a fiat lock to the buyer. Phase 5B.
    FiatReleaseRequest {
        lock: Hash,
        validity_blocks: u64,
        /// The seller's CURRENT public wallet descriptor. Empty (the default) means "read it from
        /// the verified wallet book"; needed only for an unregistered generation-one seller.
        seller_descriptor: Blob,
    }
}

impl FiatReleaseRequest {
    pub fn new(lock: Hash) -> Self {
        Self {
            lock,
            validity_blocks: DEFAULT_VALIDITY_BLOCKS,
            seller_descriptor: Blob::new(Vec::new()),
        }
    }
    /// The release stays valid in the next block and the `blocks` after it (N + 1 blocks).
    pub fn with_validity_blocks(mut self, blocks: u64) -> Self {
        self.validity_blocks = blocks;
        self
    }
    /// The seller's current public descriptor, for a seller the wallet book cannot name.
    pub fn with_seller_descriptor(mut self, descriptor: Blob) -> Self {
        self.seller_descriptor = descriptor;
        self
    }
}

request! {
    /// (e) Create a bond for a node this wallet owns. Phase 4.
    BondCreateRequest {
        node: Hash,
        node_generation: u64,
        amount_atoms: u64,
        /// Fresh nonce that derives the lot identifier.
        nonce: Hash,
        /// Number of additional inclusion heights after the next height (1..=10,080).
        validity_blocks: u64,
    }
}

impl BondCreateRequest {
    pub fn new(node: Hash, node_generation: u64, amount_atoms: u64, nonce: Hash) -> Self {
        Self {
            node,
            node_generation,
            amount_atoms,
            nonce,
            validity_blocks: DEFAULT_VALIDITY_BLOCKS,
        }
    }
    pub fn with_validity_blocks(mut self, blocks: u64) -> Self {
        self.validity_blocks = blocks;
        self
    }
}

request! {
    /// (e) Start the notice period of a bond. Phase 4. Irreversible.
    BondUnbondRequest {
        lot: Hash,
        validity_blocks: u64,
    }
}

impl BondUnbondRequest {
    pub fn new(lot: Hash) -> Self {
        Self {
            lot,
            validity_blocks: DEFAULT_VALIDITY_BLOCKS,
        }
    }
    pub fn with_validity_blocks(mut self, blocks: u64) -> Self {
        self.validity_blocks = blocks;
        self
    }
}

request! {
    /// (e) Withdraw a bond after the locked timing rules. Phase 4.
    BondWithdrawRequest {
        lot: Hash,
        validity_blocks: u64,
    }
}

impl BondWithdrawRequest {
    pub fn new(lot: Hash) -> Self {
        Self {
            lot,
            validity_blocks: DEFAULT_VALIDITY_BLOCKS,
        }
    }
    pub fn with_validity_blocks(mut self, blocks: u64) -> Self {
        self.validity_blocks = blocks;
        self
    }
}

request! {
    /// (f) Rotate the Treasury destination generation. Phase 6; Treasury profile only.
    TreasuryRotateRequest {
        /// Public descriptor of the NEW destination wallet. Its address must already resolve to
        /// exactly this descriptor in the verified wallet book (the new wallet authority generation
        /// must already exist) and must never have been a destination of this Treasury.
        new_descriptor: Blob,
        new_key_restore_verified: bool,
        restore_verified_fingerprint: Option<Hash>,
        restore_authority: Option<Hash>,
        validity_blocks: u64,
        /// The trading TreasuryID (`trading_v1` record tag 3) to rotate. `None` picks the one
        /// trading Treasury of the verified state whose ACTIVE destination this wallet controls, and
        /// refuses when there is none or more than one.
        treasury: Option<Hash>,
    }
}

impl TreasuryRotateRequest {
    pub fn new(new_descriptor: Blob) -> Self {
        Self {
            new_descriptor,
            new_key_restore_verified: false,
            restore_verified_fingerprint: None,
            restore_authority: None,
            validity_blocks: DEFAULT_VALIDITY_BLOCKS,
            treasury: None,
        }
    }
    /// Non-secret host assertion from a clean backup rehearsal; not verified by consensus.
    pub fn with_verified_restore(mut self, authority: Hash, fingerprint: Hash) -> Self {
        self.new_key_restore_verified = true;
        self.restore_authority = Some(authority);
        self.restore_verified_fingerprint = Some(fingerprint);
        self
    }
    /// Name the trading Treasury explicitly (see `treasury`).
    pub fn with_treasury(mut self, treasury: Hash) -> Self {
        self.treasury = Some(treasury);
        self
    }
    /// The rotation stays valid in the next block and the `blocks` after it (N + 1 blocks; N is
    /// 1 to 10,080).
    pub fn with_validity_blocks(mut self, blocks: u64) -> Self {
        self.validity_blocks = blocks;
        self
    }
}

request! {
    /// (f) Authorize the freeze of a Treasury offer. Phase 6; Treasury profile only. MUT authority
    /// only: this is not a Bitcoin signing API.
    TreasuryFreezeOfferRequest {
        /// The freeze PROPOSAL (`ops::treasury::freeze_proposal`): the exact unsigned freeze body
        /// (`trading_v1::PreparedTreasuryOffer::signing_payload`, prepared against the verified head
        /// this wallet reviews at) together with the maker's signed offer in its import form (the
        /// `OfferProof` encoding with an all-zero fill signature), so the wallet can verify the
        /// maker's signature and prepare the same body again through consensus code.
        prepared_offer: Blob,
    }
}

impl TreasuryFreezeOfferRequest {
    pub fn new(prepared_offer: Blob) -> Self {
        Self { prepared_offer }
    }
}

/// Everything a user may ask to cancel, and which of those the protocol allows.
///
/// Only the hash-lock refund exists on chain, and only at or after its refund height; every other
/// target is an explicit, tested refusal ([`Refusal::CancelNotAvailable`]).
#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CancelTarget {
    /// An open offer: an off-chain object with no codec in this protocol version.
    Offer,
    /// A take reservation: off-chain, no codec.
    Reservation,
    /// A signed operation that is not yet included: a signature cannot be revoked; it expires.
    SignedOperation,
    /// A started unbond: Active to Unbonding is one-way.
    Unbond,
    /// A fiat lock: the protocol has no unilateral exit.
    FiatLock,
    /// A dividend claim already signed: it stays valid until its window ends.
    DividendClaim,
    /// A License sale already signed: it stays valid for its one height.
    LicenseDvp,
    /// The one permitted cancellation: refund this hash lock (output identifier) at or after its
    /// refund height.
    HashLockRefund(Hash),
}

impl fmt::Debug for CancelTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Offer => f.write_str("Offer"),
            Self::Reservation => f.write_str("Reservation"),
            Self::SignedOperation => f.write_str("SignedOperation"),
            Self::Unbond => f.write_str("Unbond"),
            Self::FiatLock => f.write_str("FiatLock"),
            Self::DividendClaim => f.write_str("DividendClaim"),
            Self::LicenseDvp => f.write_str("LicenseDvp"),
            Self::HashLockRefund(lock) => write!(f, "HashLockRefund({})", units::short_hex(lock)),
        }
    }
}

impl CancelTarget {
    /// Why the protocol offers no cancellation (or what the permitted one is).
    pub fn explanation(&self) -> &'static str {
        match self {
            Self::Offer => {
                "An open offer cannot be cancelled here: offers are not on chain and the protocol has no cancel object for them yet."
            }
            Self::Reservation => {
                "A reservation cannot be cancelled here: reservations are not on chain and the protocol has no cancel object for them yet."
            }
            Self::SignedOperation => {
                "A signed operation cannot be revoked. It stays valid until it is included or its validity window ends; nothing can recall it."
            }
            Self::Unbond => {
                "A started unbond cannot be cancelled: moving from Active to Unbonding is one-way in the protocol."
            }
            Self::FiatLock => {
                "A fiat lock has no unilateral exit: funds stay locked unless both parties authorize the release."
            }
            Self::DividendClaim => {
                "A signed dividend claim cannot be revoked. It stays valid until its window ends."
            }
            Self::LicenseDvp => {
                "A signed License sale cannot be revoked. It remains valid within its exact signed inclusion window if its committed state still matches, and lapses after that window."
            }
            Self::HashLockRefund(_) => "A hash lock can be refunded at or after its refund height.",
        }
    }
}

request! {
    /// A request to cancel something. Only [`CancelTarget::HashLockRefund`] can succeed.
    CancelRequest {
        target: CancelTarget,
    }
}

impl CancelRequest {
    pub fn new(target: CancelTarget) -> Self {
        Self { target }
    }
}

request! {
    /// Exact canonical OfferBody bytes; context and maker must match the verified signer.
    MakerOfferRequest { body:Blob, }
}
impl MakerOfferRequest {
    pub fn new(body: Blob) -> Self {
        Self { body }
    }
}

request! {
    /// Public canonical Binding, exact Node descriptor, and Ed448 possession signature.
    /// No Worker secret or provisioning action is accepted or performed by the wallet.
    WorkerAssignmentRequest { binding: Blob, node_descriptor: Blob, worker_signature: Blob, }
}
impl WorkerAssignmentRequest {
    pub fn new(binding: Blob, node_descriptor: Blob, worker_signature: Blob) -> Self {
        Self {
            binding,
            node_descriptor,
            worker_signature,
        }
    }
}

/// A request for one operation. Every operation kind the wallet is meant to support is declared
/// here; a kind without a handler in this build is refused with [`Refusal::NotImplemented`].
#[derive(Debug)]
#[non_exhaustive]
pub enum OperationRequest {
    Payment(PaymentRequest),
    WalletRotation(RotationRequest),
    DividendClaim(DividendClaimRequest),
    LicenseDvp(LicenseDvpRequest),
    HashLock(HashLockRequest),
    ConditionalClaim(ClaimRequest),
    ConditionalRefund(RefundRequest),
    FiatLock(FiatLockRequest),
    FiatRelease(FiatReleaseRequest),
    BondCreate(BondCreateRequest),
    BondUnbond(BondUnbondRequest),
    BondWithdraw(BondWithdrawRequest),
    TreasuryRotate(TreasuryRotateRequest),
    TreasuryFreezeOffer(TreasuryFreezeOfferRequest),
    MakerOffer(MakerOfferRequest),
    WorkerAssignment(WorkerAssignmentRequest),
    /// Cancellation: every target except the hash-lock refund is refused.
    Cancel(CancelRequest),
}

impl OperationRequest {
    /// The kind of operation this request builds. `None` for a cancellation that has no kind of
    /// its own (the refusable targets).
    pub fn kind(&self) -> Option<OperationKind> {
        Some(match self {
            Self::Payment(_) => OperationKind::Payment,
            Self::WalletRotation(_) => OperationKind::WalletRotation,
            Self::DividendClaim(_) => OperationKind::DividendClaim,
            Self::LicenseDvp(_) => OperationKind::LicenseDvp,
            Self::HashLock(_) => OperationKind::HashLock,
            Self::ConditionalClaim(_) => OperationKind::ConditionalClaim,
            Self::ConditionalRefund(_) => OperationKind::ConditionalRefund,
            Self::FiatLock(_) => OperationKind::FiatLock,
            Self::FiatRelease(_) => OperationKind::FiatRelease,
            Self::BondCreate(_) => OperationKind::BondCreate,
            Self::BondUnbond(_) => OperationKind::BondUnbond,
            Self::BondWithdraw(_) => OperationKind::BondWithdraw,
            Self::TreasuryRotate(_) => OperationKind::TreasuryRotate,
            Self::TreasuryFreezeOffer(_) => OperationKind::TreasuryFreezeOffer,
            Self::MakerOffer(_) => OperationKind::MakerOffer,
            Self::WorkerAssignment(_) => OperationKind::WorkerAssignment,
            Self::Cancel(cancel) => match cancel.target {
                CancelTarget::HashLockRefund(_) => OperationKind::ConditionalRefund,
                _ => return None,
            },
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Planner
// ---------------------------------------------------------------------------------------------

/// Builds an immutable plan from a request and the verified chain.
pub trait Planner {
    fn plan(
        &self,
        request: &OperationRequest,
        view: &ChainView<'_>,
        signer: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal>;
}

/// The planner over every operation handler registered in `ops/mod.rs`.
#[derive(Clone, Copy, Debug, Default)]
pub struct StandardPlanner;

impl Planner for StandardPlanner {
    fn plan(
        &self,
        request: &OperationRequest,
        view: &ChainView<'_>,
        signer: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        plan(request, view, signer)
    }
}

/// Build a plan. A cancellation is mapped to the one operation the protocol permits, or refused;
/// every other request goes to the handler of its kind.
pub fn plan(
    request: &OperationRequest,
    view: &ChainView<'_>,
    signer: &SignerIdentity,
) -> Result<OperationPlan, Refusal> {
    if let OperationRequest::Cancel(cancel) = request {
        return match cancel.target {
            CancelTarget::HashLockRefund(lock) => {
                let refund = OperationRequest::ConditionalRefund(RefundRequest::new(lock));
                plan(&refund, view, signer)
            }
            other => Err(Refusal::CancelNotAvailable(other)),
        };
    }
    let kind = request.kind().ok_or(Refusal::UnknownOperation)?;
    crate::ops::handler(kind)?.plan(request, view, signer)
}

/// Build a plan from bytes another party prepared, so this wallet can review and sign its own part
/// (an unsigned payment prepared on an online machine for an offline signer, a counterparty's
/// partial operation). The result is an ordinary [`OperationPlan`]: same review, same approval, same
/// authorization. Bytes that name nothing this wallet must sign are refused.
pub fn adopt(
    raw: &[u8],
    view: &ChainView<'_>,
    me: &SignerIdentity,
) -> Result<OperationPlan, Refusal> {
    crate::ops::recognizing(raw)
        .ok_or(Refusal::UnknownOperation)?
        .adopt(raw, view, me)
}

/// What signed or partial bytes commit to (see `OperationHandler::describe`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Description {
    pub id: Hash,
    pub complete: bool,
    pub missing: Vec<Requirement>,
    pub validity: Validity,
    /// Sorted and de-duplicated. Coins, and (through `outbox::resource_key`) non-coin resources.
    pub reserved: Vec<OutPoint>,
}

/// One operation kind's logic. Implemented once per kind in `ops/<kind>.rs` and registered in
/// `ops/mod.rs`; crate-internal on purpose (the registry is closed, and a handler receives a
/// [`KindSigner`], which only this crate can construct).
pub(crate) trait OperationHandler: Sync {
    fn kind(&self) -> OperationKind;
    /// Whether `raw` (unsigned, partial or signed) is an object of this kind.
    fn recognizes(&self, raw: &[u8]) -> bool;
    /// Build the immutable plan. Must be deterministic in (request, view, signer).
    fn plan(
        &self,
        request: &OperationRequest,
        view: &ChainView<'_>,
        signer: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal>;
    /// Build a plan from bytes received from another party (an unsigned proposal prepared elsewhere,
    /// for example for an offline signer, or the partial operation of a counterparty) so that this
    /// wallet can review and sign its own part. Refuses bytes this wallet has nothing to sign in.
    fn adopt(
        &self,
        raw: &[u8],
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal>;
    /// Mirror, before signing, every check consensus will make that does not need the signatures,
    /// against the CURRENT view. Called by `review` and again by `authorize`.
    fn validate(&self, plan: &OperationPlan, view: &ChainView<'_>) -> Result<(), Refusal>;
    /// The review content, derived only from `plan.objects()`, `plan.signer()` and the view.
    fn review(&self, plan: &OperationPlan, view: &ChainView<'_>) -> Result<ReviewDraft, Refusal>;
    /// Exact unsigned objects bound by the review. A plan may retain verified counterparty
    /// proofs required for signing; those proofs do not change the reviewed unsigned body.
    fn reviewed_objects(&self, plan: &OperationPlan) -> Result<Vec<PlanObject>, Refusal> {
        Ok(plan.objects().to_vec())
    }
    /// The review content for raw bytes (unsigned, partial or signed) seen from `me`, plus the
    /// UNSIGNED form of the objects so the binding digest equals the plan's.
    fn explain(
        &self,
        raw: &[u8],
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<(ReviewDraft, Vec<PlanObject>), Refusal>;
    /// Check that this wallet's key controls every slot it must sign. The default resolves each
    /// `ThisWallet` requirement through the wallet book exactly as consensus does; a kind that
    /// introduces a key which is not registered yet (wallet rotation) overrides it.
    fn check_requirements(
        &self,
        plan: &OperationPlan,
        view: &ChainView<'_>,
        identity: &SignerIdentity,
    ) -> Result<(), Refusal> {
        crate::authorize::check_wallet_requirements(plan, view, identity)
    }
    /// Sign what this wallet must sign, using only domains the kind permits, and return the result.
    fn sign(
        &self,
        plan: &OperationPlan,
        signer: &KindSigner<'_>,
        view: &ChainView<'_>,
    ) -> Result<SignedOperation, Refusal>;
    /// The unsigned form of signed or partial bytes (signatures removed), for the binding check.
    fn unsigned_form(&self, raw: &[u8]) -> Result<Vec<PlanObject>, Refusal>;
    /// What signed or partial bytes commit to, derived from the BYTES ALONE: the operation
    /// identifier, whether every required signature is present, the signatures still missing, the
    /// validity window, and every coin or resource the operation consumes. The outbox stores these
    /// derived values and refuses a caller's metadata that disagrees with them.
    fn describe(&self, raw: &[u8]) -> Result<Description, Refusal>;
    /// The identity of the OPERATION `raw` carries, whichever of its signatures are present: the
    /// partial and the complete form of one operation share it (`Outbox::replace_partial` relies on
    /// it). The default is the identifier `describe` derives, which is that identity for every kind
    /// whose partial and complete records share their identifier; a kind that identifies a partial
    /// by its exact bytes overrides it.
    fn operation_identity(&self, raw: &[u8]) -> Result<Hash, Refusal> {
        self.describe(raw).map(|described| described.id)
    }
    /// Independent verification through consensus code of a signed or partial result.
    fn check_signed(&self, signed: &SignedOperation, view: &ChainView<'_>) -> Result<(), Refusal>;
    /// Where a queued record stands in verified state.
    fn reconcile(&self, record: &OutboxRecord, view: &ChainView<'_>) -> Settlement;
}

// ---------------------------------------------------------------------------------------------
// Plan state machine
// ---------------------------------------------------------------------------------------------

/// Why a plan stopped being usable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Invalidation {
    /// The validity window ended.
    Expired,
    /// The wallet was locked.
    Locked,
}

/// Where a plan is in its life. Transitions are explicit (see [`PlanSession`]); anything else is
/// refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanPhase {
    /// Built; no review has been shown at the current head.
    Planned,
    /// A review of this exact plan at the current head is on screen; acknowledgements are being
    /// collected.
    Presented,
    /// A single-use approval was issued and has not been used.
    Approved,
    /// Signed bytes exist (complete or partial). The approval is consumed.
    Signed,
    /// The signed bytes are durably in the outbox.
    Queued,
    /// Dropped by the user before anything was signed.
    Discarded,
    /// Unusable.
    Invalidated(Invalidation),
}

impl PlanPhase {
    /// A phase from which nothing further can happen to the plan.
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Queued | Self::Discarded | Self::Invalidated(_))
    }
}

/// UI-free state of one plan from "built" to "queued": the plan, its phase, the review on screen
/// and the [`ReviewGate`] that collects acknowledgements and issues the approval.
///
/// A new verified head, an expired window or a lock clears every outstanding acknowledgement, takes
/// the session out of `Presented`/`Approved` and WITHDRAWS the approval the gate issued (see
/// [`ReviewGate`]), so an approval cannot be used after the review it was given for is gone, even by
/// a caller that still holds it.
///
/// Once signed bytes exist the session never claims they were taken back: a lock leaves it in
/// `Signed` (the bytes still have to be queued or deliberately left alone), and `discard` is refused.
pub struct PlanSession {
    plan: Option<OperationPlan>,
    phase: PlanPhase,
    gate: ReviewGate,
    review: Option<Review>,
}

impl PlanSession {
    pub fn new(plan: OperationPlan) -> Self {
        Self {
            plan: Some(plan),
            phase: PlanPhase::Planned,
            gate: ReviewGate::new(),
            review: None,
        }
    }
    pub fn phase(&self) -> PlanPhase {
        self.phase
    }
    pub fn plan(&self) -> Option<&OperationPlan> {
        self.plan.as_ref()
    }
    pub fn review(&self) -> Option<&Review> {
        self.review.as_ref()
    }
    pub fn gate(&self) -> &ReviewGate {
        &self.gate
    }

    fn require_live(&self) -> Result<(), Refusal> {
        if self.phase.is_terminal() || self.plan.is_none() {
            return Err(Refusal::NotPresented);
        }
        Ok(())
    }

    /// Compute the review of the plan at `view`, put it on screen and wait for acknowledgements.
    /// Valid from `Planned`, `Presented` and `Approved` (a new head requires a new review).
    pub fn present(&mut self, view: &ChainView<'_>) -> Result<&Review, Refusal> {
        self.require_live()?;
        if self.phase == PlanPhase::Signed {
            return Err(Refusal::NotPresented);
        }
        let plan = self.plan.as_ref().ok_or(Refusal::NotPresented)?;
        let review = match crate::review::review(plan, view) {
            Ok(review) => review,
            Err(refusal) => {
                self.gate.clear();
                self.review = None;
                self.phase = PlanPhase::Planned;
                return Err(refusal);
            }
        };
        self.gate.present(&review, view);
        self.phase = PlanPhase::Presented;
        Ok(&*self.review.insert(review))
    }

    pub fn acknowledge(&mut self, ack: AckKind) -> Result<(), Refusal> {
        if self.phase != PlanPhase::Presented {
            return Err(Refusal::NotPresented);
        }
        self.gate.acknowledge(ack)
    }

    /// Type the confirmation phrase of a high-risk review (see `Review::confirmation_phrase`).
    pub fn confirm_phrase(&mut self, typed: &str) -> Result<(), Refusal> {
        if self.phase != PlanPhase::Presented {
            return Err(Refusal::NotPresented);
        }
        self.gate.confirm_phrase(typed)
    }

    /// Type the last eight characters of destination `index` (see `Review::destinations`).
    pub fn confirm_destination(&mut self, index: usize, typed: &str) -> Result<(), Refusal> {
        if self.phase != PlanPhase::Presented {
            return Err(Refusal::NotPresented);
        }
        self.gate.confirm_destination(index, typed)
    }

    /// Issue the single-use approval for the review on screen. Fails unless every acknowledgement
    /// is in and the review is still fresh.
    pub fn approve(&mut self, view: &ChainView<'_>) -> Result<Approval, Refusal> {
        if self.phase != PlanPhase::Presented {
            return Err(Refusal::NotPresented);
        }
        match self.gate.approve(view) {
            Ok(approval) => {
                self.phase = PlanPhase::Approved;
                Ok(approval)
            }
            Err(refusal) => {
                if matches!(refusal, Refusal::StaleHead { .. } | Refusal::Expired(_)) {
                    self.phase = PlanPhase::Planned;
                    self.review = None;
                }
                Err(refusal)
            }
        }
    }

    /// Hand the plan and the approval to `signer`. The approval is consumed whatever the outcome;
    /// after a refusal the session goes back to `Planned` and needs a fresh review.
    pub fn authorize<S: Signer + ?Sized>(
        &mut self,
        signer: &S,
        approval: Approval,
        view: &ChainView<'_>,
    ) -> Result<SignedOperation, Refusal> {
        if self.phase != PlanPhase::Approved {
            return Err(Refusal::NotPresented);
        }
        let plan = self.plan.clone().ok_or(Refusal::NotPresented)?;
        match signer.authorize(plan, approval, view) {
            Ok(signed) => {
                self.phase = PlanPhase::Signed;
                self.review = None;
                Ok(signed)
            }
            Err(refusal) => {
                self.gate.clear();
                self.review = None;
                self.phase = PlanPhase::Planned;
                Err(refusal)
            }
        }
    }

    /// Record that the signed bytes were durably queued.
    pub fn note_queued(&mut self) -> Result<(), Refusal> {
        if self.phase != PlanPhase::Signed {
            return Err(Refusal::NotPresented);
        }
        self.phase = PlanPhase::Queued;
        Ok(())
    }

    /// Call on every new verified head. A review or approval for any other head is dropped; a plan
    /// whose window has closed is invalidated.
    pub fn on_head(&mut self, view: &ChainView<'_>) {
        if self.phase.is_terminal() || self.phase == PlanPhase::Signed {
            return;
        }
        if let Some(plan) = &self.plan
            && !view
                .next_height()
                .is_ok_and(|next| next <= plan.validity().expiry)
        {
            self.gate.clear();
            self.review = None;
            self.plan = None;
            self.phase = PlanPhase::Invalidated(Invalidation::Expired);
            return;
        }
        let moved = self
            .review
            .as_ref()
            .is_some_and(|review| !review.is_for(view));
        if moved {
            self.gate.clear();
            self.review = None;
            self.phase = PlanPhase::Planned;
        }
    }

    /// The wallet was locked: drop everything that can still be dropped. A plan that was already
    /// signed stays `Signed`: its bytes exist and cannot be recalled, so the session keeps saying so.
    pub fn lock(&mut self) {
        self.gate.clear();
        self.review = None;
        if !self.phase.is_terminal() && self.phase != PlanPhase::Signed {
            self.plan = None;
            self.phase = PlanPhase::Invalidated(Invalidation::Locked);
        }
    }

    /// The user dropped the plan. Refused once signed bytes exist.
    pub fn discard(&mut self) -> Result<(), Refusal> {
        if matches!(self.phase, PlanPhase::Signed | PlanPhase::Queued) {
            return Err(Refusal::CancelNotAvailable(CancelTarget::SignedOperation));
        }
        self.gate.clear();
        self.review = None;
        self.plan = None;
        if !self.phase.is_terminal() {
            self.phase = PlanPhase::Discarded;
        }
        Ok(())
    }
}

impl fmt::Debug for PlanSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlanSession")
            .field("phase", &self.phase)
            .field("plan", &self.plan)
            .field("review_shown", &self.review.is_some())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_codes_are_unique_dense_and_round_trip() {
        for (index, kind) in OperationKind::ALL.iter().enumerate() {
            assert_eq!(kind.code() as usize, index + 1);
            assert_eq!(OperationKind::from_code(kind.code()), Some(*kind));
            assert!(!kind.name().is_empty() && !kind.title().is_empty());
        }
        assert_eq!(OperationKind::from_code(0), None);
        assert_eq!(OperationKind::from_code(17), None);
        let names: std::collections::BTreeSet<_> =
            OperationKind::ALL.iter().map(|k| k.name()).collect();
        assert_eq!(names.len(), OperationKind::ALL.len());
    }

    #[test]
    fn blob_and_plan_object_debug_are_bounded() {
        let blob = Blob::new(vec![7; 100_000]);
        assert!(format!("{blob:?}").len() < 80);
        let object = PlanObject::new("transfer", vec![9; 100_000]);
        assert!(format!("{object:?}").len() < 100);
    }

    #[test]
    fn only_the_refund_cancellation_has_a_kind() {
        let refund =
            OperationRequest::Cancel(CancelRequest::new(CancelTarget::HashLockRefund([1; 32])));
        assert_eq!(refund.kind(), Some(OperationKind::ConditionalRefund));
        for target in [
            CancelTarget::Offer,
            CancelTarget::Reservation,
            CancelTarget::SignedOperation,
            CancelTarget::Unbond,
            CancelTarget::FiatLock,
            CancelTarget::DividendClaim,
            CancelTarget::LicenseDvp,
        ] {
            assert_eq!(
                OperationRequest::Cancel(CancelRequest::new(target)).kind(),
                None
            );
            assert!(!target.explanation().is_empty());
        }
    }
}
