//! The review a person reads before anything is signed.
//!
//! A [`Review`] is never assembled by hand. It is produced only by [`review`] (for a plan built by
//! this wallet) or [`explain`] (for bytes received from someone else), and in both cases it is a
//! PURE function of the operation's unsigned bytes and the verified [`ChainView`]. Its private
//! fields mean outside code cannot construct a `Review` that says one thing while binding another.
//!
//! The review is complete by construction: destination(s), amount, fee (with its rule and payer),
//! change, conditions, timing, irreversible effects and warnings are all rows, and the typed
//! acknowledgements a person must give are derived from those rows rather than listed separately,
//! so a risk cannot be shown without its acknowledgement.
//!
//! Addresses in the structured rows (signing wallet, authorizations, parties, destinations, fee
//! payer) are shown in the checksummed text form of the verified chain's class first
//! (`address_format`, Order W2: the PRIMARY display), then as the LEGACY hexadecimal identifier,
//! whose last eight characters are the typed destination check. The 32-byte identifier is what
//! the operation binds; both strings are only encodings of it.
//!
//! The binding digest ties a review to exactly one operation at exactly one verified head:
//! `SHA-256(domain || kind || schema || unsigned objects || anchor || state root)`.
use crate::refusal::Refusal;
use crate::{
    address_format,
    authorize::{SignerIdentity, WalletProfile},
    context::{ChainClass, ChainContext, ChainView},
    plan::{
        OperationKind, OperationPlan, PlanObject, RequiredSigner, Requirement, RequirementStatus,
        Slot,
    },
    units,
};
use mutiny_consensus_v8::{Hash, anchors::FinalizedAnchor, transactions::OutPoint};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, fmt};

/// Domain separator of the review binding digest.
pub const BINDING_DOMAIN: &[u8] = b"MUTINY-BUILD8-WALLET-REVIEW-BINDING-V1";

/// The near-deadline WARNING threshold of a dividend claim's review (Order W20): the review carries
/// the `CLAIM_WINDOW_CLOSING` caution when at most this many epochs of the award's claim window
/// remain after the verified block's epoch (about one day at 60 s per epoch), or when the window
/// may close within the claim's own validity window. A display threshold ONLY: it is not a claim
/// time-to-live, not a validity rule and not a consensus constant. The claim window itself is
/// consensus' `CLAIM_WINDOW_EPOCHS` (65,536 epochs from the award epoch E: E <= block epoch <
/// E + 65,536); a claim's height window is its own `validity_blocks`, a separate rule.
pub const CLAIM_DEADLINE_WARNING_EPOCHS: u64 = 1_440;

// ---------------------------------------------------------------------------------------------
// Acknowledgements
// ---------------------------------------------------------------------------------------------

/// A typed acknowledgement a person must give, by risk class, before an approval is issued.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum AckKind {
    /// Every destination address was checked (with the typed last-eight-characters check).
    Destination,
    Amount,
    Fee,
    /// The conditions and timing were read.
    Conditions,
    /// The effects marked irreversible are understood.
    Irreversible,
    /// Evidence that lives outside the chain (a Bitcoin or fiat payment, a preimage's origin) is
    /// not verified by this wallet.
    ExternalEvidence,
    /// A fiat lock has no unilateral exit.
    NoUnilateralExit,
    /// A key rotation kills the old key and makes the new key's backup the only recovery.
    KeyLoss,
    /// An action on the Treasury profile changes MUT authority only.
    TreasuryAuthority,
    /// Unclaimed dividend entitlements are not bound by a License sale.
    UnboundDividends,
    /// The operation is valid only in one specific block.
    SingleBlockWindow,
    /// A claim reveals the hash-lock preimage publicly.
    DisclosesPreimage,
}

impl AckKind {
    /// Stable numeric code (bound into the approval scope). Never reused.
    pub const fn code(self) -> u8 {
        match self {
            Self::Destination => 1,
            Self::Amount => 2,
            Self::Fee => 3,
            Self::Conditions => 4,
            Self::Irreversible => 5,
            Self::ExternalEvidence => 6,
            Self::NoUnilateralExit => 7,
            Self::KeyLoss => 8,
            Self::TreasuryAuthority => 9,
            Self::UnboundDividends => 10,
            Self::SingleBlockWindow => 11,
            Self::DisclosesPreimage => 12,
        }
    }

    /// The sentence shown next to the checkbox or typed prompt.
    pub fn statement(self) -> &'static str {
        match self {
            Self::Destination => "I checked every destination address",
            Self::Amount => "I checked the amount",
            Self::Fee => "I checked the fee and who pays it",
            Self::Conditions => "I read the conditions and the timing",
            Self::Irreversible => {
                "I understand the effects marked irreversible cannot be undone once the operation is included"
            }
            Self::ExternalEvidence => {
                "I understand that payment or Bitcoin evidence outside this chain is not verified by this wallet"
            }
            Self::NoUnilateralExit => {
                "I understand the funds stay locked unless both parties authorize the release"
            }
            Self::KeyLoss => {
                "I understand the old key loses all authority and the funds are controlled only by the new key and its backup"
            }
            Self::TreasuryAuthority => {
                "I understand this changes MUT Treasury authority only and does not touch Bitcoin custody"
            }
            Self::UnboundDividends => {
                "I understand unclaimed dividend entitlements are not bound by this sale"
            }
            Self::SingleBlockWindow => {
                "I understand this is valid only in one specific block and must be reviewed again if the chain moves"
            }
            Self::DisclosesPreimage => "I understand claiming reveals the preimage publicly",
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Review content types
// ---------------------------------------------------------------------------------------------

/// How a row should be drawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Emphasis {
    Normal,
    Important,
    Warning,
    Irreversible,
}

impl Emphasis {
    fn marker(self) -> &'static str {
        match self {
            Self::Normal => "  ",
            Self::Important => "* ",
            Self::Warning => "! ",
            Self::Irreversible => "# ",
        }
    }
}

/// Review sections, in display order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Section {
    Summary,
    Chain,
    Signer,
    Authorizations,
    Parties,
    Money,
    Conditions,
    Timing,
    Effects,
    Warnings,
    Acknowledgements,
    Binding,
}

impl Section {
    pub fn title(self) -> &'static str {
        match self {
            Self::Summary => "Summary",
            Self::Chain => "Chain",
            Self::Signer => "Signing wallet",
            Self::Authorizations => "Required authorizations",
            Self::Parties => "Parties",
            Self::Money => "Money",
            Self::Conditions => "Conditions",
            Self::Timing => "Timing",
            Self::Effects => "Effects",
            Self::Warnings => "Warnings",
            Self::Acknowledgements => "You must acknowledge",
            Self::Binding => "Binding",
        }
    }
}

/// One line of a review: what a UI draws and what a golden test pins.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub section: Section,
    pub label: String,
    pub value: String,
    pub emphasis: Emphasis,
}

/// What an address is, as far as the verified chain can tell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddressLabel {
    /// An address of the signing wallet (any generation of its authority).
    ThisWallet,
    /// An address of the Treasury wallet authority.
    Treasury,
    /// A protocol escrow address derived for a bond.
    Escrow,
    /// Any other address.
    External,
    /// The address of the NEW key a wallet rotation of this wallet introduces. The verified chain
    /// does not know it before the rotation is included, so it is not `ThisWallet` yet and keeps the
    /// typed re-entry check (added in phase 8; before, such an address was labelled `External`).
    NewKey,
}

impl AddressLabel {
    pub fn text(self) -> &'static str {
        match self {
            Self::ThisWallet => "this wallet",
            Self::Treasury => "the Treasury",
            Self::Escrow => "a protocol escrow",
            Self::External => "an external address",
            Self::NewKey => "this wallet's new key, not yet known to the chain",
        }
    }
    /// Everything that is not this wallet's own address needs the typed re-entry check (Q10).
    pub fn needs_typed_check(self) -> bool {
        !matches!(self, Self::ThisWallet)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PartyRole {
    Sender,
    Recipient,
    Seller,
    Buyer,
    Maker,
    Owner,
    LockSender,
    LockRecipient,
    Claimant,
    NodeOwner,
    Treasury,
    FeePayer,
}

impl PartyRole {
    pub fn text(self) -> &'static str {
        match self {
            Self::Sender => "Sender",
            Self::Recipient => "Recipient",
            Self::Seller => "Seller",
            Self::Buyer => "Buyer",
            Self::Maker => "Maker",
            Self::Owner => "Owner",
            Self::LockSender => "Lock sender",
            Self::LockRecipient => "Lock recipient",
            Self::Claimant => "Claimant",
            Self::NodeOwner => "Node owner",
            Self::Treasury => "Treasury",
            Self::FeePayer => "Fee payer",
        }
    }
}

/// A named participant.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Party {
    pub role: PartyRole,
    pub address: Hash,
    pub label: AddressLabel,
}

impl fmt::Debug for Party {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Party({:?}, {}, {:?})",
            self.role,
            units::short_hex(&self.address),
            self.label
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DestinationRole {
    /// Value sent to somebody else.
    Payment,
    /// Value returned to the signing wallet.
    Change,
    /// Value locked in a protocol lock record.
    LockedOutput,
    /// Value the protocol pays out on its own (dividend claims, claims of a lock).
    ProtocolPayout,
    /// Value moved to a protocol escrow (bond principal).
    Escrow,
    /// The seller-side payment of a License sale.
    LicensePayment,
}

impl DestinationRole {
    pub fn text(self) -> &'static str {
        match self {
            Self::Payment => "Pays",
            Self::Change => "Returns to this wallet",
            Self::LockedOutput => "Locks",
            Self::ProtocolPayout => "The protocol pays",
            Self::Escrow => "Moves to escrow",
            Self::LicensePayment => "Pays the seller side",
        }
    }
}

/// Where value goes, and how much.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Destination {
    pub role: DestinationRole,
    pub address: Hash,
    pub label: AddressLabel,
    pub atoms: u64,
}

impl Destination {
    pub fn needs_typed_check(&self) -> bool {
        self.label.needs_typed_check()
    }
    /// Legacy hexadecimal check, retained for explicit diagnostic compatibility only.
    pub fn check_text(&self) -> String {
        units::last8_hex(&self.address)
    }
    /// The last eight characters of the class-distinguishing checksummed address.
    pub fn check_text_for(&self, class: ChainClass) -> String {
        let text = crate::address_format::encode(&self.address, class);
        text[text.len() - 8..].to_owned()
    }
}

impl fmt::Debug for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Destination({:?}, {}, {:?}, {} atoms)",
            self.role,
            units::short_hex(&self.address),
            self.label,
            self.atoms
        )
    }
}

/// One coin an operation spends.
#[derive(Clone, PartialEq, Eq)]
pub struct InputLine {
    pub point: OutPoint,
    pub atoms: u64,
    pub owned_by_signer: bool,
    pub coinbase: bool,
}

impl fmt::Debug for InputLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "InputLine({}:{}, {} atoms)",
            units::short_hex(&self.point.transaction),
            self.point.index,
            self.atoms
        )
    }
}

/// How the fee is determined.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FeeRule {
    /// The fee must be at least the encoded size of the complete signed object, one atom per byte.
    OneAtomPerEncodedByte,
    /// The greater of the trading floor and one atom per encoded byte.
    TradingMinimum { floor: u64 },
    /// The operation class is fee-exempt (dividend claims).
    Exempt,
    /// The protocol defines no fee for this operation (bond unbond and withdrawal).
    None,
}

impl FeeRule {
    pub fn text(self) -> String {
        match self {
            Self::OneAtomPerEncodedByte => {
                "at least one atom per byte of the signed encoding".into()
            }
            Self::TradingMinimum { floor } => format!(
                "the greater of {floor} STRIKES and one atom per byte of the signed encoding"
            ),
            Self::Exempt => "exempt: this operation class pays no fee".into(),
            Self::None => "the protocol defines no fee for this operation".into(),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FeePayer {
    ThisWallet,
    Counterparty(Hash),
    Protocol,
    NotApplicable,
}

impl fmt::Debug for FeePayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ThisWallet => f.write_str("ThisWallet"),
            Self::Counterparty(address) => write!(f, "Counterparty({})", units::short_hex(address)),
            Self::Protocol => f.write_str("Protocol"),
            Self::NotApplicable => f.write_str("NotApplicable"),
        }
    }
}

/// The fee, its rule and who pays it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fee {
    pub atoms: u64,
    pub rule: FeeRule,
    pub payer: FeePayer,
    /// Encoded size of the complete signed object, when the fee depends on it.
    pub size_bytes: Option<u64>,
}

/// When the operation may be included, in heights and (where it has them) epochs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    /// The verified head this review was computed against.
    pub head_height: u64,
    pub created_height: Option<u64>,
    pub expiry_height: Option<u64>,
    pub valid_only_at: Option<u64>,
    pub bound_to_parent: bool,
    /// First height at which the action becomes allowed (refund height, withdrawal floor).
    pub earliest_height: Option<u64>,
    /// Last epoch of an award claim window.
    pub deadline_epoch: Option<u64>,
}

/// A rule the operation depends on, as a labelled sentence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Condition {
    pub label: String,
    pub detail: String,
}

impl Condition {
    pub fn new(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            detail: detail.into(),
        }
    }
}

/// A consequence of including the operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Effect {
    pub text: String,
    pub irreversible: bool,
}

impl Effect {
    pub fn new(text: impl Into<String>, irreversible: bool) -> Self {
        Self {
            text: text.into(),
            irreversible,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Notice,
    Caution,
    Danger,
}

/// Something the person must be told, optionally with an acknowledgement attached.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Warning {
    /// Stable code for logs and tests.
    pub code: &'static str,
    pub severity: Severity,
    pub text: String,
    /// The acknowledgement this warning requires, if any.
    pub requires: Option<AckKind>,
}

impl Warning {
    pub fn new(code: &'static str, severity: Severity, text: impl Into<String>) -> Self {
        Self {
            code,
            severity,
            text: text.into(),
            requires: None,
        }
    }
    pub fn requiring(mut self, ack: AckKind) -> Self {
        self.requires = Some(ack);
        self
    }
}

/// The signing wallet as the review shows it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SignerSummary {
    pub address: Hash,
    pub generation: u64,
    pub authority: Hash,
    pub profile: WalletProfile,
}

impl fmt::Debug for SignerSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SignerSummary({}, generation {}, {:?})",
            units::short_hex(&self.address),
            self.generation,
            self.profile
        )
    }
}

/// The verified chain facts a review was computed against.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ChainSummary {
    pub context: ChainContext,
    pub head_height: u64,
    pub head_block: Hash,
    pub state_root: Hash,
    pub class: ChainClass,
}

impl fmt::Debug for ChainSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ChainSummary(height {}, {:?}, {})",
            self.head_height,
            self.class,
            units::short_hex(&self.state_root)
        )
    }
}

// ---------------------------------------------------------------------------------------------
// Digest
// ---------------------------------------------------------------------------------------------

/// The binding digest of one review.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ReviewDigest([u8; 32]);

impl ReviewDigest {
    /// A digest read back from storage (an outbox's approval binding).
    pub(crate) fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for ReviewDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReviewDigest({})", units::short_hex(&self.0))
    }
}

impl fmt::Display for ReviewDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// `SHA-256(domain || 0 || kind || schema || objects || anchor || state root)`.
///
/// Every variable-length field is length-prefixed, so two different operations can never share a
/// preimage by moving bytes between fields.
pub fn binding_digest(
    kind: OperationKind,
    schema: u16,
    objects: &[PlanObject],
    anchor: &FinalizedAnchor,
    state_root: &Hash,
) -> ReviewDigest {
    let mut hasher = Sha256::new();
    hasher.update(BINDING_DOMAIN);
    hasher.update([0]);
    hasher.update(kind.code().to_be_bytes());
    hasher.update(schema.to_be_bytes());
    hasher.update((objects.len() as u32).to_be_bytes());
    for object in objects {
        hasher.update([object.label.len() as u8]);
        hasher.update(object.label.as_bytes());
        hasher.update((object.bytes.len() as u32).to_be_bytes());
        hasher.update(&object.bytes);
    }
    let anchor_bytes = anchor.encode();
    hasher.update((anchor_bytes.len() as u32).to_be_bytes());
    hasher.update(&anchor_bytes);
    hasher.update(state_root);
    ReviewDigest(hasher.finalize().into())
}

// ---------------------------------------------------------------------------------------------
// Review
// ---------------------------------------------------------------------------------------------

/// What a handler contributes: everything in a review except what the core derives itself (the
/// chain summary, the acknowledgements and the digest).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReviewDraft {
    pub kind: OperationKind,
    pub schema: u16,
    pub title: String,
    pub summary: String,
    pub signer: SignerSummary,
    pub authorizations: Vec<Requirement>,
    pub parties: Vec<Party>,
    pub destinations: Vec<Destination>,
    /// Value sent to others (principal); `None` when the operation moves no principal.
    pub amount: Option<u64>,
    /// Value returned to the signing wallet.
    pub returned: u64,
    pub fee: Fee,
    /// What leaves the signing wallet in total, when it can be stated.
    pub net_debit: Option<u128>,
    pub inputs: Vec<InputLine>,
    pub conditions: Vec<Condition>,
    pub timing: Timing,
    pub effects: Vec<Effect>,
    pub warnings: Vec<Warning>,
    /// Acknowledgements beyond those derived from the rows above.
    pub extra_acks: Vec<AckKind>,
    /// The operation is among the highest-risk ones (a License transfer, a key rotation, a Treasury
    /// action, a bond withdrawal): the person must also type a confirmation phrase derived from the
    /// binding digest. The phrase changes with every review, so a stored or replayed phrase is no
    /// use; a UI must SHOW it for the person to type it (the library cannot know whether it did, and
    /// the phrase is readable through `Review::confirmation_phrase` by any code in the host).
    pub high_risk: bool,
}

/// An immutable review of one operation at one verified head.
#[derive(Clone, PartialEq, Eq)]
pub struct Review {
    draft: ReviewDraft,
    chain: ChainSummary,
    anchor: FinalizedAnchor,
    acknowledgements: Vec<AckKind>,
    binding: ReviewDigest,
}

impl Review {
    /// Seal a draft against the view and the unsigned objects: classify chain facts, derive the
    /// acknowledgements and compute the binding digest.
    pub(crate) fn seal(draft: ReviewDraft, objects: &[PlanObject], view: &ChainView<'_>) -> Self {
        let chain = ChainSummary {
            context: view.context(),
            head_height: view.anchor().height,
            head_block: view.anchor().block,
            state_root: view.state_root(),
            class: view.class(),
        };
        let acknowledgements = derive_acknowledgements(&draft);
        let binding = binding_digest(
            draft.kind,
            draft.schema,
            objects,
            view.anchor(),
            &view.state_root(),
        );
        Self {
            draft,
            chain,
            anchor: view.anchor().clone(),
            acknowledgements,
            binding,
        }
    }

    pub fn kind(&self) -> OperationKind {
        self.draft.kind
    }
    pub fn schema(&self) -> u16 {
        self.draft.schema
    }
    pub fn title(&self) -> &str {
        &self.draft.title
    }
    pub fn summary(&self) -> &str {
        &self.draft.summary
    }
    pub fn chain(&self) -> &ChainSummary {
        &self.chain
    }
    /// The verified head this review is for.
    pub fn anchor(&self) -> &FinalizedAnchor {
        &self.anchor
    }
    pub fn signer(&self) -> &SignerSummary {
        &self.draft.signer
    }
    pub fn authorizations(&self) -> &[Requirement] {
        &self.draft.authorizations
    }
    pub fn parties(&self) -> &[Party] {
        &self.draft.parties
    }
    pub fn destinations(&self) -> &[Destination] {
        &self.draft.destinations
    }
    /// The check displayed and accepted by this review, bound to its verified chain class.
    pub fn destination_check_text(&self, index: usize) -> String {
        self.destinations()[index].check_text_for(self.chain.class)
    }
    pub fn amount(&self) -> Option<u64> {
        self.draft.amount
    }
    pub fn returned(&self) -> u64 {
        self.draft.returned
    }
    pub fn fee(&self) -> &Fee {
        &self.draft.fee
    }
    pub fn net_debit(&self) -> Option<u128> {
        self.draft.net_debit
    }
    pub fn inputs(&self) -> &[InputLine] {
        &self.draft.inputs
    }
    pub fn conditions(&self) -> &[Condition] {
        &self.draft.conditions
    }
    pub fn timing(&self) -> &Timing {
        &self.draft.timing
    }
    pub fn effects(&self) -> &[Effect] {
        &self.draft.effects
    }
    pub fn warnings(&self) -> &[Warning] {
        &self.draft.warnings
    }
    /// The acknowledgements a person must give, derived from the rows above.
    pub fn acknowledgements(&self) -> &[AckKind] {
        &self.acknowledgements
    }
    pub fn binding(&self) -> ReviewDigest {
        self.binding
    }
    /// Whether this review was computed against exactly `view`'s head and state root.
    pub fn is_for(&self, view: &ChainView<'_>) -> bool {
        self.anchor == *view.anchor() && self.chain.state_root == view.state_root()
    }
    /// What a person acknowledging THIS review commits to: the signing wallet, the exact set of
    /// acknowledgements, which destinations carry a typed check and whether a phrase is required.
    /// An approval carries it, and authorization recomputes it from the plan's own review, so an
    /// approval obtained from a different reading of the same bytes (another wallet's view, with
    /// fewer acknowledgements) cannot authorize the plan.
    pub(crate) fn scope(&self) -> Hash {
        let mut body = Vec::new();
        body.extend_from_slice(&self.draft.signer.address);
        body.extend_from_slice(&self.draft.signer.generation.to_be_bytes());
        body.extend_from_slice(&self.draft.signer.authority);
        body.push(match self.draft.signer.profile {
            WalletProfile::Ordinary => 0,
            WalletProfile::Treasury => 1,
        });
        body.push(self.acknowledgements.len() as u8);
        body.extend(self.acknowledgements.iter().map(|ack| ack.code()));
        let checks = self.destinations_needing_check();
        body.extend_from_slice(&(checks.len() as u32).to_be_bytes());
        for index in checks {
            body.extend_from_slice(&(index as u32).to_be_bytes());
        }
        body.push(u8::from(self.draft.high_risk));
        mutiny_consensus_v8::domain_hash(b"MUTINY-BUILD8-WALLET-APPROVAL-SCOPE-V1", &body)
    }
    /// Whether a typed confirmation phrase is required in addition to the acknowledgements.
    pub fn requires_phrase(&self) -> bool {
        self.draft.high_risk
    }
    /// The phrase to type for a high-risk operation: `CONFIRM` and the first eight hexadecimal
    /// characters of the binding digest. It changes with every review, so it cannot be learned.
    pub fn confirmation_phrase(&self) -> Option<String> {
        self.draft
            .high_risk
            .then(|| format!("CONFIRM {}", hex::encode_upper(&self.binding.0[..4])))
    }
    /// Indices of the destinations that need the typed re-entry check.
    pub fn destinations_needing_check(&self) -> Vec<usize> {
        self.draft
            .destinations
            .iter()
            .enumerate()
            .filter(|(_, destination)| destination.needs_typed_check())
            .map(|(index, _)| index)
            .collect()
    }

    /// An address as the rows show it: the checksummed form of this review's verified chain class
    /// (the primary display), then the legacy hexadecimal identifier.
    fn show_address(&self, address: &Hash) -> String {
        format!(
            "{} (legacy hex {})",
            address_format::encode(address, self.chain.class),
            hex::encode(address)
        )
    }

    /// The same with the address's label: `<checksummed> (<label>; legacy hex <hex>)`.
    fn show_labelled(&self, address: &Hash, label: AddressLabel) -> String {
        format!(
            "{} ({}; legacy hex {})",
            address_format::encode(address, self.chain.class),
            label.text(),
            hex::encode(address)
        )
    }

    /// The review as flat rows, in display order.
    pub fn rows(&self) -> Vec<Row> {
        let mut rows = Vec::new();
        let mut put = |section: Section, label: &str, value: String, emphasis: Emphasis| {
            rows.push(Row {
                section,
                label: label.to_string(),
                value,
                emphasis,
            });
        };
        let draft = &self.draft;

        put(
            Section::Summary,
            "Action",
            draft.title.clone(),
            Emphasis::Important,
        );
        put(
            Section::Summary,
            "Summary",
            draft.summary.clone(),
            Emphasis::Normal,
        );
        if self.chain.class == ChainClass::TestValue {
            put(
                Section::Summary,
                "Chain class",
                "TEST-VALUE chain: nothing here has real value".into(),
                Emphasis::Warning,
            );
        }

        let context = &self.chain.context;
        put(
            Section::Chain,
            "Network",
            format!("0x{:08x}", context.network),
            Emphasis::Normal,
        );
        put(
            Section::Chain,
            "Genesis",
            hex::encode(context.genesis),
            Emphasis::Normal,
        );
        put(
            Section::Chain,
            "Protocol fingerprint",
            hex::encode(context.fingerprint),
            Emphasis::Normal,
        );
        put(
            Section::Chain,
            "Verified block height",
            self.chain.head_height.to_string(),
            Emphasis::Normal,
        );
        put(
            Section::Chain,
            "Verified block",
            hex::encode(self.chain.head_block),
            Emphasis::Normal,
        );
        put(
            Section::Chain,
            "State root",
            hex::encode(self.chain.state_root),
            Emphasis::Normal,
        );
        put(
            Section::Chain,
            "Chain class",
            self.chain.class.label().into(),
            Emphasis::Normal,
        );

        put(
            Section::Signer,
            "Signing address",
            self.show_address(&draft.signer.address),
            Emphasis::Normal,
        );
        put(
            Section::Signer,
            "Key generation",
            draft.signer.generation.to_string(),
            Emphasis::Normal,
        );
        put(
            Section::Signer,
            "Wallet authority",
            self.show_address(&draft.signer.authority),
            Emphasis::Normal,
        );
        put(
            Section::Signer,
            "Profile",
            draft.signer.profile.label().into(),
            Emphasis::Normal,
        );

        for requirement in &draft.authorizations {
            let who = match requirement.signer {
                RequiredSigner::Wallet(address) => {
                    format!("wallet {}", self.show_address(&address))
                }
                RequiredSigner::Maker(identity) => format!("maker {}", hex::encode(identity)),
            };
            let status = match requirement.status {
                RequirementStatus::ThisWallet => "this wallet signs",
                RequirementStatus::Counterparty => "a counterparty must sign",
                RequirementStatus::Maker => "the maker must sign",
                RequirementStatus::Provided => "already provided and verified",
            };
            put(
                Section::Authorizations,
                &slot_label(requirement.slot),
                format!("{status}; {who}"),
                Emphasis::Normal,
            );
        }

        for party in &draft.parties {
            // A maker is named by the hash of its WalletOwner descriptor, which is not an
            // address: it is never shown in the address form.
            let value = if party.role == PartyRole::Maker {
                format!(
                    "{} (the maker's descriptor commitment, not an address)",
                    hex::encode(party.address)
                )
            } else {
                self.show_labelled(&party.address, party.label)
            };
            put(Section::Parties, party.role.text(), value, Emphasis::Normal);
        }

        for destination in &draft.destinations {
            let emphasis = if destination.needs_typed_check() {
                Emphasis::Important
            } else {
                Emphasis::Normal
            };
            put(
                Section::Money,
                destination.role.text(),
                format!(
                    "{} to {}",
                    units::format_amount(destination.atoms),
                    self.show_labelled(&destination.address, destination.label)
                ),
                emphasis,
            );
            if destination.needs_typed_check() {
                put(
                    Section::Money,
                    "Type to confirm destination",
                    destination.check_text_for(self.chain.class),
                    Emphasis::Important,
                );
            }
        }
        if let Some(amount) = draft.amount {
            put(
                Section::Money,
                "Amount",
                units::format_amount(amount),
                Emphasis::Important,
            );
        }
        let fee = &draft.fee;
        let payer = match fee.payer {
            FeePayer::ThisWallet => "paid by this wallet".to_string(),
            FeePayer::Counterparty(address) => format!("paid by {}", self.show_address(&address)),
            FeePayer::Protocol => "paid by nobody (exempt)".to_string(),
            FeePayer::NotApplicable => "not applicable".to_string(),
        };
        let size = fee
            .size_bytes
            .map(|bytes| format!(", signed size {bytes} bytes"))
            .unwrap_or_default();
        put(
            Section::Money,
            "Network fee",
            format!(
                "{}; {}; {}{}",
                units::format_amount(fee.atoms),
                fee.rule.text(),
                payer,
                size
            ),
            Emphasis::Important,
        );
        if let Some(net) = draft.net_debit {
            put(
                Section::Money,
                "Total leaving this wallet",
                units::format_mut_wide(net),
                Emphasis::Important,
            );
        }
        if !draft.inputs.is_empty() {
            let total: u128 = draft
                .inputs
                .iter()
                .map(|input| u128::from(input.atoms))
                .sum();
            put(
                Section::Money,
                "Inputs",
                format!(
                    "{} coin(s) worth {}",
                    draft.inputs.len(),
                    units::format_mut_wide(total)
                ),
                Emphasis::Normal,
            );
            for (index, input) in draft.inputs.iter().enumerate() {
                let owner = if input.owned_by_signer {
                    "this wallet"
                } else {
                    "another wallet"
                };
                let kind = if input.coinbase { ", coinbase" } else { "" };
                put(
                    Section::Money,
                    &format!("Input {index}"),
                    format!(
                        "{}:{} worth {} ({owner}{kind})",
                        hex::encode(input.point.transaction),
                        input.point.index,
                        units::format_mut(input.atoms)
                    ),
                    Emphasis::Normal,
                );
            }
        }

        for condition in &draft.conditions {
            put(
                Section::Conditions,
                &condition.label,
                condition.detail.clone(),
                Emphasis::Normal,
            );
        }

        let timing = &draft.timing;
        put(
            Section::Timing,
            "Valid from block",
            opt_height(timing.created_height),
            Emphasis::Normal,
        );
        put(
            Section::Timing,
            "Valid until block",
            expiry_text(timing),
            Emphasis::Normal,
        );
        if let Some(only) = timing.valid_only_at {
            put(
                Section::Timing,
                "Valid only in block",
                only.to_string(),
                Emphasis::Warning,
            );
        }
        if timing.bound_to_parent {
            put(
                Section::Timing,
                "Bound to parent block",
                "valid only in the very next block".into(),
                Emphasis::Warning,
            );
        }
        if let Some(earliest) = timing.earliest_height {
            put(
                Section::Timing,
                "Earliest height",
                earliest_text(timing.head_height, earliest),
                Emphasis::Important,
            );
        }
        if let Some(epoch) = timing.deadline_epoch {
            put(
                Section::Timing,
                "Deadline epoch",
                epoch.to_string(),
                Emphasis::Important,
            );
        }

        for effect in &draft.effects {
            let (label, emphasis) = if effect.irreversible {
                ("Irreversible", Emphasis::Irreversible)
            } else {
                ("Effect", Emphasis::Normal)
            };
            put(Section::Effects, label, effect.text.clone(), emphasis);
        }

        for warning in &draft.warnings {
            let label = match warning.severity {
                Severity::Notice => "Notice",
                Severity::Caution => "Caution",
                Severity::Danger => "Danger",
            };
            put(
                Section::Warnings,
                label,
                warning.text.clone(),
                Emphasis::Warning,
            );
        }

        for ack in &self.acknowledgements {
            put(
                Section::Acknowledgements,
                "Required",
                ack.statement().into(),
                Emphasis::Important,
            );
        }
        if let Some(phrase) = self.confirmation_phrase() {
            put(
                Section::Acknowledgements,
                "Type to confirm",
                phrase,
                Emphasis::Important,
            );
        }

        put(
            Section::Binding,
            "Review digest",
            self.binding.to_hex(),
            Emphasis::Normal,
        );
        rows
    }

    /// The review as plain text, one `label: value` line per row under section headings. Stable
    /// output: golden tests pin it.
    pub fn render_text(&self) -> String {
        let mut text = String::new();
        let mut current: Option<Section> = None;
        for row in self.rows() {
            if current != Some(row.section) {
                if current.is_some() {
                    text.push('\n');
                }
                text.push_str(&format!("== {} ==\n", row.section.title()));
                current = Some(row.section);
            }
            text.push_str(&format!(
                "{}{}: {}\n",
                row.emphasis.marker(),
                row.label,
                row.value
            ));
        }
        text
    }
}

impl fmt::Debug for Review {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Review")
            .field("kind", &self.draft.kind)
            .field("head_height", &self.chain.head_height)
            .field("destinations", &self.draft.destinations.len())
            .field("warnings", &self.draft.warnings.len())
            .field("acknowledgements", &self.acknowledgements)
            .field("binding", &self.binding)
            .finish()
    }
}

fn slot_label(slot: Slot) -> String {
    let text = slot.to_string();
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => text,
    }
}

fn opt_height(height: Option<u64>) -> String {
    height.map_or_else(|| "not applicable".to_string(), |h| h.to_string())
}

fn expiry_text(timing: &Timing) -> String {
    match timing.expiry_height {
        None => "not applicable".to_string(),
        Some(expiry) => {
            let remaining = expiry.saturating_sub(timing.head_height);
            format!(
                "{expiry} ({remaining} blocks after the verified block; {}, approximate at the {} s target interval)",
                units::approx_blocks(remaining),
                units::TARGET_BLOCK_SECONDS
            )
        }
    }
}

fn earliest_text(head: u64, earliest: u64) -> String {
    if earliest <= head {
        format!("{earliest} (reached)")
    } else {
        let wait = earliest - head;
        format!(
            "{earliest} ({wait} blocks after the verified block; {}, approximate at the {} s target interval)",
            units::approx_blocks(wait),
            units::TARGET_BLOCK_SECONDS
        )
    }
}

/// The acknowledgements a draft requires, derived from its rows.
fn derive_acknowledgements(draft: &ReviewDraft) -> Vec<AckKind> {
    let mut set = BTreeSet::new();
    if draft
        .destinations
        .iter()
        .any(Destination::needs_typed_check)
    {
        set.insert(AckKind::Destination);
    }
    if draft.amount.is_some_and(|amount| amount > 0) {
        set.insert(AckKind::Amount);
    }
    if draft.fee.atoms > 0 {
        set.insert(AckKind::Fee);
    }
    if draft.effects.iter().any(|effect| effect.irreversible) {
        set.insert(AckKind::Irreversible);
    }
    for warning in &draft.warnings {
        if let Some(ack) = warning.requires {
            set.insert(ack);
        }
    }
    set.extend(draft.extra_acks.iter().copied());
    set.into_iter().collect()
}

// ---------------------------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------------------------

/// Review a plan built by this wallet against the verified chain.
///
/// Runs the kind's pre-signing validation first, so a review never describes an operation that
/// consensus would refuse at this head.
pub fn review(plan: &OperationPlan, view: &ChainView<'_>) -> Result<Review, Refusal> {
    let handler = crate::ops::handler(plan.kind())?;
    handler.validate(plan, view)?;
    let draft = handler.review(plan, view)?;
    Ok(Review::seal(draft, &handler.reviewed_objects(plan)?, view))
}

/// Explain bytes received from someone else (an unsigned proposal, a partial approval's object or
/// a signed operation) as seen from `me`. The digest equals the one the proposer's own review of
/// the same unsigned bytes at the same head would produce.
pub fn explain(raw: &[u8], view: &ChainView<'_>, me: &SignerIdentity) -> Result<Review, Refusal> {
    let handler = crate::ops::recognizing(raw).ok_or(Refusal::UnknownOperation)?;
    let (draft, objects) = handler.explain(raw, view, me)?;
    Ok(Review::seal(draft, &objects, view))
}

/// Shared fixtures for unit tests of other modules.
#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// A minimal draft that asks for no acknowledgement of its own: nothing leaves the wallet, no
    /// fee, no irreversible effect.
    pub(crate) fn sample_draft(high_risk: bool) -> ReviewDraft {
        ReviewDraft {
            kind: OperationKind::Payment,
            schema: 1,
            title: "t".into(),
            summary: "s".into(),
            signer: SignerSummary {
                address: [1; 32],
                generation: 1,
                authority: [1; 32],
                profile: WalletProfile::Ordinary,
            },
            authorizations: vec![],
            parties: vec![],
            destinations: vec![],
            amount: None,
            returned: 0,
            fee: Fee {
                atoms: 0,
                rule: FeeRule::Exempt,
                payer: FeePayer::Protocol,
                size_bytes: None,
            },
            net_debit: None,
            inputs: vec![],
            conditions: vec![],
            timing: Timing {
                head_height: 1,
                created_height: None,
                expiry_height: None,
                valid_only_at: None,
                bound_to_parent: false,
                earliest_height: None,
                deadline_epoch: None,
            },
            effects: vec![],
            warnings: vec![],
            extra_acks: vec![],
            high_risk,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_binds_every_field_and_length_prefixes_objects() {
        let anchor = FinalizedAnchor {
            network: mutiny_consensus_v8::NETWORK_ID,
            genesis: [1; 32],
            fingerprint: [2; 32],
            height: 7,
            block: [3; 32],
        };
        let objects = vec![PlanObject::new("transfer", vec![1, 2, 3])];
        let base = binding_digest(OperationKind::Payment, 1, &objects, &anchor, &[9; 32]);
        assert_eq!(
            base,
            binding_digest(OperationKind::Payment, 1, &objects, &anchor, &[9; 32])
        );
        assert_ne!(
            base,
            binding_digest(
                OperationKind::WalletRotation,
                1,
                &objects,
                &anchor,
                &[9; 32]
            )
        );
        assert_ne!(
            base,
            binding_digest(OperationKind::Payment, 2, &objects, &anchor, &[9; 32])
        );
        assert_ne!(
            base,
            binding_digest(
                OperationKind::Payment,
                1,
                &[PlanObject::new("transfer", vec![1, 2, 4])],
                &anchor,
                &[9; 32]
            )
        );
        assert_ne!(
            base,
            binding_digest(
                OperationKind::Payment,
                1,
                &[PlanObject::new("other", vec![1, 2, 3])],
                &anchor,
                &[9; 32]
            )
        );
        let mut moved = anchor.clone();
        moved.height += 1;
        assert_ne!(
            base,
            binding_digest(OperationKind::Payment, 1, &objects, &moved, &[9; 32])
        );
        let mut other_block = anchor.clone();
        other_block.block[0] ^= 1;
        assert_ne!(
            base,
            binding_digest(OperationKind::Payment, 1, &objects, &other_block, &[9; 32])
        );
        assert_ne!(
            base,
            binding_digest(OperationKind::Payment, 1, &objects, &anchor, &[8; 32])
        );
        // Moving a byte between two objects must change the digest.
        let split_a = vec![
            PlanObject::new("a", vec![1, 2]),
            PlanObject::new("b", vec![3]),
        ];
        let split_b = vec![
            PlanObject::new("a", vec![1]),
            PlanObject::new("b", vec![2, 3]),
        ];
        assert_ne!(
            binding_digest(OperationKind::Payment, 1, &split_a, &anchor, &[9; 32]),
            binding_digest(OperationKind::Payment, 1, &split_b, &anchor, &[9; 32])
        );
        assert_eq!(base.to_hex().len(), 64);
        assert!(format!("{base:?}").starts_with("ReviewDigest("));
    }

    #[test]
    fn acknowledgements_follow_the_rows() {
        let signer = SignerSummary {
            address: [1; 32],
            generation: 1,
            authority: [1; 32],
            profile: WalletProfile::Ordinary,
        };
        let mut draft = ReviewDraft {
            kind: OperationKind::Payment,
            schema: 1,
            title: "t".into(),
            summary: "s".into(),
            signer,
            authorizations: vec![],
            parties: vec![],
            destinations: vec![Destination {
                role: DestinationRole::Change,
                address: [1; 32],
                label: AddressLabel::ThisWallet,
                atoms: 5,
            }],
            amount: Some(0),
            returned: 5,
            fee: Fee {
                atoms: 0,
                rule: FeeRule::Exempt,
                payer: FeePayer::Protocol,
                size_bytes: None,
            },
            net_debit: None,
            inputs: vec![],
            conditions: vec![],
            timing: Timing {
                head_height: 1,
                created_height: None,
                expiry_height: None,
                valid_only_at: None,
                bound_to_parent: false,
                earliest_height: None,
                deadline_epoch: None,
            },
            effects: vec![],
            warnings: vec![],
            extra_acks: vec![],
            high_risk: false,
        };
        assert!(
            derive_acknowledgements(&draft).is_empty(),
            "own address, zero amount, no fee, no irreversible effect"
        );
        draft.destinations.push(Destination {
            role: DestinationRole::Payment,
            address: [2; 32],
            label: AddressLabel::External,
            atoms: 9,
        });
        draft.amount = Some(9);
        draft.fee.atoms = 1;
        draft.effects.push(Effect::new("gone", true));
        draft
            .warnings
            .push(Warning::new("W", Severity::Caution, "careful").requiring(AckKind::KeyLoss));
        draft.extra_acks.push(AckKind::Conditions);
        assert_eq!(
            derive_acknowledgements(&draft),
            vec![
                AckKind::Destination,
                AckKind::Amount,
                AckKind::Fee,
                AckKind::Conditions,
                AckKind::Irreversible,
                AckKind::KeyLoss
            ]
        );
    }

    #[test]
    fn only_this_wallets_own_addresses_skip_the_typed_check() {
        // The new key of a rotation is this wallet's in intent but unknown to the chain: it keeps
        // the typed check, like every label except `ThisWallet`.
        for (label, typed) in [
            (AddressLabel::ThisWallet, false),
            (AddressLabel::Treasury, true),
            (AddressLabel::Escrow, true),
            (AddressLabel::External, true),
            (AddressLabel::NewKey, true),
        ] {
            assert_eq!(label.needs_typed_check(), typed, "{label:?}");
            assert!(!label.text().is_empty());
        }
        assert_ne!(AddressLabel::NewKey.text(), AddressLabel::External.text());
    }

    #[test]
    fn every_acknowledgement_has_a_statement() {
        for ack in [
            AckKind::Destination,
            AckKind::Amount,
            AckKind::Fee,
            AckKind::Conditions,
            AckKind::Irreversible,
            AckKind::ExternalEvidence,
            AckKind::NoUnilateralExit,
            AckKind::KeyLoss,
            AckKind::TreasuryAuthority,
            AckKind::UnboundDividends,
            AckKind::SingleBlockWindow,
            AckKind::DisclosesPreimage,
        ] {
            assert!(ack.statement().starts_with("I "));
        }
    }
}
