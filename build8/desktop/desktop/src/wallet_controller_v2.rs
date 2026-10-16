//! Candidate single-owner wallet controller, UI-FREE (phase 7). No installed-wallet lookup, network
//! I/O, private-key export or production qualification override.
//!
//! The desktop is a thin shell over wallet-core. This controller owns:
//!  * the vault (`Store`) and, while unlocked, wallet-core's `KeySigner`: the vault session's key
//!    MOVES into the signer at unlock, so it exists only there (erased on lock, idle expiry, drop);
//!  * the verified `Replica`, the ONLY source of every `ChainView` (head, timestamp, epoch origin and
//!    state root from the locally replayed canonical store; `ChainView::verified` recomputes the
//!    root; `reserved` = the payment pool's reservations plus `Outbox::reserved()` of the operation
//!    outbox; the store's confirmation index attached). Never a peer's claim;
//!  * the payment pool (`Mempool`: durable queue and transport of payments) and the protected
//!    operation outbox (`OperationOutbox`: every other kind, sealed at rest, export only, Q1);
//!  * the preimage store (`PreimageVault`, Q13);
//!  * at most ONE plan on screen (`ActivePlan`: wallet-core's `PlanSession` and its `ReviewGate`).
//!
//! Every command first brings the plan to the current verified head (`PlanSession::on_head`, Q2:
//! a review or approval for any other head is dropped). Approval and authorization happen in ONE
//! step inside this controller (`ReviewInput::Authorize`): `ReviewGate::approve` (every typed
//! destination check, every acknowledgement, the phrase of a high-risk review, a fresh review at the
//! current head), `Signer::authorize` (independent verification through consensus code), then the
//! durable queue, before success is reported. An approval never leaves the controller. The idle
//! lock (and every lock) erases the key and clears the gate, which WITHDRAWS any approval it issued.
use crate::{
    operation_outbox::OperationOutbox,
    plan_review::{Countdown, GateStatus, ReviewInput, ReviewScreen},
    preimage_store::PreimageVault,
    store_v2::{Store, VaultStatus},
    verified_sync_v2::{Delivery, Replica},
    wallet_v2::{Identity, RestoredKey, Session},
};
use mutiny_consensus_v8::{
    Hash, anchors::FinalizedAnchor, execution::State, mempool_v2::Mempool, transactions::OutPoint,
};
use mutiny_crypto_v2::PublicKey;
use mutiny_wallet_core_v8::{
    Blob, ChainContext, ChainView, ClaimRequest, FeeSource, HeadInfo, KeySigner, OperationKind,
    OperationPlan, OperationRequest, Outbox, PartialApproval, PaymentRequest, PlanPhase,
    PlanSession, Refusal, Requirement, Review, ReviewDigest, RotationRequest, SignedOperation,
    Signer, SigningGate, Validity, WalletProfile, offers,
    ops::conditional::PreimageStore,
    ops::rotation::RotationSigner,
    profile::{self, TreasuryDeclaration},
};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;
type Result<T> = std::result::Result<T, String>;
/// What the test hook `ActivePlan::approve_for_test` returns (a named type keeps the hook's
/// signature free of a top-level `,`, which the signing-call tripwire's item model would read as
/// the end of the test item).
#[cfg(test)]
type TestApproval = std::result::Result<mutiny_wallet_core_v8::Approval, Refusal>;
const IDLE_LIMIT: Duration = Duration::from_secs(300);

fn text(refusal: Refusal) -> String {
    format!("{refusal} ({})", refusal.code())
}

/// The signing gate of this build. A shipping build has only wallet-core's production gate, which
/// refuses while `PRODUCTION_SECURITY_QUALIFIED` is false (and `wallet_v2::ready()` refuses before
/// it is ever reached). A test build uses wallet-core's TEST-VALUE gate, which exists only because
/// the desktop's DEV-dependency enables the non-shipping feature for tests.
fn signing_gate() -> std::result::Result<SigningGate, Refusal> {
    if cfg!(test) || cfg!(feature = "testvalue-window") {
        test_gate()
    } else {
        SigningGate::production()
    }
}
#[cfg(any(test, feature = "testvalue-window"))]
fn test_gate() -> std::result::Result<SigningGate, Refusal> {
    SigningGate::test_value()
}
#[cfg(not(any(test, feature = "testvalue-window")))]
fn test_gate() -> std::result::Result<SigningGate, Refusal> {
    Err(Refusal::GateClosed)
}

/// Where the vault and its sibling stores live: chosen by EXPLICIT runtime configuration only (phase
/// 0C removed every default path; Order W11, candidate 3, confirms and pins it). The root comes from
/// exactly one source: the argument `--vault-root <absolute path>` ([`VaultRoot::from_args`]); there is
/// no environment variable, no default folder and no current-directory fallback, and no production
/// code of the desktop reads the environment, the current directory or a profile folder (test
/// `production_code_reads_no_environment_variable_or_current_directory`). The custody folder and every
/// file name below the root are fixed, and `custody_acl_v2` refuses anything else.
///
/// The seam for a later launcher (documented here; NOT implemented): a launcher that holds a path it
/// has verified itself (one it created and checked, or an installer-registered path it re-verified)
/// passes it as `--vault-root <path>` on the command line it builds, or calls [`VaultRoot::new`]; the
/// same rules apply, and the signing flow never learns how the path was chosen (the controller
/// receives only the `VaultRoot`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultRoot(PathBuf);

/// Why a vault root was refused (Order W11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultRootError {
    /// No argument at all: there is no default location.
    Missing,
    /// `--vault-root` without its path.
    MissingValue,
    /// Anything but exactly `--vault-root <path>`: another flag, a repeated flag, an extra argument,
    /// the `--vault-root=<path>` form.
    UnexpectedArguments,
    /// An empty path.
    Empty,
    /// Not valid Unicode (on Windows: an unpaired UTF-16 surrogate).
    NotUnicode,
    /// Relative, drive-relative (`C:wallet`) or root-relative (`\wallet`): each would be resolved
    /// against a current directory, which is never used.
    NotAbsolute,
    /// A network (UNC) or device path (`\\server\share`, `\\?\UNC\...`, `\\.\...`,
    /// `\\?\GLOBALROOT\...`, a volume GUID path): the custody folder needs a local drive path whose
    /// ACL and leases this build verifies (`custody_acl_v2` accepts drive paths only).
    NetworkOrDevicePath,
    /// A `.`, `..` or empty component.
    TraversalComponent,
    /// A character Windows does not allow in a file name (`< > : " | ? *`, a control character
    /// including NUL), or `/` in a verbatim path; this covers alternate data streams (`name:stream`).
    InvalidCharacter,
    /// A component that ends in a dot or a space (Windows strips them, so the folder used would not
    /// be the folder named).
    TrailingDotOrSpace,
    /// A reserved device name (`CON`, `PRN`, `AUX`, `NUL`, `COM0`-`COM9`, `LPT0`-`LPT9`,
    /// `CONIN$`, `CONOUT$`, with or without an extension) as a component.
    ReservedName,
    /// Longer than [`MAX_VAULT_ROOT_UNITS`] UTF-16 units.
    TooLong,
}

impl std::fmt::Display for VaultRootError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Missing => "Start the wallet with --vault-root <absolute path>: there is no default vault location",
            Self::MissingValue => "--vault-root needs the absolute path of the vault folder",
            Self::UnexpectedArguments => "The wallet takes exactly --vault-root <absolute path> and nothing else",
            Self::Empty => "The vault root is empty",
            Self::NotUnicode => "The vault root is not valid Unicode",
            Self::NotAbsolute => "The vault root must be an absolute path on a drive (for example a folder under a drive letter); relative paths are not resolved",
            Self::NetworkOrDevicePath => "The vault root must be a local drive path, not a network or device path",
            Self::TraversalComponent => "The vault root must not contain '.', '..' or empty components",
            Self::InvalidCharacter => "The vault root contains a character Windows does not allow in a folder name",
            Self::TrailingDotOrSpace => "A folder name in the vault root ends in a dot or a space, which Windows would strip",
            Self::ReservedName => "A folder name in the vault root is a reserved Windows device name",
            Self::TooLong => "The vault root is too long: the custody files below it must stay within the Windows path limit",
        })
    }
}

impl std::error::Error for VaultRootError {}

/// The longest vault root accepted, in UTF-16 units: the longest custody path below it
/// (`<root>\WalletCustodyV2\operation-outbox-v1.sqlite-journal`, 51 more units) then stays within the
/// Windows path limit of 260.
pub const MAX_VAULT_ROOT_UNITS: usize = 200;

/// Whether `name` is a reserved Windows device name (compared without case, before the first dot).
fn reserved_device_name(name: &str) -> bool {
    // The text before the first dot, without trailing spaces: "CON .txt" names the device CON for
    // the classic Win32 path rules (review F5; test `reserved_names_cover_every_name_windows_treats_as_a_device`).
    let base = name
        .split('.')
        .next()
        .unwrap_or(name)
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    if matches!(
        base.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return true;
    }
    let mut chars = base.chars();
    let prefix: String = chars.by_ref().take(3).collect();
    let rest: String = chars.collect();
    (prefix == "COM" || prefix == "LPT")
        && rest.chars().count() == 1
        && rest
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '\u{b9}' | '\u{b2}' | '\u{b3}'))
}

/// The W11 rules for an explicit vault root (see [`VaultRootError`]). Pure: it reads no file, no
/// environment variable and no current directory.
fn validate_root(raw: &std::ffi::OsStr) -> std::result::Result<(), VaultRootError> {
    let text = raw.to_str().ok_or(VaultRootError::NotUnicode)?;
    if text.is_empty() {
        return Err(VaultRootError::Empty);
    }
    if text.encode_utf16().count() > MAX_VAULT_ROOT_UNITS {
        return Err(VaultRootError::TooLong);
    }
    if text.chars().any(char::is_control) {
        return Err(VaultRootError::InvalidCharacter);
    }
    let (rest, verbatim) = match text.strip_prefix("\\\\?\\") {
        Some(rest) => (rest, true),
        None if text.starts_with("\\\\")
            || text.starts_with("//")
            || text.starts_with("\\/")
            || text.starts_with("/\\") =>
        {
            return Err(VaultRootError::NetworkOrDevicePath);
        }
        None => (text, false),
    };
    let separator = |c: char| c == '\\' || (!verbatim && c == '/');
    let bytes = rest.as_bytes();
    let drive = bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':';
    if !drive {
        // `\\?\UNC\...`, `\\?\GLOBALROOT\...`, `\\?\Volume{...}\...` are not local drive paths.
        return Err(if verbatim {
            VaultRootError::NetworkOrDevicePath
        } else {
            VaultRootError::NotAbsolute
        });
    }
    // "C:" alone and "C:wallet" are relative to the drive's current directory.
    if !rest[2..].starts_with(separator) {
        return Err(VaultRootError::NotAbsolute);
    }
    let mut parts: Vec<&str> = rest[3..].split(separator).collect();
    // One trailing separator is accepted ("...\Wallets\"); the drive root itself has no component.
    if parts.last() == Some(&"") {
        parts.pop();
    }
    for part in parts {
        if part.is_empty() || part == "." || part == ".." {
            return Err(VaultRootError::TraversalComponent);
        }
        if part
            .chars()
            .any(|c| matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*') || (verbatim && c == '/'))
        {
            return Err(VaultRootError::InvalidCharacter);
        }
        if part.ends_with('.') || part.ends_with(' ') {
            return Err(VaultRootError::TrailingDotOrSpace);
        }
        if reserved_device_name(part) {
            return Err(VaultRootError::ReservedName);
        }
    }
    Ok(())
}

impl VaultRoot {
    /// An explicit root (the W11 rules of [`VaultRootError`]). The seam for a later launcher.
    pub fn new(path: &Path) -> std::result::Result<Self, VaultRootError> {
        validate_root(path.as_os_str())?;
        Ok(Self(path.to_path_buf()))
    }
    /// The vault root from the command line: exactly `--vault-root <absolute path>`; there is no
    /// default, no environment fallback and no current-directory fallback.
    pub fn from_args(args: &[std::ffi::OsString]) -> std::result::Result<Self, VaultRootError> {
        match args {
            [] => Err(VaultRootError::Missing),
            [flag] if flag == "--vault-root" => Err(VaultRootError::MissingValue),
            [flag, path] if flag == "--vault-root" => Self::new(Path::new(path)),
            _ => Err(VaultRootError::UnexpectedArguments),
        }
    }
    /// The root as given.
    pub fn path(&self) -> &Path {
        &self.0
    }
    pub fn custody(&self) -> PathBuf {
        self.0.join("WalletCustodyV2")
    }
    pub fn vault(&self) -> PathBuf {
        self.custody().join("wallet-hybrid-v2.sqlite")
    }
    pub fn operation_outbox(&self) -> PathBuf {
        self.custody().join(crate::operation_outbox::FILE_NAME)
    }
    pub fn preimages(&self) -> PathBuf {
        self.custody().join(crate::preimage_store::FILE_NAME)
    }
    /// Take the lifetime owner of this root BEFORE any same-root store is opened, created or
    /// configured: first the read-only format/path admission (Order W7, which opens no database),
    /// then the unshared owner lock. A second instance of the same root is refused here, before it
    /// reaches any SQLite open.
    pub(crate) fn take_owner(&self) -> Result<OwnerLock> {
        crate::wallet_v2::ready().map_err(str::to_owned)?;
        crate::custody_format::check_vault_root(&self.0).map_err(|format| format.to_string())?;
        OwnerLock::acquire(&self.0)
    }
}

/// Why the previous identity was not retired (Order W16). Nothing was deleted in any case.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetirementRefusal {
    /// The vault keeps no previous identity.
    NothingToRetire,
    /// The kept identity is not the active identity's immediate predecessor in the same wallet
    /// lineage (same authority, generation one lower): the vault was damaged or edited.
    NotThePredecessor,
    /// The verified chain does not (yet, or any longer) record the active identity as the current
    /// key of the wallet's authority, so the previous key may still be the key with authority.
    /// `chain_generation` is the generation the verified chain records (`None`: no current key).
    SuccessorNotCanonical { chain_generation: Option<u64> },
    /// The vault refused (no vault, a wrong password, a concurrent change).
    Vault(String),
    /// The verified view could not be built.
    View(String),
}

impl std::fmt::Display for RetirementRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NothingToRetire => f.write_str("No previous identity is kept"),
            Self::NotThePredecessor => f.write_str(
                "The kept identity is not the previous generation of this wallet's key; nothing was deleted",
            ),
            Self::SuccessorNotCanonical { chain_generation } => write!(
                f,
                "The active identity is not the chain's current authority yet (the verified chain records {}); the previous identity is kept",
                match chain_generation {
                    Some(generation) => format!("generation {generation}"),
                    None => "no current key for this wallet".into(),
                }
            ),
            Self::Vault(reason) => write!(f, "The vault refused: {reason}"),
            Self::View(reason) => write!(f, "The verified chain could not be read: {reason}"),
        }
    }
}

impl std::error::Error for RetirementRefusal {}

/// Order W16: whether the vault's previous identity may be retired, given what the VERIFIED chain
/// records as the current descriptor of the wallet's authority (`chain_current`). Pure: it reads
/// nothing else. The kept identity must be the active identity's immediate predecessor in the same
/// lineage, and the verified chain must record exactly the active identity as current.
pub(crate) fn retirement_allowed(
    status: &VaultStatus,
    chain_current: Option<&[u8]>,
) -> std::result::Result<(), RetirementRefusal> {
    let Some(previous) = &status.superseded else {
        return Err(RetirementRefusal::NothingToRetire);
    };
    let active = &status.active;
    if previous.authority_id != active.authority_id
        || previous.generation.checked_add(1) != Some(active.generation)
        || previous.owner_descriptor == active.owner_descriptor
    {
        return Err(RetirementRefusal::NotThePredecessor);
    }
    match chain_current {
        Some(current) if hex::encode(current) == active.owner_descriptor => Ok(()),
        other => Err(RetirementRefusal::SuccessorNotCanonical {
            chain_generation: other
                .and_then(|raw| PublicKey::decode_descriptor(raw).ok())
                .map(|(_, generation)| generation),
        }),
    }
}

/// The one plan on screen: wallet-core's `PlanSession` (plan, phase, `ReviewGate`) plus what the
/// gate does not report back (which typed destination checks and whether the phrase were entered
/// correctly), the last refusal of an input and a notice for the person. UI-free.
pub(crate) struct ActivePlan {
    session: PlanSession,
    kind: OperationKind,
    validity: Validity,
    /// The last review presented (shown as stale when the session dropped it).
    last_review: Option<Review>,
    /// The review the shadow state below belongs to.
    shown: Option<ReviewDigest>,
    confirmed: BTreeSet<usize>,
    phrase: bool,
    refusal: Option<Refusal>,
    notice: Option<String>,
}

impl ActivePlan {
    pub(crate) fn new(plan: OperationPlan) -> Self {
        Self {
            kind: plan.kind(),
            validity: *plan.validity(),
            session: PlanSession::new(plan),
            last_review: None,
            shown: None,
            confirmed: BTreeSet::new(),
            phrase: false,
            refusal: None,
            notice: None,
        }
    }
    pub(crate) fn kind(&self) -> OperationKind {
        self.kind
    }
    pub(crate) fn phase(&self) -> PlanPhase {
        self.session.phase()
    }
    /// Compute the review at `view` and put it on screen (a new review clears every confirmation).
    pub(crate) fn present(&mut self, view: &ChainView<'_>) -> std::result::Result<(), Refusal> {
        let review = self.session.present(view)?.clone();
        if self.shown != Some(review.binding()) {
            self.confirmed.clear();
            self.phrase = false;
            self.shown = Some(review.binding());
        }
        self.last_review = Some(review);
        Ok(())
    }
    /// A new verified head: wallet-core drops a review or approval for any other head (and
    /// invalidates a plan whose window closed); a plan that went back to `Planned` is reviewed
    /// again at the new head, with every confirmation to be given again.
    pub(crate) fn on_head(&mut self, view: &ChainView<'_>) {
        let before = self.session.phase();
        self.session.on_head(view);
        match self.session.phase() {
            PlanPhase::Planned if before != PlanPhase::Planned => {
                self.notice = Some(format!(
                    "The verified chain moved to block {}: this is a new review; give every confirmation again.",
                    view.anchor().height
                ));
                if let Err(refusal) = self.present(view) {
                    self.refusal = Some(refusal);
                }
            }
            PlanPhase::Invalidated(_) if !before.is_terminal() => {
                self.notice = Some(format!(
                    "The operation can no longer be included (its last block was {}): request it again.",
                    self.validity.expiry
                ));
            }
            _ => {}
        }
    }
    /// Apply one input of the person (not Authorize or Cancel) to the gate.
    pub(crate) fn apply(&mut self, input: &ReviewInput) -> std::result::Result<(), Refusal> {
        let result = match input {
            ReviewInput::Acknowledge(ack) => self.session.acknowledge(*ack),
            ReviewInput::ConfirmDestination { index, typed } => {
                self.session.confirm_destination(*index, typed).map(|()| {
                    self.confirmed.insert(*index);
                })
            }
            ReviewInput::ConfirmPhrase(typed) => self
                .session
                .confirm_phrase(typed)
                .map(|()| self.phrase = true),
            ReviewInput::Authorize | ReviewInput::Cancel => Err(Refusal::NotPresented),
        };
        self.refusal = result.clone().err();
        result
    }
    /// The screen: the review and what the gate says about it at `view`.
    pub(crate) fn screen(&self, view: &ChainView<'_>) -> Option<ReviewScreen> {
        let review = self.session.review().or(self.last_review.as_ref())?.clone();
        let gate = self.session.gate();
        let fresh = self.session.phase() == PlanPhase::Presented
            && self.session.review().is_some()
            && review.is_for(view);
        let pending = gate.pending_acknowledgements();
        let acknowledged = if fresh {
            review
                .acknowledgements()
                .iter()
                .filter(|ack| !pending.contains(ack))
                .copied()
                .collect()
        } else {
            Vec::new()
        };
        let status = GateStatus {
            digest: review.binding(),
            fresh,
            acknowledged,
            destinations_confirmed: if fresh {
                self.confirmed.iter().copied().collect()
            } else {
                Vec::new()
            },
            phrase_confirmed: fresh && self.phrase,
            ready: fresh && gate.is_ready(view),
            countdown: Countdown::of(&self.validity, view.anchor().height),
            refusal: self
                .refusal
                .as_ref()
                .map(|r| (r.code().to_string(), r.to_string())),
            notice: self.notice.clone(),
        };
        Some(ReviewScreen { review, status })
    }
    /// `ReviewGate::approve` then `Signer::authorize`, in one step: the approval never leaves this
    /// function. After a refusal of the authorization the plan is reviewed again from scratch.
    pub(crate) fn authorize<S: Signer + ?Sized>(
        &mut self,
        signer: &S,
        view: &ChainView<'_>,
    ) -> std::result::Result<SignedOperation, Refusal> {
        self.on_head(view);
        let approval = match self.session.approve(view) {
            Ok(approval) => approval,
            Err(refusal) => {
                self.refusal = Some(refusal.clone());
                return Err(refusal);
            }
        };
        match self.session.authorize(signer, approval, view) {
            Ok(signed) => Ok(signed),
            Err(refusal) => {
                self.refusal = Some(refusal.clone());
                if let Err(again) = self.present(view) {
                    self.refusal = Some(again);
                }
                Err(refusal)
            }
        }
    }
    pub(crate) fn note_queued(&mut self) -> std::result::Result<(), Refusal> {
        self.session.note_queued()
    }
    /// Lock: the gate is cleared, which withdraws every approval it issued.
    pub(crate) fn lock(&mut self) {
        self.session.lock();
    }
    pub(crate) fn discard(&mut self) -> std::result::Result<(), Refusal> {
        self.session.discard()
    }
    /// Test hook: take an approval out of the gate (the controller itself never does).
    #[cfg(test)]
    pub(crate) fn approve_for_test(&mut self, view: &ChainView<'_>) -> TestApproval {
        self.session.approve(view)
    }
    #[cfg(test)]
    pub(crate) fn plan_for_test(&self) -> Option<&OperationPlan> {
        self.session.plan()
    }
}

/// What a review input led to.
#[derive(Debug)]
pub enum ReviewOutcome {
    /// The review on screen, updated.
    Screen(Box<ReviewScreen>),
    /// Signed and durably queued (never "delivered" or "settled").
    Queued(QueuedOperation),
    /// The plan was dropped before anything was signed.
    Cancelled,
}

/// A signed operation that is durably queued: payments in the payment pool (transport), every other
/// kind in the protected operation outbox (export only, Q1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedOperation {
    pub id: Hash,
    pub kind: OperationKind,
    /// Every signature is present (otherwise: export the public partial for the other parties).
    pub complete: bool,
    pub missing: Vec<Requirement>,
}

/// A License sale, fiat lock or fiat release made whole from its public parts (phase 5B kinds).
/// Its `Debug` shows the length of the bytes, never the bytes (Order W10: no signed operation's
/// bytes reach a diagnostic path).
#[derive(Clone, PartialEq, Eq)]
pub struct CompletedTrade {
    pub id: Hash,
    pub kind: OperationKind,
    /// The complete signed bytes, verified through consensus code at the current head (every
    /// approval, the maker's fill, `trading_v1::prepare_batch`). Public data, for export.
    pub bytes: Vec<u8>,
    /// Whether the complete operation is queued in this wallet's outbox: a new record, or (wallet
    /// review fixes, MINOR-1) the atomic replacement of this wallet's own open part, which shares
    /// the operation identifier, by the complete record. Not when a SETTLED record of this
    /// operation holds the identifier (an outbox never holds other bytes under an existing
    /// identifier, wallet-core phase 5B change request 1).
    pub queued: bool,
}

impl std::fmt::Debug for CompletedTrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompletedTrade")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field(
                "bytes",
                &format_args!("<{} bytes, not shown>", self.bytes.len()),
            )
            .field("queued", &self.queued)
            .finish()
    }
}

struct Unlocked {
    signer: KeySigner,
    identity: Identity,
}

/// The parts every `ChainView` is built from (owned, so a view can borrow them).
struct ViewParts {
    confirmations: crate::verified_sync_v2::Confirmations,
    history: mutiny_consensus_v8::evidence_history_v2::History,
    head: HeadInfo,
    state: State,
    reserved: BTreeSet<OutPoint>,
}

pub struct Controller {
    store: Store,
    replica: Replica,
    outbox: Mempool,
    operations: OperationOutbox,
    preimages: PreimageVault,
    /// This machine's Treasury declaration, from EXPLICIT runtime configuration only (never a UI
    /// control, never inferred from a key; Q5). wallet-core's `profile::declare` checks it against the
    /// verified chain at every unlock and at every new verified head; the signer carries the Treasury
    /// profile only while it holds. `None`: the ordinary profile. No command changes it.
    treasury: Option<TreasuryDeclaration>,
    session: Option<Unlocked>,
    last_activity: Option<Instant>,
    plan: Option<ActivePlan>,
    last_head: Option<(FinalizedAnchor, Hash)>,
    /// The two-key session of a wallet rotation in progress (current and new key), if any.
    rotation: Option<RotationSigner>,
    /// The idle limit the signers get (`IDLE_LIMIT`; only a test shortens it, and wallet-core
    /// clamps any longer value to its own `DEFAULT_IDLE_LIMIT`).
    signer_idle_limit: Duration,
    /// The change markers of the canonical store and of the payment outbox right after the last
    /// completed reconcile, and when it happened (`reconcile_outbox`).
    reconciled: Option<((i64, u64), (i64, u64), Instant)>,
    /// Test observation: how many reconciles actually ran.
    #[cfg(test)]
    reconciles: u64,
    /// The lifetime exclusive owner of the vault root (`Controller::open` only). Declared last so it is
    /// released only after every store above has closed.
    _owner: Option<OwnerLock>,
}
/// The file whose unshared open marks the one live owner of a vault root.
pub(crate) const OWNER_LOCK_FILE: &str = "wallet-owner.lock";
/// Lifetime exclusive ownership of one vault root across instances and processes: the lock file beside
/// the custody folder is held open with NO sharing for as long as the opening Controller lives, so any
/// other open of the same root (another Controller in this or another process) fails with a sharing
/// violation instead of using the same stores concurrently. Released by the OS when the handle closes
/// (drop, process exit or crash); the file itself carries no state and is never read.
///
/// A clone shares the same handle: the root stays owned until the LAST clone drops. A caller that
/// builds same-root stores itself (chain, pool, an initial vault write) takes the owner FIRST with
/// [`VaultRoot::take_owner`], keeps it for as long as it uses that root, and hands a clone to
/// [`Controller::open_owned`].
#[derive(Clone)]
pub(crate) struct OwnerLock {
    root: PathBuf,
    _file: std::sync::Arc<std::fs::File>,
}
impl OwnerLock {
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }
    pub(crate) fn acquire(root: &Path) -> Result<Self> {
        let path = root.join(OWNER_LOCK_FILE);
        if let Ok(meta) = path.symlink_metadata() {
            #[cfg(windows)]
            let reparse = {
                use std::os::windows::fs::MetadataExt;
                meta.file_attributes() & 0x400 != 0
            };
            #[cfg(not(windows))]
            let reparse = false;
            if !meta.is_file() || meta.file_type().is_symlink() || reparse {
                return Err("The wallet owner lock is not a plain file".into());
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .share_mode(0)
                .open(&path)
                .map_err(|e| {
                    if e.raw_os_error() == Some(32) {
                        "This wallet is already open in another wallet instance".to_string()
                    } else {
                        format!("Wallet owner lock: {e}")
                    }
                })?;
            Ok(Self { root: root.to_path_buf(), _file: std::sync::Arc::new(file) })
        }
        #[cfg(not(windows))]
        {
            Err("Exclusive wallet ownership is only implemented on Windows".into())
        }
    }
}
/// How long a completed reconcile may stand in for a new one while neither store has been
/// written. Any write through SQLite to either store ends it at once.
const RECONCILE_REUSE_LIMIT: Duration = Duration::from_secs(5);

impl Controller {
    pub fn new(
        store: Store,
        replica: Replica,
        outbox: Mempool,
        operations: OperationOutbox,
        preimages: PreimageVault,
        treasury: Option<TreasuryDeclaration>,
    ) -> Result<Self> {
        crate::wallet_v2::ready().map_err(str::to_owned)?;
        let (head, _) = replica.verified()?;
        if *operations.context() != head.context() {
            return Err("The operation outbox belongs to another chain".into());
        }
        Ok(Self {
            store,
            replica,
            outbox,
            operations,
            preimages,
            treasury,
            session: None,
            last_activity: None,
            plan: None,
            last_head: None,
            rotation: None,
            signer_idle_limit: IDLE_LIMIT,
            reconciled: None,
            #[cfg(test)]
            reconciles: 0,
            _owner: None,
        })
    }
    /// Reconcile the payment outbox with the canonical store.
    ///
    /// A reconcile rebuilds and re-verifies the chain state, and a reconcile of two unchanged
    /// stores changes nothing. It is therefore skipped while both change markers still equal
    /// the ones taken right after the last completed reconcile and that reconcile is recent.
    /// A write to either store, by this process or another, moves a marker and the reconcile
    /// runs again; a failed reconcile is never remembered.
    fn reconcile_outbox(&mut self) -> Result<()> {
        let markers = |c: &Self| -> Result<((i64, u64), (i64, u64))> {
            Ok((
                c.replica.change_marker()?,
                c.outbox
                    .change_marker()
                    .map_err(|e| format!("Wallet outbox: {e:?}"))?,
            ))
        };
        let now = markers(self)?;
        if let Some((chain, pool, at)) = self.reconciled {
            if (chain, pool) == now && at.elapsed() < RECONCILE_REUSE_LIMIT {
                return Ok(());
            }
        }
        self.reconciled = None;
        self.replica.reconcile(&mut self.outbox)?;
        #[cfg(test)]
        {
            self.reconciles += 1;
        }
        let (chain, pool) = markers(self)?;
        self.reconciled = Some((chain, pool, Instant::now()));
        Ok(())
    }
    /// Open the vault and its sibling stores under an explicit vault root. The owner is taken before
    /// the custody stores are opened; a caller whose chain or pool files live in the same root opens
    /// them under [`VaultRoot::take_owner`] first and uses [`Controller::open_owned`] instead.
    pub fn open(
        root: &VaultRoot,
        replica: Replica,
        outbox: Mempool,
        treasury: Option<TreasuryDeclaration>,
    ) -> Result<Self> {
        let owner = root.take_owner()?;
        Self::open_owned(owner, root, replica, outbox, treasury)
    }
    /// [`Controller::open`] under an owner the caller already holds for this same root. The
    /// Controller keeps its clone until every store it owns has closed.
    pub(crate) fn open_owned(
        owner: OwnerLock,
        root: &VaultRoot,
        replica: Replica,
        outbox: Mempool,
        treasury: Option<TreasuryDeclaration>,
    ) -> Result<Self> {
        crate::wallet_v2::ready().map_err(str::to_owned)?;
        if owner.root() != root.0.as_path() {
            return Err("The wallet owner lock belongs to another vault root".into());
        }
        // Order W7: the vault root and each store file are checked before anything is created or
        // opened; a retired V1 wallet or an earlier, newer, foreign or damaged file is refused with a
        // readable reason and left exactly as it was.
        crate::custody_format::check_vault_root(&root.0).map_err(|format| format.to_string())?;
        let (head, _) = replica.verified()?;
        let store = Store::open(&root.vault()).map_err(|error| error.to_string())?;
        let operations =
            OperationOutbox::open(&root.operation_outbox(), head.context()).map_err(text)?;
        let preimages = PreimageVault::open(&root.preimages()).map_err(text)?;
        let mut controller = Self::new(store, replica, outbox, operations, preimages, treasury)?;
        controller._owner = Some(owner);
        Ok(controller)
    }
    /// The profile of the unlocked signer: `Treasury` only while this machine's runtime declaration
    /// holds on the verified chain; `Ordinary` otherwise and while locked.
    pub fn profile(&self) -> WalletProfile {
        self.session
            .as_ref()
            .map_or(WalletProfile::Ordinary, |unlocked| {
                unlocked.signer.identity().profile()
            })
    }
    pub fn lock(&mut self) {
        if let Some(unlocked) = self.session.take() {
            unlocked.signer.lock();
        }
        self.cancel_review();
        self.last_activity = None;
    }
    fn expire_at(&mut self, now: Instant) {
        if self.last_activity.is_none_or(|last| {
            now.checked_duration_since(last)
                .is_none_or(|elapsed| elapsed >= IDLE_LIMIT)
        }) {
            self.lock();
        }
    }
    pub fn tick(&mut self) {
        self.expire_at(Instant::now());
    }
    /// Refresh the unlocked signer's own idle clock (wallet review fixes): user input recorded by
    /// the service counts for the key too. Fail-closed: a signer that has already locked itself
    /// locks the whole session (key erased, approvals withdrawn).
    pub(crate) fn touch_signer(&mut self) {
        if self
            .session
            .as_ref()
            .is_some_and(|unlocked| unlocked.signer.touch().is_err())
            || self
                .rotation
                .as_ref()
                .is_some_and(|rotation| rotation.touch().is_err())
        {
            self.lock();
        }
    }
    /// Test hook: the idle limit of the signers created from now on.
    #[cfg(test)]
    pub(crate) fn set_signer_idle_limit_for_test(&mut self, limit: Duration) {
        self.signer_idle_limit = limit;
    }
    /// Call for actual local user input, never for repaint, sync or node traffic.
    /// Input at/after timeout cannot revive the expired private session.
    pub fn user_activity(&mut self) {
        let now = Instant::now();
        self.expire_at(now);
        if let Some(unlocked) = &self.session {
            if unlocked.signer.touch().is_err() {
                self.lock();
                return;
            }
            if self
                .rotation
                .as_ref()
                .is_some_and(|rotation| rotation.touch().is_err())
            {
                self.lock();
                return;
            }
            self.last_activity = Some(now);
        }
    }
    pub fn unlock(&mut self, password: &str) -> Result<()> {
        // A failed replacement unlock must not leave an earlier session active.
        self.lock();
        let (session, _) = self.store.unlock(password).map_err(str::to_owned)?;
        let identity = session.identity().clone();
        // Q5: the Treasury profile only through the runtime declaration, checked against the verified
        // chain; a declaration that does not hold refuses the unlock (the session, and with it the
        // key, is dropped and erased). The signer carries exactly the identity `profile::declare`
        // returned: the Treasury profile with the roles it checked (wallet review fixes, MINOR-2).
        let ordinary = identity.signer_identity().map_err(str::to_owned)?;
        let signer_identity = match self.treasury.clone() {
            None => ordinary,
            Some(declaration) => {
                let parts = self.verified_view_parts()?;
                let view = ChainView::verified(parts.head.clone(), &parts.state, &parts.reserved)
                    .map_err(text)?
                    .with_history(&parts.history);
                profile::declare(ordinary, &declaration, &view)
                    .map_err(|refusal| {
                        format!("This machine's Treasury declaration does not hold on the verified chain: {}", text(refusal))
                    })?
            }
        };
        let signer = session
            .into_signer(
                signing_gate().map_err(text)?,
                signer_identity,
                self.signer_idle_limit,
            )
            .map_err(text)?;
        self.session = Some(Unlocked { signer, identity });
        self.last_activity = Some(Instant::now());
        Ok(())
    }
    pub fn identity(&mut self) -> Option<&Identity> {
        self.tick();
        self.session.as_ref().map(|unlocked| &unlocked.identity)
    }
    /// Drop the plan on screen. Its gate is cleared first, which withdraws any approval it issued;
    /// the two keys of a rotation in progress are erased.
    pub fn cancel_review(&mut self) {
        if let Some(mut plan) = self.plan.take() {
            plan.lock();
        }
        if let Some(rotation) = self.rotation.take() {
            rotation.lock();
        }
    }
    fn view_parts(&mut self) -> Result<ViewParts> {
        self.view_parts_with_items(&[])
    }
    fn view_parts_with_items(&mut self, incoming: &[Vec<u8>]) -> Result<ViewParts> {
        self.reconcile_outbox()?;
        let (head, state) = self.replica.verified()?;
        let mut reserved = self
            .outbox
            .reserved_inputs()
            .map_err(|e| format!("Wallet outbox: {e:?}"))?;
        reserved.extend(self.operations.reserved().map_err(text)?);
        let records = self.operations.records().map_err(text)?;
        let ids: Vec<_> = records.iter().map(|r| r.id).collect();
        let mut reference_items = records.into_iter().map(|r| r.bytes).collect::<Vec<_>>();
        if let Some(active) = &self.plan {
            if let Some(plan) = active.session.plan() {
                reference_items.extend(plan.objects().iter().map(|o| o.bytes.clone()));
            }
        }
        reference_items.extend(incoming.iter().cloned());
        let history = self.replica.wallet_reference_history(&reference_items)?;
        let confirmations = self.replica.confirmations(&ids)?;
        if self.replica.current_anchor()? != head.anchor().clone() {
            return Err("Canonical head changed while building wallet view".into());
        }
        Ok(ViewParts {
            confirmations,
            history,
            head,
            state,
            reserved,
        })
    }
    /// Bring the operation outbox and the plan on screen to the current verified head.
    fn refresh(&mut self) -> Result<()> {
        let parts = self.view_parts()?;
        let confirmations = &parts.confirmations;
        let view = ChainView::verified(parts.head.clone(), &parts.state, &parts.reserved)
            .map_err(text)?
            .with_history(&parts.history)
            .with_confirmations(confirmations);
        let head = (view.anchor().clone(), view.state_root());
        let mut withdrawn = None;
        if self.last_head.as_ref() != Some(&head) {
            self.operations.reconcile(&view).map_err(text)?;
            // Q5: the Treasury declaration is checked again at every new verified head; when it no
            // longer holds the wallet locks (the key is erased and every approval withdrawn).
            if let (Some(declaration), Some(unlocked)) = (&self.treasury, &self.session)
                && let Err(refusal) =
                    profile::declare(unlocked.signer.identity().clone(), declaration, &view)
            {
                withdrawn = Some(format!(
                    "This machine's Treasury declaration no longer holds at block {}: {}; the wallet is locked",
                    view.anchor().height,
                    text(refusal)
                ));
            }
            self.last_head = Some(head);
        }
        if let Some(reason) = withdrawn {
            self.lock();
            return Err(reason);
        }
        if let Some(plan) = self.plan.as_mut() {
            plan.on_head(&view);
        }
        Ok(())
    }
    fn unlocked(&self) -> Result<&Unlocked> {
        self.session
            .as_ref()
            .ok_or_else(|| "Unlock the wallet first".to_string())
    }
    /// Plan an operation for this wallet and put its review on screen. Treasury-only kinds are
    /// refused by wallet-core unless this machine's runtime Treasury declaration holds (`profile`).
    pub fn request(&mut self, request: OperationRequest) -> Result<ReviewScreen> {
        self.tick();
        self.cancel_review();
        self.unlocked()?;
        self.refresh()?;
        let parts = self.view_parts()?;
        let confirmations = &parts.confirmations;
        let view = ChainView::verified(parts.head.clone(), &parts.state, &parts.reserved)
            .map_err(text)?
            .with_history(&parts.history)
            .with_confirmations(confirmations);
        let signer = &self.unlocked()?.signer;
        let planned =
            mutiny_wallet_core_v8::plan(&request, &view, signer.identity()).map_err(text)?;
        let mut active = ActivePlan::new(planned);
        active.present(&view).map_err(text)?;
        let screen = active.screen(&view).ok_or("No review to show")?;
        self.plan = Some(active);
        Ok(screen)
    }
    /// The ported payment entry point: `request(Payment)`.
    pub fn prepare(&mut self, recipient: Hash, atoms: u64) -> Result<ReviewScreen> {
        self.request(OperationRequest::Payment(PaymentRequest::new(
            recipient, atoms,
        )))
    }
    /// The review on screen at the current verified head (after `on_head`).
    pub fn screen(&mut self) -> Result<Option<ReviewScreen>> {
        self.tick();
        if self.plan.is_none() {
            return Ok(None);
        }
        self.refresh()?;
        let parts = self.view_parts()?;
        let view = ChainView::verified(parts.head.clone(), &parts.state, &parts.reserved)
            .map_err(text)?
            .with_history(&parts.history);
        Ok(self.plan.as_ref().and_then(|plan| plan.screen(&view)))
    }
    /// Apply what the person did on the review screen. A mistyped check or an acknowledgement the
    /// review does not ask for is reported in the screen's status (nothing changes); `Authorize`
    /// approves, signs and durably queues in one step, or refuses and changes nothing.
    pub fn review_input(&mut self, input: ReviewInput) -> Result<ReviewOutcome> {
        self.tick();
        self.unlocked()?;
        if self.plan.is_none() {
            return Err("No review is on screen".into());
        }
        self.refresh()?;
        let parts = self.view_parts()?;
        let confirmations = &parts.confirmations;
        let view = ChainView::verified(parts.head.clone(), &parts.state, &parts.reserved)
            .map_err(text)?
            .with_history(&parts.history)
            .with_confirmations(confirmations);
        let plan = self.plan.as_mut().ok_or("No review is on screen")?;
        match input {
            ReviewInput::Cancel => {
                plan.discard().map_err(text)?;
                self.plan = None;
                Ok(ReviewOutcome::Cancelled)
            }
            ReviewInput::Authorize => {
                // A rotation is signed by its two-key session, everything else by the wallet key.
                let signed = if plan.kind() == OperationKind::WalletRotation {
                    let rotation = self.rotation.as_ref().ok_or("Start the rotation again")?;
                    plan.authorize(rotation, &view)
                } else {
                    let signer = &self
                        .session
                        .as_ref()
                        .ok_or("Unlock the wallet first")?
                        .signer;
                    plan.authorize(signer, &view)
                }
                .map_err(text)?;
                let id = match signed.kind() {
                    OperationKind::Payment => self.replica.queue_signed_payment(
                        &mut self.outbox,
                        &signed,
                        view.anchor(),
                    )?,
                    _ => self.operations.commit(&signed, &view).map_err(text)?,
                };
                plan.note_queued().map_err(text)?;
                self.plan = None;
                if let Some(rotation) = self.rotation.take() {
                    rotation.lock();
                }
                Ok(ReviewOutcome::Queued(QueuedOperation {
                    id,
                    kind: signed.kind(),
                    complete: signed.is_complete(),
                    missing: signed.missing().to_vec(),
                }))
            }
            other => {
                // A refused input is shown on the screen; it is not a failure of the controller.
                let _ = plan.apply(&other);
                Ok(ReviewOutcome::Screen(Box::new(
                    plan.screen(&view).ok_or("No review to show")?,
                )))
            }
        }
    }
    /// Verified incoming history invalidates an outstanding review immediately.
    /// Invalid input also cancels review; it cannot create approval or extend idle time.
    pub fn accept_history(&mut self, raw: &[u8]) -> Result<bool> {
        self.tick();
        self.cancel_review();
        let inserted = self.replica.accept(raw)?;
        self.refresh()?;
        Ok(inserted)
    }
    /// Recovery is public history ingress; it never requests owner signing or
    /// renews unlock activity. An outstanding review is discarded.
    pub fn accept_recovery_history(&mut self, raw: &[u8]) -> Result<bool> {
        self.tick();
        self.cancel_review();
        self.replica.accept_recovery(raw)
    }
    pub fn pending_for_transport(&mut self) -> Result<Vec<Vec<u8>>> {
        self.tick();
        self.reconcile_outbox()?;
        self.replica.pending_after_reconcile(&self.outbox)
    }
    pub fn delivery(&mut self, id: Hash) -> Result<Delivery> {
        self.tick();
        self.replica.delivery(&mut self.outbox, id)
    }
    /// Public balance for the vault's active authority, including both durable queues' reservations.
    /// The canonical registry supplies its current descriptor after rotation; the vault may still
    /// hold the superseded key while replacement is due. This call neither unlocks nor signs.
    pub fn balance(&mut self) -> Result<Option<crate::verified_sync_v2::Balance>> {
        self.tick();
        let Some(status) = self.vault_status()? else { return Ok(None); };
        let authority: Hash = hex::decode(&status.active.authority_id)
            .map_err(|_| "Invalid wallet identity")?
            .try_into().map_err(|_| "Invalid wallet identity")?;
        let parts = self.verified_view_parts()?;
        let active_descriptor = hex::decode(&status.active.owner_descriptor)
            .map_err(|_| "Invalid wallet identity")?;
        let descriptor = parts.state.wallets.current(authority).unwrap_or(&active_descriptor);
        let balance = self.replica.balance(descriptor, &parts.reserved)?;
        if &balance.anchor != parts.head.anchor() || &self.replica.current_anchor()? != parts.head.anchor() {
            return Err("Canonical head changed while reading wallet balance".into());
        }
        if self.vault_status()? != Some(status) {
            return Err("Vault identity changed while reading wallet balance".into());
        }
        Ok(Some(balance))
    }
    /// Canonical delivery of the caller's known payment IDs, in input order. IDs are supplied by
    /// actual queue/review outcomes; this is not a complete history enumerator or an item-kind
    /// classifier. Peer and pending-cache claims cannot manufacture canonical confirmation.
    pub fn payment_activity(&mut self, ids: &[Hash]) -> Result<Vec<(Hash, Delivery)>> {
        if ids.len() > 5120 {
            return Err("Wallet activity query exceeds local queue bound".into());
        }
        self.tick();
        self.refresh()?;
        let anchor = self.replica.current_anchor()?;
        let mut rows = Vec::with_capacity(ids.len());
        for id in ids {
            rows.push((*id, self.replica.delivery(&mut self.outbox, *id)?));
        }
        if self.replica.current_anchor()? != anchor {
            return Err("Canonical head changed while reading wallet activity".into());
        }
        Ok(rows)
    }
    /// The operations queued in the protected outbox (open and settled history), reconciled from
    /// verified state first. Public metadata only: no bytes leave through this call.
    pub fn queued_operations(&mut self) -> Result<Vec<(QueuedOperation, String)>> {
        self.tick();
        self.refresh()?;
        Ok(self
            .operations
            .records()
            .map_err(text)?
            .into_iter()
            .map(|record| {
                (
                    QueuedOperation {
                        id: record.id,
                        kind: record.kind,
                        complete: record.complete,
                        missing: record.missing,
                    },
                    format!("{:?}", record.status),
                )
            })
            .collect())
    }
    /// The exportable bytes of one queued operation (public data; see `OperationOutbox::export`).
    pub fn export(&mut self, id: Hash) -> Result<Vec<u8>> {
        self.tick();
        self.operations.export(&id).map_err(text)
    }
    /// Drop a queued record and release its reservations. This does NOT revoke the signed bytes,
    /// which stay valid until they are included or expire.
    pub fn forget(&mut self, id: Hash) -> Result<()> {
        self.tick();
        self.operations.forget(&id).map_err(text)
    }
    fn verified_view_parts(&mut self) -> Result<ViewParts> {
        self.refresh()?;
        self.view_parts()
    }
    /// The review of a counterparty's public partial operation as this wallet sees it (read-only:
    /// nothing is planned or signed).
    pub fn explain_partial(&mut self, container: &[u8]) -> Result<Review> {
        self.tick();
        let me = self.unlocked()?.signer.identity().clone();
        let partial = PartialApproval::import(container).map_err(text)?;
        self.refresh()?;
        let parts = self.view_parts_with_items(&[partial.bytes().to_vec()])?;
        let view = ChainView::verified(parts.head.clone(), &parts.state, &parts.reserved)
            .map_err(text)?
            .with_history(&parts.history);
        partial.explain_for(&view, &me).map_err(text)
    }
    /// Adopt a counterparty's public partial operation to review and sign this wallet's part.
    pub fn adopt_partial(&mut self, container: &[u8]) -> Result<ReviewScreen> {
        self.tick();
        self.cancel_review();
        let me = self.unlocked()?.signer.identity().clone();
        let partial = PartialApproval::import(container).map_err(text)?;
        self.refresh()?;
        let parts = self.view_parts_with_items(&[partial.bytes().to_vec()])?;
        let view = ChainView::verified(parts.head.clone(), &parts.state, &parts.reserved)
            .map_err(text)?
            .with_history(&parts.history);
        let planned = partial.adopt_for(&view, &me).map_err(text)?;
        let mut active = ActivePlan::new(planned);
        active.present(&view).map_err(text)?;
        let screen = active.screen(&view).ok_or("No review to show")?;
        self.plan = Some(active);
        Ok(screen)
    }
    /// Complete a conditional operation from its public parts and the maker's fill
    /// (`ops::conditional::complete`: verifies everything, signs nothing) and queue it IN PLACE OF
    /// this wallet's partial record `partial`, in one atomic step (`Outbox::replace_partial`): the
    /// outbox verifies that `partial` is an open partial record of exactly this operation and the
    /// complete record takes over its reservations; a wrong identifier is refused and changes
    /// nothing, and a crash leaves the partial or the complete record, never neither.
    pub fn complete_conditional(
        &mut self,
        partial: Hash,
        parts: &[Vec<u8>],
        fill: Option<&[u8]>,
    ) -> Result<QueuedOperation> {
        self.tick();
        self.unlocked()?;
        self.refresh()?;
        let parts_view = self.view_parts_with_items(parts)?;
        let confirmations = &parts_view.confirmations;
        let view = ChainView::verified(
            parts_view.head.clone(),
            &parts_view.state,
            &parts_view.reserved,
        )
        .map_err(text)?
        .with_history(&parts_view.history)
        .with_confirmations(confirmations);
        let slices: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
        let complete = mutiny_wallet_core_v8::ops::conditional::complete(&slices, fill, &view)
            .map_err(text)?;
        if !complete.is_complete() {
            return Err("The parts do not complete the operation".into());
        }
        let id = self
            .operations
            .replace_partial(&partial, &complete, &view)
            .map_err(text)?;
        Ok(QueuedOperation {
            id,
            kind: complete.kind(),
            complete: true,
            missing: Vec::new(),
        })
    }
    /// Verify independent tag-25 approvals and atomically replace this wallet's own open part.
    /// No new signature is made here, and an incomplete/competing body changes no queue record.
    pub fn complete_rotation(
        &mut self,
        partial: Hash,
        parts: &[Vec<u8>],
    ) -> Result<QueuedOperation> {
        self.tick();
        self.unlocked()?;
        self.refresh()?;
        let facts = self.view_parts_with_items(parts)?;
        let view = ChainView::verified(facts.head.clone(), &facts.state, &facts.reserved)
            .map_err(text)?
            .with_history(&facts.history)
            .with_confirmations(&facts.confirmations);
        let slices: Vec<_> = parts.iter().map(Vec::as_slice).collect();
        let complete =
            mutiny_wallet_core_v8::ops::rotation::combine(&slices, &view).map_err(text)?;
        if !complete.is_complete() {
            return Err("Rotation approvals are still missing".into());
        }
        let id = self
            .operations
            .replace_partial(&partial, &complete, &view)
            .map_err(text)?;
        Ok(QueuedOperation {
            id,
            kind: complete.kind(),
            complete: true,
            missing: Vec::new(),
        })
    }
    /// Complete a License sale, fiat lock or fiat release (phase 5B) from its public parts and, for
    /// a kind that fills a maker offer, the maker's fill proof: `offers::attach_fill_proof` places
    /// the fill (verified over the exact body), `offers::combine` merges the parts after verifying
    /// every signature and runs consensus' `prepare_batch` on the complete result. Signs nothing.
    /// Queued here (see `CompletedTrade::queued`): in place of this wallet's own OPEN part of the
    /// same operation, in one atomic step (`Outbox::replace_partial`, which verifies that the part
    /// is a partial record of exactly this operation and passes its reservations to the complete
    /// record), or as a new record when no record of this wallet holds the operation identifier;
    /// a settled record of this operation is left as it is. The bytes are returned for export
    /// either way.
    pub fn complete_trade(
        &mut self,
        parts: &[Vec<u8>],
        fill: Option<&[u8]>,
    ) -> Result<CompletedTrade> {
        self.tick();
        self.unlocked()?;
        self.refresh()?;
        let parts_view = self.view_parts_with_items(parts)?;
        let confirmations = &parts_view.confirmations;
        let view = ChainView::verified(
            parts_view.head.clone(),
            &parts_view.state,
            &parts_view.reserved,
        )
        .map_err(text)?
        .with_history(&parts_view.history)
        .with_confirmations(confirmations);
        let mut all = parts.to_vec();
        if let Some(fill) = fill {
            let first = parts.first().ok_or("No part to complete")?;
            all.push(offers::attach_fill_proof(first, fill, &view).map_err(text)?);
        }
        let slices: Vec<&[u8]> = all.iter().map(Vec::as_slice).collect();
        let complete = offers::combine(&slices, &view).map_err(text)?;
        if !complete.is_complete() {
            return Err(format!(
                "The parts do not complete the operation: {} requirement(s) still missing",
                complete.missing().len()
            ));
        }
        let (id, kind) = (complete.id(), complete.kind());
        let queued = match self.operations.get(&id).map_err(text)? {
            None => {
                self.operations.commit(&complete, &view).map_err(text)?;
                true
            }
            // This wallet's own part (a part and its operation share the identifier).
            Some(record) if record.status.is_open() && !record.complete => {
                self.operations
                    .replace_partial(&id, &complete, &view)
                    .map_err(text)?;
                true
            }
            // Queued already (a retry), or a settled record of this operation.
            Some(record) => record.status.is_open() && record.bytes == complete.bytes(),
        };
        Ok(CompletedTrade {
            id,
            kind,
            bytes: complete.bytes().to_vec(),
            queued,
        })
    }
    /// A fresh hash-lock preimage (operating-system randomness, never derived from a key, Q13),
    /// kept sealed in the preimage store. Returns its public condition.
    pub fn create_preimage(&mut self) -> Result<Hash> {
        self.tick();
        self.unlocked()?;
        self.preimages.create().map_err(text)
    }
    /// The conditions this wallet holds a preimage for.
    pub fn preimage_conditions(&mut self) -> Result<Vec<Hash>> {
        self.tick();
        self.preimages.conditions().map_err(text)
    }
    /// Erase one preimage: the person's explicit act, never automatic (an erased preimage cannot
    /// claim its lock any more).
    pub fn erase_preimage(&mut self, condition: Hash) -> Result<bool> {
        self.tick();
        self.unlocked()?;
        self.preimages.erase(&condition).map_err(text)
    }
    /// The claim request for `lock` with the preimage this wallet's store holds for its condition.
    pub fn claim_request(&mut self, lock: Hash) -> Result<ClaimRequest> {
        self.tick();
        self.unlocked()?;
        let parts = self.verified_view_parts()?;
        let view = ChainView::verified(parts.head.clone(), &parts.state, &parts.reserved)
            .map_err(text)?
            .with_history(&parts.history);
        mutiny_wallet_core_v8::ops::conditional::claim_request(&self.preimages, lock, &view)
            .map_err(text)
    }
    /// The chain this controller's stores are bound to.
    pub fn context(&self) -> ChainContext {
        *self.operations.context()
    }
    /// Build a `ChainView` of the current verified head for read-only discovery (forms list the
    /// wallet's Licenses, entitlements, nodes, lots and locks from it).
    pub fn with_view<T>(&mut self, read: impl FnOnce(&ChainView<'_>) -> T) -> Result<T> {
        self.tick();
        let parts = self.verified_view_parts()?;
        let view = ChainView::verified(parts.head.clone(), &parts.state, &parts.reserved)
            .map_err(text)?
            .with_history(&parts.history)
            .with_confirmations(&parts.confirmations);
        Ok(read(&view))
    }
    /// The vault's public status (the identities of its records, its revision).
    pub fn vault_status(&self) -> Result<Option<VaultStatus>> {
        self.store.status().map_err(str::to_owned)
    }
    fn active_authority(&self) -> Result<(VaultStatus, Hash)> {
        let status = self
            .store
            .status()
            .map_err(str::to_owned)?
            .ok_or("No V2 wallet exists")?;
        let authority = hex::decode(&status.active.authority_id)
            .ok()
            .and_then(|raw| raw.try_into().ok())
            .ok_or("Invalid wallet identity")?;
        Ok((status, authority))
    }
    /// The descriptor the VERIFIED chain records as current for the vault's active authority, when
    /// it is the NEXT generation of the active identity: the rotation is confirmed and the vault
    /// still holds the previous key (the replacement is due). `None` otherwise.
    pub fn confirmed_rotation(&mut self) -> Result<Option<Vec<u8>>> {
        self.tick();
        let (status, authority) = self.active_authority()?;
        self.with_view(|view| {
            let current = view.state().wallets.current(authority)?;
            let (_, generation) = PublicKey::decode_descriptor(current).ok()?;
            (status.active.generation.checked_add(1) == Some(generation)
                && hex::encode(current) != status.active.owner_descriptor)
                .then(|| current.to_vec())
        })
    }
    /// A fresh phrase for the NEW key of a wallet rotation, for display only (crypto-v2's wallet
    /// entropy: operating-system randomness with its optional TPM contribution; never derived from
    /// the current key), and the descriptor it gives at the next generation. The person writes it
    /// down and types it back (`begin_rotation` restores the typed text: the clean-restore check).
    pub fn generate_rotation_phrase(&mut self) -> Result<(Zeroizing<String>, Vec<u8>)> {
        self.tick();
        crate::wallet_v2::ready().map_err(str::to_owned)?;
        let generation = self
            .unlocked()?
            .identity
            .generation
            .checked_add(1)
            .ok_or("Wallet generation overflow")?;
        let phrase = mutiny_crypto_v2::create_wallet_phrase()
            .map_err(|_| "Qualified wallet entropy unavailable".to_string())?;
        let restored = RestoredKey::restore(&phrase, generation, None).map_err(str::to_owned)?;
        Ok((phrase, restored.descriptor().to_vec()))
    }
    /// Start a wallet rotation (phase 2's operation): the vault password opens the CURRENT key a
    /// second time (the rotation needs both keys in this process), the typed-back new phrase is
    /// restored and must give exactly `expected`, the descriptor of the generation step shown when
    /// the phrase was generated (MANDATORY since the wallet review fixes, MINOR-5): the
    /// clean-restore check, whose evidence (the descriptor fingerprint) is bound into the plan.
    /// Both keys move into wallet-core's `RotationSigner`; the high-risk review is put on screen and
    /// follows the generic flow. Lock, cancel and the idle limit erase both keys.
    pub fn begin_rotation(
        &mut self,
        password: &str,
        new_phrase: &str,
        expected: &[u8],
        validity_blocks: u64,
    ) -> Result<ReviewScreen> {
        self.tick();
        self.cancel_review();
        let identity = self.unlocked()?.identity.clone();
        let generation = identity
            .generation
            .checked_add(1)
            .ok_or("Wallet generation overflow")?;
        let restored =
            RestoredKey::restore(new_phrase, generation, Some(expected)).map_err(str::to_owned)?;
        let fingerprint = restored.fingerprint();
        let proposed = restored.descriptor().to_vec();
        // The rotation signer carries the identity the unlocked signer holds (the Treasury profile
        // with its declared roles only while the runtime declaration holds: the Genesis Treasury
        // authority rotates as R1).
        let declared = self.unlocked()?.signer.identity().clone();
        let (session, _) = self.store.unlock(password).map_err(str::to_owned)?;
        if session.identity() != &identity {
            return Err("The vault holds another identity; unlock again".into());
        }
        let rotation = session
            .into_rotation_signer(
                restored,
                signing_gate().map_err(text)?,
                declared,
                self.signer_idle_limit,
            )
            .map_err(text)?;
        self.refresh()?;
        let parts = self.view_parts()?;
        let confirmations = &parts.confirmations;
        let view = ChainView::verified(parts.head.clone(), &parts.state, &parts.reserved)
            .map_err(text)?
            .with_history(&parts.history)
            .with_confirmations(confirmations);
        let request = OperationRequest::WalletRotation(
            RotationRequest::new(Blob::new(proposed), FeeSource::RotatingAuthority)
                .with_restore_verified(fingerprint)
                .with_validity_blocks(validity_blocks),
        );
        let planned =
            mutiny_wallet_core_v8::plan(&request, &view, rotation.identity()).map_err(text)?;
        let mut active = ActivePlan::new(planned);
        active.present(&view).map_err(text)?;
        let screen = active.screen(&view).ok_or("No review to show")?;
        self.plan = Some(active);
        self.rotation = Some(rotation);
        Ok(screen)
    }
    /// The vault replacement after a CONFIRMED rotation (`store_v2`): the new phrase must restore
    /// exactly the descriptor the verified chain now records as current for this wallet's authority
    /// (the clean-restore check), the new identity is staged NEXT TO the old record and read back,
    /// and only then is the single pointer flipped. The old record is kept until
    /// `retire_previous_identity`. Afterwards the wallet is locked; unlock opens the new identity.
    /// An interrupted earlier attempt (a staged record of exactly this identity) is resumed.
    pub fn replace_vault(&mut self, password: &str, new_phrase: &str) -> Result<Identity> {
        self.tick();
        crate::wallet_v2::ready().map_err(str::to_owned)?;
        let current = self
            .confirmed_rotation()?
            .ok_or("The verified chain does not show a confirmed rotation of this wallet")?;
        let (status, authority) = self.active_authority()?;
        let restored =
            RestoredKey::restore(new_phrase, status.active.generation + 1, Some(&current))
                .map_err(str::to_owned)?;
        let replacement =
            Session::restore_rotated(restored, authority, &current).map_err(str::to_owned)?;
        let identity = replacement.identity().clone();
        let revision = match &status.staged {
            Some(staged) if *staged == identity => status.revision,
            Some(_) => return Err("Another replacement is staged; abandon it first".into()),
            None => self
                .store
                .stage_replacement(status.revision, password, &replacement)
                .map_err(str::to_owned)?,
        };
        drop(replacement);
        self.store
            .activate_replacement(revision, password, &hex::encode(&current))
            .map_err(str::to_owned)?;
        self.lock();
        Ok(identity)
    }
    /// Abandon a staged replacement that never became active (the active record is untouched).
    pub fn abandon_vault_replacement(&mut self, password: &str) -> Result<()> {
        self.tick();
        let (status, _) = self.active_authority()?;
        self.store
            .abandon_replacement(status.revision, password)
            .map(drop)
            .map_err(str::to_owned)
    }
    /// Delete the superseded previous identity: the person's explicit act (Order W16), and nothing
    /// else ever deletes it. Refused unless the VERIFIED chain establishes the successor: the vault's
    /// active identity must be what the verified state records as the current key of the wallet's
    /// authority, and the kept identity must be its immediate predecessor in the same lineage (until
    /// then the previous key may still be the only key with authority). Only the superseded vault
    /// record is deleted. Like every call that reads the verified view, it first refreshes: the
    /// outbox is reconciled with the verified head and settled records beyond the newest
    /// `DEFAULT_MAX_SETTLED` (1,024) are pruned (open records never are). Apart from that refresh,
    /// queued and settled operations (their metadata and bytes), the preimages, the payment pool
    /// and the verified chain are not touched, and coins at the previous identity's
    /// address stay spendable by the successor through the wallet book's lineage rule (consensus
    /// `WalletBook::authorize`).
    pub fn retire_previous_identity(
        &mut self,
        password: &str,
    ) -> std::result::Result<(), RetirementRefusal> {
        self.tick();
        let (status, authority) = self.active_authority().map_err(RetirementRefusal::Vault)?;
        if status.superseded.is_none() {
            return Err(RetirementRefusal::NothingToRetire);
        }
        let current = self
            .with_view(|view| view.state().wallets.current(authority).map(<[u8]>::to_vec))
            .map_err(RetirementRefusal::View)?;
        retirement_allowed(&status, current.as_deref())?;
        self.store
            .retire_previous(status.revision, password)
            .map(drop)
            .map_err(|refusal| RetirementRefusal::Vault(refusal.to_owned()))
    }
    /// The signing identity (public) while unlocked.
    pub fn signer_identity(&self) -> Option<mutiny_wallet_core_v8::SignerIdentity> {
        self.session
            .as_ref()
            .map(|unlocked| unlocked.signer.identity().clone())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{
        plan_review::ReviewPanel,
        test_support::{TestDir, custody_file},
    };
    use eframe::egui;
    use mutiny_consensus_v8::{
        canonical_store_v2::CanonicalStore,
        transactions::{Coin, OutPoint, Output},
    };

    pub(crate) const PASSWORD: &str = "PUBLIC CONTROLLER PASSWORD";

    /// The public canonical-store fixture with one 100,000-atom coin of the public TEST-VALUE key A
    /// (generation one) as the trusted Genesis state, its anchor, and key A's vault identity.
    pub(crate) fn fixture_state() -> (State, FinalizedAnchor, Identity) {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/hybrid-canonical-store-public-v1.json"
        ))
        .unwrap();
        assert_eq!(fixture["synthetic_only"], true);
        let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let root: Hash = raw(&fixture["root"]).try_into().unwrap();
        let records: Vec<_> = fixture["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
            .collect();
        let mut state = State::from_records(&records, root).unwrap();
        // Explicit public recipients in this TEST-only trusted initial state. No
        // registration is inferred merely from owning a coin or a vault file.
        for key in [
            crate::test_support::synthetic::key_a(),
            crate::test_support::synthetic::key_b(),
            crate::test_support::synthetic::key_c(),
        ] {
            let address = key.public().address_id(1).unwrap();
            if state.wallets.current(address).is_none() {
                state
                    .wallets
                    .register(&key.public().descriptor(1).unwrap())
                    .unwrap();
            }
        }
        let mut genesis = FinalizedAnchor::decode(&raw(&fixture["genesis"])).unwrap();
        genesis.block = [79; 32];
        let identity = Session::restore_initial(&format!("{}art", "abandon ".repeat(23)))
            .unwrap()
            .identity()
            .clone();
        state.coins.clear();
        state.coins.insert(
            OutPoint {
                transaction: [78; 32],
                index: 0,
            },
            Coin {
                output: Output {
                    owner: hex::decode(&identity.address_id)
                        .unwrap()
                        .try_into()
                        .unwrap(),
                    atoms: 100_000,
                },
                created_height: 0,
                coinbase: false,
            },
        );
        (state, genesis, identity)
    }

    /// A controller over `state` as a trusted Genesis state, with the vault, the operation outbox and
    /// the preimage store of `base`'s custody directory (created on first use).
    pub(crate) fn controller_over(
        base: &TestDir,
        state: &State,
        genesis: &FinalizedAnchor,
        chain: &str,
        pool: &str,
    ) -> Controller {
        controller_with(base, state, genesis, chain, pool, None)
    }

    /// `controller_over` with this machine's runtime Treasury declaration.
    pub(crate) fn controller_with(
        base: &TestDir,
        state: &State,
        genesis: &FinalizedAnchor,
        chain: &str,
        pool: &str,
        treasury: Option<TreasuryDeclaration>,
    ) -> Controller {
        let chain = CanonicalStore::open_trusted_genesis(
            &base.file(chain),
            genesis,
            state,
            state.root().unwrap(),
            1000,
            [255; 32],
        )
        .unwrap();
        let replica = Replica::from_pinned_chain(chain).unwrap();
        controller_with_replica(base, genesis, replica, pool, treasury)
    }

    /// TEST-only controller using an already pinned, independently replayed canonical store.
    fn controller_with_replica(
        base: &TestDir,
        genesis: &FinalizedAnchor,
        replica: Replica,
        pool: &str,
        treasury: Option<TreasuryDeclaration>,
    ) -> Controller {
        let store = Store::open(&custody_file(base, "wallet-hybrid-v2.sqlite")).unwrap();
        let outbox = Mempool::open(
            &base.file(pool),
            genesis.genesis,
            genesis.fingerprint,
            65536,
        )
        .unwrap();
        let context = ChainContext {
            network: genesis.network,
            genesis: genesis.genesis,
            fingerprint: genesis.fingerprint,
        };
        let operations = OperationOutbox::open(
            &custody_file(base, crate::operation_outbox::FILE_NAME),
            context,
        )
        .unwrap();
        let preimages =
            PreimageVault::open(&custody_file(base, crate::preimage_store::FILE_NAME)).unwrap();
        Controller::new(store, replica, outbox, operations, preimages, treasury).unwrap()
    }

    fn controller_on_certified_chain(
        base: &TestDir,
        chain: &crate::test_support::canonical_rig::chain::Harness,
        pool: &str,
    ) -> Controller {
        controller_with_replica(
            base,
            chain.genesis(),
            Replica::from_pinned_chain(chain.reopen_canonical_store()).unwrap(),
            pool,
            None,
        )
    }

    /// Public TEST-only licensed chain with the actual assembler/certificate/store pipeline.
    fn certified_rotation_fixture(
        base: &TestDir,
    ) -> (
        Controller,
        Identity,
        crate::test_support::canonical_rig::chain::Harness,
    ) {
        use crate::test_support::canonical_rig::chain::*;
        let (small, _, identity) = fixture_state();
        let chain = Harness::with_genesis("desktop-certified-rotation", 2_000_000, |state, _| {
            state.coins.extend(small.coins);
            for key in [
                crate::test_support::synthetic::key_a(),
                crate::test_support::synthetic::key_b(),
                crate::test_support::synthetic::key_c(),
            ] {
                if state
                    .wallets
                    .current(key.public().address_id(1).unwrap())
                    .is_none()
                {
                    state
                        .wallets
                        .register(&key.public().descriptor(1).unwrap())
                        .unwrap();
                }
            }
        });
        key_a_vault(base);
        let controller = controller_on_certified_chain(base, &chain, "outbox.sqlite");
        (controller, identity, chain)
    }

    /// A controller over the fixture state with key A's vault (see `fixture_state`).
    pub(crate) fn fixture(base: &TestDir) -> (Controller, Identity, FinalizedAnchor) {
        let (state, genesis, identity) = fixture_state();
        let session = Session::restore_initial(&format!("{}art", "abandon ".repeat(23))).unwrap();
        Store::open(&custody_file(base, "wallet-hybrid-v2.sqlite"))
            .unwrap()
            .save_initial(&session, PASSWORD)
            .unwrap();
        drop(session);
        let controller = controller_over(base, &state, &genesis, "chain.sqlite", "outbox.sqlite");
        (controller, identity, genesis)
    }

    /// Everything the person must enter for the review on screen, as the review widget reports it:
    /// each typed destination check, the phrase of a high-risk review, every acknowledgement.
    pub(crate) fn confirm_everything(controller: &mut Controller, screen: &ReviewScreen) {
        let review = &screen.review;
        for index in review.destinations_needing_check() {
            let typed = review.destination_check_text(index);
            controller
                .review_input(ReviewInput::ConfirmDestination { index, typed })
                .unwrap();
        }
        if let Some(phrase) = review.confirmation_phrase() {
            controller
                .review_input(ReviewInput::ConfirmPhrase(phrase))
                .unwrap();
        }
        for ack in review.acknowledgements() {
            controller
                .review_input(ReviewInput::Acknowledge(*ack))
                .unwrap();
        }
    }

    fn authorize(controller: &mut Controller) -> Result<QueuedOperation> {
        match controller.review_input(ReviewInput::Authorize)? {
            ReviewOutcome::Queued(queued) => Ok(queued),
            other => Err(format!("not queued: {other:?}")),
        }
    }

    #[test]
    fn public_balance_and_known_payment_activity_preserve_locked_authority_and_reservations() {
        let base = TestDir::new("controller-public-metadata");
        let (mut controller, _, genesis) = fixture(&base);
        let initial = controller.balance().unwrap().unwrap();
        assert_eq!(initial.anchor, genesis);
        assert_eq!((initial.total_atoms, initial.available_atoms, initial.reserved_atoms), (100_000, 100_000, 0));
        assert!(controller.identity().is_none());
        controller.unlock(PASSWORD).unwrap();
        let review = controller.prepare([94; 32], 50_000).unwrap();
        confirm_everything(&mut controller, &review);
        let payment = authorize(&mut controller).unwrap();
        assert_eq!(payment.kind, OperationKind::Payment);
        controller.lock();
        let activity = controller.last_activity;
        let reserved = controller.balance().unwrap().unwrap();
        assert_eq!((reserved.total_atoms, reserved.available_atoms, reserved.reserved_atoms), (100_000, 0, 100_000));
        let rows = controller.payment_activity(&[payment.id, [17; 32]]).unwrap();
        assert_eq!(rows.iter().map(|(id, _)| *id).collect::<Vec<_>>(), vec![payment.id, [17; 32]]);
        assert!(matches!(&rows[0].1, Delivery::Unconfirmed(_)));
        assert_eq!(rows[1].1, Delivery::Unconfirmed(None));
        assert_eq!(controller.last_activity, activity);
        assert!(controller.identity().is_none());
        assert!(controller.payment_activity(&vec![[17; 32]; 5121]).is_err());
    }

    /// Ported (phase 7) from the test of the same name, which composed the retired desktop draft
    /// and its synthetic approval: unlock, idle expiry, review invalidation and durable submission,
    /// now through wallet-core's plan, review gate and signer.
    #[test]
    fn unlock_expiry_review_invalidation_and_durable_submission_are_composed() {
        let base = TestDir::new("controller-compose");
        let (mut controller, identity, genesis) = fixture(&base);
        assert!(controller.identity().is_none());
        assert!(controller.prepare([94; 32], 50_000).is_err());
        controller.unlock(PASSWORD).unwrap();
        assert_eq!(controller.identity(), Some(&identity));
        // Everything is confirmed, then the idle limit passes: the lock erases the key and clears
        // the gate; the confirmed review is gone and cannot be authorized.
        let screen = controller.prepare([94; 32], 50_000).unwrap();
        confirm_everything(&mut controller, &screen);
        assert!(controller.screen().unwrap().unwrap().status.ready);
        controller.last_activity = Some(Instant::now() - IDLE_LIMIT);
        controller.user_activity();
        assert!(controller.session.is_none());
        assert!(controller.plan.is_none());
        assert!(controller.review_input(ReviewInput::Authorize).is_err());
        assert!(controller.pending_for_transport().unwrap().is_empty());
        // A failed replacement unlock leaves nothing active.
        controller.unlock(PASSWORD).unwrap();
        controller.prepare([94; 32], 50_000).unwrap();
        assert!(controller.unlock("WRONG PUBLIC PASSWORD").is_err());
        assert!(controller.session.is_none());
        assert!(controller.plan.is_none());
        // History ingress, even invalid, cancels the review and does not renew activity.
        controller.unlock(PASSWORD).unwrap();
        controller.prepare([94; 32], 50_000).unwrap();
        let last = controller.last_activity;
        assert!(controller.accept_history(&[0]).is_err());
        assert!(controller.plan.is_none());
        assert_eq!(controller.last_activity, last);
        controller.prepare([94; 32], 50_000).unwrap();
        assert!(controller.accept_recovery_history(&[0]).is_err());
        assert!(controller.plan.is_none());
        assert_eq!(controller.last_activity, last);
        // Rendering the review alone produces no input, so it cannot approve.
        let screen = controller.prepare([94; 32], 50_000).unwrap();
        let mut panel = ReviewPanel::default();
        let ctx = egui::Context::default();
        let mut produced = Vec::new();
        ctx.run_ui(Default::default(), |ui| {
            produced.extend(panel.show(ui, &screen));
        })
        .drop_without_applying_deltas();
        assert!(produced.is_empty());
        assert!(controller.review_input(ReviewInput::Authorize).is_err());
        assert!(controller.pending_for_transport().unwrap().is_empty());
        // Every confirmation, then Authorize: approved, signed, durably queued, in one step.
        let screen = controller.screen().unwrap().unwrap();
        confirm_everything(&mut controller, &screen);
        let queued = authorize(&mut controller).unwrap();
        assert_eq!(queued.kind, OperationKind::Payment);
        assert!(queued.complete);
        assert!(controller.plan.is_none());
        // Single use: nothing is left to authorize.
        assert!(controller.review_input(ReviewInput::Authorize).is_err());
        controller.lock();
        let pending = controller.pending_for_transport().unwrap();
        assert_eq!(pending.len(), 1);
        assert!(matches!(
            controller.delivery(queued.id).unwrap(),
            Delivery::Unconfirmed(_)
        ));
        assert!(controller.prepare([94; 32], 1).is_err());
        drop(controller);
        let pool = Mempool::open(
            &base.file("outbox.sqlite"),
            genesis.genesis,
            genesis.fingerprint,
            65536,
        )
        .unwrap();
        assert_eq!(
            pool.pending()
                .unwrap()
                .iter()
                .map(|tx| tx.encode().unwrap())
                .collect::<Vec<_>>(),
            pending
        );
    }

    /// The outbox reconcile behind `pending_for_transport` is repeated whenever either store was
    /// written or the reuse limit has passed, and only reused in between.
    #[test]
    fn outbox_reconcile_is_reused_only_while_both_stores_are_unchanged() {
        let base = TestDir::new("controller-reconcile-reuse");
        let (mut controller, _, _) = fixture(&base);
        controller.unlock(PASSWORD).unwrap();
        assert!(controller.pending_for_transport().unwrap().is_empty());
        let first = controller.reconciles;
        assert!(first >= 1);
        assert!(controller.pending_for_transport().unwrap().is_empty());
        assert_eq!(controller.reconciles, first, "unchanged stores reuse the reconcile");
        // A queued payment writes the pool: the next read reconciles again and returns it.
        let screen = controller.prepare([94; 32], 50_000).unwrap();
        confirm_everything(&mut controller, &screen);
        authorize(&mut controller).unwrap();
        assert_eq!(controller.pending_for_transport().unwrap().len(), 1);
        let second = controller.reconciles;
        assert!(second > first, "a written store is reconciled again");
        assert_eq!(controller.pending_for_transport().unwrap().len(), 1);
        assert_eq!(controller.reconciles, second);
        // Past the reuse limit the reconcile runs again although nothing was written.
        let (chain, pool, _) = controller.reconciled.unwrap();
        controller.reconciled = Some((chain, pool, Instant::now() - RECONCILE_REUSE_LIMIT));
        assert_eq!(controller.pending_for_transport().unwrap().len(), 1);
        assert_eq!(controller.reconciles, second + 1);
    }

    /// `Controller::open` at `root` over the fixture chain (its chain and pool files in `side`).
    pub(crate) fn open_controller_at(root: &Path, side: &TestDir) -> Result<Controller> {
        let (state, genesis, _) = fixture_state();
        let chain = CanonicalStore::open_trusted_genesis(
            &side.file("chain.sqlite"),
            &genesis,
            &state,
            state.root().unwrap(),
            1000,
            [255; 32],
        )
        .unwrap();
        let replica = Replica::from_pinned_chain(chain).unwrap();
        let pool = Mempool::open(
            &side.file("pool.sqlite"),
            genesis.genesis,
            genesis.fingerprint,
            65536,
        )
        .unwrap();
        Controller::open(
            &VaultRoot::new(root).map_err(|error| error.to_string())?,
            replica,
            pool,
            None,
        )
    }

    /// Lifetime exclusivity: while one Controller holds a vault root, a second open of the SAME root is
    /// refused (sharing violation on the owner lock) before its custody state is used; after the first is
    /// dropped the root opens again normally. A different root is unaffected.
    #[test]
    fn a_vault_root_has_one_live_owner_and_reopens_after_release() {
        let base = TestDir::new("controller-owner");
        let root = base.path().to_path_buf();
        let (side_a, side_b, side_c) = (TestDir::new("owner-a"), TestDir::new("owner-b"), TestDir::new("owner-c"));
        let first = open_controller_at(&root, &side_a).unwrap();
        let second = open_controller_at(&root, &side_b).err().expect("a second simultaneous open must be refused");
        assert!(second.contains("already open"), "{second}");
        let other = TestDir::new("controller-owner-other");
        let other_root = other.path().to_path_buf();
        drop(open_controller_at(&other_root, &side_c).unwrap());
        drop(first);
        drop(open_controller_at(&root, &side_b).unwrap());
    }

    /// The idle lock clears every pending acknowledgement and WITHDRAWS an approval the gate already
    /// issued, even one a caller still holds: wallet-core refuses it with `APPROVAL_REVOKED`.
    #[test]
    fn the_idle_lock_clears_pending_approvals_and_withdraws_issued_ones() {
        let base = TestDir::new("controller-idle");
        let (mut controller, _, _) = fixture(&base);
        controller.unlock(PASSWORD).unwrap();
        let screen = controller.prepare([94; 32], 50_000).unwrap();
        confirm_everything(&mut controller, &screen);
        // Take the approval out of the gate (only this test hook can) and keep the plan.
        let parts = controller.view_parts().unwrap();
        let view = ChainView::verified(parts.head.clone(), &parts.state, &parts.reserved).unwrap();
        let plan = controller.plan.as_mut().unwrap();
        let planned = plan.plan_for_test().unwrap().clone();
        let approval = plan.approve_for_test(&view).unwrap();
        // The idle limit passes.
        controller.last_activity = Some(Instant::now() - IDLE_LIMIT);
        controller.tick();
        assert!(controller.session.is_none() && controller.plan.is_none());
        // The approval was withdrawn: even a fresh signer for the same key cannot use it.
        let signer = KeySigner::for_test(
            mutiny_crypto_v2::HybridKey::wallet_restore(
                &format!("{}art", "abandon ".repeat(23)),
                mutiny_crypto_v2::Role::WalletOwner,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            signer.authorize(planned, approval, &view).unwrap_err(),
            Refusal::ApprovalRevoked
        );
        // And the session that is unlocked again starts with nothing confirmed.
        controller.unlock(PASSWORD).unwrap();
        let screen = controller.prepare([94; 32], 50_000).unwrap();
        assert!(screen.status.acknowledged.is_empty() && !screen.status.ready);
    }

    /// Q2: a new verified head clears the gate (every acknowledgement and typed check) and the plan
    /// is reviewed again at the new head; Authorize then refuses until everything is given again.
    #[test]
    fn a_new_head_clears_the_gate_and_the_review_starts_again() {
        let base = TestDir::new("controller-head");
        let (mut controller, _, _) = fixture(&base);
        controller.unlock(PASSWORD).unwrap();
        let screen = controller.prepare([94; 32], 50_000).unwrap();
        confirm_everything(&mut controller, &screen);
        assert!(controller.screen().unwrap().unwrap().status.ready);
        // Model a new verified head for the plan on screen (the replica cannot certify blocks in a
        // unit test): the plan's session sees a view one block later.
        let parts = controller.view_parts().unwrap();
        let mut moved = parts.head.anchor().clone();
        moved.height += 1;
        moved.block[0] ^= 0xff;
        let head = HeadInfo::new(
            moved,
            parts.head.timestamp() + 60,
            parts.head.t0(),
            parts.head.state_root(),
        )
        .unwrap();
        let later = ChainView::new(head, &parts.state, &parts.reserved);
        let plan = controller.plan.as_mut().unwrap();
        plan.on_head(&later);
        let after = plan.screen(&later).unwrap();
        assert!(after.status.fresh, "reviewed again at the new head");
        assert_ne!(after.status.digest, screen.status.digest);
        assert!(after.status.acknowledged.is_empty());
        assert!(after.status.destinations_confirmed.is_empty());
        assert!(!after.status.ready);
        assert!(after.status.notice.is_some());
        let signer = &controller.session.as_ref().unwrap().signer;
        assert!(matches!(
            controller.plan.as_mut().unwrap().authorize(signer, &later),
            Err(Refusal::AcknowledgementMissing(_) | Refusal::DestinationCheckPending)
        ));
    }

    /// Every acknowledgement is required: with any one of them missing Authorize refuses, signs
    /// nothing and queues nothing; a mistyped address ending is refused and shown, not fatal.
    #[test]
    fn approval_needs_every_acknowledgement_and_every_typed_check() {
        let base = TestDir::new("controller-acks");
        let (mut controller, _, _) = fixture(&base);
        controller.unlock(PASSWORD).unwrap();
        let screen = controller.prepare([94; 32], 50_000).unwrap();
        let review = screen.review.clone();
        assert!(!review.acknowledgements().is_empty());
        for skipped in review.acknowledgements() {
            let screen = controller.prepare([94; 32], 50_000).unwrap();
            for index in screen.review.destinations_needing_check() {
                let typed = screen.review.destination_check_text(index);
                controller
                    .review_input(ReviewInput::ConfirmDestination { index, typed })
                    .unwrap();
            }
            for ack in screen.review.acknowledgements() {
                if ack != skipped {
                    controller
                        .review_input(ReviewInput::Acknowledge(*ack))
                        .unwrap();
                }
            }
            assert!(!controller.screen().unwrap().unwrap().status.ready);
            let refused = authorize(&mut controller).unwrap_err();
            assert!(refused.contains("ACKNOWLEDGEMENT_MISSING"), "{refused}");
            assert!(controller.pending_for_transport().unwrap().is_empty());
        }
        // A wrong address ending is refused and reported on the screen.
        controller.prepare([94; 32], 50_000).unwrap();
        let ReviewOutcome::Screen(shown) = controller
            .review_input(ReviewInput::ConfirmDestination {
                index: 0,
                typed: "00000000".into(),
            })
            .unwrap()
        else {
            panic!("screen expected");
        };
        assert_eq!(
            shown.status.refusal.as_ref().map(|(code, _)| code.as_str()),
            Some("DESTINATION_CHECK_FAILED")
        );
        assert!(shown.status.destinations_confirmed.is_empty());
        // The Destination acknowledgement needs the typed check first.
        let ReviewOutcome::Screen(shown) = controller
            .review_input(ReviewInput::Acknowledge(
                mutiny_wallet_core_v8::AckKind::Destination,
            ))
            .unwrap()
        else {
            panic!("screen expected");
        };
        assert_eq!(
            shown.status.refusal.as_ref().map(|(code, _)| code.as_str()),
            Some("DESTINATION_CHECK_PENDING")
        );
        assert!(controller.pending_for_transport().unwrap().is_empty());
    }

    /// P6 end to end: the rotation is signed by the two-key session (the second unlock of the
    /// current key plus the clean restore of the new phrase), consensus verifies the exact bytes,
    /// and once the verified chain shows the rotation the vault replacement (stage, read back, flip
    /// the pointer) makes the vault hold the NEW identity, which then signs; the old record is kept
    /// until its explicit retirement.
    #[test]
    fn a_signed_rotation_and_the_vault_replacement_leave_the_vault_holding_the_new_identity() {
        use mutiny_consensus_v8::hybrid_transaction_v2::Transaction;
        let base = TestDir::new("controller-rotation");
        let (mut controller, old_identity, mut chain) = certified_rotation_fixture(&base);
        let genesis = chain.genesis().clone();
        controller.unlock(PASSWORD).unwrap();
        let old_phrase = format!("{}art", "abandon ".repeat(23));
        let new_phrase = format!("{}vote", "zoo ".repeat(23));
        let named = crate::wallet_v2::RestoredKey::restore(&new_phrase, 2, None)
            .unwrap()
            .descriptor()
            .to_vec();
        // The clean-restore check and the password come before anything is planned.
        assert!(
            controller
                .begin_rotation(PASSWORD, &old_phrase, &named, 144)
                .is_err()
        );
        assert!(
            controller
                .begin_rotation("WRONG PASSWORD", &new_phrase, &named, 144)
                .is_err()
        );
        assert!(controller.plan.is_none() && controller.rotation.is_none());
        let screen = controller
            .begin_rotation(PASSWORD, &new_phrase, &named, 144)
            .unwrap();
        assert_eq!(screen.review.kind(), OperationKind::WalletRotation);
        assert!(
            screen.review.requires_phrase(),
            "a key rotation is high risk"
        );
        assert!(controller.rotation.is_some());
        confirm_everything(&mut controller, &screen);
        let queued = authorize(&mut controller).unwrap();
        assert_eq!(queued.kind, OperationKind::WalletRotation);
        assert!(queued.complete);
        assert!(
            controller.rotation.is_none(),
            "both keys are erased once signed"
        );
        // The exported bytes are the signed funded rotation; consensus verifies them.
        let raw = controller.export(queued.id).unwrap();
        let state = controller.with_view(|view| view.state().clone()).unwrap();
        let tx = Transaction::decode(&raw).unwrap();
        tx.verify(
            &mutiny_consensus_v8::hybrid_transaction_v2::Inclusion {
                parent: &genesis,
                history: &mutiny_consensus_v8::evidence_history_v2::History::default(),
            },
            &state,
        )
        .unwrap();
        // The post-rotation chain: consensus' wallet book applies exactly this rotation, and the
        // funding transfer spends its coin and creates its outputs.
        let id = tx.id().unwrap();
        assert!(matches!(&tx, Transaction::FundedRotation(_)));
        chain.admit(&tx).unwrap();
        chain.step();
        let records = chain.verified_operations(id);
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].wire,
            mutiny_consensus_v8::submission_v1::Submission::decode(0, &raw)
                .unwrap()
                .wire
        );
        assert_eq!(records[0].height, 1);
        chain = chain.restart();
        assert_eq!(chain.verified_operations(id), records);
        drop(controller);
        let mut controller = controller_on_certified_chain(&base, &chain, "outbox-rotated.sqlite");
        controller.unlock(PASSWORD).unwrap();
        assert_eq!(controller.identity(), Some(&old_identity));
        assert_eq!(
            controller.confirmed_rotation().unwrap(),
            Some(named.clone())
        );
        let balance_before_replacement = controller.balance().unwrap().unwrap();
        assert!(balance_before_replacement.total_atoms > 0, "canonical rotation preserves monetary rights before local vault replacement");
        // The old key has no authority any more.
        let refused = controller.prepare([94; 32], 30_000).unwrap_err();
        assert!(refused.contains("STALE_AUTHORITY"), "{refused}");
        // The replacement needs exactly the confirmed key's phrase and the vault password; a refused
        // attempt leaves nothing staged.
        assert!(controller.replace_vault(PASSWORD, &old_phrase).is_err());
        assert!(
            controller
                .replace_vault("WRONG PASSWORD", &new_phrase)
                .is_err()
        );
        let status = controller.vault_status().unwrap().unwrap();
        assert_eq!((status.active.generation, status.staged), (1, None));
        assert!(
            controller.retire_previous_identity(PASSWORD).is_err(),
            "nothing to retire"
        );
        let new_identity = controller.replace_vault(PASSWORD, &new_phrase).unwrap();
        assert_eq!(new_identity.generation, 2);
        assert_eq!(new_identity.authority_id, old_identity.authority_id);
        assert_eq!(new_identity.owner_descriptor, hex::encode(&named));
        assert!(
            controller.identity().is_none(),
            "locked after the replacement"
        );
        let status = controller.vault_status().unwrap().unwrap();
        assert_eq!(status.active, new_identity);
        assert_eq!(status.superseded.as_ref(), Some(&old_identity));
        assert_eq!(controller.balance().unwrap(), Some(balance_before_replacement));
        assert_eq!(controller.confirmed_rotation().unwrap(), None);
        // The retirement's chain check (survivor D3 of the independent wallet review): over a
        // verified chain that does not show the rotation (the pre-rotation state), the active
        // identity is not the chain's current authority, so the previous identity is kept.
        drop(controller);
        let mut before = controller_over(
            &base,
            &state,
            &genesis,
            "chain-before.sqlite",
            "outbox-before.sqlite",
        );
        let refused = before.retire_previous_identity(PASSWORD).unwrap_err();
        assert_eq!(
            refused,
            RetirementRefusal::SuccessorNotCanonical {
                chain_generation: Some(1)
            }
        );
        assert!(
            refused
                .to_string()
                .contains("not the chain's current authority"),
            "{refused}"
        );
        assert_eq!(
            before.vault_status().unwrap().unwrap().superseded.as_ref(),
            Some(&old_identity)
        );
        drop(before);
        let mut controller =
            controller_on_certified_chain(&base, &chain, "outbox-rotated-2.sqlite");
        // The new identity unlocks and signs (its change coin from the rotation).
        controller.unlock(PASSWORD).unwrap();
        assert_eq!(controller.identity(), Some(&new_identity));
        let screen = controller.prepare([94; 32], 30_000).unwrap();
        confirm_everything(&mut controller, &screen);
        assert_eq!(
            authorize(&mut controller).unwrap().kind,
            OperationKind::Payment
        );
        // The previous identity goes only by the explicit act, now that the new one is current.
        assert!(
            controller
                .retire_previous_identity("WRONG PASSWORD")
                .is_err()
        );
        controller.retire_previous_identity(PASSWORD).unwrap();
        assert!(
            controller
                .vault_status()
                .unwrap()
                .unwrap()
                .superseded
                .is_none()
        );
        assert!(controller.retire_previous_identity(PASSWORD).is_err());
    }

    /// A vault for the public TEST-VALUE key B (the all-"zoo" vector) under `base`.
    fn key_b_vault(base: &TestDir) {
        let session = Session::restore_initial(&format!("{}vote", "zoo ".repeat(23))).unwrap();
        Store::open(&custody_file(base, "wallet-hybrid-v2.sqlite"))
            .unwrap()
            .save_initial(&session, PASSWORD)
            .unwrap();
    }

    /// Partial-operation exchange (Q12, public data only): wallet A signs its part of a hash lock
    /// and exports the public container; wallet B reviews the same digest from it, adopts it and
    /// signs its own part; the maker's fill completes it in A (`complete_conditional` signs nothing)
    /// and consensus accepts the complete operation. B made the preimage: it stays in B's sealed
    /// store, and nothing A or B exported contains it.
    #[test]
    fn a_hash_lock_is_exchanged_as_public_partials_and_completed() {
        use crate::test_support::conditional_kit;
        use mutiny_wallet_core_v8::HashLockRequest;
        let (state, genesis, _) = fixture_state();
        let base_a = TestDir::new("controller-lock-a");
        let base_b = TestDir::new("controller-lock-b");
        let (mut a, _, _) = fixture(&base_a);
        key_b_vault(&base_b);
        let mut b = controller_over(&base_b, &state, &genesis, "chain.sqlite", "outbox.sqlite");
        a.unlock(PASSWORD).unwrap();
        b.unlock(PASSWORD).unwrap();
        let b_address = b.signer_identity().unwrap().address();
        // B makes the preimage (fresh OS randomness, sealed in B's store) and gives A its condition.
        let condition = b.create_preimage().unwrap();
        assert_eq!(b.preimage_conditions().unwrap(), vec![condition]);
        // The maker's offer (played by the test, Q7: this wallet imports offers, never makes them).
        let maker = conditional_kit::maker_key();
        let offer = conditional_kit::signed_offer(
            &maker,
            conditional_kit::context_of(&genesis),
            0,
            200,
            10_000,
            1,
            7,
        );
        let request = HashLockRequest::new(
            Blob::new(conditional_kit::offer_bytes(&offer)),
            b_address,
            10_000,
            condition,
            100,
        );
        let screen = a.request(OperationRequest::HashLock(request)).unwrap();
        assert!(screen.review.requires_phrase());
        confirm_everything(&mut a, &screen);
        let a_part = authorize(&mut a).unwrap();
        assert_eq!(a_part.kind, OperationKind::HashLock);
        assert!(!a_part.complete && !a_part.missing.is_empty());
        let a_container = a.export(a_part.id).unwrap();
        // Order W10: B's preimage (sealed in B's store) is in no public partial.
        let secret = b.preimages.plaintext_for_test(&condition).unwrap();
        crate::test_support::assert_no_secret_in_bytes(&a_container, &secret, "A's public partial");
        // B reviews exactly what A reviewed (the same binding digest), then adopts and signs.
        let seen = b.explain_partial(&a_container).unwrap();
        assert_eq!(seen.binding(), screen.review.binding());
        let b_screen = b.adopt_partial(&a_container).unwrap();
        assert_eq!(b_screen.review.binding(), screen.review.binding());
        confirm_everything(&mut b, &b_screen);
        let b_part = authorize(&mut b).unwrap();
        assert!(!b_part.complete);
        let b_container = b.export(b_part.id).unwrap();
        // The maker fills the exact body; A completes and queues the complete operation in place
        // of its partial.
        let a_bytes = PartialApproval::import(&a_container)
            .unwrap()
            .bytes()
            .to_vec();
        let b_bytes = PartialApproval::import(&b_container)
            .unwrap()
            .bytes()
            .to_vec();
        let fill = conditional_kit::fill_for(&a_bytes, &offer, &maker);
        let held = a.operations.reserved().unwrap();
        assert!(!held.is_empty());
        // An identifier that is not this wallet's partial of the operation is refused, and changes
        // nothing: the partial stays queued with its reservations.
        for wrong in [[0x55; 32], b_part.id] {
            let refused = a
                .complete_conditional(wrong, &[a_bytes.clone(), b_bytes.clone()], Some(&fill))
                .unwrap_err();
            assert!(refused.contains("UNKNOWN_OPERATION"), "{refused}");
            assert_eq!(a.operations.reserved().unwrap(), held);
            assert_eq!(a.operations.records().unwrap().len(), 1);
        }
        crate::test_support::assert_no_secret_in_bytes(&b_container, &secret, "B's public partial");
        crate::test_support::assert_no_secret_in_bytes(&fill, &secret, "the maker's fill");
        let complete = a
            .complete_conditional(a_part.id, &[a_bytes, b_bytes], Some(&fill))
            .unwrap();
        assert!(complete.complete && complete.kind == OperationKind::HashLock);
        let raw = a.export(complete.id).unwrap();
        a.with_view(|view| conditional_kit::consensus_in(view, &raw))
            .unwrap()
            .unwrap();
        crate::test_support::assert_no_secret_in_bytes(&raw, &secret, "the complete hash lock");
        // The complete record took the partial's place in ONE step (wallet review fixes, MINOR-1):
        // the partial's record is gone, not forgotten beside it, and the complete record holds
        // exactly what the partial held.
        let records = a.queued_operations().unwrap();
        assert!(
            records
                .iter()
                .any(|(q, status)| q.id == complete.id && status == "Queued")
        );
        assert!(records.iter().all(|(q, _)| q.id != a_part.id));
        assert_eq!(records.len(), 1);
        assert_eq!(a.operations.reserved().unwrap(), held);
    }

    /// The claim takes its preimage from the desktop's sealed store (`claim_request`): planned,
    /// reviewed (high risk; the disclosure acknowledged), signed and queued in the sealed outbox.
    /// The preimage is erased only on the person's request.
    #[test]
    fn a_claim_takes_its_preimage_from_the_sealed_store_and_is_queued_sealed() {
        use crate::test_support::conditional_kit;
        use mutiny_consensus_v8::trading_v1::{
            self, NativeLock, NativeLockKind, NativeRecord, Strikes,
        };
        let (mut state, genesis, identity_a) = fixture_state();
        let base = TestDir::new("controller-claim");
        key_b_vault(&base);
        // B's preimage store first: the condition the lock is made with.
        let condition = {
            let mut b =
                controller_over(&base, &state, &genesis, "chain-0.sqlite", "outbox-0.sqlite");
            b.unlock(PASSWORD).unwrap();
            b.create_preimage().unwrap()
        };
        let b_address = Session::restore_initial(&format!("{}vote", "zoo ".repeat(23)))
            .unwrap()
            .identity()
            .address_id
            .clone();
        let b_address: Hash = hex::decode(b_address).unwrap().try_into().unwrap();
        let lock = [0x6c; 32];
        state.protocol_records.insert(
            trading_v1::record_key(0, lock),
            NativeRecord::Lock(NativeLock {
                context: conditional_kit::context_of(&genesis),
                trade: [1; 32],
                contract: [2; 32],
                generation: 1,
                sender: hex::decode(&identity_a.address_id)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                recipient: b_address,
                amount: Strikes(10_000),
                created_height: 0,
                kind: NativeLockKind::Hash {
                    condition,
                    refund_height: 150,
                },
            })
            .encode(lock)
            .unwrap(),
        );
        // A lock exists only once its maker's offer was consumed: the single-fill record that
        // consensus keeps for good (and from which it derives the chain context of the native
        // records once the claim has removed the lock).
        let offer = [0x6f; 32];
        let context = conditional_kit::context_of(&genesis);
        let consumed = trading_v1::single_fill_key(&context, [0; 32], offer);
        state.protocol_records.insert(
            trading_v1::record_key(1, consumed),
            NativeRecord::Consumed {
                context,
                offer,
                trade: [1; 32],
                contract: [2; 32],
            }
            .encode(consumed)
            .unwrap(),
        );
        state.coins.insert(
            OutPoint {
                transaction: [0x5c; 32],
                index: 0,
            },
            Coin {
                output: Output {
                    owner: b_address,
                    atoms: 100_000,
                },
                created_height: 0,
                coinbase: false,
            },
        );
        let mut b = controller_over(&base, &state, &genesis, "chain-1.sqlite", "outbox-1.sqlite");
        b.unlock(PASSWORD).unwrap();
        let claim = b.claim_request(lock).unwrap();
        assert_eq!(claim.preimage.condition(), condition);
        let screen = b
            .request(OperationRequest::ConditionalClaim(claim))
            .unwrap();
        assert!(screen.review.requires_phrase());
        assert!(
            screen
                .review
                .acknowledgements()
                .contains(&mutiny_wallet_core_v8::AckKind::DisclosesPreimage)
        );
        confirm_everything(&mut b, &screen);
        let queued = authorize(&mut b).unwrap();
        assert!(queued.complete && queued.kind == OperationKind::ConditionalClaim);
        // Erasure is the person's explicit act; afterwards no claim can be made from this store.
        assert!(b.erase_preimage(condition).unwrap());
        assert!(b.claim_request(lock).is_err());
        assert!(b.preimage_conditions().unwrap().is_empty());
    }

    /// The claim world of `a_claim_takes_its_preimage_from_the_sealed_store_and_is_queued_sealed`: key
    /// B's vault under `base` with a fresh preimage in B's sealed store, and a verified state holding a
    /// hash lock of 10,000 STRIKES to B under that preimage's condition (its offer's single-fill record
    /// beside it) and a fee coin of B. Returns (state, genesis, condition, lock).
    fn claim_world(base: &TestDir) -> (State, FinalizedAnchor, Hash, Hash) {
        use crate::test_support::conditional_kit;
        use mutiny_consensus_v8::trading_v1::{
            self, NativeLock, NativeLockKind, NativeRecord, Strikes,
        };
        let (mut state, genesis, identity_a) = fixture_state();
        key_b_vault(base);
        let condition = {
            let mut b =
                controller_over(base, &state, &genesis, "chain-0.sqlite", "outbox-0.sqlite");
            b.unlock(PASSWORD).unwrap();
            b.create_preimage().unwrap()
        };
        let b_address: Hash = hex::decode(
            Session::restore_initial(&format!("{}vote", "zoo ".repeat(23)))
                .unwrap()
                .identity()
                .address_id
                .clone(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        let lock = [0x6c; 32];
        let context = conditional_kit::context_of(&genesis);
        state.protocol_records.insert(
            trading_v1::record_key(0, lock),
            NativeRecord::Lock(NativeLock {
                context: context.clone(),
                trade: [1; 32],
                contract: [2; 32],
                generation: 1,
                sender: hex::decode(&identity_a.address_id)
                    .unwrap()
                    .try_into()
                    .unwrap(),
                recipient: b_address,
                amount: Strikes(10_000),
                created_height: 0,
                kind: NativeLockKind::Hash {
                    condition,
                    refund_height: 150,
                },
            })
            .encode(lock)
            .unwrap(),
        );
        let offer = [0x6f; 32];
        let consumed = trading_v1::single_fill_key(&context, [0; 32], offer);
        state.protocol_records.insert(
            trading_v1::record_key(1, consumed),
            NativeRecord::Consumed {
                context,
                offer,
                trade: [1; 32],
                contract: [2; 32],
            }
            .encode(consumed)
            .unwrap(),
        );
        state.coins.insert(
            OutPoint {
                transaction: [0x5c; 32],
                index: 0,
            },
            Coin {
                output: Output {
                    owner: b_address,
                    atoms: 100_000,
                },
                created_height: 0,
                coinbase: false,
            },
        );
        (state, genesis, condition, lock)
    }

    /// Order W10, end to end through the controller: the claim's preimage is created sealed, the
    /// claim is reviewed (the disclosure acknowledged), signed and queued sealed; then NO file of the
    /// wallet's folders (vault, outbox, preimage store, their journals, the verified chain store, the
    /// payment pool) holds the preimage, raw or hexadecimal. It leaves the wallet only inside the
    /// authorized settlement payload, the claim's export (which does carry it: the scan's positive
    /// control). A claim can never enter the payment pool, whose file is not sealed.
    #[test]
    fn a_claim_preimage_reaches_disk_only_sealed_and_leaves_only_in_its_export() {
        let base = TestDir::new("w10-claim-files");
        let (state, genesis, condition, lock) = claim_world(&base);
        let mut b = controller_over(&base, &state, &genesis, "chain-1.sqlite", "outbox-1.sqlite");
        b.unlock(PASSWORD).unwrap();
        let secret = b.preimages.plaintext_for_test(&condition).unwrap();
        let claim = b.claim_request(lock).unwrap();
        let screen = b
            .request(OperationRequest::ConditionalClaim(claim))
            .unwrap();
        confirm_everything(&mut b, &screen);
        let queued = authorize(&mut b).unwrap();
        assert!(queued.complete && queued.kind == OperationKind::ConditionalClaim);
        let export = b.export(queued.id).unwrap();
        assert!(
            export.windows(32).any(|window| window == secret),
            "the claim's export is the settlement payload and carries the preimage"
        );
        // The scans see the preimage where it is (their positive controls): in bytes, and in a file
        // nested in a folder (as lower-case hexadecimal).
        assert!(
            std::panic::catch_unwind(|| {
                crate::test_support::assert_no_secret_in_bytes(&export, &secret, "probe")
            })
            .is_err()
        );
        let probe = TestDir::new("w10-scan-probe");
        std::fs::create_dir(probe.file("nested")).unwrap();
        std::fs::write(probe.file("nested").join("leak.txt"), hex::encode(secret)).unwrap();
        assert!(
            std::panic::catch_unwind(|| {
                crate::test_support::assert_no_secret_in_files(probe.path(), &secret, "probe")
            })
            .is_err()
        );
        // The payment pool takes complete payments only: the claim is refused before the pool or the
        // chain is touched.
        let (signed, anchor) = b
            .with_view(|view| {
                (
                    SignedOperation::import(&export, view).unwrap(),
                    view.anchor().clone(),
                )
            })
            .unwrap();
        assert_eq!(
            b.replica
                .queue_signed_payment(&mut b.outbox, &signed, &anchor)
                .unwrap_err(),
            "Only a complete payment enters the payment queue"
        );
        let scanned =
            crate::test_support::assert_no_secret_in_files(base.path(), &secret, "after the claim");
        assert!(scanned >= 7, "only {scanned} files scanned");
        drop(b);
        crate::test_support::assert_no_secret_in_files(base.path(), &secret, "after closing");
    }

    /// Order W10: no `Debug` or `Display` rendering along a claim's way through the wallet shows its
    /// preimage (hexadecimal, byte list, or partial windows: `test_support::assert_no_secret_in_text`):
    /// the claim request, the review screen and its text, the outcome, the queued record and its list,
    /// the outbox, the preimage store, the service's events (an `Exported` event shows a length, never
    /// the claim's bytes), a completed trade, and the refusals met on the way.
    #[test]
    fn debug_and_display_output_never_carry_a_preimage() {
        use crate::wallet_controller_v2::host::service::Event;
        let base = TestDir::new("w10-claim-debug");
        let (state, genesis, condition, lock) = claim_world(&base);
        let mut b = controller_over(&base, &state, &genesis, "chain-1.sqlite", "outbox-1.sqlite");
        b.unlock(PASSWORD).unwrap();
        let secret = b.preimages.plaintext_for_test(&condition).unwrap();
        let mut shown: Vec<(&str, String)> = Vec::new();
        let claim = b.claim_request(lock).unwrap();
        shown.push(("ClaimRequest", format!("{claim:?}")));
        let screen = b
            .request(OperationRequest::ConditionalClaim(claim))
            .unwrap();
        shown.push(("ReviewScreen", format!("{screen:?}")));
        shown.push(("the review text", screen.review.render_text()));
        shown.push((
            "Event::Review",
            format!("{:?}", Event::Review(Box::new(screen.clone()))),
        ));
        // A mistyped confirmation phrase is refused; its refusal shows no preimage either.
        let ReviewOutcome::Screen(refused) = b
            .review_input(ReviewInput::ConfirmPhrase("WRONG PHRASE".into()))
            .unwrap()
        else {
            panic!("a refused input is shown on the screen");
        };
        assert!(refused.status.refusal.is_some());
        shown.push(("a refused input", format!("{refused:?}")));
        confirm_everything(&mut b, &screen);
        let outcome = b.review_input(ReviewInput::Authorize).unwrap();
        shown.push(("ReviewOutcome", format!("{outcome:?}")));
        let ReviewOutcome::Queued(queued) = outcome else {
            panic!("queued");
        };
        shown.push((
            "Event::Queued",
            format!("{:?}", Event::Queued(queued.clone())),
        ));
        shown.push((
            "queued_operations",
            format!("{:?}", b.queued_operations().unwrap()),
        ));
        shown.push((
            "the outbox records",
            format!("{:?}", b.operations.records().unwrap()),
        ));
        shown.push(("OperationOutbox", format!("{:?}", b.operations)));
        shown.push(("PreimageVault", format!("{:?}", b.preimages)));
        let export = b.export(queued.id).unwrap();
        assert!(export.windows(32).any(|window| window == secret));
        let event = Event::Exported {
            id: queued.id,
            bytes: export.clone(),
        };
        let event_text = format!("{event:?}");
        assert!(
            event_text.contains(&format!("<{} bytes, not shown>", export.len())),
            "{event_text}"
        );
        shown.push(("Event::Exported", event_text));
        let trade = CompletedTrade {
            id: queued.id,
            kind: OperationKind::ConditionalClaim,
            bytes: export.clone(),
            queued: true,
        };
        shown.push(("CompletedTrade", format!("{trade:?}")));
        // Erased on the person's request: the next claim request is refused, and says nothing secret.
        assert!(b.erase_preimage(condition).unwrap());
        let refusal = b.claim_request(lock).unwrap_err();
        shown.push(("the claim refusal after erasure", refusal));
        for (what, text) in &shown {
            crate::test_support::assert_no_secret_in_text(text, &secret, what);
        }
        assert!(shown.len() >= 14, "{} renderings", shown.len());
    }

    /// A vault for the public TEST-VALUE key A (the "abandon ... art" vector) under `base`.
    fn key_a_vault(base: &TestDir) {
        let session = Session::restore_initial(&format!("{}art", "abandon ".repeat(23))).unwrap();
        Store::open(&custody_file(base, "wallet-hybrid-v2.sqlite"))
            .unwrap()
            .save_initial(&session, PASSWORD)
            .unwrap();
    }

    /// Phase 5B through the desktop: the seller's wallet (A) plans a fiat lock from the form's
    /// request (the buyer's public descriptor given), signs slot 0 and exports the public part;
    /// the buyer's wallet (B) reviews the same digest, adopts and signs slot 1; with the maker's
    /// fill over the exact body `complete_trade` merges the parts (signing nothing) and consensus
    /// accepts the complete bytes. A's own part holds the operation identifier: the complete
    /// operation replaces it in one step (wallet review fixes, MINOR-1) and takes over its
    /// reservations, and the bytes are returned for export as well.
    #[test]
    fn a_fiat_lock_is_signed_by_both_wallets_and_completed_from_public_parts() {
        use crate::{
            operation_screens::{FormKind, FormOutput, Forms},
            test_support::conditional_kit,
        };
        use mutiny_consensus_v8::trading_v1::{OfferBody, OfferTerms, SignedOffer, Strikes};
        let (state, genesis, _) = fixture_state();
        let base_a = TestDir::new("controller-fiat-a");
        let base_b = TestDir::new("controller-fiat-b");
        let (mut a, _, _) = fixture(&base_a);
        key_b_vault(&base_b);
        let mut b = controller_over(&base_b, &state, &genesis, "chain.sqlite", "outbox.sqlite");
        a.unlock(PASSWORD).unwrap();
        b.unlock(PASSWORD).unwrap();
        let buyer = b.identity().unwrap().clone();
        // The maker's offer (played by the test, Q7: the wallet imports offers, never makes them).
        let maker = mutiny_crypto_v2::HybridKey::wallet_restore(
            &format!("{}art", "abandon ".repeat(23)),
            mutiny_crypto_v2::Role::WalletOwner,
        )
        .unwrap();
        let offer = SignedOffer::sign(
            OfferBody {
                context: conditional_kit::context_of(&genesis),
                maker_descriptor: maker.public().descriptor(1).unwrap(),
                maker_wallet: maker.public().address_id(1).unwrap(),
                destination: maker.public().address_id(1).unwrap(),
                condition: None,
                max_fee: Strikes(100_000),
                nonce: [0x41; 32],
                created: 0,
                expiry: 200,
                maker_side: 0,
                terms: OfferTerms::Fiat {
                    amount: Strikes(10_000),
                    payment_terms: [0x77; 32],
                },
            },
            &maker,
        )
        .unwrap();
        let mut forms = Forms::default();
        forms.offer = hex::encode(offers::encode_offer(&offer).unwrap());
        forms.buyer = mutiny_wallet_core_v8::address_format::encode(
            &buyer.signer_identity().unwrap().address(),
            mutiny_wallet_core_v8::ChainClass::TestValue,
        );
        forms.address_class = Some(mutiny_wallet_core_v8::ChainClass::TestValue);
        forms.amount = "0.0001".into();
        forms.payment_terms = hex::encode([0x77; 32]);
        forms.trade = hex::encode([0x73; 32]);
        forms.contract = hex::encode([0x74; 32]);
        forms.descriptor = buyer.owner_descriptor.clone();
        let FormOutput::Request(request) = forms.build(FormKind::FiatLock).unwrap() else {
            panic!("a request");
        };
        let screen = a.request(*request).unwrap();
        assert_eq!(screen.review.kind(), OperationKind::FiatLock);
        assert!(screen.review.requires_phrase());
        for ack in [
            mutiny_wallet_core_v8::AckKind::NoUnilateralExit,
            mutiny_wallet_core_v8::AckKind::ExternalEvidence,
        ] {
            assert!(screen.review.acknowledgements().contains(&ack), "{ack:?}");
        }
        confirm_everything(&mut a, &screen);
        let a_part = authorize(&mut a).unwrap();
        assert_eq!(a_part.kind, OperationKind::FiatLock);
        assert!(!a_part.complete && !a_part.missing.is_empty());
        let a_container = a.export(a_part.id).unwrap();
        // B reviews exactly what A reviewed, then adopts and signs its own slot.
        assert_eq!(
            b.explain_partial(&a_container).unwrap().binding(),
            screen.review.binding()
        );
        let b_screen = b.adopt_partial(&a_container).unwrap();
        assert_eq!(b_screen.review.binding(), screen.review.binding());
        confirm_everything(&mut b, &b_screen);
        let b_part = authorize(&mut b).unwrap();
        assert!(!b_part.complete);
        assert_eq!(
            b_part.id, a_part.id,
            "a part and its operation share the identifier"
        );
        let b_container = b.export(b_part.id).unwrap();
        let a_bytes = PartialApproval::import(&a_container)
            .unwrap()
            .bytes()
            .to_vec();
        let b_bytes = PartialApproval::import(&b_container)
            .unwrap()
            .bytes()
            .to_vec();
        // A is the current maker: its owner approval also embeds a valid maker fill.
        // Both public parts complete with that fill and require no external copy.
        assert!(
            a.with_view(|view| { offers::combine(&[&a_bytes, &b_bytes], view) })
                .unwrap()
                .unwrap()
                .is_complete()
        );
        // Remove ONLY the fill from each part, retaining the genuine owner approvals.
        let unfilled: Vec<Vec<u8>> = [&a_bytes, &b_bytes]
            .iter()
            .map(|raw| {
                let mut wire = conditional_kit::wire(raw);
                wire.operation.offer_proof.as_mut().unwrap().fill_signature =
                    conditional_kit::zero();
                wire.encode().unwrap()
            })
            .collect();
        assert!(a.complete_trade(&unfilled, None).is_err());
        let fill = conditional_kit::fill_for(&a_bytes, &offer, &maker);
        let held = a.operations.reserved().unwrap();
        let completed = a.complete_trade(&[a_bytes, b_bytes], Some(&fill)).unwrap();
        assert_eq!(
            (completed.id, completed.kind),
            (a_part.id, OperationKind::FiatLock)
        );
        assert!(
            completed.queued,
            "A's own open part is replaced by the complete operation"
        );
        a.with_view(|view| conditional_kit::consensus_in(view, &completed.bytes))
            .unwrap()
            .unwrap();
        // A's record under the identifier is the complete operation now (replaced in one step; a
        // complete record exports its signed bytes), holding exactly what the part held.
        assert_eq!(a.export(a_part.id).unwrap(), completed.bytes);
        assert_eq!(a.operations.reserved().unwrap(), held);
        assert_eq!(a.operations.records().unwrap().len(), 1);
    }

    /// The fiat release (phase 5B): the buyer's wallet (B) plans it and signs slot 0 (it pays the
    /// fee); the seller's wallet (A) is told to approve only once the fiat payment has reached it
    /// and co-signs slot 1; `complete_trade` merges the two parts without any offer (a release
    /// fills none) and consensus accepts the result.
    #[test]
    fn a_fiat_release_is_planned_by_the_buyer_and_completed_with_the_sellers_part() {
        use crate::{
            operation_screens::{FormKind, FormOutput, Forms},
            test_support::conditional_kit,
        };
        use mutiny_consensus_v8::trading_v1::{
            self, NativeLock, NativeLockKind, NativeRecord, Strikes,
        };
        let (mut state, genesis, seller) = fixture_state();
        let buyer = Session::restore_initial(&format!("{}vote", "zoo ".repeat(23)))
            .unwrap()
            .identity()
            .clone();
        let address = |identity: &Identity| -> Hash {
            hex::decode(&identity.address_id)
                .unwrap()
                .try_into()
                .unwrap()
        };
        let context = conditional_kit::context_of(&genesis);
        let lock = [0x6a; 32];
        state.protocol_records.insert(
            trading_v1::record_key(0, lock),
            NativeRecord::Lock(NativeLock {
                context: context.clone(),
                trade: [0x73; 32],
                contract: [0x74; 32],
                generation: 1,
                sender: address(&seller),
                recipient: address(&buyer),
                amount: Strikes(10_000),
                created_height: 0,
                kind: NativeLockKind::Fiat { terms: [0x77; 32] },
            })
            .encode(lock)
            .unwrap(),
        );
        // The offer the lock filled stays consumed (consensus keeps the single-fill record).
        let offer = [0x6f; 32];
        let consumed = trading_v1::single_fill_key(&context, [0; 32], offer);
        state.protocol_records.insert(
            trading_v1::record_key(1, consumed),
            NativeRecord::Consumed {
                context,
                offer,
                trade: [0x73; 32],
                contract: [0x74; 32],
            }
            .encode(consumed)
            .unwrap(),
        );
        // The buyer's own coin pays the release fee.
        state.coins.insert(
            OutPoint {
                transaction: [0x5d; 32],
                index: 0,
            },
            Coin {
                output: Output {
                    owner: address(&buyer),
                    atoms: 100_000,
                },
                created_height: 0,
                coinbase: false,
            },
        );
        let base_a = TestDir::new("controller-release-a");
        let base_b = TestDir::new("controller-release-b");
        key_a_vault(&base_a);
        key_b_vault(&base_b);
        let mut a = controller_over(&base_a, &state, &genesis, "chain.sqlite", "outbox.sqlite");
        let mut b = controller_over(&base_b, &state, &genesis, "chain.sqlite", "outbox.sqlite");
        a.unlock(PASSWORD).unwrap();
        b.unlock(PASSWORD).unwrap();
        let mut forms = Forms::default();
        forms.lock = hex::encode(lock);
        forms.descriptor = seller.owner_descriptor.clone();
        let request = || match forms.build(FormKind::FiatRelease).unwrap() {
            FormOutput::Request(request) => *request,
            FormOutput::Claim(_) => panic!("a request"),
            FormOutput::MakerOffer { .. } => panic!("a direct request"),
        };
        // The seller cannot plan the release: only the buyer does.
        assert!(a.request(request()).is_err());
        let screen = b.request(request()).unwrap();
        assert_eq!(screen.review.kind(), OperationKind::FiatRelease);
        confirm_everything(&mut b, &screen);
        let b_part = authorize(&mut b).unwrap();
        assert!(!b_part.complete);
        let b_container = b.export(b_part.id).unwrap();
        let seen = a.explain_partial(&b_container).unwrap();
        assert_eq!(seen.binding(), screen.review.binding());
        assert!(
            seen.render_text().contains("fiat payment has reached you"),
            "{}",
            seen.render_text()
        );
        let a_screen = a.adopt_partial(&b_container).unwrap();
        confirm_everything(&mut a, &a_screen);
        let a_part = authorize(&mut a).unwrap();
        assert_eq!(a_part.id, b_part.id);
        let a_bytes = PartialApproval::import(&a.export(a_part.id).unwrap())
            .unwrap()
            .bytes()
            .to_vec();
        let b_bytes = PartialApproval::import(&b_container)
            .unwrap()
            .bytes()
            .to_vec();
        let held = b.operations.reserved().unwrap();
        let completed = b.complete_trade(&[b_bytes, a_bytes], None).unwrap();
        assert_eq!(completed.kind, OperationKind::FiatRelease);
        assert!(
            completed.queued,
            "B's own open part is replaced by the complete operation"
        );
        b.with_view(|view| conditional_kit::consensus_in(view, &completed.bytes))
            .unwrap()
            .unwrap();
        // B's record is the complete operation now (a complete record exports its signed bytes),
        // and it holds exactly what the part held.
        assert_eq!(b.export(b_part.id).unwrap(), completed.bytes);
        assert_eq!(b.operations.reserved().unwrap(), held);
        // A retry changes nothing.
        assert!(
            b.complete_trade(
                &[
                    PartialApproval::import(&b_container)
                        .unwrap()
                        .bytes()
                        .to_vec(),
                    PartialApproval::import(&a.export(a_part.id).unwrap())
                        .unwrap()
                        .bytes()
                        .to_vec()
                ],
                None
            )
            .unwrap()
            .queued
        );
        assert_eq!(b.operations.records().unwrap().len(), 1);
    }

    /// Q5 after the phase 6 merge: the Treasury profile comes ONLY from this machine's runtime
    /// declaration, which wallet-core's `profile::declare` checks against the verified chain at
    /// unlock. Without it the Genesis Treasury authority's spending is refused
    /// (`TREASURY_PROFILE_REQUIRED`); a declaration that does not hold refuses the unlock (nothing
    /// is unlocked); the one that holds gives the signer the Treasury profile, and the payment is
    /// planned, reviewed (bound to that profile), signed and queued.
    #[test]
    fn the_treasury_profile_comes_only_from_a_runtime_declaration_that_holds() {
        use mutiny_consensus_v8::{
            dividend_state_v1::DividendState,
            treasury_v1::{Class, Treasury},
        };
        use mutiny_wallet_core_v8::ChainClass;
        let (mut state, genesis, identity_a) = fixture_state();
        // A TEST-VALUE chain whose Genesis Treasury authority is key A ("abandon ... art").
        state.dividends = DividendState::genesis(
            Treasury::new(
                Class::TestValue,
                hex::decode(&identity_a.owner_descriptor).unwrap(),
            )
            .unwrap(),
        );
        let base = TestDir::new("controller-treasury");
        key_a_vault(&base);
        let open = |treasury: Option<TreasuryDeclaration>, chain: &str| {
            controller_with(
                &base,
                &state,
                &genesis,
                chain,
                &format!("pool-{chain}"),
                treasury,
            )
        };
        // No declaration: the ordinary profile, and the Treasury authority may not spend.
        let mut a = open(None, "chain-0.sqlite");
        a.unlock(PASSWORD).unwrap();
        assert_eq!(a.profile(), WalletProfile::Ordinary);
        let refused = a.prepare([94; 32], 30_000).unwrap_err();
        assert!(refused.contains("TREASURY_PROFILE_REQUIRED"), "{refused}");
        drop(a);
        // Declarations that do not hold refuse the unlock; nothing is unlocked.
        for (declaration, code) in [
            (
                TreasuryDeclaration::new(genesis.genesis, ChainClass::Production).with_authority(),
                "CHAIN_CLASS_MISMATCH",
            ),
            (
                TreasuryDeclaration::new([9; 32], ChainClass::TestValue).with_authority(),
                "WRONG_CONTEXT",
            ),
            (
                TreasuryDeclaration::new(genesis.genesis, ChainClass::TestValue),
                "INVALID_REQUEST",
            ),
        ] {
            let mut a = open(Some(declaration), "chain-1.sqlite");
            let refused = a.unlock(PASSWORD).unwrap_err();
            assert!(refused.contains(code), "{refused}");
            assert!(a.identity().is_none());
            assert_eq!(a.profile(), WalletProfile::Ordinary);
        }
        // The declaration that holds: the Treasury profile.
        let declaration =
            TreasuryDeclaration::new(genesis.genesis, ChainClass::TestValue).with_authority();
        let mut a = open(Some(declaration.clone()), "chain-2.sqlite");
        a.unlock(PASSWORD).unwrap();
        assert_eq!(a.profile(), WalletProfile::Treasury);
        // At every new verified head the declaration is checked again, and when it no longer holds
        // the wallet locks: the key is erased and the review on screen withdrawn. (White-box: the
        // unit-test replica cannot certify a new block, so the test forgets the last head and puts
        // in place a declaration this chain refuses.)
        let screen = a.prepare([94; 32], 20_000).unwrap();
        confirm_everything(&mut a, &screen);
        a.treasury = Some(
            TreasuryDeclaration::new(genesis.genesis, ChainClass::Production).with_authority(),
        );
        a.last_head = None;
        let refused = a.screen().unwrap_err();
        assert!(
            refused.contains("no longer holds") && refused.contains("CHAIN_CLASS_MISMATCH"),
            "{refused}"
        );
        assert!(a.identity().is_none() && a.plan.is_none());
        assert_eq!(a.profile(), WalletProfile::Ordinary);
        // With the declaration that holds, the authority's payment goes through the generic review
        // (bound to the Treasury profile), is signed and queued.
        a.treasury = Some(declaration.clone());
        a.unlock(PASSWORD).unwrap();
        let screen = a.prepare([94; 32], 30_000).unwrap();
        assert_eq!(screen.review.kind(), OperationKind::Payment);
        confirm_everything(&mut a, &screen);
        assert_eq!(authorize(&mut a).unwrap().kind, OperationKind::Payment);
        a.lock();
        assert_eq!(a.profile(), WalletProfile::Ordinary);
        drop(a);
        // The same declaration on a chain that names no Treasury (it declares no chain class) does
        // not hold.
        let (plain, _, _) = fixture_state();
        let mut a = controller_with(
            &base,
            &plain,
            &genesis,
            "chain-3.sqlite",
            "pool-3",
            Some(declaration),
        );
        let refused = a.unlock(PASSWORD).unwrap_err();
        assert!(
            refused.contains("CHAIN_CLASS_MISMATCH") && refused.contains("Undeclared"),
            "{refused}"
        );
        assert!(a.identity().is_none());
    }

    /// Order W16: the retirement gate is decided by the verified lineage alone; every refusal by its
    /// exact variant.
    #[test]
    fn retirement_is_allowed_only_when_the_verified_chain_names_the_successor() {
        let old = Session::restore_initial(&format!("{}art", "abandon ".repeat(23)))
            .unwrap()
            .identity()
            .clone();
        let authority: Hash = hex::decode(&old.authority_id).unwrap().try_into().unwrap();
        let next = |phrase: &str, generation: u64| -> Identity {
            let restored = RestoredKey::restore(phrase, generation, None).unwrap();
            let descriptor = restored.descriptor().to_vec();
            Session::restore_rotated(restored, authority, &descriptor)
                .unwrap()
                .identity()
                .clone()
        };
        let new = next(&format!("{}vote", "zoo ".repeat(23)), 2);
        let third = next(&format!("{}art", "abandon ".repeat(23)), 3);
        let stranger = Session::restore_initial(&format!("{}vote", "zoo ".repeat(23)))
            .unwrap()
            .identity()
            .clone();
        let descriptor = |identity: &Identity| hex::decode(&identity.owner_descriptor).unwrap();
        let status = |active: &Identity, superseded: Option<&Identity>| VaultStatus {
            revision: 3,
            active: active.clone(),
            staged: None,
            superseded: superseded.cloned(),
        };
        use RetirementRefusal::{NotThePredecessor, NothingToRetire, SuccessorNotCanonical};
        type Case = (
            VaultStatus,
            Option<Vec<u8>>,
            std::result::Result<(), RetirementRefusal>,
        );
        let cases: Vec<Case> = vec![
            (
                status(&new, None),
                Some(descriptor(&new)),
                Err(NothingToRetire),
            ),
            (
                status(&new, Some(&stranger)),
                Some(descriptor(&new)),
                Err(NotThePredecessor),
            ),
            (
                status(&third, Some(&old)),
                Some(descriptor(&third)),
                Err(NotThePredecessor),
            ),
            (
                status(&new, Some(&new)),
                Some(descriptor(&new)),
                Err(NotThePredecessor),
            ),
            (
                status(&new, Some(&old)),
                None,
                Err(SuccessorNotCanonical {
                    chain_generation: None,
                }),
            ),
            (
                status(&new, Some(&old)),
                Some(descriptor(&old)),
                Err(SuccessorNotCanonical {
                    chain_generation: Some(1),
                }),
            ),
            (
                status(&new, Some(&old)),
                Some(descriptor(&third)),
                Err(SuccessorNotCanonical {
                    chain_generation: Some(3),
                }),
            ),
            (
                status(&new, Some(&old)),
                Some(vec![1, 2, 3]),
                Err(SuccessorNotCanonical {
                    chain_generation: None,
                }),
            ),
            (status(&new, Some(&old)), Some(descriptor(&new)), Ok(())),
        ];
        for (index, (status, current, expected)) in cases.into_iter().enumerate() {
            assert_eq!(
                retirement_allowed(&status, current.as_deref()),
                expected,
                "case {index}"
            );
        }
        let text = SuccessorNotCanonical {
            chain_generation: Some(1),
        }
        .to_string();
        assert!(
            text.contains("generation 1") && text.contains("previous identity is kept"),
            "{text}"
        );
    }

    /// The W16 rotation world: key A's vault under `base` creates a preimage (pending secret
    /// metadata), signs a funded rotation to the all-"zoo" key with the two-key session and queues it.
    /// `before` is the fixture state; `rotated` is that state after consensus' wallet book applied
    /// exactly that rotation (its funding spent, its outputs created), plus one 1,000,000-atom coin at
    /// key A's generation-one ADDRESS: the previous identity's address.
    struct RotationWorld {
        before: State,
        rotated: State,
        genesis: FinalizedAnchor,
        old: Identity,
        new_phrase: String,
        chain: crate::test_support::canonical_rig::chain::Harness,
        old_coin: OutPoint,
    }

    fn rotation_world(base: &TestDir) -> RotationWorld {
        use mutiny_consensus_v8::hybrid_transaction_v2::Transaction;
        let (mut controller, old, mut chain) = certified_rotation_fixture(base);
        let genesis = chain.genesis().clone();
        controller.unlock(PASSWORD).unwrap();
        controller.create_preimage().unwrap();
        let new_phrase = format!("{}vote", "zoo ".repeat(23));
        let named = RestoredKey::restore(&new_phrase, 2, None)
            .unwrap()
            .descriptor()
            .to_vec();
        let screen = controller
            .begin_rotation(PASSWORD, &new_phrase, &named, 144)
            .unwrap();
        confirm_everything(&mut controller, &screen);
        let queued = authorize(&mut controller).unwrap();
        let raw = controller.export(queued.id).unwrap();
        let before = controller.with_view(|view| view.state().clone()).unwrap();
        let tx = Transaction::decode(&raw).unwrap();
        let id = tx.id().unwrap();
        assert!(matches!(&tx, Transaction::FundedRotation(_)));
        chain.admit(&tx).unwrap();
        chain.step();
        assert_eq!(chain.verified_operations(id).len(), 1);
        drop(controller);
        // A real later payment supplies the historic ADDRESS after the key rotation.
        // No synthetic post-execution coin is inserted into a finalized state.
        let treasury = crate::test_support::canonical_rig::chain::treasury_wallet_key();
        let pay = chain.hand_signed_transfer(
            &treasury,
            chain.treasury_coin(),
            10_000,
            &[
                (
                    hex::decode(&old.address_id).unwrap().try_into().unwrap(),
                    1_000_000,
                ),
                (treasury.public().address_id(1).unwrap(), 990_000),
            ],
        );
        let old_coin = OutPoint {
            transaction: pay.id().unwrap(),
            index: 0,
        };
        chain.admit(&pay).unwrap();
        let rotated = chain.step();
        assert_eq!(rotated.coins[&old_coin].output.atoms, 1_000_000);
        chain = chain.restart();
        assert_eq!(chain.state().root().unwrap(), rotated.root().unwrap());
        RotationWorld {
            before,
            rotated,
            genesis,
            old,
            new_phrase,
            chain,
            old_coin,
        }
    }

    /// What a retirement must leave untouched: every outbox record (bytes, status, reservations), the
    /// outbox's reservations, the preimage conditions and the payment pool's pending payments.
    type Preserved = (
        Vec<mutiny_wallet_core_v8::OutboxRecord>,
        BTreeSet<OutPoint>,
        Vec<Hash>,
        Vec<Vec<u8>>,
    );

    fn preserved(controller: &mut Controller) -> Preserved {
        (
            controller.operations.records().unwrap(),
            controller.operations.reserved().unwrap(),
            controller.preimage_conditions().unwrap(),
            controller.pending_for_transport().unwrap(),
        )
    }

    /// Order W16 through the controller: after the vault replacement the previous identity is kept;
    /// retirement is refused over a verified chain that does not record the rotation (no current key)
    /// and over one that still records the previous key (generation 1), changing nothing; over the
    /// rotated chain the wrong password is refused, then the explicit act deletes the superseded vault
    /// record and NOTHING else (the queued rotation record and its bytes, the reservations, the
    /// preimage, the payment pool). Afterwards the successor still spends a coin at the previous
    /// identity's ADDRESS (the wallet book's lineage rule), and consensus accepts that payment.
    #[test]
    fn retirement_waits_for_the_verified_successor_and_keeps_pending_operations_and_old_funds() {
        use mutiny_consensus_v8::hybrid_transaction_v2::Transaction;
        let base = TestDir::new("w16-retire");
        let world = rotation_world(&base);
        let mut c = controller_on_certified_chain(&base, &world.chain, "pool-r1.sqlite");
        let queued_id = c.operations.records().unwrap()[0].id;
        let own_record = world.chain.verified_operations(queued_id);
        assert_eq!(own_record.len(), 1);
        assert_eq!(
            c.with_view(|view| view.confirmed_height(&queued_id))
                .unwrap(),
            Some(own_record[0].height),
            "read-only discovery carries the same own-replay confirmation as the outbox"
        );
        let new_identity = c.replace_vault(PASSWORD, &world.new_phrase).unwrap();
        let status = c.vault_status().unwrap().unwrap();
        assert_eq!(status.active, new_identity);
        assert_eq!(status.superseded.as_ref(), Some(&world.old));
        assert_eq!(c.preimage_conditions().unwrap().len(), 1);
        assert_eq!(
            c.operations.records().unwrap().len(),
            1,
            "the queued rotation"
        );
        drop(c);
        // Verified chains that do not establish the successor: refused, nothing changes.
        let mut unregistered = world.before.clone();
        // Remove only this wallet's initial authority in this negative TEST model.
        // Unrelated licensed/Treasury authority records remain authentic and valid.
        let authority: Hash = hex::decode(&world.old.authority_id)
            .unwrap()
            .try_into()
            .unwrap();
        let mut records = unregistered.wallets.records().unwrap();
        assert!(
            records
                .remove(&mutiny_consensus_v8::wallet_authority_v1::current_key(
                    authority
                ))
                .is_some()
        );
        assert!(
            records
                .remove(&mutiny_consensus_v8::wallet_authority_v1::address_key(
                    authority
                ))
                .is_some()
        );
        unregistered.wallets =
            mutiny_consensus_v8::wallet_authority_v1::WalletBook::from_records(&records).unwrap();
        assert!(unregistered.wallets.current(authority).is_none());
        assert_eq!(unregistered.wallets.records().unwrap(), records);
        // This independent TEST initial model has no A wallet. Its immutable admission
        // policy must consequently name a retained initial authority, not the removed A.
        // The actual certified R1/successor chain and its policy remain unchanged.
        let retained = unregistered
            .dividends
            .treasury()
            .unwrap()
            .descriptor()
            .to_vec();
        let mut policy = unregistered
            .admission_policy_v2
            .as_ref()
            .unwrap()
            .initial()
            .clone();
        policy.owner_descriptor = retained.clone();
        unregistered.admission_policy_v2 =
            Some(mutiny_consensus_v8::admission_policy_v2::Record::new(policy).unwrap());
        assert_eq!(
            unregistered
                .current_admission_policy_v2(world.genesis.genesis, world.genesis.fingerprint)
                .unwrap()
                .owner_descriptor,
            retained
        );
        let initial_root = unregistered.root().unwrap();
        let initial_records = unregistered
            .records()
            .unwrap()
            .into_iter()
            .collect::<Vec<_>>();
        let reconstructed = State::from_records(&initial_records, initial_root).unwrap();
        assert_eq!(reconstructed.root().unwrap(), initial_root);
        mutiny_consensus_v8::votes_v2::HeightAuthority::from_state(
            &reconstructed,
            world.genesis.clone(),
            initial_root,
        )
        .unwrap();
        for (state, chain, generation) in [
            (&unregistered, "chain-before", None),
            (&world.before, "chain-gen1", Some(1)),
        ] {
            let mut c = controller_over(
                &base,
                state,
                &world.genesis,
                &format!("{chain}.sqlite"),
                &format!("pool-{chain}.sqlite"),
            );
            c.queued_operations().unwrap();
            let kept = preserved(&mut c);
            assert_eq!(
                c.retire_previous_identity(PASSWORD),
                Err(RetirementRefusal::SuccessorNotCanonical {
                    chain_generation: generation
                }),
                "{chain}"
            );
            assert_eq!(
                preserved(&mut c),
                kept,
                "{chain}: a refused retirement changed something"
            );
            assert_eq!(
                c.vault_status().unwrap().unwrap().superseded.as_ref(),
                Some(&world.old),
                "{chain}"
            );
        }
        // The rotated chain: the wrong password is refused; the explicit act retires; only the
        // superseded record goes.
        let mut c = controller_on_certified_chain(&base, &world.chain, "pool-r2.sqlite");
        c.queued_operations().unwrap();
        let kept = preserved(&mut c);
        assert!(matches!(
            c.retire_previous_identity("WRONG PASSWORD"),
            Err(RetirementRefusal::Vault(_))
        ));
        assert_eq!(
            c.vault_status().unwrap().unwrap().superseded.as_ref(),
            Some(&world.old)
        );
        c.retire_previous_identity(PASSWORD).unwrap();
        let status = c.vault_status().unwrap().unwrap();
        assert_eq!(
            (status.active, status.staged, status.superseded),
            (new_identity.clone(), None, None)
        );
        assert_eq!(
            preserved(&mut c),
            kept,
            "the retirement changed more than the vault record"
        );
        assert_eq!(
            c.retire_previous_identity(PASSWORD),
            Err(RetirementRefusal::NothingToRetire)
        );
        // Old-address funds after the retirement: 500,000 atoms need the 1,000,000-atom coin at the
        // previous identity's address (the rotation's change is far smaller); the successor's key
        // signs it, and consensus verifies it against the rotated state's coins and wallet book.
        c.unlock(PASSWORD).unwrap();
        assert_eq!(c.identity(), Some(&new_identity));
        let screen = c.prepare([94; 32], 500_000).unwrap();
        confirm_everything(&mut c, &screen);
        let queued = authorize(&mut c).unwrap();
        assert_eq!(queued.kind, OperationKind::Payment);
        let raw = c
            .pending_for_transport()
            .unwrap()
            .into_iter()
            .find(|raw| Transaction::decode(raw).and_then(|tx| tx.id()).ok() == Some(queued.id))
            .unwrap();
        let tx = Transaction::decode(&raw).unwrap();
        let Transaction::Transfer(transfer) = &tx else {
            panic!("a payment");
        };
        let old_coin = world.old_coin.clone();
        let input = transfer
            .inputs
            .iter()
            .find(|input| input.point == old_coin)
            .expect("the previous identity's address coin is spent");
        assert_eq!(
            hex::encode(&input.descriptor),
            new_identity.owner_descriptor
        );
        tx.verify(
            &mutiny_consensus_v8::hybrid_transaction_v2::Inclusion {
                parent: &world.chain.anchor(),
                history: &mutiny_consensus_v8::evidence_history_v2::History::default(),
            },
            &world.rotated,
        )
        .unwrap();
    }

    /// Review M13b, at the controller: when the vault's kept record is not the active identity's
    /// predecessor (here replaced by another wallet's sealed identity: a damaged or edited vault),
    /// retirement is refused with `NotThePredecessor` over the very chain that DOES establish the
    /// successor, and nothing is deleted or changed.
    #[test]
    fn retirement_refuses_a_kept_identity_that_is_not_the_predecessor() {
        let base = TestDir::new("w16-not-predecessor");
        let world = rotation_world(&base);
        let mut c = controller_on_certified_chain(&base, &world.chain, "pool-r1.sqlite");
        c.replace_vault(PASSWORD, &world.new_phrase).unwrap();
        let stranger = Session::restore_initial(&format!("{}vote", "zoo ".repeat(23))).unwrap();
        let stranger_identity = stranger.identity().clone();
        c.store
            .replace_envelope_for_test(3, &stranger.seal(PASSWORD).unwrap());
        c.queued_operations().unwrap();
        let kept = preserved(&mut c);
        let status = c.vault_status().unwrap().unwrap();
        assert_eq!(status.superseded.as_ref(), Some(&stranger_identity));
        assert_eq!(
            c.retire_previous_identity(PASSWORD),
            Err(RetirementRefusal::NotThePredecessor)
        );
        assert_eq!(
            c.vault_status().unwrap().unwrap(),
            status,
            "nothing was deleted"
        );
        assert_eq!(preserved(&mut c), kept);
    }

    /// Order W16 (structural): the previous identity is retired only by the person's explicit act:
    /// the vault's `retire_previous` has exactly one production caller, `retire_previous_identity`,
    /// which runs the lineage gate first.
    #[test]
    fn only_the_explicit_act_retires_the_previous_identity() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut callers = Vec::new();
        for entry in std::fs::read_dir(&src).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_str().unwrap().to_string();
            if !name.ends_with(".rs") || name.ends_with("_tests.rs") || name == "test_support.rs" {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .unwrap()
                .replace("\r\n", "\n");
            for (number, line) in production_lines(&text) {
                if line.contains(".retire_previous(") {
                    callers.push(format!("{name}:{number}"));
                }
            }
        }
        assert_eq!(callers.len(), 1, "{callers:?}");
        assert!(
            callers[0].starts_with("wallet_controller_v2.rs:"),
            "{callers:?}"
        );
        let source = include_str!("wallet_controller_v2.rs").replace("\r\n", "\n");
        let start = source.find("    pub fn retire_previous_identity(").unwrap();
        let body = &source[start..start + source[start..].find("\n    }\n").unwrap()];
        let gate = body
            .find("retirement_allowed(&status, current.as_deref())?;")
            .unwrap();
        assert!(
            gate < body.find(".retire_previous(").unwrap(),
            "the gate runs first"
        );
    }

    /// A rotation in progress holds two keys: lock, cancel and the idle limit erase both.
    #[test]
    fn locking_erases_both_keys_of_a_rotation_in_progress() {
        let base = TestDir::new("controller-rotation-lock");
        let (mut controller, _, _) = fixture(&base);
        let new_phrase = format!("{}vote", "zoo ".repeat(23));
        let named = crate::wallet_v2::RestoredKey::restore(&new_phrase, 2, None)
            .unwrap()
            .descriptor()
            .to_vec();
        for how in 0..3 {
            controller.unlock(PASSWORD).unwrap();
            controller
                .begin_rotation(PASSWORD, &new_phrase, &named, 144)
                .unwrap();
            assert!(controller.rotation.is_some());
            match how {
                0 => controller.lock(),
                1 => controller.cancel_review(),
                _ => {
                    controller.last_activity = Some(Instant::now() - IDLE_LIMIT);
                    controller.tick();
                }
            }
            assert!(
                controller.rotation.is_none() && controller.plan.is_none(),
                "case {how}"
            );
        }
    }

    /// `C:` followed by `rest`, built at run time (the sources carry no drive-letter path literal:
    /// main.rs's hygiene test).
    fn on_drive(rest: &str) -> String {
        format!("{}:{rest}", 'C')
    }

    /// Order W11: the vault root comes only from exactly `--vault-root <absolute path>`; every other
    /// argument form and every excluded path is refused with its exact typed reason.
    #[test]
    fn the_vault_root_is_explicit_absolute_and_refused_with_a_typed_reason() {
        use std::ffi::OsString;
        let arg = |s: &str| OsString::from(s);
        // The arguments.
        assert_eq!(VaultRoot::from_args(&[]), Err(VaultRootError::Missing));
        assert_eq!(
            VaultRoot::from_args(&[arg("--vault-root")]),
            Err(VaultRootError::MissingValue)
        );
        let good = on_drive("\\Wallets\\Main");
        for args in [
            vec![arg("--other"), arg(&good)],
            vec![arg("--vault-root"), arg(&good), arg("extra")],
            vec![
                arg("--vault-root"),
                arg(&good),
                arg("--vault-root"),
                arg(&good),
            ],
            vec![arg(&format!("--vault-root={good}"))],
            vec![arg("--VAULT-ROOT"), arg(&good)],
            vec![arg(&good)],
        ] {
            assert_eq!(
                VaultRoot::from_args(&args),
                Err(VaultRootError::UnexpectedArguments),
                "{args:?}"
            );
        }
        // The path rules, through `new` (the launcher seam) and through the argument.
        let cases: Vec<(String, VaultRootError)> = vec![
            (String::new(), VaultRootError::Empty),
            ("wallet".into(), VaultRootError::NotAbsolute),
            (".\\wallet".into(), VaultRootError::NotAbsolute),
            ("\\Wallets".into(), VaultRootError::NotAbsolute),
            ("/Wallets".into(), VaultRootError::NotAbsolute),
            (on_drive(""), VaultRootError::NotAbsolute),
            (on_drive("Wallets"), VaultRootError::NotAbsolute),
            (
                "\\\\server\\share\\Wallets".into(),
                VaultRootError::NetworkOrDevicePath,
            ),
            (
                "//server/share/Wallets".into(),
                VaultRootError::NetworkOrDevicePath,
            ),
            (
                "\\\\?\\UNC\\server\\share".into(),
                VaultRootError::NetworkOrDevicePath,
            ),
            (
                format!("\\\\.\\{}", on_drive("\\Wallets")),
                VaultRootError::NetworkOrDevicePath,
            ),
            (
                "\\\\.\\PhysicalDrive0".into(),
                VaultRootError::NetworkOrDevicePath,
            ),
            (
                "\\\\?\\GLOBALROOT\\Device\\HarddiskVolume1\\Wallets".into(),
                VaultRootError::NetworkOrDevicePath,
            ),
            (
                "\\\\?\\Volume{01234567-89ab-cdef-0123-456789abcdef}\\Wallets".into(),
                VaultRootError::NetworkOrDevicePath,
            ),
            (
                on_drive("\\Wallets\\..\\Other"),
                VaultRootError::TraversalComponent,
            ),
            (
                on_drive("\\Wallets\\.\\Main"),
                VaultRootError::TraversalComponent,
            ),
            (
                on_drive("\\Wallets\\\\Main"),
                VaultRootError::TraversalComponent,
            ),
            (on_drive("\\.."), VaultRootError::TraversalComponent),
            (
                on_drive("\\Wallets\\Main:stream"),
                VaultRootError::InvalidCharacter,
            ),
            (
                on_drive("\\Wallets\\Ma*in"),
                VaultRootError::InvalidCharacter,
            ),
            (
                on_drive("\\Wallets\\Ma\"in"),
                VaultRootError::InvalidCharacter,
            ),
            (
                on_drive("\\Wallets\\Ma\0in"),
                VaultRootError::InvalidCharacter,
            ),
            (
                on_drive("\\Wallets\\Ma\nin"),
                VaultRootError::InvalidCharacter,
            ),
            (
                format!("\\\\?\\{}", on_drive("\\Wallets/Main")),
                VaultRootError::InvalidCharacter,
            ),
            (
                on_drive("\\Wallets\\Main."),
                VaultRootError::TrailingDotOrSpace,
            ),
            (
                on_drive("\\Wallets\\Main "),
                VaultRootError::TrailingDotOrSpace,
            ),
            (on_drive("\\Wallets\\NUL"), VaultRootError::ReservedName),
            (on_drive("\\Wallets\\con.txt"), VaultRootError::ReservedName),
            (on_drive("\\COM1\\Wallets"), VaultRootError::ReservedName),
            (
                on_drive("\\Wallets\\lpt\u{b9}"),
                VaultRootError::ReservedName,
            ),
            (on_drive("\\Wallets\\CONOUT$"), VaultRootError::ReservedName),
            (
                on_drive(&format!("\\{}", "a".repeat(MAX_VAULT_ROOT_UNITS))),
                VaultRootError::TooLong,
            ),
        ];
        for (path, expected) in cases {
            assert_eq!(VaultRoot::new(Path::new(&path)), Err(expected), "{path:?}");
            assert_eq!(
                VaultRoot::from_args(&[arg("--vault-root"), arg(&path)]),
                Err(expected),
                "{path:?}"
            );
        }
        // Not Unicode: an unpaired surrogate (a Windows-only construction).
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStringExt;
            let mut wide: Vec<u16> = on_drive("\\Wallets\\").encode_utf16().collect();
            wide.push(0xD800);
            let path = OsString::from_wide(&wide);
            assert_eq!(
                VaultRoot::new(Path::new(&path)),
                Err(VaultRootError::NotUnicode)
            );
        }
        // Accepted: drive paths, forward separators, one trailing separator, the drive root, the
        // verbatim drive form, names that merely contain a reserved word, the exact length limit.
        let accepted = [
            on_drive("\\Wallets\\Main"),
            on_drive("/Wallets/Main"),
            on_drive("\\Wallets\\Main\\"),
            on_drive("\\"),
            format!("\\\\?\\{}", on_drive("\\Wallets\\Main")),
            on_drive("\\Wallets\\CONSOLE\\COM10\\nul-not\\lpt"),
            on_drive(&format!("\\{}", "a".repeat(MAX_VAULT_ROOT_UNITS - 3))),
        ];
        for path in accepted {
            let root = VaultRoot::from_args(&[arg("--vault-root"), arg(&path)])
                .unwrap_or_else(|error| panic!("{path:?}: {error}"));
            assert_eq!(root.path(), Path::new(&path));
            assert_eq!(
                root.vault(),
                Path::new(&path)
                    .join("WalletCustodyV2")
                    .join("wallet-hybrid-v2.sqlite")
            );
        }
        // The real stores sit exactly below an accepted root (a test directory).
        let base = TestDir::new("vault-root");
        let root = VaultRoot::from_args(&[arg("--vault-root"), base.path().into()]).unwrap();
        assert_eq!(root.vault(), custody_file(&base, "wallet-hybrid-v2.sqlite"));
        assert_eq!(
            root.operation_outbox(),
            custody_file(&base, crate::operation_outbox::FILE_NAME)
        );
        assert_eq!(
            root.preimages(),
            custody_file(&base, crate::preimage_store::FILE_NAME)
        );
        assert_eq!(
            VaultRoot::new(&base.path().join("..").join("x")),
            Err(VaultRootError::TraversalComponent)
        );
        // A refusal reads as an instruction.
        let text = VaultRootError::Missing.to_string();
        assert!(
            text.contains("--vault-root <absolute path>") && text.contains("no default"),
            "{text}"
        );
    }

    /// Review F5: what Windows does with device-like names, observed on this host through `std::fs`
    /// (CreateFileW): every name it does NOT store as a plain file of exactly that name is refused by
    /// the vault-root rules. The rules may refuse more (the classic set, for older Windows): "CON
    /// .txt" is refused whatever this host does. "CONSOLE" and "NULL.txt" are positive controls.
    #[cfg(windows)]
    #[test]
    fn reserved_names_cover_every_name_windows_treats_as_a_device() {
        let dir = TestDir::new("w11-device-names");
        let mut observed = Vec::new();
        for name in [
            "CON",
            "con",
            "CON.txt",
            "CON .txt",
            "con  .log",
            "NUL",
            "nul.txt",
            "NUL .x",
            "CONOUT$",
            "CONIN$",
            "CONSOLE",
            "NULL.txt",
        ] {
            let path = dir.path().join(name);
            let created = std::fs::write(&path, b"").is_ok();
            let listed = std::fs::read_dir(dir.path())
                .unwrap()
                .any(|entry| entry.unwrap().file_name() == std::ffi::OsStr::new(name));
            let device = !(created && listed);
            let refused =
                VaultRoot::new(Path::new(&on_drive(&format!("\\Wallets\\{name}")))).is_err();
            observed.push(format!("{name:?}: device={device} refused={refused}"));
            if device {
                assert!(
                    refused,
                    "{name:?} is a device for Windows here but the rules accept it"
                );
            }
            if listed {
                std::fs::remove_file(&path).unwrap();
            }
            if matches!(name, "CONSOLE" | "NULL.txt") {
                assert!(!device && !refused, "{name:?}: positive control");
            }
        }
        println!("W11 device names on this host: {}", observed.join("; "));
        assert_eq!(
            VaultRoot::new(Path::new(&on_drive("\\Wallets\\CON .txt"))),
            Err(VaultRootError::ReservedName)
        );
    }

    const ENV_CHILD: &str = "BUILD8_W11_ENV_CHILD";

    /// The child of the environment test: it runs with every plausible ambient source set by the
    /// parent to OTHER folders, and in a current directory that holds a custody folder.
    #[test]
    fn vault_root_environment_child() {
        if std::env::var_os(ENV_CHILD).is_none() {
            return;
        }
        use std::ffi::OsString;
        let arg = |s: &str| OsString::from(s);
        assert_eq!(VaultRoot::from_args(&[]), Err(VaultRootError::Missing));
        assert_eq!(
            VaultRoot::from_args(&[arg("--vault-root")]),
            Err(VaultRootError::MissingValue)
        );
        // The current directory holds a custody folder: a relative root is still refused.
        assert!(
            std::env::current_dir()
                .unwrap()
                .join("WalletCustodyV2")
                .is_dir()
        );
        for relative in ["WalletCustodyV2", ".", ""] {
            assert!(
                VaultRoot::from_args(&[arg("--vault-root"), arg(relative)]).is_err(),
                "{relative:?}"
            );
        }
        assert_eq!(
            VaultRoot::from_args(&[arg("--vault-root"), arg(".")]),
            Err(VaultRootError::NotAbsolute)
        );
        let explicit = on_drive("\\Explicit\\Vault");
        let root = VaultRoot::from_args(&[arg("--vault-root"), arg(&explicit)]).unwrap();
        assert_eq!(root.path(), Path::new(&explicit));
        assert_eq!(
            root.vault(),
            Path::new(&explicit)
                .join("WalletCustodyV2")
                .join("wallet-hybrid-v2.sqlite")
        );
        println!("W11-ENV-CHILD-PASSED");
    }

    /// Order W11: no environment variable (the names a wallet might plausibly read, and the Windows
    /// profile folders) and no current directory changes what the vault root is: the child runs with
    /// all of them pointing at OTHER folders and still sees exactly the explicit argument.
    #[test]
    fn no_environment_variable_or_current_directory_changes_the_vault_root() {
        let cwd = TestDir::new("w11-env-cwd");
        std::fs::create_dir(cwd.file("WalletCustodyV2")).unwrap();
        let elsewhere = TestDir::new("w11-env-elsewhere");
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "wallet_controller_v2::tests::vault_root_environment_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .current_dir(cwd.path())
            .env(ENV_CHILD, "1");
        for name in [
            "MUTINY_VAULT_ROOT",
            "MUTINY_WALLET_VAULT_ROOT",
            "MUTINY_WALLET_ROOT",
            "BUILD8_VAULT_ROOT",
            "VAULT_ROOT",
            "WALLET_ROOT",
            "LOCALAPPDATA",
            "APPDATA",
            "USERPROFILE",
            "HOME",
            "PROGRAMDATA",
        ] {
            command.env(name, elsewhere.path());
        }
        let output = command.output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            stdout.contains("W11-ENV-CHILD-PASSED"),
            "the child did not run: {stdout}"
        );
        assert!(stdout.contains("1 passed"), "{stdout}");
    }

    /// The lines of `text` outside test-only items: a `#[cfg(test)]` or `#[cfg(all(test, ...))]`
    /// attribute at column 0 removes the item after it (its further attributes and, for an item whose
    /// first line ends in `{`, everything up to the next line that is exactly `}`). Indented test-only
    /// statements stay in (they are scanned too, which is stricter).
    fn production_lines(text: &str) -> Vec<(usize, &str)> {
        let lines: Vec<&str> = text.lines().collect();
        let mut out = Vec::new();
        let mut i = 0;
        while i < lines.len() {
            if lines[i].starts_with("#[cfg(test)]") || lines[i].starts_with("#[cfg(all(test") {
                // The item may start on the attribute's own line (`#[cfg(test)] mod tests{`): then
                // that line is the item's first line, not a line before it.
                let same_line = lines[i]
                    .split_once(")]")
                    .map(|(_, rest)| rest.trim())
                    .filter(|rest| !rest.is_empty() && !rest.starts_with("#["));
                if let Some(rest) = same_line {
                    if rest.ends_with('{') {
                        i += 1;
                        while i < lines.len() && lines[i] != "}" {
                            i += 1;
                        }
                    }
                    i += 1;
                    continue;
                }
                i += 1;
                while i < lines.len() && lines[i].starts_with("#[") {
                    i += 1;
                }
                if i < lines.len() && lines[i].trim_end().ends_with('{') {
                    while i < lines.len() && lines[i] != "}" {
                        i += 1;
                    }
                }
                i += 1;
                continue;
            }
            out.push((i + 1, lines[i]));
            i += 1;
        }
        out
    }

    /// The NON-SHIPPING executable trees of this crate (target B, 2026-10-14). Each holds only
    /// executables that Cargo builds with the TEST window feature, which every shipping build refuses
    /// at compile time (`main.rs`), and no shipping source declares or includes a file in them. Both
    /// tripwires guard code that can reach a shipping artifact, so they skip these trees, but only
    /// after `nonshipping_trees` has proved each condition: a change that would let either tree reach
    /// the shipping root fails here instead of passing silently.
    const NONSHIPPING_TREES: [&str; 2] = ["testvalue/", "rootproducer_native/"];
    fn nonshipping_trees(src: &Path) -> [&'static str; 2] {
        let manifest = std::fs::read_to_string(src.parent().unwrap().join("Cargo.toml"))
            .unwrap()
            .replace("\r\n", "\n");
        let mut gated = [0usize; 2];
        for bin in manifest.split("[[bin]]\n").skip(1) {
            let path = bin
                .lines()
                .find_map(|line| line.strip_prefix("path = \"src/"))
                .map(|rest| rest.trim_end_matches('"'))
                .unwrap();
            match NONSHIPPING_TREES.iter().position(|tree| path.starts_with(tree)) {
                Some(index) => {
                    let required = bin
                        .lines()
                        .find(|line| line.starts_with("required-features = "))
                        .unwrap_or_else(|| panic!("{path}: no required-features"));
                    assert!(required.contains("\"testvalue-window\""), "{path}: {required}");
                    gated[index] += 1;
                }
                None => assert_eq!(path, "main.rs", "an executable outside the known roots: {path}"),
            }
        }
        assert!(gated.iter().all(|count| *count > 0), "{gated:?}");
        let root = std::fs::read_to_string(src.join("main.rs"))
            .unwrap()
            .replace("\r\n", "\n");
        let condensed: String = root.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(condensed.contains("constTEST_VALUE_WINDOW:bool=cfg!(feature=\"testvalue-window\");"));
        assert!(condensed.contains("const_:()=assert!(!TEST_VALUE_WINDOW,"));
        // No production line of a source outside the trees declares or includes a file inside them.
        let mut stack = vec![src.to_path_buf()];
        let mut checked = 0;
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                let name = path
                    .strip_prefix(src)
                    .unwrap()
                    .display()
                    .to_string()
                    .replace('\\', "/");
                if path.is_dir() {
                    if !NONSHIPPING_TREES.contains(&format!("{name}/").as_str()) {
                        stack.push(path);
                    }
                    continue;
                }
                if !name.ends_with(".rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap().replace("\r\n", "\n");
                for (number, line) in production_lines(&text) {
                    if line.contains("#[path") || line.contains("include!(") || line.contains("mod ") {
                        assert!(
                            !NONSHIPPING_TREES
                                .iter()
                                .any(|tree| line.contains(tree) || line.contains(tree.trim_end_matches('/'))),
                            "{name}:{number} reaches a non-shipping tree: {}",
                            line.trim()
                        );
                    }
                }
                checked += 1;
            }
        }
        assert!(checked >= 15, "only {checked} shipping sources checked");
        NONSHIPPING_TREES
    }

    /// Order W10, structural tripwire: no PRODUCTION code of the desktop prints, logs or writes to the
    /// debugger (so no secret can reach a log); test code is skipped as in the W11 tripwire, and so
    /// are the proved non-shipping trees (`nonshipping_trees`).
    #[test]
    fn production_code_neither_prints_nor_logs() {
        const NEEDLES: [&str; 9] = [
            "println!",
            "eprintln!",
            "print!(",
            "eprint!(",
            "dbg!",
            "log::",
            "tracing::",
            "OutputDebugString",
            "std::io::stderr",
        ];
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let nonshipping = nonshipping_trees(&src);
        let mut stack = vec![src.clone()];
        let (mut scanned, mut findings) = (0, Vec::new());
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                let name = path
                    .strip_prefix(&src)
                    .unwrap()
                    .display()
                    .to_string()
                    .replace('\\', "/");
                if !name.ends_with(".rs")
                    || name.ends_with("_tests.rs")
                    || name == "test_support.rs"
                    || nonshipping.iter().any(|tree| name.starts_with(tree))
                {
                    continue;
                }
                let text = std::fs::read_to_string(&path)
                    .unwrap()
                    .replace("\r\n", "\n");
                for (number, line) in production_lines(&text) {
                    if let Some(needle) = NEEDLES.iter().find(|needle| line.contains(*needle)) {
                        findings.push(format!("{name}:{number}: {needle}: {}", line.trim()));
                    }
                }
                scanned += 1;
            }
        }
        assert!(scanned >= 15, "only {scanned} files scanned");
        assert!(
            findings.is_empty(),
            "printing or logging in production code:\n{}",
            findings.join("\n")
        );
    }

    /// The W11 tripwire's patterns: a read of the environment (also at build time), of the process
    /// arguments or command line, of the current directory, of a home, profile or temporary folder,
    /// or of the registry. Since the independent review (F3) they also cover `option_env!`/`env!`,
    /// `temp_dir`, any `std::env` path (so an aliased import such as `use std::env as e;` is found
    /// at its `use`) and the Win32 calls a host could use instead of `std::env`.
    const ENV_NEEDLES: &[&str] = &[
        "env::var",
        "env::args",
        "env::current_dir",
        "current_dir(",
        "home_dir",
        "temp_dir",
        "option_env!",
        "env!(",
        "std::env",
        "GetEnvironmentVariable",
        "ExpandEnvironmentStrings",
        "GetCommandLine",
        "CommandLineToArgv",
        "GetCurrentDirectory",
        "SHGetKnownFolderPath",
        "SHGetFolderPath",
        "RegGetValue",
        "RegQueryValue",
        "RegOpenKey",
        "LOCALAPPDATA",
        "APPDATA",
        "USERPROFILE",
    ];

    /// The W11 findings in one source text, outside its test-only items (`production_lines`): every
    /// pattern of `ENV_NEEDLES`, and a `use` that imports `env` from `std` inside a braced list
    /// (`use std::{fs, env};`). Returns (line number, finding).
    fn environment_reads(text: &str) -> Vec<(usize, String)> {
        let mut out = Vec::new();
        for (number, line) in production_lines(text) {
            let trimmed = line.trim();
            if let Some(needle) = ENV_NEEDLES.iter().find(|needle| line.contains(*needle)) {
                out.push((number, format!("{needle}: {trimmed}")));
            } else if trimmed.starts_with("use ")
                && trimmed.contains("std")
                && trimmed
                    .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                    .any(|word| word == "env")
            {
                out.push((number, format!("an env import: {trimmed}")));
            }
        }
        out
    }

    /// Order W11, structural tripwire: no PRODUCTION code of the desktop reads an environment
    /// variable (at run or build time), the current directory, a home, profile or temporary folder,
    /// the registry, or the process arguments or command line (`ENV_NEEDLES`, and braced `env`
    /// imports). Test code is skipped (`*_tests.rs`, `test_support.rs`, `#[cfg(test)]` items). It is a
    /// textual tripwire: it reads the sources as text, so a read written in a form it does not know
    /// is not found. An executable that hands its arguments to `VaultRoot::from_args` needs an
    /// explicit `ALLOWED` entry (exact file and finding). The proved non-shipping trees
    /// (`nonshipping_trees`) are skipped.
    #[test]
    fn production_code_reads_no_environment_variable_or_current_directory() {
        // Exactly one shipping read: the explicit vault root from the process arguments. No
        // environment variable, default directory or other source site is permitted.
        const ALLOWED: [(&str, &str); 1] = [
            // Target B: the shipping executable hands its arguments to `shipping_app::parse_args`,
            // which accepts nothing or exactly `--vault-root <path>` (`VaultRoot::from_args`).
            (
                "main.rs",
                "env::args: let args: Vec<_> = std::env::args_os().skip(1).collect();",
            ),
        ];
        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    out.push(path);
                }
            }
        }
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let nonshipping = nonshipping_trees(&src);
        let mut files = Vec::new();
        walk(&src, &mut files);
        let mut scanned = 0;
        let mut findings = Vec::new();
        for path in files {
            let name = path
                .strip_prefix(&src)
                .unwrap()
                .display()
                .to_string()
                .replace('\\', "/");
            if name.ends_with("_tests.rs")
                || name == "test_support.rs"
                || nonshipping.iter().any(|tree| name.starts_with(tree))
            {
                continue;
            }
            let text = std::fs::read_to_string(&path)
                .unwrap()
                .replace("\r\n", "\n");
            for (number, finding) in environment_reads(&text) {
                if !ALLOWED
                    .iter()
                    .any(|(file, exact)| *file == name && finding == *exact)
                {
                    findings.push(format!("{name}:{number}: {finding}"));
                }
            }
            scanned += 1;
        }
        assert!(scanned >= 15, "only {scanned} files scanned");
        assert!(
            findings.is_empty(),
            "environment, directory, registry or argument reads in production code:\n{}",
            findings.join("\n")
        );
        // One positive probe per pattern: a production line holding it is found, on its line.
        for needle in ENV_NEEDLES {
            let probe = format!("fn probe() {{\n    let _ = {needle};\n}}\n");
            let found = environment_reads(&probe);
            assert_eq!(found.len(), 1, "{needle}: {found:?}");
            assert_eq!(found[0].0, 2, "{needle}");
        }
        // Aliased and braced imports, including the reviewer's mutant (M8b) forms.
        for import in [
            "use std::env as ambient;",
            "use std::env::{var_os};",
            "use std::{fs, env};",
            "use std::{env as e, fs};",
            "fn m8b() -> Option<&'static str> { option_env!(\"MUTINY_VAULT_ROOT\") }",
            "fn m8c() -> PathBuf { std::env::temp_dir() }",
        ] {
            assert_eq!(
                environment_reads(&format!("{import}\n")).len(),
                1,
                "{import}"
            );
        }
        // Test-only items are skipped; ordinary words are not findings.
        let skipped = "#[cfg(test)]\nmod tests {\n    fn y() { std::env::var(\"X\"); }\n}\n";
        assert!(environment_reads(skipped).is_empty());
        let innocent =
            "use std::{collections::BTreeSet, path::Path};\nfn f() { let environment = 1; }\n";
        assert!(environment_reads(innocent).is_empty());
    }
}

#[path = "wallet_host_v2.rs"]
pub mod host;
