//! (d) Conditional MUT funding: hash lock, claim and refund, and the one cancellation the protocol
//! permits (phase 5A).
//!
//! The three kinds are native trading operations (`trading_v1::NativeOperation`): a body (`Meta`
//! and an `Action`), the wallet approvals of its slots and, for a hash lock, the maker's offer
//! proof. Every rule mirrored here was read from `trading_v1::apply_one` and `prepare_batch`:
//!
//!  * HASH LOCK (`Action::HashLock`): amount above zero, sender and recipient different, a refund
//!    height above the inclusion height H and above the operation's expiry; approval slot 0 is the
//!    sender, slot 1 the recipient; the maker's offer proof must verify (`Operation::verify_offer`,
//!    including the maker's fill signature over this exact body); the sender's coins pay
//!    amount + change + fee exactly; the single-fill offer is consumed; the lock record is output 0
//!    and the change coin output 1.
//!  * CLAIM: the lock exists with the claim's context, TradeID, ContractHash, generation and amount
//!    and was created before H; SHA-256(preimage) is its condition; the recipient is the lock's; H
//!    is below the refund height; slot 0 is the recipient, who pays fee and change from SEPARATE
//!    coins of the recipient address; the whole locked amount is credited at output 0. The preimage
//!    becomes public in the block. No offer proof is allowed.
//!  * REFUND: the same by the lock's sender, at or after the refund height, without a preimage.
//!    Claim and refund both remove the lock record: they are mutually exclusive terminal spends.
//!  * Every input is a coin whose owner IS the paying address (consensus `debit` compares the
//!    address; it does not resolve wallet authority), created before H and mature. `meta.inputs`
//!    are the canonical native input identifiers (`native_input_id` = `utxo_key`), strictly
//!    increasing, and `NativeOperation.inputs` lists the same coins in the same order.
//!  * The fee is at least max(240, encoded length of the COMPLETE signed wire). The wire includes
//!    both approvals and the maker's offer proof, so the fee is computed with zero-signature
//!    placeholders of the exact widths (hybrid signatures are fixed width; the descriptor width of a
//!    missing approval is that of the slot address's current authority in the verified view) and
//!    is checked again whenever an approval or the fill signature arrives.
//!
//! THE UNSIGNED FORM. Both wallet approvals and the maker's fill signature sign the BODY, never
//! each other. A plan therefore holds, and every review binds, the operation with no approvals and
//! an all-zero fill signature. The maker's signed OFFER stays in it: it is imported data that the
//! review shows and verifies; maker offer creation is a separate above-consensus handler. Signing adds
//! only this wallet's approvals, so the signed result of one party is a PARTIAL operation unless
//! that party signs every slot (a claim or a refund). [`complete`] merges the approvals of several
//! partial encodings of one operation and the maker's fill signature, and imports the result
//! through `SignedOperation::import`, which verifies it through consensus code. It signs nothing.
//!
//! IDENTIFIERS. A complete operation is identified by its consensus operation id
//! (`Operation::id`, the key of its `Applied` receipt record). A partial one is identified by a
//! domain-separated hash of its exact bytes, so that one outbox can hold a partial and, after the
//! host forgets the partial, the completed operation (an outbox never accepts other bytes under an
//! existing identifier).
//!
//! RESERVATIONS. `describe` reserves the input coins and one resource: the offer for a hash lock
//! (`resource_key(OFFER_NAMESPACE, offer id)`) and the lock for a claim or a refund
//! (`resource_key(LOCK_NAMESPACE, lock id)`, the same key for both, so a claim and a refund of one
//! lock can never be planned at once).
//!
//! VERIFICATION. Pre-signing checks mirror `apply_one` against the CURRENT view (`examine`). After
//! signing, each approval present is verified with `trading_v1::verify_approval` and a complete
//! operation additionally with `trading_v1::prepare_batch` (policy
//! `CandidatePolicy::native_denomination_locked`) against the verified parent state.
//!
//! PREIMAGES (Q13). A preimage is a fresh operating-system random value ([`Preimage::generate`])
//! kept in its own record ([`PreimageStore`]); it is never derived from a wallet key. This module
//! has no Bitcoin type: the external leg of a swap is out of scope and is never verified here.
//!
//! FINALITY. A hash lock is the "native reservation" that must precede any external value
//! movement. It is final only when a certified block that includes it is in the verified chain
//! (`reconcile` and `discovery::locks::finality` require this host's own replay-derived inclusion
//! index). A queued record is local only. Authenticated submission and peer acknowledgement are
//! not confirmation, and inclusion in a proposed block is not finality.
use super::{payment, select};
use crate::{
    authorize::{SignedOperation, SignerIdentity},
    capability::KindSigner,
    context::{ChainView, is_treasury_address, require_reserve_backing, treasury_authority},
    outbox::{OutboxRecord, Settlement, resource_key},
    plan::{
        CancelTarget, ClaimRequest, Description, HashLockRequest, OperationHandler, OperationKind,
        OperationPlan, OperationRequest, PlanObject, RefundRequest, RequiredSigner, Requirement,
        RequirementStatus, Slot, Validity,
    },
    refusal::Refusal,
    review::{
        AckKind, AddressLabel, Condition, Destination, DestinationRole, Effect, Fee, FeePayer,
        FeeRule, InputLine, Party, PartyRole, ReviewDraft, Severity, Timing, Warning,
    },
    secret::Preimage,
    units,
};
use minicbor::Decoder;
use mutiny_consensus_v8::{
    Hash, domain_hash,
    native_units_v1::MINIMUM_TRADE_FEE_STRIKES,
    trading_v1::{
        self, Action, Approval as TradeApproval, CandidatePolicy, Context as TradeContext,
        MAX_NATIVE_BYTES, Meta, NativeError, NativeLock, NativeLockKind, NativeOperation,
        OfferBody, OfferProof, OfferTerms, Operation, SignedOffer, Strikes, native_input_id,
        record_key,
    },
    transactions::{Coin, EXPIRY_HORIZON, MATURITY, OutPoint, Output},
    wallet_authority_v1::address_key,
};
use mutiny_crypto_v2::PublicKey;
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

/// Layout version of the conditional plan objects.
pub const SCHEMA: u16 = 1;
/// Label of the one object of a conditional plan (the unsigned native trading operation).
pub const OBJECT_LABEL: &str = "native-trade";
/// `resource_key` namespace of a maker's offer consumed by a hash lock.
pub const OFFER_NAMESPACE: &str = "trade-offer";
/// `resource_key` namespace of a hash lock spent by a claim or a refund.
pub const LOCK_NAMESPACE: &str = "hash-lock";
/// The trading fee floor in STRIKES (`native_units_v1::MINIMUM_TRADE_FEE_STRIKES`).
pub const TRADE_FEE_FLOOR: u64 = MINIMUM_TRADE_FEE_STRIKES;
/// Most inputs of one trading operation (`trading_v1::MAX_INPUTS`).
pub const MAX_TRADE_INPUTS: usize = trading_v1::MAX_INPUTS;
/// Domain of the identifier of a PARTIAL operation (a hash of its exact bytes).
const PARTIAL_ID_DOMAIN: &[u8] = b"MUTINY-BUILD8-WALLET-CONDITIONAL-PARTIAL-ID-V1";
/// A claim window this short gets a caution.
const SHORT_WINDOW_BLOCKS: u64 = 10;
/// An operation this close to expiry gets a caution.
const EXPIRES_SOON_BLOCKS: u64 = 3;

const REFUND_NOT_ABOVE: &str = "the refund height must be above the block that includes the lock";
const EXPIRY_NOT_BELOW_REFUND: &str = "the lock operation must expire before its refund height";
/// `INVALID_REQUEST` reason (fixes of the independent wallet review, MAJOR-1): consensus accepts a
/// claim only in a block ABOVE the lock's and BELOW the refund height, so a lock that may still be
/// included in the block just below the refund height can leave its recipient no claim block at
/// all. Derived, not tuned: the worst case must leave at least one block.
pub const REASON_NO_CLAIM_WINDOW: &str = "the lock could be included so late that its recipient would have no block left to claim in: it must expire at least two blocks before its refund height";
const AMOUNT_NOT_OFFERED: &str = "the amount must equal the amount of the maker's offer";
const NOT_PAYER_COIN: &str = "an input is not a coin of the paying address";
const LOCK_MISMATCH: &str = "the operation does not match the lock it spends";
const FIAT_NOT_CLAIMABLE: &str =
    "a fiat lock has no hash condition: it is released by both parties, never claimed";
const REFUND_OWNER: &str = "the refund owner is not the lock's sender";
const NO_PREIMAGE: &str = "this wallet holds no preimage for the lock's condition";
const GENERATION_ZERO: &str = "the trade generation must be at least 1";
const PARTS_DIFFER: &str = "the parts are not encodings of one and the same operation";

const FINALITY: &str = "final only when a certified block that includes it is part of this wallet's verified chain and this host's own replay-derived index confirms its inclusion. A queued record is stored locally only; authenticated submission or peer acknowledgement is not confirmation. Inclusion in a proposed, uncertified block is not finality either.";

// ---------------------------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------------------------

pub(crate) struct ConditionalHandler {
    kind: OperationKind,
}

static HASH_LOCK: ConditionalHandler = ConditionalHandler {
    kind: OperationKind::HashLock,
};
static CLAIM: ConditionalHandler = ConditionalHandler {
    kind: OperationKind::ConditionalClaim,
};
static REFUND: ConditionalHandler = ConditionalHandler {
    kind: OperationKind::ConditionalRefund,
};

/// The handler for `kind`: hash lock, claim and refund are implemented here.
pub(crate) fn handler(kind: OperationKind) -> Option<&'static dyn OperationHandler> {
    match kind {
        OperationKind::HashLock => Some(&HASH_LOCK),
        OperationKind::ConditionalClaim => Some(&CLAIM),
        OperationKind::ConditionalRefund => Some(&REFUND),
        _ => None,
    }
}

fn own(kind: OperationKind) -> &'static ConditionalHandler {
    match kind {
        OperationKind::HashLock => &HASH_LOCK,
        OperationKind::ConditionalClaim => &CLAIM,
        _ => &REFUND,
    }
}

// ---------------------------------------------------------------------------------------------
// Preimages
// ---------------------------------------------------------------------------------------------

/// Where hash-lock preimages are kept (Q13): each is a fresh operating-system random value in its
/// own record, keyed by its public condition (SHA-256). Never derived from a wallet key or phrase.
/// The desktop provides an encrypted implementation; [`MemoryPreimageStore`] is the reference.
pub trait PreimageStore {
    /// Generate a fresh preimage from operating-system randomness, keep it and return its
    /// condition (the value to hand to the party that locks funds for this wallet).
    fn create(&mut self) -> Result<Hash, Refusal>;
    /// Keep a preimage obtained elsewhere (for example disclosed by a counterparty). Returns its
    /// condition.
    fn insert(&mut self, preimage: Preimage) -> Result<Hash, Refusal>;
    /// The preimage for `condition`, if this store holds it.
    fn preimage(&self, condition: &Hash) -> Result<Option<Preimage>, Refusal>;
    /// Erase the preimage for `condition`; whether one was held.
    fn erase(&mut self, condition: &Hash) -> Result<bool, Refusal>;
    /// Every condition this store holds a preimage for, ascending.
    fn conditions(&self) -> Result<Vec<Hash>, Refusal>;
}

/// In-memory [`PreimageStore`]: nothing survives the process; every preimage is erased on drop.
#[derive(Default)]
pub struct MemoryPreimageStore {
    entries: BTreeMap<Hash, Preimage>,
}

impl MemoryPreimageStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl PreimageStore for MemoryPreimageStore {
    fn create(&mut self) -> Result<Hash, Refusal> {
        self.insert(Preimage::generate()?)
    }
    fn insert(&mut self, preimage: Preimage) -> Result<Hash, Refusal> {
        let condition = preimage.condition();
        self.entries.entry(condition).or_insert(preimage);
        Ok(condition)
    }
    fn preimage(&self, condition: &Hash) -> Result<Option<Preimage>, Refusal> {
        Ok(self
            .entries
            .get(condition)
            .map(|preimage| Preimage::from_bytes(*preimage.expose())))
    }
    fn erase(&mut self, condition: &Hash) -> Result<bool, Refusal> {
        Ok(self.entries.remove(condition).is_some())
    }
    fn conditions(&self) -> Result<Vec<Hash>, Refusal> {
        Ok(self.entries.keys().copied().collect())
    }
}

impl fmt::Debug for MemoryPreimageStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryPreimageStore")
            .field("preimages", &self.entries.len())
            .finish()
    }
}

/// The claim request for `lock`, with the preimage this wallet's store holds for the lock's
/// condition (read from the verified state). The claim review still says the preimage was
/// supplied externally: this wallet does not know what the other leg of the trade did.
pub fn claim_request(
    store: &dyn PreimageStore,
    lock: Hash,
    view: &ChainView<'_>,
) -> Result<ClaimRequest, Refusal> {
    let found = trading_v1::locked(view.state(), lock).map_err(|_| Refusal::LockNotFound)?;
    let NativeLockKind::Hash { condition, .. } = found.kind else {
        return Err(Refusal::InvalidRequest(FIAT_NOT_CLAIMABLE));
    };
    let preimage = store
        .preimage(&condition)?
        .ok_or(Refusal::InvalidRequest(NO_PREIMAGE))?;
    Ok(ClaimRequest::new(lock, preimage))
}

// ---------------------------------------------------------------------------------------------
// Offers (imported and verified, never created: Q7)
// ---------------------------------------------------------------------------------------------

/// A maker's signed hash-linked offer after import and verification. The two external terms are
/// integer data copied from the signed offer; this wallet does not interpret or verify the
/// external leg they describe.
#[derive(Clone, PartialEq, Eq)]
pub struct HashLinkedOffer {
    /// `OfferBody::id`.
    pub id: Hash,
    /// The maker's descriptor commitment (`OfferBody::maker`), separate from its settlement address.
    pub maker: Hash,
    pub nonce: Hash,
    /// First height at which the offer can be filled.
    pub created: u64,
    /// Last height at which the offer can be filled.
    pub expiry: u64,
    /// 0: the maker is the sender (it funds the lock); 1: the maker is the recipient.
    pub maker_side: u8,
    /// Atoms (STRIKES) the lock must hold.
    pub amount: u64,
    /// External consideration, integer data from the offer.
    pub bitcoin_satoshis: u64,
    /// External network code from the offer (0 mainnet, 1 testnet, 2 signet, 3 regtest).
    pub bitcoin_network: u8,
}

impl fmt::Debug for HashLinkedOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HashLinkedOffer")
            .field("id", &units::short_hex(&self.id))
            .field("maker", &units::short_hex(&self.maker))
            .field("window", &(self.created, self.expiry))
            .field("maker_side", &self.maker_side)
            .field("amount", &self.amount)
            .finish()
    }
}

/// Import a maker's hash-linked offer through `offers::import_offer` (the one import rule of every
/// handler since W19): the canonical offer container, or the consensus `OfferProof` encoding of the
/// signed offer with an all-zero fill signature. Bytes in neither form (another encoding, a fill
/// signature already present) are `MALFORMED`, another chain is `WRONG_CONTEXT`, an offer signature
/// that does not verify is `OFFER_PROOF_INVALID`, and an offer of another kind of terms is
/// `INVALID_REQUEST` (before W19 every one of these but the chain was `OFFER_PROOF_INVALID` here).
pub fn import_offer(raw: &[u8], view: &ChainView<'_>) -> Result<HashLinkedOffer, Refusal> {
    summarize_offer(&read_offer(raw, view)?.body)
}

fn read_offer(raw: &[u8], view: &ChainView<'_>) -> Result<SignedOffer, Refusal> {
    let offer = crate::offers::import_offer(raw, view)?;
    if !matches!(offer.terms(), OfferTerms::HashLinked { .. }) {
        return Err(Refusal::InvalidRequest(crate::offers::REASON_OFFER_KIND));
    }
    Ok(offer.signed_offer().clone())
}

fn summarize_offer(body: &OfferBody) -> Result<HashLinkedOffer, Refusal> {
    let OfferTerms::HashLinked {
        amount,
        bitcoin_satoshis,
        bitcoin_network,
    } = &body.terms
    else {
        return Err(Refusal::InvalidRequest(crate::offers::REASON_OFFER_KIND));
    };
    Ok(HashLinkedOffer {
        id: body
            .id()
            .map_err(|_| Refusal::Malformed("offer identifier"))?,
        maker: body
            .maker()
            .map_err(|_| Refusal::Malformed("maker identity"))?,
        nonce: body.nonce,
        created: body.created,
        expiry: body.expiry,
        maker_side: body.maker_side,
        amount: amount.0,
        bitcoin_satoshis: *bitcoin_satoshis,
        bitcoin_network: *bitcoin_network,
    })
}

fn offer_consumed(view: &ChainView<'_>, context: &TradeContext, offer: &Hash) -> bool {
    crate::offers::consumed(view.state(), context, *offer)
}

// ---------------------------------------------------------------------------------------------
// Codec helpers
// ---------------------------------------------------------------------------------------------

/// Strict canonical decoding of a native trading operation.
pub(crate) fn decode(raw: &[u8]) -> Result<NativeOperation, Refusal> {
    NativeOperation::decode(raw)
        .map_err(|_| Refusal::Malformed("not a canonical native trading operation"))
}

fn encode(wire: &NativeOperation) -> Result<Vec<u8>, Refusal> {
    wire.encode().map_err(|error| match error {
        NativeError::Bounds | NativeError::Candidate(trading_v1::Error::Bounds) => {
            Refusal::SizeLimit {
                limit: MAX_NATIVE_BYTES,
            }
        }
        NativeError::Context => {
            Refusal::Malformed("the input list does not match the signed input identifiers")
        }
        _ => Refusal::Malformed("the native trading operation does not encode"),
    })
}

fn kind_of(action: &Action) -> Option<OperationKind> {
    match action {
        Action::HashLock { .. } => Some(OperationKind::HashLock),
        Action::Claim { .. } => Some(OperationKind::ConditionalClaim),
        Action::Refund { .. } => Some(OperationKind::ConditionalRefund),
        _ => None,
    }
}

fn operation_id(op: &Operation) -> Result<Hash, Refusal> {
    op.id()
        .map_err(|_| Refusal::Malformed("operation identity"))
}

/// The unsigned form: no approval, an all-zero fill signature. The maker's signed offer stays.
fn stripped(wire: &NativeOperation) -> NativeOperation {
    let mut copy = wire.clone();
    copy.operation.approvals.clear();
    if let Some(proof) = &mut copy.operation.offer_proof {
        proof.fill_signature = payment::zero_signature();
    }
    copy
}

fn fill_present(op: &Operation) -> bool {
    op.offer_proof
        .as_ref()
        .is_some_and(|proof| !payment::is_unsigned(&proof.fill_signature))
}

fn minimum_fee(size: u64) -> u64 {
    size.max(MINIMUM_TRADE_FEE_STRIKES)
}

fn set_fee_and_change(op: &mut Operation, fee: u64, change: u64) {
    op.meta.fee = Strikes(fee);
    if let Action::HashLock { change: field, .. }
    | Action::Claim { change: field, .. }
    | Action::Refund { change: field, .. } = &mut op.action
    {
        *field = Strikes(change);
    }
}

/// The resource a conditional operation consumes besides its coins.
fn resource_of(op: &Operation) -> Option<OutPoint> {
    match &op.action {
        Action::HashLock { offer, .. } => Some(resource_key(OFFER_NAMESPACE, offer)),
        Action::Claim { output, .. } | Action::Refund { output, .. } => {
            Some(resource_key(LOCK_NAMESPACE, output))
        }
        _ => None,
    }
}

/// The generation of the descriptor that currently authorizes `address` in the view: the current
/// descriptor of its wallet authority, or 1 for an address no rotation ever touched (consensus
/// then accepts only the generation-one key that derives it).
fn signing_generation(view: &ChainView<'_>, address: &Hash) -> u64 {
    let wallets = &view.state().wallets;
    let generation_of = |raw: &[u8]| PublicKey::decode_descriptor(raw).ok().map(|(_, g)| g);
    if let Some(generation) = wallets.current(*address).and_then(generation_of) {
        return generation;
    }
    // A later-generation address of a rotated authority: its address record names the authority.
    if let Ok(records) = wallets.records()
        && let Some(raw) = records.get(&address_key(*address))
        && let Some(authority) = record_authority(raw)
        && let Some(generation) = wallets.current(authority).and_then(generation_of)
    {
        return generation;
    }
    1
}

/// The authority named by a wallet-book address record `[1, 31, authority, descriptor]`.
fn record_authority(raw: &[u8]) -> Option<Hash> {
    let mut d = Decoder::new(raw);
    if d.array().ok()? != Some(4) || d.u8().ok()? != 1 || d.u8().ok()? != 31 {
        return None;
    }
    d.bytes().ok()?.try_into().ok()
}

/// A public key to build placeholder descriptors with: this wallet's, or the first approval's.
fn filler_key(op: &Operation, me: Option<&SignerIdentity>) -> Result<PublicKey, Refusal> {
    if let Some(me) = me {
        return Ok(me.public());
    }
    op.approvals
        .first()
        .and_then(|approval| PublicKey::decode_descriptor(&approval.descriptor).ok())
        .map(|(public, _)| public)
        .ok_or(Refusal::Malformed(
            "nothing is signed and no signer is named",
        ))
}

/// Encoded length of the COMPLETE operation: every expected approval present (missing ones as
/// zero-signature placeholders whose descriptor has the width of the slot's current authority)
/// and the maker's fill signature present (it has a fixed width, zero or not).
fn complete_len(
    wire: &NativeOperation,
    view: &ChainView<'_>,
    filler: &PublicKey,
) -> Result<u64, Refusal> {
    let mut full = wire.clone();
    let op = &mut full.operation;
    let expected = op.expected_slots();
    op.approvals
        .retain(|approval| expected.contains(&approval.slot));
    for slot in expected {
        if op.approvals.iter().any(|approval| approval.slot == slot) {
            continue;
        }
        let address = op
            .slot_address(slot)
            .ok_or(Refusal::Malformed("an approval slot without an address"))?;
        let descriptor = filler
            .descriptor(signing_generation(view, &address))
            .map_err(|_| Refusal::InvalidDescriptor)?;
        op.approvals.push(TradeApproval {
            slot,
            descriptor,
            signature: payment::zero_signature(),
        });
    }
    op.approvals.sort_by_key(|approval| approval.slot);
    Ok(encode(&full)?.len() as u64)
}

fn partial_id(raw: &[u8]) -> Hash {
    domain_hash(PARTIAL_ID_DOMAIN, raw)
}

/// The WORST-CASE claim window of a hash lock, in blocks: consensus accepts the claim only in a
/// block above the lock's (`bound_lock`: created before the claim's height) and below the refund
/// height (`trading_v1`, the claim's time rule), and the lock may be included as late as its own
/// `expiry`, so the recipient is sure of the blocks `expiry + 1` to `refund_height - 1` only.
pub fn worst_case_claim_window(expiry: u64, refund_height: u64) -> u64 {
    refund_height.saturating_sub(expiry).saturating_sub(1)
}

/// Whether a worst-case claim window is SHORT (policy, flagged for the Architect): below
/// `SHORT_WINDOW_BLOCKS`, or shorter than the span of blocks the lock itself may be included in
/// (`expiry - created + 1`), so that the timing of the inclusion alone can take more than half of
/// the window the recipient would have had if the lock were included at once.
fn short_claim_window(window: u64, created: u64, expiry: u64) -> bool {
    let inclusion_span = expiry.saturating_sub(created).saturating_add(1);
    window < SHORT_WINDOW_BLOCKS || window < inclusion_span
}

// ---------------------------------------------------------------------------------------------
// Coin selection and the fee fixed point
// ---------------------------------------------------------------------------------------------

/// Coins that may fund a trading operation paid by `payer`: owned by exactly that address, not
/// reserved, not newer than the head, mature if coinbase. At most `MAX_TRADE_INPUTS` are kept,
/// largest first with a stable tie-break by outpoint; the count and total cover all of them.
struct Funding {
    coins: Vec<(OutPoint, u64)>,
    count: usize,
    total: u128,
}

fn eligible(view: &ChainView<'_>, point: &OutPoint, coin: &Coin, next: u64) -> bool {
    !view.reserved().contains(point)
        && coin.created_height <= view.anchor().height
        && !(coin.coinbase && next - coin.created_height < MATURITY)
}

fn funding_coins(
    view: &ChainView<'_>,
    payer: &Hash,
    descriptor: &[u8],
) -> Result<Funding, Refusal> {
    view.state()
        .wallets
        .authorize(*payer, descriptor)
        .map_err(|_| Refusal::StaleAuthority)?;
    let next = view.next_height()?;
    let mut coins: Vec<(OutPoint, u64)> = Vec::with_capacity(MAX_TRADE_INPUTS);
    let mut count = 0usize;
    let mut total: u128 = 0;
    for (point, coin) in &view.state().coins {
        if view
            .state()
            .wallets
            .authorize(coin.output.owner, descriptor)
            .is_err()
            || !eligible(view, point, coin, next)
        {
            continue;
        }
        count += 1;
        total += u128::from(coin.output.atoms);
        let at = coins
            .binary_search_by(|(selected, atoms)| {
                coin.output
                    .atoms
                    .cmp(atoms)
                    .then_with(|| selected.cmp(point))
            })
            .unwrap_or_else(|at| at);
        if at < MAX_TRADE_INPUTS {
            if coins.len() == MAX_TRADE_INPUTS {
                coins.pop();
            }
            coins.insert(at, (point.clone(), coin.output.atoms));
        }
    }
    Ok(Funding {
        coins,
        count,
        total,
    })
}

enum Fit {
    Done,
    /// These inputs cannot pay; `fee` is the least fee this shape needs.
    Short {
        fee: u64,
    },
}

/// Choose the fee and the change for the current inputs (`total` atoms): the fee is a fixed point
/// of `max(240, complete size)`, only ever rising to the largest size seen.
fn fit_fee(
    wire: &mut NativeOperation,
    total: u64,
    principal: u64,
    view: &ChainView<'_>,
    filler: &PublicKey,
) -> Result<Fit, Refusal> {
    let available = total.checked_sub(principal);
    let mut fee = 0u64;
    for _ in 0..16 {
        let change = available.and_then(|available| available.checked_sub(fee));
        set_fee_and_change(&mut wire.operation, fee, change.unwrap_or(0));
        let minimum = minimum_fee(complete_len(wire, view, filler)?);
        if fee >= minimum && change.is_some() {
            return Ok(Fit::Done);
        }
        if available.is_none_or(|available| available < minimum) {
            return Ok(Fit::Short { fee: minimum });
        }
        fee = minimum;
    }
    Err(Refusal::Malformed("the fee did not converge"))
}

/// Fill in inputs, fee and change for `template` paid by `payer`: the fewest largest coins of that
/// address whose total covers `principal` + fee, ordered by native input identifier.
fn fund(
    mut wire: NativeOperation,
    principal: u64,
    view: &ChainView<'_>,
    filler: &PublicKey,
) -> Result<NativeOperation, Refusal> {
    // Consensus debits the coins of `Operation::fee_payer()` (the phase-0A accessor).
    let payer = wire.operation.fee_payer();
    let funding = funding_coins(
        view,
        &payer,
        &filler
            .descriptor(signing_generation(view, &payer))
            .map_err(|_| Refusal::InvalidDescriptor)?,
    )?;
    if funding.coins.is_empty() {
        return Err(Refusal::NothingSpendable);
    }
    let mut needed: Option<u64> = None;
    let mut total = 0u64;
    for count in 1..=funding.coins.len() {
        total = total
            .checked_add(funding.coins[count - 1].1)
            .ok_or(Refusal::Overflow)?;
        let last = count == funding.coins.len();
        if total < principal.saturating_add(MINIMUM_TRADE_FEE_STRIKES) && !last {
            continue;
        }
        let mut chosen: Vec<OutPoint> = funding.coins[..count]
            .iter()
            .map(|(point, _)| point.clone())
            .collect();
        chosen.sort_by_key(native_input_id);
        wire.operation.meta.inputs = chosen.iter().map(native_input_id).collect();
        wire.inputs = chosen;
        match fit_fee(&mut wire, total, principal, view, filler)? {
            Fit::Done => return Ok(wire),
            Fit::Short { fee } => needed = Some(fee),
        }
    }
    if funding.count > funding.coins.len() {
        return Err(Refusal::TooManyInputs {
            limit: MAX_TRADE_INPUTS,
        });
    }
    let fee = needed.unwrap_or(MINIMUM_TRADE_FEE_STRIKES);
    Err(Refusal::InsufficientFunds {
        available: u64::try_from(funding.total).unwrap_or(u64::MAX),
        requested: principal.saturating_add(fee),
    })
}

// ---------------------------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------------------------

fn check_validity_blocks(blocks: u64) -> Result<(), Refusal> {
    if blocks == 0 || blocks > EXPIRY_HORIZON {
        return Err(Refusal::InvalidValidity);
    }
    Ok(())
}

fn trade_context(view: &ChainView<'_>) -> TradeContext {
    let context = view.context();
    TradeContext {
        network: context.network,
        genesis: context.genesis,
        fingerprint: context.fingerprint,
    }
}

/// The addresses that may fund a hash lock, in the order they are tried: the requested one only,
/// or every address of this wallet holding an eligible coin, the current-generation address
/// first, then by eligible value, then by address.
fn sender_candidates(
    request: &HashLockRequest,
    view: &ChainView<'_>,
    signer: &SignerIdentity,
) -> Result<Vec<Hash>, Refusal> {
    let wallets = &view.state().wallets;
    if let Some(sender) = request.sender {
        wallets
            .authorize(sender, signer.descriptor())
            .map_err(|_| Refusal::NotRequiredSigner(Slot::Approval(0)))?;
        return Ok(vec![sender]);
    }
    let next = view.next_height()?;
    let mut controlled: BTreeMap<Hash, bool> = BTreeMap::new();
    let mut totals: BTreeMap<Hash, u128> = BTreeMap::new();
    for (point, coin) in &view.state().coins {
        if !eligible(view, point, coin, next) {
            continue;
        }
        let owner = coin.output.owner;
        let mine = *controlled
            .entry(owner)
            .or_insert_with(|| wallets.authorize(owner, signer.descriptor()).is_ok());
        if mine {
            *totals.entry(owner).or_insert(0) += u128::from(coin.output.atoms);
        }
    }
    let current = signer.address();
    let mut order: Vec<(Hash, u128)> = totals.into_iter().collect();
    order.sort_by(|a, b| {
        (b.0 == current)
            .cmp(&(a.0 == current))
            .then(b.1.cmp(&a.1))
            .then(a.0.cmp(&b.0))
    });
    Ok(order.into_iter().map(|(address, _)| address).collect())
}

fn plan_hash_lock(
    request: &HashLockRequest,
    view: &ChainView<'_>,
    signer: &SignerIdentity,
) -> Result<OperationPlan, Refusal> {
    if request.amount_atoms == 0 {
        return Err(Refusal::InvalidAmount);
    }
    if request.recipient == [0; 32] {
        return Err(Refusal::InvalidRecipient);
    }
    check_validity_blocks(request.validity_blocks)?;
    if request.generation == 0 {
        return Err(Refusal::InvalidRequest(GENERATION_ZERO));
    }
    signer.check_current(view)?;
    select::require_profile_for_treasury(view, signer)?;
    let next = view.next_height()?;
    let signed_offer = read_offer(request.offer.as_slice(), view)?;
    let offer = summarize_offer(&signed_offer.body)?;
    if offer.amount != request.amount_atoms {
        return Err(Refusal::InvalidRequest(AMOUNT_NOT_OFFERED));
    }
    crate::offers::require_fillable(&signed_offer, view)?;
    let context = trade_context(view);
    if view
        .reserved()
        .contains(&resource_key(OFFER_NAMESPACE, &offer.id))
    {
        return Err(Refusal::ReservedInput);
    }
    if request.refund_height <= next {
        return Err(Refusal::InvalidRequest(REFUND_NOT_ABOVE));
    }
    // Even included at once (the next block), a lock needs one block between it and the refund
    // height for its recipient to claim in.
    if worst_case_claim_window(next, request.refund_height) == 0 {
        return Err(Refusal::InvalidRequest(REASON_NO_CLAIM_WINDOW));
    }
    // The window only ever shrinks: within the offer's, and ending early enough that a lock
    // included in its last block still leaves its recipient at least one claim block (at least two
    // blocks before the refund height; the review states the worst case).
    let expiry = next
        .checked_add(request.validity_blocks)
        .ok_or(Refusal::Overflow)?
        .min(request.refund_height.saturating_sub(2))
        .min(offer.expiry);
    let filler = signer.public();
    let mut first_refusal = None;
    for sender in sender_candidates(request, view, signer)? {
        if sender == request.recipient {
            first_refusal.get_or_insert(Refusal::InvalidRecipient);
            continue;
        }
        let template = NativeOperation {
            operation: Operation {
                meta: Meta {
                    context: context.clone(),
                    trade: request.trade,
                    contract: request.contract,
                    generation: request.generation,
                    envelope: crate::offers::envelope(view, next, expiry, Vec::new())?,
                    fee: Strikes(0),
                    inputs: Vec::new(),
                },
                action: Action::HashLock {
                    offer: offer.id,
                    maker: offer.maker,
                    sender,
                    recipient: request.recipient,
                    amount: Strikes(request.amount_atoms),
                    condition: request.condition,
                    refund_height: request.refund_height,
                    change: Strikes(0),
                },
                approvals: Vec::new(),
                offer_proof: Some(OfferProof {
                    offer: signed_offer.clone(),
                    fill_signature: payment::zero_signature(),
                }),
            },
            inputs: Vec::new(),
        };
        match fund(template, request.amount_atoms, view, &filler) {
            Ok(wire) => return assemble(OperationKind::HashLock, &wire, view, signer),
            Err(refusal) => {
                first_refusal.get_or_insert(refusal);
            }
        }
    }
    Err(first_refusal.unwrap_or(Refusal::NothingSpendable))
}

/// The open hash lock `id` of the verified state, for a claim or refund by this wallet.
fn open_lock(view: &ChainView<'_>, id: &Hash) -> Result<(NativeLock, Hash, u64), Refusal> {
    let lock = trading_v1::locked(view.state(), *id).map_err(|_| Refusal::LockNotFound)?;
    view.require_context(
        lock.context.network,
        &lock.context.genesis,
        &lock.context.fingerprint,
    )?;
    let (condition, refund_height) = match lock.kind {
        NativeLockKind::Hash {
            condition,
            refund_height,
        } => (condition, refund_height),
        NativeLockKind::Fiat { .. } => (Hash::default(), 0),
    };
    Ok((lock, condition, refund_height))
}

fn spend_template(
    view: &ChainView<'_>,
    lock: &NativeLock,
    created: u64,
    expiry: u64,
    action: Action,
) -> Result<NativeOperation, Refusal> {
    Ok(NativeOperation {
        operation: Operation {
            meta: Meta {
                context: lock.context.clone(),
                trade: lock.trade,
                contract: lock.contract,
                generation: lock.generation,
                envelope: crate::offers::envelope(view, created, expiry, Vec::new())?,
                fee: Strikes(0),
                inputs: Vec::new(),
            },
            action,
            approvals: Vec::new(),
            offer_proof: None,
        },
        inputs: Vec::new(),
    })
}

fn plan_claim(
    request: &ClaimRequest,
    view: &ChainView<'_>,
    signer: &SignerIdentity,
) -> Result<OperationPlan, Refusal> {
    check_validity_blocks(request.validity_blocks)?;
    signer.check_current(view)?;
    select::require_profile_for_treasury(view, signer)?;
    let next = view.next_height()?;
    let (lock, condition, refund_height) = open_lock(view, &request.lock)?;
    if matches!(lock.kind, NativeLockKind::Fiat { .. }) {
        return Err(Refusal::InvalidRequest(FIAT_NOT_CLAIMABLE));
    }
    view.state()
        .wallets
        .authorize(lock.recipient, signer.descriptor())
        .map_err(|_| Refusal::NotRequiredSigner(Slot::Approval(0)))?;
    if request.preimage.condition() != condition {
        return Err(Refusal::PreimageMismatch);
    }
    if next >= refund_height {
        return Err(Refusal::WindowClosed {
            expiry: refund_height.saturating_sub(1),
            next_height: next,
        });
    }
    if view
        .reserved()
        .contains(&resource_key(LOCK_NAMESPACE, &request.lock))
    {
        return Err(Refusal::ReservedInput);
    }
    let expiry = next
        .checked_add(request.validity_blocks)
        .ok_or(Refusal::Overflow)?
        .min(refund_height.saturating_sub(1));
    let template = spend_template(
        view,
        &lock,
        next,
        expiry,
        Action::Claim {
            output: request.lock,
            recipient: lock.recipient,
            amount: lock.amount,
            preimage: *request.preimage.expose(),
            change: Strikes(0),
        },
    )?;
    let wire = fund(template, 0, view, &signer.public())?;
    assemble(OperationKind::ConditionalClaim, &wire, view, signer)
}

fn plan_refund(
    request: &RefundRequest,
    view: &ChainView<'_>,
    signer: &SignerIdentity,
) -> Result<OperationPlan, Refusal> {
    check_validity_blocks(request.validity_blocks)?;
    signer.check_current(view)?;
    select::require_profile_for_treasury(view, signer)?;
    let next = view.next_height()?;
    let (lock, _, refund_height) = open_lock(view, &request.lock)?;
    if matches!(lock.kind, NativeLockKind::Fiat { .. }) {
        return Err(Refusal::CancelNotAvailable(CancelTarget::FiatLock));
    }
    view.state()
        .wallets
        .authorize(lock.sender, signer.descriptor())
        .map_err(|_| Refusal::NotRequiredSigner(Slot::Approval(0)))?;
    if next < refund_height {
        return Err(Refusal::NotYetEligible {
            what: "Refunding this hash lock",
            height: refund_height,
        });
    }
    if view
        .reserved()
        .contains(&resource_key(LOCK_NAMESPACE, &request.lock))
    {
        return Err(Refusal::ReservedInput);
    }
    let expiry = next
        .checked_add(request.validity_blocks)
        .ok_or(Refusal::Overflow)?;
    let template = spend_template(
        view,
        &lock,
        next,
        expiry,
        Action::Refund {
            output: request.lock,
            owner: lock.sender,
            amount: lock.amount,
            change: Strikes(0),
        },
    )?;
    let wire = fund(template, 0, view, &signer.public())?;
    assemble(OperationKind::ConditionalRefund, &wire, view, signer)
}

/// Who must sign what, as seen from `me`: a pure function of the unsigned bytes and the view.
fn requirements(
    wire: &NativeOperation,
    view: &ChainView<'_>,
    me: &SignerIdentity,
) -> Result<Vec<Requirement>, Refusal> {
    let op = &wire.operation;
    let wallets = &view.state().wallets;
    let mut out = Vec::new();
    for slot in op.expected_slots() {
        let address = op
            .slot_address(slot)
            .ok_or(Refusal::Malformed("an approval slot without an address"))?;
        let status = if wallets.authorize(address, me.descriptor()).is_ok() {
            RequirementStatus::ThisWallet
        } else {
            RequirementStatus::Counterparty
        };
        out.push(Requirement {
            slot: Slot::Approval(slot),
            signer: RequiredSigner::Wallet(address),
            status,
        });
    }
    if let Action::HashLock { .. } = &op.action {
        out.push(crate::offers::fill_requirement(op, me)?);
    }
    if !out
        .iter()
        .any(|requirement| requirement.status == RequirementStatus::ThisWallet)
    {
        return Err(Refusal::NotRequiredSigner(Slot::Approval(0)));
    }
    Ok(out)
}

/// The immutable plan for the unsigned form of `wire`. A plan must pass its own validation at the
/// head it is built for.
fn assemble(
    kind: OperationKind,
    wire: &NativeOperation,
    view: &ChainView<'_>,
    signer: &SignerIdentity,
) -> Result<OperationPlan, Refusal> {
    let unsigned = stripped(wire);
    let bytes = encode(&unsigned)?;
    let requirements = requirements(&unsigned, view, signer)?;
    let meta = &unsigned.operation.meta;
    let plan = OperationPlan::assemble(
        kind,
        SCHEMA,
        signer.clone(),
        vec![PlanObject::new(OBJECT_LABEL, bytes)],
        requirements,
        unsigned.inputs.clone(),
        Validity {
            created: meta.envelope.first_height,
            expiry: meta.envelope.last_height,
            valid_only_at: None,
            bound_to_parent: false,
        },
        view,
    );
    own(kind).validate(&plan, view)?;
    Ok(plan)
}

// ---------------------------------------------------------------------------------------------
// Validation (pre-signing mirror of consensus)
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fill {
    NotRequired,
    Missing,
    Provided,
}

struct InputFact {
    point: OutPoint,
    coin: Coin,
    mine: bool,
}

struct SlotFact {
    slot: u8,
    address: Hash,
    provided: bool,
    mine: bool,
}

/// Everything a review and the checks need, derived from the bytes and the CURRENT view.
struct Facts {
    wire: NativeOperation,
    kind: OperationKind,
    head: u64,
    next: u64,
    size: u64,
    minimum: u64,
    inputs: Vec<InputFact>,
    total_in: u128,
    slots: Vec<SlotFact>,
    fill: Fill,
    offer: Option<OfferBody>,
    lock: Option<NativeLock>,
}

/// The maker's offer proof, through THE offer check of `offers::check_offer` (W19: this module's
/// own mirror was merged there, so every failure has the refusal code the License sale and the fiat
/// lock give it). An action that fills no offer (a claim, a refund) must carry none.
fn check_offer(
    op: &Operation,
    view: &ChainView<'_>,
    next: u64,
) -> Result<(Option<OfferBody>, Fill), Refusal> {
    if crate::offers::offer_ids(&op.action).is_none() {
        return if op.offer_proof.is_none() {
            Ok((None, Fill::NotRequired))
        } else {
            Err(Refusal::OfferProofInvalid)
        };
    }
    let facts = crate::offers::check_offer(op, view.state(), next)?;
    let fill = match facts.fill {
        crate::offers::Fill::Missing => Fill::Missing,
        crate::offers::Fill::Valid => Fill::Provided,
    };
    Ok((Some(facts.body), fill))
}

/// Every approval present verifies through consensus code (`trading_v1::verify_approval`: the
/// descriptor is the CURRENT authority of the slot's address in the parent wallet book, and both
/// halves of the hybrid signature verify).
fn verify_approvals(op: &Operation, view: &ChainView<'_>) -> Result<(), Refusal> {
    for approval in &op.approvals {
        trading_v1::verify_approval(&view.state().wallets, op, approval.slot)
            .map_err(|_| Refusal::CounterpartyApprovalInvalid)?;
    }
    Ok(())
}

/// The bound-lock checks of a claim or a refund (`bound_lock` in consensus).
fn bound_lock(
    view: &ChainView<'_>,
    op: &Operation,
    output: &Hash,
    amount: Strikes,
    next: u64,
) -> Result<NativeLock, Refusal> {
    let lock = trading_v1::locked(view.state(), *output).map_err(|_| Refusal::LockNotFound)?;
    let meta = &op.meta;
    if lock.context != meta.context
        || lock.trade != meta.trade
        || lock.contract != meta.contract
        || lock.generation != meta.generation
        || lock.amount != amount
    {
        return Err(Refusal::InvalidRequest(LOCK_MISMATCH));
    }
    if lock.created_height >= next {
        return Err(Refusal::NotYetEligible {
            what: "Spending this lock",
            height: lock.created_height.saturating_add(1),
        });
    }
    Ok(lock)
}

/// The coins of a trading operation (`debit` in consensus): present, owned by exactly the paying
/// address, created before the inclusion height, mature, not reserved, summing exactly to
/// `required` = principal + change + fee.
#[allow(clippy::too_many_arguments)]
fn debit(
    wire: &NativeOperation,
    view: &ChainView<'_>,
    me: Option<&SignerIdentity>,
    payer: &Hash,
    required: u128,
    next: u64,
    check_reserved: bool,
) -> Result<(Vec<InputFact>, u128), Refusal> {
    if wire.inputs.is_empty() {
        return Err(Refusal::InputUnavailable);
    }
    let state = view.state();
    let descriptor = wire
        .operation
        .approvals
        .iter()
        .find(|a| wire.operation.slot_address(a.slot) == Some(*payer))
        .map(|a| a.descriptor.clone())
        .or_else(|| crate::offers::current_descriptor(view, *payer))
        .ok_or(Refusal::StaleAuthority)?;
    state
        .wallets
        .authorize(*payer, &descriptor)
        .map_err(|_| Refusal::StaleAuthority)?;
    let mut total: u128 = 0;
    let mut inputs = Vec::with_capacity(wire.inputs.len());
    for point in &wire.inputs {
        let coin = state.coins.get(point).ok_or(Refusal::InputUnavailable)?;
        if state
            .wallets
            .authorize(coin.output.owner, &descriptor)
            .is_err()
        {
            return Err(Refusal::InvalidRequest(NOT_PAYER_COIN));
        }
        if coin.created_height >= next || (coin.coinbase && next - coin.created_height < MATURITY) {
            return Err(Refusal::ImmatureInput);
        }
        if check_reserved && view.reserved().contains(point) {
            return Err(Refusal::ReservedInput);
        }
        total = total
            .checked_add(u128::from(coin.output.atoms))
            .ok_or(Refusal::Overflow)?;
        let mine = me.is_some_and(|me| {
            state
                .wallets
                .authorize(coin.output.owner, me.descriptor())
                .is_ok()
        });
        inputs.push(InputFact {
            point: point.clone(),
            coin: coin.clone(),
            mine,
        });
    }
    if total != required {
        return Err(Refusal::Conservation);
    }
    Ok((inputs, total))
}

/// Every consensus check of `apply_one` that does not need the missing signatures, against the
/// CURRENT view, in the order consensus applies them. `check_reserved` adds the wallet's own rule
/// that nothing reserved by another pending operation is spent (off for the post-signing check of
/// bytes that may already hold their own reservations).
fn examine(
    wire: &NativeOperation,
    view: &ChainView<'_>,
    me: Option<&SignerIdentity>,
    check_reserved: bool,
) -> Result<Facts, Refusal> {
    let op = &wire.operation;
    let meta = &op.meta;
    let state = view.state();
    let kind = kind_of(&op.action).ok_or(Refusal::UnknownOperation)?;
    view.require_context(
        meta.context.network,
        &meta.context.genesis,
        &meta.context.fingerprint,
    )?;
    let head = view.anchor().height;
    let next = view.next_height()?;
    view.check_envelope(&meta.envelope)?;
    meta.envelope
        .check_preconditions(state, &meta.context)
        .map_err(|_| Refusal::StaleAuthority)?;
    if meta.envelope.first_height > next {
        return Err(Refusal::WindowNotOpen {
            created: meta.envelope.first_height,
            next_height: next,
        });
    }
    if meta.envelope.last_height < next {
        return Err(Refusal::WindowClosed {
            expiry: meta.envelope.last_height,
            next_height: next,
        });
    }
    if meta.envelope.last_height - meta.envelope.first_height > EXPIRY_HORIZON {
        return Err(Refusal::InvalidValidity);
    }
    let filler = filler_key(op, me)?;
    let size = complete_len(wire, view, &filler)?;
    let minimum = minimum_fee(size);
    if meta.fee.0 < minimum {
        return Err(Refusal::FeeBelowMinimum {
            fee: meta.fee.0,
            minimum,
        });
    }
    let id = operation_id(op)?;
    if state.protocol_records.contains_key(&record_key(2, id)) {
        return Err(Refusal::Replay);
    }
    let expected = op.expected_slots();
    if op
        .approvals
        .iter()
        .any(|approval| !expected.contains(&approval.slot))
    {
        return Err(Refusal::CounterpartyApprovalInvalid);
    }
    let (offer, fill) = check_offer(op, view, next)?;
    let fee = u128::from(meta.fee.0);
    let mut lock = None;
    let (action_payer, required, created) = match &op.action {
        Action::HashLock {
            sender,
            recipient,
            amount,
            refund_height,
            change,
            ..
        } => {
            if amount.0 == 0 {
                return Err(Refusal::InvalidAmount);
            }
            if sender == recipient {
                return Err(Refusal::InvalidRecipient);
            }
            if *refund_height <= next {
                return Err(Refusal::InvalidRequest(REFUND_NOT_ABOVE));
            }
            if meta.envelope.last_height >= *refund_height {
                return Err(Refusal::InvalidRequest(EXPIRY_NOT_BELOW_REFUND));
            }
            // Consensus would accept this lock, but included in its last block it would leave the
            // recipient no block to claim in, while the sender refunds from the refund height: for
            // every reader, built here or adopted, it is refused.
            if worst_case_claim_window(meta.envelope.last_height, *refund_height) == 0 {
                return Err(Refusal::InvalidRequest(REASON_NO_CLAIM_WINDOW));
            }
            verify_approvals(op, view)?;
            let mut created = Vec::new();
            if change.0 > 0 {
                created.push(Output {
                    owner: *sender,
                    atoms: change.0,
                });
            }
            (
                *sender,
                u128::from(amount.0) + u128::from(change.0) + fee,
                created,
            )
        }
        Action::Claim {
            output,
            recipient,
            amount,
            preimage,
            change,
        } => {
            let found = bound_lock(view, op, output, *amount, next)?;
            let NativeLockKind::Hash {
                condition,
                refund_height,
            } = found.kind
            else {
                return Err(Refusal::InvalidRequest(FIAT_NOT_CLAIMABLE));
            };
            if *recipient != found.recipient {
                return Err(Refusal::InvalidRecipient);
            }
            if trading_v1::preimage_hash(preimage) != condition {
                return Err(Refusal::PreimageMismatch);
            }
            if next >= refund_height {
                return Err(Refusal::WindowClosed {
                    expiry: refund_height.saturating_sub(1),
                    next_height: next,
                });
            }
            verify_approvals(op, view)?;
            lock = Some(found);
            (
                *recipient,
                u128::from(change.0) + fee,
                vec![
                    Output {
                        owner: *recipient,
                        atoms: amount.0,
                    },
                    Output {
                        owner: *recipient,
                        atoms: change.0,
                    },
                ],
            )
        }
        Action::Refund {
            output,
            owner,
            amount,
            change,
        } => {
            let found = bound_lock(view, op, output, *amount, next)?;
            let NativeLockKind::Hash { refund_height, .. } = found.kind else {
                return Err(Refusal::CancelNotAvailable(CancelTarget::FiatLock));
            };
            if *owner != found.sender {
                return Err(Refusal::InvalidRequest(REFUND_OWNER));
            }
            if next < refund_height {
                return Err(Refusal::NotYetEligible {
                    what: "Refunding this hash lock",
                    height: refund_height,
                });
            }
            verify_approvals(op, view)?;
            lock = Some(found);
            (
                *owner,
                u128::from(change.0) + fee,
                vec![
                    Output {
                        owner: *owner,
                        atoms: amount.0,
                    },
                    Output {
                        owner: *owner,
                        atoms: change.0,
                    },
                ],
            )
        }
        _ => return Err(Refusal::UnknownOperation),
    };
    // Consensus debits the coins of `Operation::fee_payer()` (the phase-0A accessor); the action's
    // own payer field names the same address, so a disagreement would be a mirror defect.
    let payer = op.fee_payer();
    if payer != action_payer {
        return Err(Refusal::Malformed(
            "the paying address disagrees with the action",
        ));
    }
    let (inputs, total_in) = debit(wire, view, me, &payer, required, next, check_reserved)?;
    match &op.action {
        Action::HashLock { offer, .. } => {
            if offer_consumed(view, &meta.context, offer) {
                return Err(Refusal::OfferConsumed);
            }
            if state.protocol_records.contains_key(&record_key(
                0,
                op.output_id(0)
                    .map_err(|_| Refusal::Malformed("operation identity"))?,
            )) {
                return Err(Refusal::Replay);
            }
        }
        Action::Claim { .. } | Action::Refund { .. } => {}
        _ => return Err(Refusal::UnknownOperation),
    }
    if check_reserved
        && let Some(resource) = resource_of(op)
        && view.reserved().contains(&resource)
    {
        return Err(Refusal::ReservedInput);
    }
    let spent: BTreeSet<OutPoint> = wire.inputs.iter().cloned().collect();
    require_reserve_backing(view, &spent, &created)?;
    let wallets = &state.wallets;
    let slots = expected
        .iter()
        .map(|slot| {
            let address = op
                .slot_address(*slot)
                .ok_or(Refusal::Malformed("an approval slot without an address"))?;
            Ok(SlotFact {
                slot: *slot,
                address,
                provided: op.approvals.iter().any(|approval| approval.slot == *slot),
                mine: me.is_some_and(|me| wallets.authorize(address, me.descriptor()).is_ok()),
            })
        })
        .collect::<Result<Vec<_>, Refusal>>()?;
    Ok(Facts {
        wire: wire.clone(),
        kind,
        head,
        next,
        size,
        minimum,
        inputs,
        total_in,
        slots,
        fill,
        offer,
        lock,
    })
}

// ---------------------------------------------------------------------------------------------
// Review
// ---------------------------------------------------------------------------------------------

fn classify(view: &ChainView<'_>, me: &SignerIdentity, address: &Hash) -> AddressLabel {
    if view
        .state()
        .wallets
        .authorize(*address, me.descriptor())
        .is_ok()
    {
        AddressLabel::ThisWallet
    } else if treasury_authority(view)
        .as_ref()
        .is_some_and(|authority| is_treasury_address(view, authority, address))
    {
        AddressLabel::Treasury
    } else {
        AddressLabel::External
    }
}

/// `height`, with the distance from the verified head and an approximate duration (Q11).
fn until(head: u64, height: u64) -> String {
    if height <= head {
        return format!("{height} (reached)");
    }
    let wait = height - head;
    format!(
        "{height} ({wait} blocks after the verified block; {}, approximate at the {} s target interval)",
        units::approx_blocks(wait),
        units::TARGET_BLOCK_SECONDS
    )
}

fn network_name(code: u8) -> &'static str {
    match code {
        0 => "mainnet",
        1 => "testnet",
        2 => "signet",
        3 => "regtest",
        _ => "unknown",
    }
}

fn slot_role(kind: OperationKind, slot: u8) -> &'static str {
    match (kind, slot) {
        (OperationKind::HashLock, 0) => "the sender",
        (OperationKind::HashLock, _) => "the recipient",
        (OperationKind::ConditionalClaim, _) => "the claimant",
        _ => "the refund owner",
    }
}

fn authorizations(facts: &Facts, me: &SignerIdentity) -> Vec<Requirement> {
    let mut out: Vec<Requirement> = facts
        .slots
        .iter()
        .map(|slot| Requirement {
            slot: Slot::Approval(slot.slot),
            signer: RequiredSigner::Wallet(slot.address),
            status: if slot.provided {
                RequirementStatus::Provided
            } else if slot.mine {
                RequirementStatus::ThisWallet
            } else {
                RequirementStatus::Counterparty
            },
        })
        .collect();
    if let Action::HashLock { .. } = &facts.wire.operation.action {
        out.push(
            crate::offers::fill_requirement(&facts.wire.operation, me)
                .expect("offer checked before review"),
        );
    }
    out
}

/// "Approvals still required" as a sentence derived from the authorizations.
fn still_required(facts: &Facts) -> String {
    let mut missing = Vec::new();
    for slot in &facts.slots {
        if slot.provided {
            continue;
        }
        let who = if slot.mine {
            "this wallet"
        } else {
            "a counterparty"
        };
        missing.push(format!(
            "the approval of {} (slot {}, {who})",
            slot_role(facts.kind, slot.slot),
            slot.slot
        ));
    }
    if facts.fill == Fill::Missing {
        missing.push("the maker's fill signature over this exact operation".to_string());
    }
    if missing.is_empty() {
        "None: every approval and signature is present and verified.".to_string()
    } else {
        format!("{}.", missing.join("; "))
    }
}

fn input_lines(facts: &Facts) -> Vec<InputLine> {
    facts
        .inputs
        .iter()
        .map(|input| InputLine {
            point: input.point.clone(),
            atoms: input.coin.output.atoms,
            owned_by_signer: input.mine,
            coinbase: input.coin.coinbase,
        })
        .collect()
}

fn fee_row(facts: &Facts, payer: &Hash, payer_mine: bool) -> Fee {
    Fee {
        atoms: facts.wire.operation.meta.fee.0,
        rule: FeeRule::TradingMinimum {
            floor: MINIMUM_TRADE_FEE_STRIKES,
        },
        payer: if payer_mine {
            FeePayer::ThisWallet
        } else {
            FeePayer::Counterparty(*payer)
        },
        size_bytes: Some(facts.size),
    }
}

fn timing(facts: &Facts, earliest: Option<u64>) -> Timing {
    let meta = &facts.wire.operation.meta;
    Timing {
        head_height: facts.head,
        created_height: Some(meta.envelope.first_height),
        expiry_height: Some(meta.envelope.last_height),
        valid_only_at: None,
        bound_to_parent: false,
        earliest_height: earliest,
        deadline_epoch: None,
    }
}

/// Conditions every conditional review carries, after the kind-specific ones.
fn common_conditions(
    facts: &Facts,
    payer: &Hash,
    payer_text: &str,
    view: &ChainView<'_>,
) -> Vec<Condition> {
    let meta = &facts.wire.operation.meta;
    vec![
        Condition::new(
            "Trade commitments",
            format!(
                "TradeID {} and ContractHash {} are opaque 32-byte commitments: shown, not interpreted or verified.",
                hex::encode(meta.trade),
                hex::encode(meta.contract)
            ),
        ),
        Condition::new(
            "Trade generation",
            format!(
                "{}. A claim or refund of a lock carries the generation, TradeID and ContractHash of the lock.",
                meta.generation
            ),
        ),
        Condition::new(
            "Validity window",
            format!(
                "Valid only for blocks {} to {} ({} blocks after the verified block; {}, approximate at the {} s target interval).",
                meta.envelope.first_height,
                meta.envelope.last_height,
                meta.envelope.last_height.saturating_sub(facts.head),
                units::approx_blocks(meta.envelope.last_height.saturating_sub(facts.head)),
                units::TARGET_BLOCK_SECONDS
            ),
        ),
        Condition::new(
            "Inputs",
            format!(
                "All {} input coin(s) must still be unspent coins of the {payer_text} {} when the operation is included; a conflicting spend of any of them cancels it.",
                facts.inputs.len(),
                crate::address_format::encode_for(&payer, view)
            ),
        ),
        Condition::new(
            "Fee rule",
            format!(
                "The fee must be at least the greater of {} STRIKES and the encoded size of the complete signed operation (every approval{} included): {} bytes, so {} atoms.",
                MINIMUM_TRADE_FEE_STRIKES,
                if facts.fill == Fill::NotRequired {
                    ""
                } else {
                    " and the maker's offer proof"
                },
                facts.size,
                facts.minimum
            ),
        ),
        Condition::new("Approvals still required", still_required(facts)),
    ]
}

/// Warnings every conditional review may carry.
fn common_warnings(facts: &Facts, view: &ChainView<'_>, warnings: &mut Vec<Warning>) {
    let meta = &facts.wire.operation.meta;
    if view.class() == crate::context::ChainClass::TestValue {
        warnings.push(Warning::new(
            "TEST_VALUE_CHAIN",
            Severity::Notice,
            "This is a TEST-VALUE chain: nothing here has real value.",
        ));
    }
    // Order W23: a Caution with the Conditions acknowledgement, like `OPAQUE_COMMITMENTS`.
    warnings.push(crate::offers::trade_commitments_warning());
    if meta.fee.0 > facts.minimum {
        warnings.push(Warning::new(
            "FEE_ABOVE_MINIMUM",
            Severity::Caution,
            format!(
                "The fee is {} atoms above the minimum for this size.",
                meta.fee.0 - facts.minimum
            ),
        ));
    }
    let window = meta.envelope.last_height.saturating_sub(facts.head);
    if window <= EXPIRES_SOON_BLOCKS {
        warnings.push(Warning::new(
            "EXPIRES_SOON",
            Severity::Caution,
            format!("This operation expires in {window} block(s) after the verified block."),
        ));
    }
    let treasury = treasury_authority(view);
    if facts.inputs.iter().any(|input| {
        treasury
            .as_ref()
            .is_some_and(|authority| is_treasury_address(view, authority, &input.coin.output.owner))
    }) {
        warnings.push(
            Warning::new(
                "TREASURY_FUNDS",
                Severity::Caution,
                "This spends Treasury coins. It moves MUT only; Bitcoin custody is separate and untouched.",
            )
            .requiring(AckKind::TreasuryAuthority),
        );
    }
}

fn spends_effect(facts: &Facts, payer: &Hash, payer_text: &str, view: &ChainView<'_>) -> Effect {
    Effect::new(
        format!(
            "Spends {} coin(s) worth {} of the {payer_text} {}. A spent coin cannot be recovered once the operation is included.",
            facts.inputs.len(),
            units::format_mut_wide(facts.total_in),
            crate::address_format::encode_for(&payer, view)
        ),
        true,
    )
}

fn fee_effect(facts: &Facts) -> Effect {
    Effect::new(
        format!(
            "Pays a network fee of {} to the block producer.",
            units::format_mut(facts.wire.operation.meta.fee.0)
        ),
        true,
    )
}

fn revocation_effect(facts: &Facts, complete: &str) -> Effect {
    Effect::new(
        format!(
            "Once {complete}, the operation cannot be revoked: it stays valid until it is included or until block {}.",
            facts.wire.operation.meta.envelope.last_height
        ),
        true,
    )
}

fn review_hash_lock(
    facts: &Facts,
    view: &ChainView<'_>,
    me: &SignerIdentity,
) -> Result<ReviewDraft, Refusal> {
    let Action::HashLock {
        offer: offer_id,
        maker,
        sender,
        recipient,
        amount,
        condition,
        refund_height,
        change,
    } = &facts.wire.operation.action
    else {
        return Err(Refusal::UnknownOperation);
    };
    let meta = &facts.wire.operation.meta;
    let signed_offer = facts.offer.as_ref().ok_or(Refusal::OfferProofInvalid)?;
    let offer = summarize_offer(signed_offer)?;
    let (amount, change, fee) = (amount.0, change.0, meta.fee.0);
    let sender_label = classify(view, me, sender);
    let recipient_label = classify(view, me, recipient);
    let sender_mine = sender_label == AddressLabel::ThisWallet;
    let recipient_mine = recipient_label == AddressLabel::ThisWallet;
    let head = facts.head;
    // The claim window a person can rely on is the WORST case: the lock may be included as late as
    // its own expiry, and a claim counts only in a later block below the refund height.
    let window = worst_case_claim_window(meta.envelope.last_height, *refund_height);
    let (first_claim, last_claim) = (
        meta.envelope.last_height.saturating_add(1),
        refund_height.saturating_sub(1),
    );

    let parties = vec![
        Party {
            role: PartyRole::LockSender,
            address: *sender,
            label: sender_label,
        },
        Party {
            role: PartyRole::LockRecipient,
            address: *recipient,
            label: recipient_label,
        },
    ];
    let mut destinations = vec![Destination {
        role: DestinationRole::LockedOutput,
        address: *recipient,
        label: recipient_label,
        atoms: amount,
    }];
    if sender_mine && change > 0 {
        destinations.push(Destination {
            role: DestinationRole::Change,
            address: *sender,
            label: sender_label,
            atoms: change,
        });
    }

    let mut conditions = vec![
        Condition::new(
            "Hash condition",
            format!(
                "The lock can be claimed only by publishing a 32-byte preimage whose SHA-256 is {}. The condition is opaque: this wallet does not check who knows the preimage.",
                hex::encode(condition)
            ),
        ),
        Condition::new(
            "Claim window",
            format!(
                "At least {window} block(s), the worst case: a claim counts only in a block after the lock's and below the refund height {} (last claim block {last_claim}), and this lock may be included as late as block {}, which leaves blocks {first_claim} to {last_claim}. Included earlier, the lock leaves more. Claim and refund are mutually exclusive: whichever is included first ends the lock.",
                until(head, *refund_height),
                meta.envelope.last_height
            ),
        ),
        Condition::new(
            "Refund height",
            format!(
                "From block {refund_height} on only the sender can take the locked amount back, by a separate refund that must be signed and included: refund eligibility does not execute a refund."
            ),
        ),
        Condition::new(
            "Offer",
            format!(
                "Fills the maker's single-fill offer {}, which may be filled in blocks {} to {}. The signed maker WalletOwner is bound to the {} settlement slot at {}, destination {}, maximum fee {} STRIKES and condition {}. Current maker authority is required at first canonical funding. Once the lock is included the exact funded terms persist and the offer can never be filled again.",
                hex::encode(offer_id),
                offer.created,
                offer.expiry,
                if offer.maker_side == 0 {
                    "sender"
                } else {
                    "recipient"
                },
                crate::address_format::encode_for(&signed_offer.maker_wallet, view),
                crate::address_format::encode_for(&signed_offer.destination, view),
                signed_offer.max_fee.0,
                signed_offer
                    .condition
                    .map_or("none".to_string(), hex::encode)
            ),
        ),
        Condition::new(
            "Offer terms",
            format!(
                "{amount} STRIKES locked against {} satoshis on the external chain with network code {} ({}). These external terms are integer data from the maker's signed offer; this wallet does not verify the external leg.",
                offer.bitcoin_satoshis,
                offer.bitcoin_network,
                network_name(offer.bitcoin_network)
            ),
        ),
        Condition::new(
            "Maker",
            format!(
                "Descriptor commitment {}: the maker signs with its bound WalletOwner key; this commitment is not a wallet address. The maker's fill signature over this exact operation is {}.",
                hex::encode(maker),
                if facts.fill == Fill::Provided {
                    "present and verified"
                } else {
                    "still required"
                }
            ),
        ),
        Condition::new(
            "Finality",
            format!("The lock is the native reservation of this trade. It is {FINALITY}"),
        ),
    ];
    conditions.extend(common_conditions(facts, sender, "sender address", view));

    let mut effects = Vec::new();
    if sender_mine {
        effects.push(spends_effect(facts, sender, "sender address", view));
    }
    effects.push(Effect::new(
        format!(
            "Locks {} for the recipient {} ({}) under the hash condition. The recipient can take it by publishing the preimage before block {refund_height}; nobody can recall it in that window.",
            units::format_mut(amount),
            crate::address_format::encode_for(&recipient, view),
            recipient_label.text()
        ),
        true,
    ));
    effects.push(Effect::new(
        format!(
            "From block {refund_height} on, if it was not claimed, only the sender {} can take the locked amount back, by a separate signed refund.",
            crate::address_format::encode_for(&sender, view)
        ),
        false,
    ));
    effects.push(Effect::new(
        format!(
            "Consumes the maker's single-fill offer {}: it can never be filled again.",
            units::short_hex(offer_id)
        ),
        true,
    ));
    if change > 0 {
        effects.push(Effect::new(
            format!(
                "Returns {} of change to the sender address {} ({}).",
                units::format_mut(change),
                crate::address_format::encode_for(&sender, view),
                sender_label.text()
            ),
            false,
        ));
    }
    effects.push(fee_effect(facts));
    effects.push(revocation_effect(facts, "complete and signed"));
    if recipient_mine {
        effects.push(Effect::new(
            format!(
                "This wallet may claim {} with the preimage before block {refund_height}.",
                units::format_mut(amount)
            ),
            false,
        ));
    }

    let mut warnings = Vec::new();
    common_warnings(facts, view, &mut warnings);
    warnings.push(
        Warning::new(
            "EXTERNAL_LEG_NOT_VERIFIED",
            Severity::Caution,
            format!(
                "The external leg of this trade ({} satoshis, network code {}, per the offer) is not verified by this wallet; Bitcoin custody stays outside this wallet and is never touched by it.",
                offer.bitcoin_satoshis, offer.bitcoin_network
            ),
        )
        .requiring(AckKind::ExternalEvidence),
    );
    warnings.push(Warning::new(
        "NOT_FINAL_UNTIL_CERTIFIED",
        Severity::Caution,
        "Move nothing on the external leg until this lock is final in the verified chain: a local queue entry or a proposed block is not finality.",
    ));
    if short_claim_window(
        window,
        meta.envelope.first_height,
        meta.envelope.last_height,
    ) {
        warnings.push(
            Warning::new(
                "SHORT_CLAIM_WINDOW",
                Severity::Caution,
                format!(
                    "The claim window can be as short as {window} block(s) (blocks {first_claim} to {last_claim}): the lock may be included as late as block {}, and a claim counts only below the refund height {refund_height}. The lock itself may be included in any of {} block(s).",
                    meta.envelope.last_height,
                    meta.envelope.last_height.saturating_sub(meta.envelope.first_height).saturating_add(1)
                ),
            )
            .requiring(AckKind::Conditions),
        );
    }
    if sender_mine && recipient_mine {
        warnings.push(Warning::new(
            "SELF_LOCK",
            Severity::Notice,
            "Sender and recipient are both addresses of this wallet.",
        ));
    }

    let (title, summary) = if sender_mine {
        (
            "Lock MUT to a hash condition".to_string(),
            format!(
                "Lock {} for {} under a hash condition: claimable with the preimage before block {refund_height}, in at least {window} block(s) after the lock's inclusion; refundable to this wallet from block {refund_height}. Network fee {}.",
                units::format_mut(amount),
                crate::address_format::encode_for(recipient, view),
                units::format_mut(fee)
            ),
        )
    } else if recipient_mine {
        (
            "Approve a hash lock for this wallet".to_string(),
            format!(
                "{} locks {} for this wallet; claim it with the preimage before block {refund_height}, in at least {window} block(s) after the lock's inclusion. The sender pays the network fee of {}.",
                crate::address_format::encode_for(sender, view),
                units::format_mut(amount),
                units::format_mut(fee)
            ),
        )
    } else {
        (
            "Hash lock between other wallets".to_string(),
            "This lock moves coins this wallet does not control; it has nothing to sign in it."
                .to_string(),
        )
    };

    Ok(ReviewDraft {
        kind: OperationKind::HashLock,
        schema: SCHEMA,
        title,
        summary,
        signer: me.summary(),
        authorizations: authorizations(facts, me),
        parties,
        destinations,
        amount: Some(amount),
        returned: if sender_mine { change } else { 0 },
        fee: fee_row(facts, sender, sender_mine),
        net_debit: Some(if sender_mine {
            u128::from(amount) + u128::from(fee)
        } else {
            0
        }),
        inputs: input_lines(facts),
        conditions,
        timing: timing(facts, None),
        effects,
        warnings,
        extra_acks: vec![AckKind::Conditions],
        high_risk: true,
    })
}

fn lock_condition(
    facts: &Facts,
    lock_id: &Hash,
    view: &ChainView<'_>,
) -> Result<Condition, Refusal> {
    let lock = facts.lock.as_ref().ok_or(Refusal::LockNotFound)?;
    Ok(Condition::new(
        "Lock",
        format!(
            "Spends hash lock {} created at block {} by the sender {}: {} locked for the recipient {}.",
            hex::encode(lock_id),
            lock.created_height,
            crate::address_format::encode_for(&lock.sender, view),
            units::format_amount(lock.amount.0),
            crate::address_format::encode_for(&lock.recipient, view)
        ),
    ))
}

fn review_claim(
    facts: &Facts,
    view: &ChainView<'_>,
    me: &SignerIdentity,
) -> Result<ReviewDraft, Refusal> {
    let Action::Claim {
        output,
        recipient,
        amount,
        change,
        ..
    } = &facts.wire.operation.action
    else {
        return Err(Refusal::UnknownOperation);
    };
    let lock = facts.lock.as_ref().ok_or(Refusal::LockNotFound)?;
    let NativeLockKind::Hash {
        condition,
        refund_height,
    } = lock.kind
    else {
        return Err(Refusal::InvalidRequest(FIAT_NOT_CLAIMABLE));
    };
    let meta = &facts.wire.operation.meta;
    let (amount, change, fee) = (amount.0, change.0, meta.fee.0);
    let recipient_label = classify(view, me, recipient);
    let mine = recipient_label == AddressLabel::ThisWallet;
    let head = facts.head;

    let parties = vec![
        Party {
            role: PartyRole::Claimant,
            address: *recipient,
            label: recipient_label,
        },
        Party {
            role: PartyRole::LockSender,
            address: lock.sender,
            label: classify(view, me, &lock.sender),
        },
    ];
    let mut destinations = vec![Destination {
        role: DestinationRole::ProtocolPayout,
        address: *recipient,
        label: recipient_label,
        atoms: amount,
    }];
    if mine && change > 0 {
        destinations.push(Destination {
            role: DestinationRole::Change,
            address: *recipient,
            label: recipient_label,
            atoms: change,
        });
    }

    let mut conditions = vec![
        lock_condition(facts, output, view)?,
        Condition::new(
            "Hash condition",
            format!(
                "{}: the preimage carried by this claim hashes to it (checked).",
                hex::encode(condition)
            ),
        ),
        Condition::new(
            "Claim deadline",
            format!(
                "Valid only while the including block is below the refund height {}; from that block on the sender may refund instead. This claim expires at block {}.",
                until(head, refund_height),
                meta.envelope.last_height
            ),
        ),
        Condition::new(
            "Preimage origin",
            "preimage supplied externally; Bitcoin settlement not verified by this wallet.",
        ),
        Condition::new(
            "Fee coins",
            format!(
                "The fee is paid from {} separate coin(s) of the recipient address {}; the locked amount is credited in full.",
                facts.inputs.len(),
                crate::address_format::encode_for(&recipient, view)
            ),
        ),
        Condition::new("Finality", format!("The claim is {FINALITY}")),
    ];
    conditions.extend(common_conditions(
        facts,
        recipient,
        "recipient address",
        view,
    ));

    let mut effects = vec![Effect::new(
        "Publishes the preimage in the block: from inclusion it is public, and anyone can read it and use it wherever the same hash condition applies.",
        true,
    )];
    effects.push(Effect::new(
        format!(
            "Credits the locked {} to the recipient {} ({}) and ends the lock: it can no longer be refunded.",
            units::format_mut(amount),
            crate::address_format::encode_for(&recipient, view),
            recipient_label.text()
        ),
        true,
    ));
    if mine {
        effects.push(spends_effect(facts, recipient, "recipient address", view));
    }
    if change > 0 {
        effects.push(Effect::new(
            format!(
                "Returns {} of change to the recipient address {} ({}).",
                units::format_mut(change),
                crate::address_format::encode_for(&recipient, view),
                recipient_label.text()
            ),
            false,
        ));
    }
    effects.push(fee_effect(facts));
    effects.push(revocation_effect(facts, "signed"));

    let mut warnings = Vec::new();
    common_warnings(facts, view, &mut warnings);
    warnings.push(
        Warning::new(
            "DISCLOSES_PREIMAGE",
            Severity::Danger,
            "Claiming reveals the preimage publicly. Claim only when nothing on the other leg of the trade depends on keeping it secret.",
        )
        .requiring(AckKind::DisclosesPreimage),
    );
    warnings.push(
        Warning::new(
            "PREIMAGE_SUPPLIED_EXTERNALLY",
            Severity::Caution,
            "Check the other leg of the trade yourself: preimage supplied externally; Bitcoin settlement not verified by this wallet.",
        )
        .requiring(AckKind::ExternalEvidence),
    );
    let left = refund_height.saturating_sub(facts.next);
    if left < SHORT_WINDOW_BLOCKS {
        warnings.push(Warning::new(
            "CLAIM_DEADLINE_NEAR",
            Severity::Caution,
            format!(
                "Only {left} block(s) remain before the refund height: a claim included later is invalid."
            ),
        ));
    }

    let (title, summary) = if mine {
        (
            "Claim a hash lock".to_string(),
            format!(
                "Claim {} from lock {} by publishing its preimage. Network fee {}.",
                units::format_mut(amount),
                units::short_hex(output),
                units::format_mut(fee)
            ),
        )
    } else {
        (
            "Claim of a hash lock by another wallet".to_string(),
            "This claim spends coins this wallet does not control; it has nothing to sign in it."
                .to_string(),
        )
    };

    Ok(ReviewDraft {
        kind: OperationKind::ConditionalClaim,
        schema: SCHEMA,
        title,
        summary,
        signer: me.summary(),
        authorizations: authorizations(facts, me),
        parties,
        destinations,
        amount: Some(amount),
        returned: if mine { change } else { 0 },
        fee: fee_row(facts, recipient, mine),
        net_debit: Some(if mine { u128::from(fee) } else { 0 }),
        inputs: input_lines(facts),
        conditions,
        timing: timing(facts, None),
        effects,
        warnings,
        extra_acks: vec![AckKind::Conditions],
        high_risk: true,
    })
}

fn review_refund(
    facts: &Facts,
    view: &ChainView<'_>,
    me: &SignerIdentity,
) -> Result<ReviewDraft, Refusal> {
    let Action::Refund {
        output,
        owner,
        amount,
        change,
    } = &facts.wire.operation.action
    else {
        return Err(Refusal::UnknownOperation);
    };
    let lock = facts.lock.as_ref().ok_or(Refusal::LockNotFound)?;
    let NativeLockKind::Hash { refund_height, .. } = lock.kind else {
        return Err(Refusal::CancelNotAvailable(CancelTarget::FiatLock));
    };
    let meta = &facts.wire.operation.meta;
    let (amount, change, fee) = (amount.0, change.0, meta.fee.0);
    let owner_label = classify(view, me, owner);
    let mine = owner_label == AddressLabel::ThisWallet;

    let parties = vec![
        Party {
            role: PartyRole::Owner,
            address: *owner,
            label: owner_label,
        },
        Party {
            role: PartyRole::LockRecipient,
            address: lock.recipient,
            label: classify(view, me, &lock.recipient),
        },
    ];
    let mut destinations = vec![Destination {
        role: DestinationRole::ProtocolPayout,
        address: *owner,
        label: owner_label,
        atoms: amount,
    }];
    if mine && change > 0 {
        destinations.push(Destination {
            role: DestinationRole::Change,
            address: *owner,
            label: owner_label,
            atoms: change,
        });
    }

    let mut conditions = vec![
        lock_condition(facts, output, view)?,
        Condition::new(
            "Refund height",
            format!(
                "Refund allowed from block {refund_height} on; the next block is {}.",
                facts.next
            ),
        ),
        Condition::new(
            "Exclusivity",
            "Claim and refund are mutually exclusive: if a claim of this lock is included first, this refund fails. Refund eligibility does not execute a refund: this operation must be included.",
        ),
        Condition::new(
            "Fee coins",
            format!(
                "The fee is paid from {} separate coin(s) of the sender address {}; the locked amount is returned in full.",
                facts.inputs.len(),
                crate::address_format::encode_for(&owner, view)
            ),
        ),
        Condition::new("Finality", format!("The refund is {FINALITY}")),
    ];
    conditions.extend(common_conditions(facts, owner, "sender address", view));

    let mut effects = vec![Effect::new(
        format!(
            "Returns the locked {} to the sender address {} ({}) and ends the lock: the recipient can no longer claim it.",
            units::format_mut(amount),
            crate::address_format::encode_for(&owner, view),
            owner_label.text()
        ),
        true,
    )];
    if mine {
        effects.push(spends_effect(facts, owner, "sender address", view));
    }
    if change > 0 {
        effects.push(Effect::new(
            format!(
                "Returns {} of change to the sender address {} ({}).",
                units::format_mut(change),
                crate::address_format::encode_for(&owner, view),
                owner_label.text()
            ),
            false,
        ));
    }
    effects.push(fee_effect(facts));
    effects.push(revocation_effect(facts, "signed"));

    let mut warnings = Vec::new();
    common_warnings(facts, view, &mut warnings);

    let (title, summary) = if mine {
        (
            "Refund a hash lock".to_string(),
            format!(
                "Take back {} from lock {} after its refund height. Network fee {}.",
                units::format_mut(amount),
                units::short_hex(output),
                units::format_mut(fee)
            ),
        )
    } else {
        (
            "Refund of a hash lock by another wallet".to_string(),
            "This refund spends coins this wallet does not control; it has nothing to sign in it."
                .to_string(),
        )
    };

    Ok(ReviewDraft {
        kind: OperationKind::ConditionalRefund,
        schema: SCHEMA,
        title,
        summary,
        signer: me.summary(),
        authorizations: authorizations(facts, me),
        parties,
        destinations,
        amount: Some(amount),
        returned: if mine { change } else { 0 },
        fee: fee_row(facts, owner, mine),
        net_debit: Some(if mine { u128::from(fee) } else { 0 }),
        inputs: input_lines(facts),
        conditions,
        timing: timing(facts, Some(refund_height)),
        effects,
        warnings,
        extra_acks: vec![AckKind::Conditions],
        high_risk: false,
    })
}

fn build_review(
    facts: &Facts,
    view: &ChainView<'_>,
    me: &SignerIdentity,
) -> Result<ReviewDraft, Refusal> {
    match facts.kind {
        OperationKind::HashLock => review_hash_lock(facts, view, me),
        OperationKind::ConditionalClaim => review_claim(facts, view, me),
        _ => review_refund(facts, view, me),
    }
}

// ---------------------------------------------------------------------------------------------
// Description and completion
// ---------------------------------------------------------------------------------------------

/// What signed or partial bytes commit to (see `OperationHandler::describe`).
fn describe_wire(wire: &NativeOperation, raw: &[u8]) -> Result<Description, Refusal> {
    let op = &wire.operation;
    if op.approvals.is_empty() {
        return Err(Refusal::Malformed(
            "no approval is present: nothing was signed",
        ));
    }
    let expected = op.expected_slots();
    if op
        .approvals
        .iter()
        .any(|approval| !expected.contains(&approval.slot))
    {
        return Err(Refusal::Malformed(
            "an approval for a slot this operation does not have",
        ));
    }
    let mut missing = Vec::new();
    for slot in &expected {
        if op.approvals.iter().any(|approval| approval.slot == *slot) {
            continue;
        }
        let address = op
            .slot_address(*slot)
            .ok_or(Refusal::Malformed("an approval slot without an address"))?;
        missing.push(Requirement {
            slot: Slot::Approval(*slot),
            signer: RequiredSigner::Wallet(address),
            status: RequirementStatus::Counterparty,
        });
    }
    if let Action::HashLock { maker, .. } = &op.action
        && !fill_present(op)
    {
        missing.push(Requirement {
            slot: Slot::FillSignature,
            signer: RequiredSigner::Maker(*maker),
            status: RequirementStatus::Maker,
        });
    }
    let complete = missing.is_empty();
    let id = if complete {
        operation_id(op)?
    } else {
        partial_id(raw)
    };
    let mut reserved = wire.inputs.clone();
    reserved.extend(resource_of(op));
    reserved.sort();
    reserved.dedup();
    Ok(Description {
        id,
        complete,
        missing,
        validity: Validity {
            created: op.meta.envelope.first_height,
            expiry: op.meta.envelope.last_height,
            valid_only_at: None,
            bound_to_parent: false,
        },
        reserved,
    })
}

fn signed_from(kind: OperationKind, bytes: Vec<u8>, described: Description) -> SignedOperation {
    if described.complete {
        SignedOperation::Complete {
            kind,
            id: described.id,
            bytes,
            validity: described.validity,
            reserved: described.reserved,
        }
    } else {
        SignedOperation::Partial {
            kind,
            id: described.id,
            bytes,
            missing: described.missing,
            validity: described.validity,
            reserved: described.reserved,
        }
    }
}

/// Merge the public parts of ONE conditional operation into its complete form and import it.
///
/// `parts` are encodings of the same operation (the same unsigned form) carrying different
/// approvals, for example this wallet's partial and the counterparty's; `fill`, when given, is the
/// maker's `OfferProof` encoding for exactly this operation (its offer must be the operation's
/// offer; only its fill signature is taken). EVERY approval and fill signature any part (or `fill`)
/// carries is verified before one is used, as `offers::combine` does: one that does not verify
/// refuses the whole completion, even next to a valid one for the same slot (it is a tampered or
/// foreign part, never silently dropped). The merged bytes are then imported with
/// `SignedOperation::import`, which
/// derives every field from the bytes and verifies the operation through consensus code
/// (`trading_v1::prepare_batch`). Nothing is signed here. A missing or invalid counterparty
/// approval is `COUNTERPARTY_APPROVAL_INVALID`; a missing or invalid fill signature is
/// `OFFER_PROOF_INVALID`; a fee below `max(240, complete size)` is `FEE_BELOW_MINIMUM`.
pub fn complete(
    parts: &[&[u8]],
    fill: Option<&[u8]>,
    view: &ChainView<'_>,
) -> Result<SignedOperation, Refusal> {
    let Some(first) = parts.first() else {
        return Err(Refusal::PartialInvalid("no part to complete"));
    };
    if parts.len() > 8 {
        return Err(Refusal::PartialInvalid("too many parts"));
    }
    let base = decode(first)?;
    if kind_of(&base.operation.action).is_none() {
        return Err(Refusal::UnknownOperation);
    }
    let unsigned = stripped(&base);
    let reference = encode(&unsigned)?;
    let mut candidates: BTreeMap<u8, Vec<TradeApproval>> = BTreeMap::new();
    let mut fills = Vec::new();
    for raw in parts {
        let wire = decode(raw)?;
        if encode(&stripped(&wire))? != reference {
            return Err(Refusal::PartialInvalid(PARTS_DIFFER));
        }
        for approval in wire.operation.approvals {
            candidates.entry(approval.slot).or_default().push(approval);
        }
        if let Some(proof) = &wire.operation.offer_proof
            && !payment::is_unsigned(&proof.fill_signature)
        {
            fills.push(proof.fill_signature.clone());
        }
    }
    if let Some(raw) = fill {
        let proof = OfferProof::decode(raw).map_err(|_| Refusal::OfferProofInvalid)?;
        let ours = unsigned
            .operation
            .offer_proof
            .as_ref()
            .ok_or(Refusal::OfferProofInvalid)?;
        // The maker's proof must be for this operation's offer, and whole: its own copy of the
        // offer signature must verify too, although only its fill signature is used.
        if proof.offer.body != ours.offer.body || proof.offer.verify().is_err() {
            return Err(Refusal::OfferProofInvalid);
        }
        fills.insert(0, proof.fill_signature);
    }
    let next = view.next_height()?;
    let mut merged = unsigned;
    let expected = merged.operation.expected_slots();
    for slot in expected {
        let found = candidates.remove(&slot).unwrap_or_default();
        let mut accepted = None;
        for approval in found {
            let mut trial = merged.clone();
            trial.operation.approvals.push(approval.clone());
            trial.operation.approvals.sort_by_key(|a| a.slot);
            if trading_v1::verify_approval(&view.state().wallets, &trial.operation, slot).is_err() {
                return Err(Refusal::CounterpartyApprovalInvalid);
            }
            accepted.get_or_insert(approval);
        }
        let approval = accepted.ok_or(Refusal::CounterpartyApprovalInvalid)?;
        merged.operation.approvals.push(approval);
        merged.operation.approvals.sort_by_key(|a| a.slot);
    }
    if !candidates.is_empty() {
        return Err(Refusal::CounterpartyApprovalInvalid);
    }
    if merged.operation.offer_proof.is_some() {
        let mut accepted = None;
        for signature in fills {
            let mut trial = merged.clone();
            if let Some(proof) = &mut trial.operation.offer_proof {
                proof.fill_signature = signature;
            }
            if trial.operation.verify_offer(next).is_err() {
                return Err(Refusal::OfferProofInvalid);
            }
            accepted.get_or_insert(trial);
        }
        merged = accepted.ok_or(Refusal::OfferProofInvalid)?;
    }
    let bytes = encode(&merged)?;
    let signed = SignedOperation::import(&bytes, view)?;
    if !signed.is_complete() {
        return Err(Refusal::VerificationFailed(
            "the merged operation is not complete",
        ));
    }
    Ok(signed)
}

/// A short machine-readable reason for a consensus rejection of a COMPLETE operation that the
/// wallet's own mirror accepted (a mirror gap or a view that is not the verified parent).
fn consensus_verdict(error: &NativeError) -> &'static str {
    match error {
        NativeError::Envelope(_) => "consensus: signed window or canonical reference failed",
        NativeError::Stale(_) => "consensus: committed state changed; review again",
        NativeError::Codec => "consensus: the operation does not decode",
        NativeError::Context => "consensus: wrong chain context or parent state",
        NativeError::Gate | NativeError::UnitUnresolved => "consensus: trading is not enabled",
        NativeError::Bounds => "consensus: the operation is out of bounds",
        NativeError::Authority => "consensus: an approval or an input owner is not authorized",
        NativeError::Immature => "consensus: an input is immature",
        NativeError::Missing => "consensus: an input or the lock is missing",
        NativeError::Duplicate => {
            "consensus: the operation, its offer or its outputs already exist"
        }
        NativeError::Conflict => "consensus: conflicting records",
        NativeError::Conservation => "consensus: inputs do not equal principal, change and fee",
        NativeError::Overflow => "consensus: arithmetic overflow",
        NativeError::Fee => "consensus: the fee is below the minimum",
        NativeError::Time => "consensus: the operation is outside its time window",
        NativeError::Record => "consensus: the resulting state is invalid",
        NativeError::FiatRecoveryUnspecified => {
            "consensus: a fiat lock cannot be claimed or refunded"
        }
        NativeError::LicenseLocked => "consensus: License locked",
        NativeError::Candidate(_) => "consensus: the offer proof or the encoding is invalid",
    }
}

// ---------------------------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------------------------

impl ConditionalHandler {
    /// Decode bytes of THIS handler's kind.
    fn own_wire(&self, raw: &[u8]) -> Result<NativeOperation, Refusal> {
        let wire = decode(raw)?;
        if kind_of(&wire.operation.action) != Some(self.kind) {
            return Err(Refusal::UnknownOperation);
        }
        Ok(wire)
    }

    /// The unsigned form a plan of this kind holds.
    fn plan_wire(&self, plan: &OperationPlan) -> Result<NativeOperation, Refusal> {
        let [object] = plan.objects() else {
            return Err(Refusal::Malformed(
                "a conditional plan has exactly one object",
            ));
        };
        if object.label != OBJECT_LABEL {
            return Err(Refusal::Malformed("unexpected plan object"));
        }
        let wire = self.own_wire(&object.bytes)?;
        if wire != stripped(&wire) {
            return Err(Refusal::Malformed("a plan holds the unsigned form only"));
        }
        Ok(wire)
    }
}

impl OperationHandler for ConditionalHandler {
    fn kind(&self) -> OperationKind {
        self.kind
    }

    fn recognizes(&self, raw: &[u8]) -> bool {
        NativeOperation::decode(raw)
            .is_ok_and(|wire| kind_of(&wire.operation.action) == Some(self.kind))
    }

    fn plan(
        &self,
        request: &OperationRequest,
        view: &ChainView<'_>,
        signer: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        match (self.kind, request) {
            (OperationKind::HashLock, OperationRequest::HashLock(request)) => {
                plan_hash_lock(request, view, signer)
            }
            (OperationKind::ConditionalClaim, OperationRequest::ConditionalClaim(request)) => {
                plan_claim(request, view, signer)
            }
            (OperationKind::ConditionalRefund, OperationRequest::ConditionalRefund(request)) => {
                plan_refund(request, view, signer)
            }
            _ => Err(Refusal::UnknownOperation),
        }
    }

    fn adopt(
        &self,
        raw: &[u8],
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        let wire = self.own_wire(raw)?;
        me.check_current(view)?;
        // The bytes as received are checked in full first: approvals already present and the
        // maker's fill signature must verify, and every rule must hold at this head.
        examine(&wire, view, Some(me), true)?;
        let op = &wire.operation;
        let wallets = &view.state().wallets;
        let (mut controls, mut unsigned) = (false, false);
        for slot in op.expected_slots() {
            if let Some(address) = op.slot_address(slot)
                && wallets.authorize(address, me.descriptor()).is_ok()
            {
                controls = true;
                if !op.approvals.iter().any(|approval| approval.slot == slot) {
                    unsigned = true;
                }
            }
        }
        if !controls {
            return Err(Refusal::NotRequiredSigner(Slot::Approval(0)));
        }
        if !unsigned {
            return Err(Refusal::Malformed(
                "this wallet's approval is already present: there is nothing left to sign",
            ));
        }
        assemble(self.kind, &stripped(&wire), view, me)
    }

    fn validate(&self, plan: &OperationPlan, view: &ChainView<'_>) -> Result<(), Refusal> {
        let wire = self.plan_wire(plan)?;
        // Whoever signs for the Treasury authority does so through the Treasury profile, however the
        // plan came to exist (built here or adopted from bytes).
        select::require_profile_for_treasury(view, plan.signer())?;
        plan.signer().check_current(view)?;
        examine(&wire, view, Some(plan.signer()), true)?;
        // Who signs what is derived again from the bytes and the CURRENT wallet book.
        if requirements(&wire, view, plan.signer())? != plan.requirements() {
            return Err(Refusal::StaleAuthority);
        }
        Ok(())
    }

    fn review(&self, plan: &OperationPlan, view: &ChainView<'_>) -> Result<ReviewDraft, Refusal> {
        let wire = self.plan_wire(plan)?;
        let facts = examine(&wire, view, Some(plan.signer()), true)?;
        build_review(&facts, view, plan.signer())
    }

    fn explain(
        &self,
        raw: &[u8],
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<(ReviewDraft, Vec<PlanObject>), Refusal> {
        let wire = self.own_wire(raw)?;
        let facts = examine(&wire, view, Some(me), true)?;
        let draft = build_review(&facts, view, me)?;
        let unsigned = encode(&stripped(&wire))?;
        Ok((draft, vec![PlanObject::new(OBJECT_LABEL, unsigned)]))
    }

    fn sign(
        &self,
        plan: &OperationPlan,
        signer: &KindSigner<'_>,
        _view: &ChainView<'_>,
    ) -> Result<SignedOperation, Refusal> {
        let mut wire = self.plan_wire(plan)?;
        let descriptor = plan.signer().descriptor().to_vec();
        for requirement in plan.requirements() {
            if requirement.status != RequirementStatus::ThisWallet {
                continue;
            }
            if requirement.slot == Slot::FillSignature {
                wire.operation.offer_proof = Some(
                    signer
                        .maker_fill_authorization()?
                        .authorize_fill(&wire.operation)?,
                );
                continue;
            }
            let Slot::Approval(slot) = requirement.slot else {
                return Err(Refusal::SigningFailed);
            };
            let signature =
                signer
                    .trade_approval()?
                    .approve_slot(&wire.operation, slot, plan.signer())?;
            wire.operation.approvals.push(TradeApproval {
                slot,
                descriptor: descriptor.clone(),
                signature,
            });
        }
        wire.operation
            .approvals
            .sort_by_key(|approval| approval.slot);
        let bytes = encode(&wire)?;
        let described = describe_wire(&wire, &bytes)?;
        Ok(signed_from(self.kind, bytes, described))
    }

    fn unsigned_form(&self, raw: &[u8]) -> Result<Vec<PlanObject>, Refusal> {
        let wire = self.own_wire(raw)?;
        Ok(vec![PlanObject::new(
            OBJECT_LABEL,
            encode(&stripped(&wire))?,
        )])
    }

    fn describe(&self, raw: &[u8]) -> Result<Description, Refusal> {
        let wire = self.own_wire(raw)?;
        describe_wire(&wire, raw)
    }

    /// A partial operation is identified by its exact bytes, the complete one by its consensus
    /// operation id; that id does not depend on the approvals or the maker's fill, so it is the
    /// identity of both.
    fn operation_identity(&self, raw: &[u8]) -> Result<Hash, Refusal> {
        operation_id(&self.own_wire(raw)?.operation)
    }

    fn check_signed(&self, signed: &SignedOperation, view: &ChainView<'_>) -> Result<(), Refusal> {
        if signed.kind() != self.kind {
            return Err(Refusal::UnknownOperation);
        }
        let wire = self.own_wire(signed.bytes())?;
        let described = describe_wire(&wire, signed.bytes())?;
        if described.id != signed.id() {
            return Err(Refusal::VerificationFailed(
                "operation identifier does not match the bytes",
            ));
        }
        // BOTH_REQUIRED: both halves of every approval present, then verified with the rest.
        if wire.operation.approvals.iter().any(|approval| {
            approval.signature.ed448 == [0; 114] || approval.signature.fndsa == [0; 1280]
        }) {
            return Err(Refusal::VerificationFailed(
                "an approval is missing a signature half",
            ));
        }
        // Every rule that holds at this head, approvals verified through `verify_approval`.
        examine(&wire, view, None, false)?;
        if described.complete {
            // Independent verification of the whole operation through consensus code.
            trading_v1::prepare_batch_with_history(
                view.state(),
                view.anchor(),
                view.state_root(),
                &view.history(),
                &[signed.bytes().to_vec()],
                &CandidatePolicy::native_denomination_locked(),
            )
            .map_err(|error| Refusal::VerificationFailed(consensus_verdict(&error)))?;
        }
        Ok(())
    }

    fn reconcile(&self, record: &OutboxRecord, view: &ChainView<'_>) -> Settlement {
        if let Some(height) = view.confirmed_height(&record.id) {
            return Settlement::Confirmed(height);
        }
        let state = view.state();
        let wire = NativeOperation::decode(&record.bytes).ok();
        // Receipt rows describe execution state, but cannot establish this host's own
        // canonical history. Confirmation requires the replay-derived lookup above.
        if view
            .next_height()
            .map_or(true, |next| next > record.validity.expiry)
        {
            return Settlement::Expired;
        }
        if record
            .reserved
            .iter()
            .filter(|point| point.index != u32::MAX)
            .any(|point| !state.coins.contains_key(point))
        {
            return Settlement::InputsSpent;
        }
        if let Some(wire) = &wire {
            let op = &wire.operation;
            let gone = match &op.action {
                Action::HashLock { offer, .. } => offer_consumed(view, &op.meta.context, offer),
                Action::Claim { output, .. } | Action::Refund { output, .. } => {
                    trading_v1::locked(state, *output).is_err()
                }
                _ => false,
            };
            if gone {
                return Settlement::InputsSpent;
            }
        }
        Settlement::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handlers_are_registered_for_exactly_the_three_kinds() {
        for kind in OperationKind::ALL {
            let found = handler(kind);
            assert_eq!(
                found.is_some(),
                matches!(
                    kind,
                    OperationKind::HashLock
                        | OperationKind::ConditionalClaim
                        | OperationKind::ConditionalRefund
                ),
                "{kind:?}"
            );
            if let Some(found) = found {
                assert_eq!(found.kind(), kind);
            }
        }
    }

    #[test]
    fn the_fee_floor_and_the_input_limit_are_the_consensus_values() {
        assert_eq!(TRADE_FEE_FLOOR, 240);
        assert_eq!(MAX_TRADE_INPUTS, 16);
        assert_eq!(minimum_fee(10), 240);
        assert_eq!(minimum_fee(240), 240);
        assert_eq!(minimum_fee(5_000), 5_000);
    }

    #[test]
    fn resource_namespaces_are_distinct_and_a_claim_and_a_refund_share_one() {
        let id = [7u8; 32];
        assert_ne!(
            resource_key(OFFER_NAMESPACE, &id),
            resource_key(LOCK_NAMESPACE, &id)
        );
        assert_eq!(resource_key(LOCK_NAMESPACE, &id).index, u32::MAX);
    }

    #[test]
    fn partial_identifiers_are_bound_to_the_exact_bytes() {
        assert_ne!(partial_id(b"a"), partial_id(b"b"));
        assert_eq!(partial_id(b"a"), partial_id(b"a"));
    }

    #[test]
    fn the_memory_store_keeps_fresh_preimages_by_condition_and_prints_nothing_secret() {
        let mut store = MemoryPreimageStore::new();
        assert!(store.is_empty());
        let condition = store.create().unwrap();
        let again = store.create().unwrap();
        assert_ne!(condition, again, "every preimage is fresh");
        let held = store.preimage(&condition).unwrap().unwrap();
        assert_eq!(held.condition(), condition);
        assert_eq!(store.conditions().unwrap().len(), 2);
        let shown = format!("{store:?}");
        assert_eq!(shown, "MemoryPreimageStore { preimages: 2 }");
        assert!(store.erase(&condition).unwrap());
        assert!(!store.erase(&condition).unwrap());
        assert!(store.preimage(&condition).unwrap().is_none());
        assert_eq!(store.len(), 1);
    }
}
