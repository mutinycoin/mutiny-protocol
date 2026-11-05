//! (f) Treasury profile operations (phase 6): the trading Treasury destination rotation
//! (`TreasuryRotate`, "R2") and the Treasury offer-freeze authorization.
//!
//! Both are signed by the wallet that controls the ACTIVE destination address of one trading
//! Treasury, through the Treasury profile only (`profile`). The Genesis Treasury wallet-authority
//! rotation ("R1") is the ordinary `WalletRotation` (`ops::rotation`) under the same profile; it has
//! no handler here.
//!
//! THE ROTATION (`trading_v1::Action::TreasuryRotate`). Every rule below was read from
//! `trading_v1::apply_one` and `prepare_batch` and is mirrored before signing (`examine_rotate`):
//!
//!  * context = the chain's; window `created <= H <= expiry`, `expiry - created <= 10,080`; fee at
//!    least `max(240, encoded length of the complete signed wire)`; not already applied (`Applied`
//!    receipt); approval slots exactly {0}; no maker offer proof.
//!  * the Treasury's head record (tag 3) names the ACTIVE generation; it must have taken effect
//!    (`effective_height <= H`), and the operation must name exactly that generation and its address,
//!    with `new_generation = current_generation + 1`.
//!  * slot 0 is authorized by the CURRENT wallet authority of `current_address`, through the parent
//!    wallet book, and its descriptor must hash (`trading_v1::descriptor_hash`) to the operation's
//!    `current_descriptor`.
//!  * the NEW address must ALREADY resolve to the new descriptor in the parent wallet book
//!    (`WalletBook::authorize(new_address, new_descriptor)`), the new descriptor is a wallet-owner
//!    descriptor whose own address is `new_address`, the previous generation took effect strictly
//!    before H, and the address was never a destination of this Treasury (address index, tag 6).
//!  * exactly three record writes (the new generation, its address entry, the replaced head); the
//!    rotation is effective at the inclusion height. Fee and change come from coins of exactly
//!    `current_address` (`debit`: owner equality, created before H, mature, inputs = change + fee);
//!    the change is credited to `current_address` at output 0.
//!  * Treasury coins are dividend reserve backing: when `current_address` is a Genesis Treasury
//!    address, `State::root` (run by `prepare_batch` and by block execution) refuses a state whose
//!    backing is below the reserve, so the wallet refuses such a fee first
//!    (`RESERVE_BACKING_VIOLATION`, Q15).
//!  * funded native locks keep their signed destinations and claim/refund rules across rotation.
//!    Unfunded offer/freezing witnesses prove neither existence before rotation nor canonical
//!    funding; the maker must be current at first canonical funding under the final P7 gate.
//!
//! THE FREEZE (`trading_v1::PreparedTreasuryOffer::signing_payload`). The signature is a
//! `Domain::Transaction` hybrid signature (Ed448 and FN-DSA, both required) of the Treasury wallet
//! over the ENCODED FREEZE BODY and nothing else: `[NATIVE_NAMESPACE, "treasury-freeze", 1,
//! [network, Genesis, fingerprint], creation height, creation block, creation state root,
//! TreasuryID, generation, destination address, TradeID, ContractHash, encoded offer body, wallet
//! descriptor]`. It does not cover the maker's offer signature, any funding hash lock, any Bitcoin
//! transaction, script, key or address: the offer's Bitcoin terms are two INTEGER fields (satoshis
//! and a network code, 1..=3 only, never mainnet). The wallet receives a freeze PROPOSAL (the exact
//! unsigned body as the host prepared it, plus the maker's signed offer), verifies the maker's
//! signature, prepares the same body again through the PUBLIC `trading_v1::prepare_treasury_offer`
//! against its own verified head and requires byte equality, mirrors every creation rule before
//! signing (`examine_freeze`), and verifies the result through `FrozenTreasuryOffer::decode` and
//! `trading_v1::verify_frozen_treasury_offer_at_creation`. The signed bytes are exactly the consensus
//! `FrozenTreasuryOffer` encoding (`attach_authorization`'s output).
//!
//! This module has no Bitcoin type and no Bitcoin code path: it never builds, parses or signs a
//! Bitcoin transaction or PSBT and never verifies Bitcoin evidence ("Bitcoin settlement not verified
//! by this wallet"). BTC custody stays external and under the Architect's sole control.
use super::{payment, select};
use crate::{
    authorize::{SignedOperation, SignerIdentity},
    capability::KindSigner,
    context::{ChainView, is_treasury_address, require_reserve_backing, treasury_authority},
    outbox::{OutboxRecord, Settlement, resource_key},
    plan::{
        Description, OperationHandler, OperationKind, OperationPlan, OperationRequest, PlanObject,
        RequiredSigner, Requirement, RequirementStatus, Slot, TreasuryFreezeOfferRequest,
        TreasuryRotateRequest, Validity,
    },
    profile::{self, TreasuryRole},
    refusal::Refusal,
    review::{
        AckKind, AddressLabel, Condition, Destination, DestinationRole, Effect, Fee, FeePayer,
        FeeRule, InputLine, Party, PartyRole, ReviewDraft, Severity, Timing, Warning,
    },
    units,
};
use minicbor::{Decoder, Encoder};
use mutiny_consensus_v8::{
    Hash,
    anchors::FinalizedAnchor,
    domain_hash,
    native_units_v1::MINIMUM_TRADE_FEE_STRIKES,
    trading_v1::{
        self, Action, Approval as TradeApproval, CandidatePolicy, Context as TradeContext,
        FrozenTreasuryOffer, MAX_NATIVE_BYTES, MAX_NATIVE_RECORD, Meta, NATIVE_NAMESPACE,
        NativeError, NativeLockKind, NativeOperation, NativeRecord, OfferBody, OfferTerms,
        Operation, SignedOffer, Strikes, TreasuryDestination, TreasuryOfferRequest,
        descriptor_hash, native_input_id, record_key, single_fill_key, treasury_address_id,
        treasury_generation_id,
    },
    transactions::{Coin, EXPIRY_HORIZON, MATURITY, OutPoint, Output},
    wallet_authority_v1::address_key,
};
use mutiny_crypto_v2::{HybridSignature, PublicKey, Role};
use std::{collections::BTreeSet, fmt};

/// Layout version of the Treasury plan objects.
pub const SCHEMA: u16 = 1;
/// Label of the one object of a rotation plan (the unsigned native trading operation).
pub const ROTATE_LABEL: &str = "treasury-rotate";
/// Label of the one object of a freeze plan (the freeze body: exactly the bytes that are signed).
pub const FREEZE_LABEL: &str = "treasury-freeze";
/// `resource_key` namespace of a Treasury generation being rotated away (one pending rotation per
/// Treasury and generation).
pub const ROTATION_NAMESPACE: &str = "treasury-rotation";
/// `resource_key` namespace of an offer being frozen (one pending freeze per offer).
pub const FREEZE_NAMESPACE: &str = "treasury-freeze";
/// Tag of the freeze PROPOSAL container `[tag, freeze body, maker offer]`.
pub const PROPOSAL_TAG: &[u8] = b"MUTINY-BUILD8-WALLET-TREASURY-FREEZE-PROPOSAL-V1";
/// Domain of a freeze's identifier: a hash of the freeze body (the signature is randomized, the
/// body is what the authorization means).
pub const FREEZE_ID_DOMAIN: &[u8] = b"MUTINY-BUILD8-WALLET-TREASURY-FREEZE-ID-V1";
/// The trading fee floor in STRIKES (`native_units_v1::MINIMUM_TRADE_FEE_STRIKES`).
pub const TRADE_FEE_FLOOR: u64 = MINIMUM_TRADE_FEE_STRIKES;
/// Most inputs of one trading operation (`trading_v1::MAX_INPUTS`).
pub const MAX_TRADE_INPUTS: usize = trading_v1::MAX_INPUTS;
/// The Bitcoin network codes a Treasury offer may name (`validate_treasury_creation`): 1 testnet,
/// 2 signet, 3 regtest. Code 0 (mainnet) is never accepted. Integer data only.
pub const TREASURY_BITCOIN_NETWORKS: [u8; 3] = [1, 2, 3];

/// `INVALID_REQUEST` reason: no trading Treasury of that identifier in the verified state.
pub const REASON_NO_TRADING_TREASURY: &str =
    "the verified state holds no trading Treasury of that identifier on this chain";
/// `INVALID_REQUEST` reason: the TreasuryID was not named and several match.
pub const REASON_SEVERAL_TREASURIES: &str =
    "this wallet controls the active destination of several trading Treasuries: name one";
/// `TREASURY_DESTINATION_UNRESOLVED` reason (since phase 8; before, `INVALID_REQUEST`): the new
/// address does not resolve to the new descriptor.
pub const REASON_NEW_NOT_RESOLVED: &str = "the new wallet authority generation must already exist: the verified wallet book does not resolve the new address to the new descriptor";
/// `TREASURY_DESTINATION_UNRESOLVED` reason (since phase 8): the new address is not the new
/// descriptor's own address.
pub const REASON_NEW_ADDRESS_MISMATCH: &str =
    "the new destination address is not the address of the new descriptor";
/// The text of `TREASURY_ADDRESS_USED` (since phase 8; before, an `INVALID_REQUEST` reason): the
/// new address was a destination of this Treasury before.
pub const REASON_ADDRESS_USED: &str =
    "a destination address serves one generation only: this one was used by this Treasury before";
/// `TREASURY_GENERATION` reason (since phase 8): the operation names a generation that is not
/// the active one.
pub const REASON_GENERATION_NOT_ACTIVE: &str =
    "the operation names a Treasury generation or address that is not the active one";
/// `TREASURY_GENERATION` reason (since phase 8): the new generation is not the active
/// generation plus one.
pub const REASON_GENERATION_NOT_NEXT: &str =
    "the new generation must be exactly the active generation plus one";
/// `INVALID_REQUEST` reason: an input is not a coin of the current destination.
pub const REASON_NOT_PAYER_COIN: &str =
    "an input is not a coin of the current Treasury destination";
/// `TREASURY_OFFER_TERMS` reason (since phase 8): a Treasury offer names Bitcoin mainnet.
pub const REASON_BITCOIN_MAINNET: &str =
    "a Treasury offer may name only Bitcoin network codes 1 to 3 (never 0, mainnet)";
/// `TREASURY_OFFER_TERMS` reason (since phase 8): the offer terms are not positive hash-linked
/// terms.
pub const REASON_FREEZE_TERMS: &str =
    "a Treasury offer must be a hash-linked offer with a positive amount and positive satoshis";
/// `TREASURY_OFFER_TERMS` reason (since phase 8): the offer's window or side does not fit a
/// freeze at this head.
pub const REASON_FREEZE_OFFER_WINDOW: &str = "a frozen Treasury offer must open at the creation block, close after it within 10,080 blocks, and have the maker on the recipient side";
/// `TREASURY_OFFER_TERMS` reason (since phase 8): TradeID or ContractHash is zero.
pub const REASON_FREEZE_COMMITMENTS: &str =
    "a frozen Treasury offer needs a non-zero TradeID and ContractHash";
/// `TREASURY_GENERATION` reason (since phase 8): the named generation is not the active one at
/// the creation head.
pub const REASON_FREEZE_GENERATION: &str = "a freeze must name the Treasury generation, and its address, that is active at the creation head";
/// `MALFORMED` reason: consensus prepares a different body from the same request at this head.
pub const REASON_FREEZE_DIFFERS: &str =
    "consensus prepares a different freeze body from this request at this head";
/// `MALFORMED` reason: not a freeze proposal container.
pub const REASON_PROPOSAL: &str = "not a canonical Treasury freeze proposal";

const FINALITY: &str = "final only when a certified block that includes it is part of this wallet's verified chain and this host's own replay-derived index confirms its inclusion. A queued record is stored locally only; authenticated submission or peer acknowledgement is not confirmation. Inclusion in a proposed, uncertified block is not finality either.";
const NO_BITCOIN: &str = "It does not touch Bitcoin custody: no Bitcoin key, address, script or transaction is created, parsed, signed or verified by this wallet.";
/// An operation this close to expiry gets a caution.
const EXPIRES_SOON_BLOCKS: u64 = 3;

// ---------------------------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------------------------

pub(crate) struct TreasuryHandler {
    kind: OperationKind,
}

static ROTATE: TreasuryHandler = TreasuryHandler {
    kind: OperationKind::TreasuryRotate,
};
static FREEZE: TreasuryHandler = TreasuryHandler {
    kind: OperationKind::TreasuryFreezeOffer,
};

/// The handler for `kind`: the Treasury destination rotation and the offer-freeze authorization.
pub(crate) fn handler(kind: OperationKind) -> Option<&'static dyn OperationHandler> {
    match kind {
        OperationKind::TreasuryRotate => Some(&ROTATE),
        OperationKind::TreasuryFreezeOffer => Some(&FREEZE),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------
// Trading Treasuries in the verified state (read-only)
// ---------------------------------------------------------------------------------------------

/// One trading Treasury of the verified state and its ACTIVE destination (its head record).
#[derive(Clone, PartialEq, Eq)]
pub struct TradingTreasury {
    /// The 32-byte TreasuryID (the identifier of its head record, `trading_v1` tag 3).
    pub id: Hash,
    /// The active destination generation.
    pub generation: u64,
    /// The active destination address.
    pub address: Hash,
    /// `trading_v1::descriptor_hash` of the descriptor recorded for that generation.
    pub descriptor_hash: Hash,
    /// The inclusion height from which that generation is active (0 for a Genesis generation).
    pub effective_height: u64,
}

impl TradingTreasury {
    fn of(id: Hash, destination: &TreasuryDestination) -> Self {
        Self {
            id,
            generation: destination.generation,
            address: destination.address,
            descriptor_hash: descriptor_hash(&destination.descriptor),
            effective_height: destination.effective_height,
        }
    }
}

impl fmt::Debug for TradingTreasury {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TradingTreasury")
            .field("id", &units::short_hex(&self.id))
            .field("generation", &self.generation)
            .field("address", &units::short_hex(&self.address))
            .field("effective_height", &self.effective_height)
            .finish()
    }
}

fn trade_context(view: &ChainView<'_>) -> TradeContext {
    let context = view.context();
    TradeContext {
        network: context.network,
        genesis: context.genesis,
        fingerprint: context.fingerprint,
    }
}

/// Every trading Treasury of the verified state (the tag-3 head records of this chain), by
/// TreasuryID. Read-only; a record that does not decode or sits under the wrong key is skipped
/// (consensus refuses such a state anyway).
pub fn trading_treasuries(view: &ChainView<'_>) -> Vec<TradingTreasury> {
    let context = trade_context(view);
    let mut out = Vec::new();
    for (key, raw) in &view.state().protocol_records {
        if !trading_v1::is_candidate_record(raw) {
            continue;
        }
        let Ok((
            id,
            NativeRecord::Treasury {
                context: found,
                current,
            },
        )) = NativeRecord::decode(raw)
        else {
            continue;
        };
        if found != context || record_key(3, id) != *key {
            continue;
        }
        out.push(TradingTreasury::of(id, &current));
    }
    out.sort_by_key(|treasury| treasury.id);
    out
}

/// The ACTIVE destination of trading Treasury `treasury` (`trading_v1::treasury_current`).
pub fn active_destination(
    view: &ChainView<'_>,
    treasury: &Hash,
) -> Result<TreasuryDestination, Refusal> {
    trading_v1::treasury_current(view.state(), &trade_context(view), *treasury).map_err(|error| {
        match error {
            NativeError::Missing => Refusal::InvalidRequest(REASON_NO_TRADING_TREASURY),
            _ => Refusal::Malformed("the trading Treasury records do not decode for this chain"),
        }
    })
}

/// The trading Treasuries whose ACTIVE destination `identity`'s descriptor controls in the verified
/// wallet book.
pub fn controlled_treasuries(view: &ChainView<'_>, identity: &SignerIdentity) -> Vec<Hash> {
    let wallets = &view.state().wallets;
    trading_treasuries(view)
        .into_iter()
        .filter(|treasury| {
            wallets
                .authorize(treasury.address, identity.descriptor())
                .is_ok()
        })
        .map(|treasury| treasury.id)
        .collect()
}

/// The trading Treasury a rotation request is for: the one named, or the only one whose active
/// destination this wallet controls.
fn chosen_treasury(
    request: &TreasuryRotateRequest,
    view: &ChainView<'_>,
    signer: &SignerIdentity,
) -> Result<Hash, Refusal> {
    if let Some(treasury) = request.treasury {
        if treasury != view.treasury().ok_or(Refusal::StaleAuthority)?.authority() {
            return Err(Refusal::InvalidRequest(
                "only the canonical Genesis Treasury is authorized",
            ));
        }
        return Ok(treasury);
    }
    match controlled_treasuries(view, signer).as_slice() {
        [] => Err(Refusal::NotRequiredSigner(Slot::Approval(0))),
        [one] if *one == view.treasury().ok_or(Refusal::StaleAuthority)?.authority() => Ok(*one),
        _ => Err(Refusal::InvalidRequest(REASON_SEVERAL_TREASURIES)),
    }
}

/// The reservation of one pending rotation of `treasury` away from `generation`.
pub fn rotation_resource(treasury: &Hash, generation: u64) -> OutPoint {
    resource_key(
        ROTATION_NAMESPACE,
        &treasury_generation_id(*treasury, generation),
    )
}

/// The reservation of one pending freeze of offer `offer`.
pub fn freeze_resource(offer: &Hash) -> OutPoint {
    resource_key(FREEZE_NAMESPACE, offer)
}

// ---------------------------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------------------------

/// A wallet-owner descriptor (the rule of consensus `validate_descriptor`: at most 2,048 bytes, a
/// `WalletOwner` key) and its generation.
fn owner_descriptor(raw: &[u8]) -> Result<(PublicKey, u64), Refusal> {
    if raw.len() > 2048 {
        return Err(Refusal::InvalidDescriptor);
    }
    let (public, generation) =
        PublicKey::decode_descriptor(raw).map_err(|_| Refusal::InvalidDescriptor)?;
    if public.role != Role::WalletOwner || generation == 0 {
        return Err(Refusal::InvalidDescriptor);
    }
    Ok((public, generation))
}

/// The authority named by a wallet-book address record `[1, 31, authority, descriptor]`.
fn record_authority(raw: &[u8]) -> Option<Hash> {
    let mut d = Decoder::new(raw);
    if d.array().ok()? != Some(4) || d.u8().ok()? != 1 || d.u8().ok()? != 31 {
        return None;
    }
    d.bytes().ok()?.try_into().ok()
}

/// The descriptor that currently authorizes `address` in the verified wallet book: the current
/// descriptor of the authority the address belongs to or, for an address no authority registered,
/// `direct` when that generation-one descriptor derives it (consensus' direct ownership).
fn current_descriptor_of(view: &ChainView<'_>, address: &Hash, direct: &[u8]) -> Option<Vec<u8>> {
    let wallets = &view.state().wallets;
    let found = if let Some(current) = wallets.current(*address) {
        Some(current.to_vec())
    } else if let Ok(records) = wallets.records()
        && let Some(raw) = records.get(&address_key(*address))
        && let Some(authority) = record_authority(raw)
    {
        wallets.current(authority).map(<[u8]>::to_vec)
    } else {
        Some(direct.to_vec())
    };
    found.filter(|descriptor| wallets.authorize(*address, descriptor).is_ok())
}

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

/// The candidate environment name of a Bitcoin network code (integer data from the offer).
pub fn bitcoin_network_name(code: u8) -> &'static str {
    match code {
        0 => "mainnet (never accepted for a Treasury offer)",
        1 => "testnet",
        2 => "signet",
        3 => "regtest",
        _ => "unknown",
    }
}

/// A short machine-readable reason for a consensus rejection the wallet's own mirror did not
/// predict (a mirror gap, or a view that is not the verified parent).
fn consensus_verdict(error: &NativeError) -> &'static str {
    match error {
        NativeError::Envelope(_) => "consensus: signed window or canonical reference failed",
        NativeError::Stale(_) => "consensus: committed state changed; review again",
        NativeError::Codec => "consensus: the bytes do not decode",
        NativeError::Context => "consensus: wrong chain context, generation or parent state",
        NativeError::Gate | NativeError::UnitUnresolved => "consensus: trading is not enabled",
        NativeError::Bounds => "consensus: out of bounds",
        NativeError::Authority => {
            "consensus: an approval, a signature or an input owner is not authorized"
        }
        NativeError::Immature => "consensus: an input is immature",
        NativeError::Missing => "consensus: an input or a Treasury record is missing",
        NativeError::Duplicate => "consensus: the operation or one of its records already exists",
        NativeError::Conflict => "consensus: conflicting Treasury generation or records",
        NativeError::Conservation => "consensus: inputs do not equal change and fee",
        NativeError::Overflow => "consensus: arithmetic overflow",
        NativeError::Fee => "consensus: the fee is below the minimum",
        NativeError::Time => "consensus: outside the time window",
        NativeError::Record => "consensus: the resulting state is invalid",
        NativeError::FiatRecoveryUnspecified => "consensus: fiat recovery is unspecified",
        NativeError::LicenseLocked => "consensus: License locked",
        NativeError::Candidate(_) => "consensus: the encoding or a signature is invalid",
    }
}

// ---------------------------------------------------------------------------------------------
// Rotation: codec
// ---------------------------------------------------------------------------------------------

fn decode_wire(raw: &[u8]) -> Result<NativeOperation, Refusal> {
    NativeOperation::decode(raw)
        .map_err(|_| Refusal::Malformed("not a canonical native trading operation"))
}

fn encode_wire(wire: &NativeOperation) -> Result<Vec<u8>, Refusal> {
    wire.encode().map_err(|error| match error {
        NativeError::Bounds | NativeError::Candidate(trading_v1::Error::Bounds) => {
            Refusal::SizeLimit {
                limit: MAX_NATIVE_BYTES,
            }
        }
        NativeError::Context => {
            Refusal::Malformed("the input list does not match the signed input identifiers")
        }
        NativeError::Candidate(trading_v1::Error::Authority)
        | NativeError::Candidate(trading_v1::Error::Codec) => Refusal::InvalidDescriptor,
        _ => Refusal::Malformed("the native trading operation does not encode"),
    })
}

/// The unsigned form: no approval (a rotation never carries an offer proof).
fn stripped(wire: &NativeOperation) -> NativeOperation {
    let mut copy = wire.clone();
    copy.operation.approvals.clear();
    copy
}

fn is_rotation(wire: &NativeOperation) -> bool {
    matches!(wire.operation.action, Action::TreasuryRotate { .. })
}

/// The fields of a rotation body.
struct Rotation<'a> {
    treasury: Hash,
    current_generation: u64,
    current_address: Hash,
    current_descriptor: Hash,
    new_generation: u64,
    new_address: Hash,
    new_descriptor: &'a [u8],
    change: u64,
}

fn rotation_of(op: &Operation) -> Result<Rotation<'_>, Refusal> {
    let Action::TreasuryRotate {
        treasury,
        current_generation,
        current_address,
        current_descriptor,
        new_generation,
        new_address,
        new_descriptor,
        change,
    } = &op.action
    else {
        return Err(Refusal::UnknownOperation);
    };
    Ok(Rotation {
        treasury: *treasury,
        current_generation: *current_generation,
        current_address: *current_address,
        current_descriptor: *current_descriptor,
        new_generation: *new_generation,
        new_address: *new_address,
        new_descriptor,
        change: change.0,
    })
}

fn set_fee_and_change(op: &mut Operation, fee: u64, change: u64) {
    op.meta.fee = Strikes(fee);
    if let Action::TreasuryRotate { change: field, .. } = &mut op.action {
        *field = Strikes(change);
    }
}

fn minimum_fee(size: u64) -> u64 {
    size.max(MINIMUM_TRADE_FEE_STRIKES)
}

/// Encoded length of the COMPLETE rotation: its one approval present (a zero-signature placeholder
/// with `signing_descriptor` when it is missing; hybrid signatures have a fixed width).
fn complete_len(wire: &NativeOperation, signing_descriptor: &[u8]) -> Result<u64, Refusal> {
    let mut full = wire.clone();
    full.operation
        .approvals
        .retain(|approval| approval.slot == 0);
    if full.operation.approvals.is_empty() {
        full.operation.approvals.push(TradeApproval {
            slot: 0,
            descriptor: signing_descriptor.to_vec(),
            signature: payment::zero_signature(),
        });
    }
    Ok(encode_wire(&full)?.len() as u64)
}

fn operation_id(op: &Operation) -> Result<Hash, Refusal> {
    op.id()
        .map_err(|_| Refusal::Malformed("operation identity"))
}

// ---------------------------------------------------------------------------------------------
// Rotation: funding (fee and change from the CURRENT destination's coins)
// ---------------------------------------------------------------------------------------------

struct Funding {
    coins: Vec<(OutPoint, u64)>,
    count: usize,
    total: u128,
}

fn eligible(view: &ChainView<'_>, point: &OutPoint, coin: &Coin, next: u64) -> bool {
    !view.reserved().contains(point)
        && coin.created_height < next
        && !(coin.coinbase && next - coin.created_height < MATURITY)
}

/// Coins owned by exactly `payer` (consensus `debit` compares the owner address), not reserved,
/// created before the next block, mature. At most `MAX_TRADE_INPUTS` are kept, largest first with a
/// stable tie-break by outpoint; the count and total cover all of them.
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
    Short { fee: u64 },
}

/// The fee is a fixed point of `max(240, complete size)`, only ever rising to the largest size seen;
/// the change is everything else.
fn fit_fee(
    wire: &mut NativeOperation,
    total: u64,
    signing_descriptor: &[u8],
) -> Result<Fit, Refusal> {
    let mut fee = 0u64;
    for _ in 0..16 {
        let change = total.checked_sub(fee);
        set_fee_and_change(&mut wire.operation, fee, change.unwrap_or(0));
        let minimum = minimum_fee(complete_len(wire, signing_descriptor)?);
        if fee >= minimum && change.is_some() {
            return Ok(Fit::Done);
        }
        if total < minimum {
            return Ok(Fit::Short { fee: minimum });
        }
        fee = minimum;
    }
    Err(Refusal::Malformed("the fee did not converge"))
}

/// Inputs, fee and change for `template`: the fewest largest coins of the current destination whose
/// total covers the fee, ordered by native input identifier.
fn fund(
    mut wire: NativeOperation,
    view: &ChainView<'_>,
    signing_descriptor: &[u8],
) -> Result<NativeOperation, Refusal> {
    // Consensus debits the coins of `Operation::fee_payer()`: the current Treasury address.
    let payer = wire.operation.fee_payer();
    let funding = funding_coins(view, &payer, signing_descriptor)?;
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
        if total < MINIMUM_TRADE_FEE_STRIKES && !last {
            continue;
        }
        let mut chosen: Vec<OutPoint> = funding.coins[..count]
            .iter()
            .map(|(point, _)| point.clone())
            .collect();
        chosen.sort_by_key(native_input_id);
        wire.operation.meta.inputs = chosen.iter().map(native_input_id).collect();
        wire.inputs = chosen;
        match fit_fee(&mut wire, total, signing_descriptor)? {
            Fit::Done => return Ok(wire),
            Fit::Short { fee } => needed = Some(fee),
        }
    }
    if funding.count > funding.coins.len() {
        return Err(Refusal::TooManyInputs {
            limit: MAX_TRADE_INPUTS,
        });
    }
    Err(Refusal::InsufficientFunds {
        available: u64::try_from(funding.total).unwrap_or(u64::MAX),
        requested: needed.unwrap_or(MINIMUM_TRADE_FEE_STRIKES),
    })
}

// ---------------------------------------------------------------------------------------------
// Rotation: planning
// ---------------------------------------------------------------------------------------------

fn check_validity_blocks(blocks: u64) -> Result<(), Refusal> {
    if blocks == 0 || blocks > EXPIRY_HORIZON {
        return Err(Refusal::InvalidValidity);
    }
    Ok(())
}

fn plan_rotate(
    request: &TreasuryRotateRequest,
    view: &ChainView<'_>,
    signer: &SignerIdentity,
) -> Result<OperationPlan, Refusal> {
    // An ordinary identity never reaches anything else.
    profile::require_treasury_operation(view, signer)?;
    check_validity_blocks(request.validity_blocks)?;
    signer.check_current(view)?;
    select::require_profile_for_treasury(view, signer)?;
    let next = view.next_height()?;
    let treasury = chosen_treasury(request, view, signer)?;
    if !request.new_key_restore_verified
        || request.restore_authority != Some(treasury)
        || request.restore_verified_fingerprint
            != Some(descriptor_hash(request.new_descriptor.as_slice()))
    {
        return Err(Refusal::RestoreNotVerified(
            "R2 requires a clean host backup rehearsal of the exact current Treasury authority descriptor",
        ));
    }
    let active = active_destination(view, &treasury)?;
    // The declared role, for exactly this (existing) trading Treasury.
    profile::require_role(signer, TreasuryRole::Destination, Some(&treasury))?;
    let wallets = &view.state().wallets;
    // Only the key that controls the active destination authorizes the rotation (slot 0).
    wallets
        .authorize(active.address, signer.descriptor())
        .map_err(|_| Refusal::NotRequiredSigner(Slot::Approval(0)))?;
    if active.effective_height >= next {
        return Err(Refusal::NotYetEligible {
            what: "Rotating this Treasury destination",
            height: active.effective_height.saturating_add(1),
        });
    }
    let new_descriptor = request.new_descriptor.as_slice();
    let (new_public, new_key_generation) = owner_descriptor(new_descriptor)?;
    let new_address = new_public
        .address_id(new_key_generation)
        .map_err(|_| Refusal::InvalidDescriptor)?;
    if new_descriptor != signer.descriptor() || wallets.authorize(treasury, new_descriptor).is_err()
    {
        return Err(Refusal::TreasuryDestinationUnresolved(
            "destination must be the current canonical Treasury authority generation",
        ));
    }
    // The new wallet authority generation must already exist.
    wallets
        .authorize(new_address, new_descriptor)
        .map_err(|_| Refusal::TreasuryDestinationUnresolved(REASON_NEW_NOT_RESOLVED))?;
    if address_used(view, &treasury, &new_address) {
        return Err(Refusal::TreasuryAddressUsed);
    }
    let new_generation = active.generation.checked_add(1).ok_or(Refusal::Overflow)?;
    if view
        .reserved()
        .contains(&rotation_resource(&treasury, active.generation))
    {
        return Err(Refusal::ReservedInput);
    }
    let expiry = next
        .checked_add(request.validity_blocks)
        .ok_or(Refusal::Overflow)?;
    let template = NativeOperation {
        operation: Operation {
            meta: Meta {
                context: trade_context(view),
                // A Treasury rotation is not part of a trade: no TradeID or ContractHash.
                trade: [0; 32],
                contract: [0; 32],
                generation: 1,
                envelope: crate::offers::envelope(
                    view,
                    next,
                    expiry,
                    vec![
                        mutiny_consensus_v8::op_envelope_v1::treasury_head_facts(
                            view.state(),
                            &trade_context(view),
                            treasury,
                        )
                        .map_err(|_| Refusal::StaleAuthority)?,
                    ],
                )?,
                fee: Strikes(0),
                inputs: Vec::new(),
            },
            action: Action::TreasuryRotate {
                treasury,
                current_generation: active.generation,
                current_address: active.address,
                current_descriptor: descriptor_hash(signer.descriptor()),
                new_generation,
                new_address,
                new_descriptor: new_descriptor.to_vec(),
                change: Strikes(0),
            },
            approvals: Vec::new(),
            offer_proof: None,
        },
        inputs: Vec::new(),
    };
    let wire = fund(template, view, signer.descriptor())?;
    assemble_rotate(&wire, view, signer)
}

fn address_used(view: &ChainView<'_>, treasury: &Hash, address: &Hash) -> bool {
    view.state()
        .protocol_records
        .contains_key(&record_key(6, treasury_address_id(*treasury, *address)))
}

/// Who must sign a rotation, as seen from `me`: slot 0, the current destination.
fn rotate_requirements(
    wire: &NativeOperation,
    view: &ChainView<'_>,
    me: &SignerIdentity,
) -> Result<Vec<Requirement>, Refusal> {
    let rotation = rotation_of(&wire.operation)?;
    let mine = view
        .state()
        .wallets
        .authorize(rotation.current_address, me.descriptor())
        .is_ok()
        && descriptor_hash(me.descriptor()) == rotation.current_descriptor;
    if !mine {
        return Err(Refusal::NotRequiredSigner(Slot::Approval(0)));
    }
    Ok(vec![Requirement {
        slot: Slot::Approval(0),
        signer: RequiredSigner::Wallet(rotation.current_address),
        status: RequirementStatus::ThisWallet,
    }])
}

/// Everything a rotation reserves: its coins and its Treasury generation (sorted, de-duplicated).
fn rotate_reserved(wire: &NativeOperation) -> Result<Vec<OutPoint>, Refusal> {
    let rotation = rotation_of(&wire.operation)?;
    let mut reserved = wire.inputs.clone();
    reserved.push(rotation_resource(
        &rotation.treasury,
        rotation.current_generation,
    ));
    reserved.sort();
    reserved.dedup();
    Ok(reserved)
}

fn assemble_rotate(
    wire: &NativeOperation,
    view: &ChainView<'_>,
    signer: &SignerIdentity,
) -> Result<OperationPlan, Refusal> {
    let unsigned = stripped(wire);
    let bytes = encode_wire(&unsigned)?;
    let requirements = rotate_requirements(&unsigned, view, signer)?;
    let meta = &unsigned.operation.meta;
    let plan = OperationPlan::assemble(
        OperationKind::TreasuryRotate,
        SCHEMA,
        signer.clone(),
        vec![
            PlanObject::new(ROTATE_LABEL, bytes),
            rotate_restore_evidence(&unsigned.operation)?,
        ],
        requirements,
        rotate_reserved(&unsigned)?,
        Validity {
            created: meta.envelope.first_height,
            expiry: meta.envelope.last_height,
            valid_only_at: None,
            bound_to_parent: false,
        },
        view,
    );
    ROTATE.validate(&plan, view)?;
    Ok(plan)
}

// ---------------------------------------------------------------------------------------------
// Rotation: the consensus mirror
// ---------------------------------------------------------------------------------------------

struct InputFact {
    point: OutPoint,
    coin: Coin,
    mine: bool,
}

/// Everything a rotation review and the checks need, derived from the bytes and the CURRENT view.
struct RotateFacts {
    wire: NativeOperation,
    active: TreasuryDestination,
    head: u64,
    size: u64,
    minimum: u64,
    inputs: Vec<InputFact>,
    total_in: u128,
    /// The approval of slot 0 is present (and verified).
    provided: bool,
    /// `me` controls the current destination with the descriptor the body commits to.
    mine: bool,
    /// The fee coins are Genesis Treasury coins (dividend reserve backing).
    treasury_funds: bool,
    /// (reserve, backing after this operation) when the fee coins are Treasury coins.
    reserve: Option<(u64, u128)>,
    /// Open hash locks whose recipient is the current destination: (count, total atoms).
    open_locks: (usize, u128),
    /// Generation of the new descriptor's key.
    new_key_generation: u64,
}

/// Every consensus check of `apply_one` for a `TreasuryRotate` that does not need the signature,
/// against the CURRENT view, in the order consensus applies them. `check_reserved` adds the wallet's
/// own rule that nothing reserved by another pending operation is spent.
fn examine_rotate(
    wire: &NativeOperation,
    view: &ChainView<'_>,
    me: Option<&SignerIdentity>,
    check_reserved: bool,
) -> Result<RotateFacts, Refusal> {
    let op = &wire.operation;
    let meta = &op.meta;
    let rotation = rotation_of(op)?;
    let state = view.state();
    let wallets = &state.wallets;
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
    if meta.envelope.preconditions
        != vec![
            mutiny_consensus_v8::op_envelope_v1::treasury_head_facts(
                state,
                &meta.context,
                rotation.treasury,
            )
            .map_err(|_| Refusal::StaleAuthority)?,
        ]
    {
        return Err(Refusal::StaleAuthority);
    }
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
    if meta
        .envelope
        .last_height
        .checked_sub(meta.envelope.first_height)
        .is_none_or(|span| span > EXPIRY_HORIZON)
    {
        return Err(Refusal::InvalidValidity);
    }
    // The active destination: what the body must name, and whose key signs.
    let active = active_destination(view, &rotation.treasury)?;
    let approval = op.approvals.iter().find(|approval| approval.slot == 0);
    let signing_descriptor = match (approval, me) {
        (Some(approval), _) => approval.descriptor.clone(),
        (None, Some(me)) if descriptor_hash(me.descriptor()) == rotation.current_descriptor => {
            me.descriptor().to_vec()
        }
        _ => current_descriptor_of(view, &rotation.current_address, &active.descriptor)
            .unwrap_or_else(|| active.descriptor.clone()),
    };
    let size = complete_len(wire, &signing_descriptor)?;
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
    if op.approvals.iter().any(|approval| approval.slot != 0) {
        return Err(Refusal::CounterpartyApprovalInvalid);
    }
    if op.offer_proof.is_some() {
        return Err(Refusal::OfferProofInvalid);
    }
    if active.effective_height > next {
        return Err(Refusal::NotYetEligible {
            what: "Rotating this Treasury destination",
            height: active.effective_height,
        });
    }
    if active.generation != rotation.current_generation
        || active.address != rotation.current_address
    {
        return Err(Refusal::TreasuryGeneration(REASON_GENERATION_NOT_ACTIVE));
    }
    if rotation.current_generation.checked_add(1) != Some(rotation.new_generation) {
        return Err(Refusal::TreasuryGeneration(REASON_GENERATION_NOT_NEXT));
    }
    // Slot 0: the CURRENT authority of the current address, committed by its descriptor hash.
    if approval.is_some() {
        trading_v1::verify_approval(wallets, op, 0)
            .map_err(|_| Refusal::CounterpartyApprovalInvalid)?;
    } else {
        let current = current_descriptor_of(view, &rotation.current_address, &active.descriptor)
            .ok_or(Refusal::StaleAuthority)?;
        if descriptor_hash(&current) != rotation.current_descriptor {
            return Err(Refusal::StaleAuthority);
        }
    }
    let mine = me.is_some_and(|me| {
        wallets
            .authorize(rotation.current_address, me.descriptor())
            .is_ok()
            && descriptor_hash(me.descriptor()) == rotation.current_descriptor
    });
    if rotation.treasury != view.treasury().ok_or(Refusal::StaleAuthority)?.authority()
        || rotation.new_descriptor != signing_descriptor.as_slice()
        || wallets
            .authorize(rotation.treasury, rotation.new_descriptor)
            .is_err()
    {
        return Err(Refusal::TreasuryDestinationUnresolved(
            "destination must be the current canonical Treasury authority generation",
        ));
    }
    // The new destination: already resolvable, its descriptor's own address, used once.
    wallets
        .authorize(rotation.new_address, rotation.new_descriptor)
        .map_err(|_| Refusal::TreasuryDestinationUnresolved(REASON_NEW_NOT_RESOLVED))?;
    let (new_public, new_key_generation) = owner_descriptor(rotation.new_descriptor)?;
    if new_public.address_id(new_key_generation).ok() != Some(rotation.new_address) {
        return Err(Refusal::TreasuryDestinationUnresolved(
            REASON_NEW_ADDRESS_MISMATCH,
        ));
    }
    if active.effective_height >= next {
        return Err(Refusal::NotYetEligible {
            what: "Rotating this Treasury destination",
            height: active.effective_height.saturating_add(1),
        });
    }
    if address_used(view, &rotation.treasury, &rotation.new_address) {
        return Err(Refusal::TreasuryAddressUsed);
    }
    if state.protocol_records.contains_key(&record_key(
        5,
        treasury_generation_id(rotation.treasury, rotation.new_generation),
    )) {
        return Err(Refusal::TreasuryGeneration(REASON_GENERATION_NOT_NEXT));
    }
    // `debit`: coins of exactly the current address, created before H, mature, summing exactly to
    // change + fee.
    if wire.inputs.is_empty() {
        return Err(Refusal::InputUnavailable);
    }
    let mut total_in: u128 = 0;
    let mut inputs = Vec::with_capacity(wire.inputs.len());
    for point in &wire.inputs {
        let coin = state.coins.get(point).ok_or(Refusal::InputUnavailable)?;
        if wallets
            .authorize(coin.output.owner, &signing_descriptor)
            .is_err()
        {
            return Err(Refusal::InvalidRequest(REASON_NOT_PAYER_COIN));
        }
        if coin.created_height >= next || (coin.coinbase && next - coin.created_height < MATURITY) {
            return Err(Refusal::ImmatureInput);
        }
        if check_reserved && view.reserved().contains(point) {
            return Err(Refusal::ReservedInput);
        }
        total_in = total_in
            .checked_add(u128::from(coin.output.atoms))
            .ok_or(Refusal::Overflow)?;
        let input_mine = me.is_some_and(|me| {
            wallets
                .authorize(coin.output.owner, me.descriptor())
                .is_ok()
        });
        inputs.push(InputFact {
            point: point.clone(),
            coin: coin.clone(),
            mine: input_mine,
        });
    }
    if total_in != u128::from(rotation.change) + u128::from(meta.fee.0) {
        return Err(Refusal::Conservation);
    }
    if check_reserved
        && view.reserved().contains(&rotation_resource(
            &rotation.treasury,
            rotation.current_generation,
        ))
    {
        return Err(Refusal::ReservedInput);
    }
    // The dividend reserve stays backed after the block (Q15).
    let spent: BTreeSet<OutPoint> = wire.inputs.iter().cloned().collect();
    let created = if rotation.change > 0 {
        vec![Output {
            owner: rotation.current_address,
            atoms: rotation.change,
        }]
    } else {
        Vec::new()
    };
    require_reserve_backing(view, &spent, &created)?;
    let treasury = treasury_authority(view);
    let treasury_funds = inputs.iter().any(|input| {
        !input.coin.coinbase
            && treasury.as_ref().is_some_and(|authority| {
                is_treasury_address(view, authority, &input.coin.output.owner)
            })
    });
    let reserve = if treasury_funds {
        let authority = treasury.as_ref().ok_or(Refusal::DividendInactive)?;
        let mut backing: u128 = 0;
        for (point, coin) in &state.coins {
            if !coin.coinbase
                && !spent.contains(point)
                && is_treasury_address(view, authority, &coin.output.owner)
            {
                backing += u128::from(coin.output.atoms);
            }
        }
        for output in &created {
            if is_treasury_address(view, authority, &output.owner) {
                backing += u128::from(output.atoms);
            }
        }
        Some((state.dividends.reserved(), backing))
    } else {
        None
    };
    Ok(RotateFacts {
        wire: wire.clone(),
        active,
        head,
        size,
        minimum,
        inputs,
        total_in,
        provided: approval.is_some(),
        mine,
        treasury_funds,
        reserve,
        open_locks: open_locks_paying(view, &rotation.current_address),
        new_key_generation,
    })
}

/// Hash locks of the verified state whose recipient is `address`: (count, total atoms).
fn open_locks_paying(view: &ChainView<'_>, address: &Hash) -> (usize, u128) {
    let mut count = 0usize;
    let mut total: u128 = 0;
    for raw in view.state().protocol_records.values() {
        if !trading_v1::is_candidate_record(raw) {
            continue;
        }
        if let Ok((_, NativeRecord::Lock(lock))) = NativeRecord::decode(raw)
            && lock.recipient == *address
            && matches!(lock.kind, NativeLockKind::Hash { .. })
        {
            count += 1;
            total += u128::from(lock.amount.0);
        }
    }
    (count, total)
}

// ---------------------------------------------------------------------------------------------
// Rotation: review
// ---------------------------------------------------------------------------------------------

fn review_rotate(
    facts: &RotateFacts,
    view: &ChainView<'_>,
    me: &SignerIdentity,
) -> Result<ReviewDraft, Refusal> {
    let op = &facts.wire.operation;
    let meta = &op.meta;
    let rotation = rotation_of(op)?;
    let fee = meta.fee.0;
    let change = rotation.change;
    let current = rotation.current_address;
    let new = rotation.new_address;
    let payer_label = classify(view, me, &current);
    let payer_mine = payer_label == AddressLabel::ThisWallet;
    let new_label = classify(view, me, &new);
    let head = facts.head;
    let (cur_gen, new_gen) = (rotation.current_generation, rotation.new_generation);

    let status = if facts.provided {
        RequirementStatus::Provided
    } else if facts.mine {
        RequirementStatus::ThisWallet
    } else {
        RequirementStatus::Counterparty
    };
    let authorizations = vec![Requirement {
        slot: Slot::Approval(0),
        signer: RequiredSigner::Wallet(current),
        status,
    }];

    let parties = vec![Party {
        role: PartyRole::Treasury,
        address: current,
        label: payer_label,
    }];
    // The new destination carries the typed re-entry check unless it is this wallet's own address:
    // swapping it would send every later Treasury proceed elsewhere. No value moves to it here.
    let mut destinations = vec![Destination {
        role: DestinationRole::ProtocolPayout,
        address: new,
        label: new_label,
        atoms: 0,
    }];
    if payer_mine && change > 0 {
        destinations.push(Destination {
            role: DestinationRole::Change,
            address: current,
            label: payer_label,
            atoms: change,
        });
    }

    let locks = if facts.open_locks.0 == 0 {
        " No open hash lock pays it now.".to_string()
    } else {
        format!(
            " Open hash locks paying it now: {} holding {}.",
            facts.open_locks.0,
            units::format_mut_wide(facts.open_locks.1)
        )
    };
    let reserve_text = match facts.reserve {
        Some((reserved, backing)) => format!(
            "These coins back the dividend reserve of {}: after this fee the Treasury's backing is {} (checked). A block that leaves the reserve unbacked is invalid, so a fee below the reserve is refused.",
            units::format_mut(reserved),
            units::format_mut_wide(backing)
        ),
        None => "These coins are not dividend reserve backing.".to_string(),
    };
    let window = meta.envelope.last_height.saturating_sub(head);
    let conditions = vec![
        Condition::new(
            "Treasury",
            format!(
                "Trading Treasury {} (TreasuryID). Its destination history is generation-indexed: this rotation adds generation {new_gen} and makes it the active destination; generation {cur_gen} and every earlier one stay in the history.",
                hex::encode(rotation.treasury)
            ),
        ),
        Condition::new(
            "Generation",
            format!(
                "{cur_gen} to {new_gen}: exactly one more than the active generation (a skipped, repeated or stale generation is refused)."
            ),
        ),
        Condition::new(
            "Current destination",
            format!(
                "{} ({}), generation {cur_gen}, active since block {}.",
                crate::address_format::encode_for(&current, view),
                payer_label.text(),
                facts.active.effective_height
            ),
        ),
        Condition::new(
            "Current descriptor",
            format!(
                "Descriptor hash {}: the key that controls the current destination in the verified wallet book{}. Only that key can authorize this rotation (approval slot 0).",
                hex::encode(rotation.current_descriptor),
                if facts.mine {
                    "; it is this wallet's current key"
                } else {
                    ""
                }
            ),
        ),
        Condition::new(
            "New destination",
            format!(
                "{} ({}), generation {new_gen}; descriptor hash {}; key generation {}.",
                crate::address_format::encode_for(&new, view),
                new_label.text(),
                hex::encode(descriptor_hash(rotation.new_descriptor)),
                facts.new_key_generation
            ),
        ),
        Condition::new(
            "New destination precondition",
            "The new wallet authority generation must already exist: the verified wallet book resolves the new address to exactly this descriptor (checked at this head). The reviewed plan requires a host assertion of a clean backup rehearsal bound to this exact Treasury authority and descriptor. Consensus cannot verify that rehearsal.",
        ),
        Condition::new(
            "Address used once",
            format!(
                "A destination address serves one generation only: {} has never been a destination of this Treasury (checked). After inclusion neither {} nor {} can be named by a later rotation.",
                crate::address_format::encode_for(&new, view),
                crate::address_format::encode_for(&current, view),
                crate::address_format::encode_for(&new, view)
            ),
        ),
        Condition::new(
            "Effective height",
            format!(
                "The inclusion height: the rotation takes effect in the block that includes it, between block {} and block {}.",
                meta.envelope.first_height, meta.envelope.last_height
            ),
        ),
        Condition::new(
            "New offers",
            format!(
                "Treasury offers frozen from the inclusion block on must name generation {new_gen} and {}; a new freeze naming generation {cur_gen} is refused from then on.",
                crate::address_format::encode_for(&new, view)
            ),
        ),
        Condition::new(
            "Frozen offers",
            format!(
                "Native locks already finalized against generation {cur_gen} or earlier keep their exact signed destination {} and existing claim/refund rules. Claims use that wallet lineage's current signing authority; retiring its former key does not redirect the signed destination. An unfunded offer or freeze witness has no historical authority exception and must be reviewed and signed by the current maker before first canonical funding.{locks}",
                crate::address_format::encode_for(&current, view)
            ),
        ),
        Condition::new(
            "Bitcoin custody",
            format!("This changes MUT Treasury authority and destination ONLY. {NO_BITCOIN}"),
        ),
        Condition::new(
            "Fee coins",
            format!(
                "The fee and the change come from {} coin(s) of the current destination {} (consensus debits exactly that address); the change returns to it.",
                facts.inputs.len(),
                crate::address_format::encode_for(&current, view)
            ),
        ),
        Condition::new("Dividend reserve", reserve_text),
        Condition::new(
            "Unused trade fields",
            format!(
                "TradeID {}, ContractHash {}, trade generation {}: not used by a Treasury rotation.",
                hex::encode(meta.trade),
                hex::encode(meta.contract),
                meta.generation
            ),
        ),
        Condition::new(
            "Validity window",
            format!(
                "Valid only for blocks {} to {} ({window} blocks after the verified block; {}, approximate at the {} s target interval).",
                meta.envelope.first_height,
                meta.envelope.last_height,
                units::approx_blocks(window),
                units::TARGET_BLOCK_SECONDS
            ),
        ),
        Condition::new(
            "Inputs",
            format!(
                "All {} input coin(s) must still be unspent coins of the current destination when the rotation is included; a conflicting spend of any of them cancels it.",
                facts.inputs.len()
            ),
        ),
        Condition::new(
            "Fee rule",
            format!(
                "The fee must be at least the greater of {MINIMUM_TRADE_FEE_STRIKES} STRIKES and the encoded size of the complete signed operation (its one approval included): {} bytes, so {} atoms.",
                facts.size, facts.minimum
            ),
        ),
        Condition::new(
            "One pending rotation",
            format!(
                "This wallet keeps one pending rotation per Treasury generation: generation {cur_gen} of this Treasury stays reserved until this rotation settles or is forgotten."
            ),
        ),
        Condition::new(
            "Approvals still required",
            if facts.provided {
                "None: the approval is present and verified.".to_string()
            } else if facts.mine {
                "The approval of the current Treasury destination (slot 0, this wallet)."
                    .to_string()
            } else {
                "The approval of the current Treasury destination (slot 0, another wallet)."
                    .to_string()
            },
        ),
        Condition::new("Finality", format!("The rotation is {FINALITY}")),
    ];

    let mut effects = vec![
        Effect::new(
            format!(
                "From inclusion the active destination of Treasury {} is generation {new_gen} at {}: only the key that controls it can authorize the next Treasury rotation or new offer freezes. A rotation cannot be undone; a later rotation can only move on to a new address.",
                units::short_hex(&rotation.treasury),
                crate::address_format::encode_for(&new, view)
            ),
            true,
        ),
        Effect::new(
            format!(
                "{} can never again become a destination of this Treasury.",
                crate::address_format::encode_for(&current, view)
            ),
            true,
        ),
        Effect::new(
            "Moves no MUT to the new destination, leaves every other coin of the current destination where it is, and changes no wallet key. MUT authority only: Bitcoin custody is untouched.",
            false,
        ),
    ];
    if payer_mine {
        effects.push(Effect::new(
            format!(
                "Spends {} coin(s) worth {} of the current destination {}. A spent coin cannot be recovered once the rotation is included.",
                facts.inputs.len(),
                units::format_mut_wide(facts.total_in),
                crate::address_format::encode_for(&current, view)
            ),
            true,
        ));
    }
    if change > 0 {
        effects.push(Effect::new(
            format!(
                "Returns {} of change to the current destination {} ({}).",
                units::format_mut(change),
                crate::address_format::encode_for(&current, view),
                payer_label.text()
            ),
            false,
        ));
    }
    effects.push(Effect::new(
        format!(
            "Pays a network fee of {} to the block producer.",
            units::format_mut(fee)
        ),
        true,
    ));
    effects.push(Effect::new(
        format!(
            "Once signed, the rotation cannot be revoked: it stays valid until it is included or until block {}.",
            meta.envelope.last_height
        ),
        true,
    ));

    let mut warnings = Vec::new();
    if view.class() == crate::context::ChainClass::TestValue {
        warnings.push(Warning::new(
            "TEST_VALUE_CHAIN",
            Severity::Notice,
            "This is a TEST-VALUE chain: nothing here has real value.",
        ));
    }
    warnings.push(
        Warning::new(
            "TREASURY_AUTHORITY_ONLY",
            Severity::Caution,
            "This changes the MUT Treasury destination authority only. Bitcoin custody is separate and untouched.",
        )
        .requiring(AckKind::TreasuryAuthority),
    );
    warnings.push(Warning::new(
        "NEW_DESTINATION_KEY",
        Severity::Danger,
        "From inclusion only the key that controls the new destination can rotate this Treasury further or freeze new offers, and proceeds of new offers settle to its address: if that key or its backup is lost, both are lost. This wallet checks only that the chain resolves the address to the descriptor.",
    ));
    warnings.push(Warning::new(
        "FROZEN_OFFERS_KEEP_DESTINATION",
        Severity::Caution,
        format!(
            "Already canonical funded locks preserve their historical destination {}. Historical signatures and freeze witnesses do not authorize first funding after the maker's authority retires; an unfunded offer requires fresh review and current-maker signatures.",
            crate::address_format::encode_for(&current, view)
        ),
    ));
    if facts.treasury_funds {
        warnings.push(
            Warning::new(
                "TREASURY_FUNDS",
                Severity::Caution,
                "This spends Treasury coins for the fee. It moves MUT only; Bitcoin custody is separate and untouched.",
            )
            .requiring(AckKind::TreasuryAuthority),
        );
    }
    if fee > facts.minimum {
        warnings.push(Warning::new(
            "FEE_ABOVE_MINIMUM",
            Severity::Caution,
            format!(
                "The fee is {} atoms above the minimum for this size.",
                fee - facts.minimum
            ),
        ));
    }
    if window <= EXPIRES_SOON_BLOCKS {
        warnings.push(Warning::new(
            "EXPIRES_SOON",
            Severity::Caution,
            format!("This operation expires in {window} block(s) after the verified block."),
        ));
    }

    let (title, summary) = if payer_mine {
        (
            "Rotate the Treasury destination".to_string(),
            format!(
                "Rotate Treasury {} from generation {cur_gen} ({}) to generation {new_gen} ({}), effective at inclusion. Network fee {} from the current destination's coins. MUT authority only; Bitcoin custody is untouched.",
                units::short_hex(&rotation.treasury),
                crate::address_format::encode_for(&current, view),
                crate::address_format::encode_for(&new, view),
                units::format_mut(fee)
            ),
        )
    } else if new_label == AddressLabel::ThisWallet {
        (
            "Treasury destination rotation to this wallet".to_string(),
            "The wallet that controls the current destination rotates the Treasury to an address of this wallet; this wallet has nothing to sign in it.".to_string(),
        )
    } else {
        (
            "Treasury destination rotation by another wallet".to_string(),
            "This rotation is authorized by the wallet that controls the current destination; this wallet has nothing to sign in it.".to_string(),
        )
    };

    Ok(ReviewDraft {
        kind: OperationKind::TreasuryRotate,
        schema: SCHEMA,
        title,
        summary,
        signer: me.summary(),
        authorizations,
        parties,
        destinations,
        amount: None,
        returned: if payer_mine { change } else { 0 },
        fee: Fee {
            atoms: fee,
            rule: FeeRule::TradingMinimum {
                floor: MINIMUM_TRADE_FEE_STRIKES,
            },
            payer: if payer_mine {
                FeePayer::ThisWallet
            } else {
                FeePayer::Counterparty(current)
            },
            size_bytes: Some(facts.size),
        },
        net_debit: payer_mine.then_some(u128::from(fee)),
        inputs: facts
            .inputs
            .iter()
            .map(|input| InputLine {
                point: input.point.clone(),
                atoms: input.coin.output.atoms,
                owned_by_signer: input.mine,
                coinbase: input.coin.coinbase,
            })
            .collect(),
        conditions,
        timing: Timing {
            head_height: head,
            created_height: Some(meta.envelope.first_height),
            expiry_height: Some(meta.envelope.last_height),
            valid_only_at: None,
            bound_to_parent: false,
            earliest_height: None,
            deadline_epoch: None,
        },
        effects,
        warnings,
        extra_acks: vec![AckKind::Conditions],
        high_risk: true,
    })
}

// ---------------------------------------------------------------------------------------------
// Rotation: description
// ---------------------------------------------------------------------------------------------

fn describe_rotate(wire: &NativeOperation) -> Result<Description, Refusal> {
    let op = &wire.operation;
    if op.approvals.is_empty() {
        return Err(Refusal::Malformed(
            "no approval is present: nothing was signed",
        ));
    }
    if op.approvals.iter().any(|approval| approval.slot != 0) {
        return Err(Refusal::Malformed(
            "an approval for a slot a Treasury rotation does not have",
        ));
    }
    let reserved = rotate_reserved(wire)?;
    Ok(Description {
        id: operation_id(op)?,
        complete: true,
        missing: Vec::new(),
        validity: Validity {
            created: op.meta.envelope.first_height,
            expiry: op.meta.envelope.last_height,
            valid_only_at: None,
            bound_to_parent: false,
        },
        reserved,
    })
}

// ---------------------------------------------------------------------------------------------
// Freeze: the freeze body (mirror of the private `trading_v1::TreasuryFreezeBody`)
// ---------------------------------------------------------------------------------------------

/// The freeze body: exactly what the Treasury wallet signs. The wallet's strict mirror of
/// consensus' private `trading_v1::TreasuryFreezeBody` (public as a type so that the freeze
/// capability can take it, `capability::TreasuryFreeze`; obtainable only by decoding canonical
/// bytes inside this crate).
#[derive(Clone, PartialEq, Eq)]
pub struct FreezeBody {
    context: TradeContext,
    anchor_height: u64,
    anchor_block: Hash,
    root: Hash,
    treasury: Hash,
    generation: u64,
    address: Hash,
    trade: Hash,
    contract: Hash,
    offer: OfferBody,
    wallet_descriptor: Vec<u8>,
}

impl FreezeBody {
    /// The canonical encoding (`TreasuryFreezeBody::encode`).
    pub(crate) fn encode(&self) -> Result<Vec<u8>, Refusal> {
        let offer = self
            .offer
            .encode()
            .map_err(|_| Refusal::Malformed("the offer body does not encode"))?;
        let mut e = Encoder::new(Vec::new());
        e.array(14)
            .and_then(|e| e.bytes(NATIVE_NAMESPACE))
            .and_then(|e| e.bytes(b"treasury-freeze"))
            .and_then(|e| e.u8(1))
            .and_then(|e| e.array(3))
            .and_then(|e| e.u32(self.context.network))
            .and_then(|e| e.bytes(&self.context.genesis))
            .and_then(|e| e.bytes(&self.context.fingerprint))
            .and_then(|e| e.u64(self.anchor_height))
            .and_then(|e| e.bytes(&self.anchor_block))
            .and_then(|e| e.bytes(&self.root))
            .and_then(|e| e.bytes(&self.treasury))
            .and_then(|e| e.u64(self.generation))
            .and_then(|e| e.bytes(&self.address))
            .and_then(|e| e.bytes(&self.trade))
            .and_then(|e| e.bytes(&self.contract))
            .and_then(|e| e.bytes(&offer))
            .and_then(|e| e.bytes(&self.wallet_descriptor))
            .map_err(|_| Refusal::Malformed("the freeze body does not encode"))?;
        let raw = e.into_writer();
        if raw.len() > MAX_NATIVE_RECORD {
            return Err(Refusal::SizeLimit {
                limit: MAX_NATIVE_RECORD,
            });
        }
        Ok(raw)
    }

    /// Strict canonical decoding (`TreasuryFreezeBody::decode`): bounded, every field typed, nothing
    /// after the end, and the bytes re-encode to themselves.
    pub(crate) fn decode(raw: &[u8]) -> Result<Self, Refusal> {
        const BAD: Refusal = Refusal::Malformed("not a canonical Treasury freeze body");
        if raw.len() > MAX_NATIVE_RECORD {
            return Err(BAD);
        }
        let d = &mut Decoder::new(raw);
        let fixed = |d: &mut Decoder<'_>| -> Result<Hash, Refusal> {
            d.bytes().map_err(|_| BAD)?.try_into().map_err(|_| BAD)
        };
        if d.array().map_err(|_| BAD)? != Some(14)
            || d.bytes().map_err(|_| BAD)? != NATIVE_NAMESPACE
            || d.bytes().map_err(|_| BAD)? != b"treasury-freeze"
            || d.u8().map_err(|_| BAD)? != 1
            || d.array().map_err(|_| BAD)? != Some(3)
        {
            return Err(BAD);
        }
        let context = TradeContext {
            network: d.u32().map_err(|_| BAD)?,
            genesis: fixed(d)?,
            fingerprint: fixed(d)?,
        };
        let anchor_height = d.u64().map_err(|_| BAD)?;
        let anchor_block = fixed(d)?;
        let root = fixed(d)?;
        let treasury = fixed(d)?;
        let generation = d.u64().map_err(|_| BAD)?;
        let address = fixed(d)?;
        let trade = fixed(d)?;
        let contract = fixed(d)?;
        let offer = OfferBody::decode(d.bytes().map_err(|_| BAD)?).map_err(|_| BAD)?;
        let wallet_descriptor = d.bytes().map_err(|_| BAD)?.to_vec();
        let body = Self {
            context,
            anchor_height,
            anchor_block,
            root,
            treasury,
            generation,
            address,
            trade,
            contract,
            offer,
            wallet_descriptor,
        };
        if d.position() != raw.len() || body.encode()? != raw {
            return Err(BAD);
        }
        Ok(body)
    }

    fn anchor(&self) -> FinalizedAnchor {
        FinalizedAnchor {
            network: self.context.network,
            genesis: self.context.genesis,
            fingerprint: self.context.fingerprint,
            height: self.anchor_height,
            block: self.anchor_block,
        }
    }
}

/// Build the freeze PROPOSAL a Treasury wallet reviews and signs: the exact unsigned freeze body
/// (`trading_v1::PreparedTreasuryOffer::signing_payload`, as the host prepared it against the
/// verified head) and the maker's signed offer in a form the wallet imports (the offer container,
/// or the `OfferProof` encoding with an all-zero fill signature; the one decoder of
/// `offers::import_offer`). Public data only. Both parts are checked here for form; their meaning
/// is checked by the wallet when it plans or adopts the proposal.
pub fn freeze_proposal(signing_payload: &[u8], maker_offer: &[u8]) -> Result<Vec<u8>, Refusal> {
    FreezeBody::decode(signing_payload)?;
    crate::offers::decode_maker_offer(maker_offer)?;
    let mut e = Encoder::new(Vec::new());
    e.array(3)
        .and_then(|e| e.bytes(PROPOSAL_TAG))
        .and_then(|e| e.bytes(signing_payload))
        .and_then(|e| e.bytes(maker_offer))
        .map_err(|_| Refusal::Malformed(REASON_PROPOSAL))?;
    Ok(e.into_writer())
}

/// The two parts of a freeze proposal (strict: canonical, nothing after the end).
fn proposal_parts(raw: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Refusal> {
    const BAD: Refusal = Refusal::Malformed(REASON_PROPOSAL);
    if raw.len() > MAX_NATIVE_RECORD + 8192 + 64 {
        return Err(BAD);
    }
    let d = &mut Decoder::new(raw);
    if d.array().map_err(|_| BAD)? != Some(3) || d.bytes().map_err(|_| BAD)? != PROPOSAL_TAG {
        return Err(BAD);
    }
    let body = d.bytes().map_err(|_| BAD)?.to_vec();
    let offer = d.bytes().map_err(|_| BAD)?.to_vec();
    if d.position() != raw.len() || freeze_proposal(&body, &offer)? != raw {
        return Err(BAD);
    }
    Ok((body, offer))
}

/// The consensus `FrozenTreasuryOffer` encoding `[freeze body, ed448, fndsa]`.
fn encode_frozen(body: &[u8], signature: &HybridSignature) -> Result<Vec<u8>, Refusal> {
    let mut e = Encoder::new(Vec::new());
    e.array(3)
        .and_then(|e| e.bytes(body))
        .and_then(|e| e.bytes(&signature.ed448))
        .and_then(|e| e.bytes(&signature.fndsa))
        .map_err(|_| Refusal::Malformed("the frozen offer does not encode"))?;
    let raw = e.into_writer();
    if raw.len() > MAX_NATIVE_RECORD {
        return Err(Refusal::SizeLimit {
            limit: MAX_NATIVE_RECORD,
        });
    }
    Ok(raw)
}

/// The parts of a frozen offer, read for its STRUCTURE only (the signature is verified separately
/// through consensus code).
fn frozen_parts(raw: &[u8]) -> Result<(Vec<u8>, HybridSignature), Refusal> {
    const BAD: Refusal = Refusal::Malformed("not a canonical frozen Treasury offer");
    if raw.len() > MAX_NATIVE_RECORD {
        return Err(BAD);
    }
    let d = &mut Decoder::new(raw);
    if d.array().map_err(|_| BAD)? != Some(3) {
        return Err(BAD);
    }
    let body = d.bytes().map_err(|_| BAD)?.to_vec();
    let signature = HybridSignature {
        ed448: d.bytes().map_err(|_| BAD)?.try_into().map_err(|_| BAD)?,
        fndsa: d.bytes().map_err(|_| BAD)?.try_into().map_err(|_| BAD)?,
    };
    FreezeBody::decode(&body)?;
    if d.position() != raw.len() || encode_frozen(&body, &signature)? != raw {
        return Err(BAD);
    }
    Ok((body, signature))
}

/// The forms a freeze travels in.
enum FreezeForm {
    /// The proposal: body and the maker's signed offer.
    Proposal { body: Vec<u8>, maker_offer: Vec<u8> },
    /// The bare body (for example a plan object exported elsewhere).
    Body(Vec<u8>),
    /// The signed result (the consensus `FrozenTreasuryOffer` encoding).
    Frozen {
        body: Vec<u8>,
        signature: Box<HybridSignature>,
    },
}

impl FreezeForm {
    fn read(raw: &[u8]) -> Result<Self, Refusal> {
        if let Ok((body, maker_offer)) = proposal_parts(raw) {
            return Ok(Self::Proposal { body, maker_offer });
        }
        if FreezeBody::decode(raw).is_ok() {
            return Ok(Self::Body(raw.to_vec()));
        }
        let (body, signature) = frozen_parts(raw)?;
        Ok(Self::Frozen {
            body,
            signature: Box::new(signature),
        })
    }
    fn body(&self) -> &[u8] {
        match self {
            Self::Proposal { body, .. } | Self::Body(body) | Self::Frozen { body, .. } => body,
        }
    }
}

fn freeze_id(body: &[u8]) -> Hash {
    domain_hash(FREEZE_ID_DOMAIN, body)
}

/// The maker's signed offer of a proposal: a form the wallet imports (`offers::decode_maker_offer`),
/// the same offer body the freeze names, and a maker signature that verifies.
fn verify_maker_offer(body: &FreezeBody, maker_offer: &[u8]) -> Result<SignedOffer, Refusal> {
    // The one import rule (W19): bytes in neither offer form are MALFORMED, as on every path.
    let (offer, _) = crate::offers::decode_maker_offer(maker_offer)?;
    if offer.body != body.offer {
        return Err(Refusal::OfferProofInvalid);
    }
    offer.verify().map_err(|_| Refusal::OfferProofInvalid)?;
    Ok(offer)
}

// ---------------------------------------------------------------------------------------------
// Freeze: the consensus mirror (`validate_treasury_creation`)
// ---------------------------------------------------------------------------------------------

/// What a freeze review can say about the maker's signature over the offer.
#[derive(Clone, Copy, PartialEq, Eq)]
enum MakerEvidence {
    /// Verified by this wallet before the plan was built (a plan exists only after that check).
    CheckedForPlan,
    /// Verified now, from the proposal.
    Verified,
    /// The bytes do not carry it.
    NotCarried,
}

struct FreezeFacts {
    body: FreezeBody,
    body_len: usize,
    offer_id: Hash,
    maker: Hash,
    amount: u64,
    /// The offer's external terms: INTEGER data only.
    bitcoin_satoshis: u64,
    bitcoin_network: u8,
    /// When the named generation took effect.
    active_since: u64,
    head: u64,
    /// The body's wallet descriptor is `me`'s.
    mine: bool,
    /// A verified Treasury signature is present (a signed freeze).
    signed: bool,
}

/// Every creation rule of `validate_treasury_creation` against the CURRENT view. A freeze can be
/// checked only at its own creation head: this wallet holds no historical state.
fn examine_freeze(
    body_bytes: &[u8],
    view: &ChainView<'_>,
    me: Option<&SignerIdentity>,
    check_reserved: bool,
) -> Result<FreezeFacts, Refusal> {
    let body = FreezeBody::decode(body_bytes)?;
    let state = view.state();
    view.require_context(
        body.context.network,
        &body.context.genesis,
        &body.context.fingerprint,
    )?;
    if body.anchor() != *view.anchor() || body.root != view.state_root() {
        return Err(Refusal::StaleHead {
            reviewed: body.anchor_height,
            current: view.anchor().height,
        });
    }
    let offer = &body.offer;
    view.require_context(
        offer.context.network,
        &offer.context.genesis,
        &offer.context.fingerprint,
    )?;
    if body.trade == [0; 32] || body.contract == [0; 32] {
        return Err(Refusal::TreasuryOfferTerms(REASON_FREEZE_COMMITMENTS));
    }
    let context = trade_context(view);
    let named = trading_v1::treasury_generation(state, &context, body.treasury, body.generation)
        .map_err(|_| Refusal::TreasuryGeneration(REASON_FREEZE_GENERATION))?;
    if named.effective_height > body.anchor_height {
        return Err(Refusal::NotYetEligible {
            what: "Freezing an offer to this Treasury generation",
            height: named.effective_height,
        });
    }
    let successor_active = body.generation.checked_add(1).is_some_and(|next| {
        trading_v1::treasury_generation(state, &context, body.treasury, next)
            .is_ok_and(|successor| successor.effective_height <= body.anchor_height)
    });
    if named.address != body.address || successor_active {
        return Err(Refusal::TreasuryGeneration(REASON_FREEZE_GENERATION));
    }
    if offer.created != body.anchor_height
        || offer.expiry <= body.anchor_height
        || offer.expiry - offer.created > EXPIRY_HORIZON
        || offer.maker_side != 1
    {
        return Err(Refusal::TreasuryOfferTerms(REASON_FREEZE_OFFER_WINDOW));
    }
    let (amount, bitcoin_satoshis, bitcoin_network) = match offer.terms {
        OfferTerms::HashLinked {
            bitcoin_network: 0, ..
        } => return Err(Refusal::TreasuryOfferTerms(REASON_BITCOIN_MAINNET)),
        OfferTerms::HashLinked {
            amount,
            bitcoin_satoshis,
            bitcoin_network,
        } if amount.0 > 0
            && bitcoin_satoshis > 0
            && TREASURY_BITCOIN_NETWORKS.contains(&bitcoin_network) =>
        {
            (amount.0, bitcoin_satoshis, bitcoin_network)
        }
        _ => return Err(Refusal::TreasuryOfferTerms(REASON_FREEZE_TERMS)),
    };
    state
        .wallets
        .authorize(body.address, &body.wallet_descriptor)
        .map_err(|_| Refusal::NotRequiredSigner(Slot::TreasuryFreeze))?;
    owner_descriptor(&body.wallet_descriptor)?;
    let offer_id = offer
        .id()
        .map_err(|_| Refusal::Malformed("offer identity"))?;
    if check_reserved && view.reserved().contains(&freeze_resource(&offer_id)) {
        return Err(Refusal::ReservedInput);
    }
    let maker = offer
        .maker()
        .map_err(|_| Refusal::Malformed("maker identity"))?;
    let mine = me.is_some_and(|me| me.descriptor() == body.wallet_descriptor.as_slice());
    Ok(FreezeFacts {
        body_len: body_bytes.len(),
        offer_id,
        maker,
        amount,
        bitcoin_satoshis,
        bitcoin_network,
        active_since: named.effective_height,
        head: view.anchor().height,
        mine,
        signed: false,
        body,
    })
}

fn freeze_validity(body: &FreezeBody) -> Validity {
    Validity {
        // A funding hash lock can rely on the freeze from the block after its creation head until
        // the offer closes.
        created: body.anchor_height.saturating_add(1),
        expiry: body.offer.expiry,
        valid_only_at: None,
        bound_to_parent: false,
    }
}

fn freeze_requirements(facts: &FreezeFacts) -> Vec<Requirement> {
    vec![Requirement {
        slot: Slot::TreasuryFreeze,
        signer: RequiredSigner::Wallet(facts.body.address),
        status: if facts.signed {
            RequirementStatus::Provided
        } else if facts.mine {
            RequirementStatus::ThisWallet
        } else {
            RequirementStatus::Counterparty
        },
    }]
}

/// Plan a freeze from a proposal: the maker's offer verified, every creation rule mirrored, and the
/// same body prepared again through the public `trading_v1::prepare_treasury_offer` at this head.
fn plan_freeze_proposal(
    body_bytes: &[u8],
    maker_offer: &[u8],
    view: &ChainView<'_>,
    signer: &SignerIdentity,
) -> Result<OperationPlan, Refusal> {
    profile::require_treasury_operation(view, signer)?;
    signer.check_current(view)?;
    let body = FreezeBody::decode(body_bytes)?;
    if body.wallet_descriptor != signer.descriptor() {
        return Err(Refusal::NotRequiredSigner(Slot::TreasuryFreeze));
    }
    let maker_signed = verify_maker_offer(&body, maker_offer)?;
    let facts = examine_freeze(body_bytes, view, Some(signer), true)?;
    // The declared role, for exactly the (existing) trading Treasury the freeze names. A freeze
    // spends no coin, so the Genesis Treasury authority's `Authority` role is not what it needs.
    profile::require_role(signer, TreasuryRole::Destination, Some(&body.treasury))?;
    let prepared = trading_v1::prepare_treasury_offer(
        view.state(),
        view.anchor(),
        view.state_root(),
        TreasuryOfferRequest {
            treasury: body.treasury,
            generation: body.generation,
            address: body.address,
            trade: body.trade,
            contract: body.contract,
            offer: maker_signed,
            wallet_descriptor: body.wallet_descriptor.clone(),
        },
        &CandidatePolicy::native_denomination_locked(),
    )
    .map_err(|error| Refusal::VerificationFailed(consensus_verdict(&error)))?;
    let payload = prepared
        .signing_payload()
        .map_err(|error| Refusal::VerificationFailed(consensus_verdict(&error)))?;
    if payload != body_bytes {
        return Err(Refusal::Malformed(REASON_FREEZE_DIFFERS));
    }
    let plan = OperationPlan::assemble(
        OperationKind::TreasuryFreezeOffer,
        SCHEMA,
        signer.clone(),
        vec![PlanObject::new(FREEZE_LABEL, body_bytes.to_vec())],
        freeze_requirements(&facts),
        vec![freeze_resource(&facts.offer_id)],
        freeze_validity(&facts.body),
        view,
    );
    FREEZE.validate(&plan, view)?;
    Ok(plan)
}

// ---------------------------------------------------------------------------------------------
// Freeze: review
// ---------------------------------------------------------------------------------------------

fn review_freeze(
    facts: &FreezeFacts,
    view: &ChainView<'_>,
    me: &SignerIdentity,
    maker_evidence: MakerEvidence,
) -> Result<ReviewDraft, Refusal> {
    let body = &facts.body;
    let offer = &body.offer;
    let label = classify(view, me, &body.address);
    let head = facts.head;
    let descriptor = descriptor_hash(&body.wallet_descriptor);

    let parties = vec![Party {
        role: PartyRole::Treasury,
        address: body.address,
        label,
    }];
    let destinations = vec![Destination {
        role: DestinationRole::LockedOutput,
        address: body.address,
        label,
        atoms: facts.amount,
    }];
    let maker_text = match maker_evidence {
        MakerEvidence::CheckedForPlan => {
            "Verified by this wallet over exactly this offer before the plan was built (a plan exists only after that check).".to_string()
        }
        MakerEvidence::Verified => {
            "Verified by this wallet over exactly this offer (carried by the proposal).".to_string()
        }
        MakerEvidence::NotCarried => {
            "Not carried by these bytes, so not checked here; consensus checks it when a hash lock funds the offer.".to_string()
        }
    };
    let conditions = vec![
        Condition::new(
            "What is signed",
            format!(
                "One Domain::Transaction signature (Ed448 and FN-DSA, both required) by the wallet descriptor with hash {} over the {}-byte freeze body: the chain context, the creation head (block {} {}), its state root {}, Treasury {}, generation {}, destination {}, the TradeID, the ContractHash, the complete offer body and that descriptor. Nothing else: not the maker's offer signature, not any funding hash lock, no Bitcoin data beyond the two integer terms.",
                hex::encode(descriptor),
                facts.body_len,
                body.anchor_height,
                hex::encode(body.anchor_block),
                hex::encode(body.root),
                hex::encode(body.treasury),
                body.generation,
                crate::address_format::encode_for(&body.address, view)
            ),
        ),
        Condition::new(
            "Creation head",
            format!(
                "Prepared against block {} with state root {}: this wallet signs this witness only while that block is its verified head. It does not prove a canonical listing or a pre-rotation commitment. At first canonical funding the maker must still hold current authority; after rotation an unfunded offer needs fresh review and signatures.",
                body.anchor_height,
                hex::encode(body.root)
            ),
        ),
        Condition::new(
            "Treasury destination",
            format!(
                "{} ({}): generation {} of Treasury {}, active since block {} and still active at block {} (checked).",
                crate::address_format::encode_for(&body.address, view),
                label.text(),
                body.generation,
                hex::encode(body.treasury),
                facts.active_since,
                body.anchor_height
            ),
        ),
        Condition::new(
            "Offer",
            format!(
                "Offer {} of maker descriptor commitment {}, nonce {}: open from block {} (the creation block) to block {}. Its signed WalletOwner is bound to recipient/Treasury settlement wallet {}, destination {}, maximum fee {} STRIKES and condition {}. Current maker authority is required at first canonical funding; this freeze witness creates no historical-authority exception.",
                hex::encode(facts.offer_id),
                hex::encode(facts.maker),
                hex::encode(offer.nonce),
                offer.created,
                until(head, offer.expiry),
                crate::address_format::encode_for(&offer.maker_wallet, view),
                crate::address_format::encode_for(&offer.destination, view),
                offer.max_fee.0,
                offer.condition.map_or("none".to_string(), hex::encode)
            ),
        ),
        Condition::new(
            "Offer terms",
            format!(
                "{} STRIKES ({}) for the Treasury against {} satoshis on Bitcoin network code {} ({}). Integer data fields only: this wallet does not build, parse, sign or verify any Bitcoin transaction. Bitcoin settlement not verified by this wallet.",
                facts.amount,
                units::format_mut(facts.amount),
                facts.bitcoin_satoshis,
                facts.bitcoin_network,
                bitcoin_network_name(facts.bitcoin_network)
            ),
        ),
        Condition::new("Maker's offer signature", maker_text),
        Condition::new(
            "Trade commitments",
            format!(
                "TradeID {} and ContractHash {} are opaque 32-byte commitments: shown, not interpreted or verified.",
                hex::encode(body.trade),
                hex::encode(body.contract)
            ),
        ),
        Condition::new(
            "Use",
            format!(
                "Only a hash lock that fills this exact single-fill offer, names this TradeID and ContractHash, locks exactly {} STRIKES and pays {} as its recipient can rely on this authorization. The maker must still hold current authority at first canonical funding. Once finalized, that funded lock keeps its exact terms and destination under existing claim/refund rules, including its signed routing generation {}. An unfunded witness has no historical-authority exception after rotation.",
                facts.amount,
                crate::address_format::encode_for(&body.address, view),
                body.generation
            ),
        ),
        Condition::new(
            "Signing wallet",
            format!(
                "Descriptor hash {}: the wallet that controls {} in the verified wallet book{}.",
                hex::encode(descriptor),
                crate::address_format::encode_for(&body.address, view),
                if facts.mine { " (this wallet)" } else { "" }
            ),
        ),
        Condition::new(
            "Bitcoin custody",
            format!("This authorizes the MUT destination of a Treasury offer ONLY. {NO_BITCOIN}"),
        ),
        Condition::new(
            "Finality",
            "An off-chain authorization: it is never included in a block by itself. A queued record is stored locally only and is not delivered.",
        ),
    ];

    let effects = vec![
        Effect::new(
            format!(
                "This exported witness is valid only under current authority at first canonical funding, through block {}. Historical state and an old signature do not preserve an unfunded offer after rotation. Once finalized, the funded lock keeps its exact terms and destination {} under existing claim/refund rules.",
                offer.expiry,
                crate::address_format::encode_for(&body.address, view)
            ),
            true,
        ),
        Effect::new(
            "Moves no coin, pays no fee and is not included on chain by itself.",
            false,
        ),
        Effect::new(
            "Signs no Bitcoin transaction and touches no Bitcoin key, address or custody.",
            false,
        ),
    ];

    let mut warnings = Vec::new();
    if view.class() == crate::context::ChainClass::TestValue {
        warnings.push(Warning::new(
            "TEST_VALUE_CHAIN",
            Severity::Notice,
            "This is a TEST-VALUE chain: nothing here has real value.",
        ));
    }
    warnings.push(
        Warning::new(
            "TREASURY_AUTHORITY_ONLY",
            Severity::Caution,
            "This authorizes the MUT destination of a Treasury offer only. Bitcoin custody is separate and untouched.",
        )
        .requiring(AckKind::TreasuryAuthority),
    );
    warnings.push(
        Warning::new(
            "BITCOIN_SETTLEMENT_NOT_VERIFIED",
            Severity::Caution,
            format!(
                "The Bitcoin leg ({} satoshis, network code {}) is integer data from the offer: Bitcoin settlement not verified by this wallet, and Bitcoin custody stays outside it.",
                facts.bitcoin_satoshis, facts.bitcoin_network
            ),
        )
        .requiring(AckKind::ExternalEvidence),
    );
    // Order W23: a Caution with the Conditions acknowledgement, like `OPAQUE_COMMITMENTS`.
    warnings.push(crate::offers::trade_commitments_warning());
    warnings.push(Warning::new(
        "SIGNABLE_AT_CREATION_HEAD_ONLY",
        Severity::Notice,
        format!(
            "This wallet can sign this freeze only while block {} is its verified head.",
            body.anchor_height
        ),
    ));
    if maker_evidence == MakerEvidence::NotCarried {
        warnings.push(Warning::new(
            "MAKER_SIGNATURE_NOT_CHECKED",
            Severity::Caution,
            "These bytes do not carry the maker's signature over the offer: it was not checked by this wallet.",
        ));
    }

    let (title, summary) = if facts.mine {
        (
            "Authorize a Treasury offer freeze".to_string(),
            format!(
                "Authorize the MUT proceeds of Treasury offer {} ({} against {} satoshis, Bitcoin network code {}) to settle to the Treasury destination {} (generation {}). Signs no Bitcoin transaction.",
                units::short_hex(&facts.offer_id),
                units::format_mut(facts.amount),
                facts.bitcoin_satoshis,
                facts.bitcoin_network,
                crate::address_format::encode_for(&body.address, view),
                body.generation
            ),
        )
    } else {
        (
            "Treasury offer freeze of another wallet".to_string(),
            "This freeze is signed by the wallet that controls the Treasury destination; this wallet has nothing to sign in it.".to_string(),
        )
    };

    Ok(ReviewDraft {
        kind: OperationKind::TreasuryFreezeOffer,
        schema: SCHEMA,
        title,
        summary,
        signer: me.summary(),
        authorizations: freeze_requirements(facts),
        parties,
        destinations,
        amount: Some(facts.amount),
        returned: 0,
        fee: Fee {
            atoms: 0,
            rule: FeeRule::None,
            payer: FeePayer::NotApplicable,
            size_bytes: None,
        },
        net_debit: None,
        inputs: Vec::new(),
        conditions,
        timing: Timing {
            head_height: head,
            created_height: Some(body.anchor_height.saturating_add(1)),
            expiry_height: Some(offer.expiry),
            valid_only_at: None,
            bound_to_parent: false,
            earliest_height: None,
            deadline_epoch: None,
        },
        effects,
        warnings,
        extra_acks: vec![AckKind::Conditions],
        high_risk: true,
    })
}

fn describe_freeze(raw: &[u8]) -> Result<Description, Refusal> {
    let (body_bytes, signature) = frozen_parts(raw)?;
    if signature.ed448 == [0; 114] || signature.fndsa == [0; 1280] {
        return Err(Refusal::Malformed(
            "the Treasury signature is missing a half: nothing was signed",
        ));
    }
    let body = FreezeBody::decode(&body_bytes)?;
    let offer_id = body
        .offer
        .id()
        .map_err(|_| Refusal::Malformed("offer identity"))?;
    Ok(Description {
        id: freeze_id(&body_bytes),
        complete: true,
        missing: Vec::new(),
        validity: freeze_validity(&body),
        reserved: vec![freeze_resource(&offer_id)],
    })
}

// ---------------------------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------------------------

fn rotate_restore_evidence(op: &Operation) -> Result<PlanObject, Refusal> {
    let r = rotation_of(op)?;
    let mut e = Encoder::new(Vec::new());
    e.array(4)
        .unwrap()
        .str("MUTINY-BUILD8-TREASURY-RESTORE-HOST-ASSERTION-V1")
        .unwrap()
        .bool(true)
        .unwrap()
        .bytes(&r.treasury)
        .unwrap()
        .bytes(&descriptor_hash(r.new_descriptor))
        .unwrap();
    Ok(PlanObject::new(
        "treasury-restore-evidence",
        e.into_writer(),
    ))
}
impl TreasuryHandler {
    fn own_rotation(&self, raw: &[u8]) -> Result<NativeOperation, Refusal> {
        let wire = decode_wire(raw)?;
        if !is_rotation(&wire) {
            return Err(Refusal::UnknownOperation);
        }
        Ok(wire)
    }

    fn plan_object(&self, plan: &OperationPlan) -> Result<Vec<u8>, Refusal> {
        let objects = plan.objects();
        let object = objects
            .first()
            .ok_or(Refusal::Malformed("empty Treasury plan"))?;
        if self.kind == OperationKind::TreasuryRotate {
            let wire = self.own_rotation(&object.bytes)?;
            if objects.len() != 2 || objects[1] != rotate_restore_evidence(&wire.operation)? {
                return Err(Refusal::RestoreNotVerified(
                    "Treasury restore assertion differs from the reviewed authority and destination",
                ));
            }
        } else if objects.len() != 1 {
            return Err(Refusal::Malformed("a Treasury plan has exactly one object"));
        };
        let label = match self.kind {
            OperationKind::TreasuryRotate => ROTATE_LABEL,
            _ => FREEZE_LABEL,
        };
        if object.label != label {
            return Err(Refusal::Malformed("unexpected plan object"));
        }
        Ok(object.bytes.clone())
    }

    fn plan_rotation(&self, plan: &OperationPlan) -> Result<NativeOperation, Refusal> {
        let wire = self.own_rotation(&self.plan_object(plan)?)?;
        if wire != stripped(&wire) {
            return Err(Refusal::Malformed("a plan holds the unsigned form only"));
        }
        Ok(wire)
    }

    fn plan_freeze_body(&self, plan: &OperationPlan) -> Result<Vec<u8>, Refusal> {
        let body = self.plan_object(plan)?;
        FreezeBody::decode(&body)?;
        Ok(body)
    }
}

impl OperationHandler for TreasuryHandler {
    fn kind(&self) -> OperationKind {
        self.kind
    }

    fn recognizes(&self, raw: &[u8]) -> bool {
        match self.kind {
            OperationKind::TreasuryRotate => {
                NativeOperation::decode(raw).is_ok_and(|wire| is_rotation(&wire))
            }
            _ => FreezeForm::read(raw).is_ok(),
        }
    }

    fn plan(
        &self,
        request: &OperationRequest,
        view: &ChainView<'_>,
        signer: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        match (self.kind, request) {
            (OperationKind::TreasuryRotate, OperationRequest::TreasuryRotate(request)) => {
                plan_rotate(request, view, signer)
            }
            (
                OperationKind::TreasuryFreezeOffer,
                OperationRequest::TreasuryFreezeOffer(TreasuryFreezeOfferRequest {
                    prepared_offer,
                    ..
                }),
            ) => {
                // An ordinary identity never reaches anything else.
                profile::require_treasury_operation(view, signer)?;
                let (body, maker_offer) = proposal_parts(prepared_offer.as_slice())?;
                plan_freeze_proposal(&body, &maker_offer, view, signer)
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
        match self.kind {
            OperationKind::TreasuryRotate => {
                let wire = self.own_rotation(raw)?;
                if !wire.operation.approvals.is_empty() {
                    return Err(Refusal::Malformed(
                        "these bytes are already signed: there is nothing left to sign",
                    ));
                }
                profile::require_treasury_operation(view, me)?;
                me.check_current(view)?;
                examine_rotate(&wire, view, Some(me), true)?;
                // The declared role, for exactly the (existing) trading Treasury the bytes name.
                let treasury = rotation_of(&wire.operation)?.treasury;
                profile::require_role(me, TreasuryRole::Destination, Some(&treasury))?;
                Err(Refusal::RestoreNotVerified(
                    "R2 must be planned with fresh host restore evidence; bare wire adoption is unavailable",
                ))
            }
            _ => match FreezeForm::read(raw)? {
                FreezeForm::Proposal { body, maker_offer } => {
                    plan_freeze_proposal(&body, &maker_offer, view, me)
                }
                // A freeze is signed only together with the maker's signed offer it names.
                FreezeForm::Body(_) => Err(Refusal::OfferProofInvalid),
                FreezeForm::Frozen { .. } => Err(Refusal::Malformed(
                    "these bytes are already signed: there is nothing left to sign",
                )),
            },
        }
    }

    fn validate(&self, plan: &OperationPlan, view: &ChainView<'_>) -> Result<(), Refusal> {
        let me = plan.signer();
        // The Treasury profile and the declared role are checked at every use, however the plan
        // came to exist: a rotation's fee spends this wallet's coins (Genesis Treasury coins need
        // the `Authority` role) and both kinds act for exactly one trading Treasury.
        profile::require_treasury_operation(view, me)?;
        let treasury = match self.kind {
            OperationKind::TreasuryRotate => {
                select::require_profile_for_treasury(view, me)?;
                rotation_of(&self.plan_rotation(plan)?.operation)?.treasury
            }
            _ => FreezeBody::decode(&self.plan_freeze_body(plan)?)?.treasury,
        };
        profile::require_role(me, TreasuryRole::Destination, Some(&treasury))?;
        me.check_current(view)?;
        match self.kind {
            OperationKind::TreasuryRotate => {
                let wire = self.plan_rotation(plan)?;
                let facts = examine_rotate(&wire, view, Some(me), true)?;
                if !facts.mine {
                    return Err(Refusal::NotRequiredSigner(Slot::Approval(0)));
                }
                if rotate_requirements(&wire, view, me)? != plan.requirements() {
                    return Err(Refusal::StaleAuthority);
                }
                if plan.inputs() != rotate_reserved(&wire)?.as_slice() {
                    return Err(Refusal::Malformed(
                        "the plan's reservations are not the operation's",
                    ));
                }
                Ok(())
            }
            _ => {
                let body = self.plan_freeze_body(plan)?;
                let facts = examine_freeze(&body, view, Some(me), true)?;
                if !facts.mine {
                    return Err(Refusal::NotRequiredSigner(Slot::TreasuryFreeze));
                }
                if freeze_requirements(&facts) != plan.requirements()
                    || plan.inputs() != [freeze_resource(&facts.offer_id)]
                    || *plan.validity() != freeze_validity(&facts.body)
                {
                    return Err(Refusal::Malformed(
                        "the plan does not match its freeze body",
                    ));
                }
                Ok(())
            }
        }
    }

    fn review(&self, plan: &OperationPlan, view: &ChainView<'_>) -> Result<ReviewDraft, Refusal> {
        match self.kind {
            OperationKind::TreasuryRotate => {
                let wire = self.plan_rotation(plan)?;
                let facts = examine_rotate(&wire, view, Some(plan.signer()), true)?;
                review_rotate(&facts, view, plan.signer())
            }
            _ => {
                let body = self.plan_freeze_body(plan)?;
                let facts = examine_freeze(&body, view, Some(plan.signer()), true)?;
                review_freeze(&facts, view, plan.signer(), MakerEvidence::CheckedForPlan)
            }
        }
    }

    fn explain(
        &self,
        raw: &[u8],
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<(ReviewDraft, Vec<PlanObject>), Refusal> {
        match self.kind {
            OperationKind::TreasuryRotate => {
                let wire = self.own_rotation(raw)?;
                let facts = examine_rotate(&wire, view, Some(me), true)?;
                let draft = review_rotate(&facts, view, me)?;
                Ok((
                    draft,
                    vec![
                        PlanObject::new(ROTATE_LABEL, encode_wire(&stripped(&wire))?),
                        rotate_restore_evidence(&wire.operation)?,
                    ],
                ))
            }
            _ => {
                let form = FreezeForm::read(raw)?;
                let (evidence, signed) = match &form {
                    FreezeForm::Proposal { body, maker_offer } => {
                        verify_maker_offer(&FreezeBody::decode(body)?, maker_offer)?;
                        (MakerEvidence::Verified, false)
                    }
                    FreezeForm::Body(_) => (MakerEvidence::NotCarried, false),
                    FreezeForm::Frozen { signature, .. } => {
                        // BOTH_REQUIRED, and the Treasury signature must verify (consensus decoding
                        // checks it).
                        if signature.ed448 == [0; 114] || signature.fndsa == [0; 1280] {
                            return Err(Refusal::VerificationFailed(
                                "the Treasury signature is missing a half",
                            ));
                        }
                        FrozenTreasuryOffer::decode(raw).map_err(|_| {
                            Refusal::VerificationFailed("the Treasury signature does not verify")
                        })?;
                        (MakerEvidence::NotCarried, true)
                    }
                };
                let mut facts = examine_freeze(form.body(), view, Some(me), true)?;
                facts.signed = signed;
                let draft = review_freeze(&facts, view, me, evidence)?;
                Ok((
                    draft,
                    vec![PlanObject::new(FREEZE_LABEL, form.body().to_vec())],
                ))
            }
        }
    }

    fn sign(
        &self,
        plan: &OperationPlan,
        signer: &KindSigner<'_>,
        _view: &ChainView<'_>,
    ) -> Result<SignedOperation, Refusal> {
        let descriptor = plan.signer().descriptor().to_vec();
        match self.kind {
            OperationKind::TreasuryRotate => {
                let mut wire = self.plan_rotation(plan)?;
                let signature =
                    signer
                        .trade_approval()?
                        .approve_slot(&wire.operation, 0, plan.signer())?;
                wire.operation.approvals.push(TradeApproval {
                    slot: 0,
                    descriptor,
                    signature,
                });
                let bytes = encode_wire(&wire)?;
                let described = describe_rotate(&wire)?;
                Ok(SignedOperation::Complete {
                    kind: OperationKind::TreasuryRotate,
                    id: described.id,
                    bytes,
                    validity: described.validity,
                    reserved: described.reserved,
                })
            }
            _ => {
                let body = self.plan_freeze_body(plan)?;
                let typed = FreezeBody::decode(&body)?;
                if typed.wallet_descriptor != descriptor {
                    return Err(Refusal::NotRequiredSigner(Slot::TreasuryFreeze));
                }
                let signature = signer.treasury_freeze()?.authorize_freeze(&typed)?;
                let bytes = encode_frozen(&body, &signature)?;
                // Consensus decoding re-encodes canonically and verifies the signature.
                FrozenTreasuryOffer::decode(&bytes)
                    .map_err(|_| Refusal::VerificationFailed("the frozen offer does not verify"))?;
                let described = describe_freeze(&bytes)?;
                Ok(SignedOperation::Complete {
                    kind: OperationKind::TreasuryFreezeOffer,
                    id: described.id,
                    bytes,
                    validity: described.validity,
                    reserved: described.reserved,
                })
            }
        }
    }

    fn unsigned_form(&self, raw: &[u8]) -> Result<Vec<PlanObject>, Refusal> {
        match self.kind {
            OperationKind::TreasuryRotate => {
                let wire = self.own_rotation(raw)?;
                Ok(vec![
                    PlanObject::new(ROTATE_LABEL, encode_wire(&stripped(&wire))?),
                    rotate_restore_evidence(&wire.operation)?,
                ])
            }
            _ => Ok(vec![PlanObject::new(
                FREEZE_LABEL,
                FreezeForm::read(raw)?.body().to_vec(),
            )]),
        }
    }

    fn describe(&self, raw: &[u8]) -> Result<Description, Refusal> {
        match self.kind {
            OperationKind::TreasuryRotate => describe_rotate(&self.own_rotation(raw)?),
            _ => describe_freeze(raw),
        }
    }

    fn check_signed(&self, signed: &SignedOperation, view: &ChainView<'_>) -> Result<(), Refusal> {
        if signed.kind() != self.kind {
            return Err(Refusal::UnknownOperation);
        }
        if !signed.is_complete() {
            return Err(Refusal::Malformed(
                "a Treasury operation is complete once signed: it is never partial",
            ));
        }
        let described = self.describe(signed.bytes())?;
        if described.id != signed.id() {
            return Err(Refusal::VerificationFailed(
                "operation identifier does not match the bytes",
            ));
        }
        match self.kind {
            OperationKind::TreasuryRotate => {
                let wire = self.own_rotation(signed.bytes())?;
                // BOTH_REQUIRED: both halves present, then verified with the rest.
                if wire.operation.approvals.iter().any(|approval| {
                    approval.signature.ed448 == [0; 114] || approval.signature.fndsa == [0; 1280]
                }) {
                    return Err(Refusal::VerificationFailed(
                        "the approval is missing a signature half",
                    ));
                }
                // Every rule that holds at this head; the approval through `verify_approval`.
                examine_rotate(&wire, view, None, false)?;
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
                Ok(())
            }
            _ => {
                let (body, _) = frozen_parts(signed.bytes())?;
                examine_freeze(&body, view, None, false)?;
                let frozen = FrozenTreasuryOffer::decode(signed.bytes()).map_err(|_| {
                    Refusal::VerificationFailed("the Treasury signature does not verify")
                })?;
                trading_v1::verify_frozen_treasury_offer_at_creation(
                    frozen,
                    view.state(),
                    view.anchor(),
                    view.state_root(),
                    &CandidatePolicy::native_denomination_locked(),
                )
                .map_err(|error| Refusal::VerificationFailed(consensus_verdict(&error)))?;
                Ok(())
            }
        }
    }

    fn reconcile(&self, record: &OutboxRecord, view: &ChainView<'_>) -> Settlement {
        if self.kind == OperationKind::TreasuryRotate {
            if let Some(height) = view.confirmed_height(&record.id) {
                return Settlement::Confirmed(height);
            }
        }
        let state = view.state();
        let expired = view
            .next_height()
            .map_or(true, |next| next > record.validity.expiry);
        match self.kind {
            OperationKind::TreasuryRotate => {
                let wire = NativeOperation::decode(&record.bytes).ok();
                // Protocol receipt rows alone are not local canonical confirmation. Only
                // the caller's own replay-derived confirmation lookup above can establish it.
                if expired {
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
                // Another rotation took this generation: this one can never apply.
                if let Some(wire) = &wire
                    && let Ok(rotation) = rotation_of(&wire.operation)
                    && active_destination(view, &rotation.treasury)
                        .is_ok_and(|active| active.generation != rotation.current_generation)
                {
                    return Settlement::InputsSpent;
                }
                Settlement::Pending
            }
            _ => {
                // An off-chain authorization is never "confirmed" by itself. It settles when the
                // offer it names is consumed (by whichever hash lock) or closes.
                if let Ok((body, _)) = frozen_parts(&record.bytes)
                    && let Ok(body) = FreezeBody::decode(&body)
                    && let Ok(offer) = body.offer.id()
                    && state.protocol_records.contains_key(&record_key(
                        1,
                        single_fill_key(&body.context, [0; 32], offer),
                    ))
                {
                    return Settlement::InputsSpent;
                }
                if expired {
                    return Settlement::Expired;
                }
                Settlement::Pending
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handlers_are_registered_for_exactly_the_two_treasury_kinds() {
        for kind in OperationKind::ALL {
            let found = handler(kind);
            assert_eq!(
                found.is_some(),
                matches!(
                    kind,
                    OperationKind::TreasuryRotate | OperationKind::TreasuryFreezeOffer
                ),
                "{kind:?}"
            );
            if let Some(found) = found {
                assert_eq!(found.kind(), kind);
            }
        }
    }

    #[test]
    fn constants_are_the_consensus_values() {
        assert_eq!(TRADE_FEE_FLOOR, 240);
        assert_eq!(MAX_TRADE_INPUTS, 16);
        assert_eq!(minimum_fee(10), 240);
        assert_eq!(minimum_fee(5_000), 5_000);
        assert!(!TREASURY_BITCOIN_NETWORKS.contains(&0), "never mainnet");
        assert_eq!(bitcoin_network_name(3), "regtest");
        assert!(bitcoin_network_name(0).contains("never"));
    }

    #[test]
    fn reservation_keys_are_distinct_per_treasury_generation_and_offer() {
        let id = [7u8; 32];
        assert_ne!(rotation_resource(&id, 1), rotation_resource(&id, 2));
        assert_ne!(rotation_resource(&id, 1), rotation_resource(&[8; 32], 1));
        assert_ne!(rotation_resource(&id, 1), freeze_resource(&id));
        assert_eq!(rotation_resource(&id, 1).index, u32::MAX);
        assert_eq!(freeze_resource(&id).index, u32::MAX);
    }

    /// The BTC boundary's statistical sanity check of hash-lock preimages (Q13), here because the
    /// preimage bytes are readable only inside the crate: fresh, distinct, balanced operating-system
    /// randomness with no stuck bit, never equal to anything derived from a wallet key.
    #[test]
    fn preimages_are_fresh_balanced_os_randomness() {
        use crate::secret::Preimage;
        const SAMPLES: usize = 512;
        let mut seen = std::collections::BTreeSet::new();
        let mut ones = 0u64;
        let (mut any, mut all) = ([0u8; 32], [0xffu8; 32]);
        for _ in 0..SAMPLES {
            let preimage = Preimage::generate().unwrap();
            let bytes = *preimage.expose();
            assert!(seen.insert(bytes), "a repeated preimage");
            ones += bytes.iter().map(|b| u64::from(b.count_ones())).sum::<u64>();
            for (index, byte) in bytes.iter().enumerate() {
                any[index] |= byte;
                all[index] &= byte;
            }
        }
        // 131,072 bits: mean 65,536, standard deviation about 181; 1,500 is over 8 deviations.
        let bits = (SAMPLES * 256) as u64;
        assert!(
            ones.abs_diff(bits / 2) < 1_500,
            "{ones} ones in {bits} bits"
        );
        assert!(
            any.iter().all(|byte| *byte == 0xff) && all.iter().all(|byte| *byte == 0),
            "no bit position is stuck"
        );
        // Not a function of any wallet key: two identical wallets would otherwise agree.
        let key = mutiny_crypto_v2::HybridKey::wallet_restore(
            &format!("{}art", "abandon ".repeat(23)),
            mutiny_crypto_v2::Role::WalletOwner,
        )
        .unwrap();
        let address = key.public().address_id(1).unwrap();
        assert!(!seen.contains(&address));
        assert!(!seen.contains(&descriptor_hash(&key.public().descriptor(1).unwrap())));
    }

    #[test]
    fn hostile_proposal_and_frozen_bytes_are_refused_without_a_panic() {
        assert!(proposal_parts(&[]).is_err());
        assert!(frozen_parts(&[]).is_err());
        assert!(FreezeBody::decode(&[0x8e]).is_err());
        assert!(FreezeForm::read(b"not a freeze").is_err());
        let mut e = Encoder::new(Vec::new());
        e.array(3)
            .unwrap()
            .bytes(PROPOSAL_TAG)
            .unwrap()
            .bytes(&[1, 2])
            .unwrap()
            .bytes(&[3])
            .unwrap();
        assert!(proposal_parts(&e.into_writer()).is_err());
    }
}
