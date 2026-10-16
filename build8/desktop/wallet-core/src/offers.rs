//! Maker offers and fill proofs (phase 5B), and the machinery shared by the native trading
//! operations this wallet builds or co-signs: License DvP (`ops::license_dvp`), fiat lock and fiat
//! release (`ops::fiat`).
//!
//! # Canonical wallet-owner offers and exact operation fill proofs
//!
//! A maker publishes a signed OFFER (`trading_v1::SignedOffer`): fixed terms (a License at a named
//! generation for a price, a fiat-settled amount with a payment-terms commitment, or a hash-linked
//! amount), a finite window, destination, condition, fee limit and its current wallet descriptor.
//! The typed maker capability signs under `Domain::TradeOffer`; a separate typed capability signs
//! a FILL over the exact settlement body under `Domain::TradeFill`. Consensus
//! verifies both signatures, the offer window and that the operation's terms are exactly the
//! offer's (`Operation::verify_offer`), and consumes the offer on inclusion (single fill).
//!
//! * [`import_offer`] accepts only the canonical `trading_offer_v2::MakerOffer` wire object.
//!   Wallet-specific and version-one legacy containers are refused. It verifies the maker's
//!   signature, chain context and current authority. One decoder (`decode_maker_offer`) serves every handler:
//!   the License sale, the fiat lock, the hash lock and the Treasury freeze (phase 8).
//! * [`attach_fill_proof`] places a maker's fill proof (the consensus `OfferProof` encoding) into an
//!   operation after checking that it carries the same signed offer and verifies over the EXACT body
//!   at the next height. An offer proof is forbidden on a fiat release (and on claims, refunds and
//!   Treasury rotations, which other phases own).
//! * [`combine`] merges parts of one operation that were signed separately (each wallet signs only
//!   its own approval slot; the maker signs the fill) after verifying every signature, and returns a
//!   `SignedOperation` that went through the kind's consensus verification. It takes no key and
//!   produces no signature.
//!
//! TradeID and ContractHash are shown as OPAQUE commitments with a warning (Q8): this protocol
//! version has no trade-contract codec, so nothing here interprets them.
//!
//! # The placeholder form
//!
//! A trading operation of this wallet always carries EVERY approval slot its action requires and,
//! for an offer-bearing action, the maker's offer proof. A signature that is not there yet is a
//! zero placeholder of the fixed hybrid width. Every signature has a fixed width, so the length of
//! the placeholder form is exactly the length of the completed operation: the fee
//! (`max(240, wire length)`, the rule of `trading_v1` `apply_one`) is fixed once, before anyone
//! signs, and re-checked against the same canonical length whenever a part arrives. A part whose
//! fee is too low is refused, never signed short. The UNSIGNED form (every signature zeroed) is
//! what each party reviews and what the review digest binds, so the planner's review, a
//! counterparty's explanation of a part and anybody's explanation of the completed operation share
//! one digest at one head.
use crate::{
    authorize::{SignedOperation, SignerIdentity},
    context::ChainView,
    plan::{
        Blob, Description, OperationKind, PlanObject, RequiredSigner, Requirement,
        RequirementStatus, Slot, Validity,
    },
    refusal::{ContextField, Refusal},
    review::{AckKind, Condition, Severity, Warning},
    units,
};
use minicbor::Decoder;
use mutiny_consensus_v8::{
    Hash,
    execution::State,
    trading_v1::{
        self, Action, CandidatePolicy, Context, NativeError, NativeOperation, NativeRecord,
        OfferBody, OfferProof, OfferTerms, Operation, SignedOffer,
    },
    transactions::{Coin, EXPIRY_HORIZON, MATURITY, OutPoint},
    wallet_authority_v1::address_key,
};
use mutiny_crypto_v2::{HybridSignature, PublicKey, Role};
use std::fmt;

/// Label of the canonical maker-offer container.
pub const OFFER_LABEL: &str = "MUTINY-BUILD8-WALLET-MAKER-OFFER-V1";
/// Largest accepted offer container, in bytes (an offer body is bounded at 4 KiB by consensus).
pub const MAX_OFFER_BYTES: usize = 8 * 1024;
/// Largest accepted fill proof, in bytes (the bound `OfferProof::decode` applies).
pub const MAX_FILL_PROOF_BYTES: usize = 8 * 1024;
/// The trading fee floor: `apply_one` refuses `fee < max(240, wire length)`. The literal is the
/// rule; a unit test pins that it equals `trading_v1::MINIMUM_TRADE_FEE`.
pub const TRADE_FEE_FLOOR: u64 = 240;
/// Label of the one plan object of a trading operation.
pub(crate) const OBJECT_LABEL: &str = "native-operation";
/// Reservation namespaces (see `outbox::resource_key`).
pub(crate) const LICENSE_RESOURCE: &str = "license";
pub(crate) const OFFER_RESOURCE: &str = "offer";
pub(crate) const LOCK_RESOURCE: &str = "lock";

// ---------------------------------------------------------------------------------------------
// Offers
// ---------------------------------------------------------------------------------------------

/// Whether an offer can be filled at the next block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfferWindow {
    /// The offer opens at this height.
    NotYetValid { from: u64 },
    /// The offer can be filled up to and including this height.
    Open { until: u64 },
    /// The offer's last valid height has passed.
    Expired { at: u64 },
}

/// A maker offer whose canonical encoding, maker signature and chain context were verified.
#[derive(Clone, PartialEq, Eq)]
pub struct VerifiedOffer {
    offer: SignedOffer,
    id: Hash,
    maker: Hash,
}

impl VerifiedOffer {
    /// The offer identifier (`OfferBody::id`), which the operation names and the single-fill
    /// record consumes.
    pub fn id(&self) -> Hash {
        self.id
    }
    /// The maker identity hash (`OfferBody::maker`, the hash of the maker's `Role::Transport`
    /// descriptor). The wallet never holds the maker's key.
    pub fn maker(&self) -> Hash {
        self.maker
    }
    pub fn terms(&self) -> &OfferTerms {
        &self.offer.body.terms
    }
    /// First height at which the offer can be filled.
    pub fn created(&self) -> u64 {
        self.offer.body.created
    }
    /// Last height at which the offer can be filled.
    pub fn expiry(&self) -> u64 {
        self.offer.body.expiry
    }
    /// 0 = the maker is the seller (sender) side, 1 = the buyer (recipient) side.
    pub fn maker_side(&self) -> u8 {
        self.offer.body.maker_side
    }
    /// The verified consensus object.
    pub fn signed_offer(&self) -> &SignedOffer {
        &self.offer
    }
    /// The canonical container of the offer (exactly the bytes [`import_offer`] accepted when it
    /// was given the container; the same container when it was given the zero-fill proof form).
    pub fn encode(&self) -> Vec<u8> {
        encode_offer(&self.offer).expect("a verified offer encodes")
    }
    /// The offer's window relative to the next block of `view`.
    pub fn window(&self, view: &ChainView<'_>) -> Result<OfferWindow, Refusal> {
        let next = view.next_height()?;
        Ok(if next < self.created() {
            OfferWindow::NotYetValid {
                from: self.created(),
            }
        } else if next > self.expiry() {
            OfferWindow::Expired { at: self.expiry() }
        } else {
            OfferWindow::Open {
                until: self.expiry(),
            }
        })
    }
    /// Whether the verified state already records this offer as filled (single fill).
    pub fn is_consumed(&self, view: &ChainView<'_>) -> bool {
        consumed(view.state(), &self.offer.body.context, self.id)
    }
}

impl fmt::Debug for VerifiedOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedOffer")
            .field("id", &units::short_hex(&self.id))
            .field("maker", &units::short_hex(&self.maker))
            .field("terms", &terms_kind(&self.offer.body.terms))
            .field("created", &self.offer.body.created)
            .field("expiry", &self.offer.body.expiry)
            .field("maker_side", &self.offer.body.maker_side)
            .finish()
    }
}

fn terms_kind(terms: &OfferTerms) -> &'static str {
    match terms {
        OfferTerms::HashLinked { .. } => "hash-linked",
        OfferTerms::License { .. } => "License sale",
        OfferTerms::Fiat { .. } => "fiat-settled",
    }
}

/// The canonical container of a signed maker offer:
/// `[OFFER_LABEL, offer body bytes, Ed448 signature bytes, FN-DSA signature bytes]` in definite-length
/// shortest CBOR. Encoding creates nothing and signs nothing: it serialises an offer a maker already
/// signed (for example one a host received as a value).
pub fn encode_offer(offer: &SignedOffer) -> Result<Vec<u8>, Refusal> {
    offer
        .encode()
        .map_err(|_| Refusal::Malformed("not a canonical maker offer"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OfferForm {
    Container,
}

pub(crate) fn decode_maker_offer(raw: &[u8]) -> Result<(SignedOffer, OfferForm), Refusal> {
    mutiny_consensus_v8::trading_offer_v2::decode_maker_offer(raw)
        .map(|offer| (offer, OfferForm::Container))
        .map_err(|_| Refusal::Malformed("not a canonical maker offer"))
}

/// Build finite signed bounds without changing or rebasing the verified reference.
pub(crate) fn envelope(
    view: &ChainView<'_>,
    first: u64,
    last: u64,
    preconditions: Vec<mutiny_consensus_v8::op_envelope_v1::Precondition>,
) -> Result<mutiny_consensus_v8::op_envelope_v1::Envelope, Refusal> {
    let envelope = mutiny_consensus_v8::op_envelope_v1::Envelope {
        first_height: first,
        last_height: last,
        reference_height: view.anchor().height,
        reference_block: view.anchor().block,
        preconditions,
    };
    envelope.validate().map_err(|_| Refusal::InvalidValidity)?;
    Ok(envelope)
}
/// Import a maker offer: strict canonical decoding of either accepted form
/// (`decode_maker_offer`), the maker's signature, and the chain context of `view`. The window and
/// the single-fill status are state-dependent and checked when the offer is used (see
/// [`VerifiedOffer::window`] and [`VerifiedOffer::is_consumed`]).
pub fn import_offer(raw: &[u8], view: &ChainView<'_>) -> Result<VerifiedOffer, Refusal> {
    let (offer, _) = decode_maker_offer(raw)?;
    require_context(view, &offer.body.context)?;
    offer.verify().map_err(|_| Refusal::OfferProofInvalid)?;
    let id = offer
        .body
        .id()
        .map_err(|_| Refusal::Malformed("offer identifier"))?;
    let maker = offer
        .body
        .maker()
        .map_err(|_| Refusal::Malformed("maker identity"))?;
    view.state()
        .wallets
        .authorize(offer.body.maker_wallet, &offer.body.maker_descriptor)
        .map_err(|_| Refusal::StaleAuthority)?;
    Ok(VerifiedOffer { offer, id, maker })
}

/// Place a maker's fill proof (`OfferProof::encode` bytes) into `operation` (native trading bytes of
/// this wallet's placeholder form, signed or not) and return the new bytes. Refused unless the proof
/// carries exactly the signed offer the operation already names, and its fill signature verifies
/// over the EXACT operation body at the next block (`Operation::verify_offer`). Wallet approvals are
/// untouched: the fill signs the body, not the approvals.
pub fn attach_fill_proof(
    operation: &[u8],
    proof: &[u8],
    view: &ChainView<'_>,
) -> Result<Vec<u8>, Refusal> {
    let mut wire = decode_native(operation)?;
    TradeKind::of(&wire.operation.action).ok_or(Refusal::UnknownOperation)?;
    // An offer proof is forbidden on every action that does not fill an offer.
    let (offer, maker) = offer_ids(&wire.operation.action).ok_or(Refusal::OfferProofInvalid)?;
    if proof.is_empty() || proof.len() > MAX_FILL_PROOF_BYTES {
        return Err(Refusal::Malformed("not a canonical fill proof"));
    }
    let proof =
        OfferProof::decode(proof).map_err(|_| Refusal::Malformed("not a canonical fill proof"))?;
    // A proof for another offer or by another maker does not bind this operation.
    if proof.offer.body.id().ok() != Some(offer) || proof.offer.body.maker().ok() != Some(maker) {
        return Err(Refusal::OfferProofInvalid);
    }
    let carried = wire
        .operation
        .offer_proof
        .as_ref()
        .ok_or(Refusal::Malformed(
            "the operation carries no offer: it is not in this wallet's placeholder form",
        ))?;
    // The same offer body with a second maker signature would change the reviewed unsigned form.
    if carried.offer != proof.offer {
        return Err(Refusal::Malformed(
            "the fill proof carries another signature of the offer than the operation",
        ));
    }
    require_context(view, &wire.operation.meta.context)?;
    let height = view.next_height()?;
    wire.operation.offer_proof = Some(proof);
    wire.operation
        .verify_offer(height)
        .map_err(|error| offer_refusal(error, &wire.operation, height))?;
    encode_native(&wire)
}

/// Merge parts of ONE trading operation that were signed separately (for example the buyer's part,
/// the seller's part and a part carrying the maker's fill) into one operation. Every part must have
/// the same unsigned form; every signature any part carries is verified first (a part with a
/// signature that does not verify refuses the whole combination). The result is `Complete` when
/// every required signature is present, otherwise `Partial`; either way it was verified through
/// consensus code (`trading_v1::prepare_batch` for a complete operation, `verify_approval` and
/// `verify_offer` for each signature). Takes no key and signs nothing.
pub fn combine(parts: &[&[u8]], view: &ChainView<'_>) -> Result<SignedOperation, Refusal> {
    let first = parts
        .first()
        .ok_or(Refusal::Malformed("there is nothing to combine"))?;
    let handler = crate::ops::recognizing(first).ok_or(Refusal::UnknownOperation)?;
    let kind = TradeKind::from_operation_kind(handler.kind()).ok_or(Refusal::UnknownOperation)?;
    let parsed = parts
        .iter()
        .map(|raw| parse(raw, kind))
        .collect::<Result<Vec<_>, _>>()?;
    let unsigned = encode_native(&unsigned_copy(&parsed[0].wire))?;
    for part in &parsed[1..] {
        if encode_native(&unsigned_copy(&part.wire))? != unsigned {
            return Err(Refusal::Malformed("the parts are not the same operation"));
        }
    }
    let mut merged = unsigned_copy(&parsed[0].wire);
    require_context(view, &merged.operation.meta.context)?;
    let height = view.next_height()?;
    let slots: Vec<u8> = merged.operation.approvals.iter().map(|a| a.slot).collect();
    for slot in slots {
        let mut chosen = None;
        for part in &parsed {
            let approval = part
                .wire
                .operation
                .approvals
                .iter()
                .find(|a| a.slot == slot)
                .ok_or(Refusal::Malformed("a part lacks an approval slot"))?;
            if sig_state(&approval.signature) == Sig::Missing {
                continue;
            }
            let mut probe = merged.operation.clone();
            set_approval(&mut probe, slot, approval.signature.clone())?;
            if !approval_valid(view, &probe, slot) {
                return Err(Refusal::CounterpartyApprovalInvalid);
            }
            chosen.get_or_insert(approval.signature.clone());
        }
        if let Some(signature) = chosen {
            set_approval(&mut merged.operation, slot, signature)?;
        }
    }
    if merged.operation.offer_proof.is_some() {
        let mut chosen = None;
        for part in &parsed {
            let Some(proof) = &part.wire.operation.offer_proof else {
                continue;
            };
            if sig_state(&proof.fill_signature) == Sig::Missing {
                continue;
            }
            let mut probe = merged.operation.clone();
            if let Some(slot) = &mut probe.offer_proof {
                slot.fill_signature = proof.fill_signature.clone();
            }
            probe
                .verify_offer(height)
                .map_err(|_| Refusal::OfferProofInvalid)?;
            chosen.get_or_insert(proof.fill_signature.clone());
        }
        if let (Some(signature), Some(slot)) = (chosen, merged.operation.offer_proof.as_mut()) {
            slot.fill_signature = signature;
        }
    }
    let bytes = encode_native(&merged)?;
    let described = handler.describe(&bytes)?;
    let signed = signed_from(handler.kind(), bytes, described);
    handler.check_signed(&signed, view)?;
    Ok(signed)
}

// ---------------------------------------------------------------------------------------------
// Shared machinery of the native trading operations (crate-internal)
// ---------------------------------------------------------------------------------------------

/// The native trading actions this wallet builds or co-signs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TradeKind {
    LicenseDvp,
    FiatLock,
    FiatRelease,
}

impl TradeKind {
    pub(crate) fn of(action: &Action) -> Option<Self> {
        match action {
            Action::LicenseDvp { .. } => Some(Self::LicenseDvp),
            Action::FiatLock { .. } => Some(Self::FiatLock),
            Action::FiatRelease { .. } => Some(Self::FiatRelease),
            _ => None,
        }
    }
    pub(crate) fn from_operation_kind(kind: OperationKind) -> Option<Self> {
        match kind {
            OperationKind::LicenseDvp => Some(Self::LicenseDvp),
            OperationKind::FiatLock => Some(Self::FiatLock),
            OperationKind::FiatRelease => Some(Self::FiatRelease),
            _ => None,
        }
    }
    pub(crate) fn operation_kind(self) -> OperationKind {
        match self {
            Self::LicenseDvp => OperationKind::LicenseDvp,
            Self::FiatLock => OperationKind::FiatLock,
            Self::FiatRelease => OperationKind::FiatRelease,
        }
    }
    /// Whether the action fills a maker offer (and so must carry the offer proof).
    pub(crate) fn carries_offer(self) -> bool {
        !matches!(self, Self::FiatRelease)
    }
}

/// Whether a signature is present (anything but the all-zero placeholder).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sig {
    Missing,
    Present,
}

pub(crate) fn sig_state(signature: &HybridSignature) -> Sig {
    if crate::ops::payment::is_unsigned(signature) {
        Sig::Missing
    } else {
        Sig::Present
    }
}

/// One approval slot of a parsed operation.
pub(crate) struct SlotInfo {
    pub slot: u8,
    /// The AddressID that must authorize the slot (`Operation::slot_address`).
    pub address: Hash,
    /// The descriptor the slot names (the signer's CURRENT descriptor).
    pub descriptor: Vec<u8>,
    pub sig: Sig,
}

/// A decoded trading operation of this wallet's placeholder form.
pub(crate) struct Parsed {
    pub wire: NativeOperation,
    /// Length of the canonical encoding. With fixed-width signatures and placeholders this is the
    /// length of the completed operation, so it is what the fee must cover.
    pub size: u64,
    /// Every required approval slot, in slot order.
    pub slots: Vec<SlotInfo>,
    /// The maker's fill signature, for an offer-bearing action.
    pub fill: Option<Sig>,
}

pub(crate) fn decode_native(raw: &[u8]) -> Result<NativeOperation, Refusal> {
    NativeOperation::decode(raw)
        .map_err(|_| Refusal::Malformed("not a canonical native trading operation"))
}

pub(crate) fn encode_native(wire: &NativeOperation) -> Result<Vec<u8>, Refusal> {
    wire.encode().map_err(|error| match error {
        NativeError::Bounds | NativeError::Candidate(trading_v1::Error::Bounds) => {
            Refusal::SizeLimit {
                limit: trading_v1::MAX_NATIVE_BYTES,
            }
        }
        _ => Refusal::Malformed("the trading operation does not encode"),
    })
}

/// The action tag inside native trading bytes, read without decoding any key material, so that
/// recognising an object is cheap. A matching tag is followed by a full canonical decode.
fn peek_action_tag(raw: &[u8]) -> Option<u8> {
    if raw.len() > trading_v1::MAX_NATIVE_BYTES {
        return None;
    }
    let mut d = Decoder::new(raw);
    if d.array().ok()? != Some(4) || d.bytes().ok()? != trading_v1::NATIVE_NAMESPACE {
        return None;
    }
    if d.u8().ok()? != 1 {
        return None;
    }
    let operation = d.bytes().ok()?;
    let mut d = Decoder::new(operation);
    if d.array().ok()? != Some(3) {
        return None;
    }
    let body = d.bytes().ok()?;
    let mut d = Decoder::new(body);
    if d.array().ok()? != Some(12)
        || d.bytes().ok()? != trading_v1::NAMESPACE
        || d.u8().ok()? != trading_v1::BODY_VERSION
    {
        return None;
    }
    d.u32().ok()?;
    for _ in 0..4 {
        d.bytes().ok()?;
    }
    d.u64().ok()?; // generation
    mutiny_consensus_v8::op_envelope_v1::Envelope::decode(&mut d).ok()?;
    d.u64().ok()?; // fee
    let inputs = d.array().ok()??;
    if inputs > trading_v1::MAX_INPUTS as u64 {
        return None;
    }
    for _ in 0..inputs {
        d.bytes().ok()?;
    }
    d.array().ok()??;
    d.u8().ok()
}

/// Whether `raw` is a canonical native trading operation of `kind`.
pub(crate) fn recognizes(raw: &[u8], kind: TradeKind) -> bool {
    let tag = match kind {
        TradeKind::LicenseDvp => 3,
        TradeKind::FiatLock => 4,
        TradeKind::FiatRelease => 5,
    };
    peek_action_tag(raw) == Some(tag)
        && NativeOperation::decode(raw)
            .is_ok_and(|wire| TradeKind::of(&wire.operation.action) == Some(kind))
}

/// Decode `raw` as an operation of `kind` in this wallet's placeholder form.
pub(crate) fn parse(raw: &[u8], kind: TradeKind) -> Result<Parsed, Refusal> {
    let wire = decode_native(raw)?;
    if TradeKind::of(&wire.operation.action) != Some(kind) {
        return Err(Refusal::Malformed("not this kind of trading operation"));
    }
    let op = &wire.operation;
    let expected: Vec<u8> = op.expected_slots().into_iter().collect();
    let present: Vec<u8> = op.approvals.iter().map(|a| a.slot).collect();
    if present != expected {
        return Err(Refusal::Malformed(
            "a trading operation must carry every approval slot, signed or as a zero placeholder",
        ));
    }
    let mut slots = Vec::with_capacity(op.approvals.len());
    for approval in &op.approvals {
        slots.push(SlotInfo {
            slot: approval.slot,
            address: op
                .slot_address(approval.slot)
                .ok_or(Refusal::Malformed("approval slot"))?,
            descriptor: approval.descriptor.clone(),
            sig: sig_state(&approval.signature),
        });
    }
    let fill = if kind.carries_offer() {
        // An offer-bearing action without the maker's offer: OFFER_PROOF_INVALID, the one code of
        // this failure on every path (W19; consensus: `OfferBinding`).
        let proof = op.offer_proof.as_ref().ok_or(Refusal::OfferProofInvalid)?;
        Some(sig_state(&proof.fill_signature))
    } else {
        if op.offer_proof.is_some() {
            // `verify_offer` refuses an offer proof on an action that fills no offer.
            return Err(Refusal::OfferProofInvalid);
        }
        None
    };
    let size = raw.len() as u64;
    Ok(Parsed {
        wire,
        size,
        slots,
        fill,
    })
}

/// The same operation with every approval signature and the maker's fill signature zeroed. The
/// maker's OFFER signature is kept: it is part of the imported offer, not something to produce.
pub(crate) fn unsigned_copy(wire: &NativeOperation) -> NativeOperation {
    let mut copy = wire.clone();
    for approval in &mut copy.operation.approvals {
        approval.signature = crate::ops::payment::zero_signature();
    }
    if let Some(proof) = &mut copy.operation.offer_proof {
        proof.fill_signature = crate::ops::payment::zero_signature();
    }
    copy
}

/// `unsigned_form` of an operation handler: the one plan object of the unsigned bytes.
pub(crate) fn unsigned_objects(raw: &[u8], kind: TradeKind) -> Result<Vec<PlanObject>, Refusal> {
    let parsed = parse(raw, kind)?;
    Ok(vec![PlanObject::new(
        OBJECT_LABEL,
        encode_native(&unsigned_copy(&parsed.wire))?,
    )])
}

/// The plan object of `plan`, parsed; a plan always holds exactly one unsigned trading object.
pub(crate) fn parse_plan_object(
    objects: &[PlanObject],
    kind: TradeKind,
) -> Result<Parsed, Refusal> {
    let [object] = objects else {
        return Err(Refusal::Malformed("a trading plan has exactly one object"));
    };
    if object.label != OBJECT_LABEL {
        return Err(Refusal::Malformed("unexpected plan object"));
    }
    let parsed = parse(&object.bytes, kind)?;
    if parsed.slots.iter().any(|slot| slot.sig != Sig::Missing) || parsed.fill == Some(Sig::Present)
    {
        return Err(Refusal::Malformed("a plan holds the unsigned form only"));
    }
    Ok(parsed)
}

pub(crate) fn set_approval(
    op: &mut Operation,
    slot: u8,
    signature: HybridSignature,
) -> Result<(), Refusal> {
    op.approvals
        .iter_mut()
        .find(|a| a.slot == slot)
        .ok_or(Refusal::Malformed("approval slot"))?
        .signature = signature;
    Ok(())
}

/// Whether the approval of `slot` in `op` is one consensus accepts against the view's wallet book
/// (the parent book of the next block): `trading_v1::verify_approval`.
pub(crate) fn approval_valid(view: &ChainView<'_>, op: &Operation, slot: u8) -> bool {
    trading_v1::verify_approval(&view.state().wallets, op, slot).is_ok()
}

/// The consensus context of `view`.
pub(crate) fn chain_context(view: &ChainView<'_>) -> Context {
    let c = view.context();
    Context {
        network: c.network,
        genesis: c.genesis,
        fingerprint: c.fingerprint,
    }
}

pub(crate) fn require_context(view: &ChainView<'_>, context: &Context) -> Result<(), Refusal> {
    view.require_context(context.network, &context.genesis, &context.fingerprint)
}

fn context_field(ours: &Context, theirs: &Context) -> ContextField {
    if ours.network != theirs.network {
        ContextField::Network
    } else if ours.genesis != theirs.genesis {
        ContextField::Genesis
    } else {
        ContextField::Fingerprint
    }
}

/// The operation window (`apply_one`: `created <= H <= expiry`, at most the expiry horizon).
pub(crate) fn check_meta_window(op: &Operation, height: u64) -> Result<(), Refusal> {
    let m = &op.meta;
    if m.envelope.first_height > height {
        return Err(Refusal::WindowNotOpen {
            created: m.envelope.first_height,
            next_height: height,
        });
    }
    if m.envelope.last_height < height {
        return Err(Refusal::WindowClosed {
            expiry: m.envelope.last_height,
            next_height: height,
        });
    }
    if m.envelope.last_height - m.envelope.first_height > EXPIRY_HORIZON {
        return Err(Refusal::InvalidValidity);
    }
    Ok(())
}

/// The trading fee floor for a complete operation of `size` bytes.
pub(crate) fn fee_floor(size: u64) -> u64 {
    size.max(TRADE_FEE_FLOOR)
}

pub(crate) fn check_fee(op: &Operation, size: u64) -> Result<(), Refusal> {
    let minimum = fee_floor(size);
    if op.meta.fee.0 < minimum {
        return Err(Refusal::FeeBelowMinimum {
            fee: op.meta.fee.0,
            minimum,
        });
    }
    Ok(())
}

/// The height at which consensus applied the operation with identifier `id`, if it did (the
/// `Applied` record is the replay guard and is never removed).
pub(crate) fn applied_height(state: &State, id: Hash) -> Option<u64> {
    let raw = state.protocol_records.get(&trading_v1::record_key(2, id))?;
    match NativeRecord::decode(raw) {
        Ok((found, NativeRecord::Applied { height, .. })) if found == id => Some(height),
        _ => None,
    }
}

/// Whether the single-fill record of `offer` exists.
pub(crate) fn consumed(state: &State, context: &Context, offer: Hash) -> bool {
    state.protocol_records.contains_key(&trading_v1::record_key(
        1,
        trading_v1::single_fill_key(context, [0; 32], offer),
    ))
}

/// (offer, maker) of an offer-bearing action.
pub(crate) fn offer_ids(action: &Action) -> Option<(Hash, Hash)> {
    match action {
        Action::HashLock { offer, maker, .. }
        | Action::LicenseDvp { offer, maker, .. }
        | Action::FiatLock { offer, maker, .. } => Some((*offer, *maker)),
        _ => None,
    }
}

/// The exact-terms rule of `Operation::verify_offer`.
fn terms_match(terms: &OfferTerms, action: &Action) -> bool {
    match (terms, action) {
        (OfferTerms::HashLinked { amount, .. }, Action::HashLock { amount: a, .. }) => amount == a,
        (
            OfferTerms::License {
                license,
                generation,
                price,
            },
            Action::LicenseDvp {
                license: l,
                license_generation: g,
                price: p,
                ..
            },
        ) => license == l && generation == g && price == p,
        (
            OfferTerms::Fiat {
                amount,
                payment_terms,
            },
            Action::FiatLock {
                amount: a,
                payment_terms: p,
                ..
            },
        ) => amount == a && payment_terms == p,
        _ => false,
    }
}

/// The maker's fill signature, as verified (a fill that is present and does not verify is refused).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fill {
    Missing,
    Valid,
}

/// The reason of the request-time refusal of an imported offer whose terms are for another kind of
/// operation than the one requested (`INVALID_REQUEST`, every planner alike; W19).
pub(crate) const REASON_OFFER_KIND: &str = "the offer's terms are for another kind of operation";

/// The request-time usability of an imported offer at the next block, one rule for every planner
/// that fills one (W19): `OFFER_NOT_YET_VALID` before its first block, `OFFER_EXPIRED` after its
/// last, `OFFER_CONSUMED` once the verified state records its single fill.
pub(crate) fn require_fillable(offer: &SignedOffer, view: &ChainView<'_>) -> Result<(), Refusal> {
    let next_height = view.next_height()?;
    let body = &offer.body;
    if next_height < body.created {
        return Err(Refusal::OfferNotYetValid {
            created: body.created,
            next_height,
        });
    }
    if next_height > body.expiry {
        return Err(Refusal::OfferExpired {
            expiry: body.expiry,
            next_height,
        });
    }
    let id = body
        .id()
        .map_err(|_| Refusal::Malformed("offer identifier"))?;
    if consumed(view.state(), &body.context, id) {
        return Err(Refusal::OfferConsumed);
    }
    Ok(())
}

/// What the offer check established.
pub(crate) struct OfferFacts {
    pub id: Hash,
    pub maker: Hash,
    pub body: OfferBody,
    pub consumed: bool,
    pub fill: Fill,
}

/// THE offer check of every handler whose operation carries a maker's offer: the License sale, the
/// fiat lock and the hash lock (W19: the hash lock's own mirror was merged here). Every check
/// `Operation::verify_offer` makes, in its order, with one refusal code per failure whichever
/// handler reaches it (`tests/offer_checks.rs`):
///
/// | Failure | Refusal |
/// |---|---|
/// | an action that fills no offer | `OFFER_PROOF_INVALID` |
/// | an offer-bearing action without the maker's offer | `OFFER_PROOF_INVALID` |
/// | the offer names another chain than the operation | `WRONG_CONTEXT` |
/// | the offer or the maker is not the one the action names | `OFFER_PROOF_INVALID` |
/// | the next block is before the offer's first block | `OFFER_NOT_YET_VALID` |
/// | the next block is after the offer's last block | `OFFER_EXPIRED` |
/// | the operation's window is not inside the offer's | `OFFER_WINDOW_EXCEEDED` |
/// | terms other than the offer's | `OFFER_PROOF_INVALID` |
/// | the maker's offer signature does not verify | `OFFER_PROOF_INVALID` |
/// | a fill signature is present and does not verify over this exact body | `OFFER_PROOF_INVALID` |
///
/// A fill that is still the zero placeholder is `Fill::Missing`. The single-fill status is reported
/// (`consumed`); each handler refuses it with `OFFER_CONSUMED` where consensus consumes the offer
/// (after the debit).
pub(crate) fn check_offer(
    op: &Operation,
    state: &State,
    height: u64,
) -> Result<OfferFacts, Refusal> {
    let (offer, maker) = offer_ids(&op.action).ok_or(Refusal::OfferProofInvalid)?;
    let proof = op.offer_proof.as_ref().ok_or(Refusal::OfferProofInvalid)?;
    let body = &proof.offer.body;
    if body.context != op.meta.context {
        return Err(Refusal::WrongContext(context_field(
            &op.meta.context,
            &body.context,
        )));
    }
    if body.id().ok() != Some(offer) || body.maker().ok() != Some(maker) {
        return Err(Refusal::OfferProofInvalid);
    }
    if height < body.created {
        return Err(Refusal::OfferNotYetValid {
            created: body.created,
            next_height: height,
        });
    }
    if op.meta.envelope.first_height < body.created {
        return Err(window_exceeded(op, body));
    }
    if height > body.expiry {
        return Err(Refusal::OfferExpired {
            expiry: body.expiry,
            next_height: height,
        });
    }
    if op.meta.envelope.last_height > body.expiry {
        return Err(window_exceeded(op, body));
    }
    if op.slot_address(body.maker_side) != Some(body.maker_wallet)
        || state
            .wallets
            .authorize(body.maker_wallet, &body.maker_descriptor)
            .is_err()
    {
        return Err(Refusal::OfferProofInvalid);
    }
    let destination = match (&op.action, body.maker_side) {
        (Action::HashLock { sender, .. }, 0) => Some(*sender),
        (Action::HashLock { recipient, .. }, 1) => Some(*recipient),
        (
            Action::LicenseDvp {
                payment_destination,
                ..
            },
            0,
        ) => Some(*payment_destination),
        (Action::LicenseDvp { buyer, .. }, 1) => Some(*buyer),
        (Action::FiatLock { seller, .. }, 0) => Some(*seller),
        (Action::FiatLock { buyer, .. }, 1) => Some(*buyer),
        _ => None,
    };
    if destination != Some(body.destination)
        || (op.fee_payer() == body.maker_wallet && op.meta.fee > body.max_fee)
    {
        return Err(Refusal::OfferProofInvalid);
    }
    if let (Some(expected), Action::HashLock { condition, .. }) = (&body.condition, &op.action) {
        if condition != expected {
            return Err(Refusal::OfferProofInvalid);
        }
    }
    if !terms_match(&body.terms, &op.action) {
        return Err(Refusal::OfferProofInvalid);
    }
    proof
        .offer
        .verify()
        .map_err(|_| Refusal::OfferProofInvalid)?;
    let fill = match sig_state(&proof.fill_signature) {
        Sig::Missing => Fill::Missing,
        Sig::Present if op.verify_offer(height).is_ok() => Fill::Valid,
        Sig::Present => return Err(Refusal::OfferProofInvalid),
    };
    Ok(OfferFacts {
        id: offer,
        maker,
        body: body.clone(),
        consumed: consumed(state, &op.meta.context, offer),
        fill,
    })
}

/// The refusal of an operation window that is not inside the offer's window.
fn window_exceeded(op: &Operation, offer: &OfferBody) -> Refusal {
    Refusal::OfferWindowExceeded {
        offer_created: offer.created,
        offer_expiry: offer.expiry,
        created: op.meta.envelope.first_height,
        expiry: op.meta.envelope.last_height,
    }
}

/// Every slot's descriptor is, in the view's wallet book, the CURRENT authority of the slot's
/// address (exactly the resolution consensus applies to the approvals, against the parent book).
pub(crate) fn check_slot_authority(view: &ChainView<'_>, parsed: &Parsed) -> Result<(), Refusal> {
    let wallets = &view.state().wallets;
    for slot in &parsed.slots {
        wallets
            .authorize(slot.address, &slot.descriptor)
            .map_err(|_| Refusal::StaleAuthority)?;
    }
    Ok(())
}

/// Every signature that is present verifies (approvals through `verify_approval`, the fill through
/// `verify_offer`). Missing signatures are fine here: they are the parts still to come.
pub(crate) fn check_present_signatures(
    view: &ChainView<'_>,
    parsed: &Parsed,
    height: u64,
) -> Result<(), Refusal> {
    let op = &parsed.wire.operation;
    for slot in &parsed.slots {
        if slot.sig == Sig::Present && !approval_valid(view, op, slot.slot) {
            return Err(Refusal::CounterpartyApprovalInvalid);
        }
    }
    if parsed.fill == Some(Sig::Present) {
        op.verify_offer(height)
            .map_err(|_| Refusal::OfferProofInvalid)?;
    }
    Ok(())
}

/// The coins an operation spends, as verified.
pub(crate) struct InputFacts {
    pub coins: Vec<(OutPoint, Coin)>,
    pub total: u128,
}

/// The `debit` rule of `apply_one`: at least one input; every input an existing coin of exactly
/// the paying address, created before the next height and mature if a coinbase; inputs equal
/// principal + change + fee exactly. With `check_reserved`, a coin held by another pending operation
/// is refused too (wallet policy; consensus does not know the reservation).
fn state_lineage(view: &ChainView<'_>, payer: Hash, descriptor: &[u8]) -> Result<(), Refusal> {
    view.state()
        .wallets
        .authorize(payer, descriptor)
        .map_err(|_| Refusal::StaleAuthority)
}
pub(crate) fn check_inputs(
    view: &ChainView<'_>,
    wire: &NativeOperation,
    payer: Hash,
    principal: u64,
    change: u64,
    check_reserved: bool,
) -> Result<InputFacts, Refusal> {
    let height = view.next_height()?;
    let descriptor = wire
        .operation
        .approvals
        .iter()
        .find(|a| wire.operation.slot_address(a.slot) == Some(payer))
        .map(|a| a.descriptor.clone())
        .or_else(|| current_descriptor(view, payer))
        .ok_or(Refusal::StaleAuthority)?;
    state_lineage(view, payer, &descriptor)?;
    if wire.inputs.is_empty() {
        return Err(Refusal::InvalidRequest(
            "a trading operation needs at least one input coin",
        ));
    }
    let state = view.state();
    let mut total: u128 = 0;
    let mut coins = Vec::with_capacity(wire.inputs.len());
    for point in &wire.inputs {
        let coin = state.coins.get(point).ok_or(Refusal::InputUnavailable)?;
        if check_reserved && view.reserved().contains(point) {
            return Err(Refusal::ReservedInput);
        }
        if state
            .wallets
            .authorize(coin.output.owner, &descriptor)
            .is_err()
        {
            return Err(Refusal::InvalidRequest(
                "every input must be a coin of exactly the paying address",
            ));
        }
        if coin.created_height >= height
            || (coin.coinbase && height - coin.created_height < MATURITY)
        {
            return Err(Refusal::ImmatureInput);
        }
        total += u128::from(coin.output.atoms);
        coins.push((point.clone(), coin.clone()));
    }
    let needed = u128::from(principal) + u128::from(change) + u128::from(wire.operation.meta.fee.0);
    if total != needed {
        return Err(Refusal::Conservation);
    }
    Ok(InputFacts { coins, total })
}

/// The CURRENT public descriptor that controls `address` according to the verified wallet book, if
/// the book names one: the address is an authority (generation one), or an address of a later key
/// generation whose authority the book records.
pub(crate) fn current_descriptor(view: &ChainView<'_>, address: Hash) -> Option<Vec<u8>> {
    let wallets = &view.state().wallets;
    if let Some(current) = wallets.current(address)
        && wallets.authorize(address, current).is_ok()
    {
        return Some(current.to_vec());
    }
    // A later-generation address: its authority is in the address record of the authenticated book.
    let records = wallets.records().ok()?;
    let raw = records.get(&address_key(address))?;
    let mut d = Decoder::new(raw);
    if d.array().ok()? != Some(4) || d.u8().ok()? != 1 || d.u8().ok()? != 31 {
        return None;
    }
    let authority: Hash = d.bytes().ok()?.try_into().ok()?;
    let current = wallets.current(authority)?;
    wallets.authorize(address, current).ok()?;
    Some(current.to_vec())
}

/// The descriptor a counterparty's placeholder slot must name: read from the verified wallet book,
/// or (for an address the book cannot name) the one the request supplies, checked against the book.
pub(crate) fn counterparty_descriptor(
    view: &ChainView<'_>,
    address: Hash,
    supplied: &Blob,
) -> Result<Vec<u8>, Refusal> {
    if supplied.is_empty() {
        return current_descriptor(view, address).ok_or(Refusal::InvalidRequest(
            "the counterparty's current wallet descriptor is not in the verified wallet book: supply it",
        ));
    }
    let (public, _) = PublicKey::decode_descriptor(supplied.as_slice())
        .map_err(|_| Refusal::InvalidDescriptor)?;
    if public.role != Role::WalletOwner {
        return Err(Refusal::InvalidDescriptor);
    }
    view.state()
        .wallets
        .authorize(address, supplied.as_slice())
        .map_err(|_| Refusal::StaleAuthority)?;
    Ok(supplied.as_slice().to_vec())
}

/// The coins of exactly `owner` that `signer` can spend at the next block, under the rules of
/// `ops::select` (not reserved, not newer than the head, mature if a coinbase, controlled by the
/// signer through the wallet book) plus the trading rule that every input belongs to exactly the
/// paying address. Largest first, ties by outpoint; only the largest `MAX_INPUTS` can ever be used.
pub(crate) struct OwnerCoins {
    pub coins: Vec<(OutPoint, u64)>,
    /// All eligible coins, including those beyond the input limit.
    pub count: usize,
    pub total: u128,
}

pub(crate) fn owner_coins(
    view: &ChainView<'_>,
    signer: &SignerIdentity,
    owner: Hash,
) -> Result<OwnerCoins, Refusal> {
    let next = view.next_height()?;
    let head = view.anchor().height;
    let state = view.state();
    state
        .wallets
        .authorize(owner, signer.descriptor())
        .map_err(|_| Refusal::StaleAuthority)?;
    let mut coins: Vec<(OutPoint, u64)> = state
        .coins
        .iter()
        .filter(|(point, coin)| {
            state
                .wallets
                .authorize(coin.output.owner, signer.descriptor())
                .is_ok()
                && !view.reserved().contains(*point)
                && coin.created_height <= head
                && !(coin.coinbase && next - coin.created_height < MATURITY)
        })
        .map(|(point, coin)| (point.clone(), coin.output.atoms))
        .collect();
    coins.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let count = coins.len();
    let total = coins.iter().map(|(_, atoms)| u128::from(*atoms)).sum();
    coins.truncate(trading_v1::MAX_INPUTS);
    Ok(OwnerCoins {
        coins,
        count,
        total,
    })
}

/// Set the operation's inputs, sorted by `native_input_id` as consensus requires (the locator list
/// in the same order).
pub(crate) fn set_inputs(wire: &mut NativeOperation, points: &[OutPoint]) {
    let mut sorted: Vec<(Hash, OutPoint)> = points
        .iter()
        .map(|point| (trading_v1::native_input_id(point), point.clone()))
        .collect();
    sorted.sort();
    wire.operation.meta.inputs = sorted.iter().map(|(id, _)| *id).collect();
    wire.inputs = sorted.into_iter().map(|(_, point)| point).collect();
}

/// Result of fitting the fee for one input set.
pub(crate) enum Fit {
    Done,
    NeedMore { fee: u64 },
}

/// The fee fixed point: `apply(op, fee, change)` writes fee and change; signatures have fixed width
/// so the placeholder encoding is the final length; the fee only ever rises, to the floor of the
/// largest encoding seen. `surplus` is inputs minus principal.
pub(crate) fn fit_fee(
    wire: &mut NativeOperation,
    surplus: u64,
    apply: &dyn Fn(&mut Operation, u64, u64),
) -> Result<Fit, Refusal> {
    let mut fee = 0u64;
    for _ in 0..16 {
        if fee > surplus {
            return Ok(Fit::NeedMore { fee });
        }
        apply(&mut wire.operation, fee, surplus - fee);
        let need = fee_floor(encode_native(wire)?.len() as u64);
        if need <= fee {
            return Ok(Fit::Done);
        }
        fee = need;
    }
    Ok(Fit::NeedMore { fee })
}

/// Choose inputs largest first and fit the fee: the first input set that pays `principal` plus its
/// own fee wins. Refuses with the exact funds message when no set of at most `MAX_INPUTS` coins does.
pub(crate) fn fund(
    wire: &mut NativeOperation,
    coins: &OwnerCoins,
    principal: u64,
    apply: &dyn Fn(&mut Operation, u64, u64),
) -> Result<(), Refusal> {
    if coins.coins.is_empty() {
        return Err(Refusal::NothingSpendable);
    }
    let mut chosen: Vec<OutPoint> = Vec::new();
    let mut total: u128 = 0;
    let mut needed_fee = 0u64;
    for (point, atoms) in &coins.coins {
        chosen.push(point.clone());
        total += u128::from(*atoms);
        set_inputs(wire, &chosen);
        if total <= u128::from(principal) {
            continue;
        }
        let surplus =
            u64::try_from(total - u128::from(principal)).map_err(|_| Refusal::Overflow)?;
        match fit_fee(wire, surplus, apply)? {
            Fit::Done => return Ok(()),
            Fit::NeedMore { fee } => needed_fee = fee,
        }
    }
    if coins.count > coins.coins.len() {
        return Err(Refusal::TooManyInputs {
            limit: trading_v1::MAX_INPUTS,
        });
    }
    if needed_fee == 0 {
        // The coins never exceeded the principal: the least fee is the floor of the smallest shape.
        apply(&mut wire.operation, 0, 0);
        needed_fee = fee_floor(encode_native(wire)?.len() as u64);
    }
    Err(Refusal::InsufficientFunds {
        available: u64::try_from(coins.total).unwrap_or(u64::MAX),
        requested: principal.saturating_add(needed_fee),
    })
}

/// A maker is the current WalletOwner, with a separate typed fill domain.
pub(crate) fn fill_requirement(
    op: &Operation,
    me: &SignerIdentity,
) -> Result<Requirement, Refusal> {
    let p = op.offer_proof.as_ref().ok_or(Refusal::OfferProofInvalid)?;
    // The signed settlement slot may name the stable authority A after rotation to D2.
    // Matching the exact current descriptor is mandatory; an old offer never gains this status.
    let own = p.offer.body.maker_descriptor == me.descriptor()
        && (p.offer.body.maker_wallet == me.address()
            || p.offer.body.maker_wallet == me.authority());
    let status = if sig_state(&p.fill_signature) == Sig::Present {
        RequirementStatus::Provided
    } else if own {
        RequirementStatus::ThisWallet
    } else {
        RequirementStatus::Maker
    };
    Ok(Requirement {
        slot: Slot::FillSignature,
        signer: if own {
            RequiredSigner::Wallet(p.offer.body.maker_wallet)
        } else {
            RequiredSigner::Maker(
                p.offer
                    .body
                    .maker()
                    .map_err(|_| Refusal::OfferProofInvalid)?,
            )
        },
        status,
    })
}
/// What signed or partial trading bytes commit to (`OperationHandler::describe`). At least one
/// WALLET approval must be present: bytes no wallet has signed are a proposal, not something to
/// queue. `resources` are the non-coin reservations of the action (`outbox::resource_key`).
pub(crate) fn describe_parsed(
    parsed: &Parsed,
    valid_only_at: Option<u64>,
    resources: &[OutPoint],
) -> Result<Description, Refusal> {
    if parsed.slots.iter().all(|slot| slot.sig == Sig::Missing) {
        return Err(Refusal::Malformed(
            "no wallet has approved this trading operation yet: there is nothing signed to queue",
        ));
    }
    let op = &parsed.wire.operation;
    let mut missing = Vec::new();
    for slot in &parsed.slots {
        if slot.sig == Sig::Missing {
            missing.push(Requirement {
                slot: Slot::Approval(slot.slot),
                signer: RequiredSigner::Wallet(slot.address),
                status: RequirementStatus::Counterparty,
            });
        }
    }
    if parsed.fill == Some(Sig::Missing) {
        let (_, maker) = offer_ids(&op.action).ok_or(Refusal::OfferProofInvalid)?;
        missing.push(Requirement {
            slot: Slot::FillSignature,
            signer: RequiredSigner::Maker(maker),
            status: RequirementStatus::Maker,
        });
    }
    let mut reserved: Vec<OutPoint> = parsed.wire.inputs.clone();
    reserved.extend(resources.iter().cloned());
    reserved.sort();
    reserved.dedup();
    Ok(Description {
        id: op
            .id()
            .map_err(|_| Refusal::Malformed("operation identity"))?,
        complete: missing.is_empty(),
        missing,
        validity: Validity {
            created: op.meta.envelope.first_height,
            expiry: op.meta.envelope.last_height,
            valid_only_at,
            bound_to_parent: false,
        },
        reserved,
    })
}

/// A signing result for `bytes`, with every metadata field taken from what the bytes say.
pub(crate) fn signed_from(
    kind: OperationKind,
    bytes: Vec<u8>,
    described: Description,
) -> SignedOperation {
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

/// `check_signed` shared by the trading kinds: the identifier is the bytes' own, the chain is the
/// view's, `validate` (every unsigned rule against the CURRENT view, reservations not counted)
/// passes, every signature present verifies, the completeness claim matches the bytes, and a
/// complete operation is accepted by `trading_v1::prepare_batch` with the locked native
/// denomination policy, exactly as block assembly would apply it at the next height.
pub(crate) fn check_signed_trade(
    signed: &SignedOperation,
    view: &ChainView<'_>,
    kind: TradeKind,
    validate: &dyn Fn(&Parsed, &ChainView<'_>) -> Result<(), Refusal>,
) -> Result<(), Refusal> {
    if signed.kind() != kind.operation_kind() {
        return Err(Refusal::UnknownOperation);
    }
    let parsed = parse(signed.bytes(), kind)?;
    let op = &parsed.wire.operation;
    if op
        .id()
        .map_err(|_| Refusal::Malformed("operation identity"))?
        != signed.id()
    {
        return Err(Refusal::VerificationFailed(
            "operation identifier does not match the bytes",
        ));
    }
    require_context(view, &op.meta.context)?;
    validate(&parsed, view)?;
    let height = view.next_height()?;
    check_present_signatures(view, &parsed, height)?;
    let complete = parsed.slots.iter().all(|slot| slot.sig == Sig::Present)
        && parsed.fill != Some(Sig::Missing);
    if complete != signed.is_complete() {
        return Err(Refusal::VerificationFailed(
            "the completeness claimed does not match the bytes",
        ));
    }
    if complete {
        // BOTH_REQUIRED: both halves of every signature are present before consensus runs.
        let halves = |s: &HybridSignature| s.ed448 != [0; 114] && s.fndsa != [0; 1280];
        if !op.approvals.iter().all(|a| halves(&a.signature))
            || !op
                .offer_proof
                .as_ref()
                .is_none_or(|p| halves(&p.fill_signature))
        {
            return Err(Refusal::VerificationFailed(
                "a signature is missing one of its two halves",
            ));
        }
        trading_v1::prepare_batch_with_history(
            view.state(),
            view.anchor(),
            view.state_root(),
            &view.history(),
            &[signed.bytes().to_vec()],
            &CandidatePolicy::native_denomination_locked(),
        )
        .map_err(|error| native_refusal(error, op, parsed.size, height))?;
    }
    Ok(())
}

/// Map a consensus trading error to the wallet's typed refusal. Used when consensus code refuses
/// what the wallet's own pre-signing checks passed, and by the differential tests.
pub(crate) fn native_refusal(
    error: NativeError,
    op: &Operation,
    size: u64,
    height: u64,
) -> Refusal {
    use NativeError as N;
    use trading_v1::Error as E;
    match error {
        N::Codec | N::Candidate(E::Codec) => {
            Refusal::Malformed("native trading operation encoding")
        }
        N::Fee | N::Candidate(E::Fee) => Refusal::FeeBelowMinimum {
            fee: op.meta.fee.0,
            minimum: fee_floor(size),
        },
        N::Immature => Refusal::ImmatureInput,
        N::Missing | N::Candidate(E::Missing) => Refusal::InputUnavailable,
        N::Duplicate | N::Candidate(E::Duplicate) => Refusal::Replay,
        N::Conflict | N::Candidate(E::Conflict) => Refusal::LicenseGenerationStale,
        N::Conservation | N::Candidate(E::Conservation) => Refusal::Conservation,
        N::Overflow | N::Candidate(E::Overflow) => Refusal::Overflow,
        N::Authority | N::Candidate(E::Authority) => Refusal::CounterpartyApprovalInvalid,
        N::LicenseLocked => Refusal::PendingAssignmentOrLock,
        N::FiatRecoveryUnspecified | N::Candidate(E::FiatRecoveryUnspecified) => {
            Refusal::CancelNotAvailable(crate::plan::CancelTarget::FiatLock)
        }
        N::Candidate(E::Signature | E::OfferBinding) => Refusal::OfferProofInvalid,
        // `verify_offer` reports the offer's own window (or an operation window outside it).
        N::Candidate(E::Expired) => Refusal::OfferExpired {
            expiry: op
                .offer_proof
                .as_ref()
                .map_or(op.meta.envelope.last_height, |proof| {
                    proof.offer.body.expiry
                }),
            next_height: height,
        },
        N::Candidate(E::Time) => Refusal::OfferNotYetValid {
            created: op
                .offer_proof
                .as_ref()
                .map_or(op.meta.envelope.first_height, |proof| {
                    proof.offer.body.created
                }),
            next_height: height,
        },
        N::Time => Refusal::VerificationFailed(
            "consensus refuses the operation at this height (time rule)",
        ),
        N::Context | N::Candidate(E::Context) => Refusal::VerificationFailed(
            "consensus refuses the operation's chain, lock or offer context",
        ),
        N::Bounds | N::Candidate(E::Bounds) => {
            Refusal::VerificationFailed("consensus refuses a trading field as out of range")
        }
        _ => Refusal::VerificationFailed("consensus refuses the trading operation"),
    }
}

/// Map an offer verification error (`verify_offer`) to the wallet's refusal.
fn offer_refusal(error: trading_v1::Error, op: &Operation, height: u64) -> Refusal {
    use trading_v1::Error as E;
    let window = op.offer_proof.as_ref().map(|p| &p.offer.body);
    match error {
        E::Time => Refusal::OfferNotYetValid {
            created: window.map_or(op.meta.envelope.first_height, |b| b.created),
            next_height: height,
        },
        E::Expired => Refusal::OfferExpired {
            expiry: window.map_or(op.meta.envelope.last_height, |b| b.expiry),
            next_height: height,
        },
        E::Context => Refusal::WrongContext(match window {
            Some(body) => context_field(&op.meta.context, &body.context),
            None => ContextField::Genesis,
        }),
        _ => Refusal::OfferProofInvalid,
    }
}

// ---------------------------------------------------------------------------------------------
// Shared review text
// ---------------------------------------------------------------------------------------------

/// The opaque-commitment condition (Q8), with the trade operation's generation (the re-attempt
/// counter its body signs).
pub(crate) fn commitments_condition(trade: &Hash, contract: &Hash, generation: u64) -> Condition {
    let show = |value: &Hash| {
        if *value == [0; 32] {
            "not set (zero)".to_string()
        } else {
            hex::encode(value)
        }
    };
    Condition::new(
        "Trade commitments",
        format!(
            "TradeID {} and ContractHash {} are opaque commitments: this wallet cannot interpret or verify what they commit to (Q8). Trade operation generation {}.",
            show(trade),
            show(contract),
            generation
        ),
    )
}

/// The opaque-commitment warning of a hash lock and a Treasury freeze (Q8, Order W23): the same
/// Caution with the Conditions acknowledgement as [`commitments_warning`] (before W23 it was a Notice
/// without one). A warning does not replace concrete term validation, verified external-settlement
/// evidence or the P5/P6 cryptographic commitments.
pub(crate) fn trade_commitments_warning() -> Warning {
    Warning::new(
        "OPAQUE_TRADE_COMMITMENTS",
        Severity::Caution,
        "TradeID and ContractHash are opaque commitments: check them against the trade agreement you hold. This wallet shows them but cannot check what they commit to.",
    )
    .requiring(AckKind::Conditions)
}

/// The opaque-commitment warning (Q8), with the acknowledgement that the conditions were read.
pub(crate) fn commitments_warning() -> Warning {
    Warning::new(
        "OPAQUE_COMMITMENTS",
        Severity::Caution,
        "The TradeID and ContractHash are opaque commitments: check them against the trade agreement you hold. This wallet cannot.",
    )
    .requiring(AckKind::Conditions)
}

/// The offer condition: identifier, maker, terms, side, window and single fill.
pub(crate) fn offer_condition(facts: &OfferFacts, view: &ChainView<'_>) -> Condition {
    let head = view.anchor().height;
    let body = &facts.body;
    let terms = match &body.terms {
        OfferTerms::License {
            license,
            generation,
            price,
        } => format!(
            "License {} at generation {} for {}",
            hex::encode(license),
            generation,
            units::format_amount(price.0)
        ),
        OfferTerms::Fiat {
            amount,
            payment_terms,
        } => format!(
            "{} against fiat payment terms {}",
            units::format_amount(amount.0),
            hex::encode(payment_terms)
        ),
        OfferTerms::HashLinked {
            amount,
            bitcoin_satoshis,
            bitcoin_network,
        } => format!(
            "{} against {} satoshis on Bitcoin environment {} (integer data only)",
            units::format_amount(amount.0),
            bitcoin_satoshis,
            bitcoin_network
        ),
    };
    let side = if body.maker_side == 0 {
        "the seller side"
    } else {
        "the buyer side"
    };
    let remaining = body.expiry.saturating_sub(head);
    Condition::new(
        "Offer",
        format!(
            "Offer {} by maker identity {}: {}; the maker is bound to {} and its exact settlement slot, destination, condition and maximum fee under the version-2 offer rules; current maker authority is required at first canonical funding; fillable in blocks {} to {} ({} blocks after the verified block; {}, approximate at the {} s target interval). Single fill: inclusion consumes it for good.",
            hex::encode(facts.id),
            hex::encode(facts.maker),
            terms,
            format!(
                "{}; wallet {}; receives {}; maximum fee {} STRIKES; condition {}",
                side,
                crate::address_format::encode_for(&body.maker_wallet, view),
                crate::address_format::encode_for(&body.destination, view),
                body.max_fee.0,
                body.condition.map_or("none".into(), hex::encode)
            ),
            body.created,
            body.expiry,
            remaining,
            units::approx_blocks(remaining),
            units::TARGET_BLOCK_SECONDS
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fee_floor_literal_is_the_consensus_constant() {
        assert_eq!(TRADE_FEE_FLOOR, trading_v1::MINIMUM_TRADE_FEE.0);
        assert_eq!(fee_floor(10), 240);
        assert_eq!(fee_floor(240), 240);
        assert_eq!(fee_floor(241), 241);
        assert_eq!(fee_floor(12_345), 12_345);
    }

    #[test]
    fn garbage_is_neither_an_offer_nor_a_trading_operation() {
        for raw in [&[][..], &[0x80], &[0x84, 0x00], &[0xff; 64]] {
            assert!(decode_maker_offer(raw).is_err());
            assert!(peek_action_tag(raw).is_none());
            for kind in [
                TradeKind::LicenseDvp,
                TradeKind::FiatLock,
                TradeKind::FiatRelease,
            ] {
                assert!(!recognizes(raw, kind));
            }
        }
    }
}
