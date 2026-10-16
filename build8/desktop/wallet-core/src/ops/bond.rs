//! Canonical kind-24 creation and signed-envelope unbond/withdrawal commands.
//! Current authorization resolves owner lineage; withdrawal keeps locked consensus timing.
use super::{payment, select};
use crate::{
    authorize::{SignedOperation, SignerIdentity},
    capability::{KeySlot, KindSigner},
    context::{ChainClass, ChainView, is_treasury_address, treasury_authority},
    discovery::bonds::{self as discovery, LotView, NodeView},
    outbox::{OutboxRecord, Settlement, resource_key},
    plan::{
        Description, OperationHandler, OperationKind, OperationPlan, OperationRequest, PlanObject,
        RequiredSigner, Requirement, RequirementStatus, Slot, Validity,
    },
    refusal::{ContextField, Refusal},
    review::{
        AckKind, AddressLabel, Condition, Destination, DestinationRole, Effect, Fee, FeePayer,
        FeeRule, Party, PartyRole, ReviewDraft, Severity, Timing, Warning,
    },
    units,
};
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    bond_ops_v2::{Action, Operation},
    bonds::{EVIDENCE_HEIGHTS, LOCK_HEIGHTS, LotStatus},
    execution::State,
    transactions::OutPoint,
};
use mutiny_crypto_v2::{HybridSignature, PublicKey};

/// Layout version of the bond plan objects.
pub const SCHEMA: u16 = 1;
/// Legacy label retained only for kind dispatch; current creation uses one native kind-24 body.
pub const CREATE_LABEL: &str = "bond-create";
/// Label of the one object of an unbond plan.
pub const UNBOND_LABEL: &str = "bond-unbond";
/// Label of the one object of a withdrawal plan.
pub const WITHDRAW_LABEL: &str = "bond-withdraw";
/// Namespace of a bond lot's reservation key (see [`lot_resource`]).
pub const LOT_RESOURCE: &str = "bond-lot";

/// Reason texts of the lot states. Since phase 8 an unknown lot is `Refusal::LotUnknown`, a burned
/// lot `Refusal::LotBurned`, an unbond of a lot that is not Active `Refusal::LotNotActive` and a
/// withdrawal of a lot that is not Unbonding `Refusal::LotNotUnbonding`; these texts are kept for
/// hosts that show them.
pub const UNKNOWN_LOT: &str = "no bond lot with this identifier exists in the verified state";
pub const LOT_BURNED: &str =
    "the lot was burned by equivocation evidence and can never be unbonded or withdrawn";
pub const LOT_WITHDRAWN: &str = "the lot was already withdrawn";
pub const NOTICE_NOT_STARTED: &str =
    "only an unbonding lot can be withdrawn: start its notice (unbond) first";
/// `InvalidRequest` texts (stable; tests match them).
pub const OWNER_MISMATCH: &str = "the operation names an owner other than the lot's owner";
pub const NONCE_REQUIRED: &str = "a fresh non-zero nonce is required for a new bond lot";
pub const LOT_CAPACITY: &str = "the node already holds the maximum of 64 locked bond lots";
/// `Malformed` texts.
pub const ALREADY_SIGNED: &str = "these bytes are already signed: there is nothing left to sign";

/// Unbond is refused before this block (`what` of [`Refusal::NotYetEligible`]).
const UNBOND_WHAT: &str = "Unbonding this lot";
/// Withdrawal is refused before the floor.
const WITHDRAW_WHAT: &str = "Withdrawing this lot";

pub(crate) struct BondHandler {
    kind: OperationKind,
}

pub(crate) static UNBOND: BondHandler = BondHandler {
    kind: OperationKind::BondUnbond,
};
pub(crate) static WITHDRAW: BondHandler = BondHandler {
    kind: OperationKind::BondWithdraw,
};

/// The handler for a bond kind.
pub(crate) fn handler(kind: OperationKind) -> Option<&'static dyn OperationHandler> {
    match kind {
        OperationKind::BondCreate => Some(&super::bond_create::HANDLER),
        OperationKind::BondUnbond => Some(&UNBOND),
        OperationKind::BondWithdraw => Some(&WITHDRAW),
        _ => None,
    }
}

/// The reservation key of a bond lot in the outbox and in `ChainView::reserved`.
pub fn lot_resource(lot: &Hash) -> OutPoint {
    resource_key(LOT_RESOURCE, lot)
}

/// Current kind-24 funding is atomic: no standalone principal escrow can be stranded.
/// Retained for hosts displaying historical diagnostics; never reports a current native lot.
pub fn stranded_escrow(_raw: &[u8], _state: &State) -> Option<OutPoint> {
    None
}

pub fn export_unsigned(plan: &OperationPlan) -> Result<Vec<u8>, Refusal> {
    if plan.kind() == OperationKind::BondCreate {
        return super::bond_create::export_unsigned(plan);
    }
    encode_op(&command_object(plan, plan.kind())?)
}

// ---------------------------------------------------------------------------------------------
// Codec helpers
// ---------------------------------------------------------------------------------------------

fn encode_op(op: &Operation) -> Result<Vec<u8>, Refusal> {
    op.encode()
        .map_err(|_| Refusal::Malformed("the bond operation does not encode"))
}

fn decode_op(raw: &[u8]) -> Result<Operation, Refusal> {
    Operation::decode(raw).map_err(|_| Refusal::Malformed("not a canonical bond operation"))
}

fn kind_of(action: &Action) -> OperationKind {
    match action {
        Action::Unbond { .. } => OperationKind::BondUnbond,
        Action::Withdraw { .. } => OperationKind::BondWithdraw,
    }
}

fn label_of(kind: OperationKind) -> &'static str {
    match kind {
        OperationKind::BondCreate => CREATE_LABEL,
        OperationKind::BondUnbond => UNBOND_LABEL,
        _ => WITHDRAW_LABEL,
    }
}

fn expect_kind(op: &Operation, kind: OperationKind) -> Result<(), Refusal> {
    if kind_of(&op.action) != kind {
        return Err(Refusal::Malformed("the bond operation is not of this kind"));
    }
    Ok(())
}

fn decode_command(raw: &[u8], kind: OperationKind) -> Result<Operation, Refusal> {
    let op = decode_op(raw)?;
    if kind == OperationKind::BondCreate {
        return Err(Refusal::Malformed(
            "a bond creation travels as one native kind-24 body",
        ));
    }
    expect_kind(&op, kind)?;
    Ok(op)
}

fn command_object(plan: &OperationPlan, kind: OperationKind) -> Result<Operation, Refusal> {
    let [object] = plan.objects() else {
        return Err(Refusal::Malformed(
            "a bond command plan has exactly one object",
        ));
    };
    if object.label != label_of(kind) {
        return Err(Refusal::Malformed("unexpected plan object"));
    }
    decode_command(&object.bytes, kind)
}

fn unsigned_op(op: &Operation) -> Operation {
    let mut copy = op.clone();
    copy.signature = payment::zero_signature();
    copy
}

/// Both halves of a hybrid signature are present (BOTH_REQUIRED).
fn complete(signature: &HybridSignature) -> bool {
    signature.ed448 != [0; 114] && signature.fndsa != [0; 1280]
}

/// The wallet's identifier of a bond operation: a hash of its signed body.
fn operation_id(op: &Operation) -> Result<Hash, Refusal> {
    op.id()
        .map_err(|_| Refusal::Malformed("bond operation identity"))
}

/// Preserve the signed inclusion bounds; the reference is a canonical ancestor.
fn bond_validity(op: &Operation) -> Validity {
    Validity {
        created: op.envelope.first_height,
        expiry: op.envelope.last_height,
        valid_only_at: (op.envelope.first_height == op.envelope.last_height)
            .then_some(op.envelope.first_height),
        bound_to_parent: false,
    }
}

/// Map a consensus error of `verify_owner` / `verify_command` (the independent backstop; the typed
/// checks below run first and normally explain a refusal more precisely).
fn consensus_refusal(error: mutiny_consensus_v8::Error) -> Refusal {
    use mutiny_consensus_v8::Error as E;
    match error {
        E::WrongNetwork => Refusal::WrongContext(ContextField::Network),
        E::WrongGenesis => Refusal::WrongContext(ContextField::Genesis),
        E::WrongFingerprint => Refusal::WrongContext(ContextField::Fingerprint),
        E::WrongGeneration | E::UnknownSigner => Refusal::StaleAuthority,
        E::BadSignature => Refusal::VerificationFailed("the bond owner signature does not verify"),
        E::Overflow => Refusal::Overflow,
        E::Codec | E::NonCanonical | E::Oversize | E::WrongOperation => {
            Refusal::Malformed("bond operation encoding")
        }
        _ => Refusal::VerificationFailed("consensus refuses this bond operation"),
    }
}

// ---------------------------------------------------------------------------------------------
// Checks shared by planning, review, explanation and verification
// ---------------------------------------------------------------------------------------------

/// The operation must fit its signed inclusion window and own canonical reference history.
fn check_anchor(op: &Operation, view: &ChainView<'_>) -> Result<(), Refusal> {
    view.check_envelope(&op.envelope)
}

struct CommandChain {
    lot: LotView,
    sequence: u64,
    /// Unbond: the earliest withdrawal this unbond leads to. Withdrawal: the floor itself.
    floor: u64,
    node: Option<NodeView>,
}

/// Every chain-side rule of an unbond or a withdrawal that needs no signature: the context, the
/// signed window, the lot, its owner's authority, its status, the sequence and the locked timing,
/// then consensus' own transition on a copy of the lot as a backstop.
fn command_chain(
    kind: OperationKind,
    op: &Operation,
    view: &ChainView<'_>,
) -> Result<CommandChain, Refusal> {
    view.require_context(NETWORK_ID, &op.genesis, &op.fingerprint)?;
    let (lot_id, sequence) = match (&op.action, kind) {
        (Action::Unbond { lot, sequence }, OperationKind::BondUnbond)
        | (Action::Withdraw { lot, sequence }, OperationKind::BondWithdraw) => (*lot, *sequence),
        _ => return Err(Refusal::Malformed("the bond operation is not of this kind")),
    };
    encode_op(op)?;
    check_anchor(op, view)?;
    let state = view.state();
    let lot = discovery::lot(state, &lot_id).ok_or(Refusal::LotUnknown)?;
    if op.owner != lot.owner {
        return Err(Refusal::InvalidRequest(OWNER_MISMATCH));
    }
    state
        .wallets
        .authorize(op.owner, &op.authorizer)
        .map_err(|_| Refusal::StaleAuthority)?;
    let unbond = kind == OperationKind::BondUnbond;
    match lot.status {
        LotStatus::Active if unbond => {}
        LotStatus::Unbonding if !unbond => {}
        LotStatus::Burned => return Err(Refusal::LotBurned),
        LotStatus::Unbonding => return Err(Refusal::LotNotActive("unbonding")),
        LotStatus::Withdrawn if unbond => return Err(Refusal::LotNotActive("withdrawn")),
        LotStatus::Withdrawn => return Err(Refusal::LotNotUnbonding("withdrawn")),
        LotStatus::Active => return Err(Refusal::LotNotUnbonding("active")),
    }
    let expected = lot.sequence.checked_add(1).ok_or(Refusal::Overflow)?;
    if sequence != expected {
        return Err(Refusal::WrongSequence { expected });
    }
    let floor = if unbond {
        if view.next_height()? <= lot.created_height {
            return Err(Refusal::NotYetEligible {
                what: UNBOND_WHAT,
                height: lot.created_height.saturating_add(1),
            });
        }
        view.next_height()?
            .checked_add(EVIDENCE_HEIGHTS)
            .ok_or(Refusal::Overflow)?;
        lot.earliest_withdrawal_if_unbonded_at(view.next_height()?)
            .ok_or(Refusal::Overflow)?
    } else {
        let floor = lot.earliest_withdrawal().ok_or(Refusal::Overflow)?;
        if view.next_height()? < floor {
            return Err(Refusal::NotYetEligible {
                what: WITHDRAW_WHAT,
                height: floor,
            });
        }
        floor
    };
    // Consensus' own transition on a copy: the single source of the economic rules.
    let mut check = state
        .bonds_v2
        .lots
        .get(&lot_id)
        .ok_or(Refusal::LotUnknown)?
        .clone();
    let transition = if unbond {
        check.start_unbond(view.next_height()?, sequence)
    } else {
        check.withdraw(view.next_height()?, sequence).map(|_| ())
    };
    transition
        .map_err(|_| Refusal::VerificationFailed("consensus refuses this bond transition"))?;
    if !unbond {
        let payout = OutPoint {
            transaction: op
                .payout_id()
                .map_err(|_| Refusal::Malformed("bond payout identifier"))?,
            index: 0,
        };
        if state.coins.contains_key(&payout) {
            return Err(Refusal::Replay);
        }
    }
    let node = discovery::node(state, &lot.node);
    Ok(CommandChain {
        lot,
        sequence,
        floor,
        node,
    })
}

/// [`command_chain`] plus the lot's reservation.
fn command_facts(
    kind: OperationKind,
    op: &Operation,
    view: &ChainView<'_>,
) -> Result<CommandChain, Refusal> {
    let chain = command_chain(kind, op, view)?;
    if view.reserved().contains(&lot_resource(&chain.lot.id)) {
        return Err(Refusal::ReservedInput);
    }
    Ok(chain)
}

// ---------------------------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------------------------

/// Plan an unbond/withdrawal command against current authority and a signed finite inclusion window.
fn plan_command(
    kind: OperationKind,
    lot: &Hash,
    blocks: u64,
    view: &ChainView<'_>,
    signer: &SignerIdentity,
) -> Result<OperationPlan, Refusal> {
    if blocks == 0 || blocks > mutiny_consensus_v8::transactions::EXPIRY_HORIZON {
        return Err(Refusal::InvalidRequest(
            "bond inclusion window must be 1..=10,080",
        ));
    }
    signer.check_current(view)?;
    select::require_profile_for_treasury(view, signer)?;
    let state = view.state();
    let lot = discovery::lot(state, lot).ok_or(Refusal::LotUnknown)?;
    if state
        .wallets
        .authorize(lot.owner, signer.descriptor())
        .is_err()
    {
        return Err(Refusal::NotRequiredSigner(Slot::BondOwner));
    }
    // The sequence is always derived from verified state, never supplied.
    let sequence = lot.sequence.checked_add(1).ok_or(Refusal::Overflow)?;
    let action = match kind {
        OperationKind::BondUnbond => Action::Unbond {
            lot: lot.id,
            sequence,
        },
        OperationKind::BondWithdraw => Action::Withdraw {
            lot: lot.id,
            sequence,
        },
        _ => return Err(Refusal::UnknownOperation),
    };
    let context = view.context();
    let op = Operation {
        genesis: context.genesis,
        fingerprint: context.fingerprint,
        envelope: crate::offers::envelope(
            view,
            view.next_height()?,
            view.next_height()?
                .checked_add(blocks)
                .ok_or(Refusal::Overflow)?,
            Vec::new(),
        )?,
        owner: lot.owner,
        authorizer: signer.descriptor().to_vec(),
        action,
        signature: payment::zero_signature(),
    };
    assemble_command(kind, &op, view, signer)
}

fn assemble_command(
    kind: OperationKind,
    op: &Operation,
    view: &ChainView<'_>,
    signer: &SignerIdentity,
) -> Result<OperationPlan, Refusal> {
    let lot = match &op.action {
        Action::Unbond { lot, .. } | Action::Withdraw { lot, .. } => *lot,
    };
    let plan = OperationPlan::assemble(
        kind,
        SCHEMA,
        signer.clone(),
        vec![PlanObject::new(label_of(kind), encode_op(op)?)],
        vec![Requirement {
            slot: Slot::BondOwner,
            signer: RequiredSigner::Wallet(op.owner),
            status: RequirementStatus::ThisWallet,
        }],
        vec![lot_resource(&lot)],
        bond_validity(op),
        view,
    );
    handler(kind)
        .ok_or(Refusal::UnknownOperation)?
        .validate(&plan, view)?;
    Ok(plan)
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

/// `N blocks after the verified block; about ..., approximate at the 60 s target interval`.
fn wait_text(head: u64, height: u64) -> String {
    if height <= head {
        return "reached at the verified block".to_string();
    }
    let wait = height - head;
    format!(
        "{wait} blocks after the verified block; {}, approximate at the {} s target interval",
        units::approx_blocks(wait),
        units::TARGET_BLOCK_SECONDS
    )
}

/// The status of the owner signature as seen from `me` (a non-empty signature that does not verify
/// is a danger, never "provided").
fn owner_status(
    op: &Operation,
    view: &ChainView<'_>,
    me: &SignerIdentity,
    warnings: &mut Vec<Warning>,
) -> RequirementStatus {
    let fallback = if view
        .state()
        .wallets
        .authorize(op.owner, me.descriptor())
        .is_ok()
    {
        RequirementStatus::ThisWallet
    } else {
        RequirementStatus::Counterparty
    };
    if payment::is_unsigned(&op.signature) {
        return fallback;
    }
    if complete(&op.signature) && op.verify_signatures().is_ok() {
        return RequirementStatus::Provided;
    }
    warnings.push(Warning::new(
        "BAD_SIGNATURE",
        Severity::Danger,
        "The bond owner signature does not verify. Do not rely on these bytes.",
    ));
    fallback
}

fn authority_condition(op: &Operation, view: &ChainView<'_>) -> Condition {
    let detail = match PublicKey::decode_descriptor(&op.authorizer) {
        Ok((public, generation)) => match public.address_id(generation) {
            Ok(address) => format!(
                "The owner {} signs with its current key, resolved through the wallet book as consensus resolves it: key generation {generation}, address {}. A key that was rotated away cannot sign.",
                crate::address_format::encode_for(&op.owner, view),
                crate::address_format::encode_for(&address, view)
            ),
            Err(_) => "The authorizer descriptor names no address.".to_string(),
        },
        Err(_) => "The authorizer descriptor does not decode.".to_string(),
    };
    Condition::new("Bond authority", detail)
}

fn inclusion_condition(op: &Operation, _view: &ChainView<'_>) -> Condition {
    Condition::new(
        "Signed inclusion window",
        format!(
            "Valid from block {} through {} inclusive. The signed reference is canonical block {} ({}); retained history must prove it at inclusion. Timing eligibility is evaluated at actual inclusion.",
            op.envelope.first_height,
            op.envelope.last_height,
            op.envelope.reference_height,
            hex::encode(op.envelope.reference_block)
        ),
    )
}

fn inclusion_warning(op: &Operation) -> Warning {
    Warning::new(
        "SIGNED_WINDOW",
        Severity::Caution,
        format!(
            "These signatures expire after block {}. The wallet never rebases their reference or inclusion bounds; changed bytes require a new review and signatures.",
            op.envelope.last_height
        ),
    )
    .requiring(AckKind::Conditions)
}

fn inclusion_timing(op: &Operation, view: &ChainView<'_>, earliest: Option<u64>) -> Timing {
    Timing {
        head_height: view.anchor().height,
        created_height: Some(op.envelope.first_height),
        expiry_height: Some(op.envelope.last_height),
        valid_only_at: bond_validity(op).valid_only_at,
        bound_to_parent: false,
        earliest_height: earliest,
        deadline_epoch: None,
    }
}

fn weight_condition() -> Condition {
    Condition::new(
        "Weight",
        "Reputation and quorum weight effects follow the reviewed canonical rules (consensus bonds.rs): an Active lot first supports its node from block B + 1, and from block U + 1 an unbonding lot no longer counts. This wallet does not compute or promise any weight.",
    )
}

fn test_value_warning(view: &ChainView<'_>, warnings: &mut Vec<Warning>) {
    if view.class() == ChainClass::TestValue {
        warnings.push(Warning::new(
            "TEST_VALUE_CHAIN",
            Severity::Notice,
            "This is a TEST-VALUE chain: nothing here has real value.",
        ));
    }
}

/// The review of a creation (unsigned, partly signed or signed) as seen from `me`.
fn command_review(
    kind: OperationKind,
    op: &Operation,
    chain: &CommandChain,
    view: &ChainView<'_>,
    me: &SignerIdentity,
) -> Result<ReviewDraft, Refusal> {
    let lot = &chain.lot;
    let head = view.anchor().height;
    let height = view.next_height()?;
    let unbond = kind == OperationKind::BondUnbond;
    let mut warnings = Vec::new();
    let authorizations = vec![Requirement {
        slot: Slot::BondOwner,
        signer: RequiredSigner::Wallet(op.owner),
        status: owner_status(op, view, me, &mut warnings),
    }];
    let owner_label = classify(view, me, &op.owner);
    let mine = owner_label == AddressLabel::ThisWallet;
    let parties = vec![Party {
        role: PartyRole::Owner,
        address: op.owner,
        label: owner_label,
    }];
    let fee = Fee {
        atoms: 0,
        rule: FeeRule::None,
        payer: FeePayer::NotApplicable,
        size_bytes: None,
    };
    let node_text = match &chain.node {
        Some(node) => format!(
            "node {} (lineage {}, generation {})",
            hex::encode(node.node),
            hex::encode(node.lineage),
            node.generation
        ),
        None => format!(
            "node {} (lineage {}, no longer a registry member)",
            hex::encode(lot.node),
            hex::encode(lot.lineage)
        ),
    };
    let previous = chain.sequence - 1;
    let mut conditions = vec![
        Condition::new(
            "Lot",
            match lot.unbond_height {
                None => format!(
                    "Lot {} of {node_text}: {}, Active since block {}, confirmed sequence {previous}.",
                    hex::encode(lot.id),
                    units::format_amount(lot.atoms),
                    lot.created_height
                ),
                Some(notice) => format!(
                    "Lot {} of {node_text}: {}, locked since block {} (B), unbonding since block {notice} (U), confirmed sequence {previous}.",
                    hex::encode(lot.id),
                    units::format_amount(lot.atoms),
                    lot.created_height
                ),
            },
        ),
        Condition::new(
            "Sequence",
            format!(
                "This operation carries sequence {}: the lot's confirmed sequence {previous} plus one, read from verified state.",
                chain.sequence
            ),
        ),
        inclusion_condition(op, view),
    ];
    let mut effects = Vec::new();
    let (destinations, amount, net_debit, earliest, title, summary) = if unbond {
        let exposure = height
            .checked_add(EVIDENCE_HEIGHTS)
            .ok_or(Refusal::Overflow)?;
        conditions.push(Condition::new(
            "Notice",
            format!(
                "The notice is {EVIDENCE_HEIGHTS} certified blocks from U; the minimum hold is {LOCK_HEIGHTS} certified blocks from B = {}. Both apply; heights count certified blocks, never wall time.",
                lot.created_height
            ),
        ));
        conditions.push(Condition::new(
            "Earliest withdrawal",
            format!(
                "Block {} = max({} + {LOCK_HEIGHTS}, {height} + {EVIDENCE_HEIGHTS}) if inclusion is U = {height}; {}. U is the actual finalized inclusion height; later inclusion moves the notice floor later.",
                chain.floor,
                lot.created_height,
                wait_text(head, chain.floor)
            ),
        ));
        conditions.push(Condition::new(
            "Burn exposure",
            format!(
                "If inclusion is U = {height}, the lot stays exposed until block {exposure}; actual exposure lasts through finalized U + {EVIDENCE_HEIGHTS}. A burned lot can never be withdrawn."
            ),
        ));
        conditions.push(weight_condition());
        effects.push(Effect::new(
            format!(
                "Moves lot {} from Active to Unbonding at actual finalized inclusion U (next eligible block {height}). There is no way back: an unbond cannot be cancelled.",
                hex::encode(lot.id)
            ),
            true,
        ));
        effects.push(Effect::new(
            format!(
                "Starts the {EVIDENCE_HEIGHTS}-block notice at actual U; if included next, the earliest withdrawal becomes block {}.",
                chain.floor
            ),
            true,
        ));
        effects.push(Effect::new(
            format!(
                "The lot no longer counts toward the node's weight from actual U + 1 (block {} if included next).",
                height.saturating_add(1)
            ),
            true,
        ));
        effects.push(Effect::new(
            format!(
                "Once signed, the unbond cannot be revoked; its signed inclusion window is {} through {}.", op.envelope.first_height, op.envelope.last_height
            ),
            true,
        ));
        effects.push(Effect::new(
            format!(
                "Moves no MUT now: the principal of {} stays in the lot until it is withdrawn.",
                units::format_mut(lot.atoms)
            ),
            false,
        ));
        warnings.push(
            Warning::new(
                "NO_CANCEL",
                Severity::Danger,
                "An unbond is final: Active to Unbonding is one-way and the protocol offers no cancellation.",
            )
            .requiring(AckKind::Irreversible),
        );
        warnings.push(
            Warning::new(
                "BURN_EXPOSURE",
                Severity::Caution,
                format!(
                "The lot can still be burned through actual U + {EVIDENCE_HEIGHTS} (block {exposure} if included next)."
                ),
            )
            .requiring(AckKind::Conditions),
        );
        (
            Vec::new(),
            None,
            Some(0),
            None,
            "Start a bond's notice (unbond)".to_string(),
            format!(
                "Start the {EVIDENCE_HEIGHTS}-block notice of lot {} ({}); the earliest withdrawal becomes block {}.",
                units::short_hex(&lot.id),
                units::format_mut(lot.atoms),
                chain.floor
            ),
        )
    } else {
        let payout = op
            .payout_id()
            .map_err(|_| Refusal::Malformed("bond payout identifier"))?;
        let unbonded = lot.unbond_height.unwrap_or_default();
        conditions.push(Condition::new(
            "Withdrawal rule",
            format!(
                "W >= B + {LOCK_HEIGHTS} and W >= U + {EVIDENCE_HEIGHTS}: the floor is block {} = max({} + {LOCK_HEIGHTS}, {unbonded} + {EVIDENCE_HEIGHTS}); actual inclusion W must satisfy this floor within the signed window (next eligible block {height}).",
                chain.floor, lot.created_height
            ),
        ));
        conditions.push(Condition::new(
            "Payout",
            format!(
                "The protocol creates coin {}:0 of {} owned by the original owner {} ({}).",
                hex::encode(payout),
                units::format_amount(lot.atoms),
                crate::address_format::encode_for(&lot.owner, view),
                owner_label.text()
            ),
        ));
        conditions.push(Condition::new(
            "Slashes first",
            format!(
                "Valid timely equivocation evidence in the actual inclusion block W settles before withdrawal (next eligible block {height}): a lot burned in that block pays nothing and the withdrawal has no effect."
            ),
        ));
        effects.push(Effect::new(
            format!(
                "Ends the bond at actual finalized inclusion W (next eligible block {height}): lot {} becomes Withdrawn and the protocol pays {} to {} ({}).",
                hex::encode(lot.id),
                units::format_mut(lot.atoms),
                crate::address_format::encode_for(&lot.owner, view),
                owner_label.text()
            ),
            true,
        ));
        effects.push(Effect::new(
            format!(
                "Once signed, the withdrawal cannot be revoked; its signed inclusion window is {} through {}.", op.envelope.first_height, op.envelope.last_height
            ),
            true,
        ));
        if mine {
            effects.push(Effect::new(
                format!("This wallet receives {}.", units::format_mut(lot.atoms)),
                false,
            ));
        }
        warnings.push(Warning::new(
            "SLASH_FIRST",
            Severity::Notice,
            "Evidence in the same block settles first; a lot burned there pays nothing.",
        ));
        (
            vec![Destination {
                role: DestinationRole::ProtocolPayout,
                address: lot.owner,
                label: owner_label,
                atoms: lot.atoms,
            }],
            Some(lot.atoms),
            None,
            Some(chain.floor),
            "Withdraw a bond".to_string(),
            format!(
                "Withdraw lot {}: the protocol pays {} to {}.",
                units::short_hex(&lot.id),
                units::format_mut(lot.atoms),
                crate::address_format::encode_for(&lot.owner, view)
            ),
        )
    };
    conditions.push(authority_condition(op, view));
    // A lot the Treasury owns: unbonding or withdrawing it is an act of Treasury authority,
    // acknowledged as every other Treasury act is (fixes of the independent wallet review).
    if treasury_authority(view)
        .as_ref()
        .is_some_and(|authority| is_treasury_address(view, authority, &op.owner))
    {
        warnings.push(
            Warning::new(
                "TREASURY_LOT",
                Severity::Caution,
                format!(
                    "Lot {} is owned by the Treasury: this {} is an act of Treasury authority. It moves MUT only; Bitcoin custody is separate and untouched.",
                    units::short_hex(&lot.id),
                    if unbond { "unbond" } else { "withdrawal" }
                ),
            )
            .requiring(AckKind::TreasuryAuthority),
        );
    }
    test_value_warning(view, &mut warnings);
    warnings.push(inclusion_warning(op));
    Ok(ReviewDraft {
        kind,
        schema: SCHEMA,
        title,
        summary,
        signer: me.summary(),
        authorizations,
        parties,
        destinations,
        amount,
        returned: 0,
        fee,
        net_debit,
        inputs: Vec::new(),
        conditions,
        timing: inclusion_timing(op, view, earliest),
        effects,
        warnings,
        extra_acks: vec![AckKind::Conditions],
        high_risk: true,
    })
}

// ---------------------------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------------------------

/// The owner's signature over the operation body, through the bond capability: consensus' own
/// `Operation::sign`, under the domain consensus derives from the action (BondCreate, BondUnbond
/// or BondWithdraw). The capability is granted only where `domain_for(kind, BondAction)` permits,
/// and refuses an action of another kind than the plan's.
fn authorize_operation(op: &mut Operation, signer: &KindSigner<'_>) -> Result<(), Refusal> {
    let (authorizer, _) =
        PublicKey::decode_descriptor(&op.authorizer).map_err(|_| Refusal::InvalidDescriptor)?;
    if &authorizer != signer.public(KeySlot::Primary)? {
        return Err(Refusal::NotRequiredSigner(Slot::BondOwner));
    }
    op.body()
        .map_err(|_| Refusal::Malformed("the bond operation body does not encode"))?;
    signer.bond_authorization()?.authorize_bond(op)
}

// ---------------------------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------------------------

impl OperationHandler for BondHandler {
    fn kind(&self) -> OperationKind {
        self.kind
    }
    fn recognizes(&self, raw: &[u8]) -> bool {
        decode_command(raw, self.kind).is_ok()
    }
    fn plan(
        &self,
        request: &OperationRequest,
        view: &ChainView<'_>,
        signer: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        let (lot, blocks) = match request {
            OperationRequest::BondUnbond(r) if self.kind == OperationKind::BondUnbond => {
                (r.lot, r.validity_blocks)
            }
            OperationRequest::BondWithdraw(r) if self.kind == OperationKind::BondWithdraw => {
                (r.lot, r.validity_blocks)
            }
            _ => return Err(Refusal::UnknownOperation),
        };
        plan_command(self.kind, &lot, blocks, view, signer)
    }
    fn adopt(
        &self,
        raw: &[u8],
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        let op = decode_command(raw, self.kind)?;
        if !payment::is_unsigned(&op.signature) {
            return Err(Refusal::Malformed(ALREADY_SIGNED));
        }
        if op.authorizer != me.descriptor() {
            return Err(Refusal::NotRequiredSigner(Slot::BondOwner));
        }
        me.check_current(view)?;
        assemble_command(self.kind, &op, view, me)
    }
    fn validate(&self, plan: &OperationPlan, view: &ChainView<'_>) -> Result<(), Refusal> {
        select::require_profile_for_treasury(view, plan.signer())?;
        let op = command_object(plan, self.kind)?;
        if op.authorizer != plan.signer().descriptor() {
            return Err(Refusal::NotRequiredSigner(Slot::BondOwner));
        }
        command_facts(self.kind, &op, view).map(|_| ())
    }
    fn review(&self, plan: &OperationPlan, view: &ChainView<'_>) -> Result<ReviewDraft, Refusal> {
        let op = command_object(plan, self.kind)?;
        let facts = command_facts(self.kind, &op, view)?;
        command_review(self.kind, &op, &facts, view, plan.signer())
    }
    fn explain(
        &self,
        raw: &[u8],
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<(ReviewDraft, Vec<PlanObject>), Refusal> {
        let op = decode_command(raw, self.kind)?;
        let facts = command_facts(self.kind, &op, view)?;
        Ok((
            command_review(self.kind, &op, &facts, view, me)?,
            self.unsigned_form(raw)?,
        ))
    }
    fn sign(
        &self,
        plan: &OperationPlan,
        signer: &KindSigner<'_>,
        _view: &ChainView<'_>,
    ) -> Result<SignedOperation, Refusal> {
        let mut op = command_object(plan, self.kind)?;
        authorize_operation(&mut op, signer)?;
        Ok(SignedOperation::Complete {
            kind: self.kind,
            id: operation_id(&op)?,
            bytes: encode_op(&op)?,
            validity: *plan.validity(),
            reserved: plan.inputs().to_vec(),
        })
    }
    fn unsigned_form(&self, raw: &[u8]) -> Result<Vec<PlanObject>, Refusal> {
        let op = decode_command(raw, self.kind)?;
        Ok(vec![PlanObject::new(
            label_of(self.kind),
            encode_op(&unsigned_op(&op))?,
        )])
    }
    fn describe(&self, raw: &[u8]) -> Result<Description, Refusal> {
        let op = decode_command(raw, self.kind)?;
        if !complete(&op.signature) {
            return Err(Refusal::Malformed(
                "a bond operation must be signed to be queued",
            ));
        }
        let (lot, _) = op.action.target();
        Ok(Description {
            id: operation_id(&op)?,
            complete: true,
            missing: Vec::new(),
            validity: Validity {
                created: op.envelope.first_height,
                expiry: op.envelope.last_height,
                valid_only_at: None,
                bound_to_parent: false,
            },
            reserved: vec![lot_resource(&lot)],
        })
    }
    fn check_signed(&self, signed: &SignedOperation, view: &ChainView<'_>) -> Result<(), Refusal> {
        if signed.kind() != self.kind {
            return Err(Refusal::UnknownOperation);
        }
        let op = decode_command(signed.bytes(), self.kind)?;
        let facts = command_chain(self.kind, &op, view)?;
        let lot = view
            .state()
            .bonds_v2
            .lots
            .get(&facts.lot.id)
            .ok_or(Refusal::LotUnknown)?;
        op.verify_command(view.anchor(), &view.history(), &view.state().wallets, lot)
            .map_err(consensus_refusal)
    }
    fn reconcile(&self, record: &OutboxRecord, view: &ChainView<'_>) -> Settlement {
        if let Some((height, outcome)) = view.confirmed_command_outcome(&record.id) {
            return match outcome {
                mutiny_consensus_v8::bond_ops_v2::CommandOutcome::Applied => {
                    Settlement::Confirmed(height)
                }
                mutiny_consensus_v8::bond_ops_v2::CommandOutcome::NoEffectBurned => {
                    Settlement::InputsSpent
                }
            };
        }
        if let Some(height) = view.confirmed_height(&record.id) {
            return Settlement::Confirmed(height);
        }
        let Ok(op) = decode_command(&record.bytes, self.kind) else {
            return Settlement::Pending;
        };
        let (id, sequence) = op.action.target();
        if let Some(lot) = view.state().bonds_v2.lots.get(&id) {
            if lot.0.sequence >= sequence || lot.0.status == LotStatus::Burned {
                return Settlement::InputsSpent;
            }
        }
        if view.anchor().height >= op.envelope.last_height {
            Settlement::Expired
        } else {
            Settlement::Pending
        }
    }
}
