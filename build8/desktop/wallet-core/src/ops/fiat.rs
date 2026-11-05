//! (d) Fiat-settled lock and release (phase 5B).
//!
//! `trading_v1::Action::FiatLock`: approval slots {0 seller, 1 buyer} plus the maker's offer proof
//! (exact terms: amount and payment-terms commitment); the SELLER funds it: coins of exactly the
//! seller address equal `amount + change + fee`; the amount becomes a lock record at
//! `Operation::output_id(0)` held for the buyer, change returns to the seller (output 1), the offer
//! is consumed. `trading_v1::Action::FiatRelease`: approval slots {0 buyer, 1 seller}, NO offer proof
//! (one is refused), bound to the lock (context, TradeID, ContractHash, generation, amount, fiat
//! terms, parties, created before the release's block); the BUYER pays the fee from its own coins
//! (`principal 0 + change + fee`), the locked amount is paid to the buyer (output 0), change to the
//! buyer (output 1), and the lock record is removed.
//!
//! There is NO timeout, refund or unilateral release for a fiat lock: consensus refuses a claim or a
//! refund of one (`FiatRecoveryUnspecified`), and a release needs BOTH wallets. "Disagreement may
//! leave funds locked." Every review says so, with an acknowledgement, and says that this wallet
//! verifies no fiat (or Bitcoin) settlement. `CancelTarget::FiatLock` is refused by `plan` as
//! `CANCEL_NOT_AVAILABLE`.
//!
//! The seller plans a lock (`plan(FiatLockRequest)`, signs slot 0); the buyer adopts and co-signs
//! slot 1; the maker's fill is attached with `offers::attach_fill_proof`; `offers::combine` merges.
//! The buyer plans a release (`plan(FiatReleaseRequest)`, signs slot 0); the seller co-signs slot 1.
//! Fee payers follow `Operation::fee_payer()`: the seller for a lock, the buyer for a release.
//! Independent verification: `trading_v1::verify_approval` per approval present,
//! `Operation::verify_offer` for a lock's fill, `trading_v1::prepare_batch` for a complete operation.
use super::{license_dvp, select};
use crate::{
    authorize::{SignedOperation, SignerIdentity},
    capability::KindSigner,
    context::{
        ChainClass, ChainView, is_treasury_address, require_reserve_backing, treasury_authority,
    },
    offers::{self, OfferFacts, Parsed, Sig, TradeKind},
    outbox::{OutboxRecord, Settlement, resource_key},
    plan::{
        Description, FiatLockRequest, FiatReleaseRequest, OperationHandler, OperationKind,
        OperationPlan, OperationRequest, PlanObject, RequiredSigner, Requirement,
        RequirementStatus, Slot, Validity,
    },
    refusal::Refusal,
    review::{
        AckKind, AddressLabel, Condition, Destination, DestinationRole, Effect, Fee, FeePayer,
        FeeRule, InputLine, Party, PartyRole, ReviewDraft, Severity, Timing, Warning,
    },
    units,
};
use mutiny_consensus_v8::{
    Hash,
    trading_v1::{
        self, Action, Approval, Meta, NativeLock, NativeLockKind, NativeOperation, OfferProof,
        OfferTerms, Operation, Strikes,
    },
    transactions::{EXPIRY_HORIZON, OutPoint, Output},
};
use std::collections::BTreeSet;

/// Layout version of the fiat lock and fiat release plan objects.
pub const SCHEMA: u16 = 1;
const DUST_CHANGE_ATOMS: u64 = 3_400;

pub(crate) struct FiatLockHandler;
pub(crate) struct FiatReleaseHandler;
pub(crate) static LOCK_HANDLER: FiatLockHandler = FiatLockHandler;
pub(crate) static RELEASE_HANDLER: FiatReleaseHandler = FiatReleaseHandler;

/// The handler for `kind`, registered by `ops/mod.rs`.
pub(crate) fn handler(kind: OperationKind) -> Option<&'static dyn OperationHandler> {
    match kind {
        OperationKind::FiatLock => Some(&LOCK_HANDLER),
        OperationKind::FiatRelease => Some(&RELEASE_HANDLER),
        _ => None,
    }
}

// ---------------------------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------------------------

fn requirements(
    parsed: &Parsed,
    maker: Option<Hash>,
    mine: &[u8],
    me: &SignerIdentity,
) -> Vec<Requirement> {
    let mut out: Vec<Requirement> = parsed
        .slots
        .iter()
        .map(|slot| Requirement {
            slot: Slot::Approval(slot.slot),
            signer: RequiredSigner::Wallet(slot.address),
            status: if mine.contains(&slot.slot) {
                RequirementStatus::ThisWallet
            } else {
                RequirementStatus::Counterparty
            },
        })
        .collect();
    if let Some(maker) = maker {
        out.push(Requirement {
            slot: Slot::OfferSignature,
            signer: RequiredSigner::Maker(maker),
            status: RequirementStatus::Provided,
        });
        out.push(
            offers::fill_requirement(&parsed.wire.operation, me)
                .expect("offer checked before requirements"),
        );
    }
    out
}

fn assemble(
    kind: TradeKind,
    wire: &NativeOperation,
    view: &ChainView<'_>,
    signer: &SignerIdentity,
    mine: &[u8],
) -> Result<OperationPlan, Refusal> {
    let bytes = offers::encode_native(&offers::unsigned_copy(wire))?;
    let parsed = offers::parse(&bytes, kind)?;
    let (resources, maker) = match kind {
        TradeKind::FiatLock => {
            let lock = lock_fields(&parsed.wire.operation)?;
            (
                vec![resource_key(offers::OFFER_RESOURCE, &lock.offer)],
                Some(lock.maker),
            )
        }
        _ => {
            let release = release_fields(&parsed.wire.operation)?;
            (
                vec![resource_key(offers::LOCK_RESOURCE, &release.output)],
                None,
            )
        }
    };
    let mut reserved: Vec<OutPoint> = parsed.wire.inputs.clone();
    reserved.extend(resources);
    let m = &parsed.wire.operation.meta;
    let validity = Validity {
        created: m.envelope.first_height,
        expiry: m.envelope.last_height,
        valid_only_at: None,
        bound_to_parent: false,
    };
    let plan = OperationPlan::assemble(
        kind.operation_kind(),
        SCHEMA,
        signer.clone(),
        vec![PlanObject::new(offers::OBJECT_LABEL, bytes)],
        requirements(&parsed, maker, mine, signer),
        reserved,
        validity,
        view,
    );
    crate::ops::handler(kind.operation_kind())?.validate(&plan, view)?;
    Ok(plan)
}

/// The plan's `validate`: the unsigned form only, the Treasury-profile guard (the payer's coins may
/// be Treasury coins), every unsigned rule, and every slot the plan's signer signs names its
/// descriptor.
fn validate_plan(
    plan: &OperationPlan,
    view: &ChainView<'_>,
    kind: TradeKind,
    rules: &dyn Fn(&Parsed, &ChainView<'_>, bool) -> Result<(), Refusal>,
) -> Result<(), Refusal> {
    let parsed = offers::parse_plan_object(plan.objects(), kind)?;
    select::require_profile_for_treasury(view, plan.signer())?;
    rules(&parsed, view, true)?;
    for requirement in plan.requirements() {
        if let (RequirementStatus::ThisWallet, Slot::Approval(slot)) =
            (requirement.status, requirement.slot)
        {
            let named = parsed
                .slots
                .iter()
                .find(|entry| entry.slot == slot)
                .ok_or(Refusal::Malformed("approval slot"))?;
            if named.descriptor != plan.signer().descriptor() {
                return Err(Refusal::NotRequiredSigner(Slot::Approval(slot)));
            }
        }
    }
    Ok(())
}

fn window(validity_blocks: u64, height: u64) -> Result<u64, Refusal> {
    if validity_blocks == 0 || validity_blocks > EXPIRY_HORIZON {
        return Err(Refusal::InvalidValidity);
    }
    height.checked_add(validity_blocks).ok_or(Refusal::Overflow)
}

fn classify<'v>(
    view: &'v ChainView<'_>,
    me: &'v SignerIdentity,
) -> impl Fn(&Hash) -> AddressLabel + 'v {
    let treasury = treasury_authority(view);
    move |address: &Hash| {
        if view
            .state()
            .wallets
            .authorize(*address, me.descriptor())
            .is_ok()
        {
            AddressLabel::ThisWallet
        } else if treasury
            .as_ref()
            .is_some_and(|authority| is_treasury_address(view, authority, address))
        {
            AddressLabel::Treasury
        } else {
            AddressLabel::External
        }
    }
}

/// Who signs what, with the warnings for signatures that do not verify and the list of what is still
/// missing. `names` labels slot 0 and slot 1.
fn authorizations(
    parsed: &Parsed,
    view: &ChainView<'_>,
    me: &SignerIdentity,
    names: [&str; 2],
    offer: Option<&OfferFacts>,
    warnings: &mut Vec<Warning>,
) -> (Vec<Requirement>, Vec<String>) {
    let op = &parsed.wire.operation;
    let mut out = Vec::new();
    let mut missing = Vec::new();
    // "This wallet signs" exactly where a plan or an adoption of this wallet signs.
    let mine = crate::ops::license_dvp::my_slots(parsed, view, me);
    for slot in &parsed.slots {
        let who = names[usize::from(slot.slot.min(1))];
        let pending = if mine.contains(&slot.slot) {
            RequirementStatus::ThisWallet
        } else {
            RequirementStatus::Counterparty
        };
        let status = match slot.sig {
            Sig::Missing => {
                missing.push(format!("the {who}'s approval (slot {})", slot.slot));
                pending
            }
            Sig::Present if offers::approval_valid(view, op, slot.slot) => {
                RequirementStatus::Provided
            }
            Sig::Present => {
                warnings.push(Warning::new(
                    "BAD_SIGNATURE",
                    Severity::Danger,
                    format!(
                        "The {who}'s approval (slot {}) carries a signature that does not verify. Do not rely on these bytes.",
                        slot.slot
                    ),
                ));
                missing.push(format!("the {who}'s approval (slot {})", slot.slot));
                pending
            }
        };
        out.push(Requirement {
            slot: Slot::Approval(slot.slot),
            signer: RequiredSigner::Wallet(slot.address),
            status,
        });
    }
    if let Some(offer) = offer {
        out.push(Requirement {
            slot: Slot::OfferSignature,
            signer: RequiredSigner::Maker(offer.maker),
            status: RequirementStatus::Provided,
        });
        // A fill that does not verify was refused by `offers::check_offer` (W19).
        let fill = offers::fill_requirement(&parsed.wire.operation, me)
            .expect("offer checked before review");
        if fill.status == RequirementStatus::Maker {
            missing.push("the maker's fill signature".to_string());
        }
        out.push(fill);
    }
    (out, missing)
}

/// Warnings every fiat review shares: chain class, missing parts, fee above the floor, dust change,
/// Treasury coins.
#[allow(clippy::too_many_arguments)]
fn common_warnings(
    view: &ChainView<'_>,
    warnings: &mut Vec<Warning>,
    missing: &[String],
    fee: u64,
    floor: u64,
    change_is_mine: bool,
    change: u64,
    inputs: &offers::InputFacts,
) {
    if view.class() == ChainClass::TestValue {
        warnings.push(Warning::new(
            "TEST_VALUE_CHAIN",
            Severity::Notice,
            "This is a TEST-VALUE chain: nothing here has real value.",
        ));
    }
    if !missing.is_empty() {
        warnings.push(Warning::new(
            "APPROVALS_MISSING",
            Severity::Notice,
            format!(
                "Still missing: {}. No part has any effect alone.",
                missing.join(", ")
            ),
        ));
    }
    if fee > floor {
        warnings.push(Warning::new(
            "FEE_ABOVE_MINIMUM",
            Severity::Caution,
            format!(
                "The fee is {} atoms above the minimum for this size.",
                fee - floor
            ),
        ));
    }
    if change_is_mine && change > 0 && change < DUST_CHANGE_ATOMS {
        warnings.push(Warning::new(
            "DUST_CHANGE",
            Severity::Caution,
            format!(
                "The change of {change} atoms costs about {DUST_CHANGE_ATOMS} atoms in fees to spend later."
            ),
        ));
    }
    let treasury = treasury_authority(view);
    if inputs.coins.iter().any(|(_, coin)| {
        treasury
            .as_ref()
            .is_some_and(|authority| is_treasury_address(view, authority, &coin.output.owner))
    }) {
        warnings.push(
            Warning::new(
                "TREASURY_FUNDS",
                Severity::Caution,
                "This spends Treasury funds. It moves MUT only; Bitcoin custody is separate and untouched.",
            )
            .requiring(AckKind::TreasuryAuthority),
        );
    }
}

fn input_lines(
    inputs: &offers::InputFacts,
    view: &ChainView<'_>,
    me: &SignerIdentity,
) -> Vec<InputLine> {
    inputs
        .coins
        .iter()
        .map(|(point, coin)| InputLine {
            point: point.clone(),
            atoms: coin.output.atoms,
            owned_by_signer: view
                .state()
                .wallets
                .authorize(coin.output.owner, me.descriptor())
                .is_ok(),
            coinbase: coin.coinbase,
        })
        .collect()
}

fn missing_text(missing: &[String]) -> String {
    if missing.is_empty() {
        "nothing".to_string()
    } else {
        missing.join(", ")
    }
}

fn window_condition(op: &Operation, head: u64) -> Condition {
    let window = op.meta.envelope.last_height.saturating_sub(head);
    Condition::new(
        "Validity window",
        format!(
            "Valid only for blocks {} to {} ({} blocks after the verified block; {}, approximate at the {} s target interval).",
            op.meta.envelope.first_height,
            op.meta.envelope.last_height,
            window,
            units::approx_blocks(window),
            units::TARGET_BLOCK_SECONDS
        ),
    )
}

// ---------------------------------------------------------------------------------------------
// Fiat lock
// ---------------------------------------------------------------------------------------------

struct Lock {
    offer: Hash,
    maker: Hash,
    seller: Hash,
    buyer: Hash,
    amount: u64,
    payment_terms: Hash,
    change: u64,
}

fn lock_fields(op: &Operation) -> Result<Lock, Refusal> {
    match &op.action {
        Action::FiatLock {
            offer,
            maker,
            seller,
            buyer,
            amount,
            payment_terms,
            change,
        } => Ok(Lock {
            offer: *offer,
            maker: *maker,
            seller: *seller,
            buyer: *buyer,
            amount: amount.0,
            payment_terms: *payment_terms,
            change: change.0,
        }),
        _ => Err(Refusal::Malformed("not a fiat lock")),
    }
}

fn set_lock_fee_and_change(op: &mut Operation, fee: u64, change: u64) {
    op.meta.fee = Strikes(fee);
    if let Action::FiatLock { change: slot, .. } = &mut op.action {
        *slot = Strikes(change);
    }
}

fn build_lock(
    request: &FiatLockRequest,
    view: &ChainView<'_>,
    signer: &SignerIdentity,
) -> Result<NativeOperation, Refusal> {
    signer.check_current(view)?;
    select::require_profile_for_treasury(view, signer)?;
    let offer = offers::import_offer(request.offer.as_slice(), view)?;
    let OfferTerms::Fiat {
        amount,
        payment_terms,
    } = offer.terms().clone()
    else {
        return Err(Refusal::InvalidRequest(offers::REASON_OFFER_KIND));
    };
    if request.amount_atoms != amount.0 || request.payment_terms != payment_terms {
        return Err(Refusal::InvalidRequest(
            "the request does not match the offer's amount and payment terms",
        ));
    }
    let seller = signer.address();
    let buyer = request.buyer;
    if buyer == [0; 32] {
        return Err(Refusal::InvalidRecipient);
    }
    if seller == buyer {
        return Err(Refusal::InvalidRequest(
            "the seller and the buyer are the same address",
        ));
    }
    let height = view.next_height()?;
    let expiry = window(request.validity_blocks, height)?.min(offer.expiry());
    offers::require_fillable(offer.signed_offer(), view)?;
    let buyer_descriptor = offers::counterparty_descriptor(view, buyer, &request.buyer_descriptor)?;
    let zero = crate::ops::payment::zero_signature;
    let operation = Operation {
        meta: Meta {
            context: offers::chain_context(view),
            trade: request.trade,
            contract: request.contract,
            generation: 1,
            envelope: crate::offers::envelope(view, height, expiry, Vec::new())?,
            fee: Strikes(0),
            inputs: Vec::new(),
        },
        action: Action::FiatLock {
            offer: offer.id(),
            maker: offer.maker(),
            seller,
            buyer,
            amount,
            payment_terms,
            change: Strikes(0),
        },
        approvals: vec![
            Approval {
                slot: 0,
                descriptor: signer.descriptor().to_vec(),
                signature: zero(),
            },
            Approval {
                slot: 1,
                descriptor: buyer_descriptor,
                signature: zero(),
            },
        ],
        offer_proof: Some(OfferProof {
            offer: offer.signed_offer().clone(),
            fill_signature: zero(),
        }),
    };
    let mut wire = NativeOperation {
        operation,
        inputs: Vec::new(),
    };
    let coins = offers::owner_coins(view, signer, seller)?;
    offers::fund(&mut wire, &coins, amount.0, &set_lock_fee_and_change)?;
    Ok(wire)
}

struct LockFacts {
    lock: Lock,
    inputs: offers::InputFacts,
    offer: OfferFacts,
    size: u64,
}

fn validate_lock(
    parsed: &Parsed,
    view: &ChainView<'_>,
    check_reserved: bool,
) -> Result<LockFacts, Refusal> {
    let op = &parsed.wire.operation;
    let lock = lock_fields(op)?;
    offers::require_context(view, &op.meta.context)?;
    let height = view.next_height()?;
    offers::check_meta_window(op, height)?;
    view.check_envelope(&op.meta.envelope)?;
    op.meta
        .envelope
        .check_preconditions(view.state(), &op.meta.context)
        .map_err(|_| Refusal::StaleAuthority)?;
    offers::check_fee(op, parsed.size)?;
    let id = op
        .id()
        .map_err(|_| Refusal::Malformed("operation identity"))?;
    let state = view.state();
    if offers::applied_height(state, id).is_some() {
        return Err(Refusal::Replay);
    }
    let offer = offers::check_offer(op, state, height)?;
    if lock.amount == 0 {
        return Err(Refusal::InvalidAmount);
    }
    if lock.seller == lock.buyer {
        return Err(Refusal::InvalidRequest(
            "the seller and the buyer are the same address",
        ));
    }
    if lock.buyer == [0; 32] {
        return Err(Refusal::InvalidRecipient);
    }
    offers::check_slot_authority(view, parsed)?;
    if check_reserved
        && view
            .reserved()
            .contains(&resource_key(offers::OFFER_RESOURCE, &lock.offer))
    {
        return Err(Refusal::ReservedInput);
    }
    // The payer is `Operation::fee_payer()` (the seller of a fiat lock).
    let inputs = offers::check_inputs(
        view,
        &parsed.wire,
        op.fee_payer(),
        lock.amount,
        lock.change,
        check_reserved,
    )?;
    // Consensus consumes the single-fill offer after the debit (`consume`): the same order here.
    if offer.consumed {
        return Err(Refusal::OfferConsumed);
    }
    let spent: BTreeSet<OutPoint> = parsed.wire.inputs.iter().cloned().collect();
    // The locked amount leaves the coin set: only the change is created as a coin.
    require_reserve_backing(
        view,
        &spent,
        &[Output {
            owner: lock.seller,
            atoms: lock.change,
        }],
    )?;
    Ok(LockFacts {
        lock,
        inputs,
        offer,
        size: parsed.size,
    })
}

fn review_lock(
    parsed: &Parsed,
    facts: &LockFacts,
    view: &ChainView<'_>,
    me: &SignerIdentity,
) -> Result<ReviewDraft, Refusal> {
    let op = &parsed.wire.operation;
    let lock = &facts.lock;
    let head = view.anchor().height;
    let label = classify(view, me);
    let sells = label(&lock.seller) == AddressLabel::ThisWallet;
    let buys = label(&lock.buyer) == AddressLabel::ThisWallet;
    let fee = op.meta.fee.0;
    let floor = offers::fee_floor(facts.size);
    let lock_id = op
        .output_id(0)
        .map_err(|_| Refusal::Malformed("lock identifier"))?;
    let mut warnings = Vec::new();
    let (authorizations, missing) = authorizations(
        parsed,
        view,
        me,
        ["seller", "buyer"],
        Some(&facts.offer),
        &mut warnings,
    );
    let parties = vec![
        Party {
            role: PartyRole::Seller,
            address: lock.seller,
            label: label(&lock.seller),
        },
        Party {
            role: PartyRole::Buyer,
            address: lock.buyer,
            label: label(&lock.buyer),
        },
        Party {
            role: PartyRole::Maker,
            address: lock.maker,
            label: AddressLabel::External,
        },
    ];
    let mut destinations = vec![Destination {
        role: DestinationRole::LockedOutput,
        address: lock.buyer,
        label: label(&lock.buyer),
        atoms: lock.amount,
    }];
    if sells && lock.change > 0 {
        destinations.push(Destination {
            role: DestinationRole::Change,
            address: lock.seller,
            label: AddressLabel::ThisWallet,
            atoms: lock.change,
        });
    }
    let total_in = facts.inputs.total;
    let conditions = vec![
        Condition::new(
            "Fiat lock",
            format!(
                "Locks {} from the seller {} for the buyer {} in lock {}. The lock ends ONLY through a release that BOTH the buyer and the seller approve; the protocol has no timeout, refund or unilateral release, and a claim or refund of a fiat lock is refused.",
                units::format_amount(lock.amount),
                crate::address_format::encode_for(&lock.seller, view),
                crate::address_format::encode_for(&lock.buyer, view),
                hex::encode(lock_id)
            ),
        ),
        Condition::new(
            "Payment terms",
            format!(
                "Fiat payment terms commitment {}: opaque to this wallet, which verifies no fiat or Bitcoin settlement.",
                hex::encode(lock.payment_terms)
            ),
        ),
        offers::offer_condition(&facts.offer, view),
        offers::commitments_condition(&op.meta.trade, &op.meta.contract, op.meta.generation),
        Condition::new(
            "Approvals",
            format!(
                "The seller (slot 0, wallet {}) and the buyer (slot 1, wallet {}) must both approve this exact body with their CURRENT keys, and the maker must sign the fill over the same body. Still missing: {}.",
                crate::address_format::encode_for(&lock.seller, view),
                crate::address_format::encode_for(&lock.buyer, view),
                missing_text(&missing)
            ),
        ),
        Condition::new(
            "Fee rule",
            format!(
                "The fee must be at least the greater of {} STRIKES and the encoded size of the complete signed operation (both approvals and the maker's proof included): {} bytes, so {} atoms. The seller pays it.",
                offers::TRADE_FEE_FLOOR,
                facts.size,
                floor
            ),
        ),
        Condition::new(
            "Seller inputs",
            format!(
                "All {} input coin(s) must be coins of exactly the seller address {}, unspent and mature when the lock is included, and must equal amount + change + fee exactly ({}).",
                facts.inputs.coins.len(),
                crate::address_format::encode_for(&lock.seller, view),
                units::format_mut_wide(total_in)
            ),
        ),
        window_condition(op, head),
    ];
    let mut effects = vec![
        Effect::new(
            format!(
                "Locks {} for the buyer {} in lock {}: it leaves the seller's coins at inclusion.",
                units::format_amount(lock.amount),
                crate::address_format::encode_for(&lock.buyer, view),
                hex::encode(lock_id)
            ),
            true,
        ),
        Effect::new(
            "The lock has NO unilateral exit: it ends only by a release both wallets approve. If the parties disagree, the funds may stay locked forever.",
            true,
        ),
        Effect::new(
            format!(
                "Consumes offer {}: a single-fill offer can never be filled again.",
                hex::encode(lock.offer)
            ),
            true,
        ),
        Effect::new(
            format!(
                "Spends {} coin(s) of the seller worth {}. A spent coin cannot be recovered once the lock is included.",
                facts.inputs.coins.len(),
                units::format_mut_wide(total_in)
            ),
            true,
        ),
    ];
    if lock.change > 0 {
        effects.push(Effect::new(
            format!(
                "Returns {} of change to the seller {} ({}).",
                units::format_mut(lock.change),
                crate::address_format::encode_for(&lock.seller, view),
                label(&lock.seller).text()
            ),
            false,
        ));
    }
    effects.push(Effect::new(
        format!(
            "Pays a trading fee of {} to the block producer.",
            units::format_mut(fee)
        ),
        true,
    ));
    effects.push(Effect::new(
        format!(
            "Once every party has signed, the lock cannot be revoked: it stays valid until it is included or until block {}.",
            op.meta.envelope.last_height
        ),
        true,
    ));
    warnings.push(
        Warning::new(
            "NO_UNILATERAL_EXIT",
            Severity::Danger,
            "No unilateral exit: the MUT stays locked unless BOTH parties authorize the release to the buyer. If the parties disagree, the funds may stay locked forever.",
        )
        .requiring(AckKind::NoUnilateralExit),
    );
    warnings.push(
        Warning::new(
            "FIAT_NOT_VERIFIED",
            Severity::Caution,
            "This wallet verifies no fiat (or Bitcoin) settlement: whether the fiat payment happened is for the parties to establish outside this wallet.",
        )
        .requiring(AckKind::ExternalEvidence),
    );
    warnings.push(offers::commitments_warning());
    common_warnings(
        view,
        &mut warnings,
        &missing,
        fee,
        floor,
        sells,
        lock.change,
        &facts.inputs,
    );
    let (title, summary) = if sells {
        (
            "Lock MUT for a fiat sale".to_string(),
            format!(
                "Lock {} for the buyer {} against fiat payment terms {}, with a trading fee of {}; only a release both wallets approve ends the lock.",
                units::format_mut(lock.amount),
                crate::address_format::encode_for(&lock.buyer, view),
                units::short_hex(&lock.payment_terms),
                units::format_mut(fee)
            ),
        )
    } else if buys {
        (
            "Approve a fiat-settled lock for this wallet".to_string(),
            format!(
                "The seller {} locks {} for this wallet against fiat payment terms {}; only a release both wallets approve ends the lock.",
                crate::address_format::encode_for(&lock.seller, view),
                units::format_mut(lock.amount),
                units::short_hex(&lock.payment_terms)
            ),
        )
    } else {
        (
            "Fiat lock between other wallets".to_string(),
            format!(
                "{} locks {} for {}; this wallet signs nothing in it.",
                crate::address_format::encode_for(&lock.seller, view),
                units::format_mut(lock.amount),
                crate::address_format::encode_for(&lock.buyer, view)
            ),
        )
    };
    Ok(ReviewDraft {
        kind: OperationKind::FiatLock,
        schema: SCHEMA,
        title,
        summary,
        signer: me.summary(),
        authorizations,
        parties,
        destinations,
        amount: Some(lock.amount),
        returned: if sells { lock.change } else { 0 },
        fee: Fee {
            atoms: fee,
            rule: FeeRule::TradingMinimum {
                floor: offers::TRADE_FEE_FLOOR,
            },
            payer: if sells {
                FeePayer::ThisWallet
            } else {
                FeePayer::Counterparty(op.fee_payer())
            },
            size_bytes: Some(facts.size),
        },
        net_debit: sells.then(|| total_in.saturating_sub(u128::from(lock.change))),
        inputs: input_lines(&facts.inputs, view, me),
        conditions,
        timing: Timing {
            head_height: head,
            created_height: Some(op.meta.envelope.first_height),
            expiry_height: Some(op.meta.envelope.last_height),
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

impl OperationHandler for FiatLockHandler {
    fn kind(&self) -> OperationKind {
        OperationKind::FiatLock
    }

    fn recognizes(&self, raw: &[u8]) -> bool {
        offers::recognizes(raw, TradeKind::FiatLock)
    }

    fn plan(
        &self,
        request: &OperationRequest,
        view: &ChainView<'_>,
        signer: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        let OperationRequest::FiatLock(request) = request else {
            return Err(Refusal::UnknownOperation);
        };
        let wire = build_lock(request, view, signer)?;
        // The seller funds the lock and signs slot 0 (and slot 1 too when the buyer is an address
        // of this wallet).
        let mine =
            crate::ops::license_dvp::planner_slots(&wire, TradeKind::FiatLock, view, signer, 0)?;
        assemble(TradeKind::FiatLock, &wire, view, signer, &mine)
    }

    fn adopt(
        &self,
        raw: &[u8],
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        let parsed = offers::parse(raw, TradeKind::FiatLock)?;
        let mine = license_dvp::adoptable_slots(&parsed, view, me)?;
        assemble(TradeKind::FiatLock, &parsed.wire, view, me, &mine)
    }

    fn validate(&self, plan: &OperationPlan, view: &ChainView<'_>) -> Result<(), Refusal> {
        validate_plan(
            plan,
            view,
            TradeKind::FiatLock,
            &|parsed, view, reserved| validate_lock(parsed, view, reserved).map(|_| ()),
        )
    }

    fn review(&self, plan: &OperationPlan, view: &ChainView<'_>) -> Result<ReviewDraft, Refusal> {
        let parsed = offers::parse_plan_object(plan.objects(), TradeKind::FiatLock)?;
        let facts = validate_lock(&parsed, view, true)?;
        review_lock(&parsed, &facts, view, plan.signer())
    }

    fn explain(
        &self,
        raw: &[u8],
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<(ReviewDraft, Vec<PlanObject>), Refusal> {
        let parsed = offers::parse(raw, TradeKind::FiatLock)?;
        let facts = validate_lock(&parsed, view, true)?;
        let draft = review_lock(&parsed, &facts, view, me)?;
        let unsigned = offers::encode_native(&offers::unsigned_copy(&parsed.wire))?;
        Ok((draft, vec![PlanObject::new(offers::OBJECT_LABEL, unsigned)]))
    }

    fn sign(
        &self,
        plan: &OperationPlan,
        signer: &KindSigner<'_>,
        view: &ChainView<'_>,
    ) -> Result<SignedOperation, Refusal> {
        license_dvp::approve_slots(plan, signer, view, TradeKind::FiatLock)
    }

    fn unsigned_form(&self, raw: &[u8]) -> Result<Vec<PlanObject>, Refusal> {
        offers::unsigned_objects(raw, TradeKind::FiatLock)
    }

    fn describe(&self, raw: &[u8]) -> Result<Description, Refusal> {
        let parsed = offers::parse(raw, TradeKind::FiatLock)?;
        let lock = lock_fields(&parsed.wire.operation)?;
        offers::describe_parsed(
            &parsed,
            None,
            &[resource_key(offers::OFFER_RESOURCE, &lock.offer)],
        )
    }

    fn check_signed(&self, signed: &SignedOperation, view: &ChainView<'_>) -> Result<(), Refusal> {
        offers::check_signed_trade(signed, view, TradeKind::FiatLock, &|parsed, view| {
            validate_lock(parsed, view, false).map(|_| ())
        })
    }

    fn reconcile(&self, record: &OutboxRecord, view: &ChainView<'_>) -> Settlement {
        let Ok(parsed) = offers::parse(&record.bytes, TradeKind::FiatLock) else {
            return Settlement::Pending;
        };
        if let Some(settled) = license_dvp::reconcile_trade(record, view, &parsed) {
            return settled;
        }
        let Ok(lock) = lock_fields(&parsed.wire.operation) else {
            return Settlement::Pending;
        };
        if offers::consumed(
            view.state(),
            &parsed.wire.operation.meta.context,
            lock.offer,
        ) {
            return Settlement::InputsSpent;
        }
        Settlement::Pending
    }
}

// ---------------------------------------------------------------------------------------------
// Fiat release
// ---------------------------------------------------------------------------------------------

struct Release {
    output: Hash,
    buyer: Hash,
    seller: Hash,
    amount: u64,
    payment_terms: Hash,
    change: u64,
}

fn release_fields(op: &Operation) -> Result<Release, Refusal> {
    match &op.action {
        Action::FiatRelease {
            output,
            buyer,
            seller,
            amount,
            payment_terms,
            change,
        } => Ok(Release {
            output: *output,
            buyer: *buyer,
            seller: *seller,
            amount: amount.0,
            payment_terms: *payment_terms,
            change: change.0,
        }),
        _ => Err(Refusal::Malformed("not a fiat release")),
    }
}

fn set_release_fee_and_change(op: &mut Operation, fee: u64, change: u64) {
    op.meta.fee = Strikes(fee);
    if let Action::FiatRelease { change: slot, .. } = &mut op.action {
        *slot = Strikes(change);
    }
}

/// The verified lock record `id`, or the refusal that explains why there is none to release.
fn fiat_lock(view: &ChainView<'_>, id: Hash) -> Result<(NativeLock, Hash), Refusal> {
    let lock = trading_v1::locked(view.state(), id).map_err(|_| Refusal::LockNotFound)?;
    let NativeLockKind::Fiat { terms } = lock.kind else {
        return Err(Refusal::InvalidRequest(
            "this is a hash lock: only its claim or refund applies, never a fiat release",
        ));
    };
    Ok((lock, terms))
}

fn build_release(
    request: &FiatReleaseRequest,
    view: &ChainView<'_>,
    signer: &SignerIdentity,
) -> Result<NativeOperation, Refusal> {
    signer.check_current(view)?;
    select::require_profile_for_treasury(view, signer)?;
    let (lock, terms) = fiat_lock(view, request.lock)?;
    offers::require_context(view, &lock.context)?;
    let buyer = lock.recipient;
    let seller = lock.sender;
    // The buyer plans the release: it signs slot 0 and pays the fee from its own coins.
    view.state()
        .wallets
        .authorize(buyer, signer.descriptor())
        .map_err(|_| Refusal::NotRequiredSigner(Slot::Approval(0)))?;
    let height = view.next_height()?;
    if lock.created_height >= height {
        return Err(Refusal::NotYetEligible {
            what: "The release of a lock created in the same block",
            height: lock.created_height.saturating_add(1),
        });
    }
    let expiry = window(request.validity_blocks, height)?;
    let seller_descriptor =
        offers::counterparty_descriptor(view, seller, &request.seller_descriptor)?;
    let zero = crate::ops::payment::zero_signature;
    let operation = Operation {
        meta: Meta {
            context: lock.context.clone(),
            trade: lock.trade,
            contract: lock.contract,
            generation: lock.generation,
            envelope: crate::offers::envelope(view, height, expiry, Vec::new())?,
            fee: Strikes(0),
            inputs: Vec::new(),
        },
        action: Action::FiatRelease {
            output: request.lock,
            buyer,
            seller,
            amount: lock.amount,
            payment_terms: terms,
            change: Strikes(0),
        },
        approvals: vec![
            Approval {
                slot: 0,
                descriptor: signer.descriptor().to_vec(),
                signature: zero(),
            },
            Approval {
                slot: 1,
                descriptor: seller_descriptor,
                signature: zero(),
            },
        ],
        offer_proof: None,
    };
    let mut wire = NativeOperation {
        operation,
        inputs: Vec::new(),
    };
    let coins = offers::owner_coins(view, signer, buyer)?;
    offers::fund(&mut wire, &coins, 0, &set_release_fee_and_change)?;
    Ok(wire)
}

struct ReleaseFacts {
    release: Release,
    lock: NativeLock,
    inputs: offers::InputFacts,
    size: u64,
}

fn validate_release(
    parsed: &Parsed,
    view: &ChainView<'_>,
    check_reserved: bool,
) -> Result<ReleaseFacts, Refusal> {
    let op = &parsed.wire.operation;
    let release = release_fields(op)?;
    offers::require_context(view, &op.meta.context)?;
    let height = view.next_height()?;
    offers::check_meta_window(op, height)?;
    view.check_envelope(&op.meta.envelope)?;
    op.meta
        .envelope
        .check_preconditions(view.state(), &op.meta.context)
        .map_err(|_| Refusal::StaleAuthority)?;
    offers::check_fee(op, parsed.size)?;
    let id = op
        .id()
        .map_err(|_| Refusal::Malformed("operation identity"))?;
    if offers::applied_height(view.state(), id).is_some() {
        return Err(Refusal::Replay);
    }
    let (lock, terms) = fiat_lock(view, release.output)?;
    let m = &op.meta;
    if lock.context != m.context
        || lock.trade != m.trade
        || lock.contract != m.contract
        || lock.generation != m.generation
        || lock.amount.0 != release.amount
    {
        return Err(Refusal::InvalidRequest(
            "the release does not match the lock (TradeID, ContractHash, generation or amount)",
        ));
    }
    if lock.created_height >= height {
        return Err(Refusal::NotYetEligible {
            what: "The release of a lock created in the same block",
            height: lock.created_height.saturating_add(1),
        });
    }
    if terms != release.payment_terms {
        return Err(Refusal::InvalidRequest(
            "the payment terms do not match the lock",
        ));
    }
    if lock.recipient != release.buyer || lock.sender != release.seller {
        return Err(Refusal::InvalidRequest("the parties do not match the lock"));
    }
    offers::check_slot_authority(view, parsed)?;
    if check_reserved
        && view
            .reserved()
            .contains(&resource_key(offers::LOCK_RESOURCE, &release.output))
    {
        return Err(Refusal::ReservedInput);
    }
    // The payer is `Operation::fee_payer()` (the buyer of a fiat release).
    let inputs = offers::check_inputs(
        view,
        &parsed.wire,
        op.fee_payer(),
        0,
        release.change,
        check_reserved,
    )?;
    let spent: BTreeSet<OutPoint> = parsed.wire.inputs.iter().cloned().collect();
    require_reserve_backing(
        view,
        &spent,
        &[
            Output {
                owner: release.buyer,
                atoms: release.amount,
            },
            Output {
                owner: release.buyer,
                atoms: release.change,
            },
        ],
    )?;
    Ok(ReleaseFacts {
        release,
        lock,
        inputs,
        size: parsed.size,
    })
}

fn review_release(
    parsed: &Parsed,
    facts: &ReleaseFacts,
    view: &ChainView<'_>,
    me: &SignerIdentity,
) -> Result<ReviewDraft, Refusal> {
    let op = &parsed.wire.operation;
    let release = &facts.release;
    let head = view.anchor().height;
    let label = classify(view, me);
    let buys = label(&release.buyer) == AddressLabel::ThisWallet;
    let sells = label(&release.seller) == AddressLabel::ThisWallet;
    let fee = op.meta.fee.0;
    let floor = offers::fee_floor(facts.size);
    let mut warnings = Vec::new();
    let (authorizations, missing) =
        authorizations(parsed, view, me, ["buyer", "seller"], None, &mut warnings);
    let parties = vec![
        Party {
            role: PartyRole::Buyer,
            address: release.buyer,
            label: label(&release.buyer),
        },
        Party {
            role: PartyRole::Seller,
            address: release.seller,
            label: label(&release.seller),
        },
    ];
    let mut destinations = vec![Destination {
        role: DestinationRole::ProtocolPayout,
        address: release.buyer,
        label: label(&release.buyer),
        atoms: release.amount,
    }];
    if buys && release.change > 0 {
        destinations.push(Destination {
            role: DestinationRole::Change,
            address: release.buyer,
            label: AddressLabel::ThisWallet,
            atoms: release.change,
        });
    }
    let total_in = facts.inputs.total;
    let conditions = vec![
        Condition::new(
            "Lock",
            format!(
                "Lock {} holds {} from the seller {} for the buyer {}, created at block {}, against fiat payment terms {} (opaque to this wallet).",
                hex::encode(release.output),
                units::format_amount(release.amount),
                crate::address_format::encode_for(&release.seller, view),
                crate::address_format::encode_for(&release.buyer, view),
                facts.lock.created_height,
                hex::encode(release.payment_terms)
            ),
        ),
        Condition::new(
            "Release rule",
            "This release is the only way a fiat lock ends: the buyer (slot 0) and the seller (slot 1) must both approve this exact body with their CURRENT keys. No timeout, refund or unilateral release exists, and a maker's offer proof is not allowed here.",
        ),
        offers::commitments_condition(&op.meta.trade, &op.meta.contract, op.meta.generation),
        Condition::new(
            "Approvals",
            format!("Still missing: {}.", missing_text(&missing)),
        ),
        Condition::new(
            "Fee rule",
            format!(
                "The fee must be at least the greater of {} STRIKES and the encoded size of the complete signed operation (both approvals included): {} bytes, so {} atoms. The buyer pays it from its own coins; the locked amount is paid in full.",
                offers::TRADE_FEE_FLOOR,
                facts.size,
                floor
            ),
        ),
        Condition::new(
            "Buyer inputs",
            format!(
                "All {} input coin(s) must be coins of exactly the buyer address {}, unspent and mature when the release is included, and must equal change + fee exactly ({}).",
                facts.inputs.coins.len(),
                crate::address_format::encode_for(&release.buyer, view),
                units::format_mut_wide(total_in)
            ),
        ),
        window_condition(op, head),
    ];
    let mut effects = vec![
        Effect::new(
            format!(
                "Releases lock {}: its {} is paid to the buyer {} at inclusion and the lock ends for good.",
                hex::encode(release.output),
                units::format_amount(release.amount),
                crate::address_format::encode_for(&release.buyer, view)
            ),
            true,
        ),
        Effect::new(
            format!(
                "Spends {} coin(s) of the buyer worth {} for the fee and change. A spent coin cannot be recovered once the release is included.",
                facts.inputs.coins.len(),
                units::format_mut_wide(total_in)
            ),
            true,
        ),
    ];
    if release.change > 0 {
        effects.push(Effect::new(
            format!(
                "Returns {} of change to the buyer {} ({}).",
                units::format_mut(release.change),
                crate::address_format::encode_for(&release.buyer, view),
                label(&release.buyer).text()
            ),
            false,
        ));
    }
    effects.push(Effect::new(
        format!(
            "Pays a trading fee of {} to the block producer.",
            units::format_mut(fee)
        ),
        true,
    ));
    effects.push(Effect::new(
        format!(
            "Once both wallets have signed, the release cannot be revoked: it stays valid until it is included or until block {}.",
            op.meta.envelope.last_height
        ),
        true,
    ));
    if sells {
        effects.push(Effect::new(
            format!(
                "This wallet gives up the locked {} for good.",
                units::format_amount(release.amount)
            ),
            true,
        ));
    }
    warnings.push(if sells {
        Warning::new(
            "FIAT_NOT_VERIFIED",
            Severity::Danger,
            "Approve only after the fiat payment has reached you through your own channels: this wallet cannot verify it, and the release cannot be undone.",
        )
        .requiring(AckKind::ExternalEvidence)
    } else {
        Warning::new(
            "FIAT_NOT_VERIFIED",
            Severity::Caution,
            "This wallet verifies no fiat (or Bitcoin) settlement; the seller decides whether to approve the release.",
        )
        .requiring(AckKind::ExternalEvidence)
    });
    warnings.push(
        Warning::new(
            "NO_UNILATERAL_EXIT",
            Severity::Caution,
            "The release needs both wallets: if either refuses to sign, the MUT stays locked.",
        )
        .requiring(AckKind::NoUnilateralExit),
    );
    warnings.push(offers::commitments_warning());
    common_warnings(
        view,
        &mut warnings,
        &missing,
        fee,
        floor,
        buys,
        release.change,
        &facts.inputs,
    );
    let (title, summary) = if buys {
        (
            "Release a fiat lock to this wallet".to_string(),
            format!(
                "Release lock {} so that its {} is paid to this wallet, with a trading fee of {} paid by this wallet; the seller {} must approve too.",
                units::short_hex(&release.output),
                units::format_mut(release.amount),
                units::format_mut(fee),
                crate::address_format::encode_for(&release.seller, view)
            ),
        )
    } else if sells {
        (
            "Release a fiat lock to the buyer".to_string(),
            format!(
                "Release lock {}: its {} is paid to the buyer {}. Approve only after you received the fiat payment.",
                units::short_hex(&release.output),
                units::format_mut(release.amount),
                crate::address_format::encode_for(&release.buyer, view)
            ),
        )
    } else {
        (
            "Fiat release between other wallets".to_string(),
            format!(
                "Lock {} pays {} to {}; this wallet signs nothing in it.",
                units::short_hex(&release.output),
                units::format_mut(release.amount),
                crate::address_format::encode_for(&release.buyer, view)
            ),
        )
    };
    Ok(ReviewDraft {
        kind: OperationKind::FiatRelease,
        schema: SCHEMA,
        title,
        summary,
        signer: me.summary(),
        authorizations,
        parties,
        destinations,
        amount: Some(release.amount),
        returned: if buys { release.change } else { 0 },
        fee: Fee {
            atoms: fee,
            rule: FeeRule::TradingMinimum {
                floor: offers::TRADE_FEE_FLOOR,
            },
            payer: if buys {
                FeePayer::ThisWallet
            } else {
                FeePayer::Counterparty(op.fee_payer())
            },
            size_bytes: Some(facts.size),
        },
        net_debit: buys.then(|| total_in.saturating_sub(u128::from(release.change))),
        inputs: input_lines(&facts.inputs, view, me),
        conditions,
        timing: Timing {
            head_height: head,
            created_height: Some(op.meta.envelope.first_height),
            expiry_height: Some(op.meta.envelope.last_height),
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

impl OperationHandler for FiatReleaseHandler {
    fn kind(&self) -> OperationKind {
        OperationKind::FiatRelease
    }

    fn recognizes(&self, raw: &[u8]) -> bool {
        offers::recognizes(raw, TradeKind::FiatRelease)
    }

    fn plan(
        &self,
        request: &OperationRequest,
        view: &ChainView<'_>,
        signer: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        let OperationRequest::FiatRelease(request) = request else {
            return Err(Refusal::UnknownOperation);
        };
        let wire = build_release(request, view, signer)?;
        // The buyer pays the fee and signs slot 0 (and slot 1 too when the seller is an address of
        // this wallet).
        let mine =
            crate::ops::license_dvp::planner_slots(&wire, TradeKind::FiatRelease, view, signer, 0)?;
        assemble(TradeKind::FiatRelease, &wire, view, signer, &mine)
    }

    fn adopt(
        &self,
        raw: &[u8],
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        let parsed = offers::parse(raw, TradeKind::FiatRelease)?;
        let mine = license_dvp::adoptable_slots(&parsed, view, me)?;
        assemble(TradeKind::FiatRelease, &parsed.wire, view, me, &mine)
    }

    fn validate(&self, plan: &OperationPlan, view: &ChainView<'_>) -> Result<(), Refusal> {
        validate_plan(
            plan,
            view,
            TradeKind::FiatRelease,
            &|parsed, view, reserved| validate_release(parsed, view, reserved).map(|_| ()),
        )
    }

    fn review(&self, plan: &OperationPlan, view: &ChainView<'_>) -> Result<ReviewDraft, Refusal> {
        let parsed = offers::parse_plan_object(plan.objects(), TradeKind::FiatRelease)?;
        let facts = validate_release(&parsed, view, true)?;
        review_release(&parsed, &facts, view, plan.signer())
    }

    fn explain(
        &self,
        raw: &[u8],
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<(ReviewDraft, Vec<PlanObject>), Refusal> {
        let parsed = offers::parse(raw, TradeKind::FiatRelease)?;
        let facts = validate_release(&parsed, view, true)?;
        let draft = review_release(&parsed, &facts, view, me)?;
        let unsigned = offers::encode_native(&offers::unsigned_copy(&parsed.wire))?;
        Ok((draft, vec![PlanObject::new(offers::OBJECT_LABEL, unsigned)]))
    }

    fn sign(
        &self,
        plan: &OperationPlan,
        signer: &KindSigner<'_>,
        view: &ChainView<'_>,
    ) -> Result<SignedOperation, Refusal> {
        license_dvp::approve_slots(plan, signer, view, TradeKind::FiatRelease)
    }

    fn unsigned_form(&self, raw: &[u8]) -> Result<Vec<PlanObject>, Refusal> {
        offers::unsigned_objects(raw, TradeKind::FiatRelease)
    }

    fn describe(&self, raw: &[u8]) -> Result<Description, Refusal> {
        let parsed = offers::parse(raw, TradeKind::FiatRelease)?;
        let release = release_fields(&parsed.wire.operation)?;
        offers::describe_parsed(
            &parsed,
            None,
            &[resource_key(offers::LOCK_RESOURCE, &release.output)],
        )
    }

    fn check_signed(&self, signed: &SignedOperation, view: &ChainView<'_>) -> Result<(), Refusal> {
        offers::check_signed_trade(signed, view, TradeKind::FiatRelease, &|parsed, view| {
            validate_release(parsed, view, false).map(|_| ())
        })
    }

    fn reconcile(&self, record: &OutboxRecord, view: &ChainView<'_>) -> Settlement {
        let Ok(parsed) = offers::parse(&record.bytes, TradeKind::FiatRelease) else {
            return Settlement::Pending;
        };
        if let Some(settled) = license_dvp::reconcile_trade(record, view, &parsed) {
            return settled;
        }
        let Ok(release) = release_fields(&parsed.wire.operation) else {
            return Settlement::Pending;
        };
        // The lock is gone without this release being applied: something else ended it.
        if trading_v1::locked(view.state(), release.output).is_err() {
            return Settlement::InputsSpent;
        }
        Settlement::Pending
    }
}
