//! (b) License purchase and transfer through delivery-versus-payment (phase 5B).
//!
//! The protocol operation is `trading_v1::Action::LicenseDvp` inside a `NativeOperation`
//! (`trading_v1` `apply_one`, run by `prepare_batch` / `prepare_candidate_phase`). At the block
//! height `H` it is included in, consensus requires: the operation window `created <= H <= expiry`;
//! `fee >= max(240, wire length)`; not applied before; approval slots exactly {0 seller, 1 buyer};
//! the maker's offer proof (`verify_offer(H)`: same context, offer id and maker, offer window, EXACT
//! terms License + generation + price, offer signature, fill signature over the exact body);
//! `price > 0`, `seller != buyer`; the License exists, belongs to the
//! context's Genesis and is owned by exactly `seller`; the generation named equals the License's
//! (`license_generation`) and the last buyer's rights have started; each approval authorized
//! against the PARENT wallet book (`verify_approval`); exact signed LicenseEntitlements and
//! LicenseAssignment facts (including a pending assignment if present), and a non-zero
//! TradeID and ContractHash (`Book::transfer_candidate`); the buyer's coins, all in the current
//! authorized lineage of the buyer, created before `H` and mature, equal `price + change + fee`; the single-fill offer not yet
//! consumed. Effects: the price is credited to the SIGNED `payment_destination` (output 0), change to
//! the buyer (output 1), the offer is consumed, the License changes owner, its native generation and
//! assignment sequence rise by one, its Worker is detached, and the new owner's rights start at
//! `H + 1` (the reward of block `H` stays with the parent-state owner).
//!
//! The seller (slot 0) and buyer (slot 1) sign settlement approvals. One of these current
//! WalletOwners is also the maker and signs a distinct typed TradeFill over the same exact body.
//! The BUYER builds the body: it chooses
//! the inputs, fee and change. It plans with `plan(LicenseDvpRequest)`, which imports and verifies
//! the maker's offer, reads the License, its current generation and the seller's current descriptor
//! from verified state, selects coins from its authorized lineage, fixes the fee from the
//! placeholder form (see `offers`), signs slot 1 and gets a `SignedOperation::Partial` it exchanges
//! as a `PartialApproval` (Q12). The SELLER explains the buyer's part (`explain` /
//! `PartialApproval::explain_for`: a seller-specific review), adopts it (`adopt_for`) and co-signs
//! slot 0 and its maker fill if required. An external maker fill proof is attached with
//! `offers::attach_fill_proof`; the parts are
//! merged with `offers::combine`, which verifies everything through `trading_v1::prepare_batch`.
//!
//! Finite signed validity: the exact canonical reference, inclusion bounds and entitlement and
//! assignment facts survive a retry unchanged. Every new head clears an outstanding approval and
//! requires a fresh review; already-signed bytes retain their original window and preconditions.
//!
//! Independent verification of a signed result: `trading_v1::verify_approval` for every approval
//! present, `Operation::verify_offer` for the fill, and `trading_v1::prepare_batch` with
//! `CandidatePolicy::native_denomination_locked()` for a complete operation.
use super::select;
use crate::{
    authorize::{SignedOperation, SignerIdentity},
    capability::KindSigner,
    context::{
        ChainClass, ChainView, is_treasury_address, require_reserve_backing, treasury_authority,
    },
    offers::{self, OfferFacts, Parsed, Sig, TradeKind},
    outbox::{OutboxRecord, Settlement, resource_key},
    plan::{
        Description, LicenseDvpRequest, OperationHandler, OperationKind, OperationPlan,
        OperationRequest, PlanObject, RequiredSigner, Requirement, RequirementStatus, Slot,
        Validity,
    },
    refusal::{ContextField, Refusal},
    review::{
        AckKind, AddressLabel, Condition, Destination, DestinationRole, Effect, Fee, FeePayer,
        FeeRule, InputLine, Party, PartyRole, ReviewDraft, Severity, Timing, Warning,
    },
    units,
};
use mutiny_consensus_v8::{
    Hash,
    licenses::LicenseRecord,
    trading_v1::{
        self, Action, Approval, Meta, NativeOperation, NativeRecord, OfferProof, OfferTerms,
        Operation, Strikes,
    },
    transactions::{OutPoint, Output},
};
use std::collections::BTreeSet;

/// Layout version of the License DvP plan object.
pub const SCHEMA: u16 = 1;
/// Change below this many atoms costs more in fees to spend later than it is worth (one more
/// signed input is roughly this many bytes).
const DUST_CHANGE_ATOMS: u64 = 3_400;

pub(crate) struct LicenseDvpHandler;
pub(crate) static HANDLER: LicenseDvpHandler = LicenseDvpHandler;

/// The handler for `kind`, registered by `ops/mod.rs`.
pub(crate) fn handler(kind: OperationKind) -> Option<&'static dyn OperationHandler> {
    (kind == OperationKind::LicenseDvp).then_some(&HANDLER as &'static dyn OperationHandler)
}

// ---------------------------------------------------------------------------------------------
// Fields
// ---------------------------------------------------------------------------------------------

/// The fields of a `LicenseDvp` action.
struct Dvp {
    offer: Hash,
    maker: Hash,
    license: Hash,
    generation: u64,
    seller: Hash,
    buyer: Hash,
    price: u64,
    destination: Hash,
    change: u64,
}

fn fields(op: &Operation) -> Result<Dvp, Refusal> {
    match &op.action {
        Action::LicenseDvp {
            offer,
            maker,
            license,
            license_generation,
            seller,
            buyer,
            price,
            payment_destination,
            change,
        } => Ok(Dvp {
            offer: *offer,
            maker: *maker,
            license: *license,
            generation: *license_generation,
            seller: *seller,
            buyer: *buyer,
            price: price.0,
            destination: *payment_destination,
            change: change.0,
        }),
        _ => Err(Refusal::Malformed("not a License sale")),
    }
}

fn set_fee_and_change(op: &mut Operation, fee: u64, change: u64) {
    op.meta.fee = Strikes(fee);
    if let Action::LicenseDvp { change: slot, .. } = &mut op.action {
        *slot = Strikes(change);
    }
}

/// The coins and resources a License sale consumes: the buyer's inputs, the License (a License on
/// offer cannot be in two plans) and the single-fill offer.
fn resources(dvp: &Dvp) -> [OutPoint; 2] {
    [
        resource_key(offers::LICENSE_RESOURCE, &dvp.license),
        resource_key(offers::OFFER_RESOURCE, &dvp.offer),
    ]
}

/// The generation the License's last native transfer recorded and the height from which that
/// buyer's rights started (`None` for a License never transferred, generation 1).
fn transfer_record(
    state: &mutiny_consensus_v8::execution::State,
    license: Hash,
) -> Result<(u64, Option<u64>), Refusal> {
    let generation = trading_v1::license_generation(state, license).map_err(|_| {
        Refusal::Malformed("the License's native transfer record is not a License record")
    })?;
    let rights = match state
        .protocol_records
        .get(&trading_v1::record_key(4, license))
    {
        Some(raw) => match NativeRecord::decode(raw) {
            Ok((
                _,
                NativeRecord::License {
                    rights_from_height, ..
                },
            )) => Some(rights_from_height),
            _ => {
                return Err(Refusal::Malformed(
                    "the License's native transfer record is not a License record",
                ));
            }
        },
        None => None,
    };
    Ok((generation, rights))
}

// ---------------------------------------------------------------------------------------------
// Planning (the buyer builds the body)
// ---------------------------------------------------------------------------------------------

fn build(
    request: &LicenseDvpRequest,
    view: &ChainView<'_>,
    signer: &SignerIdentity,
) -> Result<NativeOperation, Refusal> {
    if request
        .validity_blocks
        .is_some_and(|b| b == 0 || b > mutiny_consensus_v8::transactions::EXPIRY_HORIZON)
    {
        return Err(Refusal::InvalidValidity);
    }
    signer.check_current(view)?;
    select::require_profile_for_treasury(view, signer)?;
    let offer = offers::import_offer(request.offer.as_slice(), view)?;
    let OfferTerms::License {
        license,
        generation,
        price,
    } = offer.terms().clone()
    else {
        return Err(Refusal::InvalidRequest(offers::REASON_OFFER_KIND));
    };
    if license != request.license {
        return Err(Refusal::InvalidRequest("the offer is for another License"));
    }
    let state = view.state();
    let record = state
        .licenses_v2
        .license(license)
        .ok_or(Refusal::InvalidRequest(
            "the License does not exist on this chain",
        ))?;
    if record.genesis != view.context().genesis {
        return Err(Refusal::WrongContext(ContextField::Genesis));
    }
    let (current, rights) = transfer_record(state, license)?;
    if generation != current {
        return Err(Refusal::LicenseGenerationStale);
    }
    let height = view.next_height()?;
    if let Some(rights) = rights
        && rights > height
    {
        return Err(Refusal::NotYetEligible {
            what: "A sale by the License's last buyer",
            height: rights,
        });
    }
    let seller = record.owner;
    let buyer = signer.address();
    if seller == buyer {
        return Err(Refusal::InvalidRequest(
            "the seller and the buyer are the same address",
        ));
    }
    offers::require_fillable(offer.signed_offer(), view)?;
    if request.trade == [0; 32] || request.contract == [0; 32] {
        return Err(Refusal::InvalidRequest(
            "a License sale needs a non-zero TradeID and ContractHash",
        ));
    }
    let destination = request.payment_destination.unwrap_or(seller);
    if destination == [0; 32] {
        return Err(Refusal::InvalidRecipient);
    }

    let seller_descriptor =
        offers::counterparty_descriptor(view, seller, &request.seller_descriptor)?;
    let zero = crate::ops::payment::zero_signature;
    let operation = Operation {
        meta: Meta {
            context: offers::chain_context(view),
            trade: request.trade,
            contract: request.contract,
            generation: 1,
            // The reviewed finite inclusion window is capped by the signed maker offer.
            envelope: crate::offers::envelope(
                view,
                height,
                height
                    .checked_add(request.validity_blocks.unwrap_or(1))
                    .ok_or(Refusal::Overflow)?
                    .min(offer.expiry()),
                vec![
                    mutiny_consensus_v8::op_envelope_v1::entitlement_facts(state, license),
                    mutiny_consensus_v8::op_envelope_v1::assignment_facts(state, license)
                        .map_err(|_| Refusal::PendingAssignmentOrLock)?,
                ],
            )?,
            fee: Strikes(0),
            inputs: Vec::new(),
        },
        action: Action::LicenseDvp {
            offer: offer.id(),
            maker: offer.maker(),
            license,
            license_generation: generation,
            seller,
            buyer,
            price,
            payment_destination: destination,
            change: Strikes(0),
        },
        approvals: vec![
            Approval {
                slot: 0,
                descriptor: seller_descriptor,
                signature: zero(),
            },
            Approval {
                slot: 1,
                descriptor: signer.descriptor().to_vec(),
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
    let coins = offers::owner_coins(view, signer, buyer)?;
    offers::fund(&mut wire, &coins, price.0, &set_fee_and_change)?;
    Ok(wire)
}

/// The requirements of a plan whose signer signs the approval slots in `mine`.
fn requirements(
    parsed: &Parsed,
    maker: Hash,
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
    out.push(Requirement {
        slot: Slot::OfferSignature,
        signer: RequiredSigner::Maker(maker),
        status: RequirementStatus::Provided,
    });
    out.push(
        offers::fill_requirement(&parsed.wire.operation, me)
            .expect("offer checked before requirements"),
    );
    out
}

/// The immutable plan of the UNSIGNED form of `wire` for `signer`, who signs the slots in `mine`.
fn assemble(
    wire: &NativeOperation,
    view: &ChainView<'_>,
    signer: &SignerIdentity,
    mine: &[u8],
) -> Result<OperationPlan, Refusal> {
    let bytes = offers::encode_native(&offers::unsigned_copy(wire))?;
    let parsed = offers::parse(&bytes, TradeKind::LicenseDvp)?;
    let dvp = fields(&parsed.wire.operation)?;
    let mut reserved: Vec<OutPoint> = parsed.wire.inputs.clone();
    reserved.extend(resources(&dvp));
    let m = &parsed.wire.operation.meta;
    let validity = Validity {
        created: m.envelope.first_height,
        expiry: m.envelope.last_height,
        valid_only_at: None,
        bound_to_parent: false,
    };
    let plan = OperationPlan::assemble(
        OperationKind::LicenseDvp,
        SCHEMA,
        signer.clone(),
        vec![PlanObject::new(offers::OBJECT_LABEL, bytes)],
        requirements(&parsed, dvp.maker, mine, signer),
        reserved,
        validity,
        view,
    );
    HANDLER.validate(&plan, view)?;
    Ok(plan)
}

// ---------------------------------------------------------------------------------------------
// Validation (pre-signing mirror of consensus)
// ---------------------------------------------------------------------------------------------

struct Facts {
    dvp: Dvp,
    record: LicenseRecord,
    inputs: offers::InputFacts,
    offer: OfferFacts,
    size: u64,
}

/// Every consensus rule of a License sale that needs no signature, against the CURRENT view (the
/// view's state is the parent of the block the sale must be included in). With `check_reserved`,
/// coins, the License and the offer held by another pending operation are refused too.
fn validate_dvp(
    parsed: &Parsed,
    view: &ChainView<'_>,
    check_reserved: bool,
) -> Result<Facts, Refusal> {
    let op = &parsed.wire.operation;
    let dvp = fields(op)?;
    offers::require_context(view, &op.meta.context)?;
    let height = view.next_height()?;
    offers::check_meta_window(op, height)?;
    view.check_envelope(&op.meta.envelope)?;
    offers::check_fee(op, parsed.size)?;
    let id = op
        .id()
        .map_err(|_| Refusal::Malformed("operation identity"))?;
    let state = view.state();
    if offers::applied_height(state, id).is_some() {
        return Err(Refusal::Replay);
    }
    let offer = offers::check_offer(op, state, height)?;
    if dvp.price == 0 {
        return Err(Refusal::InvalidAmount);
    }
    if dvp.seller == dvp.buyer {
        return Err(Refusal::InvalidRequest(
            "the seller and the buyer are the same address",
        ));
    }
    // Wallet policy (stricter than consensus, as for payments): never pay the price to the zero
    // address.
    if dvp.destination == [0; 32] {
        return Err(Refusal::InvalidRecipient);
    }
    let record = state
        .licenses_v2
        .license(dvp.license)
        .ok_or(Refusal::InvalidRequest(
            "the License does not exist on this chain",
        ))?
        .clone();
    if record.genesis != op.meta.context.genesis {
        return Err(Refusal::WrongContext(ContextField::Genesis));
    }
    if record.owner != dvp.seller {
        return Err(Refusal::LicenseNotOwned);
    }
    let (generation, rights) = transfer_record(state, dvp.license)?;
    if let Some(rights) = rights
        && rights > height
    {
        return Err(Refusal::NotYetEligible {
            what: "A sale by the License's last buyer",
            height: rights,
        });
    }
    if generation != dvp.generation {
        return Err(Refusal::LicenseGenerationStale);
    }
    offers::check_slot_authority(view, parsed)?;
    let expected = vec![
        mutiny_consensus_v8::op_envelope_v1::entitlement_facts(state, dvp.license),
        mutiny_consensus_v8::op_envelope_v1::assignment_facts(state, dvp.license)
            .map_err(|_| Refusal::LicenseGenerationStale)?,
    ];
    if op.meta.envelope.preconditions != expected {
        return Err(Refusal::LicenseGenerationStale);
    }
    op.meta
        .envelope
        .check_preconditions(state, &op.meta.context)
        .map_err(|_| Refusal::LicenseGenerationStale)?;
    if op.meta.trade == [0; 32] || op.meta.contract == [0; 32] {
        return Err(Refusal::InvalidRequest(
            "a License sale needs a non-zero TradeID and ContractHash",
        ));
    }
    if check_reserved
        && resources(&dvp)
            .iter()
            .any(|key| view.reserved().contains(key))
    {
        return Err(Refusal::ReservedInput);
    }
    // The payer is `Operation::fee_payer()`, the mirror of the `debit` call of `apply_one` (the buyer).
    let inputs = offers::check_inputs(
        view,
        &parsed.wire,
        op.fee_payer(),
        dvp.price,
        dvp.change,
        check_reserved,
    )?;
    // Consensus consumes the single-fill offer after the debit (`consume`): the same order here.
    if offer.consumed {
        return Err(Refusal::OfferConsumed);
    }
    let spent: BTreeSet<OutPoint> = parsed.wire.inputs.iter().cloned().collect();
    require_reserve_backing(
        view,
        &spent,
        &[
            Output {
                owner: dvp.destination,
                atoms: dvp.price,
            },
            Output {
                owner: dvp.buyer,
                atoms: dvp.change,
            },
        ],
    )?;
    Ok(Facts {
        dvp,
        record,
        inputs,
        offer,
        size: parsed.size,
    })
}

// ---------------------------------------------------------------------------------------------
// Review
// ---------------------------------------------------------------------------------------------

/// One unclaimed dividend award of a License.
struct AwardLine {
    epoch: u64,
    deadline: u64,
    share: u64,
    remaining: u64,
    claims: u64,
}

/// Unclaimed dividend awards of `license` in verified state (Q9).
fn unclaimed_awards(
    state: &mutiny_consensus_v8::execution::State,
    license: Hash,
) -> Vec<AwardLine> {
    state
        .dividends
        .ledger()
        .awards_iter()
        .filter_map(|award| {
            award
                .account(&license)
                .filter(|account| account.remaining > 0)
                .map(|account| AwardLine {
                    epoch: award.epoch(),
                    deadline: award.deadline(),
                    share: account.share,
                    remaining: account.remaining,
                    claims: account.claims,
                })
        })
        .collect()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Buyer,
    Seller,
    Both,
    Observer,
}

fn build_review(
    parsed: &Parsed,
    facts: &Facts,
    view: &ChainView<'_>,
    me: &SignerIdentity,
) -> Result<ReviewDraft, Refusal> {
    let op = &parsed.wire.operation;
    let dvp = &facts.dvp;
    let record = &facts.record;
    let state = view.state();
    let head = view.anchor().height;
    let height = view.next_height()?;
    let treasury = treasury_authority(view);
    let controls = |address: &Hash| state.wallets.authorize(*address, me.descriptor()).is_ok();
    let classify = |address: &Hash| -> AddressLabel {
        if controls(address) {
            AddressLabel::ThisWallet
        } else if treasury
            .as_ref()
            .is_some_and(|authority| is_treasury_address(view, authority, address))
        {
            AddressLabel::Treasury
        } else {
            AddressLabel::External
        }
    };
    let role = match (controls(&dvp.seller), controls(&dvp.buyer)) {
        (true, true) => Role::Both,
        (true, false) => Role::Seller,
        (false, true) => Role::Buyer,
        (false, false) => Role::Observer,
    };
    let buys = matches!(role, Role::Buyer | Role::Both);
    let sells = matches!(role, Role::Seller | Role::Both);
    let fee = op.meta.fee.0;
    let floor = offers::fee_floor(facts.size);

    // ---- who signs what, and what is still missing
    let mut warnings = Vec::new();
    let mut missing: Vec<String> = Vec::new();
    let mut authorizations = Vec::new();
    // "This wallet signs" exactly where a plan or an adoption of this wallet signs: the slots whose
    // descriptor is its current one (an address it controls under another descriptor is not).
    let mine = my_slots(parsed, view, me);
    for slot in &parsed.slots {
        let who = if slot.slot == 0 { "seller" } else { "buyer" };
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
        authorizations.push(Requirement {
            slot: Slot::Approval(slot.slot),
            signer: RequiredSigner::Wallet(slot.address),
            status,
        });
    }
    authorizations.push(Requirement {
        slot: Slot::OfferSignature,
        signer: RequiredSigner::Maker(dvp.maker),
        status: RequirementStatus::Provided,
    });
    // A fill that does not verify was refused by `offers::check_offer` (W19).
    let fill = offers::fill_requirement(op, me)?;
    if fill.status == RequirementStatus::Maker {
        missing.push("the maker's fill signature".to_string());
    }
    authorizations.push(fill);

    // ---- parties and money
    let parties = vec![
        Party {
            role: PartyRole::Seller,
            address: dvp.seller,
            label: classify(&dvp.seller),
        },
        Party {
            role: PartyRole::Buyer,
            address: dvp.buyer,
            label: classify(&dvp.buyer),
        },
        Party {
            role: PartyRole::Maker,
            address: dvp.maker,
            label: AddressLabel::External,
        },
    ];
    let destination_label = classify(&dvp.destination);
    let mut destinations = vec![Destination {
        role: DestinationRole::LicensePayment,
        address: dvp.destination,
        label: destination_label,
        atoms: dvp.price,
    }];
    if buys && dvp.change > 0 {
        destinations.push(Destination {
            role: DestinationRole::Change,
            address: dvp.buyer,
            label: classify(&dvp.buyer),
            atoms: dvp.change,
        });
    }
    let inputs: Vec<InputLine> = facts
        .inputs
        .coins
        .iter()
        .map(|(point, coin)| InputLine {
            point: point.clone(),
            atoms: coin.output.atoms,
            owned_by_signer: controls(&coin.output.owner),
            coinbase: coin.coinbase,
        })
        .collect();
    let total_in = facts.inputs.total;
    let fee_row = Fee {
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
    };
    let net_debit = buys.then(|| total_in.saturating_sub(u128::from(dvp.change)));

    // ---- conditions
    let dividends_active = state.dividends.is_active();
    let status = if dividends_active {
        let activation = state.licenses_v2.dividend_activation_epoch(dvp.license);
        let view_status = state
            .dividends
            .view(dvp.license, record.owner, activation)
            .status;
        format!(
            "{}; dividend activation {}",
            match view_status {
                mutiny_consensus_v8::dividends_v1::Status::Active => "active",
                mutiny_consensus_v8::dividends_v1::Status::Suspended => "suspended",
                mutiny_consensus_v8::dividends_v1::Status::Revoked => "revoked",
            },
            match activation {
                Some(epoch) => format!("from epoch {epoch}"),
                None => "none".to_string(),
            }
        )
    } else {
        "dividends are not active on this chain".to_string()
    };
    let worker = record
        .active_worker
        .map_or_else(|| "none".to_string(), hex::encode);
    let mut conditions = vec![
        Condition::new(
            "License",
            format!(
                "License {} (index {}, issued at block {}); current native generation {}; recorded owner {}; current Worker {}; Worker assignment sequence {}; dividend status {}.",
                hex::encode(dvp.license),
                record.index,
                record.issue_height,
                dvp.generation,
                crate::address_format::encode_for(&record.owner, view),
                worker,
                record.assignment_sequence,
                status
            ),
        ),
        Condition::new(
            "Inclusion rule",
            format!(
                "Signed inclusion heights {} through {}; canonical reference height {} block {}. A retry never extends or rebases this window. Changes to the exact entitlement or assignment facts invalidate it.",
                op.meta.envelope.first_height,
                op.meta.envelope.last_height,
                op.meta.envelope.reference_height,
                hex::encode(op.meta.envelope.reference_block)
            ),
        ),
        offers::offer_condition(&facts.offer, view),
        offers::commitments_condition(&op.meta.trade, &op.meta.contract, op.meta.generation),
        Condition::new(
            "Approvals",
            format!(
                "The seller (slot 0, wallet {}) and the buyer (slot 1, wallet {}) must both approve this exact body with their CURRENT keys, and the maker must sign the fill over the same body; no part has any effect alone. Still missing: {}.",
                crate::address_format::encode_for(&dvp.seller, view),
                crate::address_format::encode_for(&dvp.buyer, view),
                if missing.is_empty() {
                    "nothing".to_string()
                } else {
                    missing.join(", ")
                }
            ),
        ),
        Condition::new(
            "Payment destination",
            if dvp.destination == dvp.seller {
                format!(
                    "The price goes to {}, the seller's own address, as the seller signs it.",
                    crate::address_format::encode_for(&dvp.destination, view)
                )
            } else {
                format!(
                    "The price goes to {}, which is NOT the seller's address {}; the seller signs this destination.",
                    crate::address_format::encode_for(&dvp.destination, view),
                    crate::address_format::encode_for(&dvp.seller, view)
                )
            },
        ),
        Condition::new(
            "Fee rule",
            format!(
                "The fee must be at least the greater of {} STRIKES and the encoded size of the complete signed operation (both approvals and the maker's proof included): {} bytes, so {} atoms. The buyer pays it.",
                offers::TRADE_FEE_FLOOR,
                facts.size,
                floor
            ),
        ),
        Condition::new(
            "Buyer inputs",
            format!(
                "All {} input coin(s) must belong to the current authorized lineage of buyer address {}, unspent and mature when the sale is included, and must equal price + change + fee exactly ({}).",
                facts.inputs.coins.len(),
                crate::address_format::encode_for(&dvp.buyer, view),
                units::format_mut_wide(total_in)
            ),
        ),
        Condition::new(
            "Worker assignment",
            format!(
                "Commit assignment sequence {}, active worker {}, pending assignment {}. Inclusion cancels that exact pending assignment and clears active work; finalized history and earned credits remain. A changed assignment fact requires fresh review.",
                record.assignment_sequence,
                record.active_worker.map_or("none".into(), hex::encode),
                op.meta
                    .envelope
                    .preconditions
                    .iter()
                    .find_map(|p| match p {
                        mutiny_consensus_v8::op_envelope_v1::Precondition::LicenseAssignment {
                            pending,
                            ..
                        } => Some(pending.map_or("none".into(), hex::encode)),
                        _ => None,
                    })
                    .ok_or(Refusal::Malformed("signed LicenseAssignment"))?
            ),
        ),
    ];
    let awards = unclaimed_awards(state, dvp.license);
    let signed_accounts = op
        .meta
        .envelope
        .preconditions
        .iter()
        .find_map(|p| match p {
            mutiny_consensus_v8::op_envelope_v1::Precondition::LicenseEntitlements {
                license,
                accounts,
            } if *license == dvp.license => Some(accounts),
            _ => None,
        })
        .ok_or(Refusal::Malformed("signed LicenseEntitlements"))?;
    conditions.push(Condition::new(
        "Dividends",
        if signed_accounts.is_empty() {
            "The signed LicenseEntitlements commits the exact empty live-account list. Any new live account before inclusion invalidates this sale and requires fresh review and signatures.".to_string()
        } else {
            let lines: Vec<String> = signed_accounts
                .iter()
                .map(|award| {
                    Ok(format!(
                        "award epoch {}: share {}, remaining {} after {} claim(s), claimable until epoch {}",
                        award.award_epoch,
                        units::format_mut(award.share),
                        units::format_mut(award.remaining),
                        award.claims,
                        award.award_epoch.checked_add(mutiny_consensus_v8::dividends_v1::CLAIM_WINDOW_EPOCHS)
                            .ok_or(Refusal::Overflow)?
                    ))
                })
                .collect::<Result<_, Refusal>>()?;
            format!(
                "The signed LicenseEntitlements binds the COMPLETE live-account list and every share, remaining amount and claim sequence: {}. A prior claim or any changed account fact invalidates these exact signed bytes: rebuild the body, review and obtain every approval again. After actual inclusion only the current owner can claim the remaining entitlements. The signed price cannot adjust on retry.",
                lines.join("; ")
            )
        },
    ));

    // ---- timing
    let timing = Timing {
        head_height: head,
        created_height: Some(op.meta.envelope.first_height),
        expiry_height: Some(op.meta.envelope.last_height),
        valid_only_at: None,
        bound_to_parent: false,
        earliest_height: Some(height),
        deadline_epoch: None,
    };

    // ---- effects
    let mut effects = vec![
        Effect::new(
            format!(
                "At actual canonical inclusion height H (earliest preview {height}), License {} moves from {} to {}: its native transfer generation becomes {} and its Worker assignment sequence becomes {}.",
                hex::encode(dvp.license),
                crate::address_format::encode_for(&dvp.seller, view),
                crate::address_format::encode_for(&dvp.buyer, view),
                dvp.generation.saturating_add(1),
                record.assignment_sequence.saturating_add(1)
            ),
            true,
        ),
        Effect::new(
            format!(
                "The License's current Worker authority ({worker}) is cleared at actual canonical inclusion height H: no Worker mines with this License until its new owner assigns one."
            ),
            true,
        ),
        Effect::new(
            "The new owner's rights start at H + 1 after actual canonical inclusion; the reward of block H itself is still attributed to the seller, the owner in the parent state.",
            true,
        ),
        Effect::new(
            "After inclusion the buyer must authorize a FRESH Worker assignment before the License can mine again. Import its exact public binding and verified Worker possession, review the current-owner assignment and deliver it within its signed epoch. It becomes effective in the next canonical epoch.",
            false,
        ),
        Effect::new(
            format!(
                "Consumes offer {}: a single-fill offer can never be filled again.",
                hex::encode(dvp.offer)
            ),
            true,
        ),
        Effect::new(
            format!(
                "Spends {} coin(s) of the buyer worth {}. A spent coin cannot be recovered once the sale is included.",
                facts.inputs.coins.len(),
                units::format_mut_wide(total_in)
            ),
            true,
        ),
        Effect::new(
            format!(
                "Pays the price of {} to {} ({}). The recipient controls it from inclusion; there is no recall.",
                units::format_amount(dvp.price),
                crate::address_format::encode_for(&dvp.destination, view),
                destination_label.text()
            ),
            true,
        ),
    ];
    if dvp.change > 0 {
        effects.push(Effect::new(
            format!(
                "Returns {} of change to the buyer {} ({}).",
                units::format_mut(dvp.change),
                crate::address_format::encode_for(&dvp.buyer, view),
                classify(&dvp.buyer).text()
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
        "Once every party has signed, the sale cannot be revoked: its exact signed inclusion window and committed entitlement/assignment facts control whether it can still execute.",
        true,
    ));
    if sells {
        effects.push(Effect::new(
            format!(
                "This wallet loses License {}, its remaining dividend entitlements and its mining rights at actual canonical inclusion height H.",
                hex::encode(dvp.license)
            ),
            true,
        ));
        effects.push(Effect::new(
            "The reward of the actual inclusion block H is still attributed to this wallet.",
            false,
        ));
        if destination_label == AddressLabel::ThisWallet {
            effects.push(Effect::new(
                format!(
                    "This wallet receives the price of {} at {}.",
                    units::format_amount(dvp.price),
                    crate::address_format::encode_for(&dvp.destination, view)
                ),
                false,
            ));
        }
    }
    if buys {
        effects.push(Effect::new(
            format!(
                "This wallet owns License {} from actual canonical inclusion height H, with rights from H + 1; mining requires its fresh Worker assignment.",
                hex::encode(dvp.license)
            ),
            false,
        ));
    }

    // ---- warnings
    if view.class() == ChainClass::TestValue {
        warnings.push(Warning::new(
            "TEST_VALUE_CHAIN",
            Severity::Notice,
            "This is a TEST-VALUE chain: nothing here has real value.",
        ));
    }
    warnings.push(
        Warning::new(
            "SIGNED_WINDOW",
            Severity::Caution,
            format!(
                "This sale retains signed inclusion heights {} through {} and canonical reference height {}. A retry never rebases or extends these bounds. Each new head requires review again before another signature.",
                op.meta.envelope.first_height,
                op.meta.envelope.last_height,
                op.meta.envelope.reference_height
            ),
        )
        .requiring(AckKind::Conditions),
    );
    warnings.push(offers::commitments_warning());
    if dvp.destination != dvp.seller {
        warnings.push(if sells {
            Warning::new(
                "PAYMENT_NOT_TO_SELLER",
                Severity::Danger,
                format!(
                    "The price is paid to {}, NOT to this wallet's selling address {}. Approve only if you chose that destination yourself.",
                    crate::address_format::encode_for(&dvp.destination, view),
                    crate::address_format::encode_for(&dvp.seller, view)
                ),
            )
        } else {
            Warning::new(
                "PAYMENT_NOT_TO_SELLER",
                Severity::Caution,
                format!(
                    "The price is paid to {}, not to the seller's address {}. The seller signs this destination: confirm it with the seller.",
                    crate::address_format::encode_for(&dvp.destination, view),
                    crate::address_format::encode_for(&dvp.seller, view)
                ),
            )
        });
    }
    if !awards.is_empty() {
        let remaining: u128 = awards.iter().map(|a| u128::from(a.remaining)).sum();
        warnings.push(
            Warning::new(
                "BOUND_DIVIDENDS",
                if sells {
                    Severity::Danger
                } else {
                    Severity::Caution
                },
                if sells {
                    format!(
                        "This wallet transfers the {} still unclaimed from {} dividend award(s) with the License at actual inclusion. Claim first if you intend to keep it; a prior claim invalidates this exact signed sale and requires a new body, review and signatures. A seller claim in the sale's own block fails.",
                        units::format_mut_wide(remaining),
                        awards.len()
                    )
                } else {
                    format!(
                        "{} from {} dividend award(s) is bound by the signed LicenseEntitlements. A changed account list, remaining amount or claim sequence invalidates these signed bytes; retry never silently reduces what you receive or changes the signed price.",
                        units::format_mut_wide(remaining),
                        awards.len()
                    )
                },
            )
            .requiring(AckKind::Conditions),
        );
    }
    if !missing.is_empty() {
        warnings.push(Warning::new(
            "APPROVALS_MISSING",
            Severity::Notice,
            format!(
                "Still missing: {}. No part has any effect alone; the sale needs every part and inclusion within the signed window.",
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
    if buys && dvp.change > 0 && dvp.change < DUST_CHANGE_ATOMS {
        warnings.push(Warning::new(
            "DUST_CHANGE",
            Severity::Caution,
            format!(
                "The change of {} atoms costs about {DUST_CHANGE_ATOMS} atoms in fees to spend later.",
                dvp.change
            ),
        ));
    }
    if facts.inputs.coins.iter().any(|(_, coin)| {
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

    // ---- title and summary
    let short = units::short_hex(&dvp.license);
    let (title, summary) = match role {
        Role::Buyer => (
            format!("Buy License {short}"),
            format!(
                "Buy License {short} (generation {}) from {} for {}, plus a trading fee of {}; valid during the finite signed height window.",
                dvp.generation,
                crate::address_format::encode_for(&dvp.seller, view),
                units::format_mut(dvp.price),
                units::format_mut(fee)
            ),
        ),
        Role::Seller => (
            format!("Sell License {short}"),
            format!(
                "Sell License {short} (generation {}) to {} for {}, paid to {}{}; valid during the finite signed height window.",
                dvp.generation,
                crate::address_format::encode_for(&dvp.buyer, view),
                units::format_mut(dvp.price),
                crate::address_format::encode_for(&dvp.destination, view),
                if destination_label == AddressLabel::ThisWallet {
                    ""
                } else {
                    " (not this wallet)"
                }
            ),
        ),
        Role::Both => (
            format!("Move License {short} between addresses of this wallet"),
            format!(
                "Transfer License {short} (generation {}) from {} to {}, both controlled by this wallet, for {} plus a trading fee of {}; valid during the finite signed height window.",
                dvp.generation,
                crate::address_format::encode_for(&dvp.seller, view),
                crate::address_format::encode_for(&dvp.buyer, view),
                units::format_mut(dvp.price),
                units::format_mut(fee)
            ),
        ),
        Role::Observer => (
            "License sale between other wallets".to_string(),
            format!(
                "{} sells License {short} to {} for {}; this wallet signs nothing in it.",
                crate::address_format::encode_for(&dvp.seller, view),
                crate::address_format::encode_for(&dvp.buyer, view),
                units::format_mut(dvp.price)
            ),
        ),
    };

    Ok(ReviewDraft {
        kind: OperationKind::LicenseDvp,
        schema: SCHEMA,
        title,
        summary,
        signer: me.summary(),
        authorizations,
        parties,
        destinations,
        amount: Some(dvp.price),
        returned: if buys { dvp.change } else { 0 },
        fee: fee_row,
        net_debit,
        inputs,
        conditions,
        timing,
        effects,
        warnings,
        extra_acks: vec![AckKind::Conditions],
        high_risk: true,
    })
}

// ---------------------------------------------------------------------------------------------
// Signing (shared by every trading kind of this phase)
// ---------------------------------------------------------------------------------------------

/// Sign every approval slot `plan` marks as this wallet's, over the operation's own signing payload
/// (`Operation::signing_payload`, through the trading capability, under the domain
/// `domain_for(kind, Spend)` selects), verify each
/// new approval through consensus code at once, and return the result with its metadata derived
/// from the bytes. Only this wallet's slots are touched: other parties' parts are merged later by
/// `offers::combine`.
pub(crate) fn approve_slots(
    plan: &OperationPlan,
    signer: &KindSigner<'_>,
    view: &ChainView<'_>,
    kind: TradeKind,
) -> Result<SignedOperation, Refusal> {
    let parsed = offers::parse_plan_object(plan.objects(), kind)?;
    let mut wire = parsed.wire;
    let mine: Vec<u8> = plan
        .requirements()
        .iter()
        .filter(|requirement| requirement.status == RequirementStatus::ThisWallet)
        .filter_map(|requirement| match requirement.slot {
            Slot::Approval(slot) => Some(slot),
            _ => None,
        })
        .collect();
    if mine.is_empty() {
        return Err(Refusal::NotRequiredSigner(Slot::Approval(0)));
    }
    for slot in mine {
        let descriptor = wire
            .operation
            .approvals
            .iter()
            .find(|approval| approval.slot == slot)
            .ok_or(Refusal::Malformed("approval slot"))?
            .descriptor
            .clone();
        if descriptor != plan.signer().descriptor() {
            return Err(Refusal::NotRequiredSigner(Slot::Approval(slot)));
        }
        let approval =
            signer
                .trade_approval()?
                .approve_slot(&wire.operation, slot, plan.signer())?;
        offers::set_approval(&mut wire.operation, slot, approval)?;
        if !offers::approval_valid(view, &wire.operation, slot) {
            return Err(Refusal::VerificationFailed(
                "this wallet's approval does not verify",
            ));
        }
    }
    if plan
        .requirements()
        .iter()
        .any(|r| r.slot == Slot::FillSignature && r.status == RequirementStatus::ThisWallet)
    {
        wire.operation.offer_proof = Some(
            signer
                .maker_fill_authorization()?
                .authorize_fill(&wire.operation)?,
        );
    }
    let bytes = offers::encode_native(&wire)?;
    let handler = crate::ops::handler(kind.operation_kind())?;
    let described = handler.describe(&bytes)?;
    Ok(offers::signed_from(kind.operation_kind(), bytes, described))
}

/// The slots of `parsed` this identity controls (its current descriptor, resolved through the wallet
/// book exactly as consensus resolves the approvals).
pub(crate) fn my_slots(parsed: &Parsed, view: &ChainView<'_>, me: &SignerIdentity) -> Vec<u8> {
    let wallets = &view.state().wallets;
    parsed
        .slots
        .iter()
        .filter(|slot| {
            slot.descriptor == me.descriptor()
                && wallets.authorize(slot.address, me.descriptor()).is_ok()
        })
        .map(|slot| slot.slot)
        .collect()
}

/// The slots a PLANNER of `wire` signs: every slot this wallet controls with its current descriptor
/// (`my_slots`), which must include `own`, the slot of the role it plans for. When the other side is
/// an address of this wallet too (a License moved between two addresses of one rotated wallet), its
/// slot is signed as well: the review says "this wallet signs" for exactly these slots.
pub(crate) fn planner_slots(
    wire: &NativeOperation,
    kind: TradeKind,
    view: &ChainView<'_>,
    signer: &SignerIdentity,
    own: u8,
) -> Result<Vec<u8>, Refusal> {
    let parsed = offers::parse(&offers::encode_native(&offers::unsigned_copy(wire))?, kind)?;
    let mine = my_slots(&parsed, view, signer);
    if !mine.contains(&own) {
        return Err(Refusal::NotRequiredSigner(Slot::Approval(own)));
    }
    Ok(mine)
}

/// Shared `adopt` logic: the slots `me` must still sign, after refusing bytes this wallet has
/// nothing (left) to sign in and any counterparty signature that does not verify.
pub(crate) fn adoptable_slots(
    parsed: &Parsed,
    view: &ChainView<'_>,
    me: &SignerIdentity,
) -> Result<Vec<u8>, Refusal> {
    // A rotated-away key is stale before it is anything else.
    me.check_current(view)?;
    let mine = my_slots(parsed, view, me);
    if mine.is_empty() {
        let slot = parsed
            .slots
            .iter()
            .find(|slot| slot.sig == Sig::Missing)
            .map_or(0, |slot| slot.slot);
        return Err(Refusal::NotRequiredSigner(Slot::Approval(slot)));
    }
    let unsigned: Vec<u8> = mine
        .into_iter()
        .filter(|n| {
            parsed
                .slots
                .iter()
                .any(|slot| slot.slot == *n && slot.sig == Sig::Missing)
        })
        .collect();
    if unsigned.is_empty() {
        return Err(Refusal::Malformed(
            "these bytes already carry this wallet's approval: there is nothing left for it to sign",
        ));
    }
    offers::check_present_signatures(view, parsed, view.next_height()?)?;
    Ok(unsigned)
}

/// Shared reconciliation: confirmation from this host's own replay-derived operation index,
/// expiration, or an input gone. A protocol `Applied` row alone is not confirmation.
pub(crate) fn reconcile_trade(
    record: &OutboxRecord,
    view: &ChainView<'_>,
    parsed: &Parsed,
) -> Option<Settlement> {
    if let Some(height) = view.confirmed_height(&record.id) {
        return Some(Settlement::Confirmed(height));
    }
    let state = view.state();
    if view
        .next_height()
        .map_or(true, |next| next > record.validity.expiry)
    {
        return Some(Settlement::Expired);
    }
    if parsed
        .wire
        .inputs
        .iter()
        .any(|point| !state.coins.contains_key(point))
    {
        return Some(Settlement::InputsSpent);
    }
    None
}

// ---------------------------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------------------------

impl OperationHandler for LicenseDvpHandler {
    fn kind(&self) -> OperationKind {
        OperationKind::LicenseDvp
    }

    fn recognizes(&self, raw: &[u8]) -> bool {
        offers::recognizes(raw, TradeKind::LicenseDvp)
    }

    fn plan(
        &self,
        request: &OperationRequest,
        view: &ChainView<'_>,
        signer: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        let OperationRequest::LicenseDvp(request) = request else {
            return Err(Refusal::UnknownOperation);
        };
        let wire = build(request, view, signer)?;
        // The buyer signs slot 1 (and slot 0 too when the seller is an address of this wallet).
        let mine = planner_slots(&wire, TradeKind::LicenseDvp, view, signer, 1)?;
        assemble(&wire, view, signer, &mine)
    }

    fn adopt(
        &self,
        raw: &[u8],
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        let parsed = offers::parse(raw, TradeKind::LicenseDvp)?;
        let mine = adoptable_slots(&parsed, view, me)?;
        assemble(&parsed.wire, view, me, &mine)
    }

    fn validate(&self, plan: &OperationPlan, view: &ChainView<'_>) -> Result<(), Refusal> {
        let parsed = offers::parse_plan_object(plan.objects(), TradeKind::LicenseDvp)?;
        // The buyer's coins may be Treasury coins: the Treasury spends only through its profile.
        select::require_profile_for_treasury(view, plan.signer())?;
        validate_dvp(&parsed, view, true)?;
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

    fn review(&self, plan: &OperationPlan, view: &ChainView<'_>) -> Result<ReviewDraft, Refusal> {
        let parsed = offers::parse_plan_object(plan.objects(), TradeKind::LicenseDvp)?;
        let facts = validate_dvp(&parsed, view, true)?;
        build_review(&parsed, &facts, view, plan.signer())
    }

    fn explain(
        &self,
        raw: &[u8],
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<(ReviewDraft, Vec<PlanObject>), Refusal> {
        let parsed = offers::parse(raw, TradeKind::LicenseDvp)?;
        let facts = validate_dvp(&parsed, view, true)?;
        let draft = build_review(&parsed, &facts, view, me)?;
        let unsigned = offers::encode_native(&offers::unsigned_copy(&parsed.wire))?;
        Ok((draft, vec![PlanObject::new(offers::OBJECT_LABEL, unsigned)]))
    }

    fn sign(
        &self,
        plan: &OperationPlan,
        signer: &KindSigner<'_>,
        view: &ChainView<'_>,
    ) -> Result<SignedOperation, Refusal> {
        approve_slots(plan, signer, view, TradeKind::LicenseDvp)
    }

    fn unsigned_form(&self, raw: &[u8]) -> Result<Vec<PlanObject>, Refusal> {
        offers::unsigned_objects(raw, TradeKind::LicenseDvp)
    }

    fn describe(&self, raw: &[u8]) -> Result<Description, Refusal> {
        let parsed = offers::parse(raw, TradeKind::LicenseDvp)?;
        let dvp = fields(&parsed.wire.operation)?;
        offers::describe_parsed(&parsed, None, &resources(&dvp))
    }

    fn check_signed(&self, signed: &SignedOperation, view: &ChainView<'_>) -> Result<(), Refusal> {
        offers::check_signed_trade(signed, view, TradeKind::LicenseDvp, &|parsed, view| {
            validate_dvp(parsed, view, false).map(|_| ())
        })
    }

    fn reconcile(&self, record: &OutboxRecord, view: &ChainView<'_>) -> Settlement {
        let Ok(parsed) = offers::parse(&record.bytes, TradeKind::LicenseDvp) else {
            return Settlement::Pending;
        };
        if let Some(settled) = reconcile_trade(record, view, &parsed) {
            return settled;
        }
        let Ok(dvp) = fields(&parsed.wire.operation) else {
            return Settlement::Pending;
        };
        let state = view.state();
        // Another operation consumed what this one needs: the offer, or the License itself (sold
        // to someone else, or its generation moved on).
        if offers::consumed(state, &parsed.wire.operation.meta.context, dvp.offer)
            || state
                .licenses_v2
                .license(dvp.license)
                .is_none_or(|license| license.owner != dvp.seller)
            || trading_v1::license_generation(state, dvp.license) != Ok(dvp.generation)
        {
            return Settlement::InputsSpent;
        }
        Settlement::Pending
    }
}
