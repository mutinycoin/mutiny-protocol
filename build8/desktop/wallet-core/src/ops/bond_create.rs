//! Canonical, consensus-atomic kind-24 BondCreate. No standalone funding transfer exists.
use crate::{
    authorize::{SignedOperation, SignerIdentity},
    capability::KindSigner,
    context::{ChainView, is_treasury_address, require_reserve_backing, treasury_authority},
    discovery::bonds as discovery,
    ops::{bond, select},
    outbox::{OutboxRecord, Settlement},
    plan::{
        Description, OperationHandler, OperationKind, OperationPlan, OperationRequest, PlanObject,
        RequiredSigner, Requirement, RequirementStatus, Slot, Validity,
    },
    refusal::Refusal,
    review::{
        AckKind, AddressLabel, Condition, Destination, DestinationRole, Effect, Fee, FeePayer,
        FeeRule, InputLine, Party, PartyRole, ReviewDraft, Severity, Timing, Warning,
    },
};
use mutiny_consensus_v8::{
    bond_create_v3::{BondError, FundedBondCreate, PartialBondCreate, UnsignedBondCreate},
    transactions::{OutPoint, Output},
};
use std::collections::BTreeSet;
pub(crate) struct Handler;
pub(crate) static HANDLER: Handler = Handler;
const LABEL: &str = "funded-bond-create-v3";
const SCHEMA: u16 = 2;
fn refuse(e: BondError) -> Refusal {
    match e {
        BondError::MissingInput => Refusal::InputUnavailable,
        BondError::Immature => Refusal::ImmatureInput,
        BondError::Conservation => Refusal::Conservation,
        BondError::Fee => Refusal::InvalidRequest("bond fee is below complete signed length"),
        BondError::Overflow => Refusal::Overflow,
        BondError::Authority(_) | BondError::Lineage(_) => Refusal::StaleAuthority,
        BondError::Eligibility(mutiny_consensus_v8::Error::Duplicate) => Refusal::Replay,
        BondError::Eligibility(mutiny_consensus_v8::Error::Capacity) => {
            Refusal::InvalidRequest(bond::LOT_CAPACITY)
        }
        BondError::Eligibility(_) => Refusal::NodeNotEligible,
        _ => Refusal::VerificationFailed("canonical funded BondCreate was refused"),
    }
}
fn decode(raw: &[u8]) -> Result<PartialBondCreate, Refusal> {
    PartialBondCreate::decode(raw).map_err(refuse)
}
fn unsigned(raw: &[u8]) -> Result<PartialBondCreate, Refusal> {
    Ok(PartialBondCreate::new(decode(raw)?.unsigned))
}
fn encode(p: &PartialBondCreate) -> Result<Vec<u8>, Refusal> {
    p.encode().map_err(refuse)
}
fn object(plan: &OperationPlan) -> Result<PartialBondCreate, Refusal> {
    let [o] = plan.objects() else {
        return Err(Refusal::Malformed("one atomic BondCreate object required"));
    };
    if o.label != LABEL {
        return Err(Refusal::Malformed("wrong BondCreate label"));
    }
    decode(&o.bytes)
}
pub(crate) fn export_unsigned(plan: &OperationPlan) -> Result<Vec<u8>, Refusal> {
    encode(&PartialBondCreate::new(object(plan)?.unsigned))
}
fn validity(p: &PartialBondCreate) -> Validity {
    let e = &p.unsigned.envelope;
    Validity {
        created: e.first_height,
        expiry: e.last_height,
        valid_only_at: None,
        bound_to_parent: false,
    }
}
fn reserved(p: &PartialBondCreate) -> Vec<OutPoint> {
    let mut v = p.unsigned.inputs.clone();
    v.push(bond::lot_resource(&p.unsigned.lot_id()));
    v.sort();
    v
}
fn requirements(p: &PartialBondCreate) -> Vec<Requirement> {
    vec![
        Requirement {
            slot: Slot::BondOwner,
            signer: RequiredSigner::Wallet(p.unsigned.owner),
            status: RequirementStatus::ThisWallet,
        },
        Requirement {
            slot: Slot::Input(0),
            signer: RequiredSigner::Wallet(p.unsigned.owner),
            status: RequirementStatus::ThisWallet,
        },
    ]
}
fn check(p: &PartialBondCreate, view: &ChainView<'_>, reservations: bool) -> Result<(), Refusal> {
    view.require_context(
        mutiny_consensus_v8::NETWORK_ID,
        &p.unsigned.genesis,
        &p.unsigned.fingerprint,
    )?;
    view.check_envelope(&p.unsigned.envelope)?;
    let minimum = p.unsigned.signed_len().map_err(refuse)? as u64;
    if p.unsigned.fee < minimum {
        return Err(Refusal::FeeBelowMinimum {
            fee: p.unsigned.fee,
            minimum,
        });
    }
    if reservations && reserved(p).iter().any(|i| view.reserved().contains(i)) {
        return Err(Refusal::ReservedInput);
    }
    p.preflight(view.state(), view.anchor(), &view.history())
        .map_err(refuse)?;
    let spent = p.unsigned.inputs.iter().cloned().collect();
    let outputs = p.unsigned.change.iter().cloned().collect::<Vec<_>>();
    require_reserve_backing(view, &spent, &outputs)
}
fn assemble(
    p: PartialBondCreate,
    view: &ChainView<'_>,
    me: &SignerIdentity,
) -> Result<OperationPlan, Refusal> {
    if p.unsigned.owner_descriptor != me.descriptor() {
        return Err(Refusal::NotRequiredSigner(Slot::BondOwner));
    }
    check(&p, view, true)?;
    select::require_profile_for_treasury(view, me)?;
    Ok(OperationPlan::assemble(
        OperationKind::BondCreate,
        SCHEMA,
        me.clone(),
        vec![PlanObject::new(LABEL, encode(&p)?)],
        requirements(&p),
        reserved(&p),
        validity(&p),
        view,
    ))
}
impl OperationHandler for Handler {
    fn kind(&self) -> OperationKind {
        OperationKind::BondCreate
    }
    fn recognizes(&self, raw: &[u8]) -> bool {
        decode(raw).is_ok()
    }
    fn plan(
        &self,
        request: &OperationRequest,
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        let OperationRequest::BondCreate(r) = request else {
            return Err(Refusal::UnknownOperation);
        };
        if r.validity_blocks == 0
            || r.validity_blocks > mutiny_consensus_v8::transactions::EXPIRY_HORIZON
        {
            return Err(Refusal::InvalidRequest(
                "bond inclusion window must be 1..=10,080",
            ));
        }
        me.check_current(view)?;
        select::require_profile_for_treasury(view, me)?;
        if r.nonce == [0; 32] {
            return Err(Refusal::InvalidRequest(bond::NONCE_REQUIRED));
        }
        if r.amount_atoms < discovery::MINIMUM_BOND_ATOMS {
            return Err(Refusal::BelowMinimumBond {
                minimum: discovery::MINIMUM_BOND_ATOMS,
            });
        }
        let node = discovery::node(view.state(), &r.node).ok_or(Refusal::NodeNotEligible)?;
        if node.locked_lots >= discovery::MAX_LOCKED_LOTS_PER_LINEAGE {
            return Err(Refusal::InvalidRequest(bond::LOT_CAPACITY));
        }
        if !node.bondable() || r.node_generation != node.generation {
            return Err(Refusal::NodeNotEligible);
        }
        view.state()
            .wallets
            .authorize(node.owner, me.descriptor())
            .map_err(|_| Refusal::NotRequiredSigner(Slot::BondOwner))?;
        let mut body = UnsignedBondCreate {
            genesis: view.context().genesis,
            fingerprint: view.context().fingerprint,
            envelope: crate::offers::envelope(
                view,
                view.next_height()?,
                view.next_height()?
                    .checked_add(r.validity_blocks)
                    .ok_or(Refusal::Overflow)?,
                Vec::new(),
            )?,
            owner: node.owner,
            owner_descriptor: me.descriptor().to_vec(),
            node: r.node,
            node_generation: r.node_generation,
            nonce: r.nonce,
            principal: r.amount_atoms,
            fee: 0,
            inputs: Vec::new(),
            change: None,
        };
        if view
            .reserved()
            .contains(&bond::lot_resource(&body.lot_id()))
        {
            return Err(Refusal::ReservedInput);
        }
        if view.state().bonds_v2.lots.contains_key(&body.lot_id()) {
            return Err(Refusal::Replay);
        }
        let coins = select::candidates(view, me.descriptor(), 128, &BTreeSet::new())?;
        if coins.count == 0 {
            return Err(Refusal::NothingSpendable);
        }
        let available = u64::try_from(coins.total).map_err(|_| Refusal::Overflow)?;
        let mut total = 0u128;
        let mut requested = r.amount_atoms.checked_add(1).ok_or(Refusal::Overflow)?;
        for (point, coin) in coins.coins {
            body.inputs.push(point.clone());
            body.inputs.sort();
            total += u128::from(coin.output.atoms);
            if total <= u128::from(body.principal) {
                continue;
            }
            let surplus =
                u64::try_from(total - u128::from(body.principal)).map_err(|_| Refusal::Overflow)?;
            let mut fee = 0;
            for _ in 0..16 {
                if fee > surplus {
                    break;
                }
                body.fee = fee;
                body.change = (surplus > fee).then_some(Output {
                    owner: me.address(),
                    atoms: surplus - fee,
                });
                let needed = body.signed_len().map_err(refuse)? as u64;
                requested = requested.max(
                    r.amount_atoms
                        .checked_add(needed)
                        .ok_or(Refusal::Overflow)?,
                );
                if needed <= fee {
                    return assemble(PartialBondCreate::new(body), view, me);
                }
                fee = needed;
            }
        }
        if coins.count > 128 && coins.total >= u128::from(requested) {
            Err(Refusal::SizeLimit {
                limit: mutiny_consensus_v8::transactions::MAX_TX_BYTES,
            })
        } else {
            Err(Refusal::InsufficientFunds {
                available,
                requested,
            })
        }
    }
    fn adopt(
        &self,
        raw: &[u8],
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        let p = decode(raw)?;
        if p.create.is_some() || p.funding.is_some() {
            return Err(Refusal::Malformed(bond::ALREADY_SIGNED));
        }
        assemble(p, view, me)
    }
    fn validate(&self, plan: &OperationPlan, view: &ChainView<'_>) -> Result<(), Refusal> {
        let p = object(plan)?;
        if p.unsigned.owner_descriptor != plan.signer().descriptor() {
            return Err(Refusal::NotRequiredSigner(Slot::BondOwner));
        }
        select::require_profile_for_treasury(view, plan.signer())?;
        check(&p, view, true)
    }
    fn review(&self, plan: &OperationPlan, view: &ChainView<'_>) -> Result<ReviewDraft, Refusal> {
        self.explain(&export_unsigned(plan)?, view, plan.signer())
            .map(|(r, _)| r)
    }
    fn explain(
        &self,
        raw: &[u8],
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<(ReviewDraft, Vec<PlanObject>), Refusal> {
        let p = decode(raw)?;
        check(&p, view, true)?;
        let u = &p.unsigned;
        let e = &u.envelope;
        let owner = me.descriptor() == u.owner_descriptor;
        let mine = |address| {
            view.state()
                .wallets
                .authorize(address, me.descriptor())
                .is_ok()
        };
        let mut authorizations = requirements(&p);
        for requirement in &mut authorizations {
            let provided = match requirement.slot {
                Slot::BondOwner => p.create.is_some(),
                Slot::Input(0) => p.funding.is_some(),
                _ => false,
            };
            requirement.status = if provided {
                RequirementStatus::Provided
            } else if owner {
                RequirementStatus::ThisWallet
            } else {
                RequirementStatus::Counterparty
            };
        }
        let inputs: Vec<InputLine> = u
            .inputs
            .iter()
            .map(|point| {
                let coin = &view.state().coins[point];
                InputLine {
                    point: point.clone(),
                    atoms: coin.output.atoms,
                    owned_by_signer: view
                        .state()
                        .wallets
                        .authorize(coin.output.owner, me.descriptor())
                        .is_ok(),
                    coinbase: coin.coinbase,
                }
            })
            .collect();
        let node = discovery::node(view.state(), &u.node).ok_or(Refusal::NodeNotEligible)?;
        let size = u.signed_len().map_err(refuse)? as u64;
        let total = inputs.iter().map(|i| u128::from(i.atoms)).sum::<u128>();
        let earliest = e
            .first_height
            .checked_add(discovery::MINIMUM_HOLD_BLOCKS)
            .ok_or(Refusal::Overflow)?;
        let window = e.last_height.saturating_sub(view.anchor().height);
        let mut conditions = vec![
            Condition::new(
                "Atomic funding",
                "The owner and funding signatures bind the same complete kind-24 body: context, reference, finite window, node, owner, nonce, principal, fee, inputs and change. Neither signature or a standalone transfer can create this lot independently.",
            ),
            Condition::new(
                "Lot",
                format!(
                    "Lot {}; fresh nonce {}; the immutable owner is {}. This same lot identifier cannot be created twice.",
                    hex::encode(u.lot_id()),
                    hex::encode(u.nonce),
                    hex::encode(u.owner)
                ),
            ),
            Condition::new(
                "Node",
                format!(
                    "Node {}; lineage {}; hardware generation {}; physical and currently eligible in own verified state.",
                    hex::encode(u.node),
                    hex::encode(node.lineage),
                    u.node_generation
                ),
            ),
            Condition::new(
                "Bond authority",
                format!(
                    "Immutable owner {}; current descriptor fingerprint {}; retired keys cannot authorize this body; a future payout remains owned by this same authority.",
                    hex::encode(u.owner),
                    hex::encode(crate::ops::rotation::descriptor_fingerprint(
                        &u.owner_descriptor
                    ))
                ),
            ),
            Condition::new(
                "Minimum",
                format!(
                    "Principal {} must be at least {} ({} STRIKES).",
                    crate::units::format_amount(u.principal),
                    crate::units::format_mut(discovery::MINIMUM_BOND_ATOMS),
                    discovery::MINIMUM_BOND_ATOMS
                ),
            ),
            Condition::new(
                "Canonical reference",
                format!(
                    "Reference {} {}. Retry never changes this signed canonical reference or extends its inclusion heights.",
                    e.reference_height,
                    hex::encode(e.reference_block)
                ),
            ),
            Condition::new(
                "Inclusion window",
                format!(
                    "Signed heights {} through {} ({window} blocks after this verified head; {}, approximate at the 60 s target interval). The lock-start height B is the actual certified inclusion height, not the review height or first allowed height.",
                    e.first_height,
                    e.last_height,
                    crate::units::approx_blocks(window)
                ),
            ),
            Condition::new(
                "Withdrawal rule",
                "Withdrawal W requires W >= B + 259200 AND W >= U + 43200 certified blocks: max(B + 259200, U + 43200). U is the actual finalized unbond height; both clocks must finish.",
            ),
            Condition::new(
                "Earliest withdrawal",
                format!(
                    "Block {earliest} at the earliest if inclusion is B = {}; a later inclusion shifts the floor later. No withdrawal is available until an unbond is finalized and both clocks finish (about 180 days for the minimum hold, approximate at the 60 s target interval).",
                    e.first_height
                ),
            ),
            Condition::new(
                "Burn exposure",
                "Equivocation can burn an Active lot, and an Unbonding lot remains exposed through its actual unbond height U + 43200. A burned lot has no withdrawal payout.",
            ),
            Condition::new(
                "Weight",
                "The lot first supports its node from actual B + 1; from actual U + 1 it no longer counts. Reputation and quorum effects follow consensus; this wallet does not promise a weight.",
            ),
            Condition::new(
                "Inputs",
                format!(
                    "{} coin(s) worth {} are consumed atomically. Input value equals principal + fee + change; every input must remain unspent and mature at inclusion.",
                    inputs.len(),
                    crate::units::format_mut_wide(total)
                ),
            ),
            Condition::new(
                "Fee rule",
                format!(
                    "The complete signed kind-24 encoding is {size} bytes, so the fee must be at least {size} STRIKES. The principal pays no additional or separate creation fee."
                ),
            ),
        ];
        if inputs.iter().any(|i| i.coinbase) {
            conditions.push(Condition::new(
                "Maturity",
                format!(
                    "Coinbase inputs must be at least {} certified blocks old.",
                    mutiny_consensus_v8::transactions::MATURITY
                ),
            ));
        }
        let mut warnings = vec![Warning::new("FUNDING_BOUND", Severity::Notice, "The principal and its funding are one native atomic body; no independent escrow payment is needed."),
            Warning::new("BURN_EXPOSURE", Severity::Danger, "Equivocation can burn the entire principal. Starting an unbond does not immediately end this exposure.").requiring(AckKind::Conditions)];
        if u.fee > size {
            warnings.push(Warning::new("FEE_ABOVE_MINIMUM", Severity::Notice,
                format!("The fee is {} STRIKES above the complete signed size minimum of {size}; the producer receives the full reviewed fee.", u.fee - size)));
        }
        if view.class() == crate::context::ChainClass::TestValue {
            warnings.push(Warning::new(
                "TEST_VALUE_CHAIN",
                Severity::Notice,
                "This is a TEST-VALUE chain: nothing here has real value.",
            ));
        }
        if let Some(treasury) = treasury_authority(view) {
            if u.inputs.iter().any(|point| {
                is_treasury_address(view, &treasury, &view.state().coins[point].output.owner)
            }) {
                warnings.push(Warning::new("TREASURY_FUNDS", Severity::Caution, "Treasury funds lock this principal; the outstanding dividend reserve must remain backed.").requiring(AckKind::TreasuryAuthority));
            }
        }
        let mut effects = vec![
            Effect::new(
                format!(
                    "Locks {} into the immutable owner's bond lot at actual certified inclusion B. There is no cancel of a created lot; withdrawal needs finalized notice and both clocks.",
                    crate::units::format_mut(u.principal)
                ),
                true,
            ),
            Effect::new(
                format!(
                    "Spends {} funding coin(s) worth {}; spent coins cannot be recovered.",
                    inputs.len(),
                    crate::units::format_mut_wide(total)
                ),
                true,
            ),
            Effect::new(
                format!(
                    "Pays a network fee of {} to the producer; this fee cannot be recovered.",
                    crate::units::format_mut(u.fee)
                ),
                true,
            ),
            Effect::new(
                "The principal is exposed to burning by timely equivocation evidence, including the notice period; a burn permanently removes its payout.",
                true,
            ),
            Effect::new(
                format!(
                    "Once signed this exact body cannot be revoked. It remains valid through signed height {} if its canonical inputs and authority still match.",
                    e.last_height
                ),
                true,
            ),
        ];
        if let Some(change) = &u.change {
            effects.push(Effect::new(
                format!(
                    "Returns {} to {} ({}).",
                    crate::units::format_mut(change.atoms),
                    hex::encode(change.owner),
                    if mine(change.owner) {
                        "this wallet"
                    } else {
                        "the bond owner"
                    }
                ),
                false,
            ));
        }
        let destinations = u
            .change
            .iter()
            .map(|o| Destination {
                role: DestinationRole::Change,
                address: o.owner,
                label: if mine(o.owner) {
                    AddressLabel::ThisWallet
                } else {
                    AddressLabel::External
                },
                atoms: o.atoms,
            })
            .collect();
        Ok((
            ReviewDraft {
                kind: self.kind(),
                schema: SCHEMA,
                title: "Create an atomic bond".into(),
                summary: format!(
                    "Lock {} STRIKES for node {}; fee {} STRIKES. Funding and creation execute together.",
                    u.principal,
                    hex::encode(u.node),
                    u.fee
                ),
                signer: me.summary(),
                authorizations,
                parties: vec![Party {
                    role: PartyRole::NodeOwner,
                    address: u.owner,
                    label: if owner {
                        AddressLabel::ThisWallet
                    } else {
                        AddressLabel::External
                    },
                }],
                destinations,
                amount: Some(u.principal),
                returned: u
                    .change
                    .as_ref()
                    .filter(|o| mine(o.owner))
                    .map_or(0, |o| o.atoms),
                fee: Fee {
                    atoms: u.fee,
                    rule: FeeRule::OneAtomPerEncodedByte,
                    payer: if owner {
                        FeePayer::ThisWallet
                    } else {
                        FeePayer::Counterparty(u.owner)
                    },
                    size_bytes: Some(u.signed_len().map_err(refuse)? as u64),
                },
                net_debit: Some(if owner {
                    u128::from(u.principal) + u128::from(u.fee)
                } else {
                    0
                }),
                inputs,
                conditions,
                timing: Timing {
                    head_height: view.anchor().height,
                    created_height: Some(e.first_height),
                    expiry_height: Some(e.last_height),
                    valid_only_at: None,
                    bound_to_parent: false,
                    earliest_height: Some(earliest),
                    deadline_epoch: None,
                },
                effects,
                warnings,
                extra_acks: vec![AckKind::Conditions],
                high_risk: owner,
            },
            vec![PlanObject::new(
                LABEL,
                encode(&PartialBondCreate::new(u.clone()))?,
            )],
        ))
    }
    fn sign(
        &self,
        plan: &OperationPlan,
        signer: &KindSigner<'_>,
        _view: &ChainView<'_>,
    ) -> Result<SignedOperation, Refusal> {
        let p = object(plan)?;
        let signed = signer
            .bond_authorization()?
            .authorize_funded_bond(p.unsigned)?;
        Ok(SignedOperation::Complete {
            kind: self.kind(),
            id: signed.id().map_err(refuse)?,
            bytes: signed.encode().map_err(refuse)?,
            validity: *plan.validity(),
            reserved: plan.inputs().to_vec(),
        })
    }
    fn unsigned_form(&self, raw: &[u8]) -> Result<Vec<PlanObject>, Refusal> {
        Ok(vec![PlanObject::new(LABEL, encode(&unsigned(raw)?)?)])
    }
    fn describe(&self, raw: &[u8]) -> Result<Description, Refusal> {
        let p = decode(raw)?;
        let complete = p.create.is_some() && p.funding.is_some();
        let mut missing = requirements(&p);
        missing.retain(|r| match r.slot {
            Slot::BondOwner => p.create.is_none(),
            Slot::Input(0) => p.funding.is_none(),
            _ => false,
        });
        for requirement in &mut missing {
            requirement.status = RequirementStatus::Counterparty;
        }
        Ok(Description {
            id: p.unsigned.id().map_err(refuse)?,
            complete,
            missing,
            validity: validity(&p),
            reserved: reserved(&p),
        })
    }
    fn check_signed(&self, signed: &SignedOperation, view: &ChainView<'_>) -> Result<(), Refusal> {
        let p = FundedBondCreate::decode(signed.bytes()).map_err(refuse)?;
        if p.id().map_err(refuse)? != signed.id() {
            return Err(Refusal::VerificationFailed("BondCreate id mismatch"));
        }
        p.verify(view.state(), view.anchor(), &view.history())
            .map_err(refuse)?;
        check(&p.as_partial(), view, false)
    }
    fn reconcile(&self, record: &OutboxRecord, view: &ChainView<'_>) -> Settlement {
        if let Some(h) = view.confirmed_height(&record.id) {
            return Settlement::Confirmed(h);
        }
        let Ok(p) = decode(&record.bytes) else {
            return Settlement::Pending;
        };
        if p.unsigned
            .inputs
            .iter()
            .any(|i| !view.state().coins.contains_key(i))
        {
            return Settlement::InputsSpent;
        }
        if view.anchor().height >= p.unsigned.envelope.last_height {
            Settlement::Expired
        } else {
            Settlement::Pending
        }
    }
}
