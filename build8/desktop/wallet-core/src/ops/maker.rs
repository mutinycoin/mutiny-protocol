//! Wallet-local maker offers. A signed offer is an exported witness, never a delivered block item.
use crate::{
    authorize::{SignedOperation, SignerIdentity},
    capability::KindSigner,
    context::ChainView,
    ops::select,
    outbox::{OutboxRecord, Settlement},
    plan::{
        Description, OperationHandler, OperationKind, OperationPlan, OperationRequest, PlanObject,
        RequiredSigner, Requirement, RequirementStatus, Slot, Validity,
    },
    refusal::Refusal,
    review::{
        AddressLabel, Condition, Destination, DestinationRole, Effect, Fee, FeePayer, FeeRule,
        ReviewDraft, Timing,
    },
};
use mutiny_consensus_v8::trading_offer_v2::{MakerOffer, OfferBody};
pub(crate) struct Handler;
pub(crate) static HANDLER: Handler = Handler;
const LABEL: &str = "maker-offer-body-v2";
fn encode(body: &OfferBody) -> Result<Vec<u8>, Refusal> {
    body.encode().map_err(|_| Refusal::OfferProofInvalid)
}
fn decode(raw: &[u8]) -> Result<MakerOffer, Refusal> {
    MakerOffer::decode(raw).map_err(|_| Refusal::OfferProofInvalid)
}
fn object(plan: &OperationPlan) -> Result<OfferBody, Refusal> {
    let [o] = plan.objects() else {
        return Err(Refusal::Malformed("one maker body required"));
    };
    if o.label != LABEL {
        return Err(Refusal::Malformed("maker body label"));
    }
    OfferBody::decode(&o.bytes).map_err(|_| Refusal::OfferProofInvalid)
}
fn validity(body: &OfferBody) -> Validity {
    Validity {
        created: body.created,
        expiry: body.expiry,
        valid_only_at: None,
        bound_to_parent: false,
    }
}
fn check(body: &OfferBody, view: &ChainView<'_>, me: &SignerIdentity) -> Result<(), Refusal> {
    encode(body)?;
    crate::offers::require_context(view, &body.context)?;
    me.check_current(view)?;
    if (body.maker_wallet != me.address() && me.authority() != body.maker_wallet)
        || body.maker_descriptor != me.descriptor()
    {
        return Err(Refusal::NotRequiredSigner(Slot::OfferSignature));
    }
    view.state()
        .wallets
        .authorize(body.maker_wallet, &body.maker_descriptor)
        .map_err(|_| Refusal::StaleAuthority)?;
    let next = view.next_height()?;
    if next < body.created {
        return Err(Refusal::OfferNotYetValid {
            created: body.created,
            next_height: next,
        });
    }
    if next > body.expiry {
        return Err(Refusal::OfferExpired {
            expiry: body.expiry,
            next_height: next,
        });
    }
    if crate::offers::consumed(
        view.state(),
        &body.context,
        body.id().map_err(|_| Refusal::OfferProofInvalid)?,
    ) {
        return Err(Refusal::OfferConsumed);
    }
    select::require_profile_for_treasury(view, me)
}
fn requirement(body: &OfferBody) -> Vec<Requirement> {
    vec![Requirement {
        slot: Slot::OfferSignature,
        signer: RequiredSigner::Wallet(body.maker_wallet),
        status: RequirementStatus::ThisWallet,
    }]
}
fn draft(
    body: &OfferBody,
    view: &ChainView<'_>,
    me: &SignerIdentity,
) -> Result<ReviewDraft, Refusal> {
    check(body, view, me)?;
    Ok(ReviewDraft {
        kind: OperationKind::MakerOffer,
        schema: 1,
        title: "Create maker offer".into(),
        summary: format!(
            "Commit maker side {}, exact terms {:?}, receiving address {}, fee limit {} STRIKES.",
            body.maker_side,
            body.terms,
            crate::address_format::encode_for(&body.destination, view),
            body.max_fee.0
        ),
        signer: me.summary(),
        authorizations: requirement(body),
        parties: Vec::new(),
        destinations: vec![Destination {
            role: DestinationRole::Payment,
            address: body.destination,
            label: if body.destination == me.address() {
                AddressLabel::ThisWallet
            } else {
                AddressLabel::External
            },
            atoms: 0,
        }],
        amount: None,
        returned: 0,
        fee: Fee {
            atoms: 0,
            rule: FeeRule::None,
            payer: FeePayer::NotApplicable,
            size_bytes: None,
        },
        net_debit: None,
        inputs: Vec::new(),
        conditions: vec![
            Condition::new(
                "Maker authority",
                format!(
                    "Current wallet {}; descriptor {}; nonce {}.",
                    crate::address_format::encode_for(&body.maker_wallet, view),
                    hex::encode(crate::ops::rotation::descriptor_fingerprint(
                        &body.maker_descriptor
                    )),
                    hex::encode(body.nonce)
                ),
            ),
            Condition::new(
                "Condition",
                body.condition.map_or("none".into(), hex::encode),
            ),
            Condition::new(
                "Delivery and freeze",
                "Signing creates a counterparty witness only. It does not deliver an operation, reserve chain funds, establish a canonical listing or prove a freeze before rotation.",
            ),
        ],
        timing: Timing {
            head_height: view.anchor().height,
            created_height: Some(body.created),
            expiry_height: Some(body.expiry),
            valid_only_at: None,
            bound_to_parent: false,
            earliest_height: None,
            deadline_epoch: None,
        },
        effects: vec![Effect::new(
            "The maker signature binds this exact chain, side, terms, destination, condition, maximum fee, nonce and finite window. A fill signature and current settlement approvals are separate.",
            true,
        )],
        warnings: Vec::new(),
        extra_acks: Vec::new(),
        high_risk: true,
    })
}
impl OperationHandler for Handler {
    fn kind(&self) -> OperationKind {
        OperationKind::MakerOffer
    }
    fn recognizes(&self, raw: &[u8]) -> bool {
        decode(raw).is_ok()
    }
    fn plan(
        &self,
        r: &OperationRequest,
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        let OperationRequest::MakerOffer(r) = r else {
            return Err(Refusal::UnknownOperation);
        };
        let body = OfferBody::decode(r.body.as_slice()).map_err(|_| Refusal::OfferProofInvalid)?;
        check(&body, view, me)?;
        Ok(OperationPlan::assemble(
            self.kind(),
            1,
            me.clone(),
            vec![PlanObject::new(LABEL, encode(&body)?)],
            requirement(&body),
            Vec::new(),
            validity(&body),
            view,
        ))
    }
    fn adopt(
        &self,
        _: &[u8],
        _: &ChainView<'_>,
        _: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        Err(Refusal::Malformed(
            "maker offers are created from an exact unsigned request",
        ))
    }
    fn validate(&self, p: &OperationPlan, v: &ChainView<'_>) -> Result<(), Refusal> {
        check(&object(p)?, v, p.signer())
    }
    fn review(&self, p: &OperationPlan, v: &ChainView<'_>) -> Result<ReviewDraft, Refusal> {
        draft(&object(p)?, v, p.signer())
    }
    fn explain(
        &self,
        raw: &[u8],
        v: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<(ReviewDraft, Vec<PlanObject>), Refusal> {
        let offer = decode(raw)?;
        offer.verify().map_err(|_| Refusal::OfferProofInvalid)?;
        Ok((draft(&offer.body, v, me)?, self.unsigned_form(raw)?))
    }
    fn sign(
        &self,
        p: &OperationPlan,
        s: &KindSigner<'_>,
        _: &ChainView<'_>,
    ) -> Result<SignedOperation, Refusal> {
        let offer = s.maker_offer_authorization()?.authorize_offer(object(p)?)?;
        Ok(SignedOperation::Complete {
            kind: self.kind(),
            id: offer.body.id().map_err(|_| Refusal::OfferProofInvalid)?,
            bytes: offer.encode().map_err(|_| Refusal::OfferProofInvalid)?,
            validity: validity(&offer.body),
            reserved: Vec::new(),
        })
    }
    fn unsigned_form(&self, raw: &[u8]) -> Result<Vec<PlanObject>, Refusal> {
        Ok(vec![PlanObject::new(LABEL, encode(&decode(raw)?.body)?)])
    }
    fn describe(&self, raw: &[u8]) -> Result<Description, Refusal> {
        let offer = decode(raw)?;
        offer.verify().map_err(|_| Refusal::OfferProofInvalid)?;
        Ok(Description {
            id: offer.body.id().map_err(|_| Refusal::OfferProofInvalid)?,
            complete: true,
            missing: Vec::new(),
            validity: validity(&offer.body),
            reserved: Vec::new(),
        })
    }
    fn check_signed(&self, s: &SignedOperation, v: &ChainView<'_>) -> Result<(), Refusal> {
        let offer = decode(s.bytes())?;
        offer.verify().map_err(|_| Refusal::OfferProofInvalid)?;
        crate::offers::require_context(v, &offer.body.context)?;
        let next = v.next_height()?;
        if next < offer.body.created {
            return Err(Refusal::OfferNotYetValid {
                created: offer.body.created,
                next_height: next,
            });
        }
        if next > offer.body.expiry {
            return Err(Refusal::OfferExpired {
                expiry: offer.body.expiry,
                next_height: next,
            });
        }
        if crate::offers::consumed(
            v.state(),
            &offer.body.context,
            offer.body.id().map_err(|_| Refusal::OfferProofInvalid)?,
        ) {
            return Err(Refusal::OfferConsumed);
        }
        if offer.body.id().map_err(|_| Refusal::OfferProofInvalid)? != s.id() {
            return Err(Refusal::OfferProofInvalid);
        }
        v.state()
            .wallets
            .authorize(offer.body.maker_wallet, &offer.body.maker_descriptor)
            .map_err(|_| Refusal::StaleAuthority)
    }
    fn reconcile(&self, r: &OutboxRecord, v: &ChainView<'_>) -> Settlement {
        let Ok(offer) = decode(&r.bytes) else {
            return Settlement::Pending;
        };
        if crate::offers::consumed(v.state(), &offer.body.context, r.id) {
            // This witness is above consensus, so its own bytes are never finalized.
            // Authenticated first funding consumes its exact single-fill offer ID.
            Settlement::InputsSpent
        } else if v.anchor().height >= offer.body.expiry {
            Settlement::Expired
        } else if v
            .state()
            .wallets
            .authorize(offer.body.maker_wallet, &offer.body.maker_descriptor)
            .is_err()
        {
            // Above-consensus witnesses have no historical freeze exception. Rotation requires
            // a new review and signatures before first canonical funding.
            Settlement::InputsSpent
        } else {
            Settlement::Pending
        }
    }
}
