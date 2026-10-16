//! Existing kind-10 fresh Worker assignment. Public possession data is imported; this wallet
//! never generates/provisions a Worker key. Current License ownership comes only from own replay.
use crate::{
    authorize::{SignedOperation, SignerIdentity},
    capability::KindSigner,
    context::ChainView,
    outbox::{OutboxRecord, Settlement, resource_key},
    plan::{
        Description, OperationHandler, OperationKind, OperationPlan, OperationRequest, PlanObject,
        RequiredSigner, Requirement, RequirementStatus, Slot, Validity,
    },
    refusal::Refusal,
    review::{
        AckKind, AddressLabel, Condition, Effect, Fee, FeePayer, FeeRule, Party, PartyRole,
        ReviewDraft, Severity, Timing, Warning,
    },
};
use mutiny_consensus_v8::{
    Hash,
    license_assignment_v2::{Assignment, ParentContext},
};
use mutiny_crypto_v2::{
    HybridSignature,
    enrollment::{Binding, Enrollment},
};
pub(crate) struct Handler;
pub(crate) static HANDLER: Handler = Handler;
const LABEL: &str = "license-worker-assignment-v2";
fn decode(raw: &[u8]) -> Result<Assignment, Refusal> {
    Assignment::decode(raw).map_err(|_| Refusal::Malformed("canonical Worker assignment"))
}
fn unsigned(mut a: Assignment) -> Assignment {
    a.enrollment.owner_signature = HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    };
    a
}
fn objects(a: &Assignment) -> Result<Vec<PlanObject>, Refusal> {
    Ok(vec![PlanObject::new(
        LABEL,
        unsigned(a.clone())
            .encode()
            .map_err(|_| Refusal::InvalidDescriptor)?,
    )])
}
fn object(plan: &OperationPlan) -> Result<Assignment, Refusal> {
    let [item] = plan.objects() else {
        return Err(Refusal::Malformed("one assignment object"));
    };
    if item.label != LABEL {
        return Err(Refusal::Malformed("assignment label"));
    }
    decode(&item.bytes)
}
fn validity(a: &Assignment) -> Validity {
    Validity {
        created: 1,
        expiry: a.enrollment.binding.valid_until_height,
        valid_only_at: None,
        bound_to_parent: false,
    }
}
fn id(a: &Assignment) -> Result<Hash, Refusal> {
    mutiny_consensus_v8::op_envelope_v1::assignment_id(a)
        .map_err(|_| Refusal::VerificationFailed("assignment identifier"))
}
fn reserved(a: &Assignment) -> Vec<mutiny_consensus_v8::transactions::OutPoint> {
    vec![resource_key(
        crate::offers::LICENSE_RESOURCE,
        &a.enrollment.binding.license,
    )]
}
fn requirements(me: &SignerIdentity) -> Vec<Requirement> {
    vec![Requirement {
        slot: Slot::AssignmentOwner,
        signer: RequiredSigner::Wallet(me.address()),
        status: RequirementStatus::ThisWallet,
    }]
}
fn check(a: &Assignment, v: &ChainView<'_>, me: Option<&SignerIdentity>) -> Result<(), Refusal> {
    let b = &a.enrollment.binding;
    v.require_context(v.context().network, &b.genesis, &b.fingerprint)?;
    b.verify_worker_possession(&a.enrollment.worker_signature)
        .map_err(|_| Refusal::VerificationFailed("Worker possession signature"))?;
    let license = v
        .state()
        .licenses_v2
        .license(b.license)
        .ok_or(Refusal::LicenseNotOwned)?;
    if v.state()
        .licenses_v2
        .pending_assignment(b.license)
        .is_some()
    {
        return Err(Refusal::InvalidRequest(
            "License already has a pending Worker assignment",
        ));
    }
    let records = v
        .state()
        .licenses_v2
        .records()
        .map_err(|_| Refusal::VerificationFailed("License assignment records"))?;
    if records.len() >= mutiny_consensus_v8::execution::MAX_STATE_RECORDS {
        return Err(Refusal::InvalidRequest(
            "License assignment state is at capacity",
        ));
    }
    // Native schedule forbids reusing any historical or pending Worker public key. Read the
    // canonical typed records of this own verified Book; no peer-supplied availability hint.
    for raw in records.values() {
        let mut d = minicbor::Decoder::new(raw);
        let count = d
            .array()
            .map_err(|_| Refusal::VerificationFailed("License record framing"))?;
        if d.u8()
            .map_err(|_| Refusal::VerificationFailed("License record version"))?
            != 2
        {
            return Err(Refusal::VerificationFailed("License record version"));
        }
        match d
            .u8()
            .map_err(|_| Refusal::VerificationFailed("License record tag"))?
        {
            40 => {}
            41 | 42 => {
                if !matches!(count, Some(3) | Some(4)) {
                    return Err(Refusal::VerificationFailed("Assignment record framing"));
                }
                let old = decode(
                    d.bytes()
                        .map_err(|_| Refusal::VerificationFailed("Assignment record payload"))?,
                )?;
                if old.enrollment.binding.worker_public == b.worker_public {
                    return Err(Refusal::InvalidRequest(
                        "Worker public key is already assigned or historically recorded",
                    ));
                }
            }
            _ => return Err(Refusal::VerificationFailed("License record tag")),
        }
    }
    if let Some(me) = me {
        me.check_current(v)?;
        crate::ops::select::require_profile_for_treasury(v, me)?;
        if a.owner_descriptor != me.descriptor() {
            return Err(Refusal::NotRequiredSigner(Slot::AssignmentOwner));
        }
    }
    let context = ParentContext {
        genesis: b.genesis,
        fingerprint: b.fingerprint,
        height: v.next_height()?,
        epoch: v.epoch()?,
        license,
        wallets: &v.state().wallets,
    };
    a.verify_next_epoch_state(&context).map_err(|_| {
        Refusal::VerificationFailed(
            "current License owner, next sequence and one-epoch delivery window",
        )
    })?;
    if me.is_some() && v.reserved().contains(&reserved(a)[0]) {
        return Err(Refusal::ReservedInput);
    }
    Ok(())
}
fn draft(a: &Assignment, v: &ChainView<'_>, me: &SignerIdentity) -> Result<ReviewDraft, Refusal> {
    check(a, v, Some(me))?;
    let b = &a.enrollment.binding;
    let info = crate::discovery::licenses::license(v.state(), b.license)
        .ok_or(Refusal::LicenseNotOwned)?;
    Ok(ReviewDraft {
        kind: OperationKind::WorkerAssignment,
        schema: 1,
        title: "Assign fresh Worker to License".into(),
        summary: format!(
            "Authorize License {} with the current owner {}. Exact public Worker {} and coordinator {}.",
            hex::encode(b.license),
            crate::address_format::encode_for(&info.owner, v),
            hex::encode(b.worker_id),
            hex::encode(b.coordinator)
        ),
        signer: me.summary(),
        authorizations: requirements(me),
        parties: vec![Party {
            role: PartyRole::Owner,
            address: info.owner,
            label: AddressLabel::ThisWallet,
        }],
        destinations: Vec::new(),
        amount: None,
        returned: 0,
        fee: Fee {
            atoms: 0,
            rule: FeeRule::None,
            payer: FeePayer::NotApplicable,
            size_bytes: None,
        },
        net_debit: Some(0),
        inputs: Vec::new(),
        conditions: vec![
            Condition::new(
                "Signed chain context",
                format!(
                    "Network {}; Genesis {}; fingerprint {}. This public binding is valid only in this own verified chain context.",
                    v.context().network,
                    hex::encode(b.genesis),
                    hex::encode(b.fingerprint)
                ),
            ),
            Condition::new(
                "Owner and License",
                format!(
                    "Current descriptor {}; bound owner descriptor identity {}; generation {}; License standing {}; active Worker {}; pending assignment {}.",
                    hex::encode(crate::ops::rotation::descriptor_fingerprint(
                        &a.owner_descriptor
                    )),
                    hex::encode(b.owner_descriptor),
                    b.owner_generation,
                    info.standing.text(),
                    info.mining,
                    info.pending_assignment
                ),
            ),
            Condition::new(
                "Exact device binding",
                format!(
                    "Worker public key {}; coordinator descriptor {}; configuration generation {}; device MAC {}; assignment sequence {}.",
                    hex::encode(b.worker_public),
                    hex::encode(crate::ops::rotation::descriptor_fingerprint(
                        &a.node_descriptor
                    )),
                    b.configuration_generation,
                    hex::encode(b.device_mac),
                    b.assignment_generation
                ),
            ),
            Condition::new(
                "Worker possession",
                "Verified Ed448 proof of this exact binding before owner authorization. The Worker is fresh against all own historical and pending assignments; no Worker secret enters the wallet.",
            ),
            Condition::new(
                "One-epoch delivery",
                format!(
                    "Inclusion only in mining epoch {}; activate in epoch {}; last inclusion height {}. Missing this epoch requires a fresh Worker proof, review and owner signature; retry never extends it.",
                    b.effective_epoch - 1,
                    b.effective_epoch,
                    b.valid_until_height
                ),
            ),
        ],
        timing: Timing {
            head_height: v.anchor().height,
            created_height: None,
            expiry_height: Some(b.valid_until_height),
            valid_only_at: None,
            bound_to_parent: false,
            earliest_height: Some(v.next_height()?),
            deadline_epoch: Some(b.effective_epoch),
        },
        effects: vec![Effect::new(
            "Queues the existing owner/Worker assignment carrier. A post-sale License needs a fresh Worker; sale transfers no Worker secret, ticket stream or coordinator assignment. Mining/dividend activation follows own canonical execution, not an acknowledgement.",
            true,
        )],
        warnings: if v.class() == crate::context::ChainClass::TestValue {
            vec![Warning::new(
                "TEST_VALUE_CHAIN",
                Severity::Notice,
                "This is a TEST-VALUE chain: nothing here has real value.",
            )]
        } else {
            Vec::new()
        },
        extra_acks: vec![AckKind::Conditions],
        high_risk: true,
    })
}
impl OperationHandler for Handler {
    fn kind(&self) -> OperationKind {
        OperationKind::WorkerAssignment
    }
    fn recognizes(&self, raw: &[u8]) -> bool {
        decode(raw).is_ok()
    }
    fn plan(
        &self,
        r: &OperationRequest,
        v: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        let OperationRequest::WorkerAssignment(r) = r else {
            return Err(Refusal::UnknownOperation);
        };
        let binding = Binding::decode(r.binding.as_slice())
            .map_err(|_| Refusal::Malformed("canonical assignment Binding"))?;
        let worker_signature = r
            .worker_signature
            .as_slice()
            .try_into()
            .map_err(|_| Refusal::Malformed("114-byte Worker possession"))?;
        let a = Assignment {
            enrollment: Enrollment {
                binding,
                worker_signature,
                owner_signature: HybridSignature {
                    ed448: [0; 114],
                    fndsa: [0; 1280],
                },
            },
            owner_descriptor: me.descriptor().to_vec(),
            node_descriptor: r.node_descriptor.as_slice().to_vec(),
        };
        check(&a, v, Some(me))?;
        Ok(OperationPlan::assemble(
            self.kind(),
            1,
            me.clone(),
            objects(&a)?,
            requirements(me),
            reserved(&a),
            validity(&a),
            v,
        ))
    }
    fn adopt(
        &self,
        _: &[u8],
        _: &ChainView<'_>,
        _: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        Err(Refusal::InvalidRequest(
            "create assignment from exact public Binding and Worker possession",
        ))
    }
    fn validate(&self, p: &OperationPlan, v: &ChainView<'_>) -> Result<(), Refusal> {
        check(&object(p)?, v, Some(p.signer()))
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
        let a = decode(raw)?;
        a.verify_signatures()
            .map_err(|_| Refusal::VerificationFailed("Assignment signatures"))?;
        Ok((draft(&a, v, me)?, objects(&a)?))
    }
    fn sign(
        &self,
        p: &OperationPlan,
        s: &KindSigner<'_>,
        _: &ChainView<'_>,
    ) -> Result<SignedOperation, Refusal> {
        let a = s
            .worker_assignment_authorization()?
            .authorize_assignment(object(p)?)?;
        Ok(SignedOperation::Complete {
            kind: self.kind(),
            id: id(&a)?,
            bytes: a.encode().map_err(|_| Refusal::SigningFailed)?,
            validity: validity(&a),
            reserved: reserved(&a),
        })
    }
    fn unsigned_form(&self, raw: &[u8]) -> Result<Vec<PlanObject>, Refusal> {
        objects(&decode(raw)?)
    }
    fn describe(&self, raw: &[u8]) -> Result<Description, Refusal> {
        let a = decode(raw)?;
        a.verify_signatures()
            .map_err(|_| Refusal::VerificationFailed("Assignment signatures"))?;
        Ok(Description {
            id: id(&a)?,
            complete: true,
            missing: Vec::new(),
            validity: validity(&a),
            reserved: reserved(&a),
        })
    }
    fn check_signed(&self, s: &SignedOperation, v: &ChainView<'_>) -> Result<(), Refusal> {
        let a = decode(s.bytes())?;
        a.verify_signatures()
            .map_err(|_| Refusal::VerificationFailed("Assignment signatures"))?;
        if id(&a)? != s.id() {
            return Err(Refusal::VerificationFailed("Assignment identity mismatch"));
        };
        check(&a, v, None)
    }
    fn reconcile(&self, r: &OutboxRecord, v: &ChainView<'_>) -> Settlement {
        if let Some(height) = v.confirmed_height(&r.id) {
            return Settlement::Confirmed(height);
        };
        let Ok(a) = decode(&r.bytes) else {
            return Settlement::Pending;
        };
        let b = &a.enrollment.binding;
        if v.anchor().height >= b.valid_until_height
            || v.epoch()
                .is_ok_and(|e| e.saturating_add(1) != b.effective_epoch)
        {
            return Settlement::Expired;
        }
        if v.state().licenses_v2.license(b.license).is_none_or(|l| {
            l.assignment_sequence.saturating_add(1) != b.assignment_generation
                || v.state()
                    .wallets
                    .authorize(l.owner, &a.owner_descriptor)
                    .is_err()
        }) {
            Settlement::InputsSpent
        } else {
            Settlement::Pending
        }
    }
}
