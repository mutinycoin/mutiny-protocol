//! Canonical tag-25 atomic funded rotation, with exact sponsor and restore evidence binding.
pub use crate::rotation_signer::RotationSigner;
use crate::{
    authorize::{SignedOperation, SignerIdentity},
    capability::{KeySlot, KindSigner},
    context::{ChainView, is_treasury_address, require_reserve_backing, treasury_authority},
    ops::select,
    outbox::{OutboxRecord, Settlement, resource_key},
    plan::{
        Description, FeeSource, OperationHandler, OperationKind, OperationPlan, OperationRequest,
        PlanObject, RequiredSigner, Requirement, RequirementStatus, Slot, Validity,
    },
    refusal::Refusal,
    review::{
        AckKind, AddressLabel, Condition, Destination, DestinationRole, Effect, Fee, FeePayer,
        FeeRule, InputLine, Party, PartyRole, ReviewDraft, Severity, Timing, Warning,
    },
};
use minicbor::Encoder;
use mutiny_consensus_v8::{
    Hash,
    funded_rotation_v2::{
        self, PartialRotation, Party as RotationParty, Payer, Slot as RotationSlot,
        UnsignedRotation,
    },
    hybrid_transaction_v2::Inclusion,
    transactions::{OutPoint, Output, TxError},
};
use mutiny_crypto_v2::PublicKey;
use std::collections::BTreeSet;
pub const SCHEMA: u16 = 2;
/// Label of the first plan object: the unsigned envelope.
pub const OBJECT_LABEL: &str = "rotate";
/// Label of the second plan object: the restore evidence the plan was built with.
pub const EVIDENCE_LABEL: &str = "restore-evidence";
/// Namespace of the reservation key that holds one pending rotation per authority.
pub const ROTATION_RESOURCE: &str = "wallet-rotation";
/// Tag inside the restore-evidence object.
pub const EVIDENCE_TAG: &str = "MUTINY-BUILD8-WALLET-ROTATION-RESTORE-EVIDENCE-V1";

/// Reason texts a UI and the tests key on. Since phase 8 the key, restore and address rules carry
/// dedicated codes (`ROTATION_GENERATION`, `ROTATION_KEY_REUSED` with the component's reason,
/// `RESTORE_NOT_VERIFIED` with its reason, `ROTATION_ADDRESS_TAKEN`, and `ROTATION_PENDING` for a
/// pending rotation); the payer, adoption and session rules stay `INVALID_REQUEST` reasons.
pub const REASON_WRONG_GENERATION: &str =
    "the proposed key must be exactly one generation after the current key";
pub const REASON_REUSED_ED448: &str =
    "the proposed key reuses the Ed448 component of the current key";
pub const REASON_REUSED_FNDSA: &str =
    "the proposed key reuses the FN-DSA component of the current key";
pub const REASON_RESTORE_NOT_VERIFIED: &str =
    "the host has not verified a clean restore of the new phrase";
pub const REASON_RESTORE_OTHER_DESCRIPTOR: &str =
    "the verified restore produced another descriptor than the proposed one";
pub const REASON_NEW_ADDRESS_REGISTERED: &str =
    "the proposed key's address is already registered in the wallet book";
pub const REASON_PAYER_IS_ROTATING: &str =
    "the fee payer must be another wallet than the rotating authority";
pub const REASON_ADOPT_ROTATION: &str = "a rotation is planned where both keys and the restore evidence are; the rotating wallet does not adopt rotation bytes";
pub const REASON_SESSION_KIND: &str =
    "a two-key rotation session authorizes only the wallet rotation";
/// `ROTATION_FUNDING` reasons (the fixes of the independent wallet review): the inputs of several
/// wallets are pooled in one funding transfer, so who pays whom is a question of net flows.
pub const REASON_OUTPUT_ZERO: &str = "an output of the funding goes to the zero address";
pub const REASON_OUTPUT_NOT_FUNDER: &str = "an output of the funding goes to an address that is neither a funder nor the rotating wallet authority";
pub const REASON_NET_DEBIT_ABOVE_FEE: &str = "this wallet's net debit exceeds the fee the rotation declares, so its coins would pay another party";

/// The exact irreversible statement every rotating wallet's review carries.
pub const IRREVERSIBLE_KEY_LOSS: &str = "the old key loses all spending authority at inclusion; funds are controlled only by the new key; if the new key cannot be restored from its backup the funds are unrecoverable";

pub fn descriptor_fingerprint(descriptor: &[u8]) -> Hash {
    mutiny_consensus_v8::trading_v1::descriptor_hash(descriptor)
}

/// The reservation key of "a rotation of `authority` is pending" (see `outbox::resource_key`).
pub fn rotation_resource(authority: &Hash) -> OutPoint {
    resource_key(ROTATION_RESOURCE, authority)
}

/// The restore-evidence plan object for a descriptor with `fingerprint`: canonical CBOR
/// `[EVIDENCE_TAG, true, fingerprint]`. A rotation plan is built only when the host's clean restore
/// produced exactly the proposed descriptor, so a valid plan always carries the object for the
/// fingerprint of its own proposed descriptor; it is bound into the review digest.
pub fn restore_evidence(fingerprint: &Hash) -> PlanObject {
    let mut e = Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .str(EVIDENCE_TAG)
        .unwrap()
        .bool(true)
        .unwrap()
        .bytes(fingerprint)
        .unwrap();
    PlanObject::new(EVIDENCE_LABEL, e.into_writer())
}

pub(crate) fn check_keys(
    current: &PublicKey,
    current_generation: u64,
    proposed: &PublicKey,
    proposed_generation: u64,
) -> Result<(), Refusal> {
    if current_generation.checked_add(1) != Some(proposed_generation) {
        return Err(Refusal::RotationGeneration);
    }
    if current.ed448 == proposed.ed448 {
        return Err(Refusal::RotationKeyReused(REASON_REUSED_ED448));
    }
    if current.fndsa == proposed.fndsa {
        return Err(Refusal::RotationKeyReused(REASON_REUSED_FNDSA));
    }
    Ok(())
}

pub(crate) struct Handler;
pub(crate) static HANDLER: Handler = Handler;
pub(crate) fn handler(kind: OperationKind) -> Option<&'static dyn OperationHandler> {
    (kind == OperationKind::WalletRotation).then_some(&HANDLER)
}
fn decode(raw: &[u8]) -> Result<PartialRotation, Refusal> {
    if let Ok(partial) = PartialRotation::decode(raw) {
        return Ok(partial);
    }
    let full = funded_rotation_v2::FundedRotation::decode(raw).map_err(refuse)?;
    Ok(PartialRotation {
        unsigned: full.unsigned,
        authorize: Some(full.authorize),
        possession: Some(full.possession),
        authority_funding: full.authority_funding,
        sponsor_funding: full.sponsor_funding,
    })
}
fn refuse(error: TxError) -> Refusal {
    match error {
        TxError::Future => Refusal::InvalidValidity,
        TxError::Expired => Refusal::InvalidValidity,
        TxError::MissingInput => Refusal::InputUnavailable,
        TxError::Immature => Refusal::ImmatureInput,
        TxError::Conservation => Refusal::Conservation,
        TxError::Overflow => Refusal::Overflow,
        TxError::Owner => Refusal::StaleAuthority,
        _ => Refusal::VerificationFailed("canonical funded rotation refused"),
    }
}
fn encode(p: &PartialRotation) -> Result<Vec<u8>, Refusal> {
    p.encode().map_err(refuse)
}
fn unsigned(p: &PartialRotation) -> PartialRotation {
    PartialRotation::new(p.unsigned.clone())
}
fn objects(p: &PartialRotation) -> Result<Vec<PlanObject>, Refusal> {
    Ok(vec![
        PlanObject::new(OBJECT_LABEL, encode(p)?),
        restore_evidence(&descriptor_fingerprint(&p.unsigned.proposed_descriptor)),
    ])
}
fn object(plan: &OperationPlan) -> Result<PartialRotation, Refusal> {
    let [o, evidence] = plan.objects() else {
        return Err(Refusal::Malformed(
            "rotation requires exact body and restore evidence",
        ));
    };
    if o.label != OBJECT_LABEL {
        return Err(Refusal::Malformed("rotation object label"));
    }
    let p = decode(&o.bytes)?;
    if *evidence != restore_evidence(&descriptor_fingerprint(&p.unsigned.proposed_descriptor)) {
        return Err(Refusal::RestoreNotVerified(REASON_RESTORE_OTHER_DESCRIPTOR));
    }
    Ok(p)
}
fn validity(p: &PartialRotation) -> Validity {
    let e = &p.unsigned.envelope;
    Validity {
        created: e.first_height,
        expiry: e.last_height,
        valid_only_at: None,
        bound_to_parent: false,
    }
}
fn reserved(p: &PartialRotation) -> Vec<OutPoint> {
    let mut v = p
        .unsigned
        .inputs
        .iter()
        .map(|(i, _)| i.clone())
        .collect::<Vec<_>>();
    v.push(rotation_resource(&p.unsigned.authority));
    v.sort();
    v.dedup();
    v
}
fn requirement_slot(s: RotationSlot) -> Slot {
    match s {
        RotationSlot::Authorize => Slot::RotationAuthorization,
        RotationSlot::Possession => Slot::RotationPossession,
        RotationSlot::AuthorityFunding => Slot::Input(0),
        RotationSlot::SponsorFunding => Slot::Input(1),
    }
}
fn requirements(
    p: &PartialRotation,
    me: Option<&SignerIdentity>,
) -> Result<Vec<Requirement>, Refusal> {
    let missing = p.missing().map_err(refuse)?;
    funded_rotation_v2::signing_intents(&p.unsigned)
        .map_err(refuse)?
        .iter()
        .map(|i| {
            let (key, g) = PublicKey::decode_descriptor(&i.descriptor)
                .map_err(|_| Refusal::InvalidDescriptor)?;
            let address = key.address_id(g).map_err(|_| Refusal::InvalidDescriptor)?;
            let mine = me.is_some_and(|me| {
                if i.party == RotationParty::NewKey {
                    me.descriptor() == p.unsigned.current_descriptor
                } else {
                    me.descriptor() == i.descriptor
                }
            });
            Ok(Requirement {
                slot: requirement_slot(i.slot),
                signer: RequiredSigner::Wallet(address),
                status: if !missing.contains(&i.slot) {
                    RequirementStatus::Provided
                } else if mine {
                    RequirementStatus::ThisWallet
                } else {
                    RequirementStatus::Counterparty
                },
            })
        })
        .collect()
}
fn check(p: &PartialRotation, view: &ChainView<'_>, reservations: bool) -> Result<(), Refusal> {
    if reservations
        && view
            .reserved()
            .contains(&rotation_resource(&p.unsigned.authority))
    {
        return Err(Refusal::RotationPending);
    }
    view.require_context(
        mutiny_consensus_v8::NETWORK_ID,
        &p.unsigned.genesis,
        &p.unsigned.fingerprint,
    )?;
    view.check_envelope(&p.unsigned.envelope)?;
    let (proposed, g) = PublicKey::decode_descriptor(&p.unsigned.proposed_descriptor)
        .map_err(|_| Refusal::InvalidDescriptor)?;
    let new_address = proposed
        .address_id(g)
        .map_err(|_| Refusal::InvalidDescriptor)?;
    if view
        .state()
        .wallets
        .records()
        .map_err(|_| Refusal::Malformed("wallet authority records"))?
        .contains_key(&mutiny_consensus_v8::wallet_authority_v1::address_key(
            new_address,
        ))
    {
        return Err(Refusal::RotationAddressTaken);
    }
    let minimum = funded_rotation_v2::signed_len(&p.unsigned).map_err(refuse)? as u64;
    if p.unsigned.fee < minimum {
        return Err(Refusal::FeeBelowMinimum {
            fee: p.unsigned.fee,
            minimum,
        });
    }
    p.preflight(view.state(), view.anchor(), &view.history())
        .map_err(refuse)?;
    if reservations && reserved(p).iter().any(|i| view.reserved().contains(i)) {
        return Err(Refusal::ReservedInput);
    }
    let (proposed, g) = PublicKey::decode_descriptor(&p.unsigned.proposed_descriptor)
        .map_err(|_| Refusal::InvalidDescriptor)?;
    let new_address = proposed
        .address_id(g)
        .map_err(|_| Refusal::InvalidDescriptor)?;
    let mut input_totals = [0u128; 2];
    let mut output_totals = [0u128; 2];
    for (point, payer) in &p.unsigned.inputs {
        input_totals[*payer as usize] += u128::from(
            view.state()
                .coins
                .get(point)
                .ok_or(Refusal::InputUnavailable)?
                .output
                .atoms,
        )
    }
    for output in &p.unsigned.outputs {
        let party = if output.owner == new_address
            || view
                .state()
                .wallets
                .authorize(output.owner, &p.unsigned.current_descriptor)
                .is_ok()
        {
            0
        } else if p
            .unsigned
            .sponsor
            .as_ref()
            .is_some_and(|(_, d)| view.state().wallets.authorize(output.owner, d).is_ok())
        {
            1
        } else {
            return Err(Refusal::RotationFunding(REASON_OUTPUT_NOT_FUNDER));
        };
        output_totals[party] += u128::from(output.atoms);
    }
    for index in 0..2 {
        if input_totals[index].saturating_sub(output_totals[index]) > u128::from(p.unsigned.fee) {
            return Err(Refusal::RotationFunding(REASON_NET_DEBIT_ABOVE_FEE));
        }
    }
    // A rotated Treasury still owns the proposed address; retain its change in backing checks.
    let mut outputs = p.unsigned.outputs.clone();
    for output in &mut outputs {
        if output.owner == new_address {
            output.owner = p.unsigned.authority
        }
    }
    require_reserve_backing(
        view,
        &p.unsigned.inputs.iter().map(|(i, _)| i.clone()).collect(),
        &outputs,
    )
}
fn assemble(
    p: &PartialRotation,
    view: &ChainView<'_>,
    me: &SignerIdentity,
) -> Result<OperationPlan, Refusal> {
    check(p, view, true)?;
    select::require_profile_for_treasury(view, me)?;
    let req = requirements(p, Some(me))?;
    if !req
        .iter()
        .any(|r| r.status == RequirementStatus::ThisWallet)
    {
        return Err(Refusal::NotRequiredSigner(Slot::RotationAuthorization));
    }
    Ok(OperationPlan::assemble(
        OperationKind::WalletRotation,
        SCHEMA,
        me.clone(),
        objects(p)?,
        req,
        reserved(p),
        validity(p),
        view,
    ))
}
fn signed(p: PartialRotation) -> Result<SignedOperation, Refusal> {
    let missing = requirements(&p, None)?
        .into_iter()
        .filter(|r| r.status != RequirementStatus::Provided)
        .collect::<Vec<_>>();
    // A completed exchange object must become the actual version-2/tag-25 transaction.
    // PartialRotation version 1 is deliberately refused by NODE, pool and consensus.
    let bytes = if missing.is_empty() {
        p.clone()
            .complete()
            .map_err(refuse)?
            .encode()
            .map_err(refuse)?
    } else {
        encode(&p)?
    };
    let id = if missing.is_empty() {
        p.unsigned.id().map_err(refuse)?
    } else {
        mutiny_consensus_v8::domain_hash(b"wallet-funded-rotation-partial-v2", &bytes)
    };
    let validity = validity(&p);
    let reserved = reserved(&p);
    if missing.is_empty() {
        Ok(SignedOperation::Complete {
            kind: OperationKind::WalletRotation,
            id,
            bytes,
            validity,
            reserved,
        })
    } else {
        Ok(SignedOperation::Partial {
            kind: OperationKind::WalletRotation,
            id,
            bytes,
            missing,
            validity,
            reserved,
        })
    }
}
pub fn combine(parts: &[&[u8]], view: &ChainView<'_>) -> Result<SignedOperation, Refusal> {
    let first = parts
        .first()
        .ok_or(Refusal::Malformed("no rotation parts"))?;
    let mut p = decode(first)?;
    for raw in parts.iter().skip(1) {
        let other = decode(raw)?;
        if other.unsigned != p.unsigned {
            return Err(Refusal::Malformed("different rotation commitments"));
        }
        for (left, right) in [
            (&mut p.authorize, other.authorize),
            (&mut p.possession, other.possession),
            (&mut p.authority_funding, other.authority_funding),
            (&mut p.sponsor_funding, other.sponsor_funding),
        ] {
            if left.is_some() && right.is_some() && *left != right {
                return Err(Refusal::CounterpartyApprovalInvalid);
            }
            if right.is_some() {
                *left = right
            }
        }
    }
    check(&p, view, false)?;
    signed(p)
}
fn build_review(
    p: &PartialRotation,
    view: &ChainView<'_>,
    me: &SignerIdentity,
    restore_bound: bool,
) -> Result<(ReviewDraft, Vec<PlanObject>), Refusal> {
    check(p, view, true)?;
    let u = &p.unsigned;
    let e = &u.envelope;
    let rotating = me.descriptor() == u.current_descriptor;
    let sponsoring = u
        .sponsor
        .as_ref()
        .is_some_and(|(_, d)| me.descriptor() == d);
    let mine_payer = |payer: Payer| {
        (rotating && payer == Payer::RotatingAuthority) || (sponsoring && payer == Payer::Sponsor)
    };
    let (current, current_generation) = PublicKey::decode_descriptor(&u.current_descriptor)
        .map_err(|_| Refusal::InvalidDescriptor)?;
    let (proposed, generation) = PublicKey::decode_descriptor(&u.proposed_descriptor)
        .map_err(|_| Refusal::InvalidDescriptor)?;
    let new_address = proposed
        .address_id(generation)
        .map_err(|_| Refusal::InvalidDescriptor)?;
    let authority_output = |owner| {
        owner == new_address
            || view
                .state()
                .wallets
                .authorize(owner, &u.current_descriptor)
                .is_ok()
    };
    let mine_output = |owner| {
        (rotating && authority_output(owner))
            || (sponsoring
                && u.sponsor
                    .as_ref()
                    .is_some_and(|(_, d)| view.state().wallets.authorize(owner, d).is_ok()))
    };
    let treasury = treasury_authority(view);
    let label = |owner| {
        if rotating && owner == new_address {
            AddressLabel::NewKey
        } else if mine_output(owner) {
            AddressLabel::ThisWallet
        } else if treasury
            .as_ref()
            .is_some_and(|t| is_treasury_address(view, t, &owner))
        {
            AddressLabel::Treasury
        } else {
            AddressLabel::External
        }
    };
    let inputs: Vec<_> = u
        .inputs
        .iter()
        .map(|(point, payer)| {
            let coin = &view.state().coins[point];
            InputLine {
                point: point.clone(),
                atoms: coin.output.atoms,
                owned_by_signer: mine_payer(*payer),
                coinbase: coin.coinbase,
            }
        })
        .collect();
    let spent = inputs
        .iter()
        .filter(|i| i.owned_by_signer)
        .map(|i| u128::from(i.atoms))
        .sum::<u128>();
    let returned = u
        .outputs
        .iter()
        .filter(|o| mine_output(o.owner))
        .map(|o| u128::from(o.atoms))
        .sum::<u128>();
    let total = inputs.iter().map(|i| u128::from(i.atoms)).sum::<u128>();
    let mut destinations = Vec::new();
    if rotating {
        destinations.push(Destination {
            role: DestinationRole::Change,
            address: new_address,
            label: AddressLabel::NewKey,
            atoms: u
                .outputs
                .iter()
                .filter(|o| o.owner == new_address)
                .map(|o| o.atoms)
                .try_fold(0u64, |a, b| a.checked_add(b))
                .ok_or(Refusal::Overflow)?,
        });
    }
    for output in &u.outputs {
        if mine_output(output.owner) && !(rotating && output.owner == new_address) {
            destinations.push(Destination {
                role: DestinationRole::Change,
                address: output.owner,
                label: label(output.owner),
                atoms: output.atoms,
            });
        }
    }
    let mut parties = vec![Party {
        role: PartyRole::Owner,
        address: u.authority,
        label: label(u.authority),
    }];
    let mut seen = BTreeSet::new();
    for (point, _) in &u.inputs {
        let owner = view.state().coins[point].output.owner;
        if seen.insert(owner) {
            parties.push(Party {
                role: PartyRole::FeePayer,
                address: owner,
                label: label(owner),
            });
        }
    }
    let payer = if spent > returned {
        FeePayer::ThisWallet
    } else {
        let counterparty = u
            .inputs
            .iter()
            .find(|(_, p)| !mine_payer(*p))
            .map(|(point, _)| view.state().coins[point].output.owner)
            .unwrap_or(u.authority);
        FeePayer::Counterparty(counterparty)
    };
    let size = funded_rotation_v2::signed_len(u).map_err(refuse)? as u64;
    let window = e.last_height.saturating_sub(view.anchor().height);
    let restore = if rotating && restore_bound {
        format!(
            "Verified by this wallet's host before planning: a clean restore of the new phrase produced exactly the new descriptor (fingerprint {}). The statement is bound into this review's digest; consensus verifies possession, not this rehearsal.",
            hex::encode(descriptor_fingerprint(&u.proposed_descriptor))
        )
    } else if rotating {
        "Not shown by these bytes: the rotation must be planned on the machine that verified a clean restore of the new phrase. Do not approve it unless that check was done.".into()
    } else {
        "Asserted by the rotating wallet's host; this wallet cannot verify the restore of another wallet's key.".into()
    };
    let mut conditions = vec![
        Condition::new(
            "Wallet authority",
            format!(
                "{} is the generation-one AddressID that names this wallet authority across every rotation; it does not change.",
                hex::encode(u.authority)
            ),
        ),
        Condition::new(
            "Key generation",
            format!(
                "from generation {current_generation} (current key) to generation {generation} (new key)"
            ),
        ),
        Condition::new(
            "Current key fingerprint",
            format!(
                "{} (generation {current_generation}); it loses all authority when the rotation is included",
                hex::encode(descriptor_fingerprint(&u.current_descriptor))
            ),
        ),
        Condition::new(
            "New key fingerprint",
            format!(
                "{} (generation {generation})",
                hex::encode(descriptor_fingerprint(&u.proposed_descriptor))
            ),
        ),
        Condition::new(
            "New key address",
            format!(
                "{} is the generation {generation} address of the NEW key ({}). It becomes the current address of authority {} at inclusion.",
                hex::encode(new_address),
                crate::address_format::encode_for(&new_address, view),
                hex::encode(u.authority)
            ),
        ),
        Condition::new("New key restore check", restore),
        Condition::new(
            "Canonical reference",
            format!(
                "Signed reference height {} block {}; no retry extends or rebases this reference or the finite inclusion heights.",
                e.reference_height,
                hex::encode(e.reference_block)
            ),
        ),
        Condition::new(
            "Validity window",
            format!(
                "Valid only for blocks {} to {} ({window} blocks after the verified block; {}, approximate at the {} s target interval).",
                e.first_height,
                e.last_height,
                crate::units::approx_blocks(window),
                crate::units::TARGET_BLOCK_SECONDS
            ),
        ),
        Condition::new(
            "One pending rotation",
            "Only one rotation of a wallet authority can be pending: another one is refused until this one is included or expires.",
        ),
        Condition::new(
            "Funding",
            format!(
                "All {} funding coin(s) must still be unspent at inclusion. The OLD key (the current key before inclusion) signs authority funding; the NEW key proves possession; a sponsor signs its own funding. The tag-25 carrier applies rotation and funding atomically.",
                u.inputs.len()
            ),
        ),
        Condition::new(
            "Bound funding",
            "Every authority, possession and funding signature commits to the exact sponsor, inputs, outputs, fee, context and finite heights. This funding is not a standalone transfer.",
        ),
        Condition::new(
            "Fee rule",
            format!(
                "The fee must be at least the encoded size of the complete signed tag-25 carrier: {size} bytes, so {size} atoms."
            ),
        ),
    ];
    if inputs.iter().any(|i| i.coinbase) {
        conditions.push(Condition::new(
            "Maturity",
            format!(
                "Coinbase coins must be at least {} blocks old.",
                mutiny_consensus_v8::transactions::MATURITY
            ),
        ));
    }
    let mut effects = Vec::new();
    if rotating {
        effects.push(Effect::new(IRREVERSIBLE_KEY_LOSS, true));
    }
    effects.extend([
        Effect::new(format!("Generation {generation} becomes the current key of wallet authority {}. Every address of this authority is then spent only with the new key. Only a later rotation signed by the new key changes it again.", hex::encode(u.authority)), true),
        Effect::new("Old addresses keep their coins: coins at earlier addresses of this authority stay where they are and are spent with the new key from inclusion.", false),
        Effect::new(format!("Spends {} funding coin(s) worth {}. A spent coin cannot be recovered once the rotation is included.", inputs.len(), crate::units::format_mut_wide(total)), true),
    ]);
    for o in &u.outputs {
        effects.push(Effect::new(
            format!(
                "Returns {} to the fee payer at {} ({}).",
                crate::units::format_mut(o.atoms),
                hex::encode(o.owner),
                label(o.owner).text()
            ),
            false,
        ));
    }
    effects.push(Effect::new(
        format!(
            "Pays a network fee of {} to the block producer.",
            crate::units::format_mut(u.fee)
        ),
        true,
    ));
    effects.push(Effect::new(format!("Once signed, the rotation cannot be revoked: it stays valid until it is included or until block {}.", e.last_height), true));
    let mut warnings = vec![Warning::new(
        "FUNDING_BOUND",
        Severity::Notice,
        "The tag-25 rotation and its funding are one signed atomic object; neither can be included independently.",
    )];
    if view.class() == crate::context::ChainClass::TestValue {
        warnings.push(Warning::new(
            "TEST_VALUE_CHAIN",
            Severity::Notice,
            "This is a TEST-VALUE chain: nothing here has real value.",
        ));
    }
    if rotating {
        warnings.push(Warning::new("KEY_ROTATION", Severity::Danger, "This hands the entire wallet authority to the new key. Without a backup that restores exactly this key, the funds are lost for good.").requiring(AckKind::KeyLoss));
        if !restore_bound {
            warnings.push(Warning::new("RESTORE_NOT_SHOWN", Severity::Caution, "These bytes do not show that the new key's backup was verified by a clean restore.").requiring(AckKind::KeyLoss));
        }
        if spent == 0 {
            warnings.push(Warning::new("COUNTERPARTY_FUNDED", Severity::Notice, "Another wallet pays the fee. Its exact funding signature is required; neither party can change the reviewed carrier."));
        }
    } else {
        warnings.push(Warning::new("ROTATION_OF_ANOTHER_WALLET", Severity::Notice, format!("This is the key rotation of another wallet authority ({}). It does not change this wallet's keys.", hex::encode(u.authority))));
    }
    if treasury.as_ref().is_some_and(|t| t.0 == u.authority) {
        warnings.push(Warning::new("TREASURY_ROTATION", Severity::Danger, "This rotates Treasury MUT authority; outstanding dividend reserves remain backed and License ownership and Workers remain unchanged. Bitcoin custody is separate and untouched.").requiring(AckKind::TreasuryAuthority));
    }
    if u.inputs.iter().any(|(point, _)| {
        treasury
            .as_ref()
            .is_some_and(|t| is_treasury_address(view, t, &view.state().coins[point].output.owner))
    }) {
        warnings.push(Warning::new("TREASURY_FUNDS", Severity::Caution, "Treasury coins fund this operation. Existing dividend reserves must remain backed.").requiring(AckKind::TreasuryAuthority));
    }
    let _ = current;
    Ok((
        ReviewDraft {
            kind: OperationKind::WalletRotation,
            schema: SCHEMA,
            title: if rotating && treasury.as_ref().is_some_and(|t| t.0 == u.authority) {
                "Rotate the Treasury wallet key"
            } else if rotating {
                "Rotate wallet key"
            } else if sponsoring {
                "Pay the fee of a wallet key rotation"
            } else {
                "Key rotation of another wallet"
            }
            .into(),
            summary: format!(
                "Authority {}; proposed descriptor {}; sponsor {}; exact fee {} STRIKES.",
                hex::encode(u.authority),
                hex::encode(descriptor_fingerprint(&u.proposed_descriptor)),
                u.sponsor
                    .as_ref()
                    .map_or("none".into(), |(a, _)| hex::encode(a)),
                u.fee
            ),
            signer: me.summary(),
            authorizations: requirements(p, Some(me))?,
            parties,
            destinations,
            amount: None,
            returned: u64::try_from(returned).map_err(|_| Refusal::Overflow)?,
            fee: Fee {
                atoms: u.fee,
                rule: FeeRule::OneAtomPerEncodedByte,
                payer,
                size_bytes: Some(size),
            },
            net_debit: spent.checked_sub(returned),
            inputs,
            conditions,
            timing: Timing {
                head_height: view.anchor().height,
                created_height: Some(e.first_height),
                expiry_height: Some(e.last_height),
                valid_only_at: None,
                bound_to_parent: false,
                earliest_height: None,
                deadline_epoch: None,
            },
            effects,
            warnings,
            extra_acks: vec![AckKind::Conditions],
            high_risk: rotating,
        },
        objects(&unsigned(p))?,
    ))
}

impl OperationHandler for Handler {
    fn kind(&self) -> OperationKind {
        OperationKind::WalletRotation
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
        let OperationRequest::WalletRotation(r) = request else {
            return Err(Refusal::UnknownOperation);
        };
        me.check_current(view)?;
        if view
            .reserved()
            .contains(&rotation_resource(&me.authority()))
        {
            return Err(Refusal::RotationPending);
        }
        let proposed = r.proposed_descriptor.as_slice();
        let (new, g) =
            PublicKey::decode_descriptor(proposed).map_err(|_| Refusal::InvalidDescriptor)?;
        check_keys(&me.public(), me.generation(), &new, g)?;
        let proposed_address = new.address_id(g).map_err(|_| Refusal::InvalidDescriptor)?;
        if view
            .state()
            .wallets
            .records()
            .map_err(|_| Refusal::Malformed("wallet authority records"))?
            .contains_key(&mutiny_consensus_v8::wallet_authority_v1::address_key(
                proposed_address,
            ))
        {
            return Err(Refusal::RotationAddressTaken);
        }
        if !r.new_key_restore_verified || r.restore_verified_fingerprint.is_none() {
            return Err(Refusal::RestoreNotVerified(REASON_RESTORE_NOT_VERIFIED));
        }
        if r.restore_verified_fingerprint != Some(descriptor_fingerprint(proposed)) {
            return Err(Refusal::RestoreNotVerified(REASON_RESTORE_OTHER_DESCRIPTOR));
        }
        let (payer, descriptor, change, sponsor) = match &r.fee_source {
            FeeSource::RotatingAuthority => (
                Payer::RotatingAuthority,
                me.descriptor(),
                new.address_id(g).map_err(|_| Refusal::InvalidDescriptor)?,
                None,
            ),
            FeeSource::OtherWallet(s) => {
                s.check_current(view)?;
                select::require_profile_for_treasury(view, s)?;
                if s.authority() == me.authority() {
                    return Err(Refusal::InvalidRequest(REASON_PAYER_IS_ROTATING));
                }
                (
                    Payer::Sponsor,
                    s.descriptor(),
                    s.address(),
                    Some((s.address(), s.descriptor().to_vec())),
                )
            }
        };
        let e = mutiny_consensus_v8::op_envelope_v1::Envelope::from_head(
            view.anchor(),
            r.validity_blocks,
            Vec::new(),
        )
        .map_err(|_| Refusal::InvalidValidity)?;
        let coins = select::candidates(view, descriptor, 128, &BTreeSet::new())?;
        if coins.count == 0 {
            return Err(Refusal::NothingSpendable);
        }
        let available = u64::try_from(coins.total).map_err(|_| Refusal::Overflow)?;
        let candidate_count = coins.count;
        let mut body = UnsignedRotation {
            genesis: view.context().genesis,
            fingerprint: view.context().fingerprint,
            envelope: e,
            authority: me.authority(),
            current_descriptor: me.descriptor().to_vec(),
            proposed_descriptor: proposed.to_vec(),
            sponsor,
            fee: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
        };
        let mut total = 0u64;
        let mut requested = 0u64;
        for (point, coin) in coins.coins {
            body.inputs.push((point.clone(), payer));
            body.inputs.sort();
            total = total
                .checked_add(coin.output.atoms)
                .ok_or(Refusal::Overflow)?;
            let mut fee = 0;
            for _ in 0..16 {
                if fee > total {
                    break;
                }
                body.fee = fee;
                body.outputs = if total > fee {
                    vec![Output {
                        owner: change,
                        atoms: total - fee,
                    }]
                } else {
                    Vec::new()
                };
                let need = funded_rotation_v2::signed_len(&body).map_err(refuse)? as u64;
                requested = requested.max(need);
                if need <= fee {
                    return assemble(&PartialRotation::new(body), view, me);
                }
                fee = need;
            }
        }
        if candidate_count > funded_rotation_v2::MAX_INPUTS && coins.total >= u128::from(requested)
        {
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
        if me.descriptor() == p.unsigned.current_descriptor {
            return Err(Refusal::InvalidRequest(REASON_ADOPT_ROTATION));
        }
        if !p
            .unsigned
            .sponsor
            .as_ref()
            .is_some_and(|(_, descriptor)| descriptor == me.descriptor())
        {
            return Err(Refusal::NotRequiredSigner(Slot::Input(0)));
        }
        assemble(&p, view, me)
    }
    fn validate(&self, plan: &OperationPlan, view: &ChainView<'_>) -> Result<(), Refusal> {
        select::require_profile_for_treasury(view, plan.signer())?;
        check(&object(plan)?, view, true)
    }
    fn check_requirements(
        &self,
        plan: &OperationPlan,
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<(), Refusal> {
        let p = object(plan)?;
        me.check_current(view)?;
        let expected = requirements(&p, Some(me))?;
        for r in plan.requirements() {
            if r.status == RequirementStatus::ThisWallet
                && !expected
                    .iter()
                    .any(|e| e.slot == r.slot && e.status == RequirementStatus::ThisWallet)
            {
                return Err(Refusal::NotRequiredSigner(r.slot));
            }
        }
        Ok(())
    }
    fn review(&self, plan: &OperationPlan, view: &ChainView<'_>) -> Result<ReviewDraft, Refusal> {
        build_review(&object(plan)?, view, plan.signer(), true).map(|(r, _)| r)
    }
    fn reviewed_objects(&self, plan: &OperationPlan) -> Result<Vec<PlanObject>, Refusal> {
        objects(&unsigned(&object(plan)?))
    }
    fn explain(
        &self,
        raw: &[u8],
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<(ReviewDraft, Vec<PlanObject>), Refusal> {
        build_review(&decode(raw)?, view, me, false)
    }
    fn sign(
        &self,
        plan: &OperationPlan,
        signer: &KindSigner<'_>,
        _view: &ChainView<'_>,
    ) -> Result<SignedOperation, Refusal> {
        let mut p = object(plan)?;
        if plan.signer().descriptor() == p.unsigned.current_descriptor {
            signer
                .rotation_proofs()?
                .authorize_funded_rotation(&mut p)?
        } else {
            signer
                .transfer_spend(KeySlot::Primary)?
                .authorize_rotation_funding(&mut p)?
        }
        signed(p)
    }
    fn unsigned_form(&self, raw: &[u8]) -> Result<Vec<PlanObject>, Refusal> {
        objects(&unsigned(&decode(raw)?))
    }
    fn describe(&self, raw: &[u8]) -> Result<Description, Refusal> {
        let p = decode(raw)?;
        let missing = requirements(&p, None)?
            .into_iter()
            .filter(|r| r.status != RequirementStatus::Provided)
            .collect::<Vec<_>>();
        Ok(Description {
            id: if missing.is_empty() {
                p.unsigned.id().map_err(refuse)?
            } else {
                mutiny_consensus_v8::domain_hash(b"wallet-funded-rotation-partial-v2", raw)
            },
            complete: missing.is_empty(),
            missing,
            validity: validity(&p),
            reserved: reserved(&p),
        })
    }
    fn operation_identity(&self, raw: &[u8]) -> Result<Hash, Refusal> {
        decode(raw)?.unsigned.id().map_err(refuse)
    }
    fn check_signed(&self, signed: &SignedOperation, view: &ChainView<'_>) -> Result<(), Refusal> {
        let p = decode(signed.bytes())?;
        if (if signed.is_complete() {
            p.unsigned.id().map_err(refuse)?
        } else {
            mutiny_consensus_v8::domain_hash(b"wallet-funded-rotation-partial-v2", signed.bytes())
        }) != signed.id()
        {
            return Err(Refusal::VerificationFailed("rotation identity mismatch"));
        }
        check(&p, view, false)?;
        if signed.is_complete() {
            p.complete()
                .map_err(refuse)?
                .verify(
                    &Inclusion {
                        parent: view.anchor(),
                        history: &view.history(),
                    },
                    view.state(),
                )
                .map_err(refuse)?;
        }
        Ok(())
    }
    fn reconcile(&self, record: &OutboxRecord, view: &ChainView<'_>) -> Settlement {
        if let Some(h) = view.confirmed_height(&record.id) {
            return Settlement::Confirmed(h);
        }
        let Ok(p) = decode(&record.bytes) else {
            return Settlement::Pending;
        };
        if view
            .state()
            .wallets
            .current(p.unsigned.authority)
            .is_some_and(|d| d != p.unsigned.current_descriptor)
        {
            return Settlement::InputsSpent;
        }
        if p.unsigned
            .inputs
            .iter()
            .any(|(i, _)| !view.state().coins.contains_key(i))
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
