//! The refusal table of the native wallet-authority rotation (phase 2): one test per refusal of the
//! wallet that applies to a rotation and per consensus rejection reason of the rotation (read from
//! `wallet_rotation_v1.rs`, `wallet_authority_v1.rs`, `hybrid_transaction_v2.rs`). Each refusal
//! changes no state, queues nothing and produces no signature, and each is checked against what
//! consensus itself says about the same bytes (the restore-evidence precondition and the two-key
//! session are wallet rules with no consensus counterpart, and are marked so). The hybrid mempool's
//! "one pending rotation per authority" is checked on the real chain in `e2e_rotation`.
//! NATIVE, TEST-VALUE; public test keys only.
#[path = "support/flow.rs"]
mod flow;
#[path = "support/synthetic.rs"]
mod synthetic;

use flow::approve;
use mutiny_consensus_v8::{
    Error, NETWORK_ID,
    dividend_state_v1::DividendState,
    funded_rotation_v2::{
        FundedRotation, PartialRotation, Payer, Slot as NativeSlot, UnsignedRotation,
    },
    hybrid_transaction_v2::Inclusion,
    hybrid_transaction_v2::Transaction,
    transactions::{OutPoint, Output, TxError},
    transactions_v2::{Input, Transfer},
    treasury_v1::{Class, Treasury},
    wallet_rotation_v1::Rotation as FixtureRotation,
};
use mutiny_crypto_v2::{HybridKey, HybridSignature, PublicKey, Role, rehearsal_keys_v1};
use mutiny_wallet_core_v8::{
    ops::rotation::{
        self, REASON_ADOPT_ROTATION, REASON_PAYER_IS_ROTATING, REASON_RESTORE_NOT_VERIFIED,
        REASON_RESTORE_OTHER_DESCRIPTOR, REASON_REUSED_ED448, REASON_REUSED_FNDSA,
        REASON_SESSION_KIND, RotationSigner, combine, rotation_resource,
    },
    *,
};
use std::{collections::BTreeSet, time::Duration};
use synthetic::{World, address, descriptor, identity, key_a, key_b, key_c};

fn new_key(label: &str) -> HybridKey {
    let phrase = rehearsal_keys_v1::label_phrase(label).unwrap();
    HybridKey::wallet_restore(&phrase, Role::WalletOwner).unwrap()
}

fn request_for(proposed: Vec<u8>, fee: FeeSource) -> RotationRequest {
    let fingerprint = rotation::descriptor_fingerprint(&proposed);
    RotationRequest::new(Blob::new(proposed), fee).with_restore_verified(fingerprint)
}

fn rotate(new: &HybridKey, generation: u64, fee: FeeSource) -> OperationRequest {
    OperationRequest::WalletRotation(request_for(
        new.public().descriptor(generation).unwrap(),
        fee,
    ))
}

fn zero() -> HybridSignature {
    HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    }
}

/// Key A (generation one) holds one 5,000,000 atom coin at head 100.
fn world() -> World {
    let mut world = World::new(100);
    world.coin(address(&key_a(), 1), 5_000_000, 1, false, 1, 0);
    world
}

fn native(raw: &[u8]) -> PartialRotation {
    if let Ok(p) = PartialRotation::decode(raw) {
        return p;
    }
    let f = FundedRotation::decode(raw).unwrap();
    PartialRotation {
        unsigned: f.unsigned,
        authorize: Some(f.authorize),
        possession: Some(f.possession),
        authority_funding: f.authority_funding,
        sponsor_funding: f.sponsor_funding,
    }
}
fn body(
    world: &World,
    current: Vec<u8>,
    proposed: Vec<u8>,
    first: u64,
    last: u64,
) -> UnsignedRotation {
    UnsignedRotation {
        genesis: world.anchor.genesis,
        fingerprint: world.anchor.fingerprint,
        envelope: mutiny_consensus_v8::op_envelope_v1::Envelope {
            first_height: first,
            last_height: last,
            reference_height: first.saturating_sub(1),
            reference_block: world.anchor.block,
            preconditions: Vec::new(),
        },
        authority: address(&key_a(), 1),
        current_descriptor: current,
        proposed_descriptor: proposed,
        sponsor: None,
        fee: 15_000,
        inputs: vec![(
            OutPoint {
                transaction: [1; 32],
                index: 0,
            },
            Payer::RotatingAuthority,
        )],
        outputs: vec![Output {
            owner: address(&key_a(), 1),
            atoms: 4_985_000,
        }],
    }
}
fn sign_native(
    p: &PartialRotation,
    current: &HybridKey,
    proposed: &HybridKey,
    sponsor: Option<&HybridKey>,
) -> Result<FundedRotation, TxError> {
    let mut p = PartialRotation::new(p.unsigned.clone());
    p.sign(NativeSlot::Authorize, current)?;
    p.sign(NativeSlot::Possession, proposed)?;
    if p.unsigned
        .inputs
        .iter()
        .any(|(_, payer)| *payer == Payer::RotatingAuthority)
    {
        p.sign(NativeSlot::AuthorityFunding, current)?;
    }
    if p.unsigned.sponsor.is_some() {
        p.sign(NativeSlot::SponsorFunding, sponsor.ok_or(TxError::Owner)?)?;
    }
    p.complete()
}
fn verdict(
    world: &World,
    p: &PartialRotation,
    current: &HybridKey,
    proposed: &HybridKey,
    sponsor: Option<&HybridKey>,
) -> Result<(), TxError> {
    let full = sign_native(p, current, proposed, sponsor)?;
    let view = world.view();
    let history = mutiny_consensus_v8::evidence_history_v2::History::default();
    full.verify(
        &Inclusion {
            parent: &world.anchor,
            history: &history,
        },
        &world.state,
    )
    .map(|_| ())
}
// Synthetic-book modelling only, never a block item or a native carrier parity oracle.
// Real canonical funded rotation and historical-address effects are tested in e2e_rotation.
fn model_rotation(
    world: &World,
    current: Vec<u8>,
    proposed: Vec<u8>,
    first: u64,
    last: u64,
) -> FixtureRotation {
    FixtureRotation {
        network: NETWORK_ID,
        genesis: world.anchor.genesis,
        fingerprint: world.anchor.fingerprint,
        authority: address(&key_a(), 1),
        current,
        proposed,
        created_height: first,
        expiry_height: last,
        authorization: zero(),
        possession: zero(),
    }
}
fn assert_no_trace(outbox: &MemoryOutbox) {
    assert!(outbox.records().unwrap().is_empty(), "nothing queued");
    assert!(outbox.reserved().unwrap().is_empty(), "nothing reserved");
}

#[test]
fn reusing_the_ed448_component_is_refused_by_the_wallet_and_by_consensus() {
    let world = world();
    let view = world.view();
    let (a, n) = (key_a(), new_key("w2-ref-new"));
    let mixed = PublicKey {
        role: Role::WalletOwner,
        ed448: a.public().ed448,
        fndsa: n.public().fndsa,
    }
    .descriptor(2)
    .unwrap();
    let request =
        OperationRequest::WalletRotation(request_for(mixed.clone(), FeeSource::RotatingAuthority));
    assert_eq!(
        plan(&request, &view, &identity(&a)).unwrap_err(),
        Refusal::RotationKeyReused(REASON_REUSED_ED448)
    );
    // Consensus refuses the rotation body itself.
    assert_eq!(
        body(&world, descriptor(&a, 1), mixed, 90, 200)
            .encode()
            .unwrap_err(),
        TxError::Duplicate
    );
    // The two-key session refuses the same key twice (both components reused).
    assert_eq!(
        RotationSigner::for_test(key_a(), identity(&key_a()), key_a()).unwrap_err(),
        Refusal::RotationKeyReused(REASON_REUSED_ED448)
    );
}

#[test]
fn reusing_the_fndsa_component_is_refused_by_the_wallet_and_by_consensus() {
    let world = world();
    let view = world.view();
    let (a, n) = (key_a(), new_key("w2-ref-new"));
    let mixed = PublicKey {
        role: Role::WalletOwner,
        ed448: n.public().ed448,
        fndsa: a.public().fndsa,
    }
    .descriptor(2)
    .unwrap();
    let request =
        OperationRequest::WalletRotation(request_for(mixed.clone(), FeeSource::RotatingAuthority));
    assert_eq!(
        plan(&request, &view, &identity(&a)).unwrap_err(),
        Refusal::RotationKeyReused(REASON_REUSED_FNDSA)
    );
    assert_eq!(
        body(&world, descriptor(&a, 1), mixed, 90, 200)
            .encode()
            .unwrap_err(),
        TxError::Duplicate
    );
}

#[test]
fn a_proposal_that_does_not_advance_the_generation_by_exactly_one_is_refused_by_both() {
    let world = world();
    let view = world.view();
    let n = new_key("w2-ref-new");
    for generation in [1u64, 3, 9] {
        assert_eq!(
            plan(
                &rotate(&n, generation, FeeSource::RotatingAuthority),
                &view,
                &identity(&key_a())
            )
            .unwrap_err(),
            Refusal::RotationGeneration,
            "generation {generation}"
        );
        assert_eq!(
            body(
                &world,
                descriptor(&key_a(), 1),
                n.public().descriptor(generation).unwrap(),
                90,
                200
            )
            .encode()
            .unwrap_err(),
            TxError::Owner
        );
    }
    // A descriptor that is not a wallet-owner descriptor at all.
    let mut bad = n.public().descriptor(2).unwrap();
    bad[0] ^= 1;
    assert_eq!(
        plan(
            &OperationRequest::WalletRotation(request_for(bad, FeeSource::RotatingAuthority)),
            &view,
            &identity(&key_a())
        )
        .unwrap_err(),
        Refusal::InvalidDescriptor
    );
}

#[test]
fn a_window_beyond_the_horizon_is_refused_by_both() {
    let world = world();
    let view = world.view();
    let n = new_key("w2-ref-new");
    let me = identity(&key_a());
    let proposed = n.public().descriptor(2).unwrap();
    for blocks in [0u64, 10_081, u64::MAX] {
        let request = OperationRequest::WalletRotation(
            request_for(proposed.clone(), FeeSource::RotatingAuthority)
                .with_validity_blocks(blocks),
        );
        assert_eq!(
            plan(&request, &view, &me).unwrap_err(),
            Refusal::InvalidValidity,
            "{blocks} blocks"
        );
    }
    // Exactly the horizon is allowed.
    let request = OperationRequest::WalletRotation(
        request_for(proposed.clone(), FeeSource::RotatingAuthority).with_validity_blocks(10_080),
    );
    let planned = plan(&request, &view, &me).unwrap();
    assert_eq!(
        planned.validity().expiry - planned.validity().created,
        10_080
    );
    // Consensus: the same spans on the rotation body.
    assert_eq!(
        body(
            &world,
            descriptor(&key_a(), 1),
            proposed.clone(),
            101,
            101 + 10_081
        )
        .encode()
        .unwrap_err(),
        TxError::Bounds
    );
    assert!(
        body(&world, descriptor(&key_a(), 1), proposed, 101, 101 + 10_080)
            .encode()
            .is_ok()
    );
}

#[test]
fn a_window_that_is_not_open_or_has_closed_is_refused_by_both() {
    let world = world();
    let me = identity(&key_a());
    let n = new_key("w2-ref-new");
    let planned = plan(
        &OperationRequest::WalletRotation(
            request_for(
                n.public().descriptor(2).unwrap(),
                FeeSource::RotatingAuthority,
            )
            .with_validity_blocks(10),
        ),
        &world.view(),
        &me,
    )
    .unwrap();
    assert_eq!(
        (planned.validity().created, planned.validity().expiry),
        (101, 111)
    );
    let p = native(&planned.objects()[0].bytes);
    for (head, accepted) in [(99, false), (100, true), (110, true), (111, false)] {
        let mut at = World::new(head);
        at.state = world.state.clone();
        let mut history = mutiny_consensus_v8::evidence_history_v2::History::default();
        history
            .insert_anchor(world.anchor.height, world.anchor.block)
            .unwrap();
        assert_eq!(
            review(&planned, &at.view().with_history(&history)).is_ok(),
            accepted,
            "head {head}"
        );
        // The signer reference is canonical only at the original parent or when independently supplied by History.
        // For later synthetic parents keep that exact reference in the test's declared History.
        let full = sign_native(&p, &key_a(), &n, None).unwrap();
        let mut history = mutiny_consensus_v8::evidence_history_v2::History::default();
        history
            .insert_anchor(world.anchor.height, world.anchor.block)
            .unwrap();
        assert_eq!(
            full.verify(
                &Inclusion {
                    parent: &at.anchor,
                    history: &history
                },
                &at.state
            )
            .is_ok(),
            accepted,
            "native head {head}"
        );
    }
}

#[test]
fn an_authority_this_wallet_does_not_control_is_refused_by_both() {
    let world = world();
    let view = world.view();
    let n = new_key("w2-ref-new");
    let request = rotate(&n, 2, FeeSource::RotatingAuthority);
    let foreign =
        SignerIdentity::from_public(key_b().public(), 2, Some(address(&key_a(), 1))).unwrap();
    assert_eq!(
        plan(&request, &view, &foreign).unwrap_err(),
        Refusal::StaleAuthority
    );
    let planned = plan(&request, &view, &identity(&key_a())).unwrap();
    let mut rotated = World::new(100);
    rotated.state = world.state.clone();
    rotated
        .state
        .wallets
        .register(&descriptor(&key_a(), 1))
        .unwrap();
    let other = new_key("w2-ref-other");
    let mut model = model_rotation(
        &world,
        descriptor(&key_a(), 1),
        other.public().descriptor(2).unwrap(),
        90,
        200,
    );
    model.sign(&key_a(), &other).unwrap();
    rotated
        .state
        .wallets
        .apply(&model, world.anchor.genesis, world.anchor.fingerprint, 101)
        .unwrap();
    assert_eq!(
        plan(&request, &rotated.view(), &identity(&key_a())).unwrap_err(),
        Refusal::StaleAuthority
    );
    assert_eq!(
        review(&planned, &rotated.view()).unwrap_err(),
        Refusal::StaleAuthority
    );
    assert!(
        verdict(
            &rotated,
            &native(&planned.objects()[0].bytes),
            &key_a(),
            &n,
            None
        )
        .is_err()
    );
    let session =
        RotationSigner::for_test(key_a(), identity(&key_a()), new_key("w2-ref-new")).unwrap();
    assert!(
        session
            .authorize(
                planned.clone(),
                approve(&review(&planned, &view).unwrap(), &view),
                &rotated.view()
            )
            .is_err()
    );
    assert_no_trace(&MemoryOutbox::new());
}

#[test]
fn a_pending_rotation_of_the_authority_blocks_another_until_it_is_forgotten() {
    let world = world();
    let view = world.view();
    let me = identity(&key_a());
    let authority = address(&key_a(), 1);
    let other_plan = plan(
        &rotate(&new_key("w2-ref-other"), 2, FeeSource::RotatingAuthority),
        &view,
        &me,
    )
    .unwrap();
    let session = RotationSigner::for_test(key_a(), me.clone(), new_key("w2-ref-new")).unwrap();
    let planned = plan(
        &rotate(&new_key("w2-ref-new"), 2, FeeSource::RotatingAuthority),
        &view,
        &me,
    )
    .unwrap();
    let signed = session
        .authorize(
            planned.clone(),
            approve(&review(&planned, &view).unwrap(), &view),
            &view,
        )
        .unwrap();
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&signed, &view).unwrap();
    let reserved = outbox.reserved().unwrap();
    assert!(reserved.contains(&rotation_resource(&authority)));
    let mut busy = World::new(100);
    busy.state = world.state.clone();
    busy.coin(authority, 3_000_000, 1, false, 7, 0);
    busy.reserved = reserved.clone();
    let busy_view = busy.view();
    // Another rotation of the same authority: refused at planning, at review and when explained.
    assert_eq!(
        plan(
            &rotate(&new_key("w2-ref-other"), 2, FeeSource::RotatingAuthority),
            &busy_view,
            &me
        )
        .unwrap_err(),
        Refusal::RotationPending
    );
    assert_eq!(
        review(&other_plan, &busy_view).unwrap_err(),
        Refusal::RotationPending
    );
    assert_eq!(
        explain(
            &other_plan.objects()[0].bytes,
            &busy_view,
            &identity(&key_b())
        )
        .unwrap_err(),
        Refusal::RotationPending
    );
    // The same refusal when the pending rotation holds every coin of the authority: the pending
    // rotation is named before any coin selection (not NOTHING_SPENDABLE).
    let mut drained = World::new(100);
    drained.state = world.state.clone();
    drained.reserved = reserved.clone();
    let drained_view = drained.view();
    assert_eq!(
        plan(
            &rotate(&new_key("w2-ref-other"), 2, FeeSource::RotatingAuthority),
            &drained_view,
            &me
        )
        .unwrap_err(),
        Refusal::RotationPending
    );
    // Forgetting the local record releases the slot (it does not revoke the signed bytes).
    outbox.forget(&signed.id()).unwrap();
    busy.reserved = outbox.reserved().unwrap();
    assert!(busy.reserved.is_empty());
    assert!(
        plan(
            &rotate(&new_key("w2-ref-other"), 2, FeeSource::RotatingAuthority),
            &busy.view(),
            &me
        )
        .is_ok()
    );
}

#[test]
fn insufficient_funding_is_typed_and_consensus_agrees() {
    let n = new_key("w2-ref-new");
    let me = identity(&key_a());
    let empty = World::new(100);
    assert_eq!(
        plan(
            &rotate(&n, 2, FeeSource::RotatingAuthority),
            &empty.view(),
            &me
        )
        .unwrap_err(),
        Refusal::NothingSpendable
    );
    let mut poor = World::new(100);
    let point = poor.coin(address(&key_a(), 1), 5_000, 1, false, 1, 0);
    let refused = plan(
        &rotate(&n, 2, FeeSource::RotatingAuthority),
        &poor.view(),
        &me,
    )
    .unwrap_err();
    let Refusal::InsufficientFunds {
        available,
        requested,
    } = refused
    else {
        panic!("{refused:?}")
    };
    assert_eq!(available, 5000);
    assert!(requested > available);
    let mut u = body(
        &poor,
        descriptor(&key_a(), 1),
        n.public().descriptor(2).unwrap(),
        101,
        245,
    );
    u.inputs = vec![(point, Payer::RotatingAuthority)];
    u.fee = 4999;
    u.outputs = vec![Output {
        owner: n.public().address_id(2).unwrap(),
        atoms: 1,
    }];
    assert!(requested >= mutiny_consensus_v8::funded_rotation_v2::signed_len(&u).unwrap() as u64);
    assert_eq!(
        verdict(&poor, &PartialRotation::new(u), &key_a(), &n, None).unwrap_err(),
        TxError::Fee
    );
    assert_eq!(
        plan(
            &rotate(&n, 2, FeeSource::OtherWallet(identity(&key_b()))),
            &poor.view(),
            &me
        )
        .unwrap_err(),
        Refusal::NothingSpendable
    );
}

#[test]
fn current_bare_input_count_bound_and_complete_size_are_enforced_without_retired_per_input_signatures()
 {
    let n = new_key("w2-ref-new");
    let me = identity(&key_a());
    let mut scattered = World::new(100);
    for tag in 1..=3 {
        scattered.coin(address(&key_a(), 1), 6000, 1, false, tag, 0);
    }
    // Three inputs are now representable: funding has one signature per party, not one per input.
    let planned = plan(
        &rotate(&n, 2, FeeSource::RotatingAuthority),
        &scattered.view(),
        &me,
    )
    .unwrap();
    let p = native(&planned.objects()[0].bytes);
    assert!(p.unsigned.inputs.len() >= 2);
    assert!(mutiny_consensus_v8::funded_rotation_v2::signed_len(&p.unsigned).unwrap() <= 16 * 1024);
    assert!(verdict(&scattered, &p, &key_a(), &n, None).is_ok());
    let mut u = p.unsigned.clone();
    u.inputs = (0..129)
        .map(|index| {
            (
                OutPoint {
                    transaction: [1; 32],
                    index,
                },
                Payer::RotatingAuthority,
            )
        })
        .collect();
    assert_eq!(u.encode().unwrap_err(), TxError::Bounds);
    u.inputs.truncate(128);
    assert!(u.encode().is_ok());
    u.outputs = (0..129)
        .map(|_| Output {
            owner: address(&key_a(), 1),
            atoms: 1,
        })
        .collect();
    assert_eq!(u.encode().unwrap_err(), TxError::Bounds);
}

#[test]
fn bytes_received_from_elsewhere_are_held_to_every_consensus_rule() {
    let world = world();
    let view = world.view();
    let me = identity(&key_a());
    let n = new_key("w2-ref-new");
    let planned = plan(&rotate(&n, 2, FeeSource::RotatingAuthority), &view, &me).unwrap();
    let p = native(&planned.objects()[0].bytes);
    let show = |u: &UnsignedRotation| {
        explain(
            &PartialRotation::new(u.clone()).encode().unwrap(),
            &view,
            &me,
        )
    };
    let verdict_u = |u: &UnsignedRotation| {
        verdict(&world, &PartialRotation::new(u.clone()), &key_a(), &n, None)
    };
    assert!(show(&p.unsigned).is_ok());
    assert!(verdict_u(&p.unsigned).is_ok());
    let mut cheap = p.unsigned.clone();
    cheap.fee -= 1;
    cheap.outputs[0].atoms += 1;
    assert!(matches!(show(&cheap), Err(Refusal::FeeBelowMinimum { .. })));
    assert_eq!(verdict_u(&cheap).unwrap_err(), TxError::Fee);
    let mut leaky = p.unsigned.clone();
    leaky.outputs[0].atoms -= 1;
    assert_eq!(show(&leaky).unwrap_err(), Refusal::Conservation);
    assert_eq!(verdict_u(&leaky).unwrap_err(), TxError::Conservation);
    let mut ghost = p.unsigned.clone();
    ghost.inputs[0].0.transaction = [0xee; 32];
    assert_eq!(show(&ghost).unwrap_err(), Refusal::InputUnavailable);
    assert_eq!(verdict_u(&ghost).unwrap_err(), TxError::MissingInput);
    let mut young = World::new(100);
    young.coin(address(&key_a(), 1), 5_000_000, 50, true, 1, 0);
    assert_eq!(
        explain(&planned.objects()[0].bytes, &young.view(), &me).unwrap_err(),
        Refusal::ImmatureInput
    );
    assert_eq!(
        verdict(&young, &p, &key_a(), &n, None).unwrap_err(),
        TxError::Immature
    );
    for field in 0..4 {
        let mut u = p.unsigned.clone();
        match field {
            0 => u.genesis[0] ^= 1,
            1 => u.fingerprint[0] ^= 1,
            2 => u.envelope.reference_block[0] ^= 1,
            _ => u.envelope.reference_height -= 1,
        }
        assert!(show(&u).is_err(), "context/reference {field}");
        assert!(verdict_u(&u).is_err());
    }
    let mut nobody = p.unsigned.clone();
    nobody.authority = [0; 32];
    assert_eq!(nobody.encode().unwrap_err(), TxError::Bounds);
    let mut anchor = world.anchor.clone();
    anchor.network ^= 1;
    assert_eq!(
        HeadInfo::new(anchor, 1, 1, [1; 32]).unwrap_err(),
        Refusal::WrongContext(ContextField::Network)
    );
    let mut held = World::new(100);
    held.state = world.state.clone();
    held.reserved = BTreeSet::from([p.unsigned.inputs[0].0.clone()]);
    assert_eq!(
        review(&planned, &held.view()).unwrap_err(),
        Refusal::ReservedInput
    );
    // An incorrect new-key funding signature never acquires OLD-key funding authority.
    let mut full = sign_native(&p, &key_a(), &n, None).unwrap();
    full.authority_funding = Some(
        n.sign(
            mutiny_crypto_v2::Domain::Transaction,
            &mutiny_consensus_v8::funded_rotation_v2::funding_payload(
                &p.unsigned.commitment().unwrap(),
                Payer::RotatingAuthority,
            ),
        )
        .unwrap(),
    );
    let history = mutiny_consensus_v8::evidence_history_v2::History::default();
    assert_eq!(
        full.verify(
            &Inclusion {
                parent: &world.anchor,
                history: &history
            },
            &world.state
        )
        .map(|_| ())
        .unwrap_err(),
        TxError::Signature
    );
}

#[test]
fn restore_evidence_missing_or_for_another_descriptor_is_refused() {
    // A wallet precondition (a rotation to a key whose backup was never restored can destroy the
    // funds); consensus has no counterpart and would accept the rotation.
    let world = world();
    let view = world.view();
    let me = identity(&key_a());
    let n = new_key("w2-ref-new");
    let proposed = n.public().descriptor(2).unwrap();
    let fingerprint = rotation::descriptor_fingerprint(&proposed);
    let refused = |request: RotationRequest| {
        plan(&OperationRequest::WalletRotation(request), &view, &me).unwrap_err()
    };
    // Nothing stated.
    assert_eq!(
        refused(RotationRequest::new(
            Blob::new(proposed.clone()),
            FeeSource::RotatingAuthority
        )),
        Refusal::RestoreNotVerified(REASON_RESTORE_NOT_VERIFIED)
    );
    // "Verified" without saying what.
    let mut flag_only =
        RotationRequest::new(Blob::new(proposed.clone()), FeeSource::RotatingAuthority);
    flag_only.new_key_restore_verified = true;
    assert_eq!(
        refused(flag_only),
        Refusal::RestoreNotVerified(REASON_RESTORE_NOT_VERIFIED)
    );
    // A fingerprint without the statement.
    let mut fingerprint_only =
        RotationRequest::new(Blob::new(proposed.clone()), FeeSource::RotatingAuthority);
    fingerprint_only.restore_verified_fingerprint = Some(fingerprint);
    assert_eq!(
        refused(fingerprint_only),
        Refusal::RestoreNotVerified(REASON_RESTORE_NOT_VERIFIED)
    );
    // The restore produced another descriptor: another key, or the right key at another generation.
    for other in [
        new_key("w2-ref-other").public().descriptor(2).unwrap(),
        n.public().descriptor(3).unwrap(),
    ] {
        let request =
            RotationRequest::new(Blob::new(proposed.clone()), FeeSource::RotatingAuthority)
                .with_restore_verified(rotation::descriptor_fingerprint(&other));
        assert_eq!(
            refused(request),
            Refusal::RestoreNotVerified(REASON_RESTORE_OTHER_DESCRIPTOR)
        );
    }
    // Rotation bytes from elsewhere carry no evidence: the rotating wallet does not adopt them.
    let planned = plan(&rotate(&n, 2, FeeSource::RotatingAuthority), &view, &me).unwrap();
    assert_eq!(
        adopt(&planned.objects()[0].bytes, &view, &me).unwrap_err(),
        Refusal::InvalidRequest(REASON_ADOPT_ROTATION)
    );
    // ... and its own explanation of such bytes says the evidence is not shown.
    let seen = explain(&planned.objects()[0].bytes, &view, &me).unwrap();
    assert!(
        seen.warnings()
            .iter()
            .any(|w| w.code == "RESTORE_NOT_SHOWN")
    );
    // Consensus accepts the same rotation: the precondition is the wallet's alone.
    assert!(
        verdict(
            &world,
            &native(&planned.objects()[0].bytes),
            &key_a(),
            &n,
            None
        )
        .is_ok()
    );
}

/// A co-funded rotation: key A rotates, key B pays from one 3,000,000 atom coin.
fn co_funded() -> (World, SignerIdentity, SignerIdentity, HybridKey) {
    let mut world = World::new(100);
    world.coin(address(&key_b(), 1), 3_000_000, 1, false, 2, 0);
    (
        world,
        identity(&key_a()),
        identity(&key_b()),
        new_key("w2-ref-cofund"),
    )
}

#[test]
fn a_co_funded_rotation_with_a_missing_or_tampered_approval_is_refused_and_consensus_agrees() {
    let (world, me, payer, new) = co_funded();
    let view = world.view();
    let planned = plan(
        &rotate(&new, 2, FeeSource::OtherWallet(payer.clone())),
        &view,
        &me,
    )
    .unwrap();
    let session = RotationSigner::for_test(key_a(), me.clone(), new_key("w2-ref-cofund")).unwrap();
    let part = session
        .authorize(
            planned.clone(),
            approve(&review(&planned, &view).unwrap(), &view),
            &view,
        )
        .unwrap();
    assert_eq!(
        part.missing().iter().map(|r| r.slot).collect::<Vec<_>>(),
        vec![Slot::Input(1)]
    );
    assert!(Transaction::decode(part.bytes()).is_err());
    let mut outbox = MemoryOutbox::new();
    let claimed = SignedOperation::Complete {
        kind: OperationKind::WalletRotation,
        id: part.id(),
        bytes: part.bytes().to_vec(),
        validity: *part.validity(),
        reserved: part.reserved().to_vec(),
    };
    assert!(outbox.commit(&claimed, &view).is_err());
    assert_no_trace(&outbox);
    let adopted = adopt(part.bytes(), &view, &payer).unwrap();
    let signer = KeySigner::for_test(key_b()).unwrap();
    let full = signer
        .authorize(
            adopted.clone(),
            approve(&review(&adopted, &view).unwrap(), &view),
            &view,
        )
        .unwrap();
    assert!(full.is_complete());
    let history = mutiny_consensus_v8::evidence_history_v2::History::default();
    for slot in 0..2 {
        let mut broken = FundedRotation::decode(full.bytes()).unwrap();
        if slot == 0 {
            broken.sponsor_funding.as_mut().unwrap().fndsa[700] ^= 0x10;
        } else {
            broken.possession.ed448[3] ^= 1;
        }
        let raw = broken.encode().unwrap();
        assert!(combine(&[part.bytes(), &raw], &view).is_err());
        assert!(SignedOperation::import(&raw, &view).is_err());
        assert!(adopt(&raw, &view, &payer).is_err());
        assert!(explain(&raw, &view, &payer).is_err());
        assert_eq!(
            broken
                .verify(
                    &Inclusion {
                        parent: &world.anchor,
                        history: &history
                    },
                    &world.state
                )
                .map(|_| ())
                .unwrap_err(),
            TxError::Signature
        );
    }
    let other = plan(
        &rotate(
            &new_key("w2-ref-cofund-other"),
            2,
            FeeSource::OtherWallet(payer.clone()),
        ),
        &view,
        &me,
    )
    .unwrap();
    let adopted = adopt(&other.objects()[0].bytes, &view, &payer).unwrap();
    let other_part = signer
        .authorize(
            adopted.clone(),
            approve(&review(&adopted, &view).unwrap(), &view),
            &view,
        )
        .unwrap();
    assert!(combine(&[part.bytes(), other_part.bytes()], &view).is_err());
    assert!(
        combine(&[part.bytes(), full.bytes()], &view)
            .unwrap()
            .is_complete()
    );
    assert_no_trace(&outbox);
}

#[test]
fn the_payer_must_be_another_current_wallet() {
    let (world, me, _payer, new) = co_funded();
    let view = world.view();
    assert_eq!(
        plan(
            &rotate(&new, 2, FeeSource::OtherWallet(me.clone())),
            &view,
            &me
        )
        .unwrap_err(),
        Refusal::InvalidRequest(REASON_PAYER_IS_ROTATING)
    );
    let stale_payer =
        SignerIdentity::from_public(key_b().public(), 2, Some(address(&key_b(), 1))).unwrap();
    assert_eq!(
        plan(
            &rotate(&new, 2, FeeSource::OtherWallet(stale_payer)),
            &view,
            &me
        )
        .unwrap_err(),
        Refusal::StaleAuthority
    );
    // A wallet that owns no funding input has nothing to adopt.
    let planned = plan(
        &rotate(&new, 2, FeeSource::OtherWallet(identity(&key_b()))),
        &view,
        &me,
    )
    .unwrap();
    assert_eq!(
        adopt(&planned.objects()[0].bytes, &view, &identity(&key_c())).unwrap_err(),
        Refusal::NotRequiredSigner(Slot::Input(0))
    );
}

#[test]
fn treasury_coins_and_the_treasury_authority_need_the_treasury_profile() {
    let mut world = World::new(100);
    let treasury = key_c();
    world
        .state
        .wallets
        .register(&descriptor(&treasury, 1))
        .unwrap();
    world.state.dividends =
        DividendState::genesis(Treasury::new(Class::TestValue, descriptor(&treasury, 1)).unwrap());
    world.coin(address(&treasury, 1), 2_000_000, 1, false, 3, 0);
    let view = world.view();
    let ordinary = identity(&treasury);
    let profiled = ordinary
        .clone()
        .with_treasury_roles_for_test(TreasuryRoles {
            authority: true,
            destination_of: None,
        });
    let new = new_key("w2-ref-treasury-new");

    // Rotating the Treasury authority.
    assert_eq!(
        plan(
            &rotate(&new, 2, FeeSource::RotatingAuthority),
            &view,
            &ordinary
        )
        .unwrap_err(),
        Refusal::TreasuryProfileRequired
    );
    let planned = plan(
        &rotate(&new, 2, FeeSource::RotatingAuthority),
        &view,
        &profiled,
    )
    .unwrap();
    let reviewed = review(&planned, &view).unwrap();
    assert!(
        reviewed
            .acknowledgements()
            .contains(&AckKind::TreasuryAuthority)
    );

    // Paying another wallet's rotation with Treasury coins.
    let a_new = new_key("w2-ref-new");
    let me = identity(&key_a());
    assert_eq!(
        plan(
            &rotate(&a_new, 2, FeeSource::OtherWallet(ordinary.clone())),
            &view,
            &me
        )
        .unwrap_err(),
        Refusal::TreasuryProfileRequired
    );
    let paid_by_treasury = plan(
        &rotate(&a_new, 2, FeeSource::OtherWallet(profiled.clone())),
        &view,
        &me,
    )
    .unwrap();
    // The Treasury's own adoption: only under the Treasury profile.
    assert_eq!(
        adopt(&paid_by_treasury.objects()[0].bytes, &view, &ordinary).unwrap_err(),
        Refusal::TreasuryProfileRequired
    );
    let adopted = adopt(&paid_by_treasury.objects()[0].bytes, &view, &profiled).unwrap();
    let payer_review = review(&adopted, &view).unwrap();
    assert!(
        payer_review
            .warnings()
            .iter()
            .any(|w| w.code == "TREASURY_FUNDS")
    );
    assert!(
        payer_review
            .acknowledgements()
            .contains(&AckKind::TreasuryAuthority)
    );
}

#[test]
fn a_new_key_whose_address_is_already_registered_is_refused_by_both() {
    let mut world = world();
    let n = new_key("w2-ref-new");
    // Key B already rotated to the same new key at generation two.
    world
        .state
        .wallets
        .register(&descriptor(&key_b(), 1))
        .unwrap();
    let mut b_rotation = FixtureRotation {
        authority: address(&key_b(), 1),
        ..model_rotation(
            &world,
            descriptor(&key_b(), 1),
            n.public().descriptor(2).unwrap(),
            90,
            200,
        )
    };
    b_rotation.sign(&key_b(), &n).unwrap();
    world
        .state
        .wallets
        .apply(
            &b_rotation,
            world.anchor.genesis,
            world.anchor.fingerprint,
            101,
        )
        .unwrap();
    let view = world.view();
    assert_eq!(
        plan(
            &rotate(&n, 2, FeeSource::RotatingAuthority),
            &view,
            &identity(&key_a())
        )
        .unwrap_err(),
        Refusal::RotationAddressTaken
    );
    // Consensus: the wallet book refuses the duplicate address.
    world
        .state
        .wallets
        .register(&descriptor(&key_a(), 1))
        .unwrap();
    let mut a_rotation = model_rotation(
        &world,
        descriptor(&key_a(), 1),
        n.public().descriptor(2).unwrap(),
        90,
        200,
    );
    a_rotation.sign(&key_a(), &n).unwrap();
    assert_eq!(
        world
            .state
            .wallets
            .apply(
                &a_rotation,
                world.anchor.genesis,
                world.anchor.fingerprint,
                101
            )
            .unwrap_err(),
        Error::Duplicate
    );
}

#[test]
fn the_rotation_session_idle_limit_can_be_shortened_never_lengthened() {
    // Fixes of the independent wallet review, MINOR-6: `RotationSigner::new` given
    // `Duration::MAX` locks both keys after `DEFAULT_IDLE_LIMIT`; a shorter limit is honoured.
    let world = world();
    let view = world.view();
    let me = identity(&key_a());
    let n = new_key("w2-ref-new");
    let planned = plan(&rotate(&n, 2, FeeSource::RotatingAuthority), &view, &me).unwrap();
    let reviewed = review(&planned, &view).unwrap();
    let second = Duration::from_secs(1);
    for (limit, idle, locks) in [
        (Duration::MAX, DEFAULT_IDLE_LIMIT, true),
        (Duration::MAX, DEFAULT_IDLE_LIMIT - second, false),
        (Duration::from_secs(10), Duration::from_secs(10), true),
        (Duration::from_secs(10), Duration::from_secs(9), false),
    ] {
        let session = RotationSigner::new(
            key_a(),
            me.clone(),
            new_key("w2-ref-new"),
            SigningGate::test_value().unwrap(),
            limit,
        )
        .unwrap();
        let now = std::time::Instant::now() + idle;
        let result = session.authorize_at(planned.clone(), approve(&reviewed, &view), &view, now);
        assert_eq!(
            result.as_ref().err() == Some(&Refusal::Locked),
            locks,
            "limit {limit:?}, idle {idle:?}: {:?}",
            result.err()
        );
    }
}

#[test]
fn the_two_key_session_refuses_everything_but_its_own_rotation() {
    // Wallet rules of the signing session; nothing reaches consensus in any of these cases.
    let world = world();
    let view = world.view();
    let me = identity(&key_a());
    let n = new_key("w2-ref-new");
    let planned = plan(&rotate(&n, 2, FeeSource::RotatingAuthority), &view, &me).unwrap();
    let reviewed = review(&planned, &view).unwrap();
    let outbox = MemoryOutbox::new();

    // A session holding another new key than the plan's proposal.
    let wrong = RotationSigner::for_test(key_a(), me.clone(), new_key("w2-ref-other")).unwrap();
    assert_eq!(
        wrong
            .authorize(planned.clone(), approve(&reviewed, &view), &view)
            .unwrap_err(),
        Refusal::NotRequiredSigner(Slot::RotationPossession)
    );
    // A single-key signer cannot produce the possession proof.
    let single = KeySigner::for_test(key_a()).unwrap();
    assert_eq!(
        single
            .authorize(planned.clone(), approve(&reviewed, &view), &view)
            .unwrap_err(),
        Refusal::NotRequiredSigner(Slot::RotationPossession)
    );
    // Another wallet's session is not the plan's signer.
    let stranger =
        RotationSigner::for_test(key_b(), identity(&key_b()), new_key("w2-ref-new")).unwrap();
    assert_eq!(
        stranger
            .authorize(planned.clone(), approve(&reviewed, &view), &view)
            .unwrap_err(),
        Refusal::NotRequiredSigner(Slot::RotationAuthorization)
    );
    // The session signs the rotation and nothing else.
    let session = RotationSigner::for_test(key_a(), me.clone(), new_key("w2-ref-new")).unwrap();
    let payment = plan(
        &OperationRequest::Payment(PaymentRequest::new(address(&key_b(), 1), 1_000)),
        &view,
        &me,
    )
    .unwrap();
    let payment_review = review(&payment, &view).unwrap();
    assert_eq!(
        session
            .authorize(payment, approve(&payment_review, &view), &view)
            .unwrap_err(),
        Refusal::InvalidRequest(REASON_SESSION_KIND)
    );
    // An approval for another plan, and an approval for another head.
    let other = plan(
        &rotate(&new_key("w2-ref-other"), 2, FeeSource::RotatingAuthority),
        &view,
        &me,
    )
    .unwrap();
    let other_approval = approve(&review(&other, &view).unwrap(), &view);
    assert_eq!(
        session
            .authorize(planned.clone(), other_approval, &view)
            .unwrap_err(),
        Refusal::PlanChanged
    );
    let moved = world.advanced();
    assert!(matches!(
        session
            .authorize(planned.clone(), approve(&reviewed, &view), &moved.view())
            .unwrap_err(),
        Refusal::StaleHead { .. }
    ));
    // Locked, and idle-expired.
    session.lock();
    assert_eq!(
        session
            .authorize(planned.clone(), approve(&reviewed, &view), &view)
            .unwrap_err(),
        Refusal::Locked
    );
    assert_eq!(session.touch().unwrap_err(), Refusal::Locked);
    let idle = RotationSigner::new(
        key_a(),
        me.clone(),
        new_key("w2-ref-new"),
        SigningGate::test_value().unwrap(),
        Duration::from_millis(0),
    )
    .unwrap();
    assert_eq!(
        idle.authorize(planned.clone(), approve(&reviewed, &view), &view)
            .unwrap_err(),
        Refusal::Locked
    );
    // A session whose current key is not the identity's.
    assert_eq!(
        RotationSigner::for_test(key_b(), me.clone(), new_key("w2-ref-new")).unwrap_err(),
        Refusal::InvalidDescriptor
    );
    // No production gate exists while production qualification is incomplete.
    if !mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED {
        assert_eq!(SigningGate::production().unwrap_err(), Refusal::GateClosed);
    }
    assert_no_trace(&outbox);
    // The genuine session still works afterwards: none of the refusals changed anything.
    let fresh = RotationSigner::for_test(key_a(), me, new_key("w2-ref-new")).unwrap();
    assert!(
        fresh
            .authorize(planned, approve(&reviewed, &view), &view)
            .unwrap()
            .is_complete()
    );
}
