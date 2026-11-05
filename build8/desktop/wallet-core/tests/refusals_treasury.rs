//! The refusal table of the Treasury profile (phase 6): every refusal that applies to the Treasury
//! destination rotation (`TreasuryRotate`, R2) and to the Treasury offer-freeze authorization, and
//! every consensus rejection reason of those operations. Each case asserts that the wallet refuses
//! (plan, adopt or explain, and import), that nothing is signed or queued (the outbox stays empty),
//! and what consensus says about the same operation signed by hand (`trading_v1::prepare_batch` for
//! a rotation; `prepare_treasury_offer` / `FrozenTreasuryOffer::decode` /
//! `verify_frozen_treasury_offer_at_creation` for a freeze). Where a refusal is a wallet rule with no
//! consensus counterpart (the profile, the chain class, the signing gate, reservations), the test
//! says so and shows consensus would accept.
//!
//! Synthetic state at head 100 (no blocks): the TEST-VALUE Genesis Treasury is key B (zoo) holding
//! 5,000,000 + 300,000 at its generation-one address; trading Treasury `TRADING_TREASURY` has key B's
//! generation-one address as its generation-one destination; key A is registered; key C is not.
//! The reserve case needs a real dividend award and runs on the real rig.
//! NATIVE, TEST-VALUE; public test keys.
#[path = "support/treasury_kit.rs"]
mod kit;
#[path = "support/synthetic.rs"]
mod synthetic;
#[path = "support/treasury_rig.rs"]
mod treasury_rig;

use kit::{FreezeTerms, TRADING_TREASURY};
use mutiny_consensus_v8::{
    Hash,
    dividend_state_v1::DividendState,
    trading_v1::{
        self, Action, FrozenTreasuryOffer, NativeError, NativeOperation, NativeRecord, OfferProof,
        SignedOffer, Strikes, TreasuryDestination, native_input_id, record_key,
        treasury_address_id, treasury_generation_id,
    },
    transactions::OutPoint,
    treasury_v1::{Class, Treasury},
    wallet_rotation_v1::Rotation,
};
use mutiny_crypto_v2::{HybridKey, Role};
use mutiny_wallet_core_v8::{
    ops::treasury::{self, freeze_proposal, rotation_resource},
    profile::{self, TreasuryDeclaration},
    *,
};
use std::collections::BTreeSet;
use synthetic::{World, address, descriptor, identity, key_a, key_b, key_c};

const T: Hash = TRADING_TREASURY;

fn key_d() -> HybridKey {
    let phrase = mutiny_crypto_v2::rehearsal_keys_v1::label_phrase("w6-refusals-key-d").unwrap();
    HybridKey::wallet_restore(&phrase, Role::WalletOwner).unwrap()
}

/// The synthetic Treasury world at `head`.
fn world_at(head: u64, class: Option<Class>) -> World {
    let mut world = World::new(head);
    world
        .state
        .wallets
        .register(&descriptor(&key_b(), 1))
        .unwrap();
    world
        .state
        .wallets
        .register(&descriptor(&key_a(), 1))
        .unwrap();
    if let Some(class) = class {
        world.state.dividends =
            DividendState::genesis(Treasury::new(class, descriptor(&key_b(), 1)).unwrap());
    }
    world.coin(address(&key_b(), 1), 5_000_000, 1, false, 0xd1, 0);
    world.coin(address(&key_b(), 1), 300_000, 1, false, 0xd2, 0);
    world.coin(address(&key_a(), 1), 900_000, 1, false, 0xa1, 0);
    let context = kit::context_of(&world.anchor);
    for (key, raw) in
        trading_v1::treasury_genesis_records(&context, T, descriptor(&key_b(), 1)).unwrap()
    {
        world.state.protocol_records.insert(key, raw);
    }
    world
}

fn world() -> World {
    world_at(100, Some(Class::TestValue))
}

fn treasury_me() -> SignerIdentity {
    identity(&key_b()).with_treasury_roles_for_test(TreasuryRoles {
        authority: true,
        destination_of: Some(T),
    })
}

/// TEST-only signed state model of an earlier R1; no fabricated canonical confirmation.
fn rotation_world_at(head: u64, class: Option<Class>) -> World {
    let mut world = world_at(head, class);
    assert!(head >= 2);
    let included = head - 1;
    let mut r1 = Rotation {
        network: world.anchor.network,
        genesis: world.anchor.genesis,
        fingerprint: world.anchor.fingerprint,
        authority: T,
        current: descriptor(&key_b(), 1),
        proposed: descriptor(&key_c(), 2),
        created_height: included,
        expiry_height: head.saturating_add(100),
        authorization: kit::zero(),
        possession: kit::zero(),
    };
    r1.sign(&key_b(), &key_c()).unwrap();
    world
        .state
        .wallets
        .apply(
            &r1,
            world.anchor.genesis,
            world.anchor.fingerprint,
            included,
        )
        .unwrap();
    assert_eq!(
        world.state.wallets.current(T).unwrap(),
        descriptor(&key_c(), 2)
    );
    assert!(
        world
            .state
            .wallets
            .authorize(T, &descriptor(&key_b(), 1))
            .is_err()
    );
    world
}
fn rotation_world() -> World {
    rotation_world_at(100, Some(Class::TestValue))
}
fn rotation_me() -> SignerIdentity {
    SignerIdentity::from_public(key_c().public(), 2, Some(T))
        .unwrap()
        .with_treasury_roles_for_test(TreasuryRoles {
            authority: true,
            destination_of: Some(T),
        })
}

fn rotate_to(new_descriptor: Vec<u8>) -> OperationRequest {
    let fingerprint = trading_v1::descriptor_hash(&new_descriptor);
    OperationRequest::TreasuryRotate(
        TreasuryRotateRequest::new(Blob::new(new_descriptor)).with_verified_restore(T, fingerprint),
    )
}

/// The rotation of `T` to key C (generation one), planned by the Treasury profile of key B.
fn planned_rotation(world: &World) -> OperationPlan {
    plan(
        &rotate_to(descriptor(&key_c(), 2)),
        &world.view(),
        &rotation_me(),
    )
    .unwrap()
}

/// The unsigned bytes of `planned` after `edit`.
fn edited(planned: &OperationPlan, edit: impl FnOnce(&mut NativeOperation)) -> Vec<u8> {
    let mut wire = kit::wire(&planned.objects()[0].bytes);
    edit(&mut wire);
    wire.encode().unwrap()
}

/// The metadata a signed rotation commits to (what `describe` derives), for queueing attempts.
fn as_signed(raw: &[u8]) -> SignedOperation {
    let wire = kit::wire(raw);
    let Action::TreasuryRotate {
        treasury,
        current_generation,
        ..
    } = &wire.operation.action
    else {
        panic!("not a rotation");
    };
    let mut reserved = wire.inputs.clone();
    reserved.push(rotation_resource(treasury, *current_generation));
    reserved.sort();
    reserved.dedup();
    SignedOperation::Complete {
        kind: OperationKind::TreasuryRotate,
        id: wire.operation.id().unwrap(),
        bytes: raw.to_vec(),
        validity: Validity {
            created: wire.operation.meta.envelope.first_height,
            expiry: wire.operation.meta.envelope.last_height,
            valid_only_at: None,
            bound_to_parent: false,
        },
        reserved,
    }
}

/// Signed bytes cannot be imported, and the outbox refuses them and stays empty.
fn nothing_queues(raw: &[u8], view: &ChainView<'_>) {
    assert!(SignedOperation::import(raw, view).is_err());
    let mut outbox = MemoryOutbox::new();
    assert!(outbox.commit(&as_signed(raw), view).is_err());
    assert!(outbox.records().unwrap().is_empty());
    assert!(outbox.reserved().unwrap().is_empty());
}

/// The wallet refuses `edit` of the planned rotation with `wallet` (explain and adopt of the
/// unsigned bytes, explain of the signed bytes), nothing queues, and consensus refuses the signed
/// operation as `consensus` says.
fn both_refuse(
    world: &World,
    what: &str,
    edit: impl Fn(&mut NativeOperation),
    wallet: Refusal,
    consensus: impl Fn(&NativeError) -> bool,
) {
    let view = world.view();
    let planned = planned_rotation(world);
    let unsigned = edited(&planned, &edit);
    assert_eq!(
        explain(&unsigned, &view, &rotation_me()).unwrap_err(),
        wallet,
        "{what}: explain"
    );
    assert_eq!(
        adopt(&unsigned, &view, &rotation_me()).unwrap_err(),
        wallet,
        "{what}: adopt"
    );
    let signed = kit::resigned(&planned.objects()[0].bytes, &key_c(), 2, &edit);
    let verdict = kit::consensus_in(&view, &signed).unwrap_err();
    assert!(consensus(&verdict), "{what}: consensus said {verdict:?}");
    nothing_queues(&signed, &view);
}

fn set_rotation(wire: &mut NativeOperation, f: impl FnOnce(&mut Action)) {
    f(&mut wire.operation.action);
}

#[test]
fn the_synthetic_world_hashes_and_the_plan_is_accepted_by_consensus() {
    let world = rotation_world();
    let view = world.view();
    assert_eq!(view.state_root(), world.state.root().unwrap());
    let planned = planned_rotation(&world);
    let signed = kit::signed_with(kit::wire(&planned.objects()[0].bytes), 0, &key_c(), 2);
    kit::consensus_in(&view, &signed).expect("the positive control");
    // The wallet's own signature path agrees.
    let reviewed = review(&planned, &view).unwrap();
    let ours = KeySigner::with_identity(
        key_c(),
        rotation_me(),
        SigningGate::test_value().unwrap(),
        DEFAULT_IDLE_LIMIT,
    )
    .unwrap()
    .authorize(planned, kit::approve(&reviewed, &view), &view)
    .unwrap();
    kit::consensus_in(&view, ours.bytes()).unwrap();
}

#[test]
fn an_ordinary_identity_never_reaches_a_treasury_operation() {
    let world = rotation_world();
    let view = world.view();
    let ordinary = SignerIdentity::from_public(key_c().public(), 2, Some(T)).unwrap();
    let mut outbox = MemoryOutbox::new();
    assert_eq!(
        plan(&rotate_to(descriptor(&key_c(), 2)), &view, &ordinary).unwrap_err(),
        Refusal::TreasuryProfileRequired
    );
    // Bytes planned by the Treasury profile elsewhere cannot be adopted by an ordinary identity.
    let planned = planned_rotation(&world);
    assert_eq!(
        adopt(&planned.objects()[0].bytes, &view, &ordinary).unwrap_err(),
        Refusal::TreasuryProfileRequired
    );
    // A key signer for the ordinary identity is not the plan's signer: no signature.
    let reviewed = review(&planned, &view).unwrap();
    assert_eq!(
        KeySigner::with_identity(
            key_c(),
            SignerIdentity::from_public(key_c().public(), 2, Some(T)).unwrap(),
            SigningGate::test_value().unwrap(),
            DEFAULT_IDLE_LIMIT
        )
        .unwrap()
        .authorize(planned.clone(), kit::approve(&reviewed, &view), &view)
        .unwrap_err(),
        Refusal::NotRequiredSigner(Slot::Approval(0))
    );
    // A freeze, planned or adopted.
    let proposal = freeze_proposal_at(&world, &FreezeOptions::default());
    assert_eq!(
        plan(&freeze_request(proposal.clone()), &view, &ordinary).unwrap_err(),
        Refusal::TreasuryProfileRequired
    );
    assert_eq!(
        adopt(&proposal, &view, &ordinary).unwrap_err(),
        Refusal::TreasuryProfileRequired
    );
    assert!(outbox.records().unwrap().is_empty());
    let _ = &mut outbox;
    // Consensus has no profile rule: the same rotation signed by hand is valid. The profile is the
    // wallet's own, stricter rule.
    let signed = kit::signed_with(kit::wire(&planned.objects()[0].bytes), 0, &key_c(), 2);
    assert!(kit::consensus_in(&view, &signed).is_ok());
}

#[test]
fn another_wallet_with_the_profile_label_still_cannot_rotate_or_freeze() {
    let world = rotation_world();
    let view = world.view();
    let impostor = identity(&key_a()).with_treasury_roles_for_test(TreasuryRoles {
        authority: true,
        destination_of: Some(T),
    });
    // No Treasury is controlled by key A: nothing is chosen, and naming one does not help.
    assert_eq!(
        plan(&rotate_to(descriptor(&key_c(), 2)), &view, &impostor).unwrap_err(),
        Refusal::NotRequiredSigner(Slot::Approval(0))
    );
    assert_eq!(
        plan(
            &OperationRequest::TreasuryRotate(
                TreasuryRotateRequest::new(Blob::new(descriptor(&key_c(), 2)))
                    .with_treasury(T)
                    .with_verified_restore(
                        T,
                        trading_v1::descriptor_hash(&descriptor(&key_c(), 2))
                    )
            ),
            &view,
            &impostor
        )
        .unwrap_err(),
        Refusal::NotRequiredSigner(Slot::Approval(0))
    );
    // The declaration refuses the label in the first place.
    assert_eq!(
        profile::declare(
            identity(&key_a()),
            &TreasuryDeclaration::new([1; 32], ChainClass::TestValue).with_destination_of(T),
            &view
        )
        .unwrap_err(),
        Refusal::NotRequiredSigner(Slot::Approval(0))
    );
    // Bare R2 wire cannot carry fresh host restore evidence, even for the real authority.
    let planned = planned_rotation(&world);
    assert_eq!(
        adopt(&planned.objects()[0].bytes, &view, &impostor).unwrap_err(),
        Refusal::RestoreNotVerified(
            "R2 must be planned with fresh host restore evidence; bare wire adoption is unavailable"
        )
    );
    // Consensus: an approval by A for the Treasury is not authorized.
    let signed = kit::signed_with(kit::wire(&planned.objects()[0].bytes), 0, &key_a(), 1);
    assert_eq!(
        kit::consensus_in(&view, &signed),
        Err(NativeError::Authority)
    );
    assert!(matches!(
        explain(&signed, &view, &rotation_me()).unwrap_err(),
        Refusal::CounterpartyApprovalInvalid
    ));
    nothing_queues(&signed, &view);
    // A freeze naming B's descriptor cannot be planned by A.
    let proposal = freeze_proposal_at(&world, &FreezeOptions::default());
    assert_eq!(
        plan(&freeze_request(proposal), &view, &impostor).unwrap_err(),
        Refusal::NotRequiredSigner(Slot::TreasuryFreeze)
    );
}

#[test]
fn the_chain_class_is_respected() {
    // A chain that declares no class (no Treasury record): Treasury operations are refused.
    let undeclared = rotation_world_at(100, None);
    let view = undeclared.view();
    assert_eq!(view.class(), ChainClass::Undeclared);
    assert_eq!(
        plan(&rotate_to(descriptor(&key_c(), 2)), &view, &rotation_me()).unwrap_err(),
        Refusal::TreasuryClassUndeclared
    );
    // Native P6 also rejects a Treasury without the Genesis dividend Treasury identity.
    let hand = kit::HandRotation {
        reference: view.anchor().clone(),
        treasury: T,
        current_generation: 1,
        current_address: address(&key_b(), 1),
        current_descriptor: descriptor(&key_c(), 2),
        new_generation: 2,
        new_address: address(&key_c(), 2),
        new_descriptor: descriptor(&key_c(), 2),
        inputs: vec![(point(0xd1), 5_000_000)],
        created: 101,
        expiry: 120,
    };
    // Same genuine current2 body/approvals/facts passes with the canonical Genesis Treasury.
    let backed = rotation_world();
    let positive = backed.view();
    let raw = kit::hand_rotation_in_view(&positive, &hand, &key_c(), 2);
    kit::consensus_in(&positive, &raw).unwrap();
    assert_eq!(kit::consensus_in(&view, &raw), Err(NativeError::Record));

    // A production chain: planning and review only read the chain; the TEST-VALUE gate refuses to
    // sign, and the production gate does not exist while production is unqualified.
    let production = rotation_world_at(100, Some(Class::Production));
    let view = production.view();
    assert_eq!(view.class(), ChainClass::Production);
    let planned = plan(&rotate_to(descriptor(&key_c(), 2)), &view, &rotation_me()).unwrap();
    let reviewed = review(&planned, &view).unwrap();
    assert!(reviewed.render_text().contains("production"));
    let signer = KeySigner::with_identity(
        key_c(),
        rotation_me(),
        SigningGate::test_value().unwrap(),
        DEFAULT_IDLE_LIMIT,
    )
    .unwrap();
    assert_eq!(
        signer
            .authorize(planned, kit::approve(&reviewed, &view), &view)
            .unwrap_err(),
        Refusal::ChainClassMismatch {
            gate: ChainClass::TestValue,
            chain: ChainClass::Production
        }
    );
    if !mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED {
        assert_eq!(SigningGate::production().unwrap_err(), Refusal::GateClosed);
    }
    // The declaration names the class it expects.
    assert_eq!(
        profile::declare(
            identity(&key_b()),
            &TreasuryDeclaration::new([1; 32], ChainClass::TestValue).with_authority(),
            &view
        )
        .unwrap_err(),
        Refusal::ChainClassMismatch {
            gate: ChainClass::TestValue,
            chain: ChainClass::Production
        }
    );
    // A production freeze is refused at signing the same way.
    let proposal = freeze_proposal_at(&production, &FreezeOptions::default());
    let planned = plan(&freeze_request(proposal), &view, &rotation_me()).unwrap();
    let reviewed = review(&planned, &view).unwrap();
    assert!(matches!(
        signer
            .authorize(planned, kit::approve(&reviewed, &view), &view)
            .unwrap_err(),
        Refusal::ChainClassMismatch { .. }
    ));
}

#[test]
fn the_new_destination_must_already_resolve_to_its_descriptor() {
    let mut world = rotation_world();
    let view = world.view();
    assert!(plan(&rotate_to(descriptor(&key_c(), 2)), &view, &rotation_me()).is_ok());
    let canonical = Refusal::TreasuryDestinationUnresolved(
        "destination must be the current canonical Treasury authority generation",
    );
    // Unregistered and registered foreign descriptors are BOTH outside this Treasury lineage.
    for foreign in [descriptor(&key_d(), 1), descriptor(&key_a(), 1)] {
        assert_eq!(
            plan(&rotate_to(foreign.clone()), &view, &rotation_me()).unwrap_err(),
            canonical
        );
        both_refuse(
            &world,
            "foreign destination",
            |wire| {
                let (key, g) = mutiny_crypto_v2::PublicKey::decode_descriptor(&foreign).unwrap();
                if let Action::TreasuryRotate {
                    new_address,
                    new_descriptor,
                    ..
                } = &mut wire.operation.action
                {
                    *new_address = key.address_id(g).unwrap();
                    *new_descriptor = foreign.clone();
                }
            },
            canonical.clone(),
            |e| *e == NativeError::Authority,
        );
    }
    let mut r1 = Rotation {
        network: world.anchor.network,
        genesis: world.anchor.genesis,
        fingerprint: world.anchor.fingerprint,
        authority: address(&key_a(), 1),
        current: descriptor(&key_a(), 1),
        proposed: descriptor(&key_d(), 2),
        created_height: 99,
        expiry_height: 120,
        authorization: kit::zero(),
        possession: kit::zero(),
    };
    r1.sign(&key_a(), &key_d()).unwrap();
    world
        .state
        .wallets
        .apply(&r1, world.anchor.genesis, world.anchor.fingerprint, 99)
        .unwrap();
    // Even a genuinely current descriptor of ANOTHER wallet is refused.
    assert_eq!(
        plan(
            &rotate_to(descriptor(&key_d(), 2)),
            &world.view(),
            &rotation_me()
        )
        .unwrap_err(),
        canonical
    );
    let transport = HybridKey::generate(Role::Transport).unwrap();
    for invalid in [transport.public().descriptor(1).unwrap(), vec![0xa1; 40]] {
        assert_eq!(
            plan(&rotate_to(invalid), &world.view(), &rotation_me()).unwrap_err(),
            Refusal::InvalidDescriptor
        );
    }
    both_refuse(
        &world,
        "address not the current descriptor's own",
        |wire| {
            if let Action::TreasuryRotate { new_address, .. } = &mut wire.operation.action {
                *new_address = T;
            }
        },
        Refusal::TreasuryDestinationUnresolved(treasury::REASON_NEW_ADDRESS_MISMATCH),
        |e| *e == NativeError::Record,
    );
}

#[test]
fn the_generation_must_be_the_active_one_and_the_new_one_exactly_one_more() {
    let world = rotation_world();
    for (what, edit, reason) in [
        (
            "generation skipped",
            Box::new(|wire: &mut NativeOperation| {
                set_rotation(wire, |action| {
                    if let Action::TreasuryRotate { new_generation, .. } = action {
                        *new_generation = 3;
                    }
                })
            }) as Box<dyn Fn(&mut NativeOperation)>,
            treasury::REASON_GENERATION_NOT_NEXT,
        ),
        (
            "generation repeated",
            Box::new(|wire: &mut NativeOperation| {
                set_rotation(wire, |action| {
                    if let Action::TreasuryRotate { new_generation, .. } = action {
                        *new_generation = 1;
                    }
                })
            }),
            treasury::REASON_GENERATION_NOT_NEXT,
        ),
        (
            "stale current generation",
            Box::new(|wire: &mut NativeOperation| {
                set_rotation(wire, |action| {
                    if let Action::TreasuryRotate {
                        current_generation,
                        new_generation,
                        ..
                    } = action
                    {
                        *current_generation = 2;
                        *new_generation = 3;
                    }
                })
            }),
            treasury::REASON_GENERATION_NOT_ACTIVE,
        ),
        (
            "another current address",
            Box::new(|wire: &mut NativeOperation| {
                set_rotation(wire, |action| {
                    if let Action::TreasuryRotate {
                        current_address, ..
                    } = action
                    {
                        *current_address = address(&key_a(), 1);
                    }
                })
            }),
            treasury::REASON_GENERATION_NOT_ACTIVE,
        ),
    ] {
        both_refuse(
            &world,
            what,
            edit,
            Refusal::TreasuryGeneration(reason),
            |e| *e == NativeError::Context,
        );
    }
}

#[test]
fn a_destination_address_is_never_used_twice() {
    // Before R1, the exact current B1 address is already routing generation1.
    let initial = world();
    assert_eq!(
        plan(
            &rotate_to(descriptor(&key_b(), 1)),
            &initial.view(),
            &treasury_me()
        )
        .unwrap_err(),
        Refusal::TreasuryAddressUsed
    );
    let mut busy = world();
    busy.reserved.insert(rotation_resource(&T, 1));
    assert_eq!(
        plan(
            &rotate_to(descriptor(&key_b(), 1)),
            &busy.view(),
            &treasury_me()
        )
        .unwrap_err(),
        Refusal::TreasuryAddressUsed
    );
    let current = rotation_world();
    let view = current.view();
    let planned = planned_rotation(&current);
    let signed = kit::signed_with(kit::wire(&planned.objects()[0].bytes), 0, &key_c(), 2);
    let after = trading_v1::prepare_batch(
        &current.state,
        view.anchor(),
        view.state_root(),
        &[signed],
        &trading_v1::CandidatePolicy::native_denomination_locked(),
    )
    .unwrap()
    .into_state();
    let mut routed = current.advanced();
    routed.state = after;
    routed.coin(address(&key_c(), 2), 400_000, 1, false, 0xc1, 0);
    // The SAME current2 address cannot serve a second routing generation.
    assert_eq!(
        plan(
            &rotate_to(descriptor(&key_c(), 2)),
            &routed.view(),
            &rotation_me()
        )
        .unwrap_err(),
        Refusal::TreasuryAddressUsed
    );
    let view = routed.view();
    let hand = kit::HandRotation {
        reference: view.anchor().clone(),
        treasury: T,
        current_generation: 2,
        current_address: address(&key_c(), 2),
        current_descriptor: descriptor(&key_c(), 2),
        new_generation: 3,
        new_address: address(&key_c(), 2),
        new_descriptor: descriptor(&key_c(), 2),
        inputs: vec![(point(0xc1), 400_000)],
        created: 102,
        expiry: 120,
    };
    let raw = kit::hand_rotation_in_view(&view, &hand, &key_c(), 2);
    assert_eq!(kit::consensus_in(&view, &raw), Err(NativeError::Record));
    nothing_queues(&raw, &view);
    // Returning to a retired B1 descriptor hits the stronger CURRENT authority requirement.
    assert_eq!(
        plan(&rotate_to(descriptor(&key_b(), 1)), &view, &rotation_me()).unwrap_err(),
        Refusal::TreasuryDestinationUnresolved(
            "destination must be the current canonical Treasury authority generation"
        )
    );
}

#[test]
fn the_descriptor_hash_and_the_approval_slot_must_be_exact() {
    let world = rotation_world();
    let view = world.view();
    // The body commits to another descriptor than the current one of the current address.
    both_refuse(
        &world,
        "descriptor hash mismatch",
        |wire| {
            set_rotation(wire, |action| {
                if let Action::TreasuryRotate {
                    current_descriptor, ..
                } = action
                {
                    *current_descriptor = trading_v1::descriptor_hash(&descriptor(&key_a(), 1));
                }
            })
        },
        Refusal::StaleAuthority,
        |e| *e == NativeError::Authority,
    );
    let planned = planned_rotation(&world);
    let raw = planned.objects()[0].bytes.clone();
    // An approval in slot 1 (a rotation has slot 0 only), alone or next to slot 0.
    for slots in [vec![1u8], vec![0, 1]] {
        let mut wire = kit::wire(&raw);
        for slot in slots {
            wire.operation.approve(slot, &key_c(), 2).unwrap();
        }
        let bytes = wire.encode().unwrap();
        assert!(matches!(
            explain(&bytes, &view, &rotation_me()).unwrap_err(),
            Refusal::CounterpartyApprovalInvalid | Refusal::FeeBelowMinimum { .. }
        ));
        assert!(SignedOperation::import(&bytes, &view).is_err());
        // One extra approval also outgrows the fee, which consensus checks first.
        assert!(matches!(
            kit::consensus_in(&view, &bytes),
            Err(NativeError::Authority | NativeError::Fee)
        ));
    }
    // Slot 0 signed by a key that does not control the current destination.
    let foreign = kit::signed_with(kit::wire(&raw), 0, &key_d(), 1);
    assert_eq!(
        explain(&foreign, &view, &rotation_me()).unwrap_err(),
        Refusal::CounterpartyApprovalInvalid
    );
    assert_eq!(
        kit::consensus_in(&view, &foreign),
        Err(NativeError::Authority)
    );
    nothing_queues(&foreign, &view);
    // One half of the hybrid signature tampered (BOTH_REQUIRED).
    for half in 0..2 {
        let mut wire = kit::wire(&kit::signed_with(kit::wire(&raw), 0, &key_c(), 2));
        if half == 0 {
            wire.operation.approvals[0].signature.ed448[3] ^= 1;
        } else {
            wire.operation.approvals[0].signature.fndsa[9] ^= 1;
        }
        let bytes = wire.encode().unwrap();
        assert_eq!(
            explain(&bytes, &view, &rotation_me()).unwrap_err(),
            Refusal::CounterpartyApprovalInvalid
        );
        assert_eq!(
            kit::consensus_in(&view, &bytes),
            Err(NativeError::Authority)
        );
        nothing_queues(&bytes, &view);
    }
    // No approval at all: consensus refuses the slot set; the wallet describes nothing signed.
    assert_eq!(kit::consensus_in(&view, &raw), Err(NativeError::Authority));
    assert!(matches!(
        SignedOperation::import(&raw, &view).unwrap_err(),
        Refusal::Malformed(_)
    ));
    // A maker offer proof attached to a rotation.
    let maker = kit::maker_key();
    let offer = kit::treasury_offer(
        &maker,
        kit::context_of(&world.anchor),
        100,
        140,
        10_000,
        1_000,
        3,
        1,
    );
    let mut wire = kit::wire(&raw);
    wire.operation.offer_proof = Some(OfferProof {
        offer,
        fill_signature: kit::zero(),
    });
    let unsigned = wire.encode().unwrap();
    assert!(matches!(
        explain(&unsigned, &view, &rotation_me()).unwrap_err(),
        Refusal::OfferProofInvalid | Refusal::FeeBelowMinimum { .. }
    ));
    let signed = kit::signed_with(wire, 0, &key_c(), 2);
    assert!(matches!(
        kit::consensus_in(&view, &signed),
        Err(NativeError::Fee | NativeError::Candidate(_))
    ));
}

#[test]
fn a_stale_authority_cannot_sign_the_rotation() {
    let mut world = rotation_world();
    let planned = planned_rotation(&world);
    let approval = kit::approve(&review(&planned, &world.view()).unwrap(), &world.view());
    // Explicit signed TEST state model: current2 changes to D3; not canonical finality evidence.
    let mut r1 = Rotation {
        network: world.anchor.network,
        genesis: world.anchor.genesis,
        fingerprint: world.anchor.fingerprint,
        authority: T,
        current: descriptor(&key_c(), 2),
        proposed: descriptor(&key_d(), 3),
        created_height: 99,
        expiry_height: 120,
        authorization: kit::zero(),
        possession: kit::zero(),
    };
    r1.sign(&key_c(), &key_d()).unwrap();
    world
        .state
        .wallets
        .apply(&r1, world.anchor.genesis, world.anchor.fingerprint, 99)
        .unwrap();
    let view = world.view();
    assert_eq!(
        review(&planned, &view).unwrap_err(),
        Refusal::StaleAuthority
    );
    let signer = KeySigner::with_identity(
        key_c(),
        rotation_me(),
        SigningGate::test_value().unwrap(),
        DEFAULT_IDLE_LIMIT,
    )
    .unwrap();
    assert!(signer.authorize(planned.clone(), approval, &view).is_err());
    assert_eq!(
        plan(&rotate_to(descriptor(&key_c(), 2)), &view, &rotation_me()).unwrap_err(),
        Refusal::StaleAuthority
    );
    let old = kit::signed_with(kit::wire(&planned.objects()[0].bytes), 0, &key_c(), 2);
    assert_eq!(kit::consensus_in(&view, &old), Err(NativeError::Authority));
    nothing_queues(&old, &view);
    let me = SignerIdentity::from_public(key_d().public(), 3, Some(T))
        .unwrap()
        .with_treasury_roles_for_test(TreasuryRoles {
            authority: true,
            destination_of: Some(T),
        });
    let fresh = plan(&rotate_to(descriptor(&key_d(), 3)), &view, &me).unwrap();
    let signed = kit::signed_with(kit::wire(&fresh.objects()[0].bytes), 0, &key_d(), 3);
    kit::consensus_in(&view, &signed).unwrap();
}

#[test]
fn context_window_fee_and_coins_are_refused_as_consensus_refuses_them() {
    let world = rotation_world();
    let raw = planned_rotation(&world).objects()[0].bytes.clone();
    let fee = kit::wire(&raw).operation.meta.fee.0;
    let change_by = |wire: &mut NativeOperation, delta: i64| {
        if let Action::TreasuryRotate { change, .. } = &mut wire.operation.action {
            change.0 = (change.0 as i64 + delta) as u64;
        }
    };
    both_refuse(
        &world,
        "another Genesis",
        |w| w.operation.meta.context.genesis[0] ^= 1,
        Refusal::WrongContext(ContextField::Genesis),
        |e| *e == NativeError::Context,
    );
    both_refuse(
        &world,
        "another fingerprint",
        |w| w.operation.meta.context.fingerprint[0] ^= 1,
        Refusal::WrongContext(ContextField::Fingerprint),
        |e| *e == NativeError::Context,
    );
    both_refuse(
        &world,
        "another network",
        |w| w.operation.meta.context.network ^= 1,
        Refusal::WrongContext(ContextField::Network),
        |e| *e == NativeError::Context,
    );
    both_refuse(
        &world,
        "created in the future",
        |w| w.operation.meta.envelope.first_height = 102,
        Refusal::WindowNotOpen {
            created: 102,
            next_height: 101,
        },
        |e| *e == NativeError::Envelope(mutiny_consensus_v8::op_envelope_v1::EnvelopeError::Future),
    );
    // Preserve exact signed bounds and supply an explicit known TEST parent anchor.
    let signed = kit::signed_with(kit::wire(&raw), 0, &key_c(), 2);
    let mut late = World::new(245);
    late.state = world.state.clone();
    let mut history = mutiny_consensus_v8::evidence_history_v2::History::default();
    history
        .insert_anchor(world.anchor.height, world.anchor.block)
        .unwrap();
    let expired = late.view().with_history(&history);
    for refusal in [
        explain(&signed, &expired, &rotation_me()).unwrap_err(),
        adopt(&raw, &expired, &rotation_me()).unwrap_err(),
    ] {
        assert_eq!(
            refusal,
            Refusal::WindowClosed {
                expiry: 245,
                next_height: 246
            }
        );
    }
    assert_eq!(
        trading_v1::prepare_batch_with_history(
            &late.state,
            expired.anchor(),
            expired.state_root(),
            &history,
            &[signed.clone()],
            &trading_v1::CandidatePolicy::native_denomination_locked()
        )
        .unwrap_err(),
        NativeError::Envelope(mutiny_consensus_v8::op_envelope_v1::EnvelopeError::Expired)
    );
    nothing_queues(&signed, &expired);
    // An over-wide native envelope cannot be encoded/signed in the canonical codec.
    let mut excessive = kit::wire(&raw);
    excessive.operation.meta.envelope.last_height = 20_000;
    assert!(excessive.encode().is_err());
    assert!(excessive.operation.approve(0, &key_c(), 2).is_err());
    both_refuse(
        &world,
        "fee one below the minimum",
        |w| {
            w.operation.meta.fee = Strikes(fee - 1);
            change_by(w, 1);
        },
        Refusal::FeeBelowMinimum {
            fee: fee - 1,
            minimum: fee,
        },
        |e| *e == NativeError::Fee,
    );
    both_refuse(
        &world,
        "conservation",
        |w| change_by(w, 1),
        Refusal::Conservation,
        |e| *e == NativeError::Conservation,
    );
    both_refuse(
        &world,
        "an input of another address",
        |w| {
            let other = point(0xa1);
            w.inputs = vec![other.clone()];
            w.operation.meta.inputs = vec![native_input_id(&other)];
            change_by(w, 900_000 - 5_000_000);
        },
        Refusal::InvalidRequest(treasury::REASON_NOT_PAYER_COIN),
        |e| *e == NativeError::Authority,
    );
    both_refuse(
        &world,
        "a coin that does not exist",
        |w| {
            let ghost = point(0xee);
            w.inputs = vec![ghost.clone()];
            w.operation.meta.inputs = vec![native_input_id(&ghost)];
        },
        Refusal::InputUnavailable,
        |e| *e == NativeError::Missing,
    );
    both_refuse(
        &world,
        "an unknown Treasury",
        |w| {
            set_rotation(w, |action| {
                if let Action::TreasuryRotate { treasury, .. } = action {
                    *treasury = [0x91; 32];
                }
            })
        },
        Refusal::StaleAuthority,
        |e| *e == NativeError::Authority,
    );
    // Planning refuses a validity window of zero or beyond the horizon.
    let view = world.view();
    for blocks in [0, 10_081] {
        assert_eq!(
            plan(
                &OperationRequest::TreasuryRotate(
                    TreasuryRotateRequest::new(Blob::new(descriptor(&key_c(), 2)))
                        .with_validity_blocks(blocks)
                ),
                &view,
                &rotation_me()
            )
            .unwrap_err(),
            Refusal::InvalidValidity
        );
    }
}

#[test]
fn immature_reserved_and_already_applied_rotations_are_refused() {
    // A coin whose creation height is not below the inclusion height (consensus `debit`: created
    // strictly before the block). A coin created AT the head is spendable in the next block.
    let mut young = World::new(100);
    young.state = rotation_world().state;
    young.state.coins.clear();
    young.coin(address(&key_b(), 1), 5_000_000, 101, false, 0xd3, 0);
    {
        let view = young.view();
        let hand = kit::HandRotation {
            reference: view.anchor().clone(),
            treasury: T,
            current_generation: 1,
            current_address: address(&key_b(), 1),
            current_descriptor: descriptor(&key_c(), 2),
            new_generation: 2,
            new_address: address(&key_c(), 2),
            new_descriptor: descriptor(&key_c(), 2),
            inputs: vec![(point(0xd3), 5_000_000)],
            created: 101,
            expiry: 120,
        };
        let raw = kit::hand_rotation_in_view(&view, &hand, &key_c(), 2);
        // Such a coin is not even a candidate for the planner, and the hand-built operation is
        // refused by both.
        assert_eq!(
            plan(&rotate_to(descriptor(&key_c(), 2)), &view, &rotation_me()).unwrap_err(),
            Refusal::NothingSpendable
        );
        let mut unsigned = kit::wire(&raw);
        unsigned.operation.approvals.clear();
        assert_eq!(
            explain(&unsigned.encode().unwrap(), &view, &rotation_me()).unwrap_err(),
            Refusal::ImmatureInput
        );
        assert_eq!(kit::consensus_in(&view, &raw), Err(NativeError::Immature));
    }
    // An immature coinbase coin.
    let mut coinbase = World::new(100);
    coinbase.state = rotation_world().state;
    coinbase.state.coins.clear();
    coinbase.coin(address(&key_b(), 1), 5_000_000, 50, true, 0xd4, 0);
    {
        let view = coinbase.view();
        assert_eq!(
            plan(&rotate_to(descriptor(&key_c(), 2)), &view, &rotation_me()).unwrap_err(),
            Refusal::NothingSpendable
        );
        let hand = kit::HandRotation {
            reference: view.anchor().clone(),
            treasury: T,
            current_generation: 1,
            current_address: address(&key_b(), 1),
            current_descriptor: descriptor(&key_c(), 2),
            new_generation: 2,
            new_address: address(&key_c(), 2),
            new_descriptor: descriptor(&key_c(), 2),
            inputs: vec![(point(0xd4), 5_000_000)],
            created: 101,
            expiry: 120,
        };
        let raw = kit::hand_rotation_in_view(&view, &hand, &key_c(), 2);
        assert_eq!(kit::consensus_in(&view, &raw), Err(NativeError::Immature));
        let mut unsigned = kit::wire(&raw);
        unsigned.operation.approvals.clear();
        assert_eq!(
            explain(&unsigned.encode().unwrap(), &view, &rotation_me()).unwrap_err(),
            Refusal::ImmatureInput
        );
    }
    // Reserved: a coin or the Treasury generation already committed to another pending operation.
    let world = rotation_world();
    let planned = planned_rotation(&world);
    assert!(planned.inputs().contains(&point(0xd1)));
    for reserved_point in [point(0xd1), rotation_resource(&T, 1)] {
        let mut busy = World::new(100);
        busy.state = world.state.clone();
        busy.reserved = BTreeSet::from([reserved_point.clone()]);
        let refusal = review(&planned, &busy.view()).unwrap_err();
        assert_eq!(refusal, Refusal::ReservedInput, "{reserved_point:?}");
    }
    let mut busy = World::new(100);
    busy.state = world.state.clone();
    busy.reserved = BTreeSet::from([rotation_resource(&T, 1)]);
    assert_eq!(
        plan(
            &rotate_to(descriptor(&key_c(), 2)),
            &busy.view(),
            &rotation_me()
        )
        .unwrap_err(),
        Refusal::ReservedInput
    );
    // Already applied: the receipt of the same operation is in state.
    let signed = kit::signed_with(kit::wire(&planned.objects()[0].bytes), 0, &key_c(), 2);
    let id = kit::wire(&signed).operation.id().unwrap();
    let mut applied = World::new(100);
    applied.state = world.state.clone();
    applied.state.protocol_records.insert(
        record_key(2, id),
        NativeRecord::Applied {
            wire_hash: [7; 32],
            height: 99,
            fee_atoms: 1,
        }
        .encode(id)
        .unwrap(),
    );
    assert_eq!(
        review(&planned, &applied.view()).unwrap_err(),
        Refusal::Replay
    );
    assert_eq!(
        kit::consensus_in(&applied.view(), &signed),
        Err(NativeError::Duplicate)
    );
}

#[test]
fn a_generation_that_has_not_taken_effect_cannot_be_rotated_yet() {
    // A head record whose generation takes effect only at block 150.
    let mut world = World::new(100);
    world.state = rotation_world_at(100, Some(Class::TestValue)).state;
    let context = kit::context_of(&world.anchor);
    let destination = TreasuryDestination {
        generation: 1,
        address: address(&key_b(), 1),
        descriptor: descriptor(&key_b(), 1),
        effective_height: 150,
    };
    let generation_id = treasury_generation_id(T, 1);
    world.state.protocol_records.insert(
        record_key(5, generation_id),
        NativeRecord::TreasuryGeneration {
            context: context.clone(),
            treasury: T,
            destination: destination.clone(),
        }
        .encode(generation_id)
        .unwrap(),
    );
    world.state.protocol_records.insert(
        record_key(3, T),
        NativeRecord::Treasury {
            context: context.clone(),
            current: destination,
        }
        .encode(T)
        .unwrap(),
    );
    let address_id = treasury_address_id(T, address(&key_b(), 1));
    assert!(
        world
            .state
            .protocol_records
            .contains_key(&record_key(6, address_id))
    );
    let view = world.view();
    assert_eq!(
        plan(&rotate_to(descriptor(&key_c(), 2)), &view, &rotation_me()).unwrap_err(),
        Refusal::NotYetEligible {
            what: "Rotating this Treasury destination",
            height: 151,
        }
    );
    let hand = kit::HandRotation {
        reference: view.anchor().clone(),
        treasury: T,
        current_generation: 1,
        current_address: address(&key_b(), 1),
        current_descriptor: descriptor(&key_c(), 2),
        new_generation: 2,
        new_address: address(&key_c(), 2),
        new_descriptor: descriptor(&key_c(), 2),
        inputs: vec![(point(0xd1), 5_000_000)],
        created: 101,
        expiry: 120,
    };
    let raw = kit::hand_rotation_in_view(&view, &hand, &key_c(), 2);
    assert_eq!(kit::consensus_in(&view, &raw), Err(NativeError::Time));
    let mut unsigned = kit::wire(&raw);
    unsigned.operation.approvals.clear();
    assert!(matches!(
        explain(&unsigned.encode().unwrap(), &view, &rotation_me()).unwrap_err(),
        Refusal::NotYetEligible { .. }
    ));
}

// Public TEST fixture: exact current Treasury facts, signed-size fee and genuine signatures.
// The legacy empty-facts hand builder remains unchanged for explicit malformed-envelope probes.
fn hand_rotation_in_view(
    view: &ChainView<'_>,
    hand: &kit::HandRotation,
    key: &HybridKey,
    generation: u64,
) -> Vec<u8> {
    let context = kit::context_of(view.anchor());
    let facts = mutiny_consensus_v8::op_envelope_v1::treasury_head_facts(
        view.state(),
        &context,
        hand.treasury,
    )
    .unwrap();
    let mut fee = 240;
    for _ in 0..8 {
        let mut wire = kit::hand_operation(context.clone(), hand, fee);
        wire.operation.meta.envelope.preconditions = vec![facts.clone()];
        let raw = kit::signed_with(wire, 0, key, generation);
        let required = (raw.len() as u64).max(240);
        if fee >= required {
            return raw;
        }
        fee = required;
    }
    panic!("signed fixture fee failed to converge");
}

#[test]
fn fee_coins_below_the_dividend_reserve_are_refused_by_the_wallet_and_by_block_execution() {
    use mutiny_wallet_core_v8::ops::rotation::{self, RotationSigner, combine};
    use treasury_rig::chain::*;
    let treasury = treasury_wallet_key();
    let a1 = address_of(&treasury, 1);
    let funder = wallet_key();
    let a = address_of(&funder, 1);
    let successor = labelled_key("w6-refusal-reserve-current2");
    let a2 = address_of(&successor, 2);
    let named = descriptor_of(&successor, 2);
    let mut chain = TreasuryChain::new(
        "w6-refusal-current2-reserve",
        1_200_000,
        Some((T, descriptor_of(&treasury, 1))),
        &[(0xa1, a, 3_000_000)],
    );
    let none = BTreeSet::new();
    chain.step_at(AWARD_EPOCH);
    let paid_tx = chain.hand_signed_transfer(
        &treasury,
        1,
        point(0xd1),
        12_000,
        &[(address_of(&other_key(), 1), 588_000), (a1, 600_000)],
    );
    chain.admit(&paid_tx).unwrap();
    let paid = chain.step();
    assert_eq!(paid.dividends.reserved(), 600_000);
    let coin = paid
        .coins
        .iter()
        .find(|(_, c)| c.output.owner == a1)
        .map(|(p, c)| (p.clone(), c.output.atoms))
        .unwrap();
    assert_eq!(coin.1, 600_000);

    // Certified, sponsored tag25 R1 establishes current2 without debiting the reserve coin.
    let view = chain.view(&none);
    let me = kit::declared(&treasury, 1, None, &view, true, Some(T));
    let payer = identity_of(&funder);
    let req = OperationRequest::WalletRotation(
        RotationRequest::new(
            Blob::new(named.clone()),
            FeeSource::OtherWallet(payer.clone()),
        )
        .with_restore_verified(rotation::descriptor_fingerprint(&named)),
    );
    let planned = plan(&req, &view, &me).unwrap();
    let reviewed = review(&planned, &view).unwrap();
    let part = RotationSigner::for_test(
        treasury_wallet_key(),
        me.clone(),
        labelled_key("w6-refusal-reserve-current2"),
    )
    .unwrap()
    .authorize(planned, kit::approve(&reviewed, &view), &view)
    .unwrap();
    assert!(!part.is_complete());
    let adopted = adopt(part.bytes(), &view, &payer).unwrap();
    let reviewed = review(&adopted, &view).unwrap();
    let sponsor = KeySigner::for_test(wallet_key())
        .unwrap()
        .authorize(adopted, kit::approve(&reviewed, &view), &view)
        .unwrap();
    let complete = combine(&[part.bytes(), sponsor.bytes()], &view).unwrap();
    let mut rotation_outbox = MemoryOutbox::new();
    rotation_outbox.commit(&part, &view).unwrap();
    rotation_outbox
        .replace_partial(&part.id(), &complete, &view)
        .unwrap();
    let mut pool = chain.submission_pool();
    let r1id = chain
        .admit_submission(&mut pool, 0, complete.bytes())
        .unwrap();
    chain.step_submissions(&mut pool);
    assert_eq!(chain.verified_operations(r1id).len(), 1);
    assert_eq!(chain.state().wallets.current(a1).unwrap(), named);
    assert_eq!(chain.state().coins[&coin.0].output.atoms, 600_000);
    let confirmations = chain.confirmations();
    assert_eq!(
        rotation_outbox
            .reconcile(&chain.view(&none).with_confirmations(&confirmations))
            .unwrap()
            .confirmed,
        1
    );
    drop(pool);

    let view = chain.view(&none);
    let me_now = kit::declared(&successor, 2, Some(a1), &view, true, Some(T));
    let req = OperationRequest::TreasuryRotate(
        TreasuryRotateRequest::new(Blob::new(named.clone()))
            .with_verified_restore(T, rotation::descriptor_fingerprint(&named)),
    );
    assert!(matches!(
        plan(&req, &view, &me_now),
        Err(Refusal::ReserveBackingViolation {
            reserved: 600_000,
            ..
        })
    ));
    let next = view.next_height().unwrap();
    let hand = kit::HandRotation {
        reference: view.anchor().clone(),
        treasury: T,
        current_generation: 1,
        current_address: a1,
        current_descriptor: named.clone(),
        new_generation: 2,
        new_address: a2,
        new_descriptor: named,
        inputs: vec![coin.clone()],
        created: next,
        expiry: next + 10,
    };
    let raw = hand_rotation_in_view(&view, &hand, &successor, 2);
    assert_eq!(kit::consensus_in(&view, &raw), Err(NativeError::Record));
    let mut unsigned = kit::wire(&raw);
    unsigned.operation.approvals.clear();
    assert!(matches!(
        explain(&unsigned.encode().unwrap(), &view, &me_now),
        Err(Refusal::ReserveBackingViolation {
            reserved: 600_000,
            ..
        })
    ));
    let mut outbox = MemoryOutbox::new();
    assert!(outbox.commit(&as_signed(&raw), &view).is_err());
    assert!(outbox.records().unwrap().is_empty());
    let root = view.state_root();
    let anchor = view.anchor().clone();
    let rows = chain.canonical_rows();
    assert!(chain.try_step_with(&[raw.clone()]).is_err());
    assert_eq!(chain.state().root().unwrap(), root);
    assert_eq!(chain.anchor(), anchor);
    assert_eq!(chain.canonical_rows(), rows);
    std::fs::write(
        chain
            .evidence_directory()
            .join("reserve-refused-current2-r2.bin"),
        &raw,
    )
    .unwrap();

    // A real payment adds backing. The old exact body now passes; reserve was the causal gate.
    let source = chain
        .state()
        .coins
        .iter()
        .filter(|(_, c)| c.output.owner == a && !c.coinbase)
        .max_by_key(|(_, c)| c.output.atoms)
        .map(|(p, c)| (p.clone(), c.output.atoms))
        .unwrap();
    let topup = chain.hand_signed_transfer(
        &funder,
        1,
        source.0,
        10_000,
        &[(a2, 50_000), (a, source.1 - 60_000)],
    );
    chain.admit(&topup).unwrap();
    let topped = chain.step();
    assert_eq!(
        mutiny_consensus_v8::dividend_state_v1::DividendState::backing(
            &topped.coins,
            &topped.treasury_owner_set()
        )
        .unwrap(),
        650_000
    );
    assert_eq!(topped.coins[&coin.0].output.atoms, 600_000);
    let history = chain.operation_history(&raw);
    trading_v1::prepare_batch_with_history(
        &topped,
        &chain.anchor(),
        topped.root().unwrap(),
        &history,
        &[raw.clone()],
        &trading_v1::CandidatePolicy::native_denomination_locked(),
    )
    .unwrap();
    let view = chain.view(&none).with_history(&history);
    let signed = as_signed(&raw);
    outbox.commit(&signed, &view).unwrap();
    let mut pool = chain.submission_pool();
    let id = chain.admit_submission(&mut pool, 1, &raw).unwrap();
    let after = chain.step_submissions(&mut pool);
    let fee = kit::wire(&raw).operation.meta.fee.0;
    assert_eq!(
        mutiny_consensus_v8::dividend_state_v1::DividendState::backing(
            &after.coins,
            &after.treasury_owner_set()
        )
        .unwrap(),
        650_000 - fee
    );
    let active =
        trading_v1::treasury_current(&after, &kit::context_of(&chain.anchor()), T).unwrap();
    assert_eq!((active.generation, active.address), (2, a2));
    let record = chain.verified_operations(id);
    assert_eq!(record.len(), 1);
    assert_eq!(
        record[0].wire,
        mutiny_consensus_v8::submission_v1::Submission::decode(1, &raw)
            .unwrap()
            .wire
    );
    let confirmations = chain.confirmations();
    assert_eq!(
        outbox
            .reconcile(&chain.view(&none).with_confirmations(&confirmations))
            .unwrap()
            .confirmed,
        1
    );
    let chain = chain.restart();
    assert_eq!(chain.verified_operations(id), record);
    println!(
        "PUBLIC TEST-VALUE reserve evidence retained: {}",
        chain.evidence_directory().display()
    );
}

// ---------------------------------------------------------------------------------------------
// Freeze refusals
// ---------------------------------------------------------------------------------------------

fn point(tag: u8) -> OutPoint {
    OutPoint {
        transaction: [tag; 32],
        index: 0,
    }
}

fn freeze_request(proposal: Vec<u8>) -> OperationRequest {
    OperationRequest::TreasuryFreezeOffer(TreasuryFreezeOfferRequest::new(Blob::new(proposal)))
}

/// What a test freeze varies.
struct FreezeOptions {
    generation: u64,
    address: Option<Hash>,
    trade: Hash,
    contract: Hash,
    wallet: Option<Vec<u8>>,
    offer_created: Option<u64>,
    offer_expiry: Option<u64>,
    maker_side: u8,
    network: u8,
    satoshis: u64,
    amount: u64,
}

impl Default for FreezeOptions {
    fn default() -> Self {
        Self {
            generation: 1,
            address: None,
            trade: [0x21; 32],
            contract: [0x22; 32],
            wallet: None,
            offer_created: None,
            offer_expiry: None,
            maker_side: 1,
            network: 3,
            satoshis: 5_000,
            amount: 100_000,
        }
    }
}

struct Freeze {
    body: Vec<u8>,
    offer: SignedOffer,
    terms: FreezeTerms,
}

/// A freeze at the world's head, encoded by the TEST (so consensus need not accept its terms), and
/// the maker's signed offer.
fn freeze_at(world: &World, options: &FreezeOptions) -> Freeze {
    let current = world.state.wallets.current(T).unwrap();
    let (_, generation) = mutiny_crypto_v2::PublicKey::decode_descriptor(current).unwrap();
    let maker = if generation == 1 {
        key_b()
    } else {
        assert_eq!(current, descriptor(&key_c(), 2));
        key_c()
    };
    let head = world.anchor.height;
    let mut body = mutiny_consensus_v8::trading_v1::OfferBody {
        context: kit::context_of(&world.anchor),
        maker_descriptor: maker.public().descriptor(generation).unwrap(),
        maker_wallet: T,
        destination: T,
        condition: None,
        max_fee: Strikes(100_000),
        nonce: [0x51; 32],
        created: options.offer_created.unwrap_or(head),
        expiry: options.offer_expiry.unwrap_or(head + 40),
        maker_side: options.maker_side,
        terms: mutiny_consensus_v8::trading_v1::OfferTerms::HashLinked {
            amount: Strikes(options.amount),
            bitcoin_satoshis: options.satoshis,
            bitcoin_network: options.network,
        },
    };
    if body.created > body.expiry {
        body.expiry = body.created;
    }
    let offer = SignedOffer::sign(body, &maker).unwrap();
    let terms = FreezeTerms {
        treasury: T,
        generation: options.generation,
        address: options.address.unwrap_or(address(&key_b(), 1)),
        trade: options.trade,
        contract: options.contract,
        wallet_descriptor: options.wallet.clone().unwrap_or_else(|| current.to_vec()),
    };
    let view = world.view();
    let body = kit::freeze_body(
        &kit::context_of(&world.anchor),
        view.anchor(),
        view.state_root(),
        &terms,
        &offer.body,
    );
    Freeze { body, offer, terms }
}

fn freeze_proposal_at(world: &World, options: &FreezeOptions) -> Vec<u8> {
    let freeze = freeze_at(world, options);
    freeze_proposal(&freeze.body, &kit::offer_import(&freeze.offer)).unwrap()
}

/// The wallet refuses the freeze with `wallet` (plan and adopt), and consensus refuses to prepare
/// it as `consensus` says.
fn freeze_refused(
    world: &World,
    what: &str,
    options: FreezeOptions,
    wallet: Refusal,
    consensus: impl Fn(&NativeError) -> bool,
) {
    let view = world.view();
    let freeze = freeze_at(world, &options);
    let proposal = freeze_proposal(&freeze.body, &kit::offer_import(&freeze.offer)).unwrap();
    assert_eq!(
        plan(&freeze_request(proposal.clone()), &view, &treasury_me()).unwrap_err(),
        wallet,
        "{what}: plan"
    );
    assert_eq!(
        adopt(&proposal, &view, &treasury_me()).unwrap_err(),
        wallet,
        "{what}: adopt"
    );
    assert_eq!(
        explain(&proposal, &view, &treasury_me()).unwrap_err(),
        wallet,
        "{what}: explain"
    );
    let verdict = kit::prepare_freeze(&view, &freeze.terms, &freeze.offer).unwrap_err();
    assert!(consensus(&verdict), "{what}: consensus said {verdict:?}");
    // Even signed by the right key, the bytes are refused by the wallet and do not verify at
    // creation in consensus.
    let frozen = kit::frozen_by_hand(&freeze.body, &key_b());
    assert!(SignedOperation::import(&frozen, &view).is_err(), "{what}");
    if let Ok(decoded) = FrozenTreasuryOffer::decode(&frozen) {
        assert!(
            trading_v1::verify_frozen_treasury_offer_at_creation(
                decoded,
                view.state(),
                view.anchor(),
                view.state_root(),
                &trading_v1::CandidatePolicy::native_denomination_locked()
            )
            .is_err(),
            "{what}"
        );
    }
}

#[test]
fn the_kit_body_equals_the_consensus_payload_and_a_valid_freeze_is_accepted() {
    let world = world();
    let view = world.view();
    let freeze = freeze_at(&world, &FreezeOptions::default());
    assert_eq!(
        kit::prepare_freeze(&view, &freeze.terms, &freeze.offer).unwrap(),
        freeze.body,
        "the test's body encoder is the consensus encoding"
    );
    let proposal = freeze_proposal(&freeze.body, &kit::offer_import(&freeze.offer)).unwrap();
    let planned = plan(&freeze_request(proposal), &view, &treasury_me()).unwrap();
    assert_eq!(planned.objects()[0].bytes, freeze.body);
}

#[test]
fn bitcoin_network_codes_outside_one_to_three_are_refused() {
    let world = world();
    freeze_refused(
        &world,
        "mainnet",
        FreezeOptions {
            network: 0,
            ..FreezeOptions::default()
        },
        Refusal::TreasuryOfferTerms(treasury::REASON_BITCOIN_MAINNET),
        |e| *e == NativeError::Bounds,
    );
    // Codes above 3 are not even encodable: no maker can sign such an offer, and offer bytes
    // carrying one are refused by the wallet and by consensus decoding.
    let maker = kit::maker_key();
    let mut body = freeze_at(&world, &FreezeOptions::default()).offer.body;
    if let mutiny_consensus_v8::trading_v1::OfferTerms::HashLinked {
        bitcoin_network, ..
    } = &mut body.terms
    {
        *bitcoin_network = 4;
    }
    assert!(SignedOffer::sign(body, &maker).is_err());
    let valid = freeze_at(&world, &FreezeOptions::default());
    let import = kit::offer_import(&valid.offer);
    // Walk the canonical 13-field body and the four-field HashLinked terms.
    let encoded_terms = valid.offer.body.encode().unwrap();
    let mut d = minicbor::Decoder::new(&encoded_terms);
    assert_eq!(d.array().unwrap(), Some(13));
    for _ in 0..9 {
        d.skip().unwrap();
    }
    assert_eq!(d.array().unwrap(), Some(4));
    for _ in 0..3 {
        d.skip().unwrap();
    }
    let network_at = d.position();
    assert_eq!(d.u8().unwrap(), 3);
    let mut patched_body = encoded_terms.clone();
    patched_body[network_at] = 4;
    let mut patched_import = import.clone();
    let at = patched_import
        .windows(encoded_terms.len())
        .position(|window| window == encoded_terms.as_slice())
        .unwrap();
    patched_import[at..at + encoded_terms.len()].copy_from_slice(&patched_body);
    assert!(SignedOffer::decode(&patched_import).is_err());
    // Bytes in neither accepted offer form: MALFORMED on every path since W19 (before:
    // OFFER_PROOF_INVALID here).
    assert_eq!(
        freeze_proposal(&valid.body, &patched_import)
            .unwrap_err()
            .code(),
        "MALFORMED"
    );
}

#[test]
fn freeze_terms_window_side_commitments_and_generation_are_checked() {
    let world = world();
    let head = world.anchor.height;
    freeze_refused(
        &world,
        "offer opened before the creation head",
        FreezeOptions {
            offer_created: Some(head - 1),
            ..FreezeOptions::default()
        },
        Refusal::TreasuryOfferTerms(treasury::REASON_FREEZE_OFFER_WINDOW),
        |e| *e == NativeError::Time,
    );
    freeze_refused(
        &world,
        "offer closing at the creation head",
        FreezeOptions {
            offer_expiry: Some(head),
            ..FreezeOptions::default()
        },
        Refusal::TreasuryOfferTerms(treasury::REASON_FREEZE_OFFER_WINDOW),
        |e| *e == NativeError::Time,
    );
    freeze_refused(
        &world,
        "offer open beyond the horizon",
        FreezeOptions {
            offer_expiry: Some(head + 10_081),
            ..FreezeOptions::default()
        },
        Refusal::TreasuryOfferTerms(treasury::REASON_FREEZE_OFFER_WINDOW),
        |e| *e == NativeError::Time,
    );
    freeze_refused(
        &world,
        "maker on the sender side",
        FreezeOptions {
            maker_side: 0,
            ..FreezeOptions::default()
        },
        Refusal::TreasuryOfferTerms(treasury::REASON_FREEZE_OFFER_WINDOW),
        |e| *e == NativeError::Time,
    );
    freeze_refused(
        &world,
        "zero TradeID",
        FreezeOptions {
            trade: [0; 32],
            ..FreezeOptions::default()
        },
        Refusal::TreasuryOfferTerms(treasury::REASON_FREEZE_COMMITMENTS),
        |e| *e == NativeError::Context,
    );
    freeze_refused(
        &world,
        "zero ContractHash",
        FreezeOptions {
            contract: [0; 32],
            ..FreezeOptions::default()
        },
        Refusal::TreasuryOfferTerms(treasury::REASON_FREEZE_COMMITMENTS),
        |e| *e == NativeError::Context,
    );
    freeze_refused(
        &world,
        "a generation that does not exist",
        FreezeOptions {
            generation: 2,
            ..FreezeOptions::default()
        },
        Refusal::TreasuryGeneration(treasury::REASON_FREEZE_GENERATION),
        |e| *e == NativeError::Conflict,
    );
    freeze_refused(
        &world,
        "another address for the generation",
        FreezeOptions {
            address: Some(address(&key_a(), 1)),
            ..FreezeOptions::default()
        },
        Refusal::TreasuryGeneration(treasury::REASON_FREEZE_GENERATION),
        |e| *e == NativeError::Conflict,
    );
    // A wallet descriptor that does not control the destination: the Treasury wallet must sign.
    let view = world.view();
    let freeze = freeze_at(
        &world,
        &FreezeOptions {
            wallet: Some(descriptor(&key_a(), 1)),
            ..FreezeOptions::default()
        },
    );
    assert_eq!(
        kit::prepare_freeze(&view, &freeze.terms, &freeze.offer).unwrap_err(),
        NativeError::Authority
    );
    let proposal = freeze_proposal(&freeze.body, &kit::offer_import(&freeze.offer)).unwrap();
    let a_me = identity(&key_a()).with_treasury_roles_for_test(TreasuryRoles {
        authority: true,
        destination_of: Some(T),
    });
    assert_eq!(
        plan(&freeze_request(proposal.clone()), &view, &a_me).unwrap_err(),
        Refusal::NotRequiredSigner(Slot::TreasuryFreeze)
    );
    assert_eq!(
        plan(&freeze_request(proposal), &view, &treasury_me()).unwrap_err(),
        Refusal::NotRequiredSigner(Slot::TreasuryFreeze)
    );
}

#[test]
fn a_freeze_is_signed_only_at_its_creation_head_and_with_the_maker_offer_it_names() {
    let world = world();
    let freeze = freeze_at(&world, &FreezeOptions::default());
    let proposal = freeze_proposal(&freeze.body, &kit::offer_import(&freeze.offer)).unwrap();
    // The chain moved: the body binds the old head and root.
    let moved = world.advanced();
    assert_eq!(
        plan(
            &freeze_request(proposal.clone()),
            &moved.view(),
            &treasury_me()
        )
        .unwrap_err(),
        Refusal::StaleHead {
            reviewed: 100,
            current: 101
        }
    );
    let frozen = kit::frozen_by_hand(&freeze.body, &key_b());
    assert!(
        trading_v1::verify_frozen_treasury_offer_at_creation(
            FrozenTreasuryOffer::decode(&frozen).unwrap(),
            moved.view().state(),
            moved.view().anchor(),
            moved.view().state_root(),
            &trading_v1::CandidatePolicy::native_denomination_locked()
        )
        .is_err(),
        "consensus verifies a freeze against its own creation head only"
    );
    // Another chain.
    let mut foreign = World::new(100);
    foreign.state = world.state.clone();
    foreign.anchor.genesis = [0x61; 32];
    assert!(matches!(
        plan(
            &freeze_request(proposal.clone()),
            &foreign.view(),
            &treasury_me()
        )
        .unwrap_err(),
        Refusal::WrongContext(_)
    ));
    // A maker offer that is not the one the body names, or whose signature does not verify.
    let view = world.view();
    let mut other = freeze_at(&world, &FreezeOptions::default());
    other.offer.body.nonce[0] ^= 1;
    other.offer = SignedOffer::sign(other.offer.body, &key_b()).unwrap();
    let mismatched = freeze_proposal(&freeze.body, &kit::offer_import(&other.offer)).unwrap();
    assert_eq!(
        plan(&freeze_request(mismatched), &view, &treasury_me()).unwrap_err(),
        Refusal::OfferProofInvalid
    );
    let mut forged = freeze.offer.clone();
    forged.signature.ed448[5] ^= 1;
    assert_eq!(
        freeze_proposal(&freeze.body, &kit::offer_import(&forged)).unwrap_err(),
        Refusal::Malformed("not a canonical maker offer"),
        "the strict current MakerOffer import rejects a corrupted signature before a proposal exists"
    );
    assert!(matches!(
        kit::prepare_freeze(&view, &freeze.terms, &forged),
        Err(NativeError::Candidate(_))
    ));
    // A fill signature present is not the import form: MALFORMED since W19 (before:
    // OFFER_PROOF_INVALID).
    let mut filled = OfferProof {
        offer: freeze.offer.clone(),
        fill_signature: kit::zero(),
    };
    filled.fill_signature.ed448[0] = 1;
    assert_eq!(
        freeze_proposal(&freeze.body, &filled.encode().unwrap())
            .unwrap_err()
            .code(),
        "MALFORMED"
    );
    // A bare body is not adopted (the maker offer must accompany it); signed bytes have nothing
    // left to sign.
    assert_eq!(
        adopt(&freeze.body, &view, &treasury_me()).unwrap_err(),
        Refusal::OfferProofInvalid
    );
    assert!(matches!(
        adopt(&frozen, &view, &treasury_me()).unwrap_err(),
        Refusal::Malformed(_)
    ));
}

#[test]
fn a_freeze_authorization_cannot_be_moved_to_another_offer_or_body() {
    let world = world();
    let view = world.view();
    let first = freeze_at(&world, &FreezeOptions::default());
    let second = freeze_at(
        &world,
        &FreezeOptions {
            amount: 70_000,
            ..FreezeOptions::default()
        },
    );
    let mut outbox = MemoryOutbox::new();
    // The signature over the first body, attached to the second body.
    let signed_first = kit::frozen_by_hand(&first.body, &key_b());
    let signature_part = &signed_first[signed_first.len() - (114 + 1280 + 2 + 3)..];
    let mut transplanted = Vec::new();
    let mut e = minicbor::Encoder::new(&mut transplanted);
    e.array(3).unwrap().bytes(&second.body).unwrap();
    transplanted.extend_from_slice(signature_part);
    assert!(FrozenTreasuryOffer::decode(&transplanted).is_err());
    assert!(SignedOperation::import(&transplanted, &view).is_err());
    assert!(matches!(
        explain(&transplanted, &view, &treasury_me()).unwrap_err(),
        Refusal::VerificationFailed(_) | Refusal::Malformed(_)
    ));
    // The same transplant as a SignedOperation the outbox would queue.
    let forged = SignedOperation::Complete {
        kind: OperationKind::TreasuryFreezeOffer,
        id: mutiny_consensus_v8::domain_hash(treasury::FREEZE_ID_DOMAIN, &second.body),
        bytes: transplanted,
        validity: Validity {
            created: 101,
            expiry: 140,
            valid_only_at: None,
            bound_to_parent: false,
        },
        reserved: vec![treasury::freeze_resource(&second.offer.body.id().unwrap())],
    };
    assert!(outbox.commit(&forged, &view).is_err());
    assert!(outbox.records().unwrap().is_empty());
    // A signature by another wallet over the right body.
    let by_a = kit::frozen_by_hand(&first.body, &key_a());
    assert!(FrozenTreasuryOffer::decode(&by_a).is_err());
    assert!(SignedOperation::import(&by_a, &view).is_err());
    // The genuine signature imports and verifies.
    assert!(SignedOperation::import(&signed_first, &view).is_ok());
}

#[test]
fn a_second_freeze_of_one_offer_waits_for_the_first() {
    let world = world();
    let view = world.view();
    let freeze = freeze_at(&world, &FreezeOptions::default());
    let proposal = freeze_proposal(&freeze.body, &kit::offer_import(&freeze.offer)).unwrap();
    let planned = plan(&freeze_request(proposal.clone()), &view, &treasury_me()).unwrap();
    let reviewed = review(&planned, &view).unwrap();
    let signed = KeySigner::with_identity(
        key_b(),
        treasury_me(),
        SigningGate::test_value().unwrap(),
        DEFAULT_IDLE_LIMIT,
    )
    .unwrap()
    .authorize(planned, kit::approve(&reviewed, &view), &view)
    .unwrap();
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&signed, &view).unwrap();
    let reserved = outbox.reserved().unwrap();
    assert_eq!(
        reserved,
        BTreeSet::from([treasury::freeze_resource(&freeze.offer.body.id().unwrap())])
    );
    let mut busy = World::new(100);
    busy.state = world.state.clone();
    busy.reserved = reserved;
    assert_eq!(
        plan(&freeze_request(proposal), &busy.view(), &treasury_me()).unwrap_err(),
        Refusal::ReservedInput
    );
}

#[test]
fn the_profile_is_required_even_where_no_genesis_treasury_guard_applies() {
    const T2: Hash = [0x92; 32];
    let world = world();
    let view = world.view();
    let ordinary = identity(&key_b());
    let false_role = identity(&key_b()).with_treasury_roles_for_test(TreasuryRoles {
        authority: false,
        destination_of: Some(T2),
    });
    // No foreign Treasury is inserted into canonical state merely to make a positive.
    assert_eq!(
        profile::declare(
            ordinary.clone(),
            &TreasuryDeclaration::new(view.anchor().genesis, ChainClass::TestValue)
                .with_destination_of(T2),
            &view
        )
        .unwrap_err(),
        Refusal::InvalidRequest(treasury::REASON_NO_TRADING_TREASURY)
    );
    let proposal = freeze_proposal_at(&world, &FreezeOptions::default());
    assert_eq!(
        plan(&freeze_request(proposal.clone()), &view, &ordinary).unwrap_err(),
        Refusal::TreasuryProfileRequired
    );
    assert_eq!(
        adopt(&proposal, &view, &ordinary).unwrap_err(),
        Refusal::TreasuryProfileRequired
    );
    assert_eq!(
        plan(&freeze_request(proposal.clone()), &view, &false_role).unwrap_err(),
        Refusal::TreasuryRoleNotDeclared(TreasuryRole::Destination)
    );
    assert!(plan(&freeze_request(proposal), &view, &treasury_me()).is_ok());
    let current = rotation_world();
    let view = current.view();
    let request = OperationRequest::TreasuryRotate(
        TreasuryRotateRequest::new(Blob::new(descriptor(&key_c(), 2)))
            .with_treasury(T2)
            .with_verified_restore(T2, trading_v1::descriptor_hash(&descriptor(&key_c(), 2))),
    );
    let ordinary = SignerIdentity::from_public(key_c().public(), 2, Some(T)).unwrap();
    assert_eq!(
        plan(&request, &view, &ordinary).unwrap_err(),
        Refusal::TreasuryProfileRequired
    );
    assert_eq!(
        plan(&request, &view, &rotation_me()).unwrap_err(),
        Refusal::InvalidRequest("only the canonical Genesis Treasury is authorized")
    );
}

#[test]
fn an_approval_given_for_an_ordinary_reading_cannot_authorize_the_treasury_plan() {
    let world = rotation_world();
    let view = world.view();
    let planned = planned_rotation(&world);
    let digest = review(&planned, &view).unwrap().binding();
    // The same bytes read by the same key as an ORDINARY identity: the same digest, another scope.
    let ordinary_reading = explain(
        &planned.objects()[0].bytes,
        &view,
        &SignerIdentity::from_public(key_c().public(), 2, Some(T)).unwrap(),
    )
    .unwrap();
    assert_eq!(ordinary_reading.binding(), digest);
    assert_eq!(ordinary_reading.signer().profile, WalletProfile::Ordinary);
    let approval = kit::approve(&ordinary_reading, &view);
    let signer = KeySigner::with_identity(
        key_c(),
        rotation_me(),
        SigningGate::test_value().unwrap(),
        DEFAULT_IDLE_LIMIT,
    )
    .unwrap();
    assert_eq!(
        signer.authorize(planned, approval, &view).unwrap_err(),
        Refusal::PlanChanged,
        "the profile is part of what an approval is bound to"
    );
}

#[test]
fn the_treasury_authority_rotation_on_a_production_chain_is_never_signed() {
    let world = world_at(100, Some(Class::Production));
    let view = world.view();
    assert_eq!(view.class(), ChainClass::Production);
    let proposed = descriptor(&key_d(), 2);
    let request = OperationRequest::WalletRotation(
        RotationRequest::new(Blob::new(proposed.clone()), FeeSource::RotatingAuthority)
            .with_restore_verified(ops::rotation::descriptor_fingerprint(&proposed)),
    );
    // Ordinary: refused whatever the class.
    assert_eq!(
        plan(&request, &view, &identity(&key_b())).unwrap_err(),
        Refusal::TreasuryProfileRequired
    );
    // The profile plans and reviews (reading only), but no gate signs on a production chain here.
    let planned = plan(&request, &view, &treasury_me()).unwrap();
    let reviewed = review(&planned, &view).unwrap();
    assert!(reviewed.render_text().contains("production"));
    let session = ops::rotation::RotationSigner::for_test(key_b(), treasury_me(), key_d()).unwrap();
    assert_eq!(
        session
            .authorize(planned, kit::approve(&reviewed, &view), &view)
            .unwrap_err(),
        Refusal::ChainClassMismatch {
            gate: ChainClass::TestValue,
            chain: ChainClass::Production
        }
    );
    if !mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED {
        assert_eq!(SigningGate::production().unwrap_err(), Refusal::GateClosed);
    }
}
