//! Adopting an unsigned proposal prepared elsewhere (an online machine preparing a payment for an
//! offline signer, a counterparty's partial operation): the same plan, the same review, the same
//! approval and the same authorization as a plan built locally. NATIVE, TEST-VALUE; public test keys.
#[path = "support/flow.rs"]
mod flow;
#[path = "support/synthetic.rs"]
mod synthetic;

use mutiny_consensus_v8::dividend_state_v1::DividendState;
use mutiny_consensus_v8::transactions::OutPoint;
use mutiny_consensus_v8::transactions_v2::{Input, Transfer};
use mutiny_consensus_v8::treasury_v1::{Class, Treasury};
use mutiny_wallet_core_v8::*;
use synthetic::{World, address, descriptor, identity, key_a, key_b};

fn pay(recipient: [u8; 32], amount: u64) -> OperationRequest {
    OperationRequest::Payment(PaymentRequest::new(recipient, amount))
}

fn world() -> World {
    let mut world = World::new(100);
    world.coin(address(&key_a(), 1), 5_000_000, 1, false, 1, 0);
    world
}

#[test]
fn an_unsigned_payment_prepared_elsewhere_is_signed_through_the_same_pipeline() {
    let world = world();
    let view = world.view();
    // The online machine knows only the PUBLIC identity: it can plan and export, never sign.
    let online = plan(
        &pay(address(&key_b(), 1), 1_000_000),
        &view,
        &identity(&key_a()),
    )
    .unwrap();
    let exported = online.objects()[0].bytes.clone();

    // The offline signer adopts the bytes against its own verified view of the same head.
    let adopted = adopt(&exported, &view, &identity(&key_a())).unwrap();
    assert_eq!(adopted.id(), online.id(), "the same operation");
    assert_eq!(adopted.objects(), online.objects());
    assert_eq!(adopted.inputs(), online.inputs());
    assert_eq!(adopted.validity(), online.validity());
    let reviewed = review(&adopted, &view).unwrap();
    assert_eq!(
        reviewed.binding(),
        review(&online, &view).unwrap().binding(),
        "the same review digest on both machines"
    );

    let signer = KeySigner::for_test(key_a()).unwrap();
    let signed = flow::sign(adopted, &signer, &view).unwrap();
    let transfer = Transfer::decode(signed.bytes()).unwrap();
    transfer
        .verify(
            world.anchor.genesis,
            world.anchor.fingerprint,
            101,
            &world.state.coins,
            &world.state.wallets,
        )
        .expect("consensus verifies the offline-signed payment");
    // And it is exactly the proposal plus signatures.
    let mut unsigned = transfer.clone();
    for input in &mut unsigned.inputs {
        input.signature = mutiny_crypto_v2::HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        };
    }
    assert_eq!(unsigned.encode().unwrap(), exported);
}

#[test]
fn adoption_refuses_what_this_wallet_cannot_or_need_not_sign() {
    let world = world();
    let view = world.view();
    let online = plan(
        &pay(address(&key_b(), 1), 1_000_000),
        &view,
        &identity(&key_a()),
    )
    .unwrap();
    let exported = online.objects()[0].bytes.clone();

    // Someone else's wallet has nothing to sign in it.
    assert_eq!(
        adopt(&exported, &view, &identity(&key_b())).unwrap_err(),
        Refusal::NotRequiredSigner(Slot::Input(0))
    );

    // Already signed: nothing is left to sign.
    let signer = KeySigner::for_test(key_a()).unwrap();
    let signed = flow::sign(online.clone(), &signer, &view).unwrap();
    assert!(matches!(
        adopt(signed.bytes(), &view, &identity(&key_a())),
        Err(Refusal::Malformed(_))
    ));

    // A proposal that mixes in another wallet's input names the first input this wallet cannot sign.
    let mut world_two = World::new(100);
    world_two.coin(address(&key_a(), 1), 5_000_000, 1, false, 1, 0);
    world_two.coin(address(&key_b(), 1), 5_000_000, 1, false, 2, 0);
    let mut mixed = Transfer::decode(&exported).unwrap();
    mixed.inputs.push(
        Input::unsigned(
            OutPoint {
                transaction: [2; 32],
                index: 0,
            },
            key_b().public(),
            1,
        )
        .unwrap(),
    );
    mixed.outputs[1].atoms += 5_000_000 - 3_400;
    mixed.fee += 3_400;
    assert_eq!(
        adopt(
            &mixed.encode().unwrap(),
            &world_two.view(),
            &identity(&key_a())
        )
        .unwrap_err(),
        Refusal::NotRequiredSigner(Slot::Input(1))
    );

    // Nonsense.
    assert_eq!(
        adopt(b"nonsense", &view, &identity(&key_a())).unwrap_err(),
        Refusal::UnknownOperation
    );

    // The chain moved on and the coin is gone.
    let mut spent = World::new(100);
    spent.coin(address(&key_a(), 1), 7, 1, false, 9, 0);
    assert_eq!(
        adopt(&exported, &spent.view(), &identity(&key_a())).unwrap_err(),
        Refusal::InputUnavailable
    );

    // A proposal for another chain.
    let mut foreign = World::new(100);
    foreign.state = world.state.clone();
    foreign.anchor.genesis = [0x61; 32];
    assert_eq!(
        adopt(&exported, &foreign.view(), &identity(&key_a())).unwrap_err(),
        Refusal::WrongContext(ContextField::Genesis)
    );

    // A key that was rotated away is not adopted either.
    let zero = mutiny_crypto_v2::HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    };
    let mut rotated = world.advanced();
    rotated
        .state
        .wallets
        .register(&descriptor(&key_a(), 1))
        .unwrap();
    let mut rotation = mutiny_consensus_v8::wallet_rotation_v1::Rotation {
        network: rotated.anchor.network,
        genesis: rotated.anchor.genesis,
        fingerprint: rotated.anchor.fingerprint,
        authority: address(&key_a(), 1),
        current: descriptor(&key_a(), 1),
        proposed: descriptor(&key_b(), 2),
        created_height: 90,
        expiry_height: 120,
        authorization: zero.clone(),
        possession: zero,
    };
    rotation.sign(&key_a(), &key_b()).unwrap();
    rotated
        .state
        .wallets
        .apply(
            &rotation,
            rotated.anchor.genesis,
            rotated.anchor.fingerprint,
            101,
        )
        .unwrap();
    assert_eq!(
        adopt(&exported, &rotated.view(), &identity(&key_a())).unwrap_err(),
        Refusal::StaleAuthority
    );
}

/// A world whose Treasury authority is key B, holding 5,000,000 atoms of backing.
fn treasury_world() -> World {
    let treasury_key = key_b();
    let mut world = World::new(100);
    world
        .state
        .wallets
        .register(&descriptor(&treasury_key, 1))
        .unwrap();
    world.state.dividends = DividendState::genesis(
        Treasury::new(Class::TestValue, descriptor(&treasury_key, 1)).unwrap(),
    );
    world.coin(address(&treasury_key, 1), 5_000_000, 1, false, 1, 0);
    world
}

#[test]
fn a_treasury_spend_prepared_elsewhere_is_adopted_only_under_the_treasury_profile() {
    let world = treasury_world();
    let view = world.view();
    let treasury = identity(&key_b()).with_treasury_roles_for_test(TreasuryRoles {
        authority: true,
        destination_of: None,
    });
    let ordinary = identity(&key_b());
    let online = plan(&pay(address(&key_a(), 1), 1_000_000), &view, &treasury).unwrap();
    let exported = online.objects()[0].bytes.clone();

    // The ordinary profile of the very same key is refused at adoption: however a plan comes into
    // being, the Treasury authority spends only through the Treasury profile.
    assert_eq!(
        adopt(&exported, &view, &ordinary).unwrap_err(),
        Refusal::TreasuryProfileRequired
    );
    // The Treasury profile adopts the same operation, and reviews it as a Treasury spend.
    let adopted = adopt(&exported, &view, &treasury).unwrap();
    assert_eq!(adopted.id(), online.id());
    let reviewed = review(&adopted, &view).unwrap();
    assert!(
        reviewed
            .acknowledgements()
            .contains(&AckKind::TreasuryAuthority)
    );
}

#[test]
fn an_approval_read_under_the_ordinary_profile_cannot_authorize_the_treasury_plan() {
    let world = treasury_world();
    let view = world.view();
    let treasury = identity(&key_b()).with_treasury_roles_for_test(TreasuryRoles {
        authority: true,
        destination_of: None,
    });
    let planned = plan(&pay(address(&key_a(), 1), 1_000_000), &view, &treasury).unwrap();
    let own = review(&planned, &view).unwrap();
    // The very same bytes read as an ordinary wallet of the same key: one operation, one digest ...
    let as_ordinary = explain(&planned.objects()[0].bytes, &view, &identity(&key_b())).unwrap();
    assert_eq!(as_ordinary.binding(), own.binding());
    // ... but a different reading: the review names the profile it was read under, so a person who
    // approved THAT reading has not approved a Treasury-profile spend.
    let profile = |review: &Review| {
        review
            .rows()
            .into_iter()
            .find(|row| row.label == "Profile")
            .map(|row| row.value)
    };
    assert_eq!(profile(&own).as_deref(), Some("Treasury profile"));
    assert_eq!(profile(&as_ordinary).as_deref(), Some("ordinary wallet"));
    let signer = KeySigner::with_identity(
        key_b(),
        treasury.clone(),
        SigningGate::test_value().unwrap(),
        DEFAULT_IDLE_LIMIT,
    )
    .unwrap();
    assert_eq!(
        signer
            .authorize(planned.clone(), flow::approve(&as_ordinary, &view), &view)
            .unwrap_err(),
        Refusal::PlanChanged
    );
    // Its own approval works.
    assert!(
        signer
            .authorize(planned, flow::approve(&own, &view), &view)
            .is_ok()
    );
}

#[test]
fn a_partial_container_is_adopted_for_the_part_this_wallet_signs() {
    let world = world();
    let view = world.view();
    let online = plan(
        &pay(address(&key_b(), 1), 1_000_000),
        &view,
        &identity(&key_a()),
    )
    .unwrap();
    // Payments are never partial in practice; the container and adoption are kind-agnostic.
    let partial = SignedOperation::Partial {
        kind: OperationKind::Payment,
        id: [5; 32],
        bytes: online.objects()[0].bytes.clone(),
        missing: online.requirements().to_vec(),
        validity: *online.validity(),
        reserved: online.inputs().to_vec(),
    };
    let container = PartialApproval::from_signed(&partial, view.context()).unwrap();
    let imported = PartialApproval::import(&container.export().unwrap()).unwrap();
    let adopted = imported.adopt_for(&view, &identity(&key_a())).unwrap();
    assert_eq!(adopted.id(), online.id());

    // A label that disagrees with the bytes, and a container for another chain.
    let mut wrong_label = partial.clone();
    if let SignedOperation::Partial { kind, .. } = &mut wrong_label {
        *kind = OperationKind::LicenseDvp;
    }
    let mislabelled = PartialApproval::from_signed(&wrong_label, view.context()).unwrap();
    assert_eq!(
        mislabelled
            .adopt_for(&view, &identity(&key_a()))
            .unwrap_err(),
        Refusal::PartialInvalid("the kind label does not match the operation inside")
    );
    let mut foreign = World::new(100);
    foreign.state = world.state.clone();
    foreign.anchor.fingerprint = [0x62; 32];
    assert_eq!(
        imported
            .adopt_for(&foreign.view(), &identity(&key_a()))
            .unwrap_err(),
        Refusal::WrongContext(ContextField::Fingerprint)
    );
}
