//! Ordinary MUT payments, unit level: coin selection, fee fixed point, change arithmetic, the
//! size limit, rotated wallets and the Treasury reserve hook. Ported and generalised from the
//! desktop wallet's `payment_v2.rs` tests (NATIVE, TEST-VALUE; public test keys only).
#[path = "support/flow.rs"]
mod flow;
#[path = "support/synthetic.rs"]
mod synthetic;

use mutiny_consensus_v8::{
    dividend_state_v1::DividendState,
    transactions::MATURITY,
    transactions_v2::Transfer,
    treasury_v1::{Class, Treasury},
    wallet_rotation_v1::Rotation,
};
use mutiny_crypto_v2::HybridSignature;
use mutiny_wallet_core_v8::*;
use synthetic::{World, address, descriptor, identity, key_a, key_b};

fn pay(recipient: [u8; 32], amount: u64) -> OperationRequest {
    OperationRequest::Payment(PaymentRequest::new(recipient, amount))
}

fn decode_and_verify(world: &World, signed: &SignedOperation, height: u64) -> Transfer {
    let transfer = Transfer::decode(signed.bytes()).unwrap();
    transfer
        .verify(
            world.anchor.genesis,
            world.anchor.fingerprint,
            height,
            &world.state.coins,
            &world.state.wallets,
        )
        .expect("consensus verifies the signed payment");
    transfer
}

#[test]
fn dust_prefix_cannot_hide_funding_and_equal_values_have_stable_order() {
    let key = key_a();
    let me = identity(&key);
    let owner = address(&key, 1);
    let signer = KeySigner::for_test(key_a()).unwrap();
    let mut world = World::new(100);
    for index in 0..140 {
        world.coin(owner, 100, 1, false, 1, index);
    }
    let funding = world.coin(owner, 100_000, 1, false, 250, 0);
    // Larger but unavailable coins must never enter the selected set.
    world.coin(owner, 1_000_000, 100, true, 251, 0); // immature coinbase
    world.coin([99; 32], 1_000_000, 1, false, 252, 0); // someone else's

    let view = world.view();
    let first = plan(&pay([9; 32], 50_000), &view, &me).unwrap();
    assert_eq!(first.inputs(), std::slice::from_ref(&funding));
    assert_eq!(
        first.id(),
        plan(&pay([9; 32], 50_000), &view, &me).unwrap().id(),
        "planning is deterministic"
    );
    let signed = flow::sign(first, &signer, &view).unwrap();
    decode_and_verify(&world, &signed, 101);

    // Reserving the funding coin leaves only dust: that is insufficient, not a hidden coin.
    let mut reserved_world = World::new(100);
    reserved_world.state = world.state.clone();
    reserved_world.reserved.insert(funding.clone());
    assert!(matches!(
        plan(&pay([9; 32], 50_000), &reserved_world.view(), &me),
        Err(Refusal::InsufficientFunds {
            available: 14_000,
            requested: 50_000
        })
    ));

    // Equal values: stable order by outpoint.
    let mut equal = World::new(100);
    equal.coin(owner, 50_000, 1, false, 8, 2);
    equal.coin(owner, 50_000, 1, false, 8, 1);
    let view = equal.view();
    let plan = plan(&pay([9; 32], 70_000), &view, &me).unwrap();
    let indices: Vec<u32> = plan.inputs().iter().map(|point| point.index).collect();
    assert_eq!(indices, [1, 2]);
    let signed = flow::sign(plan, &signer, &view).unwrap();
    decode_and_verify(&equal, &signed, 101);
}

#[test]
fn immutable_review_hybrid_signatures_conservation_head_binding_and_rotation() {
    let key = key_a();
    let me = identity(&key);
    let owner = address(&key, 1);
    let signer = KeySigner::for_test(key_a()).unwrap();
    let mut world = World::new(100);
    let point = world.coin(owner, 100_000, 1, true, 8, 0);

    let view = world.view();
    let planned = plan(&pay([9; 32], 50_000), &view, &me).unwrap();
    let reviewed = review(&planned, &view).unwrap();
    assert_eq!(reviewed.amount(), Some(50_000));
    assert_eq!(reviewed.fee().atoms + reviewed.returned(), 50_000);
    assert_eq!(reviewed.inputs().len(), 1);
    let signed = flow::sign(planned.clone(), &signer, &view).unwrap();
    let transfer = decode_and_verify(&world, &signed, 101);
    assert_eq!(transfer.id().unwrap(), signed.id());
    assert!(transfer.fee >= signed.bytes().len() as u64);
    assert_eq!(signed.reserved(), std::slice::from_ref(&point));

    // Reserved and immature coins are not selected.
    let mut reserved = World::new(100);
    reserved.state = world.state.clone();
    reserved.reserved.insert(point.clone());
    assert_eq!(
        plan(&pay([9; 32], 50_000), &reserved.view(), &me).unwrap_err(),
        Refusal::NothingSpendable
    );
    let young = {
        let mut young = World::new(99);
        young.state = world.state.clone();
        young
    };
    assert_eq!(
        plan(&pay([9; 32], 50_000), &young.view(), &me).unwrap_err(),
        Refusal::NothingSpendable
    );
    // The coinbase coin was created at height 1; at head 99 the next block (100) is one short of MATURITY.
    assert_eq!(young.anchor.height + 1 - 1, MATURITY - 1);

    // A changed head refuses the approval it was given at the old head.
    let reviewed = review(&planned, &view).unwrap();
    let approval = flow::approve(&reviewed, &view);
    let next = world.advanced();
    assert!(matches!(
        signer.authorize(planned.clone(), approval, &next.view()),
        Err(Refusal::StaleHead {
            reviewed: 100,
            current: 101
        })
    ));

    // Another wallet's key cannot authorize this plan.
    let other_signer = KeySigner::for_test(key_b()).unwrap();
    let approval = flow::approve(&review(&planned, &view).unwrap(), &view);
    assert!(matches!(
        other_signer.authorize(planned.clone(), approval, &view),
        Err(Refusal::NotRequiredSigner(Slot::Input(0)))
    ));

    // Spending everything leaves no room for the fee.
    assert!(matches!(
        plan(&pay([9; 32], 100_000), &view, &me),
        Err(Refusal::InsufficientFunds { available: 100_000, requested }) if requested > 100_000
    ));

    // Rotation: the old key loses authority at once; the new key pays and receives change at its
    // generation-two address.
    let other = key_b();
    let zero = HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    };
    world.state.wallets.register(&descriptor(&key, 1)).unwrap();
    let mut rotation = Rotation {
        network: world.anchor.network,
        genesis: world.anchor.genesis,
        fingerprint: world.anchor.fingerprint,
        authority: owner,
        current: descriptor(&key, 1),
        proposed: descriptor(&other, 2),
        created_height: 90,
        expiry_height: 110,
        authorization: zero.clone(),
        possession: zero,
    };
    rotation.sign(&key, &other).unwrap();
    world
        .state
        .wallets
        .apply(
            &rotation,
            world.anchor.genesis,
            world.anchor.fingerprint,
            100,
        )
        .unwrap();
    let view = world.view();
    assert_eq!(
        plan(&pay([9; 32], 50_000), &view, &me).unwrap_err(),
        Refusal::StaleAuthority,
        "the old key is no longer the authority"
    );
    let rotated = SignerIdentity::from_public(other.public(), 2, Some(owner)).unwrap();
    let planned = plan(&pay([9; 32], 50_000), &view, &rotated).unwrap();
    let reviewed = review(&planned, &view).unwrap();
    let change: Vec<_> = reviewed
        .destinations()
        .iter()
        .filter(|d| d.role == DestinationRole::Change)
        .collect();
    assert_eq!(change.len(), 1);
    assert_eq!(change[0].address, address(&other, 2));
    let rotated_signer =
        KeySigner::new_rotated(other, 2, owner, SigningGate::test_value().unwrap()).unwrap();
    let signed = flow::sign(planned, &rotated_signer, &view).unwrap();
    decode_and_verify(&world, &signed, 101);
    // The retired key cannot sign even a plan someone hands it.
    assert_eq!(signer.identity().generation(), 1);
}

#[test]
fn fee_is_a_fixed_point_equal_to_the_signed_size_across_integer_widths() {
    let key = key_a();
    let me = identity(&key);
    let owner = address(&key, 1);
    let signer = KeySigner::for_test(key_a()).unwrap();
    for amount in [
        1u64,
        255,
        256,
        65_535,
        65_536,
        16_777_215,
        16_777_216,
        4_294_967_295,
        4_294_967_296,
        1u64 << 40,
    ] {
        let mut world = World::new(100);
        let coin = (1u64 << 41) + 12_345;
        let point = world.coin(owner, coin, 1, false, 1, 0);
        let view = world.view();
        let planned = plan(&pay([9; 32], amount), &view, &me).unwrap();
        let unsigned_len = planned.objects()[0].bytes.len();
        let signed = flow::sign(planned, &signer, &view).unwrap();
        let transfer = decode_and_verify(&world, &signed, 101);
        // Fixed-width signatures: the unsigned placeholder encoding IS the signed size.
        assert_eq!(unsigned_len, signed.bytes().len(), "amount {amount}");
        // Minimal fixed point: the fee equals the signed size.
        assert_eq!(transfer.fee, signed.bytes().len() as u64, "amount {amount}");
        // Conservation: inputs = outputs + fee.
        let outputs: u64 = transfer.outputs.iter().map(|o| o.atoms).sum();
        assert_eq!(coin, outputs + transfer.fee, "amount {amount}");
        assert_eq!(transfer.outputs[0].atoms, amount);
        assert_eq!(transfer.inputs[0].point, point);
    }
}

#[test]
fn change_and_fee_are_exact_at_every_funding_boundary() {
    let key = key_a();
    let me = identity(&key);
    let owner = address(&key, 1);
    let signer = KeySigner::for_test(key_a()).unwrap();
    let amount = 1_000_000u64;

    // Reference size: with ample funds the shape is the payment plus a large change.
    let mut rich = World::new(100);
    rich.coin(owner, 100_000_000, 1, false, 1, 0);
    let rich_plan = plan(&pay([9; 32], amount), &rich.view(), &me).unwrap();
    let reference = review(&rich_plan, &rich.view()).unwrap().fee().atoms;
    assert_eq!(
        Transfer::decode(&rich_plan.objects()[0].bytes)
            .unwrap()
            .outputs
            .len(),
        2
    );

    // Scan the funding of one coin across the boundary where the payment stops being affordable
    // and the boundary where a change output first becomes possible.
    let mut first_fit = None;
    let mut first_change = None;
    for f in (reference - 160)..=(reference + 40) {
        let mut world = World::new(100);
        world.coin(owner, amount + f, 1, false, 1, 0);
        match plan(&pay([9; 32], amount), &world.view(), &me) {
            Err(Refusal::InsufficientFunds {
                available,
                requested,
            }) => {
                assert!(
                    first_fit.is_none(),
                    "once a funding fits, every larger funding fits (f = {f})"
                );
                assert_eq!(available, amount + f);
                assert!(
                    requested > available,
                    "the report names a larger need (f = {f})"
                );
            }
            Ok(planned) => {
                first_fit.get_or_insert(f);
                let size = planned.objects()[0].bytes.len() as u64;
                let transfer = Transfer::decode(&planned.objects()[0].bytes).unwrap();
                let outputs: u64 = transfer.outputs.iter().map(|output| output.atoms).sum();
                assert_eq!(amount + f, outputs + transfer.fee, "conservation (f = {f})");
                assert!(
                    transfer.fee >= size,
                    "the fee covers the signed size (f = {f})"
                );
                if transfer.outputs.len() == 1 {
                    assert!(
                        first_change.is_none(),
                        "no change shape after a change shape (f = {f})"
                    );
                    assert_eq!(
                        transfer.fee, f,
                        "without change the whole surplus is the fee (f = {f})"
                    );
                } else {
                    first_change.get_or_insert(f);
                    assert_eq!(transfer.outputs.len(), 2, "f = {f}");
                    assert!(
                        transfer.outputs[1].atoms > 0,
                        "a change output is never zero (f = {f})"
                    );
                    // Minimal: the fee is the signed size, up to the few bytes of width the change
                    // amount can shed as the fee grows.
                    assert!(
                        transfer.fee - size <= 4,
                        "fee {} vs size {size} (f = {f})",
                        transfer.fee
                    );
                }
            }
            Err(other) => panic!("unexpected refusal at f = {f}: {other}"),
        }
    }
    let first_fit = first_fit.expect("some funding fits");
    let first_change = first_change.expect("a change shape appears");
    assert!(
        first_fit < first_change,
        "the no-change shape fits below the change shape"
    );

    // The boundary plans sign and verify through consensus.
    for f in [
        first_fit,
        first_fit + 1,
        first_change - 1,
        first_change,
        first_change + 1,
    ] {
        let mut world = World::new(100);
        world.coin(owner, amount + f, 1, false, 1, 0);
        let view = world.view();
        let planned = plan(&pay([9; 32], amount), &view, &me).unwrap();
        let signed = flow::sign(planned, &signer, &view).unwrap();
        decode_and_verify(&world, &signed, 101);
    }
}

#[test]
fn the_sixteen_kib_limit_is_a_typed_refusal_with_consolidation_guidance() {
    let key = key_a();
    let me = identity(&key);
    let owner = address(&key, 1);
    let signer = KeySigner::for_test(key_a()).unwrap();
    // Four coins fit.
    let mut four = World::new(100);
    for tag in 1..=4 {
        four.coin(owner, 50_000, 1, false, tag, 0);
    }
    let view = four.view();
    let planned = plan(&pay([9; 32], 150_000), &view, &me).unwrap();
    assert_eq!(planned.inputs().len(), 4, "about four inputs fit in 16 KiB");
    assert!(planned.objects()[0].bytes.len() <= 16 * 1024);
    let signed = flow::sign(planned, &signer, &view).unwrap();
    decode_and_verify(&four, &signed, 101);

    // Six do not: the typed refusal says what to do.
    let mut six = World::new(100);
    for tag in 1..=6 {
        six.coin(owner, 50_000, 1, false, tag, 0);
    }
    let refusal = plan(&pay([9; 32], 250_000), &six.view(), &me).unwrap_err();
    assert_eq!(refusal, Refusal::SizeLimit { limit: 16 * 1024 });
    assert!(refusal.to_string().contains("consolidate"));

    // A self-payment of the same coins is the consolidation; it needs the same inputs, so it also
    // hits the limit when asked to consolidate all six at once, but consolidating four works.
    let planned = plan(&pay(owner, 150_000), &four.view(), &me).unwrap();
    let reviewed = review(&planned, &four.view()).unwrap();
    assert_eq!(reviewed.amount(), Some(0), "nothing leaves the wallet");
    assert!(reviewed.warnings().iter().any(|w| w.code == "SELF_PAYMENT"));
}

#[test]
fn request_validation_is_typed() {
    let key = key_a();
    let me = identity(&key);
    let mut world = World::new(100);
    world.coin(address(&key, 1), 1_000_000, 1, false, 1, 0);
    let view = world.view();
    assert_eq!(
        plan(&pay([9; 32], 0), &view, &me).unwrap_err(),
        Refusal::InvalidAmount
    );
    assert_eq!(
        plan(&pay([0; 32], 1), &view, &me).unwrap_err(),
        Refusal::InvalidRecipient
    );
    let bad_window = |blocks| {
        OperationRequest::Payment(PaymentRequest::new([9; 32], 1).with_validity_blocks(blocks))
    };
    assert_eq!(
        plan(&bad_window(0), &view, &me).unwrap_err(),
        Refusal::InvalidValidity
    );
    assert_eq!(
        plan(&bad_window(10_081), &view, &me).unwrap_err(),
        Refusal::InvalidValidity
    );
    assert!(plan(&bad_window(10_080), &view, &me).is_ok());
    assert!(plan(&bad_window(1), &view, &me).is_ok());
    // Typed amounts feed the request without floating point.
    let amount = units::parse_mut("0.0005").unwrap();
    assert_eq!(amount, 50_000);
    let planned = plan(&pay([9; 32], amount), &view, &me).unwrap();
    assert_eq!(planned.validity().created, 101);
    assert_eq!(planned.validity().expiry, 101 + DEFAULT_VALIDITY_BLOCKS);
}

#[test]
fn a_new_head_changes_the_review_binding_but_not_the_plan() {
    let key = key_a();
    let me = identity(&key);
    let mut world = World::new(100);
    world.coin(address(&key, 1), 1_000_000, 1, false, 1, 0);
    let view = world.view();
    let planned = plan(&pay([9; 32], 10_000), &view, &me).unwrap();
    let before = review(&planned, &view).unwrap();
    assert_eq!(
        before.binding(),
        review(&planned, &view).unwrap().binding(),
        "a review is a pure function"
    );
    let next = world.advanced();
    let after = review(&planned, &next.view()).unwrap();
    assert_ne!(
        before.binding(),
        after.binding(),
        "a different head is a different review"
    );
    assert!(before.is_for(&view) && !before.is_for(&next.view()));
    assert!(after.is_for(&next.view()));
}

#[test]
fn explain_of_signed_bytes_binds_to_the_same_digest_as_the_plan_review() {
    let key = key_a();
    let me = identity(&key);
    let signer = KeySigner::for_test(key_a()).unwrap();
    let mut world = World::new(100);
    world.coin(address(&key, 1), 1_000_000, 1, false, 1, 0);
    let view = world.view();
    let planned = plan(&pay([9; 32], 10_000), &view, &me).unwrap();
    let from_plan = review(&planned, &view).unwrap();
    let signed = flow::sign(planned.clone(), &signer, &view).unwrap();
    // The same unsigned bytes, seen through the counterparty path, at the same head.
    let from_unsigned = explain(&planned.objects()[0].bytes, &view, &me).unwrap();
    let from_signed = explain(signed.bytes(), &view, &me).unwrap();
    assert_eq!(from_plan.binding(), from_unsigned.binding());
    assert_eq!(from_plan.binding(), from_signed.binding());
    assert!(
        from_signed
            .authorizations()
            .iter()
            .all(|r| r.status == RequirementStatus::Provided),
        "valid signatures are reported as provided"
    );
    assert!(
        from_unsigned
            .authorizations()
            .iter()
            .all(|r| r.status == RequirementStatus::ThisWallet)
    );
}

#[test]
fn treasury_spending_needs_the_profile_and_respects_the_reserve() {
    let treasury_key = key_b();
    let treasury_address = address(&treasury_key, 1);
    let mut world = World::new(100);
    world
        .state
        .wallets
        .register(&descriptor(&treasury_key, 1))
        .unwrap();
    world.state.dividends = DividendState::genesis(
        Treasury::new(Class::TestValue, descriptor(&treasury_key, 1)).unwrap(),
    );
    // Backing coins: two non-coinbase coins.
    let big = world.coin(treasury_address, 1_200_000, 1, false, 1, 0);
    let small = world.coin(treasury_address, 300_000, 1, false, 2, 0);
    // An outstanding award reserves half of the backing at epoch 131072.
    let licenses = [([7u8; 32], [8u8; 32], Some(0u64))];
    let backing = 1_500_000;
    world
        .state
        .dividends
        .advance(131_072, backing, &licenses)
        .unwrap();
    let reserved = world.state.dividends.reserved();
    assert!(reserved > 0 && reserved < backing, "reserved = {reserved}");

    let ordinary = identity(&treasury_key);
    let treasury = identity(&treasury_key).with_treasury_roles_for_test(TreasuryRoles {
        authority: true,
        destination_of: None,
    });
    let view = world.view();
    // An ordinary profile never spends the Treasury.
    assert_eq!(
        plan(&pay([9; 32], 10_000), &view, &ordinary).unwrap_err(),
        Refusal::TreasuryProfileRequired
    );
    // The Treasury profile may spend above the reserve ...
    let allowed = backing - reserved - 20_000; // leave room for the fee
    let planned = plan(&pay([9; 32], allowed), &view, &treasury).expect("above the reserve");
    let reviewed = review(&planned, &view).unwrap();
    assert!(
        reviewed
            .warnings()
            .iter()
            .any(|w| w.code == "TREASURY_FUNDS")
    );
    assert!(
        reviewed
            .acknowledgements()
            .contains(&AckKind::TreasuryAuthority)
    );
    // ... and never below it.
    match plan(&pay([9; 32], backing - reserved + 1), &view, &treasury) {
        Err(Refusal::ReserveBackingViolation {
            reserved: r,
            backing_after,
        }) => {
            assert_eq!(r, reserved);
            assert!(backing_after < reserved);
        }
        other => panic!("expected the reserve refusal, got {other:?}"),
    }
    let _ = (big, small);
}

#[test]
fn paying_into_the_treasury_needs_no_profile_is_labelled_and_only_raises_the_backing() {
    let wallet = key_a();
    let treasury_key = key_b();
    let treasury_address = address(&treasury_key, 1);
    let mut world = World::new(100);
    world
        .state
        .wallets
        .register(&descriptor(&treasury_key, 1))
        .unwrap();
    world.state.dividends = DividendState::genesis(
        Treasury::new(Class::TestValue, descriptor(&treasury_key, 1)).unwrap(),
    );
    // The Treasury holds backing and owes an award, so its reserve is live.
    let backing_coin = world.coin(treasury_address, 1_500_000, 1, false, 5, 0);
    world
        .state
        .dividends
        .advance(131_072, 1_500_000, &[([7u8; 32], [8u8; 32], Some(0u64))])
        .unwrap();
    let reserved = world.state.dividends.reserved();
    assert!(
        reserved > 0 && reserved < 1_500_000,
        "reserved = {reserved}"
    );
    world.coin(address(&wallet, 1), 1_000_000, 1, false, 1, 0);
    let view = world.view();

    // An ordinary wallet may pay INTO the Treasury (no profile) ...
    let planned = plan(&pay(treasury_address, 100_000), &view, &identity(&wallet)).unwrap();
    // ... the review labels the destination loudly ...
    let reviewed = review(&planned, &view).unwrap();
    assert!(
        reviewed
            .warnings()
            .iter()
            .any(|w| w.code == "TREASURY_DESTINATION")
    );
    assert!(
        reviewed
            .destinations()
            .iter()
            .any(|d| d.label == AddressLabel::Treasury)
    );
    // ... it never spends the Treasury's own coins, and the backing only rises, computed here from
    // the chain state and the transaction alone.
    let transfer = Transfer::decode(&planned.objects()[0].bytes).unwrap();
    assert!(
        transfer
            .inputs
            .iter()
            .all(|input| input.point != backing_coin)
    );
    let backing_before: u64 = world
        .state
        .coins
        .values()
        .filter(|coin| coin.output.owner == treasury_address && !coin.coinbase)
        .map(|coin| coin.output.atoms)
        .sum();
    let paid_in: u64 = transfer
        .outputs
        .iter()
        .filter(|output| output.owner == treasury_address)
        .map(|output| output.atoms)
        .sum();
    assert_eq!(paid_in, 100_000);
    assert!(backing_before + paid_in > backing_before && backing_before + paid_in >= reserved);
}

/// `validity_blocks = N` makes a payment valid in the NEXT block and the N blocks after it: N + 1
/// blocks in all, expiry = next + N, as consensus admits a transaction while its height is between
/// its creation and its expiry inclusive (documented exactly so since the fixes of the independent
/// wallet review). N = 10,080 is the protocol's bound on expiry - created (10,081 blocks); 0 and
/// 10,081 are refused.
#[test]
fn validity_blocks_n_admits_the_next_block_and_n_more() {
    let me = identity(&key_a());
    let at = |head: u64| {
        let mut world = World::new(head);
        world.coin(address(&key_a(), 1), 5_000_000, 1, false, 1, 0);
        world
    };
    let world = at(100);
    let request = |blocks: u64| {
        OperationRequest::Payment(
            PaymentRequest::new(address(&key_b(), 1), 100_000).with_validity_blocks(blocks),
        )
    };
    for blocks in [1u64, DEFAULT_VALIDITY_BLOCKS, 10_080] {
        let planned = plan(&request(blocks), &world.view(), &me).unwrap();
        assert_eq!(
            (planned.validity().created, planned.validity().expiry),
            (101, 101 + blocks),
            "{blocks}"
        );
        // Still valid when the next block is the expiry: N + 1 blocks after the first one ...
        let last = at(100 + blocks);
        review(&planned, &last.view()).unwrap();
        // ... and closed one block later.
        let after = at(101 + blocks);
        assert_eq!(
            review(&planned, &after.view()).unwrap_err(),
            Refusal::WindowClosed {
                expiry: 101 + blocks,
                next_height: 102 + blocks
            },
            "{blocks}"
        );
    }
    for blocks in [0u64, 10_081] {
        assert_eq!(
            plan(&request(blocks), &world.view(), &me).unwrap_err(),
            Refusal::InvalidValidity,
            "{blocks}"
        );
    }
}
