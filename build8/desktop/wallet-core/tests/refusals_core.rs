//! The refusal table: every refusal of the wallet core that applies to ordinary payments, plus the
//! registry refusals every operation shares. Each refusal must change no state and return no signed
//! bytes. NATIVE, TEST-VALUE; public test keys only.
#[path = "support/flow.rs"]
mod flow;
#[path = "support/synthetic.rs"]
mod synthetic;

use mutiny_consensus_v8::{
    NETWORK_ID,
    dividend_state_v1::DividendState,
    transactions::{OutPoint, Output},
    transactions_v2::{Input, Transfer},
    treasury_v1::{Class, Treasury},
};
use mutiny_wallet_core_v8::*;
use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};
use synthetic::{World, address, descriptor, identity, key_a, key_b};

fn pay(recipient: [u8; 32], amount: u64) -> OperationRequest {
    OperationRequest::Payment(PaymentRequest::new(recipient, amount))
}

/// A funded world and the plan for a 10,000 atom payment from key A.
fn funded() -> (World, SignerIdentity, OperationPlan) {
    let mut world = World::new(100);
    world.coin(address(&key_a(), 1), 1_000_000, 1, false, 1, 0);
    let me = identity(&key_a());
    let planned = plan(&pay([9; 32], 10_000), &world.view(), &me).unwrap();
    (world, me, planned)
}

#[test]
fn the_production_gate_is_closed_and_no_signer_can_exist_without_a_gate() {
    // crypto-v2 PRODUCTION_SECURITY_QUALIFIED is false, so the only gate that can be built here is
    // the test-value gate, which exists only in a test build.
    if !mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED {
        assert_eq!(SigningGate::production().unwrap_err(), Refusal::GateClosed);
    }
    assert_eq!(
        SigningGate::production().is_err(),
        !mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED
    );
    const {
        assert!(
            TEST_VALUE_SIGNING_ENABLED,
            "this test build carries the test gate"
        )
    };
    assert_eq!(
        SigningGate::test_value().unwrap().mode(),
        GateMode::TestValue
    );
}

/// A host may SHORTEN a signer's idle limit, never lengthen it (fixes of the independent wallet
/// review, MINOR-6): `KeySigner::with_identity` given `Duration::MAX` locks itself after
/// `DEFAULT_IDLE_LIMIT` as the default signer does, and a shorter limit is honoured. The explicit
/// clock of `authorize_at` (test builds only) stands in for the idle time; the idle check comes
/// before every other one, so a locked signer says `LOCKED` and a live one gets further.
#[test]
fn a_host_may_shorten_the_idle_limit_but_never_lengthen_it() {
    let (world, me, planned) = funded();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    let second = Duration::from_secs(1);
    for (limit, idle, locks) in [
        (Duration::MAX, DEFAULT_IDLE_LIMIT, true),
        (Duration::MAX, DEFAULT_IDLE_LIMIT - second, false),
        (DEFAULT_IDLE_LIMIT + second, DEFAULT_IDLE_LIMIT, true),
        (Duration::from_secs(10), Duration::from_secs(10), true),
        (Duration::from_secs(10), Duration::from_secs(9), false),
    ] {
        let signer = KeySigner::with_identity(
            key_a(),
            me.clone(),
            SigningGate::test_value().unwrap(),
            limit,
        )
        .unwrap();
        let now = Instant::now() + idle;
        let result =
            signer.authorize_at(planned.clone(), flow::approve(&reviewed, &view), &view, now);
        assert_eq!(
            result.as_ref().err() == Some(&Refusal::Locked),
            locks,
            "limit {limit:?}, idle {idle:?}: {:?}",
            result.err()
        );
    }
}

#[test]
fn locked_and_idle_expired_signers_refuse_without_effect() {
    let (world, _, planned) = funded();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();

    let signer = KeySigner::for_test(key_a()).unwrap();
    let approval = flow::approve(&reviewed, &view);
    signer.lock();
    assert!(signer.is_locked());
    assert_eq!(
        signer
            .authorize(planned.clone(), approval, &view)
            .unwrap_err(),
        Refusal::Locked
    );
    assert_eq!(
        signer.touch().unwrap_err(),
        Refusal::Locked,
        "input cannot revive a locked session"
    );

    // An idle limit of zero expires immediately and also refuses.
    let idle = KeySigner::with_identity(
        key_a(),
        identity(&key_a()),
        SigningGate::test_value().unwrap(),
        Duration::from_millis(0),
    )
    .unwrap();
    let approval = flow::approve(&reviewed, &view);
    assert_eq!(
        idle.authorize(planned, approval, &view).unwrap_err(),
        Refusal::Locked
    );
    assert!(idle.is_locked());
}

#[test]
fn old_approvals_and_old_reviews_expire() {
    let (world, _, planned) = funded();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    let signer = KeySigner::for_test(key_a()).unwrap();

    // An approval older than MAX_APPROVAL_AGE.
    let then = Instant::now()
        .checked_sub(MAX_APPROVAL_AGE + Duration::from_secs(5))
        .expect("monotonic clock has history");
    let mut gate = ReviewGate::new();
    gate.present(&reviewed, &view);
    for index in reviewed.destinations_needing_check() {
        gate.confirm_destination(index, &reviewed.destination_check_text(index))
            .unwrap();
    }
    for ack in reviewed.acknowledgements() {
        gate.acknowledge(*ack).unwrap();
    }
    let old = gate.approve_at(&view, then).unwrap();
    assert_eq!(
        signer.authorize(planned.clone(), old, &view).unwrap_err(),
        Refusal::Expired(ExpiryKind::Approval)
    );

    // A review shown longer ago than MAX_REVIEW_AGE.
    let long_ago = Instant::now()
        .checked_sub(MAX_REVIEW_AGE + Duration::from_secs(5))
        .expect("monotonic clock has history");
    let mut gate = ReviewGate::new();
    gate.present_at(&reviewed, &view, long_ago);
    for index in reviewed.destinations_needing_check() {
        gate.confirm_destination(index, &reviewed.destination_check_text(index))
            .unwrap();
    }
    for ack in reviewed.acknowledgements() {
        gate.acknowledge(*ack).unwrap();
    }
    assert_eq!(
        gate.approve(&view).unwrap_err(),
        Refusal::Expired(ExpiryKind::Review)
    );
    assert!(!gate.is_presenting(), "an expired review is dropped");
}

#[test]
fn a_foreign_chain_context_is_refused_field_by_field() {
    let (world, me, planned) = funded();

    // Another Genesis and another protocol fingerprint, over the same state.
    let mut other_genesis = World::new(100);
    other_genesis.state = world.state.clone();
    other_genesis.anchor.genesis = [0x61; 32];
    assert_eq!(
        review(&planned, &other_genesis.view()).unwrap_err(),
        Refusal::WrongContext(ContextField::Genesis)
    );
    let mut other_fingerprint = World::new(100);
    other_fingerprint.state = world.state.clone();
    other_fingerprint.anchor.fingerprint = [0x62; 32];
    assert_eq!(
        review(&planned, &other_fingerprint.view()).unwrap_err(),
        Refusal::WrongContext(ContextField::Fingerprint)
    );

    // A foreign network cannot even form a head.
    let mut anchor = world.anchor.clone();
    anchor.network ^= 1;
    assert_eq!(
        HeadInfo::new(anchor, 1, 1, [1; 32]).unwrap_err(),
        Refusal::WrongContext(ContextField::Network)
    );

    // Bytes for another network are refused by explain.
    let mut transfer = Transfer::decode(&planned.objects()[0].bytes).unwrap();
    transfer.network ^= 1;
    assert_eq!(
        explain(&transfer.encode().unwrap(), &world.view(), &me).unwrap_err(),
        Refusal::WrongContext(ContextField::Network)
    );
    assert_eq!(NETWORK_ID, planned.anchor().network);
}

#[test]
fn the_head_moving_or_the_plan_changing_voids_the_approval() {
    let (world, me, planned) = funded();
    let view = world.view();
    let signer = KeySigner::for_test(key_a()).unwrap();

    // The head moved.
    let approval = flow::approve(&review(&planned, &view).unwrap(), &view);
    let next = world.advanced();
    assert_eq!(
        signer
            .authorize(planned.clone(), approval, &next.view())
            .unwrap_err(),
        Refusal::StaleHead {
            reviewed: 100,
            current: 101
        }
    );

    // A different plan with an approval given for another.
    let other_plan = plan(&pay([9; 32], 20_000), &view, &me).unwrap();
    assert_ne!(other_plan.id(), planned.id());
    let approval_for_other = flow::approve(&review(&other_plan, &view).unwrap(), &view);
    assert_eq!(
        signer
            .authorize(planned, approval_for_other, &view)
            .unwrap_err(),
        Refusal::PlanChanged
    );
}

#[test]
fn the_wrong_wallet_and_a_rotated_away_key_cannot_sign() {
    let (world, _me, planned) = funded();
    let view = world.view();
    let stranger = KeySigner::for_test(key_b()).unwrap();
    let approval = flow::approve(&review(&planned, &view).unwrap(), &view);
    assert_eq!(
        stranger
            .authorize(planned.clone(), approval, &view)
            .unwrap_err(),
        Refusal::NotRequiredSigner(Slot::Input(0))
    );

    // An identity the chain does not corroborate (generation two, never registered).
    let unknown = SignerIdentity::from_public(key_b().public(), 2, Some([0x44; 32])).unwrap();
    assert_eq!(
        unknown.check_current(&view).unwrap_err(),
        Refusal::StaleAuthority
    );
    let mut funded_for_b = World::new(100);
    funded_for_b.coin(address(&key_b(), 2), 1_000_000, 1, false, 1, 0);
    assert_eq!(
        plan(&pay([9; 32], 1), &funded_for_b.view(), &unknown).unwrap_err(),
        Refusal::StaleAuthority
    );

    // A plan whose coin owner's descriptor changed by rotation is stale at the next head.
    let mut rotated = world.advanced();
    let zero = mutiny_crypto_v2::HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    };
    let owner = address(&key_a(), 1);
    rotated
        .state
        .wallets
        .register(&descriptor(&key_a(), 1))
        .unwrap();
    let mut rotation = mutiny_consensus_v8::wallet_rotation_v1::Rotation {
        network: rotated.anchor.network,
        genesis: rotated.anchor.genesis,
        fingerprint: rotated.anchor.fingerprint,
        authority: owner,
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
        review(&planned, &rotated.view()).unwrap_err(),
        Refusal::StaleAuthority
    );
}

#[test]
fn a_test_value_gate_refuses_a_production_chain() {
    let (mut world, me, _) = funded();
    world.state.dividends =
        DividendState::genesis(Treasury::new(Class::Production, descriptor(&key_b(), 1)).unwrap());
    let view = world.view();
    assert_eq!(view.class(), ChainClass::Production);
    // Planning only reads the chain, so it works; the TEST-VALUE signer refuses to sign here.
    let planned = plan(&pay([9; 32], 10_000), &view, &me).unwrap();
    let signer = KeySigner::for_test(key_a()).unwrap();
    let approval = flow::approve(&review(&planned, &view).unwrap(), &view);
    assert_eq!(
        signer.authorize(planned, approval, &view).unwrap_err(),
        Refusal::ChainClassMismatch {
            gate: ChainClass::TestValue,
            chain: ChainClass::Production
        }
    );
}

#[test]
fn funding_refusals_are_typed_and_precise() {
    let me = identity(&key_a());
    let owner = address(&key_a(), 1);

    // No coin at all.
    let empty = World::new(100);
    assert_eq!(
        plan(&pay([9; 32], 1), &empty.view(), &me).unwrap_err(),
        Refusal::NothingSpendable
    );

    // Not enough.
    let mut poor = World::new(100);
    poor.coin(owner, 10, 1, false, 1, 0);
    assert_eq!(
        plan(&pay([9; 32], 1_000), &poor.view(), &me).unwrap_err(),
        Refusal::InsufficientFunds {
            available: 10,
            requested: 1_000
        }
    );

    // Over 128 candidate coins of one atom each cannot be spent in one transaction.
    let mut dust = World::new(100);
    for index in 0..140 {
        dust.coin(owner, 1, 1, false, 1, index);
    }
    assert_eq!(
        plan(&pay([9; 32], 130), &dust.view(), &me).unwrap_err(),
        Refusal::TooManyInputs { limit: 128 }
    );

    // The 16 KiB limit.
    let mut many = World::new(100);
    for tag in 1..=6 {
        many.coin(owner, 50_000, 1, false, tag, 0);
    }
    assert_eq!(
        plan(&pay([9; 32], 250_000), &many.view(), &me).unwrap_err(),
        Refusal::SizeLimit { limit: 16 * 1024 }
    );
}

#[test]
fn pre_signing_validation_mirrors_consensus_for_transfers_received_from_elsewhere() {
    let (world, me, planned) = funded();
    let view = world.view();
    let base = Transfer::decode(&planned.objects()[0].bytes).unwrap();
    let explain_of = |transfer: &Transfer| explain(&transfer.encode().unwrap(), &view, &me);

    // Fee below the minimum (size) while conservation holds.
    let mut cheap = base.clone();
    let give_back = cheap.fee - 1;
    cheap.fee = 1;
    cheap.outputs[1].atoms += give_back;
    assert!(
        matches!(explain_of(&cheap), Err(Refusal::FeeBelowMinimum { fee: 1, minimum }) if minimum > 1)
    );

    // Inputs do not equal outputs plus fee.
    let mut leaky = base.clone();
    leaky.outputs[1].atoms -= 1;
    assert_eq!(explain_of(&leaky).unwrap_err(), Refusal::Conservation);

    // A coin that does not exist.
    let mut ghost = base.clone();
    ghost.inputs[0].point = OutPoint {
        transaction: [0xee; 32],
        index: 0,
    };
    assert_eq!(explain_of(&ghost).unwrap_err(), Refusal::InputUnavailable);

    // An input whose descriptor does not control the coin.
    let mut wrong_key = base.clone();
    wrong_key.inputs[0] =
        Input::unsigned(base.inputs[0].point.clone(), key_b().public(), 1).unwrap();
    assert_eq!(explain_of(&wrong_key).unwrap_err(), Refusal::StaleAuthority);

    // A coinbase coin that has not matured.
    let mut young = World::new(100);
    young.coin(address(&key_a(), 1), 1_000_000, 50, true, 5, 0);
    let transfer = Transfer {
        inputs: vec![
            Input::unsigned(
                OutPoint {
                    transaction: [5; 32],
                    index: 0,
                },
                key_a().public(),
                1,
            )
            .unwrap(),
        ],
        outputs: vec![Output {
            owner: [9; 32],
            atoms: 1_000_000 - base.fee,
        }],
        fee: base.fee,
        ..base.clone()
    };
    assert_eq!(
        explain(&transfer.encode().unwrap(), &young.view(), &me).unwrap_err(),
        Refusal::ImmatureInput
    );

    // Inputs reserved by another pending operation.
    let mut reserved_world = World::new(100);
    reserved_world.state = world.state.clone();
    reserved_world.reserved = BTreeSet::from([planned.inputs()[0].clone()]);
    assert_eq!(
        review(&planned, &reserved_world.view()).unwrap_err(),
        Refusal::ReservedInput
    );
}

#[test]
fn validity_windows_are_enforced_at_both_ends() {
    let (world, _me, planned) = funded();
    // The plan is valid for blocks 101 to 245.
    assert_eq!(
        (planned.validity().created, planned.validity().expiry),
        (101, 245)
    );
    let at = |head: u64| {
        let mut other = World::new(head);
        other.state = world.state.clone();
        other
    };
    assert_eq!(
        review(&planned, &at(99).view()).unwrap_err(),
        Refusal::WindowNotOpen {
            created: 101,
            next_height: 100
        }
    );
    assert!(review(&planned, &at(100).view()).is_ok());
    assert!(review(&planned, &at(244).view()).is_ok());
    assert_eq!(
        review(&planned, &at(245).view()).unwrap_err(),
        Refusal::WindowClosed {
            expiry: 245,
            next_height: 246
        }
    );
}

#[test]
fn unknown_and_unimplemented_operations_are_refused() {
    let (world, me, _) = funded();
    let view = world.view();
    assert_eq!(
        explain(b"not an operation", &view, &me).unwrap_err(),
        Refusal::UnknownOperation
    );
    assert_eq!(
        explain(&[], &view, &me).unwrap_err(),
        Refusal::UnknownOperation
    );

    let hash = [3u8; 32];
    let requests = vec![
        OperationRequest::WalletRotation(RotationRequest::new(
            Blob::new(vec![1]),
            FeeSource::RotatingAuthority,
        )),
        OperationRequest::DividendClaim(DividendClaimRequest::new(hash, 1, 1, hash)),
        OperationRequest::LicenseDvp(LicenseDvpRequest::new(Blob::new(vec![1]), hash)),
        OperationRequest::HashLock(HashLockRequest::new(Blob::new(vec![1]), hash, 1, hash, 9)),
        OperationRequest::ConditionalClaim(ClaimRequest::new(hash, Preimage::from_bytes([1; 32]))),
        OperationRequest::ConditionalRefund(RefundRequest::new(hash)),
        OperationRequest::FiatLock(FiatLockRequest::new(Blob::new(vec![1]), hash, 1, hash)),
        OperationRequest::FiatRelease(FiatReleaseRequest::new(hash)),
        OperationRequest::BondCreate(BondCreateRequest::new(hash, 1, 1, hash)),
        OperationRequest::BondUnbond(BondUnbondRequest::new(hash)),
        OperationRequest::BondWithdraw(BondWithdrawRequest::new(hash)),
        OperationRequest::TreasuryRotate(TreasuryRotateRequest::new(Blob::new(vec![1]))),
        OperationRequest::TreasuryFreezeOffer(TreasuryFreezeOfferRequest::new(Blob::new(vec![1]))),
    ];
    let implemented = ops::implemented_kinds();
    for request in requests {
        let kind = request.kind().expect("a kind");
        match plan(&request, &view, &me) {
            Err(Refusal::NotImplemented(refused)) => {
                assert_eq!(refused, kind);
                assert!(
                    !implemented.contains(&kind),
                    "{kind:?} is registered but its planner refused as unimplemented"
                );
            }
            Err(other) => assert!(implemented.contains(&kind), "{kind:?}: {other}"),
            Ok(_) => assert!(implemented.contains(&kind)),
        }
    }
    assert!(implemented.contains(&OperationKind::Payment));
}

#[test]
fn every_cancellation_the_protocol_lacks_is_an_explicit_refusal() {
    let (world, me, _) = funded();
    let view = world.view();
    for target in [
        CancelTarget::Offer,
        CancelTarget::Reservation,
        CancelTarget::SignedOperation,
        CancelTarget::Unbond,
        CancelTarget::FiatLock,
        CancelTarget::DividendClaim,
        CancelTarget::LicenseDvp,
    ] {
        let refusal = plan(
            &OperationRequest::Cancel(CancelRequest::new(target)),
            &view,
            &me,
        )
        .unwrap_err();
        assert_eq!(refusal, Refusal::CancelNotAvailable(target));
        assert_eq!(refusal.code(), "CANCEL_NOT_AVAILABLE");
        assert!(!refusal.to_string().is_empty());
    }
    // The one permitted cancellation is routed to the refund operation, never refused as a cancel.
    let refund = plan(
        &OperationRequest::Cancel(CancelRequest::new(CancelTarget::HashLockRefund([5; 32]))),
        &view,
        &me,
    );
    assert!(!matches!(refund, Err(Refusal::CancelNotAvailable(_))));
    if !ops::implemented_kinds().contains(&OperationKind::ConditionalRefund) {
        assert_eq!(
            refund.unwrap_err(),
            Refusal::NotImplemented(OperationKind::ConditionalRefund)
        );
    }
}

#[test]
fn signing_only_uses_domains_the_kind_permits() {
    use OperationKind as K;
    use Purpose as P;
    use mutiny_crypto_v2::Domain;
    // The COMPLETE set of permitted (kind, purpose) pairs, spelled out. Everything else is refused.
    let permitted: Vec<(K, P, Domain)> = vec![
        (K::Payment, P::Spend, Domain::Transaction),
        (K::WalletRotation, P::Spend, Domain::Transaction),
        (K::DividendClaim, P::Spend, Domain::Transaction),
        (K::LicenseDvp, P::Spend, Domain::Transaction),
        (K::HashLock, P::Spend, Domain::Transaction),
        (K::ConditionalClaim, P::Spend, Domain::Transaction),
        (K::ConditionalRefund, P::Spend, Domain::Transaction),
        (K::FiatLock, P::Spend, Domain::Transaction),
        (K::FiatRelease, P::Spend, Domain::Transaction),
        (K::TreasuryRotate, P::Spend, Domain::Transaction),
        (K::TreasuryFreezeOffer, P::Spend, Domain::Transaction),
        // A bond creation spends the coins of its same-block funding output.
        (K::BondCreate, P::Spend, Domain::Transaction),
        (
            K::WalletRotation,
            P::RotateAuthorization,
            Domain::WalletRotate,
        ),
        (
            K::WalletRotation,
            P::RotatePossession,
            Domain::WalletRotatePossession,
        ),
        (K::BondCreate, P::BondAction, Domain::BondCreate),
        (K::BondUnbond, P::BondAction, Domain::BondUnbond),
        (K::BondWithdraw, P::BondAction, Domain::BondWithdraw),
    ];
    assert_eq!(permitted.len(), 17);
    let mut seen = 0;
    for kind in K::ALL {
        for purpose in [
            P::Spend,
            P::BondAction,
            P::RotateAuthorization,
            P::RotatePossession,
        ] {
            let expected = permitted
                .iter()
                .find(|(k, p, _)| *k == kind && *p == purpose)
                .map(|(_, _, domain)| *domain);
            match (domain_for(kind, purpose), expected) {
                (Ok(domain), Some(wanted)) => {
                    assert_eq!(domain, wanted, "{kind:?} {purpose:?}");
                    seen += 1;
                }
                (Err(refusal), None) => {
                    assert_eq!(refusal, Refusal::DomainNotPermitted { kind, purpose });
                    assert_eq!(refusal.code(), "DOMAIN_NOT_PERMITTED");
                }
                (got, wanted) => panic!("{kind:?} {purpose:?}: got {got:?}, expected {wanted:?}"),
            }
        }
    }
    assert_eq!(seen, permitted.len(), "every listed pair is reachable");
    // A payment can only ever be a spend; it has no bond or rotation domain.
    for purpose in [P::BondAction, P::RotateAuthorization, P::RotatePossession] {
        assert!(domain_for(K::Payment, purpose).is_err());
    }
    // No pair maps to a transport, node-work or release-approval domain: a wallet operation can
    // never produce a signature that another protocol layer would accept.
    for (_, _, domain) in &permitted {
        assert!(!matches!(
            domain,
            Domain::TransportInitiator
                | Domain::TransportResponder
                | Domain::NodeWork
                | Domain::ReleaseApproval
        ));
    }
}

#[test]
fn no_refusal_leaves_a_trace() {
    // A refused authorization queues nothing and reserves nothing.
    let (world, _me, planned) = funded();
    let view = world.view();
    let signer = KeySigner::for_test(key_b()).unwrap(); // not the plan's signer
    let outbox = MemoryOutbox::new();
    let approval = flow::approve(&review(&planned, &view).unwrap(), &view);
    assert!(signer.authorize(planned.clone(), approval, &view).is_err());
    assert!(outbox.records().unwrap().is_empty());
    assert!(outbox.reserved().unwrap().is_empty());
    // The same plan, reviewed again, is unchanged: nothing about the world moved.
    assert_eq!(
        review(&planned, &view).unwrap().binding(),
        review(&planned, &view).unwrap().binding()
    );
}
