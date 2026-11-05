//! Final candidate-3 wallet carriers. Public TEST-VALUE keys; no custody or production access.
#[path = "support/flow.rs"]
mod flow;
#[path = "support/synthetic.rs"]
mod synthetic;
use mutiny_consensus_v8::{
    anchors::FinalizedAnchor,
    bond_create_v3::FundedBondCreate,
    evidence_history_v2::History,
    execution::State,
    funded_rotation_v2::PartialRotation,
    hybrid_transaction_v2::Inclusion,
    trading_offer_v2::{MakerOffer, OfferBody, OfferTerms},
    trading_v1::Strikes,
};
use mutiny_wallet_core_v8::*;
use synthetic::{World, address, descriptor, identity, key_a, key_b, key_c};

fn fixture() -> World {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/hybrid-canonical-store-public-v1.json"
    ))
    .unwrap();
    assert_eq!(f["synthetic_only"], true);
    assert_eq!(f["production_authorized"], false);
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let records = f["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
        .collect::<Vec<_>>();
    let state = State::from_records(&records, raw(&f["root"]).try_into().unwrap()).unwrap();
    let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
    let mut world = World::new(100);
    world.state = state;
    world.anchor.genesis = genesis.genesis;
    world.anchor.fingerprint = genesis.fingerprint;
    world.state.coins.clear();
    world
}

#[test]
fn atomic_bond_has_two_bound_signatures_and_retained_reference_window() {
    let mut w = fixture();
    let me = identity(&key_a());
    let info = discovery::bonds::nodes_controlled_by(&w.state, me.descriptor())
        .into_iter()
        .next()
        .unwrap();
    let request = BondCreateRequest::new(
        info.node,
        info.generation,
        mutiny_consensus_v8::bonds::MINIMUM_ATOMS,
        [17; 32],
    )
    .with_validity_blocks(8);
    let coin = w.coin(
        me.address(),
        request.amount_atoms + 100_000,
        0,
        false,
        11,
        0,
    );
    let plan = plan(&OperationRequest::BondCreate(request), &w.view(), &me).unwrap();
    assert!(plan.inputs().contains(&coin));
    assert_eq!(plan.inputs().len(), 2, "one coin and one lot reservation");
    assert_eq!(plan.validity().created, 101);
    assert_eq!(plan.validity().expiry, 109);
    assert!(!plan.validity().bound_to_parent);
    let signed = flow::sign(plan, &KeySigner::for_test(key_a()).unwrap(), &w.view()).unwrap();
    let body = FundedBondCreate::decode(signed.bytes()).unwrap();
    assert_eq!(signed.id(), body.unsigned.id().unwrap());
    assert_eq!(
        body.unsigned.fee,
        body.unsigned.signed_len().unwrap() as u64
    );
    body.verify(&w.state, &w.anchor, &History::default())
        .unwrap();
    let mut changed = body.clone();
    changed.unsigned.nonce[0] ^= 1;
    assert!(
        changed.verify_signatures().is_err(),
        "both signatures bind exact unsigned body"
    );
    let next = w.advanced();
    assert!(
        body.verify(&next.state, &next.anchor, &History::default())
            .is_err(),
        "unproved old reference fails closed"
    );
    let mut history = History::default();
    history
        .insert_anchor(w.anchor.height, w.anchor.block)
        .unwrap();
    body.verify(&next.state, &next.anchor, &history).unwrap();
    let mut expired = next.anchor.clone();
    expired.height = 109;
    assert!(body.verify(&next.state, &expired, &history).is_err());
}

#[test]
fn funded_rotation_sponsor_approves_same_atomic_body_and_cannot_redirect_change() {
    let mut w = World::new(100);
    let me = identity(&key_a());
    let sponsor = identity(&key_b());
    w.coin(sponsor.address(), 100_000, 0, false, 20, 0);
    let proposed = descriptor(&key_c(), 2);
    let fingerprint = ops::rotation::descriptor_fingerprint(&proposed);
    let request =
        RotationRequest::new(Blob::new(proposed), FeeSource::OtherWallet(sponsor.clone()))
            .with_restore_verified(fingerprint)
            .with_validity_blocks(8);
    let p = plan(&OperationRequest::WalletRotation(request), &w.view(), &me).unwrap();
    let signer = ops::rotation::RotationSigner::for_test(key_a(), me.clone(), key_c()).unwrap();
    let approval = flow::approve(&review(&p, &w.view()).unwrap(), &w.view());
    let first = signer.authorize(p, approval, &w.view()).unwrap();
    assert!(!first.is_complete());
    assert!(
        PartialRotation::decode(first.bytes())
            .unwrap()
            .sponsor_funding
            .is_none()
    );
    let sponsor_plan = adopt(first.bytes(), &w.view(), &sponsor).unwrap();
    let sponsor_part = flow::sign(
        sponsor_plan,
        &KeySigner::for_test(key_b()).unwrap(),
        &w.view(),
    )
    .unwrap();
    assert!(
        sponsor_part.is_complete(),
        "adoption preserves the verified authority proofs and adds the sponsor approval"
    );
    let complete =
        ops::rotation::combine(&[first.bytes(), sponsor_part.bytes()], &w.view()).unwrap();
    assert!(complete.is_complete());
    let final_body =
        mutiny_consensus_v8::funded_rotation_v2::FundedRotation::decode(complete.bytes()).unwrap();
    assert!(
        mutiny_consensus_v8::hybrid_transaction_v2::Transaction::decode(complete.bytes()).is_ok()
    );
    final_body
        .verify(
            &Inclusion {
                parent: &w.anchor,
                history: &History::default(),
            },
            &w.state,
        )
        .unwrap();
    assert_eq!(complete.id(), final_body.unsigned.id().unwrap());
    use mutiny_wallet_core_v8::outbox::{MemoryOutbox, Outbox};
    let mut queue = MemoryOutbox::new();
    let partial_id = queue.commit(&first, &w.view()).unwrap();
    let before = queue.records().unwrap();
    assert_eq!(
        mutiny_wallet_core_v8::outbox::admit_replacement_record(&before[0], &first, &w.view())
            .unwrap_err(),
        Refusal::OutboxIntegrity,
        "an incomplete object cannot complete an open partial"
    );
    assert_eq!(
        queue
            .replace_partial(&partial_id, &first, &w.view())
            .unwrap(),
        partial_id,
        "exact same open bytes remain an idempotent submission"
    );
    assert_eq!(
        queue.records().unwrap(),
        before,
        "an incomplete exchange preserves the original partial and reservations"
    );
    let complete_id = queue
        .replace_partial(&partial_id, &complete, &w.view())
        .unwrap();
    assert_eq!(complete_id, complete.id());
    assert_eq!(
        queue.get(&complete_id).unwrap().unwrap().bytes,
        complete.bytes()
    );
    assert!(
        queue
            .get(&partial_id)
            .unwrap()
            .is_none_or(|record| !record.status.is_open())
    );
    assert_eq!(
        queue
            .replace_partial(&partial_id, &complete, &w.view())
            .unwrap(),
        complete_id,
        "completion retry is idempotent"
    );

    let mut tampered = PartialRotation::decode(first.bytes()).unwrap();
    tampered.unsigned.outputs[0].owner = [99; 32];
    assert!(adopt(&tampered.encode().unwrap(), &w.view(), &sponsor).is_err());
}

#[test]
fn maker_offer_authorization_binds_current_wallet_exact_terms_and_window() {
    let mut w = World::with_wallets(100);
    let me = identity(&key_a());
    let body = OfferBody {
        context: mutiny_consensus_v8::trading_v1::Context {
            network: w.anchor.network,
            genesis: w.anchor.genesis,
            fingerprint: w.anchor.fingerprint,
        },
        maker_descriptor: me.descriptor().to_vec(),
        maker_wallet: me.address(),
        maker_side: 0,
        nonce: [21; 32],
        created: 101,
        expiry: 109,
        terms: OfferTerms::HashLinked {
            amount: Strikes(50_000),
            bitcoin_satoshis: 17,
            bitcoin_network: 1,
        },
        destination: me.address(),
        condition: Some([23; 32]),
        max_fee: Strikes(10_000),
    };
    let p = plan(
        &OperationRequest::MakerOffer(MakerOfferRequest::new(Blob::new(body.encode().unwrap()))),
        &w.view(),
        &me,
    )
    .unwrap();
    assert!(
        p.inputs().is_empty(),
        "above-consensus offer does not reserve chain funds"
    );
    let signed = flow::sign(p, &KeySigner::for_test(key_a()).unwrap(), &w.view()).unwrap();
    let offer = MakerOffer::decode(signed.bytes()).unwrap();
    offer.verify().unwrap();
    assert_eq!(offer.body, body);
    let mut changed = offer.clone();
    changed.body.destination = address(&key_b(), 1);
    assert!(changed.verify().is_err());
    let mut other = body;
    other.maker_wallet = address(&key_b(), 1);
    assert!(
        plan(
            &OperationRequest::MakerOffer(MakerOfferRequest::new(Blob::new(
                other.encode().unwrap()
            ))),
            &w.view(),
            &me
        )
        .is_err()
    );

    // A newly reviewed offer may name the immutable settlement authority A after
    // rotation, but must carry its current D2 descriptor and a new D2 signature.
    let phrase =
        mutiny_crypto_v2::rehearsal_keys_v1::label_phrase("w15-maker-current-after-rotation")
            .unwrap();
    let next =
        mutiny_crypto_v2::HybridKey::wallet_restore(&phrase, mutiny_crypto_v2::Role::WalletOwner)
            .unwrap();
    let mut rotation = mutiny_consensus_v8::wallet_rotation_v1::Rotation {
        network: w.anchor.network,
        genesis: w.anchor.genesis,
        fingerprint: w.anchor.fingerprint,
        authority: me.address(),
        current: me.descriptor().to_vec(),
        proposed: descriptor(&next, 2),
        created_height: 90,
        expiry_height: 120,
        authorization: mutiny_crypto_v2::HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
        possession: mutiny_crypto_v2::HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
    };
    rotation.sign(&key_a(), &next).unwrap();
    w.state
        .wallets
        .apply(&rotation, w.anchor.genesis, w.anchor.fingerprint, 95)
        .unwrap();
    let current = SignerIdentity::from_public(next.public(), 2, Some(me.address())).unwrap();
    assert_eq!(
        plan(
            &OperationRequest::MakerOffer(MakerOfferRequest::new(Blob::new(
                offer.body.encode().unwrap()
            ))),
            &w.view(),
            &me
        )
        .unwrap_err(),
        Refusal::StaleAuthority,
        "an old signed unfunded offer has no historical freeze exception"
    );
    let mut fresh = offer.body.clone();
    fresh.maker_descriptor = current.descriptor().to_vec();
    fresh.destination = current.address();
    fresh.nonce[0] ^= 1;
    let planned = plan(
        &OperationRequest::MakerOffer(MakerOfferRequest::new(Blob::new(fresh.encode().unwrap()))),
        &w.view(),
        &current,
    )
    .unwrap();
    let signer = KeySigner::with_identity(
        next,
        current,
        SigningGate::test_value().unwrap(),
        DEFAULT_IDLE_LIMIT,
    )
    .unwrap();
    let signed = flow::sign(planned, &signer, &w.view()).unwrap();
    let fresh_signed = MakerOffer::decode(signed.bytes()).unwrap();
    fresh_signed.verify().unwrap();
    assert_eq!(fresh_signed.body, fresh);
    w.state
        .wallets
        .authorize(
            fresh_signed.body.maker_wallet,
            &fresh_signed.body.maker_descriptor,
        )
        .unwrap();
    assert_ne!(fresh_signed.body.id().unwrap(), offer.body.id().unwrap());
}

#[path = "../../desktop/src/wallet_host_fixture_licenses.rs"]
mod assignment_fixtures;
#[test]
fn fresh_worker_assignment_requires_public_possession_current_owner_and_exact_one_epoch() {
    use mutiny_consensus_v8::license_assignment_v2::{Assignment, ParentContext};
    use mutiny_crypto_v2::enrollment::{Binding, owner_descriptor_id};
    let w = fixture();
    let me = identity(&key_a());
    let license = w
        .state
        .licenses_v2
        .licenses()
        .find(|l| w.state.wallets.authorize(l.owner, me.descriptor()).is_ok())
        .unwrap();
    let node = w.state.continuity.as_ref().unwrap().members[0].node;
    let node_descriptor = w
        .state
        .membership_v2
        .get(node)
        .unwrap()
        .binding()
        .node_descriptor
        .clone();
    let mut binding = Binding {
        genesis: w.anchor.genesis,
        fingerprint: w.anchor.fingerprint,
        license: license.id,
        owner_descriptor: owner_descriptor_id(&me.public(), me.generation()).unwrap(),
        owner_generation: me.generation(),
        worker_public: assignment_fixtures::worker(0x71),
        worker_id: [0; 32],
        coordinator: mutiny_consensus_v8::work_authority_v2::node_identity(&node_descriptor)
            .unwrap(),
        configuration_generation: 1,
        device_mac: [2, 0, 0, 0, 0, 0x71],
        assignment_generation: license.assignment_sequence + 1,
        effective_epoch: w.view().epoch().unwrap() + 1,
        valid_until_height: w.anchor.height + 8,
    };
    binding.worker_id = binding.derived_worker_id();
    let public = assignment_fixtures::sign(binding.clone(), &key_a(), &node_descriptor, 0x71);
    let request = |a: &Assignment| {
        OperationRequest::WorkerAssignment(WorkerAssignmentRequest::new(
            Blob::new(a.enrollment.binding.bytes().unwrap()),
            Blob::new(a.node_descriptor.clone()),
            Blob::new(a.enrollment.worker_signature.to_vec()),
        ))
    };
    let p = plan(&request(&public), &w.view(), &me).unwrap();
    let reviewed = review(&p, &w.view()).unwrap();
    assert!(reviewed.requires_phrase());
    assert!(reviewed.render_text().contains("One-epoch delivery"));
    assert_eq!(reviewed.net_debit(), Some(0));
    assert_eq!(reviewed.fee().atoms, 0);
    assert!(reviewed.acknowledgements().contains(&AckKind::Conditions));
    assert_eq!(
        reviewed
            .warnings()
            .iter()
            .any(|w| w.code == "TEST_VALUE_CHAIN"),
        w.view().class() == ChainClass::TestValue
    );
    let text = reviewed.render_text();
    for needle in [
        hex::encode(binding.genesis),
        hex::encode(binding.fingerprint),
        hex::encode(binding.owner_descriptor),
        hex::encode(binding.worker_public),
        hex::encode(binding.worker_id),
        hex::encode(binding.coordinator),
        hex::encode(binding.device_mac),
        "fresh against all own historical and pending assignments".into(),
    ] {
        assert!(
            text.contains(&needle),
            "missing reviewed public assignment term {needle}"
        );
    }
    let signed = flow::sign(p, &KeySigner::for_test(key_a()).unwrap(), &w.view()).unwrap();
    let native = Assignment::decode(signed.bytes()).unwrap();
    native
        .verify_next_epoch(&ParentContext {
            genesis: w.anchor.genesis,
            fingerprint: w.anchor.fingerprint,
            height: w.anchor.height + 1,
            epoch: w.view().epoch().unwrap(),
            license,
            wallets: &w.state.wallets,
        })
        .unwrap();
    assert_eq!(
        signed.id(),
        mutiny_consensus_v8::op_envelope_v1::assignment_id(&native).unwrap()
    );
    let mut damaged = public.clone();
    damaged.enrollment.worker_signature[0] ^= 1;
    assert!(matches!(
        plan(&request(&damaged), &w.view(), &me),
        Err(Refusal::VerificationFailed("Worker possession signature"))
    ));
    assert!(
        plan(&request(&public), &w.view(), &identity(&key_b())).is_err(),
        "another wallet never acquires the owner capability"
    );
    let mut stale_binding = binding.clone();
    stale_binding.assignment_generation += 1;
    let stale = assignment_fixtures::sign(stale_binding, &key_a(), &node_descriptor, 0x71);
    assert!(
        plan(&request(&stale), &w.view(), &me).is_err(),
        "valid possession does not bypass parent sequence"
    );
    let mut next = w.advanced();
    next.timestamp = w.timestamp + 60;
    assert!(
        plan(&request(&public), &next.view(), &me).is_err(),
        "old one-epoch proof is not extended"
    );
    let mut pending = w.advanced();
    pending
        .state
        .licenses_v2
        .schedule(
            native.clone(),
            w.anchor.genesis,
            w.anchor.fingerprint,
            w.anchor.height + 1,
            w.view().epoch().unwrap(),
            &w.state.wallets,
        )
        .unwrap();
    assert!(matches!(
        plan(&request(&public), &pending.view(), &me),
        Err(Refusal::InvalidRequest(
            "License already has a pending Worker assignment"
        ))
    ));
    let mut queue = MemoryOutbox::new();
    queue.commit(&signed, &w.view()).unwrap();
    assert!(
        queue
            .reserved()
            .unwrap()
            .contains(&resource_key("license", &license.id))
    );
    // Scheduling/ACK is not own canonical finality. The index-specific TCP test supplies that proof.
    assert_ne!(queue.reconcile(&pending.view()).unwrap().confirmed, 1);
}
