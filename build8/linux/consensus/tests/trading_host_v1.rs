// Public synthetic admission/certification setup reused verbatim from the
// promoted wallet host qualification, with the assembler supplied by this test.
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    anchors::FinalizedAnchor,
    block_envelope_v2::BlockEnvelope,
    canonical_store_v2::{CanonicalStore, Preparation},
    certificates::Decision,
    continuity_v2::{Certificate, Vote},
    execution::State,
    hybrid_transaction_v2::Transaction,
    mempool_v2::Mempool,
    op_envelope_v1::Envelope,
    pow::{WorkAuthority, WorkHeader},
    trading_v1::*,
    transactions::{Coin, OutPoint, Output},
    transactions_v2::{Input, Transfer},
    work_authority_v2::Authority,
};
use mutiny_crypto_v2::{HybridKey, HybridSignature, Role};
#[path = "../../desktop/src/wallet_host_fixture_licenses.rs"]
mod licenses;
#[path = "support/wallet_host_fixture_tpm.rs"]
mod tpm;
fn empty() -> HybridSignature {
    HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    }
}

/// Body version 2: the signed window [1, 10] with the trusted Genesis block as its finalized
/// reference (the parent of the first block).
fn genesis_envelope(f: &Fixture) -> Envelope {
    Envelope {
        first_height: 1,
        last_height: 10,
        reference_height: 0,
        reference_block: f.genesis.block,
        preconditions: vec![],
    }
}
fn trade(
    f: &Fixture,
    sender: &HybridKey,
    recipient: &HybridKey,
    input: OutPoint,
) -> NativeOperation {
    let context = Context {
        network: NETWORK_ID,
        genesis: f.genesis.genesis,
        fingerprint: f.genesis.fingerprint,
    };
    // P7 (WP-T4, AM-6): the maker is the sender (slot 0) and signs with its wallet owner key.
    let maker: &HybridKey = sender;
    let offer = SignedOffer::sign(
        OfferBody {
            context: context.clone(),
            maker_descriptor: maker.public().descriptor(1).unwrap(),
            maker_wallet: sender.public().address_id(1).unwrap(),
            destination: sender.public().address_id(1).unwrap(),
            condition: Some(preimage_hash(&[42; 32])),
            max_fee: Strikes(20_000),
            nonce: [31; 32],
            created: 1,
            expiry: 10,
            maker_side: 0,
            terms: OfferTerms::HashLinked {
                amount: Strikes(50_000),
                bitcoin_satoshis: 10000,
                bitcoin_network: 3,
            },
        },
        &maker,
    )
    .unwrap();
    let mut operation = Operation {
        meta: Meta {
            context,
            trade: [21; 32],
            contract: [22; 32],
            generation: 1,
            envelope: genesis_envelope(f),
            fee: Strikes(20_000),
            inputs: vec![native_input_id(&input)],
        },
        action: Action::HashLock {
            offer: offer.body.id().unwrap(),
            maker: offer.body.maker().unwrap(),
            sender: sender.public().address_id(1).unwrap(),
            recipient: recipient.public().address_id(1).unwrap(),
            amount: Strikes(50_000),
            condition: preimage_hash(&[42; 32]),
            refund_height: 20,
            change: Strikes(30_000),
        },
        approvals: vec![],
        offer_proof: None,
    };
    operation.offer_proof = Some(OfferProof::sign(offer, &operation, &maker).unwrap());
    operation.approve(0, sender, 1).unwrap();
    operation.approve(1, recipient, 1).unwrap();
    NativeOperation {
        operation,
        inputs: vec![input],
    }
}

#[test]
fn complete_candidate_fee_conservation_atomic_commit_proof_and_reopen() {
    let mut f = fixture();
    let sender =
        HybridKey::wallet_restore(&("abandon ".repeat(23) + "art"), Role::WalletOwner).unwrap();
    let receiver =
        HybridKey::wallet_restore(&("zoo ".repeat(23) + "vote"), Role::WalletOwner).unwrap();
    f.state
        .wallets
        .register(&receiver.public().descriptor(1).unwrap())
        .unwrap();
    let input = OutPoint {
        transaction: [170; 32],
        index: 0,
    };
    let payment_input = OutPoint {
        transaction: [171; 32],
        index: 0,
    };
    f.state.coins.clear();
    for (point, atoms) in [(input.clone(), 100_000), (payment_input.clone(), 50_000)] {
        f.state.coins.insert(
            point,
            Coin {
                output: Output {
                    owner: sender.public().address_id(1).unwrap(),
                    atoms,
                },
                created_height: 0,
                coinbase: false,
            },
        );
    }
    let operation = trade(&f, &sender, &receiver, input.clone());
    let raw = operation.encode().unwrap();
    let parent_root = f.state.root().unwrap();
    let mut nonce = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let base = std::env::temp_dir().join(format!("build8-trading-host-{}", hex::encode(nonce)));
    std::fs::create_dir(&base).unwrap();
    let mut chain = CanonicalStore::open_trusted_genesis(
        &base.join("chain.sqlite"),
        &f.genesis,
        &f.state,
        parent_root,
        1000,
        [255; 32],
    )
    .unwrap();
    let mut pool = Mempool::open(
        &base.join("pool.sqlite"),
        f.genesis.genesis,
        f.genesis.fingerprint,
        64 * 1024 * 1024,
    )
    .unwrap();
    chain.reconcile_pool(&mut pool).unwrap();
    let payment = |point: OutPoint, atoms| {
        let mut transfer = Transfer {
            network: NETWORK_ID,
            genesis: f.genesis.genesis,
            fingerprint: f.genesis.fingerprint,
            created_height: 1,
            expiry_height: 10,
            fee: 5000,
            inputs: vec![Input::unsigned(point, sender.public(), 1).unwrap()],
            outputs: vec![Output {
                owner: receiver.public().address_id(1).unwrap(),
                atoms,
            }],
        };
        transfer.sign_input(0, &sender).unwrap();
        Transaction::Transfer(transfer)
    };
    let normal = payment(payment_input, 45_000);
    let conflict = payment(input.clone(), 95_000);
    pool.admit(&normal, &f.genesis, &f.state).unwrap();
    pool.admit(&conflict, &f.genesis, &f.state).unwrap();
    let operations = [raw.clone()];
    let selection = || Preparation {
        expected_parent: &f.genesis,
        pool: &pool,
        license: f.license,
        worker: f.worker,
        timestamp: 1100,
        ticket: 1,
        operations: &operations,
    };
    let prepared = chain.prepare_pending(selection()).unwrap();
    assert_eq!(prepared.body.fees, 25_000);
    assert_eq!(prepared.body.transactions, vec![normal.encode().unwrap()]);
    assert!(!prepared.execution.state.coins.contains_key(&input));
    assert_eq!(chain.load().unwrap().0.height, 0);
    let locked_id = operation.operation.output_id(0).unwrap();
    let lock = locked(&prepared.execution.state, locked_id).unwrap();
    assert_eq!(lock.amount, Strikes(50_000));
    let coins: u64 = prepared
        .execution
        .state
        .coins
        .values()
        .map(|c| c.output.atoms)
        .sum();
    assert_eq!(coins + lock.amount.0, 150_000 + 100_000_000);
    let reward = prepared
        .execution
        .state
        .coins
        .values()
        .find(|c| c.coinbase)
        .unwrap();
    assert_eq!(reward.output.atoms, 100_025_000);
    assert_eq!(reward.output.owner, prepared.body.reward_owner);
    let (parent, _, _) = chain.execution_parent(0).unwrap();
    let mut wrong_body = prepared.body.clone();
    wrong_body.fees += 1;
    let mut wrong_candidate = prepared.candidate.clone();
    wrong_candidate.body_root = wrong_body.root().unwrap();
    assert!(matches!(
        f.state
            .prepare_candidate_v2(mutiny_consensus_v8::execution::CandidatePreparation {
                parent: &parent,
                candidate: &wrong_candidate,
                ticket_sequence: 1,
                body: &wrong_body,
            }),
        Err(mutiny_consensus_v8::execution::ExecutionError::WrongFees)
    ));
    let envelope = certify(prepared, &f);
    let mut bad = envelope.clone();
    bad.certificate.votes[0].signature.fndsa[0] ^= 1;
    assert!(chain.commit(&bad).is_err());
    assert_eq!(chain.load().unwrap().0.root, parent_root);
    assert!(chain.commit(&envelope).unwrap());
    assert!(!chain.commit(&envelope).unwrap());
    let (head, state) = chain.load().unwrap();
    assert_eq!(head.height, 1);
    assert!(reconcile(&state, &raw).unwrap().is_some());
    assert_eq!(
        chain.confirmed_height(normal.id().unwrap()).unwrap(),
        Some(1)
    );
    assert_eq!(
        chain.confirmed_height(conflict.id().unwrap()).unwrap(),
        None
    );
    let anchor = envelope.certificate.decision.anchor();
    let proof = chain
        .state_proof(&anchor, record_key(0, locked_id))
        .unwrap()
        .encode()
        .unwrap();
    assert_eq!(
        verify_lock_proof(&proof, &anchor, head.root, locked_id).unwrap(),
        lock
    );
    drop(chain);
    let reopened = CanonicalStore::open_trusted_genesis(
        &base.join("chain.sqlite"),
        &f.genesis,
        &f.state,
        parent_root,
        1000,
        [255; 32],
    )
    .unwrap();
    assert_eq!(reopened.load().unwrap().0, head);
    assert_eq!(
        reopened.load().unwrap().1.records().unwrap(),
        state.records().unwrap()
    );
    assert!(
        reconcile(&reopened.load().unwrap().1, &raw)
            .unwrap()
            .is_some()
    );
    drop(reopened);
    drop(pool);
    assert!(base.starts_with(std::env::temp_dir()));
    std::fs::remove_dir_all(base).unwrap();
    println!(
        "TRADING_HOST_CANONICAL_PASS trade_fee=20000 payment_fee=5000 reward=100025000 conflict_excluded=true proof=true restart=true synthetic_unit_alias=true production_enabled=false"
    );
}
struct Fixture {
    state: State,
    genesis: FinalizedAnchor,
    coordinator: HybridKey,
    continuity: HybridKey,
    license: Hash,
    worker: Hash,
    backup_license: Hash,
    backup_worker: Hash,
}
fn fixture() -> Fixture {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/hybrid-canonical-store-public-v1.json"
    ))
    .unwrap();
    assert_eq!(f["synthetic_only"], true);
    assert_eq!(f["production_authorized"], false);
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let records: Vec<_> = f["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
        .collect();
    let initial = State::from_records(&records, raw(&f["root"]).try_into().unwrap()).unwrap();
    let mut state = State {
        coins: initial.coins.clone(),
        wallets: initial.wallets.clone(),
        continuity: initial.continuity.clone(),
        ..Default::default()
    };
    let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
    let (owner, assignments, expected, licenses, coordinator) = licenses::fixtures();
    state
        .wallets
        .register(&owner.public().descriptor(1).unwrap())
        .unwrap();
    let continuity = HybridKey::generate(Role::Continuity).unwrap();
    let old_node = state.continuity.as_ref().unwrap().members[0].node;
    let mut binding = initial
        .membership_v2
        .get(old_node)
        .unwrap()
        .binding()
        .clone();
    binding.node_descriptor = coordinator.public().descriptor(1).unwrap();
    binding.admission.node =
        mutiny_consensus_v8::node_admission_v2::node_id(genesis.genesis, &binding.node_descriptor)
            .unwrap();
    binding.admission.continuity_descriptor = continuity.public().descriptor(1).unwrap();
    let ak = p256::ecdsa::SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
    let profile = tpm::profile(&ak);
    assert_eq!(binding.admission.profile, profile.encode().unwrap());
    binding.admission.prove_continuity(&continuity).unwrap();
    binding.admission.quote = tpm::quote(&ak, &profile, binding.admission.challenge().unwrap());
    binding.admission.authorize(&owner, 1).unwrap();
    binding.sign(&coordinator).unwrap();
    let policy = mutiny_consensus_v8::admission_v2::Policy {
        genesis: genesis.genesis,
        fingerprint: genesis.fingerprint,
        owner_descriptor: owner.public().descriptor(1).unwrap(),
        endorsement_roots: [binding.admission.endorsement_root].into_iter().collect(),
    };
    let admission_expected = mutiny_consensus_v8::admission_v2::Expected {
        node: binding.admission.node,
        hardware_generation: 1,
        key_generation: 1,
        supervised_nonce: binding.admission.supervised_nonce,
    };
    (state.membership_v2, state.continuity_keys_v2) =
        mutiny_consensus_v8::membership_v2::Book::genesis(
            &binding,
            &policy,
            &admission_expected,
            &state.wallets, mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest,
        )
        .unwrap();
    state.continuity.as_mut().unwrap().members[0].node = binding.admission.node;
    state.licenses_v2 = mutiny_consensus_v8::license_book_v2::Book::genesis(
        &assignments,
        &expected,
        &licenses,
        &state.wallets,
        genesis.genesis,
        genesis.fingerprint,
    )
    .unwrap();
    state.admission_policy_v2 =
        Some(mutiny_consensus_v8::admission_policy_v2::Record::new(policy).unwrap());
    state.wallets.records().expect("fixture wallets");
    state
        .continuity_keys_v2
        .records()
        .expect("fixture continuity keys");
    state
        .membership_v2
        .records(&state.continuity_keys_v2)
        .expect("fixture membership");
    state.licenses_v2.records().expect("fixture licenses");
    state
        .continuity
        .as_ref()
        .unwrap()
        .state_records()
        .expect("fixture continuity");
    let rows = state.records().expect("fixture records");
    State::from_records(&rows, state.root().unwrap()).expect("fixture restore");
    Fixture {
        state,
        genesis,
        coordinator,
        continuity,
        license: licenses[0].id,
        worker: expected[0].worker_id,
        backup_license: licenses[1].id,
        backup_worker: expected[1].worker_id,
    }
}

fn certify(prepared: mutiny_consensus_v8::assembler_v2::Prepared, f: &Fixture) -> BlockEnvelope {
    certify_at(prepared, f, &f.genesis, &f.state, 1)
}
fn certify_at(
    prepared: mutiny_consensus_v8::assembler_v2::Prepared,
    f: &Fixture,
    parent: &FinalizedAnchor,
    state: &State,
    ticket: u64,
) -> BlockEnvelope {
    let height = prepared.candidate.height;
    let epoch = mutiny_consensus_v8::pow::mining_epoch(prepared.candidate.timestamp, 1000).unwrap();
    let mut book = state.licenses_v2.clone();
    book.activate_due(epoch).unwrap();
    let assignment = book
        .active(prepared.candidate.license, prepared.candidate.worker, epoch)
        .unwrap()
        .0
        .assignment_sequence;
    let mut authority = Authority {
        work: WorkAuthority {
            candidate: prepared.candidate.clone(),
            assignment_sequence: assignment,
            ticket_sequence: ticket,
            coordinator: mutiny_consensus_v8::work_authority_v2::node_identity(
                &f.coordinator.public().descriptor(1).unwrap(),
            )
            .unwrap(),
            nonce_start: 0,
            nonce_end: 100,
            epoch,
        },
        node_descriptor: f.coordinator.public().descriptor(1).unwrap(),
        signature: empty(),
    };
    authority.sign(&f.coordinator).unwrap();
    let header = WorkHeader {
        candidate: prepared.candidate,
        authority: authority.id().unwrap(),
        nonce: 1,
    };
    assert!(mutiny_consensus_v8::pow::meets_target(
        &header.block_hash(),
        &[255; 32]
    ));
    let height_authority = mutiny_consensus_v8::votes_v2::HeightAuthority::from_state(
        state,
        parent.clone(),
        state.root().unwrap(),
    )
    .unwrap();
    let (node, voter) = height_authority.voters.iter().next().unwrap();
    let decision = Decision {
        network: f.genesis.network,
        genesis: f.genesis.genesis,
        fingerprint: f.genesis.fingerprint,
        purpose: 2,
        height,
        mining_epoch: epoch,
        continuity_period: (height - 1) / 60,
        round: 0,
        step: 3,
        previous_finalized_anchor: parent.id(),
        parent: parent.block,
        block: header.block_hash(),
        state: prepared.execution.root,
        membership: height_authority.membership,
        reputation: height_authority.reputation,
        attestation: height_authority.attestation,
    };
    let mut vote = Vote {
        decision: decision.clone(),
        nil: false,
        node: *node,
        hardware_generation: voter.hardware_generation,
        key_generation: voter.key_generation,
        sequence: height * 10,
        tpm_identity: voter.tpm_identity(),
        profile: voter.profile,
        signature: empty(),
    };
    vote.sign(&f.continuity).unwrap();
    BlockEnvelope {
        header,
        body: prepared.body,
        authority,
        certificate: Certificate {
            decision,
            votes: vec![vote],
        },
    }
}

#[test]
fn license_dvp_canonical_restart_parent_reward_detachment_and_new_epoch_worker() {
    use mutiny_consensus_v8::license_assignment_v2::Assignment;
    use mutiny_crypto_v2::enrollment::owner_descriptor_id;
    let mut f = fixture();
    let seller =
        HybridKey::wallet_restore(&("abandon ".repeat(23) + "art"), Role::WalletOwner).unwrap();
    let buyer =
        HybridKey::wallet_restore(&("zoo ".repeat(23) + "vote"), Role::WalletOwner).unwrap();
    let seller_id = seller.public().address_id(1).unwrap();
    let buyer_id = buyer.public().address_id(1).unwrap();
    f.state
        .wallets
        .register(&buyer.public().descriptor(1).unwrap())
        .unwrap();
    let input = OutPoint {
        transaction: [173; 32],
        index: 0,
    };
    f.state.coins.clear();
    f.state.coins.insert(
        input.clone(),
        Coin {
            output: Output {
                owner: buyer_id,
                atoms: 100_000,
            },
            created_height: 0,
            coinbase: false,
        },
    );
    let context = Context {
        network: NETWORK_ID,
        genesis: f.genesis.genesis,
        fingerprint: f.genesis.fingerprint,
    };
    // P7 (WP-T4, AM-6): the maker is the seller (slot 0) and signs with its wallet owner key.
    let maker: &HybridKey = &seller;
    let offer = SignedOffer::sign(
        OfferBody {
            context: context.clone(),
            maker_descriptor: maker.public().descriptor(1).unwrap(),
            maker_wallet: seller_id,
            destination: seller_id,
            condition: None,
            max_fee: Strikes(20_000),
            nonce: [175; 32],
            created: 1,
            expiry: 10,
            maker_side: 0,
            terms: OfferTerms::License {
                license: f.license,
                generation: 1,
                price: Strikes(50_000),
            },
        },
        &maker,
    )
    .unwrap();
    let mut operation = Operation {
        meta: Meta {
            context,
            trade: [176; 32],
            contract: [177; 32],
            generation: 1,
            envelope: genesis_envelope(&f),
            fee: Strikes(20_000),
            inputs: vec![native_input_id(&input)],
        },
        action: Action::LicenseDvp {
            offer: offer.body.id().unwrap(),
            maker: offer.body.maker().unwrap(),
            license: f.license,
            license_generation: 1,
            seller: seller_id,
            buyer: buyer_id,
            price: Strikes(50_000),
            payment_destination: seller_id,
            change: Strikes(30_000),
        },
        approvals: vec![],
        offer_proof: None,
    };
    // WP-T2 (design 6.1): the sale commits the License facts it was reviewed against.
    operation.meta.envelope.preconditions = vec![
        mutiny_consensus_v8::op_envelope_v1::entitlement_facts(&f.state, f.license),
        mutiny_consensus_v8::op_envelope_v1::assignment_facts(&f.state, f.license).unwrap(),
    ];
    operation.offer_proof = Some(OfferProof::sign(offer, &operation, &maker).unwrap());
    operation.approve(0, &seller, 1).unwrap();
    operation.approve(1, &buyer, 1).unwrap();
    let native = NativeOperation {
        operation,
        inputs: vec![input],
    };
    let trade = native.encode().unwrap();
    let original_assignment = f
        .state
        .licenses_v2
        .active(f.license, f.worker, 1)
        .unwrap()
        .1
        .assignment
        .clone();
    let assignment = |owner: &HybridKey| -> Assignment {
        let mut b = original_assignment.enrollment.binding.clone();
        b.owner_descriptor = owner_descriptor_id(owner.public(), 1).unwrap();
        b.owner_generation = 1;
        b.worker_public = licenses::worker(29);
        b.assignment_generation = 3;
        b.configuration_generation = 2;
        b.device_mac = [2, 0, 0, 0, 0, 29];
        b.effective_epoch = 2;
        b.valid_until_height = 100;
        b.worker_id = b.derived_worker_id();
        licenses::sign(b, owner, &f.coordinator.public().descriptor(1).unwrap(), 29)
    };
    let rebound = assignment(&buyer);
    let new_worker = rebound.enrollment.binding.worker_id;
    let root = f.state.root().unwrap();
    let mut opaque_genesis = f.state.clone();
    opaque_genesis
        .protocol_records
        .insert(record_key(4, f.license), vec![0xf6]);
    assert!(
        opaque_genesis.records().is_err(),
        "known transfer key cannot hide opaque data even before detachment"
    );
    let mut nonce = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let base = std::env::temp_dir().join(format!("build8-license-host-{}", hex::encode(nonce)));
    std::fs::create_dir(&base).unwrap();
    let open = || {
        CanonicalStore::open_trusted_genesis(
            &base.join("chain.sqlite"),
            &f.genesis,
            &f.state,
            root,
            1000,
            [255; 32],
        )
        .unwrap()
    };
    let mut chain = open();
    let mut pool = Mempool::open(
        &base.join("pool.sqlite"),
        f.genesis.genesis,
        f.genesis.fingerprint,
        64 * 1024 * 1024,
    )
    .unwrap();
    chain.reconcile_pool(&mut pool).unwrap();
    // A same-block new owner cannot borrow ownership from the pending transfer.
    let same_block_assignment = |owner: &HybridKey| {
        let mut binding = assignment(owner).enrollment.binding;
        binding.assignment_generation = 2;
        binding.worker_id = binding.derived_worker_id();
        licenses::sign(
            binding,
            owner,
            &f.coordinator.public().descriptor(1).unwrap(),
            29,
        )
    };
    let combined = [
        trade.clone(),
        same_block_assignment(&buyer).encode().unwrap(),
    ];
    assert!(
        chain
            .prepare_pending(Preparation {
                expected_parent: &f.genesis,
                pool: &pool,
                license: f.license,
                worker: f.worker,
                timestamp: 1100,
                ticket: 1,
                operations: &combined
            })
            .is_err()
    );
    let pending_conflict = [
        trade.clone(),
        same_block_assignment(&seller).encode().unwrap(),
    ];
    assert!(
        chain
            .prepare_pending(Preparation {
                expected_parent: &f.genesis,
                pool: &pool,
                license: f.license,
                worker: f.worker,
                timestamp: 1100,
                ticket: 1,
                operations: &pending_conflict
            })
            .is_err()
    );
    assert!(
        chain.load().unwrap().1.records().unwrap() == f.state.records().unwrap(),
        "failed proposal preserves exact canonical state"
    );
    let trades = [trade.clone()];
    let prepared = chain
        .prepare_pending(Preparation {
            expected_parent: &f.genesis,
            pool: &pool,
            license: f.license,
            worker: f.worker,
            timestamp: 1100,
            ticket: 1,
            operations: &trades,
        })
        .unwrap();
    assert_eq!(
        prepared.body.reward_owner, seller_id,
        "inclusion H uses parent ownership"
    );
    assert_eq!(prepared.body.fees, 20_000);
    assert_eq!(
        prepared
            .execution
            .state
            .coins
            .values()
            .filter(|c| c.coinbase)
            .map(|c| c.output.atoms)
            .sum::<u64>(),
        100_020_000
    );
    let first = certify(prepared, &f);
    let mut forged = first.clone();
    forged.certificate.votes[0].signature.ed448[0] ^= 1;
    assert!(chain.commit(&forged).is_err());
    assert_eq!(chain.load().unwrap().0.height, 0);
    assert!(chain.commit(&first).unwrap());
    assert!(!chain.commit(&first).unwrap());
    let anchor1 = first.certificate.decision.anchor();
    let (_, state1) = chain.load().unwrap();
    let l = state1.licenses_v2.license(f.license).unwrap();
    assert_eq!(
        (l.owner, l.active_worker, l.assignment_sequence),
        (buyer_id, None, 2)
    );
    assert!(state1.licenses_v2.active(f.license, f.worker, 1).is_err());
    let (_, transfer_record) =
        NativeRecord::decode(&state1.protocol_records[&record_key(4, f.license)]).unwrap();
    assert!(matches!(
        transfer_record,
        NativeRecord::License {
            generation: 2,
            inclusion_height: 1,
            rights_from_height: 2,
            assignment_sequence: 2,
            ..
        }
    ));
    assert_eq!(
        state1.coins[&OutPoint {
            transaction: native.operation.id().unwrap(),
            index: 0
        }]
            .output,
        Output {
            owner: seller_id,
            atoms: 50_000
        }
    );
    let historic_key =
        mutiny_consensus_v8::domain_hash(b"MUTINY-BUILD8-WORKER-STATE-KEY-V2", &f.worker);
    let historic = state1.licenses_v2.records().unwrap()[&historic_key].clone();
    let mut d = minicbor::Decoder::new(&historic);
    assert_eq!(d.array().unwrap(), Some(4));
    assert_eq!(d.u8().unwrap(), 2);
    assert_eq!(d.u8().unwrap(), 41);
    assert_eq!(
        Assignment::decode(d.bytes().unwrap()).unwrap(),
        original_assignment
    );
    assert_eq!(
        d.u64().unwrap(),
        1,
        "transfer retains inclusion ticket high-water mark"
    );
    let mut orphan = state1.clone();
    orphan.protocol_records.clear();
    assert!(
        orphan.records().is_err(),
        "empty protocol map cannot hide detached Worker authority"
    );
    let mut opaque_transfer = state1.clone();
    opaque_transfer
        .protocol_records
        .insert(record_key(4, f.license), vec![0xf6]);
    let rows: Vec<_> = state1
        .records()
        .unwrap()
        .into_iter()
        .filter(|(_, r)| !is_candidate_record(r))
        .collect();
    assert!(
        State::from_records(
            &rows,
            mutiny_consensus_v8::blocks::state_root(&rows).unwrap()
        )
        .is_err()
    );
    drop(chain);
    chain = open();
    assert_eq!(
        chain.load().unwrap().1.records().unwrap(),
        state1.records().unwrap()
    );
    chain.reconcile_pool(&mut pool).unwrap();
    assert!(
        chain
            .prepare_pending(Preparation {
                expected_parent: &anchor1,
                pool: &pool,
                license: f.license,
                worker: f.worker,
                timestamp: 1101,
                ticket: 2,
                operations: &[]
            })
            .is_err()
    );
    let stale = [assignment(&seller).encode().unwrap()];
    assert!(
        chain
            .prepare_pending(Preparation {
                expected_parent: &anchor1,
                pool: &pool,
                license: f.backup_license,
                worker: f.backup_worker,
                timestamp: 1101,
                ticket: 1,
                operations: &stale
            })
            .is_err()
    );
    let binding = [rebound.encode().unwrap()];
    let second = chain
        .prepare_pending(Preparation {
            expected_parent: &anchor1,
            pool: &pool,
            license: f.backup_license,
            worker: f.backup_worker,
            timestamp: 1101,
            ticket: 1,
            operations: &binding,
        })
        .unwrap();
    let second = certify_at(second, &f, &anchor1, &state1, 1);
    assert!(chain.commit(&second).unwrap());
    let anchor2 = second.certificate.decision.anchor();
    let (_, state2) = chain.load().unwrap();
    assert_eq!(
        state2.licenses_v2.license(f.license).unwrap().active_worker,
        None
    );
    chain.reconcile_pool(&mut pool).unwrap();
    assert!(
        chain
            .prepare_pending(Preparation {
                expected_parent: &anchor2,
                pool: &pool,
                license: f.license,
                worker: new_worker,
                timestamp: 1110,
                ticket: 1,
                operations: &[]
            })
            .is_err()
    );
    let third = chain
        .prepare_pending(Preparation {
            expected_parent: &anchor2,
            pool: &pool,
            license: f.license,
            worker: new_worker,
            timestamp: 1120,
            ticket: 1,
            operations: &[],
        })
        .unwrap();
    assert_eq!(third.body.reward_owner, buyer_id);
    let third = certify_at(third, &f, &anchor2, &state2, 1);
    assert!(chain.commit(&third).unwrap());
    let (head3, state3) = chain.load().unwrap();
    let (l, w) = state3.licenses_v2.active(f.license, new_worker, 2).unwrap();
    assert_eq!(
        (l.owner, l.assignment_sequence, w.last_accepted_ticket),
        (buyer_id, 3, 1)
    );
    assert!(state3.licenses_v2.active(f.license, f.worker, 2).is_err());
    assert_eq!(
        state3.licenses_v2.records().unwrap()[&historic_key],
        historic
    );
    assert!(state3.coins.values().any(|c| c.coinbase
        && c.created_height == 3
        && c.output.owner == buyer_id
        && c.output.atoms == 100_000_000));
    drop(chain);
    let reopened = open();
    assert_eq!(reopened.load().unwrap().0, head3);
    assert_eq!(
        reopened.load().unwrap().1.records().unwrap(),
        state3.records().unwrap()
    );
    assert!(
        opaque_transfer.records().is_err(),
        "opaque value at transfer key cannot authorize detachment while other valid records remain"
    );
    drop(reopened);
    drop(pool);
    assert!(base.starts_with(std::env::temp_dir()));
    std::fs::remove_dir_all(base).unwrap();
    println!(
        "TRADING_HOST_LICENSE_PASS canonical_heights=3 restart=true H_reward=previous_owner rights_from_H_plus_1=true stale_worker_rejected=true new_owner_epoch_binding=true historic_ticket_preserved=true orphan_detachment_rejected=true production_enabled=false"
    );
}
