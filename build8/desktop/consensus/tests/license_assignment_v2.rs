use mutiny_consensus_v8::{
    NETWORK_ID,
    license_assignment_v2::{Assignment, ParentContext, verify_genesis_set},
    wallet_authority_v1::WalletBook,
};
use mutiny_crypto_v2::{
    HybridKey, Role,
    enrollment::{Binding, owner_descriptor_id},
};
#[path = "support/license_v2.rs"]
mod license_fixture;
use license_fixture::{fixtures, sign, worker};
#[test]
fn hybrid_pool_body_assembly_executes_owner_payment_before_node_work_signature() {
    use mutiny_consensus_v8::{
        anchors::FinalizedAnchor,
        assembler_v2,
        execution::{State, WorkParent},
        hybrid_transaction_v2::Transaction,
        license_book_v2::Book,
        mempool_v2::{Mempool, Status},
        pow::{WorkAuthority, WorkHeader},
        transactions::{Coin, OutPoint, Output},
        transactions_v2::{Input, Transfer},
        work_authority_v2::Authority,
    };
    let (owner, assignments, expected, licenses, node) = fixtures();
    let mut state = State {
        licenses_v2: Book::genesis(
            &assignments,
            &expected,
            &licenses,
            &WalletBook::default(),
            [1; 32],
            [2; 32],
        )
        .unwrap(),
        ..Default::default()
    };
    let point = OutPoint {
        transaction: [80; 32],
        index: 0,
    };
    state.coins.insert(
        point.clone(),
        Coin {
            output: Output {
                owner: licenses[0].owner,
                atoms: 100_000,
            },
            created_height: 0,
            coinbase: false,
        },
    );
    let mut transfer = Transfer {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        created_height: 1,
        expiry_height: 5,
        fee: 5_000,
        inputs: vec![Input::unsigned(point.clone(), owner.public(), 1).unwrap()],
        outputs: vec![Output {
            owner: [70; 32],
            atoms: 95_000,
        }],
    };
    transfer.sign_input(0, &owner).unwrap();
    let tx = Transaction::Transfer(transfer);
    let mut nonce = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let path =
        std::env::temp_dir().join(format!("build8-v2-assembly-{}.sqlite", hex::encode(nonce)));
    let mut pool = Mempool::open(&path, [1; 32], [2; 32], 64 * 1024 * 1024).unwrap();
    let anchor = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        height: 0,
        block: [3; 32],
    };
    pool.reconcile(&anchor, &state, &Default::default())
        .unwrap();
    pool.admit(&tx, &anchor, &state).unwrap();
    let parent = WorkParent {
        genesis: [1; 32],
        fingerprint: [2; 32],
        block: [3; 32],
        height: 0,
        t0: 1000,
        target: [255; 32],
        ancestor_timestamps: vec![1000],
    };
    let before = state.root().unwrap();
    let request = || assembler_v2::Request {
        parent: &parent,
        state: &state,
        pool: &pool,
        license: expected[0].license,
        worker: expected[0].worker_id,
        timestamp: 1100,
        ticket: 1,
        operations: &[],
    };
    let ready = assembler_v2::prepare(request()).unwrap();
    assert_eq!(ready.body.transactions, vec![tx.encode().unwrap()]);
    assert_eq!(ready.body.fees, 5_000);
    assert!(!ready.execution.state.coins.contains_key(&point));
    assert_eq!(state.root().unwrap(), before);
    assert_eq!(
        pool.status(tx.id().unwrap()).unwrap(),
        Some(Status::Pending)
    );
    assert_eq!(
        assembler_v2::prepare(request()).unwrap().candidate,
        ready.candidate
    );
    let mut changed = state.clone();
    changed.coins.clear();
    let mut wrong = request();
    wrong.state = &changed;
    assert!(assembler_v2::prepare(wrong).is_err());
    let mut wrong = request();
    let oversized_operations=[vec![0;16385]];
    wrong.operations = &oversized_operations;
    assert!(assembler_v2::prepare(wrong).is_err());
    let mut authority = Authority {
        work: WorkAuthority {
            candidate: ready.candidate.clone(),
            assignment_sequence: 1,
            ticket_sequence: 1,
            coordinator: expected[0].coordinator,
            nonce_start: 0,
            nonce_end: 100,
            epoch: 1,
        },
        node_descriptor: assignments[0].node_descriptor.clone(),
        signature: mutiny_crypto_v2::HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
    };
    authority.sign(&node).unwrap();
    let header = WorkHeader {
        candidate: ready.candidate,
        authority: authority.id().unwrap(),
        nonce: 7,
    };
    let accepted = state
        .execute_licensed_v2(&parent, &header, &authority, &ready.body)
        .unwrap();
    assert_eq!(accepted.state, ready.execution.state);
    drop(pool);
    std::fs::remove_file(path).unwrap();
}
#[test]
fn hybrid_licensed_execution_is_atomic_acyclic_and_activates_only_next_epoch() {
    use mutiny_consensus_v8::{
        blocks::BlockBody,
        execution::{CandidatePreparation, State, WorkParent},
        license_book_v2::Book,
        pow::{Candidate, WorkAuthority, WorkHeader},
        work_authority_v2::Authority,
    };
    let (owner, assignments, expected, licenses, node) = fixtures();
    let state = State {
        licenses_v2: Book::genesis(
            &assignments,
            &expected,
            &licenses,
            &WalletBook::default(),
            [1; 32],
            [2; 32],
        )
        .unwrap(),
        ..Default::default()
    };
    let original = state.records().unwrap();
    let b = &expected[0];
    let mut next = b.clone();
    next.worker_public = worker(90);
    next.worker_id = next.derived_worker_id();
    next.assignment_generation = 2;
    next.configuration_generation = 2;
    next.effective_epoch = 2;
    next.valid_until_height = 20;
    let binding = sign(next.clone(), &owner, &assignments[0].node_descriptor, 90);
    let body = BlockBody {
        height: 1,
        reward_owner: licenses[0].owner,
        fees: 0,
        transactions: vec![],
        operations: vec![binding.encode().unwrap()],
    };
    assert_eq!(BlockBody::decode(&body.encode().unwrap()).unwrap(), body);
    let parent = WorkParent {
        genesis: [1; 32],
        fingerprint: [2; 32],
        block: [3; 32],
        height: 0,
        t0: 1000,
        target: [255; 32],
        ancestor_timestamps: vec![1000],
    };
    let mut c = Candidate {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        parent: [3; 32],
        height: 1,
        timestamp: 1100,
        body_root: body.root().unwrap(),
        state_root: [0; 32],
        license: b.license,
        worker: b.worker_id,
        target: [255; 32],
    };
    let prepared = state
        .prepare_candidate_v2(CandidatePreparation {
            parent: &parent,
            candidate: &c,
            ticket_sequence: 1,
            body: &body,
        })
        .unwrap();
    assert_eq!(state.records().unwrap(), original);
    c.state_root = prepared.root;
    let mut a = Authority {
        work: WorkAuthority {
            candidate: c.clone(),
            assignment_sequence: 1,
            ticket_sequence: 1,
            coordinator: b.coordinator,
            nonce_start: 0,
            nonce_end: 100,
            epoch: 1,
        },
        node_descriptor: assignments[0].node_descriptor.clone(),
        signature: mutiny_crypto_v2::HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
    };
    a.sign(&node).unwrap();
    let h = WorkHeader {
        candidate: c.clone(),
        authority: a.id().unwrap(),
        nonce: 5,
    };
    let executed = state.execute_licensed_v2(&parent, &h, &a, &body).unwrap();
    assert_eq!(executed.state, prepared.state);
    assert_eq!(executed.root, prepared.root);
    assert_eq!(
        executed
            .state
            .licenses_v2
            .active(b.license, b.worker_id, 1)
            .unwrap()
            .1
            .last_accepted_ticket,
        1
    );
    assert!(
        executed
            .state
            .licenses_v2
            .active(b.license, next.worker_id, 1)
            .is_err()
    );
    for constituent in 0..2 {
        let mut bad = a.clone();
        if constituent == 0 {
            bad.signature.ed448[0] ^= 1;
        } else {
            bad.signature.fndsa[0] ^= 1;
        }
        assert!(state.execute_licensed_v2(&parent, &h, &bad, &body).is_err());
    }
    let mut bad = a.clone();
    bad.work.candidate.state_root[0] ^= 1;
    bad.sign(&node).unwrap();
    let bad_h = WorkHeader {
        candidate: bad.work.candidate.clone(),
        authority: bad.id().unwrap(),
        nonce: 5,
    };
    assert!(
        state
            .execute_licensed_v2(&parent, &bad_h, &bad, &body)
            .is_err()
    );
    for mutation in 0..8 {
        let mut wrong = c.clone();
        match mutation {
            0 => wrong.network ^= 1,
            1 => wrong.genesis[0] ^= 1,
            2 => wrong.fingerprint[0] ^= 1,
            3 => wrong.parent[0] ^= 1,
            4 => wrong.height = 2,
            5 => wrong.target = [0; 32],
            6 => wrong.timestamp = 1000,
            _ => wrong.worker = next.worker_id,
        }
        assert!(
            state
                .prepare_candidate_v2(CandidatePreparation {
                    parent: &parent,
                    candidate: &wrong,
                    ticket_sequence: 1,
                    body: &body
                })
                .is_err()
        );
    }
    // Failed later operations cannot leak earlier tentative assignment changes.
    let mut bad_body = body.clone();
    let mut invalid_binding = binding.clone();
    invalid_binding.enrollment.owner_signature.fndsa[0] ^= 1;
    bad_body.operations.push(invalid_binding.encode().unwrap());
    let mut bad_c = c.clone();
    bad_c.body_root = bad_body.root().unwrap();
    assert!(
        state
            .prepare_candidate_v2(CandidatePreparation {
                parent: &parent,
                candidate: &bad_c,
                ticket_sequence: 1,
                body: &bad_body
            })
            .is_err()
    );
    assert_eq!(state.records().unwrap(), original);
    let mut wrong_reward = body.clone();
    wrong_reward.reward_owner = [99; 32];
    bad_c.body_root = wrong_reward.root().unwrap();
    assert!(
        state
            .prepare_candidate_v2(CandidatePreparation {
                parent: &parent,
                candidate: &bad_c,
                ticket_sequence: 1,
                body: &wrong_reward
            })
            .is_err()
    );
    // Codec cannot reinterpret a V2 acknowledgement as its V1 counterpart.
    assert!(mutiny_consensus_v8::blocks::operation_kind(&[0x85, 2, 11, 0, 0, 0]).is_err());
    assert!(
        state
            .execute_transfers([1; 32], [2; 32], [3; 32], licenses[0].owner, &body)
            .is_err()
    );
    let records = executed.state.records().unwrap();
    let reopened = State::from_records(&records, executed.root).unwrap();
    assert_eq!(reopened, executed.state);
    let p2 = WorkParent {
        genesis: [1; 32],
        fingerprint: [2; 32],
        block: h.block_hash(),
        height: 1,
        t0: 1000,
        target: [255; 32],
        ancestor_timestamps: vec![1000, 1100],
    };
    let body2 = BlockBody {
        height: 2,
        reward_owner: licenses[0].owner,
        fees: 0,
        transactions: vec![],
        operations: vec![],
    };
    let mut c2 = c.clone();
    c2.parent = p2.block;
    c2.height = 2;
    c2.body_root = body2.root().unwrap();
    c2.timestamp = 1110;
    assert!(
        reopened
            .prepare_candidate_v2(CandidatePreparation {
                parent: &p2,
                candidate: &c2,
                ticket_sequence: 1,
                body: &body2
            })
            .is_err()
    );
    c2.timestamp = 1120;
    assert!(reopened.work_context_v2(&p2, &c2).is_err()); // old Worker at epoch 2
    c2.worker = next.worker_id;
    let prepared2 = reopened
        .prepare_candidate_v2(CandidatePreparation {
            parent: &p2,
            candidate: &c2,
            ticket_sequence: 1,
            body: &body2,
        })
        .unwrap();
    c2.state_root = prepared2.root;
    let mut a2 = a.clone();
    a2.work.candidate = c2.clone();
    a2.work.assignment_sequence = 2;
    a2.work.epoch = 2;
    a2.sign(&node).unwrap();
    let h2 = WorkHeader {
        candidate: c2,
        authority: a2.id().unwrap(),
        nonce: 6,
    };
    assert_eq!(
        reopened
            .execute_licensed_v2(&p2, &h2, &a2, &body2)
            .unwrap()
            .state,
        prepared2.state
    );
    if std::env::var("BUILD8_EXPORT_LICENSED_EXECUTION").as_deref() == Ok("1") {
        let value = serde_json::json!({"schema":"BUILD8-LICENSED-EXECUTION-V2-PUBLIC-V1","synthetic_only":true,
            "parent_records":original.iter().map(|(k,v)|serde_json::json!({"key":hex::encode(k),"record":hex::encode(v)})).collect::<Vec<_>>(),
            "blocks":([(&h,&a,&body,&executed),(&h2,&a2,&body2,&prepared2)].iter().map(|(h,a,b,e)|serde_json::json!({
                "header":hex::encode(h.encode()),"authority":hex::encode(a.encode().unwrap()),"body":hex::encode(b.encode().unwrap()),
                "state_root":hex::encode(e.root),"records":e.state.records().unwrap().iter().map(|(k,v)|serde_json::json!({"key":hex::encode(k),"record":hex::encode(v)})).collect::<Vec<_>>()
            })).collect::<Vec<_>>())});
        std::fs::write(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../qualification/licensed-execution-v2-public-v1.json"),
            serde_json::to_vec_pretty(&value).unwrap(),
        )
        .unwrap();
    }
}
#[test]
fn canonical_book_records_genesis_next_epoch_activation_and_ticket_replay() {
    use mutiny_consensus_v8::{
        license_book_v2::Book,
        pow::{Candidate, WorkAuthority, WorkContext, WorkHeader},
        work_authority_v2::Authority,
    };
    let (owner, assignments, expected, licenses, node) = fixtures();
    let wallets = WalletBook::default();
    let mut book = Book::genesis(
        &assignments,
        &expected,
        &licenses,
        &wallets,
        [1; 32],
        [2; 32],
    )
    .unwrap();
    let initial = book.records().unwrap();
    assert_eq!(initial.len(), 24);
    assert_eq!(Book::from_records(&initial).unwrap(), book);
    let b = &expected[0];
    let zero = mutiny_crypto_v2::HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    };
    let candidate = Candidate {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        parent: [3; 32],
        height: 1,
        timestamp: 1100,
        body_root: [4; 32],
        state_root: [5; 32],
        license: b.license,
        worker: b.worker_id,
        target: [255; 32],
    };
    let context = WorkContext {
        genesis: [1; 32],
        fingerprint: [2; 32],
        parent: [3; 32],
        parent_height: 0,
        t0: 1000,
        target: [255; 32],
        license: b.license,
        worker: b.worker_id,
        coordinator: b.coordinator,
        assignment_sequence: 1,
        last_accepted_ticket: 0,
        ancestor_timestamps: vec![1000],
    };
    let mut a = Authority {
        work: WorkAuthority {
            candidate: candidate.clone(),
            assignment_sequence: 1,
            ticket_sequence: 1,
            coordinator: b.coordinator,
            nonce_start: 0,
            nonce_end: 100,
            epoch: 1,
        },
        node_descriptor: assignments[0].node_descriptor.clone(),
        signature: zero,
    };
    a.sign(&node).unwrap();
    let header = WorkHeader {
        candidate,
        authority: a.id().unwrap(),
        nonce: 5,
    };
    let mut bad = a.clone();
    bad.signature.fndsa[0] ^= 1;
    assert!(
        book.verify_and_record_work(&header, &bad, &context)
            .is_err()
    );
    assert_eq!(book.records().unwrap(), initial);
    book.verify_and_record_work(&header, &a, &context).unwrap();
    let ticket = book.records().unwrap();
    assert_ne!(ticket, initial);
    assert!(book.verify_and_record_work(&header, &a, &context).is_err());
    assert_eq!(book.records().unwrap(), ticket);
    let mut next = b.clone();
    next.worker_public = worker(90);
    next.worker_id = next.derived_worker_id();
    next.assignment_generation = 2;
    next.configuration_generation = 2;
    next.effective_epoch = 2;
    next.valid_until_height = 30;
    let assignment = sign(next.clone(), &owner, &assignments[0].node_descriptor, 90);
    book.schedule(assignment.clone(), [1; 32], [2; 32], 2, 1, &wallets)
        .unwrap();
    let pending = book.records().unwrap();
    assert_eq!(pending.len(), 25);
    assert!(
        book.schedule(assignment, [1; 32], [2; 32], 2, 1, &wallets)
            .is_err()
    );
    assert_eq!(book.records().unwrap(), pending);
    assert!(book.active(b.license, next.worker_id, 1).is_err());
    book.activate_due(1).unwrap();
    assert_eq!(book.records().unwrap(), pending);
    let mut reopened = Book::from_records(&pending).unwrap();
    reopened.activate_due(2).unwrap();
    assert!(reopened.active(b.license, b.worker_id, 2).is_err());
    assert_eq!(
        reopened
            .active(b.license, next.worker_id, 2)
            .unwrap()
            .1
            .last_accepted_ticket,
        0
    );
    let final_records = reopened.records().unwrap();
    assert_eq!(final_records.len(), 25);
    reopened.activate_due(0).unwrap();
    assert_eq!(reopened.records().unwrap(), final_records);
    assert_eq!(Book::from_records(&final_records).unwrap(), reopened);
    let mut wrong_key = final_records.clone();
    let (key, raw) = wrong_key.pop_first().unwrap();
    assert_ne!(key, [0; 32]);
    wrong_key.insert([0; 32], raw);
    assert!(Book::from_records(&wrong_key).is_err());
    let mut missing = final_records.clone();
    missing.remove(&mutiny_consensus_v8::domain_hash(
        b"MUTINY-BUILD8-WORKER-STATE-KEY-V2",
        &next.worker_id,
    ));
    assert!(Book::from_records(&missing).is_err());
    let state = mutiny_consensus_v8::execution::State {
        licenses_v2: reopened.clone(),
        ..Default::default()
    };
    let records = state.records().unwrap();
    let root = state.root().unwrap();
    assert_eq!(
        mutiny_consensus_v8::execution::State::from_records(&records, root).unwrap(),
        state
    );
    let mut mixed = state.clone();
    mixed
        .licenses
        .licenses
        .insert(licenses[0].id, licenses[0].clone());
    assert!(mixed.records().is_err());
    let mut opaque = mutiny_consensus_v8::execution::State::default();
    opaque
        .protocol_records
        .insert([99; 32], vec![0x83, 2, 0x18, 41, 0x40]);
    assert!(opaque.records().is_err());
    let bad_records = vec![([99; 32], vec![0x83, 2, 0x18, 41, 0x40])];
    let bad_root = mutiny_consensus_v8::blocks::state_root(&bad_records).unwrap();
    assert!(mutiny_consensus_v8::execution::State::from_records(&bad_records, bad_root).is_err());
    if std::env::var("BUILD8_EXPORT_LICENSE_BOOK").as_deref() == Ok("1") {
        let value = serde_json::json!({"schema":"BUILD8-LICENSE-BOOK-V2-PUBLIC-V1","synthetic_only":true,
            "root":hex::encode(root),"records":records.iter().map(|(k,v)|serde_json::json!({"key":hex::encode(k),"record":hex::encode(v)})).collect::<Vec<_>>()});
        std::fs::write(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../qualification/license-book-v2-public-v1.json"),
            serde_json::to_vec_pretty(&value).unwrap(),
        )
        .unwrap();
    }
}
#[test]
fn twelve_supervised_genesis_assignments_require_distinct_devices_and_complete_authority() {
    let (owner, a, expected, licenses, _node) = fixtures();
    let wallets = WalletBook::default();
    let check = |values: &[Assignment], supervised: &[Binding]| {
        verify_genesis_set(values, supervised, &licenses, &wallets, [1; 32], [2; 32])
    };
    assert_eq!(check(&a, &expected).unwrap().len(), 12);
    assert!(check(&a[..11], &expected).is_err());
    let mut wrong = expected.clone();
    wrong[0].device_mac[5] ^= 64;
    assert!(check(&a, &wrong).is_err());
    for component in 0..3 {
        let mut bad = a.clone();
        match component {
            0 => bad[0].enrollment.owner_signature.ed448[0] ^= 1,
            1 => bad[0].enrollment.owner_signature.fndsa[0] ^= 1,
            _ => bad[0].enrollment.worker_signature[0] ^= 1,
        };
        assert!(check(&bad, &expected).is_err());
    }
    for duplicate in 0..2 {
        let mut bad = a.clone();
        let mut supervised = expected.clone();
        let seed = if duplicate == 0 {
            supervised[1].worker_public = supervised[0].worker_public;
            1
        } else {
            supervised[1].device_mac = supervised[0].device_mac;
            2
        };
        supervised[1].worker_id = supervised[1].derived_worker_id();
        bad[1] = sign(supervised[1].clone(), &owner, &a[1].node_descriptor, seed);
        assert!(check(&bad, &supervised).is_err());
    }
    let raw = a[0].encode().unwrap();
    assert_eq!(Assignment::decode(&raw).unwrap(), a[0]);
    for n in 0..raw.len() {
        assert!(Assignment::decode(&raw[..n]).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(Assignment::decode(&trailing).is_err());
    assert!(Assignment::decode(&a[0].enrollment.bytes().unwrap()).is_err());
    if std::env::var("BUILD8_EXPORT_LICENSE_ASSIGNMENT").as_deref() == Ok("1") {
        let value = serde_json::json!({"schema":"BUILD8-LICENSE-ASSIGNMENT-V2-PUBLIC-V1","synthetic_only":true,
            "assignments":a.iter().map(|a|hex::encode(a.encode().unwrap())).collect::<Vec<_>>(),
            "licenses":licenses.iter().map(|l|hex::encode(l.encode())).collect::<Vec<_>>()});
        std::fs::write(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../qualification/license-assignment-v2-public-v1.json"),
            serde_json::to_vec_pretty(&value).unwrap(),
        )
        .unwrap();
    }
}
#[test]
fn reassignment_uses_current_owner_and_next_epoch_without_same_height_authority() {
    let (owner, assignments, expected, mut licenses, _node) = fixtures();
    let mut wallets = WalletBook::default();
    wallets.register(&assignments[0].owner_descriptor).unwrap();
    let l = &mut licenses[0];
    l.assignment_sequence = 1;
    l.active_worker = Some(expected[0].worker_id);
    let mut b = expected[0].clone();
    b.assignment_generation = 2;
    b.configuration_generation = 2;
    b.effective_epoch = 6;
    b.valid_until_height = 30;
    b.worker_public = worker(99);
    b.worker_id = b.derived_worker_id();
    let assignment = sign(b.clone(), &owner, &assignments[0].node_descriptor, 99);
    // Context lifetime is explicit below to avoid inferring trust from payloads.
    let ctx = ParentContext {
        genesis: [1; 32],
        fingerprint: [2; 32],
        height: 20,
        epoch: 5,
        license: &*l,
        wallets: &wallets,
    };
    assignment.verify_next_epoch(&ctx).unwrap();
    for field in 0..4 {
        let mut bad = b.clone();
        match field {
            0 => bad.assignment_generation = 1,
            1 => bad.effective_epoch = 5,
            2 => bad.valid_until_height = 19,
            _ => bad.genesis = [3; 32],
        };
        bad.worker_id = bad.derived_worker_id();
        assert!(
            sign(bad, &owner, &assignments[0].node_descriptor, 99)
                .verify_next_epoch(&ctx)
                .is_err()
        );
    }
    let new = HybridKey::wallet_restore(&format!("{}vote", "zoo ".repeat(23)), Role::WalletOwner)
        .unwrap();
    let zero = mutiny_crypto_v2::HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    };
    let mut rotation = mutiny_consensus_v8::wallet_rotation_v1::Rotation {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        authority: l.owner,
        current: assignments[0].owner_descriptor.clone(),
        proposed: new.public().descriptor(2).unwrap(),
        created_height: 10,
        expiry_height: 30,
        authorization: zero.clone(),
        possession: zero,
    };
    rotation.sign(&owner, &new).unwrap();
    wallets.apply(&rotation, [1; 32], [2; 32], 19).unwrap();
    let ctx = ParentContext {
        genesis: [1; 32],
        fingerprint: [2; 32],
        height: 20,
        epoch: 5,
        license: &*l,
        wallets: &wallets,
    };
    assert!(assignment.verify_next_epoch(&ctx).is_err());
    b.owner_generation = 2;
    b.owner_descriptor = owner_descriptor_id(new.public(), 2).unwrap();
    sign(b, &new, &assignments[0].node_descriptor, 99)
        .verify_next_epoch(&ctx)
        .unwrap();
}
/// Amendment AM-10 (P-LANE-DESIGN-AMENDMENTS-V1; Order Q17; WP-Q17): the LOCKED rule stays,
/// effective epoch == inclusion epoch + 1, a ONE-MiningEpoch delivery window (a known
/// limitation of the Worker-assignment product path; the bound a longer lead needs is Architect
/// question C.4). Pinned at the verifier and on real executor blocks: equal, earlier, two-ahead
/// and far-future effective epochs are refused (AM-11: far future kept rejected), activation is
/// never early, a late delivery is refused and its re-signed form (`DeliveryTerms`) is included.
#[test]
fn assignment_effective_epoch_is_exactly_the_next_inclusion_epoch() {
    use mutiny_consensus_v8::{
        Error, Hash,
        blocks::BlockBody,
        execution::{CandidatePreparation, ExecutionError, State, WorkParent},
        license_assignment_v2::DeliveryTerms,
        license_book_v2::Book,
        pow::{Candidate, WorkAuthority, WorkHeader},
        work_authority_v2::Authority,
    };
    let (owner, assignments, expected, licenses, node) = fixtures();
    let signed = |index: usize, seed: u8, generation: u64, effective_epoch: u64, until: u64| {
        let mut b = expected[index].clone();
        b.assignment_generation = generation;
        b.configuration_generation = 2;
        b.effective_epoch = effective_epoch;
        b.valid_until_height = until;
        b.worker_public = worker(seed);
        b.worker_id = b.derived_worker_id();
        sign(b, &owner, &assignments[index].node_descriptor, seed)
    };
    // Verifier: License 0 at sequence 1; inclusion at height 20 in epoch 5.
    let wallets = WalletBook::default();
    let mut current = licenses[0].clone();
    current.assignment_sequence = 1;
    current.active_worker = Some(expected[0].worker_id);
    let at = |height: u64, epoch: u64| ParentContext {
        genesis: [1; 32],
        fingerprint: [2; 32],
        height,
        epoch,
        license: &current,
        wallets: &wallets,
    };
    let terms = DeliveryTerms::at(&current, 20, 5).unwrap();
    assert_eq!(
        terms,
        DeliveryTerms {
            assignment_generation: 2,
            effective_epoch: 6,
            min_valid_until_height: 20
        }
    );
    let on_time = signed(0, 99, 2, 6, 30);
    assert!(terms.admits(&on_time.enrollment.binding));
    on_time.verify_next_epoch(&at(20, 5)).unwrap();
    for effective in [0, 4, 5, 7, 100, 1_000_005, u64::MAX] {
        let a = signed(0, 99, 2, effective, 30);
        assert!(!terms.admits(&a.enrollment.binding), "effective epoch {effective}");
        assert_eq!(
            a.verify_next_epoch(&at(20, 5)).err(),
            Some(Error::StaleSequence),
            "effective epoch {effective} at inclusion epoch 5"
        );
    }
    // Late delivery: the same bytes one epoch later are stale for good; re-signed with the
    // terms of the epoch now targeted they verify.
    assert_eq!(
        on_time.verify_next_epoch(&at(21, 6)).err(),
        Some(Error::StaleSequence)
    );
    let late_terms = DeliveryTerms::at(&current, 21, 6).unwrap();
    assert!(!late_terms.admits(&on_time.enrollment.binding));
    let resigned = signed(0, 99, late_terms.assignment_generation, late_terms.effective_epoch, 30);
    assert!(late_terms.admits(&resigned.enrollment.binding));
    resigned.verify_next_epoch(&at(21, 6)).unwrap();
    // Inclusion deadline: at it valid, below it refused; a wrong generation is WrongAnchor.
    let at_deadline = signed(0, 99, 2, 6, 20);
    assert!(terms.admits(&at_deadline.enrollment.binding));
    at_deadline.verify_next_epoch(&at(20, 5)).unwrap();
    let short = signed(0, 99, 2, 6, 19);
    assert!(!terms.admits(&short.enrollment.binding));
    assert_eq!(
        short.verify_next_epoch(&at(20, 5)).err(),
        Some(Error::StaleSequence)
    );
    let skipped = signed(0, 99, 3, 6, 30);
    assert!(!terms.admits(&skipped.enrollment.binding));
    assert_eq!(
        skipped.verify_next_epoch(&at(20, 5)).err(),
        Some(Error::WrongAnchor)
    );
    assert_eq!(
        DeliveryTerms::at(&current, 0, 5).err(),
        Some(Error::StaleSequence)
    );
    assert_eq!(
        on_time.verify_next_epoch(&at(0, 5)).err(),
        Some(Error::StaleSequence)
    );

    // Real executor blocks on the twelve-License Genesis state (t0 = 1000, 60-second epochs).
    let state0 = State {
        licenses_v2: Book::genesis(
            &assignments,
            &expected,
            &licenses,
            &WalletBook::default(),
            [1; 32],
            [2; 32],
        )
        .unwrap(),
        ..Default::default()
    };
    let (license, old_worker) = (expected[0].license, expected[0].worker_id);
    let parent = |block: u8, height: u64, ancestors: Vec<u64>| WorkParent {
        genesis: [1; 32],
        fingerprint: [2; 32],
        block: [block; 32],
        height,
        t0: 1000,
        target: [255; 32],
        ancestor_timestamps: ancestors,
    };
    let candidate = |p: &WorkParent, worker: Hash, timestamp: u64, operations: Vec<Vec<u8>>| {
        let body = BlockBody {
            height: p.height + 1,
            reward_owner: licenses[0].owner,
            fees: 0,
            transactions: vec![],
            operations,
        };
        let c = Candidate {
            network: NETWORK_ID,
            genesis: [1; 32],
            fingerprint: [2; 32],
            parent: p.block,
            height: p.height + 1,
            timestamp,
            body_root: body.root().unwrap(),
            state_root: [0; 32],
            license,
            worker,
            target: [255; 32],
        };
        (c, body)
    };
    let prepare = |s: &State,
                   p: &WorkParent,
                   worker: Hash,
                   timestamp: u64,
                   ticket: u64,
                   ops: Vec<Vec<u8>>| {
        let (c, body) = candidate(p, worker, timestamp, ops);
        s.prepare_candidate_v2(CandidatePreparation {
            parent: p,
            candidate: &c,
            ticket_sequence: ticket,
            body: &body,
        })
    };
    // Block 1 at epoch 1 (timestamp 1100), mined by License 0's Genesis Worker.
    let p0 = parent(3, 0, vec![1000]);
    let before = state0.records().unwrap();
    for effective in [0, 1, 3, 1_000_001] {
        let op = signed(0, 99, 2, effective, 20).encode().unwrap();
        let refused = prepare(&state0, &p0, old_worker, 1100, 1, vec![op]);
        assert!(
            matches!(refused, Err(ExecutionError::Codec(Error::StaleSequence))),
            "effective epoch {effective} at inclusion epoch 1: {:?}",
            refused.err()
        );
        assert_eq!(state0.records().unwrap(), before);
    }
    let a0 = signed(0, 99, 2, 2, 20);
    let block1 = prepare(&state0, &p0, old_worker, 1100, 1, vec![a0.encode().unwrap()]).unwrap();
    // The complete validator path (signed hybrid work authority) accepts the same block.
    let (mut c1, body1) = candidate(&p0, old_worker, 1100, vec![a0.encode().unwrap()]);
    c1.state_root = block1.root;
    let mut authority = Authority {
        work: WorkAuthority {
            candidate: c1.clone(),
            assignment_sequence: 1,
            ticket_sequence: 1,
            coordinator: expected[0].coordinator,
            nonce_start: 0,
            nonce_end: 100,
            epoch: 1,
        },
        node_descriptor: assignments[0].node_descriptor.clone(),
        signature: mutiny_crypto_v2::HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
    };
    authority.sign(&node).unwrap();
    let header = WorkHeader {
        candidate: c1,
        authority: authority.id().unwrap(),
        nonce: 5,
    };
    assert_eq!(
        state0
            .execute_licensed_v2(&p0, &header, &authority, &body1)
            .unwrap()
            .state,
        block1.state
    );
    let state1 = block1.state;
    assert_eq!(state1.licenses_v2.pending_assignment(license), Some(&a0));
    // Block 2, a later block of the SAME epoch 1 (timestamp 1101): the new Worker has no
    // authority yet; the old Worker still mines; nothing activates early.
    let p1 = parent(4, 1, vec![1000, 1100]);
    let new_worker = a0.enrollment.binding.worker_id;
    assert!(matches!(
        prepare(&state1, &p1, new_worker, 1101, 1, vec![]),
        Err(ExecutionError::Codec(Error::UnknownSigner))
    ));
    let state2 = prepare(&state1, &p1, old_worker, 1101, 2, vec![]).unwrap().state;
    assert_eq!(state2.licenses_v2.pending_assignment(license), Some(&a0));
    assert_eq!(
        state2.licenses_v2.license(license).unwrap().active_worker,
        Some(old_worker)
    );
    // Block 3 at epoch 2 (timestamp 1120): activation at exactly the signed epoch; the old
    // Worker is stale from this block on.
    let p2 = parent(5, 2, vec![1000, 1100, 1101]);
    assert!(matches!(
        prepare(&state2, &p2, old_worker, 1120, 3, vec![]),
        Err(ExecutionError::Codec(Error::StaleSequence))
    ));
    // License 1's assignment, signed for inclusion in epoch 1, arrives in epoch 2: refused...
    let late = signed(1, 98, 2, 2, 20);
    let refused = prepare(&state2, &p2, new_worker, 1120, 1, vec![late.encode().unwrap()]);
    assert!(
        matches!(refused, Err(ExecutionError::Codec(Error::StaleSequence))),
        "{:?}",
        refused.err()
    );
    // ...and included once re-signed with the delivery terms of this block.
    let terms3 =
        DeliveryTerms::at(state2.licenses_v2.license(expected[1].license).unwrap(), 3, 2)
            .unwrap();
    assert!(!terms3.admits(&late.enrollment.binding));
    let resigned = signed(1, 98, terms3.assignment_generation, terms3.effective_epoch, 20);
    assert!(terms3.admits(&resigned.enrollment.binding));
    let block3 = prepare(&state2, &p2, new_worker, 1120, 1, vec![resigned.encode().unwrap()])
        .unwrap();
    let l0 = block3.state.licenses_v2.license(license).unwrap();
    assert_eq!((l0.active_worker, l0.assignment_sequence), (Some(new_worker), 2));
    assert_eq!(block3.state.licenses_v2.pending_assignment(license), None);
    assert_eq!(
        block3
            .state
            .licenses_v2
            .pending_assignment(expected[1].license),
        Some(&resigned)
    );
}
