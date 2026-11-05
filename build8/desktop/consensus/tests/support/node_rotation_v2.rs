// Synthetic keys and TPM evidence only. Included in the integrated rotation test.
fn qualify_node_rotation(
    initial: &State,
    genesis: &FinalizedAnchor,
    owner: &HybridKey,
    old_node: &HybridKey,
    old_continuity: &HybridKey,
    next_continuity: &HybridKey,
    ak: &SigningKey,
    profile: &TpmProfile,
) {
    use crate::{
        blocks::BlockBody, continuity_lifecycle_v2::transition, node_key_rotate_v2::NodeKeyRotate,
    };
    fn install(state: &State, parent: &FinalizedAnchor, operations: Vec<Vec<u8>>) -> State {
        let body = BlockBody {
            height: parent.height + 1,
            reward_owner: [30; 32],
            fees: 0,
            transactions: vec![],
            operations,
        };
        let t = transition(state, parent, state.root().unwrap(), &body).unwrap();
        let mut next = state.clone();
        next.accounting = t.accounting;
        next.continuity = Some(t.registry);
        next.membership_v2 = t.membership;
        next.continuity_keys_v2 = t.keys;
        next.retired_continuity_v2 = t.retired;
        next.node_key_history_v2 = t.node_history;
        next.bonds_v2 = t.bonds;
        next.penalties_v2 = t.penalties;
        let rows = next.records().unwrap();
        let restored = State::from_records(&rows, next.root().unwrap()).unwrap();
        assert!(restored.records().unwrap() == rows);
        restored
    }
    let node = initial.continuity.as_ref().unwrap().members[0].node;
    let new_node = HybridKey::generate(Role::Node).unwrap();
    let third_node = HybridKey::generate(Role::Node).unwrap();
    let empty = HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    };
    let mut rotation = NodeKeyRotate {
        parent: genesis.clone(),
        node,
        hardware_generation: 1,
        sequence: 1,
        current: old_node.public().descriptor(1).unwrap(),
        proposed: new_node.public().descriptor(2).unwrap(),
        authorizer: owner.public().descriptor(1).unwrap(),
        authorization: empty.clone(),
        possession: empty.clone(),
    };
    rotation.sign_authorization(owner).unwrap();
    rotation.sign_possession(&new_node).unwrap();
    qualify_certified_node_rotation(
        initial.clone(),
        &rotation,
        old_continuity,
        &new_node,
        old_node,
        owner,
        next_continuity,
        ak,
        profile,
    );
    let raw = rotation.encode().unwrap();
    assert_eq!(crate::blocks::operation_kind(&raw).unwrap(), 22);
    let body = BlockBody {
        height: 1,
        reward_owner: [30; 32],
        fees: 0,
        transactions: vec![],
        operations: vec![raw.clone(), raw.clone()],
    };
    assert!(transition(initial, genesis, initial.root().unwrap(), &body).is_err());
    let post = install(initial, genesis, vec![raw.clone()]);
    assert_eq!(
        post.membership_v2
            .get(node)
            .unwrap()
            .current_node_descriptor(),
        rotation.proposed
    );
    assert_eq!(
        post.membership_v2
            .get(node)
            .unwrap()
            .binding()
            .node_descriptor,
        rotation.current
    );
    assert_eq!(post.continuity_keys_v2, initial.continuity_keys_v2);
    assert_eq!(
        post.continuity.as_ref().unwrap().members,
        initial.continuity.as_ref().unwrap().members
    );
    assert_eq!(post.bonds_v2, initial.bonds_v2);
    let parent1 = FinalizedAnchor {
        height: 1,
        block: [71; 32],
        ..genesis.clone()
    };
    let replay = BlockBody {
        height: 2,
        operations: vec![raw.clone()],
        ..body.clone()
    };
    assert!(transition(&post, &parent1, post.root().unwrap(), &replay).is_err());
    let mut missing = post.clone();
    missing.node_key_history_v2 = Default::default();
    assert!(missing.records().is_err());
    let mut orphan = initial.clone();
    orphan.node_key_history_v2 = post.node_key_history_v2.clone();
    assert!(orphan.records().is_err());
    let mut hidden = initial.clone();
    hidden
        .protocol_records
        .extend(post.node_key_history_v2.records().unwrap());
    assert!(hidden.records().is_err());
    let mut malformed = initial.clone();
    malformed
        .protocol_records
        .insert([77; 32], vec![0x84, 2, 0x18, 56]);
    assert!(malformed.records().is_err());
    let mut exit = crate::continuity_exit_v2::Exit {
        genesis: genesis.genesis,
        fingerprint: genesis.fingerprint,
        height: 2,
        parent_anchor: parent1.id(),
        node,
        hardware_generation: 1,
        sequence: 2,
        authorizer: rotation.current.clone(),
        signature: empty.clone(),
    };
    exit.sign(old_node).unwrap();
    let mut exit_body = BlockBody {
        height: 2,
        operations: vec![exit.encode().unwrap()],
        ..body.clone()
    };
    assert!(transition(&post, &parent1, post.root().unwrap(), &exit_body).is_err());
    exit.authorizer = rotation.proposed.clone();
    exit.sign(&new_node).unwrap();
    exit_body.operations = vec![exit.encode().unwrap()];
    assert!(transition(&post, &parent1, post.root().unwrap(), &exit_body).is_ok());
    // A new Continuity binding retains the original NodeID commitment but must
    // prove possession of the current Node authentication key.
    let mut continuation = KeyRotate {
        parent: parent1.clone(),
        nonce: [72; 32],
        sequence: 2,
        old_key_generation: 1,
        binding: initial.membership_v2.get(node).unwrap().binding().clone(),
    };
    continuation.binding.node_signer = Some(rotation.proposed.clone());
    continuation.binding.admission.key_generation = 2;
    continuation.binding.admission.continuity_descriptor =
        next_continuity.public().descriptor(2).unwrap();
    continuation.binding.admission.supervised_nonce = continuation.admission_nonce().unwrap();
    continuation
        .binding
        .admission
        .prove_continuity(next_continuity)
        .unwrap();
    continuation.binding.admission.quote = quote(
        ak,
        profile,
        continuation.binding.admission.challenge().unwrap(),
    );
    continuation.binding.admission.authorize(owner, 1).unwrap();
    continuation.binding.sign(&new_node).unwrap();
    assert!(continuation.encode().unwrap().len() <= 16 * 1024);
    let mut stale = continuation.clone();
    stale.binding.node_signer = None;
    stale.binding.sign(old_node).unwrap();
    assert!(stale.verify(&post, &parent1, post.root().unwrap()).is_err());
    let post2 = install(&post, &parent1, vec![continuation.encode().unwrap()]);
    let parent2 = FinalizedAnchor {
        height: 2,
        block: [73; 32],
        ..genesis.clone()
    };
    let mut again = NodeKeyRotate {
        parent: parent2.clone(),
        sequence: 3,
        current: rotation.proposed.clone(),
        proposed: third_node.public().descriptor(3).unwrap(),
        authorizer: rotation.proposed.clone(),
        ..rotation.clone()
    };
    again.sign_authorization(&new_node).unwrap();
    again.sign_possession(&third_node).unwrap();
    let post3 = install(&post2, &parent2, vec![again.encode().unwrap()]);
    assert_eq!(post3.node_key_history_v2.entries().count(), 2);
    assert_eq!(
        post3
            .membership_v2
            .get(node)
            .unwrap()
            .current_node_descriptor(),
        again.proposed
    );
    assert_eq!(
        post3
            .membership_v2
            .get(node)
            .unwrap()
            .binding()
            .signer_descriptor(),
        rotation.proposed
    );
    assert_eq!(post3.continuity_keys_v2, post2.continuity_keys_v2);
    let parent3 = FinalizedAnchor {
        height: 3,
        block: [74; 32],
        ..genesis.clone()
    };
    let third_continuity = HybridKey::generate(Role::Continuity).unwrap();
    let mut retire_again = KeyRotate {
        parent: parent3.clone(),
        nonce: [75; 32],
        sequence: 4,
        old_key_generation: 2,
        binding: post3.membership_v2.get(node).unwrap().binding().clone(),
    };
    retire_again.binding.node_signer = Some(again.proposed.clone());
    retire_again.binding.admission.key_generation = 3;
    retire_again.binding.admission.continuity_descriptor =
        third_continuity.public().descriptor(3).unwrap();
    retire_again.binding.admission.supervised_nonce = retire_again.admission_nonce().unwrap();
    retire_again
        .binding
        .admission
        .prove_continuity(&third_continuity)
        .unwrap();
    retire_again.binding.admission.quote = quote(
        ak,
        profile,
        retire_again.binding.admission.challenge().unwrap(),
    );
    retire_again.binding.admission.authorize(owner, 1).unwrap();
    retire_again.binding.sign(&third_node).unwrap();
    let post4 = install(&post3, &parent3, vec![retire_again.encode().unwrap()]);
    assert_eq!(post4.retired_continuity_v2.records().unwrap().len(), 2);
    assert!(
        post4
            .retired_continuity_v2
            .records()
            .unwrap()
            .values()
            .map(|raw| crate::retired_continuity_v2::Record::decode(raw).unwrap())
            .any(|r| r.binding.admission.key_generation == 2
                && r.binding.signer_descriptor() == rotation.proposed)
    );
    if std::env::var_os("BUILD8_EXPORT_NODE_ROTATION_STATE_V1").is_some() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../qualification/node-rotation-state-public-v1.json");
        let rows: Vec<_> = post3.records().unwrap().into_iter().map(|(key, record)|
            serde_json::json!({"key": hex::encode(key), "record": hex::encode(record)})).collect();
        let value = serde_json::json!({"synthetic_only": true, "production_authorized": false,
            "node": hex::encode(node), "height": 3, "genesis": hex::encode(genesis.genesis),
            "fingerprint": hex::encode(genesis.fingerprint), "root": hex::encode(post3.root().unwrap()), "records": rows});
        use std::io::Write;
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        output
            .write_all(serde_json::to_string_pretty(&value).unwrap().as_bytes())
            .unwrap();
    }
    println!(
        "SYNTHETIC_NODE_ROTATION_CHAIN_PASS owner_then_node_authority=true history_roundtrip=true production=false"
    );
}

fn qualify_certified_node_rotation(
    mut state: State,
    rotation: &crate::node_key_rotate_v2::NodeKeyRotate,
    old: &HybridKey,
    new: &HybridKey,
    coordinator: &HybridKey,
    owner: &HybridKey,
    replacement_continuity: &HybridKey,
    ak: &SigningKey,
    profile: &TpmProfile,
) {
    use crate::{
        block_envelope_v2::BlockEnvelope,
        blocks::BlockBody,
        canonical_store_v2::CanonicalStore,
        certificates::Decision,
        continuity_v2::{Certificate, Vote},
        execution::{CandidatePreparation, WorkParent},
        pow::{Candidate, WorkAuthority, WorkHeader},
        votes_v2::HeightAuthority,
        work_authority_v2::Authority,
    };
    let (_, mut assignments, mut expected, licenses, _) = license_fixture::fixtures();
    for (index, binding) in expected.iter_mut().enumerate() {
        binding.coordinator = crate::work_authority_v2::node_identity(&rotation.current).unwrap();
        assignments[index] =
            license_fixture::sign(binding.clone(), owner, &rotation.current, index as u8 + 1);
    }
    state.licenses_v2 = crate::license_book_v2::Book::genesis(
        &assignments,
        &expected,
        &licenses,
        &state.wallets,
        [1; 32],
        [2; 32],
    )
    .unwrap();
    let genesis = rotation.parent.clone();
    let root = state.root().unwrap();
    let node = rotation.node;
    let body = BlockBody {
        height: 1,
        reward_owner: licenses[0].owner,
        fees: 0,
        transactions: vec![],
        operations: vec![rotation.encode().unwrap()],
    };
    let parent = WorkParent {
        genesis: genesis.genesis,
        fingerprint: genesis.fingerprint,
        height: 0,
        block: genesis.block,
        t0: 1000,
        target: [255; 32],
        ancestor_timestamps: vec![1000],
    };
    let mut candidate = Candidate {
        network: NETWORK_ID,
        genesis: genesis.genesis,
        fingerprint: genesis.fingerprint,
        height: 1,
        parent: genesis.block,
        timestamp: 1100,
        body_root: body.root().unwrap(),
        state_root: [0; 32],
        license: licenses[0].id,
        worker: expected[0].worker_id,
        target: parent.target,
    };
    let prepared = state
        .prepare_candidate_v2(CandidatePreparation {
            parent: &parent,
            candidate: &candidate,
            ticket_sequence: 1,
            body: &body,
        })
        .unwrap();
    candidate.state_root = prepared.root;
    assert!(!prepared.state.node_key_history_v2.is_empty());
    assert!(prepared.state.retired_continuity_v2.is_empty());
    let mut work = Authority {
        work: WorkAuthority {
            candidate: candidate.clone(),
            assignment_sequence: 1,
            ticket_sequence: 1,
            coordinator: expected[0].coordinator,
            nonce_start: 0,
            nonce_end: 100,
            epoch: 1,
        },
        node_descriptor: assignments[0].node_descriptor.clone(),
        signature: HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
    };
    work.sign(&coordinator).unwrap();
    let header = WorkHeader {
        candidate,
        authority: work.id().unwrap(),
        nonce: 1,
    };
    let before = HeightAuthority::from_state(&state, genesis.clone(), root).unwrap();
    let voter = &before.voters[&node];
    let decision = Decision {
        network: NETWORK_ID,
        genesis: genesis.genesis,
        fingerprint: genesis.fingerprint,
        purpose: 2,
        height: 1,
        mining_epoch: 1,
        continuity_period: 0,
        round: 0,
        step: 3,
        previous_finalized_anchor: genesis.id(),
        parent: genesis.block,
        block: header.block_hash(),
        state: prepared.root,
        membership: before.membership,
        reputation: before.reputation,
        attestation: before.attestation,
    };
    let mut vote = Vote {
        decision: decision.clone(),
        nil: false,
        node,
        hardware_generation: 1,
        key_generation: 1,
        sequence: 1,
        tpm_identity: voter.tpm_identity(),
        profile: voter.profile,
        signature: HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
    };
    vote.sign(old).unwrap();
    let envelope = BlockEnvelope {
        header,
        body,
        authority: work,
        certificate: Certificate {
            decision,
            votes: vec![vote],
        },
    };
    let mut random = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
    let path = std::env::temp_dir().join(format!(
        "build8-synthetic-key-rotation-{}.sqlite",
        hex::encode(random)
    ));
    let mut chain =
        CanonicalStore::open_trusted_genesis(&path, &genesis, &state, root, 1000, parent.target)
            .unwrap();
    let mut probe_backend = SyntheticCustody {
        key: old,
        counter: 100,
        calls: 0,
    };
    let probe_path = path.with_extension("probe-voter.sqlite");
    let mut probe_actor = crate::voter_actor_v2::VoterActor::open(
        &probe_path,
        node,
        Some(100),
        &mut chain,
        &mut probe_backend,
    )
    .unwrap();
    let mut probe_gate = crate::liveness_v2::WorkGate::new(before.clone(), root, 0).unwrap();
    let probe_request = probe_gate.request(0, [87; 32]).unwrap().unwrap();
    let before_probe = probe_actor.progress().unwrap();
    let mut invalid_probe = probe_request.clone();
    invalid_probe.state[0] ^= 1;
    assert!(
        probe_actor
            .sign_work_probe(&chain, &invalid_probe, &mut probe_backend)
            .is_err()
    );
    assert_eq!(probe_backend.calls, 0);
    let probe_fragment = probe_actor
        .sign_work_probe(&chain, &probe_request, &mut probe_backend)
        .unwrap();
    probe_fragment
        .verify(&probe_request, &before, root)
        .unwrap();
    assert_eq!(probe_backend.calls, 1);
    assert_eq!(probe_backend.counter, 100);
    assert!(probe_actor.progress().unwrap() == before_probe);
    let password = "synthetic Node custody test only";
    let initial_pins = chain.current_node_authority(&genesis, node).unwrap();
    assert_eq!(initial_pins.descriptor(), rotation.current);
    let encrypted_old = coordinator
        .seal_for(password, 1, &initial_pins.context())
        .unwrap();
    let old_custody = crate::node_control_custody::EncryptedNodeKey::unlock(
        &chain,
        &genesis,
        node,
        &encrypted_old,
        password,
    )
    .unwrap();
    qualify_hybrid_coordinator(&state, &genesis, &envelope, old, &old_custody);
    qualify_software_coordinator(&state, &genesis, owner, old);
    let journal_path = path.with_extension("work.sqlite");
    assert!(
        crate::work_journal_v2::Journal::reopen(
            &journal_path,
            genesis.genesis,
            genesis.fingerprint,
            &rotation.current
        )
        .is_err()
    );
    let mut journal = crate::work_journal_v2::Journal::initialize(
        &journal_path,
        genesis.genesis,
        genesis.fingerprint,
        &rotation.current,
    )
    .unwrap();
    assert!(
        crate::work_journal_v2::Journal::initialize(
            &journal_path,
            genesis.genesis,
            genesis.fingerprint,
            &rotation.current
        )
        .is_err()
    );
    let reservation = journal
        .reserve(envelope.header.candidate.worker, 0)
        .unwrap();
    assert_eq!(reservation.ticket(), 1);
    assert_eq!(reservation.worker(), envelope.header.candidate.worker);
    assert!(journal.lookup(reservation.worker()).unwrap().is_none());
    let mut custody_work = envelope.authority.clone();
    custody_work.signature = HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    };
    for mutation in 0..6 {
        let mut bad = custody_work.clone();
        match mutation {
            0 => bad.work.candidate.state_root[0] ^= 1,
            1 => bad.work.candidate.license[0] ^= 1,
            2 => bad.work.epoch += 1,
            3 => bad.work.nonce_start = bad.work.nonce_end + 1,
            4 => bad.work.assignment_sequence += 1,
            _ => bad.work.ticket_sequence = 0,
        }
        let before = bad.clone();
        assert!(
            old_custody
                .authorize_work(&chain, &genesis, &mut bad, &envelope.body)
                .is_err()
        );
        assert!(bad == before);
    }
    let mut invalid_body = envelope.body.clone();
    invalid_body.fees += 1;
    let before = custody_work.clone();
    assert!(
        old_custody
            .authorize_work(&chain, &genesis, &mut custody_work, &invalid_body)
            .is_err()
    );
    assert!(custody_work == before);
    old_custody
        .authorize_work(&chain, &genesis, &mut custody_work, &envelope.body)
        .unwrap();
    let (context, _, descriptor) = state
        .work_context_v2(&parent, &envelope.header.candidate)
        .unwrap();
    custody_work
        .verify(&envelope.header, &context, &descriptor)
        .unwrap();
    // Fail publication after the durable reservation; no offer becomes visible.
    let fault = rusqlite::Connection::open(&journal_path).unwrap();
    fault.execute_batch("CREATE TRIGGER fail_work_finish BEFORE UPDATE ON tickets BEGIN SELECT RAISE(ABORT,'synthetic work failure'); END;").unwrap();
    assert!(
        journal
            .finish(&reservation, &custody_work, &envelope.body)
            .is_err()
    );
    assert!(journal.lookup(reservation.worker()).unwrap().is_none());
    fault
        .execute_batch("DROP TRIGGER fail_work_finish;")
        .unwrap();
    drop(fault);
    journal
        .finish(&reservation, &custody_work, &envelope.body)
        .unwrap();
    journal
        .finish(&reservation, &custody_work, &envelope.body)
        .unwrap();
    let mut replacement = custody_work.clone();
    replacement.work.nonce_end += 1;
    replacement.sign(coordinator).unwrap();
    assert!(
        journal
            .finish(&reservation, &replacement, &envelope.body)
            .is_err()
    );
    drop(journal);
    let mut journal = crate::work_journal_v2::Journal::reopen(
        &journal_path,
        genesis.genesis,
        genesis.fingerprint,
        &rotation.current,
    )
    .unwrap();
    let saved = journal.lookup(reservation.worker()).unwrap().unwrap();
    assert!(saved.0 == custody_work && saved.1 == envelope.body);
    let second = journal.reserve(reservation.worker(), 0).unwrap();
    assert_eq!(second.ticket(), 2);
    assert!(
        journal
            .finish(&reservation, &custody_work, &envelope.body)
            .is_err()
    );
    drop(journal); // Crash after reservation consumes ticket 2 without delivery.
    let mut journal = crate::work_journal_v2::Journal::reopen(
        &journal_path,
        genesis.genesis,
        genesis.fingerprint,
        &rotation.current,
    )
    .unwrap();
    assert!(journal.lookup(reservation.worker()).unwrap().is_none());
    assert_eq!(
        journal.reserve(reservation.worker(), 0).unwrap().ticket(),
        3
    );
    assert_eq!(
        journal.reserve(reservation.worker(), 10).unwrap().ticket(),
        11
    );
    assert!(journal.reserve(reservation.worker(), u64::MAX).is_err());
    assert_eq!(
        journal.reserve(reservation.worker(), 0).unwrap().ticket(),
        12
    );
    drop(journal);
    assert!(
        crate::work_journal_v2::Journal::reopen(
            &journal_path,
            genesis.genesis,
            genesis.fingerprint,
            &rotation.proposed
        )
        .is_err()
    );
    std::fs::remove_file(&journal_path).unwrap();
    #[cfg(target_os = "linux")]
    let node_directory = {
        use std::os::unix::fs::PermissionsExt;
        // The qualification runner supplies a fresh protected TMPDIR. Keep generated public
        // synthetic vault evidence there rather than adding files to immutable source inputs.
        let p = std::env::temp_dir()
            .join(format!("synthetic-public-node-{}", hex::encode(random)));
        std::fs::create_dir(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        crate::node_control_custody::EncryptedNodeKey::publish_current_generation(
            &chain,
            &genesis,
            node,
            &p,
            &encrypted_old,
            password,
        )
        .unwrap();
        assert!(
            crate::node_control_custody::EncryptedNodeKey::unlock_generation_file(
                &chain, &genesis, node, &p, password
            )
            .is_ok()
        );
        p
    };
    let new_context = crate::node_authority_v2::custody_context(
        genesis.genesis,
        genesis.fingerprint,
        node,
        1,
        &rotation.proposed,
    )
    .unwrap();
    let encrypted_new = new.seal_for(password, 2, &new_context).unwrap();
    #[cfg(target_os = "linux")]
    let proposed_directory = {
        let wrong_generation = new.seal_for(password, 3, &new_context).unwrap();
        assert!(
            crate::node_generation_preparation_v2::publish(
                &chain,
                rotation,
                &node_directory,
                &wrong_generation,
                password,
            )
            .is_err()
        );
        crate::node_generation_preparation_v2::tests::before_install(
            &chain,
            rotation,
            &node_directory,
            &encrypted_old,
            &encrypted_new,
            password,
        )
    };
    assert!(
        crate::node_control_custody::EncryptedNodeKey::unlock(
            &chain,
            &genesis,
            node,
            &encrypted_new,
            password
        )
        .is_err()
    );
    let mut premature = envelope.clone();
    assert!(premature.certificate.votes[0].sign(new).is_err());
    premature.certificate.votes[0].signature.ed448[0] ^= 1;
    assert!(chain.commit(&premature).is_err());
    assert_eq!(chain.load().unwrap().0.height, 0);
    // Fail after staging both retirement and replacement, at proof-index tip
    // installation. No portion of the rotation may survive the transaction.
    let fault = rusqlite::Connection::open(&path).unwrap();
    fault.execute_batch("CREATE TRIGGER fail_rotation_tip BEFORE UPDATE ON state_merkle_tip BEGIN SELECT RAISE(ABORT,'synthetic rotation failure'); END;").unwrap();
    assert!(chain.commit(&envelope).is_err());
    fault
        .execute_batch("DROP TRIGGER fail_rotation_tip;")
        .unwrap();
    drop(fault);
    let (unchanged, rolled_back) = chain.load().unwrap();
    assert_eq!(unchanged.height, 0);
    assert_eq!(unchanged.root, root);
    assert!(rolled_back.records().unwrap() == state.records().unwrap());
    assert!(rolled_back.retired_continuity_v2.is_empty());
    assert!(rolled_back.node_key_history_v2.is_empty());
    assert_eq!(
        rolled_back
            .continuity_keys_v2
            .get(node)
            .unwrap()
            .admission()
            .key_generation,
        1
    );
    assert!(chain.commit(&envelope).unwrap());
    assert!(!chain.commit(&envelope).unwrap());
    assert!(
        probe_actor
            .sign_work_probe(&chain, &probe_request, &mut probe_backend)
            .is_err()
    );
    assert_eq!(probe_backend.calls, 1);
    assert_eq!(probe_backend.counter, 100);
    let (head, installed) = chain.load().unwrap();
    assert_eq!(head.height, 1);
    assert!(installed.records().unwrap() == prepared.state.records().unwrap());
    assert!(chain.execution_parent(0).unwrap().1.records().unwrap() == state.records().unwrap());
    drop(chain);
    let chain =
        CanonicalStore::open_trusted_genesis(&path, &genesis, &state, root, 1000, parent.target)
            .unwrap();
    let (_, restored) = chain.load().unwrap();
    assert!(restored.records().unwrap() == prepared.state.records().unwrap());
    let anchor = FinalizedAnchor {
        height: 1,
        block: envelope.block_hash(),
        ..genesis.clone()
    };
    let before_retired = custody_work.clone();
    assert!(
        old_custody
            .authorize_work(&chain, &genesis, &mut custody_work, &envelope.body)
            .is_err()
    );
    assert!(
        old_custody
            .authorize_work(&chain, &anchor, &mut custody_work, &envelope.body)
            .is_err()
    );
    assert!(custody_work == before_retired);
    let new_pins = chain.current_node_authority(&anchor, node).unwrap();
    #[cfg(target_os = "linux")]
    crate::node_generation_preparation_v2::tests::after_install(
        &chain,
        rotation,
        &anchor,
        &proposed_directory,
        &encrypted_new,
        password,
    );
    assert_eq!(new_pins.descriptor(), rotation.proposed);
    assert_eq!(new_pins.context(), new_context);
    assert!(chain.current_node_authority(&genesis, node).is_err());
    assert!(
        crate::node_control_custody::EncryptedNodeKey::unlock(
            &chain,
            &anchor,
            node,
            &encrypted_old,
            password
        )
        .is_err()
    );
    let new_custody = crate::node_control_custody::EncryptedNodeKey::unlock(
        &chain,
        &anchor,
        node,
        &encrypted_new,
        password,
    )
    .unwrap();
    #[cfg(target_os = "linux")]
    {
        // A retained old file never authorizes a new canonical generation.
        assert!(
            crate::node_control_custody::EncryptedNodeKey::unlock_generation_file(
                &chain,
                &anchor,
                node,
                &node_directory,
                password
            )
            .is_err()
        );
        assert!(
            crate::node_control_custody::EncryptedNodeKey::publish_current_generation(
                &chain,
                &anchor,
                node,
                &node_directory,
                &encrypted_old,
                password
            )
            .is_err()
        );
        crate::node_control_custody::EncryptedNodeKey::publish_current_generation(
            &chain,
            &anchor,
            node,
            &node_directory,
            &encrypted_new,
            password,
        )
        .unwrap();
        assert!(
            crate::node_control_custody::EncryptedNodeKey::publish_current_generation(
                &chain,
                &anchor,
                node,
                &node_directory,
                &encrypted_new,
                password
            )
            .is_err()
        );
        assert!(
            crate::node_control_custody::EncryptedNodeKey::unlock_generation_file(
                &chain,
                &anchor,
                node,
                &node_directory,
                password
            )
            .is_ok()
        );
        assert!(
            crate::node_control_custody::EncryptedNodeKey::unlock_generation_file(
                &chain,
                &genesis,
                node,
                &node_directory,
                password
            )
            .is_err()
        );
    }
    let mut continuity_rotation = KeyRotate {
        parent: anchor.clone(),
        nonce: [78; 32],
        sequence: 2,
        old_key_generation: 1,
        binding: restored.membership_v2.get(node).unwrap().binding().clone(),
    };
    continuity_rotation.binding.node_signer = Some(rotation.proposed.clone());
    continuity_rotation.binding.admission.key_generation = 2;
    continuity_rotation.binding.admission.continuity_descriptor =
        replacement_continuity.public().descriptor(2).unwrap();
    continuity_rotation.binding.admission.supervised_nonce =
        continuity_rotation.admission_nonce().unwrap();
    continuity_rotation
        .binding
        .admission
        .prove_continuity(replacement_continuity)
        .unwrap();
    continuity_rotation.binding.admission.quote = quote(
        ak,
        profile,
        continuity_rotation.binding.admission.challenge().unwrap(),
    );
    continuity_rotation
        .binding
        .admission
        .authorize(owner, 1)
        .unwrap();
    continuity_rotation.binding.possession = HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    };
    assert!(
        continuity_rotation
            .verify(&restored, &anchor, head.root)
            .is_err()
    );
    assert!(
        chain
            .validate_node_continuity_rotation(node, &continuity_rotation)
            .is_ok()
    );
    for mutation in 0..6 {
        let mut bad = continuity_rotation.clone();
        match mutation {
            0 => bad.binding.admission.authorization.ed448[0] ^= 1,
            1 => bad.binding.admission.authorization.fndsa[0] ^= 1,
            2 => bad.binding.admission.quote[0] ^= 1,
            3 => bad.binding.admission.possession.fndsa[0] ^= 1,
            4 => bad.parent.block[0] ^= 1,
            _ => bad.binding.node_signer = None,
        }
        let before = bad.clone();
        assert!(
            new_custody
                .authorize_continuity_rotation(&chain, &mut bad)
                .is_err()
        );
        assert!(bad == before);
    }
    let before = continuity_rotation.clone();
    assert!(
        old_custody
            .authorize_continuity_rotation(&chain, &mut continuity_rotation)
            .is_err()
    );
    assert!(continuity_rotation == before);
    new_custody
        .authorize_continuity_rotation(&chain, &mut continuity_rotation)
        .unwrap();
    continuity_rotation
        .verify(&restored, &anchor, head.root)
        .unwrap();
    let mut exit = crate::continuity_exit_v2::Exit {
        genesis: anchor.genesis,
        fingerprint: anchor.fingerprint,
        height: 2,
        parent_anchor: anchor.id(),
        node,
        hardware_generation: 1,
        sequence: 2,
        authorizer: rotation.proposed.clone(),
        signature: HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
    };
    let untouched = exit.clone();
    assert!(
        old_custody
            .authorize_exit(&chain, &anchor, &mut exit)
            .is_err()
    );
    assert!(exit == untouched);
    new_custody
        .authorize_exit(&chain, &anchor, &mut exit)
        .unwrap();
    exit.verify(&anchor, &new_pins.control(), &restored.wallets)
        .unwrap();
    let proposed = HybridKey::generate(Role::Node).unwrap();
    let mut next_rotation = crate::node_key_rotate_v2::NodeKeyRotate {
        parent: anchor.clone(),
        node,
        hardware_generation: 1,
        sequence: 2,
        current: rotation.proposed.clone(),
        proposed: proposed.public().descriptor(3).unwrap(),
        authorizer: rotation.proposed.clone(),
        authorization: HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
        possession: HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
    };
    let unsigned = next_rotation.clone();
    assert!(
        new_custody
            .authorize_rotation(&chain, &mut next_rotation)
            .is_err()
    );
    assert!(next_rotation == unsigned);
    next_rotation.sign_possession(&proposed).unwrap();
    new_custody
        .authorize_rotation(&chain, &mut next_rotation)
        .unwrap();
    next_rotation
        .verify(&anchor, &new_pins.control(), &restored.wallets)
        .unwrap();
    let after = HeightAuthority::from_state(&restored, anchor, head.root).unwrap();
    assert_eq!(after.voters[&node].public, *old.public());
    assert_eq!(
        restored
            .membership_v2
            .get(node)
            .unwrap()
            .current_node_descriptor(),
        rotation.proposed
    );
    let next_parent = WorkParent {
        height: 1,
        block: envelope.block_hash(),
        ancestor_timestamps: vec![1000, 1100],
        ..parent
    };
    let next_candidate = Candidate {
        height: 2,
        parent: envelope.block_hash(),
        timestamp: 1160,
        ..envelope.header.candidate.clone()
    };
    assert!(
        restored
            .work_context_v2(&next_parent, &next_candidate)
            .is_err()
    );
    drop(chain);
    std::fs::remove_file(path).unwrap();
}
