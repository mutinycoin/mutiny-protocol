use ed25519_dalek::{Signer, SigningKey};
use mutiny_consensus_v8::{Error, NETWORK_ID, licenses::*, transactions::address};
fn fixture() -> (LicenseBook, BindWorker) {
    let owner = SigningKey::from_bytes(&[11; 32]);
    let worker = SigningKey::from_bytes(&[12; 32]);
    let mut book = LicenseBook::default();
    book.licenses.insert(
        [3; 32],
        LicenseRecord {
            id: [3; 32],
            genesis: [1; 32],
            owner: address(&owner.verifying_key().to_bytes()),
            issuance: [4; 32],
            index: 0,
            issue_height: 0,
            active_worker: None,
            assignment_sequence: 0,
        },
    );
    let mut b = BindWorker {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        license: [3; 32],
        sequence: 1,
        valid_until_height: 100,
        owner_public: owner.verifying_key().to_bytes(),
        worker: [0; 32],
        worker_public: worker.verifying_key().to_bytes(),
        coordinator_public: [13; 32],
        effective_epoch: 2,
        owner_signature: [0; 64],
        worker_signature: [0; 64],
    };
    b.worker = b.worker_id();
    b.owner_signature = owner.sign(&b.signing_digest(false)).to_bytes();
    b.worker_signature = worker.sign(&b.signing_digest(true)).to_bytes();
    (book, b)
}
#[test]
fn owner_and_worker_both_authorize_binding_and_activation_is_not_reversible_by_time() {
    let (mut book, b) = fixture();
    let worker = b.worker_id();
    let raw = b.encode();
    assert_eq!(BindWorker::decode(&raw).unwrap(), b);
    let l = &book.licenses[&b.license];
    assert_eq!(LicenseRecord::decode(&l.encode()).unwrap(), *l);
    let mut bad = b.clone();
    bad.worker_signature[0] ^= 1;
    assert_eq!(
        book.schedule(bad, [1; 32], [2; 32], 1, 1),
        Err(Error::BadSignature)
    );
    assert!(book.pending.is_empty());
    let mut bad = b.clone();
    bad.owner_signature[0] ^= 1;
    assert_eq!(
        book.schedule(bad, [1; 32], [2; 32], 1, 1),
        Err(Error::BadSignature)
    );
    assert_eq!(
        book.schedule(b.clone(), [1; 32], [9; 32], 1, 1),
        Err(Error::WrongFingerprint)
    );
    book.schedule(b.clone(), [1; 32], [2; 32], 1, 1).unwrap();
    assert_eq!(
        book.schedule(b.clone(), [1; 32], [2; 32], 1, 1),
        Err(Error::Duplicate)
    );
    book.activate_due(1).unwrap();
    assert!(book.active(b.license, worker, 1).is_err());
    book.activate_due(2).unwrap();
    book.active(b.license, worker, 2).unwrap();
    book.activate_due(1).unwrap();
    assert_eq!(book.licenses[&b.license].active_worker, Some(worker));
    assert!(book.active(b.license, worker, 1).is_err()); // stale-time work cannot borrow a future activation
    assert_eq!(
        book.schedule(b.clone(), [1; 32], [2; 32], 3, 2),
        Err(Error::StaleSequence)
    );
    for n in 0..raw.len() {
        assert!(BindWorker::decode(&raw[..n]).is_err());
    }
}

#[test]
fn licensed_execution_derives_authority_owner_and_ticket_state_from_parent() {
    use mutiny_consensus_v8::{blocks::BlockBody, execution::*, pow::*};
    let (mut book, mut binding) = fixture();
    let coordinator = SigningKey::from_bytes(&[13; 32]);
    binding.coordinator_public = coordinator.verifying_key().to_bytes();
    binding.owner_signature = SigningKey::from_bytes(&[11; 32])
        .sign(&binding.signing_digest(false))
        .to_bytes();
    binding.worker_signature = SigningKey::from_bytes(&[12; 32])
        .sign(&binding.signing_digest(true))
        .to_bytes();
    book.schedule(binding.clone(), [1; 32], [2; 32], 1, 1)
        .unwrap();
    book.activate_due(2).unwrap();
    let worker = binding.worker_id();
    let state = State {
        licenses: book,
        ..State::default()
    };
    let before = state.root().unwrap();
    let parent = WorkParent {
        genesis: [1; 32],
        fingerprint: [2; 32],
        block: [14; 32],
        height: 10,
        t0: 0,
        target: [255; 32],
        ancestor_timestamps: vec![120; 11],
    };
    let owner = state.licenses.licenses[&binding.license].owner;
    let body = BlockBody {
        height: 11,
        reward_owner: owner,
        fees: 0,
        transactions: vec![],
        operations: vec![],
    };
    // Preparation's numeric ticket update is acyclic: no AuthorityID/BlockHash
    // is needed to execute or derive post-StateRoot.
    let mut preparation = state.clone();
    preparation
        .licenses
        .workers
        .get_mut(&worker)
        .unwrap()
        .last_accepted_ticket = 1;
    let prepared = preparation
        .execute_transfers(
            parent.genesis,
            parent.fingerprint,
            parent.block,
            owner,
            &body,
        )
        .unwrap();
    let candidate = Candidate {
        network: NETWORK_ID,
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        parent: parent.block,
        height: 11,
        timestamp: 121,
        body_root: body.root().unwrap(),
        state_root: prepared.root,
        license: binding.license,
        worker,
        target: parent.target,
    };
    let authority = WorkAuthority {
        candidate: candidate.clone(),
        assignment_sequence: 1,
        ticket_sequence: 1,
        coordinator: coordinator.verifying_key().to_bytes(),
        nonce_start: 0,
        nonce_end: u64::MAX,
        epoch: 2,
    };
    let signature = coordinator.sign(&authority.id()).to_bytes();
    let header = WorkHeader {
        candidate,
        authority: authority.id(),
        nonce: 0,
    };
    let executed = state
        .execute_licensed(&parent, &header, &authority, &signature, &body)
        .unwrap();
    assert_eq!(executed.state, prepared.state);
    assert_eq!(state.root().unwrap(), before);
    assert_eq!(
        executed.state.licenses.workers[&worker].last_accepted_ticket,
        1
    );
    assert!(
        executed
            .state
            .execute_licensed(&parent, &header, &authority, &signature, &body)
            .is_err()
    );
    let mut forged = authority.clone();
    let attacker = SigningKey::from_bytes(&[99; 32]);
    forged.coordinator = attacker.verifying_key().to_bytes();
    let mut forged_header = header.clone();
    forged_header.authority = forged.id();
    assert!(
        state
            .execute_licensed(
                &parent,
                &forged_header,
                &forged,
                &attacker.sign(&forged.id()).to_bytes(),
                &body
            )
            .is_err()
    );
    let mut wrong_root = authority.clone();
    wrong_root.candidate.state_root[0] ^= 1;
    let wrong_header = WorkHeader {
        candidate: wrong_root.candidate.clone(),
        authority: wrong_root.id(),
        nonce: 0,
    };
    assert!(
        state
            .execute_licensed(
                &parent,
                &wrong_header,
                &wrong_root,
                &coordinator.sign(&wrong_root.id()).to_bytes(),
                &body
            )
            .is_err()
    );
    assert_eq!(state.root().unwrap(), before);
}
