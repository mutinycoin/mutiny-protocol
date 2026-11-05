use ed25519_dalek::SigningKey;
use mutiny_consensus_v8::{
    anchors::FinalizedAnchor,
    certificates::{Certificate, Signer, Voter},
    liveness::WorkGate,
    observations::ObservationStore,
    pow::*,
    votes::HeightAuthority,
    work_issuance::*,
    *,
};
use p256::ecdsa::{Signature, SigningKey as TpmFixtureKey, signature::hazmat::PrehashSigner};
use primitive_types::U256;
fn gate() -> WorkGate {
    // SOFTWARE key fixture, never a substitute for physical TPM qualification.
    let key = TpmFixtureKey::from_bytes((&[51; 32]).into()).unwrap();
    let authority = HeightAuthority {
        parent: FinalizedAnchor {
            network: NETWORK_ID,
            genesis: [1; 32],
            fingerprint: [2; 32],
            height: 0,
            block: [3; 32],
        },
        membership: [4; 32],
        reputation: [5; 32],
        attestation: [6; 32],
        voters: [(
            [7; 32],
            Voter {
                key_version: 1,
                public_key: key
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                weight: U256::one(),
            },
        )]
        .into(),
    };
    let mut gate = WorkGate::new(authority, [8; 32], 0).unwrap();
    gate.set_run(true);
    let decision = gate.request(0, [9; 32]).unwrap().unwrap();
    let signature: Signature = key
        .sign_prehash(&decision.signing_digest([7; 32], 1))
        .unwrap();
    gate.accept(
        1,
        &Certificate {
            decision,
            signers: vec![Signer {
                node: [7; 32],
                key_version: 1,
                signature: signature
                    .normalize_s()
                    .unwrap_or(signature)
                    .to_bytes()
                    .into(),
            }],
        },
    )
    .unwrap();
    gate
}
fn body() -> mutiny_consensus_v8::blocks::BlockBody {
    mutiny_consensus_v8::blocks::BlockBody {
        height: 1,
        reward_owner: [8; 32],
        fees: 0,
        transactions: vec![],
        operations: vec![],
    }
}
fn prepare(
    ticket: u64,
    _: &Candidate,
) -> std::result::Result<(Hash, mutiny_consensus_v8::blocks::BlockBody), String> {
    let mut state = [0; 32];
    state[..8].copy_from_slice(&ticket.to_be_bytes());
    Ok((state, body()))
}
fn request(key: &SigningKey, now_ms: u64, unix_ms: u64) -> IssueRequest {
    IssueRequest {
        candidate: Candidate {
            network: NETWORK_ID,
            genesis: [1; 32],
            fingerprint: [2; 32],
            parent: [3; 32],
            height: 1,
            timestamp: 1060,
            body_root: body().root().unwrap(),
            state_root: [5; 32],
            license: [6; 32],
            worker: [7; 32],
            target: [255; 32],
        },
        context: WorkContext {
            genesis: [1; 32],
            fingerprint: [2; 32],
            parent: [3; 32],
            parent_height: 0,
            t0: 1000,
            target: [255; 32],
            license: [6; 32],
            worker: [7; 32],
            coordinator: key.verifying_key().to_bytes(),
            assignment_sequence: 1,
            last_accepted_ticket: 0,
            ancestor_timestamps: vec![1000],
        },
        now_ms,
        unix_ms,
    }
}
// Test-only historical fixed clock adapter. The shipping store API always
// requires its trusted caller's fresh decision reading; this fixture explicitly
// holds time constant to preserve its existing ticket/signature/replay vectors.
trait SoftwareIssueFixture {
    fn issue_fixture(
        &mut self,
        request: IssueRequest,
        key: &SigningKey,
        gate: &mut WorkGate,
        prepare: impl FnOnce(
            u64,
            &Candidate,
        ) -> std::result::Result<
            (Hash, mutiny_consensus_v8::blocks::BlockBody),
            String,
        >,
    ) -> std::result::Result<(IssuedWork, u64), String>;
}
impl SoftwareIssueFixture for WorkIssuanceStore {
    fn issue_fixture(
        &mut self,
        request: IssueRequest,
        key: &SigningKey,
        gate: &mut WorkGate,
        prepare: impl FnOnce(
            u64,
            &Candidate,
        ) -> std::result::Result<
            (Hash, mutiny_consensus_v8::blocks::BlockBody),
            String,
        >,
    ) -> std::result::Result<(IssuedWork, u64), String> {
        let fixed_sample = (request.now_ms, request.unix_ms);
        self.issue(request, key, gate, prepare, || Ok(fixed_sample))
    }
}

#[test]
fn durable_issuance_restart_quorum_epoch_atomic_faults_and_result_recovery() {
    let mut salt = [0; 8];
    getrandom::getrandom(&mut salt).unwrap();
    let root = std::env::temp_dir().join(format!("build8-work-issuance-{}", hex::encode(salt)));
    std::fs::create_dir(&root).unwrap();
    let path = root.join("work.sqlite");
    let obs_path = root.join("observations.sqlite");
    let key = SigningKey::from_bytes(&[52; 32]);
    let public = key.verifying_key().to_bytes();
    let mut store = WorkIssuanceStore::open(&path, [1; 32], [2; 32], public).unwrap();
    let mut gate = gate();
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("CREATE TRIGGER fail_ticket BEFORE INSERT ON work_tickets BEGIN SELECT RAISE(ABORT,'injected failure'); END").unwrap();
    assert!(
        store
            .issue_fixture(request(&key, 2, 1060000), &key, &mut gate, prepare)
            .is_err()
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM issued_work", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        0
    );
    db.execute_batch("DROP TRIGGER fail_ticket").unwrap();
    let (first, ttl) = store
        .issue_fixture(request(&key, 3, 1060123), &key, &mut gate, prepare)
        .unwrap();
    assert_eq!(ttl, 59877);
    assert_eq!(first.authority.ticket_sequence, 1);
    let id = first.authority.id();
    drop(store);
    let mut store = WorkIssuanceStore::open(&path, [1; 32], [2; 32], public).unwrap();
    assert!(store.lookup(id, [99; 32]).is_err());
    let recovered = store.lookup(id, [7; 32]).unwrap();
    assert_eq!(recovered.authority, first.authority);
    assert_eq!(recovered.signature, first.signature);
    let (next, _) = store
        .issue_fixture(request(&key, 4, 1060124), &key, &mut gate, prepare)
        .unwrap();
    assert_eq!(next.authority.ticket_sequence, 2);
    let mut ahead = request(&key, 5, 1060125);
    ahead.context.last_accepted_ticket = 100;
    assert_eq!(
        store
            .issue_fixture(ahead, &key, &mut gate, prepare)
            .unwrap()
            .0
            .authority
            .ticket_sequence,
        101
    );
    let mut wrong = request(&key, 6, 1060126);
    wrong.context.parent = [99; 32];
    assert!(
        store
            .issue_fixture(wrong, &key, &mut gate, prepare)
            .is_err()
    );
    assert!(
        store
            .issue_fixture(request(&key, 7, 1120000), &key, &mut gate, prepare)
            .is_err()
    );
    let (_, ttl) = store
        .issue_fixture(request(&key, 359999, 1060999), &key, &mut gate, prepare)
        .unwrap();
    assert_eq!(ttl, 1);
    assert!(
        store
            .issue_fixture(request(&key, 360000, 1061000), &key, &mut gate, prepare)
            .is_err()
    );
    // Work expires operationally, but its valid pending result is still
    // accountable after restart; that receipt does not finalize a stale block.
    let header = WorkHeader {
        candidate: recovered.authority.candidate.clone(),
        authority: id,
        nonce: 7,
    };
    let mut observations = ObservationStore::open(&obs_path, [1; 32], [2; 32]).unwrap();
    let receipt = observations
        .accept(
            &mutiny_consensus_v8::observations::Submission {
                sequence: 1,
                previous: [0; 32],
                work: header.work_bytes(),
            },
            &recovered.authority,
            &recovered.signature,
            &recovered.context,
            &key,
        )
        .unwrap();
    drop(observations);
    let mut observations = ObservationStore::open(&obs_path, [1; 32], [2; 32]).unwrap();
    assert_eq!(
        observations
            .accept(
                &mutiny_consensus_v8::observations::Submission {
                    sequence: 1,
                    previous: [0; 32],
                    work: header.work_bytes()
                },
                &recovered.authority,
                &recovered.signature,
                &recovered.context,
                &key
            )
            .unwrap(),
        receipt
    );
    assert_eq!(observations.total([7; 32]).unwrap(), 1);
    let mut fresh_gate = crate::gate();
    let mut exhausted = request(&key, 2, 1061000);
    exhausted.context.last_accepted_ticket = u64::MAX;
    assert!(
        store
            .issue_fixture(exhausted, &key, &mut fresh_gate, prepare)
            .is_err()
    );
    assert!(WorkIssuanceStore::open(&path, [8; 32], [2; 32], public).is_err());
    db.execute("UPDATE work_tickets SET ticket=?1", [[0u8; 8].as_slice()])
        .unwrap();
    drop(store);
    assert!(WorkIssuanceStore::open(&path, [1; 32], [2; 32], public).is_err());
    drop(observations);
    drop(db);
    for file in [
        "work.sqlite",
        "work.sqlite-wal",
        "work.sqlite-shm",
        "observations.sqlite",
        "observations.sqlite-wal",
        "observations.sqlite-shm",
    ] {
        let p = root.join(file);
        if p.exists() {
            std::fs::remove_file(p).unwrap();
        }
    }
    std::fs::remove_dir(root).unwrap();
}

#[test]
fn decision_clock_refusal_after_prepare_retains_ticket_and_reopens_original_authority() {
    let mut salt = [0; 8];
    getrandom::getrandom(&mut salt).unwrap();
    let root = std::env::temp_dir().join(format!("build8-issue-decision-{}", hex::encode(salt)));
    std::fs::create_dir(&root).unwrap();
    eprintln!("PRESERVED_PUBLIC_ISSUE_STORE_FIXTURE {}", root.display());
    let path = root.join("work.sqlite");
    // Public deterministic software key; no custody or physical counter claim.
    let key = SigningKey::from_bytes(&[52; 32]);
    let public = key.verifying_key().to_bytes();
    let mut store = WorkIssuanceStore::open(&path, [1; 32], [2; 32], public).unwrap();
    let mut gate = crate::gate();
    let (original, _) = store
        .issue_fixture(request(&key, 2, 1060000), &key, &mut gate, prepare)
        .unwrap();
    let original_id = original.authority.id();
    let original_envelope = original.authority.envelope(&original.signature);
    for (sample, expected) in [
        (
            Err("Qualified clock unavailable".to_string()),
            "Qualified clock unavailable",
        ),
        (Ok((4, 1120000)), "Candidate MiningEpoch is not current"),
        (Ok((360000, 1060000)), "WrongAnchor"),
        (Ok((1, 1060000)), "InvalidCounter"),
    ] {
        let mut gate = crate::gate();
        let prepared = std::cell::Cell::new(false);
        let refused = store.issue(
            request(&key, 3, 1060000),
            &key,
            &mut gate,
            |ticket, candidate| {
                assert_eq!(ticket, 2);
                prepared.set(true);
                prepare(ticket, candidate)
            },
            || {
                assert!(
                    prepared.get(),
                    "decision clock is sampled after real preparation"
                );
                sample
            },
        );
        assert!(refused.err().unwrap().contains(expected));
        let db = rusqlite::Connection::open(&path).unwrap();
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM issued_work", [], |row| row
                .get::<_, u64>(0))
                .unwrap(),
            1
        );
        let ticket: Vec<u8> = db
            .query_row("SELECT ticket FROM work_tickets", [], |row| row.get(0))
            .unwrap();
        assert_eq!(ticket, 1u64.to_be_bytes());
        drop(db);
        drop(store);
        store = WorkIssuanceStore::open(&path, [1; 32], [2; 32], public).unwrap();
        let recovered = store.lookup(original_id, [7; 32]).unwrap();
        assert_eq!(
            recovered.authority.envelope(&recovered.signature),
            original_envelope
        );
    }
    let mut gate = crate::gate();
    let (next, _) = store
        .issue_fixture(request(&key, 3, 1060000), &key, &mut gate, prepare)
        .unwrap();
    assert_eq!(
        next.authority.ticket_sequence, 2,
        "all refusals roll back ticket selection"
    );
}

#[test]
fn decision_clock_caps_lifetime_at_fresh_epoch_and_quorum_expiry() {
    for (decision_now, decision_unix) in [(4, 1119999), (359999, 1060000)] {
        let mut salt = [0; 8];
        getrandom::getrandom(&mut salt).unwrap();
        let root =
            std::env::temp_dir().join(format!("build8-issue-lifetime-{}", hex::encode(salt)));
        std::fs::create_dir(&root).unwrap();
        eprintln!("PRESERVED_PUBLIC_ISSUE_STORE_FIXTURE {}", root.display());
        let key = SigningKey::from_bytes(&[52; 32]);
        let mut store = WorkIssuanceStore::open(
            &root.join("work.sqlite"),
            [1; 32],
            [2; 32],
            key.verifying_key().to_bytes(),
        )
        .unwrap();
        let mut gate = crate::gate();
        let (issued, lifetime) = store
            .issue(request(&key, 2, 1060000), &key, &mut gate, prepare, || {
                Ok((decision_now, decision_unix))
            })
            .unwrap();
        assert_eq!(
            lifetime, 1,
            "fresh reading caps both epoch and original quorum lease"
        );
        assert_eq!(issued.authority.epoch, 1);
        assert_eq!(issued.authority.ticket_sequence, 1);
        assert!(!issued.offer([42; 32], lifetime).unwrap().is_empty());
    }
}
