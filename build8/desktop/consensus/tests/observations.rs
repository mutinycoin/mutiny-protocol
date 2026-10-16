use ed25519_dalek::{Signer, SigningKey};
use mutiny_consensus_v8::{observations::*, pow::*};
#[test]
fn bounded_sequence_hash_chain_checkpoint_atomic_restart_and_replay() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/OBSERVATION-FIXTURE-V1.json"
    ))
    .unwrap();
    let (mut authority, mut signature) = WorkAuthority::from_envelope(
        &hex::decode(fixture["authority_hex"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let work = hex::decode(fixture["work_hex"].as_str().unwrap()).unwrap();
    let mut header = WorkHeader::decode(&work[WORK_DOMAIN.len() + 1..]).unwrap();
    let c = &header.candidate;
    let context = WorkContext {
        genesis: c.genesis,
        fingerprint: c.fingerprint,
        parent: c.parent,
        parent_height: 0,
        t0: 1000,
        target: c.target,
        license: c.license,
        worker: c.worker,
        coordinator: authority.coordinator,
        assignment_sequence: 1,
        last_accepted_ticket: 0,
        ancestor_timestamps: vec![1000],
    };
    let key = SigningKey::from_bytes(&[90; 32]);
    let mut salt = [0; 8];
    getrandom::getrandom(&mut salt).unwrap();
    let path = std::env::temp_dir().join(format!(
        "build8-bounded-observations-{}.sqlite",
        hex::encode(salt)
    ));
    let mut store = ObservationStore::open(&path, c.genesis, c.fingerprint).unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    let first = Submission {
        sequence: 1,
        previous: [0; 32],
        work: work.clone(),
    };
    db.execute_batch("CREATE TRIGGER fail_checkpoint BEFORE INSERT ON observation_checkpoint BEGIN SELECT RAISE(ABORT,'injected'); END").unwrap();
    assert!(
        store
            .accept(&first, &authority, &signature, &context, &key)
            .is_err()
    );
    assert_eq!(store.total(c.worker).unwrap(), 0);
    db.execute_batch("DROP TRIGGER fail_checkpoint").unwrap();
    let mut receipt = store
        .accept(&first, &authority, &signature, &context, &key)
        .unwrap();
    assert_eq!(
        store.retry(c.worker, &first).unwrap(),
        Some(receipt.clone())
    );
    if let Ok(output) = std::env::var("BUILD8_OBSERVATION_FIXTURE_OUTPUT") {
        use std::io::Write;
        let fixture = serde_json::json!({"schema":"BUILD8-OBSERVATION-FIXTURE-V2","actual_genesis":false,"fixture_target":"MAXIMUM_SOFTWARE_TEST_ONLY","work_hex":hex::encode(&work),"submission_hex":hex::encode(first.encode()),"authority_hex":hex::encode(authority.envelope(&signature)),"receipt_hex":hex::encode(receipt.encode()),"coordinator_public":hex::encode(context.coordinator),"result_id":hex::encode(receipt.result),"accepted_total":1,"sequence":1,"chain":hex::encode(receipt.chain)});
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)
            .unwrap();
        f.write_all(serde_json::to_string_pretty(&fixture).unwrap().as_bytes())
            .unwrap();
        f.sync_all().unwrap();
    }
    let relabeled = Submission {
        sequence: 2,
        previous: receipt.chain,
        work: work.clone(),
    };
    assert!(
        store
            .accept(&relabeled, &authority, &signature, &context, &key)
            .is_err()
    );
    let mut last = first.clone();
    for sequence in 2..=128 {
        authority.ticket_sequence = sequence;
        authority.nonce_end = u64::MAX;
        header.authority = authority.id();
        header.nonce = sequence;
        signature = key.sign(&authority.id()).to_bytes();
        last = Submission {
            sequence,
            previous: receipt.chain,
            work: header.work_bytes(),
        };
        let mut wrong = last.clone();
        wrong.previous[0] ^= 1;
        assert!(
            store
                .accept(&wrong, &authority, &signature, &context, &key)
                .is_err()
        );
        receipt = store
            .accept(&last, &authority, &signature, &context, &key)
            .unwrap();
        assert_eq!(receipt.total, sequence);
    }
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM observation_checkpoint", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        1
    );
    drop(store);
    let mut store = ObservationStore::open(&path, context.genesis, context.fingerprint).unwrap();
    assert_eq!(
        store
            .accept(&last, &authority, &signature, &context, &key)
            .unwrap(),
        receipt
    );
    assert!(store.retry(context.worker, &first).is_err());
    assert_eq!(store.total(context.worker).unwrap(), 128);
    let mut conflict = last.clone();
    *conflict.work.last_mut().unwrap() ^= 1;
    assert!(store.retry(context.worker, &conflict).is_err());
    assert!(store.retry([99; 32], &last).is_err());
    db.execute(
        "UPDATE observation_checkpoint SET receipt=zeroblob(310)",
        [],
    )
    .unwrap();
    drop(store);
    assert!(ObservationStore::open(&path, context.genesis, context.fingerprint).is_err());
    drop(db);
    for suffix in ["", "-wal", "-shm"] {
        let p = std::path::PathBuf::from(format!("{}{suffix}", path.display()));
        if p.exists() {
            std::fs::remove_file(p).unwrap();
        }
    }
}
