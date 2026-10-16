#![cfg(feature = "dividend-test-fixtures")]
//! TEST-VALUE complete-object pool through real hybrid blocks, replay and reopen.
#[path = "../../desktop/src/wallet_host_fixture_licenses.rs"]
mod licenses;
#[path = "support/wallet_host_fixture_tpm.rs"]
mod tpm;
include!("support/dividend_rig.rs");
use mutiny_consensus_v8::{
    finality_v2::StoreError,
    submission_pool_v1::{MAX_BYTES, PoolError, SubmissionPool},
    submission_v1::{self as submission, Reason, Status, StatusEntry, StatusReport, Submission},
};
use rusqlite::Connection;
use std::path::Path;
#[path="support/public_child_capture.rs"]
mod public_child_capture;
fn pool(r: &Rig) -> SubmissionPool {
    SubmissionPool::open(
        &r.base.join("submissions.sqlite"),
        r.parent.genesis,
        r.parent.fingerprint,
        MAX_BYTES,
    )
    .unwrap()
}
fn archive_row_seal(db: &Connection, g: Hash, f: Hash) -> Hash {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"MUTINY-BUILD8-LOCAL-ARCHIVE-SEAL-V1");
    digest.update(g);
    digest.update(f);
    let mut q = db
        .prepare("SELECT id,class,kind,raw,first,last,wire,sig_ok,status FROM entries ORDER BY id")
        .unwrap();
    let mut rows = q.query([]).unwrap();
    while let Some(row) = rows.next().unwrap() {
        for c in 0..9 {
            match row.get_ref(c).unwrap() {
                rusqlite::types::ValueRef::Integer(n) => {
                    digest.update([0]);
                    digest.update(n.to_be_bytes());
                }
                rusqlite::types::ValueRef::Blob(b) => {
                    digest.update([1]);
                    digest.update((b.len() as u64).to_be_bytes());
                    digest.update(b);
                }
                _ => panic!("unexpected test column"),
            }
        }
    }
    digest.finalize().into()
}
#[test]
fn archive_native_signed_scale_reopen_and_queries_do_not_repeat_history_crypto() {
    // Native signatures/exact canonical codecs, local retention scale ONLY.
    // Seed above-consensus expired objects; these are not canonical executions.
    let r = Rig::new(
        fixture_with_treasury(&treasury_key(), 1_200_000),
        "archive-native-scale",
    );
    let p = pool(&r);
    drop(p);
    let path = r.base.join("submissions.sqlite");
    let mut db = Connection::open(&path).unwrap();
    let tx = db.transaction().unwrap();
    let mut ids = Vec::new();
    let begin = std::time::Instant::now();
    for n in 0..320 {
        let raw = claim_op(&r.f, &owner_key(), 0, P, 1, n, addr(&second_key(), 1));
        let object = Submission::decode(1, &raw).unwrap();
        let (first, last) = object.window();
        let report = StatusReport {
            tip_height: 0,
            tip_block: r.parent.block,
            entries: vec![StatusEntry {
                id: object.id,
                status: Status::Expired { last },
            }],
        }
        .encode()
        .unwrap();
        tx.execute(
            "INSERT INTO entries VALUES(?1,?2,?3,?4,?5,?6,?7,1,?8)",
            rusqlite::params![
                object.id.as_slice(),
                object.list,
                object.kind,
                raw,
                first.to_be_bytes().as_slice(),
                last.to_be_bytes().as_slice(),
                object.wire.as_slice(),
                report
            ],
        )
        .unwrap();
        ids.push(object.id);
    }
    tx.commit().unwrap();
    drop(db);
    let signed_ms = begin.elapsed().as_millis();
    let open = std::time::Instant::now();
    let mut p = pool(&r);
    let first_open_ms = open.elapsed().as_millis();
    assert_eq!(p.archive_terminal().unwrap(), 256);
    assert_eq!(p.archive_terminal().unwrap(), 64);
    drop(p);
    let count_before = mutiny_consensus_v8::submission_pool_v1::fixture_archive_signature_checks();
    let open = std::time::Instant::now();
    let p = pool(&r);
    let archive_open_ms = open.elapsed().as_millis();
    let count_after = mutiny_consensus_v8::submission_pool_v1::fixture_archive_signature_checks();
    assert_eq!(count_after - count_before, 320);
    let query = std::time::Instant::now();
    for n in 0..10 {
        assert!(matches!(p.status(ids[n]).unwrap(), Status::Expired { .. }));
    }
    let query10_ms = query.elapsed().as_millis();
    let batch = std::time::Instant::now();
    assert_eq!(p.statuses(&ids[..64]).unwrap().len(), 64);
    let batch64_ms = batch.elapsed().as_millis();
    assert_eq!(
        mutiny_consensus_v8::submission_pool_v1::fixture_archive_signature_checks(),
        count_after
    );
    assert_eq!(p.status([0x55; 32]).unwrap(), Status::Unknown);
    let lookup = Connection::open(p.archive_path().join("lookup.sqlite")).unwrap();
    let nodes: u64 = lookup
        .query_row("SELECT count(*) FROM nodes", [], |row| row.get(0))
        .unwrap();
    assert_eq!(nodes, 639);
    println!(
        "NATIVE-RETENTION-SCALE rows=320 shards=2 nodes={nodes} sign_ms={signed_ms} active_open_ms={first_open_ms} archive_open_ms={archive_open_ms} query10_ms={query10_ms} batch64_ms={batch64_ms} repeated_archive_signature_checks=0; NO CANONICAL EXECUTION CLAIM"
    );
    drop(lookup);
    drop(p);
    // Retain public TEST scale database and its exact raw candidates as evidence.
    drop(r);
}
#[test]
fn canonical_index_scale_uses_actual_executed_records_in_one_verified_snapshot() {
    let mut r = Rig::new(
        fixture_with_treasury(&treasury_key(), 1_200_000),
        "index-canonical-scale",
    );
    r.step(P, &[]);
    let mut ids = Vec::new();
    for group in 0..4 {
        let operations: Vec<_> = (group * 8..group * 8 + 8)
            .map(|n| claim_op(&r.f, &owner_key(), 0, P, 1, n, addr(&second_key(), 1)))
            .collect();
        ids.extend(
            operations
                .iter()
                .map(|raw| Submission::decode(1, raw).unwrap().id),
        );
        // Distinct valid block times must advance above the early-chain median. The claims
        // retain award_epoch=P; only this certified block fixture's mining epoch advances.
        r.step(P + 1 + group, &operations);
        if group == 0 || group == 3 {
            let begin = std::time::Instant::now();
            let records = r.chain.verified_operation_records_many(&ids).unwrap();
            assert_eq!(records.len(), ids.len());
            for id in &ids {
                let rows = records.get(id).unwrap();
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].op_id, *id);
            }
            println!(
                "ACTUAL-CANONICAL-IDX-SCALE records={} canonical_height={} own_replay_batch_ms={}",
                ids.len(),
                r.parent.height,
                begin.elapsed().as_millis()
            );
        }
    }
    let mut queries = ids.clone();
    queries.extend((0u8..32).map(|n| [n; 32]));
    let begin = std::time::Instant::now();
    let records = r.chain.verified_operation_records_many(&queries).unwrap();
    assert_eq!(records.values().filter(|rows| !rows.is_empty()).count(), 32);
    println!(
        "ACTUAL-CANONICAL-IDX-SCALE query_ids=64 found=32 canonical_height={} own_replay_batch_ms={}",
        r.parent.height,
        begin.elapsed().as_millis()
    );
    let p = pool(&r);
    drop(p);
    drop(r); // Retain actual public canonical evidence.
}
#[test]
fn archive_copy_delete_and_catalog_failure_are_atomic_and_reopen_recoverable() {
    let mut r = Rig::new(
        fixture_with_treasury(&treasury_key(), 1_200_000),
        "archive-rollback",
    );
    r.step(P, &[]);
    let raw = claim_op(&r.f, &owner_key(), 0, P, 1, 0, addr(&second_key(), 1));
    let mut p = SubmissionPool::open(
        &r.base.join("submissions.sqlite"),
        r.parent.genesis,
        r.parent.fingerprint,
        raw.len() as u64 * 2 + 16,
    )
    .unwrap();
    r.chain.reconcile_submission_pool(&mut p, P + 1).unwrap();
    let (id, _) = admit(&r, &mut p, P + 1, 1, &raw);
    assert_eq!(p.archive_terminal().unwrap(), 0);
    step_pool(&mut r, &mut p, P + 1, &[]);
    let final_status = p.status(id).unwrap();
    for fault in [1, 2, 3] {
        assert!(matches!(
            p.fixture_archive_fault(fault),
            Err(PoolError::Integrity)
        ));
        assert_eq!(p.status(id).unwrap(), final_status);
        assert_eq!(p.exact_bytes(id).unwrap(), Some((1, raw.clone())));
        assert_eq!(p.tracked_ids().unwrap(), vec![id]);
        let db = Connection::open(r.base.join("submissions.sqlite")).unwrap();
        assert_eq!(
            db.pragma_query_value(None, "user_version", |r| r.get::<_, u64>(0))
                .unwrap(),
            1
        );
        drop(db);
        drop(p);
        p = SubmissionPool::open(
            &r.base.join("submissions.sqlite"),
            r.parent.genesis,
            r.parent.fingerprint,
            raw.len() as u64 * 2 + 16,
        )
        .unwrap();
    }
    let second = claim_op(&r.f, &owner_key(), 0, P, 1, 1, addr(&second_key(), 1));
    let (second_id, _) = admit(&r, &mut p, P + 2, 1, &second);
    step_pool(&mut r, &mut p, P + 2, &[]);
    assert!(raw.len() + second.len() > 4096);
    let next = claim_op(&r.f, &owner_key(), 0, P, 1, 2, addr(&second_key(), 1));
    let (a, s, h) = r.chain.submission_context(1, &next).unwrap();
    assert!(matches!(
        p.admit(&a, &s, &h, P + 3, 1, &next),
        Err(PoolError::Capacity)
    ));
    let error = p.fixture_archive_fault(10).unwrap_err();
    assert!(
        matches!(error,PoolError::Storage(rusqlite::Error::SqliteFailure(e,_)) if e.code==rusqlite::ErrorCode::DiskFull)
    );
    let mut expected_ids = vec![id, second_id];
    expected_ids.sort();
    assert_eq!(p.tracked_ids().unwrap(), expected_ids);
    assert_eq!(p.exact_bytes(id).unwrap(), Some((1, raw.clone())));
    assert_eq!(p.exact_bytes(second_id).unwrap(), Some((1, second)));
    assert_eq!(p.archive_terminal().unwrap(), 2);
    assert!(p.tracked_ids().unwrap().is_empty());
    let (a, s, h) = r.chain.submission_context(1, &next).unwrap();
    assert_eq!(
        p.admit(&a, &s, &h, P + 3, 1, &next).unwrap().1,
        Status::Pending
    );
    assert_eq!(p.status(id).unwrap(), final_status);
    drop(p);
    r.finish();
}
#[test]
fn archive_crash_child() {
    let Some(path) = std::env::var_os("MUTINY_TEST_ARCHIVE_PATH") else {
        return;
    };
    public_child_capture::enter_public_child();
    let g: Hash = hex::decode(std::env::var("MUTINY_TEST_ARCHIVE_GENESIS").unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let f: Hash = hex::decode(std::env::var("MUTINY_TEST_ARCHIVE_FINGERPRINT").unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let fault: u8 = std::env::var("MUTINY_TEST_ARCHIVE_FAULT")
        .unwrap()
        .parse()
        .unwrap();
    let mut p = SubmissionPool::open(Path::new(&path), g, f, MAX_BYTES).unwrap();
    let _ = p.fixture_archive_fault(fault);
    panic!("child crash checkpoint did not run");
}
#[test]
fn archive_abrupt_process_exit_recovers_copy_delete_catalog_and_committed_state() {
    let mut r = Rig::new(
        fixture_with_treasury(&treasury_key(), 1_200_000),
        "archive-process-exit",
    );
    r.step(P, &[]);
    let mut p = pool(&r);
    r.chain.reconcile_submission_pool(&mut p, P + 1).unwrap();
    let raw = claim_op(&r.f, &owner_key(), 0, P, 1, 0, addr(&second_key(), 1));
    let (id, _) = admit(&r, &mut p, P + 1, 1, &raw);
    step_pool(&mut r, &mut p, P + 1, &[]);
    let expected = p.status(id).unwrap();
    drop(p);
    for fault in [101, 102, 103, 104] {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "archive_crash_child", "--nocapture"])
            .env(
                "MUTINY_TEST_ARCHIVE_PATH",
                r.base.join("submissions.sqlite"),
            )
            .env("MUTINY_TEST_ARCHIVE_GENESIS", hex::encode(r.parent.genesis))
            .env(
                "MUTINY_TEST_ARCHIVE_FINGERPRINT",
                hex::encode(r.parent.fingerprint),
            )
            .env("MUTINY_TEST_ARCHIVE_FAULT", fault.to_string());
        public_child_capture::capture_public_child(command,&r.base,75,&format!("archive-fault-{fault}"));
        let p = pool(&r);
        assert_eq!(p.status(id).unwrap(), expected);
        assert_eq!(p.exact_bytes(id).unwrap(), Some((1, raw.clone())));
        assert_eq!(p.tracked_ids().unwrap().is_empty(), fault == 104);
        drop(p);
    }
    // Keep abrupt-exit fixture and its recovery result for evidence inspection.
    drop(r);
}
#[test]
fn archive_derived_update_failure_and_abrupt_exit_preserve_committed_raw_outcomes() {
    let mut r = Rig::new(
        fixture_with_treasury(&treasury_key(), 1_200_000),
        "archive-derived-recovery",
    );
    r.step(P, &[]);
    let mut p = pool(&r);
    r.chain.reconcile_submission_pool(&mut p, P + 1).unwrap();
    let raw = claim_op(&r.f, &owner_key(), 0, P, 1, 0, addr(&second_key(), 1));
    let (id, _) = admit(&r, &mut p, P + 1, 1, &raw);
    step_pool(&mut r, &mut p, P + 1, &[]);
    let expected = p.status(id).unwrap();
    drop(p);
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
        .args(["--exact", "archive_crash_child", "--nocapture"])
        .env(
            "MUTINY_TEST_ARCHIVE_PATH",
            r.base.join("submissions.sqlite"),
        )
        .env("MUTINY_TEST_ARCHIVE_GENESIS", hex::encode(r.parent.genesis))
        .env(
            "MUTINY_TEST_ARCHIVE_FINGERPRINT",
            hex::encode(r.parent.fingerprint),
        )
        .env("MUTINY_TEST_ARCHIVE_FAULT", "105");
    public_child_capture::capture_public_child(command,&r.base,75,"archive-fault-105");
    let mut p = pool(&r);
    assert_eq!(p.status(id).unwrap(), expected);
    assert_eq!(p.exact_bytes(id).unwrap(), Some((1, raw)));
    let second = claim_op(&r.f, &owner_key(), 0, P, 1, 1, addr(&second_key(), 1));
    let (id2, _) = admit(&r, &mut p, P + 2, 1, &second);
    step_pool(&mut r, &mut p, P + 2, &[]);
    let expected2 = p.status(id2).unwrap();
    assert!(matches!(
        p.fixture_archive_fault(5),
        Err(PoolError::Integrity)
    ));
    assert!(matches!(p.status(id2), Err(PoolError::Integrity))); // no stale-root fallback.
    drop(p);
    let p = pool(&r);
    assert_eq!(p.status(id).unwrap(), expected);
    assert_eq!(p.status(id2).unwrap(), expected2);
    assert_eq!(p.exact_bytes(id2).unwrap(), Some((1, second)));
    assert!(p.tracked_ids().unwrap().is_empty());
    drop(p);
    drop(r); // Retain actual abrupt/failure recovered evidence.
}
#[test]
fn archive_inventory_context_seal_and_coherent_signature_forgery_refuse_without_loss() {
    let mut r = Rig::new(
        fixture_with_treasury(&treasury_key(), 1_200_000),
        "archive-integrity",
    );
    r.step(P, &[]);
    let mut p = pool(&r);
    r.chain.reconcile_submission_pool(&mut p, P + 1).unwrap();
    let raw = claim_op(&r.f, &owner_key(), 0, P, 10_000, 0, addr(&second_key(), 1));
    let (id, _) = admit(&r, &mut p, P + 1, 1, &raw);
    step_pool(&mut r, &mut p, P + 1, &[]);
    let expected = p.status(id).unwrap();
    assert_eq!(p.archive_terminal().unwrap(), 1);
    let root = p.archive_path();
    let shard = root.join("shard-00000000000000000000.sqlite");
    let db = Connection::open(&shard).unwrap();
    db.execute("UPDATE context SET fingerprint=?1", [[9u8; 32].as_slice()])
        .unwrap();
    assert!(p.status(id).is_err());
    db.execute(
        "UPDATE context SET fingerprint=?1",
        [r.parent.fingerprint.as_slice()],
    )
    .unwrap();
    assert_eq!(p.status(id).unwrap(), expected);
    let original_status: Vec<u8> = db
        .query_row(
            "SELECT status FROM entries WHERE id=?1",
            [id.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    let altered_status = StatusReport {
        tip_height: r.parent.height,
        tip_block: r.parent.block,
        entries: vec![StatusEntry {
            id,
            status: Status::Expired { last: 10000 },
        }],
    }
    .encode()
    .unwrap();
    db.execute(
        "UPDATE entries SET status=?1 WHERE id=?2",
        rusqlite::params![altered_status, id.as_slice()],
    )
    .unwrap();
    assert!(matches!(p.status(id), Err(PoolError::Integrity)));
    db.execute(
        "UPDATE entries SET status=?1 WHERE id=?2",
        rusqlite::params![original_status, id.as_slice()],
    )
    .unwrap();
    assert_eq!(p.status(id).unwrap(), expected);
    let held = root.with_extension("held-test-archive");
    drop(db);
    drop(p);
    std::fs::rename(&root, &held).unwrap();
    assert!(
        SubmissionPool::open(
            &r.base.join("submissions.sqlite"),
            r.parent.genesis,
            r.parent.fingerprint,
            MAX_BYTES
        )
        .is_err()
    );
    std::fs::rename(&held, &root).unwrap();
    let p = pool(&r);
    assert_eq!(p.status(id).unwrap(), expected);
    let db = Connection::open(&shard).unwrap();
    let mut claim = SignedClaim::decode(&raw).unwrap();
    claim.signature.ed448[0] ^= 1;
    let bad = claim.encode();
    let wire = mutiny_consensus_v8::domain_hash(
        mutiny_consensus_v8::operation_index_v2::WIRE_DOMAIN,
        &bad,
    );
    let Status::Finalized(mut receipt) = expected.clone() else {
        panic!("finality")
    };
    receipt.wire = wire;
    let status = StatusReport {
        tip_height: r.parent.height,
        tip_block: r.parent.block,
        entries: vec![StatusEntry {
            id,
            status: Status::Finalized(receipt),
        }],
    }
    .encode()
    .unwrap();
    db.execute(
        "UPDATE entries SET raw=?1,wire=?2,status=?3 WHERE id=?4",
        rusqlite::params![bad, wire.as_slice(), status, id.as_slice()],
    )
    .unwrap();
    let seal = archive_row_seal(&db, r.parent.genesis, r.parent.fingerprint);
    let main = Connection::open(r.base.join("submissions.sqlite")).unwrap();
    main.execute("UPDATE archive_catalog SET seal=?1", [seal.as_slice()])
        .unwrap();
    assert!(matches!(p.exact_bytes(id), Err(PoolError::Integrity)));
    drop(p);
    assert!(
        SubmissionPool::open(
            &r.base.join("submissions.sqlite"),
            r.parent.genesis,
            r.parent.fingerprint,
            MAX_BYTES
        )
        .is_err()
    );
    assert_eq!(
        db.query_row(
            "SELECT raw FROM entries WHERE id=?1",
            [id.as_slice()],
            |r| r.get::<_, Vec<u8>>(0)
        )
        .unwrap(),
        bad
    );
    // The failed forged archive fixture stays on disk as partial evidence.
    drop(main);
    drop(db);
    drop(r);
}
fn step_pool(r: &mut Rig, p: &mut SubmissionPool, epoch: u64, ops: &[Vec<u8>]) {
    r.chain.reconcile_submission_pool(p, epoch).unwrap();
    let prepared = r
        .chain
        .prepare_pending(Preparation {
            expected_parent: &r.parent,
            pool: p,
            license: r.f.license,
            worker: r.f.worker,
            timestamp: at(epoch),
            ticket: r.ticket,
            operations: ops,
        })
        .unwrap();
    r.commit_prepared(prepared);
    r.chain.reconcile_submission_pool(p, epoch).unwrap();
}
fn admit(r: &Rig, p: &mut SubmissionPool, epoch: u64, list: u8, raw: &[u8]) -> (Hash, Status) {
    let (a, s, h) = r.chain.submission_context(list, raw).unwrap();
    p.admit(&a, &s, &h, epoch, list, raw).unwrap()
}
#[test]
fn complete_claim_is_assembled_finalized_reopened_and_stays_final_after_payout_spent() {
    let mut r = Rig::new(
        fixture_with_treasury(&treasury_key(), 1_200_000),
        "pool-claim",
    );
    r.step(P, &[]);
    let mut p = pool(&r);
    r.chain.reconcile_submission_pool(&mut p, P + 1).unwrap();
    let raw = claim_op(&r.f, &owner_key(), 0, P, 10_000, 0, addr(&second_key(), 1));
    let (id, status) = admit(&r, &mut p, P + 1, 1, &raw);
    assert_eq!(status, Status::Pending);
    assert_eq!(admit(&r, &mut p, P + 1, 1, &raw), (id, Status::Pending));
    assert_eq!(p.exact_bytes(id).unwrap(), Some((1, raw.clone())));
    // A losing local proposal is explicitly unfinalized, then returns to pending.
    p.note_unfinalized(&r.parent, id, r.parent.height + 1, [9; 32])
        .unwrap();
    assert!(matches!(p.status(id).unwrap(), Status::Unfinalized { .. }));
    r.chain.reconcile_submission_pool(&mut p, P + 1).unwrap();
    assert_eq!(p.status(id).unwrap(), Status::Pending);
    step_pool(&mut r, &mut p, P + 1, &[]);
    let finalized = p.status(id).unwrap();
    let Status::Finalized(record) = &finalized else {
        panic!("not finalized")
    };
    assert_eq!(
        r.chain.verified_operation_records(id).unwrap(),
        vec![record.clone()]
    );
    let block = r.chain.canonical_block(record.height).unwrap().unwrap();
    assert_eq!(block.body.operations[record.position as usize], raw);
    assert_eq!(p.archive_terminal().unwrap(), 1);
    assert!(p.tracked_ids().unwrap().is_empty());
    assert_eq!(p.status(id).unwrap(), finalized);
    assert_eq!(admit(&r, &mut p, P + 1, 1, &raw), (id, finalized.clone()));
    let point = OutPoint {
        transaction: id,
        index: 0,
    };
    let pay = transfer(
        &r.f,
        &second_key(),
        1,
        point.clone(),
        5000,
        vec![Output {
            owner: addr(&owner_key(), 1),
            atoms: 5000,
        }],
    );
    let pay_raw = pay.encode().unwrap();
    let (pay_id, _) = admit(&r, &mut p, P + 2, 0, &pay_raw);
    step_pool(&mut r, &mut p, P + 2, &[]);
    assert!(!r.state.coins.contains_key(&point));
    assert_eq!(p.status(id).unwrap(), finalized);
    assert!(matches!(p.status(pay_id).unwrap(), Status::Finalized(_)));
    assert_eq!(p.archive_terminal().unwrap(), 1);
    drop(p);
    let r = r.restart();
    let mut p = pool(&r);
    r.chain.reconcile_submission_pool(&mut p, P + 2).unwrap();
    assert_eq!(p.status(id).unwrap(), finalized);
    assert_eq!(p.exact_bytes(id).unwrap(), Some((1, raw)));
    drop(p);
    r.finish();
}
#[test]
fn atomic_rotation_reserves_inputs_and_authority_and_survives_reopen() {
    let mut f = fixture_with_treasury(&treasury_key(), 1_200_000);
    let point = OutPoint {
        transaction: [0xd2; 32],
        index: 0,
    };
    f.state.coins.insert(
        point.clone(),
        Coin {
            output: Output {
                owner: addr(&treasury_key(), 1),
                atoms: 30_000,
            },
            created_height: 0,
            coinbase: false,
        },
    );
    let mut r = Rig::new(f, "pool-rotation");
    let mut p = pool(&r);
    r.chain.reconcile_submission_pool(&mut p, 1).unwrap();
    let tx = sponsored_rotation(
        &r,
        addr(&owner_key(), 1),
        (&owner_key(), 1),
        (&second_key(), 2),
        &treasury_key(),
        point.clone(),
        20_000,
        10_000,
    );
    let raw = tx.encode().unwrap();
    let (id, _) = admit(&r, &mut p, 1, 0, &raw);
    let pay = transfer(
        &r.f,
        &treasury_key(),
        1,
        point,
        20_000,
        vec![Output {
            owner: addr(&treasury_key(), 1),
            atoms: 10_000,
        }],
    );
    let (a, s, h) = r
        .chain
        .submission_context(0, &pay.encode().unwrap())
        .unwrap();
    assert!(matches!(
        p.admit(&a, &s, &h, 1, 0, &pay.encode().unwrap()),
        Err(PoolError::Conflict)
    ));
    let Transaction::FundedRotation(rotation) = tx else {
        unreachable!()
    };
    let partial =
        mutiny_consensus_v8::funded_rotation_v2::PartialRotation::new(rotation.unsigned.clone());
    assert_eq!(
        Submission::decode(0, &partial.encode().unwrap()),
        Err(Reason::Codec)
    );
    // Same canonical id but altered signature bytes never overwrites or renews it.
    let mut changed = rotation.clone();
    changed.authorize.ed448[0] ^= 1;
    assert_eq!(changed.id().unwrap(), id);
    assert!(matches!(
        p.admit(&a, &s, &h, 1, 0, &changed.encode().unwrap()),
        Err(PoolError::Conflict)
    ));
    assert_eq!(p.exact_bytes(id).unwrap(), Some((0, raw.clone())));
    drop(p);
    let mut p = pool(&r);
    assert_eq!(p.exact_bytes(id).unwrap(), Some((0, raw.clone())));
    step_pool(&mut r, &mut p, 1, &[]);
    assert!(matches!(p.status(id).unwrap(), Status::Finalized(_)));
    let record = r.chain.verified_operation_records(id).unwrap().remove(0);
    assert_eq!(
        r.chain
            .canonical_block(record.height)
            .unwrap()
            .unwrap()
            .body
            .transactions[record.position as usize],
        raw
    );
    drop(p);
    r.finish();
}
#[test]
fn expiry_and_chain_conflict_release_reservations_but_preserve_exact_evidence() {
    let mut f = fixture();
    let point = OutPoint {
        transaction: [0xd3; 32],
        index: 0,
    };
    f.state.coins.insert(
        point.clone(),
        Coin {
            output: Output {
                owner: addr(&owner_key(), 1),
                atoms: 20_000,
            },
            created_height: 0,
            coinbase: false,
        },
    );
    let mut r = Rig::new(f, "pool-expiry");
    let mut p = pool(&r);
    r.chain.reconcile_submission_pool(&mut p, 1).unwrap();
    let Transaction::Transfer(mut tx) = transfer(
        &r.f,
        &owner_key(),
        1,
        point.clone(),
        10_000,
        vec![Output {
            owner: addr(&second_key(), 1),
            atoms: 10_000,
        }],
    ) else {
        unreachable!()
    };
    tx.expiry_height = 1;
    tx.sign_input(0, &owner_key()).unwrap();
    let raw = tx.encode().unwrap();
    let (id, _) = admit(&r, &mut p, 1, 0, &raw);
    r.step(1, &[]);
    r.chain.reconcile_submission_pool(&mut p, 2).unwrap();
    assert_eq!(p.status(id).unwrap(), Status::Expired { last: 1 });
    assert!(p.pending_at(&r.parent, &r.state).unwrap().is_empty());
    assert_eq!(p.exact_bytes(id).unwrap(), Some((0, raw.clone())));
    let next = transfer(
        &r.f,
        &owner_key(),
        1,
        point.clone(),
        11_000,
        vec![Output {
            owner: addr(&second_key(), 1),
            atoms: 9000,
        }],
    );
    let (next_id, _) = admit(&r, &mut p, 2, 0, &next.encode().unwrap());
    let chain_spend = transfer(
        &r.f,
        &owner_key(),
        1,
        point,
        12_000,
        vec![Output {
            owner: addr(&owner_key(), 1),
            atoms: 8000,
        }],
    );
    r.pool.admit(&chain_spend, &r.parent, &r.state).unwrap();
    r.step(2, &[]);
    r.chain.reconcile_submission_pool(&mut p, 3).unwrap();
    assert_eq!(
        p.status(next_id).unwrap(),
        Status::Conflicting {
            reason: Reason::InputSpent,
            height: r.parent.height
        }
    );
    assert_eq!(p.status(id).unwrap(), Status::Expired { last: 1 });
    let conflict = p.status(next_id).unwrap();
    let next_raw = next.encode().unwrap();
    assert_eq!(p.archive_terminal().unwrap(), 2);
    assert!(p.tracked_ids().unwrap().is_empty());
    assert_eq!(p.status(next_id).unwrap(), conflict);
    assert_eq!(p.exact_bytes(next_id).unwrap(), Some((0, next_raw.clone())));
    let (a, s, h) = r.chain.submission_context(0, &raw).unwrap();
    assert_eq!(
        p.admit(&a, &s, &h, 3, 0, &raw).unwrap(),
        (id, Status::Expired { last: 1 })
    );
    let mut alternate = tx.clone();
    alternate.inputs[0].signature.ed448[0] ^= 1;
    assert!(matches!(
        p.admit(&a, &s, &h, 3, 0, &alternate.encode().unwrap()),
        Err(PoolError::Conflict)
    ));
    assert_eq!(p.exact_bytes(id).unwrap(), Some((0, raw.clone())));
    drop(p);
    let mut p = pool(&r);
    r.chain.reconcile_submission_pool(&mut p, 3).unwrap();
    assert!(matches!(
        p.status(next_id).unwrap(),
        Status::Conflicting { .. }
    ));
    drop(p);
    r.finish();
}
#[test]
fn rejected_signature_context_capacity_and_incompatible_schema_leave_no_partial_bundle() {
    let mut f = fixture();
    let point = OutPoint {
        transaction: [0xd4; 32],
        index: 0,
    };
    f.state.coins.insert(
        point.clone(),
        Coin {
            output: Output {
                owner: addr(&owner_key(), 1),
                atoms: 20_000,
            },
            created_height: 0,
            coinbase: false,
        },
    );
    let other = OutPoint {
        transaction: [0xd5; 32],
        index: 0,
    };
    f.state.coins.insert(
        other.clone(),
        Coin {
            output: Output {
                owner: addr(&owner_key(), 1),
                atoms: 20_000,
            },
            created_height: 0,
            coinbase: false,
        },
    );
    let r = Rig::new(f, "pool-atomic");
    let mut p = pool(&r);
    r.chain.reconcile_submission_pool(&mut p, 1).unwrap();
    let Transaction::Transfer(tx) = transfer(
        &r.f,
        &owner_key(),
        1,
        point,
        10_000,
        vec![Output {
            owner: addr(&second_key(), 1),
            atoms: 10_000,
        }],
    ) else {
        unreachable!()
    };
    let raw = tx.encode().unwrap();
    let (a, s, h) = r.chain.submission_context(0, &raw).unwrap();
    let mut bad = tx.clone();
    bad.inputs[0].signature.ed448[0] ^= 1;
    assert!(matches!(
        p.admit(&a, &s, &h, 1, 0, &bad.encode().unwrap()),
        Err(PoolError::Invalid(Reason::Signature))
    ));
    assert!(p.tracked_ids().unwrap().is_empty());
    let mut wrong = tx.clone();
    wrong.genesis = [7; 32];
    wrong.sign_input(0, &owner_key()).unwrap();
    assert!(matches!(
        p.admit(&a, &s, &h, 1, 0, &wrong.encode().unwrap()),
        Err(PoolError::Invalid(Reason::Context))
    ));
    let tiny = r.base.join("tiny.sqlite");
    let mut small =
        SubmissionPool::open(&tiny, a.genesis, a.fingerprint, (raw.len() - 1) as u64).unwrap();
    r.chain.reconcile_submission_pool(&mut small, 1).unwrap();
    assert!(matches!(
        small.admit(&a, &s, &h, 1, 0, &raw),
        Err(PoolError::Capacity)
    ));
    assert!(small.tracked_ids().unwrap().is_empty());
    drop(small);
    // Unexpected schemas are refused before writes; this does not claim a
    // mid-transaction disk-full injection (covered by the retention follow-up).
    let db = Connection::open(r.base.join("submissions.sqlite")).unwrap();
    let before: i64 = db
        .query_row("SELECT count(*) FROM entries", [], |r| r.get(0))
        .unwrap();
    // An incompatible trigger is independently refused BEFORE all writes.
    db.execute_batch("CREATE TRIGGER refuse_resource BEFORE INSERT ON resources BEGIN SELECT RAISE(ABORT,'test'); END").unwrap();
    assert!(matches!(
        p.admit(&a, &s, &h, 1, 0, &raw),
        Err(PoolError::Integrity)
    ));
    assert_eq!(
        db.query_row("SELECT count(*) FROM entries", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        before
    );
    db.execute_batch("DROP TRIGGER refuse_resource").unwrap();
    // A real SQLite FULL refusal during the row write rolls back the bundle.
    // Two signed inputs force an overflow page in this initially empty cache.
    let mut larger = tx.clone();
    larger
        .inputs
        .push(Input::unsigned(other, owner_key().public(), 1).unwrap());
    larger.outputs[0].atoms = 30_000;
    larger.sign_input(0, &owner_key()).unwrap();
    larger.sign_input(1, &owner_key()).unwrap();
    let large = larger.encode().unwrap();
    assert!(large.len() > 4096);
    let pages: u64 = db.query_row("PRAGMA page_count", [], |r| r.get(0)).unwrap();
    p.fixture_limit_pages(pages).unwrap();
    assert!(
        matches!(p.admit(&a,&s,&h,1,0,&large),Err(PoolError::Storage(rusqlite::Error::SqliteFailure(code,_))) if code.code==rusqlite::ErrorCode::DiskFull)
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM entries", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        before
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM resources", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    p.fixture_limit_pages(32_768).unwrap();
    let (id, _) = admit(&r, &mut p, 1, 0, &raw);
    assert_eq!(id, tx.id().unwrap());
    drop(db);
    drop(p);
    r.finish();
}
#[test]
fn persisted_corruption_and_forged_index_outcome_fail_closed() {
    let mut r = Rig::new(
        fixture_with_treasury(&treasury_key(), 1_200_000),
        "pool-tamper",
    );
    r.step(P, &[]);
    let mut p = pool(&r);
    r.chain.reconcile_submission_pool(&mut p, P + 1).unwrap();
    let raw = claim_op(&r.f, &owner_key(), 0, P, 10_000, 0, addr(&second_key(), 1));
    let (id, _) = admit(&r, &mut p, P + 1, 1, &raw);
    step_pool(&mut r, &mut p, P + 1, &[]);
    let original = p.status(id).unwrap();
    let chain_db = Connection::open(r.base.join("chain.sqlite")).unwrap();
    let original_record: Vec<u8> = chain_db
        .query_row(
            "SELECT record FROM operation_index_v2 WHERE id=?1",
            [id.as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    let mut forged = r.chain.operation_records(id).unwrap().remove(0);
    forged.wire = [9; 32];
    chain_db
        .execute(
            "UPDATE operation_index_v2 SET record=?1 WHERE id=?2",
            rusqlite::params![forged.encode().unwrap(), id.as_slice()],
        )
        .unwrap();
    assert!(matches!(
        r.chain.verified_operation_records(id),
        Err(StoreError::Integrity)
    ));
    assert!(matches!(
        r.chain.reconcile_submission_pool(&mut p, P + 2),
        Err(StoreError::Integrity)
    ));
    assert_eq!(p.status(id).unwrap(), original);
    chain_db
        .execute(
            "UPDATE operation_index_v2 SET record=?1 WHERE id=?2",
            rusqlite::params![original_record, id.as_slice()],
        )
        .unwrap();
    drop(chain_db);
    drop(p);
    let pool_db = Connection::open(r.base.join("submissions.sqlite")).unwrap();
    let mut bad = SignedClaim::decode(&raw).unwrap();
    bad.signature.ed448[0] ^= 1;
    let bad_raw = bad.encode();
    pool_db
        .execute(
            "UPDATE entries SET raw=?1,wire=?2 WHERE id=?3",
            rusqlite::params![
                bad_raw,
                mutiny_consensus_v8::domain_hash(
                    mutiny_consensus_v8::operation_index_v2::WIRE_DOMAIN,
                    &bad.encode()
                )
                .as_slice(),
                id.as_slice()
            ],
        )
        .unwrap();
    let Status::Finalized(mut forged_status_record) = original else {
        panic!("expected finalized")
    };
    forged_status_record.wire = mutiny_consensus_v8::domain_hash(
        mutiny_consensus_v8::operation_index_v2::WIRE_DOMAIN,
        &bad.encode(),
    );
    let coherent = StatusReport {
        tip_height: r.parent.height,
        tip_block: r.parent.block,
        entries: vec![StatusEntry {
            id,
            status: Status::Finalized(forged_status_record),
        }],
    }
    .encode()
    .unwrap();
    pool_db
        .execute(
            "UPDATE entries SET status=?1 WHERE id=?2",
            rusqlite::params![coherent, id.as_slice()],
        )
        .unwrap();
    assert!(matches!(
        SubmissionPool::open(
            &r.base.join("submissions.sqlite"),
            r.parent.genesis,
            r.parent.fingerprint,
            MAX_BYTES
        ),
        Err(PoolError::Integrity)
    ));
    drop(pool_db);
    r.finish();
}
#[test]
fn status_messages_are_bounded_canonical_and_never_convert_hints_to_finality() {
    let ids: Vec<Hash> = (0..64).map(|n| [n; 32]).collect();
    let raw = submission::encode_query(&ids).unwrap();
    assert_eq!(submission::decode_query(&raw).unwrap(), ids);
    let mut excessive = ids.clone();
    excessive.push([64; 32]);
    assert_eq!(submission::encode_query(&excessive), Err(Reason::Codec));
    let mut trailing = raw;
    trailing.push(0);
    assert_eq!(submission::decode_query(&trailing), Err(Reason::Codec));
    let report = StatusReport {
        tip_height: 7,
        tip_block: [8; 32],
        entries: (0..32)
            .map(|n| StatusEntry {
                id: [n; 32],
                status: Status::Pending,
            })
            .collect(),
    };
    assert_eq!(
        StatusReport::decode(&report.encode().unwrap()).unwrap(),
        report
    );
    let mut too_many = report.clone();
    too_many.entries.push(StatusEntry {
        id: [32; 32],
        status: Status::Unknown,
    });
    assert_eq!(too_many.encode(), Err(Reason::Codec));
    let mut duplicate = report.clone();
    duplicate.entries[1].id = duplicate.entries[0].id;
    assert_eq!(duplicate.encode(), Err(Reason::Codec));
    let mut bad = report.encode().unwrap();
    bad.push(0);
    assert_eq!(StatusReport::decode(&bad), Err(Reason::Codec));
}
#[test]
fn signature_cache_is_process_local_and_state_half_never_authorizes_a_signature() {
    let mut f = fixture();
    let point = OutPoint {
        transaction: [0xe4; 32],
        index: 0,
    };
    f.state.coins.insert(
        point.clone(),
        Coin {
            output: Output {
                owner: addr(&owner_key(), 1),
                atoms: 20_000,
            },
            created_height: 0,
            coinbase: false,
        },
    );
    let r = Rig::new(f, "pool-cached-signature");
    let mut p = pool(&r);
    r.chain.reconcile_submission_pool(&mut p, 1).unwrap();
    let Transaction::Transfer(tx) = transfer(
        &r.f,
        &owner_key(),
        1,
        point.clone(),
        10_000,
        vec![Output {
            owner: addr(&second_key(), 1),
            atoms: 10_000,
        }],
    ) else {
        unreachable!()
    };
    let raw = tx.encode().unwrap();
    let (a, s, _h) = r.chain.submission_context(0, &raw).unwrap();
    assert_eq!(
        tx.verify(a.genesis, a.fingerprint, 1, &s.coins, &s.wallets),
        tx.verify_state(a.genesis, a.fingerprint, 1, &s.coins, &s.wallets)
    );
    let mut bad = tx.clone();
    bad.inputs[0].signature.ed448[0] ^= 1;
    assert!(
        bad.verify_state(a.genesis, a.fingerprint, 1, &s.coins, &s.wallets)
            .is_ok()
    );
    assert_eq!(
        bad.verify(a.genesis, a.fingerprint, 1, &s.coins, &s.wallets),
        Err(mutiny_consensus_v8::transactions::TxError::Signature)
    );
    assert!(tx.verify_signatures().is_ok());
    let mut spent = s.clone();
    spent.coins.remove(&point);
    assert_eq!(
        tx.verify_state(a.genesis, a.fingerprint, 1, &spent.coins, &spent.wallets),
        Err(mutiny_consensus_v8::transactions::TxError::MissingInput)
    );
    let (id, _) = admit(&r, &mut p, 1, 0, &raw);
    let db = Connection::open(r.base.join("submissions.sqlite")).unwrap();
    // Fully coherent body ID/window/resources/PENDING metadata; only authorization is false.
    let bad_raw = bad.encode().unwrap();
    let wire = mutiny_consensus_v8::domain_hash(
        mutiny_consensus_v8::operation_index_v2::WIRE_DOMAIN,
        &bad_raw,
    );
    db.execute(
        "UPDATE entries SET raw=?1,wire=?2 WHERE id=?3",
        rusqlite::params![bad_raw, wire.as_slice(), id.as_slice()],
    )
    .unwrap();
    assert!(matches!(p.status(id), Err(PoolError::Integrity)));
    assert!(matches!(
        r.chain.reconcile_submission_pool(&mut p, 1),
        Err(StoreError::SubmissionPool(PoolError::Integrity))
    ));
    drop(p);
    assert!(matches!(
        SubmissionPool::open(
            &r.base.join("submissions.sqlite"),
            a.genesis,
            a.fingerprint,
            MAX_BYTES
        ),
        Err(PoolError::Integrity)
    ));
    drop(db);
    r.finish();
}
