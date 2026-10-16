//! Synthetic public fixture only. No signing, TPM, network or services.
use super::*;
use mutiny_consensus_v8::{
    anchors::FinalizedAnchor, block_envelope_v2::BlockEnvelope, canonical_store_v2::CanonicalStore,
    execution::State, mempool_v2::Mempool,
};

#[test]
fn abrupt_exit_preserves_committed_candidates_and_rolls_back_uncommitted_insert() {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/hybrid-canonical-store-public-v1.json"
    ))
    .unwrap();
    assert_eq!(f["synthetic_only"], true);
    assert_eq!(f["production_authorized"], false);
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let root: Hash = raw(&f["root"]).try_into().unwrap();
    let rows: Vec<_> = f["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
        .collect();
    let state = State::from_records(&rows, root).unwrap();
    let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
    let block = BlockEnvelope::decode(&raw(&f["envelope"])).unwrap();
    let record = Record {
        header: block.header.clone(),
        authority: block.authority.clone(),
        body: block.body.clone(),
    };
    let open_runtime = |base: &Path| {
        HybridRuntime::from_pinned_chain(
            CanonicalStore::open_trusted_genesis(
                &base.join("chain"),
                &genesis,
                &state,
                root,
                1000,
                [255; 32],
            )
            .unwrap(),
            Mempool::open(
                &base.join("pool"),
                genesis.genesis,
                genesis.fingerprint,
                64 * 1024 * 1024,
            )
            .unwrap(),
        )
        .unwrap()
    };
    if let Ok(base) = std::env::var("BUILD8_SYNTHETIC_CANDIDATE_CHILD_PATH") {
        let base = std::path::PathBuf::from(base);
        assert!(base.is_absolute());
        let runtime = open_runtime(&base);
        let mut journal = Journal::open(
            &base.join("candidates"),
            genesis.genesis,
            genesis.fingerprint,
            1024 * 1024,
            false,
        )
        .unwrap();
        let mut second = record.clone();
        second.header.nonce += 1;
        journal.preserve(&runtime, &second).unwrap();
        panic!("crash checkpoint not reached");
    }
    for (mode, exit, count) in [("before_commit", 91, 1), ("after_commit", 92, 2)] {
        let mut random = [0; 16];
        mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
        let base =
            std::env::temp_dir().join(format!("build8-candidate-crash-{}", hex::encode(random)));
        assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
        let runtime = open_runtime(&base);
        let mut journal = Journal::open(
            &base.join("candidates"),
            genesis.genesis,
            genesis.fingerprint,
            1024 * 1024,
            true,
        )
        .unwrap();
        journal.preserve(&runtime, &record).unwrap();
        drop(journal);
        drop(runtime);
        let output=std::process::Command::new(std::env::current_exe().unwrap())
            .args(["candidate_journal_v2::tests::abrupt_exit_preserves_committed_candidates_and_rolls_back_uncommitted_insert","--nocapture","--test-threads=1"])
            .env("BUILD8_SYNTHETIC_CANDIDATE_CHILD_PATH",&base)
            .env("BUILD8_SYNTHETIC_CANDIDATE_CRASH",mode).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(exit),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let runtime = open_runtime(&base);
        let journal = Journal::open(
            &base.join("candidates"),
            genesis.genesis,
            genesis.fingerprint,
            1024 * 1024,
            false,
        )
        .unwrap();
        let actual: u64 = journal
            .db
            .query_row("SELECT count(*) FROM candidates", [], |r| r.get(0))
            .unwrap();
        assert_eq!(actual, count);
        let retained: Vec<u8> = journal
            .db
            .query_row(
                "SELECT raw FROM candidates WHERE id=?1",
                [record.header.block_hash().as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(retained, record.encode().unwrap());
        let mut cursor = None;
        let mut restored = 0;
        while let Some(r) = journal.next_current(&runtime, cursor).unwrap() {
            cursor = Some(r.header.block_hash());
            restored += 1;
        }
        assert_eq!(restored, count);
        drop(journal);
        drop(runtime);
        println!("RETAINED_PUBLIC_CANDIDATE_CRASH_EVIDENCE={}",base.display());
    }
}
#[test]
fn retention_is_bounded_durable_and_pruned_only_after_finality() {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/hybrid-canonical-store-public-v1.json"
    ))
    .unwrap();
    assert_eq!(f["synthetic_only"], true);
    assert_eq!(f["production_authorized"], false);
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let root: Hash = raw(&f["root"]).try_into().unwrap();
    let rows: Vec<_> = f["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
        .collect();
    let state = State::from_records(&rows, root).unwrap();
    let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
    let block = BlockEnvelope::decode(&raw(&f["envelope"])).unwrap();
    let record = Record {
        header: block.header.clone(),
        authority: block.authority.clone(),
        body: block.body.clone(),
    };
    let mut random = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
    let base =
        std::env::temp_dir().join(format!("build8-candidate-journal-{}", hex::encode(random)));
    assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
    let mut runtime = HybridRuntime::from_pinned_chain(
        CanonicalStore::open_trusted_genesis(
            &base.join("chain"),
            &genesis,
            &state,
            root,
            1000,
            [255; 32],
        )
        .unwrap(),
        Mempool::open(
            &base.join("pool"),
            genesis.genesis,
            genesis.fingerprint,
            64 * 1024 * 1024,
        )
        .unwrap(),
    )
    .unwrap();
    let path = base.join("candidates");
    let budget = record.encode().unwrap().len();
    let open = |initialize| {
        Journal::open(
            &path,
            genesis.genesis,
            genesis.fingerprint,
            budget,
            initialize,
        )
    };
    assert!(open(false).is_err());
    let mut journal = open(true).unwrap();
    assert!(open(true).is_err());
    assert!(journal.next_current(&runtime, None).unwrap().is_none());
    let permit = journal.preserve(&runtime, &record).unwrap();
    assert!(permit.matches(&record.header));
    assert_eq!(runtime.head().unwrap().height, 0);
    assert_eq!(
        journal.next_current(&runtime, None).unwrap(),
        Some(record.clone())
    );
    assert!(
        journal
            .next_current(&runtime, Some(record.header.block_hash()))
            .unwrap()
            .is_none()
    );
    journal.preserve(&runtime, &record).unwrap();
    let mut second = record.clone();
    second.header.nonce = second.header.nonce.checked_add(1).unwrap();
    runtime
        .chain
        .validate_observation_v2(&second.header, &second.authority, &second.body)
        .unwrap();
    assert!(!permit.matches(&second.header));
    // Exhaust actual SQLite page allocation, independently of the logical
    // queue budget. A storage error must retain every previously committed row.
    let disk_path = base.join("page-limited-candidates");
    let mut disk = Journal::open(
        &disk_path,
        genesis.genesis,
        genesis.fingerprint,
        MAX_BYTES * MAX_PROPOSALS,
        true,
    )
    .unwrap();
    disk.preserve(&runtime, &record).unwrap();
    let pages: u64 = disk
        .db
        .pragma_query_value(None, "page_count", |r| r.get(0))
        .unwrap();
    disk.db
        .pragma_update(None, "max_page_count", pages)
        .unwrap();
    let mut filled = false;
    for offset in 1..=16 {
        let mut next = record.clone();
        next.header.nonce = next.header.nonce.checked_add(offset).unwrap();
        runtime
            .chain
            .validate_observation_v2(&next.header, &next.authority, &next.body)
            .unwrap();
        if let Err(e) = disk.preserve(&runtime, &next) {
            assert_eq!(e, "Hybrid candidate storage failure");
            filled = true;
            break;
        }
    }
    assert!(filled, "fixture must reach the physical SQLite page cap");
    let retained: Vec<u8> = disk
        .db
        .query_row(
            "SELECT raw FROM candidates WHERE id=?1",
            [record.header.block_hash().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(retained, record.encode().unwrap());
    drop(disk);
    let disk = Journal::open(
        &disk_path,
        genesis.genesis,
        genesis.fingerprint,
        MAX_BYTES * MAX_PROPOSALS,
        false,
    )
    .unwrap();
    assert!(disk.next_current(&runtime, None).unwrap().is_some());
    drop(disk);
    assert!(
        journal.preserve(&runtime, &second).is_err(),
        "capacity cannot evict a pending candidate"
    );
    assert_eq!(
        journal.next_current(&runtime, None).unwrap(),
        Some(record.clone())
    );
    for which in 0..3 {
        let mut bad = record.clone();
        match which {
            0 => bad.authority.signature.ed448.fill(0),
            1 => bad.authority.signature.fndsa.fill(0),
            _ => bad.body.operations.push(vec![0; 16385]),
        }
        assert!(journal.preserve(&runtime, &bad).is_err());
    }
    let mut legacy = record.encode().unwrap();
    assert_eq!(legacy[1], 2);
    legacy[1] = 1;
    assert!(Record::decode(&legacy).is_err());
    drop(journal);
    let mut journal = open(false).unwrap();
    assert_eq!(
        journal.next_current(&runtime, None).unwrap(),
        Some(record.clone())
    );
    drop(journal);
    assert!(Journal::open(&path, genesis.genesis, [9; 32], budget, false).is_err());
    let db = Connection::open(&path).unwrap();
    db.execute("UPDATE candidates SET raw=zeroblob(length(raw))", [])
        .unwrap();
    assert!(open(false).is_err());
    db.execute("UPDATE candidates SET raw=?1", [record.encode().unwrap()])
        .unwrap();
    drop(db);
    journal = open(false).unwrap();
    runtime.chain.commit(&block).unwrap();
    assert!(journal.next_current(&runtime, None).unwrap().is_none());
    assert!(
        journal
            .preserve(&runtime, &record)
            .unwrap()
            .matches(&record.header)
    );
    let count: u64 = journal
        .db
        .query_row("SELECT count(*) FROM candidates", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
    drop(journal);
    drop(runtime);
    println!("RETAINED_PUBLIC_CANDIDATE_JOURNAL_EVIDENCE={}",base.display());
}
