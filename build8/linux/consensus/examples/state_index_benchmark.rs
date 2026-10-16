//! Derived-index storage/rebuild qualification on synthetic canonical records.
use mutiny_consensus_v8::{
    NETWORK_ID,
    anchors::FinalizedAnchor,
    domain_hash,
    state_tree::{full_root, index::*},
};
use rusqlite::{Connection, params};
use std::{collections::BTreeMap, time::Instant};
fn main() {
    let count = std::env::args().nth(1).unwrap().parse::<usize>().unwrap();
    assert!((1..=1_000_000).contains(&count));
    let path = std::env::temp_dir().join(format!(
        "build8-index-benchmark-{}-{count}.sqlite",
        std::process::id()
    ));
    assert!(!path.exists());
    let key = |n: usize| {
        domain_hash(
            b"MUTINY-BUILD8-TEST-STATE-BENCHMARK-V1",
            &(n as u64).to_be_bytes(),
        )
    };
    let records: BTreeMap<_, _> = (0..count).map(|n| (key(n), vec![0])).collect();
    let pairs: Vec<_> = records.iter().map(|(k, r)| (*k, r.clone())).collect();
    let root = full_root(&pairs).unwrap();
    let anchor = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        height: 1,
        block: [3; 32],
    };
    let mut db = Connection::open(&path).unwrap();
    db.execute_batch("PRAGMA synchronous=FULL;CREATE TABLE chain_state(key BLOB PRIMARY KEY,value BLOB NOT NULL) WITHOUT ROWID;").unwrap();
    let start = Instant::now();
    let t = db.transaction().unwrap();
    install(&t).unwrap();
    for (k, r) in &pairs {
        t.execute(
            "INSERT INTO chain_state VALUES(?1,?2)",
            params![k.as_slice(), r],
        )
        .unwrap();
    }
    publish(&t, &pairs, &anchor, root, &[], true).unwrap();
    t.commit().unwrap();
    let create = start.elapsed().as_secs_f64();
    drop(db);
    let mut db = Connection::open(&path).unwrap();
    let start = Instant::now();
    let mut maximum = 0;
    let t = db.transaction().unwrap();
    for n in 0..100 {
        maximum = maximum.max(
            prove(&t, &anchor, root, key(n % count))
                .unwrap()
                .encode()
                .unwrap()
                .len(),
        );
    }
    t.commit().unwrap();
    let proofs = start.elapsed().as_secs_f64();
    let start = Instant::now();
    let t = db.transaction().unwrap();
    publish(&t, &pairs, &anchor, root, &[], true).unwrap();
    t.commit().unwrap();
    let rebuild = start.elapsed().as_secs_f64();
    let mut changed = records;
    let removed = key(0);
    changed.remove(&removed);
    changed.insert(key(count), vec![1]);
    let changed: Vec<_> = changed.into_iter().collect();
    let new_root = full_root(&changed).unwrap();
    let start = Instant::now();
    let t = db.transaction().unwrap();
    t.execute("DELETE FROM chain_state WHERE key=?1", [removed.as_slice()])
        .unwrap();
    t.execute(
        "INSERT INTO chain_state VALUES(?1,?2)",
        params![key(count).as_slice(), vec![1u8]],
    )
    .unwrap();
    publish(&t, &changed, &anchor, new_root, &[removed], false).unwrap();
    t.commit().unwrap();
    let update = start.elapsed().as_secs_f64();
    let nodes: u64 = db
        .query_row("SELECT count(*) FROM state_merkle_nodes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(nodes, (2 * count - 1) as u64);
    let t = db.transaction().unwrap();
    assert!(
        prove(&t, &anchor, new_root, removed)
            .unwrap()
            .record
            .is_none()
    );
    assert_eq!(
        prove(&t, &anchor, new_root, key(count)).unwrap().record,
        Some(vec![1])
    );
    t.commit().unwrap();
    drop(db);
    let disk = std::fs::metadata(&path).unwrap().len();
    println!(
        "{}",
        serde_json::json!({"result":"PASS","records":count,"nodes":nodes,"database_bytes":disk,
        "create_commit_seconds":create,"restart_proof_100_seconds":proofs,"max_sample_proof_bytes":maximum,
        "rebuild_commit_seconds":rebuild,"delete_insert_publish_seconds":update,
        "update_implementation":"reconstruct in-memory index; persist changed paths only",
        "initial_root":hex::encode(root),"final_root":hex::encode(new_root),"actual_genesis":false})
    );
    std::fs::remove_file(path).unwrap();
}
