use mutiny_consensus_v8::storage_budget;
use rusqlite::Connection;

#[test]
fn canonical_and_mempool_writers_retain_capacity_across_restart() {
    use mutiny_consensus_v8::{
        Hash,
        blocks::{self, GenesisDescriptor},
        canonical_store::CanonicalStore,
        execution::State,
        mempool::Mempool,
    };
    let first = include_str!("../../qualification/integration-state-v2-1/chain.jsonl")
        .lines()
        .next()
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(first).unwrap();
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let desc = GenesisDescriptor::decode(&raw(&v["descriptor"])).unwrap();
    let pairs: Vec<(Hash, Vec<u8>)> = v["initial_records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (raw(&r[0]).try_into().unwrap(), raw(&r[1])))
        .collect();
    let state = State::from_records(&pairs, blocks::state_root(&pairs).unwrap()).unwrap();
    let target = raw(&v["initial_target"]).try_into().unwrap();
    let path = std::env::temp_dir().join(format!(
        "build8-chain-capacity-{}.sqlite",
        std::process::id()
    ));
    assert!(!path.exists());
    let mut chain = CanonicalStore::open_trusted_genesis(&path, &desc, &state, target).unwrap();
    let before = chain.load().unwrap().0;
    chain.configure_storage_budget(1024 * 1024).unwrap();
    drop(Mempool::open(&path, desc.id().unwrap(), desc.fingerprint, 1024 * 1024).unwrap());
    // Inject capacity pressure through another correctly configured writer.
    let db = Connection::open(&path).unwrap();
    storage_budget::apply(&db).unwrap();
    assert!(
        db.execute(
            "INSERT INTO chain_state VALUES(zeroblob(32),zeroblob(2097152))",
            []
        )
        .is_err()
    );
    drop(db);
    assert_eq!(chain.load().unwrap().0, before);
    drop(chain);
    let mut chain = CanonicalStore::open_trusted_genesis(&path, &desc, &state, target).unwrap();
    assert_eq!(chain.load().unwrap().0, before);
    assert_eq!(chain.load().unwrap().1.records().unwrap(), pairs);
    drop(chain);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn finite_capacity_reapplies_on_restart_and_rolls_back_without_pruning() {
    let dir = std::env::temp_dir().join(format!(
        "build8-storage-budget-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("budget.sqlite");
    storage_budget::configure(&path, 1024 * 1024).unwrap();
    assert!(storage_budget::configure(&path, 2 * 1024 * 1024).is_err());
    for _ in 0..2 {
        let mut db = Connection::open(&path).unwrap();
        storage_budget::apply(&db).unwrap();
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS preserved(id INTEGER PRIMARY KEY, value BLOB);
            INSERT OR IGNORE INTO preserved VALUES(1,X'0123');",
        )
        .unwrap();
        let t = db.transaction().unwrap();
        assert!(
            t.execute("INSERT INTO preserved VALUES(2,zeroblob(2097152))", [])
                .is_err()
        );
        drop(t);
        assert_eq!(
            db.query_row("SELECT count(*) FROM preserved", [], |r| r.get::<_, u64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            db.query_row("SELECT value FROM preserved WHERE id=1", [], |r| r
                .get::<_, Vec<u8>>(0))
                .unwrap(),
            [1, 35]
        );
        assert!(std::fs::metadata(&path).unwrap().len() <= 1024 * 1024);
    }
    std::fs::remove_file(&path).unwrap();
    std::fs::remove_dir(&dir).unwrap();
}
