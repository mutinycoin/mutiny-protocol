use mutiny_consensus_v8::{
    Hash,
    anchors::FinalizedAnchor,
    state_tree::{self, index::*},
};
use rusqlite::{Connection, params};
use std::collections::BTreeMap;
fn bytes(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
fn hash(v: &serde_json::Value) -> Hash {
    bytes(v).try_into().unwrap()
}
#[test]
fn persistent_paths_match_python_commit_rollback_restart_and_corruption_rebuild() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/STATE-TREE-V2-VECTORS-V1.json"
    ))
    .unwrap();
    let anchor = FinalizedAnchor::decode(&bytes(&v["context"])).unwrap();
    let path = std::env::temp_dir().join(format!(
        "build8-state-index-v2-{}.sqlite",
        std::process::id()
    ));
    assert!(!path.exists());
    let mut db = Connection::open(&path).unwrap();
    db.execute_batch("PRAGMA synchronous=FULL;CREATE TABLE chain_state(key BLOB PRIMARY KEY,value BLOB NOT NULL);").unwrap();
    let mut records = BTreeMap::new();
    for (step, op) in v["operations"].as_array().unwrap().iter().enumerate() {
        let key = hash(&op["key"]);
        let remove = op["action"] == "delete";
        if remove {
            records.remove(&key);
        } else {
            records.insert(key, bytes(&op["record"]));
        }
        let pairs: Vec<_> = records.iter().map(|(k, r)| (*k, r.clone())).collect();
        let root = hash(&op["root"]);
        let t = db.transaction().unwrap();
        install(&t).unwrap();
        if remove {
            t.execute("DELETE FROM chain_state WHERE key=?1", [key.as_slice()])
                .unwrap();
        } else {
            t.execute("INSERT INTO chain_state VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",params![key.as_slice(),records[&key]]).unwrap();
        }
        publish(
            &t,
            &pairs,
            &anchor,
            root,
            if remove {
                std::slice::from_ref(&key)
            } else {
                &[]
            },
            false,
        )
        .unwrap();
        let proof = prove(&t, &anchor, root, key).unwrap();
        proof.verify(&anchor, root, key).unwrap();
        let nodes: u64 = t
            .query_row("SELECT count(*) FROM state_merkle_nodes", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            nodes,
            (2 * records.len()).saturating_sub(1) as u64,
            "step {step}"
        );
        if op["proof"].is_string() {
            let p = state_tree::StateProof::decode(&bytes(&op["proof"])).unwrap();
            assert_eq!(prove(&t, &anchor, root, p.key).unwrap(), p);
        }
        t.commit().unwrap();
        if step % 256 == 0 {
            // A failed publication and record edit roll back together.
            let t = db.transaction().unwrap();
            t.execute("DELETE FROM chain_state", []).unwrap();
            publish(
                &t,
                &[],
                &anchor,
                state_tree::full_root(&[]).unwrap(),
                &[],
                true,
            )
            .unwrap();
            drop(t);
            drop(db);
            db = Connection::open(&path).unwrap();
            let t = db.transaction().unwrap();
            prove(&t, &anchor, root, key).unwrap();
            t.commit().unwrap();
        }
    }
    let pairs: Vec<_> = records.into_iter().collect();
    let root = state_tree::full_root(&pairs).unwrap();
    let key = pairs[0].0;
    // Derived-node damage cannot change canonical authority; rebuild from
    // canonical records restores exactly the independently reproduced root.
    db.execute(
        "UPDATE state_merkle_nodes SET value=x'00' WHERE id=(SELECT tree FROM state_merkle_tip)",
        [],
    )
    .unwrap();
    let t = db.transaction().unwrap();
    assert!(prove(&t, &anchor, root, key).is_err());
    publish(&t, &pairs, &anchor, root, &[], true).unwrap();
    prove(&t, &anchor, root, key).unwrap();
    t.commit().unwrap();
    drop(db);
    std::fs::remove_file(path).unwrap();
}
