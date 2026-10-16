//! Software-only reproducible state-index workload, never a fleet hash measure.
use mutiny_consensus_v8::{NETWORK_ID, anchors::FinalizedAnchor, domain_hash, state_tree::*};
use std::time::Instant;
fn main() {
    let count = std::env::args().nth(1).unwrap().parse::<usize>().unwrap();
    assert!((1..=MAX_RECORDS).contains(&count));
    let key = |n: usize| {
        domain_hash(
            b"MUTINY-BUILD8-TEST-STATE-BENCHMARK-V1",
            &(n as u64).to_be_bytes(),
        )
    };
    let mut tree = StateTree::default();
    let start = Instant::now();
    for n in 0..count {
        tree.insert(key(n), vec![0]).unwrap();
    }
    let insert = start.elapsed().as_secs_f64();
    let initial = tree.root();
    let start = Instant::now();
    let mut stream = StateRootBuilder::default();
    for (k, r) in tree.iter_records() {
        stream.push(*k, r).unwrap();
    }
    assert_eq!(stream.finish(), initial);
    let rebuild = start.elapsed().as_secs_f64();
    let context = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        height: 7,
        block: [3; 32],
    };
    let start = Instant::now();
    let mut max_proof = 0;
    for n in 0..100 {
        let k = key(n % count);
        let proof = tree.proof(context.clone(), k);
        let raw = proof.encode().unwrap();
        max_proof = max_proof.max(raw.len());
        StateProof::decode(&raw)
            .unwrap()
            .verify(&context, initial, k)
            .unwrap();
    }
    let proof = start.elapsed().as_secs_f64();
    let start = Instant::now();
    for n in 0..100 {
        tree.update(key(n % count), vec![1]).unwrap();
    }
    let update = start.elapsed().as_secs_f64();
    let start = Instant::now();
    for n in 0..count.min(100) {
        tree.remove(&key(n)).unwrap();
    }
    let delete = start.elapsed().as_secs_f64();
    let mut stream = StateRootBuilder::default();
    for (k, r) in tree.iter_records() {
        stream.push(*k, r).unwrap();
    }
    assert_eq!(stream.finish(), tree.root());
    println!(
        "{}",
        serde_json::json!({"result":"PASS","records":count,"insert_seconds":insert,
        "streaming_rebuild_seconds":rebuild,"proof_encode_decode_verify_100_seconds":proof,
        "update_100_seconds":update,"delete_100_seconds":delete,"sample_max_proof_bytes":max_proof,
        "initial_root":hex::encode(initial),"final_root":hex::encode(tree.root()),
        "remaining_index_payload_bytes":tree.index_payload_bytes(),
        "index_payload_excludes":"allocator, BTreeMap and record allocations", "actual_genesis":false})
    );
}
