//! Isolated allocator accounting; no wallet/state database or network access.
use mutiny_consensus_v8::{Hash, NETWORK_ID, anchors::FinalizedAnchor, state_tree::*};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
struct Track;
fn added(n: usize) {
    let live = LIVE.fetch_add(n, SeqCst) + n;
    PEAK.fetch_max(live, SeqCst);
}
unsafe impl GlobalAlloc for Track {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            added(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), SeqCst);
        unsafe { System.dealloc(p, layout) }
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let out = unsafe { System.realloc(p, layout, new_size) };
        if !out.is_null() {
            LIVE.fetch_sub(layout.size(), SeqCst);
            added(new_size);
        }
        out
    }
}
#[global_allocator]
static ALLOC: Track = Track;
fn measured(raw: &[u8], anchor: &FinalizedAnchor, root: Hash, key: Hash) -> usize {
    let base = LIVE.load(SeqCst);
    PEAK.store(base, SeqCst);
    let proof = StateProof::decode(raw).unwrap();
    proof.verify(anchor, root, key).unwrap();
    PEAK.load(SeqCst) - base
}
fn main() {
    let context = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        height: u64::MAX,
        block: [3; 32],
    };
    let mut record = vec![0x5a, 0, 3, 0xff, 0xfb];
    record.resize(MAX_RECORD, 0);
    let proof = StateProof {
        context: context.clone(),
        count: MAX_RECORDS as u64,
        key: [0; 32],
        record: Some(record),
        bitmap: [255; 32],
        siblings: vec![[0x55; 32]; 256],
    };
    let raw = proof.encode().unwrap();
    let mut tree = leaf(proof.key, proof.record.as_ref().unwrap()).unwrap();
    for sibling in proof.siblings.iter().rev() {
        tree = branch(tree, *sibling);
    }
    let root = commitment(proof.count, tree).unwrap();
    let heap = measured(&raw, &context, root, proof.key);
    assert!(heap <= 2 * 1024 * 1024);
    let oversized = vec![0; MAX_PROOF + 1];
    let base = LIVE.load(SeqCst);
    PEAK.store(base, SeqCst);
    assert!(StateProof::decode(&oversized).is_err());
    let rejected = PEAK.load(SeqCst) - base;
    assert_eq!(rejected, 0);
    println!(
        "{}",
        serde_json::json!({"result":"PASS","largest_proof_bytes":raw.len(),
        "decoder_and_verifier_additional_peak_heap_bytes":heap,"including_input_bytes":heap+raw.len(),
        "over_limit_decoder_heap_bytes":rejected,"scope":"allocator payload in isolated process; excludes allocator metadata and stack",
        "actual_genesis":false})
    );
}
