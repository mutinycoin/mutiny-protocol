//! PUBLIC software-only native assembler controls; no signing or finality claim.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
struct CountedPending(AtomicUsize);
impl crate::op_envelope_v1::PendingReferences for CountedPending {}
impl crate::assembler_v2::PendingSource for CountedPending {
    fn pending_items_at(&self, _: &FinalizedAnchor, _: &State)
        -> std::result::Result<Vec<crate::submission_v1::Submission>, String> {
        self.0.fetch_add(1, Ordering::SeqCst); Ok(vec![])
    }
}
fn prepare(r: &Rig, pool: &CountedPending, operations: &[Vec<u8>])
    -> std::result::Result<crate::assembler_v2::Prepared, String> {
    let binding = &r.state.licenses_v2.assignments().next().unwrap().enrollment.binding;
    let parent = crate::execution::WorkParent {
        genesis:r.parent.genesis, fingerprint:r.parent.fingerprint, block:r.parent.block,
        height:0, t0:test_value_x509::T_REF, target:[255;32],
        ancestor_timestamps:vec![test_value_x509::T_REF],
    };
    crate::assembler_v2::prepare(crate::assembler_v2::Request {
        parent:&parent,state:&r.state,pool,license:binding.license,worker:binding.worker_id,
        timestamp:test_value_x509::T_REF+60,ticket:1,operations,
    })
}
#[test]
fn public_assembler_refuses_over_count_before_querying_pending_source() {
    let r=rig(); let pool=CountedPending(AtomicUsize::new(0));
    let positive=prepare(&r,&pool,&[]).unwrap();
    assert_eq!(pool.0.load(Ordering::SeqCst),1);
    assert!(!positive.execution.state.endorsement_revocations_v1.terminal_no_quorum());
    pool.0.store(0,Ordering::SeqCst);
    let small=operation(&r,Target {class:TargetClass::Root,scope:TargetScope::Certificate,identity:r.pki.root_hash()},
        Evidence::Judgment {reason:b"PUBLIC count-bound synthetic Root judgment".to_vec(),evidence:vec![r.pki.root.clone()]})
        .encode().unwrap();
    assert!(small.len()<=crate::body_capacity_v3::MAX_ORDINARY_ITEM_BYTES);
    let too_many=vec![small;crate::body_capacity_v3::MAX_ITEMS+1];
    let refused=prepare(&r,&pool,&too_many);
    assert_eq!(pool.0.load(Ordering::SeqCst),0,"quota rejection must precede pending-source callback");
    assert!(matches!(refused,Err(ref e) if e.contains("Capacity")));
    assert_eq!(r.state.root().unwrap(),r.root);
}
#[test]
fn public_assembler_refuses_two_oversized_native_items_before_pool_callback() {
    let r=rig(); let pool=CountedPending(AtomicUsize::new(0));
    let operation=operation(&r,Target {class:TargetClass::Root,scope:TargetScope::Certificate,identity:r.pki.root_hash()},
        Evidence::Judgment {reason:b"PUBLIC oversized authenticated synthetic Root judgment".to_vec(),
            evidence:vec![r.pki.root.clone(),vec![0x41;20_000]]});
    let raw=operation.encode().unwrap();
    assert!(raw.len()>crate::body_capacity_v3::MAX_ORDINARY_ITEM_BYTES);
    assert!(raw.len()<=crate::body_capacity_v3::MAX_A2_OPERATION_BYTES);
    let positive=prepare(&r,&pool,&[raw.clone()]).unwrap();
    assert_eq!(pool.0.load(Ordering::SeqCst),1);
    assert!(positive.execution.state.endorsement_revocations_v1.terminal_no_quorum());
    pool.0.store(0,Ordering::SeqCst);
    assert!(matches!(prepare(&r,&pool,&[raw.clone(),raw]),Err(ref e) if e.contains("Capacity")));
    assert_eq!(pool.0.load(Ordering::SeqCst),0,"two reserved items must fail before callback");
    assert_eq!(r.state.root().unwrap(),r.root);
}
