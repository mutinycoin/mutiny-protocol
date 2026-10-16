//! Structural transport/cache tests only; opaque bytes do not prove A2 authority.
use mutiny_transport_v2::objects::*;
fn path() -> std::path::PathBuf {
    let mut nonce = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    std::env::temp_dir().join(format!("a2-objects-{}.sqlite", hex::encode(nonce)))
}
#[test]
fn successor_type_bounds_keep_legacy_bounds_and_namespace_separation() {
    for (kind, limit) in [(ObjectKind::A2BlockProposal, 270871),
                          (ObjectKind::A2EvidenceOperation, 196608)] {
        let bytes = vec![42; limit];
        let id = object_id(kind, &bytes).unwrap();
        assert_ne!(id, object_id(ObjectKind::CertifiedBlock, &bytes).unwrap());
        assert!(object_id(kind, &[]).is_err());
        assert!(object_id(kind, &vec![42; limit + 1]).is_err());
        let offer = Offer { id, kind, length: limit };
        let (metadata, raw) = offer.have(0).unwrap();
        assert_eq!(Offer::parse(&metadata, &raw).unwrap(), offer);
    }
    assert_eq!(MAX_OBJECT_BYTES, 2097152);
    assert_eq!(MAX_QUEUE_BYTES, 4194304);
    assert_eq!(MAX_REQUESTS, 10);
    assert_eq!(MAX_SUBMISSION_BYTES, 32768);
    assert_eq!(ObjectKind::SignedOperation.max_bytes(), 16384);
    assert_eq!(ObjectKind::BlockProposal.max_bytes(), 74257);
    assert_eq!(ObjectKind::RecoveryEvidence.max_bytes(), 262144);
    assert!(object_id(ObjectKind::SignedOperation, &vec![0; 16385]).is_err());
    assert!(object_id(ObjectKind::BlockProposal, &vec![0; 74258]).is_err());
}
#[test]
fn explicit_successor_queue_retains_bytes_and_refuses_second_evidence_atomically() {
    let p = path(); let peer = [41; 32];
    let bytes = vec![7; 196608];
    let mut q = ObjectQueue::open_a2(&p, peer, true).unwrap();
    let offer = q.enqueue(ObjectKind::A2EvidenceOperation, &bytes).unwrap();
    assert_eq!(q.enqueue(ObjectKind::A2EvidenceOperation, &bytes).unwrap(), offer);
    let before = std::fs::read(&p).unwrap();
    assert!(q.enqueue(ObjectKind::A2EvidenceOperation, &vec![8; 196608]).is_err());
    assert_eq!(std::fs::read(&p).unwrap(), before);
    assert_eq!(q.read_complete(&offer.id).unwrap(), bytes);
    assert!(ObjectQueue::open_a2(&p, peer, true).is_err());
    drop(q);
    let q = ObjectQueue::open_a2(&p, peer, false).unwrap();
    assert_eq!(q.read_complete(&offer.id).unwrap(), bytes);
    drop(q);
    assert!(ObjectQueue::open(&p, peer).is_err());
    assert_eq!(std::fs::read(&p).unwrap(), before);
    std::fs::remove_file(p).unwrap();
}
#[test]
fn old_queue_keeps_its_schema_and_cannot_select_successor_capacity() {
    let p = path(); let peer = [42; 32];
    let mut q = ObjectQueue::open(&p, peer).unwrap();
    let bytes = vec![1; 16384];
    let offer = q.enqueue(ObjectKind::SignedOperation, &bytes).unwrap();
    let before = std::fs::read(&p).unwrap();
    assert!(q.enqueue(ObjectKind::A2EvidenceOperation, &[1]).is_err());
    assert!(q.enqueue(ObjectKind::A2BlockProposal, &[1]).is_err());
    assert_eq!(std::fs::read(&p).unwrap(), before);
    drop(q);
    assert!(ObjectQueue::open_a2(&p, peer, false).is_err());
    assert_eq!(std::fs::read(&p).unwrap(), before);
    let q = ObjectQueue::open(&p, peer).unwrap();
    assert_eq!(q.read_complete(&offer.id).unwrap(), bytes);
    drop(q); std::fs::remove_file(p).unwrap();
}
