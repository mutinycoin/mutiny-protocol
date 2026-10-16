use super::*;

struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("build8-b1-queue-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir(&path).unwrap(); Self(path)
    }
    fn path(&self, name: &str) -> std::path::PathBuf { self.0.join(name) }
}
impl Drop for Directory { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }

#[test]
fn b1_v9_requires_explicit_new_queue_and_exact_a2_profile_preserving_v7_v8() {
    let dir = Directory::new(); let peer = [2;32];
    for (name, a2) in [("v7", false), ("v8", true)] {
        let path = dir.path(name);
        let mut queue = if a2 { ObjectQueue::open_a2(&path, peer, true).unwrap() }
            else { ObjectQueue::open(&path, peer).unwrap() };
        queue.enqueue(ObjectKind::CertifiedBlock, b"retained canonical bytes").unwrap();
        drop(queue);
        let before = std::fs::read(&path).unwrap();
        assert!(ObjectQueue::open_history(&path, peer, a2, false).is_err());
        assert!(ObjectQueue::open_history(&path, peer, a2, true).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
    let path = dir.path("v9");
    let mut queue = ObjectQueue::open_history(&path, peer, false, true).unwrap();
    assert!(queue.history_profile());
    assert!(queue.enqueue(ObjectKind::A2EvidenceOperation, b"no implicit a2").is_err());
    drop(queue);
    let before = std::fs::read(&path).unwrap();
    assert!(ObjectQueue::open(&path, peer).is_err());
    assert!(ObjectQueue::open_a2(&path, peer, false).is_err());
    assert!(ObjectQueue::open_history(&path, peer, true, false).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert!(ObjectQueue::open_history(&path, [3;32], false, false).is_err());
    ObjectQueue::open_history(&path, peer, false, false).unwrap();
    let mut a2 = ObjectQueue::open_history(&dir.path("v9-a2"), peer, true, true).unwrap();
    a2.enqueue(ObjectKind::A2EvidenceOperation, b"explicit a2").unwrap();
    assert!(a2.enqueue(ObjectKind::A2EvidenceOperation, b"second a2 refuses").is_err());
}

#[test]
fn b1_history_kind_caps_and_two_controls_leave_only_six_general_slots() {
    let dir = Directory::new(); let mut queue = ObjectQueue::open_history(&dir.path("q"), [2;32], false, true).unwrap();
    assert_eq!(ObjectKind::HistoryRequestV1.max_bytes(), 145);
    assert_eq!(ObjectKind::HistoryPageV1.max_bytes(), 16384);
    assert!(queue.enqueue(ObjectKind::HistoryRequestV1, &[1;146]).is_err());
    assert!(queue.enqueue(ObjectKind::HistoryPageV1, &vec![1;16385]).is_err());
    assert_eq!(queue.general_capacity().unwrap().history_candidates(), HistoryCapacity {
        candidate_entries:6, candidate_bytes:MAX_QUEUE_BYTES-HISTORY_CONTROL_BYTES });
    let request = queue.enqueue(ObjectKind::HistoryRequestV1, &[1;145]).unwrap();
    let candidates: Vec<_> = (1..=6).map(|n| (ObjectKind::CertifiedBlock, vec![n;141])).collect();
    let queued = queue.enqueue_history_page(&request.id, &[2;16384], &candidates).unwrap().unwrap();
    assert_eq!(queued.offers.len(), 7);
    assert_eq!(queued.offers[0].kind, ObjectKind::HistoryPageV1);
    assert_eq!(queue.general_capacity().unwrap().free_objects, 0);
    assert!(queue.enqueue(ObjectKind::ContinuityVote, b"overflow").is_err());
    // General history never borrows or removes the separate submission slots.
    queue.enqueue(ObjectKind::SignedTransaction, b"synthetic signed transaction").unwrap();
    queue.enqueue(ObjectKind::SignedOperation, b"synthetic signed operation").unwrap();
    assert!(queue.enqueue(ObjectKind::SignedTransaction, b"third submission").is_err());
}

#[test]
fn b1_atomic_batch_busy_and_late_failure_leave_no_page_or_partial_candidates() {
    let dir = Directory::new(); let mut queue = ObjectQueue::open_history(&dir.path("q"), [2;32], false, true).unwrap();
    let request = queue.enqueue(ObjectKind::HistoryRequestV1, b"request").unwrap();
    let existing_raw = b"incomplete retained block".to_vec();
    let existing = Offer { id: object_id(ObjectKind::CertifiedBlock, &existing_raw).unwrap(),
        kind: ObjectKind::CertifiedBlock, length: existing_raw.len() };
    queue.offer(&existing).unwrap();
    let before = queue.general_capacity().unwrap();
    let page = b"page must roll back";
    let candidate = (ObjectKind::CertifiedBlock, b"first new block".to_vec());
    assert!(queue.enqueue_history_page(&request.id, page, &[candidate.clone(), (existing.kind, existing_raw)]).is_err());
    assert_eq!(queue.general_capacity().unwrap(), before);
    assert!(queue.describe(&object_id(ObjectKind::HistoryPageV1, page).unwrap()).is_err());
    assert!(queue.describe(&object_id(candidate.0, &candidate.1).unwrap()).is_err());
    for n in 1..=6 { queue.enqueue(ObjectKind::ContinuityVote, &[n;3]).unwrap(); }
    let full = queue.general_capacity().unwrap();
    assert!(queue.enqueue_history_page(&request.id, b"busy page", &[]).unwrap().is_none());
    assert_eq!(queue.general_capacity().unwrap(), full);
}

#[test]
fn b1_whole_dependency_groups_byte_reserve_and_retained_copies_are_not_reset() {
    let dir = Directory::new(); let mut queue = ObjectQueue::open_history(&dir.path("q"), [2;32], false, true).unwrap();
    let request = queue.enqueue(ObjectKind::HistoryRequestV1, b"request").unwrap();
    let before = queue.general_capacity().unwrap();
    assert!(queue.enqueue_history_page(&request.id, b"orphan", &[(ObjectKind::RecoveryEvidence, b"recovery".to_vec())]).is_err());
    assert_eq!(queue.general_capacity().unwrap(), before);
    let raw = b"pre-existing exact canonical block".to_vec();
    let retained = queue.enqueue(ObjectKind::CertifiedBlock, &raw).unwrap();
    queue.acknowledge(&retained.id, &Bitmap { start:0, bits:vec![true] }).unwrap();
    let queued = queue.enqueue_history_page(&request.id, b"page", &[(ObjectKind::CertifiedBlock, raw)]).unwrap().unwrap();
    assert_eq!(queued.fresh, vec![true,false]);
    assert_eq!(queue.acknowledged(&retained.id, 0, 1).unwrap().bits, vec![true]);
    assert_eq!(queue.read_complete(&retained.id).unwrap(), b"pre-existing exact canonical block");
    drop(queue);
    let mut queue = ObjectQueue::open_history(&dir.path("bytes"), [2;32], false, true).unwrap();
    let req = queue.enqueue(ObjectKind::HistoryRequestV1, b"q").unwrap();
    let large = vec![7;MAX_OBJECT_BYTES];
    let near_full = vec![8;MAX_OBJECT_BYTES-HISTORY_CONTROL_BYTES+1];
    assert!(queue.enqueue_history_page(&req.id, b"p", &[(ObjectKind::CertifiedBlock,large),
        (ObjectKind::CertifiedBlock,near_full)]).unwrap().is_none());
    assert_eq!(queue.general_capacity().unwrap().free_objects, 7);
}
