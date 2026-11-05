use mutiny_transport_v2::objects::*;

#[test]
fn recovery_kind_is_bounded_separated_durable_and_requires_new_queue_schema() {
    let raw = vec![7; 256 * 1024];
    let id = object_id(ObjectKind::RecoveryEvidence, &raw).unwrap();
    assert_ne!(id, object_id(ObjectKind::CertifiedBlock, &raw).unwrap());
    assert!(object_id(ObjectKind::RecoveryEvidence, &[]).is_err());
    assert!(object_id(ObjectKind::RecoveryEvidence, &vec![7; raw.len() + 1]).is_err());
    let offer = Offer {
        id,
        kind: ObjectKind::RecoveryEvidence,
        length: raw.len(),
    };
    let (meta, payload) = offer.have(1).unwrap();
    assert_eq!(Offer::parse(&meta, &payload).unwrap(), offer);
    let mut unknown = payload.clone();
    unknown[1] = 9;
    assert!(Offer::parse(&meta, &unknown).is_err());
    let mut oversized = offer.clone();
    oversized.length += 1;
    assert!(oversized.have(1).is_err());
    let mut nonce = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let path = std::env::temp_dir().join(format!(
        "build8-recovery-object-{}.sqlite",
        hex::encode(nonce)
    ));
    let mut queue = ObjectQueue::open(&path, [19; 32]).unwrap();
    assert_eq!(
        queue.enqueue(ObjectKind::RecoveryEvidence, &raw).unwrap(),
        offer
    );
    drop(queue);
    let queue = ObjectQueue::open(&path, [19; 32]).unwrap();
    assert_eq!(queue.read_complete(&id).unwrap(), raw);
    drop(queue);
    let db = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))
            .unwrap(),
        6
    );
    db.execute_batch("PRAGMA user_version=4").unwrap();
    drop(db);
    assert!(ObjectQueue::open(&path, [19; 32]).is_err());
    std::fs::remove_file(path).unwrap();
}
