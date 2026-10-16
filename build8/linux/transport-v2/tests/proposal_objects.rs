use mutiny_transport_v2::objects::*;
#[test]
fn proposal_bound_kind_separation_and_version_five_refusal() {
    let raw = vec![8; 74257];
    let id = object_id(ObjectKind::BlockProposal, &raw).unwrap();
    assert_ne!(id, object_id(ObjectKind::CertifiedBlock, &raw).unwrap());
    assert_ne!(id, object_id(ObjectKind::ContinuityVote, &raw).unwrap());
    assert!(object_id(ObjectKind::BlockProposal, &[]).is_err());
    assert!(object_id(ObjectKind::BlockProposal, &vec![8; 74258]).is_err());
    let offer = Offer {
        id,
        kind: ObjectKind::BlockProposal,
        length: raw.len(),
    };
    let (meta, bytes) = offer.have(0).unwrap();
    assert_eq!(Offer::parse(&meta, &bytes).unwrap(), offer);
    let mut unknown = bytes.clone();
    unknown[1] = 9;
    assert!(Offer::parse(&meta, &unknown).is_err());
    let mut random = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
    let path = std::env::temp_dir().join(format!(
        "build8-proposal-object-{}.sqlite",
        hex::encode(random)
    ));
    let mut queue = ObjectQueue::open(&path, [27; 32]).unwrap();
    assert_eq!(
        queue.enqueue(ObjectKind::BlockProposal, &raw).unwrap(),
        offer
    );
    drop(queue);
    let queue = ObjectQueue::open(&path, [27; 32]).unwrap();
    assert_eq!(queue.read_complete(&id).unwrap(), raw);
    drop(queue);
    let db = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))
            .unwrap(),
        6
    );
    db.execute_batch("PRAGMA user_version=5").unwrap();
    drop(db);
    assert!(ObjectQueue::open(&path, [27; 32]).is_err());
    let db = rusqlite::Connection::open(&path).unwrap();
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))
            .unwrap(),
        5
    );
    assert_eq!(
        db.query_row("SELECT count(*) FROM objects", [], |r| r.get::<_, u32>(0))
            .unwrap(),
        1
    );
    drop(db);
    std::fs::remove_file(path).unwrap();
}
