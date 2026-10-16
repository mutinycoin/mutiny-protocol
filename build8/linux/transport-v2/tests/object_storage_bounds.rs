//! Public synthetic cache corruption fixtures; never a production queue.
use mutiny_transport_v2::{Error, objects::*};
use rusqlite::{Connection, params};

#[test]
fn corrupt_fragments_fail_before_delivery_or_retry_reservation() {
    let path = std::env::temp_dir().join(format!(
        "build8-object-bounds-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut queue = ObjectQueue::open(&path, [9; 32]).unwrap();
    let public = vec![42; 141];
    let offer = queue
        .enqueue(ObjectKind::SignedTransaction, &public)
        .unwrap();
    let corrupt = Connection::open(&path).unwrap();
    corrupt
        .execute_batch("PRAGMA ignore_check_constraints=ON")
        .unwrap();
    let wanted = Bitmap {
        start: 0,
        bits: vec![true, false],
    };
    let (mut meta, _) = offer.have(0).unwrap();
    meta.kind = 3;
    for raw in [
        vec![],
        vec![0u8; 139],
        vec![0u8; 141],
        vec![0u8; 1024 * 1024],
    ] {
        corrupt
            .execute(
                "UPDATE fragments SET data=?1 WHERE id=?2 AND idx=0",
                params![raw, offer.id.as_slice()],
            )
            .unwrap();
        assert!(queue.next_fragment(&offer.id, &wanted, 0).is_err());
        assert!(queue.read_complete(&offer.id).is_err());
        assert!(queue.receive(&meta, &public[..140]).is_err());
        let attempts: u8 = corrupt
            .query_row("SELECT attempts FROM fragments WHERE idx=0", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(attempts, 0, "corrupt cache must not consume retry budget");
    }
    corrupt
        .execute("UPDATE fragments SET data=?1 WHERE idx=0", [&public[..140]])
        .unwrap();
    for value in [-1, 9, 256] {
        corrupt
            .execute("UPDATE fragments SET attempts=?1 WHERE idx=0", [value])
            .unwrap();
        assert!(queue.next_fragment(&offer.id, &wanted, 0).is_err());
    }
    corrupt
        .execute("UPDATE fragments SET attempts=0 WHERE idx=0", [])
        .unwrap();
    for flag in [-1, 2, 256] {
        corrupt
            .execute("UPDATE objects SET complete=?1", [flag])
            .unwrap();
        assert!(queue.read_complete(&offer.id).is_err());
    }
    corrupt
        .execute("UPDATE objects SET complete=1", [])
        .unwrap();
    corrupt
        .execute(
            "INSERT INTO fragments(id,idx,data) VALUES(?1,2,zeroblob(0))",
            [offer.id.as_slice()],
        )
        .unwrap();
    assert_eq!(queue.read_complete(&offer.id).unwrap_err(), Error::Encoding);
    corrupt
        .execute("DELETE FROM fragments WHERE idx=2", [])
        .unwrap();
    assert_eq!(queue.read_complete(&offer.id).unwrap(), public);
    assert_eq!(
        queue
            .next_fragment(&offer.id, &wanted, 0)
            .unwrap()
            .unwrap()
            .1,
        public[..140]
    );
    assert!(
        queue.read_complete(&offer.id).is_ok(),
        "read snapshots must release their transactions"
    );
    meta.hops = 17;
    assert!(queue.receive(&meta, &public[..140]).is_err());
    let (mut have, payload) = offer.have(0).unwrap();
    have.hops = 17;
    assert!(Offer::parse(&have, &payload).is_err());
    drop(corrupt);
    drop(queue);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn corrupt_peer_blob_rejected_on_open() {
    let path = std::env::temp_dir().join(format!(
        "build8-peer-bounds-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    drop(ObjectQueue::open(&path, [9; 32]).unwrap());
    let corrupt = Connection::open(&path).unwrap();
    corrupt
        .execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE peer SET id=zeroblob(1048576);")
        .unwrap();
    assert!(matches!(
        ObjectQueue::open(&path, [9; 32]),
        Err(Error::Storage)
    ));
    drop(corrupt);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn live_queue_rejects_schema_changes_and_peer_rebinding_before_mutation() {
    let path = std::env::temp_dir().join(format!(
        "build8-queue-schema-{}-{}.sqlite",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let mut queue = ObjectQueue::open(&path, [9; 32]).unwrap();
    let offer = queue
        .enqueue(ObjectKind::SignedTransaction, &[42; 141])
        .unwrap();
    let corrupt = Connection::open(&path).unwrap();
    let wanted = Bitmap {
        start: 0,
        bits: vec![true],
    };
    let (mut m, _) = offer.have(0).unwrap();
    m.kind = 3;
    for (create, remove) in [
        (
            "CREATE TRIGGER reset_budget AFTER UPDATE OF attempts ON fragments BEGIN UPDATE fragments SET attempts=0; END",
            "DROP TRIGGER reset_budget",
        ),
        ("CREATE TABLE sqliteXextra(n)", "DROP TABLE sqliteXextra"),
        (
            "CREATE VIEW extra AS SELECT * FROM fragments",
            "DROP VIEW extra",
        ),
        (
            "CREATE INDEX extra ON fragments(attempts)",
            "DROP INDEX extra",
        ),
    ] {
        corrupt.execute_batch(create).unwrap();
        assert!(queue.next_fragment(&offer.id, &wanted, 0).is_err());
        assert!(queue.read_complete(&offer.id).is_err());
        assert!(queue.offer(&offer).is_err());
        assert!(queue.receive(&m, &[42; 140]).is_err());
        assert!(queue.missing(&offer.id, 0, 1).is_err());
        assert!(queue.acknowledge(&offer.id, &wanted).is_err());
        assert!(queue.acknowledged(&offer.id, 0, 1).is_err());
        assert!(queue.discard(&offer.id).is_err());
        assert!(ObjectQueue::open(&path, [9; 32]).is_err());
        let count: i64 = corrupt
            .query_row("SELECT count(*) FROM objects", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
        let attempts: i64 = corrupt
            .query_row("SELECT attempts FROM fragments WHERE idx=0", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(attempts, 0);
        corrupt.execute_batch(remove).unwrap();
    }
    corrupt
        .execute("UPDATE peer SET id=?1", [[8u8; 32].as_slice()])
        .unwrap();
    assert_eq!(queue.read_complete(&offer.id).unwrap_err(), Error::Context);
    assert!(queue.next_fragment(&offer.id, &wanted, 0).is_err());
    corrupt
        .execute("UPDATE peer SET id=?1", [[9u8; 32].as_slice()])
        .unwrap();
    assert_eq!(queue.read_complete(&offer.id).unwrap(), [42; 141]);
    assert!(
        queue
            .next_fragment(&offer.id, &wanted, 0)
            .unwrap()
            .is_some()
    );
    drop(corrupt);
    drop(queue);
    std::fs::remove_file(path).unwrap();
}
