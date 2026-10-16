//! Public TEST-VALUE transport bounds/migration. Delivery is never confirmation.
use mutiny_transport_v2::{Error, objects::*};
use rusqlite::{Connection, params, types::Value};
fn dir() -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "build8-submission-objects-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&p).unwrap();
    p
}
const OLD_OBJECTS: &str = "CREATE TABLE objects(id BLOB PRIMARY KEY CHECK(length(id)=32), kind INTEGER NOT NULL CHECK(kind IN (1,2,3,4,5,6,7,8)), length INTEGER NOT NULL CHECK(length BETWEEN 1 AND 2097152), complete INTEGER NOT NULL CHECK(complete IN (0,1)), invalid INTEGER NOT NULL CHECK(invalid IN (0,1)))";
const FRAGMENTS: &str = "CREATE TABLE fragments(id BLOB NOT NULL REFERENCES objects(id) ON DELETE CASCADE, idx INTEGER NOT NULL CHECK(idx BETWEEN 0 AND 14979), data BLOB NOT NULL CHECK(length(data) BETWEEN 1 AND 140), acked INTEGER NOT NULL DEFAULT 0 CHECK(acked IN (0,1)), attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 8), PRIMARY KEY(id,idx))";
fn old(path: &std::path::Path, kind: u8, length: usize) {
    let db = Connection::open(path).unwrap();
    db.execute_batch("CREATE TABLE peer(id BLOB NOT NULL CHECK(length(id)=32))")
        .unwrap();
    db.execute_batch(OLD_OBJECTS).unwrap();
    db.execute_batch(FRAGMENTS).unwrap();
    db.execute("INSERT INTO peer VALUES(?1)", [[1u8; 32].as_slice()])
        .unwrap();
    db.execute(
        "INSERT INTO objects VALUES(?1,?2,?3,0,0)",
        params![[2u8; 32].as_slice(), kind, length],
    )
    .unwrap();
    db.execute(
        "INSERT INTO fragments VALUES(?1,0,?2,1,3)",
        params![[2u8; 32].as_slice(), vec![7u8; 140]],
    )
    .unwrap();
    db.pragma_update(None, "user_version", 6).unwrap();
}
fn rows(db: &Connection, table: &str) -> Vec<Vec<Value>> {
    let mut q = db
        .prepare(&format!("SELECT * FROM {table} ORDER BY {}",if table=="peer"{"1"}else{"1,2"}))
        .unwrap();
    let n = q.column_count();
    q.query_map([], |r| {
        (0..n)
            .map(|i| r.get(i))
            .collect::<rusqlite::Result<Vec<Value>>>()
    })
    .unwrap()
    .map(|r| r.unwrap())
    .collect()
}
#[test]
fn new_typed_object_limits_and_separate_submission_budget_do_not_starve_control() {
    for (kind, max) in [
        (ObjectKind::SignedTransaction, 16384),
        (ObjectKind::SignedOperation, 16384),
        (ObjectKind::StatusQuery, 4096),
        (ObjectKind::StatusReport, 16384),
    ] {
        assert_eq!(kind.max_bytes(), max);
        assert!(object_id(kind, &vec![0; max]).is_ok());
        assert_eq!(object_id(kind, &vec![0; max + 1]), Err(Error::Limit));
        let offer = Offer {
            id: [1; 32],
            kind,
            length: max,
        };
        let (meta, raw) = offer.have(0).unwrap();
        assert_eq!(Offer::parse(&meta, &raw).unwrap(), offer);
    }
    let base = dir();
    let path = base.join("queue.sqlite");
    let mut q = ObjectQueue::open(&path, [1; 32]).unwrap();
    for n in 0..MAX_OBJECTS {
        q.enqueue(ObjectKind::ContinuityVote, &[n as u8; 281])
            .unwrap();
    }
    assert!(matches!(
        q.enqueue(ObjectKind::WorkProbeRequest, &[9]),
        Err(Error::Limit)
    ));
    q.enqueue(ObjectKind::SignedOperation, &[8; 16384]).unwrap();
    q.enqueue(ObjectKind::SignedTransaction, &[9; 16384])
        .unwrap();
    assert!(matches!(
        q.enqueue(ObjectKind::SignedOperation, &[10]),
        Err(Error::Limit)
    ));
    drop(q);
    let q = ObjectQueue::open(&path, [1; 32]).unwrap();
    drop(q);
    std::fs::remove_dir_all(base).unwrap();
}
#[test]
fn v6_partial_fragments_receipts_and_attempts_are_preserved_atomically_on_upgrade() {
    let base = dir();
    let path = base.join("old.sqlite");
    old(&path, 3, 281);
    let db = Connection::open(&path).unwrap();
    let before = (
        rows(&db, "peer"),
        rows(&db, "objects"),
        rows(&db, "fragments"),
    );
    drop(db);
    let mut queue = ObjectQueue::open(&path, [1; 32]).unwrap();
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        7
    );
    assert_eq!(
        (
            rows(&db, "peer"),
            rows(&db, "objects"),
            rows(&db, "fragments")
        ),
        before
    );
    assert_eq!(
        queue.missing(&[2; 32], 0, 3).unwrap().bits,
        vec![false, true, true]
    );
    queue
        .enqueue(ObjectKind::SignedOperation, &[4; 4096])
        .unwrap();
    drop(db);
    drop(queue);
    let q = ObjectQueue::open(&path, [1; 32]).unwrap();
    drop(q);
    std::fs::remove_dir_all(base).unwrap();
}
#[test]
fn incompatible_old_submission_and_schema_refusals_leave_old_bytes_and_version_intact() {
    let base = dir();
    let path = base.join("oversized.sqlite");
    old(&path, 1, 16385);
    let db = Connection::open(&path).unwrap();
    let before = (rows(&db, "objects"), rows(&db, "fragments"));
    drop(db);
    assert!(matches!(
        ObjectQueue::open(&path, [1; 32]),
        Err(Error::Limit)
    ));
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        6
    );
    assert_eq!((rows(&db, "objects"), rows(&db, "fragments")), before);
    drop(db);
    let path = base.join("wrong.sqlite");
    old(&path, 3, 281);
    let db = Connection::open(&path).unwrap();
    db.execute_batch("CREATE TRIGGER unexpected BEFORE INSERT ON objects BEGIN SELECT RAISE(ABORT,'fixture'); END").unwrap();
    assert!(matches!(
        ObjectQueue::open(&path, [1; 32]),
        Err(Error::Storage)
    ));
    assert_eq!(
        db.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
            .unwrap(),
        6
    );
    drop(db);
    std::fs::remove_dir_all(base).unwrap();
}
