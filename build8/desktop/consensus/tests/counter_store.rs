use mutiny_consensus_v8::counter_store::*;
struct Counter {
    value: u64,
    fail_after_increment: bool,
    fail_before_increment: bool,
}
impl MonotonicCounter for Counter {
    fn read(&mut self) -> Result<u64, String> {
        Ok(self.value)
    }
    fn increment(&mut self) -> Result<(), String> {
        if self.fail_before_increment {
            return Err("before".into());
        }
        self.value += 1;
        if self.fail_after_increment {
            return Err("after".into());
        }
        Ok(())
    }
}
#[test]
fn whole_snapshot_counter_crash_recovery_redefinition_and_rollback() {
    let base = std::env::temp_dir().join(format!("build8-counter-store-{}", std::process::id()));
    std::fs::create_dir(&base).unwrap();
    let path = base.join("voter.sqlite");
    let backup = base.join("backup.sqlite");
    let mut c = Counter {
        value: 100,
        fail_after_increment: false,
        fail_before_increment: false,
    };
    let ctx = [2; 32];
    {
        assert!(CounterStore::open(&path, ctx, None, &mut c).is_err());
        assert!(!path.exists(), "recovery created a missing database");
        let mut s = CounterStore::open(
            &path,
            ctx,
            Some((100, b"initial locks and reservations")),
            &mut c,
        )
        .unwrap();
        std::fs::copy(&path, &backup).unwrap();
        let mut stale = CounterStore::open(&path, ctx, None, &mut c).unwrap();
        c.fail_before_increment = true;
        assert!(s.commit(b"reserved vote and updated lock", &mut c).is_err());
        assert!(s.verify_current(&mut c).is_err());
        c.fail_before_increment = false;
        let mut restart = CounterStore::open(&path, ctx, None, &mut c).unwrap();
        assert_eq!(restart.snapshot(), b"reserved vote and updated lock");
        assert_eq!(c.value, 101);
        assert!(stale.commit(b"conflicting reservation", &mut c).is_err());
        c.fail_after_increment = true;
        assert!(
            restart
                .commit(b"same vote signed and persisted", &mut c)
                .is_err()
        );
        assert_eq!(c.value, 102);
    }
    c.fail_after_increment = false;
    {
        let mut s = CounterStore::open(&path, ctx, None, &mut c).unwrap();
        assert_eq!(s.snapshot(), b"same vote signed and persisted");
        assert_eq!(c.value, 102);
        s.verify_current(&mut c).unwrap();
        s.commit(b"same vote signed and persisted", &mut c).unwrap();
        assert_eq!(c.value, 102);
        assert!(CounterStore::open(&path, [3; 32], None, &mut c).is_err());
    }
    std::fs::copy(&backup, &path).unwrap();
    assert!(CounterStore::open(&path, ctx, None, &mut c).is_err());
    // A recreated counter starts above its prior value, not at zero.
    c.value = 103;
    assert!(CounterStore::open(&path, ctx, Some((100, b"initial")), &mut c).is_err());
    std::fs::remove_file(&path).unwrap();
    assert!(CounterStore::open(&path, ctx, Some((100, b"initial")), &mut c).is_err());
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn schema_context_and_bounded_rows_fail_before_counter_access() {
    struct GuardCounter {
        value: u64,
        accesses: usize,
    }
    impl MonotonicCounter for GuardCounter {
        fn read(&mut self) -> Result<u64, String> {
            self.accesses += 1;
            Ok(self.value)
        }
        fn increment(&mut self) -> Result<(), String> {
            self.accesses += 1;
            self.value += 1;
            Ok(())
        }
    }
    let base = std::env::temp_dir().join(format!("build8-counter-schema-{}", std::process::id()));
    std::fs::create_dir(&base).unwrap();
    let path = base.join("voter.sqlite");
    let mut counter = GuardCounter {
        value: 100,
        accesses: 0,
    };
    let ctx = [2; 32];
    let mut store = CounterStore::open(&path, ctx, Some((100, b"initial")), &mut counter).unwrap();
    let db = rusqlite::Connection::open(&path).unwrap();
    let cases = [
        (
            "CREATE TRIGGER injected AFTER UPDATE ON voter_snapshot BEGIN UPDATE voter_snapshot SET pending=NULL; END",
            "DROP TRIGGER injected",
        ),
        (
            "CREATE VIEW unexpected AS SELECT * FROM voter_snapshot",
            "DROP VIEW unexpected",
        ),
        (
            "CREATE INDEX unexpected ON voter_snapshot(context)",
            "DROP INDEX unexpected",
        ),
        (
            "CREATE TABLE sqliteXhidden(id INTEGER)",
            "DROP TABLE sqliteXhidden",
        ),
        (
            "UPDATE voter_snapshot SET context=zeroblob(32)",
            "UPDATE voter_snapshot SET context=?1",
        ),
        (
            "UPDATE voter_snapshot SET context='not a blob'",
            "UPDATE voter_snapshot SET context=?1",
        ),
        (
            "UPDATE voter_snapshot SET snapshot=zeroblob(4194305)",
            "UPDATE voter_snapshot SET snapshot=x'696e697469616c'",
        ),
        (
            "UPDATE voter_snapshot SET pending=zeroblob(4194305)",
            "UPDATE voter_snapshot SET pending=NULL",
        ),
        (
            "UPDATE voter_snapshot SET pending=x''",
            "UPDATE voter_snapshot SET pending=NULL",
        ),
        (
            "UPDATE voter_snapshot SET snapshot='initial'",
            "UPDATE voter_snapshot SET snapshot=x'696e697469616c'",
        ),
        (
            "UPDATE voter_snapshot SET tip=zeroblob(9)",
            "UPDATE voter_snapshot SET tip=x'0000000000000064'",
        ),
        ("PRAGMA application_id=123", "PRAGMA application_id=0"),
        ("PRAGMA user_version=123", "PRAGMA user_version=0"),
    ];
    for (inject, repair) in cases {
        db.execute_batch(inject).unwrap();
        let accesses = counter.accesses;
        assert!(
            store.verify_current(&mut counter).is_err(),
            "verify {inject}"
        );
        assert!(
            store.commit(b"must not install", &mut counter).is_err(),
            "commit {inject}"
        );
        assert!(
            CounterStore::open(&path, ctx, None, &mut counter).is_err(),
            "open {inject}"
        );
        assert_eq!(counter.accesses, accesses, "counter accessed for {inject}");
        assert_eq!(counter.value, 100);
        assert_eq!(store.snapshot(), b"initial");
        if repair.contains("?1") {
            db.execute(repair, [ctx.as_slice()]).unwrap();
        } else {
            db.execute_batch(repair).unwrap();
        }
        store.verify_current(&mut counter).unwrap();
    }
    // A matching table name/columns cannot substitute for the CHECK constraint.
    db.execute_batch("ALTER TABLE voter_snapshot RENAME TO old_snapshot; CREATE TABLE voter_snapshot(id INTEGER PRIMARY KEY,context BLOB NOT NULL,tip BLOB NOT NULL,snapshot BLOB NOT NULL,pending BLOB); INSERT INTO voter_snapshot SELECT * FROM old_snapshot; DROP TABLE old_snapshot;").unwrap();
    let accesses = counter.accesses;
    assert!(store.verify_current(&mut counter).is_err());
    assert!(store.commit(b"must not install", &mut counter).is_err());
    assert!(CounterStore::open(&path, ctx, None, &mut counter).is_err());
    assert_eq!(counter.accesses, accesses);
    drop(db);
    drop(store);
    std::fs::remove_dir_all(base).unwrap();
}
