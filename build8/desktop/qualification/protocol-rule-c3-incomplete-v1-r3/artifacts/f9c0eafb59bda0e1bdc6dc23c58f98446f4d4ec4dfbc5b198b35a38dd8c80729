use super::*;
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static SERIAL: AtomicU64 = AtomicU64::new(0);
#[test]
fn native_and_hybrid_journals_cannot_be_silently_reinterpreted() {
    let legacy = Fixture::new();
    let hybrid = Fixture::new();
    let mut hardware = Hardware {
        value: 100,
        ..Default::default()
    };
    drop(
        crate::counter_store::CounterStore::open(
            &legacy.path,
            [1; 32],
            Some((100, b"native public snapshot")),
            &mut hardware,
        )
        .unwrap(),
    );
    let original = std::fs::read(&legacy.path).unwrap();
    assert!(CounterStore::open(&legacy.path, [1; 32], None, None, &mut hardware).is_err());
    assert!(
        CounterStore::open(
            &legacy.path,
            [1; 32],
            None,
            Some((100, b"replacement")),
            &mut hardware
        )
        .is_err()
    );
    assert!(std::fs::read(&legacy.path).unwrap() == original);
    drop(initial(&hybrid, &mut hardware));
    assert!(
        crate::counter_store::CounterStore::open(&hybrid.path, [1; 32], None, &mut hardware)
            .is_err()
    );
    assert_eq!(hardware.value, 100);
    assert_eq!(hardware.increments, 0);
}
struct Fixture {
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "build8-synthetic-migration-{}-{}.sqlite",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(!path.exists());
        Self { path }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.path.exists() {
            std::fs::remove_file(&self.path).unwrap();
        }
    }
}
#[derive(Default)]
struct Hardware {
    value: u64,
    increments: u64,
    fail: u8,
}
impl Counter for Hardware {
    fn read(&mut self) -> std::result::Result<u64, String> {
        if self.fail == 3 {
            self.fail = 0;
            Err("read".into())
        } else {
            Ok(self.value)
        }
    }
    fn increment(&mut self) -> std::result::Result<(), String> {
        if self.fail == 1 {
            self.fail = 0;
            return Err("before increment".into());
        }
        self.value = self.value.checked_add(1).ok_or("overflow")?;
        self.increments += 1;
        if self.fail == 2 {
            self.fail = 0;
            return Err("after increment".into());
        }
        Ok(())
    }
}
fn initial(f: &Fixture, h: &mut Hardware) -> CounterStore {
    CounterStore::open(
        &f.path,
        [1; 32],
        None,
        Some((h.value, b"old snapshot sequence 37")),
        h,
    )
    .unwrap()
}
const NEXT: &[u8] = b"new snapshot sequence 37 at next finalized height";
#[test]
fn context_and_snapshot_change_with_one_monotonic_advance() {
    let f = Fixture::new();
    let mut h = Hardware {
        value: 100,
        ..Default::default()
    };
    let mut store = initial(&f, &mut h);
    store.rebind([2; 32], NEXT, &mut h).unwrap();
    assert_eq!(h.value, 101);
    assert_eq!(h.increments, 1);
    assert_eq!(store.context(), [2; 32]);
    assert_eq!(store.snapshot(), NEXT);
    store.verify_current(&mut h).unwrap();
    drop(store);
    assert!(CounterStore::open(&f.path, [1; 32], None, None, &mut h).is_err());
    let mut reopened = CounterStore::open(&f.path, [2; 32], None, None, &mut h).unwrap();
    assert_eq!(reopened.snapshot(), NEXT);
    reopened.commit(NEXT, &mut h).unwrap();
    assert_eq!(h.increments, 1);
    reopened.commit(b"next vote sequence 38", &mut h).unwrap();
    assert_eq!(h.increments, 2);
}
#[test]
fn every_persistent_migration_window_recovers_exactly_once() {
    for mode in 1..=5 {
        let f = Fixture::new();
        let mut h = Hardware {
            value: 100,
            ..Default::default()
        };
        let mut store = initial(&f, &mut h);
        match mode {
            1 => FAULT.with(|x| x.set(1)),
            2 => h.fail = 1,
            3 => h.fail = 2,
            4 => FAULT.with(|x| x.set(2)),
            5 => FAULT.with(|x| x.set(3)),
            _ => unreachable!(),
        }
        assert!(store.rebind([2; 32], NEXT, &mut h).is_err(), "fault {mode}");
        assert!(store.verify_current(&mut h).is_err());
        drop(store);
        // The durable intent has one exact target. Neither old-context startup nor
        // an unrelated context can recover, sign, or advance the hardware counter.
        let before = h.value;
        for (expected, predecessor) in [
            ([1; 32], None),
            ([3; 32], Some([1; 32])),
            ([2; 32], None),
            ([2; 32], Some([4; 32])),
        ] {
            assert!(CounterStore::open(&f.path, expected, predecessor, None, &mut h).is_err());
            assert_eq!(h.value, before);
        }
        let reopened = CounterStore::open(&f.path, [2; 32], Some([1; 32]), None, &mut h).unwrap();
        assert_eq!(reopened.snapshot(), NEXT);
        assert_eq!(reopened.context(), [2; 32]);
        assert_eq!(h.value, 101);
        assert_eq!(h.increments, 1);
        drop(reopened);
        assert!(CounterStore::open(&f.path, [2; 32], None, None, &mut h).is_ok());
        assert_eq!(h.increments, 1);
    }
}
#[test]
fn old_backup_and_stale_writer_cannot_resume_after_migration() {
    let f = Fixture::new();
    let backup = Fixture::new();
    let mut h = Hardware {
        value: 100,
        ..Default::default()
    };
    let mut first = initial(&f, &mut h);
    let mut stale = CounterStore::open(&f.path, [1; 32], None, None, &mut h).unwrap();
    std::fs::copy(&f.path, &backup.path).unwrap();
    first.rebind([2; 32], NEXT, &mut h).unwrap();
    assert!(stale.commit(b"conflicting old state", &mut h).is_err());
    assert!(CounterStore::open(&backup.path, [1; 32], None, None, &mut h).is_err());
    assert_eq!(h.value, 101);
}
#[test]
fn malformed_partial_intent_cannot_increment_or_repair() {
    for mode in 0..6 {
        let f = Fixture::new();
        let mut h = Hardware {
            value: 100,
            ..Default::default()
        };
        drop(initial(&f, &mut h));
        let db = Connection::open(&f.path).unwrap();
        match mode {
            0 => db
                .execute(
                    "UPDATE voter_migration SET pending_context=?1",
                    [&[2u8; 32]],
                )
                .unwrap(),
            1 => db
                .execute("UPDATE voter_migration SET pending_snapshot=?1", [NEXT])
                .unwrap(),
            2 => db
                .execute(
                    "UPDATE voter_migration SET pending_context=?1,pending_snapshot=?2",
                    params![&[2u8; 31], NEXT],
                )
                .unwrap(),
            3 => db
                .execute(
                    "UPDATE voter_migration SET pending_context=?1,pending_snapshot=?2",
                    params![&[0u8; 32], NEXT],
                )
                .unwrap(),
            4 => db
                .execute("UPDATE voter_migration SET tip=?1", [&[0u8; 7]])
                .unwrap(),
            _ => db
                .execute(
                    "UPDATE voter_migration SET pending_context=?1,pending_snapshot=?2",
                    params![&[2u8; 32], Vec::<u8>::new()],
                )
                .unwrap(),
        };
        drop(db);
        assert!(CounterStore::open(&f.path, [2; 32], Some([1; 32]), None, &mut h).is_err());
        assert_eq!(h.increments, 0);
    }
}
#[test]
fn missing_and_existing_stores_never_silently_initialize() {
    let f = Fixture::new();
    let mut h = Hardware {
        value: 100,
        ..Default::default()
    };
    assert!(CounterStore::open(&f.path, [1; 32], None, None, &mut h).is_err());
    assert!(!f.path.exists());
    drop(initial(&f, &mut h));
    assert!(CounterStore::open(&f.path, [1; 32], None, Some((100, b"reset")), &mut h).is_err());
    assert_eq!(
        CounterStore::open(&f.path, [1; 32], None, None, &mut h)
            .unwrap()
            .snapshot(),
        b"old snapshot sequence 37"
    );
}
#[test]
fn schema_bounds_context_and_counter_overflow_fail_closed() {
    let f = Fixture::new();
    let mut h = Hardware {
        value: u64::MAX,
        ..Default::default()
    };
    let mut s = initial(&f, &mut h);
    assert!(s.rebind([2; 32], NEXT, &mut h).is_err());
    assert_eq!(h.increments, 0);
    assert!(s.rebind([1; 32], NEXT, &mut h).is_err());
    assert!(s.rebind([0; 32], NEXT, &mut h).is_err());
    assert!(s.commit(&vec![0; MAX_SNAPSHOT + 1], &mut h).is_err());
    assert!(s.commit(&[], &mut h).is_err());
    drop(s);
    let db = Connection::open(&f.path).unwrap();
    db.execute_batch("CREATE TABLE unrecognized(x);").unwrap();
    drop(db);
    assert!(CounterStore::open(&f.path, [1; 32], None, None, &mut h).is_err());
    assert_eq!(h.increments, 0);
}
#[test]
fn counter_read_failure_poisoned_instance_requires_reopen() {
    let f = Fixture::new();
    let mut h = Hardware {
        value: 100,
        ..Default::default()
    };
    let mut s = initial(&f, &mut h);
    h.fail = 3;
    assert!(s.verify_current(&mut h).is_err());
    assert!(s.commit(NEXT, &mut h).is_err());
    drop(s);
    let mut s = CounterStore::open(&f.path, [1; 32], None, None, &mut h).unwrap();
    s.verify_current(&mut h).unwrap();
    assert_eq!(h.increments, 0);
}
#[test]
fn unrelated_hardware_advance_rejects_pending_migration() {
    let f = Fixture::new();
    let mut h = Hardware {
        value: 100,
        ..Default::default()
    };
    let mut s = initial(&f, &mut h);
    FAULT.with(|x| x.set(1));
    assert!(s.rebind([2; 32], NEXT, &mut h).is_err());
    drop(s);
    h.value = 102;
    assert!(CounterStore::open(&f.path, [2; 32], Some([1; 32]), None, &mut h).is_err());
    assert_eq!(h.increments, 0);
}

// This fsynced integer is a synthetic cross-process counter, not a TPM or an
// anti-rollback claim for ordinary files. It lets child termination exercise
// real SQLite hot-journal recovery without touching any hardware.
struct DiskCounter(PathBuf);
impl Counter for DiskCounter {
    fn read(&mut self) -> std::result::Result<u64, String> {
        let raw = std::fs::read(&self.0).map_err(|_| "counter read")?;
        Ok(u64::from_be_bytes(
            raw.try_into().map_err(|_| "counter length")?,
        ))
    }
    fn increment(&mut self) -> std::result::Result<(), String> {
        use std::io::Write;
        let next = self.read()?.checked_add(1).ok_or("counter overflow")?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .open(&self.0)
            .map_err(|_| "counter open")?;
        file.write_all(&next.to_be_bytes())
            .map_err(|_| "counter write")?;
        file.sync_all().map_err(|_| "counter sync")?;
        Ok(())
    }
}
#[test]
fn crash_child_migration() {
    let Some(path) = std::env::var_os("BUILD8_SYNTHETIC_MIGRATION_CHILD") else {
        return;
    };
    let path = PathBuf::from(path);
    let phase: u8 = std::env::var("BUILD8_SYNTHETIC_MIGRATION_PHASE")
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=4).contains(&phase));
    let mut counter = DiskCounter(path.with_extension("counter"));
    let mut store = CounterStore::open(&path, [1; 32], None, None, &mut counter).unwrap();
    CRASH.with(|p| p.set(phase));
    store.rebind([2; 32], NEXT, &mut counter).unwrap();
    panic!("synthetic crash point was not reached");
}
#[test]
fn real_child_termination_recovers_intent_and_hot_journal() {
    use std::io::Write;
    for phase in 1..=4 {
        let f = Fixture::new();
        let counter_path = f.path.with_extension("counter");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&counter_path)
            .unwrap();
        file.write_all(&100u64.to_be_bytes()).unwrap();
        file.sync_all().unwrap();
        drop(file);
        let mut counter = DiskCounter(counter_path.clone());
        drop(
            CounterStore::open(
                &f.path,
                [1; 32],
                None,
                Some((100, b"old snapshot sequence 37")),
                &mut counter,
            )
            .unwrap(),
        );
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "counter_store_v2::tests::crash_child_migration",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("BUILD8_SYNTHETIC_MIGRATION_CHILD", &f.path)
            .env("BUILD8_SYNTHETIC_MIGRATION_PHASE", phase.to_string())
            .output()
            .unwrap();
        assert_eq!(
            child.status.code(),
            Some(91),
            "crash phase {phase}: {}",
            String::from_utf8_lossy(&child.stderr)
        );
        assert_eq!(counter.read().unwrap(), if phase == 1 { 100 } else { 101 });
        let recovered =
            CounterStore::open(&f.path, [2; 32], Some([1; 32]), None, &mut counter).unwrap();
        assert_eq!(recovered.snapshot(), NEXT);
        assert_eq!(recovered.context(), [2; 32]);
        assert_eq!(counter.read().unwrap(), 101);
        drop(recovered);
        assert!(CounterStore::open(&f.path, [1; 32], None, None, &mut counter).is_err());
        std::fs::remove_file(counter_path).unwrap();
    }
}
