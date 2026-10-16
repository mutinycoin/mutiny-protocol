//! Proof for the `TestDir` helper: unique under concurrency, owned by its test, never touches
//! pre-existing files, and removes the SQLite sidecars it owns.
#[path = "support/test_dir.rs"]
mod test_dir;
use std::{collections::HashSet, sync::{Arc, Mutex}, thread};
use test_dir::TestDir;

#[test]
fn directories_are_unique_atomic_and_start_empty_under_concurrency() {
    let seen = Arc::new(Mutex::new(HashSet::new()));
    let workers: Vec<_> = (0..16)
        .map(|_| {
            let seen = seen.clone();
            thread::spawn(move || {
                for _ in 0..64 {
                    let dir = TestDir::new("helper-concurrent");
                    assert!(dir.path().is_dir());
                    assert!(dir.is_empty(), "a fresh directory must be empty");
                    assert!(seen.lock().unwrap().insert(dir.path().to_path_buf()), "two tests were given the same directory");
                    std::fs::write(dir.file("x.sqlite"), b"owned").unwrap();
                }
            })
        })
        .collect();
    for w in workers {
        w.join().unwrap();
    }
    assert_eq!(seen.lock().unwrap().len(), 16 * 64);
    for path in seen.lock().unwrap().iter() {
        assert!(!path.exists(), "every owned directory is removed on drop: {}", path.display());
    }
}

#[test]
fn a_stale_pid_named_file_cannot_collide_and_is_never_deleted() {
    // The old pattern: temp/build8-<name>-<pid>.sqlite, then assert!(!path.exists()).
    let stale = std::env::temp_dir().join(format!("build8-helper-stale-{}.sqlite", std::process::id()));
    let decoy_dir = std::env::temp_dir().join(format!("build8-helper-decoy-{}", std::process::id()));
    std::fs::write(&stale, b"left over from an earlier process").unwrap();
    std::fs::create_dir_all(&decoy_dir).unwrap();
    std::fs::write(decoy_dir.join("keep.txt"), b"not ours").unwrap();
    for _ in 0..200 {
        let dir = TestDir::new("helper-stale");
        let path = dir.file("voter.sqlite");
        assert!(!path.exists(), "the old assertion holds by construction");
        std::fs::write(&path, b"x").unwrap();
    }
    assert_eq!(std::fs::read(&stale).unwrap(), b"left over from an earlier process", "pre-existing file untouched");
    assert_eq!(std::fs::read(decoy_dir.join("keep.txt")).unwrap(), b"not ours", "pre-existing directory untouched");
    std::fs::remove_file(&stale).unwrap();
    std::fs::remove_dir_all(&decoy_dir).unwrap();
}

#[test]
fn sqlite_sidecars_live_inside_the_owned_directory_and_are_removed_with_it() {
    let dir = TestDir::new("helper-sqlite");
    let artifacts = dir.sqlite_artifacts("voter.sqlite");
    for p in &artifacts {
        assert!(!p.exists());
        assert_eq!(p.parent().unwrap(), dir.path(), "sidecar names resolve inside the directory");
    }
    let conn = rusqlite::Connection::open(&artifacts[0]).unwrap();
    let mode: String = conn.query_row("PRAGMA journal_mode=WAL", [], |r| r.get(0)).unwrap();
    assert_eq!(mode.to_lowercase(), "wal");
    conn.execute_batch("CREATE TABLE t(x INTEGER); INSERT INTO t VALUES (1);").unwrap();
    assert!(artifacts[0].exists());
    assert!(artifacts[1].exists() || artifacts[2].exists(), "WAL mode created sidecars beside the database");
    let root = dir.path().to_path_buf();
    drop(conn);
    drop(dir);
    assert!(!root.exists(), "database and sidecars are removed with the directory");
}

#[test]
fn file_names_must_be_plain_and_cannot_escape_the_directory() {
    let dir = TestDir::new("helper-names");
    for bad in ["", ".", "..", "a/b", "a\\b", "../x", "C:x"] {
        let r = std::panic::catch_unwind(|| {
            let d = TestDir::new("helper-names-inner");
            d.file(bad);
        });
        assert!(r.is_err(), "{bad:?} must be rejected");
    }
    assert_eq!(dir.file("ok.sqlite").parent().unwrap(), dir.path());
}

#[test]
fn invalid_prefixes_are_rejected() {
    for bad in ["", "a b", "../x", "a/b", "x".repeat(49).as_str()] {
        let bad = bad.to_string();
        assert!(std::panic::catch_unwind(move || TestDir::new(&bad)).is_err());
    }
}
