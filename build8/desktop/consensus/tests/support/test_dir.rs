//! A per-test directory that the test owns.
//!
//! Tests that name a temp file only by process id (`build8-<name>-<pid>.sqlite`) and then assert it
//! does not exist can fail when a stale file from an earlier process with the same id is left in the
//! temp folder, and two tests that pick the same name collide. `TestDir` instead creates a fresh
//! directory with `create_dir`, which is atomic and fails if the name already exists, so the test owns
//! everything inside it. A name collision is retried with a new random suffix; an unexpected error
//! panics. SQLite sidecars (`-wal`, `-shm`, `-journal`) live next to the database and therefore inside
//! this directory. On drop only the directory this value created is removed, never anything else:
//! pre-existing files are never touched.
#![allow(dead_code)]
use std::{
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
static COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct TestDir {
    root: PathBuf,
}
impl TestDir {
    /// `prefix` is a short label: ASCII letters, digits, `-` and `_` only.
    pub fn new(prefix: &str) -> Self {
        assert!(
            !prefix.is_empty() && prefix.len() <= 48 && prefix.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "invalid test directory prefix"
        );
        let base = std::env::temp_dir();
        for _ in 0..64 {
            let mut salt = [0u8; 8];
            getrandom::getrandom(&mut salt).expect("operating system randomness");
            let salt: String = salt.iter().map(|b| format!("{b:02x}")).collect();
            let root = base.join(format!(
                "build8-{prefix}-{}-{}-{salt}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::SeqCst)
            ));
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)] {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(&root) {
                Ok(()) => {
                    #[cfg(unix)] {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
                    }
                    return Self { root };
                },
                Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("cannot create test directory {}: {e}", root.display()),
            }
        }
        panic!("could not allocate a unique test directory");
    }
    pub fn path(&self) -> &Path {
        &self.root
    }
    /// A plain file name inside the directory (no separators, no `..`).
    pub fn file(&self, name: &str) -> PathBuf {
        assert!(
            !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\']) && !name.contains(':'),
            "test file names must be plain names"
        );
        self.root.join(name)
    }
    pub fn is_empty(&self) -> bool {
        std::fs::read_dir(&self.root).map(|mut d| d.next().is_none()).unwrap_or(false)
    }
    /// The database and the sidecars SQLite may create beside it.
    pub fn sqlite_artifacts(&self, database: &str) -> [PathBuf; 4] {
        [
            self.file(database),
            self.file(&format!("{database}-wal")),
            self.file(&format!("{database}-shm")),
            self.file(&format!("{database}-journal")),
        ]
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        // Only the directory this value created; best effort (a leftover is never an error).
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
