// A per-test directory that the test owns: created atomically with a random name (create_dir fails
// if the name exists, so a stale directory is never reused) and removed on drop. Only the directory
// this value created is ever removed.
//
// Owned by phase 1 of the wallet plan; later phases use it and do not edit it.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

pub struct TempDir {
    root: PathBuf,
}

impl TempDir {
    pub fn new(label: &str) -> Self {
        assert!(
            label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "plain label only"
        );
        for _ in 0..16 {
            let mut salt = [0u8; 8];
            mutiny_crypto_v2::fill_os_random(&mut salt).expect("operating system randomness");
            let root = std::env::temp_dir().join(format!(
                "build8-wallet-core-{label}-{}-{}",
                std::process::id(),
                hex::encode(salt)
            ));
            match mutiny_consensus_v8::submission_pool_v1::SubmissionPool::private_directory(&root)
            {
                Ok(true) => return Self { root },
                Ok(false) => continue,
                Err(error) => panic!("cannot create {}: {error:?}", root.display()),
            }
        }
        panic!("could not allocate a unique test directory");
    }

    pub fn path(&self) -> &Path {
        &self.root
    }

    pub fn file(&self, name: &str) -> PathBuf {
        assert!(
            !name.contains(['/', '\\', ':']) && name != ".." && name != ".",
            "plain file name only"
        );
        self.root.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "PUBLIC TEST-VALUE failed fixture retained: {}",
                self.root.display()
            );
            return;
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}
