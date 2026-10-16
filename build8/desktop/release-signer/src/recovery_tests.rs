//! Synthetic disk recovery with a fresh process; no production key material.
use super::*;
const PASSWORD: &str = "PUBLIC SYNTHETIC RECOVERY TEST PASSWORD";

#[test]
fn isolated_restore_child() {
    let Some(base) = std::env::var_os("BUILD8_SYNTHETIC_RECOVERY_CHILD") else {
        return;
    };
    let base = std::path::PathBuf::from(base);
    let encrypted = storage_io::read_vault(&base.join("backup.vault")).unwrap();
    let session = CustodianSession::open_synthetic(PASSWORD, &encrypted).unwrap();
    let public = session.public_descriptor().unwrap();
    drop(session);
    inspect_synthetic_descriptor(&public).unwrap();
    storage_io::write_new(&base.join("restored-public.cbor"), &public).unwrap();
}

#[test]
fn encrypted_backup_restores_in_fresh_process_after_original_loss() {
    let mut nonce = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    // Linux custody requires secure ancestors; use the isolated test workspace,
    // not a world-writable temporary-directory ancestor.
    let base = std::env::current_dir()
        .unwrap()
        .join(format!("synthetic-release-recovery-{}", hex::encode(nonce)));
    std::fs::create_dir(&base).unwrap();
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let original = base.join("original.vault");
    let backup = base.join("backup.vault");
    let (encrypted, public) = CustodianSession::create_synthetic(1, PASSWORD).unwrap();
    let expected = inspect_synthetic_descriptor(&public).unwrap();
    storage_io::write_new(&original, &encrypted).unwrap();
    drop(encrypted);
    {
        let saved = storage_io::read_vault(&original).unwrap();
        let unlocked = CustodianSession::open_synthetic(PASSWORD, &saved).unwrap();
        drop(unlocked);
        storage_io::write_new(&backup, &saved).unwrap();
        assert_eq!(storage_io::read_vault(&backup).unwrap(), saved);
    }
    // The child has neither the original file nor a retained unlocked session.
    std::fs::remove_file(&original).unwrap();
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "recovery_tests::isolated_restore_child",
            "--nocapture",
        ])
        .env("BUILD8_SYNTHETIC_RECOVERY_CHILD", &base)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let restored = storage_io::read_public(&base.join("restored-public.cbor"), 3400).unwrap();
    assert_eq!(inspect_synthetic_descriptor(&restored).unwrap(), expected);
    let saved = storage_io::read_vault(&backup).unwrap();
    assert!(CustodianSession::open_synthetic("WRONG PUBLIC PASSWORD", &saved).is_err());
    for changed in [0, 1, 2, 3, 4, saved.len() / 2, saved.len() - 1] {
        let mut corrupt = saved.clone();
        corrupt[changed] ^= 1;
        assert!(CustodianSession::open_synthetic(PASSWORD, &corrupt).is_err());
    }
    for end in [0, 1, saved.len() / 2, saved.len() - 1] {
        assert!(CustodianSession::open_synthetic(PASSWORD, &saved[..end]).is_err());
    }
    // A failed restore does not rewrite or repair the encrypted backup.
    assert_eq!(storage_io::read_vault(&backup).unwrap(), saved);
    assert!(storage_io::write_new(&backup, b"replacement").is_err());
    std::fs::remove_file(backup).unwrap();
    std::fs::remove_file(base.join("restored-public.cbor")).unwrap();
    std::fs::remove_dir(base).unwrap();
}
