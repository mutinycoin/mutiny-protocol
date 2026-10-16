//! A13 (Architect's Continuation Order, 4 Oct 2026): a PINNED qualification helper keeps the production layout checks
//! (Linux only, root-owned path, no symlink, no set-user-ID or set-group-ID bit, the pinned bytes), and a byte hash
//! identifies the helper PROGRAM, not the physical authenticity of the host it runs on.
//!
//! QUALIFICATION TOOLING ONLY: the bridge below is never linked into a shipping binary
//! (`consensus/tests/private_evidence_guard.rs`). Every test here uses temporary files or synthetic metadata; no TPM, no
//! helper process and no host-specific value is involved. Evidence class: software behaviour on the host that ran it.
#[path = "../examples/support/external_helper_bridge.rs"]
mod external_helper_bridge;
#[path = "../../node/src/tpm_helper_policy.rs"]
#[allow(dead_code)]
mod tpm_helper_policy;

use external_helper_bridge::HelperSpec;
use sha2::{Digest, Sha256};
use std::path::Path;
use tpm_helper_policy::{PathEntry, check_program};

fn spec(program: &str, pin: Option<[u8; 32]>) -> HelperSpec {
    HelperSpec { argv: vec![program.to_string()], program_sha256: pin }
}

/// Off Linux a pinned qualification helper is always refused, before any file is opened.
#[cfg(not(target_os = "linux"))]
#[test]
fn pinned_qualification_helper_is_refused_off_linux() {
    let err = spec("/usr/local/libexec/mutiny/qualification-helper", Some([7; 32])).validate().unwrap_err();
    assert!(err.contains("requires Linux"), "{err}");
    // The lexical rule still applies first: a relative or dotted path is refused with its own reason.
    let err = spec("relative/helper", Some([7; 32])).validate().unwrap_err();
    assert!(err.contains("absolute"), "{err}");
}

/// On Linux a pinned helper gets the production layout checks against the REAL filesystem: a file owned by the test user
/// (unless the test runs as root), a symlink, a group-writable file and a set-user-ID file are each refused for their own
/// reason, although the pin matches the bytes. Compiled and run on Linux only: NOT run on the Windows host of this round.
#[cfg(target_os = "linux")]
#[test]
fn pinned_qualification_helper_gets_the_production_layout_checks_on_linux() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let bytes = b"#!/bin/false\nTEST-VALUE qualification helper\n";
    let pin: [u8; 32] = Sha256::digest(bytes).into();
    let mut salt = [0u8; 8];
    getrandom::getrandom(&mut salt).unwrap();
    let dir = std::env::temp_dir().join(format!("build8-a13-helper-{}", hex::encode(salt)));
    std::fs::create_dir(&dir).unwrap();
    let make = |name: &str, mode: u32| {
        let p = dir.join(name);
        std::fs::write(&p, bytes).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        p
    };
    let plain = make("plain", 0o755);
    let writable = make("writable", 0o775);
    let setuid = make("setuid", 0o4755);
    let link = dir.join("link");
    std::os::unix::fs::symlink(&plain, &link).unwrap();
    let check = |p: &Path| spec(p.to_str().unwrap(), Some(pin)).validate().unwrap_err();
    assert!(check(&link).contains("symlink"));
    assert!(check(&writable).contains("writable"));
    if std::fs::metadata(&setuid).unwrap().mode() & 0o4000 != 0 {
        assert!(check(&setuid).contains("setuid or setgid"));
    }
    // SAFETY: getuid(2) has no preconditions and cannot fail.
    if unsafe { libc::getuid() } != 0 {
        assert!(check(&plain).contains("not root-owned"));
    }
    for p in [&link, &plain, &writable, &setuid] {
        std::fs::remove_file(p).unwrap();
    }
    std::fs::remove_dir(&dir).unwrap();
}

/// A byte hash identifies the helper, not its host. The decision of `check_program` is a function of the path, the file
/// metadata the policy reads (type, owner, mode) and the file bytes ONLY: nothing that identifies a machine is an input. The
/// same pinned bytes under a root-owned layout therefore pass identically wherever they are found, and matching bytes never
/// rescue a layout that fails; different bytes fail the pin under the good layout.
#[test]
fn a_byte_hash_identifies_the_helper_not_the_host() {
    let bytes = b"#!/bin/false\nTEST-VALUE qualification helper\n".to_vec();
    let pin: [u8; 32] = Sha256::digest(&bytes).into();
    let program = Path::new("/opt/mutiny/qualification/helper");
    let file = |uid: u32, mode: u32| PathEntry { symlink: false, directory: false, regular: true, uid, mode };
    let directory = PathEntry { symlink: false, directory: true, regular: false, uid: 0, mode: 0o40755 };
    let layout = |entry: PathEntry| move |p: &Path| -> Result<PathEntry, String> {
        Ok(if p == program { entry } else { directory })
    };
    let same_bytes = |_: &Path| -> Result<Vec<u8>, String> { Ok(bytes.clone()) };
    // Two different machines that present the same bytes in a root-owned layout: identical acceptance. The policy has no
    // host input with which it could tell them apart.
    for _machine in ["the supervised qualification laptop", "any other machine holding a copy"] {
        check_program(program, Some(pin), false, &layout(file(0, 0o100755)), &same_bytes).unwrap();
    }
    // Matching bytes do not rescue a failing layout.
    let err = check_program(program, Some(pin), false, &layout(file(1000, 0o100755)), &same_bytes).unwrap_err();
    assert!(err.contains("not root-owned"), "{err}");
    let err = check_program(program, Some(pin), false, &layout(file(0, 0o104755)), &same_bytes).unwrap_err();
    assert!(err.contains("setuid or setgid"), "{err}");
    // Different bytes under the good layout fail the pin.
    let other = |_: &Path| -> Result<Vec<u8>, String> { Ok(b"#!/bin/false\nanother helper\n".to_vec()) };
    let err = check_program(program, Some(pin), false, &layout(file(0, 0o100755)), &other).unwrap_err();
    assert!(err.contains("sha256 pin mismatch"), "{err}");
}
