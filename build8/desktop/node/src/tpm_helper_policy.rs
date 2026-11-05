//! Path policy of the host-local production TPM custody helper (`tpm_backend.rs`).
//!
//! Self-contained (std and sha2 only): the qualification helper bridge of the consensus examples,
//! operator tooling that is never linked into a shipping binary, includes this file by `#[path]` so
//! that a pinned qualification helper gets the SAME validation. The rules take portable metadata
//! (`PathEntry`), so each one is testable with synthetic metadata on every platform; only the Linux
//! adapters read the real filesystem, and off Linux `check_program_on_host` always refuses.
use sha2::{Digest, Sha256};
use std::path::{Component, Path, PathBuf};

type Result<T> = std::result::Result<T, String>;

/// Set-user-ID and set-group-ID mode bits.
pub const SET_ID_BITS: u32 = 0o6000;
const SET_GID_BIT: u32 = 0o2000;

/// Filesystem facts used by the custody path policy (portable so the policy is testable on
/// every platform; only the Linux adapter reads real metadata).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathEntry {
    pub symlink: bool,
    pub directory: bool,
    pub regular: bool,
    pub uid: u32,
    pub mode: u32,
}
/// Lexical rule: absolute, valid UTF-8, no `..` or `.` component, no NUL, bounded.
pub fn check_helper_path(path: &Path) -> Result<()> {
    let text = path.to_str().ok_or("TPM helper path must be UTF-8")?;
    if text.len() > 4096 || text.contains('\0') || !text.starts_with('/') {
        return Err("TPM helper path must be an absolute Linux path".into());
    }
    if path.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir))
        || text.split('/').skip(1).any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("TPM helper path must not contain '..', '.' or empty components".into());
    }
    Ok(())
}
/// A configured helper file (program, interpreter or script): regular, not a symlink, no
/// group/world write, no set-user-ID or set-group-ID bit (the configuration declares no privilege
/// for a helper file), owned by root.
pub fn check_helper_file_entry(e: PathEntry) -> Result<()> {
    check_executable(e, SET_ID_BITS)
}
/// The absolute `sudo` wrapper of `"privilege":"sudo-n"`: the same rules, except that its
/// set-user-ID bit is the privilege that setting DECLARES (sudo works only as a set-user-ID root
/// program); a set-group-ID bit is still refused.
pub fn check_helper_wrapper_entry(e: PathEntry) -> Result<()> {
    check_executable(e, SET_GID_BIT)
}
fn check_executable(e: PathEntry, refused_bits: u32) -> Result<()> {
    if e.symlink {
        return Err("TPM helper path component is a symlink".into());
    }
    if !e.regular || e.directory {
        return Err("TPM helper must be a regular file".into());
    }
    if e.mode & 0o022 != 0 {
        return Err("TPM helper file is group- or world-writable".into());
    }
    if e.mode & refused_bits != 0 {
        return Err("TPM helper file is setuid or setgid (a privilege the configuration does not declare)".into());
    }
    if e.uid != 0 {
        return Err("TPM helper file is not root-owned".into());
    }
    Ok(())
}
/// Every ancestor directory: a real directory, not a symlink, root-owned, not group/world-writable.
pub fn check_helper_ancestor_entry(e: PathEntry) -> Result<()> {
    if e.symlink {
        return Err("TPM helper path component is a symlink".into());
    }
    if !e.directory {
        return Err("TPM helper ancestor is not a directory".into());
    }
    if e.mode & 0o022 != 0 {
        return Err("TPM helper ancestor directory is group- or world-writable".into());
    }
    if e.uid != 0 {
        return Err("TPM helper ancestor directory is not root-owned".into());
    }
    Ok(())
}
fn ancestors(path: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = path
        .ancestors()
        .skip(1)
        .map(Path::to_path_buf)
        .collect();
    out.reverse();
    out
}
/// One executed file over an explicit metadata/byte source: the lexical rule, the file rule
/// (`wrapper`: the declared `sudo` wrapper), every ancestor from the root, and the optional pin of
/// the exact file bytes.
pub fn check_program(
    path: &Path,
    sha256: Option<[u8; 32]>,
    wrapper: bool,
    lookup: &dyn Fn(&Path) -> Result<PathEntry>,
    read: &dyn Fn(&Path) -> Result<Vec<u8>>,
) -> Result<()> {
    check_helper_path(path)?;
    // The final component first (precise error), then every ancestor from the root.
    let entry = lookup(path)?;
    if wrapper {
        check_helper_wrapper_entry(entry)?;
    } else {
        check_helper_file_entry(entry)?;
    }
    for ancestor in ancestors(path) {
        check_helper_ancestor_entry(lookup(&ancestor)?)?;
    }
    if let Some(pin) = sha256 {
        if Sha256::digest(read(path)?)[..] != pin {
            return Err("TPM helper file sha256 pin mismatch".into());
        }
    }
    Ok(())
}
/// `check_program` against the real filesystem. Custody helpers are host-local Linux only:
/// elsewhere this always refuses.
pub fn check_program_on_host(path: &Path, sha256: Option<[u8; 32]>, wrapper: bool) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        check_program(path, sha256, wrapper, &linux_entry, &bounded_read)
    }
    #[cfg(not(target_os = "linux"))]
    {
        check_helper_path(path)?;
        let _ = (sha256, wrapper);
        Err("Production TPM custody helper validation requires Linux; refused".into())
    }
}
#[cfg(target_os = "linux")]
pub fn linux_entry(path: &Path) -> Result<PathEntry> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(path).map_err(|_| "TPM helper path unavailable")?;
    let kind = m.file_type();
    Ok(PathEntry {
        symlink: kind.is_symlink(),
        directory: kind.is_dir(),
        regular: kind.is_file(),
        uid: m.uid(),
        mode: m.mode(),
    })
}
#[cfg(target_os = "linux")]
pub fn bounded_read(path: &Path) -> Result<Vec<u8>> {
    use std::io::Read;
    const MAX_HASHED_HELPER_BYTES: u64 = 64 * 1024 * 1024;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| "TPM helper file unreadable")?
        .take(MAX_HASHED_HELPER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "TPM helper file unreadable")?;
    if bytes.len() as u64 > MAX_HASHED_HELPER_BYTES {
        return Err("TPM helper file too large to pin".into());
    }
    Ok(bytes)
}
