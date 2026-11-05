//! Candidate Linux encrypted-envelope publication. No key generation or signing.
//! Caller must authenticate/decrypt the envelope and bind it to canonical
//! custody before publication. Opaque bytes alone grant no signing authority.
#![cfg(target_os = "linux")]
#[cfg(test)]
#[path = "test_dir.rs"]
mod test_dir;
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
};
type Result<T> = std::result::Result<T, &'static str>;
const LIMIT: usize = 8192;
#[cfg(test)]
thread_local! {static CRASH:std::cell::Cell<u8>=const {std::cell::Cell::new(0)};}
fn checkpoint(_n: u8) {
    #[cfg(test)]
    if CRASH.with(|v| v.get() == _n) {
        std::process::exit(91);
    }
}
fn hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}
#[derive(Clone, Copy)]
enum Namespace {
    Continuity,
    Node,
}
fn name(context: [u8; 32], generation: u64) -> Result<CString> {
    name_for(Namespace::Continuity, context, generation)
}
fn name_for(role: Namespace, context: [u8; 32], generation: u64) -> Result<CString> {
    if context == [0; 32] || generation == 0 {
        return Err("invalid custody identity");
    }
    CString::new(format!(
        "{}-{}-g{generation}.vault",
        match role {
            Namespace::Continuity => "continuity",
            Namespace::Node => "node",
        },
        hex(&context)
    ))
    .map_err(|_| "name")
}
fn open_at(dir: i32, name: &std::ffi::CStr, flags: i32, mode: libc::mode_t) -> Result<File> {
    let fd = unsafe {
        libc::openat(
            dir,
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode,
        )
    };
    if fd < 0 {
        return Err("secure open");
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn directory(path: &Path) -> Result<File> {
    if !path.is_absolute() {
        return Err("absolute directory required");
    }
    let mut parts = Vec::new();
    for p in path.components() {
        match p {
            Component::RootDir if parts.is_empty() => {}
            Component::Normal(n) => parts.push(n),
            _ => return Err("directory component"),
        }
    }
    if parts.is_empty() || parts.len() > 32 {
        return Err("directory bound");
    }
    let uid = unsafe { libc::geteuid() };
    // Ancestors require trusted ownership and safe modes, not permission to
    // list their contents. O_PATH permits traversal through root-owned 0711
    // directories without broadening those directories' access permissions.
    let mut d = open_at(libc::AT_FDCWD, c"/", libc::O_PATH | libc::O_DIRECTORY, 0)?;
    for (index, n) in parts.iter().enumerate() {
        let m = d.metadata().map_err(|_| "directory metadata")?;
        if !m.is_dir() || (m.uid() != 0 && m.uid() != uid) || m.mode() & 0o022 != 0 {
            return Err("unsafe ancestor");
        }
        let n = CString::new(n.as_bytes()).map_err(|_| "directory name")?;
        let access = if index + 1 == parts.len() {
            // The final owner-only directory needs a real descriptor for
            // publication's directory fsync; no-follow remains mandatory.
            libc::O_RDONLY
        } else {
            libc::O_PATH
        };
        d = open_at(d.as_raw_fd(), &n, access | libc::O_DIRECTORY, 0)?;
        if index + 1 == parts.len() {
            let m = d.metadata().map_err(|_| "private directory metadata")?;
            if !m.is_dir() || m.uid() != uid || m.mode() & 0o7777 != 0o700 {
                return Err("private directory permissions");
            }
        }
    }
    Ok(d)
}
/// Creates one immutable generation file, never overwrites. On any error after
/// publication the target MAY exist: inspect/decrypt it under canonical pins;
/// never assume an error authorizes replacement or journal reinitialization.
fn publish_for(
    role: Namespace,
    path: &Path,
    context: [u8; 32],
    generation: u64,
    encrypted: &[u8],
) -> Result<()> {
    if encrypted.is_empty() || encrypted.len() > LIMIT {
        return Err("envelope bound");
    }
    let target = name_for(role, context, generation)?;
    let dir = directory(path)?;
    let mut nonce = [0u8; 32];
    mutiny_crypto_v2::fill_os_random(&mut nonce).map_err(|_| "OS entropy unavailable")?;
    let temporary = CString::new(format!(".pending-{}", hex(&nonce))).unwrap();
    let mut file = open_at(
        dir.as_raw_fd(),
        &temporary,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
        0o600,
    )?;
    let result = (|| {
        // Inherited ACLs/umask cannot silently widen or remove intended access.
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            return Err("file permissions");
        }
        checkpoint(1);
        file.write_all(encrypted).map_err(|_| "envelope write")?;
        file.sync_all().map_err(|_| "envelope sync")?;
        checkpoint(2);
        if unsafe {
            libc::renameat2(
                dir.as_raw_fd(),
                temporary.as_ptr(),
                dir.as_raw_fd(),
                target.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err("generation publication refused");
        }
        checkpoint(3);
        dir.sync_all().map_err(|_| "directory sync")?;
        checkpoint(4);
        Ok(())
    })();
    // Only the unique staging name created by this invocation is eligible for
    // cleanup. A published target is never removed on an ambiguous error.
    if result.is_err() {
        unsafe { libc::unlinkat(dir.as_raw_fd(), temporary.as_ptr(), 0) };
        let _ = dir.sync_all();
    }
    result
}
fn read_for(role: Namespace, path: &Path, context: [u8; 32], generation: u64) -> Result<Vec<u8>> {
    let target = name_for(role, context, generation)?;
    let dir = directory(path)?;
    let mut file = open_at(
        dir.as_raw_fd(),
        &target,
        libc::O_RDONLY | libc::O_NONBLOCK,
        0,
    )?;
    let before = file.metadata().map_err(|_| "file metadata")?;
    if !before.is_file()
        || before.uid() != unsafe { libc::geteuid() }
        || before.nlink() != 1
        || before.mode() & 0o7777 != 0o600
        || !(1..=LIMIT as u64).contains(&before.len())
    {
        return Err("file identity/permissions/bounds");
    }
    let mut raw = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take((LIMIT + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|_| "read")?;
    let after = file.metadata().map_err(|_| "file metadata")?;
    if raw.len() as u64 != before.len()
        || before.len() != after.len()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        return Err("file changed");
    }
    Ok(raw)
}
pub(crate) fn publish(
    path: &Path,
    context: [u8; 32],
    generation: u64,
    encrypted: &[u8],
) -> Result<()> {
    publish_for(Namespace::Continuity, path, context, generation, encrypted)
}
pub(crate) fn read(path: &Path, context: [u8; 32], generation: u64) -> Result<Vec<u8>> {
    read_for(Namespace::Continuity, path, context, generation)
}
pub(crate) fn publish_node(
    path: &Path,
    context: [u8; 32],
    generation: u64,
    encrypted: &[u8],
) -> Result<()> {
    publish_for(Namespace::Node, path, context, generation, encrypted)
}
pub(crate) fn read_node(path: &Path, context: [u8; 32], generation: u64) -> Result<Vec<u8>> {
    read_for(Namespace::Node, path, context, generation)
}
#[cfg(test)]
#[path = "continuity_generation_store_v2_tests.rs"]
mod tests;
