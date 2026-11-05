//! Local file identity/permission checks for encrypted custody and new outputs.
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};
type Result<T> = std::result::Result<T, &'static str>;
pub fn read_public(path: &Path, max: u64) -> Result<Vec<u8>> {
    validate_input_path(path)?;
    let (mut file, _leases) = open(path, false)?;
    let before = file
        .metadata()
        .map_err(|_| "Public input metadata failed")?;
    if !before.is_file() || before.len() > max {
        return Err("Public input bound");
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(max.checked_add(1).ok_or("Input bound overflow")?)
        .read_to_end(&mut bytes)
        .map_err(|_| "Public input read failed")?;
    let after = file
        .metadata()
        .map_err(|_| "Public input readback failed")?;
    if bytes.len() as u64 != before.len()
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err("Public input changed");
    }
    Ok(bytes)
}
pub fn read_vault(path: &Path) -> Result<Vec<u8>> {
    validate_input_path(path)?;
    let (mut file, _leases) = open(path, false)?;
    super::storage_acl::check(&file, false)?;
    let before = file.metadata().map_err(|_| "Custody metadata failed")?;
    if !before.is_file() || before.len() == 0 || before.len() > 8192 {
        return Err("Custody file bound");
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take(8193)
        .read_to_end(&mut bytes)
        .map_err(|_| "Custody read failed")?;
    let after = file
        .metadata()
        .map_err(|_| "Custody readback metadata failed")?;
    super::storage_acl::check(&file, false)?;
    if bytes.len() as u64 != before.len()
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
    {
        return Err("Custody file changed");
    }
    Ok(bytes)
}
pub fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    validate_input_path(path)?;
    let (mut file, leases) = open(path, true)?;
    super::storage_acl::check(&file, true)?;
    file.write_all(bytes).map_err(|_| "Output write failed")?;
    file.sync_all().map_err(|_| "Output durability failed")?;
    super::storage_acl::check(&file, false)?;
    #[cfg(target_os = "linux")]
    for directory in &leases {
        directory
            .sync_all()
            .map_err(|_| "Output directory durability failed")?;
    }
    drop(leases);
    Ok(())
}
fn validate_input_path(path: &Path) -> Result<()> {
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err("Custody paths may not contain parent traversal");
    }
    Ok(())
}
#[cfg(windows)]
fn open(path: &Path, create: bool) -> Result<(File, Vec<File>)> {
    use std::{
        fs::OpenOptions,
        os::windows::{
            fs::{MetadataExt, OpenOptionsExt},
            io::AsRawHandle,
        },
        path::{Component, PathBuf, Prefix},
    };
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let path = std::path::absolute(path).map_err(|_| "Absolute custody path failed")?;
    let mut leases = Vec::new();
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(p)
                if matches!(p.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_)) =>
            {
                current.push(component);
                continue;
            }
            Component::RootDir => current.push(component),
            Component::Normal(s) if !s.to_string_lossy().contains(':') => current.push(component),
            _ => return Err("Unsupported custody path component"),
        }
        if current == path {
            break;
        }
        let directory = OpenOptions::new()
            .read(true)
            .share_mode(3)
            .custom_flags(0x02000000 | 0x00200000)
            .open(&current)
            .map_err(|_| "Cannot pin custody directory")?;
        let meta = directory
            .metadata()
            .map_err(|_| "Directory metadata failed")?;
        if !meta.is_dir() || meta.file_attributes() & 0x400 != 0 {
            return Err("Reparse custody directory");
        }
        leases.push(directory);
    }
    if leases.is_empty() {
        return Err("Custody directory missing");
    }
    let mut options = OpenOptions::new();
    options.read(true).share_mode(0).custom_flags(0x00200000);
    if create {
        options
            .write(true)
            .create_new(true)
            .access_mode(0xc0000000 | 0x40000 | 0x20000);
    }
    let file = options
        .open(&path)
        .map_err(|_| "Cannot exclusively open custody file")?;
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0
        || info.dwFileAttributes & (0x400 | 0x10) != 0
        || info.nNumberOfLinks != 1
    {
        return Err("Custody file must be regular,not reparse,one link");
    }
    Ok((file, leases))
}
#[cfg(target_os = "linux")]
fn open(path: &Path, create: bool) -> Result<(File, Vec<File>)> {
    use std::{
        ffi::CString,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
        path::Component,
    };
    let path = std::path::absolute(path).map_err(|_| "Absolute custody path failed")?;
    let mut directory = File::open("/").map_err(|_| "Root directory open failed")?;
    let components = path.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(s) => s,
            _ => return Err("Unsupported custody path"),
        };
        let name = CString::new(name.as_bytes()).map_err(|_| "Invalid custody path")?;
        let leaf = index + 1 == components.len();
        let flags = if leaf {
            if create {
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL
            } else {
                libc::O_RDONLY
            }
        } else {
            libc::O_RDONLY | libc::O_DIRECTORY
        };
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0o600,
            )
        };
        if fd < 0 {
            return Err("No-follow custody open failed");
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let meta = file.metadata().map_err(|_| "Custody metadata failed")?;
        if leaf {
            if !meta.is_file() || meta.nlink() != 1 {
                return Err("Custody requires regular single-link file");
            }
            return Ok((file, vec![directory]));
        }
        if !meta.is_dir()
            || ![0, unsafe { libc::geteuid() }].contains(&meta.uid())
            || meta.mode() & 0o022 != 0
        {
            return Err("Custody directory ownership/mode rejected");
        }
        directory = file;
    }
    Err("Missing custody file")
}
#[cfg(not(any(windows, target_os = "linux")))]
fn open(_: &Path, _: bool) -> Result<(File, Vec<File>)> {
    Err("Unsupported custody platform")
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    fn directory() -> std::path::PathBuf {
        let mut nonce = [0; 16];
        mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
        let path =
            std::env::temp_dir().join(format!("build8-release-file-test-{}", hex::encode(nonce)));
        std::fs::create_dir(&path).unwrap();
        path
    }
    #[test]
    fn handle_acl_roundtrip_and_no_overwrite() {
        let base = directory();
        let path = base.join("synthetic-encrypted-vault.bin");
        write_new(&path, b"PUBLIC DUMMY DATA; NO KEY").unwrap();
        assert_eq!(read_vault(&path).unwrap(), b"PUBLIC DUMMY DATA; NO KEY");
        assert!(write_new(&path, b"replacement").is_err());
        assert_eq!(read_vault(&path).unwrap(), b"PUBLIC DUMMY DATA; NO KEY");
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(base).unwrap();
    }
    #[test]
    fn exclusive_file_and_directory_identity_lease() {
        let base = directory();
        let path = base.join("synthetic-encrypted-vault.bin");
        write_new(&path, b"PUBLIC DUMMY").unwrap();
        let (file, lease) = open(&path, false).unwrap();
        assert!(File::options().write(true).open(&path).is_err());
        assert!(std::fs::rename(&path, base.join("moved.bin")).is_err());
        assert!(std::fs::rename(&base, base.with_extension("moved")).is_err());
        super::super::storage_acl::check(&file, false).unwrap();
        drop(file);
        drop(lease);
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(base).unwrap();
    }
    #[test]
    fn public_or_hardlinked_vault_rejected_without_permission_repair() {
        let base = directory();
        let path = base.join("unprotected.bin");
        std::fs::write(&path, b"PUBLIC DUMMY").unwrap();
        assert!(read_vault(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"PUBLIC DUMMY");
        // A second attempt must still reject: reads never repair broad ACLs.
        assert!(read_vault(&path).is_err());
        std::fs::remove_file(&path).unwrap();
        write_new(&path, b"PUBLIC DUMMY").unwrap();
        let link = base.join("linked.bin");
        std::fs::hard_link(&path, &link).unwrap();
        assert!(read_vault(&path).is_err());
        assert!(read_vault(&link).is_err());
        std::fs::remove_file(link).unwrap();
        assert!(read_vault(&path).is_ok());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(base).unwrap();
    }
    #[test]
    fn invalid_paths_empty_and_oversize_files_fail_closed() {
        let base = directory();
        assert!(read_vault(&base).is_err());
        assert!(write_new(&base.join("missing/child.bin"), b"x").is_err());
        assert!(write_new(&base.join("vault.bin:stream"), b"x").is_err());
        assert!(write_new(&base.join("../escape.bin"), b"x").is_err());
        for (name, bytes) in [("empty", vec![]), ("oversize", vec![0; 8193])] {
            let path = base.join(name);
            write_new(&path, &bytes).unwrap();
            assert!(read_vault(&path).is_err());
            std::fs::remove_file(path).unwrap();
        }
        std::fs::remove_dir(base).unwrap();
    }
    #[test]
    fn junction_ancestry_cannot_redirect_reads_or_new_outputs() {
        let base = directory();
        let target = base.join("target");
        std::fs::create_dir(&target).unwrap();
        let path = target.join("dummy");
        write_new(&path, b"PUBLIC DUMMY").unwrap();
        let link = base.join("junction");
        let status=std::process::Command::new("powershell.exe")
            .args(["-NoProfile","-NonInteractive","-Command",
                "New-Item -ItemType Junction -Path $env:BUILD8_TEST_LINK -Target $env:BUILD8_TEST_TARGET -ErrorAction Stop | Out-Null"])
            .env("BUILD8_TEST_LINK",&link).env("BUILD8_TEST_TARGET",&target)
            .status().unwrap();
        assert!(status.success());
        assert!(read_vault(&link.join("dummy")).is_err());
        assert!(read_public(&link.join("dummy"), 32).is_err());
        assert!(write_new(&link.join("new"), b"PUBLIC DUMMY").is_err());
        assert!(!target.join("new").exists());
        // Remove only this junction; never recursively walk its target.
        std::fs::remove_dir(link).unwrap();
        assert_eq!(read_vault(&path).unwrap(), b"PUBLIC DUMMY");
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(target).unwrap();
        std::fs::remove_dir(base).unwrap();
    }
}

#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    fn directory() -> std::path::PathBuf {
        let mut nonce = [0; 16];
        mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
        let path = std::env::current_dir()
            .unwrap()
            .join(format!("synthetic-release-custody-{}", hex::encode(nonce)));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    #[test]
    fn protected_linux_files_modes_links_and_no_repair() {
        let base = directory();
        let path = base.join("dummy");
        write_new(&path, b"PUBLIC DUMMY").unwrap();
        assert_eq!(read_vault(&path).unwrap(), b"PUBLIC DUMMY");
        assert!(write_new(&path, b"overwrite").is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_vault(&path).is_err());
        assert_eq!(path.metadata().unwrap().permissions().mode() & 0o777, 0o644);
        assert_eq!(read_public(&path, 20).unwrap(), b"PUBLIC DUMMY");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let hard = base.join("hard");
        std::fs::hard_link(&path, &hard).unwrap();
        assert!(read_vault(&path).is_err());
        std::fs::remove_file(hard).unwrap();
        let link = base.join("link");
        symlink(&path, &link).unwrap();
        assert!(read_vault(&link).is_err());
        assert!(read_public(&link, 20).is_err());
        std::fs::remove_file(link).unwrap();
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(base).unwrap();
    }
    #[test]
    fn linux_ancestry_fifo_and_bounds_fail_closed() {
        let base = directory();
        let private = base.join("private");
        std::fs::create_dir(&private).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = private.join("dummy");
        write_new(&path, b"PUBLIC DUMMY").unwrap();
        let link = base.join("link");
        symlink(&private, &link).unwrap();
        assert!(read_vault(&link.join("dummy")).is_err());
        std::fs::remove_file(link).unwrap();
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o770)).unwrap();
        assert!(read_vault(&path).is_err());
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(read_public(&path, 2).is_err());
        assert!(write_new(&private.join("../escape"), b"x").is_err());
        let fifo = base.join("fifo");
        use std::os::unix::ffi::OsStrExt;
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_vault(&fifo).is_err());
        assert!(read_public(&fifo, 20).is_err());
        std::fs::remove_file(fifo).unwrap();
        for (name, data) in [("empty", vec![]), ("large", vec![0; 8193])] {
            let file = private.join(name);
            write_new(&file, &data).unwrap();
            assert!(read_vault(&file).is_err());
            std::fs::remove_file(file).unwrap();
        }
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(private).unwrap();
        std::fs::remove_dir(base).unwrap();
    }
}
