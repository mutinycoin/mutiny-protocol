//! Local filesystem headroom, independent of consensus validity and retention.
use std::path::{Path, PathBuf};
type Result<T> = std::result::Result<T, String>;
pub struct DiskGuard {
    directory: PathBuf,
    reserve: u64,
}
impl DiskGuard {
    pub fn new(directory: &Path, reserve: u64) -> Result<Self> {
        if reserve < 1024 * 1024 * 1024 {
            return Err("Filesystem reserve must be at least 1 GiB".into());
        }
        let guard = Self {
            directory: directory.to_path_buf(),
            reserve,
        };
        guard.check()?;
        Ok(guard)
    }
    pub fn check(&self) -> Result<()> {
        if available(&self.directory)? < self.reserve {
            return Err(
                "Local filesystem reserve reached; stop and provision capacity without pruning"
                    .into(),
            );
        }
        Ok(())
    }
}
#[cfg(unix)]
fn available(directory: &Path) -> Result<u64> {
    use std::os::unix::ffi::OsStrExt;
    let path =
        std::ffi::CString::new(directory.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let mut stats: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(path.as_ptr(), &mut stats) } != 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let bytes = u128::from(stats.f_bavail) * u128::from(stats.f_frsize);
    bytes
        .try_into()
        .map_err(|_| "Filesystem size overflow".into())
}
#[cfg(not(unix))]
fn available(_: &Path) -> Result<u64> {
    Err("Filesystem guard requires Linux".into())
}
#[cfg(all(test, unix))]
mod tests {
    use super::*;
    #[test]
    fn unavailable_or_insufficient_storage_refuses_start_without_deleting_data() {
        let directory = std::env::temp_dir();
        assert!(available(&directory).unwrap() > 0);
        assert!(DiskGuard::new(&directory, 0).is_err());
        assert!(DiskGuard::new(&directory, u64::MAX).is_err());
        assert!(available(&directory.join("build8-nonexistent-disk-guard-path")).is_err());
    }
}
