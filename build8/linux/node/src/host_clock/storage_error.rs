//! Shared storage refusal type; no native access or authority.
use std::path::{Path,PathBuf};
/// Why the anchor storage was refused at start-up. Every variant stops the start-up: the node does
/// not run its clock on storage it cannot vouch for.
#[derive(Debug, PartialEq, Eq)]
pub enum StorageError {
    /// This platform offers no owner-only check this build can perform (Order C8): refused, never
    /// assumed.
    Unsupported(&'static str),
    /// The path is not absolute, has no file name or parent, contains `.` / `..`, or a component is
    /// not a directory.
    Path(PathBuf),
    /// A component of the path is a symbolic link (path substitution).
    Symlink(PathBuf),
    /// An ancestor directory could be replaced by another user: it is owned by neither root nor
    /// this user, or it is writable by group or others without the sticky bit.
    ReplaceableAncestor(PathBuf),
    /// The anchor directory or one of its files is not owned by the effective user.
    NotOwner(PathBuf),
    /// The anchor directory or one of its files is accessible by group or others.
    Accessible(PathBuf),
    /// The opened directory handle is not the directory the path named a moment before.
    Substituted(PathBuf),
    /// Another instance holds the exclusive anchor lock (Order C12): this one fails closed.
    Locked(PathBuf),
    Io(PathBuf, String),
}
impl std::error::Error for StorageError {}
impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::Unsupported(why) => {
                write!(f, "owner-only storage check unsupported: {why}")
            }
            StorageError::Path(p) => write!(f, "unusable anchor path {}", p.display()),
            StorageError::Symlink(p) => {
                write!(f, "symbolic link in the anchor path: {}", p.display())
            }
            StorageError::ReplaceableAncestor(p) => {
                write!(
                    f,
                    "another user could replace the anchor directory via {}",
                    p.display()
                )
            }
            StorageError::NotOwner(p) => write!(f, "not owned by the node user: {}", p.display()),
            StorageError::Accessible(p) => {
                write!(
                    f,
                    "accessible by group or others (mode must be owner-only): {}",
                    p.display()
                )
            }
            StorageError::Substituted(p) => {
                write!(f, "anchor directory substituted: {}", p.display())
            }
            StorageError::Locked(p) => write!(
                f,
                "another instance holds the clock anchor lock {} (one node process per anchor directory)",
                p.display()
            ),
            StorageError::Io(p, e) => write!(f, "{}: {e}", p.display()),
        }
    }
}
// `take_lock` serves Unix and the unchecked portable test double; the Windows production
// backend uses its protected native file opener before taking that same OS lifetime lock.
#[cfg_attr(not(any(unix, test)), allow(dead_code))]
pub(super) fn io(path: &Path, e: std::io::Error) -> StorageError {
    StorageError::Io(path.to_path_buf(), e.to_string())
}

