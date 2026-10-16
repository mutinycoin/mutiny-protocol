//! Order W7 (candidate 3): what a file at a custody path IS, decided from its bytes BEFORE anything
//! else touches it, and the typed, user-readable refusal of every wallet database or file this build
//! does not open.
//!
//! The V1 Ed25519/BIP32 application path is retired (phase 0C removed its code; history keeps it).
//! Its database was `wallet.sqlite` directly in the wallet folder (by default a folder under the Windows
//! local application data directory): SQLite tables `wallet` (id, version, ciphertext, salt, identity),
//! `transactions`, `events` and, in the as-found sources of the import commit 121479b,
//! `signed_payloads`; no application id and no user version. This build never opens, converts,
//! migrates, repairs, overwrites or deletes such a file, nor any other database it does not write
//! itself: it refuses it with an [`UnsupportedFormat`] that says what the file is and what to do.
//!
//! Why the check comes FIRST, before the custody lease (`custody_acl_v2::prepare`, which creates an
//! absent file) and before SQLite opens the file for writing: opening a database read-write can
//! change it. SQLite rolls a hot rollback journal back into the main file, and folds a write-ahead
//! log into it when the last connection closes. So the check reads at most the first 100 bytes of
//! the file through a read-only handle and, only for a SQLite database that names no application,
//! its table list through SQLite opened READ-ONLY and IMMUTABLE (no lock, no journal recovery, no
//! log, no write of any kind). A refused file, its journal and its folder are left exactly as they
//! were (tests compare the bytes and the modification time of every file before and after).
//!
//! What is accepted: an absent file (a new store is created), an empty file (the custody lease
//! created it and the store was never initialised; SQLite's own rollback journal of that
//! interrupted initialisation may lie next to it and is discarded by SQLite), and a database of
//! exactly this store's application id and schema version in rollback-journal mode (a rollback
//! journal next to it is the crash recovery of this build's own format and is applied by SQLite).
//! Nothing else. The stores' own checks (exact schema, the sealed probe, the custody ACL) still
//! follow when the file is opened; this check does not replace them.
//!
//! Limitation (stated, not hidden): the check and the later open are two steps. A process that can
//! write the custody folder between them (only this Windows account and SYSTEM can: the custody ACL)
//! could swap the file; that is the same-user host compromise the custody design already excludes.
use crate::{operation_outbox, preimage_store, store_v2};
use std::{
    fmt,
    io::Read,
    path::{Path, PathBuf},
};

/// The name of the retired V1 wallet database, directly in its wallet folder.
pub const V1_WALLET_FILE: &str = "wallet.sqlite";
/// The custody folder under the vault root (fixed; `custody_acl_v2` refuses any other).
pub const CUSTODY_DIR: &str = "WalletCustodyV2";
/// SQLite's file header.
const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
/// The V1 `wallet` table's columns, in order (`git show 121479b:desktop/src/store.rs`).
const V1_WALLET_COLUMNS: [&str; 5] = ["id", "version", "ciphertext", "salt", "identity"];

/// The stores of the custody folder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreKind {
    /// The vault (`wallet-hybrid-v2.sqlite`, `store_v2`).
    Vault,
    /// The sealed operation outbox (`operation-outbox-v1.sqlite`).
    OperationOutbox,
    /// The sealed preimage store (`preimages-v1.sqlite`).
    PreimageStore,
}

impl StoreKind {
    pub const ALL: [StoreKind; 3] = [Self::Vault, Self::OperationOutbox, Self::PreimageStore];

    pub fn file_name(self) -> &'static str {
        match self {
            Self::Vault => store_v2::FILE_NAME,
            Self::OperationOutbox => operation_outbox::FILE_NAME,
            Self::PreimageStore => preimage_store::FILE_NAME,
        }
    }
    pub fn application_id(self) -> i64 {
        match self {
            Self::Vault => store_v2::APP_ID,
            Self::OperationOutbox => operation_outbox::APPLICATION_ID,
            Self::PreimageStore => preimage_store::APPLICATION_ID,
        }
    }
    /// The one schema version this build opens.
    pub fn version(self) -> i64 {
        match self {
            Self::Vault => store_v2::VERSION,
            Self::OperationOutbox => operation_outbox::SCHEMA_VERSION,
            Self::PreimageStore => preimage_store::SCHEMA_VERSION,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Vault => "wallet vault",
            Self::OperationOutbox => "operation outbox",
            Self::PreimageStore => "preimage store",
        }
    }
    fn of_application(id: i64) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.application_id() == id)
    }
}

/// What a custody path holds when it may be opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Found {
    /// No file: the store will be created.
    Absent,
    /// An empty file (created by the custody lease, never initialised).
    Empty,
    /// A database of exactly this store's application id and schema version.
    Current,
}

/// A wallet database or file this build refuses to open (Order W7). Every variant names the file;
/// `Display` says what it is, that it was left unchanged, and what to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnsupportedFormat {
    /// A database of the retired V1 desktop wallet (Ed25519/BIP32).
    RetiredV1Wallet { path: PathBuf },
    /// A file under the V1 wallet's name in the vault folder that is not a V1 wallet database.
    V1NameInUse { path: PathBuf },
    /// A hybrid vault in an earlier development format (one `vault` table, version 1 or 2).
    RetiredVaultFormat { path: PathBuf, version: i64 },
    /// A store of this wallet in a NEWER schema version than this build opens.
    NewerFormat {
        path: PathBuf,
        store: StoreKind,
        version: i64,
    },
    /// Another store of this wallet under this store's name.
    OtherStore {
        path: PathBuf,
        expected: StoreKind,
        found: StoreKind,
    },
    /// A SQLite database this wallet did not write (another application, an unknown or damaged schema).
    UnknownDatabase { path: PathBuf },
    /// Not a SQLite database at all: damaged, truncated or another kind of file.
    NotADatabase { path: PathBuf },
    /// A SQLite database in write-ahead-log mode, which this wallet never uses.
    WriteAheadLog { path: PathBuf },
    /// A directory, link, reparse point or device where a file must be (or a file where the custody
    /// folder must be).
    NotAFile { path: PathBuf },
    /// A journal, log or shared-memory file this build never leaves next to that file (or one
    /// without its database).
    UnexpectedCompanion { path: PathBuf, companion: PathBuf },
    /// The file could not be read (permissions, another program holding it, an I/O error).
    Unreadable { path: PathBuf },
}

impl UnsupportedFormat {
    /// The file the refusal is about.
    pub fn path(&self) -> &Path {
        match self {
            Self::RetiredV1Wallet { path }
            | Self::V1NameInUse { path }
            | Self::RetiredVaultFormat { path, .. }
            | Self::NewerFormat { path, .. }
            | Self::OtherStore { path, .. }
            | Self::UnknownDatabase { path }
            | Self::NotADatabase { path }
            | Self::WriteAheadLog { path }
            | Self::NotAFile { path }
            | Self::UnexpectedCompanion { path, .. }
            | Self::Unreadable { path } => path,
        }
    }
}

impl fmt::Display for UnsupportedFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const UNCHANGED: &str = "This build left it exactly as it was (nothing was opened for writing, converted, migrated, repaired or deleted).";
        match self {
            Self::RetiredV1Wallet { path } => write!(
                f,
                "{} is a database of the retired V1 desktop wallet (Ed25519/BIP32 keys). This build does not open, convert or change V1 wallets. {UNCHANGED} Keep the file and every copy of it. To use that wallet, open it with the build that created it (desktop/docs/WALLET-HOST-CANDIDATE-3.md, section W7, says which and how). Give this wallet a different --vault-root folder.",
                path.display()
            ),
            Self::V1NameInUse { path } => write!(
                f,
                "{} lies in the vault folder under the name of the retired V1 wallet database but is not one this build recognises. {UNCHANGED} Keep it, and give this wallet a different --vault-root folder.",
                path.display()
            ),
            Self::RetiredVaultFormat { path, version } => write!(
                f,
                "{} is a hybrid vault in the earlier development format {version}, which this build does not open or migrate. {UNCHANGED} Keep it; open it with the build that wrote it, or restore the wallet from its recovery phrase into a new --vault-root folder.",
                path.display()
            ),
            Self::NewerFormat {
                path,
                store,
                version,
            } => write!(
                f,
                "{} is a {} written by a newer build (format {version}; this build opens format {}). {UNCHANGED} Use the build that wrote it.",
                path.display(),
                store.label(),
                store.version()
            ),
            Self::OtherStore {
                path,
                expected,
                found,
            } => write!(
                f,
                "{} holds this wallet's {}, not its {}. {UNCHANGED} Put each store back under its own name.",
                path.display(),
                found.label(),
                expected.label()
            ),
            Self::UnknownDatabase { path } => write!(
                f,
                "{} is a database this wallet did not write (another program's, or damaged). {UNCHANGED} Keep it if it is yours, and give this wallet a different --vault-root folder.",
                path.display()
            ),
            Self::NotADatabase { path } => write!(
                f,
                "{} is not a wallet database (damaged, truncated or another kind of file). {UNCHANGED} Keep it; restore the wallet from its recovery phrase or from a copy you trust.",
                path.display()
            ),
            Self::WriteAheadLog { path } => write!(
                f,
                "{} is a database in write-ahead-log mode, which this wallet never writes. {UNCHANGED} Keep it together with any file next to it.",
                path.display()
            ),
            Self::NotAFile { path } => write!(
                f,
                "{} is a directory, link or device where the wallet expects a plain file (or a file where it expects its custody folder). {UNCHANGED}",
                path.display()
            ),
            Self::UnexpectedCompanion { path, companion } => write!(
                f,
                "{} lies next to {}: a journal or log this build never leaves there (an interrupted write of another program or format). Both were left exactly as they were. Keep them together.",
                companion.display(),
                path.display()
            ),
            Self::Unreadable { path } => write!(
                f,
                "{} could not be read (permissions, another program holding it, or an I/O error). Nothing was changed.",
                path.display()
            ),
        }
    }
}

impl std::error::Error for UnsupportedFormat {}

/// What a path holds, as far as the check needs to know.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Content {
    Absent,
    Empty,
    NotAFile,
    Unreadable,
    NotADatabase,
    WriteAheadLog,
    /// A SQLite database in rollback-journal mode with this application id and user version.
    Database { application: i64, version: i64 },
}

/// The SQLite companions of `path` that exist: `-journal`, `-wal`, `-shm` (in that order).
fn companions(path: &Path) -> Vec<PathBuf> {
    let Some(name) = path.file_name() else {
        return Vec::new();
    };
    ["-journal", "-wal", "-shm"]
        .into_iter()
        .map(|suffix| {
            let mut companion = name.to_os_string();
            companion.push(suffix);
            path.with_file_name(companion)
        })
        .filter(|companion| companion.symlink_metadata().is_ok())
        .collect()
}

fn is_rollback_journal(companion: &Path) -> bool {
    companion
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with("-journal"))
}

/// A plain regular file: not a directory, not a link, not a reparse point.
fn is_plain_file(meta: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // FILE_ATTRIBUTE_REPARSE_POINT (symbolic links, junctions, cloud placeholders).
        if meta.file_attributes() & 0x400 != 0 {
            return false;
        }
    }
    meta.is_file() && !meta.file_type().is_symlink()
}

/// Read the content class of `path` through a read-only handle (at most the 100-byte header).
fn content(path: &Path) -> Content {
    let meta = match path.symlink_metadata() {
        Ok(meta) => meta,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Content::Absent,
        Err(_) => return Content::Unreadable,
    };
    if !is_plain_file(&meta) {
        return Content::NotAFile;
    }
    let mut header = Vec::with_capacity(100);
    let read = std::fs::File::open(path).and_then(|file| file.take(100).read_to_end(&mut header));
    if read.is_err() {
        return Content::Unreadable;
    }
    if header.is_empty() {
        return if meta.len() == 0 {
            Content::Empty
        } else {
            Content::Unreadable
        };
    }
    parse_header(&header)
}

/// The SQLite file header (the first 100 bytes): magic, a valid page size, the fixed payload
/// fractions; then the journal mode (bytes 18 and 19), the user version (60) and the application id
/// (68), both signed big-endian 32-bit integers.
fn parse_header(header: &[u8]) -> Content {
    if header.len() < 100 || &header[..16] != SQLITE_MAGIC {
        return Content::NotADatabase;
    }
    let page = u16::from_be_bytes([header[16], header[17]]);
    let page_ok = page == 1 || ((512..=32768).contains(&page) && page.is_power_of_two());
    if !page_ok || header[21] != 64 || header[22] != 32 || header[23] != 32 {
        return Content::NotADatabase;
    }
    let (write, read) = (header[18], header[19]);
    if write == 2 || read == 2 {
        return Content::WriteAheadLog;
    }
    if write != 1 || read != 1 {
        return Content::NotADatabase;
    }
    let int = |at: usize| {
        i64::from(i32::from_be_bytes([
            header[at],
            header[at + 1],
            header[at + 2],
            header[at + 3],
        ]))
    };
    Content::Database {
        application: int(68),
        version: int(60),
    }
}

/// `file:` URI of `path` for SQLite, percent-encoded, opened read-only and immutable.
fn immutable_uri(path: &Path) -> Option<String> {
    let text = path.to_str()?;
    let text = text.strip_prefix(r"\\?\").unwrap_or(text);
    let mut uri = String::from("file:");
    let bytes = text.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        uri.push_str("///");
    } else if !text.starts_with('/') {
        // Only drive-letter paths (Windows) and absolute POSIX paths are expressed.
        return None;
    }
    for &byte in bytes {
        match byte {
            b'\\' => uri.push('/'),
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' | b':' => {
                uri.push(byte as char)
            }
            other => uri.push_str(&format!("%{other:02X}")),
        }
    }
    uri.push_str("?mode=ro&immutable=1");
    Some(uri)
}

/// Whether the rollback-journal SQLite database at `path` (no application id, no user version) has
/// the V1 wallet schema: tables `wallet`, `transactions` and `events` (and optionally
/// `signed_payloads`) and the `wallet` table's exact columns. Read through SQLite READ-ONLY and
/// IMMUTABLE: nothing can be written, no journal is recovered and no lock is taken. Any failure is
/// "not V1".
fn is_v1_wallet(path: &Path) -> bool {
    use rusqlite::{Connection, OpenFlags};
    let Some(uri) = immutable_uri(path) else {
        return false;
    };
    let Ok(db) = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) else {
        return false;
    };
    let tables: rusqlite::Result<Vec<String>> = db
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<String>>>()
        });
    let Ok(tables) = tables else {
        return false;
    };
    let required = ["events", "transactions", "wallet"];
    if !required.iter().all(|name| tables.iter().any(|t| t == name))
        || tables
            .iter()
            .any(|t| !required.contains(&t.as_str()) && t != "signed_payloads")
    {
        return false;
    }
    let columns: rusqlite::Result<Vec<String>> = db
        .prepare("SELECT name FROM pragma_table_info('wallet') ORDER BY cid")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| row.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<String>>>()
        });
    columns.is_ok_and(|columns| columns == V1_WALLET_COLUMNS)
}

/// Whether SQLite has written the header of the rollback journal at `journal` (its first 8 bytes,
/// the journal magic, are not all zero): SQLite treats such a journal as hot and rolls it back into
/// the database at the next open. A journal that cannot be read counts as written (fail closed).
fn journal_header_written(journal: &Path) -> bool {
    let mut head = Vec::with_capacity(8);
    match std::fs::File::open(journal).and_then(|file| file.take(8).read_to_end(&mut head)) {
        Ok(_) => head.iter().any(|byte| *byte != 0),
        Err(_) => true,
    }
}

/// Order W7 (review F1): whether the file at `path`, whose HEADER claims `expected`'s current
/// format, really has `expected`'s exact schema. Read through SQLite opened READ-ONLY and IMMUTABLE
/// (no lock, no journal recovery, no write), so a hot journal beside the file is not touched. Any
/// failure is "not verified".
fn schema_verified(path: &Path, expected: StoreKind) -> bool {
    use rusqlite::{Connection, OpenFlags};
    let Some(uri) = immutable_uri(path) else {
        return false;
    };
    let Ok(db) = Connection::open_with_flags(
        uri,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_URI | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) else {
        return false;
    };
    match expected {
        StoreKind::Vault => store_v2::validate_schema(&db).is_ok(),
        StoreKind::OperationOutbox => crate::custody_seal::schema_matches(
            &db,
            expected.application_id(),
            expected.version(),
            &operation_outbox::SCHEMA,
        )
        .unwrap_or(false),
        StoreKind::PreimageStore => crate::custody_seal::schema_matches(
            &db,
            expected.application_id(),
            expected.version(),
            &preimage_store::SCHEMA,
        )
        .unwrap_or(false),
    }
}

/// Check the file at `path`, which must be `expected`'s store, before anything opens it.
///
/// Since the independent review (findings F1, F2, F4): a file whose header claims the current
/// format must also have the exact schema (verified read-only and immutable), otherwise it is
/// `UnknownDatabase` whatever lies beside it, so no hot journal is ever rolled into a file this build
/// did not write; beside an EMPTY file only a journal whose header SQLite never wrote is accepted
/// (the leftover of this build's own interrupted initialisation; SQLite discards it); and every
/// companion must be a plain file (no directory, link or reparse point).
pub fn check_store(path: &Path, expected: StoreKind) -> Result<Found, UnsupportedFormat> {
    let owned = || path.to_path_buf();
    let companions = companions(path);
    if let Some(companion) = companions
        .iter()
        .find(|companion| !companion.symlink_metadata().is_ok_and(|meta| is_plain_file(&meta)))
    {
        return Err(UnsupportedFormat::UnexpectedCompanion {
            path: owned(),
            companion: companion.clone(),
        });
    }
    let found = match content(path) {
        Content::Absent => {
            // A journal or log without its database is never this build's.
            if let Some(companion) = companions.into_iter().next() {
                return Err(UnsupportedFormat::UnexpectedCompanion {
                    path: owned(),
                    companion,
                });
            }
            return Ok(Found::Absent);
        }
        Content::Empty => Found::Empty,
        Content::NotAFile => return Err(UnsupportedFormat::NotAFile { path: owned() }),
        Content::Unreadable => return Err(UnsupportedFormat::Unreadable { path: owned() }),
        Content::NotADatabase => return Err(UnsupportedFormat::NotADatabase { path: owned() }),
        Content::WriteAheadLog => return Err(UnsupportedFormat::WriteAheadLog { path: owned() }),
        Content::Database {
            application,
            version,
        } => {
            if application == expected.application_id() && version == expected.version() {
                Found::Current
            } else {
                return Err(classify_other(path, expected, application, version));
            }
        }
    };
    // This build writes in rollback-journal mode only: a log or shared-memory file next to an
    // accepted file is not its own.
    if let Some(companion) = companions.iter().find(|c| !is_rollback_journal(c)) {
        return Err(UnsupportedFormat::UnexpectedCompanion {
            path: owned(),
            companion: companion.clone(),
        });
    }
    if found == Found::Empty
        && let Some(journal) = companions
            .iter()
            .find(|c| is_rollback_journal(c) && journal_header_written(c))
    {
        return Err(UnsupportedFormat::UnexpectedCompanion {
            path: owned(),
            companion: journal.clone(),
        });
    }
    if found == Found::Current && !schema_verified(path, expected) {
        return Err(UnsupportedFormat::UnknownDatabase { path: owned() });
    }
    Ok(found)
}

/// The refusal of a rollback-journal database that is not exactly `expected`'s current format.
fn classify_other(path: &Path, expected: StoreKind, application: i64, version: i64) -> UnsupportedFormat {
    let path = path.to_path_buf();
    match StoreKind::of_application(application) {
        Some(StoreKind::Vault) if expected == StoreKind::Vault && (1..=2).contains(&version) => {
            UnsupportedFormat::RetiredVaultFormat { path, version }
        }
        Some(store) if store == expected && version > expected.version() => UnsupportedFormat::NewerFormat {
            path,
            store,
            version,
        },
        Some(store) if store != expected => UnsupportedFormat::OtherStore {
            path,
            expected,
            found: store,
        },
        Some(_) => UnsupportedFormat::UnknownDatabase { path },
        None if application == 0 && version == 0 && is_v1_wallet(&path) => {
            UnsupportedFormat::RetiredV1Wallet { path }
        }
        None => UnsupportedFormat::UnknownDatabase { path },
    }
}

/// Check a vault root before the wallet uses it (`Controller::open` calls this before anything is
/// created): no retired V1 wallet database (`wallet.sqlite`) in the folder itself, the custody folder
/// a plain folder if it exists, and each of the three stores absent, empty or in its current format.
pub fn check_vault_root(root: &Path) -> Result<(), UnsupportedFormat> {
    let v1 = root.join(V1_WALLET_FILE);
    match content(&v1) {
        Content::Absent => {
            if let Some(companion) = companions(&v1).into_iter().next() {
                return Err(UnsupportedFormat::UnexpectedCompanion { path: v1, companion });
            }
        }
        Content::Database {
            application: 0,
            version: 0,
        } if is_v1_wallet(&v1) => return Err(UnsupportedFormat::RetiredV1Wallet { path: v1 }),
        _ => return Err(UnsupportedFormat::V1NameInUse { path: v1 }),
    }
    let custody = root.join(CUSTODY_DIR);
    match custody.symlink_metadata() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(UnsupportedFormat::Unreadable { path: custody }),
        Ok(meta) => {
            #[cfg(windows)]
            let reparse = {
                use std::os::windows::fs::MetadataExt;
                meta.file_attributes() & 0x400 != 0
            };
            #[cfg(not(windows))]
            let reparse = false;
            if !meta.is_dir() || meta.file_type().is_symlink() || reparse {
                return Err(UnsupportedFormat::NotAFile { path: custody });
            }
        }
    }
    for kind in StoreKind::ALL {
        check_store(&custody.join(kind.file_name()), kind)?;
    }
    Ok(())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::{
        custody_acl_v2,
        operation_outbox::OperationOutbox,
        preimage_store::PreimageVault,
        store_v2::{OpenError, Store},
        test_support::{TestDir, custody_dir, custody_file, run_child},
    };
    use mutiny_wallet_core_v8::{ChainContext, Refusal};
    use rusqlite::Connection;
    use sha2::{Digest, Sha256};
    use std::{collections::BTreeMap, time::SystemTime};

    /// Every file and folder under `dir` (recursively): relative name -> (SHA-256 of the contents,
    /// length, modification time); folders as ("dir", 0, mtime).
    type Snapshot = BTreeMap<String, (String, u64, Option<SystemTime>)>;

    fn snapshot(dir: &Path) -> Snapshot {
        fn walk(base: &Path, dir: &Path, out: &mut Snapshot) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries {
                let path = entry.unwrap().path();
                let name = path.strip_prefix(base).unwrap().display().to_string();
                let meta = path.symlink_metadata().unwrap();
                if meta.is_dir() {
                    out.insert(name, ("dir".into(), 0, meta.modified().ok()));
                    walk(base, &path, out);
                } else {
                    let bytes = std::fs::read(&path).unwrap();
                    out.insert(
                        name,
                        (
                            hex::encode(Sha256::digest(&bytes)),
                            meta.len(),
                            meta.modified().ok(),
                        ),
                    );
                }
            }
        }
        let mut out = Snapshot::new();
        walk(dir, dir, &mut out);
        out
    }

    /// Write `bytes` into a custody file that carries the exact custody ACL (created by the lease,
    /// then truncated and written in place: an existing file keeps its security descriptor), so that
    /// only the format check can refuse it.
    fn custody_bytes(path: &Path, bytes: &[u8]) {
        drop(custody_acl_v2::prepare(path).unwrap());
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(path)
            .unwrap();
        file.write_all(bytes).unwrap();
        file.sync_all().unwrap();
        drop(file);
        // The lease accepts it: the ACL is the exact custody policy.
        drop(custody_acl_v2::prepare(path).unwrap());
    }

    /// The bytes of a SQLite database built by `sql` (in a scratch file under `scratch`).
    fn database(scratch: &TestDir, name: &str, sql: &str) -> Vec<u8> {
        let path = scratch.file(name);
        let db = Connection::open(&path).unwrap();
        db.execute_batch(sql).unwrap();
        drop(db);
        std::fs::read(path).unwrap()
    }

    /// The V1 schema exactly as the import commit 121479b's `desktop/src/store.rs` creates it (four
    /// tables), with one sealed-looking wallet row and one transaction.
    pub(crate) const V1_SCHEMA_121479B: &str = "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;
          CREATE TABLE IF NOT EXISTS wallet(id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, ciphertext BLOB NOT NULL, salt BLOB NOT NULL, identity TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS transactions(id TEXT PRIMARY KEY, status TEXT NOT NULL, reason TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY, txid TEXT NOT NULL REFERENCES transactions(id), status TEXT NOT NULL, reason TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS signed_payloads(txid TEXT PRIMARY KEY REFERENCES transactions(id), raw BLOB NOT NULL CHECK(length(raw)<=16384));
          INSERT INTO wallet VALUES(1,1,randomblob(512),randomblob(16),'{\"owner_public_key\":\"PUBLIC TEST VALUE\",\"address_id\":\"00\",\"account_id\":\"00\"}');
          INSERT INTO transactions VALUES('PUBLIC-TEST-TX','CREATED','REVIEWED');
          INSERT INTO events(txid,status,reason) VALUES('PUBLIC-TEST-TX','CREATED','REVIEWED');";
    /// The V1 schema of the committed commits e444c14 and d474110 (three tables).
    const V1_SCHEMA_D474110: &str = "PRAGMA journal_mode=DELETE;
          CREATE TABLE IF NOT EXISTS wallet(id INTEGER PRIMARY KEY CHECK(id=1), version INTEGER NOT NULL, ciphertext BLOB NOT NULL, salt BLOB NOT NULL, identity TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS transactions(id TEXT PRIMARY KEY, status TEXT NOT NULL, reason TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY, txid TEXT NOT NULL REFERENCES transactions(id), status TEXT NOT NULL, reason TEXT NOT NULL);
          INSERT INTO wallet VALUES(1,1,randomblob(512),randomblob(16),'{}');";

    fn chain() -> ChainContext {
        ChainContext {
            network: 0x4d55_5401,
            genesis: [0x47; 32],
            fingerprint: [0x46; 32],
        }
    }

    /// The store's own open on `path`, reduced to what it refused with.
    fn open_refusal(kind: StoreKind, path: &Path) -> String {
        match kind {
            StoreKind::Vault => format!("{:?}", Store::open(path).err().expect("refused")),
            StoreKind::OperationOutbox => format!(
                "{:?}",
                OperationOutbox::open(path, chain()).expect_err("refused")
            ),
            StoreKind::PreimageStore => {
                format!("{:?}", PreimageVault::open(path).expect_err("refused"))
            }
        }
    }

    #[test]
    fn absent_empty_and_current_custody_files_are_accepted() {
        let base = TestDir::new("w7-format-accepted");
        for kind in StoreKind::ALL {
            let path = custody_file(&base, kind.file_name());
            assert_eq!(check_store(&path, kind), Ok(Found::Absent), "{kind:?}");
        }
        // The lease creates an EMPTY file (with the custody ACL) before SQLite writes anything.
        for kind in StoreKind::ALL {
            let path = custody_file(&base, kind.file_name());
            drop(custody_acl_v2::prepare(&path).unwrap());
            assert_eq!(check_store(&path, kind), Ok(Found::Empty), "{kind:?}");
        }
        // Each real store initialises its file; the result is its current format, and it reopens.
        drop(Store::open(&custody_file(&base, StoreKind::Vault.file_name())).unwrap());
        drop(OperationOutbox::open(&custody_file(&base, StoreKind::OperationOutbox.file_name()), chain()).unwrap());
        drop(PreimageVault::open(&custody_file(&base, StoreKind::PreimageStore.file_name())).unwrap());
        for kind in StoreKind::ALL {
            let path = custody_file(&base, kind.file_name());
            assert_eq!(check_store(&path, kind), Ok(Found::Current), "{kind:?}");
        }
        assert_eq!(check_vault_root(base.path()), Ok(()));
        drop(Store::open(&custody_file(&base, StoreKind::Vault.file_name())).unwrap());
        drop(OperationOutbox::open(&custody_file(&base, StoreKind::OperationOutbox.file_name()), chain()).unwrap());
        drop(PreimageVault::open(&custody_file(&base, StoreKind::PreimageStore.file_name())).unwrap());
        // A rollback journal next to an empty file is SQLite's own leftover of an interrupted
        // initialisation (SQLite discards it): accepted.
        let fresh = TestDir::new("w7-format-empty-journal");
        let path = custody_file(&fresh, StoreKind::PreimageStore.file_name());
        drop(custody_acl_v2::prepare(&path).unwrap());
        std::fs::write(custody_file(&fresh, "preimages-v1.sqlite-journal"), [0u8; 512]).unwrap();
        assert_eq!(check_store(&path, StoreKind::PreimageStore), Ok(Found::Empty));
    }

    /// Every unsupported format is refused with its exact typed reason, by the check AND by the
    /// store's own open, and every file of the custody folder is byte-identical (same contents, same
    /// length, same modification time, no file added or removed) afterwards.
    #[test]
    fn unsupported_formats_are_refused_and_left_byte_identical() {
        let scratch = TestDir::new("w7-format-scratch");
        let v1_four = database(&scratch, "v1-four.sqlite", V1_SCHEMA_121479B);
        let v1_three = database(&scratch, "v1-three.sqlite", V1_SCHEMA_D474110);
        let v2_vault = database(
            &scratch,
            "v2.sqlite",
            "CREATE TABLE vault(id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL CHECK(revision>=1), envelope BLOB NOT NULL CHECK(length(envelope)>0 AND length(envelope)<=32768));
             INSERT INTO vault VALUES(1,1,randomblob(64)); PRAGMA application_id=1297430578; PRAGMA user_version=2;",
        );
        let future = |name: &str, application: i64, version: i64| {
            database(
                &scratch,
                name,
                &format!("CREATE TABLE later(x BLOB); INSERT INTO later VALUES(randomblob(32)); PRAGMA application_id={application}; PRAGMA user_version={version};"),
            )
        };
        let future_vault = future("future-vault.sqlite", StoreKind::Vault.application_id(), 4);
        let future_outbox = future("future-outbox.sqlite", StoreKind::OperationOutbox.application_id(), 2);
        let future_preimages = future("future-preimages.sqlite", StoreKind::PreimageStore.application_id(), 2);
        let outbox_current = future("outbox-current.sqlite", StoreKind::OperationOutbox.application_id(), 1);
        let foreign = database(
            &scratch,
            "foreign.sqlite",
            "CREATE TABLE notes(id INTEGER PRIMARY KEY, body TEXT); INSERT INTO notes VALUES(1,'not a wallet');",
        );
        let wal = database(
            &scratch,
            "wal.sqlite",
            "PRAGMA journal_mode=WAL; CREATE TABLE t(x); INSERT INTO t VALUES(1);",
        );
        let mut random = vec![0u8; 4096];
        mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
        let mut truncated = v1_four.clone();
        truncated.truncate(60);
        type Setup<'a> = (&'a str, StoreKind, Box<dyn Fn(&Path) + 'a>, Box<dyn Fn(PathBuf) -> UnsupportedFormat + 'a>);
        let cases: Vec<Setup<'_>> = vec![
            ("v1-121479b", StoreKind::Vault, Box::new(|p| custody_bytes(p, &v1_four)), Box::new(|path| UnsupportedFormat::RetiredV1Wallet { path })),
            ("v1-d474110", StoreKind::Vault, Box::new(|p| custody_bytes(p, &v1_three)), Box::new(|path| UnsupportedFormat::RetiredV1Wallet { path })),
            ("v1-as-outbox", StoreKind::OperationOutbox, Box::new(|p| custody_bytes(p, &v1_four)), Box::new(|path| UnsupportedFormat::RetiredV1Wallet { path })),
            ("v2-vault", StoreKind::Vault, Box::new(|p| custody_bytes(p, &v2_vault)), Box::new(|path| UnsupportedFormat::RetiredVaultFormat { path, version: 2 })),
            ("future-vault", StoreKind::Vault, Box::new(|p| custody_bytes(p, &future_vault)), Box::new(|path| UnsupportedFormat::NewerFormat { path, store: StoreKind::Vault, version: 4 })),
            ("future-outbox", StoreKind::OperationOutbox, Box::new(|p| custody_bytes(p, &future_outbox)), Box::new(|path| UnsupportedFormat::NewerFormat { path, store: StoreKind::OperationOutbox, version: 2 })),
            ("future-preimages", StoreKind::PreimageStore, Box::new(|p| custody_bytes(p, &future_preimages)), Box::new(|path| UnsupportedFormat::NewerFormat { path, store: StoreKind::PreimageStore, version: 2 })),
            ("outbox-as-vault", StoreKind::Vault, Box::new(|p| custody_bytes(p, &outbox_current)), Box::new(|path| UnsupportedFormat::OtherStore { path, expected: StoreKind::Vault, found: StoreKind::OperationOutbox })),
            ("foreign", StoreKind::PreimageStore, Box::new(|p| custody_bytes(p, &foreign)), Box::new(|path| UnsupportedFormat::UnknownDatabase { path })),
            ("corrupt", StoreKind::Vault, Box::new(|p| custody_bytes(p, &random)), Box::new(|path| UnsupportedFormat::NotADatabase { path })),
            ("truncated", StoreKind::OperationOutbox, Box::new(|p| custody_bytes(p, &truncated)), Box::new(|path| UnsupportedFormat::NotADatabase { path })),
            ("wal-mode", StoreKind::Vault, Box::new(|p| custody_bytes(p, &wal)), Box::new(|path| UnsupportedFormat::WriteAheadLog { path })),
            ("directory", StoreKind::Vault, Box::new(|p| {
                drop(custody_acl_v2::prepare(&p.with_file_name(StoreKind::PreimageStore.file_name())).unwrap());
                std::fs::create_dir(p).unwrap();
                std::fs::write(p.join("inside.bin"), b"PUBLIC TEST CONTENT").unwrap();
            }), Box::new(|path| UnsupportedFormat::NotAFile { path })),
            ("log-beside-current", StoreKind::OperationOutbox, Box::new(|p| {
                custody_bytes(p, &outbox_current);
                std::fs::write(p.with_file_name("operation-outbox-v1.sqlite-wal"), [7u8; 64]).unwrap();
            }), Box::new(|path| {
                let companion = path.with_file_name("operation-outbox-v1.sqlite-wal");
                UnsupportedFormat::UnexpectedCompanion { path, companion }
            })),
            ("journal-without-database", StoreKind::PreimageStore, Box::new(|p| {
                drop(custody_acl_v2::prepare(&p.with_file_name(StoreKind::Vault.file_name())).unwrap());
                std::fs::write(p.with_file_name("preimages-v1.sqlite-journal"), [9u8; 512]).unwrap();
            }), Box::new(|path| {
                let companion = path.with_file_name("preimages-v1.sqlite-journal");
                UnsupportedFormat::UnexpectedCompanion { path, companion }
            })),
        ];
        for (name, kind, setup, expected) in cases {
            let base = TestDir::new("w7-format-refused");
            let path = custody_file(&base, kind.file_name());
            setup(&path);
            let before = snapshot(base.path());
            assert!(!before.is_empty(), "{name}: nothing was set up");
            let expected = expected(path.clone());
            assert_eq!(check_store(&path, kind), Err(expected.clone()), "{name}");
            // The store's own open refuses it too, before the lease or SQLite could touch it.
            let refusal = open_refusal(kind, &path);
            match kind {
                StoreKind::Vault => assert_eq!(
                    refusal,
                    format!("{:?}", OpenError::Unsupported(expected.clone())),
                    "{name}"
                ),
                StoreKind::OperationOutbox => {
                    assert_eq!(refusal, format!("{:?}", Refusal::OutboxIntegrity), "{name}")
                }
                StoreKind::PreimageStore => assert_eq!(
                    refusal,
                    format!("{:?}", crate::preimage_store::DAMAGED),
                    "{name}"
                ),
            }
            // And so does the whole vault root.
            assert_eq!(check_vault_root(base.path()), Err(expected), "{name}");
            assert_eq!(snapshot(base.path()), before, "{name}: a file changed");
        }
    }

    const HOT_CHILD: &str = "BUILD8_W7_HOT_JOURNAL_CHILD";

    /// The child: open the V1 database at the path the parent names with plain SQLite, start a large
    /// write with a one-page cache (pages spill into the main file) and end the process before the
    /// commit, as a crash would: a hot journal and a partly written main file remain.
    #[test]
    fn hot_journal_child() {
        let Some(path) = std::env::var_os(HOT_CHILD) else {
            return;
        };
        let path = PathBuf::from(path);
        assert!(path.starts_with(std::env::temp_dir()));
        let db = Connection::open(&path).unwrap();
        db.execute_batch(
            "PRAGMA cache_size=1; PRAGMA cache_spill=ON; BEGIN IMMEDIATE;
             UPDATE wallet SET ciphertext=zeroblob(60000);
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n WHERE i<2000)
             INSERT INTO transactions SELECT 'T'||i,'CREATED','REVIEWED' FROM n;",
        )
        .unwrap();
        std::process::exit(93);
    }

    /// A V1 wallet database whose last write was interrupted (a HOT rollback journal next to it):
    /// the check refuses it and NOTHING is rolled back, written or deleted. The contrast at the end
    /// shows why the check must come first: a plain SQLite open of the same file rolls the journal
    /// back into it (the file changes and the journal disappears).
    #[test]
    fn a_v1_wallet_with_a_hot_journal_is_refused_without_being_rolled_back() {
        let scratch = TestDir::new("w7-hot-scratch");
        let v1 = database(&scratch, "v1.sqlite", V1_SCHEMA_121479B);
        // At each store's name: each store's own open must refuse before SQLite could recover it.
        for kind in StoreKind::ALL {
            let base = TestDir::new("w7-hot-journal");
            let path = custody_file(&base, kind.file_name());
            custody_bytes(&path, &v1);
            let output = run_child(
                "custody_format::tests::hot_journal_child",
                &[(HOT_CHILD, path.as_os_str())],
            );
            assert_eq!(
                output.status.code(),
                Some(93),
                "child failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let journal = custody_file(&base, &format!("{}-journal", kind.file_name()));
            assert!(journal.metadata().unwrap().len() > 512, "{kind:?}: a hot journal remains");
            let before = snapshot(base.path());
            let expected = UnsupportedFormat::RetiredV1Wallet { path: path.clone() };
            assert_eq!(check_store(&path, kind), Err(expected.clone()), "{kind:?}");
            let refusal = open_refusal(kind, &path);
            let wanted = match kind {
                StoreKind::Vault => format!("{:?}", OpenError::Unsupported(expected.clone())),
                StoreKind::OperationOutbox => format!("{:?}", Refusal::OutboxIntegrity),
                StoreKind::PreimageStore => format!("{:?}", crate::preimage_store::DAMAGED),
            };
            assert_eq!(refusal, wanted, "{kind:?}");
            assert_eq!(check_vault_root(base.path()), Err(expected), "{kind:?}");
            assert_eq!(snapshot(base.path()), before, "{kind:?}: the refusal changed a file");
            // The contrast (on this disposable test file only): plain SQLite recovers the journal.
            let plain = Connection::open(&path).unwrap();
            let _: i64 = plain
                .query_row("SELECT count(*) FROM wallet", [], |row| row.get(0))
                .unwrap();
            drop(plain);
            assert_ne!(snapshot(base.path()), before, "{kind:?}: plain SQLite rolled the journal back");
            assert!(!journal.exists(), "{kind:?}");
        }
    }

    /// The expected refusal of `kind`'s own open for a check refusal `format`.
    fn store_refusal(kind: StoreKind, format: &UnsupportedFormat) -> String {
        match kind {
            StoreKind::Vault => format!("{:?}", OpenError::Unsupported(format.clone())),
            StoreKind::OperationOutbox => format!("{:?}", Refusal::OutboxIntegrity),
            StoreKind::PreimageStore => format!("{:?}", crate::preimage_store::DAMAGED),
        }
    }

    /// Review finding F1 (the reviewer's attack, now a negative test): a V1 database whose HEADER
    /// claims a store's current format (its application id and version), with and without a HOT
    /// journal beside it. The schema verification refuses it as `UnknownDatabase` before any open, so
    /// SQLite never rolls the journal into it: every file stays byte-identical. For each store.
    #[test]
    fn a_file_that_only_claims_the_current_format_is_refused_even_with_a_hot_journal() {
        let scratch = TestDir::new("w7-forged-scratch");
        for kind in StoreKind::ALL {
            let forged = database(
                &scratch,
                &format!("forged-{}", kind.file_name()),
                &format!(
                    "{V1_SCHEMA_D474110} PRAGMA application_id={}; PRAGMA user_version={};",
                    kind.application_id(),
                    kind.version()
                ),
            );
            for hot in [false, true] {
                let base = TestDir::new("w7-forged");
                let path = custody_file(&base, kind.file_name());
                custody_bytes(&path, &forged);
                if hot {
                    let output = run_child(
                        "custody_format::tests::hot_journal_child",
                        &[(HOT_CHILD, path.as_os_str())],
                    );
                    assert_eq!(output.status.code(), Some(93), "{kind:?}");
                    let journal = custody_file(&base, &format!("{}-journal", kind.file_name()));
                    assert!(journal_header_written(&journal), "{kind:?}: a hot journal");
                }
                let before = snapshot(base.path());
                let expected = UnsupportedFormat::UnknownDatabase { path: path.clone() };
                assert_eq!(check_store(&path, kind), Err(expected.clone()), "{kind:?} hot={hot}");
                assert_eq!(open_refusal(kind, &path), store_refusal(kind, &expected), "{kind:?}");
                assert_eq!(check_vault_root(base.path()), Err(expected), "{kind:?}");
                assert_eq!(snapshot(base.path()), before, "{kind:?} hot={hot}: a file changed");
            }
        }
    }

    /// Review finding F2 (the reviewer's attack, now a negative test): an EMPTY store file with a
    /// FOREIGN hot journal beside it (one whose header SQLite wrote). Only a journal whose header was
    /// never written is this build's own leftover; this one is refused before SQLite could delete it,
    /// and both files stay byte-identical. For each store.
    #[test]
    fn an_empty_store_file_accepts_only_a_journal_sqlite_never_wrote() {
        let scratch = TestDir::new("w7-foreign-journal-scratch");
        let v1 = database(&scratch, "v1.sqlite", V1_SCHEMA_D474110);
        let donor = TestDir::new("w7-foreign-journal-donor");
        let donor_path = custody_file(&donor, StoreKind::Vault.file_name());
        custody_bytes(&donor_path, &v1);
        let output = run_child(
            "custody_format::tests::hot_journal_child",
            &[(HOT_CHILD, donor_path.as_os_str())],
        );
        assert_eq!(output.status.code(), Some(93));
        let foreign = std::fs::read(custody_file(&donor, "wallet-hybrid-v2.sqlite-journal")).unwrap();
        assert!(foreign[..8].iter().any(|byte| *byte != 0), "the donor journal is hot");
        for kind in StoreKind::ALL {
            let base = TestDir::new("w7-foreign-journal");
            let path = custody_file(&base, kind.file_name());
            drop(custody_acl_v2::prepare(&path).unwrap());
            let journal = custody_file(&base, &format!("{}-journal", kind.file_name()));
            std::fs::write(&journal, &foreign).unwrap();
            let before = snapshot(base.path());
            let expected = UnsupportedFormat::UnexpectedCompanion {
                path: path.clone(),
                companion: journal.clone(),
            };
            assert_eq!(check_store(&path, kind), Err(expected.clone()), "{kind:?}");
            assert_eq!(open_refusal(kind, &path), store_refusal(kind, &expected), "{kind:?}");
            assert_eq!(snapshot(base.path()), before, "{kind:?}: a file changed");
            assert!(journal.exists(), "{kind:?}: the foreign journal was deleted");
            // The same file with a journal whose header was never written: accepted (this build's
            // own interrupted initialisation), and the store opens.
            let unwritten = TestDir::new("w7-unwritten-journal");
            let path = custody_file(&unwritten, kind.file_name());
            drop(custody_acl_v2::prepare(&path).unwrap());
            let mut zeroed = foreign.clone();
            zeroed[..8].fill(0);
            std::fs::write(custody_file(&unwritten, &format!("{}-journal", kind.file_name())), &zeroed)
                .unwrap();
            assert_eq!(check_store(&path, kind), Ok(Found::Empty), "{kind:?}");
        }
    }

    /// Review finding F4: a store file's `-journal` companion must be a plain file, like the store
    /// file itself: a directory there is refused beside a current and beside an empty file, before
    /// SQLite could open a journal through it.
    #[test]
    fn a_journal_companion_must_be_a_plain_file() {
        for current in [true, false] {
            let base = TestDir::new("w7-journal-dir");
            let path = custody_file(&base, StoreKind::Vault.file_name());
            if current {
                drop(Store::open(&path).unwrap());
            } else {
                drop(custody_acl_v2::prepare(&path).unwrap());
            }
            let journal = custody_file(&base, "wallet-hybrid-v2.sqlite-journal");
            std::fs::create_dir(&journal).unwrap();
            std::fs::write(journal.join("inside.bin"), b"PUBLIC TEST CONTENT").unwrap();
            let before = snapshot(base.path());
            let expected = UnsupportedFormat::UnexpectedCompanion {
                path: path.clone(),
                companion: journal,
            };
            assert_eq!(check_store(&path, StoreKind::Vault), Err(expected.clone()), "current={current}");
            assert_eq!(Store::open(&path).err(), Some(OpenError::Unsupported(expected)));
            assert_eq!(snapshot(base.path()), before, "current={current}");
        }
    }

    /// A vault root that holds a retired V1 wallet database is refused before anything is created
    /// in it (no custody folder, no store); a file under the V1 name that is not a V1 database is
    /// refused too, and a file where the custody folder belongs.
    #[test]
    fn a_vault_root_holding_a_v1_wallet_is_refused_before_anything_is_created() {
        // Positive control: a fresh root opens through the controller, which creates its custody
        // folder and the three stores in their current formats.
        let fresh = TestDir::new("w7-root-fresh");
        let fresh_side = TestDir::new("w7-root-fresh-side");
        let controller = crate::wallet_controller_v2::tests::open_controller_at(fresh.path(), &fresh_side)
            .expect("a fresh vault root opens");
        drop(controller);
        assert!(custody_dir(&fresh).is_dir());
        assert_eq!(check_vault_root(fresh.path()), Ok(()));
        for kind in StoreKind::ALL {
            assert_eq!(check_store(&custody_file(&fresh, kind.file_name()), kind), Ok(Found::Current));
        }
        let scratch = TestDir::new("w7-root-scratch");
        let v1 = database(&scratch, "v1.sqlite", V1_SCHEMA_D474110);
        let root = TestDir::new("w7-root-v1");
        let wallet = root.file(V1_WALLET_FILE);
        std::fs::write(&wallet, &v1).unwrap();
        let before = snapshot(root.path());
        assert_eq!(
            check_vault_root(root.path()),
            Err(UnsupportedFormat::RetiredV1Wallet { path: wallet.clone() })
        );
        // Through the controller: refused with the readable text, and nothing created.
        let side = TestDir::new("w7-root-side");
        let refused = crate::wallet_controller_v2::tests::open_controller_at(root.path(), &side)
            .err()
            .expect("the controller refuses this vault root");
        assert!(refused.contains("retired V1 desktop wallet"), "{refused}");
        assert!(refused.contains(&wallet.display().to_string()), "{refused}");
        assert!(!custody_dir(&root).exists(), "a custody folder was created");
        assert_eq!(snapshot(root.path()), before);
        // A V1 name in use by something else; a V1 journal without its database.
        let other = TestDir::new("w7-root-other");
        std::fs::write(other.file(V1_WALLET_FILE), b"PUBLIC TEST: not a database").unwrap();
        assert_eq!(
            check_vault_root(other.path()),
            Err(UnsupportedFormat::V1NameInUse { path: other.file(V1_WALLET_FILE) })
        );
        let lone = TestDir::new("w7-root-journal");
        std::fs::write(lone.file("wallet.sqlite-journal"), [1u8; 512]).unwrap();
        assert_eq!(
            check_vault_root(lone.path()),
            Err(UnsupportedFormat::UnexpectedCompanion {
                path: lone.file(V1_WALLET_FILE),
                companion: lone.file("wallet.sqlite-journal"),
            })
        );
        // A file where the custody folder belongs.
        let file = TestDir::new("w7-root-custody-file");
        std::fs::write(file.file(CUSTODY_DIR), b"PUBLIC TEST").unwrap();
        assert_eq!(
            check_vault_root(file.path()),
            Err(UnsupportedFormat::NotAFile { path: file.file(CUSTODY_DIR) })
        );
    }

    /// Every refusal says what the file is, that it was left unchanged, and what to do.
    #[test]
    fn every_refusal_says_what_the_file_is_and_what_to_do() {
        // (Built at run time: the sources carry no drive-letter path literal, see main.rs's hygiene test.)
        let shown = format!("{}:\\PUBLIC-TEST\\wallet.sqlite", 'C');
        let path = PathBuf::from(&shown);
        let cases = [
            (UnsupportedFormat::RetiredV1Wallet { path: path.clone() }, &["retired V1 desktop wallet", "Keep the file", "the build that created it", "--vault-root"][..]),
            (UnsupportedFormat::V1NameInUse { path: path.clone() }, &["retired V1 wallet database", "--vault-root"][..]),
            (UnsupportedFormat::RetiredVaultFormat { path: path.clone(), version: 2 }, &["development format 2", "recovery phrase"][..]),
            (UnsupportedFormat::NewerFormat { path: path.clone(), store: StoreKind::Vault, version: 4 }, &["newer build", "format 4", "opens format 3"][..]),
            (UnsupportedFormat::OtherStore { path: path.clone(), expected: StoreKind::Vault, found: StoreKind::PreimageStore }, &["preimage store", "not its wallet vault"][..]),
            (UnsupportedFormat::UnknownDatabase { path: path.clone() }, &["did not write"][..]),
            (UnsupportedFormat::NotADatabase { path: path.clone() }, &["not a wallet database", "recovery phrase"][..]),
            (UnsupportedFormat::WriteAheadLog { path: path.clone() }, &["write-ahead-log"][..]),
            (UnsupportedFormat::NotAFile { path: path.clone() }, &["directory, link or device"][..]),
            (UnsupportedFormat::UnexpectedCompanion { path: path.clone(), companion: path.with_file_name("x-wal") }, &["x-wal", "Keep them together"][..]),
            (UnsupportedFormat::Unreadable { path: path.clone() }, &["could not be read", "Nothing was changed"][..]),
        ];
        for (refusal, needles) in cases {
            let text = refusal.to_string();
            assert!(text.contains(&shown), "{text}");
            assert_eq!(refusal.path(), path.as_path());
            assert!(
                text.contains("left it exactly as it was")
                    || text.contains("left exactly as they were")
                    || text.contains("Nothing was changed"),
                "{text}"
            );
            for needle in needles {
                assert!(text.contains(needle), "{needle} missing: {text}");
            }
        }
    }

    #[test]
    fn the_header_parser_and_the_uri_are_exact() {
        // Header: magic, page size, fractions, journal mode, user version and application id.
        let mut header = vec![0u8; 100];
        header[..16].copy_from_slice(SQLITE_MAGIC);
        header[16..18].copy_from_slice(&4096u16.to_be_bytes());
        header[18] = 1;
        header[19] = 1;
        header[21..24].copy_from_slice(&[64, 32, 32]);
        header[60..64].copy_from_slice(&3i32.to_be_bytes());
        header[68..72].copy_from_slice(&0x4d55_3832i32.to_be_bytes());
        assert_eq!(
            parse_header(&header),
            Content::Database {
                application: 0x4d55_3832,
                version: 3
            }
        );
        let mut wal = header.clone();
        wal[18] = 2;
        assert_eq!(parse_header(&wal), Content::WriteAheadLog);
        let mut page = header.clone();
        page[16..18].copy_from_slice(&1000u16.to_be_bytes());
        assert_eq!(parse_header(&page), Content::NotADatabase);
        let mut magic = header.clone();
        magic[0] = b's';
        assert_eq!(parse_header(&magic), Content::NotADatabase);
        assert_eq!(parse_header(&header[..99]), Content::NotADatabase);
        let mut negative = header.clone();
        negative[60..64].copy_from_slice(&(-1i32).to_be_bytes());
        assert_eq!(
            parse_header(&negative),
            Content::Database {
                application: 0x4d55_3832,
                version: -1
            }
        );
        // The URI: drive path, verbatim prefix stripped, reserved characters encoded.
        assert_eq!(
            immutable_uri(Path::new(&format!("{}:\\A b\\c#d?e%f\\wallet.sqlite", 'C'))).unwrap(),
            "file:///C:/A%20b/c%23d%3Fe%25f/wallet.sqlite?mode=ro&immutable=1"
        );
        assert_eq!(
            immutable_uri(Path::new(&format!("\\\\?\\{}:\\x\\y.sqlite", 'D'))).unwrap(),
            "file:///D:/x/y.sqlite?mode=ro&immutable=1"
        );
        assert_eq!(immutable_uri(Path::new("relative.sqlite")), None);
    }
}
