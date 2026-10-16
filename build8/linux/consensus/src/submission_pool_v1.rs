//! Local bounded complete-object pool. Exact signed bytes and terminal evidence
//! are retained; terminal rows may move atomically to protected sibling shards.
//! No shard is deleted. Archive status is local evidence, never finality proof.
use crate::{
    Hash,
    anchors::FinalizedAnchor,
    evidence_history_v2::History,
    execution::State,
    operation_index_v2::OperationRecord,
    submission_v1::{Reason, Status, StatusEntry, StatusReport, Submission},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
    time::Duration,
};
pub const MAX_ROWS: usize = 65_536;
pub const MAX_BYTES: u64 = 64 * 1024 * 1024;
pub const ARCHIVE_ROWS: usize = 256;
pub const ARCHIVE_BYTES: u64 = 4 * 1024 * 1024;
const APP_ID: i64 = 0x4d555350;
#[cfg(any(test, feature = "dividend-test-fixtures"))]
std::thread_local! { static ARCHIVE_SIGNATURE_CHECKS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) }; }
/// TEST-only measurement at the actual archive crypto verification call site.
#[cfg(any(test, feature = "dividend-test-fixtures"))]
pub fn fixture_archive_signature_checks() -> u64 {
    ARCHIVE_SIGNATURE_CHECKS.with(|count| count.get())
}
const CATALOG: &str = "CREATE TABLE archive_catalog(sequence BLOB PRIMARY KEY CHECK(length(sequence)=8),rows INTEGER NOT NULL CHECK(rows BETWEEN 1 AND 256),bytes INTEGER NOT NULL CHECK(bytes BETWEEN 1 AND 4194304),seal BLOB NOT NULL CHECK(length(seal)=32))";
const SCHEMA: [(&str, &str); 4] = [
    (
        "context",
        "CREATE TABLE context(id INTEGER PRIMARY KEY CHECK(id=1),genesis BLOB NOT NULL CHECK(length(genesis)=32),fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32))",
    ),
    (
        "basis",
        "CREATE TABLE basis(id INTEGER PRIMARY KEY CHECK(id=1),anchor BLOB NOT NULL CHECK(length(anchor)<=128),root BLOB NOT NULL CHECK(length(root)=32))",
    ),
    (
        "entries",
        "CREATE TABLE entries(id BLOB PRIMARY KEY CHECK(length(id)=32),class INTEGER NOT NULL CHECK(class IN (0,1)),kind INTEGER NOT NULL,raw BLOB NOT NULL CHECK(length(raw) BETWEEN 1 AND 16384),first BLOB NOT NULL CHECK(length(first)=8),last BLOB NOT NULL CHECK(length(last)=8),wire BLOB NOT NULL CHECK(length(wire)=32),sig_ok INTEGER NOT NULL CHECK(sig_ok=1),status BLOB NOT NULL CHECK(length(status) BETWEEN 1 AND 768))",
    ),
    (
        "resources",
        "CREATE TABLE resources(resource BLOB PRIMARY KEY CHECK(length(resource)=32),owner BLOB NOT NULL REFERENCES entries(id))",
    ),
];
#[derive(Debug)]
pub enum PoolError {
    Io(std::io::Error),
    Storage(rusqlite::Error),
    Invalid(Reason),
    Context,
    StaleBasis,
    Integrity,
    Conflict,
    Capacity,
    ArchiveProtection,
    ArchiveLocked,
}
impl From<rusqlite::Error> for PoolError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e)
    }
}
impl From<Reason> for PoolError {
    fn from(e: Reason) -> Self {
        Self::Invalid(e)
    }
}
pub type Result<T> = std::result::Result<T, PoolError>;
/// Provision one NEW private pool directory under already safe ancestors, or
/// check an existing directory without changing its permissions or contents.
pub fn private_directory(path: &Path) -> Result<bool> {
    crate::submission_archive_protection::directory(path)
}
/// TEST-VALUE only: create one NEW protected directory, or check an existing
/// private directory without changing it. Ancestors must already be safe.
#[cfg(any(test, feature = "dividend-test-fixtures"))]
pub fn fixture_private_directory(path: &Path) -> Result<()> {
    private_directory(path).map(|_| ())
}
pub struct SubmissionPool {
    db: Connection,
    genesis: Hash,
    fingerprint: Hash,
    limit: u64,
    // Process-local evidence populated ONLY by cryptographic verification.
    // A live SQLite edit cannot forge this with sig_ok or a coherently changed wire.
    signatures: BTreeMap<Hash, Hash>,
    path: PathBuf,
    archive_lock: Option<File>,
    archive_lookup: Option<crate::submission_archive_lookup::Lookup>,
    archive_shards: usize,
}
fn fixed(v: Vec<u8>) -> Result<Hash> {
    v.try_into().map_err(|_| PoolError::Integrity)
}
fn root(state: &State) -> Result<Hash> {
    state.root().map_err(|_| PoolError::Integrity)
}
fn status_raw(a: &FinalizedAnchor, id: Hash, status: Status) -> Result<Vec<u8>> {
    Ok(StatusReport {
        tip_height: a.height,
        tip_block: a.block,
        entries: vec![StatusEntry { id, status }],
    }
    .encode()?)
}
fn decode_status(id: Hash, raw: &[u8]) -> Result<Status> {
    let report = StatusReport::decode(raw).map_err(|_| PoolError::Integrity)?;
    if report.entries.len() != 1 || report.entries[0].id != id {
        return Err(PoolError::Integrity);
    }
    Ok(report
        .entries
        .into_iter()
        .next()
        .ok_or(PoolError::Integrity)?
        .status)
}
fn active(s: &Status) -> bool {
    matches!(s, Status::Pending | Status::Unfinalized { .. })
}
fn private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(file) => Ok(file),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            crate::submission_archive_protection::check(path, false)?;
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(path)
                .map_err(PoolError::Io)
        }
        Err(e) => Err(PoolError::Io(e)),
    }
}
fn archive_lock(root: &Path) -> Result<File> {
    crate::submission_archive_protection::directory(root)?;
    let path = root.join("archive.lock");
    let file = private_file(&path)?;
    crate::submission_archive_protection::check(&path, false)?;
    file.try_lock().map_err(|_| PoolError::ArchiveLocked)?;
    Ok(file)
}
fn shard_path(root: &Path, number: usize) -> PathBuf {
    root.join(format!("shard-{number:020}.sqlite"))
}
fn archive_inventory(root: &Path) -> Result<usize> {
    crate::submission_archive_protection::check(root, true)?;
    let mut count = 0usize;
    let mut maximum = None;
    for entry in fs::read_dir(root).map_err(PoolError::Io)? {
        let entry = entry.map_err(PoolError::Io)?;
        let path = entry.path();
        crate::submission_archive_protection::check(&path, false)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| PoolError::Integrity)?;
        if name == "archive.lock" {
            continue;
        }
        if name == "lookup.sqlite" || name == "lookup.sqlite-journal" {
            continue;
        }
        let (name, journal) = name
            .strip_suffix("-journal")
            .map(|s| (s.to_owned(), true))
            .unwrap_or((name, false));
        let number = name
            .strip_prefix("shard-")
            .and_then(|s| s.strip_suffix(".sqlite"))
            .filter(|s| s.len() == 20 && s.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or(PoolError::Integrity)?;
        if journal {
            if !shard_path(
                root,
                usize::try_from(number).map_err(|_| PoolError::Integrity)?,
            )
            .is_file()
            {
                return Err(PoolError::Integrity);
            }
        } else {
            count = count.checked_add(1).ok_or(PoolError::Capacity)?;
            maximum = Some(maximum.unwrap_or(0u64).max(number));
        }
    }
    if maximum.is_some_and(|n| n != count as u64 - 1) {
        return Err(PoolError::Integrity);
    }
    Ok(count)
}
fn archive_connection(path: &Path) -> Result<Connection> {
    crate::submission_archive_protection::check(path, false)?;
    if fs::metadata(path).map_err(PoolError::Io)?.len() > 8 * 1024 * 1024 {
        return Err(PoolError::Capacity);
    }
    let db = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    db.busy_timeout(Duration::from_millis(250))?;
    let mode: String = db.pragma_query_value(None, "journal_mode", |r| r.get(0))?;
    let pagesize: u64 = db.pragma_query_value(None, "page_size", |r| r.get(0))?;
    if mode != "delete" || pagesize != 4096 {
        return Err(PoolError::ArchiveProtection);
    }
    db.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA synchronous=FULL; PRAGMA max_page_count=2048;")?;
    Ok(db)
}
fn archive_rows(path: &Path, g: Hash, f: Hash) -> Result<Vec<(Submission, Status)>> {
    let db = archive_connection(path)?;
    validate_schema(&db, g, f)?;
    if db.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))? != 1 {
        return Err(PoolError::Integrity);
    }
    let out = entries(&db, ARCHIVE_BYTES, None)?;
    if out.len() > ARCHIVE_ROWS
        || db.query_row("SELECT count(*) FROM basis", [], |r| r.get::<_, u64>(0))? != 0
    {
        return Err(PoolError::Integrity);
    }
    for (o, status) in &out {
        if active(status) {
            return Err(PoolError::Integrity);
        }
        o.check_context(&FinalizedAnchor {
            network: crate::NETWORK_ID,
            genesis: g,
            fingerprint: f,
            height: 0,
            block: [1; 32],
        })
        .map_err(|_| PoolError::Integrity)?;
        o.verify_signatures().map_err(|_| PoolError::Integrity)?;
        #[cfg(any(test, feature = "dividend-test-fixtures"))]
        ARCHIVE_SIGNATURE_CHECKS.with(|count| count.set(count.get() + 1));
    }
    Ok(out)
}
fn archive_seal(db: &Connection, attached: bool, g: Hash, f: Hash) -> Result<Hash> {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(b"MUTINY-BUILD8-LOCAL-ARCHIVE-SEAL-V1");
    digest.update(g);
    digest.update(f);
    let mut query=db.prepare(if attached {"SELECT id,class,kind,raw,first,last,wire,sig_ok,status FROM terminal_archive.entries ORDER BY id LIMIT 257"} else {"SELECT id,class,kind,raw,first,last,wire,sig_ok,status FROM entries ORDER BY id LIMIT 257"})?;
    let mut rows = query.query([])?;
    let mut count = 0;
    while let Some(row) = rows.next()? {
        count += 1;
        if count > ARCHIVE_ROWS {
            return Err(PoolError::Integrity);
        }
        for col in 0..9 {
            match row.get_ref(col)? {
                rusqlite::types::ValueRef::Integer(n) => {
                    digest.update([0]);
                    digest.update(n.to_be_bytes());
                }
                rusqlite::types::ValueRef::Blob(raw) => {
                    if raw.len() > 16384 {
                        return Err(PoolError::Integrity);
                    }
                    digest.update([1]);
                    digest.update((raw.len() as u64).to_be_bytes());
                    digest.update(raw);
                }
                _ => return Err(PoolError::Integrity),
            }
        }
    }
    Ok(digest.finalize().into())
}
fn archive_fault(selected: u8, point: u8) -> Result<()> {
    #[cfg(any(test, feature = "dividend-test-fixtures"))]
    {
        if selected == 100 + point {
            // Abrupt child-process exit: destructors/SQLite rollback do not run.
            // Parent tests inspect and reopen the retained rollback journals.
            std::process::exit(75);
        }
        if selected == point {
            return Err(PoolError::Integrity);
        }
    }
    let _ = (selected, point);
    Ok(())
}
fn validate_schema(db: &Connection, g: Hash, f: Hash) -> Result<()> {
    let app: i64 = db.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let ver: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let count: i64 = db.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
    if app != APP_ID || !matches!(ver, 1 | 2) || count != if ver == 1 { 6 } else { 8 } {
        return Err(PoolError::Integrity);
    }
    if ver == 2 {
        let actual:String=db.query_row("SELECT sql FROM sqlite_schema WHERE type='table' AND name='archive_catalog' AND tbl_name='archive_catalog'",[],|r|r.get(0))?;
        if actual != CATALOG {
            return Err(PoolError::Integrity);
        }
        let index:u64=db.query_row("SELECT count(*) FROM sqlite_schema WHERE type='index' AND name='sqlite_autoindex_archive_catalog_1' AND tbl_name='archive_catalog' AND sql IS NULL",[],|r|r.get(0))?;
        if index != 1 {
            return Err(PoolError::Integrity);
        }
    }
    for (name, sql) in SCHEMA {
        let actual:String=db.query_row("SELECT CASE WHEN length(sql)<=2048 THEN sql ELSE NULL END FROM sqlite_schema WHERE type='table' AND name=?1 AND tbl_name=?1",[name],|r|r.get(0))?;
        if actual != sql {
            return Err(PoolError::Integrity);
        }
    }
    for table in ["entries", "resources"] {
        let n:i64=db.query_row("SELECT count(*) FROM sqlite_schema WHERE type='index' AND name=?1 AND tbl_name=?2 AND sql IS NULL",params![format!("sqlite_autoindex_{table}_1"),table],|r|r.get(0))?;
        if n != 1 {
            return Err(PoolError::Integrity);
        }
    }
    let n: i64 = db.query_row("SELECT count(*) FROM context", [], |r| r.get(0))?;
    let (got_g, got_f): (Vec<u8>, Vec<u8>) = db.query_row(
        "SELECT genesis,fingerprint FROM context WHERE id=1",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if n != 1 || got_g != g || got_f != f {
        return Err(PoolError::Context);
    }
    let n: i64 = db.query_row("SELECT count(*) FROM basis", [], |r| r.get(0))?;
    if n > 1 {
        return Err(PoolError::Integrity);
    }
    if n == 1 {
        let (a, r): (Vec<u8>, Vec<u8>) =
            db.query_row("SELECT anchor,root FROM basis WHERE id=1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?;
        FinalizedAnchor::decode(&a)
            .and_then(|a| a.validate_context(g, f))
            .map_err(|_| PoolError::Integrity)?;
        fixed(r)?;
    }
    Ok(())
}
fn entries(
    db: &Connection,
    limit: u64,
    signatures: Option<&BTreeMap<Hash, Hash>>,
) -> Result<Vec<(Submission, Status)>> {
    let mut q=db.prepare("SELECT id,class,kind,CASE WHEN length(raw) BETWEEN 1 AND 16384 THEN raw ELSE NULL END,first,last,wire,sig_ok,CASE WHEN length(status)<=768 THEN status ELSE NULL END FROM entries ORDER BY id LIMIT 65537")?;
    let mut out = Vec::new();
    let mut bytes = 0u64;
    for row in q.query_map([], |r| {
        Ok((
            r.get::<_, Vec<u8>>(0)?,
            r.get::<_, u8>(1)?,
            r.get::<_, u8>(2)?,
            r.get::<_, Vec<u8>>(3)?,
            r.get::<_, Vec<u8>>(4)?,
            r.get::<_, Vec<u8>>(5)?,
            r.get::<_, Vec<u8>>(6)?,
            r.get::<_, i64>(7)?,
            r.get::<_, Vec<u8>>(8)?,
        ))
    })? {
        let (id, list, kind, raw, first, last, wire, sig_ok, status) = row?;
        bytes = bytes
            .checked_add(raw.len() as u64)
            .ok_or(PoolError::Capacity)?;
        if out.len() >= MAX_ROWS || bytes > limit {
            return Err(PoolError::Capacity);
        }
        let object = Submission::decode(list, &raw).map_err(|_| PoolError::Integrity)?;
        if signatures.is_some_and(|cache| cache.get(&object.id) != Some(&object.wire)) {
            return Err(PoolError::Integrity);
        }
        if id != object.id
            || kind != object.kind
            || wire != object.wire
            || sig_ok != 1
            || first != object.window().0.to_be_bytes()
            || last != object.window().1.to_be_bytes()
        {
            return Err(PoolError::Integrity);
        }
        let status = decode_status(object.id, &status)?;
        if matches!(status, Status::Unknown) {
            return Err(PoolError::Integrity);
        }
        if let Status::Finalized(r) = &status {
            if r.op_id != object.id
                || r.wire != object.wire
                || r.kind != object.kind
                || r.list != object.list
            {
                return Err(PoolError::Integrity);
            }
        }
        out.push((object, status));
    }
    // Exact ownership of every active reservation, no terminal or orphan resources.
    let expected: BTreeMap<_, _> = out
        .iter()
        .filter(|(_, s)| active(s))
        .flat_map(|(o, _)| o.resources().into_iter().map(|r| (r, o.id)))
        .collect();
    let count: usize = out
        .iter()
        .filter(|(_, s)| active(s))
        .map(|(o, _)| o.resources().len())
        .sum();
    if expected.len() != count {
        return Err(PoolError::Integrity);
    }
    let mut actual = BTreeMap::new();
    let mut q = db.prepare("SELECT resource,owner FROM resources LIMIT 8519681")?;
    for row in q.query_map([], |r| {
        Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
    })? {
        let (r, id) = row?;
        if actual.len() >= expected.len() || actual.insert(fixed(r)?, fixed(id)?).is_some() {
            return Err(PoolError::Integrity);
        }
    }
    if expected != actual {
        return Err(PoolError::Integrity);
    }
    if signatures.is_some_and(|cache| cache.len() != out.len()) {
        return Err(PoolError::Integrity);
    }
    Ok(out)
}
impl SubmissionPool {
    /// Provision a NEW private directory, or check existing protection unchanged.
    pub fn private_directory(path: &Path) -> Result<bool> {
        private_directory(path)
    }
    pub fn open(path: &Path, genesis: Hash, fingerprint: Hash, limit: u64) -> Result<Self> {
        if genesis == [0; 32] || fingerprint == [0; 32] || limit == 0 || limit > MAX_BYTES {
            return Err(PoolError::Context);
        }
        // Complete local objects may include preimages. Refuse unsafe existing
        // locations before ANY writable SQLite open; never silently chmod/move.
        crate::submission_archive_protection::check(
            path.parent().ok_or(PoolError::ArchiveProtection)?,
            true,
        )?;
        let file = private_file(path)?;
        crate::submission_archive_protection::check(path, false)?;
        drop(file);
        for suffix in ["-journal", "-wal", "-shm"] {
            let mut name = path.as_os_str().to_owned();
            name.push(suffix);
            let sibling = PathBuf::from(name);
            if crate::submission_archive_protection::present(&sibling)? {
                crate::submission_archive_protection::check(&sibling, false)?;
            }
        }
        let mut db = Connection::open(path)?;
        db.busy_timeout(Duration::from_millis(250))?;
        db.execute_batch("PRAGMA page_size=4096; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE; PRAGMA max_page_count=32768;")?;
        let app: i64 = db.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let n: i64 = db.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
        if app == 0 && n == 0 {
            let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
            for (_, sql) in SCHEMA {
                tx.execute_batch(sql)?;
            }
            tx.execute(
                "INSERT INTO context VALUES(1,?1,?2)",
                params![genesis.as_slice(), fingerprint.as_slice()],
            )?;
            tx.pragma_update(None, "application_id", APP_ID)?;
            tx.pragma_update(None, "user_version", 1)?;
            tx.commit()?;
        }
        let mut out = Self {
            db,
            genesis,
            fingerprint,
            limit,
            signatures: BTreeMap::new(),
            path: fs::canonicalize(path).map_err(PoolError::Io)?,
            archive_lock: None,
            archive_lookup: None,
            archive_shards: 0,
        };
        validate_schema(&out.db, genesis, fingerprint)?;
        if out
            .db
            .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))?
            == 2
        {
            // Active objects retain their strict logical budget. The durable
            // catalog may grow with retained history until actual disk/SQLite
            // capacity; it must not impose the old permanent 128 MiB refusal.
            out.db
                .pragma_update(None, "max_page_count", 2147483646u64)?;
        }
        // Persisted sig_ok never makes tampered bytes acceptable on reopen.
        for (o, _) in entries(&out.db, limit, None)? {
            o.check_context(&FinalizedAnchor {
                network: crate::NETWORK_ID,
                genesis,
                fingerprint,
                height: 0,
                block: [1; 32],
            })
            .map_err(|_| PoolError::Integrity)?;
            o.verify_signatures().map_err(|_| PoolError::Integrity)?;
            out.signatures.insert(o.id, o.wire);
        }
        let archive = out.archive_path();
        if crate::submission_archive_protection::present(&archive)?
            || out
                .db
                .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))?
                == 2
        {
            if !crate::submission_archive_protection::present(&archive)? {
                return Err(PoolError::Integrity);
            }
            out.archive_lock = Some(archive_lock(&archive)?);
            out.rebuild_archive_lookup()?;
        }
        Ok(out)
    }
    pub fn archive_path(&self) -> PathBuf {
        self.path.with_extension("submission-archive")
    }
    fn visit_archive(
        &self,
        mut visit: impl FnMut(usize, Vec<(Submission, Status)>) -> Result<()>,
    ) -> Result<usize> {
        let root = self.archive_path();
        let version: i64 = self
            .db
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        if !crate::submission_archive_protection::present(&root)? {
            return if version == 1 {
                Ok(0)
            } else {
                Err(PoolError::Integrity)
            };
        }
        let count = archive_inventory(&root)?;
        let catalog: usize = if version == 2 {
            self.db
                .query_row("SELECT count(*) FROM archive_catalog", [], |r| r.get(0))?
        } else {
            0
        };
        if count < catalog || count > catalog.checked_add(1).ok_or(PoolError::Capacity)? {
            return Err(PoolError::Integrity);
        }
        if count > 0 && self.archive_lock.is_none() {
            return Err(PoolError::ArchiveLocked);
        }
        for number in 0..count {
            let path = shard_path(&root, number);
            crate::submission_archive_protection::same_filesystem(&self.path, &path)?;
            let rows = archive_rows(&path, self.genesis, self.fingerprint)?;
            let bytes: u64 = rows.iter().map(|(o, _)| o.raw.len() as u64).sum();
            if number < catalog {
                let expected: (usize, u64, Vec<u8>) = self.db.query_row(
                    "SELECT rows,bytes,seal FROM archive_catalog WHERE sequence=?1",
                    [(number as u64).to_be_bytes().as_slice()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )?;
                let archive = archive_connection(&shard_path(&root, number))?;
                if expected
                    != (
                        rows.len(),
                        bytes,
                        archive_seal(&archive, false, self.genesis, self.fingerprint)?.to_vec(),
                    )
                {
                    return Err(PoolError::Integrity);
                }
            } else if !rows.is_empty() {
                return Err(PoolError::Integrity);
            }
            visit(number, rows)?;
        }
        Ok(count)
    }
    fn archive_lookup(&self, id: Hash) -> Result<Option<(Submission, Status)>> {
        self.check_archive_inventory()?;
        self.archive_lookup_checked(id)
    }
    fn check_archive_inventory(&self) -> Result<()> {
        let root = self.archive_path();
        if self.archive_lookup.is_none() {
            return if !crate::submission_archive_protection::present(&root)?
                && self.archive_shards == 0
            {
                Ok(())
            } else {
                Err(PoolError::Integrity)
            };
        }
        // Inventory/protection metadata still grows with shard count. No shard
        // is silently skipped. Cryptography below is bounded to one ID path.
        if archive_inventory(&root)? != self.archive_shards {
            return Err(PoolError::Integrity);
        }
        Ok(())
    }
    fn archive_lookup_checked(&self, id: Hash) -> Result<Option<(Submission, Status)>> {
        let root = self.archive_path();
        if self.archive_lookup.is_none() {
            return Ok(None);
        }
        let Some((number, digest)) = self.archive_lookup.as_ref().unwrap().get(id)? else {
            return Ok(None);
        };
        let number = usize::try_from(number).map_err(|_| PoolError::Integrity)?;
        if number >= self.archive_shards {
            return Err(PoolError::Integrity);
        }
        let path = shard_path(&root, number);
        crate::submission_archive_protection::same_filesystem(&self.path, &path)?;
        let db = archive_connection(&path)?;
        validate_schema(&db, self.genesis, self.fingerprint)?;
        if crate::submission_archive_lookup::row_digest(&db, id)? != digest {
            return Err(PoolError::Integrity);
        }
        let expected: (usize, u64, Vec<u8>) = self.db.query_row(
            "SELECT rows,bytes,seal FROM archive_catalog WHERE sequence=?1",
            [(number as u64).to_be_bytes().as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        // Bounded one-shard codec/resource validation. Signatures were verified
        // at open/admission and these exact nine columns match the trusted leaf.
        let mut found = None;
        let rows = entries(&db, ARCHIVE_BYTES, None)?;
        if rows.len() > ARCHIVE_ROWS
            || expected
                != (
                    rows.len(),
                    rows.iter().map(|(o, _)| o.raw.len() as u64).sum(),
                    archive_seal(&db, false, self.genesis, self.fingerprint)?.to_vec(),
                )
        {
            return Err(PoolError::Integrity);
        }
        for row in rows {
            if active(&row.1) {
                return Err(PoolError::Integrity);
            }
            if row.0.id == id {
                found = Some(row);
            }
        }
        found.ok_or(PoolError::Integrity).map(Some)
    }
    fn rebuild_archive_lookup(&mut self) -> Result<()> {
        let root = self.archive_path();
        let path = root.join("lookup.sqlite");
        drop(private_file(&path)?);
        let mut lookup = crate::submission_archive_lookup::Lookup::rebuild(&path)?;
        let count = self.visit_archive(|number, rows| {
            let db = archive_connection(&shard_path(&root, number))?;
            for (o, _) in rows {
                if self.signatures.contains_key(&o.id) {
                    return Err(PoolError::Integrity);
                }
                lookup.insert(
                    o.id,
                    number as u64,
                    crate::submission_archive_lookup::row_digest(&db, o.id)?,
                )?;
            }
            Ok(())
        })?;
        self.archive_lookup = Some(lookup);
        self.archive_shards = count;
        Ok(())
    }
    /// Explicit reversible archival: copy complete terminal rows and their exact
    /// local evidence, then free only active-cache capacity in the SAME SQLite
    /// super-journal transaction. All shards remain recoverable forever; disk-full
    /// and protection failures refuse. DELETE/FULL and same-volume are mandatory.
    /// SQLite/OS crash recovery has targeted tests; Windows power-loss durability is not claimed.
    pub fn archive_terminal(&mut self) -> Result<usize> {
        self.archive_terminal_inner(0)
    }
    #[cfg(any(test, feature = "dividend-test-fixtures"))]
    pub fn fixture_archive_fault(&mut self, point: u8) -> Result<usize> {
        self.archive_terminal_inner(point)
    }
    fn archive_terminal_inner(&mut self, fault: u8) -> Result<usize> {
        validate_schema(&self.db, self.genesis, self.fingerprint)?;
        let all = entries(&self.db, self.limit, Some(&self.signatures))?;
        let terminal: Vec<_> = all
            .into_iter()
            .filter(|(_, s)| !active(s))
            .take(ARCHIVE_ROWS)
            .collect();
        if terminal.is_empty() {
            return Ok(0);
        }
        let root = self.archive_path();
        if self.archive_lock.is_none() {
            self.archive_lock = Some(archive_lock(&root)?);
        }
        if self.archive_lookup.is_none() {
            self.rebuild_archive_lookup()?;
        }
        crate::submission_archive_protection::same_filesystem(&self.path, &root)?;
        // Validate every shard before selecting a destination or trusting a duplicate.
        let mut last_usage = (0usize, 0u64);
        let shards = self.visit_archive(|_, rows| {
            if rows
                .iter()
                .any(|(o, _)| terminal.iter().any(|(t, _)| t.id == o.id))
            {
                return Err(PoolError::Integrity);
            }
            last_usage = (
                rows.len(),
                rows.iter().map(|(o, _)| o.raw.len() as u64).sum(),
            );
            Ok(())
        })?;
        let bytes: u64 = terminal.iter().map(|(o, _)| o.raw.len() as u64).sum();
        let (sequence, path) = if shards > 0
            && last_usage.0 + terminal.len() <= ARCHIVE_ROWS
            && last_usage.1 + bytes <= ARCHIVE_BYTES
        {
            (shards - 1, shard_path(&root, shards - 1))
        } else {
            let path = shard_path(&root, shards);
            let _file = private_file(&path)?;
            let mut archive = archive_connection(&path)?;
            let count: u64 =
                archive.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
            let app: i64 = archive.pragma_query_value(None, "application_id", |r| r.get(0))?;
            if count != 0 || app != 0 {
                return Err(PoolError::Integrity);
            }
            let tx = archive.transaction_with_behavior(TransactionBehavior::Immediate)?;
            for (_, sql) in SCHEMA {
                tx.execute_batch(sql)?;
            }
            tx.execute(
                "INSERT INTO context VALUES(1,?1,?2)",
                params![self.genesis.as_slice(), self.fingerprint.as_slice()],
            )?;
            tx.pragma_update(None, "application_id", APP_ID)?;
            tx.pragma_update(None, "user_version", 1)?;
            tx.commit()?;
            (shards, path)
        };
        crate::submission_archive_protection::same_filesystem(&self.path, &path)?;
        // ATTACH accepts a bound filename; filenames are never SQL interpolation.
        let filename = path.to_str().ok_or(PoolError::ArchiveProtection)?;
        self.db
            .execute("ATTACH DATABASE ?1 AS terminal_archive", [filename])?;
        let mut committed = false;
        let moved = (|| -> Result<usize> {
            self.db.execute_batch("PRAGMA terminal_archive.synchronous=FULL; PRAGMA terminal_archive.journal_mode=DELETE; PRAGMA terminal_archive.max_page_count=2048;")?;
            for schema in ["main", "terminal_archive"] {
                let mode: String =
                    self.db
                        .pragma_query_value(Some(schema), "journal_mode", |r| r.get(0))?;
                let sync: i64 = self
                    .db
                    .pragma_query_value(Some(schema), "synchronous", |r| r.get(0))?;
                let pagesize: u64 = self
                    .db
                    .pragma_query_value(Some(schema), "page_size", |r| r.get(0))?;
                if mode != "delete" || sync != 2 || pagesize != 4096 {
                    return Err(PoolError::ArchiveProtection);
                }
            }
            #[cfg(any(test, feature = "dividend-test-fixtures"))]
            if fault == 10 {
                let schema = "terminal_archive";
                let pages: u64 = self
                    .db
                    .pragma_query_value(Some(schema), "page_count", |r| r.get(0))?;
                self.db
                    .pragma_update(Some(schema), "max_page_count", pages)?;
            }
            let tx = self
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            let current = entries(&tx, self.limit, Some(&self.signatures))?;
            if tx.pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))? == 1 {
                tx.execute_batch(CATALOG)?;
                tx.pragma_update(None, "user_version", 2)?;
            }
            for (o, status) in &terminal {
                if !current.iter().any(|(c, s)| c == o && s == status) {
                    return Err(PoolError::Integrity);
                }
                tx.execute(
                    "INSERT INTO terminal_archive.entries SELECT * FROM main.entries WHERE id=?1",
                    [o.id.as_slice()],
                )?;
                archive_fault(fault, 1)?;
                let count=tx.execute("DELETE FROM main.entries WHERE id=?1 AND NOT EXISTS(SELECT 1 FROM main.resources WHERE owner=?1)",[o.id.as_slice()])?;
                if count != 1 {
                    return Err(PoolError::Integrity);
                }
                archive_fault(fault, 2)?;
            }
            let (rows, size): (usize, u64) = tx.query_row(
                "SELECT count(*),coalesce(sum(length(raw)),0) FROM terminal_archive.entries",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            if rows > ARCHIVE_ROWS || size > ARCHIVE_BYTES {
                return Err(PoolError::Capacity);
            }
            let seal = archive_seal(&tx, true, self.genesis, self.fingerprint)?;
            tx.execute("INSERT INTO archive_catalog VALUES(?1,?2,?3,?4) ON CONFLICT(sequence) DO UPDATE SET rows=excluded.rows,bytes=excluded.bytes,seal=excluded.seal",params![(sequence as u64).to_be_bytes().as_slice(),rows,size,seal.as_slice()])?;
            archive_fault(fault, 3)?;
            tx.commit()?;
            committed = true;
            archive_fault(fault, 4)?;
            Ok(terminal.len())
        })();
        let detached = self.db.execute_batch("DETACH DATABASE terminal_archive");
        // A completed commit remains authoritative even if a later DETACH fails.
        if committed {
            for (o, _) in &terminal {
                self.signatures.remove(&o.id);
            }
            if moved.is_err() {
                if let Some(lookup) = self.archive_lookup.as_mut() {
                    lookup.invalidate();
                }
            }
        }
        if moved.is_ok() {
            let update = (|| -> Result<()> {
                archive_fault(fault, 5)?; // Canonical retained copy committed; derived update has not.
                let db = archive_connection(&path)?;
                let lookup = self.archive_lookup.as_mut().ok_or(PoolError::Integrity)?;
                for (o, _) in &terminal {
                    lookup.insert(
                        o.id,
                        sequence as u64,
                        crate::submission_archive_lookup::row_digest(&db, o.id)?,
                    )?;
                }
                Ok(())
            })();
            if let Err(error) = update {
                if let Some(lookup) = self.archive_lookup.as_mut() {
                    lookup.invalidate();
                }
                return Err(error); // Retained main/shard commit remains intact.
            }
        }
        // A pre-copy empty shard is intentional retained evidence after failure.
        self.archive_shards = archive_inventory(&root)?;
        let count = moved?;
        detached?;
        self.db
            .pragma_update(None, "max_page_count", 2147483646u64)?;
        Ok(count)
    }
    pub fn basis(&self) -> Result<Option<(FinalizedAnchor, Hash)>> {
        validate_schema(&self.db, self.genesis, self.fingerprint)?;
        let row: Option<(Vec<u8>, Vec<u8>)> = self
            .db
            .query_row("SELECT anchor,root FROM basis WHERE id=1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;
        row.map(|(a, r)| {
            Ok((
                FinalizedAnchor::decode(&a).map_err(|_| PoolError::Integrity)?,
                fixed(r)?,
            ))
        })
        .transpose()
    }
    fn require_basis(&self, a: &FinalizedAnchor, state: &State) -> Result<()> {
        if self.basis()? != Some((a.clone(), root(state)?)) {
            Err(PoolError::StaleBasis)
        } else {
            Ok(())
        }
    }
    pub fn status(&self, id: Hash) -> Result<Status> {
        validate_schema(&self.db, self.genesis, self.fingerprint)?;
        entries(&self.db, self.limit, Some(&self.signatures))?;
        let raw: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT status FROM entries WHERE id=?1",
                [id.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        let archived = self.archive_lookup(id)?;
        if raw.is_some() && archived.is_some() {
            return Err(PoolError::Integrity);
        }
        Ok(raw
            .map(|raw| decode_status(id, &raw))
            .transpose()?
            .or(archived.map(|(_, s)| s))
            .unwrap_or(Status::Unknown))
    }
    pub fn statuses(&self, ids: &[Hash]) -> Result<BTreeMap<Hash, Status>> {
        if ids.len() > 64 {
            return Err(PoolError::Capacity);
        }
        validate_schema(&self.db, self.genesis, self.fingerprint)?;
        let mut out: BTreeMap<_, _> = ids.iter().map(|id| (*id, Status::Unknown)).collect();
        for (o, status) in entries(&self.db, self.limit, Some(&self.signatures))? {
            if let Some(s) = out.get_mut(&o.id) {
                *s = status;
            }
        }
        self.check_archive_inventory()?;
        for id in ids.iter().copied().collect::<BTreeSet<_>>() {
            if let Some((_, status)) = self.archive_lookup_checked(id)? {
                let stored = out.get_mut(&id).ok_or(PoolError::Integrity)?;
                if !matches!(stored, Status::Unknown) {
                    return Err(PoolError::Integrity);
                }
                *stored = status;
            }
        }
        Ok(out)
    }
    pub fn exact_bytes(&self, id: Hash) -> Result<Option<(u8, Vec<u8>)>> {
        validate_schema(&self.db, self.genesis, self.fingerprint)?;
        entries(&self.db, self.limit, Some(&self.signatures))?;
        let local = self
            .db
            .query_row(
                "SELECT class,raw FROM entries WHERE id=?1",
                [id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let archived = self.archive_lookup(id)?;
        if local.is_some() && archived.is_some() {
            return Err(PoolError::Integrity);
        }
        Ok(local.or(archived.map(|(o, _)| (o.list, o.raw))))
    }
    pub fn admit(
        &mut self,
        a: &FinalizedAnchor,
        state: &State,
        history: &History,
        epoch: u64,
        list: u8,
        raw: &[u8],
    ) -> Result<(Hash, Status)> {
        let object = Submission::decode(list, raw)?;
        object.check_context(a)?;
        self.require_basis(a, state)?;
        if let Some((old, status)) = self.archive_lookup(object.id)? {
            if old.list != object.list || old.wire != object.wire || old.raw != object.raw {
                return Err(PoolError::Conflict);
            }
            return Ok((object.id, status));
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_schema(&tx, self.genesis, self.fingerprint)?;
        let existing = entries(&tx, self.limit, Some(&self.signatures))?;
        if let Some((old, status)) = existing.iter().find(|(old, _)| old.id == object.id) {
            // Immutable identity + exact bytes: signature substitution never renews an item.
            if old.wire != object.wire || old.raw != object.raw || old.list != object.list {
                return Err(PoolError::Conflict);
            }
            return Ok((object.id, status.clone()));
        }
        let height = a.height.checked_add(1).ok_or(PoolError::Integrity)?;
        let (first, last) = object.window();
        if height < first {
            return Err(Reason::NotYetValid.into());
        }
        if height > last {
            return Err(Reason::WindowExpired.into());
        }
        let resources = object.resources();
        for resource in &resources {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM resources WHERE resource=?1)",
                [resource.as_slice()],
                |r| r.get(0),
            )?;
            if exists {
                return Err(PoolError::Conflict);
            }
        }
        if existing.len() >= MAX_ROWS
            || existing
                .iter()
                .map(|(o, _)| o.raw.len() as u64)
                .sum::<u64>()
                .checked_add(raw.len() as u64)
                .is_none_or(|n| n > self.limit)
        {
            return Err(PoolError::Capacity);
        }
        // Cheap state/context checks precede expensive signatures. The exact bytes are
        // cryptographically verified before any row or resource is committed.
        object.verify_state(a, state, history, epoch)?;
        object.verify_signatures()?;
        tx.execute(
            "INSERT INTO entries VALUES(?1,?2,?3,?4,?5,?6,?7,1,?8)",
            params![
                object.id.as_slice(),
                list,
                object.kind,
                raw,
                first.to_be_bytes().as_slice(),
                last.to_be_bytes().as_slice(),
                object.wire.as_slice(),
                status_raw(a, object.id, Status::Pending)?
            ],
        )?;
        for resource in resources {
            tx.execute(
                "INSERT INTO resources VALUES(?1,?2)",
                params![resource.as_slice(), object.id.as_slice()],
            )?;
        }
        tx.commit()?;
        self.signatures.insert(object.id, object.wire);
        Ok((object.id, Status::Pending))
    }
    /// Only canonical_store may supply these execution-authenticated records.
    /// Index lookup happens before expiry/current state, so spent payouts remain final.
    pub(crate) fn reconcile(
        &mut self,
        a: &FinalizedAnchor,
        state: &State,
        history: &History,
        epoch: u64,
        records: &BTreeMap<Hash, Vec<OperationRecord>>,
    ) -> Result<()> {
        a.validate_context(self.genesis, self.fingerprint)
            .map_err(|_| PoolError::Context)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_schema(&tx, self.genesis, self.fingerprint)?;
        let all = entries(&tx, self.limit, Some(&self.signatures))?;
        for (object, old) in all {
            let found = records.get(&object.id).and_then(|rows| {
                rows.iter().find(|r| {
                    r.wire == object.wire && r.list == object.list && r.kind == object.kind
                })
            });
            let status = if let Some(record) = found {
                Status::Finalized(record.clone())
            } else if matches!(old, Status::Finalized(_)) {
                return Err(PoolError::Integrity);
            } else if !active(&old) {
                old.clone()
            } else if a.height.checked_add(1).ok_or(PoolError::Integrity)? > object.window().1 {
                Status::Expired {
                    last: object.window().1,
                }
            } else {
                match object.verify_state(a, state, history, epoch) {
                    Ok(()) => Status::Pending,
                    Err(Reason::NotYetValid) => Status::Pending,
                    Err(reason) => Status::Conflicting {
                        reason,
                        height: a.height,
                    },
                }
            };
            if !active(&status) {
                tx.execute(
                    "DELETE FROM resources WHERE owner=?1",
                    [object.id.as_slice()],
                )?;
            }
            tx.execute(
                "UPDATE entries SET status=?1 WHERE id=?2",
                params![status_raw(a, object.id, status)?, object.id.as_slice()],
            )?;
        }
        tx.execute("INSERT INTO basis VALUES(1,?1,?2) ON CONFLICT(id) DO UPDATE SET anchor=excluded.anchor,root=excluded.root",params![a.encode(),root(state)?.as_slice()])?;
        tx.commit()?;
        Ok(())
    }
    /// A locally fully validated current proposal may advertise inclusion. It does
    /// not release reservations or mark finality. Reconciliation clears lost forks.
    pub fn note_unfinalized(
        &mut self,
        a: &FinalizedAnchor,
        id: Hash,
        height: u64,
        block: Hash,
    ) -> Result<()> {
        if height != a.height.checked_add(1).ok_or(PoolError::Integrity)? || block == [0; 32] {
            return Err(PoolError::Context);
        }
        let old = self.status(id)?;
        if !active(&old) {
            return Ok(());
        }
        let basis = self.basis()?.ok_or(PoolError::StaleBasis)?;
        if basis.0 != *a {
            return Err(PoolError::StaleBasis);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE entries SET status=?1 WHERE id=?2",
            params![
                status_raw(a, id, Status::Unfinalized { height, block })?,
                id.as_slice()
            ],
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn pending_at(&self, a: &FinalizedAnchor, state: &State) -> Result<Vec<Submission>> {
        self.require_basis(a, state)?;
        Ok(entries(&self.db, self.limit, Some(&self.signatures))?
            .into_iter()
            .filter(|(_, s)| active(s))
            .map(|(o, _)| o)
            .collect())
    }
    pub fn tracked_ids(&self) -> Result<Vec<Hash>> {
        validate_schema(&self.db, self.genesis, self.fingerprint)?;
        Ok(entries(&self.db, self.limit, Some(&self.signatures))?
            .into_iter()
            .map(|(o, _)| o.id)
            .collect())
    }
    pub fn reference_heights(&self) -> Result<BTreeSet<u64>> {
        validate_schema(&self.db, self.genesis, self.fingerprint)?;
        Ok(entries(&self.db, self.limit, Some(&self.signatures))?
            .into_iter()
            .filter(|(_, s)| active(s))
            .filter_map(|(o, _)| o.reference_height())
            .collect())
    }
    /// TEST-VALUE fault injection on this cache connection only; no consensus gate.
    #[cfg(any(test, feature = "dividend-test-fixtures"))]
    pub fn fixture_limit_pages(&self, pages: u64) -> Result<u64> {
        self.db.pragma_update(None, "max_page_count", pages)?;
        Ok(self
            .db
            .pragma_query_value(None, "max_page_count", |r| r.get(0))?)
    }
}
impl crate::op_envelope_v1::PendingReferences for SubmissionPool {
    fn reference_heights(&self) -> BTreeSet<u64> {
        self.reference_heights().unwrap_or_default()
    }
}
