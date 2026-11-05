//! Durable SQLite implementation of the [`Outbox`] contract.
//!
//! The exact signed bytes are committed in one atomic transaction (record row plus one reservation
//! row per input) with `synchronous = FULL` BEFORE `commit` returns, so after a crash the database
//! holds either the complete record and its reservations or nothing. The same rules as the
//! in-memory outbox apply: every commit re-verifies the bytes through consensus code against the
//! current verified view and derives the record's metadata from the bytes, a reservation can be held
//! by one open record only (the primary key of the reservation table enforces it even if the checks
//! above it were bypassed), an id is idempotent while its record is open, `forget` releases the
//! reservations but never revokes the signed bytes, and only open records count against the limits
//! (settled records are history, trimmed on every reconciliation).
//!
//! [`Outbox::replace_partial`] runs in one transaction too: the partial's rows go and the complete
//! record's rows come before it commits, so after a crash at any point the database holds the
//! partial or the complete record with its reservations, never neither and never both.
//!
//! The database is bound to one chain (network, Genesis, protocol fingerprint) when it is created and
//! refuses to open for any other, and refuses views of any other chain afterwards. The schema is
//! exact: the application id, the version and the SQL of every table are compared on every open, no
//! other object may exist, and every row read back is re-verified (checksum over kind, id, bytes and
//! metadata; the reservation rows must equal the record's own list). Anything irregular is
//! [`Refusal::OutboxIntegrity`]; a full disk is [`Refusal::OutboxFull`]; a file that cannot be
//! opened, or a name that is not a durable file (empty, `:memory:`, a `file:` URI), is
//! [`Refusal::OutboxLocation`]; another process holding the file is [`Refusal::OutboxBusy`].
//!
//! The checksums catch accidental damage and careless edits; someone who can rewrite the file can
//! recompute them (see the outbox module documentation for what protects against that).
//!
//! The diagnostic status `OutboxStatus::Stranded(height)` (Order W9) is stored without a schema
//! change, as the inputs-spent status code with its height in `status_height` (which is 0 for a
//! plain inputs-spent record, and at least 1 for a stranding, because no wallet operation is in
//! the Genesis block). A reader of schema version 1 that does not know the variant reads such a
//! row as `InputsSpent`, exactly what it reported for that case before.
//!
//! No delivery claim is made anywhere in this module: a stored record means "queued locally".
use crate::{
    authorize::SignedOperation,
    context::{ChainContext, ChainView},
    export::{ApprovalBinding, VerifiedExport},
    outbox::{
        DEFAULT_MAX_SETTLED, Outbox, OutboxRecord, OutboxStatus, ReconcileReport, Settlement,
        admit_described, admit_replacement, context_refusal, describe_checked, settle,
    },
    plan::OperationKind,
    refusal::Refusal,
};
use mutiny_consensus_v8::{Hash, transactions::OutPoint};
use rusqlite::{Connection, ErrorCode, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::Path,
    time::Duration,
};

pub use crate::outbox::MAX_RECORD_BYTES;

/// SQLite `application_id` of an outbox database ("MUOB").
pub const APPLICATION_ID: i64 = 0x4d55_4f42;
/// Schema version stored in `user_version`.
pub const SCHEMA_VERSION: i64 = 1;
/// How long a commit waits for another process that holds the database before it refuses with
/// [`Refusal::OutboxBusy`].
pub const DEFAULT_BUSY_TIMEOUT: Duration = Duration::from_secs(5);

const SCHEMA: [(&str, &str); 3] = [
    (
        "outbox_context_v1",
        "CREATE TABLE outbox_context_v1(id INTEGER PRIMARY KEY CHECK(id=1),network INTEGER NOT NULL,genesis BLOB NOT NULL CHECK(length(genesis)=32),fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32))",
    ),
    (
        "outbox_inputs_v1",
        "CREATE TABLE outbox_inputs_v1(txid BLOB NOT NULL CHECK(length(txid)=32),idx INTEGER NOT NULL CHECK(idx BETWEEN 0 AND 4294967295),record BLOB NOT NULL REFERENCES outbox_records_v1(id),PRIMARY KEY(txid,idx))",
    ),
    (
        "outbox_records_v1",
        "CREATE TABLE outbox_records_v1(id BLOB PRIMARY KEY CHECK(length(id)=32),kind INTEGER NOT NULL CHECK(kind BETWEEN 1 AND 255),raw BLOB NOT NULL CHECK(length(raw) BETWEEN 1 AND 65536),meta BLOB NOT NULL CHECK(length(meta) BETWEEN 1 AND 65536),status INTEGER NOT NULL CHECK(status BETWEEN 0 AND 4),status_height INTEGER NOT NULL CHECK(status_height>=0),checksum BLOB NOT NULL CHECK(length(checksum)=32))",
    ),
];

/// What a crash-safety test may watch in [`Outbox::replace_partial`]: called with the name of each
/// step as it is reached ("partial-removed" and "complete-inserted" inside the transaction,
/// "committed" after it). Only `SqliteOutbox::observe_replacement_for_test`, which exists in test
/// builds only, can set one; a shipping outbox never has an observer.
type Observer = Option<fn(&'static str)>;

fn reached(observer: Observer, step: &'static str) {
    if let Some(observer) = observer {
        observer(step);
    }
}

const STATUS_QUEUED: i64 = 0;
const STATUS_CONFIRMED: i64 = 1;
const STATUS_EXPIRED: i64 = 2;
const STATUS_INPUTS_SPENT: i64 = 3;
const STATUS_FORGOTTEN: i64 = 4;

/// Map a storage error: a full disk is its own refusal, a busy database is retryable, a file that
/// cannot be opened is a location problem, a violated reservation key means the coin is already
/// reserved, everything else is an integrity failure of the store.
fn storage(error: rusqlite::Error) -> Refusal {
    match &error {
        rusqlite::Error::SqliteFailure(failure, _) => match failure.code {
            ErrorCode::DiskFull => Refusal::OutboxFull,
            ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => Refusal::OutboxBusy,
            ErrorCode::CannotOpen => Refusal::OutboxLocation,
            ErrorCode::ConstraintViolation => Refusal::ReservedInput,
            _ => Refusal::OutboxIntegrity,
        },
        _ => Refusal::OutboxIntegrity,
    }
}

/// A durable outbox lives in a regular file at a real path. SQLite gives a few names a different
/// meaning: the empty name is a temporary database that vanishes on close, `:memory:` is a database
/// in memory, and (when URIs are enabled) `file:` names a URI. None of them is durable, so none is
/// accepted; URIs are not enabled when the file is opened either.
fn check_location(path: &Path) -> Result<(), Refusal> {
    let name = path.as_os_str();
    if name.is_empty() || name == ":memory:" || name.to_string_lossy().starts_with("file:") {
        return Err(Refusal::OutboxLocation);
    }
    Ok(())
}

struct Row {
    id: Vec<u8>,
    kind: i64,
    raw: Vec<u8>,
    meta: Vec<u8>,
    status: i64,
    status_height: i64,
    checksum: Vec<u8>,
}

const COLUMNS: &str = "id,kind,raw,meta,status,status_height,checksum";

fn read_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Row> {
    Ok(Row {
        id: row.get(0)?,
        kind: row.get(1)?,
        raw: row.get(2)?,
        meta: row.get(3)?,
        status: row.get(4)?,
        status_height: row.get(5)?,
        checksum: row.get(6)?,
    })
}

fn hash_of(raw: &[u8]) -> Result<Hash, Refusal> {
    raw.try_into().map_err(|_| Refusal::OutboxIntegrity)
}

/// Rebuild and verify a record from its row.
fn to_record(row: Row) -> Result<OutboxRecord, Refusal> {
    let id = hash_of(&row.id)?;
    let kind = u16::try_from(row.kind)
        .ok()
        .and_then(OperationKind::from_code)
        .ok_or(Refusal::OutboxIntegrity)?;
    if row.raw.is_empty() || row.raw.len() > MAX_RECORD_BYTES {
        return Err(Refusal::OutboxIntegrity);
    }
    let meta = OutboxRecord::decode_meta(&row.meta)?;
    let height = u64::try_from(row.status_height).map_err(|_| Refusal::OutboxIntegrity)?;
    let status = match row.status {
        STATUS_QUEUED => OutboxStatus::Queued,
        STATUS_CONFIRMED => OutboxStatus::Confirmed(height),
        STATUS_EXPIRED => OutboxStatus::Expired,
        STATUS_INPUTS_SPENT if height == 0 => OutboxStatus::InputsSpent,
        STATUS_INPUTS_SPENT => OutboxStatus::Stranded(height),
        STATUS_FORGOTTEN => OutboxStatus::Forgotten,
        _ => return Err(Refusal::OutboxIntegrity),
    };
    let record = OutboxRecord::from_stored(
        id,
        kind,
        row.raw,
        meta.complete,
        meta.missing,
        meta.validity,
        meta.reserved,
        meta.queued_at,
        status,
        hash_of(&row.checksum)?,
    )
    .with_approval(meta.approval);
    record.verify()?;
    Ok(record)
}

fn status_columns(status: OutboxStatus) -> (i64, i64) {
    match status {
        OutboxStatus::Queued => (STATUS_QUEUED, 0),
        OutboxStatus::Confirmed(height) => {
            (STATUS_CONFIRMED, i64::try_from(height).unwrap_or(i64::MAX))
        }
        OutboxStatus::Expired => (STATUS_EXPIRED, 0),
        OutboxStatus::InputsSpent => (STATUS_INPUTS_SPENT, 0),
        OutboxStatus::Stranded(height) => (
            STATUS_INPUTS_SPENT,
            i64::try_from(height).unwrap_or(i64::MAX),
        ),
        OutboxStatus::Forgotten => (STATUS_FORGOTTEN, 0),
    }
}

/// The record `id`, re-verified, if there is one.
fn record_by_id(db: &Connection, id: &Hash) -> Result<Option<OutboxRecord>, Refusal> {
    db.query_row(
        &format!("SELECT {COLUMNS} FROM outbox_records_v1 WHERE id=?1"),
        [id.as_slice()],
        read_row,
    )
    .optional()
    .map_err(storage)?
    .map(to_record)
    .transpose()
}

/// Insert an open record and one reservation row per coin or resource it holds.
fn insert_open(db: &Connection, record: &OutboxRecord) -> Result<(), Refusal> {
    let (status, status_height) = status_columns(OutboxStatus::Queued);
    db.execute(
        "INSERT INTO outbox_records_v1(id,kind,raw,meta,status,status_height,checksum) VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![
            record.id.as_slice(),
            i64::from(record.kind.code()),
            record.bytes,
            record.meta_bytes(),
            status,
            status_height,
            record.checksum().as_slice()
        ],
    )
    .map_err(storage)?;
    for point in &record.reserved {
        db.execute(
            "INSERT INTO outbox_inputs_v1(txid,idx,record) VALUES(?1,?2,?3)",
            params![
                point.transaction.as_slice(),
                i64::from(point.index),
                record.id.as_slice()
            ],
        )
        .map_err(storage)?;
    }
    Ok(())
}

/// Every record, re-verified, with the reservation table cross-checked against the open records.
fn load_all(db: &Connection) -> Result<Vec<OutboxRecord>, Refusal> {
    let mut statement = db
        .prepare(&format!(
            "SELECT {COLUMNS} FROM outbox_records_v1 ORDER BY id"
        ))
        .map_err(storage)?;
    let rows = statement.query_map([], read_row).map_err(storage)?;
    let mut records = Vec::new();
    for row in rows {
        records.push(to_record(row.map_err(storage)?)?);
    }
    let mut reservations: BTreeMap<Hash, BTreeSet<OutPoint>> = BTreeMap::new();
    let mut statement = db
        .prepare("SELECT record,txid,idx FROM outbox_inputs_v1")
        .map_err(storage)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(storage)?;
    for row in rows {
        let (record, txid, index) = row.map_err(storage)?;
        reservations
            .entry(hash_of(&record)?)
            .or_default()
            .insert(OutPoint {
                transaction: hash_of(&txid)?,
                index: u32::try_from(index).map_err(|_| Refusal::OutboxIntegrity)?,
            });
    }
    for record in &records {
        let held = reservations.remove(&record.id).unwrap_or_default();
        let expected: BTreeSet<OutPoint> = if record.status.is_open() {
            record.reserved.iter().cloned().collect()
        } else {
            BTreeSet::new()
        };
        if held != expected {
            return Err(Refusal::OutboxIntegrity);
        }
    }
    if !reservations.is_empty() {
        return Err(Refusal::OutboxIntegrity);
    }
    Ok(records)
}

/// Durable outbox in a SQLite file.
pub struct SqliteOutbox {
    db: Connection,
    context: ChainContext,
    max_records: usize,
    max_bytes: usize,
    max_settled: usize,
    observer: Observer,
}

impl SqliteOutbox {
    pub const DEFAULT_MAX_RECORDS: usize = 4096;
    pub const DEFAULT_MAX_BYTES: usize = 16 * 1024 * 1024;

    /// Open (creating if the file is new or empty) the outbox at `path` for the chain `context`.
    /// `path` must name a regular file: the empty name, `:memory:` and `file:` names are refused
    /// with [`Refusal::OutboxLocation`] because none of them is durable.
    pub fn open(path: &Path, context: ChainContext) -> Result<Self, Refusal> {
        Self::open_with_limits(
            path,
            context,
            Self::DEFAULT_MAX_RECORDS,
            Self::DEFAULT_MAX_BYTES,
        )
    }

    /// [`Self::open`] with limits on the number and total size of OPEN records.
    pub fn open_with_limits(
        path: &Path,
        context: ChainContext,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<Self, Refusal> {
        check_location(path)?;
        // Read-write, create if missing, no URI interpretation of the name.
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(storage)?;
        // Durable before success: a commit returns only after the data is on disk.
        db.pragma_update(None, "synchronous", "FULL")
            .map_err(storage)?;
        db.pragma_update(None, "foreign_keys", "ON")
            .map_err(storage)?;
        // Another process may hold the write lock briefly: wait for it instead of failing at once.
        db.busy_timeout(DEFAULT_BUSY_TIMEOUT).map_err(storage)?;
        let objects: i64 = db
            .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
            .map_err(storage)?;
        if objects == 0 {
            let transaction = db.unchecked_transaction().map_err(storage)?;
            transaction
                .pragma_update(None, "application_id", APPLICATION_ID)
                .map_err(storage)?;
            transaction
                .pragma_update(None, "user_version", SCHEMA_VERSION)
                .map_err(storage)?;
            for (_, sql) in SCHEMA {
                transaction.execute(sql, []).map_err(storage)?;
            }
            transaction
                .execute(
                    "INSERT INTO outbox_context_v1(id,network,genesis,fingerprint) VALUES(1,?1,?2,?3)",
                    params![i64::from(context.network), context.genesis.as_slice(), context.fingerprint.as_slice()],
                )
                .map_err(storage)?;
            transaction.commit().map_err(storage)?;
        }
        let outbox = Self {
            db,
            context,
            max_records,
            max_bytes,
            max_settled: DEFAULT_MAX_SETTLED,
            observer: None,
        };
        outbox.validate()?;
        Ok(outbox)
    }

    /// Exact-schema, context and integrity validation. Runs on every open.
    fn validate(&self) -> Result<(), Refusal> {
        let db = &self.db;
        let application: i64 = db
            .query_row("PRAGMA application_id", [], |row| row.get(0))
            .map_err(storage)?;
        let version: i64 = db
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(storage)?;
        if application != APPLICATION_ID || version != SCHEMA_VERSION {
            return Err(Refusal::OutboxIntegrity);
        }
        // Only the indexes SQLite itself creates for PRIMARY KEY constraints (they have no SQL text)
        // are skipped; every other object, whatever it is called, makes the file unacceptable.
        let mut statement = db
            .prepare("SELECT type,name,sql FROM sqlite_master WHERE NOT (type='index' AND sql IS NULL AND name GLOB 'sqlite_autoindex_*') ORDER BY name")
            .map_err(storage)?;
        let found: Vec<(String, String, Option<String>)> = statement
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
            .map_err(storage)?
            .collect::<Result<_, _>>()
            .map_err(storage)?;
        let expected: Vec<(String, String, Option<String>)> = SCHEMA
            .iter()
            .map(|(name, sql)| {
                (
                    "table".to_string(),
                    (*name).to_string(),
                    Some((*sql).to_string()),
                )
            })
            .collect();
        if found != expected {
            return Err(Refusal::OutboxIntegrity);
        }
        let stored: (i64, Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT network,genesis,fingerprint FROM outbox_context_v1 WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .map_err(storage)?;
        let theirs = ChainContext {
            network: u32::try_from(stored.0).map_err(|_| Refusal::OutboxIntegrity)?,
            genesis: hash_of(&stored.1)?,
            fingerprint: hash_of(&stored.2)?,
        };
        if theirs != self.context {
            return Err(context_refusal(&self.context, &theirs));
        }
        let check: String = db
            .query_row("PRAGMA quick_check(1)", [], |row| row.get(0))
            .map_err(storage)?;
        if check != "ok" {
            return Err(Refusal::OutboxIntegrity);
        }
        load_all(db).map(|_| ())
    }

    pub fn context(&self) -> &ChainContext {
        &self.context
    }

    /// How long a write waits for another process that holds the database (default 5 s).
    pub fn set_busy_timeout(&self, timeout: Duration) -> Result<(), Refusal> {
        self.db.busy_timeout(timeout).map_err(storage)
    }

    /// How many settled records reconciliation keeps as history (default
    /// [`DEFAULT_MAX_SETTLED`]).
    pub fn set_max_settled(&mut self, keep: usize) {
        self.max_settled = keep;
    }

    /// Test builds only: call `observer` with the name of each step of
    /// [`Outbox::replace_partial`] as it is reached, so a crash-safety test can end the process
    /// between the steps.
    #[cfg(any(test, feature = "test-value-signing"))]
    pub fn observe_replacement_for_test(&mut self, observer: fn(&'static str)) {
        self.observer = Some(observer);
    }
}

/// Delete settled records beyond the `keep` most recently queued (insertion order is the row id).
/// Settled records hold no reservation rows, so nothing else refers to them.
fn prune(db: &Connection, keep: usize) -> Result<usize, Refusal> {
    let keep = i64::try_from(keep).unwrap_or(i64::MAX);
    db.execute(
        "DELETE FROM outbox_records_v1 WHERE status<>0 AND rowid NOT IN (SELECT rowid FROM outbox_records_v1 WHERE status<>0 ORDER BY rowid DESC LIMIT ?1)",
        [keep],
    )
    .map_err(storage)
}

impl fmt::Debug for SqliteOutbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SqliteOutbox")
            .field("context", &self.context)
            .field("max_records", &self.max_records)
            .field("max_bytes", &self.max_bytes)
            .field("max_settled", &self.max_settled)
            .finish()
    }
}

impl SqliteOutbox {
    /// `commit` and `commit_approved` in one: `approval` is `None` for a plain commit.
    fn commit_with(
        &mut self,
        signed: &SignedOperation,
        approval: Option<ApprovalBinding>,
        view: &ChainView<'_>,
    ) -> Result<Hash, Refusal> {
        if view.context() != self.context {
            return Err(context_refusal(&self.context, &view.context()));
        }
        // The identifier is the one the BYTES commit to, never the caller's claim.
        let described = describe_checked(signed)?;
        let id = described.id;
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        // Idempotent while the record is open: the same bytes again change nothing. A settled or
        // forgotten record is replaced by a fresh admission, which consensus refuses when the
        // operation can no longer be included (a confirmed or expired one is never reported as
        // queued); the delete is rolled back with everything else when admission refuses.
        let existing = transaction
            .query_row(
                &format!("SELECT {COLUMNS} FROM outbox_records_v1 WHERE id=?1"),
                [id.as_slice()],
                read_row,
            )
            .optional()
            .map_err(storage)?;
        if let Some(row) = existing {
            let record = to_record(row)?;
            if record.bytes != signed.bytes() {
                return Err(Refusal::OutboxIntegrity);
            }
            if record.status.is_open() {
                if approval.is_some() && record.approval() != approval.as_ref() {
                    return Err(Refusal::ApprovalBindingMismatch(
                        "the operation is already queued under another approval binding",
                    ));
                }
                return Ok(id);
            }
            transaction
                .execute("DELETE FROM outbox_records_v1 WHERE id=?1", [id.as_slice()])
                .map_err(storage)?;
        }
        // Independent verification through consensus code, inside the write lock.
        let record = admit_described(signed, described, view, approval)?;
        // Only OPEN records count: settled records are history.
        let (count, total): (i64, i64) = transaction
            .query_row(
                "SELECT count(*),COALESCE(SUM(length(raw)),0) FROM outbox_records_v1 WHERE status=0",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(storage)?;
        let total = usize::try_from(total).map_err(|_| Refusal::OutboxIntegrity)?;
        if usize::try_from(count).map_err(|_| Refusal::OutboxIntegrity)? >= self.max_records
            || total
                .checked_add(record.bytes.len())
                .is_none_or(|sum| sum > self.max_bytes)
        {
            return Err(Refusal::OutboxFull);
        }
        for point in &record.reserved {
            let held: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM outbox_inputs_v1 WHERE txid=?1 AND idx=?2)",
                    params![point.transaction.as_slice(), i64::from(point.index)],
                    |row| row.get(0),
                )
                .map_err(storage)?;
            if held {
                return Err(Refusal::ReservedInput);
            }
        }
        insert_open(&transaction, &record)?;
        transaction.commit().map_err(storage)?;
        Ok(id)
    }

    /// Test builds only: rewrite a stored record and recompute its (unkeyed) checksum, as someone
    /// who can rewrite the file could (W6 export tests). The identifier and the status stay.
    #[cfg(any(test, feature = "test-value-signing"))]
    pub fn rewrite_for_test(&mut self, id: &Hash, edit: impl FnOnce(&mut OutboxRecord)) {
        let mut record = record_by_id(&self.db, id)
            .expect("a readable store")
            .expect("the record exists");
        edit(&mut record);
        record.rechecksum_for_test();
        self.db
            .execute(
                "UPDATE outbox_records_v1 SET raw=?1,meta=?2,checksum=?3 WHERE id=?4",
                params![
                    record.bytes,
                    record.meta_bytes(),
                    record.checksum().as_slice(),
                    id.as_slice()
                ],
            )
            .expect("the rewrite is stored");
    }
}

impl Outbox for SqliteOutbox {
    fn commit(&mut self, signed: &SignedOperation, view: &ChainView<'_>) -> Result<Hash, Refusal> {
        self.commit_with(signed, None, view)
    }

    fn commit_approved(
        &mut self,
        signed: &SignedOperation,
        approval: &ApprovalBinding,
        view: &ChainView<'_>,
    ) -> Result<Hash, Refusal> {
        self.commit_with(signed, Some(approval.clone()), view)
    }

    fn export_verified(&self, id: &Hash, view: &ChainView<'_>) -> Result<VerifiedExport, Refusal> {
        // A view of another chain is refused before anything else.
        if view.context() != self.context {
            return Err(context_refusal(&self.context, &view.context()));
        }
        let record = self.get(id)?.ok_or(Refusal::UnknownOperation)?;
        crate::export::verify_record(&record, view)
    }

    fn replace_partial(
        &mut self,
        partial: &Hash,
        complete: &SignedOperation,
        view: &ChainView<'_>,
    ) -> Result<Hash, Refusal> {
        if view.context() != self.context {
            return Err(context_refusal(&self.context, &view.context()));
        }
        // The identifier is the one the BYTES commit to, never the caller's claim.
        let described = describe_checked(complete)?;
        let id = described.id;
        let observer = self.observer;
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        // Idempotent: the complete record is already queued (a retry after success). Other bytes
        // under its identifier are refused, unless that record is the partial itself.
        if let Some(existing) = record_by_id(&transaction, &id)? {
            if existing.bytes == complete.bytes() {
                if existing.status.is_open() {
                    return Ok(id);
                }
            } else if id != *partial {
                return Err(Refusal::OutboxIntegrity);
            }
        }
        let old = record_by_id(&transaction, partial)?.ok_or(Refusal::UnknownOperation)?;
        // Independent verification through consensus code, inside the write lock.
        let record = admit_replacement(&old, complete, described, view)?;
        // One open record takes the place of another: only the total size can grow.
        let total: i64 = transaction
            .query_row(
                "SELECT COALESCE(SUM(length(raw)),0) FROM outbox_records_v1 WHERE status=0 AND id<>?1",
                [partial.as_slice()],
                |row| row.get(0),
            )
            .map_err(storage)?;
        let total = usize::try_from(total).map_err(|_| Refusal::OutboxIntegrity)?;
        if total
            .checked_add(record.bytes.len())
            .is_none_or(|sum| sum > self.max_bytes)
        {
            return Err(Refusal::OutboxFull);
        }
        // Nothing else may hold what the replacement takes over (the partial held it alone; the
        // primary key of the reservation table enforces it as well).
        for point in &record.reserved {
            let held: bool = transaction
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM outbox_inputs_v1 WHERE txid=?1 AND idx=?2 AND record<>?3)",
                    params![
                        point.transaction.as_slice(),
                        i64::from(point.index),
                        partial.as_slice()
                    ],
                    |row| row.get(0),
                )
                .map_err(storage)?;
            if held {
                return Err(Refusal::ReservedInput);
            }
        }
        // The swap, inside this one transaction: the partial's rows go (with a settled record of
        // the same bytes under the complete identifier, which a commit would replace as well), then
        // the complete record's rows come.
        transaction
            .execute(
                "DELETE FROM outbox_inputs_v1 WHERE record=?1",
                [partial.as_slice()],
            )
            .map_err(storage)?;
        transaction
            .execute(
                "DELETE FROM outbox_records_v1 WHERE id=?1 OR id=?2",
                params![partial.as_slice(), id.as_slice()],
            )
            .map_err(storage)?;
        reached(observer, "partial-removed");
        insert_open(&transaction, &record)?;
        reached(observer, "complete-inserted");
        transaction.commit().map_err(storage)?;
        reached(observer, "committed");
        Ok(id)
    }

    fn records(&self) -> Result<Vec<OutboxRecord>, Refusal> {
        load_all(&self.db)
    }

    fn get(&self, id: &Hash) -> Result<Option<OutboxRecord>, Refusal> {
        // Cross-checks run over the whole table, so a damaged neighbour is also reported.
        Ok(load_all(&self.db)?
            .into_iter()
            .find(|record| record.id == *id))
    }

    fn reconcile(&mut self, view: &ChainView<'_>) -> Result<ReconcileReport, Refusal> {
        if view.context() != self.context {
            return Err(context_refusal(&self.context, &view.context()));
        }
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let mut report = ReconcileReport::default();
        for record in load_all(&transaction)? {
            if !record.status.is_open() {
                continue;
            }
            let next = match settle(&record, view)? {
                Settlement::Pending => {
                    report.still_pending += 1;
                    continue;
                }
                Settlement::Confirmed(height) => {
                    report.confirmed += 1;
                    OutboxStatus::Confirmed(height)
                }
                Settlement::Expired => {
                    report.expired += 1;
                    OutboxStatus::Expired
                }
                Settlement::InputsSpent => {
                    report.inputs_spent += 1;
                    OutboxStatus::InputsSpent
                }
                Settlement::Stranded(height) => {
                    report.stranded += 1;
                    OutboxStatus::Stranded(height)
                }
            };
            let (status, status_height) = status_columns(next);
            transaction
                .execute(
                    "UPDATE outbox_records_v1 SET status=?1,status_height=?2 WHERE id=?3",
                    params![status, status_height, record.id.as_slice()],
                )
                .map_err(storage)?;
            transaction
                .execute(
                    "DELETE FROM outbox_inputs_v1 WHERE record=?1",
                    [record.id.as_slice()],
                )
                .map_err(storage)?;
        }
        report.pruned = prune(&transaction, self.max_settled)?;
        transaction.commit().map_err(storage)?;
        Ok(report)
    }

    fn forget(&mut self, id: &Hash) -> Result<(), Refusal> {
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let record = load_all(&transaction)?
            .into_iter()
            .find(|record| record.id == *id)
            .ok_or(Refusal::UnknownOperation)?;
        if record.status.is_open() {
            let (status, status_height) = status_columns(OutboxStatus::Forgotten);
            transaction
                .execute(
                    "UPDATE outbox_records_v1 SET status=?1,status_height=?2 WHERE id=?3",
                    params![status, status_height, id.as_slice()],
                )
                .map_err(storage)?;
            transaction
                .execute(
                    "DELETE FROM outbox_inputs_v1 WHERE record=?1",
                    [id.as_slice()],
                )
                .map_err(storage)?;
        }
        transaction.commit().map_err(storage)?;
        Ok(())
    }

    fn prune_settled(&mut self, keep: usize) -> Result<usize, Refusal> {
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        // Read everything first, so a damaged store is reported instead of trimmed.
        load_all(&transaction)?;
        let pruned = prune(&transaction, keep)?;
        transaction.commit().map_err(storage)?;
        Ok(pruned)
    }
}
