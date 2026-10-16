//! Atomic whole-voter snapshots anchored by a TPM monotonic NV counter.
//! Unlike an extend index, deleting/redefining a counter cannot repeat an old
//! value. All safety-critical voter state must share this snapshot, never a
//! separately rollbackable lock/journal database. This is local storage only.
use crate::Hash;
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::path::Path;

const MAX_SNAPSHOT: usize = 4 * 1024 * 1024;
// Preserve the deployed local format; no migration or TPM operation is implied.
const SCHEMA: &str = "CREATE TABLE voter_snapshot(id INTEGER PRIMARY KEY CHECK(id=1),context BLOB NOT NULL,tip BLOB NOT NULL,snapshot BLOB NOT NULL,pending BLOB)";
fn schema(db: &Connection) -> Result<()> {
    let count: i64 = db.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
    let app: i64 = db.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if count != 1 || app != 0 || version != 0 {
        return Err(CounterError::Invalid);
    }
    let exact: bool = db.query_row(
        "SELECT type='table' AND tbl_name='voter_snapshot' AND sql=?1 FROM sqlite_schema WHERE name='voter_snapshot'",
        [SCHEMA], |r| r.get(0),
    ).optional()?.unwrap_or(false);
    if !exact {
        return Err(CounterError::Invalid);
    }
    Ok(())
}
fn blob(
    row: &rusqlite::Row<'_>,
    column: usize,
    min: usize,
    max: usize,
) -> rusqlite::Result<Vec<u8>> {
    match row.get_ref(column)? {
        rusqlite::types::ValueRef::Blob(bytes) if (min..=max).contains(&bytes.len()) => {
            Ok(bytes.to_vec())
        }
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}
fn context(db: &Connection, expected: &Hash, allow_empty: bool) -> Result<bool> {
    schema(db)?;
    let count: i64 = db.query_row("SELECT count(*) FROM voter_snapshot", [], |r| r.get(0))?;
    if count == 0 && allow_empty {
        return Ok(false);
    }
    if count != 1 {
        return Err(CounterError::Invalid);
    }
    let actual = db
        .query_row("SELECT context FROM voter_snapshot WHERE id=1", [], |r| {
            blob(r, 0, 32, 32)
        })
        .optional()?;
    if actual.as_deref() != Some(expected.as_slice()) {
        return Err(CounterError::Context);
    }
    Ok(true)
}
fn state(db: &Connection, expected: &Hash) -> Result<(Vec<u8>, Vec<u8>, Option<Vec<u8>>)> {
    context(db, expected, false)?;
    Ok(db.query_row(
        "SELECT tip,snapshot,pending FROM voter_snapshot WHERE id=1",
        [],
        |r| {
            let pending = match r.get_ref(2)? {
                rusqlite::types::ValueRef::Null => None,
                _ => Some(blob(r, 2, 1, MAX_SNAPSHOT)?),
            };
            Ok((blob(r, 0, 8, 8)?, blob(r, 1, 1, MAX_SNAPSHOT)?, pending))
        },
    )?)
}
#[derive(Debug)]
pub enum CounterError {
    Storage(rusqlite::Error),
    Backend,
    Invalid,
    Context,
    Rollback,
    StaleWriter,
    Overflow,
}
impl From<rusqlite::Error> for CounterError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e)
    }
}
type Result<T> = std::result::Result<T, CounterError>;

/// A pinned non-orderly TPM NV counter. A backend must own an exclusive host
/// lock across this store's entire lifetime, including all signing operations.
/// Index/key metadata are pinned by the supervised initialization manifest.
/// Missing/unwritten/redefined indices and NV failures never trigger repair.
/// TPM clear invalidates the storage-hierarchy voting key and requires recovery.
pub trait MonotonicCounter {
    fn read(&mut self) -> std::result::Result<u64, String>;
    fn increment(&mut self) -> std::result::Result<(), String>;
}
pub struct CounterStore {
    db: Connection,
    tip: u64,
    snapshot: Vec<u8>,
    context: Hash,
}
impl CounterStore {
    /// Initialization is explicit and allowed only at the pinned ceremony
    /// counter value. Passing None can never recreate a missing database.
    pub fn open(
        path: &Path,
        context: Hash,
        initial: Option<(u64, &[u8])>,
        counter: &mut impl MonotonicCounter,
    ) -> Result<Self> {
        let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        if initial.is_some() {
            flags |= OpenFlags::SQLITE_OPEN_CREATE;
        }
        let mut db = Connection::open_with_flags(path, flags)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(
            "PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;",
        )?;
        let t = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let objects: i64 = t.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
        if objects == 0 {
            // Opening without explicit initialization cannot create a store.
            if initial.is_none() {
                return Err(CounterError::Rollback);
            }
            t.execute_batch(SCHEMA)?;
        }
        if !self::context(&t, &context, true)? {
            let (tip, snapshot) = initial.ok_or(CounterError::Rollback)?;
            valid(snapshot)?;
            if counter.read().map_err(|_| CounterError::Backend)? != tip {
                return Err(CounterError::Rollback);
            }
            t.execute(
                "INSERT INTO voter_snapshot VALUES(1,?1,?2,?3,NULL)",
                params![context.as_slice(), tip.to_be_bytes().as_slice(), snapshot],
            )?;
        }
        t.commit()?;
        let mut store = Self {
            db,
            tip: 0,
            snapshot: Vec::new(),
            context,
        };
        store.recover(counter)?;
        Ok(store)
    }
    pub fn snapshot(&self) -> &[u8] {
        &self.snapshot
    }
    pub fn counter_value(&self) -> u64 {
        self.tip
    }
    fn recover(&mut self, counter: &mut impl MonotonicCounter) -> Result<()> {
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (raw, snapshot, pending) = state(&t, &self.context)?;
        let tip = u64::from_be_bytes(raw.try_into().map_err(|_| CounterError::Invalid)?);
        valid(&snapshot)?;
        let hardware = counter.read().map_err(|_| CounterError::Backend)?;
        let (tip, snapshot) = if let Some(next_snapshot) = pending {
            valid(&next_snapshot)?;
            let next = tip.checked_add(1).ok_or(CounterError::Overflow)?;
            if hardware == tip {
                counter.increment().map_err(|_| CounterError::Backend)?;
            } else if hardware != next {
                return Err(CounterError::Rollback);
            }
            if counter.read().map_err(|_| CounterError::Backend)? != next {
                return Err(CounterError::Rollback);
            }
            t.execute(
                "UPDATE voter_snapshot SET tip=?1,snapshot=?2,pending=NULL WHERE id=1",
                params![next.to_be_bytes().as_slice(), &next_snapshot],
            )?;
            (next, next_snapshot)
        } else {
            if hardware != tip {
                return Err(CounterError::Rollback);
            }
            (tip, snapshot)
        };
        t.commit()?;
        self.tip = tip;
        self.snapshot = snapshot;
        Ok(())
    }
    /// Durable intent, hardware advance, then durable installation. An error
    /// poisons this caller operationally: reopen and recover before any signing.
    pub fn commit(&mut self, next: &[u8], counter: &mut impl MonotonicCounter) -> Result<()> {
        valid(next)?;
        self.tip.checked_add(1).ok_or(CounterError::Overflow)?;
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (tip, snapshot, pending) = state(&t, &self.context)?;
        if tip != self.tip.to_be_bytes() || snapshot != self.snapshot || pending.is_some() {
            return Err(CounterError::StaleWriter);
        }
        if counter.read().map_err(|_| CounterError::Backend)? != self.tip {
            return Err(CounterError::Rollback);
        }
        if next == snapshot {
            return Ok(());
        }
        t.execute("UPDATE voter_snapshot SET pending=?1 WHERE id=1", [next])?;
        t.commit()?;
        self.recover(counter)
    }
    /// Check again immediately before invoking the TPM signing command. The
    /// host-wide backend lock excludes another process using a cloned database.
    pub fn verify_current(&mut self, counter: &mut impl MonotonicCounter) -> Result<()> {
        let t = self.db.transaction()?;
        let (tip, snapshot, pending) = state(&t, &self.context)?;
        if pending.is_some() || tip != self.tip.to_be_bytes() || snapshot != self.snapshot {
            return Err(CounterError::StaleWriter);
        }
        if counter.read().map_err(|_| CounterError::Backend)? != self.tip {
            return Err(CounterError::Rollback);
        }
        t.commit()?;
        Ok(())
    }
}
fn valid(snapshot: &[u8]) -> Result<()> {
    if snapshot.is_empty() || snapshot.len() > MAX_SNAPSHOT {
        Err(CounterError::Invalid)
    } else {
        Ok(())
    }
}
