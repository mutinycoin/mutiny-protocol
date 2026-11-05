//! Hybrid voter snapshots with atomic, counter-bound generation migration.
//! The distinct schema rejects old journals; no deployed journal is converted.
//! The caller must authenticate context/predecessor from finalized history,
//! validate snapshot semantics, and retain the exclusive physical-counter lock.
use crate::Hash;
pub use crate::counter_store::{CounterError, MonotonicCounter};
use CounterError as Error;
use MonotonicCounter as Counter;
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use std::path::Path;
pub const MAX_SNAPSHOT: usize = 4 * 1024 * 1024;
const SCHEMA: &str = "CREATE TABLE voter_migration(id INTEGER PRIMARY KEY CHECK(id=1),context BLOB NOT NULL,tip BLOB NOT NULL,snapshot BLOB NOT NULL,pending_context BLOB,pending_snapshot BLOB)";
#[cfg(test)]
thread_local! {static FAULT:std::cell::Cell<u8>=const {std::cell::Cell::new(0)};}
#[cfg(test)]
thread_local! {static CRASH:std::cell::Cell<u8>=const {std::cell::Cell::new(0)};}
#[cfg(test)]
fn fault(point: u8) -> Result<()> {
    if CRASH.with(|f| f.get() == point) {
        std::process::exit(91);
    }
    if FAULT.with(|f| {
        if f.get() == point {
            f.set(0);
            true
        } else {
            false
        }
    }) {
        Err(Error::Backend)
    } else {
        Ok(())
    }
}
type Result<T> = std::result::Result<T, Error>;
fn valid(context: Hash, bytes: &[u8]) -> Result<()> {
    if context == [0; 32] || bytes.is_empty() || bytes.len() > MAX_SNAPSHOT {
        return Err(Error::Invalid);
    }
    Ok(())
}
fn schema(db: &Connection) -> Result<()> {
    let count: u64 = db.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
    if count!=1{return Err(Error::Invalid);}
    let app: i64 = db.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
    if app!=0||version!=0{return Err(Error::Invalid);}
    // Exact borrowed SQLite text comparison. An arbitrary stored definition
    // never becomes an owned String before this fixed-schema check.
    let exact:bool=db.query_row("SELECT sql FROM sqlite_schema WHERE name='voter_migration' AND type='table' AND tbl_name='voter_migration'",[],|r|{
        Ok(matches!(r.get_ref(0)?,rusqlite::types::ValueRef::Text(raw) if raw==SCHEMA.as_bytes()))
    })?;
    if !exact{return Err(Error::Invalid);}Ok(())
}
fn blob(r: &rusqlite::Row<'_>, i: usize, min: usize, max: usize) -> rusqlite::Result<Vec<u8>> {
    match r.get_ref(i)? {
        rusqlite::types::ValueRef::Blob(v) if (min..=max).contains(&v.len()) => Ok(v.to_vec()),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Row {
    context: Hash,
    tip: u64,
    snapshot: Vec<u8>,
    pending: Option<(Hash, Vec<u8>)>,
}
fn row(db: &Connection) -> Result<Row> {
    schema(db)?;
    let count: u64 = db.query_row("SELECT count(*) FROM voter_migration", [], |r| r.get(0))?;
    if count != 1 {
        return Err(Error::Invalid);
    }
    let value=db.query_row("SELECT context,tip,snapshot,pending_context,pending_snapshot FROM voter_migration WHERE id=1",[],|r|{
        let pending=match (r.get_ref(3)?,r.get_ref(4)?) {
            (rusqlite::types::ValueRef::Null,rusqlite::types::ValueRef::Null)=>None,
            (rusqlite::types::ValueRef::Blob(_),rusqlite::types::ValueRef::Blob(_))=>Some((blob(r,3,32,32)?.try_into().unwrap(),blob(r,4,1,MAX_SNAPSHOT)?)),
            _=>return Err(rusqlite::Error::InvalidQuery),
        };
        Ok(Row{context:blob(r,0,32,32)?.try_into().unwrap(),tip:u64::from_be_bytes(blob(r,1,8,8)?.try_into().unwrap()),snapshot:blob(r,2,1,MAX_SNAPSHOT)?,pending})
    })?;
    valid(value.context, &value.snapshot)?;
    if let Some((ctx, bytes)) = &value.pending {
        valid(*ctx, bytes)?;
    }
    Ok(value)
}
pub struct CounterStore {
    db: Connection,
    current: Row,
    poisoned: bool,
}
/// Refused existing-only V2 construction retains the exact supplied connection
/// or post-recovery store. Generic SQLite ownership grants no native authority.
pub struct ExistingCounterRefusal {cause:Error,custody:ExistingCounterCustody}
pub enum ExistingCounterCustody {
    Connection(std::mem::ManuallyDrop<Connection>),
    Counter(std::mem::ManuallyDrop<CounterStore>),
}
impl ExistingCounterRefusal {
    pub fn cause(&self)->&CounterError{&self.cause}
    pub fn into_retained(self)->(CounterError,ExistingCounterCustody){(self.cause,self.custody)}
}
pub struct ExistingCounterCloseRefusal {cause:Error,custody:ExistingCounterCustody}
impl ExistingCounterCloseRefusal {
    pub fn cause(&self)->&CounterError{&self.cause}
    pub fn into_retained(self)->(CounterError,ExistingCounterCustody){(self.cause,self.custody)}
}
impl CounterStore {
    /// Consume the installed native owner's existing V2 connection. No path
    /// open, CREATE, initial row, migration, journal-mode rewrite or reset.
    /// Expected context and optional predecessor come from authenticated own
    /// finalized history; they are never discovered as authority from this DB.
    /// The native VFS/exclusive counter lease outlive this store and all effects.
    pub fn from_existing_connection(mut db:std::mem::ManuallyDrop<Connection>,
        expected:Hash,predecessor:Option<Hash>,counter:&mut impl Counter)
        ->std::result::Result<Self,ExistingCounterRefusal>{
        let inspected=(||->Result<Row>{
            if expected==[0;32]||predecessor.is_some_and(|p|p==[0;32]||p==expected){return Err(Error::Context);}
            db.pragma_update(None,"trusted_schema",false)?;
            let mode:String=db.pragma_query_value(None,"journal_mode",|r|r.get(0))?;
            let sync:i64=db.pragma_query_value(None,"synchronous",|r|r.get(0))?;
            if !mode.eq_ignore_ascii_case("delete")||sync!=2||db.is_readonly(rusqlite::MAIN_DB)?{
                return Err(Error::Invalid);}
            let tx=db.transaction_with_behavior(TransactionBehavior::Deferred)?;
            // Validate the exact schema before integrity/snapshot inspection.
            // Both comparisons borrow native result text and allocate no copy.
            schema(&tx)?;
            let integrity:bool=tx.query_row("PRAGMA integrity_check",[],|r|{
                Ok(matches!(r.get_ref(0)?,rusqlite::types::ValueRef::Text(raw) if raw==b"ok"))
            })?;
            if !integrity{return Err(Error::Invalid);}
            let current=row(&tx)?;
            Self::authorize_resume(&current,expected,predecessor)?;
            tx.commit()?;Ok(current)
        })();
        let current=match inspected{Ok(current)=>current,Err(cause)=>return Err(ExistingCounterRefusal{
            cause,custody:ExistingCounterCustody::Connection(db)})};
        // Retain before any counter read/advance, including an unwinding backend.
        let mut store=std::mem::ManuallyDrop::new(Self{db:std::mem::ManuallyDrop::into_inner(db),current,poisoned:true});
        if let Err(cause)=store.recover(expected,predecessor,counter){return Err(ExistingCounterRefusal{
            cause,custody:ExistingCounterCustody::Counter(store)});}
        Ok(std::mem::ManuallyDrop::into_inner(store))
    }
    /// One consuming SQLite close. A poisoned/unknown transition closes nothing.
    /// Separate native main/journal close receipts and original worker join are
    /// still mandatory before the factory can release its exclusive provider.
    pub fn close_existing(self)->std::result::Result<(),ExistingCounterCloseRefusal>{
        if self.poisoned{return Err(ExistingCounterCloseRefusal{cause:Error::StaleWriter,
            custody:ExistingCounterCustody::Counter(std::mem::ManuallyDrop::new(self))});}
        let Self{db,..}=self;
        match db.close(){Ok(())=>Ok(()),Err((db,cause))=>Err(ExistingCounterCloseRefusal{
            cause:Error::Storage(cause),custody:ExistingCounterCustody::Connection(std::mem::ManuallyDrop::new(db))})}
    }
    pub fn resume_rebind(
        path: &Path,
        context: Hash,
        predecessor: Hash,
        counter: &mut impl MonotonicCounter,
    ) -> Result<Self> {
        Self::open(path, context, Some(predecessor), None, counter)
    }

    /// Initialization is explicit; absent files are never repaired on resume.
    /// For a pending rebind, predecessor must be independently authorized by
    /// the canonical rotation. Never discover expected context from this DB.
    pub fn open(
        path: &Path,
        expected: Hash,
        predecessor: Option<Hash>,
        initial: Option<(u64, &[u8])>,
        counter: &mut impl Counter,
    ) -> Result<Self> {
        if expected == [0; 32]
            || predecessor.is_some_and(|p| p == [0; 32] || p == expected)
            || (initial.is_some() && predecessor.is_some())
        {
            return Err(Error::Context);
        }
        let mut flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        if initial.is_some() {
            flags |= OpenFlags::SQLITE_OPEN_CREATE;
        }
        let mut db = Connection::open_with_flags(path, flags)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(
            "PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;",
        )?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let count: u64 = tx.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
        if count == 0 {
            let (tip, snapshot) = initial.ok_or(Error::Rollback)?;
            valid(expected, snapshot)?;
            if counter.read().map_err(|_| Error::Backend)? != tip {
                return Err(Error::Rollback);
            }
            tx.execute_batch(SCHEMA)?;
            tx.execute(
                "INSERT INTO voter_migration VALUES(1,?1,?2,?3,NULL,NULL)",
                params![&expected, tip.to_be_bytes().as_slice(), snapshot],
            )?;
        } else if initial.is_some() {
            return Err(Error::Invalid);
        }
        let current = row(&tx)?;
        Self::authorize_resume(&current, expected, predecessor)?;
        tx.commit()?;
        let mut store = Self {
            db,
            current,
            poisoned: true,
        };
        store.recover(expected, predecessor, counter)?;
        Ok(store)
    }
    fn authorize_resume(r: &Row, expected: Hash, predecessor: Option<Hash>) -> Result<()> {
        match &r.pending {
            None if r.context == expected => Ok(()),
            Some((next, _))
                if *next == expected
                    && (r.context == expected || predecessor == Some(r.context)) =>
            {
                Ok(())
            }
            _ => Err(Error::Context),
        }
    }
    fn recover(
        &mut self,
        expected: Hash,
        predecessor: Option<Hash>,
        counter: &mut impl Counter,
    ) -> Result<()> {
        self.poisoned = true;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut current = row(&tx)?;
        Self::authorize_resume(&current, expected, predecessor)?;
        let hardware = counter.read().map_err(|_| Error::Backend)?;
        if let Some((next_context, next_snapshot)) = current.pending.clone() {
            let next = current.tip.checked_add(1).ok_or(Error::Overflow)?;
            if hardware == current.tip {
                counter.increment().map_err(|_| Error::Backend)?;
            } else if hardware != next {
                return Err(Error::Rollback);
            }
            if counter.read().map_err(|_| Error::Backend)? != next {
                return Err(Error::Rollback);
            }
            #[cfg(test)]
            fault(2)?;
            tx.execute("UPDATE voter_migration SET context=?1,tip=?2,snapshot=?3,pending_context=NULL,pending_snapshot=NULL WHERE id=1",params![&next_context,next.to_be_bytes().as_slice(),&next_snapshot])?;
            #[cfg(test)]
            fault(3)?;
            current = Row {
                context: next_context,
                tip: next,
                snapshot: next_snapshot,
                pending: None,
            };
        } else if hardware != current.tip {
            return Err(Error::Rollback);
        }
        tx.commit()?;
        #[cfg(test)]
        fault(4)?;
        self.current = current;
        self.poisoned = false;
        Ok(())
    }
    pub fn context(&self) -> Hash {
        self.current.context
    }
    pub fn snapshot(&self) -> &[u8] {
        &self.current.snapshot
    }
    pub fn counter_value(&self) -> u64 {
        self.current.tip
    }
    pub fn verify_current(&mut self, counter: &mut impl Counter) -> Result<()> {
        if self.poisoned {
            return Err(Error::StaleWriter);
        }
        self.poisoned = true;
        let tx = self.db.transaction()?;
        if row(&tx)? != self.current || self.current.pending.is_some() {
            return Err(Error::StaleWriter);
        }
        if counter.read().map_err(|_| Error::Backend)? != self.current.tip {
            return Err(Error::Rollback);
        }
        tx.commit()?;
        self.poisoned = false;
        Ok(())
    }
    pub fn commit(&mut self, bytes: &[u8], counter: &mut impl Counter) -> Result<()> {
        self.install(self.current.context, bytes, counter)
    }
    /// Caller supplies a fully validated, finalized generation transition and
    /// a snapshot preserving the monotonically increasing vote sequence.
    pub fn rebind(&mut self, next: Hash, bytes: &[u8], counter: &mut impl Counter) -> Result<()> {
        if next == self.current.context {
            return Err(Error::Context);
        }
        self.install(next, bytes, counter)
    }
    fn install(&mut self, next: Hash, bytes: &[u8], counter: &mut impl Counter) -> Result<()> {
        valid(next, bytes)?;
        self.verify_current(counter)?;
        let predecessor = self.current.context;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        if row(&tx)? != self.current {
            return Err(Error::StaleWriter);
        }
        if counter.read().map_err(|_| Error::Backend)? != self.current.tip {
            return Err(Error::Rollback);
        }
        if next == predecessor && bytes == self.current.snapshot {
            return Ok(());
        }
        self.current.tip.checked_add(1).ok_or(Error::Overflow)?;
        self.poisoned = true;
        tx.execute(
            "UPDATE voter_migration SET pending_context=?1,pending_snapshot=?2 WHERE id=1",
            params![&next, bytes],
        )?;
        tx.commit()?;
        #[cfg(test)]
        fault(1)?;
        self.recover(next, (next != predecessor).then_some(predecessor), counter)
    }
}
#[cfg(test)]
#[path = "counter_store_v2_tests.rs"]
mod tests;
