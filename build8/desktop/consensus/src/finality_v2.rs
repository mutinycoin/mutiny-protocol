//! Durable hybrid finalized-history evidence and integrity halt. This component
//! does not install chain state or reconcile a mempool. Callers must supply
//! locally authenticated parent state/authority, never peer-asserted authority.
use crate::{
    Hash,
    anchors::FinalizedAnchor,
    block_envelope_v2::{BlockEnvelope, MAX_ENVELOPE_BYTES},
    execution::{State, WorkParent},
    votes_v2::HeightAuthority,
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::path::Path;
const APP_ID: i64 = 0x4d554632;
// Local storage policy only. Capacity exhaustion fails writes; it never prunes
// required history or changes the validity of a block/certificate.
const DATABASE_BYTES: u64 = 1024 * 1024 * 1024;
#[derive(Debug)]
pub enum StoreError {
    Storage(rusqlite::Error),
    Context,
    Integrity,
    WrongParent,
    Halted,
    Invalid(crate::Error),
    Verification(crate::votes::IngressError),
    Execution(crate::execution::ExecutionError),
    Pool(crate::mempool_v2::PoolError),
    SubmissionPool(crate::submission_pool_v1::PoolError),
    Assembly(String),
}
impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e)
    }
}
impl From<crate::Error> for StoreError {
    fn from(e: crate::Error) -> Self {
        Self::Invalid(e)
    }
}
impl From<crate::execution::ExecutionError> for StoreError {
    fn from(e: crate::execution::ExecutionError) -> Self {
        Self::Execution(e)
    }
}
type Result<T> = std::result::Result<T, StoreError>;
pub struct FinalityEvidenceStore {
    pub(crate) db: Connection,
    genesis: FinalizedAnchor,
}
/// A validation failure retains the original supplied SQLite connection. This
/// is not an automatic close, rollback/recovery, native identity or VFS issuer.
pub struct ExistingConnectionRefusal {
    cause:StoreError,connection:std::mem::ManuallyDrop<Connection>,
}
impl ExistingConnectionRefusal {
    pub fn cause(&self)->&StoreError{&self.cause}
    pub(crate) fn into_retained(self)->(StoreError,std::mem::ManuallyDrop<Connection>){
        (self.cause,self.connection)
    }
}
fn anchor(db: &Connection, height: u64) -> Result<Option<FinalizedAnchor>> {
    let raw:Option<Vec<u8>>=db.query_row("SELECT CASE WHEN length(anchor) BETWEEN 1 AND 256 THEN anchor ELSE NULL END FROM finalized_v2 WHERE height=?1",
        [height.to_be_bytes().as_slice()],|r|r.get(0)).optional()?;
    raw.map(|r| FinalizedAnchor::decode(&r).map_err(StoreError::from))
        .transpose()
}
impl FinalityEvidenceStore {
    /// Consuming SQLite close only. The selected native VFS owner and original
    /// worker must supply their independent close/join reports before release.
    pub(crate) fn close_existing(self)->std::result::Result<(),ExistingConnectionRefusal>{
        let Self{db,..}=self;
        match db.close(){Ok(())=>Ok(()),Err((connection,cause))=>Err(ExistingConnectionRefusal{
            cause:StoreError::Storage(cause),connection:std::mem::ManuallyDrop::new(connection)})}
    }
    /// Validate an already opened canonical-version connection. The host owns
    /// existing-only native open/VFS/placement/serialization separately; this
    /// method never opens a filename, initializes a schema or migrates version3.
    pub(crate) fn from_existing_canonical_connection(connection:std::mem::ManuallyDrop<Connection>,
        genesis:&FinalizedAnchor)->std::result::Result<Self,ExistingConnectionRefusal> {
        let checked=(||->Result<()> {
            genesis.validate_context(genesis.genesis,genesis.fingerprint)?;
            if genesis.height!=0{return Err(StoreError::Context);}
            // Connection-local setting precedes any schema interpretation.
            connection.pragma_update(None,"trusted_schema",false)?;
            let t=rusqlite::Transaction::new_unchecked(&connection,TransactionBehavior::Deferred)?;
            let app:i64=t.pragma_query_value(None,"application_id",|r|r.get(0))?;
            let version:i64=t.pragma_query_value(None,"user_version",|r|r.get(0))?;
            if app!=APP_ID||version!=4{return Err(StoreError::Context);}
            crate::store_schema_v2::validate(&t,genesis,true)?;
            let page_size:u64=t.pragma_query_value(None,"page_size",|r|r.get(0))?;
            let pages=DATABASE_BYTES.checked_div(page_size).ok_or(StoreError::Integrity)?;
            let used:u64=t.pragma_query_value(None,"page_count",|r|r.get(0))?;
            if pages<256||used>pages{return Err(StoreError::Integrity);}
            // The existing native opener must have selected the same local
            // durability/capacity policy. Inspection never switches a journal
            // mode, creates recovery files or raises the retained size limit.
            let journal:String=t.pragma_query_value(None,"journal_mode",|r|r.get(0))?;
            let synchronous:i64=t.pragma_query_value(None,"synchronous",|r|r.get(0))?;
            let maximum:u64=t.pragma_query_value(None,"max_page_count",|r|r.get(0))?;
            if journal!="delete"||synchronous!=2||maximum!=pages{return Err(StoreError::Context);}
            let halted:bool=t.query_row("SELECT halted FROM integrity_v2 WHERE id=1",[],|r|r.get(0))?;
            let conflicts:bool=t.query_row("SELECT EXISTS(SELECT 1 FROM evidence_v2 GROUP BY height HAVING count(*)>1)",[],|r|r.get(0))?;
            let orphan:bool=t.query_row("SELECT EXISTS(SELECT 1 FROM evidence_v2 e LEFT JOIN finalized_v2 f ON e.height=f.height WHERE f.height IS NULL OR e.height=?1)",[0u64.to_be_bytes().as_slice()],|r|r.get(0))?;
            if (conflicts&&!halted)||orphan{return Err(StoreError::Integrity);}
            t.commit()?;Ok(())
        })();
        if let Err(cause)=checked{return Err(ExistingConnectionRefusal{cause,connection});}
        Ok(Self{db:std::mem::ManuallyDrop::into_inner(connection),genesis:genesis.clone()})
    }
    pub fn open(path: &Path, genesis: &FinalizedAnchor) -> Result<Self> {
        genesis.validate_context(genesis.genesis, genesis.fingerprint)?;
        if genesis.height != 0 {
            return Err(StoreError::Context);
        }
        let mut db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        let app: i64 = db.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let tables: u64 = db.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
        if !((app == 0 && version == 0 && tables == 0) || (app == APP_ID && matches!(version, 3 | 4))) {
            return Err(StoreError::Context);
        }
        let page_size: u64 = db.pragma_query_value(None, "page_size", |r| r.get(0))?;
        let pages = DATABASE_BYTES
            .checked_div(page_size)
            .ok_or(StoreError::Integrity)?;
        let used: u64 = db.pragma_query_value(None, "page_count", |r| r.get(0))?;
        if pages < 256 || used > pages {
            return Err(StoreError::Integrity);
        }
        db.pragma_update(None, "max_page_count", pages)?;
        let applied: u64 = db.pragma_query_value(None, "max_page_count", |r| r.get(0))?;
        if applied != pages {
            return Err(StoreError::Integrity);
        }
        db.execute_batch(
            "PRAGMA trusted_schema=OFF;PRAGMA journal_mode=DELETE;PRAGMA synchronous=FULL;",
        )?;
        let t = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if app == 0 {
            t.pragma_update(None, "application_id", APP_ID)?;
            t.pragma_update(None, "user_version", 3)?;
            // Schema, context and initial halt metadata form one transaction.
            // Existing stores never recreate missing evidence/history tables.
            for (_, sql) in crate::store_schema_v2::EVIDENCE {
                t.execute_batch(sql)?;
            }
            t.execute(
                "INSERT INTO finalized_v2 VALUES(?1,?2)",
                params![0u64.to_be_bytes().as_slice(), genesis.encode()],
            )?;
            t.execute("INSERT INTO integrity_v2 VALUES(1,0)", [])?;
        } else {
            crate::store_schema_v2::validate(&t, genesis, false)?;
            // A missing halt row is corruption, never an instruction to clear it.
            let halted: bool =
                t.query_row("SELECT halted FROM integrity_v2 WHERE id=1", [], |r| {
                    r.get(0)
                })?;
            // A retained conflicting history cannot be made runnable by
            // clearing only the halt bit. Reject corruption rather than
            // silently repairing or deleting its evidence.
            let conflicts: bool = t.query_row(
                "SELECT EXISTS(SELECT 1 FROM evidence_v2 GROUP BY height HAVING count(*)>1)",
                [],
                |r| r.get(0),
            )?;
            let orphan: bool=t.query_row("SELECT EXISTS(SELECT 1 FROM evidence_v2 e LEFT JOIN finalized_v2 f ON e.height=f.height WHERE f.height IS NULL OR e.height=?1)",[0u64.to_be_bytes().as_slice()],|r|r.get(0))?;
            if (conflicts && !halted) || orphan {
                return Err(StoreError::Integrity);
            }
        }
        crate::store_schema_v2::validate(&t, genesis, false)?;
        t.commit()?;
        Ok(Self {
            db,
            genesis: genesis.clone(),
        })
    }
    pub fn halted(&self) -> Result<bool> {
        let _snapshot = if self.db.is_autocommit() {
            Some(self.db.unchecked_transaction()?)
        } else {
            None
        };
        crate::store_schema_v2::validate(&self.db, &self.genesis, false)?;
        Ok(self
            .db
            .query_row("SELECT halted FROM integrity_v2 WHERE id=1", [], |r| {
                r.get(0)
            })?)
    }
    pub fn anchor(&self, height: u64) -> Result<Option<FinalizedAnchor>> {
        let _snapshot = if self.db.is_autocommit() {
            Some(self.db.unchecked_transaction()?)
        } else {
            None
        };
        crate::store_schema_v2::validate(&self.db, &self.genesis, false)?;
        anchor(&self.db, height)
    }
    pub fn evidence(&self, height: u64, block: Hash) -> Result<Option<BlockEnvelope>> {
        let _snapshot = if self.db.is_autocommit() {
            Some(self.db.unchecked_transaction()?)
        } else {
            None
        };
        crate::store_schema_v2::validate(&self.db, &self.genesis, false)?;
        let raw:Option<Vec<u8>>=self.db.query_row(
            "SELECT CASE WHEN length(envelope)<=?3 THEN envelope ELSE NULL END FROM evidence_v2 WHERE height=?1 AND block=?2",
            params![height.to_be_bytes().as_slice(),block.as_slice(),MAX_ENVELOPE_BYTES as u64],|r|r.get(0)).optional()?;
        raw.map(|r| BlockEnvelope::decode(&r).map_err(StoreError::from))
            .transpose()
    }
    /// Exact retained public bytes only, bounded for the new rule. Native callers must
    /// obtain the historical canonical-parent capability before decoding/acceptance.
    pub(crate) fn evidence_raw_a2(&self, height: u64, block: Hash) -> Result<Option<Vec<u8>>> {
        let _snapshot=if self.db.is_autocommit() { Some(self.db.unchecked_transaction()?) } else { None };
        crate::store_schema_v2::validate(&self.db,&self.genesis,false)?;
        self.db.query_row(
            "SELECT CASE WHEN length(envelope) BETWEEN 1 AND ?3 THEN envelope ELSE NULL END FROM evidence_v2 WHERE height=?1 AND block=?2",
            params![height.to_be_bytes().as_slice(),block.as_slice(),crate::body_capacity_v3::MAX_ENVELOPE_BYTES as u64],|r|r.get(0))
            .optional().map_err(StoreError::from)
    }
    /// Fully verify execution, PoW and hybrid quorum before recording evidence.
    /// Returns false for another valid representation of an existing block.
    /// A second valid block at that height atomically persists evidence + halt.
    pub fn record(
        &mut self,
        envelope: &BlockEnvelope,
        state: &State,
        parent: &WorkParent,
        authority: &HeightAuthority,
        history: &crate::evidence_history_v2::History,
    ) -> Result<bool> {
        let canonical: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='canonical_v2')",
            [],
            |r| r.get(0),
        )?;
        if canonical {
            return Err(StoreError::Context);
        }
        self.record_transactional(envelope, state, parent, authority, history, |_, _| Ok(()))
    }
    /// Internal canonical installation hook. The effect runs only for a new
    /// fully verified successor, in the same transaction as its finality entry.
    /// A failed effect rolls back all writes. A historical conflict commits only
    /// its proof and halt, never a replacement state or reward.
    pub(crate) fn record_transactional<F>(
        &mut self,
        envelope: &BlockEnvelope,
        state: &State,
        parent: &WorkParent,
        authority: &HeightAuthority,
        history: &crate::evidence_history_v2::History,
        effect: F,
    ) -> Result<bool>
    where
        F: FnOnce(&rusqlite::Transaction<'_>, &crate::execution::Execution) -> Result<()>,
    {
        self.record_with_recovery(envelope, state, parent, authority, history, None, effect)
    }
    pub(crate) fn record_with_recovery<F>(
        &mut self,
        envelope: &BlockEnvelope,
        state: &State,
        parent: &WorkParent,
        authority: &HeightAuthority,
        history: &crate::evidence_history_v2::History,
        recovery: Option<&crate::recovery_transition_v2::Prepared>,
        effect: F,
    ) -> Result<bool>
    where
        F: FnOnce(&rusqlite::Transaction<'_>, &crate::execution::Execution) -> Result<()>,
    {
        if self.halted()? {
            return Err(StoreError::Halted);
        }
        let canonical: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='canonical_v2')",
            [],
            |r| r.get(0),
        )?;
        if recovery.is_some() && !canonical {
            return Err(StoreError::Context);
        }
        let expected_recovery = recovery
            .map(|r| {
                let owner = state
                    .recovery_authority_v2
                    .as_ref()
                    .ok_or(StoreError::Integrity)?;
                Ok::<_, StoreError>((r.commitment()?, r.encoded_record(owner)?))
            })
            .transpose()?;
        let p = &authority.parent;
        p.validate_context(self.genesis.genesis, self.genesis.fingerprint)?;
        if self.anchor(p.height)?.as_ref() != Some(p) {
            return Err(StoreError::WrongParent);
        }
        let executed = match recovery {
            Some(r) => {
                if r.parent() != p {
                    return Err(StoreError::WrongParent);
                }
                r.verify_envelope(state, parent, envelope, history)
            }
            None => envelope.verify_execute_with_history(state, parent, authority, history),
        }
        .map_err(StoreError::Verification)?;
        let capacity=crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(state,p.clone(),state.root()?)?;
        let raw = envelope.encode_with_capacity(&capacity)?;
        let decision = &envelope.certificate.decision;
        let proposed = decision.anchor();
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        crate::store_schema_v2::validate(&t, &self.genesis, false)?;
        let halted: bool = t.query_row("SELECT halted FROM integrity_v2 WHERE id=1", [], |r| {
            r.get(0)
        })?;
        if halted {
            return Err(StoreError::Halted);
        }
        if anchor(&t, p.height)?.as_ref() != Some(p) {
            return Err(StoreError::WrongParent);
        }
        if canonical {
            crate::recovery_store_v2::require_unchanged(&t, p.height, expected_recovery.as_ref())?;
        }
        let old = anchor(&t, proposed.height)?;
        if old.as_ref() == Some(&proposed) {
            return Ok(false);
        }
        t.execute(
            "INSERT INTO evidence_v2 VALUES(?1,?2,?3)",
            params![
                proposed.height.to_be_bytes().as_slice(),
                proposed.block.as_slice(),
                raw
            ],
        )?;
        if old.is_some() {
            t.execute("UPDATE integrity_v2 SET halted=1 WHERE id=1", [])?;
            t.commit()?;
            return Err(StoreError::Halted);
        }
        t.execute(
            "INSERT INTO finalized_v2 VALUES(?1,?2)",
            params![proposed.height.to_be_bytes().as_slice(), proposed.encode()],
        )?;
        effect(&t, &executed)?;
        t.commit()?;
        Ok(true)
    }
}
