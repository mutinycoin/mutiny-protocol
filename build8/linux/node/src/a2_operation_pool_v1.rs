//! Separate single-item A2 evidence queue. Exact bytes must pass current-parent
//! native execution before storage or return to the assembler. A local schema,
//! transport prefix, witness label or caller success flag supplies no authority.
use crate::hybrid_runtime_v2::{HybridRuntime, WorkRequest};
use mutiny_consensus_v8::{Hash, anchors::FinalizedAnchor};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::path::Path;

type Result<T> = std::result::Result<T, String>;
pub const MAX_BYTES: usize = 196_608;
const APP: i64 = 0x4d413232;
const SCHEMA: i64 = 2;
pub const MAX_ARCHIVED: usize = 2;
const CONTEXT: &str = "CREATE TABLE context(id INTEGER PRIMARY KEY CHECK(id=1),genesis BLOB NOT NULL CHECK(length(genesis)=32),fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32))";
const PENDING: &str = "CREATE TABLE pending(id INTEGER PRIMARY KEY CHECK(id=1),digest BLOB NOT NULL CHECK(length(digest)=32),wire BLOB NOT NULL CHECK(length(wire)>0 AND length(wire)<=196608))";
const ARCHIVED: &str = "CREATE TABLE archived(digest BLOB PRIMARY KEY CHECK(length(digest)=32),wire BLOB NOT NULL CHECK(length(wire)>0 AND length(wire)<=196608),reason TEXT NOT NULL CHECK(length(CAST(reason AS BLOB)) BETWEEN 1 AND 1024))";
fn storage(_: rusqlite::Error) -> String { "A2 queue storage failure".into() }
fn id(raw: &[u8]) -> Hash { Sha256::digest(raw).into() }

/// Local operator-owned candidate inputs, separate from the received operation.
/// They do not replace native license, Worker, authority or witness checks.
pub struct Context<'a> {
    pub parent: &'a FinalizedAnchor,
    pub license: Hash,
    pub worker: Hash,
    pub timestamp: u64,
    pub ticket: u64,
}

#[cfg(test)]
mod storage_controls {
    use super::*;
    // Private modeled local storage only. These synthetic byte strings NEVER pass
    // production Pool::open/submit or confer native admission/relay authority.
    fn model() -> Pool {
        let db=Connection::open_in_memory().unwrap();
        db.execute_batch(CONTEXT).unwrap();
        db.execute_batch(PENDING).unwrap();
        db.execute_batch(ARCHIVED).unwrap();
        Pool {db,genesis:[1;32],fingerprint:[2;32]}
    }
    fn insert_model(pool:&Pool,bytes:&[u8]) -> Hash {
        let digest=id(bytes);
        pool.db.execute("INSERT INTO pending VALUES(1,?1,?2)",params![digest.as_slice(),bytes]).unwrap();
        digest
    }
    #[test]
    fn modeled_local_archive_preserves_exact_bytes_and_backpressures_without_eviction() {
        let mut pool=model();
        let a=vec![7;MAX_BYTES];let ad=insert_model(&pool,&a);
        assert!(pool.archive_and_cancel([0;32],"explicit owner cancellation").is_err());
        assert!(pool.archive_and_cancel(ad,"").is_err());
        assert_eq!(pool.raw().unwrap(),Some((ad,a.clone())));
        assert!(pool.archive_and_cancel(ad,"explicit owner cancellation").unwrap());
        assert!(pool.raw().unwrap().is_none());
        assert_eq!(pool.archived(ad).unwrap(),Some((a.clone(),"explicit owner cancellation".into())));
        let b=vec![8;MAX_BYTES];let bd=insert_model(&pool,&b);
        assert!(pool.archive_and_cancel(bd,"stale parent retained").unwrap());
        let c=vec![9;MAX_BYTES];let cd=insert_model(&pool,&c);
        assert!(pool.archive_and_cancel(cd,"third archive refuses").is_err());
        assert_eq!(pool.raw().unwrap(),Some((cd,c)));
        assert_eq!(pool.archived(ad).unwrap().unwrap().0,a);
        assert_eq!(pool.archived(bd).unwrap().unwrap().0,b);
    }
    #[test]
    fn modeled_archive_transaction_failure_keeps_pending_and_complete_archive() {
        let mut pool=model();let raw=vec![5;MAX_BYTES];let digest=insert_model(&pool,&raw);
        pool.db.execute_batch("CREATE TRIGGER refuse_cancel BEFORE DELETE ON pending BEGIN SELECT RAISE(ABORT,'modeled disk/transaction refusal'); END").unwrap();
        assert!(pool.archive_and_cancel(digest,"retained transaction failure").is_err());
        assert_eq!(pool.raw().unwrap(),Some((digest,raw.clone())));
        assert!(pool.archived(digest).unwrap().is_none());
        pool.db.execute_batch("DROP TRIGGER refuse_cancel").unwrap();
        assert!(pool.archive_and_cancel(digest,"retained transaction failure").unwrap());
        pool.db.execute("UPDATE archived SET wire=?1 WHERE digest=?2",params![vec![6u8;MAX_BYTES],digest.as_slice()]).unwrap();
        assert!(pool.archived(digest).is_err());
        assert!(pool.archive_and_cancel(digest,"unchanged corrupt evidence").is_err());
        let retained:Vec<u8>=pool.db.query_row("SELECT wire FROM archived WHERE digest=?1",[digest.as_slice()],|r|r.get(0)).unwrap();
        assert_eq!(retained,vec![6u8;MAX_BYTES]);
    }
}
pub struct Pool { db: Connection, genesis: Hash, fingerprint: Hash }
impl Pool {
    pub fn open(runtime: &HybridRuntime, path: &Path, initialize: bool) -> Result<Self> {
        let parent = runtime.head().map_err(|_| "A2 canonical head")?;
        let capacity = runtime.chain.body_capacity(&parent).map_err(|_| "A2 authenticated capacity")?;
        if !capacity.allows_a2() { return Err("A2 successor not selected".into()); }
        if initialize {
            std::fs::OpenOptions::new().write(true).create_new(true).open(path)
                .map_err(|_| "A2 queue create-new")?;
        }
        let mut db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX).map_err(storage)?;
        db.busy_timeout(std::time::Duration::from_secs(5)).map_err(storage)?;
        let app: i64 = db.pragma_query_value(None, "application_id", |r| r.get(0)).map_err(storage)?;
        let version: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0)).map_err(storage)?;
        let objects: u64 = db.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0)).map_err(storage)?;
        if if initialize { app != 0 || version != 0 || objects != 0 } else { app != APP || version != SCHEMA || objects != 4 } {
            return Err("A2 queue format".into());
        }
        let page: u64 = db.pragma_query_value(None, "page_size", |r| r.get(0)).map_err(storage)?;
        if page == 0 { return Err("A2 queue page size".into()); }
        let page_limit = (1024u64 * 1024) / page;
        let pages: u64 = db.pragma_query_value(None, "page_count", |r| r.get(0)).map_err(storage)?;
        if pages > page_limit { return Err("A2 queue disk budget".into()); }
        db.pragma_update(None, "max_page_count", page_limit).map_err(storage)?;
        let actual: u64 = db.pragma_query_value(None, "max_page_count", |r| r.get(0)).map_err(storage)?;
        if actual != page_limit { return Err("A2 queue disk budget".into()); }
        db.execute_batch("PRAGMA trusted_schema=OFF;PRAGMA journal_mode=DELETE;PRAGMA synchronous=FULL;").map_err(storage)?;
        let t = db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
        if initialize {
            t.execute_batch(CONTEXT).map_err(storage)?;
            t.execute_batch(PENDING).map_err(storage)?;
            t.execute_batch(ARCHIVED).map_err(storage)?;
            t.execute("INSERT INTO context VALUES(1,?1,?2)", params![parent.genesis.as_slice(),parent.fingerprint.as_slice()]).map_err(storage)?;
            t.pragma_update(None,"application_id",APP).map_err(storage)?;
            t.pragma_update(None,"user_version",SCHEMA).map_err(storage)?;
        }
        for (name, expected) in [("context",CONTEXT),("pending",PENDING),("archived",ARCHIVED)] {
            let sql: String = t.query_row("SELECT CASE WHEN length(CAST(sql AS BLOB))<=1024 THEN sql ELSE NULL END FROM sqlite_schema WHERE type='table' AND name=?1",[name],|r|r.get(0)).map_err(storage)?;
            if sql != expected { return Err("A2 queue schema".into()); }
        }
        let stored: (Vec<u8>,Vec<u8>) = t.query_row("SELECT CASE WHEN length(genesis)=32 THEN genesis ELSE NULL END,CASE WHEN length(fingerprint)=32 THEN fingerprint ELSE NULL END FROM context WHERE id=1",[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(storage)?;
        if stored.0 != parent.genesis || stored.1 != parent.fingerprint { return Err("A2 queue context".into()); }
        let count: u64 = t.query_row("SELECT count(*) FROM pending",[],|r|r.get(0)).map_err(storage)?;
        if count > 1 { return Err("A2 queue capacity".into()); }
        let archived:u64=t.query_row("SELECT count(*) FROM archived",[],|r|r.get(0)).map_err(storage)?;
        if archived>MAX_ARCHIVED as u64 { return Err("A2 archive capacity".into()); }
        t.commit().map_err(storage)?;
        let pool = Self { db, genesis: parent.genesis, fingerprint: parent.fingerprint };
        pool.raw()?; // bounded storage integrity only; no semantic validity inferred
        pool.audit_archives()?;
        Ok(pool)
    }
    fn raw(&self) -> Result<Option<(Hash,Vec<u8>)>> {
        let row: Option<(Vec<u8>,Vec<u8>)> = self.db.query_row("SELECT CASE WHEN length(digest)=32 THEN digest ELSE NULL END,CASE WHEN length(wire)>0 AND length(wire)<=196608 THEN wire ELSE NULL END FROM pending WHERE id=1",[],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(storage)?;
        match row {
            None => Ok(None),
            Some((digest,raw)) => {
                let digest: Hash = digest.try_into().map_err(|_| "A2 queue digest")?;
                if id(&raw) != digest { return Err("A2 queue bytes changed".into()); }
                Ok(Some((digest,raw)))
            }
        }
    }
    fn audit_archives(&self) -> Result<()> {
        let mut query=self.db.prepare("SELECT CASE WHEN length(digest)=32 THEN digest ELSE NULL END,CASE WHEN length(wire) BETWEEN 1 AND 196608 THEN wire ELSE NULL END,CASE WHEN length(CAST(reason AS BLOB)) BETWEEN 1 AND 1024 THEN reason ELSE NULL END FROM archived LIMIT 3").map_err(storage)?;
        let mut count=0usize;
        for row in query.query_map([],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,String>(2)?))).map_err(storage)? {
            let (digest,wire,_)=row.map_err(storage)?; count+=1;
            if count>MAX_ARCHIVED || digest.as_slice()!=id(&wire).as_slice() { return Err("A2 archived bytes changed".into()); }
        }
        Ok(())
    }
    /// Explicit local owner action only. Insert the complete public bytes and
    /// bounded reason before deleting pending, in ONE FULL-synchronous transaction.
    /// Archive exhaustion preserves pending; there is no eviction or wire route.
    /// The reason is a local statement, never canonical eligibility evidence.
    pub fn archive_and_cancel(&mut self, expected:Hash,reason:&str) -> Result<bool> {
        if reason.is_empty() || reason.len()>1024 { return Err("A2 archive reason bound".into()); }
        self.audit_archives()?;
        let Some((digest,wire))=self.raw()? else { return Ok(false); };
        if digest!=expected { return Err("A2 owner cancellation identity changed".into()); }
        let transaction=self.db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
        let current:(Vec<u8>,Vec<u8>)=transaction.query_row("SELECT CASE WHEN length(digest)=32 THEN digest ELSE NULL END,CASE WHEN length(wire) BETWEEN 1 AND 196608 THEN wire ELSE NULL END FROM pending WHERE id=1",[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(storage)?;
        if current.0.as_slice()!=expected.as_slice() || current.1!=wire { return Err("A2 archive cancellation bytes changed".into()); }
        let prior:Option<(Vec<u8>,String)>=transaction.query_row("SELECT CASE WHEN length(wire) BETWEEN 1 AND 196608 THEN wire ELSE NULL END,CASE WHEN length(CAST(reason AS BLOB)) BETWEEN 1 AND 1024 THEN reason ELSE NULL END FROM archived WHERE digest=?1",[digest.as_slice()],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(storage)?;
        if let Some((old,old_reason))=prior {
            if old!=wire || old_reason!=reason { return Err("A2 archive identity/reason already retained".into()); }
        } else {
            let count:u64=transaction.query_row("SELECT count(*) FROM archived",[],|r|r.get(0)).map_err(storage)?;
            if count>=MAX_ARCHIVED as u64 { return Err("A2 archive full; preserve and inspect".into()); }
            transaction.execute("INSERT INTO archived VALUES(?1,?2,?3)",params![digest.as_slice(),wire,reason]).map_err(storage)?;
        }
        if transaction.execute("DELETE FROM pending WHERE id=1 AND digest=?1",[digest.as_slice()]).map_err(storage)?!=1 {
            return Err("A2 archive cancellation race".into());
        }
        transaction.commit().map_err(storage)?;
        Ok(true)
    }
    /// Bounded exact local evidence export. This supplies no admission authority.
    pub fn archived(&self,digest:Hash) -> Result<Option<(Vec<u8>,String)>> {
        let _snapshot=self.db.unchecked_transaction().map_err(storage)?;
        self.audit_archives()?;
        let row:Option<(Vec<u8>,String)>=self.db.query_row("SELECT CASE WHEN length(wire) BETWEEN 1 AND 196608 THEN wire ELSE NULL END,CASE WHEN length(CAST(reason AS BLOB)) BETWEEN 1 AND 1024 THEN reason ELSE NULL END FROM archived WHERE digest=?1",[digest.as_slice()],|r|Ok((r.get(0)?,r.get(1)?))).optional().map_err(storage)?;
        if row.as_ref().is_some_and(|(wire,_)|id(wire)!=digest) { return Err("A2 archive export bytes changed".into()); }
        Ok(row)
    }
    fn validate(&self, runtime: &HybridRuntime, context: &Context<'_>, raw: &[u8]) -> Result<Hash> {
        if raw.is_empty() || raw.len() > MAX_BYTES { return Err("A2 complete operation bound".into()); }
        if (context.parent.genesis,context.parent.fingerprint) != (self.genesis,self.fingerprint) { return Err("A2 queue candidate context".into()); }
        let operations = [raw.to_vec()];
        runtime.preview_a2_operation(WorkRequest {
            expected_parent: context.parent, license: context.license, worker: context.worker,
            timestamp: context.timestamp, ticket: context.ticket, operations: &operations,
        }).map_err(|_| "A2 full native execution refused")?;
        Ok(id(raw))
    }
    pub fn submit(&mut self, runtime: &HybridRuntime, context: &Context<'_>, raw: &[u8]) -> Result<Hash> {
        // Backpressure before expensive certificate/signature execution. No
        // replacement or eviction can erase an unfinished admitted item.
        if let Some((digest,prior)) = self.raw()? {
            if prior != raw { return Err("A2 queue full; separate finalized blocks required".into()); }
            self.validate(runtime,context,raw)?;
            return Ok(digest);
        }
        let digest = self.validate(runtime,context,raw)?;
        let t = self.db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
        let occupied: u64 = t.query_row("SELECT count(*) FROM pending",[],|r|r.get(0)).map_err(storage)?;
        if occupied != 0 { return Err("A2 queue full; retry".into()); }
        t.execute("INSERT INTO pending VALUES(1,?1,?2)",params![digest.as_slice(),raw]).map_err(storage)?;
        t.commit().map_err(storage)?;
        Ok(digest)
    }
    /// Every assembly attempt revalidates current parent, time and full native
    /// evidence. A failed revalidation preserves the pending original bytes.
    pub fn pending(&self, runtime: &HybridRuntime, context: &Context<'_>) -> Result<Option<Vec<u8>>> {
        let Some((_,raw)) = self.raw()? else { return Ok(None); };
        self.validate(runtime,context,&raw)?;
        Ok(Some(raw))
    }
    /// Retention proof only, never current admission/relay authority. A completed
    /// transport copy can be released after ACK only while these exact bytes are
    /// durable locally or authenticated in the complete canonical envelope.
    pub(crate) fn retains_exact(&self, runtime: &HybridRuntime, raw: &[u8]) -> Result<bool> {
        // Retention must belong to this runtime's canonical network before it
        // can authorize release of a completed/ACKed transport copy. Current
        // prospective validation happens later and cannot undo that deletion.
        if runtime.network_context() != (self.genesis,self.fingerprint) {
            return Err("A2 retention canonical network changed".into());
        }
        if let Some((_,prior)) = self.raw()? {
            if prior == raw { return Ok(true); }
        }
        if self.archived(id(raw))?.is_some_and(|(prior,_)|prior==raw) { return Ok(true); }
        self.finalized_exact(runtime,raw)
    }
    /// Exact durable evidence for an explicit local transport cancellation.
    /// A still-pending copy is not cancelled, even if an older archive shares
    /// its identity. This supplies retention only, never relay authorization.
    pub(crate) fn cancelled_bytes(&self, runtime: &HybridRuntime, digest: Hash) -> Result<Vec<u8>> {
        if runtime.network_context() != (self.genesis,self.fingerprint) {
            return Err("A2 cancellation canonical network changed".into());
        }
        if self.raw()?.is_some_and(|(pending,_)|pending==digest) {
            return Err("A2 cancellation item remains pending".into());
        }
        self.archived(digest)?.map(|(wire,_)|wire)
            .ok_or_else(||"A2 cancellation exact archive unavailable".into())
    }
    /// Only authenticated canonical inclusion retires the local item. The
    /// canonical evidence store retains its full authenticated operation bytes.
    pub fn reconcile_finalized(&mut self, runtime: &HybridRuntime) -> Result<bool> {
        let Some((digest,raw)) = self.raw()? else { return Ok(false); };
        if !self.finalized_exact(runtime,&raw)? { return Ok(false); }
        let t = self.db.transaction_with_behavior(TransactionBehavior::Immediate).map_err(storage)?;
        let current:(Vec<u8>,Vec<u8>)=t.query_row("SELECT CASE WHEN length(digest)=32 THEN digest ELSE NULL END,CASE WHEN length(wire) BETWEEN 1 AND 196608 THEN wire ELSE NULL END FROM pending WHERE id=1",[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(storage)?;
        if current.0.as_slice()!=digest.as_slice() || current.1!=raw { return Err("A2 finalized retirement bytes changed".into()); }
        let changed = t.execute("DELETE FROM pending WHERE id=1 AND digest=?1",[digest.as_slice()]).map_err(storage)?;
        if changed != 1 { return Err("A2 retirement race".into()); }
        t.commit().map_err(storage)?;
        Ok(true)
    }
    /// Replay-authenticated exact finalized bytes also recover a completed
    /// transport handoff after crash between pool commit and transport release.
    pub(crate) fn finalized_exact(&self, runtime: &HybridRuntime, raw: &[u8]) -> Result<bool> {
        if raw.is_empty() || raw.len() > MAX_BYTES { return Err("A2 complete operation bound".into()); }
        let parent = runtime.head().map_err(|_| "A2 canonical head")?;
        if (parent.genesis,parent.fingerprint) != (self.genesis,self.fingerprint) { return Err("A2 canonical network changed".into()); }
        let capacity = runtime.chain.body_capacity(&parent).map_err(|_| "A2 capacity")?;
        capacity.supported_a2_operation(raw).map_err(|_| "A2 typed canonical carrier")?;
        let (kind,operation) = capacity.operation_id(&raw).map_err(|_| "A2 canonical operation identity")?;
        let records = runtime.chain.verified_operation_records(operation).map_err(|_| "A2 replayed canonical inclusion")?;
        if records.is_empty() { return Ok(false); }
        for record in records {
            if record.list != 1 || record.kind != kind || record.op_id != operation
                || record.wire != mutiny_consensus_v8::domain_hash(mutiny_consensus_v8::operation_index_v2::WIRE_DOMAIN,&raw) {
                return Err("A2 canonical inclusion differs".into());
            }
            let bytes = runtime.chain.certified_envelope_bytes(record.height,record.block)
                .map_err(|_| "A2 authenticated envelope export")?.ok_or("A2 canonical evidence unavailable")?;
            let header = mutiny_consensus_v8::block_envelope_v2::BlockEnvelope::untrusted_header(&bytes)
                .map_err(|_| "A2 retained envelope header")?;
            let historical = runtime.chain.proposal_body_capacity(&header).map_err(|_| "A2 historical capacity")?;
            let envelope = mutiny_consensus_v8::block_envelope_v2::BlockEnvelope::decode_with_capacity(&bytes,&historical)
                .map_err(|_| "A2 retained envelope")?;
            record.verify_in_block_with_capacity(&envelope.body,record.block,&historical)
                .map_err(|_| "A2 exact canonical record")?;
            if envelope.body.operations.get(record.position as usize).map(Vec::as_slice) != Some(raw) {
                return Err("A2 exact finalized bytes differ".into());
            }
        }
        Ok(true)
    }
}
