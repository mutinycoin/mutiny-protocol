//! Explicit A2 successor proposal custody. The authenticated store issues capacity.
//! Structural version3 or a claimed fingerprint never supplies consensus authority.
//! Pending proposals are never evicted; this creates no production eligibility.
use crate::hybrid_runtime_v2::HybridRuntime;
use minicbor::{Decoder, Encoder};
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    blocks::{BlockBody, canonical},
    pow::{WorkHeader, meets_target},
    work_authority_v2::Authority,
};
use mutiny_crypto_v2::{Domain, PublicKey};
use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::path::Path;
type Result<T> = std::result::Result<T, String>;
pub const MAX_BYTES: usize = 270_871;
pub const MAX_QUEUE_BYTES: usize = 64 * 1024 * 1024;
const MAX_PROPOSALS: usize = 1024;
const APP: i64 = 0x4d434a33;
const IDENTITY: &str =
    "CREATE TABLE identity(id INTEGER PRIMARY KEY CHECK(id=1),context BLOB NOT NULL)";
const CANDIDATES: &str = "CREATE TABLE candidates(id BLOB PRIMARY KEY CHECK(length(id)=32),height BLOB NOT NULL CHECK(length(height)=8),raw BLOB NOT NULL CHECK(length(raw)<=270871))";
fn storage(_: rusqlite::Error) -> String {
    "Hybrid candidate storage failure".into()
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub header: WorkHeader,
    pub authority: Authority,
    pub body: BlockBody,
}
impl Record {
    pub fn encode(&self, runtime: &HybridRuntime) -> Result<Vec<u8>> {
        let capacity = runtime.chain.proposal_body_capacity(&self.header)
            .map_err(|_| "Candidate authenticated parent capacity")?;
        if !capacity.allows_a2() { return Err("Candidate successor rule not selected".into()); }
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u8(3)
            .unwrap()
            .bytes(&self.header.encode())
            .unwrap()
            .bytes(&capacity.encode(&self.body).map_err(|_| "Candidate body")?)
            .unwrap()
            .bytes(&self.authority.encode().map_err(|_| "Candidate authority")?)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > capacity.proposal_limit() || raw.len() > MAX_BYTES {
            return Err("Candidate bound".into());
        }
        Ok(raw)
    }
    /// Inspect only the bounded header; this is not custody/admission validation.
    fn header(raw: &[u8]) -> Result<WorkHeader> {
        canonical(raw, MAX_BYTES).map_err(|_| "Candidate canonical bytes")?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(|_| "Candidate array")? != Some(4)
            || d.u8().map_err(|_| "Candidate version")? != 3 {
            return Err("Candidate schema".into());
        }
        WorkHeader::decode(d.bytes().map_err(|_| "Candidate header bytes")?)
            .map_err(|_| "Candidate header".into())
    }
    pub fn decode(runtime: &HybridRuntime, raw: &[u8]) -> Result<Self> {
        let inspected = Self::header(raw)?;
        let capacity = runtime.chain.proposal_body_capacity(&inspected)
            .map_err(|_| "Candidate authenticated parent capacity")?;
        if !capacity.allows_a2() { return Err("Candidate successor rule not selected".into()); }
        canonical(raw, MAX_BYTES).map_err(|_| "Candidate canonical bytes")?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(|_| "Candidate array")? != Some(4)
            || d.u8().map_err(|_| "Candidate version")? != 3
        {
            return Err("Candidate schema".into());
        }
        let header = WorkHeader::decode(d.bytes().map_err(|_| "Candidate header bytes")?)
            .map_err(|_| "Candidate header")?;
        let body = capacity.decode(d.bytes().map_err(|_| "Candidate body bytes")?)
            .map_err(|_| "Candidate body")?;
        let authority = Authority::decode(d.bytes().map_err(|_| "Candidate authority bytes")?)
            .map_err(|_| "Candidate authority")?;
        let value = Self {
            header,
            authority,
            body,
        };
        let c = &value.header.candidate;
        if d.position() != raw.len()
            || value.encode(runtime)? != raw
            || c.network != NETWORK_ID
            || c.height == 0
            || value.header.authority
                != value
                    .authority
                    .id()
                    .map_err(|_| "Candidate authority identity")?
            || value.authority.work.candidate != *c
            || value.body.height != c.height
            || capacity.root(&value.body).map_err(|_| "Candidate body root")? != c.body_root
            || !meets_target(&value.header.digest(), &c.target)
        {
            return Err("Candidate identity/work mismatch".into());
        }
        let (public, _) = PublicKey::decode_descriptor(&value.authority.node_descriptor)
            .map_err(|_| "Candidate Node descriptor")?;
        public
            .verify(
                Domain::NodeWork,
                &value
                    .authority
                    .unsigned()
                    .map_err(|_| "Candidate unsigned work")?,
                &value.authority.signature,
            )
            .map_err(|_| "Candidate signatures")?;
        Ok(value)
    }
}
/// Created only after durable retention or authenticated canonical retirement.
/// No deserializer/constructor accepts a peer's assertion of retention.
pub struct Retention {
    genesis: Hash,
    fingerprint: Hash,
    block: Hash,
}
impl From<Retention> for crate::candidate_journal_v2::Retention {
    fn from(value: Retention) -> Self {
        crate::candidate_journal_v2::Retention::from_a2(value)
    }
}
impl Retention {
    pub(crate) fn into_identity(self) -> (Hash, Hash, Hash) { (self.genesis, self.fingerprint, self.block) }
    pub(crate) fn matches(&self, header: &WorkHeader) -> bool {
        self.genesis == header.candidate.genesis
            && self.fingerprint == header.candidate.fingerprint
            && self.block == header.block_hash()
    }
}
pub struct Journal {
    db: Connection,
    genesis: Hash,
    fingerprint: Hash,
    budget: usize,
}
impl Journal {
    pub(crate) fn register_runtime(&self, runtime: &HybridRuntime) -> Result<()> {
        self.capacity()?;
        let parent = runtime.head().map_err(|_| "Candidate status head")?;
        if (parent.genesis, parent.fingerprint) != (self.genesis, self.fingerprint) {
            return Err("Candidate status context".into());
        }
        let path = self
            .db
            .path()
            .map(std::path::PathBuf::from)
            .ok_or("Candidate status path")?;
        runtime.register_a2_candidate_journal(path, self.budget)
    }
    pub fn open(
        runtime: &HybridRuntime, path: &Path, budget: usize, initialize: bool,
    ) -> Result<Self> {
        let parent = runtime.head().map_err(|_| "Candidate authenticated head")?;
        let capacity = runtime.chain.body_capacity(&parent)
            .map_err(|_| "Candidate authenticated parent capacity")?;
        if !capacity.allows_a2() { return Err("Candidate successor rule not selected".into()); }
        let (genesis, fingerprint) = (parent.genesis, parent.fingerprint);
        if budget == 0
            || budget > MAX_QUEUE_BYTES
            || [genesis, fingerprint].contains(&[0; 32])
        {
            return Err("Candidate context/budget".into());
        }
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u8(3)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&genesis)
            .unwrap()
            .bytes(&fingerprint)
            .unwrap();
        let context = e.into_writer();
        let flags = OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX;
        if initialize {
            std::fs::OpenOptions::new().write(true).create_new(true).open(path)
                .map_err(|_| "Candidate create-new storage")?;
        }
        let mut db = Connection::open_with_flags(path, flags).map_err(storage)?;
        db.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(storage)?;
        let app: i64 = db
            .pragma_query_value(None, "application_id", |r| r.get(0))
            .map_err(storage)?;
        let version: i64 = db
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .map_err(storage)?;
        let count: u64 = db
            .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
            .map_err(storage)?;
        if if initialize {
            app != 0 || version != 0 || count != 0
        } else {
            app != APP || version != 3 || count != 3
        } {
            return Err("Candidate database format".into());
        }
        let page: u64 = db
            .pragma_query_value(None, "page_size", |r| r.get(0))
            .map_err(storage)?;
        let limit = (128u64 * 1024 * 1024)
            .checked_div(page)
            .ok_or("Candidate page size")?;
        let used: u64 = db
            .pragma_query_value(None, "page_count", |r| r.get(0))
            .map_err(storage)?;
        if limit < 256 || used > limit {
            return Err("Candidate storage capacity".into());
        }
        db.pragma_update(None, "max_page_count", limit)
            .map_err(storage)?;
        let applied: u64 = db
            .pragma_query_value(None, "max_page_count", |r| r.get(0))
            .map_err(storage)?;
        if applied != limit {
            return Err("Candidate page budget".into());
        }
        db.execute_batch(
            "PRAGMA trusted_schema=OFF;PRAGMA journal_mode=DELETE;PRAGMA synchronous=FULL;",
        )
        .map_err(storage)?;
        let t = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        if initialize {
            t.execute_batch(IDENTITY).map_err(storage)?;
            t.execute_batch(CANDIDATES).map_err(storage)?;
            t.execute("INSERT INTO identity VALUES(1,?1)", [context.as_slice()])
                .map_err(storage)?;
            t.pragma_update(None, "application_id", APP)
                .map_err(storage)?;
            t.pragma_update(None, "user_version", 3).map_err(storage)?;
        }
        for (name, sql) in [("identity", IDENTITY), ("candidates", CANDIDATES)] {
            let actual:String=t.query_row("SELECT CASE WHEN length(CAST(sql AS BLOB))<=1024 THEN sql ELSE NULL END FROM sqlite_schema WHERE type='table' AND name=?1",[name],|r|r.get(0)).map_err(storage)?;
            if actual != sql {
                return Err("Candidate schema changed".into());
            }
        }
        let stored:Vec<u8>=t.query_row("SELECT CASE WHEN length(context)<=256 THEN context ELSE NULL END FROM identity WHERE id=1",[],|r|r.get(0)).map_err(storage)?;
        if stored != context {
            return Err("Candidate identity changed".into());
        }
        t.commit().map_err(storage)?;
        let journal = Self {
            db,
            genesis,
            fingerprint,
            budget,
        };
        journal.capacity()?;
        let mut q=journal.db.prepare("SELECT CASE WHEN length(id)=32 THEN id ELSE NULL END,CASE WHEN length(height)=8 THEN height ELSE NULL END,CASE WHEN length(raw)<=270871 THEN raw ELSE NULL END FROM candidates").map_err(storage)?;
        let mut rows = q.query([]).map_err(storage)?;
        while let Some(row) = rows.next().map_err(storage)? {
            journal.row(runtime, row)?;
        }
        drop(rows);
        drop(q);
        Ok(journal)
    }
    fn capacity(&self) -> Result<()> {
        let (count, bytes): (usize, usize) = self
            .db
            .query_row(
                "SELECT count(*),coalesce(sum(length(raw)),0) FROM candidates",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(storage)?;
        if count > MAX_PROPOSALS || bytes > self.budget {
            return Err("Candidate capacity exceeded".into());
        }
        Ok(())
    }
    fn row(&self, runtime: &HybridRuntime, r: &rusqlite::Row<'_>) -> Result<Record> {
        let id: Vec<u8> = r.get(0).map_err(storage)?;
        let height: Vec<u8> = r.get(1).map_err(storage)?;
        let raw: Vec<u8> = r.get(2).map_err(storage)?;
        let record = Record::decode(runtime, &raw)?;
        let c = &record.header.candidate;
        if c.genesis != self.genesis
            || c.fingerprint != self.fingerprint
            || id != record.header.block_hash()
            || height != c.height.to_be_bytes()
        {
            return Err("Candidate row context".into());
        }
        runtime.chain.validate_observation_v2(&record.header, &record.authority, &record.body)
            .map_err(|_| "Candidate restored native execution")?;
        Ok(record)
    }
    /// Serialized owning actor only. All signatures, PoW and historical full
    /// execution are checked before capacity mutation or issuance of a permit.
    pub fn preserve(&mut self, runtime: &HybridRuntime, record: &Record) -> Result<Retention> {
        let raw = record.encode(runtime)?;
        Record::decode(runtime, &raw)?;
        let parent = runtime.head().map_err(|_| "Canonical candidate head")?;
        let c = &record.header.candidate;
        if (parent.genesis, parent.fingerprint) != (self.genesis, self.fingerprint)
            || (c.genesis, c.fingerprint) != (self.genesis, self.fingerprint)
        {
            return Err("Candidate network context".into());
        }
        runtime
            .chain
            .validate_observation_v2(&record.header, &record.authority, &record.body)
            .map_err(|_| "Candidate historical execution")?;
        if c.height > parent.height
            && (parent.height.checked_add(1) != Some(c.height) || c.parent != parent.block)
        {
            return Err("Candidate wrong current parent".into());
        }
        let id = record.header.block_hash();
        self.register_runtime(runtime)?;
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        // Only certified canonical finality permits pruning. Never evict a
        // pending candidate because another Worker found a more recent result.
        t.execute(
            "DELETE FROM candidates WHERE height<=?1",
            [parent.height.to_be_bytes().as_slice()],
        )
        .map_err(storage)?;
        if c.height > parent.height {
            let old:Option<Vec<u8>>=t.query_row("SELECT CASE WHEN length(raw)<=270871 THEN raw ELSE NULL END FROM candidates WHERE id=?1",[id.as_slice()],|r|r.get(0)).optional().map_err(storage)?;
            if let Some(old) = old {
                if old != raw {
                    let prior = Record::decode(runtime, &old)?;
                    // FN-DSA signatures are randomized. Two valid authority
                    // representations can name the same block/unsigned work.
                    // Preserve the first bytes without rejecting an equivalent
                    // candidate or allowing different execution commitments.
                    if prior.header != record.header
                        || prior.body != record.body
                        || prior
                            .authority
                            .unsigned()
                            .map_err(|_| "Prior candidate authority")?
                            != record
                                .authority
                                .unsigned()
                                .map_err(|_| "Candidate authority")?
                    {
                        return Err("Conflicting candidate bytes".into());
                    }
                }
            } else {
                let (count, bytes): (usize, usize) = t
                    .query_row(
                        "SELECT count(*),coalesce(sum(length(raw)),0) FROM candidates",
                        [],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .map_err(storage)?;
                if count >= MAX_PROPOSALS
                    || bytes.checked_add(raw.len()).is_none_or(|n| n > self.budget)
                {
                    return Err("Candidate queue full; retry without eviction".into());
                }
                t.execute(
                    "INSERT INTO candidates VALUES(?1,?2,?3)",
                    params![id.as_slice(), c.height.to_be_bytes().as_slice(), raw],
                )
                .map_err(storage)?;
            }
        }
        #[cfg(test)]
        if std::env::var("BUILD8_SYNTHETIC_A2_CANDIDATE_CRASH").as_deref() == Ok("before_commit") {
            std::process::exit(91);
        }
        t.commit().map_err(storage)?;
        #[cfg(test)]
        if std::env::var("BUILD8_SYNTHETIC_A2_CANDIDATE_CRASH").as_deref() == Ok("after_commit") {
            std::process::exit(92);
        }
        Ok(Retention {
            genesis: self.genesis,
            fingerprint: self.fingerprint,
            block: id,
        })
    }
    /// At most one candidate per owning actor turn. The cursor is local and
    /// optional, not consensus ordering; every returned proposal still enters
    /// ordinary executed VoterActor validation before any vote is requested.
    pub fn next_current(
        &self,
        runtime: &HybridRuntime,
        after: Option<Hash>,
    ) -> Result<Option<Record>> {
        self.capacity()?;
        self.register_runtime(runtime)?;
        let parent = runtime.head().map_err(|_| "Candidate head")?;
        if (parent.genesis, parent.fingerprint) != (self.genesis, self.fingerprint) {
            return Err("Candidate actor context".into());
        }
        let height = parent
            .height
            .checked_add(1)
            .ok_or("Candidate height overflow")?;
        let mut q=self.db.prepare("SELECT CASE WHEN length(id)=32 THEN id ELSE NULL END,CASE WHEN length(height)=8 THEN height ELSE NULL END,CASE WHEN length(raw)<=270871 THEN raw ELSE NULL END FROM candidates WHERE height=?1 AND (?2 IS NULL OR id>?2) ORDER BY id LIMIT 1").map_err(storage)?;
        let mut rows = q
            .query(params![
                height.to_be_bytes().as_slice(),
                after.as_ref().map(|h| h.as_slice())
            ])
            .map_err(storage)?;
        let Some(row) = rows.next().map_err(storage)? else {
            return Ok(None);
        };
        let record = self.row(runtime, row)?;
        runtime
            .chain
            .validate_observation_v2(&record.header, &record.authority, &record.body)
            .map_err(|_| "Restored candidate execution")?;
        Ok(Some(record))
    }
}
