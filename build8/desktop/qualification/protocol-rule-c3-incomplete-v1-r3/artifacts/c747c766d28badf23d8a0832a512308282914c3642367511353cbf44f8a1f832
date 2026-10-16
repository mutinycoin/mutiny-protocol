//! Bounded durable hybrid transaction admission candidate. Only the verified
//! canonical executor may supply a basis/confirmation set. Peer claims are not
//! a basis. This separate database has no V1 decoding or migration fallback.
pub use crate::mempool::Status;
use crate::{
    Hash,
    anchors::FinalizedAnchor,
    evidence_history_v2::History,
    execution::State,
    hybrid_transaction_v2::{Inclusion, Transaction},
    transactions::{OutPoint, TxError},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{collections::BTreeSet, path::Path};
pub const MAX_PENDING_BYTES: u64 = 64 * 1024 * 1024;
// Local admission/storage limits, not consensus pruning rules.
const MAX_LIFECYCLE_ROWS: u64 = 65536;
const DATABASE_BYTES: u64 = 128 * 1024 * 1024;
const APP_ID: i64 = 0x4d554d32;
const SCHEMA: [(&str, &str); 5] = [
    (
        "context_v2",
        "CREATE TABLE context_v2(id INTEGER PRIMARY KEY CHECK(id=1),genesis BLOB NOT NULL CHECK(length(genesis)=32),fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32))",
    ),
    (
        "basis_v2",
        "CREATE TABLE basis_v2(id INTEGER PRIMARY KEY CHECK(id=1),anchor BLOB NOT NULL,state_root BLOB NOT NULL CHECK(length(state_root)=32))",
    ),
    (
        "lifecycle_v2",
        "CREATE TABLE lifecycle_v2(id BLOB PRIMARY KEY CHECK(length(id)=32),raw BLOB NOT NULL CHECK(length(raw) BETWEEN 1 AND 16384),status TEXT NOT NULL CHECK(status IN ('PENDING','CONFIRMED','EXPIRED','INPUT_SPENT','REJECTED')))",
    ),
    (
        "inputs_v2",
        "CREATE TABLE inputs_v2(txid BLOB NOT NULL CHECK(length(txid)=32),idx INTEGER NOT NULL,owner BLOB NOT NULL REFERENCES lifecycle_v2(id),PRIMARY KEY(txid,idx))",
    ),
    (
        "rotations_v2",
        "CREATE TABLE rotations_v2(authority BLOB PRIMARY KEY CHECK(length(authority)=32),owner BLOB NOT NULL REFERENCES lifecycle_v2(id))",
    ),
];

#[derive(Debug)]
pub enum PoolError {
    Storage(rusqlite::Error),
    Invalid(TxError),
    Context,
    StaleBasis,
    Integrity,
    Conflict,
    Capacity,
}
impl From<rusqlite::Error> for PoolError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e)
    }
}
impl From<TxError> for PoolError {
    fn from(e: TxError) -> Self {
        Self::Invalid(e)
    }
}
type Result<T> = std::result::Result<T, PoolError>;
pub struct Mempool {
    db: Connection,
    genesis: Hash,
    fingerprint: Hash,
    limit: u64,
}
fn status(s: &str) -> Result<Status> {
    Ok(match s {
        "PENDING" => Status::Pending,
        "CONFIRMED" => Status::Confirmed,
        "EXPIRED" => Status::Expired,
        "INPUT_SPENT" => Status::InputSpent,
        "REJECTED" => Status::Rejected,
        _ => return Err(PoolError::Integrity),
    })
}
fn context(a: &FinalizedAnchor, g: Hash, f: Hash) -> Result<()> {
    a.validate_context(g, f).map_err(|_| PoolError::Context)
}
fn state_root(s: &State) -> Result<Hash> {
    s.root().map_err(|_| PoolError::Integrity)
}
fn rows(db: &Connection) -> Result<Vec<(Hash, Vec<u8>)>> {
    let mut q=db.prepare("SELECT CASE WHEN length(id)=32 THEN id ELSE NULL END,CASE WHEN length(raw) BETWEEN 1 AND 16384 THEN raw ELSE NULL END FROM lifecycle_v2 WHERE status='PENDING' ORDER BY id LIMIT 65537")?;
    let mut out = Vec::new();
    let mut bytes = 0u64;
    for item in q.query_map([], |r| {
        Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
    })? {
        let (id, raw) = item?;
        bytes = bytes
            .checked_add(raw.len() as u64)
            .ok_or(PoolError::Capacity)?;
        if bytes > MAX_PENDING_BYTES || out.len() >= MAX_LIFECYCLE_ROWS as usize {
            return Err(PoolError::Capacity);
        }
        out.push((id.try_into().map_err(|_| PoolError::Integrity)?, raw));
    }
    Ok(out)
}
// Validate within the operation's snapshot, before executing application SQL.
// This detects incompatible/corrupt caches; it is not authentication against an
// attacker with arbitrary access to the process or database contents.
fn validate_storage(db: &Connection, genesis: Hash, fingerprint: Hash) -> Result<()> {
    let app: i64 = db.pragma_query_value(None, "application_id", |r| r.get(0))?;
    let version: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
    let count: i64 = db.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
    if app != APP_ID || version != 2 || count != 8 {
        return Err(PoolError::Integrity);
    }
    for (name, sql) in SCHEMA {
        let actual: String = db.query_row("SELECT CASE WHEN length(CAST(sql AS BLOB))<=1024 THEN sql ELSE NULL END FROM sqlite_schema WHERE type='table' AND name=?1 AND tbl_name=?1", [name], |r| r.get(0))?;
        if actual != sql {
            return Err(PoolError::Integrity);
        }
    }
    for table in ["lifecycle_v2", "inputs_v2", "rotations_v2"] {
        let index = format!("sqlite_autoindex_{table}_1");
        let n: i64 = db.query_row("SELECT count(*) FROM sqlite_schema WHERE type='index' AND name=?1 AND tbl_name=?2 AND sql IS NULL", params![index, table], |r| r.get(0))?;
        if n != 1 {
            return Err(PoolError::Integrity);
        }
    }
    let count: i64 = db.query_row("SELECT count(*) FROM context_v2", [], |r| r.get(0))?;
    let (g, f): (Vec<u8>, Vec<u8>) = db.query_row("SELECT CASE WHEN typeof(genesis)='blob' AND length(genesis)=32 THEN genesis ELSE NULL END,CASE WHEN typeof(fingerprint)='blob' AND length(fingerprint)=32 THEN fingerprint ELSE NULL END FROM context_v2 WHERE id=1", [], |r| Ok((r.get(0)?,r.get(1)?)))?;
    if count != 1 || g != genesis || f != fingerprint {
        return Err(PoolError::Context);
    }
    Ok(())
}
fn pending_rows(db: &Connection) -> Result<Vec<Transaction>> {
    rows(db)?
        .into_iter()
        .map(|(id, raw)| {
            let t = Transaction::decode(&raw)?;
            if t.id()? != id {
                return Err(PoolError::Integrity);
            }
            Ok(t)
        })
        .collect()
}
fn reserve(db: &Connection, id: Hash, tx: &Transaction) -> Result<()> {
    for point in tx.inputs() {
        db.execute(
            "INSERT INTO inputs_v2 VALUES(?1,?2,?3)",
            params![point.transaction.as_slice(), point.index, id.as_slice()],
        )?;
    }
    // A funded rotation (tag 25) also reserves its wallet authority: one pending rotation per
    // authority, first seen wins (Lane P design 3.7, resource tag 2).
    if let Some(authority) = tx.rotation_authority() {
        db.execute(
            "INSERT INTO rotations_v2 VALUES(?1,?2)",
            params![authority.as_slice(), id.as_slice()],
        )?;
    }
    Ok(())
}
/// The History a pending row is re-validated with at reconciliation. A funded rotation's finalized
/// reference was verified when the row was admitted (against the anchors the admitting caller
/// supplied, or the admission parent itself), and finalized history never changes (Lane P design
/// 1.a.5: reconciliation does not re-evaluate R), so the row's own reference is the only anchor it
/// needs. Everything else (window, inputs, authority generation, preconditions, signatures,
/// conservation and fee) is re-checked in full.
fn reconciliation_history(tx: &Transaction) -> Result<History> {
    let mut history = History::default();
    if let Some(envelope) = tx.envelope() {
        history
            .insert_anchor(envelope.reference_height, envelope.reference_block)
            .map_err(|_| PoolError::Integrity)?;
    }
    Ok(history)
}
impl Mempool {
    /// Local cache location for explicit successor-cache creation. No keys or
    /// queued records are removed from this legacy database.
    pub fn cache_path(&self) -> Result<std::path::PathBuf> {
        self.db.path().map(std::path::PathBuf::from).ok_or(PoolError::Context)
    }
    pub fn open(path: &Path, genesis: Hash, fingerprint: Hash, limit: u64) -> Result<Self> {
        if genesis == [0; 32] || fingerprint == [0; 32] {
            return Err(PoolError::Context);
        }
        if limit == 0 || limit > MAX_PENDING_BYTES {
            return Err(PoolError::Capacity);
        }
        let mut db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        let app: i64 = db.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))?;
        let tables: u64 = db.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))?;
        if !((app == 0 && version == 0 && tables == 0) || (app == APP_ID && version == 2)) {
            return Err(PoolError::Context);
        }
        let page_size: u64 = db.pragma_query_value(None, "page_size", |r| r.get(0))?;
        let max = DATABASE_BYTES
            .checked_div(page_size)
            .ok_or(PoolError::Integrity)?;
        let pages: u64 = db.pragma_query_value(None, "page_count", |r| r.get(0))?;
        if max == 0 || pages > max {
            return Err(PoolError::Capacity);
        }
        db.pragma_update(None, "max_page_count", max)?;
        db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;")?;
        let t = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if app == 0 {
            for (_, sql) in SCHEMA {
                t.execute_batch(sql)?;
            }
            t.pragma_update(None, "application_id", APP_ID)?;
            t.pragma_update(None, "user_version", 2)?;
            t.execute(
                "INSERT INTO context_v2 VALUES(1,?1,?2)",
                params![genesis.as_slice(), fingerprint.as_slice()],
            )?;
        }
        validate_storage(&t, genesis, fingerprint)?;
        t.commit()?;
        Ok(Self {
            db,
            genesis,
            fingerprint,
            limit,
        })
    }
    pub fn status(&self, id: Hash) -> Result<Option<Status>> {
        let _snapshot = self.db.unchecked_transaction()?;
        validate_storage(&_snapshot, self.genesis, self.fingerprint)?;
        let s: Option<String> = self
            .db
            .query_row(
                "SELECT CASE WHEN length(CAST(status AS BLOB)) BETWEEN 1 AND 11 THEN status ELSE NULL END FROM lifecycle_v2 WHERE id=?1",
                [id.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        s.as_deref().map(status).transpose()
    }
    pub fn pending(&self) -> Result<Vec<Transaction>> {
        let snapshot = self.db.unchecked_transaction()?;
        validate_storage(&snapshot, self.genesis, self.fingerprint)?;
        let pending = pending_rows(&snapshot)?;
        snapshot.commit()?;
        Ok(pending)
    }
    /// Local reconciliation cursor, not authority. The canonical store must
    /// compare this anchor/root with its own authenticated historical state.
    pub fn basis(&self) -> Result<Option<(FinalizedAnchor, Hash)>> {
        let _snapshot = self.db.unchecked_transaction()?;
        validate_storage(&_snapshot, self.genesis, self.fingerprint)?;
        let raw: Option<(Vec<u8>, Vec<u8>)> = self
            .db
            .query_row(
                "SELECT CASE WHEN length(anchor) BETWEEN 1 AND 256 THEN anchor ELSE NULL END,CASE WHEN length(state_root)=32 THEN state_root ELSE NULL END FROM basis_v2 WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        raw.map(|(a, r)| {
            let a = FinalizedAnchor::decode(&a).map_err(|_| PoolError::Integrity)?;
            context(&a, self.genesis, self.fingerprint)?;
            Ok((a, r.try_into().map_err(|_| PoolError::Integrity)?))
        })
        .transpose()
    }
    /// Assembly must name the exact verified basis; stale pending rows cannot
    /// implicitly choose a parent or grant owner authority.
    pub fn pending_at(&self, anchor: &FinalizedAnchor, state: &State) -> Result<Vec<Transaction>> {
        context(anchor, self.genesis, self.fingerprint)?;
        let root = state_root(state)?;
        let snapshot = self.db.unchecked_transaction()?;
        validate_storage(&snapshot, self.genesis, self.fingerprint)?;
        let basis: Option<(Vec<u8>, Vec<u8>)> = self
            .db
            .query_row(
                "SELECT CASE WHEN length(anchor) BETWEEN 1 AND 256 THEN anchor ELSE NULL END,CASE WHEN length(state_root)=32 THEN state_root ELSE NULL END FROM basis_v2 WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if basis != Some((anchor.encode(), root.to_vec())) {
            return Err(PoolError::StaleBasis);
        }
        let pending = pending_rows(&snapshot)?;
        snapshot.commit()?;
        Ok(pending)
    }
    /// Advance only after certified canonical installation, including after a
    /// restart. Reconciles owner rotation as well as UTXO/maturity/expiry state.
    /// Advance one height at a time so confirmations cannot be skipped.
    pub fn reconcile(
        &mut self,
        anchor: &FinalizedAnchor,
        state: &State,
        confirmed: &BTreeSet<Hash>,
    ) -> Result<()> {
        context(anchor, self.genesis, self.fingerprint)?;
        let root = state_root(state)?;
        let height = anchor.height.checked_add(1).ok_or(PoolError::Capacity)?;
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_storage(&t, self.genesis, self.fingerprint)?;
        let old: Option<(Vec<u8>, Vec<u8>)> = t
            .query_row(
                "SELECT CASE WHEN length(anchor) BETWEEN 1 AND 256 THEN anchor ELSE NULL END,CASE WHEN length(state_root)=32 THEN state_root ELSE NULL END FROM basis_v2 WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let mut same_basis = false;
        if let Some((raw, old_root)) = old {
            let prior = FinalizedAnchor::decode(&raw).map_err(|_| PoolError::Integrity)?;
            if prior == *anchor && old_root == root {
                same_basis = true;
            }
            if !same_basis && prior.height.checked_add(1) != Some(anchor.height) {
                return Err(PoolError::StaleBasis);
            }
        }
        let pending = rows(&t)?;
        t.execute("DELETE FROM inputs_v2", [])?;
        t.execute("DELETE FROM rotations_v2", [])?;
        for (id, raw) in pending {
            let tx = Transaction::decode(&raw)?;
            if tx.id()? != id {
                return Err(PoolError::Integrity);
            }
            let next = if !same_basis && confirmed.contains(&id) {
                Status::Confirmed
            } else if tx.window().1 < height {
                Status::Expired
            } else if tx.inputs().iter().any(|p| !state.coins.contains_key(p)) {
                Status::InputSpent
            } else if tx
                .verify(
                    &Inclusion {
                        parent: anchor,
                        history: &reconciliation_history(&tx)?,
                    },
                    state,
                )
                .is_err()
            {
                Status::Rejected
            } else {
                Status::Pending
            };
            t.execute(
                "UPDATE lifecycle_v2 SET status=?1 WHERE id=?2",
                params![next.text(), id.as_slice()],
            )?;
            if next == Status::Pending {
                reserve(&t, id, &tx)?;
            }
        }
        t.execute(
            "INSERT OR REPLACE INTO basis_v2 VALUES(1,?1,?2)",
            params![anchor.encode(), root.as_slice()],
        )?;
        t.commit()?;
        Ok(())
    }
    /// No pending transaction creates authority or spendable change for another
    /// admission. Assembly may re-evaluate ordered transactions separately.
    /// Without a History, a funded rotation verifies only if its finalized reference is `anchor`
    /// itself (fail closed); `admit_with_history` accepts the store's anchors for an older one.
    pub fn admit(
        &mut self,
        tx: &Transaction,
        anchor: &FinalizedAnchor,
        state: &State,
    ) -> Result<Status> {
        self.admit_with_history(tx, anchor, state, &History::default())
    }
    /// `admit` with the caller's locally authenticated History, whose anchors (canonical block
    /// hashes from the local canonical store, never a peer's claim) resolve a funded rotation's
    /// finalized reference older than `anchor` (Lane P design 1.a.5: admission looks it up).
    pub fn admit_with_history(
        &mut self,
        tx: &Transaction,
        anchor: &FinalizedAnchor,
        state: &State,
        history: &History,
    ) -> Result<Status> {
        context(anchor, self.genesis, self.fingerprint)?;
        let root = state_root(state)?;
        anchor.height.checked_add(1).ok_or(PoolError::Capacity)?;
        let raw = tx.encode()?;
        let id = tx.id()?;
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        validate_storage(&t, self.genesis, self.fingerprint)?;
        let basis: Option<(Vec<u8>, Vec<u8>)> = t
            .query_row(
                "SELECT CASE WHEN length(anchor) BETWEEN 1 AND 256 THEN anchor ELSE NULL END,CASE WHEN length(state_root)=32 THEN state_root ELSE NULL END FROM basis_v2 WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if basis != Some((anchor.encode(), root.to_vec())) {
            return Err(PoolError::StaleBasis);
        }
        let prior: Option<(Vec<u8>, String)> = t
            .query_row(
                "SELECT CASE WHEN length(raw) BETWEEN 1 AND 16384 THEN raw ELSE NULL END,CASE WHEN length(CAST(status AS BLOB)) BETWEEN 1 AND 11 THEN status ELSE NULL END FROM lifecycle_v2 WHERE id=?1",
                [id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((bytes, s)) = prior {
            if bytes != raw {
                return Err(PoolError::Conflict);
            }
            return status(&s);
        }
        tx.verify(&Inclusion { parent: anchor, history }, state)?;
        let (count,total):(u64,u64)=t.query_row("SELECT count(*),COALESCE(SUM(CASE WHEN status='PENDING' THEN length(raw) ELSE 0 END),0) FROM lifecycle_v2",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
        if count >= MAX_LIFECYCLE_ROWS
            || total
                .checked_add(raw.len() as u64)
                .is_none_or(|n| n > self.limit)
        {
            return Err(PoolError::Capacity);
        }
        for point in tx.inputs() {
            let exists: bool = t.query_row(
                "SELECT EXISTS(SELECT 1 FROM inputs_v2 WHERE txid=?1 AND idx=?2)",
                params![point.transaction.as_slice(), point.index],
                |r| r.get(0),
            )?;
            if exists {
                return Err(PoolError::Conflict);
            }
        }
        if let Some(authority) = tx.rotation_authority() {
            let exists: bool = t.query_row(
                "SELECT EXISTS(SELECT 1 FROM rotations_v2 WHERE authority=?1)",
                [authority.as_slice()],
                |r| r.get(0),
            )?;
            if exists {
                return Err(PoolError::Conflict);
            }
        }
        t.execute(
            "INSERT INTO lifecycle_v2 VALUES(?1,?2,'PENDING')",
            params![id.as_slice(), raw],
        )?;
        reserve(&t, id, tx)?;
        t.commit()?;
        Ok(Status::Pending)
    }
    /// Every `reference_height` of a pending funded rotation's envelope. The History the
    /// assembler trial-executes pool items with must hold their anchors (design 1.a.3; the
    /// `op_envelope_v1::PendingReferences` hook of `CanonicalStore::prepare_pending`).
    pub fn pending_reference_heights(&self) -> Result<BTreeSet<u64>> {
        Ok(self
            .pending()?
            .iter()
            .filter_map(|tx| tx.envelope().map(|e| e.reference_height))
            .collect())
    }
    pub fn reserved_inputs(&self) -> Result<BTreeSet<OutPoint>> {
        let _snapshot = self.db.unchecked_transaction()?;
        validate_storage(&_snapshot, self.genesis, self.fingerprint)?;
        let mut q = self
            .db
            .prepare("SELECT CASE WHEN length(txid)=32 THEN txid ELSE NULL END,idx FROM inputs_v2 ORDER BY txid,idx")?;
        let mut out = BTreeSet::new();
        for r in q.query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, u32>(1)?)))? {
            let (id, index) = r?;
            if out.len() >= MAX_PENDING_BYTES as usize / 32 {
                return Err(PoolError::Capacity);
            }
            out.insert(OutPoint {
                transaction: id.try_into().map_err(|_| PoolError::Integrity)?,
                index,
            });
        }
        Ok(out)
    }
}
