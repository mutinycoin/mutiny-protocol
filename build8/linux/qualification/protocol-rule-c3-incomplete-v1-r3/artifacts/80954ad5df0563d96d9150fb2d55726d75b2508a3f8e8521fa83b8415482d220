//! Durable admission lifecycle. Canonical reconciliation inputs MUST come from
//! the verified chain executor, never directly from a peer or candidate builder.
use crate::{
    Hash,
    transactions::{Coin, OutPoint, Transfer, TxError},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
pub const MAX_PENDING_BYTES: u64 = 64 * 1024 * 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pending,
    Confirmed,
    Expired,
    Superseded,
    InputSpent,
    Rejected,
}
impl Status {
    pub fn text(self) -> &'static str {
        match self {
            Self::Pending => "PENDING",
            Self::Confirmed => "CONFIRMED",
            Self::Expired => "EXPIRED",
            Self::Superseded => "SUPERSEDED",
            Self::InputSpent => "INPUT_SPENT",
            Self::Rejected => "REJECTED",
        }
    }
    fn parse(s: &str) -> Result<Self> {
        match s {
            "PENDING" => Ok(Self::Pending),
            "CONFIRMED" => Ok(Self::Confirmed),
            "EXPIRED" => Ok(Self::Expired),
            "SUPERSEDED" => Ok(Self::Superseded),
            "INPUT_SPENT" => Ok(Self::InputSpent),
            "REJECTED" => Ok(Self::Rejected),
            _ => Err(PoolError::Integrity),
        }
    }
}
#[derive(Debug)]
pub enum PoolError {
    Storage(rusqlite::Error),
    Invalid(TxError),
    Conflict,
    Capacity,
    Integrity,
    WrongContext,
    StaleBasis,
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
impl Mempool {
    pub fn open(path: &Path, genesis: Hash, fingerprint: Hash, limit: u64) -> Result<Self> {
        if limit == 0 || limit > MAX_PENDING_BYTES {
            return Err(PoolError::Capacity);
        }
        let mut db = Connection::open(path)?;
        crate::storage_budget::apply(&db)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS context(id INTEGER PRIMARY KEY CHECK(id=1), genesis BLOB NOT NULL, fingerprint BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS lifecycle(id BLOB PRIMARY KEY, raw BLOB NOT NULL,status TEXT NOT NULL,reason TEXT NOT NULL,height BLOB NOT NULL CHECK(length(height)=8));
            CREATE TABLE IF NOT EXISTS reserved_input(txid BLOB NOT NULL,idx INTEGER NOT NULL,owner_tx BLOB NOT NULL,PRIMARY KEY(txid,idx));
            CREATE TABLE IF NOT EXISTS basis(id INTEGER PRIMARY KEY CHECK(id=1),height BLOB NOT NULL CHECK(length(height)=8),hash BLOB NOT NULL);")?;
        let t = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored: Option<(Vec<u8>, Vec<u8>)> = t
            .query_row(
                "SELECT genesis,fingerprint FROM context WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        match stored {
            Some((g, f)) if g != genesis || f != fingerprint => {
                return Err(PoolError::WrongContext);
            }
            None => {
                t.execute(
                    "INSERT INTO context VALUES(1,?1,?2)",
                    params![genesis.as_slice(), fingerprint.as_slice()],
                )?;
            }
            _ => {}
        }
        t.commit()?;
        Ok(Self {
            db,
            genesis,
            fingerprint,
            limit,
        })
    }
    pub fn status(&self, id: Hash) -> Result<Option<Status>> {
        let text: Option<String> = self
            .db
            .query_row(
                "SELECT status FROM lifecycle WHERE id=?1",
                [id.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        text.as_deref().map(Status::parse).transpose()
    }
    pub fn pending(&self) -> Result<Vec<Transfer>> {
        let mut s = self
            .db
            .prepare("SELECT raw FROM lifecycle WHERE status='PENDING' ORDER BY id")?;
        let mut out = Vec::new();
        for raw in s.query_map([], |r| r.get::<_, Vec<u8>>(0))? {
            out.push(Transfer::decode(&raw?)?);
        }
        Ok(out)
    }
    pub fn admit(
        &mut self,
        tx: &Transfer,
        height: u64,
        utxos: &BTreeMap<OutPoint, Coin>,
    ) -> Result<Status> {
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let status = Self::admit_in(
            &t,
            tx,
            height,
            utxos,
            self.genesis,
            self.fingerprint,
            self.limit,
        )?;
        t.commit()?;
        Ok(status)
    }
    pub(crate) fn admit_in(
        t: &rusqlite::Transaction<'_>,
        tx: &Transfer,
        height: u64,
        utxos: &BTreeMap<OutPoint, Coin>,
        genesis: Hash,
        fingerprint: Hash,
        limit: u64,
    ) -> Result<Status> {
        let raw = tx.encode()?;
        let id = tx.id()?;
        let prior: Option<(Vec<u8>, String)> = t
            .query_row(
                "SELECT raw,status FROM lifecycle WHERE id=?1",
                [id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        if let Some((bytes, status)) = prior {
            if bytes != raw {
                return Err(PoolError::Conflict);
            }
            return Status::parse(&status);
        }
        tx.verify(genesis, fingerprint, height, utxos)?;
        let total: u64 = t.query_row(
            "SELECT COALESCE(SUM(length(raw)),0) FROM lifecycle WHERE status='PENDING'",
            [],
            |r| r.get(0),
        )?;
        if total
            .checked_add(raw.len() as u64)
            .ok_or(PoolError::Capacity)?
            > limit
        {
            return Err(PoolError::Capacity);
        }
        for input in &tx.inputs {
            let reserved: bool = t.query_row(
                "SELECT EXISTS(SELECT 1 FROM reserved_input WHERE txid=?1 AND idx=?2)",
                params![input.point.transaction.as_slice(), input.point.index],
                |r| r.get(0),
            )?;
            if reserved {
                return Err(PoolError::Conflict);
            }
        }
        t.execute(
            "INSERT INTO lifecycle VALUES(?1,?2,'PENDING','ADMITTED',?3)",
            params![id.as_slice(), raw, height.to_be_bytes().as_slice()],
        )?;
        for input in &tx.inputs {
            t.execute(
                "INSERT INTO reserved_input VALUES(?1,?2,?3)",
                params![
                    input.point.transaction.as_slice(),
                    input.point.index,
                    id.as_slice()
                ],
            )?;
        }
        Ok(Status::Pending)
    }
    /// Idempotent after a verified finalized block. Candidate churn never calls this.
    /// Confirmations supplied here are the block's authenticated transaction IDs.
    pub fn reconcile(
        &mut self,
        height: u64,
        block: Hash,
        confirmed: &BTreeSet<Hash>,
        utxos: &BTreeMap<OutPoint, Coin>,
    ) -> Result<()> {
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        Self::reconcile_in(&t, height, block, confirmed, utxos)?;
        t.commit()?;
        Ok(())
    }
    pub(crate) fn reconcile_in(
        t: &rusqlite::Transaction<'_>,
        height: u64,
        block: Hash,
        confirmed: &BTreeSet<Hash>,
        utxos: &BTreeMap<OutPoint, Coin>,
    ) -> Result<()> {
        let prior: Option<(Vec<u8>, Vec<u8>)> = t
            .query_row("SELECT height,hash FROM basis WHERE id=1", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;
        if let Some((h, b)) = prior {
            let old = u64::from_be_bytes(h.try_into().map_err(|_| PoolError::Integrity)?);
            if height < old {
                return Err(PoolError::StaleBasis);
            }
            if height == old {
                if b == block {
                    return Ok(());
                }
                return Err(PoolError::Integrity);
            }
        }
        let rows = {
            let mut s =
                t.prepare("SELECT id,raw FROM lifecycle WHERE status='PENDING' ORDER BY id")?;
            s.query_map([], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
        };
        for (id, raw) in rows {
            let identity: Hash = id.as_slice().try_into().map_err(|_| PoolError::Integrity)?;
            let tx = Transfer::decode(&raw)?;
            let next = if confirmed.contains(&identity) {
                Some((Status::Confirmed, "CANONICAL_INCLUSION"))
            } else if height >= tx.expiry_height {
                Some((Status::Expired, "NO_REMAINING_VALID_HEIGHT"))
            } else if tx.inputs.iter().any(|i| !utxos.contains_key(&i.point)) {
                Some((Status::InputSpent, "CANONICAL_CONFLICT"))
            } else {
                None
            };
            if let Some((status, reason)) = next {
                t.execute(
                    "UPDATE lifecycle SET status=?1,reason=?2,height=?3 WHERE id=?4",
                    params![status.text(), reason, height.to_be_bytes().as_slice(), id],
                )?;
                t.execute(
                    "DELETE FROM reserved_input WHERE owner_tx=?1",
                    [identity.as_slice()],
                )?;
            }
        }
        t.execute("INSERT INTO basis VALUES(1,?1,?2) ON CONFLICT(id) DO UPDATE SET height=excluded.height,hash=excluded.hash",params![height.to_be_bytes().as_slice(),block.as_slice()])?;
        Ok(())
    }
}
