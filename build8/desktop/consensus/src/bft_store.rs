//! Crash-durable lock storage. Save before reserving/signing a vote. Disk snapshot
//! rollback is a separate production gate; SQLite alone does not prevent it.
use crate::{
    Hash,
    bft::{Lock, LockState},
};
use minicbor::{Decoder, Encoder, data::Type};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::path::Path;
#[derive(Debug)]
pub enum StoreError {
    Storage(rusqlite::Error),
    Context,
    Invalid,
    StaleRevision,
    Regression,
    Overflow,
}
impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e)
    }
}
type Result<T> = std::result::Result<T, StoreError>;
pub(crate) fn encode(s: &LockState) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(5).unwrap().u8(1).unwrap().u64(s.round).unwrap();
    if let Some(l) = &s.locked {
        e.array(2)
            .unwrap()
            .u64(l.round)
            .unwrap()
            .bytes(&l.block)
            .unwrap();
    } else {
        e.null().unwrap();
    }
    if let Some(b) = s.finalized {
        e.bytes(&b).unwrap();
    } else {
        e.null().unwrap();
    }
    e.bool(s.halted).unwrap();
    e.into_writer()
}
pub(crate) fn decode(raw: &[u8]) -> Result<LockState> {
    crate::blocks::canonical(raw, 256).map_err(|_| StoreError::Invalid)?;
    let mut d = Decoder::new(raw);
    let s = (|| -> std::result::Result<LockState, minicbor::decode::Error> {
        fn hash(d: &mut Decoder<'_>) -> std::result::Result<Hash, minicbor::decode::Error> {
            d.bytes()?
                .try_into()
                .map_err(|_| minicbor::decode::Error::message("hash"))
        }
        if d.array()? != Some(5) || d.u8()? != 1 {
            return Err(minicbor::decode::Error::message("state"));
        }
        let round = d.u64()?;
        let locked = if d.datatype()? == Type::Null {
            d.null()?;
            None
        } else {
            if d.array()? != Some(2) {
                return Err(minicbor::decode::Error::message("lock"));
            }
            Some(Lock {
                round: d.u64()?,
                block: hash(&mut d)?,
            })
        };
        let finalized = if d.datatype()? == Type::Null {
            d.null()?;
            None
        } else {
            Some(hash(&mut d)?)
        };
        Ok(LockState {
            round,
            locked,
            finalized,
            halted: d.bool()?,
        })
    })()
    .map_err(|_| StoreError::Invalid)?;
    if s.locked.as_ref().is_some_and(|l| l.round > s.round) || encode(&s) != raw {
        return Err(StoreError::Invalid);
    }
    Ok(s)
}
pub struct LockStore {
    db: Connection,
}
impl LockStore {
    pub fn open(path: &Path, context: Hash, initial_height: u64) -> Result<Self> {
        let mut db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch("PRAGMA journal_mode=DELETE;PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS bft_state(id INTEGER PRIMARY KEY CHECK(id=1),context BLOB NOT NULL,height BLOB NOT NULL,revision BLOB NOT NULL,state BLOB NOT NULL);")?;
        let t = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old: Option<Vec<u8>> = t
            .query_row("SELECT context FROM bft_state WHERE id=1", [], |r| r.get(0))
            .optional()?;
        if let Some(c) = old {
            if c != context {
                return Err(StoreError::Context);
            }
        } else {
            let s = LockState {
                round: 0,
                locked: None,
                finalized: None,
                halted: false,
            };
            t.execute(
                "INSERT INTO bft_state VALUES(1,?1,?2,?3,?4)",
                params![
                    context.as_slice(),
                    initial_height.to_be_bytes().as_slice(),
                    0u64.to_be_bytes().as_slice(),
                    encode(&s)
                ],
            )?;
        }
        t.commit()?;
        Ok(Self { db })
    }
    pub fn load(&self) -> Result<(u64, u64, LockState)> {
        let (h, r, s): (Vec<u8>, Vec<u8>, Vec<u8>) = self.db.query_row(
            "SELECT height,revision,state FROM bft_state WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        Ok((
            u64::from_be_bytes(h.try_into().map_err(|_| StoreError::Invalid)?),
            u64::from_be_bytes(r.try_into().map_err(|_| StoreError::Invalid)?),
            decode(&s)?,
        ))
    }
    pub fn save(&mut self, height: u64, revision: u64, next: &LockState) -> Result<u64> {
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (h, r, s): (Vec<u8>, Vec<u8>, Vec<u8>) = t.query_row(
            "SELECT height,revision,state FROM bft_state WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if h != height.to_be_bytes() || r != revision.to_be_bytes() {
            return Err(StoreError::StaleRevision);
        }
        let old = decode(&s)?;
        let raw = encode(next);
        decode(&raw)?;
        if next.round < old.round
            || (old.halted && !next.halted)
            || old.finalized.is_some_and(|b| next.finalized != Some(b))
        {
            return Err(StoreError::Regression);
        }
        let updated = revision.checked_add(1).ok_or(StoreError::Overflow)?;
        t.execute(
            "UPDATE bft_state SET revision=?1,state=?2 WHERE id=1",
            params![updated.to_be_bytes().as_slice(), raw],
        )?;
        t.commit()?;
        Ok(updated)
    }
    /// Move only after canonical block execution/finality was durably installed.
    pub fn advance(&mut self, height: u64, revision: u64, finalized_block: Hash) -> Result<u64> {
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (h, r, s): (Vec<u8>, Vec<u8>, Vec<u8>) = t.query_row(
            "SELECT height,revision,state FROM bft_state WHERE id=1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if h != height.to_be_bytes() || r != revision.to_be_bytes() {
            return Err(StoreError::StaleRevision);
        }
        let old = decode(&s)?;
        if old.halted || old.finalized != Some(finalized_block) {
            return Err(StoreError::Regression);
        }
        let next_height = height.checked_add(1).ok_or(StoreError::Overflow)?;
        let next_revision = revision.checked_add(1).ok_or(StoreError::Overflow)?;
        let next = LockState {
            round: 0,
            locked: None,
            finalized: None,
            halted: false,
        };
        t.execute(
            "UPDATE bft_state SET height=?1,revision=?2,state=?3 WHERE id=1",
            params![
                next_height.to_be_bytes().as_slice(),
                next_revision.to_be_bytes().as_slice(),
                encode(&next)
            ],
        )?;
        t.commit()?;
        Ok(next_revision)
    }
}
