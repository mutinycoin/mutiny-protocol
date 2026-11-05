//! Durable bounded local operation intents. Canonical history remains in the
//! chain store; removing an included/expired queue entry never prunes history.
use mutiny_consensus_v8::{
    Hash, block_envelope::BlockEnvelope, blocks::operation_kind, canonical_store::CanonicalStore,
    freshness::AttestationRefresh, participation::ParticipationAck,
};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::path::Path;
type Result<T> = std::result::Result<T, String>;
pub const MAX_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_ITEMS: usize = 4096;
fn err(e: impl std::fmt::Debug) -> String {
    format!("Operation queue: {e:?}")
}
fn id(raw: &[u8]) -> Hash {
    Sha256::digest(raw).into()
} // Local deduplication, no protocol authority.
pub struct OperationPool {
    db: Connection,
    genesis: Hash,
    fingerprint: Hash,
}
impl OperationPool {
    pub fn open(path: &Path, genesis: Hash, fingerprint: Hash) -> Result<Self> {
        let mut db = Connection::open(path).map_err(err)?;
        db.busy_timeout(std::time::Duration::from_secs(5))
            .map_err(err)?;
        db.execute_batch("PRAGMA journal_mode=WAL;PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS operation_context(singleton INTEGER PRIMARY KEY CHECK(singleton=1),genesis BLOB NOT NULL,fingerprint BLOB NOT NULL,height BLOB NOT NULL CHECK(length(height)=8));
            CREATE TABLE IF NOT EXISTS operation_queue(id BLOB PRIMARY KEY CHECK(length(id)=32),wire BLOB NOT NULL,slot BLOB CHECK(slot IS NULL OR length(slot)=8));").map_err(err)?;
        let t = db.transaction().map_err(err)?;
        let old: Option<(Vec<u8>, Vec<u8>)> = t
            .query_row(
                "SELECT CASE WHEN length(genesis)=32 THEN genesis END,CASE WHEN length(fingerprint)=32 THEN fingerprint END FROM operation_context WHERE singleton=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(err)?;
        if let Some((g, f)) = old {
            if g != genesis || f != fingerprint {
                return Err("Operation queue context mismatch".into());
            }
        } else {
            t.execute(
                "INSERT INTO operation_context VALUES(1,?1,?2,?3)",
                params![
                    genesis.as_slice(),
                    fingerprint.as_slice(),
                    0u64.to_be_bytes().as_slice()
                ],
            )
            .map_err(err)?;
        }
        t.commit().map_err(err)?;
        Ok(Self {
            db,
            genesis,
            fingerprint,
        })
    }
    pub fn context(&self) -> (Hash, Hash) {
        (self.genesis, self.fingerprint)
    }
    /// Only the assembler's full current-parent execution preview may call this.
    /// Equivocation uses the separate historically validated evidence inbox.
    pub(crate) fn insert_validated(&mut self, raw: &[u8]) -> Result<Hash> {
        if raw.len() > 16 * 1024 {
            return Err("Operation size bound".into());
        }
        let kind = operation_kind(raw).map_err(err)?;
        if kind == 17 {
            return Err("Use canonical equivocation inbox".into());
        }
        let slot = match kind {
            11 => Some(ParticipationAck::decode(raw).map_err(err)?.height),
            12 => Some(AttestationRefresh::decode(raw).map_err(err)?.height),
            _ => None,
        };
        let key = id(raw);
        let t = self.db.transaction().map_err(err)?;
        let old: Option<Vec<u8>> = t
            .query_row(
                "SELECT CASE WHEN length(wire)<=16384 THEN wire END FROM operation_queue WHERE id=?1",
                [key.as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        if let Some(old) = old {
            if old != raw {
                return Err("Operation queue digest collision".into());
            }
            return Ok(key);
        }
        let (count, bytes): (usize, usize) = t
            .query_row(
                "SELECT count(*),coalesce(sum(length(wire)),0) FROM operation_queue",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(err)?;
        if count >= MAX_ITEMS || bytes.checked_add(raw.len()).is_none_or(|n| n > MAX_BYTES) {
            return Err("Operation queue capacity".into());
        }
        t.execute(
            "INSERT INTO operation_queue VALUES(?1,?2,?3)",
            params![key.as_slice(), raw, slot.map(|h| h.to_be_bytes().to_vec())],
        )
        .map_err(err)?;
        t.commit().map_err(err)?;
        Ok(key)
    }
    pub fn pending(&self) -> Result<Vec<Vec<u8>>> {
        let mut q = self
            .db
            .prepare("SELECT CASE WHEN length(wire)<=16384 THEN wire END,id FROM operation_queue ORDER BY id LIMIT 4097")
            .map_err(err)?;
        let mut result = Vec::new();
        let mut bytes = 0usize;
        for row in q
            .query_map([], |r| {
                Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(err)?
        {
            let (raw, stored_id) = row.map_err(err)?;
            if id(&raw).as_slice() != stored_id {
                return Err("Operation queue digest mismatch".into());
            }
            operation_kind(&raw).map_err(err)?;
            bytes = bytes.checked_add(raw.len()).ok_or("Queue overflow")?;
            if bytes > MAX_BYTES || result.len() >= MAX_ITEMS {
                return Err("Operation queue corruption/capacity".into());
            }
            result.push(raw);
        }
        Ok(result)
    }
    /// Advance only from authenticated canonical history. A crash between chain
    /// commit and this local reconciliation repeats the same idempotent deletes.
    pub fn reconcile(&mut self, chain: &mut CanonicalStore) -> Result<()> {
        let (head, _) = chain.load().map_err(err)?;
        let old: Vec<u8> = self
            .db
            .query_row(
                "SELECT CASE WHEN length(height)=8 THEN height END FROM operation_context WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(err)?;
        let previous = u64::from_be_bytes(old.try_into().map_err(|_| "Queue cursor width")?);
        if previous > head.height {
            return Err("Operation queue ahead of canonical history".into());
        }
        let t = self.db.transaction().map_err(err)?;
        if previous < head.height {
            for height in previous + 1..=head.height {
                let raw = chain
                    .block_bytes(height)
                    .map_err(err)?
                    .ok_or("Missing canonical history for operation reconciliation")?;
                let block = BlockEnvelope::decode(&raw).map_err(err)?;
                if block.header.candidate.genesis != self.genesis
                    || block.header.candidate.fingerprint != self.fingerprint
                {
                    return Err("Canonical queue context mismatch".into());
                }
                for raw in block.body.operations {
                    t.execute(
                        "DELETE FROM operation_queue WHERE id=?1",
                        [id(&raw).as_slice()],
                    )
                    .map_err(err)?;
                }
            }
        }
        t.execute(
            "DELETE FROM operation_queue WHERE slot IS NOT NULL AND slot<=?1",
            [head.height.to_be_bytes().as_slice()],
        )
        .map_err(err)?;
        t.execute(
            "UPDATE operation_context SET height=?1 WHERE singleton=1",
            [head.height.to_be_bytes().as_slice()],
        )
        .map_err(err)?;
        t.commit().map_err(err)?;
        Ok(())
    }
}
