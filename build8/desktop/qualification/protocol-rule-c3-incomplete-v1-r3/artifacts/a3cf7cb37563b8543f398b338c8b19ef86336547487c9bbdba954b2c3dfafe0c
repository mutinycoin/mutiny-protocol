//! Recoverable disk/TPM-extend ordering for signing reservations. The TPM backend
//! must pin a non-resettable NV index for the lifetime of the admitted key. This
//! module cannot supply that hardware policy or protect an arbitrarily reset NV.
use crate::{Hash, domain_hash};
use minicbor::Encoder;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::path::Path;
#[derive(Debug)]
pub enum AnchorError {
    Storage(rusqlite::Error),
    Backend,
    Context,
    Rollback,
    Invalid,
    PendingDifferentReservation,
}
impl From<rusqlite::Error> for AnchorError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e)
    }
}
type Result<T> = std::result::Result<T, AnchorError>;
/// Implementations must serialize all use of the pinned index and persist each
/// extension before returning. TPM_NV_Extend computes SHA256(old || input).
/// Replacing/undefining/reinitializing that index while the key remains usable
/// is forbidden. NV_RATE/failures must stop signing, never fall back to disk.
pub trait PersistentAnchor {
    fn read(&mut self) -> std::result::Result<Hash, String>;
    fn extend(&mut self, event: Hash) -> std::result::Result<(), String>;
}
pub struct AnchorJournal {
    db: Connection,
    context: Hash,
}
impl AnchorJournal {
    pub fn open(path: &Path, context: Hash, anchor: &mut impl PersistentAnchor) -> Result<Self> {
        let mut db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch("PRAGMA journal_mode=DELETE;PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS signing_anchor(id INTEGER PRIMARY KEY CHECK(id=1),context BLOB NOT NULL,tip BLOB NOT NULL,last_event BLOB,pending_event BLOB,pending_tip BLOB);")?;
        let t = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old: Option<Vec<u8>> = t
            .query_row("SELECT context FROM signing_anchor WHERE id=1", [], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(old) = old {
            if old != context {
                return Err(AnchorError::Context);
            }
        } else {
            if anchor.read().map_err(|_| AnchorError::Backend)? != [0; 32] {
                return Err(AnchorError::Rollback);
            }
            t.execute(
                "INSERT INTO signing_anchor VALUES(1,?1,?2,NULL,NULL,NULL)",
                params![context.as_slice(), [0u8; 32].as_slice()],
            )?;
        }
        t.commit()?;
        Ok(Self { db, context })
    }
    /// Called after VoteJournal reservation but before TPM signing. An interrupted
    /// extension is recovered from its durable intent; unrelated pending work
    /// cannot be skipped. A rolled-back disk never causes a reset of the TPM tip.
    pub fn protect(&mut self, message: &[u8], anchor: &mut impl PersistentAnchor) -> Result<()> {
        if message.is_empty() || message.len() > 4096 {
            return Err(AnchorError::Invalid);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(3)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&self.context)
            .unwrap()
            .bytes(message)
            .unwrap();
        let event = domain_hash(b"MUTINY-BUILD8-SIGNING-ANCHOR-EVENT-V1", &e.into_writer());
        // A single serialized caller must own the NV backend as well as this
        // DB. The SQL lock also excludes independent disk writers during intent.
        {
            let t = self
                .db
                .transaction_with_behavior(TransactionBehavior::Immediate)?;
            type Row = (Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>);
            let (tip, last, pending, next): Row = t.query_row(
                "SELECT tip,last_event,pending_event,pending_tip FROM signing_anchor WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
            let tip: Hash = tip.try_into().map_err(|_| AnchorError::Invalid)?;
            let hardware = anchor.read().map_err(|_| AnchorError::Backend)?;
            if let Some(pending) = pending {
                if pending != event {
                    return Err(AnchorError::PendingDifferentReservation);
                }
                let next: Hash = next
                    .ok_or(AnchorError::Invalid)?
                    .try_into()
                    .map_err(|_| AnchorError::Invalid)?;
                let expected: Hash =
                    Sha256::digest([tip.as_slice(), event.as_slice()].concat()).into();
                if next != expected {
                    return Err(AnchorError::Invalid);
                }
                if hardware != tip && hardware != next {
                    return Err(AnchorError::Rollback);
                }
            } else {
                if next.is_some() {
                    return Err(AnchorError::Invalid);
                }
                if hardware != tip {
                    return Err(AnchorError::Rollback);
                }
                if last.as_deref() == Some(event.as_slice()) {
                    return Ok(());
                }
                let next: Hash = Sha256::digest([tip.as_slice(), event.as_slice()].concat()).into();
                t.execute(
                    "UPDATE signing_anchor SET pending_event=?1,pending_tip=?2 WHERE id=1",
                    params![event.as_slice(), next.as_slice()],
                )?;
            }
            t.commit()?;
        }
        // Intent is on disk BEFORE a TPM mutation. Hold the transaction across
        // read/extend/read/finalize to serialize cooperating processes.
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (tip, pending, next): (Vec<u8>, Vec<u8>, Vec<u8>) = t.query_row(
            "SELECT tip,pending_event,pending_tip FROM signing_anchor WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        if pending != event {
            return Err(AnchorError::PendingDifferentReservation);
        }
        let tip: Hash = tip.try_into().map_err(|_| AnchorError::Invalid)?;
        let next: Hash = next.try_into().map_err(|_| AnchorError::Invalid)?;
        let expected: Hash = Sha256::digest([tip.as_slice(), event.as_slice()].concat()).into();
        if next != expected {
            return Err(AnchorError::Invalid);
        }
        let hardware = anchor.read().map_err(|_| AnchorError::Backend)?;
        if hardware == tip {
            anchor.extend(event).map_err(|_| AnchorError::Backend)?;
        } else if hardware != next {
            return Err(AnchorError::Rollback);
        }
        if anchor.read().map_err(|_| AnchorError::Backend)? != next {
            return Err(AnchorError::Rollback);
        }
        t.execute("UPDATE signing_anchor SET tip=?1,last_event=?2,pending_event=NULL,pending_tip=NULL WHERE id=1",params![next.as_slice(),event.as_slice()])?;
        t.commit()?;
        Ok(())
    }
}
