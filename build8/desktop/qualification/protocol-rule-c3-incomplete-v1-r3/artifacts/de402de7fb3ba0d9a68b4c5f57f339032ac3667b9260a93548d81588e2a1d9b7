//! Durable signing reservations, not a consensus or signature verifier.
//! The integrating voter must validate the canonical message, proposal/POL and
//! locks before reservation, and only call the TPM after reservation commits.
//! Never delete/recreate this database to recover from an error or restore an old
//! snapshot while retaining the same signing key. Disk rollback requires a
//! separate anti-rollback mechanism before production enrollment.
use crate::Hash;
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::path::Path;

#[derive(Debug)]
pub enum JournalError {
    Storage(rusqlite::Error),
    ContextMismatch,
    ConflictingVote,
    StaleHeight,
    InvalidMessage,
    MissingReservation,
    ConflictingSignature,
    Capacity,
}
impl From<rusqlite::Error> for JournalError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Storage(value)
    }
}
type Result<T> = std::result::Result<T, JournalError>;

#[derive(Clone, Copy, Debug)]
pub enum Step {
    Propose = 0,
    Prevote = 1,
    Precommit = 2,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reservation {
    /// The exact message was durably reserved; it may now be signed.
    ReadyToSign,
    /// Retransmit these bytes instead of invoking the TPM again.
    AlreadySigned([u8; 64]),
}

pub struct VoteJournal {
    db: Connection,
}
impl VoteJournal {
    /// `context` commits the network, Genesis, protocol, lineage and hardware key
    /// generation. The integrating protocol defines and validates that commitment.
    pub fn open(path: &Path, context: Hash) -> Result<Self> {
        let mut db = Connection::open(path)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(
            "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS journal_context(
              id INTEGER PRIMARY KEY CHECK(id=1), context BLOB NOT NULL CHECK(length(context)=32));
            CREATE TABLE IF NOT EXISTS votes(
              height BLOB NOT NULL CHECK(length(height)=8),
              round BLOB NOT NULL CHECK(length(round)=8),
              step INTEGER NOT NULL CHECK(step IN (0,1,2)),
              message BLOB NOT NULL CHECK(length(message) BETWEEN 1 AND 4096),
              signature BLOB CHECK(signature IS NULL OR length(signature)=64),
              PRIMARY KEY(height,round,step));",
        )?;
        let tx = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored: Option<Vec<u8>> = tx
            .query_row("SELECT context FROM journal_context WHERE id=1", [], |r| {
                r.get(0)
            })
            .optional()?;
        match stored {
            Some(value) if value != context => return Err(JournalError::ContextMismatch),
            None => {
                tx.execute(
                    "INSERT INTO journal_context VALUES(1,?1)",
                    [context.as_slice()],
                )?;
            }
            _ => {}
        }
        tx.commit()?;
        Ok(Self { db })
    }

    /// Reserve the full validated sign bytes, not merely a caller-supplied hash.
    pub fn reserve(
        &mut self,
        height: u64,
        round: u64,
        step: Step,
        message: &[u8],
    ) -> Result<Reservation> {
        if message.is_empty() || message.len() > 4096 {
            return Err(JournalError::InvalidMessage);
        }
        let h = height.to_be_bytes();
        let r = round.to_be_bytes();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old: Option<(Vec<u8>, Option<Vec<u8>>)> = tx
            .query_row(
                "SELECT message,signature FROM votes WHERE height=?1 AND round=?2 AND step=?3",
                params![h.as_slice(), r.as_slice(), step as u8],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((bytes, signature)) = old {
            if bytes != message {
                return Err(JournalError::ConflictingVote);
            }
            return match signature {
                Some(s) => Ok(Reservation::AlreadySigned(
                    s.try_into().map_err(|_| JournalError::InvalidMessage)?,
                )),
                None => Ok(Reservation::ReadyToSign),
            };
        }
        let highest: Option<Vec<u8>> =
            tx.query_row("SELECT MAX(height) FROM votes", [], |row| row.get(0))?;
        if highest.as_deref().is_some_and(|old| old > h.as_slice()) {
            return Err(JournalError::StaleHeight);
        }
        // Advancing height and dropping old reservations are one durable atomic
        // transaction. The new row preserves the signing high-water mark.
        tx.execute("DELETE FROM votes WHERE height < ?1", [h.as_slice()])?;
        let count: u64 = tx.query_row("SELECT COUNT(*) FROM votes", [], |row| row.get(0))?;
        if count >= 100_000 {
            return Err(JournalError::Capacity);
        }
        tx.execute(
            "INSERT INTO votes(height,round,step,message) VALUES(?1,?2,?3,?4)",
            params![h.as_slice(), r.as_slice(), step as u8, message],
        )?;
        tx.commit()?;
        Ok(Reservation::ReadyToSign)
    }

    /// Persist a verified TPM signature before publishing it. The integrating
    /// caller checks its P-256 encoding/signature against the exact reservation.
    pub fn record_signature(
        &mut self,
        height: u64,
        round: u64,
        step: Step,
        message: &[u8],
        signature: [u8; 64],
    ) -> Result<()> {
        let h = height.to_be_bytes();
        let r = round.to_be_bytes();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let old: Option<(Vec<u8>, Option<Vec<u8>>)> = tx
            .query_row(
                "SELECT message,signature FROM votes WHERE height=?1 AND round=?2 AND step=?3",
                params![h.as_slice(), r.as_slice(), step as u8],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (bytes, prior) = old.ok_or(JournalError::MissingReservation)?;
        if bytes != message {
            return Err(JournalError::ConflictingVote);
        }
        if prior.as_deref().is_some_and(|p| p != signature) {
            return Err(JournalError::ConflictingSignature);
        }
        tx.execute(
            "UPDATE votes SET signature=?4 WHERE height=?1 AND round=?2 AND step=?3",
            params![h.as_slice(), r.as_slice(), step as u8, signature.as_slice()],
        )?;
        tx.commit()?;
        Ok(())
    }
}
