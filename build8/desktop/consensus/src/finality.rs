//! Durable identity ledger for already fully validated finalized blocks.
//! This is NOT a substitute for block execution, attestation or BFT locking.
use crate::{
    Hash,
    anchors::FinalizedAnchor,
    certificates::{Certificate, Decision, Voter},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::collections::BTreeMap;
use std::path::Path;
#[derive(Debug)]
pub enum FinalityError {
    Storage(rusqlite::Error),
    Invalid,
    WrongContext,
    WrongParent,
    IntegrityHalt,
    Certificate(crate::Error),
}
impl From<rusqlite::Error> for FinalityError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Storage(e)
    }
}
type Result<T> = std::result::Result<T, FinalityError>;
pub struct FinalityLedger {
    db: Connection,
    genesis: Hash,
    fingerprint: Hash,
}
impl FinalityLedger {
    pub fn open(path: &Path, genesis_anchor: &FinalizedAnchor) -> Result<Self> {
        if genesis_anchor.height != 0 || genesis_anchor.network != crate::NETWORK_ID {
            return Err(FinalityError::Invalid);
        }
        let mut db = Connection::open(path)?;
        crate::storage_budget::apply(&db)?;
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch("PRAGMA journal_mode=DELETE;PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS finalized(height BLOB PRIMARY KEY CHECK(length(height)=8),anchor BLOB NOT NULL);
            CREATE TABLE IF NOT EXISTS integrity(id INTEGER PRIMARY KEY CHECK(id=1),halted INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS finality_evidence(height BLOB NOT NULL,block BLOB NOT NULL,certificate BLOB NOT NULL,PRIMARY KEY(height,block));
            INSERT OR IGNORE INTO integrity VALUES(1,0);")?;
        let t = db.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let stored: Option<Vec<u8>> = t
            .query_row(
                "SELECT anchor FROM finalized WHERE height=?1",
                [0u64.to_be_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        match stored {
            Some(raw) if raw != genesis_anchor.encode() => return Err(FinalityError::WrongContext),
            None => {
                t.execute(
                    "INSERT INTO finalized VALUES(?1,?2)",
                    params![0u64.to_be_bytes().as_slice(), genesis_anchor.encode()],
                )?;
            }
            _ => {}
        }
        t.commit()?;
        Ok(Self {
            db,
            genesis: genesis_anchor.genesis,
            fingerprint: genesis_anchor.fingerprint,
        })
    }
    pub fn anchor(&self, height: u64) -> Result<Option<FinalizedAnchor>> {
        let raw: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT anchor FROM finalized WHERE height=?1",
                [height.to_be_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        raw.map(|b| FinalizedAnchor::decode(&b).map_err(|_| FinalityError::Invalid))
            .transpose()
    }
    /// The caller must validate the certificate AND execution/locking rules first.
    /// WARNING: on a conflict this writes the durable integrity halt WITHOUT verifying any
    /// signature; production code must use `record_certificate` (or `verify_evidence` first).
    /// It stays `pub` only because the integration test `tests/anchors.rs` calls it.
    /// Returns false for alternate evidence of an already recorded same block.
    /// It must never invoke reward/state execution a second time for false.
    pub fn record_verified(&mut self, decision: &Decision) -> Result<bool> {
        self.record(decision, None)
    }
    /// The expected decision and registry MUST come from independently validated
    /// block execution and committed authority, not from this certificate. This
    /// method checks cryptographic quorum and parent linkage; it does not replace
    /// the voting actor's lock/proposal checks or atomic canonical state install.
    /// One sufficient proof per block is retained. Evidence selection never
    /// affects canonical identity. A conflicting proof and halt commit together.
    pub fn record_certificate(
        &mut self,
        certificate: &Certificate,
        expected: &Decision,
        registry: &BTreeMap<Hash, Voter>,
    ) -> Result<bool> {
        if expected.purpose != 2 || expected.step != 3 || expected.height == 0 {
            return Err(FinalityError::Invalid);
        }
        certificate
            .verify_quorum(expected, registry)
            .map_err(FinalityError::Certificate)?;
        let raw = certificate.encode().map_err(FinalityError::Certificate)?;
        self.record(expected, Some(&raw))
    }
    pub fn evidence(&self, height: u64, block: Hash) -> Result<Option<Certificate>> {
        let raw: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT certificate FROM finality_evidence WHERE height=?1 AND block=?2",
                params![height.to_be_bytes().as_slice(), block.as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        raw.map(|b| Certificate::decode(&b).map_err(FinalityError::Certificate))
            .transpose()
    }
    pub fn halted(&self) -> Result<bool> {
        Ok(self
            .db
            .query_row("SELECT halted FROM integrity WHERE id=1", [], |r| r.get(0))?)
    }
    fn record(&mut self, decision: &Decision, evidence: Option<&[u8]>) -> Result<bool> {
        let anchor = decision.anchor();
        anchor
            .validate_context(self.genesis, self.fingerprint)
            .map_err(|_| FinalityError::WrongContext)?;
        let t = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let halted: bool =
            t.query_row("SELECT halted FROM integrity WHERE id=1", [], |r| r.get(0))?;
        if halted {
            return Err(FinalityError::IntegrityHalt);
        }
        // Validate parent even for alternate evidence of an existing block.
        // Height zero can only be established by open(), never by a certificate.
        let height = anchor
            .height
            .checked_sub(1)
            .ok_or(FinalityError::WrongParent)?;
        let raw: Vec<u8> = t
            .query_row(
                "SELECT anchor FROM finalized WHERE height=?1",
                [height.to_be_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()?
            .ok_or(FinalityError::WrongParent)?;
        let parent = FinalizedAnchor::decode(&raw).map_err(|_| FinalityError::Invalid)?;
        decision
            .verify_parent(&parent)
            .map_err(|_| FinalityError::WrongParent)?;
        if let Some(proof) = evidence {
            t.execute(
                "INSERT OR IGNORE INTO finality_evidence VALUES(?1,?2,?3)",
                params![
                    anchor.height.to_be_bytes().as_slice(),
                    anchor.block.as_slice(),
                    proof
                ],
            )?;
        }
        let prior: Option<Vec<u8>> = t
            .query_row(
                "SELECT anchor FROM finalized WHERE height=?1",
                [anchor.height.to_be_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(raw) = prior {
            if raw == anchor.encode() {
                t.commit()?;
                return Ok(false);
            }
            t.execute("UPDATE integrity SET halted=1 WHERE id=1", [])?;
            t.commit()?;
            return Err(FinalityError::IntegrityHalt);
        }
        t.execute(
            "INSERT INTO finalized VALUES(?1,?2)",
            params![anchor.height.to_be_bytes().as_slice(), anchor.encode()],
        )?;
        t.commit()?;
        Ok(true)
    }
}
