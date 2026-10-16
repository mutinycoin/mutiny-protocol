//! Bounded store-and-forward objects. Delivery ACKs are never settlement proofs.
use crate::{Error, MAX_PAYLOAD, Metadata, Result};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};
pub const MAX_OBJECT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_QUEUE_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_OBJECTS: usize = 8;
pub const MAX_SUBMISSIONS: usize = 2;
pub const MAX_SUBMISSION_BYTES: usize = 32 * 1024;
pub const MAX_REQUESTS: usize = MAX_OBJECTS + MAX_SUBMISSIONS;
pub const MAX_ATTEMPTS: u8 = 8;
pub const MAX_BITMAP_BITS: u16 = 1080;
pub const HISTORY_REQUEST_BYTES: usize = 145;
pub const HISTORY_PAGE_BYTES: usize = 16384;
pub const HISTORY_CONTROL_BYTES: usize = HISTORY_REQUEST_BYTES + HISTORY_PAGE_BYTES;
pub const MAX_HISTORY_CANDIDATES: usize = 6;
/// Actual general queue occupancy. Incomplete and invalid objects also count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GeneralCapacity {
    pub free_objects: usize,
    pub free_bytes: usize,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistoryCapacity {
    pub candidate_entries: usize,
    pub candidate_bytes: usize,
}
/// Atomic transport copies, page first. `fresh` identifies copies this batch
/// created; pre-existing retained bytes are never silently assigned ownership.
pub struct QueuedHistoryPage {
    pub offers: Vec<Offer>,
    pub fresh: Vec<bool>,
}
impl GeneralCapacity {
    /// Budget before inserting either history control. It never uses the
    /// separate submission reservation, and accounts for both full control caps.
    pub fn history_candidates(self) -> HistoryCapacity {
        HistoryCapacity {
            candidate_entries: self.free_objects.saturating_sub(2).min(MAX_HISTORY_CANDIDATES),
            candidate_bytes: self.free_bytes.saturating_sub(HISTORY_CONTROL_BYTES),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ObjectKind {
    SignedTransaction = 1,
    SettlementProof = 2,
    /// Opaque canonical V2 envelope; delivery is not certificate validation.
    CertifiedBlock = 3,
    /// Opaque hybrid vote; delivery never grants quorum weight.
    ContinuityVote = 4,
    /// Parent-bound challenge, not a vote or quorum proof.
    WorkProbeRequest = 5,
    /// Exactly one hybrid liveness fragment; semantic checks remain mandatory.
    WorkProbeFragment = 6,
    /// Public signed recovery history; authority remains a canonical-store check.
    RecoveryEvidence = 7,
    /// Uncertified hybrid proposal. Delivery is neither a vote nor finality.
    BlockProposal = 8,
    SignedOperation = 9,
    StatusQuery = 10,
    StatusReport = 11,
    /// Successor proposal bytes; the endpoint must authenticate its selected rule.
    A2BlockProposal = 12,
    /// Inline A2 evidence carrier; transport hashing is not native authorization.
    A2EvidenceOperation = 13,
    HistoryRequestV1 = 14,
    HistoryPageV1 = 15,
}
impl ObjectKind {
    pub fn max_bytes(self) -> usize {
        match self {
            Self::SignedTransaction | Self::SignedOperation | Self::StatusReport => 16384,
            Self::StatusQuery => 4096,
            Self::WorkProbeRequest => 512,
            Self::WorkProbeFragment => 4096,
            Self::RecoveryEvidence => 256 * 1024,
            Self::BlockProposal => 74257,
            Self::A2BlockProposal => 270871,
            Self::A2EvidenceOperation => 196608,
            Self::HistoryRequestV1 => HISTORY_REQUEST_BYTES,
            Self::HistoryPageV1 => HISTORY_PAGE_BYTES,
            _ => MAX_OBJECT_BYTES,
        }
    }
    fn validate_length(self, length: usize) -> Result<()> {
        if length == 0 || length > self.max_bytes() {
            return Err(Error::Limit);
        }
        Ok(())
    }
    fn parse(n: u8) -> Result<Self> {
        match n {
            1 => Ok(Self::SignedTransaction),
            2 => Ok(Self::SettlementProof),
            3 => Ok(Self::CertifiedBlock),
            4 => Ok(Self::ContinuityVote),
            5 => Ok(Self::WorkProbeRequest),
            6 => Ok(Self::WorkProbeFragment),
            7 => Ok(Self::RecoveryEvidence),
            8 => Ok(Self::BlockProposal),
            9 => Ok(Self::SignedOperation),
            10 => Ok(Self::StatusQuery),
            11 => Ok(Self::StatusReport),
            12 => Ok(Self::A2BlockProposal),
            13 => Ok(Self::A2EvidenceOperation),
            14 => Ok(Self::HistoryRequestV1),
            15 => Ok(Self::HistoryPageV1),
            _ => Err(Error::Encoding),
        }
    }
}
fn count(length: usize) -> Result<u16> {
    if length == 0 || length > MAX_OBJECT_BYTES {
        return Err(Error::Limit);
    }
    Ok(length.div_ceil(MAX_PAYLOAD) as u16)
}
pub fn object_id(kind: ObjectKind, bytes: &[u8]) -> Result<[u8; 32]> {
    kind.validate_length(bytes.len())?;
    count(bytes.len())?;
    let mut h = Sha256::new();
    h.update(b"MUTINY-BUILD8-TRANSPORT-OBJECT-V2\0");
    h.update([kind as u8]);
    h.update((bytes.len() as u32).to_be_bytes());
    h.update(bytes);
    Ok(h.finalize().into())
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    pub id: [u8; 32],
    pub kind: ObjectKind,
    pub length: usize,
}
impl Offer {
    pub fn have(&self, hops: u8) -> Result<(Metadata, Vec<u8>)> {
        if self.id == [0; 32] || hops > 16 {
            return Err(Error::Encoding);
        }
        self.kind.validate_length(self.length)?;
        let c = count(self.length)?;
        let mut p = vec![2, self.kind as u8];
        p.extend_from_slice(&(self.length as u32).to_be_bytes());
        Ok((
            Metadata {
                kind: 1,
                object: self.id,
                fragment: 0,
                count: c,
                hops,
            },
            p,
        ))
    }
    pub fn parse(meta: &Metadata, payload: &[u8]) -> Result<Self> {
        meta.validate()?;
        if meta.kind != 1
            || meta.fragment != 0
            || meta.object == [0; 32]
            || payload.len() != 6
            || payload[0] != 2
        {
            return Err(Error::Encoding);
        }
        let length = u32::from_be_bytes(payload[2..6].try_into().unwrap()) as usize;
        let kind = ObjectKind::parse(payload[1])?;
        kind.validate_length(length)?;
        if count(length)? != meta.count {
            return Err(Error::Encoding);
        }
        Ok(Self {
            id: meta.object,
            kind,
            length,
        })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bitmap {
    pub start: u16,
    pub bits: Vec<bool>,
}
impl Bitmap {
    pub fn encode(&self, total: u16) -> Result<Vec<u8>> {
        if total == 0
            || total > 16384
            || self.bits.is_empty()
            || self.bits.len() > MAX_BITMAP_BITS as usize
            || self.start as usize + self.bits.len() > total as usize
        {
            return Err(Error::Encoding);
        }
        let mut out = vec![2];
        out.extend_from_slice(&self.start.to_be_bytes());
        out.extend_from_slice(&(self.bits.len() as u16).to_be_bytes());
        out.resize(5 + self.bits.len().div_ceil(8), 0);
        for (i, bit) in self.bits.iter().enumerate() {
            if *bit {
                out[5 + i / 8] |= 1 << (i % 8);
            }
        }
        Ok(out)
    }
    pub fn parse(payload: &[u8], total: u16) -> Result<Self> {
        if total == 0
            || total > 16384
            || payload.len() < 6
            || payload.len() > MAX_PAYLOAD
            || payload[0] != 2
        {
            return Err(Error::Encoding);
        }
        let start = u16::from_be_bytes(payload[1..3].try_into().unwrap());
        let n = u16::from_be_bytes(payload[3..5].try_into().unwrap()) as usize;
        if n == 0
            || n > MAX_BITMAP_BITS as usize
            || start as usize + n > total as usize
            || payload.len() != 5 + n.div_ceil(8)
        {
            return Err(Error::Encoding);
        }
        if n % 8 != 0 && payload.last().unwrap() >> (n % 8) != 0 {
            return Err(Error::Encoding);
        }
        Ok(Self {
            start,
            bits: (0..n)
                .map(|i| (payload[5 + i / 8] >> (i % 8)) & 1 == 1)
                .collect(),
        })
    }
}
const PEER_SQL: &str = "CREATE TABLE peer(id BLOB NOT NULL CHECK(length(id)=32))";
const QUEUE_SCHEMA_VERSION: i64 = 7;
const A2_QUEUE_SCHEMA_VERSION: i64 = 8;
const HISTORY_QUEUE_SCHEMA_VERSION: i64 = 9;
const HISTORY_OBJECTS_SQL: &str = "CREATE TABLE objects(id BLOB PRIMARY KEY CHECK(length(id)=32), kind INTEGER NOT NULL CHECK(kind IN (1,2,3,4,5,6,7,8,9,10,11,14,15)), length INTEGER NOT NULL CHECK(length BETWEEN 1 AND 2097152), complete INTEGER NOT NULL CHECK(complete IN (0,1)), invalid INTEGER NOT NULL CHECK(invalid IN (0,1)))";
const HISTORY_A2_OBJECTS_SQL: &str = "CREATE TABLE objects(id BLOB PRIMARY KEY CHECK(length(id)=32), kind INTEGER NOT NULL CHECK(kind IN (1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)), length INTEGER NOT NULL CHECK(length BETWEEN 1 AND 2097152), complete INTEGER NOT NULL CHECK(complete IN (0,1)), invalid INTEGER NOT NULL CHECK(invalid IN (0,1)))";
const A2_OBJECTS_SQL: &str = "CREATE TABLE objects(id BLOB PRIMARY KEY CHECK(length(id)=32), kind INTEGER NOT NULL CHECK(kind IN (1,2,3,4,5,6,7,8,9,10,11,12,13)), length INTEGER NOT NULL CHECK(length BETWEEN 1 AND 2097152), complete INTEGER NOT NULL CHECK(complete IN (0,1)), invalid INTEGER NOT NULL CHECK(invalid IN (0,1)))";
const V6_OBJECTS_SQL: &str = "CREATE TABLE objects(id BLOB PRIMARY KEY CHECK(length(id)=32), kind INTEGER NOT NULL CHECK(kind IN (1,2,3,4,5,6,7,8)), length INTEGER NOT NULL CHECK(length BETWEEN 1 AND 2097152), complete INTEGER NOT NULL CHECK(complete IN (0,1)), invalid INTEGER NOT NULL CHECK(invalid IN (0,1)))";
const OBJECTS_SQL: &str = "CREATE TABLE objects(id BLOB PRIMARY KEY CHECK(length(id)=32), kind INTEGER NOT NULL CHECK(kind IN (1,2,3,4,5,6,7,8,9,10,11)), length INTEGER NOT NULL CHECK(length BETWEEN 1 AND 2097152), complete INTEGER NOT NULL CHECK(complete IN (0,1)), invalid INTEGER NOT NULL CHECK(invalid IN (0,1)))";
const FRAGMENTS_SQL: &str = "CREATE TABLE fragments(id BLOB NOT NULL REFERENCES objects(id) ON DELETE CASCADE, idx INTEGER NOT NULL CHECK(idx BETWEEN 0 AND 14979), data BLOB NOT NULL CHECK(length(data) BETWEEN 1 AND 140), acked INTEGER NOT NULL DEFAULT 0 CHECK(acked IN (0,1)), attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 8), PRIMARY KEY(id,idx))";
fn storage(_: rusqlite::Error) -> Error {
    Error::Storage
}
pub struct ObjectQueue {
    db: Connection,
    peer: [u8; 32],
    a2: bool,
    history: bool,
}
impl ObjectQueue {
    pub(crate) fn peer_id(&self) -> [u8; 32] {
        self.peer
    }
    pub(crate) fn describe(&self, id: &[u8; 32]) -> Result<(Offer, bool)> {
        let snapshot = self.db.unchecked_transaction().map_err(storage)?;
        self.validate_storage(&snapshot)?;
        Self::info(&snapshot, id)
    }
    /// One independently pinned peer per durable queue. Only public signed
    /// objects/fragments are stored; session keys and replay counters never are.
    pub fn open(path: &Path, peer: [u8; 32]) -> Result<Self> {
        Self::open_inner(path, peer, false, false, false)
    }
    /// Explicit local successor cache. Never migrates or replaces an old queue.
    /// This selects storage capacity only, not consensus rules or admission.
    pub fn open_a2(path: &Path, peer: [u8; 32], initialize: bool) -> Result<Self> {
        Self::open_inner(path, peer, true, false, initialize)
    }
    /// A new, explicitly selected TEST history queue. No live V7/V8 migration.
    /// The exact V9 schema durably binds the local A2 profile as well as the peer.
    pub fn open_history(path: &Path, peer: [u8; 32], allow_a2: bool, initialize: bool) -> Result<Self> {
        Self::open_inner(path, peer, allow_a2, true, initialize)
    }
    pub fn history_profile(&self) -> bool { self.history }
    fn open_inner(path: &Path, peer: [u8; 32], a2: bool, history: bool, initialize: bool) -> Result<Self> {
        if peer == [0; 32] {
            return Err(Error::Context);
        }
        let selected_version = if history { HISTORY_QUEUE_SCHEMA_VERSION } else if a2 { A2_QUEUE_SCHEMA_VERSION } else { QUEUE_SCHEMA_VERSION };
        let selected_objects = if history {
            if a2 { HISTORY_A2_OBJECTS_SQL } else { HISTORY_OBJECTS_SQL }
        } else if a2 { A2_OBJECTS_SQL } else { OBJECTS_SQL };
        let db = if a2 || history {
            if initialize {
                std::fs::OpenOptions::new().write(true).create_new(true)
                    .open(path).map_err(|_| Error::Storage)?;
            }
            let db = Connection::open_with_flags(path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX).map_err(storage)?;
            let version: i64 = db.query_row("PRAGMA user_version", [], |r| r.get(0)).map_err(storage)?;
            let count: i64 = db.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0)).map_err(storage)?;
            if if initialize { version != 0 || count != 0 } else { version != selected_version } {
                return Err(Error::Storage);
            }
            db
        } else {
            Connection::open(path).map_err(storage)?
        };
        db.busy_timeout(Duration::from_millis(250))
            .map_err(storage)?;
        db.execute_batch("PRAGMA page_size=4096; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA synchronous=FULL; PRAGMA journal_mode=DELETE; PRAGMA max_page_count=16384;").map_err(storage)?;
        let page_size: i64 = db
            .query_row("PRAGMA page_size", [], |r| r.get(0))
            .map_err(storage)?;
        if page_size != 4096 {
            return Err(Error::Storage);
        }
        let version: i64 = db
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(storage)?;
        if version == 0 {
            let tables: i64 = db
                .query_row(
                    "SELECT count(*) FROM sqlite_master WHERE type='table'",
                    [],
                    |r| r.get(0),
                )
                .map_err(storage)?;
            if tables != 0 {
                return Err(Error::Storage);
            }
            db.execute_batch(&format!("BEGIN IMMEDIATE; {PEER_SQL}; {selected_objects}; {FRAGMENTS_SQL}; PRAGMA user_version={selected_version};")).map_err(storage)?;
            db.execute("INSERT INTO peer VALUES(?1)", [peer.as_slice()])
                .map_err(storage)?;
            db.execute_batch("COMMIT").map_err(storage)?;
        } else if version != selected_version && (a2 || history || version != 6) {
            return Err(Error::Storage);
        }
        let stored: Vec<u8> = db
            .query_row("SELECT CASE WHEN typeof(id)='blob' AND length(id)=32 THEN id ELSE NULL END FROM peer", [], |r| r.get(0))
            .map_err(storage)?;
        let peers: i64 = db
            .query_row("SELECT count(*) FROM peer", [], |r| r.get(0))
            .map_err(storage)?;
        if peers != 1 {
            return Err(Error::Storage);
        }
        if stored != peer {
            return Err(Error::Context);
        }
        let check: String = db
            .query_row("PRAGMA quick_check", [], |r| r.get(0))
            .map_err(storage)?;
        if check != "ok" {
            return Err(Error::Storage);
        }
        let (n, bytes): (i64, i64) = db
            .query_row(
                "SELECT count(*),coalesce(sum(length),0) FROM objects",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(storage)?;
        if n > MAX_REQUESTS as i64
            || bytes < 0
            || bytes > (MAX_QUEUE_BYTES + MAX_SUBMISSION_BYTES) as i64
        {
            return Err(Error::Limit);
        }
        let queue = Self { db, peer, a2, history };
        if version == 6 {
            queue.validate_storage_version(&queue.db, 6, V6_OBJECTS_SQL)?;
            // Refuse incompatible old oversized submission objects in place.
            // Validate every saved offer before changing any schema/row bytes.
            let mut q = queue
                .db
                .prepare("SELECT kind,length FROM objects")
                .map_err(storage)?;
            for row in q
                .query_map([], |r| Ok((r.get::<_, u8>(0)?, r.get::<_, usize>(1)?)))
                .map_err(storage)?
            {
                let (kind, length) = row.map_err(storage)?;
                ObjectKind::parse(kind)?.validate_length(length)?;
            }
            drop(q);
            queue
                .db
                .execute_batch("PRAGMA foreign_keys=OFF")
                .map_err(storage)?;
            let migration = (|| {
                let tx = rusqlite::Transaction::new_unchecked(
                    &queue.db,
                    rusqlite::TransactionBehavior::Immediate,
                )
                .map_err(storage)?;
                // Recreate both tables, so the exact child foreign-key SQL is
                // restored without relying on ALTER TABLE rename pragmas.
                tx.execute_batch("ALTER TABLE fragments RENAME TO old_fragments; ALTER TABLE objects RENAME TO old_objects;").map_err(storage)?;
                tx.execute_batch(OBJECTS_SQL).map_err(storage)?;
                tx.execute_batch(FRAGMENTS_SQL).map_err(storage)?;
                tx.execute_batch("INSERT INTO objects SELECT * FROM old_objects; INSERT INTO fragments SELECT * FROM old_fragments; DROP TABLE old_fragments; DROP TABLE old_objects;").map_err(storage)?;
                tx.pragma_update(None, "user_version", QUEUE_SCHEMA_VERSION)
                    .map_err(storage)?;
                queue.validate_storage(&tx)?;
                let bad: bool = tx
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM pragma_foreign_key_check)",
                        [],
                        |r| r.get(0),
                    )
                    .map_err(storage)?;
                if bad {
                    return Err(Error::Storage);
                }
                tx.commit().map_err(storage)
            })();
            queue
                .db
                .execute_batch("PRAGMA foreign_keys=ON")
                .map_err(storage)?;
            migration?;
        }
        queue.validate_storage(&queue.db)?;
        Ok(queue)
    }
    /// Recheck the public cache format and peer binding inside each operation's
    /// transaction. A schema change or changed peer cannot redirect a live queue.
    fn validate_storage(&self, db: &Connection) -> Result<()> {
        self.validate_storage_version(db,
            if self.history { HISTORY_QUEUE_SCHEMA_VERSION } else if self.a2 { A2_QUEUE_SCHEMA_VERSION } else { QUEUE_SCHEMA_VERSION },
            if self.history { if self.a2 { HISTORY_A2_OBJECTS_SQL } else { HISTORY_OBJECTS_SQL } }
            else if self.a2 { A2_OBJECTS_SQL } else { OBJECTS_SQL })?;
        if self.history {
            // Exact SQL bounds the allowed kinds; recheck the narrower per-kind
            // caps even for retained/incomplete/invalid public copies on reopen.
            let mut query = db.prepare("SELECT kind,length FROM objects LIMIT 11").map_err(storage)?;
            for row in query.query_map([], |r| Ok((r.get::<_,u8>(0)?,r.get::<_,usize>(1)?))).map_err(storage)? {
                let (kind, length) = row.map_err(storage)?;
                ObjectKind::parse(kind)?.validate_length(length)?;
            }
        }
        if self.a2 {
            let (count, bytes): (usize, usize) = db.query_row(
                "SELECT count(*),coalesce(sum(length),0) FROM objects WHERE kind=13", [],
                |r| Ok((r.get(0)?,r.get(1)?))).map_err(storage)?;
            if count > 1 || bytes > ObjectKind::A2EvidenceOperation.max_bytes() {
                return Err(Error::Limit);
            }
        }
        for submission in [false, true] {
            let (n, bytes): (usize, usize) = db
                .query_row(
                    "SELECT count(*),coalesce(sum(length),0) FROM objects WHERE (kind IN (1,9))=?1",
                    [submission],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(storage)?;
            if n > if submission {
                MAX_SUBMISSIONS
            } else {
                MAX_OBJECTS
            } || bytes
                > if submission {
                    MAX_SUBMISSION_BYTES
                } else {
                    MAX_QUEUE_BYTES
                }
            {
                return Err(Error::Limit);
            }
        }
        Ok(())
    }
    fn validate_storage_version(
        &self,
        db: &Connection,
        expected_version: i64,
        objects_sql: &str,
    ) -> Result<()> {
        let version: i64 = db
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(storage)?;
        let objects: i64 = db
            .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
            .map_err(storage)?;
        if version != expected_version || objects != 5 {
            return Err(Error::Storage);
        }
        for (name, sql) in [
            ("peer", PEER_SQL),
            ("objects", objects_sql),
            ("fragments", FRAGMENTS_SQL),
        ] {
            let actual: String = db.query_row(
                "SELECT CASE WHEN length(CAST(sql AS BLOB))<=1024 THEN sql ELSE NULL END FROM sqlite_schema WHERE type='table' AND name=?1 AND tbl_name=?1",
                [name], |r| r.get(0)).map_err(storage)?;
            if actual != sql {
                return Err(Error::Storage);
            }
        }
        for (name, table) in [
            ("sqlite_autoindex_objects_1", "objects"),
            ("sqlite_autoindex_fragments_1", "fragments"),
        ] {
            let n:i64=db.query_row("SELECT count(*) FROM sqlite_schema WHERE type='index' AND name=?1 AND tbl_name=?2 AND sql IS NULL",params![name,table],|r|r.get(0)).map_err(storage)?;
            if n != 1 {
                return Err(Error::Storage);
            }
        }
        let peers: i64 = db
            .query_row("SELECT count(*) FROM peer", [], |r| r.get(0))
            .map_err(storage)?;
        let peer:Vec<u8>=db.query_row("SELECT CASE WHEN typeof(id)='blob' AND length(id)=32 THEN id ELSE NULL END FROM peer",[],|r|r.get(0)).map_err(storage)?;
        if peers != 1 || peer != self.peer {
            return Err(Error::Context);
        }
        Ok(())
    }
    fn reserve(tx: &Transaction<'_>, offer: &Offer) -> Result<bool> {
        offer.kind.validate_length(offer.length)?;
        count(offer.length)?;
        if offer.id == [0; 32] {
            return Err(Error::Encoding);
        }
        let existing: Option<(u8, usize)> = tx
            .query_row(
                "SELECT kind,length FROM objects WHERE id=?1",
                [offer.id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(storage)?;
        if let Some((kind, length)) = existing {
            if kind != offer.kind as u8 || length != offer.length {
                return Err(Error::Context);
            }
            return Ok(false);
        }
        let (n, bytes): (usize, usize) = tx
            .query_row(
                "SELECT count(*),coalesce(sum(length),0) FROM objects WHERE (kind IN (1,9))=?1",
                [matches!(
                    offer.kind,
                    ObjectKind::SignedTransaction | ObjectKind::SignedOperation
                )],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(storage)?;
        let submission = matches!(
            offer.kind,
            ObjectKind::SignedTransaction | ObjectKind::SignedOperation
        );
        if n >= if submission {
            MAX_SUBMISSIONS
        } else {
            MAX_OBJECTS
        } || bytes.checked_add(offer.length).is_none_or(|n| {
            n > if submission {
                MAX_SUBMISSION_BYTES
            } else {
                MAX_QUEUE_BYTES
            }
        }) {
            return Err(Error::Limit);
        }
        tx.execute(
            "INSERT INTO objects VALUES(?1,?2,?3,0,0)",
            params![offer.id.as_slice(), offer.kind as u8, offer.length],
        )
        .map_err(storage)?;
        Ok(true)
    }
    fn check_route(&self, tx: &Transaction<'_>, offer: &Offer) -> Result<()> {
        if matches!(offer.kind, ObjectKind::HistoryRequestV1 | ObjectKind::HistoryPageV1) && !self.history {
            return Err(Error::Context);
        }
        if matches!(offer.kind, ObjectKind::A2BlockProposal | ObjectKind::A2EvidenceOperation) && !self.a2 {
            return Err(Error::Context);
        }
        if offer.kind == ObjectKind::A2EvidenceOperation {
            // This reservation also consumes the unchanged general object budget.
            let other: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM objects WHERE kind=13 AND id<>?1)",
                [offer.id.as_slice()], |r|r.get(0)).map_err(storage)?;
            if other { return Err(Error::Limit); }
        }
        Ok(())
    }
    pub fn offer(&mut self, offer: &Offer) -> Result<bool> {
        let tx = self.db.unchecked_transaction().map_err(storage)?;
        self.validate_storage(&tx)?;
        self.check_route(&tx, offer)?;
        let fresh = Self::reserve(&tx, offer)?;
        tx.commit().map_err(storage)?;
        Ok(fresh)
    }
    /// Bounded submission transport copies for relay restart/ACK reconciliation.
    /// Their presence proves delivery bytes only, never local semantic admission.
    pub(crate) fn submission_offers(&self) -> Result<Vec<Offer>> {
        let tx = self.db.unchecked_transaction().map_err(storage)?;
        self.validate_storage(&tx)?;
        let mut q=tx.prepare("SELECT id,kind,length FROM objects WHERE kind IN (1,9) AND complete=1 AND invalid=0 ORDER BY id LIMIT 3").map_err(storage)?;
        let mut out = Vec::new();
        for row in q
            .query_map([], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, u8>(1)?,
                    r.get::<_, usize>(2)?,
                ))
            })
            .map_err(storage)?
        {
            let (id, kind, length) = row.map_err(storage)?;
            if out.len() >= MAX_SUBMISSIONS {
                return Err(Error::Limit);
            }
            out.push(Offer {
                id: id.try_into().map_err(|_| Error::Storage)?,
                kind: ObjectKind::parse(kind)?,
                length,
            });
        }
        Ok(out)
    }
    /// Bounded local occupancy, including failed and incomplete evidence.
    pub(crate) fn has_a2_reservation(&self) -> Result<bool> {
        if !self.a2 { return Err(Error::Context); }
        let tx=self.db.unchecked_transaction().map_err(storage)?;
        self.validate_storage(&tx)?;
        // Includes incomplete and invalid evidence; those occupied rows must
        // never be mistaken for an already released owner reservation.
        let count:usize=tx.query_row("SELECT count(*) FROM objects WHERE kind=13",[],|r|r.get(0)).map_err(storage)?;
        Ok(count!=0)
    }
    /// Separate explicit successor route; ordinary submission enumeration remains
    /// limited to kinds 1/9. Presence proves opaque complete bytes only.
    pub(crate) fn a2_evidence_offer(&self) -> Result<Option<Offer>> {
        if !self.a2 { return Err(Error::Context); }
        let tx = self.db.unchecked_transaction().map_err(storage)?;
        self.validate_storage(&tx)?;
        let mut q = tx.prepare("SELECT id,length FROM objects WHERE kind=13 AND complete=1 AND invalid=0 ORDER BY id LIMIT 2").map_err(storage)?;
        let mut out = None;
        for row in q.query_map([],|r|Ok((r.get::<_,Vec<u8>>(0)?,r.get::<_,usize>(1)?))).map_err(storage)? {
            if out.is_some() { return Err(Error::Limit); }
            let (id,length) = row.map_err(storage)?;
            out = Some(Offer { id:id.try_into().map_err(|_|Error::Storage)?,kind:ObjectKind::A2EvidenceOperation,length });
        }
        Ok(out)
    }
    pub fn enqueue(&mut self, kind: ObjectKind, bytes: &[u8]) -> Result<Offer> {
        let offer = Offer {
            id: object_id(kind, bytes)?,
            kind,
            length: bytes.len(),
        };
        let tx = self.db.unchecked_transaction().map_err(storage)?;
        self.validate_storage(&tx)?;
        self.check_route(&tx, &offer)?;
        if Self::reserve(&tx, &offer)? {
            for (i, chunk) in bytes.chunks(MAX_PAYLOAD).enumerate() {
                tx.execute(
                    "INSERT INTO fragments(id,idx,data) VALUES(?1,?2,?3)",
                    params![offer.id.as_slice(), i, chunk],
                )
                .map_err(storage)?;
            }
            tx.execute(
                "UPDATE objects SET complete=1 WHERE id=?1",
                [offer.id.as_slice()],
            )
            .map_err(storage)?;
        } else {
            let (_, complete) = Self::info(&tx, &offer.id)?;
            if !complete || Self::assemble(&tx, &offer)? != bytes {
                return Err(Error::Context);
            }
        }
        tx.commit().map_err(storage)?;
        Ok(offer)
    }
    fn general_capacity_in(db: &Connection) -> Result<GeneralCapacity> {
        let (objects, bytes): (usize, usize) = db.query_row(
            "SELECT count(*),coalesce(sum(length),0) FROM objects WHERE kind NOT IN (1,9)",
            [], |r| Ok((r.get(0)?, r.get(1)?))).map_err(storage)?;
        Ok(GeneralCapacity {
            free_objects: MAX_OBJECTS.checked_sub(objects).ok_or(Error::Limit)?,
            free_bytes: MAX_QUEUE_BYTES.checked_sub(bytes).ok_or(Error::Limit)?,
        })
    }
    pub fn general_capacity(&self) -> Result<GeneralCapacity> {
        let tx = self.db.unchecked_transaction().map_err(storage)?;
        self.validate_storage(&tx)?;
        Self::general_capacity_in(&tx)
    }
    /// Candidate budget with the supplied already-queued request counted once,
    /// at its full cap, plus a full response control reservation. No reservation
    /// authority escapes this snapshot; insertion rechecks under BEGIN IMMEDIATE.
    pub fn history_capacity(&self, request: &[u8; 32]) -> Result<HistoryCapacity> {
        if !self.history { return Err(Error::Context); }
        let tx = self.db.unchecked_transaction().map_err(storage)?;
        self.validate_storage(&tx)?;
        let (offer, complete) = Self::info(&tx, request)?;
        if offer.kind != ObjectKind::HistoryRequestV1 || !complete { return Err(Error::Context); }
        let free = Self::general_capacity_in(&tx)?;
        Ok(HistoryCapacity {
            candidate_entries: free.free_objects.saturating_sub(1).min(MAX_HISTORY_CANDIDATES),
            candidate_bytes: free.free_bytes.saturating_sub(HISTORY_CONTROL_BYTES - offer.length),
        })
    }
    pub(crate) fn check_history_plan_capacity(&self, request: &[u8; 32], page: &[u8; 32], members: &[Offer]) -> Result<()> {
        if !self.history { return Err(Error::Context); }
        let tx = self.db.unchecked_transaction().map_err(storage)?;
        self.validate_storage(&tx)?;
        let (req, _) = Self::info(&tx, request)?;
        let (response, _) = Self::info(&tx, page)?;
        let free = Self::general_capacity_in(&tx)?;
        let mut objects = 0usize;
        let mut bytes = HISTORY_CONTROL_BYTES.checked_sub(req.length + response.length).ok_or(Error::Context)?;
        for member in members {
            let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM objects WHERE id=?1)",
                [member.id.as_slice()], |r| r.get(0)).map_err(storage)?;
            if exists {
                let (old, _) = Self::info(&tx, &member.id)?;
                if old != *member { return Err(Error::Context); }
            } else {
                objects += 1;
                bytes = bytes.checked_add(member.length).ok_or(Error::Limit)?;
            }
        }
        if objects > free.free_objects || bytes > free.free_bytes { return Err(Error::Limit); }
        Ok(())
    }
    /// Opaque transport insertion only. The node host must supply a canonically
    /// verified, coherently exported, ordered plan. This does not grant that proof.
    /// None means quota BUSY; every error or quota miss rolls back all writes.
    pub fn enqueue_history_page(&mut self, request: &[u8; 32], page: &[u8],
        candidates: &[(ObjectKind, Vec<u8>)]) -> Result<Option<QueuedHistoryPage>> {
        if !self.history || candidates.len() > MAX_HISTORY_CANDIDATES { return Err(Error::Context); }
        let mut items = Vec::with_capacity(candidates.len() + 1);
        items.push((ObjectKind::HistoryPageV1, page));
        let mut recovery = false;
        for (kind, bytes) in candidates {
            match kind {
                ObjectKind::RecoveryEvidence if !recovery => recovery = true,
                ObjectKind::CertifiedBlock => recovery = false,
                _ => return Err(Error::Context),
            }
            items.push((*kind, bytes.as_slice()));
        }
        if recovery { return Err(Error::Context); }
        let mut offers = Vec::with_capacity(items.len());
        for (kind, bytes) in &items {
            let offer = Offer { id: object_id(*kind, bytes)?, kind: *kind, length: bytes.len() };
            if offers.iter().any(|old: &Offer| old.id == offer.id) { return Err(Error::Context); }
            offers.push(offer);
        }
        let tx = rusqlite::Transaction::new_unchecked(&self.db,
            rusqlite::TransactionBehavior::Immediate).map_err(storage)?;
        self.validate_storage(&tx)?;
        let (request_offer, complete) = Self::info(&tx, request)?;
        if request_offer.kind != ObjectKind::HistoryRequestV1 || !complete { return Err(Error::Context); }
        let free = Self::general_capacity_in(&tx)?;
        let mut needed_objects = 0usize;
        let mut needed_bytes = HISTORY_CONTROL_BYTES - request_offer.length - page.len();
        let mut fresh = Vec::with_capacity(items.len());
        for offer in &offers {
            self.check_route(&tx, offer)?;
            let exists: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM objects WHERE id=?1)",
                [offer.id.as_slice()], |r| r.get(0)).map_err(storage)?;
            fresh.push(!exists);
            if !exists {
                needed_objects += 1;
                needed_bytes = needed_bytes.checked_add(offer.length).ok_or(Error::Limit)?;
            }
        }
        if needed_objects > free.free_objects || needed_bytes > free.free_bytes { return Ok(None); }
        for ((offer, (_, bytes)), new) in offers.iter().zip(&items).zip(&fresh) {
            if *new {
                Self::reserve(&tx, offer)?;
                for (i, chunk) in bytes.chunks(MAX_PAYLOAD).enumerate() {
                    tx.execute("INSERT INTO fragments(id,idx,data) VALUES(?1,?2,?3)",
                        params![offer.id.as_slice(), i, chunk]).map_err(storage)?;
                }
                tx.execute("UPDATE objects SET complete=1 WHERE id=?1", [offer.id.as_slice()]).map_err(storage)?;
            } else {
                let (old, complete) = Self::info(&tx, &offer.id)?;
                if old != *offer || !complete || Self::assemble(&tx, offer)? != *bytes {
                    return Err(Error::Context);
                }
            }
        }
        self.validate_storage(&tx)?;
        tx.commit().map_err(storage)?;
        Ok(Some(QueuedHistoryPage { offers, fresh }))
    }
    fn info(db: &Connection, id: &[u8; 32]) -> Result<(Offer, bool)> {
        let (kind, length, complete, invalid): (u8, usize, bool, bool) = db
            .query_row(
                "SELECT kind,length,CASE WHEN complete IN (0,1) THEN complete ELSE NULL END,CASE WHEN invalid IN (0,1) THEN invalid ELSE NULL END FROM objects WHERE id=?1",
                [id.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .map_err(storage)?;
        if invalid {
            return Err(Error::Crypto);
        }
        let kind = ObjectKind::parse(kind)?;
        kind.validate_length(length)?;
        count(length)?;
        Ok((
            Offer {
                id: *id,
                kind,
                length,
            },
            complete,
        ))
    }
    fn assemble(db: &Connection, offer: &Offer) -> Result<Vec<u8>> {
        let total = count(offer.length)? as usize;
        let mut out = Vec::with_capacity(offer.length);
        let mut stmt = db
            .prepare("SELECT idx,CASE WHEN typeof(data)='blob' AND length(data) BETWEEN 1 AND 140 THEN data ELSE NULL END FROM fragments WHERE id=?1 ORDER BY idx")
            .map_err(storage)?;
        let mut rows = stmt.query([offer.id.as_slice()]).map_err(storage)?;
        let mut index = 0usize;
        while let Some(r) = rows.next().map_err(storage)? {
            if index >= total {
                return Err(Error::Encoding);
            }
            let at: usize = r.get(0).map_err(storage)?;
            let bytes: Vec<u8> = r.get(1).map_err(storage)?;
            if at != index || bytes.len() != (offer.length - out.len()).min(MAX_PAYLOAD) {
                return Err(Error::Encoding);
            }
            out.extend_from_slice(&bytes);
            index += 1;
            if out.len() > offer.length {
                return Err(Error::Limit);
            }
        }
        if out.len() != offer.length || object_id(offer.kind, &out)? != offer.id {
            return Err(Error::Crypto);
        }
        Ok(out)
    }
    /// Called only after session authentication. Completion returns exact opaque
    /// canonical bytes; the wallet must still verify transaction/proof semantics.
    pub fn receive(&mut self, meta: &Metadata, payload: &[u8]) -> Result<Option<Vec<u8>>> {
        meta.validate()?;
        if meta.kind != 3 {
            return Err(Error::Encoding);
        }
        let tx = self.db.unchecked_transaction().map_err(storage)?;
        self.validate_storage(&tx)?;
        let (offer, complete) = Self::info(&tx, &meta.object)?;
        let total = count(offer.length)?;
        if meta.count != total
            || meta.fragment >= total
            || payload.len()
                != (offer.length - meta.fragment as usize * MAX_PAYLOAD).min(MAX_PAYLOAD)
        {
            return Err(Error::Encoding);
        }
        let old: Option<Vec<u8>> = tx
            .query_row(
                "SELECT CASE WHEN typeof(data)='blob' AND length(data) BETWEEN 1 AND 140 THEN data ELSE NULL END FROM fragments WHERE id=?1 AND idx=?2",
                params![meta.object.as_slice(), meta.fragment],
                |r| r.get(0),
            )
            .optional()
            .map_err(storage)?;
        if let Some(old) = old {
            if old != payload {
                return Err(Error::Context);
            }
        } else {
            tx.execute(
                "INSERT INTO fragments(id,idx,data) VALUES(?1,?2,?3)",
                params![meta.object.as_slice(), meta.fragment, payload],
            )
            .map_err(storage)?;
        }
        let received: u16 = tx
            .query_row(
                "SELECT count(*) FROM fragments WHERE id=?1",
                [meta.object.as_slice()],
                |r| r.get(0),
            )
            .map_err(storage)?;
        if received > total {
            return Err(Error::Encoding);
        }
        let out = if received == total {
            match Self::assemble(&tx, &offer) {
                Ok(bytes) => {
                    tx.execute(
                        "UPDATE objects SET complete=1 WHERE id=?1",
                        [meta.object.as_slice()],
                    )
                    .map_err(storage)?;
                    if complete { None } else { Some(bytes) }
                }
                Err(e) => {
                    tx.execute(
                        "UPDATE objects SET invalid=1 WHERE id=?1",
                        [meta.object.as_slice()],
                    )
                    .map_err(storage)?;
                    tx.commit().map_err(storage)?;
                    return Err(e);
                }
            }
        } else {
            None
        };
        tx.commit().map_err(storage)?;
        Ok(out)
    }
    pub fn missing(&self, id: &[u8; 32], start: u16, n: u16) -> Result<Bitmap> {
        let snapshot = self.db.unchecked_transaction().map_err(storage)?;
        self.validate_storage(&snapshot)?;
        let (offer, _) = Self::info(&snapshot, id)?;
        let total = count(offer.length)?;
        if n == 0 || n > MAX_BITMAP_BITS || start as u32 + n as u32 > total as u32 {
            return Err(Error::Encoding);
        }
        let mut bits = vec![true; n as usize];
        let mut s = snapshot
            .prepare("SELECT idx FROM fragments WHERE id=?1 AND idx>=?2 AND idx<?3")
            .map_err(storage)?;
        let indices = s
            .query_map(
                params![id.as_slice(), start, start as u32 + n as u32],
                |r| r.get::<_, u16>(0),
            )
            .map_err(storage)?;
        for i in indices {
            bits[(i.map_err(storage)? - start) as usize] = false;
        }
        Ok(Bitmap { start, bits })
    }
    /// Persist the attempt reservation before returning a fragment. A crash may
    /// consume an attempt but can never reset the retry budget.
    pub fn next_fragment(
        &mut self,
        id: &[u8; 32],
        wanted: &Bitmap,
        hops: u8,
    ) -> Result<Option<(Metadata, Vec<u8>)>> {
        if hops > 16 {
            return Err(Error::Encoding);
        }
        let tx = self.db.unchecked_transaction().map_err(storage)?;
        self.validate_storage(&tx)?;
        let (offer, complete) = Self::info(&tx, id)?;
        if !complete {
            return Err(Error::Context);
        }
        let total = count(offer.length)?;
        wanted.encode(total)?;
        for (i, want) in wanted.bits.iter().enumerate() {
            if !want {
                continue;
            }
            let at = wanted.start + i as u16;
            let (data, attempts): (Vec<u8>, u8) = tx
                .query_row(
                    "SELECT CASE WHEN typeof(data)='blob' AND length(data) BETWEEN 1 AND 140 THEN data ELSE NULL END,CASE WHEN attempts BETWEEN 0 AND 8 THEN attempts ELSE NULL END FROM fragments WHERE id=?1 AND idx=?2",
                    params![id.as_slice(), at],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .map_err(storage)?;
            if data.len() != (offer.length - at as usize * MAX_PAYLOAD).min(MAX_PAYLOAD) {
                return Err(Error::Encoding);
            }
            if attempts >= MAX_ATTEMPTS {
                continue;
            }
            tx.execute(
                "UPDATE fragments SET attempts=attempts+1 WHERE id=?1 AND idx=?2",
                params![id.as_slice(), at],
            )
            .map_err(storage)?;
            tx.commit().map_err(storage)?;
            return Ok(Some((
                Metadata {
                    kind: 3,
                    object: *id,
                    fragment: at,
                    count: total,
                    hops,
                },
                data,
            )));
        }
        Ok(None)
    }
    pub fn acknowledge(&mut self, id: &[u8; 32], received: &Bitmap) -> Result<()> {
        let tx = self.db.unchecked_transaction().map_err(storage)?;
        self.validate_storage(&tx)?;
        let (offer, complete) = Self::info(&tx, id)?;
        if !complete {
            return Err(Error::Context);
        }
        received.encode(count(offer.length)?)?;
        for (i, yes) in received.bits.iter().enumerate() {
            if *yes {
                tx.execute(
                    "UPDATE fragments SET acked=1 WHERE id=?1 AND idx=?2",
                    params![id.as_slice(), received.start + i as u16],
                )
                .map_err(storage)?;
            }
        }
        tx.commit().map_err(storage)?;
        Ok(())
    }
    pub fn read_complete(&self, id: &[u8; 32]) -> Result<Vec<u8>> {
        let snapshot = self.db.unchecked_transaction().map_err(storage)?;
        self.validate_storage(&snapshot)?;
        let (offer, complete) = Self::info(&snapshot, id)?;
        if !complete {
            return Err(Error::Context);
        }
        Self::assemble(&snapshot, &offer)
    }
    pub fn acknowledged(&self, id: &[u8; 32], start: u16, n: u16) -> Result<Bitmap> {
        if n == 0 || n > MAX_BITMAP_BITS {
            return Err(Error::Encoding);
        }
        let snapshot = self.db.unchecked_transaction().map_err(storage)?;
        self.validate_storage(&snapshot)?;
        let (offer, complete) = Self::info(&snapshot, id)?;
        if !complete {
            return Err(Error::Context);
        }
        let mut result = Bitmap {
            start,
            bits: vec![false; n as usize],
        };
        result.encode(count(offer.length)?)?;
        let mut s = snapshot
            .prepare("SELECT idx FROM fragments WHERE id=?1 AND idx>=?2 AND idx<?3 AND acked=1")
            .map_err(storage)?;
        let rows = s
            .query_map(
                params![id.as_slice(), start, start as u32 + n as u32],
                |r| r.get::<_, u16>(0),
            )
            .map_err(storage)?;
        for i in rows {
            result.bits[(i.map_err(storage)? - start) as usize] = true;
        }
        Ok(result)
    }
    pub fn discard(&mut self, id: &[u8; 32]) -> Result<()> {
        let tx = self.db.unchecked_transaction().map_err(storage)?;
        self.validate_storage(&tx)?;
        tx.execute("DELETE FROM objects WHERE id=?1", [id.as_slice()])
            .map_err(storage)?;
        tx.commit().map_err(storage)?;
        Ok(())
    }
}
#[cfg(test)]
#[path = "history_queue_v1_tests.rs"]
mod history_queue_v1_tests;
