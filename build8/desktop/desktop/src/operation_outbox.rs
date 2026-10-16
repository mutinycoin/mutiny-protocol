//! The desktop's durable, restart-safe and PROTECTED-AT-REST outbox for signed operations other
//! than ordinary payments (payments keep the consensus transaction pool, `mempool_v2`, which is also
//! their transport queue).
//!
//! It implements wallet-core's `Outbox` trait with the semantics of `SqliteOutbox` (the README's
//! "Durable outbox" contract): the exact signed bytes are committed in ONE atomic transaction
//! (synchronous FULL, rollback journal) before success is reported; every commit re-verifies the
//! bytes through consensus code against the current verified view and DERIVES the record's
//! metadata from the bytes (`wallet_core::outbox::admit_record`); an identifier is idempotent while
//! its record is open; a coin or resource is held by one open record only; only open records count
//! against the limits; `forget` releases reservations and never revokes the signed bytes; settled
//! records are history, trimmed on every reconciliation; the file is bound to one chain;
//! `replace_partial` swaps an open partial record for its verified completion in ONE transaction
//! (`wallet_core::outbox::admit_replacement_record`), so the reservations pass from one record to
//! the other and a crash or a refusal leaves exactly one of them.
//!
//! Why not `SqliteOutbox` itself: it stores the signed bytes in clear, and a queued hash-lock CLAIM
//! carries its preimage in clear until it is included (phase 5A finding). Here every record is two
//! DPAPI-sealed values (`custody_seal`): the signed bytes, and the metadata (kind, identifier,
//! status, validity, reservations, missing signatures, wallet-core's record checksum), each bound to
//! the chain, this file's random identifier, the field and the record identifier. Only the record
//! identifier (a public hash) and an insertion sequence are stored in clear. A probe value sealed
//! at creation is opened on every open, so a file that this Windows account cannot unseal (another
//! account, another machine, a damaged or swapped file identifier) is refused before anything else.
//! Change request CR-W7-1 (report) proposes a sealing hook in `SqliteOutbox` so that this module
//! need not mirror its semantics.
//!
//! Integrity beyond DPAPI: every record read back is rebuilt with `OutboxRecord::from_stored` and
//! re-verified with wallet-core's checksum, its sealed identifier must equal its row, and the exact
//! schema is compared on every open. Anything irregular is `OUTBOX_INTEGRITY`.
use crate::{
    custody_acl_v2,
    custody_seal::{self, Reader, Writer},
};
use mutiny_consensus_v8::{Hash, transactions::OutPoint};
use mutiny_wallet_core_v8::{
    ChainContext, ChainView, DEFAULT_MAX_SETTLED, OperationKind, Outbox, OutboxRecord,
    OutboxStatus, PartialApproval, ReconcileReport, Refusal, RequiredSigner, Requirement,
    RequirementStatus, Settlement, SignedOperation, Slot, Validity, outbox,
};
use rusqlite::{Connection, ErrorCode, OpenFlags, TransactionBehavior, params};
use std::{collections::BTreeSet, fmt, path::Path, time::Duration};

/// File name inside the custody directory (an allow-listed name in `custody_acl_v2`).
pub const FILE_NAME: &str = "operation-outbox-v1.sqlite";
/// SQLite `application_id` ("MUOP").
pub const APPLICATION_ID: i64 = 0x4d55_4f50;
pub const SCHEMA_VERSION: i64 = 1;
/// How long a write waits for another process that holds the file before `OUTBOX_BUSY`.
pub const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const BINDING_DOMAIN: &[u8] = b"MUTINY-BUILD8-DESKTOP-OPERATION-OUTBOX-V1";
const PROBE: &[u8] = b"MUTINY-BUILD8-DESKTOP-OPERATION-OUTBOX-PROBE-V1";
const RECORD_VERSION: u8 = 1;

pub(crate) const SCHEMA: [(&str, &str); 2] = [
    (
        "operation_outbox_context_v1",
        "CREATE TABLE operation_outbox_context_v1(id INTEGER PRIMARY KEY CHECK(id=1),network INTEGER NOT NULL CHECK(network BETWEEN 0 AND 4294967295),genesis BLOB NOT NULL CHECK(length(genesis)=32),fingerprint BLOB NOT NULL CHECK(length(fingerprint)=32),file_id BLOB NOT NULL CHECK(length(file_id)=32),probe BLOB NOT NULL CHECK(length(probe) BETWEEN 1 AND 4096))",
    ),
    (
        "operation_outbox_records_v1",
        "CREATE TABLE operation_outbox_records_v1(seq INTEGER PRIMARY KEY CHECK(seq>=1),id BLOB NOT NULL UNIQUE CHECK(length(id)=32),meta BLOB NOT NULL CHECK(length(meta) BETWEEN 1 AND 131072),raw BLOB NOT NULL CHECK(length(raw) BETWEEN 1 AND 131072))",
    ),
];

/// A storage error: a full disk is its own refusal, a busy file is retryable, a file that cannot be
/// opened is a location problem, everything else is an integrity failure of the store.
fn storage(error: rusqlite::Error) -> Refusal {
    match &error {
        rusqlite::Error::SqliteFailure(failure, _) => match failure.code {
            ErrorCode::DiskFull => Refusal::OutboxFull,
            ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => Refusal::OutboxBusy,
            ErrorCode::CannotOpen => Refusal::OutboxLocation,
            _ => Refusal::OutboxIntegrity,
        },
        _ => Refusal::OutboxIntegrity,
    }
}

fn integrity<T>(_: T) -> Refusal {
    Refusal::OutboxIntegrity
}

fn status_code(status: OutboxStatus) -> (u8, u64) {
    match status {
        OutboxStatus::Queued => (0, 0),
        OutboxStatus::Confirmed(height) => (1, height),
        OutboxStatus::Expired => (2, 0),
        OutboxStatus::InputsSpent => (3, 0),
        OutboxStatus::Forgotten => (4, 0),
        // wallet-core's `OutboxStatus` is non-exhaustive (W9). This outbox never sets another
        // status: its reconciliation maps every other settlement to `InputsSpent` (below).
        _ => (3, 0),
    }
}

fn status_of(code: u8, height: u64) -> Option<OutboxStatus> {
    Some(match (code, height) {
        (0, 0) => OutboxStatus::Queued,
        (1, height) => OutboxStatus::Confirmed(height),
        (2, 0) => OutboxStatus::Expired,
        (3, 0) => OutboxStatus::InputsSpent,
        (4, 0) => OutboxStatus::Forgotten,
        _ => return None,
    })
}

fn put_slot(w: &mut Writer, slot: Slot) {
    match slot {
        Slot::Input(index) => {
            w.u8(0).u32(index);
        }
        Slot::Approval(slot) => {
            w.u8(1).u8(slot);
        }
        Slot::OfferSignature => {
            w.u8(2);
        }
        Slot::FillSignature => {
            w.u8(3);
        }
        Slot::RotationAuthorization => {
            w.u8(4);
        }
        Slot::RotationPossession => {
            w.u8(5);
        }
        Slot::Claim => {
            w.u8(6);
        }
        Slot::BondOwner => {
            w.u8(7);
        }
        Slot::TreasuryFreeze => {
            w.u8(8);
        }
        Slot::AssignmentOwner => {
            w.u8(9);
        }
    }
}

fn get_slot(r: &mut Reader<'_>) -> Option<Slot> {
    Some(match r.u8()? {
        0 => Slot::Input(r.u32()?),
        1 => Slot::Approval(r.u8()?),
        2 => Slot::OfferSignature,
        3 => Slot::FillSignature,
        4 => Slot::RotationAuthorization,
        5 => Slot::RotationPossession,
        6 => Slot::Claim,
        7 => Slot::BondOwner,
        8 => Slot::TreasuryFreeze,
        9 => Slot::AssignmentOwner,
        _ => return None,
    })
}

fn put_requirement(w: &mut Writer, requirement: &Requirement) {
    put_slot(w, requirement.slot);
    match requirement.signer {
        RequiredSigner::Wallet(address) => w.u8(0).bytes(&address),
        RequiredSigner::Maker(identity) => w.u8(1).bytes(&identity),
    };
    w.u8(match requirement.status {
        RequirementStatus::ThisWallet => 0,
        RequirementStatus::Counterparty => 1,
        RequirementStatus::Maker => 2,
        RequirementStatus::Provided => 3,
    });
}

fn get_requirement(r: &mut Reader<'_>) -> Option<Requirement> {
    let slot = get_slot(r)?;
    let signer = match r.u8()? {
        0 => RequiredSigner::Wallet(r.hash()?),
        1 => RequiredSigner::Maker(r.hash()?),
        _ => return None,
    };
    let status = match r.u8()? {
        0 => RequirementStatus::ThisWallet,
        1 => RequirementStatus::Counterparty,
        2 => RequirementStatus::Maker,
        3 => RequirementStatus::Provided,
        _ => return None,
    };
    Some(Requirement {
        slot,
        signer,
        status,
    })
}

/// Everything about a record except its signed bytes, as sealed: version, kind, identifier, status,
/// queued head, completeness, validity, reservations, missing signatures and wallet-core's checksum.
fn encode_meta(record: &OutboxRecord) -> zeroize::Zeroizing<Vec<u8>> {
    let mut w = Writer::default();
    let (status, status_height) = status_code(record.status);
    w.u8(RECORD_VERSION)
        .u16(record.kind.code())
        .bytes(&record.id)
        .u8(status)
        .u64(status_height)
        .u64(record.queued_at_height)
        .u8(u8::from(record.complete))
        .u64(record.validity.created)
        .u64(record.validity.expiry);
    match record.validity.valid_only_at {
        Some(height) => w.u8(1).u64(height),
        None => w.u8(0).u64(0),
    };
    w.u8(u8::from(record.validity.bound_to_parent));
    w.u32(record.reserved.len() as u32);
    for point in &record.reserved {
        w.bytes(&point.transaction).u32(point.index);
    }
    w.u32(record.missing.len() as u32);
    for requirement in &record.missing {
        put_requirement(&mut w, requirement);
    }
    w.bytes(&record.checksum());
    w.finish()
}

/// Rebuild a record from its opened metadata and bytes, and re-verify wallet-core's checksum.
fn decode_record(meta: &[u8], bytes: Vec<u8>) -> Result<OutboxRecord, Refusal> {
    let bad = Refusal::OutboxIntegrity;
    let r = &mut Reader::new(meta);
    if r.u8() != Some(RECORD_VERSION) {
        return Err(bad);
    }
    let kind = r
        .u16()
        .and_then(OperationKind::from_code)
        .ok_or(Refusal::OutboxIntegrity)?;
    let id = r.hash().ok_or(Refusal::OutboxIntegrity)?;
    let status = match (r.u8(), r.u64()) {
        (Some(code), Some(height)) => status_of(code, height).ok_or(Refusal::OutboxIntegrity)?,
        _ => return Err(bad),
    };
    let queued_at = r.u64().ok_or(Refusal::OutboxIntegrity)?;
    let complete = r.bool().ok_or(Refusal::OutboxIntegrity)?;
    let created = r.u64().ok_or(Refusal::OutboxIntegrity)?;
    let expiry = r.u64().ok_or(Refusal::OutboxIntegrity)?;
    let valid_only_at = match (r.u8(), r.u64()) {
        (Some(0), Some(0)) => None,
        (Some(1), Some(height)) => Some(height),
        _ => return Err(bad),
    };
    let bound_to_parent = r.bool().ok_or(Refusal::OutboxIntegrity)?;
    let count = r.u32().ok_or(Refusal::OutboxIntegrity)? as usize;
    if count > mutiny_wallet_core_v8::partial::MAX_RESERVED {
        return Err(bad);
    }
    let mut reserved = Vec::with_capacity(count);
    for _ in 0..count {
        let transaction = r.hash().ok_or(Refusal::OutboxIntegrity)?;
        let index = r.u32().ok_or(Refusal::OutboxIntegrity)?;
        reserved.push(OutPoint { transaction, index });
    }
    let count = r.u32().ok_or(Refusal::OutboxIntegrity)? as usize;
    if count > mutiny_wallet_core_v8::partial::MAX_REQUIREMENTS {
        return Err(bad);
    }
    let mut missing = Vec::with_capacity(count);
    for _ in 0..count {
        missing.push(get_requirement(r).ok_or(Refusal::OutboxIntegrity)?);
    }
    let checksum = r.hash().ok_or(Refusal::OutboxIntegrity)?;
    r.finish().ok_or(Refusal::OutboxIntegrity)?;
    let record = OutboxRecord::from_stored(
        id,
        kind,
        bytes,
        complete,
        missing,
        Validity {
            created,
            expiry,
            valid_only_at,
            bound_to_parent,
        },
        reserved,
        queued_at,
        status,
        checksum,
    );
    record.verify()?;
    Ok(record)
}

/// What every binding of this file names: the chain and the file's random identifier. `Copy`, so
/// the helpers below can run while a write transaction holds the connection.
#[derive(Clone, Copy)]
struct Sealing {
    context: ChainContext,
    file_id: Hash,
}

/// One stored row, opened and verified.
struct Stored {
    seq: i64,
    record: OutboxRecord,
}

/// The protected durable outbox. See the module documentation.
pub struct OperationOutbox {
    // Field order matters: SQLite closes before the custody lease releases the path.
    db: Connection,
    context: ChainContext,
    sealing: Sealing,
    max_records: usize,
    max_bytes: usize,
    max_settled: usize,
    _lease: custody_acl_v2::Lease,
}

impl OperationOutbox {
    pub const DEFAULT_MAX_RECORDS: usize = 4096;
    pub const DEFAULT_MAX_BYTES: usize = 16 * 1024 * 1024;

    /// Open (creating it when new) the outbox at `path` for the chain `context`. `path` must be the
    /// allow-listed file in a custody directory (`custody_acl_v2::prepare`: absolute, owner and
    /// SYSTEM ACL, no reparse point, one link); anything else is `OUTBOX_LOCATION`.
    pub fn open(path: &Path, context: ChainContext) -> Result<Self, Refusal> {
        Self::open_with_limits(
            path,
            context,
            Self::DEFAULT_MAX_RECORDS,
            Self::DEFAULT_MAX_BYTES,
        )
    }

    /// [`Self::open`] with limits on the number and total size of OPEN records.
    pub fn open_with_limits(
        path: &Path,
        context: ChainContext,
        max_records: usize,
        max_bytes: usize,
    ) -> Result<Self, Refusal> {
        if path.file_name().and_then(|name| name.to_str()) != Some(FILE_NAME) {
            return Err(Refusal::OutboxLocation);
        }
        // Order W7: the file's format is decided before the custody lease or SQLite could touch it
        // (`custody_format`); a retired, newer, foreign or damaged file is refused and left unchanged.
        crate::custody_format::check_store(path, crate::custody_format::StoreKind::OperationOutbox)
            .map_err(|_| Refusal::OutboxIntegrity)?;
        let lease = custody_acl_v2::prepare(path).map_err(|_| Refusal::OutboxLocation)?;
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(storage)?;
        db.busy_timeout(BUSY_TIMEOUT).map_err(storage)?;
        let objects: i64 = db
            .query_row("SELECT count(*) FROM sqlite_master", [], |row| row.get(0))
            .map_err(storage)?;
        let application: i64 = db
            .query_row("PRAGMA application_id", [], |row| row.get(0))
            .map_err(storage)?;
        let version: i64 = db
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .map_err(storage)?;
        if !((objects == 0 && application == 0 && version == 0)
            || (application == APPLICATION_ID && version == SCHEMA_VERSION))
        {
            // Not an outbox of this format: never adopted, never migrated.
            return Err(Refusal::OutboxIntegrity);
        }
        custody_seal::configure(&db).map_err(storage)?;
        if objects == 0 {
            let file_id = custody_seal::random32().map_err(|_| Refusal::EntropyUnavailable)?;
            let probe = custody_seal::seal(
                PROBE,
                &Self::binding_for(&context, &file_id, b"probe", &[0; 32]),
            )
            .map_err(|_| Refusal::OutboxLocation)?;
            let transaction = db.unchecked_transaction().map_err(storage)?;
            transaction
                .pragma_update(None, "application_id", APPLICATION_ID)
                .map_err(storage)?;
            transaction
                .pragma_update(None, "user_version", SCHEMA_VERSION)
                .map_err(storage)?;
            for (_, sql) in SCHEMA {
                transaction.execute(sql, []).map_err(storage)?;
            }
            transaction
                .execute(
                    "INSERT INTO operation_outbox_context_v1(id,network,genesis,fingerprint,file_id,probe) VALUES(1,?1,?2,?3,?4,?5)",
                    params![
                        i64::from(context.network),
                        context.genesis.as_slice(),
                        context.fingerprint.as_slice(),
                        file_id.as_slice(),
                        probe
                    ],
                )
                .map_err(storage)?;
            transaction.commit().map_err(storage)?;
        }
        let (network, genesis, fingerprint, file_id, probe): (i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT network,genesis,fingerprint,file_id,probe FROM operation_outbox_context_v1 WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
            )
            .map_err(storage)?;
        if !custody_seal::schema_is_exact(&db, APPLICATION_ID, SCHEMA_VERSION, &SCHEMA)
            .map_err(storage)?
        {
            return Err(Refusal::OutboxIntegrity);
        }
        let stored = ChainContext {
            network: u32::try_from(network).map_err(integrity)?,
            genesis: genesis.try_into().map_err(integrity)?,
            fingerprint: fingerprint.try_into().map_err(integrity)?,
        };
        if stored != context {
            return Err(context_refusal(&context, &stored));
        }
        let file_id: Hash = file_id.try_into().map_err(integrity)?;
        // The probe: this Windows account must be able to open what this file sealed, under this
        // file's identifier and this chain. Another account, a copied DPAPI context or an edited
        // identifier is refused here, before any record is read.
        let opened = custody_seal::open(
            &probe,
            &Self::binding_for(&context, &file_id, b"probe", &[0; 32]),
        )
        .map_err(integrity)?;
        if opened.as_slice() != PROBE {
            return Err(Refusal::OutboxIntegrity);
        }
        let outbox = Self {
            db,
            context,
            sealing: Sealing { context, file_id },
            max_records,
            max_bytes,
            max_settled: DEFAULT_MAX_SETTLED,
            _lease: lease,
        };
        outbox.sealing.load(&outbox.db)?;
        Ok(outbox)
    }

    pub fn context(&self) -> &ChainContext {
        &self.context
    }

    /// How many settled records reconciliation keeps as history (default `DEFAULT_MAX_SETTLED`).
    pub fn set_max_settled(&mut self, keep: usize) {
        self.max_settled = keep;
    }

    fn binding_for(context: &ChainContext, file_id: &Hash, field: &[u8], id: &Hash) -> [u8; 64] {
        custody_seal::binding(
            BINDING_DOMAIN,
            &[
                field,
                &context.network.to_be_bytes(),
                &context.genesis,
                &context.fingerprint,
                file_id,
                id,
            ],
        )
    }

    fn check_context(&self, view: &ChainView<'_>) -> Result<(), Refusal> {
        let theirs = view.context();
        if theirs != self.context {
            return Err(context_refusal(&self.context, &theirs));
        }
        Ok(())
    }

    /// The public export of one queued record: a complete operation's signed bytes, or a partial
    /// operation in wallet-core's public `PartialApproval` container (Q12: public data only).
    /// A complete hash-lock CLAIM carries its preimage: exporting it discloses the preimage to
    /// whoever receives the file, exactly as inclusion will (the review said so before signing).
    pub fn export(&self, id: &Hash) -> Result<Vec<u8>, Refusal> {
        let record = Outbox::get(self, id)?.ok_or(Refusal::UnknownOperation)?;
        if record.complete {
            return Ok(record.bytes);
        }
        PartialApproval::from_record(&record, self.context)?.export()
    }
}

impl Sealing {
    fn binding(&self, field: &[u8], id: &Hash) -> [u8; 64] {
        OperationOutbox::binding_for(&self.context, &self.file_id, field, id)
    }

    /// Every row, opened, rebuilt and re-verified, ordered by identifier.
    fn load(&self, db: &Connection) -> Result<Vec<Stored>, Refusal> {
        let mut statement = db
            .prepare("SELECT seq,id,meta,raw FROM operation_outbox_records_v1 ORDER BY id")
            .map_err(storage)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                ))
            })
            .map_err(storage)?;
        let mut out = Vec::new();
        let mut held = BTreeSet::new();
        for row in rows {
            let (seq, id, meta, raw) = row.map_err(storage)?;
            let id: Hash = id.try_into().map_err(integrity)?;
            let meta = custody_seal::open(&meta, &self.binding(b"meta", &id)).map_err(integrity)?;
            let bytes = custody_seal::open(&raw, &self.binding(b"raw", &id)).map_err(integrity)?;
            let record = decode_record(&meta, bytes.to_vec())?;
            if record.id != id {
                return Err(Refusal::OutboxIntegrity);
            }
            // A coin or resource is held by one open record at most.
            if record.status.is_open() {
                for point in &record.reserved {
                    if !held.insert(point.clone()) {
                        return Err(Refusal::OutboxIntegrity);
                    }
                }
            }
            out.push(Stored { seq, record });
        }
        Ok(out)
    }

    fn write_meta(&self, db: &Connection, seq: i64, record: &OutboxRecord) -> Result<(), Refusal> {
        let meta = custody_seal::seal(&encode_meta(record), &self.binding(b"meta", &record.id))
            .map_err(|_| Refusal::OutboxIntegrity)?;
        let rows = db
            .execute(
                "UPDATE operation_outbox_records_v1 SET meta=?1 WHERE seq=?2",
                params![meta, seq],
            )
            .map_err(storage)?;
        if rows != 1 {
            return Err(Refusal::OutboxIntegrity);
        }
        Ok(())
    }

    /// Insert `record` as a new row (sealed meta and raw bytes) after every existing row.
    fn insert(&self, db: &Connection, record: &OutboxRecord) -> Result<(), Refusal> {
        let seq: i64 = db
            .query_row(
                "SELECT COALESCE(MAX(seq),0)+1 FROM operation_outbox_records_v1",
                [],
                |row| row.get(0),
            )
            .map_err(storage)?;
        let meta = custody_seal::seal(&encode_meta(record), &self.binding(b"meta", &record.id))
            .map_err(|_| Refusal::OutboxIntegrity)?;
        let raw = custody_seal::seal(&record.bytes, &self.binding(b"raw", &record.id))
            .map_err(|_| Refusal::OutboxIntegrity)?;
        db.execute(
            "INSERT INTO operation_outbox_records_v1(seq,id,meta,raw) VALUES(?1,?2,?3,?4)",
            params![seq, record.id.as_slice(), meta, raw],
        )
        .map_err(storage)?;
        Ok(())
    }

    /// Delete one row.
    fn delete(&self, db: &Connection, seq: i64) -> Result<(), Refusal> {
        let rows = db
            .execute(
                "DELETE FROM operation_outbox_records_v1 WHERE seq=?1",
                [seq],
            )
            .map_err(storage)?;
        if rows != 1 {
            return Err(Refusal::OutboxIntegrity);
        }
        Ok(())
    }

    /// Delete settled records beyond the `keep` most recently queued (insertion order).
    fn prune(&self, db: &Connection, stored: &[Stored], keep: usize) -> Result<usize, Refusal> {
        let mut settled: Vec<i64> = stored
            .iter()
            .filter(|s| !s.record.status.is_open())
            .map(|s| s.seq)
            .collect();
        settled.sort_unstable();
        let excess = settled.len().saturating_sub(keep);
        for seq in settled.into_iter().take(excess) {
            db.execute(
                "DELETE FROM operation_outbox_records_v1 WHERE seq=?1",
                [seq],
            )
            .map_err(storage)?;
        }
        Ok(excess)
    }
}

/// The wrong-chain refusal (the same field order as wallet-core's).
fn context_refusal(ours: &ChainContext, theirs: &ChainContext) -> Refusal {
    use mutiny_wallet_core_v8::refusal::ContextField;
    Refusal::WrongContext(if ours.network != theirs.network {
        ContextField::Network
    } else if ours.genesis != theirs.genesis {
        ContextField::Genesis
    } else {
        ContextField::Fingerprint
    })
}

/// Whether the caller's metadata of `signed` is exactly what an earlier admission derived from the
/// same bytes (the check `SqliteOutbox` makes with the handler's description).
fn same_metadata(existing: &OutboxRecord, signed: &SignedOperation) -> bool {
    let mut reserved = signed.reserved().to_vec();
    reserved.sort();
    reserved.dedup();
    existing.id == signed.id()
        && existing.kind == signed.kind()
        && existing.complete == signed.is_complete()
        && existing.missing.as_slice() == signed.missing()
        && existing.validity == *signed.validity()
        && existing.reserved == reserved
}

impl fmt::Debug for OperationOutbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OperationOutbox")
            .field("context", &self.context)
            .field("max_records", &self.max_records)
            .field("max_bytes", &self.max_bytes)
            .field("max_settled", &self.max_settled)
            .finish()
    }
}

impl Outbox for OperationOutbox {
    fn commit(&mut self, signed: &SignedOperation, view: &ChainView<'_>) -> Result<Hash, Refusal> {
        self.check_context(view)?;
        let sealing = self.sealing;
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let stored = sealing.load(&transaction)?;
        // Idempotent while the record is open: the same bytes again change nothing. A settled or
        // forgotten record with the same bytes is replaced by a fresh admission (which refuses an
        // operation that can no longer be included); nothing is deleted unless that admission passes.
        let mut replaced = None;
        if let Some(existing) = stored.iter().find(|s| s.record.bytes == signed.bytes()) {
            if !same_metadata(&existing.record, signed) {
                return Err(Refusal::VerificationFailed(
                    "the operation's metadata does not match its bytes",
                ));
            }
            if existing.record.status.is_open() {
                return Ok(existing.record.id);
            }
            replaced = Some(existing.seq);
        }
        // Never other bytes under an existing identifier.
        if stored
            .iter()
            .any(|s| s.record.id == signed.id() && s.record.bytes != signed.bytes())
        {
            return Err(Refusal::OutboxIntegrity);
        }
        // Independent verification through consensus code, inside the write lock; the record's
        // metadata is derived from the bytes, and `view.reserved()` is checked.
        let record = outbox::admit_record(signed, view)?;
        let others: Vec<&OutboxRecord> = stored
            .iter()
            .filter(|s| Some(s.seq) != replaced)
            .map(|s| &s.record)
            .collect();
        if others.iter().any(|r| r.id == record.id) {
            return Err(Refusal::OutboxIntegrity);
        }
        let open: Vec<&&OutboxRecord> = others.iter().filter(|r| r.status.is_open()).collect();
        let open_bytes = open
            .iter()
            .try_fold(0usize, |sum, r| sum.checked_add(r.bytes.len()))
            .ok_or(Refusal::OutboxIntegrity)?;
        if open.len() >= self.max_records
            || open_bytes
                .checked_add(record.bytes.len())
                .is_none_or(|sum| sum > self.max_bytes)
        {
            return Err(Refusal::OutboxFull);
        }
        let held: BTreeSet<&OutPoint> = open.iter().flat_map(|r| r.reserved.iter()).collect();
        if record.reserved.iter().any(|point| held.contains(point)) {
            return Err(Refusal::ReservedInput);
        }
        if let Some(seq) = replaced {
            sealing.delete(&transaction, seq)?;
        }
        sealing.insert(&transaction, &record)?;
        custody_seal::crash_point("outbox-commit-before-commit");
        transaction.commit().map_err(storage)?;
        custody_seal::crash_point("outbox-commit-after-commit");
        Ok(record.id)
    }

    /// The OPEN partial record `partial` is replaced by `complete`, its completion, in ONE write
    /// transaction (wallet review fixes, MINOR-1): the complete record takes over the partial's
    /// reservations and no reader, crash or refusal ever leaves neither or both. wallet-core's
    /// `outbox::admit_replacement_record` verifies through consensus code that `complete` is the
    /// completion of exactly that open partial (the same kind and operation identity, the same
    /// reserved coins and resources, the same validity); anything else is `OUTBOX_INTEGRITY` and
    /// changes nothing, an unknown `partial` is `UNKNOWN_OPERATION`. Idempotent: once the complete
    /// record is queued, the same call returns its identifier again.
    fn replace_partial(
        &mut self,
        partial: &Hash,
        complete: &SignedOperation,
        view: &ChainView<'_>,
    ) -> Result<Hash, Refusal> {
        self.check_context(view)?;
        let sealing = self.sealing;
        let max_bytes = self.max_bytes;
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let stored = sealing.load(&transaction)?;
        // A retry after success changes nothing (an open record of other, partial, bytes is not a
        // completion); a settled record of the complete bytes is replaced as `commit` would.
        let mut settled_twin = None;
        if let Some(existing) = stored.iter().find(|s| s.record.bytes == complete.bytes()) {
            if !same_metadata(&existing.record, complete) {
                return Err(Refusal::VerificationFailed(
                    "the operation's metadata does not match its bytes",
                ));
            }
            if existing.record.status.is_open() {
                return if existing.record.complete {
                    Ok(existing.record.id)
                } else {
                    Err(Refusal::OutboxIntegrity)
                };
            }
            settled_twin = Some(existing.seq);
        }
        let old = stored
            .iter()
            .find(|s| s.record.id == *partial)
            .ok_or(Refusal::UnknownOperation)?;
        // Independent verification through consensus code, inside the write lock.
        let record = outbox::admit_replacement_record(&old.record, complete, view)?;
        let others: Vec<&OutboxRecord> = stored
            .iter()
            .filter(|s| s.seq != old.seq && Some(s.seq) != settled_twin)
            .map(|s| &s.record)
            .collect();
        // Never other bytes under an existing identifier (the partial's own goes).
        if others.iter().any(|r| r.id == record.id) {
            return Err(Refusal::OutboxIntegrity);
        }
        // One open record takes the place of another: only the total size can grow.
        let open: Vec<&&OutboxRecord> = others.iter().filter(|r| r.status.is_open()).collect();
        let open_bytes = open
            .iter()
            .try_fold(0usize, |sum, r| sum.checked_add(r.bytes.len()))
            .ok_or(Refusal::OutboxIntegrity)?;
        if open_bytes
            .checked_add(record.bytes.len())
            .is_none_or(|sum| sum > max_bytes)
        {
            return Err(Refusal::OutboxFull);
        }
        // Nothing else holds what the replacement takes over (the partial held it alone).
        let held: BTreeSet<&OutPoint> = open.iter().flat_map(|r| r.reserved.iter()).collect();
        if record.reserved.iter().any(|point| held.contains(point)) {
            return Err(Refusal::ReservedInput);
        }
        // The swap, inside this one transaction.
        sealing.delete(&transaction, old.seq)?;
        if let Some(seq) = settled_twin {
            sealing.delete(&transaction, seq)?;
        }
        custody_seal::crash_point("outbox-replace-partial-removed");
        sealing.insert(&transaction, &record)?;
        custody_seal::crash_point("outbox-replace-before-commit");
        transaction.commit().map_err(storage)?;
        custody_seal::crash_point("outbox-replace-after-commit");
        Ok(record.id)
    }

    fn records(&self) -> Result<Vec<OutboxRecord>, Refusal> {
        Ok(self
            .sealing
            .load(&self.db)?
            .into_iter()
            .map(|s| s.record)
            .collect())
    }

    fn get(&self, id: &Hash) -> Result<Option<OutboxRecord>, Refusal> {
        // Every row is opened and verified, so a damaged neighbour is reported too.
        Ok(self
            .sealing
            .load(&self.db)?
            .into_iter()
            .map(|s| s.record)
            .find(|record| record.id == *id))
    }

    fn reconcile(&mut self, view: &ChainView<'_>) -> Result<ReconcileReport, Refusal> {
        self.check_context(view)?;
        let sealing = self.sealing;
        let max_settled = self.max_settled;
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let mut stored = sealing.load(&transaction)?;
        let mut report = ReconcileReport::default();
        for entry in &mut stored {
            if !entry.record.status.is_open() {
                continue;
            }
            let next = match outbox::settle(&entry.record, view)? {
                Settlement::Pending => {
                    report.still_pending += 1;
                    continue;
                }
                Settlement::Confirmed(height) => {
                    report.confirmed += 1;
                    OutboxStatus::Confirmed(height)
                }
                Settlement::Expired => {
                    report.expired += 1;
                    OutboxStatus::Expired
                }
                Settlement::InputsSpent => {
                    report.inputs_spent += 1;
                    OutboxStatus::InputsSpent
                }
                // wallet-core's `Settlement` is non-exhaustive (W9): the diagnostic `Stranded` (a
                // bond funding included without its creation) settles here as `InputsSpent`,
                // exactly as before it existed.
                _ => {
                    report.inputs_spent += 1;
                    OutboxStatus::InputsSpent
                }
            };
            entry.record.status = next;
            sealing.write_meta(&transaction, entry.seq, &entry.record)?;
        }
        report.pruned = sealing.prune(&transaction, &stored, max_settled)?;
        transaction.commit().map_err(storage)?;
        Ok(report)
    }

    fn forget(&mut self, id: &Hash) -> Result<(), Refusal> {
        let sealing = self.sealing;
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let mut entry = sealing
            .load(&transaction)?
            .into_iter()
            .find(|s| s.record.id == *id)
            .ok_or(Refusal::UnknownOperation)?;
        if entry.record.status.is_open() {
            entry.record.status = OutboxStatus::Forgotten;
            sealing.write_meta(&transaction, entry.seq, &entry.record)?;
        }
        transaction.commit().map_err(storage)?;
        Ok(())
    }

    fn prune_settled(&mut self, keep: usize) -> Result<usize, Refusal> {
        let sealing = self.sealing;
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        // Read (and verify) everything first, so a damaged store is reported instead of trimmed.
        let stored = sealing.load(&transaction)?;
        let pruned = sealing.prune(&transaction, &stored, keep)?;
        transaction.commit().map_err(storage)?;
        Ok(pruned)
    }
}

#[cfg(all(test, windows))]
pub(crate) mod tests {
    use super::*;
    use crate::{
        preimage_store::PreimageVault,
        test_support::{
            TestDir, conditional_kit, custody_file, run_child,
            synthetic::{World, address, identity, key_a, key_b},
        },
    };
    use mutiny_consensus_v8::trading_v1::{
        self, NativeLock, NativeLockKind, NativeRecord, Strikes, preimage_hash,
    };
    use mutiny_wallet_core_v8::{
        Blob, ClaimRequest, HashLockRequest, KeySigner, OperationRequest, PaymentRequest, Preimage,
        Signer, adopt, ops::conditional, plan, review,
    };
    use zeroize::Zeroizing;

    pub(crate) fn context_of(world: &World) -> ChainContext {
        world.view().context()
    }

    /// Key A pays key B from one 5,000,000-atom coin at head 100 (public TEST-VALUE keys).
    pub(crate) fn payment_world() -> World {
        let mut world = World::with_wallets(100);
        world.coin(address(&key_a(), 1), 5_000_000, 1, false, 1, 0);
        world
    }

    /// Review, every confirmation, approval and authorization of a payment of `amount`.
    pub(crate) fn signed_payment(world: &World, amount: u64) -> SignedOperation {
        let view = world.view();
        let planned = plan(
            &OperationRequest::Payment(PaymentRequest::new(address(&key_b(), 1), amount)),
            &view,
            &identity(&key_a()),
        )
        .unwrap();
        let approval = conditional_kit::approve(&review(&planned, &view).unwrap(), &view);
        KeySigner::for_test(key_a())
            .unwrap()
            .authorize(planned, approval, &view)
            .unwrap()
    }

    /// A hash lock of 10,000 STRIKES from key A to key B on chain (refund height 150), the fee coin
    /// of key B, and key B's signed CLAIM with `preimage` (it carries the preimage in clear).
    pub(crate) fn signed_claim(world: &mut World, preimage: [u8; 32]) -> SignedOperation {
        let lock = [0x6c; 32];
        world.state.protocol_records.insert(
            trading_v1::record_key(0, lock),
            NativeRecord::Lock(NativeLock {
                context: conditional_kit::context_of(&world.anchor),
                trade: [1; 32],
                contract: [2; 32],
                generation: 1,
                sender: address(&key_a(), 1),
                recipient: address(&key_b(), 1),
                amount: Strikes(10_000),
                created_height: 50,
                kind: NativeLockKind::Hash {
                    condition: preimage_hash(&preimage),
                    refund_height: 150,
                },
            })
            .encode(lock)
            .unwrap(),
        );
        // Tag 0x5c: no byte pattern of the synthetic chain context ([1; 32], [2; 32]) is reused.
        world.coin(address(&key_b(), 1), 100_000, 1, false, 0x5c, 0);
        let view = world.view();
        let planned = plan(
            &OperationRequest::ConditionalClaim(ClaimRequest::new(
                lock,
                Preimage::from_bytes(preimage),
            )),
            &view,
            &identity(&key_b()),
        )
        .unwrap();
        let approval = conditional_kit::approve(&review(&planned, &view).unwrap(), &view);
        KeySigner::for_test(key_b())
            .unwrap()
            .authorize(planned, approval, &view)
            .unwrap()
    }

    /// Head 100; key A holds two 3,000,000-atom coins (one for each of two hash locks).
    fn lock_world() -> World {
        let mut world = World::with_wallets(100);
        world.coin(address(&key_a(), 1), 3_000_000, 1, false, 1, 0);
        world.coin(address(&key_a(), 1), 3_000_000, 1, false, 2, 0);
        world
    }

    /// A hash lock of 1,000,000 atoms from key A to key B under `condition`, filling the maker's
    /// offer of nonce `nonce` (refund height 150): A's partial (B's approval and the maker's fill
    /// still missing) and the complete operation, which has an identifier of its own. Coins in
    /// `world.reserved` are not used.
    fn lock_parts(
        world: &World,
        nonce: u8,
        condition: [u8; 32],
    ) -> (SignedOperation, SignedOperation) {
        let view = world.view();
        let maker = conditional_kit::maker_key();
        let offer = conditional_kit::signed_offer(
            &maker,
            conditional_kit::context_of(&world.anchor),
            1,
            1000,
            1_000_000,
            1,
            nonce,
        );
        let request = OperationRequest::HashLock(HashLockRequest::new(
            Blob::new(conditional_kit::offer_bytes(&offer)),
            address(&key_b(), 1),
            1_000_000,
            condition,
            150,
        ));
        let planned = plan(&request, &view, &identity(&key_a())).unwrap();
        let sender = KeySigner::for_test(key_a())
            .unwrap()
            .authorize(
                planned.clone(),
                conditional_kit::approve(&review(&planned, &view).unwrap(), &view),
                &view,
            )
            .unwrap();
        let adopted = adopt(sender.bytes(), &view, &identity(&key_b())).unwrap();
        let recipient = KeySigner::for_test(key_b())
            .unwrap()
            .authorize(
                adopted.clone(),
                conditional_kit::approve(&review(&adopted, &view).unwrap(), &view),
                &view,
            )
            .unwrap();
        let fill = conditional_kit::fill_for(sender.bytes(), &offer, &maker);
        let complete =
            conditional::complete(&[sender.bytes(), recipient.bytes()], Some(&fill), &view)
                .unwrap();
        assert!(!sender.is_complete() && complete.is_complete());
        (sender, complete)
    }

    /// Wallet review fixes, MINOR-1: the sealed outbox replaces an open partial by its completion in
    /// one step; the complete record takes over exactly the partial's reservations.
    #[test]
    fn replace_partial_puts_the_completion_in_the_partials_place_in_one_step() {
        let world = lock_world();
        let (partial, complete) = lock_parts(&world, 6, [9; 32]);
        let view = world.view();
        let base = TestDir::new("w8-desktop-replace");
        let path = custody_file(&base, FILE_NAME);
        let mut outbox = OperationOutbox::open(&path, context_of(&world)).unwrap();
        let partial_id = outbox.commit(&partial, &view).unwrap();
        let held = outbox.reserved().unwrap();
        assert!(!held.is_empty());
        // `commit` alone cannot queue the completion while the partial holds its coin and offer.
        assert_eq!(
            outbox.commit(&complete, &view).unwrap_err(),
            Refusal::ReservedInput
        );
        let id = outbox
            .replace_partial(&partial_id, &complete, &view)
            .unwrap();
        assert_eq!(id, complete.id());
        assert_ne!(
            id, partial_id,
            "a partial hash lock is identified by its exact bytes"
        );
        assert!(outbox.get(&partial_id).unwrap().is_none());
        let record = outbox.get(&id).unwrap().unwrap();
        assert_eq!(record.bytes, complete.bytes());
        assert!(record.complete && record.missing.is_empty());
        assert_eq!(record.status, OutboxStatus::Queued);
        assert_eq!(outbox.reserved().unwrap(), held);
        assert_eq!(outbox.records().unwrap().len(), 1);
        // A retry changes nothing, and the result is what a restart reads back.
        assert_eq!(
            outbox
                .replace_partial(&partial_id, &complete, &view)
                .unwrap(),
            id
        );
        drop(outbox);
        let outbox = OperationOutbox::open(&path, context_of(&world)).unwrap();
        let records = outbox.records().unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].bytes, complete.bytes());
        assert_eq!(outbox.reserved().unwrap(), held);
    }

    /// Only the completion of THAT open partial replaces it: an unknown identifier, the partial of
    /// another operation, another operation's completion, a partial offered as a completion and a
    /// forgotten partial are refused and change nothing.
    #[test]
    fn replace_partial_refuses_anything_but_the_completion_of_that_open_partial() {
        let mut world = lock_world();
        let (partial, complete) = lock_parts(&world, 6, [9; 32]);
        world.reserved = partial.reserved().iter().cloned().collect();
        let (other_partial, other_complete) = lock_parts(&world, 7, [8; 32]);
        world.reserved.clear();
        let view = world.view();
        let base = TestDir::new("w8-desktop-replace-refused");
        let mut outbox =
            OperationOutbox::open(&custody_file(&base, FILE_NAME), context_of(&world)).unwrap();
        outbox.commit(&partial, &view).unwrap();
        outbox.commit(&other_partial, &view).unwrap();
        let before = (outbox.records().unwrap(), outbox.reserved().unwrap());
        for (given, offered, refusal) in [
            ([0x55; 32], &complete, Refusal::UnknownOperation),
            (other_partial.id(), &complete, Refusal::OutboxIntegrity),
            (partial.id(), &other_complete, Refusal::OutboxIntegrity),
            (partial.id(), &other_partial, Refusal::OutboxIntegrity),
            (partial.id(), &partial, Refusal::OutboxIntegrity),
        ] {
            assert_eq!(
                outbox.replace_partial(&given, offered, &view).unwrap_err(),
                refusal
            );
            assert_eq!(
                (outbox.records().unwrap(), outbox.reserved().unwrap()),
                before
            );
        }
        outbox.forget(&partial.id()).unwrap();
        assert_eq!(
            outbox
                .replace_partial(&partial.id(), &complete, &view)
                .unwrap_err(),
            Refusal::OutboxIntegrity
        );
        // The completion of the other partial does replace it.
        assert_eq!(
            outbox
                .replace_partial(&other_partial.id(), &other_complete, &view)
                .unwrap(),
            other_complete.id()
        );
    }

    const REPLACE_CHILD: &str = "BUILD8_W8_REPLACE_CHILD";

    /// The child of the replacement crash test: open the outbox the parent prepared, then replace
    /// its partial; the crash point named by BUILD8_W7_CRASH_POINT ends the process inside.
    #[test]
    fn operation_outbox_replace_crash_child() {
        let Some(dir) = std::env::var_os(REPLACE_CHILD) else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        assert_eq!(dir.parent(), Some(std::env::temp_dir().as_path()));
        let world = lock_world();
        let view = world.view();
        let partial: Hash = std::fs::read(dir.join("partial.id"))
            .unwrap()
            .try_into()
            .unwrap();
        let complete =
            SignedOperation::import(&std::fs::read(dir.join("complete.bin")).unwrap(), &view)
                .unwrap();
        let mut outbox = OperationOutbox::open(
            &dir.join("WalletCustodyV2").join(FILE_NAME),
            context_of(&world),
        )
        .unwrap();
        outbox.replace_partial(&partial, &complete, &view).unwrap();
        std::process::exit(98);
    }

    /// Kill the process after the partial's row is deleted, after the complete row is inserted and
    /// right after the commit: a restart finds exactly the partial (the first two) or exactly the
    /// complete record (the last), with the same reservations; never neither, never both.
    #[test]
    fn a_kill_inside_replace_partial_leaves_the_partial_or_the_complete_record() {
        let world = lock_world();
        let (partial, complete) = lock_parts(&world, 6, [9; 32]);
        for (point, replaced) in [
            ("outbox-replace-partial-removed", false),
            ("outbox-replace-before-commit", false),
            ("outbox-replace-after-commit", true),
        ] {
            let base = TestDir::new("w8-replace-crash");
            let held = {
                let mut outbox =
                    OperationOutbox::open(&custody_file(&base, FILE_NAME), context_of(&world))
                        .unwrap();
                outbox.commit(&partial, &world.view()).unwrap();
                outbox.reserved().unwrap()
            };
            std::fs::write(base.file("partial.id"), partial.id()).unwrap();
            std::fs::write(base.file("complete.bin"), complete.bytes()).unwrap();
            let output = run_child(
                "operation_outbox::tests::operation_outbox_replace_crash_child",
                &[
                    (REPLACE_CHILD, base.path().as_os_str()),
                    ("BUILD8_W7_CRASH_POINT", std::ffi::OsStr::new(point)),
                ],
            );
            assert_eq!(
                output.status.code(),
                Some(97),
                "child ({point}) failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let outbox =
                OperationOutbox::open(&custody_file(&base, FILE_NAME), context_of(&world)).unwrap();
            let records = outbox.records().unwrap();
            assert_eq!(records.len(), 1, "{point}: exactly one record");
            let expected = if replaced { &complete } else { &partial };
            assert_eq!(records[0].bytes, expected.bytes(), "{point}");
            assert_eq!(records[0].status, OutboxStatus::Queued, "{point}");
            assert_eq!(
                outbox.reserved().unwrap(),
                held,
                "{point}: the reservations"
            );
        }
    }

    fn raw_files(base: &TestDir) -> Vec<u8> {
        let mut all = std::fs::read(custody_file(base, FILE_NAME)).unwrap();
        let journal = custody_file(base, &format!("{FILE_NAME}-journal"));
        if journal.exists() {
            all.extend(std::fs::read(journal).unwrap());
        }
        all
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// The phase 5A finding: a queued CLAIM carries its preimage in clear until inclusion. In this
    /// outbox neither the preimage nor the signed bytes nor its reservations appear in the file.
    #[test]
    fn a_queued_claim_leaves_no_plaintext_preimage_in_the_file() {
        let base = TestDir::new("w7-outbox-plaintext");
        let mut secret = Zeroizing::new([0u8; 32]);
        mutiny_crypto_v2::fill_os_random(secret.as_mut()).unwrap();
        // The preimage comes from the desktop's sealed preimage store, as a claim would get it.
        let mut preimages =
            PreimageVault::open(&custody_file(&base, crate::preimage_store::FILE_NAME)).unwrap();
        let condition = preimages.insert_disclosed(secret.clone()).unwrap();
        let mut world = World::with_wallets(100);
        let claim = signed_claim(&mut world, *secret);
        assert!(claim.is_complete());
        assert!(
            contains(claim.bytes(), secret.as_ref()),
            "the claim carries the preimage"
        );
        let request = mutiny_wallet_core_v8::ops::conditional::claim_request(
            &preimages,
            [0x6c; 32],
            &world.view(),
        )
        .unwrap();
        assert_eq!(request.preimage.condition(), condition);
        let mut outbox =
            OperationOutbox::open(&custody_file(&base, FILE_NAME), context_of(&world)).unwrap();
        let id = outbox.commit(&claim, &world.view()).unwrap();
        assert_eq!(outbox.get(&id).unwrap().unwrap().bytes, claim.bytes());
        drop(outbox);
        drop(preimages);
        let files = raw_files(&base);
        assert!(
            !contains(&files, secret.as_ref()),
            "plaintext preimage in the outbox file"
        );
        assert!(
            !contains(&files, &claim.bytes()[..64]),
            "plaintext signed bytes in the file"
        );
        for point in claim.reserved() {
            assert!(
                !contains(&files, &point.transaction),
                "a reservation is stored in clear"
            );
        }
        let preimage_file =
            std::fs::read(custody_file(&base, crate::preimage_store::FILE_NAME)).unwrap();
        assert!(!contains(&preimage_file, secret.as_ref()));
        // And the exact bytes come back after a restart.
        let outbox =
            OperationOutbox::open(&custody_file(&base, FILE_NAME), context_of(&world)).unwrap();
        assert_eq!(outbox.get(&id).unwrap().unwrap().bytes, claim.bytes());
    }

    const W10_CLAIM_CHILD: &str = "BUILD8_W10_CLAIM_CHILD";

    /// The child of the W10 claim test: sign a hash-lock CLAIM (it carries the preimage, which the
    /// parent passes in the environment: process memory, never a file) and queue it in the outbox of
    /// the folder the parent names; the crash point named by BUILD8_W7_CRASH_POINT (or the mode
    /// "signed-not-committed") ends the process, skipping every destructor.
    #[test]
    fn claim_crash_child() {
        let Some(dir) = std::env::var_os(W10_CLAIM_CHILD) else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        assert_eq!(dir.parent(), Some(std::env::temp_dir().as_path()));
        let secret: [u8; 32] = hex::decode(std::env::var("BUILD8_W10_SECRET").unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let mut world = World::with_wallets(100);
        let claim = signed_claim(&mut world, secret);
        assert!(
            contains(claim.bytes(), &secret),
            "the claim carries the preimage"
        );
        if std::env::var("BUILD8_W10_MODE").as_deref() == Ok("signed-not-committed") {
            std::process::exit(97);
        }
        let mut outbox = OperationOutbox::open(
            &dir.join("WalletCustodyV2").join(FILE_NAME),
            context_of(&world),
        )
        .unwrap();
        outbox.commit(&claim, &world.view()).unwrap();
        std::process::exit(98);
    }

    /// Order W10: a queued CLAIM is sealed before its first byte reaches SQLite. A process killed
    /// after signing but before the commit, inside the commit's transaction (a hot journal remains),
    /// or right after the commit leaves NO plaintext preimage in any file of the folder (raw or
    /// hexadecimal), and the next open recovers exactly the signed bytes or nothing, after which the
    /// folder is clean again. The outbox keeps SQLite's temporary files in memory.
    #[test]
    fn a_queued_claim_leaves_no_plaintext_on_disk_at_any_crash_point() {
        let mut secret = [0u8; 32];
        mutiny_crypto_v2::fill_os_random(&mut secret).unwrap();
        for (mode, point, committed) in [
            ("signed-not-committed", "", false),
            ("crash", "outbox-commit-before-commit", false),
            ("crash", "outbox-commit-after-commit", true),
        ] {
            let base = TestDir::new("w10-claim-crash");
            let output = run_child(
                "operation_outbox::tests::claim_crash_child",
                &[
                    (W10_CLAIM_CHILD, base.path().as_os_str()),
                    (
                        "BUILD8_W10_SECRET",
                        std::ffi::OsStr::new(&hex::encode(secret)),
                    ),
                    ("BUILD8_W10_MODE", std::ffi::OsStr::new(mode)),
                    ("BUILD8_W7_CRASH_POINT", std::ffi::OsStr::new(point)),
                ],
            );
            assert_eq!(
                output.status.code(),
                Some(97),
                "child ({mode} {point}) failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let journal = custody_file(&base, &format!("{FILE_NAME}-journal"));
            assert_eq!(
                journal.exists(),
                point == "outbox-commit-before-commit",
                "{mode} {point}: the crash leftover"
            );
            crate::test_support::assert_no_secret_in_files(base.path(), &secret, point);
            if journal.exists() {
                // SQLite syncs a journal's header when it commits, or earlier when its page cache
                // spills; this small transaction does not spill, so the journal left before the
                // commit is not hot: SQLite ignores it and never reads it as data. (The safety does
                // not rest on this: the journal holds sealed values only, scanned above.)
                assert_eq!(
                    std::fs::read(&journal).unwrap()[..8],
                    [0u8; 8],
                    "{point}: header"
                );
            }
            // Recovery from the leftovers: the exact signed claim, or nothing.
            let world = World::with_wallets(100);
            let mut outbox =
                OperationOutbox::open(&custody_file(&base, FILE_NAME), context_of(&world)).unwrap();
            let temp_store: i64 = outbox
                .db
                .query_row("PRAGMA temp_store", [], |row| row.get(0))
                .unwrap();
            assert_eq!(temp_store, 2, "temp_store=MEMORY");
            let records = outbox.records().unwrap();
            if committed {
                assert_eq!(records.len(), 1, "{point}");
                assert!(
                    contains(&records[0].bytes, &secret),
                    "{point}: the exact claim"
                );
                assert_eq!(outbox.export(&records[0].id).unwrap(), records[0].bytes);
            } else {
                assert!(records.is_empty(), "{mode} {point}: a record survived");
            }
            crate::test_support::assert_no_secret_in_files(
                base.path(),
                &secret,
                &format!("{mode} {point}, after recovery"),
            );
            // The next write (a payment of the same chain) replaces a stale journal and deletes it.
            let payments = payment_world();
            outbox
                .commit(&signed_payment(&payments, 1_000_000), &payments.view())
                .unwrap();
            drop(outbox);
            assert!(
                !journal.exists(),
                "{point}: the stale journal outlived the next write"
            );
            crate::test_support::assert_no_secret_in_files(
                base.path(),
                &secret,
                &format!("{mode} {point}, after the next write"),
            );
        }
    }

    /// The `SqliteOutbox` contract: exact bytes durable across a restart, metadata derived from the
    /// bytes (a lie is refused), idempotent while open, a coin held by one open record only, only
    /// open records count, `forget` releases without revoking, reconciliation from verified state,
    /// chain binding.
    #[test]
    fn the_durable_outbox_contract_holds_across_a_restart() {
        let base = TestDir::new("w7-outbox-contract");
        let path = custody_file(&base, FILE_NAME);
        let world = payment_world();
        let view = world.view();
        let first = signed_payment(&world, 1_000_000);
        let competing = signed_payment(&world, 2_000_000);
        let mut outbox = OperationOutbox::open(&path, context_of(&world)).unwrap();
        // Metadata that disagrees with the bytes is refused.
        let SignedOperation::Complete {
            kind,
            id,
            bytes,
            validity,
            ..
        } = first.clone()
        else {
            panic!("a payment is complete");
        };
        let lying = SignedOperation::Complete {
            kind,
            id,
            bytes,
            validity,
            reserved: Vec::new(),
        };
        assert!(outbox.commit(&lying, &view).is_err());
        assert!(outbox.records().unwrap().is_empty());
        let id = outbox.commit(&first, &view).unwrap();
        assert_eq!(outbox.commit(&first, &view).unwrap(), id, "idempotent");
        // The same coin again: refused, nothing stored.
        assert_eq!(
            outbox.commit(&competing, &view).unwrap_err(),
            Refusal::ReservedInput
        );
        assert_eq!(outbox.records().unwrap().len(), 1);
        let reserved = outbox.reserved().unwrap();
        assert_eq!(reserved, first.reserved().iter().cloned().collect());
        drop(outbox);
        // A restart keeps exactly the bytes, the reservation and the status.
        let mut outbox = OperationOutbox::open(&path, context_of(&world)).unwrap();
        let record = outbox.get(&id).unwrap().unwrap();
        assert_eq!(record.bytes, first.bytes());
        assert_eq!(record.status, OutboxStatus::Queued);
        assert_eq!(outbox.reserved().unwrap(), reserved);
        assert_eq!(outbox.export(&id).unwrap(), first.bytes());
        // Another chain is refused.
        let mut other = World::with_wallets(100);
        other.anchor.genesis = [9; 32];
        assert!(matches!(
            outbox.commit(&first, &other.view()),
            Err(Refusal::WrongContext(_))
        ));
        // Forget releases the coin (and revokes nothing); the competing payment then fits.
        outbox.forget(&id).unwrap();
        assert!(outbox.reserved().unwrap().is_empty());
        let second = outbox.commit(&competing, &view).unwrap();
        assert_eq!(outbox.pending().unwrap().len(), 1);
        // Reconciliation from a verified view past the window: expired, reservation released.
        let mut late = World::with_wallets(100_000);
        late.state = world.state.clone();
        assert_eq!(outbox.reconcile(&late.view()).unwrap().expired, 1);
        assert!(outbox.reserved().unwrap().is_empty());
        assert_eq!(
            outbox.get(&second).unwrap().unwrap().status,
            OutboxStatus::Expired
        );
        // Settled history is trimmed, open records never.
        assert_eq!(outbox.prune_settled(0).unwrap(), 2);
        assert!(outbox.records().unwrap().is_empty());
        drop(outbox);
        assert!(matches!(
            OperationOutbox::open(&path, context_of(&other)),
            Err(Refusal::WrongContext(_))
        ));
        // A name that is not the allow-listed file, or not in a custody directory, is refused.
        assert_eq!(
            OperationOutbox::open(&base.file(FILE_NAME), context_of(&world)).unwrap_err(),
            Refusal::OutboxLocation
        );
        assert_eq!(
            OperationOutbox::open(&custody_file(&base, "outbox.sqlite"), context_of(&world))
                .unwrap_err(),
            Refusal::OutboxLocation
        );
    }

    /// Tampering is detected (any changed byte of a sealed value, a value moved to another row or
    /// field, an edited identifier) and a file sealed under another key (here: another file
    /// identifier) is refused at open.
    #[test]
    fn tampering_and_a_wrong_key_are_refused() {
        // An EMPTY outbox under another key (here: another file identifier): only the probe can
        // tell, and it refuses the file.
        {
            let base = TestDir::new("w7-outbox-empty-key");
            let path = custody_file(&base, FILE_NAME);
            let outbox = OperationOutbox::open(&path, context_of(&payment_world())).unwrap();
            outbox
                .db
                .execute(
                    "UPDATE operation_outbox_context_v1 SET file_id=zeroblob(32)",
                    [],
                )
                .unwrap();
            drop(outbox);
            assert_eq!(
                OperationOutbox::open(&path, context_of(&payment_world())).unwrap_err(),
                Refusal::OutboxIntegrity
            );
        }
        let base = TestDir::new("w7-outbox-tamper");
        let path = custody_file(&base, FILE_NAME);
        let mut world = payment_world();
        world.coin(address(&key_a(), 1), 7_000_000, 1, false, 3, 0);
        let view = world.view();
        let mut outbox = OperationOutbox::open(&path, context_of(&world)).unwrap();
        let first = outbox
            .commit(&signed_payment(&world, 6_000_000), &view)
            .unwrap();
        // The view still counts the first record's coin as free: commit it under the outbox's own
        // reservations instead, as a host must.
        let held = outbox.reserved().unwrap();
        let next = mutiny_wallet_core_v8::ChainView::new(view.head().clone(), &world.state, &held);
        let planned = plan(
            &OperationRequest::Payment(PaymentRequest::new(address(&key_b(), 1), 1_000_000)),
            &next,
            &identity(&key_a()),
        )
        .unwrap();
        let approval = conditional_kit::approve(&review(&planned, &next).unwrap(), &next);
        let other = KeySigner::for_test(key_a())
            .unwrap()
            .authorize(planned, approval, &next)
            .unwrap();
        let second = outbox.commit(&other, &next).unwrap();
        let cell = |outbox: &OperationOutbox, column: &str, id: &Hash| -> Vec<u8> {
            outbox
                .db
                .query_row(
                    &format!("SELECT {column} FROM operation_outbox_records_v1 WHERE id=?1"),
                    [id.as_slice()],
                    |row| row.get(0),
                )
                .unwrap()
        };
        let set = |outbox: &OperationOutbox, column: &str, id: &Hash, value: &[u8]| {
            outbox
                .db
                .execute(
                    &format!("UPDATE operation_outbox_records_v1 SET {column}=?1 WHERE id=?2"),
                    rusqlite::params![value, id.as_slice()],
                )
                .unwrap();
        };
        for column in ["meta", "raw"] {
            let original = cell(&outbox, column, &first);
            for position in [0, original.len() / 2, original.len() - 1] {
                let mut damaged = original.clone();
                damaged[position] ^= 1;
                set(&outbox, column, &first, &damaged);
                assert_eq!(outbox.records().unwrap_err(), Refusal::OutboxIntegrity);
                assert_eq!(outbox.get(&second).unwrap_err(), Refusal::OutboxIntegrity);
            }
            set(&outbox, column, &first, &original);
            // Another record's sealed value under this row: its binding names the other record.
            set(&outbox, column, &first, &cell(&outbox, column, &second));
            assert_eq!(outbox.records().unwrap_err(), Refusal::OutboxIntegrity);
            set(&outbox, column, &first, &original);
        }
        // The other field of the same record: bound to its field.
        let meta = cell(&outbox, "meta", &first);
        let raw = cell(&outbox, "raw", &first);
        set(&outbox, "meta", &first, &raw);
        assert_eq!(outbox.records().unwrap_err(), Refusal::OutboxIntegrity);
        set(&outbox, "meta", &first, &meta);
        assert_eq!(outbox.records().unwrap().len(), 2);
        // An edited identifier column.
        outbox
            .db
            .execute(
                "UPDATE operation_outbox_records_v1 SET id=zeroblob(32) WHERE id=?1",
                [first.as_slice()],
            )
            .unwrap();
        assert_eq!(outbox.records().unwrap_err(), Refusal::OutboxIntegrity);
        outbox
            .db
            .execute(
                "UPDATE operation_outbox_records_v1 SET id=?1 WHERE id=zeroblob(32)",
                [first.as_slice()],
            )
            .unwrap();
        assert_eq!(outbox.records().unwrap().len(), 2);
        // Another key: the file's identifier is part of every binding, so the probe does not open.
        outbox
            .db
            .execute(
                "UPDATE operation_outbox_context_v1 SET file_id=zeroblob(32)",
                [],
            )
            .unwrap();
        drop(outbox);
        assert_eq!(
            OperationOutbox::open(&path, context_of(&world)).unwrap_err(),
            Refusal::OutboxIntegrity
        );
    }

    /// The child of the crash test: sign, write the signed (public payment) bytes beside the
    /// outbox, then end the process at the point the parent names, skipping every destructor.
    #[test]
    fn operation_outbox_crash_child() {
        let Some(dir) = std::env::var_os("BUILD8_W7_OUTBOX_CHILD") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        assert_eq!(dir.parent(), Some(std::env::temp_dir().as_path()));
        assert!(
            dir.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("build8-wallet-core-w7-outbox-crash-")
        );
        let world = payment_world();
        let signed = signed_payment(&world, 1_000_000);
        std::fs::write(dir.join("signed.bin"), signed.bytes()).unwrap();
        let mut outbox = OperationOutbox::open(
            &dir.join("WalletCustodyV2").join(FILE_NAME),
            context_of(&world),
        )
        .unwrap();
        if std::env::var("BUILD8_W7_OUTBOX_MODE").as_deref() == Ok("signed-not-committed") {
            std::process::exit(97);
        }
        // The crash point named by BUILD8_W7_CRASH_POINT ends the process inside `commit`.
        outbox.commit(&signed, &world.view()).unwrap();
        std::process::exit(98);
    }

    /// Kill the process after signing but before the commit, inside the commit's transaction, and
    /// right after the commit: on reopen the outbox holds exactly the signed bytes or nothing.
    #[test]
    fn a_kill_between_sign_and_commit_leaves_exact_bytes_or_nothing() {
        for (mode, point, committed) in [
            ("signed-not-committed", "", false),
            ("crash", "outbox-commit-before-commit", false),
            ("crash", "outbox-commit-after-commit", true),
        ] {
            let base = TestDir::new("w7-outbox-crash");
            let output = run_child(
                "operation_outbox::tests::operation_outbox_crash_child",
                &[
                    ("BUILD8_W7_OUTBOX_CHILD", base.path().as_os_str()),
                    ("BUILD8_W7_OUTBOX_MODE", std::ffi::OsStr::new(mode)),
                    ("BUILD8_W7_CRASH_POINT", std::ffi::OsStr::new(point)),
                ],
            );
            assert_eq!(
                output.status.code(),
                Some(97),
                "child ({mode} {point}) failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let signed = std::fs::read(base.file("signed.bin")).unwrap();
            let world = payment_world();
            let outbox =
                OperationOutbox::open(&custody_file(&base, FILE_NAME), context_of(&world)).unwrap();
            let records = outbox.records().unwrap();
            if committed {
                assert_eq!(records.len(), 1, "{point}");
                assert_eq!(records[0].bytes, signed, "{point}: not the exact bytes");
                assert_eq!(records[0].status, OutboxStatus::Queued);
                assert!(!outbox.reserved().unwrap().is_empty());
            } else {
                assert!(records.is_empty(), "{mode} {point}: a record survived");
                assert!(outbox.reserved().unwrap().is_empty());
            }
        }
    }
}
