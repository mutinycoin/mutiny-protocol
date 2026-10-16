//! Current V3 verifier issuance and single-consume Treasury admission.
//! Public TEST-VALUE state only. Open requires an independently trusted exact
//! store identity before writable configuration. Challenge nonces originate only
//! inside issue() from the OS CSPRNG and are registered before signing.
//! Production remains refused: a database, its copied ID/hash/key cannot prove
//! rollback resistance. Deployment needs separately protected state or an
//! externally rooted fail-closed recovery rule; neither exists in this module.
//! SQLite EXTRA/DELETE durability is checked but Windows directory-sync/power-loss
//! behavior is not physical qualification. Preserve the rollback journal sidecar.
use crate::{
    Hash,
    treasury_rehearsal_v3::{
        self as rehearsal, CeremonyConfig, Denylist, Expect, Outcome, Refusal, VerifiedProof,
    },
};
use mutiny_crypto_v2::{
    HybridSignature, PublicKey,
    treasury_proof_v1::{self as proof, Challenge},
};
use rusqlite::{Connection, MAIN_DB, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::path::Path;
use std::sync::OnceLock;

pub const STORE_SCHEMA: &str = "MUTINY-D2-TREASURY-ADMISSION-STORE-V3";
const WRITE_PRAGMAS: &str =
    "PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA;";
const READ_PRAGMAS: &str = "PRAGMA trusted_schema=OFF; PRAGMA query_only=ON;";
/// `PRAGMA synchronous` value of EXTRA.
const SYNCHRONOUS_EXTRA: i64 = 3;
const BINDING_SQL: &str = "CREATE TABLE store_binding(id INTEGER PRIMARY KEY CHECK(id=1), schema TEXT NOT NULL, \
    context BLOB NOT NULL CHECK(typeof(context)='blob' AND length(context)=32), \
    record_sha256 BLOB NOT NULL CHECK(typeof(record_sha256)='blob' AND length(record_sha256)=32), \
    store_id BLOB NOT NULL CHECK(typeof(store_id)='blob' AND length(store_id)=32))";
const ADMISSIONS_SQL: &str = "CREATE TABLE admissions(nonce BLOB PRIMARY KEY CHECK(typeof(nonce)='blob' AND length(nonce)=32), \
    challenge BLOB NOT NULL CHECK(typeof(challenge)='blob'), descriptor BLOB NOT NULL CHECK(typeof(descriptor)='blob'), \
    signature BLOB NOT NULL CHECK(typeof(signature)='blob' AND length(signature)=1394)) WITHOUT ROWID";
const ISSUED_SQL: &str = "CREATE TABLE issued(nonce BLOB PRIMARY KEY CHECK(typeof(nonce)='blob' AND length(nonce)=32), challenge BLOB NOT NULL CHECK(typeof(challenge)='blob'), descriptor BLOB NOT NULL CHECK(typeof(descriptor)='blob'), consumed INTEGER NOT NULL CHECK(typeof(consumed)='integer' AND consumed IN(0,1))) WITHOUT ROWID";
/// Public identity supplied by trusted verifier configuration, never learned
/// from the proof or substituted database during open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoreIdentity(Hash);
impl StoreIdentity {
    pub fn from_trusted_id(id: Hash) -> Outcome<Self> {
        if id == [0; 32] {
            return Err(Refusal::WrongStore);
        }
        Ok(Self(id))
    }
    pub fn store_id(self) -> Hash {
        self.0
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Issuance {
    pub challenge: Vec<u8>,
    pub descriptor: Vec<u8>,
    pub consumed: bool,
}
/// One stored admission row: (nonce, challenge, descriptor, signature).
type StoredRow = (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
/// The binding row: (schema label, context, record SHA-256, store id).
type BindingRow = (String, Vec<u8>, Vec<u8>, Vec<u8>);
/// One schema object: (type, name, sql).
type SchemaObject = (String, String, String);

/// One recorded first admission (public data).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission {
    pub nonce: Hash,
    pub challenge: Vec<u8>,
    pub descriptor: Vec<u8>,
    pub signature: Vec<u8>,
}

/// The connection settings as SQLite reports them (read back, never assumed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Durability {
    /// `PRAGMA synchronous` (3 = EXTRA on every writable connection).
    pub synchronous: i64,
    /// `PRAGMA journal_mode` (`delete` for a writable file store, `memory` for a scratch store).
    pub journal_mode: String,
    /// `PRAGMA query_only`.
    pub query_only: bool,
    /// SQLite reports the main database of the connection as read-only (`sqlite3_db_readonly`).
    pub read_only: bool,
}

pub struct AdmissionStore {
    db: Connection,
    context: Hash,
    record_sha256: Hash,
    store_id: Hash,
    writable: bool,
}

fn require_test_value(config: &CeremonyConfig) -> Outcome<()> {
    if config.phase() != proof::Phase::Rehearsal
        || config.class() != crate::treasury_v1::Class::TestValue
    {
        return Err(Refusal::ProductionRefused);
    }
    Ok(())
}
fn storage<T>(result: rusqlite::Result<T>) -> Outcome<T> {
    result.map_err(|_| Refusal::Store)
}
/// The binding of a ceremony: (expected context, SHA-256 of the trusted Treasury record).
fn binding(config: &CeremonyConfig) -> Outcome<(Hash, Hash)> {
    Ok((
        config.context().value(),
        rehearsal::record_sha256(config.treasury())?,
    ))
}
fn objects(db: &Connection) -> Outcome<Vec<SchemaObject>> {
    let mut statement =
        storage(db.prepare("SELECT type, name, sql FROM sqlite_schema ORDER BY name"))?;
    storage(storage(statement.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))))?.collect())
}
/// The exact schema objects a store must hold, as THIS SQLite records them for the store's own
/// statements (read from a scratch database created with them).
fn expected_objects() -> Outcome<&'static Vec<SchemaObject>> {
    static EXPECTED: OnceLock<Vec<SchemaObject>> = OnceLock::new();
    if let Some(v) = EXPECTED.get() {
        return Ok(v);
    }
    let db = storage(Connection::open_in_memory())?;
    storage(db.execute_batch(&format!("{BINDING_SQL};\n{ISSUED_SQL};\n{ADMISSIONS_SQL};")))?;
    let found = objects(&db)?;
    Ok(EXPECTED.get_or_init(|| found))
}
fn read_durability(db: &Connection) -> Outcome<Durability> {
    Ok(Durability {
        synchronous: storage(db.pragma_query_value(None, "synchronous", |r| r.get(0)))?,
        journal_mode: storage(db.pragma_query_value(None, "journal_mode", |r| r.get(0)))?,
        query_only: storage(db.pragma_query_value(None, "query_only", |r| r.get::<_, i64>(0)))?
            != 0,
        read_only: storage(db.is_readonly(MAIN_DB))?,
    })
}
/// Apply and READ BACK the connection settings: writable connections must run `synchronous=EXTRA` with
/// the rollback journal (`delete`; `memory` only for a scratch in-memory store), read-only ones
/// `query_only` on a connection SQLite reports read-only. Anything else is refused (`Store`).
fn configure(db: &Connection, writable: bool, in_memory: bool) -> Outcome<()> {
    storage(db.busy_timeout(std::time::Duration::from_secs(5)))?;
    storage(db.execute_batch(if writable {
        WRITE_PRAGMAS
    } else {
        READ_PRAGMAS
    }))?;
    let trusted_schema: i64 = storage(db.pragma_query_value(None, "trusted_schema", |r| r.get(0)))?;
    let d = read_durability(db)?;
    let applied = if writable {
        d.synchronous == SYNCHRONOUS_EXTRA
            && d.journal_mode == if in_memory { "memory" } else { "delete" }
            && !d.query_only
            && !d.read_only
    } else {
        d.query_only && d.read_only
    };
    if trusted_schema != 0 || !applied {
        return Err(Refusal::Store);
    }
    Ok(())
}
/// The file holds exactly this store's schema objects (names and SQL) and one binding row with the
/// current schema label and the trusted binding. Returns the store id.
fn validate(db: &Connection, context: Hash, record: Hash) -> Outcome<Hash> {
    if &objects(db)? != expected_objects()? {
        return Err(Refusal::StoreBinding);
    }
    let rows: i64 = storage(db.query_row("SELECT count(*) FROM store_binding", [], |r| r.get(0)))?;
    let row: Option<BindingRow> = storage(
        db.query_row(
            "SELECT schema, context, record_sha256, store_id FROM store_binding WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional(),
    )?;
    match row {
        Some((schema, c, r, id))
            if rows == 1 && schema == STORE_SCHEMA && c == context && r == record =>
        {
            id.try_into().map_err(|_| Refusal::StoreBinding)
        }
        _ => Err(Refusal::StoreBinding),
    }
}

fn validate_trusted_binding(
    db: &Connection,
    context: Hash,
    record: Hash,
    expected_id: Hash,
) -> Outcome<()> {
    if validate(db, context, record)? != expected_id {
        return Err(Refusal::WrongStore);
    }
    Ok(())
}

impl AdmissionStore {
    /// Create a NEW store file at `path` bound to the trusted configuration, with a fresh random store
    /// id. An existing file is never reused or overwritten (atomic `create_new`).
    pub fn create(path: &Path, config: &CeremonyConfig) -> Outcome<StoreIdentity> {
        require_test_value(config)?;
        let (context, record) = binding(config)?;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(|_| Refusal::Store)?;
        let db = storage(Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ))?;
        Self::initialize(db, context, record, false).map(|store| StoreIdentity(store.store_id))
    }
    fn initialize(
        mut db: Connection,
        context: Hash,
        record: Hash,
        in_memory: bool,
    ) -> Outcome<Self> {
        configure(&db, true, in_memory)?;
        let mut store_id = [0u8; 32];
        while store_id == [0; 32] {
            mutiny_crypto_v2::fill_os_random(&mut store_id).map_err(|_| Refusal::Store)?;
        }
        let tx = storage(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let count: i64 =
            storage(tx.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0)))?;
        if count != 0 {
            return Err(Refusal::StoreBinding);
        }
        storage(tx.execute_batch(&format!("{BINDING_SQL};\n{ISSUED_SQL};\n{ADMISSIONS_SQL};")))?;
        storage(tx.execute(
            "INSERT INTO store_binding VALUES(1,?1,?2,?3,?4)",
            params![
                STORE_SCHEMA,
                context.as_slice(),
                record.as_slice(),
                store_id.as_slice()
            ],
        ))?;
        storage(tx.commit())?;
        let found = validate(&db, context, record)?;
        if found != store_id {
            return Err(Refusal::StoreBinding);
        }
        Ok(Self {
            db,
            context,
            record_sha256: record,
            store_id,
            writable: true,
        })
    }
    /// Open an EXISTING store for admission (read-write; a missing file is an error, never created).
    pub fn open(path: &Path, config: &CeremonyConfig, expected: StoreIdentity) -> Outcome<Self> {
        Self::open_with(path, config, expected, true)
    }
    /// Open an EXISTING store for audit only (`SQLITE_OPEN_READ_ONLY`, `query_only`, read back):
    /// nothing can be written through it.
    pub fn open_read_only(
        path: &Path,
        config: &CeremonyConfig,
        expected: StoreIdentity,
    ) -> Outcome<Self> {
        Self::open_with(path, config, expected, false)
    }
    fn open_with(
        path: &Path,
        config: &CeremonyConfig,
        expected: StoreIdentity,
        writable: bool,
    ) -> Outcome<Self> {
        require_test_value(config)?;
        let (context, record) = binding(config)?;
        // Examine the file currently named by path through a read-only connection.
        // If this observed file needs write recovery, preflight refuses it.
        // Reopening below is NOT an OS-handle/path-substitution barrier: an actor
        // able to replace the path can present another file whose hot journal
        // SQLite recovers before our second validation refuses its identity.
        // TEST-VALUE use therefore requires controlled storage/ancestors; this
        // API cannot promise unchanged substituted bytes against that local actor.
        let preflight = storage(Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ))?;
        let found = validate(&preflight, context, record)?;
        if found != expected.0 {
            return Err(Refusal::WrongStore);
        }
        drop(preflight);
        let flags = if writable {
            OpenFlags::SQLITE_OPEN_READ_WRITE
        } else {
            OpenFlags::SQLITE_OPEN_READ_ONLY
        };
        let db = storage(Connection::open_with_flags(
            path,
            flags | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ))?;
        let store_id = validate(&db, context, record)?;
        if store_id != expected.0 {
            return Err(Refusal::WrongStore);
        }
        // The identity is established BEFORE any potentially writable pragma.
        configure(&db, writable, false)?;
        Ok(Self {
            db,
            context,
            record_sha256: record,
            store_id,
            writable,
        })
    }
    /// The expectation's configuration must be the configuration this store was created for.
    pub fn check_binding(&self, config: &CeremonyConfig) -> Outcome<()> {
        require_test_value(config)?;
        let (context, record) = binding(config)?;
        if context != self.context || record != self.record_sha256 {
            return Err(Refusal::StoreBinding);
        }
        if validate(&self.db, context, record)? != self.store_id {
            return Err(Refusal::WrongStore);
        }
        Ok(())
    }
    pub fn is_read_only(&self) -> bool {
        !self.writable
    }
    /// The random id drawn when this store was created.
    pub fn store_id(&self) -> Hash {
        self.store_id
    }
    /// The connection settings as SQLite reports them now.
    pub fn durability(&self) -> Outcome<Durability> {
        read_durability(&self.db)
    }

    /// Register an existing-format challenge with an OS-generated nonce before
    /// signing. No caller-selected nonce is accepted by this API.
    pub fn issue(
        &mut self,
        expect: &Expect,
        descriptor: &[u8],
        denylist: &Denylist,
    ) -> Outcome<Challenge> {
        self.issue_with_reservation(expect, descriptor, denylist, |_, _| Ok(()))
    }
    /// Internal successor integration point: the external durable reservation is
    /// made after native checks/RNG and before the SQLite issuance mutation. The
    /// owner must freeze on uncertain reservation/local commit; this hook alone
    /// is not a protected service and cannot enable Production.
    pub(crate) fn issue_with_reservation(
        &mut self,
        expect: &Expect,
        descriptor: &[u8],
        denylist: &Denylist,
        mut reserve: impl FnMut(&Challenge, &[u8]) -> Outcome<()>,
    ) -> Outcome<Challenge> {
        self.check_binding(expect.config())?;
        if !self.writable {
            return Err(Refusal::Store);
        }
        rehearsal::check_issuance_descriptor(expect, descriptor)?;
        let (public, _) = PublicKey::decode_descriptor(descriptor)
            .map_err(|_| Refusal::Proof(proof::ProofError::DescriptorInvalid))?;
        if denylist.contains(&public) {
            return Err(Refusal::Denylisted);
        }
        #[cfg(test)]
        tests::before_write_transaction();
        let tx = storage(
            self.db
                .transaction_with_behavior(TransactionBehavior::Immediate),
        )?;
        validate_trusted_binding(&tx, self.context, self.record_sha256, self.store_id)?;
        let mut nonce = [0; 32];
        while nonce == [0; 32] {
            mutiny_crypto_v2::fill_os_random(&mut nonce).map_err(|_| Refusal::Store)?;
        }
        let challenge = rehearsal::build_challenge(expect.config(), descriptor, nonce)?;
        let bytes = challenge.encode()?;
        reserve(&challenge, descriptor)?;
        storage(tx.execute(
            "INSERT INTO issued VALUES(?1,?2,?3,0)",
            params![nonce.as_slice(), bytes, descriptor],
        ))?;
        storage(tx.commit())?;
        Ok(challenge)
    }
    /// Read and strictly validate registered issuance; this never consumes it.
    pub fn issued(&self, nonce: &Hash) -> Outcome<Option<Issuance>> {
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = storage(
            self.db
                .query_row(
                    "SELECT challenge, descriptor, consumed FROM issued WHERE nonce=?1",
                    [nonce.as_slice()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional(),
        )?;
        row.map(|(challenge, descriptor, consumed)| {
            let c = Challenge::decode(&challenge).map_err(|_| Refusal::Store)?;
            if c.nonce != *nonce
                || c.ceremony_context != self.context
                || c.treasury_record_sha256 != self.record_sha256
                || c.phase != proof::Phase::Rehearsal
                || ![0, 1].contains(&consumed)
                || c.check_descriptor(&descriptor).is_err()
            {
                return Err(Refusal::Store);
            }
            let recorded: Option<(Vec<u8>, Vec<u8>)> = storage(
                self.db
                    .query_row(
                        "SELECT challenge,descriptor FROM admissions WHERE nonce=?1",
                        [nonce.as_slice()],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional(),
            )?;
            match (consumed, recorded) {
                (0, None) => {}
                (1, Some((ref a, ref d))) if a == &challenge && d == &descriptor => {}
                _ => return Err(Refusal::Store),
            }
            Ok(Issuance {
                challenge,
                descriptor,
                consumed: consumed == 1,
            })
        })
        .transpose()
    }
    /// Current read-only verification requires exact registered bytes. After
    /// consumption it accepts only the identical recorded signature as an audit.
    pub fn verify_issued(
        &self,
        expect: &Expect,
        descriptor: &[u8],
        challenge_bytes: &[u8],
        signature: &HybridSignature,
        denylist: &Denylist,
    ) -> Outcome<VerifiedProof> {
        self.check_binding(expect.config())?;
        let verified = rehearsal::verify_crypto_bound(
            expect,
            descriptor,
            challenge_bytes,
            signature,
            denylist,
        )?;
        let issued = self
            .issued(&verified.nonce)?
            .ok_or(Refusal::UnknownChallenge)?;
        if issued.challenge != challenge_bytes || issued.descriptor != descriptor {
            return Err(Refusal::IssuanceMismatch);
        }
        if issued.consumed {
            let row = self.recorded(&verified.nonce)?.ok_or(Refusal::Store)?;
            if row.signature != proof::signature_to_bytes(signature) {
                return Err(Refusal::NotAdmitted);
            }
        }
        Ok(verified)
    }
    /// Validate both signatures, require registered exact bytes and atomically
    /// consume issuance with insertion of the admission. Nothing commits on refusal.
    pub fn admit(
        &mut self,
        expect: &Expect,
        descriptor: &[u8],
        challenge_bytes: &[u8],
        signature: &HybridSignature,
        denylist: &Denylist,
    ) -> Outcome<VerifiedProof> {
        self.admit_with_consumption(
            expect,
            descriptor,
            challenge_bytes,
            signature,
            denylist,
            |_| Ok(()),
        )
    }
    /// Internal ordering point for the adopted continuity owner. Full native proof,
    /// binding and exact unconsumed issuance checks precede irreversible external
    /// consumption; local transaction commits before success. An external terminal
    /// result must never be undone on local failure. Production remains refused.
    pub(crate) fn admit_with_consumption(
        &mut self,
        expect: &Expect,
        descriptor: &[u8],
        challenge_bytes: &[u8],
        signature: &HybridSignature,
        denylist: &Denylist,
        mut consume: impl FnMut(&VerifiedProof) -> Outcome<()>,
    ) -> Outcome<VerifiedProof> {
        self.check_binding(expect.config())?;
        if !self.writable {
            return Err(Refusal::Store);
        }
        let verified = rehearsal::verify_crypto_bound(
            expect,
            descriptor,
            challenge_bytes,
            signature,
            denylist,
        )?;
        #[cfg(test)]
        tests::before_write_transaction();
        let tx = storage(
            self.db
                .transaction_with_behavior(TransactionBehavior::Immediate),
        )?;
        validate_trusted_binding(&tx, self.context, self.record_sha256, self.store_id)?;
        let row: Option<(Vec<u8>, Vec<u8>, i64)> = storage(
            tx.query_row(
                "SELECT challenge,descriptor,consumed FROM issued WHERE nonce=?1",
                [verified.nonce.as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional(),
        )?;
        let (issued_challenge, issued_descriptor, consumed) =
            row.ok_or(Refusal::UnknownChallenge)?;
        if issued_challenge != challenge_bytes || issued_descriptor != descriptor {
            return Err(Refusal::IssuanceMismatch);
        }
        if consumed == 1 {
            let recorded: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = storage(
                tx.query_row(
                    "SELECT challenge,descriptor,signature FROM admissions WHERE nonce=?1",
                    [verified.nonce.as_slice()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional(),
            )?;
            let (c, d, s) = recorded.ok_or(Refusal::Store)?;
            checked(verified.nonce, c.clone(), d.clone(), s)?;
            if c != challenge_bytes || d != descriptor {
                return Err(Refusal::Store);
            }
            return Err(Refusal::Replay);
        }
        if consumed != 0 {
            return Err(Refusal::Store);
        }
        consume(&verified)?;
        if storage(tx.execute(
            "UPDATE issued SET consumed=1 WHERE nonce=?1 AND consumed=0",
            [verified.nonce.as_slice()],
        ))? != 1
        {
            return Err(Refusal::Store);
        }
        #[cfg(test)]
        if tests::FAIL_AFTER_CONSUME.get() {
            return Err(Refusal::Store);
        }
        if storage(tx.execute(
            "INSERT INTO admissions VALUES(?1,?2,?3,?4)",
            params![
                verified.nonce.as_slice(),
                challenge_bytes,
                descriptor,
                proof::signature_to_bytes(signature).as_slice()
            ],
        ))? != 1
        {
            return Err(Refusal::Store);
        }
        #[cfg(test)]
        if tests::FAIL_BEFORE_COMMIT.get() {
            return Err(Refusal::Store);
        }
        storage(tx.commit())?;
        Ok(verified)
    }

    /// Structural checks of recorded bytes/issuance association only. This does
    /// not authenticate signatures; use verify_issued/audit_recorded for that.
    pub fn recorded(&self, nonce: &Hash) -> Outcome<Option<Admission>> {
        let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = storage(
            self.db
                .query_row(
                    "SELECT challenge, descriptor, signature FROM admissions WHERE nonce=?1",
                    [nonce.as_slice()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional(),
        )?;
        row.map(|(challenge, descriptor, signature)| {
            let row = checked(*nonce, challenge, descriptor, signature)?;
            let issuance = self.issued(nonce)?.ok_or(Refusal::Store)?;
            if !issuance.consumed
                || issuance.challenge != row.challenge
                || issuance.descriptor != row.descriptor
            {
                return Err(Refusal::Store);
            }
            Ok(row)
        })
        .transpose()
    }
    /// Recorded rows ordered by nonce, with structural byte/issuance checks.
    /// Cryptographic authenticated audit requires verify_issued/audit_recorded.
    pub fn admissions(&self) -> Outcome<Vec<Admission>> {
        let mut statement = storage(self.db.prepare(
            "SELECT nonce, challenge, descriptor, signature FROM admissions ORDER BY nonce",
        ))?;
        let rows: Vec<StoredRow> = storage(
            storage(statement.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))))?
                .collect(),
        )?;
        rows.into_iter()
            .map(|(nonce, challenge, descriptor, signature)| {
                let nonce: Hash = nonce.try_into().map_err(|_| Refusal::Store)?;
                let row = checked(nonce, challenge, descriptor, signature)?;
                let issued = self.issued(&nonce)?.ok_or(Refusal::Store)?;
                if !issued.consumed
                    || issued.challenge != row.challenge
                    || issued.descriptor != row.descriptor
                {
                    return Err(Refusal::Store);
                }
                Ok(row)
            })
            .collect()
    }

    /// Complete bounded local public rows for the continuity owner. This is a
    /// database observation, never authenticated current service authority.
    pub(crate) fn continuity_records(
        &self,
    ) -> Outcome<Vec<crate::treasury_continuity_v1::PublicRecord>> {
        // All reads below share one SQLite snapshot, including association reads.
        let _snapshot = storage(self.db.unchecked_transaction())?;
        validate_trusted_binding(&self.db, self.context, self.record_sha256, self.store_id)?;
        let count: i64 = storage(
            self.db
                .query_row("SELECT count(*) FROM issued", [], |r| r.get(0)),
        )?;
        if !(0..=2048).contains(&count) {
            return Err(Refusal::Store);
        }
        let oversized: i64 = storage(self.db.query_row(
            "SELECT count(*) FROM issued WHERE typeof(nonce)!='blob' OR length(nonce)!=32 OR typeof(challenge)!='blob' OR length(challenge)>512 OR typeof(descriptor)!='blob' OR length(descriptor)>2048",
            [],
            |r| r.get(0),
        ))?;
        if oversized != 0 {
            return Err(Refusal::Store);
        }
        let admitted: i64 = storage(self.db.query_row(
            "SELECT count(*) FROM admissions",
            [],
            |r| r.get(0),
        ))?;
        let consumed: i64 = storage(self.db.query_row(
            "SELECT count(*) FROM issued WHERE consumed=1",
            [],
            |r| r.get(0),
        ))?;
        if admitted != consumed {
            return Err(Refusal::Store);
        }
        let malformed_admitted: i64 = storage(self.db.query_row(
            "SELECT count(*) FROM admissions WHERE typeof(nonce)!='blob' OR length(nonce)!=32 OR typeof(challenge)!='blob' OR length(challenge)>512 OR typeof(descriptor)!='blob' OR length(descriptor)>2048 OR typeof(signature)!='blob' OR length(signature)!=1394",
            [], |r| r.get(0)))?;
        if malformed_admitted != 0 {
            return Err(Refusal::Store);
        }
        let mut stmt = storage(self.db.prepare("SELECT nonce FROM issued ORDER BY nonce"))?;
        let nonces: Vec<Vec<u8>> = storage(storage(stmt.query_map([], |r| r.get(0)))?.collect())?;
        nonces
            .into_iter()
            .map(|nonce| {
                let nonce: Hash = nonce.try_into().map_err(|_| Refusal::Store)?;
                let issued = self.issued(&nonce)?.ok_or(Refusal::Store)?;
                let challenge = Challenge::decode(&issued.challenge)?;
                let signature = if issued.consumed {
                    Some(self.recorded(&nonce)?.ok_or(Refusal::Store)?.signature)
                } else {
                    None
                };
                Ok(crate::treasury_continuity_v1::PublicRecord {
                    generation: challenge.generation,
                    nonce,
                    challenge: issued.challenge,
                    descriptor: issued.descriptor,
                    signature,
                })
            })
            .collect()
    }

    /// Only the adopted continuity owner may call this after authenticating the
    /// exact current external history. Historical expectations must be supplied
    /// from independently trusted lineage, never constructed from stored bytes.
    /// All native proof checks and divergence checks precede one atomic repair.
    /// External consumption is never erased. Production remains refused.
    pub(crate) fn reconcile_continuity_records(
        &mut self,
        config: &CeremonyConfig,
        records: &[(Expect, crate::treasury_continuity_v1::PublicRecord)],
        denylist: &Denylist,
    ) -> Outcome<()> {
        self.check_binding(config)?;
        if !self.writable || records.len() > 2048 {
            return Err(Refusal::Store);
        }
        let mut expected = std::collections::BTreeMap::new();
        for (expect, record) in records {
            if binding(expect.config())? != binding(config)?
                || record.challenge.len() > 512
                || record.descriptor.len() > 2048
                || record.generation != expect.generation()
                || record.nonce == [0; 32]
            {
                return Err(Refusal::StoreBinding);
            }
            let challenge = Challenge::decode(&record.challenge)?;
            if challenge.nonce != record.nonce || challenge.generation != record.generation {
                return Err(Refusal::IssuanceMismatch);
            }
            if let Some(signature) = &record.signature {
                let signature = proof::signature_from_bytes(signature)?;
                rehearsal::verify_crypto_bound(
                    expect,
                    &record.descriptor,
                    &record.challenge,
                    &signature,
                    denylist,
                )?;
            } else {
                rehearsal::check_issuance_descriptor(expect, &record.descriptor)?;
                let (public, _) =
                    PublicKey::decode_descriptor(&record.descriptor).map_err(|_| Refusal::Store)?;
                if denylist.contains(&public) {
                    return Err(Refusal::Denylisted);
                }
                if rehearsal::build_challenge(expect.config(), &record.descriptor, record.nonce)?
                    .encode()?
                    != record.challenge
                {
                    return Err(Refusal::IssuanceMismatch);
                }
            }
            if expected.insert(record.nonce, record).is_some() {
                return Err(Refusal::Store);
            }
        }
        let tx = storage(
            self.db
                .transaction_with_behavior(TransactionBehavior::Immediate),
        )?;
        validate_trusted_binding(&tx, self.context, self.record_sha256, self.store_id)?;
        let count: i64 = storage(tx.query_row("SELECT count(*) FROM issued", [], |r| r.get(0)))?;
        if count < 0 || count as usize > expected.len() {
            return Err(Refusal::Store);
        }
        let oversized: i64 = storage(tx.query_row(
            "SELECT count(*) FROM issued WHERE typeof(nonce)!='blob' OR length(nonce)!=32 OR typeof(challenge)!='blob' OR length(challenge)>512 OR typeof(descriptor)!='blob' OR length(descriptor)>2048",
            [],
            |r| r.get(0),
        ))?;
        if oversized != 0 {
            return Err(Refusal::Store);
        }
        let malformed: i64 = storage(tx.query_row(
            "SELECT count(*) FROM admissions WHERE typeof(nonce)!='blob' OR length(nonce)!=32 OR typeof(challenge)!='blob' OR length(challenge)>512 OR typeof(descriptor)!='blob' OR length(descriptor)>2048 OR typeof(signature)!='blob' OR length(signature)!=1394",
            [], |r| r.get(0)))?;
        if malformed != 0 {
            return Err(Refusal::Store);
        }
        let existing: Vec<(Vec<u8>, Vec<u8>, Vec<u8>, i64)> = {
            let mut stmt = storage(
                tx.prepare("SELECT nonce,challenge,descriptor,consumed FROM issued ORDER BY nonce"),
            )?;
            storage(
                storage(stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))))?
                    .collect(),
            )?
        };
        let mut existing_nonces = std::collections::BTreeSet::new();
        for (nonce, challenge, descriptor, consumed) in &existing {
            let nonce: Hash = nonce.as_slice().try_into().map_err(|_| Refusal::Store)?;
            let exact = expected.get(&nonce).ok_or(Refusal::IssuanceMismatch)?;
            if challenge != &exact.challenge
                || descriptor != &exact.descriptor
                || ![0, 1].contains(consumed)
            {
                return Err(Refusal::IssuanceMismatch);
            }
            let admitted: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = storage(
                tx.query_row(
                    "SELECT challenge,descriptor,signature FROM admissions WHERE nonce=?1",
                    [nonce.as_slice()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional(),
            )?;
            match (*consumed, admitted) {
                (0, None) => {}
                (1, Some((c, d, s)))
                    if c == exact.challenge
                        && d == exact.descriptor
                        && exact.signature.as_ref() == Some(&s) => {}
                _ => return Err(Refusal::Store),
            }
            existing_nonces.insert(nonce);
        }
        let admissions_count: i64 =
            storage(tx.query_row("SELECT count(*) FROM admissions", [], |r| r.get(0)))?;
        if admissions_count != existing.iter().filter(|row| row.3 == 1).count() as i64 {
            return Err(Refusal::Store);
        }
        for (nonce, record) in expected {
            if !existing_nonces.contains(&nonce) {
                storage(tx.execute(
                    "INSERT INTO issued VALUES(?1,?2,?3,0)",
                    params![nonce.as_slice(), record.challenge, record.descriptor],
                ))?;
            }
            if let Some(signature) = &record.signature {
                let consumed: i64 = storage(tx.query_row(
                    "SELECT consumed FROM issued WHERE nonce=?1",
                    [nonce.as_slice()],
                    |r| r.get(0),
                ))?;
                if consumed == 0 {
                    storage(tx.execute(
                        "UPDATE issued SET consumed=1 WHERE nonce=?1 AND consumed=0",
                        [nonce.as_slice()],
                    ))?;
                    storage(tx.execute(
                        "INSERT INTO admissions VALUES(?1,?2,?3,?4)",
                        params![
                            nonce.as_slice(),
                            record.challenge,
                            record.descriptor,
                            signature
                        ],
                    ))?;
                }
            }
        }
        storage(tx.commit())?;
        Ok(())
    }
}

/// A recorded row must still be a strict challenge carrying the row's nonce and a two-component
/// signature; anything else is a damaged store (refused, never repaired).
fn checked(
    nonce: Hash,
    challenge: Vec<u8>,
    descriptor: Vec<u8>,
    signature: Vec<u8>,
) -> Outcome<Admission> {
    let decoded = Challenge::decode(&challenge).map_err(|_| Refusal::Store)?;
    if decoded.nonce != nonce || proof::signature_from_bytes(&signature).is_err() {
        return Err(Refusal::Store);
    }
    Ok(Admission {
        nonce,
        challenge,
        descriptor,
        signature,
    })
}

#[cfg(test)]
#[path = "../tests/support/test_dir.rs"]
mod test_dir;
#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    thread_local! {
        pub(super) static BEFORE_WRITE_TX: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
        pub(super) static FAIL_AFTER_CONSUME: Cell<bool> = const { Cell::new(false) };
        pub(super) static FAIL_BEFORE_COMMIT: Cell<bool> = const { Cell::new(false) };
    }
    pub(super) fn before_write_transaction() {
        if let Some(callback) = BEFORE_WRITE_TX.with(|slot| slot.borrow_mut().take()) {
            callback();
        }
    }
    #[test]
    fn failed_consume_or_insert_commit_rolls_back_both_and_retry_admits_once() {
        use crate::treasury_v1::{Class, Treasury};
        use mutiny_crypto_v2::{NETWORK, rehearsal_keys_v1::Credential};
        let key = Credential::from_label("PUBLIC-v3-atomic-key", 1).unwrap();
        let descriptor = key.descriptor().unwrap();
        let config = CeremonyConfig::rehearsal(
            NETWORK,
            Treasury::new(Class::TestValue, descriptor.clone()).unwrap(),
            "PUBLIC-v3-atomic-context",
        )
        .unwrap();
        let expect = Expect::genesis_key(&config);
        let deny = Denylist::default();
        let dir = super::test_dir::TestDir::new("treasury-v3-atomic");
        let path = dir.file("store.sqlite");
        let id = AdmissionStore::create(&path, &config).unwrap();
        let mut store = AdmissionStore::open(&path, &config, id).unwrap();
        let challenge = store.issue(&expect, &descriptor, &deny).unwrap();
        let bytes = challenge.encode().unwrap();
        let signature = proof::sign_challenge(key.key(), &descriptor, &challenge).unwrap();
        drop(store);
        let before = std::fs::read(&path).unwrap();
        for after_consume in [true, false] {
            let mut store = AdmissionStore::open(&path, &config, id).unwrap();
            FAIL_AFTER_CONSUME.set(after_consume);
            FAIL_BEFORE_COMMIT.set(!after_consume);
            let result = store.admit(&expect, &descriptor, &bytes, &signature, &deny);
            FAIL_AFTER_CONSUME.set(false);
            FAIL_BEFORE_COMMIT.set(false);
            assert_eq!(result, Err(Refusal::Store));
            assert!(!store.issued(&challenge.nonce).unwrap().unwrap().consumed);
            assert_eq!(store.recorded(&challenge.nonce).unwrap(), None);
            drop(store);
            assert_eq!(
                std::fs::read(&path).unwrap(),
                before,
                "failure preserves exact pre-admission database bytes"
            );
        }
        let mut store = AdmissionStore::open(&path, &config, id).unwrap();
        store
            .admit(&expect, &descriptor, &bytes, &signature, &deny)
            .unwrap();
        assert!(store.issued(&challenge.nonce).unwrap().unwrap().consumed);
        assert_eq!(
            store.admit(&expect, &descriptor, &bytes, &signature, &deny),
            Err(Refusal::Replay)
        );
    }
    #[test]
    fn concurrent_binding_changes_are_refused_inside_issue_and_admit_transactions() {
        use crate::treasury_v1::{Class, Treasury};
        use mutiny_crypto_v2::{NETWORK, rehearsal_keys_v1::Credential};
        let key = Credential::from_label("PUBLIC-v3-binding-race", 1).unwrap();
        let descriptor = key.descriptor().unwrap();
        let config = CeremonyConfig::rehearsal(
            NETWORK,
            Treasury::new(Class::TestValue, descriptor.clone()).unwrap(),
            "PUBLIC-v3-binding-race-context",
        )
        .unwrap();
        let expect = Expect::genesis_key(&config);
        let deny = Denylist::default();
        for admitting in [false, true] {
            for (field, refusal) in [
                ("context", Refusal::StoreBinding),
                ("record_sha256", Refusal::StoreBinding),
                ("store_id", Refusal::WrongStore),
                ("schema", Refusal::StoreBinding),
            ] {
                let dir = super::test_dir::TestDir::new("treasury-v3-binding-race");
                let path = dir.file("store.sqlite");
                let id = AdmissionStore::create(&path, &config).unwrap();
                let mut store = AdmissionStore::open(&path, &config, id).unwrap();
                let proof = if admitting {
                    let c = store.issue(&expect, &descriptor, &deny).unwrap();
                    let b = c.encode().unwrap();
                    let signature = proof::sign_challenge(key.key(), &descriptor, &c).unwrap();
                    Some((b, signature))
                } else {
                    None
                };
                let snapshot = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
                let captured = snapshot.clone();
                let raced_path = path.clone();
                // The second connection commits a substitution exactly in the gap
                // after expectation/signature validation, before BEGIN IMMEDIATE.
                // No sleeps or probabilistic scheduling can make this test vacuous.
                BEFORE_WRITE_TX.with(|slot| {
                    *slot.borrow_mut() = Some(Box::new(move || {
                        let db = Connection::open(&raced_path).unwrap();
                        if field == "schema" {
                            db.execute("UPDATE store_binding SET schema='FOREIGN-TEST-SCHEMA'", [])
                                .unwrap();
                        } else {
                            let statement = format!("UPDATE store_binding SET {field}=?1");
                            db.execute(&statement, [[0x71u8; 32].as_slice()]).unwrap();
                        }
                        drop(db);
                        *captured.lock().unwrap() = std::fs::read(&raced_path).unwrap();
                    }))
                });
                let result = if let Some((b, signature)) = proof {
                    store
                        .admit(&expect, &descriptor, &b, &signature, &deny)
                        .map(|_| ())
                } else {
                    store.issue(&expect, &descriptor, &deny).map(|_| ())
                };
                assert_eq!(result, Err(refusal));
                drop(store);
                assert_eq!(
                    std::fs::read(&path).unwrap(),
                    *snapshot.lock().unwrap(),
                    "refusal adds no mutation beyond the explicitly injected substitution"
                );
                let db =
                    Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
                let admitted: i64 = db
                    .query_row("SELECT count(*) FROM admissions", [], |r| r.get(0))
                    .unwrap();
                let consumed: i64 = db
                    .query_row("SELECT count(*) FROM issued WHERE consumed=1", [], |r| {
                        r.get(0)
                    })
                    .unwrap();
                let issued: i64 = db
                    .query_row("SELECT count(*) FROM issued", [], |r| r.get(0))
                    .unwrap();
                assert_eq!(admitted, 0);
                assert_eq!(consumed, 0);
                assert_eq!(issued, if admitting { 1 } else { 0 });
            }
        }
    }
    #[test]
    fn denylisted_exact_descriptor_is_refused_before_nonce_or_issuance() {
        use crate::treasury_v1::{Class, Treasury};
        use mutiny_crypto_v2::{NETWORK, rehearsal_keys_v1::Credential};
        let key = Credential::from_label("PUBLIC-v3-denylist", 1).unwrap();
        let descriptor = key.descriptor().unwrap();
        let config = CeremonyConfig::rehearsal(
            NETWORK,
            Treasury::new(Class::TestValue, descriptor.clone()).unwrap(),
            "PUBLIC-v3-denylist-context",
        )
        .unwrap();
        let expect = Expect::genesis_key(&config);
        let deny = Denylist::default()
            .with_hex_lines(&hex::encode(key.key_sha256()))
            .unwrap();
        let dir = super::test_dir::TestDir::new("treasury-v3-denylist");
        let path = dir.file("store.sqlite");
        let id = AdmissionStore::create(&path, &config).unwrap();
        let before = std::fs::read(&path).unwrap();
        let mut store = AdmissionStore::open(&path, &config, id).unwrap();
        assert_eq!(
            store.issue(&expect, &descriptor, &deny),
            Err(Refusal::Denylisted)
        );
        let count: i64 = store
            .db
            .query_row("SELECT count(*) FROM issued", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
        drop(store);
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}
