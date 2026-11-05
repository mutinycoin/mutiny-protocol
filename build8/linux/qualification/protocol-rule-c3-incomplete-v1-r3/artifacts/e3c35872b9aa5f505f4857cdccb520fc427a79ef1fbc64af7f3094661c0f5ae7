//! Durable single-use ADMISSION store for Treasury proofs of control (D2 ceremony layer, Architect
//! order section 7: "first admission consumes the nonce durably; repeated read-only verify-frozen
//! checks validate the same recorded proof without consuming it again").
//!
//! SIMULATED / TEST-VALUE evidence only. Public data only: the store holds challenge, descriptor and
//! signature bytes, never a secret.
//!
//! First admission. [`AdmissionStore::admit`] verifies the proof against the TRUSTED expectation
//! (read-only, [`crate::treasury_rehearsal_v1::verify_proof`]) and then records it in ONE `IMMEDIATE`
//! SQLite transaction keyed by the nonce. Writable connections run with `journal_mode=DELETE` and
//! `synchronous=EXTRA` (EXTRA also syncs the directory after the rollback journal is deleted at the
//! commit point; with FULL it is not), and every open READS BACK the pragmas and refuses a connection on
//! which they are not in effect. The nonce is consumed if and only if that transaction commits: a
//! refusal or a failure before the commit leaves the file byte-identical and consumes nothing, and a
//! second admission of the same nonce (also a concurrent one, serialized by the write lock, and also
//! after a restart) is refused as `Replay` by the existence check inside that transaction; the primary
//! key on the nonce is a fail-closed backstop (a conflict there is `Store`).
//!
//! Audit. [`AdmissionStore::open_read_only`] opens the file with `SQLITE_OPEN_READ_ONLY` and
//! `query_only` and verifies that SQLite reports the connection read-only; the audit functions
//! ([`crate::treasury_rehearsal_v1::audit_recorded`], [`crate::treasury_rehearsal_v1::build_manifest`],
//! [`crate::treasury_rehearsal_v1::verify_frozen`]) take the store by shared reference and cannot
//! write through it, so repeated audits are repeatable and leave the store byte-identical.
//!
//! Identity and binding. [`AdmissionStore::create`] draws a random 32-byte STORE ID from the OS CSPRNG;
//! the id, the expected ceremony context (the nonce domain) and the SHA-256 of the trusted Treasury
//! record are written at creation. Context and record must equal the trusted configuration at every
//! open (never discovered from the file); the store id is reported, recorded in the rehearsal manifest
//! and required by `verify_frozen` to equal the id the approved manifest names. Creation is explicit and
//! never reuses an existing file, an admission never creates a missing store, and the schema objects
//! (names and exact SQL) and pragmas are validated on every open.
//!
//! Stated limits (not closed by this module): replay protection is RELATIVE TO THE IDENTIFIED STORE. A
//! party able to create a fresh store for the same ceremony can admit a replayed proof into THAT store
//! (it gets a new store id, which an approved manifest naming the original store does not match). A
//! party with write access to the file can delete records or substitute the file (rollback); custody of
//! the verifier machine and its storage is a procedural ceremony control. Keep the `-journal` sidecar
//! with the store: after a crash it is the rollback record of an uncommitted admission. On Windows the
//! SQLite VFS ignores the directory-sync request of `synchronous=EXTRA`; whether NTFS persists the
//! journal deletion across power loss without it is not established here. Offline != Physical.
use crate::{
    Hash,
    treasury_rehearsal_v1::{self as rehearsal, CeremonyConfig, Denylist, Expect, Outcome, Refusal, VerifiedProof},
};
use mutiny_crypto_v2::{
    HybridSignature,
    treasury_proof_v1::{self as proof, Challenge},
};
use rusqlite::{Connection, MAIN_DB, OpenFlags, OptionalExtension, TransactionBehavior, params};
use std::path::Path;
use std::sync::OnceLock;

pub const STORE_SCHEMA: &str = "MUTINY-D2-TREASURY-ADMISSION-STORE-V2";
const WRITE_PRAGMAS: &str = "PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=EXTRA;";
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

fn storage<T>(result: rusqlite::Result<T>) -> Outcome<T> {
    result.map_err(|_| Refusal::Store)
}
/// The binding of a ceremony: (expected context, SHA-256 of the trusted Treasury record).
fn binding(config: &CeremonyConfig) -> Outcome<(Hash, Hash)> {
    Ok((config.context().value(), rehearsal::record_sha256(config.treasury())?))
}
fn objects(db: &Connection) -> Outcome<Vec<SchemaObject>> {
    let mut statement = storage(db.prepare("SELECT type, name, sql FROM sqlite_schema ORDER BY name"))?;
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
    storage(db.execute_batch(&format!("{BINDING_SQL};\n{ADMISSIONS_SQL};")))?;
    let found = objects(&db)?;
    Ok(EXPECTED.get_or_init(|| found))
}
fn read_durability(db: &Connection) -> Outcome<Durability> {
    Ok(Durability {
        synchronous: storage(db.pragma_query_value(None, "synchronous", |r| r.get(0)))?,
        journal_mode: storage(db.pragma_query_value(None, "journal_mode", |r| r.get(0)))?,
        query_only: storage(db.pragma_query_value(None, "query_only", |r| r.get::<_, i64>(0)))? != 0,
        read_only: storage(db.is_readonly(MAIN_DB))?,
    })
}
/// Apply and READ BACK the connection settings: writable connections must run `synchronous=EXTRA` with
/// the rollback journal (`delete`; `memory` only for a scratch in-memory store), read-only ones
/// `query_only` on a connection SQLite reports read-only. Anything else is refused (`Store`).
fn configure(db: &Connection, writable: bool, in_memory: bool) -> Outcome<()> {
    storage(db.busy_timeout(std::time::Duration::from_secs(5)))?;
    storage(db.execute_batch(if writable { WRITE_PRAGMAS } else { READ_PRAGMAS }))?;
    let trusted_schema: i64 = storage(db.pragma_query_value(None, "trusted_schema", |r| r.get(0)))?;
    let d = read_durability(db)?;
    let applied = if writable {
        d.synchronous == SYNCHRONOUS_EXTRA && d.journal_mode == if in_memory { "memory" } else { "delete" } && !d.query_only && !d.read_only
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
        db.query_row("SELECT schema, context, record_sha256, store_id FROM store_binding WHERE id=1", [], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
        })
        .optional(),
    )?;
    match row {
        Some((schema, c, r, id)) if rows == 1 && schema == STORE_SCHEMA && c == context && r == record => id.try_into().map_err(|_| Refusal::StoreBinding),
        _ => Err(Refusal::StoreBinding),
    }
}

impl AdmissionStore {
    /// Create a NEW store file at `path` bound to the trusted configuration, with a fresh random store
    /// id. An existing file is never reused or overwritten (atomic `create_new`).
    pub fn create(path: &Path, config: &CeremonyConfig) -> Outcome<Self> {
        let (context, record) = binding(config)?;
        std::fs::OpenOptions::new().write(true).create_new(true).open(path).map_err(|_| Refusal::Store)?;
        let db = storage(Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX))?;
        Self::initialize(db, context, record, false)
    }
    /// A scratch store with identical semantics, held in memory (negative controls and tests only;
    /// it is not durable and is never a ceremony record).
    pub fn in_memory(config: &CeremonyConfig) -> Outcome<Self> {
        let (context, record) = binding(config)?;
        Self::initialize(storage(Connection::open_in_memory())?, context, record, true)
    }
    fn initialize(mut db: Connection, context: Hash, record: Hash, in_memory: bool) -> Outcome<Self> {
        configure(&db, true, in_memory)?;
        let mut store_id = [0u8; 32];
        mutiny_crypto_v2::fill_os_random(&mut store_id).map_err(|_| Refusal::Store)?;
        let tx = storage(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let count: i64 = storage(tx.query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0)))?;
        if count != 0 {
            return Err(Refusal::StoreBinding);
        }
        storage(tx.execute_batch(&format!("{BINDING_SQL};\n{ADMISSIONS_SQL};")))?;
        storage(tx.execute(
            "INSERT INTO store_binding VALUES(1,?1,?2,?3,?4)",
            params![STORE_SCHEMA, context.as_slice(), record.as_slice(), store_id.as_slice()],
        ))?;
        storage(tx.commit())?;
        let found = validate(&db, context, record)?;
        if found != store_id {
            return Err(Refusal::StoreBinding);
        }
        Ok(Self { db, context, record_sha256: record, store_id, writable: true })
    }
    /// Open an EXISTING store for admission (read-write; a missing file is an error, never created).
    pub fn open(path: &Path, config: &CeremonyConfig) -> Outcome<Self> {
        Self::open_with(path, config, true)
    }
    /// Open an EXISTING store for audit only (`SQLITE_OPEN_READ_ONLY`, `query_only`, read back):
    /// nothing can be written through it.
    pub fn open_read_only(path: &Path, config: &CeremonyConfig) -> Outcome<Self> {
        Self::open_with(path, config, false)
    }
    fn open_with(path: &Path, config: &CeremonyConfig, writable: bool) -> Outcome<Self> {
        let (context, record) = binding(config)?;
        let flags = if writable { OpenFlags::SQLITE_OPEN_READ_WRITE } else { OpenFlags::SQLITE_OPEN_READ_ONLY };
        let db = storage(Connection::open_with_flags(path, flags | OpenFlags::SQLITE_OPEN_NO_MUTEX))?;
        configure(&db, writable, false)?;
        let store_id = validate(&db, context, record)?;
        Ok(Self { db, context, record_sha256: record, store_id, writable })
    }
    /// The expectation's configuration must be the configuration this store was created for.
    pub fn check_binding(&self, config: &CeremonyConfig) -> Outcome<()> {
        let (context, record) = binding(config)?;
        if context != self.context || record != self.record_sha256 {
            return Err(Refusal::StoreBinding);
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

    /// FIRST ADMISSION: verify against the trusted expectation, then record the proof and consume its
    /// nonce in one IMMEDIATE transaction. A used nonce is `Replay`; nothing is written on any refusal.
    pub fn admit(
        &mut self,
        expect: &Expect,
        descriptor: &[u8],
        challenge_bytes: &[u8],
        signature: &HybridSignature,
        denylist: &Denylist,
    ) -> Outcome<VerifiedProof> {
        if !self.writable {
            return Err(Refusal::Store);
        }
        self.check_binding(expect.config())?;
        let verified = rehearsal::verify_proof(expect, descriptor, challenge_bytes, signature, denylist)?;
        let signature_bytes = proof::signature_to_bytes(signature);
        let tx = storage(self.db.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let used: bool = storage(tx.query_row("SELECT EXISTS(SELECT 1 FROM admissions WHERE nonce=?1)", [verified.nonce.as_slice()], |r| r.get(0)))?;
        if used {
            return Err(Refusal::Replay);
        }
        // The existence check above, under the write lock, decides `Replay`. The primary key is a
        // fail-closed backstop: a conflict there means the store is inconsistent (`Store`, nothing
        // admitted).
        match tx.execute(
            "INSERT INTO admissions VALUES(?1,?2,?3,?4)",
            params![verified.nonce.as_slice(), challenge_bytes, descriptor, signature_bytes.as_slice()],
        ) {
            Ok(1) => {}
            _ => return Err(Refusal::Store),
        }
        #[cfg(test)]
        if tests::FAIL_BEFORE_COMMIT.get() {
            return Err(Refusal::Store);
        }
        storage(tx.commit())?;
        Ok(verified)
    }

    /// The recorded first admission of `nonce`, re-validated on read.
    pub fn recorded(&self, nonce: &Hash) -> Outcome<Option<Admission>> {
        let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = storage(
            self.db
                .query_row("SELECT challenge, descriptor, signature FROM admissions WHERE nonce=?1", [nonce.as_slice()], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .optional(),
        )?;
        row.map(|(challenge, descriptor, signature)| checked(*nonce, challenge, descriptor, signature)).transpose()
    }
    /// Every recorded admission, ordered by nonce, each re-validated on read.
    pub fn admissions(&self) -> Outcome<Vec<Admission>> {
        let mut statement = storage(self.db.prepare("SELECT nonce, challenge, descriptor, signature FROM admissions ORDER BY nonce"))?;
        let rows: Vec<StoredRow> =
            storage(storage(statement.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))))?.collect())?;
        rows.into_iter()
            .map(|(nonce, challenge, descriptor, signature)| checked(nonce.try_into().map_err(|_| Refusal::Store)?, challenge, descriptor, signature))
            .collect()
    }
}

/// A recorded row must still be a strict challenge carrying the row's nonce and a two-component
/// signature; anything else is a damaged store (refused, never repaired).
fn checked(nonce: Hash, challenge: Vec<u8>, descriptor: Vec<u8>, signature: Vec<u8>) -> Outcome<Admission> {
    let decoded = Challenge::decode(&challenge).map_err(|_| Refusal::Store)?;
    if decoded.nonce != nonce || proof::signature_from_bytes(&signature).is_err() {
        return Err(Refusal::Store);
    }
    Ok(Admission { nonce, challenge, descriptor, signature })
}

#[cfg(test)]
mod tests {
    //! Atomicity of the admission transaction (fault injected after the INSERT, before the COMMIT).
    use super::*;
    use crate::treasury_v1::{Class, Treasury};
    use mutiny_crypto_v2::{NETWORK, fill_os_random, rehearsal_keys_v1::Credential};
    use std::cell::Cell;

    thread_local! {
        pub(super) static FAIL_BEFORE_COMMIT: Cell<bool> = const { Cell::new(false) };
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        loop {
            let mut n = [0u8; 8];
            fill_os_random(&mut n).unwrap();
            let dir = std::env::temp_dir().join(format!("build8-c3-admission-{tag}-{}", hex::encode(n)));
            match std::fs::create_dir(&dir) {
                Ok(()) => return dir,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("{e}"),
            }
        }
    }

    #[test]
    fn a_failure_between_insert_and_commit_admits_nothing_and_consumes_no_nonce() {
        let key = Credential::from_label("c3-atomic-k1", 1).unwrap();
        let descriptor = key.descriptor().unwrap();
        let config = CeremonyConfig::rehearsal(NETWORK, Treasury::new(Class::TestValue, descriptor.clone()).unwrap(), "c3-atomic-ceremony").unwrap();
        let expect = Expect::genesis_key(&config);
        let challenge = rehearsal::build_challenge(&config, &descriptor, [0x61; 32]).unwrap();
        let bytes = challenge.encode().unwrap();
        let signature = proof::sign_challenge(key.key(), &descriptor, &challenge).unwrap();
        let dir = scratch("atomic");
        let path = dir.join("admissions.sqlite");
        drop(AdmissionStore::create(&path, &config).unwrap());
        let before = std::fs::read(&path).unwrap();
        {
            let mut store = AdmissionStore::open(&path, &config).unwrap();
            FAIL_BEFORE_COMMIT.set(true);
            let failed = store.admit(&expect, &descriptor, &bytes, &signature, &Denylist::default());
            FAIL_BEFORE_COMMIT.set(false);
            assert_eq!(failed, Err(Refusal::Store));
            assert_eq!(store.recorded(&[0x61; 32]).unwrap(), None, "the uncommitted insert is not visible");
        }
        assert_eq!(std::fs::read(&path).unwrap(), before, "a failed admission leaves the file byte-identical");
        // After a restart the nonce is still unused: the admission succeeds exactly once.
        let mut store = AdmissionStore::open(&path, &config).unwrap();
        assert!(store.recorded(&[0x61; 32]).unwrap().is_none());
        store.admit(&expect, &descriptor, &bytes, &signature, &Denylist::default()).unwrap();
        assert_eq!(store.admit(&expect, &descriptor, &bytes, &signature, &Denylist::default()), Err(Refusal::Replay));
        drop(store);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&dir).unwrap();
    }
}
