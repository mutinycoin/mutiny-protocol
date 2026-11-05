//! The preimage store (phase 7, Q13): hash-lock preimages in their OWN encrypted record, beside the
//! vault in the custody directory; the desktop implementation of wallet-core's `PreimageStore`
//! (`ops::conditional`).
//!
//!  * Fresh operating-system random values (`create`), NEVER derived from the wallet phrase or any
//!    key: nothing here can reach a key, and the store has no input but randomness or a disclosed
//!    preimage.
//!  * Each entry (its condition and its preimage) is one DPAPI-sealed value (`custody_seal`) bound
//!    to this file's random identifier and its row: the file does not even say which locks this
//!    wallet can claim; lookup by the lock's condition opens and compares.
//!  * Erased only by the person's explicit act (`erase`): nothing here deletes a preimage on its own
//!    (a claim that is not final yet may still need it). SQLite `secure_delete` overwrites the row.
//!  * Plaintext only in zeroizing buffers and in wallet-core's redacted, zeroizing `Preimage`.
//!
//! wallet-core's `Preimage` lets only wallet-core read its bytes, so `PreimageStore::insert` (a
//! `Preimage` obtained elsewhere) cannot be stored durably here: it is refused with an explicit
//! reason, and a disclosed preimage is recorded from its raw bytes with `insert_disclosed` instead
//! (change request CR-W7-2 in the phase report).
//!
//! Order W10 (candidate 3): a preimage is SEALED before its first byte is handed to SQLite, so no
//! file (the store, its rollback journal, a crash leftover, a SQLite temporary file: those stay in
//! memory) ever holds it in clear; a crash at any write boundary leaves sealed bytes only, and the
//! next open recovers the last commit through SQLite's journal without reading anything as a
//! secret. Tested at each boundary (`crash_point`s below) by scanning every file of the folder.
use crate::{
    custody_acl_v2,
    custody_seal::{self, Reader, Writer},
};
use mutiny_consensus_v8::{Hash, trading_v1::preimage_hash};
use mutiny_wallet_core_v8::{Preimage, Refusal, ops::conditional::PreimageStore};
use rusqlite::{Connection, ErrorCode, OpenFlags, TransactionBehavior, params};
use std::{fmt, path::Path, time::Duration};
use zeroize::Zeroizing;

/// File name inside the custody directory (an allow-listed name in `custody_acl_v2`).
pub const FILE_NAME: &str = "preimages-v1.sqlite";
/// SQLite `application_id` ("MUPR").
pub const APPLICATION_ID: i64 = 0x4d55_5052;
pub const SCHEMA_VERSION: i64 = 1;
/// Most preimages one store holds.
pub const MAX_PREIMAGES: usize = 4096;
const DOMAIN: &[u8] = b"MUTINY-BUILD8-DESKTOP-PREIMAGE-STORE-V1";
const PROBE: &[u8] = b"MUTINY-BUILD8-DESKTOP-PREIMAGE-STORE-PROBE-V1";
const RECORD_VERSION: u8 = 1;
pub(crate) const DAMAGED: Refusal = Refusal::Malformed("the preimage store failed its integrity check");
const LOCATION: Refusal = Refusal::InvalidRequest(
    "the preimage store must be its allow-listed file in the custody directory",
);
const NOT_STORABLE: Refusal = Refusal::InvalidRequest(
    "a preimage given as a Preimage value cannot be read back for durable storage; record a disclosed preimage from its bytes instead",
);

pub(crate) const SCHEMA: [(&str, &str); 2] = [
    (
        "preimage_store_context_v1",
        "CREATE TABLE preimage_store_context_v1(id INTEGER PRIMARY KEY CHECK(id=1),file_id BLOB NOT NULL CHECK(length(file_id)=32),probe BLOB NOT NULL CHECK(length(probe) BETWEEN 1 AND 4096))",
    ),
    (
        "preimage_store_records_v1",
        "CREATE TABLE preimage_store_records_v1(seq INTEGER PRIMARY KEY CHECK(seq>=1),sealed BLOB NOT NULL CHECK(length(sealed) BETWEEN 1 AND 4096))",
    ),
];

fn storage(error: rusqlite::Error) -> Refusal {
    match &error {
        rusqlite::Error::SqliteFailure(failure, _) => match failure.code {
            ErrorCode::DiskFull => Refusal::InvalidRequest("the disk is full"),
            ErrorCode::DatabaseBusy | ErrorCode::DatabaseLocked => {
                Refusal::InvalidRequest("the preimage store is in use by another process")
            }
            ErrorCode::CannotOpen => LOCATION,
            _ => DAMAGED,
        },
        _ => DAMAGED,
    }
}

/// One opened entry.
struct Entry {
    seq: i64,
    condition: Hash,
    preimage: Zeroizing<[u8; 32]>,
}

/// The desktop's durable, sealed preimage store.
pub struct PreimageVault {
    // Field order: SQLite closes before the custody lease releases the path.
    db: Connection,
    file_id: Hash,
    _lease: custody_acl_v2::Lease,
}

impl PreimageVault {
    /// Open (creating it when new) the store at `path`, the allow-listed file of a custody
    /// directory. A file this Windows account cannot unseal is refused before anything is read.
    pub fn open(path: &Path) -> Result<Self, Refusal> {
        if path.file_name().and_then(|name| name.to_str()) != Some(FILE_NAME) {
            return Err(LOCATION);
        }
        // Order W7: the file's format is decided before the custody lease or SQLite could touch it
        // (`custody_format`); a retired, newer, foreign or damaged file is refused and left unchanged.
        crate::custody_format::check_store(path, crate::custody_format::StoreKind::PreimageStore)
            .map_err(|_| DAMAGED)?;
        let lease = custody_acl_v2::prepare(path).map_err(|_| LOCATION)?;
        let db = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_CREATE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(storage)?;
        db.busy_timeout(Duration::from_secs(5)).map_err(storage)?;
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
            return Err(DAMAGED);
        }
        custody_seal::configure(&db).map_err(storage)?;
        if objects == 0 {
            let file_id = custody_seal::random32().map_err(|_| Refusal::EntropyUnavailable)?;
            let probe = custody_seal::seal(PROBE, &Self::binding_for(&file_id, b"probe", 0))
                .map_err(|_| LOCATION)?;
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
                    "INSERT INTO preimage_store_context_v1(id,file_id,probe) VALUES(1,?1,?2)",
                    params![file_id.as_slice(), probe],
                )
                .map_err(storage)?;
            transaction.commit().map_err(storage)?;
        }
        if !custody_seal::schema_is_exact(&db, APPLICATION_ID, SCHEMA_VERSION, &SCHEMA)
            .map_err(storage)?
        {
            return Err(DAMAGED);
        }
        let (file_id, probe): (Vec<u8>, Vec<u8>) = db
            .query_row(
                "SELECT file_id,probe FROM preimage_store_context_v1 WHERE id=1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .map_err(storage)?;
        let file_id: Hash = file_id.try_into().map_err(|_| DAMAGED)?;
        let opened = custody_seal::open(&probe, &Self::binding_for(&file_id, b"probe", 0))
            .map_err(|_| DAMAGED)?;
        if opened.as_slice() != PROBE {
            return Err(DAMAGED);
        }
        let store = Self {
            db,
            file_id,
            _lease: lease,
        };
        Self::load(&store.file_id, &store.db)?;
        Ok(store)
    }

    fn binding_for(file_id: &Hash, field: &[u8], seq: i64) -> [u8; 64] {
        custody_seal::binding(DOMAIN, &[field, file_id, &seq.to_be_bytes()])
    }

    /// Every entry, opened and checked (the sealed condition must be SHA-256 of the sealed
    /// preimage, and no condition may appear twice).
    fn load(file_id: &Hash, db: &Connection) -> Result<Vec<Entry>, Refusal> {
        let mut statement = db
            .prepare("SELECT seq,sealed FROM preimage_store_records_v1 ORDER BY seq")
            .map_err(storage)?;
        let rows = statement
            .query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, Vec<u8>>(1)?)))
            .map_err(storage)?;
        let mut out: Vec<Entry> = Vec::new();
        for row in rows {
            let (seq, sealed) = row.map_err(storage)?;
            let plain = custody_seal::open(&sealed, &Self::binding_for(file_id, b"record", seq))
                .map_err(|_| DAMAGED)?;
            let r = &mut Reader::new(&plain);
            if r.u8() != Some(RECORD_VERSION) {
                return Err(DAMAGED);
            }
            let condition = r.hash().ok_or(DAMAGED)?;
            let preimage = Zeroizing::new(r.hash().ok_or(DAMAGED)?);
            r.finish().ok_or(DAMAGED)?;
            if preimage_hash(&preimage) != condition
                || out.iter().any(|entry| entry.condition == condition)
            {
                return Err(DAMAGED);
            }
            out.push(Entry {
                seq,
                condition,
                preimage,
            });
        }
        if out.len() > MAX_PREIMAGES {
            return Err(DAMAGED);
        }
        Ok(out)
    }

    fn add(&mut self, preimage: Zeroizing<[u8; 32]>) -> Result<Hash, Refusal> {
        let condition = preimage_hash(&preimage);
        let file_id = self.file_id;
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let entries = Self::load(&file_id, &transaction)?;
        if entries.iter().any(|entry| entry.condition == condition) {
            return Ok(condition);
        }
        if entries.len() >= MAX_PREIMAGES {
            return Err(Refusal::InvalidRequest("the preimage store is full"));
        }
        let seq: i64 = transaction
            .query_row(
                "SELECT COALESCE(MAX(seq),0)+1 FROM preimage_store_records_v1",
                [],
                |row| row.get(0),
            )
            .map_err(storage)?;
        let mut w = Writer::default();
        w.u8(RECORD_VERSION).bytes(&condition).bytes(preimage.as_ref());
        let sealed = custody_seal::seal(
            &w.finish(),
            &Self::binding_for(&file_id, b"record", seq),
        )
        .map_err(|_| DAMAGED)?;
        // Order W10: sealed above, before SQLite sees a byte of it.
        custody_seal::crash_point("preimage-add-sealed");
        transaction
            .execute(
                "INSERT INTO preimage_store_records_v1(seq,sealed) VALUES(?1,?2)",
                params![seq, sealed],
            )
            .map_err(storage)?;
        custody_seal::crash_point("preimage-add-before-commit");
        transaction.commit().map_err(storage)?;
        custody_seal::crash_point("preimage-add-after-commit");
        Ok(condition)
    }

    /// Record a preimage disclosed by someone else, from its raw bytes (for example typed or read
    /// from a counterparty's file). Returns its condition; recording it twice is one entry.
    pub fn insert_disclosed(&mut self, preimage: Zeroizing<[u8; 32]>) -> Result<Hash, Refusal> {
        self.add(preimage)
    }

    /// How many preimages the store holds.
    pub fn len(&self) -> Result<usize, Refusal> {
        Ok(Self::load(&self.file_id, &self.db)?.len())
    }

    /// Test hook (Order W10 evidence): the plaintext preimage of `condition`, so that a test can
    /// search files and texts for it. Production code reads a preimage only as wallet-core's
    /// redacted `Preimage`.
    #[cfg(test)]
    pub(crate) fn plaintext_for_test(&self, condition: &Hash) -> Option<[u8; 32]> {
        Self::load(&self.file_id, &self.db)
            .ok()?
            .into_iter()
            .find(|entry| entry.condition == *condition)
            .map(|entry| *entry.preimage)
    }
}

impl PreimageStore for PreimageVault {
    fn create(&mut self) -> Result<Hash, Refusal> {
        let mut fresh = Zeroizing::new([0u8; 32]);
        mutiny_crypto_v2::fill_os_random(fresh.as_mut()).map_err(|_| Refusal::EntropyUnavailable)?;
        self.add(fresh)
    }
    fn insert(&mut self, _preimage: Preimage) -> Result<Hash, Refusal> {
        // The value is dropped (and erased) here; see the module documentation.
        Err(NOT_STORABLE)
    }
    fn preimage(&self, condition: &Hash) -> Result<Option<Preimage>, Refusal> {
        Ok(Self::load(&self.file_id, &self.db)?
            .into_iter()
            .find(|entry| entry.condition == *condition)
            .map(|entry| Preimage::from_bytes(*entry.preimage)))
    }
    fn erase(&mut self, condition: &Hash) -> Result<bool, Refusal> {
        let file_id = self.file_id;
        let transaction = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let Some(seq) = Self::load(&file_id, &transaction)?
            .into_iter()
            .find(|entry| entry.condition == *condition)
            .map(|entry| entry.seq)
        else {
            return Ok(false);
        };
        transaction
            .execute("DELETE FROM preimage_store_records_v1 WHERE seq=?1", [seq])
            .map_err(storage)?;
        custody_seal::crash_point("preimage-erase-before-commit");
        transaction.commit().map_err(storage)?;
        custody_seal::crash_point("preimage-erase-after-commit");
        Ok(true)
    }
    fn conditions(&self) -> Result<Vec<Hash>, Refusal> {
        let mut out: Vec<Hash> = Self::load(&self.file_id, &self.db)?
            .into_iter()
            .map(|entry| entry.condition)
            .collect();
        out.sort();
        Ok(out)
    }
}

impl fmt::Debug for PreimageVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreimageVault")
            .field("preimages", &self.len().ok())
            .finish()
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    use crate::test_support::{TestDir, custody_file, run_child};

    fn raw_file(base: &TestDir) -> Vec<u8> {
        let mut all = std::fs::read(custody_file(base, FILE_NAME)).unwrap();
        let journal = custody_file(base, &format!("{FILE_NAME}-journal"));
        if journal.exists() {
            all.extend(std::fs::read(journal).unwrap());
        }
        all
    }

    #[test]
    fn fresh_preimages_are_sealed_survive_reopen_and_are_erased_only_on_request() {
        let base = TestDir::new("w7-preimages");
        let path = custody_file(&base, FILE_NAME);
        let mut store = PreimageVault::open(&path).unwrap();
        let first = store.create().unwrap();
        let second = store.create().unwrap();
        assert_ne!(first, second);
        assert_eq!(store.conditions().unwrap(), {
            let mut both = vec![first, second];
            both.sort();
            both
        });
        // Lookup by the lock's condition gives a preimage whose condition is that one.
        assert_eq!(store.preimage(&first).unwrap().unwrap().condition(), first);
        assert!(store.preimage(&[0x55; 32]).unwrap().is_none());
        // Nothing in clear: neither a preimage nor even its (public) condition is in the file.
        let secrets: Vec<[u8; 32]> = PreimageVault::load(&store.file_id, &store.db)
            .unwrap()
            .iter()
            .map(|entry| *entry.preimage)
            .collect();
        drop(store);
        let file = raw_file(&base);
        for needle in secrets.iter().chain([&first, &second]) {
            assert!(
                !file.windows(32).any(|window| window == needle),
                "a preimage or condition is stored in clear"
            );
        }
        // A restart keeps them; a value given as a `Preimage` cannot be stored; a disclosed one can.
        let mut store = PreimageVault::open(&path).unwrap();
        assert_eq!(store.len().unwrap(), 2);
        assert_eq!(
            store.insert(Preimage::from_bytes([0x61; 32])).unwrap_err(),
            NOT_STORABLE
        );
        let disclosed = store.insert_disclosed(Zeroizing::new([0x61; 32])).unwrap();
        assert_eq!(disclosed, preimage_hash(&[0x61; 32]));
        assert_eq!(store.insert_disclosed(Zeroizing::new([0x61; 32])).unwrap(), disclosed);
        assert_eq!(store.len().unwrap(), 3);
        // Erasure is the explicit act: once, then gone for good.
        assert!(store.erase(&first).unwrap());
        assert!(!store.erase(&first).unwrap());
        drop(store);
        let store = PreimageVault::open(&path).unwrap();
        assert!(store.preimage(&first).unwrap().is_none());
        assert!(store.preimage(&second).unwrap().is_some());
        assert!(!format!("{store:?}").contains(&hex::encode(second)));
        assert_eq!(format!("{store:?}"), "PreimageVault { preimages: Some(2) }");
    }

    /// The preimage source is pinned (survivor D1 of the independent wallet review): `create` takes
    /// a fresh value from the operating system's randomness through crypto-v2 and nothing else.
    /// Structural: the function is exactly that. Difference: two fresh stores never produce the same
    /// preimage (a value derived from a store's state, its size for example, repeats across stores).
    /// Statistical: every one of the 256 bit positions takes both values over the 32 preimages (a
    /// uniform source fails with probability below 2^-23).
    #[test]
    fn the_preimage_source_is_the_operating_systems_randomness() {
        let source = include_str!("preimage_store.rs");
        let start = source
            .find("    fn create(&mut self) -> Result<Hash, Refusal> {")
            .unwrap();
        let end = start + source[start..].find("\n    }\n").unwrap();
        let lines: Vec<&str> = source[start..end].lines().map(str::trim).collect();
        assert_eq!(
            lines,
            [
                "fn create(&mut self) -> Result<Hash, Refusal> {",
                "let mut fresh = Zeroizing::new([0u8; 32]);",
                "mutiny_crypto_v2::fill_os_random(fresh.as_mut()).map_err(|_| Refusal::EntropyUnavailable)?;",
                "self.add(fresh)",
            ]
        );
        let mut seen: Vec<[u8; 32]> = Vec::new();
        for label in ["w8-preimage-source-1", "w8-preimage-source-2"] {
            let base = TestDir::new(label);
            let mut store = PreimageVault::open(&custody_file(&base, FILE_NAME)).unwrap();
            for _ in 0..16 {
                store.create().unwrap();
            }
            seen.extend(
                PreimageVault::load(&store.file_id, &store.db)
                    .unwrap()
                    .iter()
                    .map(|entry| *entry.preimage),
            );
        }
        assert_eq!(seen.len(), 32);
        let distinct: std::collections::BTreeSet<[u8; 32]> = seen.iter().copied().collect();
        assert_eq!(distinct.len(), 32, "a preimage repeated");
        for bit in 0..256 {
            let ones = seen
                .iter()
                .filter(|value| value[bit / 8] >> (bit % 8) & 1 == 1)
                .count();
            assert!(ones > 0 && ones < seen.len(), "bit {bit} never varies");
        }
    }

    const W10_CHILD: &str = "BUILD8_W10_PREIMAGE_CHILD";

    /// The child of the W10 crash test: open the store of the folder the parent names and add (or
    /// erase) the preimage the parent passes in its environment (process memory, never a file); the
    /// crash point named by BUILD8_W7_CRASH_POINT ends the process there, skipping every destructor.
    #[test]
    fn preimage_crash_child() {
        let Some(dir) = std::env::var_os(W10_CHILD) else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        assert_eq!(dir.parent(), Some(std::env::temp_dir().as_path()));
        let secret: [u8; 32] = hex::decode(std::env::var("BUILD8_W10_SECRET").unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let mut store = PreimageVault::open(&dir.join("WalletCustodyV2").join(FILE_NAME)).unwrap();
        match std::env::var("BUILD8_W10_STEP").unwrap().as_str() {
            "add" => drop(store.insert_disclosed(Zeroizing::new(secret)).unwrap()),
            "erase" => assert!(store.erase(&preimage_hash(&secret)).unwrap()),
            other => panic!("unknown step {other}"),
        }
        std::process::exit(98);
    }

    /// Order W10: a process killed at any write boundary of the preimage store (after sealing,
    /// inside the write transaction, after the commit; for an addition and for an erasure) leaves NO
    /// plaintext preimage in any file of the folder (the store, its hot rollback journal, anything
    /// else), raw or hexadecimal. The next open recovers exactly the last commit through SQLite's
    /// journal without reading leftovers as secrets, and the folder is clean again afterwards. The
    /// journal a crash leaves carries only the custody folder's inherited owner and SYSTEM access.
    /// SQLite's temporary files stay in memory.
    #[test]
    fn no_plaintext_preimage_on_disk_at_any_crash_point() {
        let mut secret = [0u8; 32];
        mutiny_crypto_v2::fill_os_random(&mut secret).unwrap();
        let condition = preimage_hash(&secret);
        for (step, point, journal_left, present_after) in [
            ("add", "preimage-add-sealed", false, false),
            ("add", "preimage-add-before-commit", true, false),
            ("add", "preimage-add-after-commit", false, true),
            ("erase", "preimage-erase-before-commit", true, true),
            ("erase", "preimage-erase-after-commit", false, false),
        ] {
            let base = TestDir::new("w10-preimage-crash");
            let path = custody_file(&base, FILE_NAME);
            {
                let mut store = PreimageVault::open(&path).unwrap();
                let temp_store: i64 = store
                    .db
                    .query_row("PRAGMA temp_store", [], |row| row.get(0))
                    .unwrap();
                assert_eq!(temp_store, 2, "temp_store=MEMORY");
                store.create().unwrap(); // a neighbour entry
                if step == "erase" {
                    store.insert_disclosed(Zeroizing::new(secret)).unwrap();
                }
            }
            assert!(crate::test_support::assert_no_secret_in_files(base.path(), &secret, "before") >= 1);
            let output = run_child(
                "preimage_store::tests::preimage_crash_child",
                &[
                    (W10_CHILD, base.path().as_os_str()),
                    ("BUILD8_W10_SECRET", std::ffi::OsStr::new(&hex::encode(secret))),
                    ("BUILD8_W10_STEP", std::ffi::OsStr::new(step)),
                    ("BUILD8_W7_CRASH_POINT", std::ffi::OsStr::new(point)),
                ],
            );
            assert_eq!(
                output.status.code(),
                Some(97),
                "child ({point}) failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let journal = custody_file(&base, &format!("{FILE_NAME}-journal"));
            assert_eq!(journal.exists(), journal_left, "{point}: the crash leftover");
            let scanned = crate::test_support::assert_no_secret_in_files(base.path(), &secret, point);
            assert!(scanned > usize::from(journal_left), "{point}: {scanned} files scanned");
            if journal_left {
                let (sddl, sid) = crate::custody_acl_v2::dacl_for_test(&journal);
                let aces: std::collections::BTreeSet<String> = sddl
                    .split('(')
                    .skip(1)
                    .map(|ace| ace.trim_end_matches(')').replace(";ID;", ";;"))
                    .collect();
                assert_eq!(
                    aces,
                    std::collections::BTreeSet::from(["A;;FA;;;SY".to_string(), format!("A;;FA;;;{sid}")]),
                    "{point}: the journal's DACL {sddl}"
                );
            }
            if journal_left {
                // SQLite syncs a journal's header when it commits, or earlier when its page cache
                // spills; this small transaction does not spill, so the journal left before the
                // commit is not hot: SQLite ignores it and never reads it as data. (The safety does
                // not rest on this: the journal holds sealed values only, scanned above.)
                assert_eq!(std::fs::read(&journal).unwrap()[..8], [0u8; 8], "{point}: header");
            }
            // Recovery: exactly the last commit; the leftover is never read as a secret.
            let mut store = PreimageVault::open(&path).unwrap();
            assert_eq!(
                store.preimage(&condition).unwrap().is_some(),
                present_after,
                "{point}: after recovery"
            );
            assert_eq!(store.len().unwrap(), 1 + usize::from(present_after), "{point}");
            crate::test_support::assert_no_secret_in_files(
                base.path(),
                &secret,
                &format!("{point}, after recovery"),
            );
            // The next write replaces a stale journal and deletes it at its commit.
            store.create().unwrap();
            drop(store);
            assert!(!journal.exists(), "{point}: the stale journal outlived the next write");
            crate::test_support::assert_no_secret_in_files(
                base.path(),
                &secret,
                &format!("{point}, after the next write"),
            );
        }
    }

    /// Order W10: the store's `Debug` shows a count, never a condition or a preimage (the scan of
    /// `test_support::assert_no_secret_in_text`: hexadecimal, byte list, partial windows).
    #[test]
    fn the_store_debug_output_shows_no_preimage() {
        let base = TestDir::new("w10-preimage-debug");
        let mut store = PreimageVault::open(&custody_file(&base, FILE_NAME)).unwrap();
        let mut secret = [0u8; 32];
        mutiny_crypto_v2::fill_os_random(&mut secret).unwrap();
        let condition = store.insert_disclosed(Zeroizing::new(secret)).unwrap();
        let shown = format!("{store:?} {:?}", store.preimage(&condition).unwrap());
        crate::test_support::assert_no_secret_in_text(&shown, &secret, "the preimage store's Debug");
        assert_eq!(shown, "PreimageVault { preimages: Some(1) } Some(Preimage(<redacted>))");
        // The scan itself sees a leak.
        let leaked = std::panic::catch_unwind(|| {
            crate::test_support::assert_no_secret_in_text(&hex::encode(&secret[3..9]), &secret, "probe")
        });
        assert!(leaked.is_err());
        // ...also inside a longer decimal byte list (how a derived Debug shows a Vec<u8>).
        let longer = format!("{:?}", [&[7u8, 8, 9][..], &secret[..], &[1u8][..]].concat());
        let leaked = std::panic::catch_unwind(|| {
            crate::test_support::assert_no_secret_in_text(&longer, &secret, "probe")
        });
        assert!(leaked.is_err());
    }

    #[test]
    fn a_tampered_swapped_or_foreign_store_is_refused() {
        // An EMPTY store under another key: only the probe can tell, and it refuses the file.
        {
            let base = TestDir::new("w7-preimages-empty-key");
            let path = custody_file(&base, FILE_NAME);
            let store = PreimageVault::open(&path).unwrap();
            store
                .db
                .execute("UPDATE preimage_store_context_v1 SET file_id=zeroblob(32)", [])
                .unwrap();
            drop(store);
            assert_eq!(PreimageVault::open(&path).unwrap_err(), DAMAGED);
        }
        let base = TestDir::new("w7-preimages-tamper");
        let path = custody_file(&base, FILE_NAME);
        let mut store = PreimageVault::open(&path).unwrap();
        let first = store.create().unwrap();
        store.create().unwrap();
        // Any changed byte of a sealed entry is refused.
        let sealed: Vec<u8> = store
            .db
            .query_row("SELECT sealed FROM preimage_store_records_v1 WHERE seq=1", [], |r| r.get(0))
            .unwrap();
        for position in [0, sealed.len() / 2, sealed.len() - 1] {
            let mut damaged = sealed.clone();
            damaged[position] ^= 1;
            store
                .db
                .execute("UPDATE preimage_store_records_v1 SET sealed=?1 WHERE seq=1", [&damaged])
                .unwrap();
            assert_eq!(store.preimage(&first).unwrap_err(), DAMAGED);
            assert_eq!(store.conditions().unwrap_err(), DAMAGED);
        }
        // Moving a sealed entry to another row is refused (its binding names its row).
        let other: Vec<u8> = store
            .db
            .query_row("SELECT sealed FROM preimage_store_records_v1 WHERE seq=2", [], |r| r.get(0))
            .unwrap();
        store
            .db
            .execute("UPDATE preimage_store_records_v1 SET sealed=?1 WHERE seq=1", [&other])
            .unwrap();
        assert_eq!(store.conditions().unwrap_err(), DAMAGED);
        // Another file identifier (a copied or edited context): the probe does not open.
        store
            .db
            .execute("UPDATE preimage_store_records_v1 SET sealed=?1 WHERE seq=1", [&sealed])
            .unwrap();
        store
            .db
            .execute("UPDATE preimage_store_context_v1 SET file_id=zeroblob(32)", [])
            .unwrap();
        drop(store);
        assert_eq!(PreimageVault::open(&path).unwrap_err(), DAMAGED);
        // A file that is not a preimage store, and a name that is not the allow-listed one.
        assert_eq!(
            PreimageVault::open(&custody_file(&base, "wallet-hybrid-v2.sqlite")).unwrap_err(),
            LOCATION
        );
    }
}
