//! Dedicated V2 encrypted vault. No V1 filename, migration or private export.
//!
//! Phase 7: the vault can REPLACE its identity after a confirmed wallet rotation, with
//! compare-and-swap semantics, so that afterwards it holds the NEW identity. Schema version 3:
//!  * `vault_records`: the ACTIVE identity record and at most one other record, a STAGED
//!    replacement (written and verified, not yet active) or the SUPERSEDED previous identity (kept
//!    until the person retires it). Every record is the unchanged V2 envelope (`Session::seal`:
//!    Argon2id and XChaCha20-Poly1305 inside Windows DPAPI, both bound to the identity).
//!  * `vault_pointer`: ONE row naming the active record, with the revision every change must name
//!    (compare-and-swap).
//!
//! The replacement is three separate durable steps, each a single SQLite transaction (rollback
//! journal on disk, synchronous FULL), so a crash at any point leaves the vault at the last commit:
//!  1. `stage_replacement`: the new identity is sealed with the vault password, read back through
//!     both encryption layers, and written NEXT TO the active record (the active one is untouched).
//!  2. `activate_replacement`: the staged record is read back from disk and opened again; only
//!     then is the pointer flipped to it, and the previous record is marked superseded (kept).
//!  3. `retire_previous`: the person's explicit act deletes the superseded record.
//!
//! Every step needs the vault password (it opens the active record) and the current revision.
//! What the vault cannot know (that the verified chain confirms the rotation, and that the new
//! phrase restores exactly the descriptor the rotation named) is checked by the controller before
//! it calls these steps; `activate_replacement` re-checks the descriptor it was given.
//! A version-2 file (one record, no pointer) is refused, never migrated.
//!
//! Order W7 (candidate 3): before the custody lease or SQLite touches the file, `custody_format`
//! decides what it is; a retired V1 wallet, an earlier, newer, foreign or damaged file is refused
//! with its typed reason (`OpenError::Unsupported`) and left exactly as it was.
use crate::wallet_v2::{Identity, Session, envelope_identity, ready};
use rusqlite::{Connection, TransactionBehavior, params};
use std::path::Path;
type Result<T> = std::result::Result<T, &'static str>;
/// SQLite application id of the vault ("MU82").
pub(crate) const APP_ID: i64 = 0x4d553832;
/// The one vault schema version this build opens.
pub(crate) const VERSION: i64 = 3;
/// The vault's file name inside the custody folder.
pub(crate) const FILE_NAME: &str = "wallet-hybrid-v2.sqlite";
const MAX_VAULT: usize = 32768;
const RECORDS_SQL: &str = "CREATE TABLE vault_records(slot INTEGER PRIMARY KEY CHECK(slot IN (1,2)), state INTEGER NOT NULL CHECK(state IN (1,2,3)),
                  envelope BLOB NOT NULL CHECK(length(envelope)>0 AND length(envelope)<=32768))";
const POINTER_SQL: &str = "CREATE TABLE vault_pointer(id INTEGER PRIMARY KEY CHECK(id=1), active INTEGER NOT NULL CHECK(active IN (1,2)),
                  revision INTEGER NOT NULL CHECK(revision>=1))";
const READ_RECORDS: &str = "SELECT CASE WHEN typeof(slot)='integer' AND slot IN (1,2) THEN slot ELSE NULL END,
    CASE WHEN typeof(state)='integer' AND state IN (1,2,3) THEN state ELSE NULL END,
    CASE WHEN typeof(envelope)='blob' AND length(envelope) BETWEEN 1 AND 32768 THEN envelope ELSE NULL END
    FROM vault_records ORDER BY slot";
const READ_POINTER: &str = "SELECT CASE WHEN typeof(id)='integer' AND id=1 THEN id ELSE NULL END,
    CASE WHEN typeof(active)='integer' AND active IN (1,2) THEN active ELSE NULL END,
    CASE WHEN typeof(revision)='integer' AND revision>=1 THEN revision ELSE NULL END FROM vault_pointer";
const ACTIVE: i64 = 1;
const STAGED: i64 = 2;
const SUPERSEDED: i64 = 3;

fn normalize(sql: &str) -> String {
    sql.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_uppercase()
}

/// The vault's exact schema (application id, version, the two tables' SQL, nothing else). Also used
/// by `custody_format` through a read-only, immutable connection before the vault is opened.
pub(crate) fn validate_schema(db: &Connection) -> Result<()> {
    let app: i64 = db
        .query_row("PRAGMA application_id", [], |r| r.get(0))
        .map_err(|_| "Invalid wallet database")?;
    let version: i64 = db
        .query_row("PRAGMA user_version", [], |r| r.get(0))
        .map_err(|_| "Invalid wallet database")?;
    if app != APP_ID || version != VERSION {
        return Err("Wallet format changed");
    }
    let count: i64 = db
        .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
        .map_err(|_| "Invalid wallet schema")?;
    if count != 2 {
        return Err("Unexpected wallet schema objects");
    }
    for (name, expected) in [("vault_records", RECORDS_SQL), ("vault_pointer", POINTER_SQL)] {
        let sql: String = db
            .query_row(
                "SELECT CASE WHEN typeof(sql)='text' AND length(CAST(sql AS BLOB))<=1024 THEN sql ELSE NULL END
                 FROM sqlite_schema WHERE type='table' AND name=?1 AND tbl_name=?1",
                [name],
                |r| r.get(0),
            )
            .map_err(|_| "Invalid wallet schema")?;
        if normalize(&sql) != normalize(expected) {
            return Err("Noncanonical wallet schema; migration is prohibited");
        }
    }
    Ok(())
}

/// One `vault_records` row as read: slot, state and envelope, each NULL when ill-typed or out of range.
type RecordRow = (Option<i64>, Option<i64>, Option<Vec<u8>>);
/// The `vault_pointer` row as read: id, active slot and revision, each NULL when ill-typed.
type PointerRow = (Option<i64>, Option<i64>, Option<i64>);

/// One vault: the pointer and its records, every invariant checked.
struct VaultRows {
    revision: i64,
    active_slot: i64,
    active: Vec<u8>,
    /// The other record, if any: (slot, state STAGED or SUPERSEDED, envelope).
    other: Option<(i64, i64, Vec<u8>)>,
}

fn read_vault(db: &Connection) -> Result<Option<VaultRows>> {
    validate_schema(db)?;
    let mut statement = db
        .prepare(READ_RECORDS)
        .map_err(|_| "Invalid wallet records")?;
    let records: Vec<RecordRow> = statement
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .map_err(|_| "Invalid wallet records")?
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| "Invalid encrypted wallet record")?;
    let mut statement = db
        .prepare(READ_POINTER)
        .map_err(|_| "Invalid wallet pointer")?;
    let pointers: Vec<PointerRow> = statement
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .map_err(|_| "Invalid wallet pointer")?
        .collect::<std::result::Result<_, _>>()
        .map_err(|_| "Invalid wallet pointer")?;
    let mut rows = Vec::new();
    for (slot, state, envelope) in records {
        match (slot, state, envelope) {
            (Some(slot), Some(state), Some(envelope)) => rows.push((slot, state, envelope)),
            _ => return Err("Invalid encrypted wallet record"),
        }
    }
    match pointers.as_slice() {
        [] if rows.is_empty() => Ok(None),
        [(Some(1), Some(active_slot), Some(revision))] => {
            if rows.len() > 2 || rows.iter().filter(|(_, state, _)| *state == ACTIVE).count() != 1 {
                return Err("Unexpected wallet records");
            }
            let active = rows
                .iter()
                .find(|(slot, state, _)| slot == active_slot && *state == ACTIVE)
                .ok_or("Wallet pointer does not name the active record")?
                .2
                .clone();
            let other = rows.into_iter().find(|(slot, _, _)| slot != active_slot);
            if other
                .as_ref()
                .is_some_and(|(_, state, _)| *state != STAGED && *state != SUPERSEDED)
            {
                return Err("Unexpected wallet records");
            }
            Ok(Some(VaultRows {
                revision: *revision,
                active_slot: *active_slot,
                active,
                other,
            }))
        }
        _ => Err("Unexpected wallet records"),
    }
}

/// What the vault holds, as public data (identities are stored beside their ciphertext).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultStatus {
    pub revision: i64,
    pub active: Identity,
    /// A replacement written and verified, not yet active.
    pub staged: Option<Identity>,
    /// The previous identity after a replacement, kept until the person retires it.
    pub superseded: Option<Identity>,
}

fn next_revision(revision: i64) -> Result<i64> {
    revision
        .checked_add(1)
        .filter(|n| *n > 1)
        .ok_or("Wallet revision overflow")
}

/// Why the vault was not opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// Order W7: a retired V1, earlier, newer, foreign or damaged format, or not a plain file; the
    /// file was left exactly as it was.
    Unsupported(crate::custody_format::UnsupportedFormat),
    /// Any other refusal (the closed gate, the file name, the custody ACL, SQLite, the schema).
    Refused(&'static str),
}
impl From<&'static str> for OpenError {
    fn from(reason: &'static str) -> Self {
        Self::Refused(reason)
    }
}
impl From<crate::custody_format::UnsupportedFormat> for OpenError {
    fn from(format: crate::custody_format::UnsupportedFormat) -> Self {
        Self::Unsupported(format)
    }
}
impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported(format) => format.fmt(f),
            Self::Refused(reason) => f.write_str(reason),
        }
    }
}

pub struct Store {
    connection: Connection,
    // Field drop order keeps path identities pinned until SQLite closes.
    _lease: Option<crate::custody_acl_v2::Lease>,
}
impl Store {
    /// Open (creating it when absent) the vault at `path`, the allow-listed file of a custody folder.
    /// Order W7: the file's format is decided FIRST (`custody_format::check_store`), before the
    /// custody lease or SQLite could touch it; a retired V1, earlier, newer, foreign or damaged file
    /// is refused with its typed reason and left exactly as it was.
    pub fn open(path: &Path) -> std::result::Result<Self, OpenError> {
        ready()?;
        if path.file_name().and_then(|s| s.to_str()) != Some(FILE_NAME) {
            return Err("V2 custody requires its dedicated database filename".into());
        }
        crate::custody_format::check_store(path, crate::custody_format::StoreKind::Vault)?;
        if path
            .symlink_metadata()
            .is_ok_and(|m| m.file_type().is_symlink())
        {
            return Err("Wallet database must not be a symbolic link".into());
        }
        let lease = crate::custody_acl_v2::prepare(path)?;
        let connection = Connection::open(path).map_err(|_| "Cannot open V2 wallet database")?;
        let mut store = Self::initialize(connection)?;
        store._lease = Some(lease);
        Ok(store)
    }
    fn initialize(connection: Connection) -> Result<Self> {
        let app: i64 = connection
            .query_row("PRAGMA application_id", [], |r| r.get(0))
            .map_err(|_| "Invalid wallet database")?;
        let version: i64 = connection
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .map_err(|_| "Invalid wallet database")?;
        let tables: i64 = connection
            .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
            .map_err(|_| "Invalid wallet schema")?;
        if app == APP_ID && version == 2 {
            return Err("Wallet format 2 is not opened by this build; automatic migration is prohibited");
        }
        if !((app == 0 && version == 0 && tables == 0) || (app == APP_ID && version == VERSION)) {
            return Err("Unknown wallet database; automatic migration is prohibited");
        }
        connection
            .execute_batch(
                "PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
            PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON; PRAGMA temp_store=MEMORY;",
            )
            .map_err(|_| "Cannot configure durable wallet storage")?;
        if app == 0 {
            connection
                .execute_batch(&format!(
                    "BEGIN IMMEDIATE; {RECORDS_SQL}; {POINTER_SQL};
                PRAGMA application_id=1297430578; PRAGMA user_version=3; COMMIT;"
                ))
                .map_err(|_| "Cannot initialize V2 wallet schema")?;
        }
        validate_schema(&connection)?;
        Ok(Self {
            connection,
            _lease: None,
        })
    }
    pub fn save_initial(&mut self, session: &Session, password: &str) -> Result<()> {
        let envelope = session.seal(password)?;
        // Read back through both authenticated encryption layers before custody
        // is committed. A wrong password/provider error cannot create a vault.
        if Session::unlock(&envelope, password)?.identity() != session.identity() {
            return Err("Wallet encryption readback mismatch");
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "Wallet storage busy")?;
        if read_vault(&tx)?.is_some() {
            return Err("Wallet already exists");
        }
        tx.execute(
            "INSERT INTO vault_records VALUES(1,?1,?2)",
            params![ACTIVE, envelope],
        )
        .map_err(|_| "Wallet already exists or durable write failed")?;
        tx.execute("INSERT INTO vault_pointer VALUES(1,1,1)", [])
            .map_err(|_| "Wallet already exists or durable write failed")?;
        tx.commit().map_err(|_| "Durable wallet commit failed")?;
        Ok(())
    }
    /// Open the ACTIVE identity; returns it with the vault's current revision.
    pub fn unlock(&self, password: &str) -> Result<(Session, i64)> {
        let (revision, raw) = self.read()?.ok_or("No V2 wallet exists")?;
        Ok((Session::unlock(&raw, password)?, revision))
    }
    /// The revision and envelope of the active record.
    fn read(&self) -> Result<Option<(i64, Vec<u8>)>> {
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(|_| "Wallet storage busy")?;
        Ok(read_vault(&tx)?.map(|rows| (rows.revision, rows.active)))
    }
    /// Test hook (Order W16 review, M13b): replace the envelope of the record in `state` (1 active,
    /// 2 staged, 3 superseded) without any check, to model a damaged or edited vault.
    #[cfg(test)]
    pub(crate) fn replace_envelope_for_test(&self, state: i64, envelope: &[u8]) {
        let changed = self
            .connection
            .execute(
                "UPDATE vault_records SET envelope=?1 WHERE state=?2",
                params![envelope, state],
            )
            .unwrap();
        assert_eq!(changed, 1);
    }
    /// The vault's public status: revision and the identities of its records.
    pub fn status(&self) -> Result<Option<VaultStatus>> {
        let tx = self
            .connection
            .unchecked_transaction()
            .map_err(|_| "Wallet storage busy")?;
        let Some(rows) = read_vault(&tx)? else {
            return Ok(None);
        };
        let other = match &rows.other {
            Some((_, state, envelope)) => Some((*state, envelope_identity(envelope)?)),
            None => None,
        };
        Ok(Some(VaultStatus {
            revision: rows.revision,
            active: envelope_identity(&rows.active)?,
            staged: other
                .as_ref()
                .filter(|(state, _)| *state == STAGED)
                .map(|(_, identity)| identity.clone()),
            superseded: other
                .filter(|(state, _)| *state == SUPERSEDED)
                .map(|(_, identity)| identity),
        }))
    }
    /// Re-encrypt the same identity with compare-and-replace, not key rotation.
    /// Old password authorization happens inside the exclusive write snapshot.
    /// Refused while a replacement is staged (it is sealed with the old password).
    pub fn change_password(&mut self, expected_revision: i64, old: &str, new: &str) -> Result<i64> {
        ready()?;
        let next = next_revision(expected_revision)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "Wallet storage busy")?;
        let rows = read_vault(&tx)?.ok_or("No V2 wallet exists")?;
        if rows.revision != expected_revision {
            return Err("Wallet changed; unlock again");
        }
        if rows
            .other
            .as_ref()
            .is_some_and(|(_, state, _)| *state == STAGED)
        {
            return Err("Finish or abandon the staged vault replacement first");
        }
        let session = Session::unlock(&rows.active, old)?;
        let envelope = session.seal(new)?;
        if envelope.len() > MAX_VAULT
            || Session::unlock(&envelope, new)?.identity() != session.identity()
        {
            return Err("Wallet re-encryption verification failed");
        }
        let changed = tx
            .execute(
                "UPDATE vault_records SET envelope=?1 WHERE slot=?2 AND state=?3",
                params![envelope, rows.active_slot, ACTIVE],
            )
            .map_err(|_| "Wallet update failed")?;
        let flipped = tx
            .execute(
                "UPDATE vault_pointer SET revision=?1 WHERE id=1 AND revision=?2",
                params![next, expected_revision],
            )
            .map_err(|_| "Wallet update failed")?;
        if changed != 1 || flipped != 1 {
            return Err("Wallet revision changed");
        }
        tx.commit().map_err(|_| "Durable wallet commit failed")?;
        Ok(next)
    }
    /// Replacement step 1: seal `replacement` (the NEXT generation of the active identity's
    /// authority) with the vault password, read it back through both layers, and write it next to
    /// the active record. The active record and the pointer's target are untouched.
    pub fn stage_replacement(
        &mut self,
        expected_revision: i64,
        password: &str,
        replacement: &Session,
    ) -> Result<i64> {
        ready()?;
        let next = next_revision(expected_revision)?;
        let envelope = replacement.seal(password)?;
        if Session::unlock(&envelope, password)?.identity() != replacement.identity() {
            return Err("Wallet encryption readback mismatch");
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "Wallet storage busy")?;
        let rows = read_vault(&tx)?.ok_or("No V2 wallet exists")?;
        if rows.revision != expected_revision {
            return Err("Wallet changed; unlock again");
        }
        match &rows.other {
            Some((_, STAGED, _)) => return Err("A vault replacement is already staged"),
            Some(_) => return Err("Retire the previous identity before another replacement"),
            None => {}
        }
        // The vault password authorizes the step: it must open the active record.
        let active = Session::unlock(&rows.active, password)?;
        check_successor(active.identity(), replacement.identity())?;
        let slot = 3 - rows.active_slot;
        tx.execute(
            "INSERT INTO vault_records VALUES(?1,?2,?3)",
            params![slot, STAGED, envelope],
        )
        .map_err(|_| "Durable wallet write failed")?;
        let flipped = tx
            .execute(
                "UPDATE vault_pointer SET revision=?1 WHERE id=1 AND revision=?2",
                params![next, expected_revision],
            )
            .map_err(|_| "Wallet update failed")?;
        if flipped != 1 {
            return Err("Wallet revision changed");
        }
        crate::custody_seal::crash_point("vault-stage-before-commit");
        tx.commit().map_err(|_| "Durable wallet commit failed")?;
        crate::custody_seal::crash_point("vault-stage-after-commit");
        Ok(next)
    }
    /// Replacement step 2: read the staged record back from disk, open it through both layers
    /// with the vault password, check it is exactly `expected_descriptor` (hex: the descriptor the
    /// verified chain now records as current) of the next generation of the active authority, and
    /// only then flip the pointer to it. The previous record is kept, marked superseded.
    pub fn activate_replacement(
        &mut self,
        expected_revision: i64,
        password: &str,
        expected_descriptor: &str,
    ) -> Result<i64> {
        ready()?;
        let next = next_revision(expected_revision)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "Wallet storage busy")?;
        let rows = read_vault(&tx)?.ok_or("No V2 wallet exists")?;
        if rows.revision != expected_revision {
            return Err("Wallet changed; unlock again");
        }
        let Some((slot, STAGED, staged)) = &rows.other else {
            return Err("No vault replacement is staged");
        };
        let active = Session::unlock(&rows.active, password)?;
        let replacement = Session::unlock(staged, password)?;
        check_successor(active.identity(), replacement.identity())?;
        if replacement.identity().owner_descriptor != expected_descriptor {
            return Err("The staged identity is not the confirmed new key");
        }
        drop((active, replacement));
        let superseded = tx
            .execute(
                "UPDATE vault_records SET state=?1 WHERE slot=?2 AND state=?3",
                params![SUPERSEDED, rows.active_slot, ACTIVE],
            )
            .map_err(|_| "Wallet update failed")?;
        let activated = tx
            .execute(
                "UPDATE vault_records SET state=?1 WHERE slot=?2 AND state=?3",
                params![ACTIVE, slot, STAGED],
            )
            .map_err(|_| "Wallet update failed")?;
        // The single durable pointer.
        let flipped = tx
            .execute(
                "UPDATE vault_pointer SET active=?1, revision=?2 WHERE id=1 AND active=?3 AND revision=?4",
                params![slot, next, rows.active_slot, expected_revision],
            )
            .map_err(|_| "Wallet update failed")?;
        if superseded != 1 || activated != 1 || flipped != 1 {
            return Err("Wallet revision changed");
        }
        // The vault after the flip must still satisfy every invariant before anything is committed.
        if read_vault(&tx)?.is_none_or(|after| after.active_slot != *slot) {
            return Err("Wallet pointer flip verification failed");
        }
        crate::custody_seal::crash_point("vault-activate-before-commit");
        tx.commit().map_err(|_| "Durable wallet commit failed")?;
        crate::custody_seal::crash_point("vault-activate-after-commit");
        Ok(next)
    }
    /// Abandon a staged replacement (it never became active); the active record is untouched.
    pub fn abandon_replacement(&mut self, expected_revision: i64, password: &str) -> Result<i64> {
        self.delete_other(expected_revision, password, STAGED, "No vault replacement is staged")
    }
    /// Replacement step 3, the person's explicit act: delete the superseded previous identity.
    /// The controller allows it only once the active identity is the chain's current authority.
    pub fn retire_previous(&mut self, expected_revision: i64, password: &str) -> Result<i64> {
        let next = self.delete_other(
            expected_revision,
            password,
            SUPERSEDED,
            "No previous identity is kept",
        )?;
        Ok(next)
    }
    fn delete_other(
        &mut self,
        expected_revision: i64,
        password: &str,
        state: i64,
        missing: &'static str,
    ) -> Result<i64> {
        ready()?;
        let next = next_revision(expected_revision)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| "Wallet storage busy")?;
        let rows = read_vault(&tx)?.ok_or("No V2 wallet exists")?;
        if rows.revision != expected_revision {
            return Err("Wallet changed; unlock again");
        }
        let Some((slot, found, _)) = &rows.other else {
            return Err(missing);
        };
        if *found != state {
            return Err(missing);
        }
        // The vault password authorizes the deletion.
        drop(Session::unlock(&rows.active, password)?);
        let deleted = tx
            .execute(
                "DELETE FROM vault_records WHERE slot=?1 AND state=?2",
                params![slot, state],
            )
            .map_err(|_| "Wallet update failed")?;
        let flipped = tx
            .execute(
                "UPDATE vault_pointer SET revision=?1 WHERE id=1 AND revision=?2",
                params![next, expected_revision],
            )
            .map_err(|_| "Wallet update failed")?;
        if deleted != 1 || flipped != 1 {
            return Err("Wallet revision changed");
        }
        crate::custody_seal::crash_point("vault-delete-before-commit");
        tx.commit().map_err(|_| "Durable wallet commit failed")?;
        crate::custody_seal::crash_point("vault-delete-after-commit");
        Ok(next)
    }
}

/// A replacement must be the NEXT generation of the SAME wallet authority.
fn check_successor(active: &Identity, replacement: &Identity) -> Result<()> {
    if replacement.authority_id != active.authority_id
        || active.generation.checked_add(1) != Some(replacement.generation)
        || replacement.owner_descriptor == active.owner_descriptor
    {
        return Err("The replacement is not the next generation of this wallet authority");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet_v2::RestoredKey;

    const V2_SQL: &str = "CREATE TABLE vault(id INTEGER PRIMARY KEY CHECK(id=1), revision INTEGER NOT NULL CHECK(revision>=1),
                  envelope BLOB NOT NULL CHECK(length(envelope)>0 AND length(envelope)<=32768))";

    fn initial() -> Session {
        Session::restore_initial(&format!("{}art", "abandon ".repeat(23))).unwrap()
    }
    /// The rotated identity of the all-"abandon" wallet: the all-"zoo" key at generation two.
    fn rotated() -> (Session, String) {
        let authority = hex::decode(&initial().identity().authority_id)
            .unwrap()
            .try_into()
            .unwrap();
        let new = RestoredKey::restore(&format!("{}vote", "zoo ".repeat(23)), 2, None).unwrap();
        let descriptor = new.descriptor().to_vec();
        (
            Session::restore_rotated(new, authority, &descriptor).unwrap(),
            hex::encode(descriptor),
        )
    }

    #[test]
    fn exact_schema_rejects_views_triggers_indexes_and_lookalike_internal_names() {
        let both = format!("{RECORDS_SQL}; {POINTER_SQL};");
        let variants = [
            format!("CREATE VIEW vault_records AS SELECT 1 AS slot,1 AS state,zeroblob(32) AS envelope; {POINTER_SQL};"),
            format!("CREATE TABLE vault_records(slot INTEGER PRIMARY KEY,state INTEGER,envelope BLOB); {POINTER_SQL};"),
            format!("{RECORDS_SQL};"),
            format!("{both} CREATE TABLE sqliteXextra(value BLOB);"),
            format!("{both} CREATE INDEX added ON vault_records(state);"),
            format!(
                "{both} CREATE TRIGGER added AFTER INSERT ON vault_records BEGIN UPDATE vault_pointer SET revision=999; END;"
            ),
        ];
        for sql in variants {
            let db = Connection::open_in_memory().unwrap();
            db.execute_batch(&sql).unwrap();
            db.execute_batch("PRAGMA application_id=1297430578; PRAGMA user_version=3;")
                .unwrap();
            assert!(
                Store::initialize(db).is_err(),
                "accepted unexpected schema: {sql}"
            );
        }
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch("CREATE TABLE sqliteXextra(value BLOB);")
            .unwrap();
        assert!(
            Store::initialize(db).is_err(),
            "lookalike internal names must not be treated as an empty database"
        );
        // A version-2 vault (one record, no pointer) is refused, never migrated.
        let db = Connection::open_in_memory().unwrap();
        db.execute_batch(&format!(
            "{V2_SQL}; PRAGMA application_id=1297430578; PRAGMA user_version=2;"
        ))
        .unwrap();
        assert_eq!(
            Store::initialize(db).err(),
            Some("Wallet format 2 is not opened by this build; automatic migration is prohibited")
        );
    }
    #[test]
    fn corrupted_vault_record_is_bounded_and_never_treated_as_empty() {
        let store = Store::initialize(Connection::open_in_memory().unwrap()).unwrap();
        assert!(store.read().unwrap().is_none());
        store
            .connection
            .execute_batch("PRAGMA ignore_check_constraints=ON;")
            .unwrap();
        for sql in [
            // records without a pointer, a pointer without records
            "INSERT INTO vault_records VALUES(1,1,zeroblob(32));",
            "INSERT INTO vault_pointer VALUES(1,1,1);",
            // bounds and types
            "INSERT INTO vault_records VALUES(1,1,zeroblob(1048576)); INSERT INTO vault_pointer VALUES(1,1,1);",
            "INSERT INTO vault_records VALUES(1,1,'text is not ciphertext blob'); INSERT INTO vault_pointer VALUES(1,1,1);",
            "INSERT INTO vault_records VALUES(3,1,zeroblob(32)); INSERT INTO vault_pointer VALUES(1,3,1);",
            "INSERT INTO vault_records VALUES(1,4,zeroblob(32)); INSERT INTO vault_pointer VALUES(1,1,1);",
            "INSERT INTO vault_records VALUES(1,1,zeroblob(32)); INSERT INTO vault_pointer VALUES(1,1,0);",
            "INSERT INTO vault_records VALUES(1,1,zeroblob(32)); INSERT INTO vault_pointer VALUES(2,1,1);",
            // two active records, or a pointer to a record that is not the active one
            "INSERT INTO vault_records VALUES(1,1,zeroblob(32)),(2,1,zeroblob(32)); INSERT INTO vault_pointer VALUES(1,1,1);",
            "INSERT INTO vault_records VALUES(1,1,zeroblob(32)),(2,2,zeroblob(32)); INSERT INTO vault_pointer VALUES(1,2,1);",
            "INSERT INTO vault_records VALUES(1,3,zeroblob(32)); INSERT INTO vault_pointer VALUES(1,1,1);",
            // two pointers
            "INSERT INTO vault_records VALUES(1,1,zeroblob(32)); INSERT INTO vault_pointer VALUES(1,1,1),(2,1,1);",
        ] {
            store.connection.execute_batch(sql).unwrap();
            assert!(store.read().is_err(), "accepted corrupted vault: {sql}");
            store
                .connection
                .execute_batch("DELETE FROM vault_records; DELETE FROM vault_pointer;")
                .unwrap();
        }
        store
            .connection
            .execute_batch(
                "INSERT INTO vault_records VALUES(1,1,zeroblob(32)),(2,2,zeroblob(32)); INSERT INTO vault_pointer VALUES(1,1,1);",
            )
            .unwrap();
        assert_eq!(store.read().unwrap().unwrap().0, 1);
        // Even a schema change after construction is rejected before custody use.
        store
            .connection
            .execute_batch(
                "CREATE TRIGGER later AFTER UPDATE ON vault_pointer BEGIN DELETE FROM vault_records; END;",
            )
            .unwrap();
        assert!(store.read().is_err());
    }
    /// Order W10: the vault keeps SQLite's temporary files (statement journals, sorts) in memory, so
    /// nothing of it is written to the user's temporary folder outside the custody ACL.
    #[test]
    fn the_vault_keeps_sqlite_temporary_files_in_memory() {
        let store = Store::initialize(Connection::open_in_memory().unwrap()).unwrap();
        let temp_store: i64 = store
            .connection
            .query_row("PRAGMA temp_store", [], |row| row.get(0))
            .unwrap();
        assert_eq!(temp_store, 2, "temp_store=MEMORY");
    }
    #[test]
    fn crash_child_after_uncommitted_write() {
        let Some(raw) = std::env::var_os("BUILD8_V2_PUBLIC_CRASH_FIXTURE") else {
            return;
        };
        let path = std::path::PathBuf::from(raw);
        let parent = path.parent().unwrap().parent().unwrap();
        assert!(
            parent
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("build8-v2-vault-crash-")
        );
        assert!(
            parent
                .canonicalize()
                .unwrap()
                .starts_with(std::env::temp_dir().canonicalize().unwrap())
        );
        let store = Store::open(&path).unwrap();
        // Force a hot rollback journal without exporting or decrypting custody.
        // process::exit deliberately skips Rust/SQLite connection destructors.
        store.connection.execute_batch("PRAGMA cache_size=1; PRAGMA cache_spill=ON; BEGIN IMMEDIATE; UPDATE vault_records SET envelope=zeroblob(32000) WHERE slot=1; UPDATE vault_pointer SET revision=2 WHERE id=1;").unwrap();
        let journal = path.with_file_name("wallet-hybrid-v2.sqlite-journal");
        assert!(journal.metadata().unwrap().len() > 512);
        std::process::exit(91);
    }
    #[test]
    fn filesystem_reopen_recovers_uncommitted_process_crash() {
        let mut nonce = [0; 16];
        mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
        let directory =
            std::env::temp_dir().join(format!("build8-v2-vault-crash-{}", hex::encode(nonce)));
        std::fs::create_dir(&directory).unwrap();
        let custody = directory.join("WalletCustodyV2");
        let path = custody.join("wallet-hybrid-v2.sqlite");
        let mut store = Store::open(&path).unwrap();
        let session = initial();
        let identity = session.identity().clone();
        store
            .save_initial(&session, "PUBLIC CRASH TEST PASSWORD")
            .unwrap();
        drop(session);
        drop(store);
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "store_v2::tests::crash_child_after_uncommitted_write",
                "--nocapture",
            ])
            .env("BUILD8_V2_PUBLIC_CRASH_FIXTURE", &path)
            .output()
            .unwrap();
        assert_eq!(
            result.status.code(),
            Some(91),
            "child failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        // Order W7 (review F1): a genuine current-format vault with its OWN hot journal (the child's
        // write spilled, so SQLite wrote the journal's header) passes the format check, whose schema
        // verification reads the main file read-only and immutable; then SQLite recovers it.
        let hot = custody.join("wallet-hybrid-v2.sqlite-journal");
        assert!(std::fs::read(&hot).unwrap()[..8].iter().any(|b| *b != 0), "a hot journal");
        assert_eq!(
            crate::custody_format::check_store(&path, crate::custody_format::StoreKind::Vault),
            Ok(crate::custody_format::Found::Current)
        );
        let mut reopened = Store::open(&path).unwrap();
        let (session, revision) = reopened.unlock("PUBLIC CRASH TEST PASSWORD").unwrap();
        assert_eq!(revision, 1);
        assert_eq!(session.identity(), &identity);
        drop(session);
        reopened
            .change_password(1, "PUBLIC CRASH TEST PASSWORD", "PUBLIC COMMITTED PASSWORD")
            .unwrap();
        drop(reopened);
        let reopened = Store::open(&path).unwrap();
        assert!(reopened.unlock("PUBLIC CRASH TEST PASSWORD").is_err());
        assert_eq!(reopened.unlock("PUBLIC COMMITTED PASSWORD").unwrap().1, 2);
        drop(reopened);
        std::fs::remove_file(&path).unwrap();
        let journal = custody.join("wallet-hybrid-v2.sqlite-journal");
        if journal.exists() {
            std::fs::remove_file(journal).unwrap();
        }
        std::fs::remove_dir(custody).unwrap();
        std::fs::remove_dir(directory).unwrap();
    }
    #[test]
    fn dedicated_vault_password_cas_and_failed_update_preserve_custody() {
        let mut store = Store::initialize(Connection::open_in_memory().unwrap()).unwrap();
        assert!(store.unlock("PUBLIC OLD PASSWORD").is_err());
        let session = initial();
        let identity = session.identity().clone();
        store.save_initial(&session, "PUBLIC OLD PASSWORD").unwrap();
        assert!(
            store
                .save_initial(&session, "PUBLIC OTHER PASSWORD")
                .is_err()
        );
        drop(session);
        assert_eq!(
            store.unlock("PUBLIC OLD PASSWORD").unwrap().0.identity(),
            &identity
        );
        assert!(
            store
                .change_password(2, "PUBLIC OLD PASSWORD", "PUBLIC NEW PASSWORD")
                .is_err()
        );
        assert!(
            store
                .change_password(1, "WRONG PASSWORD", "PUBLIC NEW PASSWORD")
                .is_err()
        );
        assert_eq!(store.unlock("PUBLIC OLD PASSWORD").unwrap().1, 1);
        assert_eq!(
            store
                .change_password(1, "PUBLIC OLD PASSWORD", "PUBLIC NEW PASSWORD")
                .unwrap(),
            2
        );
        assert!(store.unlock("PUBLIC OLD PASSWORD").is_err());
        assert_eq!(
            store.unlock("PUBLIC NEW PASSWORD").unwrap().0.identity(),
            &identity
        );
        assert!(
            store
                .change_password(1, "PUBLIC NEW PASSWORD", "PUBLIC THIRD PASSWORD")
                .is_err()
        );
        let Store { connection, .. } = store;
        let reopened = Store::initialize(connection).unwrap();
        assert_eq!(reopened.unlock("PUBLIC NEW PASSWORD").unwrap().1, 2);
        let legacy = Connection::open_in_memory().unwrap();
        legacy
            .execute_batch("CREATE TABLE wallet(id INTEGER);")
            .unwrap();
        assert!(Store::initialize(legacy).is_err());
        // The retired V1 file name is never the vault's.
        assert_eq!(
            Store::open(Path::new("wallet.sqlite")).err(),
            Some(OpenError::Refused("V2 custody requires its dedicated database filename"))
        );
    }

    /// Stage, verify, flip, keep, retire: after a replacement the vault holds the NEW identity and
    /// still the old one until the explicit retirement; every step needs the password and the
    /// current revision, and nothing but the next generation of the same authority is accepted.
    #[test]
    fn the_vault_replacement_stages_flips_one_pointer_and_keeps_the_old_record() {
        const PASSWORD: &str = "PUBLIC REPLACEMENT PASSWORD";
        let mut store = Store::initialize(Connection::open_in_memory().unwrap()).unwrap();
        let old = initial();
        let old_identity = old.identity().clone();
        store.save_initial(&old, PASSWORD).unwrap();
        let (new, descriptor) = rotated();
        let new_identity = new.identity().clone();
        assert_eq!(new_identity.generation, 2);
        assert_eq!(new_identity.authority_id, old_identity.authority_id);
        // Refusals of step 1: stale revision, wrong password, not the next generation of the same
        // authority (the old identity itself; another wallet's identity).
        assert!(store.stage_replacement(2, PASSWORD, &new).is_err());
        assert!(store.stage_replacement(1, "WRONG PASSWORD", &new).is_err());
        assert!(store.stage_replacement(1, PASSWORD, &old).is_err());
        let stranger =
            Session::restore_initial(&format!("{}vote", "zoo ".repeat(23))).unwrap();
        assert!(store.stage_replacement(1, PASSWORD, &stranger).is_err());
        assert!(store.activate_replacement(1, PASSWORD, &descriptor).is_err());
        assert_eq!(store.status().unwrap().unwrap().staged, None);
        // Step 1: staged next to the active record, which is still what unlock opens.
        let staged = store.stage_replacement(1, PASSWORD, &new).unwrap();
        assert_eq!(staged, 2);
        let status = store.status().unwrap().unwrap();
        assert_eq!(status.active, old_identity);
        assert_eq!(status.staged.as_ref(), Some(&new_identity));
        assert_eq!(store.unlock(PASSWORD).unwrap().0.identity(), &old_identity);
        assert!(store.stage_replacement(2, PASSWORD, &new).is_err(), "one staged record");
        assert!(store.change_password(2, PASSWORD, "OTHER").is_err());
        // Step 2: the flip needs the confirmed descriptor, the password and the revision.
        assert!(store.activate_replacement(2, PASSWORD, &old_identity.owner_descriptor).is_err());
        assert!(store.activate_replacement(2, "WRONG PASSWORD", &descriptor).is_err());
        assert!(store.activate_replacement(1, PASSWORD, &descriptor).is_err());
        assert_eq!(store.unlock(PASSWORD).unwrap().0.identity(), &old_identity);
        let flipped = store.activate_replacement(2, PASSWORD, &descriptor).unwrap();
        assert_eq!(flipped, 3);
        let status = store.status().unwrap().unwrap();
        assert_eq!(status.active, new_identity);
        assert_eq!(status.superseded.as_ref(), Some(&old_identity));
        assert_eq!(store.unlock(PASSWORD).unwrap().0.identity(), &new_identity);
        // The old record is kept: no further replacement before it is retired.
        let (other, _) = rotated();
        assert!(store.stage_replacement(3, PASSWORD, &other).is_err());
        assert!(store.abandon_replacement(3, PASSWORD).is_err(), "nothing staged");
        // Step 3: the explicit retirement.
        assert!(store.retire_previous(3, "WRONG PASSWORD").is_err());
        assert_eq!(store.retire_previous(3, PASSWORD).unwrap(), 4);
        let status = store.status().unwrap().unwrap();
        assert_eq!((status.superseded, status.staged), (None, None));
        assert_eq!(store.unlock(PASSWORD).unwrap().1, 4);
        assert!(store.retire_previous(4, PASSWORD).is_err());
        // A staged replacement can be abandoned instead; the active record stays.
        let mut store = Store::initialize(Connection::open_in_memory().unwrap()).unwrap();
        store.save_initial(&initial(), PASSWORD).unwrap();
        store.stage_replacement(1, PASSWORD, &new).unwrap();
        assert!(store.abandon_replacement(2, "WRONG PASSWORD").is_err());
        assert_eq!(store.abandon_replacement(2, PASSWORD).unwrap(), 3);
        let status = store.status().unwrap().unwrap();
        assert_eq!((status.active, status.staged), (old_identity, None));
    }

    /// The crash child: perform the replacement up to the step the parent names and end the
    /// process at the crash point it names (skipping every destructor, as a process crash would).
    #[test]
    fn vault_replacement_crash_child() {
        let Some(raw) = std::env::var_os("BUILD8_W7_VAULT_CHILD") else {
            return;
        };
        let path = std::path::PathBuf::from(raw);
        let base = path.parent().unwrap().parent().unwrap();
        assert_eq!(base.parent(), Some(std::env::temp_dir().as_path()));
        assert!(
            base.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("build8-wallet-core-w7-vault-crash-")
        );
        const PASSWORD: &str = "PUBLIC REPLACEMENT PASSWORD";
        let mut store = Store::open(&path).unwrap();
        let (new, descriptor) = rotated();
        let step = std::env::var("BUILD8_W7_VAULT_STEP").unwrap();
        let revision = store.status().unwrap().unwrap().revision;
        match step.as_str() {
            "stage" => drop(store.stage_replacement(revision, PASSWORD, &new)),
            "activate" => drop(store.activate_replacement(revision, PASSWORD, &descriptor)),
            "retire" => drop(store.retire_previous(revision, PASSWORD)),
            other => panic!("unknown step {other}"),
        }
        std::process::exit(98);
    }

    /// Kill the process inside and right after each step and reopen: the vault is always at the
    /// last commit, its invariants hold, and unlock opens exactly the identity the pointer names.
    #[test]
    fn the_vault_replacement_is_crash_safe_at_every_step() {
        const PASSWORD: &str = "PUBLIC REPLACEMENT PASSWORD";
        let old = initial().identity().clone();
        let new = rotated().0.identity().clone();
        // (steps to complete first, step to crash in, crash point, expected (active, staged, superseded))
        type Case<'a> = (&'a [&'a str], &'a str, &'a str, (&'a Identity, bool, bool));
        let cases: [Case<'_>; 6] = [
            (&[], "stage", "vault-stage-before-commit", (&old, false, false)),
            (&[], "stage", "vault-stage-after-commit", (&old, true, false)),
            (&["stage"], "activate", "vault-activate-before-commit", (&old, true, false)),
            (&["stage"], "activate", "vault-activate-after-commit", (&new, false, true)),
            (&["stage", "activate"], "retire", "vault-delete-before-commit", (&new, false, true)),
            (&["stage", "activate"], "retire", "vault-delete-after-commit", (&new, false, false)),
        ];
        for (done, step, point, (active, staged, superseded)) in cases {
            let base = crate::test_support::TestDir::new("w7-vault-crash");
            let path = crate::test_support::custody_file(&base, "wallet-hybrid-v2.sqlite");
            let mut store = Store::open(&path).unwrap();
            store.save_initial(&initial(), PASSWORD).unwrap();
            let (replacement, descriptor) = rotated();
            for previous in done {
                let revision = store.status().unwrap().unwrap().revision;
                match *previous {
                    "stage" => store.stage_replacement(revision, PASSWORD, &replacement).unwrap(),
                    "activate" => store.activate_replacement(revision, PASSWORD, &descriptor).unwrap(),
                    _ => unreachable!(),
                };
            }
            let before = store.status().unwrap().unwrap().revision;
            drop(store);
            let output = crate::test_support::run_child(
                "store_v2::tests::vault_replacement_crash_child",
                &[
                    ("BUILD8_W7_VAULT_CHILD", path.as_os_str()),
                    ("BUILD8_W7_VAULT_STEP", std::ffi::OsStr::new(step)),
                    ("BUILD8_W7_CRASH_POINT", std::ffi::OsStr::new(point)),
                ],
            );
            assert_eq!(
                output.status.code(),
                Some(97),
                "child ({step} {point}) failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            let store = Store::open(&path).unwrap();
            let status = store.status().unwrap().unwrap();
            assert_eq!(&status.active, active, "{point}: active");
            assert_eq!(status.staged.is_some(), staged, "{point}: staged");
            assert_eq!(status.superseded.is_some(), superseded, "{point}: superseded");
            let committed = point.ends_with("after-commit");
            assert_eq!(
                status.revision,
                if committed { before + 1 } else { before },
                "{point}: revision"
            );
            assert_eq!(store.unlock(PASSWORD).unwrap().0.identity(), active, "{point}");
        }
    }
}
