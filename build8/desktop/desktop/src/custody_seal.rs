//! Protection at rest for the desktop stores that live next to the vault in the custody directory
//! (the operation outbox and the preimage store), and the strict byte encoding they share.
//!
//! Every stored value is SEALED with Windows DPAPI (CurrentUser scope, `dpapi_v2`) under a BINDING
//! (DPAPI "optional entropy") that names the store, the field, the file and the record:
//! `SHA-512(domain || 0 || each part length-prefixed)`. DPAPI authenticates what it seals, so a
//! changed byte is refused, and a sealed value moved to another record, another field, another file
//! or another store does not open, because its binding differs.
//!
//! What this protects, and what it does not (stated again in desktop/docs/PHASE-7-DESKTOP.md):
//!  * protected: the files read by another Windows account (the custody directory ACL already
//!    denies it), copied off the machine (disk image, backup, synchronised folder) or edited; the
//!    DPAPI master key needs the account's logon secret;
//!  * NOT protected: any process running as the same Windows user (it can ask DPAPI to unseal),
//!    administrators and SYSTEM, the process memory while the wallet runs, the deletion of a row or
//!    of a whole file, and the replacement of a file by an older copy of itself (rollback).
//!
//! No value is derived from a wallet key or phrase; no key reaches this module.
use mutiny_consensus_v8::Hash;
use rusqlite::Connection;
use sha2::{Digest, Sha512};
use zeroize::Zeroizing;

/// Largest value one DPAPI call accepts (the bound of `dpapi_v2`).
pub(crate) const MAX_SEALED_INPUT: usize = 65536;

/// `SHA-512(domain || 0 || len(part) || part ...)`: the DPAPI binding of one stored value. Every part
/// is length-prefixed, so no two different part lists share a binding.
pub(crate) fn binding(domain: &[u8], parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(domain);
    h.update([0]);
    for part in parts {
        h.update((part.len() as u32).to_be_bytes());
        h.update(part);
    }
    h.finalize().into()
}

/// Seal `plain` under `binding`. Refuses an empty or oversized value before any Windows call.
pub(crate) fn seal(plain: &[u8], binding: &[u8; 64]) -> Result<Vec<u8>, &'static str> {
    if plain.is_empty() || plain.len() > MAX_SEALED_INPUT {
        return Err("value to seal exceeds its bound");
    }
    crate::dpapi_v2::dpapi(plain, binding, true).map(|sealed| sealed.to_vec())
}

/// Open a value sealed under `binding`. Any damage, another binding or another Windows account is
/// refused; nothing is ever partially opened.
pub(crate) fn open(sealed: &[u8], binding: &[u8; 64]) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    crate::dpapi_v2::dpapi(sealed, binding, false)
}

/// 32 fresh bytes from the operating system (no fallback: an entropy failure is an error).
pub(crate) fn random32() -> Result<Zeroizing<[u8; 32]>, &'static str> {
    let mut out = Zeroizing::new([0u8; 32]);
    mutiny_crypto_v2::fill_os_random(out.as_mut()).map_err(|_| "operating-system randomness unavailable")?;
    Ok(out)
}

/// Durable-storage settings shared by the custody stores: rollback journal on disk (a crash leaves
/// the file at the last commit), full synchronisation (a commit returns only after the data is on
/// disk), deleted content overwritten, no schema-defined code, and (Order W10, candidate 3) SQLite's
/// temporary files (statement journals, sorts, transient indices) kept in MEMORY, so no SQLite
/// temporary file is ever written to the user's temporary folder, outside the custody folder's ACL
/// (it could only hold sealed values: nothing reaches SQLite unsealed).
pub(crate) fn configure(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "PRAGMA trusted_schema=OFF; PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON; PRAGMA temp_store=MEMORY;",
    )
}

/// Exact-schema check: the application id, the version and the SQL of every table must be exactly
/// the expected ones and no other object may exist (only the indexes SQLite creates itself for
/// PRIMARY KEY and UNIQUE constraints, which have no SQL text, are skipped); then SQLite's
/// `quick_check` must pass.
pub(crate) fn schema_is_exact(
    db: &Connection,
    application_id: i64,
    version: i64,
    schema: &[(&str, &str)],
) -> rusqlite::Result<bool> {
    if !schema_matches(db, application_id, version, schema)? {
        return Ok(false);
    }
    let check: String = db.query_row("PRAGMA quick_check(1)", [], |row| row.get(0))?;
    Ok(check == "ok")
}

/// The schema part of [`schema_is_exact`] without `quick_check`: what `custody_format` verifies
/// through a read-only, immutable connection before anything opens a file for writing (a hot
/// journal may lie beside it, so the main file may be mid-transaction).
pub(crate) fn schema_matches(
    db: &Connection,
    application_id: i64,
    version: i64,
    schema: &[(&str, &str)],
) -> rusqlite::Result<bool> {
    let application: i64 = db.query_row("PRAGMA application_id", [], |row| row.get(0))?;
    let found_version: i64 = db.query_row("PRAGMA user_version", [], |row| row.get(0))?;
    if application != application_id || found_version != version {
        return Ok(false);
    }
    let mut statement = db.prepare(
        "SELECT type,name,sql FROM sqlite_master WHERE NOT (type='index' AND sql IS NULL AND name GLOB 'sqlite_autoindex_*') ORDER BY name",
    )?;
    let found: Vec<(String, String, Option<String>)> = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<_, _>>()?;
    let mut expected: Vec<(String, String, Option<String>)> = schema
        .iter()
        .map(|(name, sql)| ("table".to_string(), (*name).to_string(), Some((*sql).to_string())))
        .collect();
    expected.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(found == expected)
}

/// Test-only crash hook: when the environment names this point, the process ends at once, skipping
/// every destructor (no clean close of SQLite, no rollback by the program), as a process crash
/// would. It is not a power cut: the operating system still writes back what it has cached.
#[cfg(test)]
pub(crate) fn crash_point(name: &str) {
    if std::env::var("BUILD8_W7_CRASH_POINT").as_deref() == Ok(name) {
        std::process::exit(97);
    }
}
#[cfg(not(test))]
#[inline(always)]
pub(crate) fn crash_point(_: &str) {}

/// Strict big-endian writer for the sealed record encodings.
#[derive(Default)]
pub(crate) struct Writer(Zeroizing<Vec<u8>>);

impl Writer {
    pub(crate) fn u8(&mut self, value: u8) -> &mut Self {
        self.0.push(value);
        self
    }
    pub(crate) fn u16(&mut self, value: u16) -> &mut Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }
    pub(crate) fn u32(&mut self, value: u32) -> &mut Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }
    pub(crate) fn u64(&mut self, value: u64) -> &mut Self {
        self.0.extend_from_slice(&value.to_be_bytes());
        self
    }
    pub(crate) fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.0.extend_from_slice(value);
        self
    }
    pub(crate) fn finish(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

/// Strict reader: every read is bounds-checked and [`Reader::finish`] refuses trailing bytes.
pub(crate) struct Reader<'a> {
    raw: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(raw: &'a [u8]) -> Self {
        Self { raw, at: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(n)?;
        let out = self.raw.get(self.at..end)?;
        self.at = end;
        Some(out)
    }
    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    pub(crate) fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    pub(crate) fn u32(&mut self) -> Option<u32> {
        self.take(4).and_then(|b| b.try_into().ok()).map(u32::from_be_bytes)
    }
    pub(crate) fn u64(&mut self) -> Option<u64> {
        self.take(8).and_then(|b| b.try_into().ok()).map(u64::from_be_bytes)
    }
    pub(crate) fn hash(&mut self) -> Option<Hash> {
        self.take(32).and_then(|b| b.try_into().ok())
    }
    pub(crate) fn bool(&mut self) -> Option<bool> {
        match self.u8()? {
            0 => Some(false),
            1 => Some(true),
            _ => None,
        }
    }
    pub(crate) fn finish(&self) -> Option<()> {
        (self.at == self.raw.len()).then_some(())
    }
}
