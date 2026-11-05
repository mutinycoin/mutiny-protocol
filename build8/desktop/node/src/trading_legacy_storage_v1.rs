//! Candidate-only encrypted SQLite persistence for existing trade journals.
//! All keys are local data keys; this module has no signing/network capability.
//! A caller must protect checkpoints independently. Coherent rollback of both
//! files and the caller checkpoint remains a production custody gate.
use super::*;
use std::sync::Arc;

const LEGACY_NS: &[u8] = b"MUTINY-OFFLINE-ENCRYPTED-JOURNAL-V2";
const SNAP_MAX: usize = 128 * 1024 * 1024;
const CHUNK: usize = 128 * 1024;
const MAX_NONCE: u64 = (i64::MAX as u64) / 2;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalKind {
    BitcoinEngine = 1,
    BitcoinSigner = 2,
    Recovery = 3,
    Blocks = 4,
}
#[derive(Clone, Debug)]
pub struct Paths {
    pub snapshot: std::path::PathBuf,
    pub nonces: std::path::PathBuf,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurableCheckpoint {
    pub generation: u64,
    pub commitment: Hash,
    pub nonce_counter: u64,
    pub prefix: [u8; 16],
}
fn context(c: &StorageContext, kind: JournalKind) -> Result<Vec<u8>> {
    if c.key_generation == 0 || c.storage == [0; 32] {
        return Err(Error::Context);
    }
    let mut e = Encoder::new(Vec::new());
    e.array(8)
        .unwrap()
        .bytes(LEGACY_NS)
        .unwrap()
        .u8(1)
        .unwrap()
        .u8(kind as u8)
        .unwrap()
        .u32(c.network)
        .unwrap()
        .bytes(&c.genesis)
        .unwrap()
        .bytes(&c.fingerprint)
        .unwrap()
        .bytes(&c.storage)
        .unwrap()
        .u64(c.key_generation)
        .unwrap();
    Ok(e.into_writer())
}
fn digest(label: &[u8], raw: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(LEGACY_NS);
    h.update([0]);
    h.update(label);
    h.update([0]);
    h.update(raw);
    h.finalize().into()
}
fn nonce(prefix: [u8; 16], counter: u64, data: bool) -> Result<[u8; 24]> {
    if counter > MAX_NONCE {
        return Err(Error::Bounds);
    }
    let mut out = [0; 24];
    out[..16].copy_from_slice(&prefix);
    out[16..].copy_from_slice(&(counter * 2 + u64::from(data)).to_be_bytes());
    Ok(out)
}
fn crypt(
    key: &StorageKey,
    nonce: &[u8; 24],
    ad: &[u8],
    input: &[u8],
    encrypt: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    if input.len() > CHUNK + 1024 {
        return Err(Error::Bounds);
    }
    let mut b = Zeroizing::new(Vec::with_capacity(input.len() + 16));
    b.extend_from_slice(input);
    let cipher = XChaCha20Poly1305::new_from_slice(key.0.as_ref()).map_err(|_| Error::Crypto)?;
    if encrypt {
        cipher.encrypt_in_place(XNonce::from_slice(nonce), ad, &mut *b)
    } else {
        cipher.decrypt_in_place(XNonce::from_slice(nonce), ad, &mut *b)
    }
    .map_err(|_| Error::Crypto)?;
    Ok(b)
}
fn associated(context: &[u8], class: u8, counter: u64) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .bytes(context)
        .unwrap()
        .u8(class)
        .unwrap()
        .u64(counter)
        .unwrap();
    e.into_writer()
}
fn file_bound(path: &Path) -> Result<()> {
    for p in [
        path.to_path_buf(),
        std::path::PathBuf::from(format!("{}-wal", path.display())),
    ] {
        match std::fs::metadata(p) {
            Ok(m) if m.len() > 4 * SNAP_MAX as u64 => return Err(Error::Bounds),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(Error::Store),
        }
    }
    Ok(())
}
fn connection(path: &Path, create: bool) -> Result<Connection> {
    file_bound(path)?;
    if create && path.exists() {
        return Err(Error::Store);
    }
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX
        | if create {
            OpenFlags::SQLITE_OPEN_CREATE
        } else {
            OpenFlags::empty()
        };
    let c = db(Connection::open_with_flags(path, flags))?;
    db(c.busy_timeout(std::time::Duration::from_secs(2)))?;
    db(c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY;"))?;
    Ok(c)
}
fn integrity(c: &Connection) -> Result<()> {
    let s: String = db(c.query_row("PRAGMA quick_check", [], |r| r.get(0)))?;
    if s != "ok" {
        return Err(Error::Corrupt);
    }
    Ok(())
}

/// Durable ordinals precede encryption but are NOT rollback-proof nonce allocation.
/// Deterministic even suffixes authenticate only the identical empty ledger statement.
/// Data encryption uses the reviewed parent seal() with fresh OS-random XChaCha nonces.
/// Replaying a ledger does not supply any data-encryption nonce.
struct Nonces {
    db: Connection,
    key: Arc<StorageKey>,
    context: Vec<u8>,
    prefix: [u8; 16],
    counter: u64,
    poisoned: bool,
}
impl Nonces {
    fn create(path: &Path, key: Arc<StorageKey>, context: Vec<u8>) -> Result<Self> {
        let c = connection(path, true)?;
        db(c.execute_batch("CREATE TABLE nonce_head(id INTEGER PRIMARY KEY CHECK(id=1),context BLOB NOT NULL,prefix BLOB NOT NULL CHECK(length(prefix)=16),counter INTEGER NOT NULL CHECK(counter>=0),tag BLOB NOT NULL CHECK(length(tag)=16)); PRAGMA user_version=1;"))?;
        let mut prefix = [0; 16];
        mutiny_crypto_v2::fill_os_random(&mut prefix).map_err(|_| Error::Crypto)?;
        let tag = crypt(
            &key,
            &nonce(prefix, 0, false)?,
            &associated(&context, 0, 0),
            &[],
            true,
        )?;
        db(c.execute(
            "INSERT INTO nonce_head VALUES(1,?1,?2,0,?3)",
            params![context, prefix.as_slice(), tag.as_slice()],
        ))?;
        Ok(Self {
            db: c,
            key,
            context,
            prefix,
            counter: 0,
            poisoned: false,
        })
    }
    fn open(
        path: &Path,
        key: Arc<StorageKey>,
        context: Vec<u8>,
        minimum: DurableCheckpoint,
    ) -> Result<Self> {
        let c = connection(path, false)?;
        integrity(&c)?;
        let size: i64 = db(c.query_row(
            "SELECT length(context)+length(prefix)+length(tag) FROM nonce_head WHERE id=1",
            [],
            |r| r.get(0),
        ))?;
        if size > 2048 {
            return Err(Error::Bounds);
        }
        let (ctx, prefix, counter, tag): (Vec<u8>, Vec<u8>, u64, Vec<u8>) = db(c.query_row(
            "SELECT context,prefix,counter,tag FROM nonce_head WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        ))?;
        let prefix: [u8; 16] = prefix.try_into().map_err(|_| Error::Corrupt)?;
        if ctx != context || prefix != minimum.prefix || counter < minimum.nonce_counter {
            return Err(Error::Context);
        }
        if !crypt(
            &key,
            &nonce(prefix, counter, false)?,
            &associated(&context, 0, counter),
            &tag,
            false,
        )?
        .is_empty()
        {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            db: c,
            key,
            context,
            prefix,
            counter,
            poisoned: false,
        })
    }
    fn reserve(&mut self, n: u64) -> Result<std::ops::RangeInclusive<u64>> {
        if self.poisoned || n == 0 || n > 2048 {
            return Err(Error::Poisoned);
        }
        let end = self.counter.checked_add(n).ok_or(Error::Bounds)?;
        if end > MAX_NONCE {
            return Err(Error::Bounds);
        }
        let tag = crypt(
            &self.key,
            &nonce(self.prefix, end, false)?,
            &associated(&self.context, 0, end),
            &[],
            true,
        )?;
        self.poisoned = true;
        let t = db(self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let old: (u64, Vec<u8>) = db(t.query_row(
            "SELECT counter,tag FROM nonce_head WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ))?;
        if old.0 != self.counter {
            return Err(Error::Stale);
        }
        crypt(
            &self.key,
            &nonce(self.prefix, old.0, false)?,
            &associated(&self.context, 0, old.0),
            &old.1,
            false,
        )?;
        db(t.execute(
            "UPDATE nonce_head SET counter=?1,tag=?2 WHERE id=1",
            params![end, tag.as_slice()],
        ))?;
        crash("nonce_before_commit");
        db(t.commit())?;
        crash("nonce_after_commit");
        let start = self.counter + 1;
        self.counter = end;
        self.poisoned = false;
        Ok(start..=end)
    }
}

fn schema(c: &Connection) -> Result<Hash> {
    let mut e = Encoder::new(Vec::new());
    let version: i64 = db(c.pragma_query_value(None, "user_version", |r| r.get(0)))?;
    let mut q=db(c.prepare("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY name"))?;
    let rows = db(q.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<String>>(3)?,
        ))
    }))?;
    let rows: Vec<_> = rows.map(db).collect::<Result<_>>()?;
    if rows.len() > 16 {
        return Err(Error::Bounds);
    }
    e.array(2)
        .unwrap()
        .i64(version)
        .unwrap()
        .array(rows.len() as u64)
        .unwrap();
    for (kind, name, table, sql) in rows {
        e.array(4)
            .unwrap()
            .str(&kind)
            .unwrap()
            .str(&name)
            .unwrap()
            .str(&table)
            .unwrap();
        if let Some(sql) = sql {
            e.str(&sql).unwrap();
        } else {
            e.null().unwrap();
        }
    }
    Ok(digest(b"schema", &e.into_writer()))
}
pub(in crate::trading_service_v1) struct SnapshotStore {
    db: Connection,
    nonces: Nonces,
    context: Vec<u8>,
    scope: StorageContext,
    head: DurableCheckpoint,
    wire: Vec<u8>,
    schema: Hash,
    plain_hash: Hash,
    poisoned: bool,
}
impl SnapshotStore {
    pub(in crate::trading_service_v1) fn create(
        paths: &Paths,
        key: Arc<StorageKey>,
        ctx: &StorageContext,
        kind: JournalKind,
        inner: &Connection,
        policy: &CandidatePolicy,
    ) -> Result<Self> {
        native(policy.check())?;
        if paths.snapshot == paths.nonces {
            return Err(Error::Context);
        }
        let context = context(ctx, kind)?;
        let nonces = Nonces::create(&paths.nonces, key, context.clone())?;
        let c = connection(&paths.snapshot, true)?;
        db(c.execute_batch("CREATE TABLE encrypted_meta(id INTEGER PRIMARY KEY CHECK(id=1),context BLOB NOT NULL,prefix BLOB NOT NULL CHECK(length(prefix)=16),counter INTEGER NOT NULL,head BLOB NOT NULL); CREATE TABLE encrypted_chunk(part INTEGER PRIMARY KEY,counter INTEGER UNIQUE NOT NULL,frame BLOB NOT NULL CHECK(length(frame)<=132096)); PRAGMA user_version=1;"))?;
        let head = DurableCheckpoint {
            generation: 0,
            commitment: [0; 32],
            nonce_counter: 0,
            prefix: nonces.prefix,
        };
        db(c.execute(
            "INSERT INTO encrypted_meta VALUES(1,?1,?2,0,X'')",
            params![context, nonces.prefix.as_slice()],
        ))?;
        let mut s = Self {
            db: c,
            nonces,
            context,
            scope: ctx.clone(),
            head,
            wire: vec![],
            schema: schema(inner)?,
            plain_hash: [0; 32],
            poisoned: false,
        };
        s.persist(inner)?;
        Ok(s)
    }
    pub(in crate::trading_service_v1) fn open(
        paths: &Paths,
        key: Arc<StorageKey>,
        ctx: &StorageContext,
        kind: JournalKind,
        minimum: DurableCheckpoint,
        inner: &mut Connection,
        policy: &CandidatePolicy,
    ) -> Result<Self> {
        native(policy.check())?;
        if paths.snapshot == paths.nonces {
            return Err(Error::Context);
        }
        let context = context(ctx, kind)?;
        let expected = schema(inner)?;
        let nonces = Nonces::open(&paths.nonces, key, context.clone(), minimum)?;
        let c = connection(&paths.snapshot, false)?;
        integrity(&c)?;
        let invalid:i64=db(c.query_row("SELECT (SELECT count(*) FROM encrypted_meta WHERE id!=1 OR length(context)>1024 OR length(head)>2048 OR length(prefix)!=16)+(SELECT count(*) FROM encrypted_chunk WHERE part<0 OR part>=1024 OR length(frame)>132096)",[],|r|r.get(0)))?;
        if invalid != 0 {
            return Err(Error::Bounds);
        }
        let (stored_context, prefix, counter, wire): (Vec<u8>, Vec<u8>, u64, Vec<u8>) = db(c
            .query_row(
                "SELECT context,prefix,counter,head FROM encrypted_meta WHERE id=1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            ))?;
        if stored_context != context
            || prefix != nonces.prefix
            || counter > nonces.counter
            || counter == 0
        {
            return Err(Error::Context);
        }
        let h = unseal(&nonces.key, &associated(&context, 2, counter), &wire)?;
        let mut d = Decoder::new(&h);
        arr(&mut d, 6)?;
        let generation = uint(&mut d)?;
        let schema_hash = fixed(&mut d)?;
        let plain_hash = fixed(&mut d)?;
        let size = usize::try_from(uint(&mut d)?).map_err(|_| Error::Bounds)?;
        let start = uint(&mut d)?;
        let count = usize::try_from(uint(&mut d)?).map_err(|_| Error::Bounds)?;
        let mut canonical = Encoder::new(Vec::new());
        canonical
            .array(6)
            .unwrap()
            .u64(generation)
            .unwrap()
            .bytes(&schema_hash)
            .unwrap()
            .bytes(&plain_hash)
            .unwrap()
            .u64(size as u64)
            .unwrap()
            .u64(start)
            .unwrap()
            .u64(count as u64)
            .unwrap();
        if canonical.into_writer() != h.as_slice() {
            return Err(Error::Codec);
        }
        let head = DurableCheckpoint {
            generation,
            commitment: digest(b"head", &wire),
            nonce_counter: counter,
            prefix: nonces.prefix,
        };
        if d.position() != h.len()
            || generation < minimum.generation
            || generation == minimum.generation && head.commitment != minimum.commitment
            || expected != schema_hash
            || size == 0
            || size > SNAP_MAX
            || count != size.div_ceil(CHUNK)
            || start == 0
            || start.checked_add(count as u64) != Some(counter)
        {
            return Err(Error::Corrupt);
        }
        let actual: usize =
            db(c.query_row("SELECT count(*) FROM encrypted_chunk", [], |r| r.get(0)))?;
        if actual != count {
            return Err(Error::Corrupt);
        }
        let mut plain = Zeroizing::new(Vec::with_capacity(size));
        {
            let mut q =
                db(c.prepare("SELECT part,counter,frame FROM encrypted_chunk ORDER BY part"))?;
            let mut rows = db(q.query([]))?;
            let mut part = 0usize;
            while let Some(row) = db(rows.next())? {
                let p: usize = db(row.get(0))?;
                let ctr: u64 = db(row.get(1))?;
                let frame: Vec<u8> = db(row.get(2))?;
                if p != part || ctr != start + part as u64 {
                    return Err(Error::Corrupt);
                }
                let bytes = unseal(&nonces.key, &associated(&context, 1, ctr), &frame)?;
                if bytes.len() != CHUNK.min(size - part * CHUNK) {
                    return Err(Error::Corrupt);
                }
                plain.extend_from_slice(&bytes);
                part += 1;
            }
        }
        if plain.len() != size
            || digest(b"sqlite", &plain) != plain_hash
            || !plain.starts_with(b"SQLite format 3\0")
        {
            return Err(Error::Corrupt);
        }
        let mut restored = db(Connection::open_in_memory())?;
        db(restored.deserialize_read_exact(
            rusqlite::MAIN_DB,
            std::io::Cursor::new(plain.as_slice()),
            plain.len(),
            false,
        ))?;
        db(restored.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; PRAGMA secure_delete=ON; PRAGMA foreign_keys=ON;"))?;
        integrity(&restored)?;
        if schema(&restored)? != expected {
            return Err(Error::Corrupt);
        };
        *inner = restored;
        Ok(Self {
            db: c,
            nonces,
            context,
            scope: ctx.clone(),
            head,
            wire,
            schema: expected,
            plain_hash,
            poisoned: false,
        })
    }
    pub(in crate::trading_service_v1) fn matches_anchor(&self, a: &FinalizedAnchor) -> Result<()> {
        if a.network == self.scope.network
            && a.genesis == self.scope.genesis
            && a.fingerprint == self.scope.fingerprint
        {
            Ok(())
        } else {
            Err(Error::Context)
        }
    }
    pub(in crate::trading_service_v1) fn checkpoint(&self) -> Result<DurableCheckpoint> {
        self.healthy()?;
        Ok(DurableCheckpoint {
            nonce_counter: self.nonces.counter,
            ..self.head
        })
    }
    pub(in crate::trading_service_v1) fn healthy(&self) -> Result<()> {
        if self.poisoned || self.nonces.poisoned {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }
    pub(in crate::trading_service_v1) fn persist(&mut self, inner: &Connection) -> Result<()> {
        self.healthy()?;
        self.poisoned = true;
        if schema(inner)? != self.schema {
            return Err(Error::Corrupt);
        }
        let size: u64 = db(inner.query_row(
            "SELECT page_count*page_size FROM pragma_page_count,pragma_page_size",
            [],
            |r| r.get(0),
        ))?;
        if size == 0 || size > SNAP_MAX as u64 {
            return Err(Error::Bounds);
        }
        let data = db(inner.serialize(rusqlite::MAIN_DB))?;
        let plain_hash = digest(b"sqlite", &data);
        if plain_hash == self.plain_hash {
            self.poisoned = false;
            return Ok(());
        }
        if data.len() != size as usize {
            return Err(Error::Corrupt);
        }
        let count = data.len().div_ceil(CHUNK);
        let generation = self.head.generation.checked_add(1).ok_or(Error::Bounds)?;
        self.poisoned = true;
        let reservation = self.nonces.reserve(count as u64 + 1)?;
        let start = *reservation.start();
        let end = *reservation.end();
        let mut frames = Vec::with_capacity(count);
        for (part, bytes) in data.chunks(CHUNK).enumerate() {
            let ctr = start + part as u64;
            frames.push((
                ctr,
                seal(&self.nonces.key, &associated(&self.context, 1, ctr), bytes)?,
            ));
        }
        let mut e = Encoder::new(Vec::new());
        e.array(6)
            .unwrap()
            .u64(generation)
            .unwrap()
            .bytes(&self.schema)
            .unwrap()
            .bytes(&plain_hash)
            .unwrap()
            .u64(size)
            .unwrap()
            .u64(start)
            .unwrap()
            .u64(count as u64)
            .unwrap();
        let wire = seal(
            &self.nonces.key,
            &associated(&self.context, 2, end),
            &e.into_writer(),
        )?;
        #[cfg(test)]
        if let Some(root) = std::env::var_os("TRADING_NONCE_PROBE") {
            let first = &frames[0];
            std::fs::write(std::path::PathBuf::from(root).join("encrypted-nonce-probe.json"),serde_json::to_vec_pretty(&serde_json::json!({"first_counter":first.0,"first_nonce":hex::encode(data_nonce_for_test(self.nonces.prefix,first.0,&first.1)),"frame":hex::encode(&first.1)})).unwrap()).unwrap();
        }
        crash("snapshot_after_encryption");
        let t = db(self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let old: Vec<u8> = db(t.query_row(
            "SELECT head FROM encrypted_meta WHERE id=1",
            [],
            |r| r.get(0),
        ))?;
        if old != self.wire {
            return Err(Error::Stale);
        }
        db(t.execute("DELETE FROM encrypted_chunk", []))?;
        for (part, (ctr, frame)) in frames.iter().enumerate() {
            db(t.execute(
                "INSERT INTO encrypted_chunk VALUES(?1,?2,?3)",
                params![part, ctr, frame.as_slice()],
            ))?;
        }
        db(t.execute(
            "UPDATE encrypted_meta SET counter=?1,head=?2 WHERE id=1",
            params![end, wire],
        ))?;
        crash("snapshot_before_commit");
        db(t.commit())?;
        crash("snapshot_after_commit");
        self.head = DurableCheckpoint {
            generation,
            commitment: digest(b"head", &wire),
            nonce_counter: end,
            prefix: self.nonces.prefix,
        };
        self.wire = wire;
        self.plain_hash = plain_hash;
        self.poisoned = false;
        Ok(())
    }
}

/// Hardening applies to memory-only logical journals. Disk files store encrypted
/// snapshots and authenticated nonce reservations, never SQLite plaintext pages.
pub(in crate::trading_service_v1) fn memory_hardening(c: &Connection) -> Result<()> {
    db(c.execute_batch(
        "PRAGMA temp_store=MEMORY; PRAGMA secure_delete=ON; PRAGMA trusted_schema=OFF;",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn key(n: u8) -> Arc<StorageKey> {
        Arc::new(StorageKey::qualification(Zeroizing::new([n; 32])).unwrap())
    }
    fn context() -> StorageContext {
        StorageContext {
            network: 8,
            genesis: [31; 32],
            fingerprint: [32; 32],
            storage: [33; 32],
            key_generation: 1,
        }
    }
    fn policy() -> CandidatePolicy {
        CandidatePolicy::native_denomination_locked()
    }
    #[test]
    fn r7_nonce_context_independent_vector_material() {
        let c = context();
        let mut prefix = [0u8; 16];
        for (i, b) in prefix.iter_mut().enumerate() {
            *b = i as u8;
        }
        let engine = super::context(&c, JournalKind::BitcoinEngine).unwrap();
        let signer = super::context(&c, JournalKind::BitcoinSigner).unwrap();
        assert_ne!(engine, signer);
        let mut vectors = vec![
            serde_json::json!({"name":"engine_context","hex":hex::encode(&engine)}),
            serde_json::json!({"name":"signer_context","hex":hex::encode(&signer)}),
        ];
        for (name, counter, data) in [
            ("ledger_zero", 0, false),
            ("data_zero", 0, true),
            ("ledger_one", 1, false),
            ("data_one", 1, true),
            ("last_ledger", MAX_NONCE, false),
            ("last_data", MAX_NONCE, true),
        ] {
            vectors.push(serde_json::json!({"name":name,"hex":hex::encode(nonce(prefix,counter,data).unwrap())}));
        }
        assert_eq!(nonce(prefix, MAX_NONCE + 1, true), Err(Error::Bounds));
        vectors.push(
            serde_json::json!({"name":"chunk_aad","hex":hex::encode(associated(&engine,1,17))}),
        );
        vectors.push(
            serde_json::json!({"name":"head_aad","hex":hex::encode(associated(&engine,2,18))}),
        );
        std::fs::write(
            std::path::PathBuf::from(std::env::var_os("BITCOIN_TRADING_EVIDENCE_DIR").unwrap())
                .join("r7-nonce-vectors.json"),
            serde_json::to_vec_pretty(&vectors).unwrap(),
        )
        .unwrap();
    }
    fn paths(label: &str) -> Paths {
        let root =
            std::path::PathBuf::from(std::env::var_os("BITCOIN_TRADING_EVIDENCE_DIR").unwrap())
                .join(label);
        std::fs::create_dir(&root).unwrap();
        Paths {
            snapshot: root.join("cipher.sqlite"),
            nonces: root.join("nonces.sqlite"),
        }
    }
    fn memory() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        memory_hardening(&c).unwrap();
        c.execute_batch("CREATE TABLE fixture(id BLOB PRIMARY KEY,secret BLOB NOT NULL); PRAGMA user_version=1;").unwrap();
        c
    }
    #[test]
    fn r7_snapshot_nonce_reservation_restart_and_multi_chunk_roundtrip() {
        let p = paths("r7-snapshot-roundtrip");
        let key = key(201);
        let context = context();
        let c = memory();
        let mut s = SnapshotStore::create(
            &p,
            key.clone(),
            &context,
            JournalKind::Recovery,
            &c,
            &policy(),
        )
        .unwrap();
        let first = s.checkpoint().unwrap();
        let secret = vec![91u8; 300 * 1024];
        c.execute(
            "INSERT INTO fixture VALUES(?1,?2)",
            params![[17u8; 32].as_slice(), secret],
        )
        .unwrap();
        s.persist(&c).unwrap();
        let end = s.checkpoint().unwrap();
        assert!(end.generation > first.generation);
        assert!(end.nonce_counter > first.nonce_counter + 2);
        assert_eq!(end.prefix, first.prefix);
        let before = s.nonces.counter;
        s.persist(&c).unwrap();
        assert_eq!(before, s.nonces.counter); // exact state is idempotent
        let counters: Vec<u64> =
            s.db.prepare("SELECT counter FROM encrypted_chunk ORDER BY part")
                .unwrap()
                .query_map([], |r| r.get(0))
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
        assert!(counters.windows(2).all(|w| w[0] + 1 == w[1]));
        assert_eq!(counters.last().unwrap() + 1, end.nonce_counter);
        drop(s);
        drop(c);
        for path in [&p.snapshot, &p.nonces] {
            let disk = std::fs::read(path).unwrap();
            assert!(!disk.windows(64).any(|b| b == [91u8; 64]));
        }
        let mut c = memory();
        let s = SnapshotStore::open(
            &p,
            key,
            &context,
            JournalKind::Recovery,
            end,
            &mut c,
            &policy(),
        )
        .unwrap();
        assert_eq!(s.checkpoint().unwrap(), end);
        let found: Vec<u8> = c
            .query_row(
                "SELECT secret FROM fixture WHERE id=?1",
                [[17u8; 32].as_slice()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(found, secret);
    }
    #[test]
    fn r7_snapshot_wrong_key_role_rollback_and_stale_writer_fail_closed() {
        let p = paths("r7-snapshot-hostile");
        let key = key(202);
        let context = context();
        let c = memory();
        let mut s = SnapshotStore::create(
            &p,
            key.clone(),
            &context,
            JournalKind::BitcoinEngine,
            &c,
            &policy(),
        )
        .unwrap();
        let first = s.checkpoint().unwrap();
        drop(s);
        let old = p.snapshot.with_extension("previous");
        let old_nonce = p.nonces.with_extension("previous");
        std::fs::copy(&p.snapshot, &old).unwrap();
        std::fs::copy(&p.nonces, &old_nonce).unwrap();
        let mut c2 = memory();
        assert!(
            SnapshotStore::open(
                &p,
                self::key(203),
                &context,
                JournalKind::BitcoinEngine,
                first,
                &mut c2,
                &policy()
            )
            .is_err()
        );
        assert!(
            SnapshotStore::open(
                &p,
                key.clone(),
                &context,
                JournalKind::BitcoinSigner,
                first,
                &mut c2,
                &policy()
            )
            .is_err()
        );
        let mut c2 = memory();
        s = SnapshotStore::open(
            &p,
            key.clone(),
            &context,
            JournalKind::BitcoinEngine,
            first,
            &mut c2,
            &policy(),
        )
        .unwrap();
        let mut c3 = memory();
        let mut other = SnapshotStore::open(
            &p,
            key.clone(),
            &context,
            JournalKind::BitcoinEngine,
            first,
            &mut c3,
            &policy(),
        )
        .unwrap();
        c2.execute(
            "INSERT INTO fixture VALUES(?1,?2)",
            params![[19u8; 32].as_slice(), b"SYNTHETIC SECRET ROW".as_slice()],
        )
        .unwrap();
        s.persist(&c2).unwrap();
        let latest = s.checkpoint().unwrap();
        c3.execute(
            "INSERT INTO fixture VALUES(?1,?2)",
            params![[20u8; 32].as_slice(), b"OTHER PRIVATE ROW".as_slice()],
        )
        .unwrap();
        assert_eq!(other.persist(&c3), Err(Error::Stale));
        assert_eq!(other.checkpoint(), Err(Error::Poisoned));
        assert_eq!(other.persist(&c3), Err(Error::Poisoned));
        drop(other);
        drop(s);
        let mut restore = memory();
        assert!(
            SnapshotStore::open(
                &Paths {
                    snapshot: old.clone(),
                    nonces: p.nonces.clone()
                },
                key.clone(),
                &context,
                JournalKind::BitcoinEngine,
                latest,
                &mut restore,
                &policy()
            )
            .is_err()
        );
        assert!(
            SnapshotStore::open(
                &Paths {
                    snapshot: p.snapshot.clone(),
                    nonces: old_nonce
                },
                key.clone(),
                &context,
                JournalKind::BitcoinEngine,
                latest,
                &mut restore,
                &policy()
            )
            .is_err()
        );
        let c = Connection::open(&p.snapshot).unwrap();
        let mut frame: Vec<u8> = c
            .query_row("SELECT frame FROM encrypted_chunk WHERE part=0", [], |r| {
                r.get(0)
            })
            .unwrap();
        frame[0] ^= 1;
        c.execute("UPDATE encrypted_chunk SET frame=?1 WHERE part=0", [frame])
            .unwrap();
        drop(c);
        assert!(
            SnapshotStore::open(
                &p,
                key,
                &context,
                JournalKind::BitcoinEngine,
                latest,
                &mut restore,
                &policy()
            )
            .is_err()
        );
    }
    #[test]
    fn r7_torn_frames_context_counter_and_failed_persist_poison() {
        let base = paths("r7-torn");
        let k = key(210);
        let ctx = context();
        let c = memory();
        let mut s =
            SnapshotStore::create(&base, k.clone(), &ctx, JournalKind::Recovery, &c, &policy())
                .unwrap();
        c.execute(
            "INSERT INTO fixture VALUES(?1,?2)",
            params![[21u8; 32].as_slice(), vec![92u8; 300 * 1024]],
        )
        .unwrap();
        s.persist(&c).unwrap();
        let min = s.checkpoint().unwrap();
        drop(s);
        let mutations = [
            "head-bit",
            "chunk-bit",
            "chunk-truncate",
            "missing-chunk",
            "wrong-counter",
            "context",
            "prefix",
            "ledger-tag",
            "ledger-counter",
            "extra-chunk",
        ];
        for name in mutations {
            let p = paths(&format!("r7-torn-{name}"));
            std::fs::copy(&base.snapshot, &p.snapshot).unwrap();
            std::fs::copy(&base.nonces, &p.nonces).unwrap();
            let db = Connection::open(if name.starts_with("ledger") {
                &p.nonces
            } else {
                &p.snapshot
            })
            .unwrap();
            match name {
                "head-bit" => {
                    let mut v: Vec<u8> = db
                        .query_row("SELECT head FROM encrypted_meta", [], |r| r.get(0))
                        .unwrap();
                    v[0] ^= 1;
                    db.execute("UPDATE encrypted_meta SET head=?1", [v])
                        .unwrap();
                }
                "chunk-bit" => {
                    let mut v: Vec<u8> = db
                        .query_row("SELECT frame FROM encrypted_chunk WHERE part=0", [], |r| {
                            r.get(0)
                        })
                        .unwrap();
                    v[0] ^= 1;
                    db.execute("UPDATE encrypted_chunk SET frame=?1 WHERE part=0", [v])
                        .unwrap();
                }
                "chunk-truncate" => {
                    db.execute("UPDATE encrypted_chunk SET frame=substr(frame,1,length(frame)-1) WHERE part=0",[]).unwrap();
                }
                "missing-chunk" => {
                    db.execute("DELETE FROM encrypted_chunk WHERE part=1", [])
                        .unwrap();
                }
                "wrong-counter" => {
                    db.execute(
                        "UPDATE encrypted_chunk SET counter=counter+100 WHERE part=0",
                        [],
                    )
                    .unwrap();
                }
                "context" => {
                    db.execute("UPDATE encrypted_meta SET context=X'00'", [])
                        .unwrap();
                }
                "prefix" => {
                    db.execute("UPDATE encrypted_meta SET prefix=zeroblob(16)", [])
                        .unwrap();
                }
                "ledger-tag" => {
                    db.execute("UPDATE nonce_head SET tag=zeroblob(16)", [])
                        .unwrap();
                }
                "ledger-counter" => {
                    db.execute("UPDATE nonce_head SET counter=counter+1", [])
                        .unwrap();
                }
                "extra-chunk" => {
                    db.execute("INSERT INTO encrypted_chunk VALUES(999,10000,X'00')", [])
                        .unwrap();
                }
                _ => unreachable!(),
            };
            drop(db);
            let mut inner = memory();
            assert!(
                SnapshotStore::open(
                    &p,
                    k.clone(),
                    &ctx,
                    JournalKind::Recovery,
                    min,
                    &mut inner,
                    &policy()
                )
                .is_err(),
                "{name}"
            );
        }
        let mut inner = memory();
        let mut s = SnapshotStore::open(
            &base,
            k,
            &ctx,
            JournalKind::Recovery,
            min,
            &mut inner,
            &policy(),
        )
        .unwrap();
        inner.execute_batch("CREATE TABLE unexpected(x);").unwrap();
        assert_eq!(s.persist(&inner), Err(Error::Corrupt));
        assert_eq!(s.checkpoint(), Err(Error::Poisoned));
        assert_eq!(s.healthy(), Err(Error::Poisoned));
    }
    #[test]
    fn r7a_ledger_only_rollback_must_not_reuse_data_nonce() {
        let p = paths("r7a-ledger-rollback");
        let root = p.snapshot.parent().unwrap();
        let k = key(221);
        let ctx = context();
        let c = memory();
        let s = SnapshotStore::create(&p, k.clone(), &ctx, JournalKind::Recovery, &c, &policy())
            .unwrap();
        let min = s.checkpoint().unwrap();
        drop(s);
        let snapshot_before = Sha256::digest(std::fs::read(&p.snapshot).unwrap()).to_vec();
        let old = root.join("retained-nonce.sqlite");
        std::fs::copy(&p.nonces, &old).unwrap();
        let input = serde_json::json!({"generation":min.generation,"commitment":hex::encode(min.commitment),"counter":min.nonce_counter,"prefix":hex::encode(min.prefix)});
        std::fs::write(
            root.join("protected-checkpoint.json"),
            serde_json::to_vec_pretty(&input).unwrap(),
        )
        .unwrap();
        let result=std::process::Command::new(std::env::current_exe().unwrap()).args(["--ignored","--exact","trading_service_v1::local_storage_candidate::legacy_candidate::tests::r7a_nonce_rollback_worker","--nocapture"]).env("TRADING_STORAGE_CRASH","snapshot_after_encryption").env("TRADING_NONCE_PROBE",root).output().unwrap();
        std::fs::write(root.join("worker.stdout.log"), result.stdout).unwrap();
        std::fs::write(root.join("worker.stderr.log"), result.stderr).unwrap();
        assert_eq!(result.status.code(), Some(86));
        let probe: serde_json::Value = serde_json::from_slice(
            &std::fs::read(root.join("encrypted-nonce-probe.json")).unwrap(),
        )
        .unwrap();
        let first_nonce = hex::decode(probe["first_nonce"].as_str().unwrap()).unwrap();
        let first_counter = probe["first_counter"].as_u64().unwrap();
        assert!(first_counter > min.nonce_counter);
        // Preserve every crashed ledger file before restoring ONLY that ledger.
        // The data snapshot and independently retained checkpoint stay untouched.
        for suffix in ["", "-wal", "-shm"] {
            let path = std::path::PathBuf::from(format!("{}{suffix}", p.nonces.display()));
            if path.exists() {
                let backup = root.join(format!("after-crash-nonces{suffix}"));
                std::fs::rename(path, backup).unwrap();
            }
        }
        std::fs::copy(&old, &p.nonces).unwrap();
        assert_eq!(
            Sha256::digest(std::fs::read(&p.snapshot).unwrap()).to_vec(),
            snapshot_before
        );
        let mut restored = memory();
        let mut s = SnapshotStore::open(
            &p,
            k,
            &ctx,
            JournalKind::Recovery,
            min,
            &mut restored,
            &policy(),
        )
        .unwrap();
        assert_eq!(s.checkpoint().unwrap(), min);
        restored
            .execute(
                "INSERT INTO fixture VALUES(?1,?2)",
                params![
                    [22u8; 32].as_slice(),
                    b"SECOND DISTINCT SYNTHETIC PLAINTEXT".as_slice()
                ],
            )
            .unwrap();
        s.persist(&restored).unwrap();
        let (counter, frame): (u64, Vec<u8>) =
            s.db.query_row(
                "SELECT counter,frame FROM encrypted_chunk WHERE part=0",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        let next_nonce = data_nonce_for_test(s.nonces.prefix, counter, &frame);
        assert_eq!(counter, first_counter);
        let reused = first_nonce == next_nonce;
        std::fs::write(root.join("regression-result.json"),serde_json::to_vec_pretty(&serde_json::json!({"ledger_only_rollback_accepted":true,"snapshot_and_checkpoint_unchanged":true,"ordinal_repeated":counter==first_counter,"data_nonce_reused":reused,"first_nonce":hex::encode(&first_nonce),"next_nonce":hex::encode(next_nonce),"production":false})).unwrap()).unwrap();
        assert!(
            !reused,
            "ledger-only rollback reused an AEAD data nonce after pre-commit encryption"
        );
    }
    #[test]
    #[ignore = "R7a ledger rollback subprocess"]
    fn r7a_nonce_rollback_worker() {
        let root = std::path::PathBuf::from(std::env::var_os("TRADING_NONCE_PROBE").unwrap());
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("protected-checkpoint.json")).unwrap())
                .unwrap();
        let decode = |k: &str| hex::decode(v[k].as_str().unwrap()).unwrap();
        let min = DurableCheckpoint {
            generation: v["generation"].as_u64().unwrap(),
            commitment: decode("commitment").try_into().unwrap(),
            nonce_counter: v["counter"].as_u64().unwrap(),
            prefix: decode("prefix").try_into().unwrap(),
        };
        let p = Paths {
            snapshot: root.join("cipher.sqlite"),
            nonces: root.join("nonces.sqlite"),
        };
        let mut c = memory();
        let mut s = SnapshotStore::open(
            &p,
            key(221),
            &context(),
            JournalKind::Recovery,
            min,
            &mut c,
            &policy(),
        )
        .unwrap();
        c.execute(
            "INSERT INTO fixture VALUES(?1,?2)",
            params![
                [22u8; 32].as_slice(),
                b"FIRST DISTINCT SYNTHETIC PLAINTEXT".as_slice()
            ],
        )
        .unwrap();
        s.persist(&c).unwrap();
        panic!("crash boundary missed");
    }
    #[test]
    fn r7a_legacy_v1_store_is_not_silently_opened() {
        let root = std::path::PathBuf::from(std::env::var_os("TRADING_R7_ORIGINAL_STORE").unwrap());
        let p = paths("r7a-legacy-blocked");
        std::fs::copy(root.join("cipher.sqlite"), &p.snapshot).unwrap();
        std::fs::copy(root.join("nonces.sqlite"), &p.nonces).unwrap();
        let v: serde_json::Value =
            serde_json::from_slice(&std::fs::read(root.join("protected-checkpoint.json")).unwrap())
                .unwrap();
        let decode = |k: &str| hex::decode(v[k].as_str().unwrap()).unwrap();
        let min = DurableCheckpoint {
            generation: v["generation"].as_u64().unwrap(),
            commitment: decode("commitment").try_into().unwrap(),
            nonce_counter: v["counter"].as_u64().unwrap(),
            prefix: decode("prefix").try_into().unwrap(),
        };
        let mut c = memory();
        assert!(matches!(
            SnapshotStore::open(
                &p,
                key(221),
                &context(),
                JournalKind::Recovery,
                min,
                &mut c,
                &policy()
            ),
            Err(Error::Context)
        ));
    }
}

#[cfg(test)]
fn data_nonce_for_test(_prefix: [u8; 16], _counter: u64, frame: &[u8]) -> Vec<u8> {
    let mut d = Decoder::new(frame);
    arr(&mut d, 3).unwrap();
    assert_eq!(uint(&mut d).unwrap(), 1);
    let n = bytes(&mut d).unwrap();
    assert_eq!(n.len(), 24);
    n.to_vec()
}
