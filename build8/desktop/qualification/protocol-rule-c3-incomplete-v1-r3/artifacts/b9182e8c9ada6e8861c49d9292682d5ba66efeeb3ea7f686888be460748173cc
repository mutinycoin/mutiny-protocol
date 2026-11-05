//! Nonproduction encrypted local state, using the same pinned XChaCha20-Poly1305
//! provider as Build8 custody. No wallet key derivation, key ceremony or network.
//! Production key-vault/rollback integration and full memory qualification remain gated.
use super::{completion_candidate as completion, *};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::AeadInPlace};
use minicbor::{Decoder, Encoder};
use mutiny_consensus_v8::trading_v1 as tr;
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::Zeroizing;

const NS: &[u8] = b"MUTINY-OFFLINE-ENCRYPTED-LOCAL-STATE-V1";
const MAX_BODY: usize = 196608;
const MAX_FRAME: usize = MAX_BODY + 1024;
const MAX_EVENTS: u64 = 4096;
const MAX_TOTAL: u64 = 64 * 1024 * 1024;
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Gate,
    Unit,
    Store,
    Codec,
    Context,
    Crypto,
    Bounds,
    Corrupt,
    Stale,
    Poisoned,
    NotPublic,
    Unapplied,
    Completion(completion::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
impl From<completion::Error> for Error {
    fn from(e: completion::Error) -> Self {
        Self::Completion(e)
    }
}
fn db<T>(r: rusqlite::Result<T>) -> Result<T> {
    r.map_err(|_| Error::Store)
}
fn native<T>(r: tr::NativeResult<T>) -> Result<T> {
    r.map_err(|e| match e {
        tr::NativeError::Gate => Error::Gate,
        tr::NativeError::UnitUnresolved => Error::Unit,
        _ => Error::Context,
    })
}
fn arr(d: &mut Decoder<'_>, n: u64) -> Result<()> {
    if d.array().map_err(|_| Error::Codec)? == Some(n) {
        Ok(())
    } else {
        Err(Error::Codec)
    }
}
fn bytes<'a>(d: &mut Decoder<'a>) -> Result<&'a [u8]> {
    d.bytes().map_err(|_| Error::Codec)
}
fn fixed(d: &mut Decoder<'_>) -> Result<Hash> {
    bytes(d)?.try_into().map_err(|_| Error::Codec)
}
fn uint(d: &mut Decoder<'_>) -> Result<u64> {
    d.u64().map_err(|_| Error::Codec)
}
fn hash(label: &[u8], raw: &[u8]) -> Hash {
    let mut h = Sha256::new();
    h.update(NS);
    h.update([0]);
    h.update(label);
    h.update([0]);
    h.update(raw);
    h.finalize().into()
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StorageContext {
    pub network: u32,
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub storage: Hash,
    pub key_generation: u64,
}
impl StorageContext {
    fn encode(&self, purpose: u8) -> Result<Vec<u8>> {
        if self.key_generation == 0 || self.storage == [0; 32] || !matches!(purpose, 1 | 2) {
            return Err(Error::Context);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(8)
            .unwrap()
            .bytes(NS)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(purpose)
            .unwrap()
            .u32(self.network)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .bytes(&self.storage)
            .unwrap()
            .u64(self.key_generation)
            .unwrap();
        Ok(e.into_writer())
    }
    fn matches(&self, context: &tr::Context) -> bool {
        self.network == context.network
            && self.genesis == context.genesis
            && self.fingerprint == context.fingerprint
    }
}
/// Separate local-data key, never a wallet/BTC/trade-identity spending key.
/// No production constructor/export is supplied by this candidate.
pub struct StorageKey(Zeroizing<[u8; 32]>);
impl StorageKey {
    #[cfg(test)]
    pub fn qualification(key: Zeroizing<[u8; 32]>) -> Result<Self> {
        mutiny_crypto_v2::protect_process().map_err(|_| Error::Crypto)?;
        Ok(Self(key))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Checkpoint {
    pub sequence: u64,
    pub commitment: Hash,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EntryRef {
    pub sequence: u64,
    pub commitment: Hash,
}
struct PlainEntry {
    reference: EntryRef,
    kind: u8,
    body: Zeroizing<Vec<u8>>,
}
fn aad(context: &[u8], class: u8, sequence: u64, previous: Hash) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(4)
        .unwrap()
        .bytes(context)
        .unwrap()
        .u8(class)
        .unwrap()
        .u64(sequence)
        .unwrap()
        .bytes(&previous)
        .unwrap();
    e.into_writer()
}
fn seal(key: &StorageKey, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    if plain.len() > MAX_BODY + 32 {
        return Err(Error::Bounds);
    }
    let mut nonce = [0u8; 24];
    mutiny_crypto_v2::fill_os_random(&mut nonce).map_err(|_| Error::Crypto)?;
    let mut guarded = Zeroizing::new(Vec::with_capacity(plain.len() + 16));
    guarded.extend_from_slice(plain);
    XChaCha20Poly1305::new_from_slice(key.0.as_ref())
        .map_err(|_| Error::Crypto)?
        .encrypt_in_place(XNonce::from_slice(&nonce), aad, &mut *guarded)
        .map_err(|_| Error::Crypto)?;
    let mut e = Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&nonce)
        .unwrap()
        .bytes(&guarded)
        .unwrap();
    Ok(e.into_writer())
}
fn unseal(key: &StorageKey, aad: &[u8], raw: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if raw.len() > MAX_FRAME {
        return Err(Error::Bounds);
    }
    let mut d = Decoder::new(raw);
    arr(&mut d, 3)?;
    if uint(&mut d)? != 1 {
        return Err(Error::Codec);
    }
    let nonce: [u8; 24] = bytes(&mut d)?.try_into().map_err(|_| Error::Codec)?;
    let ciphertext = bytes(&mut d)?;
    if ciphertext.len() < 16 || ciphertext.len() > MAX_BODY + 48 {
        return Err(Error::Bounds);
    }
    let mut e = Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&nonce)
        .unwrap()
        .bytes(ciphertext)
        .unwrap();
    if d.position() != raw.len() || e.into_writer() != raw {
        return Err(Error::Codec);
    }
    let mut plain = Zeroizing::new(ciphertext.to_vec());
    XChaCha20Poly1305::new_from_slice(key.0.as_ref())
        .map_err(|_| Error::Crypto)?
        .decrypt_in_place(XNonce::from_slice(&nonce), aad, &mut *plain)
        .map_err(|_| Error::Crypto)?;
    Ok(plain)
}
fn head_bytes(c: Checkpoint) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(2)
        .unwrap()
        .u64(c.sequence)
        .unwrap()
        .bytes(&c.commitment)
        .unwrap();
    e.into_writer()
}
fn parse_head(raw: &[u8]) -> Result<Checkpoint> {
    let mut d = Decoder::new(raw);
    arr(&mut d, 2)?;
    let c = Checkpoint {
        sequence: uint(&mut d)?,
        commitment: fixed(&mut d)?,
    };
    if c.sequence > MAX_EVENTS || d.position() != raw.len() || head_bytes(c) != raw {
        return Err(Error::Codec);
    }
    Ok(c)
}
#[cfg(test)]
fn crash(point: &str) {
    if std::env::var("TRADING_STORAGE_CRASH").ok().as_deref() == Some(point) {
        std::process::exit(86)
    }
}
#[cfg(not(test))]
fn crash(_: &str) {}

/// Ciphertext-only SQLite/WAL. Counts, ciphertext sizes and local store context
/// are visible. An independently retained minimum checkpoint detects rollback
/// below it; coherent rollback of database AND checkpoint is not solved here.
struct SealedLog<'k> {
    connection: Connection,
    key: &'k StorageKey,
    context: Vec<u8>,
    head: Checkpoint,
    head_wire: Vec<u8>,
    entries: Vec<PlainEntry>,
    total: u64,
    poisoned: bool,
}
impl<'k> SealedLog<'k> {
    fn create(
        path: &Path,
        key: &'k StorageKey,
        context: Vec<u8>,
        policy: &CandidatePolicy,
    ) -> Result<Self> {
        native(policy.check())?;
        if path.exists() {
            return Err(Error::Store);
        }
        let c = db(Connection::open(path))?;
        db(c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY; BEGIN IMMEDIATE; CREATE TABLE store_meta(id INTEGER PRIMARY KEY CHECK(id=1),context BLOB NOT NULL,head BLOB NOT NULL); CREATE TABLE sealed_event(seq INTEGER PRIMARY KEY CHECK(seq BETWEEN 1 AND 4096),frame BLOB NOT NULL CHECK(length(frame)<=197632)); PRAGMA user_version=1;"))?;
        let head = Checkpoint {
            sequence: 0,
            commitment: hash(b"empty", &context),
        };
        let wire = seal(key, &aad(&context, 0, 0, [0; 32]), &head_bytes(head))?;
        db(c.execute(
            "INSERT INTO store_meta VALUES(1,?1,?2)",
            params![context, wire],
        ))?;
        db(c.execute_batch("COMMIT;"))?;
        Ok(Self {
            connection: c,
            key,
            context,
            head,
            head_wire: wire,
            entries: vec![],
            total: 0,
            poisoned: false,
        })
    }
    fn open(
        path: &Path,
        key: &'k StorageKey,
        context: Vec<u8>,
        minimum: Checkpoint,
        policy: &CandidatePolicy,
    ) -> Result<Self> {
        native(policy.check())?;
        // Bound work before SQLite integrity traversal or loading attacker-sized
        // blobs. A full local disk is still an environmental availability risk.
        for file in [
            path.to_path_buf(),
            std::path::PathBuf::from(format!("{}-wal", path.display())),
        ] {
            match std::fs::metadata(&file) {
                Ok(m) if m.len() > 2 * MAX_TOTAL => return Err(Error::Bounds),
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => return Err(Error::Store),
            }
        }
        let c = db(Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        ))?;
        db(c.busy_timeout(std::time::Duration::from_secs(2)))?;
        db(c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY;"))?;
        let version: i64 = db(c.pragma_query_value(None, "user_version", |r| r.get(0)))?;
        let check: String = db(c.query_row("PRAGMA quick_check", [], |r| r.get(0)))?;
        if version != 1 || check != "ok" {
            return Err(Error::Corrupt);
        }
        let invalid:i64=db(c.query_row("SELECT (SELECT count(*) FROM store_meta WHERE id!=1 OR length(context)>1024 OR length(head)>1024)+(SELECT count(*) FROM sealed_event WHERE seq<1 OR seq>4096 OR length(frame)>197632)",[],|r|r.get(0)))?;
        if invalid != 0 {
            return Err(Error::Bounds);
        }
        let (stored, head_wire): (Vec<u8>, Vec<u8>) = db(c.query_row(
            "SELECT context,head FROM store_meta WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ))?;
        if stored != context {
            return Err(Error::Context);
        }
        let head = parse_head(&unseal(key, &aad(&context, 0, 0, [0; 32]), &head_wire)?)?;
        let (count, total): (u64, u64) = db(c.query_row(
            "SELECT count(*),coalesce(sum(length(frame)),0) FROM sealed_event",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        ))?;
        if count != head.sequence
            || count > MAX_EVENTS
            || total > MAX_TOTAL
            || minimum.sequence > head.sequence
        {
            return Err(Error::Corrupt);
        }
        let mut prior = Checkpoint {
            sequence: 0,
            commitment: hash(b"empty", &context),
        };
        let mut entries = Vec::new();
        let mut matched = minimum == prior;
        {
            let mut q = db(c.prepare("SELECT seq,frame FROM sealed_event ORDER BY seq"))?;
            let mut rows = db(q.query([]))?;
            while let Some(row) = db(rows.next())? {
                let sequence: u64 = db(row.get(0))?;
                let frame: Vec<u8> = db(row.get(1))?;
                if sequence != prior.sequence + 1 {
                    return Err(Error::Corrupt);
                }
                let plain = unseal(key, &aad(&context, 1, sequence, prior.commitment), &frame)?;
                let mut d = Decoder::new(&plain);
                arr(&mut d, 2)?;
                let kind = d.u8().map_err(|_| Error::Codec)?;
                let body = bytes(&mut d)?;
                if kind > 4 || body.len() > MAX_BODY {
                    return Err(Error::Bounds);
                }
                let mut e = Encoder::new(Vec::with_capacity(plain.len()));
                e.array(2).unwrap().u8(kind).unwrap().bytes(body).unwrap();
                let canonical = Zeroizing::new(e.into_writer());
                if d.position() != plain.len() || canonical.as_slice() != plain.as_slice() {
                    return Err(Error::Codec);
                }
                prior = Checkpoint {
                    sequence,
                    commitment: hash(b"frame", &frame),
                };
                if prior == minimum {
                    matched = true
                }
                entries.push(PlainEntry {
                    reference: EntryRef {
                        sequence,
                        commitment: prior.commitment,
                    },
                    kind,
                    body: Zeroizing::new(body.to_vec()),
                });
            }
        }
        if prior != head || !matched {
            return Err(Error::Corrupt);
        }
        Ok(Self {
            connection: c,
            key,
            context,
            head,
            head_wire,
            entries,
            total,
            poisoned: false,
        })
    }
    fn append(&mut self, kind: u8, body: &[u8]) -> Result<EntryRef> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        if kind > 4 || body.len() > MAX_BODY {
            return Err(Error::Bounds);
        }
        if let Some(old) = self
            .entries
            .iter()
            .find(|e| e.kind == kind && e.body.as_slice() == body)
        {
            return Ok(old.reference);
        }
        if self.head.sequence >= MAX_EVENTS {
            return Err(Error::Bounds);
        }
        let sequence = self.head.sequence + 1;
        let mut e = Encoder::new(Vec::with_capacity(body.len() + 16));
        e.array(2).unwrap().u8(kind).unwrap().bytes(body).unwrap();
        let plain = Zeroizing::new(e.into_writer());
        let frame = seal(
            self.key,
            &aad(&self.context, 1, sequence, self.head.commitment),
            &plain,
        )?;
        let total = self
            .total
            .checked_add(frame.len() as u64)
            .ok_or(Error::Bounds)?;
        if total > MAX_TOTAL {
            return Err(Error::Bounds);
        }
        let head = Checkpoint {
            sequence,
            commitment: hash(b"frame", &frame),
        };
        let head_wire = seal(
            self.key,
            &aad(&self.context, 0, 0, [0; 32]),
            &head_bytes(head),
        )?;
        self.poisoned = true;
        let t = db(self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate))?;
        let old: Vec<u8> =
            db(t.query_row("SELECT head FROM store_meta WHERE id=1", [], |r| r.get(0)))?;
        if old != self.head_wire {
            return Err(Error::Stale);
        }
        db(t.execute(
            "INSERT INTO sealed_event VALUES(?1,?2)",
            params![sequence, frame],
        ))?;
        db(t.execute("UPDATE store_meta SET head=?1 WHERE id=1", [&head_wire]))?;
        crash("sealed_before_commit");
        db(t.commit())?;
        crash("sealed_after_commit");
        self.head = head;
        self.head_wire = head_wire;
        self.total = total;
        self.poisoned = false;
        let reference = EntryRef {
            sequence,
            commitment: head.commitment,
        };
        self.entries.push(PlainEntry {
            reference,
            kind,
            body: Zeroizing::new(body.to_vec()),
        });
        Ok(reference)
    }
    fn healthy(&self) -> Result<()> {
        if self.poisoned {
            Err(Error::Poisoned)
        } else {
            Ok(())
        }
    }
    fn get(&self, reference: EntryRef) -> Result<&PlainEntry> {
        self.healthy()?;
        self.entries
            .iter()
            .find(|e| e.reference == reference)
            .ok_or(Error::Context)
    }
}

/// Generic native completion/history adapter. The authoritative disk state is
/// encrypted; the existing qualified coordinator runs in an in-memory SQLite
/// database. No plaintext operational database or automatic legacy migration.
pub struct EncryptedCompletion<'k> {
    log: SealedLog<'k>,
    inner: completion::Journal,
    context: StorageContext,
    policy: CandidatePolicy,
    poisoned: bool,
}
impl<'k> EncryptedCompletion<'k> {
    pub fn create(
        path: &Path,
        key: &'k StorageKey,
        context: StorageContext,
        policy: CandidatePolicy,
    ) -> Result<Self> {
        let log = SealedLog::create(path, key, context.encode(1)?, &policy)?;
        let inner = completion::Journal::private_memory(policy.clone())?;
        Ok(Self {
            log,
            inner,
            context,
            policy,
            poisoned: false,
        })
    }
    pub fn open(
        path: &Path,
        key: &'k StorageKey,
        context: StorageContext,
        minimum: Checkpoint,
        policy: CandidatePolicy,
    ) -> Result<Self> {
        let log = SealedLog::open(path, key, context.encode(1)?, minimum, &policy)?;
        let mut inner = completion::Journal::private_memory(policy.clone())?;
        for entry in &log.entries {
            match entry.kind {
                0 => {
                    if !context.matches(&inner.restore_private_row(&entry.body)?) {
                        return Err(Error::Context);
                    }
                }
                1..=3 => {}
                _ => return Err(Error::Context),
            }
        }
        Ok(Self {
            log,
            inner,
            context,
            policy,
            poisoned: false,
        })
    }
    fn healthy(&self) -> Result<()> {
        if self.poisoned {
            return Err(Error::Poisoned);
        }
        self.log.healthy()
    }
    pub fn checkpoint(&self) -> Result<Checkpoint> {
        self.healthy()?;
        Ok(self.log.head)
    }
    fn begin(&mut self) -> Result<()> {
        self.healthy()?;
        self.poisoned = true;
        Ok(())
    }
    fn persisted(&mut self, id: Hash) -> Result<()> {
        let row = self.inner.private_row(id)?;
        self.log.append(0, &row)?;
        self.poisoned = false;
        Ok(())
    }
    fn check_context(&self, w: &tr::NativeOperation) -> Result<()> {
        if self.context.matches(&w.operation.meta.context) {
            Ok(())
        } else {
            Err(Error::Context)
        }
    }
    pub fn find_by_locked_output(&self, output: Hash) -> Result<Option<Hash>> {
        self.healthy()?;
        Ok(self.inner.find_by_locked_output(output)?)
    }
    pub fn prepare(
        &mut self,
        store: &CanonicalStore,
        funding: &tr::NativeOperation,
        path: completion::PathChoice,
        fees: completion::FeeTerms,
    ) -> Result<Hash> {
        self.check_context(funding)?;
        self.begin()?;
        let id = self.inner.prepare(store, funding, path, fees)?;
        crash("completion_prepare_after_inner");
        self.persisted(id)?;
        crash("completion_prepare_after_seal");
        Ok(id)
    }
    pub fn request_approval(
        &mut self,
        store: &CanonicalStore,
        id: Hash,
        slot: u8,
        descriptor: Vec<u8>,
    ) -> Result<completion::WalletRequest> {
        self.begin()?;
        let request = self.inner.request_approval(store, id, slot, descriptor)?;
        crash("completion_request_after_inner");
        self.persisted(id)?;
        crash("completion_request_after_seal");
        Ok(request)
    }
    pub fn reconcile_request(&self, id: Hash, slot: u8) -> Result<completion::ApprovalQuery> {
        self.healthy()?;
        Ok(self.inner.reconcile_request(id, slot)?)
    }
    pub fn accept_approval(
        &mut self,
        store: &CanonicalStore,
        id: Hash,
        slot: u8,
        signature: mutiny_crypto_v2::HybridSignature,
    ) -> Result<()> {
        self.begin()?;
        self.inner.accept_approval(store, id, slot, signature)?;
        crash("completion_approval_after_inner");
        self.persisted(id)?;
        crash("completion_approval_after_seal");
        Ok(())
    }
    pub fn signed_bytes(&self, id: Hash) -> Result<Zeroizing<Vec<u8>>> {
        self.healthy()?;
        Ok(Zeroizing::new(self.inner.signed_bytes(id)?))
    }
    pub fn dispatch(&mut self, store: &CanonicalStore, id: Hash) -> Result<CandidateSubmission> {
        self.begin()?;
        let submission = self.inner.dispatch(store, id)?;
        crash("completion_dispatch_after_inner");
        self.persisted(id)?;
        crash("completion_dispatch_after_seal");
        Ok(submission)
    }
    pub fn reconcile(
        &mut self,
        store: &CanonicalStore,
        id: Hash,
    ) -> Result<completion::Reconciliation> {
        self.begin()?;
        let result = self.inner.reconcile(store, id)?;
        crash("completion_reconcile_after_inner");
        self.persisted(id)?;
        crash("completion_reconcile_after_seal");
        Ok(result)
    }
    pub fn private_note(&mut self, body: &[u8]) -> Result<EntryRef> {
        self.healthy()?;
        self.log.append(1, body)
    }
    pub fn read_private_note(&self, reference: EntryRef) -> Result<Zeroizing<Vec<u8>>> {
        self.healthy()?;
        let e = self.log.get(reference)?;
        if e.kind != 1 {
            return Err(Error::Context);
        }
        Ok(Zeroizing::new(e.body.to_vec()))
    }
    /// Capture only an actual canonical applied operation. The export contains
    /// public chain identifiers/amounts, never preimages, signatures or fiat notes.
    pub fn capture_native_audit(&mut self, store: &CanonicalStore, id: Hash) -> Result<EntryRef> {
        self.healthy()?;
        let raw = self.inner.signed_bytes(id)?;
        let w = native(tr::NativeOperation::decode(&raw))?;
        self.check_context(&w)?;
        let AdmissionPreview::AlreadyApplied(receipt) =
            super::preview(store, raw, &self.policy).map_err(|_| Error::Context)?
        else {
            return Err(Error::Unapplied);
        };
        let (p, _, root) = store
            .execution_parent(receipt.height)
            .map_err(|_| Error::Store)?;
        let (kind, amount, recipient) = match w.operation.action {
            tr::Action::Claim {
                amount, recipient, ..
            } => (0, amount, recipient),
            tr::Action::Refund { amount, owner, .. } => (1, amount, owner),
            tr::Action::FiatRelease { amount, buyer, .. } => (2, amount, buyer),
            _ => return Err(Error::Context),
        };
        let anchor = FinalizedAnchor {
            network: self.context.network,
            genesis: p.genesis,
            fingerprint: p.fingerprint,
            height: p.height,
            block: p.block,
        };
        let mut e = Encoder::new(Vec::new());
        e.array(14)
            .unwrap()
            .bytes(b"MUTINY-OFFLINE-NATIVE-TRADE-AUDIT-V1")
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&anchor.encode())
            .unwrap()
            .bytes(&root)
            .unwrap()
            .bytes(&id)
            .unwrap()
            .bytes(&receipt.wire_hash)
            .unwrap()
            .bytes(&w.operation.meta.trade)
            .unwrap()
            .bytes(&w.operation.meta.contract)
            .unwrap()
            .u8(kind)
            .unwrap()
            .u64(amount.0)
            .unwrap()
            .bytes(&recipient)
            .unwrap()
            .u64(w.operation.meta.fee.0)
            .unwrap()
            .str("CANONICAL_NATIVE_APPLIED_EXTERNAL_PAYMENT_NOT_ASSERTED")
            .unwrap()
            .bool(false)
            .unwrap();
        self.log.append(2, &e.into_writer())
    }
    pub fn public_export(&self, reference: EntryRef) -> Result<Vec<u8>> {
        self.healthy()?;
        let e = self.log.get(reference)?;
        if !matches!(e.kind, 2 | 3) {
            return Err(Error::NotPublic);
        }
        Ok(e.body.to_vec())
    }
}

#[cfg(feature = "trading-bitcoin-candidate")]
pub mod bitcoin_headers {
    use super::*;
    use crate::trading_service_v1::bitcoin_candidate::{
        RegtestHeaders, TreasurySwapIntent,
        recovery::{RecoveryJournal, RecoveryView},
    };
    use bitcoin::{
        BlockHash,
        block::Header,
        consensus::{deserialize, serialize},
    };
    use std::collections::BTreeMap;
    pub struct HeaderStore<'k> {
        log: SealedLog<'k>,
        headers: RegtestHeaders,
        seen: BTreeMap<BlockHash, EntryRef>,
        poisoned: bool,
    }
    impl<'k> HeaderStore<'k> {
        pub fn create(
            path: &Path,
            key: &'k StorageKey,
            context: StorageContext,
            policy: &CandidatePolicy,
        ) -> Result<Self> {
            Ok(Self {
                log: SealedLog::create(path, key, context.encode(2)?, policy)?,
                headers: RegtestHeaders::new(),
                seen: BTreeMap::new(),
                poisoned: false,
            })
        }
        pub fn open(
            path: &Path,
            key: &'k StorageKey,
            context: StorageContext,
            minimum: Checkpoint,
            policy: &CandidatePolicy,
        ) -> Result<Self> {
            let log = SealedLog::open(path, key, context.encode(2)?, minimum, policy)?;
            let mut headers = RegtestHeaders::new();
            let mut seen = BTreeMap::new();
            for e in &log.entries {
                if e.kind != 4 {
                    return Err(Error::Context);
                }
                let mut d = Decoder::new(&e.body);
                arr(&mut d, 2)?;
                let now = d.u32().map_err(|_| Error::Codec)?;
                let raw = bytes(&mut d)?;
                let mut enc = Encoder::new(Vec::new());
                enc.array(2).unwrap().u32(now).unwrap().bytes(raw).unwrap();
                if d.position() != e.body.len() || enc.into_writer() != e.body.as_slice() {
                    return Err(Error::Codec);
                }
                let id = headers.insert(raw, now).map_err(|_| Error::Context)?;
                if seen.insert(id, e.reference).is_some() {
                    return Err(Error::Corrupt);
                }
            }
            Ok(Self {
                log,
                headers,
                seen,
                poisoned: false,
            })
        }
        fn healthy(&self) -> Result<()> {
            if self.poisoned {
                return Err(Error::Poisoned);
            }
            self.log.healthy()
        }
        pub fn checkpoint(&self) -> Result<Checkpoint> {
            self.healthy()?;
            Ok(self.log.head)
        }
        pub fn headers(&self) -> Result<&RegtestHeaders> {
            self.healthy()?;
            Ok(&self.headers)
        }
        pub fn insert(&mut self, raw: &[u8], now: u32) -> Result<BlockHash> {
            self.healthy()?;
            if raw.len() != 80 {
                return Err(Error::Bounds);
            }
            let h: Header = deserialize(raw).map_err(|_| Error::Codec)?;
            if serialize(&h) != raw {
                return Err(Error::Codec);
            }
            let id = h.block_hash();
            if self.seen.contains_key(&id) || id == RegtestHeaders::new().tip().0 {
                return Ok(id);
            }
            let mut next = self.headers.clone();
            next.insert(raw, now).map_err(|_| Error::Context)?;
            let mut e = Encoder::new(Vec::new());
            e.array(2).unwrap().u32(now).unwrap().bytes(raw).unwrap();
            self.poisoned = true;
            crash("header_after_validation");
            let reference = self.log.append(4, &e.into_writer())?;
            crash("header_after_seal");
            self.headers = next;
            self.seen.insert(id, reference);
            self.poisoned = false;
            Ok(id)
        }
    }
    impl EncryptedCompletion<'_> {
        pub fn capture_treasury_assessment(
            &mut self,
            journal: &mut RecoveryJournal,
            intent: &TreasurySwapIntent,
            view: RecoveryView<'_>,
        ) -> Result<EntryRef> {
            self.healthy()?;
            let assessment = journal.assess(intent, view).map_err(|_| Error::Context)?;
            let anchor = &assessment.native_anchor;
            if anchor.network != self.context.network
                || anchor.genesis != self.context.genesis
                || anchor.fingerprint != self.context.fingerprint
            {
                return Err(Error::Context);
            }
            self.log.append(3, &assessment.encode())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> CandidatePolicy {
        CandidatePolicy::native_denomination_locked()
    }
    fn context() -> StorageContext {
        StorageContext {
            network: 8,
            genesis: [1; 32],
            fingerprint: [2; 32],
            storage: [3; 32],
            key_generation: 1,
        }
    }
    fn path(label: &str) -> std::path::PathBuf {
        let root =
            std::path::PathBuf::from(std::env::var_os("BITCOIN_TRADING_EVIDENCE_DIR").unwrap());
        let p = root.join(label);
        std::fs::create_dir(&p).unwrap();
        p.join("private.sqlite")
    }
    fn key() -> StorageKey {
        StorageKey::qualification(Zeroizing::new([47; 32])).unwrap()
    }
    #[test]
    fn r6_ciphertext_integrity_rollback_context_concurrency_and_export_boundary() {
        let k = key();
        let ctx = context();
        let p = path("r6-storage-tamper");
        let mut j = EncryptedCompletion::create(&p, &k, ctx.clone(), policy()).unwrap();
        let empty = j.checkpoint().unwrap();
        let note = b"SYNTHETIC PRIVATE PAYMENT ACCOUNT 771237 AND PREIMAGE NOTE";
        let reference = j.private_note(note).unwrap();
        let first = j.checkpoint().unwrap();
        assert_eq!(j.private_note(note).unwrap(), reference);
        assert_eq!(j.public_export(reference), Err(Error::NotPublic));
        assert_eq!(j.read_private_note(reference).unwrap().as_slice(), note);
        drop(j);
        let rollback = p.with_extension("old");
        std::fs::copy(&p, &rollback).unwrap();
        let wrong = StorageKey::qualification(Zeroizing::new([48; 32])).unwrap();
        assert!(EncryptedCompletion::open(&p, &wrong, ctx.clone(), first, policy()).is_err());
        for changed in [
            StorageContext {
                genesis: [8; 32],
                ..ctx.clone()
            },
            StorageContext {
                key_generation: 2,
                ..ctx.clone()
            },
            StorageContext {
                storage: [9; 32],
                ..ctx.clone()
            },
        ] {
            assert!(EncryptedCompletion::open(&p, &k, changed, first, policy()).is_err())
        }
        assert!(SealedLog::open(&p, &k, ctx.encode(2).unwrap(), first, &policy()).is_err());
        let mut a = EncryptedCompletion::open(&p, &k, ctx.clone(), first, policy()).unwrap();
        let mut b = EncryptedCompletion::open(&p, &k, ctx.clone(), first, policy()).unwrap();
        a.private_note(b"newer private record").unwrap();
        let latest = a.checkpoint().unwrap();
        assert_eq!(b.private_note(b"stale writer"), Err(Error::Stale));
        assert!(!b.poisoned);
        assert!(b.log.poisoned); // Reproduce the reviewed nested-state defect.
        assert_eq!(b.checkpoint(), Err(Error::Poisoned));
        assert_eq!(b.read_private_note(reference), Err(Error::Poisoned));
        assert_eq!(b.public_export(reference), Err(Error::Poisoned));
        assert_eq!(b.find_by_locked_output([0; 32]), Err(Error::Poisoned));
        assert!(matches!(
            b.reconcile_request([0; 32], 0),
            Err(Error::Poisoned)
        ));
        assert_eq!(b.signed_bytes([0; 32]), Err(Error::Poisoned));
        assert_eq!(b.private_note(b"retry prohibited"), Err(Error::Poisoned));
        drop(a);
        drop(b);
        assert!(EncryptedCompletion::open(&rollback, &k, ctx.clone(), latest, policy()).is_err());
        for file in std::fs::read_dir(p.parent().unwrap()).unwrap() {
            let bytes = std::fs::read(file.unwrap().path()).unwrap();
            assert!(!bytes.windows(note.len()).any(|w| w == note));
        }
        let base = std::fs::read(&p).unwrap();
        for change in 0..5 {
            let altered = p.with_extension(format!("bad{change}"));
            std::fs::write(&altered, &base).unwrap();
            let db = Connection::open(&altered).unwrap();
            match change {
                0 => {
                    let mut frame: Vec<u8> = db
                        .query_row("SELECT frame FROM sealed_event WHERE seq=1", [], |r| {
                            r.get(0)
                        })
                        .unwrap();
                    *frame.last_mut().unwrap() ^= 1;
                    db.execute("UPDATE sealed_event SET frame=?1 WHERE seq=1", [frame])
                        .unwrap();
                }
                1 => {
                    db.execute("DELETE FROM sealed_event WHERE seq=2", [])
                        .unwrap();
                }
                2 => {
                    db.execute("UPDATE sealed_event SET frame=(SELECT frame FROM sealed_event WHERE seq=2) WHERE seq=1",[]).unwrap();
                }
                3 => {
                    db.execute("UPDATE store_meta SET head=zeroblob(length(head))", [])
                        .unwrap();
                }
                _ => {
                    let mut frame: Vec<u8> = db
                        .query_row("SELECT frame FROM sealed_event WHERE seq=1", [], |r| {
                            r.get(0)
                        })
                        .unwrap();
                    frame.push(0);
                    db.execute("UPDATE sealed_event SET frame=?1 WHERE seq=1", [frame])
                        .unwrap();
                }
            }
            drop(db);
            assert!(
                EncryptedCompletion::open(&altered, &k, ctx.clone(), empty, policy()).is_err(),
                "tamper {change}"
            );
        }
    }
    #[test]
    fn r6_strict_frame_hostile_mutations_and_published_aead_vector() {
        // Independent published vector bundled by the approved provider:
        // draft-arciszewski-xchacha-03, Appendix A.1 (provider tests/lib.rs).
        let k: Vec<u8> = (0x80..=0x9f).collect();
        let nonce: Vec<u8> = (0x40..=0x57).collect();
        let aad = hex::decode("50515253c0c1c2c3c4c5c6c7").unwrap();
        let plain=b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected=hex::decode(concat!("bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e","c0875924c1c7987947deafd8780acf49")).unwrap();
        let mut body = plain.to_vec();
        XChaCha20Poly1305::new_from_slice(&k)
            .unwrap()
            .encrypt_in_place(XNonce::from_slice(&nonce), &aad, &mut body)
            .unwrap();
        assert_eq!(body, expected);
        let key = key();
        let ad = b"exact-storage-context";
        let frame = seal(&key, ad, plain).unwrap();
        assert_eq!(unseal(&key, ad, &frame).unwrap().as_slice(), plain);
        for n in 0..frame.len() {
            let mut m = frame.clone();
            m[n] ^= 1;
            assert!(unseal(&key, ad, &m).is_err(), "bit mutation {n}");
            assert!(unseal(&key, ad, &frame[..n]).is_err());
        }
        let mut nonminimal = frame.clone();
        nonminimal.splice(1..2, [0x18, 0x01]);
        assert!(unseal(&key, ad, &nonminimal).is_err());
        assert!(unseal(&key, b"wrong context", &frame).is_err());
        assert!(seal(&key, ad, &vec![0; MAX_BODY + 33]).is_err());
        let mut x = 0x1234u32;
        for len in 0..512 {
            let mut bytes = vec![0; len];
            for b in &mut bytes {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                *b = x as u8;
            }
            assert!(std::panic::catch_unwind(|| unseal(&key, ad, &bytes)).is_ok());
        }
        let context = context().encode(1).unwrap();
        let empty = hash(b"empty", &context);
        let vectors = serde_json::json!({"context":hex::encode(&context),"empty":hex::encode(empty),"entry_aad":hex::encode(super::aad(&context,1,1,empty)),"head":hex::encode(head_bytes(Checkpoint{sequence:0,commitment:empty})),"frame":hex::encode(&frame),"commitment":hex::encode(hash(b"frame",&frame)),"aead_published_vector":true});
        std::fs::write(
            path("r6-storage-vectors").with_extension("json"),
            serde_json::to_vec_pretty(&vectors).unwrap(),
        )
        .unwrap();
    }
    #[test]
    fn r6_store_capacity_and_authenticated_malformed_rows_fail_closed() {
        let k = key();
        let ctx = context();
        let p = path("r6-storage-bounds");
        let mut log = SealedLog::create(&p, &k, ctx.encode(1).unwrap(), &policy()).unwrap();
        let min = log.head;
        assert_eq!(log.append(7, b"invalid kind"), Err(Error::Bounds));
        assert_eq!(log.append(1, &vec![0; MAX_BODY + 1]), Err(Error::Bounds));
        log.append(0, b"authenticated but malformed completion snapshot")
            .unwrap();
        drop(log);
        assert!(EncryptedCompletion::open(&p, &k, ctx.clone(), min, policy()).is_err());
        let p = path("r6-storage-limit");
        let mut log = SealedLog::create(&p, &k, ctx.encode(1).unwrap(), &policy()).unwrap();
        // Exercise the real event limit with 4096 atomic writes, no fake counts.
        for i in 0..MAX_EVENTS {
            log.append(1, &i.to_le_bytes()).unwrap();
        }
        assert_eq!(log.append(1, b"one too many"), Err(Error::Bounds));
        let end = log.head;
        drop(log);
        assert_eq!(
            SealedLog::open(&p, &k, ctx.encode(1).unwrap(), end, &policy())
                .unwrap()
                .head,
            end
        );
    }
    #[cfg(feature = "trading-bitcoin-candidate")]
    fn one_header() -> bitcoin::block::Header {
        use bitcoin::hashes::Hash as _;
        let mut h = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).header;
        h.prev_blockhash = h.block_hash();
        h.time += 600;
        h.merkle_root = bitcoin::TxMerkleNode::from_byte_array([71; 32]);
        h.nonce = 0;
        while h.validate_pow(h.target()).is_err() {
            h.nonce += 1;
        }
        h
    }
    #[cfg(feature = "trading-bitcoin-candidate")]
    #[test]
    fn r6_header_four_abrupt_publication_boundaries() {
        use bitcoin_headers::HeaderStore;
        let k = key();
        let ctx = context();
        let h = one_header();
        for phase in [
            "header_after_validation",
            "sealed_before_commit",
            "sealed_after_commit",
            "header_after_seal",
        ] {
            let p = path(&format!("r6-header-crash-{phase}"));
            let store = HeaderStore::create(&p, &k, ctx.clone(), &policy()).unwrap();
            let min = store.checkpoint().unwrap();
            drop(store);
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "trading_service_v1::local_storage_candidate::tests::header_crash_worker",
                    "--nocapture",
                ])
                .env("TRADING_STORAGE_CRASH", phase)
                .env("TRADING_HEADER_CASE", &p)
                .output()
                .unwrap();
            std::fs::write(p.with_extension("stdout.log"), result.stdout).unwrap();
            std::fs::write(p.with_extension("stderr.log"), result.stderr).unwrap();
            assert_eq!(result.status.code(), Some(86), "{phase}");
            let mut store = HeaderStore::open(&p, &k, ctx.clone(), min, &policy()).unwrap();
            let committed = matches!(phase, "sealed_after_commit" | "header_after_seal");
            assert_eq!(
                store.checkpoint().unwrap().sequence,
                if committed { 1 } else { 0 }
            );
            if committed {
                assert_eq!(store.headers().unwrap().tip().0, h.block_hash());
            }
            store
                .insert(&bitcoin::consensus::serialize(&h), h.time)
                .unwrap();
            assert_eq!(store.checkpoint().unwrap().sequence, 1);
            assert_eq!(store.headers().unwrap().tip().0, h.block_hash());
        }
    }
    #[cfg(feature = "trading-bitcoin-candidate")]
    #[test]
    #[ignore = "subprocess entry for four header persistence boundaries"]
    fn header_crash_worker() {
        let p = std::path::PathBuf::from(std::env::var_os("TRADING_HEADER_CASE").unwrap());
        let k = key();
        let ctx = context();
        let min = Checkpoint {
            sequence: 0,
            commitment: hash(b"empty", &ctx.encode(2).unwrap()),
        };
        let mut store = bitcoin_headers::HeaderStore::open(&p, &k, ctx, min, &policy()).unwrap();
        let h = one_header();
        store
            .insert(&bitcoin::consensus::serialize(&h), h.time)
            .unwrap();
        panic!("crash point not reached");
    }
}

#[cfg(feature = "trading-bitcoin-candidate")]
#[path = "trading_legacy_storage_v1.rs"]
pub mod legacy_candidate;
