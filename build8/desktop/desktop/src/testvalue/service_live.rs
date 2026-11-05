//! NON-SHIPPING live B1 acceptance caller (TEST-VALUE only): the Desktop side of Forge's
//! `--test-value-live-node` two-phase run. It drives `service_acceptance::run` (the wallet Service,
//! never direct Controller turns) against the real node over one pinned wallet Transport identity that
//! lives for this whole process (initial Service and the in-process restarted Service).
//!
//! Start: `--service-acceptance-live --root <absolute new folder> [--command-spool]`. It creates the folder, a fresh
//! in-memory Transport key, first a public `process` record (pid, image path and SHA-256, argv; for
//! correlation only), then ONLY its public key descriptor (`wallet_transport_descriptor`); that
//! value is what the node is started with. Then plain stdin lines, one per step, each answered by JSON:
//!   trust <absolute application.json> <sha256>   the node's published public trust bundle (sibling files)
//!   node <ip:port> <node transport descriptor hex>
//!   pay <recipient 32-byte hex> <atoms>           starts the flow (target own height 100, next block 101)
//!   connect                                        after each `ready_to_connect`, once the node side has
//!                                                  sent its `attach` (first time: after IdleAt100)
//!   retired true <request id> <sequence> <session id hex> <peer id hex>
//!                                                  relayed from the node's own `retired` event
//!                                                  (restart_barrier=true) for the session it names
//!   quit
//! With `--command-spool` the same lines come from files instead of stdin, so one operator can feed this
//! still-running process over existing authenticated file operations: the process creates
//! `<root>\spool` and announces it; each command is ONE file `<id>.cmd` (canonical positive id, strictly
//! increasing; write it as `<id>.tmp` then rename) holding one printable ASCII line of at most 4096
//! bytes (the stdin bound; a node line is about 3.9 KB). The process polls every 100 ms (at most 1024
//! folder entries, each a plain file named `<id>.cmd|tmp|done|ack|ack.tmp`), reads the command through
//! its opened handle within the bound, renames it to `<id>.done` and writes the receipt `<id>.ack`
//! (JSON: id, line_sha256, received_utc) by rename; a stale or reused id, a bad name, type, size or
//! content refuses the run. The receipt is INTAKE only: it is written before the line is parsed, it
//! never authorizes a next phase, a payment outcome, a retirement or the node's finish, and `.done`
//! plus `.ack` are not one durable transaction (no fsync claimed); an ambiguous delivery means stop
//! and reconcile read-only, never replay. Events stay on stdout and `<root>\events.jsonl`.
//! After `quiesced` for a session the operator sends the node `retire` with that session's fields from
//! the node's `attached` event, and relays the node's `retired` line here. The relayed session id must
//! equal this wallet's own admitted session id for that connection and the peer id must be this wallet's
//! Transport identity; request ids and sequences must be canonical, positive and strictly increasing.
//! The relayed record is kept as relayed node evidence, not Desktop proof. After `flow_complete` the
//! operator sends the node `finish` (terminal); `shutdown` is the node's cancellation path only.
//! Every event goes to stdout and `<root>/events.jsonl`; a failed log write is reported and fails the
//! run. The stdin reader thread is detached and ends at process exit. No key, password, vault or spending descriptor
//! is printed. The TEST vault uses the public TEST phrase (the fixture's reward owner) and the public
//! TEST password; both are synthetic public test vectors.
use crate::{
    joint_host,
    node_link::{self, NodeSession},
    service_acceptance::{self, HistoryConnector, Plan, RetirementBarrier},
    store_v2::Store,
    verified_sync_v2::Replica,
    wallet_controller_v2::{Controller, OwnerLock, VaultRoot, host::WalletPeer},
    wallet_v2::Session,
};
use mutiny_consensus_v8::{
    Hash, anchors::FinalizedAnchor, canonical_store_v2::CanonicalStore, execution::State, mempool_v2::Mempool,
};
use mutinyd_v8::{genesis_artifact_v2::VerifiedGenesisV2, hybrid_peer_admission_v2::Registry};
use serde_json::{Value, json};
use std::{
    io::{BufRead, Read, Write},
    path::{Path, PathBuf},
    sync::mpsc,
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, String>;
const MAX_LINE: usize = 4096;
const HANDSHAKE: Duration = Duration::from_secs(30);
/// One overall bound for the whole Desktop flow (the node owner keeps its own original limits).
const FLOW: Duration = Duration::from_secs(3600);
const TARGET_HEIGHT: u64 = 100;

struct Log {
    file: Box<dyn Write>,
    /// The first durable-log write failure, if any; reported and fails the run.
    failed: Option<String>,
}
impl Log {
    fn emit(&mut self, event: Value) {
        let line = event.to_string();
        println!("{line}");
        if let Err(e) = writeln!(self.file, "{line}").and_then(|()| self.file.flush()) {
            if self.failed.is_none() {
                self.failed = Some(e.to_string());
            }
        }
    }
}

/// Operator lines from one reader thread (stdin or the command spool); every wait is bounded by the
/// flow deadline. A reader failure arrives as Err and refuses the run.
struct Input {
    rx: mpsc::Receiver<std::result::Result<String, String>>,
}
impl Input {
    fn line(&self, deadline: Instant) -> Result<String> {
        // A line already queued is never accepted once the deadline has passed.
        if Instant::now() >= deadline {
            return Err("deadline reached waiting for an operator line".into());
        }
        let left = deadline.saturating_duration_since(Instant::now());
        match self.rx.recv_timeout(left) {
            Ok(Ok(_)) if Instant::now() >= deadline => Err("deadline reached waiting for an operator line".into()),
            Ok(Ok(line)) => Ok(line.trim_end_matches(['\r', '\n']).to_owned()),
            Ok(Err(reason)) => Err(format!("command input refused: {reason}")),
            Err(mpsc::RecvTimeoutError::Timeout) => Err("deadline reached waiting for an operator line".into()),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err("stdin closed".into()),
        }
    }
}
/// The spool carries the same bounded grammar as stdin (a node line with its public descriptor is
/// about 3.9 KB). The native node's own command bound, wire, sessions and deadlines are not involved.
const SPOOL_LINE: usize = MAX_LINE;
/// At most this many folder entries are examined per poll (a private single-operator folder).
const SPOOL_ENTRIES: usize = 1024;
const SPOOL_POLL: Duration = Duration::from_millis(100);
/// A plain file: not a folder, symbolic link or other reparse point.
fn plain_file(meta: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    let reparse = {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes() & 0x400 != 0
    };
    #[cfg(not(windows))]
    let reparse = false;
    meta.is_file() && !meta.file_type().is_symlink() && !reparse
}
/// The next command from the spool: the lowest canonical id above `last`. Every entry (cmd, tmp,
/// done, ack, ack.tmp) must be a plain file named `<canonical id>.<kind>`; the folder is enumerated
/// within a fixed bound and the command is read through its opened handle within the line bound.
/// The file is renamed to `<id>.done` and its receipt written before the line is returned. The
/// receipt is INTAKE only (written before parsing); it authorizes nothing. Anything unexpected refuses.
fn spool_next(dir: &Path, last: u64) -> Result<Option<(u64, String)>> {
    let mut next: Option<u64> = None;
    for (count, entry) in std::fs::read_dir(dir).map_err(|e| format!("spool: {e}"))?.enumerate() {
        if count >= SPOOL_ENTRIES {
            return Err(format!("spool: more than {SPOOL_ENTRIES} entries"));
        }
        let entry = entry.map_err(|e| format!("spool: {e}"))?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("spool: non-UTF-8 file name")?;
        let (stem, kind) = name.split_once('.').ok_or_else(|| format!("spool: unexpected file {name:?}"))?;
        if !matches!(kind, "cmd" | "tmp" | "ack" | "done" | "ack.tmp") {
            return Err(format!("spool: unexpected file {name:?}"));
        }
        let id = positive(stem, "spool entry id")?;
        if !plain_file(&entry.metadata().map_err(|e| format!("spool: {e}"))?) {
            return Err(format!("spool: {name:?} is not a plain file"));
        }
        if kind != "cmd" {
            continue;
        }
        if id <= last {
            return Err(format!("spool: stale or reused command id {id} (last {last})"));
        }
        next = Some(next.map_or(id, |n| n.min(id)));
    }
    let Some(id) = next else { return Ok(None) };
    let path = dir.join(format!("{id}.cmd"));
    let raw = {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(0x0020_0000); // FILE_FLAG_OPEN_REPARSE_POINT: never follow one
        }
        let file = options.open(&path).map_err(|e| format!("spool: {e}"))?;
        if !plain_file(&file.metadata().map_err(|e| format!("spool: {e}"))?) {
            return Err(format!("spool: command {id} is not a plain file"));
        }
        let mut raw = Vec::new();
        file.take(SPOOL_LINE as u64 + 3).read_to_end(&mut raw).map_err(|e| format!("spool: {e}"))?;
        if raw.len() > SPOOL_LINE + 2 {
            return Err(format!("spool: command {id} exceeds {SPOOL_LINE} bytes"));
        }
        raw
    };
    let body = raw.strip_suffix(b"\r\n").or_else(|| raw.strip_suffix(b"\n")).unwrap_or(&raw);
    if body.is_empty() || body.len() > SPOOL_LINE || body.iter().any(|b| !(0x20..0x7f).contains(b)) {
        return Err(format!("spool: command {id} must be one printable ASCII line of at most {SPOOL_LINE} bytes"));
    }
    let line = String::from_utf8(body.to_vec()).map_err(|_| "spool: not ASCII")?;
    // Never overwrite: an existing done/ack/receipt-temp for this id refuses (no replay, no repair).
    let (done, ack, tmp) = (dir.join(format!("{id}.done")), dir.join(format!("{id}.ack")), dir.join(format!("{id}.ack.tmp")));
    if [&done, &ack, &tmp].iter().any(|p| p.symlink_metadata().is_ok()) {
        return Err(format!("spool: command {id} already has a done/ack entry"));
    }
    std::fs::rename(&path, &done).map_err(|e| format!("spool: {e}"))?;
    let receipt = json!({"id":id,"line_sha256":hex::encode(<sha2::Sha256 as sha2::Digest>::digest(body)),
        "received_utc":format!("{:?}", std::time::SystemTime::now())});
    let mut file = std::fs::File::create_new(&tmp).map_err(|e| format!("spool receipt: {e}"))?;
    file.write_all(receipt.to_string().as_bytes()).map_err(|e| format!("spool receipt: {e}"))?;
    drop(file);
    if ack.symlink_metadata().is_ok() {
        return Err(format!("spool: command {id} receipt appeared concurrently"));
    }
    std::fs::rename(&tmp, &ack).map_err(|e| format!("spool receipt: {e}"))?;
    Ok(Some((id, line)))
}
fn positive(text: &str, what: &str) -> Result<u64> {
    let value: u64 = text.parse().map_err(|_| format!("{what}: canonical positive integer required"))?;
    if value == 0 || value.to_string() != text {
        return Err(format!("{what}: canonical positive integer required"));
    }
    Ok(value)
}
fn hash(text: &str) -> Result<Hash> {
    if text.len() != 64 || text.bytes().any(|b| !matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err("64 lowercase hex characters required".into());
    }
    hex::decode(text).map_err(|e| e.to_string())?.try_into().map_err(|_| "32 bytes required".into())
}

/// Parsed operator lines (kept separate so the grammar is unit tested).
#[derive(Debug, PartialEq, Eq)]
enum Line {
    Trust(PathBuf, Hash),
    Node(String, String),
    Pay(Hash, u64),
    Connect,
    Retired { request: u64, sequence: u64, session: Hash, peer: Hash },
    Quit,
}
fn parse(line: &str) -> Result<Line> {
    let words: Vec<&str> = line.split(' ').collect();
    Ok(match words.as_slice() {
        ["trust", path, pin] => {
            let path = PathBuf::from(path);
            if !path.is_absolute() {
                return Err("trust: absolute application.json path required".into());
            }
            Line::Trust(path, hash(pin)?)
        }
        ["node", address, descriptor] => Line::Node((*address).into(), (*descriptor).into()),
        ["pay", recipient, atoms] => Line::Pay(hash(recipient)?, positive(atoms, "pay atoms")?),
        ["connect"] => Line::Connect,
        ["retired", "true", request, sequence, session, peer] => Line::Retired {
            request: positive(request, "retired request id")?,
            sequence: positive(sequence, "retired sequence")?,
            session: hash(session)?,
            peer: hash(peer)?,
        },
        ["quit"] => Line::Quit,
        _ => return Err(format!("unrecognised line {line:?}")),
    })
}

struct Connector<'a> {
    key: &'a mutiny_crypto_v2::HybridKey,
    session: NodeSession,
    input: &'a Input,
    log: &'a std::cell::RefCell<Log>,
    /// Each connection's registry lives as long as the process (the peer is checked against it).
    registries: Vec<Registry>,
    /// The admitted session id of each connection, by session ordinal (for the retirement check).
    sessions: &'a std::cell::RefCell<Vec<(u32, Hash)>>,
}
impl HistoryConnector for Connector<'_> {
    fn connect(&mut self, session: u32, deadline: Instant) -> Result<WalletPeer> {
        self.log.borrow_mut().emit(json!({"event":"ready_to_connect","session":session}));
        match parse(&self.input.line(deadline)?)? {
            Line::Connect => {}
            Line::Quit => return Err("quit requested".into()),
            other => return Err(format!("connect expected, got {other:?}")),
        }
        // The handshake budget never runs past the original deadline.
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("deadline reached before connecting".into());
        }
        let connection = self.session.connect(self.key, HANDSHAKE.min(left))?;
        let (mut peer, registry) = connection.into_parts();
        self.registries.push(registry);
        if Instant::now() >= deadline {
            return Err("deadline reached during the handshake".into());
        }
        let (session_id, node_peer) = peer.history_session_identity().map_err(|e| format!("{e:?}"))?;
        self.sessions.borrow_mut().push((session, session_id));
        self.log.borrow_mut().emit(json!({"event":"connected","session":session,"session_id":hex::encode(session_id),
            "node_peer_id":hex::encode(node_peer),"link":format!("{:?}", self.session.state())}));
        Ok(peer)
    }
}
struct Barrier<'a> {
    input: &'a Input,
    log: &'a std::cell::RefCell<Log>,
    sessions: &'a std::cell::RefCell<Vec<(u32, Hash)>>,
    /// This wallet's Transport identity as the node sees it (the `peer id` of its records).
    own: Hash,
    /// The last accepted (request id, sequence); both must strictly increase.
    last: Option<(u64, u64)>,
}
impl RetirementBarrier for Barrier<'_> {
    fn await_retired(&mut self, session: u32, deadline: Instant) -> Result<Value> {
        self.log.borrow_mut().emit(json!({"event":"awaiting_node_retirement","session":session}));
        match parse(&self.input.line(deadline)?)? {
            // Relayed from the node owner's own `retired` event (restart_barrier=true, native join Ok);
            // the Desktop checks only its exact form and freshness, so it is recorded as relayed.
            Line::Retired { request, sequence, session: id, peer } => {
                let expected = self.sessions.borrow().iter().find(|(ordinal, _)| *ordinal == session).map(|(_, id)| *id);
                if expected != Some(id) {
                    return Err("relayed retirement names a different session than this connection's".into());
                }
                if peer != self.own {
                    return Err("relayed retirement names a different wallet peer".into());
                }
                if let Some((last_request, last_sequence)) = self.last {
                    if request <= last_request || sequence <= last_sequence {
                        return Err("relayed retirement is stale (request id and sequence must increase)".into());
                    }
                }
                self.last = Some((request, sequence));
                Ok(json!({"relayed_from_node":true,"restart_barrier":true,"session":session,"request_id":request,
                    "sequence":sequence,"session_id":hex::encode(id),"peer_id":hex::encode(peer)}))
            }
            Line::Quit => Err("quit requested".into()),
            other => Err(format!("retired line expected, got {other:?}")),
        }
    }
}

/// The trusted Genesis values the wallet's own chain store is opened with.
pub(crate) struct ChainPin<'a> {
    pub(crate) anchor: FinalizedAnchor,
    pub(crate) state: &'a State,
    pub(crate) root: Hash,
    pub(crate) t0: u64,
    pub(crate) target: Hash,
}
impl<'a> ChainPin<'a> {
    fn of(verified: &'a VerifiedGenesisV2) -> Self {
        let g = &verified.genesis;
        Self { anchor: g.anchor(), state: &g.state, root: g.root, t0: g.t0, target: g.target }
    }
}

/// The full wallet root (vault, chain and pool, all under `vault`) opened under an owner the caller
/// took FIRST (`VaultRoot::take_owner`) and keeps for as long as it uses this root. `trace` records
/// each step before it runs (instrumentation for the same-root witness; no content).
pub(crate) fn open_wallet(owner: &OwnerLock, vault: &VaultRoot, pin: &ChainPin, trace: &mut dyn FnMut(&'static str)) -> Result<Controller> {
    if owner.root() != vault.path() {
        return Err("the wallet owner lock belongs to another root".into());
    }
    trace("chain_store_open");
    let chain = CanonicalStore::open_trusted_genesis(&vault.path().join("public-chain.sqlite"), &pin.anchor, pin.state, pin.root, pin.t0, pin.target)
        .map_err(|e| format!("wallet chain: {e:?}"))?;
    trace("pool_store_open");
    let pool = Mempool::open(&vault.path().join("public-payment-pool.sqlite"), pin.anchor.genesis, pin.anchor.fingerprint, 65536)
        .map_err(|e| format!("wallet pool: {e:?}"))?;
    trace("controller_open_owned");
    Controller::open_owned(owner.clone(), vault, Replica::from_pinned_chain(chain)?, pool, None)
}

pub fn run_if_requested() -> Option<eframe::Result> {
    let values: Vec<String> = std::env::args().skip(1).collect();
    if values.first().map(String::as_str) != Some("--service-acceptance-live") {
        return None;
    }
    Some(run(&values).map_err(|e| eframe::Error::AppCreation(e.into())))
}

fn run(values: &[String]) -> Result<()> {
    if mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED || mutiny_crypto_v2::RELEASE_CUSTODY_ENABLED {
        return Err("the live TEST caller requires closed production gates".into());
    }
    let usage = "usage: --service-acceptance-live --root <absolute new folder> [--command-spool]";
    let (flag, root, spool) = match values {
        [_, flag, root] => (flag, root, false),
        [_, flag, root, spool] if spool == "--command-spool" => (flag, root, true),
        _ => return Err(usage.into()),
    };
    if flag != "--root" {
        return Err(usage.into());
    }
    let root = PathBuf::from(root);
    if !root.is_absolute() || root.exists() {
        return Err("--root must be a new absolute folder".into());
    }
    if !mutiny_consensus_v8::submission_pool_v1::private_directory(&root).map_err(|e| format!("{e:?}"))? {
        return Err("root folder was not newly created".into());
    }
    let log = std::cell::RefCell::new(Log {
        file: Box::new(std::fs::File::create_new(root.join("events.jsonl")).map_err(|e| e.to_string())?),
        failed: None,
    });
    // Public process self-report for correlation with the owner's OS records (the owner's records
    // decide; this line alone proves nothing): own pid, image path and SHA-256, and the TEST argv.
    let image = std::env::current_exe().map_err(|e| e.to_string())?;
    let image_sha256 = {
        use sha2::{Digest, Sha256};
        let mut file = std::fs::File::open(&image).map_err(|e| e.to_string())?;
        let mut hasher = Sha256::new();
        std::io::copy(&mut file, &mut hasher).map_err(|e| e.to_string())?;
        hex::encode(hasher.finalize())
    };
    log.borrow_mut().emit(json!({"event":"process","pid":std::process::id(),"image":image.display().to_string(),
        "image_sha256":image_sha256,"argv":values,"class":"TEST-VALUE"}));
    // One Transport identity for this whole process; only its public descriptor leaves it.
    let key = mutiny_crypto_v2::HybridKey::generate(mutiny_crypto_v2::Role::Transport).map_err(|e| format!("{e:?}"))?;
    let descriptor = hex::encode(key.public().descriptor(1).map_err(|e| format!("{e:?}"))?);
    log.borrow_mut().emit(json!({"event":"wallet_transport_descriptor","descriptor":descriptor}));

    let deadline = Instant::now() + FLOW;
    let (tx, rx) = mpsc::sync_channel::<std::result::Result<String, String>>(1);
    if spool {
        let dir = root.join("spool");
        if !mutiny_consensus_v8::submission_pool_v1::private_directory(&dir).map_err(|e| format!("{e:?}"))? {
            return Err("spool folder was not newly created".into());
        }
        log.borrow_mut().emit(json!({"event":"command_spool","path":dir.display().to_string(),"max_line":SPOOL_LINE,"poll_ms":100}));
        // Bounded by the same deadline plus cleanup; ends when the flow stops listening.
        let stop = deadline + Duration::from_secs(30);
        std::thread::spawn(move || {
            let mut last = 0;
            while Instant::now() < stop {
                match spool_next(&dir, last) {
                    Ok(Some((id, line))) => {
                        last = id;
                        if tx.send(Ok(line)).is_err() {
                            return;
                        }
                    }
                    Ok(None) => std::thread::sleep(SPOOL_POLL),
                    Err(reason) => {
                        let _ = tx.send(Err(reason));
                        return;
                    }
                }
            }
        });
    } else {
        std::thread::spawn(move || {
            let stdin = std::io::stdin();
            let mut reader = stdin.lock();
            loop {
                let mut line = Vec::new();
                match reader.by_ref().take(MAX_LINE as u64 + 1).read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) if line.len() > MAX_LINE => {
                        let _ = tx.send(Err("stdin line exceeds its bound".into()));
                        break;
                    }
                    Ok(_) => {
                        if tx.send(Ok(String::from_utf8_lossy(&line).into_owned())).is_err() {
                            break;
                        }
                    }
                }
            }
        });
    }
    let input = Input { rx };
    let result = (|| -> Result<Hash> {
        let Line::Trust(config, pin) = parse(&input.line(deadline)?)? else { return Err("trust line expected first".into()) };
        let verified = joint_host::genesis(&config, pin)?;
        let anchor = verified.genesis.anchor();
        log.borrow_mut().emit(json!({"event":"trust_verified","class":"TEST-VALUE","genesis":hex::encode(anchor.genesis),
            "fingerprint":hex::encode(anchor.fingerprint),"h0_block":hex::encode(anchor.block),
            "artifact_sha256":hex::encode(verified.artifact_sha256)}));
        let Line::Node(address, node_descriptor) = parse(&input.line(deadline)?)? else { return Err("node line expected".into()) };
        let node = node_link::parse_node(&address, &node_descriptor)?;
        let Line::Pay(recipient, atoms) = parse(&input.line(deadline)?)? else { return Err("pay line expected".into()) };
        // A fresh TEST vault holding the public TEST phrase (the fixture's reward owner).
        let vault_path = root.join("vault");
        if !mutiny_consensus_v8::submission_pool_v1::private_directory(&vault_path).map_err(|e| format!("{e:?}"))? {
            return Err("vault folder was not newly created".into());
        }
        let vault = VaultRoot::new(&vault_path).map_err(|e| e.to_string())?;
        // The lifetime owner of this whole root, taken before any store in it is opened and held
        // until this process has closed them all (both Services included).
        let owner = vault.take_owner()?;
        log.borrow_mut().emit(json!({"event":"wallet_owner_acquired","root":"vault"}));
        let mut store = Store::open(&vault.vault()).map_err(|e| e.to_string())?;
        let session = Session::restore_initial(&crate::chain::phrase(false)).map_err(str::to_owned)?;
        store.save_initial(&session, joint_host::PASSWORD).map_err(str::to_owned)?;
        drop(session);
        drop(store);
        let sessions = std::cell::RefCell::new(Vec::new());
        let own = mutiny_transport_v2::Endpoint::pinned(key.public().clone(), 1).map_err(|e| format!("{e:?}"))?.id();
        let mut connector = Connector {
            key: &key,
            session: NodeSession::history(anchor.genesis, anchor.fingerprint, node, vault_path.join("public-history-queue.sqlite")),
            input: &input,
            log: &log,
            registries: Vec::new(),
            sessions: &sessions,
        };
        let mut barrier = Barrier { input: &input, log: &log, sessions: &sessions, own, last: None };
        let plan = Plan { target_height: TARGET_HEIGHT, recipient, atoms, deadline };
        let pin = ChainPin::of(&verified);
        let mut open = || open_wallet(&owner, &vault, &pin, &mut |_| {});
        service_acceptance::run(&mut open, joint_host::PASSWORD, &mut connector, &mut barrier, &plan, &mut |record| {
            log.borrow_mut().emit(json!({"event":"flow","record":record}))
        })
    })();
    conclude(&log, result).map(|_| ())
}

/// The terminal record and the run's final result. The log's write/flush outcome, INCLUDING the terminal
/// record's own write, decides: any log failure turns an otherwise successful flow into Err (no finish
/// authority), and a refusal stays a refusal with its primary cause plus the log failure. A failed terminal
/// write is reported on stderr only; that record is not claimed as durable. The payment is never retried.
fn conclude(log: &std::cell::RefCell<Log>, result: Result<Hash>) -> Result<Hash> {
    let before = log.borrow().failed.clone();
    match &result {
        Ok(id) if before.is_none() => log.borrow_mut().emit(json!({"event":"flow_complete","payment":hex::encode(id),
            "witness":"synthetic Service review inputs","desktop_service_verified":true,"ui_verified":false,"production_eligible":false,
            "stdin_reader":"detached; ends at process exit","next_node_command":"finish"})),
        Ok(_) => log.borrow_mut().emit(json!({"event":"flow_refused","reason":"durable event log write failed earlier",
            "production_eligible":false,"stdin_reader":"detached; ends at process exit","next_node_command":"shutdown (cancellation)"})),
        Err(reason) => log.borrow_mut().emit(json!({"event":"flow_refused","reason":reason,"earlier_log_failure":before.is_some(),
            "production_eligible":false,"stdin_reader":"detached; ends at process exit","next_node_command":"shutdown (cancellation)"})),
    }
    let after = log.borrow().failed.clone();
    if let Some(failure) = &after {
        eprintln!("{}", json!({"event":"durable_log_failed","error":failure,"terminal_record_not_durable":before.is_none()}));
    }
    match (result, after) {
        (Ok(_), Some(failure)) => Err(format!("durable event log write failed: {failure}")),
        (Err(reason), Some(failure)) => Err(format!("{reason}; durable event log write also failed: {failure}")),
        (result, None) => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet_controller_v2::host::service::{Command, Event, Service};

    #[test]
    fn a_relayed_retirement_must_name_this_connections_session_and_this_wallet_and_be_fresh() {
        let dir = std::env::temp_dir().join(format!("service-live-barrier-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = std::cell::RefCell::new(Log { file: Box::new(std::fs::File::create(dir.join("events.jsonl")).unwrap()), failed: None });
        let sessions = std::cell::RefCell::new(vec![(1u32, [0x11; 32]), (2u32, [0x22; 32])]);
        let (tx, rx) = mpsc::sync_channel::<std::result::Result<String, String>>(8);
        let input = Input { rx };
        let mut barrier = Barrier { input: &input, log: &log, sessions: &sessions, own: [0x0a; 32], last: None };
        let deadline = Instant::now() + Duration::from_secs(5);
        let (s1, s2, me, other) = ("11".repeat(32), "22".repeat(32), "0a".repeat(32), "0b".repeat(32));
        for line in [format!("retired true 5 2 {s2} {me}"), format!("retired true 5 2 {s1} {other}")] {
            tx.send(Ok(line)).unwrap();
            assert!(barrier.await_retired(1, deadline).is_err(), "wrong session or wrong wallet");
        }
        tx.send(Ok(format!("retired true 5 2 {s1} {me}"))).unwrap();
        let ack = barrier.await_retired(1, deadline).unwrap();
        assert_eq!(ack["relayed_from_node"], true);
        assert_eq!(ack["request_id"], 5);
        tx.send(Ok(format!("retired true 5 3 {s2} {me}"))).unwrap();
        assert!(barrier.await_retired(2, deadline).is_err(), "request id must increase");
        tx.send(Ok(format!("retired true 6 2 {s2} {me}"))).unwrap();
        assert!(barrier.await_retired(2, deadline).is_err(), "sequence must increase");
        tx.send(Ok(format!("retired true 6 3 {s2} {me}"))).unwrap();
        assert_eq!(barrier.await_retired(2, deadline).unwrap()["sequence"], 3);
        drop(log);
        std::fs::remove_dir_all(&dir).unwrap();
    }
    /// A writer that fails its Nth write (0-based) or its Nth flush.
    struct Faulty {
        writes: usize,
        flushes: usize,
        fail_write: Option<usize>,
        fail_flush: Option<usize>,
    }
    impl Write for Faulty {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let n = self.writes;
            self.writes += 1;
            if Some(n) == self.fail_write { Err(std::io::Error::other("injected write failure")) } else { Ok(buf.len()) }
        }
        fn flush(&mut self) -> std::io::Result<()> {
            let n = self.flushes;
            self.flushes += 1;
            if Some(n) == self.fail_flush { Err(std::io::Error::other("injected flush failure")) } else { Ok(()) }
        }
    }
    fn log(fail_write: Option<usize>, fail_flush: Option<usize>) -> std::cell::RefCell<Log> {
        std::cell::RefCell::new(Log { file: Box::new(Faulty { writes: 0, flushes: 0, fail_write, fail_flush }), failed: None })
    }

    #[test]
    fn the_final_result_includes_every_log_failure_including_the_terminal_record() {
        // All writes succeed: the flow result stands.
        assert_eq!(conclude(&log(None, None), Ok([7; 32])), Ok([7; 32]));
        // Terminal write failure on a fresh log (its first and only record).

        assert!(conclude(&log(Some(0), None), Ok([7; 32])).is_err(), "terminal write failure");
        // Terminal flush failure.
        assert!(conclude(&log(None, Some(0)), Ok([7; 32])).is_err(), "terminal flush failure");
        // Earlier failure (first record's flush), terminal fine.
        let l = log(None, Some(0));
        l.borrow_mut().emit(json!({"event":"earlier"}));
        assert!(conclude(&l, Ok([7; 32])).is_err(), "earlier log failure");
        // An existing refusal stays a refusal and keeps its cause, with the log failure added.
        let refused = conclude(&log(None, Some(0)), Err("node session expired".into())).unwrap_err();
        assert!(refused.starts_with("node session expired"), "{refused}");
        assert!(refused.contains("log write also failed"), "{refused}");
        // A refusal with a working log is unchanged.
        assert_eq!(conclude(&log(None, None), Err("x".into())), Err("x".into()));
    }

    #[test]
    fn the_command_spool_takes_increasing_single_line_files_and_writes_receipts() {
        let dir = std::env::temp_dir().join(format!("service-live-spool-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(spool_next(&dir, 0).unwrap(), None);
        std::fs::write(dir.join("2.cmd"), "connect\n").unwrap();
        std::fs::write(dir.join("1.cmd"), "pay x 5\r\n").unwrap();
        std::fs::write(dir.join("3.tmp"), "half written").unwrap();
        assert_eq!(spool_next(&dir, 0).unwrap(), Some((1, "pay x 5".into())));
        assert!(dir.join("1.done").exists() && dir.join("1.ack").exists() && !dir.join("1.cmd").exists());
        let receipt: Value = serde_json::from_slice(&std::fs::read(dir.join("1.ack")).unwrap()).unwrap();
        assert_eq!(receipt["id"], 1);
        assert_eq!(spool_next(&dir, 1).unwrap(), Some((2, "connect".into())));
        // A reused id, a non-canonical id, an unknown file, an oversize or multi-line command refuse.
        for (name, body) in [("2.cmd", "connect"), ("04.cmd", "connect"), ("notes.txt", "x"),
            ("5.cmd", &"x".repeat(SPOOL_LINE + 1)[..]), ("6.cmd", "connect\nquit"), ("7.cmd", "connect\r"),
            ("8.cmd", ""), ("9.cmd", "pay\tx"), ("x.tmp", "x"), ("07.done", "x"), ("10.cmd.bak", "x")] {
            let probe = dir.join(name);
            std::fs::write(&probe, body).unwrap();
            assert!(spool_next(&dir, 2).is_err(), "{name}");
            std::fs::remove_file(&probe).unwrap();
        }
        // A receipt that already exists for a new id is never overwritten: the command is not taken.
        std::fs::write(dir.join("3.ack"), "{}").unwrap();
        std::fs::write(dir.join("3.cmd"), "connect").unwrap();
        assert!(spool_next(&dir, 2).is_err());
        assert!(dir.join("3.cmd").exists() && !dir.join("3.done").exists());
        // A line already queued is refused once the deadline has passed.
        let (tx, rx) = mpsc::sync_channel::<std::result::Result<String, String>>(1);
        tx.send(Ok("connect".into())).unwrap();
        assert!(Input { rx }.line(Instant::now()).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The actual-length node line: Forge's PUBLIC fixture from the already-CLOSED Linux startup/cancel
    /// run (3915-byte body + LF, 3890-hex descriptor). A size/grammar vector only, never current trust.
    #[test]
    fn a_real_length_node_line_passes_through_the_spool_and_the_grammar_and_the_bound_is_exact() {
        use sha2::{Digest, Sha256};
        const FIXTURE: &[u8] = include_bytes!("fixtures/closed-smoke-public-node-command.txt");
        assert_eq!(FIXTURE.len(), 3916);
        assert_eq!(hex::encode(Sha256::digest(&FIXTURE[..3915])), "110b6872dc4c24474c1e629a2b947ac7197256699477acec71f3ce9def922ffc");
        let dir = std::env::temp_dir().join(format!("service-live-spool-real-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("1.tmp"), FIXTURE).unwrap();
        std::fs::rename(dir.join("1.tmp"), dir.join("1.cmd")).unwrap();
        let (id, line) = spool_next(&dir, 0).unwrap().unwrap();
        assert_eq!((id, line.len()), (1, 3915));
        let receipt: Value = serde_json::from_slice(&std::fs::read(dir.join("1.ack")).unwrap()).unwrap();
        assert_eq!(receipt["line_sha256"], "110b6872dc4c24474c1e629a2b947ac7197256699477acec71f3ce9def922ffc");
        let Line::Node(address, descriptor) = parse(&line).unwrap() else { panic!("node line expected") };
        assert_eq!((address.as_str(), descriptor.len()), ("192.168.68.58:49735", 3890));
        assert_eq!(hex::encode(Sha256::digest(descriptor.as_bytes())), "432dedbabbccec6463192600478e41da2182dae707398b854df452dd4b83ad2a");
        node_link::parse_node(&address, &descriptor).expect("a well-formed public node descriptor");
        // The same line over CRLF; then exactly the bound accepted and one byte more refused.
        let mut crlf = FIXTURE[..3915].to_vec();
        crlf.extend_from_slice(b"\r\n");
        std::fs::write(dir.join("2.cmd"), &crlf).unwrap();
        assert_eq!(spool_next(&dir, 1).unwrap().unwrap(), (2, line.clone()));
        std::fs::write(dir.join("3.cmd"), format!("{}\r\n", "x".repeat(SPOOL_LINE))).unwrap();
        assert_eq!(spool_next(&dir, 2).unwrap().unwrap().1.len(), SPOOL_LINE);
        std::fs::write(dir.join("4.cmd"), format!("{}\n", "x".repeat(SPOOL_LINE + 1))).unwrap();
        assert!(spool_next(&dir, 3).is_err());
        assert!(dir.join("4.cmd").exists() && !dir.join("4.ack").exists(), "a refused command is not taken");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_operator_grammar_is_exact() {
        let h = "ab".repeat(32);
        assert_eq!(parse(&format!("pay {h} 5000")).unwrap(), Line::Pay([0xab; 32], 5000));
        assert_eq!(parse("connect").unwrap(), Line::Connect);
        assert_eq!(parse(&format!("retired true 7 3 {h} {h}")).unwrap(), Line::Retired { request: 7, sequence: 3, session: [0xab; 32], peer: [0xab; 32] });
        for bad in [
            format!("pay {h} 0"),
            format!("pay {h} 05"),
            format!("pay {} 5", "AB".repeat(32)),
            format!("retired false 7 3 {h} {h}"),
            format!("retired true 7 0 {h} {h}"),
            format!("retired true 0 3 {h} {h}"),
            format!("retired true 7 03 {h} {h}"),
            format!("retired true 3 {h} {h}"),
            format!("trust relative.json {h}"),
            "connect now".into(),
            " connect".into(),
            "".into(),
            "block 101".into(),
        ] {
            assert!(parse(&bad).is_err(), "{bad:?}");
        }
    }

    // Same-root witness: separate OS processes of this test binary on ONE full fresh TEST wallet root
    // (vault, chain and pool all under it), each through the live caller's own open sequence.
    const WITNESS_ROLE: &str = "MUTINY_SAME_ROOT_WITNESS_ROLE";
    const WITNESS_ROOT: &str = "MUTINY_SAME_ROOT_WITNESS_ROOT";
    const WITNESS_CONTROL: &str = "MUTINY_SAME_ROOT_WITNESS_CONTROL";
    /// Each child ends by itself within this bound (no process is ever killed by the witness).
    const CHILD_BOUND: Duration = Duration::from_secs(120);
    const PARENT_BOUND: Duration = Duration::from_secs(180);
    const OUTPUT_CAP: u64 = 64 * 1024;

    /// Every opener of an EXISTING full root: the owner first, then chain, pool and Controller. Each step
    /// is recorded before it runs, so a refusal shows exactly how far the opener got.
    fn open_existing(vault: &VaultRoot, pin: &ChainPin, steps: &mut Vec<&'static str>) -> Result<(OwnerLock, Controller)> {
        steps.push("admission_and_owner");
        let owner = vault.take_owner()?;
        let controller = open_wallet(&owner, vault, pin, &mut |step| steps.push(step))?;
        Ok((owner, controller))
    }
    fn witness_event(service: &Service, bound: Instant) -> Result<Event> {
        loop {
            match service.try_event() {
                Ok(Event::Sync { .. }) => {}
                Ok(Event::Rejected(reason)) => return Err(format!("service rejected: {reason}")),
                Ok(event) => return Ok(event),
                Err(mpsc::TryRecvError::Disconnected) => return Err("wallet service stopped".into()),
                Err(mpsc::TryRecvError::Empty) if Instant::now() >= bound => return Err("witness bound reached".into()),
                Err(mpsc::TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(5)),
            }
        }
    }
    fn witness_unlock(service: &Service, bound: Instant) -> Result<String> {
        service.try_submit(Command::Unlock(zeroize::Zeroizing::new(joint_host::PASSWORD.to_owned()))).map_err(|r| r.reason.to_string())?;
        match witness_event(service, bound)? {
            Event::Unlocked(identity) => Ok(identity.address_id.clone()),
            other => Err(format!("unlock expected, got {other:?}")),
        }
    }
    /// True when the Service reports no unlocked identity.
    fn witness_locked(service: &Service, bound: Instant) -> Result<bool> {
        service.try_submit(Command::Snapshot { payment: None }).map_err(|r| r.reason.to_string())?;
        match witness_event(service, bound)? {
            Event::Snapshot(view) => Ok(view.identity.is_none()),
            other => Err(format!("snapshot expected, got {other:?}")),
        }
    }
    fn witness_role(role: &str, root: &Path, control: &Path) -> Result<Value> {
        let (state, anchor, _) = crate::wallet_controller_v2::tests::fixture_state();
        let pin = ChainPin { anchor, state: &state, root: state.root().map_err(|e| format!("{e:?}"))?, t0: 1000, target: [255; 32] };
        let vault = VaultRoot::new(root).map_err(|e| e.to_string())?;
        let bound = Instant::now() + CHILD_BOUND;
        match role {
            // The first owner: creates the fresh TEST wallet exactly as the live caller does, keeps
            // its Service running until the parent releases it, then shuts it down and exits.
            "owner" => {
                let mut steps = vec!["admission_and_owner"];
                let owner = vault.take_owner()?;
                steps.push("vault_initial");
                let mut store = Store::open(&vault.vault()).map_err(|e| e.to_string())?;
                let session = Session::restore_initial(&crate::chain::phrase(false)).map_err(str::to_owned)?;
                store.save_initial(&session, joint_host::PASSWORD).map_err(str::to_owned)?;
                drop(session);
                drop(store);
                let controller = open_wallet(&owner, &vault, &pin, &mut |step| steps.push(step))?;
                let service = Service::start(controller)?;
                let address = witness_unlock(&service, bound)?;
                let ready = json!({"pid":std::process::id(),"steps":steps,"address_id":address});
                std::fs::write(control.join("owner.ready"), ready.to_string()).map_err(|e| e.to_string())?;
                while !control.join("release.cmd").exists() {
                    if Instant::now() >= bound {
                        service.shutdown()?;
                        return Err("the parent never released the owner".into());
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                // Still the live, usable owner after the other process was refused.
                let usable = !witness_locked(&service, bound)?;
                service.shutdown()?;
                drop(owner);
                Ok(json!({"steps":steps,"address_id":address,"usable_after_refusal":usable,"service_joined":true,"owner_released":true}))
            }
            "second" => {
                let mut steps = Vec::new();
                match open_existing(&vault, &pin, &mut steps) {
                    Err(reason) => Ok(json!({"refused":reason,"steps":steps})),
                    Ok(_) => Err(format!("a second opener of the same root was admitted after {steps:?}")),
                }
            }
            "restart" => {
                let mut steps = Vec::new();
                let (owner, controller) = open_existing(&vault, &pin, &mut steps)?;
                let service = Service::start(controller)?;
                let locked = witness_locked(&service, bound)?;
                let address = witness_unlock(&service, bound)?;
                service.shutdown()?;
                drop(owner);
                Ok(json!({"steps":steps,"locked_on_open":locked,"address_id":address,"service_joined":true}))
            }
            _ => Err(format!("unknown witness role {role}")),
        }
    }

    /// A child process of the witness below; inert (passes at once) unless the witness started it.
    #[test]
    fn same_root_witness_child() {
        let Ok(role) = std::env::var(WITNESS_ROLE) else { return };
        let root = PathBuf::from(std::env::var(WITNESS_ROOT).unwrap());
        let control = PathBuf::from(std::env::var(WITNESS_CONTROL).unwrap());
        let result = witness_role(&role, &root, &control);
        let outcome = match &result {
            Ok(value) => value.clone(),
            Err(error) => json!({"error":error}),
        };
        let record = json!({"role":role,"pid":std::process::id(),"ok":result.is_ok(),"result":outcome});
        std::fs::write(control.join(format!("{role}.json")), record.to_string()).unwrap();
        result.unwrap();
    }

    /// Every file under `dir` except the owner lock (held unshared by the owner): name -> (SHA-256, length).
    fn witness_tree(dir: &Path) -> std::collections::BTreeMap<String, (String, u64)> {
        use sha2::{Digest, Sha256};
        let mut out = std::collections::BTreeMap::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(folder) = stack.pop() {
            for entry in std::fs::read_dir(&folder).unwrap() {
                let path = entry.unwrap().path();
                let name = path.strip_prefix(dir).unwrap().display().to_string();
                if path.is_dir() {
                    stack.push(path);
                } else if name != crate::wallet_controller_v2::OWNER_LOCK_FILE {
                    let bytes = std::fs::read(&path).unwrap();
                    out.insert(name, (hex::encode(Sha256::digest(&bytes)), bytes.len() as u64));
                }
            }
        }
        out
    }
    fn bounded_text(path: &Path) -> String {
        let mut text = String::new();
        if let Ok(file) = std::fs::File::open(path) {
            let _ = file.take(OUTPUT_CAP).read_to_string(&mut text);
        }
        text
    }

    /// FORGE-B1 required witness: while one process owns a full fresh TEST wallet root (vault, chain and
    /// pool under it) with its Service running, an independent second process using the same open
    /// sequence is refused at the owner step, before any store open; the owner stays usable; after the
    /// owner's Service is shut down (joined) and its process exits, a fresh process reopens the root.
    #[test]
    fn a_second_process_on_the_same_full_wallet_root_is_refused_before_any_store_open() {
        use crate::test_support::TestDir;
        use std::process::{Child, Command as Process, Stdio};
        let root_dir = TestDir::new("same-root-witness");
        let control_dir = TestDir::new("same-root-witness-ctl");
        let (root, control) = (root_dir.path().to_path_buf(), control_dir.path().to_path_buf());
        let test = format!("{}::same_root_witness_child", module_path!().split_once("::").unwrap().1);
        let spawn = |role: &str| -> Child {
            Process::new(std::env::current_exe().unwrap())
                .args(["--exact", &test, "--nocapture", "--test-threads=1"])
                .env(WITNESS_ROLE, role)
                .env(WITNESS_ROOT, &root)
                .env(WITNESS_CONTROL, &control)
                .stdin(Stdio::null())
                .stdout(std::fs::File::create(control.join(format!("{role}.stdout"))).unwrap())
                .stderr(std::fs::File::create(control.join(format!("{role}.stderr"))).unwrap())
                .spawn()
                .unwrap()
        };
        // Releases the owner on every exit path, so it always ends by itself (never killed).
        struct Release(PathBuf);
        impl Drop for Release {
            fn drop(&mut self) {
                let _ = std::fs::write(&self.0, b"release");
            }
        }
        let release = Release(control.join("release.cmd"));
        let bound = Instant::now() + PARENT_BOUND;
        let finish = |child: &mut Child, role: &str| {
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    let out = bounded_text(&control.join(format!("{role}.stderr")));
                    assert!(status.success(), "{role} failed: {}", out);
                    break;
                }
                assert!(Instant::now() < bound, "{role} did not end within the bound");
                std::thread::sleep(Duration::from_millis(20));
            }
            let record: Value = serde_json::from_str(&bounded_text(&control.join(format!("{role}.json")))).unwrap();
            assert_eq!(record["pid"], child.id(), "{role} record from another process");
            assert_eq!(record["ok"], true, "{record}");
            record
        };

        let mut owner = spawn("owner");
        while !control.join("owner.ready").exists() {
            assert!(owner.try_wait().unwrap().is_none(), "owner ended early: {}", bounded_text(&control.join("owner.stderr")));
            assert!(Instant::now() < bound, "owner never became ready");
            std::thread::sleep(Duration::from_millis(20));
        }
        let ready: Value = serde_json::from_str(&bounded_text(&control.join("owner.ready"))).unwrap();
        assert_eq!(ready["pid"], owner.id());
        assert_eq!(ready["steps"], json!(["admission_and_owner", "vault_initial", "chain_store_open", "pool_store_open", "controller_open_owned"]));
        let full = witness_tree(&root);
        for store in ["public-chain.sqlite", "public-payment-pool.sqlite", "WalletCustodyV2\\wallet-hybrid-v2.sqlite"] {
            assert!(full.contains_key(store), "the full root lacks {store}: {:?}", full.keys());
        }

        let mut second = spawn("second");
        let refused = finish(&mut second, "second");
        assert!(refused["result"]["refused"].as_str().unwrap().contains("already open"), "{refused}");
        // The instrumented sequence stopped at the owner step: no chain, pool or Controller step ran.
        assert_eq!(refused["result"]["steps"], json!(["admission_and_owner"]));
        // Supplemental only (equal bytes do not by themselves prove no open): nothing changed.
        assert_eq!(witness_tree(&root), full);
        assert!(owner.try_wait().unwrap().is_none(), "the first owner must still be running");

        drop(release);
        let closed = finish(&mut owner, "owner");
        assert_eq!(closed["result"]["usable_after_refusal"], true, "{closed}");
        assert_eq!(closed["result"]["service_joined"], true);

        let mut restart = spawn("restart");
        let reopened = finish(&mut restart, "restart");
        assert_eq!(reopened["result"]["steps"], json!(["admission_and_owner", "chain_store_open", "pool_store_open", "controller_open_owned"]));
        assert_eq!(reopened["result"]["locked_on_open"], true);
        assert_eq!(reopened["result"]["address_id"], ready["address_id"], "the same wallet reopened");

        let pids = [owner.id(), second.id(), restart.id(), std::process::id()];
        assert!(pids.iter().enumerate().all(|(i, a)| pids[i + 1..].iter().all(|b| a != b)), "{pids:?}");
        let sizes: Vec<_> = ["owner", "second", "restart"].iter().flat_map(|role| ["stdout", "stderr"].map(|s| {
            let path = control.join(format!("{role}.{s}"));
            json!({"file":format!("{role}.{s}"),"bytes":std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0)})
        })).collect();
        println!("{}", json!({"witness":"same_full_root_separate_process","parent_pid":std::process::id(),
            "owner":{"pid":owner.id(),"ready_steps":ready["steps"],"closed":closed["result"]},
            "second":{"pid":second.id(),"refused":refused["result"]["refused"],"steps":refused["result"]["steps"]},
            "restart":{"pid":restart.id(),"result":reopened["result"]},
            "root_files_unchanged_supplemental":full.len(),"child_outputs":sizes}));
    }
}
