//! NON-SHIPPING wallet side of Forge's joint TEST run forge-joint-h01-20261015-r2 (r1 ended at the Linux firewall) (synthetic H0 -> H1 and one
//! fresh-handshake reconnect; plan and authorization in the mailbox, FORGE-JOINT-H01-R1-PREPARE-*). The
//! wallet is the real controller over an EMPTY vault store (no seed restored or saved, session never
//! unlocked) and a replica pinned to the public fixture's H0; the connection is the existing NodeSession
//! with the restricted `Registry::new_wallet_client`. History is installed only through the controller's
//! canonical replay. Live control is the file contract in the control directory; Forge launches this once.
use crate::{
    node_link::{self, NodeSession},
    verified_sync_v2::Replica,
    wallet_controller_v2::{Controller, VaultRoot, host::Progress},
};
use mutiny_consensus_v8::{
    Hash, anchors::FinalizedAnchor, canonical_store_v2::CanonicalStore, execution::State, mempool_v2::Mempool,
};
use mutiny_crypto_v2::{HybridKey, PublicKey, Role};
use mutiny_transport_v2::Endpoint;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type R<T> = std::result::Result<T, String>;
pub const RUN_ID: &str = "forge-joint-h01-20261015-r2";
pub const FIXTURE_SHA: &str = "80475698b7614760f9fc1a0b114e3aae72ad24d06fd68b8b7d615104296c70a6";
pub const ENVELOPE_SHA: &str = "81055f6e680eeedaee51ff92e1b17e443c1f817656fa7b83f1c54ef414c87783";
pub const NODE_BIND: &str = "192.168.68.58:49735";
const FIXTURE: &str = include_str!("../../../qualification/hybrid-canonical-store-public-v1.json");
const SCOPE: u64 = 900;
const EVENT_WAIT: Duration = Duration::from_secs(120);
const HANDSHAKE: Duration = Duration::from_secs(30);
const TURN: Duration = Duration::from_millis(100);
const POLL: Duration = Duration::from_millis(20);

fn e(x: impl std::fmt::Debug) -> String {
    format!("{x:?}")
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn anchor(a: &FinalizedAnchor) -> Value {
    json!({"network":a.network,"genesis":hex::encode(a.genesis),"fingerprint":hex::encode(a.fingerprint),
        "height":a.height,"block":hex::encode(a.block),"encoded":hex::encode(a.encode())})
}
fn write_new(dir: &Path, name: &str, v: Value) -> R<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().create_new(true).write(true).open(dir.join(name))
        .map_err(|x| format!("{name}: {x}"))?;
    f.write_all(serde_json::to_string_pretty(&v).map_err(e)?.as_bytes()).map_err(e)?;
    f.sync_all().map_err(e)
}
fn read_control(dir: &Path, name: &str) -> R<Option<Value>> {
    let p = dir.join(name);
    let m = match std::fs::symlink_metadata(&p) {
        Ok(m) => m,
        Err(x) if x.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(x) => return Err(format!("{name}: {x}")),
    };
    if !m.is_file() || m.len() > 64 * 1024 {
        return Err(format!("{name}: control file type/bound"));
    }
    // A file still being copied is retried on the next poll, never accepted partially.
    let Ok(v) = serde_json::from_slice::<Value>(&std::fs::read(&p).map_err(e)?) else { return Ok(None) };
    if v["runId"] != RUN_ID {
        return Err(format!("{name}: run identity"));
    }
    Ok(Some(v))
}

/// The public fixture: pinned file, H0 anchor, trusted state and the H1 envelope.
pub fn fixture() -> R<(FinalizedAnchor, State, Hash, Vec<u8>)> {
    if sha(FIXTURE.as_bytes()) != FIXTURE_SHA {
        return Err("fixture pin".into());
    }
    let f: Value = serde_json::from_str(FIXTURE).map_err(e)?;
    if f["synthetic_only"] != true || f["production_authorized"] != false {
        return Err("fixture scope".into());
    }
    let bytes = |v: &Value| -> R<Vec<u8>> { hex::decode(v.as_str().ok_or("public hex")?).map_err(e) };
    let genesis = FinalizedAnchor::decode(&bytes(&f["genesis"])?).map_err(e)?;
    if genesis.genesis != [1; 32] || genesis.fingerprint != [2; 32] || genesis.height != 0 {
        return Err("fixture context".into());
    }
    let root: Hash = bytes(&f["root"])?.try_into().map_err(|_| "fixture root")?;
    let records = f["records"].as_array().ok_or("records")?.iter()
        .map(|r| Ok((bytes(&r["key"])?.try_into().map_err(|_| "record key")?, bytes(&r["record"])?)))
        .collect::<R<Vec<_>>>()?;
    let state = State::from_records(&records, root).map_err(e)?;
    let block = bytes(&f["envelope"])?;
    if sha(&block) != ENVELOPE_SHA {
        return Err("envelope pin".into());
    }
    Ok((genesis, state, root, block))
}

/// The locked wallet over an empty store and a replica pinned to H0 (new private directory).
pub fn open_wallet(private: &Path) -> R<Controller> {
    let (genesis, state, root, _) = fixture()?;
    let vault = VaultRoot::new(&private.join("vault")).map_err(|x| x.to_string())?;
    if !mutiny_consensus_v8::submission_pool_v1::private_directory(vault.path()).map_err(e)? {
        return Err("wallet vault root was not newly created".into());
    }
    let chain = CanonicalStore::open_trusted_genesis(&vault.path().join("public-chain.sqlite"), &genesis, &state, root, 1000, [255; 32])
        .map_err(e)?;
    let replica = Replica::from_pinned_chain(chain)?;
    let pool = Mempool::open(&vault.path().join("public-payment-pool.sqlite"), genesis.genesis, genesis.fingerprint, 65536).map_err(e)?;
    // Controller::open = Controller::new over the stores it opens; the vault store stays EMPTY (no
    // save_initial, no restore) and the controller is never unlocked (session None).
    let wallet = Controller::open(&vault, replica, pool, None)?;
    Ok(wallet)
}

/// Offline readiness check: fixture pins, a fresh wallet at H0, and the H1 envelope accepted by the
/// controller's canonical replay into a SEPARATE scratch wallet. No key, no socket.
pub fn offline_check(scratch: &Path) -> R<Value> {
    let (genesis, _, _, block) = fixture()?;
    let mut wallet = open_wallet(scratch)?;
    let h0 = wallet.with_view(|v| v.anchor().clone())?;
    if anchor(&h0) != anchor(&genesis) || wallet.identity().is_some() {
        return Err("fresh wallet is not the locked fixture H0".into());
    }
    let inserted = wallet.accept_history(&block)?;
    let h1 = wallet.with_view(|v| v.anchor().clone())?;
    let again = wallet.accept_history(&block)?;
    let unchanged = wallet.with_view(|v| v.anchor().clone())?;
    if !inserted || h1.height != 1 || again || unchanged != h1 {
        return Err("canonical H1 replay or idempotence failed offline".into());
    }
    Ok(json!({"status":"PASS","savedH0":anchor(&h0),"finalizedH1":anchor(&h1),"duplicateInserted":again,
        "keysGenerated":false,"socketCreated":false,"walletSeedSaved":false,"unlocked":false}))
}

struct Live<'a> {
    control: &'a Path,
    deadline: Instant,
    wallet: Controller,
    /// The link error seen while waiting for the node's close notice (the node closes first).
    closed_link: Option<String>,
}
impl Live<'_> {
    fn check(&self) -> R<()> {
        if Instant::now() >= self.deadline { Err("900-second TEST scope expired".into()) } else { Ok(()) }
    }
    /// Waits for a control file. While connected, keeps draining the wallet peer so the session stays
    /// serviced; history events go to `events`. A link failure while waiting for the node's own close
    /// notice (`node-closed-*`) is recorded and the wait continues: the node closes first. Any other
    /// link failure ends the run.
    fn wait(&mut self, name: &str, peer: Option<&mut node_link::NodeConnection>, events: &mut Vec<(Hash, bool)>) -> R<Value> {
        let end = (Instant::now() + EVENT_WAIT).min(self.deadline);
        let mut peer = peer;
        loop {
            self.check()?;
            if Instant::now() >= end {
                return Err(format!("timed out waiting for {name}"));
            }
            if let Some(v) = read_control(self.control, name)? {
                return Ok(v);
            }
            let turned = match peer.as_mut() {
                Some(c) => Some(self.wallet.peer_turn(&mut c.peer, Instant::now() + TURN)),
                None => None,
            };
            match turned {
                Some(Ok(Some(Progress::History { object, inserted }))) => events.push((object, inserted)),
                Some(Ok(_)) => {}
                Some(Err(x)) if name.starts_with("node-closed-") => {
                    self.closed_link = Some(x);
                    peer = None;
                }
                Some(Err(x)) => return Err(x),
                None => std::thread::sleep(POLL),
            }
        }
    }
    /// Turns the peer until a history event satisfying `want` arrives (bounded by EVENT_WAIT and scope).
    fn until_history(&mut self, c: &mut node_link::NodeConnection, events: &mut Vec<(Hash, bool)>, want: impl Fn(&(Hash, bool)) -> bool) -> R<(Hash, bool)> {
        let end = (Instant::now() + EVENT_WAIT).min(self.deadline);
        loop {
            if let Some(found) = events.iter().find(|x| want(x)) {
                return Ok(*found);
            }
            self.check()?;
            if Instant::now() >= end {
                return Err("timed out waiting for certified history".into());
            }
            if let Some(Progress::History { object, inserted }) = self.wallet.peer_turn(&mut c.peer, Instant::now() + TURN)? {
                events.push((object, inserted));
            }
        }
    }
}

/// The live run. `bind` is the node address the contract fixes; `private` is a new private directory.
pub fn live(control: &Path, private: &Path, deadline_unix: u64, bind: &str) -> R<Value> {
    let start = Instant::now();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(e)?.as_secs();
    let remaining = deadline_unix.checked_sub(now).ok_or("expired authorized run")?.min(SCOPE);
    if remaining < 60 {
        return Err("insufficient coordinated run budget".into());
    }
    let (genesis, _, _, _) = fixture()?;
    let mut run = Live { control, deadline: start + Duration::from_secs(remaining), wallet: open_wallet(private)?, closed_link: None };
    let h0 = run.wallet.with_view(|v| v.anchor().clone())?;
    if anchor(&h0) != anchor(&genesis) {
        return Err("wallet did not start at the fixture H0".into());
    }
    // 1. One in-memory Transport key, generation 1; only public data leaves.
    let key = HybridKey::generate(Role::Transport).map_err(e)?;
    let descriptor = key.public().descriptor(1).map_err(e)?;
    let own = Endpoint::pinned(key.public().clone(), 1).map_err(e)?;
    write_new(control, "wallet-public.json", json!({"schema":"CIPHER-JOINT-PUBLIC-ENDPOINT-V1","runId":RUN_ID,"side":"wallet",
        "generation":1,"descriptorHex":hex::encode(&descriptor),"descriptorSha256":sha(&descriptor),"endpointId":hex::encode(own.id()),
        "genesis":hex::encode(genesis.genesis),"fingerprint":hex::encode(genesis.fingerprint),"fixtureSha256":FIXTURE_SHA,
        "privateKeysPersisted":false}))?;
    let mut events = Vec::new();
    let node = run.wait("node-public.json", None, &mut events)?;
    let listening = run.wait("node-listening.json", None, &mut events)?;
    if node["generation"] != 1 || node["genesis"] != hex::encode(genesis.genesis) || node["fingerprint"] != hex::encode(genesis.fingerprint)
        || node["fixtureSha256"] != FIXTURE_SHA || node["savedH0"] != anchor(&genesis) {
        return Err("node public context differs".into());
    }
    let node_descriptor = hex::decode(node["descriptorHex"].as_str().ok_or("node descriptor")?).map_err(e)?;
    if node_descriptor.len() > 8192 || node["descriptorSha256"] != sha(&node_descriptor) {
        return Err("node descriptor pin/bound".into());
    }
    let (node_key, generation) = PublicKey::decode_descriptor(&node_descriptor).map_err(e)?;
    let node_endpoint = Endpoint::pinned(node_key, generation).map_err(e)?;
    if generation != 1 || node["endpointId"] != hex::encode(node_endpoint.id()) {
        return Err("node endpoint identity".into());
    }
    if listening["bind"] != bind {
        return Err(format!("node listens on {} not the approved {bind}", listening["bind"]));
    }
    let address = node_link::parse_node(bind, &hex::encode(&node_descriptor))?;
    let mut session = NodeSession::new(genesis.genesis, genesis.fingerprint, address, private.join("node-queue.sqlite"));

    // 2-3. First session: report H0, then accept H1 through canonical replay.
    let mut first = session.connect(&key, HANDSHAKE)?;
    let saved = run.wallet.with_view(|v| v.anchor().clone())?;
    write_new(control, "wallet-connected-1.json", json!({"runId":RUN_ID,"session":1,"savedFinalized":anchor(&saved),
        "freshHandshakeCompleted":true,"restrictedRegistry":"Registry::new_wallet_client"}))?;
    let (object, _) = run.until_history(&mut first, &mut events, |(_, inserted)| *inserted)?;
    let h1 = run.wallet.with_view(|v| v.anchor().clone())?;
    if h1.height != 1 || h1.genesis != genesis.genesis || h1.fingerprint != genesis.fingerprint {
        return Err("canonical acceptance did not reach H1".into());
    }
    let h1_root = run.wallet.with_view(|v| v.head().state_root())?;
    write_new(control, "wallet-accepted-1.json", json!({"runId":RUN_ID,"finalized":anchor(&h1),"canonicalVerified":true,
        "inserted":true,"object":hex::encode(object),"stateRoot":hex::encode(h1_root)}))?;

    // 4. Close the first session only when the node has closed; keep controller, state and queue.
    run.wait("node-closed-1.json", Some(&mut first), &mut events)?;
    first.peer.close();
    drop(first);
    session.lost("closed on node-closed-1");
    let queue_preserved = private.join("node-queue.sqlite").exists();
    write_new(control, "wallet-closed-1.json", json!({"runId":RUN_ID,"joined":true,"queuePreserved":queue_preserved,"linkEndAfterNodeClose":run.closed_link.take()}))?;
    run.wait("reconnect.json", None, &mut events)?;

    // 5. Same Transport owner and queue, fresh handshake; retained bytes alone must not authorize retry.
    let mut second = session.connect(&key, HANDSHAKE)?;
    let denied = !second.peer.completed_retry_authorized(object)?;
    let saved = run.wallet.with_view(|v| v.anchor().clone())?;
    if !denied || saved != h1 {
        return Err("reconnect state: retained bytes authorized a retry or the checkpoint moved".into());
    }
    let before = events.len();
    write_new(control, "wallet-connected-2.json", json!({"runId":RUN_ID,"session":2,"savedFinalized":anchor(&saved),
        "preFreshOfferRetryDenied":denied,"sameDurableQueue":queue_preserved,"freshHandshakeCompleted":true}))?;

    // 6. An actual duplicate verification AFTER the fresh offer: the same object, processed again, not inserted.
    let mut after = events.split_off(before);
    let (dup, inserted) = run.until_history(&mut second, &mut after, |(o, _)| *o == object)?;
    let now_anchor = run.wallet.with_view(|v| v.anchor().clone())?;
    let now_root = run.wallet.with_view(|v| v.head().state_root())?;
    if inserted || dup != object || now_anchor != h1 || now_root != h1_root {
        return Err("duplicate H1 was not idempotent".into());
    }
    write_new(control, "wallet-accepted-2.json", json!({"runId":RUN_ID,"finalized":anchor(&h1),"canonicalVerified":true,
        "duplicateVerified":true,"canonicalUnchanged":true,"freshAuthenticatedOfferObserved":true,"object":hex::encode(dup)}))?;

    // 7. Close after the node, then drop every key owner.
    run.wait("node-closed-2.json", Some(&mut second), &mut after)?;
    second.peer.close();
    drop(second);
    drop(session);
    drop(key);
    run.wallet.lock();
    Ok(json!({"runId":RUN_ID,"status":"PASS","sessions":2,"sameDurableQueue":queue_preserved,"duplicateVerified":true,
        "finalized":anchor(&h1),"keyOwnersDropped":true,"workerJoinsComplete":true,"privateKeysPersisted":false,
        "walletSeedSaved":false,"linkEndAfterNodeClose2":run.closed_link.take(),"elapsedSeconds":start.elapsed().as_secs_f64()}))
}

/// Loopback rehearsal of the whole contract on this machine: the node side is Forge's host logic
/// (forge_joint_node_host_20261015.rs, same Listener/Worker/Enqueue calls) plus the coordinator's control
/// files, on 127.0.0.1 instead of the approved LAN address. TEST only; it is not the joint run.
#[cfg(test)]
mod loopback_tests {
    use super::*;
    use mutinyd_v8::{
        hybrid_peer_admission_v2::Registry,
        hybrid_peer_listener_v2::Listener,
        hybrid_peer_worker_v2::{Command, Worker},
        hybrid_runtime_v2::HybridRuntime,
    };
    use mutiny_transport_v2::objects::{ObjectKind, ObjectQueue};
    use std::sync::{Arc, Mutex};

    fn wait_file(dir: &Path, name: &str, worker: Option<&Worker>) -> Value {
        let end = Instant::now() + Duration::from_secs(120);
        loop {
            assert!(Instant::now() < end, "timed out waiting for {name}");
            if let Some(v) = read_control(dir, name).unwrap() {
                return v;
            }
            if let Some(w) = worker {
                while w.try_notification().is_ok() {}
            }
            std::thread::sleep(POLL);
        }
    }

    #[test]
    fn joint_h01_contract_passes_against_the_node_host_logic_on_loopback() {
        let base = crate::test_support::TestDir::new("joint-h01-loopback");
        let control = base.path().join("control");
        std::fs::create_dir(&control).unwrap();
        let node_dir = base.path().join("node");
        assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&node_dir).unwrap());
        // Node: fresh canonical runtime at H0 that installs and verifies H1 (as Forge's fixture_runtime).
        let (genesis, state, root, block) = fixture().unwrap();
        let chain = CanonicalStore::open_trusted_genesis(&node_dir.join("chain.sqlite"), &genesis, &state, root, 1000, [255; 32]).unwrap();
        let pool = Mempool::open(&node_dir.join("pool.sqlite"), genesis.genesis, genesis.fingerprint, 64 * 1024 * 1024).unwrap();
        let mut runtime = HybridRuntime::from_pinned_chain(chain, pool).unwrap();
        assert!(runtime.install(&block).unwrap().inserted);
        let target = runtime.head().unwrap();
        let runtime = Arc::new(Mutex::new(runtime));
        let key = HybridKey::generate(Role::Transport).unwrap();
        let public = key.public().descriptor(1).unwrap();
        let own = Endpoint::pinned(key.public().clone(), 1).unwrap();
        write_new(&control, "node-public.json", json!({"runId":RUN_ID,"side":"node","generation":1,"descriptorHex":hex::encode(&public),
            "descriptorSha256":sha(&public),"endpointId":hex::encode(own.id()),"genesis":hex::encode(genesis.genesis),
            "fingerprint":hex::encode(genesis.fingerprint),"fixtureSha256":FIXTURE_SHA,"savedH0":anchor(&genesis),"nodeH1":anchor(&target)})).unwrap();
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let bind = socket.local_addr().unwrap().to_string();
        // Wallet side: the real live() in its own thread.
        let deadline = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 600;
        let wallet = {
            let (control, private, bind) = (control.clone(), base.path().join("wallet"), bind.clone());
            std::fs::create_dir(&private).unwrap();
            std::thread::spawn(move || live(&control, &private, deadline, &bind))
        };
        let peer_public = wait_file(&control, "wallet-public.json", None);
        assert_eq!(peer_public["privateKeysPersisted"], false);
        let desc = hex::decode(peer_public["descriptorHex"].as_str().unwrap()).unwrap();
        assert_eq!(peer_public["descriptorSha256"], sha(&desc));
        let (pk, generation) = PublicKey::decode_descriptor(&desc).unwrap();
        let peer = Endpoint::pinned(pk, generation).unwrap();
        let registry = Registry::new_wallet_clients(genesis.genesis, genesis.fingerprint, own, vec![peer.clone()], 1, 1).unwrap();
        let mut listener = Listener::new(socket, registry.clone(), peer.id(), Duration::from_secs(30)).unwrap();
        write_new(&control, "node-listening.json", json!({"runId":RUN_ID,"bind":bind})).unwrap();
        for session in 1..=2 {
            let end = Instant::now() + Duration::from_secs(120);
            let connection = loop {
                assert!(Instant::now() < end, "no wallet connection");
                if let Some(accepted) = listener.poll().unwrap() { break accepted.respond(&key).unwrap(); }
                std::thread::sleep(POLL);
            };
            assert_eq!(connection.peer_id(), peer.id());
            let queue = ObjectQueue::open(&node_dir.join("peer-queue.sqlite"), connection.peer_id()).unwrap();
            let worker = Worker::start(connection, queue, runtime.clone()).unwrap();
            let connected = wait_file(&control, &format!("wallet-connected-{session}.json"), Some(&worker));
            let expected = if session == 1 { anchor(&genesis) } else { anchor(&target) };
            assert_eq!(connected["savedFinalized"], expected);
            if session == 2 {
                assert_eq!(connected["preFreshOfferRetryDenied"], true);
            }
            let mut command = Command::Enqueue { kind: ObjectKind::CertifiedBlock, bytes: block.clone() };
            loop {
                while worker.try_notification().is_ok() {}
                match worker.try_submit(command) {
                    Ok(()) => break,
                    Err(rejected) if rejected.reason == "Peer command backpressure" => { command = rejected.command; std::thread::sleep(POLL); }
                    Err(rejected) => panic!("enqueue refused: {}", rejected.reason),
                }
            }
            let accepted = wait_file(&control, &format!("wallet-accepted-{session}.json"), Some(&worker));
            assert_eq!(accepted["finalized"], anchor(&target));
            let _ = worker.shutdown();
            drop(registry.begin().unwrap());
            write_new(&control, &format!("node-closed-{session}.json"), json!({"runId":RUN_ID,"session":session,"joined":true})).unwrap();
            if session == 1 {
                write_new(&control, "reconnect.json", json!({"runId":RUN_ID})).unwrap();
            }
        }
        let result = wallet.join().unwrap().unwrap();
        assert_eq!(result["status"], "PASS");
        assert_eq!(result["duplicateVerified"], true);
        assert_eq!(result["finalized"], anchor(&target));
        assert_eq!(runtime.lock().unwrap().head().unwrap(), target);
        let accepted2 = read_control(&control, "wallet-accepted-2.json").unwrap().unwrap();
        assert_eq!(accepted2["canonicalUnchanged"], true);
    }

    #[test]
    fn offline_check_accepts_h1_once_without_keys_or_sockets() {
        let base = crate::test_support::TestDir::new("joint-h01-offline");
        std::fs::create_dir(base.path().join("scratch")).unwrap();
        let v = offline_check(&base.path().join("scratch")).unwrap();
        assert_eq!(v["status"], "PASS");
        assert_eq!(v["duplicateInserted"], false);
    }
}

/// `--joint-h01-offline-check <new scratch dir>` or `--joint-h01-live <new private dir>` (live reads
/// FORGE_JOINT_CONTROL_DIR, FORGE_JOINT_DEADLINE_UNIX, FORGE_JOINT_RUN_ID).
pub fn run_if_requested() -> Option<eframe::Result> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mode = args.first().map(String::as_str)?;
    if mode != "--joint-h01-offline-check" && mode != "--joint-h01-live" {
        return None;
    }
    let outcome = (|| -> R<i32> {
        if mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED || mutiny_crypto_v2::RELEASE_CUSTODY_ENABLED {
            return Err("closed production gates required".into());
        }
        let [_, dir] = args.as_slice() else { return Err("usage: <mode> <new absolute directory>".into()) };
        let dir = PathBuf::from(dir);
        if !dir.is_absolute() || dir.exists() {
            return Err("directory must be new and absolute".into());
        }
        if !mutiny_consensus_v8::submission_pool_v1::private_directory(&dir).map_err(e)? {
            return Err("directory was not newly created".into());
        }
        if mode == "--joint-h01-offline-check" {
            let v = offline_check(&dir)?;
            println!("{v}");
            return Ok(0);
        }
        let control = PathBuf::from(std::env::var("FORGE_JOINT_CONTROL_DIR").map_err(|_| "FORGE_JOINT_CONTROL_DIR")?);
        let deadline: u64 = std::env::var("FORGE_JOINT_DEADLINE_UNIX").map_err(|_| "FORGE_JOINT_DEADLINE_UNIX")?
            .parse().map_err(|_| "FORGE_JOINT_DEADLINE_UNIX")?;
        if std::env::var("FORGE_JOINT_RUN_ID").map_err(|_| "FORGE_JOINT_RUN_ID")? != RUN_ID {
            return Err("FORGE_JOINT_RUN_ID differs".into());
        }
        if !control.is_dir() || control.join("wallet-public.json").exists() || control.join("wallet-terminal.json").exists() {
            return Err("fresh existing control directory required; no duplicate run".into());
        }
        let result = live(&control, &dir, deadline, NODE_BIND);
        // live() has returned: its key, session, peers and wallet have all been dropped, also on Err.
        let (code, record) = match result {
            Ok(v) => (0, v),
            Err(x) => (1, json!({"runId":RUN_ID,"status":"FAIL","error":x,"keyOwnersDropped":true,"privateKeysPersisted":false,"walletSeedSaved":false})),
        };
        let _ = write_new(&control, "wallet-terminal.json", record.clone());
        println!("{record}");
        Ok(code)
    })();
    Some(match outcome {
        Ok(0) => Ok(()),
        Ok(code) => std::process::exit(code),
        Err(x) => Err(eframe::Error::AppCreation(x.into())),
    })
}
