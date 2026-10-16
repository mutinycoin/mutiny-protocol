//! NON-SHIPPING joint Desktop/Linux TEST host (Architect item 3, 2026-10-14). The real wallet controller on
//! its own verified replica of a sealed TEST-VALUE V2 Genesis bundle, connected to a REAL node through the
//! restricted wallet-client admission (G2). There is no simulated certification here: certified history
//! arrives only from the node and is installed by the wallet's own canonical replay; a payment is confirmed
//! only when that replay includes it. Commands are JSON lines on stdin; every event is a JSON line on stdout
//! and in `<evidence>/events.jsonl`. Start: `--joint-test --vault-root <abs> --genesis-config <abs json>
//! --genesis-config-sha256 <hex> --node <ip:port> --node-descriptor <hex> --evidence-root <abs, new>`,
//! optionally followed by `--history`: the B1 automatic-history profile (`NodeSession::history`) with its V9
//! queue kept in the vault root, so a restart on the same vault reuses it. Connecting is still an explicit
//! `connect` command; after it, catch-up runs by itself through the same `history_open`/`history_turn` the
//! wallet service uses, and every change is a `sync` event.
use crate::{
    node_link::{self, LinkState, NodeSession},
    store_v2::Store,
    verified_sync_v2::{Delivery, Replica},
    wallet_controller_v2::{Controller, ReviewOutcome, VaultRoot, host::Progress},
    wallet_v2::Session,
};
use mutiny_consensus_v8::{
    Hash,
    canonical_store_v2::CanonicalStore,
    genesis_v2::{Approved, GenesisClass},
    mempool_v2::Mempool,
    protocol_manifest::RuleManifest,
};
use mutinyd_v8::genesis_artifact_v2::{MAX_ARTIFACT, TrustV2, VerifiedGenesisV2};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::{BufRead, Read, Write},
    path::{Path, PathBuf},
    sync::mpsc,
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, String>;
pub(crate) const PASSWORD: &str = "PUBLIC JOINT TEST-VALUE PASSWORD";
const TURN: Duration = Duration::from_millis(100);
const HANDSHAKE: Duration = Duration::from_secs(30);
const MAX_LINE: usize = 64 * 1024;

fn fail(e: impl std::fmt::Debug) -> String {
    format!("{e:?}")
}
fn read_pinned(path: &Path, pin: Hash, limit: usize) -> Result<Vec<u8>> {
    let mut raw = Vec::new();
    std::fs::File::open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?
        .take(limit as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(fail)?;
    if raw.len() > limit || <[u8; 32]>::from(Sha256::digest(&raw)) != pin {
        return Err(format!("{}: size or SHA256 differs from its pin", path.display()));
    }
    Ok(raw)
}
fn hash(text: &str) -> Result<Hash> {
    hex::decode(text).map_err(fail)?.try_into().map_err(|_| "32-byte hex required".into())
}
fn field<'a>(v: &'a Value, name: &str) -> Result<&'a str> {
    v[name].as_str().ok_or_else(|| format!("genesis config field {name}"))
}

struct Args {
    vault: VaultRoot,
    config: PathBuf,
    config_pin: Hash,
    node: node_link::NodeAddress,
    evidence: PathBuf,
    history: bool,
}
fn args(values: &[String]) -> Result<Args> {
    let (values, history) = match values {
        [rest @ .., last] if last == "--history" => (rest, true),
        _ => (values, false),
    };
    let [_, a, vault, b, config, c, pin, d, node, e, descriptor, f, evidence] = values else {
        return Err("usage: --joint-test --vault-root V --genesis-config C --genesis-config-sha256 H --node A --node-descriptor D --evidence-root E [--history]".into());
    };
    if [a, b, c, d, e, f].map(String::as_str)
        != ["--vault-root", "--genesis-config", "--genesis-config-sha256", "--node", "--node-descriptor", "--evidence-root"]
    {
        return Err("unexpected joint TEST arguments".into());
    }
    let evidence = PathBuf::from(evidence);
    if !evidence.is_absolute() || evidence.exists() {
        return Err("--evidence-root must be a new absolute folder".into());
    }
    Ok(Args {
        vault: VaultRoot::new(Path::new(vault)).map_err(|e| e.to_string())?,
        config: PathBuf::from(config),
        config_pin: hash(pin)?,
        node: node_link::parse_node(node, descriptor)?,
        evidence,
        history,
    })
}

/// The sealed TEST-VALUE Genesis, verified with its public evidence (same fields as the node's
/// BUILD8-HYBRID-TEST-APPLICATION-V1 configuration).
/// A file named by the configuration: an absolute path as before, or a bare sibling basename (as in the
/// node's published application.json) resolved next to the configuration file. Nothing else is accepted.
fn sibling(config: &Path, named: &str) -> Result<PathBuf> {
    let path = Path::new(named);
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let mut parts = path.components();
    match (parts.next(), parts.next()) {
        (Some(std::path::Component::Normal(_)), None) => {}
        _ => return Err(format!("{named}: only an absolute path or a bare sibling file name is accepted")),
    }
    Ok(config.parent().ok_or("configuration has no folder")?.join(path))
}
pub(crate) fn genesis(config: &Path, pin: Hash) -> Result<VerifiedGenesisV2> {
    let raw = read_pinned(config, pin, 64 * 1024)?;
    let v: Value = serde_json::from_slice(&raw).map_err(fail)?;
    let trust = TrustV2 {
        artifact_sha256: hash(field(&v, "artifact_sha256")?)?,
        genesis_block_hash: hash(field(&v, "genesis_block_hash")?)?,
        approved: Approved {
            manifest: RuleManifest::decode(&hex::decode(field(&v, "approved_manifest")?).map_err(fail)?).map_err(fail)?,
            class: GenesisClass::TestValue,
            initial_target: hash(field(&v, "initial_target")?)?,
        },
    };
    let artifact = read_pinned(&sibling(config, field(&v, "artifact")?)?, trust.artifact_sha256, MAX_ARTIFACT)?;
    let evidence = read_pinned(
        &sibling(config, field(&v, "public_evidence")?)?,
        hash(field(&v, "public_evidence_sha256")?)?,
        mutiny_consensus_v8::admission_evidence_v1::MAX_BUNDLE,
    )?;
    let verified = VerifiedGenesisV2::verify_with_public_evidence(&artifact, &trust, &evidence)?;
    if verified.genesis.class != GenesisClass::TestValue {
        return Err("only a TEST-VALUE Genesis is accepted".into());
    }
    Ok(verified)
}

struct Host {
    wallet: Controller,
    session: NodeSession,
    key: mutiny_crypto_v2::HybridKey,
    peer: Option<(node_link::NodeConnection,)>,
    /// The B1 client of the current history-profile connection; dropped with the connection.
    history: Option<crate::wallet_controller_v2::host::history::HistoryClient>,
    log: std::fs::File,
}
impl Host {
    fn sync_event(&self) -> Option<Value> {
        let sync = self.history.as_ref()?.sync();
        Some(json!({"event":"sync","saved":sync.saved(),"tip":sync.observed_tip(),"line":sync.describe()}))
    }
    fn emit(&mut self, event: Value) {
        let line = event.to_string();
        println!("{line}");
        let _ = writeln!(self.log, "{line}");
    }
    fn status(&mut self) -> Result<Value> {
        let anchor = self.wallet.with_view(|v| v.anchor().clone())?;
        let balance = self.wallet.verified_balance().ok();
        let pending = self
            .wallet
            .pending_for_transport()?
            .iter()
            .filter_map(|raw| mutiny_consensus_v8::operation_index_v2::operation_id(0, raw).ok())
            .map(|(_, id)| hex::encode(id))
            .collect::<Vec<_>>();
        Ok(json!({"event":"status","verified_height":anchor.height,"verified_block":hex::encode(anchor.block),
            "balance":balance.map(|b| json!({"total":b.total_atoms,"available":b.available_atoms,"reserved":b.reserved_atoms})),
            "unlocked":self.wallet.identity().is_some(),"link":format!("{:?}", self.session.state()),"pending_payments":pending,
            "sync":self.history.as_ref().map(|h| h.sync().describe())}))
    }
    fn command(&mut self, c: &Value) -> Result<Value> {
        match c["cmd"].as_str().unwrap_or_default() {
            "status" => self.status(),
            "unlock" => {
                self.wallet.unlock(PASSWORD)?;
                Ok(json!({"event":"unlocked"}))
            }
            "connect" => {
                self.peer = None;
                self.history = None;
                let mut connection = self.session.connect(&self.key, HANDSHAKE)?;
                if self.session.profile() == node_link::Profile::History {
                    // Catch-up starts at once from the saved anchor; a refusal closes this connection.
                    match self.wallet.history_open(&mut connection.peer, Instant::now()) {
                        Ok(client) => self.history = Some(client),
                        Err(failure) => {
                            self.session.failed(failure);
                            return Err(format!("history start refused; link {:?}", self.session.state()));
                        }
                    }
                }
                self.peer = Some((connection,));
                Ok(json!({"event":"connected","link":format!("{:?}", self.session.state()),
                    "sync":self.history.as_ref().map(|h| h.sync().describe())}))
            }
            "disconnect" => {
                self.peer = None;
                self.history = None;
                self.session.lost("disconnected on request");
                Ok(json!({"event":"disconnected"}))
            }
            "pay" => {
                let to = hash(c["to"].as_str().ok_or("to")?)?;
                let atoms = c["atoms"].as_u64().ok_or("atoms")?;
                let screen = self.wallet.prepare(to, atoms)?;
                use crate::plan_review::ReviewInput;
                for index in screen.review.destinations_needing_check() {
                    self.wallet.review_input(ReviewInput::ConfirmDestination { index, typed: screen.review.destination_check_text(index) })?;
                }
                for ack in screen.review.acknowledgements() {
                    self.wallet.review_input(ReviewInput::Acknowledge(*ack))?;
                }
                if let Some(phrase) = screen.review.confirmation_phrase() {
                    self.wallet.review_input(ReviewInput::ConfirmPhrase(phrase.into()))?;
                }
                match self.wallet.review_input(ReviewInput::Authorize)? {
                    ReviewOutcome::Queued(q) => Ok(json!({"event":"queued","id":hex::encode(q.id),"kind":q.kind.title(),"complete":q.complete})),
                    _ => Err("payment was not queued".into()),
                }
            }
            "advertise" => {
                let id = hash(c["id"].as_str().ok_or("id")?)?;
                let is_payment = self.wallet.pending_for_transport()?.iter().any(|raw| {
                    mutiny_consensus_v8::operation_index_v2::operation_id(0, raw).map(|(_, x)| x == id).unwrap_or(false)
                });
                let limit = Instant::now() + HANDSHAKE;
                let peer = self.peer.as_mut().map(|(c,)| &mut c.peer).ok_or("not connected")?;
                let offer = if is_payment {
                    self.wallet.advertise_payment(peer, id, limit)?
                } else {
                    self.wallet.advertise_operation(peer, id, limit)?
                };
                Ok(json!({"event":"advertised","id":hex::encode(id),"offer":format!("{offer:?}")}))
            }
            "query" => {
                let ids = c["ids"].as_array().ok_or("ids")?.iter()
                    .map(|v| hash(v.as_str().unwrap_or_default())).collect::<Result<Vec<_>>>()?;
                let limit = Instant::now() + HANDSHAKE;
                let peer = self.peer.as_mut().map(|(c,)| &mut c.peer).ok_or("not connected")?;
                let offer = self.wallet.query_operation_status(peer, &ids, limit)?;
                Ok(json!({"event":"status_query_sent","offer":format!("{offer:?}")}))
            }
            "delivery" => {
                let id = hash(c["id"].as_str().ok_or("id")?)?;
                Ok(match self.wallet.delivery(id)? {
                    Delivery::ConfirmedAt(h) => json!({"event":"delivery","id":hex::encode(id),"own_replay_confirmed_height":h}),
                    Delivery::Unconfirmed(s) => json!({"event":"delivery","id":hex::encode(id),"unconfirmed":format!("{s:?}")}),
                })
            }
            other => Err(format!("unknown command {other:?}")),
        }
    }
}

pub fn run_if_requested() -> Option<eframe::Result> {
    let values: Vec<String> = std::env::args().skip(1).collect();
    if values.first().map(String::as_str) != Some("--joint-test") {
        return None;
    }
    Some(run(&values).map_err(|e| eframe::Error::AppCreation(e.into())))
}

fn run(values: &[String]) -> Result<()> {
    if mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED || mutiny_crypto_v2::RELEASE_CUSTODY_ENABLED {
        return Err("the joint TEST host requires closed production gates".into());
    }
    let a = args(values)?;
    if !mutiny_consensus_v8::submission_pool_v1::private_directory(&a.evidence).map_err(fail)? {
        return Err("evidence folder was not newly created".into());
    }
    let verified = genesis(&a.config, a.config_pin)?;
    let g = &verified.genesis;
    let anchor = g.anchor();
    if !a.vault.path().exists()
        && !mutiny_consensus_v8::submission_pool_v1::private_directory(a.vault.path()).map_err(fail)?
    {
        return Err("vault root was not newly created".into());
    }
    let chain = CanonicalStore::open_trusted_genesis(&a.vault.path().join("public-chain.sqlite"), &anchor, &g.state, g.root, g.t0, g.target)
        .map_err(|e| format!("wallet chain: {e:?}"))?;
    let replica = Replica::from_pinned_chain(chain)?;
    let pool = Mempool::open(&a.vault.path().join("public-payment-pool.sqlite"), anchor.genesis, anchor.fingerprint, 65536)
        .map_err(|e| format!("wallet pool: {e:?}"))?;
    let mut store = Store::open(&a.vault.vault()).map_err(|e| e.to_string())?;
    if store.status().map_err(str::to_owned)?.is_none() {
        let session = Session::restore_initial(&crate::chain::phrase(false)).map_err(str::to_owned)?;
        store.save_initial(&session, PASSWORD).map_err(str::to_owned)?;
    }
    drop(store);
    let mut wallet = Controller::open(&a.vault, replica, pool, None)?;
    wallet.unlock(PASSWORD)?;
    let key = mutiny_crypto_v2::HybridKey::generate(mutiny_crypto_v2::Role::Transport).map_err(fail)?;
    let descriptor = hex::encode(key.public().descriptor(1).map_err(fail)?);
    std::fs::write(a.evidence.join("wallet-transport-descriptor.txt"), &descriptor).map_err(fail)?;
    let session = if a.history {
        // Kept beside the wallet's replica so a restart on the same vault resumes with the same queue.
        NodeSession::history(anchor.genesis, anchor.fingerprint, a.node, a.vault.path().join("public-history-queue.sqlite"))
    } else {
        NodeSession::new(anchor.genesis, anchor.fingerprint, a.node, a.evidence.join("node-queue.sqlite"))
    };
    let log = std::fs::File::create_new(a.evidence.join("events.jsonl")).map_err(fail)?;
    let mut host = Host { wallet, session, key, peer: None, history: None, log };
    let address = host.wallet.identity().map(|i| i.address_id.clone());
    host.emit(json!({"event":"ready","class":"TEST-VALUE","genesis":hex::encode(anchor.genesis),"fingerprint":hex::encode(anchor.fingerprint),
        "genesis_block":hex::encode(g.block_hash),"artifact_sha256":hex::encode(verified.artifact_sha256),
        "wallet_transport_descriptor":descriptor,"wallet_address_id":address}));

    let (tx, rx) = mpsc::sync_channel::<String>(1);
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut reader = stdin.lock();
        loop {
            let mut line = Vec::new();
            match reader.by_ref().take(MAX_LINE as u64 + 1).read_until(b'\n', &mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if tx.send(String::from_utf8_lossy(&line).into_owned()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    loop {
        host.wallet.tick();
        match rx.try_recv() {
            Ok(line) => {
                let event = match serde_json::from_str::<Value>(&line) {
                    Ok(c) if c["cmd"] == "quit" => break,
                    Ok(c) => host.command(&c).unwrap_or_else(|e| json!({"event":"refused","cmd":c["cmd"],"reason":e})),
                    Err(e) => json!({"event":"refused","reason":format!("malformed command: {e}")}),
                };
                host.emit(event);
            }
            Err(mpsc::TryRecvError::Disconnected) => break,
            Err(mpsc::TryRecvError::Empty) => {}
        }
        if host.peer.is_some() && host.history.is_some() {
            // History-profile connection: the B1 client owns every turn of this link.
            let turn = {
                let Host { wallet, peer, history, .. } = &mut host;
                let peer = &mut peer.as_mut().expect("checked").0.peer;
                wallet.history_turn(peer, history.as_mut().expect("checked"), Instant::now())
            };
            use crate::wallet_controller_v2::host::history::HistoryProgress;
            match turn {
                Ok(HistoryProgress::Idle | HistoryProgress::Transport) => {}
                Ok(progress) => {
                    let sync = host.sync_event();
                    host.emit(json!({"event":"history","progress":format!("{progress:?}")}));
                    if let Some(sync) = sync {
                        host.emit(sync);
                    }
                }
                Err(failure) => {
                    let reason = format!("{failure:?}");
                    host.peer = None;
                    host.history = None;
                    host.session.failed(failure);
                    host.emit(json!({"event":"link_lost","reason":reason,"link":format!("{:?}", host.session.state())}));
                }
            }
        } else if host.peer.is_some() {
            let turn = {
                let Host { wallet, peer, .. } = &mut host;
                let peer = &mut peer.as_mut().expect("checked").0.peer;
                wallet.peer_turn(peer, Instant::now() + TURN)
            };
            match turn {
                Ok(None | Some(Progress::Transport)) => {}
                Ok(Some(progress)) => {
                    let head = host.wallet.with_view(|v| v.anchor().height).ok();
                    host.emit(json!({"event":"history","progress":format!("{progress:?}"),"verified_height":head}));
                }
                Err(reason) => {
                    host.peer = None;
                    host.session.lost(reason.clone());
                    host.emit(json!({"event":"link_lost","reason":reason}));
                }
            }
        } else {
            std::thread::sleep(TURN);
        }
        if matches!(host.session.state(), LinkState::Lost { .. }) && host.peer.is_some() {
            host.peer = None;
        }
    }
    host.peer = None;
    host.history = None;
    host.wallet.lock();
    host.emit(json!({"event":"closed"}));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(extra: &[&str]) -> Vec<String> {
        let key = mutiny_crypto_v2::HybridKey::generate(mutiny_crypto_v2::Role::Transport).unwrap();
        let descriptor = hex::encode(key.public().descriptor(1).unwrap());
        let base = std::env::temp_dir();
        let mut v: Vec<String> = [
            "--joint-test", "--vault-root", base.join("joint-vault").to_str().unwrap(),
            "--genesis-config", base.join("genesis.json").to_str().unwrap(),
            "--genesis-config-sha256", &"ab".repeat(32), "--node", "127.0.0.1:9735",
            "--node-descriptor", &descriptor,
            "--evidence-root", base.join("joint-evidence-not-created").to_str().unwrap(),
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        v.extend(extra.iter().map(|s| s.to_string()));
        v
    }

    #[test]
    fn configuration_files_are_absolute_or_bare_siblings_only() {
        let config = std::env::temp_dir().join("bundle").join("application.json");
        assert_eq!(sibling(&config, "artifact.json").unwrap(), std::env::temp_dir().join("bundle").join("artifact.json"));
        let absolute = std::env::temp_dir().join("elsewhere.cbor");
        assert_eq!(sibling(&config, absolute.to_str().unwrap()).unwrap(), absolute);
        for refused in ["../artifact.json", "sub/artifact.json", "sub\\artifact.json", ".", ""] {
            assert!(sibling(&config, refused).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn the_history_profile_is_only_an_explicit_trailing_flag() {
        assert!(!args(&values(&[])).unwrap().history);
        assert!(args(&values(&["--history"])).unwrap().history);
        for refused in [&["--history", "--history"][..], &["--histories"], &["history"]] {
            assert!(args(&values(refused)).is_err(), "{refused:?}");
        }
        // Moving the flag anywhere but the end is refused.
        let mut early = values(&[]);
        early.insert(1, "--history".into());
        assert!(args(&early).is_err());
    }
}