//! Real executable coverage for the explicit Mainnet bootstrap command.
//! Run with --release for the mandatory release gate. No node/service is started.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

const GENESIS: &str = "9def7a0cc83e92f6e1d8692e9c29bb3f11a8986b9cb590b89214774e2c7e5481";
const BLOCK1: &str = "9d8026ac82592abb40cb1809142af67ea57b89e19ad51db35ff3d53f09907ded";
const ROOT: &str = "4d844f0393da16e076f0873358b3471425261e9fda0bf011124f1dae705faae7";
const PAYMENT: &str = "e7aa3d2f8459a0fd58683e1a7c3ea79c08403e1a82aec051db72fe0e3ddd8a89";
const WITNESS_HASH: &str = "b115c11cc8a4085a5d950be608c0e6448d9d3823d3ab15fb439d1fd231aa6126";

struct Gate {
    root: PathBuf,
    exe: PathBuf,
    witness: PathBuf,
}

impl Gate {
    fn new(name: &str) -> Self {
        let parent = env::var_os("MUTINY_BUILD70_CLI_EVIDENCE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| env::temp_dir().join("mutiny-build70-cli-evidence"));
        fs::create_dir_all(&parent).unwrap();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = parent.join(format!("{name}-{}-{nonce}", std::process::id()));
        fs::create_dir(&root).unwrap();
        let exe = env::var_os("MUTINY_BUILD70_RELEASE_EXE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_mutinyd")));
        let witness = PathBuf::from(
            env::var_os("MUTINY_MAINNET_BOOTSTRAP_WITNESS")
                .expect("set MUTINY_MAINNET_BOOTSTRAP_WITNESS to the canonical witness"),
        );
        let witness_bytes = fs::read(&witness).unwrap();
        assert_eq!(witness_bytes.len(), 161_323);
        assert_eq!(hex::encode(Sha256::digest(&witness_bytes)), WITNESS_HASH);
        fs::write(
            root.join("inputs.json"),
            serde_json::to_vec_pretty(&json!({
                "executable": exe, "executable_sha256": hex::encode(Sha256::digest(fs::read(&exe).unwrap())),
                "witness": witness, "witness_sha256": WITNESS_HASH,
            })).unwrap(),
        ).unwrap();
        eprintln!("CLI evidence: {}", root.display());
        Self { root, exe, witness }
    }

    fn run(&self, label: &str, args: &[&str]) -> Output {
        let started = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let output = Command::new(&self.exe)
            .args(args)
            .current_dir(&self.root)
            .env_remove("MUTINY_DEV_STORAGE_CRASH_AFTER")
            .stdin(Stdio::null())
            .output()
            .expect("launch actual mutinyd executable");
        fs::write(self.root.join(format!("{label}.stdout")), &output.stdout).unwrap();
        fs::write(self.root.join(format!("{label}.stderr")), &output.stderr).unwrap();
        fs::write(
            self.root.join(format!("{label}.json")),
            serde_json::to_vec_pretty(&json!({
                "executable": self.exe, "args": args, "cwd": self.root,
                "started_unix_ms": started,
                "finished_unix_ms": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis(),
                "exit_code": output.status.code(), "success": output.status.success(),
            })).unwrap(),
        ).unwrap();
        output
    }

    fn success(&self, label: &str, args: &[&str]) -> String {
        let output = self.run(label, args);
        assert!(
            output.status.success(),
            "{label}: exit={:?}; stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    fn init(&self, name: &str, network: &str) -> PathBuf {
        let dir = self.root.join(name);
        self.success(
            &format!("init-{name}"),
            &["init", "--network", network, "--data-dir", path(&dir)],
        );
        dir
    }

    fn reject_unchanged(&self, label: &str, dir: &Path, args: &[&str], error: &str) {
        let before = tree(dir);
        let output = self.run(label, args);
        let after = tree(dir);
        self.record_tree(&format!("{label}-before"), &before);
        self.record_tree(&format!("{label}-after"), &after);
        assert_eq!(before, after, "{label} changed the input directory");
        assert!(!output.status.success(), "{label} unexpectedly succeeded");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(error),
            "{label}: expected {error:?}, got {stderr}"
        );
    }

    fn record_tree(&self, label: &str, entries: &BTreeMap<String, Option<Vec<u8>>>) {
        let hashes: BTreeMap<_, _> = entries
            .iter()
            .map(|(name, bytes)| (name, bytes.as_ref().map(|b| hex::encode(Sha256::digest(b)))))
            .collect();
        fs::write(
            self.root.join(format!("{label}.tree.json")),
            serde_json::to_vec_pretty(&hashes).unwrap(),
        )
        .unwrap();
    }
}

fn path(value: &Path) -> &str {
    value.to_str().expect("test path must be Unicode")
}

// Compare actual file bytes and directory membership, including unexpected new entries.
fn tree(root: &Path) -> BTreeMap<String, Option<Vec<u8>>> {
    fn visit(root: &Path, at: &Path, out: &mut BTreeMap<String, Option<Vec<u8>>>) {
        for entry in fs::read_dir(at).unwrap() {
            let entry = entry.unwrap();
            let full = entry.path();
            assert!(
                !entry.file_type().unwrap().is_symlink(),
                "unexpected link in isolated state"
            );
            let name = full
                .strip_prefix(root)
                .unwrap()
                .to_str()
                .unwrap()
                .replace('\\', "/");
            if entry.file_type().unwrap().is_dir() {
                out.insert(format!("{name}/"), None);
                visit(root, &full, out);
            } else {
                out.insert(name, Some(fs::read(full).unwrap()));
            }
        }
    }
    let mut out = BTreeMap::new();
    if root.exists() {
        out.insert("/".into(), None);
        visit(root, root, &mut out);
    }
    out
}

fn committed_json(dir: &Path) -> Value {
    // Test-only inspection of the existing MutinyStorageV1 framing. CLI
    // storage-verify independently authenticates the snapshot and full replay.
    let meta = fs::read(dir.join("storage/meta.bin")).unwrap();
    assert_eq!(&meta[..8], b"MUTSTG01");
    let generation = u64::from_be_bytes(meta[46..54].try_into().unwrap());
    let frame =
        fs::read(dir.join(format!("storage/state/generation-{generation:020}.mst"))).unwrap();
    assert_eq!(&frame[..8], b"MUTSNP01");
    let len = u64::from_be_bytes(frame[18..26].try_into().unwrap()) as usize;
    assert_eq!(frame.len(), 26 + len + 32);
    serde_json::from_slice(&frame[26..26 + len]).unwrap()
}

#[test]
fn build70_candidate2_cli_activation_and_repeat() {
    let gate = Gate::new("activation");
    let dir = gate.init("mainnet", "mainnet");
    let initial = tree(&dir);
    gate.record_tree("height0", &initial);
    let activation = gate.success(
        "bootstrap",
        &[
            "bootstrap-mainnet",
            "--network",
            "mainnet",
            "--data-dir",
            path(&dir),
            "--bootstrap-witness",
            path(&gate.witness),
        ],
    );
    assert!(activation.contains("Mutiny Protocol V1.0 Build 7.0 Candidate 2"));
    assert!(activation.contains("Canonical Mainnet Block 1 committed"));
    for expected in [
        BLOCK1,
        ROOT,
        PAYMENT,
        "P2P listener started: NO",
        "Mining activated: NO",
    ] {
        assert!(
            activation.contains(expected),
            "missing activation result {expected}"
        );
    }
    let committed = tree(&dir);
    assert_ne!(initial, committed);
    gate.record_tree("height1", &committed);
    let status = gate.success(
        "status",
        &[
            "status",
            "--network",
            "mainnet",
            "--data-dir",
            path(&dir),
            "--bootstrap-witness",
            path(&gate.witness),
        ],
    );
    for (label, value) in [
        ("Canonical height:", "1"),
        ("Mining Licenses total:", "12"),
        ("Consumed Bitcoin pays:", "1"),
    ] {
        assert!(
            status
                .lines()
                .any(|line| line.strip_prefix(label).map(str::trim) == Some(value)),
            "missing status {label} {value}"
        );
    }
    let check = gate.success(
        "check",
        &[
            "check",
            "--network",
            "mainnet",
            "--data-dir",
            path(&dir),
            "--bootstrap-witness",
            path(&gate.witness),
        ],
    );
    for expected in [
        "State validation: PASS",
        "Full block replay: PASS",
        BLOCK1,
        ROOT,
    ] {
        assert!(check.contains(expected));
    }
    let storage = gate.success(
        "storage-verify",
        &[
            "storage-verify",
            "--network",
            "mainnet",
            "--data-dir",
            path(&dir),
            "--bootstrap-witness",
            path(&gate.witness),
        ],
    );
    for expected in [
        "0x4d555401",
        GENESIS,
        "Storage integrity: PASS",
        "Canonical replay: PASS",
    ] {
        assert!(storage.contains(expected));
    }
    let state = committed_json(&dir);
    assert_eq!(state["network_id"], 0x4d555401u32);
    assert_eq!(state["height"], 1);
    assert_eq!(state["genesis_hash"], GENESIS);
    assert_eq!(state["tip_hash"], BLOCK1);
    assert_eq!(state["current_state_root"], ROOT);
    assert_eq!(state["licenses"].as_array().unwrap().len(), 12);
    assert_eq!(
        state["consumed_bitcoin_payments"].as_array().unwrap().len(),
        1
    );
    assert_eq!(state["consumed_bitcoin_payments"][0]["payment_id"], PAYMENT);
    assert_eq!(state["bitcoin_headers"].as_array().unwrap().len(), 2_003);
    assert!(state["bitcoin_best_chain"].is_object());
    assert_eq!(
        committed,
        tree(&dir),
        "read-only CLI checks changed persisted bytes"
    );
    gate.reject_unchanged(
        "repeat",
        &dir,
        &[
            "bootstrap-mainnet",
            "--network",
            "mainnet",
            "--data-dir",
            path(&dir),
            "--bootstrap-witness",
            path(&gate.witness),
        ],
        "exact clean Mainnet height-0 state",
    );
}

#[test]
fn build70_candidate2_cli_witness_and_network_failures_are_atomic() {
    let gate = Gate::new("negative-inputs");
    let dir = gate.init("mainnet", "mainnet");
    let canonical = fs::read(&gate.witness).unwrap();
    let mut malformed = canonical.clone();
    malformed[..2].copy_from_slice(&[0, 0]);
    let mut wrong_hash = canonical.clone();
    wrong_hash[100] ^= 1;
    let mut wrong_network = canonical.clone();
    wrong_network[2] ^= 1;
    let mut wrong_genesis = canonical.clone();
    wrong_genesis[6] ^= 1;
    let truncated = canonical[..canonical.len() - 1].to_vec();
    let mut trailing = canonical.clone();
    trailing.push(0);
    for (label, bytes) in [
        ("malformed", malformed),
        ("wrong-hash", wrong_hash),
        ("wrong-network", wrong_network),
        ("wrong-genesis", wrong_genesis),
        ("truncated", truncated),
        ("trailing-byte", trailing),
    ] {
        let witness = gate.root.join(format!("{label}.bin"));
        fs::write(&witness, bytes).unwrap();
        gate.reject_unchanged(
            label,
            &dir,
            &[
                "bootstrap-mainnet",
                "--network",
                "mainnet",
                "--data-dir",
                path(&dir),
                "--bootstrap-witness",
                path(&witness),
            ],
            "LOCAL_INPUT_FAILURE: witness",
        );
    }
    let missing = gate.root.join("missing.bin");
    gate.reject_unchanged(
        "missing-path",
        &dir,
        &[
            "bootstrap-mainnet",
            "--network",
            "mainnet",
            "--data-dir",
            path(&dir),
            "--bootstrap-witness",
            path(&missing),
        ],
        "LOCAL_INPUT_FAILURE: missing witness",
    );
    gate.reject_unchanged(
        "missing-option",
        &dir,
        &[
            "bootstrap-mainnet",
            "--network",
            "mainnet",
            "--data-dir",
            path(&dir),
        ],
        "requires --bootstrap-witness PATH",
    );
    for (network, error) in [
        ("devnet", "requires --network mainnet"),
        ("testnet", "Testnet is inactive and fail-closed"),
    ] {
        gate.reject_unchanged(
            network,
            &dir,
            &[
                "bootstrap-mainnet",
                "--network",
                network,
                "--data-dir",
                path(&dir),
                "--bootstrap-witness",
                path(&gate.witness),
            ],
            error,
        );
    }
    gate.reject_unchanged(
        "implicit-network",
        &dir,
        &[
            "bootstrap-mainnet",
            "--data-dir",
            path(&dir),
            "--bootstrap-witness",
            path(&gate.witness),
        ],
        "requires --network mainnet",
    );
    let devnet = gate.init("devnet", "devnet");
    gate.reject_unchanged(
        "wrong-stored-network",
        &devnet,
        &[
            "bootstrap-mainnet",
            "--network",
            "mainnet",
            "--data-dir",
            path(&devnet),
            "--bootstrap-witness",
            path(&gate.witness),
        ],
        "NetworkID mismatch",
    );
}

#[test]
fn build70_candidate2_cli_preflight_never_recovers_or_creates_state() {
    let gate = Gate::new("read-only-preflight");
    let absent = gate.root.join("absent");
    gate.reject_unchanged(
        "absent-state",
        &absent,
        &[
            "bootstrap-mainnet",
            "--network",
            "mainnet",
            "--data-dir",
            path(&absent),
            "--bootstrap-witness",
            path(&gate.witness),
        ],
        "requires initialized Mainnet storage",
    );
    let dir = gate.init("pending-journal", "mainnet");
    fs::write(
        dir.join("storage/canonical.commit"),
        b"unrecovered journal sentinel",
    )
    .unwrap();
    gate.reject_unchanged(
        "pending-journal",
        &dir,
        &[
            "bootstrap-mainnet",
            "--network",
            "mainnet",
            "--data-dir",
            path(&dir),
            "--bootstrap-witness",
            path(&gate.witness),
        ],
        "without a pending journal",
    );
    let legacy = gate.root.join("legacy");
    fs::create_dir(&legacy).unwrap();
    fs::write(legacy.join("state.json"), b"unmigrated legacy sentinel").unwrap();
    gate.reject_unchanged(
        "legacy",
        &legacy,
        &[
            "bootstrap-mainnet",
            "--network",
            "mainnet",
            "--data-dir",
            path(&legacy),
            "--bootstrap-witness",
            path(&gate.witness),
        ],
        "requires initialized Mainnet storage",
    );
    for (field, value) in [
        ("anchor_epoch", json!(1)),
        ("anchor_license_id", json!(hex::encode([1u8; 32]))),
        ("anchor_ticket_index", json!(1)),
        ("anchor_argon2_proof", json!(hex::encode([1u8; 32]))),
    ] {
        let dirty = gate.init(field, "mainnet");
        rewrite_anchor_fixture(&dirty, field, value);
        gate.reject_unchanged(
            field,
            &dirty,
            &[
                "bootstrap-mainnet",
                "--network",
                "mainnet",
                "--data-dir",
                path(&dirty),
                "--bootstrap-witness",
                path(&gate.witness),
            ],
            "full runtime replay does not reconstruct persisted state",
        );
    }
}

// Make a validly framed, checksummed snapshot whose uncommitted Genesis anchor
// differs. This isolates clean-prestate validation from storage corruption.
fn rewrite_anchor_fixture(dir: &Path, field: &str, value: Value) {
    let mut state = committed_json(dir);
    state[field] = value;
    let payload = serde_json::to_vec(&state).unwrap();
    let meta_path = dir.join("storage/meta.bin");
    let mut meta = fs::read(&meta_path).unwrap();
    let generation = u64::from_be_bytes(meta[46..54].try_into().unwrap());
    let snapshot_path = dir.join(format!("storage/state/generation-{generation:020}.mst"));
    let original = fs::read(&snapshot_path).unwrap();
    let mut frame = original[..18].to_vec();
    frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    frame.extend_from_slice(&payload);
    let checksum = Sha256::digest(&frame);
    frame.extend_from_slice(&checksum);
    meta[158..190].copy_from_slice(&Sha256::digest(&frame));
    let checksum = Sha256::digest(&meta[..190]);
    meta[190..222].copy_from_slice(&checksum);
    fs::write(snapshot_path, frame).unwrap();
    fs::write(meta_path, meta).unwrap();
}
