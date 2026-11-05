//! D2 Treasury ceremony REHEARSAL: tooling flow, negative controls, manifest class safety,
//! deterministic public outputs, retry safety, durable admission and the secret/TEST-VALUE guard.
//! SIMULATED / TEST-VALUE evidence only. All keys derive from public labels or OS entropy kept in
//! temp dirs that the test deletes. Nothing here is a production identity.
use mutiny_consensus_v8::{
    blocks::GenesisDescriptor,
    genesis_inputs::{GenesisProfile, Parameters, dividend_state},
    treasury_v1::{Class, Treasury},
};
use crate::{
    treasury_admission_v1::AdmissionStore,
    treasury_rehearsal_v1::{self as r, CeremonyConfig, Denylist, ExpectedContext, Expect, Refusal},
};
use mutiny_crypto_v2::{
    Domain, HybridKey, NETWORK, Role, rehearsal_keys_v1 as keys,
    treasury_proof_v1::{self as proof, Challenge, Phase, ProofError},
};
use sha2::{Digest, Sha256};

#[path = "support/legacy_treasury_public_tool_v2.rs"]
#[allow(dead_code)]
mod public_tool;
#[path = "support/treasury_ceremony_support.rs"]
mod support;

const CONTEXT: &str = "d2-rehearsal-ceremony-2026";

fn run_with(f: impl Fn(&[String], &mut dyn std::io::Write, &mut dyn std::io::Write) -> i32, args: &[&str]) -> (i32, String, String) {
    let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = f(&args, &mut out, &mut err);
    (code, String::from_utf8(out).unwrap(), String::from_utf8(err).unwrap())
}
fn key_tool(args: &[&str]) -> (i32, String, String) {
    run_with(|a, o, e| keys::run(a, o, e), args)
}
fn pub_tool(args: &[&str]) -> (i32, String, String) {
    run_with(|a, o, e| public_tool::run(a, o, e), args)
}
fn p(dir: &std::path::Path, name: &str) -> String {
    dir.join(name).to_str().unwrap().to_string()
}
fn file(path: &str) -> String {
    std::fs::read_to_string(path).unwrap()
}
fn raw(path: &str) -> Vec<u8> {
    hex::decode(file(path).trim()).unwrap()
}
fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(|s| s.to_string()).collect()
}
/// `args` with the value after `flag` replaced.
fn with(args: &[String], flag: &str, value: &str) -> Vec<String> {
    let mut v = args.to_vec();
    let i = v.iter().position(|a| a == flag).unwrap_or_else(|| panic!("{flag} not in {v:?}"));
    v[i + 1] = value.to_string();
    v
}
/// `args` without `flag` and its value.
fn without(args: &[String], flag: &str) -> Vec<String> {
    let mut v = args.to_vec();
    let i = v.iter().position(|a| a == flag).unwrap_or_else(|| panic!("{flag} not in {v:?}"));
    v.drain(i..i + 2);
    v
}
/// The value printed after `key ` on its own output line.
fn printed(out: &str, key: &str) -> String {
    out.lines().find_map(|l| l.strip_prefix(&format!("{key} "))).unwrap_or_else(|| panic!("{key} not printed: {out}")).to_string()
}

/// Everything an operator run produces, in one temp directory.
struct Run {
    dir: std::path::PathBuf,
}
impl Run {
    fn new(tag: &str) -> Self {
        let dir = support::scratch_dir(tag);
        let d = dir.to_str().unwrap();
        assert_eq!(key_tool(&["keygen", "--generation", "1", "--out-dir", d, "--label", "d2-int-k1"]).0, 0);
        assert_eq!(key_tool(&["keygen", "--generation", "2", "--out-dir", d, "--label", "d2-int-k2"]).0, 0);
        let run = Self { dir };
        let (code, _, err) = tool("challenge", &run.trusted(), &["--descriptor-file", &run.f("key-g1.descriptor.hex"), "--nonce-label", "n1", "--out", &run.f("challenge-g1.hex")]);
        assert_eq!(code, 0, "{err}");
        let (code, _, err) = key_tool(&["sign", "--generation", "1", "--label", "d2-int-k1", "--challenge-file", &run.f("challenge-g1.hex"), "--out", &run.f("proof-g1.sig.hex")]);
        assert_eq!(code, 0, "{err}");
        run
    }
    fn f(&self, name: &str) -> String {
        p(&self.dir, name)
    }
    /// The approved (pinned) SHA-256 of the TEST-VALUE Treasury record of K1.
    fn record_pin(&self) -> String {
        let treasury = Treasury::new(Class::TestValue, raw(&self.f("key-g1.descriptor.hex"))).unwrap();
        hex::encode(r::record_sha256(&treasury).unwrap())
    }
    /// The TRUSTED ceremony configuration arguments.
    fn trusted(&self) -> Vec<String> {
        strings(&["--treasury-descriptor-file", &self.f("key-g1.descriptor.hex"), "--expected-record-sha256", &self.record_pin(), "--context-label", CONTEXT])
    }
    /// The trusted configuration plus the K1 proof files.
    fn g1(&self) -> Vec<String> {
        let mut v = self.trusted();
        v.extend(strings(&["--descriptor-file", &self.f("key-g1.descriptor.hex"), "--challenge-file", &self.f("challenge-g1.hex"), "--signature-file", &self.f("proof-g1.sig.hex")]));
        v
    }
}
impl Drop for Run {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
fn tool(cmd: &str, base: &[String], extra: &[&str]) -> (i32, String, String) {
    let mut args = vec![cmd];
    args.extend(base.iter().map(String::as_str));
    args.extend_from_slice(extra);
    pub_tool(&args)
}

fn all_outputs(dir: &std::path::Path) -> Vec<(String, String)> {
    let mut v = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let path = e.unwrap().path();
        if path.is_dir() {
            v.extend(all_outputs(&path));
        } else {
            v.push((path.to_str().unwrap().to_string(), String::from_utf8_lossy(&std::fs::read(&path).unwrap()).into_owned()));
        }
    }
    v
}
/// Secret-shape guard for consensus-side outputs. `labels` are the public labels whose phrase and
/// entropy must never appear in any emitted text.
fn assert_public_only(what: &str, text: &str, labels: &[&str]) {
    let lower = text.to_ascii_lowercase();
    for label in labels {
        let phrase = keys::label_phrase(label).unwrap();
        let words: Vec<&str> = phrase.split_whitespace().collect();
        for w in words.windows(3) {
            assert!(!text.contains(&w.join(" ")), "{what}: phrase fragment of {label}");
        }
        let mut h = Sha256::new();
        h.update(b"MUTINY-BUILD8-TREASURY-REHEARSAL-TEST-VALUE-LABEL-V1\0");
        h.update(label.as_bytes());
        assert!(!lower.contains(&hex::encode(h.finalize())), "{what}: entropy of {label}");
    }
    for banned in ["mnemonic", "passphrase", "private key", "begin private", "seed phrase", "secret key"] {
        assert!(!lower.contains(banned), "{what}: secret-shaped word {banned}");
    }
    // Any run of 24 lowercase words is secret-shaped (a BIP39 phrase has exactly 24 words).
    let words: Vec<&str> = text.split_whitespace().collect();
    let mut run = 0;
    for w in &words {
        run = if w.len() >= 3 && w.len() <= 8 && w.bytes().all(|b| b.is_ascii_lowercase()) { run + 1 } else { 0 };
        assert!(run < 12, "{what}: twelve consecutive short lowercase words");
    }
}
/// The approver's final manifest: the reviewed rehearsal manifest JSON, plus the approved GenesisID when
/// a full Genesis descriptor is to be checked. Returns (path, SHA-256 hex) of the written file.
fn approval_file(dir: &std::path::Path, name: &str, manifest_json: &str, genesis_id: Option<&str>) -> (String, String) {
    let mut v: serde_json::Value = serde_json::from_str(manifest_json).unwrap();
    if let Some(id) = genesis_id {
        v["genesis_id"] = serde_json::Value::String(id.to_string());
    }
    let text = serde_json::to_string_pretty(&v).unwrap() + "\n";
    let path = p(dir, name);
    std::fs::write(&path, &text).unwrap();
    (path, hex::encode(Sha256::digest(text.as_bytes())))
}

#[test]
fn operator_flow_end_to_end_with_negative_controls_admission_and_class_safety() {
    let run = Run::new("flow");
    let g1 = run.g1();
    let store = run.f("admissions.sqlite");
    let store_path = std::path::Path::new(&store);
    // ---- A9: read-only verification with the ceremony negative controls (no store, no consumption).
    let (code, out, err) = tool("verify", &g1, &["--generation", "1", "--negative-controls"]);
    assert_eq!(code, 0, "{out}\n{err}");
    assert!(out.contains("CLASS: TEST-VALUE (2)") && out.contains("VERIFIED (read-only; no nonce consumed)"));
    assert_eq!(out.matches("[PASS]").count(), 16, "{out}");
    assert!(!out.contains("[FAIL]"));
    // The Treasury identity is never taken from the proof: without the trusted descriptor, refused.
    let (code, _, err) = tool("verify", &without(&g1, "--treasury-descriptor-file"), &["--generation", "1"]);
    assert_eq!(code, 2);
    assert!(err.contains("--treasury-descriptor-file"), "{err}");
    // F7: the trusted descriptor must reproduce the pinned record hash; the pin is mandatory.
    let (code, _, err) = tool("verify", &without(&g1, "--expected-record-sha256"), &["--generation", "1"]);
    assert_eq!(code, 2);
    assert!(err.contains("--expected-record-sha256"), "{err}");
    let (code, _, err) = tool("verify", &with(&g1, "--expected-record-sha256", &hex::encode([0x11; 32])), &["--generation", "1"]);
    assert_eq!(code, 2);
    assert!(err.contains("does not produce the pinned record SHA-256"), "{err}");
    // A wrong ceremony context fails.
    let wrong_context = with(&g1, "--context-label", "some-other-ceremony");
    let (code, _, err) = tool("verify", &wrong_context, &["--generation", "1"]);
    assert_eq!(code, 1, "{err}");
    assert!(err.contains("WrongContext"), "{err}");

    // ---- Durable first admission: explicit store creation, admission, replay refused across restarts.
    let (code, _, err) = tool("admit", &g1, &["--generation", "1", "--store", &store]);
    assert_eq!(code, 2, "an admission never creates a missing store: {err}");
    assert!(!store_path.exists());
    let (code, out, err) = tool("create-store", &run.trusted(), &["--store", &store]);
    assert_eq!(code, 0, "{out}{err}");
    let store_id = printed(&out, "store_id");
    assert_eq!(store_id.len(), 64);
    let (code, _, _) = tool("create-store", &run.trusted(), &["--store", &store]);
    assert_eq!(code, 2, "an existing store is never re-created");
    let empty_store = support::file_sha256(store_path);
    // A wrong ceremony context cannot even open this ceremony's store; nothing changes.
    let (code, _, err) = tool("admit", &wrong_context, &["--generation", "1", "--store", &store]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("StoreBinding"), "{err}");
    assert_eq!(support::file_sha256(store_path), empty_store);
    let (code, out, err) = tool("admit", &g1, &["--generation", "1", "--store", &store]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("ADMITTED (nonce consumed durably in this store)"));
    assert_eq!(printed(&out, "store_id"), store_id);
    let admitted = support::file_sha256(store_path);
    assert_ne!(admitted, empty_store);
    // Every tool invocation reopens the file: a replay is refused after the "restart" and leaves the
    // store byte-identical.
    let (code, _, err) = tool("admit", &g1, &["--generation", "1", "--store", &store]);
    assert_eq!(code, 1);
    assert!(err.contains("Replay"), "{err}");
    assert_eq!(support::file_sha256(store_path), admitted);
    // Read-only verification is still possible and still consumes nothing.
    assert_eq!(tool("verify", &g1, &["--generation", "1"]).0, 0);
    assert_eq!(support::file_sha256(store_path), admitted);

    // ---- A8/A9: the rehearsal Genesis manifest from the ADMITTED proof: deterministic, TEST-VALUE,
    //      retry safe, read-only on the store, naming the store id.
    let out1 = run.dir.join("m1");
    let out2 = run.dir.join("m2");
    std::fs::create_dir(&out1).unwrap();
    std::fs::create_dir(&out2).unwrap();
    for o in [&out1, &out2, &out1] {
        let (code, text, err) = tool("manifest", &g1, &["--store", &store, "--out-dir", o.to_str().unwrap()]);
        assert_eq!(code, 0, "{err}");
        assert!(text.contains("CLASS: TEST-VALUE (2)"));
        assert_eq!(printed(&text, "admission_store_id"), store_id);
    }
    assert_eq!(support::file_sha256(store_path), admitted, "the manifest build consumes nothing");
    let manifest = file(&p(&out1, "genesis-manifest.json"));
    assert_eq!(manifest, file(&p(&out2, "genesis-manifest.json")), "deterministic bytes");
    assert_eq!(file(&p(&out1, "genesis-parameters.hex")), file(&p(&out2, "genesis-parameters.hex")));
    let store_line = format!("\"admission_store_id\": \"{store_id}\"");
    for needle in ["\"class\": \"TEST-VALUE\"", "\"class_byte\": 2", "CLASS: TEST-VALUE (2)", "SIMULATED-REHEARSAL-NOT-PRODUCTION", "TEST-VALUE != production", "\"production_security_qualified\": false", "IMPOSSIBLE-FROM-REHEARSAL-KEYS", "\"test_profile_accepts\": true", "\"production_profile_rejects\": true", "MUTINY-BUILD8-TREASURY-PROOF-OF-CONTROL-V1", "\"ceremony_context_label\": \"d2-rehearsal-ceremony-2026\"", store_line.as_str()] {
        assert!(manifest.contains(needle), "manifest lacks {needle}");
    }
    assert!(!manifest.contains("PRODUCTION (1)") && !manifest.contains("\"class\": \"PRODUCTION\""));
    assert!(serde_json::from_str::<serde_json::Value>(&manifest).is_ok(), "the manifest is JSON");
    // The manifest hashes are the independent recomputation of the public bytes.
    let descriptor = raw(&run.f("key-g1.descriptor.hex"));
    let treasury = Treasury::new(Class::TestValue, descriptor.clone()).unwrap();
    assert!(manifest.contains(&hex::encode(Sha256::digest(&descriptor))));
    assert!(manifest.contains(&hex::encode(Sha256::digest(treasury.encode().unwrap()))));
    // A tampered manifest request is refused and emits nothing: wrong context (store binding).
    let bad_dir = run.dir.join("m3");
    std::fs::create_dir(&bad_dir).unwrap();
    let (code, _, _) = tool("manifest", &wrong_context, &["--store", &store, "--out-dir", bad_dir.to_str().unwrap()]);
    assert_ne!(code, 0);
    assert!(std::fs::read_dir(&bad_dir).unwrap().next().is_none(), "nothing emitted on refusal");
    // Production requests are refused by name, by both tools.
    for args in [vec!["manifest", "--class", "production", "--out-dir", "."], vec!["manifest", "--production"]] {
        let (code, o, e) = pub_tool(&args);
        assert_eq!(code, 2);
        assert!(o.is_empty() && e.contains("no production mode"));
    }

    // ---- B8: post-freeze recomputation against the independently approved manifest, which is pinned by
    //      a SHA-256 supplied separately; read-only, repeatable, the store stays byte-identical.
    let params_file = p(&out1, "genesis-parameters.hex");
    let frozen = raw(&params_file);
    let approvals = run.dir.join("approvals");
    std::fs::create_dir(&approvals).unwrap();
    let (approved, approved_pin) = approval_file(&approvals, "approved-parameters.json", &manifest, None);
    let mut frozen_args = run.trusted();
    frozen_args.extend(strings(&["--challenge-file", &run.f("challenge-g1.hex"), "--signature-file", &run.f("proof-g1.sig.hex"), "--store", &store, "--approved-manifest", &approved, "--approved-manifest-sha256", &approved_pin]));
    for _ in 0..2 {
        let (code, out, err) = tool("verify-frozen", &frozen_args, &["--parameters-file", &params_file]);
        assert_eq!(code, 0, "{err}");
        assert!(out.contains("CLASS: TEST-VALUE (2)") && !out.contains("genesis_id_recomputed"), "{out}");
        assert!(out.contains("PASS FOR THE PARAMETERS BYTES ONLY") && out.contains("NOT compared"), "{out}");
        assert!(!out.contains("approved manifest matched"), "no over-claiming wording: {out}");
        assert_eq!(printed(&out, "store_id"), store_id);
        assert_eq!(support::file_sha256(store_path), admitted, "an audit consumes nothing");
    }
    // F6: the approval is pinned by its SHA-256; a different file (or a missing pin) is refused.
    let (code, _, err) = tool("verify-frozen", &with(&frozen_args, "--approved-manifest-sha256", &hex::encode(Sha256::digest(manifest.as_bytes()))), &["--parameters-file", &params_file]);
    assert_eq!(code, 2, "the manifest command's own output is not the pinned approval");
    assert!(err.contains("does not match the pinned SHA-256"), "{err}");
    let (code, _, err) = tool("verify-frozen", &without(&frozen_args, "--approved-manifest-sha256"), &["--parameters-file", &params_file]);
    assert_eq!(code, 2);
    assert!(err.contains("--approved-manifest-sha256"), "{err}");
    // F3 / review r4: a full Genesis descriptor needs the approved GenesisID (flag AND approval JSON).
    let parameters = Parameters::decode(&frozen).unwrap();
    let descriptor_g = GenesisDescriptor {
        timestamp: 1,
        nonce: [1; 32],
        fingerprint: parameters.rules.fingerprint().unwrap(),
        owner: [2; 32],
        purchase: [3; 32],
        parameters: frozen.clone(),
        admission_records: vec![],
        recovery: [4; 32],
    };
    let gfile = p(&run.dir, "genesis-descriptor.bin");
    std::fs::write(&gfile, descriptor_g.encode().unwrap()).unwrap();
    let genesis_id = hex::encode(descriptor_g.id().unwrap());
    let unapproved = GenesisDescriptor { timestamp: 4242, nonce: [0x42; 32], fingerprint: [0x66; 32], owner: [0xee; 32], purchase: [0xdd; 32], recovery: [0xcc; 32], ..descriptor_g.clone() };
    let ufile = p(&run.dir, "unapproved-genesis-descriptor.bin");
    std::fs::write(&ufile, unapproved.encode().unwrap()).unwrap();
    let unapproved_id = hex::encode(unapproved.id().unwrap());
    let (code, out, err) = tool("verify-frozen", &frozen_args, &["--genesis-descriptor-file", &ufile]);
    assert_eq!((code, out.as_str()), (2, ""), "r4: no PASS without an approved GenesisID: {err}");
    assert!(err.contains("--approved-genesis-id"), "{err}");
    let (code, _, err) = tool("verify-frozen", &frozen_args, &["--genesis-descriptor-file", &ufile, "--approved-genesis-id", &unapproved_id]);
    assert_eq!(code, 2, "the approval JSON names no GenesisID: {err}");
    assert!(err.contains("must name the GenesisID"), "{err}");
    let (code, _, err) = tool("verify-frozen", &frozen_args, &["--parameters-file", &params_file, "--approved-genesis-id", &genesis_id]);
    assert_eq!(code, 2);
    assert!(err.contains("applies to --genesis-descriptor-file only"), "{err}");
    // The approver's final manifest names the GenesisID of the approved descriptor.
    let (named, named_pin) = approval_file(&approvals, "approved-genesis.json", &manifest, Some(&genesis_id));
    let genesis_args = with(&with(&frozen_args, "--approved-manifest", &named), "--approved-manifest-sha256", &named_pin);
    let (code, out, err) = tool("verify-frozen", &genesis_args, &["--genesis-descriptor-file", &gfile, "--approved-genesis-id", &genesis_id]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("PASS: the recomputed GenesisID equals the approved GenesisID (every Genesis field is covered)"), "{out}");
    assert_eq!(printed(&out, "genesis_id_recomputed"), genesis_id);
    // r4 with an approval that names the approved GenesisID: the unapproved wrapper is refused.
    let (code, _, err) = tool("verify-frozen", &genesis_args, &["--genesis-descriptor-file", &ufile, "--approved-genesis-id", &genesis_id]);
    assert_eq!(code, 1);
    assert!(err.contains("ManifestMismatch"), "{err}");
    // Another Genesis wrapper (other nonce only) is not the approved one.
    let ofile = p(&run.dir, "other-genesis-descriptor.bin");
    std::fs::write(&ofile, GenesisDescriptor { nonce: [9; 32], ..descriptor_g.clone() }.encode().unwrap()).unwrap();
    let (code, _, err) = tool("verify-frozen", &genesis_args, &["--genesis-descriptor-file", &ofile, "--approved-genesis-id", &genesis_id]);
    assert_eq!(code, 1);
    assert!(err.contains("ManifestMismatch"), "{err}");
    // An approval that names a GenesisID cannot be satisfied by the Parameters bytes alone.
    let (code, _, err) = tool("verify-frozen", &genesis_args, &["--parameters-file", &params_file]);
    assert_eq!(code, 1);
    assert!(err.contains("ManifestMismatch"), "{err}");
    // An approval of other Parameters bytes (another initial target) does not match the frozen bytes.
    let changed = Parameters { initial_target: [254; 32], ..parameters.clone() };
    let changed_file = run.dir.join("changed-parameters.hex");
    std::fs::write(&changed_file, hex::encode(changed.encode().unwrap())).unwrap();
    let (code, _, err) = tool("verify-frozen", &frozen_args, &["--parameters-file", changed_file.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(err.contains("ManifestMismatch"), "{err}");
    // Frozen Treasury differing from the trusted one is caught: another key's Treasury.
    let impostor = Parameters {
        initial_target: [255; 32],
        rules: r::rehearsal_rules(),
        treasury: Some(Treasury::new(Class::TestValue, HybridKey::wallet_restore(&keys::label_phrase("d2-int-imp").unwrap(), Role::WalletOwner).unwrap().public().descriptor(1).unwrap()).unwrap()),
    };
    let impostor_file = run.dir.join("impostor-parameters.hex");
    std::fs::write(&impostor_file, hex::encode(impostor.encode().unwrap())).unwrap();
    let (code, _, err) = tool("verify-frozen", &frozen_args, &["--parameters-file", impostor_file.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert!(err.contains("FrozenMismatch"), "{err}");
    assert_eq!(support::file_sha256(store_path), admitted);
    // F5 / review r5 through the tool: a second store for the same ceremony admits the replayed nonce
    // (the stated limit), but it is not the store the approval names.
    let second = run.f("second.sqlite");
    let (code, out, _) = tool("create-store", &run.trusted(), &["--store", &second]);
    assert_eq!(code, 0);
    assert_ne!(printed(&out, "store_id"), store_id);
    assert_eq!(tool("admit", &g1, &["--generation", "1", "--store", &second]).0, 0, "replay into a fresh store (not prevented)");
    let (code, _, err) = tool("verify-frozen", &with(&frozen_args, "--store", &second), &["--parameters-file", &params_file]);
    assert_eq!(code, 1);
    assert!(err.contains("WrongStore"), "{err}");
    // inspect prints the class unmistakably for rehearsal and for a production-class record alike.
    let (code, out, _) = pub_tool(&["inspect", "--parameters-file", &params_file]);
    assert_eq!(code, 0);
    assert!(out.starts_with("CLASS: TEST-VALUE (2)"));
    let production_class = Parameters { initial_target: [255; 32], rules: r::rehearsal_rules(), treasury: Some(Treasury::new(Class::Production, descriptor.clone()).unwrap()) };
    assert!(r::inspect_parameters(&production_class.encode().unwrap()).unwrap().starts_with("CLASS: PRODUCTION (1)"));
    // Class gating: TEST-VALUE Parameters are refused by the Production profile.
    assert!(dividend_state(&parameters, GenesisProfile::Production).is_err());
    assert!(dividend_state(&parameters, GenesisProfile::Test).is_ok());

    // ---- A11: K2 (generation 2) proves control against the Treasury of K1 ONLY with the exact
    //      authorized rotation plan K1 -> K2, pinned by identity in the trusted configuration and
    //      evaluated on the trusted chain at the trusted height; an impostor generation-2 key is refused.
    let k1 = keys::Credential::from_label("d2-int-k1", 1).unwrap();
    let k2 = keys::Credential::from_label("d2-int-k2", 2).unwrap();
    let k3 = keys::Credential::from_label("d2-int-k3", 2).unwrap();
    let plan = support::rotation_plan(treasury.authority(), k1.key(), k1.descriptor().unwrap(), k2.key(), k2.descriptor().unwrap(), support::plan_genesis(), support::plan_fingerprint());
    std::fs::write(run.f("plan-g2.hex"), hex::encode(plan.encode().unwrap())).unwrap();
    let rival = support::rotation_plan(treasury.authority(), k1.key(), k1.descriptor().unwrap(), k3.key(), k3.descriptor().unwrap(), support::plan_genesis(), support::plan_fingerprint());
    std::fs::write(run.f("rival-plan.hex"), hex::encode(rival.encode().unwrap())).unwrap();
    let (code, _, err) = tool("challenge", &run.trusted(), &["--descriptor-file", &run.f("key-g2.descriptor.hex"), "--nonce-label", "n2", "--out", &run.f("challenge-g2.hex")]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(key_tool(&["sign", "--generation", "2", "--label", "d2-int-k2", "--challenge-file", &run.f("challenge-g2.hex"), "--out", &run.f("proof-g2.sig.hex")]).0, 0);
    let mut g2 = run.trusted();
    g2.extend(strings(&[
        "--descriptor-file",
        &run.f("key-g2.descriptor.hex"),
        "--challenge-file",
        &run.f("challenge-g2.hex"),
        "--signature-file",
        &run.f("proof-g2.sig.hex"),
        "--generation",
        "2",
    ]));
    let plan_args = strings(&[
        "--rotation-plan-file",
        &run.f("plan-g2.hex"),
        "--plan-identity",
        &hex::encode(plan.identity().unwrap()),
        "--chain-genesis",
        &hex::encode(support::plan_genesis()),
        "--chain-fingerprint",
        &hex::encode(support::plan_fingerprint()),
        "--trusted-height",
        &support::TRUSTED_HEIGHT.to_string(),
    ]);
    let g2_plan = [g2.clone(), plan_args.clone()].concat();
    // Without the plan inputs, a generation-2 proof is not even considered.
    let (code, _, err) = tool("verify", &g2, &[]);
    assert_eq!(code, 2);
    assert!(err.contains("--rotation-plan-file") && err.contains("--plan-identity"), "{err}");
    let (code, _, err) = tool("verify", &without(&g2_plan, "--plan-identity"), &[]);
    assert_eq!(code, 2, "the plan identity comes from the configuration, never from the plan file: {err}");
    let (code, out, err) = tool("verify", &g2_plan, &["--negative-controls"]);
    assert_eq!(code, 0, "{out}{err}");
    assert!(out.contains("key_generation 2") && out.matches("[PASS]").count() == 16, "{out}");
    let (code, out, err) = tool("admit", &g2_plan, &["--store", &store]);
    assert_eq!(code, 0, "{out}{err}");
    // F2 / S1 through the tool: the chain identity, the pinned identity and the trusted height decide.
    let wrong_chain = with(&g2_plan, "--chain-genesis", &hex::encode(support::plan_fingerprint()));
    let (code, _, err) = tool("verify", &wrong_chain, &[]);
    assert_eq!(code, 2);
    assert!(err.contains("WrongChain"), "{err}");
    let expired = with(&g2_plan, "--trusted-height", "101");
    let (code, _, err) = tool("verify", &expired, &[]);
    assert_eq!(code, 2);
    assert!(err.contains("PlanOutOfWindow"), "{err}");
    let rival_file = with(&g2_plan, "--rotation-plan-file", &run.f("rival-plan.hex"));
    let (code, _, err) = tool("verify", &rival_file, &[]);
    assert_eq!(code, 2, "a second validly signed plan is not the pinned plan");
    assert!(err.contains("PlanNotAuthorized"), "{err}");
    // Impostor: K3 (generation 2) signs the Treasury's PUBLIC identifiers under its own nonce.
    let imp_dir = run.dir.join("imp");
    std::fs::create_dir(&imp_dir).unwrap();
    assert_eq!(key_tool(&["keygen", "--generation", "2", "--out-dir", imp_dir.to_str().unwrap(), "--label", "d2-int-k3"]).0, 0);
    let (code, _, err) = tool("challenge", &run.trusted(), &["--descriptor-file", &p(&imp_dir, "key-g2.descriptor.hex"), "--nonce-label", "n3", "--out", &p(&imp_dir, "challenge.hex")]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(key_tool(&["sign", "--generation", "2", "--label", "d2-int-k3", "--challenge-file", &p(&imp_dir, "challenge.hex"), "--out", &p(&imp_dir, "proof.sig.hex")]).0, 0);
    let impostor_args = with(&with(&with(&g2_plan, "--descriptor-file", &p(&imp_dir, "key-g2.descriptor.hex")), "--challenge-file", &p(&imp_dir, "challenge.hex")), "--signature-file", &p(&imp_dir, "proof.sig.hex"));
    let before_impostor = support::file_sha256(store_path);
    let (code, _, err) = tool("admit", &impostor_args, &["--store", &store]);
    assert_eq!(code, 1);
    assert!(err.contains("UnauthorizedSuccessor"), "{err}");
    assert_eq!(support::file_sha256(store_path), before_impostor, "a refused impostor consumes nothing");
    // ... and pinning the rival plan is what would make K3 the successor (the pin is the trusted input).
    let rival_pinned = with(&with(&impostor_args, "--rotation-plan-file", &run.f("rival-plan.hex")), "--plan-identity", &hex::encode(rival.identity().unwrap()));
    assert_eq!(tool("verify", &rival_pinned, &[]).0, 0);
    // K2's proof is not accepted as generation 1.
    let (code, _, err) = tool("verify", &with(&g2, "--generation", "1"), &[]);
    assert_eq!(code, 1);
    assert!(err.contains("WrongKeyVersion"), "{err}");
    let (code, _, err) = tool("verify", &with(&g2_plan, "--generation", "1"), &[]);
    assert_eq!(code, 2, "a rotation plan applies to generation 2 only: {err}");

    // ---- R-guard: nothing emitted contains a secret shape; every JSON file is stamped TEST-VALUE.
    for (name, text) in all_outputs(&run.dir) {
        assert_public_only(&name, &text, &["d2-int-k1", "d2-int-k2", "d2-int-k3", "d2-int-imp"]);
        if name.ends_with(".json") {
            assert!(text.contains("TEST-VALUE"), "{name} lacks the TEST-VALUE marker");
        }
    }
}

#[test]
fn library_controls_cover_every_rejection_reason_and_cannot_emit_production() {
    let k1 = keys::Credential::from_label("d2-lib-k1", 1).unwrap();
    let descriptor = k1.descriptor().unwrap();
    let treasury = Treasury::new(Class::TestValue, descriptor.clone()).unwrap();
    let config = CeremonyConfig::rehearsal(NETWORK, treasury.clone(), CONTEXT).unwrap();
    let expect = Expect::genesis_key(&config);
    let nonce: [u8; 32] = Sha256::digest(b"lib-nonce").into();
    let c = r::build_challenge(&config, &descriptor, nonce).unwrap();
    let bytes = c.encode().unwrap();
    let sig = proof::sign_challenge(k1.key(), &descriptor, &c).unwrap();
    let deny = Denylist::default();
    let ok = r::verify_proof(&expect, &descriptor, &bytes, &sig, &deny).unwrap();
    assert_eq!(ok.class, Class::TestValue);
    // Controls, with specific reasons.
    let v = |e: &Expect, d: &[u8], b: &[u8], s: &mutiny_crypto_v2::HybridSignature| r::verify_proof(e, d, b, s, &deny);
    let mut altered = descriptor.clone();
    altered[300] ^= 1;
    assert_eq!(v(&expect, &altered, &bytes, &sig), Err(Refusal::AlteredDescriptor));
    let other = keys::Credential::from_label("d2-lib-other", 1).unwrap().descriptor().unwrap();
    assert_eq!(v(&expect, &other, &bytes, &sig), Err(Refusal::AlteredDescriptor));
    let other_context = CeremonyConfig::rehearsal(NETWORK, treasury.clone(), "another-ceremony").unwrap();
    assert_eq!(v(&Expect::genesis_key(&other_context), &descriptor, &bytes, &sig), Err(Refusal::WrongContext));
    // Another Treasury record (different key) does not match the challenge's record binding.
    let foreign = CeremonyConfig::rehearsal(NETWORK, Treasury::new(Class::TestValue, other.clone()).unwrap(), CONTEXT).unwrap();
    assert_eq!(v(&Expect::genesis_key(&foreign), &other, &bytes, &sig), Err(Refusal::TreasuryMismatch));
    // Class mismatch: the same descriptor in a production-class record is not a rehearsal ceremony,
    // and a production configuration is refused at every step.
    let production = Treasury::new(Class::Production, descriptor.clone()).unwrap();
    assert_eq!(CeremonyConfig::rehearsal(NETWORK, production.clone(), CONTEXT), Err(Refusal::ClassMismatch));
    let production_config = CeremonyConfig::new(NETWORK, production.clone(), ExpectedContext::production_supplied([0x5c; 32]).unwrap()).unwrap();
    assert_eq!(r::build_challenge(&production_config, &descriptor, nonce), Err(Refusal::ProductionRefused));
    assert_eq!(v(&Expect::genesis_key(&production_config), &descriptor, &bytes, &sig), Err(Refusal::ProductionRefused));
    // Production-phase challenge: refused at signing and at verification.
    let pc = Challenge::new(&descriptor, Phase::Production, treasury.authority(), r::record_sha256(&production).unwrap(), config.context().value(), nonce).unwrap();
    assert_eq!(proof::sign_challenge(k1.key(), &descriptor, &pc), Err(ProofError::ProductionRefused));
    let praw = k1.key().sign(Domain::TreasuryProofOfControl, &pc.encode().unwrap()).unwrap();
    assert_eq!(v(&expect, &descriptor, &pc.encode().unwrap(), &praw), Err(Refusal::ProductionRefused));
    // The manifest builder refuses a production configuration and consumes nothing.
    let store = AdmissionStore::in_memory(&config).unwrap();
    assert_eq!(
        r::build_manifest(&Expect::genesis_key(&production_config), &descriptor, &bytes, &sig, [255; 32], &r::rehearsal_rules(), &deny, &store),
        Err(Refusal::ProductionRefused)
    );
    assert!(store.admissions().unwrap().is_empty(), "a refusal consumes no nonce");
    // A manifest needs an ADMITTED proof.
    assert_eq!(r::build_manifest(&expect, &descriptor, &bytes, &sig, [255; 32], &r::rehearsal_rules(), &deny, &store), Err(Refusal::NotAdmitted));
    // Replay.
    let mut store = AdmissionStore::in_memory(&config).unwrap();
    store.admit(&expect, &descriptor, &bytes, &sig, &deny).unwrap();
    assert_eq!(store.admit(&expect, &descriptor, &bytes, &sig, &deny), Err(Refusal::Replay));
    // Only one signature component.
    let mut half = sig.clone();
    half.ed448 = [0; 114];
    assert_eq!(v(&expect, &descriptor, &bytes, &half), Err(Refusal::Proof(ProofError::BadSignature)));
    // The built-in negative-control runner passes in full; on a proof that is not accepted (or a
    // challenge too short to mutate) it reports only the failed control and never panics.
    let results = r::negative_controls(&expect, &descriptor, &bytes, &sig);
    assert_eq!(results.len(), 16);
    for (name, rejected) in &results {
        assert!(rejected, "{name}");
    }
    for short in [&[][..], &[0x8e][..], &bytes[..4]] {
        assert_eq!(r::negative_controls(&expect, &descriptor, short, &sig), vec![("control: unmodified proof accepted", false)]);
    }
    assert_eq!(r::negative_controls(&expect, &descriptor[..10], &bytes, &sig), vec![("control: unmodified proof accepted", false)]);
    // A signature from the proof domain is not valid as a spend authorization.
    assert!(k1.key().public().verify(Domain::Transaction, &bytes, &sig).is_err());
    // Manifest bytes are a pure function of the inputs.
    let m1 = r::build_manifest(&expect, &descriptor, &bytes, &sig, [255; 32], &r::rehearsal_rules(), &deny, &store).unwrap();
    let m2 = r::build_manifest(&expect, &descriptor, &bytes, &sig, [255; 32], &r::rehearsal_rules(), &deny, &store).unwrap();
    assert_eq!(m1, m2);
    // The rehearsal rules are structurally distinct from any other rule set.
    let production_like = mutiny_consensus_v8::protocol_manifest::RuleManifest { commitments: vec![(b"rule-a".to_vec(), [7; 32])] };
    assert_ne!(r::rehearsal_rules().fingerprint().unwrap(), production_like.fingerprint().unwrap());
}

#[test]
fn denylist_covers_public_fixtures_and_default_rehearsal_labels_and_blocks_production_class() {
    let fixtures: Vec<(&str, String)> = vec![
        ("abandon-art", "abandon ".repeat(23) + "art"),
        ("zoo-vote", "zoo ".repeat(23) + "vote"),
        ("legal-winner", "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title".to_string()),
        ("rehearsal-k1", keys::label_phrase("d2-rehearsal-k1").unwrap().to_string()),
        ("rehearsal-k2", keys::label_phrase("d2-rehearsal-k2").unwrap().to_string()),
    ];
    let deny = Denylist::default();
    for (name, phrase) in &fixtures {
        let key = HybridKey::wallet_restore(phrase, Role::WalletOwner).unwrap();
        assert!(deny.contains(key.public()), "{name} must be on the built-in denylist");
    }
    assert_eq!(r::KNOWN_PUBLIC_KEY_SHA256_HEX.len(), fixtures.len());
    // An unknown key is not on the list until an operator adds its public hash (OS-entropy runs).
    let fresh = keys::Credential::from_label("d2-not-listed", 1).unwrap();
    assert!(!deny.contains(fresh.key().public()));
    let extra = Denylist::default().with_hex_lines(&format!("# rehearsal keys\n{}\n", hex::encode(r::key_sha256(fresh.key().public())))).unwrap();
    assert!(extra.contains(fresh.key().public()));
    assert!(Denylist::default().with_hex_lines("zz").is_err());
    // The public tool takes no denylist input (it only matters for a production class, which the tool
    // refuses): the former `--denylist-file` flag is gone and is refused as unknown.
    let (code, _, err) = pub_tool(&["verify", "--denylist-file", "x"]);
    assert_eq!(code, 2);
    assert!(err.contains("unknown argument --denylist-file"), "{err}");
}

#[test]
fn tool_retries_are_idempotent_and_never_overwrite() {
    let run = Run::new("retry");
    let g1 = run.g1();
    // The challenge needs the explicit trusted Treasury configuration.
    let (code, _, err) = pub_tool(&["challenge", "--descriptor-file", &run.f("key-g1.descriptor.hex"), "--context-label", CONTEXT, "--nonce-label", "n1", "--out", &run.f("c-x.hex")]);
    assert_eq!(code, 2);
    assert!(err.contains("--treasury-descriptor-file"), "{err}");
    assert!(!run.dir.join("c-x.hex").exists());
    // Same challenge inputs again: identical bytes accepted; a different nonce to the same path refused.
    let (code, _, _) = tool("challenge", &run.trusted(), &["--descriptor-file", &run.f("key-g1.descriptor.hex"), "--nonce-label", "n1", "--out", &run.f("challenge-g1.hex")]);
    assert_eq!(code, 0);
    let before = file(&run.f("challenge-g1.hex"));
    let (code, _, err) = tool("challenge", &run.trusted(), &["--descriptor-file", &run.f("key-g1.descriptor.hex"), "--nonce-label", "n-other", "--out", &run.f("challenge-g1.hex")]);
    assert_eq!(code, 2, "{err}");
    assert_eq!(before, file(&run.f("challenge-g1.hex")));
    // Signature output is never replaced.
    let sig_before = file(&run.f("proof-g1.sig.hex"));
    let (code, _, _) = key_tool(&["sign", "--generation", "1", "--label", "d2-int-k1", "--challenge-file", &run.f("challenge-g1.hex"), "--out", &run.f("proof-g1.sig.hex")]);
    assert_eq!(code, 2);
    assert_eq!(sig_before, file(&run.f("proof-g1.sig.hex")));
    // A one-component signature file is refused at the input stage (the signature serialization,
    // section 7.0) before any verification: a proof refusal, Malformed.
    let half = run.dir.join("half.sig.hex");
    std::fs::write(&half, &sig_before.trim()[..228]).unwrap();
    let (code, _, err) = tool("verify", &with(&g1, "--signature-file", half.to_str().unwrap()), &["--generation", "1"]);
    assert_eq!(code, 1);
    assert!(err.contains("Proof(Malformed)"), "{err}");
    // Signing with the wrong key or wrong generation is refused and writes nothing.
    let (code, _, _) = key_tool(&["sign", "--generation", "1", "--label", "d2-int-k2", "--challenge-file", &run.f("challenge-g1.hex"), "--out", &run.f("wrong.sig.hex")]);
    assert_eq!(code, 2);
    assert!(!run.dir.join("wrong.sig.hex").exists());
    let (code, _, _) = key_tool(&["sign", "--generation", "2", "--label", "d2-int-k1", "--challenge-file", &run.f("challenge-g1.hex"), "--out", &run.f("wrong2.sig.hex")]);
    assert_eq!(code, 2);
    // A challenge file that is not a challenge is refused.
    std::fs::write(run.dir.join("junk.hex"), "00ff").unwrap();
    assert_eq!(key_tool(&["sign", "--generation", "1", "--label", "d2-int-k1", "--challenge-file", &run.f("junk.hex"), "--out", &run.f("junk.sig")]).0, 2);
    // A failed admission attempt (tampered payload) leaves the store byte-identical, and the
    // untampered proof is then admitted exactly once.
    let mut unaltered = file(&run.f("challenge-g1.hex")).trim().to_string();
    let original = unaltered.clone();
    unaltered.replace_range(unaltered.len() - 2.., if original.ends_with("00") { "01" } else { "00" });
    let tampered = run.dir.join("tampered.hex");
    std::fs::write(&tampered, unaltered).unwrap();
    let store = run.f("ledger.sqlite");
    assert_eq!(tool("create-store", &run.trusted(), &["--store", &store]).0, 0);
    let empty = support::file_sha256(std::path::Path::new(&store));
    let (code, _, _) = tool("admit", &with(&g1, "--challenge-file", tampered.to_str().unwrap()), &["--generation", "1", "--store", &store]);
    assert_eq!(code, 1);
    assert_eq!(support::file_sha256(std::path::Path::new(&store)), empty);
    assert_eq!(tool("admit", &g1, &["--generation", "1", "--store", &store]).0, 0);
    assert_eq!(tool("admit", &g1, &["--generation", "1", "--store", &store]).0, 1);
}

// Historical V1/V2 software model only. Superseded unrestricted admission is
// compiled in this test crate, never exported by the shipping library graph.
// Only paths required by the isolated frozen model are supplied here.
pub use mutiny_consensus_v8::{domain_hash, blocks, execution, genesis_inputs, protocol_manifest, treasury_v1, wallet_rotation_v1, dividend_state_v1, NETWORK_ID};
pub use mutiny_consensus_v8::Hash;
#[path = "../src/treasury_rehearsal_v1.rs"]
mod treasury_rehearsal_v1;
#[path = "../src/treasury_admission_v1.rs"]
mod treasury_admission_v1;
