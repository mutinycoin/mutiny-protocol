//! D2 Treasury ceremony REHEARSAL public tool (SIMULATED / TEST-VALUE; public data only).
//!
//! Builds the proof-of-control challenge, creates the durable admission store (with a random store
//! id), verifies a proof against TRUSTED expectations (read-only), ADMITS it (the first admission
//! consumes its nonce durably and atomically in that store), builds the rehearsal Genesis manifest from
//! an admitted proof, re-verifies the recorded proof after the freeze against an independently approved
//! manifest pinned by its SHA-256 (read-only, repeatable) and inspects any Genesis Parameters. It reads
//! and writes PUBLIC files only and never touches a secret. It has no production mode: any production
//! request is refused by name.
//!
//! Trusted inputs (from the approved ceremony configuration, never from the proof or the plan file):
//! the Treasury generation-one descriptor with its pinned record SHA-256, the ceremony context label,
//! and for generation 2 the pinned rotation-plan identity, the trusted chain identity and the trusted
//! height. See docs/TREASURY-REHEARSAL-TOOLING-V1.md.
use crate::{
    Hash,
    treasury_admission_v1::AdmissionStore,
    treasury_rehearsal_v1::{self as r, ApprovedManifest, CeremonyConfig, Denylist, Expect, Refusal, TrustedChain},
    treasury_v1::{Class, Treasury},
    wallet_rotation_v1::Rotation,
};
use mutiny_crypto_v2::{HybridSignature, NETWORK, treasury_proof_v1 as proof};
use std::io::Write;
use std::path::Path;

const USAGE: &str = "TEST-VALUE Treasury rehearsal public tool (SIMULATED, not production)\n\
  challenge TRUSTED --descriptor-file F (--nonce-label N | --os-nonce) --out F\n\
  create-store TRUSTED --store F\n\
  verify TRUSTED PROOF --generation <1|2> [ROTATION-PLAN] [--negative-controls]\n\
  admit TRUSTED PROOF --generation <1|2> [ROTATION-PLAN] --store F\n\
  manifest TRUSTED PROOF --store F --out-dir D\n\
  verify-frozen TRUSTED (--parameters-file F | --genesis-descriptor-file F --approved-genesis-id H) --challenge-file F --signature-file F --store F --approved-manifest F --approved-manifest-sha256 H\n\
  inspect --parameters-file F\n\
  TRUSTED = --treasury-descriptor-file F --expected-record-sha256 H --context-label L\n\
  PROOF = --descriptor-file F --challenge-file F --signature-file F\n\
  ROTATION-PLAN (generation 2 only, required) = --rotation-plan-file F --plan-identity H --chain-genesis H --chain-fingerprint H --trusted-height N\n";

const TRUSTED: [&str; 3] = ["--treasury-descriptor-file", "--expected-record-sha256", "--context-label"];
const PROOF: [&str; 3] = ["--descriptor-file", "--challenge-file", "--signature-file"];
const PLAN: [&str; 5] = ["--rotation-plan-file", "--plan-identity", "--chain-genesis", "--chain-fingerprint", "--trusted-height"];

/// (flag-value pairs, boolean flags).
type Parsed = (Vec<(String, String)>, Vec<String>);
fn parse(raw: &[String], valued: &[&str], boolean: &[&str]) -> Result<Parsed, String> {
    let (mut values, mut flags) = (Vec::new(), Vec::new());
    let mut i = 0;
    while i < raw.len() {
        let a = raw[i].as_str();
        if boolean.contains(&a) {
            flags.push(a.to_string());
            i += 1;
        } else if valued.contains(&a) {
            let v = raw.get(i + 1).ok_or_else(|| format!("{a} needs a value"))?;
            if values.iter().any(|(k, _): &(String, String)| k == a) {
                return Err(format!("{a} given twice"));
            }
            values.push((a.to_string(), v.clone()));
            i += 2;
        } else {
            return Err(format!("unknown argument {a}"));
        }
    }
    Ok((values, flags))
}
fn get<'a>(v: &'a [(String, String)], k: &str) -> Option<&'a str> {
    v.iter().find(|(n, _)| n == k).map(|(_, x)| x.as_str())
}
fn read_hex(path: &str) -> Option<Vec<u8>> {
    hex::decode(std::fs::read_to_string(path).ok()?.trim()).ok()
}
fn read_bytes(path: &str) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}
fn hex32(text: &str) -> Option<Hash> {
    hex::decode(text.trim()).ok()?.try_into().ok()
}
/// Create the file, or accept an identical existing one (safe retry). Never overwrites.
fn create_or_identical(path: &str, bytes: &[u8]) -> Result<(), &'static str> {
    match std::fs::read(path) {
        Ok(existing) if existing == bytes => Ok(()),
        Ok(_) => Err("existing file differs; refusing to overwrite"),
        Err(_) => {
            let mut f = std::fs::OpenOptions::new().write(true).create_new(true).open(path).map_err(|_| "cannot create file")?;
            f.write_all(bytes).map_err(|_| "write failed")?;
            f.sync_all().map_err(|_| "sync failed")
        }
    }
}
/// The TRUSTED ceremony configuration: the Treasury generation-one descriptor, which must hash to the
/// pinned record SHA-256, and the context label. Never taken from the proof.
fn config(v: &[(String, String)]) -> Result<CeremonyConfig, String> {
    let file = get(v, "--treasury-descriptor-file").ok_or("needs --treasury-descriptor-file (the trusted Treasury generation-one descriptor; it is never taken from the proof)")?;
    let pinned = get(v, "--expected-record-sha256").ok_or("needs --expected-record-sha256 (the Treasury record hash of the approved ceremony configuration)")?;
    let label = get(v, "--context-label").ok_or("needs --context-label")?;
    let pinned = hex32(pinned).ok_or("--expected-record-sha256 must be 32-byte hex")?;
    let descriptor = read_hex(file).ok_or("treasury descriptor file unreadable")?;
    let treasury = Treasury::new(Class::TestValue, descriptor).map_err(|_| "treasury descriptor must be a generation-1 TEST-VALUE wallet-owner descriptor")?;
    if r::record_sha256(&treasury).map_err(|e| format!("{e:?}"))? != pinned {
        return Err("the treasury descriptor does not produce the pinned record SHA-256 (--expected-record-sha256)".into());
    }
    CeremonyConfig::rehearsal(NETWORK, treasury, label).map_err(|e| format!("invalid ceremony configuration ({e:?})"))
}
/// The expectation for the proven generation: the record's own key (1), or the proposed key of the
/// exact rotation plan that the trusted configuration pins (2), evaluated on the trusted chain at the
/// trusted height. A generation-2 descriptor alone proves no succession.
fn expectation(v: &[(String, String)], config: &CeremonyConfig) -> Result<Expect, String> {
    let generation = get(v, "--generation").and_then(|g| g.parse::<u64>().ok()).filter(|g| (1..=2).contains(g)).ok_or("needs --generation 1 or 2")?;
    let any_plan = PLAN.iter().any(|k| get(v, k).is_some());
    match generation {
        1 if any_plan => Err("a rotation plan applies to generation 2 only".into()),
        1 => Ok(Expect::genesis_key(config)),
        _ => {
            let (Some(file), Some(identity), Some(genesis), Some(fingerprint), Some(height)) =
                (get(v, PLAN[0]), get(v, PLAN[1]), get(v, PLAN[2]), get(v, PLAN[3]), get(v, PLAN[4]))
            else {
                return Err("generation 2 needs --rotation-plan-file, --plan-identity, --chain-genesis, --chain-fingerprint and --trusted-height (from the approved configuration)".into());
            };
            let (Some(identity), Some(genesis), Some(fingerprint), Some(height)) = (hex32(identity), hex32(genesis), hex32(fingerprint), height.parse::<u64>().ok()) else {
                return Err("--plan-identity, --chain-genesis and --chain-fingerprint must be 32-byte hex; --trusted-height a number".into());
            };
            let plan = read_hex(file).and_then(|raw| Rotation::decode(&raw).ok()).ok_or("rotation plan file is not a canonical rotation")?;
            let trusted = config
                .clone()
                .with_trusted_chain(TrustedChain { network: config.network(), genesis, fingerprint, height })
                .and_then(|c| c.with_authorized_plan(identity))
                .map_err(|e| format!("invalid trusted succession inputs ({e:?})"))?;
            Expect::authorized_rotation(&trusted, &plan).map_err(|e| format!("rotation plan does not establish the successor ({e:?})"))
        }
    }
}
/// The proof files in the normative order (section 7.0): unreadable files are a usage error; then the
/// challenge decodes strictly and the signature serialization has both components (a proof refusal).
enum Inputs {
    Unreadable(&'static str),
    Refused(Refusal),
    Ok(Box<(Vec<u8>, Vec<u8>, HybridSignature)>),
}
fn proof_inputs(descriptor_file: &str, challenge_file: &str, signature_file: &str) -> Inputs {
    let (Some(descriptor), Some(challenge), Some(signature)) = (read_hex(descriptor_file), read_hex(challenge_file), read_hex(signature_file)) else {
        return Inputs::Unreadable("an input file is unreadable or not hex");
    };
    match r::decode_proof(&challenge, &signature) {
        Ok((_, sig)) => Inputs::Ok(Box::new((descriptor, challenge, sig))),
        Err(e) => Inputs::Refused(e),
    }
}
/// The independently approved final manifest: the JSON file the approver reviewed, pinned by the
/// SHA-256 supplied separately (a procedural control: the pin says which file was approved).
fn approved_manifest(path: &str, pinned_sha256: &str, approved_genesis_id: Option<&str>, genesis_input: bool) -> Result<ApprovedManifest, &'static str> {
    let raw = std::fs::read(path).map_err(|_| "approved manifest unreadable")?;
    let pinned = hex32(pinned_sha256).ok_or("--approved-manifest-sha256 must be 32-byte hex")?;
    if proof::sha256(&raw) != pinned {
        return Err("the approved manifest does not match the pinned SHA-256 (--approved-manifest-sha256)");
    }
    let v: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| "approved manifest is not JSON")?;
    let h = |x: &serde_json::Value| x.as_str().and_then(hex32);
    let class = match v["class_byte"].as_u64() {
        Some(1) => Class::Production,
        Some(2) => Class::TestValue,
        _ => return Err("approved manifest lacks class_byte"),
    };
    let named = match &v["genesis_id"] {
        serde_json::Value::Null => None,
        x => Some(h(x).ok_or("approved manifest genesis_id must be 32-byte hex")?),
    };
    if genesis_input {
        let flag = hex32(approved_genesis_id.ok_or("--genesis-descriptor-file needs --approved-genesis-id")?).ok_or("--approved-genesis-id must be 32-byte hex")?;
        if named != Some(flag) {
            return Err("the approved manifest must name the GenesisID given by --approved-genesis-id");
        }
    } else if approved_genesis_id.is_some() {
        return Err("--approved-genesis-id applies to --genesis-descriptor-file only");
    }
    Ok(ApprovedManifest {
        class,
        descriptor_sha256: h(&v["treasury"]["descriptor_sha256"]).ok_or("approved manifest lacks treasury.descriptor_sha256")?,
        record_sha256: h(&v["treasury"]["record_sha256"]).ok_or("approved manifest lacks treasury.record_sha256")?,
        parameters_sha256: h(&v["genesis_parameters"]["parameters_sha256"]).ok_or("approved manifest lacks genesis_parameters.parameters_sha256")?,
        genesis_id: named,
        admission_store_id: h(&v["admission_store_id"]).ok_or("approved manifest lacks admission_store_id")?,
    })
}

pub fn run(raw: &[String], out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let refuse = |err: &mut dyn Write, msg: &str| -> i32 {
        let _ = writeln!(err, "REFUSED: {msg}");
        2
    };
    let fail = |err: &mut dyn Write, e: Refusal| -> i32 {
        let _ = writeln!(err, "FAIL: proof rejected ({e:?})");
        1
    };
    if raw.iter().any(|a| {
        let l = a.to_ascii_lowercase();
        l == "--production" || l == "production" || l == "--class"
    }) {
        return refuse(err, "this tool is TEST-VALUE rehearsal only; there is no production mode and no production-class manifest");
    }
    let Some((cmd, rest)) = raw.split_first() else {
        let _ = write!(err, "{USAGE}");
        return 2;
    };
    match cmd.as_str() {
        "challenge" => {
            let mut valued = TRUSTED.to_vec();
            valued.extend(["--descriptor-file", "--nonce-label", "--out"]);
            let (v, flags) = match parse(rest, &valued, &["--os-nonce"]) {
                Ok(x) => x,
                Err(e) => return refuse(err, &e),
            };
            let config = match config(&v) {
                Ok(c) => c,
                Err(e) => return refuse(err, &e),
            };
            let (Some(df), Some(outf)) = (get(&v, "--descriptor-file"), get(&v, "--out")) else {
                return refuse(err, "challenge needs --descriptor-file and --out");
            };
            let Some(descriptor) = read_hex(df) else { return refuse(err, "descriptor file unreadable") };
            let nonce: Hash = match (get(&v, "--nonce-label"), flags.iter().any(|f| f == "--os-nonce")) {
                (Some(n), false) => proof::sha256(format!("D2-REHEARSAL-NONCE\0{n}").as_bytes()),
                (None, true) => {
                    let mut n = [0u8; 32];
                    if mutiny_crypto_v2::fill_os_random(&mut n).is_err() {
                        return refuse(err, "entropy unavailable");
                    }
                    n
                }
                _ => return refuse(err, "use exactly one of --nonce-label or --os-nonce"),
            };
            let challenge = match r::build_challenge(&config, &descriptor, nonce).and_then(|c| c.encode().map_err(Refusal::from)) {
                Ok(c) => c,
                Err(e) => return refuse(err, &format!("cannot build challenge ({e:?})")),
            };
            if let Err(e) = create_or_identical(outf, (hex::encode(&challenge) + "\n").as_bytes()) {
                return refuse(err, e);
            }
            let _ = writeln!(out, "{} challenge written ({} bytes) - {}", r::CLASS_NAME, challenge.len(), r::EVIDENCE_LABEL);
            0
        }
        "create-store" => {
            let mut valued = TRUSTED.to_vec();
            valued.push("--store");
            let (v, _) = match parse(rest, &valued, &[]) {
                Ok(x) => x,
                Err(e) => return refuse(err, &e),
            };
            let config = match config(&v) {
                Ok(c) => c,
                Err(e) => return refuse(err, &e),
            };
            let Some(path) = get(&v, "--store") else { return refuse(err, "create-store needs --store") };
            match AdmissionStore::create(Path::new(path), &config) {
                Ok(store) => {
                    let _ = writeln!(
                        out,
                        "{} admission store created - {}\nstore_id {}\nceremony_context {}\nrecord_sha256 {}",
                        r::CLASS_NAME,
                        r::EVIDENCE_LABEL,
                        hex::encode(store.store_id()),
                        hex::encode(config.context().value()),
                        hex::encode(r::record_sha256(config.treasury()).unwrap_or([0; 32]))
                    );
                    0
                }
                Err(e) => refuse(err, &format!("cannot create the admission store (an existing file is never reused) ({e:?})")),
            }
        }
        "verify" | "admit" => {
            let admit = cmd == "admit";
            let mut valued: Vec<&str> = TRUSTED.iter().chain(PROOF.iter()).chain(PLAN.iter()).copied().collect();
            valued.push("--generation");
            if admit {
                valued.push("--store");
            }
            let boolean: &[&str] = if admit { &[] } else { &["--negative-controls"] };
            let (v, flags) = match parse(rest, &valued, boolean) {
                Ok(x) => x,
                Err(e) => return refuse(err, &e),
            };
            let (Some(df), Some(cf), Some(sf)) = (get(&v, PROOF[0]), get(&v, PROOF[1]), get(&v, PROOF[2])) else {
                return refuse(err, "needs --descriptor-file --challenge-file --signature-file");
            };
            let config = match config(&v) {
                Ok(c) => c,
                Err(e) => return refuse(err, &e),
            };
            let expect = match expectation(&v, &config) {
                Ok(e) => e,
                Err(e) => return refuse(err, &e),
            };
            let (descriptor, challenge, sig) = match proof_inputs(df, cf, sf) {
                Inputs::Ok(p) => *p,
                Inputs::Unreadable(e) => return refuse(err, e),
                Inputs::Refused(e) => return fail(err, e),
            };
            let deny = Denylist::default();
            let result = if admit {
                let Some(path) = get(&v, "--store") else { return refuse(err, "admit needs --store (create it first with create-store)") };
                match AdmissionStore::open(Path::new(path), &config) {
                    Ok(mut store) => store.admit(&expect, &descriptor, &challenge, &sig, &deny).map(|p| (p, Some(store.store_id()))),
                    Err(e) => return refuse(err, &format!("admission store unavailable; nothing admitted ({e:?})")),
                }
            } else {
                r::verify_proof(&expect, &descriptor, &challenge, &sig, &deny).map(|p| (p, None))
            };
            match result {
                Ok((p, store_id)) => {
                    let _ = writeln!(
                        out,
                        "{} proof of control {} (both components) - {}\n{}\nkey_generation {}\ndescriptor_sha256 {}\nrecord_sha256 {}\naddress_id {}\ntreasury_authority {}\nceremony_context {}\nnonce {}",
                        r::CLASS_NAME,
                        if admit { "ADMITTED (nonce consumed durably in this store)" } else { "VERIFIED (read-only; no nonce consumed)" },
                        r::EVIDENCE_LABEL,
                        r::class_display(p.class),
                        p.generation,
                        hex::encode(p.descriptor_sha256),
                        hex::encode(p.record_sha256),
                        hex::encode(p.address_id),
                        hex::encode(p.treasury_authority),
                        hex::encode(p.context),
                        hex::encode(p.nonce)
                    );
                    if let Some(id) = store_id {
                        let _ = writeln!(out, "store_id {}", hex::encode(id));
                    }
                    if flags.iter().any(|f| f == "--negative-controls") {
                        let results = r::negative_controls(&expect, &descriptor, &challenge, &sig);
                        let mut all = true;
                        for (name, ok) in &results {
                            all &= ok;
                            let _ = writeln!(out, "negative control [{}] {name}", if *ok { "PASS" } else { "FAIL" });
                        }
                        if !all {
                            let _ = writeln!(err, "FAIL: a negative control did not behave as required");
                            return 1;
                        }
                    }
                    0
                }
                Err(e) => fail(err, e),
            }
        }
        "manifest" => {
            let mut valued: Vec<&str> = TRUSTED.iter().chain(PROOF.iter()).copied().collect();
            valued.extend(["--store", "--out-dir"]);
            let (v, _) = match parse(rest, &valued, &[]) {
                Ok(x) => x,
                Err(e) => return refuse(err, &e),
            };
            let (Some(df), Some(cf), Some(sf), Some(dir), Some(path)) = (get(&v, PROOF[0]), get(&v, PROOF[1]), get(&v, PROOF[2]), get(&v, "--out-dir"), get(&v, "--store")) else {
                return refuse(err, "manifest needs --descriptor-file --challenge-file --signature-file --store --out-dir");
            };
            if !Path::new(dir).is_dir() {
                return refuse(err, "--out-dir must be an existing directory");
            }
            let config = match config(&v) {
                Ok(c) => c,
                Err(e) => return refuse(err, &e),
            };
            let (descriptor, challenge, sig) = match proof_inputs(df, cf, sf) {
                Inputs::Ok(p) => *p,
                Inputs::Unreadable(e) => return refuse(err, e),
                Inputs::Refused(e) => return fail(err, e),
            };
            // Read-only: the proof must have been ADMITTED; building the manifest consumes nothing.
            let store = match AdmissionStore::open_read_only(Path::new(path), &config) {
                Ok(s) => s,
                Err(e) => return refuse(err, &format!("admission store unavailable ({e:?})")),
            };
            let built = r::build_manifest(&Expect::genesis_key(&config), &descriptor, &challenge, &sig, [255; 32], &r::rehearsal_rules(), &Denylist::default(), &store);
            let manifest = match built {
                Ok(m) => m,
                Err(e) => {
                    let _ = writeln!(err, "FAIL: manifest not built ({e:?})");
                    return 1;
                }
            };
            for (name, bytes) in [("genesis-manifest.json", manifest.text.clone().into_bytes()), ("genesis-parameters.hex", (hex::encode(&manifest.parameters) + "\n").into_bytes())] {
                if let Err(e) = create_or_identical(&format!("{dir}/{name}"), &bytes) {
                    return refuse(err, e);
                }
            }
            let _ = writeln!(
                out,
                "{} rehearsal Genesis manifest written - {}\n{}\nadmission_store_id {}",
                r::CLASS_NAME,
                r::EVIDENCE_LABEL,
                r::class_display(Class::TestValue),
                hex::encode(store.store_id())
            );
            0
        }
        "verify-frozen" => {
            let mut valued = TRUSTED.to_vec();
            valued.extend([
                "--parameters-file",
                "--genesis-descriptor-file",
                "--approved-genesis-id",
                "--challenge-file",
                "--signature-file",
                "--store",
                "--approved-manifest",
                "--approved-manifest-sha256",
            ]);
            let (v, _) = match parse(rest, &valued, &[]) {
                Ok(x) => x,
                Err(e) => return refuse(err, &e),
            };
            let (Some(cf), Some(sf), Some(path), Some(approved), Some(pin)) =
                (get(&v, "--challenge-file"), get(&v, "--signature-file"), get(&v, "--store"), get(&v, "--approved-manifest"), get(&v, "--approved-manifest-sha256"))
            else {
                return refuse(err, "verify-frozen needs --challenge-file --signature-file --store --approved-manifest --approved-manifest-sha256");
            };
            let (frozen, is_descriptor) = match (get(&v, "--parameters-file"), get(&v, "--genesis-descriptor-file")) {
                (Some(p), None) => (read_hex(p).or_else(|| read_bytes(p)), false),
                (None, Some(g)) => (read_bytes(g), true),
                _ => return refuse(err, "give exactly one of --parameters-file or --genesis-descriptor-file"),
            };
            let Some(frozen) = frozen else { return refuse(err, "frozen input unreadable") };
            let config = match config(&v) {
                Ok(c) => c,
                Err(e) => return refuse(err, &e),
            };
            let approved = match approved_manifest(approved, pin, get(&v, "--approved-genesis-id"), is_descriptor) {
                Ok(a) => a,
                Err(e) => return refuse(err, e),
            };
            let (Some(challenge), Some(signature)) = (read_hex(cf), read_hex(sf)) else {
                return refuse(err, "an input file is unreadable or not hex");
            };
            let sig = match r::decode_proof(&challenge, &signature) {
                Ok((_, s)) => s,
                Err(e) => return fail(err, e),
            };
            // Read-only audit of the RECORDED proof: nothing is consumed, so it is repeatable.
            let store = match AdmissionStore::open_read_only(Path::new(path), &config) {
                Ok(s) => s,
                Err(e) => return refuse(err, &format!("admission store unavailable ({e:?})")),
            };
            match r::verify_frozen(&frozen, is_descriptor, &Expect::genesis_key(&config), &approved, &store, &challenge, &sig) {
                Ok(rep) => {
                    let scope = match rep.genesis_id {
                        Some(_) => "PASS: the recomputed GenesisID equals the approved GenesisID (every Genesis field is covered)",
                        None => "PASS FOR THE PARAMETERS BYTES ONLY: no Genesis descriptor was supplied, so Genesis fields outside the Parameters are NOT compared",
                    };
                    let _ = writeln!(
                        out,
                        "{} frozen-bytes verification {scope}; Treasury, Parameters and store equal the approved manifest; recorded proof re-validated read-only - {}\n{}\ndescriptor_sha256 {}\nrecord_sha256 {}\ntreasury_authority {}\nparameters_sha256 {}\nstore_id {}",
                        r::CLASS_NAME,
                        r::EVIDENCE_LABEL,
                        r::class_display(rep.class),
                        hex::encode(rep.descriptor_sha256),
                        hex::encode(rep.record_sha256),
                        hex::encode(rep.treasury_authority),
                        hex::encode(rep.parameters_sha256),
                        hex::encode(store.store_id())
                    );
                    if let Some(id) = rep.genesis_id {
                        let _ = writeln!(out, "genesis_id_recomputed {}", hex::encode(id));
                    }
                    0
                }
                Err(e) => {
                    let _ = writeln!(err, "FAIL: frozen bytes do not match ({e:?})");
                    1
                }
            }
        }
        "inspect" => {
            let (v, _) = match parse(rest, &["--parameters-file"], &[]) {
                Ok(x) => x,
                Err(e) => return refuse(err, &e),
            };
            let Some(bytes) = get(&v, "--parameters-file").and_then(|p| read_hex(p).or_else(|| read_bytes(p))) else {
                return refuse(err, "inspect needs --parameters-file");
            };
            match r::inspect_parameters(&bytes) {
                Ok(text) => {
                    let _ = writeln!(out, "{text}");
                    0
                }
                Err(_) => {
                    let _ = writeln!(err, "FAIL: not canonical Genesis parameters");
                    1
                }
            }
        }
        _ => {
            let _ = write!(err, "{USAGE}");
            2
        }
    }
}

#[allow(dead_code)]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = run(&args, &mut std::io::stdout(), &mut std::io::stderr());
    std::process::exit(code);
}
