//! Drift guard and self-tests for the three TEST-VALUE admission fixtures (JOIN, RECOVERY
//! MATERIAL, ROTATION) that replaced the formerly tracked host-derived fixtures, plus the
//! tracked-profile guard (analysis T15). SIMULATED != PHYSICAL: nothing here is TPM evidence.
#[path = "support/software_tpm.rs"]
mod software_tpm;
#[path = "support/ignore_rules.rs"]
mod ignore_rules;
use mutiny_consensus_v8::{
    admission::ApprovedProfile,
    anchors::FinalizedAnchor,
    join::ContinuityJoin,
    recovery::Certificate,
    recovery_material::RecoveryMaterial,
    rotation::HardwareRotate,
    tpm::TpmProfile,
};
use std::path::{Path, PathBuf};

fn normalized(s: &str) -> String {
    s.replace("\r\n", "\n")
}
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}
fn committed(name: &str) -> String {
    // Runtime read (not include_str!): the consumer unit tests include the files themselves.
    let path = root().join("qualification").join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}
fn hex_field(v: &serde_json::Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap_or_else(|| panic!("{k} missing"))).unwrap()
}

/// The committed files equal the generator output (line-ending tolerant), ALWAYS. With
/// BUILD8_EXPORT_TEST_VALUE_ADMISSION_FIXTURES=<new directory> the generator also writes the three
/// files into that NEW directory (the directory must not exist; files are created with create_new;
/// the committed copies are never touched), and the freshly written files are read back and compared
/// with the generator output and with the committed files: an export never skips the comparison.
#[test]
fn committed_test_value_admission_fixtures_match_generator() {
    let generated = software_tpm::admission_fixture_texts();
    if let Ok(dir) = std::env::var("BUILD8_EXPORT_TEST_VALUE_ADMISSION_FIXTURES") {
        use std::io::Write;
        let dir = PathBuf::from(dir);
        std::fs::create_dir(&dir).expect("export directory must be new");
        for (name, text) in &generated {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(dir.join(name))
                .unwrap()
                .write_all(text.as_bytes())
                .unwrap();
        }
        for (name, text) in &generated {
            let written = std::fs::read_to_string(dir.join(name)).unwrap();
            assert_eq!(&written, text, "{name}: the exported file differs from the generator output");
            assert_eq!(normalized(&committed(name)), written, "{name}: the committed file differs from the fresh export");
        }
    }
    for (name, text) in &generated {
        assert_eq!(&normalized(&committed(name)), text, "{name} drifted from the generator");
    }
}

#[test]
fn generator_is_deterministic() {
    assert_eq!(
        software_tpm::admission_fixture_texts(),
        software_tpm::admission_fixture_texts()
    );
}

/// Every regenerated profile carries the TEST-VALUE marker and every fixture is labelled
/// simulated; possession signatures are low-S (the verifiers reject high-S).
#[test]
fn fixtures_are_labelled_simulated_marked_and_low_s() {
    let low_s = |raw: &[u8; 64]| {
        let s = p256::ecdsa::Signature::from_slice(raw).unwrap();
        assert!(s.normalize_s().is_none(), "high-S possession signature");
    };
    let profile_of = |approved: &[u8]| {
        let a = ApprovedProfile::decode(approved).unwrap();
        TpmProfile::decode(&a.profile).unwrap()
    };
    for (name, text) in software_tpm::admission_fixture_texts() {
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(v["TEST_VALUE"], true, "{name}");
        for k in ["physical_tpm", "qualifies_hardware", "production_eligible", "bond_eligible", "actual_genesis"] {
            assert_eq!(v[k], false, "{name}: {k}");
        }
        assert_eq!(v["provenance"]["real_host_evidence"], "none", "{name}");
        assert!(v["provenance"]["generator"].as_str().unwrap().ends_with("software_tpm.rs"));
        assert!(v.get("counter_before").is_none() && v.get("counter_after").is_none(), "{name}");
        let profile = if name == software_tpm::RECOVERY_FIXTURE_FILE {
            let m = RecoveryMaterial::decode(&hex_field(&v, "material")).unwrap();
            low_s(&m.possession_signature);
            Certificate::decode(&hex_field(&v, "certificate")).unwrap();
            profile_of(&m.approved_profile)
        } else if name == software_tpm::JOIN_FIXTURE_FILE {
            let j = ContinuityJoin::decode(&hex_field(&v, "operation")).unwrap();
            low_s(&j.possession_signature);
            FinalizedAnchor::decode(&hex_field(&v, "parent")).unwrap();
            profile_of(&j.approved_profile)
        } else {
            let r = HardwareRotate::decode(&hex_field(&v, "operation")).unwrap();
            low_s(&r.possession);
            assert_eq!(r.node, software_tpm::ROTATION_NODE);
            profile_of(&r.approved_profile)
        };
        assert!(profile.is_test_value(), "{name}: profile must carry the TEST-VALUE marker");
    }
}

/// T7: relabeling a committed fixture (claiming TEST_VALUE false, production or Bond eligible) is a
/// drift failure, never a different evidence class: the committed bytes must equal the generator.
/// No Rust API reads these labels (`host_independence_guard::no_shipped_code_reads_fixture_evidence_labels`).
#[test]
fn relabeled_fixture_is_a_drift_failure_not_a_different_evidence_class() {
    let mut texts: Vec<(String, String)> = software_tpm::admission_fixture_texts()
        .into_iter()
        .map(|(name, text)| (name.to_string(), text))
        .collect();
    texts.push((
        "TEST-VALUE-SOFTWARE-TPM-FIXTURE-V1.json".into(),
        software_tpm::TestTpm::new().fixture_text(),
    ));
    for (name, generated) in texts {
        let committed_text = normalized(&committed(&name));
        assert_eq!(committed_text, generated, "{name}");
        for (from, to) in [
            ("\"TEST_VALUE\": true", "\"TEST_VALUE\": false"),
            ("\"production_eligible\": false", "\"production_eligible\": true"),
            ("\"bond_eligible\": false", "\"bond_eligible\": true"),
            ("\"physical_tpm\": false", "\"physical_tpm\": true"),
        ] {
            assert!(committed_text.contains(from), "{name}: {from}");
            assert_ne!(committed_text.replace(from, to), generated, "{name}: {from}");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// T15: no tracked JSON embeds a TPM profile that is neither TEST-VALUE marked nor an allow-listed
// synthetic repeated-byte hardware id. The walk never opens private evidence: a JSON file under
// `qualification/` is skipped when ANY component of its path, at any depth and in any
// capitalisation, matches a `qualification/...` pattern of .gitignore (deliberately broader than
// git's own semantics, see `support/ignore_rules.rs`); build/target trees are skipped by name.
// ---------------------------------------------------------------------------------------------
/// Repeated-byte synthetic hardware ids used by public vectors (each `[b; 32]`).
const SYNTHETIC_HARDWARE_BYTES: &[u8] = &[12, 21, 22, 55, 85];

fn json_files(dir: &Path, private: &[String], out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if p.is_dir() {
            if !matches!(name.as_str(), "target" | ".git" | "node_modules" | "crypto-v2-sources") {
                json_files(&p, private, out);
            }
        } else if name.ends_with(".json") {
            let relative = p.strip_prefix(root()).unwrap().to_string_lossy().replace('\\', "/");
            if let Some(q) = relative.to_ascii_lowercase().strip_prefix("qualification/") {
                if ignore_rules::any_component_matches_ignoring_case(private, q) {
                    continue; // possible private evidence: never opened
                }
            }
            out.push(p);
        }
    }
}
fn strings(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::String(s) => out.push(s.clone()),
        serde_json::Value::Array(a) => a.iter().for_each(|x| strings(x, out)),
        serde_json::Value::Object(o) => o.values().for_each(|x| strings(x, out)),
        _ => {}
    }
}
/// Every TPM profile (version 1: CBOR array(10), 1, bytes(32)...; version 2: array(11), 2, ...)
/// embedded anywhere in `bytes`, found by its canonical prefix and decoded strictly.
pub fn embedded_profiles(bytes: &[u8]) -> Vec<TpmProfile> {
    let mut found = Vec::new();
    for prefix in [[0x8a, 0x01, 0x58, 0x20], [0x8b, 0x02, 0x58, 0x20]] {
        let mut at = 0;
        while let Some(off) = bytes[at..].windows(4).position(|w| w == prefix) {
            let start = at + off;
            let mut d = minicbor::Decoder::new(&bytes[start..]);
            if d.skip().is_ok() {
                if let Ok(p) = TpmProfile::decode(&bytes[start..start + d.position()]) {
                    found.push(p);
                }
            }
            at = start + 1;
        }
    }
    found
}
#[test]
fn tracked_json_profiles_are_test_value_or_synthetic() {
    let private = ignore_rules::qualification_patterns(&root());
    assert!(private.len() >= 3);
    let mut files = Vec::new();
    json_files(&root(), &private, &mut files);
    assert!(files.len() > 50, "walk found too few JSON files: {}", files.len());
    let mut profiles_seen = 0;
    for f in files {
        let Ok(text) = std::fs::read_to_string(&f) else { continue };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
        let mut all = Vec::new();
        strings(&v, &mut all);
        for s in all {
            if s.len() < 400 || s.len() % 2 != 0 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
                continue;
            }
            for p in embedded_profiles(&hex::decode(&s).unwrap()) {
                profiles_seen += 1;
                let synthetic = p.hardware.iter().all(|b| *b == p.hardware[0])
                    && SYNTHETIC_HARDWARE_BYTES.contains(&p.hardware[0]);
                assert!(
                    p.is_test_value() || synthetic,
                    "{} embeds a TPM profile that is neither TEST-VALUE marked nor an allow-listed synthetic hardware id",
                    f.display()
                );
            }
        }
    }
    assert!(profiles_seen > 0, "the guard found no embedded profile at all");
}
