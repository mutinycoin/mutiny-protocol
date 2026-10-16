//! LOCAL SYNTHETIC TEST ONLY. Never copy generated JSON or custody envelopes
//! into repository/evidence/public archives. No hardware or production authority.
//! Proposed opt-in module registration is separately reviewed before compilation.
use super::*;
use std::{fs, io::Write, path::Component};
#[cfg(windows)]
use std::path::Prefix;

const SCHEMA: &str = "MUTINY-BUILD8-PUBLIC-A2-NATIVE-LIFECYCLE-V1";
// Public synthetic test value, never a production password or user secret.
const TEST_PASSWORD: &str = "PUBLIC TEST VALUE A2 ONLY";
const MAX_LOCAL_BYTES: usize = 2 * 1024 * 1024;

// Exact public TEST selection only. It never supplies state/root/authority.
#[derive(Clone, Copy, PartialEq, Eq)]
enum FixtureVariant { Default, ForeignGenesis, GenuineTerminalPki }
impl FixtureVariant {
    fn parse(value: Option<&str>) -> Self {
        match value {
            None => Self::Default,
            Some("FOREIGN_GENESIS_V1") => Self::ForeignGenesis,
            Some("GENUINE_TERMINAL_PKI_V1") => Self::GenuineTerminalPki,
            _ => panic!("unknown public synthetic fixture variant"),
        }
    }
    fn labels(self) -> [&'static str; 3] {
        if self == Self::ForeignGenesis {
            ["a2-local-public-foreign-unused-root-A-v1",
             "a2-local-public-foreign-unused-root-B-v1",
             "a2-local-public-foreign-live-root-C-v1"]
        } else {
            ["a2-local-public-unused-root-A", "a2-local-public-unused-root-B",
             "a2-local-public-live-root-C"]
        }
    }
}

fn fixture_material(variant: FixtureVariant,
    unused: &[test_value_x509::X509Pki]) -> (Rig, Option<Vec<u8>>) {
    if variant != FixtureVariant::GenuineTerminalPki {
        return (rig_with_root_set(false, &[0x51],
            test_value_x509::X509Pki::new(variant.labels()[2]), unused), None);
    }
    // Same genuine, already reviewed PKI machinery: every chain certificate and
    // each of four CRLs is used. Off-path entries are actually issued serials.
    let mut pki = genuine_long_path_pki_tests::LongPathPki::new();
    let original_tpm = TestTpm::with_identity("a2-long-path-largest-public-EK");
    let chain = pki.maximize_path(&original_tpm.simulator_ek(), 4096);
    let serial = crate::ek_chain::CertificateSyntax::parse_certificate(
        &crate::x509_syntax::X509Syntax, &chain[0]).unwrap().serial;
    let historical = pki.historical_crls();
    pki.verify(&chain, &historical, test_value_x509::T_REF).unwrap();
    let mut crls = Vec::new();
    for issuer in 0..4 {
        let (raw, population) = pki.maximize_crl(issuer,
            if issuer == 0 { Some(serial.as_slice()) } else { None }, 32768);
        assert!((32700..=32768).contains(&raw.len()));
        assert!(!population.is_empty());
        crls.push(raw);
    }
    let tpm = original_tpm.strip(software_tpm::Strip::ConsistentProvenance(pki.pki.root_hash()));
    let anchor = pki.anchor();
    let r = rig_with_authenticated_material(pki.pki, unused, tpm, chain, historical, anchor);
    let op = operation(&r, Target { class: TargetClass::Ek, scope: TargetScope::Certificate,
        identity: test_value_x509::sha256(&r.chain[0]) }, Evidence::Crl {
        target_certificate: r.chain[0].clone(), signer_chain: r.chain[1..].to_vec(), crls });
    let exact = op.encode().unwrap();
    assert!((151201..=151785).contains(&exact.len()));
    assert!(Operation::decode(&exact).unwrap() == op);
    let before = r.state.records().unwrap();
    let next = transition(&r, &op).unwrap();
    assert!(next.endorsement_revocations_v1.terminal_no_quorum());
    assert_eq!(r.state.records().unwrap(), before);
    assert_eq!(r.state.root().unwrap(), r.root);
    // This output is the pre-withdrawal licensed state. Node must perform real
    // transport/finality; generation never substitutes this transition result.
    (r, Some(exact))
}

#[test]
fn fixture_variant_selection_preserves_default_and_requires_exact_public_names() {
    assert!(FixtureVariant::parse(None) == FixtureVariant::Default);
    assert!(FixtureVariant::parse(Some("FOREIGN_GENESIS_V1")) == FixtureVariant::ForeignGenesis);
    assert!(FixtureVariant::parse(Some("GENUINE_TERMINAL_PKI_V1")) == FixtureVariant::GenuineTerminalPki);
    assert_ne!(FixtureVariant::ForeignGenesis.labels(), FixtureVariant::Default.labels());
    for bad in ["", "DEFAULT", "FOREIGN_GENESIS_V1 ", "foreign_genesis_v1"] {
        assert!(std::panic::catch_unwind(|| FixtureVariant::parse(Some(bad))).is_err());
    }
}

fn local_destination() -> std::path::PathBuf {
    let path = std::path::PathBuf::from(std::env::var_os("BUILD8_A2_LOCAL_SOFTWARE_FIXTURE")
        .expect("mandatory nonsecret protected local fixture path"));
    assert!(path.is_absolute());
    assert!(!path.components().any(|p| matches!(p, Component::ParentDir | Component::CurDir)));
    assert_eq!(path.file_name(), Some(std::ffi::OsStr::new("fixture.json")));
    let directory = path.parent().expect("local fixture directory");
    #[cfg(windows)] {
        let profile = std::path::PathBuf::from(std::env::var_os("USERPROFILE")
            .expect("current-user profile path required"));
        assert!(profile.is_absolute());
        assert!(matches!(path.components().next(), Some(Component::Prefix(p))
            if matches!(p.kind(), Prefix::Disk(b'C') | Prefix::Disk(b'c'))));
        assert_eq!(directory.parent(), Some(profile.as_path()), "new leaf directly under current user's C profile");
    }
    #[cfg(target_os="linux")] {
        let qualification=std::path::Path::new("/var/lib/mutiny/qualification-c3.tX6KzBh4");
        assert_eq!(directory.parent(),Some(qualification),"exact approved Linux qualification root");
        crate::submission_archive_protection::check(qualification,true).unwrap();
        // Existing-only read/validate API: missing root refuses without creation.
    }
    assert!(directory.file_name().and_then(|s|s.to_str()).is_some_and(|s|
        s.starts_with("MutinyBuild8-A2-LocalSynthetic-") && s.len() > "MutinyBuild8-A2-LocalSynthetic-".len()));
    assert!(matches!(fs::symlink_metadata(directory), Err(e) if e.kind() == std::io::ErrorKind::NotFound),
        "create-new fixture leaf only; never alter old ACLs or fixture contents");
    assert!(crate::submission_pool_v1::private_directory(directory).unwrap(),
        "normal API must create a protected current-user/SYSTEM-only leaf under safe ancestors");
    assert!(!crate::submission_pool_v1::private_directory(directory).unwrap());
    path
}

fn sealed_roundtrip(key: &HybridKey, role: Role, context: &[u8]) -> Vec<u8> {
    let encrypted = key.seal_for(TEST_PASSWORD, 1, context).unwrap();
    let (opened, generation) = HybridKey::open_for(role, TEST_PASSWORD, context, &encrypted).unwrap();
    assert_eq!(generation, 1);
    assert_eq!(opened.public().descriptor(1).unwrap(), key.public().descriptor(1).unwrap());
    let mut wrong_context = context.to_vec();
    assert!(!wrong_context.is_empty()); wrong_context[0] ^= 1;
    assert!(HybridKey::open_for(role, TEST_PASSWORD, &wrong_context, &encrypted).is_err());
    let other_role = if role == Role::Transport { Role::Node } else { Role::Transport };
    assert!(HybridKey::open_for(other_role, TEST_PASSWORD, context, &encrypted).is_err());
    // HybridKey retains private seeds in erasing ownership. Nothing private is exported in plaintext.
    drop(opened);
    encrypted
}

#[test]
fn generate_protected_local_synthetic_a2_native_fixture() {
    // Missing input is a failed selected generation, never an absent-input PASS.
    let path = local_destination();
    let directory = path.parent().unwrap();
    let selected = std::env::var("BUILD8_A2_LOCAL_SOFTWARE_VARIANT");
    let variant = match selected {
        Ok(ref public) => FixtureVariant::parse(Some(public)),
        Err(std::env::VarError::NotPresent) => FixtureVariant::parse(None),
        Err(std::env::VarError::NotUnicode(_)) => panic!("public fixture variant must be Unicode"),
    };
    let labels = variant.labels();
    let unused = [test_value_x509::X509Pki::new(labels[0]),
        test_value_x509::X509Pki::new(labels[1])];
    let (r, terminal_operation) = fixture_material(variant, &unused);
    assert_eq!(r.parameters.roots.roots.len(), 3);
    assert_eq!(r.state.continuity.as_ref().unwrap().members.len(), 1);
    assert!(!r.state.endorsement_revocations_v1.terminal_no_quorum());
    for pki in &unused {
        assert!(r.parameters.roots.roots.contains_key(&pki.root_hash()));
        assert_ne!(pki.root_hash(), r.pki.root_hash());
    }
    assert_ne!(unused[0].root_hash(), unused[1].root_hash());
    let records = r.state.records().unwrap();
    assert_eq!(r.state.root().unwrap(), r.root);
    let reconstructed = State::from_records(&records, r.root).unwrap();
    assert_eq!(reconstructed.records().unwrap(), records);
    assert_eq!(reconstructed.root().unwrap(), r.root);
    assert_eq!(r.parent.height, 0);
    assert_eq!(test_value_x509::T_REF, 1_800_000_000);
    assert_eq!(FinalizedAnchor::decode(&r.parent.encode()).unwrap(), r.parent);
    let chain_path = directory.join("generator-roundtrip.sqlite");
    assert!(!chain_path.exists());
    let chain = crate::canonical_store_v2::CanonicalStore::open_trusted_genesis(
        &chain_path, &r.parent, &reconstructed, r.root, test_value_x509::T_REF, [255;32],
    ).unwrap();
    let pins = chain.current_node_authority(&r.parent, r.node).unwrap();
    assert_eq!(pins.descriptor(), r.node_key.public().descriptor(1).unwrap());
    let parent_authority = chain.current_authority(&r.parent).unwrap();
    assert_eq!(parent_authority.voters.len(), 1);
    assert!(!parent_authority.voters[&r.node].weight().unwrap().is_zero());
    assert!(chain.body_capacity(&r.parent).unwrap().allows_a2());
    let continuity_context = crate::domain_hash(
        b"MUTINY-BUILD8-PUBLIC-A2-CONTINUITY-FIXTURE-V1", &r.parent.genesis);
    let transport_context = crate::domain_hash(
        b"MUTINY-BUILD8-PUBLIC-A2-TRANSPORT-FIXTURE-V1", &r.parent.genesis);
    let node_encrypted = sealed_roundtrip(&r.node_key, Role::Node, &pins.context());
    let continuity_encrypted = sealed_roundtrip(&r.continuity, Role::Continuity, &continuity_context);
    let transport_a = HybridKey::generate(Role::Transport).unwrap();
    let transport_b = HybridKey::generate(Role::Transport).unwrap();
    assert_ne!(transport_a.public().descriptor(1).unwrap(), transport_b.public().descriptor(1).unwrap());
    let transport_a_encrypted = sealed_roundtrip(&transport_a, Role::Transport, &transport_context);
    let transport_b_encrypted = sealed_roundtrip(&transport_b, Role::Transport, &transport_context);
    let rows: Vec<_> = records.iter().map(|(key,record)|serde_json::json!({
        "key":hex::encode(key), "record":hex::encode(record),
    })).collect();
    let mut value = serde_json::json!({
        "schema":SCHEMA, "synthetic_only":true, "production_authorized":false,
        "t0":test_value_x509::T_REF, "root":hex::encode(r.root), "records":rows,
        "genesis":hex::encode(r.parent.encode()), "node":hex::encode(r.node),
        "unused_root_certificates":[hex::encode(&unused[0].root),hex::encode(&unused[1].root)],
        "node_encrypted":hex::encode(node_encrypted),
        "continuity_encrypted":hex::encode(continuity_encrypted),
        "transport_a_encrypted":hex::encode(transport_a_encrypted),
        "transport_b_encrypted":hex::encode(transport_b_encrypted),
    });
    match variant {
        FixtureVariant::Default => assert!(terminal_operation.is_none()),
        FixtureVariant::ForeignGenesis => {
            assert!(terminal_operation.is_none());
            value["software_variant"] = serde_json::json!("FOREIGN_GENESIS_V1");
        }
        FixtureVariant::GenuineTerminalPki => {
            value["software_variant"] = serde_json::json!("GENUINE_TERMINAL_PKI_V1");
            value["terminal_operation"] = serde_json::json!(hex::encode(terminal_operation.unwrap()));
        }
    }
    let raw = serde_json::to_vec(&value).unwrap();
    assert!(raw.len() <= MAX_LOCAL_BYTES);
    let decoded: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert!(decoded == value, "local JSON roundtrip mismatch; custody bytes must not enter panic output");
    let decode_hash = |v:&serde_json::Value| -> Hash {
        hex::decode(v.as_str().unwrap()).unwrap().try_into().unwrap()
    };
    let decoded_records:Vec<(Hash,Vec<u8>)> = decoded["records"].as_array().unwrap().iter()
        .map(|row|(decode_hash(&row["key"]),hex::decode(row["record"].as_str().unwrap()).unwrap())).collect();
    assert_eq!(decoded_records, records);
    assert_eq!(State::from_records(&decoded_records,decode_hash(&decoded["root"])).unwrap().records().unwrap(), records);
    assert_eq!(FinalizedAnchor::decode(&hex::decode(decoded["genesis"].as_str().unwrap()).unwrap()).unwrap(), r.parent);
    assert_eq!(decode_hash(&decoded["node"]), r.node);
    for (field,key,role,context) in [
        ("node_encrypted", &r.node_key, Role::Node, pins.context()),
        ("continuity_encrypted", &r.continuity, Role::Continuity, continuity_context),
        ("transport_a_encrypted", &transport_a, Role::Transport, transport_context),
        ("transport_b_encrypted", &transport_b, Role::Transport, transport_context),
    ] {
        let encoded = hex::decode(decoded[field].as_str().unwrap()).unwrap();
        let (opened,generation) = HybridKey::open_for(role,TEST_PASSWORD,&context,&encoded).unwrap();
        assert_eq!(generation,1);
        assert_eq!(opened.public().descriptor(1).unwrap(),key.public().descriptor(1).unwrap());
        drop(opened);
    }
    // Only authenticated encrypted custody + public state reach the local protected file.
    // Account/admin trust applies; this is not a barrier against that account's compromise.
    let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&path).unwrap();
    crate::submission_archive_protection::check(&path, false).unwrap();
    file.write_all(&raw).unwrap(); file.sync_all().unwrap();
    crate::submission_archive_protection::check(&path, false).unwrap();
    assert!(fs::read(&path).unwrap() == raw, "protected local fixture readback mismatch; custody bytes must not enter panic output");
    drop(file); drop(chain);
    assert!(!crate::submission_pool_v1::private_directory(directory).unwrap());
    // Output receipts may report hash/size only. Never print JSON/envelopes or password.
    use sha2::{Digest, Sha256};
    eprintln!("LOCAL SYNTHETIC A2 fixture created; bytes={} sha256={}", raw.len(), hex::encode(Sha256::digest(&raw)));
    // All existing failure/partial files and sidecars remain; no cleanup or overwrite.
}
