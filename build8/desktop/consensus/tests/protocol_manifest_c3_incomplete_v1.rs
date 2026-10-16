//! Independent Rust recomputation of the Python source-only candidate. No roots,
//! physical enrollment, Production artifact or signer is created by these tests.
use mutiny_consensus_v8::protocol_manifest::RuleManifest;
use sha2::{Digest, Sha256};
use std::path::PathBuf;

const REPORT: &str = include_str!(
    "../../qualification/protocol-rule-c3-incomplete-v1-r3/PROTOCOL-FINGERPRINT-CANDIDATE-C3-INCOMPLETE-V1.json"
);
fn document() -> serde_json::Value {
    serde_json::from_str(REPORT).unwrap()
}

#[test]
fn c3_source_candidate_recomputes_artifacts_canonical_manifest_and_fingerprint_independently() {
    let doc = document();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../qualification/protocol-rule-c3-incomplete-v1-r3");
    let mut commitments = Vec::new();
    for (name, entry) in doc["files"].as_object().unwrap() {
        let digest = hex::decode(entry["sha256"].as_str().unwrap()).unwrap();
        let digest: [u8; 32] = digest.try_into().unwrap();
        let snapshot = entry["snapshot"].as_str().unwrap();
        assert_eq!(snapshot, format!("artifacts/{}", hex::encode(digest)));
        let raw = std::fs::read(root.join(snapshot)).unwrap();
        assert_eq!(<[u8; 32]>::from(Sha256::digest(&raw)), digest, "{name}");
        commitments.push((name.as_bytes().to_vec(), digest));
    }
    commitments.sort();
    let independently_rebuilt = RuleManifest { commitments };
    let encoded = independently_rebuilt.encode().unwrap();
    assert_eq!(hex::encode(&encoded), doc["manifest_hex"].as_str().unwrap());
    assert_eq!(RuleManifest::decode(&encoded).unwrap(), independently_rebuilt);
    assert_eq!(hex::encode(independently_rebuilt.fingerprint().unwrap()), doc["fingerprint"].as_str().unwrap());
}

#[test]
fn c3_incomplete_candidate_has_no_authentic_or_legacy_binding_and_cannot_supply_v2_parameters() {
    let doc = document();
    assert_eq!(doc["qualification_status"], "INCOMPLETE");
    for key in ["locked_for_genesis", "genesis_sealed", "production_authorized", "instance_identities_included"] {
        assert_eq!(doc[key], false, "{key}");
    }
    let missing = doc["unresolved_bindings"].as_array().unwrap();
    assert_eq!(missing.len(), 4);
    let raw = hex::decode(doc["manifest_hex"].as_str().unwrap()).unwrap();
    let manifest = RuleManifest::decode(&raw).unwrap();
    let mut names = std::collections::BTreeSet::new();
    for reason in missing {
        let name = reason["name"].as_str().unwrap();
        assert!(names.insert(name));
        assert!(!reason["reason"].as_str().unwrap().is_empty());
        assert!(!manifest.commitments.iter().any(|(n, _)| n == name.as_bytes()));
    }
    assert_eq!(names, std::collections::BTreeSet::from([
        "genesis-class-v2", "endorsement-root-set-v2", "endorsement-identity-classes-v1", "accepted-pcr-profile-set-v1",
    ]));
    assert!(!manifest.commitments.iter().any(|(n, _)| n == b"physical-admission-trust-roots-v1"));
    // Reuse the explicitly public historical TESTVALUE fixture solely to isolate
    // the codec's missing-binding gate. No fake Production root is manufactured.
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/GENESIS-V2-TEST-VALUE-FIXTURE-V1.json"
    )).unwrap();
    assert_eq!(fixture["TEST_VALUE"], true);
    assert_eq!(fixture["production_eligible"], false);
    let mut inputs = mutiny_consensus_v8::genesis_v2::Inputs::decode(
        &hex::decode(fixture["inputs"].as_str().unwrap()).unwrap()
    ).unwrap();
    inputs.parameters.rules = manifest;
    assert_eq!(inputs.encode(), Err(mutiny_consensus_v8::genesis_v2::GenesisV2Error::ManifestEntryMissing));
    assert_eq!(
        mutiny_consensus_v8::admission_evidence_v1::require_qualified_physical_evidence(
            mutiny_consensus_v8::genesis_v2::GenesisClass::Production
        ),
        Err(mutiny_consensus_v8::admission_evidence_v1::EvidenceFailure::PhysicalQualificationUnestablished)
    );
}

#[test]
fn retained_v9_history_has_its_own_independent_fingerprint() {
    let old: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/PROTOCOL-FINGERPRINT-CANDIDATE-V9.json"
    )).unwrap();
    let bytes = hex::decode(old["manifest_hex"].as_str().unwrap()).unwrap();
    let manifest = RuleManifest::decode(&bytes).unwrap();
    assert_eq!(hex::encode(manifest.fingerprint().unwrap()), old["fingerprint"].as_str().unwrap());
    assert_ne!(old["fingerprint"], document()["fingerprint"]);
}
