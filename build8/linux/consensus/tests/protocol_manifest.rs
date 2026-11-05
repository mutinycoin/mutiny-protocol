use mutiny_consensus_v8::protocol_manifest::RuleManifest;
#[test]
fn runtime_candidate_v9_matches_independent_python() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/PROTOCOL-FINGERPRINT-CANDIDATE-V9.json"
    ))
    .unwrap();
    let manifest =
        RuleManifest::decode(&hex::decode(v["manifest_hex"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(
        hex::encode(manifest.fingerprint().unwrap()),
        v["fingerprint"]
    );
}
#[test]
fn runtime_candidate_v8_matches_independent_python() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/PROTOCOL-FINGERPRINT-CANDIDATE-V8.json"
    ))
    .unwrap();
    let manifest =
        RuleManifest::decode(&hex::decode(v["manifest_hex"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(
        hex::encode(manifest.fingerprint().unwrap()),
        v["fingerprint"]
    );
}
#[test]
fn runtime_candidate_v7_matches_independent_python() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/PROTOCOL-FINGERPRINT-CANDIDATE-V7.json"
    ))
    .unwrap();
    let manifest =
        RuleManifest::decode(&hex::decode(v["manifest_hex"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(
        hex::encode(manifest.fingerprint().unwrap()),
        v["fingerprint"]
    );
}
#[test]
fn runtime_candidate_v6_matches_independent_python() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/PROTOCOL-FINGERPRINT-CANDIDATE-V6.json"
    ))
    .unwrap();
    let manifest =
        RuleManifest::decode(&hex::decode(v["manifest_hex"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(
        hex::encode(manifest.fingerprint().unwrap()),
        v["fingerprint"]
    );
}
#[test]
fn runtime_candidate_v5_matches_independent_python() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/PROTOCOL-FINGERPRINT-CANDIDATE-V5.json"
    ))
    .unwrap();
    let manifest =
        RuleManifest::decode(&hex::decode(v["manifest_hex"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(
        hex::encode(manifest.fingerprint().unwrap()),
        v["fingerprint"]
    );
}
#[test]
fn runtime_candidate_v4_matches_independent_python() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/PROTOCOL-FINGERPRINT-CANDIDATE-V4.json"
    ))
    .unwrap();
    let manifest =
        RuleManifest::decode(&hex::decode(v["manifest_hex"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(
        hex::encode(manifest.fingerprint().unwrap()),
        v["fingerprint"]
    );
}
#[test]
fn runtime_candidate_v3_matches_independent_python() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/PROTOCOL-FINGERPRINT-CANDIDATE-V3.json"
    ))
    .unwrap();
    let manifest =
        RuleManifest::decode(&hex::decode(v["manifest_hex"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(
        hex::encode(manifest.fingerprint().unwrap()),
        v["fingerprint"]
    );
}
#[test]
fn current_candidate_v2_matches_independent_python() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/PROTOCOL-FINGERPRINT-CANDIDATE-V2.json"
    ))
    .unwrap();
    let manifest =
        RuleManifest::decode(&hex::decode(v["manifest_hex"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(
        hex::encode(manifest.fingerprint().unwrap()),
        v["fingerprint"]
    );
}
#[test]
fn independent_candidate_reproduction_and_noncanonical_rejection() {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/PROTOCOL-FINGERPRINT-CANDIDATE-V1.json"
    ))
    .unwrap();
    let raw = hex::decode(v["manifest_hex"].as_str().unwrap()).unwrap();
    let manifest = RuleManifest::decode(&raw).unwrap();
    assert_eq!(manifest.encode().unwrap(), raw);
    assert_eq!(
        hex::encode(manifest.fingerprint().unwrap()),
        v["fingerprint"]
    );
    let mut changed = manifest.clone();
    changed.commitments[0].1[0] ^= 1;
    assert_ne!(
        changed.fingerprint().unwrap(),
        manifest.fingerprint().unwrap()
    );
    let mut duplicate = manifest.clone();
    duplicate
        .commitments
        .insert(0, duplicate.commitments[0].clone());
    assert!(duplicate.encode().is_err());
    let mut reversed = manifest.clone();
    reversed.commitments.reverse();
    assert!(reversed.encode().is_err());
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(RuleManifest::decode(&trailing).is_err());
    let mut version = raw.clone();
    version[1] = 2;
    assert!(RuleManifest::decode(&version).is_err());
    for (name, _) in &manifest.commitments {
        assert!(!String::from_utf8_lossy(name).contains("qualification/"));
    }
}
