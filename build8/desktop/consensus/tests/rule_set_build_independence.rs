//! Shipping-configuration regression (Architect decision, 3 Oct 2026): no consensus rule may
//! depend on a Cargo feature. Validators on one NetworkID/GenesisID must apply identical rules
//! whatever flags they were built with. Runs in the default build; it inspects the real source
//! and manifest, so adding a feature-dependent rule fails it.
use std::{fs, path::PathBuf};

const ALLOWED_FEATURES: [&str; 2] = ["dividend-test-fixtures", "legacy-v0-test-fixtures"];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn manifest_declares_only_test_fixture_features() {
    let manifest = fs::read_to_string(root().join("Cargo.toml")).unwrap();
    let mut in_features = false;
    let mut declared = Vec::new();
    for line in manifest.lines() {
        let t = line.trim();
        if t.starts_with('[') {
            in_features = t == "[features]";
            continue;
        }
        if in_features && !t.is_empty() && !t.starts_with('#') {
            declared.push(t.split('=').next().unwrap().trim().to_string());
        }
    }
    declared.sort();
    assert_eq!(
        declared,
        ["default", "dividend-test-fixtures", "legacy-v0-test-fixtures"],
        "consensus must not grow a rule-selecting feature"
    );
}

#[test]
fn no_source_rule_is_selected_by_a_feature() {
    let mut offenders = Vec::new();
    for entry in fs::read_dir(root().join("src")).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        for (n, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap();
            if !code.contains("feature") || !code.contains('"') {
                continue;
            }
            let uses_cfg = code.contains("cfg(") || code.contains("cfg!(") || code.contains("cfg_attr(");
            if !uses_cfg || !code.contains("feature") {
                continue;
            }
            let allowed = ALLOWED_FEATURES.iter().any(|f| code.contains(&format!("\"{f}\"")));
            if !allowed {
                offenders.push(format!("{}:{}: {}", path.display(), n + 1, line.trim()));
            }
        }
    }
    assert!(offenders.is_empty(), "feature-dependent source: {offenders:#?}");
}

#[test]
fn fixture_features_are_not_compiled_in_this_default_build() {
    // The two remaining features gate test fixtures only (never block execution); the
    // exported constants let production binaries assert they are off.
    #[cfg(not(feature = "dividend-test-fixtures"))]
    assert!(!mutiny_consensus_v8::DIVIDEND_TEST_FIXTURES_ENABLED);
    #[cfg(not(feature = "legacy-v0-test-fixtures"))]
    assert!(!mutiny_consensus_v8::LEGACY_V0_TEST_FIXTURES_ENABLED);
}
