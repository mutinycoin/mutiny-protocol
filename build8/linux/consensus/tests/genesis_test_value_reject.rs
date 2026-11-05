//! Software TEST-VALUE TPM evidence can never enter PRODUCTION Genesis.
#[path = "support/software_tpm.rs"]
mod software_tpm;
use ed25519_dalek::SigningKey as Ed;
use mutiny_consensus_v8::{
    Error, blocks::GenesisDescriptor, genesis_inputs::*, protocol_manifest::RuleManifest,
    transactions, treasury_v1::{Class, Treasury},
};
use mutiny_crypto_v2::{HybridKey, Role};
use software_tpm::TestTpm;

fn descriptor(t: &TestTpm) -> (GenesisDescriptor, RuleManifest, [u8; 32]) {
    let owner = Ed::from_bytes(&[80; 32]).verifying_key().to_bytes();
    let node = Ed::from_bytes(&[81; 32]).verifying_key().to_bytes();
    let recovery = Ed::from_bytes(&[82; 32]).verifying_key().to_bytes();
    let rules = RuleManifest { commitments: vec![(b"test-value-rules".to_vec(), [86; 32])] };
    let target = [87; 32];
    let input = PhysicalAdmissionInput {
        owner,
        node_authentication: node,
        endorsement_root: [88; 32],
        profile: t.profile().clone(),
    };
    // Public all-"zoo" TEST-VALUE mnemonic; never a production identity.
    let treasury_key = HybridKey::wallet_restore(&("zoo ".repeat(23) + "vote"), Role::WalletOwner)
        .unwrap()
        .public()
        .descriptor(1)
        .unwrap();
    let params = Parameters {
        initial_target: target,
        rules: rules.clone(),
        treasury: Some(Treasury::new(Class::Production, treasury_key).unwrap()),
    };
    let d = GenesisDescriptor {
        timestamp: 1_800_000_000,
        nonce: [89; 32],
        fingerprint: rules.fingerprint().unwrap(),
        owner: transactions::address(&input.owner),
        purchase: [90; 32],
        parameters: params.encode().unwrap(),
        admission_records: vec![input.encode().unwrap()],
        recovery,
    };
    (d, rules, target)
}

#[test]
fn test_value_profile_rejected_by_production_genesis() {
    let (d, rules, target) = descriptor(&TestTpm::new());
    // Structurally valid, so the rejection below is specifically the TEST-VALUE marker.
    validate_descriptor(&d, &rules, target).unwrap();
    let err = validate_production_descriptor(&d, &rules, target).unwrap_err();
    assert!(matches!(err, Error::UnqualifiedPhysical), "{err:?}");
}

/// FLIPPED (TPM admission package, analysis T1). This negative control USED TO pass Production
/// descriptor validation, which showed that the TEST-VALUE marker was the only barrier. Production
/// Genesis now also requires the Production admission class (a Genesis rule manifest committing
/// to the endorsement-root set) and a verified typed provenance statement, so stripping the marker
/// gains nothing and the same descriptor is rejected. The marker is an accidental-use guard only.
#[test]
fn unmarked_profile_is_rejected_by_production_genesis_without_class_and_provenance() {
    let (d, rules, target) = descriptor(&TestTpm::unmarked_negative_control());
    // Still structurally valid, so the rejection is the class/provenance rule, not a defect.
    validate_descriptor(&d, &rules, target).unwrap();
    let err = validate_production_descriptor(&d, &rules, target).unwrap_err();
    assert!(matches!(err, Error::UnqualifiedPhysical), "{err:?}");
}
