#[path = "../tests/support/software_tpm.rs"]
mod software_tpm;
use ed25519_dalek::{Signer, SigningKey};
use software_tpm::TestTpm;
use mutiny_consensus_v8::{admission::*, execution::State, tpm::TpmProfile};
fn main() {
    // SOFTWARE TEST-VALUE profile (real ECDSA signatures; not physical evidence).
    let tpm = TestTpm::new();
    // Public deterministic test authority; never production wallet custody.
    let signer = SigningKey::from_bytes(&[51; 32]);
    let policy = AdmissionPolicy {
        genesis: [1; 32],
        fingerprint: [2; 32],
        authority: signer.verifying_key().to_bytes(),
        endorsement_roots: [[3; 32]].into_iter().collect(),
    };
    let mut approved = ApprovedProfile {
        genesis: policy.genesis,
        fingerprint: policy.fingerprint,
        endorsement_root: [3; 32],
        profile: tpm.profile().encode().unwrap(),
        signature: [0; 64],
    };
    approved.signature = signer.sign(&approved.signing_digest().unwrap()).to_bytes();
    let commitment = TpmProfile::decode(&approved.profile)
        .unwrap()
        .commitment()
        .unwrap();
    let state = State {
        admission: AdmissionBook {
            policy: Some(policy.clone()),
            profiles: [(commitment, approved.clone())].into_iter().collect(),
        },
        ..Default::default()
    };
    println!(
        "{}",
        serde_json::json!({"schema":"BUILD8-ADMISSION-VECTORS-V1", "actual_genesis":false, "test_value":true, "physical_tpm":false, "production_eligible":false,
        "authority_fixture_only":true, "policy":hex::encode(policy.encode().unwrap()),
        "approved_profile":hex::encode(approved.encode().unwrap()), "signing_digest":hex::encode(approved.signing_digest().unwrap()),
        "records":state.records().unwrap().iter().map(|(k,v)|[hex::encode(k),hex::encode(v)]).collect::<Vec<_>>(),
        "state_root":hex::encode(state.root().unwrap())})
    );
}
