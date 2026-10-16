//! Self-tests and drift guard for the TEST-VALUE software TPM fixture generator.
//! SIMULATED != PHYSICAL: nothing here is physical TPM evidence.
#[path = "support/software_tpm.rs"]
mod software_tpm;
use mutiny_consensus_v8::{
    freshness::{PhysicalAttestationVerifier, PhysicalMember},
    tpm::*,
};
use software_tpm::TestTpm;

#[test]
fn generator_is_deterministic_and_signatures_are_really_valid() {
    let (a, b) = (TestTpm::new(), TestTpm::new());
    assert_eq!(a.fixture_text(), b.fixture_text());
    let p = a.profile();
    p.verify_certified_key().unwrap();
    assert_eq!(TpmProfile::decode(&p.encode().unwrap()).unwrap().commitment().unwrap(), p.commitment().unwrap());
    let c = TestTpm::challenge();
    let q = a.quote(c);
    p.verify_quote(c, &q).unwrap();
    // A quote is bound to its challenge and to the signature bytes.
    assert!(p.verify_quote(TestTpm::second_challenge(), &q).is_err());
    let mut bad = q.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(p.verify_quote(c, &bad).is_err());
    assert!(p.is_test_value());
    assert!(!TestTpm::unmarked_negative_control().profile().is_test_value());
}

#[test]
fn fixture_json_carries_explicit_test_value_labels() {
    let v = TestTpm::new().fixture_json();
    assert_eq!(v["schema"], software_tpm::FIXTURE_SCHEMA);
    assert_eq!(v["TEST_VALUE"], true);
    for k in ["physical_tpm", "qualifies_hardware", "production_eligible", "bond_eligible", "actual_genesis_admission"] {
        assert_eq!(v[k], false, "{k}");
    }
    assert!(v["warning"].as_str().unwrap().contains("Not a TPM"));
    assert!(v["provenance"]["generator"].as_str().unwrap().ends_with("software_tpm.rs"));
    assert_eq!(v["provenance"]["real_host_evidence"], "none");
}

#[test]
fn pinned_verifier_accepts_simulator_member_and_rejects_wrong_binding() {
    let t = TestTpm::new();
    let p = t.profile();
    let m = PhysicalMember {
        node: [1; 32],
        generation: 0,
        continuity_key: t.voting_point(),
        hardware: p.hardware,
        admission_commitment: p.commitment().unwrap(),
        attestation_key: p.ak_public.clone(),
    };
    let v = PinnedTpmVerifier { profiles: [(m.admission_commitment, p.clone())].into() };
    let c = TestTpm::challenge();
    v.verify(&m, c, &t.quote(c)).unwrap();
    let mut wrong = m.clone();
    wrong.hardware[0] ^= 1;
    assert!(v.verify(&wrong, c, &t.quote(c)).is_err());
}

fn normalized(s: &str) -> String {
    s.replace("\r\n", "\n")
}
const COMMITTED: &str = "../qualification/TEST-VALUE-SOFTWARE-TPM-FIXTURE-V1.json";

/// The committed JSON must equal the generator output (line-ending tolerant). When
/// BUILD8_EXPORT_TEST_VALUE_TPM_FIXTURE=<new path> is set, writes the file (create_new).
#[test]
fn committed_test_value_fixture_matches_generator() {
    let generated = TestTpm::new().fixture_text();
    if let Ok(path) = std::env::var("BUILD8_EXPORT_TEST_VALUE_TPM_FIXTURE") {
        use std::io::Write;
        std::fs::OpenOptions::new().write(true).create_new(true).open(path).unwrap()
            .write_all(generated.as_bytes()).unwrap();
        return;
    }
    // Runtime read (not include_str!): the JSON is for tools and humans, never a build input.
    let committed = std::fs::read_to_string(COMMITTED).expect("committed TEST-VALUE fixture present");
    assert_eq!(normalized(&committed), generated, "TEST-VALUE fixture drifted from generator");
}
