#[path = "support/software_tpm.rs"]
mod software_tpm;
use mutiny_consensus_v8::{
    freshness::{PhysicalAttestationVerifier, PhysicalMember},
    tpm::*,
};
use software_tpm::TestTpm;
fn bytes(v: &serde_json::Value, k: &str) -> Vec<u8> {
    hex::decode(v[k].as_str().unwrap()).unwrap()
}
fn profile_from(v: &serde_json::Value) -> TpmProfile {
    TpmProfile {
        hardware: bytes(v, "hardware").try_into().unwrap(),
        ak_public: bytes(v, "ak_public"),
        voting_public: bytes(v, "voting_public"),
        qualified_signer: bytes(v, "qualified_signer"),
        pcr_bitmap: bytes(v, "pcr_bitmap").try_into().unwrap(),
        pcr_digest: bytes(v, "pcr_digest").try_into().unwrap(),
        certify_message: bytes(v, "certify_message"),
        certify_signature: bytes(v, "certify_signature"),
        admission_trust_manifest: bytes(v, "admission_trust_manifest").try_into().unwrap(),
        provenance: None,
    }
}
/// Portable: SOFTWARE TEST-VALUE evidence from the in-repo simulator (signatures are real ECDSA).
/// This does NOT establish physical TPM qualification.
#[test]
fn software_quote_certification_profile_and_tamper_matrix() {
    let tpm = TestTpm::new();
    let p = tpm.profile().clone();
    assert!(p.is_test_value());
    assert_eq!(TpmProfile::decode(&p.encode().unwrap()).unwrap().commitment().unwrap(), p.commitment().unwrap());
    let challenge = TestTpm::challenge();
    let evidence = tpm.quote(challenge);
    p.verify_certified_key().unwrap();
    p.verify_quote(challenge, &evidence).unwrap();
    // A second fresh quote under the same key, for cross-challenge replay rejection.
    let other_challenge = TestTpm::second_challenge();
    let other_evidence = tpm.quote(other_challenge);
    p.verify_quote(other_challenge, &other_evidence).unwrap();
    assert!(p.verify_quote(challenge, &other_evidence).is_err());
    assert!(p.verify_quote(other_challenge, &evidence).is_err());
    exercise_matrix(&p, challenge, &evidence);
}
fn exercise_matrix(p: &TpmProfile, challenge: [u8; 32], evidence: &[u8]) {
    let m = PhysicalMember {
        node: [1; 32],
        generation: 0,
        continuity_key: public_key(&p.voting_public, false).unwrap(),
        hardware: p.hardware,
        admission_commitment: p.commitment().unwrap(),
        attestation_key: p.ak_public.clone(),
    };
    let verifier = PinnedTpmVerifier {
        profiles: std::collections::BTreeMap::from([(m.admission_commitment, p.clone())]),
    };
    verifier.verify(&m, challenge, evidence).unwrap();
    let mut wrong = challenge;
    wrong[0] ^= 1;
    assert!(p.verify_quote(wrong, evidence).is_err());
    for offset in [0, 10, evidence.len() - 1] {
        let mut bad = evidence.to_vec();
        bad[offset] ^= 1;
        assert!(p.verify_quote(challenge, &bad).is_err());
    }
    for field in 0..5 {
        let mut bad = p.clone();
        match field {
            0 => bad.pcr_digest[0] ^= 1,
            1 => bad.pcr_bitmap[0] ^= 1,
            2 => bad.qualified_signer[4] ^= 1,
            3 => bad.certify_message[20] ^= 1,
            _ => bad.voting_public[9] ^= 1,
        };
        assert!(bad.verify_quote(challenge, evidence).is_err());
    }
    for n in 0..evidence.len() {
        assert!(p.verify_quote(challenge, &evidence[..n]).is_err());
    }
}

/// PHYSICAL-ONLY (needs evidence from a real TPM host, supplied at RUNTIME; never compiled in).
/// BUILD8_PHYSICAL_TPM_PROFILE_FIXTURE=<path to physical public fixture JSON>
/// BUILD8_PHYSICAL_TPM_LIVE_QUOTE=<path to a fresh live quote JSON from the same AK>
/// Run: cargo test --offline --locked --test tpm -- --ignored
#[test]
#[ignore = "requires physical TPM evidence supplied by env path (runtime)"]
fn physical_tpm_quote_certification_and_live_quote() {
    let read = |var: &str| -> serde_json::Value {
        let path = std::env::var(var).unwrap_or_else(|_| {
            panic!("PHYSICAL TPM EVIDENCE MISSING: {var} is not set; this test must not pass without real evidence")
        });
        serde_json::from_str(&std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{var}={path}: {e}"))).unwrap()
    };
    let v = read("BUILD8_PHYSICAL_TPM_PROFILE_FIXTURE");
    assert_ne!(v["TEST_VALUE"], true, "a TEST_VALUE fixture is not physical evidence");
    let p = profile_from(&v);
    assert!(!p.is_test_value(), "a TEST-VALUE profile is not physical evidence");
    assert_eq!(p.encode().unwrap(), bytes(&v, "profile"));
    assert_eq!(p.commitment().unwrap().as_slice(), bytes(&v, "commitment"));
    let challenge = bytes(&v, "challenge").try_into().unwrap();
    let evidence = bytes(&v, "quote_evidence");
    p.verify_certified_key().unwrap();
    p.verify_quote(challenge, &evidence).unwrap();
    let live = read("BUILD8_PHYSICAL_TPM_LIVE_QUOTE");
    let live_challenge = bytes(&live, "challenge").try_into().unwrap();
    let live_evidence = encode_quote(&bytes(&live, "quote_message"), &bytes(&live, "quote_signature")).unwrap();
    p.verify_quote(live_challenge, &live_evidence).unwrap();
    assert!(p.verify_quote(challenge, &live_evidence).is_err());
    assert!(p.verify_quote(live_challenge, &evidence).is_err());
    exercise_matrix(&p, challenge, &evidence);
}
