#[path = "support/software_tpm.rs"]
mod software_tpm;
use ed25519_dalek::{Signer, SigningKey};
use software_tpm::TestTpm;
use mutiny_consensus_v8::admission::*;
// Legacy/Test admission class: this test has no committed Genesis trust-root declaration.
use mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest;
#[test]
fn supervised_profile_authority_is_context_bound_and_not_self_asserted() {
    // SOFTWARE TEST-VALUE profile (real ECDSA signatures, not physical evidence).
    let tpm = TestTpm::new();
    let authority = SigningKey::from_bytes(&[51; 32]);
    let policy = AdmissionPolicy {
        genesis: [1; 32],
        fingerprint: [2; 32],
        authority: authority.verifying_key().to_bytes(),
        endorsement_roots: [[3; 32]].into_iter().collect(),
    };
    assert_eq!(
        AdmissionPolicy::decode(&policy.encode().unwrap()).unwrap(),
        policy
    );
    let mut record = ApprovedProfile {
        genesis: [1; 32],
        fingerprint: [2; 32],
        endorsement_root: [3; 32],
        profile: tpm.profile().encode().unwrap(),
        signature: [0; 64],
    };
    assert!(record.verify(&policy, LegacyTest).is_err());
    record.signature = authority.sign(&record.signing_digest().unwrap()).to_bytes();
    let verified = record.verify(&policy, LegacyTest).unwrap();
    assert_eq!(verified.commitment().unwrap(), tpm.profile().commitment().unwrap());
    assert!(verified.is_test_value());
    assert_eq!(
        ApprovedProfile::decode(&record.encode().unwrap()).unwrap(),
        record
    );
    let commitment = verified.commitment().unwrap();
    let book = AdmissionBook {
        policy: Some(policy.clone()),
        profiles: [(commitment, record.clone())].into_iter().collect(),
    };
    assert_eq!(
        AdmissionBook::from_records(&book.records(LegacyTest).unwrap(), None).unwrap(),
        book
    );
    let state = mutiny_consensus_v8::execution::State {
        admission: book.clone(),
        ..Default::default()
    };
    let root = state.root().unwrap();
    assert_eq!(
        mutiny_consensus_v8::execution::State::from_records(&state.records().unwrap(), root)
            .unwrap(),
        state
    );
    assert_ne!(
        root,
        mutiny_consensus_v8::execution::State::default()
            .root()
            .unwrap()
    );
    let mut missing = book.records(LegacyTest).unwrap();
    missing.remove(&policy_key());
    assert!(AdmissionBook::from_records(&missing, None).is_err());
    let mut opaque = state.clone();
    opaque.protocol_records.insert(policy_key(), vec![0]);
    assert!(opaque.root().is_err());
    let mut tampered = book.clone();
    tampered.profiles.get_mut(&commitment).unwrap().signature[0] ^= 1;
    assert!(tampered.records(LegacyTest).is_err());
    let registry = mutiny_consensus_v8::recovery::ContinuityState::bootstrap(
        policy.genesis,
        policy.fingerprint,
        mutiny_consensus_v8::recovery::Anchor {
            height: 0,
            tip: [8; 32],
            state_root: root,
            registry_root: [9; 32],
        },
        policy.authority,
        vec![mutiny_consensus_v8::recovery::Member {
            lineage: [6; 32],
            node: [7; 32],
            hardware: verified.hardware,
            generation: 0,
            voting_key: mutiny_consensus_v8::tpm::public_key(&verified.voting_public, false)
                .unwrap(),
            attestation: commitment,
            history: Default::default(),
            physical: true,
            eligible: true,
            genesis_member: true,
        }],
    )
    .unwrap();
    let (members, verifier) = book.physical_context(&registry, LegacyTest).unwrap();
    use mutiny_consensus_v8::freshness::PhysicalAttestationVerifier;
    verifier
        .verify(
            &members[&[7; 32]],
            TestTpm::challenge(),
            &tpm.quote(TestTpm::challenge()),
        )
        .unwrap();
    let mut wrong_registry = registry.clone();
    wrong_registry.members[0].hardware[0] ^= 1;
    assert!(book.physical_context(&wrong_registry, LegacyTest).is_err());
    wrong_registry = registry.clone();
    wrong_registry.members[0].attestation[0] ^= 1;
    assert!(book.physical_context(&wrong_registry, LegacyTest).is_err());
    let mut wrong = policy.clone();
    wrong.genesis[0] ^= 1;
    assert!(record.verify(&wrong, LegacyTest).is_err());
    wrong = policy.clone();
    wrong.fingerprint[0] ^= 1;
    assert!(record.verify(&wrong, LegacyTest).is_err());
    wrong = policy.clone();
    wrong.authority = SigningKey::from_bytes(&[52; 32]).verifying_key().to_bytes();
    assert!(record.verify(&wrong, LegacyTest).is_err());
    wrong = policy.clone();
    wrong.endorsement_roots = [[4; 32]].into_iter().collect();
    assert!(record.verify(&wrong, LegacyTest).is_err());
    record.profile[5] ^= 1;
    assert!(record.verify(&policy, LegacyTest).is_err());
}
