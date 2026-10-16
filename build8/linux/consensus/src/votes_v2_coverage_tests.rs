//! Public software-only projection test. No authenticated StateRoot, recovery
//! acceptance, physical witness or post-sealing admission authority is claimed.
#[path = "../tests/support/software_tpm.rs"]
mod software_tpm;
use super::*;
use crate::{
    admission_v2::{Admission, Expected, Policy},
    ek_chain::{AnchorConstraints, RevocationMode, SignatureAlgorithm},
    endorsement_identity::{ECC_TAG, IdentityClass, IdentityClasses, RSA_TAG, TPM_ECC_NIST_P256},
    genesis_v2::{EndorsementRoot, EndorsementRootSet, GenesisClass, Parameters},
    node_admission_v2::{Binding, node_id},
    pcr_profiles::{AcceptedPcrProfiles, INTERPRETATION_QUOTE_COMPOSITE, PcrProfile, SHA256_BANK, UPDATE_FROZEN_AT_GENESIS},
    provenance::AdmissionClass,
    recovery::{Anchor, ContinuityState, Member},
};
use mutiny_crypto_v2::{HybridKey, HybridSignature, Role};
use software_tpm::{Strip, TestTpm};

#[test]
fn projected_production_authority_requires_every_committed_identity_class() {
    let label = |part: &str| domain_hash(b"MUTINY-BUILD8-TEST-VALUE-PROJECTION-COVERAGE", part.as_bytes());
    let root = label("invented-root-not-manufacturer-evidence");
    let genesis = label("synthetic-genesis");
    let single = TestTpm::with_identity("projection-coverage")
        .strip(Strip::ConsistentProvenance(root));
    let classes = IdentityClasses::new(vec![
        IdentityClass { algorithm: RSA_TAG, size: 2048, template_sha256: label("rsa-template") },
        IdentityClass { algorithm: ECC_TAG, size: TPM_ECC_NIST_P256, template_sha256: label("ecc-template") },
    ]).unwrap();
    let roots = EndorsementRootSet { roots: [(root, EndorsementRoot {
        constraints: AnchorConstraints {
            max_intermediates: 0,
            signature_algorithms: [SignatureAlgorithm::EcdsaP256Sha256].into(),
            ek_classes: [(RSA_TAG, 2048), (ECC_TAG, TPM_ECC_NIST_P256)].into(),
            revocation: RevocationMode::NoCrlPublished,
        },
        test_value_label: None,
    })].into() };
    let profile = single.profile();
    let pcr_profiles = AcceptedPcrProfiles::new(UPDATE_FROZEN_AT_GENESIS, vec![PcrProfile {
        bank: SHA256_BANK,
        selection: profile.pcr_bitmap,
        digest: profile.pcr_digest,
        interpretation: INTERPRETATION_QUOTE_COMPOSITE,
    }]).unwrap();
    let mut commitments = crate::genesis_v2::binding_entries(
        GenesisClass::Production, &roots, &pcr_profiles, &classes,
    ).unwrap();
    commitments.sort();
    let parameters = Parameters {
        class: GenesisClass::Production,
        initial_target: [0xff; 32],
        rules: crate::protocol_manifest::RuleManifest { commitments },
        roots,
        pcr_profiles,
        identity_classes: classes,
    };
    let fingerprint = parameters.fingerprint().unwrap();
    let owner = HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner).unwrap();
    let node = HybridKey::generate(Role::Node).unwrap();
    let continuity = HybridKey::generate(Role::Continuity).unwrap();
    let descriptor = node.public().descriptor(1).unwrap();
    let id = node_id(genesis, &descriptor).unwrap();
    let nonce = label("public-synthetic-genesis-ceremony-nonce");
    let policy = Policy { genesis, fingerprint, owner_descriptor: owner.public().descriptor(1).unwrap(),
        endorsement_roots: [root].into() };
    let parent = FinalizedAnchor { network: crate::NETWORK_ID, genesis, fingerprint, height: 0, block: label("parent") };
    for count in [2, 1] {
        let tpm = if count == 2 {
            single.edited(|p| {
                let provenance = p.provenance.as_mut().unwrap();
                provenance.endorsement.as_mut().unwrap().identities.push((root, label("second-public-identity")));
                p.admission_trust_manifest = provenance.commitment();
            })
        } else { single.edited(|_| {}) };
        let zero = || HybridSignature { ed448: [0; 114], fndsa: [0; 1280] };
        let mut binding = Binding {
            node_signer: None,
            node_descriptor: descriptor.clone(),
            possession: zero(),
            admission: Admission {
                genesis, fingerprint, node: id, hardware_generation: 1, key_generation: 1,
                continuity_descriptor: continuity.public().descriptor(1).unwrap(),
                profile: tpm.profile().encode().unwrap(), endorsement_root: root,
                owner: owner.public().address_id(1).unwrap(), supervised_nonce: nonce,
                quote: vec![], possession: zero(), authorization: zero(),
            },
        };
        binding.admission.prove_continuity(&continuity).unwrap();
        binding.admission.quote = tpm.quote(binding.admission.challenge().unwrap());
        binding.admission.authorize(&owner, 1).unwrap();
        binding.sign(&node).unwrap();
        let mut state = State::default();
        state.wallets.register(&policy.owner_descriptor).unwrap();
        state.admission_policy_v2 = Some(crate::admission_policy_v2::Record::new(policy.clone()).unwrap());
        state.protocol_records.insert(crate::genesis_v2::parameters_key(), parameters.encode().unwrap());
        assert_eq!(state.admission_class().unwrap(), AdmissionClass::Production);
        (state.membership_v2, state.continuity_keys_v2) = crate::membership_v2::Book::genesis(
            &binding, &policy,
            &Expected { node: id, hardware_generation: 1, key_generation: 1, supervised_nonce: nonce },
            &state.wallets, AdmissionClass::Production,
        ).unwrap();
        state.continuity = Some(ContinuityState::bootstrap(genesis, fingerprint,
            Anchor { height: 0, tip: parent.block, state_root: [0; 32], registry_root: [0; 32] },
            label("synthetic-recovery-authority"), vec![Member {
                lineage: id, node: id, hardware: tpm.profile().hardware, generation: 1,
                voting_key: tpm.voting_point(), attestation: tpm.profile().commitment().unwrap(),
                history: Default::default(), physical: true, eligible: true, genesis_member: true,
            }],
        ).unwrap());
        // The exact authority method used for a recovery projection intentionally
        // does not authenticate a StateRoot. Validate this boundary directly;
        // public Production Prepared::verify is independently closed by A8.
        let result = HeightAuthority::from_validated_components(&state, parent.clone());
        if count == 2 {
            assert!(result.unwrap().voters.contains_key(&id), "full count control");
        } else {
            assert!(matches!(result, Err(IngressError::Invalid(Error::UnqualifiedPhysical))),
                "deficient projected authority was exposed: {result:?}");
        }
    }
}
