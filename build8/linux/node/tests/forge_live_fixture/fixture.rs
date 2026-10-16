//! Genesis V2 (Lane A1; Order A9, A10 and the representation part of A1): the explicit constructor and
//! verifier, the class byte committed into the identity and bound by the rule manifest, and the
//! endorsement-root SET with per-root constraints.
//!
//! Every value is public deterministic TEST-VALUE material: the software TPM simulator (TEST-VALUE
//! marked), public mnemonics, labelled TEST-VALUE roots with illustrative TEST-VALUE constraint values,
//! a labelled TEST-VALUE rule entry, and fresh random Node/Continuity/Worker-coordinator keys. Nothing
//! here is physical evidence, a production key, a real endorsement root or a Genesis seal; no test
//! claims a Production-class Genesis is acceptable. DOCUMENTED LIMIT (review F1): any party can CONSTRUCT a
//! Production-class Genesis from an invented root (`production_genesis_from_an_invented_root_constructs_and_only_the_
//! approved_manifest_refuses_it`); only the independently approved manifest refuses it. SIMULATED != PHYSICAL.
#[path = "support/software_tpm.rs"]
mod software_tpm;
#[allow(dead_code)]
#[path = "support/license_v2.rs"]
mod license_fixture;
#[path = "support/test_dir.rs"]
mod test_dir;
#[path = "support/test_value_ek.rs"]
mod test_value_ek;
#[path = "support/test_value_x509.rs"]
mod test_value_x509;
#[allow(dead_code)]
#[path = "support/x509_syntax.rs"]
mod x509_syntax;
use mutiny_consensus_v8::{
    Error, Hash, NETWORK_ID,
    admission_v2::Admission,
    blocks::genesis_license,
    domain_hash,
    execution::State,
    genesis_v2::{
        self, Approved, Claimed, Constructed, EndorsementRoot, EndorsementRootSet, Enrollment,
        GenesisClass, GenesisV2Error as E, Inputs, MemberInput, Parameters,
    },
    ek_chain::{AnchorConstraints, RevocationMode, SignatureAlgorithm},
    endorsement_identity::{ECC_TAG, IdentityClass, IdentityClasses, RSA_TAG, TPM_ECC_NIST_P256},
    pcr_profiles::{
        AcceptedPcrProfiles, INTERPRETATION_QUOTE_COMPOSITE, PcrFailure, PcrProfile, SHA256_BANK, UPDATE_FROZEN_AT_GENESIS,
    },
    node_admission_v2::{Binding, node_id},
    protocol_manifest::RuleManifest,
    provenance::{self, AdmissionClass},
    treasury_v1::{Class, Treasury},
    work_authority_v2::node_identity,
};
use mutiny_crypto_v2::{
    HybridKey, HybridSignature, Role,
    enrollment::{Binding as SupervisedBinding, owner_descriptor_id},
};
use software_tpm::TestTpm;
use std::collections::BTreeSet;

// ---------------------------------------------------------------------------------------------
// TEST-VALUE fixture
// ---------------------------------------------------------------------------------------------
const T0: u64 = 1000;
const ROOT_A: &str = "genesis-v2-test-value-root-a";
const ROOT_B: &str = "genesis-v2-test-value-root-b";
/// A labelled TEST-VALUE root that is NOT in the frozen set (the "second root" of the negative tests).
const ROOT_C: &str = "genesis-v2-test-value-root-c";
const FIXTURE_FILE: &str = "../qualification/GENESIS-V2-TEST-VALUE-FIXTURE-V1.json";
const FIXTURE_SCHEMA: &str = "BUILD8-GENESIS-V2-TEST-VALUE-FIXTURE-V1";

fn label(part: &str) -> Hash {
    domain_hash(b"MUTINY-BUILD8-TEST-VALUE-GENESIS-V2-FIXTURE-V1", part.as_bytes())
}
/// Public test mnemonics (never production identities).
fn owner_key() -> HybridKey {
    HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner).unwrap()
}
fn treasury_key() -> HybridKey {
    HybridKey::wallet_restore(&("zoo ".repeat(23) + "vote"), Role::WalletOwner).unwrap()
}
fn recovery_key() -> HybridKey {
    HybridKey::wallet_restore(
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        Role::WalletRecovery,
    )
    .unwrap()
}
fn root(l: &str) -> Hash {
    genesis_v2::test_value_root(l.as_bytes())
}
/// TEST-VALUE illustrative constraint values (A2's `AnchorConstraints`): root A certifies RSA-2048 and P-256 EKs with
/// two ECDSA signature algorithms and one intermediate; root B only P-256 EKs, ECDSA-P256, no intermediate, no CRL.
fn tv_constraints(wide: bool) -> AnchorConstraints {
    if wide {
        AnchorConstraints {
            max_intermediates: 1,
            signature_algorithms: [SignatureAlgorithm::EcdsaP256Sha256, SignatureAlgorithm::EcdsaP384Sha384].into(),
            ek_classes: [(RSA_TAG, 2048), (ECC_TAG, TPM_ECC_NIST_P256)].into(),
            revocation: RevocationMode::CrlRequired,
        }
    } else {
        AnchorConstraints {
            max_intermediates: 0,
            signature_algorithms: [SignatureAlgorithm::EcdsaP256Sha256].into(),
            ek_classes: [(ECC_TAG, TPM_ECC_NIST_P256)].into(),
            revocation: RevocationMode::NoCrlPublished,
        }
    }
}
fn entry(l: &str, wide: bool) -> (Hash, EndorsementRoot) {
    (root(l), EndorsementRoot { constraints: tv_constraints(wide), test_value_label: Some(l.as_bytes().to_vec()) })
}
fn test_roots() -> EndorsementRootSet {
    EndorsementRootSet { roots: [entry(ROOT_A, true), entry(ROOT_B, false)].into_iter().collect() }
}
fn profile_of(t: &TestTpm) -> PcrProfile {
    PcrProfile {
        bank: SHA256_BANK,
        selection: t.profile().pcr_bitmap,
        digest: t.profile().pcr_digest,
        interpretation: INTERPRETATION_QUOTE_COMPOSITE,
    }
}
fn pcr(t: &TestTpm) -> AcceptedPcrProfiles {
    AcceptedPcrProfiles::new(UPDATE_FROZEN_AT_GENESIS, vec![profile_of(t)]).unwrap()
}
/// TEST-VALUE identity-class list: one P-256 class with a labelled template hash.
fn classes() -> IdentityClasses {
    IdentityClasses::new(vec![IdentityClass { algorithm: ECC_TAG, size: TPM_ECC_NIST_P256, template_sha256: label("ek-template") }])
        .unwrap()
}
/// Recompute the four binding entries for the inputs' current class, root set, PCR set and class list.
fn rebuild(mut inputs: Inputs) -> Inputs {
    let names = [genesis_v2::CLASS_ENTRY, genesis_v2::ROOT_SET_ENTRY, genesis_v2::PCR_SET_ENTRY, genesis_v2::IDENTITY_CLASSES_ENTRY];
    let mut commitments: Vec<(Vec<u8>, Hash)> = inputs
        .parameters
        .rules
        .commitments
        .iter()
        .filter(|(n, _)| !names.contains(&n.as_slice()))
        .cloned()
        .collect();
    let p = &inputs.parameters;
    commitments.extend(genesis_v2::binding_entries(p.class, &p.roots, &p.pcr_profiles, &p.identity_classes).unwrap());
    commitments.sort();
    inputs.parameters.rules = RuleManifest { commitments };
    inputs
}
fn test_value_inputs() -> Inputs {
    let tpm = TestTpm::new();
    let owner = owner_key();
    rebuild(Inputs {
        timestamp: T0,
        nonce: label("nonce"),
        parameters: Parameters {
            class: GenesisClass::TestValue,
            initial_target: [0xff; 32],
            rules: RuleManifest {
                commitments: vec![(b"test-value-genesis-v2-rules".to_vec(), label("rules"))],
            },
            roots: test_roots(),
            pcr_profiles: pcr(&tpm),
            identity_classes: classes(),
        },
        admission_owner: owner.public().descriptor(1).unwrap(),
        member: MemberInput { endorsement_root: root(ROOT_A), profile: tpm.profile().encode().unwrap() },
        recovery: recovery_key().public().descriptor(1).unwrap(),
        treasury: Treasury::new(Class::TestValue, treasury_key().public().descriptor(1).unwrap()).unwrap(),
        purchase: label("purchase"),
    })
}
fn approved(inputs: &Inputs) -> Approved {
    Approved {
        manifest: inputs.parameters.rules.clone(),
        class: inputs.parameters.class,
        initial_target: inputs.parameters.initial_target,
    }
}
fn zero() -> HybridSignature {
    HybridSignature { ed448: [0; 114], fndsa: [0; 1280] }
}
struct Genesis {
    inputs: Inputs,
    enrollment: Enrollment,
    node: HybridKey,
    continuity: HybridKey,
}
/// Post-identity enrollment over the frozen GenesisID: the member's fresh Node and Continuity keys,
/// its owner-authorized supervised admission (TEST-VALUE simulator quote), and the twelve owner/Worker
/// signed Bootstrap License assignments (Licenses 0-5 coordinated by the member's Node key, 6-11 by a
/// second, cloud-style Node key).
fn enroll(inputs: &Inputs) -> Genesis {
    enroll_with(inputs, &TestTpm::new())
}
fn enroll_with(inputs: &Inputs, tpm: &TestTpm) -> Genesis {
    let owner = owner_key();
    let identity = inputs.identity().unwrap();
    let fingerprint = inputs.parameters.fingerprint().unwrap();
    assert_eq!(tpm.profile().encode().unwrap(), inputs.member.profile);
    let node = HybridKey::generate(Role::Node).unwrap();
    let node_b = HybridKey::generate(Role::Node).unwrap();
    let continuity = HybridKey::generate(Role::Continuity).unwrap();
    let node_descriptor = node.public().descriptor(1).unwrap();
    let mut binding = Binding {
        node_signer: None,
        node_descriptor: node_descriptor.clone(),
        possession: zero(),
        admission: Admission {
            genesis: identity,
            fingerprint,
            node: node_id(identity, &node_descriptor).unwrap(),
            hardware_generation: 1,
            key_generation: 1,
            continuity_descriptor: continuity.public().descriptor(1).unwrap(),
            profile: inputs.member.profile.clone(),
            endorsement_root: inputs.member.endorsement_root,
            owner: owner.public().address_id(1).unwrap(),
            supervised_nonce: label("supervised-nonce"),
            quote: vec![],
            possession: zero(),
            authorization: zero(),
        },
    };
    binding.admission.prove_continuity(&continuity).unwrap();
    binding.admission.quote = tpm.quote(binding.admission.challenge().unwrap());
    binding.admission.authorize(&owner, 1).unwrap();
    binding.sign(&node).unwrap();
    let node_b_descriptor = node_b.public().descriptor(1).unwrap();
    let mut assignments = Vec::new();
    let mut supervised = Vec::new();
    for i in 0..12u64 {
        let coordinator = if i < 6 { &node_descriptor } else { &node_b_descriptor };
        let mut b = SupervisedBinding {
            genesis: identity,
            fingerprint,
            license: genesis_license(identity, i).unwrap(),
            owner_descriptor: owner_descriptor_id(owner.public(), 1).unwrap(),
            owner_generation: 1,
            worker_public: license_fixture::worker(i as u8 + 1),
            worker_id: [0; 32],
            coordinator: node_identity(coordinator).unwrap(),
            configuration_generation: 1,
            device_mac: [2, 0, 0, 0, 0, i as u8 + 1],
            assignment_generation: 1,
            effective_epoch: 0,
            valid_until_height: 0,
        };
        b.worker_id = b.derived_worker_id();
        assignments.push(license_fixture::sign(b.clone(), &owner, coordinator, i as u8 + 1));
        supervised.push(b);
    }
    Genesis {
        inputs: inputs.clone(),
        enrollment: Enrollment {
            supervised_nonce: label("supervised-nonce"),
            member_binding: binding,
            assignments,
            supervised,
        },
        node,
        continuity,
    }
}
fn claimed(c: &Constructed) -> Claimed {
    Claimed {
        genesis_id: c.identity,
        records: c.records().unwrap(),
        state_root: c.root,
        block: c.block.clone(),
        block_hash: c.block_hash,
    }
}
pub fn with_fresh_ephemeral(f:impl FnOnce(&Inputs,&Enrollment,&Constructed,&HybridKey,&HybridKey,&[u8])) {
    use mutiny_consensus_v8::{
        admission_evidence_v1::{self as evidence,PublicWitnessBundle},
        attestation_witness::{self,AttestationWitness,EndorsementEvidence},
        anchors::FinalizedAnchor,canonical_store_v2::CanonicalStore,
        test_value_root_alias_v1 as alias,
    };
    let pki=test_value_x509::X509Pki::new("selected-test-value-root-alias-genesis");
    let der_root=pki.root_hash();
    let mut label_bytes=alias::LABEL_PREFIX.to_vec();label_bytes.extend(der_root);
    let logical_root=genesis_v2::test_value_root(&label_bytes);
    assert_ne!(logical_root,der_root);
    let tpm=TestTpm::stripped(software_tpm::Strip::ConsistentProvenance(logical_root));
    let statement=tpm.profile().provenance.as_ref().unwrap().clone();
    let chain=pki.chain(&tpm.simulator_ek(),&[0x71]);
    let witness=AttestationWitness {
        reference_time:test_value_x509::T_REF,
        endorsements:vec![EndorsementEvidence {
            ek_public_area:test_value_ek::public_area(&test_value_ek::template(ECC_TAG,test_value_ek::TEST_ATTRIBUTES),&tpm.simulator_ek()),
            certificates:chain.clone(),crls:pki.crls(&[],&[]),
        }],
        activation:vec![test_value_ek::activation(0,statement.ak_name,"public-only-no-activation-proof")],
    };
    let raw=witness.encode().unwrap();
    let mut statement=statement;
    statement.endorsement.as_mut().unwrap().witness_sha256=witness.commitment().unwrap();
    statement.ek_public_sha256=mutiny_consensus_v8::x509_syntax::certified_public_key_sha256(&chain[0]).unwrap();
    let tpm=tpm.with_provenance(statement);
    let anchor=pki.anchor(RevocationMode::CrlRequired,&[test_value_ek::ECC_CLASS],
        &[SignatureAlgorithm::EcdsaP256Sha256,SignatureAlgorithm::EcdsaP384Sha384]);
    let mut inputs=test_value_inputs();
    mutiny_crypto_v2::fill_os_random(&mut inputs.nonce).unwrap();
    inputs.timestamp=test_value_x509::T_REF;
    inputs.parameters.roots=EndorsementRootSet {roots:[(logical_root,EndorsementRoot {
        constraints:anchor.constraints,test_value_label:Some(label_bytes),
    })].into()};
    inputs.parameters.identity_classes=IdentityClasses::new(vec![test_value_ek::class_of(ECC_TAG,test_value_ek::TEST_ATTRIBUTES)]).unwrap();
    inputs.parameters.pcr_profiles=pcr(&tpm);
    inputs.parameters.rules.commitments.push((alias::RULE_ENTRY.to_vec(),alias::rule_commitment()));
    inputs.parameters.rules.commitments.push((mutiny_consensus_v8::endorsement_revocation_v1::RULE_ENTRY.to_vec(),
        mutiny_consensus_v8::endorsement_revocation_v1::rule_commitment()));
    inputs.member=MemberInput {endorsement_root:logical_root,profile:tpm.profile().encode().unwrap()};
    let inputs=rebuild(inputs);
    inputs.validate().unwrap();
    let enrolled=enroll_with(&inputs,&tpm);
    let bundle=PublicWitnessBundle {genesis:inputs.identity().unwrap(),fingerprint:inputs.parameters.fingerprint().unwrap(),
        entries:vec![(enrolled.enrollment.member_binding.admission.node,raw.clone())]};
    assert!(genesis_v2::construct(&inputs,&enrolled.enrollment).is_err(),"A2 marked Genesis must require available evidence");
    let constructed=genesis_v2::construct_with_public_dependencies(&inputs,&enrolled.enrollment,&bundle.encode().unwrap()).unwrap();
    let verified=evidence::verify_genesis_public_evidence(&inputs.encode().unwrap(),&enrolled.enrollment.encode().unwrap(),
        &approved(&inputs),&claimed(&constructed),&bundle.encode().unwrap()).unwrap();
    assert_eq!(verified.root,constructed.root);

    let public_evidence=bundle.encode().unwrap();
    f(&inputs,&enrolled.enrollment,&constructed,&enrolled.node,&enrolled.continuity,&public_evidence);
}
