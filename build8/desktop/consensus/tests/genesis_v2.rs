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
fn production(mut inputs: Inputs) -> Inputs {
    inputs.parameters.class = GenesisClass::Production;
    inputs.treasury = Treasury::new(Class::Production, treasury_key().public().descriptor(1).unwrap()).unwrap();
    inputs
}

// ---------------------------------------------------------------------------------------------
// Test-side INDEPENDENT encoders of the documented layouts (design note section 2). They reproduce
// the library's bytes and build malformed byte strings the typed API cannot express.
// ---------------------------------------------------------------------------------------------
struct RootEntry<'a> {
    root: Hash,
    constraints: AnchorConstraints,
    label: Option<&'a [u8]>,
}
/// Independent encoder of the documented constraints layout `[2, max, [sig codes], [[tag, size]], revocation]` with the
/// documented codes (signature algorithms 1..6 in declaration order; CrlRequired 1, NoCrlPublished 2).
fn manual_constraints(e: &mut minicbor::Encoder<Vec<u8>>, c: &AnchorConstraints) {
    let code = |a: &SignatureAlgorithm| match a {
        SignatureAlgorithm::RsaPkcs1Sha256 => 1u8,
        SignatureAlgorithm::RsaPkcs1Sha384 => 2,
        SignatureAlgorithm::RsaPssSha256 => 3,
        SignatureAlgorithm::RsaPssSha384 => 4,
        SignatureAlgorithm::EcdsaP256Sha256 => 5,
        SignatureAlgorithm::EcdsaP384Sha384 => 6,
    };
    e.array(5).unwrap().u8(2).unwrap().u8(c.max_intermediates).unwrap();
    e.array(c.signature_algorithms.len() as u64).unwrap();
    for a in &c.signature_algorithms {
        e.u8(code(a)).unwrap();
    }
    e.array(c.ek_classes.len() as u64).unwrap();
    for (tag, size) in &c.ek_classes {
        e.array(2).unwrap().u8(*tag).unwrap().u16(*size).unwrap();
    }
    e.u8(match c.revocation { RevocationMode::CrlRequired => 1, RevocationMode::NoCrlPublished => 2 }).unwrap();
}
fn manual_root_set(version: u8, entries: &[RootEntry<'_>]) -> Vec<u8> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(2).unwrap().u8(version).unwrap().array(entries.len() as u64).unwrap();
    for x in entries {
        e.array(3).unwrap().bytes(&x.root).unwrap();
        manual_constraints(&mut e, &x.constraints);
        match x.label {
            Some(l) => {
                e.bytes(l).unwrap();
            }
            None => {
                e.null().unwrap();
            }
        }
    }
    e.into_writer()
}
#[allow(clippy::too_many_arguments)] // one argument per field of the documented layout
fn manual_parameters(version: u8, tag: u8, network: u32, class: u8, target: Hash, rules: &[u8], roots: &[u8], pcr: &[u8], classes: &[u8]) -> Vec<u8> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(9)
        .unwrap()
        .u8(version)
        .unwrap()
        .u8(tag)
        .unwrap()
        .u32(network)
        .unwrap()
        .u8(class)
        .unwrap()
        .bytes(&target)
        .unwrap()
        .bytes(rules)
        .unwrap()
        .bytes(roots)
        .unwrap()
        .bytes(pcr)
        .unwrap()
        .bytes(classes)
        .unwrap();
    e.into_writer()
}
fn manual_member(version: u8, root: Hash, profile: &[u8]) -> Vec<u8> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3).unwrap().u8(version).unwrap().bytes(&root).unwrap().bytes(profile).unwrap();
    e.into_writer()
}
fn manual_inputs(version: u8, i: &Inputs, parameters: &[u8], member: &[u8]) -> Vec<u8> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(10)
        .unwrap()
        .u8(version)
        .unwrap()
        .u32(NETWORK_ID)
        .unwrap()
        .u64(i.timestamp)
        .unwrap()
        .bytes(&i.nonce)
        .unwrap()
        .bytes(parameters)
        .unwrap()
        .bytes(&i.admission_owner)
        .unwrap()
        .bytes(member)
        .unwrap()
        .bytes(&i.recovery)
        .unwrap()
        .bytes(&i.treasury.encode().unwrap())
        .unwrap()
        .bytes(&i.purchase)
        .unwrap();
    e.into_writer()
}
/// Manual encoding of the test inputs with a substituted root-set encoding whose commitment the
/// manifest carries (so only the root-set bytes are malformed).
fn inputs_with_root_set_bytes(i: &Inputs, roots: &[u8]) -> Vec<u8> {
    let p = &i.parameters;
    let pcr = p.pcr_profiles.encode();
    let mut rules = p.rules.clone();
    for (name, value) in rules.commitments.iter_mut() {
        if name.as_slice() == genesis_v2::ROOT_SET_ENTRY {
            *value = domain_hash(genesis_v2::ROOT_SET_DOMAIN, roots);
        }
    }
    let parameters = manual_parameters(2, 64, NETWORK_ID, p.class.byte(), p.initial_target, &rules.encode().unwrap(), roots, &pcr, &p.identity_classes.encode());
    manual_inputs(2, i, &parameters, &manual_member(2, i.member.endorsement_root, &i.member.profile))
}
fn test_value_root_entries() -> [(Hash, &'static str, bool); 2] {
    [(root(ROOT_A), ROOT_A, true), (root(ROOT_B), ROOT_B, false)]
}

// ---------------------------------------------------------------------------------------------
// POSITIVE
// ---------------------------------------------------------------------------------------------
/// A full TEST-VALUE V2 Genesis: constructed twice with identical identity, state, records, root and
/// block; every initial component derives from the inputs and enrollment; the class in committed state
/// is the input class; reconstruction from records is exact; the verifier accepts it against the
/// independently approved trust; identity and block hash are recomputed independently here.
#[test]
fn test_value_genesis_constructs_identically_twice_and_verifies() {
    let g = enroll(&test_value_inputs());
    let a = genesis_v2::construct(&g.inputs, &g.enrollment).unwrap();
    let b = genesis_v2::construct(&g.inputs, &g.enrollment).unwrap();
    assert_eq!((a.identity, a.root, &a.block, a.block_hash), (b.identity, b.root, &b.block, b.block_hash));
    assert_eq!(a.state, b.state);
    assert_eq!(a.records().unwrap(), b.records().unwrap());
    // Identity: H(MUTINY-BUILD8-GENESIS-ID-V2, canonical inputs), recomputed independently.
    let preimage = g.inputs.encode().unwrap();
    let mut sha = <sha2::Sha256 as sha2::Digest>::new();
    sha2::Digest::update(&mut sha, b"MUTINY-BUILD8-GENESIS-ID-V2");
    sha2::Digest::update(&mut sha, [0u8]);
    sha2::Digest::update(&mut sha, &preimage);
    let independent: Hash = sha2::Digest::finalize(sha).into();
    assert_eq!(a.identity, independent);
    assert_eq!(a.fingerprint, g.inputs.parameters.rules.fingerprint().unwrap());
    // Block: [2, NetworkID, GenesisID, fingerprint, timestamp, root] under MUTINY-BUILD8-GENESIS-BLOCK-V2.
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(6).unwrap().u8(2).unwrap().u32(NETWORK_ID).unwrap().bytes(&a.identity).unwrap()
        .bytes(&a.fingerprint).unwrap().u64(T0).unwrap().bytes(&a.root).unwrap();
    assert_eq!(a.block, e.into_writer());
    assert_eq!(a.block_hash, domain_hash(b"MUTINY-BUILD8-GENESIS-BLOCK-V2", &a.block));
    assert_eq!((a.t0, a.target, a.class), (T0, [0xff; 32], GenesisClass::TestValue));
    // Components (design note section 1).
    let s = &a.state;
    let owner = owner_key();
    assert!(s.coins.is_empty());
    assert_eq!(s.wallets.current(owner.public().address_id(1).unwrap()), Some(g.inputs.admission_owner.as_slice()));
    let policy = s.admission_policy_v2.as_ref().unwrap().initial();
    assert_eq!((policy.genesis, policy.fingerprint), (a.identity, a.fingerprint));
    assert_eq!(policy.endorsement_roots, [root(ROOT_A), root(ROOT_B)].into(), "a SET, not one slot");
    let registry = s.continuity.as_ref().unwrap();
    assert_eq!(registry.members.len(), 1);
    let member = &registry.members[0];
    let node = g.enrollment.member_binding.admission.node;
    assert_eq!((member.node, member.lineage, member.generation), (node, node, 1));
    assert!(member.physical && member.eligible && member.genesis_member);
    assert_eq!(
        registry.recovery_authority,
        mutiny_consensus_v8::recovery_genesis_input_v2::RecoveryInput::new(g.inputs.recovery.clone()).unwrap().commitment()
    );
    assert_eq!(s.recovery_authority_v2.as_ref().unwrap().descriptor, g.inputs.recovery);
    assert!(s.membership_v2.get(node).is_some() && s.continuity_keys_v2.get(node).is_some());
    let licenses: Vec<_> = s.licenses_v2.licenses().collect();
    assert_eq!(licenses.len(), 12);
    for (i, l) in licenses.iter().enumerate() {
        assert_eq!((l.owner, l.issuance, l.issue_height, l.assignment_sequence), (owner.public().address_id(1).unwrap(), g.inputs.purchase, 0, 1), "{i}");
        assert!(l.active_worker.is_some());
        assert_eq!(s.licenses_v2.dividend_activation_epoch(l.id), Some(0));
    }
    assert_eq!(s.dividends.treasury(), Some(&g.inputs.treasury));
    let fresh = &s.accounting.freshness[&node];
    assert_eq!((fresh.generation, fresh.committed_height), (1, 0));
    assert_eq!(
        fresh.evidence_commitment,
        domain_hash(b"MUTINY-BUILD8-ATTESTATION-EVIDENCE-V1", &g.enrollment.member_binding.admission.quote)
    );
    assert_eq!(s.protocol_records.len(), 1, "only the immutable GenesisParametersV2 record");
    assert_eq!(s.protocol_records[&genesis_v2::parameters_key()], g.inputs.parameters.encode().unwrap());
    assert!(s.admission.is_empty().unwrap() && s.membership.controls.is_empty() && s.bonds_v2.is_empty());
    assert!(s.licenses.licenses.is_empty() && s.node_key_history_v2.is_empty() && s.retired_continuity_v2.is_empty());
    // The class from committed state is the input class (TestValue -> Legacy/Test rule).
    assert_eq!(s.admission_class().unwrap(), AdmissionClass::LegacyTest);
    // Exact reconstruction from the committed records.
    let records = a.records().unwrap();
    assert_eq!(State::from_records(&records, a.root).unwrap(), a.state);
    // The verifier, against the independently approved TEST-VALUE trust.
    let verified = genesis_v2::verify(&preimage, &g.enrollment.encode().unwrap(), &approved(&g.inputs), &claimed(&a)).unwrap();
    assert_eq!((verified.identity, verified.root), (a.identity, a.root));
    // Strict codecs round-trip exactly.
    assert_eq!(Inputs::decode(&preimage).unwrap(), g.inputs);
    assert_eq!(Enrollment::decode(&g.enrollment.encode().unwrap()).unwrap(), g.enrollment);
}

/// The identity is a golden value of the deterministic TEST-VALUE inputs (no random key is an identity
/// input: the V2 Node/Continuity keys come after GenesisID). The class byte sits at its documented
/// place inside the preimage, so the identity covers it; a claimed identity computed WITHOUT the class
/// byte is refused by the verifier.
#[test]
fn golden_identity_pins_the_preimage_including_the_class_byte() {
    let inputs = test_value_inputs();
    let preimage = inputs.encode().unwrap();
    let parameters = inputs.parameters.encode().unwrap();
    let at = preimage.windows(parameters.len()).position(|w| w == parameters).unwrap();
    // [array9, 2, 0x18 64, 0x1a NetworkID(4), class]: the class byte is at offset 9 of the record.
    assert_eq!(&parameters[..4], &[0x89, 0x02, 0x18, 64]);
    assert_eq!(preimage[at + 9], GenesisClass::TestValue.byte());
    assert_eq!(
        hex::encode(inputs.identity().unwrap()),
        GOLDEN_TEST_VALUE_IDENTITY,
        "TEST-VALUE V2 GenesisID changed: the derivation or a deterministic input changed"
    );
    let mut without_class = preimage.clone();
    without_class.remove(at + 9);
    let g = enroll(&inputs);
    let c = genesis_v2::construct(&g.inputs, &g.enrollment).unwrap();
    let mut forged = claimed(&c);
    forged.genesis_id = domain_hash(genesis_v2::IDENTITY_DOMAIN, &without_class);
    assert_eq!(
        genesis_v2::verify(&preimage, &g.enrollment.encode().unwrap(), &approved(&inputs), &forged).err(),
        Some(E::IdentityMismatch)
    );
}
/// Re-pinned 2026-10-04 after review F2 (Genesis commits A2 structures) (Lane A1) from the deterministic TEST-VALUE inputs; a public test value only.
const GOLDEN_TEST_VALUE_IDENTITY: &str = "71e63dff4aa21141530d5c1deda979df5944a691c0b640cc2302cde6472f9434";

/// The library's encodings equal the test's independent encoders of the documented layouts.
#[test]
fn library_encoding_matches_the_independent_encoder() {
    let i = test_value_inputs();
    let p = &i.parameters;
    let entries: Vec<RootEntry<'static>> = test_value_root_entries()
        .into_iter()
        .map(|(root, l, wide)| RootEntry { root, constraints: tv_constraints(wide), label: Some(l.as_bytes()) })
        .collect();
    let mut sorted = entries;
    sorted.sort_by_key(|x| x.root);
    let roots = manual_root_set(1, &sorted);
    assert_eq!(p.roots.encode().unwrap(), roots);
    // The PCR set and class list are Lane A2's own codecs (single definition), embedded unchanged.
    let pcr_bytes = p.pcr_profiles.encode();
    assert_eq!(AcceptedPcrProfiles::decode(&pcr_bytes).unwrap(), p.pcr_profiles);
    let class_bytes = p.identity_classes.encode();
    let parameters = manual_parameters(2, 64, NETWORK_ID, 2, p.initial_target, &p.rules.encode().unwrap(), &roots, &pcr_bytes, &class_bytes);
    assert_eq!(p.encode().unwrap(), parameters);
    let member = manual_member(2, i.member.endorsement_root, &i.member.profile);
    assert_eq!(i.encode().unwrap(), manual_inputs(2, &i, &parameters, &member));
    // The three binding entries are the documented domain hashes of exactly these bytes.
    let entries = genesis_v2::binding_entries(p.class, &p.roots, &p.pcr_profiles, &p.identity_classes).unwrap();
    assert!(entries.contains(&(b"genesis-class-v2".to_vec(), domain_hash(b"MUTINY-BUILD8-GENESIS-CLASS-V2", &[2]))));
    assert!(entries.contains(&(b"endorsement-root-set-v2".to_vec(), domain_hash(b"MUTINY-BUILD8-ENDORSEMENT-ROOT-SET-V2", &roots))));
    assert!(entries.contains(&(b"accepted-pcr-profile-set-v1".to_vec(), domain_hash(b"MUTINY-BUILD8-ACCEPTED-PCR-PROFILES-V1", &pcr_bytes))));
    assert!(entries.contains(&(b"endorsement-identity-classes-v1".to_vec(), domain_hash(b"MUTINY-BUILD8-EK-IDENTITY-CLASSES-V1", &class_bytes))));
    assert_eq!(genesis_v2::parameters_key(), domain_hash(b"MUTINY-BUILD8-GENESIS-PARAMETERS-KEY-V2", &[]));
}

// ---------------------------------------------------------------------------------------------
// NEGATIVE: class (A10)
// ---------------------------------------------------------------------------------------------
/// Wrong class byte: an unknown value is a codec error; a known value the manifest does not commit to
/// cannot be encoded or decoded (the record and its manifest can never disagree).
#[test]
fn class_byte_must_be_known_and_committed_by_the_manifest() {
    let inputs = test_value_inputs();
    let preimage = inputs.encode().unwrap();
    let parameters = inputs.parameters.encode().unwrap();
    let at = preimage.windows(parameters.len()).position(|w| w == parameters).unwrap() + 9;
    for byte in [0u8, 3, 0x17] {
        let mut bad = preimage.clone();
        bad[at] = byte;
        assert_eq!(Inputs::decode(&bad), Err(E::UnknownClass), "class byte {byte}");
    }
    let mut flipped = preimage.clone();
    flipped[at] = GenesisClass::Production.byte();
    assert_eq!(Inputs::decode(&flipped), Err(E::ManifestClassMismatch));
    let mut typed = inputs.clone();
    typed.parameters.class = GenesisClass::Production;
    assert_eq!(typed.encode(), Err(E::ManifestClassMismatch));
    assert_eq!(typed.identity(), Err(E::ManifestClassMismatch));
}

/// Class changed after construction: (a) the committed parameters record swapped for a Production-class
/// one leaves no StateRoot (the policy's fingerprint no longer matches; with the policy also swapped,
/// the Production backstop refuses the TEST-VALUE member binding); (b) an artifact claiming such records
/// is refused; (c) changing the class in the inputs is a different identity, and refused for Production.
#[test]
fn class_changed_after_construction_is_refused_everywhere() {
    let g = enroll(&test_value_inputs());
    let c = genesis_v2::construct(&g.inputs, &g.enrollment).unwrap();
    let rebuilt = rebuild(production(g.inputs.clone()));
    let production_record = rebuilt.parameters.encode().unwrap();
    let mut state = c.state.clone();
    state.protocol_records.insert(genesis_v2::parameters_key(), production_record.clone());
    assert_eq!(state.admission_class(), Err(Error::WrongFingerprint));
    assert!(state.root().is_err());
    let mut policy = state.admission_policy_v2.as_ref().unwrap().initial().clone();
    policy.fingerprint = rebuilt.parameters.fingerprint().unwrap();
    state.admission_policy_v2 = Some(mutiny_consensus_v8::admission_policy_v2::Record::new(policy).unwrap());
    assert_eq!(state.admission_class(), Ok(AdmissionClass::Production));
    assert!(state.root().is_err(), "Production backstop refuses the TEST-VALUE member binding");
    let mut forged = claimed(&c);
    for (key, value) in forged.records.iter_mut() {
        if *key == genesis_v2::parameters_key() {
            *value = production_record.clone();
        }
    }
    assert_eq!(
        genesis_v2::verify(&g.inputs.encode().unwrap(), &g.enrollment.encode().unwrap(), &approved(&g.inputs), &forged).err(),
        Some(E::RecordsMismatch)
    );
    assert_ne!(
        domain_hash(genesis_v2::IDENTITY_DOMAIN, &rebuilt.encode().unwrap()),
        c.identity
    );
    assert_eq!(rebuilt.identity(), Err(E::TestValueRootInProduction));
    assert_eq!(genesis_v2::construct(&rebuilt, &g.enrollment).err(), Some(E::TestValueRootInProduction));
}

// ---------------------------------------------------------------------------------------------
// NEGATIVE: Production fail-closed root set (A1, A14)
// ---------------------------------------------------------------------------------------------
/// Production class: an empty set, a placeholder root, a labelled TEST-VALUE root, the V1 TEST-VALUE
/// root and a zero root are each refused with their precise reason, and no Genesis is constructed.
#[test]
fn production_class_refuses_empty_placeholder_test_value_and_zero_roots() {
    let g = enroll(&test_value_inputs());
    let base = production(g.inputs.clone());
    // Empty: the set cannot even be encoded.
    let mut empty = base.clone();
    empty.parameters.roots.roots.clear();
    assert_eq!(empty.encode(), Err(E::EmptyRootSet));
    assert_eq!(empty.identity(), Err(E::EmptyRootSet));
    assert_eq!(genesis_v2::construct(&empty, &g.enrollment).err(), Some(E::EmptyRootSet));
    let only = |root: Hash, label: Option<Vec<u8>>| -> Inputs {
        let mut i = base.clone();
        i.parameters.roots.roots.clear();
        i.parameters.roots.roots.insert(
            root,
            EndorsementRoot {
                constraints: tv_constraints(false),
                test_value_label: label,
            },
        );
        i.member.endorsement_root = root;
        rebuild(i)
    };
    for (name, inputs, expected) in [
        ("placeholder 0x11", only([0x11; 32], None), E::PlaceholderRoot),
        ("placeholder 0xff", only([0xff; 32], None), E::PlaceholderRoot),
        ("labelled TEST-VALUE root", only(root(ROOT_A), Some(ROOT_A.as_bytes().to_vec())), E::TestValueRootInProduction),
        ("V1 TEST-VALUE root", only(software_tpm::test_value_endorsement_root(), None), E::TestValueRootInProduction),
        ("the TEST-VALUE pair", rebuild(base.clone()), E::TestValueRootInProduction),
    ] {
        assert_eq!(inputs.validate(), Err(expected), "{name}");
        assert_eq!(inputs.identity(), Err(expected), "{name}");
        assert_eq!(genesis_v2::construct(&inputs, &g.enrollment).err(), Some(expected), "{name}");
    }
    let mut zero_root = base.clone();
    zero_root.parameters.roots.roots.insert(
        [0; 32],
        EndorsementRoot { constraints: tv_constraints(false), test_value_label: None },
    );
    assert_eq!(zero_root.encode(), Err(E::ZeroRoot));
}

/// TestValue class: every root must be a labelled public TEST-VALUE derivation, so a test chain can
/// never commit a hash that could be a real root certificate.
#[test]
fn test_value_class_requires_labelled_test_value_roots() {
    let inputs = test_value_inputs();
    let mut unlabelled = inputs.clone();
    unlabelled.parameters.roots.roots.values_mut().next().unwrap().test_value_label = None;
    assert_eq!(rebuild(unlabelled).validate(), Err(E::UnlabelledRootInTestValue));
    let mut mislabelled = inputs.clone();
    mislabelled.parameters.roots.roots.values_mut().next().unwrap().test_value_label = Some(b"another label".to_vec());
    assert_eq!(rebuild(mislabelled).validate(), Err(E::UnlabelledRootInTestValue));
}

/// Duplicate and unsorted roots are refused at the byte level, alone and inside complete inputs whose
/// manifest commits to exactly those bytes; an unknown set version is refused.
#[test]
fn root_set_order_uniqueness_and_version_are_enforced_on_bytes() {
    let i = test_value_inputs();
    let [(ra, la, wa), (rb, lb, wb)] = test_value_root_entries();
    let (first, second) = if ra < rb { ((ra, la, wa), (rb, lb, wb)) } else { ((rb, lb, wb), (ra, la, wa)) };
    let e = |x: (Hash, &'static str, bool)| RootEntry { root: x.0, constraints: tv_constraints(x.2), label: Some(x.1.as_bytes()) };
    let duplicate = manual_root_set(1, &[e(first), e(first)]);
    let unsorted = manual_root_set(1, &[e(second), e(first)]);
    let unknown = manual_root_set(2, &[e(first), e(second)]);
    assert_eq!(EndorsementRootSet::decode(&duplicate), Err(E::RootOrder));
    assert_eq!(EndorsementRootSet::decode(&unsorted), Err(E::RootOrder));
    assert_eq!(EndorsementRootSet::decode(&unknown), Err(E::UnknownVersion));
    assert_eq!(EndorsementRootSet::decode(&manual_root_set(1, &[])), Err(E::EmptyRootSet));
    assert_eq!(Inputs::decode(&inputs_with_root_set_bytes(&i, &duplicate)), Err(E::RootOrder));
    assert_eq!(Inputs::decode(&inputs_with_root_set_bytes(&i, &unsorted)), Err(E::RootOrder));
    // Control: the same manual path with the canonical set decodes to the fixture inputs.
    let canonical = manual_root_set(1, &[e(first), e(second)]);
    assert_eq!(Inputs::decode(&inputs_with_root_set_bytes(&i, &canonical)).unwrap(), i);
}

/// The manifest must commit to exactly this root set, class and PCR slot: an entry for another set or
/// slot, a missing entry and the V1 class representation are refused; the verifier refuses an approved
/// manifest that commits to a different set.
#[test]
fn manifest_must_commit_to_exactly_this_root_set_class_and_pcr_slot() {
    let inputs = test_value_inputs();
    let mut other_set = inputs.parameters.roots.clone();
    other_set.roots.extend([entry(ROOT_C, false)]);
    let swap = |name: &[u8], value: Hash| -> Inputs {
        let mut i = inputs.clone();
        for (n, v) in i.parameters.rules.commitments.iter_mut() {
            if n.as_slice() == name {
                *v = value;
            }
        }
        i
    };
    assert_eq!(swap(genesis_v2::ROOT_SET_ENTRY, other_set.commitment().unwrap()).encode(), Err(E::ManifestRootSetMismatch));
    let mut other = profile_of(&TestTpm::new());
    other.digest[0] ^= 1;
    let other_pcr = AcceptedPcrProfiles::new(UPDATE_FROZEN_AT_GENESIS, vec![profile_of(&TestTpm::new()), other]).unwrap();
    assert_eq!(swap(genesis_v2::PCR_SET_ENTRY, other_pcr.commitment()).encode(), Err(E::ManifestPcrSetMismatch));
    let other_classes = IdentityClasses::new(vec![IdentityClass { algorithm: RSA_TAG, size: 2048, template_sha256: label("rsa") }]).unwrap();
    assert_eq!(
        swap(genesis_v2::IDENTITY_CLASSES_ENTRY, genesis_v2::identity_classes_commitment(&other_classes)).encode(),
        Err(E::ManifestIdentityClassesMismatch)
    );
    assert_eq!(swap(genesis_v2::CLASS_ENTRY, GenesisClass::Production.commitment()).encode(), Err(E::ManifestClassMismatch));
    for name in [genesis_v2::CLASS_ENTRY, genesis_v2::ROOT_SET_ENTRY, genesis_v2::PCR_SET_ENTRY, genesis_v2::IDENTITY_CLASSES_ENTRY] {
        let mut missing = inputs.clone();
        missing.parameters.rules.commitments.retain(|(n, _)| n.as_slice() != name);
        assert_eq!(missing.encode(), Err(E::ManifestEntryMissing), "{}", String::from_utf8_lossy(name));
    }
    let mut v1 = inputs.clone();
    v1.parameters.rules.commitments.push((provenance::TRUST_ROOTS_COMMITMENT.to_vec(), provenance::trust_roots_commitment(&inputs.parameters.roots.hashes()).unwrap()));
    v1.parameters.rules.commitments.sort();
    assert_eq!(v1.encode(), Err(E::V1TrustRootsEntry));
    // The verifier: the approved manifest commits to another set.
    let g = enroll(&inputs);
    let c = genesis_v2::construct(&g.inputs, &g.enrollment).unwrap();
    let mut foreign = approved(&inputs);
    for (n, v) in foreign.manifest.commitments.iter_mut() {
        if n.as_slice() == genesis_v2::ROOT_SET_ENTRY {
            *v = other_set.commitment().unwrap();
        }
    }
    assert_eq!(
        genesis_v2::verify(&inputs.encode().unwrap(), &g.enrollment.encode().unwrap(), &foreign, &claimed(&c)).err(),
        Some(E::ManifestMismatch)
    );
}

/// A second root outside the frozen set (Order A2 "freeze the permitted root universe before Genesis")
/// is refused at Genesis (the member's root), in committed state (policy roots must equal the frozen
/// set) and at a later V2 JOIN; a JOIN naming the OTHER root of the set is accepted (a set, not a slot),
/// and the refused JOIN leaves the state byte-identical.
#[test]
fn a_second_root_outside_the_frozen_set_is_refused_at_genesis_in_state_and_at_join() {
    let mut outside = test_value_inputs();
    outside.member.endorsement_root = root(ROOT_C);
    assert_eq!(outside.validate(), Err(E::MemberRootNotInSet));
    let g = enroll(&test_value_inputs());
    let c = genesis_v2::construct(&g.inputs, &g.enrollment).unwrap();
    let mut widened = c.state.clone();
    let mut policy = widened.admission_policy_v2.as_ref().unwrap().initial().clone();
    policy.endorsement_roots.insert(root(ROOT_C));
    widened.admission_policy_v2 = Some(mutiny_consensus_v8::admission_policy_v2::Record::new(policy).unwrap());
    assert_eq!(widened.admission_class(), Err(Error::UnqualifiedPhysical));
    assert!(widened.root().is_err());
    let before = c.records().unwrap();
    let anchor = c.anchor();
    let join = |endorsement_root: Hash| -> mutiny_consensus_v8::join_v2::Join {
        let tpm = TestTpm::with_identity("genesis-v2-second-root-join");
        let continuity = HybridKey::generate(Role::Continuity).unwrap();
        let node = HybridKey::generate(Role::Node).unwrap();
        let node_descriptor = node.public().descriptor(1).unwrap();
        let owner = owner_key();
        let mut join = mutiny_consensus_v8::join_v2::Join {
            parent: anchor.clone(),
            nonce: label("join-nonce"),
            binding: Binding {
                node_signer: None,
                node_descriptor: node_descriptor.clone(),
                possession: zero(),
                admission: Admission {
                    genesis: c.identity,
                    fingerprint: c.fingerprint,
                    node: node_id(c.identity, &node_descriptor).unwrap(),
                    hardware_generation: 1,
                    key_generation: 1,
                    continuity_descriptor: continuity.public().descriptor(1).unwrap(),
                    profile: tpm.profile().encode().unwrap(),
                    endorsement_root,
                    owner: owner.public().address_id(1).unwrap(),
                    supervised_nonce: [5; 32],
                    quote: vec![],
                    possession: zero(),
                    authorization: zero(),
                },
            },
        };
        join.binding.admission.supervised_nonce = join.admission_nonce().unwrap();
        join.binding.admission.prove_continuity(&continuity).unwrap();
        join.binding.admission.quote = tpm.quote(join.binding.admission.challenge().unwrap());
        join.binding.admission.authorize(&owner, 1).unwrap();
        join.binding.sign(&node).unwrap();
        join
    };
    join(root(ROOT_B)).verify(&c.state, &anchor, c.root).unwrap();
    assert_eq!(join(root(ROOT_C)).verify(&c.state, &anchor, c.root).err(), Some(Error::UnqualifiedPhysical));
    assert_eq!(c.records().unwrap(), before, "a refused JOIN changes nothing");
}

// ---------------------------------------------------------------------------------------------
// NEGATIVE: other input rules, codecs and the verifier
// ---------------------------------------------------------------------------------------------
/// Treasury class, roles (Order A8: Treasury custody is not admission authority), descriptor roles and
/// generations, and zero fields.
#[test]
fn treasury_role_descriptor_and_zero_field_rules() {
    let inputs = test_value_inputs();
    let mut production_treasury = inputs.clone();
    production_treasury.treasury = Treasury::new(Class::Production, treasury_key().public().descriptor(1).unwrap()).unwrap();
    assert_eq!(production_treasury.validate(), Err(E::TreasuryClassMismatch));
    let mut owner_treasury = inputs.clone();
    owner_treasury.treasury = Treasury::new(Class::TestValue, inputs.admission_owner.clone()).unwrap();
    assert_eq!(owner_treasury.validate(), Err(E::TreasuryIsAdmissionOwner));
    // The owner's own key halves relabelled as a WalletRecovery descriptor: a role alias.
    let (owner_public, _) = mutiny_crypto_v2::PublicKey::decode_descriptor(&inputs.admission_owner).unwrap();
    let alias = mutiny_crypto_v2::PublicKey { role: Role::WalletRecovery, ..owner_public }.descriptor(1).unwrap();
    let mut aliased = inputs.clone();
    aliased.recovery = alias;
    assert_eq!(aliased.validate(), Err(E::RoleAlias));
    let mut wrong_role = inputs.clone();
    wrong_role.admission_owner = inputs.recovery.clone();
    assert_eq!(wrong_role.validate(), Err(E::BadDescriptor));
    let mut wrong_generation = inputs.clone();
    wrong_generation.admission_owner = owner_key().public().descriptor(2).unwrap();
    assert_eq!(wrong_generation.validate(), Err(E::BadDescriptor));
    // The Bootstrap Licenses belong to the admission owner (as V1 derives its descriptor owner).
    assert_eq!(inputs.license_owner(), Ok(owner_key().public().address_id(1).unwrap()));
    type Edit = (&'static str, fn(&mut Inputs));
    let edits: [Edit; 4] = [
        ("timestamp", |i| i.timestamp = 0),
        ("nonce", |i| i.nonce = [0; 32]),
        ("purchase", |i| i.purchase = [0; 32]),
        ("target", |i| i.parameters.initial_target = [0; 32]),
    ];
    for (name, edit) in edits {
        let mut i = inputs.clone();
        edit(&mut i);
        assert_eq!(i.validate(), Err(E::ZeroField), "{name}");
    }
    let mut bad_profile = inputs.clone();
    bad_profile.member.profile.pop();
    assert_eq!(bad_profile.validate(), Err(E::BadMemberProfile));
}

/// Unknown versions, a wrong network, wrong tags and trailing bytes are refused in every codec.
#[test]
fn unknown_versions_wrong_network_and_trailing_bytes_are_refused() {
    let i = test_value_inputs();
    let p = &i.parameters;
    let (rules, roots, pcr, cls) = (p.rules.encode().unwrap(), p.roots.encode().unwrap(), p.pcr_profiles.encode(), p.identity_classes.encode());
    let member = manual_member(2, i.member.endorsement_root, &i.member.profile);
    let good = manual_parameters(2, 64, NETWORK_ID, 2, p.initial_target, &rules, &roots, &pcr, &cls);
    for (name, parameters, expected) in [
        ("parameters version", manual_parameters(3, 64, NETWORK_ID, 2, p.initial_target, &rules, &roots, &pcr, &cls), E::UnknownVersion),
        ("parameters tag", manual_parameters(2, 65, NETWORK_ID, 2, p.initial_target, &rules, &roots, &pcr, &cls), E::UnknownVersion),
        ("parameters network", manual_parameters(2, 64, NETWORK_ID + 1, 2, p.initial_target, &rules, &roots, &pcr, &cls), E::WrongNetwork),
        ("pcr version", manual_parameters(2, 64, NETWORK_ID, 2, p.initial_target, &rules, &roots, &{ let mut b = pcr.clone(); b[1] = 2; b }, &cls), E::PcrSet(PcrFailure::Codec)),
        ("class list version", manual_parameters(2, 64, NETWORK_ID, 2, p.initial_target, &rules, &roots, &pcr, &{ let mut b = cls.clone(); b[1] = 2; b }), E::IdentityClasses),
    ] {
        assert_eq!(Parameters::decode(&parameters), Err(expected), "{name}");
        assert_eq!(Inputs::decode(&manual_inputs(2, &i, &parameters, &member)), Err(expected), "{name} in inputs");
    }
    assert_eq!(Inputs::decode(&manual_inputs(3, &i, &good, &member)), Err(E::UnknownVersion));
    assert_eq!(Inputs::decode(&manual_inputs(2, &i, &good, &manual_member(3, i.member.endorsement_root, &i.member.profile))), Err(E::UnknownVersion));
    for (name, mut raw) in [("inputs", i.encode().unwrap()), ("parameters", good.clone()), ("roots", roots.clone()), ("pcr", pcr.clone())] {
        raw.push(0);
        let result = match name {
            "inputs" => Inputs::decode(&raw).err(),
            "parameters" => Parameters::decode(&raw).err(),
            "roots" => EndorsementRootSet::decode(&raw).err(),
            _ => AcceptedPcrProfiles::decode(&raw).err().map(E::PcrSet),
        };
        let expected = if name == "pcr" { E::PcrSet(PcrFailure::Codec) } else { E::NonCanonical };
        assert_eq!(result, Some(expected), "{name} trailing byte");
    }
    let g = enroll(&i);
    let mut enrollment = g.enrollment.encode().unwrap();
    assert_eq!(enrollment[1], 2);
    let mut unknown = enrollment.clone();
    unknown[1] = 3;
    assert_eq!(Enrollment::decode(&unknown), Err(E::UnknownVersion));
    enrollment.push(0);
    assert_eq!(Enrollment::decode(&enrollment), Err(E::NonCanonical));
    // V1 bytes are never read as V2.
    let v1 = mutiny_consensus_v8::genesis_inputs::Parameters { initial_target: [255; 32], rules: p.rules.clone(), treasury: None };
    assert_eq!(Parameters::decode(&v1.encode().unwrap()).err(), Some(E::Codec));
}

/// Each input field flips the identity: every one-field variant has a distinct identity preimage hash
/// (and, where the variant is valid, a distinct `identity()`).
#[test]
fn every_input_field_flips_the_identity() {
    let base = test_value_inputs();
    let other_tpm = TestTpm::with_identity("genesis-v2-identity-variant");
    let mut variants: Vec<(&str, Inputs)> = vec![("base", base.clone())];
    let mut push = |name: &'static str, edit: &dyn Fn(&mut Inputs), recommit: bool| {
        let mut i = base.clone();
        edit(&mut i);
        variants.push((name, if recommit { rebuild(i) } else { i }));
    };
    push("timestamp", &|i| i.timestamp += 1, false);
    push("nonce", &|i| i.nonce[31] ^= 1, false);
    push("class", &|i| *i = production(i.clone()), true);
    push("initial target", &|i| i.parameters.initial_target[0] = 0x7f, false);
    push("manifest rule", &|i| i.parameters.rules.commitments.push((b"zz-test-value-extra-rule".to_vec(), [9; 32])), false);
    push("root added", &|i| { i.parameters.roots.roots.extend([entry(ROOT_C, false)]); }, true);
    push("root constraint", &|i| i.parameters.roots.roots.get_mut(&root(ROOT_B)).unwrap().constraints.max_intermediates = 2, true);
    push("root revocation mode", &|i| i.parameters.roots.roots.get_mut(&root(ROOT_B)).unwrap().constraints.revocation = RevocationMode::CrlRequired, true);
    push("pcr profile", &|i| { let mut q = profile_of(&TestTpm::new()); q.digest = label("pcr"); i.parameters.pcr_profiles = AcceptedPcrProfiles::new(UPDATE_FROZEN_AT_GENESIS, vec![profile_of(&TestTpm::new()), q]).unwrap(); }, true);
    push("identity classes", &|i| i.parameters.identity_classes = IdentityClasses::new(vec![IdentityClass { algorithm: ECC_TAG, size: TPM_ECC_NIST_P256, template_sha256: label("other-template") }]).unwrap(), true);
    push("admission owner", &|i| i.admission_owner = HybridKey::wallet_restore("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title", Role::WalletOwner).unwrap().public().descriptor(1).unwrap(), false);
    push("member root", &|i| i.member.endorsement_root = root(ROOT_B), false);
    push("member profile", &|i| i.member.profile = other_tpm.profile().encode().unwrap(), false);
    push("recovery", &|i| i.recovery = HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletRecovery).unwrap().public().descriptor(1).unwrap(), false);
    push("treasury", &|i| i.treasury = Treasury::new(Class::Production, i.treasury.descriptor().to_vec()).unwrap(), false);
    push("purchase", &|i| i.purchase[0] ^= 1, false);
    let mut seen = BTreeSet::new();
    for (name, v) in &variants {
        let preimage = v.encode().unwrap_or_else(|e| panic!("{name}: {e:?}"));
        assert!(seen.insert(domain_hash(genesis_v2::IDENTITY_DOMAIN, &preimage)), "{name} did not change the identity");
    }
    assert_eq!(seen.len(), 17);
    // The variants that remain valid inputs also have distinct identity() values.
    let valid: BTreeSet<Hash> = variants.iter().filter_map(|(_, v)| v.identity().ok()).collect();
    assert!(valid.len() >= 10, "{}", valid.len());
}

/// Verifier negatives: wrong expected class (a Production verifier), manifest and target; tampered
/// claims; tampered enrollment (signature, nonce, member binding contents, counts).
#[test]
fn verifier_refuses_foreign_trust_tampered_claims_and_tampered_enrollment() {
    let g = enroll(&test_value_inputs());
    let c = genesis_v2::construct(&g.inputs, &g.enrollment).unwrap();
    let inputs = g.inputs.encode().unwrap();
    let enrollment = g.enrollment.encode().unwrap();
    let good = approved(&g.inputs);
    let check = |trust: &Approved, claim: &Claimed, enrollment: &[u8]| genesis_v2::verify(&inputs, enrollment, trust, claim).err();
    assert_eq!(check(&good, &claimed(&c), &enrollment), None);
    let mut production_verifier = good.clone();
    production_verifier.class = GenesisClass::Production;
    assert_eq!(check(&production_verifier, &claimed(&c), &enrollment), Some(E::ClassMismatch));
    let mut other_manifest = good.clone();
    other_manifest.manifest.commitments.push((b"zz-other-rule".to_vec(), [7; 32]));
    assert_eq!(check(&other_manifest, &claimed(&c), &enrollment), Some(E::ManifestMismatch));
    let mut other_target = good.clone();
    other_target.initial_target[0] = 0x0f;
    assert_eq!(check(&other_target, &claimed(&c), &enrollment), Some(E::TargetMismatch));
    let mut claim = claimed(&c);
    claim.genesis_id[0] ^= 1;
    assert_eq!(check(&good, &claim, &enrollment), Some(E::IdentityMismatch));
    let mut claim = claimed(&c);
    claim.records[0].1.push(0);
    assert_eq!(check(&good, &claim, &enrollment), Some(E::RecordsMismatch));
    let mut claim = claimed(&c);
    claim.records.pop();
    assert_eq!(check(&good, &claim, &enrollment), Some(E::RecordsMismatch));
    let mut claim = claimed(&c);
    claim.state_root[0] ^= 1;
    assert_eq!(check(&good, &claim, &enrollment), Some(E::StateRootMismatch));
    let mut claim = claimed(&c);
    claim.block_hash[0] ^= 1;
    assert_eq!(check(&good, &claim, &enrollment), Some(E::BlockMismatch));
    // Enrollment tampering.
    let mut signature = g.enrollment.clone();
    signature.assignments[3].enrollment.owner_signature.ed448[0] ^= 1;
    assert_eq!(check(&good, &claimed(&c), &signature.encode().unwrap()), Some(E::Consensus(Error::BadSignature)));
    let mut possession = g.enrollment.clone();
    possession.member_binding.possession.ed448[0] ^= 1;
    assert_eq!(check(&good, &claimed(&c), &possession.encode().unwrap()), Some(E::Consensus(Error::BadSignature)));
    let mut nonce = g.enrollment.clone();
    nonce.supervised_nonce[0] ^= 1;
    assert_eq!(check(&good, &claimed(&c), &nonce.encode().unwrap()), Some(E::Consensus(Error::WrongAnchor)));
    let mut other_root = g.enrollment.clone();
    other_root.member_binding.admission.endorsement_root = root(ROOT_B);
    assert_eq!(genesis_v2::construct(&g.inputs, &other_root).err(), Some(E::MemberBindingMismatch));
    let mut other_profile = g.enrollment.clone();
    other_profile.member_binding.admission.profile = TestTpm::with_identity("genesis-v2-other-profile").profile().encode().unwrap();
    assert_eq!(genesis_v2::construct(&g.inputs, &other_profile).err(), Some(E::MemberBindingMismatch));
    let mut eleven = g.enrollment.clone();
    eleven.assignments.pop();
    assert_eq!(eleven.encode(), Err(E::EnrollmentCount));
    let mut zero_nonce = g.enrollment.clone();
    zero_nonce.supervised_nonce = [0; 32];
    assert_eq!(zero_nonce.encode(), Err(E::ZeroField));
}

/// A refused construction produces no state: the same enrollment against inputs of another Genesis
/// (one input byte changed) is refused, because every enrollment element signs the frozen GenesisID.
#[test]
fn enrollment_signed_for_one_identity_never_constructs_another() {
    let g = enroll(&test_value_inputs());
    let mut other = g.inputs.clone();
    other.purchase[0] ^= 1;
    assert_eq!(genesis_v2::construct(&other, &g.enrollment).err(), Some(E::Consensus(Error::WrongAnchor)));
}

// ---------------------------------------------------------------------------------------------
// Class independence from local configuration (A10)
// ---------------------------------------------------------------------------------------------
const CHILD: &str = "BUILD8_GENESIS_V2_ENVIRONMENT_CHILD";
/// The same input bytes give the same identity and class in a child process whose environment names a
/// Production class in several plausible spellings. (Shipped code reads no environment at all:
/// `host_independence_guard.rs` and `genesis_v2_sources_read_no_environment_feature_or_profile`.)
#[test]
fn class_and_identity_ignore_the_process_environment() {
    let inputs = test_value_inputs();
    let line = format!(
        "GENESIS-V2 identity={} class={}",
        hex::encode(inputs.identity().unwrap()),
        inputs.class().byte()
    );
    if std::env::var_os(CHILD).is_some() {
        println!("{line}");
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["class_and_identity_ignore_the_process_environment", "--exact", "--nocapture", "--test-threads", "1"])
        .env(CHILD, "1")
        .env("MUTINY_GENESIS_CLASS", "Production")
        .env("BUILD8_GENESIS_CLASS", "1")
        .env("GENESIS_PROFILE", "production")
        .env("MUTINY_PRODUCTION", "1")
        .env("MUTINYD_PHYSICAL_PROFILE_COMMITMENT", "00".repeat(32))
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    // libtest prints "test <name> ... " on the same line before the test's own output.
    assert!(stdout.contains(&line), "child printed: {stdout}");
    assert!(line.ends_with("class=2"));
}

/// The shipped parts of the V2 Genesis sources contain no environment read, no Cargo-feature or
/// build-profile conditional and no compile-time environment: nothing local can select the class.
#[test]
fn genesis_v2_sources_read_no_environment_feature_or_profile() {
    for path in [
        "src/genesis_v2.rs",
        "../node/src/genesis_artifact_v2.rs",
        "../node/src/genesis_ceremony_v2.rs",
    ] {
        let text = std::fs::read_to_string(path).unwrap();
        let shipped = text.split("#[cfg(test)]").next().unwrap();
        for forbidden in ["std::env", "env!(", "option_env!", "cfg!(", "cfg(feature", "debug_assertions", "var_os", "getenv"] {
            assert!(!shipped.contains(forbidden), "{path} contains {forbidden}");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The committed TEST-VALUE fixture (consumed by the node's artifact and ceremony tests)
// ---------------------------------------------------------------------------------------------
fn fixture_json(g: &Genesis, c: &Constructed) -> serde_json::Value {
    serde_json::json!({
        "schema": FIXTURE_SCHEMA,
        "TEST_VALUE": true,
        "physical_tpm": false,
        "production_eligible": false,
        "actual_genesis": false,
        "sealed": false,
        "warning": "SOFTWARE SIMULATOR TEST VALUE. Not a Production Genesis, not a real endorsement root, not physical evidence.",
        "provenance": {
            "generator": "consensus/tests/genesis_v2.rs",
            "kind": "TEST-VALUE V2 Genesis inputs (deterministic: public mnemonics, labelled TEST-VALUE roots and constraints, TEST-VALUE simulator TPM) and enrollment (fresh random Node/Continuity keys, randomized hybrid signatures)",
            "regenerate": "BUILD8_EXPORT_GENESIS_V2_TEST_VALUE=<new file path> cargo test --offline --locked --test genesis_v2 export_test_value_fixture_when_requested",
            "real_host_evidence": "none"
        },
        "class": g.inputs.class().byte(),
        "inputs": hex::encode(g.inputs.encode().unwrap()),
        "enrollment": hex::encode(g.enrollment.encode().unwrap()),
        "approved_manifest": hex::encode(g.inputs.parameters.rules.encode().unwrap()),
        "initial_target": hex::encode(g.inputs.parameters.initial_target),
        "genesis_id": hex::encode(c.identity),
        "fingerprint": hex::encode(c.fingerprint),
        "state_root": hex::encode(c.root),
        "genesis_block_hash": hex::encode(c.block_hash),
    })
}
/// Writes a NEW fixture file only when explicitly requested (never overwrites).
#[test]
fn export_test_value_fixture_when_requested() {
    let Some(path) = std::env::var_os("BUILD8_EXPORT_GENESIS_V2_TEST_VALUE") else {
        return;
    };
    let g = enroll(&test_value_inputs());
    let c = genesis_v2::construct(&g.inputs, &g.enrollment).unwrap();
    let mut text = serde_json::to_string_pretty(&fixture_json(&g, &c)).unwrap();
    text.push('\n');
    use std::io::Write;
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .unwrap()
        .write_all(text.as_bytes())
        .unwrap();
}
/// The committed fixture: its inputs are exactly the deterministic builder's bytes; the whole Genesis
/// reconstructs from it and reproduces its recorded identity, fingerprint, root and block hash; its
/// labels say TEST-VALUE.
#[test]
fn committed_test_value_fixture_reconstructs_and_matches_the_builder() {
    let f: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(FIXTURE_FILE).unwrap()).unwrap();
    assert_eq!(f["schema"], FIXTURE_SCHEMA);
    assert_eq!((f["TEST_VALUE"].as_bool(), f["production_eligible"].as_bool(), f["actual_genesis"].as_bool()), (Some(true), Some(false), Some(false)));
    let raw = |k: &str| hex::decode(f[k].as_str().unwrap()).unwrap();
    assert_eq!(raw("inputs"), test_value_inputs().encode().unwrap(), "fixture inputs drifted from the builder");
    let inputs = Inputs::decode(&raw("inputs")).unwrap();
    let enrollment = Enrollment::decode(&raw("enrollment")).unwrap();
    let c = genesis_v2::construct(&inputs, &enrollment).unwrap();
    assert_eq!(c.identity.to_vec(), raw("genesis_id"));
    assert_eq!(c.fingerprint.to_vec(), raw("fingerprint"));
    assert_eq!(c.root.to_vec(), raw("state_root"));
    assert_eq!(c.block_hash.to_vec(), raw("genesis_block_hash"));
    assert_eq!(raw("approved_manifest"), inputs.parameters.rules.encode().unwrap());
    assert_eq!(f["class"], 2);
}

// ---------------------------------------------------------------------------------------------
// REAL BLOCK: the constructed Genesis is a live V2 chain start
// ---------------------------------------------------------------------------------------------
fn certify(
    g: &Genesis,
    c: &Constructed,
    prepared: mutiny_consensus_v8::assembler_v2::Prepared,
    parent: &mutiny_consensus_v8::anchors::FinalizedAnchor,
) -> mutiny_consensus_v8::block_envelope_v2::BlockEnvelope {
    use mutiny_consensus_v8::{
        block_envelope_v2::BlockEnvelope,
        certificates::Decision,
        continuity_v2::{Certificate, Vote},
        pow::{WorkAuthority, WorkHeader, mining_epoch},
        votes_v2::HeightAuthority,
        work_authority_v2::Authority,
    };
    let height = prepared.candidate.height;
    let epoch = mining_epoch(prepared.candidate.timestamp, c.t0).unwrap();
    let node_descriptor = g.node.public().descriptor(1).unwrap();
    let mut authority = Authority {
        work: WorkAuthority {
            candidate: prepared.candidate.clone(),
            assignment_sequence: 1,
            ticket_sequence: 1,
            coordinator: node_identity(&node_descriptor).unwrap(),
            nonce_start: 0,
            nonce_end: 100,
            epoch,
        },
        node_descriptor,
        signature: zero(),
    };
    authority.sign(&g.node).unwrap();
    let header = WorkHeader { candidate: prepared.candidate, authority: authority.id().unwrap(), nonce: 1 };
    let parent_authority = HeightAuthority::from_state(&c.state, parent.clone(), c.root).unwrap();
    let (node, voter) = parent_authority.voters.iter().next().unwrap();
    let decision = Decision {
        network: NETWORK_ID,
        genesis: c.identity,
        fingerprint: c.fingerprint,
        purpose: 2,
        height,
        mining_epoch: epoch,
        continuity_period: (height - 1) / 60,
        round: 0,
        step: 3,
        previous_finalized_anchor: parent.id(),
        parent: parent.block,
        block: header.block_hash(),
        state: prepared.execution.root,
        membership: parent_authority.membership,
        reputation: parent_authority.reputation,
        attestation: parent_authority.attestation,
    };
    let mut vote = Vote {
        decision: decision.clone(),
        nil: false,
        node: *node,
        hardware_generation: voter.hardware_generation,
        key_generation: voter.key_generation,
        sequence: height * 10,
        tpm_identity: voter.tpm_identity(),
        profile: voter.profile,
        signature: zero(),
    };
    vote.sign(&g.continuity).unwrap();
    BlockEnvelope { header, body: prepared.body, authority, certificate: Certificate { decision, votes: vec![vote] } }
}
/// The constructed TEST-VALUE Genesis opens the V2 canonical store as its trusted Genesis; block 1 is
/// assembled by the production assembler, certified by the Genesis member's hybrid vote and committed by
/// the store, which re-executes it. A block whose certificate commits to another post-state is
/// rejected and leaves the Genesis records byte-identical.
#[test]
fn constructed_genesis_opens_the_v2_store_and_finalizes_a_real_block() {
    use mutiny_consensus_v8::{
        canonical_store_v2::{CanonicalStore, Preparation},
        mempool_v2::Mempool,
    };
    let g = enroll(&test_value_inputs());
    let c = genesis_v2::construct(&g.inputs, &g.enrollment).unwrap();
    let anchor = c.anchor();
    let genesis_records = c.records().unwrap();
    let dir = test_dir::TestDir::new("genesis-v2-store");
    let mut chain = CanonicalStore::open_trusted_genesis(&dir.file("chain.sqlite"), &anchor, &c.state, c.root, c.t0, c.target).unwrap();
    let mut pool = Mempool::open(&dir.file("pool.sqlite"), anchor.genesis, anchor.fingerprint, 64 * 1024 * 1024).unwrap();
    chain.reconcile_pool(&mut pool).unwrap();
    let prepared = chain
        .prepare_pending(Preparation {
            expected_parent: &anchor,
            pool: &pool,
            license: genesis_license(c.identity, 0).unwrap(),
            worker: g.enrollment.supervised[0].worker_id,
            timestamp: c.t0 + 65,
            ticket: 1,
            operations: &[],
        })
        .unwrap();
    let post_root = prepared.execution.root;
    let good = certify(&g, &c, prepared, &anchor);
    let mut bad = good.clone();
    bad.certificate.decision.state[0] ^= 1;
    bad.certificate.votes[0].decision.state[0] ^= 1;
    assert!(chain.commit(&bad).is_err(), "a certificate over another post-state is rejected");
    let (head, unchanged) = chain.load().unwrap();
    assert_eq!(head.height, 0);
    assert_eq!(unchanged.records().unwrap(), genesis_records, "rejection leaves Genesis byte-identical");
    assert!(chain.commit(&good).unwrap());
    let (head, state) = chain.load().unwrap();
    assert_eq!((head.height, head.root), (1, post_root));
    assert_eq!(state.admission_class().unwrap(), AdmissionClass::LegacyTest);
    assert_eq!(state.protocol_records[&genesis_v2::parameters_key()], g.inputs.parameters.encode().unwrap());
    drop(pool);
    drop(chain);
}

// ---------------------------------------------------------------------------------------------
// Domain registry (PROPOSED/unfrozen entries)
// ---------------------------------------------------------------------------------------------
#[test]
fn genesis_v2_domains_are_registered_as_proposed_and_unfrozen() {
    let registry: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("../spec/DOMAIN-REGISTRY-V1.json").unwrap()).unwrap();
    let listed = registry["domains"].as_array().unwrap();
    for domain in [
        genesis_v2::IDENTITY_DOMAIN,
        genesis_v2::BLOCK_DOMAIN,
        genesis_v2::PARAMETERS_KEY_DOMAIN,
        genesis_v2::CLASS_DOMAIN,
        genesis_v2::ROOT_SET_DOMAIN,
        genesis_v2::TEST_VALUE_ROOT_DOMAIN,
    ] {
        let ascii = std::str::from_utf8(domain).unwrap();
        let entries: Vec<_> = listed.iter().filter(|e| e["ascii"] == ascii).collect();
        assert_eq!(entries.len(), 1, "{ascii} registered exactly once");
        assert_eq!(entries[0]["status"], "PROPOSED-UNFROZEN", "{ascii}");
    }
    let body = |ascii: &[u8]| -> String {
        listed.iter().find(|e| e["ascii"] == std::str::from_utf8(ascii).unwrap()).unwrap()["body"].as_str().unwrap().to_string()
    };
    assert!(body(genesis_v2::CLASS_DOMAIN).contains("genesis-class-v2"));
    assert!(body(genesis_v2::ROOT_SET_DOMAIN).contains("endorsement-root-set-v2"));
    let parameters_entry = listed.iter().find(|e| e["ascii"] == "MUTINY-BUILD8-GENESIS-PARAMETERS-KEY-V2").unwrap()["purpose"].as_str().unwrap().to_string();
    assert!(parameters_entry.contains("accepted-pcr-profile-set-v1") && parameters_entry.contains("endorsement-identity-classes-v1"));
    assert!(listed.iter().all(|e| e["ascii"] != "MUTINY-BUILD8-PCR-PROFILE-SET-V1"), "the PCR set has one definition (Lane A2)");
}

// ---------------------------------------------------------------------------------------------
// Independent review fixes (candidate 3): F1, F2, F4, F8
// ---------------------------------------------------------------------------------------------
/// Inputs of a Production-class Genesis whose single root is INVENTED (an unlabelled random-looking hash) and whose
/// member is the stripped simulator with a self-consistent provenance statement naming that root (T14 material).
fn invented_production(seed: &[u8]) -> (Inputs, TestTpm) {
    use software_tpm::Strip;
    let invented = domain_hash(b"MUTINY-BUILD8-TEST-VALUE-INVENTED-NOT-A-ROOT", seed);
    let tpm = TestTpm::stripped(Strip::ConsistentProvenance(invented));
    let mut i = production(test_value_inputs());
    i.parameters.roots = EndorsementRootSet {
        roots: [(invented, EndorsementRoot { constraints: tv_constraints(false), test_value_label: None })].into(),
    };
    i.parameters.pcr_profiles = pcr(&tpm);
    i.member = MemberInput { endorsement_root: invented, profile: tpm.profile().encode().unwrap() };
    (rebuild(i), tpm)
}

/// F1, DOCUMENTED LIMIT (the Order's section 4 warning: this is NOT a closed bypass). Any party can CONSTRUCT a
/// Production-class V2 Genesis from an invented, unlabelled, random-looking root and authority-signed software
/// provenance (T14 material): `construct` cannot know whether a root hash names an authentic manufacturer certificate,
/// and `verify` accepts it against a trust built from the same self-made manifest. What refuses it is the independently
/// approved manifest: the binary-supported trust (the V9 candidate manifest, class Production) refuses it, and so does
/// any approved manifest that does not commit to exactly these roots. Only an Architect-supplied manifest derived from
/// authentic manufacturer material can make a Production Genesis acceptable.
#[test]
fn production_genesis_from_an_invented_root_constructs_and_only_the_approved_manifest_refuses_it() {
    let (i, tpm) = invented_production(b"random-looking root");
    i.validate().unwrap();
    let g = enroll_with(&i, &tpm);
    let c = genesis_v2::construct(&g.inputs, &g.enrollment).unwrap();
    assert_eq!(c.class, GenesisClass::Production);
    assert_eq!(c.state.admission_class().unwrap(), AdmissionClass::Production);
    let inputs = i.encode().unwrap();
    let enrollment = g.enrollment.encode().unwrap();
    let self_approved = approved(&i);
    genesis_v2::verify(&inputs, &enrollment, &self_approved, &claimed(&c)).unwrap();
    let v9: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string("../qualification/PROTOCOL-FINGERPRINT-CANDIDATE-V9.json").unwrap(),
    )
    .unwrap();
    let supported = Approved {
        manifest: RuleManifest::decode(&hex::decode(v9["manifest_hex"].as_str().unwrap()).unwrap()).unwrap(),
        class: GenesisClass::Production,
        initial_target: i.parameters.initial_target,
    };
    assert_eq!(genesis_v2::verify(&inputs, &enrollment, &supported, &claimed(&c)).err(), Some(E::ManifestMismatch));
    let mut other = self_approved.clone();
    for (n, v) in other.manifest.commitments.iter_mut() {
        if n.as_slice() == genesis_v2::ROOT_SET_ENTRY {
            *v = test_roots().commitment().unwrap();
        }
    }
    assert_eq!(genesis_v2::verify(&inputs, &enrollment, &other, &claimed(&c)).err(), Some(E::ManifestMismatch));
}

/// F2: what Genesis commits is exactly what the validators consume. The committed root set decodes to the
/// `ek_chain::TrustAnchor`s with which a TEST-VALUE X.509 chain verifies in the Production class (and fails once a
/// committed constraint is narrowed); the committed PCR set is A2's `AcceptedPcrProfiles`, whose `check_accepted`
/// admits the member's profile; the committed identity-class list is A2's `IdentityClasses`.
#[test]
fn genesis_commits_exactly_the_structures_the_chain_pcr_and_identity_checks_consume() {
    use mutiny_consensus_v8::ek_chain::{ChainContext, ChainFailure, validate_endorsement_chain};
    let pki = test_value_x509::X509Pki::new("genesis-v2-committed-anchor");
    let ek = test_value_x509::CaKey::P256(test_value_x509::p256_key("genesis-v2-leaf")).public();
    let chain = pki.chain(&ek, &[0x31]);
    let crls = pki.crls(&[], &[]);
    let anchor = pki.anchor(
        RevocationMode::CrlRequired,
        &[test_value_ek::ECC_CLASS, test_value_ek::RSA_CLASS],
        &[SignatureAlgorithm::EcdsaP256Sha256, SignatureAlgorithm::EcdsaP384Sha384],
    );
    let set = EndorsementRootSet {
        roots: [(anchor.root_cert_der_sha256, EndorsementRoot { constraints: anchor.constraints.clone(), test_value_label: None })]
            .into(),
    };
    let committed = EndorsementRootSet::decode(&set.encode().unwrap()).unwrap().anchors();
    assert_eq!(committed, vec![anchor.clone()]);
    let check = |anchors: &[mutiny_consensus_v8::ek_chain::TrustAnchor]| {
        validate_endorsement_chain(
            &x509_syntax::X509Syntax,
            &chain,
            &crls,
            &ChainContext { class: AdmissionClass::Production, reference_time: test_value_x509::T_REF, anchors },
        )
    };
    assert_eq!(check(&committed).unwrap().anchor, anchor.root_cert_der_sha256);
    let mut narrowed = set.clone();
    narrowed.roots.values_mut().next().unwrap().constraints.ek_classes = [test_value_ek::RSA_CLASS].into();
    let narrowed = EndorsementRootSet::decode(&narrowed.encode().unwrap()).unwrap().anchors();
    assert_eq!(check(&narrowed).err(), Some(ChainFailure::ClassNotAllowed));
    let g = enroll(&test_value_inputs());
    let c = genesis_v2::construct(&g.inputs, &g.enrollment).unwrap();
    let record = Parameters::decode(&c.state.protocol_records[&genesis_v2::parameters_key()]).unwrap();
    let member = TestTpm::new();
    assert_eq!(
        record.pcr_profiles.check_accepted(member.profile().pcr_bitmap, member.profile().pcr_digest),
        Ok(provenance::platform_profile(member.profile().pcr_bitmap, member.profile().pcr_digest))
    );
    assert_eq!(record.pcr_profiles.check_accepted([1, 0, 0], [7; 32]), Err(PcrFailure::NotAccepted));
    assert_eq!(record.identity_classes, classes());
    assert_eq!(record.roots.anchors(), g.inputs.parameters.roots.anchors());
}

/// All keys/certificates/activation labels are PUBLIC software fixtures. This proves
/// deterministic available-evidence replay, never real activation or qualifying physical TPM evidence.
#[test]
fn available_public_genesis_witness_is_authenticated_and_never_grants_physical_qualification() {
    use mutiny_consensus_v8::{
        admission_evidence_v1::{self as ev, EvidenceFailure, PublicWitnessBundle},
        attestation_witness::{AttestationWitness, EndorsementEvidence, WitnessFailure},
    };
    let pki = test_value_x509::X509Pki::new("available-genesis-public-evidence");
    let root = pki.root_hash();
    let tpm = TestTpm::stripped(software_tpm::Strip::ConsistentProvenance(root));
    let template = test_value_ek::template(ECC_TAG, test_value_ek::TEST_ATTRIBUTES);
    let area = test_value_ek::public_area(&template, &tpm.simulator_ek());
    let statement = tpm.profile().provenance.as_ref().unwrap();
    let witness = AttestationWitness {
        reference_time: test_value_x509::T_REF,
        endorsements: vec![EndorsementEvidence {
            ek_public_area: area,
            certificates: pki.chain(&tpm.simulator_ek(), &[0x51]),
            crls: pki.crls(&[], &[]),
        }],
        activation: vec![test_value_ek::activation(
            0,
            statement.ak_name,
            "public-label-no-activation-proof",
        )],
    };
    let witness_bytes = witness.encode().unwrap();
    let mut statement = statement.clone();
    statement.endorsement.as_mut().unwrap().witness_sha256 = witness.commitment().unwrap();
    statement.ek_public_sha256 = mutiny_consensus_v8::x509_syntax::certified_public_key_sha256(
        &witness.endorsements[0].certificates[0],
    )
    .unwrap();
    let tpm = tpm.with_provenance(statement);
    let anchor = pki.anchor(
        RevocationMode::CrlRequired,
        &[test_value_ek::ECC_CLASS],
        &[
            SignatureAlgorithm::EcdsaP256Sha256,
            SignatureAlgorithm::EcdsaP384Sha384,
        ],
    );
    let mut inputs = production(test_value_inputs());
    inputs.timestamp = test_value_x509::T_REF;
    inputs.parameters.roots = EndorsementRootSet {
        roots: [(
            root,
            EndorsementRoot {
                constraints: anchor.constraints,
                test_value_label: None,
            },
        )]
        .into(),
    };
    inputs.parameters.identity_classes = IdentityClasses::new(vec![test_value_ek::class_of(
        ECC_TAG,
        test_value_ek::TEST_ATTRIBUTES,
    )])
    .unwrap();
    inputs.parameters.pcr_profiles = pcr(&tpm);
    inputs.member = MemberInput {
        endorsement_root: root,
        profile: tpm.profile().encode().unwrap(),
    };
    let inputs = rebuild(inputs);
    let genesis = enroll_with(&inputs, &tpm);
    let constructed = genesis_v2::construct(&inputs, &genesis.enrollment).unwrap();
    let bundle = PublicWitnessBundle {
        genesis: constructed.identity,
        fingerprint: constructed.fingerprint,
        entries: vec![(
            genesis.enrollment.member_binding.admission.node,
            witness_bytes,
        )],
    };
    let ib = inputs.encode().unwrap();
    let eb = genesis.enrollment.encode().unwrap();
    let trust = approved(&inputs);
    let claim = claimed(&constructed);
    if let Some(path) = std::env::var_os("PUBLIC_GENESIS_WITNESS_FIXTURE_OUTPUT") {
        use std::io::Write;
        let fixture = serde_json::json!({"schema":"BUILD8-PUBLIC-GENESIS-WITNESS-TEST-VALUE-FIXTURE-V1",
            "synthetic_only":true,"production_authorized":false,
            "warning":"Public software fixtures only. No real qualifying TPM evidence, activation or Genesis seal.",
            "inputs":hex::encode(&ib),"enrollment":hex::encode(&eb),"evidence":hex::encode(bundle.encode().unwrap()),
            "manifest":hex::encode(trust.manifest.encode().unwrap()),"target":hex::encode(trust.initial_target),
            "genesis_id":hex::encode(constructed.identity),"state_root":hex::encode(constructed.root),
            "genesis_block":hex::encode(&constructed.block),"genesis_block_hash":hex::encode(constructed.block_hash),
            "records":claim.records.iter().map(|(k,v)|vec![hex::encode(k),hex::encode(v)]).collect::<Vec<_>>()});
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        output
            .write_all(serde_json::to_string_pretty(&fixture).unwrap().as_bytes())
            .unwrap();
        output.write_all(b"\n").unwrap();
    }
    let check = |b: &PublicWitnessBundle| {
        ev::verify_genesis_public_evidence(&ib, &eb, &trust, &claim, &b.encode().unwrap())
    };
    assert_eq!(check(&bundle).unwrap().root, constructed.root);
    assert_eq!(
        check(&bundle).unwrap().identity,
        constructed.identity,
        "same historical bytes replay identically"
    );
    assert_eq!(
        ev::require_qualified_physical_evidence(constructed.class),
        Err(EvidenceFailure::PhysicalQualificationUnestablished)
    );
    let mut other = bundle.clone();
    other.genesis[0] ^= 1;
    assert_eq!(check(&other).err(), Some(EvidenceFailure::Network));
    let mut other = bundle.clone();
    other.entries[0].0[0] ^= 1;
    assert_eq!(check(&other).err(), Some(EvidenceFailure::NodeSet));
    let mut other = bundle.clone();
    other.entries[0].1.push(0);
    assert!(matches!(
        check(&other),
        Err(EvidenceFailure::Witness(WitnessFailure::Encoding(_)))
    ));
    let mut old = witness.clone();
    old.reference_time -= 1;
    let mut other = bundle.clone();
    other.entries[0].1 = old.encode().unwrap();
    assert_eq!(
        check(&other).err(),
        Some(EvidenceFailure::Witness(WitnessFailure::CommitmentMismatch))
    );
    let mut wrong = trust.clone();
    wrong.initial_target = [0x11; 32];
    assert_eq!(
        ev::verify_genesis_public_evidence(&ib, &eb, &wrong, &claim, &bundle.encode().unwrap())
            .err(),
        Some(EvidenceFailure::Genesis(E::TargetMismatch))
    );
    // Recommit the altered public witness and genuinely reenroll the software profile so these
    // negatives reach their exact gate rather than stopping at CommitmentMismatch. The unchanged
    // witness is the positive control; this uses only publicly labelled simulator material.
    let rebound_check = |rebound: &AttestationWitness| {
        let mut rebound_statement = tpm.profile().provenance.as_ref().unwrap().clone();
        rebound_statement.endorsement.as_mut().unwrap().witness_sha256 =
            rebound.commitment().unwrap();
        rebound_statement.ek_public_sha256 =
            mutiny_consensus_v8::x509_syntax::certified_public_key_sha256(
                &rebound.endorsements[0].certificates[0],
            ).unwrap();
        let rebound_tpm = tpm.with_provenance(rebound_statement);
        let mut rebound_inputs = inputs.clone();
        rebound_inputs.member.profile = rebound_tpm.profile().encode().unwrap();
        let rebound_genesis = enroll_with(&rebound_inputs, &rebound_tpm);
        let rebound_constructed =
            genesis_v2::construct(&rebound_inputs, &rebound_genesis.enrollment).unwrap();
        let mut rebound_bundle = bundle.clone();
        rebound_bundle.genesis = rebound_constructed.identity;
        rebound_bundle.fingerprint = rebound_constructed.fingerprint;
        rebound_bundle.entries[0] = (
            rebound_genesis.enrollment.member_binding.admission.node,
            rebound.encode().unwrap(),
        );
        ev::verify_genesis_public_evidence(
            &rebound_inputs.encode().unwrap(),
            &rebound_genesis.enrollment.encode().unwrap(),
            &approved(&rebound_inputs),
            &claimed(&rebound_constructed),
            &rebound_bundle.encode().unwrap(),
        )
    };
    assert!(rebound_check(&witness).is_ok(), "valid recommitted public control");
    let mut stale_reference = witness.clone();
    stale_reference.reference_time -= 1;
    for _ in 0..2 {
        assert_eq!(
            rebound_check(&stale_reference).err(),
            Some(EvidenceFailure::Witness(WitnessFailure::ReferenceTimeMismatch)),
            "fixed committed historical time; no ambient clock or network input",
        );
    }
    let mut mismatched_key = witness.clone();
    let different_public_ek =
        test_value_ek::ecc_public(&test_value_ek::key("public-witness-other-certified-ek"));
    assert_ne!(different_public_ek, tpm.simulator_ek());
    // The alternate leaf has a genuine public-fixture chain/CRL signature under the same trusted
    // root. Its C2 digest is updated above; the committed public area and identity stay original.
    mismatched_key.endorsements[0].certificates = pki.chain(&different_public_ek, &[0x52]);
    assert_eq!(
        rebound_check(&mismatched_key).err(),
        Some(EvidenceFailure::Witness(WitnessFailure::KeyMismatch(0))),
    );

    // A self-consistent authority-signed profile with the wrong C2 SPKI digest
    // still constructs structurally, but cannot authenticate this public witness.
    let mut bad_statement = tpm.profile().provenance.as_ref().unwrap().clone();
    bad_statement.ek_public_sha256[0] ^= 1;
    let bad_tpm = tpm.with_provenance(bad_statement);
    let mut bad_inputs = inputs.clone();
    bad_inputs.member.profile = bad_tpm.profile().encode().unwrap();
    let bad_genesis = enroll_with(&bad_inputs, &bad_tpm);
    let bad_constructed = genesis_v2::construct(&bad_inputs, &bad_genesis.enrollment).unwrap();
    let mut bad_bundle = bundle.clone();
    bad_bundle.genesis = bad_constructed.identity;
    bad_bundle.entries[0].0 = bad_genesis.enrollment.member_binding.admission.node;
    assert_eq!(
        ev::verify_genesis_public_evidence(
            &bad_inputs.encode().unwrap(),
            &bad_genesis.enrollment.encode().unwrap(),
            &approved(&bad_inputs),
            &claimed(&bad_constructed),
            &bad_bundle.encode().unwrap()
        )
        .err(),
        Some(EvidenceFailure::PublicKeyDigestMismatch)
    );
}

/// F8: the Production placeholder guard covers PCR profiles too (all-equal digest bytes); the control passes.
#[test]
fn production_class_refuses_placeholder_pcr_profiles() {
    let (i, tpm) = invented_production(b"pcr guard");
    let mut placeholder = profile_of(&tpm);
    placeholder.digest = [0x5a; 32];
    let mut bad = i.clone();
    bad.parameters.pcr_profiles = AcceptedPcrProfiles::new(UPDATE_FROZEN_AT_GENESIS, vec![profile_of(&tpm), placeholder]).unwrap();
    assert_eq!(rebuild(bad).validate(), Err(E::PlaceholderPcrProfile));
    i.validate().unwrap();
}

/// F4 item 1: a state carrying the V2 parameters record must not also carry a V1 policy or a V1 parameters record.
#[test]
fn a_v2_genesis_state_refuses_a_v1_policy_or_v1_parameters_record() {
    let g = enroll(&test_value_inputs());
    let c = genesis_v2::construct(&g.inputs, &g.enrollment).unwrap();
    let mut v1_params = c.state.clone();
    v1_params.protocol_records.insert(
        mutiny_consensus_v8::genesis_inputs::parameters_key(),
        mutiny_consensus_v8::genesis_inputs::Parameters {
            initial_target: [255; 32],
            rules: RuleManifest { commitments: vec![(b"x".to_vec(), [1; 32])] },
            treasury: None,
        }
        .encode()
        .unwrap(),
    );
    assert_eq!(v1_params.admission_class(), Err(Error::UnqualifiedPhysical));
    assert!(v1_params.root().is_err());
    let mut v1_policy = c.state.clone();
    v1_policy.admission.policy = Some(software_tpm::fixture_policy());
    assert_eq!(v1_policy.admission_class(), Err(Error::UnqualifiedPhysical));
    assert!(v1_policy.root().is_err());
    assert_eq!(c.state.admission_class(), Ok(AdmissionClass::LegacyTest), "control");
}

// Rule M coverage is checked at the actual V2 constructor and StateRoot entry
// points. Public software material exercises the rule, not physical provenance.
#[test]
fn rule_m_v2_genesis_requires_every_committed_identity_class() {
    let (one, tpm) = invented_production(b"rule-m-coverage");
    let original = enroll_with(&one, &tpm);
    let mut two = one.clone();
    two.parameters.identity_classes = IdentityClasses::new(vec![
        IdentityClass { algorithm: RSA_TAG, size: 2048, template_sha256: label("rule-m-rsa-template") },
        IdentityClass { algorithm: ECC_TAG, size: TPM_ECC_NIST_P256, template_sha256: label("rule-m-ecc-template") },
    ]).unwrap();
    two = rebuild(two);
    assert_eq!(two.validate(), Err(E::Consensus(Error::UnqualifiedPhysical)));
    assert_eq!(genesis_v2::construct(&two, &original.enrollment).err(), Some(E::Consensus(Error::UnqualifiedPhysical)));
    // A second independent TEST-VALUE identity covers the second committed slot.
    let both_tpm = tpm.edited(|p| {
        let provenance = p.provenance.as_mut().unwrap();
        provenance.endorsement.as_mut().unwrap().identities.push((two.member.endorsement_root, label("rule-m-secondary")));
        p.admission_trust_manifest = provenance.commitment();
    });
    two.member.profile = both_tpm.profile().encode().unwrap();
    two.validate().unwrap();
    let enrolled = enroll_with(&two, &both_tpm);
    let canonical = genesis_v2::construct(&two, &enrolled.enrollment).unwrap();
    assert_eq!(canonical.state.admission_class().unwrap(), AdmissionClass::Production);
    canonical.state.root().unwrap();
    State::from_records(&canonical.records().unwrap(), canonical.root).unwrap();
    // An independently signed one-class binding can pass the policy/key-book
    // verifier, but cannot enter this two-class committed state or its replay.
    let mut single = enrolled.enrollment.member_binding.clone();
    single.admission.profile = tpm.profile().encode().unwrap();
    single.admission.prove_continuity(&enrolled.continuity).unwrap();
    single.admission.quote = tpm.quote(single.admission.challenge().unwrap());
    single.admission.authorize(&owner_key(), 1).unwrap();
    single.sign(&enrolled.node).unwrap();
    let expected = mutiny_consensus_v8::admission_v2::Expected {
        node: single.admission.node,
        hardware_generation: 1,
        key_generation: 1,
        supervised_nonce: single.admission.supervised_nonce,
    };
    let mut keys = mutiny_consensus_v8::continuity_keys_v2::Book::default();
    keys.admit(&single.admission,
        canonical.state.admission_policy_v2.as_ref().unwrap().initial(),
        &expected, &canonical.state.wallets, AdmissionClass::Production).unwrap();
    let mut bad_state = canonical.state.clone();
    bad_state.continuity_keys_v2 = keys.clone();
    assert!(matches!(bad_state.root(), Err(mutiny_consensus_v8::execution::ExecutionError::Codec(Error::UnqualifiedPhysical))));
    let mut corrupted = canonical.records().unwrap();
    for (key, value) in keys.records().unwrap() {
        let record = corrupted.iter_mut().find(|(k, _)| *k == key).unwrap();
        record.1 = value;
    }
    let forged_root = mutiny_consensus_v8::blocks::state_root(&corrupted).unwrap();
    assert_eq!(State::from_records(&corrupted, forged_root).err(), Some(Error::WrongAnchor));
    // Excess coverage is also refused; one identity cannot be silently dropped.
    let extra = both_tpm.edited(|p| {
        let provenance = p.provenance.as_mut().unwrap();
        provenance.endorsement.as_mut().unwrap().identities.push((two.member.endorsement_root, label("rule-m-extra")));
        p.admission_trust_manifest = provenance.commitment();
    });
    let mut bad = two.clone();
    bad.member.profile = extra.profile().encode().unwrap();
    assert_eq!(bad.validate(), Err(E::Consensus(Error::UnqualifiedPhysical)));
}
// Signed recovery fixtures keep locked A8 distinct from prospective coverage.
// All roots, endorsement identities and TPM keys here are public software values;
// "full coverage" means the committed count, not EK/witness authenticity.
#[test]
fn signed_recovery_coverage_keeps_production_scope_closed_and_legacy_positive() {
    use mutiny_consensus_v8::{
        anchors::FinalizedAnchor,
        recovery_authority_v2::Authorization,
        recovery_history_v2::Record,
        recovery_replacement_v2::Replacement,
        recovery_transition_v2::Prepared,
        recovery_witness_v2::Witnesses,
        state_tree::StateTree,
        votes_v2::HeightAuthority,
    };
    use software_tpm::Strip;
    let two_classes = || IdentityClasses::new(vec![
        IdentityClass { algorithm: RSA_TAG, size: 2048, template_sha256: label("recovery-rsa-template") },
        IdentityClass { algorithm: ECC_TAG, size: TPM_ECC_NIST_P256, template_sha256: label("recovery-ecc-template") },
    ]).unwrap();
    let with_second = |tpm: &TestTpm, root: Hash, secondary: &str| tpm.edited(|p| {
        let provenance = p.provenance.as_mut().unwrap();
        provenance.endorsement.as_mut().unwrap().identities.push((root, label(secondary)));
        p.admission_trust_manifest = provenance.commitment();
    });
    let make_parent = |production: bool| {
        let (mut inputs, single) = if production {
            invented_production(b"signed-recovery-coverage")
        } else {
            let mut inputs = test_value_inputs();
            let tpm = TestTpm::new().strip(Strip::ConsistentProvenance(inputs.member.endorsement_root));
            inputs.member.profile = tpm.profile().encode().unwrap();
            (inputs, tpm)
        };
        let full = with_second(&single, inputs.member.endorsement_root, "recovery-parent-secondary");
        inputs.parameters.identity_classes = two_classes();
        inputs.member.profile = full.profile().encode().unwrap();
        inputs = rebuild(inputs);
        inputs.validate().unwrap();
        let enrolled = enroll_with(&inputs, &full);
        let canonical = genesis_v2::construct(&inputs, &enrolled.enrollment).unwrap();
        State::from_records(&canonical.records().unwrap(), canonical.root).unwrap();
        (canonical, inputs.member.endorsement_root)
    };
    let signed_replacement = |canonical: &Constructed, root: Hash, count: usize| {
        let state = &canonical.state;
        let registry = state.continuity.as_ref().unwrap();
        let old = &registry.members[0];
        let parent = FinalizedAnchor {
            network: NETWORK_ID,
            genesis: canonical.identity,
            fingerprint: registry.fingerprint,
            height: 0,
            block: canonical.block_hash,
        };
        let authority = HeightAuthority::from_state(state, parent.clone(), canonical.root).unwrap();
        let single = TestTpm::with_identity("signed-recovery-new-hardware")
            .strip(Strip::ConsistentProvenance(root));
        let replacement = if count == 2 {
            with_second(&single, root, "recovery-replacement-secondary")
        } else {
            single
        };
        assert_eq!(replacement.profile().provenance.as_ref().unwrap()
            .endorsement.as_ref().unwrap().identities.len(), count);
        let node = HybridKey::generate(Role::Node).unwrap();
        let continuity = HybridKey::generate(Role::Continuity).unwrap();
        let mut binding = state.membership_v2.get(old.node).unwrap().binding().clone();
        binding.node_descriptor = node.public().descriptor(1).unwrap();
        binding.admission.node = node_id(parent.genesis, &binding.node_descriptor).unwrap();
        binding.admission.hardware_generation = 2;
        binding.admission.key_generation = 2;
        binding.admission.continuity_descriptor = continuity.public().descriptor(2).unwrap();
        binding.admission.profile = replacement.profile().encode().unwrap();
        let mut material = Replacement {
            parent: parent.clone(),
            root: canonical.root,
            membership: authority.membership,
            sequence: 1,
            lineage: old.lineage,
            old_node: old.node,
            old_hardware_generation: 1,
            old_key_generation: 1,
            nonce: label("signed-recovery-context-nonce"),
            lost: vec![(old.lineage, 1)],
            binding,
            native_possession: [0; 64],
        };
        material.binding.admission.supervised_nonce = material.admission_nonce().unwrap();
        material.binding.admission.prove_continuity(&continuity).unwrap();
        material.binding.admission.quote = replacement.quote(material.binding.admission.challenge().unwrap());
        material.binding.admission.authorize(&owner_key(), 1).unwrap();
        material.binding.sign(&node).unwrap();
        material.native_possession = replacement.possession(material.native_digest().unwrap());
        let recovery = state.recovery_authority_v2.as_ref().unwrap();
        let authorization = Authorization::sign(material.intent().unwrap(), recovery, &recovery_key()).unwrap();
        let mut tree = StateTree::default();
        for (key, raw) in canonical.records().unwrap() { tree.insert(key, raw).unwrap(); }
        let witnesses = Witnesses {
            control: tree.proof(parent.clone(), domain_hash(b"MUTINY-BUILD8-NODE-CONTROL-KEY-V2", &old.node)),
            continuity: tree.proof(parent.clone(), domain_hash(b"MUTINY-BUILD8-CONTINUITY-KEY-STATE-V2", &old.node)),
        };
        let policy = state.current_admission_policy_v2(parent.genesis, parent.fingerprint).unwrap();
        let record = Record { material, authorization, witnesses, policy };
        record.verify_history_only(recovery).unwrap();
        let raw = record.encode(recovery).unwrap();
        assert_eq!(Record::decode(&raw, recovery).unwrap(), record);
        (parent, record)
    };
    let (production, root) = make_parent(true);
    assert_eq!(production.state.admission_class().unwrap(), AdmissionClass::Production);
    let before = production.records().unwrap();
    for count in [1, 2] {
        let (parent, record) = signed_replacement(&production, root, count);
        // Complete hybrid/TPM/native signatures and exact historical witnesses
        // verify. Locked A8 then refuses hardware replacement after sealing.
        assert_eq!(record.material.verify_material(&production.state, &parent,
            production.root, &record.authorization, false), Err(Error::AdmissionAuthorityEnded));
        assert_eq!(Prepared::verify(&production.state, &parent, production.root, record, false)
            .err(), Some(Error::AdmissionAuthorityEnded));
        assert_eq!(production.records().unwrap(), before);
    }
    let (legacy, root) = make_parent(false);
    assert_eq!(legacy.state.admission_class().unwrap(), AdmissionClass::LegacyTest);
    let (parent, record) = signed_replacement(&legacy, root, 2);
    record.material.verify_material(&legacy.state, &parent, legacy.root,
        &record.authorization, false).unwrap();
    let old_node = record.material.old_node;
    let new_node = record.material.binding.admission.node;
    let prepared = Prepared::verify(&legacy.state, &parent, legacy.root, record, false).unwrap();
    let projected = prepared.authority().unwrap();
    assert_eq!(projected.parent, parent);
    assert!(!projected.voters.contains_key(&old_node));
    assert!(projected.voters.contains_key(&new_node));
    assert_eq!(prepared.canonical_parent_root(), legacy.root);
    State::from_records(&legacy.records().unwrap(), legacy.root).unwrap();
}


// Selected TEST-VALUE-only successor: real public software DER/signatures and
// validated GenesisInputs, not a trusted-State model or physical activation.
#[test]
fn selected_test_value_alias_authenticates_real_der_genesis_and_own_reopen() {
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
    let policy=inputs.parameters.witness_policy().unwrap();
    let statement=tpm.profile().provenance.as_ref().unwrap();
    attestation_witness::verify_witness_with_policy(statement,Some(&raw),&policy,inputs.timestamp,&mutiny_consensus_v8::x509_syntax::X509Syntax).unwrap();
    assert!(attestation_witness::verify_witness(statement,Some(&raw),&policy.context(inputs.timestamp),&mutiny_consensus_v8::x509_syntax::X509Syntax).is_err(),
        "bare DER context does not reinterpret a logical statement root");
    // Absence of selector retains the original anchors even for marker-looking labels.
    let mut historical=inputs.clone();historical.parameters.rules.commitments.retain(|(name,_)|name.as_slice()!=alias::RULE_ENTRY);
    let historical=rebuild(historical);historical.validate().unwrap();
    assert_ne!(historical.identity().unwrap(),inputs.identity().unwrap());
    let old_policy=historical.parameters.witness_policy().unwrap();
    assert_eq!(old_policy.anchors()[0].root_cert_der_sha256,logical_root);
    assert!(attestation_witness::verify_witness_with_policy(statement,Some(&raw),&old_policy,inputs.timestamp,&mutiny_consensus_v8::x509_syntax::X509Syntax).is_err());
    // An independently committed wrong DER cannot be repaired by applicant witness bytes.
    let mut other=inputs.clone();let (_,mut entry)=other.parameters.roots.roots.pop_first().unwrap();
    let mut other_label=alias::LABEL_PREFIX.to_vec();other_label.extend([0x5a;32]);entry.test_value_label=Some(other_label.clone());
    other.parameters.roots.roots.insert(genesis_v2::test_value_root(&other_label),entry);
    let other=rebuild(other);let other_policy=other.parameters.witness_policy().unwrap();
    assert!(attestation_witness::verify_witness_with_policy(statement,Some(&raw),&other_policy,inputs.timestamp,&mutiny_consensus_v8::x509_syntax::X509Syntax).is_err());
    // Recommit corrupted certificate bytes to reach the real DER/signature parser,
    // rather than stopping at the witness checksum gate.
    let mut corrupt=witness.clone();*corrupt.endorsements[0].certificates[0].last_mut().unwrap()^=1;
    let mut corrupt_statement=statement.clone();corrupt_statement.endorsement.as_mut().unwrap().witness_sha256=corrupt.commitment().unwrap();
    assert!(attestation_witness::verify_witness_with_policy(&corrupt_statement,Some(&corrupt.encode().unwrap()),&policy,inputs.timestamp,&mutiny_consensus_v8::x509_syntax::X509Syntax).is_err());
    let mut wrong_primary=statement.clone();wrong_primary.endorsement_root=[0x33;32];
    assert_eq!(attestation_witness::verify_witness_with_policy(&wrong_primary,Some(&raw),&policy,inputs.timestamp,&mutiny_consensus_v8::x509_syntax::X509Syntax),
        Err(attestation_witness::WitnessFailure::RootMismatch(0)));
    // Actual own trusted Genesis is built above from authentic Input/Enrollment/witness.
    // This control is height-zero persistence/reopen, not a certified new block.
    let mut nonce=[0;16];mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let dir=std::env::temp_dir().join(format!("build8-public-selected-alias-genesis-{}",hex::encode(nonce)));
    assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&dir).unwrap());
    let anchor=FinalizedAnchor {network:NETWORK_ID,genesis:constructed.identity,fingerprint:constructed.fingerprint,height:0,block:constructed.block_hash};
    let path=dir.join("canonical.sqlite");
    let chain=CanonicalStore::open_trusted_genesis(&path,&anchor,&constructed.state,constructed.root,inputs.timestamp,inputs.parameters.initial_target).unwrap();
    assert_eq!(chain.load().unwrap().0.height,0);drop(chain);
    let reopened=CanonicalStore::open_trusted_genesis(&path,&anchor,&constructed.state,constructed.root,inputs.timestamp,inputs.parameters.initial_target).unwrap();
    assert_eq!(reopened.load().unwrap().1.records().unwrap(),constructed.records().unwrap());
    println!("PUBLIC selected alias Genesis evidence retained: {}",dir.display());
}
