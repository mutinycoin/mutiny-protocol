//! Physical-admission enforcement under the existing locked policy (TPM admission package,
//! Stage B): the admission class comes from consensus-committed Genesis data, a typed provenance
//! statement (checks C1..C5) is bound to the attestation key and the device profile, and one rule
//! set is applied at the single choke points. Negative tests from the analysis (section 5).
//!
//! SIMULATED != PHYSICAL. Every profile here is deterministic software-simulator material; a
//! passing test proves software behaviour only. The TEST-VALUE marker is an accidental-use guard,
//! not a hardware proof. T14 documents the limit: an authority-signed software profile carrying a
//! self-made, internally consistent provenance statement IS accepted in the Production class;
//! authority attestation (the supervised ceremony behind the signature) is the anchor.
#[path = "support/software_tpm.rs"]
mod software_tpm;
#[path = "support/license_v2.rs"]
mod license_fixture;
use ed25519_dalek::{Signer, SigningKey as Ed};
use mutiny_consensus_v8::{
    Hash, admission::*, blocks, execution::State, freshness, genesis_inputs::*, join,
    licenses::BindWorker, protocol_manifest::RuleManifest,
    provenance::{self, AdmissionClass, Failure, Provenance},
    tpm::TpmProfile, transactions,
    treasury_v1::{Class, Treasury},
};
use mutiny_crypto_v2::{HybridKey, Role};
use software_tpm::{Strip, TestTpm};
use std::collections::BTreeSet;

fn root() -> Hash {
    software_tpm::test_value_endorsement_root()
}
/// Candidate 3, Order A8: refused, and NOT by the post-sealing scope rule. Every negative variant must
/// fail on its own check first, so these assertions keep pinning the provenance rule even though the
/// Production class now refuses every post-sealing admission anyway.
fn refused_before_scope<T>(result: mutiny_consensus_v8::Result<T>) -> bool {
    matches!(result, Err(e) if e != mutiny_consensus_v8::Error::AdmissionAuthorityEnded)
}
/// Candidate 3, Order A8: refused exactly by the post-sealing scope rule.
fn refused_by_scope<T>(result: mutiny_consensus_v8::Result<T>) -> bool {
    matches!(result, Err(mutiny_consensus_v8::Error::AdmissionAuthorityEnded))
}
fn roots() -> BTreeSet<Hash> {
    [root()].into()
}

// ------------------------------------------------------------------------------------------
// Provenance codec and profile versions (PROPOSED/UNFROZEN schema)
// ------------------------------------------------------------------------------------------
#[test]
fn provenance_codec_is_canonical_fixed_size_and_typed() {
    let tpm = TestTpm::stripped(Strip::ConsistentProvenanceV1(root()));
    let p = tpm.profile().provenance.clone().unwrap();
    let raw = p.encode();
    assert_eq!(raw.len(), provenance::PROVENANCE_BYTES);
    assert_eq!(Provenance::decode(&raw).unwrap(), p);
    assert_eq!(tpm.profile().admission_trust_manifest, p.commitment());
    assert_eq!(
        p.commitment(),
        mutiny_consensus_v8::domain_hash(provenance::PROVENANCE_DOMAIN, &raw)
    );
    // Truncated, extended, or with any single byte changed: never a different valid statement
    // that decodes to the same value; kinds must be exactly 1..5 in order.
    assert!(Provenance::decode(&raw[..raw.len() - 1]).is_err());
    let mut longer = raw.clone();
    longer.push(0);
    assert!(Provenance::decode(&longer).is_err());
    for i in 0..raw.len() {
        let mut m = raw.clone();
        m[i] ^= 0x01;
        if let Ok(decoded) = Provenance::decode(&m) {
            assert_ne!(decoded, p, "byte {i}");
        }
    }
    let kinds_at: Vec<usize> = (0..5).map(|k| raw.len() - 5 * 36 + k * 36 + 1).collect();
    for (k, at) in kinds_at.iter().enumerate() {
        assert_eq!(raw[*at], k as u8 + 1, "evidence kind position");
        let mut swapped = raw.clone();
        swapped[*at] = if k == 0 { 2 } else { 1 };
        assert!(Provenance::decode(&swapped).is_err(), "kind order {k}");
    }
}

#[test]
fn version_1_profile_bytes_are_unchanged_and_version_2_commits_to_provenance() {
    // Version 1: the committed TEST-VALUE fixture still decodes and re-encodes byte-identically.
    let fixture: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string("../qualification/TEST-VALUE-SOFTWARE-TPM-FIXTURE-V1.json").unwrap(),
    )
    .unwrap();
    let v1 = hex::decode(fixture["profile"].as_str().unwrap()).unwrap();
    let decoded = TpmProfile::decode(&v1).unwrap();
    assert!(decoded.provenance.is_none());
    assert_eq!(decoded.encode().unwrap(), v1);
    assert_eq!(v1[0..2], [0x8a, 0x01]);
    // Version 2 round-trips, carries the statement, and its commitment covers it.
    let tpm = TestTpm::stripped(Strip::ConsistentProvenance(root()));
    let v2 = tpm.profile().encode().unwrap();
    assert_eq!(v2[0..2], [0x8b, 0x02]);
    let back = TpmProfile::decode(&v2).unwrap();
    assert_eq!(back.encode().unwrap(), v2);
    assert_eq!(back.commitment().unwrap(), tpm.profile().commitment().unwrap());
    let mut other = tpm.profile().provenance.clone().unwrap();
    other.evidence[0][0] ^= 1;
    let changed = tpm.with_provenance(other);
    assert_ne!(changed.profile().commitment().unwrap(), tpm.profile().commitment().unwrap());
    // Version and arity must agree: an 11-element array labelled version 1, or a 10-element array
    // labelled version 2, is not a profile.
    let mut mislabelled = v2.clone();
    mislabelled[1] = 0x01;
    assert!(TpmProfile::decode(&mislabelled).is_err());
    let mut relabelled = v1.clone();
    relabelled[1] = 0x02;
    assert!(TpmProfile::decode(&relabelled).is_err());
}

// ------------------------------------------------------------------------------------------
// T13: the Production rule, one field at a time, with the precise failure
// ------------------------------------------------------------------------------------------
#[test]
fn production_rule_checks_c1_to_c5_one_field_at_a_time() {
    for (name, tpm, expected) in software_tpm::production_negative_variants(root()) {
        let got = provenance::check_profile_detailed(AdmissionClass::Production, tpm.profile(), root(), &roots());
        match expected {
            Some(failure) => assert_eq!(got, Err(failure), "{name}"),
            None => assert!(got.is_err(), "{name}"),
        }
        // Legacy/Test class: the rule adds nothing (pre-package behaviour).
        assert_eq!(
            provenance::check_profile_detailed(AdmissionClass::LegacyTest, tpm.profile(), root(), &roots()),
            Ok(()),
            "{name}"
        );
    }
    // C2, second half: a statement whose root is not in the committed policy set.
    let consistent = TestTpm::stripped(Strip::ConsistentProvenance(root()));
    let other: BTreeSet<Hash> = [[0x42; 32]].into();
    assert_eq!(
        provenance::check_profile_detailed(AdmissionClass::Production, consistent.profile(), root(), &other),
        Err(Failure::RootNotInPolicy)
    );
    assert_eq!(
        provenance::check_profile_detailed(AdmissionClass::Production, consistent.profile(), root(), &roots()),
        Ok(())
    );
}

/// T13 complement: a version-2 profile that KEEPS the hardware TEST-VALUE marker but carries a
/// statement consistent with C1..C5 is refused in the Production class for the marker alone: by the
/// rule (exactly `TestValueMarker`), by the V1 choke point (`ApprovedProfile::verify`) and by the
/// parent-bound V2 JOIN. The Legacy/Test class accepts the same profile through both choke points.
#[test]
fn production_class_refuses_the_hardware_marker_even_with_a_consistent_statement() {
    let marked = TestTpm::new();
    let tpm = marked.with_provenance(marked.consistent_provenance(root()));
    assert!(tpm.profile().is_test_value(), "the hardware marker is kept");
    assert!(tpm.profile().provenance.is_some());
    assert_eq!(
        provenance::check_profile_detailed(AdmissionClass::Production, tpm.profile(), root(), &roots()),
        Err(Failure::TestValueMarker)
    );
    let policy = software_tpm::fixture_policy();
    let approved = software_tpm::approve(&policy, root(), tpm.profile());
    assert!(approved.verify(&policy, AdmissionClass::Production).is_err());
    approved.verify(&policy, AdmissionClass::LegacyTest).unwrap();
    let production = v2::setup(true);
    let join = v2::join(&production, &tpm);
    assert!(join.verify(&production.state, &production.parent, production.state.root().unwrap()).is_err());
    let legacy = v2::setup(false);
    let join = v2::join(&legacy, &tpm);
    join.verify(&legacy.state, &legacy.parent, legacy.state.root().unwrap()).unwrap();
}

// ------------------------------------------------------------------------------------------
// Class (E1): only from committed Genesis data
// ------------------------------------------------------------------------------------------
#[test]
fn admission_class_comes_only_from_committed_genesis_data() {
    let policy = software_tpm::fixture_policy();
    let mut state = State::default();
    assert_eq!(state.admission_class().unwrap(), AdmissionClass::LegacyTest);
    state.admission.policy = Some(policy.clone());
    assert_eq!(state.admission_class().unwrap(), AdmissionClass::LegacyTest);
    // A parameters record WITHOUT the trust-roots commitment: Legacy/Test.
    let legacy = Parameters {
        initial_target: [255; 32],
        rules: RuleManifest { commitments: vec![(b"test-value-rules".to_vec(), [7; 32])] },
        treasury: None,
    };
    state.protocol_records.insert(parameters_key(), legacy.encode().unwrap());
    assert_eq!(state.admission_class().unwrap(), AdmissionClass::LegacyTest);
    // The matching commitment: Production.
    state
        .protocol_records
        .insert(parameters_key(), software_tpm::production_parameters(&policy.endorsement_roots));
    assert_eq!(state.admission_class().unwrap(), AdmissionClass::Production);
    // A commitment to a different root set: an error, never a fallback to Legacy/Test.
    let mismatch: BTreeSet<Hash> = [[0x42; 32]].into();
    state
        .protocol_records
        .insert(parameters_key(), software_tpm::production_parameters(&mismatch));
    assert!(state.admission_class().is_err());
    assert!(state.root().is_err(), "no StateRoot for a mismatched declaration");
    // T9: a declared Production root set without any admission policy is an error before any
    // attestation could be consulted; such a state has no StateRoot at all.
    let mut policyless = State::default();
    policyless
        .protocol_records
        .insert(parameters_key(), software_tpm::production_parameters(&policy.endorsement_roots));
    assert!(policyless.admission_class().is_err());
    assert!(policyless.root().is_err());
    // The commitment is the domain hash over the sorted CBOR root array, and the set must be
    // non-empty without zero roots.
    assert!(provenance::trust_roots_commitment(&BTreeSet::new()).is_err());
    assert!(provenance::trust_roots_commitment(&[[0; 32]].into()).is_err());
    let two: BTreeSet<Hash> = [[2; 32], [1; 32]].into();
    let mut body = vec![0x82, 0x58, 0x20];
    body.extend([1; 32]);
    body.extend([0x58, 0x20]);
    body.extend([2; 32]);
    assert_eq!(
        provenance::trust_roots_commitment(&two).unwrap(),
        mutiny_consensus_v8::domain_hash(provenance::TRUST_ROOTS_DOMAIN, &body)
    );
}

// ------------------------------------------------------------------------------------------
// Genesis V1 (T1, T2, T14, B4, B6)
// ------------------------------------------------------------------------------------------
struct GenesisCase {
    descriptor: blocks::GenesisDescriptor,
    rules: RuleManifest,
    target: Hash,
    bindings: Vec<BindWorker>,
    approved: ApprovedProfile,
    nonce: Hash,
    evidence: Vec<u8>,
    input: PhysicalAdmissionInput,
}
/// A complete V1 Genesis input set around `tpm` (public test seeds; TEST-VALUE treasury key).
/// `production_rules`: the rule manifest commits to {root()}; `production_treasury`: Treasury
/// class Production (required by the Production profile) instead of TestValue.
fn genesis_case(tpm: &TestTpm, production_rules: bool, production_treasury: bool) -> Option<GenesisCase> {
    let owner = Ed::from_bytes(&[80; 32]);
    let node_key = Ed::from_bytes(&[81; 32]);
    let recovery = Ed::from_bytes(&[82; 32]);
    let rules = if production_rules {
        software_tpm::production_rules(&roots())
    } else {
        RuleManifest { commitments: vec![(b"test-value-rules".to_vec(), [86; 32])] }
    };
    let target = [87; 32];
    let input = PhysicalAdmissionInput {
        owner: owner.verifying_key().to_bytes(),
        node_authentication: node_key.verifying_key().to_bytes(),
        endorsement_root: root(),
        profile: tpm.profile().clone(),
    };
    // Public all-"zoo" TEST-VALUE mnemonic; never a production identity.
    let treasury_key = HybridKey::wallet_restore(&("zoo ".repeat(23) + "vote"), Role::WalletOwner)
        .unwrap()
        .public()
        .descriptor(1)
        .unwrap();
    let class = if production_treasury { Class::Production } else { Class::TestValue };
    let parameters = Parameters {
        initial_target: target,
        rules: rules.clone(),
        treasury: Some(Treasury::new(class, treasury_key).unwrap()),
    };
    let descriptor = blocks::GenesisDescriptor {
        timestamp: 1_800_000_000,
        nonce: [89; 32],
        fingerprint: rules.fingerprint().unwrap(),
        owner: transactions::address(&input.owner),
        purchase: [90; 32],
        parameters: parameters.encode().unwrap(),
        // Zero trust manifest: the input itself cannot be encoded (variant e).
        admission_records: vec![input.encode().ok()?],
        recovery: recovery.verifying_key().to_bytes(),
    };
    let gid = descriptor.id().unwrap();
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/GENESIS-BINDING-VECTORS-STATE-V2.json"
    ))
    .unwrap();
    let mut bindings: Vec<BindWorker> = vectors["cases"][0]["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| BindWorker::decode(&hex::decode(v["binding_hex"].as_str().unwrap()).unwrap()).unwrap())
        .collect();
    for (i, b) in bindings.iter_mut().enumerate() {
        b.genesis = gid;
        b.fingerprint = descriptor.fingerprint;
        b.license = blocks::genesis_license(gid, i as u64).unwrap();
        b.worker = b.worker_id();
        b.owner_signature = owner.sign(&b.signing_digest(false)).to_bytes();
        b.worker_signature = Ed::from_bytes(&[10 + i as u8; 32]).sign(&b.signing_digest(true)).to_bytes();
    }
    // V1 Genesis: the policy authority is the input owner and the root set is the input's root.
    let mut approved = ApprovedProfile {
        genesis: gid,
        fingerprint: descriptor.fingerprint,
        endorsement_root: root(),
        profile: tpm.profile().encode().unwrap(),
        signature: [0; 64],
    };
    approved.signature = owner.sign(&approved.signing_digest().unwrap()).to_bytes();
    let member = freshness::PhysicalMember {
        node: join::node_id(gid, input.node_authentication),
        generation: 0,
        continuity_key: tpm.voting_point(),
        hardware: tpm.profile().hardware,
        admission_commitment: tpm.profile().commitment().unwrap(),
        attestation_key: tpm.profile().ak_public.clone(),
    };
    let nonce = [91; 32];
    let evidence = tpm.quote(freshness::genesis_challenge(gid, nonce, &member));
    Some(GenesisCase { descriptor, rules, target, bindings, approved, nonce, evidence, input })
}
fn initial(case: &GenesisCase, profile: GenesisProfile) -> mutiny_consensus_v8::Result<State> {
    initial_state(
        &case.descriptor,
        &case.rules,
        case.target,
        &case.bindings,
        &case.approved,
        case.nonce,
        &case.evidence,
        profile,
    )
}

/// T1: Production Genesis V1 rejects the marked profile, every stripped/relabeled variant and
/// every one-field provenance inconsistency, in `validate_production_descriptor` and in
/// `initial_state(Production)`, even though the descriptor commits to the trust-root set.
#[test]
fn production_genesis_rejects_marked_stripped_and_inconsistent_software_profiles() {
    for (name, tpm, _) in software_tpm::production_negative_variants(root()) {
        let Some(case) = genesis_case(&tpm, true, true) else {
            // Variant (e): the zero-manifest input cannot even be encoded as Genesis input.
            continue;
        };
        assert!(validate_production_descriptor(&case.descriptor, &case.rules, case.target).is_err(), "{name}");
        assert!(genesis_admission_class(&case.descriptor, &case.input, GenesisProfile::Production).is_err(), "{name}");
        assert!(initial(&case, GenesisProfile::Production).is_err(), "{name}");
    }
}

/// T2: class mismatch both ways. Production Genesis without the committed root set (the V9
/// candidate manifest has none: the root-set content is an open decision) is refused even for
/// consistent material; Test Genesis refuses a descriptor that commits to a Production root set.
#[test]
fn genesis_class_must_match_the_declared_profile_in_both_directions() {
    let tpm = TestTpm::stripped(Strip::ConsistentProvenance(root()));
    let legacy_rules = genesis_case(&tpm, false, true).unwrap();
    assert!(validate_production_descriptor(&legacy_rules.descriptor, &legacy_rules.rules, legacy_rules.target).is_err());
    assert!(initial(&legacy_rules, GenesisProfile::Production).is_err());
    let production_rules = genesis_case(&tpm, true, false).unwrap();
    assert!(genesis_admission_class(&production_rules.descriptor, &production_rules.input, GenesisProfile::Test).is_err());
    assert!(initial(&production_rules, GenesisProfile::Test).is_err());
    // Legacy/Test Genesis with Legacy/Test rules is unchanged (the existing vectors).
    let marked = genesis_case(&TestTpm::new(), false, false).unwrap();
    let state = initial(&marked, GenesisProfile::Test).unwrap();
    assert_eq!(state.admission_class().unwrap(), AdmissionClass::LegacyTest);
}

/// T14 (Genesis) and Order A9. DOCUMENTED LIMIT, authority attestation is the anchor: a
/// marker-stripped software profile with a self-made consistent provenance statement, approved by
/// the authority, still PASSES the V1 Production class rule (`genesis_admission_class`, kept as a
/// test/replay evaluator). Order A9: V1 is not a Production Genesis implementation, so every V1
/// construction path refuses it with `Error::V1NotProductionGenesis` and no Production state is
/// built. FLIPPED (Lane A1, candidate 3): this test formerly built the V1 Production Genesis; the
/// state-level Production-class properties stay covered by the T6 tests below.
#[test]
fn authority_attestation_is_the_anchor_consistent_software_provenance_passes_the_v1_class_rule_but_production_is_refused() {
    let tpm = TestTpm::stripped(Strip::ConsistentProvenance(root()));
    let case = genesis_case(&tpm, true, true).unwrap();
    assert_eq!(
        genesis_admission_class(&case.descriptor, &case.input, GenesisProfile::Production),
        Ok(AdmissionClass::Production),
        "the material satisfies the V1 Production class rule"
    );
    assert_eq!(
        validate_production_descriptor(&case.descriptor, &case.rules, case.target).err(),
        Some(mutiny_consensus_v8::Error::V1NotProductionGenesis)
    );
    assert_eq!(
        initial(&case, GenesisProfile::Production).err(),
        Some(mutiny_consensus_v8::Error::V1NotProductionGenesis)
    );
    assert_eq!(
        mutiny_consensus_v8::genesis_inputs::V1_PRODUCTION_REFUSAL,
        "V1 is not a Production Genesis implementation (Order A9)"
    );
}

// ------------------------------------------------------------------------------------------
// T6: Bond / reconstruction (V1)
// ------------------------------------------------------------------------------------------
/// T6 (ii): a marked or provenance-less approved profile injected into a Production-class book is
/// refused by `AdmissionBook::records`, by `AdmissionBook::from_records` and by
/// `State::from_records` (reconstruction applies the admission rule). The same book is valid in
/// the Legacy/Test class.
#[test]
fn production_class_reconstruction_refuses_injected_software_profiles() {
    let policy = software_tpm::fixture_policy();
    let parameters = software_tpm::production_parameters(&policy.endorsement_roots);
    for (name, tpm) in [
        ("marked", TestTpm::new()),
        ("provenance-less", TestTpm::stripped(Strip::Both)),
    ] {
        let approved = software_tpm::approve(&policy, root(), tpm.profile());
        let commitment = tpm.profile().commitment().unwrap();
        let book = AdmissionBook {
            policy: Some(policy.clone()),
            profiles: [(commitment, approved)].into_iter().collect(),
        };
        let records = book.records(AdmissionClass::LegacyTest).unwrap();
        assert!(book.records(AdmissionClass::Production).is_err(), "{name}");
        assert_eq!(AdmissionBook::from_records(&records, None).unwrap(), book);
        assert!(AdmissionBook::from_records(&records, Some(&parameters)).is_err(), "{name}");
        // Whole-state reconstruction with the committed parameters record.
        let mut rows: Vec<(Hash, Vec<u8>)> = records.into_iter().collect();
        rows.push((parameters_key(), parameters.clone()));
        rows.sort();
        let state_root = blocks::state_root(&rows).unwrap();
        assert!(State::from_records(&rows, state_root).is_err(), "{name}");
    }
}

/// T6 (ii), the V1 committed-state backstop itself (`State::records` ->
/// `AdmissionBook::records(class)`): a Production-class V1 state holding an injected marked or
/// provenance-less approved profile has no StateRoot; the same state without the declaration
/// (Legacy/Test) has one; the T14 limit profile has one in both classes.
#[test]
fn production_class_v1_state_has_no_root_over_injected_software_profiles() {
    let policy = software_tpm::fixture_policy();
    let parameters = software_tpm::production_parameters(&policy.endorsement_roots);
    for (name, tpm, ok_in_production) in [
        ("marked", TestTpm::new(), false),
        ("provenance-less", TestTpm::stripped(Strip::Both), false),
        ("consistent (T14 limit)", TestTpm::stripped(Strip::ConsistentProvenance(root())), true),
    ] {
        let mut state = State::default();
        state.admission.policy = Some(policy.clone());
        state
            .admission
            .profiles
            .insert(tpm.profile().commitment().unwrap(), software_tpm::approve(&policy, root(), tpm.profile()));
        assert!(state.root().is_ok(), "{name}: Legacy/Test state root");
        state.protocol_records.insert(parameters_key(), parameters.clone());
        assert_eq!(state.admission_class().unwrap(), AdmissionClass::Production, "{name}");
        assert_eq!(state.root().is_ok(), ok_in_production, "{name}");
    }
}

// ------------------------------------------------------------------------------------------
// V2 (hybrid candidate stack): JOIN through the parent state, and the committed-state backstop
// ------------------------------------------------------------------------------------------
mod v2 {
    use super::*;
    use mutiny_consensus_v8::{
        NETWORK_ID,
        admission_policy_v2::Record,
        admission_v2::{Admission, Expected, Policy},
        anchors::FinalizedAnchor,
        join_v2::Join,
        node_admission_v2::{Binding, node_id},
    };
    use mutiny_crypto_v2::HybridSignature;
    pub struct Setup {
        pub owner: HybridKey,
        pub policy: Policy,
        pub state: State,
        pub parent: FinalizedAnchor,
    }
    pub fn setup(production: bool) -> Setup {
        let owner = HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner).unwrap();
        let policy = Policy {
            genesis: [1; 32],
            fingerprint: [2; 32],
            owner_descriptor: owner.public().descriptor(1).unwrap(),
            endorsement_roots: roots(),
        };
        let mut state = State::default();
        state.wallets.register(&policy.owner_descriptor).unwrap();
        state.admission_policy_v2 = Some(Record::new(policy.clone()).unwrap());
        if production {
            state
                .protocol_records
                .insert(parameters_key(), software_tpm::production_parameters(&roots()));
        }
        let parent = FinalizedAnchor { network: NETWORK_ID, genesis: [1; 32], fingerprint: [2; 32], height: 59, block: [8; 32] };
        Setup { owner, policy, state, parent }
    }
    /// A complete owner-authorized hybrid join for the simulator profile `tpm`.
    pub fn join(s: &Setup, tpm: &TestTpm) -> Join {
        let continuity = HybridKey::generate(Role::Continuity).unwrap();
        let node = HybridKey::generate(Role::Node).unwrap();
        let node_descriptor = node.public().descriptor(1).unwrap();
        let zero = HybridSignature { ed448: [0; 114], fndsa: [0; 1280] };
        let binding = Binding {
            node_signer: None,
            admission: Admission {
                genesis: s.policy.genesis,
                fingerprint: s.policy.fingerprint,
                node: node_id(s.policy.genesis, &node_descriptor).unwrap(),
                hardware_generation: 1,
                key_generation: 1,
                continuity_descriptor: continuity.public().descriptor(1).unwrap(),
                profile: tpm.profile().encode().unwrap(),
                endorsement_root: root(),
                owner: s.owner.public().address_id(1).unwrap(),
                supervised_nonce: [5; 32],
                quote: vec![],
                possession: zero.clone(),
                authorization: zero.clone(),
            },
            node_descriptor,
            possession: zero,
        };
        let mut join = Join { parent: s.parent.clone(), nonce: [7; 32], binding };
        join.binding.admission.supervised_nonce = join.admission_nonce().unwrap();
        join.binding.admission.prove_continuity(&continuity).unwrap();
        join.binding.admission.quote = tpm.quote(join.binding.admission.challenge().unwrap());
        join.binding.admission.authorize(&s.owner, 1).unwrap();
        join.binding.sign(&node).unwrap();
        join
    }
    pub fn expected(join: &Join) -> Expected {
        Expected {
            node: join.binding.admission.node,
            hardware_generation: 1,
            key_generation: 1,
            supervised_nonce: join.binding.admission.supervised_nonce,
        }
    }
    /// A one-member V2 state (genesis book + registry) at parent height 58 whose member is the
    /// simulator identity `genesis`; `production` adds the committed trust-root declaration.
    pub struct Lifecycle {
        pub setup: Setup,
        pub state: State,
        pub parent: FinalizedAnchor,
        pub node_key: HybridKey,
        pub node: Hash,
    }
    pub fn lifecycle(production: bool, genesis: &TestTpm) -> Lifecycle {
        use mutiny_consensus_v8::{
            membership_v2::Book,
            recovery::{Anchor, ContinuityState, Member},
        };
        let class = if production { AdmissionClass::Production } else { AdmissionClass::LegacyTest };
        let setup = setup(production);
        let continuity = HybridKey::generate(Role::Continuity).unwrap();
        let node_key = HybridKey::generate(Role::Node).unwrap();
        let node_descriptor = node_key.public().descriptor(1).unwrap();
        let zero = HybridSignature { ed448: [0; 114], fndsa: [0; 1280] };
        let mut binding = Binding {
            node_signer: None,
            admission: Admission {
                genesis: setup.policy.genesis,
                fingerprint: setup.policy.fingerprint,
                node: node_id(setup.policy.genesis, &node_descriptor).unwrap(),
                hardware_generation: 1,
                key_generation: 1,
                continuity_descriptor: continuity.public().descriptor(1).unwrap(),
                profile: genesis.profile().encode().unwrap(),
                endorsement_root: root(),
                owner: setup.owner.public().address_id(1).unwrap(),
                supervised_nonce: [5; 32],
                quote: vec![],
                possession: zero.clone(),
                authorization: zero.clone(),
            },
            node_descriptor,
            possession: zero,
        };
        binding.admission.prove_continuity(&continuity).unwrap();
        binding.admission.quote = genesis.quote(binding.admission.challenge().unwrap());
        binding.admission.authorize(&setup.owner, 1).unwrap();
        binding.sign(&node_key).unwrap();
        let node = binding.admission.node;
        let expected = Expected { node, hardware_generation: 1, key_generation: 1, supervised_nonce: [5; 32] };
        let mut state = setup.state.clone();
        (state.membership_v2, state.continuity_keys_v2) =
            Book::genesis(&binding, &setup.policy, &expected, &state.wallets, class).unwrap();
        state.continuity = Some(
            ContinuityState::bootstrap(
                setup.policy.genesis,
                setup.policy.fingerprint,
                Anchor { height: 0, tip: [19; 32], state_root: [0; 32], registry_root: [0; 32] },
                [20; 32],
                vec![Member {
                    lineage: node,
                    node,
                    hardware: genesis.profile().hardware,
                    generation: 1,
                    voting_key: genesis.voting_point(),
                    attestation: genesis.profile().commitment().unwrap(),
                    history: Default::default(),
                    physical: true,
                    eligible: true,
                    genesis_member: true,
                }],
            )
            .unwrap(),
        );
        state.accounting.slots.last_height = 58;
        state.accounting.slots.period = 0;
        let parent = FinalizedAnchor {
            network: NETWORK_ID,
            genesis: setup.policy.genesis,
            fingerprint: setup.policy.fingerprint,
            height: 58,
            block: [19; 32],
        };
        Lifecycle { setup, state, parent, node_key, node }
    }
    /// An ordinary V2 hardware rotation of the lifecycle member to the simulator profile `tpm`.
    pub fn hardware_rotation(l: &Lifecycle, tpm: &TestTpm) -> mutiny_consensus_v8::hardware_rotate_v2::HardwareRotate {
        let continuity = HybridKey::generate(Role::Continuity).unwrap();
        let mut rotation = mutiny_consensus_v8::hardware_rotate_v2::HardwareRotate {
            parent: l.parent.clone(),
            nonce: [56; 32],
            sequence: 1,
            old_hardware_generation: 1,
            old_key_generation: 1,
            binding: l.state.membership_v2.get(l.node).unwrap().binding().clone(),
            native_possession: [0; 64],
        };
        rotation.binding.admission.hardware_generation = 2;
        rotation.binding.admission.key_generation = 2;
        rotation.binding.admission.continuity_descriptor = continuity.public().descriptor(2).unwrap();
        rotation.binding.admission.profile = tpm.profile().encode().unwrap();
        rotation.binding.admission.supervised_nonce = rotation.admission_nonce().unwrap();
        rotation.binding.admission.prove_continuity(&continuity).unwrap();
        rotation.binding.admission.quote = tpm.quote(rotation.binding.admission.challenge().unwrap());
        rotation.binding.admission.authorize(&l.setup.owner, 1).unwrap();
        rotation.binding.sign(&l.node_key).unwrap();
        rotation.native_possession = tpm.possession(rotation.native_digest().unwrap());
        rotation
    }
}

/// T3 (V2 JOIN): in the Production class the parent-bound `Join::verify` (policy, wallets and
/// class all from the parent state) rejects the marked profile, the stripped variants and every
/// one-field provenance inconsistency; `Admission::verify` (the V2 choke point used by JOIN,
/// key and hardware rotation and recovery replacement) rejects them with the class supplied.
/// The marked profile is still accepted in the Legacy/Test class (unchanged behaviour).
#[test]
fn production_class_v2_join_and_admission_reject_marked_stripped_and_inconsistent_software_profiles() {
    let production = v2::setup(true);
    assert_eq!(production.state.admission_class().unwrap(), AdmissionClass::Production);
    let state_root = production.state.root().unwrap();
    for (name, tpm, _) in software_tpm::production_negative_variants(root()) {
        let join = v2::join(&production, &tpm);
        assert!(refused_before_scope(join.verify(&production.state, &production.parent, state_root)), "{name}");
        assert!(
            join.binding
                .admission
                .verify(&production.policy, &v2::expected(&join), &production.state.wallets, AdmissionClass::Production)
                .is_err(),
            "{name}"
        );
    }
    let legacy = v2::setup(false);
    let join = v2::join(&legacy, &TestTpm::new());
    join.verify(&legacy.state, &legacy.parent, legacy.state.root().unwrap()).unwrap();
}

/// Order A8 (candidate 3; formerly the T14 acceptance `authority_attestation_is_the_anchor_
/// consistent_software_provenance_joins_v2_production_class`): the policy owner's signature ALONE
/// no longer admits hardware after sealing. The same owner-authorized JOIN of consistent self-made
/// software provenance that passed before is refused in the Production class with exactly
/// `AdmissionAuthorityEnded`; the Legacy/Test class still verifies it (the construction is valid).
#[test]
fn policy_owner_signature_alone_cannot_join_after_sealing_v2_production_class() {
    let production = v2::setup(true);
    let tpm = TestTpm::stripped(Strip::ConsistentProvenance(root()));
    let join = v2::join(&production, &tpm);
    assert!(refused_by_scope(join.verify(&production.state, &production.parent, production.state.root().unwrap())));
    let legacy = v2::setup(false);
    let join = v2::join(&legacy, &tpm);
    join.verify(&legacy.state, &legacy.parent, legacy.state.root().unwrap()).unwrap();
}

/// Committed-state backstop (V2): a Legacy/Test-admitted genesis book whose binding carries the
/// marked simulator profile has a StateRoot; the moment the same state declares the Production
/// root set it has none (`State::records` applies the class rule to every current binding), and
/// `membership_v2::Book::genesis` itself refuses the binding in the Production class.
#[test]
fn production_class_state_cannot_commit_a_software_marked_v2_binding() {
    use mutiny_consensus_v8::membership_v2::Book;
    let legacy = v2::setup(false);
    let join = v2::join(&legacy, &TestTpm::new());
    let expected = v2::expected(&join);
    let mut state = legacy.state.clone();
    (state.membership_v2, state.continuity_keys_v2) =
        Book::genesis(&join.binding, &legacy.policy, &expected, &state.wallets, AdmissionClass::LegacyTest).unwrap();
    assert!(Book::genesis(&join.binding, &legacy.policy, &expected, &state.wallets, AdmissionClass::Production).is_err());
    let profile = tpm_profile(&join);
    state.continuity = Some(
        mutiny_consensus_v8::recovery::ContinuityState::bootstrap(
            legacy.policy.genesis,
            legacy.policy.fingerprint,
            mutiny_consensus_v8::recovery::Anchor { height: 0, tip: [19; 32], state_root: [0; 32], registry_root: [0; 32] },
            [20; 32],
            vec![mutiny_consensus_v8::recovery::Member {
                lineage: join.binding.admission.node,
                node: join.binding.admission.node,
                hardware: profile.hardware,
                generation: 1,
                voting_key: mutiny_consensus_v8::tpm::public_key(&profile.voting_public, false).unwrap(),
                attestation: profile.commitment().unwrap(),
                history: Default::default(),
                physical: true,
                eligible: true,
                genesis_member: true,
            }],
        )
        .unwrap(),
    );
    state.root().unwrap();
    let mut declared = state.clone();
    declared
        .protocol_records
        .insert(parameters_key(), software_tpm::production_parameters(&roots()));
    assert_eq!(declared.admission_class().unwrap(), AdmissionClass::Production);
    assert!(declared.root().is_err());
}
fn tpm_profile(join: &mutiny_consensus_v8::join_v2::Join) -> TpmProfile {
    TpmProfile::decode(&join.binding.admission.profile).unwrap()
}

/// T3 (V2 JOIN through the lifecycle transition, i.e. `membership_v2::Book::stage_join`) and Order
/// A8: in a Production-class V2 state every marked, stripped or provenance-inconsistent joining
/// profile makes `continuity_lifecycle_v2::transition` fail on its own check, with the parent state
/// unchanged and no member, key or freshness record; since candidate 3 the consistent self-made,
/// owner-authorized statement (the former T14 acceptance) is refused too, exactly by the post-sealing
/// scope rule, while the same JOIN still stages in a Legacy/Test-class state.
#[test]
fn production_class_v2_lifecycle_join_refuses_software_profiles_and_the_owner_signed_limit() {
    use mutiny_consensus_v8::{blocks::BlockBody, continuity_lifecycle_v2::transition, join_v2::Join};
    let genesis = TestTpm::with_identity("v2-genesis").strip(Strip::ConsistentProvenance(root()));
    let l = v2::lifecycle(true, &genesis);
    let state_root = l.state.root().unwrap();
    let join_for = |tpm: &TestTpm| -> Join {
        let mut s = v2::setup(true);
        s.parent = l.parent.clone();
        v2::join(&s, tpm)
    };
    let body = |join: &Join| BlockBody {
        height: 59,
        reward_owner: [30; 32],
        fees: 0,
        transactions: vec![],
        operations: vec![join.encode().unwrap()],
    };
    for (name, tpm, _) in software_tpm::production_negative_variants(root()) {
        let before = l.state.clone();
        let join = join_for(&tpm);
        assert!(refused_before_scope(transition(&l.state, &l.parent, state_root, &body(&join))), "{name}");
        assert_eq!(l.state, before, "{name}");
    }
    let limit = TestTpm::stripped(Strip::ConsistentProvenance(root()));
    let join = join_for(&limit);
    let before = l.state.clone();
    assert!(refused_by_scope(transition(&l.state, &l.parent, state_root, &body(&join))));
    assert_eq!(l.state, before);
    // Positive control: the same JOIN stages in the Legacy/Test class.
    let legacy = v2::lifecycle(false, &genesis);
    let result = transition(&legacy.state, &legacy.parent, legacy.state.root().unwrap(), &body(&join)).unwrap();
    assert!(result.keys.get(join.binding.admission.node).is_some());
    let staged = result.registry.members.iter().find(|m| m.node == join.binding.admission.node).unwrap();
    assert!(!staged.eligible && staged.history.p == 0, "staged with zero weight (unchanged join rule)");
}

/// T4 (V2 hardware rotation, `hardware_rotate_v2::HardwareRotate::verify` with the policy, wallets
/// and class of the parent state) and Order A8: in the Production class a rotation to a marked,
/// stripped or provenance-inconsistent software profile is refused on its own check; since
/// candidate 3 the consistent self-made, owner-authorized rotation (the former T14 acceptance) is
/// refused exactly by the post-sealing scope rule. The Legacy/Test class is unchanged.
#[test]
fn production_class_v2_hardware_rotation_refuses_software_profiles_and_the_owner_signed_limit() {
    let genesis = TestTpm::with_identity("v2-genesis").strip(Strip::ConsistentProvenance(root()));
    let l = v2::lifecycle(true, &genesis);
    let state_root = l.state.root().unwrap();
    for (name, tpm, _) in software_tpm::production_negative_variants(root()) {
        let rotation = v2::hardware_rotation(&l, &tpm);
        assert!(refused_before_scope(rotation.verify(&l.state, &l.parent, state_root)), "{name}");
    }
    let limit = TestTpm::stripped(Strip::ConsistentProvenance(root()));
    assert!(refused_by_scope(v2::hardware_rotation(&l, &limit).verify(&l.state, &l.parent, state_root)));
    // Legacy/Test class: the marked simulator rotation is accepted (unchanged behaviour).
    let legacy = v2::lifecycle(false, &TestTpm::with_identity("v2-genesis"));
    v2::hardware_rotation(&legacy, &TestTpm::new())
        .verify(&legacy.state, &legacy.parent, legacy.state.root().unwrap())
        .unwrap();
}

// ------------------------------------------------------------------------------------------
// T5 (V2 RECOVERY replacement): `recovery_replacement_v2::Replacement::verify_material` and
// `recovery_transition_v2::Prepared::verify`, with the class of the parent state
// ------------------------------------------------------------------------------------------
mod v2_recovery {
    use super::*;
    use mutiny_consensus_v8::{
        NETWORK_ID, admission_policy_v2,
        admission_v2::{Admission, Expected, Policy},
        anchors::FinalizedAnchor,
        domain_hash, license_book_v2, membership_v2,
        node_admission_v2::{Binding, node_id},
        recovery::{Anchor, ContinuityState, Member},
        recovery_authority_v2::{Authority, Authorization},
        recovery_history_v2,
        recovery_replacement_v2::Replacement,
        recovery_transition_v2,
        recovery_witness_v2::Witnesses,
        state_tree::StateTree,
        votes_v2::HeightAuthority,
    };
    use mutiny_crypto_v2::HybridSignature;
    /// A one-member V2 state (genesis member `genesis`, owner-authorized, a recovery authority and
    /// the shared License fixture; `production` adds the committed trust-root declaration) and an
    /// owner-authorized, recovery-authority-signed replacement of that member by `replacement`.
    /// Returns the results of (`Replacement::verify_material`, `Prepared::verify`).
    pub fn replace(
        production: bool,
        genesis: &TestTpm,
        replacement: &TestTpm,
    ) -> (mutiny_consensus_v8::Result<()>, mutiny_consensus_v8::Result<()>) {
        let phrase = format!("{}art", "abandon ".repeat(23));
        let owner = HybridKey::wallet_restore(&phrase, Role::WalletOwner).unwrap();
        let recovery = HybridKey::wallet_restore(&phrase, Role::WalletRecovery).unwrap();
        let old_node = HybridKey::generate(Role::Node).unwrap();
        let old_continuity = HybridKey::generate(Role::Continuity).unwrap();
        let new_node = HybridKey::generate(Role::Node).unwrap();
        let new_continuity = HybridKey::generate(Role::Continuity).unwrap();
        let policy = Policy {
            genesis: [1; 32],
            fingerprint: [2; 32],
            owner_descriptor: owner.public().descriptor(1).unwrap(),
            endorsement_roots: roots(),
        };
        let class = if production { AdmissionClass::Production } else { AdmissionClass::LegacyTest };
        let descriptor = old_node.public().descriptor(1).unwrap();
        let id = node_id(policy.genesis, &descriptor).unwrap();
        let zero = HybridSignature { ed448: [0; 114], fndsa: [0; 1280] };
        let mut binding = Binding {
            node_signer: None,
            node_descriptor: descriptor,
            possession: zero.clone(),
            admission: Admission {
                genesis: policy.genesis,
                fingerprint: policy.fingerprint,
                node: id,
                hardware_generation: 1,
                key_generation: 1,
                continuity_descriptor: old_continuity.public().descriptor(1).unwrap(),
                profile: genesis.profile().encode().unwrap(),
                endorsement_root: root(),
                owner: owner.public().address_id(1).unwrap(),
                supervised_nonce: [5; 32],
                quote: vec![],
                possession: zero.clone(),
                authorization: zero,
            },
        };
        binding.admission.prove_continuity(&old_continuity).unwrap();
        binding.admission.quote = genesis.quote(binding.admission.challenge().unwrap());
        binding.admission.authorize(&owner, 1).unwrap();
        binding.sign(&old_node).unwrap();
        let mut state = State::default();
        state.wallets.register(&policy.owner_descriptor).unwrap();
        state.admission_policy_v2 = Some(admission_policy_v2::Record::new(policy.clone()).unwrap());
        if production {
            state
                .protocol_records
                .insert(parameters_key(), software_tpm::production_parameters(&policy.endorsement_roots));
        }
        assert_eq!(state.admission_class().unwrap(), class);
        (state.membership_v2, state.continuity_keys_v2) = membership_v2::Book::genesis(
            &binding,
            &policy,
            &Expected { node: id, hardware_generation: 1, key_generation: 1, supervised_nonce: [5; 32] },
            &state.wallets,
            class,
        )
        .unwrap();
        state.continuity = Some(
            ContinuityState::bootstrap(
                policy.genesis,
                policy.fingerprint,
                Anchor { height: 0, tip: [19; 32], state_root: [0; 32], registry_root: [0; 32] },
                [20; 32],
                vec![Member {
                    lineage: id,
                    node: id,
                    hardware: genesis.profile().hardware,
                    generation: 1,
                    voting_key: genesis.voting_point(),
                    attestation: genesis.profile().commitment().unwrap(),
                    history: Default::default(),
                    physical: true,
                    eligible: true,
                    genesis_member: true,
                }],
            )
            .unwrap(),
        );
        state.recovery_authority_v2 = Some(Authority {
            genesis: policy.genesis,
            fingerprint: policy.fingerprint,
            descriptor: recovery.public().descriptor(1).unwrap(),
        });
        let (license_owner, assignments, expected, licenses, _coordinator) = license_fixture::fixtures();
        assert_eq!(license_owner.public(), owner.public());
        state.licenses_v2 = license_book_v2::Book::genesis(
            &assignments,
            &expected,
            &licenses,
            &state.wallets,
            policy.genesis,
            policy.fingerprint,
        )
        .unwrap();
        let parent = FinalizedAnchor {
            network: NETWORK_ID,
            genesis: policy.genesis,
            fingerprint: policy.fingerprint,
            height: 0,
            block: [19; 32],
        };
        let root = state.root().unwrap();
        let authority = HeightAuthority::from_state(&state, parent.clone(), root).unwrap();
        binding.node_descriptor = new_node.public().descriptor(1).unwrap();
        binding.admission.node = node_id(policy.genesis, &binding.node_descriptor).unwrap();
        binding.admission.hardware_generation = 2;
        binding.admission.key_generation = 2;
        binding.admission.continuity_descriptor = new_continuity.public().descriptor(2).unwrap();
        binding.admission.profile = replacement.profile().encode().unwrap();
        let mut material = Replacement {
            parent: parent.clone(),
            root,
            membership: authority.membership,
            sequence: 1,
            lineage: id,
            old_node: id,
            old_hardware_generation: 1,
            old_key_generation: 1,
            nonce: [57; 32],
            lost: vec![(id, 1)],
            binding,
            native_possession: [0; 64],
        };
        material.binding.admission.supervised_nonce = material.admission_nonce().unwrap();
        material.binding.admission.prove_continuity(&new_continuity).unwrap();
        material.binding.admission.quote = replacement.quote(material.binding.admission.challenge().unwrap());
        material.binding.admission.authorize(&owner, 1).unwrap();
        material.binding.sign(&new_node).unwrap();
        material.native_possession = replacement.possession(material.native_digest().unwrap());
        let authorization = Authorization::sign(
            material.intent().unwrap(),
            state.recovery_authority_v2.as_ref().unwrap(),
            &recovery,
        )
        .unwrap();
        let direct = material.verify_material(&state, &parent, root, &authorization, false);
        let mut tree = StateTree::default();
        for (key, raw) in state.records().unwrap() {
            tree.insert(key, raw).unwrap();
        }
        let witnesses = Witnesses {
            control: tree.proof(parent.clone(), domain_hash(b"MUTINY-BUILD8-NODE-CONTROL-KEY-V2", &id)),
            continuity: tree.proof(parent.clone(), domain_hash(b"MUTINY-BUILD8-CONTINUITY-KEY-STATE-V2", &id)),
        };
        let archive = recovery_history_v2::Record { material, authorization, witnesses, policy };
        let prepared = recovery_transition_v2::Prepared::verify(&state, &parent, root, archive, false).map(|_| ());
        (direct, prepared)
    }
}

/// T5 (V2 RECOVERY replacement) and Order A8: in the Production class a recovery replacement whose
/// new binding carries a marked, marker-stripped, relabeled or provenance-inconsistent software
/// profile is refused on its own check by `Replacement::verify_material` (class from the parent
/// state) and by `recovery_transition_v2::Prepared::verify`. Since candidate 3 the consistent
/// owner-authorized replacement (the former T14 acceptance) is refused exactly by the post-sealing
/// scope rule. Positive controls: the same limit replacement and the marked simulator recover in the
/// Legacy/Test class (unchanged behaviour).
#[test]
fn production_class_v2_recovery_replacement_refuses_software_profiles_and_the_owner_signed_limit() {
    let genesis = TestTpm::with_identity("v2-recovery-genesis").strip(Strip::ConsistentProvenance(root()));
    for (name, tpm, _) in software_tpm::production_negative_variants(root()) {
        let (direct, prepared) = v2_recovery::replace(true, &genesis, &tpm);
        assert!(refused_before_scope(direct), "verify_material accepted {name}");
        assert!(refused_before_scope(prepared), "Prepared::verify accepted {name}");
    }
    let limit = TestTpm::stripped(Strip::ConsistentProvenance(root()));
    let (direct, prepared) = v2_recovery::replace(true, &genesis, &limit);
    assert!(refused_by_scope(direct));
    assert!(refused_by_scope(prepared));
    let legacy_genesis = TestTpm::with_identity("v2-recovery-genesis");
    let (direct, prepared) = v2_recovery::replace(false, &legacy_genesis, &limit);
    direct.unwrap();
    prepared.unwrap();
    let (direct, prepared) = v2_recovery::replace(false, &genesis, &TestTpm::new());
    direct.unwrap();
    prepared.unwrap();
}

/// Candidate 3, Order A4: a V2 recovery replacement may not commit an endorsement identity that is already committed, here
/// the LOST member's own identity as a secondary identity of the replacement (exactly as the replacement may not reuse its
/// `hardware`): refused with `Duplicate` by `Replacement::verify_material` and `Prepared::verify`. Legacy/Test class, because
/// in the Production class every post-sealing replacement is refused by the A8 rule first. The same replacement without
/// the shared identity recovers.
#[test]
fn v2_recovery_replacement_cannot_reuse_a_committed_endorsement_identity() {
    let genesis = TestTpm::with_identity("v2-recovery-identity").strip(Strip::ConsistentProvenance(root()));
    let base = TestTpm::with_identity("v2-recovery-replacement").strip(Strip::ConsistentProvenance(root()));
    let mut statement = base.profile().provenance.clone().unwrap();
    statement.endorsement.as_mut().unwrap().identities.push((root(), genesis.ek_identity()));
    let reusing = base.with_provenance(statement);
    assert_ne!(reusing.profile().hardware, genesis.profile().hardware);
    let (direct, prepared) = v2_recovery::replace(false, &genesis, &reusing);
    assert_eq!(direct, Err(mutiny_consensus_v8::Error::Duplicate));
    assert_eq!(prepared, Err(mutiny_consensus_v8::Error::Duplicate));
    let (direct, prepared) = v2_recovery::replace(false, &genesis, &base);
    direct.unwrap();
    prepared.unwrap();
}

// ------------------------------------------------------------------------------------------
// Domain registry (PROPOSED/unfrozen entries)
// ------------------------------------------------------------------------------------------
#[test]
fn new_domains_are_registered_as_proposed_and_unfrozen() {
    let registry: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("../spec/DOMAIN-REGISTRY-V1.json").unwrap()).unwrap();
    let listed = registry["domains"].as_array().unwrap();
    for domain in [
        provenance::PROVENANCE_DOMAIN,
        provenance::PLATFORM_PROFILE_DOMAIN,
        provenance::TRUST_ROOTS_DOMAIN,
    ] {
        let ascii = std::str::from_utf8(domain).unwrap();
        let entries: Vec<_> = listed.iter().filter(|e| e["ascii"] == ascii).collect();
        assert_eq!(entries.len(), 1, "{ascii} registered exactly once");
        assert_eq!(entries[0]["status"], "PROPOSED-UNFROZEN", "{ascii}");
    }
    // The rule-manifest entry name is documented with the trust-roots domain.
    let roots_entry = listed
        .iter()
        .find(|e| e["ascii"] == std::str::from_utf8(provenance::TRUST_ROOTS_DOMAIN).unwrap())
        .unwrap();
    assert!(roots_entry["body"].as_str().unwrap().contains("physical-admission-trust-roots-v1"));
}

/// The public TEST-VALUE example printed in docs/PHYSICAL-ADMISSION-ENFORCEMENT-V1.md section 5
/// (computed independently from the schema text; this pins the Rust encoding to it). Simulator
/// limit material (T14), not evidence.
#[test]
fn documented_test_value_provenance_example_matches_the_encoder() {
    const PROVENANCE: &str = "86015820fef7ba57cb5be22c726c654257dbc3911f6470a9194baa17ddd9bf5c7af322665820705493ec23029699ac5e5c5c0dc191ec41e42fd279dbbc8674379fa22b6c2d7f5822000b867490fe24b0d860d8bb55dd1394b38e8df502eb8d27f07e69f9782d5001615e5820524465ec946a87917d91a99adf35a5c85f9ef6a43125a7a890dd0707eeaaf4cc85820158208cf9c77b16656e3d12dd38ad83f29d93368889c6aa76ecc7a35ef44907fae67e82025820bf37fb90e3e98cc24cf8567024b829f9ad26c0b3b6b03fe877ff62d123088079820358207fec6057ffe37d01b0851fe0bd7b5a2b79cccaa6644cee2d3c0083a646b7635f82045820d58bc81f072f28ca115c32fdf6283a419328034b88c8941b293de3b6e4ba2eb68205582048b7de525a49c0b30ed0c87a36ee69a5158f533847c196f957a1ee4f0bf12143";
    const MANIFEST: &str = "dee7106a724b2db25c36b4f50357d51feaca6bb84e9d57ab5f7639e135e48ab8";
    const TRUST_ROOTS: &str = "57fc4e1dfc32b27d814340a2aec15bad77138bda2e209a6d0a7e94f9f3876544";
    let tpm = TestTpm::stripped(Strip::ConsistentProvenanceV1(root()));
    let statement = tpm.profile().provenance.clone().unwrap();
    assert_eq!(hex::encode(statement.encode()), PROVENANCE);
    assert_eq!(hex::encode(tpm.profile().admission_trust_manifest), MANIFEST);
    assert_eq!(hex::encode(provenance::trust_roots_commitment(&roots()).unwrap()), TRUST_ROOTS);
}

/// T12 (ii): transport configuration (`allowed_peers` pins a peer's TRANSPORT key) is not consensus
/// authority. A configured peer that is not a committed registry member cannot produce an accepted
/// vote (UnknownSigner); a registry member that is not physical and eligible has zero weight; only
/// the committed physical member's signature is counted.
#[test]
fn a_configured_peer_absent_from_the_committed_registry_cannot_vote() {
    use mutiny_consensus_v8::{
        Error, NETWORK_ID,
        certificates::{Certificate, Decision, Signer as CertSigner},
        recovery::{Anchor, ContinuityState, Member},
    };
    let tpm = TestTpm::new();
    let physical = Member {
        lineage: [1; 32],
        node: [1; 32],
        hardware: tpm.profile().hardware,
        generation: 0,
        voting_key: tpm.voting_point(),
        attestation: tpm.profile().commitment().unwrap(),
        history: Default::default(),
        physical: true,
        eligible: true,
        genesis_member: true,
    };
    let peer = TestTpm::with_identity("configured-peer");
    let cloud = Member {
        lineage: [2; 32],
        node: [2; 32],
        hardware: [2; 32],
        generation: 0,
        voting_key: peer.voting_point(),
        attestation: [2; 32],
        history: Default::default(),
        physical: false,
        eligible: false,
        genesis_member: false,
    };
    let registry = ContinuityState::bootstrap(
        [1; 32],
        [2; 32],
        Anchor { height: 0, tip: [3; 32], state_root: [0; 32], registry_root: [0; 32] },
        [4; 32],
        vec![physical, cloud],
    )
    .unwrap();
    let voters = registry.voters().unwrap();
    let decision = Decision {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        purpose: 2,
        height: 1,
        mining_epoch: 1,
        continuity_period: 0,
        round: 0,
        step: 3,
        previous_finalized_anchor: [5; 32],
        parent: [3; 32],
        block: [6; 32],
        state: [7; 32],
        membership: [8; 32],
        reputation: [9; 32],
        attestation: [10; 32],
    };
    let sign = |tpm: &TestTpm, node: Hash| CertSigner {
        node,
        key_version: 0,
        signature: tpm.possession(decision.signing_digest(node, 0)),
    };
    // A peer absent from the registry (an allowed transport peer is not a member).
    let outsider = Certificate { decision: decision.clone(), signers: vec![sign(&peer, [9; 32])] };
    assert!(matches!(outsider.verify_quorum(&decision, &voters), Err(Error::UnknownSigner)));
    // A member that is not physical and eligible carries zero weight.
    let zero = Certificate { decision: decision.clone(), signers: vec![sign(&peer, [2; 32])] };
    assert!(zero.verify_quorum(&decision, &voters).is_err());
    // The committed physical member's signature is the only one counted.
    let member = Certificate { decision: decision.clone(), signers: vec![sign(&tpm, [1; 32])] };
    member.verify_quorum(&decision, &voters).unwrap();
}
