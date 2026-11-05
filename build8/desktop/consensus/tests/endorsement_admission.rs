//! Candidate 3, Lane A2 (Order of 4 Oct 2026, decisions A4 and A8): canonical endorsement identity, duplicate-live-lineage
//! rejection over every committed identity, the version-2 provenance statement with check C6, the end of the admission
//! authority at sealing, and Treasury/admission role separation. Design: `qualification/candidate-3/A-ADMISSION-DESIGN-V1.md`.
//!
//! SIMULATED != PHYSICAL. Every profile is deterministic software-simulator material, every endorsement key a public
//! TEST-VALUE key; a passing test proves software behaviour only. Block-path tests run the V2 lifecycle transition (the V2
//! block executor of membership operations) and compare the parent StateRoot and records before and after a refusal.
#[path = "support/software_tpm.rs"]
mod software_tpm;
#[path = "support/test_value_ek.rs"]
mod test_value_ek;
use mutiny_consensus_v8::{
    Error, Hash, NETWORK_ID, domain_hash,
    admission_policy_v2::Record,
    admission_scope::*,
    admission_v2::{Admission, Expected, Policy},
    anchors::FinalizedAnchor,
    blocks::BlockBody,
    continuity_keys_v2::Book as KeyBook,
    continuity_lifecycle_v2::{Transition, transition},
    dividend_state_v1::DividendState,
    endorsement_identity::*,
    execution::{ExecutionError, State},
    genesis_inputs::parameters_key,
    hardware_rotate_v2::HardwareRotate,
    join_v2::Join,
    membership::NodeControl,
    membership_v2::Book,
    node_admission_v2::{Binding, node_id},
    provenance::{self, AdmissionClass, Failure, PROVENANCE_V2_DOMAIN, Provenance},
    recovery::{Anchor, ContinuityState, Member},
    tpm::TpmProfile,
    treasury_v1::{Class, Treasury},
};
use mutiny_crypto_v2::{HybridKey, HybridSignature, Role};
use sha2::{Digest, Sha256};
use software_tpm::{Strip, TestTpm};
use std::collections::BTreeSet;

fn root() -> Hash {
    software_tpm::test_value_endorsement_root()
}
fn roots() -> BTreeSet<Hash> {
    [root()].into()
}
/// A simulator identity whose version-2 statement commits `identities` (class order) under the TEST-VALUE root; the
/// first identity is the primary one and becomes `hardware` (C6 holds).
fn with_identities(tag: &str, identities: &[Hash]) -> TestTpm {
    let base = TestTpm::with_identity(tag).strip(Strip::ConsistentProvenance(root()));
    let mut statement = base.profile().provenance.clone().unwrap();
    statement.endorsement.as_mut().unwrap().identities = identities.iter().map(|id| (root(), *id)).collect();
    base.edited(|p| p.hardware = identities[0]).with_provenance(statement)
}
fn identity(tag: &str) -> Hash {
    TestTpm::with_identity(tag).ek_identity()
}

// ------------------------------------------------------------------------------------------------
// A4: the canonical encoding and the derivation
// ------------------------------------------------------------------------------------------------
/// EKPUB-CANON-V1 has exactly one encoding per key; every alternative form is refused with its own reason.
#[test]
fn canonical_ek_encoding_is_unique_per_key_and_rejects_every_alternative_form() {
    use IdentityFailure as F;
    let ecc = TestTpm::new().simulator_ek();
    let raw = ecc.encode().unwrap();
    assert_eq!(raw.len(), 67);
    assert_eq!(raw[..3], [0x02, 0x00, 0x03]);
    assert_eq!(EkPublicKey::decode(&raw).unwrap(), ecc);
    let rsa = test_value_ek::rsa_like_public("canon", 2048);
    let rsa_raw = rsa.encode().unwrap();
    assert_eq!(rsa_raw.len(), 263);
    assert_eq!(rsa_raw[..7], [0x01, 0x08, 0x00, 0x00, 0x01, 0x00, 0x01]);
    assert_eq!(EkPublicKey::decode(&rsa_raw).unwrap(), rsa);
    let EkPublicKey::Ecc { x, y, .. } = &ecc else { unreachable!() };
    let EkPublicKey::Rsa { modulus, .. } = &rsa else { unreachable!() };
    let ecc_with = |curve: u16, x: Vec<u8>, y: Vec<u8>| EkPublicKey::Ecc { curve, x, y };
    let rsa_with = |bits: u16, exponent: u32, modulus: Vec<u8>| EkPublicKey::Rsa { bits, exponent, modulus };
    let mut top_clear = modulus.clone();
    top_clear[0] &= 0x7f;
    let mut even = modulus.clone();
    *even.last_mut().unwrap() &= 0xfe;
    let cases: Vec<(&str, std::result::Result<Vec<u8>, F>, F)> = vec![
        ("P-384 curve (not validated without a reviewed crate)", ecc_with(TPM_ECC_NIST_P384, vec![1; 48], vec![2; 48]).encode(), F::UnsupportedCurve),
        ("unknown curve", ecc_with(0x0009, x.clone(), y.clone()).encode(), F::UnsupportedCurve),
        ("point not on the curve", ecc_with(TPM_ECC_NIST_P256, vec![1; 32], vec![2; 32]).encode(), F::PointNotOnCurve),
        ("short coordinate", ecc_with(TPM_ECC_NIST_P256, x[1..].to_vec(), y.clone()).encode(), F::Length),
        ("RSA-1024", rsa_with(1024, 65537, modulus[..128].to_vec()).encode(), F::RsaModulusSize),
        ("modulus top bit clear", rsa_with(2048, 65537, top_clear).encode(), F::RsaModulusSize),
        ("modulus length differs from bits", rsa_with(3072, 65537, modulus.clone()).encode(), F::RsaModulusSize),
        ("even modulus", rsa_with(2048, 65537, even).encode(), F::RsaModulusEven),
        ("exponent 1", rsa_with(2048, 1, modulus.clone()).encode(), F::RsaExponent),
        ("even exponent", rsa_with(2048, 65536, modulus.clone()).encode(), F::RsaExponent),
    ];
    for (label, got, expected) in cases {
        assert_eq!(got, Err(expected), "{label}");
    }
    // Decoding refuses every other byte string: unknown tag, trailing byte, truncation, a compressed point.
    let mut unknown = raw.clone();
    unknown[0] = 0x03;
    assert_eq!(EkPublicKey::decode(&unknown), Err(F::UnknownAlgorithm));
    let mut trailing = raw.clone();
    trailing.push(0);
    assert_eq!(EkPublicKey::decode(&trailing), Err(F::Length));
    assert_eq!(EkPublicKey::decode(&raw[..66]), Err(F::Length));
    assert_eq!(EkPublicKey::decode(&raw[..35]), Err(F::Length));
    assert_eq!(EkPublicKey::decode(&[]), Err(F::Length));
    let mut zero_exponent = rsa_raw.clone();
    zero_exponent[3..7].copy_from_slice(&0u32.to_be_bytes());
    assert_eq!(EkPublicKey::decode(&zero_exponent), Err(F::RsaExponent));
    // The TPM public area's exponent 0 means 65537: two public areas that differ only in that template field carry the
    // SAME key and therefore the same identity (the identity is the key's, not the object template's).
    let mut template_65537 = test_value_ek::template(RSA_TAG, test_value_ek::TEST_ATTRIBUTES);
    let at = template_65537.len() - 4;
    template_65537[at..].copy_from_slice(&65537u32.to_be_bytes());
    let zero = parse_ek_public_area(&test_value_ek::public_area(&test_value_ek::template(RSA_TAG, test_value_ek::TEST_ATTRIBUTES), &rsa)).unwrap();
    let explicit = parse_ek_public_area(&test_value_ek::public_area(&template_65537, &rsa)).unwrap();
    assert_eq!(zero.key, rsa);
    assert_eq!(explicit.key, rsa);
    assert_ne!(zero.template_sha256, explicit.template_sha256);
    assert_eq!(zero.key.identity(), explicit.key.identity());
}

/// The identity is `H("MUTINY-BUILD8-PHYSICAL-HARDWARE-ID-V2", u32_be(NETWORK_ID) || EKPUB-CANON-V1)`: recomputed here
/// independently, network-scoped, the same for the same key and different for another key. No name enters it.
#[test]
fn endorsement_identity_is_network_scoped_label_free_and_stable() {
    let ek = TestTpm::new().simulator_ek();
    let canonical = ek.encode().unwrap();
    let derive = |network: u32| -> Hash {
        let mut h = Sha256::new();
        h.update(b"MUTINY-BUILD8-PHYSICAL-HARDWARE-ID-V2");
        h.update([0]);
        h.update(network.to_be_bytes());
        h.update(&canonical);
        h.finalize().into()
    };
    assert_eq!(NETWORK_ID, 0x4d55_5401);
    assert_eq!(ek.identity().unwrap(), derive(NETWORK_ID));
    assert_eq!(ek_identity(&canonical), derive(NETWORK_ID));
    assert_ne!(derive(NETWORK_ID), derive(NETWORK_ID ^ 1), "another network derives another identity");
    assert_eq!(TestTpm::new().simulator_ek().identity(), ek.identity());
    assert_ne!(TestTpm::with_identity("other").ek_identity(), TestTpm::new().ek_identity());
    // A consistent (limit) profile's hardware IS this identity (C6), whatever label the operator would have chosen.
    let limit = TestTpm::stripped(Strip::ConsistentProvenance(root()));
    assert_eq!(limit.profile().hardware, limit.ek_identity());
}

/// The version-2 statement: canonical, 1..=4 identities, committed under its own domain; version 1 is unchanged.
#[test]
fn provenance_v2_codec_is_canonical_bounded_and_committed_under_its_own_domain() {
    let tpm = TestTpm::stripped(Strip::ConsistentProvenance(root()));
    let statement = tpm.profile().provenance.clone().unwrap();
    let raw = statement.encode();
    assert_eq!(raw[..2], [0x88, 0x02]);
    assert_eq!(Provenance::decode(&raw).unwrap(), statement);
    assert_eq!(statement.commitment(), domain_hash(PROVENANCE_V2_DOMAIN, &raw));
    assert_eq!(tpm.profile().admission_trust_manifest, statement.commitment());
    assert_eq!(TpmProfile::decode(&tpm.profile().encode().unwrap()).unwrap().provenance, Some(statement.clone()));
    let v1 = tpm.consistent_provenance_v1(root());
    assert_eq!(v1.encode().len(), provenance::PROVENANCE_BYTES);
    assert_eq!(v1.commitment(), domain_hash(provenance::PROVENANCE_DOMAIN, &v1.encode()));
    let with = |n: usize| {
        let mut s = statement.clone();
        s.endorsement.as_mut().unwrap().identities = (1..=n as u8).map(|i| (root(), [i; 32])).collect();
        s.encode()
    };
    for n in 1..=4 {
        assert!(Provenance::decode(&with(n)).is_ok(), "{n} identities");
    }
    assert_eq!(Provenance::decode(&with(0)), Err(Error::Codec));
    // Five identities exceed the statement bound (derived from four), refused before structural decoding.
    assert_eq!(Provenance::decode(&with(5)), Err(Error::Oversize));
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(Provenance::decode(&trailing).is_err());
    assert!(Provenance::decode(&raw[..raw.len() - 1]).is_err());
    let mut relabelled = raw.clone();
    relabelled[1] = 0x01;
    assert_eq!(Provenance::decode(&relabelled), Err(Error::Codec));
    for i in 0..raw.len() {
        let mut m = raw.clone();
        m[i] ^= 0x01;
        if let Ok(decoded) = Provenance::decode(&m) {
            assert_ne!(decoded, statement, "byte {i}");
        }
    }
}

/// Production class: only a version-2 statement passes, and `hardware` must be the class-1 identity (C6): a label-only
/// identity change is refused. The Legacy/Test class adds nothing. The Genesis ceremony book still admits the authority-
/// signed limit material (limit L1 of the design: the anchor of a Genesis admission is the supervised ceremony).
#[test]
fn production_requires_the_v2_statement_and_hardware_is_the_primary_identity() {
    let limit = TestTpm::stripped(Strip::ConsistentProvenance(root()));
    let v1 = TestTpm::stripped(Strip::ConsistentProvenanceV1(root()));
    let relabeled = limit.edited(|p| p.hardware = domain_hash(b"MUTINY-BUILD8-TEST-VALUE-OPERATOR-LABEL-V1", b"host-17"));
    let check = |class, t: &TestTpm| provenance::check_profile_detailed(class, t.profile(), root(), &roots());
    assert_eq!(check(AdmissionClass::Production, &limit), Ok(()));
    assert_eq!(check(AdmissionClass::Production, &v1), Err(Failure::MissingEndorsementIdentity));
    assert_eq!(check(AdmissionClass::Production, &relabeled), Err(Failure::HardwareMismatch));
    for t in [&limit, &v1, &relabeled] {
        assert_eq!(check(AdmissionClass::LegacyTest, t), Ok(()));
    }
    let s = setup(true);
    let (binding, expected) = genesis_binding(&s, &relabeled);
    assert_eq!(
        Book::genesis(&binding, &s.policy, &expected, &s.state.wallets, AdmissionClass::Production).err(),
        Some(Error::UnqualifiedPhysical)
    );
    let (binding, expected) = genesis_binding(&s, &limit);
    Book::genesis(&binding, &s.policy, &expected, &s.state.wallets, AdmissionClass::Production).unwrap();
}

// ------------------------------------------------------------------------------------------------
// V2 construction helpers (deterministic simulator profiles; random hybrid node/continuity keys)
// ------------------------------------------------------------------------------------------------
struct Setup {
    owner: HybridKey,
    policy: Policy,
    state: State,
}
fn setup(production: bool) -> Setup {
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
        state.protocol_records.insert(parameters_key(), software_tpm::production_parameters(&roots()));
    }
    Setup { owner, policy, state }
}
struct NodeKeys {
    continuity: HybridKey,
    node: HybridKey,
}
fn node_keys() -> NodeKeys {
    NodeKeys { continuity: HybridKey::generate(Role::Continuity).unwrap(), node: HybridKey::generate(Role::Node).unwrap() }
}
fn unsigned_binding(policy: &Policy, owner: &HybridKey, tpm: &TestTpm, k: &NodeKeys) -> Binding {
    let node_descriptor = k.node.public().descriptor(1).unwrap();
    let zero = HybridSignature { ed448: [0; 114], fndsa: [0; 1280] };
    Binding {
        node_signer: None,
        admission: Admission {
            genesis: policy.genesis,
            fingerprint: policy.fingerprint,
            node: node_id(policy.genesis, &node_descriptor).unwrap(),
            hardware_generation: 1,
            key_generation: 1,
            continuity_descriptor: k.continuity.public().descriptor(1).unwrap(),
            profile: tpm.profile().encode().unwrap(),
            endorsement_root: root(),
            owner: owner.public().address_id(1).unwrap(),
            supervised_nonce: [5; 32],
            quote: vec![],
            possession: zero.clone(),
            authorization: zero.clone(),
        },
        node_descriptor,
        possession: zero,
    }
}
fn sign_binding(b: &mut Binding, owner: &HybridKey, tpm: &TestTpm, k: &NodeKeys) {
    b.admission.prove_continuity(&k.continuity).unwrap();
    b.admission.quote = tpm.quote(b.admission.challenge().unwrap());
    b.admission.authorize(owner, 1).unwrap();
    b.sign(&k.node).unwrap();
}
/// A complete owner-authorized Genesis-book binding (supervised nonce [5; 32]).
fn genesis_binding(s: &Setup, tpm: &TestTpm) -> (Binding, Expected) {
    let k = node_keys();
    let mut b = unsigned_binding(&s.policy, &s.owner, tpm, &k);
    sign_binding(&mut b, &s.owner, tpm, &k);
    let expected = Expected { node: b.admission.node, hardware_generation: 1, key_generation: 1, supervised_nonce: [5; 32] };
    (b, expected)
}
/// A one-member V2 chain at parent height 58 whose Genesis member is `genesis`.
struct Chain {
    s: Setup,
    parent: FinalizedAnchor,
    genesis_node: Hash,
    genesis_keys: NodeKeys,
}
fn chain(production: bool, genesis: &TestTpm) -> Chain {
    let class = if production { AdmissionClass::Production } else { AdmissionClass::LegacyTest };
    let mut s = setup(production);
    let k = node_keys();
    let mut binding = unsigned_binding(&s.policy, &s.owner, genesis, &k);
    sign_binding(&mut binding, &s.owner, genesis, &k);
    let node = binding.admission.node;
    let expected = Expected { node, hardware_generation: 1, key_generation: 1, supervised_nonce: [5; 32] };
    (s.state.membership_v2, s.state.continuity_keys_v2) =
        Book::genesis(&binding, &s.policy, &expected, &s.state.wallets, class).unwrap();
    s.state.continuity = Some(
        ContinuityState::bootstrap(
            s.policy.genesis,
            s.policy.fingerprint,
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
    s.state.accounting.slots.last_height = 58;
    s.state.accounting.slots.period = 0;
    let parent = FinalizedAnchor { network: NETWORK_ID, genesis: s.policy.genesis, fingerprint: s.policy.fingerprint, height: 58, block: [19; 32] };
    Chain { s, parent, genesis_node: node, genesis_keys: k }
}
fn join(c: &Chain, tpm: &TestTpm, k: &NodeKeys) -> Join {
    let mut join = Join { parent: c.parent.clone(), nonce: [7; 32], binding: unsigned_binding(&c.s.policy, &c.s.owner, tpm, k) };
    join.binding.admission.supervised_nonce = join.admission_nonce().unwrap();
    sign_binding(&mut join.binding, &c.s.owner, tpm, k);
    join
}
/// An owner-authorized hardware rotation of `node` (current generation `old`) to `tpm`.
fn rotation(c: &Chain, node: Hash, node_key: &HybridKey, tpm: &TestTpm, sequence: u64, old: u64) -> HardwareRotate {
    let continuity = HybridKey::generate(Role::Continuity).unwrap();
    let mut r = HardwareRotate {
        parent: c.parent.clone(),
        nonce: [56; 32],
        sequence,
        old_hardware_generation: old,
        old_key_generation: old,
        binding: c.s.state.membership_v2.get(node).unwrap().binding().clone(),
        native_possession: [0; 64],
    };
    r.binding.admission.hardware_generation = old + 1;
    r.binding.admission.key_generation = old + 1;
    r.binding.admission.continuity_descriptor = continuity.public().descriptor(old + 1).unwrap();
    r.binding.admission.profile = tpm.profile().encode().unwrap();
    r.binding.admission.supervised_nonce = r.admission_nonce().unwrap();
    r.binding.admission.prove_continuity(&continuity).unwrap();
    r.binding.admission.quote = tpm.quote(r.binding.admission.challenge().unwrap());
    r.binding.admission.authorize(&c.s.owner, 1).unwrap();
    r.binding.sign(node_key).unwrap();
    r.native_possession = tpm.possession(r.native_digest().unwrap());
    r
}
fn body(height: u64, operations: Vec<Vec<u8>>) -> BlockBody {
    BlockBody { height, reward_owner: [30; 32], fees: 0, transactions: vec![], operations }
}
/// One V2 block on the chain's current state (not installed).
fn attempt(c: &Chain, operations: Vec<Vec<u8>>) -> mutiny_consensus_v8::Result<Transition> {
    transition(&c.s.state, &c.parent, c.s.state.root().unwrap(), &body(c.parent.height + 1, operations))
}
/// Refused with exactly `error`; the parent StateRoot and every record are byte-identical afterwards.
fn expect_refused(c: &Chain, operations: Vec<Vec<u8>>, error: Error) {
    let (root_before, records_before) = (c.s.state.root().unwrap(), c.s.state.records().unwrap());
    assert_eq!(attempt(c, operations).err(), Some(error));
    assert_eq!(c.s.state.root().unwrap(), root_before);
    assert_eq!(c.s.state.records().unwrap(), records_before);
}
/// Apply one block and install its components, then advance a synthetic finalized parent (test harness only; not a
/// claim of mined or certified history).
fn advance(c: &mut Chain, operations: Vec<Vec<u8>>) {
    let t = attempt(c, operations).unwrap();
    assert!(t.payouts.is_empty() && t.burned == 0);
    let state = &mut c.s.state;
    state.accounting = t.accounting;
    state.continuity = Some(t.registry);
    state.membership_v2 = t.membership;
    state.continuity_keys_v2 = t.keys;
    state.retired_continuity_v2 = t.retired;
    state.node_key_history_v2 = t.node_history;
    state.penalties_v2 = t.penalties;
    state.bonds_v2 = t.bonds;
    let height = c.parent.height + 1;
    c.parent = FinalizedAnchor {
        height,
        block: domain_hash(b"MUTINY-BUILD8-TEST-VALUE-A2-SYNTHETIC-PARENT", &height.to_be_bytes()),
        ..c.parent.clone()
    };
    c.s.state.root().unwrap();
}

// ------------------------------------------------------------------------------------------------
// A4: duplicate-live-lineage rejection over every committed identity
// ------------------------------------------------------------------------------------------------
/// The V2 key book (every Genesis-book, JOIN, rotation and recovery insertion, reconstruction and every StateRoot) refuses a
/// second lineage that commits ANY identity already committed by another lineage, here a secondary one so that the
/// `hardware` labels differ, in both classes; a lineage with only its own identities is admitted.
#[test]
fn a_second_lineage_cannot_commit_a_live_endorsement_identity() {
    for production in [true, false] {
        let class = if production { AdmissionClass::Production } else { AdmissionClass::LegacyTest };
        let s = setup(production);
        let mut keys = KeyBook::default();
        let a = with_identities("lineage-a", &[identity("lineage-a")]);
        let (binding, expected) = genesis_binding(&s, &a);
        keys.admit(&binding.admission, &s.policy, &expected, &s.state.wallets, class).unwrap();
        let shared = with_identities("lineage-b", &[identity("lineage-b"), identity("lineage-a")]);
        assert_ne!(shared.profile().hardware, a.profile().hardware);
        let (binding, expected) = genesis_binding(&s, &shared);
        let before = keys.clone();
        assert_eq!(keys.admit(&binding.admission, &s.policy, &expected, &s.state.wallets, class), Err(Error::Duplicate), "{class:?}");
        assert_eq!(keys, before);
        let own = with_identities("lineage-b", &[identity("lineage-b")]);
        let (binding, expected) = genesis_binding(&s, &own);
        keys.admit(&binding.admission, &s.policy, &expected, &s.state.wallets, class).unwrap();
    }
}

/// Rule M: a TPM commonly holds an RSA and an ECC endorsement key. When the committed identity-class list names BOTH, every
/// admission commits both identities and reusing EITHER in another lineage is refused. DOCUMENTED LIMIT (L5): when the list
/// names only one class, the TPM's other key is never an identity and a second lineage can present it; one EK identity is
/// not one device. (The class COUNT per admission is enforced by `attestation_witness::verify_witness`, `ClassCount`.)
#[test]
fn rsa_and_ecc_endorsement_keys_of_one_tpm_cannot_split_into_two_lineages_when_both_classes_are_committed() {
    let s = setup(true);
    let class = AdmissionClass::Production;
    let r1 = test_value_ek::rsa_like_public("tpm-1/rsa", 2048).identity().unwrap();
    let e1 = identity("tpm-1");
    let r2 = test_value_ek::rsa_like_public("tpm-2/rsa", 2048).identity().unwrap();
    let admit = |keys: &mut KeyBook, tpm: &TestTpm| {
        let (binding, expected) = genesis_binding(&s, tpm);
        keys.admit(&binding.admission, &s.policy, &expected, &s.state.wallets, class)
    };
    // Both classes committed by TPM 1's lineage.
    let mut keys = KeyBook::default();
    admit(&mut keys, &with_identities("tpm-1", &[r1, e1])).unwrap();
    assert_eq!(admit(&mut keys, &with_identities("tpm-2", &[r2, e1])), Err(Error::Duplicate), "TPM 1's ECC key next to another RSA key");
    assert_eq!(admit(&mut keys, &with_identities("tpm-2", &[e1])), Err(Error::Duplicate), "TPM 1's ECC key alone");
    assert_eq!(admit(&mut keys, &with_identities("tpm-2", &[r1])), Err(Error::Duplicate), "TPM 1's RSA key alone");
    admit(&mut keys, &with_identities("tpm-2", &[r2, identity("tpm-2")])).unwrap();
    // DOCUMENTED LIMIT: a one-class list (RSA only); TPM 1's ECC key is not committed and passes as another lineage.
    let mut one_class = KeyBook::default();
    admit(&mut one_class, &with_identities("tpm-1", &[r1])).unwrap();
    admit(&mut one_class, &with_identities("tpm-2", &[e1])).unwrap();
}

/// Real block path (V2 lifecycle, Legacy/Test class so that the A8 rule does not hide it): a JOIN committing the live Genesis
/// member's identity as a secondary identity is refused with exactly `Duplicate`, parent root and records byte-identical;
/// the same JOIN without it stages. In the Production class the same JOIN is refused first by the A8 rule.
#[test]
fn duplicate_identity_join_is_refused_in_a_real_block_with_a_byte_identical_parent() {
    let genesis = with_identities("block-g", &[identity("block-g")]);
    let c = chain(false, &genesis);
    let k = node_keys();
    let shared = with_identities("block-j", &[identity("block-j"), identity("block-g")]);
    expect_refused(&c, vec![join(&c, &shared, &k).encode().unwrap()], Error::Duplicate);
    let own = with_identities("block-j", &[identity("block-j")]);
    let staged = attempt(&c, vec![join(&c, &own, &k).encode().unwrap()]).unwrap();
    assert_eq!(staged.registry.members.len(), 2);
    let p = chain(true, &genesis);
    expect_refused(&p, vec![join(&p, &shared, &k).encode().unwrap()], Error::AdmissionAuthorityEnded);
    expect_refused(&p, vec![join(&p, &own, &k).encode().unwrap()], Error::AdmissionAuthorityEnded);
}

/// Identity preserved across legitimate rotation: the same endorsement identity with new attestation and voting keys keeps
/// the lineage's hardware-local history `h`; a different identity restarts it (Legacy/Test class; in Production every
/// post-sealing rotation is refused by A8).
#[test]
fn same_lineage_keeps_its_identity_and_history_across_hardware_rotation() {
    let genesis = with_identities("keep-g", &[identity("keep-g")]);
    let mut c = chain(false, &genesis);
    let member = &mut c.s.state.continuity.as_mut().unwrap().members[0];
    member.history.p = 3;
    member.history.a = 3;
    member.history.s = 3;
    member.history.h = 2;
    c.s.state.root().unwrap();
    let rekeyed_same_tpm = with_identities("keep-g-new-ak", &[identity("keep-g")]);
    assert_eq!(rekeyed_same_tpm.profile().hardware, genesis.profile().hardware);
    let r = rotation(&c, c.genesis_node, &c.genesis_keys.node, &rekeyed_same_tpm, 1, 1);
    let kept = attempt(&c, vec![r.encode().unwrap()]).unwrap();
    assert_eq!(kept.registry.members[0].history.h, 2, "same endorsement identity: history kept");
    let new_tpm = with_identities("keep-g-new-tpm", &[identity("keep-g-new-tpm")]);
    let r = rotation(&c, c.genesis_node, &c.genesis_keys.node, &new_tpm, 1, 1);
    let reset = attempt(&c, vec![r.encode().unwrap()]).unwrap();
    assert_eq!(reset.registry.members[0].history.h, 0, "another identity: history restarts");
    assert_eq!(reset.registry.members[0].history.p, 3, "lineage history is kept");
}

/// Real blocks over several heights (Legacy/Test class): B joins (59) and becomes eligible at the boundary (60). B cannot
/// rotate onto a profile that also commits G's LIVE identity (`HardwareRotate::verify` alone, and the block path); after G
/// rotates to a new TPM (61), its old identity is RETIRED and still cannot be taken: not by B's rotation and not by a new
/// lineage's JOIN (62). Every refusal is exactly `Duplicate` with a byte-identical parent.
#[test]
fn another_lineage_cannot_take_a_live_or_retired_endorsement_identity() {
    let g = with_identities("multi-g", &[identity("multi-g")]);
    let mut c = chain(false, &g);
    let kb = node_keys();
    let b = with_identities("multi-b", &[identity("multi-b")]);
    let jb = join(&c, &b, &kb);
    let node_b = jb.binding.admission.node;
    advance(&mut c, vec![jb.encode().unwrap()]);
    advance(&mut c, vec![]);
    assert!(c.s.state.continuity.as_ref().unwrap().members.iter().any(|m| m.node == node_b && m.eligible));
    // LIVE identity of G as a secondary identity of B's new profile.
    let onto_live = with_identities("multi-b2", &[identity("multi-b2"), identity("multi-g")]);
    let r = rotation(&c, node_b, &kb.node, &onto_live, 1, 1);
    assert_eq!(r.verify(&c.s.state, &c.parent, c.s.state.root().unwrap()).err(), Some(Error::Duplicate));
    expect_refused(&c, vec![r.encode().unwrap()], Error::Duplicate);
    let own = with_identities("multi-b2", &[identity("multi-b2")]);
    rotation(&c, node_b, &kb.node, &own, 1, 1).verify(&c.s.state, &c.parent, c.s.state.root().unwrap()).unwrap();
    // G rotates to a new TPM: its old binding (identity of multi-g) is retired.
    let g2 = with_identities("multi-g2", &[identity("multi-g2")]);
    let retire_g = rotation(&c, c.genesis_node, &c.genesis_keys.node, &g2, 1, 1).encode().unwrap();
    advance(&mut c, vec![retire_g]);
    assert!(!c.s.state.retired_continuity_v2.is_empty());
    // RETIRED identity: B's rotation (verify alone, and the block) and a new lineage's JOIN.
    let onto_retired = with_identities("multi-b3", &[identity("multi-b3"), identity("multi-g")]);
    let r = rotation(&c, node_b, &kb.node, &onto_retired, 1, 1);
    assert_eq!(r.verify(&c.s.state, &c.parent, c.s.state.root().unwrap()).err(), Some(Error::Duplicate));
    expect_refused(&c, vec![r.encode().unwrap()], Error::Duplicate);
    let newcomer = with_identities("multi-n", &[identity("multi-n"), identity("multi-g")]);
    expect_refused(&c, vec![join(&c, &newcomer, &node_keys()).encode().unwrap()], Error::Duplicate);
    // Positive controls at the same height.
    let fresh = with_identities("multi-n", &[identity("multi-n")]);
    attempt(&c, vec![join(&c, &fresh, &node_keys()).encode().unwrap()]).unwrap();
    let b3 = with_identities("multi-b3", &[identity("multi-b3")]);
    attempt(&c, vec![rotation(&c, node_b, &kb.node, &b3, 1, 1).encode().unwrap()]).unwrap();
}

/// The Production-class committed-state backstop (`State::records`, every StateRoot) also covers V1: two V1 lineages whose
/// approved profiles commit the same (secondary) identity have no StateRoot; the same state is valid in the Legacy/Test
/// class, and in the Production class without the shared identity.
#[test]
fn state_backstop_refuses_an_identity_committed_by_two_v1_lineages() {
    let shared = identity("v1-shared");
    let build = |production: bool, share: bool| -> State {
        let policy = software_tpm::fixture_policy();
        let (genesis, fingerprint) = software_tpm::fixture_context();
        let a = with_identities("v1-a", &[identity("v1-a"), shared]);
        let b_ids = if share { vec![identity("v1-b"), shared] } else { vec![identity("v1-b")] };
        let b = with_identities("v1-b", &b_ids);
        let mut state = State::default();
        state.admission.policy = Some(policy.clone());
        let mut members = Vec::new();
        for (t, node, seed) in [(&a, [1u8; 32], 71u8), (&b, [2u8; 32], 73u8)] {
            let commitment = t.profile().commitment().unwrap();
            state.admission.profiles.insert(commitment, software_tpm::approve(&policy, root(), t.profile()));
            members.push(Member {
                lineage: node,
                node,
                hardware: t.profile().hardware,
                generation: 0,
                voting_key: t.voting_point(),
                attestation: commitment,
                history: Default::default(),
                physical: true,
                eligible: true,
                genesis_member: true,
            });
            let key = |s: u8| ed25519_dalek::SigningKey::from_bytes(&[s; 32]).verifying_key().to_bytes();
            state.membership.controls.insert(
                node,
                NodeControl {
                    node,
                    generation: 0,
                    owner: key(seed),
                    node_authentication: key(seed + 1),
                    sequence: 0,
                    exit_boundary: None,
                    admitted_height: 0,
                    admission_boundary: None,
                    hardware_since_height: 0,
                },
            );
        }
        state.continuity = Some(
            ContinuityState::bootstrap(genesis, fingerprint, Anchor { height: 0, tip: [3; 32], state_root: [0; 32], registry_root: [0; 32] }, [4; 32], members)
                .unwrap(),
        );
        if production {
            state.protocol_records.insert(parameters_key(), software_tpm::production_parameters(&policy.endorsement_roots));
        }
        state
    };
    build(false, true).root().unwrap();
    build(true, false).root().unwrap();
    assert!(matches!(build(true, true).root(), Err(ExecutionError::Codec(Error::Duplicate))));
}

// ------------------------------------------------------------------------------------------------
// A8: the admission authority ends at sealing; Treasury custody grants no admission authority
// ------------------------------------------------------------------------------------------------
/// The scope rule: in the Production class an authority-signed hardware admission is permitted in the Genesis ceremony and
/// refused after sealing; the Legacy/Test class is unchanged.
#[test]
fn admission_authority_scope_ends_at_sealing_in_the_production_class_only() {
    use AdmissionStage::*;
    assert_eq!(check_authority_scope(AdmissionClass::Production, PostSealing), Err(ScopeFailure::AuthorityEndedAtSealing));
    assert_eq!(check_authority_scope(AdmissionClass::Production, GenesisCeremony), Ok(()));
    assert_eq!(check_authority_scope(AdmissionClass::LegacyTest, PostSealing), Ok(()));
    assert_eq!(check_authority_scope(AdmissionClass::LegacyTest, GenesisCeremony), Ok(()));
    assert_eq!(require_post_sealing_admission(AdmissionClass::Production), Err(Error::AdmissionAuthorityEnded));
    assert_eq!(require_post_sealing_admission(AdmissionClass::LegacyTest), Ok(()));
    // The same authority-signed limit material: accepted by the Genesis ceremony book, refused as a post-sealing JOIN.
    let limit = TestTpm::stripped(Strip::ConsistentProvenance(root()));
    let s = setup(true);
    let (binding, expected) = genesis_binding(&s, &limit);
    Book::genesis(&binding, &s.policy, &expected, &s.state.wallets, AdmissionClass::Production).unwrap();
    let genesis = with_identities("scope-g", &[identity("scope-g")]);
    let c = chain(true, &genesis);
    let j = join(&c, &limit, &node_keys());
    assert_eq!(j.verify(&c.s.state, &c.parent, c.s.state.root().unwrap()).err(), Some(Error::AdmissionAuthorityEnded));
}

/// Treasury custody grants no hardware-admission authority: a Production-class state whose V2 admission owner is the Treasury
/// wallet has no StateRoot; a distinct Treasury wallet is fine; the Legacy/Test class is unchanged.
#[test]
fn treasury_wallet_cannot_be_the_admission_authority() {
    let s = setup(true);
    let mut alias = s.state.clone();
    alias.dividends = DividendState::genesis(Treasury::new(Class::TestValue, s.policy.owner_descriptor.clone()).unwrap());
    assert!(matches!(alias.root(), Err(ExecutionError::Codec(Error::Duplicate))));
    assert_eq!(reject_treasury_alias(&s.policy.owner_descriptor, &s.policy.owner_descriptor), Err(Error::Duplicate));
    let treasury = HybridKey::wallet_restore(&("zoo ".repeat(23) + "vote"), Role::WalletOwner).unwrap().public().descriptor(1).unwrap();
    reject_treasury_alias(&s.policy.owner_descriptor, &treasury).unwrap();
    let mut distinct = s.state.clone();
    distinct.wallets.register(&treasury).unwrap();
    distinct.dividends = DividendState::genesis(Treasury::new(Class::TestValue, treasury).unwrap());
    distinct.root().unwrap();
    let mut legacy = setup(false).state;
    legacy.dividends = DividendState::genesis(Treasury::new(Class::TestValue, s.policy.owner_descriptor.clone()).unwrap());
    legacy.root().unwrap();
}

/// The candidate-3 domain strings are registered exactly once each, PROPOSED-UNFROZEN, in `spec/DOMAIN-REGISTRY-V1.json`.
#[test]
fn candidate_3_domains_are_registered_as_proposed_and_unfrozen() {
    let registry: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("../spec/DOMAIN-REGISTRY-V1.json").unwrap()).unwrap();
    let listed = registry["domains"].as_array().unwrap();
    for domain in [
        PROVENANCE_V2_DOMAIN,
        HARDWARE_ID_DOMAIN,
        IDENTITY_CLASSES_DOMAIN,
        mutiny_consensus_v8::attestation_witness::WITNESS_DOMAIN,
        mutiny_consensus_v8::pcr_profiles::ACCEPTED_PCR_PROFILES_DOMAIN,
        b"MUTINY-BUILD8-ACTIVATION-SECRET-V1".as_slice(),
    ] {
        let ascii = std::str::from_utf8(domain).unwrap();
        let entries: Vec<_> = listed.iter().filter(|e| e["ascii"] == ascii).collect();
        assert_eq!(entries.len(), 1, "{ascii} registered exactly once");
        assert_eq!(entries[0]["status"], "PROPOSED-UNFROZEN", "{ascii}");
    }
}
