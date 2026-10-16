//! PUBLIC TEST-VALUE ONLY. Genuine software-generated signatures and DER, no
//! manufacturer, TPM activation, physical host, production key or Genesis seal.
use super::*;
use crate::{
    Hash,
    admission_evidence_v1::PublicWitnessBundle,
    admission_v2::Admission,
    anchors::FinalizedAnchor,
    attestation_witness::{AttestationWitness, EndorsementEvidence},
    ek_chain::{RevocationMode, SignatureAlgorithm},
    endorsement_identity::{ECC_TAG, IdentityClasses},
    execution::State,
    genesis_v2::{
        self, EndorsementRoot, EndorsementRootSet, Enrollment, GenesisClass, Inputs, MemberInput,
        Parameters,
    },
    node_admission_v2::{Binding, node_id},
    pcr_profiles::{
        AcceptedPcrProfiles, INTERPRETATION_QUOTE_COMPOSITE, PcrProfile, SHA256_BANK,
        UPDATE_FROZEN_AT_GENESIS,
    },
    protocol_manifest::RuleManifest,
    software_tpm::{self, TestTpm},
};
use mutiny_crypto_v2::{
    HybridKey, HybridSignature, Role,
    enrollment::{Binding as LicenseBinding, owner_descriptor_id},
};
#[path = "../../tests/support/license_v2.rs"]
mod licenses;
#[path = "../../tests/support/test_value_ek.rs"]
mod test_value_ek;
#[path = "../../tests/support/test_value_x509.rs"]
mod test_value_x509;
use x509_cert::der::asn1::Uint;
use x509_cert::der::{Encode, asn1::OctetString};
use x509_cert::ext::pkix::CrlNumber;
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, IssuingDistributionPoint, KeyUsages,
    SubjectKeyIdentifier,
    crl::{CrlDistributionPoints, dp::DistributionPoint},
    name::GeneralName,
};
use x509_cert::{der::asn1::ObjectIdentifier, ext::pkix::crl::CrlReason};

fn label(s: &str) -> Hash {
    crate::domain_hash(
        b"MUTINY-BUILD8-TEST-VALUE-A2-TERMINAL-FIXTURE-V1",
        s.as_bytes(),
    )
}
fn zero() -> HybridSignature {
    HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    }
}
struct Rig {
    state: State,
    parent: FinalizedAnchor,
    root: Hash,
    pki: test_value_x509::X509Pki,
    chain: Vec<Vec<u8>>,
    node: Hash,
    binding: Binding,
    witness: Vec<u8>,
    parameters: Parameters,
    continuity: HybridKey,
    // Retain only the locally generated synthetic TEST node key for full-native work.
    node_key: HybridKey,
}
fn rig() -> Rig {
    rig_with_delegated_target(false)
}
fn delegate_key() -> test_value_x509::CaKey {
    test_value_x509::CaKey::P256(test_value_x509::p256_key("a2-public-delegated-crl-signer"))
}
fn delegate_name() -> x509_cert::name::Name {
    test_value_x509::name("TEST-VALUE A2 delegated public CRL signer")
}
fn rig_with_delegated_target(delegated: bool) -> Rig {
    rig_with_pki(delegated, &[0x51], test_value_x509::X509Pki::new("a2-terminal-public-software-fixture"))
}
// Fresh full signed fixture construction: never rewrite authenticated old witness bytes.
fn rig_with_pki(delegated: bool, serial: &[u8], pki: test_value_x509::X509Pki) -> Rig {
    rig_with_root_set(delegated, serial, pki, &[])
}
// TEST-only local fixture may freeze additional unused genuine public roots.
// Every original rig keeps exactly the same single-root input via the empty slice.
#[derive(Clone, Copy)]
enum FixtureRules { A2Only, CurrentActivation, WrongActivation }
fn rig_current_activation() -> Rig { rig_with_root_set_and_rules(false, &[0x51],
    test_value_x509::X509Pki::new("a2-terminal-public-software-fixture"), &[], FixtureRules::CurrentActivation) }
fn rig_wrong_activation() -> genesis_v2::Result<Rig> { try_rig_with_root_set_and_rules(false, &[0x51],
    test_value_x509::X509Pki::new("a2-terminal-public-software-fixture"), &[], FixtureRules::WrongActivation) }
fn rig_with_root_set(
    delegated: bool, serial: &[u8], pki: test_value_x509::X509Pki,
    unused: &[test_value_x509::X509Pki],
) -> Rig { rig_with_root_set_and_rules(delegated, serial, pki, unused, FixtureRules::A2Only) }
fn rig_with_root_set_and_rules(
    delegated: bool, serial: &[u8], pki: test_value_x509::X509Pki,
    unused: &[test_value_x509::X509Pki], rules: FixtureRules,
) -> Rig {
    try_rig_with_root_set_and_rules(delegated, serial, pki, unused, rules).unwrap()
}
fn try_rig_with_root_set_and_rules(
    delegated: bool, serial: &[u8], pki: test_value_x509::X509Pki,
    unused: &[test_value_x509::X509Pki], rules: FixtureRules,
) -> genesis_v2::Result<Rig> {
    let root = pki.root_hash();
    let tpm = TestTpm::stripped(software_tpm::Strip::ConsistentProvenance(root));
    let area = test_value_ek::public_area(
        &test_value_ek::template(ECC_TAG, test_value_ek::TEST_ATTRIBUTES),
        &tpm.simulator_ek(),
    );
    let mut chain = pki.chain(&tpm.simulator_ek(), serial);
    if delegated {
        let mut leaf = pki.ek_tbs(&tpm.simulator_ek(), serial);
        leaf.extensions.as_mut().unwrap().push(test_value_x509::ext(
            ObjectIdentifier::new_unwrap("2.5.29.31"),
            false,
            &CrlDistributionPoints(vec![DistributionPoint {
                distribution_point: None,
                reasons: None,
                crl_issuer: Some(vec![GeneralName::DirectoryName(delegate_name())]),
            }]),
        ));
        chain[0] = pki.issue(&leaf);
    }
    let admission_crls: Vec<_> = [false, true]
        .into_iter()
        .map(|by_root| {
            let mut tbs = pki.crl_tbs(by_root, &[]);
            // Historical admission remains valid at parent T_ref but these exact
            // genuine signed CRLs expire before the later containing-H timestamp.
            tbs.next_update = Some(test_value_x509::time(test_value_x509::T_REF + 30));
            pki.sign_crl(&tbs, by_root)
        })
        .collect();
    let anchor = pki.anchor(
        RevocationMode::CrlRequired,
        &[test_value_ek::ECC_CLASS],
        &[SignatureAlgorithm::EcdsaP256Sha256, SignatureAlgorithm::EcdsaP384Sha384],
    );
    try_rig_with_authenticated_material_and_rules(pki, unused, tpm, chain, admission_crls, anchor, rules)
}
// TEST-only factoring: callers provide exact signed public material, but the
// existing full witness/Genesis constructor below remains mandatory. No raw
// dependency Book insertion or caller authenticity flag is introduced.
fn rig_with_authenticated_material(
    pki: test_value_x509::X509Pki, unused: &[test_value_x509::X509Pki],
    tpm: TestTpm, chain: Vec<Vec<u8>>, admission_crls: Vec<Vec<u8>>,
    anchor: crate::ek_chain::TrustAnchor,
) -> Rig {
    rig_with_authenticated_material_and_rules(pki, unused, tpm, chain, admission_crls,
        anchor, FixtureRules::A2Only)
}
fn rig_with_authenticated_material_and_rules(
    pki: test_value_x509::X509Pki, unused: &[test_value_x509::X509Pki],
    tpm: TestTpm, chain: Vec<Vec<u8>>, admission_crls: Vec<Vec<u8>>,
    anchor: crate::ek_chain::TrustAnchor, rules: FixtureRules,
) -> Rig {
    try_rig_with_authenticated_material_and_rules(
        pki, unused, tpm, chain, admission_crls, anchor, rules).unwrap()
}
fn try_rig_with_authenticated_material_and_rules(
    pki: test_value_x509::X509Pki, unused: &[test_value_x509::X509Pki],
    tpm: TestTpm, chain: Vec<Vec<u8>>, admission_crls: Vec<Vec<u8>>,
    anchor: crate::ek_chain::TrustAnchor, rules: FixtureRules,
) -> genesis_v2::Result<Rig> {
    try_rig_with_selected_material(pki, unused, tpm, chain, admission_crls, anchor, rules, false)
}
fn rig_with_selected_material(
    pki: test_value_x509::X509Pki, unused: &[test_value_x509::X509Pki],
    tpm: TestTpm, chain: Vec<Vec<u8>>, admission_crls: Vec<Vec<u8>>,
    anchor: crate::ek_chain::TrustAnchor, selected: bool,
) -> Rig {
    try_rig_with_selected_material(pki, unused, tpm, chain, admission_crls, anchor,
        FixtureRules::A2Only, selected).unwrap()
}
fn try_rig_with_selected_material(
    pki: test_value_x509::X509Pki, unused: &[test_value_x509::X509Pki],
    tpm: TestTpm, chain: Vec<Vec<u8>>, admission_crls: Vec<Vec<u8>>,
    anchor: crate::ek_chain::TrustAnchor, rules: FixtureRules, selected: bool,
) -> genesis_v2::Result<Rig> {
    let der_root = pki.root_hash();
    let mut alias_label = crate::test_value_root_alias_v1::LABEL_PREFIX.to_vec();
    alias_label.extend(der_root);
    let root = if selected { genesis_v2::test_value_root(&alias_label) } else { der_root };
    let area = test_value_ek::public_area(
        &test_value_ek::template(ECC_TAG, test_value_ek::TEST_ATTRIBUTES),
        &tpm.simulator_ek(),
    );
    let statement = tpm.profile().provenance.as_ref().unwrap();
    let witness = AttestationWitness {
        reference_time: test_value_x509::T_REF,
        endorsements: vec![EndorsementEvidence {
            ek_public_area: area,
            certificates: chain.clone(),
            crls: admission_crls,
        }],
        activation: vec![test_value_ek::activation(
            0,
            statement.ak_name,
            "public-no-activation-proof",
        )],
    };
    let mut statement = statement.clone();
    if selected {
        statement.endorsement_root = root;
        statement.endorsement.as_mut().unwrap().identities[0].0 = root;
    }
    statement.endorsement.as_mut().unwrap().witness_sha256 = witness.commitment().unwrap();
    statement.ek_public_sha256 =
        crate::x509_syntax::certified_public_key_sha256(&chain[0]).unwrap();
    let tpm = tpm.with_provenance(statement);
    let owner =
        HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner)
            .unwrap();
    let treasury =
        HybridKey::wallet_restore(&("zoo ".repeat(23) + "vote"), Role::WalletOwner).unwrap();
    let recovery = HybridKey::wallet_restore("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title", Role::WalletRecovery).unwrap();
    let mut parameters = Parameters {
        // Synthetic Production-shaped public software fixture, no physical/production authority.
        class: if selected { GenesisClass::TestValue } else { GenesisClass::Production },
        initial_target: [0xff; 32],
        rules: RuleManifest {
            commitments: vec![(RULE_ENTRY.to_vec(), rule_commitment())],
        },
        roots: EndorsementRootSet {
            roots: [(
                root,
                EndorsementRoot {
                    constraints: anchor.constraints,
                    test_value_label: if selected { Some(alias_label) } else { None },
                },
            )]
            .into(),
        },
        pcr_profiles: AcceptedPcrProfiles::new(
            UPDATE_FROZEN_AT_GENESIS,
            vec![PcrProfile {
                bank: SHA256_BANK,
                selection: tpm.profile().pcr_bitmap,
                digest: tpm.profile().pcr_digest,
                interpretation: INTERPRETATION_QUOTE_COMPOSITE,
            }],
        )
        .unwrap(),
        identity_classes: IdentityClasses::new(vec![test_value_ek::class_of(
            ECC_TAG,
            test_value_ek::TEST_ATTRIBUTES,
        )])
        .unwrap(),
    };
    for unused_pki in unused {
        let unused_anchor = unused_pki.anchor(
            RevocationMode::CrlRequired,
            &[test_value_ek::ECC_CLASS],
            &[SignatureAlgorithm::EcdsaP256Sha256, SignatureAlgorithm::EcdsaP384Sha384],
        );
        let mut unused_label = crate::test_value_root_alias_v1::LABEL_PREFIX.to_vec();
        unused_label.extend(unused_pki.root_hash());
        let unused_root = if selected { genesis_v2::test_value_root(&unused_label) } else { unused_pki.root_hash() };
        assert!(parameters.roots.roots.insert(unused_root, EndorsementRoot {
            constraints: unused_anchor.constraints,
            test_value_label: if selected { Some(unused_label) } else { None },
        }).is_none(), "unused synthetic roots must be distinct frozen roots");
    }
    // Freeze the selected marker in original Inputs, BEFORE identity, fingerprint,
    // binding signatures, witness verification and native Genesis construction.
    match rules {
        FixtureRules::A2Only => {},
        FixtureRules::CurrentActivation => parameters.rules.commitments.push((
            crate::activation_attestation_v1::RULE_ENTRY.to_vec(),
            crate::activation_attestation_v1::rule_commitment())),
        FixtureRules::WrongActivation => parameters.rules.commitments.push((
            crate::activation_attestation_v1::RULE_ENTRY.to_vec(), label("wrong-activation-rule"))),
    }
    if selected {
        parameters.rules.commitments.push((crate::test_value_root_alias_v1::RULE_ENTRY.to_vec(),
            crate::test_value_root_alias_v1::rule_commitment()));
    }
    parameters.rules.commitments.extend(
        genesis_v2::binding_entries(
            parameters.class,
            &parameters.roots,
            &parameters.pcr_profiles,
            &parameters.identity_classes,
        )
        .unwrap(),
    );
    parameters.rules.commitments.sort();
    let inputs = Inputs {
        timestamp: test_value_x509::T_REF,
        nonce: label("nonce"),
        parameters,
        admission_owner: owner.public().descriptor(1).unwrap(),
        member: MemberInput {
            endorsement_root: root,
            profile: tpm.profile().encode().unwrap(),
        },
        recovery: recovery.public().descriptor(1).unwrap(),
        treasury: crate::treasury_v1::Treasury::new(
            // Class-specific Genesis input validation only; key remains public synthetic TEST-VALUE.
            if selected { crate::treasury_v1::Class::TestValue } else { crate::treasury_v1::Class::Production },
            treasury.public().descriptor(1).unwrap(),
        )
        .unwrap(),
        purchase: label("purchase"),
    };
    if selected { inputs.validate()?; }
    let identity = inputs.identity().unwrap();
    let fingerprint = inputs.parameters.fingerprint().unwrap();
    let node_key = HybridKey::generate(Role::Node).unwrap();
    let continuity = HybridKey::generate(Role::Continuity).unwrap();
    let descriptor = node_key.public().descriptor(1).unwrap();
    let node = node_id(identity, &descriptor).unwrap();
    let mut binding = Binding {
        node_signer: None,
        node_descriptor: descriptor.clone(),
        possession: zero(),
        admission: Admission {
            genesis: identity,
            fingerprint,
            node,
            hardware_generation: 1,
            key_generation: 1,
            continuity_descriptor: continuity.public().descriptor(1).unwrap(),
            profile: inputs.member.profile.clone(),
            endorsement_root: root,
            owner: owner.public().address_id(1).unwrap(),
            supervised_nonce: label("admission"),
            quote: vec![],
            possession: zero(),
            authorization: zero(),
        },
    };
    binding.admission.prove_continuity(&continuity).unwrap();
    binding.admission.quote = tpm.quote(binding.admission.challenge().unwrap());
    binding.admission.authorize(&owner, 1).unwrap();
    binding.sign(&node_key).unwrap();
    let mut assignments = Vec::new();
    let mut supervised = Vec::new();
    for i in 0..12u64 {
        let mut assignment = LicenseBinding {
            genesis: identity,
            fingerprint,
            license: crate::blocks::genesis_license(identity, i).unwrap(),
            owner_descriptor: owner_descriptor_id(owner.public(), 1).unwrap(),
            owner_generation: 1,
            worker_public: licenses::worker(i as u8 + 1),
            worker_id: [0; 32],
            coordinator: crate::work_authority_v2::node_identity(&descriptor).unwrap(),
            configuration_generation: 1,
            device_mac: [2, 0, 0, 0, 0, i as u8 + 1],
            assignment_generation: 1,
            effective_epoch: 0,
            valid_until_height: 0,
        };
        assignment.worker_id = assignment.derived_worker_id();
        assignments.push(licenses::sign(
            assignment.clone(),
            &owner,
            &descriptor,
            i as u8 + 1,
        ));
        supervised.push(assignment);
    }
    let enrollment = Enrollment {
        supervised_nonce: label("admission"),
        member_binding: binding.clone(),
        assignments,
        supervised,
    };
    let bundle = PublicWitnessBundle {
        genesis: identity,
        fingerprint,
        entries: vec![(node, witness.encode().unwrap())],
    };
    assert!(
        genesis_v2::construct(&inputs, &enrollment).is_err(),
        "marked Genesis cannot omit genuine available witnesses"
    );
    let constructed = genesis_v2::construct_with_public_dependencies(
        &inputs,
        &enrollment,
        &bundle.encode().unwrap(),
    )?;
    let parent = FinalizedAnchor {
        network: crate::NETWORK_ID,
        genesis: identity,
        fingerprint,
        height: 0,
        block: constructed.block_hash,
    };
    Ok(Rig {
        state: constructed.state,
        parent,
        root: constructed.root,
        pki,
        chain,
        node,
        binding,
        witness: witness.encode().unwrap(),
        parameters: inputs.parameters,
        continuity,
        node_key,
    })
}
fn operation(r: &Rig, target: Target, evidence: Evidence) -> Operation {
    Operation {
        context: Context {
            genesis: r.parent.genesis,
            fingerprint: r.parent.fingerprint,
            parent_height: 0,
            parent_block: r.parent.block,
            parent_state: r.root,
            height: 1,
            timestamp: test_value_x509::T_REF + 60,
        },
        target,
        evidence,
    }
}
fn transition(r: &Rig, op: &Operation) -> Result<State> {
    let body = crate::blocks::BlockBody {
        height: 1,
        reward_owner: [0; 32],
        fees: 0,
        transactions: vec![],
        operations: vec![op.encode()?],
    };
    let context = crate::parent_context_v2::ParentContext::canonical(&r.state, &r.parent, r.root)?;
    let next = crate::continuity_lifecycle_v2::transition_in_parent_at(
        context,
        &body,
        &Default::default(),
        Some(test_value_x509::T_REF),
        Some(op.context.timestamp),
    )?;
    let mut state = r.state.clone();
    state.accounting = next.accounting;
    state.continuity = Some(next.registry);
    state.membership_v2 = next.membership;
    state.continuity_keys_v2 = next.keys;
    state.retired_continuity_v2 = next.retired;
    state.node_key_history_v2 = next.node_history;
    state.endorsement_dependencies_v1 = next.endorsement_dependencies;
    state.endorsement_revocations_v1 = next.endorsement_revocations;
    state.bonds_v2 = next.bonds;
    state.penalties_v2 = next.penalties;
    state.root().map_err(|_| Error::WrongAnchor)?;
    Ok(state)
}
fn direct(r: &Rig) -> Operation {
    operation(
        r,
        Target {
            class: TargetClass::Ek,
            scope: TargetScope::Certificate,
            identity: test_value_x509::sha256(&r.chain[0]),
        },
        Evidence::Crl {
            target_certificate: r.chain[0].clone(),
            signer_chain: r.chain[1..].to_vec(),
            crls: r.pki.crls(&[&[0x51]], &[]),
        },
    )
}
// Canonical records deliberately omit the cycle-forming current block anchor.
// Restore only the already authenticated fixture anchor before full typed equality.
fn assert_canonical_state_roundtrip(next: &State) {
    let records = next.records().unwrap();
    let root = next.root().unwrap();
    let mut reopened = State::from_records(&records, root).unwrap();
    assert!(reopened.records().unwrap() == records, "exact canonical records changed");
    assert_eq!(reopened.root().unwrap(), root);
    let decoded = &reopened.continuity.as_ref().unwrap().anchor;
    assert_eq!(decoded.height, 0);
    assert_eq!((decoded.tip, decoded.state_root, decoded.registry_root), ([0;32], [0;32], [0;32]));
    reopened.continuity.as_mut().unwrap().anchor = next.continuity.as_ref().unwrap().anchor.clone();
    assert!(reopened == *next, "typed state changed beyond the explicitly omitted trusted anchor");
}

#[test]
fn genuine_direct_crl_excludes_without_erasing_lineage_or_money_and_replays() {
    let r = rig();
    let before = r.state.records().unwrap();
    let next = transition(&r, &direct(&r)).unwrap();
    assert_eq!(
        r.state.records().unwrap(),
        before,
        "pure preparation keeps original state exact"
    );
    let registry = next.continuity.as_ref().unwrap();
    assert_eq!(registry.members.len(), 1);
    assert_eq!(registry.members[0].node, r.node);
    assert_eq!(registry.members[0].lineage, r.node);
    assert!(!registry.members[0].eligible);
    assert!(registry.weights().unwrap().iter().all(|w| w.is_zero()));
    assert_eq!(next.wallets, r.state.wallets);
    assert_eq!(next.coins, r.state.coins);
    assert_eq!(next.bonds_v2, r.state.bonds_v2);
    assert_eq!(next.penalties_v2, r.state.penalties_v2);
    assert_eq!(next.licenses_v2, r.state.licenses_v2);
    assert_eq!(next.accounting.freshness, r.state.accounting.freshness);
    assert_canonical_state_roundtrip(&next);
}

#[test]
fn genuine_admission_dependency_keeps_finalized_parent_time_distinct_from_h() {
    let r = rig();
    // The signed Genesis fixture has passed native owner/Continuity/Node/quote
    // verification. This private constructor tests its full public witness,
    // not a new admission authorization or containing-block certificate.
    let parent_time = crate::endorsement_dependencies_v1::Book::default()
        .stage_authenticated(
            &r.binding,
            r.node,
            test_value_x509::T_REF,
            &r.witness,
            &r.parameters,
        )
        .unwrap();
    let mut rebuilt = r.state.clone();
    rebuilt.endorsement_dependencies_v1 = parent_time;
    assert_eq!(rebuilt.root().unwrap(), r.root);
    assert_eq!(
        crate::endorsement_dependencies_v1::Book::default()
            .stage_authenticated(
                &r.binding,
                r.node,
                test_value_x509::T_REF + 60,
                &r.witness,
                &r.parameters
            )
            .err(),
        Some(Error::UnqualifiedPhysical)
    );
    // New issuer CRLs are separately authenticated at containing H, while
    // retained admission CRLs expired30s earlier. Replay remains offline.
    let next = transition(&r, &direct(&r)).unwrap();
    assert_canonical_state_roundtrip(&next);
}
#[test]
fn genuine_root_judgment_is_terminal_and_prospective_authority_refuses_reinstatement() {
    let r = rig();
    let op = operation(
        &r,
        Target {
            class: TargetClass::Root,
            scope: TargetScope::Certificate,
            identity: r.pki.root_hash(),
        },
        Evidence::Judgment {
            reason: b"public software withdrawal fixture".to_vec(),
            evidence: vec![
                r.pki.root.clone(),
                b"TEST-VALUE explicit terminal judgment; no allegation-proof claim".to_vec(),
            ],
        },
    );
    let next = transition(&r, &op).unwrap();
    let mut revived = next.clone();
    revived.continuity.as_mut().unwrap().members[0].eligible = true;
    assert!(revived.root().is_err());
    assert!(
        crate::votes_v2::HeightAuthority::from_validated_components(&revived, r.parent.clone())
            .is_err()
    );
    assert_eq!(next.accounting.freshness, r.state.accounting.freshness);
}
#[test]
fn signed_hold_is_not_terminal_crl_but_explicit_judgment_can_withdraw() {
    let r = rig();
    let mut tbs = r.pki.crl_tbs(false, &[&[0x51]]);
    tbs.revoked_certificates.as_mut().unwrap()[0].crl_entry_extensions =
        Some(vec![test_value_x509::ext(
            ObjectIdentifier::new_unwrap("2.5.29.21"),
            false,
            &CrlReason::CertificateHold,
        )]);
    let held = r.pki.sign_crl(&tbs, false);
    let mut op = direct(&r);
    if let Evidence::Crl { crls, .. } = &mut op.evidence {
        crls[0] = held.clone();
    }
    assert_eq!(transition(&r, &op).err(), Some(Error::UnqualifiedPhysical));
    op.evidence = Evidence::Judgment {
        reason: b"explicit terminal judgment on public hold evidence".to_vec(),
        evidence: vec![held],
    };
    assert!(transition(&r, &op).is_ok());
}

#[test]
fn signed_crl_uses_containing_h_time_and_actual_issuer_signature() {
    let r = rig();
    let h_time = test_value_x509::T_REF + 60;
    // This CRL did not exist at Genesis/admission T_ref. Its fresh H context,
    // rather than the retained admission witness time, governs new withdrawal.
    let mut tbs = r.pki.crl_tbs(false, &[&[0x51]]);
    tbs.this_update = test_value_x509::time(h_time);
    tbs.next_update = Some(test_value_x509::time(h_time));
    let with_crl = |raw: Vec<u8>| {
        let mut op = direct(&r);
        if let Evidence::Crl { crls, .. } = &mut op.evidence {
            crls[0] = raw;
        }
        op
    };
    let good = with_crl(r.pki.sign_crl(&tbs, false));
    assert!(
        transition(&r, &good).is_ok(),
        "inclusive H freshness boundary"
    );
    let mut future = tbs.clone();
    future.this_update = test_value_x509::time(h_time + 1);
    future.next_update = Some(test_value_x509::time(h_time + 10));
    assert_eq!(
        transition(&r, &with_crl(r.pki.sign_crl(&future, false))).err(),
        Some(Error::UnqualifiedPhysical)
    );
    let mut expired = tbs.clone();
    expired.this_update = test_value_x509::time(h_time - 2);
    expired.next_update = Some(test_value_x509::time(h_time - 1));
    assert_eq!(
        transition(&r, &with_crl(r.pki.sign_crl(&expired, false))).err(),
        Some(Error::UnqualifiedPhysical)
    );
    let mut wrong_signature = r.pki.sign_crl(&tbs, false);
    *wrong_signature.last_mut().unwrap() ^= 1;
    assert!(transition(&r, &with_crl(wrong_signature)).is_err());
    assert_eq!(
        r.state.root().unwrap(),
        r.root,
        "all preparation retains parent"
    );
}

#[test]
fn genuine_base_delta_pair_withdraws_but_wrong_base_and_hold_removal_do_not() {
    let r = rig();
    let delta_oid = ObjectIdentifier::new_unwrap("2.5.29.27");
    let number_oid = ObjectIdentifier::new_unwrap("2.5.29.20");
    let delta = |reason: CrlReason, minimum: u8| {
        let mut tbs = r.pki.crl_tbs(false, &[&[0x51]]);
        tbs.revoked_certificates.as_mut().unwrap()[0].crl_entry_extensions =
            Some(vec![test_value_x509::ext(
                ObjectIdentifier::new_unwrap("2.5.29.21"),
                false,
                &reason,
            )]);
        let extensions = tbs.crl_extensions.as_mut().unwrap();
        extensions.retain(|ext| ext.extn_id != number_oid);
        extensions.push(test_value_x509::ext(
            number_oid,
            false,
            &CrlNumber(Uint::new(&[3]).unwrap()),
        ));
        extensions.push(test_value_x509::ext(
            delta_oid,
            true,
            &Uint::new(&[minimum]).unwrap(),
        ));
        r.pki.sign_crl(&tbs, false)
    };
    let paired = |base: Vec<u8>, delta: Vec<u8>| {
        let mut op = direct(&r);
        if let Evidence::Crl { crls, .. } = &mut op.evidence {
            *crls = vec![base, delta, r.pki.sign_crl(&r.pki.crl_tbs(true, &[]), true)];
        }
        op
    };
    let base = r.pki.sign_crl(&r.pki.crl_tbs(false, &[]), false);
    assert!(
        transition(
            &r,
            &paired(base.clone(), delta(CrlReason::KeyCompromise, 1))
        )
        .is_ok()
    );
    assert_eq!(
        transition(&r, &paired(base, delta(CrlReason::KeyCompromise, 2))).err(),
        Some(Error::UnqualifiedPhysical)
    );
    let mut held = r.pki.crl_tbs(false, &[&[0x51]]);
    held.revoked_certificates.as_mut().unwrap()[0].crl_entry_extensions =
        Some(vec![test_value_x509::ext(
            ObjectIdentifier::new_unwrap("2.5.29.21"),
            false,
            &CrlReason::CertificateHold,
        )]);
    assert_eq!(
        transition(
            &r,
            &paired(
                r.pki.sign_crl(&held, false),
                delta(CrlReason::RemoveFromCRL, 1)
            )
        )
        .err(),
        Some(Error::UnqualifiedPhysical)
    );
    assert_eq!(r.state.root().unwrap(), r.root);
}

fn delegated(r: &Rig, indirect: bool, entry_issuer: x509_cert::name::Name) -> Operation {
    let signer = delegate_key();
    let mut cert = r.pki.intermediate_tbs();
    cert.serial_number = x509_cert::serial_number::SerialNumber::new(&[0x90]).unwrap();
    cert.subject = delegate_name();
    cert.issuer = r.pki.intermediate_name();
    cert.signature = r.pki.intermediate_key.algorithm();
    cert.subject_public_key_info = test_value_x509::spki(&signer.public());
    cert.extensions = Some(vec![
        test_value_x509::ext(
            ObjectIdentifier::new_unwrap("2.5.29.19"),
            true,
            &BasicConstraints {
                ca: false,
                path_len_constraint: None,
            },
        ),
        test_value_x509::ext(
            ObjectIdentifier::new_unwrap("2.5.29.15"),
            true,
            &test_value_x509::key_usage(KeyUsages::CRLSign),
        ),
        test_value_x509::ext(
            ObjectIdentifier::new_unwrap("2.5.29.14"),
            false,
            &SubjectKeyIdentifier(OctetString::new(signer.key_id()).unwrap()),
        ),
        test_value_x509::ext(
            ObjectIdentifier::new_unwrap("2.5.29.35"),
            false,
            &AuthorityKeyIdentifier {
                key_identifier: Some(OctetString::new(r.pki.intermediate_key.key_id()).unwrap()),
                ..Default::default()
            },
        ),
    ]);
    let signer_cert = r.pki.issue(&cert);
    let mut crl = r.pki.crl_tbs(false, &[&[0x51]]);
    crl.issuer = delegate_name();
    crl.signature = signer.algorithm();
    let extensions = crl.crl_extensions.as_mut().unwrap();
    extensions.retain(|ext| ext.extn_id != ObjectIdentifier::new_unwrap("2.5.29.35"));
    extensions.push(test_value_x509::ext(
        ObjectIdentifier::new_unwrap("2.5.29.35"),
        false,
        &AuthorityKeyIdentifier {
            key_identifier: Some(OctetString::new(signer.key_id()).unwrap()),
            ..Default::default()
        },
    ));
    // Explicit RFC IDP OID, not this pinned library's incorrect AssociatedOid.
    extensions.push(test_value_x509::ext(
        ObjectIdentifier::new_unwrap("2.5.29.28"),
        true,
        &IssuingDistributionPoint {
            distribution_point: None,
            only_contains_user_certs: true,
            only_contains_ca_certs: false,
            only_some_reasons: None,
            indirect_crl: indirect,
            only_contains_attribute_certs: false,
        },
    ));
    crl.revoked_certificates.as_mut().unwrap()[0].crl_entry_extensions =
        Some(vec![test_value_x509::ext(
            ObjectIdentifier::new_unwrap("2.5.29.29"),
            true,
            &vec![GeneralName::DirectoryName(entry_issuer)],
        )]);
    let tbs = crl.to_der().unwrap();
    let signed =
        test_value_x509::assemble(&tbs, &crl.signature.to_der().unwrap(), &signer.sign(&tbs));
    operation(
        r,
        Target {
            class: TargetClass::Ek,
            scope: TargetScope::Certificate,
            identity: test_value_x509::sha256(&r.chain[0]),
        },
        Evidence::Crl {
            target_certificate: r.chain[0].clone(),
            signer_chain: vec![signer_cert, r.pki.intermediate.clone(), r.pki.root.clone()],
            crls: vec![
                signed,
                r.pki.sign_crl(&r.pki.crl_tbs(false, &[]), false),
                r.pki.sign_crl(&r.pki.crl_tbs(true, &[]), true),
            ],
        },
    )
}
#[test]
fn genuine_authorized_delegate_requires_target_distribution_point_and_entry_issuer() {
    let r = rig_with_delegated_target(true);
    let op = delegated(&r, true, r.pki.intermediate_name());
    assert!(
        transition(&r, &op).is_ok(),
        "genuine signed authorized indirect CRL"
    );
    assert_eq!(
        transition(&r, &delegated(&r, true, r.pki.root_name())).err(),
        Some(Error::UnqualifiedPhysical),
        "same serial with wrong entry issuer cannot match"
    );
    assert_eq!(
        transition(&r, &delegated(&r, false, r.pki.intermediate_name())).err(),
        Some(Error::UnqualifiedPhysical),
        "certificateIssuer requires signed indirect profile"
    );
    let no_delegate = rig();
    assert_eq!(
        transition(
            &no_delegate,
            &delegated(&no_delegate, true, no_delegate.pki.intermediate_name())
        )
        .err(),
        Some(Error::UnqualifiedPhysical),
        "a genuine same-anchor signer is insufficient without target authorization"
    );
    assert_eq!(r.state.root().unwrap(), r.root);
    assert_eq!(no_delegate.state.root().unwrap(), no_delegate.root);
}

#[test]
fn genuine_containing_h_certificate_uses_parent_weights_and_reopened_h_is_no_quorum() {
    let r = rig();
    let next = transition(&r, &direct(&r)).unwrap();
    let authority =
        crate::votes_v2::HeightAuthority::from_state(&r.state, r.parent.clone(), r.root).unwrap();
    let voter = &authority.voters[&r.node];
    // Native certificate/weight boundary only. This does not claim a complete
    // licensed PoW envelope, canonical store installation or physical host.
    let decision = crate::certificates::Decision {
        network: crate::NETWORK_ID,
        genesis: r.parent.genesis,
        fingerprint: r.parent.fingerprint,
        purpose: 2,
        height: 1,
        mining_epoch: 0,
        continuity_period: 0,
        round: 0,
        step: 3,
        previous_finalized_anchor: r.parent.id(),
        parent: r.parent.block,
        block: label("component-certificate-block"),
        state: next.root().unwrap(),
        membership: authority.membership,
        reputation: authority.reputation,
        attestation: authority.attestation,
    };
    let mut vote = crate::continuity_v2::Vote {
        decision: decision.clone(),
        nil: false,
        node: r.node,
        hardware_generation: voter.hardware_generation,
        key_generation: voter.key_generation,
        sequence: 1,
        tpm_identity: voter.tpm_identity(),
        profile: voter.profile,
        signature: zero(),
    };
    vote.sign(&r.continuity).unwrap();
    let cert = crate::continuity_v2::Certificate {
        decision: decision.clone(),
        votes: vec![vote],
    };
    cert.verify_quorum(&decision, &r.parent, &authority.voters)
        .unwrap();
    let reopened = State::from_records(&next.records().unwrap(), next.root().unwrap()).unwrap();
    assert!(reopened.endorsement_revocations_v1.terminal_no_quorum());
    let post = crate::votes_v2::HeightAuthority::from_validated_components(
        &reopened,
        FinalizedAnchor {
            height: 1,
            block: decision.block,
            ..r.parent.clone()
        },
    )
    .unwrap();
    assert_eq!(
        cert.verify_quorum(&decision, &r.parent, &post.voters),
        Err(Error::NoQuorum)
    );
    assert!(matches!(
        crate::votes_v2::AuthenticatedRound::new(post),
        Err(crate::votes::IngressError::Bft(
            crate::bft::BftError::NoQuorum
        ))
    ));
    assert_eq!(r.state.root().unwrap(), r.root);
}

#[path = "canonical_store_no_quorum_tests.rs"]
mod canonical_store_tests;

#[path = "serial_magnitude_tests.rs"]
mod serial_magnitude_tests;

#[path = "assembler_preflight_tests.rs"]
mod assembler_preflight_tests;

#[path = "genuine_long_path_pki_tests.rs"]
mod genuine_long_path_pki_tests;

#[cfg(all(test, any(windows, target_os="linux"), feature = "a2-local-fixture-generator"))]
#[path = "local_synthetic_fixture_generator.rs"]
mod local_fixture_generator;

// Current-rule private modeled host; ordinary library graph cannot reach it.
#[path = "native16_test_host.rs"]
pub(crate) mod native16_test_host;


// Selected TEST-VALUE root alias tests use the genuine pre-identity Genesis
// constructor and available signed DER witnesses above, not private State edits.
fn selected_alias_rig(unused:&[test_value_x509::X509Pki])->Rig {
    let pki=test_value_x509::X509Pki::new("selected-test-value-a2-root-alias");
    let tpm=TestTpm::stripped(software_tpm::Strip::ConsistentProvenance(pki.root_hash()));
    let chain=pki.chain(&tpm.simulator_ek(),&[0x51]);
    let crls=pki.crls(&[],&[]);
    let anchor=pki.anchor(RevocationMode::CrlRequired,&[test_value_ek::ECC_CLASS],
        &[SignatureAlgorithm::EcdsaP256Sha256,SignatureAlgorithm::EcdsaP384Sha384]);
    rig_with_selected_material(pki,unused,tpm,chain,crls,anchor,true)
}
#[test]
fn selected_alias_crl_keeps_exact_der_targets_and_replayed_dependencies() {
    let r=selected_alias_rig(&[]);
    assert_eq!(r.parameters.class,GenesisClass::TestValue);
    let logical=*r.parameters.roots.roots.keys().next().unwrap();assert_ne!(logical,r.pki.root_hash());
    let rebuilt=crate::endorsement_dependencies_v1::Book::default().stage_authenticated(
        &r.binding,r.node,test_value_x509::T_REF,&r.witness,&r.parameters).unwrap();
    let mut exact=r.state.clone();exact.endorsement_dependencies_v1=rebuilt;
    assert_eq!(exact.root().unwrap(),r.root);
    let next=transition(&r,&direct(&r)).unwrap();
    assert!(next.endorsement_revocations_v1.terminal_no_quorum());
    assert_eq!(next.licenses_v2,r.state.licenses_v2);assert_eq!(next.wallets,r.state.wallets);
    assert_canonical_state_roundtrip(&next);
}
#[test]
fn selected_alias_unused_root_judgment_authenticates_der_not_logical_id() {
    let unused=test_value_x509::X509Pki::new("selected-alias-unused-root");
    let r=selected_alias_rig(std::slice::from_ref(&unused));
    let target=Target {class:TargetClass::Root,scope:TargetScope::Certificate,identity:unused.root_hash()};
    let op=operation(&r,target,Evidence::Judgment {reason:b"PUBLIC TEST unused root judgment".to_vec(),evidence:vec![unused.root.clone()]});
    let next=transition(&r,&op).unwrap();
    assert!(!next.endorsement_revocations_v1.terminal_no_quorum());
    assert_eq!(next.continuity.as_ref().unwrap().members,r.state.continuity.as_ref().unwrap().members);
    assert_canonical_state_roundtrip(&next);
    let mut label=crate::test_value_root_alias_v1::LABEL_PREFIX.to_vec();label.extend(unused.root_hash());
    let mut wrong=op.clone();wrong.target.identity=genesis_v2::test_value_root(&label);
    assert!(transition(&r,&wrong).is_err(),"logical policy roots are not certificate targets");
    let before=r.state.records().unwrap();assert!(transition(&r,&wrong).is_err());assert_eq!(r.state.records().unwrap(),before);
}
#[test]
fn selected_alias_root_judgment_certified_store_finality_and_reopen() {
    let r=selected_alias_rig(&[]);
    let op=operation(&r,Target {class:TargetClass::Root,scope:TargetScope::Certificate,identity:r.pki.root_hash()},
        Evidence::Judgment {reason:b"PUBLIC TEST selected alias terminal root".to_vec(),evidence:vec![r.pki.root.clone()]});
    canonical_store_tests::assert_terminal_store(r,op);
}
