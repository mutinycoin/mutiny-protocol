//! UNRUN private public-DER controls. Production activation remains refused.
//! Scope comes only from AuthenticatedRound's successful native execution.
use super::*;
use super::canonical_chain_tests::{anchor, certified_next, prepare_body};
use super::super::foundation_tests::{genuine_material_at, Material};
use crate::activation_attestation_v1::{Scope, Position, Purpose, Failure};

fn executed_join(host: &ModelHost)
    -> (BlockEnvelope, crate::execution::Execution, Option<Scope>, Join, Vec<u8>) {
    let prefix = VerifiedPrefix::verify(host, &[]).unwrap();
    let material = genuine_material_at(host, 1, &host.fixture.parent, prefix.parent.t0);
    let outer = material.outer.clone();
    let join = material.join.clone();
    let witness = crate::admission_public_v3::Carrier::decode(&outer).unwrap().witness().to_vec();
    let materials: Vec<Material> = vec![material];
    let raw = certified_next(host, &prefix, vec![outer.clone()], &materials);
    let capacity = crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(
        &prefix.state, anchor(host, &prefix), prefix.root).unwrap();
    let block = BlockEnvelope::decode_with_capacity(&raw, &capacity).unwrap();
    let (_, body, prepared) = prepare_body(host, &prefix, vec![outer]).unwrap();
    assert_eq!(body, block.body);
    assert_eq!(prepared.computed_root, block.header.candidate.state_root);
    let x = ExecutionPin { prepared: prepared.pin, computed_root: prepared.computed_root,
        header: block.header.encode(), authority: block.authority.encode().unwrap() };
    let old = HeightAuthority::from_state(&prefix.state, host.fixture.parent.clone(), prefix.root).unwrap();
    let mut round = crate::votes_v2::AuthenticatedRound::new(old).unwrap();
    let execution = {
        let _entry = Lease::install(Mode::Execute(x)).unwrap();
        round.validate_proposal_with_history(&prefix.state, &prefix.parent,
            &block.header, &block.authority, &block.body, &prefix.history).unwrap()
    };
    assert_eq!(execution.root, block.header.candidate.state_root);
    let scope = round.activation_scope(block.header.block_hash()).unwrap().cloned();
    assert!(ACTIVE.with(|slot| slot.borrow().is_none()));
    (block, execution, scope, join, witness)
}

fn independent_commitment(parent: &FinalizedAnchor, block: &BlockEnvelope,
    body: &[u8], binding: &crate::node_admission_v2::Binding) -> Hash {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(8).unwrap().u8(1).unwrap().u32(crate::NETWORK_ID).unwrap()
        .bytes(&parent.encode()).unwrap().bytes(&block.header.block_hash()).unwrap()
        .bytes(&block.header.encode()).unwrap().bytes(body).unwrap()
        .bytes(&crate::activation_attestation_v1::rule_commitment()).unwrap()
        .array(1).unwrap().array(3).unwrap().array(2).unwrap().u8(1).unwrap().u32(0).unwrap()
        .bytes(&crate::domain_hash(crate::operation_index_v2::WIRE_DOMAIN,
            &block.body.operations[0])).unwrap()
        .bytes(&binding.encode().unwrap()).unwrap();
    crate::domain_hash(crate::activation_attestation_v1::SCOPE_DOMAIN, &e.into_writer())
}

#[test]
fn original_unselected_genuine_v3_join_has_no_activation_scope() {
    let host = ModelHost::new();
    assert_eq!(crate::activation_attestation_v1::selected(&host.fixture.state), Ok(false));
    let (_, execution, scope, join, _) = executed_join(&host);
    assert!(execution.state.membership_v2.get(join.binding.admission.node).is_some());
    assert!(scope.is_none());
}

#[test]
fn independently_refrozen_wrong_activation_commitment_cannot_select_authority() {
    // Wrong commitment is frozen in independently constructed Inputs before
    // any native Genesis/signatures, never patched into a verified State.
    assert!(matches!(super::super::super::rig_wrong_activation(),
        Err(crate::genesis_v2::GenesisV2Error::Consensus(Error::WrongFingerprint))));
    // Native Genesis refuses the independently frozen wrong rule before a
    // State/authority exists. Never synthesize a verified wrong-rule State.
    let fixture = super::super::super::rig_current_activation();
    assert_eq!(crate::activation_attestation_v1::selected(&fixture.state), Ok(true));
    assert!(HeightAuthority::from_state(&fixture.state,
        fixture.parent.clone(), fixture.root).is_ok());
    assert!(ACTIVE.with(|slot| slot.borrow().is_none()));
}

#[test]
fn selected_genuine_v3_join_native_scope_keeps_outer_witness_whole_body_and_inner_binding() {
    let host = ModelHost::with_current_activation();
    assert_eq!(crate::activation_attestation_v1::selected(&host.fixture.state), Ok(true));
    let (block, execution, scope, join, witness) = executed_join(&host);
    let scope = scope.expect("successful selected native execution must retain scope");
    let capacity = crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(
        &host.fixture.state, host.fixture.parent.clone(), host.fixture.root).unwrap();
    let body = capacity.encode(&block.body).unwrap();
    assert_eq!(scope.parent(), &host.fixture.parent);
    assert_eq!(scope.block(), block.header.block_hash());
    assert_eq!(scope.body_bytes(), body);
    assert_eq!(scope.admissions().len(), 1);
    let accepted = &scope.admissions()[0];
    assert_eq!(accepted.position(), Position::Operation(0));
    assert_eq!(accepted.purpose(), Purpose::Join);
    assert_eq!(accepted.node(), join.binding.admission.node);
    assert_eq!(accepted.binding_bytes(), join.binding.encode().unwrap());
    let profile = crate::tpm::TpmProfile::decode(&join.binding.admission.profile).unwrap();
    assert_eq!(accepted.ak_name(), &crate::provenance::ak_name(&profile.ak_public).unwrap());
    assert_eq!(accepted.endorsements(), crate::endorsement_identity::committed_identities(&profile));
    assert_eq!(scope.commitment(), independent_commitment(&host.fixture.parent, &block, &body, &join.binding));
    assert_eq!(execution.state.membership_v2.get(accepted.node()).unwrap().binding(), &join.binding);
    // The real accepted Production-shaped receipt cannot enable the normal
    // private activation provider. No class rewrite or TEST material substitute.
    let anchors = host.fixture.parameters.roots.anchors();
    let ctx = crate::attestation_witness::WitnessContext {
        chain: crate::ek_chain::ChainContext { class: host.fixture.parameters.class.admission_class(),
            reference_time: crate::execution_v2::admission_parent_time(
                &VerifiedPrefix::verify(&host, &[]).unwrap().parent).unwrap(), anchors: &anchors },
        identity_classes: &host.fixture.parameters.identity_classes,
    };
    assert!(matches!(crate::activation_attestation_v1::Material::validate(
        accepted, &witness, &ctx, &crate::x509_syntax::X509Syntax), Err(Failure::ProviderUnavailable)));
}

#[test]
fn selected_join_substituted_witness_refuses_before_any_private_preparation_grant() {
    let host = ModelHost::with_current_activation();
    let prefix = VerifiedPrefix::verify(&host, &[]).unwrap();
    let material = genuine_material_at(&host, 1, &host.fixture.parent, prefix.parent.t0);
    let parsed = crate::admission_public_v3::Carrier::decode(&material.outer).unwrap();
    let donor = genuine_material_at(&host, 2, &host.fixture.parent, prefix.parent.t0);
    let donor_carrier = crate::admission_public_v3::Carrier::decode(&donor.outer).unwrap();
    let donor_witness = donor_carrier.witness().to_vec();
    assert_ne!(donor_witness.as_slice(), parsed.witness());
    crate::attestation_witness::AttestationWitness::decode(&donor_witness).unwrap();
    let bad = crate::admission_public_v3::Carrier::new(15,
        parsed.signed().to_vec(), donor_witness).unwrap().encode().unwrap();
    assert_eq!(crate::admission_public_v3::Carrier::decode(&bad).unwrap().signed(), parsed.signed());
    let mut body = BlockBody { height: 1, reward_owner: [0;32], transactions: vec![], fees: 0, operations: vec![bad] };
    let root = host.fixture.state.root().unwrap();
    assert!(matches!(host.verify_pins(&host.fixture.state, &prefix.parent, &body),
        Err(Error::UnqualifiedPhysical)));
    assert!(ACTIVE.with(|slot| slot.borrow().is_none()));
    assert_eq!(host.fixture.state.root().unwrap(), root);
    // Positive full independent witness control; this is native witness-API
    // refusal before grants, not a claimed later Round execution branch.
    body.operations = vec![material.outer];
    assert_eq!(host.verify_pins(&host.fixture.state, &prefix.parent, &body).unwrap().len(), 1);
}

#[test]
fn selected_same_hardware_key_rotation_native_scope_keeps_exact_new_and_retired_bindings() {
    use mutiny_crypto_v2::{HybridKey, Role};
    use super::super::super::{software_tpm, TestTpm, zero, label};
    let host = ModelHost::with_current_activation();
    let prefix = VerifiedPrefix::verify(&host, &[]).unwrap();
    let old = host.fixture.binding.clone();
    let profile = crate::tpm::TpmProfile::decode(&old.admission.profile).unwrap();
    let tpm = TestTpm::stripped(software_tpm::Strip::ConsistentProvenance(
        host.fixture.pki.root_hash())).with_provenance(profile.provenance.clone().unwrap());
    assert_eq!(tpm.profile().encode().unwrap(), old.admission.profile);
    let replacement = HybridKey::generate(Role::Continuity).unwrap();
    let owner = HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)),
        Role::WalletOwner).unwrap();
    let mut binding = old.clone();
    binding.admission.key_generation = 2;
    binding.admission.continuity_descriptor = replacement.public().descriptor(2).unwrap();
    binding.admission.possession = zero();
    binding.admission.authorization = zero();
    binding.possession = zero();
    let mut rotation = crate::continuity_key_rotate_v2::KeyRotate {
        parent: host.fixture.parent.clone(), nonce: label("scope37-key-rotate"),
        sequence: host.fixture.state.membership_v2.get(host.fixture.node).unwrap()
            .sequence().checked_add(1).unwrap(), old_key_generation: 1, binding,
    };
    rotation.binding.admission.supervised_nonce = rotation.admission_nonce().unwrap();
    rotation.binding.admission.prove_continuity(&replacement).unwrap();
    rotation.binding.admission.quote = tpm.quote(rotation.binding.admission.challenge().unwrap());
    rotation.binding.admission.authorize(&owner, 1).unwrap();
    rotation.binding.sign(&host.fixture.node_key).unwrap();
    // Same hardware/profile, genuinely new BOTH_REQUIRED software key tuple.
    rotation.verify(&prefix.state, &host.fixture.parent, prefix.root).unwrap();
    let operation = rotation.encode().unwrap();
    let raw = certified_next(&host, &prefix, vec![operation.clone()], &[]);
    let capacity = crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(
        &prefix.state, host.fixture.parent.clone(), prefix.root).unwrap();
    let block = BlockEnvelope::decode_with_capacity(&raw, &capacity).unwrap();
    let (_, body, prepared) = prepare_body(&host, &prefix, vec![operation]).unwrap();
    assert_eq!(body, block.body);
    assert_eq!(prepared.computed_root, block.header.candidate.state_root);
    let x = ExecutionPin { prepared: prepared.pin, computed_root: prepared.computed_root,
        header: block.header.encode(), authority: block.authority.encode().unwrap() };
    let authority = HeightAuthority::from_state(&prefix.state,
        host.fixture.parent.clone(), prefix.root).unwrap();
    let mut round = crate::votes_v2::AuthenticatedRound::new(authority).unwrap();
    let execution = {
        let _x = Lease::install(Mode::Execute(x)).unwrap();
        round.validate_proposal_with_history(&prefix.state, &prefix.parent,
            &block.header, &block.authority, &block.body, &prefix.history).unwrap()
    };
    assert_eq!(execution.root, block.header.candidate.state_root);
    let scope = round.activation_scope(block.header.block_hash()).unwrap().unwrap();
    assert_eq!(scope.admissions().len(), 1);
    let admitted = &scope.admissions()[0];
    assert_eq!(admitted.purpose(), Purpose::ContinuityBinding);
    assert_eq!(admitted.binding_bytes(), rotation.binding.encode().unwrap());
    assert_eq!(scope.commitment(), independent_commitment(&host.fixture.parent,
        &block, &capacity.encode(&block.body).unwrap(), &rotation.binding));
    assert_eq!(execution.state.membership_v2.get(host.fixture.node).unwrap().binding(),
        &rotation.binding);
    assert!(execution.state.retired_continuity_v2.entries().any(|retired|
        retired.retired_height == 1 && retired.binding == old));
    assert!(ACTIVE.with(|slot| slot.borrow().is_none()));
    // This native continuity receipt retains class/lineage semantics; it is not
    // a hardware replacement, private activation or factory qualification.
}

#[test]
fn selected_genuine_v3_hardware_replacement_preserves_post_sealing_production_refusal() {
    use mutiny_crypto_v2::{HybridKey, Role};
    use super::super::super::{label, zero};
    let host = ModelHost::with_current_activation();
    let prefix = VerifiedPrefix::verify(&host, &[]).unwrap();
    let material = genuine_material_at(&host, 1, &host.fixture.parent, prefix.parent.t0);
    let witness = crate::admission_public_v3::Carrier::decode(&material.outer)
        .unwrap().witness().to_vec();
    let owner = HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)),
        Role::WalletOwner).unwrap();
    let mut binding = material.join.binding.clone();
    binding.node_descriptor = host.fixture.binding.node_descriptor.clone();
    binding.admission.node = host.fixture.node;
    binding.admission.hardware_generation = 2;
    binding.admission.key_generation = 2;
    binding.admission.continuity_descriptor = material.continuity.public().descriptor(2).unwrap();
    binding.admission.possession = zero(); binding.admission.authorization = zero();
    binding.possession = zero();
    let mut rotation = crate::hardware_rotate_v2::HardwareRotate {
        parent: host.fixture.parent.clone(), nonce: label("scope37-hardware-rotate"),
        sequence: host.fixture.state.membership_v2.get(host.fixture.node).unwrap()
            .sequence().checked_add(1).unwrap(), old_hardware_generation: 1,
        old_key_generation: 1, binding, native_possession: [0;64],
    };
    rotation.binding.admission.supervised_nonce = rotation.admission_nonce().unwrap();
    rotation.binding.admission.prove_continuity(&material.continuity).unwrap();
    rotation.binding.admission.quote = material.tpm.quote(
        rotation.binding.admission.challenge().unwrap());
    rotation.binding.admission.authorize(&owner, 1).unwrap();
    rotation.binding.sign(&host.fixture.node_key).unwrap();
    rotation.native_possession = material.tpm.possession(rotation.native_digest().unwrap());
    // This verifier reaches the unchanged class guard ONLY after full native
    // hybrid/owner/Node/quote and new-identity native-possession verification.
    assert!(matches!(rotation.verify(&prefix.state, &host.fixture.parent, prefix.root),
        Err(Error::AdmissionAuthorityEnded)));
    let mut bad = rotation.clone(); bad.native_possession = [0;64];
    assert!(matches!(bad.verify(&prefix.state, &host.fixture.parent, prefix.root),
        Err(Error::BadSignature)));
    let operation = crate::admission_public_v3::Carrier::new(16,
        rotation.encode().unwrap(), witness).unwrap().encode().unwrap();
    let records = prefix.state.records().unwrap();
    assert!(matches!(prepare_body(&host, &prefix, vec![operation]),
        Err(crate::execution::ExecutionError::Codec(Error::AdmissionAuthorityEnded))));
    assert_eq!(prefix.state.root().unwrap(), prefix.root);
    assert_eq!(prefix.state.records().unwrap(), records);
    assert!(ACTIVE.with(|slot|slot.borrow().is_none()));
    // No actual hardware Scope can be claimed: native execution refuses this
    // Production-shaped software fixture. No hardware/private-provider grant
    // was added to the narrowly Join-only TEST model.
}

#[test]
fn selected_genuine_recovery_material_and_available_v3_record_preserve_production_refusal() {
    use mutiny_crypto_v2::{HybridKey, Role};
    use super::super::super::{label, zero};
    let host = ModelHost::with_current_activation();
    let prefix = VerifiedPrefix::verify(&host, &[]).unwrap();
    let material = genuine_material_at(&host, 1, &host.fixture.parent, prefix.parent.t0);
    let witness = crate::admission_public_v3::Carrier::decode(&material.outer)
        .unwrap().witness().to_vec();
    let owner = HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)),
        Role::WalletOwner).unwrap();
    let recovery_key = HybridKey::wallet_restore("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title", Role::WalletRecovery).unwrap();
    let recovery = prefix.state.recovery_authority_v2.as_ref().unwrap();
    assert_eq!(recovery.descriptor, recovery_key.public().descriptor(1).unwrap());
    let old_authority = HeightAuthority::from_state(&prefix.state,
        host.fixture.parent.clone(), prefix.root).unwrap();
    let old_member = prefix.state.continuity.as_ref().unwrap().members.iter()
        .find(|m|m.node == host.fixture.node).unwrap();
    let mut binding = material.join.binding.clone();
    binding.admission.hardware_generation = 2; binding.admission.key_generation = 2;
    binding.admission.continuity_descriptor = material.continuity.public().descriptor(2).unwrap();
    binding.admission.possession = zero(); binding.admission.authorization = zero();
    binding.possession = zero();
    let mut replacement = crate::recovery_replacement_v2::Replacement {
        parent: host.fixture.parent.clone(), root: prefix.root,
        membership: old_authority.membership, sequence: 1, lineage: old_member.lineage,
        old_node: old_member.node, old_hardware_generation: 1, old_key_generation: 1,
        nonce: label("scope37-recovery"), lost: vec![(old_member.node, 1)],
        binding, native_possession: [0;64],
    };
    replacement.binding.admission.supervised_nonce = replacement.admission_nonce().unwrap();
    replacement.binding.admission.prove_continuity(&material.continuity).unwrap();
    replacement.binding.admission.quote = material.tpm.quote(
        replacement.binding.admission.challenge().unwrap());
    replacement.binding.admission.authorize(&owner, 1).unwrap();
    replacement.binding.sign(&material.node).unwrap();
    replacement.native_possession = material.tpm.possession(replacement.native_digest().unwrap());
    let authorization = crate::recovery_authority_v2::Authorization::sign(
        replacement.intent().unwrap(), recovery, &recovery_key).unwrap();
    // Actual full cryptographic, loss, alias, old-lineage and material verifier
    // reaches its unchanged final Production class guard, not an invented loss.
    assert!(matches!(replacement.verify_material(&prefix.state, &host.fixture.parent,
        prefix.root, &authorization, false), Err(Error::AdmissionAuthorityEnded)));
    let mut bad_authorization = authorization.clone(); bad_authorization.signature = zero();
    assert!(matches!(replacement.verify_material(&prefix.state, &host.fixture.parent,
        prefix.root, &bad_authorization, false), Err(Error::BadSignature)));
    let policy = prefix.state.current_admission_policy_v2(
        host.fixture.parent.genesis, host.fixture.parent.fingerprint).unwrap();
    let mut tree = crate::state_tree::StateTree::default();
    let records = prefix.state.records().unwrap();
    for (key, raw) in &records { tree.insert(*key, raw.clone()).unwrap(); }
    assert_eq!(tree.root(), prefix.root);
    let record = crate::recovery_history_v2::Record {
        material: replacement, authorization, policy,
        witnesses: crate::recovery_witness_v2::Witnesses {
            control: tree.proof(host.fixture.parent.clone(), crate::domain_hash(
                b"MUTINY-BUILD8-NODE-CONTROL-KEY-V2", &old_member.node)),
            continuity: tree.proof(host.fixture.parent.clone(), crate::domain_hash(
                b"MUTINY-BUILD8-CONTINUITY-KEY-STATE-V2", &old_member.node)),
        },
    };
    record.verify_history_only(recovery).unwrap();
    let carrier = crate::recovery_public_v3::Carrier::new(record.encode(recovery).unwrap(),
        witness.clone(), recovery).unwrap();
    let outer = carrier.encode(recovery).unwrap();
    let parsed = crate::recovery_public_v3::Carrier::decode(&outer, recovery).unwrap();
    assert_eq!(parsed.record(recovery).unwrap(), record);
    assert_eq!(parsed.witness(), witness);
    // Public witness authentication remains at finalized-parent T_ref. It
    // supplies no eligibility grant or direct mutation of canonical State.
    prefix.state.endorsement_dependencies_v1.stage_authenticated(&record.material.binding,
        old_member.lineage, prefix.parent.t0, &witness, &host.fixture.parameters).unwrap();
    assert!(matches!(crate::recovery_transition_v2::Prepared::verify_with_public_witness(
        &prefix.state, &host.fixture.parent, prefix.root, record, false,
        Some((&witness, prefix.parent.t0))), Err(Error::AdmissionAuthorityEnded)));
    assert_eq!(prefix.state.root().unwrap(), prefix.root);
    assert_eq!(prefix.state.records().unwrap(), records);
    assert!(ACTIVE.with(|slot|slot.borrow().is_none()));
    // No Prepared/Scope was constructed. Recovery and same-H retired recovery
    // Scope success still require a separately reviewed native host mechanism.
}


#[test]
fn selected_join_certified_substituted_body_refuses_exact_x_atomically_then_genuine_commit_reopens() {
    use super::canonical_chain_tests::{database_rows,directory,install,signed_invalid_variant};
    let host=ModelHost::with_current_activation();
    let prefix=VerifiedPrefix::verify(&host,&[]).unwrap();
    let (block,execution,scope,_,_)=executed_join(&host);
    assert!(scope.is_some());
    let capacity=crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(
        &prefix.state,host.fixture.parent.clone(),prefix.root).unwrap();
    let valid_raw=block.encode_with_capacity(&capacity).unwrap();
    // The invalid wrapper retains genuinely signed inner admission bytes; only
    // its public witness changes. No private preparation grant is made for it.
    let parsed=crate::admission_public_v3::Carrier::decode(&block.body.operations[0]).unwrap();
    // A foreign complete public witness is structurally canonical. Byte[0] is
    // not a witness and would only fail the constructor before native submit.
    let donor=genuine_material_at(&host,2,&host.fixture.parent,prefix.parent.t0);
    let donor_carrier=crate::admission_public_v3::Carrier::decode(&donor.outer).unwrap();
    let donor_witness=donor_carrier.witness().to_vec();
    assert_ne!(donor_witness.as_slice(),parsed.witness());
    crate::attestation_witness::AttestationWitness::decode(&donor_witness).unwrap();
    let substituted=crate::admission_public_v3::Carrier::new(15,
        parsed.signed().to_vec(),donor_witness).unwrap().encode().unwrap();
    assert_eq!(crate::admission_public_v3::Carrier::decode(&substituted).unwrap().signed(),parsed.signed());
    let invalid=signed_invalid_variant(&host,&prefix,&valid_raw,vec![substituted],&[]);
    // The helper actually verifies re-signed Node work and old-parent quorum.
    // This does not assert that the claimed invalid execution root is correct.
    let path=directory().join("scope-canonical.sqlite");
    let mut chain=CanonicalStore::open_trusted_genesis(&path,&host.fixture.parent,
        &host.fixture.state,host.fixture.root,super::super::super::test_value_x509::T_REF,
        [255;32]).unwrap();
    let persisted=database_rows(&path);let records=prefix.state.records().unwrap();
    {let _only_history=prefix.replay().unwrap();
        assert!(matches!(chain.commit(&invalid),
            Err(crate::finality_v2::StoreError::Verification(
                IngressError::Execution(crate::execution::ExecutionError::Codec(Error::WrongAnchor))))));
        let (tip,state)=chain.load().unwrap();
        assert_eq!(tip.height,0);assert_eq!(tip.root,prefix.root);
        assert!(state.records().unwrap()==records,"invalid exact-X submission changed state records");
    }
    assert!(database_rows(&path)==persisted,"invalid exact-X submission changed canonical SQL tables");
    assert!(ACTIVE.with(|slot|slot.borrow().is_none()));
    // Positive commit uses a newly independently verified complete row prefix,
    // not the failing body's scope or a caller supplied eligibility flag.
    let mut rows=Vec::new();let installed=install(&host,&mut chain,&mut rows,valid_raw.clone());
    assert_eq!(installed.root,execution.root);assert_eq!(installed.parent.height,1);
    assert!(installed.state.records().unwrap()==execution.state.records().unwrap());
    let (kind,id)=crate::operation_index_v2::operation_id(1,&block.body.operations[0]).unwrap();
    assert_eq!(kind,15);
    drop(chain);
    VerifiedPrefix::with_reverified_store(&host,&path,&rows,|reopened| {
        let (tip,state)=reopened.load().unwrap();assert_eq!(tip.height,1);assert_eq!(tip.root,execution.root);
        assert!(state.records().unwrap()==execution.state.records().unwrap());
        let indexed=reopened.verified_operation_records(id).unwrap();
        assert_eq!(indexed.len(),1);assert_eq!(indexed[0].kind,15);assert_eq!(indexed[0].height,1);
        assert_eq!(reopened.certified_envelope_bytes(1,tip.block).unwrap(),Some(valid_raw.clone()));
    }).unwrap();
    // Exact-X WrongAnchor is context-bound canonical atomic rejection. It is
    // NOT later witness typed validation or Hardware/Recovery success credit.
}
