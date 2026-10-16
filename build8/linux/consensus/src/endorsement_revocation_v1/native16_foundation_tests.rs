//! Registered private child of native16_test_host; four V7 controls passed separately.
//! The changed Material helper remains uncompiled. Not a 16-member
//! canonical fleet, full hosted replay or activation claim.
use super::*;
use super::super::{label, zero, test_value_ek, test_value_x509, software_tpm, TestTpm};
use mutiny_crypto_v2::{HybridKey, Role};

struct Empty;
impl crate::op_envelope_v1::PendingReferences for Empty {}
impl crate::assembler_v2::PendingSource for Empty {
    fn pending_items_at(&self,_:&FinalizedAnchor,_:&State)
        -> std::result::Result<Vec<crate::submission_v1::Submission>,String> {Ok(vec![])}
}
// Applicant-generated software material is not an eligibility capability. This
// helper's output must still pass ModelHost independent Binding/witness native
// verification, complete canonical-entry checks and normal economic/lifecycle
// verification. All TEST keys stay in memory; no production class relabeling.
pub(super) fn genuine_join(host:&ModelHost,ordinal:u8) -> (Join,Vec<u8>) {
    genuine_join_at(host,ordinal,&host.fixture.parent,test_value_x509::T_REF)
}
pub(super) fn genuine_join_at(host:&ModelHost,ordinal:u8,parent:&FinalizedAnchor,reference:u64) -> (Join,Vec<u8>) {
    let material=genuine_material_at(host,ordinal,parent,reference);
    (material.join,material.outer)
}
// Only owned synthetic test material. No Debug/Clone/export/custody output.
pub(super) struct Material {
    pub(super) join:Join,
    pub(super) outer:Vec<u8>,
    pub(super) tpm:TestTpm,
    pub(super) node:HybridKey,
    pub(super) continuity:HybridKey,
}
pub(super) fn genuine_material_at(host:&ModelHost,ordinal:u8,parent:&FinalizedAnchor,reference:u64) -> Material {
    assert!((1..=15).contains(&ordinal));
    material_with_identity(host,&format!("a2-private-native16-public-member-{ordinal}"),
        &format!("a2-private-native16-context-{ordinal}"),&[0x61,ordinal],parent,reference)
}
pub(super) fn maximum_material_at(host:&ModelHost,ordinal:u16,parent:&FinalizedAnchor,reference:u64)->Material {
    assert!(host.maximum_profile && (1..=1023).contains(&ordinal));
    let serial=[0x62,(ordinal>>8) as u8,ordinal as u8];
    material_with_identity(host,&format!("a2-private-maximum-public-member-{ordinal}"),
        &format!("a2-private-maximum-context-{ordinal}"),&serial,parent,reference)
}
fn material_with_identity(host:&ModelHost,identity:&str,nonce_label:&str,serial:&[u8],parent:&FinalizedAnchor,reference:u64)->Material {
    let pki=host.capacity_join_pki.as_ref().unwrap_or(&host.fixture.pki);
    let root=pki.root_hash();
    let tpm=TestTpm::with_identity(identity)
        .strip(software_tpm::Strip::ConsistentProvenance(root));
    let chain=pki.chain(&tpm.simulator_ek(),serial);
    let area=test_value_ek::public_area(
        &test_value_ek::template(crate::endorsement_identity::ECC_TAG,test_value_ek::TEST_ATTRIBUTES),
        &tpm.simulator_ek());
    let witness=crate::attestation_witness::AttestationWitness {
        reference_time:reference,
        endorsements:vec![crate::attestation_witness::EndorsementEvidence {
            ek_public_area:area,certificates:chain.clone(),
            crls:[false,true].into_iter().map(|by_root| {
                let mut tbs=pki.crl_tbs(by_root,&[]);
                tbs.next_update=Some(test_value_x509::time(reference+30));
                pki.sign_crl(&tbs,by_root)
            }).collect(),
        }],
        activation:vec![test_value_ek::activation(0,
            tpm.profile().provenance.as_ref().unwrap().ak_name,
            "PUBLIC PRIVATE MODELED HOST; no actual activation proof")],
    };
    let mut provenance=tpm.profile().provenance.as_ref().unwrap().clone();
    provenance.endorsement.as_mut().unwrap().witness_sha256=witness.commitment().unwrap();
    provenance.ek_public_sha256=crate::x509_syntax::certified_public_key_sha256(&chain[0]).unwrap();
    let tpm=tpm.with_provenance(provenance);
    let node=HybridKey::generate(Role::Node).unwrap();
    let continuity=HybridKey::generate(Role::Continuity).unwrap();
    let owner=HybridKey::wallet_restore(&format!("{}art","abandon ".repeat(23)),Role::WalletOwner).unwrap();
    let descriptor=node.public().descriptor(1).unwrap();
    let mut join=Join {parent:parent.clone(),
        nonce:label(nonce_label),
        binding:crate::node_admission_v2::Binding {node_signer:None,
            node_descriptor:descriptor.clone(),possession:zero(),
            admission:crate::admission_v2::Admission {
                genesis:host.fixture.parent.genesis,fingerprint:host.fixture.parent.fingerprint,
                node:crate::node_admission_v2::node_id(host.fixture.parent.genesis,&descriptor).unwrap(),
                hardware_generation:1,key_generation:1,
                continuity_descriptor:continuity.public().descriptor(1).unwrap(),
                profile:tpm.profile().encode().unwrap(),endorsement_root:root,
                owner:owner.public().address_id(1).unwrap(),supervised_nonce:[1;32],
                quote:vec![],possession:zero(),authorization:zero(),
            },
        }};
    join.binding.admission.supervised_nonce=join.admission_nonce().unwrap();
    join.binding.admission.prove_continuity(&continuity).unwrap();
    join.binding.admission.quote=tpm.quote(join.binding.admission.challenge().unwrap());
    join.binding.admission.authorize(&owner,1).unwrap();
    join.binding.sign(&node).unwrap();
    let outer=crate::admission_public_v3::Carrier::new(15,join.encode().unwrap(),witness.encode().unwrap())
        .unwrap().encode().unwrap();
    Material {join,outer,tpm,node,continuity}
}

#[test]
fn genuine_join_still_refuses_without_exact_private_canonical_entries() {
    let host=ModelHost::new();let (join,_)=genuine_join(&host,1);
    assert!(matches!(join.verify(&host.fixture.state,&host.fixture.parent,host.fixture.root),
        Err(Error::AdmissionAuthorityEnded)));
    let context=crate::parent_context_v2::ParentContext::canonical(
        &host.fixture.state,&host.fixture.parent,host.fixture.root).unwrap();
    assert_eq!(permits_join(&join,context),Ok(false));
}

#[test]
fn genuine_join_private_unsigned_and_signed_native_execution_bind_whole_body() {
    let mut host=ModelHost::new();let (join,outer)=genuine_join(&host,1);
    let mut id=[0;16];mutiny_crypto_v2::fill_os_random(&mut id).unwrap();
    let directory=std::env::temp_dir().join(format!("build8-public-private-native16-{}",hex::encode(id)));
    assert!(crate::submission_pool_v1::private_directory(&directory).unwrap());
    let chain=CanonicalStore::open_trusted_genesis(&directory.join("canonical.sqlite"),
        &host.fixture.parent,&host.fixture.state,host.fixture.root,test_value_x509::T_REF,[255;32]).unwrap();
    let binding=host.fixture.state.licenses_v2.assignments().next().unwrap().enrollment.binding.clone();
    let timestamp=test_value_x509::T_REF+1;
    let positive=chain.prepare_pending(crate::canonical_store_v2::Preparation {
        expected_parent:&host.fixture.parent,pool:&Empty,license:binding.license,
        worker:binding.worker_id,timestamp,ticket:1,operations:&[],
    }).unwrap();
    let mut body=positive.body;body.operations=vec![outer];
    let mut candidate=positive.candidate;candidate.state_root=[0;32];
    candidate.body_root=chain.body_capacity(&host.fixture.parent).unwrap().root(&body).unwrap();
    let prepared=host.prepare_exact(&chain,&candidate,1,&body).unwrap();
    assert_ne!(prepared.computed_root,host.fixture.root);
    let epoch=crate::pow::mining_epoch(timestamp,test_value_x509::T_REF).unwrap();
    let (license,_)=host.fixture.state.licenses_v2.active(binding.license,binding.worker_id,epoch).unwrap();
    let mut candidate=candidate;candidate.state_root=prepared.computed_root;
    let mut authority=Authority {work:crate::pow::WorkAuthority {
        candidate:candidate.clone(),assignment_sequence:license.assignment_sequence,ticket_sequence:1,
        coordinator:crate::work_authority_v2::node_identity(&host.fixture.node_key.public().descriptor(1).unwrap()).unwrap(),
        nonce_start:0,nonce_end:100,epoch,
    },node_descriptor:host.fixture.node_key.public().descriptor(1).unwrap(),signature:zero()};
    authority.sign(&host.fixture.node_key).unwrap();
    let header=WorkHeader {candidate,authority:authority.id().unwrap(),nonce:1};
    let execution=host.execute_exact(&prepared,&chain,&header,&authority,&body).unwrap();
    assert!(execution.state.membership_v2.get(join.binding.admission.node).is_some());
    assert_eq!(execution.state.continuity.as_ref().unwrap().members.len(),2);
    assert_eq!(execution.root,prepared.computed_root);
    let mut changed=body.clone();changed.fees+=1;
    assert!(matches!(host.execute_exact(&prepared,&chain,&header,&authority,&changed),
        Err(crate::execution::ExecutionError::Codec(Error::WrongAnchor))));
    assert_eq!(chain.load().unwrap().0.height,0);
    assert_eq!(chain.load().unwrap().1.records().unwrap(),host.fixture.state.records().unwrap());
    // No certificate/finality/publish/reopen is claimed by this two-member pure
    // preparation/execution foundation. The full15-step hosted chain is next.
}
