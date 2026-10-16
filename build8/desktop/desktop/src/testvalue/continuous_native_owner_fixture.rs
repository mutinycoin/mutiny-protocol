//! Explicit NONSHIPPING native-owner TEST bootstrap only. All DER/profile/wallet
//! fixture seeds are public software values; no physical TPM or production identity.
//! Fresh matching Node/Continuity keys are generated only after immutable Inputs.
#![cfg(all(windows,feature="native-owner-test"))]
#[path="../../../consensus/tests/support/test_value_ek.rs"] mod ek;
#[path="../../../consensus/tests/support/test_value_x509.rs"] mod x509;
#[path="../../../consensus/tests/support/software_tpm.rs"] mod software_tpm;
#[path="../../../consensus/tests/support/license_v2.rs"] mod licenses;
use mutiny_consensus_v8::x509_syntax; // Required crate alias of the shared TEST DER source.
use mutiny_consensus_v8::{
    Hash, NETWORK_ID, activation_attestation_v1 as activation,
    admission_v2::{Admission,Expected,Policy}, anchors::FinalizedAnchor,
    attestation_witness::{AttestationWitness,EndorsementEvidence,WitnessContext},
    canonical_store_v2::{CanonicalStore,Preparation},continuity_key_rotate_v2::KeyRotate,
    genesis_v2::{self,EndorsementRoot,EndorsementRootSet,GenesisClass,Parameters},
    endorsement_identity::{ECC_TAG,RSA_TAG,IdentityClasses},execution::State,
    licenses::LicenseRecord,membership_v2,license_book_v2,mempool_v2::Mempool,
    node_admission_v2::{Binding,node_id},pcr_profiles::{AcceptedPcrProfiles,PcrProfile,SHA256_BANK,
        INTERPRETATION_QUOTE_COMPOSITE,UPDATE_FROZEN_AT_GENESIS},pow::{WorkAuthority,WorkHeader},
    protocol_manifest::RuleManifest,recovery::{Anchor,ContinuityState,Member},
    counter_store::MonotonicCounter,counter_voter_v2::CounterSigningBackend,
    work_authority_v2::Authority,bft::Step,
};
use mutiny_crypto_v2::{Domain,HybridKey,HybridSignature,PublicKey,Role,
    enrollment::{Binding as WorkerBinding,owner_descriptor_id}};
use std::{cell::RefCell,rc::Rc,sync::Arc,time::{Duration,Instant}};
fn hash(label:&str)->Hash {mutiny_consensus_v8::domain_hash(b"PUBLIC-SELECTED-TEST-ACTIVATION-GENESIS-V1",label.as_bytes())}
fn zero()->HybridSignature {HybridSignature{ed448:[0;114],fndsa:[0;1280]}}
pub(crate) struct Fixture {pub state:State,pub parent:FinalizedAnchor,pub node:Hash,pub node_key:HybridKey,
    pub continuity:HybridKey,pub owner:HybridKey,pub tpm:software_tpm::TestTpm,pub license:Hash,pub worker:Hash,
    pub inputs:genesis_v2::Inputs,pub enrollment:genesis_v2::Enrollment,pub public_evidence:Vec<u8>}

pub(crate) fn fresh()->Fixture {
    let pki=x509::X509Pki::new("PUBLIC TEST selected activation Genesis genuine DER");
    let der=pki.root_hash();
    let mut root_label=mutiny_consensus_v8::test_value_root_alias_v1::LABEL_PREFIX.to_vec();root_label.extend(der);
    let root=genesis_v2::test_value_root(&root_label);assert_ne!(root,der);
    let tpm=software_tpm::TestTpm::stripped(software_tpm::Strip::ConsistentProvenance(root));
    let keys=[tpm.simulator_ek(),x509::public_rsa_fixture(mutiny_consensus_v8::ek_chain::SignatureAlgorithm::RsaPkcs1Sha256).public()];
    let witness=AttestationWitness {reference_time:ek::T_REF,
        endorsements:keys.iter().enumerate().map(|(i,key)|EndorsementEvidence {
            ek_public_area:ek::public_area(&ek::template(key.class().0,ek::TEST_ATTRIBUTES),key),
            certificates:pki.chain(key,&[0x61+i as u8]),crls:pki.crls(&[],&[]),
        }).collect(),
        activation:(0..2u8).map(|i|ek::activation(i,
            mutiny_consensus_v8::provenance::ak_name(&tpm.profile().ak_public).unwrap(),
            "PUBLIC TEST no private activation proof")).collect(),
    };
    let mut statement=tpm.profile().provenance.clone().unwrap();
    statement.endorsement.as_mut().unwrap().identities=keys.iter().map(|key|(root,key.identity().unwrap())).collect();
    statement.endorsement.as_mut().unwrap().witness_sha256=witness.commitment().unwrap();
    statement.ek_public_sha256=x509_syntax::certified_public_key_sha256(&witness.endorsements[0].certificates[0]).unwrap();
    let tpm=tpm.with_provenance(statement);
    let anchor=pki.anchor(mutiny_consensus_v8::ek_chain::RevocationMode::CrlRequired,&[ek::ECC_CLASS,ek::RSA_CLASS],
        &[mutiny_consensus_v8::ek_chain::SignatureAlgorithm::EcdsaP256Sha256,mutiny_consensus_v8::ek_chain::SignatureAlgorithm::EcdsaP384Sha384]);
    let mut parameters=Parameters {class:GenesisClass::TestValue,initial_target:[255;32],
        rules:RuleManifest {commitments:vec![
            (activation::RULE_ENTRY.to_vec(),activation::rule_commitment()),
            (mutiny_consensus_v8::endorsement_revocation_v1::RULE_ENTRY.to_vec(),mutiny_consensus_v8::endorsement_revocation_v1::rule_commitment()),
            (mutiny_consensus_v8::test_value_root_alias_v1::RULE_ENTRY.to_vec(),mutiny_consensus_v8::test_value_root_alias_v1::rule_commitment()),
        ]},
        roots:EndorsementRootSet {roots:[(root,EndorsementRoot {constraints:anchor.constraints,test_value_label:Some(root_label)})].into()},
        pcr_profiles:AcceptedPcrProfiles::new(UPDATE_FROZEN_AT_GENESIS,vec![PcrProfile {
            bank:SHA256_BANK,selection:tpm.profile().pcr_bitmap,digest:tpm.profile().pcr_digest,
            interpretation:INTERPRETATION_QUOTE_COMPOSITE,
        }]).unwrap(),
        identity_classes:IdentityClasses::new(vec![ek::class_of(ECC_TAG,ek::TEST_ATTRIBUTES),ek::class_of(RSA_TAG,ek::TEST_ATTRIBUTES)]).unwrap(),
    };
    parameters.rules.commitments.extend(genesis_v2::binding_entries(parameters.class,&parameters.roots,&parameters.pcr_profiles,&parameters.identity_classes).unwrap());
    parameters.rules.commitments.sort();
    let policy=parameters.witness_policy().unwrap();
    mutiny_consensus_v8::attestation_witness::verify_witness_with_policy(tpm.profile().provenance.as_ref().unwrap(),Some(&witness.encode().unwrap()),
        &policy,ek::T_REF,&x509_syntax::X509Syntax).unwrap();
    let owner=HybridKey::wallet_restore(&("abandon ".repeat(23)+"art"),Role::WalletOwner).unwrap();
    let treasury=HybridKey::wallet_restore(&("zoo ".repeat(23)+"vote"),Role::WalletOwner).unwrap();
    let recovery=HybridKey::wallet_restore("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",Role::WalletRecovery).unwrap();
    let inputs=genesis_v2::Inputs {timestamp:ek::T_REF,nonce:hash("selected TEST Genesis nonce"),parameters,
        admission_owner:owner.public().descriptor(1).unwrap(),
        member:genesis_v2::MemberInput {endorsement_root:root,profile:tpm.profile().encode().unwrap()},
        recovery:recovery.public().descriptor(1).unwrap(),
        treasury:mutiny_consensus_v8::treasury_v1::Treasury::new(mutiny_consensus_v8::treasury_v1::Class::TestValue,treasury.public().descriptor(1).unwrap()).unwrap(),
        purchase:hash("selected TEST Genesis purchase"),
    };
    inputs.validate().unwrap();let identity=inputs.identity().unwrap();let fingerprint=inputs.parameters.fingerprint().unwrap();
    // Node and Continuity keys are created only after pre-identity Inputs are final.
    let node_key=HybridKey::generate(Role::Node).unwrap();let continuity=HybridKey::generate(Role::Continuity).unwrap();
    let descriptor=node_key.public().descriptor(1).unwrap();let node=node_id(identity,&descriptor).unwrap();
    let nonce=hash("selected supervised admission nonce");
    let mut binding=Binding {node_signer:None,node_descriptor:descriptor.clone(),possession:zero(),
        admission:Admission {genesis:identity,fingerprint,node,hardware_generation:1,key_generation:1,
            continuity_descriptor:continuity.public().descriptor(1).unwrap(),profile:inputs.member.profile.clone(),endorsement_root:root,
            owner:owner.public().address_id(1).unwrap(),supervised_nonce:nonce,quote:vec![],possession:zero(),authorization:zero()},
    };
    binding.admission.prove_continuity(&continuity).unwrap();binding.admission.quote=tpm.quote(binding.admission.challenge().unwrap());
    binding.admission.authorize(&owner,1).unwrap();binding.sign(&node_key).unwrap();
    let mut assignments=vec![];let mut supervised=vec![];
    for i in 0..12u64 {
        let mut worker=WorkerBinding {genesis:identity,fingerprint,license:mutiny_consensus_v8::blocks::genesis_license(identity,i).unwrap(),
            owner_descriptor:owner_descriptor_id(owner.public(),1).unwrap(),owner_generation:1,
            worker_public:licenses::worker(i as u8+1),worker_id:[0;32],
            coordinator:mutiny_consensus_v8::work_authority_v2::node_identity(&descriptor).unwrap(),configuration_generation:1,
            device_mac:[2,0,0,0,0,i as u8+1],assignment_generation:1,effective_epoch:0,valid_until_height:0};
        worker.worker_id=worker.derived_worker_id();assignments.push(licenses::sign(worker.clone(),&owner,&descriptor,i as u8+1));supervised.push(worker);
    }
    let enrollment=genesis_v2::Enrollment {supervised_nonce:nonce,member_binding:binding,assignments,supervised:supervised.clone()};
    let bundle=mutiny_consensus_v8::admission_evidence_v1::PublicWitnessBundle {genesis:identity,fingerprint,entries:vec![(node,witness.encode().unwrap())]};
    assert!(genesis_v2::construct(&inputs,&enrollment).is_err(),"native A2 selection requires available public witness");
    let constructed=genesis_v2::construct_with_public_dependencies(&inputs,&enrollment,&bundle.encode().unwrap()).unwrap();
    let approved=genesis_v2::Approved {manifest:inputs.parameters.rules.clone(),class:inputs.parameters.class,initial_target:inputs.parameters.initial_target};
    let claimed=genesis_v2::Claimed {genesis_id:identity,records:constructed.records().unwrap(),state_root:constructed.root,
        block:constructed.block.clone(),block_hash:constructed.block_hash};
    let verified=mutiny_consensus_v8::admission_evidence_v1::verify_genesis_public_evidence(&inputs.encode().unwrap(),&enrollment.encode().unwrap(),
        &approved,&claimed,&bundle.encode().unwrap()).unwrap();
    assert_eq!(verified.root,constructed.root);assert_eq!(constructed.identity,identity);
    let parent=FinalizedAnchor {network:NETWORK_ID,genesis:identity,fingerprint,height:0,block:constructed.block_hash};
    assert_eq!(constructed.state.admission_class().unwrap(),mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest);
    Fixture {state:constructed.state,parent,node,node_key,continuity,owner,tpm,license:supervised[0].license,worker:supervised[0].worker_id,inputs,enrollment,public_evidence:bundle.encode().unwrap()}
}

