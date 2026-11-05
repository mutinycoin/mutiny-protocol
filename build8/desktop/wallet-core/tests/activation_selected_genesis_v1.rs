//! Genuine selected TEST-VALUE Genesis + native scope collector controls.
//! Real public software DER/quote/owner/Worker/work/vote signatures; no physical
//! TPM or real tool/simulator claim. The historical private initial model remains
//! preserved as a separate target. No Scope/Admission/Material/Permit factory.
//! UNCOMPILED / UNRUN; only explicit reviewed host controls may run this target.
#[path="../../node/src/activation_test_adapter_v1/mod.rs"]
mod activation_test_adapter_v1;
#[path="../../node/src/credential_activation_workflow.rs"]
mod credential_activation_workflow;
#[path="../../consensus/tests/support/test_value_ek.rs"]
mod ek;
#[path="../../consensus/tests/support/test_value_x509.rs"]
mod x509;
#[path="../../consensus/tests/support/software_tpm.rs"]
mod software_tpm;
#[path="../../consensus/tests/support/license_v2.rs"]
mod licenses;

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
struct Fixture {state:State,parent:FinalizedAnchor,node:Hash,node_key:HybridKey,
    continuity:HybridKey,owner:HybridKey,tpm:software_tpm::TestTpm,license:Hash,worker:Hash}

fn selected_genesis()->Fixture {
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
    Fixture {state:constructed.state,parent,node,node_key,continuity,owner,tpm,license:supervised[0].license,worker:supervised[0].worker_id}
}

#[derive(Default)]struct Calls{counter:u64,signatures:u64}
struct Backend{key:HybridKey,node:Hash,calls:Rc<RefCell<Calls>>}
impl MonotonicCounter for Backend {
    fn read(&mut self)->Result<u64,String>{Ok(self.calls.borrow().counter)}
    fn increment(&mut self)->Result<(),String>{let mut value=self.calls.borrow_mut();value.counter=value.counter.checked_add(1).ok_or("counter overflow")?;Ok(())}
}
impl CounterSigningBackend for Backend {
    fn public_key(&self)->&PublicKey{self.key.public()}
    fn sign_vote(&mut self,message:&[u8])->Result<HybridSignature,String>{self.calls.borrow_mut().signatures+=1;self.key.sign(Domain::ContinuityVote,message).map_err(|_|"software TEST signing".into())}
    fn sign_reserved_vote(&mut self,message:&[u8],permit:&activation::PrivateSignPermit)->Result<HybridSignature,String>{
        permit.check_at_custody_entry(self.node,Some(activation::rule_commitment()),message).map_err(|_|"native permit custody refusal")?;self.sign_vote(message)
    }
}
struct Elapsed(Instant);
impl activation::Elapsed for Elapsed {fn elapsed(&self)->Result<Duration,activation::Failure>{Ok(self.0.elapsed())}}

#[test]
fn selected_genesis_native_scope_cancel_context_and_all_classes() {
    // Mandatory reviewed LOCAL input; missing input fails selected control.
    // There is no protocol expiry or default lifetime here.
    let millis:u64=std::env::var("BUILD8_ACTIVATION_TEST_LOCAL_LIMIT_MS").expect("explicit local test limit required").parse().unwrap();
    assert!(millis>0);let lifetime=Duration::from_millis(millis);
    let f=selected_genesis();let mut nonce=[0;16];mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let base=std::env::temp_dir().join(format!("PUBLIC-selected-genesis-native-activation-{}",hex::encode(nonce)));
    assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
    let root=f.state.root().unwrap();let chain_path=base.join("canonical.sqlite");
    let open_chain=||CanonicalStore::open_trusted_genesis(&chain_path,&f.parent,&f.state,root,ek::T_REF,[255;32]).unwrap();
    let chain=open_chain();let public_chain=open_chain();
    chain.verified_activation_parent(&f.parent).unwrap();
    let pool=Mempool::open(&base.join("mempool.sqlite"),f.parent.genesis,f.parent.fingerprint,1024*1024).unwrap();
    let mut runtime=mutinyd_v8::hybrid_runtime_v2::HybridRuntime::from_pinned_chain_with_clock(chain,pool,||ek::T_REF+1).unwrap();
    let replacement=HybridKey::generate(Role::Continuity).unwrap();
    let mut rotation=KeyRotate{parent:f.parent.clone(),nonce:hash("actual native key rotation"),sequence:1,old_key_generation:1,
        binding:f.state.membership_v2.get(f.node).unwrap().binding().clone()};
    rotation.binding.admission.key_generation=2;
    rotation.binding.admission.continuity_descriptor=replacement.public().descriptor(2).unwrap();
    rotation.binding.admission.supervised_nonce=rotation.admission_nonce().unwrap();
    rotation.binding.admission.prove_continuity(&replacement).unwrap();
    rotation.binding.admission.quote=f.tpm.quote(rotation.binding.admission.challenge().unwrap());
    rotation.binding.admission.authorize(&f.owner,1).unwrap();rotation.binding.sign(&f.node_key).unwrap();
    rotation.verify(&f.state,&f.parent,root).unwrap();let raw=rotation.encode().unwrap();
    let timestamp=ek::T_REF+1;
    let prepared=runtime.prepare(mutinyd_v8::hybrid_runtime_v2::WorkRequest{expected_parent:&f.parent,
        license:f.license,worker:f.worker,timestamp,ticket:1,operations:&[raw]}).unwrap();
    let mut authority=Authority{work:WorkAuthority{candidate:prepared.candidate.clone(),assignment_sequence:1,ticket_sequence:1,
        coordinator:mutiny_consensus_v8::work_authority_v2::node_identity(&f.node_key.public().descriptor(1).unwrap()).unwrap(),
        nonce_start:0,nonce_end:100,epoch:0},node_descriptor:f.node_key.public().descriptor(1).unwrap(),signature:zero()};
    authority.sign(&f.node_key).unwrap();let header=WorkHeader{candidate:prepared.candidate,authority:authority.id().unwrap(),nonce:1};
    let block=header.block_hash();let record=mutinyd_v8::candidate_journal_v3::Record{header,authority,body:prepared.body};
    let mut journal=mutinyd_v8::candidate_journal_v3::Journal::open(&runtime,&base.join("candidate.sqlite"),1024*1024,true).unwrap();
    journal.preserve(&runtime,&record).unwrap();
    let calls=Rc::new(RefCell::new(Calls{counter:100,signatures:0}));
    let backend=Backend{key:f.continuity,node:f.node,calls:calls.clone()};
    let mut voter=mutinyd_v8::hybrid_voter_v2::VotingRuntime::open(runtime,&base.join("custody.sqlite"),f.node,Some(100),backend).unwrap();
    voter.set_vote_clock(mutiny_consensus_v8::vote_clock_v1::ControlledClock::at(timestamp));
    assert_eq!(voter.restore_a2_candidate(&journal,None).unwrap(),Some(block));
    voter.configure_activation(lifetime,Arc::new(Elapsed(Instant::now()))).unwrap();
    let request=voter.activation_request(Step::Prevote,Some(block),None).unwrap().unwrap();
    assert_eq!(request.scope().admissions().len(),1);assert_eq!(request.scope().admissions()[0].endorsements().len(),2);
    let mut provider=activation_test_adapter_v1::provider::OwnContext::test_only(&public_chain,f.node).unwrap();
    let receipt=activation_test_adapter_v1::native_controls::run_with_prepared(&mut voter,&mut provider,Step::Prevote,Some(block),None).unwrap();
    assert_eq!(receipt.scope,request.scope().commitment());assert_eq!(receipt.class_count,2);
    assert!(receipt.partial_refused&&receipt.mismatched_context_refused&&receipt.native_missing_after_cancel&&receipt.all_classes_completed);
    assert_eq!(calls.borrow().signatures,0);assert_eq!(calls.borrow().counter,100);
    let vote=voter.sign(Step::Prevote,Some(block),None).unwrap();
    assert_eq!(calls.borrow().signatures,1);
    let authority=public_chain.current_authority(&f.parent).unwrap();
    vote.verify(&authority.parent,authority.roots(),&authority.voters).unwrap();
    assert_eq!(public_chain.verified_activation_parent(&f.parent).unwrap().0.parent,f.parent);
    let evidence=serde_json::json!({
        "scope":"Genuine selected TEST-VALUE Inputs/Enrollment/public DER Genesis; collector uses a private secret-return model, not simulator interoperability",
        "source":"activation_selected_genesis_v1",
        "parent_height":f.parent.height,"parent_block":hex::encode(f.parent.block),
        "initial_state_root":hex::encode(root),"executed_block":hex::encode(block),
        "scope_commitment":hex::encode(receipt.scope),"endorsement_classes":receipt.class_count,
        "partial_refused":receipt.partial_refused,"mismatched_context_refused":receipt.mismatched_context_refused,
        "native_missing_after_cancel":receipt.native_missing_after_cancel,"all_classes_completed":receipt.all_classes_completed,
        "signatures_before_complete":0,"actual_signatures_after_complete":calls.borrow().signatures,
        "local_elapsed_limit_ms":millis,"protocol_expiry_default":serde_json::Value::Null,
        "canonical_parent_advanced":false,"genuine_genesis_input_validation":true,"physical_genesis_qualification":"NOT CLOSED",
        "simulator_interoperability":"UNRUN","physical_qualification":"NOT CLOSED"
    });
    let mut output=std::fs::OpenOptions::new().create_new(true).write(true).open(base.join("NATIVE-COLLECTOR-SELECTED-GENESIS.json")).unwrap();
    use std::io::Write;
    output.write_all(&serde_json::to_vec_pretty(&evidence).unwrap()).unwrap();output.write_all(b"\n").unwrap();output.sync_all().unwrap();
    println!("PUBLIC TEST selected Genesis/native collector evidence retained {}. Real simulator/physical qualification remains UNRUN.",base.display());
}

// This companion control authenticates the same genuine selected Genesis
// witness through the older local Candidate API's new Parameters-bound route.
// Collector below is explicitly a private secret-return model, not TPM crypto.
fn candidate_inputs(f:&Fixture)->(Parameters,Binding,Policy,Expected,Vec<u8>,credential_activation_workflow::Anchor) {
    let parameters=Parameters::decode(f.state.protocol_records.get(&genesis_v2::parameters_key()).unwrap()).unwrap();
    let binding=f.state.membership_v2.get(f.node).unwrap().binding().clone();
    let policy=f.state.current_admission_policy_v2(f.parent.genesis,f.parent.fingerprint).unwrap();
    let expected=Expected{node:f.node,hardware_generation:binding.admission.hardware_generation,
        key_generation:binding.admission.key_generation,supervised_nonce:binding.admission.supervised_nonce};
    let (time,witness)=f.state.endorsement_dependencies_v1.activation_witness(&f.state,&binding).unwrap().unwrap();
    assert_eq!(time,ek::T_REF);
    let anchor=credential_activation_workflow::Anchor{network:NETWORK_ID,
        admission_class:parameters.class.admission_class(),genesis:f.parent.genesis,fingerprint:f.parent.fingerprint,
        parent:[0;32],purpose:credential_activation_workflow::Purpose::Genesis,
        authorized_transition:f.parent.block,identity_classes:parameters.identity_classes.commitment(),
        verifier_policy:mutiny_consensus_v8::test_value_root_alias_v1::rule_commitment()};
    (parameters,binding,policy,expected,witness,anchor)
}
struct LocalContext {anchor:credential_activation_workflow::Anchor}
impl credential_activation_workflow::CurrentContext for LocalContext {
    fn current_for(&mut self,scope:&credential_activation_workflow::Scope)
        ->Result<credential_activation_workflow::Anchor,credential_activation_workflow::Failure>{
        if scope.anchor!=self.anchor{return Err(credential_activation_workflow::Failure::Context);}Ok(self.anchor.clone())
    }
}
#[derive(Default)]struct LocalSecretReturnModel {responses:Vec<credential_activation_workflow::RecoveryResponse>,calls:usize}
impl credential_activation_workflow::MakeCredential for LocalSecretReturnModel {
    fn make_credential(&mut self,_:&[u8],_:&[u8;34],secret:&[u8;32])
        ->Result<credential_activation_workflow::EncryptedCredential,credential_activation_workflow::Failure>{
        let index=self.calls;self.calls+=1;
        self.responses.push(credential_activation_workflow::RecoveryResponse::new(index as u8,zeroize::Zeroizing::new(*secret)));
        credential_activation_workflow::EncryptedCredential::new(vec![index as u8+1;32],vec![index as u8+11;64])
    }
}
#[test]
fn selected_genesis_candidate_parameters_witness_and_model_makecredential() {
    use credential_activation_workflow::{Candidate,Failure,Workflow};
    let f=selected_genesis();let (parameters,binding,policy,expected,witness,anchor)=candidate_inputs(&f);
    let derived=parameters.witness_policy().unwrap();let historical_context=derived.context(ek::T_REF);
    // Genuine valid selected material demonstrates the old API's safe refusal;
    // the historical function is not silently reinterpreted by global state.
    assert!(matches!(Candidate::validate(&binding,&policy,&expected,&f.state.wallets,anchor.clone(),&witness,
        &historical_context,&x509_syntax::X509Syntax),Err(Failure::PublicWitness)));
    let candidate=Candidate::validate_with_parameters(&binding,&policy,&expected,&f.state.wallets,anchor.clone(),
        &witness,&parameters,ek::T_REF,&x509_syntax::X509Syntax).unwrap();
    assert_eq!(candidate.scope().node,f.node);assert_eq!(candidate.scope().profile_commitment,f.tpm.profile().commitment().unwrap());
    let mut bad_witness=witness.clone();*bad_witness.last_mut().unwrap()^=1;
    assert!(matches!(Candidate::validate_with_parameters(&binding,&policy,&expected,&f.state.wallets,anchor.clone(),
        &bad_witness,&parameters,ek::T_REF,&x509_syntax::X509Syntax),Err(Failure::PublicWitness)));
    let mut wrong=parameters.clone();let (_,mut entry)=wrong.roots.roots.pop_first().unwrap();
    *entry.test_value_label.as_mut().unwrap().last_mut().unwrap()^=1;
    wrong.roots.roots.insert(genesis_v2::test_value_root(entry.test_value_label.as_ref().unwrap()),entry);
    wrong.rules.commitments.retain(|(name,_)|!genesis_v2::binding_entries(parameters.class,&parameters.roots,
        &parameters.pcr_profiles,&parameters.identity_classes).unwrap().iter().any(|(bound,_)|bound==name));
    wrong.rules.commitments.extend(genesis_v2::binding_entries(wrong.class,&wrong.roots,&wrong.pcr_profiles,&wrong.identity_classes).unwrap());
    wrong.rules.commitments.sort();wrong.encode().unwrap();assert_ne!(wrong.fingerprint().unwrap(),f.parent.fingerprint);
    assert!(matches!(Candidate::validate_with_parameters(&binding,&policy,&expected,&f.state.wallets,anchor.clone(),
        &witness,&wrong,ek::T_REF,&x509_syntax::X509Syntax),Err(Failure::Context)));
    let mut wrong_anchor=anchor.clone();wrong_anchor.genesis[0]^=1;
    assert!(matches!(Candidate::validate_with_parameters(&binding,&policy,&expected,&f.state.wallets,wrong_anchor,
        &witness,&parameters,ek::T_REF,&x509_syntax::X509Syntax),Err(Failure::Context)));
    let millis:u64=std::env::var("BUILD8_ACTIVATION_TEST_LOCAL_LIMIT_MS").expect("explicit local test limit required").parse().unwrap();assert!(millis>0);
    let mut workflow=Workflow::new(1,Duration::from_millis(millis)).unwrap();
    let mut context=LocalContext{anchor};let mut model=LocalSecretReturnModel::default();
    let exchange=workflow.begin(&candidate,&mut context,&mut model).unwrap();assert_eq!(exchange.challenges.len(),2);assert_eq!(model.calls,2);
    let observation=workflow.complete(exchange.session,&exchange.scope,std::mem::take(&mut model.responses),&mut context).unwrap();
    assert_eq!(observation.classes.len(),2);assert_eq!(workflow.pending_count(),0);
    assert!(matches!(workflow.complete(exchange.session,&exchange.scope,vec![],&mut context),Err(Failure::UnknownAttempt)));
}

// Separate explicit real MakeCredential control. No default tool/image pin or
// skip; selecting it without reviewed static deployment inputs fails. Uses the
// exact same valid Candidate, ECC+RSA public areas and AK name, but does not
// invoke a TPM/simulator or claim ActivateCredential/native permit completion.
#[cfg(target_os="linux")]
#[test]
fn selected_genesis_candidate_pinned_real_makecredential() {
    use credential_activation_workflow::{Candidate,Workflow};
    struct LocalToolMaker(activation_test_adapter_v1::linux_tools::SoftwareMakeCredential);
    impl credential_activation_workflow::MakeCredential for LocalToolMaker {
        fn make_credential(&mut self,ek:&[u8],name:&[u8;34],secret:&[u8;32])
            ->Result<credential_activation_workflow::EncryptedCredential,credential_activation_workflow::Failure>{
            use mutiny_consensus_v8::activation_attestation_v1::MakeCredential;
            let encrypted=self.0.make_credential(ek,name,secret).map_err(|_|credential_activation_workflow::Failure::Adapter)?;
            credential_activation_workflow::EncryptedCredential::new(encrypted.credential().to_vec(),encrypted.encrypted_seed().to_vec())
        }
    }
    let tool=std::path::PathBuf::from(std::env::var("BUILD8_ACTIVATION_STATIC_TOOL").expect("explicit reviewed static tool required"));
    let pin:Hash=hex::decode(std::env::var("BUILD8_ACTIVATION_STATIC_TOOL_SHA256").expect("explicit reviewed tool SHA required")).unwrap().try_into().unwrap();
    let millis:u64=std::env::var("BUILD8_ACTIVATION_TEST_LOCAL_LIMIT_MS").expect("explicit local test limit required").parse().unwrap();assert!(millis>0);
    let f=selected_genesis();let (parameters,binding,policy,expected,witness,anchor)=candidate_inputs(&f);
    let candidate=Candidate::validate_with_parameters(&binding,&policy,&expected,&f.state.wallets,anchor.clone(),
        &witness,&parameters,ek::T_REF,&x509_syntax::X509Syntax).unwrap();
    let mut maker=LocalToolMaker(activation_test_adapter_v1::linux_tools::SoftwareMakeCredential::test_only(
        activation_test_adapter_v1::linux_tools::ToolPin::open_static_test(&tool,pin).unwrap()));
    let mut workflow=Workflow::new(1,Duration::from_millis(millis)).unwrap();let mut context=LocalContext{anchor};
    let first=workflow.begin(&candidate,&mut context,&mut maker).unwrap();assert_eq!(first.challenges.len(),2);
    let public_first=first.challenges.iter().map(|c|(c.ek_identity,c.encrypted.credential().to_vec(),c.encrypted.encrypted_seed().to_vec())).collect::<Vec<_>>();
    assert!(workflow.cancel(first.session));
    let second=workflow.begin(&candidate,&mut context,&mut maker).unwrap();assert_eq!(second.challenges.len(),2);
    for (a,b) in public_first.iter().zip(&second.challenges){
        assert_eq!(a.0,b.ek_identity);assert!(!b.encrypted.credential().is_empty()&&!b.encrypted.encrypted_seed().is_empty());
        assert_ne!((a.1.as_slice(),a.2.as_slice()),(b.encrypted.credential(),b.encrypted.encrypted_seed()));
    }
    assert!(workflow.cancel(second.session));assert_eq!(workflow.pending_count(),0);
}

#[test]
fn selected_genesis_ordinary_owner_actual_private_routes_and_native_signing() {
    // Mandatory reviewed LOCAL input; missing input fails selected control.
    // There is no protocol expiry or default lifetime here.
    let millis:u64=std::env::var("BUILD8_ACTIVATION_TEST_LOCAL_LIMIT_MS").expect("explicit local test limit required").parse().unwrap();
    assert!(millis>0);let lifetime=Duration::from_millis(millis);
    let f=selected_genesis();let mut nonce=[0;16];mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let base=std::env::temp_dir().join(format!("PUBLIC-selected-genesis-native-activation-{}",hex::encode(nonce)));
    assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
    let root=f.state.root().unwrap();let chain_path=base.join("canonical.sqlite");
    let open_chain=||CanonicalStore::open_trusted_genesis(&chain_path,&f.parent,&f.state,root,ek::T_REF,[255;32]).unwrap();
    let chain=open_chain();let public_chain=open_chain();
    chain.verified_activation_parent(&f.parent).unwrap();
    let pool=Mempool::open(&base.join("mempool.sqlite"),f.parent.genesis,f.parent.fingerprint,1024*1024).unwrap();
    let mut runtime=mutinyd_v8::hybrid_runtime_v2::HybridRuntime::from_pinned_chain_with_clock(chain,pool,||ek::T_REF+1).unwrap();
    let replacement=HybridKey::generate(Role::Continuity).unwrap();
    let mut rotation=KeyRotate{parent:f.parent.clone(),nonce:hash("actual native key rotation"),sequence:1,old_key_generation:1,
        binding:f.state.membership_v2.get(f.node).unwrap().binding().clone()};
    rotation.binding.admission.key_generation=2;
    rotation.binding.admission.continuity_descriptor=replacement.public().descriptor(2).unwrap();
    rotation.binding.admission.supervised_nonce=rotation.admission_nonce().unwrap();
    rotation.binding.admission.prove_continuity(&replacement).unwrap();
    rotation.binding.admission.quote=f.tpm.quote(rotation.binding.admission.challenge().unwrap());
    rotation.binding.admission.authorize(&f.owner,1).unwrap();rotation.binding.sign(&f.node_key).unwrap();
    rotation.verify(&f.state,&f.parent,root).unwrap();let raw=rotation.encode().unwrap();
    let timestamp=ek::T_REF+1;
    let prepared=runtime.prepare(mutinyd_v8::hybrid_runtime_v2::WorkRequest{expected_parent:&f.parent,
        license:f.license,worker:f.worker,timestamp,ticket:1,operations:&[raw]}).unwrap();
    let mut authority=Authority{work:WorkAuthority{candidate:prepared.candidate.clone(),assignment_sequence:1,ticket_sequence:1,
        coordinator:mutiny_consensus_v8::work_authority_v2::node_identity(&f.node_key.public().descriptor(1).unwrap()).unwrap(),
        nonce_start:0,nonce_end:100,epoch:0},node_descriptor:f.node_key.public().descriptor(1).unwrap(),signature:zero()};
    authority.sign(&f.node_key).unwrap();let header=WorkHeader{candidate:prepared.candidate,authority:authority.id().unwrap(),nonce:1};
    let block=header.block_hash();let record=mutinyd_v8::candidate_journal_v3::Record{header,authority,body:prepared.body};
    let mut journal=mutinyd_v8::candidate_journal_v3::Journal::open(&runtime,&base.join("candidate.sqlite"),1024*1024,true).unwrap();
    journal.preserve(&runtime,&record).unwrap();
    let calls=Rc::new(RefCell::new(Calls{counter:100,signatures:0}));
    let backend=Backend{key:f.continuity,node:f.node,calls:calls.clone()};
    let mut voter=mutinyd_v8::hybrid_voter_v2::VotingRuntime::open(runtime,&base.join("custody.sqlite"),f.node,Some(100),backend).unwrap();
    voter.set_vote_clock(mutiny_consensus_v8::vote_clock_v1::ControlledClock::at(timestamp));
    assert_eq!(voter.restore_a2_candidate(&journal,None).unwrap(),Some(block));
    // Owner::from_existing_test configures the gate exactly once below.
    let request=voter.activation_request(Step::Prevote,Some(block),None).unwrap().unwrap();
    assert_eq!(request.scope().admissions().len(),1);assert_eq!(request.scope().admissions()[0].endorsements().len(),2);
    use mutinyd_v8::activation_private_owner_v1 as native;
    use mutiny_transport_v2::{Context,Endpoint,InitiatorPending,ResponderPending};
    use std::net::{TcpListener,TcpStream};
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use zeroize::Zeroizing;
    struct Model {next:u64,secrets:Arc<Mutex<BTreeMap<u64,Zeroizing<[u8;32]>>>>}
    impl activation::MakeCredential for Model {
        fn make_credential(&mut self,ek:&[u8],name:&[u8;34],secret:&[u8;32])->Result<activation::EncryptedCredential,activation::Failure>{
            mutiny_consensus_v8::endorsement_identity::parse_ek_public_area(ek).map_err(|_|activation::Failure::Classes)?;
            if name[..2]!=[0,11]||secret==&[0;32]{return Err(activation::Failure::Material);}
            self.next=self.next.checked_add(1).ok_or(activation::Failure::Bounds)?;
            self.secrets.lock().unwrap().insert(self.next,Zeroizing::new(*secret));
            activation::EncryptedCredential::new(self.next.to_be_bytes().to_vec(),vec![1])
        }
    }
    let mut owner=native::Owner::from_existing_test(voter,public_chain,lifetime,
        Arc::new(Elapsed(Instant::now())),mutiny_consensus_v8::vote_clock_v1::ControlledClock::at(timestamp)).unwrap();
    let mut maker=Model{next:0,secrets:Arc::new(Mutex::new(BTreeMap::new()))};
    assert!(matches!(owner.fresh_sign(&mut maker,Step::Prevote,Some(block),None,None),
        Err(native::OwnerError::Private(native::Error::Endpoint))));
    assert_eq!(calls.borrow().signatures,0);assert_eq!(calls.borrow().counter,100);
    assert!(native::OwnedTargets::for_request(&request,BTreeMap::new()).is_err());
    // Authenticated malicious-peer request/route changes refuse BEFORE any
    // modeled private endpoint recovery or native custody call. These malformed
    // challenge bytes are negative private-channel fixtures, not public evidence.
    for wrong_scope in [true,false]{
        let a=HybridKey::generate(Role::Transport).unwrap();let b=HybridKey::generate(Role::Transport).unwrap();
        let ae=Endpoint::pinned(a.public().clone(),1).unwrap();let be=Endpoint::pinned(b.public().clone(),1).unwrap();
        let aid=ae.id();let bid=be.id();let parent=request.scope().parent();
        let ctx=Context::pinned(parent.genesis,parent.fingerprint,ae,be).unwrap();
        let(ip,hello)=InitiatorPending::start(ctx.clone(),&a).unwrap();let(rp,response)=ResponderPending::accept(ctx.clone(),&b,&hello).unwrap();
        let(confirm,finish)=ip.accept(&a,&response).unwrap();let(bs,tag)=rp.finish(&finish).unwrap();let asession=confirm.finish(&tag).unwrap();
        let ac=native::channel::PrivateChannel::from_authenticated(asession,&ctx,bid).unwrap();
        let bc=native::channel::PrivateChannel::from_authenticated(bs,&ctx,aid).unwrap();
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();let ai=TcpStream::connect(listener.local_addr().unwrap()).unwrap();let(bi,_)=listener.accept().unwrap();
        let mut sender=native::socket::PrivateSocket::new(ai,ac,lifetime).unwrap();let mut peer=native::socket::PrivateSocket::new(bi,bc,lifetime).unwrap();
        let admission=&request.scope().admissions()[0];
        let mut malformed=native::exchange::ChallengeFrame{session:[7;32],scope:request.scope().commitment(),signer:request.signer(),round:request.round(),step:request.step(),
            items:vec![native::exchange::EncryptedItem{admission:0,class:0,identity:admission.endorsements()[0],ak_name:*admission.ak_name(),credential:vec![1],seed:vec![1]}]};
        if wrong_scope{malformed.scope[0]^=1;}else{malformed.items[0].class=1;malformed.items[0].identity=admission.endorsements()[1];}
        sender.send_challenge(&malformed).unwrap();
        assert!(matches!(peer.receive_requested_challenge(&request,0,0),Err(native::Error::Context)));
        assert!(matches!(peer.receive_requested_challenge(&request,0,0),Err(native::Error::Endpoint)));
        assert_eq!(maker.next,0);assert_eq!(calls.borrow().signatures,0);assert_eq!(calls.borrow().counter,100);
    }
    std::thread::scope(|workers|{
        let mut routes=BTreeMap::new();let mut peers=Vec::new();
        for (i,admission) in request.scope().admissions().iter().enumerate(){
            for (class,identity) in admission.endorsements().iter().enumerate(){
                let a=HybridKey::generate(Role::Transport).unwrap();let b=HybridKey::generate(Role::Transport).unwrap();
                let ae=Endpoint::pinned(a.public().clone(),1).unwrap();let be=Endpoint::pinned(b.public().clone(),1).unwrap();
                let aid=ae.id();let bid=be.id();let parent=request.scope().parent();
                let ctx=Context::pinned(parent.genesis,parent.fingerprint,ae,be).unwrap();
                let(ip,hello)=InitiatorPending::start(ctx.clone(),&a).unwrap();
                let(rp,response)=ResponderPending::accept(ctx.clone(),&b,&hello).unwrap();
                let(confirm,finish)=ip.accept(&a,&response).unwrap();let(bs,tag)=rp.finish(&finish).unwrap();let asession=confirm.finish(&tag).unwrap();
                let ac=native::channel::PrivateChannel::from_authenticated(asession,&ctx,bid).unwrap();
                let bc=native::channel::PrivateChannel::from_authenticated(bs,&ctx,aid).unwrap();
                let listener=TcpListener::bind("127.0.0.1:0").unwrap();
                let ai=TcpStream::connect(listener.local_addr().unwrap()).unwrap();let(bi,_)=listener.accept().unwrap();
                let socket=native::socket::PrivateSocket::new(ai,ac,lifetime).unwrap();
                let mut peer=native::socket::PrivateSocket::new(bi,bc,lifetime).unwrap();
                assert!(routes.insert((i as u32,class as u8,*identity),socket).is_none());
                let own_request=request.clone();let secrets=maker.secrets.clone();
                peers.push(workers.spawn(move||{
                    let received=peer.receive_requested_challenge(&own_request,i as u32,class as u8).unwrap();
                    assert_eq!(received.items.len(),1);
                    let id=u64::from_be_bytes(received.items[0].credential.as_slice().try_into().unwrap());
                    let value=Zeroizing::new(**secrets.lock().unwrap().get(&id).unwrap());
                    let response=native::exchange::ResponseFrame::new(&received,vec![value]).unwrap();
                    peer.send_response(&received,&response).unwrap();
                }));
            }
        }
        let targets=native::OwnedTargets::for_request(&request,routes).unwrap();
        let vote=owner.fresh_sign(&mut maker,Step::Prevote,Some(block),None,Some(targets)).unwrap();
        assert_eq!(calls.borrow().signatures,1);
        let public_chain=open_chain();let authority=public_chain.current_authority(&f.parent).unwrap();
        vote.verify(&authority.parent,authority.roots(),&authority.voters).unwrap();
        let unsigned=vote.unsigned().unwrap();
        let decoded=native::decode_reserved_vote(&unsigned).unwrap();assert_eq!(decoded.unsigned().unwrap(),unsigned);
        let own=public_chain.validate_unsigned_vote_at_current_parent(&decoded).unwrap();assert_eq!(own.parent,f.parent);
        let mut wrong_parent=decoded.clone();wrong_parent.decision.parent[0]^=1;
        assert!(public_chain.validate_unsigned_vote_at_current_parent(&wrong_parent).is_err());
        let mut wrong_generation=decoded.clone();wrong_generation.key_generation+=1;
        assert!(public_chain.validate_unsigned_vote_at_current_parent(&wrong_generation).is_err());
        for n in 0..unsigned.len(){assert!(native::decode_reserved_vote(&unsigned[..n]).is_err());}
        let mut trailing=unsigned.clone();trailing.push(0);assert!(native::decode_reserved_vote(&trailing).is_err());
        assert!(matches!(native::decode_reserved_vote(&vec![0;mutiny_consensus_v8::continuity_v2::MAX_VOTE_BYTES+1]),Err(native::Error::Bounds)));
        let reserved_counter=calls.borrow().counter;let repeated=owner.replay(Step::Prevote).unwrap().unwrap();assert_eq!(repeated.encode().unwrap(),vote.encode().unwrap());
        assert_eq!(calls.borrow().signatures,1);assert_eq!(calls.borrow().counter,reserved_counter);for peer in peers{peer.join().unwrap();}
    });
    assert_eq!(maker.next,2);
}
