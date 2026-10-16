//! UNRUN native-service controls. Genuine synthetic hybrid wire and native
//! SQLite boundary; private TEST Provider construction is not enrollment.
use super::*;
use crate::{treasury_continuity_v1::{Action,PublicRecord},
    treasury_continuity_provider_v1::authenticated_wire::{AuthenticatedProvider,WireTransport},
    treasury_continuity_owner_v1::{Owner as AdmissionOwner,Error as OwnerError},
    treasury_admission_v3::{AdmissionStore,StoreIdentity,LocalStoragePolicy},
    treasury_rehearsal_v3::{Expect,Denylist}};
use std::{rc::Rc,cell::RefCell,io::{Read,Cursor,Write},path::PathBuf,fs,
    os::unix::fs::{DirBuilderExt,OpenOptionsExt}};
use mutiny_crypto_v2::{Role,treasury_proof_v1 as proof};
fn directory(label:&str)->PathBuf{
    let root=PathBuf::from(std::env::var_os("BUILD8_NATIVE_SQLITE_FIXTURE_ROOT").expect("mandatory native TEST root"));
    assert!(root.is_absolute());let mut salt=[0;32];mutiny_crypto_v2::fill_os_random(&mut salt).unwrap();
    let path=root.join(format!("native-service-{label}-{}",hex::encode(salt)));
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    eprintln!("RETAINED_PUBLIC_NATIVE_SERVICE_TEST={}",path.display());path
}
fn policy()->Policy{Policy::new(32*1024*1024,NonZeroU64::new(4_000_000).unwrap()).unwrap()}
fn admission_policy()->LocalStoragePolicy{LocalStoragePolicy::new(32*1024*1024,NonZeroU64::new(4_000_000).unwrap()).unwrap()}
fn copy(dir:&PathBuf,label:&str)->PathBuf{
    let dest=directory(label);let bytes=fs::read(dir.join("state.sqlite")).unwrap();
    let mut f=fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(dest.join("state.sqlite")).unwrap();
    f.write_all(&bytes).unwrap();f.sync_all().unwrap();dest
}
#[derive(Clone)] struct LocalWire{endpoint:Rc<RefCell<Endpoint>>}
impl WireTransport for LocalWire{
    fn exchange(&mut self,request:&[u8])->Result<Box<dyn Read>,ProviderError>{
        let mut endpoint=self.endpoint.try_borrow_mut().map_err(|_|ProviderError::Unavailable)?;
        let raw=endpoint.handle(request).map_err(|error|match error{
            Error::Unknown=>ProviderError::Unknown,Error::Context=>ProviderError::Context,
            Error::Authentication(e)=>e,_=>ProviderError::Invalid})?;
        Ok(Box::new(Cursor::new(raw)))
    }
}
struct Fixture{admission_dir:PathBuf,service_dir:PathBuf,config:CeremonyConfig,scope:Scope,
    id:StoreIdentity,key:mutiny_crypto_v2::rehearsal_keys_v1::Credential,
    endpoint:Rc<RefCell<Endpoint>>,client_encrypted:Vec<u8>}
fn fixture(label:&str)->(Fixture,AdmissionOwner<AuthenticatedProvider<LocalWire>>){
    let key=mutiny_crypto_v2::rehearsal_keys_v1::Credential::from_label(label,1).unwrap();
    let config=CeremonyConfig::rehearsal(mutiny_crypto_v2::NETWORK,
        crate::treasury_v1::Treasury::new(crate::treasury_v1::Class::TestValue,key.descriptor().unwrap()).unwrap(),label).unwrap();
    let admission_dir=directory("admission");let service_dir=directory("external-service");
    let id=AdmissionStore::create_native(&admission_dir,&config,admission_policy()).unwrap();
    let scope=Scope{network:config.network(),genesis:None,ceremony_context:config.context().value(),
        treasury_record:crate::treasury_rehearsal_v3::record_sha256(config.treasury()).unwrap(),
        verifier:[71;32],store:id.store_id(),service:[72;32]};
    let client=HybridKey::generate(Role::Transport).unwrap();let server=HybridKey::generate(Role::Transport).unwrap();
    let pins=PublicPins::new(scope.clone(),[73;32],client.public().descriptor(1).unwrap(),server.public().descriptor(1).unwrap()).unwrap();
    let endpoint=Rc::new(RefCell::new(Endpoint::new(Service::create_native(&service_dir,&config,scope.clone(),policy()).unwrap(),pins.clone(),server).unwrap()));
    let client_encrypted=client.seal_for("PUBLIC NATIVE STARTUP TEST ONLY",1,&[76;32]).unwrap();
    let provider=AuthenticatedProvider::modeled(pins,client,LocalWire{endpoint:endpoint.clone()}).unwrap();
    let store=AdmissionStore::open_native(&admission_dir,&config,id,admission_policy()).unwrap();
    let owner=AdmissionOwner::new(store,provider,scope.clone(),Expect::genesis_key(&config),vec![],Denylist::default()).unwrap();
    assert!(!owner.frozen());(Fixture{admission_dir,service_dir,config,scope,id,key,endpoint,client_encrypted},owner)
}
fn head(f:&Fixture)->PublicSnapshot{f.endpoint.borrow().service.current([75;32]).unwrap()}
fn close_service(service:Service){assert!(service.close().is_ok(),"native explicit close failed");}

// TEST-only independent administrator selection of the exact current public
// history is MODELED. Native close/reopen, authenticated wire and SQLite are
// actual software actions; AfterCommit is an injected acknowledgement fault,
// and the path-substitution control supplies no physical power-loss credit.
// Caller has dropped the ordinary admission owner: it has no explicit close API.
fn restart_exact(f:Fixture,pinned:PublicSnapshot,destination:PathBuf,
    expected_failed_close:bool)->(Fixture,AdmissionOwner<AuthenticatedProvider<LocalWire>>){
    let Fixture{admission_dir,service_dir:_,config,scope,id,key,endpoint,client_encrypted}=f;
    let Endpoint{service,pins,key:server_key,head,frozen}=
        Rc::try_unwrap(endpoint).ok().expect("all old TEST clients dropped").into_inner();
    assert!(frozen);assert!(head.is_none());assert_eq!(pins.scope(),&scope);
    assert_eq!(pinned.scope(),&scope);
    match service.close(){
        Ok(())=>assert!(!expected_failed_close,"latched failure must refuse close"),
        Err((retained,error))=>{
            // The failed original native owner remains quarantined. Dropping
            // it would retry cleanup/close; no successful close is claimed.
            std::mem::forget(retained);
            assert!(expected_failed_close);assert_eq!(error,Error::Storage);
        }
    }
    let service=Service::open_native(&destination,&config,scope.clone(),policy(),&pinned,true).unwrap();
    assert_eq!(service.current([77;32]).unwrap().operations(),pinned.operations());
    assert_eq!(server_key.public().descriptor(1).unwrap(),pins.service_descriptor());
    let(client,generation)=HybridKey::open_for(mutiny_crypto_v2::Role::Transport,
        "PUBLIC NATIVE STARTUP TEST ONLY",&[76;32],&client_encrypted).unwrap();
    assert_eq!(generation,1);assert_eq!(client.public().descriptor(1).unwrap(),pins.client_descriptor());
    let endpoint=Rc::new(RefCell::new(Endpoint::new(service,pins.clone(),server_key).unwrap()));
    let provider=AuthenticatedProvider::modeled(pins,client,LocalWire{endpoint:endpoint.clone()}).unwrap();
    let store=AdmissionStore::open_native(&admission_dir,&config,id,admission_policy()).unwrap();
    let owner=AdmissionOwner::new(store,provider,scope.clone(),Expect::genesis_key(&config),vec![],Denylist::default()).unwrap();
    assert!(owner.frozen(),"external pending operation must remain unresolved on restart");
    (Fixture{admission_dir,service_dir:destination,config,scope,id,key,endpoint,client_encrypted},owner)
}
#[test]
fn real_service_reopen_read_only_audits_exact_head_and_refuses_transition(){
    let(f,mut owner)=fixture("PUBLIC-native-service-reopen");owner.issue(&f.key.descriptor().unwrap()).unwrap();
    let pinned=head(&f);assert_eq!(pinned.sequence(),2);drop(owner);
    let endpoint=Rc::try_unwrap(f.endpoint).ok().unwrap().into_inner();close_service(endpoint.service);
    let before=fs::read(f.service_dir.join("state.sqlite")).unwrap();
    let mut ro=Service::open_native(&f.service_dir,&f.config,f.scope,policy(),&pinned,false).unwrap();
    assert_eq!(ro.current([76;32]).unwrap().operations(),pinned.operations());
    let req=Request{scope:ro.scope.clone(),operation:[77;32],request_nonce:[78;32],expected_sequence:2,
        action:Action::Reserve(PublicRecord{generation:1,nonce:[79;32],challenge:vec![1],descriptor:vec![2],signature:None})};
    assert_eq!(ro.apply(&req),Err(Error::ReadOnly));close_service(ro);
    assert_eq!(fs::read(f.service_dir.join("state.sqlite")).unwrap(),before);
}
#[test]
fn service_stale_restore_refuses_exact_independent_head_before_promotion(){
    let(f,mut owner)=fixture("PUBLIC-native-service-stale");let stale=copy(&f.service_dir,"stale-service");
    owner.issue(&f.key.descriptor().unwrap()).unwrap();let pinned=head(&f);assert_eq!(pinned.sequence(),2);
    let before=fs::read(stale.join("state.sqlite")).unwrap();
    assert!(matches!(Service::open_native(&stale,&f.config,f.scope.clone(),policy(),&pinned,true),Err(Error::History)));
    assert_eq!(fs::read(stale.join("state.sqlite")).unwrap(),before);
    assert!(matches!(fs::symlink_metadata(stale.join("state.sqlite-journal")), Err(e) if e.kind()==std::io::ErrorKind::NotFound));
    // This does not detect an administrator also substituting the independently
    // trusted pinned head; such authority is a deployment dependency.
}
#[test]
fn native_service_lost_reserve_ack_freezes_both_then_exact_reconciliation(){
    let(f,mut owner)=fixture("PUBLIC-native-service-lost-reserve");
    f.endpoint.borrow_mut().service.fault=Some(Fault::AfterCommit);
    let before=fs::read(f.admission_dir.join("state.sqlite")).unwrap();
    assert_eq!(owner.issue(&f.key.descriptor().unwrap()),Err(OwnerError::Provider(ProviderError::Unknown)));
    assert!(owner.frozen());let public=head(&f);assert_eq!(public.sequence(),1);assert!(public.pending_operation().is_some());
    assert_eq!(fs::read(f.admission_dir.join("state.sqlite")).unwrap(),before);
    assert_eq!(owner.issue(&f.key.descriptor().unwrap()),Err(OwnerError::Frozen));
    assert_eq!(owner.reconcile(),Err(OwnerError::Provider(ProviderError::Unknown)));
    assert!(f.endpoint.borrow().frozen);assert_eq!(fs::read(f.admission_dir.join("state.sqlite")).unwrap(),before);
    let directory=f.service_dir.clone();let operations=public.operations().to_vec();drop(owner);
    let(f,mut owner)=restart_exact(f,public,directory,false);
    assert_eq!(head(&f).operations(),operations.as_slice());
    owner.reconcile().unwrap();assert!(!owner.frozen());assert_eq!(owner.sequence(),2);assert_eq!(head(&f).pending_operation(),None);
}
#[test]
fn native_service_both_halves_then_consume_before_local_commit_and_exact_repair(){
    let(f,mut owner)=fixture("PUBLIC-native-service-lost-consume");let d=f.key.descriptor().unwrap();
    let ch=owner.issue(&d).unwrap();let raw=ch.encode().unwrap();let sig=proof::sign_challenge(f.key.key(),&d,&ch).unwrap();
    let before=fs::read(f.admission_dir.join("state.sqlite")).unwrap();
    for half in 0..2{let mut bad=sig.clone();if half==0{bad.ed448[0]^=1}else{bad.fndsa[0]^=1}
        assert!(owner.admit(&d,&raw,&bad).is_err());assert!(!owner.frozen());assert_eq!(head(&f).sequence(),2);
        assert_eq!(fs::read(f.admission_dir.join("state.sqlite")).unwrap(),before);}
    f.endpoint.borrow_mut().service.fault=Some(Fault::AfterCommit);
    assert_eq!(owner.admit(&d,&raw,&sig),Err(OwnerError::Provider(ProviderError::Unknown)));
    assert!(owner.frozen());assert_eq!(head(&f).sequence(),3);assert!(head(&f).pending_operation().is_some());
    assert_eq!(fs::read(f.admission_dir.join("state.sqlite")).unwrap(),before);
    assert_eq!(owner.admit(&d,&raw,&sig),Err(OwnerError::Frozen));
    assert_eq!(owner.reconcile(),Err(OwnerError::Provider(ProviderError::Unknown)));
    assert!(f.endpoint.borrow().frozen);assert_eq!(fs::read(f.admission_dir.join("state.sqlite")).unwrap(),before);
    let pinned=head(&f);let operations=pinned.operations().to_vec();let directory=f.service_dir.clone();drop(owner);
    let(f,mut owner)=restart_exact(f,pinned,directory,false);
    assert_eq!(head(&f).operations(),operations.as_slice());owner.reconcile().unwrap();
    assert_eq!(owner.sequence(),4);assert!(!owner.frozen());assert_eq!(head(&f).pending_operation(),None);
    assert_eq!(owner.admit(&d,&raw,&sig),Err(OwnerError::Native(Refusal::Replay)));
}
#[test]
fn native_service_held_main_and_journal_substitution_never_acknowledge(){
    for journal in [false,true]{
        let(f,mut owner)=fixture(if journal{"PUBLIC-native-service-journal"}else{"PUBLIC-native-service-main"});
        let main=f.service_dir.join("state.sqlite");let old=f.service_dir.join("preserved-original.sqlite");
        let original=fs::read(&main).unwrap();
        if journal{std::os::unix::fs::symlink(&main,f.service_dir.join("state.sqlite-journal")).unwrap();}
        else{fs::rename(&main,&old).unwrap();let mut replacement=fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&main).unwrap();replacement.write_all(&original).unwrap();replacement.sync_all().unwrap();}
        assert!(owner.issue(&f.key.descriptor().unwrap()).is_err());assert!(owner.frozen());
        assert_eq!(fs::read(&main).unwrap(),original);
        if !journal{assert_eq!(fs::read(&old).unwrap(),original);}
    }
}
#[test]
fn terminal_consumption_survives_real_service_close_reopen_and_cannot_reconsume(){
    let(f,mut owner)=fixture("PUBLIC-native-service-terminal-reopen");let d=f.key.descriptor().unwrap();
    let ch=owner.issue(&d).unwrap();let sig=proof::sign_challenge(f.key.key(),&d,&ch).unwrap();
    owner.admit(&d,&ch.encode().unwrap(),&sig).unwrap();let pinned=head(&f);
    assert_eq!(pinned.sequence(),4);assert_eq!(pinned.pending_operation(),None);
    let terminal=PublicRecord{generation:1,nonce:ch.nonce,challenge:ch.encode().unwrap(),descriptor:d,
        signature:Some(proof::signature_to_bytes(&sig))};drop(owner);
    let endpoint=Rc::try_unwrap(f.endpoint).ok().unwrap().into_inner();close_service(endpoint.service);
    let mut reopened=Service::open_native(&f.service_dir,&f.config,f.scope.clone(),policy(),&pinned,true).unwrap();
    let before=fs::read(f.service_dir.join("state.sqlite")).unwrap();
    let request=Request{scope:f.scope,operation:[81;32],request_nonce:[82;32],expected_sequence:4,action:Action::Consume(terminal)};
    assert_eq!(reopened.apply(&request),Err(Error::Model(ModelError::Replay)));
    assert_eq!(reopened.current([83;32]).unwrap().operations(),pinned.operations());close_service(reopened);
    assert_eq!(fs::read(f.service_dir.join("state.sqlite")).unwrap(),before);
}

// Test-only destination substitution; neither a mocked status nor power-loss evidence.
// The held original inode already contains the completed transaction. Retain it.
pub(super) fn substitute_committed_main(dir:&std::path::Path)->Result<(),Error>{
    let main=dir.join("state.sqlite");let retained=dir.join("preserved-postcommit-original.sqlite");
    let raw=fs::read(&main).map_err(|_|Error::Unknown)?;
    if raw.is_empty() || raw.len()>32*1024*1024{return Err(Error::Unknown);}
    if !matches!(fs::symlink_metadata(&retained),Err(e) if e.kind()==std::io::ErrorKind::NotFound){return Err(Error::Unknown);}
    fs::rename(&main,&retained).map_err(|_|Error::Unknown)?;
    let mut replacement=fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(&main).map_err(|_|Error::Unknown)?;
    replacement.write_all(&raw).map_err(|_|Error::Unknown)?;
    replacement.sync_all().map_err(|_|Error::Unknown)?;
    fs::File::open(dir).and_then(|f|f.sync_all()).map_err(|_|Error::Unknown)?;
    Ok(())
}
#[test]
fn real_outer_postcommit_boundary_fault_is_unknown_freezes_both_and_reconciles_exact(){
    let(f,mut owner)=fixture("PUBLIC-native-service-outer-postcommit");
    let observed=Rc::new(RefCell::new(None));
    f.endpoint.borrow_mut().service.fault=Some(Fault::AfterPostcheckPathSubstitution {
        directory:f.service_dir.clone(),committed:observed.clone()});
    let descriptor=f.key.descriptor().unwrap();
    let admission_before=fs::read(f.admission_dir.join("state.sqlite")).unwrap();
    assert_eq!(owner.issue(&descriptor),Err(OwnerError::Provider(ProviderError::Unknown)));
    assert!(owner.frozen());
    assert_eq!(fs::read(f.admission_dir.join("state.sqlite")).unwrap(),admission_before);
    // Actual outer status latched: even a public current read is unavailable on this owner.
    assert_eq!(f.endpoint.borrow().service.current([85;32]),Err(Error::Storage));
    let pinned=observed.borrow().clone().expect("real commit and inner check reached");
    assert_eq!(pinned.sequence(),1);assert!(pinned.pending_operation().is_some());
    let record=match &pinned.operations()[0].action {
        Action::Reserve(record)=>record.clone(),_=>panic!("exact external Reserve required")};
    let challenge=proof::Challenge::decode(&record.challenge).unwrap();
    let signature=proof::sign_challenge(f.key.key(),&descriptor,&challenge).unwrap();
    assert_eq!(owner.issue(&descriptor),Err(OwnerError::Frozen));
    assert_eq!(owner.admit(&descriptor,&record.challenge,&signature),Err(OwnerError::Frozen));
    let original=f.service_dir.join("preserved-postcommit-original.sqlite");
    assert_eq!(fs::read(&original).unwrap(),fs::read(f.service_dir.join("state.sqlite")).unwrap());
    // Fresh independent native owner proves the durably retained record by full replay,
    // exact pinned head and genuine authenticated endpoint. This TEST pin is an
    // independently retained postcommit observation, not production restore authority.
    let restored=copy(&f.service_dir,"outer-postcommit-restored");
    assert_eq!(owner.reconcile(),Err(OwnerError::Provider(ProviderError::Unknown)));
    assert!(f.endpoint.borrow().frozen);assert_eq!(fs::read(f.admission_dir.join("state.sqlite")).unwrap(),admission_before);
    let original_main=f.service_dir.join("state.sqlite");let operations=pinned.operations().to_vec();drop(owner);
    let(f,mut owner)=restart_exact(f,pinned,restored,true);
    assert_eq!(head(&f).operations(),operations.as_slice());owner.reconcile().unwrap();
    assert!(!owner.frozen());assert_eq!(owner.sequence(),2);
    assert_eq!(head(&f).pending_operation(),None);
    owner.admit(&descriptor,&record.challenge,&signature).unwrap();
    assert_eq!(owner.sequence(),4);assert_eq!(head(&f).pending_operation(),None);
    assert_eq!(owner.admit(&descriptor,&record.challenge,&signature),Err(OwnerError::Native(Refusal::Replay)));
    assert_eq!(fs::read(&original).unwrap(),fs::read(&original_main).unwrap());
}
