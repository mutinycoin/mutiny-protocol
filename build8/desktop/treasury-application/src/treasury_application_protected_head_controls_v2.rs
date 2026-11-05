//! SOURCE ONLY / UNCOMPILED / UNRUN native protected-head ambiguity controls.
//! No normal initializer or enrollment input is exposed by this private child.
use super::*;
use crate::{treasury_continuity_v1::{Action,PublicRecord},
    treasury_continuity_provider_v1::authenticated_wire::PublicPins,
    treasury_rehearsal_v3::CeremonyConfig,treasury_native_service_v1::Policy};
use mutiny_crypto_v2::{rehearsal_keys_v1::Credential,treasury_proof_v1 as proof};
use std::{fs,io::Write,path::Path,os::unix::fs::{DirBuilderExt,OpenOptionsExt}};

fn directory(label:&str)->PathBuf{
    let root=PathBuf::from(std::env::var_os("BUILD8_NATIVE_SQLITE_FIXTURE_ROOT").expect("mandatory reviewed native TEST root"));
    assert!(root.is_absolute());let mut salt=[0;32];mutiny_crypto_v2::fill_os_random(&mut salt).unwrap();
    let path=root.join(format!("protected-head-{label}-{}",hex::encode(salt)));
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    eprintln!("RETAINED_PUBLIC_NATIVE_HEAD_TEST={}",path.display());path
}
fn policy()->Policy{Policy::new(32*1024*1024,NonZeroU64::new(4_000_000).unwrap()).unwrap()}
fn close_service(service:Service){assert!(service.close().is_ok(),"explicit service close failed");}
fn close_head(head:HeadOwner){assert!(head.close().is_ok(),"explicit head close failed");}
fn new_file(path:&Path,raw:&[u8]){
    let mut f=fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
    f.write_all(raw).unwrap();f.sync_all().unwrap();fs::File::open(path.parent().unwrap()).unwrap().sync_all().unwrap();
}
struct Fixture{approval:VerifiedApproval,location:Location,config:CeremonyConfig,
    credential:Credential,head:HeadOwner,service:Service,record:PublicRecord}
fn fixture(label:&str)->Fixture{
    let credential=Credential::from_label(label,1).unwrap();let descriptor=credential.descriptor().unwrap();
    let config=CeremonyConfig::rehearsal(mutiny_crypto_v2::NETWORK,
        crate::treasury_v1::Treasury::new(crate::treasury_v1::Class::TestValue,descriptor.clone()).unwrap(),label).unwrap();
    let(mut r,client,server)=super::super::tests::fixture();
    let scope=Scope{network:config.network(),genesis:None,ceremony_context:config.context().value(),
        treasury_record:crate::treasury_rehearsal_v3::record_sha256(config.treasury()).unwrap(),
        verifier:[71;32],store:[72;32],service:[73;32]};
    r.store=scope.store;r.admission=directory("admission");r.service=directory("service");
    r.pins=PublicPins::new(scope.clone(),[74;32],client.public().descriptor(1).unwrap(),server.public().descriptor(1).unwrap()).unwrap();
    r.checkpoint=PublicSnapshot::new(scope.clone(),[75;32],0,None,vec![]).unwrap();
    let document=r.encode().unwrap();let current=r.checkpoint.clone();
    // Fixed private TEST administration, never normal application_selection.
    let approval=VerifiedApproval{selection:digest(&document),record:r,document,current};
    let location=Location{path:directory("head"),file_cap:32*1024*1024,steps:NonZeroU64::new(4_000_000).unwrap()};
    location.validate(&approval).unwrap();let binding=Binding::approved(&approval).unwrap();
    let mut owner=NativeOwner::new_only(&location.path,location.file_cap).unwrap();
    owner.mutate_typed(native,|db,boundary,slot|{
        durability(db,true)?;let tx=sql(db.transaction_with_behavior(TransactionBehavior::Immediate))?;
        let budget=VmBudget::install(&tx,slot,location.steps).map_err(resource)?;
        sql(tx.execute_batch(&format!("{META};{OPS};{INTENT};")))?;
        sql(tx.execute("INSERT INTO head_meta VALUES(1,?1,?2,?3,?4)",params![scope_bytes(&binding.scope)?,
            binding.administrator.as_slice(),binding.document.as_slice(),binding.seed.as_slice()]))?;
        drop(budget);boundary.status().map_err(native)?;tx.commit().map_err(|_|Error::Unknown)?;
        boundary.status().map_err(|_|Error::Unknown)?;Ok(())
    }).unwrap();
    let head=HeadOwner{owner,binding,steps:location.steps,writable:true,frozen:false};
    let service=Service::create_native(&approval.record.service,&config,scope.clone(),policy()).unwrap();
    head.matches_service(&service).unwrap();
    let challenge=proof::Challenge::new(&descriptor,proof::Phase::Rehearsal,
        credential.key().public().address_id(1).unwrap(),scope.treasury_record,scope.ceremony_context,[76;32]).unwrap();
    let record=PublicRecord{generation:1,nonce:challenge.nonce,challenge:challenge.encode().unwrap(),descriptor,signature:None};
    Fixture{approval,location,config,credential,head,service,record}
}
fn request(f:&Fixture,sequence:u64,byte:u8,action:Action)->Request{
    Request{scope:f.service.scope().clone(),operation:[byte;32],request_nonce:[byte+1;32],expected_sequence:sequence,action}
}
fn prepare_consumption(f:&mut Fixture)->Request{
    let reserve=request(f,0,80,Action::Reserve(f.record.clone()));
    f.head.begin(&f.service,&reserve).unwrap();f.service.apply(&reserve).unwrap();f.head.publish(&f.service).unwrap();
    let confirm=request(f,1,82,Action::ConfirmLocal{pending_operation:reserve.operation,exact:f.record.clone()});
    f.head.begin(&f.service,&confirm).unwrap();f.service.apply(&confirm).unwrap();f.head.publish(&f.service).unwrap();
    let challenge=proof::Challenge::decode(&f.record.challenge).unwrap();
    let signature=proof::sign_challenge(f.credential.key(),&f.record.descriptor,&challenge).unwrap();
    // Both hybrid halves are verified before any irreversible consume/intent.
    let before=f.head.read().unwrap();
    for half in 0..2{let mut bad=signature.clone();if half==0{bad.ed448[0]^=1}else{bad.fndsa[0]^=1}
        assert!(challenge.verify(&f.record.descriptor,&bad).is_err());assert_eq!(f.head.read().unwrap(),before);}
    challenge.verify(&f.record.descriptor,&signature).unwrap();
    let mut signed=f.record.clone();signed.signature=Some(proof::signature_to_bytes(&signature));
    request(f,2,84,Action::Consume(signed))
}
#[test]
fn consumed_service_restored_before_intent_remains_frozen_across_native_reopen(){
    let mut f=fixture("PUBLIC-head-consumed-service-restore");let consume=prepare_consumption(&mut f);
    let Fixture{approval,location,config,credential:_,mut head,service,record:_}=f;
    close_service(service);let older=fs::read(approval.service_path().join("state.sqlite")).unwrap();
    let pinned=head.read().unwrap().0;assert_eq!(pinned.sequence(),2);
    let mut service=Service::open_native(approval.service_path(),&config,approval.pins().scope().clone(),policy(),&pinned,true).unwrap();
    head.begin(&service,&consume).unwrap();service.apply(&consume).unwrap();assert_eq!(service.current([90;32]).unwrap().sequence(),3);
    // Lost publication/ACK. Preserve the actual consumed public DB before TEST restore.
    close_service(service);let main=approval.service_path().join("state.sqlite");
    let consumed=approval.service_path().join("preserved-consumed.sqlite");
    assert!(matches!(fs::symlink_metadata(&consumed),Err(e) if e.kind()==std::io::ErrorKind::NotFound));
    fs::rename(&main,&consumed).unwrap();new_file(&main,&older);
    let head_before=fs::read(location.path.join("state.sqlite")).unwrap();let target=head.recovery_target().unwrap();
    let restored=Service::open_reconciling_native(approval.service_path(),&config,approval.pins().scope().clone(),policy(),&target).unwrap();
    assert_eq!(head.reconcile(&restored),Err(Error::Frozen));assert!(head.frozen);
    assert_eq!(head.read().unwrap().1,Some(consume.clone()));
    assert_eq!(head.begin(&restored,&consume),Err(Error::Frozen));
    assert_eq!(head.matches_service(&restored),Err(Error::Frozen));
    assert_eq!(fs::read(location.path.join("state.sqlite")).unwrap(),head_before);
    close_service(restored);close_head(head);
    let mut reopened=HeadOwner::open(&approval,&location,true).unwrap();
    assert_eq!(reopened.read().unwrap().1,Some(consume.clone()));
    let target=reopened.recovery_target().unwrap();
    let restored=Service::open_reconciling_native(approval.service_path(),&config,approval.pins().scope().clone(),policy(),&target).unwrap();
    assert_eq!(reopened.reconcile(&restored),Err(Error::Frozen));assert_eq!(reopened.matches_service(&restored),Err(Error::Frozen));
    assert_eq!(fs::read(location.path.join("state.sqlite")).unwrap(),head_before);
    assert!(reopened.approved_current(approval).is_err());close_service(restored);close_head(reopened);
}
#[test]
fn crash_before_service_apply_keeps_exact_durable_intent_and_refuses_new_rights(){
    let mut f=fixture("PUBLIC-head-before-service-apply");let reserve=request(&f,0,96,Action::Reserve(f.record.clone()));
    f.head.begin(&f.service,&reserve).unwrap();let head_before=fs::read(f.location.path.join("state.sqlite")).unwrap();
    assert_eq!(f.service.current([98;32]).unwrap().sequence(),0);
    assert_eq!(f.head.reconcile(&f.service),Err(Error::Frozen));assert_eq!(f.head.read().unwrap().1,Some(reserve.clone()));
    assert_eq!(f.head.begin(&f.service,&reserve),Err(Error::Frozen));
    assert_eq!(fs::read(f.location.path.join("state.sqlite")).unwrap(),head_before);
    let Fixture{approval,location,config,credential:_,head,service,record:_}=f;close_service(service);close_head(head);
    let mut head=HeadOwner::open(&approval,&location,true).unwrap();let target=head.recovery_target().unwrap();
    let service=Service::open_reconciling_native(approval.service_path(),&config,approval.pins().scope().clone(),policy(),&target).unwrap();
    assert_eq!(head.reconcile(&service),Err(Error::Frozen));assert_eq!(head.read().unwrap().1,Some(reserve));
    assert_eq!(fs::read(location.path.join("state.sqlite")).unwrap(),head_before);
    close_service(service);close_head(head);
}
#[test]
fn exact_after_reconciliation_retains_operation_receipt_and_immutable_seed(){
    let mut f=fixture("PUBLIC-head-exact-after");let reserve=request(&f,0,100,Action::Reserve(f.record.clone()));
    let document=f.approval.document.clone();let seed=f.approval.record.checkpoint.clone();
    f.head.begin(&f.service,&reserve).unwrap();let(receipt,_)=f.service.apply(&reserve).unwrap();
    f.head.freeze();f.head.reconcile(&f.service).unwrap();assert!(!f.head.frozen);
    let(current,intent)=f.head.read().unwrap();assert!(intent.is_none());assert_eq!(current.sequence(),1);
    assert_eq!(current.pending_operation(),Some(reserve.operation));
    f.head.owner.inspect_typed(native,|db,_|{
        let row:(Vec<u8>,Vec<u8>)=sql(db.query_row("SELECT request,receipt FROM head_operations WHERE sequence=1",[],|r|Ok((r.get(0)?,r.get(1)?))))?;
        assert_eq!(row.0,reserve.encode().unwrap());assert_eq!(decode_receipt(&row.1).unwrap(),receipt);Ok(())
    }).unwrap();
    assert_eq!(f.approval.document,document);assert_eq!(f.approval.record.checkpoint,seed);
    let Fixture{approval,location,config,credential:_,head,service,record:_}=f;close_service(service);close_head(head);
    let head=HeadOwner::open(&approval,&location,false).unwrap();let approved=head.approved_current(approval).unwrap();
    assert_eq!(approved.checkpoint().sequence(),1);assert_eq!(approved.record.checkpoint,seed);assert_eq!(approved.document,document);
    let service=Service::open_native(approved.service_path(),&config,approved.pins().scope().clone(),policy(),approved.checkpoint(),false).unwrap();
    head.matches_service(&service).unwrap();close_service(service);close_head(head);
    // Pending Reserve remains pending; no local admission/consume rights claimed.
}
