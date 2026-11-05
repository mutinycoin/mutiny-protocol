//! Genuine native TEST-VALUE entry control; no deployment selection or spending keys.
use super::*;
#[path="../../desktop/src/wallet_host_fixture_licenses.rs"] mod licenses;
#[path="../../consensus/tests/support/wallet_host_fixture_tpm.rs"] mod tpm;
include!("../../consensus/tests/support/dividend_rig.rs");
use crate::{treasury_admission_v3::{AdmissionStore,LocalStoragePolicy},
    treasury_rehearsal_v3::{CeremonyConfig,TrustedChain,Denylist},
    treasury_native_service_v1::{Service,Policy,tcp::Error as TcpError},
    treasury_native_application_entry_v1 as entry};
use crate::treasury_application_api_v1::{Client as OrdinaryClient,Service as OrdinaryService,OpenError};
use zeroize::Zeroizing;
use std::{fs,thread,sync::mpsc,num::NonZeroU64,os::unix::fs::DirBuilderExt};
use mutiny_crypto_v2::{rehearsal_keys_v1::Credential,treasury_proof_v1 as proof};
const VALUE:&str="PUBLIC TREASURY SHARED ENTRY TEST ONLY";
// Ceremony labels follow the existing graphic-only public context grammar.
const CEREMONY_LABEL:&str="PUBLIC-TREASURY-SHARED-ENTRY-TEST-ONLY";
fn main_dispatch(command:&str,document:&[u8],custody:&[u8])->Result<(),crate::StartupRefusal>{
    let mut input=Vec::new();for raw in [document,custody,VALUE.as_bytes()]{
        input.extend_from_slice(&(raw.len() as u32).to_be_bytes());input.extend_from_slice(raw);
    }
    crate::application_main(&[command.into()],&mut std::io::Cursor::new(input))
}
#[test]
fn shared_entry_missing_selection_refuses_all_service_paths_before_io(){
    let credential=Credential::from_label("PUBLIC-entry-refusal-k1",1).unwrap();
    let config=CeremonyConfig::rehearsal(mutiny_crypto_v2::NETWORK,
        Treasury::new(Class::TestValue,credential.descriptor().unwrap()).unwrap(),CEREMONY_LABEL).unwrap();
    assert!(matches!(entry::reopen_service(b"untrusted",b"not-custody",VALUE,&config,service_policy()),
        Err(entry::Error::Enrollment(Error::MissingEnrollment))));
    assert!(matches!(entry::reconcile_service(b"untrusted",b"not-custody",VALUE,&config,service_policy()),
        Err(entry::Error::Enrollment(Error::MissingEnrollment))));
    assert_eq!(crate::deployment_status(),Err(crate::StartupRefusal::MissingAuthenticEnrollment));
    assert!(matches!(OrdinaryService::open(b"untrusted",Zeroizing::new(b"not-custody".to_vec()),Zeroizing::new(VALUE.into())),
        Err(OpenError::MissingAuthenticEnrollment)));
    assert!(matches!(OrdinaryService::open_reconciling(b"untrusted",Zeroizing::new(b"not-custody".to_vec()),Zeroizing::new(VALUE.into())),
        Err(OpenError::MissingAuthenticEnrollment)));
    let f=fixture_with_treasury(credential.key(),1_200_000);let rig=Rig::new(f,"ordinary-missing-selection");
    assert!(matches!(OrdinaryClient::open(b"untrusted",Zeroizing::new(b"not-custody".to_vec()),Zeroizing::new(VALUE.into()),&rig.chain,Denylist::default()),
        Err(OpenError::MissingAuthenticEnrollment)));
    struct NeverRead;impl std::io::Read for NeverRead{fn read(&mut self,_:&mut[u8])->std::io::Result<usize>{panic!("missing selection must precede custody I/O");}}
    assert_eq!(crate::application_main(&["service-check".into()],&mut NeverRead),Err(crate::StartupRefusal::MissingAuthenticEnrollment));
    assert_eq!(crate::application_main(&["serve-ready".into()],&mut NeverRead),Err(crate::StartupRefusal::MissingAuthenticEnrollment));
}
#[test]
fn ordinary_main_serve_ready_authenticates_one_native_request_with_selected_budget(){
    use crate::treasury_continuity_provider_v1::authenticated_wire::{ClientSession,ClientAction};
    use std::{io::{Read,Write},net::{TcpStream,Shutdown},time::Instant};
    let credential=Credential::from_label("PUBLIC-ordinary-main-serve-k1",1).unwrap();
    let config=CeremonyConfig::rehearsal(mutiny_crypto_v2::NETWORK,
        Treasury::new(Class::TestValue,credential.descriptor().unwrap()).unwrap(),CEREMONY_LABEL).unwrap();
    let admission=directory("main-serve-admission");let id=AdmissionStore::create_native(&admission,&config,local_policy()).unwrap();
    let service_path=directory("main-serve-service");let head=directory("main-serve-head");
    let client=HybridKey::generate(Role::Transport).unwrap();let service=HybridKey::generate(Role::Transport).unwrap();
    let scope=Scope{network:config.network(),genesis:None,ceremony_context:config.context().value(),
        treasury_record:crate::treasury_rehearsal_v3::record_sha256(config.treasury()).unwrap(),
        verifier:[171;32],store:id.store_id(),service:[172;32]};
    let pins=PublicPins::new(scope.clone(),[173;32],client.public().descriptor(1).unwrap(),service.public().descriptor(1).unwrap()).unwrap();
    let socket=std::net::TcpListener::bind("127.0.0.1:0").unwrap();let address=socket.local_addr().unwrap();drop(socket);
    let record=ParsedRecord{administrator:[174;32],pins,client_context:[175;32],service_context:[176;32],store:id.store_id(),
        address,admission,service:service_path,io_budget:Duration::from_secs(10),
        checkpoint:PublicSnapshot::new(scope,[177;32],0,None,vec![]).unwrap()};
    let document=record.encode().unwrap();let current=record.checkpoint.clone();
    let approval=VerifiedApproval{record,document:document.clone(),selection:digest(&document),current};
    let location=protected_head::Location{path:head.clone(),file_cap:32*1024*1024,steps:NonZeroU64::new(4_000_000).unwrap()};
    protected_head::initialize_test_head(&approval,&location).unwrap();
    let native=Service::create_native(approval.service_path(),&config,approval.pins().scope().clone(),service_policy()).unwrap();assert!(native.close().is_ok());
    let custody=service.seal_for(VALUE,1,&approval.record.service_context).unwrap();drop(service);
    let session=ClientSession::prepare(approval.pins(),&client,ClientAction::Current{request_nonce:[178;32],minimum_sequence:0}).unwrap();drop(client);
    let pins=approval.pins().clone();let service_before=fs::read(approval.service_path().join("state.sqlite")).unwrap();
    let child=thread::spawn(move||->Result<(),String>{
        let end=Instant::now()+Duration::from_secs(10);
        let remaining=||end.checked_duration_since(Instant::now()).filter(|d|!d.is_zero()).ok_or("TEST connection/response budget expired".to_owned());
        // TEST startup coordination only: no request is sent until the first
        // connection succeeds. Every other outcome stops; no logical retry.
        let mut stream=loop{match TcpStream::connect_timeout(&address,remaining()?){
            Ok(stream)=>break stream,
            Err(error) if error.kind()==std::io::ErrorKind::ConnectionRefused=>{remaining()?;thread::yield_now();},
            Err(error)=>return Err(error.to_string()),
        }};
        stream.set_write_timeout(Some(remaining()?)).map_err(|e|e.to_string())?;
        stream.write_all(&(session.wire().len() as u32).to_be_bytes()).map_err(|e|e.to_string())?;
        stream.write_all(session.wire()).map_err(|e|e.to_string())?;stream.shutdown(Shutdown::Write).map_err(|e|e.to_string())?;
        stream.set_read_timeout(Some(remaining()?)).map_err(|e|e.to_string())?;
        let mut prefix=[0;4];stream.read_exact(&mut prefix).map_err(|e|e.to_string())?;
        let n=u32::from_be_bytes(prefix) as usize;
        if n==0||n>crate::treasury_native_service_v1::tcp::MAX_RESPONSE_FRAME{return Err("TEST reply bound".into());}
        stream.set_read_timeout(Some(remaining()?)).map_err(|e|e.to_string())?;
        let mut reply=vec![0;n];stream.read_exact(&mut reply).map_err(|e|e.to_string())?;
        stream.set_read_timeout(Some(remaining()?)).map_err(|e|e.to_string())?;
        let mut trailing=[0;1];if stream.read(&mut trailing).map_err(|e|e.to_string())?!=0{return Err("TEST reply trailing bytes".into());}
        remaining()?;let(snapshot,receipt)=session.inspect_response(&pins,&reply,&[]).map_err(|e|format!("{e:?}"))?;
        if snapshot.sequence()!=0||snapshot.pending_operation().is_some()||!snapshot.operations().is_empty()||receipt.is_some(){return Err("TEST wrong authenticated result".into());}
        Ok(())
    });
    let _selection=selected(&approval,&head,&config);
    let result=main_dispatch("serve-ready",&document,&custody);
    let response=child.join();assert!(result.is_ok());assert!(response.is_ok());assert!(response.unwrap().is_ok());
    assert_eq!(fs::read(approval.service_path().join("state.sqlite")).unwrap(),service_before);
}
#[test]
fn shared_entry_exact_consumption_reconciliation_preserves_durable_consumption(){
    use crate::treasury_continuity_v1::{Request,Action,PublicRecord};
    let credential=Credential::from_label("PUBLIC-entry-reconcile-k1",1).unwrap();let descriptor=credential.descriptor().unwrap();
    let config=CeremonyConfig::rehearsal(mutiny_crypto_v2::NETWORK,
        Treasury::new(Class::TestValue,descriptor.clone()).unwrap(),CEREMONY_LABEL).unwrap();
    let admission=directory("reconcile-admission");let id=AdmissionStore::create_native(&admission,&config,local_policy()).unwrap();
    let service_path=directory("reconcile-service");let head=directory("reconcile-head");
    let client=HybridKey::generate(Role::Transport).unwrap();let service=HybridKey::generate(Role::Transport).unwrap();
    let scope=Scope{network:config.network(),genesis:None,ceremony_context:config.context().value(),
        treasury_record:crate::treasury_rehearsal_v3::record_sha256(config.treasury()).unwrap(),
        verifier:[151;32],store:id.store_id(),service:[152;32]};
    let pins=PublicPins::new(scope.clone(),[153;32],client.public().descriptor(1).unwrap(),service.public().descriptor(1).unwrap()).unwrap();
    let socket=std::net::TcpListener::bind("127.0.0.1:0").unwrap();let address=socket.local_addr().unwrap();drop(socket);
    let record=ParsedRecord{administrator:[154;32],pins,client_context:[155;32],service_context:[156;32],store:id.store_id(),
        address,admission,service:service_path,io_budget:Duration::from_secs(10),
        checkpoint:PublicSnapshot::new(scope.clone(),[157;32],0,None,vec![]).unwrap()};
    let document=record.encode().unwrap();let current=record.checkpoint.clone();
    let approval=VerifiedApproval{record,document:document.clone(),selection:digest(&document),current};
    let location=protected_head::Location{path:head.clone(),file_cap:32*1024*1024,steps:NonZeroU64::new(4_000_000).unwrap()};
    protected_head::initialize_test_head(&approval,&location).unwrap();
    let native=Service::create_native(approval.service_path(),&config,scope.clone(),service_policy()).unwrap();assert!(native.close().is_ok());
    let custody=service.seal_for(VALUE,1,&approval.record.service_context).unwrap();drop(service);drop(client);
    let challenge=proof::Challenge::new(&descriptor,proof::Phase::Rehearsal,credential.key().public().address_id(1).unwrap(),
        scope.treasury_record,scope.ceremony_context,[158;32]).unwrap();
    let reserved=PublicRecord{generation:1,nonce:challenge.nonce,challenge:challenge.encode().unwrap(),descriptor:descriptor.clone(),signature:None};
    let signature=proof::sign_challenge(credential.key(),&descriptor,&challenge).unwrap();challenge.verify(&descriptor,&signature).unwrap();
    let mut consumed=reserved.clone();consumed.signature=Some(proof::signature_to_bytes(&signature));
    let reserve=Request{scope:scope.clone(),operation:[159;32],request_nonce:[160;32],expected_sequence:0,action:Action::Reserve(reserved.clone())};
    let confirm=Request{scope:scope.clone(),operation:[161;32],request_nonce:[162;32],expected_sequence:1,
        action:Action::ConfirmLocal{pending_operation:reserve.operation,exact:reserved}};
    let consume=Request{scope:scope.clone(),operation:[163;32],request_nonce:[164;32],expected_sequence:2,action:Action::Consume(consumed)};
    protected_head::apply_test_without_last_publication(&approval,&location,&config,service_policy(),&[reserve,confirm,consume.clone()]).unwrap();
    let service_before=fs::read(approval.service_path().join("state.sqlite")).unwrap();let _selection=selected(&approval,&head,&config);
    assert!(entry::reopen_service(&document,&custody,VALUE,&config,service_policy()).is_err(),"pending durable intent must freeze startup");
    main_dispatch("reconcile-service",&document,&custody).unwrap();
    assert_eq!(fs::read(approval.service_path().join("state.sqlite")).unwrap(),service_before);
    let approved=configured_approval(&document).unwrap();assert_eq!(approved.checkpoint().sequence(),3);
    assert_eq!(approved.checkpoint().pending_operation(),Some(consume.operation));
    assert_eq!(approved.record.checkpoint.sequence(),0);assert_eq!(approved.document,document);
    let last=approved.checkpoint().operations().last().unwrap();assert_eq!(last.operation,consume.operation);assert_eq!(last.action,consume.action);
    main_dispatch("service-check",&document,&custody).unwrap();
    assert_eq!(fs::read(approval.service_path().join("state.sqlite")).unwrap(),service_before);
}
fn directory(label:&str)->PathBuf{
    let root=PathBuf::from(std::env::var_os("BUILD8_NATIVE_SQLITE_FIXTURE_ROOT").expect("mandatory reviewed TEST root"));
    assert!(root.is_absolute());let mut salt=[0;32];mutiny_crypto_v2::fill_os_random(&mut salt).unwrap();
    let path=root.join(format!("entry-{label}-{}",hex::encode(salt)));
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    eprintln!("RETAINED_PUBLIC_NATIVE_ENTRY_TEST={}",path.display());path
}
fn local_policy()->LocalStoragePolicy{LocalStoragePolicy::new(32*1024*1024,NonZeroU64::new(4_000_000).unwrap()).unwrap()}
fn service_policy()->Policy{Policy::new(32*1024*1024,NonZeroU64::new(4_000_000).unwrap()).unwrap()}
fn selected(a:&VerifiedApproval,head:&PathBuf,config:&CeremonyConfig)->application_selection::test_selection::ScopeGuard{
    application_selection::test_selection::install(a,head.clone(),32*1024*1024,NonZeroU64::new(4_000_000).unwrap(),config.clone())
}
fn serve_until(endpoint:&mut OrdinaryService,finished:impl Fn()->bool,done:&mpsc::Receiver<()>){
    let end=std::time::Instant::now()+Duration::from_secs(60);
    loop{
        if done.try_recv().is_ok(){return;}
        assert!(!finished(),"client ended before phase completion");
        assert!(std::time::Instant::now()<end,"finite entry TEST observation expired");
        match endpoint.serve_ready(){Ok(())|Err(TcpError::Idle)=>{},Err(_)=>panic!("ordinary endpoint refused")}
        thread::yield_now();
    }
}
#[test]
fn shared_entry_native_issue_consume_reopen_and_continue_same_identities(){
    thread::scope(|threads|{
    let(public_tx,public_rx)=mpsc::channel();let(ready_tx,ready_rx)=mpsc::channel();
    let(done_tx,done_rx)=mpsc::channel();let(resume_tx,resume_rx)=mpsc::channel();
    let child=threads.spawn(move||{
        let credential=Credential::from_label("PUBLIC-entry-native-k1",1).unwrap();
        let f=fixture_with_treasury(credential.key(),1_200_000);let rig=Rig::new(f,"native-entry");
        let config=CeremonyConfig::rehearsal(mutiny_crypto_v2::NETWORK,
            Treasury::new(Class::TestValue,credential.descriptor().unwrap()).unwrap(),CEREMONY_LABEL).unwrap()
            .with_trusted_chain(TrustedChain{network:rig.parent.network,genesis:rig.parent.genesis,
                fingerprint:rig.parent.fingerprint,height:rig.parent.height}).unwrap();
        let admission=directory("admission");let identity=AdmissionStore::create_native(&admission,&config,local_policy()).unwrap();
        let service_path=directory("service");let head=directory("head");
        let client=HybridKey::generate(Role::Transport).unwrap();let service=HybridKey::generate(Role::Transport).unwrap();
        let scope=Scope{network:config.network(),genesis:Some(rig.parent.genesis),
            ceremony_context:config.context().value(),treasury_record:crate::treasury_rehearsal_v3::record_sha256(config.treasury()).unwrap(),
            verifier:[141;32],store:identity.store_id(),service:[142;32]};
        let pins=PublicPins::new(scope.clone(),[143;32],client.public().descriptor(1).unwrap(),service.public().descriptor(1).unwrap()).unwrap();
        let socket=std::net::TcpListener::bind("127.0.0.1:0").unwrap();let address=socket.local_addr().unwrap();drop(socket);
        let record=ParsedRecord{administrator:[144;32],pins,client_context:[145;32],service_context:[146;32],store:identity.store_id(),
            address,admission,service:service_path,io_budget:Duration::from_secs(10),
            checkpoint:PublicSnapshot::new(scope,[147;32],0,None,vec![]).unwrap()};
        let document=record.encode().unwrap();let current=record.checkpoint.clone();
        let approval=VerifiedApproval{record,document:document.clone(),selection:digest(&document),current};
        let location=protected_head::Location{path:head.clone(),file_cap:32*1024*1024,steps:NonZeroU64::new(4_000_000).unwrap()};
        protected_head::initialize_test_head(&approval,&location).unwrap();
        let native_service=Service::create_native(approval.service_path(),&config,approval.pins().scope().clone(),service_policy()).unwrap();
        assert!(native_service.close().is_ok());
        let sealed_client=client.seal_for(VALUE,1,&approval.record.client_context).unwrap();
        let sealed_service=service.seal_for(VALUE,1,&approval.record.service_context).unwrap();
        drop(client);drop(service);
        public_tx.send((document.clone(),sealed_service,head.clone(),config.clone())).unwrap();
        ready_rx.recv_timeout(Duration::from_secs(60)).unwrap();let _selection=selected(&approval,&head,&config);
        let mut owner=OrdinaryClient::open(&document,Zeroizing::new(sealed_client.clone()),Zeroizing::new(VALUE.into()),&rig.chain,Denylist::default())
            .unwrap_or_else(|_|panic!("ordinary client entry refused"));
        assert!(!owner.frozen());let descriptor=credential.descriptor().unwrap();
        let challenge=owner.issue(&descriptor).unwrap();let signature=proof::sign_challenge(credential.key(),&descriptor,&challenge).unwrap();
        owner.admit(&descriptor,&challenge.encode().unwrap(),&signature).unwrap();assert_eq!(owner.sequence(),4);assert!(owner.close().is_ok());
        let first_state=fs::read(approval.admission_path().join("state.sqlite")).unwrap();
        done_tx.send(()).unwrap();resume_rx.recv_timeout(Duration::from_secs(60)).unwrap();
        let mut owner=OrdinaryClient::open(&document,Zeroizing::new(sealed_client.clone()),Zeroizing::new(VALUE.into()),&rig.chain,Denylist::default())
            .unwrap_or_else(|_|panic!("ordinary client reopen refused"));
        assert!(!owner.frozen());assert_eq!(owner.sequence(),4);
        let next=owner.issue(&descriptor).unwrap();assert_ne!(next.nonce,challenge.nonce);
        let signature=proof::sign_challenge(credential.key(),&descriptor,&next).unwrap();
        owner.admit(&descriptor,&next.encode().unwrap(),&signature).unwrap();assert_eq!(owner.sequence(),8);assert!(owner.close().is_ok());
        done_tx.send(()).unwrap();resume_rx.recv_timeout(Duration::from_secs(60)).unwrap();
        // TEST restoration uses the real filesystem only after both previous
        // native client/service owners closed. No external history is replaced.
        fs::write(approval.admission_path().join("state.sqlite"),first_state).unwrap();
        let mut owner=OrdinaryClient::open(&document,Zeroizing::new(sealed_client),Zeroizing::new(VALUE.into()),&rig.chain,Denylist::default())
            .unwrap_or_else(|_|panic!("ordinary client restore entry refused"));
        assert!(owner.frozen());assert!(owner.issue(&descriptor).is_err());
        owner.reconcile().unwrap();assert!(!owner.frozen());assert_eq!(owner.sequence(),8);
        assert!(owner.admit(&descriptor,&next.encode().unwrap(),&signature).is_err());
        assert!(owner.close().is_ok());done_tx.send(()).unwrap();
    });
    let(document,sealed_service,head,config)=public_rx.recv_timeout(Duration::from_secs(60)).unwrap();
    let record=ParsedRecord::decode(&document).unwrap();let current=record.checkpoint.clone();
    let approval=VerifiedApproval{record,document:document.clone(),selection:digest(&document),current};
    let _selection=selected(&approval,&head,&config);
    main_dispatch("service-check",&document,&sealed_service).unwrap();
    let mut endpoint=OrdinaryService::open(&document,Zeroizing::new(sealed_service.clone()),Zeroizing::new(VALUE.into()))
        .unwrap_or_else(|_|panic!("ordinary service entry refused"));
    ready_tx.send(()).unwrap();serve_until(&mut endpoint,||child.is_finished(),&done_rx);assert!(endpoint.close().is_ok());
    main_dispatch("service-check",&document,&sealed_service).unwrap();
    let mut endpoint=OrdinaryService::open(&document,Zeroizing::new(sealed_service.clone()),Zeroizing::new(VALUE.into()))
        .unwrap_or_else(|_|panic!("ordinary service restart refused"));
    resume_tx.send(()).unwrap();serve_until(&mut endpoint,||child.is_finished(),&done_rx);assert!(endpoint.close().is_ok());
    let mut endpoint=OrdinaryService::open(&document,Zeroizing::new(sealed_service),Zeroizing::new(VALUE.into()))
        .unwrap_or_else(|_|panic!("ordinary service exact-repair entry refused"));
    resume_tx.send(()).unwrap();serve_until(&mut endpoint,||child.is_finished(),&done_rx);child.join().unwrap();assert!(endpoint.close().is_ok());
    });
}
