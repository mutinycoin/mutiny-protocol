//! SOURCE ONLY / UNRUN. Real native Service/Admission owners and loopback IO.
//! Synthetic keys never leave RAM. A modeled TEST Provider is not enrollment.
use super::*;
use crate::{treasury_admission_v3::{AdmissionStore,StoreIdentity,LocalStoragePolicy},
    treasury_continuity_owner_v1::{Owner as AdmissionOwner,Error as OwnerError},
    treasury_continuity_v1::{Action,PublicRecord},
    treasury_rehearsal_v3::{CeremonyConfig,Expect,Denylist,Refusal}};
use mutiny_crypto_v2::{Role,rehearsal_keys_v1::Credential,treasury_proof_v1 as proof};
use std::{fs,path::PathBuf,num::NonZeroU64,thread,sync::mpsc,
    os::unix::fs::DirBuilderExt};
fn directory(label:&str)->PathBuf{
    let root=PathBuf::from(std::env::var_os("BUILD8_NATIVE_SQLITE_FIXTURE_ROOT")
        .expect("mandatory protected native TEST root"));
    assert!(root.is_absolute());let mut salt=[0;32];mutiny_crypto_v2::fill_os_random(&mut salt).unwrap();
    let dir=root.join(format!("native-service-tcp-{label}-{}",hex::encode(salt)));
    fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
    eprintln!("RETAINED_PUBLIC_NATIVE_SERVICE_TCP={}",dir.display());dir
}
fn local_policy()->LocalStoragePolicy{
    LocalStoragePolicy::new(32*1024*1024,NonZeroU64::new(4_000_000).unwrap()).unwrap()
}
fn service_policy()->Policy{Policy::new(32*1024*1024,NonZeroU64::new(4_000_000).unwrap()).unwrap()}
fn limits()->IoLimits{IoLimits::new(Duration::from_secs(10)).unwrap()}
struct Fixture{label:&'static str,config:CeremonyConfig,admission:PathBuf,service:PathBuf,
    id:StoreIdentity,pins:PublicPins,client:Option<HybridKey>,client_encrypted:Vec<u8>,server_encrypted:Vec<u8>,server:SerializedEndpoint}
fn fixture(label:&'static str)->Fixture{
    let key=Credential::from_label(label,1).unwrap();
    let config=CeremonyConfig::rehearsal(mutiny_crypto_v2::NETWORK,
        crate::treasury_v1::Treasury::new(crate::treasury_v1::Class::TestValue,key.descriptor().unwrap()).unwrap(),label).unwrap();
    let admission=directory("admission");let service=directory("service");
    let id=AdmissionStore::create_native(&admission,&config,local_policy()).unwrap();
    let scope=Scope{network:config.network(),genesis:None,ceremony_context:config.context().value(),
        treasury_record:crate::treasury_rehearsal_v3::record_sha256(config.treasury()).unwrap(),
        verifier:[111;32],store:id.store_id(),service:[112;32]};
    let client=HybridKey::generate(Role::Transport).unwrap();let server_key=HybridKey::generate(Role::Transport).unwrap();
    let pins=PublicPins::new(scope,[113;32],client.public().descriptor(1).unwrap(),
        server_key.public().descriptor(1).unwrap()).unwrap();
    let client_encrypted=client.seal_for("PUBLIC NATIVE TCP TEST ONLY",1,&[119;32]).unwrap();
    let server_encrypted=server_key.seal_for("PUBLIC NATIVE TCP TEST ONLY",1,&[119;32]).unwrap();
    let server=SerializedEndpoint::create_testvalue("127.0.0.1:0".parse().unwrap(),&config,
        &service,pins.clone(),server_key,service_policy(),limits()).unwrap();
    Fixture{label,config,admission,service,id,pins,client:Some(client),client_encrypted,server_encrypted,server}
}
fn client_owner(dir:PathBuf,id:StoreIdentity,config:CeremonyConfig,pins:PublicPins,
    key:HybridKey,address:SocketAddr)->AdmissionOwner<TestProvider>{
    let provider=test_provider(pins.clone(),key,address,limits()).unwrap();
    let store=AdmissionStore::open_native(&dir,&config,id,local_policy()).unwrap();
    AdmissionOwner::new(store,provider,pins.scope().clone(),Expect::genesis_key(&config),
        vec![],Denylist::default()).unwrap()
}
// The Service/held VFS stays on this thread. Every spawned client is joined,
// even if the server reports a refused request; no early panic abandons a peer.
fn drive<R:Send+'static>(server:&mut SerializedEndpoint,client:thread::JoinHandle<R>,
    mut observe:impl FnMut(&mut SerializedEndpoint,Option<Error>))->(R,Vec<Error>){
    let mut errors=Vec::new();
    while !client.is_finished(){
        observe(server,None);
        match server.serve_ready(){
            Ok(())=>{},Err(Error::Idle)=>thread::yield_now(),
            Err(e)=>{errors.push(e);observe(server,Some(e));},
        }
    }
    let result=client.join().expect("owned TEST client failed; retained fixtures");
    (result,errors)
}
fn head(server:&SerializedEndpoint)->PublicSnapshot{
    server.endpoint.service.current([114;32]).unwrap()
}
#[test]
fn native_endpoint_tcp_both_proof_finalizes_then_exact_service_and_admission_reopen(){
    let mut f=fixture("PUBLIC-native-tcp-terminal");
    let client=f.client.take().unwrap();let pins=f.pins.clone();let config=f.config.clone();
    let dir=f.admission.clone();let id=f.id;let address=f.server.local_addr().unwrap();let label=f.label;
    let child=thread::spawn(move||{
        let credential=Credential::from_label(label,1).unwrap();let descriptor=credential.descriptor().unwrap();
        let mut owner=client_owner(dir.clone(),id,config,pins,client,address);assert!(!owner.frozen());
        let challenge=owner.issue(&descriptor).unwrap();let raw=challenge.encode().unwrap();
        let signature=proof::sign_challenge(credential.key(),&descriptor,&challenge).unwrap();
        let before=fs::read(dir.join("state.sqlite")).unwrap();
        for half in 0..2{
            let mut invalid=signature.clone();if half==0{invalid.ed448[0]^=1}else{invalid.fndsa[0]^=1}
            assert!(owner.admit(&descriptor,&raw,&invalid).is_err());assert!(!owner.frozen());
            assert_eq!(owner.sequence(),2);assert_eq!(fs::read(dir.join("state.sqlite")).unwrap(),before);
        }
        owner.admit(&descriptor,&raw,&signature).unwrap();assert_eq!(owner.sequence(),4);
        assert_eq!(owner.admit(&descriptor,&raw,&signature),Err(OwnerError::Native(Refusal::Replay)));
        drop(owner); // Existing ordinary Owner has no explicit close API.
    });
    let(_,errors)=drive(&mut f.server,child,|_,_|{});assert!(errors.is_empty(),"server refusal observed");
    let pinned=head(&f.server);assert_eq!(pinned.sequence(),4);assert_eq!(pinned.pending_operation(),None);
    let service_db=fs::read(f.service.join("state.sqlite")).unwrap();
    assert!(f.server.close().is_ok(),"explicit native service close failed");
    let(key,g)=HybridKey::open_for(Role::Transport,"PUBLIC NATIVE TCP TEST ONLY",&[119;32],&f.client_encrypted).unwrap();assert_eq!(g,1);
    let(server_key,g)=HybridKey::open_for(Role::Transport,"PUBLIC NATIVE TCP TEST ONLY",&[119;32],&f.server_encrypted).unwrap();assert_eq!(g,1);
    let pins=f.pins.clone();
    assert_eq!(key.public().descriptor(1).unwrap(),pins.client_descriptor());
    assert_eq!(server_key.public().descriptor(1).unwrap(),pins.service_descriptor());
    // Exact selected transport keys/context survive restart via normal TEST
    // role/context custody envelopes retained only in RAM, never public files.
    let mut reopened=SerializedEndpoint::reopen_testvalue("127.0.0.1:0".parse().unwrap(),&f.config,
        &f.service,pins.clone(),server_key,service_policy(),&pinned,limits()).unwrap();
    let dir=f.admission;let config=f.config;let id=f.id;let label=f.label;let address=reopened.local_addr().unwrap();
    let child=thread::spawn(move||{
        let mut owner=client_owner(dir,id,config,pins,key,address);
        assert!(!owner.frozen());assert_eq!(owner.sequence(),4);
        let descriptor=Credential::from_label(label,1).unwrap().descriptor().unwrap();
        owner.issue(&descriptor).unwrap();assert_eq!(owner.sequence(),6);assert!(!owner.frozen());
    });
    let(_,errors)=drive(&mut reopened,child,|_,_|{});assert!(errors.is_empty());
    let after=head(&reopened);assert_eq!(after.sequence(),6);assert_eq!(&after.operations()[..4],pinned.operations());
    assert_ne!(fs::read(f.service.join("state.sqlite")).unwrap(),service_db);
    assert!(reopened.close().is_ok());
}
#[test]
fn native_endpoint_tcp_lost_reserve_and_consume_ack_keep_durable_record_and_freeze_both(){
    for consume in [false,true]{
        let mut f=fixture(if consume{"PUBLIC-native-tcp-unknown-consume"}else{"PUBLIC-native-tcp-unknown-reserve"});
        if !consume{f.server.endpoint.service.fault=Some(super::super::Fault::AfterCommit);}
        let client=f.client.take().unwrap();let pins=f.pins.clone();let config=f.config.clone();
        let dir=f.admission.clone();let id=f.id;let address=f.server.local_addr().unwrap();let label=f.label;
        let(arm_tx,arm_rx)=mpsc::channel::<()>();let(armed_tx,armed_rx)=mpsc::channel::<()>();
        let(record_tx,record_rx)=mpsc::channel::<PublicRecord>();
        let child=thread::spawn(move||{
            let key=Credential::from_label(label,1).unwrap();let descriptor=key.descriptor().unwrap();
            let mut owner=client_owner(dir.clone(),id,config,pins,client,address);assert!(!owner.frozen());
            let(before,raw,signature)=if consume{
                let challenge=owner.issue(&descriptor).unwrap();let raw=challenge.encode().unwrap();
                let signature=proof::sign_challenge(key.key(),&descriptor,&challenge).unwrap();
                let before=fs::read(dir.join("state.sqlite")).unwrap();
                arm_tx.send(()).unwrap();armed_rx.recv().unwrap();
                assert_eq!(owner.admit(&descriptor,&raw,&signature),Err(OwnerError::Provider(ProviderError::Unknown)));
                (before,raw,signature)
            }else{
                let before=fs::read(dir.join("state.sqlite")).unwrap();
                assert_eq!(owner.issue(&descriptor),Err(OwnerError::Provider(ProviderError::Unknown)));
                let record=record_rx.recv().unwrap();let challenge=proof::Challenge::decode(&record.challenge).unwrap();
                let signature=proof::sign_challenge(key.key(),&descriptor,&challenge).unwrap();
                (before,record.challenge,signature)
            };
            assert!(owner.frozen());assert_eq!(fs::read(dir.join("state.sqlite")).unwrap(),before);
            assert_eq!(owner.issue(&descriptor),Err(OwnerError::Frozen));
            assert_eq!(owner.admit(&descriptor,&raw,&signature),Err(OwnerError::Frozen));
            // The external endpoint deliberately remains frozen after Unknown.
            // Client reconciliation cannot bypass that owner's sticky latch.
            assert_eq!(owner.reconcile(),Err(OwnerError::Provider(ProviderError::Unknown)));
            assert!(owner.frozen());assert_eq!(fs::read(dir.join("state.sqlite")).unwrap(),before);
            drop(owner);(raw,signature)
        });
        let mut armed=false;let mut observed=false;
        let((raw,signature),errors)=drive(&mut f.server,child,|server,error|{
            if consume && !armed && matches!(arm_rx.try_recv(),Ok(())){
                assert_eq!(head(server).sequence(),2);
                server.endpoint.service.fault=Some(super::super::Fault::AfterCommit);
                armed_tx.send(()).unwrap();armed=true;
            }
            if error==Some(Error::Unknown) && !observed{
                let current=head(server);assert_eq!(current.sequence(),if consume{3}else{1});
                assert!(current.pending_operation().is_some());
                if !consume{
                    let record=match &current.operations()[0].action{Action::Reserve(r)=>r.clone(),_=>panic!("real Reserve required")};
                    record_tx.send(record).unwrap();
                }
                observed=true;
            }
        });
        assert!(observed);assert_eq!(errors,[Error::Unknown,Error::Unknown]);
        assert!(f.server.endpoint.frozen);
        let pending=head(&f.server);assert_eq!(pending.sequence(),if consume{3}else{1});
        assert!(pending.pending_operation().is_some());
        let retained=fs::read(f.service.join("state.sqlite")).unwrap();
        assert!(f.server.close().is_ok());
        // This component's separately selected TEST administrator records the
        // exact retained head, then closes/reopens the same service/key/store.
        // This is native restart evidence, not a real administrative deployment
        // or a claim that the database authenticates its own latestness.
        let(server,g)=HybridKey::open_for(Role::Transport,"PUBLIC NATIVE TCP TEST ONLY",&[119;32],&f.server_encrypted).unwrap();assert_eq!(g,1);
        let(client,g)=HybridKey::open_for(Role::Transport,"PUBLIC NATIVE TCP TEST ONLY",&[119;32],&f.client_encrypted).unwrap();assert_eq!(g,1);
        let mut reopened=SerializedEndpoint::reopen_testvalue("127.0.0.1:0".parse().unwrap(),&f.config,
            &f.service,f.pins.clone(),server,service_policy(),&pending,limits()).unwrap();
        assert_eq!(fs::read(f.service.join("state.sqlite")).unwrap(),retained);
        let address=reopened.local_addr().unwrap();let dir=f.admission;let config=f.config.clone();let pins=f.pins.clone();let id=f.id;let label=f.label;
        let child=thread::spawn(move||{
            let descriptor=Credential::from_label(label,1).unwrap().descriptor().unwrap();
            let mut owner=client_owner(dir,id,config,pins,client,address);assert!(owner.frozen());
            owner.reconcile().unwrap();assert!(!owner.frozen());
            if !consume{assert_eq!(owner.sequence(),2);owner.admit(&descriptor,&raw,&signature).unwrap();}
            assert_eq!(owner.sequence(),4);
            assert_eq!(owner.admit(&descriptor,&raw,&signature),Err(OwnerError::Native(Refusal::Replay)));
        });
        let(_,errors)=drive(&mut reopened,child,|_,_|{});assert!(errors.is_empty());
        let pinned=head(&reopened);assert_eq!(pinned.sequence(),4);assert_eq!(pinned.pending_operation(),None);
        assert_eq!(&pinned.operations()[..pending.operations().len()],pending.operations());
        assert!(reopened.close().is_ok());
        let audited=Service::open_native(&f.service,&f.config,f.pins.scope().clone(),service_policy(),&pinned,false).unwrap();
        assert_eq!(audited.current([116;32]).unwrap().operations(),pinned.operations());assert!(audited.close().is_ok());
    }
}

#[test]
fn native_endpoint_tcp_wrong_selected_context_and_overlength_prefix_do_not_mutate_service(){
    let mut f=fixture("PUBLIC-native-tcp-wrong-context");let before=fs::read(f.service.join("state.sqlite")).unwrap();
    let key=f.client.take().unwrap();let pins=f.pins.clone();let address=f.server.local_addr().unwrap();
    let child=thread::spawn(move||{
        let bad=PublicPins::new(pins.scope().clone(),[117;32],pins.client_descriptor().to_vec(),pins.service_descriptor().to_vec()).unwrap();
        let session=ClientSession::prepare(&bad,&key,ClientAction::Current{request_nonce:[118;32],minimum_sequence:0}).unwrap();
        let mut transport=TcpExchange::new(address,limits()).unwrap();assert!(matches!(transport.exchange(session.wire()),Err(Error::Unknown)));
        let mut socket=TcpStream::connect_timeout(&address,Duration::from_secs(10)).unwrap();
        socket.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
        socket.write_all(&u32::try_from(MAX_REQUEST_FRAME+1).unwrap().to_be_bytes()).unwrap();
        socket.shutdown(Shutdown::Write).unwrap();socket.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut b=[0;1];assert_eq!(socket.read(&mut b).unwrap(),0);
    });
    let(_,errors)=drive(&mut f.server,child,|_,_|{});assert_eq!(errors,[Error::Endpoint,Error::Invalid]);
    assert_eq!(head(&f.server).sequence(),0);assert_eq!(fs::read(f.service.join("state.sqlite")).unwrap(),before);
    assert!(f.server.close().is_ok());
}

#[path="native_service_canonical_tcp_controls.rs"] mod canonical;


// Native concurrency coverage only. The protected administrator selection and
// TEST keys remain modeled; both clients are fully queued before the ordinary
// same-thread server accepts either request. No deadline is changed.
#[test]
fn native_endpoint_tcp_concurrent_consumption_serializes_identical_and_conflicting_operations(){
    for conflicting in [false,true]{
        let mut f=fixture(if conflicting{"PUBLIC-native-tcp-concurrent-conflict"}
            else{"PUBLIC-native-tcp-concurrent-identical"});
        let client=f.client.take().unwrap();let pins=f.pins.clone();let config=f.config.clone();
        let dir=f.admission.clone();let id=f.id;let address=f.server.local_addr().unwrap();let label=f.label;
        let initial=thread::spawn(move||{
            let credential=Credential::from_label(label,1).unwrap();let descriptor=credential.descriptor().unwrap();
            let mut owner=client_owner(dir.clone(),id,config.clone(),pins,client,address);
            let challenge=owner.issue(&descriptor).unwrap();let raw=challenge.encode().unwrap();
            let signature=proof::sign_challenge(credential.key(),&descriptor,&challenge).unwrap();
            drop(owner);
            let store=AdmissionStore::open_native(&dir,&config,id,local_policy()).unwrap();
            crate::treasury_rehearsal_v3::verify_proof(&store,&Expect::genesis_key(&config),
                &descriptor,&raw,&signature,&Denylist::default()).unwrap();
            drop(store);
            PublicRecord{generation:1,nonce:challenge.nonce,challenge:raw,descriptor,
                signature:Some(proof::signature_to_bytes(&signature))}
        });
        let(record,errors)=drive(&mut f.server,initial,|_,_|{});assert!(errors.is_empty());
        let before=head(&f.server);assert_eq!(before.sequence(),2);assert_eq!(before.pending_operation(),None);
        let local_before=fs::read(f.admission.join("state.sqlite")).unwrap();
        let(key,g)=HybridKey::open_for(Role::Transport,"PUBLIC NATIVE TCP TEST ONLY",&[119;32],&f.client_encrypted).unwrap();
        assert_eq!(g,1);assert_eq!(key.public().descriptor(g).unwrap(),f.pins.client_descriptor());
        let mut sessions=Vec::new();
        for i in 0..2{
            let operation=if conflicting&&i==1{[182;32]}else{[181;32]};
            let request=crate::treasury_continuity_v1::Request{scope:f.pins.scope().clone(),operation,
                request_nonce:[183+i as u8;32],expected_sequence:2,action:Action::Consume(record.clone())};
            sessions.push(ClientSession::prepare(&f.pins,&key,ClientAction::Transition(request)).unwrap());
        }
        drop(key);
        let(ready_tx,ready_rx)=mpsc::channel();let mut clients=Vec::new();
        for session in sessions{
            let ready=ready_tx.clone();let pins=f.pins.clone();let history=before.operations().to_vec();
            clients.push(thread::spawn(move||->Result<_,Error>{
                let deadline=Deadline::start(limits())?;
                let mut stream=std::net::TcpStream::connect_timeout(&address,deadline.remaining()?).map_err(|_|Error::Unknown)?;
                frame(&mut stream,&deadline,session.wire(),MAX_REQUEST_FRAME)?;
                stream.shutdown(std::net::Shutdown::Write).map_err(|_|Error::Unknown)?;
                ready.send(()).map_err(|_|Error::Unknown)?;
                let response=read_frame(&mut stream,&deadline,MAX_RESPONSE_FRAME)?;
                exact_eof(&mut stream,&deadline)?;
                session.inspect_response(&pins,&response,&history).map_err(Error::Authentication)
            }));
        }
        drop(ready_tx);
        // Preserve every owned join even if readiness or a request refuses.
        let queued=[ready_rx.recv_timeout(limits().exchange),ready_rx.recv_timeout(limits().exchange)];
        let mut refusals=Vec::new();
        while clients.iter().any(|child|!child.is_finished()){
            match f.server.serve_ready(){Ok(())=>{},Err(Error::Idle)=>thread::yield_now(),Err(e)=>refusals.push(e)}
        }
        let outcomes:Vec<_>=clients.into_iter().map(|child|child.join()).collect();
        assert!(queued.iter().all(Result::is_ok),"both complete requests must be queued before acceptance");
        assert!(outcomes.iter().all(Result::is_ok),"all native clients joined");
        let outcomes:Vec<_>=outcomes.into_iter().map(Result::unwrap).collect();
        let successes:Vec<_>=outcomes.iter().filter_map(|r|r.as_ref().ok()).collect();
        assert_eq!(successes.len(),if conflicting{1}else{2});
        assert_eq!(refusals.len(),if conflicting{1}else{0});
        for(snapshot,receipt) in successes{
            assert_eq!(snapshot.sequence(),3);let receipt=receipt.as_ref().unwrap();
            assert_eq!(receipt.outcome,crate::treasury_continuity_v1::Outcome::Consumed);
            assert_eq!(receipt.operation_sequence,3);assert_eq!(receipt.sequence,3);
        }
        let consumed=head(&f.server);assert_eq!(consumed.sequence(),3);
        assert_eq!(consumed.operations()[..2],before.operations()[..]);
        assert_eq!(consumed.operations().iter().filter(|entry|matches!(entry.action,Action::Consume(_))).count(),1);
        assert_eq!(fs::read(f.admission.join("state.sqlite")).unwrap(),local_before,
            "direct service concurrency never reports a local admission");
        assert_eq!(f.server.endpoint.frozen,conflicting);
        let service_before=fs::read(f.service.join("state.sqlite")).unwrap();
        assert!(f.server.close().is_ok());
        let(server_key,g)=HybridKey::open_for(Role::Transport,"PUBLIC NATIVE TCP TEST ONLY",&[119;32],&f.server_encrypted).unwrap();assert_eq!(g,1);
        // Independent current-head selection is a TEST premise, not production enrollment.
        let reopened=SerializedEndpoint::reopen_testvalue("127.0.0.1:0".parse().unwrap(),&f.config,
            &f.service,f.pins,server_key,service_policy(),&consumed,limits()).unwrap();
        assert_eq!(head(&reopened).operations(),consumed.operations());
        assert_eq!(fs::read(f.service.join("state.sqlite")).unwrap(),service_before);
        assert!(reopened.close().is_ok());
    }
}
