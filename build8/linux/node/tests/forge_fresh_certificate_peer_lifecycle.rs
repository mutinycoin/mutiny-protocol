//! Isolated TEST integration over existing SDK transport; not a Desktop acceptance test.
use mutinyd_v8::{genesis_artifact_v2::{TrustV2,VerifiedGenesisV2},
    hybrid_runtime_v2::HybridRuntime,hybrid_peer_admission_v2::Registry,
    hybrid_peer_worker_v2::{Worker,Command,Notification},hybrid_dispatch_v2::DispatchEvent};
use mutiny_consensus_v8::{Hash,NETWORK_ID,anchors::FinalizedAnchor,
    genesis_v2::{Approved,GenesisClass},protocol_manifest::RuleManifest,
    canonical_store_v2::CanonicalStore,mempool_v2::{Mempool,MAX_PENDING_BYTES},
    block_envelope_v2::BlockEnvelope};
use mutiny_crypto_v2::{HybridKey,Role};
use mutiny_transport_v2::{Endpoint,objects::{ObjectQueue,ObjectKind},object_link::Event};
use sha2::{Digest,Sha256};
use std::{path::Path,sync::{Arc,Mutex,mpsc::TryRecvError},net::{TcpListener,TcpStream},time::{Duration,Instant}};

fn hash(text:&str)->Hash {hex::decode(text).unwrap().try_into().unwrap()}
fn next(worker:&Worker)->Notification {
    let limit=Instant::now()+Duration::from_secs(120);
    loop {match worker.try_notification(){Ok(value)=>return value,
        Err(TryRecvError::Disconnected)=>panic!("peer notification channel disconnected"),
        Err(TryRecvError::Empty)=>{assert!(Instant::now()<limit,"bounded event wait expired");std::thread::sleep(Duration::from_millis(2));}}}
}
fn submit(worker:&Worker,mut cmd:Command){
    let limit=Instant::now()+Duration::from_secs(5);
    loop {match worker.try_submit(cmd){Ok(())=>return,
        Err(e)if e.reason=="Peer command backpressure"=>{assert!(Instant::now()<limit);cmd=e.command;std::thread::sleep(Duration::from_millis(2));},
        Err(e)=>panic!("peer command refused: {}",e.reason)}}
}
fn runtime(base:&Path,v:&VerifiedGenesisV2,anchor:&FinalizedAnchor)->HybridRuntime{
    let chain=CanonicalStore::open_trusted_genesis(&base.join("chain.sqlite"),anchor,&v.genesis.state,
        v.genesis.root,v.inputs.timestamp,v.inputs.parameters.initial_target).unwrap();
    let pool=Mempool::open(&base.join("pool.sqlite"),anchor.genesis,anchor.fingerprint,MAX_PENDING_BYTES).unwrap();
    let ts=v.inputs.timestamp+1;
    HybridRuntime::from_pinned_chain_with_time_source(chain,pool,Arc::new(move||ts)).unwrap()
}
fn connect(base:&Path,outgoing:&Registry,incoming:&Registry,a:&HybridKey,b:Arc<HybridKey>,
    pa:&Endpoint,pb:&Endpoint,sender_runtime:Arc<Mutex<HybridRuntime>>,receiver_runtime:Arc<Mutex<HybridRuntime>>)->(Worker,Worker){
    let listener=TcpListener::bind("127.0.0.1:0").unwrap();
    assert!(listener.local_addr().unwrap().ip().is_loopback());
    let client=TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let socket=listener.accept().unwrap().0;drop(listener);
    let pending=incoming.begin().unwrap();let peer=pa.id();
    let joining=std::thread::spawn(move||pending.respond(peer,socket,&b,Duration::from_secs(30)).unwrap());
    let client=outgoing.begin().unwrap().initiate(pb.id(),client,a,Duration::from_secs(30)).unwrap();
    let server=joining.join().unwrap();
    let tx=ObjectQueue::open(&base.join("send.sqlite"),client.peer_id()).unwrap();
    let rx=ObjectQueue::open(&base.join("recv.sqlite"),server.peer_id()).unwrap();
    (Worker::start(client,tx,sender_runtime).unwrap(),Worker::start(server,rx,receiver_runtime).unwrap())
}
fn stop(sender:Worker,receiver:Worker,outgoing:&Registry,incoming:&Registry)->Option<String>{
    receiver.shutdown().unwrap();
    // SDK's normal remote-close outcome may be Err; record it rather than suppressing it.
    let remote_close=sender.shutdown().err();
    drop(incoming.begin().expect("incoming admission lease leaked"));
    drop(outgoing.begin().expect("outgoing admission lease leaked"));
    remote_close
}

#[test]
fn fresh_certified_block_crosses_existing_peer_worker_and_reconnects(){
    assert!(!mutiny_transport_v2::PRODUCTION_QUALIFIED);
    let evidence=std::path::PathBuf::from(std::env::var_os("FORGE_FRESH_CERT_EVIDENCE").expect("explicit public evidence path"));
    let artifact=std::fs::read(evidence.join("public-bundle/artifact.json")).unwrap();
    let public=std::fs::read(evidence.join("public-bundle/public-evidence.cbor")).unwrap();
    let trust_bytes=std::fs::read(evidence.join("public-bundle/trust.json")).unwrap();
    assert_eq!(<[u8;32]>::from(Sha256::digest(&artifact)),hash("6b66a1cada32761973d4c468d01ff7989d0243372ba972d6eb651ef62e706ba9"));
    assert_eq!(<[u8;32]>::from(Sha256::digest(&public)),hash("6444bcaad203249a93361adbf4a8b175d0d113ba0c320525b17f818629e5799d"));
    assert_eq!(<[u8;32]>::from(Sha256::digest(&trust_bytes)),hash("f9a73fc15b0054307f8f76b92e6ea502a5328294801773d9a2f84bf5edd9c775"));
    let t:serde_json::Value=serde_json::from_slice(&trust_bytes).unwrap();
    assert_eq!(t["class"],2);assert_eq!(t["production_eligible"],false);
    let pins=TrustV2 {artifact_sha256:Sha256::digest(&artifact).into(),
        genesis_block_hash:hash("d7154dd949ff73e319971910bccc2fe39806b9eb0551b5ed95beb6ebd76a0265"),
        approved:Approved {manifest:RuleManifest::decode(&hex::decode(t["approved_manifest"].as_str().unwrap()).unwrap()).unwrap(),
            class:GenesisClass::TestValue,initial_target:hash(t["initial_target"].as_str().unwrap())}};
    let verified=VerifiedGenesisV2::verify_with_public_evidence(&artifact,&pins,&public).unwrap();
    assert_eq!(verified.genesis.class,GenesisClass::TestValue);
    let wire=std::fs::read(evidence.join("certification/fresh-block-envelope.cbor")).unwrap();
    assert_eq!(<[u8;32]>::from(Sha256::digest(&wire)),hash("5ba5ecaf0a55f254d57f658762a0e32363dcc6700fa4edd0c5952bc8bcabadc7"));
    let block=BlockEnvelope::decode(&wire).unwrap();
    assert_eq!(block.block_hash(),hash("c042a3ae3a543668346d22d46272fff691eb7b7ef58b7d06f059c8c7454070f4"));
    let genesis=FinalizedAnchor {network:NETWORK_ID,genesis:verified.genesis.identity,
        fingerprint:verified.genesis.fingerprint,height:0,block:verified.genesis.block_hash};
    let mut nonce=[0;16];mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let base=std::env::temp_dir().join(format!("forge-fresh-cert-peer-{}",hex::encode(nonce)));
    assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
    for name in ["sender","receiver"]{assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base.join(name)).unwrap());}
    let sender_runtime=Arc::new(Mutex::new(runtime(&base.join("sender"),&verified,&genesis)));
    let receiver_runtime=Arc::new(Mutex::new(runtime(&base.join("receiver"),&verified,&genesis)));
    assert!(sender_runtime.lock().unwrap().install(&wire).unwrap().inserted);
    assert_eq!(receiver_runtime.lock().unwrap().head().unwrap().height,0);
    let a=HybridKey::generate(Role::Transport).unwrap();let b=Arc::new(HybridKey::generate(Role::Transport).unwrap());
    let pa=Endpoint::pinned(a.public().clone(),1).unwrap();let pb=Endpoint::pinned(b.public().clone(),1).unwrap();
    let outgoing=Registry::new(genesis.genesis,genesis.fingerprint,pa.clone(),vec![pb.clone()],1,1).unwrap();
    let incoming=Registry::new(genesis.genesis,genesis.fingerprint,pb.clone(),vec![pa.clone()],1,1).unwrap();
    let(sender,receiver)=connect(&base,&outgoing,&incoming,&a,b.clone(),&pa,&pb,sender_runtime.clone(),receiver_runtime.clone());
    submit(&sender,Command::Enqueue{kind:ObjectKind::CertifiedBlock,bytes:wire.clone()});
    let Notification::Advertised(offer)=next(&sender)else{panic!("certified block advertisement")};
    assert!(matches!(next(&receiver),Notification::Dispatched(DispatchEvent::Transport(Event::Offered(got)))if got==offer));
    assert_eq!(receiver_runtime.lock().unwrap().head().unwrap().height,0,"transport offer grants no finality");
    submit(&receiver,Command::RequestMissing{object:offer.id});
    let Notification::RequestWindow{object,start,count}=next(&receiver)else{panic!("missing fragment request")};
    assert_eq!(object,offer.id);assert_eq!(start,0);
    assert_eq!(usize::from(count),wire.len().div_ceil(mutiny_transport_v2::MAX_PAYLOAD));
    assert!(matches!(next(&receiver),Notification::Dispatched(DispatchEvent::BlockInstalled{result,..})if result.inserted&&result.finalized.height==1&&result.finalized.block==block.block_hash()));
    assert_eq!(receiver_runtime.lock().unwrap().head().unwrap().height,1);
    submit(&receiver,Command::Receipt{object,start,count});
    let close1=stop(sender,receiver,&outgoing,&incoming);
    let(sender,receiver)=connect(&base,&outgoing,&incoming,&a,b.clone(),&pa,&pb,sender_runtime.clone(),receiver_runtime.clone());
    submit(&sender,Command::Advertise{object});
    assert!(matches!(next(&receiver),Notification::Dispatched(DispatchEvent::Transport(Event::Offered(got)))if got.id==object));
    submit(&receiver,Command::RequestMissing{object});
    assert!(matches!(next(&receiver),Notification::NoMissingFragments{object:got}if got==object));
    submit(&receiver,Command::RetryCompleted{object});
    assert!(matches!(next(&receiver),Notification::Dispatched(DispatchEvent::BlockInstalled{result,..})if !result.inserted&&result.finalized.height==1));
    let close2=stop(sender,receiver,&outgoing,&incoming);
    drop(sender_runtime);drop(receiver_runtime);
    let reopened=runtime(&base.join("receiver"),&verified,&genesis);
    assert_eq!(reopened.head().unwrap().height,1);assert_eq!(reopened.head().unwrap().block,block.block_hash());
    let output=std::path::PathBuf::from(std::env::var_os("FORGE_PEER_LIFECYCLE_RESULT").unwrap());
    let result=serde_json::json!({"schema":"FORGE-FRESH-CERTIFICATE-SDK-PEER-LIFECYCLE-V1","height":1,
        "block_hash":hex::encode(block.block_hash()),"genesis_block_hash":hex::encode(genesis.block),
        "authenticated_connections":2,"loopback_only":true,"durable_completed_object_reused":true,
        "reconnect_duplicate_install":false,"runtime_reopen_passed":true,"admission_leases_released":true,
        "remote_close_results":[close1,close2],"state_directory":base.display().to_string(),
        "transport_private_keys_persisted":false,"production_eligible":false,"rf_activated":false,
        "desktop_compatibility_verified":false,"certifier":"fresh prior bounded fixture; its private keys already discarded"});
    use std::io::Write;let mut file=std::fs::OpenOptions::new().write(true).create_new(true).open(output).unwrap();
    file.write_all(&serde_json::to_vec_pretty(&result).unwrap()).unwrap();file.sync_all().unwrap();
    println!("FORGE SDK PEER LIFECYCLE RESULT: {result}");
}
