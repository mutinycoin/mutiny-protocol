//! Finite live TEST certifier + existing SDK responder, with a canonical test client.
//! All newly generated signing/transport keys remain in memory for this test scope.
#[path="forge_live_fixture/fixture.rs"]
mod fixture;
#[path="forge_live_fixture/support/x509_syntax.rs"]
mod x509_syntax;
use mutinyd_v8::{genesis_artifact_v2::{TrustV2,VerifiedGenesisV2,freeze_with_public_evidence},
    hybrid_runtime_v2::HybridRuntime,hybrid_peer_admission_v2::Registry,
    hybrid_peer_worker_v2::{Worker,Command,Notification},hybrid_dispatch_v2::DispatchEvent};
use mutiny_consensus_v8::{Hash,genesis_v2::{Inputs,Constructed,Approved,GenesisClass},
    anchors::FinalizedAnchor,canonical_store_v2::{CanonicalStore,Preparation},mempool_v2::{Mempool,MAX_PENDING_BYTES},
    voter_actor_v2::{VoterActor,Proposal},continuity_v2::Certificate,block_envelope_v2::BlockEnvelope,
    pow::{WorkAuthority,WorkHeader},work_authority_v2::Authority,bft::Step};
use mutiny_crypto_v2::{HybridKey,HybridSignature,Role,Domain};
use mutiny_transport_v2::{Endpoint,objects::{ObjectQueue,ObjectKind},object_link::Event};
use sha2::{Digest,Sha256};
use std::{path::{Path,PathBuf},sync::{Arc,Mutex,atomic::{AtomicU64,Ordering},mpsc::TryRecvError},
    net::{TcpListener,TcpStream},time::{Duration,Instant},io::Write};

fn zero()->HybridSignature{HybridSignature{ed448:[0;114],fndsa:[0;1280]}}
struct EphemeralBackend<'a>{continuity:&'a HybridKey,node:&'a HybridKey,counter:u64,path:PathBuf,calls:u64,work_calls:u64}
impl mutiny_consensus_v8::counter_store::MonotonicCounter for EphemeralBackend<'_>{
    fn read(&mut self)->Result<u64,String>{Ok(self.counter)}
    fn increment(&mut self)->Result<(),String>{self.counter=self.counter.checked_add(1).ok_or("TEST counter exhausted")?;Ok(())}
}
impl mutiny_consensus_v8::counter_voter_v2::CounterSigningBackend for EphemeralBackend<'_>{
    fn public_key(&self)->&mutiny_crypto_v2::PublicKey{self.continuity.public()}
    fn sign_vote(&mut self,message:&[u8])->Result<HybridSignature,String>{
        let db=rusqlite::Connection::open(&self.path).map_err(|e|e.to_string())?;
        let(tip,snapshot,pending):(Vec<u8>,Vec<u8>,Option<Vec<u8>>)=db.query_row(
            "SELECT tip,snapshot,pending_snapshot FROM voter_migration",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|e|e.to_string())?;
        if tip!=self.counter.to_be_bytes()||pending.is_some()||!snapshot.windows(message.len()).any(|w|w==message){return Err("exact durable TEST reservation missing".into())}
        self.calls+=1;self.continuity.sign(Domain::ContinuityVote,message).map_err(|e|format!("{e:?}"))
    }
}
fn public_file(path:&Path,bytes:&[u8]){
    let mut f=std::fs::OpenOptions::new().write(true).create_new(true).open(path).unwrap();f.write_all(bytes).unwrap();f.sync_all().unwrap();
}
fn runtime(path:&Path,v:&VerifiedGenesisV2,clock:Arc<AtomicU64>)->HybridRuntime{
    let chain=CanonicalStore::open_trusted_genesis(&path.join("chain.sqlite"),&v.genesis.anchor(),&v.genesis.state,
        v.genesis.root,v.inputs.timestamp,v.inputs.parameters.initial_target).unwrap();
    let pool=Mempool::open(&path.join("pool.sqlite"),v.genesis.identity,v.genesis.fingerprint,MAX_PENDING_BYTES).unwrap();
    HybridRuntime::from_pinned_chain_with_time_source(chain,pool,Arc::new(move||clock.load(Ordering::SeqCst))).unwrap()
}
fn submit(w:&Worker,mut c:Command){let limit=Instant::now()+Duration::from_secs(5);loop{match w.try_submit(c){
    Ok(())=>return,Err(e)if e.reason=="Peer command backpressure"=>{assert!(Instant::now()<limit);c=e.command;std::thread::sleep(Duration::from_millis(2));},Err(e)=>panic!("{}",e.reason)}}}
fn next(w:&Worker,session_deadline:Instant)->Notification{let limit=(Instant::now()+Duration::from_secs(120)).min(session_deadline);loop{match w.try_notification(){
    Ok(v)=>return v,Err(TryRecvError::Disconnected)=>panic!("canonical peer disconnected"),Err(TryRecvError::Empty)=>{assert!(Instant::now()<limit,"finite live session wait expired");std::thread::sleep(Duration::from_millis(2));}}}}
fn connect(path:&Path,outgoing:&Registry,incoming:&Registry,client_key:&HybridKey,host_key:Arc<HybridKey>,
    client_pin:&Endpoint,host_pin:&Endpoint,host_runtime:Arc<Mutex<HybridRuntime>>,client_runtime:Arc<Mutex<HybridRuntime>>)->(Worker,Worker){
    let listener=TcpListener::bind("127.0.0.1:0").unwrap();assert!(listener.local_addr().unwrap().ip().is_loopback());
    let stream=TcpStream::connect(listener.local_addr().unwrap()).unwrap();let socket=listener.accept().unwrap().0;drop(listener);
    let pending=incoming.begin().unwrap();let client_id=client_pin.id();
    let joined=std::thread::spawn(move||pending.respond(client_id,socket,&host_key,Duration::from_secs(30)).unwrap());
    let client=outgoing.begin().unwrap().initiate(host_pin.id(),stream,client_key,Duration::from_secs(30)).unwrap();
    let host=joined.join().unwrap();
    let host_queue=ObjectQueue::open(&path.join("host-queue.sqlite"),host.peer_id()).unwrap();
    let client_queue=ObjectQueue::open(&path.join("client-queue.sqlite"),client.peer_id()).unwrap();
    (Worker::start(host,host_queue,host_runtime).unwrap(),Worker::start(client,client_queue,client_runtime).unwrap())
}
fn stop(host:Worker,client:Worker,outgoing:&Registry,incoming:&Registry)->Option<String>{
    client.shutdown().unwrap();let remote_close=host.shutdown().err();
    drop(outgoing.begin().expect("client lease leaked"));drop(incoming.begin().expect("host lease leaked"));remote_close
}
fn certify(inputs:&Inputs,constructed:&Constructed,enrollment:&mutiny_consensus_v8::genesis_v2::Enrollment,
    chain:&mut CanonicalStore,pool:&mut Mempool,actor:&mut VoterActor,backend:&mut EphemeralBackend<'_>,height:u64)->BlockEnvelope{
    let tip=chain.load().unwrap().0;let parent=FinalizedAnchor{height:tip.height,block:tip.block,..constructed.anchor()};
    assert_eq!(tip.height+1,height);chain.reconcile_pool(pool).unwrap();
    let assignment=&enrollment.supervised[0];let timestamp=inputs.timestamp+height;
    let(ctx,descriptor)=chain.current_work_context(&parent,assignment.license,assignment.worker_id,timestamp).unwrap();
    let ticket=ctx.last_accepted_ticket+1;
    let prepared=chain.prepare_pending(Preparation{expected_parent:&parent,pool,license:assignment.license,worker:assignment.worker_id,timestamp,ticket,operations:&[]}).unwrap();
    let mut work=Authority{work:WorkAuthority{candidate:prepared.candidate.clone(),assignment_sequence:ctx.assignment_sequence,
        ticket_sequence:ticket,coordinator:ctx.coordinator,nonce_start:0,nonce_end:1023,
        epoch:mutiny_consensus_v8::pow::mining_epoch(timestamp,ctx.t0).unwrap()},node_descriptor:descriptor,signature:zero()};
    // Existing TEST Authority API only: no installed NodeWork issuer or production custody is asserted.
    work.sign(backend.node).unwrap();backend.work_calls+=1;
    let mut header=WorkHeader{candidate:prepared.candidate,authority:work.id().unwrap(),nonce:0};
    while !mutiny_consensus_v8::pow::meets_target(&header.digest(),&header.candidate.target){header.nonce=header.next_nonce(work.work.nonce_end).expect("bounded TEST work exhausted")}
    let block=header.block_hash();actor.validate_candidate(chain,Proposal{header:&header,body:&prepared.body,authority:&work}).unwrap();
    let clock=mutiny_consensus_v8::vote_clock_v1::ControlledClock::at(timestamp);
    let prevote=actor.sign_with_clock(chain,Step::Prevote,Some(block),None,backend,clock.clone()).unwrap();assert!(!prevote.nil);actor.observe(chain,&prevote,backend).unwrap();
    let precommit=actor.sign_with_clock(chain,Step::Precommit,Some(block),None,backend,clock).unwrap();assert!(!precommit.nil);actor.observe(chain,&precommit,backend).unwrap();
    let authority=chain.current_authority(&parent).unwrap();
    let certificate=Certificate{decision:precommit.decision.clone(),votes:vec![precommit.clone()]};
    certificate.verify_quorum(&precommit.decision,&authority.parent,&authority.voters).unwrap();
    let envelope=BlockEnvelope{header,body:prepared.body,authority:work,certificate};
    assert!(chain.commit(&envelope).unwrap());actor.reconcile(chain,backend).unwrap();assert_eq!(actor.height(),height+1);envelope
}
fn deliver(host:&Worker,client:&Worker,client_runtime:&Mutex<HybridRuntime>,block:&BlockEnvelope,deadline:Instant){
    let before=client_runtime.lock().unwrap().head().unwrap().height;
    let bytes=block.encode().unwrap();submit(host,Command::Enqueue{kind:ObjectKind::CertifiedBlock,bytes:bytes.clone()});
    let Notification::Advertised(offer)=next(host,deadline)else{panic!("live host did not advertise")};
    assert!(matches!(next(client,deadline),Notification::Dispatched(DispatchEvent::Transport(Event::Offered(got)))if got==offer));
    assert_eq!(client_runtime.lock().unwrap().head().unwrap().height,before,"offer grants no finality");
    submit(client,Command::RequestMissing{object:offer.id});
    let Notification::RequestWindow{object,start,count}=next(client,deadline)else{panic!("canonical client fragment request")};
    assert_eq!(object,offer.id);assert_eq!(start,0);assert_eq!(usize::from(count),bytes.len().div_ceil(mutiny_transport_v2::MAX_PAYLOAD));
    assert!(matches!(next(client,deadline),Notification::Dispatched(DispatchEvent::BlockInstalled{result,..})if result.inserted&&result.finalized.block==block.block_hash()));
    assert_eq!(client_runtime.lock().unwrap().head().unwrap().height,block.header.candidate.height);
    submit(client,Command::Receipt{object,start,count});
}

#[test]
fn bounded_live_ephemeral_certifier_serves_two_blocks_across_reconnect(){
    assert!(!mutiny_transport_v2::PRODUCTION_QUALIFIED);
    let started=Instant::now();let deadline=started+Duration::from_secs(900);
    let output=PathBuf::from(std::env::var_os("FORGE_LIVE_SESSION_OUTPUT").expect("explicit public output directory"));
    std::fs::create_dir(&output).unwrap();
    fixture::with_fresh_ephemeral(|inputs,enrollment,constructed,node,continuity,public_evidence|{
        assert_eq!(inputs.class(),GenesisClass::TestValue);
        let approved=Approved{manifest:inputs.parameters.rules.clone(),class:GenesisClass::TestValue,initial_target:inputs.parameters.initial_target};
        let(artifact,reconstructed)=freeze_with_public_evidence(inputs,enrollment,&approved,public_evidence).unwrap();assert_eq!(reconstructed.block_hash,constructed.block_hash);
        let trust=TrustV2{artifact_sha256:Sha256::digest(&artifact).into(),genesis_block_hash:constructed.block_hash,approved};
        let verified=VerifiedGenesisV2::verify_with_public_evidence(&artifact,&trust,public_evidence).unwrap();
        public_file(&output.join("artifact.json"),&artifact);public_file(&output.join("public-evidence.cbor"),public_evidence);
        let mut random=[0;16];mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
        let base=std::env::temp_dir().join(format!("forge-live-ephemeral-session-{}",hex::encode(random)));
        assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
        for n in ["certifier","host","canonical-client"]{assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base.join(n)).unwrap());}
        let producer_path=base.join("certifier/chain.sqlite");
        let mut chain=CanonicalStore::open_trusted_genesis(&producer_path,&constructed.anchor(),&constructed.state,constructed.root,inputs.timestamp,inputs.parameters.initial_target).unwrap();
        let mut pool=Mempool::open(&base.join("certifier/pool.sqlite"),constructed.identity,constructed.fingerprint,MAX_PENDING_BYTES).unwrap();
        let voter_path=base.join("certifier/voter.sqlite");let mut backend=EphemeralBackend{continuity,node,counter:100,path:voter_path.clone(),calls:0,work_calls:0};
        let voter_node=enrollment.member_binding.admission.node;
        let mut actor=VoterActor::open(&voter_path,voter_node,Some(100),&mut chain,&mut backend).unwrap();
        let clock=Arc::new(AtomicU64::new(inputs.timestamp+1));
        let host_runtime=Arc::new(Mutex::new(runtime(&base.join("host"),&verified,clock.clone())));
        let client_runtime=Arc::new(Mutex::new(runtime(&base.join("canonical-client"),&verified,clock.clone())));
        let client_key=HybridKey::generate(Role::Transport).unwrap();let host_key=Arc::new(HybridKey::generate(Role::Transport).unwrap());
        let client_pin=Endpoint::pinned(client_key.public().clone(),1).unwrap();let host_pin=Endpoint::pinned(host_key.public().clone(),1).unwrap();
        let outgoing=Registry::new(constructed.identity,constructed.fingerprint,client_pin.clone(),vec![host_pin.clone()],1,1).unwrap();
        let incoming=Registry::new(constructed.identity,constructed.fingerprint,host_pin.clone(),vec![client_pin.clone()],1,1).unwrap();
        let public_pins=serde_json::json!({"schema":"FORGE-LIVE-TEST-SESSION-PUBLIC-PINS-V1","genesis_id":hex::encode(constructed.identity),
            "genesis_block_hash":hex::encode(constructed.block_hash),"fingerprint":hex::encode(constructed.fingerprint),
            "artifact_sha256":hex::encode(trust.artifact_sha256),"public_evidence_sha256":hex::encode(Sha256::digest(public_evidence)),
            "approved_manifest":hex::encode(inputs.parameters.rules.encode().unwrap()),"target":hex::encode(inputs.parameters.initial_target),
            "host_transport_descriptor":hex::encode(host_key.public().descriptor(1).unwrap()),"client_transport_descriptor":hex::encode(client_key.public().descriptor(1).unwrap()),
            "endpoint_generation":1,"test_timestamp":inputs.timestamp,"nonce":hex::encode(inputs.nonce),"production_eligible":false,"private_keys_persisted":false});
        public_file(&output.join("pins.json"),&serde_json::to_vec_pretty(&public_pins).unwrap());
        println!("LIVE SESSION public pins ready: Genesis {}; matching ephemeral signing keys retained",hex::encode(constructed.identity));
        let mut hashes=Vec::new();let mut closes=Vec::new();
        for height in 1..=2u64{
            assert!(Instant::now()<deadline,"finite session lifetime expired");clock.store(inputs.timestamp+height,Ordering::SeqCst);
            let(host,client)=connect(&base,&outgoing,&incoming,&client_key,host_key.clone(),&client_pin,&host_pin,host_runtime.clone(),client_runtime.clone());
            println!("LIVE SESSION connection {height}: host responder and canonical SDK client authenticated before signing");
            let block=certify(inputs,constructed,enrollment,&mut chain,&mut pool,&mut actor,&mut backend,height);
            assert!(host_runtime.lock().unwrap().install(&block.encode().unwrap()).unwrap().inserted);
            println!("LIVE SESSION newly certified height {height}: {} counter {}",hex::encode(block.block_hash()),backend.counter);
            deliver(&host,&client,&client_runtime,&block,deadline);
            println!("LIVE SESSION canonical client accepted height {height}; signature keys still retained");
            public_file(&output.join(format!("block-{height}.cbor")),&block.encode().unwrap());hashes.push(hex::encode(block.block_hash()));
            closes.push(stop(host,client,&outgoing,&incoming));
        }
        assert_eq!(backend.calls,4);assert_eq!(backend.work_calls,2);assert_eq!(backend.counter,110);assert_eq!(actor.height(),3);
        drop(actor);let reopened_actor=VoterActor::open(&voter_path,voter_node,None,&mut chain,&mut backend).unwrap();assert_eq!(reopened_actor.height(),3);drop(reopened_actor);
        drop(host_runtime);drop(client_runtime);
        let reopened=runtime(&base.join("canonical-client"),&verified,clock);assert_eq!(reopened.head().unwrap().height,2);assert_eq!(hex::encode(reopened.head().unwrap().block),hashes[1]);drop(reopened);
        let result=serde_json::json!({"schema":"FORGE-BOUNDED-LIVE-TEST-CERTIFIER-PEER-SESSION-V1","fresh_genesis_id":hex::encode(constructed.identity),
            "fresh_genesis_nonce":hex::encode(inputs.nonce),"block_hashes":hashes,"final_height":2,"voter_height":3,
            "continuity_signatures":backend.calls,"node_work_signatures":backend.work_calls,"counter_start":100,"counter_end":backend.counter,
            "authenticated_connections":2,"certified_while_connected":true,"same_ephemeral_signing_keys_retained_across_reconnect":true,
            "client":"canonical SDK HybridRuntime test client; not actual Desktop","desktop_compatibility_verified":false,
            "host":"existing SDK responder/Worker, no new server transport implementation","loopback_only":true,
            "max_session_seconds":900,"elapsed_seconds":started.elapsed().as_secs_f64(),"worker_joins_complete":true,"admission_leases_released":true,
            "runtime_and_voter_reopen_passed":true,"remote_close_results":closes,"private_keys_persisted":false,
            "node_work_custody":"ephemeral TEST Authority API; installed issuer remains unavailable","production_eligible":false,"hardware_or_rf_activated":false,
            "state_directory":base.display().to_string()});
        public_file(&output.join("result.json"),&serde_json::to_vec_pretty(&result).unwrap());println!("LIVE SESSION shutdown/result: {result}");
    });
    // Constructor's fresh Node/Continuity keys and all transport owners have now dropped.
    public_file(&output.join("key-scope-ended.json"),&serde_json::to_vec(&serde_json::json!({"fixture_callback_returned":true,"sdk_key_owners_dropped":true,"private_keys_persisted":false,"endpoint_running":false})).unwrap());
    println!("LIVE SESSION key-owning scope ended; no endpoint or private key retained");
}
