use super::*;
use crate::{hybrid_dispatch_v2::{self,DispatchEvent,DispatchError},hybrid_runtime_v2::HybridRuntime};
use mutiny_consensus_v8::{anchors::FinalizedAnchor,canonical_store_v2::CanonicalStore,execution::State,mempool_v2::Mempool,block_envelope_v2::BlockEnvelope};
use mutiny_crypto_v2::{HybridKey,Role};
use mutiny_transport_v2::{object_link::Event,objects::{ObjectKind,ObjectQueue}};
use std::{net::{TcpListener,TcpStream},path::PathBuf};

struct Scope(PathBuf);
impl Scope { fn new()->Self {let mut n=[0;16];mutiny_crypto_v2::fill_os_random(&mut n).unwrap();let p=std::env::temp_dir().join(format!("wallet-client-admission-{}",hex::encode(n)));assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&p).unwrap());Self(p)} }
impl Drop for Scope {fn drop(&mut self){std::fs::remove_dir_all(&self.0).unwrap();}}
fn connections(outgoing:&Registry,incoming:&Registry,a:&HybridKey,b:&HybridKey,pa:&Endpoint,pb:&Endpoint)->(Connection,Connection){
    let socket=TcpListener::bind("127.0.0.1:0").unwrap();assert!(socket.local_addr().unwrap().ip().is_loopback());
    let c=TcpStream::connect(socket.local_addr().unwrap()).unwrap();let s=socket.accept().unwrap().0;drop(socket);
    std::thread::scope(|threads|{let pending=incoming.begin().unwrap();let t=threads.spawn(||pending.respond(pa.id(),s,b,Duration::from_secs(30)).unwrap());
        let c=outgoing.begin().unwrap().initiate(pb.id(),c,a,Duration::from_secs(30)).unwrap();(c,t.join().unwrap())})
}
fn links(scope:&Scope,out:&Registry,input:&Registry,a:&HybridKey,b:&HybridKey,pa:&Endpoint,pb:&Endpoint)->(PeerLink,PeerLink){
    let(c,s)=connections(out,input,a,b,pa,pb);let cq=ObjectQueue::open(&scope.0.join("client.sqlite"),c.peer_id()).unwrap();let sq=ObjectQueue::open(&scope.0.join("node.sqlite"),s.peer_id()).unwrap();(c.attach(cq).unwrap(),s.attach(sq).unwrap())
}
fn fixture(s:&Scope)->(HybridRuntime,FinalizedAnchor,Vec<u8>){
    let f:serde_json::Value=serde_json::from_str(include_str!("../../qualification/hybrid-canonical-store-public-v1.json")).unwrap();assert_eq!(f["synthetic_only"],true);assert_eq!(f["production_authorized"],false);
    let raw=|v:&serde_json::Value|hex::decode(v.as_str().unwrap()).unwrap();let root:Hash=raw(&f["root"]).try_into().unwrap();
    let rows:Vec<_>=f["records"].as_array().unwrap().iter().map(|r|(raw(&r["key"]).try_into().unwrap(),raw(&r["record"]))).collect();
    let state=State::from_records(&rows,root).unwrap();let genesis=FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();let envelope=BlockEnvelope::decode(&raw(&f["envelope"])).unwrap();
    let runtime=HybridRuntime::from_pinned_chain(CanonicalStore::open_trusted_genesis(&s.0.join("chain.sqlite"),&genesis,&state,root,1000,[255;32]).unwrap(),Mempool::open(&s.0.join("pool.sqlite"),genesis.genesis,genesis.fingerprint,64*1024*1024).unwrap()).unwrap();
    (runtime,genesis,envelope.body.transactions[0].clone())
}
fn canonical_state(scope:&Scope)->Vec<(Vec<u8>,Vec<u8>)>{
    let db=rusqlite::Connection::open_with_flags(scope.0.join("chain.sqlite"),rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let mut q=db.prepare("SELECT key,value FROM state_v2 ORDER BY key").unwrap();
    q.query_map([],|row|Ok((row.get(0)?,row.get(1)?))).unwrap().map(|row|row.unwrap()).collect()
}
fn transfer(client:&mut PeerLink,node:&mut PeerLink,runtime:&mut HybridRuntime,kind:ObjectKind,raw:&[u8])->std::result::Result<DispatchEvent,DispatchError>{
    let(o,f)=client.with_current(|l|l.enqueue(kind,raw,0)).unwrap().unwrap();client.send(&f,Instant::now()+Duration::from_secs(5)).unwrap();
    let e=node.receive(Instant::now()+Duration::from_secs(5)).unwrap();assert!(matches!(hybrid_dispatch_v2::dispatch_peer(runtime,node,e).unwrap(),DispatchEvent::Transport(Event::Offered(_))));
    let req=node.with_current(|l|l.next_missing_request(&o.id,0,false)).unwrap().unwrap().unwrap();node.send(&req.frame,Instant::now()+Duration::from_secs(5)).unwrap();let e=client.receive(Instant::now()+Duration::from_secs(5)).unwrap();client.dispatch_received(e,|_,_|()).unwrap();
    let mut result=None;
    while let Some(f)=client.with_current(|l|l.send_one()).unwrap().unwrap(){
        client.send(&f,Instant::now()+Duration::from_secs(5)).unwrap();let e=node.receive(Instant::now()+Duration::from_secs(5)).unwrap();let value=hybrid_dispatch_v2::dispatch_peer(runtime,node,e);
        if !matches!(value,Ok(DispatchEvent::Transport(Event::FragmentReceived))){result=Some(value);}
    }
    result.expect("complete bounded candidate")
}

#[test]
fn wallet_client_allowed_candidates_keep_spending_and_canonical_authority_separate(){
    let scope=Scope::new();let(mut runtime,g,tx)=fixture(&scope);let initial=runtime.head().unwrap();let initial_state=canonical_state(&scope);
    let a=HybridKey::generate(Role::Transport).unwrap();let b=HybridKey::generate(Role::Transport).unwrap();let pa=Endpoint::pinned(a.public().clone(),1).unwrap();let pb=Endpoint::pinned(b.public().clone(),1).unwrap();
    let out=Registry::new_wallet_client(g.genesis,g.fingerprint,pa.clone(),vec![pb.clone()],1,1).unwrap();let input=Registry::new_wallet_clients(g.genesis,g.fingerprint,pb.clone(),vec![pa.clone()],1,1).unwrap();
    let(mut client,mut node)=links(&scope,&out,&input,&a,&b,&pa,&pb);
    let accepted=transfer(&mut client,&mut node,&mut runtime,ObjectKind::SignedTransaction,&tx).unwrap();
    let DispatchEvent::TransactionAccepted{id,..}=accepted else{panic!("canonical payment admission missing")};
    let query=mutiny_consensus_v8::submission_v1::encode_query(&[id]).unwrap();
    assert!(matches!(transfer(&mut client,&mut node,&mut runtime,ObjectKind::StatusQuery,&query).unwrap(),DispatchEvent::StatusQueryAnswered{..}));
    // Kind permission never bypasses complete-operation decoding/signatures/state.
    assert!(transfer(&mut client,&mut node,&mut runtime,ObjectKind::SignedOperation,b"invalid complete operation").is_err());
    let now=runtime.head().unwrap();assert_eq!(now,initial);assert_eq!(canonical_state(&scope),initial_state);
    assert!(node.with_current(|l|l.enqueue(ObjectKind::SignedTransaction,b"node relay forbidden",0)).unwrap().is_err());
    node.close();assert!(node.with_current(|_|()).is_err());client.close();drop(node);drop(client);drop(input.begin().unwrap());drop(out.begin().unwrap());
}

#[test]
fn wallet_client_queued_event_revocation_readdition_and_reconnect_do_not_inherit_authority(){
    let scope=Scope::new();let a=HybridKey::generate(Role::Transport).unwrap();let b=HybridKey::generate(Role::Transport).unwrap();let pa=Endpoint::pinned(a.public().clone(),1).unwrap();let pb=Endpoint::pinned(b.public().clone(),1).unwrap();
    let out=Registry::new_wallet_client([1;32],[2;32],pa.clone(),vec![pb.clone()],1,1).unwrap();let input=Registry::new_wallet_clients([1;32],[2;32],pb.clone(),vec![pa.clone()],1,1).unwrap();
    // Identity/generation substitution fails lookup before private handshake work.
    let changed=Endpoint::pinned(a.public().clone(),2).unwrap();assert!(input.begin().unwrap().context(changed.id()).is_err());
    let mut wrong=a.public().clone();wrong.role=Role::Node;assert!(Endpoint::pinned(wrong,1).is_err());
    let(mut client,mut node)=links(&scope,&out,&input,&a,&b,&pa,&pb);
    let(o,f)=client.with_current(|l|l.enqueue(ObjectKind::StatusQuery,b"candidate",0)).unwrap().unwrap();client.send(&f,Instant::now()+Duration::from_secs(5)).unwrap();let offered=node.receive(Instant::now()+Duration::from_secs(5)).unwrap();
    let request=node.with_current(|l|l.next_missing_request(&o.id,0,false)).unwrap().unwrap().unwrap();node.send(&request.frame,Instant::now()+Duration::from_secs(5)).unwrap();let e=client.receive(Instant::now()+Duration::from_secs(5)).unwrap();client.dispatch_received(e,|_,_|()).unwrap();let f=client.with_current(|l|l.send_one()).unwrap().unwrap().unwrap();client.send(&f,Instant::now()+Duration::from_secs(5)).unwrap();let completed=node.receive(Instant::now()+Duration::from_secs(5)).unwrap();
    input.replace_peers(vec![]).unwrap();input.replace_peers(vec![pa.clone()]).unwrap();
    let mut processed=false;assert!(node.dispatch_received(offered,|_,_|{processed=true}).is_err());assert!(!processed);assert!(input.begin().is_err());
    drop(node);drop(client);drop(input.begin().unwrap());drop(out.begin().unwrap());
    let(mut client,mut node)=links(&scope,&out,&input,&a,&b,&pa,&pb);
    assert!(node.with_current(|l|l.completed_incoming(&o.id)).unwrap().is_err());
    assert!(node.dispatch_received(completed,|_,_|{processed=true}).is_err());assert!(!processed);
    assert!(node.with_current(|_|()).is_err());client.close();drop(node);drop(client);drop(input.begin().unwrap());drop(out.begin().unwrap());
}

#[test]
fn wallet_client_prohibited_live_offer_closes_before_queue_and_canonical_mutation(){
    let scope=Scope::new();let(mut runtime,g,_)=fixture(&scope);let initial=runtime.head().unwrap();let initial_state=canonical_state(&scope);
    let a=HybridKey::generate(Role::Transport).unwrap();let b=HybridKey::generate(Role::Transport).unwrap();let pa=Endpoint::pinned(a.public().clone(),1).unwrap();let pb=Endpoint::pinned(b.public().clone(),1).unwrap();
    // Authenticated malicious client uses generic sender; this cannot broaden node policy.
    let out=Registry::new(g.genesis,g.fingerprint,pa.clone(),vec![pb.clone()],1,1).unwrap();let input=Registry::new_wallet_clients(g.genesis,g.fingerprint,pb.clone(),vec![pa.clone()],1,1).unwrap();let(mut client,mut node)=links(&scope,&out,&input,&a,&b,&pa,&pb);
    let public:serde_json::Value=serde_json::from_str(include_str!("../../qualification/hybrid-canonical-store-public-v1.json")).unwrap();
    let valid_block=hex::decode(public["envelope"].as_str().unwrap()).unwrap();
    let(o,f)=client.with_current(|l|l.enqueue(ObjectKind::CertifiedBlock,&valid_block,0)).unwrap().unwrap();client.send(&f,Instant::now()+Duration::from_secs(5)).unwrap();
    assert!(node.receive(Instant::now()+Duration::from_secs(5)).is_err());assert!(node.link.describe(&o.id).is_err());assert!(node.with_current(|_|()).is_err());
    let now=runtime.head().unwrap();assert_eq!(now,initial);assert_eq!(canonical_state(&scope),initial_state);
    client.close();drop(node);drop(client);drop(input.begin().unwrap());drop(out.begin().unwrap());
}

#[test]
fn wallet_client_verified_history_catchup_reconnect_and_idempotent_retry(){
    let host_scope=Scope::new();let wallet_scope=Scope::new();
    let(mut host_runtime,g,_)=fixture(&host_scope);let(mut wallet_runtime,_,_)=fixture(&wallet_scope);
    let f:serde_json::Value=serde_json::from_str(include_str!("../../qualification/hybrid-canonical-store-public-v1.json")).unwrap();
    let block=hex::decode(f["envelope"].as_str().unwrap()).unwrap();
    assert!(host_runtime.install(&block).unwrap().inserted);
    let a=HybridKey::generate(Role::Transport).unwrap();let b=HybridKey::generate(Role::Transport).unwrap();let pa=Endpoint::pinned(a.public().clone(),1).unwrap();let pb=Endpoint::pinned(b.public().clone(),1).unwrap();
    let out=Registry::new_wallet_client(g.genesis,g.fingerprint,pa.clone(),vec![pb.clone()],1,1).unwrap();let input=Registry::new_wallet_clients(g.genesis,g.fingerprint,pb.clone(),vec![pa.clone()],1,1).unwrap();
    let(mut client,mut node)=links(&host_scope,&out,&input,&a,&b,&pa,&pb);
    assert_eq!(wallet_runtime.head().unwrap().height,0);
    let result=transfer(&mut node,&mut client,&mut wallet_runtime,ObjectKind::CertifiedBlock,&block).unwrap();
    let DispatchEvent::BlockInstalled{offer,result}=result else{panic!("verified wallet history not installed")};assert!(result.inserted);
    assert_eq!(wallet_runtime.head().unwrap(),host_runtime.head().unwrap());
    assert!(client.with_current(|l|l.enqueue(ObjectKind::CertifiedBlock,&block,0)).unwrap().is_err());
    let accepted=wallet_runtime.head().unwrap();let accepted_state=canonical_state(&wallet_scope);
    client.close();node.close();drop(client);drop(node);drop(out.begin().unwrap());drop(input.begin().unwrap());
    let(mut client,mut node)=links(&host_scope,&out,&input,&a,&b,&pa,&pb);
    assert!(client.with_current(|l|l.completed_incoming(&offer.id)).unwrap().is_err());
    let have=node.with_current(|l|l.advertise(&offer.id,0)).unwrap().unwrap();node.send(&have,Instant::now()+Duration::from_secs(5)).unwrap();
    let queued=client.receive(Instant::now()+Duration::from_secs(5)).unwrap();hybrid_dispatch_v2::dispatch_peer(&mut wallet_runtime,&mut client,queued).unwrap();
    let wallet_actor=std::sync::Mutex::new(wallet_runtime);
    let duplicate=hybrid_dispatch_v2::retry_peer_completed(&wallet_actor,&mut client,offer.id,Instant::now()+Duration::from_secs(5)).unwrap();
    assert!(matches!(duplicate,DispatchEvent::BlockInstalled{result,..} if !result.inserted));
    assert_eq!(wallet_actor.lock().unwrap().head().unwrap(),accepted);assert_eq!(canonical_state(&wallet_scope),accepted_state);
    client.close();node.close();drop(client);drop(node);drop(out.begin().unwrap());drop(input.begin().unwrap());
}
