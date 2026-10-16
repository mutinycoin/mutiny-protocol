//! B1 local-purpose admission, provenance and deferred canonical verification.
use super::*;
use crate::{
    history_protocol_v1::{HistoryPage, HistoryRequest, HistoryStatus},
    hybrid_dispatch_v2::{self, DispatchError, DispatchEvent},
    hybrid_runtime_v2::HybridRuntime,
};
use mutiny_consensus_v8::{anchors::FinalizedAnchor, canonical_store_v2::CanonicalStore,
    execution::State, mempool_v2::Mempool};
use mutiny_crypto_v2::{HybridKey, Role};
use mutiny_transport_v2::{object_link::Event, objects::{ObjectKind, ObjectQueue, Offer, object_id}};
use std::{net::{TcpListener, TcpStream}, path::PathBuf};

struct Scope(PathBuf);
impl Scope {
    fn new() -> Self {
        let mut random = [0;16]; mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!("b1-history-admission-{}",hex::encode(random)));
        assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&path).unwrap());
        Self(path)
    }
}
impl Drop for Scope { fn drop(&mut self) { std::fs::remove_dir_all(&self.0).unwrap(); } }

fn fixture(scope: &Scope) -> (HybridRuntime, FinalizedAnchor, Vec<u8>) {
    let f: serde_json::Value = serde_json::from_str(include_str!("../../qualification/hybrid-canonical-store-public-v1.json")).unwrap();
    assert_eq!(f["synthetic_only"],true); assert_eq!(f["production_authorized"],false);
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let root: Hash = raw(&f["root"]).try_into().unwrap();
    let rows: Vec<_> = f["records"].as_array().unwrap().iter().map(|r|
        (raw(&r["key"]).try_into().unwrap(),raw(&r["record"]))).collect();
    let state = State::from_records(&rows,root).unwrap();
    let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
    let runtime = HybridRuntime::from_pinned_chain(
        CanonicalStore::open_trusted_genesis(&scope.0.join("chain.sqlite"),&genesis,&state,root,1000,[255;32]).unwrap(),
        Mempool::open(&scope.0.join("pool.sqlite"),genesis.genesis,genesis.fingerprint,64*1024*1024).unwrap()).unwrap();
    (runtime,genesis,raw(&f["envelope"]))
}
fn request(anchor: FinalizedAnchor) -> HistoryRequest {
    HistoryRequest { sequence:1,saved_anchor:anchor,max_blocks:64,max_candidate_bytes:4_000_000,max_candidate_entries:6 }
}
fn connections(out: &Registry,input: &Registry,a: &HybridKey,b: &HybridKey,pa: &Endpoint,pb: &Endpoint) -> (Connection,Connection) {
    let listener=TcpListener::bind("127.0.0.1:0").unwrap();
    assert!(listener.local_addr().unwrap().ip().is_loopback());
    let c=TcpStream::connect(listener.local_addr().unwrap()).unwrap(); let s=listener.accept().unwrap().0; drop(listener);
    std::thread::scope(|threads| {
        let pending=input.begin().unwrap();
        let server=threads.spawn(|| pending.respond(pa.id(),s,b,Duration::from_secs(30)).unwrap());
        let client=out.begin().unwrap().initiate(pb.id(),c,a,Duration::from_secs(30)).unwrap();
        (client,server.join().unwrap())
    })
}
fn links(scope: &Scope,out: &Registry,input: &Registry,a: &HybridKey,b: &HybridKey,pa: &Endpoint,pb: &Endpoint,initialize: bool) -> (PeerLink,PeerLink) {
    let (c,s)=connections(out,input,a,b,pa,pb);
    let cq=ObjectQueue::open_history(&scope.0.join("client.sqlite"),c.peer_id(),false,initialize).unwrap();
    let sq=ObjectQueue::open_history(&scope.0.join("node.sqlite"),s.peer_id(),false,initialize).unwrap();
    (c.attach(cq).unwrap(),s.attach(sq).unwrap())
}
fn transfer(send: &mut PeerLink,recv: &mut PeerLink,runtime: &mut HybridRuntime,kind: ObjectKind,bytes: &[u8]) -> std::result::Result<DispatchEvent,DispatchError> {
    let (offer,frame)=send.with_current(|l|l.enqueue(kind,bytes,0)).unwrap().unwrap();
    transfer_frame(send,recv,runtime,offer,frame)
}
fn transfer_frame(send: &mut PeerLink,recv: &mut PeerLink,runtime: &mut HybridRuntime,offer: Offer,frame: Vec<u8>) -> std::result::Result<DispatchEvent,DispatchError> {
    let limit=||Instant::now()+Duration::from_secs(5);
    send.send(&frame,limit()).unwrap();
    let e=recv.receive(limit()).unwrap();
    assert!(matches!(hybrid_dispatch_v2::dispatch_peer(runtime,recv,e).unwrap(),DispatchEvent::Transport(Event::Offered(_))));
    let want=recv.with_current(|l|l.next_missing_request(&offer.id,0,false)).unwrap().unwrap().unwrap();
    recv.send(&want.frame,limit()).unwrap();
    let e=send.receive(limit()).unwrap(); send.dispatch_received(e,|_,_|()).unwrap();
    let mut completed=None;
    while let Some(frame)=send.with_current(|l|l.send_one()).unwrap().unwrap() {
        send.send(&frame,limit()).unwrap(); let e=recv.receive(limit()).unwrap();
        let value=hybrid_dispatch_v2::dispatch_peer(runtime,recv,e);
        if !matches!(value,Ok(DispatchEvent::Transport(Event::FragmentReceived))) { completed=Some(value); }
    }
    completed.expect("bounded completed object")
}
fn keys() -> (HybridKey,HybridKey,Endpoint,Endpoint) {
    let a=HybridKey::generate(Role::Transport).unwrap(); let b=HybridKey::generate(Role::Transport).unwrap();
    let pa=Endpoint::pinned(a.public().clone(),1).unwrap(); let pb=Endpoint::pinned(b.public().clone(),1).unwrap();
    (a,b,pa,pb)
}

#[test]
fn b1_authenticated_controls_are_typed_exact_and_do_not_mutate_canonical_state() {
    let scope=Scope::new(); let (mut runtime,g,_)=fixture(&scope); let head=runtime.head().unwrap();
    let (a,b,pa,pb)=keys();
    let out=Registry::new_wallet_history_client(g.genesis,g.fingerprint,pa.clone(),vec![pb.clone()],1,1).unwrap();
    let input=Registry::new_wallet_history_clients(g.genesis,g.fingerprint,pb.clone(),vec![pa.clone()],1,1).unwrap();
    let (mut client,mut node)=links(&scope,&out,&input,&a,&b,&pa,&pb,true);
    let req=request(g.clone()); let raw=req.encode().unwrap();
    let event=transfer(&mut client,&mut node,&mut runtime,ObjectKind::HistoryRequestV1,&raw).unwrap();
    assert!(matches!(event,DispatchEvent::HistoryRequest{offer,bytes,request} if offer.id==req.object_id().unwrap() && bytes==raw && request==req));
    let page=HistoryPage { request_object_id:req.object_id().unwrap(),status:HistoryStatus::AtSnapshotTip,
        from_anchor:g.clone(),offered_through_anchor:Some(g.clone()),observed_tip_anchor:Some(g),entries:vec![] };
    let raw=page.encode().unwrap();
    let offers=node.with_current(|l|l.enqueue_history_page(&req.object_id().unwrap(),&raw,&[])).unwrap().unwrap().unwrap();
    let frame=node.with_current(|l|l.advertise(&offers[0].id,0)).unwrap().unwrap();
    let event=transfer_frame(&mut node,&mut client,&mut runtime,offers[0].clone(),frame).unwrap();
    assert!(matches!(event,DispatchEvent::HistoryPage{bytes,page:p,..} if bytes==raw && p==page));
    assert_eq!(runtime.head().unwrap(),head);
    assert!(client.with_current(|l|l.enqueue(ObjectKind::HistoryPageV1,&raw,0)).unwrap().is_err());
    assert!(node.with_current(|l|l.enqueue(ObjectKind::HistoryRequestV1,&req.encode().unwrap(),0)).unwrap().is_err());
    assert!(client.with_current(|l|l.enqueue(ObjectKind::ContinuityVote,b"not voter authority",0)).unwrap().is_err());
    assert!(node.with_current(|l|l.enqueue(ObjectKind::WorkProbeRequest,b"not miner authority",0)).unwrap().is_err());
}

#[test]
fn b1_old_g2_and_unrestricted_refuse_history_offer_before_persistence() {
    for legacy_g2 in [false,true] {
        let scope=Scope::new(); let (_,g,_)=fixture(&scope); let (a,b,pa,pb)=keys();
        let out=Registry::new_wallet_history_client(g.genesis,g.fingerprint,pa.clone(),vec![pb.clone()],1,1).unwrap();
        let ctor=if legacy_g2 {Registry::new_wallet_clients} else {Registry::new};
        let input=ctor(g.genesis,g.fingerprint,pb.clone(),vec![pa.clone()],1,1).unwrap();
        let (mut client,mut node)=links(&scope,&out,&input,&a,&b,&pa,&pb,true);
        let (offer,frame)=client.with_current(|l|l.enqueue(ObjectKind::HistoryRequestV1,&request(g).encode().unwrap(),0)).unwrap().unwrap();
        client.send(&frame,Instant::now()+Duration::from_secs(5)).unwrap();
        assert!(node.receive_typed(Instant::now()+Duration::from_secs(5)).is_err());
        assert!(node.link.describe(&offer.id).is_err(),"forbidden incoming HAVE never persisted");
        assert!(node.with_current(|_|()).is_err(),"authorization failure closes link");
    }
}

#[test]
fn b1_history_candidate_defers_install_and_retry_until_ordered_plan_owner_verifies() {
    let scope=Scope::new(); let (mut runtime,g,block)=fixture(&scope); let head=runtime.head().unwrap();
    let (a,b,pa,pb)=keys();
    let out=Registry::new_wallet_history_client(g.genesis,g.fingerprint,pa.clone(),vec![pb.clone()],1,1).unwrap();
    let input=Registry::new_wallet_history_clients(g.genesis,g.fingerprint,pb.clone(),vec![pa.clone()],1,1).unwrap();
    let (mut client,mut node)=links(&scope,&out,&input,&a,&b,&pa,&pb,true);
    let req=request(g.clone());
    transfer(&mut client,&mut node,&mut runtime,ObjectKind::HistoryRequestV1,&req.encode().unwrap()).unwrap();
    let recovery=b"invalid recovery remains opaque".to_vec();
    let through=mutiny_consensus_v8::block_envelope_v2::BlockEnvelope::decode(&block).unwrap().certificate.decision.anchor();
    let candidates=vec![(ObjectKind::RecoveryEvidence,recovery.clone()),(ObjectKind::CertifiedBlock,block.clone())];
    let entries=candidates.iter().enumerate().map(|(i,(kind,bytes))|crate::history_protocol_v1::HistoryEntry {
        kind:*kind,height:i as u64,object_id:object_id(*kind,bytes).unwrap(),encoded_length:bytes.len() as u32
    }).collect();
    let page=HistoryPage { request_object_id:req.object_id().unwrap(),status:HistoryStatus::Page,from_anchor:g,
        offered_through_anchor:Some(through.clone()),observed_tip_anchor:Some(through),entries };
    let offers=node.with_current(|l|l.enqueue_history_page(&req.object_id().unwrap(),&page.encode().unwrap(),&candidates)).unwrap().unwrap().unwrap();
    let frame=node.with_current(|l|l.advertise(&offers[0].id,0)).unwrap().unwrap();
    assert!(matches!(transfer_frame(&mut node,&mut client,&mut runtime,offers[0].clone(),frame).unwrap(),DispatchEvent::HistoryPage{..}));
    client.with_current(|l|l.history_accept_plan(&req.object_id().unwrap(),&offers[0].id,&offers[1..])).unwrap().unwrap();
    // Even a complete, valid successor is only an opaque host candidate. The
    // ordered receiver, not generic dispatch, must first accept its recovery.
    let frame=node.with_current(|l|l.advertise(&offers[2].id,0)).unwrap().unwrap();
    let event=transfer_frame(&mut node,&mut client,&mut runtime,offers[2].clone(),frame).unwrap();
    let DispatchEvent::HistoryCandidate{offer,bytes}=event else {panic!("B1 cannot auto-install a candidate")};
    assert_eq!(bytes,block); assert_eq!(runtime.head().unwrap(),head);
    let duplicate=client.with_current(|link|hybrid_dispatch_v2::retry_completed(&mut runtime,link,&offer.id)).unwrap().unwrap();
    assert!(matches!(duplicate,DispatchEvent::HistoryCandidate{bytes,..} if bytes==block));
    assert_eq!(runtime.head().unwrap(),head,"durable retry must also defer canonical application");
    let frame=node.with_current(|l|l.advertise(&offers[1].id,0)).unwrap().unwrap();
    let event=transfer_frame(&mut node,&mut client,&mut runtime,offers[1].clone(),frame).unwrap();
    assert!(matches!(event,DispatchEvent::HistoryCandidate{bytes,..} if bytes==recovery));
    assert_eq!(runtime.head().unwrap(),head);
}

#[test]
fn b1_bad_canonical_control_is_other_not_expiry_and_cannot_mutate_head() {
    let scope=Scope::new(); let (mut runtime,g,_)=fixture(&scope); let head=runtime.head().unwrap(); let (a,b,pa,pb)=keys();
    let out=Registry::new_wallet_history_client(g.genesis,g.fingerprint,pa.clone(),vec![pb.clone()],1,1).unwrap();
    let input=Registry::new_wallet_history_clients(g.genesis,g.fingerprint,pb.clone(),vec![pa.clone()],1,1).unwrap();
    let (mut client,mut node)=links(&scope,&out,&input,&a,&b,&pa,&pb,true);
    let error=transfer(&mut client,&mut node,&mut runtime,ObjectKind::HistoryRequestV1,b"bad CBOR").err().unwrap();
    assert!(matches!(error,DispatchError::History(_)));
    assert!(matches!(crate::hybrid_peer_error_v2::PeerFailure::dispatch("history",error),crate::hybrid_peer_error_v2::PeerFailure::Other(_)));
    assert_eq!(runtime.head().unwrap(),head);
}

#[test]
fn b1_queued_control_cannot_survive_pin_readdition_or_fresh_session_without_offer() {
    let scope=Scope::new(); let (_,g,_)=fixture(&scope); let (a,b,pa,pb)=keys();
    let out=Registry::new_wallet_history_client(g.genesis,g.fingerprint,pa.clone(),vec![pb.clone()],1,1).unwrap();
    let input=Registry::new_wallet_history_clients(g.genesis,g.fingerprint,pb.clone(),vec![pa.clone()],1,1).unwrap();
    let (mut client,mut node)=links(&scope,&out,&input,&a,&b,&pa,&pb,true);
    let (offer,frame)=client.with_current(|l|l.enqueue(ObjectKind::HistoryRequestV1,&request(g).encode().unwrap(),0)).unwrap().unwrap();
    client.send(&frame,Instant::now()+Duration::from_secs(5)).unwrap(); let queued=node.receive(Instant::now()+Duration::from_secs(5)).unwrap();
    input.replace_peers(vec![]).unwrap(); input.replace_peers(vec![pa.clone()]).unwrap();
    let mut called=false; assert!(node.dispatch_received(queued,|_,_|called=true).is_err()); assert!(!called);
    drop(node); drop(client);
    let (mut client,mut node)=links(&scope,&out,&input,&a,&b,&pa,&pb,false);
    assert!(node.with_current(|l|l.completed_incoming(&offer.id)).unwrap().is_err(),"disk presence is not fresh incoming permission");
    let frame=client.with_current(|l|l.advertise(&offer.id,0)).unwrap().unwrap();
    client.send(&frame,Instant::now()+Duration::from_secs(5)).unwrap();
    let fresh=node.receive(Instant::now()+Duration::from_secs(5)).unwrap();
    node.dispatch_received(fresh,|_,event|assert!(matches!(event,Event::Offered(_)))).unwrap();
    assert!(node.with_current(|l|l.next_missing_request(&offer.id,0,false)).unwrap().unwrap().is_some());
}

#[test]
fn b1_readonly_session_proof_tracks_close_drop_repin_and_does_not_hold_capacity() {
    let scope=Scope::new(); let (_,g,_)=fixture(&scope); let (a,b,pa,pb)=keys();
    let out=Registry::new_wallet_history_client(g.genesis,g.fingerprint,pa.clone(),vec![pb.clone()],1,1).unwrap();
    let input=Registry::new_wallet_history_clients(g.genesis,g.fingerprint,pb.clone(),vec![pa.clone()],1,1).unwrap();
    let (mut client,mut node)=links(&scope,&out,&input,&a,&b,&pa,&pb,true);
    let client_proof=client.history_session().unwrap(); let node_proof=node.history_session().unwrap();
    assert_eq!(client_proof.peer_id(),pb.id()); assert_eq!(node_proof.peer_id(),pa.id());
    assert_eq!(client_proof.session_id(),node_proof.session_id());
    assert_eq!(client_proof.authorization(),LocalAuthorization::NodeToWalletHistoryClient);
    assert_eq!(node_proof.authorization(),LocalAuthorization::WalletHistoryClientToNode);
    assert_eq!(client_proof.lifetime_deadline,client.link.lifetime_deadline(),"exact existing deadline, never mint time plus a new lifetime");
    client_proof.check_current().unwrap(); node_proof.check_current().unwrap();
    input.replace_peers(vec![]).unwrap(); input.replace_peers(vec![pa.clone()]).unwrap();
    assert!(node_proof.check_current().is_err(),"pin readdition cannot revive an old proof");
    assert!(input.begin().is_err(),"proof does not release the actual connection permit");
    client.close(); assert!(client_proof.check_current().is_err());
    drop(node); drop(client);
    assert!(node_proof.check_current().is_err()); assert!(client_proof.check_current().is_err());
    drop(input.begin().unwrap()); drop(out.begin().unwrap());
    // Retaining both proof clones has not retained either actual reservation.
    let (mut client,mut node)=links(&scope,&out,&input,&a,&b,&pa,&pb,false);
    let fresh=client.history_session().unwrap(); assert_ne!(fresh.session_id(),client_proof.session_id());
    fresh.check_current().unwrap(); drop(client); assert!(fresh.check_current().is_err());
    assert!(node.history_session().is_ok());
}

fn ready_publication(value: crate::history_service_v1::Preparation) -> crate::history_service_v1::PreparedHistoryPublication {
    match value {
        crate::history_service_v1::Preparation::Ready(publication) => publication,
        _ => panic!("expected bounded prepared publication"),
    }
}

#[test]
fn b1_host_export_publication_is_bound_to_received_request_and_exact_live_session() {
    use crate::history_service_v1::{HistoryBudget,NodeHistoryService};
    let scope=Scope::new(); let (mut runtime,g,_)=fixture(&scope); let (a,b,pa,pb)=keys();
    let out=Registry::new_wallet_history_client(g.genesis,g.fingerprint,pa.clone(),vec![pb.clone()],1,1).unwrap();
    let input=Registry::new_wallet_history_clients(g.genesis,g.fingerprint,pb.clone(),vec![pa.clone()],1,1).unwrap();
    let (mut client,mut node)=links(&scope,&out,&input,&a,&b,&pa,&pb,true);
    let req=request(g.clone()); let request_id=req.object_id().unwrap();
    let event=transfer(&mut client,&mut node,&mut runtime,ObjectKind::HistoryRequestV1,&req.encode().unwrap()).unwrap();
    let DispatchEvent::HistoryRequest{request:received,offer,..}=event else {panic!("typed received request")};
    assert_eq!(offer.id,request_id);
    let wallet_proof=client.history_session().unwrap(); let node_proof=node.history_session().unwrap();
    let budget=HistoryBudget::default();
    assert!(NodeHistoryService::new(wallet_proof,budget.clone()).is_err(),"wallet-side purpose cannot export node history");
    let mut service=NodeHistoryService::new(node_proof.clone(),budget).unwrap();
    let capacity=node.with_current(|l|l.history_capacity(&request_id)).unwrap().unwrap();
    let publication=ready_publication(service.prepare(&runtime,received,capacity,Instant::now()).unwrap());
    let (id,raw,objects)=publication.clone().into_parts(&node_proof).unwrap();
    assert_eq!(id,request_id); assert!(objects.is_empty());
    let page=HistoryPage::decode(&raw).unwrap(); page.validate_for(&req).unwrap();
    assert_eq!(page.status,HistoryStatus::AtSnapshotTip);

    // A distinct, simultaneously live, equally permitted session is not an
    // interchangeable publication target, even with the same chain context.
    let other_scope=Scope::new(); let (c,d,pc,pd)=keys();
    let other_out=Registry::new_wallet_history_client(g.genesis,g.fingerprint,pc.clone(),vec![pd.clone()],1,1).unwrap();
    let other_input=Registry::new_wallet_history_clients(g.genesis,g.fingerprint,pd.clone(),vec![pc.clone()],1,1).unwrap();
    let (_other_client,mut other_node)=links(&other_scope,&other_out,&other_input,&c,&d,&pc,&pd,true);
    let other_proof=other_node.history_session().unwrap();
    assert!(publication.clone().into_parts(&other_proof).is_err());
    assert!(publication.clone().into_parts(&node_proof).is_ok());
    input.replace_peers(vec![]).unwrap(); input.replace_peers(vec![pa]).unwrap();
    assert!(publication.into_parts(&node_proof).is_err(),"remove/re-add cannot publish an earlier prepared snapshot");
    assert!(service.prepare(&runtime,req,capacity,Instant::now()).is_err());
}

#[test]
fn b1_host_active_retry_overlap_retirement_and_ten_second_tip_cadence() {
    use crate::history_service_v1::{HistoryBudget,NodeHistoryService,Preparation,REFRESH};
    let scope=Scope::new(); let (mut runtime,g,block)=fixture(&scope); let (a,b,pa,pb)=keys();
    let out=Registry::new_wallet_history_client(g.genesis,g.fingerprint,pa.clone(),vec![pb.clone()],1,1).unwrap();
    let input=Registry::new_wallet_history_clients(g.genesis,g.fingerprint,pb.clone(),vec![pa.clone()],1,1).unwrap();
    let (mut client,mut node)=links(&scope,&out,&input,&a,&b,&pa,&pb,true);
    let req=request(g); let id=req.object_id().unwrap();
    transfer(&mut client,&mut node,&mut runtime,ObjectKind::HistoryRequestV1,&req.encode().unwrap()).unwrap();
    let proof=node.history_session().unwrap(); let mut service=NodeHistoryService::new(proof.clone(),HistoryBudget::default()).unwrap();
    let capacity=node.with_current(|l|l.history_capacity(&id)).unwrap().unwrap();
    let original=ready_publication(service.prepare(&runtime,req.clone(),capacity,Instant::now()).unwrap()).into_parts(&proof).unwrap();
    assert_eq!(HistoryPage::decode(&original.1).unwrap().status,HistoryStatus::AtSnapshotTip);
    runtime.install(&block).unwrap();
    let retried=ready_publication(service.prepare(&runtime,req.clone(),capacity,Instant::now()).unwrap()).into_parts(&proof).unwrap();
    assert_eq!(original,retried,"active exact retry retains the frozen snapshot even after a canonical append");
    let mut changed=req.clone(); changed.max_blocks-=1;
    assert!(service.prepare(&runtime,changed,capacity,Instant::now()).is_err(),"same sequence with different bytes is refused");
    let mut next=req.clone(); next.sequence+=1;
    assert!(matches!(service.prepare(&runtime,next.clone(),capacity,Instant::now()).unwrap(),Preparation::OverlappingBusy));
    let mut wrong=id; wrong[0]^=1;
    assert!(service.completed(wrong,Instant::now()).is_err());
    let completed_at=Instant::now(); service.completed(id,completed_at).unwrap();
    assert!(service.completed(id,Instant::now()).is_err(),"completion cannot be replayed");
    assert!(service.prepare(&runtime,req,capacity,Instant::now()).is_err(),"retired sequence cannot resurrect a cached page");
    let Preparation::RetryAfter(deadline)=service.prepare(&runtime,next,capacity,Instant::now()).unwrap() else {panic!("tip refresh must wait")};
    assert_eq!(deadline,completed_at+REFRESH); assert_eq!(REFRESH,Duration::from_secs(10));
}

#[test]
fn b1_host_nonempty_page_allows_immediate_progress_and_checkpoint_rejection_stops() {
    use crate::history_service_v1::{HistoryBudget,NodeHistoryService};
    for reject_checkpoint in [false,true] {
        let scope=Scope::new(); let (mut runtime,g,block)=fixture(&scope); let (a,b,pa,pb)=keys();
        runtime.install(&block).unwrap();
        let out=Registry::new_wallet_history_client(g.genesis,g.fingerprint,pa.clone(),vec![pb.clone()],1,1).unwrap();
        let input=Registry::new_wallet_history_clients(g.genesis,g.fingerprint,pb.clone(),vec![pa.clone()],1,1).unwrap();
        let (mut client,mut node)=links(&scope,&out,&input,&a,&b,&pa,&pb,true);
        let mut req=request(g); if reject_checkpoint {req.saved_anchor.block[0]^=1;}
        let id=req.object_id().unwrap();
        transfer(&mut client,&mut node,&mut runtime,ObjectKind::HistoryRequestV1,&req.encode().unwrap()).unwrap();
        let proof=node.history_session().unwrap(); let mut service=NodeHistoryService::new(proof.clone(),HistoryBudget::default()).unwrap();
        let capacity=node.with_current(|l|l.history_capacity(&id)).unwrap().unwrap();
        let (_,raw,objects)=ready_publication(service.prepare(&runtime,req.clone(),capacity,Instant::now()).unwrap()).into_parts(&proof).unwrap();
        let page=HistoryPage::decode(&raw).unwrap(); page.validate_for(&req).unwrap();
        service.completed(id,Instant::now()).unwrap();
        let mut next=req; next.sequence+=1; next.saved_anchor=runtime.head().unwrap();
        if reject_checkpoint {
            assert_eq!(page.status,HistoryStatus::CheckpointRejected); assert!(objects.is_empty());
            assert!(service.prepare(&runtime,next,capacity,Instant::now()).is_err(),"a new sequence cannot silently recover a rejected checkpoint");
        } else {
            assert_eq!(page.status,HistoryStatus::Page); assert_eq!(objects.len(),1);
            assert_eq!(objects[0],(ObjectKind::CertifiedBlock,block));
            let (_,raw,objects)=ready_publication(service.prepare(&runtime,next.clone(),capacity,Instant::now()).unwrap()).into_parts(&proof).unwrap();
            let page=HistoryPage::decode(&raw).unwrap(); page.validate_for(&next).unwrap();
            assert_eq!(page.status,HistoryStatus::AtSnapshotTip); assert!(objects.is_empty());
        }
    }
}

fn recovery_fixture(scope: &Scope) -> (HybridRuntime,FinalizedAnchor,Vec<u8>,Vec<u8>,Vec<u8>) {
    let f:serde_json::Value=serde_json::from_str(include_str!("../../qualification/hybrid-recovery-chain-public-v4.json")).unwrap();
    assert_eq!(f["synthetic_only"],true); assert_eq!(f["production_authorized"],false); assert_eq!(f["physical_tpm"],false);
    let raw=|v:&serde_json::Value|hex::decode(v.as_str().unwrap()).unwrap();
    let root:Hash=raw(&f["root"]).try_into().unwrap();
    let records:Vec<_>=f["records"].as_array().unwrap().iter().map(|r|(raw(&r["key"]).try_into().unwrap(),raw(&r["record"]))).collect();
    let state=State::from_records(&records,root).unwrap();
    let genesis=FinalizedAnchor::decode(&raw(&f["genesis_anchor"])).unwrap();
    let runtime=HybridRuntime::from_pinned_chain(
        CanonicalStore::open_trusted_genesis(&scope.0.join("chain.sqlite"),&genesis,&state,root,1000,[255;32]).unwrap(),
        Mempool::open(&scope.0.join("pool.sqlite"),genesis.genesis,genesis.fingerprint,64*1024*1024).unwrap()).unwrap();
    (runtime,genesis,raw(&f["block1"]),raw(&f["recovery1"]),raw(&f["block2"]))
}
fn page_offer(page: &HistoryPage) -> Offer {
    let raw=page.encode().unwrap();
    Offer {kind:ObjectKind::HistoryPageV1,id:object_id(ObjectKind::HistoryPageV1,&raw).unwrap(),length:raw.len()}
}
fn block_page(req: &HistoryRequest,block: &[u8]) -> HistoryPage {
    let through=mutiny_consensus_v8::block_envelope_v2::BlockEnvelope::decode(block).unwrap().certificate.decision.anchor();
    HistoryPage {request_object_id:req.object_id().unwrap(),status:HistoryStatus::Page,
        from_anchor:req.saved_anchor.clone(),offered_through_anchor:Some(through.clone()),observed_tip_anchor:Some(through),
        entries:vec![crate::history_protocol_v1::HistoryEntry {kind:ObjectKind::CertifiedBlock,height:req.saved_anchor.height+1,
            object_id:object_id(ObjectKind::CertifiedBlock,block).unwrap(),encoded_length:block.len() as u32}]}
}

#[test]
fn b1_receiver_real_recovery_then_block_install_mints_only_session_bound_reclaim_proofs() {
    use crate::history_service_v1::{HistoryBudget,NodeHistoryService,ReceiverHistoryPlan};
    let host_scope=Scope::new(); let wallet_scope=Scope::new();
    let (mut host,g,block1,recovery,block2)=recovery_fixture(&host_scope);
    let (mut wallet,_,_,_,_)=recovery_fixture(&wallet_scope);
    host.install(&block1).unwrap(); host.accept_recovery(&recovery).unwrap(); host.install(&block2).unwrap();
    wallet.install(&block1).unwrap(); let parent=wallet.head().unwrap(); assert_eq!(parent.height,1);
    let (a,b,pa,pb)=keys();
    let out=Registry::new_wallet_history_client(g.genesis,g.fingerprint,pa.clone(),vec![pb.clone()],1,1).unwrap();
    let input=Registry::new_wallet_history_clients(g.genesis,g.fingerprint,pb.clone(),vec![pa.clone()],1,1).unwrap();
    let (mut client,mut node)=links(&host_scope,&out,&input,&a,&b,&pa,&pb,true);
    let req=request(parent.clone()); let request_id=req.object_id().unwrap();
    transfer(&mut client,&mut node,&mut host,ObjectKind::HistoryRequestV1,&req.encode().unwrap()).unwrap();
    let node_proof=node.history_session().unwrap(); let wallet_proof=client.history_session().unwrap();
    let capacity=node.with_current(|l|l.history_capacity(&request_id)).unwrap().unwrap();
    let mut service=NodeHistoryService::new(node_proof.clone(),HistoryBudget::default()).unwrap();
    let (id,raw,objects)=ready_publication(service.prepare(&host,req.clone(),capacity,Instant::now()).unwrap()).into_parts(&node_proof).unwrap();
    assert_eq!(objects,vec![(ObjectKind::RecoveryEvidence,recovery.clone()),(ObjectKind::CertifiedBlock,block2.clone())]);
    let offers=node.with_current(|l|l.enqueue_history_page(&id,&raw,&objects)).unwrap().unwrap().unwrap();
    let frame=node.with_current(|l|l.advertise(&offers[0].id,0)).unwrap().unwrap();
    let event=transfer_frame(&mut node,&mut client,&mut wallet,offers[0].clone(),frame).unwrap();
    let DispatchEvent::HistoryPage{offer,page,..}=event else {panic!("receiver requires typed current plan")};
    let mut plan=ReceiverHistoryPlan::accept(&mut client,&req,&offer,page,&wallet).unwrap();
    assert_eq!(plan.next_entry().unwrap().kind,ObjectKind::RecoveryEvidence); assert!(!plan.complete());
    let frame=node.with_current(|l|l.advertise(&offers[1].id,0)).unwrap().unwrap();
    let event=transfer_frame(&mut node,&mut client,&mut wallet,offers[1].clone(),frame).unwrap();
    let DispatchEvent::HistoryCandidate{offer:member,bytes}=event else {panic!("opaque recovery candidate")};
    let proof=plan.install(&member,&bytes,&mut wallet).unwrap();
    assert_eq!(wallet.head().unwrap(),parent,"verified recovery installs authority without advancing finalized history");
    assert_eq!(proof.into_parts(&wallet_proof).unwrap(),(offer.id,member.id));
    assert_eq!(plan.next_entry().unwrap().kind,ObjectKind::CertifiedBlock);

    let other_scope=Scope::new(); let (c,d,pc,pd)=keys();
    let other_out=Registry::new_wallet_history_client(g.genesis,g.fingerprint,pc.clone(),vec![pd.clone()],1,1).unwrap();
    let other_input=Registry::new_wallet_history_clients(g.genesis,g.fingerprint,pd.clone(),vec![pc.clone()],1,1).unwrap();
    let (mut other_client,_other_node)=links(&other_scope,&other_out,&other_input,&c,&d,&pc,&pd,true);
    let other_wallet_proof=other_client.history_session().unwrap();
    let frame=node.with_current(|l|l.advertise(&offers[2].id,0)).unwrap().unwrap();
    let event=transfer_frame(&mut node,&mut client,&mut wallet,offers[2].clone(),frame).unwrap();
    let DispatchEvent::HistoryCandidate{offer:member,bytes}=event else {panic!("opaque certified successor")};
    let proof=plan.install(&member,&bytes,&mut wallet).unwrap();
    assert_eq!(wallet.head().unwrap(),host.head().unwrap()); assert!(plan.complete()); assert!(plan.next_entry().is_none());
    assert!(proof.into_parts(&other_wallet_proof).is_err(),"a fully verified member still cannot reclaim another live session's copy");
    assert!(plan.install(&member,&bytes,&mut wallet).is_err(),"completed plan does not mint repeated reclaim proofs");
}

#[test]
fn b1_receiver_wrong_have_hash_dependency_order_and_terminal_full_anchor_refuse_before_commit() {
    use crate::history_service_v1::ReceiverHistoryPlan;
    let scope=Scope::new(); let (mut runtime,g,block)=fixture(&scope); let (a,b,pa,pb)=keys();
    let out=Registry::new_wallet_history_client(g.genesis,g.fingerprint,pa.clone(),vec![pb.clone()],1,1).unwrap();
    let input=Registry::new_wallet_history_clients(g.genesis,g.fingerprint,pb.clone(),vec![pa.clone()],1,1).unwrap();
    let (mut client,mut node)=links(&scope,&out,&input,&a,&b,&pa,&pb,true);
    let proof=client.history_session().unwrap(); let req=request(g.clone()); let page=block_page(&req,&block); let offer=page_offer(&page);
    transfer(&mut client,&mut node,&mut runtime,ObjectKind::HistoryRequestV1,&req.encode().unwrap()).unwrap();
    assert!(ReceiverHistoryPlan::accept(&mut client,&req,&offer,page.clone(),&runtime).is_err(),"correct raw plan is not a fresh incoming page");
    // Model retained complete PUBLIC bytes, with an actual fresh outgoing request
    // but no page HAVE in this session. Storage is not an incoming capability.
    let mut retained=ObjectQueue::open_history(&scope.0.join("client.sqlite"),client.peer_id(),false,false).unwrap();
    assert_eq!(retained.enqueue(ObjectKind::HistoryPageV1,&page.encode().unwrap()).unwrap(),offer);
    drop(retained);
    assert!(client.link.describe(&offer.id).unwrap().1);
    assert!(client.with_current(|l|l.completed_incoming(&offer.id)).unwrap().is_err());
    assert!(ReceiverHistoryPlan::accept(&mut client,&req,&offer,page.clone(),&runtime).is_err(),"retained complete page still lacks this session's incoming grant");
    assert_eq!(runtime.head().unwrap(),g);
    for bad in [Offer {id:[7;32],..offer.clone()},Offer {length:offer.length+1,..offer.clone()},Offer {kind:ObjectKind::CertifiedBlock,..offer.clone()}] {
        assert!(ReceiverHistoryPlan::new(proof.clone(),&req,&bad,page.clone(),&runtime).is_err());
        assert_eq!(runtime.head().unwrap(),g);
    }
    // The raw-cache check is finished. Only this public transport copy is
    // removed so the following adversarial pages traverse fresh HAVE/fragments.
    client.with_current(|l|l.discard(&offer.id)).unwrap().unwrap();
    let member=Offer {kind:ObjectKind::CertifiedBlock,id:object_id(ObjectKind::CertifiedBlock,&block).unwrap(),length:block.len()};
    let (actual_offer,mut plan)=accept_test_page(&mut client,&mut node,&mut runtime,&req,page.clone(),&[(ObjectKind::CertifiedBlock,block.clone())]);
    let mut wrong_offer=member.clone(); wrong_offer.id[0]^=1;
    assert!(plan.install(&wrong_offer,&block,&mut runtime).is_err());
    let mut wrong_bytes=block.clone(); *wrong_bytes.last_mut().unwrap()^=1;
    assert!(plan.install(&member,&wrong_bytes,&mut runtime).is_err());
    assert_eq!(runtime.head().unwrap(),g); assert!(!plan.complete());
    retire_test_page(&mut client,&mut node,&req,&actual_offer);
    client.history_session().unwrap().check_current().unwrap();
    assert!(plan.install(&member,&block,&mut runtime).is_err(),"retired plan refuses even valid canonical bytes while the session stays live");
    assert_eq!(runtime.head().unwrap(),g);

    // A dependency plan cannot be skipped. These unverified recovery bytes are
    // never passed to the verifier in this test: the out-of-order block refuses.
    let mut ordered_request=req.clone(); ordered_request.sequence+=1;
    transfer(&mut client,&mut node,&mut runtime,ObjectKind::HistoryRequestV1,&ordered_request.encode().unwrap()).unwrap();
    let mut ordered=block_page(&ordered_request,&block); let recovery=b"not accepted recovery material";
    ordered.entries.insert(0,crate::history_protocol_v1::HistoryEntry {kind:ObjectKind::RecoveryEvidence,height:0,
        object_id:object_id(ObjectKind::RecoveryEvidence,recovery).unwrap(),encoded_length:recovery.len() as u32});
    let (ordered_offer,mut ordered_plan)=accept_test_page(&mut client,&mut node,&mut runtime,&ordered_request,ordered,
        &[(ObjectKind::RecoveryEvidence,recovery.to_vec()),(ObjectKind::CertifiedBlock,block.clone())]);
    assert!(ordered_plan.install(&member,&block,&mut runtime).is_err()); assert_eq!(runtime.head().unwrap(),g);
    retire_test_page(&mut client,&mut node,&ordered_request,&ordered_offer);

    let mut lying_request=ordered_request; lying_request.sequence+=1;
    transfer(&mut client,&mut node,&mut runtime,ObjectKind::HistoryRequestV1,&lying_request.encode().unwrap()).unwrap();
    let mut lie=block_page(&lying_request,&block); lie.offered_through_anchor.as_mut().unwrap().block[0]^=1;
    lie.observed_tip_anchor=lie.offered_through_anchor.clone();
    let (_,mut lying_plan)=accept_test_page(&mut client,&mut node,&mut runtime,&lying_request,lie,&[(ObjectKind::CertifiedBlock,block.clone())]);
    assert!(lying_plan.install(&member,&block,&mut runtime).is_err(),"matching height does not validate a lying terminal block hash");
    assert_eq!(runtime.head().unwrap(),g); assert!(!lying_plan.complete());
}

fn accept_test_page(client:&mut PeerLink,node:&mut PeerLink,runtime:&mut HybridRuntime,request:&HistoryRequest,
    page:HistoryPage,candidates:&[(ObjectKind,Vec<u8>)])->(Offer,crate::history_service_v1::ReceiverHistoryPlan) {
    let offers=node.with_current(|l|l.enqueue_history_page(&request.object_id().unwrap(),&page.encode().unwrap(),candidates)).unwrap().unwrap().unwrap();
    let frame=node.with_current(|l|l.advertise(&offers[0].id,0)).unwrap().unwrap();
    let event=transfer_frame(node,client,runtime,offers[0].clone(),frame).unwrap();
    let DispatchEvent::HistoryPage{offer,page,..}=event else {panic!("fresh authenticated test page")};
    let plan=crate::history_service_v1::ReceiverHistoryPlan::accept(client,request,&offer,page,runtime).unwrap();
    (offer,plan)
}
fn retire_test_page(client:&mut PeerLink,node:&mut PeerLink,request:&HistoryRequest,offer:&Offer) {
    for peer in [client,node] {
        peer.with_current(|l|l.history_retire_consumed_request(&request.object_id().unwrap())).unwrap().unwrap();
        peer.with_current(|l|l.history_retire_plan(&offer.id)).unwrap().unwrap();
    }
}
