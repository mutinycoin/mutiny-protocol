//! Real loopback B1 node worker, with no external publication commands.
use crate::{
    hybrid_dispatch_v2::{self,DispatchEvent},
    hybrid_peer_admission_v2::{Connection,PeerLink,Registry},
    hybrid_peer_worker_v2::{Worker,Command,Notification},
    hybrid_runtime_v2::HybridRuntime,
    history_protocol_v1::{HistoryRequest,HistoryPage,HistoryStatus},
    history_service_v1::{HistoryBudget,ReceiverHistoryPlan,HistoryPlanAdmission},
};
use mutiny_consensus_v8::{Hash,anchors::FinalizedAnchor,canonical_store_v2::CanonicalStore,execution::State,mempool_v2::Mempool};
use mutiny_crypto_v2::{HybridKey,Role};
use mutiny_transport_v2::{Endpoint,object_link::Event,objects::{ObjectKind,ObjectQueue,Offer,MAX_OBJECTS,MAX_QUEUE_BYTES,MAX_BITMAP_BITS}};
use std::{net::{TcpListener,TcpStream},path::{Path,PathBuf},sync::{Arc,Mutex},time::{Duration,Instant}};

struct Scope(PathBuf);
impl Scope {
    fn new()->Self {
        let mut random=[0;16]; mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
        let path=std::env::temp_dir().join(format!("b1-autonomous-node-{}",hex::encode(random)));
        assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&path).unwrap()); Self(path)
    }
}
impl Drop for Scope {fn drop(&mut self){std::fs::remove_dir_all(&self.0).unwrap();}}
fn fixture(scope:&Scope)->(HybridRuntime,FinalizedAnchor,Vec<u8>,Vec<u8>,Vec<u8>) {
    let f:serde_json::Value=serde_json::from_str(include_str!("../../qualification/hybrid-recovery-chain-public-v4.json")).unwrap();
    assert_eq!(f["synthetic_only"],true);assert_eq!(f["production_authorized"],false);assert_eq!(f["physical_tpm"],false);
    let raw=|v:&serde_json::Value|hex::decode(v.as_str().unwrap()).unwrap();
    let root:Hash=raw(&f["root"]).try_into().unwrap();
    let records:Vec<_>=f["records"].as_array().unwrap().iter().map(|r|(raw(&r["key"]).try_into().unwrap(),raw(&r["record"]))).collect();
    let state=State::from_records(&records,root).unwrap();
    let g=FinalizedAnchor::decode(&raw(&f["genesis_anchor"])).unwrap();
    let runtime=HybridRuntime::from_pinned_chain(
        CanonicalStore::open_trusted_genesis(&scope.0.join("chain.sqlite"),&g,&state,root,1000,[255;32]).unwrap(),
        Mempool::open(&scope.0.join("pool.sqlite"),g.genesis,g.fingerprint,64*1024*1024).unwrap()).unwrap();
    (runtime,g,raw(&f["block1"]),raw(&f["recovery1"]),raw(&f["block2"]))
}
fn connections(out:&Registry,input:&Registry,a:&HybridKey,b:&HybridKey,pa:&Endpoint,pb:&Endpoint)->(Connection,Connection) {
    let listener=TcpListener::bind("127.0.0.1:0").unwrap(); assert!(listener.local_addr().unwrap().ip().is_loopback());
    let c=TcpStream::connect(listener.local_addr().unwrap()).unwrap();let s=listener.accept().unwrap().0;drop(listener);
    std::thread::scope(|threads|{
        let pending=input.begin().unwrap();let server=threads.spawn(||pending.respond(pa.id(),s,b,Duration::from_secs(30)).unwrap());
        let client=out.begin().unwrap().initiate(pb.id(),c,a,Duration::from_secs(30)).unwrap();(client,server.join().unwrap())
    })
}
fn limit(deadline:Instant)->Instant {assert!(Instant::now()<deadline,"bounded autonomous test deadline");deadline.min(Instant::now()+Duration::from_secs(5))}
fn send(client:&mut PeerLink,frame:&[u8],deadline:Instant){client.send_typed(frame,limit(deadline)).unwrap();}
fn request(sequence:u32,wallet:&HybridRuntime)->HistoryRequest {
    HistoryRequest {sequence,saved_anchor:wallet.head().unwrap(),max_blocks:64,max_candidate_bytes:4_000_000,max_candidate_entries:6}
}
fn enqueue_request(client:&mut PeerLink,req:&HistoryRequest,deadline:Instant) {
    let (_,frame)=client.with_current(|l|l.enqueue(ObjectKind::HistoryRequestV1,&req.encode().unwrap(),0)).unwrap().unwrap();
    send(client,&frame,deadline);
}
struct Window {offer:Offer,start:u16,count:u16}
fn begin_window(client:&mut PeerLink,offer:Offer,start:u16,deadline:Instant)->Window {
    let total=offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD) as u16;
    let count=(total-start).min(16); assert!(count>0);
    let frame=client.with_current(|l|l.request_missing(&offer.id,start,count,0,false)).unwrap().unwrap();
    send(client,&frame,deadline);Window {offer,start,count}
}
fn full_ack(client:&mut PeerLink,offer:&Offer,deadline:Instant) {
    let total=offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD) as u16;
    for start in (0..total).step_by(MAX_BITMAP_BITS as usize) {
        let count=(total-start).min(MAX_BITMAP_BITS);
        let frame=client.with_current(|l|l.receipt(&offer.id,start,count,0)).unwrap().unwrap();
        send(client,&frame,deadline);
    }
}
fn queue_objects(path:&Path)->usize {
    let db=rusqlite::Connection::open_with_flags(path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    db.busy_timeout(Duration::from_millis(250)).unwrap();
    db.query_row("SELECT COUNT(*) FROM objects",[],|r|r.get(0)).unwrap()
}


/// The autonomous history owner consumes its internal events. Never discard an
/// unexpected public notification or hide an ended worker behind a socket wait.
fn check_auto_node(worker:&mut Option<Worker>) {
    loop {
        let current=worker.as_ref().expect("owned node worker");
        match current.try_notification() {
            Ok(notification)=>panic!("unexpected autonomous node notification: {:?}",std::mem::discriminant(&notification)),
            Err(std::sync::mpsc::TryRecvError::Empty)=>break,
            Err(std::sync::mpsc::TryRecvError::Disconnected)=>{
                let outcome=worker.take().unwrap().shutdown_typed();
                panic!("autonomous node notification channel closed; exact worker outcome: {outcome:?}");
            },
        }
    }
    if worker.as_ref().unwrap().is_finished() {
        let outcome=worker.take().unwrap().shutdown_typed();
        panic!("autonomous node ended; exact worker outcome: {outcome:?}");
    }
}

#[test]
fn b1_autonomous_node_worker_exports_orders_recovery_and_retires_before_next_tip_request() {
    let deadline=Instant::now()+Duration::from_secs(150);
    let host_scope=Scope::new();let wallet_scope=Scope::new();
    let (mut host,g,block1,recovery,block2)=fixture(&host_scope);
    let (mut wallet,_,_,_,_)=fixture(&wallet_scope);
    host.install(&block1).unwrap();host.accept_recovery(&recovery).unwrap();host.install(&block2).unwrap();
    let expected=host.head().unwrap();assert_eq!(expected.height,2);assert_eq!(wallet.head().unwrap().height,0);
    let runtime=Arc::new(Mutex::new(host));
    let a=HybridKey::generate(Role::Transport).unwrap();let b=HybridKey::generate(Role::Transport).unwrap();
    let pa=Endpoint::pinned(a.public().clone(),1).unwrap();let pb=Endpoint::pinned(b.public().clone(),1).unwrap();
    let out=Registry::new_wallet_history_client(g.genesis,g.fingerprint,pa.clone(),vec![pb.clone()],1,1).unwrap();
    let input=Registry::new_wallet_history_clients(g.genesis,g.fingerprint,pb.clone(),vec![pa.clone()],1,1).unwrap();
    let (connection,node_connection)=connections(&out,&input,&a,&b,&pa,&pb);
    let cq=ObjectQueue::open_history(&wallet_scope.0.join("client.sqlite"),connection.peer_id(),false,true).unwrap();
    let node_queue=host_scope.0.join("node.sqlite");
    let nq=ObjectQueue::open_history(&node_queue,node_connection.peer_id(),false,true).unwrap();
    let mut client=connection.attach(cq).unwrap();
    let mut worker=Some(Worker::start_history_node_typed(node_connection,nq,runtime.clone(),HistoryBudget::default()).unwrap());
    // Only the ordinary authenticated request is sent. There are deliberately
    // no PublishHistoryPage, Advertise, RequestMissing or other worker commands.
    let mut req=request(1,&wallet);enqueue_request(&mut client,&req,deadline);
    let mut window:Option<Window>=None;let mut plan:Option<ReceiverHistoryPlan>=None;
    let mut page_id=None;let mut statuses=Vec::new();let mut installed=Vec::new();
    let mut finished=false;
    while !finished {
        assert!(Instant::now()<deadline,"autonomous history completion timeout");
        check_auto_node(&mut worker);
        // Readiness is an idle service wait under the test's real deadline,
        // not a five-second complete-frame I/O operation. Native export may
        // finish an indivisible canonical verification between network frames.
        let ready=client.wait_for_frame_typed(deadline.min(Instant::now()+Duration::from_millis(20)));
        let ready=match ready {
            Ok(ready)=>ready,
            Err(error)=>{
                let outcome=worker.take().unwrap().shutdown_typed();
                panic!("client readiness failed: {error:?}; exact node outcome: {outcome:?}");
            },
        };
        check_auto_node(&mut worker);
        if !ready {continue;}
        // Once bytes are ready, retain the unchanged five-second full-frame
        // read bound; partial/stalled frames still fail through the real carrier.
        let received=match client.receive_typed(limit(deadline)) {
            Ok(received)=>received,
            Err(error)=>{
                let outcome=worker.take().unwrap().shutdown_typed();
                panic!("client complete-frame receive failed: {error:?}; exact node outcome: {outcome:?}");
            },
        };
        let event=hybrid_dispatch_v2::dispatch_peer(&mut wallet,&mut client,received).unwrap();
        match event {
            DispatchEvent::Transport(Event::Requested)=>{
                while let Some(frame)=client.with_current(|l|l.send_one()).unwrap().unwrap(){send(&mut client,&frame,deadline);}
            },
            DispatchEvent::Transport(Event::ReceiptRecorded)=>{},
            DispatchEvent::Transport(Event::Offered(offer))=>{
                assert!(window.is_none(),"one requested dependency/window at a time");
                if offer.kind==ObjectKind::HistoryPageV1 {assert!(plan.is_none());}
                else {assert!(plan.as_ref().unwrap().next_entry().unwrap().matches_offer(&offer),"node offers next semantic dependency only");}
                window=Some(begin_window(&mut client,offer,0,deadline));
            },
            DispatchEvent::Transport(Event::FragmentReceived)=>{
                let active=window.as_ref().expect("fragment belongs to requested window");
                let bits=client.with_current(|l|l.missing_window(&active.offer.id,active.start,active.count)).unwrap().unwrap();
                if bits.bits.iter().all(|missing|!*missing) {
                    let next=active.start+active.count;let offer=active.offer.clone();
                    assert!(usize::from(next)<offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD));
                    window=Some(begin_window(&mut client,offer,next,deadline));
                }
            },
            DispatchEvent::HistoryPage{offer,page,..}=>{
                assert_eq!(window.take().unwrap().offer,offer);page.validate_for(&req).unwrap();
                statuses.push(page.status);page_id=Some(offer.id);
                let accepted=ReceiverHistoryPlan::accept(&mut client,&req,&offer,page,&wallet).unwrap();
                client.with_current(|l|l.history_retire_consumed_request(&req.object_id().unwrap())).unwrap().unwrap();
                // The plan has been semantically validated before full page ACK;
                // only that ACK permits the node's first candidate advertisement.
                full_ack(&mut client,&offer,deadline);
                if accepted.complete() {
                    assert_eq!(wallet.head().unwrap(),expected);
                    client.with_current(|l|l.history_retire_plan(&offer.id)).unwrap().unwrap();finished=true;
                } else {plan=Some(accepted);}
            },
            DispatchEvent::HistoryCandidate{offer,bytes}=>{
                assert_eq!(window.take().unwrap().offer,offer);
                let before=wallet.head().unwrap();
                let receiver=plan.as_mut().unwrap();let verified=receiver.install(&offer,&bytes,&mut wallet).unwrap();
                let after=wallet.head().unwrap();
                if offer.kind==ObjectKind::RecoveryEvidence {assert_eq!(after,before,"recovery is authority, not a finalized successor");}
                installed.push((offer.kind,after.height));
                // Real canonical verification precedes the transport ACK. ACK
                // bytes must be constructed before reclaiming their public copy.
                full_ack(&mut client,&offer,deadline);
                let proof=client.history_session().unwrap();let (page,object)=verified.into_parts(&proof).unwrap();
                assert_eq!(Some(page),page_id);assert_eq!(object,offer.id);
                client.with_current(|l|l.history_reclaim_verified_candidate(&page,&object)).unwrap().unwrap();
                if receiver.complete() {
                    client.with_current(|l|l.history_retire_plan(&page)).unwrap().unwrap();plan=None;
                    req=request(req.sequence+1,&wallet);enqueue_request(&mut client,&req,deadline);
                }
            },
            _=>panic!("unexpected event in bounded history-only client pump"),
        }
    }
    assert_eq!(statuses,vec![HistoryStatus::Page,HistoryStatus::AtSnapshotTip]);
    assert_eq!(installed,vec![(ObjectKind::CertifiedBlock,1),(ObjectKind::RecoveryEvidence,1),(ObjectKind::CertifiedBlock,2)]);
    assert_eq!(wallet.head().unwrap(),expected);
    let capacity=client.with_current(|l|l.history_general_capacity()).unwrap().unwrap();
    assert_eq!(capacity.free_objects,MAX_OBJECTS);assert_eq!(capacity.free_bytes,MAX_QUEUE_BYTES);
    // Give the final full ACK its normal worker turn; no clock is overridden.
    let cleanup=Instant::now()+Duration::from_secs(5);
    while queue_objects(&node_queue)!=0 {
        assert!(Instant::now()<cleanup,"node must retire request/page/export copies");
        check_auto_node(&mut worker);
        std::thread::sleep(Duration::from_millis(10));
    }
    check_auto_node(&mut worker);
    worker.take().unwrap().shutdown_typed().unwrap();
    client.close();drop(client);
    assert_eq!(queue_objects(&node_queue),0);
    // Capacity is released only after the actual socket/key owner has joined.
    drop(input.begin().unwrap());drop(out.begin().unwrap());
    assert_eq!(runtime.lock().unwrap().head().unwrap(),expected);
    assert!(Instant::now()<deadline);
}

fn submit(worker:&Worker,mut command:Command,deadline:Instant) {
    loop {
        match worker.try_submit(command) {
            Ok(())=>return,
            Err(rejected)=>{
                assert_eq!(rejected.reason,"Peer command backpressure");
                assert!(Instant::now()<deadline,"bounded worker command submission");
                command=rejected.command;std::thread::sleep(Duration::from_millis(1));
            },
        }
    }
}
fn notice(worker:&Worker,deadline:Instant)->Notification {
    loop {
        match worker.try_notification() {
            Ok(value)=>return value,
            Err(std::sync::mpsc::TryRecvError::Empty)=>{
                assert!(Instant::now()<deadline,"bounded worker bridge notification wait");
                assert!(!worker.is_finished(),"worker must remain live until explicit test shutdown");
                std::thread::sleep(Duration::from_millis(1));
            },
            Err(std::sync::mpsc::TryRecvError::Disconnected)=>panic!("worker bridge unexpectedly disconnected"),
        }
    }
}
struct BridgePair {
    client:Worker,
    node:Worker,
    wallet:Arc<Mutex<HybridRuntime>>,
    host:Arc<Mutex<HybridRuntime>>,
    out:Registry,
    input:Registry,
    client_queue:PathBuf,
    node_queue:PathBuf,
    _wallet_scope:Scope,
    _host_scope:Scope,
}
impl BridgePair {
    fn new()->Self {
        let host_scope=Scope::new();let wallet_scope=Scope::new();
        let (host,g,_,_,_)=fixture(&host_scope);let (wallet,_,_,_,_)=fixture(&wallet_scope);
        let host=Arc::new(Mutex::new(host));let wallet=Arc::new(Mutex::new(wallet));
        let a=HybridKey::generate(Role::Transport).unwrap();let b=HybridKey::generate(Role::Transport).unwrap();
        let pa=Endpoint::pinned(a.public().clone(),1).unwrap();let pb=Endpoint::pinned(b.public().clone(),1).unwrap();
        let out=Registry::new_wallet_history_client(g.genesis,g.fingerprint,pa.clone(),vec![pb.clone()],1,1).unwrap();
        let input=Registry::new_wallet_history_clients(g.genesis,g.fingerprint,pb.clone(),vec![pa.clone()],1,1).unwrap();
        let (client_connection,node_connection)=connections(&out,&input,&a,&b,&pa,&pb);
        let client_queue=wallet_scope.0.join("bridge-client.sqlite");let node_queue=host_scope.0.join("bridge-node.sqlite");
        let cq=ObjectQueue::open_history(&client_queue,client_connection.peer_id(),false,true).unwrap();
        let nq=ObjectQueue::open_history(&node_queue,node_connection.peer_id(),false,true).unwrap();
        let client=Worker::start_typed(client_connection,cq,wallet.clone()).unwrap();
        let node=Worker::start_history_node_typed(node_connection,nq,host.clone(),HistoryBudget::default()).unwrap();
        Self {client,node,wallet,host,out,input,client_queue,node_queue,_wallet_scope:wallet_scope,_host_scope:host_scope}
    }
    fn exchange(&self,deadline:Instant)->(HistoryRequest,Offer,HistoryPage,HistoryPlanAdmission) {
        let req=request(1,&self.wallet.lock().unwrap());let id=req.object_id().unwrap();
        submit(&self.client,Command::Enqueue{kind:ObjectKind::HistoryRequestV1,bytes:req.encode().unwrap()},deadline);
        let Notification::Advertised(request_offer)=notice(&self.client,deadline) else {panic!("worker must advertise the actual request")};
        assert_eq!(request_offer.id,id);assert_eq!(request_offer.kind,ObjectKind::HistoryRequestV1);
        let Notification::Dispatched(DispatchEvent::Transport(Event::Offered(page_offer)))=notice(&self.client,deadline) else {panic!("automatic node must offer the response")};
        assert_eq!(page_offer.kind,ObjectKind::HistoryPageV1);
        submit(&self.client,Command::RequestMissing{object:page_offer.id},deadline);
        let Notification::RequestWindow{object,start,count}=notice(&self.client,deadline) else {panic!("worker requests a bounded page window")};
        assert_eq!(object,page_offer.id);assert_eq!(start,0);
        assert_eq!(usize::from(count),page_offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD));
        assert!(count<=4,"empty tip page carries three bounded full anchors");
        let Notification::Dispatched(DispatchEvent::HistoryPage{offer,page,..})=notice(&self.client,deadline) else {panic!("worker must deliver decoded canonical page")};
        assert_eq!(offer,page_offer);page.validate_for(&req).unwrap();assert_eq!(page.status,HistoryStatus::AtSnapshotTip);
        assert!(page.entries.is_empty());assert_eq!(page.from_anchor,self.wallet.lock().unwrap().head().unwrap());
        submit(&self.client,Command::QueryWindow{object:offer.id,start,count},deadline);
        let Notification::WindowProgress{object,missing,..}=notice(&self.client,deadline) else {panic!("worker must report durable page progress")};
        assert_eq!(object,offer.id);assert_eq!(missing,0);
        submit(&self.client,Command::HistoryAcceptPlan{request:id,page:offer.id,members:vec![]},deadline);
        let Notification::HistoryPlanAccepted{request,page:page_id,grant}=notice(&self.client,deadline) else {panic!("actual worker acceptance must mint the opaque grant")};
        assert_eq!(request,id);assert_eq!(page_id,offer.id);
        (req,offer,page,grant)
    }
    fn retire_controls(&self,req:&HistoryRequest,offer:&Offer,deadline:Instant) {
        // This empty page was fully decoded/correlated and the owned transport
        // plan accepted before any ACK or public transport-copy retirement.
        submit(&self.client,Command::Receipt{object:offer.id,start:0,
            count:offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD) as u16},deadline);
        submit(&self.client,Command::HistoryRetireRequest{request:req.object_id().unwrap()},deadline);
        let Notification::HistoryReclaimed{object}=notice(&self.client,deadline) else {panic!("request retirement")};
        assert_eq!(object,req.object_id().unwrap());
        submit(&self.client,Command::HistoryRetirePlan{page:offer.id},deadline);
        let Notification::HistoryReclaimed{object}=notice(&self.client,deadline) else {panic!("page retirement")};
        assert_eq!(object,offer.id);
        while queue_objects(&self.node_queue)!=0 {
            assert!(Instant::now()<deadline,"node retires its acknowledged empty page");
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(queue_objects(&self.client_queue),0);
    }
    fn join(self) {
        assert!(!self.client.is_finished());assert!(!self.node.is_finished());
        self.node.shutdown_typed().unwrap();
        // Node shutdown closes the TCP peer. The wallet may observe that normal
        // departure before its own explicit stop reaches its receive boundary.
        if let Err(error)=self.client.shutdown_typed() {
            let crate::hybrid_peer_error_v2::PeerFailure::Other(message)=error else {panic!("peer close must not become expiry")};
            assert!(message.contains("Closed"),"unexpected wallet shutdown failure: {message}");
        }
        drop(self.input.begin().unwrap());drop(self.out.begin().unwrap());
        assert_eq!(self.wallet.lock().unwrap().head().unwrap(),self.host.lock().unwrap().head().unwrap());
    }
    fn retire_and_join(self,req:&HistoryRequest,offer:&Offer,deadline:Instant) {
        self.retire_controls(req,offer,deadline);self.join();
    }
}

#[test]
fn b1_worker_bridge_grant_requires_exact_live_worker_session_and_request_page() {
    let deadline=Instant::now()+Duration::from_secs(300);
    let first=BridgePair::new();let second=BridgePair::new();let correct=BridgePair::new();
    let (r1,o1,p1,g1)=first.exchange(deadline);
    let other_live_proof=second.client.history_session().unwrap();
    assert!(ReceiverHistoryPlan::from_admitted_plan(other_live_proof,&r1,&o1,p1,&*first.wallet.lock().unwrap(),g1).is_err(),
        "actual grant from one worker cannot authorize a second live wallet worker");
    let (r2,o2,p2,g2)=second.exchange(deadline);
    let mut changed_request=r2.clone();changed_request.sequence+=1;
    let mut changed_page=p2;changed_page.request_object_id=changed_request.object_id().unwrap();
    let raw=changed_page.encode().unwrap();
    let changed_offer=Offer {kind:ObjectKind::HistoryPageV1,
        id:mutiny_transport_v2::objects::object_id(ObjectKind::HistoryPageV1,&raw).unwrap(),length:raw.len()};
    assert!(ReceiverHistoryPlan::from_admitted_plan(second.client.history_session().unwrap(),&changed_request,&changed_offer,
        changed_page,&*second.wallet.lock().unwrap(),g2).is_err(),"a self-consistent alternate request/page cannot reuse the actual grant");
    let (r3,o3,p3,g3)=correct.exchange(deadline);
    let accepted=ReceiverHistoryPlan::from_admitted_plan(correct.client.history_session().unwrap(),&r3,&o3,p3,
        &*correct.wallet.lock().unwrap(),g3).unwrap();
    assert!(accepted.complete());assert!(accepted.next_entry().is_none());
    first.retire_and_join(&r1,&o1,deadline);second.retire_and_join(&r2,&o2,deadline);correct.retire_and_join(&r3,&o3,deadline);
    let stale=BridgePair::new();let (r4,o4,p4,g4)=stale.exchange(deadline);
    stale.retire_controls(&r4,&o4,deadline);
    let still_live=stale.client.history_session().unwrap();still_live.check_current().unwrap();
    assert!(ReceiverHistoryPlan::from_admitted_plan(still_live,&r4,&o4,p4,&*stale.wallet.lock().unwrap(),g4).is_err(),
        "retiring the actual transport plan invalidates its unconsumed grant even while the worker session stays live");
    stale.join();
    assert!(Instant::now()<deadline);
}

fn queued_kinds(path:&Path)->Vec<u8> {
    let db=rusqlite::Connection::open_with_flags(path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    db.busy_timeout(Duration::from_millis(250)).unwrap();
    let mut query=db.prepare("SELECT kind FROM objects ORDER BY kind").unwrap();
    let result=query.query_map([],|r|r.get(0)).unwrap().map(|r|r.unwrap()).collect();result
}
fn request_is_complete(path:&Path,id:Hash)->bool {
    let db=rusqlite::Connection::open_with_flags(path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    db.busy_timeout(Duration::from_millis(250)).unwrap();
    db.query_row("SELECT EXISTS(SELECT 1 FROM objects WHERE id=?1 AND complete=1)",[id.as_slice()],|r|r.get(0)).unwrap()
}
fn next_small_page(client:&mut PeerLink,wallet:&mut HybridRuntime,worker:&Worker,deadline:Instant)->(Offer,HistoryPage) {
    loop {
        while worker.try_notification().is_ok() {}
        if !client.wait_for_frame_typed(deadline.min(Instant::now()+Duration::from_millis(20))).unwrap() {
            assert!(Instant::now()<deadline,"bounded real-time page wait");continue;
        }
        let received=client.receive_typed(limit(deadline)).unwrap();
        match hybrid_dispatch_v2::dispatch_peer(wallet,client,received).unwrap() {
            DispatchEvent::Transport(Event::Requested)=>{
                while let Some(frame)=client.with_current(|l|l.send_one()).unwrap().unwrap(){send(client,&frame,deadline);}
            },
            DispatchEvent::Transport(Event::Offered(offer))=>{
                assert_eq!(offer.kind,ObjectKind::HistoryPageV1);
                assert!(offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD)<=16);
                begin_window(client,offer,0,deadline);
            },
            DispatchEvent::Transport(Event::FragmentReceived|Event::ReceiptRecorded)=>{},
            DispatchEvent::HistoryPage{offer,page,..}=>return (offer,page),
            _=>panic!("only bounded history controls expected"),
        }
    }
}

#[test]
fn b1_overlapping_request_gets_delayed_busy_after_active_slots_retire() {
    let deadline=Instant::now()+Duration::from_secs(300);
    let host_scope=Scope::new();let wallet_scope=Scope::new();
    let (host,g,block1,_,_)=fixture(&host_scope);let (mut wallet,_,_,_,_)=fixture(&wallet_scope);
    let runtime=Arc::new(Mutex::new(host));
    let a=HybridKey::generate(Role::Transport).unwrap();let b=HybridKey::generate(Role::Transport).unwrap();
    let pa=Endpoint::pinned(a.public().clone(),1).unwrap();let pb=Endpoint::pinned(b.public().clone(),1).unwrap();
    let out=Registry::new_wallet_history_client(g.genesis,g.fingerprint,pa.clone(),vec![pb.clone()],1,1).unwrap();
    let input=Registry::new_wallet_history_clients(g.genesis,g.fingerprint,pb.clone(),vec![pa.clone()],1,1).unwrap();
    let (connection,node_connection)=connections(&out,&input,&a,&b,&pa,&pb);
    let cq=ObjectQueue::open_history(&wallet_scope.0.join("overlap-client.sqlite"),connection.peer_id(),false,true).unwrap();
    let node_queue=host_scope.0.join("overlap-node.sqlite");
    let nq=ObjectQueue::open_history(&node_queue,node_connection.peer_id(),false,true).unwrap();
    let mut client=connection.attach(cq).unwrap();
    let worker=Worker::start_history_node_typed(node_connection,nq,runtime.clone(),HistoryBudget::default()).unwrap();
    let first=request(1,&wallet);enqueue_request(&mut client,&first,deadline);
    let (old_offer,old_page)=next_small_page(&mut client,&mut wallet,&worker,deadline);
    assert_eq!(old_page.status,HistoryStatus::AtSnapshotTip);old_page.validate_for(&first).unwrap();
    let old_plan=ReceiverHistoryPlan::accept(&mut client,&first,&old_offer,old_page,&wallet).unwrap();assert!(old_plan.complete());
    let old_fragments=old_offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD) as u16;
    let held_ack=client.with_current(|l|l.receipt(&old_offer.id,0,old_fragments,0)).unwrap().unwrap();
    // Seal while the exact old page grant is live, but deliberately delay its
    // delivery. Subsequent authenticated request frames stay within the existing
    // 128-sequence replay window; no session reset or authority bypass is used.
    client.with_current(|l|l.history_retire_consumed_request(&first.object_id().unwrap())).unwrap().unwrap();
    client.with_current(|l|l.history_retire_plan(&old_offer.id)).unwrap().unwrap();
    let second=request(2,&wallet);let second_id=second.object_id().unwrap();enqueue_request(&mut client,&second,deadline);
    let received=client.receive_typed(limit(deadline)).unwrap();
    assert!(matches!(hybrid_dispatch_v2::dispatch_peer(&mut wallet,&mut client,received).unwrap(),DispatchEvent::Transport(Event::Requested)));
    while let Some(frame)=client.with_current(|l|l.send_one()).unwrap().unwrap(){send(&mut client,&frame,deadline);}
    while !request_is_complete(&node_queue,second_id) {
        assert!(Instant::now()<deadline);assert!(!worker.is_finished());
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(queued_kinds(&node_queue),vec![ObjectKind::HistoryRequestV1 as u8,ObjectKind::HistoryPageV1 as u8],
        "overlap retains one request beside the old page, never a second response plan");
    assert!(!client.wait_for_frame_typed(Instant::now()+Duration::from_millis(20)).unwrap(),"no overlap response before old plan retirement");
    // If overlap were incorrectly promoted to a normal export, this append
    // would produce a nonempty block page. The required reply is still BUSY.
    runtime.lock().unwrap().install(&block1).unwrap();
    let old_ack_sent=Instant::now();send(&mut client,&held_ack,deadline);
    let (busy_offer,busy_page)=next_small_page(&mut client,&mut wallet,&worker,deadline);
    busy_page.validate_for(&second).unwrap();assert_eq!(busy_page.status,HistoryStatus::Busy);
    assert!(busy_page.entries.is_empty());assert!(busy_page.offered_through_anchor.is_none());assert!(busy_page.observed_tip_anchor.is_none());
    assert!(old_ack_sent.elapsed()>=crate::history_service_v1::REFRESH,"old empty-tip completion retains its real ten-second retry cadence");
    assert_eq!(wallet.head().unwrap(),g);assert_eq!(runtime.lock().unwrap().head().unwrap().height,1);
    let accepted=ReceiverHistoryPlan::accept(&mut client,&second,&busy_offer,busy_page,&wallet).unwrap();assert!(accepted.complete());
    client.with_current(|l|l.history_retire_consumed_request(&second_id)).unwrap().unwrap();
    assert_eq!(queued_kinds(&node_queue),vec![ObjectKind::HistoryPageV1 as u8],"old page and consumed overlapping request have retired");
    full_ack(&mut client,&busy_offer,deadline);
    client.with_current(|l|l.history_retire_plan(&busy_offer.id)).unwrap().unwrap();
    while queue_objects(&node_queue)!=0 {assert!(Instant::now()<deadline);std::thread::sleep(Duration::from_millis(10));}
    let free=client.with_current(|l|l.history_general_capacity()).unwrap().unwrap();assert_eq!(free.free_objects,MAX_OBJECTS);
    worker.shutdown_typed().unwrap();client.close();drop(client);drop(input.begin().unwrap());drop(out.begin().unwrap());
    assert!(Instant::now()<deadline);
}
