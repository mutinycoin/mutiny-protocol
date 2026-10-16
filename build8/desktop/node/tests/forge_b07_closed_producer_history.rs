//! Opt-in B07: real passive B1 host and canonical receiver over >8 objects.
//! Original producer keys have already dropped. No signing/mining/Desktop claim.
#[path="forge_b07_closed_producer_history/inputs.rs"] mod inputs;
use mutinyd_v8::{hybrid_dispatch_v2::{self,DispatchEvent},hybrid_peer_admission_v2::{Connection,PeerLink,Registry},
    hybrid_peer_worker_v2::Worker,hybrid_runtime_v2::HybridRuntime,
    history_protocol_v1::{HistoryRequest,HistoryStatus},history_service_v1::{HistoryBudget,ReceiverHistoryPlan,REFRESH}};
use mutiny_crypto_v2::{HybridKey,Role};
use mutiny_transport_v2::{Endpoint,object_link::Event,objects::{ObjectKind,ObjectQueue,Offer,MAX_OBJECTS,MAX_QUEUE_BYTES,MAX_BITMAP_BITS}};
use std::{net::{TcpListener,TcpStream},path::Path,sync::{Arc,Mutex},time::{Duration,Instant}};

/// Every unwind closes and joins the sole host worker through its typed API.
struct OwnedWorker(Option<Worker>);
impl OwnedWorker {
    fn check(&mut self) {
        let worker=self.0.as_ref().expect("one owned passive host worker");
        let failure=match worker.try_notification() {
            Err(std::sync::mpsc::TryRecvError::Empty)=>None,
            Err(std::sync::mpsc::TryRecvError::Disconnected)=>Some("host notification channel disconnected"),
            Ok(_)=>Some("unexpected public notification in passive history-only host"),
        };
        if let Some(reason)=failure {
            let outcome=self.0.take().unwrap().shutdown_typed();panic!("{reason}; exact host outcome: {outcome:?}");
        }
        if self.0.as_ref().unwrap().is_finished() {
            let outcome=self.0.take().unwrap().shutdown_typed();panic!("passive host ended: {outcome:?}");
        }
    }
    fn finish(mut self) {self.check();self.0.take().unwrap().shutdown_typed().unwrap();}
}
impl Drop for OwnedWorker {
    fn drop(&mut self) {
        if let Some(worker)=self.0.take() {
            let result=worker.shutdown_typed();eprintln!("B07 unwind/guard typed host join: {result:?}");
        }
    }
}
fn connections(out:&Registry,input:&Registry,a:&HybridKey,b:&HybridKey,pa:&Endpoint,pb:&Endpoint)->(Connection,Connection) {
    let listener=TcpListener::bind("127.0.0.1:0").unwrap();assert!(listener.local_addr().unwrap().ip().is_loopback());
    let c=TcpStream::connect(listener.local_addr().unwrap()).unwrap();let s=listener.accept().unwrap().0;drop(listener);
    std::thread::scope(|threads| {
        let pending=input.begin().unwrap();let server=threads.spawn(||pending.respond(pa.id(),s,b,Duration::from_secs(30)).unwrap());
        let client=out.begin().unwrap().initiate(pb.id(),c,a,Duration::from_secs(30)).unwrap();(client,server.join().unwrap())
    })
}
fn limit(deadline:Instant)->Instant {assert!(Instant::now()<deadline,"finite B07 lifetime");deadline.min(Instant::now()+Duration::from_secs(5))}
fn send(peer:&mut PeerLink,frame:&[u8],deadline:Instant) {peer.send_typed(frame,limit(deadline)).unwrap();}
fn request(sequence:u32,wallet:&HybridRuntime)->HistoryRequest {
    HistoryRequest {sequence,saved_anchor:wallet.head().unwrap(),max_blocks:64,max_candidate_bytes:4_000_000,max_candidate_entries:6}
}
fn enqueue(peer:&mut PeerLink,request:&HistoryRequest,deadline:Instant) {
    let (_,frame)=peer.with_current(|link|link.enqueue(ObjectKind::HistoryRequestV1,&request.encode().unwrap(),0)).unwrap().unwrap();
    send(peer,&frame,deadline);
}
struct Window {offer:Offer,start:u16,count:u16}
fn window(peer:&mut PeerLink,offer:Offer,start:u16,deadline:Instant)->Window {
    let total=offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD) as u16;let count=(total-start).min(16);assert!(count>0);
    let frame=peer.with_current(|link|link.request_missing(&offer.id,start,count,0,false)).unwrap().unwrap();send(peer,&frame,deadline);
    Window {offer,start,count}
}
fn ack(peer:&mut PeerLink,offer:&Offer,deadline:Instant) {
    let total=offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD) as u16;
    for start in (0..total).step_by(MAX_BITMAP_BITS as usize) {
        let count=(total-start).min(MAX_BITMAP_BITS);let frame=peer.with_current(|link|link.receipt(&offer.id,start,count,0)).unwrap().unwrap();
        send(peer,&frame,deadline);
    }
}
fn occupancy(path:&Path)->(usize,usize) {
    let db=rusqlite::Connection::open_with_flags(path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    db.busy_timeout(Duration::from_millis(250)).unwrap();
    let value:(usize,usize)=db.query_row("SELECT count(*),coalesce(sum(length),0) FROM objects",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
    assert!(value.0<=MAX_OBJECTS&&value.1<=MAX_QUEUE_BYTES,"general history queue bounds: {value:?}");value
}

#[test]
#[ignore = "requires explicit closed owned TEST producer inputs"]
fn b07_closed_101_block_producer_tail_crosses_queue_capacity_with_real_budget_and_canonical_replay() {
    assert!(!mutiny_transport_v2::PRODUCTION_QUALIFIED);
    let started=Instant::now();let deadline=started+Duration::from_secs(3000);
    let input=inputs::ClosedInput::load();
    let mut suffix=[0;16];mutiny_crypto_v2::fill_os_random(&mut suffix).unwrap();
    let base=std::env::temp_dir().join(format!("forge-b07-closed-producer-{}",hex::encode(suffix)));
    assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
    let hp=base.join("host");let wp=base.join("receiver");
    for p in [&hp,&wp] {assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(p).unwrap());}
    input.copy_chain(&hp.join("chain.sqlite"));
    let host=inputs::runtime(&hp,&input.verified);let mut wallet=inputs::runtime(&wp,&input.verified);
    assert_eq!(host.head().unwrap(),input.expected_anchor);assert_eq!(wallet.head().unwrap().height,0);
    assert_eq!(host.confirmed_height(input.payment).unwrap(),Some(101));
    assert_eq!(wallet.confirmed_height(input.payment).unwrap(),None);
    {let chain=inputs::chain(&hp,&input.verified);assert_eq!(chain.load().unwrap().1.root().unwrap(),input.expected_root);}
    let runtime=Arc::new(Mutex::new(host));
    // Only ephemeral Transport keys, never the dropped producer signing keys.
    let a=HybridKey::generate(Role::Transport).unwrap();let b=HybridKey::generate(Role::Transport).unwrap();
    let pa=Endpoint::pinned(a.public().clone(),1).unwrap();let pb=Endpoint::pinned(b.public().clone(),1).unwrap();
    let g=&input.verified.genesis;
    let out=Registry::new_wallet_history_client(g.identity,g.fingerprint,pa.clone(),vec![pb.clone()],1,1).unwrap();
    let incoming=Registry::new_wallet_history_clients(g.identity,g.fingerprint,pb.clone(),vec![pa.clone()],1,1).unwrap();
    let (cc,nc)=connections(&out,&incoming,&a,&b,&pa,&pb);
    let cp=wp.join("history.sqlite");let np=hp.join("history.sqlite");
    let cq=ObjectQueue::open_history(&cp,cc.peer_id(),false,true).unwrap();let nq=ObjectQueue::open_history(&np,nc.peer_id(),false,true).unwrap();
    let mut peer=cc.attach(cq).unwrap();
    let mut worker=OwnedWorker(Some(Worker::start_history_node_typed(nc,nq,runtime.clone(),HistoryBudget::default()).unwrap()));
    let mut req=request(1,&wallet);enqueue(&mut peer,&req,deadline);
    let mut active:Option<Window>=None;let mut plan:Option<ReceiverHistoryPlan>=None;let mut page_id=None;
    let mut next_request:Option<(Instant,bool)>=None;let mut complete=false;
    let mut installed=0u64;let mut pages=0usize;let mut busy=0usize;let mut retries=0usize;
    let mut max_node=(0usize,0usize);let mut max_receiver=(0usize,0usize);let mut trace=Vec::new();
    while !complete {
        assert!(Instant::now()<deadline,"finite B07 catch-up deadline");worker.check();
        let n=occupancy(&np);let c=occupancy(&cp);
        max_node=(max_node.0.max(n.0),max_node.1.max(n.1));max_receiver=(max_receiver.0.max(c.0),max_receiver.1.max(c.1));
        if let Some((at,temporary))=next_request {
            if Instant::now()>=at {
                if temporary {retries+=1;}
                req=request(req.sequence.checked_add(1).unwrap(),&wallet);enqueue(&mut peer,&req,deadline);next_request=None;
            }
        }
        // Idle export/native work has no invented complete-frame deadline.
        let ready=peer.wait_for_frame_typed(deadline.min(Instant::now()+Duration::from_millis(20)))
            .unwrap_or_else(|e|panic!("B07 readiness: {e:?}"));worker.check();if !ready {continue;}
        let received=peer.receive_typed(limit(deadline)).unwrap();
        let event=hybrid_dispatch_v2::dispatch_peer(&mut wallet,&mut peer,received).unwrap();
        match event {
            DispatchEvent::Transport(Event::Requested)=> {
                while let Some(frame)=peer.with_current(|link|link.send_one()).unwrap().unwrap() {send(&mut peer,&frame,deadline);}
            },
            DispatchEvent::Transport(Event::ReceiptRecorded)=>{},
            DispatchEvent::Transport(Event::Offered(offer))=> {
                assert!(active.is_none(),"one semantic dependency/window");
                if offer.kind==ObjectKind::HistoryPageV1 {assert!(plan.is_none());}
                else {assert!(plan.as_ref().unwrap().next_entry().unwrap().matches_offer(&offer));}
                active=Some(window(&mut peer,offer,0,deadline));
            },
            DispatchEvent::Transport(Event::FragmentReceived)=> {
                let w=active.as_ref().unwrap();let bits=peer.with_current(|link|link.missing_window(&w.offer.id,w.start,w.count)).unwrap().unwrap();
                if bits.bits.iter().all(|missing|!*missing) {
                    let next=w.start+w.count;let offer=w.offer.clone();assert!(usize::from(next)<offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD));
                    active=Some(window(&mut peer,offer,next,deadline));
                }
            },
            DispatchEvent::HistoryPage {offer,page,..}=> {
                assert_eq!(active.take().unwrap().offer,offer);page.validate_for(&req).unwrap();assert!(page.entries.len()<=6);
                let status=page.status;let entries=page.entries.len();
                trace.push(serde_json::json!({"sequence":req.sequence,"status":status as u8,"entries":entries,
                    "saved_height":wallet.head().unwrap().height,"elapsed_seconds":started.elapsed().as_secs_f64()}));
                let accepted=ReceiverHistoryPlan::accept(&mut peer,&req,&offer,page,&wallet).unwrap();page_id=Some(offer.id);
                peer.with_current(|link|link.history_retire_consumed_request(&req.object_id().unwrap())).unwrap().unwrap();
                // Actual plan correlation precedes ACK; ACK grants no finality.
                ack(&mut peer,&offer,deadline);
                if accepted.complete() {
                    peer.with_current(|link|link.history_retire_plan(&offer.id)).unwrap().unwrap();
                    match status {
                        HistoryStatus::AtSnapshotTip=> {assert_eq!(wallet.head().unwrap(),input.expected_anchor);complete=true;},
                        HistoryStatus::Busy|HistoryStatus::EvidenceUnavailable|HistoryStatus::NodeUnavailable=> {
                            if status==HistoryStatus::Busy {busy+=1;}
                            next_request=Some((Instant::now()+REFRESH,true));
                        },
                        _=>panic!("unexpected empty/error history page: {status:?}"),
                    }
                }else {
                    assert!(matches!(status,HistoryStatus::More|HistoryStatus::Page));pages+=1;plan=Some(accepted);
                }
            },
            DispatchEvent::HistoryCandidate {offer,bytes}=> {
                assert_eq!(active.take().unwrap().offer,offer);assert_eq!(offer.kind,ObjectKind::CertifiedBlock,"closed producer has no recovery fixture");
                let before=wallet.head().unwrap();
                let receiver=plan.as_mut().unwrap();let _verified=receiver.install(&offer,&bytes,&mut wallet).unwrap();
                let after=wallet.head().unwrap();assert_eq!(after.height,before.height+1);installed+=1;
                assert_eq!(after.height,installed);assert!(installed<=101);
                // Canonical install above is the prerequisite for the public
                // direct-link reclaim API. No private token extractor is used.
                ack(&mut peer,&offer,deadline);let page=page_id.unwrap();
                peer.with_current(|link|link.history_reclaim_verified_candidate(&page,&offer.id)).unwrap().unwrap();
                if receiver.complete() {
                    peer.with_current(|link|link.history_retire_plan(&page)).unwrap().unwrap();plan=None;
                    next_request=Some((Instant::now(),false));
                }
            },
            _=>panic!("unexpected passive B07 event"),
        }
    }
    assert_eq!(installed,101);assert!(installed>MAX_OBJECTS as u64);assert!(pages>=17);
    assert_eq!(wallet.confirmed_height(input.payment).unwrap(),Some(101));
    let capacity=peer.with_current(|link|link.history_general_capacity()).unwrap().unwrap();
    assert_eq!(capacity.free_objects,MAX_OBJECTS);assert_eq!(capacity.free_bytes,MAX_QUEUE_BYTES);
    let cleanup=Instant::now()+Duration::from_secs(5);
    while occupancy(&np)!=(0,0) {assert!(Instant::now()<cleanup,"passive node transport cleanup");worker.check();std::thread::sleep(Duration::from_millis(10));}
    assert_eq!(occupancy(&cp),(0,0));worker.finish();peer.close();drop(peer);
    drop(incoming.begin().unwrap());drop(out.begin().unwrap());
    assert_eq!(runtime.lock().unwrap().head().unwrap(),input.expected_anchor);drop(runtime);drop(wallet);
    let restored=inputs::chain(&wp,&input.verified);let (head,state)=restored.load().unwrap();
    assert_eq!(head.height,101);assert_eq!(head.block,input.expected_anchor.block);assert_eq!(state.root().unwrap(),input.expected_root);
    assert_eq!(restored.confirmed_height(input.payment).unwrap(),Some(101));drop(restored);
    input.assert_unchanged();
    let result=serde_json::json!({"schema":"FORGE-B07-CLOSED-PRODUCER-PASSIVE-HISTORY-V1",
        "producer_public":input.public.display().to_string(),"original_producer_state":input.state.display().to_string(),
        "pins_sha256":input.pins_sha,"producer_result_sha256":input.result_sha,"original_chain_sha256":input.chain_sha,
        "source_inputs_unchanged":true,"producer_keys_previously_dropped":true,"copied_private_scope":base.display().to_string(),
        "canonical_blocks_verified":installed,"nonempty_pages":pages,"busy_pages":busy,"temporary_retries":retries,
        "final_anchor":hex::encode(input.expected_anchor.encode()),"final_root":hex::encode(input.expected_root),
        "confirmed_payment":hex::encode(input.payment),"confirmed_height":101,"host_queue_max_objects":max_node.0,
        "host_queue_max_bytes":max_node.1,"receiver_queue_max_objects":max_receiver.0,"receiver_queue_max_bytes":max_receiver.1,
        "queue_samples_checked_on_every_pump_turn":true,"queues_empty_after_cleanup":true,"host_typed_join_complete":true,
        "node_budget":"unchanged real rolling 32 global / 8 peer per 60 seconds; retained single owner",
        "temporary_retry_seconds":10,"no_history_transport_timing_overrides":true,
        "pending_cache_clock":"synthetic local t0+101 only; not the history budget clock or qualified UTC",
        "budget_exhaustion_asserted":false,"busy_observed":busy>0,"complete_frame_io_seconds":5,"readiness_wait_ms":20,
        "max_session_seconds":3000,"elapsed_seconds":started.elapsed().as_secs_f64(),"page_trace":trace,
        "loopback_only":true,"new_blocks_or_votes_or_rewards":0,"desktop_tested":false,"new_payment_admitted":false,
        "production_eligible":false,"rf_or_hardware_used":false});
    inputs::public_file(&base.join("result.json"),&result);
    println!("B07 verified passive long-tail result: {result}");
}
