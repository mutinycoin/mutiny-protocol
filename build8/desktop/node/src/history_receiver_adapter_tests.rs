//! UNRUN candidate regressions: real public fixture, direct admitted PeerLink,
//! and the wallet's single CanonicalStore; no runtime or pool is constructed.
use super::*;
use crate::{history_protocol_v1::HistoryEntry,
    hybrid_peer_admission_v2::{Registry,Connection,PeerLink}};
use mutiny_consensus_v8::{anchors::FinalizedAnchor,block_envelope_v2::BlockEnvelope,
    canonical_store_v2::{CanonicalStore,HistoryPreparation},execution::State,finality_v2::StoreError};
use mutiny_crypto_v2::{HybridKey,Role};
use mutiny_transport_v2::{Endpoint,object_link::Event,
    objects::{ObjectQueue,MAX_BITMAP_BITS}};
use std::{net::{TcpListener,TcpStream},path::PathBuf};

struct Scope(PathBuf);
impl Scope {
    fn new()->Self {
        let mut random=[0;16];mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
        let path=std::env::temp_dir().join(format!("b1-store-receiver-{}",hex::encode(random)));
        assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&path).unwrap());Self(path)
    }
}
impl Drop for Scope {fn drop(&mut self){std::fs::remove_dir_all(&self.0).unwrap();}}
fn fixture(scope:&Scope)->(CanonicalStore,FinalizedAnchor,Vec<u8>,Vec<u8>,Vec<u8>) {
    let f:serde_json::Value=serde_json::from_str(include_str!("../../qualification/hybrid-recovery-chain-public-v4.json")).unwrap();
    assert_eq!(f["synthetic_only"],true);assert_eq!(f["production_authorized"],false);assert_eq!(f["physical_tpm"],false);
    let raw=|v:&serde_json::Value|hex::decode(v.as_str().unwrap()).unwrap();
    let root:Hash=raw(&f["root"]).try_into().unwrap();
    let rows:Vec<_>=f["records"].as_array().unwrap().iter().map(|r|(raw(&r["key"]).try_into().unwrap(),raw(&r["record"]))).collect();
    let state=State::from_records(&rows,root).unwrap();
    let g=FinalizedAnchor::decode(&raw(&f["genesis_anchor"])).unwrap();
    let store=CanonicalStore::open_trusted_genesis(&scope.0.join("chain.sqlite"),&g,&state,root,1000,[255;32]).unwrap();
    (store,g,raw(&f["block1"]),raw(&f["recovery1"]),raw(&f["block2"]))
}
fn transaction_fixture(scope:&Scope)->(CanonicalStore,FinalizedAnchor,Vec<u8>,Hash) {
    let f:serde_json::Value=serde_json::from_str(include_str!("../../qualification/hybrid-canonical-store-public-v1.json")).unwrap();
    assert_eq!(f["synthetic_only"],true);assert_eq!(f["production_authorized"],false);
    let raw=|v:&serde_json::Value|hex::decode(v.as_str().unwrap()).unwrap();
    let root:Hash=raw(&f["root"]).try_into().unwrap();
    let rows:Vec<_>=f["records"].as_array().unwrap().iter().map(|r|(raw(&r["key"]).try_into().unwrap(),raw(&r["record"]))).collect();
    let state=State::from_records(&rows,root).unwrap();let g=FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
    let store=CanonicalStore::open_trusted_genesis(&scope.0.join("chain.sqlite"),&g,&state,root,1000,[255;32]).unwrap();
    (store,g,raw(&f["envelope"]),raw(&f["transaction_id"]).try_into().unwrap())
}
fn no_pool(scope:&Scope) {
    let files:Vec<_>=std::fs::read_dir(&scope.0).unwrap().map(|e|e.unwrap().file_name().into_string().unwrap()).collect();
    assert!(files.iter().all(|n|matches!(n.as_str(),"chain.sqlite"|"chain.sqlite-wal"|"chain.sqlite-shm"|"chain.sqlite-journal")),
        "borrowing verifier must not create a second owner/pool: {files:?}");
}
fn request(sequence:u32,anchor:FinalizedAnchor)->HistoryRequest {
    HistoryRequest{sequence,saved_anchor:anchor,max_blocks:64,max_candidate_bytes:4_000_000,max_candidate_entries:6}
}
fn connections(out:&Registry,input:&Registry,a:&HybridKey,b:&HybridKey,pa:&Endpoint,pb:&Endpoint)->(Connection,Connection) {
    let listener=TcpListener::bind("127.0.0.1:0").unwrap();assert!(listener.local_addr().unwrap().ip().is_loopback());
    let c=TcpStream::connect(listener.local_addr().unwrap()).unwrap();let s=listener.accept().unwrap().0;drop(listener);
    std::thread::scope(|threads|{
        let pending=input.begin().unwrap();let server=threads.spawn(||pending.respond(pa.id(),s,b,Duration::from_secs(30)).unwrap());
        let client=out.begin().unwrap().initiate(pb.id(),c,a,Duration::from_secs(30)).unwrap();(client,server.join().unwrap())
    })
}
fn links(scope:&Scope,g:&FinalizedAnchor)->(Registry,Registry,PeerLink,PeerLink) {
    let a=HybridKey::generate(Role::Transport).unwrap();let b=HybridKey::generate(Role::Transport).unwrap();
    let pa=Endpoint::pinned(a.public().clone(),1).unwrap();let pb=Endpoint::pinned(b.public().clone(),1).unwrap();
    let out=Registry::new_wallet_history_client(g.genesis,g.fingerprint,pa.clone(),vec![pb.clone()],1,1).unwrap();
    let input=Registry::new_wallet_history_clients(g.genesis,g.fingerprint,pb.clone(),vec![pa.clone()],1,1).unwrap();
    let (c,s)=connections(&out,&input,&a,&b,&pa,&pb);
    let cq=ObjectQueue::open_history(&scope.0.join("client.sqlite"),c.peer_id(),false,true).unwrap();
    let nq=ObjectQueue::open_history(&scope.0.join("node.sqlite"),s.peer_id(),false,true).unwrap();
    (out,input,c.attach(cq).unwrap(),s.attach(nq).unwrap())
}
fn limit(deadline:Instant)->Instant {assert!(Instant::now()<deadline,"bounded adapter test");deadline.min(Instant::now()+Duration::from_secs(5))}
fn event(peer:&mut PeerLink,deadline:Instant)->Event {
    let received=peer.receive_typed(limit(deadline)).unwrap();
    peer.dispatch_received_typed(received,|_,event|event).unwrap()
}
/// Exactly one requested window of at most 16 fragments is outstanding. The
/// caller supplies semantic verification before acknowledging a page/member.
fn transfer(send:&mut PeerLink,recv:&mut PeerLink,offer:&Offer,frame:Vec<u8>,deadline:Instant)->Vec<u8> {
    send.send_typed(&frame,limit(deadline)).unwrap();
    assert!(matches!(event(recv,deadline),Event::Offered(ref actual) if actual==offer));
    let total=offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD) as u16;
    let mut complete=None;
    for start in (0..total).step_by(16) {
        let count=(total-start).min(16);
        let want=recv.with_current_transport(|l|l.request_missing(&offer.id,start,count,0,false)).unwrap();
        recv.send_typed(&want,limit(deadline)).unwrap();assert!(matches!(event(send,deadline),Event::Requested));
        for _ in 0..count {
            let frame=send.with_current_transport(|l|l.send_one()).unwrap().expect("one bounded requested fragment");
            send.send_typed(&frame,limit(deadline)).unwrap();
            match event(recv,deadline) {
                Event::FragmentReceived=>{},
                Event::Completed{offer:actual,bytes}=>{assert_eq!(&actual,offer);assert!(complete.replace(bytes).is_none());},
                _=>panic!("only requested authenticated fragments"),
            }
        }
        assert!(send.with_current_transport(|l|l.send_one()).unwrap().is_none(),"no unrequested extra window");
    }
    complete.expect("real complete incoming object, not retained raw bytes")
}
fn ack(send:&mut PeerLink,recv:&mut PeerLink,offer:&Offer,deadline:Instant) {
    let total=offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD) as u16;
    for start in (0..total).step_by(MAX_BITMAP_BITS as usize) {
        let count=(total-start).min(MAX_BITMAP_BITS);
        let frame=recv.with_current_transport(|l|l.receipt(&offer.id,start,count,0)).unwrap();
        recv.send_typed(&frame,limit(deadline)).unwrap();assert!(matches!(event(send,deadline),Event::ReceiptRecorded));
    }
}
fn send_request(client:&mut PeerLink,node:&mut PeerLink,request:&HistoryRequest,deadline:Instant) {
    let raw=request.encode().unwrap();let (offer,frame)=client.with_current_transport(|l|l.enqueue(ObjectKind::HistoryRequestV1,&raw,0)).unwrap();
    assert_eq!(HistoryRequest::decode(&transfer(client,node,&offer,frame,deadline)).unwrap(),*request);
}
fn page(request:&HistoryRequest,candidates:&[(ObjectKind,u64,Vec<u8>)],through:FinalizedAnchor)->HistoryPage {
    HistoryPage{request_object_id:request.object_id().unwrap(),status:HistoryStatus::Page,from_anchor:request.saved_anchor.clone(),
        offered_through_anchor:Some(through.clone()),observed_tip_anchor:Some(through),entries:candidates.iter().map(|(kind,height,raw)|
            HistoryEntry{kind:*kind,height:*height,object_id:object_id(*kind,raw).unwrap(),encoded_length:raw.len() as u32}).collect()}
}
fn accept(client:&mut PeerLink,node:&mut PeerLink,store:&mut CanonicalStore,request:&HistoryRequest,
    page:&HistoryPage,candidates:&[(ObjectKind,u64,Vec<u8>)],deadline:Instant)->(ReceiverHistoryPlan,Vec<Offer>) {
    send_request(client,node,request,deadline);
    let objects:Vec<_>=candidates.iter().map(|(kind,_,raw)|(*kind,raw.clone())).collect();
    let offers=node.with_current_transport(|l|l.enqueue_history_page(&request.object_id().unwrap(),&page.encode().unwrap(),&objects)).unwrap().unwrap();
    let frame=node.with_current_transport(|l|l.advertise(&offers[0].id,0)).unwrap();
    let raw=transfer(node,client,&offers[0],frame,deadline);let actual=HistoryPage::decode(&raw).unwrap();assert_eq!(&actual,page);
    let verifier=CanonicalHistoryVerifier::new(store);
    let plan=ReceiverHistoryPlan::accept(client,request,&offers[0],actual,&verifier).unwrap();
    ack(node,client,&offers[0],deadline);(plan,offers)
}
fn retire(client:&mut PeerLink,node:&mut PeerLink,request:&HistoryRequest,page:&Offer) {
    for peer in [client,node] {
        peer.with_current_transport(|l|l.history_retire_consumed_request(&request.object_id().unwrap())).unwrap();
        peer.with_current_transport(|l|l.history_retire_plan(&page.id)).unwrap();
    }
}

#[test]
fn b1_store_receiver_installs_actual_recovery_then_block_and_retirement_revokes_completed_proof() {
    let deadline=Instant::now()+Duration::from_secs(300);
    let host_scope=Scope::new();let wallet_scope=Scope::new();let transport_scope=Scope::new();
    let (mut host,g,block1,recovery,block2)=fixture(&host_scope);let (mut wallet,_,_,_,_)=fixture(&wallet_scope);
    let mut verifier=CanonicalHistoryVerifier::new(&mut host);
    verifier.history_install(&block1).unwrap();verifier.history_accept_recovery(&recovery).unwrap();let expected=verifier.history_install(&block2).unwrap();
    CanonicalHistoryVerifier::new(&mut wallet).history_install(&block1).unwrap();let parent=wallet.current_anchor().unwrap();assert_eq!(parent.height,1);
    let (_out,_input,mut client,mut node)=links(&transport_scope,&g);
    let request=request(1,parent.clone());
    let HistoryPreparation::Page(prepared)=host.prepare_history_page(&parent,64,4_000_000,6).unwrap() else {panic!("actual native export")};
    let candidates=vec![(ObjectKind::RecoveryEvidence,1,recovery),(ObjectKind::CertifiedBlock,2,block2)];
    assert_eq!(prepared.objects().iter().map(|o|(o.kind(),o.height(),o.bytes())).collect::<Vec<_>>(),
        candidates.iter().map(|(k,h,b)|(*k as u8,*h,b.as_slice())).collect::<Vec<_>>());
    let page=page(&request,&candidates,prepared.through().clone());
    let raw_page=page.encode().unwrap();let raw_offer=Offer{kind:ObjectKind::HistoryPageV1,
        id:object_id(ObjectKind::HistoryPageV1,&raw_page).unwrap(),length:raw_page.len()};
    assert!(ReceiverHistoryPlan::accept(&mut client,&request,&raw_offer,page.clone(),
        &CanonicalHistoryVerifier::new(&mut wallet)).is_err(),"correct retained raw page cannot mint a fresh grant");
    let (mut plan,offers)=accept(&mut client,&mut node,&mut wallet,&request,&page,&candidates,deadline);
    let proof=client.history_session().unwrap();let mut final_reclaim=None;
    let block_offer=&offers[2];
    assert!(plan.install(block_offer,&candidates[1].2,&mut CanonicalHistoryVerifier::new(&mut wallet)).is_err(),
        "actual successor cannot skip the planned recovery authority");
    assert_eq!(wallet.current_anchor().unwrap(),parent);
    for (i,(kind,_,expected_bytes)) in candidates.iter().enumerate() {
        let member=&offers[i+1];assert!(plan.next_entry().unwrap().matches_offer(member));
        let frame=node.with_current_transport(|l|l.advertise(&member.id,0)).unwrap();let raw=transfer(&mut node,&mut client,member,frame,deadline);assert_eq!(&raw,expected_bytes);
        let reclaim=plan.install(member,&raw,&mut CanonicalHistoryVerifier::new(&mut wallet)).unwrap();
        ack(&mut node,&mut client,member,deadline);
        if *kind==ObjectKind::RecoveryEvidence {
            assert_eq!(wallet.current_anchor().unwrap(),parent,"native recovery installs authority without advancing history");
            assert_eq!(reclaim.into_parts(&proof).unwrap(),(offers[0].id,member.id));
        } else {final_reclaim=Some(reclaim);}
    }
    assert!(plan.complete());assert_eq!(wallet.current_anchor().unwrap(),expected);
    retire(&mut client,&mut node,&request,&offers[0]);proof.check_current().unwrap();
    assert!(final_reclaim.unwrap().into_parts(&proof).is_err(),"post-commit plan retirement cannot release a stale reclaim proof");
    assert_eq!(wallet.current_anchor().unwrap(),expected,"retirement never rolls back native canonical state");
    no_pool(&wallet_scope);no_pool(&host_scope);
}

#[test]
fn b1_store_receiver_lying_terminal_and_pre_retired_lease_refuse_before_native_head_change() {
    for stale in [false,true] {
        let deadline=Instant::now()+Duration::from_secs(300);
        let wallet_scope=Scope::new();let transport_scope=Scope::new();let (mut wallet,g,block,_,_)=fixture(&wallet_scope);
        let (_out,_input,mut client,mut node)=links(&transport_scope,&g);let request=request(1,g.clone());
        let through=CanonicalHistoryVerifier::new(&mut wallet).history_decode_anchor(&block).unwrap();let candidates=vec![(ObjectKind::CertifiedBlock,1,block.clone())];
        let mut page=page(&request,&candidates,through);
        if !stale {page.offered_through_anchor.as_mut().unwrap().block[0]^=1;page.observed_tip_anchor=page.offered_through_anchor.clone();}
        let (mut plan,offers)=accept(&mut client,&mut node,&mut wallet,&request,&page,&candidates,deadline);
        let frame=node.with_current_transport(|l|l.advertise(&offers[1].id,0)).unwrap();let raw=transfer(&mut node,&mut client,&offers[1],frame,deadline);
        if stale {retire(&mut client,&mut node,&request,&offers[0]);client.history_session().unwrap().check_current().unwrap();}
        let error=plan.install(&offers[1],&raw,&mut CanonicalHistoryVerifier::new(&mut wallet)).err().expect("actual accepted grant must refuse");
        if !stale {assert!(format!("{error:?}").contains("terminal full anchor"),"must reach the pre-commit full-anchor check");}
        else {assert!(format!("{error:?}").contains("retired"),"must refuse on the actual revoked plan lease: {error:?}");}
        assert_eq!(wallet.current_anchor().unwrap(),g);assert!(!plan.complete());no_pool(&wallet_scope);
    }
}

#[test]
fn b1_store_receiver_canonical_decodable_native_signature_failure_preserves_head_and_progress() {
    for half in 0..2 {
        let deadline=Instant::now()+Duration::from_secs(300);
        let wallet_scope=Scope::new();let transport_scope=Scope::new();let (mut wallet,g,block,_,_)=fixture(&wallet_scope);
        let capacity=wallet.proposal_body_capacity(&BlockEnvelope::untrusted_header(&block).unwrap()).unwrap();
        let mut wrong=BlockEnvelope::decode_with_capacity(&block,&capacity).unwrap();
        if half==0 {wrong.certificate.votes[0].signature.ed448[0]^=1;} else {
            assert_eq!(wrong.certificate.votes[0].signature.fndsa[0],0x3a);
            wrong.certificate.votes[0].signature.fndsa[17]^=1;
            assert_eq!(wrong.certificate.votes[0].signature.fndsa[0],0x3a);
        }
        let raw=wrong.encode_with_capacity(&capacity).unwrap();assert_eq!(BlockEnvelope::decode_with_capacity(&raw,&capacity).unwrap(),wrong,"must pass canonical decode");
        let candidates=vec![(ObjectKind::CertifiedBlock,1,raw.clone())];let request=request(1,g.clone());let page=page(&request,&candidates,wrong.certificate.decision.anchor());
        let (_out,_input,mut client,mut node)=links(&transport_scope,&g);
        let (mut plan,offers)=accept(&mut client,&mut node,&mut wallet,&request,&page,&candidates,deadline);
        let frame=node.with_current_transport(|l|l.advertise(&offers[1].id,0)).unwrap();let received=transfer(&mut node,&mut client,&offers[1],frame,deadline);assert_eq!(received,raw);
        let error=plan.install(&offers[1],&received,&mut CanonicalHistoryVerifier::new(&mut wallet)).err().expect("native certificate must refuse");
        assert!(format!("{error:?}").contains("Verification"),"failure must reach native verification: {error:?}");
        assert_eq!(wallet.current_anchor().unwrap(),g);assert_eq!(plan.next_entry().unwrap().object_id,offers[1].id);assert!(!plan.complete());
        // Retirement after the failed atomic attempt also leaves no path to
        // install a correctly signed member through the old grant.
        retire(&mut client,&mut node,&request,&offers[0]);client.history_session().unwrap().check_current().unwrap();
        let good=Offer{kind:ObjectKind::CertifiedBlock,id:object_id(ObjectKind::CertifiedBlock,&block).unwrap(),length:block.len()};
        let stale=plan.install(&good,&block,&mut CanonicalHistoryVerifier::new(&mut wallet)).err().expect("retired lease");
        assert!(format!("{stale:?}").contains("retired"),"retirement must be checked before the changed candidate identity: {stale:?}");
        assert_eq!(wallet.current_anchor().unwrap(),g);no_pool(&wallet_scope);
    }
}

#[test]
fn b1_store_current_anchor_refuses_halted_and_corrupt_schema() {
    for halted in [false,true] {
        let scope=Scope::new();let (store,g,_,_,_)=fixture(&scope);assert_eq!(store.current_anchor().unwrap(),g);
        // An independent writer corrupts/latches only this isolated fixture.
        // Neither case authorizes an accessor to mint a usable current anchor.
        let db=rusqlite::Connection::open(scope.0.join("chain.sqlite")).unwrap();
        if halted {
            assert_eq!(db.execute("UPDATE integrity_v2 SET halted=1 WHERE id=1",[]).unwrap(),1);
            assert!(matches!(store.current_anchor(),Err(StoreError::Halted)));
        } else {
            db.pragma_update(None,"user_version",99).unwrap();
            assert!(matches!(store.current_anchor(),Err(StoreError::Integrity)));
        }
        drop(db);drop(store);no_pool(&scope);
    }
}

/// Test-only wallet ownership wrapper. This does not implement HistoryVerifier:
/// the sole verifier is the real borrowing CanonicalHistoryVerifier. The small
/// local outbox is reconciled by actual canonical confirmation lookups.
struct WalletOwner {
    chain:CanonicalStore,
    snapshot:Option<FinalizedAnchor>,
    outbox:Vec<Hash>,
    invalidations:usize,
    reloads:usize,
    reconciliations:usize,
}
impl WalletOwner {
    fn begin_install(&mut self,plan:&mut ReceiverHistoryPlan,offer:&Offer,raw:&[u8])
        ->PeerResult<VerifiedHistoryReclaim> {
        self.snapshot=None;self.invalidations+=1;
        assert!(self.snapshot.is_none(),"snapshot invalidated BEFORE entering actual canonical verifier");
        let result=plan.install(offer,raw,&mut CanonicalHistoryVerifier::new(&mut self.chain));
        assert!(self.snapshot.is_none(),"old cache cannot become visible between native return and wallet reconciliation");
        result
    }
    fn finish_install(&mut self,result:PeerResult<VerifiedHistoryReclaim>,session:&AdmittedHistorySession)
        ->PeerResult<(Hash,Hash)> {
        // A post-commit reclaim refusal is still an error visible to this wallet
        // operation. Do not return it before re-reading the committed store.
        let result=result.and_then(|verified|verified.into_parts(session));
        assert!(self.snapshot.is_none());
        let pending=self.outbox.iter().copied().filter_map(|id|match self.chain.confirmed_height(id).unwrap() {
            Some(_)=>None,None=>Some(id),
        }).collect();
        self.outbox=pending;self.reconciliations+=1;
        let anchor=self.chain.current_anchor().unwrap();
        let (head,state)=self.chain.load().unwrap();
        assert_eq!(head.height,anchor.height);assert_eq!(head.block,anchor.block);assert_eq!(head.root,state.root().unwrap());
        self.snapshot=Some(anchor);self.reloads+=1;
        result
    }
}

#[test]
fn b1_wallet_owner_invalidates_before_install_and_reconciles_after_success_native_failure_and_postcommit_refusal() {
    let deadline=Instant::now()+Duration::from_secs(300);
    // 0: ordinary success, 1: actual commit then reclaim refusal after plan
    // retirement, 2: actual canonical-decodable native certificate failure.
    for outcome in 0..3 {
        let wallet_scope=Scope::new();let transport_scope=Scope::new();
        let (chain,g,block,transaction)=transaction_fixture(&wallet_scope);
        let unknown=[0x79;32];assert_ne!(unknown,transaction);
        assert!(chain.confirmed_height(transaction).unwrap().is_none());assert!(chain.confirmed_height(unknown).unwrap().is_none());
        let mut wallet=WalletOwner{chain,snapshot:Some(g.clone()),outbox:vec![transaction,unknown],
            invalidations:0,reloads:0,reconciliations:0};
        let mut raw=block;
        if outcome==2 {
            let capacity=wallet.chain.proposal_body_capacity(&BlockEnvelope::untrusted_header(&raw).unwrap()).unwrap();
            let mut wrong=BlockEnvelope::decode_with_capacity(&raw,&capacity).unwrap();wrong.certificate.votes[0].signature.ed448[0]^=1;
            raw=wrong.encode_with_capacity(&capacity).unwrap();assert_eq!(BlockEnvelope::decode_with_capacity(&raw,&capacity).unwrap(),wrong);
        }
        let through=CanonicalHistoryVerifier::new(&mut wallet.chain).history_decode_anchor(&raw).unwrap();
        let candidates=vec![(ObjectKind::CertifiedBlock,1,raw.clone())];let request=request(1,g.clone());let page=page(&request,&candidates,through.clone());
        let (_out,_input,mut client,mut node)=links(&transport_scope,&g);
        let (mut plan,offers)=accept(&mut client,&mut node,&mut wallet.chain,&request,&page,&candidates,deadline);
        let session=client.history_session().unwrap();let frame=node.with_current_transport(|l|l.advertise(&offers[1].id,0)).unwrap();
        let received=transfer(&mut node,&mut client,&offers[1],frame,deadline);
        assert_eq!(wallet.snapshot.as_ref(),Some(&g));assert_eq!(wallet.outbox,vec![transaction,unknown]);
        let installed=wallet.begin_install(&mut plan,&offers[1],&received);
        assert_eq!(wallet.invalidations,1);assert!(wallet.snapshot.is_none());assert_eq!(wallet.reconciliations,0);assert_eq!(wallet.reloads,0);
        if outcome==2 {
            let error=installed.as_ref().err().expect("native rejection");assert!(format!("{error:?}").contains("Verification"));
            assert_eq!(wallet.chain.current_anchor().unwrap(),g);
        } else {
            assert!(installed.is_ok());assert_eq!(wallet.chain.current_anchor().unwrap(),through);
            assert_eq!(wallet.chain.confirmed_height(transaction).unwrap(),Some(1),"actual native commit confirms the wallet's own outbox item");
        }
        if outcome==1 {
            // Deliberately AFTER a successful indivisible native install and
            // BEFORE proof consumption. No callback runs inside verification.
            retire(&mut client,&mut node,&request,&offers[0]);session.check_current().unwrap();
        }
        let result=wallet.finish_install(installed,&session);
        assert_eq!(wallet.reconciliations,1);assert_eq!(wallet.reloads,1);
        if outcome==2 {
            assert!(result.is_err());assert_eq!(wallet.snapshot.as_ref(),Some(&g));assert_eq!(wallet.outbox,vec![transaction,unknown]);
        } else {
            assert_eq!(wallet.snapshot.as_ref(),Some(&through));assert_eq!(wallet.outbox,vec![unknown],"confirmed item must be reconciled on BOTH success and post-commit refusal");
            if outcome==0 {assert_eq!(result.unwrap(),(offers[0].id,offers[1].id));}
            else {assert!(format!("{:?}",result.err().expect("actual retired proof")).contains("retired"));}
        }
        no_pool(&wallet_scope);
    }
}

#[path = "history_direct_reclaim_tests.rs"]
mod history_direct_reclaim_tests;
