use super::*;
use crate::{Context, Endpoint, InitiatorPending, ResponderPending};
use mutiny_crypto_v2::{HybridKey, Role};

struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("build8-b1-link-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir(&path).unwrap(); Self(path)
    }
}
impl Drop for Directory { fn drop(&mut self) { let _ = std::fs::remove_dir_all(&self.0); } }
fn sessions(a: &HybridKey, b: &HybridKey) -> (Session, Session) {
    let ctx = Context::pinned([1;32], [2;32], Endpoint::pinned(a.public().clone(),1).unwrap(),
        Endpoint::pinned(b.public().clone(),1).unwrap()).unwrap();
    let (i,hello)=InitiatorPending::start(ctx.clone(),a).unwrap();
    let (r,response)=ResponderPending::accept(ctx,b,&hello).unwrap();
    let (i,finish)=i.accept(a,&response).unwrap();
    let (r,tag)=r.finish(&finish).unwrap();
    (i.finish(&tag).unwrap(),r)
}
fn links(dir: &Directory, a: &HybridKey, b: &HybridKey) -> (ObjectLink,ObjectLink) {
    let (wallet,node)=sessions(a,b);
    let wq=ObjectQueue::open_history(&dir.0.join("wallet"), wallet.peer_id(),false,true).unwrap();
    let nq=ObjectQueue::open_history(&dir.0.join("node"), node.peer_id(),false,true).unwrap();
    (ObjectLink::new_authorized(wallet,wq,LocalAuthorization::NodeToWalletHistoryClient).unwrap(),
     ObjectLink::new_authorized(node,nq,LocalAuthorization::WalletHistoryClientToNode).unwrap())
}
fn receive_complete(sender: &mut ObjectLink, receiver: &mut ObjectLink, offer: &Offer, have: &[u8], ack: bool) {
    assert!(matches!(receiver.receive(have).unwrap(),Event::Offered(_)));
    let window=receiver.next_missing_request(&offer.id,0,false).unwrap().unwrap();
    sender.receive(&window.frame).unwrap();
    while let Some(frame)=sender.send_one().unwrap() { receiver.receive(&frame).unwrap(); }
    assert!(receiver.completed_incoming(&offer.id).is_ok());
    if ack {
        let frame=receiver.receipt(&offer.id,0,offer.length.div_ceil(crate::MAX_PAYLOAD) as u16,0).unwrap();
        sender.receive(&frame).unwrap();
    }
}

#[test]
fn b1_only_explicit_history_profiles_authorize_new_kinds_in_exact_directions() {
    for legacy in [LocalAuthorization::Unrestricted,LocalAuthorization::WalletClientToNode,
        LocalAuthorization::NodeToWalletClient] {
        for kind in [ObjectKind::HistoryRequestV1,ObjectKind::HistoryPageV1] {
            assert!(!legacy.incoming(kind)); assert!(!legacy.outgoing(kind));
        }
    }
    assert!(LocalAuthorization::WalletHistoryClientToNode.incoming(ObjectKind::HistoryRequestV1));
    assert!(!LocalAuthorization::WalletHistoryClientToNode.outgoing(ObjectKind::HistoryRequestV1));
    assert!(LocalAuthorization::NodeToWalletHistoryClient.incoming(ObjectKind::HistoryPageV1));
    for profile in [LocalAuthorization::WalletHistoryClientToNode, LocalAuthorization::NodeToWalletHistoryClient] {
        for kind in [ObjectKind::ContinuityVote,ObjectKind::BlockProposal,ObjectKind::SettlementProof,
            ObjectKind::WorkProbeRequest,ObjectKind::A2EvidenceOperation] {
            assert!(!profile.incoming(kind)); assert!(!profile.outgoing(kind));
        }
    }
}

#[test]
fn b1_plan_first_bounded_candidates_and_scoped_public_copy_lifecycle() {
    let dir=Directory::new();
    let a=HybridKey::generate(Role::Transport).unwrap(); let b=HybridKey::generate(Role::Transport).unwrap();
    let (mut wallet,mut node)=links(&dir,&a,&b);
    let (request,have)=wallet.enqueue(ObjectKind::HistoryRequestV1,b"opaque test request",0).unwrap();
    receive_complete(&mut wallet,&mut node,&request,&have,false);
    assert!(wallet.enqueue(ObjectKind::HistoryRequestV1,b"overlapping request",0).is_err());
    assert!(node.enqueue(ObjectKind::CertifiedBlock,b"unplanned",0).is_err());
    let candidates=vec![(ObjectKind::RecoveryEvidence,b"public recovery".to_vec()),
        (ObjectKind::CertifiedBlock,vec![5;281])];
    let offers=node.enqueue_history_page(&request.id,b"opaque verified test plan",&candidates).unwrap().unwrap();
    let page=offers[0].clone();
    assert!(node.advertise(&offers[1].id,0).is_err());
    let have=node.advertise(&page.id,0).unwrap();
    receive_complete(&mut node,&mut wallet,&page,&have,true);
    // Host has decoded and validated correlation/ordering before invoking this.
    wallet.history_accept_plan(&request.id,&page.id,&offers[1..]).unwrap();
    node.history_retire_consumed_request(&request.id).unwrap();
    wallet.history_retire_consumed_request(&request.id).unwrap();
    for member in &offers[1..] {
        let have=node.advertise(&member.id,0).unwrap();
        receive_complete(&mut node,&mut wallet,member,&have,false);
        assert!(node.history_reclaim_acknowledged_export(&page.id,&member.id).is_err());
        assert!(wallet.history_reclaim_verified_candidate(&[8;32],&member.id).is_err());
        let ack=wallet.receipt(&member.id,0,member.length.div_ceil(crate::MAX_PAYLOAD) as u16,0).unwrap();
        node.receive(&ack).unwrap();
        node.history_reclaim_acknowledged_export(&page.id,&member.id).unwrap();
        // Transport test models the host's post-canonical-commit callback; this
        // API invocation itself is deliberately not a claim of canonical proof.
        wallet.history_reclaim_verified_candidate(&page.id,&member.id).unwrap();
        assert!(wallet.describe(&member.id).is_err());
    }
    node.history_retire_plan(&page.id).unwrap(); wallet.history_retire_plan(&page.id).unwrap();
    assert_eq!(node.history_general_capacity().unwrap().free_objects,8);
    assert_eq!(wallet.history_general_capacity().unwrap().free_objects,8);
    assert!(wallet.enqueue(ObjectKind::HistoryRequestV1,b"next request",0).is_ok());
}

#[test]
fn b1_reconnect_retained_bytes_need_fresh_plan_and_preexisting_exports_are_not_owned() {
    let dir=Directory::new();
    let a=HybridKey::generate(Role::Transport).unwrap(); let b=HybridKey::generate(Role::Transport).unwrap();
    let (mut wallet,mut node)=links(&dir,&a,&b);
    let retained=node.queue.enqueue(ObjectKind::CertifiedBlock,b"retained public canonical bytes").unwrap();
    let (req,have)=wallet.enqueue(ObjectKind::HistoryRequestV1,b"q",0).unwrap();
    receive_complete(&mut wallet,&mut node,&req,&have,false);
    let offers=node.enqueue_history_page(&req.id,b"p",&[(retained.kind,b"retained public canonical bytes".to_vec())]).unwrap().unwrap();
    let page=offers[0].id;
    let have=node.advertise(&page,0).unwrap();
    receive_complete(&mut node,&mut wallet,&offers[0],&have,true);
    wallet.history_accept_plan(&req.id,&page,&offers[1..]).unwrap();
    let have=node.advertise(&retained.id,0).unwrap();
    receive_complete(&mut node,&mut wallet,&retained,&have,true);
    assert!(node.history_reclaim_acknowledged_export(&page,&retained.id).is_err());
    let wq=wallet.disconnect(); let nq=node.disconnect();
    let (w,n)=sessions(&a,&b);
    let wallet=ObjectLink::new_authorized(w,wq,LocalAuthorization::NodeToWalletHistoryClient).unwrap();
    let mut node=ObjectLink::new_authorized(n,nq,LocalAuthorization::WalletHistoryClientToNode).unwrap();
    assert!(wallet.completed_incoming(&retained.id).is_err());
    assert!(node.advertise(&retained.id,0).is_err());
    assert!(wallet.history_general_capacity().is_ok());
    assert_eq!(node.queue.read_complete(&retained.id).unwrap(),b"retained public canonical bytes");
}

#[test]
fn b1_actual_plan_lease_retirement_is_permanent_even_if_same_page_is_accepted_again() {
    let dir=Directory::new();
    let a=HybridKey::generate(Role::Transport).unwrap(); let b=HybridKey::generate(Role::Transport).unwrap();
    let (mut wallet,mut node)=links(&dir,&a,&b);
    let (request,have)=wallet.enqueue(ObjectKind::HistoryRequestV1,b"lease request one",0).unwrap();
    receive_complete(&mut wallet,&mut node,&request,&have,false);
    let offers=node.enqueue_history_page(&request.id,b"same opaque lease page",&[]).unwrap().unwrap();
    let page=offers[0].clone();
    assert!(wallet.history_plan_lease(&page.id).is_err());
    let have=node.advertise(&page.id,0).unwrap();
    receive_complete(&mut node,&mut wallet,&page,&have,true);
    wallet.history_accept_plan(&request.id,&page.id,&[]).unwrap();
    let old=wallet.history_plan_lease(&page.id).unwrap(); let old_clone=old.clone();
    assert!(old.check_current().is_ok());
    assert!(node.history_plan_lease(&page.id).is_err());
    wallet.history_retire_consumed_request(&request.id).unwrap();
    node.history_retire_consumed_request(&request.id).unwrap();
    wallet.history_retire_plan(&page.id).unwrap();node.history_retire_plan(&page.id).unwrap();
    assert!(old.check_current().is_err());assert!(old_clone.check_current().is_err());
    assert!(wallet.history_plan_lease(&page.id).is_err());
    let (request,have)=wallet.enqueue(ObjectKind::HistoryRequestV1,b"lease request two",0).unwrap();
    receive_complete(&mut wallet,&mut node,&request,&have,false);
    let offers=node.enqueue_history_page(&request.id,b"same opaque lease page",&[]).unwrap().unwrap();
    assert_eq!(offers[0].id,page.id);
    let have=node.advertise(&page.id,0).unwrap();
    receive_complete(&mut node,&mut wallet,&offers[0],&have,true);
    wallet.history_accept_plan(&request.id,&page.id,&[]).unwrap();
    let current=wallet.history_plan_lease(&page.id).unwrap();
    assert!(current.check_current().is_ok());assert!(old.check_current().is_err());
    let _retained=wallet.disconnect();
    assert!(current.check_current().is_err());assert!(old_clone.check_current().is_err());
}
