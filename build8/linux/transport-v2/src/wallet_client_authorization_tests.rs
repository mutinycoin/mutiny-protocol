use super::*;
use crate::{Context, Endpoint, InitiatorPending, ResponderPending};
use mutiny_crypto_v2::{HybridKey, Role};
use std::path::PathBuf;

struct Scope(PathBuf);
impl Scope {
    fn new() -> Self {
        let mut nonce=[0;16]; mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
        let p=std::env::temp_dir().join(format!("wallet-client-policy-{}", hex::encode(nonce)));
        std::fs::create_dir(&p).unwrap(); Self(p)
    }
}
impl Drop for Scope { fn drop(&mut self) { std::fs::remove_dir_all(&self.0).unwrap(); } }
fn sessions(a:&HybridKey,b:&HybridKey)->(Session,Session) {
    let c=Context::pinned([1;32],[2;32],Endpoint::pinned(a.public().clone(),1).unwrap(),Endpoint::pinned(b.public().clone(),1).unwrap()).unwrap();
    let(i,h)=InitiatorPending::start(c.clone(),a).unwrap();
    let(r,v)=ResponderPending::accept(c,b,&h).unwrap();
    let(i,f)=i.accept(a,&v).unwrap(); let(r,t)=r.finish(&f).unwrap(); (i.finish(&t).unwrap(),r)
}
fn pair(s:&Scope,a:&HybridKey,b:&HybridKey)->(ObjectLink,ObjectLink) {
    let(i,r)=sessions(a,b);
    let qi=ObjectQueue::open(&s.0.join("wallet.sqlite"),i.peer_id()).unwrap();
    let qr=ObjectQueue::open(&s.0.join("node.sqlite"),r.peer_id()).unwrap();
    (ObjectLink::new_authorized(i,qi,LocalAuthorization::NodeToWalletClient).unwrap(),
     ObjectLink::new_authorized(r,qr,LocalAuthorization::WalletClientToNode).unwrap())
}
fn offer(sender:&mut ObjectLink, kind:ObjectKind, raw:&[u8])->(Offer,Vec<u8>) {
    let o=Offer{id:crate::objects::object_id(kind,raw).unwrap(),kind,length:raw.len()};
    let(m,p)=o.have(0).unwrap(); let f=sender.session.seal(&m,&p).unwrap(); (o,f)
}
fn fragment(sender:&mut ObjectLink,o:&Offer,raw:&[u8])->Vec<u8> {
    let(mut m,_)=o.have(0).unwrap();m.kind=3; sender.session.seal(&m,raw).unwrap()
}

#[test]
fn wallet_client_exact_kind_allowlists_unknown_and_self_assertion_precede_queue() {
    let s=Scope::new();let a=HybridKey::generate(Role::Transport).unwrap();let b=HybridKey::generate(Role::Transport).unwrap();
    let(mut wallet,mut node)=pair(&s,&a,&b);
    for kind in [ObjectKind::SignedTransaction,ObjectKind::SettlementProof,ObjectKind::CertifiedBlock,
        ObjectKind::ContinuityVote,ObjectKind::WorkProbeRequest,ObjectKind::WorkProbeFragment,
        ObjectKind::RecoveryEvidence,ObjectKind::BlockProposal,ObjectKind::SignedOperation,
        ObjectKind::StatusQuery,ObjectKind::StatusReport,ObjectKind::A2BlockProposal,ObjectKind::A2EvidenceOperation] {
        let raw=[kind as u8];
        let(o,f)=offer(&mut wallet,kind,&raw);
        let allowed=matches!(kind,ObjectKind::SignedTransaction|ObjectKind::SignedOperation|ObjectKind::StatusQuery);
        if allowed {
            assert!(matches!(node.receive(&f).unwrap(),Event::Offered(_)));
            let f=fragment(&mut wallet,&o,&raw);
            let Event::Completed{bytes,..}=node.receive(&f).unwrap() else {panic!("candidate incomplete")};
            assert_eq!(bytes,raw);node.check_incoming_event(&Event::Offered(o.clone())).unwrap();
            node.discard(&o.id).unwrap();assert!(!node.incoming.contains(&o.id));
        } else {assert!(node.receive(&f).is_err());assert!(node.queue.describe(&o.id).is_err());}
        let(o,f)=offer(&mut node,kind,&raw);
        let allowed=matches!(kind,ObjectKind::CertifiedBlock|ObjectKind::RecoveryEvidence|ObjectKind::StatusReport);
        if allowed {wallet.receive(&f).unwrap();let f=fragment(&mut node,&o,&raw);assert!(matches!(wallet.receive(&f).unwrap(),Event::Completed{..}));wallet.discard(&o.id).unwrap();}
        else {assert!(wallet.receive(&f).is_err());assert!(wallet.queue.describe(&o.id).is_err());}
    }
    let o=Offer{id:[77;32],kind:ObjectKind::StatusQuery,length:1};let(m,mut p)=o.have(0).unwrap();p[1]=255;
    let f=wallet.session.seal(&m,&p).unwrap();assert!(node.receive(&f).is_err());assert!(node.queue.describe(&o.id).is_err());
    // A claimed capability is not a field in the locked Offer encoding.
    let(_,mut p)=o.have(0).unwrap();p.extend(b"WalletClient;role=Node;admin=true");
    let f=wallet.session.seal(&m,&p).unwrap();assert!(node.receive(&f).is_err());assert!(node.queue.describe(&o.id).is_err());
    assert!(node.enqueue(ObjectKind::SignedTransaction,b"unauthorized local relay",0).is_err());
    assert!(wallet.enqueue(ObjectKind::CertifiedBlock,b"self-granted node authority",0).is_err());
}

#[test]
fn wallet_client_reconnect_replay_requires_fresh_authenticated_offer() {
    let s=Scope::new();let a=HybridKey::generate(Role::Transport).unwrap();let b=HybridKey::generate(Role::Transport).unwrap();
    let(mut wallet,mut node)=pair(&s,&a,&b);let raw=b"public candidate bytes";
    let(o,f)=wallet.enqueue(ObjectKind::StatusQuery,raw,0).unwrap();let old_session=node.session_id();
    node.receive(&f).unwrap();let data=fragment(&mut wallet,&o,raw);node.receive(&data).unwrap();
    assert_eq!(node.completed_incoming(&o.id).unwrap().1,raw);
    let qw=wallet.disconnect();let qn=node.disconnect();let(i,r)=sessions(&a,&b);
    let mut wallet=ObjectLink::new_authorized(i,qw,LocalAuthorization::NodeToWalletClient).unwrap();
    let mut node=ObjectLink::new_authorized(r,qn,LocalAuthorization::WalletClientToNode).unwrap();
    assert_ne!(old_session,node.session_id());
    assert!(node.completed_incoming(&o.id).is_err());assert!(node.next_missing_request(&o.id,0,false).is_err());
    assert!(node.receive(&f).is_err()); // old authenticated frame cannot resume
    let premature=fragment(&mut wallet,&o,raw);assert!(node.receive(&premature).is_err());
    let mut m=o.have(0).unwrap().0;m.kind=2;let bitmap=Bitmap{start:0,bits:vec![true]}.encode(m.count).unwrap();
    let premature=node.session.seal(&m,&bitmap).unwrap();assert!(wallet.receive(&premature).is_err());assert!(wallet.wanted.is_empty());
    let fresh=wallet.advertise(&o.id,0).unwrap();node.receive(&fresh).unwrap();
    assert_eq!(node.completed_incoming(&o.id).unwrap().1,raw); // fresh authority, still opaque bytes
    let pin=Endpoint::pinned(a.public().clone(),2).unwrap();
    assert!(ObjectQueue::open(&s.0.join("node.sqlite"),pin.id()).is_err()); // generation substitution
}

#[test]
fn wallet_client_wrong_direction_controls_and_fragments_do_not_mutate_queue() {
    let s=Scope::new();let a=HybridKey::generate(Role::Transport).unwrap();let b=HybridKey::generate(Role::Transport).unwrap();
    let(mut wallet,mut node)=pair(&s,&a,&b);
    let(query,have)=wallet.enqueue(ObjectKind::StatusQuery,b"query",0).unwrap();node.receive(&have).unwrap();
    let(report,have)=node.enqueue(ObjectKind::StatusReport,b"hint",0).unwrap();wallet.receive(&have).unwrap();
    for k in [2,4,5] {
        let(mut m,_)=query.have(0).unwrap();m.kind=k;let p=Bitmap{start:0,bits:vec![true]}.encode(m.count).unwrap();
        let f=wallet.session.seal(&m,&p).unwrap();assert!(node.receive(&f).is_err());assert!(node.wanted.is_empty());
    }
    let f=fragment(&mut wallet,&report,b"hint");assert!(node.receive(&f).is_err());
    assert_eq!(node.queue.read_complete(&report.id).unwrap(),b"hint");
    assert!(!node.queue.describe(&query.id).unwrap().1);
    assert!(node.completed_incoming(&report.id).is_err());
    let request=wallet.request_missing(&report.id,0,1,0,false).unwrap();node.receive(&request).unwrap();
    let data=node.send_one().unwrap().unwrap();assert!(matches!(wallet.receive(&data).unwrap(),Event::Completed{..}));
    let ack=wallet.receipt(&report.id,0,1,0).unwrap();node.receive(&ack).unwrap();assert!(node.acknowledged(&report.id,0,1).unwrap().bits[0]);
}

#[test]
fn wallet_client_session_grants_are_bounded_and_discard_removes_authority() {
    let s=Scope::new();let a=HybridKey::generate(Role::Transport).unwrap();let b=HybridKey::generate(Role::Transport).unwrap();
    let(mut wallet,mut node)=pair(&s,&a,&b);let mut ids=Vec::new();
    for v in 1..=10 {
        let kind=if v<=2 {ObjectKind::SignedTransaction}else{ObjectKind::StatusQuery};
        let(o,f)=offer(&mut wallet,kind,&[v]);node.receive(&f).unwrap();ids.push(o.id);
    }
    assert_eq!(node.incoming.len(),crate::objects::MAX_REQUESTS);
    let(o,f)=offer(&mut wallet,ObjectKind::StatusQuery,&[11]);assert!(node.receive(&f).is_err());assert!(!node.incoming.contains(&o.id));
    node.discard(&ids[0]).unwrap();assert_eq!(node.incoming.len(),9);assert!(node.incoming_object(&ids[0]).is_err());
}

#[test]
fn wallet_client_expired_session_cannot_process_queued_work_or_admit_outbound() {
    let s=Scope::new();let a=HybridKey::generate(Role::Transport).unwrap();let b=HybridKey::generate(Role::Transport).unwrap();
    let(mut wallet,mut node)=pair(&s,&a,&b);
    let(o,f)=offer(&mut wallet,ObjectKind::StatusQuery,b"candidate");
    let queued=node.receive(&f).unwrap();
    node.session.expire_for_authorization_test();
    assert!(matches!(node.check_incoming_event(&queued),Err(Error::Expired)));
    assert!(matches!(node.next_missing_request(&o.id,0,false),Err(Error::Expired)));
    assert!(matches!(node.completed_incoming(&o.id),Err(Error::Expired)));
    let id=crate::objects::object_id(ObjectKind::StatusReport,b"hint").unwrap();
    assert!(matches!(node.enqueue(ObjectKind::StatusReport,b"hint",0),Err(Error::Expired)));
    assert!(node.queue.describe(&id).is_err());
}
