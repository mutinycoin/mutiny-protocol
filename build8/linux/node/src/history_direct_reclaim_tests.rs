//! UNRUN R9: actual public fixture/native commit and direct authenticated links.
//! Reuse the R8 store-only fixture/pump; do not add a verifier or raw-hash bypass.
use super::*;

struct DirectSession {
    chain:CanonicalStore,
    client:PeerLink,
    node:PeerLink,
    plan:ReceiverHistoryPlan,
    request:HistoryRequest,
    offers:Vec<Offer>,
    raw:Vec<u8>,
    genesis:FinalizedAnchor,
    _out:Registry,
    _input:Registry,
    // Stores and carriers close before their private test directories disappear.
    _wallet_scope:Scope,
    _transport_scope:Scope,
}
impl DirectSession {
    fn new(deadline:Instant)->Self {
        let wallet_scope=Scope::new();let transport_scope=Scope::new();
        let (mut chain,g,block,_,_)=fixture(&wallet_scope);
        let (out,input,mut client,mut node)=links(&transport_scope,&g);
        let request=request(1,g.clone());
        let through=CanonicalHistoryVerifier::new(&mut chain).history_decode_anchor(&block).unwrap();
        let candidates=vec![(ObjectKind::CertifiedBlock,1,block)];
        let page=page(&request,&candidates,through);
        let (plan,offers)=accept(&mut client,&mut node,&mut chain,&request,&page,&candidates,deadline);
        let frame=node.with_current_transport(|l|l.advertise(&offers[1].id,0)).unwrap();
        let raw=transfer(&mut node,&mut client,&offers[1],frame,deadline);
        assert_eq!(raw,candidates[0].2);
        Self{chain,client,node,plan,request,offers,raw,genesis:g,_out:out,_input:input,
            _wallet_scope:wallet_scope,_transport_scope:transport_scope}
    }
    fn verify(&mut self,deadline:Instant)->VerifiedHistoryReclaim {
        let verified=self.plan.install(&self.offers[1],&self.raw,
            &mut CanonicalHistoryVerifier::new(&mut self.chain)).unwrap();
        assert!(self.plan.complete());assert_eq!(self.chain.current_anchor().unwrap().height,1);
        // ACK uses the current complete public copy, so it precedes consuming
        // the proof and deleting that transport copy.
        ack(&mut self.node,&mut self.client,&self.offers[1],deadline);
        verified
    }
    fn copy_present(&mut self)->bool {
        self.client.with_current_transport(|l|l.describe(&self.offers[1].id)).unwrap().1
    }
}

#[test]
fn b1_direct_link_consumes_actual_native_proof_and_reclaims_only_its_transport_copy() {
    let deadline=Instant::now()+Duration::from_secs(300);let mut session=DirectSession::new(deadline);
    let verified=session.verify(deadline);let head=session.chain.current_anchor().unwrap();
    assert!(session.copy_present());
    session.client.history_reclaim_verified(verified).unwrap();
    assert!(session.client.with_current_transport(|l|l.describe(&session.offers[1].id)).is_err(),
        "exact complete candidate copy is removed only after actual native proof");
    assert_eq!(session.chain.current_anchor().unwrap(),head,"canonical state is never reclaimed");
    session.client.history_session().unwrap().check_current().unwrap();
    retire(&mut session.client,&mut session.node,&session.request,&session.offers[0]);
    no_pool(&session._wallet_scope);
}

#[test]
fn b1_direct_link_wrong_live_session_refuses_proof_before_deleting_identical_candidate() {
    let deadline=Instant::now()+Duration::from_secs(300);
    let mut source=DirectSession::new(deadline);let mut target=DirectSession::new(deadline);
    assert_eq!(source.offers[1],target.offers[1],"same genuine block/HAVE bytes do not identify a session");
    let verified=source.verify(deadline);
    let source_proof=source.client.history_session().unwrap();let target_proof=target.client.history_session().unwrap();
    assert_ne!(source_proof.session_id(),target_proof.session_id());
    assert!(source.copy_present());assert!(target.copy_present());
    let error=target.client.history_reclaim_verified(verified).unwrap_err();
    assert!(format!("{error:?}").contains("another session"),"must reach opaque proof provenance check: {error:?}");
    source_proof.check_current().unwrap();target_proof.check_current().unwrap();
    assert!(source.copy_present());assert!(target.copy_present(),"wrong live proof cannot delete target's exact same hash");
    assert_eq!(target.chain.current_anchor().unwrap(),target.genesis);
    assert_eq!(source.chain.current_anchor().unwrap().height,1);
    no_pool(&source._wallet_scope);no_pool(&target._wallet_scope);
}

#[test]
fn b1_direct_link_retired_plan_refuses_actual_proof_while_session_and_copy_remain_live() {
    let deadline=Instant::now()+Duration::from_secs(300);let mut session=DirectSession::new(deadline);
    let verified=session.verify(deadline);let head=session.chain.current_anchor().unwrap();
    retire(&mut session.client,&mut session.node,&session.request,&session.offers[0]);
    session.client.history_session().unwrap().check_current().unwrap();assert!(session.copy_present());
    let error=session.client.history_reclaim_verified(verified).unwrap_err();
    assert!(format!("{error:?}").contains("retired"),"actual stale lease must refuse before transport action: {error:?}");
    assert!(session.copy_present(),"retired proof does not delete a retained public copy");
    assert_eq!(session.chain.current_anchor().unwrap(),head);
    no_pool(&session._wallet_scope);
}
