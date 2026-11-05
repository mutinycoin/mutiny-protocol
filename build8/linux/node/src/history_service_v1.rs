//! B1 node host owner. Fetch plans never confer canonical authority.
use crate::{hybrid_peer_admission_v2::AdmittedHistorySession,
    hybrid_peer_error_v2::{PeerFailure, PeerResult}, hybrid_runtime_v2::HybridRuntime,
    history_protocol_v1::{HistoryRequest, HistoryPage, HistoryStatus}};
use mutiny_consensus_v8::Hash;
use mutiny_transport_v2::{object_link::{HistoryPlanLease,LocalAuthorization}, objects::{HistoryCapacity, ObjectKind, Offer, object_id}};
use std::{collections::VecDeque, sync::{Arc,Mutex}, time::{Duration,Instant}};

pub const REFRESH: Duration = Duration::from_secs(10);
const WINDOW: Duration = Duration::from_secs(60);
const GLOBAL_EXPORTS: usize = 32;
const PEER_EXPORTS: usize = 8;

/// One shared node-wide owner, retained across reconnects and pin re-addition.
/// At most 32 rows/peer hashes survive in its rolling minute.
#[derive(Clone,Default)]
pub struct HistoryBudget(Arc<Mutex<VecDeque<(Instant,Hash)>>>);
impl HistoryBudget {
    fn charge(&self, peer:Hash, now:Instant)->PeerResult<bool> {
        let mut rows=self.0.lock().map_err(|_| "History budget poisoned")?;
        while rows.front().is_some_and(|(t,_)| now.saturating_duration_since(*t)>=WINDOW) {
            rows.pop_front();
        }
        if rows.len()>=GLOBAL_EXPORTS || rows.iter().filter(|(_,p)|*p==peer).count()>=PEER_EXPORTS {
            return Ok(false);
        }
        rows.push_back((now,peer)); Ok(true)
    }
}

/// Only this service can construct a queued publication. The worker checks the
/// exact live opaque session again when consuming it; no caller supplies bytes.
#[derive(Clone)]
pub struct PreparedHistoryPublication {
    session: AdmittedHistorySession,
    request: Hash,
    page: Vec<u8>,
    candidates: Vec<(ObjectKind,Vec<u8>)>,
}
impl PreparedHistoryPublication {
    pub(crate) fn into_parts(self,current:&AdmittedHistorySession)
        ->PeerResult<(Hash,Vec<u8>,Vec<(ObjectKind,Vec<u8>)>)> {
        self.session.check_current()?; current.check_current()?;
        if self.session.session_id()!=current.session_id()
            || self.session.peer_id()!=current.peer_id()
            || self.session.authorization()!=current.authorization() {
            return Err("History publication belongs to another session".into());
        }
        Ok((self.request,self.page,self.candidates))
    }
}

pub enum Preparation {
    Ready(PreparedHistoryPublication),
    /// Current plan keeps its bounded slots. Do not insert a second page.
    OverlappingBusy,
    RetryAfter(Instant),
}

/// One owner per admitted node->wallet connection. One shared budget per node.
pub struct NodeHistoryService {
    session: AdmittedHistorySession,
    budget: HistoryBudget,
    last: Option<(HistoryRequest,PreparedHistoryPublication,HistoryStatus)>,
    active: bool,
    next: Instant,
    stopped: bool,
}
impl NodeHistoryService {
    pub fn new(session:AdmittedHistorySession,budget:HistoryBudget)->PeerResult<Self> {
        session.check_current()?;
        if session.authorization()!=LocalAuthorization::WalletHistoryClientToNode {
            return Err("History exporter requires node-to-wallet purpose".into());
        }
        Ok(Self{session,budget,last:None,active:false,next:Instant::now(),stopped:false})
    }
    pub fn prepare(&mut self,runtime:&HybridRuntime,request:HistoryRequest,
        capacity:HistoryCapacity,now:Instant)->PeerResult<Preparation> {
        self.session.check_current()?;
        request.validate().map_err(|e|PeerFailure::Other(format!("History request: {e:?}")))?;
        if let Some((old,publication,_))=&self.last {
            if old==&request && self.active { return Ok(Preparation::Ready(publication.clone())); }
            if request.sequence<=old.sequence { return Err("History sequence reused or wrapped".into()); }
            if self.active { return Ok(Preparation::OverlappingBusy); }
        }
        if self.stopped { return Err("History automatic service stopped for this connection".into()); }
        if now<self.next { return Ok(Preparation::RetryAfter(self.next)); }
        let request_id=request.object_id().map_err(|_| "History request identity")?;
        let mut candidates=Vec::new();
        let page=if !self.budget.charge(self.session.peer_id(),now)? {
            status_page(&request,HistoryStatus::Busy)?
        } else {
            // A snapshot/actor lock is never retained across a queue or socket wait.
            match runtime.prepare_history_export(&request,capacity.candidate_bytes,capacity.candidate_entries) {
                Ok(prepared)=>{
                    let (page,objects)=prepared.into_parts();
                    for object in objects { candidates.push((object.kind(),object.into_bytes())); }
                    page
                },
                Err(_)=>status_page(&request,HistoryStatus::NodeUnavailable)?,
            }
        };
        self.session.check_current()?;
        page.validate_for(&request).map_err(|_| "Invalid prepared history plan")?;
        let status=page.status;
        let publication=PreparedHistoryPublication{session:self.session.clone(),request:request_id,
            page:page.encode().map_err(|_| "History page encoding")?,candidates};
        self.last=Some((request,publication.clone(),status)); self.active=true;
        Ok(Preparation::Ready(publication))
    }
    /// Call only after the current plan has completed its bounded transport
    /// lifecycle and been retired. Missing replies never imply caught-up state.
    pub fn completed(&mut self,request_id:Hash,now:Instant)->PeerResult<()> {
        self.session.check_current()?;
        let (request,_,status)=self.last.as_ref().ok_or("No current history request")?;
        if request.object_id().map_err(|_| "History request identity")?!=request_id || !self.active {
            return Err("History completion correlation".into());
        }
        self.active=false;
        self.stopped=matches!(status,HistoryStatus::CheckpointRejected|HistoryStatus::BoundsRejected);
        self.next=if matches!(status,HistoryStatus::More|HistoryStatus::Page) {now} else {now+REFRESH};
        Ok(())
    }

    /// A request observed while the preceding page was active receives BUSY,
    /// after that page has released its reserved slots. Never export a later
    /// snapshot merely because queue retirement delayed this response.
    pub(crate) fn prepare_overlapping_busy(&mut self,request:HistoryRequest,now:Instant)
        ->PeerResult<Preparation> {
        self.session.check_current()?;
        request.validate().map_err(|e|PeerFailure::Other(format!("History request: {e:?}")))?;
        if let Some((old,publication,status))=&self.last {
            if old==&request && self.active && *status==HistoryStatus::Busy {
                return Ok(Preparation::Ready(publication.clone()));
            }
            if request.sequence<=old.sequence {return Err("History sequence reused or wrapped".into());}
            if self.active {return Ok(Preparation::OverlappingBusy);}
        }
        if self.stopped {return Err("History automatic service stopped for this connection".into());}
        if now<self.next {return Ok(Preparation::RetryAfter(self.next));}
        let page=status_page(&request,HistoryStatus::Busy)?;
        page.validate_for(&request).map_err(|_|"Invalid overlapping history status")?;
        let publication=PreparedHistoryPublication{session:self.session.clone(),
            request:request.object_id().map_err(|_|"History request identity")?,
            page:page.encode().map_err(|_|"History page encoding")?,candidates:Vec::new()};
        self.session.check_current()?;
        self.last=Some((request,publication.clone(),HistoryStatus::Busy));self.active=true;
        Ok(Preparation::Ready(publication))
    }
}
fn status_page(request:&HistoryRequest,status:HistoryStatus)->PeerResult<HistoryPage> {
    Ok(HistoryPage{request_object_id:request.object_id().map_err(|_| "History request identity")?,
        status,from_anchor:request.saved_anchor.clone(),offered_through_anchor:None,
        observed_tip_anchor:None,entries:Vec::new()})
}

/// An exact member whose real canonical verification/installation succeeded.
/// Transport copies may now be discarded; canonical state is never discarded.
pub struct VerifiedHistoryReclaim {
    session:AdmittedHistorySession,
    lease:HistoryPlanLease,
    page:Hash,
    object:Hash,
}
impl VerifiedHistoryReclaim {
    pub(crate) fn into_parts(self,current:&AdmittedHistorySession)->PeerResult<(Hash,Hash)> {
        self.session.check_current()?;current.check_current()?;
        self.lease.check_current().map_err(|e|PeerFailure::transport("History verification plan retired",e))?;
        if self.session.session_id()!=current.session_id()
            || self.session.peer_id()!=current.peer_id()
            || self.session.authorization()!=current.authorization() {
            return Err("History verification belongs to another session".into());
        }
        Ok((self.page,self.object))
    }
}

// This module is private: downstream callers cannot implement a verifier
// that fabricates canonical success and thereby obtains a reclaim capability.
mod history_verifier_sealed {
    pub trait Sealed {}
}

/// The existing native canonical owners accepted by the ordered receiver.
/// Implementations are sealed to this crate; transport/page claims never select
/// a verifier or supply its parent capacity. No method mints a reclaim proof.
pub trait HistoryVerifier: history_verifier_sealed::Sealed {
    type Error: std::fmt::Debug;
    fn history_head(&self)->Result<mutiny_consensus_v8::anchors::FinalizedAnchor,Self::Error>;
    fn history_decode_anchor(&self,raw:&[u8])->Result<mutiny_consensus_v8::anchors::FinalizedAnchor,Self::Error>;
    fn history_accept_recovery(&mut self,raw:&[u8])->Result<mutiny_consensus_v8::anchors::FinalizedAnchor,Self::Error>;
    fn history_install(&mut self,raw:&[u8])->Result<mutiny_consensus_v8::anchors::FinalizedAnchor,Self::Error>;
}
impl history_verifier_sealed::Sealed for HybridRuntime {}
impl HistoryVerifier for HybridRuntime {
    type Error=crate::hybrid_runtime_v2::RuntimeError;
    fn history_head(&self)->Result<mutiny_consensus_v8::anchors::FinalizedAnchor,Self::Error> {self.head()}
    fn history_decode_anchor(&self,raw:&[u8])->Result<mutiny_consensus_v8::anchors::FinalizedAnchor,Self::Error> {
        Ok(self.decode_envelope(raw)?.certificate.decision.anchor())
    }
    fn history_accept_recovery(&mut self,raw:&[u8])->Result<mutiny_consensus_v8::anchors::FinalizedAnchor,Self::Error> {
        Ok(self.accept_recovery(raw)?.parent)
    }
    fn history_install(&mut self,raw:&[u8])->Result<mutiny_consensus_v8::anchors::FinalizedAnchor,Self::Error> {
        // Preserve this owner's existing pending/submission reconciliation.
        Ok(self.install(raw)?.finalized)
    }
}

/// A temporary exclusive borrow of the wallet's already opened canonical store.
/// Creates no database, mempool, submission pool, cache, or second runtime.
/// The caller must invalidate its cached snapshot BEFORE any install attempt,
/// and reconcile its own outbox afterward even if installation returns an error:
/// an indivisible native commit can succeed before a post-commit lease refusal.
pub struct CanonicalHistoryVerifier<'a> {
    store:&'a mut mutiny_consensus_v8::canonical_store_v2::CanonicalStore,
}
impl<'a> CanonicalHistoryVerifier<'a> {
    pub fn new(store:&'a mut mutiny_consensus_v8::canonical_store_v2::CanonicalStore)->Self {Self{store}}
    fn decode_envelope(&self,raw:&[u8])
        ->Result<mutiny_consensus_v8::block_envelope_v2::BlockEnvelope,mutiny_consensus_v8::finality_v2::StoreError> {
        use mutiny_consensus_v8::{block_envelope_v2::BlockEnvelope,finality_v2::StoreError};
        let header=BlockEnvelope::untrusted_header(raw).map_err(StoreError::from)?;
        let capacity=self.store.proposal_body_capacity(&header)?;
        BlockEnvelope::decode_with_capacity(raw,&capacity).map_err(StoreError::from)
    }
}
impl history_verifier_sealed::Sealed for CanonicalHistoryVerifier<'_> {}
impl HistoryVerifier for CanonicalHistoryVerifier<'_> {
    type Error=mutiny_consensus_v8::finality_v2::StoreError;
    fn history_head(&self)->Result<mutiny_consensus_v8::anchors::FinalizedAnchor,Self::Error> {
        self.store.current_anchor()
    }
    fn history_decode_anchor(&self,raw:&[u8])->Result<mutiny_consensus_v8::anchors::FinalizedAnchor,Self::Error> {
        Ok(self.decode_envelope(raw)?.certificate.decision.anchor())
    }
    fn history_accept_recovery(&mut self,raw:&[u8])->Result<mutiny_consensus_v8::anchors::FinalizedAnchor,Self::Error> {
        Ok(self.store.accept_recovery_encoded(raw)?.parent)
    }
    fn history_install(&mut self,raw:&[u8])->Result<mutiny_consensus_v8::anchors::FinalizedAnchor,Self::Error> {
        let envelope=self.decode_envelope(raw)?;
        self.store.commit(&envelope)?;
        Ok(envelope.certificate.decision.anchor())
    }
}

/// Wallet-side ordered plan. Construction validates the current checkpoint,
/// request ID, exact page HAVE and all bounds; install uses the existing native
/// canonical verifier for each dependency and never trusts page anchor claims.
pub struct ReceiverHistoryPlan {
    session:AdmittedHistorySession,
    lease:Option<HistoryPlanLease>,
    page_id:Hash,
    page:HistoryPage,
    next:usize,
}
/// Minted only after the owned worker established this session's actual
/// complete incoming page grant and exact bounded transport member plan.
pub struct HistoryPlanAdmission {
    session:AdmittedHistorySession,
    lease:HistoryPlanLease,
    request:Hash,
    page:Hash,
    members:Vec<Offer>,
}
impl HistoryPlanAdmission {
    pub(crate) fn new(session:AdmittedHistorySession,request:Hash,page:Hash,members:Vec<Offer>,lease:HistoryPlanLease)
        ->PeerResult<Self> {
        session.check_current()?;
        lease.check_current().map_err(|e|PeerFailure::transport("History admitted plan retired",e))?;
        if session.authorization()!=LocalAuthorization::NodeToWalletHistoryClient || members.len()>6 {
            return Err("History plan admission purpose/bounds".into());
        }
        Ok(Self{session,lease,request,page,members})
    }
}
impl ReceiverHistoryPlan {
    /// Worker-owned link bridge. The grant cannot be fabricated from public
    /// hashes/retained bytes; it is produced by successful HistoryAcceptPlan.
    pub fn from_admitted_plan<V:HistoryVerifier+?Sized>(session:AdmittedHistorySession,request:&HistoryRequest,
        offer:&Offer,page:HistoryPage,runtime:&V,admission:HistoryPlanAdmission)
        ->PeerResult<Self> {
        admission.session.check_current()?;
        admission.lease.check_current().map_err(|e|PeerFailure::transport("History admitted plan retired",e))?;
        let mut plan=Self::new(session,request,offer,page,runtime)?;
        let members:Vec<_>=plan.page.entries.iter().map(|entry|Offer{kind:entry.kind,
            id:entry.object_id,length:entry.encoded_length as usize}).collect();
        if plan.session.session_id()!=admission.session.session_id()
            || plan.session.peer_id()!=admission.session.peer_id()
            || plan.session.authorization()!=admission.session.authorization()
            || admission.request!=plan.page.request_object_id || admission.page!=plan.page_id
            || admission.members!=members {
            return Err("History admitted plan belongs to another session/request/page".into());
        }
        plan.lease=Some(admission.lease);
        Ok(plan)
    }
    /// Direct link owner: establish the fresh incoming grant and transport plan
    /// before exposing an install-capable receiver. Retained bytes alone refuse.
    pub fn accept<V:HistoryVerifier+?Sized>(peer:&mut crate::hybrid_peer_admission_v2::PeerLink,request:&HistoryRequest,
        offer:&Offer,page:HistoryPage,runtime:&V)->PeerResult<Self> {
        let proof=peer.history_session()?;
        let mut plan=Self::new(proof,request,offer,page,runtime)?;
        let members:Vec<_>=plan.page.entries.iter().map(|entry|Offer{kind:entry.kind,
            id:entry.object_id,length:entry.encoded_length as usize}).collect();
        peer.with_current(|link|link.history_accept_plan(&plan.page.request_object_id,&plan.page_id,&members))?
            .map_err(|e|PeerFailure::transport("History fresh plan grant",e))?;
        plan.lease=Some(peer.with_current(|link|link.history_plan_lease(&plan.page_id))?
            .map_err(|e|PeerFailure::transport("History current plan lease",e))?);
        Ok(plan)
    }
    pub(crate) fn new<V:HistoryVerifier+?Sized>(session:AdmittedHistorySession,request:&HistoryRequest,
        offer:&Offer,page:HistoryPage,runtime:&V)->PeerResult<Self> {
        session.check_current()?;
        if session.authorization()!=LocalAuthorization::NodeToWalletHistoryClient {
            return Err("History receiver requires wallet-side history purpose".into());
        }
        page.validate_for(request).map_err(|_| "History page correlation/bounds")?;
        let raw=page.encode().map_err(|_| "History page encoding")?;
        if offer.kind!=ObjectKind::HistoryPageV1 || offer.length!=raw.len()
            || object_id(offer.kind,&raw).map_err(|_| "History page identity")?!=offer.id
            || runtime.history_head().map_err(|_| "History local checkpoint unavailable")?!=request.saved_anchor {
            return Err("History page HAVE/current checkpoint mismatch".into());
        }
        Ok(Self{session,lease:None,page_id:offer.id,page,next:0})
    }
    pub fn next_entry(&self)->Option<&crate::history_protocol_v1::HistoryEntry> {
        self.page.entries.get(self.next)
    }
    pub fn complete(&self)->bool { self.next==self.page.entries.len() }
    pub fn install<V:HistoryVerifier+?Sized>(&mut self,offer:&Offer,raw:&[u8],runtime:&mut V)
        ->PeerResult<VerifiedHistoryReclaim> {
        self.session.check_current()?;
        let lease=self.lease.as_ref().ok_or("History receiver has no admitted plan lease")?;
        lease.check_current().map_err(|e|PeerFailure::transport("History receiver plan retired",e))?;
        let entry=self.page.entries.get(self.next).ok_or("History plan already complete")?;
        if !entry.matches_offer(offer) || raw.len()!=offer.length
            || object_id(offer.kind,raw).map_err(|_| "History candidate identity")?!=offer.id {
            return Err("History candidate differs from next planned dependency".into());
        }
        match offer.kind {
            ObjectKind::RecoveryEvidence=>{
                if runtime.history_head().map_err(|_| "History head unavailable")?.height!=entry.height {
                    return Err("History recovery parent ordering".into());
                }
                let accepted=runtime.history_accept_recovery(raw)
                    .map_err(|e|PeerFailure::Other(format!("History recovery verification: {e:?}")))?;
                if accepted.height!=entry.height {return Err("History recovery parent mismatch".into());}
            },
            ObjectKind::CertifiedBlock=>{
                // Decode with the actual parent capacity before any commit.
                let anchor=runtime.history_decode_anchor(raw)
                    .map_err(|e|PeerFailure::Other(format!("History certificate decode: {e:?}")))?;
                if anchor.height!=entry.height || (self.next+1==self.page.entries.len()
                    && self.page.offered_through_anchor.as_ref()!=Some(&anchor)) {
                    return Err("History terminal full anchor mismatch".into());
                }
                let installed=runtime.history_install(raw)
                    .map_err(|e|PeerFailure::Other(format!("History canonical verification: {e:?}")))?;
                if installed!=anchor {return Err("History installed anchor mismatch".into());}
            },
            _=>return Err("History candidate kind".into()),
        }
        self.session.check_current()?;
        // An indivisible native/canonical operation is never interrupted. If
        // retirement crossed it, the committed canonical state remains, but no
        // further plan progress or reclaim capability is released.
        lease.check_current().map_err(|e|PeerFailure::transport("History receiver plan retired",e))?;
        self.next+=1;
        Ok(VerifiedHistoryReclaim{session:self.session.clone(),lease:lease.clone(),page:self.page_id,object:offer.id})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn b1_service_budget_survives_reconnect_owner_and_is_rolling() {
        let now=Instant::now(); let budget=HistoryBudget::default();
        for _ in 0..8 {assert!(budget.charge([1;32],now).unwrap());}
        let reconnect=budget.clone(); assert!(!reconnect.charge([1;32],now).unwrap());
        assert!(!reconnect.charge([1;32],now+Duration::from_secs(59)).unwrap());
        assert!(reconnect.charge([1;32],now+WINDOW).unwrap());
    }
    #[test]
    fn b1_service_global_budget_is_bounded_across_peers() {
        let now=Instant::now();let budget=HistoryBudget::default();
        for peer in 0..32 {assert!(budget.charge([peer;32],now).unwrap());}
        assert!(!budget.charge([33;32],now).unwrap());
        assert_eq!(budget.0.lock().unwrap().len(),32);
        assert!(budget.charge([33;32],now+WINDOW).unwrap());
    }
}

#[cfg(test)]
#[path = "history_receiver_adapter_tests.rs"]
mod history_receiver_adapter_tests;
