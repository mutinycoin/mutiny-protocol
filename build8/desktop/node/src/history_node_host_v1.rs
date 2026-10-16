//! Explicit autonomous B1 node owner, driven by the existing single Worker.
//! No listener, keys, signing, client installer or second notification consumer.
use crate::{
    history_protocol_v1::HistoryRequest,
    history_service_v1::{HistoryBudget,NodeHistoryService,Preparation,PreparedHistoryPublication,REFRESH},
    hybrid_dispatch_v2::{self,DispatchEvent},
    hybrid_peer_admission_v2::PeerLink,
    hybrid_peer_error_v2::{PeerFailure,PeerResult},
    hybrid_runtime_v2::HybridRuntime,
};
use mutiny_consensus_v8::Hash;
use mutiny_transport_v2::{object_link::{Event,LocalAuthorization},objects::{Offer,ObjectKind,MAX_BITMAP_BITS}};
use std::{sync::Mutex,time::{Duration,Instant}};
const IO:Duration=Duration::from_secs(5);

struct Active {
    request:HistoryRequest,
    offers:Vec<Offer>, // page first, then at most six candidates
    next:usize,
    advertised:bool,
}
struct Incoming {offer:Offer,requested:bool,overlapping:bool}

/// Exactly one instance is owned inside an explicitly selected node Worker.
/// One overlapping request is deferred until the active plan retires; no second
/// BUSY response can occupy the full eight-object queue beside that plan.
pub(crate) struct NodeHistoryHost {
    service:NodeHistoryService,
    active:Option<Active>,
    incoming:Option<Incoming>,
    pending:Option<HistoryRequest>,
    pending_overlapping:bool,
    publication:Option<(HistoryRequest,PreparedHistoryPublication)>,
    next_attempt:Instant,
    repeat_page:bool,
}
impl NodeHistoryHost {
    pub(crate) fn new(peer:&mut PeerLink,budget:HistoryBudget)->PeerResult<Self> {
        let proof=peer.history_session()?;
        if proof.authorization()!=LocalAuthorization::WalletHistoryClientToNode {
            return Err("Autonomous history host requires explicit node purpose".into());
        }
        peer.with_current(|link|link.history_general_capacity())?
            .map_err(|e|PeerFailure::transport("History node queue profile",e))?;
        Ok(Self{service:NodeHistoryService::new(proof,budget)?,active:None,incoming:None,
            pending:None,pending_overlapping:false,publication:None,next_attempt:Instant::now(),repeat_page:false})
    }
    /// Inspect by reference so unrelated existing notifications retain ownership.
    /// Only authenticated dispatch events from this Worker's real receive path
    /// may enter here. No event manufactures an outbound frame inside receive.
    pub(crate) fn receive(&mut self,event:&DispatchEvent,peer:&mut PeerLink)->PeerResult<bool> {
        match event {
            DispatchEvent::Transport(Event::Offered(offer)) if offer.kind==ObjectKind::HistoryRequestV1=>{
                if let Some(pending)=self.pending.as_ref() {
                    if pending.object_id().map_err(|_|"History pending request identity")?!=offer.id {
                        return Err("More than one deferred history request offer".into());
                    }
                }
                if let Some(old)=&self.incoming {
                    if old.offer!=*offer {return Err("More than one pending history request offer".into());}
                } else {self.incoming=Some(Incoming{offer:offer.clone(),requested:false,
                    overlapping:self.active.is_some()||self.publication.is_some()});}
                Ok(true)
            },
            DispatchEvent::HistoryRequest{offer,bytes,request}=>{
                if offer.kind!=ObjectKind::HistoryRequestV1 || offer.length!=bytes.len()
                    || request.object_id().map_err(|_|"History request identity")?!=offer.id {
                    return Err("History node request correlation".into());
                }
                // Retain arrival classification even if the old final ACK was
                // processed before these request fragments finished decoding.
                let overlapping=self.incoming.take().is_some_and(|incoming|incoming.overlapping);
                if let Some(active)=&self.active {
                    if active.request==*request {
                        self.repeat_page=true;
                        // A duplicate fresh request copy is consumed; the exact
                        // frozen page and cursor survive, with no new export.
                        peer.with_current(|link|link.history_retire_consumed_request(&offer.id))?
                            .map_err(|e|PeerFailure::transport("History retry request retire",e))?;
                        return Ok(true);
                    }
                }
                if self.publication.as_ref().is_some_and(|(old,_)|old==request) {
                    return Ok(true); // exact frozen publication retry, not a new request
                }
                if let Some(old)=self.pending.as_ref() {
                    if old!=request {return Err("More than one deferred history request".into());}
                    return Ok(true); // exact pending retry keeps its classification
                }
                self.pending=Some(request.clone());
                self.pending_overlapping=overlapping||self.active.is_some()||self.publication.is_some();
                Ok(true)
            },
            DispatchEvent::Transport(Event::FragmentReceived|Event::Requested|Event::ReceiptRecorded)=>Ok(true),
            _=>Ok(false),
        }
    }
    fn full_ack(peer:&mut PeerLink,offer:&Offer)->PeerResult<bool> {
        let total=offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD) as u16;
        for start in (0..total).step_by(MAX_BITMAP_BITS as usize) {
            let count=(total-start).min(MAX_BITMAP_BITS);
            let bits=peer.with_current(|link|link.history_acknowledged(&offer.id,start,count))?
                .map_err(|e|PeerFailure::transport("History node ACK progress",e))?;
            if bits.bits.iter().any(|bit|!*bit) {return Ok(false);}
        }
        Ok(true)
    }
    fn progress(&mut self,peer:&mut PeerLink,now:Instant)->PeerResult<()> {
        let Some(active)=self.active.as_mut() else {return Ok(());};
        if !active.advertised || !Self::full_ack(peer,&active.offers[active.next])? {return Ok(());}
        if active.next>0 {
            let page=active.offers[0].id;
            let object=active.offers[active.next].id;
            peer.with_current(|link|link.history_reclaim_acknowledged_export_if_owned(&page,&object))?
                .map_err(|e|PeerFailure::transport("History node export reclaim",e))?;
        }
        active.next+=1;active.advertised=false;
        if active.next==active.offers.len() {
            let page=active.offers[0].id;
            let request=active.request.object_id().map_err(|_|"History completion identity")?;
            peer.with_current(|link|link.history_retire_plan(&page))?
                .map_err(|e|PeerFailure::transport("History node plan retire",e))?;
            self.service.completed(request,Instant::now())?;
            self.active=None;self.repeat_page=false;
            self.next_attempt=now;
        }
        Ok(())
    }
    /// At most one outbound frame, always outside the canonical actor. A false
    /// result permits the same Worker to send one requested fragment instead.
    pub(crate) fn turn(&mut self,peer:&mut PeerLink,runtime:&Mutex<HybridRuntime>,now:Instant)->PeerResult<bool> {
        // Fulfil an already-admitted exact retry before a concurrent last ACK
        // can retire its frozen page. Neither cursor nor ACK bits are reset.
        if self.repeat_page {
            if let Some(active)=self.active.as_ref() {
                let frame=peer.with_current(|link|link.advertise(&active.offers[0].id,0))?
                    .map_err(|e|PeerFailure::transport("History frozen page retry",e))?;
                self.repeat_page=false;
                peer.send_typed(&frame,Instant::now()+IO)?;
                return Ok(true);
            }
        }
        self.progress(peer,now)?;
        if let Some(incoming)=self.incoming.as_mut() {
            if !incoming.requested {
                let id=incoming.offer.id;
                let complete=peer.with_current(|link|link.describe(&id))?
                    .map_err(|e|PeerFailure::transport("History request offer state",e))?.1;
                if complete {
                    let event=hybrid_dispatch_v2::retry_peer_completed(runtime,peer,id,Instant::now()+IO)
                        .map_err(|e|PeerFailure::dispatch("History retained request dispatch",e))?;
                    self.receive(&event,peer)?;
                } else {
                    let window=peer.with_current(|link|link.next_missing_request(&id,0,false))?
                        .map_err(|e|PeerFailure::transport("History request window",e))?
                        .ok_or("History incomplete request has no missing window")?;
                    // RequestV1 is <=145 bytes, so a single existing bounded
                    // missing window covers at most two fragments.
                    if window.start!=0 || window.count>2 {return Err("History request window bound".into());}
                    incoming.requested=true;
                    peer.send_typed(&window.frame,Instant::now()+IO)?;
                    return Ok(true);
                }
            }
        }
        if let Some(active)=self.active.as_mut() {
            if !active.advertised {
                let frame=peer.with_current(|link|link.advertise(&active.offers[active.next].id,0))?
                    .map_err(|e|PeerFailure::transport("History paced candidate advertise",e))?;
                active.advertised=true;
                peer.send_typed(&frame,Instant::now()+IO)?;
                return Ok(true);
            }
            return Ok(false);
        }
        if now<self.next_attempt {return Ok(false);}
        if self.publication.is_none() {
            let Some(request)=self.pending.as_ref() else {return Ok(false);};
            let request_id=request.object_id().map_err(|_|"History pending request identity")?;
            let preparation=if self.pending_overlapping {
                // No canonical export or second page beside the active plan.
                // The approved BUSY result survives retirement of that plan.
                self.service.prepare_overlapping_busy(request.clone(),now)?
            } else {
                let capacity=peer.with_current(|link|link.history_capacity(&request_id))?
                    .map_err(|e|PeerFailure::transport("History node actual capacity",e))?;
                hybrid_dispatch_v2::with_actor(runtime,peer,Instant::now()+IO,
                    |actor,_|Ok(self.service.prepare(actor,request.clone(),capacity,now)))
                    .map_err(|e|PeerFailure::dispatch("History bounded canonical export",e))??
            };
            match preparation {
                Preparation::Ready(publication)=>{
                    self.publication=Some((self.pending.take().unwrap(),publication));
                    self.pending_overlapping=false;
                },
                Preparation::RetryAfter(at)=>{self.next_attempt=at;return Ok(false);},
                Preparation::OverlappingBusy=>return Err("History host/service active ownership mismatch".into()),
            }
        }
        let (request,publication)=self.publication.as_ref().ok_or("No prepared history publication")?;
        let request_id=request.object_id().map_err(|_|"History publication request identity")?;
        let publication=publication.clone();
        let proof=peer.history_session()?;
        let (id,page,candidates)=publication.into_parts(&proof)?;
        if id!=request_id {return Err("History publication request changed".into());}
        let Some(offers)=peer.with_current(|link|link.enqueue_history_page(&id,&page,&candidates))?
            .map_err(|e|PeerFailure::transport("History node atomic queue",e))? else {
                // Preserve the same charged frozen publication; do not repeat a
                // native export, clear another plan or refund transport quota.
                self.next_attempt=Instant::now()+REFRESH;return Ok(false);
            };
        peer.with_current(|link|link.history_retire_consumed_request(&id))?
            .map_err(|e|PeerFailure::transport("History consumed request retire",e))?;
        let (request,_)=self.publication.take().unwrap();
        self.active=Some(Active{request,offers,next:0,advertised:false});
        let active=self.active.as_mut().unwrap();
        let frame=peer.with_current(|link|link.advertise(&active.offers[0].id,0))?
            .map_err(|e|PeerFailure::transport("History page first advertise",e))?;
        active.advertised=true;
        peer.send_typed(&frame,Instant::now()+IO)?;
        Ok(true)
    }
}

#[cfg(test)]
#[path="history_node_host_v1_tests.rs"]
mod tests;
