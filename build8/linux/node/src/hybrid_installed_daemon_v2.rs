//! Conditional ordinary V2 lifecycle and original-private-runtime message bridge.
//! No listener/key/peer selection, source registration or clock owner is issued.
#![cfg(target_os="linux")]
use std::mem::ManuallyDrop as MD;
use mutiny_consensus_v8::{Hash,bft::Step,continuity_v2::Vote,activation_attestation_v1::Request};
use crate::{hybrid_installed_private_worker_v2::{InstalledPrivateWorker,InstalledReply,InstalledCommandRefusal,InstalledWorkerCancellation},
    hybrid_installed_worker_join_v2::{InstalledWorkerJoin,InstalledWorkerJoinRefusal},
    hybrid_peer_admission_v2::{PeerLink,Received},hybrid_dispatch_v2::DispatchEvent};
type Result<T>=std::result::Result<T,String>;

struct PeerState {
    peer:Option<MD<PeerLink>>,received:Option<MD<Received>>,event:Option<DispatchEvent>,
    attempted:bool,accepted:bool,cause:Option<String>,
}
/// One SAME peer and opaque original receive. No event extraction or raw session
/// constructor exists. Every unresolved graph stays boxed, even on panic/drop.
pub struct InstalledPeerMessage {original:Option<MD<Box<PeerState>>>}
impl InstalledPeerMessage {
    pub(crate) fn from_received(peer:PeerLink,received:Received)->Self {
        let peer=MD::new(peer);let received=MD::new(received);
        Self{original:Some(MD::new(Box::new(PeerState{peer:Some(peer),received:Some(received),
            event:None,attempted:false,accepted:false,cause:None})))}
    }
    fn state(&self)->&PeerState{&***self.original.as_ref().expect("original peer message graph")}
    fn state_mut(&mut self)->&mut PeerState{&mut ***self.original.as_mut().expect("original peer message graph")}
    pub fn accepted(&self)->bool{self.state().accepted}
    pub fn cause(&self)->Option<&str>{self.state().cause.as_deref()}
    pub(crate) fn refuse(&mut self,cause:String){let state=self.state_mut();state.accepted=false;
        if state.cause.is_none(){state.cause=Some(cause);}}
    /// ONLY called on the original private signer thread, between factory
    /// entry checks. dispatch_peer repeats original peer/current/network checks.
    pub(crate) fn dispatch_original(&mut self,runtime:&mut crate::hybrid_runtime_v2::HybridRuntime)->Result<()> {
        let state=self.state_mut();
        if state.attempted{return Err("original peer message already attempted".into());}
        state.attempted=true;
        let received=MD::into_inner(state.received.take().ok_or("original opaque receive absent")?);
        match crate::hybrid_dispatch_v2::dispatch_peer(runtime,
            &mut **state.peer.as_mut().ok_or("original peer absent")?,received) {
            Ok(event)=>{state.event=Some(event);Ok(())},
            Err(error)=>Err(format!("installed original peer dispatch: {error:?}")),
        }
    }
    pub(crate) fn accept_after_current(&mut self)->Result<()> {
        let state=self.state_mut();
        if !state.attempted||state.received.is_some()||state.event.is_none()||state.cause.is_some(){
            return Err("original dispatch/current completion absent".into());}
        state.accepted=true;Ok(())
    }
    /// Transfer the SAME typed connection only after actual dispatch plus the
    /// post-current check. This conveys no socket/native-close qualification.
    pub fn into_original_peer(mut self)->std::result::Result<(PeerLink,DispatchEvent),Self> {
        if !self.accepted(){return Err(self);}
        let mut state=MD::into_inner(self.original.take().expect("accepted original message"));
        let peer=MD::into_inner(state.peer.take().expect("same accepted peer"));
        let event=state.event.take().expect("same accepted event");Ok((peer,event))
    }
}
impl Drop for InstalledPeerMessage {fn drop(&mut self){
    // MD includes the whole heap, not just its socket/receive fields.
    if let Some(original)=self.original.take(){let _custody=original;}
}}

#[derive(Clone,Copy,PartialEq,Eq)]
enum Phase {Starting,Ready,Pending,Failed,Closing,Closed}
enum CompletedReply {
    Request(MD<InstalledReply<Option<Request>>>),Sign(MD<InstalledReply<Vote>>),
    Dispatch(MD<InstalledReply<InstalledPeerMessage>>),
}
struct State {
    worker:Option<MD<InstalledPrivateWorker>>,phase:Phase,
    cancellation:Option<MD<InstalledWorkerCancellation>>,
    request:Option<MD<InstalledReply<Option<Request>>>>,
    sign:Option<MD<InstalledReply<Vote>>>,dispatch:Option<MD<InstalledReply<InstalledPeerMessage>>>,
    command_refusal:Option<MD<InstalledCommandRefusal>>,join:Option<MD<InstalledWorkerJoin>>,
    join_refusal:Option<MD<InstalledWorkerJoinRefusal>>,
    startup_result:Option<Result<()>>,operation_error:Option<String>,
    cancel_result:Option<Result<()>>,join_known:bool,pending_active:bool,
    completed:Vec<CompletedReply>,
    // A known predecessor's complete observations remain in the same successor
    // graph. Reopening requires a NEW genuine source registration, never a bool.
    predecessors:Vec<MD<Box<State>>>,
}
pub struct InstalledDaemon {original:Option<MD<Box<State>>>}
pub struct InstalledDaemonFailure {cause:String,original:MD<InstalledDaemon>}
impl InstalledDaemonFailure {pub fn cause(&self)->&str{&self.cause}}
impl Drop for InstalledDaemonFailure {fn drop(&mut self){self.original.cancel();}}
pub struct ClosedInstalledDaemon {original:MD<InstalledDaemon>}
impl ClosedInstalledDaemon {
    pub fn original_join_known(&self)->bool{
        let state=self.original.state();state.phase==Phase::Closed&&state.join_known&&state.join_refusal.is_none()
    }
    /// Public ordinary retry still obtains the fixed issuer first; its current
    /// UNAVAILABLE refusal preserves this original closed predecessor graph.
    pub async fn restart_installed(self)->std::result::Result<InstalledDaemon,InstalledDaemonFailure> {
        let source=match crate::hybrid_installed_secret_source_v2::require_registered_source(){
            Ok(source)=>source,Err(cause)=>return Err(InstalledDaemonFailure{cause,original:self.original})};
        Self::restart_registered(self,source).await
    }
    pub(crate) async fn restart_registered(mut self,
        source:crate::hybrid_installed_secret_source_v2::InstalledSecretSourceRegistration)
        ->std::result::Result<InstalledDaemon,InstalledDaemonFailure> {
        if !self.original_join_known(){return Err(InstalledDaemonFailure{
            cause:"original daemon closure incomplete".into(),original:self.original});}
        // Allocate history capacity before moving the original closed state.
        let mut history=Vec::with_capacity(1);
        let state=self.original.original.take().expect("original closed daemon state");
        history.push(state);InstalledDaemon::start_registered_with_history(source,history).await
    }
}
impl InstalledDaemon {
    fn state(&self)->&State{&***self.original.as_ref().expect("original daemon graph")}
    fn state_mut(&mut self)->&mut State{&mut ***self.original.as_mut().expect("original daemon graph")}
    fn empty(predecessors:Vec<MD<Box<State>>>)->Self {
        Self{original:Some(MD::new(Box::new(State{worker:None,phase:Phase::Starting,
            cancellation:None,
            request:None,sign:None,dispatch:None,command_refusal:None,join:None,join_refusal:None,
            startup_result:None,operation_error:None,cancel_result:None,join_known:false,
            pending_active:false,completed:Vec::new(),predecessors})))}
    }
    /// No registration, caller secret, path/profile or TEST constructor enters.
    /// The fixed unavailable issuer refuses before native/worker acquisition.
    pub async fn start_installed()->std::result::Result<Self,InstalledDaemonFailure> {
        let source=match crate::hybrid_installed_secret_source_v2::require_registered_source(){
            Ok(source)=>source,Err(cause)=>return Err(InstalledDaemonFailure{
                cause,original:MD::new(Self::empty(Vec::new()))})};
        Self::start_registered_with_history(source,Vec::new()).await
    }
    pub(crate) async fn start_registered(
        source:crate::hybrid_installed_secret_source_v2::InstalledSecretSourceRegistration)
        ->std::result::Result<Self,InstalledDaemonFailure> {
        Self::start_registered_with_history(source,Vec::new()).await
    }
    async fn start_registered_with_history(
        source:crate::hybrid_installed_secret_source_v2::InstalledSecretSourceRegistration,
        predecessors:Vec<MD<Box<State>>>)
        ->std::result::Result<Self,InstalledDaemonFailure> {
        let mut original=Self::empty(predecessors);
        match InstalledPrivateWorker::start_registered(source){
            Ok(worker)=>{
                // Root the whole worker BEFORE retaining its original signal
                // capability. This remains outside every blocking join mutex.
                original.state_mut().worker=Some(MD::new(worker));
                let cancellation=original.state().worker.as_ref().expect("original startup worker").cancellation_handle();
                original.state_mut().cancellation=Some(MD::new(cancellation));
            },
            Err(cause)=>{original.state_mut().phase=Phase::Failed;
                original.state_mut().startup_result=Some(Err(cause.clone()));
                return Err(InstalledDaemonFailure{cause,original:MD::new(original)});}
        }
        let ready=original.state_mut().worker.as_mut().expect("original startup worker").startup_pending().await;
        original.state_mut().startup_result=Some(ready.clone());
        if let Err(cause)=ready {
            original.state_mut().phase=Phase::Failed;
            // Store original join/refusal in this SAME already rooted graph.
            // Cancellation of this await invokes whole daemon abandonment.
            let _closure=original.settle_original().await;
            return Err(InstalledDaemonFailure{cause,original:MD::new(original)});
        }
        original.state_mut().phase=Phase::Ready;Ok(original)
    }
    fn require_ready(&self)->Result<()> {
        if self.state().phase!=Phase::Ready{return Err("installed daemon pending/frozen/stopped".into());}Ok(())
    }
    fn begin_command(&mut self)->Result<()> {
        self.require_ready()?;
        // Reserve complete-reply observation storage BEFORE command effects.
        self.state_mut().completed.try_reserve(1).map_err(|_|"original command observation allocation refused")?;
        self.state_mut().pending_active=true;self.state_mut().phase=Phase::Pending;Ok(())
    }
    fn record_command_error(&mut self,cause:String)->String {
        self.state_mut().phase=Phase::Failed;self.state_mut().operation_error=Some(cause.clone());cause
    }
    fn offer_refused(&mut self,refusal:InstalledCommandRefusal)->String {
        let cause=refusal.cause().to_owned();self.state_mut().command_refusal=Some(MD::new(refusal));
        self.state_mut().pending_active=false;
        self.record_command_error(cause)
    }
    pub async fn request(&mut self,step:Step,block:Option<Hash>,pol:Option<u64>)->Result<Option<Request>> {
        self.begin_command()?;
        let pending=match self.state().worker.as_ref().expect("same private worker").request(step,block,pol){
            Ok(pending)=>pending,Err(refusal)=>return Err(self.offer_refused(refusal))};
        self.state_mut().request=Some(MD::new(pending));
        let result=(&mut **self.state_mut().request.as_mut().expect("same request reply")).await;
        let observed=self.state_mut().request.take().expect("observed original request reply");
        self.state_mut().completed.push(CompletedReply::Request(observed));
        self.state_mut().pending_active=false;
        match result{Ok(request)=>{self.state_mut().phase=Phase::Ready;Ok(request)},
            Err(cause)=>Err(self.record_command_error(cause))}
    }
    pub async fn sign(&mut self,step:Step,block:Option<Hash>,pol:Option<u64>,
        targets:Option<crate::activation_private_owner_v1::OwnedTargets>)->Result<Vote> {
        // Own native targets before any refusal/unwind. The original bounded
        // channel/factory performs the actual same-voter/counter/time checks.
        let targets=MD::new(Box::new(targets));
        self.begin_command()?;
        let pending=match self.state().worker.as_ref().expect("same private worker")
            .sign(step,block,pol,*MD::into_inner(targets)) {
            Ok(pending)=>pending,Err(refusal)=>return Err(self.offer_refused(refusal))};
        self.state_mut().sign=Some(MD::new(pending));
        let result=(&mut **self.state_mut().sign.as_mut().expect("same sign reply")).await;
        let observed=self.state_mut().sign.take().expect("observed original sign reply");
        self.state_mut().completed.push(CompletedReply::Sign(observed));
        self.state_mut().pending_active=false;
        match result{Ok(vote)=>{self.state_mut().phase=Phase::Ready;Ok(vote)},
            Err(cause)=>Err(self.record_command_error(cause))}
    }
    /// The future genuine installed transport controller is the only caller.
    /// A caller-created public Registry/PeerLink is not an installed selection.
    pub(crate) async fn dispatch_received(&mut self,peer:PeerLink,received:Received)->Result<InstalledPeerMessage> {
        let message=InstalledPeerMessage::from_received(peer,received);
        // A refused admission drops only the retaining wrapper; its entire
        // original peer/receive graph remains in preallocated heap custody.
        self.begin_command()?;
        let pending=match self.state().worker.as_ref().expect("same private worker").dispatch_received(message){
            Ok(pending)=>pending,Err(refusal)=>return Err(self.offer_refused(refusal))};
        self.state_mut().dispatch=Some(MD::new(pending));
        let result=(&mut **self.state_mut().dispatch.as_mut().expect("same peer reply")).await;
        let observed=self.state_mut().dispatch.take().expect("observed original peer reply");
        self.state_mut().completed.push(CompletedReply::Dispatch(observed));
        self.state_mut().pending_active=false;
        match result{Ok(message)=>{if message.accepted(){self.state_mut().phase=Phase::Ready;}
                else{self.record_command_error(message.cause().unwrap_or("original peer dispatch refused").to_owned());}
                Ok(message)},Err(cause)=>Err(self.record_command_error(cause))}
    }
    /// Admission stop is distinct from cancellation and original join. It does
    /// not claim server, protected-clock owner, peer or private native closure.
    pub fn finish_admission(&mut self){self.state_mut().phase=Phase::Closing;
        if let Some(worker)=self.state_mut().worker.as_mut(){worker.finish_admission();}}
    pub fn cancel(&mut self){
        if self.state().cancel_result.is_some(){return;}
        // Known completed shutdown needs no signal. A missing worker slot
        // alone does not establish completion or successful cancellation.
        if self.state().phase==Phase::Closed&&self.state().join_known{return;}
        self.state_mut().phase=Phase::Failed;
        if let Some(worker)=self.state_mut().worker.as_mut(){worker.finish_admission();}
        let result=match self.state().cancellation.as_ref(){Some(signal)=>signal.stop(),
            None=>Err("original private cancellation capability unavailable".into())};
        self.state_mut().cancel_result=Some(result);
    }
    pub fn original_finished(&self)->bool{
        self.state().worker.as_ref().is_some_and(|worker|worker.original_finished())
    }
    async fn settle_original(&mut self)->Result<()> {
        let worker=self.state_mut().worker.take().ok_or("original worker already transferred")?;
        self.state_mut().phase=Phase::Closing;
        match MD::into_inner(worker).join_on_owned_executor(){
            Ok(join)=>self.state_mut().join=Some(MD::new(join)),
            Err(refusal)=>{let cause=refusal.cause().to_owned();self.state_mut().join_refusal=Some(MD::new(refusal));
                self.state_mut().phase=Phase::Failed;return Err(cause);}
        }
        let result=(&mut **self.state_mut().join.as_mut().expect("same original join")).await;
        match result{Ok(())=>{self.state_mut().join_known=true;self.state_mut().phase=Phase::Closed;Ok(())},
            Err(refusal)=>{let cause=refusal.cause().to_owned();self.state_mut().join_refusal=Some(MD::new(refusal));
                self.state_mut().phase=Phase::Failed;Err(cause)}}
    }
    pub async fn finish(mut self)->std::result::Result<ClosedInstalledDaemon,InstalledDaemonFailure> {
        if self.state().pending_active {
            self.cancel();return Err(InstalledDaemonFailure{
                cause:"original command outcome pending; entire daemon retained".into(),original:MD::new(self)});
        }
        match self.settle_original().await{Ok(())=>Ok(ClosedInstalledDaemon{original:MD::new(self)}),
            Err(cause)=>Err(InstalledDaemonFailure{cause,original:MD::new(self)})}
    }
}
impl Drop for InstalledDaemon {fn drop(&mut self){
    if self.original.is_some(){self.cancel();}
    // Native/private/task owners, pending replies and all predecessor/close
    // observations stay in the ENTIRE original heap; no abort or join in Drop.
    if let Some(original)=self.original.take(){let _custody=original;}
}}
