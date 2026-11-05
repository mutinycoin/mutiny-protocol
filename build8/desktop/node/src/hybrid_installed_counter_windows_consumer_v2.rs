//! Windows factory component over the original installed counter issuer and
//! same-object native pipe. It issues no secret source, worker, SQLite provider,
//! key, profile, principal, TPM provision/reset action or clock qualification.
#![cfg(windows)]
use std::{mem::ManuallyDrop as MD,sync::Arc,thread::{self,ThreadId}};
use mutiny_consensus_v8::{Hash,canonical_store_v2::CanonicalStore,counter_store::MonotonicCounter};
use crate::{hybrid_authenticated_counter_v2::{ExactCounter,ExistingExactCounterRefusal},
    hybrid_installed_counter_windows_v2::{InstalledCounterWindowsAuthority,AuthorizedWindowsCounterPeer,WindowsCounterAuthorityFailure},
    hybrid_counter_windows_transport_v2::{PreparedWindowsCounterConnection,WindowsCounterNativeTransport,
        WindowsCounterTransportFailure,WindowsCounterTransportClose,WindowsCounterStop},
    host_clock::RetainedCloseReport};
type Result<T>=std::result::Result<T,String>;
type Counter=ExactCounter<WindowsCounterNativeTransport>;

struct State {
    original_thread:ThreadId,node:Hash,context:Option<Hash>,ciphertext_pins:Option<(Hash,Hash)>,
    chain:Option<MD<CanonicalStore>>,stop:Option<MD<Arc<WindowsCounterStop>>>,
    authority:Option<MD<InstalledCounterWindowsAuthority>>,
    prepared:Option<MD<PreparedWindowsCounterConnection>>,
    permission:Option<MD<AuthorizedWindowsCounterPeer>>,transport:Option<MD<WindowsCounterNativeTransport>>,
    counter:Option<MD<Counter>>,authority_failure:Option<MD<WindowsCounterAuthorityFailure>>,
    transport_failure:Option<MD<WindowsCounterTransportFailure>>,
    counter_failure:Option<MD<ExistingExactCounterRefusal<WindowsCounterNativeTransport>>>,
    transport_close:Option<MD<WindowsCounterTransportClose>>,selection_close:Option<MD<RetainedCloseReport>>,
    frozen:bool,closed:bool,cancel_result:Option<Result<()>>,operation_error:Option<String>,
}
/// Only the future genuine original Windows private factory can call this
/// crate-private component. A held canonical context is not a secret issuer.
pub(crate) struct InstalledWindowsCounterConsumer {original:Option<MD<Box<State>>>}
pub(crate) struct WindowsCounterConsumerFailure {cause:String,original:MD<InstalledWindowsCounterConsumer>}
impl WindowsCounterConsumerFailure {pub(crate) fn cause(&self)->&str{&self.cause}}
impl Drop for WindowsCounterConsumerFailure {fn drop(&mut self){self.original.signal_abandonment();}}
pub(crate) struct ClosedWindowsCounterConsumer {original:MD<InstalledWindowsCounterConsumer>}
/// Retains the ORIGINAL transport and selection close observations even after
/// original canonical/stop ownership transfers to its factory's separate close.
pub(crate) struct WindowsCounterConsumerCloseReceipt {original:MD<InstalledWindowsCounterConsumer>}
impl WindowsCounterConsumerCloseReceipt {
    pub(crate) fn original_counter_handles_closed(&self)->bool{self.original.counter_handles_closed()}
}
pub(crate) struct WindowsCounterFactoryParts {
    pub(crate) original_chain:MD<CanonicalStore>,pub(crate) original_stop:MD<Arc<WindowsCounterStop>>,
    pub(crate) original_counter_close:WindowsCounterConsumerCloseReceipt,
}
impl ClosedWindowsCounterConsumer {
    pub(crate) fn original_counter_handles_closed(&self)->bool{self.original.counter_handles_closed()}
    /// No new chain/session/event is opened. The existing factory must retain
    /// these SAME owners through actual original worker join/database shutdown.
    /// In particular this grants no stop-event close before original join.
    pub(crate) fn into_original_factory_parts(mut self)->WindowsCounterFactoryParts {
        let state=self.original.state_mut();
        let original_chain=state.chain.take().expect("closed original canonical observer");
        let original_stop=state.stop.take().expect("original stop transfer");
        WindowsCounterFactoryParts{original_chain,original_stop,
            original_counter_close:WindowsCounterConsumerCloseReceipt{original:self.original}}
    }
}
impl InstalledWindowsCounterConsumer {
    fn state(&self)->&State{&***self.original.as_ref().expect("original Windows counter graph")}
    fn state_mut(&mut self)->&mut State{&mut ***self.original.as_mut().expect("original Windows counter graph")}
    pub(crate) fn open_on_original_worker(chain:MD<CanonicalStore>,node:Hash,stop:Arc<WindowsCounterStop>)
        ->std::result::Result<Self,WindowsCounterConsumerFailure> {
        // Incoming holders and all failure/outcome slots precede native work.
        // The original issuer still checks actual Production/current/principal/
        // profile/NV/ciphertext/incarnation facts; no caller Boolean is added.
        let stop=MD::new(stop);
        let mut original=Self{original:Some(MD::new(Box::new(State{
            original_thread:thread::current().id(),node,context:None,ciphertext_pins:None,
            chain:Some(chain),stop:Some(stop),authority:None,prepared:None,permission:None,
            transport:None,counter:None,authority_failure:None,transport_failure:None,counter_failure:None,
            transport_close:None,selection_close:None,frozen:true,closed:false,cancel_result:None,operation_error:None})))};
        let initialized=(||->Result<()>{
            let state=original.state_mut();
            let chain=state.chain.take().ok_or("original Windows counter canonical context absent")?;
            match InstalledCounterWindowsAuthority::open_from_own_chain(chain,state.node){
                Ok(authority)=>state.authority=Some(MD::new(authority)),
                Err(failure)=>{let cause=failure.cause.clone();state.authority_failure=Some(MD::new(failure));return Err(cause);}
            }
            let stop=Arc::clone(&**state.stop.as_ref().ok_or("original Windows counter stop absent")?);
            match PreparedWindowsCounterConnection::connect_existing(
                &**state.authority.as_ref().ok_or("original installed counter authority absent")?,stop) {
                Ok(prepared)=>state.prepared=Some(MD::new(prepared)),
                Err(failure)=>{let cause=failure.description().to_owned();state.transport_failure=Some(MD::new(failure));return Err(cause);}
            }
            let authority=MD::into_inner(state.authority.take().ok_or("same original authority absent")?);
            let observed=state.prepared.as_ref().ok_or("same original prepared pipe absent")?.observation();
            match authority.bind_observed_peer(observed){
                Ok(permission)=>state.permission=Some(MD::new(permission)),
                Err(failure)=>{let cause=failure.cause.clone();state.authority_failure=Some(MD::new(failure));return Err(cause);}
            }
            let permission=state.permission.as_ref().ok_or("original one-use permission absent")?;
            let profile=permission.profile().clone();let nv=permission.nv_public_sha256();
            let context=permission.context();state.context=Some(context);
            state.ciphertext_pins=Some(permission.encrypted_role_pins());
            let prepared=MD::into_inner(state.prepared.take().ok_or("same observed pipe absent")?);
            let permission=MD::into_inner(state.permission.take().ok_or("same original pipe permission absent")?);
            match prepared.authorize(permission){
                Ok(transport)=>state.transport=Some(MD::new(transport)),
                Err(failure)=>{let cause=failure.description().to_owned();state.transport_failure=Some(MD::new(failure));return Err(cause);}
            }
            let transport=state.transport.take().ok_or("same authorized counter transport absent")?;
            match Counter::from_retained_endpoint(transport,profile,nv,context){
                Ok(counter)=>state.counter=Some(MD::new(counter)),
                Err(failure)=>{let cause=failure.cause().to_owned();state.counter_failure=Some(MD::new(failure));return Err(cause);}
            }
            state.frozen=false;Ok(())
        })();
        match initialized{Ok(())=>Ok(original),Err(cause)=>Err(WindowsCounterConsumerFailure{
            cause,original:MD::new(original)})}
    }
    fn require_original_live(&self)->Result<()> {
        let state=self.state();
        if state.original_thread!=thread::current().id()||state.frozen||state.closed{
            return Err("original Windows counter worker pending/frozen/stopped".into());}Ok(())
    }
    pub(crate) fn selected_context(&self)->Result<Hash>{
        self.require_original_live()?;self.state().context.ok_or_else(||"original counter context absent".into())
    }
    pub(crate) fn selected_role_ciphertext_pins(&self)->Result<(Hash,Hash)>{
        self.require_original_live()?;self.state().ciphertext_pins.ok_or_else(||"original selected role pins absent".into())
    }
    /// Signal the SAME original cancellation event once and preserve its actual
    /// result. Cancellation never grants entitlement non-consumption, a native
    /// close, original worker join or permission to repeat an uncertain NV op.
    pub(crate) fn request_cancel(&mut self)->Result<()> {
        if self.state().closed{return Err("original counter already closed".into());}
        self.signal_abandonment();
        self.state().cancel_result.as_ref().expect("original cancel observation").clone()
    }
    fn signal_abandonment(&mut self){
        let state=self.state_mut();
        if state.closed||state.cancel_result.is_some(){return;}
        state.frozen=true;
        state.cancel_result=Some(match state.stop.as_ref(){Some(stop)=>stop.signal(),None=>Err("original stop absent".into())});
    }
    fn counter_handles_closed(&self)->bool {
        let state=self.state();state.closed&&state.counter.is_none()&&state.transport.is_none()
            &&state.authority.is_none()&&state.permission.is_none()&&state.prepared.is_none()
            &&state.transport_close.as_ref().is_some_and(|report|report.transport_handles_closed())
            &&state.selection_close.as_ref().is_some_and(|report|report.retained_handles_closed())
    }
    /// SAME original exclusive worker has returned from its last NV operation.
    /// This performs existing settled transport/selection closes only; it does
    /// not join that worker, close its cancellation event or close SQLite.
    pub(crate) fn close_settled(mut self)->std::result::Result<ClosedWindowsCounterConsumer,WindowsCounterConsumerFailure> {
        let closed=(||->Result<()>{
            self.require_original_live()?;let state=self.state_mut();state.frozen=true;
            let counter=state.counter.take().ok_or("original exact counter absent")?;
            match MD::into_inner(counter).into_existing_endpoint(){
                Ok(transport)=>state.transport=Some(transport),
                Err(counter)=>{state.counter=Some(counter);return Err("original NV unknown outcome retained".into());}
            }
            let transport=MD::into_inner(state.transport.take().ok_or("original settled transport absent")?);
            match transport.close_settled(){
                Ok(report)=>state.transport_close=Some(MD::new(report)),
                Err(failure)=>{let cause=failure.description().to_owned();state.transport_failure=Some(MD::new(failure));return Err(cause);}
            }
            let report=state.transport_close.as_mut().ok_or("original transport close absent")?;
            if !report.transport_handles_closed(){return Err("original transport once-close unknown; retained without retry".into());}
            state.permission=Some(report.take_retained_permission().map_err(|_|"original closed transport permission consumed")?);
            let permission=MD::into_inner(state.permission.take().ok_or("original closed-pipe permission absent")?);
            match permission.close_after_transport(){
                Ok((chain,report))=>{state.chain=Some(chain);state.selection_close=Some(MD::new(report));},
                Err(failure)=>{let cause=failure.cause.clone();state.authority_failure=Some(MD::new(failure));return Err(cause);}
            }
            if !state.selection_close.as_ref().ok_or("original selected-current close absent")?.retained_handles_closed(){
                return Err("original counter selection/current close incomplete".into());}
            state.closed=true;Ok(())
        })();
        match closed{Ok(())=>Ok(ClosedWindowsCounterConsumer{original:MD::new(self)}),
            Err(cause)=>Err(WindowsCounterConsumerFailure{cause,original:MD::new(self)})}
    }
}
impl MonotonicCounter for InstalledWindowsCounterConsumer {
    fn read(&mut self)->Result<u64>{
        self.require_original_live()?;let state=self.state_mut();state.frozen=true;
        let result=state.counter.as_mut().ok_or("same exact counter absent")?.read();
        match result{Ok(value)=>{state.frozen=false;Ok(value)},Err(cause)=>{state.operation_error=Some(cause.clone());Err(cause)}}
    }
    fn increment(&mut self)->Result<()> {
        self.require_original_live()?;let state=self.state_mut();state.frozen=true;
        let result=state.counter.as_mut().ok_or("same exact counter absent")?.increment();
        match result{Ok(())=>{state.frozen=false;Ok(())},Err(cause)=>{state.operation_error=Some(cause.clone());Err(cause)}}
    }
}
impl Drop for InstalledWindowsCounterConsumer {fn drop(&mut self){
    if self.original.is_some(){self.signal_abandonment();}
    // Retain the ENTIRE original heap, all native/failure/close slots and SAME
    // canonical/stop custody. No unsafe Send assertion, automatic close/retry,
    // new worker, force-close or native token/credential bypass is provided.
    if let Some(original)=self.original.take(){let _custody=original;}
}}
