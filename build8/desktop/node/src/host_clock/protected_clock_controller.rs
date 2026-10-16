//! Ordinary V2 controller composition over the original installed interfaces.
//! Entire controller graphs are boxed before acquisition and retained on
//! abandonment. Node construction stays private to the genuine normal factory.
use super::protected_clock_application::{OwnedProtectedClockApplication,
    ProtectedClockApplicationStop,JoinedProtectedClockApplication,ApplicationRetainedClose};
#[cfg(target_os="linux")]
use super::protected_clock_node_query::{InstalledNodeClockQuery,NodeClockQueryFailure,NodeClockRetainedClose};
use std::mem::ManuallyDrop;
#[cfg(target_os="linux")]
use std::thread::{self,ThreadId};
type Result<T>=std::result::Result<T,String>;

struct OwnerState {
    application:Option<OwnedProtectedClockApplication>,stop:Option<ProtectedClockApplicationStop>,
    joined:Option<ManuallyDrop<JoinedProtectedClockApplication>>,
    retired:Vec<ManuallyDrop<ApplicationRetainedClose>>,
    record:Vec<u8>,own_genesis:Vec<u8>,failed:bool,
}
pub struct ProtectedClockController {original:Option<Box<ManuallyDrop<OwnerState>>>}
pub struct ProtectedClockControllerFailure {cause:String,original:ManuallyDrop<ProtectedClockController>}
impl ProtectedClockControllerFailure {pub fn cause(&self)->&str{&self.cause}}
impl Drop for ProtectedClockControllerFailure {fn drop(&mut self){self.original.stop();}}
/// Known original application/IPC/writer/current closes; no qualification.
pub struct ClosedProtectedClockController {original:ManuallyDrop<ProtectedClockController>}
impl ClosedProtectedClockController {
    pub fn retained_handles_closed(&self)->bool {
        let state=self.original.state();
        state.application.is_none()&&state.joined.is_none()&&!state.retired.is_empty()
            &&state.retired.iter().all(|r|r.retained_application_handles_closed())
    }
    /// Existing-only restart with the SAME record/Genesis request. Installed
    /// checks and the original protected same-boot/cross-boot logic run again.
    pub fn restart(self)->std::result::Result<ProtectedClockController,ProtectedClockControllerFailure> {
        if !self.retained_handles_closed(){return Err(ProtectedClockControllerFailure{
            cause:"original protected restart close incomplete".into(),original:self.original});}
        let mut original=ManuallyDrop::into_inner(self.original);
        let record=original.state().record.clone();let own_genesis=original.state().own_genesis.clone();
        match OwnedProtectedClockApplication::start(record,own_genesis) {
            Ok((application,stop))=>{let state=original.state_mut();state.application=Some(application);
                state.stop=Some(stop);state.failed=false;Ok(original)},
            Err(cause)=>Err(ProtectedClockControllerFailure{cause,original:ManuallyDrop::new(original)}),
        }
    }
}
impl ProtectedClockController {
    fn state(&self)->&OwnerState {&***self.original.as_ref().expect("original owner controller graph")}
    fn state_mut(&mut self)->&mut OwnerState {&mut ***self.original.as_mut().expect("original owner controller graph")}
    pub fn start(record:Vec<u8>,own_genesis:Vec<u8>)
        ->std::result::Result<Self,ProtectedClockControllerFailure> {
        // This stable holder precedes worker/native effects. Raw public requests
        // still pass the existing fixed installed issuer and dedicated principal.
        let mut out=Self{original:Some(Box::new(ManuallyDrop::new(OwnerState{
            application:None,stop:None,joined:None,retired:Vec::new(),record,own_genesis,failed:false})))};
        let record=out.state().record.clone();let own_genesis=out.state().own_genesis.clone();
        match OwnedProtectedClockApplication::start(record,own_genesis) {
            Ok((application,stop))=>{let state=out.state_mut();state.application=Some(application);state.stop=Some(stop);Ok(out)},
            Err(cause)=>{out.state_mut().failed=true;Err(ProtectedClockControllerFailure{cause,original:ManuallyDrop::new(out)})},
        }
    }
    pub fn started(&self)->Result<bool> {
        let state=self.state();if state.failed{return Err("protected owner controller frozen".into());}
        state.application.as_ref().ok_or("original protected application absent")?.started()
    }
    pub fn original_finished(&self)->bool {
        self.state().application.as_ref().is_some_and(|application|application.original_finished())
    }
    /// Signal only; original completion/closure is observed separately.
    pub fn stop(&self){if let Some(stop)=&self.state().stop{stop.stop();}}
    fn close_current(&mut self)->Result<()> {
        let state=self.state_mut();
        if state.failed{return Err("protected owner controller retains a prior unresolved outcome".into());}
        state.retired.try_reserve(1).map_err(|_|"original close observation allocation refused")?;
        state.failed=true;if let Some(stop)=&state.stop{stop.stop();}
        let application=state.application.take().ok_or("original application already consumed")?;
        state.joined=Some(ManuallyDrop::new(application.join()));
        state.joined.as_ref().expect("recorded original join").operation_result()?;
        let joined=ManuallyDrop::into_inner(state.joined.take().expect("original joined graph"));
        match joined.close_retained() {
            Ok(report)=>{let closed=report.retained_application_handles_closed();
                state.retired.push(ManuallyDrop::new(report));
                if !closed{return Err("original application retained close incomplete".into());}},
            Err(joined)=>{state.joined=Some(joined);return Err("original application close uncertain; graph retained".into());},
        }
        state.stop=None;Ok(())
    }
    /// Pure preflight rejection preserves the current owner. After stop begins,
    /// a refusal freezes this same graph; it never retries unknown closure.
    pub fn replace(&mut self,record:Vec<u8>,own_genesis:Vec<u8>)->Result<()> {
        if self.state().failed{return Err("protected replacement controller frozen".into());}
        if own_genesis!=self.state().own_genesis{return Err("protected replacement own Genesis changed".into());}
        if !self.started()?{return Err("original owner startup has not succeeded".into());}
        super::native_nts_deployment_record::require_successor(&self.state().record,&record)
            .map_err(|_|"protected replacement succession refused")?;
        let next_record=record.clone();let next_genesis=own_genesis.clone();
        self.close_current()?;
        let replacement=self.state_mut().retired.last_mut().expect("retained predecessor close")
            .take_replacement_retained().map_err(|_|"original stopped continuity unavailable")?;
        match OwnedProtectedClockApplication::start_replacement(next_record,next_genesis,replacement) {
            Ok((application,stop))=>{let state=self.state_mut();state.application=Some(application);state.stop=Some(stop);
                state.record=record;state.own_genesis=own_genesis;state.failed=false;Ok(())},
            Err(cause)=>Err(cause),
        }
    }
    /// Original blocking joins belong on the owned shutdown controller. Every
    /// refusal returns this SAME boxed graph, including completed observations.
    pub fn finish(mut self)->std::result::Result<ClosedProtectedClockController,ProtectedClockControllerFailure> {
        match self.close_current() {
            Ok(())=>Ok(ClosedProtectedClockController{original:ManuallyDrop::new(self)}),
            Err(cause)=>{self.stop();Err(ProtectedClockControllerFailure{cause,original:ManuallyDrop::new(self)})},
        }
    }
}
impl Drop for ProtectedClockController {
    fn drop(&mut self){
        if let Some(state)=self.original.as_ref(){if let Some(stop)=&state.stop{stop.stop();}}
        // Retain the ENTIRE original heap graph. In particular, freeing a Vec
        // of MD reports would lose the enclosing once-close observations.
        if let Some(original)=self.original.take(){let _custody=Box::into_raw(original);}
    }
}

#[cfg(target_os="linux")]
struct NodeState<B:mutiny_consensus_v8::counter_voter_v2::CounterSigningBackend> {
    query:Option<ManuallyDrop<InstalledNodeClockQuery>>,
    failure:Option<ManuallyDrop<NodeClockQueryFailure>>,close:Option<ManuallyDrop<NodeClockRetainedClose>>,
    thread:ThreadId,blocked:bool,
    registration:ManuallyDrop<crate::hybrid_installed_secret_source_v2::InstalledSecretSourceRegistration>,
    voter:ManuallyDrop<crate::hybrid_voter_v2::VotingRuntime<B>>,
    database:ManuallyDrop<crate::hybrid_installed_databases_v2::InstalledDatabases>,
    signer:ManuallyDrop<crate::hybrid_installed_signer_inputs_v2::InstalledSignerInputs>,record:Vec<u8>,
}
#[cfg(target_os="linux")]
pub(crate) struct OrdinaryNodeClockController<B:mutiny_consensus_v8::counter_voter_v2::CounterSigningBackend> {
    original:Option<Box<ManuallyDrop<NodeState<B>>>>,
}
#[cfg(target_os="linux")]
pub(crate) struct OrdinaryNodeClockFailure<B:mutiny_consensus_v8::counter_voter_v2::CounterSigningBackend> {
    cause:String,original:ManuallyDrop<OrdinaryNodeClockController<B>>,
}
#[cfg(target_os="linux")]
impl<B:mutiny_consensus_v8::counter_voter_v2::CounterSigningBackend> OrdinaryNodeClockFailure<B> {
    pub(crate) fn cause(&self)->&str{&self.cause}
}
#[cfg(target_os="linux")]
pub(crate) struct ClosedOrdinaryNodeClock<B:mutiny_consensus_v8::counter_voter_v2::CounterSigningBackend> {
    original:ManuallyDrop<OrdinaryNodeClockController<B>>,
}
#[cfg(target_os="linux")]
impl<B:mutiny_consensus_v8::counter_voter_v2::CounterSigningBackend> ClosedOrdinaryNodeClock<B> {
    pub(crate) fn retained_handles_closed(&self)->bool{
        let state=self.original.state();state.query.is_none()&&state.close.as_ref().is_some_and(|r|r.retained_handles_closed())
    }
    /// Return the SAME opaque native/selection owners to their existing factory
    /// shutdown transfer. Clock close alone does not close the native group.
    pub(crate) fn into_original_inputs(self)->(
        ManuallyDrop<crate::hybrid_voter_v2::VotingRuntime<B>>,
        ManuallyDrop<crate::hybrid_installed_databases_v2::InstalledDatabases>,
        ManuallyDrop<crate::hybrid_installed_signer_inputs_v2::InstalledSignerInputs>,
        ManuallyDrop<crate::hybrid_installed_secret_source_v2::InstalledSecretSourceRegistration>,
        ManuallyDrop<NodeClockRetainedClose>) {
        let mut controller=ManuallyDrop::into_inner(self.original);
        let state=ManuallyDrop::into_inner(*controller.original.take().expect("original closed Node graph"));
        (state.voter,state.database,state.signer,state.registration,state.close.expect("known original Node clock close"))
    }
}
#[cfg(target_os="linux")]
impl<B:mutiny_consensus_v8::counter_voter_v2::CounterSigningBackend> OrdinaryNodeClockController<B> {
    fn state(&self)->&NodeState<B>{&***self.original.as_ref().expect("original Node controller graph")}
    fn state_mut(&mut self)->&mut NodeState<B>{&mut ***self.original.as_mut().expect("original Node controller graph")}
    fn recheck(&mut self)->Result<()> {
        let state=self.state_mut();
        if state.thread!=thread::current().id(){return Err("ordinary Node moved from its original exclusive executor".into());}
        state.database.recheck_canonical(&state.voter.validator().chain)?;
        if state.voter.signer_node()!=state.database.node()?{return Err("original voter/installed Node identity differs".into());}
        state.signer.recheck(&mut state.database)?;
        if !state.record.is_empty()&&state.signer.clock_record()?!=state.record.as_slice(){
            return Err("original installed clock selection changed".into());}Ok(())
    }
    /// Existing conditional factory transfers its SAME replayed voter, held
    /// selections and source registration. No caller record/Genesis/role or
    /// secret constructor exists. Registration is currently uninhabited.
    pub(crate) async fn connect_from_original_inputs(
        registration:crate::hybrid_installed_secret_source_v2::InstalledSecretSourceRegistration,
        voter:crate::hybrid_voter_v2::VotingRuntime<B>,
        database:crate::hybrid_installed_databases_v2::InstalledDatabases,
        signer:crate::hybrid_installed_signer_inputs_v2::InstalledSignerInputs)
        ->std::result::Result<Self,OrdinaryNodeClockFailure<B>> {
        // Wrap original inputs before the stable holder allocation, using the
        // accepted constructor-custody pattern; no RAII release on unwind.
        let mut out=Self{original:Some(Box::new(ManuallyDrop::new(NodeState{
            query:None,failure:None,close:None,thread:thread::current().id(),blocked:true,
            registration:ManuallyDrop::new(registration),voter:ManuallyDrop::new(voter),
            database:ManuallyDrop::new(database),signer:ManuallyDrop::new(signer),record:Vec::new()})))};
        let inputs=(||->Result<(Vec<u8>,Vec<u8>)>{out.recheck()?;
            let state=out.state_mut();Ok((state.signer.clock_record()?.to_vec(),state.database.original_genesis_bytes()?.to_vec()))})();
        let (record,own_genesis)=match inputs{Ok(inputs)=>inputs,Err(cause)=>return Err(
            OrdinaryNodeClockFailure{cause,original:ManuallyDrop::new(out)})};
        out.state_mut().record=record;
        match InstalledNodeClockQuery::connect_installed(&out.state().record,&own_genesis).await {
            Ok(query)=>{out.state_mut().query=Some(ManuallyDrop::new(query));
                if let Err(cause)=out.recheck(){return Err(OrdinaryNodeClockFailure{cause,original:ManuallyDrop::new(out)});}
                out.state_mut().blocked=false;Ok(out)},
            Err(error)=>{let cause=error.description().to_owned();out.state_mut().failure=Some(ManuallyDrop::new(error));
                Err(OrdinaryNodeClockFailure{cause,original:ManuallyDrop::new(out)})},
        }
    }
    /// The authoritative existing V2 pure gate decides fresh-query need. Nil,
    /// guarded and exact durable replay retain the zero-RPC exemption. No cached
    /// VoteClock escapes, and current native checks bracket the actual sign.
    pub(crate) async fn sign(&mut self,step:mutiny_consensus_v8::bft::Step,
        block:Option<mutiny_consensus_v8::Hash>,pol:Option<u64>)
        ->std::result::Result<mutiny_consensus_v8::continuity_v2::Vote,crate::hybrid_voter_v2::VotingError> {
        use crate::hybrid_voter_v2::VotingError;
        if self.state().blocked{return Err(VotingError::Initialization("ordinary installed clock frozen/pending".into()));}
        self.state_mut().blocked=true;
        if let Err(cause)=self.recheck(){return Err(VotingError::Initialization(cause));}
        let Some(query)=self.state_mut().query.take() else{return Err(VotingError::Initialization("original Node query absent".into()));};
        // A dropped/panicked future leaves the stable original state blocked;
        // original installed query Drop retains pending native task/operation.
        let outcome=self.state_mut().voter.sign_with_installed_clock(ManuallyDrop::into_inner(query),step,block,pol).await;
        self.state_mut().query=outcome.query.map(ManuallyDrop::new);
        if let Err(cause)=self.recheck(){return Err(VotingError::Initialization(cause));}
        let state=self.state_mut();state.blocked=state.query.is_none();outcome.vote
    }
    /// No request at shutdown; only the SAME idle connection may close once.
    pub(crate) fn finish(mut self)->std::result::Result<ClosedOrdinaryNodeClock<B>,OrdinaryNodeClockFailure<B>> {
        if self.state().blocked{return Err(OrdinaryNodeClockFailure{
            cause:"original Node clock pending/frozen; custody retained".into(),original:ManuallyDrop::new(self)});}
        self.state_mut().blocked=true;
        if let Err(cause)=self.recheck(){return Err(OrdinaryNodeClockFailure{cause,original:ManuallyDrop::new(self)});}
        let Some(query)=self.state_mut().query.take() else{return Err(OrdinaryNodeClockFailure{
            cause:"original idle Node query absent".into(),original:ManuallyDrop::new(self)});};
        let report=ManuallyDrop::into_inner(query).close_idle_retained();
        let closed=report.retained_handles_closed();self.state_mut().close=Some(ManuallyDrop::new(report));
        if !closed{return Err(OrdinaryNodeClockFailure{
            cause:"original idle Node close incomplete; whole report/inputs retained".into(),original:ManuallyDrop::new(self)});}
        Ok(ClosedOrdinaryNodeClock{original:ManuallyDrop::new(self)})
    }
}
#[cfg(target_os="linux")]
impl<B:mutiny_consensus_v8::counter_voter_v2::CounterSigningBackend> Drop for OrdinaryNodeClockController<B> {
    fn drop(&mut self){if let Some(original)=self.original.take(){let _custody=Box::into_raw(original);}}
}

// Private signing remains the exact Source92-selected factory78/worker88/actor90
// composition: original pre-spawn cancellation, signer-thread session binding,
// gate-needed refresh, native ownership transfer, and original clock join/close.
// This module does not instantiate an unavailable registration or replace that
// factory with an independent public clock/Elapsed or secret constructor.