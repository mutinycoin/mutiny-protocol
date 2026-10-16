//! NORMAL dedicated-principal application coupling. All installation/current/
//! qualification gates run on the owned application thread before endpoint
//! creation. The protected owner, genuine acquisition scheduler and IPC remain
//! together until original-thread shutdown. No service/account installation,
//! credentials, calibration fixture, profile default or detached join exists.
use super::protected_clock_owner::{ProtectedClockOwner,ProtectedOwnerDispatcher,ProtectedAcquisitionOutcome};
use std::{future::{Future,poll_fn},mem::{ManuallyDrop,MaybeUninit},sync::{Arc,Mutex,
    atomic::{AtomicBool,Ordering}},task::{Poll,Waker},thread::JoinHandle,time::Duration};
type Result<T>=std::result::Result<T,String>;

struct Wake {stopped:AtomicBool,waker:Mutex<Option<Waker>>}
impl Wake {
    fn signal(&self){self.stopped.store(true,Ordering::SeqCst);
        if let Some(wake)=self.waker.lock().unwrap_or_else(|p|p.into_inner()).take(){wake.wake();}}
    fn stopped(&self)->bool{self.stopped.load(Ordering::SeqCst)}
}
/// Signal-only controller capability, allocated before any worker starts.
pub(crate) struct ProtectedClockApplicationStop {wake:Arc<Wake>}
impl ProtectedClockApplicationStop {pub(crate) fn stop(&self){self.wake.signal();}}
struct Core {
    owner:Option<Box<ProtectedClockOwner>>,
    #[cfg(target_os="linux")]
    listener:Option<Box<super::protected_clock_unix_channel::InstalledUnixListener>>,
    #[cfg(target_os="linux")]
    connection:Option<Box<super::protected_clock_unix_channel::InstalledUnixConnection>>,
    #[cfg(windows)]
    ipc:Option<super::protected_clock_windows_channel::OwnedOwnerWorker>,
    #[cfg(windows)]
    joined_ipc:Option<ManuallyDrop<super::protected_clock_windows_channel::JoinedOwnerWorker>>,
}
impl Core {fn new()->Self {Self{owner:None,
    #[cfg(target_os="linux")]listener:None,#[cfg(target_os="linux")]connection:None,
    #[cfg(windows)]ipc:None,#[cfg(windows)]joined_ipc:None}}}
impl Drop for Core {
    fn drop(&mut self){
        // Unwind/abandonment is never whole lifecycle closure. Retain every
        // original native writer, listener/peer and installed-current guard.
        if let Some(owner)=self.owner.take(){let _custody=Box::into_raw(owner);}
        #[cfg(target_os="linux")]
        {if let Some(listener)=self.listener.take(){let _custody=Box::into_raw(listener);}
         if let Some(connection)=self.connection.take(){let _custody=Box::into_raw(connection);}}
        // Windows worker Drop already signals cancellation and quarantines its
        // original JoinHandle and complete server slot. Joined IPC is MD.
    }
}
struct Slot {core:Option<Box<Core>>,result:Option<Result<()>>,started:bool,
    last_acquisition_failure:Option<String>}
pub(crate) struct OwnedProtectedClockApplication {
    thread:Option<JoinHandle<()>>,slot:Arc<Mutex<Slot>>,wake:Arc<Wake>,
    abandoned:Option<Box<MaybeUninit<(JoinHandle<()>,Arc<Mutex<Slot>>,Arc<Wake>)>>>,
}
/// Original worker joined; exact holders remain in custody. This is not a
/// transport/event/guard/lineage close assertion or a replacement capability.
pub(crate) struct JoinedProtectedClockApplication {slot:ManuallyDrop<Arc<Mutex<Slot>>>,joined:bool}
enum OwnerRetainedClose {
    Closed(std::result::Result<super::native_nts_deployment_record::SelectionRetainedClose,
        ManuallyDrop<super::native_nts_deployment_record::NativeSelectionGuard>>),
    Quarantined(ManuallyDrop<super::protected_clock_owner::OwnerLineageCloseFailure>),
    TransportUnknown(ManuallyDrop<Box<ProtectedClockOwner>>),
}
/// Reports only ORIGINAL retained application holders after natural joins.
/// Prior transient RAII/quarantines and stale endpoint names are not closed or
/// erased here. This is deliberately not a replacement/startup authorization.
/// Linear, private controller capability: no Clone, raw bytes or caller bool.
/// It preserves the exact stopped predecessor, complete protected history and
/// original native identities after every retained application holder closes.
pub(crate) struct ProtectedClockReplacement {
    continuity:super::protected_clock_owner::ClosedLineageContinuity,
}
impl ProtectedClockReplacement {
    pub(super) fn into_lineage(self)->super::protected_clock_owner::ClosedLineageContinuity{self.continuity}
}
pub(crate) struct ApplicationRetainedClose {
    owner:Option<OwnerRetainedClose>,continuity:Option<super::protected_clock_owner::ClosedLineageContinuity>,
    #[cfg(target_os="linux")]
    listener:Option<std::result::Result<super::protected_clock_unix_channel::UnixRetainedClose,
        ManuallyDrop<super::protected_clock_unix_channel::InstalledUnixListener>>>,
    #[cfg(target_os="linux")]
    connection:Option<std::result::Result<super::protected_clock_unix_channel::UnixRetainedClose,
        ManuallyDrop<super::protected_clock_unix_channel::InstalledUnixConnection>>>,
    #[cfg(windows)]
    ipc:Option<std::result::Result<super::protected_clock_windows_channel::JoinedOwnerRetainedClose,
        ManuallyDrop<super::protected_clock_windows_channel::JoinedOwnerWorker>>>,
}
impl ApplicationRetainedClose {
    /// Preserve original close observations while moving only the established
    /// one-use stopped-lineage continuity into the installed successor.
    pub(crate) fn take_replacement_retained(&mut self)->std::result::Result<ProtectedClockReplacement,()> {
        if !self.retained_application_handles_closed(){return Err(());}
        self.continuity.take().map(|continuity|ProtectedClockReplacement{continuity}).ok_or(())
    }
    pub(crate) fn into_replacement(mut self)->std::result::Result<ProtectedClockReplacement,Self> {
        if !self.retained_application_handles_closed(){return Err(self);}
        match self.continuity.take(){Some(continuity)=>Ok(ProtectedClockReplacement{continuity}),None=>Err(self)}
    }
    fn transport_closed(&self)->bool {
        #[cfg(target_os="linux")]
        let transport=self.listener.as_ref().is_some_and(|r|r.as_ref().is_ok_and(|r|r.retained_handles_closed()))
            &&self.connection.as_ref().is_none_or(|r|r.as_ref().is_ok_and(|r|r.retained_handles_closed()));
        #[cfg(windows)]
        let transport=self.ipc.as_ref().is_some_and(|r|r.as_ref().is_ok_and(|r|r.retained_handles_closed()));
        #[cfg(not(any(target_os="linux",windows)))]
        let transport=false;
        transport
    }
    pub(crate) fn retained_application_handles_closed(&self)->bool {
        matches!(&self.owner,Some(OwnerRetainedClose::Closed(Ok(r))) if r.retained_handles_closed())&&self.transport_closed()
    }
}
fn combine(first:Result<()>,next:Result<()>,label:&str)->Result<()> {
    match(first,next){(Err(first),Err(next))=>Err(format!("{first}; {label}: {next}")),
        (Ok(()),Err(next))=>Err(format!("{label}: {next}")),(first,Ok(()))=>first}
}
async fn acquire_loop(owner:&mut ProtectedClockOwner,cadence:Duration,wake:&Arc<Wake>,
    slot:&Arc<Mutex<Slot>>,dispatcher:&ProtectedOwnerDispatcher)->Result<()> {
    loop {
        if wake.stopped(){return Ok(());}
        let result=owner.acquire_for_application().await;
        match result {
            Ok(ProtectedAcquisitionOutcome::DurablyStoppedAfterNativeJoin)=>return Ok(()),
            Ok(ProtectedAcquisitionOutcome::Applied(_)) if wake.stopped()=>return Ok(()),
            Ok(ProtectedAcquisitionOutcome::Applied(_))=>{},
            Err(error) if wake.stopped()=>return Err(error),
            Err(error)=>{
            slot.lock().map_err(|_|"application result mutex poisoned")?.last_acquisition_failure=Some(error);
            // A network/provider refusal may leave legitimate bounded holdover.
            // Storage/current/unknown failure instead revokes this SAME owner.
            dispatcher.channel_context()?;
            },
        }
        let mut next=Box::pin(tokio::time::sleep(cadence));
        poll_fn(|cx| {if wake.stopped(){Poll::Ready(())}else{next.as_mut().poll(cx)}}).await;
    }
}
#[cfg(target_os="linux")]
async fn serve_linux(listener:&mut super::protected_clock_unix_channel::InstalledUnixListener,
    connection:&mut Option<Box<super::protected_clock_unix_channel::InstalledUnixConnection>>,
    dispatcher:&ProtectedOwnerDispatcher,record:&[u8],genesis:&[u8])->Result<()> {
    let stop=dispatcher.stop_handle();
    loop {
        let stopped=poll_fn(|cx|Poll::Ready(stop.poll_stopped(cx).is_ready())).await;
        if stopped {
            if let Some(connection)=connection{connection.idle_for_stop()?;}
            listener.idle_for_stop()?;return stop.stop_checked();
        }
        if connection.is_none(){
            let authority=super::native_nts_deployment_record::issue_installed_channel(record,genesis,
                super::protected_clock_unix_channel::ChannelRole::Owner).map_err(|e|format!("installed peer registration: {e:?}"))?;
            let mut accepting=Box::pin(listener.accept(authority));
            let accepted=poll_fn(|cx| {
                if stop.poll_stopped(cx).is_ready(){return Poll::Ready(Ok(None));}
                match accepting.as_mut().poll(cx){Poll::Ready(result)=>Poll::Ready(result.map(Some)),Poll::Pending=>Poll::Pending}
            }).await?;
            drop(accepting);
            let Some(accepted)=accepted else {listener.idle_for_stop()?;return stop.stop_checked();};
            *connection=Some(Box::new(accepted));
        }
        // A disconnected/ambiguous logical connection stops the application;
        // no silent reconnect or exact-operation replay is invented here.
        if matches!(connection.as_mut().ok_or("installed connection absent")?.serve_cancellable(dispatcher).await?,
            super::protected_clock_unix_channel::UnixOwnerIpcStep::StoppedBeforeOperation){
            listener.idle_for_stop()?;return stop.stop_checked();
        }
    }
}
fn run(core:&mut Core,runtime:&tokio::runtime::Runtime,wake:&Arc<Wake>,slot:&Arc<Mutex<Slot>>,
    record:&[u8],genesis:&[u8],replacement:Option<ProtectedClockReplacement>)->Result<()> {
    if wake.stopped(){return Err("owner application stopped before installed entry".into());}
    let(owner,cadence)=match replacement {
        Some(proof)=>super::native_nts_deployment_record::open_installed_protected_successor(record,genesis,proof),
        None=>super::native_nts_deployment_record::open_installed_protected_application(record,genesis),
    }
        .map_err(|e|format!("installed protected application refused: {e:?}"))?;
    core.owner=Some(Box::new(owner));
    let owner=core.owner.as_mut().ok_or("installed protected owner absent")?;
    let stop=owner.stop_handle();let dispatcher=owner.dispatcher();
    if wake.stopped(){return stop.stop_checked();}
    #[cfg(windows)]
    {
        let authority=super::native_nts_deployment_record::issue_installed_windows_channel(record,genesis,
            super::protected_clock_windows_channel::ChannelRole::Owner).map_err(|e|format!("installed owner endpoint: {e:?}"))?;
        let server=super::protected_clock_windows_channel::InstalledAsyncOwnerServer::bind_new(authority)
            .map_err(|error|{let text=error.description().to_owned();let _custody=Box::into_raw(Box::new(error));text})?;
        core.ipc=Some(super::protected_clock_windows_channel::OwnedOwnerWorker::start(server,owner.dispatcher())
            .map_err(|error|{let text=error.description().to_owned();let _custody=Box::into_raw(Box::new(error));text})?);
    }
    let entered=runtime.enter();
    #[cfg(target_os="linux")]
    {
        let authority=super::native_nts_deployment_record::issue_installed_channel(record,genesis,
            super::protected_clock_unix_channel::ChannelRole::Owner).map_err(|e|format!("installed owner endpoint: {e:?}"))?;
        core.listener=Some(Box::new(super::protected_clock_unix_channel::InstalledUnixListener::bind_new(authority)?));
    }
    drop(entered);
    slot.lock().map_err(|_|"application startup mutex poisoned")?.started=true;
    let mut durable_stop=None;
    let result=runtime.block_on(async {
        let mut acquisition=Box::pin(acquire_loop(owner,cadence,wake,slot,&dispatcher));
        #[cfg(target_os="linux")]
        let mut ipc=Box::pin(serve_linux(core.listener.as_mut().ok_or("listener absent")?,
            &mut core.connection,&dispatcher,record,genesis));
        #[cfg(target_os="linux")]
        let mut ipc_outcome:Option<Result<()>>=None;
        #[cfg(windows)]
        let mut ipc_outcome:Option<Result<()>>=Some(Ok(()));
        let mut acquisition_finished:Option<Result<()>>=None;
        let acquisition_outcome=poll_fn(|cx| {
            *wake.waker.lock().unwrap_or_else(|p|p.into_inner())=Some(cx.waker().clone());
            if stop.poll_stopped(cx).is_ready(){wake.signal();}
            if wake.stopped() && durable_stop.is_none(){durable_stop=Some(stop.stop_checked());
                #[cfg(windows)] if let Some(ipc)=&core.ipc{if let Err(error)=ipc.stop(){ipc_outcome=Some(Err(error));}}}
            #[cfg(target_os="linux")]
            if ipc_outcome.is_none(){
                if let Poll::Ready(result)=ipc.as_mut().poll(cx){ipc_outcome=Some(result);wake.signal();cx.waker().wake_by_ref();}
            }
            if acquisition_finished.is_none(){
                if let Poll::Ready(result)=acquisition.as_mut().poll(cx){acquisition_finished=Some(result);wake.signal();cx.waker().wake_by_ref();}
            }
            if acquisition_finished.is_some() && ipc_outcome.is_some(){Poll::Ready(acquisition_finished.take().expect("original acquisition outcome"))}
            else{Poll::Pending}
        }).await;
        // Drop only the Linux borrowed operation future. Native socket/peer/
        // endpoint/installed guard stay in Core; interrupted call freezes itself.
        #[cfg(target_os="linux")]drop(ipc);
        combine(acquisition_outcome,ipc_outcome.unwrap_or(Ok(())),"owner IPC")
    });
    *wake.waker.lock().unwrap_or_else(|p|p.into_inner())=None;wake.signal();
    let result=combine(result,durable_stop.unwrap_or_else(||stop.stop_checked()),"durable owner stop");
    result
}
impl OwnedProtectedClockApplication {
    /// No process/service launch or privilege change. The actual worker must
    /// already run as the installation-selected dedicated principal.
    /// Return immediately; started()/result inspection never blocks an actor.
    pub(crate) fn start(record:Vec<u8>,own_genesis:Vec<u8>)
        ->Result<(Self,ProtectedClockApplicationStop)> {
        Self::start_inner(record,own_genesis,None)
    }
    /// No reset/initial head/new journal or stale endpoint adoption. The fixed
    /// installation must already select the exact qualified successor naming
    /// this predecessor. Explicit predecessor close removed only its ORIGINAL
    /// bound socket under the SAME stopped writer lease; start never unlinks,
    /// adopts a foreign stale name or changes installation/ACLs.
    pub(crate) fn start_replacement(record:Vec<u8>,own_genesis:Vec<u8>,replacement:ProtectedClockReplacement)
        ->Result<(Self,ProtectedClockApplicationStop)> {
        Self::start_inner(record,own_genesis,Some(replacement))
    }
    fn start_inner(record:Vec<u8>,own_genesis:Vec<u8>,mut replacement:Option<ProtectedClockReplacement>)
        ->Result<(Self,ProtectedClockApplicationStop)> {
        let wake=Arc::new(Wake{stopped:AtomicBool::new(false),waker:Mutex::new(None)});
        let slot=Arc::new(Mutex::new(Slot{core:Some(Box::new(Core::new())),result:None,started:false,last_acquisition_failure:None}));
        let worker_wake=Arc::clone(&wake);let worker_slot=Arc::clone(&slot);
        let abandoned=Some(Box::new(MaybeUninit::uninit()));
        let launched=std::thread::Builder::new().name("mutiny-protected-clock-owner".into()).spawn(move||{
            let mut core=worker_slot.lock().unwrap_or_else(|p|p.into_inner()).core.take().expect("one owner application core");
            let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build()
                    .map_err(|e|format!("owner application runtime refused: {e}"))?;
                let outcome=run(&mut core,&runtime,&worker_wake,&worker_slot,&record,&own_genesis,replacement.take());
                // No timeout/destructor escape: original runtime destruction
                // precedes publication and original std-thread return.
                drop(runtime);outcome
            })).unwrap_or_else(|_|Err("owner application unwound; complete original custody retained".into()));
            worker_wake.signal();
            // Attempt shutdown independently after EVERY body outcome, even a
            // post-creation startup error or caught unwind. Do not publish the
            // application thread as complete while its original IPC is live.
            let mut result=result;
            #[cfg(target_os="linux")]
            {
                // Revoke independently after every returned/caught outcome.
                // The ORIGINAL socket is still held in Core. Unknown request/
                // acquisition outcomes stay retained; shutdown releases no
                // buffer, descriptor, record or writer and proves no outcome.
                if let Some(connection)=core.connection.as_mut(){
                    result=combine(result,connection.shutdown_after_join(),"original UNIX endpoint revocation");
                }
            }
            if let Some(owner)=&core.owner {
                result=combine(result,owner.stop_handle().stop_checked(),"final checked owner stop");
            }
            #[cfg(windows)]
            if let Some(ipc)=core.ipc.take(){
                let joined=ipc.join();
                let outcome=if joined.thread_joined(){joined.operation_result()}
                    else{Err("original IPC thread did not join".into())};
                result=combine(result,outcome,"original IPC shutdown");
                core.joined_ipc=Some(ManuallyDrop::new(joined));
            }
            let mut slot=worker_slot.lock().unwrap_or_else(|p|p.into_inner());slot.core=Some(core);slot.result=Some(result);
        });
        match launched{Ok(thread)=>Ok((Self{thread:Some(thread),slot,wake:Arc::clone(&wake),abandoned},ProtectedClockApplicationStop{wake})),
            Err(error)=>{wake.signal();let _custody=Arc::into_raw(slot);Err(format!("owner application spawn refused: {error}"))}}
    }
    pub(crate) fn started(&self)->Result<bool>{Ok(self.slot.lock().map_err(|_|"owner startup mutex poisoned")?.started)}
    pub(crate) fn original_finished(&self)->bool {
        self.thread.as_ref().is_some_and(JoinHandle::is_finished)
    }
    /// Use only the owned controller's blocking shutdown route, never actor/UI.
    pub(crate) fn join(mut self)->JoinedProtectedClockApplication {
        self.wake.signal();let joined=self.thread.take().expect("original owner application thread").join().is_ok();
        JoinedProtectedClockApplication{slot:ManuallyDrop::new(Arc::clone(&self.slot)),joined}
    }
}
impl Drop for OwnedProtectedClockApplication {
    fn drop(&mut self){self.wake.signal();if let Some(thread)=self.thread.take(){
        let mut holder=self.abandoned.take().expect("preallocated application thread custody");
        holder.write((thread,Arc::clone(&self.slot),Arc::clone(&self.wake)));
        let _custody=Box::into_raw(unsafe{holder.assume_init()});}}
}
impl JoinedProtectedClockApplication {
    pub(crate) fn thread_joined(&self)->bool{self.joined}
    pub(crate) fn operation_result(&self)->Result<()> {
        if !self.joined{return Err("original application thread join failed".into());}
        self.slot.lock().map_err(|_|"joined application mutex poisoned")?.result.clone()
            .ok_or_else(||String::from("original application returned without a recorded result"))?
    }
    /// Explicit consuming controller route AFTER both original application and
    /// native acquisition/IPC joins and SAME-owner durable stop succeeded.
    /// Any partial/failed result keeps the entire core rather than releasing a
    /// writer/guard to retry or manufacture replacement authority.
    pub(crate) fn close_retained(self)->std::result::Result<ApplicationRetainedClose,ManuallyDrop<Self>> {
        if self.operation_result().is_err() || Arc::strong_count(&self.slot)!=1 {
            return Err(ManuallyDrop::new(self));
        }
        let core={match self.slot.lock(){Ok(mut state)=>state.core.take(),Err(_)=>None}};
        let Some(mut core)=core else{return Err(ManuallyDrop::new(self));};
        // Inline custody for every success/failure exists before first close.
        let mut report=ApplicationRetainedClose{owner:None,continuity:None,
            #[cfg(target_os="linux")]listener:None,#[cfg(target_os="linux")]connection:None,
            #[cfg(windows)]ipc:None};
        #[cfg(target_os="linux")]
        {
            if let Some(connection)=core.connection.take(){report.connection=Some((*connection).close_retained());}
            if let Some(mut listener)=core.listener.take(){
                let cleanup=if report.connection.as_ref().is_none_or(|r|r.as_ref().is_ok_and(|r|r.retained_handles_closed())) {
                    core.owner.as_ref().ok_or_else(||"cleanup original owner absent".to_string()).and_then(|owner|owner.stopped_namespace_lease())
                        .and_then(|mut lease|listener.remove_bound_after_join(&mut lease))
                }else{Err("cleanup connection close outcome unresolved".into())};
                report.listener=Some(if cleanup.is_ok(){(*listener).close_retained()}else{Err(ManuallyDrop::new(*listener))});
            }
        }
        #[cfg(windows)]
        {
            if let Some(ipc)=core.joined_ipc.take(){report.ipc=Some(ManuallyDrop::into_inner(ipc).close_retained());}
        }
        if let Some(owner)=core.owner.take(){report.owner=Some(if report.transport_closed(){
            match (*owner).close_lineage(){
                Ok(closed)=>{
                    let(result,continuity)=closed.close_for_successor();
                    if result.as_ref().is_ok_and(|r|r.retained_handles_closed()){report.continuity=Some(continuity);}
                    OwnerRetainedClose::Closed(result)
                },
                Err(error)=>OwnerRetainedClose::Quarantined(ManuallyDrop::new(error)),
            }
        }else{OwnerRetainedClose::TransportUnknown(ManuallyDrop::new(owner))});}
        // Empty Core no longer has any native holder to release via Drop.
        // It never contained a live IPC worker after a successful application.
        drop(core);drop(ManuallyDrop::into_inner(self.slot));Ok(report)
    }
}
