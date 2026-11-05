use super::*;
/// Owns the actual Windows owner worker; no detached task or elapsed timer.
/// The same dispatcher supplies the stop capability. Cancellation signals
/// native I/O; the worker disconnects and durably stops before joining returns.
/// Only explicit JoinedOwnerWorker::close_retained closes its installed guard
/// and cancellation event. Lineage closes separately; no replacement token.
pub(in super::super) struct OwnedOwnerWorker {
    thread:Option<std::thread::JoinHandle<()>>,
    slot:Arc<std::sync::Mutex<OwnerWorkerSlot>>,
    cancellation:Option<ManuallyDrop<FreshRequestCancellation>>,
    abandoned:Option<Box<std::mem::MaybeUninit<(std::thread::JoinHandle<()>,Arc<std::sync::Mutex<OwnerWorkerSlot>>)>>>,
}
struct OwnerWorkerSlot {server:Option<InstalledAsyncOwnerServer>,result:Option<Result<()>>}
pub(in super::super) struct OwnerWorkerStartFailure {
    error:String,slot:ManuallyDrop<Arc<std::sync::Mutex<OwnerWorkerSlot>>>,
    cancellation:Option<ManuallyDrop<FreshRequestCancellation>>,
}
impl OwnerWorkerStartFailure {pub(in super::super) fn description(&self)->&str{&self.error}}
pub(in super::super) struct JoinedOwnerWorker {
    slot:Arc<std::sync::Mutex<OwnerWorkerSlot>>,
    cancellation:Option<ManuallyDrop<FreshRequestCancellation>>,
    joined:bool,
}
pub(in super::super) struct JoinedOwnerRetainedClose {
    transport:JoinedTransportClose,
    cancellation:JoinedCancellationClose,
}
enum JoinedTransportClose {
    Closed(std::result::Result<WindowsRetainedTransportClose,ManuallyDrop<WindowsTransportClose>>),
    Quarantined(ManuallyDrop<InstalledAsyncOwnerServer>),
}
enum JoinedCancellationClose {
    Closed(std::result::Result<(),CompletedCancellationFailure>),
    Quarantined(ManuallyDrop<FreshRequestCancellation>),
}
impl JoinedOwnerRetainedClose {pub(in super::super) fn retained_handles_closed(&self)->bool {
    matches!(&self.cancellation,JoinedCancellationClose::Closed(Ok(())))
        &&matches!(&self.transport,JoinedTransportClose::Closed(Ok(r)) if r.retained_handles_closed())
}}
impl OwnedOwnerWorker {
    pub(in super::super) fn start(mut server:InstalledAsyncOwnerServer,
        owner:super::super::protected_clock_owner::ProtectedOwnerDispatcher)
        ->std::result::Result<Self,OwnerWorkerStartFailure> {
        let stop=owner.stop_handle();
        if let Err(error)=server.require_dispatcher(&owner){
            let slot=Arc::new(std::sync::Mutex::new(OwnerWorkerSlot{server:Some(server),result:Some(Err(error.clone()))}));
            return Err(OwnerWorkerStartFailure{error,slot:ManuallyDrop::new(slot),cancellation:None});
        }
        let cancellation=match FreshRequestCancellation::new_owner_cancellation(){
            Ok(cancellation)=>cancellation,
            Err(error)=>{
                let slot=Arc::new(std::sync::Mutex::new(OwnerWorkerSlot{server:Some(server),result:Some(Err(error.clone()))}));
                stop.stop();return Err(OwnerWorkerStartFailure{error,slot:ManuallyDrop::new(slot),cancellation:None});
            },
        };
        let worker_cancel=FreshRequestCancellation{inner:ManuallyDrop::new(Arc::clone(&cancellation.inner))};
        let slot=Arc::new(std::sync::Mutex::new(OwnerWorkerSlot{server:Some(server),result:None}));
        let worker_slot=Arc::clone(&slot);
        let worker_stop=owner.stop_handle();
        let abandoned=Some(Box::new(std::mem::MaybeUninit::uninit()));
        // Slots, holder and cancellation ownership exist BEFORE spawn. Spawn
        // refusal retains them; no native endpoint is silently recreated.
        let launched=std::thread::Builder::new().name("mutiny-clock-owner-ipc".into()).spawn(move||{
            let mut server={let mut state=worker_slot.lock().unwrap_or_else(|p|p.into_inner());
                state.server.take().expect("one exclusive owner worker")};
            let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
                match server.connect(&worker_cancel)? {
                    OwnerIpcStep::StoppedBeforeOperation=>return Ok(()),
                    OwnerIpcStep::Continue=>{},
                }
                loop {
                    match server.serve_one(&owner,&worker_cancel)? {
                        OwnerIpcStep::StoppedBeforeOperation=>return Ok(()),
                        OwnerIpcStep::Continue=>{},
                    }
                }
            })).unwrap_or_else(|_|Err("owner worker unwound; endpoint/operation retained".into()));
            let cancelled=worker_cancel.cancel();
            // Invalidate the actual client connection before publishing thread
            // completion. Native buffers remain owned if their outcome is unknown.
            let disconnect=server.disconnect_for_stop();
            let stopped=worker_stop.stop_checked();
            let result=match (result,disconnect){
                (Err(first),Err(last))=>Err(format!("{first}; endpoint invalidation: {last}")),
                (Ok(()),Err(error))=>Err(error),(result,Ok(()))=>result,
            };
            let result=match (result,cancelled){
                (Err(first),Err(last))=>Err(format!("{first}; cancellation signal: {last}")),
                (Ok(()),Err(error))=>Err(error),(result,Ok(()))=>result,
            };
            let result=match (result,stopped){
                (Err(first),Err(last))=>Err(format!("{first}; durable owner stop: {last}")),
                (Ok(()),Err(error))=>Err(error),(result,Ok(()))=>result,
            };
            let mut state=worker_slot.lock().unwrap_or_else(|p|p.into_inner());
            state.server=Some(server);state.result=Some(result);drop(state);
            // Original worker returned: release only its cancellation reference.
            drop(ManuallyDrop::into_inner(worker_cancel.inner));
        });
        match launched {
            Ok(thread)=>Ok(Self{thread:Some(thread),slot,cancellation:Some(ManuallyDrop::new(cancellation)),abandoned}),
            Err(error)=>{let _cancel_result=cancellation.cancel();stop.stop();
                Err(OwnerWorkerStartFailure{error:format!("owner worker spawn refused: {error}"),
                    slot:ManuallyDrop::new(slot),cancellation:Some(ManuallyDrop::new(cancellation))})},
        }
    }
    /// Signal only; successful signal is not completed owner revocation.
    /// The original worker disconnects then durably stops before join returns.
    pub(in super::super) fn stop(&self)->Result<()> {
        self.cancellation.as_ref().ok_or("owner cancellation ownership absent")?.cancel()
    }
    /// Blocking join belongs on the controller's owned blocking shutdown route,
    /// never an actor/UI. Cancellation alone supplies no join or close credit.
    pub(in super::super) fn join(mut self)->JoinedOwnerWorker {
        let cancelled=self.stop();
        let joined=self.thread.take().expect("original owner thread").join().is_ok();
        if !joined || cancelled.is_err(){
            let mut state=self.slot.lock().unwrap_or_else(|p|p.into_inner());
            let original=state.result.take();
            let mut errors=Vec::new();
            if let Some(Err(error))=original{errors.push(error);}
            if !joined{errors.push("original owner worker join failed; exact holders retained".into());}
            if let Err(error)=cancelled{errors.push(format!("controller cancellation signal: {error}"));}
            state.result=Some(Err(errors.join("; ")));
        }
        let slot=Arc::clone(&self.slot);
        let cancellation=self.cancellation.take();
        JoinedOwnerWorker{slot,cancellation,joined}
    }
}
impl Drop for OwnedOwnerWorker {
    fn drop(&mut self){if let Some(cancel)=&self.cancellation{let _cancel_result=cancel.cancel();}
        if let Some(thread)=self.thread.take(){
            // No detached completion assertion: retain original JoinHandle and
            // result slot until explicit shutdown or process termination.
            let mut holder=self.abandoned.take().expect("preallocated original thread custody");
            holder.write((thread,Arc::clone(&self.slot)));
            let _thread_custody=Box::into_raw(unsafe{holder.assume_init()});
        }}
}
impl JoinedOwnerWorker {
    pub(in super::super) fn thread_joined(&self)->bool{self.joined}
    pub(in super::super) fn operation_result(&self)->Result<()> {
        self.slot.lock().map_err(|_|"joined owner slot poisoned")?.result.clone()
            .ok_or_else(||String::from("joined owner result missing; no outcome"))?
    }
    /// The returned server still owns any unresolved I/O/pending ID. Its narrow
    /// close method must refuse unknown native state; this is NOT whole lineage
    /// or installed-selection lifecycle closure or a replacement token.
    pub(in super::super) fn into_server(self)->std::result::Result<InstalledAsyncOwnerServer,Self> {
        if !self.joined{return Err(self);}
        let server={match self.slot.lock(){Ok(mut state)=>state.server.take(),Err(_)=>None}};
        match server{Some(server)=>Ok(server),None=>Err(self)}
    }
    /// ORIGINAL IPC thread returned successfully after checked durable stop and
    /// disconnect. Do not consume any unknown result, sharing or pending I/O.
    pub(in super::super) fn close_retained(mut self)->std::result::Result<JoinedOwnerRetainedClose,ManuallyDrop<Self>> {
        if !self.joined || self.operation_result().is_err() || self.cancellation.is_none()
            || Arc::strong_count(&self.slot)!=1 {return Err(ManuallyDrop::new(self));}
        let ready={match self.slot.lock(){Ok(mut state)=>state.server.as_mut()
            .ok_or_else(||"joined server missing".to_string()).and_then(|server|server.require_joined_close_ready()),
            Err(_)=>Err("joined server mutex poisoned".into())}};
        if ready.is_err(){return Err(ManuallyDrop::new(self));}
        let server={self.slot.lock().expect("checked original slot").server.take().expect("checked original server")};
        let transport=match server.close_transport(){Ok(report)=>JoinedTransportClose::Closed(report.close_installed_retained()),
            Err(server)=>{
                // Readiness was checked immediately above, but preserve a
                // contradictory internal state as the complete endpoint.
                JoinedTransportClose::Quarantined(ManuallyDrop::new(server))
            }};
        let owned_cancel=self.cancellation.take().expect("original joined cancellation");
        let cancellation=if matches!(&transport,JoinedTransportClose::Closed(_)) {
            JoinedCancellationClose::Closed(ManuallyDrop::into_inner(owned_cancel).close_joined())
        }else{JoinedCancellationClose::Quarantined(owned_cancel)};
        Ok(JoinedOwnerRetainedClose{transport,cancellation})
    }
}
