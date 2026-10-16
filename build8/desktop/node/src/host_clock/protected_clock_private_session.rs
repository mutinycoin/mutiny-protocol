//! One installed owner connection shared by the owned private signer worker.
//! Each activation capture replaces its opaque prepared receipt with a NEW
//! authenticated operation. Native RPC waits belong to the separate owned I/O
//! thread; current interval reconstruction occurs on the actual signer thread.
//! No timer, cached capture, caller qualification or second connection exists.
use super::protected_clock_node_query::{InstalledNodeClockQuery,PreparedNodeClockAttempt,NodeClockQueryFailure};
use mutiny_consensus_v8::{activation_attestation_v1::{Elapsed,ElapsedCapture,Failure},
    vote_clock_v1::{ClockReading,VoteClock}};
use std::{future::Future,mem::{ManuallyDrop,MaybeUninit},sync::{Arc,Mutex,
    atomic::{AtomicBool,Ordering},mpsc::{self,SyncSender}},task::{Poll,Waker},thread::{self,JoinHandle,ThreadId}};
type Result<T>=std::result::Result<T,String>;

struct Wake {stopped:AtomicBool,waker:Mutex<Option<Waker>>}
impl Wake {
    fn stop(&self){self.stopped.store(true,Ordering::SeqCst);
        if let Some(wake)=self.waker.lock().unwrap_or_else(|p|p.into_inner()).take(){wake.wake();}}
    fn stopped(&self)->bool{self.stopped.load(Ordering::SeqCst)}
}
enum Command {
    Refresh {previous:PreparedNodeClockAttempt,
        reply:SyncSender<std::result::Result<PreparedNodeClockAttempt,NodeClockQueryFailure>>},
    Stop,
}
struct StartControl {wake:Arc<Wake>,send:Mutex<Option<SyncSender<Command>>>,started:AtomicBool}
/// Non-clone startup token owns cancellation before any initial connection.
/// It creates no installed authority, endpoint or qualified observation.
pub(crate) struct PrivateClockSessionStart {control:Arc<StartControl>}
struct State {attempt:Option<PreparedNodeClockAttempt>,failure:Option<ManuallyDrop<NodeClockQueryFailure>>,
    worker_result:Option<Result<()>>,frozen:bool}
struct OwnedRefreshWorker {
    send:SyncSender<Command>,wake:Arc<Wake>,thread:Option<JoinHandle<()>>,
    control:Arc<StartControl>,
    // Allocated before spawn; abandonment never releases an unjoined worker.
    abandoned:Option<Box<MaybeUninit<(JoinHandle<()>,Arc<Wake>,Arc<Mutex<State>>)>>>,
    state:Arc<Mutex<State>>,
}
pub(crate) struct PrivateClockSessionStartFailure {
    error:String,state:ManuallyDrop<Arc<Mutex<State>>>,
}
impl PrivateClockSessionStartFailure{pub(crate) fn description(&self)->&str{&self.error}}
fn run_owned<T>(runtime:&tokio::runtime::Runtime,wake:&Arc<Wake>,
    future:impl Future<Output=std::result::Result<T,NodeClockQueryFailure>>)
    ->std::result::Result<T,NodeClockQueryFailure> {
    let mut query=Box::pin(future);
    let result=runtime.block_on(std::future::poll_fn(|cx|{
        *wake.waker.lock().unwrap_or_else(|p|p.into_inner())=Some(cx.waker().clone());
        if wake.stopped(){return Poll::Ready(Err(NodeClockQueryFailure::Inputs(
            "private clock RPC cancelled; operation outcome unknown".into())));}
        query.as_mut().poll(cx)
    }));
    *wake.waker.lock().unwrap_or_else(|p|p.into_inner())=None;
    // Pending native query Drop retains its complete uncertainty custody.
    drop(query);result
}
impl OwnedRefreshWorker {
    fn start(state:Arc<Mutex<State>>,record:Vec<u8>,own_genesis:Vec<u8>,start:PrivateClockSessionStart)
        ->std::result::Result<(Self,mpsc::Receiver<std::result::Result<PreparedNodeClockAttempt,NodeClockQueryFailure>>),PrivateClockSessionStartFailure> {
        let control=start.control;
        if control.started.compare_exchange(false,true,Ordering::SeqCst,Ordering::SeqCst).is_err()
            || control.wake.stopped(){return Err(PrivateClockSessionStartFailure{
                error:"private clock startup token reused/stopped before entry".into(),state:ManuallyDrop::new(state)});}
        let(send,receive)=mpsc::sync_channel::<Command>(1);
        let(initial_send,initial_receive)=mpsc::sync_channel(1);
        let wake=Arc::clone(&control.wake);
        // Publish the original bounded queue BEFORE spawning or beginning the
        // initial RPC. A concurrent early stop always sets the same wake flag;
        // a pre-publication stop therefore cannot be lost.
        *control.send.lock().unwrap_or_else(|p|p.into_inner())=Some(send.clone());
        let worker_wake=Arc::clone(&wake);let worker_state=Arc::clone(&state);
        let abandoned=Some(Box::new(MaybeUninit::uninit()));
        let launched=thread::Builder::new().name("mutiny-private-clock-rpc".into()).spawn(move||{
            let result=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||->Result<()>{
                let runtime=tokio::runtime::Builder::new_current_thread().enable_all().build()
                    .map_err(|e|format!("owned clock RPC runtime refused: {e}"))?;
                // The socket/reactor and every subsequent operation belong to
                // THIS same owned runtime. Moving an already connected Unix
                // socket from a temporary caller runtime is not permitted.
                let initial=run_owned(&runtime,&worker_wake,async {
                    InstalledNodeClockQuery::connect_installed(&record,&own_genesis).await?.prepare().await
                });
                let initial_failed=initial.is_err();
                initial_send.send(initial).map_err(|_|"private factory abandoned installed connection".to_owned())?;
                if initial_failed{return Err("initial installed clock operation refused".into());}
                loop{
                    if worker_wake.stopped(){break;}
                    match receive.recv(){
                        Ok(Command::Stop)|Err(_)=>break,
                        Ok(Command::Refresh{previous,reply})=>{
                            // Cancellation drops the owned refresh future. Its
                            // native query retains original pending identity,
                            // buffers, handles and task; runtime destruction
                            // cannot report this thread joined while its actual
                            // blocking tasks remain unsettled.
                            let response=run_owned(&runtime,&worker_wake,previous.refresh());
                            if reply.send(response).is_err(){return Err("private caller abandoned owned clock result".into());}
                        },
                    }
                }
                // Runtime drops here, before the original std thread returns.
                // No shutdown_timeout or detached blocking-thread escape.
                Ok(())
            })).unwrap_or_else(|_|Err("private clock RPC worker unwound; native custody retained".into()));
            // Release queued senders BEFORE acquiring the caller's state mutex;
            // a failed runtime/spawned exchange must wake a caller waiting for
            // its reply, rather than deadlock while that caller owns the mutex.
            drop(receive);
            if result.is_err(){worker_wake.stop();}
            let mut state=worker_state.lock().unwrap_or_else(|p|p.into_inner());
            if result.is_err(){state.frozen=true;}state.worker_result=Some(result);
        });
        match launched{
            Ok(thread)=>Ok((Self{send,wake,thread:Some(thread),control,abandoned,state},initial_receive)),
            Err(error)=>{wake.stop();state.lock().unwrap_or_else(|p|p.into_inner()).frozen=true;
                Err(PrivateClockSessionStartFailure{error:format!("private clock RPC spawn refused: {error}"),state:ManuallyDrop::new(state)})},
        }
    }
    fn stop(&self){self.wake.stop();let _signal=self.send.try_send(Command::Stop);}
    fn refresh(&self,previous:PreparedNodeClockAttempt)
        ->std::result::Result<PreparedNodeClockAttempt,NodeClockQueryFailure> {
        let(reply,receive)=mpsc::sync_channel(1);
        if self.wake.stopped(){return Err(NodeClockQueryFailure::Inputs("private clock worker already stopped".into()));}
        self.send.send(Command::Refresh{previous,reply}).map_err(|_|NodeClockQueryFailure::Inputs(
            "private clock worker unavailable; exact connection abandoned".into()))?;
        receive.recv().map_err(|_|NodeClockQueryFailure::Inputs("private clock result unknown; no retry".into()))?
    }
    fn join(mut self)->Result<()> {
        self.stop();let joined=self.thread.take().ok_or("original private clock worker absent")?.join();
        if joined.is_err(){return Err("original private clock worker join failed".into());}
        self.state.lock().map_err(|_|"joined private worker state poisoned")?.worker_result.clone()
            .ok_or_else(||String::from("original worker returned without a published outcome"))?
    }
}
impl Drop for OwnedRefreshWorker {
    fn drop(&mut self){self.stop();if let Some(thread)=self.thread.take(){
        let mut holder=self.abandoned.take().expect("preallocated original private worker custody");
        holder.write((thread,Arc::clone(&self.wake),Arc::clone(&self.state)));
        let _custody=Box::into_raw(unsafe{holder.assume_init()});
    }}
}

pub(crate) struct InstalledPrivateClockSession {
    state:Arc<Mutex<State>>,worker:Option<OwnedRefreshWorker>,signer_thread:ThreadId,joined_transferred:bool,
}
/// Signal-only capability. It cannot create a query, reset a connection or
/// release pending native holders. Completed shutdown requires original join.
pub(crate) struct PrivateClockSessionStop {control:Arc<StartControl>}
impl PrivateClockSessionStop {
    pub(crate) fn stop(&self){self.control.wake.stop();
        if let Some(send)=self.control.send.lock().unwrap_or_else(|p|p.into_inner()).as_ref(){let _signal=send.try_send(Command::Stop);}}
}
/// The opaque last receipt remains owned after the I/O thread actually joins.
/// Closing its transport/current guard is a separate explicit operation.
pub(crate) struct JoinedPrivateClockSession {state:ManuallyDrop<Arc<Mutex<State>>>}
impl JoinedPrivateClockSession {
    /// ORIGINAL I/O runtime/thread joined successfully before this stage.
    /// Known completed attempt only; any pending/failed/shared custody stays
    /// retained. Closure creates no fresh time, new RPC or replacement token.
    pub(crate) fn close_retained(self)->std::result::Result<super::protected_clock_node_query::NodeClockRetainedClose,ManuallyDrop<Self>> {
        if Arc::strong_count(&self.state)!=1{return Err(ManuallyDrop::new(self));}
        let ready={match self.state.lock(){Ok(state)=>!state.frozen&&state.failure.is_none()
            &&matches!(&state.worker_result,Some(Ok(())))&&state.attempt.is_some(),Err(_)=>false}};
        if !ready{return Err(ManuallyDrop::new(self));}
        let attempt={self.state.lock().expect("checked joined private state").attempt.take().expect("original completed private attempt")};
        let report=attempt.close_retained();drop(ManuallyDrop::into_inner(self.state));Ok(report)
    }
}
impl InstalledPrivateClockSession {
    /// Prepare on the controller BEFORE spawning the private crypto worker.
    /// The stop capability remains valid during initial installed connect and
    /// first operation; it has no reset/query/qualification authority.
    pub(crate) fn prepare_start()->(PrivateClockSessionStart,PrivateClockSessionStop) {
        let control=Arc::new(StartControl{wake:Arc::new(Wake{
            stopped:AtomicBool::new(false),waker:Mutex::new(None)}),
            send:Mutex::new(None),started:AtomicBool::new(false)});
        (PrivateClockSessionStart{control:Arc::clone(&control)},PrivateClockSessionStop{control})
    }
    /// Invoke in the NORMAL factory's already owned exclusive private signing
    /// worker. This binds its real current ThreadId, not a caller-supplied ID.
    /// Exact public record/Genesis bytes are verified by the existing installed
    /// issuer INSIDE the owned reactor; they are not authority or caller claims.
    /// No key is retained by the I/O worker. The private factory owns any wait.
    pub(crate) fn connect_on_private_worker(record:Vec<u8>,own_genesis:Vec<u8>,start:PrivateClockSessionStart)
        ->std::result::Result<Self,PrivateClockSessionStartFailure> {
        let state=Arc::new(Mutex::new(State{attempt:None,failure:None,worker_result:None,frozen:false}));
        let(worker,initial)=OwnedRefreshWorker::start(Arc::clone(&state),record,own_genesis,start)?;
        let result=initial.recv().unwrap_or_else(|_|Err(NodeClockQueryFailure::Inputs(
            "installed clock startup outcome unknown; exact custody retained".into())));
        match result{
            Ok(attempt)=>{state.lock().unwrap_or_else(|p|p.into_inner()).attempt=Some(attempt);},
            Err(error)=>{let mut locked=state.lock().unwrap_or_else(|p|p.into_inner());locked.frozen=true;
                let description=error.description().to_owned();locked.failure=Some(ManuallyDrop::new(error));drop(locked);
                worker.stop();drop(worker);
                return Err(PrivateClockSessionStartFailure{error:description,state:ManuallyDrop::new(state)});},
        }
        Ok(Self{state,worker:Some(worker),signer_thread:thread::current().id(),joined_transferred:false})
    }
    pub(crate) fn stop_handle(&self)->PrivateClockSessionStop {
        let worker=self.worker.as_ref().expect("original private clock worker");
        PrivateClockSessionStop{control:Arc::clone(&worker.control)}
    }
    fn on_signer_thread(&self)->Result<()> {
        if thread::current().id()!=self.signer_thread{return Err("private clock entry outside its owned signer thread".into());}
        if self.worker.as_ref().ok_or("private clock worker absent")?.wake.stopped(){return Err("private clock session stopped".into());}
        Ok(())
    }
    /// Called only after the authoritative pure voter gate indicates a fresh
    /// clock is needed. Nil/guarded/exact durable replay never call this route.
    pub(crate) fn prepare_next_vote_attempt(&self)->Result<()> {
        self.on_signer_thread()?;
        let previous={let mut state=self.state.lock().map_err(|_|"private clock state poisoned")?;
            if state.frozen{return Err("private clock session frozen".into());}
            state.attempt.take().ok_or("private clock attempt absent")?};
        // No shared mutex is held during I/O. Only the bound private signing
        // thread waits; actor/UI tasks never execute this synchronous entry.
        let refreshed=self.worker.as_ref().expect("owned worker").refresh(previous);
        let mut state=self.state.lock().map_err(|_|"private clock state poisoned")?;
        match refreshed{
            Ok(attempt)=>{state.attempt=Some(attempt);self.on_signer_thread()},
            Err(error)=>{state.frozen=true;state.failure=Some(ManuallyDrop::new(error));
                Err("new private clock operation failed; exact custody retained".into())},
        }
    }
    pub(crate) fn current_reading(&self)->Result<ClockReading> {
        self.on_signer_thread()?;let mut state=self.state.lock().map_err(|_|"private clock state poisoned")?;
        if state.frozen{return Err("private clock session frozen".into());}
        let result=state.attempt.as_mut().ok_or("private clock attempt absent")?.reading();
        match result{Ok(reading)=>{self.on_signer_thread()?;Ok(reading)},Err(error)=>{state.frozen=true;state.failure=Some(ManuallyDrop::new(error));
            Err("private clock current reconstruction failed".into())}}
    }
    /// Current installation/own native guard only: no owner query, external
    /// floor, time qualification or new requirement for nil/durable replay.
    pub(crate) fn recheck_installed_only(&self)->Result<()> {
        self.on_signer_thread()?;let mut state=self.state.lock().map_err(|_|"private clock state poisoned")?;
        if state.frozen{return Err("private clock session frozen".into());}
        let result=state.attempt.as_mut().ok_or("private clock attempt absent")?.recheck_installed_only();
        match result{Ok(())=>{self.on_signer_thread()?;Ok(())},Err(error)=>{state.frozen=true;state.failure=Some(ManuallyDrop::new(error));
            Err("private installed native inputs changed".into())}}
    }
    /// NEW operation for every required private activation capture, followed
    /// by actual CURRENT reconstruction on this exact signer thread.
    fn fresh_capture(&self)->Result<Option<ElapsedCapture>> {
        self.prepare_next_vote_attempt()?;
        let mut state=self.state.lock().map_err(|_|"private clock state poisoned")?;
        let result=state.attempt.as_mut().ok_or("private capture attempt absent")?.capture_current();
        match result{Ok(capture)=>{self.on_signer_thread()?;Ok(capture)},
            Err(error)=>{state.frozen=true;state.failure=Some(ManuallyDrop::new(error));Err("private capture current reconstruction failed".into())}}
    }
    /// Blocking original-thread join belongs on the owned private shutdown
    /// route. It supplies no transport/event/guard/lineage replacement token.
    pub(crate) fn join(mut self)->Result<JoinedPrivateClockSession> {
        self.worker.take().ok_or("original private clock worker absent")?.join()?;
        {
            let state=self.state.lock().map_err(|_|"joined private clock state poisoned")?;
            if state.frozen || state.failure.is_some() || state.attempt.is_none(){return Err("joined private clock retains unknown outcome".into());}
        }
        self.joined_transferred=true;
        Ok(JoinedPrivateClockSession{state:ManuallyDrop::new(Arc::clone(&self.state))})
    }
}
impl Drop for InstalledPrivateClockSession {
    fn drop(&mut self){if let Some(worker)=&self.worker{worker.stop();}
        // Preserve the entire last receipt even if the last caller abandons
        // this session. The worker's Drop separately retains original join.
        if !self.joined_transferred{let _custody=Arc::into_raw(Arc::clone(&self.state));}}
}
impl VoteClock for InstalledPrivateClockSession {
    fn reading(&self)->ClockReading{self.current_reading().unwrap_or(ClockReading::Unqualified)}
}
impl Elapsed for InstalledPrivateClockSession {
    fn elapsed(&self)->std::result::Result<std::time::Duration,Failure>{Err(Failure::Elapsed)}
    fn capture(&self)->std::result::Result<ElapsedCapture,Failure>{
        self.fresh_capture().map_err(|_|Failure::Elapsed)?.ok_or(Failure::Elapsed)
    }
}
