//! Ordinary library facade. The original private worker constructs and owns
//! all non-Send database/key/provider state. Only bounded commands and public
//! results cross its channel. No caller passwords, paths or profiles are read.
#![cfg(target_os="linux")]
use std::{mem::{ManuallyDrop as MD,MaybeUninit},sync::{Arc,Weak,atomic::{AtomicBool,Ordering},mpsc},thread::{self,JoinHandle}};
use mutiny_consensus_v8::{Hash,bft::Step,continuity_v2::Vote,activation_attestation_v1::Request};
use crate::{activation_private_owner_v1::OwnedTargets,hybrid_counter_unix_v2::{CounterStop,CounterStopClose},
    hybrid_normal_factory_v2::InstalledPrivateFactory,host_clock::{InstalledPrivateClockSession,PrivateClockSessionStop}};
struct ReplyWake{waiter:std::sync::Mutex<Option<std::task::Waker>>}
struct ReplySender<T>{send:Option<mpsc::SyncSender<std::result::Result<T,String>>>,wake:Arc<ReplyWake>}
impl<T> ReplySender<T>{
    fn send(&self,value:std::result::Result<T,String>)->std::result::Result<(),mpsc::SendError<std::result::Result<T,String>>>{
        let sent=self.send.as_ref().expect("original reply sender").send(value);
        // Publish before waking. The mutex holds scheduling state only, never
        // time, qualification, key/provider authority or a signing decision.
        let waiter=self.wake.waiter.lock().unwrap_or_else(|v|v.into_inner()).take();
        if let Some(waiter)=waiter{waiter.wake();}sent
    }
}
impl<T> Drop for ReplySender<T>{fn drop(&mut self){
    // Publish channel disconnection BEFORE waking the actual registered actor.
    // No wake-before-drop gap can leave a refused startup/command pending.
    self.send.take();
    let waiter=self.wake.waiter.lock().unwrap_or_else(|v|v.into_inner()).take();
    if let Some(waiter)=waiter{waiter.wake();}
}}
pub struct InstalledReply<T>{receive:mpsc::Receiver<std::result::Result<T,String>>,wake:Arc<ReplyWake>}
fn reply_channel<T>()->(ReplySender<T>,InstalledReply<T>){
    let(send,receive)=mpsc::sync_channel(1);let wake=Arc::new(ReplyWake{waiter:std::sync::Mutex::new(None)});
    (ReplySender{send:Some(send),wake:Arc::clone(&wake)},InstalledReply{receive,wake})
}
impl<T> std::future::Future for InstalledReply<T>{type Output=std::result::Result<T,String>;
    fn poll(self:std::pin::Pin<&mut Self>,cx:&mut std::task::Context<'_>)->std::task::Poll<Self::Output>{
        let own=self.as_ref().get_ref();
        match own.receive.try_recv(){
            Ok(v)=>return std::task::Poll::Ready(v),
            Err(mpsc::TryRecvError::Disconnected)=>return std::task::Poll::Ready(Err("original private worker reply unknown".into())),
            Err(mpsc::TryRecvError::Empty)=>(),
        }
        let mut slot=own.wake.waiter.lock().unwrap_or_else(|v|v.into_inner());
        *slot=Some(cx.waker().clone());
        // Register then recheck under the same scheduling lock. Publication
        // before registration is observed here; publication afterward wakes
        // this exact waiter. No polling cadence or protocol deadline is added.
        match own.receive.try_recv(){
            Ok(v)=>{slot.take();std::task::Poll::Ready(v)},
            Err(mpsc::TryRecvError::Disconnected)=>{slot.take();std::task::Poll::Ready(Err("original private worker reply unknown".into()))},
            Err(mpsc::TryRecvError::Empty)=>std::task::Poll::Pending,
        }
    }
}
impl<T> InstalledReply<T>{
    /// Nonblocking; actual actor scheduling remains the actor's own transport
    /// and wake policy. There is no new poll period, timeout or receipt cache.
    pub fn poll(&self)->std::result::Result<Option<std::result::Result<T,String>>,String>{
        match self.receive.try_recv(){Ok(v)=>Ok(Some(v)),Err(mpsc::TryRecvError::Empty)=>Ok(None),
            Err(mpsc::TryRecvError::Disconnected)=>Err("original private worker reply unknown".into())}
    }
}
enum Command{
    Request{step:Step,block:Option<Hash>,pol:Option<u64>,reply:ReplySender<Option<Request>>},
    Sign{step:Step,block:Option<Hash>,pol:Option<u64>,targets:Option<OwnedTargets>,reply:ReplySender<Vote>},
    Dispatch{message:crate::hybrid_installed_daemon_v2::InstalledPeerMessage,reply:ReplySender<crate::hybrid_installed_daemon_v2::InstalledPeerMessage>},
    Finish,
}
// Ordinary compile-only composition check. No runtime/test selector or unsafe
// trait assertion: the compiler must prove real retained commands are Send.
fn require_original_command_send(){fn check<T:Send>(){}check::<MD<Command>>();}
pub struct InstalledCommandRefusal{cause:String,original:Option<MD<Command>>}
impl InstalledCommandRefusal{pub fn cause(&self)->&str{&self.cause}}
struct Abandoned{thread:JoinHandle<std::result::Result<(),String>>,send:Option<mpsc::SyncSender<MD<Command>>>,
    counter_stop:MD<Arc<CounterStop>>,clock_stop:Arc<PrivateClockSessionStop>,admitting:Arc<AtomicBool>}
/// Signals the SAME original clock/counter holders without the owned-join
/// mutex. Weak references do not prevent the original exclusive native close.
/// This capability creates no wake, runtime, source registration or owner.
pub(crate) struct InstalledWorkerCancellation {
    counter:Weak<CounterStop>,clock:Weak<PrivateClockSessionStop>,admitting:Arc<AtomicBool>,
}
impl InstalledWorkerCancellation {
    pub(crate) fn stop(&self)->std::result::Result<(),String>{
        self.admitting.store(false,Ordering::SeqCst);
        let clock=self.clock.upgrade();
        if let Some(clock)=clock.as_ref(){clock.stop();}
        // Signal whichever original is available, retaining a real refusal
        // when either original capability has already been consumed.
        let counter_result=match self.counter.upgrade(){Some(counter)=>counter.stop(),
            None=>Err("original counter cancellation holder unavailable after transfer".into())};
        if clock.is_none(){return Err("original clock cancellation holder unavailable after transfer".into());}
        counter_result
    }
}
pub struct InstalledPrivateWorker{
    thread:Option<JoinHandle<std::result::Result<(),String>>>,send:Option<mpsc::SyncSender<MD<Command>>>,
    counter_stop:Option<MD<Arc<CounterStop>>>,clock_stop:Option<Arc<PrivateClockSessionStop>>,admitting:Arc<AtomicBool>,
    startup:InstalledReply<()>,abandoned:Option<Box<MaybeUninit<Abandoned>>>,
    // Populated immediately from the ORIGINAL once-join; the exact private
    // body error or opaque panic payload stays owned on refusal. No late owner
    // allocation, outcome replacement or second join is possible.
    original_outcome:Option<thread::Result<std::result::Result<(),String>>>,
    // Before any consuming wake close, keep an outcome slot inside this same
    // whole worker. A blocking join task can unwind without releasing it.
    wake_outcome:Option<CounterStopClose>,
}
pub struct InstalledWorkerCloseRefusal{cause:String,worker:MD<InstalledPrivateWorker>,wake:Option<CounterStopClose>}
impl InstalledWorkerCloseRefusal{pub fn cause(&self)->&str{&self.cause}}
impl InstalledPrivateWorker{
    pub fn start_installed()->std::result::Result<Self,String>{
        // Governing installer input classification: no accepted installed
        // Node/Continuity secret-source kind, issuer pins or ownership contract
        // has been supplied. This public entry performs NO native acquisition
        // and cannot infer that authority from an administrator descriptor,
        // SSH identity, clock account, existing endpoint or TEST provider.
        Self::start_registered(crate::hybrid_installed_secret_source_v2::require_registered_source()?)
    }
    /// Actual worker implementation is composed below, but is reachable only
    /// with an opaque accepted secret-source registration. That capability is
    /// currently uninhabited; adding a new source requires an attributable
    /// accepted mechanism, not a caller password or approval Boolean.
    pub(crate) fn start_registered(_source:crate::hybrid_installed_secret_source_v2::InstalledSecretSourceRegistration)
        ->std::result::Result<Self,String>{
        // Allocate abandonment storage and the admission flag before native
        // wake acquisition or any worker spawn. Opaque Start/Stop precedes the
        // signer spawn and can cancel its initial installed clock connection.
        let abandoned=Box::new(MaybeUninit::uninit());
        let admitting=Arc::new(AtomicBool::new(true));
        let (send,receive)=mpsc::sync_channel::<MD<Command>>(1);
        let (ready,ready_pending)=reply_channel();
        let (start,clock_stop)=InstalledPrivateClockSession::prepare_start();
        // Share only the SAME signal holder, before native wake acquisition.
        let clock_stop=Arc::new(clock_stop);
        let counter_stop=CounterStop::new()?;
        let worker_stop=Arc::clone(&counter_stop);let worker_admitting=Arc::clone(&admitting);
        let original=thread::Builder::new().name("mutiny-installed-private-signer".into()).spawn(move||{
            // !Send SQLite/key owners are born only here and never returned or
            // exported. A failed constructor's original MD custody is retained
            // on this thread; its error string contains no secret payload.
            let mut factory=match InstalledPrivateFactory::open_on_private_worker(&_source,start,worker_stop){
                Ok(v)=>v,Err(e)=>{worker_admitting.store(false,Ordering::SeqCst);
                    let cause=e.cause().to_owned();let _delivered=ready.send(Err(cause.clone()));
                    let _retained=MD::new(e);return Err(cause);}};
            if !worker_admitting.load(Ordering::SeqCst){let retained=MD::new(factory);
                let _delivered=ready.send(Err("private signer stopped during startup".into()));
                let _original=retained;return Err("private signer startup canceled; original custody retained".into());}
            if ready.send(Ok(())).is_err(){let _retained=MD::new(factory);
                return Err("private signer startup delivery unknown".into());}
            while let Ok(command)=receive.recv(){
                if !worker_admitting.load(Ordering::SeqCst){
                    // No queued key operation may enter after stop. The command
                    // stays MD if it owns an unconsumed native target route.
                    match MD::into_inner(command){
                        Command::Finish=>break,
                        Command::Dispatch{mut message,reply}=>{message.refuse("private peer dispatch refused after admission stop".into());
                            let _withheld=reply.send(Ok(message));},
                        Command::Request{reply,..}=>{let _withheld=reply.send(Err("private command refused after admission stop".into()));},
                        Command::Sign{targets,reply,..}=>{let _original_routes=MD::new(targets);
                            let _withheld=reply.send(Err("private sign refused after admission stop; original target custody retained".into()));},
                    }
                    continue;
                }
                match MD::into_inner(command){
                    Command::Request{step,block,pol,reply}=>{let value=factory.request(step,block,pol);
                        if reply.send(value).is_err(){worker_admitting.store(false,Ordering::SeqCst);
                            let _retained=MD::new(factory);return Err("private request outcome delivery unknown".into());}},
                    Command::Sign{step,block,pol,targets,reply}=>{let value=factory.sign(step,block,pol,targets);
                        if reply.send(value).is_err(){worker_admitting.store(false,Ordering::SeqCst);
                            let _retained=MD::new(factory);return Err("private signed outcome delivery unknown; exact durable record retained".into());}},
                    Command::Dispatch{mut message,reply}=>{factory.dispatch_message(&mut message);
                        if reply.send(Ok(message)).is_err(){worker_admitting.store(false,Ordering::SeqCst);
                            let _retained=MD::new(factory);return Err("private original peer outcome delivery unknown".into());}},
                    Command::Finish=>{worker_admitting.store(false,Ordering::SeqCst);break;},
                }
            }
            worker_admitting.store(false,Ordering::SeqCst);
            match factory.close_on_private_worker(){Ok(())=>Ok(()),Err(e)=>{
                let cause=e.cause().to_owned();let _retained=MD::new(e);Err(cause)}}
        }).map_err(|_|"original private signer spawn unavailable")?;
        Ok(Self{thread:Some(original),send:Some(send),counter_stop:Some(MD::new(counter_stop)),
            clock_stop:Some(clock_stop),admitting,startup:ready_pending,abandoned:Some(abandoned),original_outcome:None,wake_outcome:None})
    }
    pub fn startup(&self)->&InstalledReply<()>{&self.startup}
    pub(crate) fn cancellation_handle(&self)->InstalledWorkerCancellation{
        InstalledWorkerCancellation{
            counter:Arc::downgrade(&**self.counter_stop.as_ref().expect("original counter stop")),
            clock:Arc::downgrade(self.clock_stop.as_ref().expect("original clock stop")),
            admitting:Arc::clone(&self.admitting),
        }
    }
    /// Await the ORIGINAL worker startup result using its bounded reply wake.
    /// The mutable borrow prevents another consumer from reading that same
    /// result during the await. Ready is a constructor outcome, never a clock,
    /// counter, membership or private-key permit; each operation rechecks those.
    pub fn startup_pending(&mut self)->&mut InstalledReply<()>{&mut self.startup}
    fn offer(&self,command:Command)->std::result::Result<(),InstalledCommandRefusal>{
        let original=MD::new(command);
        if !self.admitting.load(Ordering::SeqCst){return Err(InstalledCommandRefusal{cause:"private signer admission stopped".into(),original:Some(original)});}
        let send=match self.send.as_ref(){Some(v)=>v,None=>return Err(InstalledCommandRefusal{cause:"original signer channel absent".into(),original:Some(original)})};
        match send.try_send(original){Ok(())=>Ok(()),Err(mpsc::TrySendError::Full(v))=>
            Err(InstalledCommandRefusal{cause:"one original signer command already pending".into(),original:Some(v)}),
            Err(mpsc::TrySendError::Disconnected(v))=>Err(InstalledCommandRefusal{cause:"original signer channel unavailable".into(),original:Some(v)})}
    }
    pub fn request(&self,step:Step,block:Option<Hash>,pol:Option<u64>)->std::result::Result<InstalledReply<Option<Request>>,InstalledCommandRefusal>{
        let(reply,pending)=reply_channel();self.offer(Command::Request{step,block,pol,reply})?;Ok(pending)
    }
    pub fn sign(&self,step:Step,block:Option<Hash>,pol:Option<u64>,targets:Option<OwnedTargets>)
        ->std::result::Result<InstalledReply<Vote>,InstalledCommandRefusal>{
        let(reply,pending)=reply_channel();self.offer(Command::Sign{step,block,pol,targets,reply})?;Ok(pending)
    }
    pub(crate) fn dispatch_received(&self,message:crate::hybrid_installed_daemon_v2::InstalledPeerMessage)
        ->std::result::Result<InstalledReply<crate::hybrid_installed_daemon_v2::InstalledPeerMessage>,InstalledCommandRefusal>{
        let(reply,pending)=reply_channel();self.offer(Command::Dispatch{message,reply})?;Ok(pending)
    }
    /// Orderly stop closes command admission only. It does NOT cancel the
    /// counter/current check needed for the actual durable shutdown transfer.
    pub fn finish_admission(&mut self){
        self.admitting.store(false,Ordering::SeqCst);
        if let Some(send)=self.send.take(){let _queued=send.try_send(MD::new(Command::Finish));drop(send);}
    }
    /// Explicit cancellation wakes original clock/counter I/O. Unknown private
    /// mutation stays frozen; this grants no force-close, kill or reset action.
    pub fn cancel(&mut self)->std::result::Result<(),String>{
        self.finish_admission();if let Some(clock)=self.clock_stop.as_ref(){clock.stop();}
        self.counter_stop.as_ref().ok_or("original counter cancellation holder absent")?.stop()
    }
    pub fn original_finished(&self)->bool{self.thread.as_ref().is_some_and(JoinHandle::is_finished)}
    /// Caller invokes only after the original worker has naturally completed.
    /// No detached worker or synthetic native-close receipt is produced.
    pub fn join(self)->std::result::Result<(),InstalledWorkerCloseRefusal>{
        let mut original=MD::new(self);
        if !original.original_finished(){return Err(InstalledWorkerCloseRefusal{cause:"original private worker has not completed".into(),worker:original,wake:None});}
        if let Err(cause)=original.settle_original_on_blocking_executor(){
            return Err(InstalledWorkerCloseRefusal{cause,worker:original,wake:None});}
        // Only after original join/body/native wake closure are known may the
        // otherwise empty controller be dropped. Unknowns retain it whole.
        drop(MD::into_inner(original));Ok(())
    }
    /// Stop admission and await the ORIGINAL private thread on the caller's
    /// existing owned Tokio executor. Actor/UI polling never performs join or
    /// native close. No timer, replacement thread identity or receipt is used.
    pub fn join_on_owned_executor(self)->std::result::Result<crate::hybrid_installed_worker_join_v2::InstalledWorkerJoin,crate::hybrid_installed_worker_join_v2::InstalledWorkerJoinRefusal>{
        crate::hybrid_installed_worker_join_v2::InstalledWorkerJoin::start(self)
    }
    // Private scheduling seam for the owned blocking task only. The actual
    // worker remains MD in its preallocated shared slot throughout all effects.
    pub(crate) fn settle_original_on_blocking_executor(&mut self)->std::result::Result<(),String>{
        let thread=self.thread.take().ok_or("original private worker join already consumed")?;
        self.original_outcome=Some(thread.join());
        if !matches!(self.original_outcome.as_ref(),Some(Ok(Ok(())))){
            return Err("original private worker closure unknown/refused".into());}
        let stop=MD::into_inner(self.counter_stop.take().ok_or("original controller counter wake absent")?);
        if let Err(wake)=stop.close_after_join(){
            self.wake_outcome=Some(wake);return Err("original controller wake close retained".into());}
        self.clock_stop.take();self.send.take();self.abandoned.take();Ok(())
    }
}
impl Drop for InstalledPrivateWorker{
    fn drop(&mut self){
        if let Some(thread)=self.thread.take(){
            self.admitting.store(false,Ordering::SeqCst);
            if let Some(clock)=self.clock_stop.as_ref(){clock.stop();}
            if let Some(counter)=self.counter_stop.as_ref(){let _signal=counter.stop();}
            let mut slot=self.abandoned.take().expect("preallocated original worker abandonment custody");
            slot.write(Abandoned{thread,send:self.send.take(),
                counter_stop:self.counter_stop.take().expect("original counter wake"),
                clock_stop:self.clock_stop.take().expect("original clock cancellation"),admitting:Arc::clone(&self.admitting)});
            let _retained=MD::new(slot);
        }
    }
}

#[cfg(test)]
mod installed_reply_owned_wake_models{
    use super::*;
    use std::{future::Future,pin::Pin,sync::atomic::AtomicUsize,task::{Context,Poll,Wake,Waker}};
    struct Count(AtomicUsize);
    impl Wake for Count{fn wake(self:Arc<Self>){self.0.fetch_add(1,Ordering::SeqCst);}}
    #[test]
    fn actual_bounded_reply_publication_before_registration_is_observed(){
        let(send,mut receive)=reply_channel();assert!(send.send(Ok(7usize)).is_ok());
        let count=Arc::new(Count(AtomicUsize::new(0)));let waker=Waker::from(Arc::clone(&count));let mut cx=Context::from_waker(&waker);
        assert!(matches!(Future::poll(Pin::new(&mut receive),&mut cx),Poll::Ready(Ok(7))));
        assert_eq!(count.0.load(Ordering::SeqCst),0);
    }
    #[test]
    fn actual_registered_waiter_is_woken_after_original_reply_publication(){
        let(send,mut receive)=reply_channel();
        let count=Arc::new(Count(AtomicUsize::new(0)));let waker=Waker::from(Arc::clone(&count));let mut cx=Context::from_waker(&waker);
        assert!(matches!(Future::poll(Pin::new(&mut receive),&mut cx),Poll::Pending));
        assert!(send.send(Ok(9usize)).is_ok());assert_eq!(count.0.load(Ordering::SeqCst),1);
        assert!(matches!(Future::poll(Pin::new(&mut receive),&mut cx),Poll::Ready(Ok(9))));
    }
    #[test]
    fn disconnected_original_reply_is_refused_without_a_result_or_timer(){
        let(send,mut receive)=reply_channel::<usize>();
        let count=Arc::new(Count(AtomicUsize::new(0)));let waker=Waker::from(Arc::clone(&count));let mut cx=Context::from_waker(&waker);
        assert!(matches!(Future::poll(Pin::new(&mut receive),&mut cx),Poll::Pending));
        drop(send);assert_eq!(count.0.load(Ordering::SeqCst),1);
        assert!(matches!(Future::poll(Pin::new(&mut receive),&mut cx),Poll::Ready(Err(_))));
    }
}
