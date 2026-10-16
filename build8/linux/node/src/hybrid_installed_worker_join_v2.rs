//! Owned completion of the ORIGINAL private signer worker. This module owns no
//! keys, issuer, replacement provider, new reactor or protocol timing policy.
#![cfg(target_os="linux")]
use std::{future::Future,mem::ManuallyDrop as MD,pin::Pin,sync::{Arc,Mutex},task::{Context,Poll}};
use crate::hybrid_installed_private_worker_v2::InstalledPrivateWorker;

struct State{
    worker:Option<MD<InstalledPrivateWorker>>,
    // Original key-thread outcome lives inside worker; this is its exact
    // consuming close result. The Tokio blocking task outcome is separate.
    close_result:Option<std::result::Result<(),String>>,
    original_task_outcome:Option<std::result::Result<(),tokio::task::JoinError>>,
}
pub struct InstalledWorkerJoin{
    state:Option<MD<Arc<Mutex<State>>>>,
    task:Option<MD<tokio::task::JoinHandle<()>>>,
    completed:bool,
}
pub struct InstalledWorkerJoinRefusal{cause:String,state:MD<Arc<Mutex<State>>>,
    // Outside the job's mutex: unknown submission cannot require waiting for
    // a potentially running original join before publishing this outcome.
    start_panic:Option<Box<dyn std::any::Any+Send+'static>>}
impl InstalledWorkerJoinRefusal{pub fn cause(&self)->&str{&self.cause}}
impl InstalledWorkerJoin{
    pub(crate) fn start(worker:InstalledPrivateWorker)->std::result::Result<Self,InstalledWorkerJoinRefusal>{
        // Root original controller BEFORE allocation, executor lookup or task
        // submission. No mutation/close can escape through an ordinary Drop.
        let worker=MD::new(worker);
        let state=MD::new(Arc::new(Mutex::new(State{worker:Some(worker),
            close_result:None,original_task_outcome:None})));
        let mut refusal=InstalledWorkerJoinRefusal{cause:String::new(),state,start_panic:None};
        let runtime=match tokio::runtime::Handle::try_current(){Ok(v)=>v,Err(_)=>{
            refusal.cause="owned caller executor unavailable; original worker retained".into();return Err(refusal);}};
        // Orderly admission stop preserves the existing shutdown counter/time
        // checks. Explicit worker.cancel remains a distinct earlier operation.
        refusal.state.lock().unwrap_or_else(|v|v.into_inner()).worker.as_mut()
            .expect("rooted original worker").finish_admission();
        let retained=Arc::clone(&refusal.state);
        let submitted=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||{
            runtime.spawn_blocking(move||{
                // The whole worker stays in State throughout join/native close.
                // Panic poisoning never drops a taken owner: future refusal can
                // recover this exact slot plus original partial outcomes.
                let mut state=retained.lock().unwrap_or_else(|v|v.into_inner());
                let result=state.worker.as_mut().expect("original worker task slot")
                    .settle_original_on_blocking_executor();
                state.close_result=Some(result);
            })
        }));
        match submitted{
            Ok(task)=>Ok(Self{state:Some(refusal.state),task:Some(MD::new(task)),completed:false}),
            Err(payload)=>{
                refusal.start_panic=Some(payload);
                refusal.cause="owned blocking task submission unknown; original controller retained".into();
                Err(refusal)
            }
        }
    }
}
impl Future for InstalledWorkerJoin{
    type Output=std::result::Result<(),InstalledWorkerJoinRefusal>;
    fn poll(self:Pin<&mut Self>,cx:&mut Context<'_>)->Poll<Self::Output>{
        let own=self.get_mut();
        assert!(!own.completed,"original private worker completion already consumed");
        // Tokio's real task completion wake; no new cadence/deadline and no
        // worker-is_finished polling on the actor/UI thread.
        let result=match Pin::new(&mut **own.task.as_mut().expect("original blocking task")).poll(cx){
            Poll::Pending=>return Poll::Pending,Poll::Ready(v)=>v,
        };
        own.completed=true;
        let mut state=own.state.as_ref().expect("original completion state")
            .lock().unwrap_or_else(|v|v.into_inner());
        state.original_task_outcome=Some(result);
        let known=matches!(state.original_task_outcome.as_ref(),Some(Ok(())))
            &&matches!(state.close_result.as_ref(),Some(Ok(())));
        if known{
            // The job has actually completed and the original private thread
            // joined with known native wake closure. No native owners remain.
            let worker=state.worker.take().expect("known original worker slot");
            drop(MD::into_inner(worker));
        }
        drop(state);
        // A completed Tokio task handle is scheduler bookkeeping, not a native
        // HANDLE or a private worker join substitute. Never abort a live job.
        drop(MD::into_inner(own.task.take().expect("completed original task")));
        let original_state=own.state.take().expect("completed original state");
        if known{
            drop(MD::into_inner(original_state));Poll::Ready(Ok(()))
        }else{
            Poll::Ready(Err(InstalledWorkerJoinRefusal{
                cause:"original private worker/task/native closure refused; exact outcomes retained".into(),
                state:original_state,start_panic:None}))
        }
    }
}
// On cancellation/unwind this Future's MD task and whole shared slot remain
// quarantined. It performs no abort, blocking lock/join, native close or retry.
// The accepted original worker admission/cancel capabilities remain distinct.
fn require_owned_join_send(){fn check<T:Send>(){}check::<InstalledWorkerJoin>();}
