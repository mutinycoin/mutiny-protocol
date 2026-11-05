//! Ordinary installed V2 actor interface. The original private thread owns keys,
//! SQLite and provider state; callers receive bounded typed operations and their
//! actual wake-driven replies. No V1 backend, caller secrets or profiles enter.
#![cfg(target_os="linux")]

pub use crate::hybrid_installed_private_worker_v2::{
    InstalledPrivateWorker as InstalledActor,
    InstalledReply,
    InstalledCommandRefusal,
    InstalledWorkerCloseRefusal,
};
pub use crate::hybrid_installed_worker_join_v2::{InstalledWorkerJoin,InstalledWorkerJoinRefusal};

/// Start through the fixed installed source issuer. Its current authoritative
/// classification is UNAVAILABLE, so this call refuses before native resources
/// or workers are acquired. The genuine conditional worker/factory underneath
/// remains separate from that missing external source; no fallback is selected.
pub fn start_installed()->std::result::Result<InstalledActor,String>{
    InstalledActor::start_installed()
}

/// Ordinary binary startup entry for the currently settled unavailable source.
/// It refuses before effects. There is no successful daemon branch to drop an
/// owned worker or manufacture service completion. If an accepted mechanism
/// later inhabits Registration, this exhaustive match MUST be replaced by the
/// real selected daemon/transport controller; no new variant silently runs.
pub fn run_installed()->std::result::Result<(),String>{
    let source=crate::hybrid_installed_secret_source_v2::require_registered_source()?;
    match source{}
}

// Exact original retained command/reply types are reexported above; no wrapper
// translates a refusal into success or discards its original opaque custody.
// Public transport calls request/sign synchronously to transfer their bounded
// command into the original channel, then awaits InstalledReply on its own
// executor. Dropping a pending reply cannot cancel a durable private mutation.
// The worker withholds further admission if an outcome cannot be delivered.
//
// Shutdown admission/cancellation and original_finished/join remain distinct.
// A reply or completion of a signing operation is not a worker-join receipt.
// Call join only after the original thread is actually finished; a failed
// original join/native close returns the exact opaque retained worker refusal.
// Alternatively join_on_owned_executor consumes the controller into one owned
// blocking job on the existing caller runtime; awaiting its Future never blocks
// the actor/UI. Original thread and task outcomes stay separately retained.

/// Public startup refusal preserves the actual startup result separately from
/// the ORIGINAL worker/task/native closure refusal. Neither is qualification.
pub struct InstalledStartupFailure {
    cause:String,
    original_closure:Option<InstalledWorkerJoinRefusal>,
}
impl InstalledStartupFailure {
    pub fn cause(&self)->&str { &self.cause }
    pub fn original_closure_refusal(&self)->Option<&InstalledWorkerJoinRefusal> {
        self.original_closure.as_ref()
    }
}

/// Await the actual original startup reply on the caller's owned executor.
/// No actor/UI synchronous receive or original ThreadHandle join is performed.
pub async fn start_installed_ready()
    ->std::result::Result<InstalledActor,InstalledStartupFailure>
{
    // Outcome storage precedes the real conditional worker constructor.
    let mut refusal=InstalledStartupFailure{cause:String::new(),original_closure:None};
    let mut actor=match start_installed() {
        Ok(actor)=>actor,
        Err(cause)=>{refusal.cause=cause;return Err(refusal);}
    };
    // This exclusive borrow consumes ONLY that original bounded ready reply.
    // Dropping this future here invokes the accepted whole-worker abandonment
    // path: signal cancellation and retain its original thread/native owners.
    if let Err(cause)=actor.startup_pending().await {
        refusal.cause=cause;
        // Even failed startup must observe the ORIGINAL worker outcome.
        // The accepted consuming join roots the whole actor before submission.
        let original_join=match actor.join_on_owned_executor() {
            Ok(join)=>join,
            Err(closure)=>{refusal.original_closure=Some(closure);return Err(refusal);}
        };
        if let Err(closure)=original_join.await {
            refusal.original_closure=Some(closure);
        }
        // Clean cleanup is never a successful startup/daemon receipt.
        return Err(refusal);
    }
    Ok(actor)
}

/// Conditional ordinary lifecycle keeps the original worker and message bridge;
/// no public registered-source constructor or transport/key selection is supplied.
pub use crate::hybrid_installed_daemon_v2::{InstalledDaemon,InstalledDaemonFailure,ClosedInstalledDaemon,InstalledPeerMessage};
pub async fn start_installed_daemon_ready()->std::result::Result<InstalledDaemon,InstalledDaemonFailure>{
    InstalledDaemon::start_installed().await
}
