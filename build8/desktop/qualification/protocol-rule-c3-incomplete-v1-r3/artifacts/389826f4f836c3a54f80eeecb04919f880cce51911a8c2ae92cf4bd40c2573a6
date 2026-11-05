//! Periodic local consensus dispatch. Publication is outside the actor mutex;
//! the finite output channel applies backpressure without dropping vote intent.
use crate::{
    integrated_actor::{ActorTick, IntegratedActor},
    worker_coordinator::BodyBuilder,
};
use mutiny_consensus_v8::{
    counter_voter::CounterSigningBackend, freshness::PhysicalAttestationVerifier,
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, TrySendError},
    },
    thread::{self, JoinHandle},
    time::Duration,
};
type Result<T> = std::result::Result<T, String>;
pub struct ActorService {
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Result<()>>>,
    pub output: Receiver<Result<ActorTick>>,
}
impl ActorService {
    pub fn start<V, H, B>(actor: Arc<Mutex<IntegratedActor<V, H, B>>>) -> Result<Self>
    where
        V: PhysicalAttestationVerifier + Send + 'static,
        H: BodyBuilder,
        B: CounterSigningBackend
            + crate::participation_producer::ParticipationSigner
            + Send
            + 'static,
    {
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = stop.clone();
        let (sender, output) = mpsc::sync_channel(8);
        let worker = thread::Builder::new()
            .name("canonical-actor".into())
            .spawn(move || {
                let mut pending = None;
                let mut failure = None;
                while !shutdown.load(Ordering::Acquire) {
                    if pending.is_none() {
                        let mut actor = actor.lock().map_err(|_| "Actor poisoned")?;
                        match actor.tick(None) {
                            Ok(tick)
                                if tick.proposal.is_some()
                                    || !tick.consensus.publish.is_empty()
                                    || tick.consensus.finalized.is_some()
                                    || tick.consensus.advanced_round.is_some() =>
                            {
                                pending = Some(Ok(tick))
                            }
                            Ok(_) => (),
                            Err(error) => {
                                actor.pause_after_fault(error.clone());
                                failure = Some(error.clone());
                                pending = Some(Err(error));
                            }
                        }
                    }
                    if let Some(message) = pending.take() {
                        match sender.try_send(message) {
                            Ok(()) => {
                                if let Some(error) = failure.take() {
                                    return Err(error);
                                }
                            }
                            Err(TrySendError::Full(message)) => pending = Some(message),
                            Err(TrySendError::Disconnected(_)) => return Ok(()),
                        }
                    }
                    thread::sleep(Duration::from_millis(250));
                }
                Ok(())
            })
            .map_err(|e| e.to_string())?;
        Ok(Self {
            stop,
            worker: Some(worker),
            output,
        })
    }
    pub fn stop(mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        self.worker
            .take()
            .ok_or("Actor already stopped")?
            .join()
            .map_err(|_| "Actor thread panicked")?
    }
}
impl Drop for ActorService {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
