//! Structured ownership of the existing chrony poller. This supplies no new
//! source, profile, protected restart state, or deployment authority.
use super::{HostClock, Result};
use mutiny_consensus_v8::holdover_clock_v1::TimeBasis;
use std::sync::{Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

struct Lifetime {
    stopped: Mutex<bool>,
    wake: Condvar,
}
struct OwnedPoll {
    lifetime: Arc<Lifetime>,
    task: Option<JoinHandle<()>>,
}
impl OwnedPoll {
    fn start(interval: Duration, mut poll: impl FnMut() + Send + 'static) -> Result<Self> {
        if interval.is_zero() {
            return Err("host clock poll interval is zero".into());
        }
        let lifetime = Arc::new(Lifetime { stopped: Mutex::new(false), wake: Condvar::new() });
        let worker = lifetime.clone();
        let task = std::thread::Builder::new().name("host-clock-owned".into())
            .spawn(move || {
                let Ok(mut stopped) = worker.stopped.lock() else { return; };
                loop {
                    if *stopped { return; }
                    // Serialize stop with the complete current poll, including
                    // its existing bounded chronyc calls and store mutation.
                    // After stop acknowledges, no later poll can begin.
                    poll();
                    match worker.wake.wait_timeout(stopped, interval) {
                        Ok((next, _)) => stopped = next,
                        Err(_) => return,
                    }
                }
            }).map_err(|e| format!("host clock thread: {e}"))?;
        Ok(Self { lifetime, task: Some(task) })
    }
    fn alive(&self) -> bool {
        self.task.as_ref().is_some_and(|t| !t.is_finished())
            && self.lifetime.stopped.lock().is_ok_and(|s| !*s)
    }
    fn stop(&mut self) -> Result<()> {
        match self.lifetime.stopped.lock() {
            Ok(mut stopped) => *stopped = true,
            Err(poisoned) => *poisoned.into_inner() = true,
        }
        self.lifetime.wake.notify_all();
        match self.task.take() {
            None => Ok(()),
            Some(task) => task.join().map_err(|_| "host clock task panicked".to_owned()),
        }
    }
}
impl Drop for OwnedPoll {
    fn drop(&mut self) {
        if self.stop().is_err() { eprintln!("host clock natural shutdown refused"); }
    }
}
struct ChronyBasis { inner: Arc<dyn TimeBasis>, lifetime: Arc<Lifetime> }
impl TimeBasis for ChronyBasis {
    fn lower_bound_ms(&self) -> Option<u64> {
        // Hold the same gate across reading: a check made before stop cannot
        // escape it and return fresh authority after stop has acknowledged.
        let stopped = self.lifetime.stopped.lock().ok()?;
        if *stopped { return None; }
        self.inner.lower_bound_ms()
    }
}
/// Owns the poller and original held anchor owner. Retained consumers revoke
/// when this owner stops or drops; there is no detached strong-Arc cycle.
pub struct ChronyClock {
    basis: Arc<dyn TimeBasis>,
    poll: OwnedPoll,
}
impl ChronyClock {
    pub(super) fn start(host: Arc<HostClock>, every: Duration) -> Result<Self> {
        let inner = host.basis();
        // Only the owned thread retains HostClock/the anchor store. Joining
        // drops that owner even when consumers retain their revoked engine.
        let worker = host;
        let mut reported: Option<String> = None;
        let mut last_poll = std::time::Instant::now();
        let mut first = true;
        let poll = OwnedPoll::start(super::wake_interval(every), move || {
            let result = if first {
                first = false;
                Some(worker.calibrate_once())
            } else {
                worker.background_step(every, last_poll.elapsed())
            };
            if let Some(result) = result {
                last_poll = std::time::Instant::now();
                if let Some(line) = super::store_failure_to_report(&result, &mut reported) {
                    eprintln!("{line}");
                }
            }
        })?;
        let basis = Arc::new(ChronyBasis { inner, lifetime: poll.lifetime.clone() });
        Ok(Self { basis, poll })
    }
    pub fn basis(&self) -> Arc<dyn TimeBasis> {
        self.basis.clone()
    }
    pub(crate) fn alive(&self) -> bool { self.poll.alive() }
    pub fn stop(&mut self) -> Result<()> { self.poll.stop() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{atomic::{AtomicUsize, Ordering}, mpsc};
    struct Fixed;
    impl TimeBasis for Fixed { fn lower_bound_ms(&self) -> Option<u64> { Some(123) } }
    fn fixture() -> (OwnedPoll, Arc<AtomicUsize>, Arc<dyn TimeBasis>) {
        let count = Arc::new(AtomicUsize::new(0));
        let worker_count = count.clone();
        let (tx, rx) = mpsc::sync_channel(1);
        let mut first = Some(tx);
        let poll = OwnedPoll::start(Duration::from_secs(60), move || {
            worker_count.fetch_add(1, Ordering::SeqCst);
            if let Some(tx) = first.take() { tx.send(()).unwrap(); }
        }).unwrap();
        // Test harness watchdog only, not an elapsed/clock qualification bound.
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let basis = Arc::new(ChronyBasis { inner: Arc::new(Fixed), lifetime: poll.lifetime.clone() });
        (poll, count, basis)
    }
    #[test]
    fn stop_wakes_naturally_joins_and_revokes_retained_basis_idempotently() {
        let (mut poll, count, basis) = fixture();
        assert_eq!(basis.lower_bound_ms(), Some(123));
        poll.stop().unwrap();
        assert!(poll.task.is_none());
        assert!(!poll.alive());
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(basis.lower_bound_ms(), None);
        poll.stop().unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn owner_drop_joins_and_revokes_surviving_consumer() {
        let (poll, count, basis) = fixture();
        drop(poll);
        assert_eq!(count.load(Ordering::SeqCst), 1);
        assert_eq!(basis.lower_bound_ms(), None);
    }
    #[test]
    fn poll_panic_cannot_leave_qualified_consumers_or_detach_on_stop() {
        let (tx, rx) = mpsc::sync_channel(1);
        let mut poll = OwnedPoll::start(Duration::from_secs(60), move || {
            tx.send(()).unwrap();
            panic!("PUBLIC MODELED poll failure");
        }).unwrap();
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let basis = ChronyBasis { inner: Arc::new(Fixed), lifetime: poll.lifetime.clone() };
        assert_eq!(poll.stop(), Err("host clock task panicked".into()));
        assert!(poll.task.is_none());
        assert_eq!(basis.lower_bound_ms(), None);
    }
}
