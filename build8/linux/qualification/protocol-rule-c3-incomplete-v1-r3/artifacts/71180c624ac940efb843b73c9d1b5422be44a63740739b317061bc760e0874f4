//! Local pending-connection resources only; never Worker or mining authority.
//! Reserve before reading untrusted bytes, claim after public context routing,
//! and retain the permit until the handshake's buffers/socket are retired or
//! transferred to a separately bounded confirmed-connection owner.
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const WINDOW: Duration = Duration::from_secs(60);
pub type Worker = [u8; 32];
type Result<T> = std::result::Result<T, &'static str>;

/// Explicit operator resource policy, not a consensus registry-size limit.
#[derive(Clone, Copy)]
pub struct Limits {
    pub pending: u16,
    pub attempts_per_minute: u16,
    pub attempts_per_worker_per_minute: u16,
}
struct Entry {
    began: Instant,
    worker: Option<Worker>,
    claim_attempted: bool,
}
struct State {
    next: u64,
    window: Instant,
    attempts: u16,
    workers: BTreeMap<Worker, u16>,
    pending: BTreeMap<u64, Entry>,
}
struct Inner {
    limits: Limits,
    state: Mutex<State>,
}
#[derive(Clone)]
pub struct Budget(Arc<Inner>);
/// Not cloneable: one owner retains the reservation for its full lifetime.
pub struct Permit {
    budget: Budget,
    id: u64,
}
impl Budget {
    pub fn new(limits: Limits) -> Result<Self> {
        if limits.pending == 0
            || limits.attempts_per_minute == 0
            || limits.attempts_per_worker_per_minute == 0
            || limits.attempts_per_worker_per_minute > limits.attempts_per_minute
        {
            return Err("Invalid Worker resource limits");
        }
        Ok(Self(Arc::new(Inner {
            limits,
            state: Mutex::new(State {
                next: 0,
                window: Instant::now(),
                attempts: 0,
                workers: BTreeMap::new(),
                pending: BTreeMap::new(),
            }),
        })))
    }
    pub fn reserve(&self) -> Result<Permit> {
        let mut state = self.0.state.lock().map_err(|_| "Worker budget poisoned")?;
        // Read time while holding the lock, so racing callers cannot reorder it.
        self.reserve_locked(&mut state, Instant::now())
    }
    fn reserve_locked(&self, state: &mut State, now: Instant) -> Result<Permit> {
        reset_window(state, now)?;
        if state.pending.len() >= usize::from(self.0.limits.pending)
            || state.attempts >= self.0.limits.attempts_per_minute
        {
            return Err("Worker pending capacity or attempt rate exhausted");
        }
        let id = state
            .next
            .checked_add(1)
            .ok_or("Worker permit ID exhausted")?;
        state.next = id;
        state.attempts += 1;
        state.pending.insert(
            id,
            Entry {
                began: now,
                worker: None,
                claim_attempted: false,
            },
        );
        Ok(Permit {
            budget: self.clone(),
            id,
        })
    }
}
fn reset_window(state: &mut State, now: Instant) -> Result<()> {
    let age = now
        .checked_duration_since(state.window)
        .ok_or("Worker budget clock regressed")?;
    if age >= WINDOW {
        state.window = now;
        state.attempts = 0;
        state.workers.clear();
    }
    Ok(())
}
impl Permit {
    /// A routing claim is not authentication. The canonical handshake must still
    /// validate this Worker. Claims cannot change, including after a failed try.
    pub fn claim(&self, worker: Worker) -> Result<()> {
        let mut state = self
            .budget
            .0
            .state
            .lock()
            .map_err(|_| "Worker budget poisoned")?;
        self.claim_locked(&mut state, worker, Instant::now())
    }
    fn claim_locked(&self, state: &mut State, worker: Worker, now: Instant) -> Result<()> {
        self.check_locked(state, now)?;
        if state
            .pending
            .get(&self.id)
            .ok_or("Worker permit absent")?
            .claim_attempted
        {
            return Err("Worker permit already claimed");
        }
        state
            .pending
            .get_mut(&self.id)
            .ok_or("Worker permit absent")?
            .claim_attempted = true;
        reset_window(state, now)?;
        // Charge one per-Worker attempt even when another pending claim exists.
        let count = state.workers.get(&worker).copied().unwrap_or(0);
        if count >= self.budget.0.limits.attempts_per_worker_per_minute {
            return Err("Worker attempt rate exhausted");
        }
        // Old-window reservations may claim in this window. Bound the map by
        // the finite sum of current attempts and still-owned pending permits.
        state.workers.insert(worker, count + 1);
        if state
            .pending
            .values()
            .any(|entry| entry.worker == Some(worker))
        {
            return Err("Worker already has a pending handshake");
        }
        state
            .pending
            .get_mut(&self.id)
            .ok_or("Worker permit absent")?
            .worker = Some(worker);
        Ok(())
    }
    pub fn check(&self) -> Result<()> {
        let state = self
            .budget
            .0
            .state
            .lock()
            .map_err(|_| "Worker budget poisoned")?;
        self.check_locked(&state, Instant::now())
    }
    fn check_locked(&self, state: &State, now: Instant) -> Result<()> {
        let entry = state.pending.get(&self.id).ok_or("Worker permit absent")?;
        let age = now
            .checked_duration_since(entry.began)
            .ok_or("Worker permit clock regressed")?;
        if age >= WINDOW {
            return Err("Worker pending lifetime exhausted");
        }
        Ok(())
    }
    pub fn claimed_worker(&self) -> Result<Worker> {
        let state = self
            .budget
            .0
            .state
            .lock()
            .map_err(|_| "Worker budget poisoned")?;
        self.check_locked(&state, Instant::now())?;
        state
            .pending
            .get(&self.id)
            .and_then(|e| e.worker)
            .ok_or("Worker permit unclaimed")
    }
    pub fn began(&self) -> Result<Instant> {
        let state = self
            .budget
            .0
            .state
            .lock()
            .map_err(|_| "Worker budget poisoned")?;
        self.check_locked(&state, Instant::now())?;
        Ok(state
            .pending
            .get(&self.id)
            .ok_or("Worker permit absent")?
            .began)
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        // Poison remains fail-closed for future users, but release owned memory.
        let mut state = self
            .budget
            .0
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        state.pending.remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn budget() -> Budget {
        Budget::new(Limits {
            pending: 2,
            attempts_per_minute: 4,
            attempts_per_worker_per_minute: 2,
        })
        .unwrap()
    }
    #[test]
    fn pending_capacity_is_owned_until_drop_even_after_expiry() {
        let b = budget();
        let p = b.reserve().unwrap();
        let q = b.reserve().unwrap();
        assert!(b.reserve().is_err());
        let later = p.began().unwrap() + WINDOW;
        {
            let mut s = b.0.state.lock().unwrap();
            assert!(p.check_locked(&s, later).is_err());
            assert!(b.reserve_locked(&mut s, later).is_err());
        }
        drop(p);
        drop(q);
        let mut s = b.0.state.lock().unwrap();
        let r = b.reserve_locked(&mut s, later).unwrap();
        drop(s);
        drop(r);
    }
    #[test]
    fn failures_and_drop_do_not_refund_attempts() {
        let b = budget();
        for _ in 0..4 {
            drop(b.reserve().unwrap());
        }
        assert!(b.reserve().is_err());
    }
    #[test]
    fn duplicate_worker_and_claim_replacement_rejected() {
        let b = budget();
        let p = b.reserve().unwrap();
        let q = b.reserve().unwrap();
        p.claim([1; 32]).unwrap();
        assert!(p.claim([2; 32]).is_err());
        assert!(q.claim([1; 32]).is_err());
        drop(p);
        assert!(q.claim([1; 32]).is_err()); // failed duplicate consumed attempt
    }
    #[test]
    fn exact_lifetime_boundary_and_rollback_rejected() {
        let b = budget();
        let p = b.reserve().unwrap();
        let start = p.began().unwrap();
        let s = b.0.state.lock().unwrap();
        assert!(
            p.check_locked(&s, start + WINDOW - Duration::from_nanos(1))
                .is_ok()
        );
        assert!(p.check_locked(&s, start + WINDOW).is_err());
        assert!(
            p.check_locked(&s, start - Duration::from_millis(1))
                .is_err()
        );
    }
    #[test]
    fn identifier_overflow_and_invalid_limits_rejected() {
        assert!(
            Budget::new(Limits {
                pending: 0,
                attempts_per_minute: 1,
                attempts_per_worker_per_minute: 1
            })
            .is_err()
        );
        assert!(
            Budget::new(Limits {
                pending: 1,
                attempts_per_minute: 1,
                attempts_per_worker_per_minute: 2
            })
            .is_err()
        );
        let b = budget();
        b.0.state.lock().unwrap().next = u64::MAX;
        assert!(b.reserve().is_err());
    }
    #[test]
    fn failed_claim_cannot_grow_map_with_different_workers() {
        let b = budget();
        let p = b.reserve().unwrap();
        let q = b.reserve().unwrap();
        p.claim([1; 32]).unwrap();
        assert!(q.claim([1; 32]).is_err());
        for n in 2..=255 {
            assert!(q.claim([n; 32]).is_err());
        }
        assert_eq!(b.0.state.lock().unwrap().workers.len(), 1);
        assert!(q.claimed_worker().is_err());
    }
    #[test]
    fn concurrent_reservations_never_exceed_capacity() {
        let b = budget();
        let barrier = Arc::new(std::sync::Barrier::new(9));
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let b = b.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let p = b.reserve();
                    barrier.wait();
                    barrier.wait();
                    p.is_ok()
                })
            })
            .collect();
        barrier.wait();
        assert_eq!(b.0.state.lock().unwrap().pending.len(), 2);
        barrier.wait();
        assert_eq!(
            handles
                .into_iter()
                .filter(|h| h.thread().id() != std::thread::current().id())
                .map(|h| usize::from(h.join().unwrap()))
                .sum::<usize>(),
            2
        );
        assert!(b.0.state.lock().unwrap().pending.is_empty());
    }
}
