//! Local confirmed-connection ownership and replacement, not mining authority.
use crate::{
    hybrid_coordinator_v2::Clock,
    worker_carrier_v2::{Carrier, NonblockingIo},
};
use mutiny_consensus_v8::{Hash, anchors::FinalizedAnchor, canonical_store_v2::CanonicalStore};
use mutiny_transport_v2::{Error, Result};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::{Arc, Mutex, Weak},
    time::Instant,
};
use zeroize::Zeroizing;

struct State {
    next: u64,
    owned: BTreeSet<u64>,
    current: BTreeMap<Hash, u64>,
}
struct Inner {
    limit: u16,
    state: Mutex<State>,
}
#[derive(Clone)]
pub struct Registry(Arc<Inner>);
struct Lease {
    registry: Registry,
    id: u64,
    worker: Hash,
}
pub struct Connection<I: NonblockingIo> {
    carrier: Option<Carrier<I>>,
    lease: Option<Arc<Lease>>,
    outstanding: Weak<()>,
}
/// Single-use dispatch object. No public plaintext extractor or constructor.
pub struct Received {
    // Field order erases/drops plaintext before releasing its resource lease.
    plain: Zeroizing<Vec<u8>>,
    lease: Arc<Lease>,
    _outstanding: Arc<()>,
}
impl Registry {
    pub fn new(limit: u16) -> Result<Self> {
        if limit == 0 {
            return Err(Error::Limit);
        }
        Ok(Self(Arc::new(Inner {
            limit,
            state: Mutex::new(State {
                next: 0,
                owned: BTreeSet::new(),
                current: BTreeMap::new(),
            }),
        })))
    }
    fn claim(&self, worker: Hash) -> Result<Lease> {
        let mut s = self.0.state.lock().map_err(|_| Error::Context)?;
        // Retired but still-owned connections count until their resources drop.
        if s.owned.len() >= usize::from(self.0.limit) {
            return Err(Error::Limit);
        }
        let id = s.next.checked_add(1).ok_or(Error::Limit)?;
        s.next = id;
        s.owned.insert(id);
        s.current.insert(worker, id);
        Ok(Lease {
            registry: self.clone(),
            id,
            worker,
        })
    }
    pub fn admit<I: NonblockingIo>(
        &self,
        mut carrier: Carrier<I>,
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        clock: &mut impl Clock,
    ) -> Result<Connection<I>> {
        carrier.check(chain, parent, clock)?;
        let worker = carrier.worker_identity()?;
        let lease = self.claim(worker)?;
        Ok(Connection {
            carrier: Some(carrier),
            lease: Some(Arc::new(lease)),
            outstanding: Weak::new(),
        })
    }
}
impl Lease {
    fn received_matches(&self, r: &Received) -> bool {
        Arc::ptr_eq(&r.lease.registry.0, &self.registry.0) && r.lease.id == self.id
    }
    fn retire(&self) {
        let mut s = self
            .registry
            .0
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if s.current.get(&self.worker) == Some(&self.id) {
            s.current.remove(&self.worker);
        }
    }
    fn check_locked(&self, s: &State) -> Result<()> {
        if !s.owned.contains(&self.id) || s.current.get(&self.worker) != Some(&self.id) {
            return Err(Error::Context);
        }
        Ok(())
    }
    fn check(&self) -> Result<()> {
        let state = self.registry.0.state.lock().map_err(|_| Error::Context)?;
        self.check_locked(&state)
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let mut s = self
            .registry
            .0
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        s.owned.remove(&self.id);
        if s.current.get(&self.worker) == Some(&self.id) {
            s.current.remove(&self.worker);
        }
    }
}
impl<I: NonblockingIo> Connection<I> {
    pub fn close(&mut self) {
        // Drop buffers/socket/keys before making their capacity reusable.
        if let Some(mut carrier) = self.carrier.take() {
            carrier.close();
            drop(carrier);
        }
        if let Some(lease) = self.lease.take() {
            lease.retire();
        }
    }
    pub fn queue(
        &mut self,
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        clock: &mut impl Clock,
        plain: &[u8],
        deadline: Instant,
    ) -> Result<bool> {
        let result = (|| {
            self.lease.as_ref().ok_or(Error::Context)?.check()?;
            let queued = self
                .carrier
                .as_mut()
                .ok_or(Error::Context)?
                .queue(chain, parent, clock, plain, deadline)?;
            self.lease.as_ref().ok_or(Error::Context)?.check()?;
            Ok(queued)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    pub fn step(
        &mut self,
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        clock: &mut impl Clock,
    ) -> Result<Option<Received>> {
        let result = (|| {
            let lease = self.lease.as_ref().ok_or(Error::Context)?;
            lease.check()?;
            if self.outstanding.upgrade().is_some() {
                self.carrier
                    .as_mut()
                    .ok_or(Error::Context)?
                    .check(chain, parent, clock)?;
                lease.check()?;
                return Ok(None);
            }
            let plain = self
                .carrier
                .as_mut()
                .ok_or(Error::Context)?
                .step(chain, parent, clock)?
                .map(Zeroizing::new);
            lease.check()?;
            Ok(plain.map(|plain| {
                let token = Arc::new(());
                self.outstanding = Arc::downgrade(&token);
                Received {
                    plain,
                    lease: lease.clone(),
                    _outstanding: token,
                }
            }))
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Caller owns the canonical actor. Run only bounded typed application
    /// validation/dispatch here; no socket I/O or registry reentry in action.
    /// Replacement linearizes under this lock, including after receive waits.
    pub(crate) fn dispatch<T>(
        &mut self,
        received: Received,
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        clock: &mut impl Clock,
        action: impl FnOnce(&[u8]) -> Result<T>,
    ) -> Result<T> {
        let result = (|| {
            self.carrier
                .as_mut()
                .ok_or(Error::Context)?
                .check(chain, parent, clock)?;
            let lease = self.lease.as_ref().ok_or(Error::Context)?;
            if !lease.received_matches(&received) {
                return Err(Error::Context);
            }
            let state = lease.registry.0.state.lock().map_err(|_| Error::Context)?;
            lease.check_locked(&state)?;
            action(&received.plain)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// The packet cannot supply its own expected identity scope. That scope
    /// comes from the confirmed canonical channel, which dispatch revalidates.
    pub fn dispatch_typed<T>(
        &mut self,
        received: Received,
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        clock: &mut impl Clock,
        action: impl FnOnce(crate::worker_protocol_v2::Incoming) -> Result<T>,
    ) -> Result<T> {
        let scope = match self
            .carrier
            .as_ref()
            .ok_or(Error::Context)
            .and_then(|c| c.scope())
        {
            Ok(s) => s,
            Err(e) => {
                self.close();
                return Err(e);
            }
        };
        self.dispatch(received, chain, parent, clock, |raw| {
            action(crate::worker_protocol_v2::decode(raw, scope)?)
        })
    }
}
impl<I: NonblockingIo> Drop for Connection<I> {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn replacement_retains_owned_capacity_and_old_drop_preserves_new() {
        let r = Registry::new(2).unwrap();
        let old = r.claim([1; 32]).unwrap();
        let new = r.claim([1; 32]).unwrap();
        assert!(old.check().is_err());
        new.check().unwrap();
        assert!(r.claim([2; 32]).is_err());
        drop(old);
        new.check().unwrap();
        let other = r.claim([2; 32]).unwrap();
        other.check().unwrap();
        drop(new);
        assert!(!r.0.state.lock().unwrap().current.contains_key(&[1; 32]));
    }
    #[test]
    fn failed_capacity_does_not_revoke_current() {
        let r = Registry::new(1).unwrap();
        let old = r.claim([1; 32]).unwrap();
        assert!(r.claim([1; 32]).is_err());
        old.check().unwrap();
    }
    #[test]
    fn overflow_and_zero_capacity_fail_closed() {
        assert!(Registry::new(0).is_err());
        let r = Registry::new(1).unwrap();
        r.0.state.lock().unwrap().next = u64::MAX;
        assert!(r.claim([1; 32]).is_err());
        assert!(r.0.state.lock().unwrap().owned.is_empty());
    }
    #[test]
    fn received_identity_cannot_cross_registry_or_replacement() {
        let a = Registry::new(2).unwrap();
        let b = Registry::new(2).unwrap();
        let old = Arc::new(a.claim([1; 32]).unwrap());
        let foreign = b.claim([1; 32]).unwrap();
        let event = Received {
            plain: Zeroizing::new(vec![1, 2, 3]),
            lease: old.clone(),
            _outstanding: Arc::new(()),
        };
        assert!(old.received_matches(&event));
        assert!(!foreign.received_matches(&event));
        let new = a.claim([1; 32]).unwrap();
        assert!(!new.received_matches(&event));
        assert!(old.check().is_err());
    }
    #[test]
    fn outstanding_plaintext_retains_capacity_after_connection_retirement() {
        let r = Registry::new(1).unwrap();
        let lease = Arc::new(r.claim([1; 32]).unwrap());
        let received = Received {
            plain: Zeroizing::new(vec![1]),
            lease: lease.clone(),
            _outstanding: Arc::new(()),
        };
        lease.retire();
        drop(lease);
        assert!(received.lease.check().is_err());
        assert!(r.claim([1; 32]).is_err());
        drop(received);
        assert!(r.claim([1; 32]).is_ok());
    }
}
