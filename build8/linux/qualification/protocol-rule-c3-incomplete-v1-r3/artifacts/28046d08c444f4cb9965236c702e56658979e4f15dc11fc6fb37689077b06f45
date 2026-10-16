//! Local resource policy, not consensus. Pins are installed by trusted provisioning.
//! A claimed peer ID is only a queue key until hybrid Finished verification.
use crate::handshake::{CLIENT_FINISH_LEN, HELLO_LEN};
use crate::{Context, Error, ResponderPending, Result, Session};
use mutiny_crypto_v2::HybridKey;
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
const MAX_PINS: usize = 64;
const MAX_PENDING: usize = 4;
const PER_PEER_MINUTE: u32 = 8;
const GLOBAL_MINUTE: u32 = 32;
const WINDOW: Duration = Duration::from_secs(60);
const LIFETIME: Duration = Duration::from_secs(600);
struct Budget {
    start: Instant,
    used: u32,
}
impl Budget {
    fn refresh(&mut self, now: Instant) {
        if now.duration_since(self.start) >= WINDOW {
            self.start = now;
            self.used = 0;
        }
    }
}
struct Pin {
    context: Context,
    budget: Budget,
}
struct Pending {
    started: Instant,
    state: ResponderPending,
}
pub struct ResponderIngress {
    pins: BTreeMap<[u8; 32], Pin>,
    pending: BTreeMap<[u8; 32], Pending>,
    budget: Budget,
}
impl ResponderIngress {
    /// A bounded immutable pin set; changing authority requires a newly provisioned
    /// instance. Never construct this list from unauthenticated wire descriptors.
    pub fn new(contexts: Vec<Context>) -> Result<Self> {
        if contexts.is_empty() || contexts.len() > MAX_PINS {
            return Err(Error::Limit);
        }
        let now = Instant::now();
        let mut pins = BTreeMap::new();
        for context in contexts {
            let id = context.initiator_id();
            if pins
                .insert(
                    id,
                    Pin {
                        context,
                        budget: Budget {
                            start: now,
                            used: 0,
                        },
                    },
                )
                .is_some()
            {
                return Err(Error::Context);
            }
        }
        Ok(Self {
            pins,
            pending: BTreeMap::new(),
            budget: Budget {
                start: now,
                used: 0,
            },
        })
    }
    pub fn expire(&mut self) {
        self.expire_at(Instant::now());
    }
    fn expire_at(&mut self, now: Instant) {
        self.pending
            .retain(|_, p| now.duration_since(p.started) <= LIFETIME);
    }
    /// The fixed-width context match, rate and memory limits precede private
    /// operations. Failed crypto consumes its reserved rate budget.
    pub fn accept(&mut self, peer: [u8; 32], key: &HybridKey, hello: &[u8]) -> Result<Vec<u8>> {
        let now = Instant::now();
        self.expire_at(now);
        if hello.len() != HELLO_LEN {
            return Err(Error::Encoding);
        }
        let pin = self.pins.get(&peer).ok_or(Error::Context)?;
        if hello[..pin.context.bytes.len()] != pin.context.bytes {
            return Err(Error::Context);
        }
        self.reserve(peer, now)?;
        let (state, response) =
            ResponderPending::accept(self.pins[&peer].context.clone(), key, hello)?;
        self.pending.insert(
            peer,
            Pending {
                started: now,
                state,
            },
        );
        Ok(response)
    }
    fn reserve(&mut self, peer: [u8; 32], now: Instant) -> Result<()> {
        if self.pending.contains_key(&peer) {
            return Err(Error::Replay);
        }
        if self.pending.len() >= MAX_PENDING {
            return Err(Error::Limit);
        }
        let pin = self.pins.get_mut(&peer).ok_or(Error::Context)?;
        self.budget.refresh(now);
        pin.budget.refresh(now);
        if self.budget.used >= GLOBAL_MINUTE || pin.budget.used >= PER_PEER_MINUTE {
            return Err(Error::Limit);
        }
        self.budget.used += 1;
        pin.budget.used += 1;
        Ok(())
    }
    /// One finish attempt consumes the pending handshake, including malformed
    /// input. An invalid message cannot keep private ephemeral state indefinitely.
    pub fn finish(&mut self, peer: [u8; 32], finish: &[u8]) -> Result<(Session, Vec<u8>)> {
        self.expire();
        let p = self.pending.remove(&peer).ok_or(Error::Context)?;
        if finish.len() != CLIENT_FINISH_LEN {
            return Err(Error::Encoding);
        }
        p.state.finish(finish)
    }
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Endpoint, InitiatorPending};
    use mutiny_crypto_v2::Role;
    #[test]
    fn fixed_pins_rate_before_crypto_expiry_and_single_attempt_finish() {
        let a = HybridKey::generate(Role::Transport).unwrap();
        let b = HybridKey::generate(Role::Transport).unwrap();
        let peer = Endpoint::pinned(a.public().clone(), 1).unwrap();
        let id = peer.id();
        let ctx = Context::pinned(
            [1; 32],
            [2; 32],
            peer,
            Endpoint::pinned(b.public().clone(), 1).unwrap(),
        )
        .unwrap();
        assert!(ResponderIngress::new(vec![ctx.clone(); 65]).is_err());
        assert!(ResponderIngress::new(vec![ctx.clone(), ctx.clone()]).is_err());
        let mut gate = ResponderIngress::new(vec![ctx.clone()]).unwrap();
        let (i, hello) = InitiatorPending::start(ctx.clone(), &a).unwrap();
        assert!(gate.accept([0; 32], &b, &hello).is_err());
        assert!(gate.accept(id, &b, &hello[..hello.len() - 1]).is_err());
        assert_eq!(gate.budget.used, 0);
        let response = gate.accept(id, &b, &hello).unwrap();
        assert_eq!(gate.pending_count(), 1);
        assert_eq!(gate.accept(id, &b, &hello).unwrap_err(), Error::Replay);
        let (i, finish) = i.accept(&a, &response).unwrap();
        let (_, tag) = gate.finish(id, &finish).unwrap();
        i.finish(&tag).unwrap();
        assert_eq!(gate.pending_count(), 0);
        assert!(gate.finish(id, &finish).is_err());
        gate.accept(id, &b, &hello).unwrap();
        assert!(gate.finish(id, &[]).is_err());
        assert_eq!(gate.pending_count(), 0);
        gate.accept(id, &b, &hello).unwrap();
        gate.expire_at(Instant::now() + LIFETIME + Duration::from_secs(1));
        assert_eq!(gate.pending_count(), 0);
        let now = Instant::now();
        while gate.pins[&id].budget.used < PER_PEER_MINUTE {
            gate.reserve(id, now).unwrap();
        }
        assert_eq!(gate.reserve(id, now).unwrap_err(), Error::Limit);
        gate.reserve(id, now + WINDOW).unwrap();
        assert_eq!(gate.pins[&id].budget.used, 1);
        gate.budget.used = GLOBAL_MINUTE;
        assert_eq!(gate.reserve(id, now + WINDOW).unwrap_err(), Error::Limit);
    }
    #[test]
    fn pending_capacity_is_global_across_pinned_peers() {
        let responder = HybridKey::generate(Role::Transport).unwrap();
        let mut contexts = Vec::new();
        let mut hellos = Vec::new();
        for _ in 0..5 {
            let key = HybridKey::generate(Role::Transport).unwrap();
            let endpoint = Endpoint::pinned(key.public().clone(), 1).unwrap();
            let id = endpoint.id();
            let ctx = Context::pinned(
                [1; 32],
                [2; 32],
                endpoint,
                Endpoint::pinned(responder.public().clone(), 1).unwrap(),
            )
            .unwrap();
            let (_, hello) = InitiatorPending::start(ctx.clone(), &key).unwrap();
            contexts.push(ctx);
            hellos.push((id, hello));
        }
        let mut gate = ResponderIngress::new(contexts).unwrap();
        for (id, hello) in &hellos[..4] {
            gate.accept(*id, &responder, hello).unwrap();
        }
        assert_eq!(gate.pending_count(), 4);
        assert_eq!(gate.budget.used, 4);
        assert_eq!(
            gate.accept(hellos[4].0, &responder, &hellos[4].1)
                .unwrap_err(),
            Error::Limit
        );
        assert_eq!(gate.budget.used, 4);
        assert!(gate.finish(hellos[0].0, &[]).is_err());
        gate.accept(hellos[4].0, &responder, &hellos[4].1).unwrap();
        assert_eq!(gate.pending_count(), 4);
    }
}
