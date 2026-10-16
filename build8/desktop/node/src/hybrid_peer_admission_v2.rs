//! Local connection budgets and current transport-pin dispatch guard.
//! No consensus membership, private keys, listener or provisioning authority.
use mutiny_consensus_v8::Hash;
use crate::hybrid_peer_error_v2::{PeerFailure, PeerResult};
use mutiny_transport_v2::{Context, Endpoint, Session, object_link::LocalAuthorization};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, atomic::{AtomicBool, Ordering}},
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, String>;

/// Same local attempt limits as transport-v2 datagram ingress. Not consensus.
struct AttemptBudget {
    start: Instant,
    used: u32,
    peers: BTreeMap<Hash, u32>,
}
impl AttemptBudget {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            used: 0,
            peers: BTreeMap::new(),
        }
    }
    fn reserve(&mut self, peer: Hash, now: Instant) -> Result<()> {
        let elapsed = now
            .checked_duration_since(self.start)
            .ok_or("Handshake budget clock regressed")?;
        if elapsed >= Duration::from_secs(60) {
            self.start = now;
            self.used = 0;
            self.peers.clear();
        }
        if self.used >= 32 || self.peers.get(&peer).copied().unwrap_or(0) >= 8 {
            return Err("Handshake attempt rate exhausted".into());
        }
        self.used += 1;
        *self.peers.entry(peer).or_default() += 1;
        // At most 32 distinct entries, independently of pin replacement churn.
        Ok(())
    }
}
struct State {
    revision: u64,
    next: u64,
    peers: BTreeMap<Hash, Endpoint>,
    reservations: BTreeMap<u64, Option<Hash>>,
    pending_peers: BTreeMap<Hash, u64>,
    attempts: AttemptBudget,
}
struct Inner {
    genesis: Hash,
    fingerprint: Hash,
    local: Endpoint,
    connections: usize,
    pending: usize,
    authorization: LocalAuthorization,
    state: Mutex<State>,
}
#[derive(Clone)]
pub struct Registry(Arc<Inner>);
pub struct Pending {
    registry: Registry,
    id: u64,
    revision: u64,
    peer: Option<Hash>,
    initiator: bool,
    charged: bool,
    released: bool,
}
pub struct Active {
    reservation: Pending,
    session_id: Hash,
}
/// Field order keeps capacity reserved until socket and traffic keys are dropped.
pub struct Connection {
    carrier: mutiny_transport_v2::tcp::Carrier,
    session: Session,
    active: Active,
}
pub struct PeerLink {
    carrier: mutiny_transport_v2::tcp::Carrier,
    link: mutiny_transport_v2::object_link::ObjectLink,
    active: Active,
    closed: bool,
    alive: Arc<AtomicBool>,
}
/// Opaque, read-only proof minted only from an admitted B1 connection. It owns
/// neither a socket/session key nor its reservation permit. Keeping a clone does
/// not keep the lease alive or refund an attempt. Recheck before and after any
/// read/export wait; queue publication still needs the live Worker's own guard.
#[derive(Clone)]
pub struct AdmittedHistorySession {
    registry: Arc<Inner>,
    reservation_id: u64,
    revision: u64,
    session_id: Hash,
    peer: Hash,
    authorization: LocalAuthorization,
    alive: Arc<AtomicBool>,
    lifetime_deadline: Instant,
}
impl AdmittedHistorySession {
    pub fn peer_id(&self) -> Hash { self.peer }
    pub fn session_id(&self) -> Hash { self.session_id }
    pub fn authorization(&self) -> LocalAuthorization { self.authorization }
    /// The registry mutex is released on return; it is never retained across an
    /// actor/snapshot/socket wait. Close, drop, repin and natural expiry refuse.
    pub fn check_current(&self) -> PeerResult<()> {
        if !self.alive.load(Ordering::Acquire) { return Err("Peer closed".into()); }
        let state = self.registry.state.lock().map_err(|_| "Transport admission poisoned")?;
        if state.revision != self.revision || !state.peers.contains_key(&self.peer)
            || state.reservations.get(&self.reservation_id) != Some(&Some(self.peer))
            || !self.alive.load(Ordering::Acquire)
        { return Err("Transport session/pin retired".into()); }
        if Instant::now() > self.lifetime_deadline { return Err(PeerFailure::SessionExpired); }
        Ok(())
    }
}
/// Opaque, single-use handoff from socket receive to guarded actor dispatch.
/// No public constructor or event extractor: another connection cannot claim it.
pub struct Received {
    session_id: Hash,
    reservation_id: u64,
    registry: Arc<Inner>,
    event: mutiny_transport_v2::object_link::Event,
}
impl Connection {
    pub fn peer_id(&self) -> Hash {
        self.session.peer_id()
    }
    pub fn attach(self, queue: mutiny_transport_v2::objects::ObjectQueue) -> Result<PeerLink> {
        let Self {
            mut carrier,
            session,
            active,
        } = self;
        match mutiny_transport_v2::object_link::ObjectLink::new_authorized(session, queue, active.reservation.registry.0.authorization) {
            Ok(link) => Ok(PeerLink {
                carrier,
                link,
                active,
                closed: false,
                alive: Arc::new(AtomicBool::new(true)),
            }),
            Err(e) => {
                carrier.close();
                Err(format!("Peer queue/session mismatch: {e:?}"))
            }
        }
    }
}
impl PeerLink {
    pub fn peer_id(&self) -> Hash {
        self.link.peer_id()
    }
    pub fn close(&mut self) {
        self.alive.store(false, Ordering::Release);
        self.carrier.close();
        self.closed = true;
    }
    /// Mint a read-only B1 host proof under the exact current admitted pin. No
    /// caller-supplied peer, epoch or role can construct or refresh this proof.
    pub fn history_session(&mut self) -> PeerResult<AdmittedHistorySession> {
        let result = (|| {
            if self.closed { return Err("Peer closed".into()); }
            self.active.with_current(self.link.session_id(), || {
                let authorization = self.link.authorization();
                if !matches!(authorization, LocalAuthorization::WalletHistoryClientToNode
                    | LocalAuthorization::NodeToWalletHistoryClient) {
                    return Err("History purpose not admitted".into());
                }
                let proof = AdmittedHistorySession {
                    registry: self.active.reservation.registry.0.clone(),
                    reservation_id: self.active.reservation.id,
                    revision: self.active.reservation.revision,
                    session_id: self.link.session_id(),
                    peer: self.link.peer_id(),
                    authorization,
                    alive: self.alive.clone(),
                    lifetime_deadline: self.link.lifetime_deadline(),
                };
                if Instant::now() > proof.lifetime_deadline { return Err(PeerFailure::SessionExpired); }
                Ok(proof)
            })?
        })();
        if result.is_err() { self.close(); }
        result
    }
    /// Consume an opaque proof produced by the ordered native receiver and
    /// discard only its exact current-session public transport copy. Canonical
    /// state is never discarded. Construct/send required ACK frames beforehand.
    /// Raw page/object hashes cannot replace native verification proof:
    /// ```compile_fail
    /// use mutinyd_v8::hybrid_peer_admission_v2::PeerLink;
    /// fn raw(peer: &mut PeerLink, page: [u8;32], object: [u8;32]) {
    ///     peer.history_reclaim_verified((page, object));
    /// }
    /// ```
    /// Proof internals remain inaccessible to downstream callers:
    /// ```compile_fail
    /// use mutinyd_v8::{history_service_v1::VerifiedHistoryReclaim,
    ///     hybrid_peer_admission_v2::AdmittedHistorySession};
    /// fn extract(proof: VerifiedHistoryReclaim, session: &AdmittedHistorySession) {
    ///     let _ = proof.into_parts(session);
    /// }
    /// ```
    pub fn history_reclaim_verified(&mut self,
        verified:crate::history_service_v1::VerifiedHistoryReclaim)->PeerResult<()> {
        self.history_reclaim_verified_object(verified).map(|_|())
    }
    /// One consuming path shared with the worker's existing object notification.
    /// The ID is exposed only inside this crate, after successful guarded reclaim.
    pub(crate) fn history_reclaim_verified_object(&mut self,
        verified:crate::history_service_v1::VerifiedHistoryReclaim)->PeerResult<Hash> {
        let proof=self.history_session()?;
        let (page,object)=verified.into_parts(&proof)?;
        self.with_current(|link|link.history_reclaim_verified_candidate(&page,&object))?
            .map_err(|e|PeerFailure::transport("History verified reclaim",e))?;
        Ok(object)
    }
    /// Bounded idle wait outside the canonical actor. Revocation is checked on
    /// both sides of the socket wait, even when no bytes arrived. Readiness does
    /// not authorize a message; receive and guarded actor dispatch still apply.
    pub fn wait_for_frame(&mut self, limit: Instant) -> Result<bool> {
        self.wait_for_frame_typed(limit).map_err(String::from)
    }
    pub fn wait_for_frame_typed(&mut self, limit: Instant) -> PeerResult<bool> {
        let result = (|| {
            if self.closed { return Err("Peer closed".into()); }
            self.active.with_current(self.link.session_id(), || ())?;
            let ready = self
                .carrier
                .wait_for_frame(limit)
                .map_err(|e| PeerFailure::carrier("Peer idle wait", e))?;
            self.active.with_current(self.link.session_id(), || ())?;
            Ok(ready)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Receive outside the canonical actor. Recheck again with with_current
    /// inside that actor before semantic dispatch, including after actor waits.
    pub fn receive(&mut self, limit: std::time::Instant) -> Result<Received> {
        self.receive_typed(limit).map_err(String::from)
    }
    pub fn receive_typed(&mut self, limit: std::time::Instant) -> PeerResult<Received> {
        let result = (|| {
            if self.closed { return Err("Peer closed".into()); }
            self.active.with_current(self.link.session_id(), || ())?;
            let frame = self.carrier
                .receive_frame_for_session(self.link.session_id(), limit)
                .map_err(|e| PeerFailure::carrier("Peer receive", e))?;
            // No socket wait under this guard. Pin/capability retirement and
            // authentication/queue admission are serialized, before persistence.
            let event = self.active.with_current(self.link.session_id(), || self.link.receive(&frame))?
                .map_err(|e| PeerFailure::transport("Peer authorization/receive", e))?;
            Ok(Received {
                session_id: self.link.session_id(),
                reservation_id: self.active.reservation.id,
                registry: self.active.reservation.registry.0.clone(),
                event,
            })
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// Acquire the canonical actor before calling. The event must originate
    /// from this exact connection, even across registry recreation or reconnect.
    /// The closure must not perform socket I/O or recursively call the registry.
    pub fn dispatch_received<T>(
        &mut self,
        received: Received,
        action: impl FnOnce(
            &mut mutiny_transport_v2::object_link::ObjectLink,
            mutiny_transport_v2::object_link::Event,
        ) -> T,
    ) -> Result<T> {
        self.dispatch_received_typed(received, action).map_err(String::from)
    }
    pub fn dispatch_received_typed<T>(
        &mut self,
        received: Received,
        action: impl FnOnce(
            &mut mutiny_transport_v2::object_link::ObjectLink,
            mutiny_transport_v2::object_link::Event,
        ) -> T,
    ) -> PeerResult<T> {
        let own = &self.active.reservation;
        if received.session_id != self.link.session_id()
            || received.reservation_id != own.id
            || !Arc::ptr_eq(&received.registry, &own.registry.0)
        {
            self.close();
            return Err("Received event belongs to another connection".into());
        }
        let result = self.with_current(|link| {
            link.check_incoming_event(&received.event).map_err(|e| PeerFailure::transport("Peer processing authorization", e))?;
            Ok(action(link, received.event))
        }).map_err(PeerFailure::from).and_then(|value| value);
        if result.is_err() {
            self.close();
        }
        result
    }
    pub fn send(&mut self, frame: &[u8], limit: std::time::Instant) -> Result<()> {
        self.send_typed(frame, limit).map_err(String::from)
    }
    pub fn send_typed(&mut self, frame: &[u8], limit: std::time::Instant) -> PeerResult<()> {
        let result = (|| {
            if self.closed { return Err("Peer closed".into()); }
            self.active.with_current(self.link.session_id(), || ())?;
            self.carrier
                .send_frame(frame, limit)
                .map_err(|e| PeerFailure::carrier("Peer send", e))?;
            self.active.with_current(self.link.session_id(), || ())?;
            Ok(())
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// The closure may validate/dispatch/enqueue bounded objects, never wait on
    /// sockets or call the registry. Acquire the canonical actor first.
    pub fn with_current<T>(
        &mut self,
        action: impl FnOnce(&mut mutiny_transport_v2::object_link::ObjectLink) -> T,
    ) -> Result<T> {
        if self.closed { return Err("Peer closed".into()); }
        self.active
            .with_current(self.link.session_id(), || action(&mut self.link))
    }
    /// Flatten a transport action under the same current-pin guard. This does
    /// not add an expiry timer or reconnect; the caller retains failure cleanup.
    /// A retained queue object is never sufficient session authorization.
    pub fn with_current_transport<T>(
        &mut self,
        action: impl FnOnce(&mut mutiny_transport_v2::object_link::ObjectLink)
            -> mutiny_transport_v2::Result<T>,
    ) -> PeerResult<T> {
        self.with_current(action).map_err(PeerFailure::from)?
            .map_err(|e| PeerFailure::transport("Peer transport action", e))
    }
}
fn pins(peers: Vec<Endpoint>, local: Hash) -> Result<BTreeMap<Hash, Endpoint>> {
    if peers.len() > 1024 {
        return Err("Transport pin limit".into());
    }
    let mut result = BTreeMap::new();
    for peer in peers {
        if peer.id() == local || result.insert(peer.id(), peer).is_some() {
            return Err("Reflected or duplicate transport pin".into());
        }
    }
    Ok(result)
}
impl Drop for PeerLink {
    fn drop(&mut self) {
        // Invalidate read-only clones before releasing socket, keys and permit.
        self.alive.store(false, Ordering::Release);
        self.carrier.close();
    }
}
impl Registry {
    pub fn new(
        genesis: Hash,
        fingerprint: Hash,
        local: Endpoint,
        peers: Vec<Endpoint>,
        connections: usize,
        pending: usize,
    ) -> Result<Self> {
        Self::new_authorized(genesis, fingerprint, local, peers, connections, pending, LocalAuthorization::Unrestricted)
    }
    /// Trusted local admission: a proven transport pin may submit wallet-client
    /// candidates only. No wire field grants this capability or spending power.
    pub fn new_wallet_clients(genesis: Hash, fingerprint: Hash, local: Endpoint,
        peers: Vec<Endpoint>, connections: usize, pending: usize) -> Result<Self> {
        Self::new_authorized(genesis, fingerprint, local, peers, connections, pending, LocalAuthorization::WalletClientToNode)
    }
    /// Wallet-side mirror: receive verified-history candidates from a pinned node.
    pub fn new_wallet_client(genesis: Hash, fingerprint: Hash, local: Endpoint,
        peers: Vec<Endpoint>, connections: usize, pending: usize) -> Result<Self> {
        Self::new_authorized(genesis, fingerprint, local, peers, connections, pending, LocalAuthorization::NodeToWalletClient)
    }
    /// Explicit B1 node-side history service. The capability is selected by the
    /// trusted local owner, never by a wire field or by a stored object.
    pub fn new_wallet_history_clients(genesis: Hash, fingerprint: Hash, local: Endpoint,
        peers: Vec<Endpoint>, connections: usize, pending: usize) -> Result<Self> {
        Self::new_authorized(genesis, fingerprint, local, peers, connections, pending,
            LocalAuthorization::WalletHistoryClientToNode)
    }
    /// Explicit B1 wallet-side mirror. Requires a separately provisioned V9
    /// history queue on attach; it grants no node, voter or spending authority.
    pub fn new_wallet_history_client(genesis: Hash, fingerprint: Hash, local: Endpoint,
        peers: Vec<Endpoint>, connections: usize, pending: usize) -> Result<Self> {
        Self::new_authorized(genesis, fingerprint, local, peers, connections, pending,
            LocalAuthorization::NodeToWalletHistoryClient)
    }
    fn new_authorized(genesis: Hash, fingerprint: Hash, local: Endpoint,
        peers: Vec<Endpoint>, connections: usize, pending: usize,
        authorization: LocalAuthorization) -> Result<Self> {
        if genesis == [0; 32]
            || fingerprint == [0; 32]
            || !(1..=32).contains(&connections)
            || pending == 0
            || pending > connections
        {
            return Err("Peer admission context/budget".into());
        }
        let peers = pins(peers, local.id())?;
        Ok(Self(Arc::new(Inner {
            genesis,
            fingerprint,
            local,
            connections,
            pending,
            authorization,
            state: Mutex::new(State {
                revision: 1,
                next: 1,
                peers,
                reservations: BTreeMap::new(),
                pending_peers: BTreeMap::new(),
                attempts: AttemptBudget::new(),
            }),
        })))
    }
    /// Acquire BEFORE private handshake work. Drop on every rejected/aborted
    /// socket. A reserved socket counts until its owner closes it and drops this.
    pub fn begin(&self) -> Result<Pending> {
        let mut s = self
            .0
            .state
            .lock()
            .map_err(|_| "Transport admission poisoned")?;
        if s.reservations.len() >= self.0.connections
            || s.reservations.values().filter(|p| p.is_none()).count() >= self.0.pending
        {
            return Err("Transport connection budget exhausted".into());
        }
        let id = s.next;
        s.next = s
            .next
            .checked_add(1)
            .ok_or("Transport reservation overflow")?;
        s.reservations.insert(id, None);
        Ok(Pending {
            registry: self.clone(),
            id,
            revision: s.revision,
            peer: None,
            initiator: false,
            charged: false,
            released: false,
        })
    }
    /// Trusted local replacement, not a wire command or Continuity transition.
    /// Every old reservation/session is retired, including remove/re-add of an
    /// identical pin. Counts are retained until old socket owners drop leases.
    /// Replacing the local endpoint requires a new Registry and closed service.
    pub fn replace_peers(&self, peers: Vec<Endpoint>) -> Result<()> {
        let peers = pins(peers, self.0.local.id())?;
        let mut s = self
            .0
            .state
            .lock()
            .map_err(|_| "Transport admission poisoned")?;
        let revision = s
            .revision
            .checked_add(1)
            .ok_or("Transport pin revision overflow")?;
        s.peers = peers;
        s.revision = revision;
        Ok(())
    }
}
impl Pending {
    /// Reserve before socket handshake/private crypto. Silent and failed
    /// handshakes consume the attempt. Dropping/repinning never refunds it.
    fn charge_attempt(&mut self) -> Result<()> {
        let peer = self.peer.ok_or("Pending peer not selected")?;
        let mut s = self
            .registry
            .0
            .state
            .lock()
            .map_err(|_| "Transport admission poisoned")?;
        if self.charged
            || s.revision != self.revision
            || s.reservations.get(&self.id) != Some(&None)
            || !s.peers.contains_key(&peer)
            || s.pending_peers.contains_key(&peer)
            || s.reservations.values().any(|p| *p == Some(peer))
        {
            return Err("Duplicate or retired handshake attempt".into());
        }
        s.attempts.reserve(peer, Instant::now())?;
        s.pending_peers.insert(peer, self.id);
        self.charged = true;
        Ok(())
    }
    /// Peer ID is only a lookup selector. The returned complete trusted context
    /// must then be authenticated by the existing V2 handshake.
    pub fn context(&mut self, peer: Hash) -> Result<Context> {
        let s = self
            .registry
            .0
            .state
            .lock()
            .map_err(|_| "Transport admission poisoned")?;
        if s.revision != self.revision
            || !s.reservations.contains_key(&self.id)
            || self.peer.is_some_and(|old| old != peer)
        {
            return Err("Retired or changed pending peer".into());
        }
        let endpoint = s
            .peers
            .get(&peer)
            .ok_or("Unconfigured transport peer")?
            .clone();
        let (initiator, responder) = if self.initiator {
            (self.registry.0.local.clone(), endpoint)
        } else {
            (endpoint, self.registry.0.local.clone())
        };
        let context = Context::pinned(
            self.registry.0.genesis,
            self.registry.0.fingerprint,
            initiator,
            responder,
        )
        .map_err(|e| format!("Peer context: {e:?}"))?;
        self.peer = Some(peer);
        Ok(context)
    }
    /// Complete a fresh responder handshake owned by this reservation. External
    /// callers cannot promote a previously established Session into a new lease.
    /// Socket/crypto waits occur without holding the admission mutex.
    pub fn respond(
        mut self,
        peer: Hash,
        stream: std::net::TcpStream,
        key: &mutiny_crypto_v2::HybridKey,
        budget: std::time::Duration,
    ) -> Result<Connection> {
        let context = self.context(peer)?;
        self.charge_attempt()?;
        let (carrier, session) =
            mutiny_transport_v2::tcp::Carrier::respond(stream, context, key, budget)
                .map_err(|e| format!("Reserved hybrid handshake: {e:?}"))?;
        self.complete(carrier, session)
    }
    /// Absolute accept-time deadline for a queued inbound connection.
    pub(crate) fn respond_until(
        mut self,
        peer: Hash,
        stream: std::net::TcpStream,
        key: &mutiny_crypto_v2::HybridKey,
        deadline: Instant,
    ) -> Result<Connection> {
        let context = self.context(peer)?;
        self.charge_attempt()?;
        let (carrier, session) =
            mutiny_transport_v2::tcp::Carrier::respond_until(stream, context, key, deadline)
                .map_err(|e| format!("Queued hybrid handshake: {e:?}"))?;
        self.complete(carrier, session)
    }
    /// Outbound equivalent, with the same shared budgets and revocation guard.
    /// A reservation that already selected responder context cannot change role.
    pub fn initiate(
        mut self,
        peer: Hash,
        stream: std::net::TcpStream,
        key: &mutiny_crypto_v2::HybridKey,
        budget: std::time::Duration,
    ) -> Result<Connection> {
        if self.peer.is_some() {
            return Err("Pending handshake direction already selected".into());
        }
        self.initiator = true;
        let context = self.context(peer)?;
        self.charge_attempt()?;
        let (carrier, session) =
            mutiny_transport_v2::tcp::Carrier::initiate(stream, context, key, budget)
                .map_err(|e| format!("Reserved hybrid handshake: {e:?}"))?;
        self.complete(carrier, session)
    }
    fn complete(
        mut self,
        mut carrier: mutiny_transport_v2::tcp::Carrier,
        session: Session,
    ) -> Result<Connection> {
        if let Err(error) = self.validate(&session) {
            carrier.close();
            return Err(error);
        }
        let active = Active {
            reservation: self,
            session_id: session.id(),
        };
        Ok(Connection {
            carrier,
            session,
            active,
        })
    }
    #[cfg(test)]
    fn authenticate(mut self, session: &Session) -> Result<Active> {
        self.charge_attempt()?;
        self.validate(session)?;
        Ok(Active {
            reservation: self,
            session_id: session.id(),
        })
    }
    fn validate(&mut self, session: &Session) -> Result<()> {
        let peer = self.peer.ok_or("Pending peer not selected")?;
        {
            let mut s = self
                .registry
                .0
                .state
                .lock()
                .map_err(|_| "Transport admission poisoned")?;
            if !self.charged
                || s.revision != self.revision
                || s.reservations.get(&self.id) != Some(&None)
                || s.pending_peers.get(&peer) != Some(&self.id)
            {
                return Err("Retired pending handshake".into());
            }
            let endpoint = s.peers.get(&peer).ok_or("Peer pin revoked")?.clone();
            let (initiator, responder) = if self.initiator {
                (self.registry.0.local.clone(), endpoint)
            } else {
                (endpoint, self.registry.0.local.clone())
            };
            let context = Context::pinned(
                self.registry.0.genesis,
                self.registry.0.fingerprint,
                initiator,
                responder,
            )
            .map_err(|e| format!("Peer context: {e:?}"))?;
            if session.peer_id() != peer || !session.matches_context(&context) {
                return Err("Handshake/pin context mismatch".into());
            }
            if s.reservations.values().any(|p| *p == Some(peer)) {
                return Err("Duplicate authenticated peer".into());
            }
            s.reservations.insert(self.id, Some(peer));
            s.pending_peers.remove(&peer);
        }
        Ok(())
    }
}
impl Active {
    pub fn session_id(&self) -> Hash {
        self.session_id
    }
    /// Check immediately before actor dispatch, even after a socket/actor wait.
    /// Caller acquires its canonical actor BEFORE this guard. The closure must
    /// perform no socket I/O or call back into this registry. Pin replacement is
    /// serialized against this closure; a panic poisons future admission closed.
    pub fn with_current<T>(&self, session_id: Hash, action: impl FnOnce() -> T) -> Result<T> {
        let p = &self.reservation;
        let s = p
            .registry
            .0
            .state
            .lock()
            .map_err(|_| "Transport admission poisoned")?;
        let peer = p.peer.ok_or("Missing authenticated peer")?;
        if session_id != self.session_id
            || s.revision != p.revision
            || !s.peers.contains_key(&peer)
            || s.reservations.get(&p.id) != Some(&Some(peer))
        {
            return Err("Transport session/pin retired".into());
        }
        Ok(action())
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        if !self.released {
            // Cleanup may recover the mutex contents, but every operational
            // path still rejects its poison state. Never resurrect admission.
            let mut s = self
                .registry
                .0
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            s.reservations.remove(&self.id);
            if let Some(peer) = self.peer {
                if s.pending_peers.get(&peer) == Some(&self.id) {
                    s.pending_peers.remove(&peer);
                }
            }
            self.released = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mutiny_crypto_v2::{HybridKey, Role};
    use mutiny_transport_v2::{InitiatorPending, ResponderPending};
    fn session(a: &HybridKey, b: &HybridKey, context: Context) -> Session {
        let (i, hello) = InitiatorPending::start(context.clone(), a).unwrap();
        let (r, response) = ResponderPending::accept(context, b, &hello).unwrap();
        let (_, finish) = i.accept(a, &response).unwrap();
        r.finish(&finish).unwrap().0
    }
    #[test]
    fn hybrid_peer_attempt_rates_failures_repins_and_single_pending() {
        let mut rate = AttemptBudget::new();
        let start = rate.start;
        assert!(
            rate.reserve([1; 32], start - Duration::from_secs(1))
                .is_err()
        );
        assert_eq!(rate.used, 0);
        for n in 1..=4 {
            for _ in 0..8 {
                rate.reserve([n; 32], start).unwrap();
            }
            assert!(rate.reserve([n; 32], start).is_err());
        }
        assert!(
            rate.reserve([5; 32], start + Duration::from_secs(59))
                .is_err()
        );
        assert_eq!(rate.used, 32);
        rate.reserve([5; 32], start + Duration::from_secs(60))
            .unwrap();
        assert_eq!(rate.used, 1);
        assert_eq!(rate.peers.len(), 1);
        for n in 6..37 {
            rate.reserve([n; 32], start + Duration::from_secs(60))
                .unwrap();
        }
        assert_eq!(rate.peers.len(), 32);
        assert!(
            rate.reserve([37; 32], start + Duration::from_secs(60))
                .is_err()
        );

        let a = HybridKey::generate(Role::Transport).unwrap();
        let b = HybridKey::generate(Role::Transport).unwrap();
        let pa = Endpoint::pinned(a.public().clone(), 1).unwrap();
        let pb = Endpoint::pinned(b.public().clone(), 1).unwrap();
        let registry = Registry::new([1; 32], [2; 32], pb, vec![pa.clone()], 2, 2).unwrap();
        let mut pending = registry.begin().unwrap();
        pending.context(pa.id()).unwrap();
        pending.charge_attempt().unwrap();
        assert!(pending.charge_attempt().is_err());
        let mut duplicate = registry.begin().unwrap();
        duplicate.context(pa.id()).unwrap();
        assert!(duplicate.charge_attempt().is_err());
        drop(duplicate);
        drop(pending); // Interrupted/failed attempt cannot refund rate budget.
        assert!(registry.0.state.lock().unwrap().pending_peers.is_empty());
        for _ in 1..8 {
            registry.replace_peers(vec![]).unwrap();
            registry.replace_peers(vec![pa.clone()]).unwrap();
            let mut pending = registry.begin().unwrap();
            pending.context(pa.id()).unwrap();
            pending.charge_attempt().unwrap();
        }
        let mut denied = registry.begin().unwrap();
        denied.context(pa.id()).unwrap();
        assert!(denied.charge_attempt().is_err());
        assert_eq!(registry.0.state.lock().unwrap().attempts.used, 8);
    }
    #[test]
    fn hybrid_peer_budgets_exact_context_duplicates_and_revocation() {
        let a = HybridKey::generate(Role::Transport).unwrap();
        let b = HybridKey::generate(Role::Transport).unwrap();
        let pa = Endpoint::pinned(a.public().clone(), 1).unwrap();
        let pb = Endpoint::pinned(b.public().clone(), 1).unwrap();
        let registry = Registry::new([1; 32], [2; 32], pb.clone(), vec![pa.clone()], 2, 1).unwrap();
        let mut pending = registry.begin().unwrap();
        assert!(registry.begin().is_err());
        assert!(pending.context([0; 32]).is_err());
        let context = pending.context(pa.id()).unwrap();
        let valid = session(&a, &b, context);
        let active = pending.authenticate(&valid).unwrap();
        assert_eq!(active.with_current(valid.id(), || 17).unwrap(), 17);
        let mut duplicate = registry.begin().unwrap();
        duplicate.context(pa.id()).unwrap();
        assert!(duplicate.authenticate(&valid).is_err()); // releases its slot
        let other_registry =
            Registry::new([1; 32], [2; 32], pb.clone(), vec![pa.clone()], 1, 1).unwrap();
        let mut wrong = other_registry.begin().unwrap();
        wrong.context(pa.id()).unwrap();
        let other = session(
            &a,
            &b,
            Context::pinned([3; 32], [2; 32], pa.clone(), pb).unwrap(),
        );
        assert!(
            matches!(wrong.authenticate(&other), Err(e) if e == "Handshake/pin context mismatch")
        );
        assert!(
            active
                .with_current(other.id(), || panic!("wrong session executed"))
                .is_err()
        );
        let mut old_pending = registry.begin().unwrap();
        old_pending.context(pa.id()).unwrap();
        registry.replace_peers(vec![]).unwrap();
        registry.replace_peers(vec![pa.clone()]).unwrap();
        assert!(
            active
                .with_current(valid.id(), || panic!("retired callback executed"))
                .is_err()
        );
        assert!(old_pending.authenticate(&valid).is_err());
        let next = registry.begin().unwrap();
        assert!(registry.begin().is_err());
        drop(next);
        drop(active);
        let next = registry.begin().unwrap();
        drop(next);
        assert!(registry.replace_peers(vec![pa.clone(), pa]).is_err());
    }
    #[test]
    fn hybrid_peer_pin_replacement_serializes_with_dispatch_and_panics_fail_closed() {
        let a = HybridKey::generate(Role::Transport).unwrap();
        let b = HybridKey::generate(Role::Transport).unwrap();
        let pa = Endpoint::pinned(a.public().clone(), 1).unwrap();
        let pb = Endpoint::pinned(b.public().clone(), 1).unwrap();
        let registry = Registry::new([1; 32], [2; 32], pb, vec![pa.clone()], 2, 1).unwrap();
        let mut pending = registry.begin().unwrap();
        let context = pending.context(pa.id()).unwrap();
        let session = session(&a, &b, context);
        let active = pending.authenticate(&session).unwrap();
        let (entered, ready) = std::sync::mpsc::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let dispatch = std::thread::spawn(move || {
            active
                .with_current(session.id(), || {
                    entered.send(()).unwrap();
                    wait.recv().unwrap();
                })
                .unwrap();
            active
        });
        ready.recv().unwrap();
        let copy = registry.clone();
        let (attempted, attempt) = std::sync::mpsc::channel();
        let rotate = std::thread::spawn(move || {
            attempted.send(()).unwrap();
            copy.replace_peers(vec![]).unwrap();
        });
        attempt.recv().unwrap();
        release.send(()).unwrap();
        let active = dispatch.join().unwrap();
        rotate.join().unwrap();
        assert!(active.with_current(active.session_id(), || ()).is_err());
        drop(active);
        registry.replace_peers(vec![pa.clone()]).unwrap();
        let mut pending = registry.begin().unwrap();
        let context = pending.context(pa.id()).unwrap();
        let valid = tests::session(&a, &b, context);
        let active = pending.authenticate(&valid).unwrap();
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            active.with_current(valid.id(), || panic!("synthetic dispatch fault"))
        }));
        assert!(caught.is_err());
        drop(active);
        assert!(registry.begin().is_err());
        assert!(registry.replace_peers(vec![]).is_err());
    }
    #[test]
    fn hybrid_peer_reserved_tcp_handshake_holds_budget_until_owner_releases() {
        use std::{
            net::{TcpListener, TcpStream},
            time::Duration,
        };
        let a = HybridKey::generate(Role::Transport).unwrap();
        let b = HybridKey::generate(Role::Transport).unwrap();
        let pa = Endpoint::pinned(a.public().clone(), 1).unwrap();
        let pb = Endpoint::pinned(b.public().clone(), 1).unwrap();
        let registry = Registry::new([1; 32], [2; 32], pb.clone(), vec![pa.clone()], 1, 1).unwrap();
        let outgoing = Registry::new([1; 32], [2; 32], pa.clone(), vec![pb.clone()], 1, 1).unwrap();
        let server_peer = pb.id();
        let peer = pa.id();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let mut listener = crate::hybrid_peer_listener_v2::Listener::new(
            listener,
            registry.clone(),
            peer,
            Duration::from_secs(30),
        )
        .unwrap();
        let pending = listener.poll().unwrap().unwrap();
        assert!(registry.begin().is_err());
        let server = std::thread::spawn(move || pending.respond(&b).unwrap());
        let Connection {
            active: client_active,
            carrier: client,
            session: client_session,
        } = outgoing
            .begin()
            .unwrap()
            .initiate(server_peer, client, &a, Duration::from_secs(30))
            .unwrap();
        let Connection {
            active,
            carrier,
            session,
        } = server.join().unwrap();
        assert_eq!(session.id(), client_session.id());
        assert!(outgoing.begin().is_err());
        assert!(
            client_active
                .with_current(client_session.id(), || ())
                .is_ok()
        );
        assert_eq!(
            active
                .with_current(session.id(), || "authorized dispatch")
                .unwrap(),
            "authorized dispatch"
        );
        assert!(registry.begin().is_err());
        registry.replace_peers(vec![]).unwrap();
        assert!(
            active
                .with_current(session.id(), || panic!("revoked socket dispatched"))
                .is_err()
        );
        assert!(registry.begin().is_err()); // retired socket still consumes budget
        drop(carrier);
        drop(session);
        drop(active);
        drop(client);
        drop(client_session);
        drop(client_active);
        drop(outgoing.begin().unwrap());
        drop(registry.begin().unwrap());
    }
    #[test]
    fn hybrid_peer_owned_link_rechecks_pins_after_receive_before_dispatch() {
        use mutiny_transport_v2::{
            object_link::Event,
            objects::{ObjectKind, ObjectQueue},
        };
        use std::{
            net::{TcpListener, TcpStream},
            time::{Duration, Instant},
        };
        let a = HybridKey::generate(Role::Transport).unwrap();
        let b = HybridKey::generate(Role::Transport).unwrap();
        let pa = Endpoint::pinned(a.public().clone(), 1).unwrap();
        let pb = Endpoint::pinned(b.public().clone(), 1).unwrap();
        let inbound = Registry::new([1; 32], [2; 32], pb.clone(), vec![pa.clone()], 1, 1).unwrap();
        let outbound = Registry::new([1; 32], [2; 32], pa.clone(), vec![pb.clone()], 1, 1).unwrap();
        let pending = inbound.begin().unwrap();
        let peer = pa.id();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let server = listener.accept().unwrap().0;
        let server = std::thread::spawn(move || {
            pending
                .respond(peer, server, &b, Duration::from_secs(30))
                .unwrap()
        });
        let client = outbound
            .begin()
            .unwrap()
            .initiate(pb.id(), client, &a, Duration::from_secs(30))
            .unwrap();
        let server = server.join().unwrap();
        let mut random = [0; 16];
        mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
        let base = std::env::temp_dir().join(format!("build8-owned-peer-{}", hex::encode(random)));
        std::fs::create_dir(&base).unwrap();
        let txq = ObjectQueue::open(&base.join("send.sqlite"), client.peer_id()).unwrap();
        let rxq = ObjectQueue::open(&base.join("recv.sqlite"), server.peer_id()).unwrap();
        let mut client = client.attach(txq).unwrap();
        let mut server = server.attach(rxq).unwrap();
        for _ in 0..2 {
            assert!(
                !server
                    .wait_for_frame(Instant::now() + Duration::from_millis(20))
                    .unwrap()
            );
            assert!(inbound.begin().is_err()); // idle sessions retain their lease
        }
        let mut events = Vec::new();
        for n in 0..3 {
            let (_, have) = client
                .with_current(|link| link.enqueue(ObjectKind::WorkProbeRequest, &[n], 0))
                .unwrap()
                .unwrap();
            client
                .send(&have, Instant::now() + Duration::from_secs(5))
                .unwrap();
            assert!(
                server
                    .wait_for_frame(Instant::now() + Duration::from_secs(5))
                    .unwrap()
            );
            events.push(
                server
                    .receive(Instant::now() + Duration::from_secs(5))
                    .unwrap(),
            );
        }
        let current = events.remove(0);
        assert!(
            server
                .dispatch_received(current, |_, event| matches!(event, Event::Offered(_)))
                .unwrap()
        );
        // Both directions have the same SessionID and reservation number. The
        // registry/connection provenance still forbids swapping their events.
        let swapped = events.remove(0);
        assert!(
            client
                .dispatch_received(swapped, |_, _| panic!("foreign event dispatched"))
                .is_err()
        );
        let stale = events.remove(0);
        inbound.replace_peers(vec![]).unwrap();
        assert!(
            server
                .wait_for_frame(Instant::now() + Duration::from_secs(5))
                .is_err()
        );
        let mut dispatched = false;
        assert!(
            server
                .dispatch_received(stale, |_, _| dispatched = true)
                .is_err()
        );
        assert!(!dispatched);
        assert!(
            server
                .receive(Instant::now() + Duration::from_secs(5))
                .is_err()
        );
        assert!(inbound.begin().is_err());
        drop(server);
        drop(inbound.begin().unwrap());
        drop(client);
        drop(outbound.begin().unwrap());
        for name in [
            "send.sqlite",
            "recv.sqlite",
            "send.sqlite-wal",
            "recv.sqlite-wal",
            "send.sqlite-shm",
            "recv.sqlite-shm",
        ] {
            let p = base.join(name);
            if p.exists() {
                std::fs::remove_file(p).unwrap();
            }
        }
        std::fs::remove_dir(base).unwrap();
    }
}

#[cfg(test)]
mod g3_typed_tests {
    use super::*;
    use mutiny_crypto_v2::{HybridKey, Role};
    use mutiny_transport_v2::objects::ObjectQueue;
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn g3_guarded_transport_expiry_is_typed_and_retired_pin_is_other() {
        // Real local authenticated connection, with an exact synthetic transport
        // failure injected in the trusted action. No production lifetime override.
        let a = HybridKey::generate(Role::Transport).unwrap();
        let b = HybridKey::generate(Role::Transport).unwrap();
        let pa = Endpoint::pinned(a.public().clone(), 1).unwrap();
        let pb = Endpoint::pinned(b.public().clone(), 1).unwrap();
        let incoming = Registry::new_wallet_clients([1; 32], [2; 32], pb.clone(), vec![pa.clone()], 1, 1).unwrap();
        let outgoing = Registry::new_wallet_client([1; 32], [2; 32], pa.clone(), vec![pb.clone()], 1, 1).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let accepted = listener.accept().unwrap().0;
        drop(listener);
        let pending = incoming.begin().unwrap();
        let remote = pa.id();
        let server = std::thread::spawn(move || pending.respond(remote, accepted, &b, Duration::from_secs(30)).unwrap());
        let client = outgoing.begin().unwrap().initiate(pb.id(), socket, &a, Duration::from_secs(30)).unwrap();
        let server = server.join().unwrap();
        let dir = std::env::temp_dir().join(format!("g3-guarded-{}-{}", std::process::id(),
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()));
        std::fs::create_dir(&dir).unwrap();
        let queue = ObjectQueue::open(&dir.join("queue.sqlite"), client.peer_id()).unwrap();
        let mut client = client.attach(queue).unwrap();
        assert_eq!(client.with_current_transport::<()>(|_| Err(mutiny_transport_v2::Error::Expired)).unwrap_err(), PeerFailure::SessionExpired);
        assert!(matches!(client.with_current_transport::<()>(|_| Err(mutiny_transport_v2::Error::Limit)), Err(PeerFailure::Other(_))));
        outgoing.replace_peers(vec![]).unwrap();
        let mut called = false;
        let error = client.with_current_transport::<()>(|_| { called = true; Err(mutiny_transport_v2::Error::Expired) }).unwrap_err();
        assert!(!called, "retired admission cannot enter the transport action");
        assert!(matches!(error, PeerFailure::Other(_)), "revocation is not session expiry");
        outgoing.replace_peers(vec![pb]).unwrap();
        assert!(client.with_current_transport::<()>(|_| Ok(())).is_err(), "pin readdition cannot resurrect this session");
        client.close();
        assert!(matches!(client.wait_for_frame_typed(Instant::now() + Duration::from_millis(20)), Err(PeerFailure::Other(_))));
        drop(client); drop(server);
        assert!(outgoing.begin().is_ok());
        assert!(incoming.begin().is_ok());
        for entry in std::fs::read_dir(&dir).unwrap() { std::fs::remove_file(entry.unwrap().path()).unwrap(); }
        std::fs::remove_dir(dir).unwrap();
    }
}

#[cfg(test)]
#[path = "wallet_client_admission_tests.rs"]
mod wallet_client_admission_tests;

#[cfg(test)]
#[path = "wallet_history_admission_tests.rs"]
mod wallet_history_admission_tests;
