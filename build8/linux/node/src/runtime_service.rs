//! Process-owned services sharing one canonical actor. Constructing this owner
//! does not establish Genesis trust or initialize protected voter custody.
use crate::{
    actor_service::ActorService,
    integrated_actor::{ActorTick, IntegratedActor},
    peer_server::PeerServer,
    peer_supervisor::{PeerProgress, PeerSupervisor, PeerTarget},
    worker_coordinator::BodyBuilder,
    worker_server::WorkerServer,
};
use ed25519_dalek::SigningKey;
use mutiny_consensus_v8::{
    Hash, counter_voter::CounterSigningBackend, freshness::PhysicalAttestationVerifier,
};
use std::{
    collections::BTreeSet,
    net::{SocketAddr, TcpListener},
    sync::{Arc, Mutex, mpsc::TryRecvError},
};
type Result<T> = std::result::Result<T, String>;

pub struct NetworkConfig {
    pub worker_bind: SocketAddr,
    pub peer_bind: SocketAddr,
    pub worker_connections: usize,
    pub peer_connections: usize,
    pub allowed_peers: Vec<Hash>,
    pub outbound: Vec<PeerTarget>,
}
impl NetworkConfig {
    pub fn validate(&self, local: Hash) -> Result<()> {
        if !(1..=256).contains(&self.worker_connections)
            || !(1..=32).contains(&self.peer_connections)
            || self.allowed_peers.is_empty()
            || self.allowed_peers.len() > 1024
            || self.outbound.len() > 32
        {
            return Err("Runtime network bounds".into());
        }
        let pins: BTreeSet<_> = self.allowed_peers.iter().copied().collect();
        if pins.len() != self.allowed_peers.len() || pins.contains(&local) {
            return Err("Runtime duplicate/reflected peer pin".into());
        }
        let mut targets = BTreeSet::new();
        for target in &self.outbound {
            if !pins.contains(&target.public)
                || !targets.insert(target.public)
                || target.address.port() == 0
                || target.address.ip().is_unspecified()
            {
                return Err("Runtime outbound peer configuration".into());
            }
        }
        Ok(())
    }
}
pub struct RuntimeService {
    actor: Option<ActorService>,
    peers: Option<PeerSupervisor>,
    worker_listener: Option<WorkerServer>,
    peer_listener: Option<PeerServer>,
    pub worker_address: SocketAddr,
    pub peer_address: SocketAddr,
}
impl RuntimeService {
    pub fn start<V, H, B>(
        config: NetworkConfig,
        worker_key: SigningKey,
        peer_key: SigningKey,
        actor: Arc<Mutex<IntegratedActor<V, H, B>>>,
    ) -> Result<Self>
    where
        V: PhysicalAttestationVerifier + Send + 'static,
        H: BodyBuilder,
        B: CounterSigningBackend
            + crate::participation_producer::ParticipationSigner
            + Send
            + 'static,
    {
        config.validate(peer_key.verifying_key().to_bytes())?;
        if actor
            .lock()
            .map_err(|_| "Actor poisoned")?
            .workers
            .coordinator_public()
            != worker_key.verifying_key().to_bytes()
        {
            return Err("Runtime Worker signer differs from coordinator authority".into());
        }
        // Bind both before any actor tick or outgoing connection. Every later
        // error drops this owner, joining already-started services.
        let worker = TcpListener::bind(config.worker_bind).map_err(|e| e.to_string())?;
        let peer = TcpListener::bind(config.peer_bind).map_err(|e| e.to_string())?;
        let mut runtime = Self {
            actor: None,
            peers: None,
            worker_listener: None,
            peer_listener: None,
            worker_address: worker.local_addr().map_err(|e| e.to_string())?,
            peer_address: peer.local_addr().map_err(|e| e.to_string())?,
        };
        runtime.worker_listener = Some(WorkerServer::start(
            worker,
            worker_key,
            actor.clone(),
            config.worker_connections,
        )?);
        runtime.peer_listener = Some(PeerServer::start(
            peer,
            peer_key.clone(),
            &config.allowed_peers,
            actor.clone(),
            config.peer_connections,
        )?);
        if !config.outbound.is_empty() {
            runtime.peers = Some(PeerSupervisor::start(
                peer_key,
                config.outbound,
                actor.clone(),
            )?);
        }
        runtime.actor = Some(ActorService::start(actor)?);
        Ok(runtime)
    }
    /// Drain on each process-loop iteration. Messages are notifications: peer
    /// exchange obtains the already-durable proposals/votes from the actor.
    pub fn poll(&self) -> Result<Option<ActorTick>> {
        if self
            .worker_listener
            .as_ref()
            .is_some_and(WorkerServer::is_finished)
            || self
                .peer_listener
                .as_ref()
                .is_some_and(PeerServer::is_finished)
        {
            return Err("Runtime listener exited".into());
        }
        match self
            .actor
            .as_ref()
            .ok_or("Runtime stopped")?
            .output
            .try_recv()
        {
            Ok(result) => result.map(Some),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err("Canonical actor exited".into()),
        }
    }
    pub fn peer_progress(&self) -> Result<Vec<(Hash, PeerProgress)>> {
        self.peers
            .as_ref()
            .map_or(Ok(Vec::new()), PeerSupervisor::progress)
    }
    fn shutdown(&mut self) -> Result<()> {
        let mut errors = Vec::new();
        // Stop signing first; incoming requests never sign. Then stop exchange
        // and both listeners, retaining errors while joining every service.
        if let Some(actor) = self.actor.take() {
            if let Err(e) = actor.stop() {
                errors.push(e);
            }
        }
        if let Some(peers) = self.peers.take() {
            if let Err(e) = peers.stop() {
                errors.push(e);
            }
        }
        if let Some(listener) = self.worker_listener.take() {
            if let Err(e) = listener.stop() {
                errors.push(e);
            }
        }
        if let Some(listener) = self.peer_listener.take() {
            if let Err(e) = listener.stop() {
                errors.push(e);
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }
    pub fn stop(mut self) -> Result<()> {
        self.shutdown()
    }
}
impl Drop for RuntimeService {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}
