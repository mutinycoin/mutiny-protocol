//! Continuous bounded peer exchange. Network failures only trigger reconnect;
//! they cannot change canonical weights, TPM custody, RUN intent or finality.
use crate::{
    peer_client::PeerClient,
    peer_gossip::{GossipCursor, exchange},
    peer_server::PeerBackend,
};
use ed25519_dalek::SigningKey;
use mutiny_consensus_v8::Hash;
use std::{
    collections::BTreeSet,
    net::{Shutdown, SocketAddr, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, String>;
#[derive(Clone)]
pub struct PeerTarget {
    pub address: SocketAddr,
    pub public: Hash,
}
#[derive(Clone, Default, Debug)]
pub struct PeerProgress {
    pub connected: bool,
    pub completed_exchanges: u64,
    pub connection_attempts: u64,
    pub last_error: Option<String>,
}
pub struct PeerSupervisor {
    stop: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
    progress: Vec<(Hash, Arc<Mutex<PeerProgress>>)>,
    sockets: Vec<Arc<Mutex<Option<TcpStream>>>>,
}
fn delay(stop: &AtomicBool, duration: Duration) {
    let until = Instant::now() + duration;
    while !stop.load(Ordering::Acquire) {
        let Some(left) = until.checked_duration_since(Instant::now()) else {
            break;
        };
        thread::sleep(left.min(Duration::from_millis(100)));
    }
}
impl PeerSupervisor {
    pub fn start<B: PeerBackend>(
        key: SigningKey,
        targets: Vec<PeerTarget>,
        actor: Arc<Mutex<B>>,
    ) -> Result<Self> {
        if targets.is_empty() || targets.len() > 32 {
            return Err("Peer supervisor requires 1..32 configured peers".into());
        }
        let mut unique = BTreeSet::new();
        for peer in &targets {
            if peer.public == key.verifying_key().to_bytes() || !unique.insert(peer.public) {
                return Err("Duplicate/reflected peer target".into());
            }
        }
        let context = actor.lock().map_err(|_| "Actor poisoned")?.context();
        let stop = Arc::new(AtomicBool::new(false));
        let mut service = Self {
            stop: stop.clone(),
            workers: Vec::new(),
            progress: Vec::new(),
            sockets: Vec::new(),
        };
        for peer in targets {
            let socket = Arc::new(Mutex::new(None::<TcpStream>));
            service.sockets.push(socket.clone());
            let key = key.clone();
            let actor = actor.clone();
            let stop = stop.clone();
            let status = Arc::new(Mutex::new(PeerProgress::default()));
            service.progress.push((peer.public, status.clone()));
            service.workers.push(
                thread::Builder::new()
                    .name("peer-exchange".into())
                    .spawn(move || {
                        let mut cursor = GossipCursor::default();
                        let mut failures = 0u32;
                        while !stop.load(Ordering::Acquire) {
                            if let Ok(mut state) = status.lock() {
                                state.connection_attempts =
                                    state.connection_attempts.saturating_add(1);
                            }
                            let result = (|| -> Result<()> {
                                let mut client = PeerClient::connect(
                                    peer.address,
                                    key.clone(),
                                    peer.public,
                                    context.0,
                                    context.1,
                                )?;
                                *socket.lock().map_err(|_| "Peer socket control poisoned")? =
                                    Some(client.interrupt_handle()?);
                                if let Ok(mut state) = status.lock() {
                                    state.connected = true;
                                }
                                while !stop.load(Ordering::Acquire) {
                                    if actor.lock().map_err(|_| "Actor poisoned")?.context()
                                        != context
                                    {
                                        return Err("Local chain context changed".into());
                                    }
                                    exchange(&mut client, &actor, peer.public, &mut cursor)?;
                                    failures = 0;
                                    if let Ok(mut state) = status.lock() {
                                        state.completed_exchanges =
                                            state.completed_exchanges.saturating_add(1);
                                        state.last_error = None;
                                    }
                                    delay(&stop, Duration::from_millis(250));
                                }
                                Ok(())
                            })();
                            if let Ok(mut current) = socket.lock() {
                                current.take();
                            }
                            if let Ok(mut state) = status.lock() {
                                state.connected = false;
                                if let Err(error) = result {
                                    state.last_error = Some(error.chars().take(1024).collect());
                                }
                            }
                            failures = failures.saturating_add(1);
                            let backoff = Duration::from_millis(
                                500u64.saturating_mul(1u64 << failures.min(6)).min(30_000),
                            );
                            delay(&stop, backoff);
                        }
                    })
                    .map_err(|e| e.to_string())?,
            );
        }
        Ok(service)
    }
    pub fn progress(&self) -> Result<Vec<(Hash, PeerProgress)>> {
        self.progress
            .iter()
            .map(|(key, state)| {
                Ok((
                    *key,
                    state.lock().map_err(|_| "Peer progress poisoned")?.clone(),
                ))
            })
            .collect()
    }
    pub fn stop(mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        for socket in &self.sockets {
            if let Ok(current) = socket.lock() {
                if let Some(stream) = current.as_ref() {
                    let _ = stream.shutdown(Shutdown::Both);
                }
            }
        }
        let mut failed = false;
        for worker in self.workers.drain(..) {
            failed |= worker.join().is_err();
        }
        if failed {
            Err("Peer worker panicked".into())
        } else {
            Ok(())
        }
    }
}
impl Drop for PeerSupervisor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        for socket in &self.sockets {
            if let Ok(current) = socket.lock() {
                if let Some(stream) = current.as_ref() {
                    let _ = stream.shutdown(Shutdown::Both);
                }
            }
        }
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}
