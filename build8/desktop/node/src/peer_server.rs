//! Bounded authenticated P2P listener. Network waits never own the node actor.
use crate::{deadline_io::DeadlineIo, peer::Session};
use ed25519_dalek::SigningKey;
use mutiny_consensus_v8::Hash;
use std::{
    collections::BTreeSet,
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::Duration,
};
type Result<T> = std::result::Result<T, String>;
const IO_DEADLINE: Duration = Duration::from_secs(15);
pub struct PeerReply {
    pub payload: Vec<u8>,
    pub close: bool,
}
pub trait PeerBackend: Send + 'static {
    fn context(&self) -> (Hash, Hash);
    fn handle(&mut self, peer: Hash, request: &[u8]) -> Result<PeerReply>;
}
pub struct PeerServer {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<()>>>,
    allowed: Arc<Mutex<BTreeSet<Hash>>>,
    local: Hash,
}
fn pins(peers: &[Hash], local: Hash) -> Result<BTreeSet<Hash>> {
    if peers.is_empty() || peers.len() > 1024 || peers.contains(&local) {
        return Err("Peer pin bounds/reflection".into());
    }
    let set: BTreeSet<_> = peers.iter().copied().collect();
    if set.len() != peers.len() {
        return Err("Duplicate peer pin".into());
    }
    Ok(set)
}
impl PeerServer {
    pub fn is_finished(&self) -> bool {
        self.thread
            .as_ref()
            .is_none_or(|thread| thread.is_finished())
    }
    pub fn start<B: PeerBackend>(
        listener: TcpListener,
        key: SigningKey,
        peers: &[Hash],
        backend: Arc<Mutex<B>>,
        maximum_connections: usize,
    ) -> Result<Self> {
        if !(1..=32).contains(&maximum_connections) {
            return Err("Peer connection limit must be 1..32".into());
        }
        let local = key.verifying_key().to_bytes();
        let allowed = Arc::new(Mutex::new(pins(peers, local)?));
        let context = backend.lock().map_err(|_| "Actor poisoned")?.context();
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = stop.clone();
        let configured = allowed.clone();
        let worker = thread::Builder::new()
            .name("peer-listener".into())
            .spawn(move || {
                let sessions = Arc::new(Mutex::new(BTreeSet::new()));
                let mut clients: Vec<JoinHandle<()>> = Vec::new();
                let outcome = (|| {
                    while !shutdown.load(Ordering::Acquire) {
                        let mut i = 0;
                        while i < clients.len() {
                            if clients[i].is_finished() {
                                let _ = clients.swap_remove(i).join();
                            } else {
                                i += 1;
                            }
                        }
                        match listener.accept() {
                            Ok((stream, _)) if clients.len() < maximum_connections => {
                                let backend = backend.clone();
                                let key = key.clone();
                                let allowed = configured.clone();
                                let sessions = sessions.clone();
                                let stop = shutdown.clone();
                                clients.push(
                                    thread::Builder::new()
                                        .name("peer-session".into())
                                        .spawn(move || {
                                            let _ = serve(
                                                stream, key, context, allowed, sessions, backend,
                                                stop,
                                            );
                                        })
                                        .map_err(|e| e.to_string())?,
                                );
                            }
                            Ok((stream, _)) => drop(stream),
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(10))
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
                            Err(e) => return Err(e.to_string()),
                        }
                    }
                    Ok(())
                })();
                shutdown.store(true, Ordering::Release);
                for client in clients {
                    let _ = client.join();
                }
                outcome
            })
            .map_err(|e| e.to_string())?;
        Ok(Self {
            stop,
            thread: Some(worker),
            allowed,
            local,
        })
    }
    /// Administrative pin changes are not Continuity membership changes.
    /// Existing sessions recheck this set before every actor dispatch.
    pub fn set_peers(&self, peers: &[Hash]) -> Result<()> {
        let next = pins(peers, self.local)?;
        *self.allowed.lock().map_err(|_| "Peer pins poisoned")? = next;
        Ok(())
    }
    pub fn stop(mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        self.thread
            .take()
            .ok_or("Listener already joined")?
            .join()
            .map_err(|_| "Peer listener panicked")?
    }
}
impl Drop for PeerServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.thread.take() {
            let _ = worker.join();
        }
    }
}
struct Lease {
    peer: Hash,
    sessions: Arc<Mutex<BTreeSet<Hash>>>,
}
impl Drop for Lease {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(&self.peer);
        }
    }
}
fn serve<B: PeerBackend>(
    mut stream: TcpStream,
    key: SigningKey,
    context: (Hash, Hash),
    allowed: Arc<Mutex<BTreeSet<Hash>>>,
    sessions: Arc<Mutex<BTreeSet<Hash>>>,
    backend: Arc<Mutex<B>>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    stream.set_nonblocking(false).map_err(|e| e.to_string())?;
    stream.set_nodelay(true).map_err(|e| e.to_string())?;
    let peers: Vec<_> = allowed
        .lock()
        .map_err(|_| "Peer pins poisoned")?
        .iter()
        .copied()
        .collect();
    let (mut session, peer) = Session::handshake_pinned(
        &mut DeadlineIo::new(&mut stream, IO_DEADLINE).map_err(|e| e.to_string())?,
        key,
        &peers,
        context.0,
        context.1,
        false,
    )?;
    if !sessions
        .lock()
        .map_err(|_| "Peer sessions poisoned")?
        .insert(peer)
    {
        return Err("Duplicate authenticated peer session".into());
    }
    let _lease = Lease { peer, sessions };
    for _ in 0..4096 {
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        let request = session
            .receive(&mut DeadlineIo::new(&mut stream, IO_DEADLINE).map_err(|e| e.to_string())?)?;
        let response = {
            let mut actor = backend.lock().map_err(|_| "Actor poisoned")?;
            // Serialize pin revocation against dispatch, including requests that
            // waited for a busy actor. No network wait holds either mutex.
            let configured = allowed.lock().map_err(|_| "Peer pins poisoned")?;
            if !configured.contains(&peer) {
                return Err("Peer pin revoked".into());
            }
            if actor.context() != context {
                return Err("Peer chain context changed".into());
            }
            actor.handle(peer, &request)?
        };
        session.send(
            &mut DeadlineIo::new(&mut stream, IO_DEADLINE).map_err(|e| e.to_string())?,
            &response.payload,
        )?;
        if response.close {
            return Ok(());
        }
    }
    Err("Peer session request bound".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    struct Echo {
        calls: usize,
    }
    impl PeerBackend for Echo {
        fn context(&self) -> (Hash, Hash) {
            ([1; 32], [2; 32])
        }
        fn handle(&mut self, _: Hash, request: &[u8]) -> Result<PeerReply> {
            self.calls += 1;
            Ok(PeerReply {
                payload: request.to_vec(),
                close: request == b"close",
            })
        }
    }
    #[test]
    fn authenticated_listener_duplicate_revocation_and_unlocked_network_waits() {
        let key = SigningKey::from_bytes(&[21; 32]);
        let client = SigningKey::from_bytes(&[22; 32]);
        let other = SigningKey::from_bytes(&[23; 32]);
        let public = key.verifying_key().to_bytes();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let backend = Arc::new(Mutex::new(Echo { calls: 0 }));
        let server = PeerServer::start(
            listener,
            key,
            &[
                client.verifying_key().to_bytes(),
                other.verifying_key().to_bytes(),
            ],
            backend.clone(),
            4,
        )
        .unwrap();
        let connect = |key: SigningKey| {
            let mut stream = TcpStream::connect(address).unwrap();
            let session = Session::handshake(
                &mut DeadlineIo::new(&mut stream, Duration::from_secs(2)).unwrap(),
                key,
                public,
                [1; 32],
                [2; 32],
                true,
            )
            .unwrap();
            (stream, session)
        };
        let (mut stream, mut session) = connect(client.clone());
        session.send(&mut stream, b"first").unwrap();
        assert_eq!(session.receive(&mut stream).unwrap(), b"first");
        assert!(backend.try_lock().is_ok());
        let (mut duplicate, mut duplicate_session) = connect(client.clone());
        let _ = duplicate_session.send(&mut duplicate, b"duplicate");
        assert!(duplicate_session.receive(&mut duplicate).is_err());
        drop(duplicate);
        assert_eq!(backend.lock().unwrap().calls, 1);
        let (mut second, mut second_session) = connect(other.clone());
        second_session.send(&mut second, b"other").unwrap();
        assert_eq!(second_session.receive(&mut second).unwrap(), b"other");
        server
            .set_peers(&[other.verifying_key().to_bytes()])
            .unwrap();
        session.send(&mut stream, b"revoked").unwrap();
        assert!(session.receive(&mut stream).is_err());
        assert_eq!(backend.lock().unwrap().calls, 2);
        drop(stream);
        second_session.send(&mut second, b"close").unwrap();
        assert_eq!(second_session.receive(&mut second).unwrap(), b"close");
        assert!(second_session.receive(&mut second).is_err());
        drop(second);
        server.stop().unwrap();
    }
}
