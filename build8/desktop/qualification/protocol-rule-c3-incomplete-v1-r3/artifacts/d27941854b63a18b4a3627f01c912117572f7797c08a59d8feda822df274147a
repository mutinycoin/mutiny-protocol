//! Bounded direct-Wi-Fi service. Socket waits never hold the node actor lock.
//! Limits are local resource policy, not consensus or Worker entitlement.
use crate::{worker_protocol, worker_transport::CoordinatorConnection};
use ed25519_dalek::SigningKey;
use mutiny_consensus_v8::{Hash, licenses::BindWorker};
use std::{
    collections::BTreeSet,
    net::{TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, String>;

/// The same actor lock must serialize this implementation with canonical commits.
pub trait WorkerBackend: Send + 'static {
    /// Derive active binding from current canonical state, including activation,
    /// assignment generation and this node's coordinator authority.
    fn active(&mut self, worker: Hash) -> Result<BindWorker>;
    /// Return a bounded signed-frame payload. Result handling must durably
    /// preserve candidate ingress BEFORE returning an observation receipt.
    fn handle(&mut self, worker: Hash, message: worker_protocol::WorkerMessage) -> Result<Vec<u8>>;
}

pub struct WorkerServer {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<()>>>,
}
impl WorkerServer {
    pub fn is_finished(&self) -> bool {
        self.thread
            .as_ref()
            .is_none_or(|thread| thread.is_finished())
    }
    /// The caller binds an explicitly configured interface/port. No implicit
    /// wildcard listener, service installation or firewall change occurs here.
    pub fn start<B: WorkerBackend>(
        listener: TcpListener,
        signer: SigningKey,
        backend: Arc<Mutex<B>>,
        maximum_connections: usize,
    ) -> Result<Self> {
        if !(1..=256).contains(&maximum_connections) {
            return Err("Worker connection limit must be 1..256".into());
        }
        listener.set_nonblocking(true).map_err(|e| e.to_string())?;
        let stop = Arc::new(AtomicBool::new(false));
        let shutdown = stop.clone();
        let thread = thread::Builder::new()
            .name("worker-listener".into())
            .spawn(move || {
                let sessions = Arc::new(Mutex::new(BTreeSet::new()));
                let mut clients: Vec<JoinHandle<()>> = Vec::new();
                let outcome = (|| {
                    while !shutdown.load(Ordering::Acquire) {
                        let mut i = 0;
                        while i < clients.len() {
                            if clients[i].is_finished() {
                                // A panicking handler loses only its connection;
                                // any poisoned actor lock subsequently fails closed.
                                let _ = clients.swap_remove(i).join();
                            } else {
                                i += 1;
                            }
                        }
                        match listener.accept() {
                            Ok((stream, _)) if clients.len() < maximum_connections => {
                                let backend = backend.clone();
                                let sessions = sessions.clone();
                                let signer = signer.clone();
                                let stop = shutdown.clone();
                                clients.push(
                                    thread::Builder::new()
                                        .name("worker-session".into())
                                        .spawn(move || {
                                            let _ = serve(stream, signer, backend, sessions, stop);
                                        })
                                        .map_err(|e| e.to_string())?,
                                );
                            }
                            Ok((stream, _)) => drop(stream), // No unbounded accepted-socket queue.
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                thread::sleep(Duration::from_millis(10));
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
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
            thread: Some(thread),
        })
    }
    pub fn stop(mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        self.thread
            .take()
            .ok_or("Worker listener already joined")?
            .join()
            .map_err(|_| "Worker listener panicked".to_string())?
    }
}
impl Drop for WorkerServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct SessionLease {
    worker: Hash,
    sessions: Arc<Mutex<BTreeSet<Hash>>>,
}
impl Drop for SessionLease {
    fn drop(&mut self) {
        if let Ok(mut sessions) = self.sessions.lock() {
            sessions.remove(&self.worker);
        }
    }
}
fn serve<B: WorkerBackend>(
    stream: TcpStream,
    signer: SigningKey,
    backend: Arc<Mutex<B>>,
    sessions: Arc<Mutex<BTreeSet<Hash>>>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    // Windows may inherit the listener's nonblocking mode on accepted sockets.
    // The transport uses bounded blocking I/O with a total per-frame deadline.
    stream.set_nonblocking(false).map_err(|e| e.to_string())?;
    stream.set_nodelay(true).map_err(|e| e.to_string())?;
    let active = |worker| {
        backend
            .lock()
            .map_err(|_| "Node actor poisoned")?
            .active(worker)
    };
    let mut connection = CoordinatorConnection::accept(stream, signer, active)?;
    let worker = connection.worker();
    if !sessions
        .lock()
        .map_err(|_| "Worker sessions poisoned")?
        .insert(worker)
    {
        return Err("Worker already connected".into());
    }
    let _lease = SessionLease { worker, sessions };
    let mut response = worker_protocol::heartbeat().to_vec();
    while !stop.load(Ordering::Acquire) {
        let started = Instant::now();
        let binding = active(worker)?;
        connection.send(&binding, &response)?;
        let raw = connection.receive(active)?;
        let message = worker_protocol::decode(&raw)?;
        // Throttle BEFORE preparing the next offer so its lease is computed at
        // dispatch, not a second before sending. The device also times its
        // request locally and conservatively subtracts that transport delay.
        while started.elapsed() < Duration::from_secs(1) && !stop.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(10));
        }
        if stop.load(Ordering::Acquire) {
            break;
        }
        {
            let mut actor = backend.lock().map_err(|_| "Node actor poisoned")?;
            // Close the gap between transport validation and actor dispatch.
            if actor.active(worker)? != binding {
                return Err("Worker reassigned".into());
            }
            response = actor.handle(worker, message)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worker_transport::tests::{binding, connect, receive};
    use std::io::{Read, Write};
    struct Backend {
        binding: BindWorker,
        enabled: bool,
        calls: usize,
        reject: bool,
    }
    impl WorkerBackend for Backend {
        fn active(&mut self, worker: Hash) -> Result<BindWorker> {
            if !self.enabled || worker != self.binding.worker {
                return Err("inactive".into());
            }
            Ok(self.binding.clone())
        }
        fn handle(&mut self, _: Hash, message: worker_protocol::WorkerMessage) -> Result<Vec<u8>> {
            self.calls += 1;
            if self.reject {
                return Err("durable ingress unavailable".into());
            }
            match message {
                worker_protocol::WorkerMessage::Status { .. } => Ok(vec![1]),
                worker_protocol::WorkerMessage::Request { nonce, .. } => {
                    worker_protocol::waiting_quorum(nonce)
                }
                _ => Err("fixture has no result sink".into()),
            }
        }
    }
    fn start(maximum: usize) -> (WorkerServer, std::net::SocketAddr, Arc<Mutex<Backend>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let actor = Arc::new(Mutex::new(Backend {
            binding: binding(),
            enabled: true,
            calls: 0,
            reject: false,
        }));
        let server = WorkerServer::start(
            listener,
            SigningKey::from_bytes(&[90; 32]),
            actor.clone(),
            maximum,
        )
        .unwrap();
        (server, addr, actor)
    }
    fn closed(stream: &mut TcpStream) {
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        match stream.read(&mut [0; 1]) {
            Ok(0) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionAborted
                ) => {}
            other => panic!("expected closed connection: {other:?}"),
        }
    }
    #[test]
    fn bounded_listener_dispatch_duplicate_session_revocation_and_ingress_failure() {
        let (server, addr, actor) = start(2);
        let (mut first, mut channel) = connect(addr, &binding());
        assert_eq!(receive(&mut first, &mut channel), [1]);
        let (mut duplicate, _) = connect(addr, &binding());
        closed(&mut duplicate);
        assert_eq!(actor.lock().unwrap().calls, 0);
        let mut request = vec![5];
        request.extend([42; 32]);
        request.extend([0; 40]);
        first
            .write_all(
                &channel
                    .send(&SigningKey::from_bytes(&[10; 32]), &request)
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(
            receive(&mut first, &mut channel),
            worker_protocol::waiting_quorum([42; 32]).unwrap()
        );
        assert_eq!(actor.lock().unwrap().calls, 1);
        actor.lock().unwrap().enabled = false;
        let status = [2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5];
        first
            .write_all(
                &channel
                    .send(&SigningKey::from_bytes(&[10; 32]), &status)
                    .unwrap(),
            )
            .unwrap();
        closed(&mut first);
        assert_eq!(actor.lock().unwrap().calls, 1);
        server.stop().unwrap();

        let (server, addr, actor) = start(1);
        let (mut first, mut channel) = connect(addr, &binding());
        assert_eq!(receive(&mut first, &mut channel), [1]);
        // Even an unauthenticated socket cannot exceed the configured cap.
        let mut overflow = TcpStream::connect(addr).unwrap();
        closed(&mut overflow);
        actor.lock().unwrap().reject = true;
        first
            .write_all(
                &channel
                    .send(&SigningKey::from_bytes(&[10; 32]), &request)
                    .unwrap(),
            )
            .unwrap();
        closed(&mut first); // No response or receipt after failed actor dispatch.
        assert_eq!(actor.lock().unwrap().calls, 1);
        server.stop().unwrap();
    }
}
