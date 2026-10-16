//! Bounded admission for a listener configured for one explicitly pinned peer.
//! No discovery, wire selector, key provisioning or production socket creation.
use crate::hybrid_peer_admission_v2::{Connection, Pending, Registry};
use mutiny_consensus_v8::Hash;
use mutiny_crypto_v2::HybridKey;
use std::{
    net::{TcpListener, TcpStream},
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, String>;
pub struct Listener {
    socket: TcpListener,
    registry: Registry,
    peer: Hash,
    budget: Duration,
}
/// Socket drops before its lease. Queueing consumes the same handshake budget
/// as crypto and I/O; callers cannot reset it by delaying worker dispatch.
pub struct Accepted {
    socket: TcpStream,
    pending: Pending,
    peer: Hash,
    deadline: Instant,
}
impl Listener {
    /// Caller transfers exclusive ownership of an already-bound socket. This
    /// dedicated listener expects the configured peer; its IP grants no trust.
    /// Every connection must still prove the complete pinned hybrid context.
    pub fn new(
        socket: TcpListener,
        registry: Registry,
        peer: Hash,
        budget: Duration,
    ) -> Result<Self> {
        if budget.is_zero() || budget > Duration::from_secs(30) {
            return Err("Peer listener handshake budget".into());
        }
        // Public configuration check only; no attempt or private signing.
        registry.begin()?.context(peer)?;
        socket
            .set_nonblocking(true)
            .map_err(|e| format!("Peer listener mode: {e}"))?;
        Ok(Self {
            socket,
            registry,
            peer,
            budget,
        })
    }
    /// Nonblocking accept, with a shared capacity lease acquired first. No
    /// private operation or unbounded thread/queue is created here. A caller
    /// must drop rejected Accepted values and service at most its leased count.
    pub fn poll(&mut self) -> Result<Option<Accepted>> {
        let pending = self.registry.begin()?;
        match self.socket.accept() {
            Ok((socket, _)) => Ok(Some(Accepted {
                socket,
                pending,
                peer: self.peer,
                deadline: Instant::now()
                    .checked_add(self.budget)
                    .ok_or("Peer listener deadline overflow")?,
            })),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(e) => Err(format!("Peer listener accept: {e}")),
        }
    }
}
impl Accepted {
    pub fn respond(self, key: &HybridKey) -> Result<Connection> {
        if Instant::now() >= self.deadline {
            return Err("Queued peer handshake expired".into());
        }
        self.pending
            .respond_until(self.peer, self.socket, key, self.deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mutiny_crypto_v2::Role;
    use mutiny_transport_v2::Endpoint;
    #[test]
    fn hybrid_listener_bounds_queue_expiry_and_rechecks_revoked_pins() {
        let local = HybridKey::generate(Role::Transport).unwrap();
        let peer = HybridKey::generate(Role::Transport).unwrap();
        let a = Endpoint::pinned(local.public().clone(), 1).unwrap();
        let b = Endpoint::pinned(peer.public().clone(), 1).unwrap();
        let registry = Registry::new([1; 32], [2; 32], a, vec![b.clone()], 1, 1).unwrap();
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        let mut listener =
            Listener::new(socket, registry.clone(), b.id(), Duration::from_secs(30)).unwrap();
        assert!(listener.poll().unwrap().is_none());
        let client = TcpStream::connect(addr).unwrap();
        let mut accepted = listener.poll().unwrap().unwrap();
        assert!(registry.begin().is_err());
        assert!(listener.poll().is_err());
        accepted.deadline = Instant::now() - Duration::from_secs(1);
        assert!(accepted.respond(&local).is_err());
        drop(registry.begin().unwrap());
        drop(client);
        let client = TcpStream::connect(addr).unwrap();
        let accepted = listener.poll().unwrap().unwrap();
        registry.replace_peers(vec![]).unwrap();
        // Reject before waiting for a hello or doing private handshake work.
        assert!(accepted.respond(&local).is_err());
        drop(registry.begin().unwrap());
        drop(client);
        let socket = TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(Listener::new(socket, registry, b.id(), Duration::ZERO).is_err());
    }
}
