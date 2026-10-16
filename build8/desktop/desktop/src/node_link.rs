//! The wallet's authenticated connection to one node (target B). The node is named by an IP literal
//! and its transport descriptor, both from explicit configuration; there is no discovery, no DNS
//! lookup and no unauthenticated fallback. The connection is the V2 pinned handshake of
//! `hybrid_peer_admission_v2` bound to the verified chain's Genesis and rule fingerprint, so a node of
//! another chain or with another key is refused before any object moves. A connected node is a
//! transport only: nothing it sends is believed until the wallet's own canonical replay accepts it.
use crate::wallet_controller_v2::host::WalletPeer;
use mutiny_consensus_v8::Hash;
use mutiny_crypto_v2::{HybridKey, PublicKey};
use mutiny_transport_v2::{Endpoint, objects::ObjectQueue};
use mutinyd_v8::hybrid_peer_admission_v2::Registry;
use std::{net::SocketAddr, path::Path, time::Duration};

type Result<T> = std::result::Result<T, String>;
const MAX_DESCRIPTOR_HEX: usize = 16 * 1024;

/// One configured node: where it listens and the transport key it must prove.
#[derive(Clone)]
pub(crate) struct NodeAddress {
    pub socket: SocketAddr,
    pub node: Endpoint,
}

/// `address` is an IP literal with a port (`192.0.2.7:9735`, `[2001:db8::7]:9735`); `descriptor` is
/// the node's transport descriptor in hex, obtained through trusted provisioning.
pub(crate) fn parse_node(address: &str, descriptor: &str) -> Result<NodeAddress> {
    let socket: SocketAddr = address
        .parse()
        .map_err(|_| "Node address must be an IP address and port; names are not resolved")?;
    if socket.port() == 0 || socket.ip().is_unspecified() || socket.ip().is_multicast() {
        return Err("Node address is not a connectable unicast address".into());
    }
    if descriptor.len() > MAX_DESCRIPTOR_HEX {
        return Err("Node transport descriptor exceeds its bound".into());
    }
    let raw = hex::decode(descriptor).map_err(|_| "Node transport descriptor is not hex")?;
    let (key, generation) = PublicKey::decode_descriptor(&raw)
        .map_err(|_| "Node transport descriptor is invalid")?;
    let node = Endpoint::pinned(key, generation)
        .map_err(|_| "Node descriptor is not a transport key")?;
    Ok(NodeAddress { socket, node })
}

/// An open, authenticated connection. The registry holds the pins the connection is checked
/// against on every turn, so it lives exactly as long as the peer.
pub(crate) struct NodeConnection {
    pub peer: WalletPeer,
    _registry: Registry,
}
impl NodeConnection {
    /// The peer and the registry whose pins it is checked against; the caller keeps the registry alive
    /// for as long as the peer is used (for example after handing the peer to the wallet Service).
    pub(crate) fn into_parts(self) -> (WalletPeer, Registry) {
        (self.peer, self._registry)
    }
}

/// Connect to `node` for the chain `(genesis, fingerprint)` as the transport identity `own`, with the
/// durable object queue at `queue`. Every failure is a genuine disconnected state for the caller.
pub(crate) fn connect(
    genesis: Hash,
    fingerprint: Hash,
    own: &HybridKey,
    node: &NodeAddress,
    queue: &Path,
    budget: Duration,
) -> Result<NodeConnection> {
    connect_with(Profile::WalletClient, genesis, fingerprint, own, node, queue, budget)
}

/// Which explicitly provisioned wallet-side purpose a connection uses. Chosen locally, never on the
/// wire; an older node without the history purpose refuses the handshake rather than falling back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Profile {
    /// G2 wallet client: node-to-wallet history kinds, generic history path.
    WalletClient,
    /// B1 automatic history (`Registry::new_wallet_history_client`) on its own V9 history queue file.
    /// A queue file of another schema is refused, never migrated.
    History,
}

pub(crate) fn connect_with(
    profile: Profile,
    genesis: Hash,
    fingerprint: Hash,
    own: &HybridKey,
    node: &NodeAddress,
    queue: &Path,
    budget: Duration,
) -> Result<NodeConnection> {
    let local = Endpoint::pinned(own.public().clone(), 1)
        .map_err(|_| "Wallet transport key is not a transport key")?;
    if local.id() == node.node.id() {
        return Err("The node key is this wallet's own transport key".into());
    }
    // The wallet-side mirror of the node's wallet-client admission (G2): only node-to-wallet history
    // kinds are accepted from this peer. The generic `Registry::new` would not enforce that.
    let registry = match profile {
        Profile::WalletClient => {
            Registry::new_wallet_client(genesis, fingerprint, local, vec![node.node.clone()], 1, 1)?
        }
        Profile::History => {
            Registry::new_wallet_history_client(genesis, fingerprint, local, vec![node.node.clone()], 1, 1)?
        }
    };
    let pending = registry.begin()?;
    let stream = std::net::TcpStream::connect_timeout(&node.socket, budget)
        .map_err(|e| format!("Node unreachable at {}: {e}", node.socket))?;
    stream
        .set_nodelay(true)
        .map_err(|e| format!("Node socket: {e}"))?;
    let connection = pending
        .initiate(node.node.id(), stream, own, budget)
        .map_err(|e| format!("Node authentication refused: {e}"))?;
    let queue = match profile {
        Profile::WalletClient => ObjectQueue::open(queue, connection.peer_id()),
        // Initialize only a file that does not exist yet; an existing file must already be V9.
        Profile::History => ObjectQueue::open_history(queue, connection.peer_id(), false, !queue.exists()),
    }
    .map_err(|e| format!("Wallet transport queue: {e:?}"))?;
    Ok(NodeConnection {
        peer: WalletPeer::new(connection.attach(queue)?),
        _registry: registry,
    })
}

/// What the wallet knows about its node connection, for the shell to show. A lost connection keeps the
/// transport's own reason; the durable queue file is kept, so a reconnect (a fresh handshake, hence fresh
/// session keys) resumes any incomplete object transfer. There is no automatic retry: the transport
/// specifies no retry interval, so a reconnect happens only when the person asks for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LinkState {
    NotConnected,
    Connected { since: std::time::Instant },
    Lost { reason: String },
    /// The transport's own session lifetime ended (typed, G3). Shown as such; a new session is a
    /// fresh handshake on request only, and retained queue bytes still need a fresh offer.
    Expired,
}

/// One configured node and the wallet's durable queue for it, across sessions.
pub(crate) struct NodeSession {
    profile: Profile,
    genesis: Hash,
    fingerprint: Hash,
    node: NodeAddress,
    queue: std::path::PathBuf,
    state: LinkState,
}
impl NodeSession {
    pub(crate) fn new(genesis: Hash, fingerprint: Hash, node: NodeAddress, queue: std::path::PathBuf) -> Self {
        Self { profile: Profile::WalletClient, genesis, fingerprint, node, queue, state: LinkState::NotConnected }
    }
    /// A B1 automatic-history session; `queue` is its own V9 history queue file.
    pub(crate) fn history(genesis: Hash, fingerprint: Hash, node: NodeAddress, queue: std::path::PathBuf) -> Self {
        Self { profile: Profile::History, genesis, fingerprint, node, queue, state: LinkState::NotConnected }
    }
    pub(crate) fn profile(&self) -> Profile {
        self.profile
    }
    pub(crate) fn state(&self) -> &LinkState {
        &self.state
    }
    /// A fresh authenticated session on the same durable queue. The returned peer goes to the wallet
    /// service (`Command::Attach`); a failure is recorded as the lost state with its reason.
    pub(crate) fn connect(&mut self, own: &HybridKey, budget: Duration) -> Result<NodeConnection> {
        match connect_with(self.profile, self.genesis, self.fingerprint, own, &self.node, &self.queue, budget) {
            Ok(connection) => {
                self.state = LinkState::Connected { since: std::time::Instant::now() };
                Ok(connection)
            }
            Err(reason) => {
                self.state = LinkState::Lost { reason: reason.clone() };
                Err(reason)
            }
        }
    }
    /// The link was closed or detached for a reason given as text (never parsed for expiry).
    pub(crate) fn lost(&mut self, reason: impl Into<String>) {
        self.state = LinkState::Lost { reason: reason.into() };
    }
    /// A typed link failure: the transport's expiry becomes `Expired`; anything else is `Lost`.
    pub(crate) fn failed(&mut self, failure: crate::wallet_controller_v2::host::PeerFailure) {
        use crate::wallet_controller_v2::host::PeerFailure;
        self.state = match failure {
            PeerFailure::SessionExpired => LinkState::Expired,
            PeerFailure::Other(reason) => LinkState::Lost { reason },
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::TestDir;
    use mutiny_crypto_v2::Role;
    use std::net::TcpListener;

    const GENESIS: Hash = [7; 32];
    const RULES: Hash = [9; 32];

    fn descriptor(key: &HybridKey) -> String {
        hex::encode(key.public().descriptor(1).unwrap())
    }

    /// A real responder on loopback that pins exactly `wallet` and proves `node_key`.
    fn responder(
        node_key: HybridKey,
        wallet: Endpoint,
        genesis: Hash,
    ) -> (SocketAddr, std::thread::JoinHandle<Result<Hash>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let node = Endpoint::pinned(node_key.public().clone(), 1).unwrap();
        let thread = std::thread::spawn(move || {
            let registry = Registry::new_wallet_clients(genesis, RULES, node, vec![wallet.clone()], 1, 1)?;
            let (stream, _) = listener.accept().map_err(|e| e.to_string())?;
            let connection =
                registry
                    .begin()?
                    .respond(wallet.id(), stream, &node_key, Duration::from_secs(30))?;
            Ok(connection.peer_id())
        });
        (address, thread)
    }

    #[test]
    fn node_addresses_are_ip_literals_with_a_valid_transport_descriptor() {
        let key = HybridKey::generate(Role::Transport).unwrap();
        let good = descriptor(&key);
        let node = parse_node("127.0.0.1:9735", &good).unwrap();
        assert_eq!(node.socket.port(), 9735);
        for (address, descriptor) in [
            ("localhost:9735", good.as_str()),
            ("127.0.0.1", good.as_str()),
            ("127.0.0.1:0", good.as_str()),
            ("0.0.0.0:9735", good.as_str()),
            ("127.0.0.1:9735", "zz"),
            ("127.0.0.1:9735", "00"),
        ] {
            assert!(parse_node(address, descriptor).is_err(), "{address} {descriptor}");
        }
        // A wallet-owner key is not a transport key.
        let owner = HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner)
            .unwrap();
        assert!(parse_node("127.0.0.1:9735", &descriptor(&owner)).is_err());
    }

    #[test]
    fn connects_to_the_pinned_node_and_refuses_another_key_or_chain() {
        let base = TestDir::new("node-link");
        let own = HybridKey::generate(Role::Transport).unwrap();
        let wallet = Endpoint::pinned(own.public().clone(), 1).unwrap();
        let node_key = HybridKey::generate(Role::Transport).unwrap();
        let node_descriptor = descriptor(&node_key);

        // The pinned node on the same chain: authenticated, queue attached.
        let (address, thread) = responder(node_key, wallet.clone(), GENESIS);
        let node = parse_node(&address.to_string(), &node_descriptor).unwrap();
        let connection = connect(
            GENESIS,
            RULES,
            &own,
            &node,
            &base.path().join("queue-1.sqlite"),
            Duration::from_secs(30),
        )
        .unwrap();
        assert_eq!(thread.join().unwrap().unwrap(), wallet.id());
        drop(connection);

        // A listener proving a different key than the pinned one is refused.
        let impostor = HybridKey::generate(Role::Transport).unwrap();
        let (address, thread) = responder(impostor, wallet.clone(), GENESIS);
        let node = parse_node(&address.to_string(), &node_descriptor).unwrap();
        assert!(
            connect(GENESIS, RULES, &own, &node, &base.path().join("queue-2.sqlite"), Duration::from_secs(30))
                .is_err()
        );
        let _ = thread.join();

        // The pinned node of another chain is refused.
        let other_chain_key = HybridKey::generate(Role::Transport).unwrap();
        let other_chain_descriptor = descriptor(&other_chain_key);
        let (address, thread) = responder(other_chain_key, wallet, [8; 32]);
        let node = parse_node(&address.to_string(), &other_chain_descriptor).unwrap();
        assert!(
            connect(GENESIS, RULES, &own, &node, &base.path().join("queue-3.sqlite"), Duration::from_secs(30))
                .is_err()
        );
        let _ = thread.join();
    }

    #[test]
    fn a_session_reconnects_with_fresh_handshakes_on_the_same_queue() {
        let base = TestDir::new("node-session");
        let own = HybridKey::generate(Role::Transport).unwrap();
        let wallet = Endpoint::pinned(own.public().clone(), 1).unwrap();
        let first_key = HybridKey::generate(Role::Transport).unwrap();
        let node_descriptor = descriptor(&first_key);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let node = parse_node(&address.to_string(), &node_descriptor).unwrap();
        let node_endpoint = node.node.clone();
        // One node process accepting two sessions from the same wallet.
        let server = std::thread::spawn(move || -> Result<Vec<Hash>> {
            let registry = Registry::new_wallet_clients(GENESIS, RULES, node_endpoint, vec![wallet.clone()], 1, 1)?;
            let mut seen = Vec::new();
            for _ in 0..2 {
                let (stream, _) = listener.accept().map_err(|e| e.to_string())?;
                let connection = registry.begin()?.respond(wallet.id(), stream, &first_key, Duration::from_secs(30))?;
                seen.push(connection.peer_id());
            }
            Ok(seen)
        });
        let queue = base.path().join("node-queue.sqlite");
        let mut session = NodeSession::new(GENESIS, RULES, node, queue.clone());
        assert_eq!(session.state(), &LinkState::NotConnected);
        let first = session.connect(&own, Duration::from_secs(30)).unwrap();
        assert!(matches!(session.state(), LinkState::Connected { .. }));
        drop(first);
        session.lost("Peer receive: Expired");
        assert_eq!(session.state(), &LinkState::Lost { reason: "Peer receive: Expired".into() });
        let second = session.connect(&own, Duration::from_secs(30)).unwrap();
        assert!(matches!(session.state(), LinkState::Connected { .. }));
        drop(second);
        let seen = server.join().unwrap().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0], seen[1], "the same wallet identity on both sessions");
        assert!(queue.exists(), "the durable queue survives across sessions");
    }

    /// G3 at the Desktop boundary (injected typed failures; the transport origin of `Error::Expired`
    /// is tested by the node's own tests): only the typed expiry is `Expired`; text that merely says
    /// "Expired" stays an ordinary lost link.
    #[test]
    fn only_the_typed_transport_expiry_becomes_the_expired_state() {
        use crate::wallet_controller_v2::host::PeerFailure;
        let key = HybridKey::generate(Role::Transport).unwrap();
        let node = parse_node("127.0.0.1:9", &descriptor(&key)).unwrap();
        let mut session = NodeSession::new(GENESIS, RULES, node, std::path::PathBuf::from("unused-queue"));
        session.failed(PeerFailure::SessionExpired);
        assert_eq!(session.state(), &LinkState::Expired);
        for text in ["Expired", "Peer receive: Expired", "Peer idle wait: Closed", "Peer session expired"] {
            session.failed(PeerFailure::Other(text.into()));
            assert_eq!(session.state(), &LinkState::Lost { reason: text.into() });
            session.lost(text);
            assert_eq!(session.state(), &LinkState::Lost { reason: text.into() });
        }
        // The transport's own mapping: only Error::Expired (directly or carried by TCP) is expiry.
        use mutiny_transport_v2::{Error, tcp};
        assert_eq!(PeerFailure::transport("x", Error::Expired), PeerFailure::SessionExpired);
        assert_eq!(PeerFailure::carrier("x", tcp::Error::Transport(Error::Expired)), PeerFailure::SessionExpired);
        for other in [PeerFailure::transport("x", Error::Limit), PeerFailure::transport("x", Error::Replay),
            PeerFailure::carrier("x", tcp::Error::Deadline), PeerFailure::carrier("x", tcp::Error::Closed)] {
            assert!(matches!(other, PeerFailure::Other(_)), "{other:?}");
        }
    }

    /// A history node pinning exactly `wallet`, accepting `sessions` connections in turn.
    fn history_responder(
        node_key: HybridKey,
        wallet: Endpoint,
        sessions: usize,
    ) -> (SocketAddr, std::thread::JoinHandle<Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let node = Endpoint::pinned(node_key.public().clone(), 1).unwrap();
        let thread = std::thread::spawn(move || {
            let registry = Registry::new_wallet_history_clients(GENESIS, RULES, node, vec![wallet.clone()], 1, 1)?;
            for _ in 0..sessions {
                let (stream, _) = listener.accept().map_err(|e| e.to_string())?;
                drop(registry.begin()?.respond(wallet.id(), stream, &node_key, Duration::from_secs(30))?);
            }
            Ok(())
        });
        (address, thread)
    }

    #[test]
    fn a_history_session_uses_its_own_v9_queue_and_never_migrates_an_existing_queue() {
        let base = TestDir::new("node-history");
        let own = HybridKey::generate(Role::Transport).unwrap();
        let wallet = Endpoint::pinned(own.public().clone(), 1).unwrap();
        let node_key = HybridKey::generate(Role::Transport).unwrap();
        let node_descriptor = descriptor(&node_key);
        let (address, thread) = history_responder(node_key, wallet, 3);
        let node = parse_node(&address.to_string(), &node_descriptor).unwrap();

        // A fresh history queue file is created once and reopened by the next session.
        let queue = base.path().join("history-queue.sqlite");
        let mut session = NodeSession::history(GENESIS, RULES, node.clone(), queue.clone());
        drop(session.connect(&own, Duration::from_secs(30)).unwrap());
        assert!(queue.exists());
        assert!(matches!(session.state(), LinkState::Connected { .. }));
        drop(session.connect(&own, Duration::from_secs(30)).unwrap());

        // An existing ordinary (non-history) queue file is refused as a history queue, not upgraded.
        let ordinary = base.path().join("ordinary-queue.sqlite");
        drop(ObjectQueue::open(&ordinary, [5; 32]).unwrap());
        let before = std::fs::read(&ordinary).unwrap();
        let mut session = NodeSession::history(GENESIS, RULES, node, ordinary.clone());
        let error = session.connect(&own, Duration::from_secs(30)).err().unwrap();
        assert!(error.starts_with("Wallet transport queue"), "{error}");
        assert!(matches!(session.state(), LinkState::Lost { .. }));
        assert_eq!(std::fs::read(&ordinary).unwrap(), before, "the refused queue file is unchanged");
        thread.join().unwrap().unwrap();
    }

    #[test]
    fn an_absent_node_is_a_disconnected_state() {
        let base = TestDir::new("node-link-absent");
        let own = HybridKey::generate(Role::Transport).unwrap();
        let key = HybridKey::generate(Role::Transport).unwrap();
        // Bind and drop: the port is closed when the wallet connects.
        let address = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let node = parse_node(&address.to_string(), &descriptor(&key)).unwrap();
        let error = connect(GENESIS, RULES, &own, &node, &base.path().join("q.sqlite"), Duration::from_secs(5))
            .err()
            .unwrap();
        assert!(error.starts_with("Node unreachable"), "{error}");
    }
}
