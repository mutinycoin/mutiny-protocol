//! Public signed fixtures and real pinned loopback sessions only. No Worker
//! submission commands, TestTPM adapter, private signing key, or funding setup.
use super::*;
use crate::{history_service_v1::HistoryBudget, hybrid_peer_admission_v2::{Connection, Registry}};
use mutiny_consensus_v8::{anchors::FinalizedAnchor, block_envelope_v2::BlockEnvelope,
    canonical_store_v2::CanonicalStore, execution::State, mempool_v2::{Mempool, Status}};
use mutiny_crypto_v2::{HybridKey, Role};
use mutiny_transport_v2::{Endpoint, objects::{MAX_BITMAP_BITS, MAX_SUBMISSIONS, MAX_SUBMISSION_BYTES}};
use std::{net::{TcpListener, TcpStream}, path::{Path, PathBuf}};

struct Scope(PathBuf);
impl Scope {
    fn new() -> Self {
        let mut random = [0; 16]; mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!("worker-submission-pull-{}", hex::encode(random)));
        assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&path).unwrap());
        Self(path)
    }
}
impl Drop for Scope { fn drop(&mut self) { std::fs::remove_dir_all(&self.0).unwrap(); } }
struct Public {
    genesis: FinalizedAnchor, state: State, root: Hash, envelope: Vec<u8>, tx: Vec<u8>, id: Hash,
}
impl Public {
    fn load() -> Self {
        let f: serde_json::Value = serde_json::from_str(include_str!("../../qualification/hybrid-canonical-store-public-v1.json")).unwrap();
        assert_eq!(f["synthetic_only"], true); assert_eq!(f["production_authorized"], false);
        let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let root: Hash = raw(&f["root"]).try_into().unwrap();
        let records: Vec<_> = f["records"].as_array().unwrap().iter()
            .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"]))).collect();
        let state = State::from_records(&records, root).unwrap();
        let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
        let envelope = raw(&f["envelope"]);
        let tx = BlockEnvelope::decode(&envelope).unwrap().body.transactions[0].clone();
        let id = raw(&f["transaction_id"]).try_into().unwrap();
        Self { genesis, state, root, envelope, tx, id }
    }
    fn chain(&self, scope: &Scope) -> CanonicalStore {
        // Opening an existing store runs its real full replay from these same
        // independently checked public genesis records; no witness is supplied.
        CanonicalStore::open_trusted_genesis(&scope.0.join("chain.sqlite"), &self.genesis,
            &self.state, self.root, 1000, [255; 32]).unwrap()
    }
    fn runtime(&self, scope: &Scope) -> Arc<Mutex<HybridRuntime>> {
        Arc::new(Mutex::new(HybridRuntime::from_pinned_chain(self.chain(scope),
            Mempool::open(&scope.0.join("pool.sqlite"), self.genesis.genesis,
                self.genesis.fingerprint, 64 * 1024 * 1024).unwrap()).unwrap()))
    }
}
struct Network {
    a: HybridKey, b: HybridKey, pa: Endpoint, pb: Endpoint, out: Registry, input: Registry, history: bool,
}
impl Network {
    fn new(g: &FinalizedAnchor, history: bool) -> Self {
        let a = HybridKey::generate(Role::Transport).unwrap(); let b = HybridKey::generate(Role::Transport).unwrap();
        let pa = Endpoint::pinned(a.public().clone(), 1).unwrap(); let pb = Endpoint::pinned(b.public().clone(), 1).unwrap();
        let (out, input) = if history {
            (Registry::new_wallet_history_client(g.genesis, g.fingerprint, pa.clone(), vec![pb.clone()], 1, 1).unwrap(),
             Registry::new_wallet_history_clients(g.genesis, g.fingerprint, pb.clone(), vec![pa.clone()], 1, 1).unwrap())
        } else {
            (Registry::new(g.genesis, g.fingerprint, pa.clone(), vec![pb.clone()], 1, 1).unwrap(),
             Registry::new(g.genesis, g.fingerprint, pb.clone(), vec![pa.clone()], 1, 1).unwrap())
        };
        Self { a, b, pa, pb, out, input, history }
    }
    fn connections(&self) -> (Connection, Connection) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        assert!(listener.local_addr().unwrap().ip().is_loopback());
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let server = listener.accept().unwrap().0; drop(listener);
        std::thread::scope(|threads| {
            let pending = self.input.begin().unwrap();
            let response = threads.spawn(|| pending.respond(self.pa.id(), server, &self.b, IO * 6).unwrap());
            let client = self.out.begin().unwrap().initiate(self.pb.id(), client, &self.a, IO * 6).unwrap();
            (client, response.join().unwrap())
        })
    }
    fn queue(&self, path: &Path, peer: Hash, initialize: bool) -> ObjectQueue {
        if self.history { ObjectQueue::open_history(path, peer, false, initialize).unwrap() }
        else { ObjectQueue::open(path, peer).unwrap() }
    }
    fn links(&self, scope: &Scope, initialize: bool) -> (PeerLink, PeerLink) {
        let (client, node) = self.connections();
        let cq = self.queue(&scope.0.join("wallet.sqlite"), client.peer_id(), initialize);
        let nq = self.queue(&scope.0.join("node.sqlite"), node.peer_id(), initialize);
        (client.attach(cq).unwrap(), node.attach(nq).unwrap())
    }
}
fn deadline() -> Instant { Instant::now() + Duration::from_secs(120) }
fn io_limit(end: Instant) -> Instant { assert!(Instant::now() < end); end.min(Instant::now() + IO) }
fn send(peer: &mut PeerLink, frame: &[u8], end: Instant) { peer.send_typed(frame, io_limit(end)).unwrap(); }
fn event(peer: &mut PeerLink, end: Instant) -> Event {
    assert!(peer.wait_for_frame_typed(end).unwrap());
    let received = peer.receive_typed(io_limit(end)).unwrap();
    peer.dispatch_received_typed(received, |_, event| event).unwrap()
}
fn offer(client: &mut PeerLink, kind: ObjectKind, bytes: &[u8], end: Instant) -> Offer {
    let (offer, frame) = client.with_current(|link| link.enqueue(kind, bytes, 0)).unwrap().unwrap();
    send(client, &frame, end); offer
}
fn receive_offer(node: &mut PeerLink, pull: &mut SubmissionPull, expected: &Offer, end: Instant) {
    let received = event(node, end);
    assert!(matches!(&received, Event::Offered(offer) if offer == expected));
    assert!(pull.receive(&DispatchEvent::Transport(received), node).unwrap());
}
fn serve_complete(client: &mut PeerLink, node: &mut PeerLink, expected: &Offer, end: Instant) {
    assert!(matches!(event(client, end), Event::Requested));
    let mut completed = false;
    while let Some(frame) = client.with_current(|link| link.send_one()).unwrap().unwrap() {
        send(client, &frame, end);
        match event(node, end) {
            Event::FragmentReceived => assert!(!completed),
            Event::Completed { offer, .. } => { assert_eq!(offer, *expected); assert!(!completed); completed = true; }
            _ => panic!("unexpected public fragment event"),
        }
    }
    assert!(completed);
}
fn rows(path: &Path) -> usize {
    let db = rusqlite::Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    db.busy_timeout(Duration::from_millis(250)).unwrap();
    db.query_row("SELECT COUNT(*) FROM objects", [], |r| r.get(0)).unwrap()
}
fn drain(worker: &Worker, expected: &Offer, id: Hash, accepted: &mut usize) {
    loop { match worker.try_notification() {
        Ok(Notification::Dispatched(DispatchEvent::TransactionAccepted { offer, id: actual, status: Status::Pending })) => {
            assert_eq!(&offer, expected); assert_eq!(actual, id); *accepted += 1;
        }
        Ok(other) => panic!("unexpected automatic notification: {:?}", std::mem::discriminant(&other)),
        Err(TryRecvError::Empty) => break,
        Err(TryRecvError::Disconnected) => panic!("automatic node disconnected: {:?}", worker.exit_result()),
    } }
    assert!(!worker.is_finished(), "automatic node ended: {:?}", worker.exit_result());
}
fn autonomous_payment(pause_first_window: bool, history_retries: bool) {
    let end = deadline(); let scope = Scope::new(); let public = Public::load();
    let runtime = public.runtime(&scope); let network = Network::new(&public.genesis, true);
    let (client, node) = network.connections();
    let cq = network.queue(&scope.0.join("wallet.sqlite"), client.peer_id(), true);
    let nq = network.queue(&scope.0.join("node.sqlite"), node.peer_id(), true);
    let mut client = client.attach(cq).unwrap();
    let worker = Worker::start_history_node_typed(node, nq, runtime.clone(), HistoryBudget::default()).unwrap();
    let mut history_offer = None;
    if history_retries {
        let request = crate::history_protocol_v1::HistoryRequest { sequence: 1, saved_anchor: public.genesis.clone(),
            max_blocks: 64, max_candidate_bytes: 4_000_000, max_candidate_entries: 6 };
        history_offer = Some(offer(&mut client, ObjectKind::HistoryRequestV1, &request.encode().unwrap(), end));
    }
    let mut submitted = None;
    if !history_retries { submitted = Some(offer(&mut client, ObjectKind::SignedTransaction, &public.tx, end)); }
    let mut accepted = 0; let mut receipt = false; let mut paused = false; let mut retries = 0; let mut pages = 0;
    while !receipt || accepted == 0 || (history_retries && pages < 2) {
        assert!(Instant::now() < end, "bounded autonomous payment completion");
        if let Some(expected) = &submitted { drain(&worker, expected, public.id, &mut accepted); }
        else { assert!(!worker.is_finished(), "history node ended: {:?}", worker.exit_result()); }
        if !client.wait_for_frame_typed(end.min(Instant::now() + TICK)).unwrap() { continue; }
        let received = client.receive_typed(io_limit(end)).unwrap();
        let next = client.dispatch_received_typed(received, |_, event| event).unwrap();
        match next {
            Event::Offered(page) if page.kind == ObjectKind::HistoryPageV1 => {
                pages += 1;
                if submitted.is_none() { submitted = Some(offer(&mut client, ObjectKind::SignedTransaction, &public.tx, end)); }
                // Real exact-request retries share this same authenticated socket.
                // There is no alternate endpoint or manual Worker pull command.
                if retries < 3 {
                    let old = history_offer.as_ref().unwrap();
                    let frame = client.with_current(|link| link.advertise(&old.id, 0)).unwrap().unwrap();
                    send(&mut client, &frame, end); retries += 1;
                }
            }
            Event::Requested => {
                if pause_first_window && !paused {
                    paused = true;
                    let expected = submitted.as_ref().unwrap();
                    let duplicate = client.with_current(|link| link.advertise(&expected.id, 0)).unwrap().unwrap();
                    send(&mut client, &duplicate, end);
                    // This exceeds IO intentionally: five seconds bounds each
                    // complete frame, not the lifetime of a paced WANT window.
                    std::thread::sleep(IO + Duration::from_millis(100));
                    drain(&worker, expected, public.id, &mut accepted);
                    assert_eq!(accepted, 0); assert_eq!(runtime.lock().unwrap().head().unwrap(), public.genesis);
                    assert!(!client.wait_for_frame_typed(Instant::now() + TICK).unwrap(), "duplicate HAVE reset requested window");
                }
                while let Some(frame) = client.with_current(|link| link.send_one()).unwrap().unwrap() { send(&mut client, &frame, end); }
            }
            Event::ReceiptRecorded => {
                let expected = submitted.as_ref().unwrap();
                let count = expected.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD) as u16;
                let bits = client.with_current(|link| link.acknowledged(&expected.id, 0, count)).unwrap().unwrap();
                receipt = bits.bits.iter().all(|bit| *bit);
            }
            _ => panic!("unexpected automatic submission client event"),
        }
    }
    assert_eq!(accepted, 1);
    if history_retries { assert!(pages >= 2 && retries >= 1, "history retry and payment must coexist"); }
    let expected = submitted.unwrap();
    { let node = runtime.lock().unwrap();
      assert_eq!(node.exact_submission_bytes(public.id).unwrap(), Some((0, public.tx.clone())));
      assert_eq!(node.head().unwrap(), public.genesis);
      assert_eq!(node.confirmed_height(public.id).unwrap(), None, "transport receipt is not finality"); }
    worker.shutdown_typed().unwrap(); client.close(); drop(client);
    { let mut node = runtime.lock().unwrap();
      node.install(&public.envelope).unwrap();
      assert_eq!(node.confirmed_height(public.id).unwrap(), Some(1)); }
    if !history_retries { assert_eq!(rows(&scope.0.join("node.sqlite")), 0, "only transport copy is reclaimed"); }
    let chain = public.chain(&scope); // actual existing-store full replay
    assert_eq!(chain.load().unwrap().0.height, 1); drop(chain);
    assert_eq!(expected.kind, ObjectKind::SignedTransaction);
    drop(network.input.begin().unwrap()); drop(network.out.begin().unwrap());
}
#[test]
fn autonomous_payment_same_session_duplicate_slow_window_receipt_then_canonical_replay() {
    autonomous_payment(true, false);
}
#[test]
fn autonomous_payment_progresses_with_real_history_page_and_exact_request_retries() {
    autonomous_payment(false, true);
}
#[test]
fn submission_pull_retained_complete_requires_fresh_reconnect_have_then_native_retry() {
    let end = deadline(); let scope = Scope::new(); let public = Public::load(); let runtime = public.runtime(&scope);
    let network = Network::new(&public.genesis, true); let (mut client, mut node) = network.links(&scope, true);
    let mut old = SubmissionPull::new(&mut node).unwrap(); let old_session = old.session.session_id();
    let expected = offer(&mut client, ObjectKind::SignedTransaction, &public.tx, end);
    receive_offer(&mut node, &mut old, &expected, end);
    assert!(matches!(old.turn(&mut node, &runtime).unwrap(), SubmissionTurn::Requested));
    serve_complete(&mut client, &mut node, &expected, end);
    assert_eq!(runtime.lock().unwrap().exact_submission_bytes(public.id).unwrap(), None);
    client.close(); node.close(); drop(client); drop(node);
    let (mut client, mut node) = network.links(&scope, false);
    assert_ne!(node.history_session().unwrap().session_id(), old_session);
    assert!(old.turn(&mut node, &runtime).is_err(), "old session token cannot retarget reconnect");
    let mut pull = SubmissionPull::new(&mut node).unwrap();
    let stale = DispatchEvent::Transport(Event::Offered(expected.clone()));
    assert!(pull.receive(&stale, &mut node).is_err(), "retained queue metadata is not a current HAVE grant");
    let frame = client.with_current(|link| link.advertise(&expected.id, 0)).unwrap().unwrap(); send(&mut client, &frame, end);
    receive_offer(&mut node, &mut pull, &expected, end);
    let SubmissionTurn::Completed(accepted) = pull.turn(&mut node, &runtime).unwrap() else { panic!("retained native retry"); };
    assert!(matches!(&accepted, DispatchEvent::TransactionAccepted { offer, id, status: Status::Pending } if *offer == expected && *id == public.id));
    assert!(pull.offers.is_empty());
    assert!(!client.wait_for_frame_typed(Instant::now() + TICK).unwrap(), "complete retained copy needs no fragment WANT");
    let (tx, rx) = mpsc::sync_channel(CHANNEL_CAPACITY); let mut pending = None;
    auto_response(&mut node, &runtime, AutoResponse::new(accepted).unwrap(), &tx, &mut pending).unwrap();
    assert!(matches!(event(&mut client, end), Event::ReceiptRecorded));
    assert!(matches!(rx.try_recv().unwrap(), Notification::Dispatched(DispatchEvent::TransactionAccepted { .. })));
    assert_eq!(rows(&scope.0.join("node.sqlite")), 0);
    assert_eq!(runtime.lock().unwrap().confirmed_height(public.id).unwrap(), None);
    client.close(); node.close();
}
#[test]
fn submission_pull_fifo_duplicates_maximum_legal_window_and_reserved_caps() {
    let end = deadline(); let scope = Scope::new(); let public = Public::load(); let runtime = public.runtime(&scope);
    let network = Network::new(&public.genesis, true); let (mut client, mut node) = network.links(&scope, true);
    let mut pull = SubmissionPull::new(&mut node).unwrap();
    let bytes = vec![11; ObjectKind::SignedTransaction.max_bytes()];
    let first = offer(&mut client, ObjectKind::SignedTransaction, &bytes, end); receive_offer(&mut node, &mut pull, &first, end);
    let second = offer(&mut client, ObjectKind::SignedOperation, &vec![22; ObjectKind::SignedOperation.max_bytes()], end);
    receive_offer(&mut node, &mut pull, &second, end);
    assert_eq!(pull.offers.len(), MAX_SUBMISSIONS); assert_eq!(first.length + second.length, MAX_SUBMISSION_BYTES);
    assert!(matches!(pull.turn(&mut node, &runtime).unwrap(), SubmissionTurn::Requested));
    assert!(matches!(event(&mut client, end), Event::Requested));
    let count = first.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD) as u16;
    assert!(count < MAX_BITMAP_BITS, "multiwindow submission is unreachable under existing kind cap");
    assert_eq!(pull.offers.front().unwrap().window, Some((0, count)));
    let frame = client.with_current(|link| link.advertise(&first.id, 0)).unwrap().unwrap(); send(&mut client, &frame, end);
    receive_offer(&mut node, &mut pull, &first, end);
    assert_eq!(pull.offers.len(), MAX_SUBMISSIONS); assert_eq!(pull.offers.front().unwrap().window, Some((0, count)));
    for _ in 0..3 { assert!(matches!(pull.turn(&mut node, &runtime).unwrap(), SubmissionTurn::Idle)); }
    assert!(!client.wait_for_frame_typed(Instant::now() + TICK).unwrap(), "incomplete front retains one in-flight window");
    assert_eq!(runtime.lock().unwrap().head().unwrap(), public.genesis);
    assert!(client.with_current(|link| link.enqueue(ObjectKind::SignedOperation, &vec![0; 16385], 0)).unwrap().is_err());
    client.with_current(|link| link.discard(&second.id)).unwrap().unwrap();
    let _third = offer(&mut client, ObjectKind::SignedOperation, &[33; 100], end);
    assert!(node.wait_for_frame_typed(end).unwrap());
    assert!(matches!(node.receive_typed(io_limit(end)), Err(PeerFailure::Other(_))), "third incoming submission must hit unchanged reserved quota");
    assert_eq!(pull.offers.len(), MAX_SUBMISSIONS); client.close(); node.close();
}
#[test]
fn submission_pull_direction_and_repin_revoke_before_outbound_want() {
    let end = deadline(); let scope = Scope::new(); let public = Public::load(); let runtime = public.runtime(&scope);
    let network = Network::new(&public.genesis, true); let (mut client, mut node) = network.links(&scope, true);
    assert!(SubmissionPull::new(&mut client).is_err(), "wallet direction has no node pull authority");
    let mut pull = SubmissionPull::new(&mut node).unwrap();
    let expected = offer(&mut client, ObjectKind::SignedTransaction, &public.tx, end); receive_offer(&mut node, &mut pull, &expected, end);
    network.input.replace_peers(vec![]).unwrap();
    assert!(pull.turn(&mut node, &runtime).is_err());
    assert!(!client.wait_for_frame_typed(Instant::now() + TICK).unwrap(), "revoked pin emits no WANT");
    assert_eq!(runtime.lock().unwrap().exact_submission_bytes(public.id).unwrap(), None);
    assert_eq!(runtime.lock().unwrap().head().unwrap(), public.genesis); client.close(); node.close();
}
#[test]
fn submission_pull_corrupt_complete_public_transaction_refuses_before_ack_or_release() {
    let end = deadline(); let scope = Scope::new(); let public = Public::load(); let runtime = public.runtime(&scope);
    let network = Network::new(&public.genesis, true); let (mut client, mut node) = network.links(&scope, true);
    let mut raw = public.tx.clone(); *raw.last_mut().unwrap() ^= 1;
    let mut pull = SubmissionPull::new(&mut node).unwrap();
    let expected = offer(&mut client, ObjectKind::SignedTransaction, &raw, end); receive_offer(&mut node, &mut pull, &expected, end);
    assert!(matches!(pull.turn(&mut node, &runtime).unwrap(), SubmissionTurn::Requested));
    serve_complete(&mut client, &mut node, &expected, end);
    assert!(pull.turn(&mut node, &runtime).is_err(), "actual canonical dispatch rejects malformed/invalid signed bytes");
    assert_eq!(rows(&scope.0.join("node.sqlite")), 1, "rejected transport bytes are not ACKed/reclaimed");
    assert_eq!(runtime.lock().unwrap().exact_submission_bytes(public.id).unwrap(), None);
    assert_eq!(runtime.lock().unwrap().head().unwrap(), public.genesis); client.close(); node.close();
}
#[test]
fn ordinary_worker_keeps_explicit_manual_pull_behavior() {
    let end = deadline(); let scope = Scope::new(); let public = Public::load(); let runtime = public.runtime(&scope);
    let network = Network::new(&public.genesis, false); let (client, node) = network.connections();
    let cq = network.queue(&scope.0.join("wallet.sqlite"), client.peer_id(), true);
    let nq = network.queue(&scope.0.join("node.sqlite"), node.peer_id(), true);
    let mut client = client.attach(cq).unwrap(); let worker = Worker::start_typed(node, nq, runtime.clone()).unwrap();
    let expected = offer(&mut client, ObjectKind::SignedTransaction, &public.tx, end);
    loop { match worker.try_notification() {
        Ok(Notification::Dispatched(DispatchEvent::Transport(Event::Offered(actual)))) => { assert_eq!(actual, expected); break; }
        Ok(_) => panic!("ordinary Worker changed notification"),
        Err(TryRecvError::Empty) => { assert!(Instant::now() < end); std::thread::sleep(TICK); }
        Err(TryRecvError::Disconnected) => panic!("ordinary worker ended: {:?}", worker.exit_result()),
    } }
    assert!(!client.wait_for_frame_typed(Instant::now() + TICK * 3).unwrap());
    assert_eq!(runtime.lock().unwrap().exact_submission_bytes(public.id).unwrap(), None);
    worker.shutdown_typed().unwrap(); client.close();
}

#[test]
fn ready_payment_control_alternates_with_actual_history_retry_before_frame_sealing() {
    let end = deadline(); let scope = Scope::new(); let public = Public::load(); let runtime = public.runtime(&scope);
    let network = Network::new(&public.genesis, true); let (mut client, mut node) = network.links(&scope, true);
    let mut host = crate::history_node_host_v1::NodeHistoryHost::new(&mut node, HistoryBudget::default()).unwrap();
    let mut pull = SubmissionPull::new(&mut node).unwrap();
    let request = crate::history_protocol_v1::HistoryRequest { sequence: 1, saved_anchor: public.genesis.clone(),
        max_blocks: 64, max_candidate_bytes: 4_000_000, max_candidate_entries: 6 };
    let history = offer(&mut client, ObjectKind::HistoryRequestV1, &request.encode().unwrap(), end);
    assert!(host.receive(&DispatchEvent::Transport(event(&mut node, end)), &mut node).unwrap());
    assert!(host.turn(&mut node, &runtime, Instant::now()).unwrap());
    serve_complete(&mut client, &mut node, &history, end);
    let decoded = hybrid_dispatch_v2::retry_peer_completed(&runtime, &mut node, history.id, io_limit(end)).unwrap();
    assert!(matches!(&decoded, DispatchEvent::HistoryRequest { .. }));
    assert!(host.receive(&decoded, &mut node).unwrap());
    let mut submission_first = false; let mut response = None;
    assert!(automatic_control(&mut host, &mut pull, &mut submission_first, &mut node, &runtime, &mut response).unwrap());
    assert!(submission_first); assert!(response.is_none());
    assert!(matches!(event(&mut client, end), Event::Offered(page) if page.kind == ObjectKind::HistoryPageV1));
    // Both classes are now ready: history needs to pull its real exact retry,
    // while the existing same-session payment also needs its first WANT.
    let duplicate = client.with_current(|link| link.advertise(&history.id, 0)).unwrap().unwrap(); send(&mut client, &duplicate, end);
    assert!(host.receive(&DispatchEvent::Transport(event(&mut node, end)), &mut node).unwrap());
    let payment = offer(&mut client, ObjectKind::SignedTransaction, &public.tx, end);
    receive_offer(&mut node, &mut pull, &payment, end);
    assert!(pull.offers.front().unwrap().window.is_none());
    assert!(automatic_control(&mut host, &mut pull, &mut submission_first, &mut node, &runtime, &mut response).unwrap());
    assert!(!submission_first); assert!(pull.offers.front().unwrap().window.is_some(), "ready payment wins its next class turn");
    assert!(matches!(event(&mut client, end), Event::Requested));
    assert!(!client.wait_for_frame_typed(Instant::now() + TICK).unwrap(), "one selected action must not seal/send both classes");
    assert!(automatic_control(&mut host, &mut pull, &mut submission_first, &mut node, &runtime, &mut response).unwrap());
    assert!(submission_first); assert!(matches!(event(&mut client, end), Event::Requested));
    assert!(!automatic_control(&mut host, &mut pull, &mut submission_first, &mut node, &runtime, &mut response).unwrap());
    assert!(submission_first, "idle polls do not toggle control-class priority");
    assert_eq!(runtime.lock().unwrap().head().unwrap(), public.genesis);
    client.close(); node.close();
}
