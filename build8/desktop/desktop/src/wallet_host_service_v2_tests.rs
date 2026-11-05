use super::super::service::{Command, Event as ServiceEvent, Service};
use super::*;
use mutiny_wallet_core_v8::{OperationRequest, PaymentRequest};
use std::sync::mpsc::TryRecvError;
use zeroize::Zeroizing;

fn submit(service: &Service, command: Command) {
    if let Err(rejected) = service.try_submit(command) {
        panic!("{}", rejected.reason);
    }
}
fn event(service: &Service) -> ServiceEvent {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match service.try_event() {
            Ok(event) => return event,
            Err(TryRecvError::Disconnected) => panic!("service stopped"),
            Err(TryRecvError::Empty) => {}
        }
        assert!(Instant::now() < deadline, "service event timeout");
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn unlock(service: &Service) {
    submit(
        service,
        Command::Unlock(Zeroizing::new(PASSWORD.to_owned())),
    );
    assert!(matches!(event(service), ServiceEvent::Unlocked(_)));
}
fn create(base: &Path) {
    let session = Session::restore_initial(&phrase()).unwrap();
    let mut vault = Store::open(&base.join("WalletCustodyV2/wallet-hybrid-v2.sqlite")).unwrap();
    vault.save_initial(&session, PASSWORD).unwrap();
}
fn request_payment(service: &Service) -> ReviewScreen {
    submit(
        service,
        Command::Request(Box::new(OperationRequest::Payment(PaymentRequest::new(
            [94; 32], 50_000,
        )))),
    );
    match event(service) {
        ServiceEvent::Review(screen) => *screen,
        other => panic!("review missing: {other:?}"),
    }
}
/// Phase 7: every typed check and acknowledgement through the service, then Authorize (which
/// approves, signs and queues inside the controller; no approval crosses the queue).
fn confirm_and_authorize(service: &Service, screen: &ReviewScreen) {
    let review = &screen.review;
    for index in review.destinations_needing_check() {
        let typed = review.destination_check_text(index);
        submit(
            service,
            Command::Review(ReviewInput::ConfirmDestination { index, typed }),
        );
        assert!(matches!(event(service), ServiceEvent::Review(_)));
    }
    for ack in review.acknowledgements() {
        submit(service, Command::Review(ReviewInput::Acknowledge(*ack)));
        assert!(matches!(event(service), ServiceEvent::Review(_)));
    }
    submit(service, Command::Review(ReviewInput::Authorize));
}
fn directory(label: &str) -> std::path::PathBuf {
    let mut random = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
    let base = std::env::temp_dir().join(format!(
        "build8-wallet-service-{label}-{}",
        hex::encode(random)
    ));
    assert!(
        mutiny_consensus_v8::submission_pool_v1::SubmissionPool::private_directory(&base).unwrap(),
        "fixture owns only a new protected directory"
    );
    base
}

#[test]
fn sustained_service_signs_delivers_confirms_and_recovers_custody() {
    assert!(mutinyd_v8::production_gate::require_production_ready().is_err());
    let f = fixture();
    let base = directory("lifecycle");
    create(&base);
    let service = Service::start(controller(&base, &f)).unwrap();
    submit(
        &service,
        Command::Unlock(Zeroizing::new("WRONG PUBLIC PASSWORD".to_owned())),
    );
    assert!(matches!(event(&service), ServiceEvent::Rejected(_)));
    submit(&service, Command::Snapshot { payment: None });
    assert!(
        matches!(event(&service), ServiceEvent::Snapshot(v) if v.identity.is_none() && v.balance.is_none())
    );
    unlock(&service);
    request_payment(&service);
    submit(&service, Command::CancelReview);
    assert!(matches!(event(&service), ServiceEvent::Cancelled));
    // Authorize after a cancel: nothing is on screen, refused (and custody locked).
    submit(&service, Command::Review(ReviewInput::Authorize));
    assert!(matches!(event(&service), ServiceEvent::Rejected(_)));
    unlock(&service);
    let screen = request_payment(&service);
    let change_atoms = screen.review.returned();
    confirm_and_authorize(&service, &screen);
    let ServiceEvent::Queued(queued) = event(&service) else {
        panic!("durable submission missing");
    };
    let id = queued.id;
    submit(&service, Command::Lock);
    assert!(matches!(event(&service), ServiceEvent::Locked));
    let node = runtime(&base, &f);
    let a = HybridKey::generate(Role::Transport).unwrap();
    let b = HybridKey::generate(Role::Transport).unwrap();
    let (client, mut server, pin) = pair(&base, &f, &a, &b);
    submit(&service, Command::Attach(Box::new(client)));
    assert!(matches!(event(&service), ServiceEvent::PeerAttached));
    submit(&service, Command::Advertise { transaction: id });
    let observed = event(&service);
    let ServiceEvent::Advertised(offer) = observed else {
        panic!("advertisement missing: {observed:?}");
    };
    request_from_node(&mut server, &offer);
    // The running service alone performs the wallet turns; no test drives its
    // controller, network reader or sender after ownership moves to the thread.
    for i in 0..offer.length.div_ceil(MAX_PAYLOAD) {
        let incoming = hybrid_dispatch_v2::poll_peer(&node, &mut server, limit())
            .unwrap()
            .unwrap();
        if i + 1 == offer.length.div_ceil(MAX_PAYLOAD) {
            assert!(
                matches!(incoming, DispatchEvent::TransactionAccepted { id: accepted, .. } if accepted == id)
            );
        }
    }
    submit(&service, Command::Snapshot { payment: Some(id) });
    assert!(
        matches!(event(&service), ServiceEvent::Snapshot(v) if v.identity.is_none() && v.payment == Some((id, Delivery::Unconfirmed(Some(Status::Pending)))))
    );
    let envelope = certify(&node, &f);
    let raw = envelope.encode().unwrap();
    node.lock().unwrap().install(&raw).unwrap();
    let (history, have) = server
        .with_current(|link| link.enqueue(ObjectKind::CertifiedBlock, &raw, 0))
        .unwrap()
        .unwrap();
    server.send(&have, limit()).unwrap();
    let received = server.receive(limit()).unwrap_or_else(|error| {
        // Only this synthetic test emits the public service error on failure.
        let observed = event(&service);
        panic!("history request failed: {error}; service event: {observed:?}");
    });
    server
        .dispatch_received(received, |_, incoming| {
            assert!(matches!(incoming, Event::Requested))
        })
        .unwrap();
    for _ in 0..history.length.div_ceil(MAX_PAYLOAD) {
        let frame = server
            .with_current(|link| link.send_one())
            .unwrap()
            .unwrap()
            .unwrap();
        server.send(&frame, limit()).unwrap();
    }
    assert!(matches!(
        event(&service),
        ServiceEvent::History(Progress::History { inserted: true, .. })
    ));
    submit(&service, Command::Snapshot { payment: Some(id) });
    assert!(
        matches!(event(&service), ServiceEvent::Snapshot(v) if v.payment == Some((id, Delivery::ConfirmedAt(1))) && v.identity.is_none())
    );
    unlock(&service);
    submit(&service, Command::Snapshot { payment: Some(id) });
    assert!(
        matches!(event(&service), ServiceEvent::Snapshot(v) if v.balance.as_ref().unwrap().available_atoms == change_atoms)
    );
    pin.replace_peers(vec![]).unwrap();
    assert!(matches!(event(&service), ServiceEvent::Rejected(_)));
    submit(&service, Command::Snapshot { payment: Some(id) });
    assert!(
        matches!(event(&service), ServiceEvent::Snapshot(v) if v.identity.is_none() && v.payment == Some((id, Delivery::ConfirmedAt(1))))
    );
    service.shutdown().unwrap();
    let mut reopened = controller(&base, &f);
    assert!(reopened.identity().is_none());
    assert_eq!(reopened.delivery(id).unwrap(), Delivery::ConfirmedAt(1));
    reopened.unlock(PASSWORD).unwrap();
    assert_eq!(
        reopened.verified_balance().unwrap().available_atoms,
        change_atoms
    );
    drop(reopened);
    drop(node);
    drop(server);
    drop(pin);
    assert!(base.starts_with(std::env::temp_dir()));
    std::fs::remove_dir_all(base).unwrap();
    println!(
        "HOST_SERVICE_LIFECYCLE_PASS signed=true locked_delivery=true confirmed=true pin_revocation_locked=true restart=true synthetic_only=true"
    );
}

/// The service's UserActivity refreshes the KeySigner's own idle clock (fixes of the independent
/// wallet review): input every 500 ms for 6 s keeps a signer whose idle limit is 4 s alive, and
/// with input between the review steps the payment is signed afterwards; without input the signer
/// locks itself, and the next recorded input then locks the session (fail-closed).
#[test]
fn user_activity_keeps_the_signer_alive_and_a_dead_signer_locks_the_session() {
    let f = fixture();
    let base = directory("activity");
    create(&base);
    let mut wallet = controller(&base, &f);
    let limit = Duration::from_secs(4);
    wallet.set_signer_idle_limit_for_test(limit);
    wallet.unlock(PASSWORD).unwrap();
    let service = Service::start(wallet).unwrap();
    let active = |service: &Service| {
        submit(service, Command::UserActivity);
        assert!(matches!(event(service), ServiceEvent::ActivityRecorded));
    };
    for _ in 0..12 {
        std::thread::sleep(Duration::from_millis(500));
        active(&service);
    }
    let screen = request_payment(&service);
    active(&service);
    let review = &screen.review;
    for index in review.destinations_needing_check() {
        let typed = review.destination_check_text(index);
        submit(
            &service,
            Command::Review(ReviewInput::ConfirmDestination { index, typed }),
        );
        assert!(matches!(event(&service), ServiceEvent::Review(_)));
        active(&service);
    }
    for ack in review.acknowledgements() {
        submit(&service, Command::Review(ReviewInput::Acknowledge(*ack)));
        assert!(matches!(event(&service), ServiceEvent::Review(_)));
        active(&service);
    }
    submit(&service, Command::Review(ReviewInput::Authorize));
    let observed = event(&service);
    let ServiceEvent::Queued(queued) = observed else {
        panic!("the payment was not signed and queued: {observed:?}");
    };
    assert!(queued.complete);
    std::thread::sleep(limit + Duration::from_millis(500));
    submit(&service, Command::UserActivity);
    assert!(matches!(event(&service), ServiceEvent::ActivityRecorded));
    submit(&service, Command::Snapshot { payment: None });
    assert!(matches!(event(&service), ServiceEvent::Snapshot(v) if v.identity.is_none()));
    service.shutdown().unwrap();
    assert!(base.starts_with(std::env::temp_dir()));
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn service_expires_without_ui_and_backpressure_preserves_durable_payment() {
    let f = fixture();
    let base = directory("failure");
    create(&base);
    let mut wallet = controller(&base, &f);
    wallet.unlock(PASSWORD).unwrap();
    // Exercise the real expiry boundary without a five-minute test sleep.
    wallet.last_activity =
        Some(Instant::now() - super::super::super::IDLE_LIMIT + Duration::from_millis(100));
    let service = Service::start(wallet).unwrap();
    std::thread::sleep(Duration::from_millis(250));
    submit(&service, Command::UserActivity);
    assert!(matches!(event(&service), ServiceEvent::ActivityRecorded));
    submit(&service, Command::Snapshot { payment: None });
    assert!(matches!(event(&service), ServiceEvent::Snapshot(v) if v.identity.is_none()));
    unlock(&service);
    let screen = request_payment(&service);
    confirm_and_authorize(&service, &screen);
    // Deliberately abandon the UI event consumer. Even if its signed-payment
    // event cannot be delivered, the durable outbox is the status authority.
    let deadline = Instant::now() + Duration::from_secs(60);
    while !service.is_finished() {
        let _ = service.try_submit(Command::Snapshot { payment: None });
        assert!(
            Instant::now() < deadline,
            "backpressure did not stop service"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(service.shutdown().unwrap_err().contains("backpressure"));
    let mut reopened = controller(&base, &f);
    assert!(reopened.identity().is_none());
    let pending = reopened.pending_for_transport().unwrap();
    assert_eq!(pending.len(), 1);
    let id = mutiny_consensus_v8::hybrid_transaction_v2::Transaction::decode(&pending[0])
        .unwrap()
        .id()
        .unwrap();
    assert_eq!(
        reopened.delivery(id).unwrap(),
        Delivery::Unconfirmed(Some(Status::Pending))
    );
    drop(reopened);
    assert!(base.starts_with(std::env::temp_dir()));
    std::fs::remove_dir_all(base).unwrap();
    println!(
        "HOST_SERVICE_FAILURE_PASS idle_expiry=true backpressure_stopped=true durable_submission_retained=true synthetic_only=true"
    );
}

/// G3: the service reports the typed expiry as its own event and keeps `Rejected` for everything else
/// (custody lock and peer detach happen first in both cases, in `run`).
#[test]
fn g3_service_maps_only_typed_expiry_to_the_session_expired_event() {
    use super::super::service::link_failure_event;
    assert!(matches!(link_failure_event(PeerFailure::SessionExpired), ServiceEvent::SessionExpired));
    for text in ["Expired", "Peer receive: Expired", "Peer idle wait: Closed"] {
        assert!(matches!(link_failure_event(PeerFailure::Other(text.into())), ServiceEvent::Rejected(reason) if reason == text));
    }
    assert_eq!(format!("{:?}", ServiceEvent::SessionExpired), "SessionExpired");
}
/// B1 through the wallet service: attaching a history-profile connection starts catch-up at once,
/// the service reports the wallet's own verified height, and it reaches the node's head unattended.
#[test]
fn b1_service_attaches_a_history_connection_and_catches_up_unattended() {
    let f = fixture();
    let base = directory("history");
    create(&base);
    let (node, expected) = history_node(&base, &f);
    let (peer, worker, registries) = history_pair(&base, &f.genesis, &node);
    let service = Service::start(controller(&base, &f)).unwrap();
    submit(&service, Command::Attach(Box::new(peer)));
    assert!(matches!(event(&service), ServiceEvent::PeerAttached));
    match event(&service) {
        ServiceEvent::Sync { saved: 0, line, .. } => assert!(line.contains("Asking the node"), "{line}"),
        other => panic!("first sync report missing: {other:?}"),
    }
    let deadline = Instant::now() + Duration::from_secs(120);
    let line = loop {
        assert!(Instant::now() < deadline, "bounded unattended catch-up");
        assert!(!worker.is_finished(), "the autonomous node must stay up");
        match event(&service) {
            ServiceEvent::Sync { saved: 1, tip: Some(1), line } if line.contains("Up to date") => break line,
            ServiceEvent::Sync { .. } => {}
            other => panic!("unexpected service event during catch-up: {other:?}"),
        }
    };
    assert_eq!(line, "Verified to height 1. Up to date with the node.");
    submit(&service, Command::Snapshot { payment: None });
    match event(&service) {
        ServiceEvent::Snapshot(view) => assert_eq!(view.anchor, expected, "the service's own verified anchor"),
        other => panic!("snapshot missing: {other:?}"),
    }
    submit(&service, Command::Detach);
    assert!(matches!(event(&service), ServiceEvent::PeerDetached));
    service.shutdown().unwrap();
    // The wallet left first, so the node's worker ends on the closed link: an ordinary failure, not expiry.
    let ended = worker.shutdown_typed();
    assert!(matches!(ended, Err(PeerFailure::Other(_))), "{ended:?}");
    drop(registries);
    drop(node);
    assert!(base.starts_with(std::env::temp_dir()));
    std::fs::remove_dir_all(base).unwrap();
}
/// B1 end to end through the wallet Service (loopback, public fixture): attach a history connection,
/// review and authorize a payment through service commands, advertise it on the same history session,
/// the autonomous node pulls and finalizes it, the service's own replay reports it confirmed; then the
/// service shuts down and a new Service on the same wallet files shows the same verified state.
#[test]
fn b1_service_pays_over_history_confirms_by_own_replay_and_survives_restart() {
    fn next(service: &Service) -> ServiceEvent {
        // Sync reports may arrive at any time (10 s refresh); every other event is in command order.
        loop {
            match event(service) {
                ServiceEvent::Sync { .. } => continue,
                other => return other,
            }
        }
    }
    let f = fixture();
    let base = directory("history-pay");
    create(&base);
    let node = std::sync::Arc::new(runtime(&base, &f));
    let (peer, worker, registries) = history_pair(&base, &f.genesis, &node);
    let service = Service::start(controller(&base, &f)).unwrap();
    submit(&service, Command::Unlock(Zeroizing::new(PASSWORD.to_owned())));
    let identity = match next(&service) {
        ServiceEvent::Unlocked(identity) => identity,
        other => panic!("unlock: {other:?}"),
    };
    submit(&service, Command::Attach(Box::new(peer)));
    assert!(matches!(next(&service), ServiceEvent::PeerAttached));
    // Review and authorize exactly as the UI does, through the service queue.
    submit(&service, Command::Request(Box::new(OperationRequest::Payment(PaymentRequest::new([94; 32], 50_000)))));
    let screen = match next(&service) {
        ServiceEvent::Review(screen) => *screen,
        other => panic!("review: {other:?}"),
    };
    for index in screen.review.destinations_needing_check() {
        let typed = screen.review.destination_check_text(index);
        submit(&service, Command::Review(ReviewInput::ConfirmDestination { index, typed }));
        assert!(matches!(next(&service), ServiceEvent::Review(_)));
    }
    for ack in screen.review.acknowledgements() {
        submit(&service, Command::Review(ReviewInput::Acknowledge(*ack)));
        assert!(matches!(next(&service), ServiceEvent::Review(_)));
    }
    submit(&service, Command::Review(ReviewInput::Authorize));
    let id = match next(&service) {
        ServiceEvent::Queued(queued) => queued.id,
        other => panic!("queue: {other:?}"),
    };
    submit(&service, Command::Advertise { transaction: id });
    assert!(matches!(next(&service), ServiceEvent::Advertised(_)));
    // The node admits it from the history session; its next block includes exactly this payment.
    let deadline = Instant::now() + Duration::from_secs(180);
    let block = loop {
        assert!(Instant::now() < deadline, "node admission through the service's history link");
        assert!(!worker.is_finished(), "the autonomous node must stay up");
        let envelope = certify_pending(&node, &f);
        if !envelope.body.transactions.is_empty() {
            break envelope;
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    assert_eq!(block.body.transactions.len(), 1);
    assert!(node.lock().unwrap().install(&block.encode().unwrap()).unwrap().inserted);
    let head = node.lock().unwrap().head().unwrap();
    // The service's own refresh and replay, nothing else, confirm it.
    loop {
        assert!(Instant::now() < deadline, "service refresh and replay");
        match event(&service) {
            ServiceEvent::Sync { saved: 1, .. } => break,
            ServiceEvent::Sync { .. } => {}
            other => panic!("unexpected event while syncing: {other:?}"),
        }
    }
    submit(&service, Command::Snapshot { payment: Some(id) });
    match next(&service) {
        ServiceEvent::Snapshot(view) => {
            assert_eq!(view.anchor, head);
            assert_eq!(view.payment, Some((id, Delivery::ConfirmedAt(1))));
        }
        other => panic!("snapshot: {other:?}"),
    }
    submit(&service, Command::Detach);
    assert!(matches!(next(&service), ServiceEvent::PeerDetached));
    service.shutdown().unwrap();
    let ended = worker.shutdown_typed();
    assert!(matches!(ended, Err(PeerFailure::Other(_))), "{ended:?}");
    drop(registries);

    // Restart: a new Service over the same wallet files, after the first has joined.
    let service = Service::start(controller(&base, &f)).unwrap();
    submit(&service, Command::Snapshot { payment: Some(id) });
    match next(&service) {
        ServiceEvent::Snapshot(view) => {
            assert_eq!(view.anchor, head, "the same verified anchor after restart");
            assert_eq!(view.payment, Some((id, Delivery::ConfirmedAt(1))), "the same own-replay confirmation");
            assert!(view.identity.is_none(), "custody starts locked after restart");
        }
        other => panic!("snapshot after restart: {other:?}"),
    }
    submit(&service, Command::Unlock(Zeroizing::new(PASSWORD.to_owned())));
    match next(&service) {
        ServiceEvent::Unlocked(again) => assert_eq!(again, identity, "the same wallet identity"),
        other => panic!("unlock after restart: {other:?}"),
    }
    service.shutdown().unwrap();
    drop(node);
    assert!(base.starts_with(std::env::temp_dir()));
    std::fs::remove_dir_all(base).unwrap();
}
/// The composed Service acceptance flow (crate::service_acceptance) in loopback, with the public desktop
/// fixture: target own height 0 (Genesis-funded fixture wallet), a stand-in producer thread that
/// certifies the node's next block once the payment is admitted, and a TEST-ONLY retirement barrier
/// that joins the node worker (the live barrier is the node owner's pending acknowledgement API).
#[test]
fn b1_service_acceptance_flow_runs_end_to_end_in_loopback() {
    use crate::service_acceptance::{HistoryConnector, Plan, RetirementBarrier, run};
    use mutinyd_v8::hybrid_peer_worker_v2::Worker;
    struct Connector {
        base: std::path::PathBuf,
        genesis: FinalizedAnchor,
        node: std::sync::Arc<Mutex<HybridRuntime>>,
        live: std::rc::Rc<std::cell::RefCell<Vec<(Worker, [Registry; 2])>>>,
        count: usize,
    }
    impl HistoryConnector for Connector {
        fn connect(&mut self, _session: u32, _deadline: Instant) -> std::result::Result<WalletPeer, String> {
            self.count += 1;
            let base = self.base.join(format!("connection-{}", self.count));
            std::fs::create_dir_all(&base).map_err(|e| e.to_string())?;
            let (peer, worker, registries) = history_pair(&base, &self.genesis, &self.node);
            self.live.borrow_mut().push((worker, registries));
            Ok(peer)
        }
    }
    struct TestBarrier(std::rc::Rc<std::cell::RefCell<Vec<(Worker, [Registry; 2])>>>);
    impl RetirementBarrier for TestBarrier {
        fn await_retired(&mut self, session: u32, _: Instant) -> std::result::Result<serde_json::Value, String> {
            // TEST ONLY stand-in for the node owner's acknowledgement: the wallet link is still attached
            // but quiesced; stop this session's node worker and require its typed join to be Ok.
            let (worker, registries) = self.0.borrow_mut().remove(0);
            let outcome = worker.shutdown_typed();
            drop(registries);
            match outcome {
                Ok(()) => Ok(serde_json::json!({"test_only_stand_in":true,"session":session,"native_join_ok":true})),
                Err(failure) => Err(format!("test node worker join failed: {failure:?}")),
            }
        }
    }
    // One fixture for wallet, node and stand-in producer: it holds the synthetic continuity key.
    let f = std::sync::Arc::new(fixture());
    let base = directory("acceptance");
    create(&base);
    let node = std::sync::Arc::new(runtime(&base, &f));
    // Stand-in producer: certify the next block as soon as the node has admitted a payment.
    let producer = {
        let node = node.clone();
        let f = f.clone();
        let deadline = Instant::now() + Duration::from_secs(300);
        std::thread::spawn(move || loop {
            assert!(Instant::now() < deadline, "stand-in producer deadline");
            let envelope = certify_pending(&node, &f);
            if !envelope.body.transactions.is_empty() {
                assert!(node.lock().unwrap().install(&envelope.encode().unwrap()).unwrap().inserted);
                return;
            }
            std::thread::sleep(Duration::from_millis(200));
        })
    };
    let live = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let mut connector = Connector { base: base.join("links"), genesis: f.genesis.clone(), node: node.clone(), live: live.clone(), count: 0 };
    let mut barrier = TestBarrier(live.clone());
    let plan = Plan { target_height: 0, recipient: [94; 32], atoms: 50_000, deadline: Instant::now() + Duration::from_secs(300) };
    let mut records = Vec::new();
    let mut open = || Ok(controller(&base, &f));
    let id = run(&mut open, PASSWORD, &mut connector, &mut barrier, &plan, &mut |r| records.push(r)).unwrap();
    producer.join().unwrap();
    let steps: Vec<_> = records.iter().filter_map(|r| r["step"].as_str()).filter(|s| *s != "sync").collect();
    assert_eq!(steps, ["unlocked", "attached", "caught_up", "reviewed", "queued", "advertised", "confirmed", "quiesced", "node_retired",
        "service_joined", "restart_state", "restart_unlocked", "attached", "restart_attached", "quiesced", "node_retired",
        "service_joined", "done"]);
    assert!(records.iter().filter(|r| r["step"] == "node_retired").all(|r| r["ack"]["native_join_ok"] == true));
    assert!(records.iter().any(|r| r["step"] == "confirmed" && r["own_replay_height"] == 1));
    assert_eq!(node.lock().unwrap().confirmed_height(id).unwrap(), Some(1));
    for (worker, registries) in live.borrow_mut().drain(..) {
        let _ = worker.shutdown_typed();
        drop(registries);
    }
    drop(barrier);
    drop(connector);
    drop(node);
    assert!(base.starts_with(std::env::temp_dir()));
    std::fs::remove_dir_all(base).unwrap();
}