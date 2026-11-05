use super::*;

#[path = "wallet_host_service_v2_tests.rs"]
mod service_tests;
use crate::{
    operation_outbox::OperationOutbox,
    plan_review::{ReviewInput, ReviewScreen},
    preimage_store::PreimageVault,
    store_v2::Store,
    verified_sync_v2::Replica,
    wallet_controller_v2::{ReviewOutcome, tests::confirm_everything},
    wallet_v2::Session,
};
use mutiny_consensus_v8::{
    anchors::FinalizedAnchor,
    block_envelope_v2::BlockEnvelope,
    canonical_store_v2::CanonicalStore,
    certificates::Decision,
    continuity_v2::{Certificate, Vote},
    execution::State,
    mempool_v2::{Mempool, Status},
    pow::{WorkAuthority, WorkHeader},
    work_authority_v2::Authority,
};
use mutiny_crypto_v2::{HybridKey, HybridSignature, Role};
use mutiny_transport_v2::{Endpoint, MAX_PAYLOAD, objects::ObjectQueue};
use mutiny_wallet_core_v8::ChainContext;
use mutinyd_v8::{
    hybrid_dispatch_v2::{self, DispatchEvent},
    hybrid_peer_admission_v2::Registry,
    hybrid_runtime_v2::{HybridRuntime, WorkRequest},
};
use std::{
    net::{TcpListener, TcpStream},
    path::Path,
    sync::Mutex,
};

#[path = "wallet_host_fixture_licenses.rs"]
mod licenses;
#[path = "wallet_host_fixture_tpm.rs"]
mod tpm;

fn empty() -> HybridSignature {
    HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    }
}
fn phrase() -> String {
    format!("{}art", "abandon ".repeat(23))
}
const PASSWORD: &str = "PUBLIC SYNTHETIC HOST QUALIFICATION PASSWORD";

// Rebuild only synthetic Genesis admission using the repository's existing
// public software TPM fixture. No production authority, TPM, or live miner.
struct Fixture {
    state: State,
    genesis: FinalizedAnchor,
    coordinator: HybridKey,
    continuity: HybridKey,
    license: Hash,
    worker: Hash,
}
fn fixture() -> Fixture {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/hybrid-canonical-store-public-v1.json"
    ))
    .unwrap();
    assert_eq!(f["synthetic_only"], true);
    assert_eq!(f["production_authorized"], false);
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let records: Vec<_> = f["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
        .collect();
    let initial = State::from_records(&records, raw(&f["root"]).try_into().unwrap()).unwrap();
    let mut state = State {
        coins: initial.coins.clone(),
        wallets: initial.wallets.clone(),
        continuity: initial.continuity.clone(),
        ..Default::default()
    };
    let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
    let (owner, assignments, expected, licenses, coordinator) = licenses::fixtures();
    state
        .wallets
        .register(&owner.public().descriptor(1).unwrap())
        .unwrap();
    let continuity = HybridKey::generate(Role::Continuity).unwrap();
    let old_node = state.continuity.as_ref().unwrap().members[0].node;
    let mut binding = initial
        .membership_v2
        .get(old_node)
        .unwrap()
        .binding()
        .clone();
    binding.node_descriptor = coordinator.public().descriptor(1).unwrap();
    binding.admission.node =
        mutiny_consensus_v8::node_admission_v2::node_id(genesis.genesis, &binding.node_descriptor)
            .unwrap();
    binding.admission.continuity_descriptor = continuity.public().descriptor(1).unwrap();
    let ak = p256::ecdsa::SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
    let profile = tpm::profile(&ak);
    assert_eq!(binding.admission.profile, profile.encode().unwrap());
    binding.admission.prove_continuity(&continuity).unwrap();
    binding.admission.quote = tpm::quote(&ak, &profile, binding.admission.challenge().unwrap());
    binding.admission.authorize(&owner, 1).unwrap();
    binding.sign(&coordinator).unwrap();
    let policy = mutiny_consensus_v8::admission_v2::Policy {
        genesis: genesis.genesis,
        fingerprint: genesis.fingerprint,
        owner_descriptor: owner.public().descriptor(1).unwrap(),
        endorsement_roots: [binding.admission.endorsement_root].into_iter().collect(),
    };
    let admission_expected = mutiny_consensus_v8::admission_v2::Expected {
        node: binding.admission.node,
        hardware_generation: 1,
        key_generation: 1,
        supervised_nonce: binding.admission.supervised_nonce,
    };
    (state.membership_v2, state.continuity_keys_v2) =
        mutiny_consensus_v8::membership_v2::Book::genesis(
            &binding,
            &policy,
            &admission_expected,
            &state.wallets,
            mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest,
        )
        .unwrap();
    state.continuity.as_mut().unwrap().members[0].node = binding.admission.node;
    state.licenses_v2 = mutiny_consensus_v8::license_book_v2::Book::genesis(
        &assignments,
        &expected,
        &licenses,
        &state.wallets,
        genesis.genesis,
        genesis.fingerprint,
    )
    .unwrap();
    state.admission_policy_v2 =
        Some(mutiny_consensus_v8::admission_policy_v2::Record::new(policy).unwrap());
    state.wallets.records().expect("fixture wallets");
    state
        .continuity_keys_v2
        .records()
        .expect("fixture continuity keys");
    state
        .membership_v2
        .records(&state.continuity_keys_v2)
        .expect("fixture membership");
    state.licenses_v2.records().expect("fixture licenses");
    state
        .continuity
        .as_ref()
        .unwrap()
        .state_records()
        .expect("fixture continuity");
    let rows = state.records().expect("fixture records");
    State::from_records(&rows, state.root().unwrap()).expect("fixture restore");
    Fixture {
        state,
        genesis,
        coordinator,
        continuity,
        license: licenses[0].id,
        worker: expected[0].worker_id,
    }
}
fn chain(base: &Path, name: &str, f: &Fixture) -> CanonicalStore {
    CanonicalStore::open_trusted_genesis(
        &base.join(name),
        &f.genesis,
        &f.state,
        f.state.root().unwrap(),
        1000,
        [255; 32],
    )
    .unwrap()
}
fn pool(base: &Path, name: &str, f: &Fixture) -> Mempool {
    Mempool::open(
        &base.join(name),
        f.genesis.genesis,
        f.genesis.fingerprint,
        64 * 1024 * 1024,
    )
    .unwrap()
}
/// The protected operation outbox and the preimage store beside the vault (phase 7).
fn custody_stores(base: &Path, genesis: &FinalizedAnchor) -> (OperationOutbox, PreimageVault) {
    let context = ChainContext {
        network: genesis.network,
        genesis: genesis.genesis,
        fingerprint: genesis.fingerprint,
    };
    let custody = base.join("WalletCustodyV2");
    (
        OperationOutbox::open(&custody.join(crate::operation_outbox::FILE_NAME), context).unwrap(),
        PreimageVault::open(&custody.join(crate::preimage_store::FILE_NAME)).unwrap(),
    )
}
fn controller(base: &Path, f: &Fixture) -> Controller {
    let (operations, preimages) = custody_stores(base, &f.genesis);
    Controller::new(
        Store::open(&base.join("WalletCustodyV2/wallet-hybrid-v2.sqlite")).unwrap(),
        Replica::from_pinned_chain(chain(base, "wallet-chain.sqlite", f)).unwrap(),
        pool(base, "wallet-outbox.sqlite", f),
        operations,
        preimages,
        None,
    )
    .unwrap()
}
/// Phase 7 (replaces the retired synthetic approval): review a payment, enter every typed check
/// and acknowledgement as the review widget reports them, then Authorize (approve, sign, queue).
fn pay(wallet: &mut Controller, recipient: Hash, atoms: u64) -> (Hash, ReviewScreen) {
    let screen = wallet.prepare(recipient, atoms).unwrap();
    confirm_everything(wallet, &screen);
    match wallet.review_input(ReviewInput::Authorize).unwrap() {
        ReviewOutcome::Queued(queued) => (queued.id, screen),
        other => panic!("payment not queued: {other:?}"),
    }
}
fn runtime(base: &Path, f: &Fixture) -> Mutex<HybridRuntime> {
    Mutex::new(
        HybridRuntime::from_pinned_chain(
            chain(base, "node-chain.sqlite", f),
            pool(base, "node-pool.sqlite", f),
        )
        .unwrap(),
    )
}
fn pair(
    base: &Path,
    f: &Fixture,
    a: &HybridKey,
    b: &HybridKey,
) -> (WalletPeer, PeerLink, Registry) {
    let pa = Endpoint::pinned(a.public().clone(), 1).unwrap();
    let pb = Endpoint::pinned(b.public().clone(), 1).unwrap();
    let outgoing = Registry::new(
        f.genesis.genesis,
        f.genesis.fingerprint,
        pa.clone(),
        vec![pb.clone()],
        1,
        1,
    )
    .unwrap();
    let incoming = Registry::new(
        f.genesis.genesis,
        f.genesis.fingerprint,
        pb.clone(),
        vec![pa.clone()],
        1,
        1,
    )
    .unwrap();
    let pending = incoming.begin().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let server = listener.accept().unwrap().0;
    drop(listener);
    let (client, server) = std::thread::scope(|scope| {
        let responder = scope.spawn(|| {
            pending
                .respond(pa.id(), server, b, Duration::from_secs(30))
                .unwrap()
        });
        let client = outgoing
            .begin()
            .unwrap()
            .initiate(pb.id(), client, a, Duration::from_secs(30))
            .unwrap();
        (client, responder.join().unwrap())
    });
    let send_queue = ObjectQueue::open(&base.join("wallet-link.sqlite"), client.peer_id()).unwrap();
    let recv_queue = ObjectQueue::open(&base.join("node-link.sqlite"), server.peer_id()).unwrap();
    (
        WalletPeer::new(client.attach(send_queue).unwrap()),
        server.attach(recv_queue).unwrap(),
        outgoing,
    )
}
fn limit() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn turn(controller: &mut Controller, peer: &mut WalletPeer) -> Option<Progress> {
    let progress = controller.peer_turn(peer, limit()).unwrap();
    if peer.pending_control.is_some() {
        controller.peer_turn(peer, limit()).unwrap();
    }
    progress
}
fn request_from_node(peer: &mut PeerLink, offer: &Offer) {
    let received = peer.receive(limit()).unwrap();
    let want = peer
        .dispatch_received(received, |link, event| {
            assert!(matches!(event, Event::Offered(_)));
            link.next_missing_request(&offer.id, 0, false)
                .unwrap()
                .unwrap()
                .frame
        })
        .unwrap();
    peer.send(&want, limit()).unwrap();
}

#[test]
fn wallet_host_late_durable_reply_preserves_frame_order_and_revocation() {
    let f = fixture();
    let mut random = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
    let base = std::env::temp_dir().join(format!("build8-wallet-turn-{}", hex::encode(random)));
    assert!(
        mutiny_consensus_v8::submission_pool_v1::SubmissionPool::private_directory(&base).unwrap(),
        "fixture owns only a new protected directory"
    );
    let session = Session::restore_initial(&phrase()).unwrap();
    let mut vault = Store::open(&base.join("WalletCustodyV2/wallet-hybrid-v2.sqlite")).unwrap();
    vault.save_initial(&session, PASSWORD).unwrap();
    drop(vault);
    drop(session);
    let mut wallet = controller(&base, &f);
    wallet.unlock(PASSWORD).unwrap();
    let (id, _) = pay(&mut wallet, [94; 32], 50_000);
    wallet.lock();
    let exact = wallet.pending_for_transport().unwrap();
    let anchor = wallet.replica.current_anchor().unwrap();
    let a = HybridKey::generate(Role::Transport).unwrap();
    let b = HybridKey::generate(Role::Transport).unwrap();
    let (mut client, mut server, pin) = pair(&base, &f, &a, &b);
    let (_, have) = server
        .with_current(|link| link.enqueue(ObjectKind::CertifiedBlock, &[77; 200], 0))
        .unwrap()
        .unwrap();
    server.send(&have, limit()).unwrap();
    // Model durable local dispatch completing after the receive I/O budget.
    // The network's100ms budget is unchanged; this delay is test-only.
    client.after_dispatch_delay = TURN_LIMIT + Duration::from_millis(20);
    let deadline = Instant::now() + TURN_LIMIT;
    assert!(matches!(
        wallet.peer_turn(&mut client, deadline).unwrap(),
        Some(Progress::Transport)
    ));
    assert!(Instant::now() > deadline);
    assert!(
        !server
            .wait_for_frame(Instant::now() + Duration::from_millis(10))
            .unwrap()
    );
    // A service command arriving before the next turn cannot overtake the
    // already encoded request and break authenticated frame sequence order.
    let payment = wallet.advertise_payment(&mut client, id, limit()).unwrap();
    let received = server.receive(limit()).unwrap();
    server
        .dispatch_received(received, |_, event| {
            assert!(matches!(event, Event::Requested))
        })
        .unwrap();
    let received = server.receive(limit()).unwrap();
    server
        .dispatch_received(received, |_, event| {
            assert!(matches!(event, Event::Offered(offer) if offer.id == payment.id))
        })
        .unwrap();
    assert_eq!(wallet.replica.current_anchor().unwrap(), anchor);
    assert!(wallet.identity().is_none());
    assert_eq!(wallet.pending_for_transport().unwrap(), exact);
    // Revoke the connection after another reply is retained but before its
    // next send. The original pin check must reject that queued frame.
    let (_, have) = server
        .with_current(|link| link.enqueue(ObjectKind::CertifiedBlock, &[78; 200], 0))
        .unwrap()
        .unwrap();
    server.send(&have, limit()).unwrap();
    assert!(matches!(
        wallet.peer_turn(&mut client, limit()).unwrap(),
        Some(Progress::Transport)
    ));
    pin.replace_peers(vec![]).unwrap();
    assert!(wallet.peer_turn(&mut client, limit()).is_err());
    assert_eq!(wallet.pending_for_transport().unwrap(), exact);
    assert_eq!(wallet.replica.current_anchor().unwrap(), anchor);
    drop(wallet);
    drop(client);
    drop(server);
    drop(pin);
    assert!(base.starts_with(std::env::temp_dir()));
    std::fs::remove_dir_all(base).unwrap();
    println!(
        "HOST_WALLET_TURN_PASS original_io_ms=100 late_durable_reply=true frame_order=true pin_revocation=true no_signing=true no_confirmation=true"
    );
}
fn send_history(
    wallet: &mut Controller,
    wallet_peer: &mut WalletPeer,
    node_peer: &mut PeerLink,
    raw: &[u8],
) -> (Offer, std::result::Result<Progress, String>) {
    let (offer, have) = node_peer
        .with_current(|link| link.enqueue(ObjectKind::CertifiedBlock, raw, 0))
        .unwrap()
        .unwrap();
    node_peer.send(&have, limit()).unwrap();
    turn(wallet, wallet_peer);
    let received = node_peer.receive(limit()).unwrap();
    node_peer
        .dispatch_received(received, |_, event| {
            assert!(matches!(event, Event::Requested))
        })
        .unwrap();
    let count = offer.length.div_ceil(MAX_PAYLOAD);
    let mut completed = None;
    for i in 0..count {
        let frame = node_peer
            .with_current(|link| link.send_one())
            .unwrap()
            .unwrap()
            .unwrap();
        node_peer.send(&frame, limit()).unwrap();
        let result = wallet.peer_turn(wallet_peer, limit());
        if i + 1 == count {
            completed = Some(result.map(|v| v.unwrap()));
        } else {
            assert!(matches!(result, Ok(Some(Progress::Transport))));
            if (i + 1).is_multiple_of(mutiny_transport_v2::objects::MAX_BITMAP_BITS as usize) {
                // The service sends the durable window reply on its next turn.
                turn(wallet, wallet_peer);
                let received = node_peer.receive(limit()).unwrap();
                node_peer
                    .dispatch_received(received, |_, event| {
                        assert!(matches!(event, Event::Requested))
                    })
                    .unwrap();
            }
        }
    }
    (offer, completed.unwrap())
}
fn certify(runtime: &Mutex<HybridRuntime>, f: &Fixture) -> BlockEnvelope {
    let envelope = certify_pending(runtime, f);
    assert_eq!(envelope.body.transactions.len(), 1);
    envelope
}
/// Height 1 over whatever the node's pool holds (possibly nothing).
fn certify_pending(runtime: &Mutex<HybridRuntime>, f: &Fixture) -> BlockEnvelope {
    let mut runtime = runtime.lock().unwrap();
    let prepared = runtime
        .prepare(WorkRequest {
            expected_parent: &f.genesis,
            license: f.license,
            worker: f.worker,
            timestamp: 1100,
            ticket: 1,
            operations: &[],
        })
        .unwrap();
    let mut authority = Authority {
        work: WorkAuthority {
            candidate: prepared.candidate.clone(),
            assignment_sequence: 1,
            ticket_sequence: 1,
            coordinator: mutiny_consensus_v8::work_authority_v2::node_identity(
                &f.coordinator.public().descriptor(1).unwrap(),
            )
            .unwrap(),
            nonce_start: 0,
            nonce_end: 100,
            epoch: 1,
        },
        node_descriptor: f.coordinator.public().descriptor(1).unwrap(),
        signature: empty(),
    };
    authority.sign(&f.coordinator).unwrap();
    let header = WorkHeader {
        candidate: prepared.candidate,
        authority: authority.id().unwrap(),
        nonce: 1,
    };
    assert!(mutiny_consensus_v8::pow::meets_target(
        &header.block_hash(),
        &[255; 32]
    ));
    let height_authority = runtime.current_authority(&f.genesis).unwrap();
    let (node, voter) = height_authority.voters.iter().next().unwrap();
    let decision = Decision {
        network: f.genesis.network,
        genesis: f.genesis.genesis,
        fingerprint: f.genesis.fingerprint,
        purpose: 2,
        height: 1,
        mining_epoch: 1,
        continuity_period: 0,
        round: 0,
        step: 3,
        previous_finalized_anchor: f.genesis.id(),
        parent: f.genesis.block,
        block: header.block_hash(),
        state: prepared.execution.root,
        membership: height_authority.membership,
        reputation: height_authority.reputation,
        attestation: height_authority.attestation,
    };
    let mut vote = Vote {
        decision: decision.clone(),
        nil: false,
        node: *node,
        hardware_generation: voter.hardware_generation,
        key_generation: voter.key_generation,
        sequence: 10,
        tpm_identity: voter.tpm_identity(),
        profile: voter.profile,
        signature: empty(),
    };
    vote.sign(&f.continuity).unwrap();
    BlockEnvelope {
        header,
        body: prepared.body,
        authority,
        certificate: Certificate {
            decision,
            votes: vec![vote],
        },
    }
}

#[test]
fn wallet_host_signed_payment_authenticated_node_confirmation_and_restart() {
    assert!(mutinyd_v8::production_gate::require_production_ready().is_err());
    let f = fixture();
    let mut random = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
    let base = std::env::temp_dir().join(format!("build8-host-wallet-{}", hex::encode(random)));
    assert!(
        mutiny_consensus_v8::submission_pool_v1::SubmissionPool::private_directory(&base).unwrap(),
        "fixture owns only a new protected directory"
    );
    let session = Session::restore_initial(&phrase()).unwrap();
    let identity = session.identity().clone();
    let mut vault = Store::open(&base.join("WalletCustodyV2/wallet-hybrid-v2.sqlite")).unwrap();
    vault.save_initial(&session, PASSWORD).unwrap();
    drop(vault);
    drop(session);
    println!("HOST_WALLET_STEP disposable encrypted custody created");
    let mut wallet = controller(&base, &f);
    assert!(wallet.verified_balance().is_err());
    assert!(wallet.unlock("WRONG PUBLIC PASSWORD").is_err());
    wallet.unlock(PASSWORD).unwrap();
    assert_eq!(wallet.identity(), Some(&identity));
    assert_eq!(wallet.verified_balance().unwrap().available_atoms, 100_000);
    let (id, screen) = pay(&mut wallet, [94; 32], 50_000);
    let change_atoms = screen.review.returned();
    let fee_atoms = screen.review.fee().atoms;
    let expected = wallet.pending_for_transport().unwrap();
    assert_eq!(expected.len(), 1);
    assert_eq!(wallet.verified_balance().unwrap().reserved_atoms, 100_000);
    assert_eq!(
        wallet.delivery(id).unwrap(),
        Delivery::Unconfirmed(Some(Status::Pending))
    );
    println!("HOST_WALLET_STEP reviewed payment dual-signed and durably queued");
    // Close private custody and both wallet databases before any delivery.
    drop(wallet);
    let mut wallet = controller(&base, &f);
    assert_eq!(wallet.pending_for_transport().unwrap(), expected);
    assert!(wallet.identity().is_none());
    let node = runtime(&base, &f);
    let a = HybridKey::generate(Role::Transport).unwrap();
    let b = HybridKey::generate(Role::Transport).unwrap();
    let (mut client, mut server, _pin) = pair(&base, &f, &a, &b);
    let offer = wallet.advertise_payment(&mut client, id, limit()).unwrap();
    assert!(
        wallet
            .reclaim_confirmed_payment(&mut client, offer.id)
            .is_err()
    );
    request_from_node(&mut server, &offer);
    turn(&mut wallet, &mut client); // receive request; no private session needed
    turn(&mut wallet, &mut client); // persist one fragment then interrupt the connection
    assert!(matches!(
        hybrid_dispatch_v2::poll_peer(&node, &mut server, limit()).unwrap(),
        Some(DispatchEvent::Transport(Event::FragmentReceived))
    ));
    let first_session = client.link.with_current(|link| link.session_id()).unwrap();
    drop(client);
    drop(server);
    let (mut client, mut server, _pin) = pair(&base, &f, &a, &b);
    assert_ne!(
        client.link.with_current(|link| link.session_id()).unwrap(),
        first_session
    );
    let replay_offer = wallet.advertise_payment(&mut client, id, limit()).unwrap();
    assert_eq!(replay_offer.id, offer.id);
    request_from_node(&mut server, &offer);
    turn(&mut wallet, &mut client);
    let remaining = server
        .with_current(|link| {
            link.missing_window(&offer.id, 0, offer.length.div_ceil(MAX_PAYLOAD) as u16)
        })
        .unwrap()
        .unwrap()
        .bits
        .into_iter()
        .filter(|missing| *missing)
        .count();
    assert_eq!(remaining, offer.length.div_ceil(MAX_PAYLOAD) - 1);
    for index in 0..remaining {
        turn(&mut wallet, &mut client); // one authenticated fragment per turn
        let event = hybrid_dispatch_v2::poll_peer(&node, &mut server, limit())
            .unwrap()
            .unwrap();
        if index + 1 == remaining {
            assert!(
                matches!(event, DispatchEvent::TransactionAccepted { id: accepted, status: Status::Pending, .. } if accepted == id)
            );
        } else {
            assert!(matches!(
                event,
                DispatchEvent::Transport(Event::FragmentReceived)
            ));
        }
    }
    assert_eq!(node.lock().unwrap().confirmed_height(id).unwrap(), None);
    println!("HOST_WALLET_STEP authenticated loopback node admission accepted; unconfirmed");
    assert_eq!(
        wallet.delivery(id).unwrap(),
        Delivery::Unconfirmed(Some(Status::Pending))
    );
    let envelope = certify(&node, &f);
    let raw = envelope.encode().unwrap();
    assert_eq!(envelope.body.transactions, expected);
    let result = node.lock().unwrap().install(&raw).unwrap();
    assert!(result.inserted);
    assert_eq!(node.lock().unwrap().confirmed_height(id).unwrap(), Some(1));
    println!("HOST_WALLET_STEP assembled synthetic work accepted and canonically finalized");
    // The node's confirmation cannot change the wallet until authenticated replay.
    assert_eq!(
        wallet.delivery(id).unwrap(),
        Delivery::Unconfirmed(Some(Status::Pending))
    );
    let (history, result) = send_history(&mut wallet, &mut client, &mut server, &raw);
    assert!(matches!(
        result,
        Ok(Progress::History { inserted: true, .. })
    ));
    assert_eq!(wallet.delivery(id).unwrap(), Delivery::ConfirmedAt(1));
    assert!(wallet.pending_for_transport().unwrap().is_empty());
    wallet.unlock(PASSWORD).unwrap();
    let balance = wallet.verified_balance().unwrap();
    assert_eq!(balance.available_atoms, change_atoms);
    assert_eq!(balance.reserved_atoms, 0);
    let context = egui::Context::default();
    context
        .run_ui(Default::default(), |ui| {
            wallet.show_payment_status(ui, id).unwrap()
        })
        .drop_without_applying_deltas();
    let public_restart = serde_json::json!({"synthetic_only":true, "production_authorized":false,
        "genesis":hex::encode(f.genesis.encode()), "root":hex::encode(f.state.root().unwrap()),
        "records":f.state.records().unwrap().into_iter().map(|(key,record)|serde_json::json!({"key":hex::encode(key),"record":hex::encode(record)})).collect::<Vec<_>>(),
        "transaction":hex::encode(id), "available_atoms":change_atoms});
    std::fs::write(
        base.join("restart-public.json"),
        serde_json::to_vec(&public_restart).unwrap(),
    )
    .unwrap();
    drop(wallet);
    drop(node);
    drop(client);
    drop(server);
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "wallet_controller_v2::host::tests::wallet_host_restart_child",
            "--nocapture",
        ])
        .env("BUILD8_HOST_RESTART_PUBLIC", &base)
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "fresh process failed: {} {}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
    assert!(String::from_utf8_lossy(&child.stdout).contains("HOST_WALLET_RESTART_PASS"));
    println!(
        "HOST_WALLET_STEP fresh process reopened custody, node, wallet, outbox; confirmation and balance preserved"
    );
    let mut wallet = controller(&base, &f);
    let node = runtime(&base, &f);
    assert_eq!(wallet.delivery(id).unwrap(), Delivery::ConfirmedAt(1));
    assert_eq!(node.lock().unwrap().confirmed_height(id).unwrap(), Some(1));
    assert!(!node.lock().unwrap().install(&raw).unwrap().inserted);
    let (mut client, mut server, pin) = pair(&base, &f, &a, &b);
    assert!(matches!(
        wallet.retry_peer_history(&mut client, history.id),
        Ok(Progress::History {
            inserted: false,
            ..
        })
    ));
    wallet
        .reclaim_confirmed_payment(&mut client, offer.id)
        .unwrap();
    assert!(
        client
            .link
            .with_current(|link| link.completed(&offer.id))
            .unwrap()
            .is_err()
    );
    // An authenticated transport sender still cannot forge canonical finality.
    let mut bad = envelope.clone();
    bad.certificate.votes[0].signature.fndsa[0] ^= 1;
    let (_, result) = send_history(
        &mut wallet,
        &mut client,
        &mut server,
        &bad.encode().unwrap(),
    );
    assert!(result.is_err());
    assert_eq!(wallet.delivery(id).unwrap(), Delivery::ConfirmedAt(1));
    drop(client);
    drop(server);
    drop(pin);
    let (mut client, server, pin) = pair(&base, &f, &a, &b);
    assert!(matches!(
        wallet.retry_peer_history(&mut client, history.id),
        Ok(Progress::History {
            inserted: false,
            ..
        })
    ));
    pin.replace_peers(vec![]).unwrap();
    assert!(wallet.retry_peer_history(&mut client, history.id).is_err());
    assert_eq!(wallet.delivery(id).unwrap(), Delivery::ConfirmedAt(1));
    drop(client);
    drop(server);
    drop(pin);
    let (mut client, server, pin) = pair(&base, &f, &a, &b);
    assert!(matches!(
        wallet.reclaim_peer_history(&mut client, history.id),
        Ok(Progress::History {
            inserted: false,
            ..
        })
    ));
    assert!(
        client
            .link
            .with_current(|link| link.completed(&history.id))
            .unwrap()
            .is_err()
    );
    assert_eq!(wallet.delivery(id).unwrap(), Delivery::ConfirmedAt(1));
    assert!(mutinyd_v8::production_gate::require_production_ready().is_err());
    println!(
        "HOST_WALLET_PASS tx={} height=1 available={} fee={} synthetic_only=true production_authorized=false",
        hex::encode(id),
        change_atoms,
        fee_atoms
    );
    drop(wallet);
    drop(node);
    drop(client);
    drop(server);
    drop(pin);
    // Test owns this exact fresh random directory; no installed wallet lookup.
    assert!(base.starts_with(std::env::temp_dir()));
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn wallet_host_restart_child() {
    let Some(base) = std::env::var_os("BUILD8_HOST_RESTART_PUBLIC") else {
        return;
    };
    let base = std::path::PathBuf::from(base);
    assert_eq!(base.parent(), Some(std::env::temp_dir().as_path()));
    assert!(
        base.file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("build8-host-wallet-")
    );
    let f: serde_json::Value =
        serde_json::from_slice(&std::fs::read(base.join("restart-public.json")).unwrap()).unwrap();
    assert_eq!(f["synthetic_only"], true);
    assert_eq!(f["production_authorized"], false);
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
    let root = raw(&f["root"]).try_into().unwrap();
    let records: Vec<_> = f["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
        .collect();
    let state = State::from_records(&records, root).unwrap();
    let open_chain = |name: &str| {
        CanonicalStore::open_trusted_genesis(
            &base.join(name),
            &genesis,
            &state,
            root,
            1000,
            [255; 32],
        )
        .unwrap()
    };
    let open_pool = |name: &str| {
        Mempool::open(
            &base.join(name),
            genesis.genesis,
            genesis.fingerprint,
            64 * 1024 * 1024,
        )
        .unwrap()
    };
    let node = HybridRuntime::from_pinned_chain(
        open_chain("node-chain.sqlite"),
        open_pool("node-pool.sqlite"),
    )
    .unwrap();
    let (operations, preimages) = custody_stores(&base, &genesis);
    let mut wallet = Controller::new(
        Store::open(&base.join("WalletCustodyV2/wallet-hybrid-v2.sqlite")).unwrap(),
        Replica::from_pinned_chain(open_chain("wallet-chain.sqlite")).unwrap(),
        open_pool("wallet-outbox.sqlite"),
        operations,
        preimages,
        None,
    )
    .unwrap();
    let id = raw(&f["transaction"]).try_into().unwrap();
    assert!(wallet.identity().is_none());
    assert_eq!(wallet.delivery(id).unwrap(), Delivery::ConfirmedAt(1));
    assert_eq!(node.confirmed_height(id).unwrap(), Some(1));
    assert!(wallet.pending_for_transport().unwrap().is_empty());
    wallet.unlock(PASSWORD).unwrap();
    assert_eq!(
        wallet.verified_balance().unwrap().available_atoms,
        f["available_atoms"].as_u64().unwrap()
    );
    assert!(mutinyd_v8::production_gate::require_production_ready().is_err());
    println!("HOST_WALLET_RESTART_PASS synthetic_only=true production_authorized=false");
}

#[test]
fn wallet_host_multiwindow_history_requires_canonical_finality() {
    let f = fixture();
    let mut random = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
    let base = std::env::temp_dir().join(format!(
        "build8-host-wallet-windows-{}",
        hex::encode(random)
    ));
    assert!(
        mutiny_consensus_v8::submission_pool_v1::SubmissionPool::private_directory(&base).unwrap(),
        "fixture owns only a new protected directory"
    );
    let mut wallet = controller(&base, &f);
    let a = HybridKey::generate(Role::Transport).unwrap();
    let b = HybridKey::generate(Role::Transport).unwrap();
    let (mut client, mut server, _pin) = pair(&base, &f, &a, &b);
    let raw = vec![0u8; MAX_PAYLOAD * (mutiny_transport_v2::objects::MAX_BITMAP_BITS as usize + 2)];
    let (_, result) = send_history(&mut wallet, &mut client, &mut server, &raw);
    assert!(result.is_err());
    assert_eq!(wallet.replica.current_anchor().unwrap(), f.genesis);
    assert!(wallet.pending_for_transport().unwrap().is_empty());
    assert!(wallet.identity().is_none());
    println!("HOST_WALLET_MULTIWINDOW_PASS windows=2 forged_history_rejected=true");
    drop(wallet);
    drop(client);
    drop(server);
    assert!(base.starts_with(std::env::temp_dir()));
    std::fs::remove_dir_all(base).unwrap();
}

#[test]
fn wallet_host_readiness_at_idle_boundary_keeps_complete_frame_budget() {
    let f = fixture();
    let mut random = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
    let base =
        std::env::temp_dir().join(format!("build8-wallet-readiness-{}", hex::encode(random)));
    assert!(
        mutiny_consensus_v8::submission_pool_v1::SubmissionPool::private_directory(&base).unwrap(),
        "fixture owns only a new protected directory"
    );
    let mut wallet = controller(&base, &f);
    let a = HybridKey::generate(Role::Transport).unwrap();
    let b = HybridKey::generate(Role::Transport).unwrap();
    let (mut client, mut server, pin) = pair(&base, &f, &a, &b);
    let (_, have) = server
        .with_current(|link| link.enqueue(ObjectKind::CertifiedBlock, &[77; 200], 0))
        .unwrap()
        .unwrap();
    server.send(&have, limit()).unwrap();
    // Deterministically reproduce a scheduler pause after readiness, with no
    // frame bytes consumed. The old shared idle deadline fails this test.
    client.after_readiness_delay = TURN_LIMIT + Duration::from_millis(20);
    let idle_limit = Instant::now() + TURN_LIMIT;
    assert!(matches!(
        wallet.peer_turn(&mut client, idle_limit).unwrap(),
        Some(Progress::Transport)
    ));
    assert!(Instant::now() > idle_limit);
    assert!(wallet.peer_turn(&mut client, limit()).unwrap().is_none());
    let received = server.receive(limit()).unwrap();
    server
        .dispatch_received(received, |_, event| {
            assert!(matches!(event, Event::Requested))
        })
        .unwrap();
    assert!(wallet.identity().is_none());
    drop(wallet);
    drop(client);
    drop(server);
    drop(pin);
    assert!(base.starts_with(std::env::temp_dir()));
    std::fs::remove_dir_all(base).unwrap();
}

/// G3: a failed turn keeps the transport's expiry discriminant; every other failure keeps its diagnostic
/// with the same prefix as before (injected typed failures; the origin is tested in the node crate).
#[test]
fn g3_peer_turn_failure_context_keeps_only_the_typed_expiry() {
    assert_eq!(context("Wallet fragment", PeerFailure::SessionExpired), PeerFailure::SessionExpired);
    assert_eq!(
        context("Wallet fragment", PeerFailure::Other("Peer send: Closed".into())),
        PeerFailure::Other("Wallet fragment: Peer send: Closed".into())
    );
    assert_eq!(
        context("Wallet outgoing fragment", PeerFailure::Other("Expired".into())),
        PeerFailure::Other("Wallet outgoing fragment: Expired".into())
    );
    // The String API is the same diagnostic text as before.
    assert_eq!(String::from(PeerFailure::Other("x: y".into())), "x: y");
}
/// G3 command paths: `guarded` keeps the action's typed expiry and turns only a guard refusal into
/// `Other`; every typed command (advertise, query, retry, reclaim) flattens through it.
#[test]
fn g3_command_paths_keep_the_typed_expiry_through_the_pin_guard() {
    let expired: Result<PeerResult<u8>> = Ok(Err(PeerFailure::SessionExpired));
    assert_eq!(guarded(expired), Err(PeerFailure::SessionExpired));
    let guard: Result<PeerResult<u8>> = Err("Peer closed".into());
    assert_eq!(guarded(guard), Err(PeerFailure::Other("Peer closed".into())));
    let text: Result<PeerResult<u8>> = Err("Expired".into());
    assert_eq!(guarded(text), Err(PeerFailure::Other("Expired".into())));
    let semantic: Result<PeerResult<u8>> = Ok(Err("Payment has no local canonical confirmation".into()));
    assert_eq!(guarded(semantic), Err(PeerFailure::Other("Payment has no local canonical confirmation".into())));
    let fine: Result<PeerResult<u8>> = Ok(Ok(7));
    assert_eq!(guarded(fine), Ok(7));
    // The actual transport discriminant, as produced inside the typed command closures.
    assert_eq!(PeerFailure::transport("Wallet completed object", mutiny_transport_v2::Error::Expired), PeerFailure::SessionExpired);
    assert!(matches!(PeerFailure::transport("Wallet completed object", mutiny_transport_v2::Error::Context), PeerFailure::Other(_)));
}
/// G3 receive-callback operations: a link whose chosen operation fails with an exact transport error.
struct FailingHistoryLink {
    request: Option<fn() -> mutiny_transport_v2::Error>,
    complete: Option<fn() -> mutiny_transport_v2::Error>,
    window: Option<fn() -> mutiny_transport_v2::Error>,
    /// `next_missing_request` answers None (object already complete) when no failure is set for it.
    request_none: bool,
}
impl HistoryLink for FailingHistoryLink {
    fn next_missing_request(&mut self, _: &Hash, _: u8, _: bool)
        -> mutiny_transport_v2::Result<Option<mutiny_transport_v2::object_link::RequestWindow>> {
        match self.request {
            Some(e) => Err(e()),
            None if self.request_none => Ok(None),
            None => Ok(Some(mutiny_transport_v2::object_link::RequestWindow { start: 0, count: 1, frame: vec![1] })),
        }
    }
    fn missing_window(&self, _: &Hash, start: u16, _: u16) -> mutiny_transport_v2::Result<mutiny_transport_v2::objects::Bitmap> {
        match self.window {
            Some(e) => Err(e()),
            None => Ok(mutiny_transport_v2::objects::Bitmap { start, bits: vec![false] }),
        }
    }
    fn completed(&self, _: &Hash) -> mutiny_transport_v2::Result<(Offer, Vec<u8>)> {
        Err(self.complete.map_or(mutiny_transport_v2::Error::Context, |e| e()))
    }
}
fn history_offer(kind: ObjectKind) -> Offer {
    Offer { id: [5; 32], kind, length: 1 }
}

#[test]
fn g3_each_receive_callback_operation_keeps_the_typed_expiry_and_other_failures_stay_other() {
    use mutiny_transport_v2::Error;
    let f = fixture();
    let mut random = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
    let base = std::env::temp_dir().join(format!("build8-host-g3-callback-{}", hex::encode(random)));
    assert!(mutiny_consensus_v8::submission_pool_v1::SubmissionPool::private_directory(&base).unwrap());
    let mut wallet = controller(&base, &f);
    let offered = || Event::Offered(history_offer(ObjectKind::CertifiedBlock));
    // (operation, link, event, expected Other prefix) for each of the four link operations.
    let cases: Vec<(&str, Box<dyn Fn(fn() -> Error) -> FailingHistoryLink>, Box<dyn Fn() -> Event>, bool)> = vec![
        ("Wallet history request", Box::new(|e| FailingHistoryLink { request: Some(e), complete: None, window: None, request_none: false }), Box::new(offered), false),
        ("Wallet completed history", Box::new(|e| FailingHistoryLink { request: None, complete: Some(e), window: None, request_none: true }), Box::new(offered), false),
        ("Wallet history progress", Box::new(|e| FailingHistoryLink { request: None, complete: None, window: Some(e), request_none: false }), Box::new(|| Event::FragmentReceived), true),
        ("Wallet next history window", Box::new(|e| FailingHistoryLink { request: Some(e), complete: None, window: None, request_none: false }), Box::new(|| Event::FragmentReceived), true),
    ];
    for (operation, make, event, needs_window) in &cases {
        let errors: [(fn() -> Error, bool); 4] = [(|| Error::Expired, true), (|| Error::Context, false), (|| Error::Replay, false), (|| Error::Limit, false)];
        for (error, expiry) in errors {
            let mut windows = BTreeMap::new();
            if *needs_window {
                windows.insert([5; 32], (0u16, 1u16));
            }
            let before = windows.clone();
            let mut link = make(error);
            let failure = wallet.history_event(&mut link, &mut windows, event()).unwrap_err();
            if expiry {
                assert_eq!(failure, PeerFailure::SessionExpired, "{operation}");
            } else {
                assert_eq!(failure, PeerFailure::Other(format!("{operation}: {:?}", error())), "{operation}");
            }
            // A failed callback leaves the transfer windows exactly as they were.
            assert_eq!(windows, before, "{operation}");
        }
    }
    // Semantic refusals are Other, never expiry, even when their text mentions it.
    let mut link = FailingHistoryLink { request: None, complete: None, window: None, request_none: false };
    let refused = wallet.history_event(&mut link, &mut BTreeMap::new(), Event::Offered(history_offer(ObjectKind::SignedTransaction))).unwrap_err();
    assert_eq!(refused, PeerFailure::Other("Unexpected wallet history offer".into()));
    // Successful operations still behave as before.
    let mut windows = BTreeMap::new();
    let (progress, reply) = wallet.history_event(&mut link, &mut windows, offered()).unwrap();
    assert!(matches!(progress, Progress::Transport) && reply == Some(vec![1]) && windows.contains_key(&[5; 32]));
    // Canonical state untouched by every refusal above.
    assert_eq!(wallet.replica.current_anchor().unwrap(), f.genesis);
    drop(wallet);
    assert!(base.starts_with(std::env::temp_dir()));
    std::fs::remove_dir_all(base).unwrap();
}

/// G3 shutdown: a peer that goes away is an ordinary (non-expiry) failure; the wallet closes its link,
/// keeps canonical state, and a later turn on the closed link refuses without being reported as expiry.
#[test]
fn g3_peer_departure_is_not_expiry_and_closes_the_wallet_link_cleanly() {
    let f = fixture();
    let mut random = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
    let base = std::env::temp_dir().join(format!("build8-host-g3-shutdown-{}", hex::encode(random)));
    assert!(mutiny_consensus_v8::submission_pool_v1::SubmissionPool::private_directory(&base).unwrap());
    let mut wallet = controller(&base, &f);
    let a = HybridKey::generate(Role::Transport).unwrap();
    let b = HybridKey::generate(Role::Transport).unwrap();
    let (mut client, mut server, _pin) = pair(&base, &f, &a, &b);
    server.close();
    drop(server);
    let deadline = Instant::now() + Duration::from_secs(10);
    let failure = loop {
        match wallet.peer_turn_typed(&mut client, limit()) {
            Err(failure) => break failure,
            Ok(_) => assert!(Instant::now() < deadline, "peer departure was not observed"),
        }
    };
    assert!(matches!(failure, PeerFailure::Other(_)), "{failure:?}");
    let again = wallet.peer_turn_typed(&mut client, limit()).unwrap_err();
    assert!(matches!(again, PeerFailure::Other(_)), "{again:?}");
    assert_eq!(wallet.replica.current_anchor().unwrap(), f.genesis);
    drop(wallet);
    drop(client);
    assert!(base.starts_with(std::env::temp_dir()));
    std::fs::remove_dir_all(base).unwrap();
}
/// B1 over a real loopback history session: the node is Forge's autonomous history owner (no manual
/// scheduling), the wallet is the history client over its own store. The wallet asks at once,
/// verifies and commits the planned block itself, then finds the tip on its 10 s idle refresh.
#[test]
fn b1_wallet_history_client_catches_up_from_the_autonomous_node_and_refreshes_at_the_tip() {
    use crate::history_sync::{PageStatus, REFRESH, State as SyncState};
    use history::HistoryProgress;
    let f = fixture();
    let mut random = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
    let base = std::env::temp_dir().join(format!("build8-b1-wallet-{}", hex::encode(random)));
    assert!(mutiny_consensus_v8::submission_pool_v1::SubmissionPool::private_directory(&base).unwrap());
    let mut wallet = controller(&base, &f);
    let (node, expected) = history_node(&base, &f);
    assert_eq!(wallet.replica.current_anchor().unwrap(), f.genesis);
    let (mut peer, worker, _registries) = history_pair(&base, &f.genesis, &node);

    let deadline = Instant::now() + Duration::from_secs(120);
    let mut history = wallet.history_open(&mut peer, Instant::now()).unwrap();
    assert_eq!(history.sync().active(), Some(1), "catch-up asks at once on connect");
    let mut seen = Vec::new();
    while history.sync().saved() < 1 || !matches!(history.sync().state(), SyncState::Current { .. }) {
        assert!(Instant::now() < deadline, "bounded catch-up; seen {seen:?}");
        assert!(!worker.is_finished(), "the autonomous node must stay up");
        match wallet.history_turn(&mut peer, &mut history, Instant::now()).unwrap() {
            HistoryProgress::Idle | HistoryProgress::Transport => {}
            other => seen.push(other),
        }
    }
    assert_eq!(seen.first(), Some(&HistoryProgress::Page { status: PageStatus::Page, entries: 1 }), "{seen:?}");
    assert_eq!(seen.last(), Some(&HistoryProgress::Installed { kind: ObjectKind::CertifiedBlock, height: 1 }), "{seen:?}");
    assert_eq!(wallet.replica.current_anchor().unwrap(), expected, "the wallet's own verified store reached the node's head");
    // Request retired after plan admission, verified candidate reclaimed through its proof, page retired.
    let room = peer.link.with_current(|l| l.history_general_capacity()).unwrap().unwrap();
    assert_eq!(
        (room.free_objects, room.free_bytes),
        (mutiny_transport_v2::objects::MAX_OBJECTS, mutiny_transport_v2::objects::MAX_QUEUE_BYTES),
        "every history transport copy on the wallet side is released"
    );

    // Nothing more until the idle refresh is due; then a new sequence finds the snapshot tip.
    assert_eq!(wallet.history_turn(&mut peer, &mut history, Instant::now()).unwrap(), HistoryProgress::Idle);
    let later = Instant::now() + REFRESH;
    assert_eq!(wallet.history_turn(&mut peer, &mut history, later).unwrap(), HistoryProgress::Requested { sequence: 2 });
    let tip = loop {
        assert!(Instant::now() < deadline, "bounded refresh");
        match wallet.history_turn(&mut peer, &mut history, later).unwrap() {
            HistoryProgress::Page { status, entries } => break (status, entries),
            HistoryProgress::Idle | HistoryProgress::Transport => {}
            other => panic!("unexpected refresh progress {other:?}"),
        }
    };
    assert_eq!(tip, (PageStatus::AtSnapshotTip, 0));
    assert!(matches!(history.sync().state(), SyncState::Current { .. }));
    assert_eq!(history.sync().saved(), 1);
    assert_eq!(wallet.replica.current_anchor().unwrap(), expected);

    worker.shutdown_typed().unwrap();
    peer.close();
    drop(peer);
    drop(wallet);
    drop(node);
    assert!(base.starts_with(std::env::temp_dir()));
    std::fs::remove_dir_all(base).unwrap();
}
/// A fixture node at height 1 (block over whatever its pool holds) and its head.
fn history_node(base: &Path, f: &Fixture) -> (std::sync::Arc<Mutex<HybridRuntime>>, FinalizedAnchor) {
    let node = std::sync::Arc::new(runtime(base, f));
    let raw = certify_pending(&node, f).encode().unwrap();
    assert!(node.lock().unwrap().install(&raw).unwrap().inserted);
    let expected = node.lock().unwrap().head().unwrap();
    assert_eq!(expected.height, 1);
    (node, expected)
}
/// A real loopback B1 connection: the wallet's history-profile peer on its own V9 queue, and Forge's
/// autonomous history node owner (no manual scheduling) serving `node`.
fn history_pair(
    base: &Path,
    chain: &FinalizedAnchor,
    node: &std::sync::Arc<Mutex<HybridRuntime>>,
) -> (WalletPeer, mutinyd_v8::hybrid_peer_worker_v2::Worker, [Registry; 2]) {
    use mutinyd_v8::{history_service_v1::HistoryBudget, hybrid_peer_worker_v2::Worker};
    let a = HybridKey::generate(Role::Transport).unwrap();
    let b = HybridKey::generate(Role::Transport).unwrap();
    let pa = Endpoint::pinned(a.public().clone(), 1).unwrap();
    let pb = Endpoint::pinned(b.public().clone(), 1).unwrap();
    let (genesis, fingerprint) = (chain.genesis, chain.fingerprint);
    let outgoing = Registry::new_wallet_history_client(genesis, fingerprint, pa.clone(), vec![pb.clone()], 1, 1).unwrap();
    let incoming = Registry::new_wallet_history_clients(genesis, fingerprint, pb.clone(), vec![pa.clone()], 1, 1).unwrap();
    let pending = incoming.begin().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let accepted = listener.accept().unwrap().0;
    drop(listener);
    let (client, server) = std::thread::scope(|scope| {
        let responder = scope.spawn(|| pending.respond(pa.id(), accepted, &b, Duration::from_secs(30)).unwrap());
        let client = outgoing.begin().unwrap().initiate(pb.id(), stream, &a, Duration::from_secs(30)).unwrap();
        (client, responder.join().unwrap())
    });
    let wallet_queue = ObjectQueue::open_history(&base.join("wallet-history.sqlite"), client.peer_id(), false, true).unwrap();
    let node_queue = ObjectQueue::open_history(&base.join("node-history.sqlite"), server.peer_id(), false, true).unwrap();
    let peer = WalletPeer::new(client.attach(wallet_queue).unwrap());
    let worker = Worker::start_history_node_typed(server, node_queue, node.clone(), HistoryBudget::default()).unwrap();
    // The registries hold the pins every turn is checked against: they live as long as the link.
    (peer, worker, [outgoing, incoming])
}

/// Multi-page B1 on the public recovery chain (block 1, recovery evidence at height 1, block 2). With a
/// two-entry receiver budget the node can only page whole groups: MORE [block 1], then PAGE [recovery,
/// block 2]. The wallet asks again at once after MORE and installs recovery before its block.
#[test]
fn b1_wallet_history_client_pages_the_recovery_chain_in_order_under_a_small_budget() {
    use crate::history_sync::{PageStatus, State as SyncState};
    use history::HistoryProgress;
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../../qualification/hybrid-recovery-chain-public-v4.json")).unwrap();
    assert_eq!(v["synthetic_only"], true);
    assert_eq!(v["production_authorized"], false);
    assert_eq!(v["physical_tpm"], false);
    let raw = |x: &serde_json::Value| hex::decode(x.as_str().unwrap()).unwrap();
    let root: Hash = raw(&v["root"]).try_into().unwrap();
    let records: Vec<_> = v["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
        .collect();
    let state = State::from_records(&records, root).unwrap();
    let genesis = FinalizedAnchor::decode(&raw(&v["genesis_anchor"])).unwrap();
    let mut random = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
    let base = std::env::temp_dir().join(format!("build8-b1-pages-{}", hex::encode(random)));
    assert!(mutiny_consensus_v8::submission_pool_v1::SubmissionPool::private_directory(&base).unwrap());
    let chain = |name: &str| {
        CanonicalStore::open_trusted_genesis(&base.join(name), &genesis, &state, root, 1000, [255; 32]).unwrap()
    };
    let pool = |name: &str| Mempool::open(&base.join(name), genesis.genesis, genesis.fingerprint, 64 * 1024 * 1024).unwrap();
    let node = std::sync::Arc::new(Mutex::new(
        HybridRuntime::from_pinned_chain(chain("node-chain.sqlite"), pool("node-pool.sqlite")).unwrap(),
    ));
    {
        let mut node = node.lock().unwrap();
        node.install(&raw(&v["block1"])).unwrap();
        node.accept_recovery(&raw(&v["recovery1"])).unwrap();
        node.install(&raw(&v["block2"])).unwrap();
    }
    let expected = node.lock().unwrap().head().unwrap();
    assert_eq!(expected.height, 2);
    let (operations, preimages) = custody_stores(&base, &genesis);
    let mut wallet = Controller::new(
        Store::open(&base.join("WalletCustodyV2/wallet-hybrid-v2.sqlite")).unwrap(),
        Replica::from_pinned_chain(chain("wallet-chain.sqlite")).unwrap(),
        pool("wallet-outbox.sqlite"),
        operations,
        preimages,
        None,
    )
    .unwrap();
    assert_eq!(wallet.replica.current_anchor().unwrap(), genesis);
    let (mut peer, worker, registries) = history_pair(&base, &genesis, &node);
    let deadline = Instant::now() + Duration::from_secs(300);
    let mut history = wallet.history_open_bounded(&mut peer, Instant::now(), 2).unwrap();
    let mut seen = Vec::new();
    while history.sync().saved() < 2 || !matches!(history.sync().state(), SyncState::Current { .. }) {
        assert!(Instant::now() < deadline, "bounded multi-page catch-up; seen {seen:?}");
        assert!(!worker.is_finished(), "the autonomous node must stay up");
        match wallet.history_turn(&mut peer, &mut history, Instant::now()).unwrap() {
            HistoryProgress::Idle | HistoryProgress::Transport => {}
            other => seen.push(other),
        }
    }
    assert_eq!(
        seen,
        vec![
            HistoryProgress::Page { status: PageStatus::More, entries: 1 },
            HistoryProgress::Installed { kind: ObjectKind::CertifiedBlock, height: 1 },
            HistoryProgress::Page { status: PageStatus::Page, entries: 2 },
            HistoryProgress::Installed { kind: ObjectKind::RecoveryEvidence, height: 1 },
            HistoryProgress::Installed { kind: ObjectKind::CertifiedBlock, height: 2 },
        ]
    );
    assert_eq!(wallet.replica.current_anchor().unwrap(), expected);
    let room = peer.link.with_current(|l| l.history_general_capacity()).unwrap().unwrap();
    assert_eq!(
        (room.free_objects, room.free_bytes),
        (mutiny_transport_v2::objects::MAX_OBJECTS, mutiny_transport_v2::objects::MAX_QUEUE_BYTES)
    );
    assert!(wallet.history_open_bounded(&mut peer, Instant::now(), 0).is_err());
    peer.close();
    let _ = worker.shutdown_typed();
    drop(peer);
    drop(registries);
    drop(wallet);
    drop(node);
    assert!(base.starts_with(std::env::temp_dir()));
    std::fs::remove_dir_all(base).unwrap();
}
/// Payment egress while the B1 client owns the link: the reviewed, durably queued payment is advertised
/// on the history session, the client's turn serves the node's fragment requests, the autonomous node
/// admits it, and the payment becomes confirmed ONLY when the wallet's own replay installs the block that
/// includes it (fetched by the client's ordinary refresh). No status report is used or believed.
#[test]
fn b1_payment_egress_on_the_history_session_is_confirmed_only_by_own_replay() {
    use crate::history_sync::{REFRESH, State as SyncState};
    use history::HistoryProgress;
    let f = fixture();
    let mut random = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
    let base = std::env::temp_dir().join(format!("build8-b1-pay-{}", hex::encode(random)));
    assert!(mutiny_consensus_v8::submission_pool_v1::SubmissionPool::private_directory(&base).unwrap());
    let session = Session::restore_initial(&phrase()).unwrap();
    let mut vault = Store::open(&base.join("WalletCustodyV2/wallet-hybrid-v2.sqlite")).unwrap();
    vault.save_initial(&session, PASSWORD).unwrap();
    drop(vault);
    drop(session);
    let mut wallet = controller(&base, &f);
    wallet.unlock(PASSWORD).unwrap();
    let node = std::sync::Arc::new(runtime(&base, &f));
    let (mut peer, worker, registries) = history_pair(&base, &f.genesis, &node);
    let deadline = Instant::now() + Duration::from_secs(180);
    let mut history = wallet.history_open(&mut peer, Instant::now()).unwrap();
    // The node is at Genesis too: the first page is the snapshot tip.
    while !matches!(history.sync().state(), SyncState::Current { .. }) {
        assert!(Instant::now() < deadline, "initial tip");
        wallet.history_turn(&mut peer, &mut history, Instant::now()).unwrap();
    }
    let (id, _) = pay(&mut wallet, [94; 32], 50_000);
    assert_eq!(wallet.delivery(id).unwrap(), Delivery::Unconfirmed(Some(Status::Pending)));
    let offer = wallet.advertise_payment_typed(&mut peer, id, Instant::now() + Duration::from_secs(30)).unwrap();
    // Serve the node's requests from the history turn until every fragment is acknowledged.
    let fragments = offer.length.div_ceil(MAX_PAYLOAD) as u16;
    loop {
        assert!(Instant::now() < deadline, "payment egress");
        assert!(!worker.is_finished(), "the autonomous node must stay up");
        let progress = wallet.history_turn(&mut peer, &mut history, Instant::now()).unwrap();
        // The 10 s idle refresh may run meanwhile; the node is still at Genesis, so nothing installs.
        assert!(!matches!(progress, HistoryProgress::Installed { .. }), "{progress:?}");
        let acked = peer.link.with_current(|l| l.acknowledged(&offer.id, 0, fragments)).unwrap().unwrap();
        if acked.bits.iter().all(|bit| *bit) {
            break;
        }
    }
    assert_eq!(wallet.delivery(id).unwrap(), Delivery::Unconfirmed(Some(Status::Pending)), "a receipt is not confirmation");
    // The node admitted it: its next block (height 1) includes exactly this payment.
    let block = loop {
        assert!(Instant::now() < deadline, "node admission");
        let envelope = certify_pending(&node, &f);
        if !envelope.body.transactions.is_empty() {
            break envelope;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(block.body.transactions, wallet.pending_for_transport().unwrap());
    assert!(node.lock().unwrap().install(&block.encode().unwrap()).unwrap().inserted);
    assert_eq!(node.lock().unwrap().confirmed_height(id).unwrap(), Some(1));
    assert_eq!(wallet.delivery(id).unwrap(), Delivery::Unconfirmed(Some(Status::Pending)), "the node's finality is not the wallet's");
    // Only the client's own refresh and replay confirm it.
    let later = Instant::now() + REFRESH;
    while history.sync().saved() < 1 {
        assert!(Instant::now() < deadline, "refresh and replay");
        wallet.history_turn(&mut peer, &mut history, later).unwrap();
    }
    assert_eq!(wallet.delivery(id).unwrap(), Delivery::ConfirmedAt(1));
    peer.close();
    let _ = worker.shutdown_typed();
    drop(peer);
    drop(registries);
    drop(wallet);
    drop(node);
    assert!(base.starts_with(std::env::temp_dir()));
    std::fs::remove_dir_all(base).unwrap();
}