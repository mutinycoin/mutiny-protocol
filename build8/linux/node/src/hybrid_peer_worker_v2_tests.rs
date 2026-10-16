use super::*;
use crate::hybrid_peer_admission_v2::Registry;
use mutiny_consensus_v8::{
    anchors::FinalizedAnchor,
    block_envelope_v2::BlockEnvelope,
    canonical_store_v2::CanonicalStore,
    execution::State,
    mempool_v2::{Mempool, Status},
};
use mutiny_crypto_v2::{HybridKey, Role};
use mutiny_transport_v2::Endpoint;
use std::net::{TcpListener, TcpStream};
fn next(worker: &Worker) -> Notification {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        match worker.try_notification() {
            Ok(value) => return value,
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => panic!("public fixture worker disconnected: {:?}", worker.exit_result()),
        }
        assert!(
            Instant::now() < deadline,
            "bounded public fixture event wait"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}
fn submit(worker: &Worker, mut command: Command) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match worker.try_submit(command) {
            Ok(()) => return,
            Err(error) if error.reason == "Peer command backpressure" => {
                assert!(Instant::now() < deadline, "bounded producer retry expired");
                command = error.command;
                std::thread::sleep(Duration::from_millis(2));
            }
            Err(error) => panic!("{}", error.reason),
        }
    }
}
#[test]
fn hybrid_worker_paced_objects_canonical_confirmation_and_consumer_backpressure() {
    exercise(false, false, false);
}
#[test]
fn hybrid_worker_notification_failure_preserves_committed_block() {
    exercise(true, false, false);
}
#[test]
fn hybrid_worker_graceful_shutdown_releases_owned_connection() {
    exercise(false, true, false);
}
#[test]
fn hybrid_worker_maximum_object_durable_windows_preserve_canonical_authority() {
    exercise(false, true, true);
}
fn exercise(drop_completion_notice: bool, graceful: bool, maximum_object: bool) {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/hybrid-canonical-store-public-v1.json"
    ))
    .unwrap();
    assert_eq!(f["synthetic_only"], true);
    assert_eq!(f["production_authorized"], false);
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let root: Hash = raw(&f["root"]).try_into().unwrap();
    let rows: Vec<_> = f["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
        .collect();
    let state = State::from_records(&rows, root).unwrap();
    let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
    let envelope = BlockEnvelope::decode(&raw(&f["envelope"])).unwrap();
    let id: Hash = raw(&f["transaction_id"]).try_into().unwrap();
    let mut random = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
    let base = std::env::temp_dir().join(format!("build8-tcp-canonical-{}", hex::encode(random)));
    assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
    let runtime = HybridRuntime::from_pinned_chain(
        CanonicalStore::open_trusted_genesis(
            &base.join("chain.sqlite"),
            &genesis,
            &state,
            root,
            1000,
            [255; 32],
        )
        .unwrap(),
        Mempool::open(
            &base.join("pool.sqlite"),
            genesis.genesis,
            genesis.fingerprint,
            64 * 1024 * 1024,
        )
        .unwrap(),
    )
    .unwrap();
    let a = HybridKey::generate(Role::Transport).unwrap();
    let b = Arc::new(HybridKey::generate(Role::Transport).unwrap());
    let runtime = Arc::new(Mutex::new(runtime));
    let pa = Endpoint::pinned(a.public().clone(), 1).unwrap();
    let pb = Endpoint::pinned(b.public().clone(), 1).unwrap();
    let outgoing = Registry::new(
        genesis.genesis,
        genesis.fingerprint,
        pa.clone(),
        vec![pb.clone()],
        1,
        1,
    )
    .unwrap();
    let incoming = Registry::new(
        genesis.genesis,
        genesis.fingerprint,
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
    let responder_key = b.clone();
    let remote_peer = pa.id();
    let server = std::thread::spawn(move || {
        pending
            .respond(remote_peer, server, &responder_key, Duration::from_secs(30))
            .unwrap()
    });
    let client = outgoing
        .begin()
        .unwrap()
        .initiate(pb.id(), client, &a, Duration::from_secs(30))
        .unwrap();
    let server = server.join().unwrap();
    let send_queue = ObjectQueue::open(&base.join("send.sqlite"), client.peer_id()).unwrap();
    let recv_queue = ObjectQueue::open(&base.join("recv.sqlite"), server.peer_id()).unwrap();
    let sender = Worker::start(client, send_queue, runtime.clone()).unwrap();
    let receiver = Worker::start(server, recv_queue, runtime.clone()).unwrap();
    assert!(
        sender
            .try_submit(Command::Enqueue {
                kind: ObjectKind::WorkProbeRequest,
                bytes: vec![0; 513]
            })
            .is_err()
    );
    let deliver = |kind: ObjectKind, bytes: Vec<u8>| {
        submit(&sender, Command::Enqueue { kind, bytes });
        let Notification::Advertised(offer) = next(&sender) else {
            panic!("expected advertised public object");
        };
        let Notification::Dispatched(DispatchEvent::Transport(Event::Offered(remote))) =
            next(&receiver)
        else {
            panic!("expected peer offer");
        };
        assert_eq!(remote, offer);
        submit(&receiver, Command::RequestMissing { object: offer.id });
        let Notification::RequestWindow {
            object,
            start,
            count,
        } = next(&receiver)
        else {
            panic!("expected bounded request");
        };
        assert_eq!(object, offer.id);
        assert_eq!(start, 0);
        assert_eq!(
            usize::from(count),
            offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD)
        );
        let Notification::Dispatched(outcome) = next(&receiver) else {
            panic!("expected validated or opaque complete object");
        };
        submit(
            &receiver,
            Command::Receipt {
                object,
                start,
                count,
            },
        );
        outcome
    };
    assert!(matches!(
        deliver(
            ObjectKind::WorkProbeRequest,
            b"public opaque probe".to_vec()
        ),
        DispatchEvent::Transport(Event::Completed { .. })
    ));
    assert_eq!(runtime.lock().unwrap().head().unwrap(), genesis);
    if maximum_object {
        use mutiny_transport_v2::{
            MAX_PAYLOAD,
            objects::{MAX_BITMAP_BITS, MAX_OBJECT_BYTES},
        };
        // Deliberately not a settlement proof: exact transport reconstruction
        // must leave canonical state unchanged until its own verifier accepts.
        let bytes: Vec<u8> = (0..MAX_OBJECT_BYTES).map(|i| (i % 251) as u8).collect();
        let started = Instant::now();
        submit(
            &sender,
            Command::Enqueue {
                kind: ObjectKind::SettlementProof,
                bytes: bytes.clone(),
            },
        );
        let Notification::Advertised(offer) = next(&sender) else {
            panic!("large offer")
        };
        assert!(
            matches!(next(&receiver), Notification::Dispatched(DispatchEvent::Transport(Event::Offered(got))) if got == offer)
        );
        let total = bytes.len().div_ceil(MAX_PAYLOAD) as u16;
        let mut expected_start = 0;
        let mut windows = 0u16;
        let mut queries = 0;
        loop {
            submit(&receiver, Command::RequestMissing { object: offer.id });
            let Notification::RequestWindow {
                object,
                start,
                count,
            } = next(&receiver)
            else {
                panic!("large window")
            };
            assert_eq!(object, offer.id);
            assert_eq!(start, expected_start);
            assert_eq!(count, (total - start).min(MAX_BITMAP_BITS));
            windows += 1;
            expected_start = start.checked_add(count).unwrap();
            if expected_start == total {
                let Notification::Dispatched(DispatchEvent::Transport(Event::Completed {
                    offer: got,
                    bytes: reconstructed,
                })) = next(&receiver)
                else {
                    panic!("opaque completion")
                };
                assert_eq!(got, offer);
                assert!(
                    reconstructed == bytes,
                    "exact maximum object reconstruction"
                );
                break;
            }
            let deadline = Instant::now() + Duration::from_secs(120);
            let mut previous = count;
            loop {
                assert!(Instant::now() < deadline, "bounded fragment window stalled");
                submit(
                    &receiver,
                    Command::QueryWindow {
                        object,
                        start,
                        count,
                    },
                );
                let Notification::WindowProgress {
                    object: got,
                    start: got_start,
                    count: got_count,
                    missing,
                } = next(&receiver)
                else {
                    panic!("durable progress")
                };
                assert_eq!((got, got_start, got_count), (object, start, count));
                assert!(missing <= previous);
                previous = missing;
                queries += 1;
                if missing == 0 {
                    break;
                }
                std::thread::sleep(Duration::from_millis(250));
            }
            submit(
                &receiver,
                Command::Receipt {
                    object,
                    start,
                    count,
                },
            );
        }
        assert_eq!(
            usize::from(windows),
            usize::from(total).div_ceil(usize::from(MAX_BITMAP_BITS))
        );
        submit(&receiver, Command::RequestMissing { object: offer.id });
        assert!(
            matches!(next(&receiver), Notification::NoMissingFragments { object } if object == offer.id)
        );
        assert_eq!(runtime.lock().unwrap().head().unwrap(), genesis);
        assert_eq!(runtime.lock().unwrap().confirmed_height(id).unwrap(), None);
        println!(
            "public maximum transport measurement: bytes={} fragments={} windows={} progress_queries={} elapsed_ms={}",
            bytes.len(),
            total,
            windows,
            queries,
            started.elapsed().as_millis()
        );
    }
    assert!(matches!(
        deliver(
            ObjectKind::SignedTransaction,
            envelope.body.transactions[0].clone()
        ),
        DispatchEvent::TransactionAccepted {
            status: Status::Pending,
            ..
        }
    ));
    assert_eq!(runtime.lock().unwrap().confirmed_height(id).unwrap(), None);
    if drop_completion_notice {
        submit(
            &sender,
            Command::Enqueue {
                kind: ObjectKind::CertifiedBlock,
                bytes: raw(&f["envelope"]),
            },
        );
        let Notification::Advertised(offer) = next(&sender) else {
            panic!("expected public block advertisement");
        };
        assert!(matches!(
            next(&receiver),
            Notification::Dispatched(DispatchEvent::Transport(Event::Offered(_)))
        ));
        submit(&receiver, Command::RequestMissing { object: offer.id });
        // Leave the request-window notification queued. Full canonical block
        // validation/commit still precedes the failed completion notification.
    } else {
        assert!(matches!(
            deliver(ObjectKind::CertifiedBlock, raw(&f["envelope"])),
            DispatchEvent::BlockInstalled { .. }
        ));
        assert_eq!(
            runtime.lock().unwrap().confirmed_height(id).unwrap(),
            Some(1)
        );
        // Deliberately stop consuming inbound offers. A second notification
        // closes the worker instead of growing a queue or blocking the actor.
        for n in 0..(if graceful { 0 } else { 2u8 }) {
            submit(
                &sender,
                Command::Enqueue {
                    kind: ObjectKind::WorkProbeRequest,
                    bytes: vec![n; 10],
                },
            );
            assert!(matches!(next(&sender), Notification::Advertised(_)));
        }
    }
    if drop_completion_notice {
        // The queued RequestWindow deliberately fills the event channel. Wait
        // for the atomic canonical commit before measuring notification closure;
        // a slow verification is not consumer backpressure or a protocol timeout.
        // Reuse the fixture's existing 120-second event bound (see next()).
        let commit_deadline = Instant::now() + Duration::from_secs(120);
        while runtime.lock().unwrap().confirmed_height(id).unwrap() != Some(1) {
            assert!(Instant::now() < commit_deadline, "public certified block did not commit");
            assert!(!receiver.is_finished(), "worker stopped before canonical commit: {:?}", receiver.exit_result());
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    while !graceful && !receiver.is_finished() {
        assert!(
            Instant::now() < deadline,
            "event backpressure did not close peer"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    if graceful {
        receiver.shutdown().unwrap();
    } else {
        assert!(receiver.shutdown().is_err());
    }
    let _ = sender.shutdown(); // remote close is a normal disconnect result here
    drop(incoming.begin().unwrap());
    drop(outgoing.begin().unwrap());
    assert_eq!(
        runtime.lock().unwrap().confirmed_height(id).unwrap(),
        Some(1)
    );
    // Reconnect with fresh traffic keys and the same authenticated public peer
    // queues. Durable completion is revalidated, never promoted to authority.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let socket = listener.accept().unwrap().0;
    let pending = incoming.begin().unwrap();
    let responder_key = b.clone();
    let server = std::thread::spawn(move || {
        pending
            .respond(remote_peer, socket, &responder_key, Duration::from_secs(30))
            .unwrap()
    });
    let client = outgoing
        .begin()
        .unwrap()
        .initiate(pb.id(), client, &a, Duration::from_secs(30))
        .unwrap();
    let server = server.join().unwrap();
    let tx = ObjectQueue::open(&base.join("send.sqlite"), client.peer_id()).unwrap();
    let rx = ObjectQueue::open(&base.join("recv.sqlite"), server.peer_id()).unwrap();
    let sender = Worker::start(client, tx, runtime.clone()).unwrap();
    let receiver = Worker::start(server, rx, runtime.clone()).unwrap();
    let object =
        mutiny_transport_v2::objects::object_id(ObjectKind::CertifiedBlock, &raw(&f["envelope"]))
            .unwrap();
    submit(&sender, Command::Advertise { object });
    assert!(matches!(
        next(&receiver),
        Notification::Dispatched(DispatchEvent::Transport(Event::Offered(_)))
    ));
    submit(&receiver, Command::RequestMissing { object });
    assert!(
        matches!(next(&receiver),Notification::NoMissingFragments{object:known} if known==object)
    );
    submit(&receiver, Command::RetryCompleted { object });
    assert!(
        matches!(next(&receiver),Notification::Dispatched(DispatchEvent::BlockInstalled{result,..}) if !result.inserted)
    );
    receiver.shutdown().unwrap();
    let _ = sender.shutdown();
    drop(incoming.begin().unwrap());
    drop(outgoing.begin().unwrap());
    drop(runtime);
    let reopened = HybridRuntime::from_pinned_chain(
        CanonicalStore::open_trusted_genesis(
            &base.join("chain.sqlite"),
            &genesis,
            &state,
            root,
            1000,
            [255; 32],
        )
        .unwrap(),
        Mempool::open(
            &base.join("pool.sqlite"),
            genesis.genesis,
            genesis.fingerprint,
            64 * 1024 * 1024,
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(reopened.confirmed_height(id).unwrap(), Some(1));
    drop(reopened);
    // Preserve the exact public TEST transport, canonical replay, pool and
    // protected archive evidence. Neither terminal shards nor sidecars are
    // removed merely because the delivery assertions completed.
    println!("RETAINED_PUBLIC_HYBRID_WORKER_EVIDENCE={} maximum_object={maximum_object}", base.display());
}
