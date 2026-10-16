use super::*;
use mutiny_consensus_v8::{
    anchors::FinalizedAnchor, block_envelope_v2::BlockEnvelope, canonical_store_v2::CanonicalStore,
    execution::State, mempool_v2::Mempool,
};
use mutiny_crypto_v2::{HybridKey, Role};
use mutiny_transport_v2::{
    Context, Endpoint, InitiatorPending, MAX_PAYLOAD, ResponderPending, objects::ObjectQueue,
};
fn pair(
    genesis: Hash,
    fingerprint: Hash,
    a: &HybridKey,
    b: &HybridKey,
) -> (mutiny_transport_v2::Session, mutiny_transport_v2::Session) {
    let context = Context::pinned(
        genesis,
        fingerprint,
        Endpoint::pinned(a.public().clone(), 1).unwrap(),
        Endpoint::pinned(b.public().clone(), 1).unwrap(),
    )
    .unwrap();
    let (initiator, hello) = InitiatorPending::start(context.clone(), a).unwrap();
    let (responder, response) = ResponderPending::accept(context, b, &hello).unwrap();
    let (initiator, finish) = initiator.accept(a, &response).unwrap();
    let (responder, tag) = responder.finish(&finish).unwrap();
    (initiator.finish(&tag).unwrap(), responder)
}
#[test]
fn hybrid_tcp_objects_require_canonical_validation_before_confirmation() {
    use crate::hybrid_peer_admission_v2::Registry;
    use std::{
        net::{TcpListener, TcpStream},
        time::{Duration, Instant},
    };
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
    let b = HybridKey::generate(Role::Transport).unwrap();
    let runtime = std::sync::Mutex::new(runtime);
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
    let server = std::thread::spawn(move || {
        pending
            .respond(pa.id(), server, &b, Duration::from_secs(30))
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
    let mut send = client.attach(send_queue).unwrap();
    let mut recv = server.attach(recv_queue).unwrap();
    let limit = || Instant::now() + Duration::from_secs(5);
    // An idle socket never waits for or holds the canonical actor.
    {
        let _held = runtime.lock().unwrap();
        assert!(matches!(
            poll_peer(
                &runtime,
                &mut recv,
                Instant::now() + Duration::from_millis(20)
            ),
            Ok(None)
        ));
    }
    let mut deliver = |kind: ObjectKind, bytes: &[u8]| {
        let (offer, have) = send
            .with_current(|link| link.enqueue(kind, bytes, 0))
            .unwrap()
            .unwrap();
        send.send(&have, limit()).unwrap();
        let received = recv.receive(limit()).unwrap();
        let want = recv
            .dispatch_received(received, |link, event| {
                assert!(matches!(event, Event::Offered(_)));
                link.next_missing_request(&offer.id, 0, false)
                    .unwrap()
                    .unwrap()
                    .frame
            })
            .unwrap();
        let count = offer.length.div_ceil(MAX_PAYLOAD) as u16;
        assert!(count <= 1080); // This fixture fits one bounded request window.
        recv.send(&want, limit()).unwrap();
        let requested = send.receive(limit()).unwrap();
        assert!(
            send.dispatch_received(requested, |_, event| matches!(event, Event::Requested))
                .unwrap()
        );
        let mut completed = None;
        for index in 0..count {
            let frame = send
                .with_current(|link| link.send_one())
                .unwrap()
                .unwrap()
                .unwrap();
            send.send(&frame, limit()).unwrap();
            // Actual service turn receives outside the actor, then dispatches
            // under the current-pin guard after bounded actor acquisition.
            let outcome = poll_peer(&runtime, &mut recv, limit());
            if index + 1 == count {
                completed = Some(outcome.map(|value| value.expect("frame arrived")))
            } else {
                assert!(matches!(
                    outcome,
                    Ok(Some(DispatchEvent::Transport(Event::FragmentReceived)))
                ));
            }
        }
        let outcome = completed.unwrap();
        let receipt = recv
            .with_current(|link| link.receipt(&offer.id, 0, count, 0))
            .unwrap()
            .unwrap();
        recv.send(&receipt, limit()).unwrap();
        let received = send.receive(limit()).unwrap();
        assert!(
            send.dispatch_received(received, |_, event| matches!(event, Event::ReceiptRecorded))
                .unwrap()
        );
        outcome
    };
    assert!(matches!(
        deliver(ObjectKind::SignedTransaction, b"confirmed"),
        Err(DispatchError::Runtime(_))
    ));
    assert_eq!(runtime.lock().unwrap().head().unwrap(), genesis);
    assert_eq!(runtime.lock().unwrap().confirmed_height(id).unwrap(), None);
    assert!(matches!(
        deliver(
            ObjectKind::SignedTransaction,
            &envelope.body.transactions[0]
        ),
        Ok(DispatchEvent::TransactionAccepted {
            status: Status::Pending,
            ..
        })
    ));
    assert_eq!(runtime.lock().unwrap().head().unwrap(), genesis);
    assert_eq!(runtime.lock().unwrap().confirmed_height(id).unwrap(), None);
    assert!(matches!(
        deliver(ObjectKind::CertifiedBlock, &raw(&f["envelope"])),
        Ok(DispatchEvent::BlockInstalled { .. })
    ));
    assert_eq!(
        runtime.lock().unwrap().confirmed_height(id).unwrap(),
        Some(1)
    );
    drop(deliver);
    // A received event cannot wait indefinitely for a busy actor or mutate it
    // after the service deadline. Existing canonical history stays unchanged.
    {
        let actor = runtime.lock().unwrap();
        let before = actor.head().unwrap();
        let (_, have) = send
            .with_current(|link| {
                link.enqueue(ObjectKind::WorkProbeRequest, b"bounded actor wait", 0)
            })
            .unwrap()
            .unwrap();
        send.send(&have, limit()).unwrap();
        assert!(matches!(
            poll_peer(
                &runtime,
                &mut recv,
                Instant::now() + Duration::from_millis(30)
            ),
            Err(DispatchError::ActorDeadline)
        ));
        assert_eq!(actor.head().unwrap(), before);
        assert!(recv.wait_for_frame(limit()).is_err());
    }
    drop(runtime);
    drop(send);
    drop(recv);
    println!("RETAINED_PUBLIC_HYBRID_TCP_DISPATCH_EVIDENCE={}", base.display());
}
fn deliver(
    runtime: &mut HybridRuntime,
    send: &mut ObjectLink,
    recv: &mut ObjectLink,
    kind: ObjectKind,
    bytes: &[u8],
) -> Result<DispatchEvent, DispatchError> {
    let (offer, have) = send.enqueue(kind, bytes, 0).unwrap();
    let mut damaged = have.clone();
    *damaged.last_mut().unwrap() ^= 1;
    assert!(matches!(
        receive(runtime, recv, &damaged),
        Err(DispatchError::Transport(_))
    ));
    assert!(matches!(
        receive(runtime, recv, &have),
        Ok(DispatchEvent::Transport(Event::Offered(_)))
    ));
    assert!(matches!(
        receive(runtime, recv, &have),
        Err(DispatchError::Transport(mutiny_transport_v2::Error::Replay))
    ));
    let count = offer.length.div_ceil(MAX_PAYLOAD) as u16;
    assert!(count <= 1080);
    let want = recv.request_missing(&offer.id, 0, count, 0, false).unwrap();
    send.receive(&want).unwrap();
    let mut result = None;
    for n in 0..count {
        let frame = send.send_one().unwrap().unwrap();
        let event = receive(runtime, recv, &frame);
        if n + 1 == count {
            result = Some(event);
        } else {
            assert!(matches!(
                event,
                Ok(DispatchEvent::Transport(Event::FragmentReceived))
            ));
        }
    }
    assert!(send.send_one().unwrap().is_none());
    // Delivery acknowledgement remains a transport event, including for an
    // object that will fail canonical semantic validation at the destination.
    let receipt = recv.receipt(&offer.id, 0, count, 0).unwrap();
    assert!(matches!(send.receive(&receipt), Ok(Event::ReceiptRecorded)));
    result.unwrap()
}
#[test]
fn authenticated_fragment_delivery_requires_independent_transaction_and_block_validation() {
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
    let mut nonce = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let base = std::env::temp_dir().join(format!("build8-hybrid-dispatch-{}", hex::encode(nonce)));
    assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
    let mut runtime = HybridRuntime::from_pinned_chain(
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
    let b = HybridKey::generate(Role::Transport).unwrap();
    let (initiator, responder) = pair(genesis.genesis, genesis.fingerprint, &a, &b);
    let send = ObjectQueue::open(&base.join("send.sqlite"), initiator.peer_id()).unwrap();
    let recv = ObjectQueue::open(&base.join("recv.sqlite"), responder.peer_id()).unwrap();
    let mut send = ObjectLink::new(initiator, send).unwrap();
    let mut recv = ObjectLink::new(responder, recv).unwrap();
    qualify_probe_dispatch(&runtime, &mut send, &mut recv, &genesis);
    assert!(matches!(
        deliver(
            &mut runtime,
            &mut send,
            &mut recv,
            ObjectKind::SignedTransaction,
            b"confirmed"
        ),
        Err(DispatchError::Runtime(_))
    ));
    assert_eq!(runtime.head().unwrap(), genesis);
    assert_eq!(runtime.confirmed_height(id).unwrap(), None);
    let fault = rusqlite::Connection::open(base.join("pool.sqlite")).unwrap();
    fault
        .execute_batch("CREATE TABLE unexpected(id INTEGER)")
        .unwrap();
    assert!(matches!(
        deliver(
            &mut runtime,
            &mut send,
            &mut recv,
            ObjectKind::SignedTransaction,
            &envelope.body.transactions[0]
        ),
        Err(DispatchError::Runtime(_))
    ));
    assert_eq!(runtime.confirmed_height(id).unwrap(), None);
    fault.execute_batch("DROP TABLE unexpected").unwrap();
    drop(fault);
    let object = mutiny_transport_v2::objects::object_id(
        ObjectKind::SignedTransaction,
        &envelope.body.transactions[0],
    )
    .unwrap();
    // Close both transport databases and discard session keys. A fresh hybrid
    // handshake rebinds the same pinned peer before retrying persisted bytes.
    drop(send);
    drop(recv);
    let (initiator, responder) = pair(genesis.genesis, genesis.fingerprint, &a, &b);
    let send_queue = ObjectQueue::open(&base.join("send.sqlite"), initiator.peer_id()).unwrap();
    let recv_queue = ObjectQueue::open(&base.join("recv.sqlite"), responder.peer_id()).unwrap();
    let mut send = ObjectLink::new(initiator, send_queue).unwrap();
    let mut recv = ObjectLink::new(responder, recv_queue).unwrap();
    let accepted = retry_completed(&mut runtime, &recv, &object).unwrap();
    assert!(
        matches!(accepted,DispatchEvent::TransactionAccepted{id:got,status:Status::Pending,..} if got==id)
    );
    assert_eq!(runtime.head().unwrap(), genesis);
    assert_eq!(runtime.confirmed_height(id).unwrap(), None);
    let mut bad = envelope.clone();
    bad.header.candidate.state_root[0] ^= 1;
    assert!(matches!(
        deliver(
            &mut runtime,
            &mut send,
            &mut recv,
            ObjectKind::CertifiedBlock,
            &bad.encode().unwrap()
        ),
        Err(DispatchError::Runtime(_))
    ));
    assert_eq!(runtime.head().unwrap(), genesis);
    assert_eq!(runtime.confirmed_height(id).unwrap(), None);
    let installed = deliver(
        &mut runtime,
        &mut send,
        &mut recv,
        ObjectKind::CertifiedBlock,
        &envelope.encode().unwrap(),
    )
    .unwrap();
    assert!(matches!(
        installed,
        DispatchEvent::BlockInstalled {
            result: Installation { inserted: true, .. },
            ..
        }
    ));
    assert_eq!(
        runtime.head().unwrap(),
        envelope.certificate.decision.anchor()
    );
    assert_eq!(runtime.confirmed_height(id).unwrap(), Some(1));
    let block_object = mutiny_transport_v2::objects::object_id(
        ObjectKind::CertifiedBlock,
        &envelope.encode().unwrap(),
    )
    .unwrap();
    assert!(matches!(
        retry_completed(&mut runtime, &recv, &block_object).unwrap(),
        DispatchEvent::BlockInstalled {
            result: Installation {
                inserted: false,
                ..
            },
            ..
        }
    ));
    assert!(retry_completed(&mut runtime, &recv, &[0; 32]).is_err());
    drop(send);
    drop(recv);
    drop(runtime);
    println!("RETAINED_PUBLIC_HYBRID_NATIVE_DISPATCH_EVIDENCE={}", base.display());
}

fn qualify_probe_dispatch(
    runtime: &HybridRuntime,
    send: &mut ObjectLink,
    recv: &mut ObjectLink,
    parent: &FinalizedAnchor,
) {
    use crate::hybrid_probe_dispatch_v2::{ProbeEvent, receive};
    use crate::hybrid_work_probes_v2::WorkProbes;
    use mutiny_consensus_v8::liveness_v2::WorkGate;
    let (authority, root) = runtime.chain.current_liveness(parent).unwrap();
    let decision = WorkGate::new(authority.clone(), root, 0)
        .unwrap()
        .request(0, [89; 32])
        .unwrap()
        .unwrap();
    let mut pool = WorkProbes::default();
    for case in 0..5 {
        let mut d = decision.clone();
        let (kind, bytes) = match case {
            0 => (ObjectKind::WorkProbeRequest, d.encode()),
            1 => {
                d.purpose = 2;
                (ObjectKind::WorkProbeRequest, d.encode())
            }
            2 => {
                d.state[0] ^= 1;
                (ObjectKind::WorkProbeRequest, d.encode())
            }
            3 => {
                d.parent[0] ^= 1;
                (ObjectKind::WorkProbeRequest, d.encode())
            }
            _ => (ObjectKind::WorkProbeFragment, vec![0]),
        };
        let (offer, have) = send.enqueue(kind, &bytes, 0).unwrap();
        let mut bad = have.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(receive(runtime, &mut pool, recv, &bad, 0).is_err());
        assert!(matches!(
            receive(runtime, &mut pool, recv, &have, 0).unwrap(),
            ProbeEvent::Transport(Event::Offered(_))
        ));
        assert!(receive(runtime, &mut pool, recv, &have, 0).is_err());
        let count = offer.length.div_ceil(MAX_PAYLOAD) as u16;
        let want = recv.request_missing(&offer.id, 0, count, 0, false).unwrap();
        send.receive(&want).unwrap();
        let mut result = None;
        for n in 0..count {
            let frame = send.send_one().unwrap().unwrap();
            let event = receive(runtime, &mut pool, recv, &frame, 0);
            if n + 1 == count {
                result = Some(event);
            } else {
                assert!(matches!(
                    event.unwrap(),
                    ProbeEvent::Transport(Event::FragmentReceived)
                ));
            }
        }
        if case == 0 {
            let ProbeEvent::RequestQueued { receipt } = result.unwrap().unwrap() else {
                panic!("Expected queued request");
            };
            assert!(matches!(
                send.receive(&receipt).unwrap(),
                Event::ReceiptRecorded
            ));
            assert!(
                send.acknowledged(&offer.id, 0, count)
                    .unwrap()
                    .bits
                    .iter()
                    .all(|v| *v)
            );
            let pending = pool.pending([0; 32], &authority, root, 0).unwrap();
            assert_eq!(pending, vec![(Some(recv.peer_id()), decision.clone())]);
        } else {
            assert!(result.unwrap().is_err());
        }
        // Valid and invalid ephemeral completed objects are removed, preserving
        // capacity; the original valid peer request survives malformed traffic.
        assert!(recv.completed(&offer.id).is_err());
        assert!(pool.quorum(&authority, root, 0).unwrap().is_none());
        send.discard(&offer.id).unwrap();
    }
}

#[test]
fn encrypted_probe_fragments_need_both_signatures_before_gate_acceptance() {
    use crate::hybrid_probe_dispatch_v2::{ProbeEvent, receive};
    use crate::hybrid_work_probes_v2::WorkProbes;
    use mutiny_consensus_v8::liveness_v2::{Proof, WorkGate, WorkState};
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/hybrid-work-network-public-v1.json"
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
    let proof = Proof::decode(&raw(&f["proof"])).unwrap();
    let mut nonce = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let base = std::env::temp_dir().join(format!("build8-probe-dispatch-{}", hex::encode(nonce)));
    assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
    let mut runtime = HybridRuntime::from_pinned_chain(
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
    let b = HybridKey::generate(Role::Transport).unwrap();
    let (i, r) = pair(genesis.genesis, genesis.fingerprint, &a, &b);
    let send_peer = i.peer_id();
    let mut send = ObjectLink::new(
        i,
        ObjectQueue::open(&base.join("send.sqlite"), send_peer).unwrap(),
    )
    .unwrap();
    let recv_peer = r.peer_id();
    let mut recv = ObjectLink::new(
        r,
        ObjectQueue::open(&base.join("recv.sqlite"), recv_peer).unwrap(),
    )
    .unwrap();
    // Authenticated foreign-network frames must not enter the actor's local
    // queue/status path, even with the same admitted endpoint identities.
    for (index,(g,fp)) in [([9;32],genesis.fingerprint),(genesis.genesis,[9;32])].into_iter().enumerate() {
        let (i,r)=pair(g,fp,&a,&b);let ip=i.peer_id();let rp=r.peer_id();
        let sp=base.join(format!("foreign-{index}-send.sqlite"));let rp_path=base.join(format!("foreign-{index}-recv.sqlite"));
        let mut wrong_send=ObjectLink::new(i,ObjectQueue::open(&sp,ip).unwrap()).unwrap();let mut wrong_recv=ObjectLink::new(r,ObjectQueue::open(&rp_path,rp).unwrap()).unwrap();
        let query=mutiny_consensus_v8::submission_v1::encode_query(&[[3;32]]).unwrap();let (offer,have)=wrong_send.enqueue(ObjectKind::StatusQuery,&query,0).unwrap();
        assert!(matches!(super::receive(&mut runtime,&mut wrong_recv,&have),Err(DispatchError::Admission(_))));
        assert!(wrong_recv.describe(&offer.id).is_err());assert_eq!(runtime.head().unwrap(),genesis);
        drop(wrong_send);drop(wrong_recv);
    }
    let authority = runtime.current_authority(&genesis).unwrap();
    let mut gate = WorkGate::new(authority.clone(), root, 0).unwrap();
    gate.set_run(true);
    assert_eq!(
        gate.request(0, proof.decision.block).unwrap().unwrap(),
        proof.decision
    );
    let mut pool = WorkProbes::default();
    pool.begin(proof.decision.clone(), &authority, root, 0)
        .unwrap();
    for case in 0..5 {
        let mut p = proof.clone();
        match case {
            0 => p.fragments[0].signature.ed448[0] ^= 1,
            1 => p.fragments[0].signature.fndsa[0] ^= 1,
            2 => p.decision.block[0] ^= 1,
            _ => {}
        }
        let (offer, have) = send
            .enqueue(ObjectKind::WorkProbeFragment, &p.encode().unwrap(), 0)
            .unwrap();
        assert!(matches!(
            receive(&runtime, &mut pool, &mut recv, &have, 0).unwrap(),
            ProbeEvent::Transport(Event::Offered(_))
        ));
        let count = offer.length.div_ceil(MAX_PAYLOAD) as u16;
        let want = recv.request_missing(&offer.id, 0, count, 0, false).unwrap();
        send.receive(&want).unwrap();
        let mut result = None;
        for n in 0..count {
            let frame = send.send_one().unwrap().unwrap();
            let event = receive(&runtime, &mut pool, &mut recv, &frame, 0);
            if n + 1 == count {
                result = Some(event);
            } else {
                assert!(matches!(
                    event.unwrap(),
                    ProbeEvent::Transport(Event::FragmentReceived)
                ));
            }
        }
        if case < 3 {
            assert!(result.unwrap().is_err());
            assert!(pool.quorum(&authority, root, 0).unwrap().is_none());
            assert_eq!(gate.state(0).unwrap(), WorkState::WaitingQuorum);
        } else {
            let ProbeEvent::FragmentAccepted { receipt } = result.unwrap().unwrap() else {
                panic!("Expected fragment");
            };
            assert!(matches!(
                send.receive(&receipt).unwrap(),
                Event::ReceiptRecorded
            ));
            let quorum = pool.quorum(&authority, root, 0).unwrap().unwrap();
            assert_eq!(quorum, proof);
            gate.accept(0, &quorum).unwrap();
            assert_eq!(gate.state(0).unwrap(), WorkState::Running);
        }
        assert!(recv.completed(&offer.id).is_err());
        send.discard(&offer.id).unwrap();
    }
    assert_eq!(gate.state(360_000).unwrap(), WorkState::WaitingQuorum);
    drop(send);
    drop(recv);
    drop(runtime);
    println!("RETAINED_PUBLIC_HYBRID_PROBE_DISPATCH_EVIDENCE={}", base.display());
}
