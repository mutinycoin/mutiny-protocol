//! Actual authenticated TCP TEST-VALUE operation delivery and bounded relay.
#[path = "../../desktop/src/wallet_host_fixture_licenses.rs"]
mod licenses;
#[path = "../../consensus/tests/support/wallet_host_fixture_tpm.rs"]
mod tpm;
#[path = "support/stage2_builders.rs"]
mod wallet_builders;
include!("../../consensus/tests/support/dividend_rig.rs");
use mutiny_consensus_v8::submission_v1::{self as submission, Status, StatusReport};
use mutiny_transport_v2::{
    Endpoint,
    object_link::Event,
    objects::{ObjectKind, ObjectQueue},
};
use mutinyd_v8::submission_relay_v1::Relay;
use mutinyd_v8::{
    hybrid_dispatch_v2::{self, DispatchEvent},
    hybrid_peer_admission_v2::{PeerLink, Registry},
    hybrid_runtime_v2::{HybridRuntime, WorkRequest},
};
use std::{
    net::{TcpListener, TcpStream},
    time::{Duration, Instant},
};
fn sponsor_key() -> HybridKey {
    HybridKey::wallet_restore(
        &mutiny_crypto_v2::rehearsal_keys_v1::label_phrase("candidate3-public-stage2-node-sponsor")
            .unwrap(),
        Role::WalletOwner,
    )
    .unwrap()
}
fn clock() -> u64 {
    at(P + 1)
}
fn runtime(r: &Rig, name: &str, chain_path: &std::path::Path) -> HybridRuntime {
    HybridRuntime::from_pinned_chain_with_clock(
        CanonicalStore::open_trusted_genesis(
            chain_path,
            &r.f.genesis,
            &r.initial,
            r.initial_root,
            T0,
            [255; 32],
        )
        .unwrap(),
        Mempool::open(
            &r.base.join(format!("{name}-legacy.sqlite")),
            r.f.genesis.genesis,
            r.f.genesis.fingerprint,
            64 * 1024 * 1024,
        )
        .unwrap(),
        clock,
    )
    .unwrap()
}
fn peers(r: &Rig) -> (PeerLink, PeerLink, Registry, Registry) {
    let a = HybridKey::generate(Role::Transport).unwrap();
    let b = HybridKey::generate(Role::Transport).unwrap();
    let pa = Endpoint::pinned(a.public().clone(), 1).unwrap();
    let pb = Endpoint::pinned(b.public().clone(), 1).unwrap();
    let ra = Registry::new(
        r.f.genesis.genesis,
        r.f.genesis.fingerprint,
        pa.clone(),
        vec![pb.clone()],
        1,
        1,
    )
    .unwrap();
    let rb = Registry::new(
        r.f.genesis.genesis,
        r.f.genesis.fingerprint,
        pb.clone(),
        vec![pa.clone()],
        1,
        1,
    )
    .unwrap();
    let pending = rb.begin().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let server = listener.accept().unwrap().0;
    drop(listener);
    let responder = std::thread::spawn(move || {
        pending
            .respond(pa.id(), server, &b, Duration::from_secs(30))
            .unwrap()
    });
    let client = ra
        .begin()
        .unwrap()
        .initiate(pb.id(), client, &a, Duration::from_secs(30))
        .unwrap();
    let server = responder.join().unwrap();
    let aq = ObjectQueue::open(&r.base.join("a-peer.sqlite"), client.peer_id()).unwrap();
    let bq = ObjectQueue::open(&r.base.join("b-peer.sqlite"), server.peer_id()).unwrap();
    (
        client.attach(aq).unwrap(),
        server.attach(bq).unwrap(),
        ra,
        rb,
    )
}
fn limit() -> Instant {
    Instant::now() + Duration::from_secs(5)
}
fn canonical_rows(path: &std::path::Path) -> Vec<(String, Vec<Vec<String>>)> {
    use rusqlite::{Connection, OpenFlags, types::ValueRef};
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let mut q = db
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .unwrap();
    let names = q
        .query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    assert!(!names.is_empty());
    names
        .into_iter()
        .map(|name| {
            let mut q = db
                .prepare(&format!("SELECT * FROM \"{}\"", name.replace('"', "\"\"")))
                .unwrap();
            let count = q.column_count();
            let mut rows = q
                .query_map([], |r| {
                    (0..count)
                        .map(|i| {
                            Ok(match r.get_ref(i)? {
                                ValueRef::Null => "null".into(),
                                ValueRef::Integer(v) => format!("i:{v}"),
                                ValueRef::Real(v) => format!("r:{:016x}", v.to_bits()),
                                ValueRef::Text(v) => format!("t:{}", hex::encode(v)),
                                ValueRef::Blob(v) => format!("b:{}", hex::encode(v)),
                            })
                        })
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap();
            rows.sort();
            (name, rows)
        })
        .collect()
}
fn receive(runtime: &mut HybridRuntime, peer: &mut PeerLink) -> Result<DispatchEvent, String> {
    let event = peer.receive(limit())?;
    hybrid_dispatch_v2::dispatch_peer(runtime, peer, event).map_err(|e| format!("{e:?}"))
}
fn delivered(
    a: &mut HybridRuntime,
    b: &mut HybridRuntime,
    send: &mut PeerLink,
    recv: &mut PeerLink,
    have: Vec<u8>,
) -> Result<DispatchEvent, String> {
    send.send(&have, limit())?;
    let DispatchEvent::Transport(Event::Offered(offer)) = receive(b, recv)? else {
        return Err("Missing HAVE".into());
    };
    let window = recv
        .with_current(|link| link.next_missing_request(&offer.id, 0, false))?
        .map_err(|e| format!("request {e:?}"))?
        .ok_or("No missing window")?;
    recv.send(&window.frame, limit())?;
    assert!(matches!(
        receive(a, send)?,
        DispatchEvent::Transport(Event::Requested)
    ));
    let mut result = None;
    while let Some(frame) = send
        .with_current(|link| link.send_one())?
        .map_err(|e| format!("fragment {e:?}"))?
    {
        send.send(&frame, limit())?;
        let event = receive(b, recv)?;
        if !matches!(event, DispatchEvent::Transport(Event::FragmentReceived)) {
            result = Some(event);
        }
    }
    result.ok_or("No complete object".into())
}
#[test]
fn authenticated_tcp_native_claim_relay_dedup_status_hints_and_own_chain_finality() {
    let mut r = Rig::new(
        fixture_with_treasury(&treasury_key(), 1_200_000),
        "node-relay",
    );
    println!(
        "PUBLIC TEST-VALUE actual TCP evidence retained: {}",
        r.base.display()
    );
    r.step(P, &[]);
    let mut a = runtime(&r, "a", &r.base.join("chain.sqlite"));
    let mut b = runtime(&r, "b", &r.base.join("b-chain.sqlite"));
    b.install(
        &r.chain
            .canonical_block(1)
            .unwrap()
            .unwrap()
            .encode()
            .unwrap(),
    )
    .unwrap();
    let raw = claim_op(&r.f, &owner_key(), 0, P, 10_000, 0, addr(&second_key(), 1));
    let (id, status) = a.admit_submission(1, &raw).unwrap();
    assert_eq!(status, Status::Pending);
    let (mut send, mut recv, _ra, _rb) = peers(&r);
    assert!(
        send.with_current(|link| link.matches_network(r.parent.genesis, r.parent.fingerprint))
            .unwrap()
    );
    assert!(
        !send
            .with_current(|link| link.matches_network([9; 32], r.parent.fingerprint))
            .unwrap()
    );
    assert!(
        !send
            .with_current(|link| link.matches_network(r.parent.genesis, [9; 32]))
            .unwrap()
    );
    let mut relay = Relay::new(send.peer_id()).unwrap();
    let frames = send
        .with_current(|link| relay.prepare(&mut a, link))
        .unwrap()
        .unwrap();
    assert_eq!(frames.len(), 1);
    let (offer, have) = frames.into_iter().next().unwrap();
    assert_eq!(offer.kind, ObjectKind::SignedOperation);
    let accepted = delivered(&mut a, &mut b, &mut send, &mut recv, have).unwrap();
    assert!(
        matches!(accepted,DispatchEvent::OperationAccepted{id:got,status:Status::Pending,..} if got==id)
    );
    assert_eq!(
        b.exact_submission_bytes(id).unwrap(),
        Some((1, raw.clone()))
    );
    assert_eq!(a.submission_status(id).unwrap(), Status::Pending);
    assert_eq!(b.submission_status(id).unwrap(), Status::Pending);
    assert!(
        send.with_current(|link| relay.prepare(&mut a, link))
            .unwrap()
            .unwrap()
            .is_empty()
    );
    // A fresh relay owner recovers exact in-flight IDs from durable transport,
    // and still does not rebroadcast a different representation of that body.
    let mut restarted = Relay::new(send.peer_id()).unwrap();
    assert!(
        send.with_current(|link| restarted.prepare(&mut a, link))
            .unwrap()
            .unwrap()
            .is_empty()
    );
    let count = offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD) as u16;
    let ack = recv
        .with_current(|link| link.receipt(&offer.id, 0, count, 0))
        .unwrap()
        .unwrap();
    recv.send(&ack, limit()).unwrap();
    assert!(matches!(
        receive(&mut a, &mut send).unwrap(),
        DispatchEvent::Transport(Event::ReceiptRecorded)
    ));
    assert!(
        send.with_current(|link| restarted.prepare(&mut a, link))
            .unwrap()
            .unwrap()
            .is_empty()
    );
    assert!(
        send.with_current(|link| link.completed(&offer.id))
            .unwrap()
            .is_err()
    );
    assert_eq!(
        a.exact_submission_bytes(id).unwrap(),
        Some((1, raw.clone()))
    );
    // Query is 64 IDs; response is split into two canonical <=32-entry reports.
    let mut ids = vec![id];
    ids.extend((0..63).map(|n| [n; 32]));
    let query = submission::encode_query(&ids).unwrap();
    let (_, have) = send
        .with_current(|link| link.enqueue(ObjectKind::StatusQuery, &query, 0))
        .unwrap()
        .unwrap();
    let DispatchEvent::StatusQueryAnswered { reports, .. } =
        delivered(&mut a, &mut b, &mut send, &mut recv, have).unwrap()
    else {
        panic!("query not answered")
    };
    assert_eq!(reports.len(), 2);
    let parsed = StatusReport::decode(&reports[0]).unwrap();
    assert_eq!(parsed.entries[0].status, Status::Pending);
    let (_, have) = recv
        .with_current(|link| link.enqueue(ObjectKind::StatusReport, &reports[0], 0))
        .unwrap()
        .unwrap();
    assert!(matches!(
        delivered(&mut b, &mut a, &mut recv, &mut send, have).unwrap(),
        DispatchEvent::StatusHints { .. }
    ));
    assert_eq!(a.submission_status(id).unwrap(), Status::Pending);
    // A real locally validated journal proposal gives an unfinalized status,
    // while neither the status nor the transport ACK installs canonical state.
    let prepared = a
        .prepare(WorkRequest {
            expected_parent: &r.parent,
            license: r.f.license,
            worker: r.f.worker,
            timestamp: at(P + 1),
            ticket: r.ticket,
            operations: &[],
        })
        .unwrap();
    assert_eq!(prepared.body.operations, vec![raw.clone()]);
    let proposed = certify_at(prepared, &r.f, &r.parent, &r.state, r.ticket);
    let record = mutinyd_v8::candidate_journal_v2::Record {
        header: proposed.header.clone(),
        authority: proposed.authority.clone(),
        body: proposed.body.clone(),
    };
    let mut journal = mutinyd_v8::candidate_journal_v2::Journal::open(
        &r.base.join("candidate.sqlite"),
        r.parent.genesis,
        r.parent.fingerprint,
        mutinyd_v8::candidate_journal_v2::MAX_BYTES * 2,
        true,
    )
    .unwrap();
    journal.preserve(&a, &record).unwrap();
    assert_eq!(
        a.submission_status(id).unwrap(),
        Status::Unfinalized {
            height: 2,
            block: proposed.block_hash()
        }
    );
    assert_eq!(a.head().unwrap(), r.parent);
    // Failed block installation preserves pending object bytes and all chain roots.
    let mut bad = proposed.clone();
    bad.header.candidate.state_root[0] ^= 1;
    let before = a.head().unwrap();
    assert!(a.install(&bad.encode().unwrap()).is_err());
    assert_eq!(a.head().unwrap(), before);
    assert_eq!(
        a.exact_submission_bytes(id).unwrap(),
        Some((1, raw.clone()))
    );
    a.install(&proposed.encode().unwrap()).unwrap();
    let Status::Finalized(finalized) = a.submission_status(id).unwrap() else {
        panic!("not finalized")
    };
    // Even an accurate finalized peer report cannot finalize the receiver.
    let reports = a
        .status_reports(&submission::encode_query(&[id]).unwrap())
        .unwrap();
    let (_, have) = send
        .with_current(|link| link.enqueue(ObjectKind::StatusReport, &reports[0], 0))
        .unwrap()
        .unwrap();
    assert!(matches!(
        delivered(&mut a, &mut b, &mut send, &mut recv, have).unwrap(),
        DispatchEvent::StatusHints { .. }
    ));
    assert_eq!(b.submission_status(id).unwrap(), Status::Pending);
    b.install(&proposed.encode().unwrap()).unwrap();
    assert_eq!(
        b.submission_status(id).unwrap(),
        Status::Finalized(finalized.clone())
    );
    // Replayed encrypted frames are rejected before semantic dispatch.
    let (_, have) = send
        .with_current(|link| {
            link.enqueue(
                ObjectKind::StatusQuery,
                &submission::encode_query(&[id]).unwrap(),
                0,
            )
        })
        .unwrap()
        .unwrap();
    send.send(&have, limit()).unwrap();
    receive(&mut b, &mut recv).unwrap();
    send.send(&have, limit()).unwrap();
    assert!(recv.receive(limit()).is_err());
    assert_eq!(
        a.submission_status(id).unwrap(),
        Status::Finalized(finalized)
    );
    send.close();
    recv.close();
    drop(send);
    drop(recv);
    drop(journal);
    drop(a);
    drop(b);
    println!(
        "PUBLIC TEST-VALUE actual TCP evidence retained: {}",
        r.base.display()
    );
    drop(r);
}
#[test]
fn wallet_reviewed_carriers_cross_actual_node_tcp_and_blocks() {
    for case in 0..3 {
        run_wallet_reviewed_carrier(case);
    }
}
#[test]
fn post_sale_fresh_worker_crosses_actual_node_tcp_and_activates() {
    run_wallet_reviewed_carrier(3);
}
fn run_wallet_reviewed_carrier(case: u8) {
    use mutiny_consensus_v8::bonds::MINIMUM_ATOMS;
    use mutiny_wallet_core_v8::{ChainView, HeadInfo};
    let mut f = fixture_with_treasury(&treasury_key(), MINIMUM_ATOMS + 1_000_000);
    if case != 1 {
        f.state.wallets.register(&desc(&second_key(), 1)).unwrap();
    }
    f.state.coins.insert(
        OutPoint {
            transaction: [0xa2; 32],
            index: 0,
        },
        Coin {
            output: Output {
                owner: addr(&sponsor_key(), 1),
                atoms: 1_000_000,
            },
            created_height: 0,
            coinbase: false,
        },
    );
    f.state.coins.insert(
        OutPoint {
            transaction: [0xa1; 32],
            index: 0,
        },
        Coin {
            output: Output {
                owner: addr(&owner_key(), 1),
                atoms: MINIMUM_ATOMS + 100_000,
            },
            created_height: 0,
            coinbase: false,
        },
    );
    if case == 3 {
        f.state.coins.insert(
            OutPoint {
                transaction: [0xa3; 32],
                index: 0,
            },
            Coin {
                output: Output {
                    owner: addr(&second_key(), 1),
                    atoms: 1_000_000,
                },
                created_height: 0,
                coinbase: false,
            },
        );
    }
    let node = f.state.continuity.as_ref().unwrap().members[0].node;
    let mut r = Rig::new(f, "node-wallet-stage2");
    println!(
        "PUBLIC TEST-VALUE actual TCP evidence retained: {}",
        r.base.display()
    );
    r.step(P, &[]);
    let reserved = std::collections::BTreeSet::new();
    let sale_license = r
        .state
        .licenses_v2
        .licenses()
        .find(|l| l.id != r.f.license && l.id != r.f.backup_license)
        .unwrap()
        .id;
    if case == 3 {
        // Commit the epoch's entitlement/assignment transition before reviewing the sale.
        // A DVP must not silently rewrite its exact signed preconditions across an epoch.
        r.step(P + 1, &[]);
        let view = ChainView::new(
            HeadInfo::new(r.parent.clone(), at(P + 1), T0, r.state.root().unwrap()).unwrap(),
            &r.state,
            &reserved,
        );
        let sale = wallet_builders::license_sale(
            &view,
            owner_key(),
            second_key(),
            sale_license,
            50_000,
            [0xb4; 32],
        );
        std::fs::write(r.base.join("wallet-reviewed-sale.bin"), sale.bytes()).unwrap();
        let operations = [sale.bytes().to_vec()];
        let empty = r
            .chain
            .prepare_pending(Preparation {
                expected_parent: &r.parent,
                pool: &r.pool,
                license: r.f.license,
                worker: r.f.worker,
                timestamp: at(P + 1) + 1,
                ticket: r.ticket,
                operations: &[],
            })
            .unwrap();
        let diagnostic = mutiny_consensus_v8::trading_v1::prepare_candidate_phase(
            &r.state,
            &empty.execution.state,
            &r.parent,
            r.state.root().unwrap(),
            &Default::default(),
            &operations,
            &mutiny_consensus_v8::trading_v1::CandidatePolicy::native_denomination_locked(),
        );
        let diagnostic = format!(
            "Actual empty-candidate prospective state plus sale: {:?}",
            diagnostic.err()
        );
        println!("{diagnostic}");
        std::fs::write(r.base.join("sale-phase-diagnostic.txt"), diagnostic).unwrap();
        let prepared = r
            .chain
            .prepare_pending(Preparation {
                expected_parent: &r.parent,
                pool: &r.pool,
                license: r.f.license,
                worker: r.f.worker,
                timestamp: at(P + 1) + 1,
                ticket: r.ticket,
                operations: &operations,
            })
            .unwrap();
        r.commit_prepared(prepared);
        assert_eq!(
            r.state.licenses_v2.license(sale_license).unwrap().owner,
            addr(&second_key(), 1)
        );
        assert!(
            r.state
                .licenses_v2
                .license(sale_license)
                .unwrap()
                .active_worker
                .is_none()
        );
    }
    let view = ChainView::new(
        HeadInfo::new(
            r.parent.clone(),
            if case == 3 { at(P + 1) + 1 } else { at(P) },
            T0,
            r.state.root().unwrap(),
        )
        .unwrap(),
        &r.state,
        &reserved,
    );
    let signed = match case {
        0 => wallet_builders::atomic_bond(&view, owner_key(), node, 1, MINIMUM_ATOMS, [0xb1; 32]),
        1 => wallet_builders::sponsored_rotation(&view, owner_key(), second_key(), sponsor_key()),
        3 => {
            let license = r.state.licenses_v2.license(sale_license).unwrap();
            let me =
                mutiny_wallet_core_v8::SignerIdentity::from_public(second_key().public(), 1, None)
                    .unwrap();
            let node_descriptor = r.f.coordinator.public().descriptor(1).unwrap();
            let mut binding = mutiny_crypto_v2::enrollment::Binding {
                genesis: r.parent.genesis,
                fingerprint: r.parent.fingerprint,
                license: sale_license,
                owner_descriptor: mutiny_crypto_v2::enrollment::owner_descriptor_id(
                    &me.public(),
                    1,
                )
                .unwrap(),
                owner_generation: 1,
                worker_public: licenses::worker(0x71),
                worker_id: [0; 32],
                coordinator: mutiny_consensus_v8::work_authority_v2::node_identity(
                    &node_descriptor,
                )
                .unwrap(),
                configuration_generation: 1,
                device_mac: [2, 0, 0, 0, 0, 0x71],
                assignment_generation: license.assignment_sequence + 1,
                effective_epoch: P + 2,
                valid_until_height: r.parent.height + 8,
            };
            binding.worker_id = binding.derived_worker_id();
            let public = licenses::sign(binding, &second_key(), &node_descriptor, 0x71);
            wallet_builders::fresh_worker_assignment(&view, second_key(), &public)
        }
        _ => wallet_builders::native_hash_lock(
            &view,
            owner_key(),
            second_key(),
            50_000,
            [0xb2; 32],
            [0xb3; 32],
            100,
        ),
    };
    assert!(signed.is_complete());
    let raw = signed.bytes().to_vec();
    std::fs::write(r.base.join("wallet-produced.bin"), &raw).unwrap();
    let list = if case == 1 { 0 } else { 1 };
    let (_, id) = mutiny_consensus_v8::operation_index_v2::operation_id(list, &raw).unwrap();
    let mut a = runtime(&r, "a", &r.base.join("chain.sqlite"));
    let mut b = runtime(&r, "b", &r.base.join("b-chain.sqlite"));
    for height in 1..=r.height() {
        b.install(
            &r.chain
                .canonical_block(height)
                .unwrap()
                .unwrap()
                .encode()
                .unwrap(),
        )
        .unwrap();
    }
    assert_eq!(
        a.admit_submission(list, &raw).unwrap(),
        (id, Status::Pending)
    );
    let (mut send, mut recv, _ra, _rb) = peers(&r);
    let mut relay = Relay::new(send.peer_id()).unwrap();
    let frames = send
        .with_current(|link| relay.prepare(&mut a, link))
        .unwrap()
        .unwrap();
    assert_eq!(frames.len(), 1);
    let (_, have) = frames.into_iter().next().unwrap();
    let result = delivered(&mut a, &mut b, &mut send, &mut recv, have).unwrap();
    assert!(matches!(
        result,
        DispatchEvent::OperationAccepted { .. } | DispatchEvent::TransactionAccepted { .. }
    ));
    assert_eq!(
        b.exact_submission_bytes(id).unwrap(),
        Some((list, raw.clone()))
    );
    let prepared = a
        .prepare(WorkRequest {
            expected_parent: &r.parent,
            license: r.f.license,
            worker: r.f.worker,
            timestamp: at(P + 1) + 2 * u64::from(case == 3),
            ticket: r.ticket,
            operations: &[],
        })
        .unwrap();
    assert_eq!(
        if list == 0 {
            &prepared.body.transactions
        } else {
            &prepared.body.operations
        },
        &vec![raw.clone()]
    );
    let block = certify_at(prepared, &r.f, &r.parent, &r.state, r.ticket);
    let before = a.head().unwrap();
    let rows_before = canonical_rows(&r.base.join("chain.sqlite"));
    let mut bad = block.clone();
    bad.header.candidate.state_root[0] ^= 1;
    std::fs::write(r.base.join("refused-block.bin"), bad.encode().unwrap()).unwrap();
    assert!(a.install(&bad.encode().unwrap()).is_err());
    assert_eq!(a.head().unwrap(), before);
    assert_eq!(
        canonical_rows(&r.base.join("chain.sqlite")),
        rows_before,
        "failed block preserves every canonical/finality/lifecycle/outcome row"
    );
    assert_eq!(
        a.exact_submission_bytes(id).unwrap(),
        Some((list, raw.clone()))
    );
    a.install(&block.encode().unwrap()).unwrap();
    b.install(&block.encode().unwrap()).unwrap();
    let Status::Finalized(record) = a.submission_status(id).unwrap() else {
        panic!("wallet bytes not finalized")
    };
    assert_eq!(
        record.wire,
        submission::Submission::decode(list, &raw).unwrap().wire
    );
    assert_eq!(
        b.submission_status(id).unwrap(),
        Status::Finalized(record.clone())
    );
    if case == 3 {
        let (_, scheduled_state) = r.chain.load().unwrap();
        assert!(
            scheduled_state
                .licenses_v2
                .license(sale_license)
                .unwrap()
                .active_worker
                .is_none()
        );
        let assignment =
            mutiny_consensus_v8::license_assignment_v2::Assignment::decode(&raw).unwrap();
        assert_eq!(
            scheduled_state.licenses_v2.pending_assignment(sale_license),
            Some(&assignment)
        );
        // Actual next mining epoch activates the fresh buyer-bound Worker. A sale alone
        // and an authenticated delivery acknowledgement never activate it.
        let parent = a.head().unwrap();
        let prepared = a
            .prepare(WorkRequest {
                expected_parent: &parent,
                license: r.f.license,
                worker: r.f.worker,
                timestamp: at(P + 2),
                ticket: r.ticket + 1,
                operations: &[],
            })
            .unwrap();
        let activated = certify_at(prepared, &r.f, &parent, &scheduled_state, r.ticket + 1);
        a.install(&activated.encode().unwrap()).unwrap();
        b.install(&activated.encode().unwrap()).unwrap();
        let (_, active) = r.chain.load().unwrap();
        assert_eq!(
            active
                .licenses_v2
                .license(sale_license)
                .unwrap()
                .active_worker,
            Some(assignment.enrollment.binding.worker_id)
        );
        assert!(
            active
                .licenses_v2
                .pending_assignment(sale_license)
                .is_none()
        );
        assert_eq!(
            a.submission_status(id).unwrap(),
            Status::Finalized(record.clone())
        );
    }
    if case == 0 {
        let point = OutPoint {
            transaction: id,
            index: 0,
        };
        let (_, state) = r.chain.load().unwrap();
        let coin = state.coins.get(&point).unwrap();
        let parent = a.head().unwrap();
        let tx = transfer(
            &r.f,
            &owner_key(),
            1,
            point.clone(),
            10_000,
            vec![Output {
                owner: addr(&second_key(), 1),
                atoms: coin.output.atoms - 10_000,
            }],
        );
        a.admit_submission(0, &tx.encode().unwrap()).unwrap();
        let prepared = a
            .prepare(WorkRequest {
                expected_parent: &parent,
                license: r.f.license,
                worker: r.f.worker,
                timestamp: at(P + 2),
                ticket: r.ticket + 1,
                operations: &[],
            })
            .unwrap();
        let spent = certify_at(prepared, &r.f, &parent, &state, r.ticket + 1);
        a.install(&spent.encode().unwrap()).unwrap();
        assert!(!r.chain.load().unwrap().1.coins.contains_key(&point));
        assert_eq!(a.submission_status(id).unwrap(), Status::Finalized(record));
    }
    send.close();
    recv.close();
    drop(send);
    drop(recv);
    drop(a);
    drop(b);
    println!(
        "PUBLIC TEST-VALUE actual TCP evidence retained: {}",
        r.base.display()
    );
    drop(r);
}
