use super::*;
use mutiny_consensus_v8::{
    anchors::FinalizedAnchor, block_envelope_v2::BlockEnvelope, canonical_store_v2::CanonicalStore,
    execution::State, mempool_v2::Mempool,
};
use mutiny_crypto_v2::{HybridKey, Role};
use mutiny_transport_v2::{
    Endpoint, MAX_PAYLOAD,
    objects::{ObjectQueue, object_id},
};
fn deliver(
    send: &mut crate::hybrid_peer_admission_v2::PeerLink,
    recv: &mut crate::hybrid_peer_admission_v2::PeerLink,
    bytes: &[u8],
) -> crate::hybrid_peer_admission_v2::Received {
    use std::time::{Duration, Instant};
    let limit = || Instant::now() + Duration::from_secs(5);
    let (offer, have) = send
        .with_current(|link| link.enqueue(ObjectKind::BlockProposal, bytes, 0))
        .unwrap()
        .unwrap();
    send.send(&have, limit()).unwrap();
    let event = recv.receive(limit()).unwrap();
    let request = recv
        .dispatch_received(event, |link, event| {
            assert!(matches!(event, Event::Offered(_)));
            link.next_missing_request(&offer.id, 0, false)
                .unwrap()
                .unwrap()
                .frame
        })
        .unwrap();
    recv.send(&request, limit()).unwrap();
    let requested = send.receive(limit()).unwrap();
    assert!(
        send.dispatch_received(requested, |_, event| matches!(event, Event::Requested))
            .unwrap()
    );
    let count = bytes.len().div_ceil(MAX_PAYLOAD);
    assert!(count <= 1080);
    for index in 0..count {
        let frame = send
            .with_current(|link| link.send_one())
            .unwrap()
            .unwrap()
            .unwrap();
        send.send(&frame, limit()).unwrap();
        let event = recv.receive(limit()).unwrap();
        if index + 1 == count {
            return event;
        }
        assert!(
            recv.dispatch_received(event, |_, event| matches!(event, Event::FragmentReceived))
                .unwrap()
        );
    }
    panic!("no proposal fragments")
}
#[test]
fn authenticated_proposal_fragments_require_execution_and_never_install_finality() {
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
    let block = BlockEnvelope::decode(&raw(&f["envelope"])).unwrap();
    let record = Record {
        header: block.header.clone(),
        authority: block.authority.clone(),
        body: block.body.clone(),
    };
    let mut random = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
    let base =
        std::env::temp_dir().join(format!("build8-proposal-ingress-{}", hex::encode(random)));
    assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
    let runtime = HybridRuntime::from_pinned_chain(
        CanonicalStore::open_trusted_genesis(
            &base.join("chain"),
            &genesis,
            &state,
            root,
            1000,
            [255; 32],
        )
        .unwrap(),
        Mempool::open(
            &base.join("pool"),
            genesis.genesis,
            genesis.fingerprint,
            64 * 1024 * 1024,
        )
        .unwrap(),
    )
    .unwrap();
    let mut journal = Journal::open(
        &base.join("candidates"),
        genesis.genesis,
        genesis.fingerprint,
        1024 * 1024,
        true,
    )
    .unwrap();
    // Test-only transport keys. No wallet/Continuity keys or physical devices.
    let a = HybridKey::generate(Role::Transport).unwrap();
    let b = HybridKey::generate(Role::Transport).unwrap();
    use crate::hybrid_peer_admission_v2::Registry;
    use std::{
        net::{TcpListener, TcpStream},
        time::Duration,
    };
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
    let send_queue = ObjectQueue::open(&base.join("send"), client.peer_id()).unwrap();
    let recv_queue = ObjectQueue::open(&base.join("recv"), server.peer_id()).unwrap();
    let mut send = client.attach(send_queue).unwrap();
    let mut recv = server.attach(recv_queue).unwrap();
    let mut bad = record.clone();
    bad.authority.signature.fndsa.fill(0);
    let bad_event = deliver(&mut send, &mut recv, &bad.encode().unwrap());
    assert!(dispatch_peer(&runtime, &mut journal, &mut recv, bad_event).is_err());
    assert!(journal.next_current(&runtime, None).unwrap().is_none());
    let bytes = record.encode().unwrap();
    let event = deliver(&mut send, &mut recv, &bytes);
    assert!(
        matches!(dispatch_peer(&runtime,&mut journal,&mut recv,event).unwrap(),Outcome::Retained{block:id,..} if id==block.block_hash())
    );
    assert_eq!(
        runtime.head().unwrap().height,
        0,
        "proposal transport installed finality"
    );
    assert_eq!(
        journal.next_current(&runtime, None).unwrap(),
        Some(record.clone())
    );
    let id = object_id(ObjectKind::BlockProposal, &bytes).unwrap();
    let offer = Offer {
        id,
        kind: ObjectKind::BlockProposal,
        length: bytes.len(),
    };
    assert!(matches!(
        retry_completed(&runtime, &mut journal, &mut recv, &id).unwrap(),
        Outcome::Retained { .. }
    ));
    let mut wrong = offer.clone();
    wrong.id[0] ^= 1;
    assert!(
        dispatch(
            &runtime,
            &mut journal,
            Event::Completed {
                offer: wrong,
                bytes: bytes.clone()
            }
        )
        .is_err()
    );
    let mut wrong = offer.clone();
    wrong.length += 1;
    assert!(
        dispatch(
            &runtime,
            &mut journal,
            Event::Completed {
                offer: wrong,
                bytes: bytes.clone()
            }
        )
        .is_err()
    );
    let certificate = Offer {
        id: object_id(ObjectKind::CertifiedBlock, &bytes).unwrap(),
        kind: ObjectKind::CertifiedBlock,
        length: bytes.len(),
    };
    assert!(matches!(
        dispatch(
            &runtime,
            &mut journal,
            Event::Completed {
                offer: certificate,
                bytes
            }
        )
        .unwrap(),
        Outcome::Other(_)
    ));
    assert_eq!(runtime.head().unwrap().height, 0);
    let mut next = record.clone();
    next.header.nonce += 1;
    let waiting = deliver(&mut send, &mut recv, &next.encode().unwrap());
    incoming.replace_peers(vec![]).unwrap();
    assert!(dispatch_peer(&runtime, &mut journal, &mut recv, waiting).is_err());
    assert!(retry_completed(&runtime, &mut journal, &mut recv, &id).is_err());
    assert_eq!(journal.next_current(&runtime, None).unwrap(), Some(record));
    drop(send);
    drop(recv);
    drop(journal);
    drop(runtime);
    println!("RETAINED_PUBLIC_PROPOSAL_DISPATCH_EVIDENCE={}",base.display());
}
