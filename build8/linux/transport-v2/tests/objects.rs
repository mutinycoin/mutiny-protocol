use mutiny_transport_v2::{objects::*, *};
mod test_dir;
fn directory() -> test_dir::TestDir {
    test_dir::TestDir::new("transport-objects")
}
#[test]
fn same_settlement_bytes_verify_after_encrypted_transport() {
    use mutiny_consensus_v8::{
        anchors::FinalizedAnchor, continuity_v2::ParentVoter, settlement::*,
    };
    use mutiny_crypto_v2::{HybridKey, PublicKey, Role};
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/settlement-public-v1.json"
    ))
    .unwrap();
    let bytes = |name: &str| hex::decode(f[name].as_str().unwrap()).unwrap();
    let raw = bytes("proof");
    let a = HybridKey::generate(Role::Transport).unwrap();
    let b = HybridKey::generate(Role::Transport).unwrap();
    let ctx = Context::pinned(
        [1; 32],
        [2; 32],
        Endpoint::pinned(a.public().clone(), 1).unwrap(),
        Endpoint::pinned(b.public().clone(), 1).unwrap(),
    )
    .unwrap();
    let (i, h) = InitiatorPending::start(ctx.clone(), &a).unwrap();
    let (r, response) = ResponderPending::accept(ctx, &b, &h).unwrap();
    let (i, fini) = i.accept(&a, &response).unwrap();
    let (mut r, tag) = r.finish(&fini).unwrap();
    let mut i = i.finish(&tag).unwrap();
    let dir = directory();
    let mut send = ObjectQueue::open(&dir.join("send.sqlite"), [8; 32]).unwrap();
    let mut recv = ObjectQueue::open(&dir.join("recv.sqlite"), [8; 32]).unwrap();
    let offer = send.enqueue(ObjectKind::SettlementProof, &raw).unwrap();
    let (m, p) = offer.have(1).unwrap();
    let (m, p) = r.open(&i.seal(&m, &p).unwrap()).unwrap();
    recv.offer(&Offer::parse(&m, &p).unwrap()).unwrap();
    let mut wanted = recv.missing(&offer.id, 0, m.count).unwrap();
    let (mut count, mut wire) = (0, 0);
    while let Some((m, p)) = send.next_fragment(&offer.id, &wanted, 1).unwrap() {
        wanted.bits[m.fragment as usize] = false;
        let frame = i.seal(&m, &p).unwrap();
        count += 1;
        wire += frame.len();
        let (m, p) = r.open(&frame).unwrap();
        recv.receive(&m, &p).unwrap();
    }
    let delivered = recv.read_complete(&offer.id).unwrap();
    assert_eq!(delivered, raw);
    let parent = FinalizedAnchor::decode(&bytes("parent_anchor")).unwrap();
    let v = &f["trusted_voter"];
    let vb = |name: &str| hex::decode(v[name].as_str().unwrap()).unwrap();
    let registry = std::collections::BTreeMap::from([(
        vb("node").try_into().unwrap(),
        ParentVoter {
            lineage: [1; 32],
            admitted: true,
            physical: true,
            eligible: true,
            revoked: false,
            hardware_generation: 1,
            key_generation: 1,
            tpm_public: vb("tpm_public").try_into().unwrap(),
            profile: vb("profile").try_into().unwrap(),
            public: PublicKey::decode_descriptor(&vb("descriptor")).unwrap().0,
            reputation: 1u64.into(),
        },
    )]);
    let roots: Vec<[u8; 32]> = f["trusted_roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            hex::decode(x.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect();
    let history: Vec<u64> = f["ancestor_timestamps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap())
        .collect();
    let trusted = AuthenticatedParent {
        anchor: &parent,
        registry: &registry,
        membership: roots[0],
        reputation: roots[1],
        attestation: roots[2],
        target: bytes("trusted_target").try_into().unwrap(),
        genesis_timestamp: f["genesis_timestamp"].as_u64().unwrap(),
        ancestor_timestamps: &history,
    };
    let e = &f["expected_payment"];
    let expected = ExpectedPayment {
        transaction: hex::decode(e["txid"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        output_index: 0,
        destination: hex::decode(e["destination"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        atoms: e["atoms"].as_u64().unwrap(),
    };
    let proof = SettlementProof::decode(&delivered).unwrap();
    assert_eq!(
        proof.verify(&trusted, &expected).unwrap().atoms(),
        expected.atoms
    );
    let report = serde_json::json!({"schema":"BUILD8-SETTLEMENT-ENCRYPTED-TRANSPORT-V1","result":"EXACT_BYTES_LOCAL_HYBRID_SETTLEMENT_VERIFY_PASS","synthetic":true,
        "proof_bytes":raw.len(),"fragment_count":count,"encrypted_fragment_bytes":wire,"radio_used":false,"production_qualified":false,"parent_authority":"synthetic locally pinned parent; production chain authentication pending"});
    if std::env::var("BUILD8_EXPORT_PUBLIC_TRANSPORT").as_deref() == Ok("1") {
    std::fs::write(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../qualification/settlement-transport-v1.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    }
}
#[test]
fn same_hybrid_transaction_survives_encrypted_fragment_transport() {
    use mutiny_consensus_v8::{
        transactions::{Coin, OutPoint, Output},
        transactions_v2::Transfer,
    };
    use mutiny_crypto_v2::{HybridKey, Role};
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/hybrid-transaction-public-v2.json"
    ))
    .unwrap();
    let raw = hex::decode(fixture["transaction"].as_str().unwrap()).unwrap();
    let a = HybridKey::generate(Role::Transport).unwrap();
    let b = HybridKey::generate(Role::Transport).unwrap();
    let ctx = Context::pinned(
        [1; 32],
        [2; 32],
        Endpoint::pinned(a.public().clone(), 1).unwrap(),
        Endpoint::pinned(b.public().clone(), 1).unwrap(),
    )
    .unwrap();
    let (i, h) = InitiatorPending::start(ctx.clone(), &a).unwrap();
    let (r, response) = ResponderPending::accept(ctx, &b, &h).unwrap();
    let (i, f) = i.accept(&a, &response).unwrap();
    let (mut r, tag) = r.finish(&f).unwrap();
    let mut i = i.finish(&tag).unwrap();
    let dir = directory();
    let mut send = ObjectQueue::open(&dir.join("send.sqlite"), [8; 32]).unwrap();
    let mut receive = ObjectQueue::open(&dir.join("receive.sqlite"), [8; 32]).unwrap();
    let offer = send.enqueue(ObjectKind::SignedTransaction, &raw).unwrap();
    let (meta, p) = offer.have(1).unwrap();
    let packet = i.seal(&meta, &p).unwrap();
    let (meta, p) = r.open(&packet).unwrap();
    receive.offer(&Offer::parse(&meta, &p).unwrap()).unwrap();
    let mut wanted = receive.missing(&offer.id, 0, meta.count).unwrap();
    let mut total = 0usize;
    let mut packets = 0usize;
    while let Some((m, p)) = send.next_fragment(&offer.id, &wanted, 1).unwrap() {
        wanted.bits[m.fragment as usize] = false;
        let packet = i.seal(&m, &p).unwrap();
        total += packet.len();
        packets += 1;
        let (m, p) = r.open(&packet).unwrap();
        receive.receive(&m, &p).unwrap();
    }
    let delivered = receive.read_complete(&offer.id).unwrap();
    assert_eq!(delivered, raw);
    let tx = Transfer::decode(&delivered).unwrap();
    let owner = hex::decode(fixture["source_owner"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let coins = std::collections::BTreeMap::from([(
        OutPoint {
            transaction: [8; 32],
            index: 0,
        },
        Coin {
            output: Output {
                owner,
                atoms: 1_000_000,
            },
            created_height: 1,
            coinbase: true,
        },
    )]);
    assert_eq!(
        tx.verify([1; 32], [2; 32], 101, &coins, &Default::default())
            .unwrap(),
        10_000
    );
    let report = serde_json::json!({"schema":"BUILD8-HYBRID-TX-ENCRYPTED-TRANSPORT-V1","result":"EXACT_BYTES_LOCAL_HYBRID_VERIFY_PASS",
        "synthetic":true,"transaction_bytes":raw.len(),"fragment_count":packets,"encrypted_fragment_bytes":total,
        "radio_used":false,"hardware_qualified":false,"settlement_claimed":false});
    if std::env::var("BUILD8_EXPORT_PUBLIC_TRANSPORT").as_deref() == Ok("1") {
    std::fs::write(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../qualification/hybrid-transaction-transport-v1.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    }
}
#[test]
fn exact_opaque_objects_loss_reordering_duplicate_restart_ack_and_retry_limits() {
    let dir = directory();
    let peer = [3; 32];
    let send_path = dir.join("sender.sqlite");
    let recv_path = dir.join("receiver.sqlite");
    let mut sender = ObjectQueue::open(&send_path, peer).unwrap();
    let mut receiver = ObjectQueue::open(&recv_path, peer).unwrap();
    for kind in [
        ObjectKind::SignedTransaction,
        ObjectKind::SettlementProof,
        ObjectKind::CertifiedBlock,
        ObjectKind::ContinuityVote,
        ObjectKind::WorkProbeRequest,
        ObjectKind::WorkProbeFragment,
        ObjectKind::RecoveryEvidence,
        ObjectKind::BlockProposal,
    ] {
        // Public size fixtures, not claimed to be semantically valid tx/proofs.
        let bytes: Vec<u8> = (0..4097.min(kind.max_bytes()))
            .map(|x| (x % 251) as u8)
            .collect();
        let offer = sender.enqueue(kind, &bytes).unwrap();
        let (m, p) = offer.have(3).unwrap();
        assert_eq!(Offer::parse(&m, &p).unwrap(), offer);
        assert!(receiver.offer(&offer).unwrap());
        assert!(!receiver.offer(&offer).unwrap());
        let mut wanted = receiver.missing(&offer.id, 0, m.count).unwrap();
        let mut packets = Vec::new();
        while let Some((meta, payload)) = sender.next_fragment(&offer.id, &wanted, 2).unwrap() {
            wanted.bits[meta.fragment as usize] = false;
            packets.push((meta, payload));
        }
        // Deliver in reverse order; drop one, duplicate another, restart midway.
        packets.reverse();
        let lost = packets.pop().unwrap();
        let (meta, payload) = &packets[0];
        assert!(receiver.receive(meta, payload).unwrap().is_none());
        assert!(receiver.receive(meta, payload).unwrap().is_none());
        let mut changed = payload.clone();
        changed[0] ^= 1;
        assert_eq!(
            receiver.receive(meta, &changed).unwrap_err(),
            Error::Context
        );
        drop(receiver);
        receiver = ObjectQueue::open(&recv_path, peer).unwrap();
        for (meta, payload) in &packets[1..] {
            assert!(receiver.receive(meta, payload).unwrap().is_none());
        }
        assert!(receiver.read_complete(&offer.id).is_err());
        let missing = receiver.missing(&offer.id, 0, m.count).unwrap();
        assert_eq!(missing.bits.iter().filter(|x| **x).count(), 1);
        let wire = missing.encode(m.count).unwrap();
        assert_eq!(Bitmap::parse(&wire, m.count).unwrap(), missing);
        let retry = sender
            .next_fragment(&offer.id, &missing, 2)
            .unwrap()
            .unwrap();
        assert_eq!(retry, lost);
        assert_eq!(
            receiver.receive(&retry.0, &retry.1).unwrap().unwrap(),
            bytes
        );
        assert!(receiver.receive(&retry.0, &retry.1).unwrap().is_none());
        let ack = Bitmap {
            start: 0,
            bits: vec![true; m.count as usize],
        };
        sender.acknowledge(&offer.id, &ack).unwrap();
        drop(sender);
        drop(receiver);
        sender = ObjectQueue::open(&send_path, peer).unwrap();
        receiver = ObjectQueue::open(&recv_path, peer).unwrap();
        assert_eq!(sender.acknowledged(&offer.id, 0, m.count).unwrap(), ack);
        assert_eq!(receiver.read_complete(&offer.id).unwrap(), bytes);
        // Explicit repeated WANT does not reset the durable attempt budget.
        let request = Bitmap {
            start: 0,
            bits: vec![true],
        };
        for _ in 2..MAX_ATTEMPTS {
            assert!(
                sender
                    .next_fragment(&offer.id, &request, 1)
                    .unwrap()
                    .is_some()
            );
        }
        drop(sender);
        sender = ObjectQueue::open(&send_path, peer).unwrap();
        assert!(
            sender
                .next_fragment(&offer.id, &request, 1)
                .unwrap()
                .is_none()
        );
        assert_eq!(sender.enqueue(kind, &bytes).unwrap(), offer); // dedupe cannot reset attempts
        assert!(
            sender
                .next_fragment(&offer.id, &request, 1)
                .unwrap()
                .is_none()
        );
    }
    assert!(ObjectQueue::open(&send_path, [4; 32]).is_err());
}
#[test]
fn capacity_bad_hash_malformed_controls_and_transaction_rollback() {
    let dir = directory();
    let path = dir.join("bounded.sqlite");
    let mut queue = ObjectQueue::open(&path, [1; 32]).unwrap();
    let offer = Offer {
        id: [2; 32],
        kind: ObjectKind::SettlementProof,
        length: 141,
    };
    queue.offer(&offer).unwrap();
    assert!(queue.enqueue(ObjectKind::SignedTransaction, &[]).is_err());
    assert!(
        queue
            .enqueue(
                ObjectKind::SignedTransaction,
                &vec![0; MAX_OBJECT_BYTES + 1]
            )
            .is_err()
    );
    assert!(
        queue
            .receive(
                &Metadata {
                    kind: 3,
                    object: offer.id,
                    fragment: 0,
                    count: 2,
                    hops: 0
                },
                &[0; 139]
            )
            .is_err()
    );
    assert!(
        queue
            .receive(
                &Metadata {
                    kind: 3,
                    object: offer.id,
                    fragment: 0,
                    count: 2,
                    hops: 0
                },
                &[0; 140]
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        queue
            .receive(
                &Metadata {
                    kind: 3,
                    object: offer.id,
                    fragment: 1,
                    count: 2,
                    hops: 0
                },
                &[0]
            )
            .unwrap_err(),
        Error::Crypto
    );
    assert!(queue.read_complete(&offer.id).is_err());
    queue.discard(&offer.id).unwrap();
    for n in 1..=8 {
        queue
            .offer(&Offer {
                id: [n; 32],
                kind: ObjectKind::SettlementProof,
                length: 1,
            })
            .unwrap();
    }
    assert_eq!(
        queue
            .offer(&Offer {
                id: [9; 32],
                kind: ObjectKind::SettlementProof,
                length: 1
            })
            .unwrap_err(),
        Error::Limit
    );
    for n in 1..=8 {
        queue.discard(&[n; 32]).unwrap();
    }
    queue
        .offer(&Offer {
            id: [1; 32],
            kind: ObjectKind::SettlementProof,
            length: MAX_OBJECT_BYTES,
        })
        .unwrap();
    queue
        .offer(&Offer {
            id: [2; 32],
            kind: ObjectKind::SettlementProof,
            length: MAX_OBJECT_BYTES,
        })
        .unwrap();
    assert_eq!(
        queue
            .offer(&Offer {
                id: [3; 32],
                kind: ObjectKind::SettlementProof,
                length: 1
            })
            .unwrap_err(),
        Error::Limit
    );
    drop(queue);
    // Simulated crash before COMMIT: SQLite rolls back staged public fragments.
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("BEGIN IMMEDIATE; DELETE FROM objects;")
        .unwrap();
    drop(db);
    let mut queue = ObjectQueue::open(&path, [1; 32]).unwrap();
    assert_eq!(
        queue
            .offer(&Offer {
                id: [3; 32],
                kind: ObjectKind::SettlementProof,
                length: 1
            })
            .unwrap_err(),
        Error::Limit
    );
    for payload in [
        vec![],
        vec![2, 0, 0, 0, 0, 0],
        vec![2, 0, 0, 0, 1, 0x80],
        vec![2, 0, 0, 0, 1, 1, 0],
        vec![2, 0xff, 0xff, 0, 1, 1],
    ] {
        assert!(Bitmap::parse(&payload, 10).is_err());
    }
    assert!(
        Bitmap {
            start: 0,
            bits: vec![true; 1081]
        }
        .encode(2000)
        .is_err()
    );
}
