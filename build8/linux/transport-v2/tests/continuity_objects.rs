//! Offline encrypted relay; delivery never substitutes for consensus checks.
use mutiny_consensus_v8::{
    NETWORK_ID,
    anchors::FinalizedAnchor,
    block_envelope_v2::BlockEnvelope,
    continuity_v2::{ParentVoter, Vote},
    execution::{State, WorkParent},
    votes_v2::HeightAuthority,
};
use mutiny_crypto_v2::{HybridKey, PublicKey, Role};
use mutiny_transport_v2::{objects::*, *};
mod test_dir;
fn directory() -> test_dir::TestDir {
    test_dir::TestDir::new("transport-objects")
}
#[test]
fn hybrid_envelope_and_vote_relay_require_independent_final_verification() {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/hybrid-certified-envelope-v2-public-v1.json"
    ))
    .unwrap();
    let licensed: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/licensed-execution-v2-public-v1.json"
    ))
    .unwrap();
    let bytes = |name: &str| hex::decode(f[name].as_str().unwrap()).unwrap();
    let records: Vec<_> = licensed["parent_records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                hex::decode(r["key"].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                hex::decode(r["record"].as_str().unwrap()).unwrap(),
            )
        })
        .collect();
    let state =
        State::from_records(&records, bytes("parent_state_root").try_into().unwrap()).unwrap();
    // Independently fixed synthetic test chain context, not trusted from relay.
    let parent = WorkParent {
        genesis: [1; 32],
        fingerprint: [2; 32],
        block: [3; 32],
        height: 0,
        t0: 1000,
        target: [255; 32],
        ancestor_timestamps: vec![1000],
    };
    let roots: Vec<[u8; 32]> = f["parent_roots"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            hex::decode(r.as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        })
        .collect();
    let authority = HeightAuthority {
        parent: FinalizedAnchor {
            network: NETWORK_ID,
            genesis: [1; 32],
            fingerprint: [2; 32],
            height: 0,
            block: [3; 32],
        },
        membership: roots[0],
        reputation: roots[1],
        attestation: roots[2],
        activation_rule: None,
        voters: std::collections::BTreeMap::from([(
            bytes("node").try_into().unwrap(),
            ParentVoter {
                lineage: bytes("lineage").try_into().unwrap(),
                admitted: true,
                physical: true,
                eligible: true,
                revoked: false,
                hardware_generation: 1,
                key_generation: 1,
                tpm_public: bytes("tpm_public").try_into().unwrap(),
                profile: bytes("profile").try_into().unwrap(),
                public: PublicKey::decode_descriptor(&bytes("continuity_descriptor"))
                    .unwrap()
                    .0,
                reputation: 1u64.into(),
            },
        )]),
    };
    let original = BlockEnvelope::decode(&bytes("envelope")).unwrap();
    let vote = original.certificate.votes[0].clone();
    let a = HybridKey::generate(Role::Transport).unwrap();
    let b = HybridKey::generate(Role::Transport).unwrap();
    let context = Context::pinned(
        [1; 32],
        [2; 32],
        Endpoint::pinned(a.public().clone(), 1).unwrap(),
        Endpoint::pinned(b.public().clone(), 1).unwrap(),
    )
    .unwrap();
    let (i, hello) = InitiatorPending::start(context.clone(), &a).unwrap();
    let (r, response) = ResponderPending::accept(context, &b, &hello).unwrap();
    let (i, finish) = i.accept(&a, &response).unwrap();
    let (mut receiver, tag) = r.finish(&finish).unwrap();
    let mut sender = i.finish(&tag).unwrap();
    let dir = directory();
    let mut send = ObjectQueue::open(&dir.join("send.sqlite"), [8; 32]).unwrap();
    let mut recv = ObjectQueue::open(&dir.join("receive.sqlite"), [8; 32]).unwrap();
    let mut delivered = Vec::new();
    for (kind, raw) in [
        (ObjectKind::CertifiedBlock, original.encode().unwrap()),
        (ObjectKind::ContinuityVote, vote.encode().unwrap()),
    ] {
        assert_ne!(
            object_id(kind, &raw).unwrap(),
            object_id(ObjectKind::SignedTransaction, &raw).unwrap()
        );
        let offer = send.enqueue(kind, &raw).unwrap();
        let (m, p) = offer.have(1).unwrap();
        let (m, p) = receiver.open(&sender.seal(&m, &p).unwrap()).unwrap();
        recv.offer(&Offer::parse(&m, &p).unwrap()).unwrap();
        let mut missing = recv.missing(&offer.id, 0, m.count).unwrap();
        while let Some((m, p)) = send.next_fragment(&offer.id, &missing, 1).unwrap() {
            missing.bits[m.fragment as usize] = false;
            let frame = sender.seal(&m, &p).unwrap();
            let (m, p) = receiver.open(&frame).unwrap();
            recv.receive(&m, &p).unwrap();
            assert!(receiver.open(&frame).is_err(), "AEAD replay accepted");
        }
        let result = recv.read_complete(&offer.id).unwrap();
        assert_eq!(result, raw);
        delivered.push(result);
    }
    let received = BlockEnvelope::decode(&delivered[0]).unwrap();
    assert_eq!(
        received
            .verify_execute(&state, &parent, &authority)
            .unwrap()
            .root,
        bytes("executed_state_root").as_slice()
    );
    let received_vote = Vote::decode(&delivered[1]).unwrap();
    received_vote
        .verify(&authority.parent, authority.roots(), &authority.voters)
        .unwrap();
    // An authenticated relay can deliver invalid signed objects. Endpoints must
    // reject them even when object digest and transport authentication are valid.
    let mut bad = received.clone();
    bad.certificate.votes[0].signature.fndsa[500] ^= 1;
    let bad_offer = send
        .enqueue(ObjectKind::CertifiedBlock, &bad.encode().unwrap())
        .unwrap();
    let transported = BlockEnvelope::decode(&send.read_complete(&bad_offer.id).unwrap()).unwrap();
    assert!(
        transported
            .verify_execute(&state, &parent, &authority)
            .is_err()
    );
    let mut cloud = authority.clone();
    for v in cloud.voters.values_mut() {
        v.physical = false;
    }
    assert!(received.verify_execute(&state, &parent, &cloud).is_err());
    let mut bad_vote = received_vote;
    bad_vote.signature.ed448[0] ^= 1;
    assert!(
        bad_vote
            .verify(&authority.parent, authority.roots(), &authority.voters)
            .is_err()
    );
}
#[test]
fn bounded_full_envelope_offers_and_old_queue_schema_fail_closed() {
    use mutiny_consensus_v8::block_envelope_v2::MAX_ENVELOPE_BYTES;
    assert!(MAX_ENVELOPE_BYTES <= MAX_OBJECT_BYTES);
    let dir = directory();
    let path = dir.join("queue.sqlite");
    let mut queue = ObjectQueue::open(&path, [7; 32]).unwrap();
    for id in [1u8, 2] {
        let offer = Offer {
            id: [id; 32],
            kind: ObjectKind::CertifiedBlock,
            length: MAX_ENVELOPE_BYTES,
        };
        let (m, p) = offer.have(16).unwrap();
        assert_eq!(m.count as usize, MAX_ENVELOPE_BYTES.div_ceil(MAX_PAYLOAD));
        assert!(m.count <= 16384);
        assert_eq!(Offer::parse(&m, &p).unwrap(), offer);
        queue.offer(&offer).unwrap();
        let mut unknown = p;
        unknown[1] = 8;
        assert!(Offer::parse(&m, &unknown).is_err());
    }
    assert!(
        queue
            .offer(&Offer {
                id: [3; 32],
                kind: ObjectKind::CertifiedBlock,
                length: MAX_ENVELOPE_BYTES
            })
            .is_err()
    );
    drop(queue);
    let old = dir.join("old-v3.sqlite");
    let db = rusqlite::Connection::open(&old).unwrap();
    db.execute_batch("CREATE TABLE sentinel(value TEXT); INSERT INTO sentinel VALUES('keep'); PRAGMA user_version=3;").unwrap();
    drop(db);
    assert!(ObjectQueue::open(&old, [7; 32]).is_err());
    let db = rusqlite::Connection::open(&old).unwrap();
    assert_eq!(
        db.query_row("PRAGMA user_version", [], |r| r.get::<_, u32>(0))
            .unwrap(),
        3
    );
    assert_eq!(
        db.query_row("SELECT value FROM sentinel", [], |r| r.get::<_, String>(0))
            .unwrap(),
        "keep"
    );
}
