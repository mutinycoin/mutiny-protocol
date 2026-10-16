use mutiny_consensus_v8::{Error, NETWORK_ID, anchors::FinalizedAnchor, participation::*};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use std::collections::BTreeMap;
fn fixtures() -> (ParticipationAck, ParentMember, FinalizedAnchor) {
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/PARTICIPATION-VECTORS.json"
    ))
    .unwrap();
    let ack = ParticipationAck::decode(&hex::decode(v["ack"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(
        hex::encode(ack.signing_digest()),
        v["digest"].as_str().unwrap()
    );
    let mut member = ParentMember {
        node: [3; 32],
        generation: 0,
        key: hex::decode(v["public_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
        admitted: true,
        physical: true,
        revoked: false,
        freshness: None,
    };
    member.freshness = Some(mutiny_consensus_v8::freshness::FreshnessRecord {
        node: member.node,
        generation: member.generation,
        key: member.key,
        committed_height: 0,
        evidence_commitment: [9; 32],
    });
    let parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        height: 0,
        block: [4; 32],
    };
    (ack, member, parent)
}
#[test]
fn independent_codec_context_and_eligibility() {
    let (ack, mut member, parent) = fixtures();
    ack.verify(&parent, &member).unwrap();
    for field in 0..8 {
        let mut bad = ack.clone();
        match field {
            0 => bad.network ^= 1,
            1 => bad.genesis[0] ^= 1,
            2 => bad.fingerprint[0] ^= 1,
            3 => bad.node[0] ^= 1,
            4 => bad.height += 1,
            5 => bad.parent[0] ^= 1,
            6 => bad.generation += 1,
            _ => bad.signature[0] ^= 1,
        }
        assert!(bad.verify(&parent, &member).is_err());
    }
    member.revoked = true;
    assert_eq!(
        ack.verify(&parent, &member),
        Err(Error::UnqualifiedPhysical)
    );
    member.revoked = false;
    let saved = member.freshness.take();
    assert!(ack.verify(&parent, &member).is_err());
    member.freshness = saved;
    member.physical = false;
    assert!(ack.verify(&parent, &member).is_err());
    member.physical = true;
    member.admitted = false;
    assert!(ack.verify(&parent, &member).is_err());
    assert_eq!(
        normalize(&[ack.clone(), ack.clone()]).unwrap(),
        vec![ack.clone()]
    );
    let mut bad = ack.clone();
    bad.signature[0] ^= 1;
    assert_eq!(normalize(&[ack, bad]), Err(Error::Duplicate));
}
#[test]
fn distinct_finalized_slots_and_boundaries() {
    let (mut ack, member, mut parent) = fixtures();
    let mut scalar = [0u8; 32];
    scalar[31] = 17;
    let key = SigningKey::from_bytes((&scalar).into()).unwrap();
    let registry = BTreeMap::from([(member.node, member)]);
    for count in [53, 54, 60] {
        let mut slots = PeriodSlots::default();
        parent.height = 0;
        for height in 1..=60 {
            ack.height = height;
            ack.parent = parent.id();
            let sig: Signature = key.sign_prehash(&ack.signing_digest()).unwrap();
            ack.signature = sig.normalize_s().unwrap_or(sig).to_bytes().into();
            let acks = if height <= count {
                vec![ack.clone(), ack.clone()]
            } else {
                vec![]
            };
            slots = slots.apply(&parent, &acks, &registry).unwrap();
            assert_eq!(
                PeriodSlots::decode(&slots.encode().unwrap()).unwrap(),
                slots
            );
            assert!(slots.apply(&parent, &acks, &registry).is_err());
            if height < 60 {
                assert!(slots.close().is_err());
            }
            parent.height = height;
        }
        let (next, qualified) = slots.close().unwrap();
        assert_eq!(qualified[&ack.node], count >= 54);
        assert_eq!((next.period, next.last_height), (1, 60));
        assert!(next.bits.is_empty());
        // The acknowledgement for 60 cannot earn slot 61, and expired rolling
        // attestation cannot earn later credit. No certificate input exists.
        assert!(next.apply(&parent, &[ack.clone()], &registry).is_err());
    }
}

#[test]
fn body_order_duplicates_and_boundary_authority() {
    use mutiny_consensus_v8::{
        blocks::BlockBody,
        recovery::{Anchor, ContinuityState, Member},
        reputation::History,
    };
    let (ack, member, _) = fixtures();
    let mut second = ack.clone();
    second.node = [2; 32];
    let mut body = BlockBody {
        height: 1,
        reward_owner: [8; 32],
        fees: 0,
        transactions: vec![],
        operations: vec![ack.encode(), second.encode(), ack.encode()],
    };
    assert!(body.encode().is_err());
    body.normalize_participation().unwrap();
    assert_eq!(body.operations, vec![second.encode(), ack.encode()]);
    assert_eq!(BlockBody::decode(&body.encode().unwrap()).unwrap(), body);
    let root = body.root().unwrap();
    body.operations.pop();
    assert_ne!(root, body.root().unwrap());
    let slots = PeriodSlots {
        period: 0,
        last_height: 60,
        bits: BTreeMap::from([(ack.node, (1u64 << 54) - 1)]),
    };
    for genesis_member in [true, false] {
        let state = ContinuityState::bootstrap(
            [1; 32],
            [2; 32],
            Anchor {
                height: 59,
                tip: [4; 32],
                state_root: [5; 32],
                registry_root: [6; 32],
            },
            [7; 32],
            vec![Member {
                lineage: [9; 32],
                node: ack.node,
                hardware: [10; 32],
                generation: 0,
                voting_key: member.key,
                attestation: [11; 32],
                history: History::default(),
                physical: true,
                eligible: true,
                genesis_member,
            }],
        )
        .unwrap();
        let old_weight = state.voters().unwrap()[&ack.node].weight;
        assert_eq!(
            old_weight,
            primitive_types::U256::from(u8::from(genesis_member))
        );
        let (_, next) = slots.close_reputation(&state).unwrap();
        assert_eq!(state.voters().unwrap()[&ack.node].weight, old_weight);
        assert_eq!(
            next.voters().unwrap()[&ack.node].weight,
            primitive_types::U256::from(1007)
        );
        assert_eq!(next.members[0].history.p, 1);
        // An absent ACK has no credit even if a certificate carried that node.
        let mut absent = slots.clone();
        absent.bits.clear();
        let (_, missed) = absent.close_reputation(&state).unwrap();
        assert_eq!(missed.members[0].history.p, 0);
    }
}
