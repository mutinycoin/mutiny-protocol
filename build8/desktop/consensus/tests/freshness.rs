use mutiny_consensus_v8::{
    Error, NETWORK_ID, Result, anchors::FinalizedAnchor, freshness::*, participation::*,
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use std::collections::BTreeMap;
// This verifier isolates scheduling from hardware validation. Production TPM
// attestation qualification remains a separate required integration gate.
struct ChallengeVerifier;
impl PhysicalAttestationVerifier for ChallengeVerifier {
    fn verify(&self, _: &PhysicalMember, challenge: [u8; 32], evidence: &[u8]) -> Result<()> {
        if evidence == challenge {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }
}
fn fixture() -> (SigningKey, PhysicalMember, FinalizedAnchor, FreshnessRecord) {
    let key = SigningKey::from_bytes((&[17; 32]).into()).unwrap();
    let member = PhysicalMember {
        node: [3; 32],
        generation: 1,
        continuity_key: key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap(),
        hardware: [4; 32],
        admission_commitment: [10; 32],
        attestation_key: vec![5; 33],
    };
    let parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        height: 0,
        block: [6; 32],
    };
    let evidence = genesis_challenge([7; 32], [8; 32], &member);
    let record =
        validate_genesis([7; 32], [8; 32], &member, &evidence, &ChallengeVerifier).unwrap();
    (key, member, parent, record)
}
fn refresh(parent: &FinalizedAnchor, m: &PhysicalMember) -> AttestationRefresh {
    let mut r = AttestationRefresh {
        network: parent.network,
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        node: m.node,
        generation: m.generation,
        height: parent.height + 1,
        parent_anchor: parent.id(),
        evidence: vec![],
    };
    r.evidence = r.challenge().to_vec();
    r
}
#[test]
fn rolling_windows_exact_boundaries_and_replay_rejection() {
    let (_, m, mut parent, genesis) = fixture();
    for h in 0..=61 {
        assert_eq!(
            genesis.eligible(m.node, m.generation, m.continuity_key, h),
            (1..=60).contains(&h)
        );
    }
    for committed in [59, 60, 120] {
        parent.height = committed - 1;
        let r = refresh(&parent, &m);
        let record = r.validate(&parent, &m, &ChallengeVerifier).unwrap();
        assert_eq!(FreshnessRecord::decode(&record.encode()).unwrap(), record);
        for h in [
            committed - 1,
            committed,
            committed + 1,
            committed + 60,
            committed + 61,
        ] {
            assert_eq!(
                record.eligible(m.node, m.generation, m.continuity_key, h),
                h > committed && h <= committed + 60
            );
        }
        assert!(!record.eligible(m.node, m.generation + 1, m.continuity_key, committed + 1));
        assert!(!record.eligible(m.node, m.generation, [9; 33], committed + 1));
        // Anchor of current block H is never an accepted refresh challenge.
        let mut cycle = r.clone();
        let mut current = parent.clone();
        current.height = committed;
        cycle.parent_anchor = current.id();
        cycle.evidence = cycle.challenge().to_vec();
        assert_eq!(
            cycle.validate(&parent, &m, &ChallengeVerifier),
            Err(Error::WrongAnchor)
        );
        let mut bad = r.clone();
        bad.evidence[0] ^= 1;
        assert_eq!(
            bad.validate(&parent, &m, &ChallengeVerifier),
            Err(Error::BadSignature)
        );
    }
    // Subtraction-based window arithmetic cannot overflow near u64::MAX.
    let mut last = genesis;
    last.committed_height = u64::MAX - 1;
    assert!(last.eligible(m.node, m.generation, m.continuity_key, u64::MAX));
    assert!(!last.eligible(m.node, m.generation, m.continuity_key, 0));
}
#[test]
fn three_complete_periods_with_refresh_and_no_same_block_authority() {
    let (key, m, mut parent, genesis) = fixture();
    let member = ParentMember {
        node: m.node,
        generation: m.generation,
        key: m.continuity_key,
        admitted: true,
        physical: true,
        revoked: false,
        freshness: Some(genesis),
    };
    let mut registry = BTreeMap::from([(m.node, member)]);
    let mut slots = PeriodSlots::default();
    for height in 1..=180 {
        let mut ack = ParticipationAck {
            network: parent.network,
            genesis: parent.genesis,
            fingerprint: parent.fingerprint,
            node: m.node,
            height,
            parent: parent.id(),
            generation: m.generation,
            signature: [0; 64],
        };
        let sig: Signature = key.sign_prehash(&ack.signing_digest()).unwrap();
        ack.signature = sig.normalize_s().unwrap_or(sig).to_bytes().into();
        let next_refresh = if height == 60 || height == 120 {
            Some(
                refresh(&parent, &m)
                    .validate(&parent, &m, &ChallengeVerifier)
                    .unwrap(),
            )
        } else {
            None
        };
        if let Some(record) = &next_refresh {
            let mut wrong = registry[&m.node].clone();
            wrong.freshness = Some(record.clone());
            assert_eq!(ack.verify(&parent, &wrong), Err(Error::UnqualifiedPhysical));
        }
        slots = slots.apply(&parent, &[ack], &registry).unwrap();
        if height % 60 == 0 {
            assert_eq!(slots.bits[&m.node].count_ones(), 60);
            let (next, qualified) = slots.close().unwrap();
            assert!(qualified[&m.node]);
            slots = next;
        }
        if let Some(record) = next_refresh {
            registry.get_mut(&m.node).unwrap().freshness = Some(record);
        }
        parent.height = height;
        parent.block[0] = height as u8;
    }
    assert_eq!(slots.period, 3);
}
#[test]
fn expired_node_can_refresh_but_gets_no_credit_until_next_height() {
    let (_, m, mut parent, genesis) = fixture();
    parent.height = 65;
    assert!(!genesis.eligible(m.node, m.generation, m.continuity_key, 66));
    // Freshness expiration does not revoke physical admission; it must not
    // prevent a valid new TPM attestation from restoring the next-slot window.
    let record = refresh(&parent, &m)
        .validate(&parent, &m, &ChallengeVerifier)
        .unwrap();
    assert!(!record.eligible(m.node, m.generation, m.continuity_key, 66));
    assert!(record.eligible(m.node, m.generation, m.continuity_key, 67));
    assert!(record.eligible(m.node, m.generation, m.continuity_key, 126));
    assert!(!record.eligible(m.node, m.generation, m.continuity_key, 127));
}

#[test]
fn canonical_body_transition_uses_parent_records_and_commits_next_window() {
    use mutiny_consensus_v8::{
        blocks::BlockBody,
        continuity_execution::ContinuityAccounting,
        recovery::{Anchor, ContinuityState, Member},
        reputation::History,
    };
    let (key, m, mut parent, genesis) = fixture();
    let mut registry = ContinuityState::bootstrap(
        parent.genesis,
        parent.fingerprint,
        Anchor {
            height: 0,
            tip: parent.block,
            state_root: [0; 32],
            registry_root: [0; 32],
        },
        [9; 32],
        vec![Member {
            node: m.node,
            lineage: [9; 32],
            hardware: m.hardware,
            generation: m.generation,
            voting_key: m.continuity_key,
            attestation: m.admission_commitment,
            history: History::default(),
            physical: true,
            eligible: true,
            genesis_member: true,
        }],
    )
    .unwrap();
    let physical = BTreeMap::from([(m.node, m)]);
    let m = &physical[&[3; 32]];
    let mut state = ContinuityAccounting {
        slots: PeriodSlots::default(),
        freshness: BTreeMap::from([(m.node, genesis)]),
    };
    for height in 1..=180 {
        let old_weight = registry.voters().unwrap()[&m.node].weight;
        let mut ack = ParticipationAck {
            network: parent.network,
            genesis: parent.genesis,
            fingerprint: parent.fingerprint,
            node: m.node,
            height,
            parent: parent.id(),
            generation: m.generation,
            signature: [0; 64],
        };
        let sig: Signature = key.sign_prehash(&ack.signing_digest()).unwrap();
        ack.signature = sig.normalize_s().unwrap_or(sig).to_bytes().into();
        let mut body = BlockBody {
            height,
            reward_owner: [1; 32],
            fees: 0,
            transactions: vec![],
            operations: vec![],
        };
        if height == 60 || height == 120 {
            let r = refresh(&parent, m);
            assert_eq!(AttestationRefresh::decode(&r.encode().unwrap()).unwrap(), r);
            body.operations.push(r.encode().unwrap());
        }
        body.operations.push(ack.encode());
        let (next, next_registry) = state
            .apply(&parent, &body, &registry, &physical, &ChallengeVerifier)
            .unwrap();
        assert_eq!(registry.voters().unwrap()[&m.node].weight, old_weight);
        state = ContinuityAccounting::from_records(&next.records().unwrap()).unwrap();
        registry = next_registry;
        if height % 60 == 0 {
            assert_eq!(registry.members[0].history.p, height / 60);
        }
        parent.height = height;
        parent.block[0] = height as u8;
        registry.anchor.height = height;
        registry.anchor.tip = parent.block;
    }
    assert_eq!(registry.members[0].history.p, 3);
    assert_eq!(state.slots.period, 3);
    // At 181 the old record has expired. A refresh in this body is valid but
    // cannot make its accompanying ACK eligible until 182. Failed application
    // does not modify either original registry or accounting state.
    let r = refresh(&parent, m);
    let mut ack = ParticipationAck {
        network: parent.network,
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        node: m.node,
        height: 181,
        parent: parent.id(),
        generation: m.generation,
        signature: [0; 64],
    };
    let sig: Signature = key.sign_prehash(&ack.signing_digest()).unwrap();
    ack.signature = sig.normalize_s().unwrap_or(sig).to_bytes().into();
    let mut body = BlockBody {
        height: 181,
        reward_owner: [1; 32],
        fees: 0,
        transactions: vec![],
        operations: vec![r.encode().unwrap(), ack.encode()],
    };
    assert_eq!(
        state.apply(&parent, &body, &registry, &physical, &ChallengeVerifier),
        Err(Error::UnqualifiedPhysical)
    );
    assert_eq!(state.slots.last_height, 180);
    body.operations.pop();
    let (next, _) = state
        .apply(&parent, &body, &registry, &physical, &ChallengeVerifier)
        .unwrap();
    assert!(next.slots.bits.is_empty());
    assert!(next.freshness[&m.node].eligible(m.node, m.generation, m.continuity_key, 182));
}

#[test]
fn independent_python_challenges_records_operations_and_windows_match() {
    let (_, m, mut parent, genesis) = fixture();
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/ROLLING-FRESHNESS-VECTORS.json"
    ))
    .unwrap();
    for case in v["cases"].as_array().unwrap() {
        let height = case["committed_height"].as_u64().unwrap();
        let record = if height == 0 {
            assert_eq!(
                hex::encode(genesis_challenge([7; 32], [8; 32], &m)),
                case["challenge"].as_str().unwrap()
            );
            genesis.clone()
        } else {
            parent.height = height - 1;
            let r = refresh(&parent, &m);
            assert_eq!(
                hex::encode(r.challenge()),
                case["challenge"].as_str().unwrap()
            );
            assert_eq!(
                hex::encode(r.encode().unwrap()),
                case["operation"].as_str().unwrap()
            );
            r.validate(&parent, &m, &ChallengeVerifier).unwrap()
        };
        assert_eq!(
            hex::encode(record.encode()),
            case["record"].as_str().unwrap()
        );
        for slot in case["eligibility"].as_array().unwrap() {
            assert_eq!(
                record.eligible(
                    m.node,
                    m.generation,
                    m.continuity_key,
                    slot["slot"].as_u64().unwrap()
                ),
                slot["eligible"].as_bool().unwrap()
            );
        }
    }
}
