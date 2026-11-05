use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    anchors::FinalizedAnchor,
    bft::{BftError, Observation},
    blocks::*,
    certificates::*,
    execution::*,
    genesis::*,
    licenses::*,
    pow::*,
    votes::*,
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use primitive_types::U256;
use serde_json::Value;
fn raw(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
fn registry(keys: &[SigningKey]) -> std::collections::BTreeMap<Hash, Voter> {
    keys.iter()
        .enumerate()
        .map(|(i, k)| {
            (
                [i as u8; 32],
                Voter {
                    key_version: 1,
                    weight: U256::one(),
                    public_key: k
                        .verifying_key()
                        .to_encoded_point(true)
                        .as_bytes()
                        .try_into()
                        .unwrap(),
                },
            )
        })
        .collect()
}
#[test]
fn signed_votes_require_executed_proposal_and_preserve_locks_across_rounds() {
    let v: Value = serde_json::from_str(include_str!(
        "../../qualification/GENESIS-BINDING-VECTORS-STATE-V2.json"
    ))
    .unwrap();
    let descriptor = GenesisDescriptor::decode(&raw(&v["descriptor_hex"])).unwrap();
    let id = GenesisIdentity::new(descriptor.clone()).unwrap();
    let case = &v["cases"][0];
    let bindings: Vec<_> = case["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| BindWorker::decode(&raw(&b["binding_hex"])).unwrap())
        .collect();
    let state = State {
        licenses: id.bind_workers(&bindings).unwrap(),
        ..State::default()
    };
    let header = WorkHeader::decode(&raw(&case["height1"]["header_hex"])).unwrap();
    let body = BlockBody::decode(&raw(&case["height1"]["body_hex"])).unwrap();
    let (work, signature) =
        WorkAuthority::from_envelope(&raw(&case["height1"]["authority_envelope_hex"])).unwrap();
    let parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: id.id(),
        fingerprint: descriptor.fingerprint,
        height: 0,
        block: descriptor.block_hash(state.root().unwrap()).unwrap(),
    };
    let work_parent = WorkParent {
        genesis: id.id(),
        fingerprint: descriptor.fingerprint,
        block: parent.block,
        height: 0,
        t0: descriptor.timestamp,
        target: header.candidate.target,
        ancestor_timestamps: vec![descriptor.timestamp],
    };
    let keys: Vec<_> = (1..=4u8)
        .map(|n| SigningKey::from_bytes((&[n; 32]).into()).unwrap())
        .collect();
    let height_authority = || HeightAuthority {
        parent: parent.clone(),
        membership: [7; 32],
        reputation: [8; 32],
        attestation: [9; 32],
        voters: registry(&keys),
    };
    let decision = Decision {
        network: NETWORK_ID,
        genesis: id.id(),
        fingerprint: descriptor.fingerprint,
        purpose: 2,
        height: 1,
        mining_epoch: 0,
        continuity_period: 0,
        round: 0,
        step: 2,
        previous_finalized_anchor: parent.id(),
        parent: parent.block,
        block: header.block_hash(),
        state: header.candidate.state_root,
        membership: [7; 32],
        reputation: [8; 32],
        attestation: [9; 32],
    };
    let vote = |node: usize, round: u64, step: u8, nil: bool| {
        let mut d = decision.clone();
        d.round = round;
        d.step = step;
        if nil {
            d.block = [0; 32];
            d.state = [0; 32];
            d.mining_epoch = 0;
        }
        let mut v = Vote {
            nil,
            decision: d,
            node: [node as u8; 32],
            key_version: 1,
            signature: [0; 64],
        };
        let s: Signature = keys[node].sign_prehash(&v.signing_digest()).unwrap();
        v.signature = s.normalize_s().unwrap_or(s).to_bytes().into();
        v
    };
    let mut receiver = AuthenticatedRound::new(height_authority()).unwrap();
    let first = vote(0, 0, 2, false);
    assert_eq!(Vote::decode(&first.encode()).unwrap(), first);
    assert!(matches!(
        receiver.observe(&first),
        Err(IngressError::UnknownProposal)
    ));
    receiver
        .validate_proposal(&state, &work_parent, &header, &work, &signature, &body)
        .unwrap();
    for mutation in 0..5 {
        let mut bad = first.clone();
        match mutation {
            0 => bad.decision.round += 1,
            1 => bad.decision.step = 3,
            2 => bad.decision.membership[0] ^= 1,
            3 => bad.signature[0] ^= 1,
            4 => bad.nil = true,
            _ => unreachable!(),
        }
        assert!(receiver.observe(&bad).is_err());
    }
    assert_eq!(receiver.observe(&first).unwrap(), Observation::Added);
    assert_eq!(receiver.observe(&first).unwrap(), Observation::Duplicate);
    assert!(matches!(
        receiver.observe(&vote(0, 0, 2, true)),
        Err(IngressError::Bft(BftError::Equivocation))
    ));
    for n in 1..3 {
        receiver.observe(&vote(n, 0, 2, false)).unwrap();
    }
    assert_eq!(
        receiver.precommit(Some(decision.block)).unwrap(),
        Some(decision.block)
    );
    receiver.observe(&vote(0, 0, 3, false)).unwrap();
    receiver.observe(&vote(1, 0, 3, false)).unwrap();
    receiver.observe(&vote(3, 0, 3, true)).unwrap();
    assert!(receiver.commit(0, decision.block).is_err());
    receiver.timeout_precommit().unwrap();
    let lock = receiver.machine().state().clone();
    let mut restored = AuthenticatedRound::restore(height_authority(), lock).unwrap();
    restored
        .validate_proposal(&state, &work_parent, &header, &work, &signature, &body)
        .unwrap();
    assert_eq!(
        restored.prevote(Some(decision.block), None).unwrap(),
        Some(decision.block)
    );
    for n in 0..3 {
        restored.observe(&vote(n, 1, 2, false)).unwrap();
        restored.observe(&vote(n, 1, 3, false)).unwrap();
    }
    assert_eq!(
        restored.precommit(Some(decision.block)).unwrap(),
        Some(decision.block)
    );
    assert!(restored.commit(1, decision.block).unwrap());
    for n in 0..3 {
        restored.observe(&vote(n, 0, 3, false)).unwrap();
    }
    assert!(!restored.commit(0, decision.block).unwrap());
    for n in 0..first.encode().len() {
        assert!(Vote::decode(&first.encode()[..n]).is_err());
    }
    let nil = vote(0, 2, 3, true);
    assert_ne!(
        nil.signing_digest(),
        nil.decision.signing_digest(nil.node, nil.key_version)
    );
    let mut cloud = height_authority();
    cloud.voters.get_mut(&[0; 32]).unwrap().weight = U256::zero();
    let mut receiver = AuthenticatedRound::new(cloud).unwrap();
    assert!(receiver.observe(&nil).is_err());
}
