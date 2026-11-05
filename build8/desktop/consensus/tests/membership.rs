use ed25519_dalek::{Signer, SigningKey};
use mutiny_consensus_v8::{
    anchors::FinalizedAnchor, membership::*, recovery::*, reputation::History, *,
};
fn fixture(height: u64) -> (FinalizedAnchor, ContinuityState, MembershipBook, SigningKey) {
    let owner = SigningKey::from_bytes(&[61; 32]);
    let node_key = SigningKey::from_bytes(&[62; 32]);
    let parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        height,
        block: [3; 32],
    };
    let registry = ContinuityState::bootstrap(
        parent.genesis,
        parent.fingerprint,
        Anchor {
            height,
            tip: parent.block,
            state_root: [4; 32],
            registry_root: [5; 32],
        },
        owner.verifying_key().to_bytes(),
        vec![Member {
            lineage: [6; 32],
            node: [7; 32],
            hardware: [8; 32],
            generation: 0,
            voting_key: p256::ecdsa::SigningKey::from_bytes((&[9; 32]).into())
                .unwrap()
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
            attestation: [10; 32],
            history: History::default(),
            physical: true,
            eligible: true,
            genesis_member: true,
        }],
    )
    .unwrap();
    let book = MembershipBook {
        controls: [(
            [7; 32],
            NodeControl {
                node: [7; 32],
                generation: 0,
                owner: owner.verifying_key().to_bytes(),
                node_authentication: node_key.verifying_key().to_bytes(),
                sequence: 0,
                exit_boundary: None,
                admitted_height: 0,
                admission_boundary: None,
                hardware_since_height: 0,
            },
        )]
        .into_iter()
        .collect(),
        ..Default::default()
    };
    (parent, registry, book, owner)
}
fn exit(parent: &FinalizedAnchor, key: &SigningKey) -> ContinuityExit {
    let mut e = ContinuityExit {
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        height: parent.height + 1,
        parent_anchor: parent.id(),
        node: [7; 32],
        generation: 0,
        sequence: 1,
        authorizer: key.verifying_key().to_bytes(),
        signature: [0; 64],
    };
    e.signature = key.sign(&e.signing_digest()).to_bytes();
    e
}
#[test]
fn owner_exit_waits_for_boundary_and_preserves_history_with_old_parent_weights() {
    let (parent, registry, book, owner) = fixture(58);
    let e = exit(&parent, &owner);
    assert_eq!(ContinuityExit::decode(&e.encode()).unwrap(), e);
    let before = registry.weights().unwrap();
    let mut post = registry.clone();
    let pending = book
        .apply_exits(&parent, &[e.encode()], &registry, &mut post)
        .unwrap();
    assert_eq!(post, registry);
    assert_eq!(pending.controls[&[7; 32]].exit_boundary, Some(60));
    assert_eq!(
        MembershipBook::from_records(&pending.records().unwrap()).unwrap(),
        pending
    );
    let boundary = FinalizedAnchor {
        height: 59,
        ..parent.clone()
    };
    // The accounting transition for H60 ran first; exit retains that new history.
    post.members[0].history.complete_period(true).unwrap();
    post.first_period_committed = true;
    let expected_history = post.members[0].history.clone();
    let finished = pending
        .apply_exits(&boundary, &[], &registry, &mut post)
        .unwrap();
    assert!(!post.members[0].eligible);
    assert_eq!(post.members[0].history, expected_history);
    assert!(post.weights().unwrap()[0].is_zero());
    assert_eq!(registry.weights().unwrap(), before);
    assert_eq!(finished.controls[&[7; 32]].sequence, 1);
    assert_eq!(finished.controls[&[7; 32]].exit_boundary, None);
    // Same-boundary inclusion is effective only in the post-state, never H60's votes.
    let mut direct = registry.clone();
    book.apply_exits(
        &boundary,
        &[exit(&boundary, &owner).encode()],
        &registry,
        &mut direct,
    )
    .unwrap();
    assert!(!direct.members[0].eligible);
    assert_eq!(registry.weights().unwrap(), before);
}
#[test]
fn node_authorization_replay_tamper_and_atomic_failure() {
    let (parent, registry, book, owner) = fixture(59);
    let valid = exit(&parent, &owner);
    let node = SigningKey::from_bytes(&[62; 32]);
    exit(&parent, &node)
        .validate(&parent, &book.controls[&[7; 32]])
        .unwrap();
    for field in 0..8 {
        let mut wrong = valid.clone();
        match field {
            0 => wrong.genesis[0] ^= 1,
            1 => wrong.fingerprint[0] ^= 1,
            2 => wrong.height += 1,
            3 => wrong.parent_anchor[0] ^= 1,
            4 => wrong.node[0] ^= 1,
            5 => wrong.generation += 1,
            6 => wrong.sequence += 1,
            _ => wrong.authorizer = SigningKey::from_bytes(&[63; 32]).verifying_key().to_bytes(),
        };
        // Even freshly signed mutations cannot override the pinned parent/control.
        wrong.signature = owner.sign(&wrong.signing_digest()).to_bytes();
        let mut post = registry.clone();
        assert!(
            book.apply_exits(&parent, &[wrong.encode()], &registry, &mut post)
                .is_err()
        );
        assert_eq!(post, registry);
    }
    let mut post = registry.clone();
    assert!(
        book.apply_exits(
            &parent,
            &[valid.encode(), valid.encode()],
            &registry,
            &mut post
        )
        .is_err()
    );
    assert_eq!(post, registry);
    let state = execution::State {
        membership: book.clone(),
        continuity: Some(registry),
        ..Default::default()
    };
    let rebuilt =
        execution::State::from_records(&state.records().unwrap(), state.root().unwrap()).unwrap();
    assert_eq!(rebuilt.membership, book);
    let mut opaque = state.clone();
    opaque.protocol_records.extend(book.records().unwrap());
    assert!(opaque.root().is_err());
}
