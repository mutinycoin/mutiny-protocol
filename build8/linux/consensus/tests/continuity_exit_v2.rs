use mutiny_consensus_v8::{
    NETWORK_ID,
    anchors::FinalizedAnchor,
    continuity_exit_v2::{Exit, ParentControl},
    wallet_authority_v1::WalletBook,
    wallet_rotation_v1::Rotation,
};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, Role};
fn empty() -> HybridSignature {
    HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    }
}
#[test]
fn exit_requires_current_hybrid_owner_or_exact_node_and_parent_sequence() {
    let owner =
        HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner)
            .unwrap();
    let node = HybridKey::generate(Role::Node).unwrap();
    let parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        height: 59,
        block: [3; 32],
    };
    let descriptor = node.public().descriptor(1).unwrap();
    let control = ParentControl {
        node: [4; 32],
        hardware_generation: 1,
        sequence: 7,
        owner_address: owner.public().address_id(1).unwrap(),
        node_descriptor: &descriptor,
        exit_pending: false,
    };
    let mut wallets = WalletBook::default();
    let authority = wallets
        .register(&owner.public().descriptor(1).unwrap())
        .unwrap();
    let mut owner_exit = Exit {
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        height: 60,
        parent_anchor: parent.id(),
        node: control.node,
        hardware_generation: 1,
        sequence: 8,
        authorizer: owner.public().descriptor(1).unwrap(),
        signature: empty(),
    };
    owner_exit.sign(&owner).unwrap();
    owner_exit.verify(&parent, &control, &wallets).unwrap();
    let mut node_exit = owner_exit.clone();
    node_exit.authorizer = descriptor.clone();
    node_exit.sign(&node).unwrap();
    node_exit.verify(&parent, &control, &wallets).unwrap();
    assert!(
        owner
            .sign(Domain::ContinuityExitNode, &owner_exit.body().unwrap())
            .is_err()
    );
    assert!(
        node.sign(Domain::ContinuityExitOwner, &node_exit.body().unwrap())
            .is_err()
    );
    for exit in [&owner_exit, &node_exit] {
        let raw = exit.encode().unwrap();
        assert!(raw.len() <= 4096);
        assert_eq!(Exit::decode(&raw).unwrap(), *exit);
        for n in 0..raw.len() {
            assert!(Exit::decode(&raw[..n]).is_err());
        }
        let mut trailing = raw;
        trailing.push(0);
        assert!(Exit::decode(&trailing).is_err());
        for field in 0..10 {
            let mut bad = exit.clone();
            match field {
                0 => bad.genesis[0] ^= 1,
                1 => bad.fingerprint[0] ^= 1,
                2 => bad.height += 1,
                3 => bad.parent_anchor[0] ^= 1,
                4 => bad.node[0] ^= 1,
                5 => bad.hardware_generation += 1,
                6 => bad.sequence += 1,
                7 => bad.signature.ed448[0] ^= 1,
                8 => bad.signature.fndsa[500] ^= 1,
                _ => bad.authorizer[10] ^= 1,
            }
            assert!(
                bad.verify(&parent, &control, &wallets).is_err(),
                "field {field}"
            );
        }
    }
    let mut wrong_domain = owner_exit.clone();
    wrong_domain.signature = owner
        .sign(Domain::Transaction, &owner_exit.body().unwrap())
        .unwrap();
    assert!(wrong_domain.verify(&parent, &control, &wallets).is_err());
    let mut wrong_domain = node_exit.clone();
    wrong_domain.signature = node
        .sign(Domain::NodeWork, &node_exit.body().unwrap())
        .unwrap();
    assert!(wrong_domain.verify(&parent, &control, &wallets).is_err());
    let another_node = HybridKey::generate(Role::Node).unwrap();
    let mut wrong_node = node_exit.clone();
    wrong_node.authorizer = another_node.public().descriptor(1).unwrap();
    wrong_node.sign(&another_node).unwrap();
    assert!(wrong_node.verify(&parent, &control, &wallets).is_err());
    let continuity = HybridKey::generate(Role::Continuity).unwrap();
    let mut wrong_role = node_exit.clone();
    wrong_role.authorizer = continuity.public().descriptor(1).unwrap();
    assert!(wrong_role.sign(&continuity).is_err());
    let pending = ParentControl {
        exit_pending: true,
        ..control
    };
    assert!(owner_exit.verify(&parent, &pending, &wallets).is_err());
    let exhausted = ParentControl {
        sequence: u64::MAX,
        ..control
    };
    assert!(owner_exit.verify(&parent, &exhausted, &wallets).is_err());

    let successor =
        HybridKey::wallet_restore(&format!("{}vote", "zoo ".repeat(23)), Role::WalletOwner)
            .unwrap();
    let mut rotation = Rotation {
        network: NETWORK_ID,
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        authority,
        current: owner.public().descriptor(1).unwrap(),
        proposed: successor.public().descriptor(2).unwrap(),
        created_height: 1,
        expiry_height: 100,
        authorization: empty(),
        possession: empty(),
    };
    rotation.sign(&owner, &successor).unwrap();
    wallets
        .apply(&rotation, parent.genesis, parent.fingerprint, 59)
        .unwrap();
    assert!(owner_exit.verify(&parent, &control, &wallets).is_err());
    let mut successor_exit = owner_exit.clone();
    successor_exit.authorizer = successor.public().descriptor(2).unwrap();
    successor_exit.sign(&successor).unwrap();
    successor_exit.verify(&parent, &control, &wallets).unwrap();
    node_exit.verify(&parent, &control, &wallets).unwrap();
    if std::env::var("BUILD8_EXPORT_HYBRID_EXIT").as_deref() == Ok("1") {
        let value = serde_json::json!({"schema":"BUILD8-SYNTHETIC-HYBRID-EXIT-V2",
            "synthetic_only":true,"production_authorized":false,"parent":hex::encode(parent.encode()),
            "owner_address":hex::encode(control.owner_address),"node_descriptor":hex::encode(&descriptor),
            "node":hex::encode(control.node),"hardware_generation":1,"prior_sequence":7,
            "owner_exit":hex::encode(owner_exit.encode().unwrap()),
            "node_exit":hex::encode(node_exit.encode().unwrap()),
            "successor_exit":hex::encode(successor_exit.encode().unwrap()),
            "rotation":hex::encode(rotation.encode().unwrap())});
        use std::io::Write;
        std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../qualification/continuity-exit-v2-public-v1.json"),
            )
            .unwrap()
            .write_all(&serde_json::to_vec_pretty(&value).unwrap())
            .unwrap();
    }
}
