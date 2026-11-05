use mutiny_consensus_v8::{NETWORK_ID, certificates::*};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use primitive_types::U256;
use std::collections::BTreeMap;

#[test]
fn round_dependent_previous_anchor_reproduces_pre_genesis_blocker() {
    // Retain the legacy defect demonstration, then prove the approved correction.
    // Three honest voters may remain locked on B across a timed-out round while
    // a fourth nil precommit lets each observe +2/3 ANY votes without +2/3 for B.
    // Delayed round-0 votes and later round-1 votes can therefore prove the same B.
    let base = Decision {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        purpose: 2,
        height: 8,
        mining_epoch: 8,
        continuity_period: 0,
        round: 0,
        step: 3,
        previous_finalized_anchor: [3; 32],
        parent: [4; 32],
        block: [5; 32],
        state: [6; 32],
        membership: [7; 32],
        reputation: [8; 32],
        attestation: [9; 32],
    };
    let mut registry = BTreeMap::new();
    let keys: Vec<_> = (1..=4u8)
        .map(|n| SigningKey::from_bytes((&[n; 32]).into()).unwrap())
        .collect();
    for (n, key) in keys.iter().enumerate() {
        registry.insert(
            [n as u8 + 1; 32],
            Voter {
                key_version: 1,
                weight: U256::one(),
                public_key: key
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .try_into()
                    .unwrap(),
            },
        );
    }
    let certify = |decision: Decision| {
        let signers = keys[..3]
            .iter()
            .enumerate()
            .map(|(n, key)| {
                let node = [n as u8 + 1; 32];
                let sig: Signature = key.sign_prehash(&decision.signing_digest(node, 1)).unwrap();
                Signer {
                    node,
                    key_version: 1,
                    signature: sig.normalize_s().unwrap_or(sig).to_bytes().into(),
                }
            })
            .collect();
        Certificate { decision, signers }
    };
    let round_zero = certify(base.clone());
    let mut later = base.clone();
    later.round = 1;
    let round_one = certify(later.clone());
    round_zero.verify_quorum(&base, &registry).unwrap();
    round_one.verify_quorum(&later, &registry).unwrap();
    assert_eq!(round_zero.decision.block, round_one.decision.block);
    assert_eq!(round_zero.decision.state, round_one.decision.state);
    assert_ne!(round_zero.decision.id(), round_one.decision.id());
    let mut child = base.clone();
    child.height = 9;
    child.parent = base.block;
    child.block = [10; 32];
    child.previous_finalized_anchor = round_zero.decision.id();
    let child_certificate = certify(child.clone());
    child_certificate.verify_quorum(&child, &registry).unwrap();
    let mut other_node_expected = child.clone();
    other_node_expected.previous_finalized_anchor = round_one.decision.id();
    assert_eq!(
        child_certificate.verify_quorum(&other_node_expected, &registry),
        Err(mutiny_consensus_v8::Error::WrongAnchor)
    );
    // A round-specific evidence ID is now rejected as a history link.
    assert!(child.verify_parent(&round_zero.decision.anchor()).is_err());
    assert_eq!(round_zero.decision.anchor(), round_one.decision.anchor());
    child.previous_finalized_anchor = round_zero.decision.anchor().id();
    let corrected = certify(child.clone());
    for parent in [&round_zero, &round_one] {
        parent.verify_quorum(&parent.decision, &registry).unwrap();
        corrected
            .decision
            .verify_parent(&parent.decision.anchor())
            .unwrap();
        corrected.verify_quorum(&child, &registry).unwrap();
    }
    let mut conflicting = round_one.decision.anchor();
    conflicting.block = [77; 32];
    assert!(corrected.decision.verify_parent(&conflicting).is_err());
    let mut tampered = corrected.clone();
    tampered.decision.round += 1;
    assert!(
        tampered
            .verify_quorum(&tampered.decision, &registry)
            .is_err()
    );
    let mut tampered = corrected.clone();
    tampered.decision.step = 2;
    assert!(
        tampered
            .verify_quorum(&tampered.decision, &registry)
            .is_err()
    );
    let mut wrong_registry = child.clone();
    wrong_registry.membership = [78; 32];
    assert!(corrected.verify_quorum(&wrong_registry, &registry).is_err());
    println!(
        "ROUND_ANCHOR_DEFECT_REPRODUCED parent_block={} round0_id={} round1_id={} child_accepts_first=true child_accepts_second=false",
        hex::encode(base.block),
        hex::encode(round_zero.decision.id()),
        hex::encode(round_one.decision.id())
    );
}
#[test]
fn signer_subsets_have_one_decision_identity_but_require_strict_old_quorum() {
    let decision = Decision {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        purpose: 2,
        height: 1,
        mining_epoch: 1,
        continuity_period: 0,
        round: 0,
        step: 3,
        previous_finalized_anchor: [3; 32],
        parent: [4; 32],
        block: [5; 32],
        state: [6; 32],
        membership: [7; 32],
        reputation: [8; 32],
        attestation: [9; 32],
    };
    let mut registry = BTreeMap::new();
    let mut signers = Vec::new();
    for n in 1..=4u8 {
        let key = SigningKey::from_bytes((&[n; 32]).into()).unwrap();
        let node = [n; 32];
        let sig: Signature = key.sign_prehash(&decision.signing_digest(node, 1)).unwrap();
        let sig = sig.normalize_s().unwrap_or(sig);
        registry.insert(
            node,
            Voter {
                key_version: 1,
                public_key: key
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                weight: U256::one(),
            },
        );
        signers.push(Signer {
            node,
            key_version: 1,
            signature: sig.to_bytes().into(),
        });
    }
    let first = Certificate {
        decision: decision.clone(),
        signers: signers[..3].to_vec(),
    };
    let other = Certificate {
        decision: decision.clone(),
        signers: signers[1..].to_vec(),
    };
    assert_ne!(first.encode().unwrap(), other.encode().unwrap());
    assert_eq!(first.decision.id(), other.decision.id());
    assert_eq!(first.decision.anchor().id(), other.decision.anchor().id());
    first.verify_quorum(&decision, &registry).unwrap();
    other.verify_quorum(&decision, &registry).unwrap();
    assert_eq!(
        Certificate::decode(&first.encode().unwrap()).unwrap(),
        first
    );
    let mut bad = first.clone();
    bad.signers.pop();
    assert!(bad.verify_quorum(&decision, &registry).is_err());
    // Offline fourth voter remains in total. Removing it cannot make exactly 2/3 pass either.
    registry.remove(&[4; 32]);
    assert!(bad.verify_quorum(&decision, &registry).is_err());
    bad.signers.push(bad.signers[0].clone());
    assert!(bad.encode().is_err());
    let mut bad = first.clone();
    bad.signers[0].signature[0] ^= 1;
    assert!(bad.verify_quorum(&decision, &registry).is_err());
    let mut wrong = decision.clone();
    wrong.purpose = 3;
    assert!(first.verify_quorum(&wrong, &registry).is_err());
    registry.get_mut(&[1; 32]).unwrap().weight = U256::zero();
    assert!(first.verify_quorum(&decision, &registry).is_err());
}
