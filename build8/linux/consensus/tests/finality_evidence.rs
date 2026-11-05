use mutiny_consensus_v8::{NETWORK_ID, anchors::FinalizedAnchor, certificates::*, finality::*};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use primitive_types::U256;
use std::collections::BTreeMap;

#[test]
fn authenticated_conflicts_retain_both_proofs_and_halt_across_restart() {
    let path =
        std::env::temp_dir().join(format!("build8-proof-ledger-{}.sqlite", std::process::id()));
    assert!(!path.exists());
    let parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        height: 0,
        block: [3; 32],
    };
    let decision = Decision {
        network: NETWORK_ID,
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        purpose: 2,
        height: 1,
        mining_epoch: 0,
        continuity_period: 0,
        round: 0,
        step: 3,
        previous_finalized_anchor: parent.id(),
        parent: parent.block,
        block: [4; 32],
        state: [5; 32],
        membership: [6; 32],
        reputation: [7; 32],
        attestation: [8; 32],
    };
    let keys: Vec<_> = (1..=4u8)
        .map(|n| SigningKey::from_bytes((&[n; 32]).into()).unwrap())
        .collect();
    let registry: BTreeMap<_, _> = keys
        .iter()
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
        .collect();
    let certify = |d: Decision| Certificate {
        signers: keys[..3]
            .iter()
            .enumerate()
            .map(|(i, k)| {
                let node = [i as u8; 32];
                let s: Signature = k.sign_prehash(&d.signing_digest(node, 1)).unwrap();
                Signer {
                    node,
                    key_version: 1,
                    signature: s.normalize_s().unwrap_or(s).to_bytes().into(),
                }
            })
            .collect(),
        decision: d,
    };
    let first = certify(decision.clone());
    let mut later = decision.clone();
    later.round = 1;
    let later = certify(later);
    let mut conflicting = decision.clone();
    conflicting.block = [9; 32];
    conflicting.state = [10; 32];
    let conflicting = certify(conflicting);
    {
        let mut ledger = FinalityLedger::open(&path, &parent).unwrap();
        let mut forged = first.clone();
        forged.signers[0].signature[0] ^= 1;
        assert!(
            ledger
                .record_certificate(&forged, &decision, &registry)
                .is_err()
        );
        assert!(ledger.anchor(1).unwrap().is_none());
        assert!(ledger.evidence(1, decision.block).unwrap().is_none());
        assert!(!ledger.halted().unwrap());
        assert!(
            ledger
                .record_certificate(&first, &decision, &registry)
                .unwrap()
        );
        assert!(
            !ledger
                .record_certificate(&later, &later.decision, &registry)
                .unwrap()
        );
        let mut wrong_parent = later.decision.clone();
        wrong_parent.previous_finalized_anchor = [0; 32];
        let wrong_parent = certify(wrong_parent);
        assert!(matches!(
            ledger.record_certificate(&wrong_parent, &wrong_parent.decision, &registry),
            Err(FinalityError::WrongParent)
        ));
        // Conflicting same-round certificates must halt even though feeding their
        // individual votes into a reducer would first report equivocation.
        assert!(matches!(
            ledger.record_certificate(&conflicting, &conflicting.decision, &registry),
            Err(FinalityError::IntegrityHalt)
        ));
    }
    {
        let mut ledger = FinalityLedger::open(&path, &parent).unwrap();
        assert!(ledger.halted().unwrap());
        assert_eq!(ledger.anchor(1).unwrap().unwrap(), decision.anchor());
        assert_eq!(ledger.evidence(1, decision.block).unwrap().unwrap(), first);
        assert_eq!(
            ledger
                .evidence(1, conflicting.decision.block)
                .unwrap()
                .unwrap(),
            conflicting
        );
        assert!(matches!(
            ledger.record_certificate(&later, &later.decision, &registry),
            Err(FinalityError::IntegrityHalt)
        ));
    }
    std::fs::remove_file(path).unwrap();
}
