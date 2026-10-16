use mutiny_consensus_v8::{
    NETWORK_ID,
    anchors::FinalizedAnchor,
    certificates::Decision,
    continuity_v2::{Certificate, ParentVoter, Vote},
    hybrid_transaction_v2::Transaction,
    pow::{Candidate, WorkHeader},
    settlement::*,
    state_proof::utxo_key,
    state_tree::StateTree,
    transactions::OutPoint,
};
use mutiny_crypto_v2::{HybridKey, HybridSignature, Role};
use primitive_types::U256;
use std::collections::BTreeMap;
#[test]
fn local_payment_expectation_pow_hybrid_quorum_and_typed_state_inclusion() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/hybrid-transaction-public-v2.json"
    ))
    .unwrap();
    let transaction = hex::decode(fixture["transaction"].as_str().unwrap()).unwrap();
    verify_fixture(transaction, 101, 101, 990_000, "settlement-public-v1.json");
}
#[test]
fn funded_rotation_output_has_independently_verifiable_settlement() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/funded-wallet-rotation-public-v1.json"
    ))
    .unwrap();
    let transaction = hex::decode(fixture["wire"].as_str().unwrap()).unwrap();
    verify_fixture(
        transaction.clone(),
        15,
        15,
        80_000,
        "funded-rotation-settlement-public-v1.json",
    );
    // The bundle window closed at 20, but its output remains provable at height 30.
    verify_fixture(transaction,30,15,80_000,"funded-rotation-later-settlement-public-v1.json");
}
fn verify_fixture(transaction: Vec<u8>, height: u64, created_height:u64, expected_atoms: u64, output_name: &str) {
    let operation = Transaction::decode(&transaction).unwrap();
    let outputs = operation.outputs();
    let txid = operation.id().unwrap();
    let key = HybridKey::generate(Role::Continuity).unwrap();
    let tpm: [u8; 33] = p256::ecdsa::SigningKey::from_bytes((&[9u8; 32]).into())
        .unwrap()
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    let member = ParentVoter {
        lineage: [1; 32],
        admitted: true,
        physical: true,
        eligible: true,
        revoked: false,
        hardware_generation: 1,
        key_generation: 1,
        tpm_public: tpm,
        profile: [8; 32],
        public: key.public().clone(),
        reputation: U256::one(),
    };
    let registry = BTreeMap::from([([7; 32], member.clone())]);
    let parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        height: height - 1,
        block: [3; 32],
    };
    let history = [1000 + (height - 1) * 60; 11];
    let trusted = AuthenticatedParent {
        anchor: &parent,
        registry: &registry,
        membership: [4; 32],
        reputation: [5; 32],
        attestation: [6; 32],
        target: [255; 32],
        genesis_timestamp: 1000,
        ancestor_timestamps: &history,
    };
    let expected = ExpectedPayment {
        transaction: txid,
        output_index: 0,
        destination: outputs[0].owner,
        atoms: outputs[0].atoms,
    };
    let point = OutPoint {
        transaction: txid,
        index: 0,
    };
    let mut record = minicbor::Encoder::new(Vec::new());
    record
        .array(7)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&txid)
        .unwrap()
        .u32(0)
        .unwrap()
        .bytes(&expected.destination)
        .unwrap()
        .u64(expected.atoms)
        .unwrap()
        .u64(created_height)
        .unwrap()
        .bool(false)
        .unwrap();
    let mut tree = StateTree::default();
    tree.insert(utxo_key(&point), record.into_writer()).unwrap();
    let header = WorkHeader {
        candidate: Candidate {
            network: NETWORK_ID,
            genesis: [1; 32],
            fingerprint: [2; 32],
            parent: parent.block,
            height,
            timestamp: 1000 + height * 60,
            body_root: [10; 32],
            state_root: tree.root(),
            license: [11; 32],
            worker: [12; 32],
            target: [255; 32],
        },
        authority: [13; 32],
        nonce: 0,
    };
    let decision = Decision {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        purpose: 2,
        height,
        mining_epoch: height,
        continuity_period: (height - 1) / 60,
        round: 2,
        step: 3,
        previous_finalized_anchor: parent.id(),
        parent: parent.block,
        block: header.block_hash(),
        state: tree.root(),
        membership: [4; 32],
        reputation: [5; 32],
        attestation: [6; 32],
    };
    let state_proof = tree
        .proof(decision.anchor(), utxo_key(&point))
        .encode()
        .unwrap();
    let mut vote = Vote {
        decision: decision.clone(),
        nil: false,
        node: [7; 32],
        hardware_generation: 1,
        key_generation: 1,
        sequence: height,
        tpm_identity: member.tpm_identity(),
        profile: member.profile,
        signature: HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
    };
    vote.sign(&key).unwrap();
    let proof = SettlementProof {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        transaction,
        header,
        certificate: Certificate {
            decision,
            votes: vec![vote],
        },
        output_index: 0,
        state_proof,
    };
    let raw = proof.encode().unwrap();
    assert_eq!(SettlementProof::decode(&raw).unwrap(), proof);
    let verified = proof.verify(&trusted, &expected).unwrap();
    assert_eq!(verified.transaction(), txid);
    assert_eq!(verified.atoms(), expected_atoms);
    assert_eq!(verified.created_height(), created_height);
    for field in 0..10 {
        let mut bad = proof.clone();
        match field {
            0 => bad.network ^= 1,
            1 => bad.genesis[0] ^= 1,
            2 => bad.fingerprint[0] ^= 1,
            3 => bad.header.nonce += 1,
            4 => bad.header.candidate.state_root[0] ^= 1,
            5 => bad.certificate.votes[0].signature.fndsa[500] ^= 1,
            6 => bad.certificate.votes[0].signature.ed448[0] ^= 1,
            7 => bad.output_index = 1,
            8 => bad.state_proof[40] ^= 1,
            _ => bad.transaction[40] ^= 1,
        }
        assert!(bad.verify(&trusted, &expected).is_err(), "field {field}");
    }
    for (id, destination, amount) in [
        ([0; 32], expected.destination, expected.atoms),
        (txid, [0; 32], expected.atoms),
        (txid, expected.destination, expected.atoms + 1),
    ] {
        assert!(
            proof
                .verify(
                    &trusted,
                    &ExpectedPayment {
                        transaction: id,
                        output_index: 0,
                        destination,
                        atoms: amount
                    }
                )
                .is_err()
        );
    }
    let mut cloud = registry.clone();
    cloud.get_mut(&[7; 32]).unwrap().physical = false;
    let wrong = AuthenticatedParent {
        registry: &cloud,
        ..trusted
    };
    assert!(proof.verify(&wrong, &expected).is_err());
    for n in [0, 1, raw.len() - 1] {
        assert!(SettlementProof::decode(&raw[..n]).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(SettlementProof::decode(&trailing).is_err());
    let public = serde_json::json!({"schema":"BUILD8-SYNTHETIC-SETTLEMENT-PROOF-V1","synthetic":true,"production_authorized":false,
        "proof":hex::encode(raw),"parent_anchor":hex::encode(parent.encode()),"trusted_target":hex::encode([255;32]),"genesis_timestamp":1000,"ancestor_timestamps":history,
        "trusted_roots":[hex::encode([4;32]),hex::encode([5;32]),hex::encode([6;32])],
        "trusted_voter":{"node":hex::encode([7;32]),"tpm_public":hex::encode(tpm),"profile":hex::encode(member.profile),"hardware_generation":1,"key_generation":1,"weight":1,"descriptor":hex::encode(key.public().descriptor(1).unwrap())},
        "expected_payment":{"txid":hex::encode(txid),"output_index":0,"destination":hex::encode(expected.destination),"atoms":expected.atoms},
        "warning":"Synthetic trusted parent inputs only. No real TPM qualification or production chain authority is asserted."});
    // Generator (create_new: it refuses to overwrite; delete the file first). Run it only for the
    // test whose files must change: the voter key is fresh, so every regeneration changes all bytes.
    if std::env::var("BUILD8_EXPORT_PUBLIC_SETTLEMENT").as_deref() == Ok("1") {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../qualification")
            .join(output_name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .expect("refusing to overwrite: delete the vector file first");
        std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(&public).unwrap()).unwrap();
    }
}
