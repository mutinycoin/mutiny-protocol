use mutiny_consensus_v8::{
    NETWORK_ID, anchors::FinalizedAnchor, block_envelope::BlockEnvelope, blocks::*,
    canonical_store::*, certificates::*, execution::State, genesis::*, licenses::*, pow::*,
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use primitive_types::U256;
use serde_json::Value;
fn raw(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
#[test]
fn state_finality_and_pool_basis_commit_atomically_and_duplicate_proof_never_mints() {
    let v: Value = serde_json::from_str(include_str!(
        "../../qualification/GENESIS-BINDING-VECTORS-STATE-V2.json"
    ))
    .unwrap();
    let descriptor = GenesisDescriptor::decode(&raw(&v["descriptor_hex"])).unwrap();
    let identity = GenesisIdentity::new(descriptor.clone()).unwrap();
    let case = &v["cases"][0];
    let bindings: Vec<_> = case["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| BindWorker::decode(&raw(&b["binding_hex"])).unwrap())
        .collect();
    let initial = State {
        licenses: identity.bind_workers(&bindings).unwrap(),
        ..State::default()
    };
    let header = WorkHeader::decode(&raw(&case["height1"]["header_hex"])).unwrap();
    let body = BlockBody::decode(&raw(&case["height1"]["body_hex"])).unwrap();
    let (authority, authority_signature) =
        WorkAuthority::from_envelope(&raw(&case["height1"]["authority_envelope_hex"])).unwrap();
    let parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: identity.id(),
        fingerprint: descriptor.fingerprint,
        height: 0,
        block: header.candidate.parent,
    };
    let decision = Decision {
        network: NETWORK_ID,
        genesis: identity.id(),
        fingerprint: descriptor.fingerprint,
        purpose: 2,
        height: 1,
        mining_epoch: 0,
        continuity_period: 0,
        round: 0,
        step: 3,
        previous_finalized_anchor: parent.id(),
        parent: parent.block,
        block: header.block_hash(),
        state: header.candidate.state_root,
        membership: [7; 32],
        reputation: [8; 32],
        attestation: [9; 32],
    };
    let key = SigningKey::from_bytes((&[30; 32]).into()).unwrap();
    let registry = [(
        [1; 32],
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
    )]
    .into_iter()
    .collect();
    let certify = |decision: Decision| {
        let s: Signature = key
            .sign_prehash(&decision.signing_digest([1; 32], 1))
            .unwrap();
        Certificate {
            decision,
            signers: vec![Signer {
                node: [1; 32],
                key_version: 1,
                signature: s.normalize_s().unwrap_or(s).to_bytes().into(),
            }],
        }
    };
    let block = BlockEnvelope {
        header,
        body,
        authority,
        authority_signature,
        certificate: certify(decision.clone()),
    };
    let path = std::env::temp_dir().join(format!("build8-canonical-{}.sqlite", std::process::id()));
    assert!(!path.exists());
    let target = block.header.candidate.target;
    {
        let mut store =
            CanonicalStore::open_trusted_genesis(&path, &descriptor, &initial, target).unwrap();
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute_batch("CREATE TRIGGER injected_failure BEFORE INSERT ON chain_history WHEN NEW.height != X'0000000000000000' BEGIN SELECT RAISE(ABORT,'injected failure after state and mempool changes'); END;").unwrap();
        assert!(
            store
                .commit_successor(&block, &decision, &registry)
                .is_err()
        );
        let (head, state) = store.load().unwrap();
        assert_eq!(head.height, 0);
        assert_eq!(state, initial);
        let basis: Vec<u8> = db
            .query_row("SELECT height FROM basis", [], |r| r.get(0))
            .unwrap();
        assert_eq!(basis, 0u64.to_be_bytes());
        db.execute_batch("DROP TRIGGER injected_failure;").unwrap();
        assert!(
            store
                .commit_successor(&block, &decision, &registry)
                .unwrap()
        );
        let (head, state) = store.load().unwrap();
        assert_eq!(head.height, 1);
        assert_eq!(head.block, block.block_hash());
        assert_eq!(state.coins.len(), 1);
        let mut alternate = block.clone();
        let mut later = decision.clone();
        later.round = 1;
        alternate.certificate = certify(later.clone());
        assert!(
            !store
                .commit_successor(&alternate, &later, &registry)
                .unwrap()
        );
        assert_eq!(store.load().unwrap().1, state);
        let basis: Vec<u8> = db
            .query_row("SELECT height FROM basis", [], |r| r.get(0))
            .unwrap();
        assert_eq!(basis, 1u64.to_be_bytes());
    }
    {
        let mut store =
            CanonicalStore::open_trusted_genesis(&path, &descriptor, &initial, target).unwrap();
        let (head, state) = store.load().unwrap();
        assert_eq!(head.height, 1);
        assert_eq!(state.coins.len(), 1);
        let mut wrong = descriptor.clone();
        wrong.timestamp += 1;
        assert!(CanonicalStore::open_trusted_genesis(&path, &wrong, &initial, target).is_err());
        let mut conflicting = decision.clone();
        conflicting.block = [99; 32];
        conflicting.state = [98; 32];
        let conflict = certify(conflicting.clone());
        assert!(
            store
                .inspect_history_proof(&conflict, &conflicting, &registry)
                .is_err()
        );
        assert!(
            store
                .commit_successor(&block, &decision, &registry)
                .is_err()
        );
        assert_eq!(store.load().unwrap().1, state);
        let db = rusqlite::Connection::open(&path).unwrap();
        db.execute(
            "UPDATE chain_state SET value=X'80' WHERE key=(SELECT key FROM chain_state LIMIT 1)",
            [],
        )
        .unwrap();
        assert!(store.load().is_err());
    }
    std::fs::remove_file(path).unwrap();
}
