use minicbor::Encoder;
use mutiny_consensus_v8::{
    NETWORK_ID, anchors::FinalizedAnchor, state_proof::*, state_tree::*, transactions::OutPoint,
};

fn context() -> FinalizedAnchor {
    FinalizedAnchor {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        height: u64::MAX,
        block: [3; 32],
    }
}
fn coin(point: &OutPoint, owner: [u8; 32], amount: u64, height: u64) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(7)
        .unwrap()
        .u8(1)
        .unwrap()
        .bytes(&point.transaction)
        .unwrap()
        .u32(point.index)
        .unwrap()
        .bytes(&owner)
        .unwrap()
        .u64(amount)
        .unwrap()
        .u64(height)
        .unwrap()
        .bool(true)
        .unwrap();
    e.into_writer()
}
#[test]
fn typed_utxo_inclusion_absence_and_substitution() {
    let ctx = context();
    let owner = [5; 32];
    let point = OutPoint {
        transaction: [4; 32],
        index: u32::MAX,
    };
    let raw = coin(&point, owner, u64::MAX, u64::MAX);
    assert_eq!(raw.len(), MAX_UTXO_RECORD);
    let mut tree = StateTree::default();
    tree.insert(utxo_key(&point), raw).unwrap();
    let proof = tree.proof(ctx.clone(), utxo_key(&point)).encode().unwrap();
    assert_eq!(
        verify_utxo(&proof, &ctx, tree.root(), &point, owner)
            .unwrap()
            .unwrap()
            .output
            .atoms,
        u64::MAX
    );
    assert!(verify_utxo(&proof, &ctx, tree.root(), &point, [6; 32]).is_err());
    let other = OutPoint {
        transaction: [7; 32],
        index: 0,
    };
    assert!(verify_utxo(&proof, &ctx, tree.root(), &other, owner).is_err());
    let absent = tree.proof(ctx.clone(), utxo_key(&other)).encode().unwrap();
    assert!(
        verify_utxo(&absent, &ctx, tree.root(), &other, owner)
            .unwrap()
            .is_none()
    );
    assert!(verify_utxo(&absent, &ctx, tree.root(), &point, owner).is_err());
    // Even a valid generic inclusion at the expected key cannot substitute a
    // different typed record, outpoint, amount, or future creation height.
    for record in [
        vec![0],
        coin(&other, owner, 1, 1),
        coin(&point, owner, 0, 1),
    ] {
        tree.update(utxo_key(&point), record).unwrap();
        let proof = tree.proof(ctx.clone(), utxo_key(&point)).encode().unwrap();
        assert!(verify_utxo(&proof, &ctx, tree.root(), &point, owner).is_err());
    }
    let mut earlier = ctx.clone();
    earlier.height = 10;
    tree.update(utxo_key(&point), coin(&point, owner, 1, 11))
        .unwrap();
    let proof = tree
        .proof(earlier.clone(), utxo_key(&point))
        .encode()
        .unwrap();
    assert!(verify_utxo(&proof, &earlier, tree.root(), &point, owner).is_err());
    // Wallet bounds run before generic proof parsing/allocation.
    assert!(
        verify_utxo(
            &vec![0; MAX_UTXO_PROOF + 1],
            &ctx,
            tree.root(),
            &point,
            owner
        )
        .is_err()
    );
}

#[test]
fn exact_maximum_encoded_size_and_profile_bounds() {
    let mut record = vec![0x5a, 0, 3, 0xff, 0xfb];
    record.resize(MAX_RECORD, 0);
    let mut p = StateProof {
        context: context(),
        count: MAX_RECORDS as u64,
        key: [0; 32],
        record: Some(record),
        bitmap: [255; 32],
        siblings: vec![[0x55; 32]; 256],
    };
    // Size qualification uses the maximal codec witness. It need not represent
    // an actual state: the authenticated root still must pass in verification.
    let raw = p.encode().unwrap();
    assert_eq!(raw.len(), 271052);
    assert!(raw.len() < MAX_PROOF);
    assert_eq!(StateProof::decode(&raw).unwrap(), p);
    assert!(StateProof::decode_bounded(&raw, MAX_UTXO_PROOF, MAX_UTXO_RECORD).is_err());
    p.record = Some(coin(
        &OutPoint {
            transaction: [4; 32],
            index: u32::MAX,
        },
        [5; 32],
        u64::MAX,
        u64::MAX,
    ));
    let wallet = p.encode().unwrap();
    assert_eq!(wallet.len(), 8999);
    assert!(wallet.len() < MAX_UTXO_PROOF);
    assert_eq!(
        StateProof::decode_bounded(&wallet, MAX_UTXO_PROOF, MAX_UTXO_RECORD).unwrap(),
        p
    );
}

#[test]
fn independent_python_typed_and_rejection_vectors() {
    let bytes = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/STATE-PROOF-V2-TYPED-VECTORS-V1.json"
    ))
    .unwrap();
    let context = FinalizedAnchor::decode(&bytes(&v["context"])).unwrap();
    let root = bytes(&v["root"]).try_into().unwrap();
    for case in v["proofs"].as_array().unwrap() {
        let key = bytes(&case["key"]).try_into().unwrap();
        let p = StateProof::decode(&bytes(&case["proof"])).unwrap();
        assert_eq!(
            p.verify(&context, root, key).unwrap().unwrap(),
            bytes(&case["record"])
        );
    }
    let v: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/STATE-PROOF-V2-REJECTION-VECTORS-V1.json"
    ))
    .unwrap();
    for case in v["cases"].as_array().unwrap() {
        let raw = bytes(&case["encoded"]);
        let root = bytes(&case["root"]).try_into().unwrap();
        let key = bytes(&case["key"]).try_into().unwrap();
        if let Ok(proof) = StateProof::decode(&raw) {
            assert!(
                proof.verify(&context, root, key).is_err(),
                "{}",
                case["name"]
            );
        }
    }
}
