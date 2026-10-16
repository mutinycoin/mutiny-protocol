use mutiny_consensus_v8::{
    NETWORK_ID,
    transactions::{Coin, OutPoint, Output, TxError},
    transactions_v2::{Input, Transfer},
};
use mutiny_crypto_v2::{HybridKey, Role};
use std::collections::BTreeMap;
#[test]
fn hybrid_transaction_full_intent_conservation_bounds_and_public_transport_fixture() {
    let key = HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner).unwrap();
    let owner = key.public().address_id(1).unwrap();
    let point = OutPoint {
        transaction: [8; 32],
        index: 0,
    };
    let mut coins = BTreeMap::from([(
        point.clone(),
        Coin {
            output: Output {
                owner,
                atoms: 1_000_000,
            },
            created_height: 1,
            coinbase: true,
        },
    )]);
    let mut tx = Transfer {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        created_height: 100,
        expiry_height: 200,
        fee: 10_000,
        inputs: vec![Input::unsigned(point.clone(), key.public(), 1).unwrap()],
        outputs: vec![Output {
            owner: [9; 32],
            atoms: 990_000,
        }],
    };
    tx.sign_input(0, &key).unwrap();
    let raw = tx.encode().unwrap();
    assert_eq!(Transfer::decode(&raw).unwrap(), tx);
    assert_eq!(tx.verify([1; 32], [2; 32], 101, &coins, &Default::default()).unwrap(), 10_000);
    assert_eq!(
        tx.verify([1; 32], [2; 32], 100, &coins, &Default::default()).unwrap_err(),
        TxError::Immature
    );
    assert_eq!(
        tx.verify([1; 32], [2; 32], 99, &coins, &Default::default()).unwrap_err(),
        TxError::Future
    );
    assert_eq!(
        tx.verify([1; 32], [2; 32], 201, &coins, &Default::default()).unwrap_err(),
        TxError::Expired
    );
    for field in 0..10 {
        let mut bad = tx.clone();
        match field {
            0 => bad.network ^= 1,
            1 => bad.genesis[0] ^= 1,
            2 => bad.fingerprint[0] ^= 1,
            3 => bad.created_height += 1,
            4 => bad.expiry_height += 1,
            5 => bad.fee += 1,
            6 => bad.outputs[0].atoms -= 1,
            7 => bad.outputs[0].owner[0] ^= 1,
            8 => bad.inputs[0].signature.ed448[0] ^= 1,
            _ => bad.inputs[0].signature.fndsa[500] ^= 1,
        }
        assert!(
            bad.verify([1; 32], [2; 32], 150, &coins, &Default::default()).is_err(),
            "field {field}"
        );
    }
    let id = tx.id().unwrap();
    tx.sign_input(0, &key).unwrap();
    assert_eq!(id, tx.id().unwrap()); // signature randomness does not change economic TxID
    let mut duplicate = tx.clone();
    duplicate.inputs.push(duplicate.inputs[0].clone());
    assert_eq!(duplicate.encode().unwrap_err(), TxError::Duplicate);
    let mut low_fee = tx.clone();
    low_fee.fee = 1;
    low_fee.outputs[0].atoms = 999_999;
    low_fee.sign_input(0, &key).unwrap();
    assert_eq!(
        low_fee.verify([1; 32], [2; 32], 150, &coins, &Default::default()).unwrap_err(),
        TxError::Fee
    );
    let mut bad_generation = tx.clone();
    bad_generation.inputs[0].descriptor = key.public().descriptor(2).unwrap();
    bad_generation.sign_input(0, &key).unwrap();
    assert_eq!(
        bad_generation
            .verify([1; 32], [2; 32], 150, &coins, &Default::default())
            .unwrap_err(),
        TxError::Owner
    );
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(Transfer::decode(&trailing).is_err());
    for n in 0..raw.len() {
        assert!(Transfer::decode(&raw[..n]).is_err());
    }
    let mut obsolete = raw.clone();
    obsolete[1] = 1;
    assert!(Transfer::decode(&obsolete).is_err());
    coins.get_mut(&point).unwrap().output.atoms = 1;
    assert_eq!(
        tx.verify([1; 32], [2; 32], 150, &coins, &Default::default()).unwrap_err(),
        TxError::Conservation
    );
    if std::env::var("BUILD8_EXPORT_PUBLIC_TRANSACTION").as_deref() == Ok("1") {
        let v = serde_json::json!({"schema":"BUILD8-SYNTHETIC-HYBRID-TRANSACTION-V2","synthetic":true,"production_authorized":false,
            "transaction":hex::encode(tx.encode().unwrap()),"txid":hex::encode(tx.id().unwrap()),"bytes":tx.encode().unwrap().len(),
            "signing_payload":hex::encode(tx.signing_payload(0).unwrap()),"source_owner":hex::encode(owner),
            "utxo":{"transaction":hex::encode(point.transaction),"index":0,"atoms":1_000_000,"created_height":1,"coinbase":true}});
        std::fs::write(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../qualification/hybrid-transaction-public-v2.json"),
            serde_json::to_vec_pretty(&v).unwrap(),
        )
        .unwrap();
    }
}
