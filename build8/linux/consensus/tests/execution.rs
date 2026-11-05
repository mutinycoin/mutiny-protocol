use ed25519_dalek::{Signer, SigningKey};
use mutiny_consensus_v8::{NETWORK_ID, blocks::BlockBody, execution::*, transactions::*};
#[test]
fn empty_genesis_mining_maturity_fees_and_failure_atomicity() {
    let key = SigningKey::from_bytes(&[42; 32]);
    let public = key.verifying_key().to_bytes();
    let owner = address(&public);
    let initial = State::default();
    let body = BlockBody {
        height: 1,
        reward_owner: owner,
        fees: 0,
        transactions: vec![],
        operations: vec![],
    };
    let mined = initial
        .execute_transfers([1; 32], [2; 32], [3; 32], owner, &body)
        .unwrap();
    assert!(initial.coins.is_empty());
    assert_eq!(mined.state.coins.len(), 1);
    let point = OutPoint {
        transaction: mined.coinbase_id,
        index: 0,
    };
    assert_eq!(mined.state.coins[&point].output.atoms, SUBSIDY);
    let mut tx = Transfer {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        created_height: 2,
        expiry_height: 200,
        inputs: vec![Input {
            point,
            public_key: public,
            signature: [0; 64],
        }],
        outputs: vec![Output {
            owner: [9; 32],
            atoms: SUBSIDY - 1000,
        }],
    };
    tx.inputs[0].signature = key.sign(&tx.signing_digest(0).unwrap()).to_bytes();
    let mut spend = BlockBody {
        height: 100,
        reward_owner: owner,
        fees: 1000,
        transactions: vec![tx.encode().unwrap()],
        operations: vec![],
    };
    let before = mined.state.root().unwrap();
    assert!(matches!(
        mined
            .state
            .execute_transfers([1; 32], [2; 32], [4; 32], owner, &spend),
        Err(ExecutionError::Transfer(TxError::Immature))
    ));
    assert_eq!(mined.state.root().unwrap(), before);
    spend.height = 101;
    let next = mined
        .state
        .execute_transfers([1; 32], [2; 32], [4; 32], owner, &spend)
        .unwrap();
    assert_eq!(next.fees, 1000);
    assert_eq!(next.state.coins.len(), 2);
    assert_eq!(
        next.state
            .coins
            .values()
            .map(|c| u128::from(c.output.atoms))
            .sum::<u128>(),
        2 * u128::from(SUBSIDY)
    );
    assert_ne!(next.root, before);
    spend.fees += 1;
    assert!(matches!(
        mined
            .state
            .execute_transfers([1; 32], [2; 32], [4; 32], owner, &spend),
        Err(ExecutionError::WrongFees)
    ));
    assert_eq!(mined.state.root().unwrap(), before);
    let mut altered = next.state.clone();
    altered.protocol_records.insert([88; 32], vec![0x81, 1]);
    assert_ne!(altered.root().unwrap(), next.root); // registry/recovery records are covered too
}
