use mutiny_consensus_v8::{
    NETWORK_ID,
    anchors::FinalizedAnchor,
    assembler_v2,
    blocks::{BlockBody, state_root},
    bond_create_v3::FundedBondCreate,
    execution::{State, WorkParent},
    hybrid_transaction_v2::Transaction,
    mempool_v2::Mempool,
    pow::WorkHeader,
    transactions::Output,
    transactions_v2::{Input, Transfer},
};
use mutiny_crypto_v2::{HybridKey, Role};
fn bytes(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
/// Candidate 3 (Lane P design 2.4 and 5.5): the funded BondCreate (operation kind 24) carries its
/// own inputs, so the assembler pre-selects no funding transaction; the caller's operation alone
/// reproduces the vector's block and post-state. A pending payment that spends the create's input
/// is trial-added and skipped (the combination fails the bond-create phase), never fatal and never
/// silently dropping the create.
#[test]
fn funded_bond_is_assembled_atomically_from_public_vector() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/hybrid-funded-candidate-public-v1.json"
    ))
    .unwrap();
    assert_eq!(fixture["synthetic_only"], true);
    let records: Vec<_> = fixture["before"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (bytes(&r["key"]).try_into().unwrap(), bytes(&r["record"])))
        .collect();
    let root = state_root(&records).unwrap();
    let state = State::from_records(&records, root).unwrap();
    let body = BlockBody::decode(&bytes(&fixture["body"])).unwrap();
    assert!(body.transactions.is_empty(), "no separate funding transaction exists");
    let create = FundedBondCreate::decode(&body.operations[0]).unwrap();
    assert_eq!(body.fees, create.unsigned.fee, "the declared create fee is the block fee");
    let licensed: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/licensed-execution-v2-public-v1.json"
    ))
    .unwrap();
    let candidate = WorkHeader::decode(&bytes(&licensed["blocks"][0]["header"]))
        .unwrap()
        .candidate;
    let anchor = FinalizedAnchor::decode(&bytes(&fixture["parent"])).unwrap();
    let parent = WorkParent {
        genesis: anchor.genesis,
        fingerprint: anchor.fingerprint,
        block: anchor.block,
        height: anchor.height,
        t0: 1000,
        target: candidate.target,
        ancestor_timestamps: vec![1000],
    };
    let mut nonce = [0; 16];
    mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let path = std::env::temp_dir().join(format!(
        "build8-funded-assembly-{}.sqlite",
        hex::encode(nonce)
    ));
    let mut pool =
        Mempool::open(&path, parent.genesis, parent.fingerprint, 64 * 1024 * 1024).unwrap();
    pool.reconcile(&anchor, &state, &Default::default())
        .unwrap();
    macro_rules! request {
        () => {
            assembler_v2::Request {
                parent: &parent,
                state: &state,
                pool: &pool,
                license: candidate.license,
                worker: candidate.worker,
                timestamp: candidate.timestamp,
                ticket: fixture["ticket_sequence"].as_u64().unwrap(),
                operations: &body.operations,
            }
        };
    }
    let expected: Vec<_> = fixture["after"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (bytes(&r["key"]).try_into().unwrap(), bytes(&r["record"])))
        .collect();
    let ready = assembler_v2::prepare(request!()).unwrap();
    assert_eq!(ready.body, body);
    assert_eq!(ready.execution.root.to_vec(), bytes(&fixture["post_root"]));
    assert_eq!(ready.execution.state.records().unwrap(), expected);
    // A valid pending payment spending the create's own input: admitted by the pool, trial-added
    // by the assembler, and skipped because the block holding both fails (MissingInput at V7).
    let owner =
        HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner)
            .unwrap();
    let input = create.unsigned.inputs[0].clone();
    let atoms = state.coins[&input].output.atoms;
    let mut spend = Transfer {
        network: NETWORK_ID,
        genesis: anchor.genesis,
        fingerprint: anchor.fingerprint,
        created_height: anchor.height + 1,
        expiry_height: anchor.height + 2,
        fee: 5000,
        inputs: vec![Input::unsigned(input, owner.public(), 1).unwrap()],
        outputs: vec![Output {
            owner: [94; 32],
            atoms: atoms - 5000,
        }],
    };
    spend.sign_input(0, &owner).unwrap();
    pool.admit(&Transaction::Transfer(spend), &anchor, &state)
        .unwrap();
    assert_eq!(pool.pending_at(&anchor, &state).unwrap().len(), 1);
    let skipped = assembler_v2::prepare(request!()).unwrap();
    assert_eq!(skipped.body, body, "the conflicting payment is not included");
    assert_eq!(skipped.execution.state.records().unwrap(), expected);
    assert_eq!(
        assembler_v2::prepare_with_history(request!(), &Default::default())
            .unwrap()
            .candidate,
        ready.candidate
    );
    let mut bad = body.operations.clone();
    let last = bad[0].len() - 1;
    bad[0][last] ^= 1;
    let mut invalid = request!();
    invalid.operations = &bad;
    assert!(assembler_v2::prepare(invalid).is_err());
    assert_eq!(state.root().unwrap(), root);
    assert_eq!(pool.pending_at(&anchor, &state).unwrap().len(), 1);
    drop(pool);
    std::fs::remove_file(path).unwrap();
}
