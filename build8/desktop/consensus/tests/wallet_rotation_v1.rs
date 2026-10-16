use mutiny_consensus_v8::{
    NETWORK_ID,
    wallet_rotation_v1::{MAX_ROTATION, Rotation},
};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, Role};
fn fixture() -> (HybridKey, HybridKey, Rotation) {
    // Standard public BIP39 vectors, never production identity material.
    let old =
        HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner)
            .unwrap();
    let new = HybridKey::wallet_restore(&format!("{}vote", "zoo ".repeat(23)), Role::WalletOwner)
        .unwrap();
    let zero = HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    };
    let mut r = Rotation {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        authority: [3; 32],
        current: old.public().descriptor(1).unwrap(),
        proposed: new.public().descriptor(2).unwrap(),
        created_height: 10,
        expiry_height: 20,
        authorization: zero.clone(),
        possession: zero,
    };
    r.sign(&old, &new).unwrap();
    (old, new, r)
}
#[test]
fn rotation_requires_both_current_halves_and_both_new_halves_on_exact_context() {
    let (old, new, r) = fixture();
    let verify = |v: &Rotation| v.verify([1; 32], [2; 32], 15, [3; 32], &r.current);
    let bytes = r.encode().unwrap();
    assert!(bytes.len() < MAX_ROTATION);
    assert_eq!(Rotation::decode(&bytes).unwrap(), r);
    assert!(verify(&r).is_ok());
    for field in 0..13 {
        let mut bad = r.clone();
        match field {
            0 => bad.network ^= 1,
            1 => bad.genesis[0] ^= 1,
            2 => bad.fingerprint[0] ^= 1,
            3 => bad.authority[0] ^= 1,
            4 => bad.created_height = 16,
            5 => bad.expiry_height = 14,
            6 => bad.authorization.ed448[0] ^= 1,
            7 => bad.authorization.fndsa[0] ^= 1,
            8 => bad.possession.ed448[0] ^= 1,
            9 => bad.possession.fndsa[0] ^= 1,
            10 => bad.proposed = old.public().descriptor(2).unwrap(),
            11 => bad.proposed = new.public().descriptor(3).unwrap(),
            _ => bad.current = new.public().descriptor(1).unwrap(),
        }
        assert!(verify(&bad).is_err(), "field {field}");
    }
    let mut wrong_domain = r.clone();
    wrong_domain.possession = new
        .sign(Domain::WalletRotate, &r.unsigned().unwrap())
        .unwrap();
    assert!(verify(&wrong_domain).is_err());
    let mut wrong_role = r.clone();
    let recovery =
        HybridKey::wallet_restore(&format!("{}vote", "zoo ".repeat(23)), Role::WalletRecovery)
            .unwrap();
    wrong_role.proposed = recovery.public().descriptor(2).unwrap();
    assert!(wrong_role.unsigned().is_err());
    let mut overflow = r.clone();
    overflow.current = old.public().descriptor(u64::MAX).unwrap();
    overflow.proposed = new.public().descriptor(1).unwrap();
    assert!(overflow.unsigned().is_err());
    let mut altered = r.clone();
    altered.sign(&old, &new).unwrap();
    assert_eq!(altered.identity().unwrap(), r.identity().unwrap());
    if std::env::var("BUILD8_EXPORT_WALLET_ROTATION").as_deref() == Ok("1") {
        let body = r.unsigned().unwrap();
        use sha2::{Digest, Sha512};
        let intent = |domain: Domain| {
            let mut h = Sha512::new();
            h.update(domain.bytes());
            h.update([0]);
            h.update(&body);
            hex::encode(h.finalize())
        };
        let public = serde_json::json!({"schema":"BUILD8-WALLET-ROTATION-PUBLIC-V1","synthetic_only":true,
          "wire":hex::encode(&bytes),"unsigned":hex::encode(&body),"identity":hex::encode(r.identity().unwrap()),
          "old_intent":intent(Domain::WalletRotate),"new_intent":intent(Domain::WalletRotatePossession),
          "current":hex::encode(&r.current),"proposed":hex::encode(&r.proposed)});
        std::fs::write(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../qualification/wallet-rotation-public-v1.json"),
            serde_json::to_vec_pretty(&public).unwrap(),
        )
        .unwrap();
    }
}
#[test]
fn rotation_atomic_compare_replace_replay_and_hostile_codec() {
    let (_, _, r) = fixture();
    let verified = r.verify([1; 32], [2; 32], 10, [3; 32], &r.current).unwrap();
    let mut state = r.current.clone();
    assert!(verified.apply([4; 32], &mut state).is_err());
    assert_eq!(state, r.current);
    verified.apply([3; 32], &mut state).unwrap();
    assert_eq!(state, r.proposed);
    assert!(verified.apply([3; 32], &mut state).is_err());
    assert!(r.verify([1; 32], [2; 32], 15, [3; 32], &state).is_err());
    assert_eq!(state, r.proposed);
    let raw = r.encode().unwrap();
    for n in 0..raw.len() {
        assert!(Rotation::decode(&raw[..n]).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(Rotation::decode(&trailing).is_err());
    assert!(Rotation::decode(&vec![0; MAX_ROTATION + 1]).is_err());
    let mut nonminimal = vec![0x98, 6];
    nonminimal.extend_from_slice(&raw[1..]);
    assert!(Rotation::decode(&nonminimal).is_err());
    assert!(Rotation::decode(&[0x9f, 0xff]).is_err());
}

#[test]
fn canonical_wallet_records_retire_old_keys_and_preserve_exact_utxo_addresses() {
    use mutiny_consensus_v8::{
        blocks::state_root,
        execution::State,
        transactions::{Coin, OutPoint, Output},
        transactions_v2::{Input, Transfer},
    };
    let (old, new, mut rotation) = fixture();
    let mut state = State::default();
    let id = state.wallets.register(&rotation.current).unwrap();
    assert_eq!(id, old.public().address_id(1).unwrap());
    rotation.authority = id;
    rotation.sign(&old, &new).unwrap();
    let point = OutPoint {
        transaction: [8; 32],
        index: 0,
    };
    state.coins.insert(
        point.clone(),
        Coin {
            output: Output {
                owner: id,
                atoms: 100_000,
            },
            created_height: 1,
            coinbase: false,
        },
    );
    let mut tx = Transfer {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        created_height: 10,
        expiry_height: 20,
        fee: 10_000,
        inputs: vec![Input::unsigned(point.clone(), old.public(), 1).unwrap()],
        outputs: vec![Output {
            owner: [9; 32],
            atoms: 90_000,
        }],
    };
    tx.sign_input(0, &old).unwrap();
    assert!(
        tx.verify([1; 32], [2; 32], 15, &state.coins, &state.wallets)
            .is_ok()
    );
    let before = state.root().unwrap();
    let saved = state.clone();
    let mut invalid = rotation.clone();
    invalid.possession.fndsa[0] ^= 1;
    assert!(state.wallets.apply(&invalid, [1; 32], [2; 32], 15).is_err());
    assert_eq!(state, saved);
    state
        .wallets
        .apply(&rotation, [1; 32], [2; 32], 15)
        .unwrap();
    assert_ne!(state.root().unwrap(), before);
    assert_eq!(state.coins, saved.coins); // Rotation changes authority, never coin identity/value.
    assert!(
        tx.verify([1; 32], [2; 32], 15, &state.coins, &state.wallets)
            .is_err()
    );
    tx.inputs[0] = Input::unsigned(point, new.public(), 2).unwrap();
    tx.sign_input(0, &new).unwrap();
    assert!(
        tx.verify([1; 32], [2; 32], 15, &state.coins, &state.wallets)
            .is_ok()
    );
    assert!(
        tx.verify([1; 32], [2; 32], 15, &state.coins, &Default::default())
            .is_err()
    );
    let records = state.records().unwrap();
    let root = state.root().unwrap();
    if std::env::var("BUILD8_EXPORT_WALLET_STATE").as_deref() == Ok("1") {
        let export = serde_json::json!({"schema":"BUILD8-WALLET-AUTHORITY-STATE-PUBLIC-V1","synthetic_only":true,
            "root":hex::encode(root),"authority":hex::encode(id),
            "records":records.iter().map(|(key,raw)|serde_json::json!({"key":hex::encode(key),"record":hex::encode(raw)})).collect::<Vec<_>>()});
        std::fs::write(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../qualification/wallet-authority-state-public-v1.json"),
            serde_json::to_vec_pretty(&export).unwrap(),
        )
        .unwrap();
    }
    let replay = State::from_records(&records, root).unwrap();
    assert_eq!(replay, state);
    assert!(
        tx.verify([1; 32], [2; 32], 15, &replay.coins, &replay.wallets)
            .is_ok()
    );
    let stable = state.clone();
    assert!(
        state
            .wallets
            .apply(&rotation, [1; 32], [2; 32], 15)
            .is_err()
    );
    assert_eq!(state, stable);
    let wallet_records = state.wallets.records().unwrap();
    assert_eq!(wallet_records.len(), 3);
    for key in wallet_records.keys() {
        let incomplete: Vec<_> = records.iter().filter(|(k, _)| k != key).cloned().collect();
        assert!(State::from_records(&incomplete, state_root(&incomplete).unwrap()).is_err());
    }
    let mut malformed = records.clone();
    let at = malformed
        .iter()
        .position(|(key, _)| wallet_records.contains_key(key))
        .unwrap();
    malformed[at].0 = [0xa5; 32];
    malformed.sort_by_key(|(key, _)| *key);
    assert!(State::from_records(&malformed, state_root(&malformed).unwrap()).is_err());
}

/// The funded wallet-rotation bundle (Lane P design 3.1/3.2: hybrid transaction tag 25, which
/// REPLACES the retired `[2, 21, rotation, transfer]` wrapper) executes atomically: the rotation, the
/// input consumption, the outputs and the fee are one item; every signed byte is charged.
/// `BUILD8_EXPORT_FUNDED_ROTATION=1` regenerates `qualification/funded-wallet-rotation-public-v1.json`
/// (create_new: delete the file first).
#[test]
fn funded_rotation_executes_atomically_and_charges_all_signed_bytes() {
    use mutiny_consensus_v8::{
        anchors::FinalizedAnchor,
        blocks::BlockBody,
        evidence_history_v2::History,
        execution::State,
        funded_rotation_v2::{self as fr, Party, PartialRotation, Payer, UnsignedRotation},
        hybrid_transaction_v2::{Inclusion, Transaction},
        op_envelope_v1::Envelope,
        transactions::{Coin, OutPoint, Output, SUBSIDY, TxError},
    };
    let (old, new, _) = fixture();
    let id = old.public().address_id(1).unwrap();
    let point = OutPoint {
        transaction: [8; 32],
        index: 0,
    };
    let mut initial = State::default();
    initial.coins.insert(
        point.clone(),
        Coin {
            output: Output {
                owner: id,
                atoms: 100_000,
            },
            created_height: 1,
            coinbase: false,
        },
    );
    // Signed at the parent of the executing block (height 14, block [4; 32]): window [15, 20].
    let parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        height: 14,
        block: [4; 32],
    };
    let bundle = |fee: u64| {
        let unsigned = UnsignedRotation {
            genesis: [1; 32],
            fingerprint: [2; 32],
            envelope: Envelope::from_head(&parent, 5, vec![]).unwrap(),
            authority: id,
            current_descriptor: old.public().descriptor(1).unwrap(),
            proposed_descriptor: new.public().descriptor(2).unwrap(),
            sponsor: None,
            fee,
            inputs: vec![(point.clone(), Payer::RotatingAuthority)],
            outputs: vec![Output {
                owner: new.public().address_id(2).unwrap(),
                atoms: 100_000 - fee,
            }],
        };
        let mut partial = PartialRotation::new(unsigned);
        for intent in fr::signing_intents(&partial.unsigned).unwrap() {
            let key = if intent.party == Party::NewKey { &new } else { &old };
            partial.sign(intent.slot, key).unwrap();
        }
        Transaction::FundedRotation(partial.complete().unwrap())
    };
    let transaction = bundle(20_000);
    let raw = transaction.encode().unwrap();
    assert_eq!(Transaction::decode(&raw).unwrap(), transaction);
    assert!(raw.len() > 8_000 && raw.len() < 16_384, "{}", raw.len());
    // The fee must cover every signed byte of the bundle (all four signature slots included).
    let fee_insufficient = bundle(5_000);
    assert!((5_000 as usize) < fee_insufficient.encode().unwrap().len());
    let history = History::default();
    assert!(matches!(
        fee_insufficient.verify(&Inclusion { parent: &parent, history: &history }, &initial),
        Err(TxError::Fee)
    ));
    let body = BlockBody {
        height: 15,
        reward_owner: id,
        fees: 20_000,
        transactions: vec![raw.clone()],
        operations: vec![],
    };
    let saved = initial.clone();
    let execution = initial
        .execute_hybrid_transfers([1; 32], [2; 32], [4; 32], id, &body)
        .unwrap();
    assert_eq!(initial, saved);
    assert!(execution.state.coins.get(&point).is_none());
    assert_eq!(
        execution.state.wallets.current(id),
        Some(new.public().descriptor(2).unwrap().as_slice())
    );
    let output = OutPoint {
        transaction: transaction.id().unwrap(),
        index: 0,
    };
    assert_eq!(execution.state.coins[&output].output.atoms, 80_000);
    assert_eq!(
        execution
            .state
            .coins
            .values()
            .map(|coin| coin.output.atoms as u128)
            .sum::<u128>(),
        100_000 + SUBSIDY as u128
    );
    assert_eq!(
        State::from_records(&execution.state.records().unwrap(), execution.root).unwrap(),
        execution.state
    );
    assert!(
        initial
            .execute_transfers([1; 32], [2; 32], [4; 32], id, &body)
            .is_err()
    );
    let mut duplicate = body.clone();
    duplicate.transactions.push(raw.clone());
    duplicate.fees = 40_000;
    assert!(
        initial
            .execute_hybrid_transfers([1; 32], [2; 32], [4; 32], id, &duplicate)
            .is_err()
    );
    assert_eq!(initial, saved);
    let mut bad_context = body.clone();
    bad_context.transactions[0] = fee_insufficient.encode().unwrap();
    bad_context.fees = 5_000;
    assert!(
        initial
            .execute_hybrid_transfers([1; 32], [2; 32], [4; 32], id, &bad_context)
            .is_err()
    );
    assert_eq!(initial, saved);
    assert!(transaction.verify_signatures([1; 32], [2; 32], 15).is_ok());
    assert!(transaction.verify_signatures([1; 32], [2; 32], 21).is_err());
    if std::env::var("BUILD8_EXPORT_FUNDED_ROTATION").as_deref() == Ok("1") {
        let export = serde_json::json!({"schema":"BUILD8-FUNDED-WALLET-ROTATION-PUBLIC-V1","synthetic_only":true,
            "wire_format":"funded wallet-rotation bundle, hybrid transaction tag 25 (qualification/candidate-3/P-LANE-DESIGN-V1.md 3.2); the retired [2,21,rotation,transfer] wrapper no longer decodes",
            "wire":hex::encode(&raw),"id":hex::encode(transaction.id().unwrap()),"fee":20_000,
            "initial_root":hex::encode(initial.root().unwrap()),"final_root":hex::encode(execution.root),
            "final_records":execution.state.records().unwrap().iter().map(|(key,value)|serde_json::json!({"key":hex::encode(key),"record":hex::encode(value)})).collect::<Vec<_>>()});
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../qualification/funded-wallet-rotation-public-v1.json");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .expect("refusing to overwrite: delete the vector file first");
        std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(&export).unwrap()).unwrap();
    }
}

#[test]
fn wallet_lookup_proves_current_authority_or_exact_address_absence() {
    use mutiny_consensus_v8::{
        anchors::FinalizedAnchor,
        execution::State,
        state_proof::verify_wallet_authority,
        state_tree::StateTree,
        wallet_authority_v1::{address_key, current_key},
    };
    let (old, new, mut rotation) = fixture();
    let mut state = State::default();
    let id = state.wallets.register(&rotation.current).unwrap();
    rotation.authority = id;
    rotation.sign(&old, &new).unwrap();
    state
        .wallets
        .apply(&rotation, [1; 32], [2; 32], 15)
        .unwrap();
    let mut tree = StateTree::default();
    for (key, raw) in state.records().unwrap() {
        tree.insert(key, raw).unwrap();
    }
    let anchor = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        height: 15,
        block: [4; 32],
    };
    let address = tree
        .proof(anchor.clone(), address_key(id))
        .encode()
        .unwrap();
    let current = tree
        .proof(anchor.clone(), current_key(id))
        .encode()
        .unwrap();
    let verified = verify_wallet_authority(&address, &current, &anchor, tree.root(), id).unwrap();
    assert_eq!(verified.authority(), Some(id));
    assert_eq!(verified.descriptor(), Some(rotation.proposed.as_slice()));
    assert_eq!(verified.context(), &anchor);
    assert_eq!(verified.root(), tree.root());
    assert!(verified.authorize(&rotation.proposed).is_ok());
    assert!(verified.authorize(&rotation.current).is_err());
    assert!(verify_wallet_authority(&address, &[], &anchor, tree.root(), id).is_err());
    assert!(verify_wallet_authority(&address, &current, &anchor, [0; 32], id).is_err());
    let mut changed = anchor.clone();
    changed.height += 1;
    assert!(verify_wallet_authority(&address, &current, &changed, tree.root(), id).is_err());
    assert!(verify_wallet_authority(&address, &current, &anchor, tree.root(), [9; 32]).is_err());
    let unregistered = new.public().address_id(1).unwrap();
    let absent = tree
        .proof(anchor.clone(), address_key(unregistered))
        .encode()
        .unwrap();
    let absence =
        verify_wallet_authority(&absent, &[], &anchor, tree.root(), unregistered).unwrap();
    if std::env::var("BUILD8_EXPORT_WALLET_AUTHORITY_PROOF").as_deref() == Ok("1") {
        let export = serde_json::json!({"schema":"BUILD8-WALLET-AUTHORITY-PROOF-PUBLIC-V1","synthetic_only":true,
            "context":hex::encode(anchor.encode()),"root":hex::encode(tree.root()),"address":hex::encode(id),
            "address_proof":hex::encode(&address),"current_proof":hex::encode(&current),
            "unregistered_address":hex::encode(unregistered),"absence_proof":hex::encode(&absent),
            "current_descriptor":hex::encode(&rotation.proposed),"old_descriptor":hex::encode(&rotation.current),
            "unregistered_descriptor":hex::encode(new.public().descriptor(1).unwrap())});
        std::fs::write(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../qualification/wallet-authority-proof-public-v1.json"),
            serde_json::to_vec_pretty(&export).unwrap()).unwrap();
    }
    assert_eq!(absence.descriptor(), None);
    assert!(
        absence
            .authorize(&new.public().descriptor(1).unwrap())
            .is_ok()
    );
    assert!(absence.authorize(&rotation.proposed).is_err());
    assert!(absence.authorize(&rotation.current).is_err());
    assert!(
        verify_wallet_authority(&absent, &current, &anchor, tree.root(), unregistered).is_err()
    );
    for n in [0, 1, address.len() - 1] {
        assert!(
            verify_wallet_authority(&address[..n], &current, &anchor, tree.root(), id).is_err()
        );
    }
}
#[test]
fn malformed_wallet_record_tags_cannot_fall_through_as_opaque_state() {
    use mutiny_consensus_v8::{blocks::state_root, execution::State};
    for kind in [30u8,31] {
        for arity in 2..=6 {
            let mut e=minicbor::Encoder::new(Vec::new());
            e.array(arity).unwrap().u8(1).unwrap().u8(kind).unwrap();
            for _ in 2..arity {e.u8(0).unwrap();}
            let raw=e.into_writer();
            let records=vec![([99;32],raw.clone())];
            let root=state_root(&records).unwrap();
            assert!(State::from_records(&records,root).is_err());
            let mut candidate=State::default();candidate.protocol_records.insert([99;32],raw);
            assert!(candidate.records().is_err());
        }
    }
}
