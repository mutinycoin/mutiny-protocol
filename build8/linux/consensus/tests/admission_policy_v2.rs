use mutiny_consensus_v8::{
    NETWORK_ID,
    admission_policy_v2::{Record, key},
    admission_v2::Policy,
    blocks::state_root,
    execution::State,
    wallet_rotation_v1::Rotation,
};
use mutiny_crypto_v2::{HybridKey, HybridSignature, Role};
use std::collections::BTreeSet;
fn fixture() -> (HybridKey, State, Record) {
    let owner =
        HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner)
            .unwrap();
    let descriptor = owner.public().descriptor(1).unwrap();
    let record = Record::new(Policy {
        genesis: [1; 32],
        fingerprint: [2; 32],
        owner_descriptor: descriptor.clone(),
        endorsement_roots: BTreeSet::from([[3; 32]]),
    })
    .unwrap();
    let mut state = State::default();
    state.wallets.register(&descriptor).unwrap();
    state.admission_policy_v2 = Some(record.clone());
    (owner, state, record)
}
#[test]
fn policy_is_committed_typed_and_context_checked() {
    let (_, state, record) = fixture();
    let root = state.root().unwrap();
    let records = state.records().unwrap();
    if let Some(path)=std::env::var_os("BUILD8_EXPORT_ADMISSION_POLICY_PUBLIC_V1") {
        use std::io::Write;
        let public=serde_json::json!({"schema":"BUILD8-ADMISSION-POLICY-PUBLIC-V1","synthetic_only":true,
            "key":hex::encode(key()),"wire":hex::encode(record.encode().unwrap()),
            "policy":hex::encode(record.initial().encode().unwrap()),"root":hex::encode(root),
            "records":records.iter().map(|(k,v)|serde_json::json!({"key":hex::encode(k),"value":hex::encode(v)})).collect::<Vec<_>>()});
        std::fs::OpenOptions::new().write(true).create_new(true).open(path).unwrap()
            .write_all(&serde_json::to_vec_pretty(&public).unwrap()).unwrap();
    }
    assert_eq!(State::from_records(&records, root).unwrap(), state);
    assert_eq!(
        state.current_admission_policy_v2([1; 32], [2; 32]).unwrap(),
        *record.initial()
    );
    assert!(state.current_admission_policy_v2([9; 32], [2; 32]).is_err());
    assert!(state.current_admission_policy_v2([1; 32], [9; 32]).is_err());
    let mut missing = state.clone();
    missing.admission_policy_v2 = None;
    assert_ne!(missing.root().unwrap(), root);
    assert!(
        missing
            .current_admission_policy_v2([1; 32], [2; 32])
            .is_err()
    );
    let mut changed = record.initial().clone();
    changed.endorsement_roots.insert([4; 32]);
    let mut changed_state = state.clone();
    changed_state.admission_policy_v2 = Some(Record::new(changed).unwrap());
    assert_ne!(changed_state.root().unwrap(), root);
    let mut absent = state.clone();
    absent.wallets = Default::default();
    assert!(absent.records().is_err());
    for raw in [vec![0], vec![0x82, 2, 0x18, 54], record.encode().unwrap()] {
        let mut opaque = missing.clone();
        opaque.protocol_records.insert(key(), raw.clone());
        assert!(opaque.records().is_err());
        // A recognized typed tag under a wrong key must never fall through.
        if raw != vec![0] {
            let mut malformed = records.clone();
            malformed.retain(|(k, _)| *k != key());
            malformed.push(([88; 32], raw));
            malformed.sort_by_key(|(k, _)| *k);
            assert!(State::from_records(&malformed, state_root(&malformed).unwrap()).is_err());
        }
    }
    let mut trailing = record.encode().unwrap();
    trailing.push(0);
    assert!(Record::decode(&trailing).is_err());
    let mut wrong_generation = record.initial().clone();
    let (owner, _) =
        mutiny_crypto_v2::PublicKey::decode_descriptor(&wrong_generation.owner_descriptor).unwrap();
    wrong_generation.owner_descriptor = owner.descriptor(2).unwrap();
    assert!(Record::new(wrong_generation).is_err());
}
#[test]
fn canonical_wallet_rotation_changes_authority_without_changing_trust_roots() {
    let (old, mut state, record) = fixture();
    let new = HybridKey::wallet_restore(&format!("{}vote", "zoo ".repeat(23)), Role::WalletOwner)
        .unwrap();
    let id = old.public().address_id(1).unwrap();
    let zero = HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    };
    let mut rotation = Rotation {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        authority: id,
        current: old.public().descriptor(1).unwrap(),
        proposed: new.public().descriptor(2).unwrap(),
        created_height: 1,
        expiry_height: 10,
        authorization: zero.clone(),
        possession: zero,
    };
    rotation.sign(&old, &new).unwrap();
    state.wallets.apply(&rotation, [1; 32], [2; 32], 1).unwrap();
    let resolved = state.current_admission_policy_v2([1; 32], [2; 32]).unwrap();
    assert_eq!(resolved.owner_descriptor, rotation.proposed);
    assert_eq!(
        resolved.endorsement_roots,
        record.initial().endorsement_roots
    );
    assert_eq!(
        state
            .admission_policy_v2
            .as_ref()
            .unwrap()
            .encode()
            .unwrap(),
        record.encode().unwrap()
    );
    assert!(state.wallets.authorize(id, &rotation.current).is_err());
    assert_eq!(
        State::from_records(&state.records().unwrap(), state.root().unwrap()).unwrap(),
        state
    );
}
