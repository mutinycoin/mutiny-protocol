use super::*;

#[test]
fn reserved_namespace_cannot_hide_in_indefinite_arrays_or_opaque_state() {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.begin_array()
        .unwrap()
        .bytes(NAMESPACE)
        .unwrap()
        .u8(255)
        .unwrap()
        .end()
        .unwrap();
    let malformed = e.into_writer();
    assert!(reserved(&malformed));
    assert!(operation(&malformed).is_err());
    let mut state = State::default();
    state.protocol_records.insert([9; 32], malformed);
    assert!(state.records().is_err());
    let mut chunked = vec![0x9f, 0x5f, 0x58, NAMESPACE.len() as u8];
    chunked.extend_from_slice(NAMESPACE);
    chunked.extend_from_slice(&[0xff, 0x00, 0xff]);
    assert!(reserved(&chunked));
    assert!(operation(&chunked).is_err());
    state.protocol_records.insert([9; 32], chunked);
    assert!(state.records().is_err());
    {
        use crate::trading_v1::{NativeRecord, record_key};
        let record = NativeRecord::Applied {
            wire_hash: [3; 32],
            height: 1,
            fee_atoms: 240,
        }
        .encode([2; 32])
        .unwrap();
        state.protocol_records.clear();
        state.protocol_records.insert([9; 32], record.clone());
        assert!(state.records().is_err());
        state.protocol_records.clear();
        state
            .protocol_records
            .insert(record_key(2, [2; 32]), record);
        let rows = state.records().unwrap();
        State::from_records(&rows, state.root().unwrap()).unwrap();
        let genesis = FinalizedAnchor {
            network: crate::NETWORK_ID,
            genesis: [1; 32],
            fingerprint: [2; 32],
            height: 0,
            block: [3; 32],
        };
        assert!(records(&state, Some(&genesis)).is_err());
    }
}

#[test]
fn canonical_candidate_namespace_is_one_rule_in_every_build() {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(5)
        .unwrap()
        .bytes(NAMESPACE)
        .unwrap()
        .u8(1)
        .unwrap()
        .u8(2)
        .unwrap()
        .bytes(&[2; 32])
        .unwrap()
        .array(3)
        .unwrap()
        .bytes(&[3; 32])
        .unwrap()
        .u64(1)
        .unwrap()
        .u64(240)
        .unwrap();
    let raw = e.into_writer();
    assert!(reserved(&raw));
    // A well-formed trading record is a CONSENSUS record in the single build, but a
    // record stored under a key that is not its typed key is still rejected.
    let rows = vec![([4; 32], raw.clone())];
    let root = crate::blocks::state_root(&rows).unwrap();
    assert!(State::from_records(&rows, root).is_err());
    let rows = vec![(crate::trading_v1::record_key(2, [2; 32]), raw.clone())];
    let root = crate::blocks::state_root(&rows).unwrap();
    assert!(State::from_records(&rows, root).is_ok());
    // A record is not an operation: the operation dispatcher rejects it.
    assert!(operation(&raw).is_err());
}
