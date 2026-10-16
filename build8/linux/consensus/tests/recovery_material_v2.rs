use mutiny_consensus_v8::{
    Hash,
    execution::State,
    recovery_authority_v2::Authority,
    recovery_history_v2::{Book, Record},
};
#[test]
fn recovery_history_state_reconstructs_without_erasing_retired_identity_evidence() {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/bootstrap-recovery-history-state-public-v1.json"
    ))
    .unwrap();
    assert_eq!(f["constructed_state_fixture_not_execution"], true);
    assert_eq!(f["production_authorized"], false);
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let root: Hash = raw(&f["root"]).try_into().unwrap();
    let rows: Vec<_> = f["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
        .collect();
    let state = State::from_records(&rows, root).unwrap();
    assert_eq!(state.root().unwrap(), root);
    assert!(!state.recovery_history_v2.is_empty());
    assert!(!state.retired_continuity_v2.is_empty());
    assert!(state.records().unwrap() == rows);
    // A matching Merkle root does not legitimize registry metadata that points
    // at a different recovery. Recompute the root for every adversarial input.
    for mutation in 0..3 {
        let mut altered = rows.clone();
        let meta = &mut altered
            .iter_mut()
            .find(|r| r.0 == mutiny_consensus_v8::recovery::continuity_meta_key())
            .unwrap()
            .1;
        let mut d = minicbor::Decoder::new(meta);
        assert_eq!(d.array().unwrap(), Some(9));
        for _ in 0..6 {
            d.skip().unwrap();
        }
        let sequence_offset = d.position();
        assert_eq!(d.u64().unwrap(), 1);
        let digest_offset = d.position();
        assert_eq!(d.bytes().unwrap().len(), 32);
        let digest_end = d.position();
        match mutation {
            0 => meta[digest_end - 1] ^= 1,
            1 => {
                meta.splice(digest_offset..digest_end, [0xf6]);
            }
            _ => meta[sequence_offset] = 0,
        }
        let altered_root = mutiny_consensus_v8::blocks::state_root(&altered).unwrap();
        assert!(State::from_records(&altered, altered_root).is_err());
    }
    let parent = mutiny_consensus_v8::anchors::FinalizedAnchor::decode(&raw(&f["parent"])).unwrap();
    let key: Hash = raw(&f["history_key"]).try_into().unwrap();
    let mut tree = mutiny_consensus_v8::state_tree::StateTree::default();
    for (key, value) in &rows {
        tree.insert(*key, value.clone()).unwrap();
    }
    assert_eq!(
        tree.proof(parent.clone(), key).encode().unwrap(),
        raw(&f["proof"])
    );
    let authority =
        mutiny_consensus_v8::votes_v2::HeightAuthority::from_state(&state, parent, root).unwrap();
    assert_eq!(authority.voters.len(), 1);
    let mut missing = state.clone();
    missing.recovery_history_v2 = Book::default();
    assert!(missing.root().is_err());
    let mut missing = state.clone();
    missing.retired_continuity_v2 = Default::default();
    assert!(missing.root().is_err());
}
#[test]
fn hybrid_recovery_history_is_tentative_parent_authenticated_and_exactly_reconstructed() {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/bootstrap-recovery-replacement-public-v2.json"
    ))
    .unwrap();
    assert_eq!(f["synthetic_only"], true);
    assert_eq!(f["production_authorized"], false);
    assert_eq!(f["state_installed"], false);
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let authority = Authority::decode(&raw(&f["authority"])).unwrap();
    let record = Record::decode(&raw(&f["history_record"]), &authority).unwrap();
    let root: Hash = raw(&f["root"]).try_into().unwrap();
    let rows: Vec<_> = f["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
        .collect();
    let state = State::from_records(&rows, root).unwrap();
    let parent = record.material.parent.clone();
    let book = Book::default()
        .stage(record.clone(), &state, &parent, root, false)
        .unwrap();
    let records = book.records(&authority).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(Book::from_records(&records, &authority).unwrap(), book);
    // Historical evidence is not the missing canonical recovery transition.
    let mut pending = state.clone();
    pending.recovery_history_v2 = book.clone();
    assert!(pending.root().is_err());
    let mut hidden = state.clone();
    hidden.protocol_records.extend(records.clone());
    assert!(hidden.root().is_err());
    let mut malformed = rows.clone();
    malformed.push(([253; 32], vec![0x82, 2, 0x18, 58]));
    malformed.sort_by_key(|x| x.0);
    let malformed_root = mutiny_consensus_v8::blocks::state_root(&malformed).unwrap();
    assert!(State::from_records(&malformed, malformed_root).is_err());
    let mut wrong = records.clone();
    let value = wrong.remove(&record.key()).unwrap();
    wrong.insert([0; 32], value);
    assert!(Book::from_records(&wrong, &authority).is_err());
    assert!(
        Book::default()
            .stage(record.clone(), &state, &parent, root, true)
            .is_err()
    );
    assert!(
        book.stage(record.clone(), &state, &parent, root, false)
            .is_err()
    );
    let mut bad = record.clone();
    bad.policy.endorsement_roots.insert([99; 32]);
    // Extra policy roots are not covered by a material signature and cannot be
    // silently accepted as if they were the actual historical parent policy.
    assert!(
        Book::default()
            .stage(bad, &state, &parent, root, false)
            .is_err()
    );
    let mut parent = parent;
    parent.block[0] ^= 1;
    assert!(
        Book::default()
            .stage(record, &state, &parent, root, false)
            .is_err()
    );
    assert!(state.records().unwrap() == rows);
}
