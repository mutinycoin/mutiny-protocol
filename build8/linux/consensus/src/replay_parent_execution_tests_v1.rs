//! Public synthetic TEST fixtures only. No transport, keys, signing or hardware.
use super::*;

fn raw(v: &serde_json::Value) -> Vec<u8> { hex::decode(v.as_str().unwrap()).unwrap() }
fn fixture(recovery: bool) -> (std::path::PathBuf, CanonicalStore, FinalizedAnchor,
    State, Vec<BlockEnvelope>, Option<Vec<u8>>) {
    let f: serde_json::Value = serde_json::from_str(if recovery {
        include_str!("../../qualification/hybrid-recovery-chain-public-v4.json")
    } else { include_str!("../../qualification/hybrid-canonical-store-public-v1.json") }).unwrap();
    assert_eq!(f["synthetic_only"], true);
    assert_eq!(f["production_authorized"], false);
    let root = raw(&f["root"]).try_into().unwrap();
    let records: Vec<_> = f["records"].as_array().unwrap().iter().map(|r|
        (raw(&r["key"]).try_into().unwrap(), raw(&r["record"]))).collect();
    let state = State::from_records(&records, root).unwrap();
    let genesis = FinalizedAnchor::decode(&raw(&f[if recovery {"genesis_anchor"} else {"genesis"}])).unwrap();
    let mut nonce = [0;16];
    mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let path = std::env::temp_dir().join(format!("build8-replay-parent-execution-{}.sqlite", hex::encode(nonce)));
    assert!(!path.exists());
    let chain = CanonicalStore::open_trusted_genesis(&path, &genesis, &state,
        root, 1000, [255;32]).unwrap();
    let blocks = if recovery { vec![BlockEnvelope::decode(&raw(&f["block1"])).unwrap(),
        BlockEnvelope::decode(&raw(&f["block2"])).unwrap()] }
        else { vec![BlockEnvelope::decode(&raw(&f["envelope"])).unwrap()] };
    let proof = recovery.then(|| raw(&f["recovery1"]));
    (path, chain, genesis, state, blocks, proof)
}
fn cleanup(path: std::path::PathBuf, chain: CanonicalStore) {
    drop(chain);
    std::fs::remove_file(&path).unwrap();
    for suffix in ["-wal","-shm"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
    }
}

impl CanonicalStore {
    fn replay_parent_execution_baseline(&self, genesis_state: &State, rebuild_operations: bool) -> Result<()> {
        let transaction = if self.evidence.db.is_autocommit() {
            Some(self.evidence.db.unchecked_transaction()?)
        } else { None };
        let snapshot = &self.evidence.db;
        crate::store_schema_v2::validate(&snapshot, &self.genesis, true)?;
        let tip = head(&snapshot, None)?;
        let mut previous = head(&snapshot, Some(0))?;
        let mut state = genesis_state.clone();
        let mut times = std::collections::VecDeque::from([self.t0]);
        let mut undo_count = 0u64;
        let mut confirmation_count = 0u64;
        let mut recovery_count = 0u64;
        let mut operation_count = 0u64;
        for height in 1..=tip.height {
            let stored = head(&snapshot, Some(height))?;
            let block = self
                .replay_parent_envelope(height, stored.block, &previous, &state)?
                .ok_or(StoreError::Integrity)?;
            let window: Vec<u64> = times.iter().copied().collect();
            if !crate::pow::window_ends_at_parent(&window, previous.timestamp) {
                return Err(StoreError::Integrity);
            }
            let parent = WorkParent {
                genesis: self.genesis.genesis,
                fingerprint: self.genesis.fingerprint,
                block: previous.block,
                height: previous.height,
                t0: self.t0,
                target: previous.target,
                ancestor_timestamps: window,
            };
            let mut history = crate::evidence_history_v2::History::default();
            for raw in &block.body.operations {
                if crate::trading_host_v1::operation(raw)? { continue; }
                if crate::blocks::operation_kind(raw)? != 17 {
                    continue;
                }
                let proof = crate::equivocation_v2::Evidence::decode(raw)?;
                let e = proof.a.decision.height;
                if !crate::bonds::actionable(e, height) {
                    return Err(crate::Error::InvalidCounter.into());
                }
                if history.contains_key(&e) {
                    continue;
                }
                let (past, s, root) = self.execution_parent(e - 1)?;
                let anchor = FinalizedAnchor {
                    height: past.height,
                    block: past.block,
                    ..self.genesis.clone()
                };
                let recovery = crate::recovery_store_v2::prepared(&snapshot, &s, &anchor, root, self.t0)?;
                history.insert(
                    e,
                    HeightAuthority::from_state(&s, anchor, root)
                        .map_err(StoreError::Verification)?,
                );
                if let Some(r) = recovery { history.attach_recovery(e, &r)?; }
            }
            // Design 1.a.3: the same reference anchors that `operation_history` supplies to commit.
            self.insert_reference_anchors(&snapshot, height, &crate::op_envelope_v1::referenced_heights(&block.body), &mut history)?;
            let anchor = FinalizedAnchor { height: previous.height, block: previous.block, ..self.genesis.clone() };
            let recovery = crate::recovery_store_v2::prepared(&snapshot, &state, &anchor, previous.root, self.t0)?;
            let result = match recovery {
                Some(ref r) => {
                    recovery_count = recovery_count.checked_add(1).ok_or(StoreError::Integrity)?;
                    r.verify_envelope(&state, &parent, &block, &history)
                }
                None => block.verify_execute_from_parent_state(&state, &parent, previous.root, &history),
            }.map_err(StoreError::Verification)?;
            let timestamp = block.header.candidate.timestamp;
            let start = if height.is_multiple_of(60) {
                head(&snapshot, Some(height - 60))?.timestamp
            } else {
                timestamp
            };
            let target =
                crate::pow::target_after_height(height, previous.target, start, timestamp)?;
            let expected = Head {
                height,
                block: block.block_hash(),
                root: result.root,
                target,
                timestamp,
            };
            if stored != expected
                || self.evidence.anchor(height)?.as_ref()
                    != Some(&block.certificate.decision.anchor())
            {
                return Err(StoreError::Integrity);
            }
            // These indexes are derived data, not independent authority. Check
            // them against the reproduced transition before serving queries.
            let before: BTreeMap<_, _> = state.records()?.into_iter().collect();
            let after: BTreeMap<_, _> = result.state.records()?.into_iter().collect();
            let keys: BTreeSet<_> = before.keys().chain(after.keys()).copied().collect();
            let expected_undo: BTreeMap<_, _> = keys
                .into_iter()
                .filter(|key| before.get(key) != after.get(key))
                .map(|key| (key, before.get(&key).cloned()))
                .collect();
            let mut actual_undo = BTreeMap::new();
            let mut query = snapshot.prepare("SELECT key,CASE WHEN length(previous)<=262144 THEN previous ELSE NULL END,length(previous) FROM undo_v2 WHERE height=?1")?;
            for row in query.query_map([height.to_be_bytes().as_slice()], |r| {
                Ok((
                    r.get::<_, Vec<u8>>(0)?,
                    r.get::<_, Option<Vec<u8>>>(1)?,
                    r.get::<_, Option<u64>>(2)?,
                ))
            })? {
                let (key, value, size) = row?;
                if size.is_some_and(|n| n > crate::state_tree::MAX_RECORD as u64)
                    || actual_undo.len() >= expected_undo.len()
                    || actual_undo.insert(fixed(key)?, value).is_some()
                {
                    return Err(StoreError::Integrity);
                }
            }
            if actual_undo != expected_undo {
                return Err(StoreError::Integrity);
            }
            undo_count = undo_count
                .checked_add(actual_undo.len() as u64)
                .ok_or(StoreError::Integrity)?;
            let expected_ids: BTreeSet<_> = block
                .body
                .transactions
                .iter()
                .map(|raw| {
                    crate::hybrid_transaction_v2::Transaction::decode(raw)
                        .and_then(|tx| tx.id())
                        .map_err(|_| StoreError::Integrity)
                })
                .collect::<Result<_>>()?;
            let mut actual_ids = BTreeSet::new();
            let mut query = snapshot.prepare("SELECT id FROM confirmations_v2 WHERE height=?1")?;
            for row in query.query_map([height.to_be_bytes().as_slice()], |r| {
                r.get::<_, Vec<u8>>(0)
            })? {
                if actual_ids.len() >= expected_ids.len() || !actual_ids.insert(fixed(row?)?) {
                    return Err(StoreError::Integrity);
                }
            }
            if actual_ids != expected_ids {
                return Err(StoreError::Integrity);
            }
            confirmation_count = confirmation_count
                .checked_add(actual_ids.len() as u64)
                .ok_or(StoreError::Integrity)?;
            let capacity=crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(&state,FinalizedAnchor { height:previous.height,block:previous.block,..self.genesis.clone() },previous.root)?;
            let expected_operations = crate::operation_index_v2::records_with_capacity(&block.body, block.block_hash(), &result.bond_command_outcomes,&capacity)
                .map_err(|_| StoreError::Integrity)?;
            if rebuild_operations {
                insert_operation_records(snapshot, &expected_operations)?;
            } else {
                let actual_operations = operation_rows(snapshot, "WHERE height=?1 ORDER BY list,position", height.to_be_bytes().as_slice())?;
                if actual_operations != expected_operations { return Err(StoreError::Integrity); }
            }
            operation_count = operation_count.checked_add(expected_operations.len() as u64).ok_or(StoreError::Integrity)?;
            state = result.state;
            previous = expected;
            times.push_back(timestamp);
            if times.len() > 11 {
                times.pop_front();
            }
        }
        let last_anchor = FinalizedAnchor { height: previous.height, block: previous.block, ..self.genesis.clone() };
        if crate::recovery_store_v2::prepared(&snapshot, &state, &last_anchor, previous.root, self.t0)?.is_some() {
            recovery_count = recovery_count.checked_add(1).ok_or(StoreError::Integrity)?;
        }
        let actual_recovery: u64 = snapshot.query_row("SELECT count(*) FROM accepted_recovery_v2", [], |r| r.get(0))?;
        if actual_recovery != recovery_count { return Err(StoreError::Integrity); }
        let (stored, state_on_disk) = self.load()?;
        if stored != previous || state_on_disk.records()? != state.records()? {
            return Err(StoreError::Integrity);
        }
        // Reject orphan and height-zero rows, including rows beyond the tip.
        let actual_undo: u64 =
            snapshot.query_row("SELECT count(*) FROM undo_v2", [], |r| r.get(0))?;
        let actual_confirmations: u64 =
            snapshot.query_row("SELECT count(*) FROM confirmations_v2", [], |r| r.get(0))?;
        let actual_operations: u64 = snapshot.query_row("SELECT count(*) FROM operation_index_v2", [], |r| r.get(0))?;
        if actual_undo != undo_count || actual_confirmations != confirmation_count || actual_operations != operation_count {
            return Err(StoreError::Integrity);
        }
        if let Some(t) = transaction { t.commit()?; }
        Ok(())
    }
}

// Public signed fixture bytes only. All tests below are UNCOMPILED and UNRUN.
fn installed(recovery: bool) -> (std::path::PathBuf, CanonicalStore, State) {
    let (path, mut store, _, initial, blocks, proof) = fixture(recovery);
    store.commit(&blocks[0]).unwrap();
    if let Some(proof) = proof {
        store.accept_recovery_encoded(&proof).unwrap();
        store.commit(&blocks[1]).unwrap();
    }
    (path, store, initial)
}
fn compare_full(store: &CanonicalStore, initial: &State) -> Option<String> {
    let changes = store.evidence.db.total_changes();
    let old = store.replay_parent_execution_baseline(initial, false);
    let new = store.verify_replay_inner(initial, false);
    assert_eq!(format!("{new:?}"), format!("{old:?}"));
    assert_eq!(store.evidence.db.total_changes(), changes, "verification cannot repair rows");
    new.err().map(|error| format!("{error:?}"))
}
fn index_rows(store: &CanonicalStore) -> Vec<crate::operation_index_v2::OperationRecord> {
    operation_rows(&store.evidence.db, "WHERE height>=?1 ORDER BY height,list,position",
        0u64.to_be_bytes().as_slice()).unwrap()
}
fn with_test_proof<T>(store: &CanonicalStore, state: &State, previous: &Head,
    parent: &WorkParent, invoke: impl FnOnce(&ReplayParent<'_>) -> T) -> T {
    // Test-only construction is confined to a genuine held read transaction and
    // an actual full root/capacity check; no successful Boolean can mint proof.
    assert!(!store.evidence.db.is_autocommit());
    let anchor = FinalizedAnchor { height: previous.height, block: previous.block,
        ..store.genesis.clone() };
    let capacity = crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(
        state, anchor.clone(), previous.root).unwrap();
    let scope = ReplayScope { _connection: &store.evidence.db };
    let proof = ReplayParent { state, head: previous, parent, anchor, capacity,
        authority: std::cell::OnceCell::new(), _scope: &scope };
    invoke(&proof)
}
fn debug_execution(result: &std::result::Result<crate::execution::Execution,
    crate::votes::IngressError>) -> String {
    match result { Ok(value) => format!("ok:{:?}", value.root), Err(error) => format!("{error:?}") }
}

#[test]
fn replay_parent_execution_matches_original_h0_h1_pending_recovery_h2_and_rebuild() {
    for recovery in [false, true] {
        let (path, mut store, _, initial, blocks, proof) = fixture(recovery);
        assert!(compare_full(&store, &initial).is_none());
        store.commit(&blocks[0]).unwrap();
        assert!(compare_full(&store, &initial).is_none());
        if let Some(proof) = proof {
            store.accept_recovery_encoded(&proof).unwrap();
            assert!(compare_full(&store, &initial).is_none());
            store.commit(&blocks[1]).unwrap();
            assert!(compare_full(&store, &initial).is_none());
        }
        let original = index_rows(&store);
        let transaction = rusqlite::Transaction::new_unchecked(&store.evidence.db,
            TransactionBehavior::Immediate).unwrap();
        transaction.execute("DELETE FROM operation_index_v2", []).unwrap();
        store.replay_parent_execution_baseline(&initial, true).unwrap();
        transaction.commit().unwrap();
        assert_eq!(index_rows(&store), original);
        store.evidence.db.execute("DELETE FROM operation_index_v2", []).unwrap();
        store.rebuild_operation_index(&initial).unwrap();
        assert_eq!(index_rows(&store), original);
        assert!(compare_full(&store, &initial).is_none());
        cleanup(path, store);
    }
}

#[test]
fn replay_parent_execution_exact_result_and_authority_first_use_on_real_ordinary_parent() {
    let (path, store, _) = installed(false);
    store.read_snapshot(|s| {
        let previous = head(&s.evidence.db, Some(0))?;
        let (parent, state, root) = s.execution_parent_snapshot(0)?;
        let tip = head(&s.evidence.db, Some(1))?;
        let block = s.retained_envelope(1, tip.block)?.unwrap();
        let history = s.operation_history(1, &block.body)?;
        let unchanged = state.records()?;
        let old = block.verify_execute_from_parent_state(&state, &parent, root, &history).unwrap();
        with_test_proof(s, &state, &previous, &parent, |proof| {
            assert!(proof.authority.get().is_none(), "root checking cannot derive authority early");
            let new = block.verify_execute_from_replayed_parent(proof, &parent, &history).unwrap();
            assert!(proof.authority.get().is_some());
            assert_eq!(new.root, old.root);
            assert_eq!(new.state.records().unwrap(), old.state.records().unwrap());
            assert_eq!(new.transaction_ids, old.transaction_ids);
            assert_eq!(new.coinbase_id, old.coinbase_id);
            assert_eq!(new.fees, old.fees);
            assert_eq!(new.bond_command_outcomes, old.bond_command_outcomes);
            assert_eq!(proof.authority().unwrap(), proof.authority().unwrap());
        });
        assert_eq!(state.records()?, unchanged);
        Ok(())
    }).unwrap();
    cleanup(path, store);
}

#[test]
fn replay_parent_execution_rejects_substituted_state_anchor_target_t0_and_window() {
    let (path, store, _) = installed(false);
    store.read_snapshot(|s| {
        let previous = head(&s.evidence.db, Some(0))?;
        let (parent, state, _) = s.execution_parent_snapshot(0)?;
        with_test_proof(s, &state, &previous, &parent, |proof| {
            assert!(proof.check(&state, &parent).is_ok());
            let equal_but_distinct = state.clone();
            assert_eq!(equal_but_distinct, state);
            assert!(proof.check(&equal_but_distinct, &parent).is_err());
            for field in 0..7 {
                let mut wrong = WorkParent { genesis: parent.genesis,
                    fingerprint: parent.fingerprint, block: parent.block,
                    height: parent.height, t0: parent.t0, target: parent.target,
                    ancestor_timestamps: parent.ancestor_timestamps.clone() };
                match field { 0 => wrong.genesis[0] ^= 1, 1 => wrong.fingerprint[0] ^= 1,
                    2 => wrong.block[0] ^= 1, 3 => wrong.height += 1,
                    4 => wrong.t0 += 1, 5 => wrong.target[0] ^= 1,
                    _ => wrong.ancestor_timestamps.push(parent.t0 + 1) }
                assert!(proof.check(&state, &wrong).is_err(), "substituted WorkParent field {field}");
            }
            let mut anchor = proof.anchor.clone(); anchor.block[0] ^= 1;
            assert!(crate::parent_context_v2::ParentContext::replayed(&state, &anchor, proof).is_err());
            assert!(proof.authority.get().is_none(), "mismatch checks do not consult authority/custody");
        });
        Ok(())
    }).unwrap();
    cleanup(path, store);
}

#[test]
fn replay_parent_execution_keeps_work_body_and_both_native_certificate_signature_guards() {
    let (path, store, _) = installed(false);
    store.read_snapshot(|s| {
        let previous = head(&s.evidence.db, Some(0))?;
        let (parent, state, root) = s.execution_parent_snapshot(0)?;
        let block = s.retained_envelope(1, head(&s.evidence.db, Some(1))?.block)?.unwrap();
        let history = s.operation_history(1, &block.body)?;
        for fault in 0..5 {
            let mut damaged = block.clone();
            match fault {
                0 => damaged.authority.signature.ed448[0] ^= 1,
                1 => damaged.authority.signature.fndsa[17] ^= 1,
                2 => damaged.certificate.votes[0].signature.ed448[0] ^= 1,
                3 => damaged.certificate.votes[0].signature.fndsa[17] ^= 1,
                _ => damaged.body.fees = damaged.body.fees.checked_add(1).unwrap(),
            }
            let old = damaged.verify_execute_from_parent_state(&state, &parent, root, &history);
            with_test_proof(s, &state, &previous, &parent, |proof| {
                let new = damaged.verify_execute_from_replayed_parent(proof, &parent, &history);
                assert!(old.is_err() && new.is_err(), "actual cryptographic/body fault {fault}");
                assert_eq!(debug_execution(&new), debug_execution(&old), "fault {fault}");
                if fault == 2 || fault == 3 {
                    let raw = damaged.encode_with_capacity(proof.capacity()).unwrap();
                    assert_eq!(BlockEnvelope::decode_with_capacity(&raw, proof.capacity()).unwrap(), damaged,
                        "certificate fault must remain canonically decodable");
                }
            });
        }
        Ok(())
    }).unwrap();
    cleanup(path, store);
}

#[test]
fn replay_parent_execution_same_head_state_undo_index_and_retarget_rows_still_refuse() {
    let (path, store, initial) = installed(false);
    let saved = head(&store.evidence.db, None).unwrap();
    let target = crate::pow::target_after_height(60, saved.target, 1000, 1001).unwrap();
    assert_ne!(target, saved.target, "real retarget arithmetic supplies a distinct wrong stored target");
    for fault in 0..5 {
        let transaction = store.evidence.db.unchecked_transaction().unwrap();
        match fault {
            0 => { assert_eq!(transaction.execute("UPDATE state_v2 SET value=X'01' WHERE rowid=(SELECT rowid FROM state_v2 LIMIT 1)", []).unwrap(), 1); }
            1 => { assert_eq!(transaction.execute("UPDATE undo_v2 SET previous=X'01' WHERE rowid=(SELECT rowid FROM undo_v2 LIMIT 1)", []).unwrap(), 1); }
            2 => { assert_eq!(transaction.execute("UPDATE operation_index_v2 SET record=X'01' WHERE rowid=(SELECT rowid FROM operation_index_v2 LIMIT 1)", []).unwrap(), 1); }
            3 => { assert_eq!(transaction.execute("UPDATE canonical_v2 SET target=?1 WHERE height=?2", params![target.as_slice(), saved.height.to_be_bytes().as_slice()]).unwrap(), 1); }
            _ => { transaction.execute("INSERT INTO undo_v2 VALUES(?1,?2,NULL)", params![(saved.height+1).to_be_bytes().as_slice(), [0u8;32].as_slice()]).unwrap(); }
        }
        assert!(compare_full(&store, &initial).is_some(), "same-head corruption {fault}");
        transaction.rollback().unwrap();
        assert_eq!(head(&store.evidence.db, None).unwrap(), saved);
    }
    assert!(compare_full(&store, &initial).is_none());
    cleanup(path, store);
}

#[test]
fn replay_parent_execution_fresh_call_revalidates_external_same_head_mutation() {
    let (path, store, initial) = installed(false);
    assert!(compare_full(&store, &initial).is_none());
    let saved = head(&store.evidence.db, None).unwrap();
    let writer = rusqlite::Connection::open(&path).unwrap();
    let (key, original): (Vec<u8>, Vec<u8>) = writer.query_row(
        "SELECT key,value FROM state_v2 ORDER BY key LIMIT 1", [], |r| Ok((r.get(0)?,r.get(1)?))).unwrap();
    writer.execute("UPDATE state_v2 SET value=X'01' WHERE key=?1", [&key]).unwrap();
    assert_eq!(head(&store.evidence.db, None).unwrap(), saved);
    assert!(compare_full(&store, &initial).is_some(), "no successful replay/token is cached across calls");
    writer.execute("UPDATE state_v2 SET value=?1 WHERE key=?2", params![original,key]).unwrap();
    drop(writer);
    assert!(compare_full(&store, &initial).is_none());
    cleanup(path, store);
}

#[test]
fn replay_parent_execution_preserves_halted_and_malformed_decoder_error_order() {
    let (path, store, initial) = installed(false);
    let transaction = store.evidence.db.unchecked_transaction().unwrap();
    transaction.execute("UPDATE integrity_v2 SET halted=1 WHERE id=1", []).unwrap();
    assert!(compare_full(&store, &initial).unwrap().starts_with("Halted"));
    transaction.execute("UPDATE evidence_v2 SET envelope=X'00'", []).unwrap();
    assert!(compare_full(&store, &initial).unwrap().starts_with("Invalid("),
        "malformed raw/header input still precedes halted decoder guard");
    let previous = head(&store.evidence.db, Some(0)).unwrap();
    assert!(store.replay_parent_envelope(9, [9;32], &previous, &initial).unwrap().is_none());
    transaction.rollback().unwrap();
    assert!(compare_full(&store, &initial).is_none());
    cleanup(path, store);
}
