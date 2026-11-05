//! Unrun source-only regressions using existing public synthetic fixtures.
//! No custody, keys, signature generation, providers, timers or workers.
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
    let mut nonce = [0;16]; mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let path = std::env::temp_dir().join(format!("build8-coherent-authority-{}.sqlite",hex::encode(nonce)));
    assert!(!path.exists());
    let chain = CanonicalStore::open_trusted_genesis(&path,&genesis,&state,root,1000,[255;32]).unwrap();
    let blocks = if recovery {vec![BlockEnvelope::decode(&raw(&f["block1"])).unwrap(),
        BlockEnvelope::decode(&raw(&f["block2"])).unwrap()]}
        else {vec![BlockEnvelope::decode(&raw(&f["envelope"])).unwrap()]};
    (path,chain,genesis,state,blocks,recovery.then(||raw(&f["recovery1"])))
}
fn cleanup(path: std::path::PathBuf, chain: CanonicalStore) {
    drop(chain); std::fs::remove_file(&path).unwrap();
    for suffix in ["-wal","-shm"] {let _=std::fs::remove_file(format!("{}{suffix}",path.display()));}
}
// Exact original actor helper, with the same typed StoreError (before ActorError::Chain).
fn baseline(chain: &CanonicalStore) -> Result<HeightAuthority> {
    let (tip,_) = chain.load()?;
    let authority = chain.voting_authority_at(tip.height)?;
    chain.current_authority(&authority.parent)
}
fn same(chain: &CanonicalStore) -> HeightAuthority {
    let changes=chain.evidence.db.total_changes();
    let expected=baseline(chain).unwrap();
    let actual=chain.current_actor_authority().unwrap();
    assert_eq!(actual,expected);
    assert_eq!(chain.evidence.db.total_changes(),changes,"authority reads cannot write");
    actual
}
fn same_refusal(chain: &CanonicalStore) {
    let changes=chain.evidence.db.total_changes();
    let old=baseline(chain).unwrap_err();
    let new=chain.current_actor_authority().unwrap_err();
    assert_eq!(format!("{new:?}"),format!("{old:?}"),"stable snapshot diagnostic changed");
    assert_eq!(chain.evidence.db.total_changes(),changes,"refusal cannot repair or mutate");
}

#[test]
fn coherent_actor_authority_matches_ordinary_and_recovery_h0_h1_h2() {
    for recovery in [false,true] {
        let (path,mut chain,genesis,_,blocks,proof)=fixture(recovery);
        assert_eq!(same(&chain).parent,genesis);
        chain.commit(&blocks[0]).unwrap();
        let ordinary=same(&chain);
        assert_eq!(ordinary.parent,blocks[0].certificate.decision.anchor());
        if let Some(proof)=proof {
            chain.accept_recovery_encoded(&proof).unwrap();
            let recovered=same(&chain);
            assert_eq!(recovered.parent,ordinary.parent);
            assert_ne!(recovered,ordinary,"accepted recovery must affect effective authority");
            chain.commit(&blocks[1]).unwrap();
            assert_eq!(same(&chain).parent,blocks[1].certificate.decision.anchor());
        }
        cleanup(path,chain);
    }
}

#[test]
fn coherent_actor_authority_rechecks_same_connection_halt_state_and_schema() {
    let (path,chain,_,_,_,_)=fixture(false);
    same(&chain);
    chain.evidence.db.execute("UPDATE integrity_v2 SET halted=1 WHERE id=1",[]).unwrap();
    assert!(matches!(chain.current_actor_authority(),Err(StoreError::Halted)));
    same_refusal(&chain);
    chain.evidence.db.execute("UPDATE integrity_v2 SET halted=0 WHERE id=1",[]).unwrap();
    same(&chain);
    chain.evidence.db.execute_batch("BEGIN").unwrap();
    chain.evidence.db.execute("DELETE FROM state_v2",[]).unwrap();
    same_refusal(&chain);
    chain.evidence.db.execute_batch("ROLLBACK").unwrap();
    same(&chain);
    chain.evidence.db.execute_batch("BEGIN; CREATE TABLE unrecognized(x)").unwrap();
    assert!(matches!(chain.current_actor_authority(),Err(StoreError::Integrity)));
    same_refusal(&chain);
    chain.evidence.db.execute_batch("ROLLBACK").unwrap();
    same(&chain);
    cleanup(path,chain);
}

#[test]
fn coherent_actor_authority_retains_timestamp_window_and_load_before_halt() {
    let (path,mut chain,_,_,blocks,_)=fixture(false);
    chain.commit(&blocks[0]).unwrap();
    chain.evidence.db.execute_batch("BEGIN").unwrap();
    // Tip evidence/time remain valid. Only the older row exceeds the tip,
    // which load_snapshot alone does not reject; work_parent_from_head must.
    let too_new=blocks[0].header.candidate.timestamp+1;
    chain.evidence.db.execute("UPDATE canonical_v2 SET timestamp=?1 WHERE height=?2",
        params![too_new.to_be_bytes().as_slice(),0u64.to_be_bytes().as_slice()]).unwrap();
    assert!(chain.load().is_ok());
    assert!(matches!(chain.current_actor_authority(),Err(StoreError::Integrity)));
    same_refusal(&chain);
    chain.evidence.db.execute_batch("ROLLBACK").unwrap();
    same(&chain);
    chain.evidence.db.execute_batch("BEGIN").unwrap();
    chain.evidence.db.execute("UPDATE integrity_v2 SET halted=1 WHERE id=1",[]).unwrap();
    chain.evidence.db.execute("DELETE FROM finalized_v2 WHERE height=?1",
        [1u64.to_be_bytes().as_slice()]).unwrap();
    // Missing finalized tip is discovered by the old initial load, before halt.
    assert!(matches!(chain.current_actor_authority(),Err(StoreError::Integrity)));
    same_refusal(&chain);
    chain.evidence.db.execute_batch("ROLLBACK").unwrap();
    cleanup(path,chain);
}

#[test]
fn coherent_actor_authority_preserves_existing_tip_anchor_binding_policy() {
    let (path,mut chain,_,_,blocks,_)=fixture(false);
    chain.commit(&blocks[0]).unwrap();
    let authority=same(&chain);
    let tip=authority.parent.clone();
    for field in 0..5 {
        chain.evidence.db.execute_batch("BEGIN").unwrap();
        let mut altered=tip.clone();
        match field {0=>altered.network^=1,1=>altered.genesis[0]^=1,
            2=>altered.fingerprint[0]^=1,3=>altered.height+=1,_=>altered.block[0]^=1}
        chain.evidence.db.execute("UPDATE finalized_v2 SET anchor=?1 WHERE height=?2",
            params![altered.encode(),1u64.to_be_bytes().as_slice()]).unwrap();
        // This performance candidate intentionally adds no new persisted-anchor
        // policy: ordinary current authority uses its own constructor context.
        if field<4 {assert_eq!(same(&chain),authority);} else {same_refusal(&chain);}
        chain.evidence.db.execute_batch("ROLLBACK").unwrap();
    }
    chain.evidence.db.execute_batch("BEGIN").unwrap();
    chain.evidence.db.execute("UPDATE canonical_v2 SET root=?1 WHERE height=?2",
        params![[9u8;32].as_slice(),1u64.to_be_bytes().as_slice()]).unwrap();
    same_refusal(&chain);
    chain.evidence.db.execute_batch("ROLLBACK").unwrap();
    cleanup(path,chain);
}

#[test]
fn coherent_actor_authority_rechecks_accepted_recovery_commitment() {
    let (path,mut chain,_,_,blocks,proof)=fixture(true);
    chain.commit(&blocks[0]).unwrap();
    chain.accept_recovery_encoded(&proof.unwrap()).unwrap();
    same(&chain);
    chain.evidence.db.execute_batch("BEGIN").unwrap();
    chain.evidence.db.execute("UPDATE accepted_recovery_v2 SET commitment=?1",
        [[7u8;32].as_slice()]).unwrap();
    assert!(matches!(chain.current_actor_authority(),Err(StoreError::Integrity)));
    same_refusal(&chain);
    chain.evidence.db.execute_batch("ROLLBACK").unwrap();
    same(&chain);
    cleanup(path,chain);
}

#[test]
fn coherent_actor_authority_retains_tip_evidence_and_header_refusals() {
    let (path,mut chain,_,_,blocks,_)=fixture(false);
    chain.commit(&blocks[0]).unwrap();
    for mutation in 0..3 {
        chain.evidence.db.execute_batch("BEGIN").unwrap();
        match mutation {
            0=>{chain.evidence.db.execute("DELETE FROM evidence_v2",[]).unwrap();},
            1=>{chain.evidence.db.execute("UPDATE evidence_v2 SET envelope=?1",
                [vec![0u8]]).unwrap();},
            _=>{
                let mut wrong=blocks[0].clone();
                wrong.header.candidate.parent[0]^=1;
                chain.evidence.db.execute("UPDATE evidence_v2 SET envelope=?1",
                    [wrong.encode().unwrap()]).unwrap();
            },
        }
        same_refusal(&chain);
        chain.evidence.db.execute_batch("ROLLBACK").unwrap();
        same(&chain);
    }
    cleanup(path,chain);
}

#[test]
fn coherent_actor_authority_joins_snapshot_and_rechecks_external_commits() {
    let (path,chain,genesis,state,blocks,_)=fixture(false);
    let mut writer=CanonicalStore::open_trusted_genesis(&path,&genesis,&state,
        state.root().unwrap(),1000,[255;32]).unwrap();
    // TEST-only WAL allows deterministic writer interleaving. Normal open
    // retains DELETE/FULL and no production setting changes are proposed.
    chain.evidence.db.pragma_update(None,"journal_mode","WAL").unwrap();
    writer.evidence.db.pragma_update(None,"journal_mode","WAL").unwrap();
    let frozen=chain.read_snapshot(|store| {
        assert!(writer.commit(&blocks[0])?);
        store.current_actor_authority()
    }).unwrap();
    assert_eq!(frozen.parent,genesis);
    assert_eq!(same(&chain).parent,blocks[0].certificate.decision.anchor());
    // No retained witness/cache may hide a later same-head external halt.
    writer.evidence.db.execute("UPDATE integrity_v2 SET halted=1 WHERE id=1",[]).unwrap();
    assert!(matches!(chain.current_actor_authority(),Err(StoreError::Halted)));
    same_refusal(&chain);
    drop(writer); cleanup(path,chain);
}
