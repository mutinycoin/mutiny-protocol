//! Public synthetic fixtures; replay optimization changes no custody/native gate.
use super::*;

fn fixture() -> (std::path::PathBuf, CanonicalStore, State, BlockEnvelope) {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/hybrid-canonical-store-public-v1.json")).unwrap();
    assert_eq!(f["synthetic_only"], true);
    assert_eq!(f["production_authorized"], false);
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let root = raw(&f["root"]).try_into().unwrap();
    let rows: Vec<_> = f["records"].as_array().unwrap().iter().map(|r|
        (raw(&r["key"]).try_into().unwrap(), raw(&r["record"]))).collect();
    let state = State::from_records(&rows, root).unwrap();
    let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
    let block = BlockEnvelope::decode(&raw(&f["envelope"])).unwrap();
    let mut nonce = [0;16]; mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let base = std::env::temp_dir().join(format!("build8-replay-parent-{}",hex::encode(nonce)));
    assert!(crate::submission_pool_v1::private_directory(&base).unwrap());
    let path = base.join("chain.sqlite");
    assert!(!path.exists());
    let chain = CanonicalStore::open_trusted_genesis(&path,&genesis,&state,root,1000,[255;32]).unwrap();
    (path,chain,state,block)
}
fn cleanup(path: std::path::PathBuf, chain: CanonicalStore) {
    drop(chain); std::fs::remove_file(&path).unwrap();
    let pool=path.with_file_name("submissions.sqlite");
    if pool.exists() {std::fs::remove_file(pool).unwrap();}
    std::fs::remove_dir(path.parent().unwrap()).unwrap();
}
fn replace(chain: &CanonicalStore, raw: &[u8]) {
    assert_eq!(chain.evidence.db.execute("UPDATE evidence_v2 SET envelope=?1",[raw]).unwrap(),1);
}
fn public_replay_refusal_without_mutation(chain: &CanonicalStore, path: &Path) -> StoreError {
    let pool_path=path.with_file_name("submissions.sqlite");
    let mut pool=crate::submission_pool_v1::SubmissionPool::open(&pool_path,
        chain.genesis.genesis,chain.genesis.fingerprint,crate::submission_pool_v1::MAX_BYTES).unwrap();
    let canonical_before=std::fs::read(path).unwrap();
    let pool_before=std::fs::read(&pool_path).unwrap();
    let cause=chain.reconcile_submission_pool(&mut pool,0).unwrap_err();
    assert_eq!(std::fs::read(path).unwrap(),canonical_before,"refusal cannot repair canonical bytes");
    assert_eq!(std::fs::read(&pool_path).unwrap(),pool_before,"refusal cannot mutate submission state");
    drop(pool);
    cause
}

#[test]
fn replay_parent_reuse_binds_verified_height_hash_target_root_and_state() {
    let (path,mut chain,state,block) = fixture();
    chain.commit(&block).unwrap();
    let previous = head(&chain.evidence.db,Some(0)).unwrap();
    let original = chain.retained_envelope(1,block.block_hash()).unwrap().unwrap();
    let reused = chain.replay_parent_envelope(1,block.block_hash(),&previous,&state).unwrap().unwrap();
    assert_eq!(reused,original);
    chain.verify_replay(&state).unwrap();
    for field in 0..4 {
        let mut wrong=previous.clone();
        match field {0=>wrong.height+=1,1=>wrong.block[0]^=1,
            2=>wrong.target[0]^=1,_=>wrong.root[0]^=1}
        assert!(chain.replay_parent_envelope(1,block.block_hash(),&wrong,&state).is_err(),
            "wrong replay parent field {field} must refuse");
    }
    let mut wrong_state=state.clone(); wrong_state.coins.clear();
    assert_ne!(wrong_state.root().unwrap(),previous.root);
    assert!(chain.replay_parent_envelope(1,block.block_hash(),&previous,&wrong_state).is_err());
    cleanup(path,chain);
}

#[test]
fn replay_parent_reuse_still_refuses_changed_archived_headers() {
    let (path,mut chain,state,block)=fixture(); chain.commit(&block).unwrap();
    let original=block.encode().unwrap();
    let saved=head(&chain.evidence.db,None).unwrap();
    for field in 0..7 {
        let mut wrong=block.clone();
        match field {0=>wrong.header.candidate.network^=1,1=>wrong.header.candidate.genesis[0]^=1,
            2=>wrong.header.candidate.fingerprint[0]^=1,3=>wrong.header.candidate.parent[0]^=1,
            4=>wrong.header.candidate.height+=1,5=>wrong.header.candidate.target[0]^=1,
            _=>wrong.header.candidate.timestamp+=1}
        replace(&chain,&wrong.encode().unwrap());
        assert!(chain.verify_replay(&state).is_err(),"archived header field {field}");
        let _=public_replay_refusal_without_mutation(&chain,&path);
        assert_eq!(head(&chain.evidence.db,None).unwrap(),saved,"replay must not repair state");
    }
    replace(&chain,&original); chain.verify_replay(&state).unwrap();
    cleanup(path,chain);
}

#[test]
fn replay_parent_reuse_verifies_both_archived_certificate_signature_halves() {
    let (path,mut chain,state,block)=fixture(); chain.commit(&block).unwrap();
    let original=block.encode().unwrap();
    let capacity=chain.proposal_body_capacity(&block.header).unwrap();
    for half in 0..2 {
        let mut wrong=block.clone();
        if half==0 {wrong.certificate.votes[0].signature.ed448[0]^=1;}
        else {
            assert_eq!(wrong.certificate.votes[0].signature.fndsa[0],0x3a);
            // Interior nonce payload: keep the required marker and compressed
            // signature bytes intact, so the FNDSA verification path must run.
            wrong.certificate.votes[0].signature.fndsa[17]^=1;
            assert_eq!(wrong.certificate.votes[0].signature.fndsa[0],0x3a);
            assert_eq!(wrong.certificate.votes[0].signature.ed448,block.certificate.votes[0].signature.ed448);
        }
        assert_eq!(wrong.block_hash(),block.block_hash(),"same archived header/block identity");
        let raw=wrong.encode().unwrap();
        let decoded=BlockEnvelope::decode_with_capacity(&raw,&capacity).unwrap();
        assert_eq!(decoded,wrong,"corruption is canonical-decodable, not a codec refusal");
        replace(&chain,&raw);
        assert!(matches!(chain.verify_replay(&state),Err(StoreError::Verification(_))),
            "native certificate half {half} must still verify");
        assert!(matches!(public_replay_refusal_without_mutation(&chain,&path),StoreError::Verification(_)),
            "canonical signature bytes must reach native certification in the public path");
    }
    replace(&chain,&original); chain.verify_replay(&state).unwrap();
    cleanup(path,chain);
}

#[test]
fn replay_parent_reuse_detects_same_head_undo_operation_index_and_state_corruption() {
    for table in ["undo_v2","operation_index_v2","state_v2"] {
        let (path,mut chain,state,block)=fixture(); chain.commit(&block).unwrap();
        chain.verify_replay(&state).unwrap();
        let saved=head(&chain.evidence.db,None).unwrap();
        let sql=match table {
            "undo_v2"=>"UPDATE undo_v2 SET previous=X'01' WHERE rowid=(SELECT rowid FROM undo_v2 LIMIT 1)",
            "operation_index_v2"=>"UPDATE operation_index_v2 SET record=X'01' WHERE rowid=(SELECT rowid FROM operation_index_v2 LIMIT 1)",
            _=>"UPDATE state_v2 SET value=X'01' WHERE rowid=(SELECT rowid FROM state_v2 LIMIT 1)",
        };
        assert_eq!(chain.evidence.db.execute(sql,[]).unwrap(),1);
        assert_eq!(head(&chain.evidence.db,None).unwrap(),saved);
        assert!(chain.verify_replay(&state).is_err(),"same-head {table} mutation must refuse");
        let _=public_replay_refusal_without_mutation(&chain,&path);
        assert_eq!(head(&chain.evidence.db,None).unwrap(),saved);
        cleanup(path,chain);
    }
}

#[test]
fn replay_parent_reuse_uses_actual_legacy_parent_body_capacity_before_execution() {
    let (path,mut chain,state,block)=fixture(); chain.commit(&block).unwrap();
    let previous=head(&chain.evidence.db,Some(0)).unwrap();
    let capacity=chain.proposal_body_capacity(&block.header).unwrap();
    assert_eq!(capacity.body_limit(),crate::body_capacity_v3::MAX_LEGACY_BODY_BYTES);
    // Canonical outer syntax stays small enough for global ingress, but this
    // fabricated body exceeds the ACTUAL legacy parent's 64-KiB capacity. Its
    // original header remains unchanged so header/hash checks alone cannot win.
    let mut body=minicbor::Encoder::new(Vec::new());
    body.array(5).unwrap().u8(1).unwrap().u64(1).unwrap().array(3).unwrap()
        .bytes(&block.body.reward_owner).unwrap().u64(100_000_000).unwrap()
        .u64(block.body.fees).unwrap().array(5).unwrap();
    for _ in 0..5 {body.bytes(&vec![0;16_384]).unwrap();}
    body.array(0).unwrap(); let body=body.into_writer();
    assert!(body.len()>capacity.body_limit());
    let mut outer=minicbor::Encoder::new(Vec::new());
    outer.array(5).unwrap().u8(2).unwrap().bytes(&block.header.encode()).unwrap()
        .bytes(&body).unwrap().bytes(&block.authority.encode().unwrap()).unwrap()
        .bytes(&block.certificate.encode().unwrap()).unwrap();
    let raw=outer.into_writer();
    assert_eq!(BlockEnvelope::untrusted_header(&raw).unwrap(),block.header);
    replace(&chain,&raw);
    assert!(matches!(chain.replay_parent_envelope(1,block.block_hash(),&previous,&state),
        Err(StoreError::Invalid(crate::Error::Oversize))));
    assert!(matches!(chain.verify_replay(&state),Err(StoreError::Invalid(crate::Error::Oversize))));
    cleanup(path,chain);
}

#[test]
fn replay_parent_reuse_preserves_halted_missing_and_malformed_refusal_order() {
    let (path,mut chain,state,block)=fixture(); chain.commit(&block).unwrap();
    let previous=head(&chain.evidence.db,Some(0)).unwrap();
    chain.evidence.db.execute("UPDATE integrity_v2 SET halted=1 WHERE id=1",[]).unwrap();
    assert!(matches!(chain.replay_parent_envelope(1,block.block_hash(),&previous,&state),Err(StoreError::Halted)));
    assert!(matches!(chain.retained_envelope(1,block.block_hash()),Err(StoreError::Halted)));
    assert!(chain.replay_parent_envelope(9,[9;32],&previous,&state).unwrap().is_none());
    assert!(chain.retained_envelope(9,[9;32]).unwrap().is_none());
    replace(&chain,&[0]);
    assert!(matches!(chain.replay_parent_envelope(1,block.block_hash(),&previous,&state),Err(StoreError::Invalid(_))));
    assert!(matches!(chain.retained_envelope(1,block.block_hash()),Err(StoreError::Invalid(_))));
    cleanup(path,chain);
}
