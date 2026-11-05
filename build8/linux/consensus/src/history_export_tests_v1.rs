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
    let path = std::env::temp_dir().join(format!("build8-history-export-{}.sqlite", hex::encode(nonce)));
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
fn page(outcome: HistoryPreparation) -> PreparedCanonicalHistory {
    match outcome { HistoryPreparation::Page(p) => p, other => panic!("expected page, got {other:?}") }
}

#[test]
fn b1_export_h0_uses_own_full_pin_and_rejects_every_checkpoint_field() {
    let (path, chain, genesis, _, _, _) = fixture(false);
    assert!(chain.canonical_block(0).unwrap().is_none());
    let empty = page(chain.prepare_history_page(&genesis,64,4*1024*1024,6).unwrap());
    assert_eq!(empty.from(), &genesis);
    assert_eq!(empty.through(), &genesis);
    assert_eq!(empty.tip(), &genesis);
    assert!(empty.objects().is_empty());
    for field in 0..5 {
        let mut wrong = genesis.clone();
        match field { 0 => wrong.network ^= 1, 1 => wrong.genesis[0] ^= 1,
            2 => wrong.fingerprint[0] ^= 1, 3 => wrong.height = 1,
            _ => wrong.block[0] ^= 1 }
        assert!(matches!(chain.prepare_history_page(&wrong,64,4*1024*1024,6).unwrap(),
            HistoryPreparation::CheckpointRejected));
    }
    for (blocks,bytes,entries) in [(0,1,1),(65,1,1),(1,0,1),
        (1,4*1024*1024+1,1),(1,1,0),(1,1,7)] {
        assert!(chain.prepare_history_page(&genesis,blocks,bytes,entries).is_err());
    }
    assert_eq!(chain.load().unwrap().0.height,0);
    cleanup(path,chain);
}

#[test]
fn b1_export_h1_full_envelope_exact_caps_and_at_tip_are_read_only() {
    let (path, mut chain, genesis, _, blocks, _) = fixture(false);
    chain.commit(&blocks[0]).unwrap();
    let tip = blocks[0].certificate.decision.anchor();
    let original = chain.certified_envelope_bytes(1,tip.block).unwrap().unwrap();
    assert!(matches!(chain.prepare_history_page(&genesis,1,original.len()-1,1).unwrap(),
        HistoryPreparation::Busy));
    let p = page(chain.prepare_history_page(&genesis,1,original.len(),1).unwrap());
    assert_eq!(p.from(), &genesis);
    assert_eq!(p.through(), &tip);
    assert_eq!(p.tip(), &tip);
    assert_eq!(p.objects().len(),1);
    assert_eq!(p.objects()[0].kind(),3);
    assert_eq!(p.objects()[0].height(),1);
    assert_eq!(p.objects()[0].bytes(),original);
    let empty = page(chain.prepare_history_page(&tip,64,1,1).unwrap());
    assert_eq!(empty.through(), &tip);
    assert!(empty.objects().is_empty());
    for field in 0..5 {
        let mut wrong = tip.clone();
        match field {0=>wrong.network^=1,1=>wrong.genesis[0]^=1,
            2=>wrong.fingerprint[0]^=1,3=>wrong.height=2,_=>wrong.block[0]^=1}
        assert!(matches!(chain.prepare_history_page(&wrong,1,4*1024*1024,6).unwrap(),
            HistoryPreparation::CheckpointRejected));
    }
    assert_eq!(chain.load().unwrap().0.height,1);
    assert_eq!(chain.evidence.anchor(1).unwrap().unwrap(),tip);
    cleanup(path,chain);
}

#[test]
fn b1_export_never_trusts_corrupt_native_evidence_or_halted_store() {
    let (path, mut chain, genesis, _, blocks, _) = fixture(false);
    chain.commit(&blocks[0]).unwrap();
    let tip = blocks[0].certificate.decision.anchor();
    let original = chain.certified_envelope_bytes(1,tip.block).unwrap().unwrap();
    let mut corrupted = original.clone();
    let last = corrupted.len()-1;
    corrupted[last] ^= 1;
    chain.evidence.db.execute("UPDATE evidence_v2 SET envelope=?1",[&corrupted]).unwrap();
    assert!(chain.prepare_history_page(&genesis,1,4*1024*1024,6).is_err());
    chain.evidence.db.execute("UPDATE evidence_v2 SET envelope=?1",[&original]).unwrap();
    chain.evidence.db.execute("UPDATE integrity_v2 SET halted=1 WHERE id=1",[]).unwrap();
    assert!(matches!(chain.prepare_history_page(&tip,1,1,1),Err(StoreError::Halted)));
    chain.evidence.db.execute("UPDATE integrity_v2 SET halted=0 WHERE id=1",[]).unwrap();
    assert_eq!(page(chain.prepare_history_page(&tip,1,1,1).unwrap()).tip(), &tip);
    cleanup(path,chain);
}

#[test]
fn b1_export_missing_tip_evidence_is_unavailable_and_h0_row_cannot_replace_pin() {
    let (path, mut chain, genesis, _, blocks, _) = fixture(false);
    // The independently pinned Genesis root is checked even though there is no
    // height-zero CertifiedBlock and a disk row could claim a different root.
    chain.evidence.db.execute("UPDATE canonical_v2 SET root=?1 WHERE height=?2",
        params![[9u8;32].as_slice(),0u64.to_be_bytes().as_slice()]).unwrap();
    assert!(matches!(chain.prepare_history_page(&genesis,1,1,1),Err(StoreError::Integrity)));
    chain.evidence.db.execute("UPDATE canonical_v2 SET root=?1 WHERE height=?2",
        params![chain.genesis_root.as_slice(),0u64.to_be_bytes().as_slice()]).unwrap();
    chain.commit(&blocks[0]).unwrap();
    chain.evidence.db.execute("DELETE FROM evidence_v2",[]).unwrap();
    assert!(matches!(chain.prepare_history_page(&genesis,1,4*1024*1024,6).unwrap(),
        HistoryPreparation::EvidenceUnavailable));
    cleanup(path,chain);
}

#[test]
fn b1_export_snapshot_is_frozen_across_an_external_writer_commit() {
    let (path, chain, genesis, state, blocks, _) = fixture(false);
    let mut writer = CanonicalStore::open_trusted_genesis(&path,&genesis,&state,
        state.root().unwrap(),1000,[255;32]).unwrap();
    // TEST-only WAL permits a synchronous external commit during a read. Normal
    // store construction keeps its existing DELETE/FULL durability policy.
    chain.evidence.db.pragma_update(None,"journal_mode","WAL").unwrap();
    writer.evidence.db.pragma_update(None,"journal_mode","WAL").unwrap();
    // read_snapshot's schema reads have established the transaction before the
    // second independent SQLite connection appends a fully valid H1.
    let frozen = chain.read_snapshot(|same_snapshot| {
        assert!(writer.commit(&blocks[0])?);
        same_snapshot.prepare_history_page_snapshot(&genesis,64,4*1024*1024,6)
    }).unwrap();
    let frozen = page(frozen);
    assert_eq!(frozen.tip(),&genesis);
    assert!(frozen.objects().is_empty());
    let fresh = page(chain.prepare_history_page(&genesis,64,4*1024*1024,6).unwrap());
    assert_eq!(fresh.tip().height,1);
    assert_eq!(fresh.objects().len(),1);
    drop(writer);
    cleanup(path,chain);
}

#[test]
fn b1_export_recovery_is_a_complete_group_and_short_prefix_is_more() {
    let (path, mut chain, genesis, _, blocks, proof) = fixture(true);
    chain.commit(&blocks[0]).unwrap();
    chain.accept_recovery_encoded(&proof.unwrap()).unwrap();
    chain.commit(&blocks[1]).unwrap();
    let parent = blocks[0].certificate.decision.anchor();
    let tip = blocks[1].certificate.decision.anchor();
    let recovery = chain.recovery_record(1).unwrap().unwrap();
    let block2 = chain.certified_envelope_bytes(2,tip.block).unwrap().unwrap();
    let group_len = recovery.len()+block2.len();
    assert!(matches!(chain.prepare_history_page(&parent,64,group_len,1).unwrap(),HistoryPreparation::Busy));
    assert!(matches!(chain.prepare_history_page(&parent,64,group_len-1,2).unwrap(),HistoryPreparation::Busy));
    let pair = page(chain.prepare_history_page(&parent,64,group_len,2).unwrap());
    assert_eq!(pair.through(),&tip);
    assert_eq!(pair.objects().len(),2);
    assert_eq!((pair.objects()[0].kind(),pair.objects()[0].height()),(7,1));
    assert_eq!((pair.objects()[1].kind(),pair.objects()[1].height()),(3,2));
    assert_eq!(pair.objects()[0].bytes(),recovery);
    assert_eq!(pair.objects()[1].bytes(),block2);
    let prefix = page(chain.prepare_history_page(&genesis,64,4*1024*1024,2).unwrap());
    assert_eq!(prefix.through(),&parent);
    assert_eq!(prefix.tip(),&tip);
    assert_eq!(prefix.objects().len(),1,"no orphan recovery-only suffix");
    let one_block = page(chain.prepare_history_page(&genesis,1,4*1024*1024,6).unwrap());
    assert_eq!(one_block.through(),&parent);
    assert_eq!(one_block.tip(),&tip);
    cleanup(path,chain);
}
