//! TEST public canonical bytes only, without transport processes or key owners.
use super::*;
use crate::history_protocol_v1::{HistoryRequest, HistoryStatus};
use mutiny_consensus_v8::execution::State;
use mutiny_transport_v2::objects::object_id;

#[test]
fn b1_runtime_export_uses_actual_object_hashes_and_minimum_local_peer_budget() {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/hybrid-canonical-store-public-v1.json")).unwrap();
    assert_eq!(f["synthetic_only"],true);
    assert_eq!(f["production_authorized"],false);
    let raw = |v:&serde_json::Value|hex::decode(v.as_str().unwrap()).unwrap();
    let root = raw(&f["root"]).try_into().unwrap();
    let records:Vec<_> = f["records"].as_array().unwrap().iter().map(|r|
        (raw(&r["key"]).try_into().unwrap(),raw(&r["record"]))).collect();
    let state = State::from_records(&records,root).unwrap();
    let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
    let envelope = BlockEnvelope::decode(&raw(&f["envelope"])).unwrap();
    let mut nonce=[0;16]; mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let base=std::env::temp_dir().join(format!("build8-runtime-history-{}",hex::encode(nonce)));
    assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
    let chain=CanonicalStore::open_trusted_genesis(&base.join("chain.sqlite"),
        &genesis,&state,root,1000,[255;32]).unwrap();
    let pool=Mempool::open(&base.join("pool.sqlite"),genesis.genesis,
        genesis.fingerprint,64*1024*1024).unwrap();
    let mut runtime=HybridRuntime::from_pinned_chain_with_clock(chain,pool,||1000).unwrap();
    runtime.chain.commit(&envelope).unwrap();
    let tip=envelope.certificate.decision.anchor();
    let bytes=runtime.chain.certified_envelope_bytes(1,tip.block).unwrap().unwrap();
    let mut request=HistoryRequest{sequence:1,saved_anchor:genesis.clone(),
        max_blocks:64,max_candidate_bytes:4*1024*1024,max_candidate_entries:6};
    for (local_bytes,local_entries) in [(0,6),(4*1024*1024,0),(bytes.len()-1,6)] {
        let busy=runtime.prepare_history_export(&request,local_bytes,local_entries).unwrap();
        assert_eq!(busy.page().status,HistoryStatus::Busy);
        assert!(busy.objects().is_empty());
        assert!(busy.page().observed_tip_anchor.is_none());
    }
    request.max_candidate_bytes=(bytes.len()-1) as u32;
    assert_eq!(runtime.prepare_history_export(&request,4*1024*1024,6).unwrap().page().status,
        HistoryStatus::Busy);
    request.max_candidate_bytes=4*1024*1024;
    let prepared=runtime.prepare_history_export(&request,bytes.len(),1).unwrap();
    assert_eq!(prepared.page().status,HistoryStatus::Page);
    assert_eq!(prepared.page().request_object_id,request.object_id().unwrap());
    assert_eq!(prepared.page().offered_through_anchor.as_ref(),Some(&tip));
    assert_eq!(prepared.objects().len(),1);
    let object=&prepared.objects()[0];
    assert_eq!(object.bytes(),bytes);
    assert_eq!(object.object_id(),object_id(object.kind(),object.bytes()).unwrap());
    assert_eq!(object.object_id(),prepared.page().entries[0].object_id);
    assert_eq!(object.height(),prepared.page().entries[0].height);
    request.saved_anchor=tip.clone(); request.sequence+=1;
    let empty=runtime.prepare_history_export(&request,1,1).unwrap();
    assert_eq!(empty.page().status,HistoryStatus::AtSnapshotTip);
    assert!(empty.objects().is_empty());
    request.saved_anchor.block[0]^=1; request.sequence+=1;
    assert_eq!(runtime.prepare_history_export(&request,1,1).unwrap().page().status,
        HistoryStatus::CheckpointRejected);
    assert_eq!(runtime.chain.load().unwrap().0.height,1);
    drop(runtime);
    std::fs::remove_dir_all(base).unwrap();
}
