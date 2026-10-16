//! NONSHIPPING diagnostic: first eight ORIGINAL producer ticks, no maturity/payment claim.
#[path = "forge_live_fixture/fixture.rs"]
mod fixture;
#[path = "forge_live_fixture/support/x509_syntax.rs"]
mod x509_syntax;
#[path = "forge_producer_phase_probe/producer.rs"]
mod producer;

use mutinyd_v8::genesis_artifact_v2::{freeze_with_public_evidence, TrustV2, VerifiedGenesisV2};
use mutiny_consensus_v8::genesis_v2::{Approved,GenesisClass};
use sha2::{Digest,Sha256};
use std::{io::Write,path::Path,time::Instant};
const PROBE_BLOCKS:u64=8;
fn public_file(path:&Path,bytes:&[u8]) {
    let mut file=std::fs::OpenOptions::new().write(true).create_new(true).open(path).unwrap();
    file.write_all(bytes).unwrap();file.sync_all().unwrap();
}
#[test]
fn first_eight_original_producer_ticks_phase_probe_then_voter_reopen() {
    assert!(!mutiny_transport_v2::PRODUCTION_QUALIFIED);
    assert_eq!(mutiny_consensus_v8::transactions::MATURITY,100);
    assert_eq!(producer::MAX_BLOCKS,101);
    assert_eq!(producer::MAX_SECONDS,3600);
    let started=Instant::now();
    let mut suffix=[0;16];mutiny_crypto_v2::fill_os_random(&mut suffix).unwrap();
    let base=std::env::temp_dir().join(format!("forge-producer-phase-probe-{}",hex::encode(suffix)));
    assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
    let output=base.join("public");std::fs::create_dir(&output).unwrap();
    fixture::with_fresh_ephemeral(|inputs,enrollment,constructed,node,continuity,public_evidence| {
        assert_eq!(inputs.class(),GenesisClass::TestValue);
        let approved=Approved {manifest:inputs.parameters.rules.clone(),class:GenesisClass::TestValue,
            initial_target:inputs.parameters.initial_target};
        let (artifact,reconstructed)=freeze_with_public_evidence(inputs,enrollment,&approved,public_evidence).unwrap();
        assert_eq!(reconstructed.anchor(),constructed.anchor());
        let trust=TrustV2 {artifact_sha256:Sha256::digest(&artifact).into(),
            genesis_block_hash:constructed.block_hash,approved};
        let verified=VerifiedGenesisV2::verify_with_public_evidence(&artifact,&trust,public_evidence).unwrap();
        assert!(verified.genesis.state.coins.is_empty());
        public_file(&output.join("artifact.json"),&artifact);
        public_file(&output.join("public-evidence.cbor"),public_evidence);
        public_file(&output.join("approved-rules.cbor"),&inputs.parameters.rules.encode().unwrap());
        public_file(&output.join("pins.json"),&serde_json::to_vec_pretty(&serde_json::json!({
            "schema":"FORGE-PRODUCER-PHASE-PROBE-R1","class":"TEST-VALUE",
            "artifact_sha256":hex::encode(trust.artifact_sha256),
            "public_evidence_sha256":hex::encode(Sha256::digest(public_evidence)),
            "h0_anchor":hex::encode(constructed.anchor().encode()),
            "h0_state_root":hex::encode(constructed.root),"probe_blocks":PROBE_BLOCKS,
            "max_seconds":producer::MAX_SECONDS,"max_blocks":producer::MAX_BLOCKS,
            "maturity":mutiny_consensus_v8::transactions::MATURITY,
            "probe_source_sha256":hex::encode(Sha256::digest(include_bytes!("forge_producer_phase_probe.rs"))),
            "owner_source_sha256":hex::encode(Sha256::digest(include_bytes!("forge_producer_phase_probe/producer.rs"))),
            "private_keys_persisted":false,"production_eligible":false})).unwrap());
        let open=Instant::now();
        let mut owner=producer::Producer::open(&base,&verified,enrollment,node,continuity);
        eprintln!("{}",serde_json::json!({"kind":"FORGE-PRODUCER-PHASE-PROBE-R1","stage":"open",
            "elapsed_ns":open.elapsed().as_nanos().to_string(),"state_directory":base.display().to_string()}));
        for _ in 0..PROBE_BLOCKS {assert!(owner.tick());}
        // EXTRA OBSERVER ONLY: outside original tick timing and not producer work.
        let observer=Instant::now();
        let (observed_head,observed_state)=owner.chain.load().unwrap();
        let load_ns=observer.elapsed().as_nanos().to_string();
        let records_started=Instant::now();
        let records=observed_state.records().unwrap();
        let records_ns=records_started.elapsed().as_nanos().to_string();
        let raw_started=Instant::now();
        let raw_root=mutiny_consensus_v8::blocks::state_root(&records).unwrap();
        let raw_root_ns=raw_started.elapsed().as_nanos().to_string();
        let record_count=records.len();
        let record_bytes:usize=records.iter().map(|(_,v)|v.len()).sum();
        drop(records); // Do not retain the observer Vec during full root serialization.
        let full_started=Instant::now();
        let full_root=observed_state.root().unwrap();
        let full_root_ns=full_started.elapsed().as_nanos().to_string();
        assert_eq!(raw_root,observed_head.root);assert_eq!(full_root,observed_head.root);
        eprintln!("{}",serde_json::json!({"kind":"FORGE-PRODUCER-EXTRA-OBSERVER-R1",
            "outside_tick":true,"height":observed_head.height,"record_count":record_count,
            "record_value_bytes":record_bytes,"load_ns":load_ns,"records_ns":records_ns,
            "raw_state_root_ns":raw_root_ns,"full_state_root_ns":full_root_ns,
            "observer_total_ns":observer.elapsed().as_nanos().to_string()}));
        drop(observed_state);
        assert_eq!(owner.generated,PROBE_BLOCKS);
        assert_eq!(owner.runtime.head().unwrap().height,PROBE_BLOCKS);
        assert_eq!(owner.actor.height(),PROBE_BLOCKS+1);
        assert_eq!(owner.backend.vote_signatures,2*PROBE_BLOCKS);
        assert_eq!(owner.backend.work_signatures,PROBE_BLOCKS);
        let counters=(owner.backend.counter,owner.backend.vote_signatures,owner.backend.work_signatures,owner.nonce_trials);
        let close=Instant::now();
        owner.close_verify_voter(); // EXACT original reopen/counter-preservation ceremony.
        let close_ns=close.elapsed().as_nanos().to_string();
        let result=serde_json::json!({"schema":"FORGE-PRODUCER-PHASE-PROBE-R1",
            "blocks":PROBE_BLOCKS,"counter_end":counters.0,"vote_signatures":counters.1,
            "work_signatures":counters.2,"nonce_trials":counters.3,"voter_reopen_passed":true,
            "close_reopen_ns":close_ns,"elapsed_seconds":started.elapsed().as_secs_f64(),
            "maturity":100,"max_seconds":producer::MAX_SECONDS,"max_blocks":producer::MAX_BLOCKS,
            "maturity_or_payment_qualification":false,"private_keys_persisted":false,
            "production_eligible":false,"state_directory":base.display().to_string()});
        public_file(&output.join("result.json"),&serde_json::to_vec_pretty(&result).unwrap());
        eprintln!("FORGE PRODUCER PHASE PROBE RESULT {result}");
    });
    public_file(&output.join("key-scope-ended.json"),&serde_json::to_vec(&serde_json::json!({
        "fixture_callback_returned":true,"ephemeral_key_owners_dropped":true,
        "private_keys_persisted":false,"endpoint_running":false,"worker_running":false})).unwrap());
    eprintln!("FORGE PRODUCER PHASE PROBE public evidence {}",output.display());
}
