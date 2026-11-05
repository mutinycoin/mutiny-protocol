//! Explicit nonshipping TEST producer qualification; no Desktop/network claim.
#[path = "forge_live_fixture/fixture.rs"]
mod fixture;
#[path = "forge_live_fixture/support/x509_syntax.rs"]
mod x509_syntax;
#[path = "forge_automatic_test_producer/producer.rs"]
mod producer;

use mutinyd_v8::genesis_artifact_v2::{freeze_with_public_evidence, TrustV2, VerifiedGenesisV2};
use mutiny_consensus_v8::{genesis_v2::{Approved, GenesisClass}, hybrid_transaction_v2::{Inclusion, Transaction},
    transactions::{OutPoint, Output, TxError, MATURITY, SUBSIDY}, transactions_v2::{Input, Transfer}};
use mutiny_crypto_v2::{HybridKey, Role};
use sha2::{Digest, Sha256};
use std::{io::Write, path::{Path, PathBuf}, sync::{Arc, atomic::AtomicU64}, time::Instant};

fn public_file(path: &Path, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(path).unwrap();
    file.write_all(bytes).unwrap(); file.sync_all().unwrap();
}
fn payment(verified: &VerifiedGenesisV2, point: OutPoint, first: u64, owner: &HybridKey) -> Transaction {
    let mut transfer = Transfer { network: mutiny_consensus_v8::NETWORK_ID,
        genesis: verified.genesis.identity, fingerprint: verified.genesis.fingerprint,
        created_height: first, expiry_height: 201, fee: 10_000,
        inputs: vec![Input::unsigned(point, owner.public(), 1).unwrap()],
        outputs: vec![Output { owner: mutiny_consensus_v8::domain_hash(b"FORGE-TEST-RECIPIENT", b"synthetic-only"), atoms: SUBSIDY - 10_000 }] };
    transfer.sign_input(0, owner).unwrap();
    let tx = Transaction::Transfer(transfer);
    assert!(tx.encode().unwrap().len() <= tx.fee() as usize);
    tx
}

#[test]
fn automatic_test_producer_earns_matures_and_confirms_actual_admitted_payment_then_reopens() {
    assert!(!mutiny_transport_v2::PRODUCTION_QUALIFIED);
    assert_eq!(MATURITY, 100);
    let started = Instant::now();
    let mut suffix = [0; 16]; mutiny_crypto_v2::fill_os_random(&mut suffix).unwrap();
    let base = std::env::temp_dir().join(format!("forge-automatic-test-producer-{}", hex::encode(suffix)));
    assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
    let output = std::env::var_os("FORGE_AUTOMATIC_PRODUCER_OUTPUT").map(PathBuf::from)
        .unwrap_or_else(|| base.join("public"));
    std::fs::create_dir(&output).unwrap();
    fixture::with_fresh_ephemeral(|inputs, enrollment, constructed, node, continuity, public_evidence| {
        assert_eq!(inputs.class(), GenesisClass::TestValue);
        let approved = Approved { manifest: inputs.parameters.rules.clone(), class: GenesisClass::TestValue,
            initial_target: inputs.parameters.initial_target };
        let (artifact, reconstructed) = freeze_with_public_evidence(inputs, enrollment, &approved, public_evidence).unwrap();
        assert_eq!(reconstructed.anchor(), constructed.anchor());
        let trust = TrustV2 { artifact_sha256: Sha256::digest(&artifact).into(),
            genesis_block_hash: constructed.block_hash, approved };
        let verified = VerifiedGenesisV2::verify_with_public_evidence(&artifact, &trust, public_evidence).unwrap();
        assert!(verified.genesis.state.coins.is_empty(), "fresh Genesis grants no spendable coins");
        public_file(&output.join("artifact.json"), &artifact);
        public_file(&output.join("public-evidence.cbor"), public_evidence);
        let rules = inputs.parameters.rules.encode().unwrap();
        public_file(&output.join("approved-rules.cbor"), &rules);
        let pins = serde_json::json!({"schema":"FORGE-AUTOMATIC-PRODUCER-PUBLIC-TRUST-V1",
            "network":mutiny_consensus_v8::NETWORK_ID,"genesis_id":hex::encode(constructed.identity),
            "genesis_block_hash":hex::encode(constructed.block_hash),"fingerprint":hex::encode(constructed.fingerprint),
            "h0_anchor":hex::encode(constructed.anchor().encode()),"h0_state_root":hex::encode(constructed.root),
            "artifact_sha256":hex::encode(trust.artifact_sha256),"public_evidence_sha256":hex::encode(Sha256::digest(public_evidence)),
            "approved_manifest_sha256":hex::encode(Sha256::digest(&rules)),"class":"TEST-VALUE",
            "initial_target":hex::encode(inputs.parameters.initial_target),"test_timestamp":inputs.timestamp,
            "eligible_voters":1,"authority":"single eligible synthetic bootstrap certifier; centralized TEST quorum",
            "vultr_voting_weight":0,"routing_addresses":[],"transport_descriptors":[],
            "private_keys_persisted":false,"production_eligible":false,
            "test_source_sha256":hex::encode(Sha256::digest(include_bytes!("forge_automatic_test_producer.rs"))),
            "owner_source_sha256":hex::encode(Sha256::digest(include_bytes!("forge_automatic_test_producer/producer.rs")))});
        public_file(&output.join("pins.json"), &serde_json::to_vec_pretty(&pins).unwrap());
        println!("AUTOMATIC TEST public trust ready: {}", hex::encode(constructed.identity));
        let mut owner = producer::Producer::open(&base, &verified, enrollment, node, continuity);
        assert!(owner.tick());
        assert_eq!(owner.runtime.head().unwrap().height, 1);
        let (_, state) = owner.chain.load().unwrap();
        let key = HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner).unwrap();
        let owner_id = key.public().address_id(1).unwrap();
        let (earned_point, earned_coin) = state.coins.iter().find(|(_, c)| c.coinbase && c.created_height == 1
            && c.output.owner == owner_id).expect("actual earned H1 reward for fixture owner");
        assert_eq!(earned_coin.output.atoms, SUBSIDY);
        let earned_point = earned_point.clone();
        let premature = payment(&verified, earned_point.clone(), 2, &key);
        let parent = owner.runtime.head().unwrap();
        assert!(matches!(premature.verify(&Inclusion { parent: &parent, history: &Default::default() }, &state), Err(TxError::Immature)));
        // Real admission also refuses this H2 immature spend; no state mutation or
        // weaker direct Mempool insertion substitutes for the runtime gate.
        assert!(owner.runtime.admit(&premature.encode().unwrap()).is_err());
        assert!(owner.runtime.relay_pending().unwrap().is_empty());
        assert_eq!(owner.runtime.confirmed_height(premature.id().unwrap()).unwrap(), None);
        println!("AUTOMATIC TEST H1 earned coin maturity refusal passed");
        while owner.tick() {
            if owner.generated % 10 == 0 { println!("AUTOMATIC TEST funding progress H{} elapsed {:.1}s", owner.generated, started.elapsed().as_secs_f64()); }
        }
        assert_eq!(owner.runtime.head().unwrap().height, MATURITY);
        assert_eq!(owner.generated, MATURITY);
        assert!(!owner.tick(), "idle producer must not emit arbitrary empty blocks after funding");
        let tx = payment(&verified, earned_point.clone(), MATURITY + 1, &key);
        let tx_id = tx.id().unwrap(); let raw = tx.encode().unwrap();
        let admitted = owner.runtime.admit(&raw).unwrap();
        assert_eq!(admitted.0, tx_id);
        assert_eq!(admitted.1, mutiny_consensus_v8::mempool_v2::Status::Pending);
        assert_eq!(owner.runtime.confirmed_height(tx_id).unwrap(), None, "admission grants no confirmation");
        assert_eq!(owner.runtime.relay_pending().unwrap().len(), 1);
        let confirmed = owner.wait_for_confirmation(tx_id);
        assert_eq!(confirmed, MATURITY + 1);
        let envelope = owner.last_block.as_ref().unwrap();
        assert!(envelope.body.transactions.contains(&raw), "actual admitted bytes must be included");
        assert!(!owner.tick(), "confirmed pool must not trigger another block");
        let final_anchor = owner.runtime.head().unwrap();
        let (_, final_state) = owner.chain.load().unwrap(); let final_root = final_state.root().unwrap();
        assert!(!final_state.coins.contains_key(&earned_point));
        assert_eq!(final_state.coins.get(&OutPoint { transaction: tx_id, index: 0 }).unwrap().output, tx.outputs()[0]);
        assert_eq!(owner.backend.vote_signatures, 202); assert_eq!(owner.backend.work_signatures, 101);
        assert_eq!(owner.backend.counter, 605); assert_eq!(owner.actor.height(), 102);
        let counters = (owner.backend.counter, owner.backend.vote_signatures, owner.backend.work_signatures, owner.nonce_trials);
        owner.close_verify_voter(); // No worker/thread or socket was ever created by this owner.
        let clock = Arc::new(AtomicU64::new(inputs.timestamp + 101));
        let mut reopened = producer::open_runtime(&base, &verified, clock);
        assert_eq!(reopened.head().unwrap(), final_anchor);
        assert_eq!(reopened.confirmed_height(tx_id).unwrap(), Some(101));
        assert!(matches!(reopened.submission_status(tx_id).unwrap(), mutiny_consensus_v8::submission_v1::Status::Finalized(_)));
        assert!(reopened.relay_pending().unwrap().is_empty()); drop(reopened);
        let reopened_chain = mutiny_consensus_v8::canonical_store_v2::CanonicalStore::open_trusted_genesis(
            &base.join("chain.sqlite"), &constructed.anchor(), &constructed.state, constructed.root,
            inputs.timestamp, inputs.parameters.initial_target).unwrap();
        assert_eq!(reopened_chain.load().unwrap().1.root().unwrap(), final_root); drop(reopened_chain);
        let result = serde_json::json!({"schema":"FORGE-AUTOMATIC-TEST-PRODUCER-RESULT-V1",
            "final_height":101,"payment_id":hex::encode(tx_id),"confirmed_height":confirmed,
            "payment_bytes":raw.len(),"fee_atoms":tx.fee(),"earned_h1_subsidy_atoms":SUBSIDY,
            "maturity":MATURITY,"maturity_refused_at_inclusion":2,"first_spend_inclusion":101,
            "final_anchor":hex::encode(final_anchor.encode()),"final_root":hex::encode(final_root),
            "continuity_signatures":counters.1,"node_work_signatures":counters.2,"nonce_trials":counters.3,
            "counter_start":100,"counter_end":counters.0,"blocks":101,"voter_height":102,
            "max_blocks":producer::MAX_BLOCKS,"max_seconds":producer::MAX_SECONDS,
            "elapsed_seconds":started.elapsed().as_secs_f64(),"saved_state_reopen_passed":true,"voter_reopen_passed":true,
            "automatic_after_actual_admission":true,"manual_block_schedule":false,
            "clock":"synthetic ControlledClock t0+height; no qualified UTC assertion",
            "signing_backend":"ephemeral TEST counter with exact durable reservation check; not production TPM",
            "quorum":"one actual eligible synthetic bootstrap voter; no lowered threshold",
            "state_directory":base.display().to_string(),"threads_created":0,"sockets_created":0,
            "background_worker_remaining":false,"private_keys_persisted":false,
            "desktop_user_authorization_tested":false,"network_catchup_tested":false,
            "hardware_or_rf_activated":false,"production_eligible":false});
        public_file(&output.join("result.json"), &serde_json::to_vec_pretty(&result).unwrap());
        println!("AUTOMATIC TEST producer result: {result}");
    });
    public_file(&output.join("key-scope-ended.json"), &serde_json::to_vec(&serde_json::json!({
        "fixture_callback_returned":true,"ephemeral_key_owners_dropped":true,"private_keys_persisted":false,
        "endpoint_running":false,"worker_running":false})).unwrap());
    println!("AUTOMATIC TEST key-owning scope ended; public evidence {}", output.display());
}
