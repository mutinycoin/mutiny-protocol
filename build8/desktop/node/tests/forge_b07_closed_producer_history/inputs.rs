//! Read-only, explicitly pinned CLOSED TEST producer input. Never opens its DB.
use mutinyd_v8::{genesis_artifact_v2::{TrustV2,VerifiedGenesisV2},hybrid_runtime_v2::HybridRuntime};
use mutiny_consensus_v8::{Hash,anchors::FinalizedAnchor,canonical_store_v2::CanonicalStore,
    genesis_v2::{Approved,GenesisClass},mempool_v2::{Mempool,MAX_PENDING_BYTES},protocol_manifest::RuleManifest};
use sha2::{Digest,Sha256};
use std::{collections::BTreeMap,io::{Read,Write},path::{Path,PathBuf}};

pub fn hash_file(path:&Path)->String {
    let mut file=std::fs::File::open(path).unwrap();let mut hash=Sha256::new();let mut buf=[0;65536];
    loop {let n=file.read(&mut buf).unwrap();if n==0 {break;}hash.update(&buf[..n]);}
    hex::encode(hash.finalize())
}
fn env_digest(name:&str)->String {
    let value=std::env::var(name).unwrap_or_else(|_|panic!("explicit {name} required"));
    assert_eq!(value.len(),64,"exact SHA256 hex required for {name}");
    assert!(value.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)),"lowercase SHA256 required");value
}
fn hash_value(v:&serde_json::Value)->Hash {hex::decode(v.as_str().expect("public hex hash")).unwrap().try_into().unwrap()}
fn read(path:&Path,cap:usize)->Vec<u8> {
    let meta=std::fs::symlink_metadata(path).unwrap();assert!(meta.is_file()&&!meta.file_type().is_symlink());
    assert!(meta.len()<=cap as u64);let bytes=std::fs::read(path).unwrap();assert!(bytes.len()<=cap);bytes
}
fn snapshot(path:&Path)->BTreeMap<PathBuf,(u64,String)> {
    fn visit(root:&Path,path:&Path,out:&mut BTreeMap<PathBuf,(u64,String)>,total:&mut u64,entries:&mut usize,depth:usize) {
        assert!(depth<=8,"bounded closed TEST directory depth");
        for row in std::fs::read_dir(path).unwrap() {
            *entries=entries.checked_add(1).unwrap();assert!(*entries<=512,"bounded closed TEST directory entries");
            let item=row.unwrap();let p=item.path();let meta=std::fs::symlink_metadata(&p).unwrap();
            assert!(!meta.file_type().is_symlink(),"closed TEST input must contain no symbolic link");
            if meta.is_dir(){visit(root,&p,out,total,entries,depth+1);}else {
                assert!(meta.is_file());*total=total.checked_add(meta.len()).unwrap();
                assert!(*total<=512*1024*1024,"bounded closed TEST input tree");
                assert!(out.len()<256,"bounded closed TEST file count");
                out.insert(p.strip_prefix(root).unwrap().to_path_buf(),(meta.len(),hash_file(&p)));
            }
        }
    }
    let mut out=BTreeMap::new();visit(path,path,&mut out,&mut 0,&mut 0,0);out
}
pub struct ClosedInput {
    pub public:PathBuf,pub state:PathBuf,pub verified:VerifiedGenesisV2,
    pub expected_anchor:FinalizedAnchor,pub expected_root:Hash,pub payment:Hash,
    before_public:BTreeMap<PathBuf,(u64,String)>,before_state:BTreeMap<PathBuf,(u64,String)>,
    pub chain_sha:String,pub pins_sha:String,pub result_sha:String,
}
impl ClosedInput {
    pub fn load()->Self {
        let absolute=|name:&str| {
            let path=PathBuf::from(std::env::var_os(name).unwrap_or_else(||panic!("explicit {name} required")));
            assert!(path.is_absolute(),"absolute closed TEST input required");
            let meta=std::fs::symlink_metadata(&path).unwrap();assert!(meta.is_dir()&&!meta.file_type().is_symlink());
            path.canonicalize().unwrap()
        };
        let public=absolute("FORGE_B07_CLOSED_PRODUCER_PUBLIC");let state=absolute("FORGE_B07_CLOSED_PRODUCER_STATE");
        assert_ne!(public,state);
        let pins_sha=env_digest("FORGE_B07_PINS_SHA256");let result_sha=env_digest("FORGE_B07_RESULT_SHA256");
        let chain_sha=env_digest("FORGE_B07_CHAIN_SHA256");
        let before_public=snapshot(&public);let before_state=snapshot(&state);
        assert_eq!(hash_file(&public.join("pins.json")),pins_sha);
        assert_eq!(hash_file(&public.join("result.json")),result_sha);
        assert_eq!(hash_file(&state.join("chain.sqlite")),chain_sha);
        for suffix in ["-journal","-wal","-shm"] {
            assert!(!state.join(format!("chain.sqlite{suffix}")).exists(),"producer DB must already be closed/checkpointed");
        }
        let pins:serde_json::Value=serde_json::from_slice(&read(&public.join("pins.json"),65536)).unwrap();
        let result:serde_json::Value=serde_json::from_slice(&read(&public.join("result.json"),65536)).unwrap();
        let closed:serde_json::Value=serde_json::from_slice(&read(&public.join("key-scope-ended.json"),4096)).unwrap();
        assert_eq!(pins["schema"],"FORGE-AUTOMATIC-PRODUCER-PUBLIC-TRUST-V1");
        assert_eq!(result["schema"],"FORGE-AUTOMATIC-TEST-PRODUCER-RESULT-V1");
        assert_eq!(pins["class"],"TEST-VALUE");assert_eq!(pins["production_eligible"],false);
        assert_eq!(pins["private_keys_persisted"],false);assert_eq!(result["private_keys_persisted"],false);
        assert_eq!(result["final_height"],101);assert_eq!(result["confirmed_height"],101);
        assert_eq!(result["blocks"],101);assert_eq!(result["maturity"],100);
        assert_eq!(result["saved_state_reopen_passed"],true);
        assert_eq!(closed["fixture_callback_returned"],true);assert_eq!(closed["ephemeral_key_owners_dropped"],true);
        assert_eq!(closed["private_keys_persisted"],false);assert_eq!(closed["endpoint_running"],false);
        assert_eq!(closed["worker_running"],false);
        assert_eq!(PathBuf::from(result["state_directory"].as_str().unwrap()).canonicalize().unwrap(),state);
        // Bind the retained artifact to this exact already reviewed producer
        // source, rather than trusting an arbitrary file's claimed origin.
        assert_eq!(pins["test_source_sha256"],hex::encode(Sha256::digest(include_bytes!("../forge_automatic_test_producer.rs"))));
        assert_eq!(pins["owner_source_sha256"],hex::encode(Sha256::digest(include_bytes!("../forge_automatic_test_producer/producer.rs"))));
        let artifact=read(&public.join("artifact.json"),4*1024*1024);
        let evidence=read(&public.join("public-evidence.cbor"),4*1024*1024);
        let rules=read(&public.join("approved-rules.cbor"),128*1024);
        assert_eq!(hash_value(&pins["artifact_sha256"]),<[u8;32]>::from(Sha256::digest(&artifact)));
        assert_eq!(hash_value(&pins["public_evidence_sha256"]),<[u8;32]>::from(Sha256::digest(&evidence)));
        assert_eq!(hash_value(&pins["approved_manifest_sha256"]),<[u8;32]>::from(Sha256::digest(&rules)));
        let trust=TrustV2 {artifact_sha256:hash_value(&pins["artifact_sha256"]),
            genesis_block_hash:hash_value(&pins["genesis_block_hash"]),
            approved:Approved {manifest:RuleManifest::decode(&rules).unwrap(),class:GenesisClass::TestValue,
                initial_target:hash_value(&pins["initial_target"])}};
        let verified=VerifiedGenesisV2::verify_with_public_evidence(&artifact,&trust,&evidence).unwrap();
        assert_eq!(verified.inputs.class(),GenesisClass::TestValue);
        assert_eq!(verified.genesis.identity,hash_value(&pins["genesis_id"]));
        assert_eq!(verified.genesis.fingerprint,hash_value(&pins["fingerprint"]));
        assert_eq!(verified.genesis.root,hash_value(&pins["h0_state_root"]));
        assert_eq!(verified.genesis.anchor().encode(),hex::decode(pins["h0_anchor"].as_str().unwrap()).unwrap());
        let expected_anchor=FinalizedAnchor::decode(&hex::decode(result["final_anchor"].as_str().unwrap()).unwrap()).unwrap();
        expected_anchor.validate_context(verified.genesis.identity,verified.genesis.fingerprint).unwrap();
        assert_eq!(expected_anchor.height,101);
        let expected_root=hash_value(&result["final_root"]);let payment=hash_value(&result["payment_id"]);
        Self {public,state,verified,expected_anchor,expected_root,payment,before_public,before_state,chain_sha,pins_sha,result_sha}
    }
    pub fn copy_chain(&self,to:&Path) {
        assert!(!to.exists());std::fs::copy(self.state.join("chain.sqlite"),to).unwrap();
        assert_eq!(hash_file(to),self.chain_sha);self.assert_unchanged();
    }
    pub fn assert_unchanged(&self) {
        assert_eq!(snapshot(&self.public),self.before_public,"original producer public inputs changed");
        assert_eq!(snapshot(&self.state),self.before_state,"original producer state changed");
    }
}
pub fn runtime(path:&Path,v:&VerifiedGenesisV2)->HybridRuntime {
    let chain=chain(path,v);
    let pool=Mempool::open(&path.join("pool.sqlite"),v.genesis.identity,v.genesis.fingerprint,MAX_PENDING_BYTES).unwrap();
    let timestamp=v.inputs.timestamp+101;
    HybridRuntime::from_pinned_chain_with_time_source(chain,pool,std::sync::Arc::new(move||timestamp)).unwrap()
}
pub fn chain(path:&Path,v:&VerifiedGenesisV2)->CanonicalStore {
    CanonicalStore::open_trusted_genesis(&path.join("chain.sqlite"),&v.genesis.anchor(),&v.genesis.state,
        v.genesis.root,v.inputs.timestamp,v.inputs.parameters.initial_target).unwrap()
}
pub fn public_file(path:&Path,value:&serde_json::Value) {
    let bytes=serde_json::to_vec_pretty(value).unwrap();let mut f=std::fs::OpenOptions::new().create_new(true).write(true).open(path).unwrap();
    f.write_all(&bytes).unwrap();f.sync_all().unwrap();
}
