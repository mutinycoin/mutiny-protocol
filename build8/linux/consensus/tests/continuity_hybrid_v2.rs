use mutiny_consensus_v8::{continuity_v2::*,certificates::Decision,anchors::FinalizedAnchor,Error,NETWORK_ID};
use mutiny_crypto_v2::{HybridKey,HybridSignature,Role};
use primitive_types::U256;
use std::collections::BTreeMap;
fn parent()->FinalizedAnchor{FinalizedAnchor{network:NETWORK_ID,genesis:[1;32],fingerprint:[2;32],height:59,block:[3;32]}}
fn decision()->Decision {
    Decision{network:NETWORK_ID,genesis:[1;32],fingerprint:[2;32],purpose:2,height:60,mining_epoch:59,continuity_period:0,round:4,step:3,
        previous_finalized_anchor:parent().id(),parent:[3;32],block:[4;32],state:[5;32],membership:[6;32],reputation:[7;32],attestation:[8;32]}
}
fn voter(n:u8,key:&HybridKey)->ParentVoter {
    let tpm=p256::ecdsa::SigningKey::from_bytes((&[n;32]).into()).unwrap().verifying_key().to_encoded_point(true).as_bytes().try_into().unwrap();
    ParentVoter{lineage:[n;32],admitted:true,physical:true,eligible:true,revoked:false,hardware_generation:1,key_generation:1,tpm_public:tpm,profile:[n;32],public:key.public().clone(),reputation:U256::from(1)}
}
fn vote(n:u8,v:&ParentVoter,key:&HybridKey)->Vote {
    let mut v=Vote{decision:decision(),nil:false,node:[n;32],hardware_generation:1,key_generation:1,sequence:10,
        tpm_identity:v.tpm_identity(),profile:v.profile,signature:HybridSignature{ed448:[0;114],fndsa:[0;1280]}};v.sign(key).unwrap();v
}
#[test]
fn physical_parent_weight_dual_signatures_bind_hardware_generation_and_full_context() {
    let keys:Vec<_>=(0..4).map(|_|HybridKey::generate(Role::Continuity).unwrap()).collect();
    let registry:BTreeMap<_,_>=keys.iter().enumerate().map(|(i,k)|([(i+1)as u8;32],voter((i+1)as u8,k))).collect();
    let votes:Vec<_>=keys.iter().enumerate().map(|(i,k)|vote((i+1)as u8,&registry[&[(i+1)as u8;32]],k)).collect();
    let cert=Certificate{decision:decision(),votes:votes[..3].to_vec()};cert.verify_quorum(&decision(),&parent(),&registry).unwrap();
    assert_eq!(Certificate::decode(&cert.encode().unwrap()).unwrap(),cert);
    assert_eq!(Vote::decode(&votes[0].encode().unwrap()).unwrap(),votes[0]);
    assert_eq!(Certificate{decision:decision(),votes:votes[..2].to_vec()}.verify_quorum(&decision(),&parent(),&registry).unwrap_err(),Error::NoQuorum);
    for field in 0..12 {
        let mut v=votes[0].clone();match field{
            0=>v.signature.ed448[0]^=1,1=>v.signature.fndsa[500]^=1,2=>v.tpm_identity[0]^=1,
            3=>v.hardware_generation+=1,4=>v.key_generation+=1,5=>v.node=[9;32],6=>v.decision.genesis[0]^=1,
            7=>v.decision.parent[0]^=1,8=>v.decision.mining_epoch+=1,9=>v.sequence+=1,10=>v.profile[0]^=1,_=>v.decision.fingerprint[0]^=1,
        }assert!(v.verify(&parent(),[[6;32],[7;32],[8;32]],&registry).is_err(),"field {field}");
    }
    for state in 0..4 {
        let mut r=registry.clone();let v=r.get_mut(&[1;32]).unwrap();match state{0=>v.physical=false,1=>v.admitted=false,2=>v.revoked=true,_=>v.eligible=false}
        v.reputation=U256::from(1_000_000); // software keys/nominal reputation cannot override ineligibility
        assert_eq!(v.weight().unwrap(),U256::zero());
        assert!(votes[0].verify(&parent(),[[6;32],[7;32],[8;32]],&r).is_err());
    }
    let mut duplicated=registry.clone();duplicated.get_mut(&[2;32]).unwrap().public=keys[0].public().clone();assert_eq!(cert.verify_quorum(&decision(),&parent(),&duplicated).unwrap_err(),Error::Duplicate);
    let mut duplicated=registry.clone();duplicated.get_mut(&[2;32]).unwrap().lineage=[1;32];assert_eq!(cert.verify_quorum(&decision(),&parent(),&duplicated).unwrap_err(),Error::Duplicate);
    let mut duplicates=cert.clone();duplicates.votes[1]=duplicates.votes[0].clone();assert_eq!(duplicates.encode().unwrap_err(),Error::Duplicate);
    // The caller's committed parent weights, not candidate post-state reputation, decide quorum.
    let mut changed=registry.clone();changed.get_mut(&[4;32]).unwrap().reputation=U256::from(100);
    assert_eq!(cert.verify_quorum(&decision(),&parent(),&changed).unwrap_err(),Error::NoQuorum);
    let mut nil=votes[0].clone();nil.nil=true;nil.decision.block=[0;32];nil.decision.state=[0;32];nil.decision.mining_epoch=0;nil.sign(&keys[0]).unwrap();
    nil.verify(&parent(),[[6;32],[7;32],[8;32]],&registry).unwrap();
    assert!(Certificate{decision:nil.decision.clone(),votes:vec![nil]}.encode().is_err());
}
#[test]
fn maximum_certificate_serialization_is_bounded_without_claiming_fake_signatures_valid() {
    let mut votes=Vec::new();
    for i in 1u32..=1024 {let mut node=[0;32];node[28..].copy_from_slice(&i.to_be_bytes());
        votes.push(Vote{decision:decision(),nil:false,node,hardware_generation:u64::MAX,key_generation:u64::MAX,sequence:u64::MAX,tpm_identity:[9;32],profile:[10;32],signature:HybridSignature{ed448:[0;114],fndsa:[0;1280]}});}
    let cert=Certificate{decision:decision(),votes};let raw=cert.encode().unwrap();assert!(raw.len()<=MAX_CERTIFICATE_BYTES);
    assert!(raw.len()>256*1024);assert_eq!(Certificate::decode(&raw).unwrap(),cert);
    let quorum=Certificate{decision:decision(),votes:cert.votes[..683].to_vec()}.encode().unwrap();
    let report=serde_json::json!({"schema":"BUILD8-HYBRID-CERTIFICATE-CAPACITY-V1","synthetic_size_fixture_only":true,"signatures_valid":false,
        "voters_1024_bytes":raw.len(),"signers_683_bytes":quorum.len(),"candidate_bound":MAX_CERTIFICATE_BYTES,
        "old_bound":256*1024,"runtime_bound_changed":false});
    if std::env::var("BUILD8_EXPORT_PUBLIC_CAPACITY").as_deref() == Ok("1") {
        std::fs::write(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../qualification/continuity-hybrid-capacity-v1.json"),serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
}
