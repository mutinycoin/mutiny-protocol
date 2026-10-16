//! Offline synthetic public-capacity measurement. No TPM, network or production
//! keys. Each temporary Continuity key is dropped after creating its test vote.
use mutiny_consensus_v8::{
    NETWORK_ID,
    anchors::FinalizedAnchor,
    certificates::Decision,
    continuity_v2::{Certificate, MAX_CERTIFICATE_BYTES, MAX_VOTERS, ParentVoter, Vote},
};
use mutiny_crypto_v2::{HybridKey, HybridSignature, Role};
use primitive_types::U256;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io::Write, time::Instant};
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 2, "One new public report path is required");
    let output = std::path::Path::new(&args[1]);
    assert!(!output.exists());
    let parent = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        height: 59,
        block: [3; 32],
    };
    let decision = Decision {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        purpose: 2,
        height: 60,
        mining_epoch: 59,
        continuity_period: 0,
        round: 4,
        step: 3,
        previous_finalized_anchor: parent.id(),
        parent: parent.block,
        block: [4; 32],
        state: [5; 32],
        membership: [6; 32],
        reputation: [7; 32],
        attestation: [8; 32],
    };
    let mut registry = BTreeMap::new();
    let mut votes = Vec::with_capacity(MAX_VOTERS);
    let start = Instant::now();
    for i in 1..=MAX_VOTERS {
        let mut node = [0; 32];
        node[24..].copy_from_slice(&(i as u64).to_be_bytes());
        // Deterministic software P-256 point is a conspicuous fixture, never
        // evidence of actual physical hardware or attestation.
        let tpm = p256::ecdsa::SigningKey::from_bytes((&node).into())
            .unwrap()
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap();
        let key = HybridKey::generate(Role::Continuity).unwrap();
        let voter = ParentVoter {
            lineage: node,
            admitted: true,
            physical: true,
            eligible: true,
            revoked: false,
            hardware_generation: 1,
            key_generation: 1,
            tpm_public: tpm,
            profile: [10; 32],
            public: key.public().clone(),
            reputation: U256::one(),
        };
        let mut vote = Vote {
            decision: decision.clone(),
            nil: false,
            node,
            hardware_generation: 1,
            key_generation: 1,
            sequence: 2,
            tpm_identity: voter.tpm_identity(),
            profile: voter.profile,
            signature: HybridSignature {
                ed448: [0; 114],
                fndsa: [0; 1280],
            },
        };
        vote.sign(&key).unwrap();
        votes.push(vote);
        registry.insert(node, voter);
        if i % 128 == 0 {
            eprintln!("Public synthetic capacity fixture: {i}/{MAX_VOTERS}");
        }
    }
    let setup_ms = start.elapsed().as_millis();
    let cert = Certificate {
        decision: decision.clone(),
        votes,
    };
    let raw = cert.encode().unwrap();
    assert!(raw.len() <= MAX_CERTIFICATE_BYTES);
    let timer = Instant::now();
    let decoded = Certificate::decode(&raw).unwrap();
    let decode_ms = timer.elapsed().as_millis();
    assert_eq!(decoded, cert);
    let timer = Instant::now();
    decoded
        .verify_quorum(&decision, &parent, &registry)
        .unwrap();
    let verify_full_ms = timer.elapsed().as_millis();
    let minimum = Certificate {
        decision: decision.clone(),
        votes: cert.votes[..683].to_vec(),
    };
    let timer = Instant::now();
    minimum
        .verify_quorum(&decision, &parent, &registry)
        .unwrap();
    let verify_minimum_ms = timer.elapsed().as_millis();
    let insufficient = Certificate {
        decision: decision.clone(),
        votes: cert.votes[..682].to_vec(),
    };
    assert_eq!(
        insufficient
            .verify_quorum(&decision, &parent, &registry)
            .unwrap_err(),
        mutiny_consensus_v8::Error::NoQuorum
    );
    let mut corrupted = cert.clone();
    corrupted.votes.last_mut().unwrap().signature.fndsa[700] ^= 1;
    assert!(
        corrupted
            .verify_quorum(&decision, &parent, &registry)
            .is_err()
    );
    let report = serde_json::json!({"schema":"BUILD8-HYBRID-CONTINUITY-CAPACITY-PROBE-V2",
        "result":"PASS","synthetic_only":true,"physical_attestation_qualified":false,"production_qualified":false,
        "signers":MAX_VOTERS,"full_certificate_bytes":raw.len(),"minimum_quorum_signers":683,
        "minimum_quorum_bytes":minimum.encode().unwrap().len(),"insufficient_signers_rejected":682,
        "certificate_sha256":hex::encode(Sha256::digest(&raw)),"certificate_limit":MAX_CERTIFICATE_BYTES,
        "setup_ms":setup_ms,"decode_full_ms":decode_ms,"verify_full_ms":verify_full_ms,
        "verify_minimum_ms":verify_minimum_ms,"elapsed_ms":start.elapsed().as_millis(),
        "timing_scope":"One local optimized host run; not a real-time deadline guarantee, not a side-channel result",
        "private_material_exported":false,"tpm_commands":0,"genesis_sealed":false});
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .unwrap();
    file.write_all(serde_json::to_string_pretty(&report).unwrap().as_bytes())
        .unwrap();
    file.write_all(b"\n").unwrap();
    file.sync_all().unwrap();
    println!("{}", serde_json::to_string(&report).unwrap());
}
