//! Isolated software-key chain fixture. Never requests contradictory TPM votes.
use ed25519_dalek::{Signer, SigningKey as EdKey};
use mutiny_consensus_v8::{
    anchors::FinalizedAnchor,
    blocks::*,
    canonical_store::CanonicalStore,
    certificates::{Certificate, Decision, Signer as CertSigner},
    equivocation::Evidence,
    execution::*,
    pow::*,
    recovery::{Anchor, ContinuityState, Member},
    reputation::History,
    votes::Vote,
    *,
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use std::collections::BTreeMap;
struct RejectAttestation;
impl freshness::PhysicalAttestationVerifier for RejectAttestation {
    fn verify(&self, _: &freshness::PhysicalMember, _: Hash, _: &[u8]) -> Result<()> {
        Err(Error::UnqualifiedPhysical)
    }
}
impl recovery::PhysicalAdmissionVerifier for RejectAttestation {
    fn verify_replacement(&self, _: &recovery::Recovery) -> Result<()> {
        Err(Error::UnqualifiedPhysical)
    }
}
fn signature(key: &SigningKey, digest: Hash) -> [u8; 64] {
    let s: Signature = key.sign_prehash(&digest).unwrap();
    s.normalize_s().unwrap_or(s).to_bytes().into()
}
#[test]
fn historical_evidence_executes_atomically_survives_restart_and_cannot_restore_voting() {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/GENESIS-BINDING-VECTORS-STATE-V2.json"
    ))
    .unwrap();
    let descriptor = GenesisDescriptor::decode(
        &hex::decode(fixture["descriptor_hex"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let identity = genesis::GenesisIdentity::new(descriptor.clone()).unwrap();
    let g = identity.id();
    let fp = descriptor.fingerprint;
    let bindings: Vec<_> = fixture["cases"][0]["bindings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            licenses::BindWorker::decode(&hex::decode(b["binding_hex"].as_str().unwrap()).unwrap())
                .unwrap()
        })
        .collect();
    let key = SigningKey::from_bytes((&[17; 32]).into()).unwrap();
    let registry = ContinuityState::bootstrap(
        g,
        fp,
        Anchor {
            height: 0,
            tip: [0; 32],
            state_root: [0; 32],
            registry_root: [0; 32],
        },
        descriptor.recovery,
        vec![Member {
            lineage: [4; 32],
            node: [5; 32],
            hardware: [6; 32],
            generation: 0,
            voting_key: key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
            attestation: [7; 32],
            history: History::default(),
            physical: true,
            eligible: true,
            genesis_member: true,
        }],
    )
    .unwrap();
    let mut initial = State {
        licenses: identity.bind_workers(&bindings).unwrap(),
        continuity: Some(registry),
        ..Default::default()
    };
    initial.accounting.freshness.insert(
        [5; 32],
        freshness::FreshnessRecord {
            node: [5; 32],
            generation: 0,
            key: key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap(),
            committed_height: 0,
            evidence_commitment: [8; 32],
        },
    );
    let path =
        std::env::temp_dir().join(format!("build8-equivocation-{}.sqlite", std::process::id()));
    assert!(!path.exists());
    let mut chain =
        CanonicalStore::open_trusted_genesis(&path, &descriptor, &initial, [255; 32]).unwrap();
    let coordinator = EdKey::from_bytes(&[90; 32]);
    let mut evidence = None;
    let mut last = None;
    for height in 1..=2 {
        let (parent, state) = chain.execution_parent(height - 1).unwrap();
        let anchor = FinalizedAnchor {
            network: NETWORK_ID,
            genesis: g,
            fingerprint: fp,
            height: height - 1,
            block: parent.block,
        };
        let body = BlockBody {
            height,
            reward_owner: descriptor.owner,
            fees: 0,
            transactions: vec![],
            operations: evidence
                .as_ref()
                .map(|e: &Evidence| vec![e.encode().unwrap()])
                .unwrap_or_default(),
        };
        let history = chain.evidence_history(&body).unwrap();
        let mut candidate = Candidate {
            network: NETWORK_ID,
            genesis: g,
            fingerprint: fp,
            parent: parent.block,
            height,
            timestamp: descriptor.timestamp + height * 60,
            body_root: body.root().unwrap(),
            state_root: [0; 32],
            license: bindings[0].license,
            worker: bindings[0].worker,
            target: parent.target,
        };
        let before = state.root().unwrap();
        if height == 2 {
            assert_eq!(history.len(), 1);
            assert!(
                state
                    .prepare_candidate(
                        CandidatePreparation {
                            parent: &parent,
                            candidate: &candidate,
                            ticket_sequence: height,
                            body: &body
                        },
                        &BTreeMap::new(),
                        &RejectAttestation
                    )
                    .is_err()
            ); // No peer-supplied authority fallback.
        }
        let prepared = state
            .prepare_candidate_with_history(
                CandidatePreparation {
                    parent: &parent,
                    candidate: &candidate,
                    ticket_sequence: height,
                    body: &body,
                },
                &BTreeMap::new(),
                &RejectAttestation,
                &history,
            )
            .unwrap();
        assert_eq!(state.root().unwrap(), before);
        candidate.state_root = prepared.root;
        let authority = WorkAuthority {
            candidate: candidate.clone(),
            assignment_sequence: 1,
            ticket_sequence: height,
            coordinator: coordinator.verifying_key().to_bytes(),
            nonce_start: 0,
            nonce_end: u64::MAX,
            epoch: height,
        };
        let authority_signature = coordinator.sign(&authority.id()).to_bytes();
        let header = WorkHeader {
            candidate,
            authority: authority.id(),
            nonce: 0,
        };
        assert!(meets_target(&header.digest(), &parent.target));
        let registry = state.continuity.as_ref().unwrap();
        let (membership, reputation, attestation) = registry.roots().unwrap();
        let decision = Decision {
            network: NETWORK_ID,
            genesis: g,
            fingerprint: fp,
            purpose: 2,
            height,
            mining_epoch: height,
            continuity_period: 0,
            round: 0,
            step: 3,
            previous_finalized_anchor: anchor.id(),
            parent: parent.block,
            block: header.block_hash(),
            state: prepared.root,
            membership,
            reputation,
            attestation,
        };
        let sig = signature(&key, decision.signing_digest([5; 32], 0));
        let block = block_envelope::BlockEnvelope {
            header,
            body,
            authority,
            authority_signature,
            certificate: Certificate {
                decision: decision.clone(),
                signers: vec![CertSigner {
                    node: [5; 32],
                    key_version: 0,
                    signature: sig,
                }],
            },
        };
        if height == 1 {
            let a = Vote {
                nil: false,
                decision: decision.clone(),
                node: [5; 32],
                key_version: 0,
                signature: sig,
            };
            let mut b = a.clone();
            b.decision.block = [88; 32];
            b.signature = signature(&key, b.signing_digest());
            evidence = Some(Evidence::new(a, b).unwrap());
        } else {
            let mut invalid = block.clone();
            invalid.certificate.signers[0].signature[0] ^= 1;
            let head = chain.load().unwrap().0;
            assert!(
                chain
                    .commit_integrated(&invalid, &BTreeMap::new(), &RejectAttestation)
                    .is_err()
            );
            assert_eq!(chain.load().unwrap().0, head);
            assert_eq!(
                chain
                    .equivocation_status(evidence.as_ref().unwrap().id())
                    .unwrap(),
                Some(canonical_store::evidence_pool::EvidenceStatus::Pending)
            );
            assert!(!prepared.state.continuity.as_ref().unwrap().members[0].eligible);
            assert!(!registry.voters().unwrap()[&[5; 32]].weight.is_zero()); // Parent certifies revocation.
        }
        assert!(
            chain
                .commit_integrated(&block, &BTreeMap::new(), &RejectAttestation)
                .unwrap()
        );
        let proof = evidence.as_ref().unwrap();
        use canonical_store::evidence_pool::EvidenceStatus;
        if height == 1 {
            let mut bad = proof.clone();
            bad.a.signature[0] ^= 1;
            assert!(chain.admit_equivocation(&bad, 8192).is_err());
            assert!(matches!(
                chain.admit_equivocation(proof, 1),
                Err(canonical_store::ChainError::EvidenceCapacity)
            ));
            assert!(chain.pending_equivocations(8192).unwrap().is_empty());
            assert_eq!(
                chain.admit_equivocation(proof, 8192).unwrap(),
                EvidenceStatus::Pending
            );
            assert_eq!(
                chain.admit_equivocation(proof, 0).unwrap(),
                EvidenceStatus::Pending
            );
            assert!(chain.admit_equivocation(&bad, 8192).is_err());
            assert_eq!(
                chain.pending_equivocations(8192).unwrap(),
                vec![proof.encode().unwrap()]
            );
            drop(chain);
            chain = CanonicalStore::open_trusted_genesis(&path, &descriptor, &initial, [255; 32])
                .unwrap();
            assert_eq!(
                chain.equivocation_status(proof.id()).unwrap(),
                Some(EvidenceStatus::Pending)
            );
        } else {
            assert_eq!(
                chain.equivocation_status(proof.id()).unwrap(),
                Some(EvidenceStatus::Included)
            );
            assert!(chain.pending_equivocations(8192).unwrap().is_empty());
        }
        last = Some(block);
    }
    let (head, state) = chain.load().unwrap();
    assert_eq!(head.height, 2);
    assert!(state.penalties.revoked([4; 32]));
    assert!(state.continuity.as_ref().unwrap().weights().unwrap()[0].is_zero());
    assert_eq!(
        State::from_records(&state.records().unwrap(), state.root().unwrap()).unwrap(),
        state
    );
    let mut resurrection = state.clone();
    resurrection.continuity.as_mut().unwrap().members[0].eligible = true;
    assert!(resurrection.root().is_err());
    if let Ok(destination) = std::env::var("BUILD8_EQUIVOCATION_FIXTURE_OUTPUT") {
        use std::io::Write;
        let bundle = serde_json::json!({"actual_genesis":false,"physical_evidence_fixture_only":true,
            "descriptor":hex::encode(descriptor.encode().unwrap()),"initial_target":hex::encode([255u8;32]),
            "initial_records":initial.records().unwrap().iter().map(|(k,v)|[hex::encode(k),hex::encode(v)]).collect::<Vec<_>>()});
        let output = serde_json::json!({"schema":"BUILD8-EQUIVOCATION-PROCESS-FIXTURE-V1","bundle":bundle,
            "blocks":[hex::encode(chain.block_bytes(1).unwrap().unwrap()),hex::encode(chain.block_bytes(2).unwrap().unwrap())],
            "evidence":hex::encode(evidence.as_ref().unwrap().encode().unwrap()),"evidence_id":hex::encode(evidence.as_ref().unwrap().id()),
            "final_state_root":hex::encode(head.root),"software_keys_only":true,"actual_genesis":false});
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)
            .unwrap();
        file.write_all(serde_json::to_string_pretty(&output).unwrap().as_bytes())
            .unwrap();
        file.sync_all().unwrap();
    }
    drop(chain);
    let mut restarted =
        CanonicalStore::open_trusted_genesis(&path, &descriptor, &initial, [255; 32]).unwrap();
    assert_eq!(restarted.load().unwrap().0, head);
    assert_eq!(restarted.load().unwrap().1.penalties, state.penalties);
    assert!(
        !restarted
            .commit_integrated(&last.unwrap(), &BTreeMap::new(), &RejectAttestation)
            .unwrap()
    );
    assert_eq!(restarted.load().unwrap().0, head);
    let archive = path.with_extension("checkpoint");
    let imported = path.with_extension("restored.sqlite");
    let report = restarted.export_checkpoint(&archive, 1024 * 1024).unwrap();
    let empty = BTreeMap::new();
    let restore = |source: &std::path::Path, destination: &std::path::Path| {
        canonical_store::checkpoint::restore_checkpoint(
            canonical_store::checkpoint::CheckpointRestore {
                archive: source,
                database: destination,
                descriptor: &descriptor,
                initial: &initial,
                initial_target: [255; 32],
                physical: &empty,
                attestation: &RejectAttestation,
                legacy_recovery: &RejectAttestation,
                byte_budget: 1024 * 1024,
            },
        )
    };
    let (mut copied, copy_report) = restore(&archive, &imported).unwrap();
    assert_eq!(report, copy_report);
    assert_eq!(
        copied.load().unwrap().1.records().unwrap(),
        restarted.load().unwrap().1.records().unwrap()
    );
    assert!(copied.load().unwrap().1.penalties.revoked([4; 32]));
    drop(copied);
    let mut bytes = std::fs::read(&archive).unwrap();
    let header_len = u32::from_be_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let offset = bytes[12..12 + header_len]
        .windows(32)
        .position(|b| b == head.root)
        .unwrap()
        + 12;
    bytes[offset] ^= 1; // Forge the checkpoint claim and recompute its untrusted file checksum.
    use sha2::{Digest, Sha256};
    let end = bytes.len() - 32;
    let digest = Sha256::digest(&bytes[..end]);
    bytes[end..].copy_from_slice(&digest);
    let corrupt = path.with_extension("corrupt.checkpoint");
    let quarantine = path.with_extension("quarantine.sqlite");
    std::fs::write(&corrupt, &bytes).unwrap();
    assert!(restore(&corrupt, &quarantine).is_err());
    assert!(
        CanonicalStore::open_trusted_genesis(&quarantine, &descriptor, &initial, [255; 32])
            .is_err()
    );
    let partial = path.with_extension("partial.checkpoint");
    assert!(restarted.export_checkpoint(&partial, 64).is_err());
    assert_eq!(restarted.load().unwrap().0, head);
    drop(restarted);
    for p in [&archive, &imported, &corrupt, &quarantine, &partial] {
        std::fs::remove_file(p).unwrap();
    }
    let mut marker = quarantine.as_os_str().to_os_string();
    marker.push(".checkpoint-import");
    std::fs::remove_file(std::path::PathBuf::from(marker)).unwrap();
    std::fs::remove_file(path).unwrap();
}
