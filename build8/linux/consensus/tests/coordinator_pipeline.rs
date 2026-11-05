//! Exact previously mined qualification chain, through durable coordinator
//! preparation and result recovery. All signing keys here are public fixtures.
use ed25519_dalek::SigningKey as EdKey;
use mutiny_consensus_v8::{
    anchors::FinalizedAnchor,
    block_envelope::BlockEnvelope,
    blocks::*,
    canonical_store::CanonicalStore,
    certificates::{Certificate, Signer},
    coordinator::*,
    execution::State,
    freshness::{PhysicalAttestationVerifier, PhysicalMember},
    liveness::WorkGate,
    votes::HeightAuthority,
    *,
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use std::collections::BTreeMap;
struct Fixture;
impl PhysicalAttestationVerifier for Fixture {
    fn verify(&self, _: &PhysicalMember, challenge: Hash, raw: &[u8]) -> Result<()> {
        if raw == challenge {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }
}
#[test]
fn executed_candidate_durable_ticket_worker_result_receipt_and_finality_restart() {
    let mut rows = include_str!("../../qualification/integration-state-v2-1/chain.jsonl").lines();
    let initial: serde_json::Value = serde_json::from_str(rows.next().unwrap()).unwrap();
    let descriptor =
        GenesisDescriptor::decode(&hex::decode(initial["descriptor"].as_str().unwrap()).unwrap())
            .unwrap();
    let records: Vec<(Hash, Vec<u8>)> = initial["initial_records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                hex::decode(r[0].as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap(),
                hex::decode(r[1].as_str().unwrap()).unwrap(),
            )
        })
        .collect();
    let state = State::from_records(&records, state_root(&records).unwrap()).unwrap();
    let physical: BTreeMap<_, _> = state
        .continuity
        .as_ref()
        .unwrap()
        .members
        .iter()
        .map(|m| {
            (
                m.node,
                PhysicalMember {
                    node: m.node,
                    generation: m.generation,
                    continuity_key: m.voting_key,
                    hardware: m.hardware,
                    admission_commitment: m.attestation,
                    attestation_key: vec![6; 33],
                },
            )
        })
        .collect();
    let genesis = descriptor.id().unwrap();
    let fingerprint = descriptor.fingerprint;
    let target = hex::decode("00000350e94ccd16c4d5661eafcd07f2f220b12f07c24ab8f8b90a0f2c131b43")
        .unwrap()
        .try_into()
        .unwrap();
    let mut salt = [0; 8];
    getrandom::getrandom(&mut salt).unwrap();
    let root = std::env::temp_dir().join(format!("build8-coordinator-chain-{}", hex::encode(salt)));
    std::fs::create_dir(&root).unwrap();
    let chain_path = root.join("chain.sqlite");
    let work_path = root.join("work.sqlite");
    let observation_path = root.join("observation.sqlite");
    let mut chain =
        CanonicalStore::open_trusted_genesis(&chain_path, &descriptor, &state, target).unwrap();
    let open = || {
        Coordinator::open(
            &work_path,
            &observation_path,
            genesis,
            fingerprint,
            EdKey::from_bytes(&[90; 32]),
        )
        .unwrap()
    };
    let mut coordinator = open();
    let mut first = None;
    let mut sequence = 0;
    let mut observation_chain = [0; 32];
    for row in rows {
        let row: serde_json::Value = serde_json::from_str(row).unwrap();
        let block = BlockEnvelope::decode(&hex::decode(row["envelope"].as_str().unwrap()).unwrap())
            .unwrap();
        let (tip, state) = chain.load_effective().unwrap();
        let registry = state.continuity.as_ref().unwrap();
        let (membership, reputation, attestation) = registry.roots().unwrap();
        let authority = HeightAuthority {
            parent: FinalizedAnchor {
                network: NETWORK_ID,
                genesis,
                fingerprint,
                height: tip.height,
                block: tip.block,
            },
            membership,
            reputation,
            attestation,
            voters: registry.voters().unwrap(),
        };
        let mut gate = WorkGate::new(authority, state.root().unwrap(), 0).unwrap();
        gate.set_run(true);
        let decision = gate.request(0, [55; 32]).unwrap().unwrap();
        let key = SigningKey::from_bytes((&[17; 32]).into()).unwrap();
        let member = &registry.members[0];
        let signature: Signature = key
            .sign_prehash(&decision.signing_digest(member.node, member.generation))
            .unwrap();
        gate.accept(
            1,
            &Certificate {
                decision,
                signers: vec![Signer {
                    node: member.node,
                    key_version: member.generation,
                    signature: signature
                        .normalize_s()
                        .unwrap_or(signature)
                        .to_bytes()
                        .into(),
                }],
            },
        )
        .unwrap();
        let c = &block.header.candidate;
        let (issued, ttl) = coordinator
            .issue(
                &mut chain,
                &mut gate,
                MiningRequest {
                    worker: c.worker,
                    license: c.license,
                    body: block.body.clone(),
                    timestamp: c.timestamp,
                    now_ms: 2,
                    unix_ms: c.timestamp * 1000,
                    observation_sequence: sequence,
                    observation_chain,
                },
                &physical,
                &Fixture,
                // Explicit software fixture decision clock, never a host qualification.
                || Ok((2, c.timestamp * 1000)),
            )
            .unwrap();
        assert_eq!(ttl, 60000);
        assert_eq!(issued.authority, block.authority);
        assert_eq!(issued.signature, block.authority_signature);
        assert!(!issued.offer([42; 32], ttl).unwrap().is_empty());
        let submission = observations::Submission {
            sequence: sequence + 1,
            previous: observation_chain,
            work: block.header.work_bytes(),
        };
        // Crash after sending authority but before receiving the found nonce.
        drop(coordinator);
        coordinator = open();
        assert!(coordinator.result([99; 32], &submission.encode()).is_err());
        let mut invalid = block.header.clone();
        invalid.nonce = invalid.nonce.wrapping_add(1);
        if !pow::meets_target(&invalid.digest(), &c.target) {
            assert!(
                coordinator
                    .result(
                        c.worker,
                        &observations::Submission {
                            work: invalid.work_bytes(),
                            ..submission.clone()
                        }
                        .encode()
                    )
                    .is_err()
            );
        }
        let observed = coordinator.result(c.worker, &submission.encode()).unwrap();
        assert_eq!(observed.header, block.header);
        assert_eq!(observed.issued.as_ref().unwrap().body, block.body);
        assert_eq!(chain.load().unwrap().0.height, tip.height); // Receipt is not finality.
        assert!(
            chain
                .commit_integrated(&block, &physical, &Fixture)
                .unwrap()
        );
        assert_eq!(coordinator.total(c.worker).unwrap(), c.height);
        assert_eq!(
            coordinator
                .result(c.worker, &submission.encode())
                .unwrap()
                .receipt,
            observed.receipt
        );
        sequence = observed.receipt.sequence;
        observation_chain = observed.receipt.chain;
        if first.is_none() {
            first = Some((c.worker, submission.encode(), observed.receipt));
        }
    }
    drop(coordinator);
    let mut coordinator = open();
    let (worker, bytes, receipt) = first.unwrap();
    // An acknowledged old sequence cannot increment totals after pruning.
    let _ = receipt;
    assert!(coordinator.result(worker, &bytes).is_err());
    assert_eq!(coordinator.total(worker).unwrap(), 180);
    drop(coordinator);
    drop(chain);
    let db = rusqlite::Connection::open(&work_path).unwrap();
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM issued_work", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM work_tickets", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        1
    );
    drop(db);
    let db = rusqlite::Connection::open(&observation_path).unwrap();
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM observation_checkpoint", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        1
    );
    drop(db);
    for name in ["chain.sqlite", "work.sqlite", "observation.sqlite"] {
        for suffix in ["", "-wal", "-shm"] {
            let p = root.join(format!("{name}{suffix}"));
            if p.exists() {
                std::fs::remove_file(p).unwrap();
            }
        }
    }
    std::fs::remove_dir(root).unwrap();
}
