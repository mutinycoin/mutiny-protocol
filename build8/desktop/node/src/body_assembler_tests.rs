use super::*;
use mutiny_consensus_v8::{
    anchors::FinalizedAnchor,
    block_envelope::BlockEnvelope,
    blocks::{GenesisDescriptor, state_root},
    mempool::MAX_PENDING_BYTES,
};
struct Fixture;
impl PhysicalAttestationVerifier for Fixture {
    fn verify(
        &self,
        _: &PhysicalMember,
        challenge: Hash,
        evidence: &[u8],
    ) -> mutiny_consensus_v8::Result<()> {
        if challenge == evidence {
            Ok(())
        } else {
            Err(mutiny_consensus_v8::Error::BadSignature)
        }
    }
}
#[test]
fn durable_inputs_order_independence_invalid_rejection_and_canonical_retirement() {
    let mut rows = include_str!("../../qualification/integration-state-v2-1/chain.jsonl").lines();
    let initial: serde_json::Value = serde_json::from_str(rows.next().unwrap()).unwrap();
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let descriptor = GenesisDescriptor::decode(&raw(&initial["descriptor"])).unwrap();
    let records: Vec<(Hash, Vec<u8>)> = initial["initial_records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (raw(&r[0]).try_into().unwrap(), raw(&r[1])))
        .collect();
    let state = State::from_records(&records, state_root(&records).unwrap()).unwrap();
    let row: serde_json::Value = serde_json::from_str(rows.next().unwrap()).unwrap();
    let block = BlockEnvelope::decode(&raw(&row["envelope"])).unwrap();
    let binding = state.licenses.workers[&block.header.candidate.worker]
        .binding
        .clone();
    let member = &state.continuity.as_ref().unwrap().members[0];
    let physical_map = || {
        BTreeMap::from([(
            member.node,
            PhysicalMember {
                node: member.node,
                generation: member.generation,
                continuity_key: member.voting_key,
                hardware: member.hardware,
                admission_commitment: member.attestation,
                attestation_key: vec![6; 33],
            },
        )])
    };
    let mut salt = [0; 8];
    getrandom::getrandom(&mut salt).unwrap();
    let dir = std::env::temp_dir().join(format!("build8-body-{}", hex::encode(salt)));
    std::fs::create_dir(&dir).unwrap();
    let chain_path = dir.join("chain.sqlite");
    let mut chain = CanonicalStore::open_trusted_genesis(
        &chain_path,
        &descriptor,
        &state,
        block.header.candidate.target,
    )
    .unwrap();
    let make = |name: &str| Assembler {
        transactions: Mempool::open(
            &chain_path,
            descriptor.id().unwrap(),
            descriptor.fingerprint,
            MAX_PENDING_BYTES,
        )
        .unwrap(),
        operations: OperationPool::open(
            &dir.join(name),
            descriptor.id().unwrap(),
            descriptor.fingerprint,
        )
        .unwrap(),
        physical: physical_map(),
        verifier: Fixture,
    };
    let mut a = make("operations-a.sqlite");
    let mut b = make("operations-b.sqlite");
    let timestamp = block.header.candidate.timestamp;
    let ack = block
        .body
        .operations
        .iter()
        .find(|r| operation_kind(r).unwrap() == 11)
        .unwrap()
        .clone();
    let mut invalid = ParticipationAck::decode(&ack).unwrap();
    invalid.signature[0] ^= 1;
    assert!(
        a.admit_operation(&mut chain, &binding, timestamp, &invalid.encode())
            .is_err()
    );
    assert!(a.operations.pending().unwrap().is_empty());
    a.admit_operation(&mut chain, &binding, timestamp, &ack)
        .unwrap();
    a.admit_operation(&mut chain, &binding, timestamp, &ack)
        .unwrap();
    assert_eq!(a.operations.pending().unwrap().len(), 1);
    assert_eq!(
        a.assemble(&mut chain, &binding, timestamp).unwrap(),
        block.body
    );
    let anchor = FinalizedAnchor {
        network: NETWORK_ID,
        genesis: descriptor.id().unwrap(),
        fingerprint: descriptor.fingerprint,
        height: 0,
        block: block.header.candidate.parent,
    };
    let mut refresh = AttestationRefresh {
        network: NETWORK_ID,
        genesis: anchor.genesis,
        fingerprint: anchor.fingerprint,
        node: member.node,
        generation: member.generation,
        height: 1,
        parent_anchor: anchor.id(),
        evidence: vec![1],
    };
    refresh.evidence = refresh.challenge().to_vec();
    let refresh = refresh.encode().unwrap();
    a.admit_operation(&mut chain, &binding, timestamp, &refresh)
        .unwrap();
    b.admit_operation(&mut chain, &binding, timestamp, &refresh)
        .unwrap();
    b.admit_operation(&mut chain, &binding, timestamp, &ack)
        .unwrap();
    let planned = a.assemble(&mut chain, &binding, timestamp).unwrap();
    assert_eq!(
        planned,
        b.assemble(&mut chain, &binding, timestamp).unwrap()
    );
    assert_eq!(planned.operations.len(), 2);
    assert_eq!(
        operation_kind(planned.operations.last().unwrap()).unwrap(),
        11
    );
    drop(a);
    let mut a = make("operations-a.sqlite");
    assert_eq!(
        a.assemble(&mut chain, &binding, timestamp).unwrap(),
        planned
    );
    assert!(
        OperationPool::open(
            &dir.join("operations-a.sqlite"),
            [99; 32],
            descriptor.fingerprint
        )
        .is_err()
    );
    assert!(
        chain
            .commit_integrated(&block, &physical_map(), &Fixture)
            .unwrap()
    );
    a.operations.reconcile(&mut chain).unwrap();
    assert!(a.operations.pending().unwrap().is_empty());
    assert!(
        a.admit_operation(&mut chain, &binding, timestamp + 60, &ack)
            .is_err()
    );
    assert_eq!(chain.load().unwrap().0.height, 1); // Planning never committed anything.
    drop(a);
    drop(b);
    drop(chain);
    // Generated files only; no recursive cleanup or external state access.
    for name in ["chain.sqlite", "operations-a.sqlite", "operations-b.sqlite"] {
        let p = dir.join(name);
        std::fs::remove_file(p).unwrap();
    }
    std::fs::remove_dir(dir).unwrap();
}
