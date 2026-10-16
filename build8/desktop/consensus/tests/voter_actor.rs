use mutiny_consensus_v8::{
    bft::Step,
    block_envelope::BlockEnvelope,
    blocks::{GenesisDescriptor, state_root},
    canonical_store::CanonicalStore,
    counter_store::MonotonicCounter,
    counter_voter::CounterSigningBackend,
    execution::State,
    freshness::{PhysicalAttestationVerifier, PhysicalMember},
    voter_actor::VoterActor,
    *,
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use std::collections::BTreeMap;
struct Backend {
    key: SigningKey,
    counter: u64,
}
impl MonotonicCounter for Backend {
    fn read(&mut self) -> std::result::Result<u64, String> {
        Ok(self.counter)
    }
    fn increment(&mut self) -> std::result::Result<(), String> {
        self.counter += 1;
        Ok(())
    }
}
impl CounterSigningBackend for Backend {
    fn public_key(&self) -> [u8; 33] {
        self.key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap()
    }
    fn sign_digest(&mut self, d: Hash) -> std::result::Result<[u8; 64], String> {
        let s: Signature = self.key.sign_prehash(&d).unwrap();
        Ok(s.normalize_s().unwrap_or(s).to_bytes().into())
    }
}
struct Evidence;
impl PhysicalAttestationVerifier for Evidence {
    fn verify(&self, _: &PhysicalMember, c: Hash, e: &[u8]) -> Result<()> {
        if c == e {
            Ok(())
        } else {
            Err(Error::BadSignature)
        }
    }
}
fn raw(v: &serde_json::Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}
#[test]
fn certified_commit_restart_reconciles_voter_without_repeated_signing() {
    let mut lines = include_str!("../../qualification/integration-state-v2-1/chain.jsonl").lines();
    let bundle: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
    assert_eq!(bundle["physical_evidence_fixture_only"], true);
    let descriptor = GenesisDescriptor::decode(&raw(&bundle["descriptor"])).unwrap();
    let records: Vec<(Hash, Vec<u8>)> = bundle["initial_records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (raw(&r[0]).try_into().unwrap(), raw(&r[1])))
        .collect();
    let initial = State::from_records(&records, state_root(&records).unwrap()).unwrap();
    let physical: BTreeMap<_, _> = initial
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
    let target = raw(&bundle["initial_target"]).try_into().unwrap();
    let node = *physical.keys().next().unwrap();
    let dir = std::env::temp_dir().join(format!("build8-voter-actor-{}", std::process::id()));
    std::fs::create_dir(&dir).unwrap();
    let chain_path = dir.join("chain.sqlite");
    let voter_path = dir.join("voter.sqlite");
    let open = || {
        CanonicalStore::open_trusted_genesis(&chain_path, &descriptor, &initial, target).unwrap()
    };
    let mut chain = open();
    let mut backend = Backend {
        key: SigningKey::from_bytes((&[17; 32]).into()).unwrap(),
        counter: 1000,
    };
    let mut actor = VoterActor::open(
        &voter_path,
        node,
        Some(1000),
        &mut chain,
        &mut backend,
        &physical,
        &Evidence,
    )
    .unwrap();
    // Existing behavior test: not about time. Dedicated coverage: tests/vote_timestamp_guard_v1.rs.
    actor.set_vote_clock(mutiny_consensus_v8::vote_clock_v1::ControlledClock::at(u64::MAX));
    // Snapshot of the chain alone must never resurrect an older signing height.
    let old_chain = dir.join("old-chain.sqlite");
    std::fs::copy(&chain_path, &old_chain).unwrap();
    let blocks: Vec<_> = lines
        .take(61)
        .map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).unwrap();
            BlockEnvelope::decode(&raw(&v["envelope"])).unwrap()
        })
        .collect();
    actor
        .validate_proposal(&mut chain, &blocks[0], &physical, &Evidence)
        .unwrap();
    let prevote = actor
        .sign(
            &mut chain,
            Step::Prevote,
            Some(blocks[0].block_hash()),
            None,
            &mut backend,
        )
        .unwrap();
    actor.observe(&prevote).unwrap();
    let precommit = actor
        .sign(
            &mut chain,
            Step::Precommit,
            Some(blocks[0].block_hash()),
            None,
            &mut backend,
        )
        .unwrap();
    actor.observe(&precommit).unwrap();
    chain
        .commit_integrated(&blocks[0], &physical, &Evidence)
        .unwrap();
    // Crash after canonical commit, before TPM voter advance.
    drop(actor);
    drop(chain);
    chain = open();
    actor = VoterActor::open(
        &voter_path,
        node,
        None,
        &mut chain,
        &mut backend,
        &physical,
        &Evidence,
    )
    .unwrap();
    assert_eq!(actor.height(), 2);
    assert_eq!(backend.counter, 1005);
    drop(actor);
    // An offline voter can catch up from revalidated canonical evidence, including
    // the bootstrap-weight/reputation boundary. It emits no retrospective votes.
    for block in blocks.iter().skip(1) {
        chain
            .commit_integrated(block, &physical, &Evidence)
            .unwrap();
    }
    actor = VoterActor::open(
        &voter_path,
        node,
        None,
        &mut chain,
        &mut backend,
        &physical,
        &Evidence,
    )
    .unwrap();
    assert_eq!(actor.height(), 62);
    assert_eq!(backend.counter, 1065);
    drop(actor);
    let saved = backend.counter;
    actor = VoterActor::open(
        &voter_path,
        node,
        None,
        &mut chain,
        &mut backend,
        &physical,
        &Evidence,
    )
    .unwrap();
    assert_eq!(backend.counter, saved);
    assert_eq!(
        actor.timeout_precommit(&mut chain, &mut backend).unwrap(),
        None
    );
    let nil = actor
        .sign(&mut chain, Step::Prevote, None, None, &mut backend)
        .unwrap();
    actor.observe(&nil).unwrap();
    let nil = actor
        .sign(&mut chain, Step::Precommit, None, None, &mut backend)
        .unwrap();
    actor.observe(&nil).unwrap();
    assert_eq!(
        actor.timeout_precommit(&mut chain, &mut backend).unwrap(),
        None
    );
    let counter = backend.counter;
    std::thread::sleep(std::time::Duration::from_secs(2));
    assert_eq!(
        actor
            .sign(&mut chain, Step::Precommit, None, None, &mut backend)
            .unwrap(),
        nil
    );
    assert_eq!(backend.counter, counter);
    std::thread::sleep(std::time::Duration::from_millis(1050));
    assert_eq!(
        actor.timeout_precommit(&mut chain, &mut backend).unwrap(),
        Some(1)
    );
    assert_eq!(backend.counter, counter + 1);
    let next = actor
        .sign(&mut chain, Step::Prevote, None, None, &mut backend)
        .unwrap();
    assert_eq!(next.decision.round, 1);
    let saved = backend.counter;
    drop(actor);
    drop(chain);
    std::fs::copy(&old_chain, &chain_path).unwrap();
    chain = open();
    assert!(
        VoterActor::open(
            &voter_path,
            node,
            None,
            &mut chain,
            &mut backend,
            &physical,
            &Evidence
        )
        .is_err()
    );
    assert_eq!(backend.counter, saved);
    drop(chain);
    std::fs::remove_dir_all(dir).unwrap();
}
