use super::*;
use crate::candidate_journal::CandidateJournal;
use ed25519_dalek::SigningKey;
use mutiny_consensus_v8::{
    block_envelope::BlockEnvelope,
    blocks::{GenesisDescriptor, state_root},
    certificates::Signer,
    execution::State,
    observations::Submission,
};
use p256::ecdsa::{Signature, SigningKey as TpmFixture, signature::hazmat::PrehashSigner};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
pub(super) struct Fixture;
pub(super) struct SoftwareCounter {
    pub(super) key: TpmFixture,
    pub(super) counter: u64,
}
impl mutiny_consensus_v8::counter_store::MonotonicCounter for SoftwareCounter {
    fn read(&mut self) -> Result<u64> {
        Ok(self.counter)
    }
    fn increment(&mut self) -> Result<()> {
        self.counter = self.counter.checked_add(1).unwrap();
        Ok(())
    }
}
impl mutiny_consensus_v8::counter_voter::CounterSigningBackend for SoftwareCounter {
    fn public_key(&self) -> [u8; 33] {
        self.key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap()
    }
    fn sign_digest(&mut self, digest: Hash) -> Result<[u8; 64]> {
        let signature: Signature = self.key.sign_prehash(&digest).unwrap();
        Ok(signature
            .normalize_s()
            .unwrap_or(signature)
            .to_bytes()
            .into())
    }
}
impl crate::participation_producer::ParticipationSigner for SoftwareCounter {
    fn public_key(&self) -> [u8; 33] {
        mutiny_consensus_v8::counter_voter::CounterSigningBackend::public_key(self)
    }
    fn acknowledgement(
        &mut self,
        ack: &mutiny_consensus_v8::participation::ParticipationAck,
    ) -> Result<[u8; 64]> {
        mutiny_consensus_v8::counter_voter::CounterSigningBackend::sign_digest(
            self,
            ack.signing_digest(),
        )
    }
    fn refresh_quote(
        &mut self,
        refresh: &mutiny_consensus_v8::freshness::AttestationRefresh,
    ) -> Result<Vec<u8>> {
        Ok(refresh.challenge().to_vec())
    }
}
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
struct Hooks {
    block: BlockEnvelope,
    builder: crate::body_assembler::Assembler<Fixture>,
    journal: CandidateJournal,
    unavailable: Arc<AtomicBool>,
}
impl CandidateHooks for Hooks {
    fn body(
        &mut self,
        chain: &mut CanonicalStore,
        binding: &BindWorker,
        timestamp: u64,
    ) -> Result<BlockBody> {
        self.builder.assemble(chain, binding, timestamp)
    }
    fn preserve<V: PhysicalAttestationVerifier>(
        &mut self,
        chain: &mut CanonicalStore,
        result: &ObservedWork,
        physical: &BTreeMap<Hash, PhysicalMember>,
        verifier: &V,
    ) -> Result<()> {
        if self.unavailable.load(Ordering::Acquire) {
            return Err("fixture disk unavailable".into());
        }
        assert_eq!(chain.load().unwrap().0.height, 0); // A receipt never commits a block.
        assert_eq!(result.header, self.block.header);
        assert_eq!(result.issued.as_ref().unwrap().body, self.block.body);
        self.journal.preserve(chain, result, physical, verifier)
    }
}
#[test]
fn canonical_adapter_quorum_gate_and_receipt_waits_for_durable_candidate() {
    pipeline(false);
}
#[test]
fn driver_replays_cached_vote_and_automatically_precommits_and_finalizes() {
    pipeline(true);
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum DriverTime {
    /// Existing behaviour test: an always-eligible controlled clock.
    Standard,
    /// Controlled qualified clock 5 s BEHIND the proposal; it becomes eligible while the proposal
    /// is still current, and the real driver/custody path must then sign and finalize it.
    EligibleLater,
    /// Same clock, but the round timeout fires first: the driver must still abstain-by-nil.
    TimeoutFirst,
    /// D3: pairwise skew of U_a + U_b = 2 s (1 s maximum uncertainty each) with this node's clock
    /// BEHIND the proposal. It must wait without a fault and then finalize WITHOUT any nil vote.
    SkewWithinBudget,
    /// D3: a long blackout stalled this height. The qualified clock is now more than 2 h past the
    /// candidate's timestamp, so the candidate is far older than the old 7,200 s window. It must be
    /// admitted, voted and finalized: there is no wall-clock limit on the past side.
    AfterBlackout,
}
#[test]
fn driver_finalizes_without_nil_when_clock_skew_is_within_the_pairwise_budget() {
    fresh_driver(DriverTime::SkewWithinBudget);
}
#[test]
fn driver_admits_and_finalizes_a_candidate_older_than_two_hours_after_a_blackout() {
    fresh_driver(DriverTime::AfterBlackout);
}
#[test]
fn round_delay_is_unchanged_and_leaves_headroom_over_the_pairwise_skew_budget() {
    use crate::voter_driver::{BASE_ROUND_DELAY_SECS, round_delay};
    let secs = |r| round_delay(r).as_secs();
    // Production nil-timeout semantics, exactly as before D3: 3 s * 2^round, capped at 120 s.
    assert_eq!(
        [secs(0), secs(1), secs(2), secs(3), secs(4), secs(5), secs(6), secs(7), secs(1000)],
        [3, 6, 12, 24, 48, 96, 120, 120, 120]
    );
    // D1: maximum uncertainty to vote is 1 s, so honest nodes can differ by 2 s; the first-round
    // delay (the tightest) must exceed that, leaving 1 s of headroom.
    let skew = 2 * 1;
    assert_eq!(BASE_ROUND_DELAY_SECS, 3);
    assert_eq!(secs(0) - skew, 1);
}
#[test]
fn signed_round_proposal_drives_fresh_prevoting_through_finality() {
    fresh_driver(DriverTime::Standard);
}
#[test]
fn driver_defers_future_proposal_then_signs_and_finalizes_when_time_becomes_eligible() {
    fresh_driver(DriverTime::EligibleLater);
}
#[test]
fn driver_keeps_timeout_nil_behavior_while_the_proposal_is_ahead_of_the_clock() {
    fresh_driver(DriverTime::TimeoutFirst);
}
// Real socket latency remains a separately named release campaign with the
// unchanged transport deadlines. The ordinary driver test models authenticated
// frame delivery deterministically so canonical execution speed cannot masquerade
// as a BFT/coordinator state defect.
#[cfg(not(debug_assertions))]
#[test]
fn coordinator_release_socket_latency_preserves_five_second_deadlines() {
    fresh_driver_inner(DriverTime::Standard, true);
}
fn fresh_driver(mode: DriverTime) { fresh_driver_inner(mode, false); }
fn fresh_driver_inner(mode: DriverTime, live_worker_socket: bool) {
    use mutiny_consensus_v8::{
        membership::NodeControl,
        pow::{WorkHeader, meets_target, sha256d},
    };
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
    let mut state = State::from_records(&records, state_root(&records).unwrap()).unwrap();
    let first: serde_json::Value = serde_json::from_str(rows.next().unwrap()).unwrap();
    let original = BlockEnvelope::decode(&raw(&first["envelope"])).unwrap();
    let member = state.continuity.as_ref().unwrap().members[0].clone();
    let authentication = SigningKey::from_bytes(&[91; 32]);
    state.membership.controls.insert(
        member.node,
        NodeControl {
            node: member.node,
            generation: member.generation,
            owner: SigningKey::from_bytes(&[80; 32]).verifying_key().to_bytes(),
            node_authentication: authentication.verifying_key().to_bytes(),
            sequence: 0,
            exit_boundary: None,
            admitted_height: 0,
            admission_boundary: None,
            hardware_since_height: 0,
        },
    );
    let physical = BTreeMap::from([(
        member.node,
        PhysicalMember {
            node: member.node,
            generation: member.generation,
            continuity_key: member.voting_key,
            hardware: member.hardware,
            admission_commitment: member.attestation,
            attestation_key: vec![6; 33],
        },
    )]);
    let mut salt = [0; 8];
    getrandom::getrandom(&mut salt).unwrap();
    let dir = std::env::temp_dir().join(format!("build8-fresh-driver-{}", hex::encode(salt)));
    std::fs::create_dir(&dir).unwrap();
    let chain_path = dir.join("chain.sqlite");
    let mut chain = CanonicalStore::open_trusted_genesis(
        &chain_path,
        &descriptor,
        &state,
        original.header.candidate.target,
    )
    .unwrap();
    let (parent, _) = chain.execution_parent(0).unwrap();
    let mut gate = WorkGate::new(
        voter_actor::authority(&parent, &state).unwrap(),
        state.root().unwrap(),
        0,
    )
    .unwrap();
    gate.set_run(true);
    let decision = gate.request(0, [42; 32]).unwrap().unwrap();
    let tpm_key = TpmFixture::from_bytes((&[17; 32]).into()).unwrap();
    let signature: Signature = tpm_key
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
    let c = &original.header.candidate;
    let binding = &state.licenses.workers[&c.worker].binding;
    let mut builder = crate::body_assembler::Assembler {
        transactions: mutiny_consensus_v8::mempool::Mempool::open(
            &chain_path,
            descriptor.id().unwrap(),
            descriptor.fingerprint,
            mutiny_consensus_v8::mempool::MAX_PENDING_BYTES,
        )
        .unwrap(),
        operations: crate::operation_pool::OperationPool::open(
            &dir.join("operations.sqlite"),
            descriptor.id().unwrap(),
            descriptor.fingerprint,
        )
        .unwrap(),
        physical: BTreeMap::new(),
        verifier: Fixture,
    };
    let body = builder.assemble(&mut chain, binding, c.timestamp).unwrap();
    let mut coordinator = Coordinator::open(
        &dir.join("work.sqlite"),
        &dir.join("observations.sqlite"),
        descriptor.id().unwrap(),
        descriptor.fingerprint,
        SigningKey::from_bytes(&[90; 32]),
    )
    .unwrap();
    let (issued, _) = coordinator
        .issue(
            &mut chain,
            &mut gate,
            MiningRequest {
                worker: c.worker,
                license: c.license,
                body,
                timestamp: c.timestamp,
                now_ms: 2,
                unix_ms: c.timestamp * 1000,
                observation_sequence: 0,
                observation_chain: [0; 32],
            },
            &physical,
            &Fixture,
            // Explicit software fixture decision clock, never a host qualification.
            || Ok((2, c.timestamp * 1000)),
        )
        .unwrap();
    let mut header = WorkHeader {
        candidate: issued.authority.candidate.clone(),
        authority: issued.authority.id(),
        nonce: issued.authority.nonce_start,
    };
    let mut work = header.work_bytes();
    let offset = header.nonce_offset();
    let mut found = false;
    // Same measured-fleet target. This host test searches a bounded nonce range;
    // it is neither a miner throughput measurement nor actual Genesis mining.
    for nonce in 0..100_000_000u64 {
        assert!(nonce <= issued.authority.nonce_end);
        work[offset..].copy_from_slice(&nonce.to_be_bytes());
        if meets_target(&sha256d(&work), &header.candidate.target) {
            header.nonce = nonce;
            found = true;
            break;
        }
    }
    assert!(found, "software qualification nonce bound exhausted");
    let candidate = crate::candidate_journal::CandidateRecord {
        header: header.clone(),
        body: issued.body,
        authority: issued.authority,
        signature: issued.signature,
    };
    let mut journal = CandidateJournal::open(
        &dir.join("candidates.sqlite"),
        descriptor.id().unwrap(),
        descriptor.fingerprint,
        100_000,
    )
    .unwrap();
    journal
        .accept(&mut chain, &candidate, &physical, &Fixture)
        .unwrap();
    let mut backend = SoftwareCounter {
        key: tpm_key,
        counter: 4000,
    };
    let mut voter = voter_actor::VoterActor::open(
        &dir.join("voter.sqlite"),
        member.node,
        Some(4000),
        &mut chain,
        &mut backend,
        &physical,
        &Fixture,
    )
    .unwrap();
    // Standard: not about time (an always-eligible controlled clock; the default is fail-closed).
    let planned_clock = match mode {
        DriverTime::Standard => u64::MAX,
        DriverTime::SkewWithinBudget => c.timestamp - 2,
        DriverTime::AfterBlackout => c.timestamp + 3 * 3600,
        _ => c.timestamp - 5,
    };
    let clock = mutiny_consensus_v8::vote_clock_v1::ControlledClock::at(planned_clock);
    voter.set_vote_clock(clock.clone());
    let mut received = crate::vote_journal::VoteJournal::open(
        &dir.join("received.sqlite"),
        descriptor.id().unwrap(),
        descriptor.fingerprint,
    )
    .unwrap();
    let proposer_path = dir.join("proposer.sqlite");
    let mut local = crate::local_proposer::LocalProposer::open(
        &proposer_path,
        member.node,
        authentication.clone(),
        descriptor.id().unwrap(),
        descriptor.fingerprint,
    )
    .unwrap();
    // The proposer only offers candidates it could itself vote for now, so the proposal is made
    // while the controlled clock is eligible (it is restored below, before any driver tick). A
    // persisted proposal is later returned unchanged whatever the clock says.
    clock.set(u64::MAX);
    let proposal = local
        .propose(
            &mut chain,
            &voter,
            &mut journal,
            &received,
            &physical,
            &Fixture,
        )
        .unwrap()
        .unwrap();
    assert_eq!(proposal.block, header.block_hash());
    drop(local);
    assert!(
        crate::local_proposer::LocalProposer::open(
            &proposer_path,
            member.node,
            SigningKey::from_bytes(&[92; 32]),
            descriptor.id().unwrap(),
            descriptor.fingerprint
        )
        .is_err()
    );
    let mut local = crate::local_proposer::LocalProposer::open(
        &proposer_path,
        member.node,
        authentication,
        descriptor.id().unwrap(),
        descriptor.fingerprint,
    )
    .unwrap();
    assert_eq!(
        local
            .propose(
                &mut chain,
                &voter,
                &mut journal,
                &received,
                &physical,
                &Fixture
            )
            .unwrap()
            .unwrap(),
        proposal
    );
    clock.set(planned_clock);
    let mut driver = crate::voter_driver::Driver::default();
    // The signature is private to `round_proposal` (sealed construction), so its first byte is
    // corrupted through the wire encoding: the signature is the last 64 bytes of the envelope.
    let invalid = {
        let mut wire = proposal.encode();
        let first = wire.len() - 64;
        wire[first] ^= 1;
        crate::round_proposal::RoundProposal::decode(&wire).unwrap()
    };
    assert!(
        driver
            .tick(
                &mut chain,
                &mut voter,
                &mut backend,
                &journal,
                &mut received,
                Some(&invalid),
                &physical,
                &Fixture
            )
            .is_err()
    );
    assert_eq!(backend.counter, 4000);
    // Start the public winning candidate on a nonvoting peer. The voting
    // actor receives it through authenticated gossip before autonomous BFT.
    let remote_chain = CanonicalStore::open_trusted_genesis(
        &dir.join("remote.sqlite"),
        &descriptor,
        &state,
        raw(&initial["initial_target"]).try_into().unwrap(),
    )
    .unwrap();
    let remote_builder = crate::body_assembler::Assembler {
        transactions: mutiny_consensus_v8::mempool::Mempool::open(
            &dir.join("remote.sqlite"),
            descriptor.id().unwrap(),
            descriptor.fingerprint,
            mutiny_consensus_v8::mempool::MAX_PENDING_BYTES,
        )
        .unwrap(),
        operations: crate::operation_pool::OperationPool::open(
            &dir.join("remote-operations.sqlite"),
            descriptor.id().unwrap(),
            descriptor.fingerprint,
        )
        .unwrap(),
        physical: BTreeMap::new(),
        verifier: Fixture,
    };
    let remote_physical = BTreeMap::from([(
        member.node,
        PhysicalMember {
            node: member.node,
            generation: member.generation,
            continuity_key: member.voting_key,
            hardware: member.hardware,
            admission_commitment: member.attestation,
            attestation_key: vec![6; 33],
        },
    )]);
    let remote_coordinator = Coordinator::open(
        &dir.join("remote-work.sqlite"),
        &dir.join("remote-observations.sqlite"),
        descriptor.id().unwrap(),
        descriptor.fingerprint,
        SigningKey::from_bytes(&[90; 32]),
    )
    .unwrap();
    let remote_workers = WorkerCoordinator::new(
        remote_chain,
        remote_coordinator,
        SigningKey::from_bytes(&[90; 32]).verifying_key().to_bytes(),
        remote_physical,
        Fixture,
        JournaledCandidates {
            journal,
            builder: remote_builder,
        },
        // The remote actor issues work on top of the synchronized height-1 block, so its
        // controlled time is later than that block's timestamp (it was the host clock before).
        mutiny_consensus_v8::holdover_clock_v1::FixedBasis::at_ms((c.timestamp + 600) * 1000),
    );
    let remote_votes = crate::vote_journal::VoteJournal::open(
        &dir.join("remote-votes.sqlite"),
        descriptor.id().unwrap(),
        descriptor.fingerprint,
    )
    .unwrap();
    let remote_actor = Arc::new(std::sync::Mutex::new(
        crate::integrated_actor::IntegratedActor::<_, _, SoftwareCounter>::new(
            remote_workers,
            remote_votes,
            None,
        )
        .unwrap(),
    ));
    let journal = CandidateJournal::open(
        &dir.join("incoming-candidates.sqlite"),
        descriptor.id().unwrap(),
        descriptor.fingerprint,
        100_000,
    )
    .unwrap();
    let basis = mutiny_consensus_v8::holdover_clock_v1::FixedBasis::at_ms(c.timestamp * 1000);
    let workers = WorkerCoordinator::new(
        chain,
        coordinator,
        SigningKey::from_bytes(&[90; 32]).verifying_key().to_bytes(),
        physical,
        Fixture,
        JournaledCandidates { journal, builder },
        basis,
    );
    let mut integrated = crate::integrated_actor::IntegratedActor::new(
        workers,
        received,
        Some(crate::integrated_actor::SigningState {
            voter,
            backend,
            proposer: Some(local),
            participation: Some(
                crate::participation_producer::Producer::open(
                    &dir.join("participation.sqlite"),
                    descriptor.id().unwrap(),
                    descriptor.fingerprint,
                    member.node,
                )
                .unwrap(),
            ),
        }),
    )
    .unwrap();
    let driver_time = Arc::new(std::sync::Mutex::new(Instant::now()));
    struct SharedActorTimer(Arc<std::sync::Mutex<Instant>>);
    impl voter_actor::MonotonicTimer for SharedActorTimer {
        fn now(&self) -> Instant {
            *self.0.lock().unwrap()
        }
    }
    integrated
        .signing
        .as_mut()
        .unwrap()
        .voter
        .set_monotonic_timer(Arc::new(SharedActorTimer(driver_time.clone())))
        .unwrap();
    integrated.set_driver_time_for_test(driver_time.clone());
    let advance_driver = |ms| {
        let mut instant = driver_time.lock().unwrap();
        *instant += std::time::Duration::from_millis(ms);
    };
    let shared = Arc::new(std::sync::Mutex::new(integrated));
    let remote_key = SigningKey::from_bytes(&[93; 32]);
    let pull_key = SigningKey::from_bytes(&[94; 32]);
    let remote_public = remote_key.verifying_key().to_bytes();
    let remote_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let remote_address = remote_listener.local_addr().unwrap();
    let remote_server = crate::peer_server::PeerServer::start(
        remote_listener,
        remote_key,
        &[pull_key.verifying_key().to_bytes()],
        remote_actor.clone(),
        2,
    )
    .unwrap();
    let supervisor = crate::peer_supervisor::PeerSupervisor::start(
        pull_key,
        vec![crate::peer_supervisor::PeerTarget {
            address: remote_address,
            public: remote_public,
        }],
        shared.clone(),
    )
    .unwrap();
    let deadline = Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if supervisor.progress().unwrap()[0].1.completed_exchanges > 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "peer exchange did not complete: {:?}",
            supervisor.progress().unwrap()
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert_eq!(
        shared
            .lock()
            .unwrap()
            .workers
            .hooks
            .journal
            .records()
            .unwrap()
            .len(),
        1
    );
    supervisor.stop().unwrap();
    remote_server.stop().unwrap();
    if mode != DriverTime::Standard {
        use mutiny_consensus_v8::vote_clock_v1::TimeStatus;
        let timestamp = c.timestamp;
        let counter = |a: &crate::integrated_actor::IntegratedActor<_, _, SoftwareCounter>| {
            a.signing.as_ref().unwrap().backend.counter
        };
        let mut guard = shared.lock().unwrap();
        assert_eq!(counter(&guard), 4000);
        // 2. (Run first so that no slow verification sits inside the 3 s round window that the
        //    driver's ordinary nil timeout is measured against.) Stale or altered context is
        //    rejected, never voted, and costs nothing.
        let mut stale_parent = proposal.clone();
        stale_parent.parent.block[0] ^= 1;
        let mut stale_round = proposal.clone();
        stale_round.round += 1;
        let mut other_block = proposal.clone();
        other_block.block[0] ^= 1;
        let mut other_membership = proposal.clone();
        other_membership.proposer[0] ^= 1;
        for bad in [stale_parent, stale_round, other_block, other_membership] {
            assert!(guard.round_proposal(bad).is_err());
        }
        assert_eq!(counter(&guard), 4000);
        // Expensive verification/signing does not advance the injected monotonic
        // clock. Advance exactly the production round timer when testing timeout;
        // keep qualified UTC eligibility independently controlled by `clock`.
        // Monotonic time remains fixed through expensive validation/signature work.
        // Production 3-second round delay remains in force.
        if mode == DriverTime::AfterBlackout {
            // D3: the clock is more than two hours PAST the candidate. It was admitted by the
            // journal and gossip above with no wall-clock filter; nothing is deferred, the same
            // still-current proposal is signed through the driver and finalized, with no nil vote.
            let done = guard.tick(None).unwrap();
            assert_eq!(done.proposal.as_ref(), Some(&proposal));
            let done = done.consensus;
            assert!(done.time_deferred.is_none());
            assert_eq!(done.publish.len(), 2);
            assert_eq!(done.publish[0].decision.step, 2);
            assert_eq!(done.publish[1].decision.step, 3);
            assert!(done.publish.iter().all(|v| !v.nil));
            assert_eq!(done.finalized, Some(header.block_hash()));
            assert_eq!(counter(&guard), 4005);
            assert_eq!(guard.signing.as_ref().unwrap().voter.height(), 2);
            assert_eq!(guard.workers.chain.load().unwrap().0.height, 1);
            drop(guard);
            drop(shared);
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }
        let ahead: u64 = if mode == DriverTime::SkewWithinBudget { 2 } else { 5 };
        // 1. The proposal is current, validated and ahead of the qualified clock by `ahead` s: the
        //    driver withholds the vote without a fault, a signature or a counter write.
        let first = guard.tick(None).unwrap();
        assert_eq!(first.proposal.as_ref(), Some(&proposal));
        assert_eq!(
            first.consensus.time_deferred,
            Some(TimeStatus::Future { ahead_seconds: ahead })
        );
        assert!(first.consensus.publish.is_empty());
        assert_eq!(counter(&guard), 4000);
        assert_eq!(guard.signing.as_ref().unwrap().voter.height(), 1);
        if mode == DriverTime::TimeoutFirst {
            // The production 3-second propose deadline fires while qualified UTC
            // still defers the block. A NIL prevote costs exactly two counter writes.
            advance_driver(3000);
            let timeout = guard.tick(None).unwrap().consensus;
            assert_eq!(timeout.time_deferred, Some(TimeStatus::Future { ahead_seconds: ahead }));
            assert!(!timeout.publish.is_empty());
            assert_eq!(timeout.publish[0].decision.step, 2);
            assert!(timeout.publish.iter().all(|v| v.nil));
            assert_eq!(counter(&guard), 4000 + 2 * timeout.publish.len() as u64);
            let after_timeout = counter(&guard);
            // Time becoming eligible afterwards cannot revive a block vote in a slot that already
            // holds the durable nil decision: only that identical nil vote is retransmitted.
            clock.set(timestamp);
            let later = guard.tick(None).unwrap().consensus;
            assert!(later.publish.iter().all(|v| v.nil));
            assert!(later.finalized.is_none());
            // No BLOCK vote was created. Under heavy load the ordinary precommit delay may also
            // have elapsed, in which case exactly one further NIL precommit (counter +2) is the
            // only permitted extra decision; either way the counter never reflects a block vote.
            // The precommit timeout may also advance the round, which durably records the new
            // round (counter +1) without signing anything.
            let advanced = u64::from(later.advanced_round.is_some());
            let extra = counter(&guard) - after_timeout - advanced;
            assert!(
                extra == 0
                    || (extra == 2
                        && later
                            .publish
                            .iter()
                            .any(|v| v.nil && v.decision.step == 3)),
                "unexpected counter use {extra}"
            );
        } else {
            // 3b. Still deferred on the next tick, with no state change.
            let again = guard.tick(None).unwrap().consensus;
            assert_eq!(again.time_deferred, Some(TimeStatus::Future { ahead_seconds: ahead }));
            assert!(again.publish.is_empty());
            assert_eq!(counter(&guard), 4000);
            // 4. The qualified clock reaches the timestamp: the same still-current proposal
            //    reaches actual signing THROUGH THE DRIVER and is finalized.
            clock.set(timestamp);
            let done = guard.tick(None).unwrap().consensus;
            assert!(done.time_deferred.is_none());
            assert_eq!(done.publish.len(), 2);
            assert_eq!(done.publish[0].decision.step, 2);
            assert_eq!(done.publish[1].decision.step, 3);
            assert!(done.publish.iter().all(|v| !v.nil));
            assert_eq!(done.finalized, Some(header.block_hash()));
            assert_eq!(counter(&guard), 4005);
            assert_eq!(guard.signing.as_ref().unwrap().voter.height(), 2);
            assert_eq!(guard.workers.chain.load().unwrap().0.height, 1);
        }
        drop(guard);
        drop(shared);
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }
    let network = || crate::runtime_service::NetworkConfig {
        worker_bind: "127.0.0.1:0".parse().unwrap(),
        peer_bind: "127.0.0.1:0".parse().unwrap(),
        worker_connections: 2,
        peer_connections: 2,
        allowed_peers: vec![SigningKey::from_bytes(&[44; 32]).verifying_key().to_bytes()],
        outbound: vec![],
    };
    assert!(
        crate::runtime_service::RuntimeService::start(
            network(),
            SigningKey::from_bytes(&[89; 32]),
            SigningKey::from_bytes(&[43; 32]),
            shared.clone()
        )
        .is_err()
    );
    let reserved = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let available_address = reserved.local_addr().unwrap();
    drop(reserved);
    let mut unavailable = network();
    unavailable.worker_bind = available_address;
    unavailable.peer_bind = occupied.local_addr().unwrap();
    let counter_before = shared
        .lock()
        .unwrap()
        .signing
        .as_ref()
        .unwrap()
        .backend
        .counter;
    assert!(
        crate::runtime_service::RuntimeService::start(
            unavailable,
            SigningKey::from_bytes(&[90; 32]),
            SigningKey::from_bytes(&[43; 32]),
            shared.clone()
        )
        .is_err()
    );
    assert_eq!(
        shared
            .lock()
            .unwrap()
            .signing
            .as_ref()
            .unwrap()
            .backend
            .counter,
        counter_before
    );
    drop(std::net::TcpListener::bind(available_address).unwrap());
    drop(occupied);
    let service = crate::runtime_service::RuntimeService::start(
        network(),
        SigningKey::from_bytes(&[90; 32]),
        SigningKey::from_bytes(&[43; 32]),
        shared.clone(),
    )
    .unwrap();
    // This is a harness deadline, not a protocol round timer. Slow cloud CPUs
    // still execute exactly the same candidate and custody transitions.
    let until = std::time::Instant::now() + std::time::Duration::from_secs(90);
    let result = loop {
        if let Some(tick) = service.poll().unwrap() {
            break tick;
        }
        assert!(std::time::Instant::now() < until);
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    let worker_address = service.worker_address;
    let peer_address = service.peer_address;
    service.stop().unwrap();
    // Joined process shutdown releases both ports and all actor references.
    drop(std::net::TcpListener::bind(worker_address).unwrap());
    drop(std::net::TcpListener::bind(peer_address).unwrap());
    let mut integrated = Arc::try_unwrap(shared).ok().unwrap().into_inner().unwrap();
    assert_eq!(result.proposal, Some(proposal));
    let result = result.consensus;
    assert_eq!(result.publish.len(), 2);
    assert_eq!(result.publish[0].decision.step, 2);
    assert_eq!(result.publish[1].decision.step, 3);
    assert!(result.publish.iter().all(|v| !v.nil));
    assert_eq!(result.finalized, Some(header.block_hash()));
    assert_eq!(integrated.signing.as_ref().unwrap().voter.height(), 2);
    assert_eq!(integrated.signing.as_ref().unwrap().backend.counter, 4005);
    assert_eq!(integrated.workers.chain.load().unwrap().0.height, 1);
    // The same serialized owner now serves mining, proposer selection, durable
    // vote ingress, certificate construction and canonical publication.
    assert_eq!(integrated.active(c.worker).unwrap().worker, c.worker);
    let waiting = integrated.tick(None).unwrap();
    assert!(waiting.proposal.is_none());
    assert!(waiting.consensus.publish.is_empty());
    advance_driver(3100);
    let nil_prevote = integrated.tick(None).unwrap().consensus;
    assert_eq!(nil_prevote.publish.len(), 1);
    assert!(nil_prevote.publish[0].nil);
    assert_eq!(integrated.signing.as_ref().unwrap().backend.counter, 4007);
    advance_driver(3100);
    let nil_precommit = integrated.tick(None).unwrap().consensus;
    assert_eq!(nil_precommit.publish.len(), 2);
    assert!(nil_precommit.publish.iter().all(|v| v.nil));
    assert!(nil_precommit.advanced_round.is_none());
    assert_eq!(integrated.signing.as_ref().unwrap().backend.counter, 4009);
    let deadline = integrated
        .signing
        .as_ref()
        .unwrap()
        .voter
        .precommit_deadline()
        .unwrap()
        .2;
    assert_eq!(
        deadline.duration_since(*driver_time.lock().unwrap()),
        std::time::Duration::from_secs(3),
        "ordinary actor interval is unchanged, and cached replay does not extend it"
    );
    assert!(
        matches!(
            integrated
                .signing
                .as_mut()
                .unwrap()
                .voter
                .set_monotonic_timer(Arc::new(SharedActorTimer(driver_time.clone())),),
            Err(voter_actor::ActorError::Invalid(
                mutiny_consensus_v8::Error::Duplicate
            ))
        ),
        "an armed timer cannot be replaced to move its deadline"
    );
    advance_driver(2999);
    let before_deadline = integrated.tick(None).unwrap().consensus;
    assert!(
        before_deadline.advanced_round.is_none(),
        "actor cannot advance before its genuine deadline"
    );
    assert_eq!(integrated.signing.as_ref().unwrap().backend.counter, 4009);
    advance_driver(1);
    let advanced = integrated.tick(None).unwrap().consensus;
    assert_eq!(advanced.advanced_round, Some(1));
    assert!(advanced.finalized.is_none());
    assert_eq!(integrated.signing.as_ref().unwrap().backend.counter, 4010);
    assert_eq!(integrated.workers.chain.load().unwrap().0.height, 1);
    println!(
        "fresh driver fixture nonce={} block={}",
        header.nonce,
        hex::encode(header.block_hash())
    );
    // Deterministic authenticated frame dispatch and the separate release socket
    // counterpart both use the same actor mutex and canonical chain.
    use std::io::Write;
    let binding = integrated.active(c.worker).unwrap();
    assert_eq!(
        binding.worker_public,
        SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes()
    );
    let integrated = Arc::new(std::sync::Mutex::new(integrated));
    let (worker_server, stream) = if live_worker_socket {
        let worker_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let worker_addr = worker_listener.local_addr().unwrap();
        let worker_server = crate::worker_server::WorkerServer::start(
            worker_listener,
            SigningKey::from_bytes(&[90; 32]),
            integrated.clone(),
            2,
        )
        .unwrap();
        let (mut stream, mut channel) = crate::worker_transport::tests::connect(worker_addr, &binding);
        assert_eq!(
            crate::worker_transport::tests::receive(&mut stream, &mut channel),
            [1]
        );
        stream
            .write_all(
                &channel
                    .send(
                        &SigningKey::from_bytes(&[10; 32]),
                        &[2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
                    )
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(
            crate::worker_transport::tests::receive(&mut stream, &mut channel),
            [1]
        );
        (Some(worker_server), Some(stream))
    } else {
        use ed25519_dalek::{Signature, Signer as _, VerifyingKey};
        use mutiny_consensus_v8::worker_session::{
            FrameChannel, PendingSession, Role, worker_digest,
        };
        let coordinator_key = SigningKey::from_bytes(&[90; 32]);
        let worker_key = SigningKey::from_bytes(&[10; 32]);
        let mut pending = PendingSession::issue(&binding, &coordinator_key, [27; 32], [28; 32]).unwrap();
        let (transcript, challenge) = pending.challenge();
        VerifyingKey::from_bytes(&binding.coordinator_public)
            .unwrap()
            .verify_strict(
                &mutiny_consensus_v8::worker_session::coordinator_digest(transcript),
                &Signature::from_bytes(challenge),
            )
            .unwrap();
        let possession = worker_key.sign(&worker_digest(transcript)).to_bytes();
        let session = pending.finish(&binding, possession).unwrap();
        let mut coordinator_channel = FrameChannel::new(session.clone(), Role::Coordinator);
        let mut worker_channel = FrameChannel::new(session, Role::Worker);
        let heartbeat = coordinator_channel.send(&coordinator_key, &[1]).unwrap();
        assert_eq!(worker_channel.receive(&heartbeat).unwrap(), [1]);
        let request = worker_channel.send(&worker_key, &[2, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]).unwrap();
        let payload = coordinator_channel.receive(&request).unwrap().to_vec();
        let mut actor = integrated.lock().unwrap();
        let current = actor.active(c.worker).unwrap();
        assert_eq!(current, binding);
        assert!(coordinator_channel.authorizes(&current));
        let response = actor.handle(c.worker, crate::worker_protocol::decode(&payload).unwrap()).unwrap();
        assert_eq!(actor.active(c.worker).unwrap(), binding);
        assert!(coordinator_channel.authorizes(&binding));
        let wire = coordinator_channel.send(&coordinator_key, &response).unwrap();
        assert_eq!(worker_channel.receive(&wire).unwrap(), [1]);
        (None, None)
    };
    let peer_key = SigningKey::from_bytes(&[43; 32]);
    let client_key = SigningKey::from_bytes(&[44; 32]);
    let peer_public = peer_key.verifying_key().to_bytes();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer_server = crate::peer_server::PeerServer::start(
        listener,
        peer_key,
        &[client_key.verifying_key().to_bytes()],
        integrated.clone(),
        2,
    )
    .unwrap();
    let mut client = crate::peer_client::PeerClient::connect(
        address,
        client_key,
        peer_public,
        descriptor.id().unwrap(),
        descriptor.fingerprint,
    )
    .unwrap();
    assert_eq!(
        client.request("status", &serde_json::Map::new()).unwrap()["height"],
        1
    );
    assert!(
        client
            .request("cast_vote", &serde_json::Map::new())
            .is_err()
    );
    let votes = client
        .request(
            "get_votes",
            serde_json::json!({"height":2,"offset":0})
                .as_object()
                .unwrap(),
        )
        .unwrap();
    assert_eq!(votes["items"].as_array().unwrap().len(), 2);
    assert_eq!(
        integrated
            .lock()
            .unwrap()
            .signing
            .as_ref()
            .unwrap()
            .backend
            .counter,
        4010
    );
    // Only the physical voter initiates connections, as on a NATed LAN.
    // The cloud listener starts one finalized height behind and never dials it.
    drop(client);
    peer_server.stop().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let peer_key = SigningKey::from_bytes(&[43; 32]);
    let client_key = SigningKey::from_bytes(&[44; 32]);
    let peer_server = crate::peer_server::PeerServer::start(
        listener,
        peer_key,
        &[client_key.verifying_key().to_bytes()],
        remote_actor.clone(),
        2,
    )
    .unwrap();
    let mut client = crate::peer_client::PeerClient::connect(
        address,
        client_key,
        peer_public,
        descriptor.id().unwrap(),
        descriptor.fingerprint,
    )
    .unwrap();
    let synchronized = crate::peer_gossip::exchange(
        &mut client,
        &integrated,
        peer_public,
        &mut crate::peer_gossip::GossipCursor::default(),
    )
    .unwrap();
    assert_eq!(synchronized.finalized, 1);
    assert_eq!(synchronized.votes, 2);
    assert_eq!(synchronized.operations, 1);
    assert_eq!(
        remote_actor.lock().unwrap().workers.chain.load().unwrap().0,
        integrated.lock().unwrap().workers.chain.load().unwrap().0
    );
    assert!(remote_actor.lock().unwrap().signing.is_none());
    remote_actor.lock().unwrap().tick(None).unwrap();
    crate::peer_gossip::exchange(
        &mut client,
        &integrated,
        peer_public,
        &mut crate::peer_gossip::GossipCursor::default(),
    )
    .unwrap();
    // Peer ingress only queued the purpose-bound challenge. The local actor
    // checks its protected custody before producing the liveness fragment.
    integrated.lock().unwrap().tick(None).unwrap();
    crate::peer_gossip::exchange(
        &mut client,
        &integrated,
        peer_public,
        &mut crate::peer_gossip::GossipCursor::default(),
    )
    .unwrap();
    remote_actor.lock().unwrap().tick(None).unwrap();
    let offer = remote_actor
        .lock()
        .unwrap()
        .handle(
            c.worker,
            WorkerMessage::Request {
                nonce: [88; 32],
                sequence: 0,
                chain: [0; 32],
            },
        )
        .unwrap();
    assert_eq!(offer[0], 5); // Work offer, after strict unchanged-parent quorum.
    assert_eq!(
        integrated
            .lock()
            .unwrap()
            .signing
            .as_ref()
            .unwrap()
            .backend
            .counter,
        4010
    );
    drop(remote_actor);
    drop(client);
    drop(stream);
    peer_server.stop().unwrap();
    if let Some(server) = worker_server { server.stop().unwrap(); }
    integrated
        .lock()
        .unwrap()
        .signing
        .as_mut()
        .unwrap()
        .backend
        .counter -= 1;
    let failed_service = crate::actor_service::ActorService::start(integrated.clone()).unwrap();
    assert!(
        failed_service
            .output
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap()
            .is_err()
    );
    assert!(failed_service.stop().is_err());
    assert!(integrated.lock().unwrap().active(c.worker).is_err());
    assert_eq!(
        integrated
            .lock()
            .unwrap()
            .workers
            .chain
            .load()
            .unwrap()
            .0
            .height,
        1
    );
    drop(integrated);
    for entry in std::fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        assert!(entry.file_type().unwrap().is_file());
        std::fs::remove_file(entry.path()).unwrap();
    }
    std::fs::remove_dir(dir).unwrap();
}
fn pipeline(automatic: bool) {
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
    let row: serde_json::Value = serde_json::from_str(rows.next().unwrap()).unwrap();
    let block =
        BlockEnvelope::decode(&hex::decode(row["envelope"].as_str().unwrap()).unwrap()).unwrap();
    let member = state.continuity.as_ref().unwrap().members[0].clone();
    let physical = BTreeMap::from([(
        member.node,
        PhysicalMember {
            node: member.node,
            generation: member.generation,
            continuity_key: member.voting_key,
            hardware: member.hardware,
            admission_commitment: member.attestation,
            attestation_key: vec![6; 33],
        },
    )]);
    let mut salt = [0; 8];
    getrandom::getrandom(&mut salt).unwrap();
    let dir = std::env::temp_dir().join(format!("build8-worker-adapter-{}", hex::encode(salt)));
    std::fs::create_dir(&dir).unwrap();
    let mut chain = CanonicalStore::open_trusted_genesis(
        &dir.join("chain.sqlite"),
        &descriptor,
        &state,
        block.header.candidate.target,
    )
    .unwrap();
    let key = SigningKey::from_bytes(&[90; 32]);
    let mut coordinator = Coordinator::open(
        &dir.join("work.sqlite"),
        &dir.join("observation.sqlite"),
        descriptor.id().unwrap(),
        descriptor.fingerprint,
        key.clone(),
    )
    .unwrap();
    let (parent, _) = chain.execution_parent(0).unwrap();
    let mut gate = WorkGate::new(
        voter_actor::authority(&parent, &state).unwrap(),
        state.root().unwrap(),
        0,
    )
    .unwrap();
    gate.set_run(true);
    let certify = |decision: Decision| {
        let signature: Signature = TpmFixture::from_bytes((&[17; 32]).into())
            .unwrap()
            .sign_prehash(&decision.signing_digest(member.node, member.generation))
            .unwrap();
        Certificate {
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
        }
    };
    let proof = certify(gate.request(0, [42; 32]).unwrap().unwrap());
    gate.accept(1, &proof).unwrap();
    let c = &block.header.candidate;
    let mut builder = crate::body_assembler::Assembler {
        transactions: mutiny_consensus_v8::mempool::Mempool::open(
            &dir.join("chain.sqlite"),
            descriptor.id().unwrap(),
            descriptor.fingerprint,
            mutiny_consensus_v8::mempool::MAX_PENDING_BYTES,
        )
        .unwrap(),
        operations: crate::operation_pool::OperationPool::open(
            &dir.join("operations.sqlite"),
            descriptor.id().unwrap(),
            descriptor.fingerprint,
        )
        .unwrap(),
        physical: BTreeMap::from([(
            member.node,
            PhysicalMember {
                node: member.node,
                generation: member.generation,
                continuity_key: member.voting_key,
                hardware: member.hardware,
                admission_commitment: member.attestation,
                attestation_key: vec![6; 33],
            },
        )]),
        verifier: Fixture,
    };
    let binding = &state.licenses.workers[&c.worker].binding;
    for operation in &block.body.operations {
        builder
            .admit_operation(&mut chain, binding, c.timestamp, operation)
            .unwrap();
    }
    let assembled = builder.assemble(&mut chain, binding, c.timestamp).unwrap();
    assert_eq!(assembled, block.body);
    coordinator
        .issue(
            &mut chain,
            &mut gate,
            MiningRequest {
                worker: c.worker,
                license: c.license,
                body: assembled,
                timestamp: c.timestamp,
                now_ms: 2,
                unix_ms: c.timestamp * 1000,
                observation_sequence: 0,
                observation_chain: [0; 32],
            },
            &physical,
            &Fixture,
            // Explicit software fixture decision clock, never a host qualification.
            || Ok((2, c.timestamp * 1000)),
        )
        .unwrap();
    let submission = Submission {
        sequence: 1,
        previous: [0; 32],
        work: block.header.work_bytes(),
    };
    let unavailable = Arc::new(AtomicBool::new(true));
    let pending_path = dir.join("candidates.sqlite");
    let journal = CandidateJournal::open(
        &pending_path,
        descriptor.id().unwrap(),
        descriptor.fingerprint,
        100_000,
    )
    .unwrap();
    let mut runtime = WorkerCoordinator::new(
        chain,
        coordinator,
        key.verifying_key().to_bytes(),
        physical,
        Fixture,
        Hooks {
            block: block.clone(),
            builder,
            journal,
            unavailable: unavailable.clone(),
        },
        mutiny_consensus_v8::holdover_clock_v1::FixedBasis::at_ms(c.timestamp * 1000),
    );
    assert_eq!(runtime.active(c.worker).unwrap().worker, c.worker);
    assert!(runtime.active([99; 32]).is_err());
    assert_eq!(
        runtime
            .handle(
                c.worker,
                WorkerMessage::Status {
                    run: true,
                    faults: 0,
                    accepted_total: Some(0),
                    state: 2,
                }
            )
            .unwrap(),
        [1]
    ); // Outbox polling must not wait for renewed quorum.
    assert_eq!(
        runtime
            .handle(
                c.worker,
                WorkerMessage::Request {
                    nonce: [43; 32],
                    sequence: 0,
                    chain: [0; 32]
                }
            )
            .unwrap(),
        worker_protocol::waiting_quorum([43; 32]).unwrap()
    );
    let challenge = runtime.probe().unwrap().unwrap();
    assert!(runtime.accept_probe(&proof).is_err()); // A previous coordinator's nonce is not this lease.
    runtime.accept_probe(&certify(challenge)).unwrap();
    assert_eq!(
        runtime
            .handle(
                c.worker,
                WorkerMessage::Status {
                    run: true,
                    faults: 0,
                    accepted_total: Some(0),
                    state: 3
                }
            )
            .unwrap(),
        [1]
    );
    assert!(
        runtime
            .handle(c.worker, WorkerMessage::Result(submission.clone()))
            .is_err()
    );
    assert!(runtime.hooks.journal.records().unwrap().is_empty());
    assert_eq!(runtime.coordinator.total(c.worker).unwrap(), 1); // Durable accounting awaits ingress retry.
    let observed = runtime
        .coordinator
        .result(c.worker, &submission.encode())
        .unwrap();
    let mut tiny = CandidateJournal::open(
        &dir.join("tiny.sqlite"),
        descriptor.id().unwrap(),
        descriptor.fingerprint,
        1,
    )
    .unwrap();
    assert!(
        tiny.preserve(&mut runtime.chain, &observed, &runtime.physical, &Fixture)
            .is_err()
    );
    assert!(tiny.records().unwrap().is_empty());
    drop(tiny);
    unavailable.store(false, Ordering::Release);
    let receipt = runtime
        .handle(c.worker, WorkerMessage::Result(submission.clone()))
        .unwrap();
    assert_eq!(receipt[0], 4);
    assert_eq!(runtime.hooks.journal.records().unwrap().len(), 1);
    assert_eq!(
        runtime
            .handle(c.worker, WorkerMessage::Result(submission))
            .unwrap(),
        receipt
    );
    assert_eq!(runtime.chain.load().unwrap().0.height, 0);
    let voter_path = dir.join("software-voter.sqlite");
    let mut backend = SoftwareCounter {
        key: TpmFixture::from_bytes((&[17; 32]).into()).unwrap(),
        counter: 1000,
    };
    let mut voter = voter_actor::VoterActor::open(
        &voter_path,
        member.node,
        Some(1000),
        &mut runtime.chain,
        &mut backend,
        &runtime.physical,
        &Fixture,
    )
    .unwrap();
    // Existing behavior test, not about time: a controlled eligible clock (the default is fail-closed).
    voter.set_vote_clock(mutiny_consensus_v8::vote_clock_v1::ControlledClock::at(
        u64::MAX,
    ));
    let before = backend.counter;
    assert_eq!(
        runtime
            .hooks
            .journal
            .restore_into_voter(&mut runtime.chain, &mut voter, &runtime.physical, &Fixture)
            .unwrap(),
        1
    );
    assert_eq!(backend.counter, before);
    let saved_vote = voter
        .sign(
            &mut runtime.chain,
            mutiny_consensus_v8::bft::Step::Prevote,
            Some(block.block_hash()),
            None,
            &mut backend,
        )
        .unwrap();
    let after_vote = backend.counter;
    let inspected = voter.progress().unwrap();
    assert_eq!(inspected.1, Some(saved_vote.clone()));
    assert!(inspected.2.is_none());
    assert_eq!(backend.counter, after_vote);
    drop(voter);
    let mut voter = voter_actor::VoterActor::open(
        &voter_path,
        member.node,
        None,
        &mut runtime.chain,
        &mut backend,
        &runtime.physical,
        &Fixture,
    )
    .unwrap();
    // Existing behavior test, not about time: a controlled eligible clock (the default is fail-closed).
    voter.set_vote_clock(mutiny_consensus_v8::vote_clock_v1::ControlledClock::at(
        u64::MAX,
    ));
    assert_eq!(
        runtime
            .hooks
            .journal
            .restore_into_voter(&mut runtime.chain, &mut voter, &runtime.physical, &Fixture)
            .unwrap(),
        1
    );
    assert_eq!(
        voter
            .sign(
                &mut runtime.chain,
                mutiny_consensus_v8::bft::Step::Prevote,
                Some(block.block_hash()),
                None,
                &mut backend
            )
            .unwrap(),
        saved_vote
    );
    assert_eq!(backend.counter, after_vote); // Restore and cached vote add no software counter writes.
    if automatic {
        let mut received = crate::vote_journal::VoteJournal::open(
            &dir.join("automatic-received.sqlite"),
            descriptor.id().unwrap(),
            descriptor.fingerprint,
        )
        .unwrap();
        let mut driver = crate::voter_driver::Driver::default();
        let result = driver
            .tick(
                &mut runtime.chain,
                &mut voter,
                &mut backend,
                &runtime.hooks.journal,
                &mut received,
                None,
                &runtime.physical,
                &Fixture,
            )
            .unwrap();
        assert_eq!(result.publish.len(), 2);
        assert_eq!(result.publish[0], saved_vote);
        assert_eq!(result.publish[1].decision.step, 3);
        assert!(!result.publish[1].nil);
        assert_eq!(result.finalized, Some(block.block_hash()));
        assert_eq!(voter.height(), 2);
        // Two writes for the new precommit; one for height advancement. The
        // cached prevote caused neither a new signature nor a counter write.
        assert_eq!(backend.counter, after_vote + 3);
        assert_eq!(runtime.chain.load().unwrap().0.height, 1);
        drop(voter);
        drop(received);
        drop(runtime);
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            assert!(entry.file_type().unwrap().is_file());
            std::fs::remove_file(entry.path()).unwrap();
        }
        std::fs::remove_dir(dir).unwrap();
        return;
    }
    voter.observe(&saved_vote).unwrap();
    let precommit = voter
        .sign(
            &mut runtime.chain,
            mutiny_consensus_v8::bft::Step::Precommit,
            Some(block.block_hash()),
            None,
            &mut backend,
        )
        .unwrap();
    assert!(!precommit.nil);
    let proposal = runtime.hooks.journal.records().unwrap().remove(0);
    let received_path = dir.join("received-votes.sqlite");
    let mut received = crate::vote_journal::VoteJournal::open(
        &received_path,
        descriptor.id().unwrap(),
        descriptor.fingerprint,
    )
    .unwrap();
    assert!(
        received
            .admit(
                &mut runtime.chain,
                &saved_vote,
                Some(&proposal),
                &runtime.physical,
                &Fixture
            )
            .unwrap()
    );
    assert!(
        received
            .admit(
                &mut runtime.chain,
                &precommit,
                Some(&proposal),
                &runtime.physical,
                &Fixture
            )
            .unwrap()
    );
    assert!(
        !received
            .admit(
                &mut runtime.chain,
                &precommit,
                Some(&proposal),
                &runtime.physical,
                &Fixture
            )
            .unwrap()
    );
    assert!(
        received
            .admit(
                &mut runtime.chain,
                &precommit,
                None,
                &runtime.physical,
                &Fixture
            )
            .is_err()
    );
    let mut bad = precommit.clone();
    bad.signature[0] ^= 1;
    assert!(
        received
            .admit(
                &mut runtime.chain,
                &bad,
                Some(&proposal),
                &runtime.physical,
                &Fixture
            )
            .is_err()
    );
    assert_eq!(received.height(1).unwrap().len(), 2);
    drop(received);
    let received = crate::vote_journal::VoteJournal::open(
        &received_path,
        descriptor.id().unwrap(),
        descriptor.fingerprint,
    )
    .unwrap();
    assert!(
        crate::vote_journal::VoteJournal::open(&received_path, [99; 32], descriptor.fingerprint)
            .is_err()
    );
    let durable_precommits: Vec<_> = received
        .height(1)
        .unwrap()
        .into_iter()
        .filter(|v| v.decision.step == 3)
        .collect();
    assert_eq!(durable_precommits, vec![precommit.clone()]);
    assert!(
        crate::certificate_assembly::assemble(
            &mut runtime.chain,
            &proposal,
            &[],
            &runtime.physical,
            &Fixture,
        )
        .unwrap()
        .is_none()
    );
    assert!(
        crate::certificate_assembly::assemble(
            &mut runtime.chain,
            &proposal,
            &[saved_vote],
            &runtime.physical,
            &Fixture,
        )
        .is_err()
    );
    let mut invalid = precommit.clone();
    invalid.signature[0] ^= 1;
    assert!(
        crate::certificate_assembly::assemble(
            &mut runtime.chain,
            &proposal,
            &[invalid],
            &runtime.physical,
            &Fixture,
        )
        .is_err()
    );
    let assembled = crate::certificate_assembly::assemble(
        &mut runtime.chain,
        &proposal,
        &[precommit.clone(), precommit.clone()],
        &runtime.physical,
        &Fixture,
    )
    .unwrap()
    .unwrap();
    assert_eq!(assembled.certificate.signers.len(), 1);
    assert_eq!(assembled.block_hash(), block.block_hash());
    assert_eq!(runtime.chain.load().unwrap().0.height, 0);
    let finalized = received
        .finalize_ready(&mut runtime.chain, &[proposal], &runtime.physical, &Fixture)
        .unwrap()
        .unwrap();
    assert_eq!(finalized.block_hash(), block.block_hash());
    voter
        .reconcile(
            &mut runtime.chain,
            &mut backend,
            &runtime.physical,
            &Fixture,
        )
        .unwrap();
    assert_eq!(voter.height(), 2);
    drop(voter);
    drop(received);
    // A canonical parent change immediately revokes the old local lease.
    assert_eq!(
        runtime
            .handle(
                c.worker,
                WorkerMessage::Status {
                    run: true,
                    faults: 0,
                    accepted_total: Some(1),
                    state: 4
                }
            )
            .unwrap(),
        [7]
    );
    // Only a finalized predecessor can be reclaimed; the new still-pending
    // proposal survives restart and never establishes finality on its own.
    let row: serde_json::Value = serde_json::from_str(rows.next().unwrap()).unwrap();
    let next =
        BlockEnvelope::decode(&hex::decode(row["envelope"].as_str().unwrap()).unwrap()).unwrap();
    let (parent, state) = runtime.chain.execution_parent(1).unwrap();
    let (context, _) = state.work_context(&parent, &next.header.candidate).unwrap();
    let next_observed = ObservedWork {
        header: next.header.clone(),
        issued: Some(mutiny_consensus_v8::work_issuance::IssuedWork {
            authority: next.authority.clone(),
            signature: next.authority_signature,
            context,
            body: next.body.clone(),
        }),
        receipt: observed.receipt,
    };
    runtime
        .hooks
        .journal
        .preserve(
            &mut runtime.chain,
            &next_observed,
            &runtime.physical,
            &Fixture,
        )
        .unwrap();
    assert_eq!(runtime.hooks.journal.records().unwrap().len(), 1);
    assert_eq!(runtime.chain.load().unwrap().0.height, 1);
    drop(runtime);
    let restored = CandidateJournal::open(
        &pending_path,
        descriptor.id().unwrap(),
        descriptor.fingerprint,
        100_000,
    )
    .unwrap();
    assert_eq!(restored.records().unwrap()[0].header, next.header);
    assert!(
        CandidateJournal::open(&pending_path, [88; 32], descriptor.fingerprint, 100_000).is_err()
    );
    assert!(
        CandidateJournal::open(
            &pending_path,
            descriptor.id().unwrap(),
            descriptor.fingerprint,
            1
        )
        .is_err()
    );
    drop(restored);
    let corrupt = rusqlite::Connection::open(&pending_path).unwrap();
    corrupt
        .execute("UPDATE candidates SET id=?1", [[0u8; 32].as_slice()])
        .unwrap();
    drop(corrupt);
    assert!(
        CandidateJournal::open(
            &pending_path,
            descriptor.id().unwrap(),
            descriptor.fingerprint,
            100_000
        )
        .is_err()
    );
    std::fs::remove_dir_all(dir).unwrap();
}
