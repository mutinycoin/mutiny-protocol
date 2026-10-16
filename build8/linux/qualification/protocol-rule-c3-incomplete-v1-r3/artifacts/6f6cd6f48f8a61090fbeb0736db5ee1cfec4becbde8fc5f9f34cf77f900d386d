//! OS-clock coverage (package P-D). Everything here runs against the real `IntegratedActor`,
//! `Driver`, `LocalProposer`, `CandidateJournal` and `ActorService` with a CONTROLLED time basis.
//! No test reads the host clock. See docs/OS-CLOCK-CLASSIFICATION-V1.md for the property map.
use super::tests::{Fixture, SoftwareCounter};
use super::*;
use crate::{
    body_assembler::Assembler,
    candidate_journal::{CandidateJournal, CandidateRecord},
    integrated_actor::{IntegratedActor, SigningState},
    peer_server::PeerBackend,
};
use ed25519_dalek::SigningKey;
use mutiny_consensus_v8::{
    block_envelope::BlockEnvelope,
    blocks::{GenesisDescriptor, state_root},
    certificates::Signer,
    execution::State,
    holdover_clock_v1::FixedBasis,
    membership::NodeControl,
    pow::{Candidate, WorkAuthority, WorkHeader, meets_target},
    vote_clock_v1::{ControlledClock, TimeStatus},
};
use p256::ecdsa::{Signature, SigningKey as TpmFixture, signature::hazmat::PrehashSigner};
use std::{
    path::PathBuf,
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// Software counter whose TPM signature can be made to fail AFTER the reservation commit, which is
/// the exact interruption point crash recovery must survive.
pub(super) struct Flaky {
    inner: SoftwareCounter,
    fail: Arc<AtomicBool>,
}
impl mutiny_consensus_v8::counter_store::MonotonicCounter for Flaky {
    fn read(&mut self) -> Result<u64> {
        self.inner.read()
    }
    fn increment(&mut self) -> Result<()> {
        self.inner.increment()
    }
}
impl mutiny_consensus_v8::counter_voter::CounterSigningBackend for Flaky {
    fn public_key(&self) -> [u8; 33] {
        mutiny_consensus_v8::counter_voter::CounterSigningBackend::public_key(&self.inner)
    }
    fn sign_digest(&mut self, digest: Hash) -> Result<[u8; 64]> {
        // Armed only AFTER a reservation commit has moved the counter, i.e. exactly between the
        // durable reservation and the signature (liveness-probe signatures happen before it).
        if self.fail.load(Ordering::SeqCst) && self.inner.counter > START {
            return Err("fixture signer interrupted".into());
        }
        mutiny_consensus_v8::counter_voter::CounterSigningBackend::sign_digest(
            &mut self.inner,
            digest,
        )
    }
}
impl crate::participation_producer::ParticipationSigner for Flaky {
    fn public_key(&self) -> [u8; 33] {
        mutiny_consensus_v8::counter_voter::CounterSigningBackend::public_key(&self.inner)
    }
    fn acknowledgement(
        &mut self,
        ack: &mutiny_consensus_v8::participation::ParticipationAck,
    ) -> Result<[u8; 64]> {
        crate::participation_producer::ParticipationSigner::acknowledgement(&mut self.inner, ack)
    }
    fn refresh_quote(
        &mut self,
        refresh: &mutiny_consensus_v8::freshness::AttestationRefresh,
    ) -> Result<Vec<u8>> {
        crate::participation_producer::ParticipationSigner::refresh_quote(&mut self.inner, refresh)
    }
}

type Actor = IntegratedActor<Fixture, Assembler<Fixture>, Flaky>;
const START: u64 = 4000;

struct Rig {
    actor: Actor,
    basis: Arc<FixedBasis>,
    clock: Arc<ControlledClock>,
    fail: Arc<AtomicBool>,
    ts: u64,
    worker: Hash,
    node: Hash,
    _dir: Dir,
    voter_path: PathBuf,
    original: BlockEnvelope,
    eligible: Option<CandidateRecord>,
    future: Vec<CandidateRecord>,
}
struct Dir(PathBuf);
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn set_time(basis: &FixedBasis, clock: &ControlledClock, qualified: bool, ts: u64) {
    basis.set(ts * 1000);
    basis.set_qualified(qualified);
    clock.set(ts);
    clock.set_qualified(qualified);
}
fn counter(actor: &Actor) -> u64 {
    actor.signing.as_ref().unwrap().backend.inner.counter
}
fn peer_call(actor: &mut Actor, request: serde_json::Value) -> serde_json::Value {
    let reply =
        PeerBackend::handle(actor, [9; 32], &serde_json::to_vec(&request).unwrap()).unwrap();
    serde_json::from_slice(&reply.payload).unwrap()
}

/// `easy` replaces the chain's proof-of-work target with an all-ones target so many valid
/// candidates can be minted through the REAL issuance/execution path in milliseconds; the hard
/// fixture target is kept when `easy` is false (used for the finalized-import test). `eligible` mints
/// one candidate at the fixture timestamp; `future_offsets` mint candidates that many seconds AHEAD
/// of it, each with a block hash lower than the eligible one (the griefing shape).
fn build(easy: bool, eligible: bool, future_offsets: &[u64]) -> Rig {
    build_with(easy, eligible, future_offsets, |_, _, _| {})
}
/// `build` with one extra step: `edit(state, fixture candidate timestamp, Genesis t0)` may change
/// the Genesis state (after the proposer control record) before the chain is opened.
fn build_with(
    easy: bool,
    eligible: bool,
    future_offsets: &[u64],
    edit: impl FnOnce(&mut State, u64, u64),
) -> Rig {
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
    // The proposer needs a node-authentication control record; adding it changes the genesis state,
    // so the unmodified fixture chain (needed to import the fixture's own certified block) has no
    // proposer.
    if easy {
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
    }
    edit(
        &mut state,
        original.header.candidate.timestamp,
        descriptor.timestamp,
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
    let dir = std::env::temp_dir().join(format!("build8-osclock-{}", hex::encode(salt)));
    std::fs::create_dir(&dir).unwrap();
    let chain_path = dir.join("chain.sqlite");
    let target = if easy {
        [0xff; 32]
    } else {
        original.header.candidate.target
    };
    let mut chain =
        CanonicalStore::open_trusted_genesis(&chain_path, &descriptor, &state, target).unwrap();
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
    let c = original.header.candidate.clone();
    let binding = state.licenses.workers[&c.worker].binding.clone();
    let mut builder = Assembler {
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
    let mut coordinator = Coordinator::open(
        &dir.join("work.sqlite"),
        &dir.join("observations.sqlite"),
        descriptor.id().unwrap(),
        descriptor.fingerprint,
        SigningKey::from_bytes(&[90; 32]),
    )
    .unwrap();
    let mut journal = CandidateJournal::open(
        &dir.join("candidates.sqlite"),
        descriptor.id().unwrap(),
        descriptor.fingerprint,
        1 << 24,
    )
    .unwrap();
    let mut issued_at = 1;
    let mut mint = |timestamp: u64, below: Option<Hash>| -> CandidateRecord {
        let body = builder.assemble(&mut chain, &binding, timestamp).unwrap();
        issued_at += 1;
        let (issued, _) = coordinator
            .issue(
                &mut chain,
                &mut gate,
                MiningRequest {
                    worker: c.worker,
                    license: c.license,
                    body,
                    timestamp,
                    now_ms: issued_at,
                    // A coordinator-supplied clock parameter, NOT a host read: it lets the fixture
                    // play a hostile or skewed licensed coordinator that stamps a future time.
                    unix_ms: timestamp * 1000,
                    observation_sequence: 0,
                    observation_chain: [0; 32],
                },
                &physical,
                &Fixture,
                // Explicit software fixture decision clock, never a host qualification.
                || Ok((issued_at, timestamp * 1000)),
            )
            .unwrap();
        let mut header = WorkHeader {
            candidate: issued.authority.candidate.clone(),
            authority: issued.authority.id(),
            nonce: 0,
        };
        loop {
            if meets_target(&header.digest(), &header.candidate.target)
                && below.is_none_or(|limit| header.block_hash() < limit)
            {
                break;
            }
            header.nonce += 1;
            assert!(header.nonce < 100_000, "nonce search bound");
        }
        let record = CandidateRecord {
            header,
            body: issued.body,
            authority: issued.authority,
            signature: issued.signature,
        };
        journal
            .accept(&mut chain, &record, &physical, &Fixture)
            .unwrap();
        record
    };
    let mut eligible_record = None;
    let mut future = Vec::new();
    if easy {
        if eligible {
            eligible_record = Some(mint(c.timestamp, None));
        }
        let limit = eligible_record.as_ref().map(|r| r.header.block_hash());
        for offset in future_offsets {
            future.push(mint(c.timestamp + offset, limit));
        }
    }
    let fail = Arc::new(AtomicBool::new(false));
    let mut backend = Flaky {
        inner: SoftwareCounter {
            key: tpm_key,
            counter: START,
        },
        fail: fail.clone(),
    };
    let voter_path = dir.join("voter.sqlite");
    let mut voter = voter_actor::VoterActor::open(
        &voter_path,
        member.node,
        Some(START),
        &mut chain,
        &mut backend,
        &physical,
        &Fixture,
    )
    .unwrap();
    let clock = ControlledClock::at(c.timestamp);
    voter.set_vote_clock(clock.clone());
    let received = crate::vote_journal::VoteJournal::open(
        &dir.join("received.sqlite"),
        descriptor.id().unwrap(),
        descriptor.fingerprint,
    )
    .unwrap();
    let local = easy.then(|| {
        crate::local_proposer::LocalProposer::open(
            &dir.join("proposer.sqlite"),
            member.node,
            authentication,
            descriptor.id().unwrap(),
            descriptor.fingerprint,
        )
        .unwrap()
    });
    let basis = FixedBasis::at_ms(c.timestamp * 1000);
    let workers = WorkerCoordinator::new(
        chain,
        coordinator,
        SigningKey::from_bytes(&[90; 32]).verifying_key().to_bytes(),
        physical,
        Fixture,
        JournaledCandidates { journal, builder },
        basis.clone(),
    );
    let actor = IntegratedActor::new(
        workers,
        received,
        Some(SigningState {
            voter,
            backend,
            proposer: local,
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
    Rig {
        actor,
        basis,
        clock,
        fail,
        ts: c.timestamp,
        worker: c.worker,
        node: member.node,
        _dir: Dir(dir),
        voter_path,
        original,
        eligible: eligible_record,
        future,
    }
}
impl Rig {
    fn set_time(&self, qualified: bool, ts: u64) {
        set_time(&self.basis, &self.clock, qualified, ts);
    }
    /// Model a process restart of the voter custody and the driver's memory. Durable state (the
    /// counter, the vote store, the candidate journal) is untouched.
    fn restart(&mut self) {
        let a = &mut self.actor;
        let s = a.signing.as_mut().unwrap();
        let mut reopened = voter_actor::VoterActor::open(
            &self.voter_path,
            self.node,
            None,
            &mut a.workers.chain,
            &mut s.backend,
            &a.workers.physical,
            &Fixture,
        )
        .unwrap();
        reopened.set_vote_clock(self.clock.clone());
        s.voter = reopened;
        a.restart_driver_for_test();
        // The restarted driver has the ordinary delay again; keep the test independent of tick speed.
        a.set_round_delay_for_test(Duration::from_secs(3600));
    }
    fn request(&mut self) -> std::result::Result<Vec<u8>, String> {
        WorkerBackend::handle(
            &mut self.actor,
            self.worker,
            WorkerMessage::Request {
                nonce: [7; 32],
                sequence: 0,
                chain: [0; 32],
            },
        )
    }
}

// ---------------------------------------------------------------------------------------------
// R2 / T-c4 / T-c5: the actor under an UNQUALIFIED time basis.
// ---------------------------------------------------------------------------------------------

#[test]
fn cold_boot_without_an_anchor_is_a_deferral_not_a_fault_and_resumes_on_qualification() {
    let mut r = build(true, true, &[]);
    r.set_time(false, r.ts); // First tick runs before any calibration: no restorable anchor.
    r.actor.set_round_delay_for_test(Duration::from_secs(3600));
    let before = counter(&r.actor);
    for _ in 0..3 {
        // Previously: tick -> workers.probe()? -> "Qualified clock unavailable" on EVERY call.
        let tick = r
            .actor
            .tick(None)
            .expect("an unqualified clock defers; it is not a fault");
        assert!(
            tick.proposal.is_none(),
            "no fresh proposal without qualified time"
        );
        assert!(tick.consensus.publish.is_empty());
        assert!(tick.consensus.finalized.is_none());
    }
    assert_eq!(counter(&r.actor), before, "no vote, no counter use");
    assert!(r.actor.runtime_fault().is_none());
    // No NEW work authorization and no binding of the Worker to the current epoch without qualified
    // time. The session itself authenticates against finalized state (Architect decision V2:
    // status, stop and stored-receipt retransmission stay available); that binds nothing new.
    let refused = r.request().unwrap_err();
    assert!(refused.contains("Qualified clock unavailable"), "{refused}");
    assert_eq!(
        WorkerBackend::active(&mut r.actor, r.worker)
            .unwrap()
            .worker,
        r.worker
    );
    // T-c5: operation admission is withheld, nothing is queued, and no participation operation was
    // produced or admitted.
    let reply = peer_call(
        &mut r.actor,
        serde_json::json!({"id":1,"method":"submit_operation","operation":""}),
    );
    assert_eq!(
        reply["error"],
        "Qualified clock unavailable: operation admission withheld"
    );
    let a = &mut r.actor;
    assert!(
        a.workers
            .hooks
            .builder
            .pending_operations(&mut a.workers.chain)
            .unwrap()
            .is_empty()
    );
    // The real ActorService must not latch a fault either (it exits the process on any tick Err).
    let shared = Arc::new(Mutex::new(r.actor));
    let service = crate::actor_service::ActorService::start(shared.clone()).unwrap();
    std::thread::sleep(Duration::from_millis(1200));
    assert!(
        service.output.try_recv().is_err(),
        "an unqualified clock produced a service message (fault latch)"
    );
    assert!(shared.lock().unwrap().runtime_fault().is_none());
    service.stop().expect("actor thread must not have exited");
    // Qualification resumes cleanly: the same actor proposes, votes and finalizes.
    set_time(&r.basis, &r.clock, true, r.ts);
    let mut guard = shared.lock().unwrap();
    let tick = guard.tick(None).unwrap();
    let block = r.eligible.as_ref().unwrap().header.block_hash();
    assert_eq!(tick.proposal.as_ref().map(|p| p.block), Some(block));
    assert_eq!(tick.consensus.finalized, Some(block));
    assert_eq!(tick.consensus.publish.len(), 2);
    assert!(tick.consensus.time_deferred.is_none());
    assert_eq!(counter(&guard), START + 5);
}

#[test]
fn clock_lost_mid_run_retransmits_the_exact_reserved_vote_and_creates_no_new_one() {
    let mut r = build(true, true, &[]);
    r.actor.set_round_delay_for_test(Duration::from_secs(3600));
    let block = r.eligible.as_ref().unwrap().header.block_hash();
    // Qualified: the prevote passes the fresh-vote guard and its reservation is committed durably,
    // then the TPM signature is interrupted (crash between reservation and signature).
    r.fail.store(true, Ordering::SeqCst);
    assert!(r.actor.tick(None).is_err());
    let reserved_counter = counter(&r.actor);
    assert_eq!(
        reserved_counter,
        START + 1,
        "exactly one reservation commit"
    );
    // Process restart, and the qualified clock is now lost for the voter AND the time basis.
    r.fail.store(false, Ordering::SeqCst);
    r.set_time(false, r.ts);
    r.restart();
    let reserved = r
        .actor
        .signing
        .as_ref()
        .unwrap()
        .voter
        .progress()
        .unwrap()
        .1
        .expect("durable unsigned reservation");
    assert_eq!(reserved.signature, [0; 64]);
    assert!(!reserved.nil);
    // The unqualified tick completes ONLY that exact decision and creates nothing else.
    let first = r
        .actor
        .tick(None)
        .expect("recovery under an unqualified clock is not a fault");
    assert_eq!(first.consensus.publish.len(), 1, "no second slot is signed");
    let sent = first.consensus.publish[0].clone();
    assert!(!sent.nil);
    assert_eq!(sent.decision.id(), reserved.decision.id());
    assert_eq!(sent.decision.block, block);
    assert_ne!(sent.signature, [0; 64]);
    assert_eq!(first.consensus.time_deferred, Some(TimeStatus::Unqualified));
    assert!(first.consensus.finalized.is_none());
    let completed = counter(&r.actor);
    assert!(
        completed <= reserved_counter + 1,
        "completion writes at most the signed marker"
    );
    // A further unqualified tick is a pure retransmission of the identical vote.
    let second = r.actor.tick(None).unwrap();
    assert_eq!(second.consensus.publish, vec![sent.clone()]);
    assert_eq!(counter(&r.actor), completed);
    assert!(r.actor.runtime_fault().is_none());
    // Qualification returns: the precommit (a NEW slot) is only now authorized, and finalizes.
    r.set_time(true, r.ts);
    let done = r.actor.tick(None).unwrap();
    assert_eq!(done.consensus.publish.len(), 2);
    assert_eq!(done.consensus.publish[0], sent);
    assert!(!done.consensus.publish[1].nil);
    assert_eq!(done.consensus.finalized, Some(block));
}

/// Re-encode a version-3 voter snapshot as the version-1 record an old build wrote: unsigned
/// reservations carry NO guard marker.
fn to_legacy(v3: &[u8]) -> Vec<u8> {
    use minicbor::{Decoder, Encoder};
    let mut d = Decoder::new(v3);
    assert_eq!(d.array().unwrap(), Some(4));
    assert_eq!(d.u8().unwrap(), 3);
    let height = d.u64().unwrap();
    let state = d.bytes().unwrap().to_vec();
    let count = d.array().unwrap().unwrap();
    let mut e = Encoder::new(Vec::new());
    e.array(4)
        .unwrap()
        .u8(1)
        .unwrap()
        .u64(height)
        .unwrap()
        .bytes(&state)
        .unwrap()
        .array(count)
        .unwrap();
    for _ in 0..count {
        assert_eq!(d.array().unwrap(), Some(5));
        let (round, step) = (d.u64().unwrap(), d.u8().unwrap());
        let vote = d.bytes().unwrap().to_vec();
        let signed = d.bool().unwrap();
        let _gated = d.bool().unwrap();
        e.array(4)
            .unwrap()
            .u64(round)
            .unwrap()
            .u8(step)
            .unwrap()
            .bytes(&vote)
            .unwrap()
            .bool(signed)
            .unwrap();
    }
    e.into_writer()
}

#[test]
fn a_legacy_unmarked_reservation_under_an_unqualified_clock_is_a_deferral_not_a_halt() {
    use mutiny_consensus_v8::{counter_store::CounterStore, votes::AuthenticatedRound};
    let mut r = build(true, true, &[]);
    r.actor.set_round_delay_for_test(Duration::from_secs(3600));
    let block = r.eligible.as_ref().unwrap().header.block_hash();
    r.fail.store(true, Ordering::SeqCst);
    assert!(r.actor.tick(None).is_err()); // reservation committed, signature interrupted
    r.fail.store(false, Ordering::SeqCst);
    {
        // Rewrite the durable record as a version-1 build left it.
        let a = &mut r.actor;
        let (tip, state) = a.workers.chain.load_effective().unwrap();
        let (parent, _) = a.workers.chain.execution_parent(tip.height).unwrap();
        let authority = voter_actor::authority(&parent, &state).unwrap();
        let context = AuthenticatedRound::new(authority)
            .unwrap()
            .signing_context(r.node)
            .unwrap();
        let backend = &mut a.signing.as_mut().unwrap().backend;
        let mut store = CounterStore::open(&r.voter_path, context, None, backend).unwrap();
        let legacy = to_legacy(store.snapshot());
        store.commit(&legacy, backend).unwrap();
    }
    r.set_time(false, r.ts);
    r.restart();
    let before = counter(&r.actor);
    // Previously this was a hard tick error (and, through ActorService, a latched fault); worse,
    // the voter actor halted itself. Now: a deferral that signs nothing, tick after tick.
    for _ in 0..3 {
        let tick = r
            .actor
            .tick(None)
            .expect("an unmarked legacy reservation under an unqualified clock is a deferral");
        assert!(
            tick.consensus.publish.is_empty(),
            "nothing is signed or retransmitted"
        );
        assert_eq!(tick.consensus.time_deferred, Some(TimeStatus::Unqualified));
    }
    assert_eq!(counter(&r.actor), before);
    assert!(r.actor.runtime_fault().is_none());
    // With a qualified, eligible clock the exact reserved decision completes, then the round runs.
    r.set_time(true, r.ts);
    let done = r.actor.tick(None).unwrap();
    assert_eq!(done.consensus.publish.len(), 2);
    assert_eq!(done.consensus.publish[0].decision.block, block);
    assert_eq!(done.consensus.finalized, Some(block));
}

#[test]
fn nil_timeout_votes_proceed_under_an_unqualified_clock_and_no_block_vote_is_possible() {
    let mut r = build(true, true, &[]);
    r.set_time(false, r.ts);
    r.actor.set_round_delay_for_test(Duration::from_millis(1));
    let (mut nil_prevote, mut nil_precommit) = (false, false);
    for _ in 0..8 {
        std::thread::sleep(Duration::from_millis(5));
        let tick = r
            .actor
            .tick(None)
            .expect("timeouts must keep working")
            .consensus;
        for vote in &tick.publish {
            assert!(vote.nil, "a block vote needs a qualified clock");
            if vote.decision.step == 2 {
                nil_prevote = true;
            } else {
                nil_precommit = true;
            }
        }
        assert!(tick.finalized.is_none());
    }
    assert!(
        nil_prevote && nil_precommit,
        "nil votes are not time-dependent"
    );
    assert!(r.actor.runtime_fault().is_none());
}

#[test]
fn finalized_import_and_sync_proceed_under_an_unqualified_clock() {
    let mut r = build(false, false, &[]);
    r.set_time(false, r.ts);
    let original = r.original.clone();
    // Finalized ingestion reads no clock (D3/F4): the certified block commits while unqualified.
    assert!(r.actor.commit(&original).unwrap());
    assert_eq!(r.actor.workers.chain.load().unwrap().0.height, 1);
    let tick = r.actor.tick(None).unwrap();
    assert!(tick.consensus.publish.is_empty());
    assert!(r.actor.runtime_fault().is_none());
    assert_eq!(r.actor.signing.as_ref().unwrap().voter.height(), 2);
}

// ---------------------------------------------------------------------------------------------
// R3 / T-a4 / T-a6: proposer liveness against far-future candidates.
// ---------------------------------------------------------------------------------------------

fn sorted(mut v: Vec<CandidateRecord>) -> Vec<CandidateRecord> {
    v.sort_by_key(|r| r.header.block_hash());
    v
}

#[test]
fn proposer_skips_far_future_candidates_with_lower_hashes_and_discards_nothing() {
    let mut r = build(true, true, &[3600, 7200]);
    let eligible = r.eligible.as_ref().unwrap().header.block_hash();
    assert!(
        r.future.iter().all(|f| f.header.block_hash() < eligible),
        "fixture: the future candidates win the lowest-hash rule"
    );
    r.actor.set_round_delay_for_test(Duration::from_secs(3600));
    let stored = sorted(r.actor.workers.hooks.journal.records().unwrap());
    assert_eq!(stored.len(), 3);
    let tick = r.actor.tick(None).unwrap();
    // Previously the lowest-hash (future) candidate was proposed and every honest validator deferred.
    assert_eq!(tick.proposal.as_ref().map(|p| p.block), Some(eligible));
    assert_eq!(tick.consensus.finalized, Some(eligible));
    // Deferred candidates are neither dropped nor altered.
    assert_eq!(
        sorted(r.actor.workers.hooks.journal.records().unwrap()),
        stored
    );
}

#[test]
fn far_future_flood_is_stored_bounded_proposed_never_voted_and_released_by_the_clock() {
    let offsets = [120, 3_600, 7_200, 86_400, 172_800];
    let mut r = build(true, false, &offsets);
    r.actor.set_round_delay_for_test(Duration::from_secs(3600));
    let stored = sorted(r.actor.workers.hooks.journal.records().unwrap());
    assert_eq!(stored.len(), offsets.len());
    let before = counter(&r.actor);
    for round in 0..3 {
        let tick = r
            .actor
            .tick(None)
            .expect("a far-future flood is never a fault");
        assert!(tick.proposal.is_none(), "nothing is eligible yet");
        assert!(tick.consensus.publish.is_empty());
        assert!(tick.consensus.finalized.is_none());
        // All five were executed once (bounded), then memoised.
        assert_eq!(tick.consensus.validations, if round == 0 { 5 } else { 0 });
    }
    assert_eq!(counter(&r.actor), before);
    assert_eq!(
        sorted(r.actor.workers.hooks.journal.records().unwrap()),
        stored
    );
    // The qualified clock reaches ONE candidate: only it becomes proposable and votable, after the
    // ordinary revalidation, with no nil vote and without touching the others.
    r.set_time(true, r.ts + 120);
    let tick = r.actor.tick(None).unwrap();
    let first = r.future[0].header.block_hash();
    assert_eq!(tick.proposal.as_ref().map(|p| p.block), Some(first));
    assert_eq!(tick.consensus.publish.len(), 2);
    assert!(tick.consensus.publish.iter().all(|v| !v.nil));
    assert_eq!(tick.consensus.finalized, Some(first));
    assert_eq!(
        sorted(r.actor.workers.hooks.journal.records().unwrap()),
        stored
    );
}

#[test]
fn a_persisted_proposal_is_returned_unchanged_whatever_the_clock_does_later() {
    let mut r = build(true, true, &[]);
    let propose = |r: &mut Rig| {
        let a = &mut r.actor;
        let s = a.signing.as_mut().unwrap();
        s.proposer
            .as_mut()
            .unwrap()
            .propose(
                &mut a.workers.chain,
                &s.voter,
                &mut a.workers.hooks.journal,
                &a.received,
                &a.workers.physical,
                &Fixture,
            )
            .unwrap()
    };
    let first = propose(&mut r).expect("eligible candidate is proposed");
    let stored = sorted(r.actor.workers.hooks.journal.records().unwrap());
    r.set_time(false, r.ts); // the clock is lost
    let again = propose(&mut r).expect("a persisted proposal needs no clock");
    assert_eq!(again.encode(), first.encode());
    r.set_time(true, 1); // and even steps far backwards
    assert_eq!(propose(&mut r).unwrap().encode(), first.encode());
    assert_eq!(
        sorted(r.actor.workers.hooks.journal.records().unwrap()),
        stored
    );
    assert_eq!(stored[0].header.candidate.timestamp, r.ts);
}

// ---------------------------------------------------------------------------------------------
// R4 / T-a5: bounded, fault-tolerant per-tick validation.
// ---------------------------------------------------------------------------------------------

/// A decodable but unexecutable row: the all-ones target makes it self-consistent for the journal
/// codec while its authority/signature/parent target cannot execute. Models a stored candidate that
/// fails validation.
fn synthetic(base: &CandidateRecord, nonce: u64, timestamp: u64) -> CandidateRecord {
    let mut r = base.clone();
    r.header.candidate.target = [0xff; 32];
    r.header.candidate.timestamp = timestamp;
    r.authority.candidate = r.header.candidate.clone();
    r.header.authority = r.authority.id();
    r.header.nonce = nonce;
    r
}

#[test]
fn per_tick_validation_is_bounded_and_one_invalid_candidate_does_not_abort_the_tick() {
    use crate::voter_driver::MAX_VALIDATIONS_PER_TICK;
    let mut r = build(true, true, &[]);
    r.set_time(false, r.ts); // pure validation workload: nothing can be proposed or voted
    r.actor.set_round_delay_for_test(Duration::from_secs(3600));
    let base = r.eligible.clone().unwrap();
    const FLOOD: u64 = 40;
    for n in 0..FLOOD {
        let record = synthetic(&base, n + 1, base.header.candidate.timestamp + 50_000_000);
        r.actor
            .workers
            .hooks
            .journal
            .persist_for_test(&record, 0)
            .unwrap();
    }
    let total = FLOOD as usize + 1;
    let mut validations = Vec::new();
    let mut awaiting = Vec::new();
    for _ in 0..5 {
        let tick = r
            .actor
            .tick(None)
            .expect("an invalid stored candidate must not abort the tick")
            .consensus;
        assert!(tick.validations <= MAX_VALIDATIONS_PER_TICK);
        validations.push(tick.validations);
        awaiting.push(tick.awaiting_validation);
        assert!(tick.publish.is_empty());
    }
    assert_eq!(
        validations.iter().sum::<usize>(),
        total,
        "each row executed exactly once"
    );
    assert_eq!(validations, [16, 16, 9, 0, 0]);
    assert_eq!(awaiting, [25, 9, 0, 0, 0]);
    let last = r.actor.tick(None).unwrap().consensus;
    assert_eq!(last.refused_candidates, FLOOD as usize);
    // The valid candidate was never starved: with qualified time it is proposed, voted, finalized;
    // the invalid far-future rows were filtered out of proposer selection and are still stored.
    r.set_time(true, r.ts);
    let tick = r.actor.tick(None).unwrap();
    let block = base.header.block_hash();
    assert_eq!(tick.proposal.as_ref().map(|p| p.block), Some(block));
    assert_eq!(tick.consensus.finalized, Some(block));
    assert_eq!(
        r.actor.workers.hooks.journal.records().unwrap().len(),
        total
    );
}

// ---------------------------------------------------------------------------------------------
// T-b1: proposal choice (pure) - a held lock is never filtered, fresh choice is time-eligible.
// ---------------------------------------------------------------------------------------------

fn scratch(nonce: u64, timestamp: u64, transactions: Vec<Vec<u8>>) -> CandidateRecord {
    let body = BlockBody {
        height: 1,
        reward_owner: [3; 32],
        fees: 0,
        transactions,
        operations: vec![],
    };
    let candidate = Candidate {
        network: 1,
        genesis: [1; 32],
        fingerprint: [2; 32],
        parent: [4; 32],
        height: 1,
        timestamp,
        body_root: body.root().unwrap(),
        state_root: [5; 32],
        license: [6; 32],
        worker: [7; 32],
        target: [0xff; 32],
    };
    let authority = WorkAuthority {
        candidate: candidate.clone(),
        assignment_sequence: 1,
        ticket_sequence: 1,
        coordinator: [8; 32],
        nonce_start: 0,
        nonce_end: u64::MAX,
        epoch: 0,
    };
    let header = WorkHeader {
        authority: authority.id(),
        candidate,
        nonce,
    };
    CandidateRecord {
        header,
        body,
        authority,
        signature: [9; 64],
    }
}
fn scratch_where(timestamp: u64, accept: impl Fn(Hash) -> bool) -> CandidateRecord {
    (0..10_000)
        .map(|n| scratch(n, timestamp, vec![]))
        .find(|r| accept(r.header.block_hash()))
        .expect("hash search bound")
}

#[test]
fn a_held_lock_is_reproposed_unchanged_and_unfiltered_while_fresh_choice_is_time_eligible() {
    use crate::local_proposer::fallback_choice;
    let now = 1_000;
    let c = scratch_where(now, |_| true);
    let ch = c.header.block_hash();
    let future = scratch_where(now + 1_000_000, |h| h < ch); // lower hash, far ahead
    let locked = scratch_where(now + 2_000_000, |h| h > ch); // the lock: higher hash, far ahead
    let records = vec![c.clone(), future.clone(), locked.clone()];
    let eligible = |t: u64| t <= now;
    let (height, parent) = (1, [4; 32]);
    // Fresh choice: the lowest-hash ELIGIBLE candidate, never the lower-hash far-future one.
    assert_eq!(
        fallback_choice(&records, None, height, parent, &eligible),
        Some((ch, None))
    );
    // A held lock wins over every candidate and is NOT filtered by the clock, even though its
    // timestamp is ahead of it and an eligible lower-hash block exists. The proposal names the
    // lock's hash, which commits the header and therefore the original timestamp.
    let lock = locked.header.block_hash();
    assert_eq!(
        fallback_choice(&records, Some(lock), height, parent, &eligible),
        Some((lock, None))
    );
    assert_eq!(
        fallback_choice(&records, Some(lock), height, parent, &|_| false),
        Some((lock, None)),
        "a lock stays proposable while the clock is unqualified"
    );
    // Nothing eligible (unqualified clock, or all ahead): no NEW proposal, no fallback reading.
    assert_eq!(
        fallback_choice(&records, None, height, parent, &|_| false),
        None
    );
    assert_eq!(
        fallback_choice(
            &[future.clone(), locked.clone()],
            None,
            height,
            parent,
            &eligible
        ),
        None
    );
    // Wrong height or parent is never chosen.
    assert_eq!(fallback_choice(&records, None, 2, parent, &eligible), None);
    assert_eq!(
        fallback_choice(&records, None, height, [5; 32], &eligible),
        None
    );
    // The stored bytes and the timestamp the lock commits to are untouched by any of this: the
    // journal is idempotent for identical bytes and the timestamp is part of the block hash.
    let (_dir, mut journal, _) = journal("lock-bytes", 1 << 20);
    journal.persist_for_test(&locked, 0).unwrap();
    let stored = journal.records().unwrap();
    journal.persist_for_test(&locked, 0).unwrap();
    assert_eq!(journal.records().unwrap(), stored);
    assert_eq!(stored[0].header.candidate.timestamp, now + 2_000_000);
    let mut moved = locked.clone();
    moved.header.candidate.timestamp -= 1_000_000;
    assert_ne!(moved.header.block_hash(), locked.header.block_hash());
}

// ---------------------------------------------------------------------------------------------
// T-a1..T-a3: the live journal's count, byte-budget and per-record encoded-size bounds.
// ---------------------------------------------------------------------------------------------

fn journal(name: &str, budget: usize) -> (Dir, CandidateJournal, PathBuf) {
    let dir = std::env::temp_dir().join(format!("build8-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("candidates.sqlite");
    let j = CandidateJournal::open(&path, [1; 32], [2; 32], budget).unwrap();
    (Dir(dir), j, path)
}

#[test]
fn journal_count_cap_is_1024_full_fails_closed_and_rows_are_unchanged() {
    use crate::candidate_journal::{MAX_BYTES, MAX_PROPOSALS};
    let (_dir, mut j, _) = journal("count-cap", MAX_BYTES * MAX_PROPOSALS);
    for n in 0..MAX_PROPOSALS as u64 {
        j.persist_for_test(&scratch(n, 100, vec![]), 0).unwrap();
    }
    let before = j.records().unwrap();
    assert_eq!(before.len(), MAX_PROPOSALS);
    let refused = j
        .persist_for_test(&scratch(MAX_PROPOSALS as u64, 100, vec![]), 0)
        .unwrap_err();
    assert!(
        refused.contains("Candidate journal full; retry without dropping existing proposals"),
        "{refused}"
    );
    assert_eq!(j.records().unwrap(), before, "no eviction, no change");
    // An identical re-insert is idempotent, not a new row.
    j.persist_for_test(&scratch(5, 100, vec![]), 0).unwrap();
    assert_eq!(j.records().unwrap().len(), MAX_PROPOSALS);
    // A foreign writer that bypasses `persist` and adds a 1,025th row: every read fails closed on
    // the aggregate check BEFORE any row is decoded (bounded processing, not just storage).
    j.db_for_test()
        .execute(
            "INSERT INTO candidates VALUES(?1,?2,?3)",
            rusqlite::params![
                [0xEEu8; 32].as_slice(),
                1u64.to_be_bytes().as_slice(),
                vec![0u8; 8]
            ],
        )
        .unwrap();
    let e = j.records().unwrap_err();
    assert!(e.contains("Candidate journal capacity"), "{e}");
}

#[test]
fn journal_byte_budget_is_enforced_on_insert_and_on_reopen() {
    use crate::candidate_journal::{MAX_BYTES, MAX_PROPOSALS};
    let one = scratch(0, 100, vec![]).encode().unwrap().len();
    let budget = 2 * one + 1;
    let (dir, mut j, path) = journal("byte-budget", budget);
    j.persist_for_test(&scratch(0, 100, vec![]), 0).unwrap();
    j.persist_for_test(&scratch(1, 100, vec![]), 0).unwrap();
    let refused = j.persist_for_test(&scratch(2, 100, vec![]), 0).unwrap_err();
    assert!(refused.contains("Candidate journal full"), "{refused}");
    let stored = j.records().unwrap();
    assert_eq!(stored.len(), 2);
    assert!(
        stored
            .iter()
            .map(|r| r.encode().unwrap().len())
            .sum::<usize>()
            <= budget
    );
    drop(j);
    // Reopening under a budget smaller than what is stored fails closed; it never silently trims.
    let e = CandidateJournal::open(&path, [1; 32], [2; 32], one)
        .err()
        .unwrap();
    assert!(e.contains("Candidate journal capacity"), "{e}");
    assert!(CandidateJournal::open(&path, [1; 32], [2; 32], 0).is_err());
    assert!(
        CandidateJournal::open(&path, [1; 32], [2; 32], MAX_BYTES * MAX_PROPOSALS + 1).is_err()
    );
    assert_eq!(
        CandidateJournal::open(&path, [1; 32], [2; 32], budget)
            .unwrap()
            .records()
            .unwrap(),
        stored
    );
    drop(dir);
}

/// A canonical CBOR byte-string transaction of `len` payload bytes (unique per `tag`).
fn blob(tag: u8, len: usize) -> Vec<u8> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.bytes(&vec![tag; len]).unwrap();
    e.into_writer()
}
/// The largest valid record: the block body is capped at 64 KiB by `BlockBody::encode`, so the
/// record (body plus header/authority) stays under the journal's per-record cap.
fn largest_record(nonce: u64) -> CandidateRecord {
    let body_of = |last: usize| {
        let mut txs: Vec<Vec<u8>> = (1..=3).map(|t| blob(t, 16_381)).collect();
        txs.push(blob(9, last));
        txs
    };
    let fits = |last: usize| scratch_body_ok(body_of(last));
    assert!(fits(0), "three maximum transactions fit");
    let (mut lo, mut hi) = (0usize, 16_381usize);
    while lo < hi {
        let mid = (lo + hi).div_ceil(2);
        if fits(mid) {
            lo = mid;
        } else {
            hi = mid - 1;
        }
    }
    scratch(nonce, 100, body_of(lo))
}
fn scratch_body_ok(transactions: Vec<Vec<u8>>) -> bool {
    BlockBody {
        height: 1,
        reward_owner: [3; 32],
        fees: 0,
        transactions,
        operations: vec![],
    }
    .encode()
    .is_ok()
}

#[test]
fn journal_per_record_encoded_size_cap_is_enforced_on_write_and_read() {
    use crate::candidate_journal::MAX_BYTES;
    let largest = largest_record(0);
    let encoded = largest.encode().unwrap();
    // A valid body is at most 64 KiB, so the largest record sits between 64 KiB and the cap.
    assert!(
        encoded.len() <= MAX_BYTES && encoded.len() > 65_536,
        "{}",
        encoded.len()
    );
    assert_eq!(CandidateRecord::decode(&encoded).unwrap(), largest);
    // One more transaction exceeds the 64 KiB body bound: no record can even be formed.
    let mut over: Vec<Vec<u8>> = (1..=4).map(|t| blob(t, 16_381)).collect();
    over.push(blob(7, 16_381));
    assert!(!scratch_body_ok(over));
    let (_dir, mut j, _) = journal("record-cap", 1 << 26);
    assert!(j.records().unwrap().is_empty());
    j.persist_for_test(&largest, 0).unwrap();
    // The journal's own cap is a second, independent bound: decode rejects anything above it and a
    // foreign oversize row makes every read fail closed.
    assert!(CandidateRecord::decode(&vec![0u8; MAX_BYTES + 1]).is_err());
    j.db_for_test()
        .execute(
            "INSERT INTO candidates VALUES(?1,?2,?3)",
            rusqlite::params![
                [0xEEu8; 32].as_slice(),
                1u64.to_be_bytes().as_slice(),
                vec![0u8; MAX_BYTES + 1]
            ],
        )
        .unwrap();
    assert!(j.records().is_err());
}

#[test]
fn journal_64_mib_budget_bounds_maximum_size_records_below_the_row_cap() {
    // Production budget (main.rs): 64 MiB. Maximum-size records exhaust the byte budget first.
    let budget = 64 * 1024 * 1024;
    let one = largest_record(0).encode().unwrap().len();
    let (_dir, mut j, _) = journal("budget-64", budget);
    let fits = (budget / one).min(crate::candidate_journal::MAX_PROPOSALS);
    for n in 0..fits as u64 {
        j.persist_for_test(&largest_record(n), 0).unwrap();
    }
    let refused = j
        .persist_for_test(&largest_record(fits as u64), 0)
        .unwrap_err();
    assert!(refused.contains("Candidate journal full"), "{refused}");
    let stored = j.records().unwrap();
    assert_eq!(stored.len(), fits);
    assert!(
        stored
            .iter()
            .map(|r| r.encode().unwrap().len())
            .sum::<usize>()
            <= budget
    );
}

#[path = "unqualified_proposal_tests.rs"]
mod unqualified_proposal;
