//! Delivery 1, timestamp upper-bound policy (Architect ruling 2 Oct 2026, 15:46 ET).
//!
//!     A fresh vote is time-eligible only when block.timestamp <= qualified_local_UTC_now.
//!
//! Controlled clocks only. This proves the RULE; it does not qualify a production clock source
//! (accuracy, drift, holdover, restart recovery, round-timing compatibility remain a named gate).
//! OFFLINE, TEST-VALUE synthetic fixture (licensed-execution-v2-public-v1.json).
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    anchors::FinalizedAnchor,
    bft::Step,
    blocks::{BlockBody, state_root},
    continuity_v2::ParentVoter,
    counter_store::MonotonicCounter,
    counter_voter::CounterVoterError,
    counter_voter_v2::{CounterSigningBackend, CounterVoter},
    execution::{State, WorkParent},
    pow::WorkHeader,
    vote_clock_v1::{
        ClockReading, ControlledClock, HighWater, TimeStatus, UnqualifiedClock, VoteClock, VoteGate,
    },
    votes::IngressError,
    votes_v2::{AuthenticatedRound, HeightAuthority},
    work_authority_v2::Authority,
};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, PublicKey, Role};
use primitive_types::U256;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

struct Backend {
    key: HybridKey,
    counter: u64,
    calls: u64,
    path: PathBuf,
}
impl MonotonicCounter for Backend {
    fn read(&mut self) -> Result<u64, String> {
        Ok(self.counter)
    }
    fn increment(&mut self) -> Result<(), String> {
        self.counter = self.counter.checked_add(1).ok_or("overflow")?;
        Ok(())
    }
}
impl CounterSigningBackend for Backend {
    fn public_key(&self) -> &PublicKey {
        self.key.public()
    }
    fn sign_vote(&mut self, message: &[u8]) -> Result<HybridSignature, String> {
        self.calls += 1;
        self.key
            .sign(Domain::ContinuityVote, message)
            .map_err(|_| "sign".to_string())
    }
}
fn backend(label: &str) -> Backend {
    let path = std::env::temp_dir().join(format!(
        "build8-vote-time-{label}-{}.sqlite",
        std::process::id()
    ));
    assert!(!path.exists());
    Backend {
        key: HybridKey::generate(Role::Continuity).unwrap(),
        counter: 100,
        calls: 0,
        path,
    }
}
fn authority(key: &PublicKey, parent: &WorkParent) -> HeightAuthority {
    let tpm = p256::ecdsa::SigningKey::from_bytes((&[9; 32]).into())
        .unwrap()
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    HeightAuthority {
        parent: FinalizedAnchor {
            network: NETWORK_ID,
            genesis: parent.genesis,
            fingerprint: parent.fingerprint,
            height: parent.height,
            block: parent.block,
        },
        membership: [6; 32],
        reputation: [7; 32],
        attestation: [8; 32],
        activation_rule: None,
        voters: [(
            [9; 32],
            ParentVoter {
                lineage: [9; 32],
                admitted: true,
                physical: true,
                eligible: true,
                revoked: false,
                hardware_generation: 1,
                key_generation: 1,
                tpm_public: tpm,
                profile: [10; 32],
                public: key.clone(),
                reputation: U256::one(),
            },
        )]
        .into_iter()
        .collect(),
    }
}
fn fixture() -> (State, WorkParent, WorkHeader, Authority, BlockBody) {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/licensed-execution-v2-public-v1.json"
    ))
    .unwrap();
    assert_eq!(f["synthetic_only"], true);
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let records: Vec<(Hash, Vec<u8>)> = f["parent_records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
        .collect();
    let state = State::from_records(&records, state_root(&records).unwrap()).unwrap();
    let b = &f["blocks"][0];
    let header = WorkHeader::decode(&raw(&b["header"])).unwrap();
    let c = &header.candidate;
    let parent = WorkParent {
        genesis: c.genesis,
        fingerprint: c.fingerprint,
        block: c.parent,
        height: c.height - 1,
        t0: 1000,
        target: c.target,
        ancestor_timestamps: vec![1000],
    };
    (
        state,
        parent,
        header,
        Authority::decode(&raw(&b["authority"])).unwrap(),
        BlockBody::decode(&raw(&b["body"])).unwrap(),
    )
}
fn time_deferral(e: &CounterVoterError) -> Option<IngressError> {
    match e {
        CounterVoterError::Ingress(IngressError::FutureTimestamp { ahead_seconds }) => {
            Some(IngressError::FutureTimestamp {
                ahead_seconds: *ahead_seconds,
            })
        }
        CounterVoterError::Ingress(IngressError::ClockUnqualified) => {
            Some(IngressError::ClockUnqualified)
        }
        _ => None,
    }
}

#[test]
fn falsely_future_proposal_obtains_no_vote_and_changes_no_state() {
    let (state, parent, header, work, body) = fixture();
    let ts = header.candidate.timestamp;
    let block = header.block_hash();
    assert!(ts > 1, "fixture timestamp must allow a one-second-early clock");
    let mut b = backend("future");
    let a = authority(b.key.public(), &parent);
    let path = b.path.clone();
    let mut v = CounterVoter::open(&path, a.clone(), [9; 32], Some(100), &mut b).unwrap();
    v.round_mut()
        .unwrap()
        .validate_proposal(&state, &parent, &header, &work, &body)
        .unwrap();
    // The proposal executes fine against a scratch copy of state: the gate withholds only the VOTE.
    let clock = ControlledClock::at(ts - 1);
    v.set_vote_clock(clock.clone());
    assert_eq!(v.time_status(block), TimeStatus::Future { ahead_seconds: 1 });
    let counter = b.counter;
    // Precommit is deliberately not in this list: without a prevote quorum the reducer resolves a
    // precommit to NIL, which is not time-gated (see precommit_that_resolves_to_nil_is_not_time_gated;
    // a precommit that WOULD carry a block is covered by the locked-block test).
    for step in [Step::Prevote] {
        let e = v.sign(step, Some(block), None, &mut b).unwrap_err();
        assert!(
            matches!(
                time_deferral(&e),
                Some(IngressError::FutureTimestamp { ahead_seconds: 1 })
            ),
            "{e:?}"
        );
    }
    // Nothing was reserved, signed, counted or locked, and custody is not poisoned.
    assert_eq!(b.calls, 0);
    assert_eq!(b.counter, counter);
    assert_eq!(v.last_sequence(), 0);
    let (locks, prevote, precommit) = v.progress().unwrap();
    assert!(prevote.is_none() && precommit.is_none() && locks.locked.is_none());
    v.check_backend(&mut b).unwrap();
    // The reducer itself was never touched either (gate runs before prevote()/precommit()).
    let mut round = AuthenticatedRound::new(a.clone()).unwrap();
    round
        .validate_proposal(&state, &parent, &header, &work, &body)
        .unwrap();
    let refused = round.prepare_vote([9; 32], Step::Prevote, Some(block), None, 1, VoteGate::Fresh(&*clock));
    assert!(matches!(
        refused,
        Err(IngressError::FutureTimestamp { ahead_seconds: 1 })
    ));
    assert!(round.machine().state().locked.is_none());
    // Zero allowance: exactly equal is eligible, one second short is not.
    clock.set(ts);
    assert_eq!(v.time_status(block), TimeStatus::Eligible);
    let vote = v.sign(Step::Prevote, Some(block), None, &mut b).unwrap();
    assert!(!vote.nil);
    assert_eq!(vote.decision.block, block);
    assert_eq!(b.calls, 1);
    drop(v);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn deferred_proposal_becomes_eligible_only_after_full_revalidation() {
    let (state, parent, header, work, body) = fixture();
    let ts = header.candidate.timestamp;
    let block = header.block_hash();
    let mut b = backend("revalidate");
    let a = authority(b.key.public(), &parent);
    let path = b.path.clone();
    let mut v = CounterVoter::open(&path, a.clone(), [9; 32], Some(100), &mut b).unwrap();
    v.round_mut()
        .unwrap()
        .validate_proposal(&state, &parent, &header, &work, &body)
        .unwrap();
    v.set_vote_clock(ControlledClock::at(ts - 5));
    let e = v.sign(Step::Prevote, Some(block), None, &mut b).unwrap_err();
    assert!(time_deferral(&e).is_some(), "{e:?}");
    assert_eq!(b.calls, 0);
    // The deferral timer fires (clock now far past the timestamp) after a restart: custody keeps
    // no memory of the proposal, so the due timer alone authorizes nothing. It must be executed
    // again under current authority first.
    drop(v);
    let mut v = CounterVoter::open(&path, a.clone(), [9; 32], None, &mut b).unwrap();
    v.set_vote_clock(ControlledClock::at(ts + 3600));
    assert_eq!(v.time_status(block), TimeStatus::UnknownProposal);
    let e = v.sign(Step::Prevote, Some(block), None, &mut b).unwrap_err();
    assert!(matches!(
        e,
        CounterVoterError::Ingress(IngressError::UnknownProposal)
    ));
    assert_eq!(b.calls, 0);
    // A stale or different parent cannot revalidate the deferred block at all.
    let mut stale = a.clone();
    stale.parent.block[0] ^= 1;
    let mut stale_round = AuthenticatedRound::new(stale).unwrap();
    assert!(
        stale_round
            .validate_proposal(&state, &parent, &header, &work, &body)
            .is_err()
    );
    assert_eq!(stale_round.time_status(&UnqualifiedClock, block), TimeStatus::UnknownProposal);
    // Current-context revalidation succeeds; only now can the vote be cast.
    v.round_mut()
        .unwrap()
        .validate_proposal(&state, &parent, &header, &work, &body)
        .unwrap();
    assert_eq!(v.time_status(block), TimeStatus::Eligible);
    let vote = v.sign(Step::Prevote, Some(block), None, &mut b).unwrap();
    assert!(!vote.nil);
    assert_eq!(b.calls, 1);
    drop(v);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn clock_faults_abstain_and_never_silently_bypass_the_guard() {
    let (state, parent, header, work, body) = fixture();
    let ts = header.candidate.timestamp;
    let block = header.block_hash();
    let mut b = backend("faults");
    let a = authority(b.key.public(), &parent);
    let path = b.path.clone();
    let mut v = CounterVoter::open(&path, a.clone(), [9; 32], Some(100), &mut b).unwrap();
    v.round_mut()
        .unwrap()
        .validate_proposal(&state, &parent, &header, &work, &body)
        .unwrap();
    // 1. No clock installed: fail closed.
    assert_eq!(v.time_status(block), TimeStatus::Unqualified);
    let e = v.sign(Step::Prevote, Some(block), None, &mut b).unwrap_err();
    assert!(matches!(
        time_deferral(&e),
        Some(IngressError::ClockUnqualified)
    ));
    // 2. A source that loses qualification abstains, however far ahead its reading claims to be.
    let clock = ControlledClock::at(ts + 10);
    let guarded = Arc::new(HighWater::new(clock.clone()));
    v.set_vote_clock(guarded.clone());
    assert_eq!(v.time_status(block), TimeStatus::Eligible);
    clock.set_qualified(false);
    clock.set(ts + 1_000_000);
    assert_eq!(v.time_status(block), TimeStatus::Unqualified);
    assert!(v.sign(Step::Prevote, Some(block), None, &mut b).is_err());
    // 3. A reading that steps BACKWARD below the highest qualified reading is a fault.
    clock.set_qualified(true);
    clock.set(ts + 20);
    assert_eq!(v.time_status(block), TimeStatus::Eligible);
    clock.set(ts - 1);
    assert_eq!(v.time_status(block), TimeStatus::Unqualified);
    let e = v.sign(Step::Prevote, Some(block), None, &mut b).unwrap_err();
    assert!(matches!(
        time_deferral(&e),
        Some(IngressError::ClockUnqualified)
    ));
    assert_eq!(b.calls, 0);
    assert_eq!(guarded.reading(), mutiny_consensus_v8::vote_clock_v1::ClockReading::Unqualified);
    // 4. Abstaining keeps the validator in the committed authority (quorum denominator): the
    //    unchanged authority still matches, and a nil vote (not time-dependent) stays available
    //    so rounds and timeouts keep progressing.
    assert!(v.matches_authority(&a));
    let nil = v.sign(Step::Prevote, None, None, &mut b).unwrap();
    assert!(nil.nil);
    assert_eq!(b.calls, 1);
    drop(v);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn finalized_replay_reads_no_clock_and_reserved_slot_is_not_a_fresh_vote() {
    let (state, parent, header, work, body) = fixture();
    let ts = header.candidate.timestamp;
    let block = header.block_hash();
    let mut b = backend("replay");
    let a = authority(b.key.public(), &parent);
    let path = b.path.clone();
    let mut v = CounterVoter::open(&path, a.clone(), [9; 32], Some(100), &mut b).unwrap();
    let clock = ControlledClock::at(ts);
    v.set_vote_clock(clock.clone());
    v.round_mut()
        .unwrap()
        .validate_proposal(&state, &parent, &header, &work, &body)
        .unwrap();
    let prevote = v.sign(Step::Prevote, Some(block), None, &mut b).unwrap();
    v.round_mut().unwrap().observe(&prevote).unwrap();
    let precommit = v.sign(Step::Precommit, Some(block), None, &mut b).unwrap();
    v.round_mut().unwrap().observe(&precommit).unwrap();
    let calls = b.calls;
    assert_eq!(calls, 2);
    // The clock now fails entirely. Already-reserved slots are retransmitted exactly, with no
    // new signature: they were gated when created and are not fresh votes.
    clock.set_qualified(false);
    assert_eq!(v.replay(Step::Prevote, &mut b).unwrap().unwrap(), prevote);
    assert_eq!(v.replay(Step::Precommit, &mut b).unwrap().unwrap(), precommit);
    assert_eq!(
        v.sign(Step::Prevote, Some(block), None, &mut b).unwrap(),
        prevote
    );
    assert_eq!(b.calls, calls);
    // Finalized history needs no clock at all: a fresh round that has NO clock concept executes
    // the proposal, observes the certificate vote and commits it, and the envelope verifies
    // against the committed authority. A replaying machine's present time is irrelevant.
    let mut replay_round = AuthenticatedRound::new(a.clone()).unwrap();
    replay_round
        .validate_proposal(&state, &parent, &header, &work, &body)
        .unwrap();
    replay_round.observe(&prevote).unwrap();
    replay_round.observe(&precommit).unwrap();
    assert!(replay_round.commit(0, block).unwrap());
    let envelope = mutiny_consensus_v8::block_envelope_v2::BlockEnvelope {
        header: header.clone(),
        body: body.clone(),
        authority: work.clone(),
        certificate: mutiny_consensus_v8::continuity_v2::Certificate {
            decision: precommit.decision.clone(),
            votes: vec![precommit.clone()],
        },
    };
    let executed = envelope.verify_execute(&state, &parent, &a).unwrap();
    assert_eq!(executed.root, header.candidate.state_root);
    // And the result is identical whatever the (unqualified) local clock says.
    assert_eq!(UnqualifiedClock.reading(), mutiny_consensus_v8::vote_clock_v1::ClockReading::Unqualified);
    drop(v);
    std::fs::remove_file(path).unwrap();
}

/// Reads differ by call number: the first reading is `first`, every later one is `rest`.
struct Flap {
    reads: AtomicU64,
    first: ClockReading,
    rest: ClockReading,
}
impl VoteClock for Flap {
    fn reading(&self) -> ClockReading {
        if self.reads.fetch_add(1, Ordering::SeqCst) == 0 {
            self.first
        } else {
            self.rest
        }
    }
}

/// Audit finding F1: a validator that holds a lock votes its LOCKED block even when called with no
/// proposal. The gate must judge the block the reducer would return, not the caller's argument.
#[test]
fn locked_block_cannot_be_prevoted_through_a_no_proposal_call_unless_the_clock_allows_it() {
    let (state, parent, header, work, body) = fixture();
    let ts = header.candidate.timestamp;
    let block = header.block_hash();
    let mut b = backend("locked");
    let a = authority(b.key.public(), &parent);
    let path = b.path.clone();
    let mut v = CounterVoter::open(&path, a.clone(), [9; 32], Some(100), &mut b).unwrap();
    let clock = ControlledClock::at(ts);
    v.set_vote_clock(clock.clone());
    v.round_mut()
        .unwrap()
        .validate_proposal(&state, &parent, &header, &work, &body)
        .unwrap();
    let prevote = v.sign(Step::Prevote, Some(block), None, &mut b).unwrap();
    v.round_mut().unwrap().observe(&prevote).unwrap();
    let precommit = v.sign(Step::Precommit, Some(block), None, &mut b).unwrap();
    v.round_mut().unwrap().observe(&precommit).unwrap();
    // Round 0 times out: the lock on `block` survives into round 1.
    v.timeout_precommit(&mut b).unwrap();
    let calls = b.calls;
    // Clock behind the locked block's timestamp: a "no proposal" prevote would still vote the
    // locked block, so it must be refused as a future-dated vote, with nothing changed.
    clock.set(ts - 5);
    let e = v.sign(Step::Prevote, None, None, &mut b).unwrap_err();
    assert!(matches!(time_deferral(&e), Some(IngressError::FutureTimestamp { ahead_seconds: 5 })), "{e:?}");
    assert_eq!(b.calls, calls, "no signature, no counter use");
    // Unhealthy clock: abstain, same result.
    clock.set(ts + 10);
    clock.set_qualified(false);
    let e = v.sign(Step::Prevote, None, None, &mut b).unwrap_err();
    assert!(matches!(time_deferral(&e), Some(IngressError::ClockUnqualified)), "{e:?}");
    assert_eq!(b.calls, calls);
    // The refusals neither poisoned custody nor halted anything: with a healthy eligible clock
    // the locked block is voted.
    clock.set_qualified(true);
    let vote = v.sign(Step::Prevote, None, None, &mut b).unwrap();
    assert!(!vote.nil);
    assert_eq!(vote.decision.block, block);
    assert_eq!(b.calls, calls + 1);
    drop(v);
    std::fs::remove_file(path).unwrap();
}

/// Audit finding F7: a precommit that the reducer turns into nil (no prevote quorum) is not
/// time-dependent, whatever proposal the caller names.
#[test]
fn precommit_that_resolves_to_nil_is_not_time_gated() {
    let (state, parent, header, work, body) = fixture();
    let ts = header.candidate.timestamp;
    let block = header.block_hash();
    let mut b = backend("nilprecommit");
    let a = authority(b.key.public(), &parent);
    let path = b.path.clone();
    let mut v = CounterVoter::open(&path, a.clone(), [9; 32], Some(100), &mut b).unwrap();
    v.set_vote_clock(ControlledClock::at(ts - 5));
    v.round_mut()
        .unwrap()
        .validate_proposal(&state, &parent, &header, &work, &body)
        .unwrap();
    // No prevote quorum exists, so this precommit is nil even though it names a future block.
    let vote = v.sign(Step::Precommit, Some(block), None, &mut b).unwrap();
    assert!(vote.nil);
    drop(v);
    std::fs::remove_file(path).unwrap();
}

/// Audit finding F2: one signing attempt reads the clock once, so a clock change between two
/// internal reads can neither halt custody after the gate passed nor admit a vote the gate refused.
#[test]
fn one_clock_reading_per_attempt_so_flapping_cannot_poison_custody() {
    let (state, parent, header, work, body) = fixture();
    let ts = header.candidate.timestamp;
    let block = header.block_hash();
    let mut b = backend("flap");
    let a = authority(b.key.public(), &parent);
    let path = b.path.clone();
    let mut v = CounterVoter::open(&path, a.clone(), [9; 32], Some(100), &mut b).unwrap();
    v.round_mut()
        .unwrap()
        .validate_proposal(&state, &parent, &header, &work, &body)
        .unwrap();
    // Eligible on the first read, unqualified on every later one: the attempt must succeed
    // (a second read inside the attempt would have failed after the poison latch was set).
    v.set_vote_clock(Arc::new(Flap {
        reads: AtomicU64::new(0),
        first: ClockReading::Qualified { utc_seconds: ts },
        rest: ClockReading::Unqualified,
    }));
    let vote = v.sign(Step::Prevote, Some(block), None, &mut b).unwrap();
    assert!(!vote.nil);
    // Unqualified on the first read, eligible afterwards: refused, and custody is not poisoned.
    drop(v);
    std::fs::remove_file(&path).unwrap();
    let mut b = backend("flap2");
    let path = b.path.clone();
    let a = authority(b.key.public(), &parent);
    let mut v = CounterVoter::open(&path, a, [9; 32], Some(100), &mut b).unwrap();
    v.round_mut()
        .unwrap()
        .validate_proposal(&state, &parent, &header, &work, &body)
        .unwrap();
    v.set_vote_clock(Arc::new(Flap {
        reads: AtomicU64::new(0),
        first: ClockReading::Unqualified,
        rest: ClockReading::Qualified { utc_seconds: ts },
    }));
    let e = v.sign(Step::Prevote, Some(block), None, &mut b).unwrap_err();
    assert!(matches!(time_deferral(&e), Some(IngressError::ClockUnqualified)), "{e:?}");
    assert_eq!(b.calls, 0);
    let vote = v.sign(Step::Prevote, Some(block), None, &mut b).unwrap();
    assert!(!vote.nil, "not poisoned by the refused attempt");
    drop(v);
    std::fs::remove_file(path).unwrap();
}
