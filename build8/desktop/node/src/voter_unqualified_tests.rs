//! Candidate 3, Architect decisions V1, V3 and V4 (docs/OS-CLOCK-CLASSIFICATION-V1.md, 9.10), on
//! the real `IntegratedActor`, `Driver`, `LocalProposer`, `CandidateJournal`, `VoteJournal` and
//! canonical store, with real blocks minted through the real issuance and execution path of the
//! `os_clock_tests` rig. Controlled time bases and clocks only (no host clock read); software
//! custody with deterministic TEST-VALUE keys. Windows-host software evidence: Implemented, not
//! Qualified; Offline, not Physical.
//!
//! * V4: a LOCKED validator whose clock is unqualified keeps its round timers and round progress,
//!   signs no prevote at all (neither its locked block, a fresh block vote, nor a nil vote that
//!   would escape the lock), keeps its lock, still ingests finality, and on clock recovery
//!   revalidates the current context: a vote decided for an expired round is refused.
//! * V3: an exact proof-of-lock reproposal while unqualified needs the current round, the current
//!   parent and membership, a valid proof, a stored block and a lock no newer than the proof; nothing
//!   else is reproposed and no new block or timestamp is ever selected. A receiver that has not
//!   verified the named proof does not vote the proposal and does not fault.
//! * V1: an invalid-signature conflicting finality claim creates no durable halt; a valid one does,
//!   with both proofs retained, and it survives every reopen.
use super::*;
use mutiny_consensus_v8::{
    anchors::FinalizedAnchor,
    bft::{Lock, Step},
    finality::FinalityLedger,
    voter_actor::{ActorError, VoteContext},
};
use std::time::Instant;

struct ReviewActorTimer(Arc<Mutex<Instant>>);
impl voter_actor::MonotonicTimer for ReviewActorTimer {
    fn now(&self) -> Instant {
        *self.0.lock().unwrap()
    }
}
fn install_review_actor_timer(r: &mut Rig) -> Arc<Mutex<Instant>> {
    let clock = Arc::new(Mutex::new(Instant::now()));
    r.actor
        .signing
        .as_mut()
        .unwrap()
        .voter
        .set_monotonic_timer(Arc::new(ReviewActorTimer(clock.clone())))
        .unwrap();
    clock
}

/// Independent review successor: the driver observes the production-sized round-1 interval
/// through its test-only monotonic seam. The actor's release timer and protocol signatures are
/// unchanged. This checks elapsed time, not an inflated test deadline or a sleep-based guess.
#[test]
fn review_v4_locked_nil_precommit_waits_for_driver_interval_and_retransmits_exactly() {
    let (r, block, _, _) = locked_and_unqualified();
    // Retain public fixture bytes even on panic; the test process closes its database handles.
    let mut r = std::mem::ManuallyDrop::new(r);
    eprintln!(
        "PRESERVED_PUBLIC_DRIVER_INTERVAL_FIXTURE {}",
        r._dir.0.display()
    );
    let lock = Lock { round: 0, block };
    let delay = Duration::from_secs(6);
    r.actor.set_round_delay_for_test(delay);
    let origin = Instant::now();
    let driver_time = Arc::new(Mutex::new(origin));
    r.actor
        .signing
        .as_mut()
        .unwrap()
        .voter
        .set_monotonic_timer(Arc::new(ReviewActorTimer(driver_time.clone())))
        .unwrap();
    r.actor.set_driver_time_for_test(driver_time.clone());
    let before = counter(&r.actor);
    for offset in [
        Duration::ZERO,
        delay - Duration::from_nanos(1),
        delay,
        delay + delay - Duration::from_nanos(1),
    ] {
        *driver_time.lock().unwrap() = origin + offset;
        let tick = r.actor.tick(None).unwrap();
        assert!(
            tick.consensus.publish.is_empty(),
            "early publish at {offset:?}"
        );
        assert!(tick.consensus.finalized.is_none());
        assert!(tick.consensus.advanced_round.is_none());
        let (state, prevote, precommit) = progress(&r);
        assert_eq!(state.locked.as_ref(), Some(&lock));
        assert!(prevote.is_none() && precommit.is_none());
        assert_eq!(counter(&r.actor), before);
    }
    *driver_time.lock().unwrap() = origin + delay + delay;
    let tick = r.actor.tick(None).unwrap();
    assert!(tick.consensus.prevote_withheld);
    assert!(tick.consensus.finalized.is_none());
    assert!(tick.consensus.advanced_round.is_none());
    assert_eq!(tick.consensus.publish.len(), 1);
    let nil = &tick.consensus.publish[0];
    assert_eq!(
        (nil.decision.round, nil.decision.step, nil.nil),
        (1, 3, true)
    );
    let (state, prevote, precommit) = progress(&r);
    assert_eq!(state.locked.as_ref(), Some(&lock));
    assert!(prevote.is_none());
    assert_eq!(precommit.unwrap().encode(), nil.encode());
    assert_eq!(
        counter(&r.actor),
        before + 2,
        "one reservation and its signature"
    );
    let a = &mut r.actor;
    let s = a.signing.as_mut().unwrap();
    for _ in 0..3 {
        let replay = s
            .voter
            .replay(&mut a.workers.chain, Step::Precommit, &mut s.backend)
            .unwrap()
            .unwrap();
        assert_eq!(replay.encode(), nil.encode());
    }
    assert_eq!(counter(&r.actor), before + 2);
    let deadline = r
        .actor
        .signing
        .as_ref()
        .unwrap()
        .voter
        .precommit_deadline()
        .unwrap()
        .2;
    assert!(
        matches!(
            r.actor
                .signing
                .as_mut()
                .unwrap()
                .voter
                .set_monotonic_timer(Arc::new(ReviewActorTimer(driver_time.clone()))),
            Err(ActorError::Invalid(mutiny_consensus_v8::Error::Duplicate))
        ),
        "an armed round-one timer cannot be replaced or extended"
    );
    assert_eq!(
        deadline.duration_since(*driver_time.lock().unwrap()),
        delay,
        "ordinary round-one actor interval remains six seconds"
    );
    *driver_time.lock().unwrap() = deadline - Duration::from_nanos(1);
    {
        let a = &mut r.actor;
        let s = a.signing.as_mut().unwrap();
        assert_eq!(
            s.voter
                .timeout_precommit(&mut a.workers.chain, &mut s.backend)
                .unwrap(),
            None
        );
    }
    assert_eq!(counter(&r.actor), before + 2);
    assert_eq!(progress(&r).0.locked.as_ref(), Some(&lock));
    *driver_time.lock().unwrap() = deadline;
    {
        let a = &mut r.actor;
        let s = a.signing.as_mut().unwrap();
        assert_eq!(
            s.voter
                .timeout_precommit(&mut a.workers.chain, &mut s.backend)
                .unwrap(),
            Some(2)
        );
    }
    assert_eq!(counter(&r.actor), before + 3);
    assert_eq!(progress(&r).0.locked.as_ref(), Some(&lock));
    assert_eq!(halted_or_poisoned(&r), (false, false));
}

/// A vote signed by the fixture's software TPM key (the rig's only member), outside custody. Used
/// only to build evidence rows that differ from a real vote in exactly one checked field.
fn hand_signed(mut vote: Vote) -> Vote {
    let key = TpmFixture::from_bytes((&[17; 32]).into()).unwrap();
    let signature: Signature = key.sign_prehash(&vote.signing_digest()).unwrap();
    vote.signature = signature
        .normalize_s()
        .unwrap_or(signature)
        .to_bytes()
        .into();
    vote
}
/// Write a vote row straight into the received-vote journal, bypassing ingress validation, exactly
/// as the journal stores it (key = SHA-256 of the wire). It models evidence the proposer must
/// re-check itself (a row kept from an earlier authority, or a damaged one).
fn insert_received_row(r: &Rig, vote: &Vote) {
    use sha2::Digest;
    let raw = vote.encode();
    let id: [u8; 32] = sha2::Sha256::digest(&raw).into();
    Connection::open(r._dir.0.join("received.sqlite"))
        .unwrap()
        .execute(
            "INSERT INTO received_votes VALUES(?1,?2,?3)",
            rusqlite::params![
                id.as_slice(),
                vote.decision.height.to_be_bytes().as_slice(),
                raw
            ],
        )
        .unwrap();
}
fn admit(r: &mut Rig, vote: &Vote) {
    let a = &mut r.actor;
    let record = a
        .workers
        .hooks
        .journal
        .records()
        .unwrap()
        .into_iter()
        .find(|c| c.header.block_hash() == vote.decision.block);
    a.received
        .admit(
            &mut a.workers.chain,
            vote,
            record.as_ref(),
            &a.workers.physical,
            &Fixture,
        )
        .unwrap();
}
fn halted_or_poisoned(r: &Rig) -> (bool, bool) {
    let voter = &r.actor.signing.as_ref().unwrap().voter;
    (voter.is_halted(), voter.voter_poisoned())
}

// ---------------------------------------------------------------------------------------------
// V4: the locked/unqualified timer stall, repaired.
// ---------------------------------------------------------------------------------------------

/// Locked in round 0 on the eligible candidate, now in round 1 (a real 3 s precommit timeout), the
/// clock lost, and the driver's propose and prevote timers set to fire at once (1 ms). The
/// precommit timeout stays the actor's own 3 s * 2^round. The local proposer (this node is the
/// only member, so it is scheduled every round) re-proposes the held lock each round.
fn locked_and_unqualified() -> (Rig, Hash, Vote, Vote) {
    let mut r = build(true, true, &[]);
    long_round(&mut r);
    let (block, prevote, precommit) = hold_a_lock(&mut r);
    r.set_time(false, r.ts);
    r.actor.set_round_delay_for_test(Duration::from_millis(1));
    (r, block, prevote, precommit)
}
/// Tick until round 1 times out (or fail with the stall), checking the lock on every tick.
/// Returns every vote published meanwhile. The deadline only detects a stall: the timeout itself is
/// the actor's 6 s precommit timeout of round 1; the rest is slack for slow ticks on a loaded host.
fn run_round_one_unqualified(r: &mut Rig, lock: &Lock) -> Vec<Vote> {
    let mut published = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let t = r
            .actor
            .tick(None)
            .expect("a tick while the clock is unqualified is never a fault");
        assert!(t.consensus.finalized.is_none());
        published.extend(t.consensus.publish.iter().cloned());
        let (state, prevote, _) = progress(r);
        assert_eq!(
            state.locked.as_ref(),
            Some(lock),
            "the lock is preserved on every tick"
        );
        if let Some(next) = t.consensus.advanced_round {
            assert_eq!(next, 2, "round 1 timed out");
            return published;
        }
        assert_eq!(state.round, 1);
        assert!(
            prevote.is_none(),
            "no prevote decision exists for round 1, of any kind"
        );
        assert!(
            Instant::now() < deadline,
            "round 1 never advanced while the clock was unqualified: the locked/unqualified timer \
             stall (Architect decision V4)"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn v4_a_locked_validator_keeps_round_progress_while_unqualified_with_no_prevote_and_its_lock() {
    // Reproduces the stall first: before the repair the locked validator's propose-timeout
    // prevote (a fresh vote for its locked block) was deferred and the driver returned early, so it
    // never precommitted, never armed its precommit timeout and stayed in round 1 forever (this test
    // then fails at the deadline above).
    let (mut r, block, _, _) = locked_and_unqualified();
    let lock = Lock { round: 0, block };
    let start = counter(&r.actor);
    let published = run_round_one_unqualified(&mut r, &lock);
    let (state, _, _) = progress(&r);
    assert_eq!(state.round, 2);
    assert_eq!(
        state.locked,
        Some(lock),
        "the lock is preserved across the unqualified interval"
    );
    // The only votes of the unqualified interval are the round's NIL PRECOMMIT (retransmitted):
    // no prevote at all (no nil prevote fabricated to escape the lock, no block prevote), and no
    // block vote of any step.
    assert!(!published.is_empty(), "the precommit step was taken");
    for v in &published {
        assert_eq!(
            (v.decision.round, v.decision.step, v.nil),
            (1, 3, true),
            "{v:?}"
        );
    }
    assert_eq!(
        counter(&r.actor),
        start + 3,
        "the nil precommit (reservation and signature) and the round timeout; nothing else"
    );
    assert!(r.actor.runtime_fault().is_none());
    assert_eq!(halted_or_poisoned(&r), (false, false));
}

#[test]
fn v4_the_withheld_prevote_is_reported_and_clock_recovery_refuses_a_stale_round_vote() {
    let (mut r, block, _, _) = locked_and_unqualified();
    let lock = Lock { round: 0, block };
    // The driver reports the withheld prevote while it takes the round's steps without one.
    let t = r.actor.tick(None).unwrap();
    std::thread::sleep(Duration::from_millis(20));
    let u = r.actor.tick(None).unwrap();
    assert!(
        t.consensus.prevote_withheld || u.consensus.prevote_withheld,
        "the propose timeout fired and the prevote was withheld"
    );
    run_round_one_unqualified(&mut r, &lock);
    let stale = VoteContext {
        height: 1,
        round: 1,
    };
    let current = VoteContext {
        height: 1,
        round: 2,
    };
    // The clock returns. A vote that was DECIDED for round 1 (deferred then) is presented again
    // now that round 1 has expired: it is refused, explicitly and without any effect, for every
    // step and target, before the clock, the latch, the reducer or custody are consulted.
    r.set_time(true, r.ts);
    let before = counter(&r.actor);
    {
        let a = &mut r.actor;
        let w = &mut a.workers;
        let s = a.signing.as_mut().unwrap();
        assert_eq!(s.voter.context().unwrap(), current);
        for (step, target) in [
            (Step::Prevote, None),
            (Step::Prevote, Some(block)),
            (Step::Precommit, None),
            (Step::Precommit, Some(block)),
        ] {
            let e = s
                .voter
                .sign_for(&mut w.chain, stale, step, target, None, &mut s.backend)
                .unwrap_err();
            assert!(
                matches!(
                    e,
                    ActorError::StaleContext { requested, current: now }
                        if requested == stale && now == current
                ),
                "{step:?}/{target:?}: {e:?}"
            );
            assert!(!e.is_time_deferral());
            assert!(!s.voter.is_halted() && !s.voter.voter_poisoned());
        }
    }
    assert_eq!(
        counter(&r.actor),
        before,
        "nothing signed for the expired round"
    );
    // The driver re-derives the CURRENT context: it prevotes the locked block in round 2 (its
    // timestamp is eligible now), precommits it and the height finalizes. No round-1 vote is signed.
    let done = r.actor.tick(None).unwrap();
    assert_eq!(
        done.consensus.publish.len(),
        2,
        "{:?}",
        done.consensus.publish
    );
    for (v, step) in done.consensus.publish.iter().zip([2, 3]) {
        assert_eq!(
            (v.decision.round, v.decision.step, v.nil, v.decision.block),
            (2, step, false, block)
        );
    }
    assert_eq!(done.consensus.finalized, Some(block));
    assert!(!done.consensus.prevote_withheld);
}

#[test]
fn v4_a_passed_prevote_step_is_never_signed_when_the_clock_returns_within_the_round() {
    let (mut r, block, _, _) = locked_and_unqualified();
    let lock = Lock { round: 0, block };
    // Round 1 runs until its NIL precommit is taken: the prevote step passed without a vote.
    let deadline = Instant::now() + Duration::from_secs(90);
    while progress(&r).2.is_none() {
        assert!(
            Instant::now() < deadline,
            "the precommit step was never taken"
        );
        r.actor.tick(None).unwrap();
        std::thread::sleep(Duration::from_millis(20));
    }
    let (state, prevote, precommit) = progress(&r);
    assert_eq!(state.round, 1);
    assert!(prevote.is_none());
    assert!(precommit.unwrap().nil);
    // The clock returns before round 1 times out. The locked block is eligible now, but round 1's
    // prevote step has passed: nothing is signed for it, only the nil precommit is retransmitted.
    // (A very slow host may let round 1 time out meanwhile; the loop then stops at that tick, and
    // the round-1 checks still cover every tick before it.)
    r.set_time(true, r.ts);
    let before = counter(&r.actor);
    let mut recovered = 0;
    for tick in 0..3 {
        let t = r.actor.tick(None).unwrap();
        for v in t.consensus.publish.iter().filter(|v| v.decision.round == 1) {
            assert_eq!(
                (v.decision.step, v.nil),
                (3, true),
                "tick {tick}: in round 1 only the nil precommit is ever sent"
            );
        }
        // The tick's prevote step ran inside round 1 (a timeout advances only at its end).
        assert!(t.consensus.prevote_withheld, "tick {tick}");
        recovered += 1;
        if t.consensus.advanced_round.is_some() {
            break;
        }
        assert!(
            progress(&r).1.is_none(),
            "tick {tick}: no prevote decision for round 1"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(recovered > 0, "no recovered tick ran inside round 1");
    if progress(&r).0.round == 1 {
        assert_eq!(counter(&r.actor), before, "retransmission only");
    }
    assert_eq!(progress(&r).0.locked, Some(lock));
}

#[test]
fn v4_finality_is_ingested_while_locked_and_unqualified_and_signs_nothing() {
    let (mut r, block, prevote, precommit) = locked_and_unqualified();
    // The round-0 votes reach the journal late, as ordinary authenticated ingress (synchronization):
    // the precommit certifies the locked block.
    admit(&mut r, &prevote);
    admit(&mut r, &precommit);
    let before = counter(&r.actor);
    let t = r
        .actor
        .tick(None)
        .expect("finalized ingestion reads no clock");
    assert_eq!(t.consensus.finalized, Some(block));
    assert!(
        t.consensus.publish.is_empty(),
        "no vote is signed while unqualified"
    );
    assert_eq!(r.actor.workers.chain.load().unwrap().0.height, 1);
    assert_eq!(r.actor.signing.as_ref().unwrap().voter.height(), 2);
    assert_eq!(
        counter(&r.actor),
        before + 1,
        "only the custody advance to the next height"
    );
    assert_eq!(halted_or_poisoned(&r), (false, false));
}

// ---------------------------------------------------------------------------------------------
// V3: exact validated locked-block reproposals while unqualified.
// ---------------------------------------------------------------------------------------------

/// Round 0: this validator prevotes the eligible candidate E and precommits NIL (it takes no
/// lock: the reducer locks only on its own precommit for a block), the round times out (a real 3 s
/// precommit timeout) and round 1 starts UNLOCKED. The round-0 prevote for E, a proof of lock for
/// round 0, is returned and NOT admitted to the received-vote journal.
fn unlocked_in_round_one(r: &mut Rig) -> (Hash, Vote) {
    let actor_time = install_review_actor_timer(r);
    let record = r.eligible.clone().unwrap();
    let block = record.header.block_hash();
    let a = &mut r.actor;
    let w = &mut a.workers;
    let s = a.signing.as_mut().unwrap();
    s.voter
        .validate_candidate(
            &mut w.chain,
            voter_actor::Proposal {
                header: &record.header,
                body: &record.body,
                authority: &record.authority,
                signature: &record.signature,
            },
            &w.physical,
            &w.verifier,
        )
        .unwrap();
    let prevote = s
        .voter
        .sign(
            &mut w.chain,
            Step::Prevote,
            Some(block),
            None,
            &mut s.backend,
        )
        .unwrap();
    s.voter.observe(&prevote).unwrap();
    let precommit = s
        .voter
        .sign(&mut w.chain, Step::Precommit, None, None, &mut s.backend)
        .unwrap();
    assert!(precommit.nil);
    s.voter.observe(&precommit).unwrap();
    *actor_time.lock().unwrap() += Duration::from_secs(3);
    assert_eq!(
        s.voter
            .timeout_precommit(&mut w.chain, &mut s.backend)
            .unwrap(),
        Some(1)
    );
    let (state, _, _) = s.voter.progress().unwrap();
    assert_eq!((state.round, state.locked), (1, None));
    (block, prevote)
}

#[test]
fn v3_an_exact_proof_of_lock_reproposal_needs_round_parent_membership_proof_and_its_own_block() {
    let mut r = build(true, true, &[]);
    long_round(&mut r);
    let (block, prevote) = unlocked_in_round_one(&mut r);
    r.set_time(false, r.ts);
    let unchanged = |r: &Rig| (stores(r), journal_bytes(r), counter(&r.actor));
    let before = unchanged(&r);
    // Each row below is a VALIDLY SIGNED round prevote for a block that differs from the real proof
    // of lock in exactly one checked field. None of them is a proof the proposer may use, and with
    // no lock and no qualified clock it then selects, signs and persists nothing.
    let mut current_round = prevote.decision.clone();
    current_round.round = 1;
    let mut later_round = prevote.decision.clone();
    later_round.round = 7;
    let mut other_parent = prevote.decision.clone();
    other_parent.previous_finalized_anchor[0] ^= 1;
    let mut other_membership = prevote.decision.clone();
    other_membership.membership[0] ^= 1;
    let mut not_stored = prevote.decision.clone();
    not_stored.block = [0xab; 32];
    for (what, decision) in [
        (
            "a quorum of the CURRENT round proves no earlier lock",
            current_round,
        ),
        ("a later round", later_round),
        ("another parent", other_parent),
        ("another membership", other_membership),
        (
            "a block this node does not hold: re-proposing it would need a new block and timestamp",
            not_stored,
        ),
    ] {
        insert_received_row(
            &r,
            &hand_signed(Vote {
                decision,
                ..prevote.clone()
            }),
        );
        assert!(propose(&mut r).is_none(), "{what}: nothing is reproposed");
        assert_eq!(unchanged(&r), before, "{what}: nothing selected or written");
    }
    // The REAL proof (the same signed prevote, admitted through validated ingress) is re-proposed
    // exactly: the stored block, its proof round, the current round, the current parent and this
    // proposer's current generation; and it verifies against the canonical schedule.
    admit(&mut r, &prevote);
    let proposal = propose(&mut r).expect("an exact proof-of-lock reproposal needs no clock");
    assert_eq!(
        (proposal.block, proposal.pol_round, proposal.round),
        (block, Some(0), 1)
    );
    {
        let a = &mut r.actor;
        let chain = &mut a.workers.chain;
        let (tip, state) = chain.load_effective().unwrap();
        let (parent, _) = chain.execution_parent(tip.height).unwrap();
        let authority = voter_actor::authority(&parent, &state).unwrap();
        assert_eq!(proposal.parent, authority.parent);
        assert_eq!(
            proposal.generation,
            state.membership.controls[&r.node].generation
        );
        proposal.verify_current(chain, (1, r.node)).unwrap();
    }
    assert_eq!(
        journal_bytes(&r),
        before.1,
        "the stored block is unchanged: nothing new selected or built"
    );
    assert_eq!(persisted_proposals(&r), vec![proposal.encode()]);
}

#[test]
fn v3_an_invalid_proof_is_never_reproposed_and_refuses_selection_without_writing() {
    let mut r = build(true, true, &[]);
    long_round(&mut r);
    let (_, prevote) = unlocked_in_round_one(&mut r);
    r.set_time(false, r.ts);
    let before = (stores(&r), journal_bytes(&r), counter(&r.actor));
    // The real prevote with one signature bit flipped: a forged proof of lock.
    let mut forged = prevote.clone();
    forged.signature[5] ^= 1;
    insert_received_row(&r, &forged);
    for (qualified, ts) in [(false, r.ts), (true, r.ts)] {
        r.set_time(qualified, ts);
        let a = &mut r.actor;
        let s = a.signing.as_mut().unwrap();
        let e = s
            .proposer
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
            .unwrap_err();
        assert!(e.contains("BadSignature"), "{qualified}: {e}");
    }
    assert_eq!(
        (stores(&r), journal_bytes(&r), counter(&r.actor)),
        before,
        "nothing selected, signed or written"
    );
}

#[test]
fn v3_a_proof_of_lock_older_than_the_held_lock_is_never_reproposed() {
    // E at the fixture timestamp, F one second later with a lower hash.
    let mut r = build(true, true, &[1]);
    let actor_time = install_review_actor_timer(&mut r);
    long_round(&mut r);
    let e = r.eligible.clone().unwrap();
    let f = r.future[0].clone();
    r.set_time(true, r.ts + 1);
    let (e_block, f_block) = (e.header.block_hash(), f.header.block_hash());
    let f_prevote = {
        let a = &mut r.actor;
        let w = &mut a.workers;
        let s = a.signing.as_mut().unwrap();
        for record in [&e, &f] {
            s.voter
                .validate_candidate(
                    &mut w.chain,
                    voter_actor::Proposal {
                        header: &record.header,
                        body: &record.body,
                        authority: &record.authority,
                        signature: &record.signature,
                    },
                    &w.physical,
                    &w.verifier,
                )
                .unwrap();
        }
        // Round 0: prevote F, precommit NIL, no lock; the round times out.
        let f_prevote = s
            .voter
            .sign(
                &mut w.chain,
                Step::Prevote,
                Some(f_block),
                None,
                &mut s.backend,
            )
            .unwrap();
        s.voter.observe(&f_prevote).unwrap();
        let nil = s
            .voter
            .sign(&mut w.chain, Step::Precommit, None, None, &mut s.backend)
            .unwrap();
        assert!(nil.nil);
        s.voter.observe(&nil).unwrap();
        *actor_time.lock().unwrap() += Duration::from_secs(3);
        assert_eq!(
            s.voter
                .timeout_precommit(&mut w.chain, &mut s.backend)
                .unwrap(),
            Some(1)
        );
        // Round 1: prevote and precommit E: the validator locks E in round 1; the round times out.
        let prevote = s
            .voter
            .sign(
                &mut w.chain,
                Step::Prevote,
                Some(e_block),
                None,
                &mut s.backend,
            )
            .unwrap();
        s.voter.observe(&prevote).unwrap();
        let precommit = s
            .voter
            .sign(
                &mut w.chain,
                Step::Precommit,
                Some(e_block),
                None,
                &mut s.backend,
            )
            .unwrap();
        assert!(!precommit.nil);
        s.voter.observe(&precommit).unwrap();
        *actor_time.lock().unwrap() += Duration::from_secs(6);
        assert_eq!(
            s.voter
                .timeout_precommit(&mut w.chain, &mut s.backend)
                .unwrap(),
            Some(2)
        );
        f_prevote
    };
    let (state, _, _) = progress(&r);
    assert_eq!(
        (state.round, state.locked),
        (
            2,
            Some(Lock {
                round: 1,
                block: e_block
            })
        )
    );
    // Only the round-0 proof for F is durable evidence here (the round-1 votes are not admitted).
    admit(&mut r, &f_prevote);
    r.set_time(false, r.ts);
    let proposal = propose(&mut r).expect("the held lock is re-proposed without a clock");
    assert_eq!(
        (proposal.block, proposal.pol_round, proposal.round),
        (e_block, None, 2),
        "a proof of lock older than the held lock (F, round 0) never displaces the lock (E, round 1)"
    );
}

#[test]
fn v3_a_receiver_that_has_not_verified_the_named_proof_does_not_vote_and_does_not_fault() {
    // The proposer and the receiver are two processes of the same single-member fixture (same
    // keys, same canonical state). The proposer holds the round-0 proof of lock for E and
    // re-proposes E in round 1 with it; the receiver has not received those votes yet.
    let mut p = build(true, true, &[]);
    long_round(&mut p);
    let (block, prevote) = unlocked_in_round_one(&mut p);
    admit(&mut p, &prevote);
    let proposal = propose(&mut p).expect("proof-of-lock reproposal");
    assert_eq!((proposal.block, proposal.pol_round), (block, Some(0)));
    let mut r = build(true, true, &[]);
    long_round(&mut r);
    unlocked_in_round_one(&mut r);
    // A restart forgets the round-0 votes this receiver observed in memory, and it runs without a
    // local proposer, so the incoming proposal is the one it acts on.
    r.restart();
    r.actor.signing.as_mut().unwrap().proposer = None;
    r.actor.round_proposal(proposal.clone()).unwrap();
    let before = counter(&r.actor);
    // Qualified and eligible: the only obstacle is the unverified proof. Before the repair this tick
    // returned the reducer's InvalidProof as an error, which the actor service latches as a fault.
    for tick in 0..3 {
        let t = r
            .actor
            .tick(None)
            .unwrap_or_else(|e| panic!("tick {tick}: an unverified proof is not a fault: {e}"));
        assert!(
            t.consensus.publish.is_empty(),
            "tick {tick}: not votable yet"
        );
    }
    assert_eq!(counter(&r.actor), before);
    assert!(r.actor.runtime_fault().is_none());
    assert_eq!(halted_or_poisoned(&r), (false, false));
    // The proof arrives through validated ingress: the same proposal is now votable and the height
    // finalizes on it.
    admit(&mut r, &prevote);
    let done = r.actor.tick(None).unwrap();
    assert_eq!(
        done.consensus.publish.len(),
        2,
        "{:?}",
        done.consensus.publish
    );
    assert!(
        done.consensus
            .publish
            .iter()
            .all(|v| !v.nil && v.decision.block == block)
    );
    assert_eq!(done.consensus.finalized, Some(block));
}

// ---------------------------------------------------------------------------------------------
// V1: invalid signatures never create a durable finality halt; valid conflicting finality does.
// ---------------------------------------------------------------------------------------------

/// Finalize one height-1 candidate through the real driver: E with the clock at its timestamp
/// (F is one second ahead and not eligible), F with the clock one second later (lower hash).
fn finalize(r: &mut Rig, ts: u64, expected: Hash) -> BlockEnvelope {
    r.set_time(true, ts);
    let t = r.actor.tick(None).unwrap();
    assert_eq!(t.consensus.finalized, Some(expected));
    BlockEnvelope::decode(&r.actor.workers.chain.block_bytes(1).unwrap().unwrap()).unwrap()
}
fn genesis_anchor(r: &mut Rig) -> FinalizedAnchor {
    let (parent, _) = r.actor.workers.chain.execution_parent(0).unwrap();
    FinalizedAnchor {
        network: mutiny_consensus_v8::NETWORK_ID,
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        height: 0,
        block: parent.block,
    }
}

#[test]
fn v1_an_invalid_signature_finality_claim_creates_no_durable_halt_and_a_valid_conflict_does() {
    let mut a = build(true, true, &[1]);
    long_round(&mut a);
    let mut b = build(true, true, &[1]);
    long_round(&mut b);
    let (e, f) = (
        a.eligible.as_ref().unwrap().header.block_hash(),
        a.future[0].header.block_hash(),
    );
    assert_eq!(
        b.future[0].header.block_hash(),
        f,
        "same fixture, same blocks"
    );
    let ts = a.ts;
    let first = finalize(&mut a, ts, e);
    let rival = finalize(&mut b, ts + 1, f);
    assert_ne!(first.block_hash(), rival.block_hash());
    // A conflicting finality claim for height 1 whose certificate signature is invalid: refused by
    // verification, before anything is recorded. No proof is stored and no halt is written, the
    // voter stays healthy and every reopen works.
    let mut forged = rival.clone();
    forged.certificate.signers[0].signature[7] ^= 1;
    a.set_time(false, ts);
    let e1 = a.actor.commit(&forged).unwrap_err();
    assert!(!e1.contains("IntegrityHalt"), "{e1}");
    assert!(!a.actor.workers.chain.integrity_halted().unwrap());
    let anchor = genesis_anchor(&mut a);
    let chain_path = a._dir.0.join("chain.sqlite");
    {
        let ledger = FinalityLedger::open(&chain_path, &anchor).unwrap();
        assert!(!ledger.halted().unwrap());
        assert!(
            ledger.evidence(1, f).unwrap().is_none(),
            "no forged proof stored"
        );
        assert_eq!(ledger.evidence(1, e).unwrap().unwrap(), first.certificate);
    }
    a.actor.tick(None).expect("the actor is healthy");
    try_restart(&mut a).expect("an invalid signature never refuses a reopen");
    // The VALID conflicting certificate is genuine conflicting finality evidence: durable halt,
    // both proofs retained, the reopen refused, every tick refused.
    let e2 = a.actor.commit(&rival).unwrap_err();
    assert!(e2.contains("IntegrityHalt"), "{e2}");
    assert!(a.actor.workers.chain.integrity_halted().unwrap());
    {
        let ledger = FinalityLedger::open(&chain_path, &anchor).unwrap();
        assert!(ledger.halted().unwrap());
        assert_eq!(ledger.evidence(1, e).unwrap().unwrap(), first.certificate);
        assert_eq!(ledger.evidence(1, f).unwrap().unwrap(), rival.certificate);
        assert_eq!(
            ledger.anchor(1).unwrap().unwrap().block,
            e,
            "never switches chain"
        );
    }
    assert!(matches!(try_restart(&mut a), Err(ActorError::Halted)));
    assert!(a.actor.tick(None).is_err());
}

#[test]
fn v4_after_a_restart_the_locked_block_is_validated_first_and_its_prevote_judged_for_time() {
    // Independent review NIT-1. After a restart the round forgets every executed proposal. With
    // 40 other stored candidates of the height (more than the 16 validations of one tick) and no
    // proposal naming the lock, the locked block must still be validated in the first tick, or the
    // locked prevote request is refused as an unknown proposal: a tick error that ActorService
    // latches as a fault.
    let (mut r, _, _, _) = locked_and_unqualified();
    let base = r.eligible.clone().unwrap();
    for n in 0..40 {
        let record = synthetic(&base, n + 1, base.header.candidate.timestamp + 50_000_000);
        r.actor
            .workers
            .hooks
            .journal
            .persist_for_test(&record, 0)
            .unwrap();
    }
    r.restart();
    r.actor.set_round_delay_for_test(Duration::from_millis(1));
    r.actor.signing.as_mut().unwrap().proposer = None;
    std::thread::sleep(Duration::from_millis(5));
    let t = r
        .actor
        .tick(None)
        .expect("the locked prevote is judged for time, not refused as unknown");
    assert!(t.consensus.prevote_withheld);
    assert!(
        t.consensus.publish.is_empty()
            || t.consensus
                .publish
                .iter()
                .all(|v| v.nil && v.decision.step == 3)
    );
}
