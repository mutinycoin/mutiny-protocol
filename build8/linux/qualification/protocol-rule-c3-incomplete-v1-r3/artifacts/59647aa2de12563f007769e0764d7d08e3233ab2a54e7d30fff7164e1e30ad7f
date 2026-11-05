//! Package P-E, Architect decision (6): an UNQUALIFIED clock must prevent selecting or constructing
//! a NEW block proposal, on every path, while the activity the protocol already authorized keeps
//! working and cannot change a stored block or signing payload. Also: a healthy actor that is only
//! waiting for time continues its permitted work across ticks, and a genuine halt survives every
//! pending time deferral across ticks and reopen.
//!
//! Everything runs against the real `IntegratedActor`, `Driver`, `LocalProposer`,
//! `CandidateJournal`, `WorkerCoordinator` and `ActorService` with a CONTROLLED time basis (see
//! `os_clock_tests`, whose rig this module reuses). No test reads the host clock. Implemented, not
//! Qualified; offline, not physical.
use super::*;
use crate::round_proposal::RoundProposal;
use mutiny_consensus_v8::{
    bft::{Lock, Step},
    votes::Vote,
};
use rusqlite::{Connection, OpenFlags, types::ValueRef};
use std::path::Path;

// ---------------------------------------------------------------------------------------------
// Whole-database fingerprints: "nothing was written" is checked on every durable table.
// ---------------------------------------------------------------------------------------------

type Dump = Vec<(String, Vec<Vec<String>>)>;
fn dump(path: &Path) -> Dump {
    let db = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE).unwrap();
    let tables: Vec<String> = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|t| t.unwrap())
        .collect();
    tables
        .into_iter()
        .map(|table| {
            let mut statement = db.prepare(&format!("SELECT * FROM \"{table}\"")).unwrap();
            let columns = statement.column_count();
            let rows = statement
                .query_map([], |r| {
                    (0..columns)
                        .map(|i| {
                            Ok(match r.get_ref(i)? {
                                ValueRef::Null => "NULL".to_string(),
                                ValueRef::Integer(n) => n.to_string(),
                                ValueRef::Real(f) => f.to_string(),
                                ValueRef::Text(t) => hex::encode(t),
                                ValueRef::Blob(b) => hex::encode(b),
                            })
                        })
                        .collect::<rusqlite::Result<Vec<_>>>()
                })
                .unwrap()
                .map(|row| row.unwrap())
                .collect();
            (table, rows)
        })
        .collect()
}
/// The stores in which a NEW proposal, candidate, work authorization or signature would leave a
/// durable trace.
fn stores(r: &Rig) -> Vec<(&'static str, Dump)> {
    [
        "proposer.sqlite",
        "work.sqlite",
        "observations.sqlite",
        "candidates.sqlite",
        "operations.sqlite",
    ]
    .into_iter()
    .filter(|name| r._dir.0.join(name).exists())
    .map(|name| (name, dump(&r._dir.0.join(name))))
    .collect()
}
/// Every wire the proposer has ever persisted (what it signed), in key order.
fn persisted_proposals(r: &Rig) -> Vec<Vec<u8>> {
    let db = Connection::open(r._dir.0.join("proposer.sqlite")).unwrap();
    db.prepare("SELECT wire FROM local_proposals ORDER BY height,round")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(|w| w.unwrap())
        .collect()
}
fn journal_bytes(r: &Rig) -> Vec<Vec<u8>> {
    let mut v: Vec<_> = r
        .actor
        .workers
        .hooks
        .journal
        .records()
        .unwrap()
        .iter()
        .map(|c| c.encode().unwrap())
        .collect();
    v.sort();
    v
}
fn propose(r: &mut Rig) -> Option<RoundProposal> {
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
}
fn long_round(r: &mut Rig) {
    r.actor.set_round_delay_for_test(Duration::from_secs(3600));
}
fn progress(
    r: &Rig,
) -> (
    mutiny_consensus_v8::bft::LockState,
    Option<Vote>,
    Option<Vote>,
) {
    r.actor.signing.as_ref().unwrap().voter.progress().unwrap()
}

// ---------------------------------------------------------------------------------------------
// 1. Nothing NEW: no selection, no signed proposal, no candidate, no work, no worker binding.
// ---------------------------------------------------------------------------------------------

#[test]
fn an_unqualified_clock_selects_signs_constructs_and_issues_nothing_new() {
    // The journal holds an eligible candidate AND a lower-hash far-future one: exactly what a
    // proposer that read the OS clock (or no clock) would pick from.
    let mut r = build(true, true, &[3600]);
    long_round(&mut r);
    let eligible = r.eligible.as_ref().unwrap().header.block_hash();
    r.set_time(false, r.ts);
    let before = stores(&r);
    let candidates_before = journal_bytes(&r);
    assert!(persisted_proposals(&r).is_empty());
    for tick in 0..3 {
        let t = r.actor.tick(None).expect("an unqualified clock defers");
        // PROPOSER: no fresh choice, so nothing is produced, advertised or published.
        assert!(t.proposal.is_none(), "tick {tick}: no new RoundProposal");
        assert!(t.consensus.publish.is_empty(), "tick {tick}");
        assert!(t.consensus.finalized.is_none(), "tick {tick}");
    }
    assert!(
        propose(&mut r).is_none(),
        "LocalProposer::propose selects nothing"
    );
    let advertised = peer_call(
        &mut r.actor,
        serde_json::json!({"id":1,"method":"get_round_proposal"}),
    );
    assert!(advertised["result"]["proposal"].is_null(), "{advertised}");
    // SIGNING: nothing was signed by the proposer key, and no TPM vote was created either.
    assert!(
        persisted_proposals(&r).is_empty(),
        "no proposal signature persisted"
    );
    assert_eq!(counter(&r.actor), START, "no vote, no counter use");
    // WORK / CANDIDATES: no work authorization for the next height, no binding of the Worker to the
    // current epoch, nothing assembled from the operation queue. (Architect decision V2: the
    // session still authenticates against finalized state, and status, stop and a bounded result
    // deferral stay available; none of them issues, binds, accepts or credits anything.)
    let refused = r.request().unwrap_err();
    assert!(refused.contains("Qualified clock unavailable"), "{refused}");
    assert_eq!(
        WorkerBackend::active(&mut r.actor, r.worker)
            .unwrap()
            .worker,
        r.worker
    );
    let status = WorkerBackend::handle(
        &mut r.actor,
        r.worker,
        WorkerMessage::Status {
            run: true,
            faults: 0,
            accepted_total: Some(0),
            state: 4,
        },
    )
    .unwrap();
    assert!(
        status == worker_protocol::heartbeat() || status == worker_protocol::retire(),
        "{status:?}"
    );
    // A FRESH result for work issued earlier is held, bounded and in memory, while unqualified: no
    // acceptance, no credit, no receipt; the reply is a heartbeat and the device keeps the result
    // in its durable outbox (decision V2). Nothing durable changes (checked below).
    let solved = r.eligible.as_ref().unwrap().header.work_bytes();
    let result = WorkerBackend::handle(
        &mut r.actor,
        r.worker,
        WorkerMessage::Result(mutiny_consensus_v8::observations::Submission {
            sequence: 1,
            previous: [0; 32],
            work: solved,
        }),
    )
    .unwrap();
    assert_eq!(result, worker_protocol::heartbeat());
    assert_eq!(r.actor.workers.deferred_results(), 1);
    // Every durable store that a new proposal, candidate, authorization or signature would touch is
    // byte-for-byte what it was, the stored candidates (eligible and far-future) included.
    assert_eq!(stores(&r), before);
    assert_eq!(journal_bytes(&r), candidates_before);
    assert_eq!(counter(&r.actor), START);
    assert!(r.actor.runtime_fault().is_none());
    // The CLOCK alone decides: the same actor, qualified, proposes exactly the eligible candidate
    // (never the lower-hash far-future one) and finalizes it.
    r.set_time(true, r.ts);
    let t = r.actor.tick(None).unwrap();
    assert_eq!(t.proposal.as_ref().map(|p| p.block), Some(eligible));
    assert_eq!(t.consensus.finalized, Some(eligible));
    assert_eq!(persisted_proposals(&r).len(), 1);
}

#[test]
fn work_for_a_new_height_needs_the_qualified_clock_and_finalized_ingestion_does_not() {
    // The fixture's own certified block is finalized while the clock is unqualified: ingestion reads
    // no clock. The height after it is a NEW height: no work may be issued for it until the clock is
    // qualified, and no state of the work coordinator changes while it is not.
    let mut r = build(false, false, &[]);
    long_round(&mut r);
    r.set_time(false, r.ts);
    let original = r.original.clone();
    let tip_before = r.actor.workers.chain.load().unwrap().0.height;
    assert!(r.actor.commit(&original).unwrap());
    assert_eq!(
        r.actor.workers.chain.load().unwrap().0.height,
        tip_before + 1
    );
    assert_eq!(r.actor.signing.as_ref().unwrap().voter.height(), 2);
    // Re-ingesting the same finalized block is idempotent, again without a clock.
    assert!(!r.actor.commit(&original).unwrap());
    let before = stores(&r);
    for _ in 0..3 {
        let t = r
            .actor
            .tick(None)
            .expect("sync and ticks proceed while unqualified");
        assert!(t.proposal.is_none());
        assert!(t.consensus.publish.is_empty());
    }
    let refused = r.request().unwrap_err();
    assert!(refused.contains("Qualified clock unavailable"), "{refused}");
    // The session authenticates against the finalized height-1 state (decision V2); that binds the
    // Worker to no new epoch and issues nothing.
    assert_eq!(
        WorkerBackend::active(&mut r.actor, r.worker)
            .unwrap()
            .worker,
        r.worker
    );
    assert_eq!(
        stores(&r),
        before,
        "no work authorization, no candidate, no signature"
    );
    assert!(r.actor.runtime_fault().is_none());
}

// ---------------------------------------------------------------------------------------------
// 2. What the protocol already authorized keeps working, and none of it can change a stored
//    block or a signing payload (byte equality).
// ---------------------------------------------------------------------------------------------

#[test]
fn a_persisted_proposal_and_the_exact_reserved_vote_are_replayed_byte_for_byte_while_unqualified() {
    let mut r = build(true, true, &[]);
    long_round(&mut r);
    let block = r.eligible.as_ref().unwrap().header.block_hash();
    let candidates = journal_bytes(&r);
    // Qualified: the proposal is chosen and persisted, the prevote reservation is committed, and
    // the TPM signature is interrupted: the exact crash point recovery must survive.
    r.fail.store(true, Ordering::SeqCst);
    assert!(r.actor.tick(None).is_err());
    let persisted = persisted_proposals(&r);
    assert_eq!(persisted.len(), 1, "one proposal, signed once");
    // The process restarts (an interrupted signer is halted in-process; only a reopen continues).
    r.fail.store(false, Ordering::SeqCst);
    r.restart();
    let reserved = progress(&r).1.expect("durable unsigned reservation");
    assert_eq!(reserved.signature, [0; 64]);
    assert_eq!(counter(&r.actor), START + 1);
    // and the qualified clock is lost.
    r.set_time(false, r.ts);
    let proposer_rows = dump(&r._dir.0.join("proposer.sqlite"));
    let mut sent: Vec<Vec<u8>> = Vec::new();
    let mut counters = Vec::new();
    for tick in 0..4 {
        let t = r
            .actor
            .tick(None)
            .unwrap_or_else(|e| panic!("tick {tick}: recovery while unqualified is no fault: {e}"));
        // Exact reproposal: the persisted bytes, the original block, the original timestamp.
        let proposal = t.proposal.expect("a persisted proposal needs no clock");
        assert_eq!(
            proposal.encode(),
            persisted[0],
            "tick {tick}: original proposal bytes"
        );
        assert_eq!(proposal.block, block);
        // Exact vote: completed once, then retransmitted identically; nothing else is created.
        assert_eq!(
            t.consensus.publish.len(),
            1,
            "tick {tick}: no second slot is signed"
        );
        let vote = &t.consensus.publish[0];
        assert!(!vote.nil);
        assert_eq!(vote.decision.id(), reserved.decision.id(), "tick {tick}");
        assert_eq!(vote.decision.block, block);
        sent.push(vote.encode());
        counters.push(counter(&r.actor));
        assert_eq!(t.consensus.time_deferred, Some(TimeStatus::Unqualified));
        assert!(t.consensus.finalized.is_none());
    }
    assert!(
        sent.windows(2).all(|w| w[0] == w[1]),
        "byte-identical retransmission"
    );
    assert!(
        counters[0] <= START + 2,
        "the completion writes at most the signed marker"
    );
    assert!(
        counters.windows(2).all(|w| w[0] == w[1]),
        "retransmission uses no counter"
    );
    // The stored block and the signed proposal payload were not touched: same bytes, same
    // timestamp, same row.
    assert_eq!(journal_bytes(&r), candidates);
    assert_eq!(
        r.eligible.as_ref().unwrap().header.candidate.timestamp,
        r.ts
    );
    assert_eq!(persisted_proposals(&r), persisted);
    assert_eq!(dump(&r._dir.0.join("proposer.sqlite")), proposer_rows);
    // The very same vote then continues the round when the clock is qualified again.
    r.set_time(true, r.ts);
    let done = r.actor.tick(None).unwrap();
    assert_eq!(done.consensus.publish[0].encode(), sent[0]);
    assert_eq!(done.consensus.finalized, Some(block));
    assert_eq!(done.proposal.unwrap().encode(), persisted[0]);
}

/// Hold a lock without finalizing: this validator prevotes and precommits the proposal in round 0,
/// the round times out, and the lock survives into round 1. Returns (block, prevote, precommit);
/// neither vote is admitted to the received-vote journal.
fn hold_a_lock(r: &mut Rig) -> (Hash, Vote, Vote) {
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
        .sign(
            &mut w.chain,
            Step::Precommit,
            Some(block),
            None,
            &mut s.backend,
        )
        .unwrap();
    assert!(!precommit.nil);
    s.voter.observe(&precommit).unwrap();
    // The monotonic round deadline (3 s for round 0) must pass; elapsed time alone advances nothing
    // without the precommit quorum, which this validator's own precommit supplies.
    std::thread::sleep(Duration::from_millis(3150));
    assert_eq!(
        s.voter
            .timeout_precommit(&mut w.chain, &mut s.backend)
            .unwrap(),
        Some(1)
    );
    let (state, _, _) = s.voter.progress().unwrap();
    assert_eq!(state.round, 1);
    assert_eq!(state.locked, Some(Lock { round: 0, block }));
    (block, prevote, precommit)
}

#[test]
fn a_held_lock_is_reproposed_with_its_original_bytes_and_timestamp_while_unqualified() {
    let mut r = build(true, true, &[3600]);
    long_round(&mut r);
    let (block, _prevote, _precommit) = hold_a_lock(&mut r);
    let candidates = journal_bytes(&r);
    // The clock is lost AND regressed: a fresh choice would find nothing eligible, and the far-
    // future candidate has a lower hash than the lock. The lock wins and is never filtered.
    r.set_time(false, r.ts);
    let proposal = propose(&mut r).expect("a held lock is re-proposed without a clock");
    assert_eq!(
        proposal.block, block,
        "the locked block, not the lower-hash candidate"
    );
    assert_eq!(proposal.round, 1);
    assert_eq!(proposal.pol_round, None);
    let wire = proposal.encode();
    // The proposal commits the block hash, which commits the original header and timestamp; the
    // stored candidate bytes are untouched.
    let stored = r
        .actor
        .workers
        .hooks
        .journal
        .records()
        .unwrap()
        .into_iter()
        .find(|c| c.header.block_hash() == block)
        .unwrap();
    assert_eq!(stored.header.candidate.timestamp, r.ts);
    assert_eq!(journal_bytes(&r), candidates);
    assert_eq!(persisted_proposals(&r), vec![wire.clone()]);
    // A later clock (lost, regressed, anything) returns the persisted proposal unchanged.
    for (qualified, ts) in [(false, r.ts), (true, 1), (true, r.ts + 10_000)] {
        r.set_time(qualified, ts);
        assert_eq!(propose(&mut r).unwrap().encode(), wire);
    }
    assert_eq!(persisted_proposals(&r), vec![wire]);
    assert_eq!(journal_bytes(&r), candidates);
}

#[test]
fn a_proof_of_lock_block_is_reproposed_while_unqualified_and_changes_no_stored_block() {
    let mut r = build(true, true, &[3600]);
    long_round(&mut r);
    let (block, prevote, _precommit) = hold_a_lock(&mut r);
    // The round-0 prevote quorum is durable evidence (PoLC) in the received-vote journal.
    {
        let a = &mut r.actor;
        let record = a
            .workers
            .hooks
            .journal
            .records()
            .unwrap()
            .into_iter()
            .find(|c| c.header.block_hash() == block)
            .unwrap();
        a.received
            .admit(
                &mut a.workers.chain,
                &prevote,
                Some(&record),
                &a.workers.physical,
                &Fixture,
            )
            .unwrap();
    }
    let candidates = journal_bytes(&r);
    r.set_time(false, r.ts);
    let proposal = propose(&mut r).expect("a PoLC block is re-proposed without a clock");
    assert_eq!(proposal.block, block);
    assert_eq!(proposal.round, 1);
    assert_eq!(
        proposal.pol_round,
        Some(0),
        "the proof of lock names its round"
    );
    assert_eq!(
        journal_bytes(&r),
        candidates,
        "the stored block is unchanged"
    );
    assert_eq!(persisted_proposals(&r), vec![proposal.encode()]);
}

// ---------------------------------------------------------------------------------------------
// 3. The proposer, as the Architect confirmed it: only candidates eligible under its OWN qualified
//    clock are chosen; a held lock, a PoLC block and a persisted proposal are never filtered.
// ---------------------------------------------------------------------------------------------

#[test]
fn only_candidates_eligible_under_the_proposers_own_qualified_clock_are_chosen_zero_allowance() {
    // E at the fixture timestamp, F one second AHEAD with a lower hash.
    let mut r = build(true, true, &[1]);
    long_round(&mut r);
    let e = r.eligible.as_ref().unwrap().header.block_hash();
    let f = r.future[0].header.block_hash();
    assert!(f < e, "fixture: F wins the lowest-hash rule");
    // One second before E: nothing is eligible, nothing is signed.
    r.set_time(true, r.ts - 1);
    assert!(propose(&mut r).is_none());
    assert!(persisted_proposals(&r).is_empty());
    // Unqualified, however far ahead its reading claims to be: nothing.
    r.clock.set(r.ts + 1_000_000);
    r.basis.set_qualified(false);
    r.clock.set_qualified(false);
    assert!(propose(&mut r).is_none());
    // Exactly at E's timestamp: E only (F is one second ahead).
    r.set_time(true, r.ts);
    let p = propose(&mut r).expect("E is eligible");
    assert_eq!(p.block, e, "F is not eligible yet");
    // The choice is persisted for the round: a later clock cannot swap it for the lower-hash F.
    r.set_time(true, r.ts + 1);
    assert_eq!(propose(&mut r).unwrap().encode(), p.encode());
    assert_eq!(persisted_proposals(&r), vec![p.encode()]);
}

// ---------------------------------------------------------------------------------------------
// 4. Halting: a genuine halt survives every pending time deferral across ticks and reopen, in both
//    orders; a healthy actor that only waits for time never halts.
// ---------------------------------------------------------------------------------------------

/// An actor with a legacy, unmarked, unsigned prevote reservation under an unqualified clock: every
/// tick is a time deferral that signs nothing.
fn waiting_with_a_legacy_reservation() -> Rig {
    use mutiny_consensus_v8::{counter_store::CounterStore, votes::AuthenticatedRound};
    let mut r = build(true, true, &[]);
    long_round(&mut r);
    r.fail.store(true, Ordering::SeqCst);
    assert!(r.actor.tick(None).is_err()); // reservation committed, signature interrupted
    r.fail.store(false, Ordering::SeqCst);
    {
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
    r
}
fn try_restart(r: &mut Rig) -> std::result::Result<(), voter_actor::ActorError> {
    let a = &mut r.actor;
    let s = a.signing.as_mut().unwrap();
    let mut reopened = voter_actor::VoterActor::open(
        &r.voter_path,
        r.node,
        None,
        &mut a.workers.chain,
        &mut s.backend,
        &a.workers.physical,
        &Fixture,
    )?;
    reopened.set_vote_clock(r.clock.clone());
    s.voter = reopened;
    a.restart_driver_for_test();
    a.set_round_delay_for_test(Duration::from_secs(3600));
    Ok(())
}
/// Ticks that only wait for time: no error, a deferral, nothing signed, and the actor keeps
/// retransmitting/proposing what it already owns.
fn healthy_deferring_ticks(r: &mut Rig, why: &str) {
    let before = counter(&r.actor);
    for tick in 0..3 {
        let t = r
            .actor
            .tick(None)
            .unwrap_or_else(|e| panic!("{why}/{tick}: waiting for time is not a halt: {e}"));
        assert!(
            t.consensus.publish.is_empty(),
            "{why}/{tick}: nothing is signed"
        );
        assert_eq!(
            t.consensus.time_deferred,
            Some(TimeStatus::Unqualified),
            "{why}/{tick}"
        );
    }
    assert_eq!(counter(&r.actor), before, "{why}");
    assert!(r.actor.runtime_fault().is_none(), "{why}");
}
/// Ticks of a halted actor: every one of them fails, under every clock, and a deferral is never
/// reported for them.
fn halted_ticks(r: &mut Rig, why: &str) {
    for (qualified, ts) in [(false, r.ts), (true, r.ts - 5), (true, r.ts)] {
        r.set_time(qualified, ts);
        for tick in 0..2 {
            let e =
                r.actor.tick(None).err().unwrap_or_else(|| {
                    panic!("{why}/{qualified}/{ts}/{tick}: a halted actor ticked")
                });
            assert!(!e.is_empty());
        }
    }
}

#[test]
fn a_halt_after_pending_deferrals_stays_across_ticks_and_reopen_counter_inconsistency() {
    let mut r = waiting_with_a_legacy_reservation();
    healthy_deferring_ticks(&mut r, "before the halt");
    let signs = counter(&r.actor);
    // The backend counter no longer matches the durable reservation.
    r.actor.signing.as_mut().unwrap().backend.inner.counter += 2;
    let e = r
        .actor
        .tick(None)
        .err()
        .expect("the cause is found by the next tick");
    assert!(e.contains("Rollback") || e.contains("Halted"), "{e}");
    assert!(
        r.actor.signing.as_ref().unwrap().voter.is_halted(),
        "the voter latch is set"
    );
    halted_ticks(&mut r, "counter inconsistency");
    assert!(
        r.actor.signing.as_ref().unwrap().voter.is_halted(),
        "and stays set"
    );
    // The ActorService turns the first failed tick into a latched fault, and it never clears.
    assert!(r.actor.tick(None).is_err());
    // Reopening while the cause persists is refused.
    let e = try_restart(&mut r).unwrap_err();
    assert!(
        matches!(
            &e,
            voter_actor::ActorError::Voter(
                mutiny_consensus_v8::counter_voter::CounterVoterError::Counter(
                    mutiny_consensus_v8::counter_store::CounterError::Rollback
                )
            )
        ),
        "{e:?}"
    );
    // Only repairing the BACKEND and reopening gets a working actor back, with the durable
    // decision intact: completing it needs a qualified eligible clock (it is a legacy record).
    r.actor.signing.as_mut().unwrap().backend.inner.counter -= 2;
    try_restart(&mut r).unwrap();
    r.set_time(false, r.ts);
    healthy_deferring_ticks(&mut r, "after the repair");
    assert_eq!(counter(&r.actor), signs);
}

#[test]
fn a_halt_before_any_deferral_stays_across_ticks_and_reopen_backend_key_corruption() {
    let mut r = waiting_with_a_legacy_reservation();
    let good = r.actor.signing.as_ref().unwrap().backend.inner.key.clone();
    // The backend now reports another public key than the one the custody is bound to.
    r.actor.signing.as_mut().unwrap().backend.inner.key =
        TpmFixture::from_bytes((&[18; 32]).into()).unwrap();
    // HALT FIRST: the very first tick fails. The pending deferral (legacy reservation, unqualified
    // clock) is never delivered.
    let e = r.actor.tick(None).err().expect("a corrupt backend halts");
    assert!(!e.contains("time_deferred"), "{e}");
    assert!(
        r.actor.signing.as_ref().unwrap().voter.is_halted(),
        "the voter latch is set"
    );
    halted_ticks(&mut r, "backend key corruption");
    assert!(
        r.actor.signing.as_ref().unwrap().voter.is_halted(),
        "and stays set"
    );
    let e = try_restart(&mut r).unwrap_err();
    assert!(
        matches!(
            &e,
            voter_actor::ActorError::Voter(
                mutiny_consensus_v8::counter_voter::CounterVoterError::Invalid(
                    mutiny_consensus_v8::Error::WrongGeneration
                )
            )
        ),
        "{e:?}"
    );
    r.actor.signing.as_mut().unwrap().backend.inner.key = good;
    try_restart(&mut r).unwrap();
    r.set_time(false, r.ts);
    healthy_deferring_ticks(&mut r, "after the repair");
}

#[test]
fn a_durable_chain_integrity_halt_stays_across_ticks_and_reopen_in_both_orders() {
    for deferral_first in [true, false] {
        let mut r = waiting_with_a_legacy_reservation();
        if deferral_first {
            healthy_deferring_ticks(&mut r, "before the halt");
        }
        // The flag finality.rs writes when two certified blocks conflict at one height.
        Connection::open(r._dir.0.join("chain.sqlite"))
            .unwrap()
            .execute("UPDATE integrity SET halted=1 WHERE id=1", [])
            .unwrap();
        assert!(r.actor.workers.chain.integrity_halted().unwrap());
        halted_ticks(
            &mut r,
            &format!("integrity halt (deferral first: {deferral_first})"),
        );
        // Reopen: refused for as long as the durable flag holds.
        let e = try_restart(&mut r).unwrap_err();
        assert!(matches!(e, voter_actor::ActorError::Halted), "{e:?}");
        // Whatever the clock does afterwards.
        r.set_time(true, r.ts);
        assert!(r.actor.tick(None).is_err());
    }
}

#[test]
fn the_service_latches_a_halt_and_a_later_deferral_cannot_clear_it() {
    let r = waiting_with_a_legacy_reservation();
    // A healthy waiting actor makes the service neither fault nor stop.
    let shared = Arc::new(Mutex::new(r.actor));
    let service = crate::actor_service::ActorService::start(shared.clone()).unwrap();
    std::thread::sleep(Duration::from_millis(900));
    while let Ok(message) = service.output.try_recv() {
        assert!(message.is_ok(), "waiting for time is not a fault");
    }
    assert!(shared.lock().unwrap().runtime_fault().is_none());
    // A genuine halt appears while a deferral is pending.
    shared
        .lock()
        .unwrap()
        .signing
        .as_mut()
        .unwrap()
        .backend
        .inner
        .counter += 2;
    // (Earlier messages are the persisted proposal that every healthy tick re-offers.)
    let failure = loop {
        match service
            .output
            .recv_timeout(Duration::from_secs(20))
            .expect("the halt reaches the service")
        {
            Ok(_) => continue,
            Err(e) => break e,
        }
    };
    assert!(
        failure.contains("Rollback") || failure.contains("Halted"),
        "{failure}"
    );
    let latched = shared.lock().unwrap().runtime_fault().map(str::to_string);
    assert!(latched.is_some(), "the fault is latched");
    // The clock becomes eligible: nothing un-latches it, and every tick still fails.
    set_time(&r.basis, &r.clock, true, r.ts);
    assert!(service.stop().is_err(), "the service ended on the fault");
    let mut guard = shared.lock().unwrap();
    assert!(guard.runtime_fault().is_some());
    let e = guard.tick(None).err().expect("paused after the failure");
    assert!(e.contains("Runtime paused after actor failure"), "{e}");
}

// Candidate 3, Architect decisions V1-V4 (docs/OS-CLOCK-CLASSIFICATION-V1.md, 9.10). Declared here
// at file scope of this module file (never inside an inline module), so the paths resolve from
// node/src on every host.
#[path = "voter_unqualified_tests.rs"]
mod voter_unqualified;
#[path = "worker_unqualified_tests.rs"]
mod worker_unqualified;
