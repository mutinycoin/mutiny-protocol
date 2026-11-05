//! Candidate 3, Architect decision V2 (docs/OS-CLOCK-CLASSIFICATION-V1.md, 9.10): while the clock
//! is unqualified a Worker session still authenticates (against finalized state) for status,
//! stop, exact stored-receipt retransmission and a bounded deferral of a fresh result; binding a
//! Worker to the current epoch, issuing work, accepting or crediting a fresh result and signing a
//! new receipt stay fail-closed; finalized canonical results apply identically whatever the clock
//! says. Real `IntegratedActor` / `WorkerCoordinator` / consensus `Coordinator` over the
//! `os_clock_tests` rig, controlled time bases only. Windows-host software evidence: Implemented, not
//! Qualified; Offline, not Physical.
use super::*;
use mutiny_consensus_v8::observations::Submission;

fn solved(r: &Rig) -> Submission {
    Submission {
        sequence: 1,
        previous: [0; 32],
        work: r.eligible.as_ref().unwrap().header.work_bytes(),
    }
}
fn status(r: &mut Rig, state: u8) -> std::result::Result<Vec<u8>, String> {
    WorkerBackend::handle(
        &mut r.actor,
        r.worker,
        WorkerMessage::Status {
            run: true,
            faults: 0,
            accepted_total: Some(0),
            state,
        },
    )
}
fn result(r: &mut Rig, submission: &Submission) -> std::result::Result<Vec<u8>, String> {
    WorkerBackend::handle(
        &mut r.actor,
        r.worker,
        WorkerMessage::Result(submission.clone()),
    )
}
fn total(r: &Rig) -> u64 {
    r.actor.workers.coordinator.total(r.worker).unwrap()
}

#[test]
fn v2_stop_status_and_diagnostic_reads_stay_available_while_unqualified_and_bind_nothing_new() {
    let mut r = build(true, true, &[]);
    long_round(&mut r);
    // Qualified: the session's binding for the current epoch.
    let bound = WorkerBackend::active(&mut r.actor, r.worker).unwrap();
    r.set_time(false, r.ts);
    let before = stores(&r);
    // The session still authenticates, against the binding finalized state establishes: the same
    // canonical binding (nothing pending applies here), and nothing new is bound.
    assert_eq!(
        WorkerBackend::active(&mut r.actor, r.worker).unwrap(),
        bound
    );
    // An unknown Worker is still refused.
    assert!(WorkerBackend::active(&mut r.actor, [0xee; 32]).is_err());
    // Safe stop: no quorum lease is held yet, so a mining device is told to stop (retire) ...
    assert_eq!(status(&mut r, 4).unwrap(), worker_protocol::retire());
    // ... and an idle device keeps an authenticated status exchange (heartbeat).
    assert_eq!(status(&mut r, 2).unwrap(), worker_protocol::heartbeat());
    // Diagnostic reads need no clock either.
    let reply = peer_call(&mut r.actor, serde_json::json!({"id":1,"method":"status"}));
    assert_eq!(reply["result"]["height"], 0, "{reply}");
    assert_eq!(reply["result"]["integrity_halted"], false, "{reply}");
    // New work binds the Worker to the current epoch: refused, nothing issued.
    let refused = r.request().unwrap_err();
    assert!(
        refused.contains("Qualified clock unavailable: no new work is issued"),
        "{refused}"
    );
    assert_eq!(
        stores(&r),
        before,
        "nothing issued, accepted, credited or written"
    );
    assert_eq!(counter(&r.actor), START);
    assert!(r.actor.runtime_fault().is_none());
}

#[test]
fn v2_a_stored_receipt_is_retransmitted_byte_for_byte_while_unqualified_with_no_new_credit() {
    let mut r = build(true, true, &[]);
    long_round(&mut r);
    let submission = solved(&r);
    // Qualified: the fresh result is accepted, credited once and receipted.
    let receipt = result(&mut r, &submission).unwrap();
    assert_eq!(receipt[0], 4, "a receipt");
    assert_eq!(total(&r), 1);
    // Unqualified: the device retransmits the same result (it did not get the receipt). It gets the
    // stored receipt back, byte for byte: no acceptance, no credit, no new signature, no write.
    r.set_time(false, r.ts);
    let before = stores(&r);
    for _ in 0..3 {
        assert_eq!(result(&mut r, &submission).unwrap(), receipt);
    }
    assert_eq!(total(&r), 1, "credited exactly once");
    assert_eq!(stores(&r), before);
    assert_eq!(
        r.actor.workers.deferred_results(),
        0,
        "a retransmission is not held"
    );
    // A different result claiming the same sequence contradicts the stored checkpoint: refused,
    // never held, never credited.
    let mut conflicting = submission.clone();
    conflicting.work = r.future_work();
    assert!(result(&mut r, &conflicting).is_err());
    assert_eq!(r.actor.workers.deferred_results(), 0);
    assert_eq!(total(&r), 1);
    assert_eq!(stores(&r), before);
}

#[test]
fn v2_a_fresh_result_is_held_bounded_without_credit_or_receipt_and_processed_once_qualified() {
    let mut r = build(true, true, &[]);
    long_round(&mut r);
    let submission = solved(&r);
    r.set_time(false, r.ts);
    let before = stores(&r);
    // A full deferral (capacity 0 here) refuses the result and holds nothing.
    r.actor.workers.set_deferred_capacity_for_test(0);
    let full = result(&mut r, &submission).unwrap_err();
    assert!(full.contains("deferral full"), "{full}");
    assert_eq!(r.actor.workers.deferred_results(), 0);
    // Room for one: the fresh result is held. The reply is a heartbeat, never a receipt: the device
    // keeps the result in its durable outbox. No acceptance, no credit, no signature, no write.
    r.actor.workers.set_deferred_capacity_for_test(1);
    for _ in 0..3 {
        assert_eq!(
            result(&mut r, &submission).unwrap(),
            worker_protocol::heartbeat()
        );
        assert_eq!(r.actor.workers.deferred_results(), 1, "one per Worker");
    }
    assert_eq!(total(&r), 0, "nothing credited");
    assert_eq!(stores(&r), before, "nothing written");
    // Ticks while unqualified keep it held and process nothing.
    for _ in 0..2 {
        r.actor.tick(None).unwrap();
    }
    assert_eq!(r.actor.workers.deferred_results(), 1);
    assert_eq!(total(&r), 0);
    assert_eq!(stores(&r), before);
    // The clock is qualified again: the next tick processes it exactly like a new result (binding
    // at the current epoch, acceptance, durable receipt, credit), once.
    r.set_time(true, r.ts);
    r.actor.tick(None).unwrap();
    assert_eq!(r.actor.workers.deferred_results(), 0);
    assert_eq!(total(&r), 1, "credited once, after requalification");
    // The device's retransmission now gets the stored receipt, and nothing is credited twice.
    let receipt = result(&mut r, &submission).unwrap();
    assert_eq!(receipt[0], 4);
    assert_eq!(result(&mut r, &submission).unwrap(), receipt);
    assert_eq!(total(&r), 1);
}

#[test]
fn v2_finalized_results_apply_identically_whatever_the_clock_says() {
    // The same certified block (whose execution credits its License's Worker and pays its owner)
    // applied by two identical nodes: one with a qualified clock, one with none.
    let mut q = build(true, true, &[]);
    long_round(&mut q);
    let block = q.eligible.as_ref().unwrap().header.block_hash();
    let t = q.actor.tick(None).unwrap();
    assert_eq!(t.consensus.finalized, Some(block));
    let envelope =
        BlockEnvelope::decode(&q.actor.workers.chain.block_bytes(1).unwrap().unwrap()).unwrap();
    let mut u = build(true, true, &[]);
    long_round(&mut u);
    u.set_time(false, u.ts);
    assert!(
        u.actor.commit(&envelope).unwrap(),
        "applied while unqualified"
    );
    let (qt, qs) = q.actor.workers.chain.load().unwrap();
    let (ut, us) = u.actor.workers.chain.load().unwrap();
    assert_eq!(
        (qt.height, qt.block, qt.root, qt.next_target, qt.timestamp),
        (ut.height, ut.block, ut.root, ut.next_target, ut.timestamp)
    );
    assert_eq!(
        qs.records().unwrap(),
        us.records().unwrap(),
        "byte-identical canonical state, Worker and License records included"
    );
    assert_eq!(u.actor.signing.as_ref().unwrap().voter.height(), 2);
}

impl Rig {
    /// The work bytes of the fixture's far-future candidate when one was minted, else the eligible
    /// candidate's work with another nonce: in both cases a header for this Worker that differs from
    /// the eligible candidate's.
    fn future_work(&self) -> Vec<u8> {
        match self.future.first() {
            Some(f) => f.header.work_bytes(),
            None => {
                let mut header = self.eligible.as_ref().unwrap().header.clone();
                header.nonce = header.nonce.wrapping_add(1);
                header.work_bytes()
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Independent review, MAJOR-1 and MINOR-1.
// ---------------------------------------------------------------------------------------------

/// The fixture Workers' canonical assignments are made effective from the fixture candidate's
/// MiningEpoch E, later than the Genesis tip's epoch: finalized state alone does not make the
/// Worker active (as for an assignment that takes effect at an epoch no finalized block has reached
/// yet), qualified time at E does.
fn assignment_effective_after_the_tip() -> (Rig, u64) {
    let mut epoch = 0;
    let mut r = build_with(true, true, &[], |state, ts, t0| {
        epoch = mining_epoch(ts, t0).unwrap();
        assert!(
            epoch > 0,
            "fixture: the candidate's epoch is later than Genesis"
        );
        for w in state.licenses.workers.values_mut() {
            w.binding.effective_epoch = epoch;
        }
    });
    long_round(&mut r);
    let (parent, _) = r.actor.workers.chain.execution_parent(0).unwrap();
    (r, parent.t0)
}

#[test]
fn v2_a_worker_bound_for_an_epoch_no_finalized_block_reached_keeps_status_stop_and_retransmission()
{
    let (mut r, _) = assignment_effective_after_the_tip();
    // A process that never saw qualified time has only finalized state: the Worker is not active
    // there, so it is refused (nothing to authenticate against).
    r.set_time(false, r.ts);
    assert!(WorkerBackend::active(&mut r.actor, r.worker).is_err());
    // Qualified at epoch E: the Worker is bound, and its result is accepted and receipted.
    r.set_time(true, r.ts);
    let bound = WorkerBackend::active(&mut r.actor, r.worker).unwrap();
    let submission = solved(&r);
    let receipt = result(&mut r, &submission).unwrap();
    assert_eq!(receipt[0], 4);
    // The clock is lost before any block of epoch E is finalized. Before the repair the Worker lost
    // its session here ("Unknown Worker"): no stop, no status, no retransmission.
    r.set_time(false, r.ts);
    let before = stores(&r);
    assert_eq!(
        WorkerBackend::active(&mut r.actor, r.worker).unwrap(),
        bound
    );
    assert_eq!(status(&mut r, 4).unwrap(), worker_protocol::retire());
    assert_eq!(status(&mut r, 2).unwrap(), worker_protocol::heartbeat());
    assert_eq!(result(&mut r, &submission).unwrap(), receipt);
    // Still nothing new: no work, no credit, no write.
    assert!(
        r.request()
            .unwrap_err()
            .contains("Qualified clock unavailable")
    );
    assert_eq!(total(&r), 1);
    assert_eq!(stores(&r), before);
}

#[test]
fn v2_a_held_result_is_judged_again_at_the_epoch_the_clock_returns_to_and_dropped_uncredited() {
    let (mut r, t0) = assignment_effective_after_the_tip();
    let submission = solved(&r);
    r.set_time(true, r.ts);
    WorkerBackend::active(&mut r.actor, r.worker).unwrap();
    r.set_time(false, r.ts);
    assert_eq!(
        result(&mut r, &submission).unwrap(),
        worker_protocol::heartbeat()
    );
    assert_eq!(r.actor.workers.deferred_results(), 1);
    // Qualified time returns at an epoch at which this Worker is NOT bound (the Genesis epoch: the
    // assignment takes effect only at E). The held result is judged again with the binding at that
    // epoch, refused, and dropped: no acceptance, no credit, no receipt stored.
    let before = stores(&r);
    r.set_time(true, t0);
    assert_eq!(r.actor.workers.process_deferred_results(), 0);
    assert_eq!(r.actor.workers.deferred_results(), 0);
    assert_eq!(total(&r), 0, "nothing credited");
    assert_eq!(stores(&r), before, "nothing written");
    // The device still holds it: submitted again at epoch E it is accepted, once.
    r.set_time(true, r.ts);
    assert_eq!(result(&mut r, &submission).unwrap()[0], 4);
    assert_eq!(total(&r), 1);
}

// Append-only draft for the isolated review scratch after the mutant queue restores its source.
// TEST-VALUE controlled time; existing public twelve-license fixture; actual issued work/PoW,
// canonical execution, observation receipt signatures and candidate preservation are retained.
struct ReviewTransitionHooks<B> {
    inner: JournaledCandidates<B>,
    basis: Arc<FixedBasis>,
    transition: Option<Option<u64>>,
}
impl<B: BodyBuilder> CandidateHooks for ReviewTransitionHooks<B> {
    fn body(
        &mut self,
        chain: &mut CanonicalStore,
        binding: &BindWorker,
        timestamp: u64,
    ) -> std::result::Result<BlockBody, String> {
        self.inner.body(chain, binding, timestamp)
    }
    fn preserve<V: PhysicalAttestationVerifier>(
        &mut self,
        chain: &mut CanonicalStore,
        result: &ObservedWork,
        physical: &BTreeMap<Hash, PhysicalMember>,
        verifier: &V,
    ) -> std::result::Result<(), String> {
        self.inner.preserve(chain, result, physical, verifier)?;
        if let Some(next) = self.transition.take() {
            if let Some(seconds) = next {
                self.basis.set(seconds * 1000);
            }
            self.basis.set_qualified(next.is_some());
        }
        Ok(())
    }
}

fn review_second_worker_result(r: &mut Rig) -> (Hash, Submission) {
    let w = &mut r.actor.workers;
    let (tip, state) = w.chain.load_effective().unwrap();
    let (parent, _) = w.chain.execution_parent(tip.height).unwrap();
    let binding = state
        .licenses
        .workers
        .iter()
        .find(|(worker, active)| {
            **worker != r.worker && active.binding.coordinator_public == w.coordinator_public()
        })
        .map(|(_, active)| active.binding.clone())
        .expect("second licensed fixture Worker");
    let mut gate = WorkGate::new(
        voter_actor::authority(&parent, &state).unwrap(),
        state.root().unwrap(),
        0,
    )
    .unwrap();
    gate.set_run(true);
    let decision = gate.request(0, [0x64; 32]).unwrap().unwrap();
    let member = &state.continuity.as_ref().unwrap().members[0];
    let key = TpmFixture::from_bytes((&[17; 32]).into()).unwrap();
    let sig: Signature = key
        .sign_prehash(&decision.signing_digest(member.node, member.generation))
        .unwrap();
    gate.accept(
        1,
        &Certificate {
            decision,
            signers: vec![Signer {
                node: member.node,
                key_version: member.generation,
                signature: sig.normalize_s().unwrap_or(sig).to_bytes().into(),
            }],
        },
    )
    .unwrap();
    let body = w.hooks.body(&mut w.chain, &binding, r.ts).unwrap();
    let (issued, _) = w
        .coordinator
        .issue(
            &mut w.chain,
            &mut gate,
            MiningRequest {
                worker: binding.worker,
                license: binding.license,
                body,
                timestamp: r.ts,
                now_ms: 2,
                unix_ms: r.ts * 1000,
                observation_sequence: 0,
                observation_chain: [0; 32],
            },
            &w.physical,
            &Fixture,
            // Explicit software fixture decision clock, never a host qualification.
            || Ok((2, r.ts * 1000)),
        )
        .unwrap();
    let mut header = WorkHeader {
        candidate: issued.authority.candidate.clone(),
        authority: issued.authority.id(),
        nonce: 0,
    };
    while !meets_target(&header.digest(), &header.candidate.target) {
        header.nonce += 1;
        assert!(header.nonce < 100_000);
    }
    (
        binding.worker,
        Submission {
            sequence: 1,
            previous: [0; 32],
            work: header.work_bytes(),
        },
    )
}

#[test]
fn review_v2_qualification_loss_between_real_held_results_preserves_the_remaining_result() {
    let mut r = build(true, true, &[]);
    let first_submission = solved(&r);
    let (other, other_submission) = review_second_worker_result(&mut r);
    let basis = r.basis.clone();
    let worker = r.worker;
    let timestamp = r.ts;
    eprintln!("PRESERVED_PUBLIC_BATCH_FIXTURE {}", r._dir.0.display());
    std::mem::forget(r._dir);
    let w = r.actor.workers;
    let mut runtime = WorkerCoordinator::new(
        w.chain,
        w.coordinator,
        w.coordinator_public,
        w.physical,
        Fixture,
        ReviewTransitionHooks {
            inner: w.hooks,
            basis: basis.clone(),
            transition: Some(None),
        },
        basis.clone(),
    );
    basis.set_qualified(false);
    let submissions = BTreeMap::from([(worker, first_submission), (other, other_submission)]);
    for (&id, submission) in &submissions {
        assert_eq!(
            runtime
                .handle(id, WorkerMessage::Result(submission.clone()))
                .unwrap(),
            worker_protocol::heartbeat()
        );
        assert_eq!(runtime.coordinator.total(id).unwrap(), 0);
    }
    assert_eq!(runtime.deferred_results(), 2);
    let ids: Vec<_> = submissions.keys().copied().collect();
    basis.set(timestamp * 1000);
    basis.set_qualified(true);
    let processed = runtime.process_deferred_results();
    let totals = (
        runtime.coordinator.total(ids[0]).unwrap(),
        runtime.coordinator.total(ids[1]).unwrap(),
    );
    assert_eq!(
        (processed, totals, runtime.deferred_results()),
        (1, (1, 0), 1),
        "time was revoked after first real receipt/preservation; second result must remain uncredited"
    );
    let retained = runtime
        .coordinator
        .retransmission(ids[0], &submissions[&ids[0]].encode())
        .unwrap()
        .unwrap();
    let exact = worker_protocol::receipt(&retained.receipt);
    for _ in 0..3 {
        assert_eq!(
            runtime
                .handle(ids[0], WorkerMessage::Result(submissions[&ids[0]].clone()))
                .unwrap(),
            exact
        );
        assert_eq!(runtime.process_deferred_results(), 0);
        assert_eq!(runtime.deferred_results(), 1);
        assert_eq!(runtime.coordinator.total(ids[1]).unwrap(), 0);
    }
    basis.set_qualified(true);
    assert_eq!(runtime.process_deferred_results(), 1);
    assert_eq!(runtime.deferred_results(), 0);
    for (&id, submission) in &submissions {
        assert_eq!(runtime.coordinator.total(id).unwrap(), 1);
        let expected = runtime
            .coordinator
            .retransmission(id, &submission.encode())
            .unwrap()
            .unwrap();
        assert_eq!(
            runtime
                .handle(id, WorkerMessage::Result(submission.clone()))
                .unwrap(),
            worker_protocol::receipt(&expected.receipt)
        );
        assert_eq!(runtime.coordinator.total(id).unwrap(), 1);
    }
}

#[test]
fn review_v2_epoch_change_between_real_held_results_preserves_then_revalidates_remaining() {
    let mut r = build(true, true, &[]);
    let (parent, _) = r.actor.workers.chain.execution_parent(0).unwrap();
    let next_timestamp = parent.t0 + (mining_epoch(r.ts, parent.t0).unwrap() + 1) * 60;
    let first_submission = solved(&r);
    let (other, other_submission) = review_second_worker_result(&mut r);
    let basis = r.basis.clone();
    let timestamp = r.ts;
    let submissions = BTreeMap::from([(r.worker, first_submission), (other, other_submission)]);
    eprintln!("PRESERVED_PUBLIC_BATCH_FIXTURE {}", r._dir.0.display());
    std::mem::forget(r._dir);
    let w = r.actor.workers;
    let mut runtime = WorkerCoordinator::new(
        w.chain,
        w.coordinator,
        w.coordinator_public,
        w.physical,
        Fixture,
        ReviewTransitionHooks {
            inner: w.hooks,
            basis: basis.clone(),
            transition: Some(Some(next_timestamp)),
        },
        basis.clone(),
    );
    // Establish authentic current-epoch bindings before losing qualification.
    for &id in submissions.keys() {
        runtime.active(id).unwrap();
    }
    basis.set_qualified(false);
    for (&id, submission) in &submissions {
        assert_eq!(
            runtime
                .handle(id, WorkerMessage::Result(submission.clone()))
                .unwrap(),
            worker_protocol::heartbeat()
        );
    }
    basis.set(timestamp * 1000);
    basis.set_qualified(true);
    let ids: Vec<_> = submissions.keys().copied().collect();
    let processed = runtime.process_deferred_results();
    assert_eq!(
        (
            processed,
            runtime.coordinator.total(ids[0]).unwrap(),
            runtime.coordinator.total(ids[1]).unwrap(),
            runtime.deferred_results()
        ),
        (1, 1, 0, 1),
        "an epoch change within the batch must retain the next result for fresh revalidation"
    );
    // Next drain starts in the new epoch and revalidates the canonical binding. These two real
    // bindings remain active, so the remaining actual result is accepted exactly once. The
    // separate changed-epoch invalid-binding test retains its documented drop/retry behavior.
    assert_eq!(runtime.process_deferred_results(), 1);
    assert_eq!(runtime.deferred_results(), 0);
    assert_eq!(runtime.coordinator.total(ids[1]).unwrap(), 1);
    let stored = runtime
        .coordinator
        .retransmission(ids[1], &submissions[&ids[1]].encode())
        .unwrap()
        .unwrap();
    assert_eq!(
        runtime
            .handle(ids[1], WorkerMessage::Result(submissions[&ids[1]].clone()))
            .unwrap(),
        worker_protocol::receipt(&stored.receipt)
    );
    assert_eq!(runtime.coordinator.total(ids[1]).unwrap(), 1);
}

struct ReviewOneQualifiedReading {
    unix_ms: u64,
    calls: std::sync::atomic::AtomicUsize,
}

// Public software clock: ordinary Request observes qualified time at entry and
// after body assembly. Subsequent decision-time readings observe the transition.
// Candidate preparation, signatures, canonical state and quorum are real fixture
// paths; no protocol verdict is replaced by this controlled time source.
struct ReviewIssueDecisionClock {
    initial: u64,
    subsequent: Option<u64>,
    calls: std::sync::atomic::AtomicUsize,
}
impl mutiny_consensus_v8::holdover_clock_v1::TimeBasis for ReviewIssueDecisionClock {
    fn lower_bound_ms(&self) -> Option<u64> {
        if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2 {
            Some(self.initial)
        } else {
            self.subsequent
        }
    }
}

fn review_issue_decision_transition(subsequent: Option<u64>, expected: &str) {
    let mut r = std::mem::ManuallyDrop::new(build(true, false, &[]));
    eprintln!(
        "PRESERVED_PUBLIC_ISSUE_DECISION_FIXTURE {}",
        r._dir.0.display()
    );
    let decision = r.actor.workers.probe().unwrap().unwrap();
    let (tip, state) = r.actor.workers.chain.load_effective().unwrap();
    assert_eq!(tip.height, 0);
    let member = &state.continuity.as_ref().unwrap().members[0];
    let key = TpmFixture::from_bytes((&[17; 32]).into()).unwrap();
    let sig: Signature = key
        .sign_prehash(&decision.signing_digest(member.node, member.generation))
        .unwrap();
    r.actor
        .workers
        .accept_probe(&Certificate {
            decision,
            signers: vec![Signer {
                node: member.node,
                key_version: member.generation,
                signature: sig.normalize_s().unwrap_or(sig).to_bytes().into(),
            }],
        })
        .unwrap();
    let basis = Arc::new(ReviewIssueDecisionClock {
        initial: r.ts * 1000,
        subsequent: subsequent.map(|offset| r.ts * 1000 + offset),
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    r.actor.workers.time = basis.clone();
    let before = stores(&r);
    let outcome = r.request();
    assert!(
        outcome.is_err(),
        "new signed work escaped decision-time qualification/epoch recheck: {outcome:?}"
    );
    assert!(outcome.unwrap_err().contains(expected));
    assert_eq!(
        stores(&r),
        before,
        "refused issuance consumes no ticket and persists no authority"
    );
    assert_eq!(counter(&r.actor), START);
    assert!(
        basis.calls.load(std::sync::atomic::Ordering::SeqCst) >= 3,
        "qualified time must be sampled after preparation"
    );
    assert!(r.actor.runtime_fault().is_none());
    r.actor.workers.time = r.basis.clone();
    r.set_time(true, r.ts);
    let offer = r.request().unwrap();
    assert_eq!(
        offer[0], 5,
        "recovery may issue ordinary authenticated work"
    );
}

#[test]
fn review_v2_work_issue_refuses_qualification_loss_after_body_reading() {
    review_issue_decision_transition(None, "Qualified clock unavailable");
}

#[test]
fn review_v2_work_issue_refuses_changed_epoch_after_body_reading() {
    review_issue_decision_transition(Some(60_000), "Candidate MiningEpoch is not current");
}
impl mutiny_consensus_v8::holdover_clock_v1::TimeBasis for ReviewOneQualifiedReading {
    fn lower_bound_ms(&self) -> Option<u64> {
        (self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0).then_some(self.unix_ms)
    }
}

#[test]
fn review_v2_direct_result_rechecks_after_binding_and_keeps_exact_retransmission() {
    for accepted_before in [false, true] {
        let mut r = build(true, true, &[]);
        let submission = solved(&r);
        let expected = if accepted_before {
            result(&mut r, &submission).unwrap()
        } else {
            worker_protocol::heartbeat().to_vec()
        };
        let worker = r.worker;
        let basis = Arc::new(ReviewOneQualifiedReading {
            unix_ms: r.ts * 1000,
            calls: std::sync::atomic::AtomicUsize::new(0),
        });
        eprintln!(
            "PRESERVED_PUBLIC_DIRECT_RESULT_FIXTURE {}",
            r._dir.0.display()
        );
        std::mem::forget(r._dir);
        let w = r.actor.workers;
        let mut runtime = WorkerCoordinator::new(
            w.chain,
            w.coordinator,
            w.coordinator_public,
            w.physical,
            Fixture,
            w.hooks,
            basis.clone(),
        );
        let before = runtime.coordinator.total(worker).unwrap();
        assert_eq!(
            runtime
                .handle(worker, WorkerMessage::Result(submission.clone()))
                .unwrap(),
            expected,
            "clock expires after canonical binding: fresh result must be held, exact receipt may replay"
        );
        assert_eq!(runtime.coordinator.total(worker).unwrap(), before);
        assert_eq!(runtime.deferred_results(), usize::from(!accepted_before));
        assert!(
            basis.calls.load(std::sync::atomic::Ordering::SeqCst) >= 2,
            "fresh guard was sampled again after binding"
        );
    }
}

#[test]
fn review_v2_held_result_rechecks_after_binding_before_new_receipt() {
    let mut r = build(true, true, &[]);
    let worker = r.worker;
    let submission = solved(&r);
    r.set_time(false, r.ts);
    assert_eq!(
        result(&mut r, &submission).unwrap(),
        worker_protocol::heartbeat()
    );
    assert_eq!(r.actor.workers.deferred_results(), 1);
    let basis = Arc::new(ReviewOneQualifiedReading {
        unix_ms: r.ts * 1000,
        calls: std::sync::atomic::AtomicUsize::new(0),
    });
    eprintln!(
        "PRESERVED_PUBLIC_HELD_RESULT_FIXTURE {}",
        r._dir.0.display()
    );
    std::mem::forget(r._dir);
    let mut runtime = r.actor.workers;
    runtime.time = basis.clone();
    assert_eq!(runtime.process_deferred_results(), 0);
    assert_eq!(runtime.deferred_results(), 1);
    assert_eq!(runtime.coordinator.total(worker).unwrap(), 0);
    assert!(
        runtime
            .coordinator
            .retransmission(worker, &submission.encode())
            .unwrap()
            .is_none()
    );
    assert!(basis.calls.load(std::sync::atomic::Ordering::SeqCst) >= 2);
}
