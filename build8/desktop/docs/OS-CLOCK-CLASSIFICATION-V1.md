# OS wall-clock classification, V1

Status: Implemented, not Qualified. Offline, not Physical. Every test named here uses a controlled
time basis and controlled clocks; none reads the host clock and none is a device or field result.

Scope: `consensus/src` and `node/src`, branch `sc/osclock-coverage`. Line numbers are from the tree
at the commit that adds this file. Section 9 (explicit nonfatal time deferral, the halting latch, and
no new proposal while unqualified) is the package P-E addition on branch `succ/actor-halt`; its line
numbers are from that branch.

## 1. The rule

| Class | Meaning | Allowed time source |
|---|---|---|
| (i) | Fresh timestamp-dependent voting, work or signing authorization | Qualified time (`TimeBasis` / `VoteClock`) or the canonical block context for that rule. No silent unqualified fallback. |
| (ii) | Deterministic block validation and finalized replay | No dependence on the receiving machine's wall clock at all. |
| (iii) | Local queue management, diagnostics, display | Local time, only when it cannot change consensus validity or signing authority. |

A wall-clock read is not replaced by qualified time unless it is class (i). A class (iii) read is
left alone. A class (ii) path must read no clock.

## 2. Enforcement

`node/tests/timestamp_admission_v1.rs::no_os_wall_clock_read_outside_the_allow_list` walks every
`.rs` file under `node/src` and `consensus/src`, removes all `#[cfg(test)]` items and `*_tests.rs`
modules, strips comments, and fails on any `SystemTime` or `UNIX_EPOCH` outside the allow-list. The
allow-list has one entry (`host_clock.rs`, section 3a) and the test asserts that every entry carries a
justification. `the_time_basis_is_mandatory_and_has_no_system_clock_implementation` fails if a
`time: None` field, an `Option<Arc<dyn ...>>` basis or a `SystemClock` returns.
`admission_handlers_read_no_wall_clock` additionally pins `integrated_actor.rs` to no wall-clock
token at all. `finalized_ingestion_clock_free_v1` is unchanged and still pins the finalized path.
A NEW signed round proposal is sealed at compile time: `round_proposal.rs` keeps the signature and
the signing payload private, and its only constructor of a new signed proposal consumes a
`local_proposer::Offer` that only the proposer's selection can build (section 9.4, row 7).
`node/tests/proposal_construction_paths_v1.rs` pins that seal, the construction sites of candidates
and work, every clock implementation, every path to hybrid work preparation, the order in which each
consults qualified time, and that no actor branch on a time deferral may touch the halting latch
(section 9.4). Its matching ignores whitespace, so a line break cannot hide a site.

## 3. Inventory of remaining non-test wall-clock reads

### 3a. Wall-clock (UTC) reads in non-test code: exactly one

| path:line | read | class | justification |
|---|---|---|---|
| `node/src/host_clock.rs:307-310` (`OsWall::unix_ms`, used by `ChronySource::observe` at `:388` and wired in `HostClock::start` at `:647`) | OS UTC milliseconds | (i), allowed | This is the declared qualification mechanism, not a consumer of time. The value is only the CENTRE of an interval whose width is the NTS-authenticated chrony uncertainty plus the read window; the holdover engine (`consensus/src/holdover_clock_v1.rs`) widens it, enforces the lower bound, high-water mark, holdover limit, elapsed-uncertainty ledger, boot-id and suspend checks, and the output is `Unqualified` unless at least `min_nts_selected` authenticated sources agree. An OS-clock step between calibrations cannot move voting authority (`host_clock::tests::os_wall_clock_steps_cannot_move_voting_authority_between_calibrations`). Since the Order of 4 Oct 2026 (C4) a stored anchor never qualifies a restarted node either: every start needs a fresh authenticated sample (docs/CLOCK-PROFILE-V1.md, section 5). |

`consensus/src` contains no `SystemTime`, `UNIX_EPOCH`, `chrono` or `Utc::now` at all.
`node/src/host_clock.rs:69-94` (`mod sys`) calls `clock_gettime` only for the elapsed source
(monotonic and boottime clocks, no wall time).

### 3b. Wall-clock reads that existed and were removed

| was | class | now |
|---|---|---|
| `integrated_actor.rs` `admission_seconds`, `None` arm (OS seconds) | (iii) by effect, structural gap | `admission_seconds()` is `self.time.seconds()` (`integrated_actor.rs:82`); `None` while unqualified withholds admission. |
| `integrated_actor.rs` `tick` participation gate, `None` arm (always `Some`) | (i), vacuous gate | `admission_time = self.time.seconds()` (`integrated_actor.rs:134`); no participation operation is produced or admitted while unqualified. |
| `worker_coordinator.rs` `now()`, `None` arm (OS milliseconds became the `MiningRequest` timestamp, candidate timestamp and epoch binding) | (i) | `qualified_unix_ms()` (`worker_coordinator.rs:146`) errors while unqualified; no fallback. |
| `hybrid_coordinator_v2.rs` `SystemClock` (public `Clock` impl, no non-test user) | (i), latent | Deleted. Only `QualifiedClock` remains. |

The basis is now mandatory by construction: `WorkerCoordinator::new` takes `Arc<dyn TimeBasis>`,
`IntegratedActor::new` reads it from the coordinator, and `main.rs` requires `clock` in every runtime
configuration (the qualification schema no longer allows omitting it, which was the only production
path to `time: None`).

### 3c. Wall-clock reads in test code (excluded, verified inside `cfg(test)`)

`node/src/main.rs:232,282` (`mod runtime_ingress_tests`, `:147`), `node/src/continuity_custody_v2.rs:378`
(nested `mod tests`, `:368`) and `:670` (`mod tests`, `:490`), `node/src/host_clock.rs:955` (`mod tests`,
`:865`). `consensus/tests/storage_budget.rs:62` is an integration test. None can reach a non-test build.
(Line numbers of the clock rows re-read on branch `cand3/clock`; the other rows are unchanged.)

### 3d. Monotonic (`Instant`) reads, non-test

Monotonic time has no UTC meaning and cannot be stepped by the wall clock.

| path:line | use | class |
|---|---|---|
| `consensus/src/voter_actor.rs:429,455` (and the unwired `voter_actor_v2.rs:465,482`) | precommit timeout deadline, 3 * 2^r s capped at 120 s. `timeout_precommit` still needs the reducer's unchanged-weight quorum condition; elapsed time alone advances nothing. | (iii) |
| `node/src/voter_driver.rs:126,306` and the `started`/`prevote_started` timers | when to REQUEST a nil vote. Every request still goes through `VoterActor::sign` and the guard. Nil carries no block and is not time-dependent by design (`vote_clock_v1.rs`). | (iii) |
| `node/src/worker_coordinator.rs:130` (`started`) via `monotonic_ms()` | `WorkGate` probe and lease timing. Independent of UTC; work issuance additionally needs `qualified_unix_ms()`. | (iii), authorizes nothing alone |
| `node/src/work_probes.rs:91` | probe acceptance time (local expiry) | (iii) |
| `node/src/main.rs:1866-1875` | 1 s disk-guard poll | (iii) |
| `node/src/host_clock.rs:660,668` (`HostClock::start`, `last_poll`) | when the background thread polls chrony (`poll_due`). No signing decision depends on it: every clock reading recomputes the holdover state from the elapsed source (Order C3). | (iii) |
| `node/src/host_clock/chrony_exec.rs:102,179` | the hard deadline of one `chronyc` child and the grace for collecting a killed one (Order C3) | (iii), authorizes nothing |
| `node/src/{deadline_io,cancellable_pipe,worker_transport,worker_server,worker_carrier_v2,worker_handshake_io_v2,worker_pending_budget_v2,worker_active_connections_v2,peer_supervisor,hybrid_dispatch_v2,hybrid_peer_*_v2,tpm_backend,hybrid_coordinator_v2}.rs` | socket and IO deadlines, rate windows, handshake budgets, hybrid `QualifiedClock` monotonic part | (iii) |

(ii): nothing in `consensus/src` or `node/src` reads a receiver wall clock on a finalized-replay or
deterministic-validation path. `pow::validate_timestamp` is clock-free (median-time-past lower bound
and non-decreasing). Finalized ingestion (`commit_integrated`) is untouched.

## 4. Traced downstream effects

### 4a. `submit_operation` (operation admission)

`PeerBackend::handle("submit_operation")` -> `available()` -> `admission_seconds()`; `None` returns
`Qualified clock unavailable: operation admission withheld` -> `Assembler::admit_current_operation`.
That computes the mining epoch from the timestamp, activates due licenses on a LOCAL clone, picks an
active worker binding and calls `admit_operation`, whose `preview()` runs
`prepare_candidate_with_history` on a placeholder candidate. `OperationPool::insert_validated` stores
only the raw operation bytes. The timestamp is not persisted, not signed and not returned. When work
is issued, `assemble()` re-previews every queued operation against the WORK timestamp (the qualified
lower bound) and skips any that fail. Consensus validity is decided later by deterministic execution.
Effect of a skewed clock: wrongly reject, or wrongly enqueue, an operation in this node's local queue
(bounded by `MAX_PREVIEWS = 128` and the pool bounds). It cannot change signing authority, a vote, work
authorization or block validity. Class (iii); qualified time is used for queue hygiene and so that
no clock path exists that is not qualified.

### 4b. Participation operations (`tick`)

`admission_time` gates `Producer::produce` and the subsequent `admit_current_operation`. `produce`
takes no time argument. `ParticipationAck` and `AttestationRefresh` contain no timestamp; freshness is
height-based (`committed_height + 60 ... remaining <= 10`); the TPM signature is idempotent through the
`participation_pending` cache keyed by (anchor, state root, voting key). The clock is purely a POLICY
gate: no participation operation is produced or admitted without a qualified clock, and one is produced
on a later tick, never created and discarded. Before this change the gate was vacuous when no basis was
installed. Production could not reach that (a signing custody required `clock`), so no authority bypass
existed in a production-configured node; the structural gap is closed rather than a live exploit.

### 4c. Do these timestamps reach signed data, freshness, authority, bodies or deadlines?

No for all five. The one place the clock reached authority was `WorkerCoordinator::now()` (work
authorization and candidate timestamp), now qualified-only.

## 5. Defects found and repaired

| id | defect | severity | repair | commit |
|---|---|---|---|---|
| D1 | Silent OS-clock fallbacks (section 3b); permissive source guard blessed them. | structural, rule (i) | Mandatory basis, fallbacks and `SystemClock` removed, new guard. | f9e5ff1 |
| D2 | With a basis installed but UNQUALIFIED, `IntegratedActor::tick` failed on every call (`workers.probe()` -> `now()` -> error). `ActorService` latches a fault on any tick error and the process exits. So a cold boot with no anchor, or any later loss of qualification, stopped retransmission of an already authorized vote, nil timeouts, reconcile and finalize. Fail-closed but severe. | availability | `monotonic_ms()` for probe, accept_probe, synchronize; `qualified_unix_ms()` only for binding and issuance. `tick` no longer errors on an unqualified clock; fresh votes, work and admission still need qualified time. | f9e5ff1 |
| D3 | `LocalProposer` chose the lowest block hash with no time-eligibility filter; a far-future candidate (no upper timestamp bound by design) with a low hash could be proposed every round and end every round in nil. | liveness | `fallback_choice`: held lock first and unfiltered, else lowest hash among candidates eligible under the proposer's own qualified clock; deferred candidates stay in the journal. Decision recorded in section 7. | fe789f2 |
| D4a | Driver replay used `?`, not the deferral mapping, so a legacy unmarked unsigned reservation under an unqualified clock was a hard tick error. | availability | Mapped through `defer_status`; it can only ever complete the exact stored decision once the clock is qualified. | 6c6d6b8 |
| D4b | `VoterActor::replay` set `halted = true` and never cleared it when the error was a time deferral, so even a deferral would have halted the actor until restart. Found while repairing D4a. | availability | Reset the latch for time deferrals only (`sign` already did). SUPERSEDED by section 9: that reset was a broad `halted = false` after the latch was set. It is gone; the deferral is an explicit result taken before the latch. | 04f31af |
| D4c | One stored candidate failing `validate_candidate` aborted the whole tick (poison pill). | availability | Candidates refused by deterministic validity rules are recorded for the height, skipped, never voted and kept in the journal. Chain, custody, halt and rollback failures stay hard errors. Validation itself is unchanged. | 6c6d6b8 |
| D4d | The first tick after a restart or a burst executed every unvalidated stored candidate (up to 1,024 full body executions) in one actor-mutex hold. | availability / DoS cost | `MAX_VALIDATIONS_PER_TICK = 16`; proposal and recovered-reservation blocks first. | 6c6d6b8 |

The repairs never let a new vote, work authorization or signing happen without qualified time. The
guard `VoteGate::Fresh`, the exact-bound reservation exemption and `ReservedToken` are untouched.

## 6. Property to test map

Tests are in `node/src/os_clock_tests.rs` (module `worker_coordinator::os_clock_tests`) unless a path
is given.

| Property | Test |
|---|---|
| T-a1 count cap 1,024, 1,025th refused, rows unchanged, read fails closed before decoding any row | `journal_count_cap_is_1024_full_fails_closed_and_rows_are_unchanged` |
| T-a2 byte budget on insert and on reopen; 64 MiB production budget | `journal_byte_budget_is_enforced_on_insert_and_on_reopen`, `journal_64_mib_budget_bounds_maximum_size_records_below_the_row_cap` |
| T-a3 per-record encoded size: body bound 64 KiB, record cap 69,632, decode and read reject larger | `journal_per_record_encoded_size_cap_is_enforced_on_write_and_read` |
| T-a4 far-future flood stored, executed once, never voted, released one at a time by the clock, nothing dropped | `far_future_flood_is_stored_bounded_proposed_never_voted_and_released_by_the_clock` |
| T-a5 per-tick processing bounded; one refused candidate does not abort the tick | `per_tick_validation_is_bounded_and_one_invalid_candidate_does_not_abort_the_tick` |
| T-a6 proposer skips a lower-hash far-future candidate and discards nothing | `proposer_skips_far_future_candidates_with_lower_hashes_and_discards_nothing` |
| T-b1 held lock re-proposed unchanged and unfiltered; fresh choice time-eligible; lock bytes and timestamp unchanged | `a_held_lock_is_reproposed_unchanged_and_unfiltered_while_fresh_choice_is_time_eligible` |
| T-b1 persisted proposal returned unchanged whatever the clock does | `a_persisted_proposal_is_returned_unchanged_whatever_the_clock_does_later` |
| T-b1 vote-gate side (locked block judged as a fresh vote in its new slot) | existing: `consensus/tests/vote_timestamp_guard_v1.rs::locked_block_cannot_be_prevoted_through_a_no_proposal_call_unless_the_clock_allows_it`, `consensus/tests/bft.rs::locked_vote_survives_timeout_restart_and_delayed_round_proofs` |
| T-c1 live-voter recovery completes only the exact reserved decision under unqualified or regressed clock; new slot needs the guard | `consensus/tests/live_voter_clock_recovery_v1.rs::reserved_block_vote_recovers_identically_under_an_unqualified_or_regressed_clock`, `::sign_path_returns_the_exact_reserved_vote_without_the_clock_for_the_bound_decision` |
| T-c2 conflicting same-slot decision poisons custody; only the original completes | `consensus/tests/live_voter_clock_recovery_v1.rs::a_different_decision_in_a_reserved_slot_is_a_conflict_and_only_the_original_completes` |
| T-c3 version-1 unmarked reservation needs a qualified eligible clock, rewritten as version 3 | `consensus/tests/live_voter_clock_recovery_v1.rs::a_legacy_unmarked_unsigned_reservation_needs_a_qualified_eligible_clock_to_complete` |
| T-c4 actor under an unqualified basis: cold boot, no fault, no fresh vote/work/admission, ActorService does not latch, resumes on qualification | `cold_boot_without_an_anchor_is_a_deferral_not_a_fault_and_resumes_on_qualification` |
| T-c4 clock lost mid-run: exact reservation retransmitted, no new slot, resumes | `clock_lost_mid_run_retransmits_the_exact_reserved_vote_and_creates_no_new_one` |
| T-c4 nil/timeout and sync proceed while unqualified | `nil_timeout_votes_proceed_under_an_unqualified_clock_and_no_block_vote_is_possible`, `finalized_import_and_sync_proceed_under_an_unqualified_clock` |
| T-c4 legacy reservation under unqualified clock is a deferral, not a halt | `a_legacy_unmarked_reservation_under_an_unqualified_clock_is_a_deferral_not_a_halt` |
| T-c5 admission withheld, nothing queued, no participation operation | asserted inside the cold-boot test (`submit_operation` error text, `pending_operations` empty) |
| Source guards | `node/tests/timestamp_admission_v1.rs` (section 2) |
| Existing evidence reused | `consensus/tests/signer_reserved_recovery_v1.rs`, `consensus/tests/vote_timestamp_guard_v1.rs`, `consensus/tests/counter_voter.rs`, `worker_coordinator::tests::driver_*` |

## 7. Decision recorded: the far-future proposer stall

Chosen: filter fresh proposal choice by the proposer's own qualified clock (`timestamp <= qualified
now`, the voter's exact comparison, via `VoterActor::timestamp_status`), never filter a held lock, a
PoLC block or an already persisted proposal, and never discard a deferred candidate.

Why: with the 7,200 s hold gone `validate_timestamp` has no upper bound by design, so a licensed
coordinator that can produce valid work can make a far-future candidate with a low hash. Honest
validators defer it, so proposing it each round ends each round in nil. The filter is a local choice
(class iii): it changes no validity rule and no vote, only which valid block this node proposes.
Alternatives rejected: a wall-clock hold (reintroduces a consensus-adjacent receiver-clock dependency
and the 2 h constant the D3 ruling removed); dropping far-future candidates from the journal (loses
valid data that becomes votable, and eviction is forbidden for pending candidates); rejecting them at
admission (would add an upper bound to validity, which is a consensus change).

What the vote gate does with a locked block in a later round: it is a new (round, step) slot, so it is
a fresh vote judged like any block (`block.timestamp <= qualified now`). Only a slot that already holds
a durable gated or signed decision is exempt. The lock was created under the gate and the qualified
clock does not go backwards, so a held lock is normally still eligible; if the clock is unqualified the
validator abstains (liveness only). Nil votes stay available only to a validator WITHOUT a lock: a
locked validator's nil request is a vote for its locked block and is deferred as well (9.8).

Residual: an unqualified proposer makes no NEW proposal (nothing is eligible) until it requalifies.
Rounds still time out to nil. A proposer holding only far-future candidates proposes nothing until the
clock reaches the earliest one. Section 9 records the path trace and the tests that prove this on every
construction path, and the halt semantics that go with it.

## 8. Not done, limits

The clock decisions of the Order of 4 Oct 2026 (C1 to C12: restart state, leap policy, polling,
storage, lock, elapsed-uncertainty ledger) and their limits are in docs/CLOCK-PROFILE-V1.md,
section 10. The relevant one here: since C4 a process restart is unqualified until a fresh
authenticated calibration, so every restart behaves like the "cold boot without an anchor" of
section 6 (T-c4) until chrony answers.

* Worker `Status` and `Result` messages still require qualified time because they bind the worker for
  the current epoch before dispatch (`WorkerCoordinator::handle`). While unqualified they return a
  session error, not an actor fault. Splitting the binding from outbox draining would be a separate
  change and was not made. (Superseded in candidate 3 by Architect decision V2: section 9.10.2.)
* `ActorService` still latches a fault on any tick error that remains (genuine custody, chain or
  storage failures). Only time deferrals no longer reach it.
* A stored candidate that fails `CandidateJournal::accept` re-execution inside
  `LocalProposer::propose` still returns an error (it can only be a corrupt row, since admission
  executes the candidate). Not changed.
* `voter_actor_v2::replay` had the same halt-latch pattern as the v1 actor. Resolved in section 9: v1
  and v2 now share one design and the hybrid actor is covered by its own scenarios (the hybrid
  modules are still library code, not wired to `main.rs`).
* `Instant` (CLOCK_MONOTONIC) stops across host suspend, unlike the qualified clock's boottime check.
  A `WorkGate` lease measured in `Instant` could therefore outlive a suspend; it is capped by the
  qualified-UTC epoch remainder at issuance (`work_issuance.rs`). Not traced further.
* Per-tick cost of `candidate_journal::records()` (full decode of up to 64 MiB per call) is bounded but
  not reduced; the journal limits (1,024 records, 64 KiB body, 64 MiB budget) are unchanged and no
  test found a hole.

## 9. Explicit nonfatal time deferral, the halting latch, and no new proposal while unqualified

Status: Implemented, not Qualified. Offline, not Physical. Controlled clocks and software custody only.
Added by package P-E on branch `succ/actor-halt` (base: the self-contained candidate). Line numbers in
this section are from that branch. Candidate 3 (branch `cand3/voter`) adds 9.10, the Architect's
decisions V1-V4 of the Continuation Order (4 October 2026), and marks in 9.1, 9.3, 9.4, 9.5, 9.6, 9.8
and 9.9 what those decisions settled or changed; 9.10 refers to code by function name.

### 9.1 Architect decision (6), as implemented

1. An unqualified clock prevents selecting or constructing a NEW block proposal. Preserved, because the
   protocol already authorized them: exact locked reproposals, stored vote retransmission, completion
   of the exact previously guarded durable reservation, nil and timeout handling, synchronization and
   finalized ingestion. None of these may change a stored block or a signing payload.
2. A fresh block vote still needs the clock guard, unless it completes the exact previously guarded
   reservation.
3. A time deferral cannot clear a genuine safety halt. A healthy actor that is only waiting for time
   continues its permitted work. A halted actor stays halted across every later tick, `sign` and
   `replay`, under every clock, in both stacks. Across REOPEN the causes differ (9.3): a cause that
   lives in durable state (counter inconsistency, an unreadable counter, backend key corruption, the
   canonical integrity halt, a stored reducer halt bit, v2's unissued-own-vote bit, a corrupt record)
   is re-derived and refuses or halts the reopened actor again; a REQUEST conflict (a request that
   contradicts the counter-protected stored decision of its slot) is held in memory only, in v1 and v2
   alike, so the reopened actor resumes the ORIGINAL decision and refuses the conflicting request
   again. Architect decision V1 keeps it that way: a request conflict stays in memory only (9.10.1).
   The deferral is an explicit nonfatal result, not a broad reset of `halted`. (Decision V4 adds, for a
   LOCKED validator while time defers its prevote, the precommit step and the round timeouts without
   any prevote: 9.10.4.)

### 9.2 What changed

| Where | Before (section 5, D4b) | Now |
|---|---|---|
| `ActorError` (`voter_actor.rs:34`, `voter_actor_v2.rs:35`) | a deferral was `Voter(Ingress(FutureTimestamp \| ClockUnqualified))`, the same shape as a fault | `ActorError::TimeDeferred(TimeStatus)`. `time_deferral()` and `is_time_deferral()` recognise only it. |
| `VoterActor::sign` (`voter_actor.rs:389`, `voter_actor_v2.rs:399`) | pre-gate on one clock read, set `halted`, the voter read the clock a second time, and a deferral from that read reset `halted = false` | `check_backend` (rejects an already-halted actor) -> ONE reading (`clock_reading`) -> pure pre-check (`time_gate_with`) -> `refusal` -> latch -> `sign_at` on the same reading. Nothing resets the latch. |
| `VoterActor::replay` (`voter_actor.rs:230`, `voter_actor_v2.rs:425`) | v1: latch, call, reset on deferral. v2: latch, call, no reset (a deferral halted the actor). | the same shape as `sign`: `replay_gate_at` before the latch, `replay_at` after it on the same reading. |
| `refusal` (`voter_actor.rs:212`, `voter_actor_v2.rs:381`) | n/a | classifies a refusal raised by a pure pre-check: time -> `TimeDeferred`; a request conflict or a halted reducer -> `halted = true` and the voter is poisoned (both in memory: 9.3 says which causes a reopen re-derives); anything else touched nothing and is returned unchanged. |
| `CounterVoter` (`counter_voter.rs:205-517`, `counter_voter_v2.rs:275-773`) | `sign` and `replay` read the clock internally | crate-visible `clock_reading`, `time_gate_with`, `replay_gate_at`, `poison`, `replay_at`, `sign_at`. The public `sign` and `replay` are the same operations over their own single reading. |
| `Driver` (`voter_driver.rs:61`), `VotingError::is_time_deferral` (`hybrid_voter_v2.rs:36`) | matched the old error shapes | treat only the explicit result as a deferral. |
| `VoterActor::is_halted` | n/a | read-only view of the latch. |
| `VoterActor::voter_poisoned`, `VoterActor::precommit_deadline`, `CounterVoter::is_poisoned` (both stacks) | n/a | read-only views of the voter poison and the armed precommit timeout, so the tests can show that `refusal` poisons the voter and that a deferral leaves in-memory state alone (9.7 E8). |

Latching, stated exactly (independent review NIT-2). `check_backend`, `reconcile`, v2
`rotate_finalized_generation`, and `sign` and `replay` after their pure pre-checks set `halted` first
and clear it only on their own success, after starting with it clear. Which refusals set the latch and
keep it, and what is deliberately NOT latched:

| Call | Sets the latch and keeps it | Not latched, by design |
|---|---|---|
| `check_backend` | an already-halted actor (`Halted`); v1: a canonical integrity halt or a chain/voter height mismatch (`Halted`); every failure after the latch: a canonical read (in v2 an integrity halt fails it), a stale authority (`Rollback`), a custody check (the voter is poisoned too) | - |
| `reconcile` | an already-halted actor; v1: a canonical integrity halt; every failure inside (canonical commit, revalidation, voter advance; in v2 a `require_local_vote` failure also writes the voter's durable halt bit) | - |
| `sign`, `replay` | an already-halted actor (through `check_backend`); `refusal` of a request conflict or a halted reducer (it poisons the voter too); every failure after the latch (custody, reducer, counter); v2: a stale authority after signing (`Rollback`) | a time deferral (`TimeDeferred`) or an unexecuted proposal, both raised by the pure pre-check, which touched nothing |
| `validate_candidate` | an already-halted actor; v1: a canonical integrity halt; v2: a stale authority (`Rollback`) | the candidate's own validation: it only adds an executed proposal to the reducer's in-memory table, and a refusal is a verdict about the candidate; v1: a chain/voter height mismatch (`Rollback`) |
| `observe` | an already-halted actor; v2: a `require_local_vote` failure (the voter also writes its durable halt bit) | the vote's own ingestion: it only adds an authenticated vote to the reducer's in-memory table, and an equivocation or invalid input is a verdict about the peer vote |
| `timeout_precommit` | an already-halted actor; v1: a canonical integrity halt, a chain height mismatch (`Rollback`); v2: through `check_backend` | the voter call itself: the voter sets its own poison before any custody step and keeps it on failure, so the next actor call's `check_backend` refuses (`Poisoned`) and sets the latch then; a reducer refusal (no precommit quorum, a halted reducer) touches nothing |
| v2 `sign_work_probe` | through `check_backend` | the probe signature: the voter fails closed through its own poison, as above |
| `progress` | reports `Halted` for a halted actor | read-only |

After the latch no time verdict is left, because the voter judges the reading the pre-check judged; if
a deferral could ever surface after the latch it would leave the actor halted, so the failure direction
is closed. A deferral also leaves the actor's in-memory state alone (latch, voter poison, armed
precommit timeout), which the tests assert (9.7 E8), and it cannot change the reducer or custody: both
pre-checks borrow the voter immutably (`&self`). The latch and the poison are in-memory state; which
causes a reopen re-derives is in 9.3. Not changed: consensus validity, `candidate_journal` limits,
finalized ingestion, `VoteGate::Fresh`, `VoteGate::reserved()`, `ReservedToken`, the durable gated
marker.

### 9.3 Halt semantics: what stays halted, and what a reopen re-derives

The latch (`halted`) and the voter poison are in-memory state; neither is written anywhere. Every cause
below halts the live actor for every later call under every clock. What a REOPEN (closing the actor
and opening it again with the cause still present) does depends on where the cause lives:

* (a) re-derived from durable state: the cause is in the backend, the counter-protected voter record or
  the canonical store, so the open itself, or the first vote attempt, finds it again;
* (b) in memory only: nothing about the cause is written, and the reopened actor resumes from the
  intact counter-protected record.

The v1 tests also close and reopen the canonical store; in the hybrid fixture the store is shared
(reopening it is expensive) except for the integrity-halt case, which reopens it from disk.

| Cause | Found by | Live actor | Durable state | Reopen, v1 | Reopen, v2 |
|---|---|---|---|---|---|
| Backend counter differs from the stored record | `check_backend` (`CounterStore::verify_current`) | halted, voter poisoned, `Counter(Rollback)` | record untouched; the mismatch is between the TPM counter and the record | (a) open refused, `Counter(Rollback)` | (a) open refused, `Counter(Rollback)` |
| Backend cannot report a counter (an impossible state) | `check_backend` | halted, voter poisoned, `Counter(Backend)` | untouched; the cause is in the backend | (a) open refused, `Counter(Backend)` | (a) by the same `CounterStore` open path as the counter mismatch; not exercised by the v2 tests |
| Backend reports another public key (key corruption) | `check_backend` | halted, voter poisoned, `Invalid(WrongGeneration)` | untouched; the record binds the key | (a) open refused, `WrongGeneration` | (a) open refused, `WrongGeneration` |
| Canonical integrity halt (`integrity.halted`, written when two certified blocks conflict) | v1: `check_backend`, `reconcile`, `validate_candidate`, `timeout_precommit`, `open`; v2: every canonical read | halted | the flag in the canonical store | (a) open refused, `Halted` | (a) open refused (the canonical read fails) |
| Stored reducer halt bit (`LockState.halted` in the record) | v1: the first `sign` (reducer preview) or `replay` (`replay_gate_at`), in the pure pre-check (9.7 E6); v2: `check()`, inside `check_backend` and `reconcile` | halted; v1: voter poisoned, `Ingress(Bft(IntegrityHalt))`; v2: the voter refuses every operation because of the bit (`Poisoned`) | the bit in the counter-protected record | (a) the open succeeds; the first `sign` or `replay` halts the actor again, and nothing is signed, completed or retransmitted | (a) open refused (`reconcile` reaches `check()`) |
| Own certificate vote that custody never issued | v2 only: `reconcile` or `observe` -> `require_local_vote` | halted, voter poisoned; the voter WRITES its halt bit (one counter commit) | `locks.halted` in the record | not applicable: v1 has no such check | (a) open refused, whatever the clock says |
| Corrupt stored lock or vote (lock newer than its round, vote naming another round, two votes for one slot) | `CounterVoter::open` (snapshot decode, `RoundMachine::restore`) | never opens | the corrupt record | (a) open refused, whatever the clock says | (a) open refused |
| REQUEST conflict: the request contradicts the counter-protected stored decision of its slot (`ConflictingVote`) | the pure pre-check (`time_gate_with`, then `refusal`) for EVERY reserved slot, guard-marked, signed or unmarked legacy, before the latch and before the clock (9.7 E5); `sign_inner` still compares the full vote bytes after the latch | halted, voter poisoned; nothing signed, written or changed in the reducer | NOTHING is written for the conflict; the stored decision is untouched | (b) in memory only: the open succeeds and the actor is healthy. It can complete or retransmit only the ORIGINAL stored decision, byte for byte (a guard-marked or signed one under any clock, an unmarked legacy block reservation under a qualified eligible clock, nil under any clock), and the conflicting request is refused again (`ConflictingVote`, halted) under every clock | (b) the same |
| Interrupted signature (the backend fails after the reservation commit) | `sign` or `replay`, after the latch | halted, voter poisoned | the unsigned reservation | (b) the open succeeds; the exact reservation completes (guard-marked: no clock; unmarked legacy block: a qualified eligible clock) | (b) the same |

Why holding a request conflict in memory only is safe (confirmed by the independent review): every
request is compared with the counter-protected record BEFORE anything is reserved, signed or committed,
and that record is the only source of a reopened actor's decisions. No restart timing can therefore
produce a second decision for the slot or reuse a counter value; a reopen only gives back the ability
to finish the ORIGINAL decision. The node's driver never makes a conflicting request (it replays a slot
that holds a reservation and signs only an empty slot), so in the node this halt is defence in depth.
Decided (Architect decision V1): a request conflict stays in memory only; no counter value is used to
record or punish it (9.10.1). The canonical integrity halt row above is written only for VALID
conflicting finality evidence; an invalid signature fails verification before anything is recorded.

A halted actor reports `Halted` for `progress`, `check_backend`, `reconcile`, `observe`,
`validate_candidate`, `timeout_precommit`, `sign` and `replay`, under every clock, and never a
deferral, a retransmission or a signature. For an (a) cause, repairing the backend (or the canonical
store) and reopening is the only way back, and the stored decision is then intact; for a (b) cause the
reopen itself is the way back.

### 9.4 What an unqualified clock can still select or construct (path trace)

| # | Path | Selects or constructs | Needs | While unqualified | Evidence |
|---|---|---|---|---|---|
| 1 | `LocalProposer::propose`, fresh choice (`local_proposer.rs:191-198`, `fallback_choice` `:273`); the selection becomes the `Offer` (`:210`), the only input of `RoundProposal::signed` (`:211`) | a NEW `RoundProposal` and its signature | candidate timestamp <= the voter's own qualified clock (`VoterActor::timestamp_status`) | nothing is eligible: `Ok(None)`, nothing signed, nothing written | `an_unqualified_clock_selects_signs_constructs_and_issues_nothing_new`; guard |
| 2 | the same function: held lock (`:280`), PoLC block (`:141-190`), persisted proposal (`:127-140`) | the SAME block again | the original bytes; no clock | re-proposed or returned unchanged | `a_held_lock_is_reproposed_with_its_original_bytes_and_timestamp_while_unqualified`, `a_proof_of_lock_block_is_reproposed_while_unqualified_and_changes_no_stored_block`, `a_persisted_proposal_and_the_exact_reserved_vote_are_replayed_byte_for_byte_while_unqualified` |
| 3 | `WorkerCoordinator::handle`, `Request` arm (`worker_coordinator.rs:253-289`): `hooks.body` (body assembly at the work timestamp), then `coordinator.issue` (candidate header, work authorization, ticket reservation) | a NEW candidate and work for a new height | `self.now()` = `qualified_unix_ms()` (`:146`), the first statement of `handle` (`:230`) and `active` (`:225`) | `Err("Qualified clock unavailable...")` before assembly or issuance; `work.sqlite`, `candidates.sqlite`, `observations.sqlite`, `operations.sqlite`, `proposer.sqlite` byte-identical | `an_unqualified_clock_selects_signs_constructs_and_issues_nothing_new`, `work_for_a_new_height_needs_the_qualified_clock_and_finalized_ingestion_does_not`; guard |
| 4 | `Status` and `Result` messages, `WorkerBackend::active` | worker binding for the current epoch | same read | candidate 3 (decision V2, 9.10.2): the session authenticates against the binding finalized state holds; status, stop and exact stored-receipt retransmission work; a fresh result is held (bounded) with no acceptance, credit or receipt; new work and a new receipt still need qualified time | `worker_unqualified::v2_*` |
| 5 | `Assembler::assemble`, `admit_operation` (`body_assembler.rs:195`, `:172`), placeholder `Candidate` in `preview` (`:81`) | a body with timestamps; the placeholder is never persisted | an explicit `timestamp` argument; called only from #3 and from operation admission (`integrated_actor.rs:151`, `:428`), both qualified-only | not reachable | guard `work_and_candidates_are_only_constructed_behind_the_qualified_clock` |
| 6 | `IntegratedActor::tick` participation (`integrated_actor.rs:134`) | participation operations | `self.time.seconds()` | none produced or admitted | `cold_boot_without_an_anchor_...` (section 6) |
| 7 | `RoundProposal::signed` (`round_proposal.rs:37`), the only constructor of a NEW signed proposal; the `signature` field, `sign`, `body` and `digest` are private to `round_proposal.rs` (9.7 E7) | a signature over a proposal payload | an `Offer`, which only `local_proposer.rs` can build (private fields), once, in `propose` after the selection | see 1 | compile time: any other proposal literal or signing call does not compile (`E0451`, `E0624`); guard `a_new_round_proposal_can_only_be_built_and_signed_by_the_local_proposer` pins the seal |
| 8 | hybrid `Coordinator::prepare_with_signer` (`hybrid_coordinator_v2.rs:341`) | work authorization (hybrid, not wired) | `self.sample(clock)?` first (`:352`), before `journal.reserve` (`:368`), `HybridRuntime::prepare` (`:370`; it takes a CALLER-chosen timestamp, `hybrid_runtime_v2.rs:147`) and `authorize_work` (`:397`). The non-test `Clock` implementations are `QualifiedClock` (`:50`) and `ContinuingClock` (`worker_handshake_io_v2.rs:36`), a wrapper inside the worker handshake that forwards its inner clock's sample, refuses a regression or an overrun of the 60 s handshake budget, and constructs no time of its own | `Err`, no ticket reserved | `support/hybrid_coordinator_v2.rs` (unavailable clock), guard `the_hybrid_coordinator_samples_qualified_time_...` (pins every `impl ... Clock for`, the one `WorkRequest` literal and every mention of the type, every non-SQL `prepare(` and every `authorize_work(`) |
| 9 | peer ingress `submit_candidate`, `submit_round_proposal`, `submit_vote`, `submit_block` | stores what a peer built; constructs nothing | deterministic validation, no clock | works while unqualified (synchronization, finalized ingestion) | `finalized_import_and_sync_proceed_under_an_unqualified_clock`, `work_for_a_new_height_...` |

Preserved while unqualified, with byte equality asserted: the persisted proposal (`RoundProposal::encode`
equal to the persisted wire), the stored candidate records (`CandidateRecord::encode` equal, timestamp
unchanged), the reserved vote (completed once, then `Vote::encode` identical on every tick, no counter
use after the completion), and the held lock's block hash, which commits the original header and
timestamp.

### 9.5 Proposer behaviour, re-confirmed

* Fresh choice: only candidates with `timestamp <= qualified now` under the proposer's own clock, zero
  allowance (one second early is not eligible, equal is). The lowest hash among the eligible wins; a
  lower-hash far-future candidate is skipped and stays in the journal.
* Never filtered: a held lock, a PoLC block, a persisted proposal for the (height, round). The persisted
  proposal also means a later clock cannot swap a choice already made.
* A PoLC block is re-proposed while unqualified, and that is implemented as permitted. It is a new
  `RoundProposal` message for the new round, but it selects no new block and constructs nothing: the
  block, its header and timestamp, and its proof (the prevote quorum of an earlier round that the
  proposer verified) are all unchanged, exactly as for a held lock, and every validator still judges
  its own vote with its own clock. Architect decision V3 confirms this reading, with current round,
  parent, membership, proof and lock checks; they are listed and pinned in 9.10.3.
* Unqualified: nothing is eligible, `Ok(None)`. No reading is substituted.
* Test: `only_candidates_eligible_under_the_proposers_own_qualified_clock_are_chosen_zero_allowance`
  (with the earlier `proposer_skips_far_future_candidates_...` and
  `a_held_lock_is_reproposed_unchanged_and_unfiltered_...`).

### 9.6 Property to test map

Consensus tests are in `consensus/tests/actor_halt_latch_v1.rs` (live actor). The hybrid actor runs the
same properties in `consensus/tests/support/halt_latch_v2.rs`, called from
`admission_hybrid_v2::both_owner_halves_continuity_possession_native_quote_and_supervised_context_required`
(the only hybrid actor fixture). Node tests are in `node/src/unqualified_proposal_tests.rs` (module
`worker_coordinator::os_clock_tests::unqualified_proposal`); guards in
`node/tests/proposal_construction_paths_v1.rs`.

| Property | Test |
|---|---|
| A healthy actor waiting for time retransmits the stored vote byte for byte, defers a fresh block vote explicitly, touches nothing, and resumes cleanly | `a_healthy_actor_waiting_for_time_retransmits_the_stored_vote_byte_for_byte_and_resumes_cleanly`; v2 `waiting_actor_resumes` |
| Finalized ingestion and synchronization proceed while time defers | `finalized_ingestion_and_sync_proceed_while_time_defers_and_leave_the_latch_alone`; v2 `nil_and_finalized_ingestion_while_unqualified`; node `work_for_a_new_height_needs_the_qualified_clock_and_finalized_ingestion_does_not` |
| Nil votes and the precommit timeout proceed while unqualified, for a validator WITHOUT a lock (a locked validator defers, 9.8) | `nil_votes_and_the_precommit_timeout_proceed_while_the_clock_is_unqualified`; node (section 6) `nil_timeout_votes_proceed_under_an_unqualified_clock_and_no_block_vote_is_possible` |
| The deferral is explicit and pure; no old implicit shape leaves the actor | `a_time_deferral_is_explicit_pure_and_never_touches_custody_or_the_latch`, `no_deferral_shape_other_than_the_explicit_variant_ever_leaves_the_actor`; v2 `deferral_is_explicit_and_pure` |
| A deferral leaves the actor's in-memory state (latch, voter poison, armed precommit timeout) intact, and the armed timeout still fires | `a_time_deferral_leaves_the_armed_precommit_timeout_and_all_in_memory_state_intact`; v2 `deferral_leaves_the_armed_precommit_timeout_intact`; every "touches nothing" check in both suites compares the in-memory state too (9.7 E8) |
| Every halt raised by `refusal` (a request conflict, a halted reducer) also poisons the voter | asserted with `voter_poisoned()` in each request-conflict and reducer-halt test, v1 and v2 (9.7 E8) |
| An unexecuted proposal is a recoverable absence, not a halt and not a deferral | `an_unexecuted_proposal_is_a_recoverable_absence_not_a_halt_and_not_a_time_deferral`; v2 `deferral_is_explicit_and_pure` |
| One clock reading per attempt, so a flapping clock cannot halt the actor or bypass the guard | `one_clock_reading_serves_each_attempt_so_a_flapping_clock_cannot_halt_or_bypass_the_guard`; v2 `one_reading_per_attempt` |
| Counter inconsistency, backend corruption, an unreadable counter and the integrity halt stay halted across later `sign`/`replay` and a pending deferral in BOTH orders, and are re-derived on reopen; a request conflict stays halted across later calls and deferrals and is held in memory only across reopen (the reopened actor resumes the original decision and halts again on the conflicting request) | `counter_inconsistency_stays_halted_...`, `backend_key_corruption_stays_halted_...`, `an_unreadable_backend_counter_stays_halted_...`, `a_durable_chain_integrity_halt_stays_halted_...`, `request_conflict_unmarked_record_halts_in_memory_only_and_reopen_resumes_the_original`; v2 `run_case` for five causes (counter inconsistency, backend key corruption, integrity halt, request conflict, and the durable own-vote halt that only v2 has) in both orders; the unreadable-counter cause shares `check_backend` with the counter mismatch and is covered in v1 only |
| A cause noticed by the deferring call itself is reported, never deferred | `a_cause_that_is_noticed_by_the_deferring_call_itself_is_reported_not_deferred`; v2 `a_cause_noticed_by_the_deferring_call_is_reported_not_deferred` (9.7 E8) |
| A request conflict with a guarded decision halts even when the clock would defer | `request_conflict_guarded_decision_halts_any_clock_in_memory_only_reopen_resumes_original`; v2 `request_conflict_guarded_decision_halts_any_clock_in_memory_only_reopen_resumes_original` |
| A request that conflicts with an UNMARKED legacy reservation halts before the time gate, under every clock, signing and writing nothing (9.7 E5) | `a_request_conflicting_with_an_unmarked_legacy_reservation_halts_before_the_time_gate`; v2 `request_conflict_with_an_unmarked_reservation_halts_before_the_time_gate` |
| A stored reducer halt bit does not refuse the open, but the first `sign` or `replay` finds it in the pure pre-check and halts the actor; `replay` neither retransmits a signed vote nor completes an unsigned reservation under it (9.7 E6) | `a_reducer_halt_found_by_the_pre_check_halts_the_actor_whatever_the_clock_says`, `a_stored_reducer_halt_refuses_replay_halts_the_actor_and_signs_nothing` |
| A corrupt stored lock or vote refuses every reopen | `a_corrupt_stored_lock_or_vote_refuses_every_reopen_whatever_the_clock_says` |
| A request conflict is held in memory only, in both stacks: a reopen yields a healthy, unpoisoned actor that resumes the ORIGINAL decision, and the conflicting request is refused again | `request_conflict_is_in_memory_only_reopen_resumes_original_and_refuses_the_conflict_again`, and the reopen part of every request-conflict test above (v1 and v2) |
| Tick level: a halt stays across ticks and reopen, in both orders; the service latches it | node `a_halt_after_pending_deferrals_stays_across_ticks_and_reopen_counter_inconsistency`, `a_halt_before_any_deferral_stays_across_ticks_and_reopen_backend_key_corruption`, `a_durable_chain_integrity_halt_stays_across_ticks_and_reopen_in_both_orders`, `the_service_latches_a_halt_and_a_later_deferral_cannot_clear_it` |
| No new proposal, signature, candidate, work or worker binding while unqualified; every durable store unchanged | node `an_unqualified_clock_selects_signs_constructs_and_issues_nothing_new` |
| Exact reproposal and vote retransmission, byte for byte | node `a_persisted_proposal_and_the_exact_reserved_vote_are_replayed_byte_for_byte_while_unqualified`, `a_held_lock_is_reproposed_with_its_original_bytes_and_timestamp_while_unqualified`, `a_proof_of_lock_block_is_reproposed_while_unqualified_and_changes_no_stored_block` |
| Proposer eligibility, zero allowance | node `only_candidates_eligible_under_the_proposers_own_qualified_clock_are_chosen_zero_allowance` |
| A new signed round proposal can only be made behind the proposer's selection (compile time); the other construction sites, the clock implementations and the paths to hybrid work preparation, and their time ordering, are pinned | compile time: the `round_proposal.rs` seal; `node/tests/proposal_construction_paths_v1.rs` (four guards, including that the seal is intact and that no actor branch on a deferral may touch `halted`). The reviewer's probes G1, G2, G4 and N1 now fail (9.7 E7) |
| The hybrid coordinator authorizes nothing with an unavailable clock | `consensus/tests/support/hybrid_coordinator_v2.rs`, run by `continuity_key_rotation_v2::synthetic_same_hardware_rotation_requires_new_dual_keys_and_exact_parent_authority` |

The tests for Architect decisions V1-V4 (candidate 3) are mapped in 9.10.5.

Mutation checks. Each mutation was applied to one file, run, reverted and verified with `cmp`. The
hybrid scenarios stop at their first failing assertion, so for v2 the scenario named is the first one
that caught the mutation.

* At the time of writing (v1): conflicting decision no longer halts (three tests; v2: the hybrid
  scenario), a second clock reading in `sign` (the one-reading test), no pre-latch check in `replay`
  (ten tests), an already-halted actor no longer rejected by `check_backend` (SEVEN tests: the earlier
  count of six was wrong, as the independent review's re-run, M9, showed).
* Independent review (v1 only): M1 to M6 and M9 were caught; M7 (`refusal` no longer poisons the
  voter) and M8 (a deferral clears the armed precommit deadline) were not (9.7 E8). Re-run after the
  repair: M7 fails six tests
  (`request_conflict_guarded_decision_halts_any_clock_in_memory_only_reopen_resumes_original`,
  `a_reducer_halt_found_by_the_pre_check_halts_the_actor_whatever_the_clock_says`,
  `a_request_conflicting_with_an_unmarked_legacy_reservation_halts_before_the_time_gate`,
  `a_stored_reducer_halt_refuses_replay_halts_the_actor_and_signs_nothing`,
  `request_conflict_unmarked_record_halts_in_memory_only_and_reopen_resumes_the_original`,
  `request_conflict_is_in_memory_only_reopen_resumes_original_and_refuses_the_conflict_again`); M8
  fails `a_time_deferral_leaves_the_armed_precommit_timeout_and_all_in_memory_state_intact`.
* v2, this package (`voter_actor_v2.rs`, run through `admission_hybrid_v2`):

| v2 mutation | First caught by |
|---|---|
| V2-M1: `sign` runs its time pre-check before `check_backend` and resets `halted` on a deferral | `a_cause_noticed_by_the_deferring_call_is_reported_not_deferred` (a counter mismatch came back as `TimeDeferred`) |
| V2-M2: `sign` sets the latch before its pre-check, so `TimeDeferred` is returned after the latch | `waiting_actor_resumes` (the actor is halted after a deferral) |
| V2-M3: `refusal` no longer halts or poisons on a request conflict | `request_conflict_guarded_decision_halts_any_clock_in_memory_only_reopen_resumes_original` (not halted) |
| V2-M4: `replay` turns a counter mismatch from `check_backend` into a deferral and clears the latch | NOT caught by the v2 suite as it stood: it passed, because every cause scenario noticed the mismatch through `check_backend`. Caught after the repair by `a_cause_noticed_by_the_deferring_call_is_reported_not_deferred` (9.7 E8) |
| V2-M7: `refusal` no longer poisons the voter | `request_conflict_guarded_decision_halts_any_clock_in_memory_only_reopen_resumes_original` (the new poison assertion) |
| V2-M8: a deferral clears the armed precommit deadline | `deferral_leaves_the_armed_precommit_timeout_intact` |

### 9.7 Defects found and repaired in this package

| id | defect | severity | repair |
|---|---|---|---|
| E1 | The actor's pre-latch gate in `sign` (section 5, D4b: `sign` already had one) returned a `ConflictingVote` raised by `time_gate_with` BEFORE the latch and before the voter's poison, so a conflicting durable decision found there neither halted the actor nor poisoned the voter. | safety response weakened (nothing unsafe was signed) | `refusal`: a conflicting decision or a halted reducer halts the actor and poisons the voter, exactly as when the same check ran after the latch. Test `request_conflict_guarded_decision_halts_any_clock_in_memory_only_reopen_resumes_original`. |
| E2 | `replay` of a legacy unmarked reservation whose proposal was not re-executed (`UnknownProposal`) halted the actor, although `sign` treats the same absence as recoverable. | availability | recoverable absence in both actors. `an_unexecuted_proposal_is_a_recoverable_absence_not_a_halt_and_not_a_time_deferral`. |
| E3 | `voter_actor_v2::replay` halted the actor on a time deferral (the pattern D4b repaired only in v1). | availability | same design as v1. |
| E4 | `sign` consulted the clock twice (actor pre-gate, then the voter) and cleared the latch when the second read deferred. | structure | one reading per attempt; no reset. |
| E5 | Independent review, MINOR-1. A request that contradicted an UNMARKED legacy reservation was compared with it only after the time gate. While the clock was unqualified or behind, it was reported as a time deferral (actor not halted, nothing written); only a qualified, eligible clock found the conflict. | safety response delayed (nothing unsafe could be signed: `sign_inner` still compared the full vote bytes) | `time_gate_with` (both voters) compares the request with ANY stored reservation before the clock is consulted; only a matching request reaches the time gate, and only a matching guard-marked or signed one is exempt from it. `a_request_conflicting_with_an_unmarked_legacy_reservation_halts_before_the_time_gate`; v2 `request_conflict_with_an_unmarked_reservation_halts_before_the_time_gate`. |
| E6 | Independent review, MINOR-2 (pre-existing: older than this package). v1 `replay` never consulted the stored reducer halt bit (`LockState.halted`). A record carrying it still retransmitted a signed vote and COMPLETED an unsigned guard-marked reservation (one signature, one counter commit) without halting; only a later `sign` halted. Reachable only from a crafted or foreign record: v1 itself refuses every reducer write once its reducer is halted. | safety response missing on one path (what completed was the exact stored decision) | v1 `replay_gate_at` refuses with `IntegrityHalt` when the stored or the live reducer state is halted, so `refusal` latches the halt and poisons the voter, as v2's `check()` already refuses a halted record. `a_stored_reducer_halt_refuses_replay_halts_the_actor_and_signs_nothing`. |
| E7 | Independent review, MINOR-3. The source guard matched literal syntax only. An ungated proposal built with functional update syntax and signed through `as_mut()?.sign(..)` (G1), an ungated `HybridRuntime::prepare` at a caller-chosen timestamp (G2) and a path-qualified `impl ...::Clock for` holdover clock (G4) each compiled and passed all four guard tests. | guard gap (the tree itself had no ungated path) | Structural seal: `RoundProposal`'s `signature` field, `sign`, `body` and `digest` are private; its only constructor of a new signed proposal, `RoundProposal::signed`, consumes a `local_proposer::Offer`, whose fields are private and which `propose` builds once, after the selection. The guards ignore whitespace and pin the seal, every `impl ... Clock for` (any path), the `WorkRequest` literal and every mention of the type, every non-SQL `prepare(`, every `authorize_work(`, and the exact eligibility closure. Re-run against the new guard: G1 and its control no longer compile (`E0624`, `sign` is private; a bare literal is `E0451`, `signature` is private); G2 and G4 fail the guard; N1 fails the guard and two behavioural tests. Test edit: `worker_coordinator_tests.rs` corrupts the signature through the wire encoding, since the field is private. |
| E8 | Independent review, mutation runs M7 and M8 (test gaps, not code defects). Removing the voter poison from `refusal` (M7), or clearing the armed precommit deadline on a deferral (M8), failed no test: nothing outside the actor could see the poison or the deadline, and the "touches nothing" checks covered custody only. A v2 mutation run of this package found a third gap: a v2 `replay` that turned a counter mismatch into a deferral (V2-M4) passed the v2 suite, because its cause scenarios notice the mismatch through `check_backend` only. | test gap | Read-only views `voter_poisoned()` and `precommit_deadline()` on both actors (`is_poisoned()` on both voters). Every refusal-path halt now asserts the poison; every "touches nothing" check also compares the latch, the poison and the deadline; new tests `a_time_deferral_leaves_the_armed_precommit_timeout_and_all_in_memory_state_intact`, v2 `deferral_leaves_the_armed_precommit_timeout_intact`, v2 `a_cause_noticed_by_the_deferring_call_is_reported_not_deferred`. Mutation results in 9.6. |

### 9.8 Not done, limits, decisions needed

* A request conflict is held in memory only, in v1 AND v2 (9.3): the latch and the voter poison,
  nothing written; v2's durable halt bit is written only for an own certificate vote that custody never
  issued. Decided by the Architect (V1): it stays in memory only (9.10.1).
* (Superseded in candidate 3 by decision V2, 9.10.2.) Worker `Status` and `Result` needed qualified
  time (they bound the worker for the current epoch first). Now the session authenticates against the
  binding finalized state holds, status, stop and exact stored-receipt retransmission work, and a fresh
  result is held, bounded, without acceptance, credit or receipt until the clock is qualified again;
  new work and new receipts stay fail-closed.
* The hybrid actor and coordinator are library code, not wired to `main.rs`. Their tests run inside the
  two heavy hybrid fixtures; there is no cheaper fixture. The actor scenarios add four to six minutes to
  `admission_hybrid_v2` (`halt_latch_v2::qualify` took 246 s and 323 s in two clean runs on the
  loaded host; debug build; every actor call re-reads the canonical store, about half a second). The
  coordinator assertion sits in
  `continuity_key_rotation_v2::synthetic_same_hardware_rotation_requires_new_dual_keys_and_exact_parent_authority`,
  which on the loaded host used for this package fails at real-time deadline stages in the UNMODIFIED
  base commit as well (`worker_handshake_io_v2.rs:133` there; `worker_carrier_v2.rs:88` on this
  branch). The new assertion sits between those two stages: it ran and passed before the carrier
  failure on this branch, but that test is not a clean pass on this host.
* (Repaired in candidate 3 by decision V4, 9.10.4.) Nil availability while unqualified holds only for
  a validator WITHOUT a lock. A locked validator's nil prevote request (`sign(Prevote, None)`) is a
  vote for its locked block: `prevote_plan` returns the lock, which in a new round is a fresh block
  vote, so it is time-gated and deferred while unqualified. Before the repair the driver then returned
  early, so that validator neither prevoted nor precommitted, and did not arm its precommit timeout,
  until the clock was qualified again: its round never advanced (reproduced by
  `v4_a_locked_validator_keeps_round_progress_while_unqualified_with_no_prevote_and_its_lock`, which
  fails on the pre-repair driver). It still ingested finalized blocks and synchronized, and its weight
  stays in the quorum denominator. An unlocked validator's nil votes and timeouts proceed
  (`nil_votes_and_the_precommit_timeout_proceed_while_the_clock_is_unqualified`).
* `LocalProposer::propose` reads the voter clock once per candidate. A candidate judged eligible stays
  eligible while the clock is qualified and non-decreasing, so no ineligible candidate can pass; a single
  reading per selection would be tidier and was not needed.
* `ActorService` still turns the first failed tick into a latched fault; a halted actor therefore ends the
  service (`the_service_latches_a_halt_and_a_later_deferral_cannot_clear_it`). That is the intended
  fail-closed behaviour, unchanged.
* Everything here is Implemented, not Qualified, and Offline, not Physical: no host clock, no TPM and no
  device was involved.

### 9.9 Decision for the Architect: should a request conflict become a durable halt?

Decided (Architect decision V1, Continuation Order of 4 October 2026): option (1), keep a request
conflict in memory only; see 9.10.1. The analysis below is kept as the record of the question.

Question. A REQUEST conflict (a request that contradicts the counter-protected stored decision of its
slot, `ConflictingVote`) halts the live actor and poisons the voter, but nothing is written, so a reopen
yields a working actor that can only complete the ORIGINAL decision and refuses the conflicting request
again (9.3). This holds in v1 and in v2. Should detecting a request conflict instead commit a DURABLE
halt marker that refuses every later open, as v2 already does for an own certificate vote that custody
never issued? Not implemented: it changes custody behaviour, and it is the Architect's call.

Trade-off:

* Fail-stop across restarts (for a durable marker). Today a restart clears the halt: a process that
  keeps making the conflicting request is halted again each time it makes it, but it keeps operating
  in between, and the conflict leaves no durable trace for diagnosis. A durable marker would stop the
  validator until someone acts, and would record that a conflict was seen.
* Bricking risk (against). The marker is a custody write on an error path (one TPM counter increment
  per detection). A spurious conflict, for example a caller or driver defect, or a reducer-state
  mistake rather than an attempt to equivocate, would then stop the validator permanently. Today the
  same false alarm costs one restart, and it can never produce a second decision, because the reopened
  actor still compares every request with the record first.
* The clear path. No operator path exists to clear a durable halt: neither stack has an API that resets
  `LockState.halted` (neither stack advances or signs under it, and v2 does not rotate under it
  either), and v2's unissued-own-vote bit is permanent for that custody, whose only way forward is new
  custody through the recovery ceremony. A durable request-conflict halt would need a defined clear
  path: who may clear it, on what evidence, and how the clear itself is counter-protected. That is a
  custody policy decision in its own right.
* Safety is not at stake either way: the independent review confirmed that no restart timing allows a
  second decision for the slot or a reused counter value today (9.3). The choice is between fail-stop
  semantics across restarts and the risk of permanently stopping a validator on a false alarm.

Options: (1) keep a request conflict in memory only, as implemented; (2) a durable halt marker in both
stacks, refused on every open, together with a defined, counter-protected clear path; (3) a durable,
counter-protected record of the conflict for diagnosis that does NOT refuse the open (evidence survives
restarts, no bricking, still one counter increment per detection).

### 9.10 Candidate 3: Architect decisions V1-V4 (Continuation Order, 4 October 2026)

Status: Implemented, not Qualified. Offline, not Physical. Windows-host software tests with controlled
clocks and synthetic (TEST-VALUE) custody; nothing here ran on Linux, on a device or against a physical
clock. Branch `cand3/voter` (base `integration/candidate-3` = d56064b).

The decisions, as the Order states them:

* V1: keep conflicting REQUEST rejection/session poisoning non-durable where the sole durable decision
  remains intact and reopening can complete only that decision; correct the documentation; an invalid
  request is not evidence of two durable decisions, do not burn counters to punish it; genuine
  key/counter/backend inconsistency, conflicting durable decisions and valid conflicting finality
  evidence retain durable halt behaviour; invalid signatures do not create a durable finality halt.
* V2: new epoch-dependent work binding, local acceptance/crediting of fresh Worker results and new
  coordinator receipts remain fail-closed; deterministic application of finalized canonical
  results/credits remains clock-independent; authenticated status, safe stop, diagnostic reads and exact
  stored-receipt retransmission must remain available; bounded receipt of a Result may defer
  processing, granting no acceptance, credit or new signature; qualification loss must not prevent
  stopping work.
* V3: permit exact validated locked-block reproposals with current round, parent, membership, proof and
  lock checks; no new block or timestamp is selected; fresh block votes remain guarded; preserve only
  the already-defined exact durable signing-decision recovery exception.
* V4: repair the locked/unqualified timer stall; continue permitted timeouts, round progress, sync and
  finality ingestion while withholding fresh block votes; preserve locks, do not fabricate nil votes to
  escape them; clock recovery revalidates the current context instead of signing for an expired round.

#### 9.10.1 V1: what is held in memory and what is durable

| State | Where it lives | Written when | After a reopen |
|---|---|---|---|
| Halting latch `halted` | `VoterActor`, both stacks: memory | never | gone (a reopen starts clean) |
| Voter poison | `CounterVoter::poisoned`, both stacks: memory | never | gone |
| The slot's durable decision: a reservation (with its `gated` marker) or a signed vote | the counter-protected record (`voter_snapshot`, v2 `voter_migration`) | when the fresh guard passes (reservation commit), and when the signature completes; one counter increment each | kept: the reopened actor can complete or retransmit exactly it |
| Reducer halt bit `LockState.halted` | the record | v1: never by v1 itself (a crafted or foreign record); v2: by `require_local_vote`, for a VALID own vote custody never issued (one counter increment) | v1: the open succeeds, the first `sign`/`replay` halts again; v2: the open is refused |
| Canonical integrity halt | v1 `integrity.halted` (`finality.rs`), v2 `integrity_v2` (`finality_v2.rs`) | only by `FinalityLedger::record` / `FinalityEvidenceStore::record_with_recovery` for a second, fully verified certificate at a finalized height, in the same transaction as that proof (both proofs kept in `finality_evidence` / `evidence_v2`) | the open is refused |
| Counter or key inconsistency | the backend (TPM; a software double here) | n/a | the open is refused |

A REQUEST conflict (a request that contradicts the sole durable decision of its slot) sets the latch and
the poison and nothing else, in both stacks: no write, no counter increment, the stored decision
untouched. A reopen therefore re-derives nothing for it; the reopened actor completes or retransmits
only the original decision (a signed vote: no counter value and no signature; an interrupted
reservation: one signature and one commit at the next counter value) and refuses the conflicting
request again. This was already the behaviour; no code changed for V1. The comments that called a
request conflict a "conflicting durable decision", or said the actor stays halted "for good", now say
"request conflict" and "this in-memory actor" (`voter_actor.rs`, `voter_actor_v2.rs`,
`counter_voter.rs`, `counter_voter_v2.rs`).

Invalid signatures never create a durable finality halt. v1: `CanonicalStore::commit_integrated` sends a
block at a finalized height to `inspect_integrated_history`, which verifies the block and its
certificate (`verify_evidence`) and executes it before `inspect_history_proof`; `record_certificate`
verifies the quorum again before `record` can write the halt. v2: `record_with_recovery` runs
`verify_execute_with_history` before it compares with the finalized anchor.

The documentation correction. The earlier text that called the request-conflict halt durable (reviewed
commit 0b292cd) was corrected in aed3999; at d56064b section 9.3 and the briefing already said "in
memory only". What candidate 3 adds is the recorded decision, the table above, the corrected comments,
and an amendment under the briefing's section 3.C.

#### 9.10.2 V2: the Worker path while the clock is unqualified

The shipping Worker path is `node/src/worker_coordinator.rs` (`WorkerBackend` for `WorkerCoordinator`,
reached through `IntegratedActor`).

| Message or call | Qualified | Unqualified, before | Unqualified, now |
|---|---|---|---|
| `active` (session authentication, each frame) | `binding`: the Worker's binding at the epoch of qualified time | error: no session at all | `settled_binding`: the binding finalized state already holds, judged at the later of the tip block's own MiningEpoch and the latest epoch this process already bound a Worker at under qualified time (`last_qualified_epoch`, memory only, monotone; no clock is read). A Worker this process bound and issued work to while qualified therefore keeps status, stop and retransmission even when no finalized block has reached its assignment's epoch (review finding MAJOR-1, fixed). A Worker whose assignment is pending beyond both epochs is refused (`LicenseBook::active`) |
| `Status` (status, safe stop) | heartbeat; retire when the work gate holds no quorum lease and the device is mining | error | unchanged from the qualified case (the gate is monotonic): status and stop work. Work already issued keeps its own bounded lifetime (at most the rest of its 60 s MiningEpoch); a result found meanwhile is held, not credited |
| `Request` (new work) | issued under the gate | error | error `Qualified clock unavailable: no new work is issued`: nothing bound for the current epoch, nothing issued. The session layer turns that error into closing the session; the device is expected to reconnect and retry (the Worker firmware is not in this repository, so the device's reaction is NOT verified here) |
| `Result`, exact retransmission of an accepted result | stored receipt, after the candidate is durably preserved | error | the stored receipt, byte for byte, after the same clock-free preservation; `Coordinator::retransmission` never accepts, credits or signs |
| `Result`, a result that contradicts the stored checkpoint | refused | error | refused, never held |
| `Result`, fresh | accepted, credited, receipt signed, candidate preserved | error | held in memory, one per Worker (a later one replaces an earlier one), at most `MAX_DEFERRED_RESULTS` = 16 Workers; the reply is a heartbeat, never a receipt, so the device keeps the result in its durable outbox; a full hold refuses and holds nothing |
| held results | n/a | n/a | `process_deferred_results`, called by `IntegratedActor::tick`, processes them once qualified time returns exactly like a fresh result (current-epoch `binding`, acceptance, durable receipt, credit, preservation); one that now fails is dropped, the device still holds it |
| finalized blocks (canonical results and credits) | applied | applied | applied: byte-identical canonical state whatever the clock says |
| diagnostic reads (peer `status`, `get_block`, ...) | yes | yes | yes |

Why the settled binding is safe while unqualified: it authenticates the session only for status, stop,
retransmission of receipts this coordinator already issued to that Worker, and a hold that grants
nothing. The settled epoch never runs ahead of an epoch this process has already acted on under
qualified time, so the Worker it is currently mining with keeps status, stop and its own stored
receipts (test `v2_a_worker_bound_for_an_epoch_no_finalized_block_reached_keeps_status_stop_and_retransmission`).
Anything that binds work or credit is judged again with the current-epoch binding once the clock is
qualified (`process_held`), so no old assignment retains a right: a result held for a Worker that is no
longer bound at the epoch the clock returns to is dropped with no credit and no receipt (test
`v2_a_held_result_is_judged_again_at_the_epoch_the_clock_returns_to_and_dropped_uncredited`).

Limits, stated plainly. `last_qualified_epoch` is memory only: after a restart while unqualified the
settled binding falls back to the finalized tip's epoch, and a Worker activated only after that tip is
refused a session until the clock is qualified again (its issued work still expires within its 60 s
MiningEpoch, and nothing new is issued). The case named in the review, a PENDING reassignment of the
old Worker coexisting with the new one, could not be reproduced with the genesis fixture (the genesis
open forbids pending assignments); the test instead makes the bound Worker's own assignment effective
at an epoch no finalized block has reached, which exercises the same epoch comparison.

Not changed: the hybrid (v2) Worker path (`worker_handshake_io_v2.rs`, `worker_current_channel_v2.rs`,
the probes of `hybrid_coordinator_v2.rs`) still samples the qualified clock for its handshake and its
liveness probes. It is library code, not wired to `main.rs`. Held results are memory only: a process
restart drops them and the device retries.

#### 9.10.3 V3: exact validated locked-block reproposals

What `LocalProposer::propose` can offer while unqualified, with the checks that apply. No code of the
proposer changed: the checks were already there and are now pinned by tests.

* A persisted proposal for (height, round): returned unchanged after `RoundProposal::verify_current`
  (current parent anchor, scheduled proposer and round, eligible proposer generation) and re-execution
  of its candidate.
* A proof-of-lock (PoLC) block. The proof is a prevote quorum read from the received-vote journal:
  non-nil prevotes (step 2) of a round BEFORE the current round (round), whose membership, reputation
  and attestation roots are the current authority's (membership) and whose finalized parent anchor is
  the current one (parent), verified as a quorum with valid signatures against the current voters
  (`Certificate::verify_quorum`; proof); skipped when the held lock is newer than its round (lock); its
  block must be a stored candidate, re-executed against the current parent before anything is signed.
  The reproposal names the block and `pol_round`. Votes in that journal were fully validated at
  ingress (`VoteJournal::admit`); this is the re-check against the CURRENT authority.
* The held lock (`fallback_choice`): its own block, unchanged, without `pol_round`.
* Nothing else: a fresh choice needs a candidate eligible under the proposer's own qualified clock, so
  while unqualified no new block or timestamp is selected, and a proof whose block is not stored is not
  rebuilt.

Receiving validators judge their own votes: a fresh block vote still needs their qualified clock
(`VoteGate::Fresh`); the only exemption is the exact durable signing-decision recovery
(`VoteGate::reserved()`: a guard-marked or signed slot).

Defect found and repaired (pre-existing, on the qualified path). A proposal naming a proof of lock that
the receiving validator has not verified in its own vote table (the proof's votes have not reached it
yet) made the prevote's pure pre-check return `InvalidProof`; the driver turned that into a tick error,
which `ActorService` latches as a fault, stopping the actor. Now (`voter_driver.rs`,
`unverified_proof`) such a proposal is simply not votable yet: the round's timeouts proceed as for a
missing proposal, and the same proposal is voted once the proof arrives through validated ingress. The
pre-check touched nothing, so no state can be affected.

#### 9.10.4 V4: the locked/unqualified timer stall, repaired

Before: a LOCKED validator's propose-timeout prevote is a vote for its locked block in a new slot, a
fresh block vote; while time deferred it the driver returned early, so the validator never precommitted,
never armed its precommit timeout and stayed in its round until the clock returned (9.8).

Now (`Driver::tick`, `timeout_prevote`):

* Propose timeout. An unlocked validator prevotes nil (unchanged). A locked validator whose prevote is
  deferred for time WITHHOLDS it: no prevote at all, in particular no nil prevote in its place (a locked
  validator that prevoted nil would escape its lock, and the unlock-on-nil-quorum rule is safe only
  because locked validators never prevote nil), and its lock is untouched (the time pre-check runs before
  the reducer). `Tick::prevote_withheld` reports it.
* The prevote step is then taken without a vote: the precommit step's timer runs and, after the
  ordinary delay, the validator precommits NIL. That is the vote the protocol prescribes at the prevote
  timeout for every validator without a votable block quorum in the round; it never unlocks by itself
  (`RoundMachine::precommit(None)` keeps the lock unless OTHER validators' authenticated prevotes form a
  nil quorum in that round, exactly the rule a qualified validator follows). It arms the precommit
  timeout, and the round advances once the reducer holds a precommit quorum.
* A round whose precommit this validator has taken has passed its prevote step: no prevote is signed
  for it afterwards, even when the clock returns within the round.
* Synchronization and finality ingestion continue as before (finalized blocks, late certificates).
* Clock recovery revalidates the context. The real protection is that the driver re-derives (height,
  round) from the actor at the start of every tick and carries no vote decision from one tick to the
  next. At the actor API, `VoterActor::sign_for(VoteContext)` refuses a vote decided for a round or
  height the actor has left with the explicit, nonfatal `ActorError::StaleContext`, before the clock,
  the latch, the reducer and custody are consulted (tested directly). Inside the driver that binding is
  defence in depth only: nothing changes the round within a tick before a signature (the round changes
  only in `timeout_precommit` at the end of a tick, or in `reconcile` followed by a return), so the
  comparison cannot fail today, and replacing `sign_for` by `sign` there (review mutant N01) cannot be
  caught by a behavioural test. Should it become reachable, the driver treats `StaleContext` as
  nonfatal (`Tick::stale_context`, no fault, nothing signed) instead of letting `ActorService` latch it
  as a runtime fault. The hybrid actor has the same `voter_actor_v2::VoterActor::sign_for`.
* The locked block is validated first (the driver's priority set), so after a restart the locked
  prevote request is judged for time, not refused as an unknown proposal (test
  `v4_after_a_restart_the_locked_block_is_validated_first_and_its_prevote_judged_for_time`).

Not changed: a LEGACY unmarked, unsigned prevote reservation (a record written by an older build) still
waits for a qualified, eligible clock before its round continues: that is the exact durable-decision
recovery path, kept as it was. The hybrid stack has no driver; its actor offers `sign_for`.

#### 9.10.5 Decision table

| Decision | Code | Documentation | Tests | Status |
|---|---|---|---|---|
| V1 | no behaviour change; comments in `voter_actor.rs`, `voter_actor_v2.rs`, `counter_voter.rs`, `counter_voter_v2.rs` | 9.1, 9.3, 9.8, 9.9, 9.10.1; amendment under section 3.C of `qualification/nonce-20261002/CANDIDATE-2-ARCHITECT-BRIEFING-20261004.md` | consensus `actor_halt_latch_v1::v1_a_request_conflict_burns_no_counter_writes_nothing_and_reopen_completes_only_the_original`; the existing request-conflict tests and the `run_case` durable-halt tests (v1, and v2 in `halt_latch_v2`, whose request-conflict scenario now also asserts the counter); node `voter_unqualified::v1_an_invalid_signature_finality_claim_creates_no_durable_halt_and_a_valid_conflict_does` (real blocks); existing `finality_evidence::authenticated_conflicts_retain_both_proofs_and_halt_across_restart`, `counter_voter_v2::unrecorded_valid_own_vote_persists_local_halt_but_bad_signature_does_not`, `dividends_v1::conflicting_finalized_block_retains_both_proofs_halts_durably_and_never_switches_chain` | completed |
| V2 | `worker_coordinator.rs` (`active`, `handle`, `settled_binding`, `binding_at`, `unqualified_result`, `process_deferred_results`, `process_held`, `MAX_DEFERRED_RESULTS`), `consensus/src/coordinator.rs` (`Coordinator::retransmission`), `integrated_actor.rs` (`tick` calls `process_deferred_results`) | 9.4, 9.8, 9.10.2, a pointer in section 8 | node `worker_unqualified::v2_stop_status_and_diagnostic_reads_stay_available_while_unqualified_and_bind_nothing_new`, `v2_a_stored_receipt_is_retransmitted_byte_for_byte_while_unqualified_with_no_new_credit`, `v2_a_fresh_result_is_held_bounded_without_credit_or_receipt_and_processed_once_qualified`, `v2_finalized_results_apply_identically_whatever_the_clock_says`, `v2_a_worker_bound_for_an_epoch_no_finalized_block_reached_keeps_status_stop_and_retransmission` (review MAJOR-1), `v2_a_held_result_is_judged_again_at_the_epoch_the_clock_returns_to_and_dropped_uncredited` (review MINOR-1); updated `an_unqualified_clock_selects_signs_constructs_and_issues_nothing_new`, `work_for_a_new_height_needs_the_qualified_clock_and_finalized_ingestion_does_not`, `cold_boot_without_an_anchor_is_a_deferral_not_a_fault_and_resumes_on_qualification`; guard `work_and_candidates_are_only_constructed_behind_the_qualified_clock` (re-pinned) | implemented for the shipping Worker path, with the stated limit that the qualified-epoch memory is lost on restart (9.10.2); the hybrid Worker path is unchanged; the device reaction to the new-work error is not verified |
| V3 | proposer unchanged; driver `unverified_proof` (the defect above) | 9.4, 9.5, 9.10.3 | node `voter_unqualified::v3_an_exact_proof_of_lock_reproposal_needs_round_parent_membership_proof_and_its_own_block`, `v3_an_invalid_proof_is_never_reproposed_and_refuses_selection_without_writing`, `v3_a_proof_of_lock_older_than_the_held_lock_is_never_reproposed`, `v3_a_receiver_that_has_not_verified_the_named_proof_does_not_vote_and_does_not_fault` (failed before the repair: `Voter driver: Voter(Ingress(Bft(InvalidProof)))`); existing `a_held_lock_is_reproposed_with_its_original_bytes_and_timestamp_while_unqualified`, `a_proof_of_lock_block_is_reproposed_while_unqualified_and_changes_no_stored_block`, `a_persisted_proposal_and_the_exact_reserved_vote_are_replayed_byte_for_byte_while_unqualified` | completed |
| V4 | `voter_driver.rs` (`timeout_prevote`, the withheld prevote, the passed prevote step, the lock in the priority set, every fresh signature through `sign_for`); `voter_actor.rs` and `voter_actor_v2.rs` (`VoteContext`, `context`, `sign_for`, `ActorError::StaleContext`) | 9.1, 9.8, 9.10.4 | node `voter_unqualified::v4_a_locked_validator_keeps_round_progress_while_unqualified_with_no_prevote_and_its_lock` (fails on the pre-repair driver: "round 1 never advanced"), `v4_the_withheld_prevote_is_reported_and_clock_recovery_refuses_a_stale_round_vote`, `v4_a_passed_prevote_step_is_never_signed_when_the_clock_returns_within_the_round`, `v4_finality_is_ingested_while_locked_and_unqualified_and_signs_nothing`, `v4_after_a_restart_the_locked_block_is_validated_first_and_its_prevote_judged_for_time` (review NIT-1); consensus `actor_halt_latch_v1::v4_a_vote_decided_for_an_expired_round_is_refused_explicitly_and_touches_nothing`; v2 `halt_latch_v2::deferral_leaves_the_armed_precommit_timeout_intact` (its new stale-context part) | completed in the node driver; the hybrid stack has no driver |

Mutation checks (Windows host; each mutant applied to the committed tree, the named tests run, the
file restored and the tree verified clean against the index). Every mutant below is caught:

| Mutant | Caught by |
|---|---|
| m01 driver returns early after a withheld prevote (the old stall) | `v4_a_locked_validator_keeps_round_progress_...` ("round 1 never advanced") |
| m02 `prevote_plan`: a locked validator's request without a proposal becomes nil (a fabricated nil prevote) | same test ("no prevote decision exists for round 1") |
| m03 `RoundMachine::precommit(None)` unlocks without a nil quorum | same test ("the lock is preserved on every tick") |
| m04 `sign_for` without the context check | consensus `v4_a_vote_decided_for_an_expired_round_...`; node `v4_the_withheld_prevote_is_reported_...` |
| m05 driver without the passed-prevote-step branch | `v4_a_passed_prevote_step_is_never_signed_...` |
| m06 an unqualified fresh Result is accepted and credited | `v2_a_fresh_result_is_held_...`; guard `work_and_candidates_...` |
| m07 the result hold has no bound | `v2_a_fresh_result_is_held_...` |
| m08 new work while unqualified (`qualified.unwrap_or(0)`) | `v2_stop_status_and_diagnostic_reads_...`; guard |
| m09 no stored-receipt retransmission while unqualified | `v2_a_stored_receipt_is_retransmitted_...` |
| m10 held results never processed | `v2_a_fresh_result_is_held_...` |
| m11 `active` refuses while unqualified (the old behaviour) | `v2_stop_status_...`; guard |
| m12 a request conflict durably writes a halt marker (one counter increment) | consensus `v1_a_request_conflict_burns_no_counter_...` |
| m13 a conflicting certificate is recorded without signature verification (both sites) | node `v1_an_invalid_signature_finality_claim_...` (`Finality(IntegrityHalt)` on the forged claim) |
| m14 proposer without the lock-newer-than-proof check | `v3_a_proof_of_lock_older_than_the_held_lock_...` |
| m15 proposer without the parent check | `v3_an_exact_proof_of_lock_reproposal_...` ("another parent") |
| m16 driver faults on an unverified proof (the old behaviour) | `v3_a_receiver_that_has_not_verified_...` |
| m17 proposer without the membership check | `v3_an_exact_proof_of_lock_reproposal_...` ("another membership") |
| m18 proposer accepts a quorum of the current round as a proof | `v3_an_exact_proof_of_lock_reproposal_...` |
| r16 (review N16) `process_held` without the current-epoch re-binding | `v2_a_held_result_is_judged_again_at_the_epoch_the_clock_returns_to_and_dropped_uncredited` |
| r18 (review N18) the lock removed from the driver's validation priority set | `v4_after_a_restart_the_locked_block_is_validated_first_and_its_prevote_judged_for_time` |
| rM1 the settled binding judged at the tip epoch only (MAJOR-1 reverted) | `v2_a_worker_bound_for_an_epoch_no_finalized_block_reached_keeps_status_stop_and_retransmission` and the held-result test |

One review mutant survives by construction: r01 (review N01), the driver precommit through `sign` instead of `sign_for`, passes every `v4_` test because the round cannot change within a tick before a signature (9.10.4); the `StaleContext` refusal is tested at the actor API.

A first version of m12 (re-committing the unchanged record) was an equivalent mutant: the counter
store does not write an identical record, so nothing was burned; it was replaced by the mutant above.

#### 9.10.6 Limits and open points

* "Do not fabricate nil votes to escape them" is read as: a locked validator never signs a nil PREVOTE
  (it withholds instead); its nil PRECOMMIT at the prevote timeout is the protocol's own vote for that
  step and does not unlock. If the Architect meant that a locked, unqualified validator must sign no
  vote at all, the alternative is to run the precommit timer without a vote and advance only on other
  validators' precommit quorum; then a network in which locked validators are needed for that quorum
  makes no round progress while their clocks are unqualified.
* v1 has no counterpart of v2's durable halt for a valid own vote that custody never issued
  (`counter_voter_v2::require_local_vote`). V1 says "retain", so nothing was added.
* The hybrid Worker path and the hybrid runtime (`VotingRuntime`) are unchanged (V2, V4); they are not
  wired to `main.rs`.
* A legacy unmarked unsigned prevote reservation still holds its round until the clock is qualified
  (9.10.4).
* Each round in which this node is the scheduled proposer and re-proposes its lock while unqualified
  adds one row to `local_proposals`; the existing bound is 4,096 rows for unfinalized heights, beyond
  which `LocalProposer::propose` refuses with an error (not changed).
* Windows only: no Linux run, no physical clock, no device. A passing software test proves software
  behaviour only.
