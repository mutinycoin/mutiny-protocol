//! Package P-E, Architect decision (6): time deferral is an EXPLICIT NONFATAL result and can never
//! clear a genuine safety halt of the live voter actor (`voter_actor::VoterActor`, the module the
//! node drives).
//!
//! The actor's `halted` field is a one-way latch. `sign` and `replay` take their time verdict BEFORE
//! the latch, from one clock reading that the voter then reuses, and report a refusal for local time
//! reasons as `ActorError::TimeDeferred` without touching it. Nothing resets `halted` for a deferral.
//! A healthy actor that is only waiting for time keeps doing every permitted thing (retransmit the
//! stored vote byte for byte, nil votes and the precommit timeout, finalized ingestion and sync) and
//! resumes cleanly. An actor halted for counter inconsistency, backend corruption, an unreadable
//! counter, a durable chain integrity halt, a stored reducer halt bit or a REQUEST conflict STAYS
//! halted across later ticks (`sign` and `replay`) and across a pending deferral in either order.
//! Across close and reopen, a cause that lives in durable state is re-derived (the open, or the
//! first vote attempt, refuses again), while a request conflict is held in memory only: the
//! reopened actor resumes the ORIGINAL decision and refuses the conflicting request again.
//!
//! Controlled clocks only, offline; the fixture is the synthetic integration-state-v2-1 chain. This
//! proves the rule for the software actor; it is not a physical or qualified-clock result.
use minicbor::{Decoder, Encoder};
use mutiny_consensus_v8::{
    Error, Hash,
    bft::Step,
    block_envelope::BlockEnvelope,
    blocks::{GenesisDescriptor, state_root},
    canonical_store::CanonicalStore,
    counter_store::{CounterError, CounterStore, MonotonicCounter},
    counter_voter::{CounterSigningBackend, CounterVoterError},
    execution::State,
    freshness::{PhysicalAttestationVerifier, PhysicalMember},
    vote_clock_v1::{ClockReading, ControlledClock, TimeStatus, VoteClock},
    voter_actor::{self, ActorError, VoteContext, VoterActor},
    votes::{AuthenticatedRound, IngressError, Vote},
};
use p256::ecdsa::{Signature, SigningKey, signature::hazmat::PrehashSigner};
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

struct Backend {
    key: SigningKey,
    counter: u64,
    signs: u64,
    fail_sign: bool,
    fail_read: bool,
}
impl MonotonicCounter for Backend {
    fn read(&mut self) -> std::result::Result<u64, String> {
        if self.fail_read {
            return Err("counter unreadable".into());
        }
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
        self.signs += 1;
        if self.fail_sign {
            return Err("interrupted at the signing boundary".into());
        }
        let s: Signature = self.key.sign_prehash(&d).unwrap();
        Ok(s.normalize_s().unwrap_or(s).to_bytes().into())
    }
}
struct Evidence;
impl PhysicalAttestationVerifier for Evidence {
    fn verify(&self, _: &PhysicalMember, c: Hash, e: &[u8]) -> mutiny_consensus_v8::Result<()> {
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

struct Dir(PathBuf);
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
type Custody = (Vec<u8>, Vec<u8>, Option<Vec<u8>>);
/// Everything observable about custody: the counter, the signing calls and the durable record.
type Mark = (u64, u64, Custody);
/// The actor's in-memory safety and scheduling state: the halting latch, the voter poison and the
/// armed precommit timeout (height, round, deadline). A time deferral must not touch it either.
type Local = (bool, bool, Option<(u64, u64, Instant)>);

/// Fixture chain + live actor + software TPM, with a controlled clock. `_dir` is the LAST field so
/// the files are closed before the directory is removed.
struct Rig {
    descriptor: GenesisDescriptor,
    initial: State,
    target: Hash,
    physical: BTreeMap<Hash, PhysicalMember>,
    node: Hash,
    block0: BlockEnvelope,
    chain_path: PathBuf,
    voter_path: PathBuf,
    backend: Backend,
    clock: Arc<ControlledClock>,
    actor: Option<VoterActor>,
    chain: CanonicalStore,
    _dir: Dir,
}
const START: u64 = 1000;
impl Rig {
    fn new(label: &str) -> Rig {
        static SERIAL: AtomicU64 = AtomicU64::new(0);
        let mut lines =
            include_str!("../../qualification/integration-state-v2-1/chain.jsonl").lines();
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
        let target: Hash = raw(&bundle["initial_target"]).try_into().unwrap();
        let node = *physical.keys().next().unwrap();
        let first: serde_json::Value = serde_json::from_str(lines.next().unwrap()).unwrap();
        let block0 = BlockEnvelope::decode(&raw(&first["envelope"])).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "build8-halt-latch-{label}-{}-{}",
            std::process::id(),
            SERIAL.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let chain_path = dir.join("chain.sqlite");
        let voter_path = dir.join("voter.sqlite");
        let mut chain =
            CanonicalStore::open_trusted_genesis(&chain_path, &descriptor, &initial, target)
                .unwrap();
        let mut backend = Backend {
            key: SigningKey::from_bytes((&[17; 32]).into()).unwrap(),
            counter: START,
            signs: 0,
            fail_sign: false,
            fail_read: false,
        };
        let mut actor = VoterActor::open(
            &voter_path,
            node,
            Some(START),
            &mut chain,
            &mut backend,
            &physical,
            &Evidence,
        )
        .unwrap();
        let clock = ControlledClock::at(block0.header.candidate.timestamp);
        actor.set_vote_clock(clock.clone());
        Rig {
            descriptor,
            initial,
            target,
            physical,
            node,
            block0,
            chain_path,
            voter_path,
            backend,
            clock,
            actor: Some(actor),
            chain,
            _dir: Dir(dir),
        }
    }
    fn ts(&self) -> u64 {
        self.block0.header.candidate.timestamp
    }
    fn block(&self) -> Hash {
        self.block0.block_hash()
    }
    fn actor(&mut self) -> &mut VoterActor {
        self.actor.as_mut().expect("actor is open")
    }
    /// Qualified, exactly at the block's timestamp: the block is eligible.
    fn eligible(&self) {
        self.clock.set_qualified(true);
        self.clock.set(self.ts());
    }
    fn unqualified(&self) {
        self.clock.set_qualified(false);
    }
    /// Qualified but `ahead` seconds behind the block's timestamp.
    fn behind(&self, ahead: u64) {
        self.clock.set_qualified(true);
        self.clock.set(self.ts() - ahead);
    }
    /// One of the clock states the scenarios sweep: "unqualified", "behind" (9 s behind the block)
    /// or "eligible".
    fn clock_to(&self, state: &str) {
        match state {
            "unqualified" => self.unqualified(),
            "behind" => self.behind(9),
            "eligible" => self.eligible(),
            other => panic!("unknown clock state {other}"),
        }
    }
    fn validate(&mut self) {
        let block0 = self.block0.clone();
        self.actor
            .as_mut()
            .unwrap()
            .validate_proposal(&mut self.chain, &block0, &self.physical, &Evidence)
            .unwrap();
    }
    fn sign(&mut self, step: Step, block: Option<Hash>) -> Result<Vote, ActorError> {
        self.actor
            .as_mut()
            .unwrap()
            .sign(&mut self.chain, step, block, None, &mut self.backend)
    }
    fn replay(&mut self, step: Step) -> Result<Option<Vote>, ActorError> {
        self.actor
            .as_mut()
            .unwrap()
            .replay(&mut self.chain, step, &mut self.backend)
    }
    fn check(&mut self) -> Result<(), ActorError> {
        self.actor
            .as_mut()
            .unwrap()
            .check_backend(&mut self.chain, &mut self.backend)
    }
    fn reconcile(&mut self) -> Result<(), ActorError> {
        self.actor.as_mut().unwrap().reconcile(
            &mut self.chain,
            &mut self.backend,
            &self.physical,
            &Evidence,
        )
    }
    fn timeout(&mut self) -> Result<Option<u64>, ActorError> {
        self.actor
            .as_mut()
            .unwrap()
            .timeout_precommit(&mut self.chain, &mut self.backend)
    }
    fn custody(&self) -> Custody {
        let db = rusqlite::Connection::open_with_flags(
            &self.voter_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        db.query_row(
            "SELECT tip,snapshot,pending FROM voter_snapshot WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap()
    }
    fn mark(&self) -> Mark {
        (self.backend.counter, self.backend.signs, self.custody())
    }
    fn local(&mut self) -> Local {
        let actor = self.actor();
        (
            actor.is_halted(),
            actor.voter_poisoned(),
            actor.precommit_deadline(),
        )
    }
    /// Close the actor AND the canonical store, then open both again from disk. The clock is the
    /// rig's controlled clock, as the node installs its qualified clock after every open.
    fn reopen(&mut self) -> Result<(), ActorError> {
        self.actor = None;
        self.chain = CanonicalStore::open_trusted_genesis(
            &self.chain_path,
            &self.descriptor,
            &self.initial,
            self.target,
        )
        .unwrap();
        let mut actor = VoterActor::open(
            &self.voter_path,
            self.node,
            None,
            &mut self.chain,
            &mut self.backend,
            &self.physical,
            &Evidence,
        )?;
        actor.set_vote_clock(self.clock.clone());
        self.actor = Some(actor);
        Ok(())
    }
    /// A durable, SIGNED, guard-marked (version 3) prevote for the proposal in a healthy actor that
    /// holds a qualified, eligible clock.
    fn with_stored_prevote(label: &str) -> Rig {
        let mut rig = Rig::new(label);
        rig.validate();
        let block = rig.block();
        let vote = rig.sign(Step::Prevote, Some(block)).unwrap();
        assert!(!vote.nil);
        rig
    }
    /// A durable, UNSIGNED, UNMARKED (version 1) prevote reservation for the proposal, exactly what
    /// an old build leaves after a crash between the reservation and the signature. The actor that
    /// is running afterwards is a fresh, healthy one that has executed the proposal; the clock is
    /// left unqualified.
    fn with_legacy_reservation(label: &str) -> Rig {
        let mut rig = Rig::new(label);
        rig.validate();
        rig.backend.fail_sign = true;
        let e = rig.sign(Step::Prevote, Some(rig.block())).unwrap_err();
        assert!(
            matches!(e, ActorError::Voter(CounterVoterError::Backend)),
            "{e:?}"
        );
        assert!(rig.actor().is_halted(), "an interrupted signature halts");
        rig.backend.fail_sign = false;
        assert_eq!(rig.backend.counter, START + 1, "one reservation commit");
        // Rewrite the durable record as a version-1 build left it: unsigned, NO guard marker.
        commit_as_version_1(&mut rig);
        rig.unqualified();
        rig.reopen().unwrap();
        rig.validate();
        let reserved = rig
            .actor()
            .progress()
            .unwrap()
            .1
            .expect("reservation survived");
        assert_eq!(reserved.signature, [0; 64], "unsigned");
        assert_eq!(reserved.decision.block, rig.block());
        rig
    }
}

/// Close the actor and rewrite the durable record exactly as a version-1 build left it: the same
/// decisions, with NO guard marker. The rewrite goes through the real counter store, so the counter
/// advances once.
fn commit_as_version_1(rig: &mut Rig) {
    rig.actor = None;
    let (parent, state) = {
        let (tip, state) = rig.chain.load_effective().unwrap();
        let (parent, _) = rig.chain.execution_parent(tip.height).unwrap();
        (parent, state)
    };
    let authority = voter_actor::authority(&parent, &state).unwrap();
    let context = AuthenticatedRound::new(authority)
        .unwrap()
        .signing_context(rig.node)
        .unwrap();
    let mut store = CounterStore::open(&rig.voter_path, context, None, &mut rig.backend).unwrap();
    let legacy = to_legacy(store.snapshot());
    store.commit(&legacy, &mut rig.backend).unwrap();
}

/// Re-encode a version-3 snapshot as the version-1 record an old build wrote (no gated marker).
fn to_legacy(v3: &[u8]) -> Vec<u8> {
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

/// Reads differ by call number: the first reading is `first`, every later one is `rest`. `reads`
/// counts how many times the actor consulted the clock.
struct Flap {
    reads: Arc<AtomicU64>,
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

fn is_deferred(e: &ActorError, status: TimeStatus) -> bool {
    e.is_time_deferral() && e.time_deferral() == Some(status)
}
/// The old, implicit shapes of a time deferral must never come out of the actor any more: they would
/// be indistinguishable from a fault for a caller that matches on the error.
fn is_legacy_deferral_shape(e: &ActorError) -> bool {
    matches!(
        e,
        ActorError::Voter(CounterVoterError::Ingress(
            IngressError::FutureTimestamp { .. } | IngressError::ClockUnqualified
        )) | ActorError::Ingress(
            IngressError::FutureTimestamp { .. } | IngressError::ClockUnqualified
        )
    )
}

// ---------------------------------------------------------------------------------------------
// A healthy actor that is only waiting for time keeps its permitted work and resumes cleanly.
// ---------------------------------------------------------------------------------------------

#[test]
fn a_healthy_actor_waiting_for_time_retransmits_the_stored_vote_byte_for_byte_and_resumes_cleanly()
{
    let mut rig = Rig::new("waiting");
    rig.validate();
    let block = rig.block();
    // Qualified and eligible: the prevote passes the fresh guard and is stored, signed.
    let prevote = rig.sign(Step::Prevote, Some(block)).unwrap();
    assert!(!prevote.nil);
    assert_eq!(prevote.decision.block, block);
    rig.actor().observe(&prevote).unwrap();
    let stored = rig.actor().progress().unwrap().1.expect("stored prevote");
    assert_eq!(stored.encode(), prevote.encode());
    let after_vote = (rig.mark(), rig.local());
    // The qualified clock is lost, then it is regressed behind the block, over several ticks.
    for (round, state) in [
        ("unqualified", None),
        ("behind 7 s", Some(7u64)),
        ("unqualified again", None),
    ] {
        match state {
            None => rig.unqualified(),
            Some(ahead) => rig.behind(ahead),
        }
        for tick in 0..3 {
            // Stored vote retransmission: byte for byte, no signature, no counter use.
            let again = rig
                .replay(Step::Prevote)
                .unwrap_or_else(|e| panic!("{round}/{tick}: {e:?}"))
                .expect("stored prevote");
            assert_eq!(again.encode(), prevote.encode(), "{round}/{tick}");
            assert_eq!(
                rig.replay(Step::Precommit).unwrap(),
                None,
                "{round}/{tick}: nothing stored for the precommit slot"
            );
            // A fresh block vote needs the guard: the explicit nonfatal deferral, nothing else.
            let deferred = rig.sign(Step::Precommit, Some(block)).unwrap_err();
            let expected = match state {
                None => TimeStatus::Unqualified,
                Some(ahead) => TimeStatus::Future {
                    ahead_seconds: ahead,
                },
            };
            assert!(
                is_deferred(&deferred, expected),
                "{round}/{tick}: {deferred:?}"
            );
            assert!(!is_legacy_deferral_shape(&deferred));
            assert!(!rig.actor().is_halted(), "{round}/{tick}");
            rig.check().expect("a healthy actor stays healthy");
            assert_eq!(
                (rig.mark(), rig.local()),
                after_vote,
                "{round}/{tick}: nothing was touched, in custody or in memory"
            );
        }
    }
    // Permitted local work continues meanwhile.
    rig.actor().observe(&prevote).unwrap();
    rig.validate();
    // Time returns: the SAME actor completes the round, no restart, no reset.
    rig.eligible();
    let precommit = rig.sign(Step::Precommit, Some(block)).unwrap();
    assert!(!precommit.nil);
    assert_eq!(precommit.decision.block, block);
    rig.actor().observe(&precommit).unwrap();
    assert!(!rig.actor().is_halted());
    // The retransmitted prevote is still the identical stored bytes.
    assert_eq!(
        rig.replay(Step::Prevote).unwrap().unwrap().encode(),
        prevote.encode()
    );
}

#[test]
fn finalized_ingestion_and_sync_proceed_while_time_defers_and_leave_the_latch_alone() {
    let mut rig = Rig::new("ingest");
    rig.validate();
    let block = rig.block();
    rig.unqualified();
    let deferred = rig.sign(Step::Prevote, Some(block)).unwrap_err();
    assert!(
        is_deferred(&deferred, TimeStatus::Unqualified),
        "{deferred:?}"
    );
    assert!(!rig.actor().is_halted());
    // Finalized ingestion reads no clock: the certified block commits while the clock is lost, and
    // the actor reconciles to the new height from revalidated canonical evidence (sync).
    let block0 = rig.block0.clone();
    assert!(
        rig.chain
            .commit_integrated(&block0, &rig.physical, &Evidence)
            .unwrap()
    );
    rig.reconcile().unwrap();
    assert_eq!(rig.actor().height(), 2);
    assert!(!rig.actor().is_halted());
    rig.check().unwrap();
    // The next height starts clean. Nil is still available; a block vote is still deferred or
    // unknown, never a halt.
    let nil = rig.sign(Step::Prevote, None).unwrap();
    assert!(nil.nil);
    assert_eq!(nil.decision.height, 2);
    assert!(!rig.actor().is_halted());
}

#[test]
fn nil_votes_and_the_precommit_timeout_proceed_while_the_clock_is_unqualified() {
    let mut rig = Rig::new("nil");
    rig.unqualified();
    let before = rig.backend.counter;
    let prevote = rig.sign(Step::Prevote, None).unwrap();
    assert!(prevote.nil, "nil carries no block and needs no clock");
    rig.actor().observe(&prevote).unwrap();
    let precommit = rig.sign(Step::Precommit, None).unwrap();
    assert!(precommit.nil);
    rig.actor().observe(&precommit).unwrap();
    // Elapsed time alone advances nothing: the monotonic deadline has not passed yet.
    assert_eq!(rig.timeout().unwrap(), None);
    let stored = rig.backend.counter;
    assert!(stored > before);
    std::thread::sleep(Duration::from_millis(3150));
    assert_eq!(rig.timeout().unwrap(), Some(1), "round 0 times out");
    assert_eq!(rig.backend.counter, stored + 1);
    assert!(!rig.actor().is_halted());
    // The next round's nil vote is a new slot and again needs no clock.
    let next = rig.sign(Step::Prevote, None).unwrap();
    assert!(next.nil);
    assert_eq!(next.decision.round, 1);
    assert!(!rig.actor().is_halted());
}

// ---------------------------------------------------------------------------------------------
// The deferral is explicit, pure, and never touches the latch (so nothing is ever reset).
// ---------------------------------------------------------------------------------------------

#[test]
fn a_time_deferral_is_explicit_pure_and_never_touches_custody_or_the_latch() {
    let mut rig = Rig::with_legacy_reservation("pure");
    let block = rig.block();
    let before = (rig.mark(), rig.local());
    for (clock, expected) in [
        (None, TimeStatus::Unqualified),
        (Some(5u64), TimeStatus::Future { ahead_seconds: 5 }),
        (Some(1u64), TimeStatus::Future { ahead_seconds: 1 }),
    ] {
        match clock {
            None => rig.unqualified(),
            Some(ahead) => rig.behind(ahead),
        }
        // Completing the unmarked legacy reservation needs the guard now.
        let e = rig.replay(Step::Prevote).unwrap_err();
        assert!(is_deferred(&e, expected), "replay: {e:?}");
        assert!(!is_legacy_deferral_shape(&e));
        // A fresh vote in the same slot is judged identically.
        let e = rig.sign(Step::Prevote, Some(block)).unwrap_err();
        assert!(is_deferred(&e, expected), "sign: {e:?}");
        assert!(!rig.actor().is_halted());
        rig.actor().progress().expect("custody is not poisoned");
        assert_eq!(
            (rig.mark(), rig.local()),
            before,
            "no signature, no counter, no record, no in-memory change"
        );
    }
    // Zero allowance: at the timestamp the exact reserved decision completes, and only it.
    rig.eligible();
    let done = rig.replay(Step::Prevote).unwrap().expect("completes");
    assert_eq!(done.decision.block, block);
    assert_ne!(done.signature, [0; 64]);
    assert_eq!(rig.backend.signs, 2, "interrupted attempt + the completion");
    assert!(!rig.actor().is_halted());
    // Afterwards the record is version 3 and recovery no longer depends on the clock.
    rig.unqualified();
    assert_eq!(
        rig.replay(Step::Prevote).unwrap().unwrap().encode(),
        done.encode()
    );
}

#[test]
fn an_unexecuted_proposal_is_a_recoverable_absence_not_a_halt_and_not_a_time_deferral() {
    let mut rig = Rig::with_legacy_reservation("unknown");
    let block = rig.block();
    // A restart forgets the executed proposal: the reducer must execute it again first.
    rig.reopen().unwrap();
    rig.unqualified();
    let before = (rig.mark(), rig.local());
    let e = rig.replay(Step::Prevote).unwrap_err();
    assert!(
        matches!(
            &e,
            ActorError::Voter(CounterVoterError::Ingress(IngressError::UnknownProposal))
        ),
        "{e:?}"
    );
    assert!(!e.is_time_deferral());
    let e = rig.sign(Step::Prevote, Some(block)).unwrap_err();
    assert!(
        matches!(
            &e,
            ActorError::Voter(CounterVoterError::Ingress(IngressError::UnknownProposal))
        ),
        "{e:?}"
    );
    // It touched nothing and halted nothing; once the proposal is executed the verdict is the
    // ordinary time deferral.
    assert!(!rig.actor().is_halted());
    assert_eq!((rig.mark(), rig.local()), before);
    rig.validate();
    let e = rig.replay(Step::Prevote).unwrap_err();
    assert!(is_deferred(&e, TimeStatus::Unqualified), "{e:?}");
    assert!(!rig.actor().is_halted());
}

#[test]
fn one_clock_reading_serves_each_attempt_so_a_flapping_clock_cannot_halt_or_bypass_the_guard() {
    let qualified = |ts: u64| ClockReading::Qualified { utc_seconds: ts };
    // sign: eligible on the first read, unqualified afterwards. A second read inside the attempt
    // would have deferred AFTER the latch and left the actor halted. One read: it simply succeeds.
    let mut rig = Rig::new("flap-sign-ok");
    rig.validate();
    let reads = Arc::new(AtomicU64::new(0));
    let ts = rig.ts();
    rig.actor().set_vote_clock(Arc::new(Flap {
        reads: reads.clone(),
        first: qualified(ts),
        rest: ClockReading::Unqualified,
    }));
    let block = rig.block();
    let vote = rig.sign(Step::Prevote, Some(block)).unwrap();
    assert!(!vote.nil);
    assert_eq!(
        reads.load(Ordering::SeqCst),
        1,
        "exactly one reading per attempt"
    );
    assert!(!rig.actor().is_halted());
    // sign: unqualified on the first read, eligible afterwards. The refusal stands (the guard was
    // not bypassed by the later reading) and the actor is untouched; the next attempt succeeds.
    let mut rig = Rig::new("flap-sign-defer");
    rig.validate();
    let reads = Arc::new(AtomicU64::new(0));
    let ts = rig.ts();
    rig.actor().set_vote_clock(Arc::new(Flap {
        reads: reads.clone(),
        first: ClockReading::Unqualified,
        rest: qualified(ts),
    }));
    let before = (rig.mark(), rig.local());
    let e = rig.sign(Step::Prevote, Some(block)).unwrap_err();
    assert!(is_deferred(&e, TimeStatus::Unqualified), "{e:?}");
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert!(!rig.actor().is_halted());
    assert_eq!((rig.mark(), rig.local()), before);
    assert!(!rig.sign(Step::Prevote, Some(block)).unwrap().nil);
    // replay of an unmarked legacy reservation: same two shapes.
    let mut rig = Rig::with_legacy_reservation("flap-replay-ok");
    let reads = Arc::new(AtomicU64::new(0));
    let ts = rig.ts();
    rig.actor().set_vote_clock(Arc::new(Flap {
        reads: reads.clone(),
        first: qualified(ts),
        rest: ClockReading::Unqualified,
    }));
    let done = rig.replay(Step::Prevote).unwrap().expect("completes");
    assert_eq!(done.decision.block, block);
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert!(!rig.actor().is_halted());
    let mut rig = Rig::with_legacy_reservation("flap-replay-defer");
    let reads = Arc::new(AtomicU64::new(0));
    let ts = rig.ts();
    rig.actor().set_vote_clock(Arc::new(Flap {
        reads: reads.clone(),
        first: ClockReading::Unqualified,
        rest: qualified(ts),
    }));
    let before = (rig.mark(), rig.local());
    let e = rig.replay(Step::Prevote).unwrap_err();
    assert!(is_deferred(&e, TimeStatus::Unqualified), "{e:?}");
    assert_eq!(reads.load(Ordering::SeqCst), 1);
    assert!(!rig.actor().is_halted());
    assert_eq!((rig.mark(), rig.local()), before);
    assert_eq!(
        rig.replay(Step::Prevote).unwrap().unwrap().decision.block,
        block
    );
}

#[test]
fn a_time_deferral_leaves_the_armed_precommit_timeout_and_all_in_memory_state_intact() {
    // A deferral leaves in-memory actor state alone too, the armed precommit timeout included (a
    // gap the review's mutation run M8 exposed). A nil precommit needs no clock, and signing it
    // arms the round's precommit deadline. Deferrals of every shape then leave the latch, the voter
    // poison, the deadline and custody exactly as they were, and the armed timeout still fires.
    let mut rig = Rig::with_legacy_reservation("deadline");
    let block = rig.block();
    let precommit = rig.sign(Step::Precommit, None).unwrap();
    assert!(precommit.nil);
    rig.actor().observe(&precommit).unwrap();
    let (height, round, deadline) = rig
        .actor()
        .precommit_deadline()
        .expect("a signed precommit arms the timeout");
    assert_eq!((height, round), (1, 0));
    let before = (rig.mark(), rig.local());
    for clock in ["unqualified", "behind"] {
        rig.clock_to(clock);
        // Completing the unmarked legacy prevote reservation, and a request that matches it.
        let e = rig.replay(Step::Prevote).unwrap_err();
        assert!(e.is_time_deferral(), "{clock}: {e:?}");
        let e = rig.sign(Step::Prevote, Some(block)).unwrap_err();
        assert!(e.is_time_deferral(), "{clock}: {e:?}");
        assert_eq!(
            (rig.mark(), rig.local()),
            before,
            "{clock}: a deferral touches nothing, in custody or in memory"
        );
    }
    // The armed timeout still fires: elapsed time plus the reducer's precommit quorum.
    std::thread::sleep(
        deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(100),
    );
    rig.unqualified();
    assert_eq!(rig.timeout().unwrap(), Some(1), "round 0 times out");
    assert!(!rig.actor().is_halted());
}

// ---------------------------------------------------------------------------------------------
// Genuine halts are never cleared by a time deferral: tick, replay, both orders, reopen.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cause {
    /// The backend counter differs from the durable reservation.
    CounterInconsistency,
    /// The backend reports another public key than the one the custody is bound to.
    BackendKeyMismatch,
    /// The backend cannot report a counter at all (an impossible state).
    BackendCounterUnreadable,
    /// The canonical store carries a durable integrity halt (conflicting finality).
    ChainIntegrityHalt,
    /// The durable record is an UNMARKED legacy reservation for the block and the request names
    /// nil: a request conflict. Like every request conflict it is found by the pure pre-check,
    /// before the latch and before the clock is consulted, whatever the slot's marker.
    RequestConflictsWithAnUnmarkedRecord,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Order {
    /// Time deferrals first (the actor is healthy), then the genuine halt.
    DeferralThenHalt,
    /// The genuine halt first, then time deferrals are presented to the halted actor.
    HaltThenDeferral,
}

fn all_calls_report_halted(rig: &mut Rig, why: &str) {
    let block = rig.block();
    let before = rig.mark();
    assert!(rig.actor().is_halted(), "{why}");
    assert!(
        matches!(rig.actor().progress(), Err(ActorError::Halted)),
        "{why}"
    );
    assert!(matches!(rig.check(), Err(ActorError::Halted)), "{why}");
    assert!(matches!(rig.reconcile(), Err(ActorError::Halted)), "{why}");
    assert!(matches!(rig.timeout(), Err(ActorError::Halted)), "{why}");
    let block0 = rig.block0.clone();
    assert!(
        matches!(
            rig.actor.as_mut().unwrap().validate_proposal(
                &mut rig.chain,
                &block0,
                &rig.physical,
                &Evidence
            ),
            Err(ActorError::Halted)
        ),
        "{why}"
    );
    // A sample vote (any would do): a halted actor refuses to observe.
    let sample = Vote {
        nil: true,
        decision: mutiny_consensus_v8::certificates::Decision {
            network: mutiny_consensus_v8::NETWORK_ID,
            genesis: [0; 32],
            fingerprint: [0; 32],
            purpose: 2,
            height: 1,
            mining_epoch: 0,
            continuity_period: 0,
            round: 0,
            step: 2,
            previous_finalized_anchor: [0; 32],
            parent: [0; 32],
            block: [0; 32],
            state: [0; 32],
            membership: [0; 32],
            reputation: [0; 32],
            attestation: [0; 32],
        },
        node: rig.node,
        key_version: 1,
        signature: [0; 64],
    };
    assert!(
        matches!(rig.actor().observe(&sample), Err(ActorError::Halted)),
        "{why}"
    );
    // The pending deferrals of every shape, under every clock: always `Halted`, never a deferral,
    // never a retransmission, and the latch never moves.
    for clock in ["unqualified", "behind", "eligible"] {
        match clock {
            "unqualified" => rig.unqualified(),
            "behind" => rig.behind(5),
            _ => rig.eligible(),
        }
        for step in [Step::Prevote, Step::Precommit] {
            let e = rig.replay(step).unwrap_err();
            assert!(
                matches!(e, ActorError::Halted),
                "{why}/{clock}/replay: {e:?}"
            );
            for target in [Some(block), None] {
                let e = rig.sign(step, target).unwrap_err();
                assert!(matches!(e, ActorError::Halted), "{why}/{clock}/sign: {e:?}");
                assert!(!e.is_time_deferral());
            }
        }
        assert!(rig.actor().is_halted(), "{why}/{clock}");
    }
    assert_eq!(rig.mark(), before, "{why}: a halted actor touches nothing");
}

/// Present every shape of time deferral to a HEALTHY actor and check that none of them halts it.
fn deferrals_are_nonfatal(rig: &mut Rig, why: &str) {
    let block = rig.block();
    let before = (rig.mark(), rig.local());
    rig.unqualified();
    let e = rig.replay(Step::Prevote).unwrap_err();
    assert!(is_deferred(&e, TimeStatus::Unqualified), "{why}: {e:?}");
    let e = rig.sign(Step::Prevote, Some(block)).unwrap_err();
    assert!(is_deferred(&e, TimeStatus::Unqualified), "{why}: {e:?}");
    rig.behind(4);
    let e = rig.replay(Step::Prevote).unwrap_err();
    assert!(
        is_deferred(&e, TimeStatus::Future { ahead_seconds: 4 }),
        "{why}: {e:?}"
    );
    let e = rig.sign(Step::Prevote, Some(block)).unwrap_err();
    assert!(
        is_deferred(&e, TimeStatus::Future { ahead_seconds: 4 }),
        "{why}: {e:?}"
    );
    assert!(!rig.actor().is_halted(), "{why}");
    rig.check().expect("healthy");
    assert_eq!((rig.mark(), rig.local()), before, "{why}");
    rig.unqualified();
}

fn inject(rig: &mut Rig, cause: Cause) {
    match cause {
        Cause::CounterInconsistency => rig.backend.counter += 2,
        Cause::BackendKeyMismatch => {
            rig.backend.key = SigningKey::from_bytes((&[18; 32]).into()).unwrap()
        }
        Cause::BackendCounterUnreadable => rig.backend.fail_read = true,
        Cause::ChainIntegrityHalt => {
            // The flag finality.rs writes when two certified blocks conflict at one height.
            let db = rusqlite::Connection::open(&rig.chain_path).unwrap();
            db.execute("UPDATE integrity SET halted=1 WHERE id=1", [])
                .unwrap();
            assert!(rig.chain.integrity_halted().unwrap());
        }
        Cause::RequestConflictsWithAnUnmarkedRecord => {}
    }
}
fn repair(rig: &mut Rig, cause: Cause) {
    match cause {
        Cause::CounterInconsistency => rig.backend.counter -= 2,
        Cause::BackendKeyMismatch => {
            rig.backend.key = SigningKey::from_bytes((&[17; 32]).into()).unwrap()
        }
        Cause::BackendCounterUnreadable => rig.backend.fail_read = false,
        Cause::ChainIntegrityHalt | Cause::RequestConflictsWithAnUnmarkedRecord => {}
    }
}
/// The first call after the cause appeared. It must fail with the cause (or `Halted`), halt the
/// actor, and sign nothing.
fn notice(rig: &mut Rig, cause: Cause) {
    let signs = rig.backend.signs;
    match cause {
        Cause::CounterInconsistency => {
            let e = rig.check().unwrap_err();
            assert!(
                matches!(
                    &e,
                    ActorError::Voter(CounterVoterError::Counter(CounterError::Rollback))
                ),
                "{e:?}"
            );
        }
        Cause::BackendKeyMismatch => {
            let e = rig.check().unwrap_err();
            assert!(
                matches!(
                    &e,
                    ActorError::Voter(CounterVoterError::Invalid(Error::WrongGeneration))
                ),
                "{e:?}"
            );
        }
        Cause::BackendCounterUnreadable => {
            let e = rig.check().unwrap_err();
            assert!(
                matches!(
                    &e,
                    ActorError::Voter(CounterVoterError::Counter(CounterError::Backend))
                ),
                "{e:?}"
            );
        }
        Cause::ChainIntegrityHalt => {
            let e = rig.check().unwrap_err();
            assert!(matches!(e, ActorError::Halted), "{e:?}");
        }
        Cause::RequestConflictsWithAnUnmarkedRecord => {
            // The slot holds a prevote for the block; the request is NIL, which no clock gates.
            let e = rig.sign(Step::Prevote, None).unwrap_err();
            assert!(
                matches!(&e, ActorError::Voter(CounterVoterError::ConflictingVote)),
                "{e:?}"
            );
            assert!(
                rig.actor().voter_poisoned(),
                "a request conflict also poisons the voter"
            );
        }
    }
    assert!(rig.actor().is_halted(), "{cause:?} halts the actor");
    assert_eq!(rig.backend.signs, signs, "{cause:?}: nothing was signed");
}

/// After close and reopen: a cause that lives in durable state still refuses the open (and the
/// refusal names it); a request conflict is held in memory only, so the reopened actor is healthy,
/// can complete only the ORIGINAL decision and halts again on the conflicting request.
fn reopen_keeps_the_halt(rig: &mut Rig, cause: Cause, record: &Custody) {
    let block = rig.block();
    rig.actor = None;
    match cause {
        Cause::CounterInconsistency => {
            let e = rig.reopen().unwrap_err();
            assert!(
                matches!(
                    &e,
                    ActorError::Voter(CounterVoterError::Counter(CounterError::Rollback))
                ),
                "{e:?}"
            );
        }
        Cause::BackendKeyMismatch => {
            let e = rig.reopen().unwrap_err();
            assert!(
                matches!(
                    &e,
                    ActorError::Voter(CounterVoterError::Invalid(Error::WrongGeneration))
                ),
                "{e:?}"
            );
        }
        Cause::BackendCounterUnreadable => {
            let e = rig.reopen().unwrap_err();
            assert!(
                matches!(
                    &e,
                    ActorError::Voter(CounterVoterError::Counter(CounterError::Backend))
                ),
                "{e:?}"
            );
        }
        Cause::ChainIntegrityHalt => {
            let e = rig.reopen().unwrap_err();
            assert!(matches!(e, ActorError::Halted), "{e:?}");
            assert!(rig.chain.integrity_halted().unwrap(), "the halt is durable");
        }
        Cause::RequestConflictsWithAnUnmarkedRecord => {
            rig.reopen().expect("an intact record reopens");
            rig.validate();
            // In memory only: the reopen yields a healthy actor, and the durable decision is the
            // only one that exists:
            assert!(!rig.actor().is_halted() && !rig.actor().voter_poisoned());
            rig.unqualified();
            let e = rig.replay(Step::Prevote).unwrap_err();
            assert!(is_deferred(&e, TimeStatus::Unqualified), "{e:?}");
            rig.eligible();
            let done = rig
                .replay(Step::Prevote)
                .unwrap()
                .expect("original completes");
            assert!(
                !done.nil,
                "the ORIGINAL decision (the block), not the nil request"
            );
            assert_eq!(done.decision.block, block);
            // and the conflicting request halts the reopened actor again, signing nothing.
            let signs = rig.backend.signs;
            let e = rig.sign(Step::Prevote, None).unwrap_err();
            assert!(
                matches!(&e, ActorError::Voter(CounterVoterError::ConflictingVote)),
                "{e:?}"
            );
            assert!(rig.actor().is_halted());
            assert_eq!(rig.backend.signs, signs);
            return;
        }
    }
    // The durable record survived untouched while the cause held (reading it needs no backend).
    assert_eq!(
        &rig.custody(),
        record,
        "{cause:?}: the stored decision is untouched"
    );
    // Repairing the BACKEND (not the actor) is the only way back: a full revalidating reopen.
    if cause != Cause::ChainIntegrityHalt {
        repair(rig, cause);
        rig.reopen().expect("repaired backend reopens");
        rig.validate();
        rig.eligible();
        let done = rig.replay(Step::Prevote).unwrap().expect("stored decision");
        assert_eq!(done.decision.block, block);
        assert!(!rig.actor().is_halted());
    }
}

fn run_case(cause: Cause, order: Order) {
    let label = format!("{cause:?}-{order:?}");
    let mut rig = Rig::with_legacy_reservation(&label);
    let record = rig.custody();
    if order == Order::DeferralThenHalt {
        deferrals_are_nonfatal(&mut rig, &label);
    }
    inject(&mut rig, cause);
    notice(&mut rig, cause);
    // Halt then deferral: the deferral shapes (a legacy unmarked reservation and a fresh block vote,
    // under an unqualified, a regressed and an eligible clock) are presented to the HALTED actor.
    // Deferral then halt: the same, after the actor already served them while healthy. Either way
    // every call reports `Halted`, nothing is retransmitted, nothing is signed, the latch holds.
    all_calls_report_halted(&mut rig, &label);
    reopen_keeps_the_halt(&mut rig, cause, &record);
}

#[test]
fn counter_inconsistency_stays_halted_across_deferrals_both_orders_and_reopen() {
    for order in [Order::DeferralThenHalt, Order::HaltThenDeferral] {
        run_case(Cause::CounterInconsistency, order);
    }
}
#[test]
fn backend_key_corruption_stays_halted_across_deferrals_both_orders_and_reopen() {
    for order in [Order::DeferralThenHalt, Order::HaltThenDeferral] {
        run_case(Cause::BackendKeyMismatch, order);
    }
}
#[test]
fn an_unreadable_backend_counter_stays_halted_across_deferrals_both_orders_and_reopen() {
    for order in [Order::DeferralThenHalt, Order::HaltThenDeferral] {
        run_case(Cause::BackendCounterUnreadable, order);
    }
}
#[test]
fn a_durable_chain_integrity_halt_stays_halted_across_deferrals_both_orders_and_reopen() {
    for order in [Order::DeferralThenHalt, Order::HaltThenDeferral] {
        run_case(Cause::ChainIntegrityHalt, order);
    }
}
/// A request conflict halts the live actor across deferrals in both orders. It is held in memory
/// only (the latch and the voter poison): a reopen resumes the original decision, and the
/// conflicting request halts the reopened actor again.
#[test]
fn request_conflict_unmarked_record_halts_in_memory_only_and_reopen_resumes_the_original() {
    for order in [Order::DeferralThenHalt, Order::HaltThenDeferral] {
        run_case(Cause::RequestConflictsWithAnUnmarkedRecord, order);
    }
}

#[test]
fn a_cause_that_is_noticed_by_the_deferring_call_itself_is_reported_not_deferred() {
    // The cause appears while a deferral is pending and is not yet noticed. The very call that
    // would have returned the deferral runs the backend check first: it reports the cause, halts the
    // actor, and the deferral that was pending is never delivered.
    for (cause, replay) in [
        (Cause::CounterInconsistency, true),
        (Cause::CounterInconsistency, false),
        (Cause::BackendKeyMismatch, true),
        (Cause::BackendKeyMismatch, false),
        (Cause::BackendCounterUnreadable, true),
        (Cause::BackendCounterUnreadable, false),
        (Cause::ChainIntegrityHalt, true),
        (Cause::ChainIntegrityHalt, false),
    ] {
        let mut rig = Rig::with_legacy_reservation(&format!("noticed-{cause:?}-{replay}"));
        let block = rig.block();
        rig.unqualified();
        // The deferral is pending (and would be returned right now):
        let e = rig.replay(Step::Prevote).unwrap_err();
        assert!(is_deferred(&e, TimeStatus::Unqualified), "{e:?}");
        inject(&mut rig, cause);
        let signs = rig.backend.signs;
        let e = if replay {
            rig.replay(Step::Prevote).unwrap_err()
        } else {
            rig.sign(Step::Prevote, Some(block)).unwrap_err()
        };
        assert!(!e.is_time_deferral(), "{cause:?}: {e:?}");
        assert!(rig.actor().is_halted(), "{cause:?}");
        assert_eq!(rig.backend.signs, signs);
        // And the pending deferral can no longer be delivered, whatever the clock does.
        rig.eligible();
        let e = rig.replay(Step::Prevote).unwrap_err();
        assert!(matches!(e, ActorError::Halted), "{cause:?}: {e:?}");
        assert!(rig.actor().is_halted());
    }
}

#[test]
fn request_conflict_guarded_decision_halts_any_clock_in_memory_only_reopen_resumes_original() {
    // The slot holds a SIGNED, guard-marked prevote for the block. A request for NIL in the same
    // slot contradicts the durable decision. That verdict is taken in the pure pre-check, before
    // the latch, and must still be a genuine halt: it can neither be mistaken for a time deferral
    // nor be skipped because the clock is lost. The request conflict is held in memory only: a
    // reopen resumes the original decision and refuses the conflicting request again.
    for clock in ["eligible", "unqualified", "behind"] {
        let mut rig = Rig::new(&format!("guarded-conflict-{clock}"));
        rig.validate();
        let block = rig.block();
        let stored = rig.sign(Step::Prevote, Some(block)).unwrap();
        rig.actor().observe(&stored).unwrap();
        match clock {
            "eligible" => rig.eligible(),
            "unqualified" => rig.unqualified(),
            _ => rig.behind(9),
        }
        let before = rig.mark();
        let e = rig.sign(Step::Prevote, None).unwrap_err();
        assert!(
            matches!(&e, ActorError::Voter(CounterVoterError::ConflictingVote)),
            "{clock}: {e:?}"
        );
        assert!(!e.is_time_deferral());
        assert!(
            rig.actor().is_halted(),
            "{clock}: a conflicting decision halts"
        );
        assert!(
            rig.actor().voter_poisoned(),
            "{clock}: and poisons the voter"
        );
        assert_eq!(rig.mark(), before, "{clock}: nothing was signed or written");
        // It stays halted: no retransmission, no deferral, whatever the clock does now.
        all_calls_report_halted(&mut rig, &format!("guarded-conflict-{clock}"));
        // In memory only: the reopened actor is healthy, retransmits the ORIGINAL decision byte for
        // byte, and refuses the conflicting request again.
        rig.actor = None;
        rig.eligible();
        rig.reopen().expect("intact record reopens");
        rig.validate();
        assert!(!rig.actor().voter_poisoned(), "{clock}: in memory only");
        let again = rig.replay(Step::Prevote).unwrap().unwrap();
        assert_eq!(
            again.encode(),
            stored.encode(),
            "{clock}: byte-exact retransmission"
        );
        assert!(!rig.actor().is_halted());
        let e = rig.sign(Step::Prevote, None).unwrap_err();
        assert!(matches!(
            &e,
            ActorError::Voter(CounterVoterError::ConflictingVote)
        ));
        assert!(rig.actor().is_halted());
    }
}

#[test]
fn a_request_conflicting_with_an_unmarked_legacy_reservation_halts_before_the_time_gate() {
    // Review finding MINOR-1. The slot holds an UNMARKED legacy (version-1) reservation: an
    // interrupted NIL precommit. Once the prevote for the block is observed again, a request to
    // precommit the BLOCK contradicts that stored decision. The comparison runs before the time
    // gate, so the request is a conflicting durable decision under EVERY clock: the actor halts and
    // nothing is signed or written. (Before the repair an unqualified or regressed clock reported
    // it as a time deferral, and only a qualified clock found the conflict.) The request conflict is
    // held in memory only: a reopen resumes the ORIGINAL decision, the nil precommit, which needs no
    // clock, and the conflicting request halts the reopened actor again.
    for clock in ["unqualified", "behind", "eligible"] {
        let label = format!("legacy-conflict-{clock}");
        let mut rig = Rig::new(&label);
        rig.validate();
        let block = rig.block();
        let prevote = rig.sign(Step::Prevote, Some(block)).unwrap();
        rig.actor().observe(&prevote).unwrap();
        rig.backend.fail_sign = true;
        let e = rig.sign(Step::Precommit, None).unwrap_err();
        assert!(
            matches!(e, ActorError::Voter(CounterVoterError::Backend)),
            "{e:?}"
        );
        rig.backend.fail_sign = false;
        commit_as_version_1(&mut rig);
        rig.reopen().unwrap();
        rig.validate();
        let (_, stored_prevote, stored_precommit) = rig.actor().progress().unwrap();
        let stored_precommit = stored_precommit.expect("the interrupted nil precommit");
        assert!(stored_precommit.nil && stored_precommit.signature == [0; 64]);
        let stored_prevote = stored_prevote.expect("the signed prevote");
        assert_eq!(stored_prevote.encode(), prevote.encode());
        rig.actor().observe(&stored_prevote).unwrap();
        rig.clock_to(clock);
        let before = rig.mark();
        let e = rig.sign(Step::Precommit, Some(block)).unwrap_err();
        assert!(
            matches!(&e, ActorError::Voter(CounterVoterError::ConflictingVote)),
            "{clock}: {e:?}"
        );
        assert!(!e.is_time_deferral(), "{clock}");
        assert!(rig.actor().is_halted(), "{clock}: a request conflict halts");
        assert!(
            rig.actor().voter_poisoned(),
            "{clock}: and poisons the voter"
        );
        assert_eq!(rig.mark(), before, "{clock}: nothing signed or written");
        all_calls_report_halted(&mut rig, &label);
        // In memory only: the reopened actor completes the ORIGINAL decision without a clock.
        rig.actor = None;
        rig.unqualified();
        rig.reopen().expect("an intact record reopens");
        rig.validate();
        rig.actor().observe(&prevote).unwrap();
        assert!(!rig.actor().voter_poisoned(), "{clock}: in memory only");
        let signs = rig.backend.signs;
        let done = rig
            .replay(Step::Precommit)
            .unwrap()
            .expect("the original decision completes");
        assert!(
            done.nil,
            "{clock}: the nil precommit, not the conflicting request"
        );
        assert_eq!(rig.backend.signs, signs + 1, "{clock}: one completion");
        assert!(!rig.actor().is_halted());
        // and the conflicting request is refused again, whatever the clock.
        rig.clock_to(clock);
        let before = rig.mark();
        let e = rig.sign(Step::Precommit, Some(block)).unwrap_err();
        assert!(
            matches!(&e, ActorError::Voter(CounterVoterError::ConflictingVote)),
            "{clock}: {e:?}"
        );
        assert!(rig.actor().is_halted());
        assert_eq!(rig.mark(), before, "{clock}: nothing signed or written");
    }
}

// ---------------------------------------------------------------------------------------------
// A corrupt durable lock or vote refuses every reopen (the cause is in the store itself).
// ---------------------------------------------------------------------------------------------

/// Rewrite the durable record through the real counter store: `edit` receives the decoded
/// version-3 fields and returns the replacement record bytes.
fn rewrite_record(
    rig: &mut Rig,
    edit: impl FnOnce(u64, Vec<u8>, Vec<(u64, u8, Vec<u8>, bool, bool)>) -> Vec<u8>,
) {
    rig.actor = None;
    let (parent, state) = {
        let (tip, state) = rig.chain.load_effective().unwrap();
        let (parent, _) = rig.chain.execution_parent(tip.height).unwrap();
        (parent, state)
    };
    let authority = voter_actor::authority(&parent, &state).unwrap();
    let context = AuthenticatedRound::new(authority)
        .unwrap()
        .signing_context(rig.node)
        .unwrap();
    let mut store = CounterStore::open(&rig.voter_path, context, None, &mut rig.backend).unwrap();
    let mut d = Decoder::new(store.snapshot());
    assert_eq!(d.array().unwrap(), Some(4));
    assert_eq!(d.u8().unwrap(), 3);
    let height = d.u64().unwrap();
    let state = d.bytes().unwrap().to_vec();
    let count = d.array().unwrap().unwrap();
    let mut votes = Vec::new();
    for _ in 0..count {
        assert_eq!(d.array().unwrap(), Some(5));
        votes.push((
            d.u64().unwrap(),
            d.u8().unwrap(),
            d.bytes().unwrap().to_vec(),
            d.bool().unwrap(),
            d.bool().unwrap(),
        ));
    }
    let replacement = edit(height, state, votes);
    store.commit(&replacement, &mut rig.backend).unwrap();
}
fn encode_record(height: u64, state: &[u8], votes: &[(u64, u8, Vec<u8>, bool, bool)]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(4)
        .unwrap()
        .u8(3)
        .unwrap()
        .u64(height)
        .unwrap()
        .bytes(state)
        .unwrap()
        .array(votes.len() as u64)
        .unwrap();
    for (round, step, vote, signed, gated) in votes {
        e.array(5)
            .unwrap()
            .u64(*round)
            .unwrap()
            .u8(*step)
            .unwrap()
            .bytes(vote)
            .unwrap()
            .bool(*signed)
            .unwrap()
            .bool(*gated)
            .unwrap();
    }
    e.into_writer()
}
/// Set the reducer integrity-halt bit (`LockState.halted`) of the durable record and keep every
/// stored vote and guard marker: the lock state becomes version 1, round 0, no lock, not finalized,
/// halted.
fn set_reducer_halt_bit(rig: &mut Rig) {
    rewrite_record(rig, |height, _state, votes| {
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(1)
            .unwrap()
            .u64(0)
            .unwrap()
            .null()
            .unwrap()
            .null()
            .unwrap()
            .bool(true)
            .unwrap();
        encode_record(height, &e.into_writer(), &votes)
    });
}

#[test]
fn a_corrupt_stored_lock_or_vote_refuses_every_reopen_whatever_the_clock_says() {
    // 1. A stored lock newer than its own round (a lock the reducer can never have held).
    let mut rig = Rig::with_stored_prevote("corrupt-lock");
    let block = rig.block();
    rewrite_record(&mut rig, |height, _state, votes| {
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(1)
            .unwrap()
            .u64(0)
            .unwrap()
            .array(2)
            .unwrap()
            .u64(5)
            .unwrap()
            .bytes(&block)
            .unwrap()
            .null()
            .unwrap()
            .bool(false)
            .unwrap();
        encode_record(height, &e.into_writer(), &votes)
    });
    for clock in ["unqualified", "behind", "eligible"] {
        match clock {
            "unqualified" => rig.unqualified(),
            "behind" => rig.behind(5),
            _ => rig.eligible(),
        }
        assert!(
            rig.reopen().is_err(),
            "{clock}: a corrupt lock is never reopened"
        );
        assert!(rig.actor.is_none());
    }
    // 2. A stored vote whose own decision names another round than its slot.
    let mut rig = Rig::with_stored_prevote("corrupt-vote");
    rewrite_record(&mut rig, |height, state, mut votes| {
        let mut vote = Vote::decode(&votes[0].2).unwrap();
        vote.decision.round += 1;
        votes[0].2 = vote.encode();
        encode_record(height, &state, &votes)
    });
    for clock in ["unqualified", "eligible"] {
        match clock {
            "unqualified" => rig.unqualified(),
            _ => rig.eligible(),
        }
        assert!(
            rig.reopen().is_err(),
            "{clock}: a conflicting stored vote is never reopened"
        );
        assert!(rig.actor.is_none());
    }
    // 3. Two stored votes for one slot cannot even be written canonically.
    let mut rig = Rig::with_stored_prevote("corrupt-dup");
    rewrite_record(&mut rig, |height, state, mut votes| {
        let again = votes[0].clone();
        votes.push(again);
        encode_record(height, &state, &votes)
    });
    assert!(rig.reopen().is_err());
}

#[test]
fn a_reducer_halt_found_by_the_pre_check_halts_the_actor_whatever_the_clock_says() {
    // A durable reducer state with `halted = true` (the integrity-halt bit of the lock state) does
    // not stop the open itself, but the very first `sign` (here) or `replay` (the next test) finds
    // it in the pure pre-check, before the latch. That is a genuine halt, not a recoverable refusal
    // and not a deferral.
    for clock in ["eligible", "unqualified", "behind"] {
        let mut rig = Rig::with_stored_prevote(&format!("reducer-halt-{clock}"));
        let block = rig.block();
        set_reducer_halt_bit(&mut rig);
        match clock {
            "eligible" => rig.eligible(),
            "unqualified" => rig.unqualified(),
            _ => rig.behind(9),
        }
        rig.reopen()
            .expect("the stored halt bit alone does not refuse the open");
        rig.validate();
        assert!(!rig.actor().is_halted());
        let signs = rig.backend.signs;
        let e = rig.sign(Step::Prevote, Some(block)).unwrap_err();
        assert!(
            matches!(
                &e,
                ActorError::Voter(CounterVoterError::Ingress(IngressError::Bft(
                    mutiny_consensus_v8::bft::BftError::IntegrityHalt
                )))
            ),
            "{clock}: {e:?}"
        );
        assert!(!e.is_time_deferral());
        assert!(
            rig.actor().is_halted(),
            "{clock}: a halted reducer halts the actor"
        );
        assert!(
            rig.actor().voter_poisoned(),
            "{clock}: and poisons the voter"
        );
        assert_eq!(rig.backend.signs, signs, "{clock}: nothing was signed");
        all_calls_report_halted(&mut rig, &format!("reducer-halt-{clock}"));
    }
}

#[test]
fn a_stored_reducer_halt_refuses_replay_halts_the_actor_and_signs_nothing() {
    // Review finding MINOR-2. A record whose reducer state carries the integrity-halt bit is no more
    // replayable than it is signable: `replay`'s pure pre-check refuses with `IntegrityHalt`, the
    // actor halts and nothing is retransmitted, completed or written, whatever the clock says. Both
    // stored shapes: a SIGNED prevote (before the repair it was retransmitted) and an UNSIGNED
    // guard-marked reservation (before the repair it was completed: one signature, one counter
    // commit, and the actor stayed healthy).
    for clock in ["eligible", "unqualified", "behind"] {
        for signed in [true, false] {
            let label = format!("replay-reducer-halt-{clock}-{signed}");
            let mut rig = if signed {
                Rig::with_stored_prevote(&label)
            } else {
                let mut rig = Rig::new(&label);
                rig.validate();
                rig.backend.fail_sign = true;
                let block = rig.block();
                let e = rig.sign(Step::Prevote, Some(block)).unwrap_err();
                assert!(
                    matches!(e, ActorError::Voter(CounterVoterError::Backend)),
                    "{e:?}"
                );
                rig.backend.fail_sign = false;
                rig
            };
            set_reducer_halt_bit(&mut rig);
            rig.clock_to(clock);
            rig.reopen()
                .expect("the stored halt bit alone does not refuse the open");
            rig.validate();
            let stored = rig.actor().progress().unwrap().1.expect("stored prevote");
            assert_eq!(stored.signature != [0; 64], signed, "{label}");
            assert!(!rig.actor().is_halted());
            let before = rig.mark();
            let e = rig.replay(Step::Prevote).unwrap_err();
            assert!(
                matches!(
                    &e,
                    ActorError::Voter(CounterVoterError::Ingress(IngressError::Bft(
                        mutiny_consensus_v8::bft::BftError::IntegrityHalt
                    )))
                ),
                "{label}: {e:?}"
            );
            assert!(!e.is_time_deferral());
            assert!(
                rig.actor().is_halted(),
                "{label}: a halted reducer halts the actor"
            );
            assert!(
                rig.actor().voter_poisoned(),
                "{label}: and poisons the voter"
            );
            assert_eq!(
                rig.mark(),
                before,
                "{label}: nothing retransmitted, completed or written"
            );
            all_calls_report_halted(&mut rig, &label);
        }
    }
}

#[test]
fn request_conflict_is_in_memory_only_reopen_resumes_original_and_refuses_the_conflict_again() {
    // A request conflict is held in memory only, in v1 and v2 alike: the latch and the voter
    // poison, nothing written. A reopen therefore resumes the original decision, and the conflict
    // is found again from the intact counter-protected record the next time the conflicting
    // request is made (the node's driver never makes one: it replays a stored decision). Whether a
    // request conflict should become a durable halt is the Architect's decision
    // (docs/OS-CLOCK-CLASSIFICATION-V1.md section 9.9); this test pins the behaviour as
    // implemented.
    let mut rig = Rig::new("reopen-healthy");
    rig.validate();
    let block = rig.block();
    let stored = rig.sign(Step::Prevote, Some(block)).unwrap();
    assert!(matches!(
        rig.sign(Step::Prevote, None).unwrap_err(),
        ActorError::Voter(CounterVoterError::ConflictingVote)
    ));
    assert!(rig.actor().is_halted());
    assert!(rig.actor().voter_poisoned());
    assert!(matches!(rig.actor().progress(), Err(ActorError::Halted)));
    rig.reopen().unwrap();
    rig.validate();
    assert!(
        !rig.actor().is_halted() && !rig.actor().voter_poisoned(),
        "a reopen revalidates both stores and starts clean"
    );
    assert_eq!(
        rig.replay(Step::Prevote).unwrap().unwrap().encode(),
        stored.encode()
    );
    assert!(matches!(
        rig.sign(Step::Prevote, None).unwrap_err(),
        ActorError::Voter(CounterVoterError::ConflictingVote)
    ));
    assert!(rig.actor().is_halted());
}

// ---------------------------------------------------------------------------------------------
// Candidate 3, Architect decision V1: a request conflict is a refused REQUEST, not evidence of two
// durable decisions. It is held in memory only, writes nothing and burns, reuses or consumes no
// counter value; the reopened actor completes only the original decision. The true durable halts
// (counter, key and backend inconsistency, the canonical integrity halt) are re-derived on every
// reopen by the `run_case` tests above.
// ---------------------------------------------------------------------------------------------

#[test]
fn v1_a_request_conflict_burns_no_counter_writes_nothing_and_reopen_completes_only_the_original() {
    for signed in [true, false] {
        let label = format!("v1-no-burn-{signed}");
        let mut rig = Rig::new(&label);
        rig.validate();
        let block = rig.block();
        // The slot's one durable decision: a prevote for the block, either signed or reserved and
        // interrupted at the signing boundary (unsigned, guard-marked).
        if signed {
            assert!(!rig.sign(Step::Prevote, Some(block)).unwrap().nil);
        } else {
            rig.backend.fail_sign = true;
            let e = rig.sign(Step::Prevote, Some(block)).unwrap_err();
            assert!(
                matches!(e, ActorError::Voter(CounterVoterError::Backend)),
                "{e:?}"
            );
            rig.backend.fail_sign = false;
            rig.reopen().unwrap();
            rig.validate();
        }
        let record = rig.custody();
        let (counter, signs) = (rig.backend.counter, rig.backend.signs);
        // The conflicting REQUEST (nil for the same slot), repeated under every clock: refused and
        // halting every time, but nothing is written, signed or counted.
        for clock in ["eligible", "unqualified", "behind"] {
            rig.clock_to(clock);
            for _ in 0..3 {
                let e = rig.sign(Step::Prevote, None).unwrap_err();
                assert!(
                    matches!(
                        &e,
                        ActorError::Voter(CounterVoterError::ConflictingVote) | ActorError::Halted
                    ),
                    "{label}/{clock}: {e:?}"
                );
                assert!(rig.actor().is_halted());
            }
            assert_eq!(
                (rig.backend.counter, rig.backend.signs),
                (counter, signs),
                "{label}/{clock}: no counter value burned, nothing signed"
            );
            assert_eq!(
                rig.custody(),
                record,
                "{label}/{clock}: no second decision written"
            );
        }
        // The reopen is healthy and itself uses no counter value.
        rig.actor = None;
        rig.eligible();
        rig.reopen().expect("an intact record reopens");
        rig.validate();
        assert!(!rig.actor().is_halted() && !rig.actor().voter_poisoned());
        assert_eq!(
            rig.backend.counter, counter,
            "{label}: the reopen uses no counter value"
        );
        // Only the ORIGINAL decision completes or is retransmitted ...
        let done = rig
            .replay(Step::Prevote)
            .unwrap()
            .expect("the original decision");
        assert_eq!((done.nil, done.decision.block), (false, block));
        if signed {
            assert_eq!(
                (rig.backend.counter, rig.backend.signs),
                (counter, signs),
                "{label}: retransmission uses no counter value and no signature"
            );
            assert_eq!(rig.custody(), record);
        } else {
            assert_eq!(
                (rig.backend.counter, rig.backend.signs),
                (counter + 1, signs + 1),
                "{label}: completion is one signature and one commit at the NEXT counter value"
            );
        }
        // ... and the conflicting request is refused again, still burning nothing.
        let after = (rig.backend.counter, rig.backend.signs, rig.custody());
        let e = rig.sign(Step::Prevote, None).unwrap_err();
        assert!(
            matches!(&e, ActorError::Voter(CounterVoterError::ConflictingVote)),
            "{label}: {e:?}"
        );
        assert_eq!(
            (rig.backend.counter, rig.backend.signs, rig.custody()),
            after
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Candidate 3, Architect decision V4: clock recovery revalidates the current context instead of
// signing for an expired round. `sign_for` binds a request to the (height, round) it was decided
// in; once the actor has left it, the request is refused explicitly and touches nothing.
// ---------------------------------------------------------------------------------------------

#[test]
fn v4_a_vote_decided_for_an_expired_round_is_refused_explicitly_and_touches_nothing() {
    let mut rig = Rig::new("v4-stale");
    rig.validate();
    let block = rig.block();
    rig.unqualified();
    let decided = rig.actor().context().unwrap();
    assert_eq!(
        decided,
        VoteContext {
            height: 1,
            round: 0
        }
    );
    // While the clock is lost a block prevote decided for round 0 is deferred. Round 0 then times
    // out on nil votes (real 3 s monotonic deadline).
    assert!(
        rig.sign(Step::Prevote, Some(block))
            .unwrap_err()
            .is_time_deferral()
    );
    let nil = rig.sign(Step::Prevote, None).unwrap();
    rig.actor().observe(&nil).unwrap();
    let nil = rig.sign(Step::Precommit, None).unwrap();
    rig.actor().observe(&nil).unwrap();
    std::thread::sleep(Duration::from_millis(3150));
    assert_eq!(rig.timeout().unwrap(), Some(1));
    let current = rig.actor().context().unwrap();
    assert_eq!(
        current,
        VoteContext {
            height: 1,
            round: 1
        }
    );
    // The clock returns and the round-0 decision is presented again: refused for every step and
    // target, and for a context of another height, before the clock, the latch, the reducer or
    // custody are consulted.
    rig.eligible();
    let before = (rig.mark(), rig.local());
    for requested in [
        decided,
        VoteContext {
            height: 2,
            round: 1,
        },
    ] {
        for (step, target) in [
            (Step::Prevote, Some(block)),
            (Step::Prevote, None),
            (Step::Precommit, Some(block)),
            (Step::Precommit, None),
        ] {
            let e = rig
                .actor
                .as_mut()
                .unwrap()
                .sign_for(
                    &mut rig.chain,
                    requested,
                    step,
                    target,
                    None,
                    &mut rig.backend,
                )
                .unwrap_err();
            assert!(
                matches!(
                    e,
                    ActorError::StaleContext { requested: r, current: c }
                        if r == requested && c == current
                ),
                "{requested:?}/{step:?}/{target:?}: {e:?}"
            );
            assert!(!e.is_time_deferral());
        }
    }
    assert_eq!(
        (rig.mark(), rig.local()),
        before,
        "nothing signed, written, latched or poisoned"
    );
    // The current context signs: the block prevote of round 1.
    let vote = rig
        .actor
        .as_mut()
        .unwrap()
        .sign_for(
            &mut rig.chain,
            current,
            Step::Prevote,
            Some(block),
            None,
            &mut rig.backend,
        )
        .unwrap();
    assert_eq!(
        (vote.decision.round, vote.nil, vote.decision.block),
        (1, false, block)
    );
    rig.actor().observe(&vote).unwrap();
    // A stale request is never mistaken for a request conflict: the same nil prevote request for
    // round 0, presented through `sign`, would contradict round 1's stored block decision and halt.
    let e = rig
        .actor
        .as_mut()
        .unwrap()
        .sign_for(
            &mut rig.chain,
            decided,
            Step::Prevote,
            None,
            None,
            &mut rig.backend,
        )
        .unwrap_err();
    assert!(matches!(e, ActorError::StaleContext { .. }), "{e:?}");
    assert!(!rig.actor().is_halted() && !rig.actor().voter_poisoned());
    // A genuine halt cause is still reported by the backend check that precedes the context check.
    rig.backend.counter += 2;
    let e = rig
        .actor
        .as_mut()
        .unwrap()
        .sign_for(
            &mut rig.chain,
            decided,
            Step::Prevote,
            None,
            None,
            &mut rig.backend,
        )
        .unwrap_err();
    assert!(
        matches!(
            &e,
            ActorError::Voter(CounterVoterError::Counter(CounterError::Rollback))
        ),
        "{e:?}"
    );
    assert!(rig.actor().is_halted());
}

#[test]
fn no_deferral_shape_other_than_the_explicit_variant_ever_leaves_the_actor() {
    // Sweep every clock state over sign and replay of a healthy actor and a legacy reservation:
    // a deferral is only ever `TimeDeferred`; the old implicit shapes are gone.
    let mut rig = Rig::with_legacy_reservation("shapes");
    let block = rig.block();
    for clock in [None, Some(1u64), Some(60), Some(86_400)] {
        match clock {
            None => rig.unqualified(),
            Some(ahead) => rig.behind(ahead),
        }
        for e in [
            rig.replay(Step::Prevote).unwrap_err(),
            rig.sign(Step::Prevote, Some(block)).unwrap_err(),
        ] {
            assert!(e.is_time_deferral(), "{e:?}");
            assert!(!is_legacy_deferral_shape(&e), "{e:?}");
            assert!(matches!(e, ActorError::TimeDeferred(_)));
        }
    }
}
