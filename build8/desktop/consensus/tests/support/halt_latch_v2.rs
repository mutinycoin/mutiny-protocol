//! Package P-E, Architect decision (6), hybrid actor: a time deferral is an EXPLICIT NONFATAL
//! result and can never clear a genuine halt. Same properties as `tests/actor_halt_latch_v1.rs`,
//! for `voter_actor_v2::VoterActor` (the hybrid modules are not wired into the node; they are kept
//! consistent). Controlled clocks, synthetic custody; offline, not physical.
//!
//! Included by `support/voter_actor_v2.rs` (the only hybrid actor fixture) and run at the end of
//! `actor_fixture::qualify`, i.e. from the hybrid admission test.
//!
//! Cost: in this debug build every actor call re-reads the canonical store (`current(chain)`, about
//! half a second), so the fixture is built to need few of them: scenarios that leave the chain at
//! height zero share ONE store (each rig has its own voter custody file), only the scenarios that
//! change the chain own one, and the durable custody of a crash between a reservation and its
//! signature is built ONCE and copied for every scenario that needs it.
use super::*;
use minicbor::{Decoder, Encoder};
use mutiny_consensus_v8::{
    continuity_v2::Vote,
    counter_store::CounterError,
    counter_store_v2::CounterStore as V2Store,
    counter_voter::CounterVoterError,
    vote_clock_v1::{ClockReading, ControlledClock, TimeStatus, VoteClock},
    votes::IngressError,
    votes_v2::AuthenticatedRound,
};
use mutiny_crypto_v2::Role;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

type Custody = (Vec<u8>, Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>);
type Mark = (u64, u64, Custody);
/// The actor's in-memory safety and scheduling state: the halting latch, the voter poison and the
/// armed precommit timeout (height, round, deadline). A time deferral must not touch it either.
type Local = (bool, bool, Option<(u64, u64, std::time::Instant)>);
struct Dir(std::path::PathBuf);
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn unique_dir(label: &str) -> std::path::PathBuf {
    let mut nonce = [0; 8];
    mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
    let dir = std::env::temp_dir().join(format!(
        "build8-halt-latch-v2-{label}-{}",
        hex::encode(nonce)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
#[derive(Clone, Copy)]
struct Fixtures<'a> {
    state: &'a State,
    genesis: &'a FinalizedAnchor,
    root: Hash,
    fixture: &'a BlockEnvelope,
    key: &'a HybridKey,
    wrong: &'a HybridKey,
}
fn open_chain(
    path: &std::path::Path,
    genesis: &FinalizedAnchor,
    state: &State,
    root: Hash,
) -> CanonicalStore {
    CanonicalStore::open_trusted_genesis(path, genesis, state, root, 1000, [255; 32]).unwrap()
}
/// A canonical store with its own directory. `chain` is declared before `_dir`, so the connection
/// is closed before the directory is removed.
struct OwnedChain {
    chain: CanonicalStore,
    path: std::path::PathBuf,
    _dir: Dir,
}
fn owned_chain(label: &str, a: &Fixtures<'_>) -> OwnedChain {
    let dir = unique_dir(label);
    let path = dir.join("chain.sqlite");
    let chain = open_chain(&path, a.genesis, a.state, a.root);
    OwnedChain {
        chain,
        path,
        _dir: Dir(dir),
    }
}
/// The durable custody of an actor that crashed between a reservation and its signature, as an old
/// build left it: an UNSIGNED, UNMARKED (version 2) prevote reservation for the proposal.
struct Legacy {
    custody: Vec<u8>,
    counter: u64,
}
/// A live actor with its own voter custody over a (possibly shared) canonical store and a synthetic
/// counter. `_dir` is the LAST field so the custody file is closed before its directory is removed.
struct Hx<'a> {
    a: Fixtures<'a>,
    node: Hash,
    voter_path: std::path::PathBuf,
    backend: Backend<'a>,
    clock: Arc<ControlledClock>,
    actor: Option<VoterActor>,
    chain: &'a mut CanonicalStore,
    _dir: Dir,
}
impl<'a> Hx<'a> {
    fn assemble(
        a: &Fixtures<'a>,
        chain: &'a mut CanonicalStore,
        dir: Dir,
        voter_path: std::path::PathBuf,
        backend: Backend<'a>,
        actor: VoterActor,
        clock: Arc<ControlledClock>,
    ) -> Hx<'a> {
        Hx {
            a: *a,
            node: a.fixture.certificate.votes[0].node,
            voter_path,
            backend,
            clock,
            actor: Some(actor),
            chain,
            _dir: dir,
        }
    }
    fn backend(a: &Fixtures<'a>, counter: u64) -> Backend<'a> {
        Backend {
            key: a.key,
            counter,
            calls: 0,
            interrupt: false,
            fail_sign: false,
        }
    }
    /// Fresh custody (no stored decision), eligible clock.
    fn new(label: &str, a: &Fixtures<'a>, chain: &'a mut CanonicalStore) -> Hx<'a> {
        let dir = unique_dir(label);
        let voter_path = dir.join("voter.sqlite");
        let node = a.fixture.certificate.votes[0].node;
        let mut backend = Hx::backend(a, 100);
        let mut actor =
            VoterActor::open(&voter_path, node, Some(100), &mut *chain, &mut backend).unwrap();
        let clock = ControlledClock::at(a.fixture.header.candidate.timestamp);
        actor.set_vote_clock(clock.clone());
        Hx::assemble(a, chain, Dir(dir), voter_path, backend, actor, clock)
    }
    /// Custody copied from a crash between a reservation and its signature, opened healthy, the
    /// proposal executed, the clock lost.
    fn from_legacy(
        label: &str,
        a: &Fixtures<'a>,
        chain: &'a mut CanonicalStore,
        legacy: &Legacy,
    ) -> Hx<'a> {
        let dir = unique_dir(label);
        let voter_path = dir.join("voter.sqlite");
        std::fs::write(&voter_path, &legacy.custody).unwrap();
        let node = a.fixture.certificate.votes[0].node;
        let mut backend = Hx::backend(a, legacy.counter);
        let mut actor =
            VoterActor::open(&voter_path, node, None, &mut *chain, &mut backend).unwrap();
        let clock = ControlledClock::at(a.fixture.header.candidate.timestamp);
        actor.set_vote_clock(clock.clone());
        let mut rig = Hx::assemble(a, chain, Dir(dir), voter_path, backend, actor, clock);
        rig.unqualified();
        rig.validate();
        let reserved = rig
            .actor()
            .progress()
            .unwrap()
            .1
            .expect("reservation survived");
        assert_eq!(reserved.signature.ed448, [0; 114], "unsigned");
        assert_eq!(reserved.decision.block, rig.block());
        rig
    }
    fn ts(&self) -> u64 {
        self.a.fixture.header.candidate.timestamp
    }
    fn block(&self) -> Hash {
        self.a.fixture.block_hash()
    }
    fn actor(&mut self) -> &mut VoterActor {
        self.actor.as_mut().expect("actor is open")
    }
    fn eligible(&self) {
        self.clock.set_qualified(true);
        self.clock.set(self.ts());
    }
    fn unqualified(&self) {
        self.clock.set_qualified(false);
    }
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
    /// Close the actor and rewrite the durable record exactly as a version-2 build left it: the
    /// same decisions, with NO guard marker. The rewrite goes through the real counter store, so
    /// the counter advances once. The canonical store must still be at height zero.
    fn commit_as_version_2(&mut self) {
        self.actor = None;
        let context = AuthenticatedRound::new(self.chain.voting_authority_at(0).unwrap())
            .unwrap()
            .signing_context(self.node)
            .unwrap();
        let mut store =
            V2Store::open(&self.voter_path, context, None, None, &mut self.backend).unwrap();
        let legacy = to_legacy(store.snapshot());
        store.commit(&legacy, &mut self.backend).unwrap();
    }
    fn validate(&mut self) {
        self.actor
            .as_mut()
            .unwrap()
            .validate_proposal(&*self.chain, self.a.fixture)
            .unwrap();
    }
    fn sign(&mut self, step: Step, block: Option<Hash>) -> Result<Vote, ActorError> {
        self.actor
            .as_mut()
            .unwrap()
            .sign(&*self.chain, step, block, None, &mut self.backend)
    }
    fn observe(&mut self, vote: &Vote) {
        self.actor
            .as_mut()
            .unwrap()
            .observe(&*self.chain, vote, &mut self.backend)
            .unwrap();
    }
    fn replay(&mut self, step: Step) -> Result<Option<Vote>, ActorError> {
        self.actor
            .as_mut()
            .unwrap()
            .replay(&*self.chain, step, &mut self.backend)
    }
    fn check(&mut self) -> Result<(), ActorError> {
        self.actor
            .as_mut()
            .unwrap()
            .check_backend(&*self.chain, &mut self.backend)
    }
    fn reconcile(&mut self) -> Result<(), ActorError> {
        self.actor
            .as_mut()
            .unwrap()
            .reconcile(&mut *self.chain, &mut self.backend)
    }
    fn custody(&self) -> Custody {
        let db = rusqlite::Connection::open_with_flags(
            &self.voter_path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        db.query_row(
            "SELECT context,tip,snapshot,pending_context,pending_snapshot FROM voter_migration WHERE id=1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .unwrap()
    }
    fn mark(&self) -> Mark {
        (self.backend.counter, self.backend.calls, self.custody())
    }
    fn local(&mut self) -> Local {
        let actor = self.actor();
        (
            actor.is_halted(),
            actor.voter_poisoned(),
            actor.precommit_deadline(),
        )
    }
    /// Close the actor and open the voter custody again from disk, against the same canonical
    /// store. The clock is the rig's controlled clock, as the node installs its own after an open.
    fn reopen(&mut self) -> Result<(), ActorError> {
        self.actor = None;
        let mut actor = VoterActor::open(
            &self.voter_path,
            self.node,
            None,
            &mut *self.chain,
            &mut self.backend,
        )?;
        actor.set_vote_clock(self.clock.clone());
        self.actor = Some(actor);
        Ok(())
    }
    /// A healthy actor with a signed, guard-marked prevote for the proposal.
    fn with_stored_prevote(
        label: &str,
        a: &Fixtures<'a>,
        chain: &'a mut CanonicalStore,
    ) -> (Hx<'a>, Vote) {
        let mut rig = Hx::new(label, a, chain);
        rig.validate();
        let block = rig.block();
        let prevote = rig.sign(Step::Prevote, Some(block)).unwrap();
        assert!(!prevote.nil);
        (rig, prevote)
    }
}

/// Re-encode a version-3 snapshot as the version-2 record an old build wrote (no gated marker).
fn to_legacy(v3: &[u8]) -> Vec<u8> {
    let mut d = Decoder::new(v3);
    assert_eq!(d.array().unwrap(), Some(7));
    assert_eq!(d.u8().unwrap(), 3);
    let height = d.u64().unwrap();
    let last_sequence = d.u64().unwrap();
    let parent = d.bytes().unwrap().to_vec();
    assert_eq!(d.array().unwrap(), Some(3));
    let roots = [
        d.bytes().unwrap().to_vec(),
        d.bytes().unwrap().to_vec(),
        d.bytes().unwrap().to_vec(),
    ];
    let locks = d.bytes().unwrap().to_vec();
    let count = d.array().unwrap().unwrap();
    let mut e = Encoder::new(Vec::new());
    e.array(7)
        .unwrap()
        .u8(2)
        .unwrap()
        .u64(height)
        .unwrap()
        .u64(last_sequence)
        .unwrap()
        .bytes(&parent)
        .unwrap()
        .array(3)
        .unwrap();
    for r in &roots {
        e.bytes(r).unwrap();
    }
    e.bytes(&locks).unwrap().array(count).unwrap();
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

/// Build the legacy custody ONCE: reserve an eligible prevote, interrupt at the signing boundary
/// (the reservation is durably committed, the signature is never produced) and rewrite the record
/// exactly as a version-2 build left it.
fn legacy_template(a: &Fixtures<'_>, chain: &mut CanonicalStore) -> Legacy {
    let mut rig = Hx::new("template", a, chain);
    rig.validate();
    rig.backend.fail_sign = true;
    let block = rig.block();
    let e = rig.sign(Step::Prevote, Some(block)).unwrap_err();
    assert!(
        matches!(e, ActorError::Voter(CounterVoterError::Backend)),
        "{e:?}"
    );
    assert!(rig.actor().is_halted(), "an interrupted signature halts");
    rig.backend.fail_sign = false;
    rig.commit_as_version_2();
    Legacy {
        custody: std::fs::read(&rig.voter_path).unwrap(),
        counter: rig.backend.counter,
    }
}

/// Reads differ by call number: the first reading is `first`, every later one is `rest`.
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
/// The old, implicit shapes of a time deferral must never come out of the actor any more.
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

/// A healthy actor that only waits for time keeps retransmitting the stored vote, byte for byte,
/// defers fresh block votes explicitly and resumes cleanly.
fn waiting_actor_resumes(a: &Fixtures<'_>, chain: &mut CanonicalStore) {
    let (mut rig, prevote) = Hx::with_stored_prevote("waiting", a, chain);
    let block = rig.block();
    rig.observe(&prevote);
    let after_vote = (rig.mark(), rig.local());
    for (round, ahead) in [("unqualified", None), ("behind", Some(7u64))] {
        match ahead {
            None => rig.unqualified(),
            Some(n) => rig.behind(n),
        }
        for tick in 0..2 {
            let again = rig
                .replay(Step::Prevote)
                .unwrap_or_else(|e| panic!("{round}/{tick}: {e:?}"))
                .expect("stored prevote");
            assert_eq!(again, prevote, "{round}/{tick}: byte-exact retransmission");
            assert_eq!(
                again.encode().unwrap(),
                prevote.encode().unwrap(),
                "{round}/{tick}"
            );
            assert!(rig.replay(Step::Precommit).unwrap().is_none());
            let deferred = rig.sign(Step::Precommit, Some(block)).unwrap_err();
            let expected = match ahead {
                None => TimeStatus::Unqualified,
                Some(n) => TimeStatus::Future { ahead_seconds: n },
            };
            assert!(
                is_deferred(&deferred, expected),
                "{round}/{tick}: {deferred:?}"
            );
            assert!(!is_legacy_deferral_shape(&deferred));
            assert!(!rig.actor().is_halted(), "{round}/{tick}");
            assert_eq!(
                (rig.mark(), rig.local()),
                after_vote,
                "{round}/{tick}: nothing touched, in custody or in memory"
            );
        }
    }
    // Time returns: the SAME actor completes the round, no restart, no reset.
    rig.eligible();
    let precommit = rig.sign(Step::Precommit, Some(block)).unwrap();
    assert!(!precommit.nil);
    assert_eq!(precommit.decision.block, block);
    assert!(!rig.actor().is_halted());
    assert_eq!(rig.replay(Step::Prevote).unwrap().unwrap(), prevote);
}

/// Nil votes need no clock; finalized ingestion and sync need none either. This scenario commits a
/// block, so it owns its chain.
fn nil_and_finalized_ingestion_while_unqualified(a: &Fixtures<'_>) {
    let mut own = owned_chain("ingest", a);
    let mut rig = Hx::new("ingest", a, &mut own.chain);
    rig.validate();
    let block = rig.block();
    // Votes under an eligible clock; the certificate of the block is this node's own precommit.
    let prevote = rig.sign(Step::Prevote, Some(block)).unwrap();
    rig.observe(&prevote);
    let precommit = rig.sign(Step::Precommit, Some(block)).unwrap();
    rig.observe(&precommit);
    // The clock is lost. Ingestion of the certified block and the actor's reconciliation read no
    // clock at all.
    rig.unqualified();
    let certified = BlockEnvelope {
        certificate: Certificate {
            decision: precommit.decision.clone(),
            votes: vec![precommit.clone()],
        },
        ..rig.a.fixture.clone()
    };
    assert!(rig.chain.commit(&certified).unwrap());
    rig.reconcile().unwrap();
    assert_eq!(rig.actor().height(), 2);
    assert!(!rig.actor().is_halted());
    // The next height: nil is available without a clock.
    let nil = rig.sign(Step::Prevote, None).unwrap();
    assert!(nil.nil);
    assert_eq!(nil.decision.height, 2);
    assert!(!rig.actor().is_halted());
    let nil = rig.sign(Step::Precommit, None).unwrap();
    assert!(nil.nil);
    assert!(!rig.actor().is_halted());
}

/// The deferral is explicit, pure, and never touches custody or the latch.
fn deferral_is_explicit_and_pure(a: &Fixtures<'_>, chain: &mut CanonicalStore, legacy: &Legacy) {
    let block = a.fixture.block_hash();
    {
        let mut rig = Hx::from_legacy("pure", a, &mut *chain, legacy);
        let before = (rig.mark(), rig.local());
        for (ahead, expected) in [
            (None, TimeStatus::Unqualified),
            (Some(5u64), TimeStatus::Future { ahead_seconds: 5 }),
            (Some(1u64), TimeStatus::Future { ahead_seconds: 1 }),
        ] {
            match ahead {
                None => rig.unqualified(),
                Some(n) => rig.behind(n),
            }
            let e = rig.replay(Step::Prevote).unwrap_err();
            assert!(is_deferred(&e, expected), "replay: {e:?}");
            assert!(!is_legacy_deferral_shape(&e));
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
        assert_ne!(done.signature.ed448, [0; 114]);
        assert_eq!(rig.backend.calls, 1, "exactly the completion signs");
        assert!(!rig.actor().is_halted());
        // Afterwards recovery no longer depends on the clock.
        rig.unqualified();
        assert_eq!(rig.replay(Step::Prevote).unwrap().unwrap(), done);
    }
    // An unexecuted proposal is a recoverable absence: not a halt, not a time deferral.
    let mut rig = Hx::from_legacy("unknown", a, &mut *chain, legacy);
    rig.reopen().unwrap();
    rig.unqualified();
    let before = (rig.mark(), rig.local());
    for e in [
        rig.replay(Step::Prevote).unwrap_err(),
        rig.sign(Step::Prevote, Some(block)).unwrap_err(),
    ] {
        assert!(
            matches!(
                &e,
                ActorError::Voter(CounterVoterError::Ingress(IngressError::UnknownProposal))
            ),
            "{e:?}"
        );
        assert!(!e.is_time_deferral());
    }
    assert!(!rig.actor().is_halted());
    assert_eq!((rig.mark(), rig.local()), before);
    rig.validate();
    let e = rig.replay(Step::Prevote).unwrap_err();
    assert!(is_deferred(&e, TimeStatus::Unqualified), "{e:?}");
}

/// One clock reading serves each attempt: a flapping clock can neither halt nor bypass the guard.
fn one_reading_per_attempt(a: &Fixtures<'_>, chain: &mut CanonicalStore, legacy: &Legacy) {
    let ts = a.fixture.header.candidate.timestamp;
    let qualified = |t: u64| ClockReading::Qualified { utc_seconds: t };
    let block = a.fixture.block_hash();
    let flap = |first: ClockReading, rest: ClockReading| {
        let reads = Arc::new(AtomicU64::new(0));
        (
            reads.clone(),
            Arc::new(Flap { reads, first, rest }) as Arc<dyn VoteClock>,
        )
    };
    // sign: eligible first, lost afterwards -> succeeds with ONE reading (a second reading inside
    // the attempt would have deferred AFTER the latch).
    {
        let mut rig = Hx::new("flap1", a, &mut *chain);
        rig.validate();
        let (reads, clock) = flap(qualified(ts), ClockReading::Unqualified);
        rig.actor().set_vote_clock(clock);
        assert!(!rig.sign(Step::Prevote, Some(block)).unwrap().nil);
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        assert!(!rig.actor().is_halted());
    }
    // sign: lost first, eligible afterwards -> explicit deferral, ONE reading, nothing touched.
    {
        let mut rig = Hx::new("flap2", a, &mut *chain);
        rig.validate();
        let (reads, clock) = flap(ClockReading::Unqualified, qualified(ts));
        rig.actor().set_vote_clock(clock);
        let before = (rig.mark(), rig.local());
        let e = rig.sign(Step::Prevote, Some(block)).unwrap_err();
        assert!(is_deferred(&e, TimeStatus::Unqualified), "{e:?}");
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        assert!(!rig.actor().is_halted());
        assert_eq!((rig.mark(), rig.local()), before);
        assert!(!rig.sign(Step::Prevote, Some(block)).unwrap().nil);
    }
    // replay of an unmarked reservation: same two shapes.
    {
        let mut rig = Hx::from_legacy("flap3", a, &mut *chain, legacy);
        let (reads, clock) = flap(qualified(ts), ClockReading::Unqualified);
        rig.actor().set_vote_clock(clock);
        assert_eq!(
            rig.replay(Step::Prevote).unwrap().unwrap().decision.block,
            block
        );
        assert_eq!(reads.load(Ordering::SeqCst), 1);
        assert!(!rig.actor().is_halted());
    }
    {
        let mut rig = Hx::from_legacy("flap4", a, &mut *chain, legacy);
        let (reads, clock) = flap(ClockReading::Unqualified, qualified(ts));
        rig.actor().set_vote_clock(clock);
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
}

/// A deferral leaves in-memory actor state alone too, the armed precommit timeout included (a gap
/// the review's mutation run M8 exposed). A nil precommit needs no clock and arms the round's
/// timeout; deferrals of every shape leave the latch, the poison, the deadline and custody as they
/// were, and the armed timeout still fires.
fn deferral_leaves_the_armed_precommit_timeout_intact(
    a: &Fixtures<'_>,
    chain: &mut CanonicalStore,
    legacy: &Legacy,
) {
    let block = a.fixture.block_hash();
    let mut rig = Hx::from_legacy("deadline", a, &mut *chain, legacy);
    let precommit = rig.sign(Step::Precommit, None).unwrap();
    assert!(precommit.nil);
    rig.observe(&precommit);
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
        deadline.saturating_duration_since(std::time::Instant::now())
            + std::time::Duration::from_millis(100),
    );
    rig.unqualified();
    let next = rig
        .actor
        .as_mut()
        .unwrap()
        .timeout_precommit(&*rig.chain, &mut rig.backend)
        .unwrap();
    assert_eq!(next, Some(1), "round 0 times out");
    assert!(!rig.actor().is_halted());
    // Candidate 3, Architect decision V4: a vote decided for round 0 (the legacy reservation's
    // round) is refused now that round 0 has expired, explicitly and without any effect; the
    // current context signs (a nil prevote: no lock is held).
    let decided = mutiny_consensus_v8::voter_actor::VoteContext {
        height: 1,
        round: 0,
    };
    let current = rig.actor().context().unwrap();
    assert_eq!(
        current,
        mutiny_consensus_v8::voter_actor::VoteContext {
            height: 1,
            round: 1
        }
    );
    rig.eligible();
    let before = (rig.mark(), rig.local());
    let e = rig
        .actor
        .as_mut()
        .unwrap()
        .sign_for(
            &*rig.chain,
            decided,
            Step::Prevote,
            Some(block),
            None,
            &mut rig.backend,
        )
        .unwrap_err();
    assert!(
        matches!(e, ActorError::StaleContext { requested, current: now }
            if requested == decided && now == current),
        "{e:?}"
    );
    assert_eq!((rig.mark(), rig.local()), before, "a stale request touches nothing");
    let nil = rig
        .actor
        .as_mut()
        .unwrap()
        .sign_for(&*rig.chain, current, Step::Prevote, None, None, &mut rig.backend)
        .unwrap();
    assert!(nil.nil && nil.decision.round == 1);
}

// ---------------------------------------------------------------------------------------------
// Genuine halts are never cleared by a time deferral: replay/sign, both orders, reopen.
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Cause {
    CounterInconsistency,
    BackendKeyMismatch,
    /// The canonical store carries a durable integrity halt. Owns its chain.
    ChainIntegrityHalt,
    /// The durable record is an UNMARKED legacy reservation for the block, the request names nil:
    /// a request conflict, found by the pure pre-check before the latch and before the clock.
    RequestConflictsWithAnUnmarkedRecord,
    /// A canonical certificate carries this node's own vote that custody never issued: the voter
    /// writes a DURABLE halt bit, so even the reopened actor is refused. Owns its chain.
    UnissuedOwnVote,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Order {
    DeferralThenHalt,
    HaltThenDeferral,
}

fn all_calls_report_halted(rig: &mut Hx<'_>, why: &str) {
    let block = rig.block();
    let before = rig.mark();
    assert!(rig.actor().is_halted(), "{why}");
    assert!(
        matches!(rig.actor().progress(), Err(ActorError::Halted)),
        "{why}"
    );
    assert!(matches!(rig.check(), Err(ActorError::Halted)), "{why}");
    assert!(matches!(rig.reconcile(), Err(ActorError::Halted)), "{why}");
    let fixture = rig.a.fixture;
    assert!(
        matches!(
            rig.actor
                .as_mut()
                .unwrap()
                .validate_proposal(&*rig.chain, fixture),
            Err(ActorError::Halted)
        ),
        "{why}"
    );
    let sample = fixture.certificate.votes[0].clone();
    assert!(
        matches!(
            rig.actor
                .as_mut()
                .unwrap()
                .observe(&*rig.chain, &sample, &mut rig.backend),
            Err(ActorError::Halted)
        ),
        "{why}"
    );
    assert!(
        matches!(
            rig.actor
                .as_mut()
                .unwrap()
                .timeout_precommit(&*rig.chain, &mut rig.backend),
            Err(ActorError::Halted)
        ),
        "{why}"
    );
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

fn deferrals_are_nonfatal(rig: &mut Hx<'_>, why: &str) {
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
    assert!(!rig.actor().is_halted(), "{why}");
    assert_eq!((rig.mark(), rig.local()), before, "{why}");
    rig.unqualified();
}

fn inject(rig: &mut Hx<'_>, cause: Cause, chain_path: Option<&std::path::Path>) {
    match cause {
        Cause::CounterInconsistency => rig.backend.counter += 2,
        Cause::BackendKeyMismatch => rig.backend.key = rig.a.wrong,
        Cause::ChainIntegrityHalt => {
            let db = rusqlite::Connection::open(chain_path.expect("own chain")).unwrap();
            db.execute("UPDATE integrity_v2 SET halted=1 WHERE id=1", [])
                .unwrap();
        }
        Cause::RequestConflictsWithAnUnmarkedRecord => {}
        Cause::UnissuedOwnVote => {
            // The certified block carries this node's own sequence-10 precommit, never issued by
            // this custody: it is committed to the canonical store as finalized history.
            let fixture = rig.a.fixture;
            assert!(rig.chain.commit(fixture).unwrap());
        }
    }
}
fn repair(rig: &mut Hx<'_>, cause: Cause) {
    match cause {
        Cause::CounterInconsistency => rig.backend.counter -= 2,
        Cause::BackendKeyMismatch => rig.backend.key = rig.a.key,
        _ => {}
    }
}
fn notice(rig: &mut Hx<'_>, cause: Cause) {
    let calls = rig.backend.calls;
    let err = match cause {
        Cause::RequestConflictsWithAnUnmarkedRecord => rig.sign(Step::Prevote, None).unwrap_err(),
        Cause::UnissuedOwnVote => rig.reconcile().unwrap_err(),
        _ => rig.check().unwrap_err(),
    };
    match cause {
        Cause::CounterInconsistency => assert!(
            matches!(
                &err,
                ActorError::Voter(CounterVoterError::Counter(CounterError::Rollback))
            ),
            "{err:?}"
        ),
        Cause::BackendKeyMismatch => assert!(
            matches!(
                &err,
                ActorError::Voter(CounterVoterError::Invalid(
                    mutiny_consensus_v8::Error::WrongGeneration
                ))
            ),
            "{err:?}"
        ),
        Cause::ChainIntegrityHalt => assert!(!err.is_time_deferral(), "{err:?}"),
        Cause::RequestConflictsWithAnUnmarkedRecord | Cause::UnissuedOwnVote => {
            assert!(
                matches!(&err, ActorError::Voter(CounterVoterError::ConflictingVote)),
                "{err:?}"
            );
            assert!(
                rig.actor().voter_poisoned(),
                "{cause:?} also poisons the voter"
            );
        }
    }
    assert!(rig.actor().is_halted(), "{cause:?} halts the actor");
    assert_eq!(rig.backend.calls, calls, "{cause:?}: nothing was signed");
}

/// Close and reopen with the cause still present. `full` also repairs the BACKEND (the only way
/// back) and completes the stored decision on the reopened actor.
fn reopen_keeps_the_halt(rig: &mut Hx<'_>, cause: Cause, record: &Custody, full: bool) {
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
                    ActorError::Voter(CounterVoterError::Invalid(
                        mutiny_consensus_v8::Error::WrongGeneration
                    ))
                ),
                "{e:?}"
            );
        }
        Cause::ChainIntegrityHalt => {
            assert!(rig.reopen().is_err(), "the chain halt is durable");
            assert!(rig.chain.halted().unwrap());
        }
        Cause::UnissuedOwnVote => {
            // The halt bit is DURABLE: repairing nothing and reopening is still refused.
            for clock in ["unqualified", "eligible"] {
                match clock {
                    "unqualified" => rig.unqualified(),
                    _ => rig.eligible(),
                }
                assert!(
                    rig.reopen().is_err(),
                    "{clock}: a durable halt is never reopened"
                );
                assert!(rig.actor.is_none());
            }
            return;
        }
        Cause::RequestConflictsWithAnUnmarkedRecord => {
            // In memory only: the reopen yields a healthy actor; only the original decision exists.
            rig.reopen().expect("an intact record reopens");
            rig.validate();
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
            let calls = rig.backend.calls;
            let e = rig.sign(Step::Prevote, None).unwrap_err();
            assert!(
                matches!(&e, ActorError::Voter(CounterVoterError::ConflictingVote)),
                "{e:?}"
            );
            assert!(rig.actor().is_halted());
            assert_eq!(rig.backend.calls, calls);
            return;
        }
    }
    assert_eq!(
        &rig.custody(),
        record,
        "{cause:?}: the stored decision is untouched"
    );
    if full && cause != Cause::ChainIntegrityHalt {
        repair(rig, cause);
        rig.reopen().expect("repaired backend reopens");
        rig.validate();
        rig.eligible();
        let done = rig.replay(Step::Prevote).unwrap().expect("stored decision");
        assert_eq!(done.decision.block, block);
        assert!(!rig.actor().is_halted());
    }
}

fn run_on(
    cause: Cause,
    order: Order,
    a: &Fixtures<'_>,
    chain: &mut CanonicalStore,
    chain_path: Option<&std::path::Path>,
    legacy: &Legacy,
    label: &str,
) {
    let mut rig = Hx::from_legacy(label, a, chain, legacy);
    let record = rig.custody();
    if order == Order::DeferralThenHalt {
        deferrals_are_nonfatal(&mut rig, label);
    }
    inject(&mut rig, cause, chain_path);
    notice(&mut rig, cause);
    // Halt then deferral: the deferral shapes are presented to the HALTED actor. Deferral then
    // halt: the same, after the actor already served them while healthy. Either way every call
    // reports `Halted`, nothing is retransmitted, nothing is signed, and the latch holds.
    all_calls_report_halted(&mut rig, label);
    reopen_keeps_the_halt(&mut rig, cause, &record, order == Order::HaltThenDeferral);
}

fn run_case(
    cause: Cause,
    order: Order,
    a: &Fixtures<'_>,
    shared: &mut CanonicalStore,
    legacy: &Legacy,
) {
    let label = format!("{cause:?}-{order:?}");
    match cause {
        Cause::ChainIntegrityHalt | Cause::UnissuedOwnVote => {
            let mut own = owned_chain(&label, a);
            let path = own.path.clone();
            run_on(cause, order, a, &mut own.chain, Some(&path), legacy, &label);
            if cause == Cause::ChainIntegrityHalt {
                // Closed and reopened from disk: the integrity halt is durable.
                let again = open_chain(&path, a.genesis, a.state, a.root);
                assert!(again.halted().unwrap());
            }
        }
        _ => run_on(cause, order, a, shared, None, legacy, &label),
    }
}

/// A cause that appears while a deferral is pending is reported by the very call that would have
/// returned the deferral: the backend check runs first, it halts the actor, and the pending
/// deferral is never delivered, whatever the clock does next. (The v2 mutation run showed that the
/// cause scenarios above notice a counter mismatch only through `check_backend`, so a `replay` that
/// turned it into a deferral went unseen; this scenario closes that gap.)
fn a_cause_noticed_by_the_deferring_call_is_reported_not_deferred(
    a: &Fixtures<'_>,
    chain: &mut CanonicalStore,
    legacy: &Legacy,
) {
    let block = a.fixture.block_hash();
    for (cause, replay) in [
        (Cause::CounterInconsistency, true),
        (Cause::CounterInconsistency, false),
        (Cause::BackendKeyMismatch, true),
        (Cause::BackendKeyMismatch, false),
    ] {
        let label = format!("noticed-{cause:?}-{replay}");
        let mut rig = Hx::from_legacy(&label, a, &mut *chain, legacy);
        rig.unqualified();
        // The deferral is pending (and would be returned right now):
        let e = rig.replay(Step::Prevote).unwrap_err();
        assert!(is_deferred(&e, TimeStatus::Unqualified), "{label}: {e:?}");
        inject(&mut rig, cause, None);
        let calls = rig.backend.calls;
        let e = if replay {
            rig.replay(Step::Prevote).unwrap_err()
        } else {
            rig.sign(Step::Prevote, Some(block)).unwrap_err()
        };
        assert!(!e.is_time_deferral(), "{label}: {e:?}");
        assert!(rig.actor().is_halted(), "{label}");
        assert_eq!(rig.backend.calls, calls, "{label}: nothing was signed");
        // And the pending deferral can no longer be delivered, whatever the clock does.
        rig.eligible();
        let e = rig.replay(Step::Prevote).unwrap_err();
        assert!(matches!(e, ActorError::Halted), "{label}: {e:?}");
        assert!(rig.actor().is_halted());
    }
}

/// A conflict with a SIGNED, guard-marked decision is found by the pure pre-check, before the
/// latch, and must still halt - whatever the clock says. The request conflict is held in memory
/// only: a reopen resumes the original decision and refuses the conflicting request again.
fn request_conflict_guarded_decision_halts_any_clock_in_memory_only_reopen_resumes_original(
    a: &Fixtures<'_>,
    chain: &mut CanonicalStore,
) {
    for clock in ["eligible", "unqualified"] {
        let (mut rig, stored) =
            Hx::with_stored_prevote(&format!("guarded-{clock}"), a, &mut *chain);
        match clock {
            "eligible" => rig.eligible(),
            _ => rig.unqualified(),
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
        all_calls_report_halted(&mut rig, &format!("guarded-{clock}"));
        rig.actor = None;
        rig.eligible();
        rig.reopen().expect("intact record reopens");
        rig.validate();
        assert!(!rig.actor().voter_poisoned(), "{clock}: in memory only");
        assert_eq!(
            rig.replay(Step::Prevote).unwrap().unwrap(),
            stored,
            "{clock}"
        );
        // Architect decision V1: the conflict, the reopen and the retransmission of the original
        // decision used no counter value and wrote nothing (the `before` mark includes the counter).
        assert_eq!(rig.mark(), before, "{clock}: no counter value burned or reused");
        assert!(!rig.actor().is_halted());
        let e = rig.sign(Step::Prevote, None).unwrap_err();
        assert!(matches!(
            &e,
            ActorError::Voter(CounterVoterError::ConflictingVote)
        ));
        assert!(rig.actor().is_halted());
    }
}

/// Review finding MINOR-1, hybrid actor. The slot holds an UNMARKED legacy (version-2)
/// reservation: an interrupted NIL precommit. A request to precommit the BLOCK contradicts it. The
/// comparison runs before the time gate, so the request is a conflicting durable decision under
/// every clock, never a deferral: the actor halts and nothing is signed or written. The request
/// conflict is held in memory only: the reopened actor completes the ORIGINAL nil precommit
/// without a clock and refuses the conflicting request again.
fn request_conflict_with_an_unmarked_reservation_halts_before_the_time_gate(
    a: &Fixtures<'_>,
    chain: &mut CanonicalStore,
) {
    let block = a.fixture.block_hash();
    for clock in ["unqualified", "eligible"] {
        let label = format!("legacy-conflict-{clock}");
        let (mut rig, prevote) = Hx::with_stored_prevote(&label, a, &mut *chain);
        rig.observe(&prevote);
        rig.backend.fail_sign = true;
        let e = rig.sign(Step::Precommit, None).unwrap_err();
        assert!(
            matches!(e, ActorError::Voter(CounterVoterError::Backend)),
            "{e:?}"
        );
        rig.backend.fail_sign = false;
        rig.commit_as_version_2();
        rig.reopen().unwrap();
        rig.validate();
        let (_, stored_prevote, stored_precommit) = rig.actor().progress().unwrap();
        let stored_precommit = stored_precommit.expect("the interrupted nil precommit");
        assert!(stored_precommit.nil);
        assert_eq!(stored_precommit.signature.ed448, [0; 114], "unsigned");
        assert_eq!(stored_prevote.as_ref(), Some(&prevote));
        rig.observe(&prevote);
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
        assert!(!rig.actor().voter_poisoned(), "{clock}: in memory only");
        rig.observe(&prevote);
        let calls = rig.backend.calls;
        let done = rig
            .replay(Step::Precommit)
            .unwrap()
            .expect("the original decision completes");
        assert!(
            done.nil,
            "{clock}: the nil precommit, not the conflicting request"
        );
        assert_eq!(rig.backend.calls, calls + 1, "{clock}: one completion");
        assert!(!rig.actor().is_halted());
        // and the conflicting request is refused again, whatever the clock.
        rig.clock_to(clock);
        let e = rig.sign(Step::Precommit, Some(block)).unwrap_err();
        assert!(
            matches!(&e, ActorError::Voter(CounterVoterError::ConflictingVote)),
            "{clock}: {e:?}"
        );
        assert!(rig.actor().is_halted());
    }
}

pub fn qualify(
    state: &State,
    genesis: &FinalizedAnchor,
    root: Hash,
    fixture: &BlockEnvelope,
    key: &HybridKey,
) {
    let started = std::time::Instant::now();
    let wrong = HybridKey::generate(Role::Continuity).unwrap();
    let a = Fixtures {
        state,
        genesis,
        root,
        fixture,
        key,
        wrong: &wrong,
    };
    // One canonical store, left at height zero, serves every scenario that does not change it.
    let mut shared = owned_chain("shared", &a);
    let legacy = legacy_template(&a, &mut shared.chain);
    waiting_actor_resumes(&a, &mut shared.chain);
    nil_and_finalized_ingestion_while_unqualified(&a);
    deferral_is_explicit_and_pure(&a, &mut shared.chain, &legacy);
    one_reading_per_attempt(&a, &mut shared.chain, &legacy);
    deferral_leaves_the_armed_precommit_timeout_intact(&a, &mut shared.chain, &legacy);
    a_cause_noticed_by_the_deferring_call_is_reported_not_deferred(&a, &mut shared.chain, &legacy);
    request_conflict_guarded_decision_halts_any_clock_in_memory_only_reopen_resumes_original(
        &a,
        &mut shared.chain,
    );
    request_conflict_with_an_unmarked_reservation_halts_before_the_time_gate(&a, &mut shared.chain);
    for cause in [
        Cause::CounterInconsistency,
        Cause::BackendKeyMismatch,
        Cause::ChainIntegrityHalt,
        Cause::RequestConflictsWithAnUnmarkedRecord,
        Cause::UnissuedOwnVote,
    ] {
        for order in [Order::DeferralThenHalt, Order::HaltThenDeferral] {
            run_case(cause, order, &a, &mut shared.chain, &legacy);
        }
    }
    assert_eq!(
        shared.chain.load().unwrap().0.height,
        0,
        "the shared store was never changed"
    );
    eprintln!("halt_latch_v2::qualify finished in {:?}", started.elapsed());
}
