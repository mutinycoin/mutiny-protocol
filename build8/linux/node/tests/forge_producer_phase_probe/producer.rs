//! NONSHIPPING TEST owner. No endpoint, installed issuer, TPM or background signer.
use mutinyd_v8::{genesis_artifact_v2::VerifiedGenesisV2, hybrid_runtime_v2::{HybridRuntime, WorkRequest}};
use mutiny_consensus_v8::{Hash, bft::Step, block_envelope_v2::BlockEnvelope,
    canonical_store_v2::CanonicalStore, continuity_v2::Certificate, genesis_v2::Enrollment,
    mempool_v2::{Mempool, MAX_PENDING_BYTES}, pow::{WorkAuthority, WorkHeader},
    voter_actor_v2::{VoterActor, Proposal}, work_authority_v2::Authority};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature};
use std::{path::{Path, PathBuf}, sync::{Arc, atomic::{AtomicU64, Ordering}}, time::{Duration, Instant}};

pub const MAX_BLOCKS: u64 = 101;
pub const MAX_SECONDS: u64 = 3600;

pub fn open_runtime(path: &Path, verified: &VerifiedGenesisV2, clock: Arc<AtomicU64>) -> HybridRuntime {
    let g = &verified.genesis;
    let chain = CanonicalStore::open_trusted_genesis(&path.join("chain.sqlite"), &g.anchor(),
        &g.state, g.root, verified.inputs.timestamp, verified.inputs.parameters.initial_target).unwrap();
    let pool = Mempool::open(&path.join("pool.sqlite"), g.identity, g.fingerprint, MAX_PENDING_BYTES).unwrap();
    HybridRuntime::from_pinned_chain_with_time_source(chain, pool,
        Arc::new(move || clock.load(Ordering::SeqCst))).unwrap()
}

pub struct Backend<'a> {
    continuity: &'a HybridKey,
    node: &'a HybridKey,
    path: PathBuf,
    pub counter: u64,
    pub vote_signatures: u64,
    pub work_signatures: u64,
}
impl mutiny_consensus_v8::counter_store::MonotonicCounter for Backend<'_> {
    fn read(&mut self) -> Result<u64, String> { Ok(self.counter) }
    fn increment(&mut self) -> Result<(), String> {
        self.counter = self.counter.checked_add(1).ok_or("TEST counter exhausted")?;
        Ok(())
    }
}
impl mutiny_consensus_v8::counter_voter_v2::CounterSigningBackend for Backend<'_> {
    fn public_key(&self) -> &mutiny_crypto_v2::PublicKey { self.continuity.public() }
    fn sign_vote(&mut self, message: &[u8]) -> Result<HybridSignature, String> {
        if message.is_empty() { return Err("empty TEST vote reservation".into()); }
        let db = rusqlite::Connection::open(&self.path).map_err(|e| e.to_string())?;
        let (tip, snapshot, pending): (Vec<u8>, Vec<u8>, Option<Vec<u8>>) = db.query_row(
            "SELECT tip,snapshot,pending_snapshot FROM voter_migration", [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?))).map_err(|e| e.to_string())?;
        if tip != self.counter.to_be_bytes() || pending.is_some()
            || !snapshot.windows(message.len()).any(|w| w == message) {
            return Err("exact durable TEST vote reservation missing".into());
        }
        self.vote_signatures += 1;
        self.continuity.sign(Domain::ContinuityVote, message).map_err(|e| format!("{e:?}"))
    }
}

/// One synchronous owner polls the SAME runtime's admitted pending bytes. Initial
/// empty production has a fixed earned-funding target; afterwards no pending item
/// means no block. The caller never supplies a height, block body or payment ID.
/// Two same-path SQLite handles are serialized here: runtime owns admission,
/// assembly and installation; the actor's handle supplies authenticated votes.
pub struct Producer<'a> {
    pub runtime: HybridRuntime,
    pub chain: CanonicalStore,
    pub actor: VoterActor,
    pub backend: Backend<'a>,
    assignment: mutiny_crypto_v2::enrollment::Binding,
    clock: Arc<AtomicU64>,
    t0: u64,
    deadline: Instant,
    warmup_height: u64,
    pub generated: u64,
    pub nonce_trials: u64,
    pub last_block: Option<BlockEnvelope>,
}
impl<'a> Producer<'a> {
    pub fn open(path: &Path, verified: &VerifiedGenesisV2, enrollment: &Enrollment,
        node: &'a HybridKey, continuity: &'a HybridKey) -> Self {
        assert_eq!(mutiny_consensus_v8::transactions::MATURITY, 100);
        let clock = Arc::new(AtomicU64::new(verified.inputs.timestamp + 1));
        let runtime = open_runtime(path, verified, clock.clone());
        let g = &verified.genesis;
        let mut chain = CanonicalStore::open_trusted_genesis(&path.join("chain.sqlite"),
            &g.anchor(), &g.state, g.root, verified.inputs.timestamp,
            verified.inputs.parameters.initial_target).unwrap();
        let voter_path = path.join("voter.sqlite");
        let mut backend = Backend { continuity, node, path: voter_path.clone(), counter: 100,
            vote_signatures: 0, work_signatures: 0 };
        let actor = VoterActor::open(&voter_path, enrollment.member_binding.admission.node,
            Some(100), &mut chain, &mut backend).unwrap();
        Self { runtime, chain, actor, backend, assignment: enrollment.supervised[0].clone(), clock,
            t0: verified.inputs.timestamp, deadline: Instant::now() + Duration::from_secs(MAX_SECONDS),
            warmup_height: mutiny_consensus_v8::transactions::MATURITY, generated: 0,
            nonce_trials: 0, last_block: None }
    }
    pub fn tick(&mut self) -> bool {
        assert!(Instant::now() < self.deadline, "finite TEST producer deadline expired");
        let mut phase_report = TickPhases::new();
        let parent = self.runtime.head().unwrap();
        phase_report.mark("head");
        let pending = self.runtime.relay_pending().unwrap();
        phase_report.mark("relay_pending");
        if parent.height >= self.warmup_height && pending.is_empty() { return false; }
        assert!(self.generated < MAX_BLOCKS, "finite TEST block budget exhausted");
        let height = parent.height.checked_add(1).unwrap();
        let timestamp = self.t0.checked_add(height).unwrap();
        self.clock.store(timestamp, Ordering::SeqCst);
        let (ctx, descriptor) = self.runtime.current_work_context(&parent,
            self.assignment.license, self.assignment.worker_id, timestamp).unwrap();
        phase_report.mark("work_context");
        let ticket = ctx.last_accepted_ticket.checked_add(1).unwrap();
        let prepared = self.runtime.prepare(WorkRequest { expected_parent: &parent,
            license: self.assignment.license, worker: self.assignment.worker_id,
            timestamp, ticket, operations: &[] }).unwrap();
        phase_report.mark("prepare");
        let mut authority = Authority { work: WorkAuthority { candidate: prepared.candidate.clone(),
            assignment_sequence: ctx.assignment_sequence, ticket_sequence: ticket,
            coordinator: ctx.coordinator, nonce_start: 0, nonce_end: 1023,
            epoch: mutiny_consensus_v8::pow::mining_epoch(timestamp, ctx.t0).unwrap() },
            node_descriptor: descriptor,
            signature: HybridSignature { ed448: [0; 114], fndsa: [0; 1280] } };
        // Existing explicit TEST Authority API, not an installed NodeWork issuer.
        authority.sign(self.backend.node).unwrap();
        self.backend.work_signatures += 1;
        phase_report.mark("work_sign");
        let mut header = WorkHeader { candidate: prepared.candidate, authority: authority.id().unwrap(), nonce: 0 };
        loop {
            self.nonce_trials += 1;
            if mutiny_consensus_v8::pow::meets_target(&header.digest(), &header.candidate.target) { break; }
            header.nonce = header.next_nonce(authority.work.nonce_end).expect("bounded actual TEST PoW exhausted");
        }
        let block = header.block_hash();
        phase_report.mark("pow");
        self.actor.validate_candidate(&self.chain, Proposal { header: &header, body: &prepared.body,
            authority: &authority }).unwrap();
        phase_report.mark("actor_validate");
        let clock = mutiny_consensus_v8::vote_clock_v1::ControlledClock::at(timestamp);
        let prevote = self.actor.sign_with_clock(&self.chain, Step::Prevote, Some(block), None,
            &mut self.backend, clock.clone()).unwrap();
        assert!(!prevote.nil);
        phase_report.mark("prevote_sign");
        self.actor.observe(&self.chain, &prevote, &mut self.backend).unwrap();
        phase_report.mark("prevote_observe");
        let precommit = self.actor.sign_with_clock(&self.chain, Step::Precommit, Some(block), None,
            &mut self.backend, clock).unwrap();
        assert!(!precommit.nil);
        phase_report.mark("precommit_sign");
        self.actor.observe(&self.chain, &precommit, &mut self.backend).unwrap();
        phase_report.mark("precommit_observe");
        let current = self.chain.current_authority(&parent).unwrap();
        assert_eq!(current.voters.len(), 1, "explicit single eligible TEST bootstrap voter");
        phase_report.mark("current_authority");
        let certificate = Certificate { decision: precommit.decision.clone(), votes: vec![precommit] };
        certificate.verify_quorum(&certificate.decision, &current.parent, &current.voters).unwrap();
        phase_report.mark("certificate_quorum");
        let envelope = BlockEnvelope { header, body: prepared.body, authority, certificate };
        assert!(self.runtime.install(&envelope.encode().unwrap()).unwrap().inserted);
        phase_report.mark("install");
        self.actor.reconcile(&mut self.chain, &mut self.backend).unwrap();
        phase_report.mark("actor_reconcile");
        assert_eq!(self.runtime.head().unwrap().height, height);
        phase_report.mark("final_head");
        self.generated += 1;
        self.last_block = Some(envelope);
        phase_report.mark("bookkeeping");
        phase_report.completed = true;
        true
    }
    pub fn wait_for_confirmation(&mut self, id: Hash) -> u64 {
        loop {
            if let Some(height) = self.runtime.confirmed_height(id).unwrap() { return height; }
            assert!(self.tick(), "payment was not pending in the actual owned runtime");
        }
    }
    pub fn close_verify_voter(self) {
        let Self { mut chain, actor, mut backend, runtime, .. } = self;
        let node = actor.node(); let height = actor.height(); let counter = backend.counter;
        drop(actor);
        let reopened = VoterActor::open(&backend.path.clone(), node, None, &mut chain, &mut backend).unwrap();
        assert_eq!(reopened.height(), height);
        assert_eq!(backend.counter, counter, "restart must not allocate another counter");
        drop(reopened); drop(runtime); drop(chain);
    }
}

// Diagnostic-only local monotonic markers; no IO occurs between original calls.
struct TickPhases {
    started: Instant, last: Instant, names: [&'static str;17], nanos: [u128;17],
    used: usize, completed: bool,
}
impl TickPhases {
    fn new()->Self {let now=Instant::now();Self {started:now,last:now,names:["";17],nanos:[0;17],used:0,completed:false}}
    fn mark(&mut self,name:&'static str) {
        let now=Instant::now();
        if self.used<17 {self.names[self.used]=name;self.nanos[self.used]=now.duration_since(self.last).as_nanos();self.used+=1;}
        self.last=now;
    }
}
impl Drop for TickPhases {
    fn drop(&mut self) {
        eprintln!("{}",serde_json::json!({"kind":"FORGE-PRODUCER-TICK-PHASES-R1",
            "completed":self.completed,"phases":&self.names[..self.used],
            "elapsed_ns":self.started.elapsed().as_nanos().to_string(),
            "phase_ns":self.nanos[..self.used].iter().map(|v|v.to_string()).collect::<Vec<_>>()}));
    }
}
