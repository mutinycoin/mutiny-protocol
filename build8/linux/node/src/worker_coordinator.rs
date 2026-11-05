//! Canonical-state adapter between Wi-Fi sessions and durable mining services.
//! The enclosing node actor supplies body assembly and durable BFT ingress.
use crate::{
    worker_protocol::{self, WorkerMessage},
    worker_server::WorkerBackend,
};
use mutiny_consensus_v8::holdover_clock_v1::TimeBasis;
use mutiny_consensus_v8::{
    Hash,
    blocks::BlockBody,
    canonical_store::CanonicalStore,
    certificates::{Certificate, Decision},
    coordinator::{Coordinator, MiningRequest, ObservedWork},
    freshness::{PhysicalAttestationVerifier, PhysicalMember},
    licenses::BindWorker,
    liveness::{WorkGate, WorkState},
    observations::Submission,
    pow::mining_epoch,
    voter_actor,
};
use std::{collections::BTreeMap, sync::Arc, time::Instant};
type Result<T> = std::result::Result<T, String>;
#[cfg(test)]
#[path = "os_clock_tests.rs"]
mod os_clock_tests;
#[cfg(test)]
#[path = "worker_coordinator_tests.rs"]
mod tests;
fn err(e: impl std::fmt::Debug) -> String {
    format!("Worker coordinator: {e:?}")
}
/// At most this many fresh Worker results are held while the clock is unqualified (Architect
/// decision V2), one per Worker: more than the twelve Genesis Licenses can have active Workers, so
/// every active Worker fits, and nothing beyond it is ever held.
pub(crate) const MAX_DEFERRED_RESULTS: usize = 16;
/// The MiningEpoch at which a Worker's binding is judged.
#[derive(Clone, Copy)]
enum BindingEpoch {
    /// The epoch of qualified time (a timestamp in whole seconds): binds the Worker for the
    /// CURRENT epoch, activating assignments due by then. Unavailable while unqualified.
    Qualified(u64),
    /// The finalized tip block's own epoch, a canonical value: no clock is read and no assignment
    /// is activated beyond what finalized state holds (Architect decision V2).
    Settled,
}

pub trait CandidateHooks: Send + 'static {
    fn body(
        &mut self,
        chain: &mut CanonicalStore,
        binding: &BindWorker,
        timestamp: u64,
    ) -> Result<BlockBody>;
    /// Must durably preserve a still-current candidate for normal BFT ingress,
    /// or establish from canonical state that it is already finalized/retired.
    /// On failure no receipt is sent: the device retries its durable outbox.
    fn preserve<V: PhysicalAttestationVerifier>(
        &mut self,
        chain: &mut CanonicalStore,
        result: &ObservedWork,
        physical: &BTreeMap<Hash, PhysicalMember>,
        verifier: &V,
    ) -> Result<()>;
}
pub trait BodyBuilder: Send + 'static {
    fn admit_current_operation(
        &mut self,
        _chain: &mut CanonicalStore,
        _timestamp: u64,
        _raw: &[u8],
    ) -> Result<Hash> {
        Err("Operation admission unavailable".into())
    }
    fn pending_operations(&mut self, _chain: &mut CanonicalStore) -> Result<Vec<Vec<u8>>> {
        Err("Operation queue unavailable".into())
    }
    fn body(
        &mut self,
        chain: &mut CanonicalStore,
        binding: &BindWorker,
        timestamp: u64,
    ) -> Result<BlockBody>;
}
/// Production receipt ordering with bounded, executed, durable proposal custody.
pub struct JournaledCandidates<B> {
    pub journal: crate::candidate_journal::CandidateJournal,
    pub builder: B,
}
impl<B: BodyBuilder> CandidateHooks for JournaledCandidates<B> {
    fn body(
        &mut self,
        chain: &mut CanonicalStore,
        binding: &BindWorker,
        timestamp: u64,
    ) -> Result<BlockBody> {
        self.builder.body(chain, binding, timestamp)
    }
    fn preserve<V: PhysicalAttestationVerifier>(
        &mut self,
        chain: &mut CanonicalStore,
        result: &ObservedWork,
        physical: &BTreeMap<Hash, PhysicalMember>,
        verifier: &V,
    ) -> Result<()> {
        self.journal.preserve(chain, result, physical, verifier)
    }
}
pub struct WorkerCoordinator<V, H> {
    pub chain: CanonicalStore,
    coordinator: Coordinator,
    coordinator_public: Hash,
    pub(crate) physical: BTreeMap<Hash, PhysicalMember>,
    pub(crate) verifier: V,
    pub(crate) hooks: H,
    gate: Option<WorkGate>,
    context: Option<(Hash, Hash)>,
    started: Instant,
    /// Conservative qualified UTC basis (floor of the lower bound). MANDATORY: it is the ONLY
    /// source of candidate/work timestamps and of the worker epoch binding; while it is unqualified
    /// no work is issued and no worker is bound to the current epoch. There is no OS-clock
    /// fallback.
    time: Arc<dyn TimeBasis>,
    /// Fresh Worker results received while the clock was unqualified (Architect decision V2).
    /// Holding one grants no acceptance, credit, receipt or signature: `process_deferred_results`
    /// processes it exactly like a new result once qualified time returns, with the Worker's
    /// binding judged again at that epoch, and drops it if that fails (the device still holds it
    /// in its durable outbox and retries). In memory only. Bounded: one per Worker (a later result
    /// replaces an earlier one) and `MAX_DEFERRED_RESULTS` Workers.
    deferred: BTreeMap<Hash, Submission>,
    /// The bound on `deferred`: always `MAX_DEFERRED_RESULTS` outside tests.
    deferred_capacity: usize,
    /// The highest MiningEpoch of qualified time this process has bound a Worker at (memory only,
    /// never decreasing). While unqualified, a session is judged at the later of this epoch and the
    /// finalized tip's own epoch, so a Worker this node bound for an epoch that no finalized block
    /// has reached yet keeps status, stop and retransmission (independent review MAJOR-1).
    last_qualified_epoch: u64,
}
impl<V: PhysicalAttestationVerifier, H: CandidateHooks> WorkerCoordinator<V, H> {
    pub fn coordinator_public(&self) -> Hash {
        self.coordinator_public
    }
    pub fn new(
        chain: CanonicalStore,
        coordinator: Coordinator,
        coordinator_public: Hash,
        physical: BTreeMap<Hash, PhysicalMember>,
        verifier: V,
        hooks: H,
        time: Arc<dyn TimeBasis>,
    ) -> Self {
        Self {
            chain,
            coordinator,
            coordinator_public,
            physical,
            verifier,
            hooks,
            gate: None,
            context: None,
            started: Instant::now(),
            time,
            deferred: BTreeMap::new(),
            deferred_capacity: MAX_DEFERRED_RESULTS,
            last_qualified_epoch: 0,
        }
    }
    /// Results currently held for processing once the clock is qualified again. Read-only.
    pub fn deferred_results(&self) -> usize {
        self.deferred.len()
    }
    /// Test support only: a smaller bound for the result deferral, so its refusal can be shown
    /// with the fixture's Workers. Absent from every non-test build.
    #[cfg(test)]
    pub(crate) fn set_deferred_capacity_for_test(&mut self, capacity: usize) {
        self.deferred_capacity = capacity;
    }
    /// Process the results held while the clock was unqualified (Architect decision V2) once it
    /// is qualified again. Each goes through exactly the qualified Result path of `handle`: the
    /// Worker's binding at the current epoch, acceptance with its durable receipt and credit, and
    /// durable candidate preservation. A held result that now fails (a reassigned Worker, a stale
    /// sequence, invalid work, a storage error) is dropped here: the device still holds it in its
    /// durable outbox, and its next submission is judged afresh. While the clock is unqualified
    /// everything stays held. A qualification loss or MiningEpoch change within a batch keeps
    /// that entry and the rest held for a new drain and fresh canonical revalidation. Returns
    /// the number processed; it never fails its caller.
    pub fn process_deferred_results(&mut self) -> usize {
        if self.deferred.is_empty() {
            return 0;
        }
        // Genesis t0 is immutable; obtain it before sampling the per-entry basis. A canonical
        // read failure leaves the queue intact instead of claiming any fresh acceptance.
        let Ok(t0) = self.result_time_origin() else {
            return 0;
        };
        let mut processed = 0;
        let mut batch_epoch = None;
        while !self.deferred.is_empty() {
            let Ok(unix) = self.qualified_unix_ms() else {
                break;
            };
            let Ok(epoch) = mining_epoch(unix / 1000, t0) else {
                break;
            };
            if batch_epoch.is_some_and(|first| first != epoch) {
                break;
            }
            batch_epoch = Some(epoch);
            let (worker, submission) = self.deferred.pop_first().unwrap();
            match self.process_held(worker, &submission, unix) {
                Ok(true) => processed += 1,
                Ok(false) => {
                    self.deferred.insert(worker, submission);
                    break;
                }
                // Invalid/stale bindings and storage failures retain the documented device
                // outbox retry semantics; no acceptance is implied by dropping a held entry.
                Err(_) => (),
            }
        }
        processed
    }
    fn process_held(&mut self, worker: Hash, submission: &Submission, unix: u64) -> Result<bool> {
        let now = self.monotonic_ms()?;
        self.synchronize(now)?;
        self.binding(worker, unix / 1000)?;
        // Canonical synchronization/binding can block. Neither an earlier clock read nor the
        // current batch authorizes a new receipt after qualification or its epoch changes.
        if !self.result_clock_still_current(unix)? {
            return Ok(false);
        }
        let result = self.coordinator.result(worker, &submission.encode())?;
        self.hooks
            .preserve(&mut self.chain, &result, &self.physical, &self.verifier)?;
        Ok(true)
    }
    fn result_time_origin(&mut self) -> Result<u64> {
        let (tip, _) = self.chain.load_effective().map_err(err)?;
        let (parent, _) = self.chain.execution_parent(tip.height).map_err(err)?;
        Ok(parent.t0)
    }
    fn result_clock_still_current(&mut self, bound_unix: u64) -> Result<bool> {
        let t0 = self.result_time_origin()?;
        let bound_epoch = mining_epoch(bound_unix / 1000, t0).map_err(err)?;
        // Final qualified reading is AFTER all canonical reads, immediately before acceptance.
        let Ok(current_unix) = self.qualified_unix_ms() else {
            return Ok(false);
        };
        Ok(mining_epoch(current_unix / 1000, t0).ok() == Some(bound_epoch))
    }
    /// A Worker Result while the clock is unqualified (Architect decision V2). An EXACT
    /// retransmission of a result this coordinator already accepted gets its stored receipt back,
    /// byte for byte, after its candidate is durably preserved (deterministic and clock-free, as on
    /// the qualified path): no acceptance, no credit, no new signature. A fresh result is held,
    /// bounded, for processing once qualified time returns, and the reply is an ordinary heartbeat:
    /// no receipt, so the device keeps the result in its durable outbox. Nothing durable changes
    /// for a held result; a full deferral refuses it and holds nothing.
    fn unqualified_result(&mut self, worker: Hash, submission: Submission) -> Result<Vec<u8>> {
        if let Some(stored) = self
            .coordinator
            .retransmission(worker, &submission.encode())?
        {
            self.hooks
                .preserve(&mut self.chain, &stored, &self.physical, &self.verifier)?;
            return Ok(worker_protocol::receipt(&stored.receipt));
        }
        if !self.deferred.contains_key(&worker) && self.deferred.len() >= self.deferred_capacity {
            return Err(
                "Worker result deferral full: nothing is held, accepted or credited until the clock is qualified".into(),
            );
        }
        self.deferred.insert(worker, submission);
        Ok(worker_protocol::heartbeat().to_vec())
    }
    /// The shared qualified time basis (the same one the voter guard uses).
    pub fn time_basis(&self) -> Arc<dyn TimeBasis> {
        self.time.clone()
    }
    /// Local monotonic milliseconds for probe/lease logic. Independent of UTC: it needs no
    /// qualification, so liveness probing and lease expiry keep working while the clock is
    /// unqualified. It authorizes no work by itself (issuance also needs `qualified_unix_ms`).
    fn monotonic_ms(&self) -> Result<u64> {
        u64::try_from(self.started.elapsed().as_millis()).map_err(err)
    }
    /// Qualified UTC (floor of the lower bound). Errors while the clock is unqualified: this is a
    /// deferral for work authorization and worker binding, never a substitute reading.
    fn qualified_unix_ms(&self) -> Result<u64> {
        self.time
            .lower_bound_ms()
            .ok_or_else(|| "Qualified clock unavailable: no new work is issued".to_string())
    }
    fn now(&self) -> Result<(u64, u64)> {
        Ok((self.monotonic_ms()?, self.qualified_unix_ms()?))
    }
    fn synchronize(&mut self, now: u64) -> Result<()> {
        if self.chain.integrity_halted().map_err(err)? {
            self.gate = None;
            self.context = None;
            return Err("Canonical integrity halt".into());
        }
        let (tip, _) = self.chain.load_effective().map_err(err)?;
        let (parent, state) = self.chain.execution_parent(tip.height).map_err(err)?;
        let root = state.root().map_err(err)?; // Includes any authenticated recovery overlay.
        let context = (parent.block, root);
        if self.context != Some(context) {
            let mut gate = WorkGate::new(
                voter_actor::authority(&parent, &state).map_err(err)?,
                root,
                now,
            )
            .map_err(err)?;
            gate.set_run(true); // Device RUN remains its own persistent intent.
            self.gate = Some(gate);
            self.context = Some(context);
        }
        Ok(())
    }
    pub fn probe(&mut self) -> Result<Option<Decision>> {
        let now = self.monotonic_ms()?;
        self.synchronize(now)?;
        let mut nonce = [0; 32];
        getrandom::getrandom(&mut nonce).map_err(err)?;
        self.gate
            .as_mut()
            .ok_or("No work gate")?
            .request(now, nonce)
            .map_err(err)
    }
    pub fn accept_probe(&mut self, proof: &Certificate) -> Result<()> {
        let now = self.monotonic_ms()?;
        self.synchronize(now)?;
        self.gate
            .as_mut()
            .ok_or("No work gate")?
            .accept(now, proof)
            .map_err(err)
    }
    /// The Worker's binding for the CURRENT epoch of qualified time (`timestamp`, whole seconds):
    /// assignments due by then are activated first. Needed to issue work or accept a result.
    fn binding(&mut self, worker: Hash, timestamp: u64) -> Result<BindWorker> {
        self.binding_at(worker, BindingEpoch::Qualified(timestamp))
    }
    /// The Worker's binding without a clock (Architect decision V2): canonical state judged at the
    /// later of the finalized tip block's own MiningEpoch and the latest epoch of qualified time this
    /// process already bound a Worker at (`last_qualified_epoch`). It reads no clock and binds the
    /// Worker to no epoch beyond one already seen, so it authenticates a session ONLY for status,
    /// stop, exact stored-receipt retransmission and a bounded result deferral; it never issues
    /// work, accepts or credits a result, or signs a receipt.
    fn settled_binding(&mut self, worker: Hash) -> Result<BindWorker> {
        self.binding_at(worker, BindingEpoch::Settled)
    }
    fn binding_at(&mut self, worker: Hash, at: BindingEpoch) -> Result<BindWorker> {
        let (tip, _) = self.chain.load_effective().map_err(err)?;
        let (parent, mut state) = self.chain.execution_parent(tip.height).map_err(err)?;
        let epoch = match at {
            BindingEpoch::Qualified(timestamp) => {
                let epoch = mining_epoch(timestamp, parent.t0).map_err(err)?;
                self.last_qualified_epoch = self.last_qualified_epoch.max(epoch);
                epoch
            }
            // No clock is read: the finalized tip's epoch, or the latest epoch this process has
            // already bound a Worker at under qualified time, whichever is later.
            BindingEpoch::Settled => mining_epoch(tip.timestamp, parent.t0)
                .map_err(err)?
                .max(self.last_qualified_epoch),
        };
        state.licenses.activate_due(epoch).map_err(err)?;
        let license = state
            .licenses
            .workers
            .get(&worker)
            .ok_or("Unknown Worker")?
            .binding
            .license;
        let (_, active) = state.licenses.active(license, worker, epoch).map_err(err)?;
        let binding = &active.binding;
        if binding.coordinator_public != self.coordinator_public
            || binding.genesis != parent.genesis
            || binding.fingerprint != parent.fingerprint
        {
            return Err("Wrong canonical Worker coordinator/context".into());
        }
        // valid_until_height limits submission of the assignment operation;
        // it is NOT an expiry for an already canonical active assignment.
        Ok(binding.clone())
    }
}
impl<V: PhysicalAttestationVerifier + Send + 'static, H: CandidateHooks> WorkerBackend
    for WorkerCoordinator<V, H>
{
    fn active(&mut self, worker: Hash) -> Result<BindWorker> {
        // Architect decision V2: session authentication needs no qualified clock. With qualified
        // time the Worker is bound for the current epoch; without it, only the binding finalized
        // state already establishes authenticates the session (status, stop, stored-receipt
        // retransmission, a bounded result deferral), and no work is bound or issued.
        let now = self.monotonic_ms()?;
        self.synchronize(now)?;
        match self.qualified_unix_ms() {
            Ok(unix) => self.binding(worker, unix / 1000),
            Err(_) => self.settled_binding(worker),
        }
    }
    fn handle(&mut self, worker: Hash, message: WorkerMessage) -> Result<Vec<u8>> {
        // Architect decision V2: monotonic time and canonical state come first, so status, stop,
        // exact stored-receipt retransmission and a bounded deferral of a fresh result need no
        // qualified clock. Qualified time is required before anything binds the Worker to the
        // current epoch, issues work, accepts or credits a result, or signs a new receipt.
        let now = self.monotonic_ms()?;
        self.synchronize(now)?;
        let qualified = self.qualified_unix_ms();
        let binding = match &qualified {
            Ok(unix) => self.binding(worker, unix / 1000)?,
            Err(_) => self.settled_binding(worker)?,
        };
        match message {
            WorkerMessage::Status { state, .. } => {
                if self
                    .gate
                    .as_mut()
                    .ok_or("No work gate")?
                    .state(now)
                    .map_err(err)?
                    == WorkState::Running
                    || state != 4
                {
                    // Keep polling non-mining devices even without a quorum
                    // lease: an earlier valid result must still drain from its
                    // durable outbox. New requests remain quorum-gated below.
                    Ok(worker_protocol::heartbeat().to_vec())
                } else {
                    Ok(worker_protocol::retire().to_vec())
                }
            }
            WorkerMessage::Request {
                nonce,
                sequence,
                chain,
            } => {
                // New work binds the Worker to the current epoch: qualified time or nothing.
                let unix = qualified?;
                if self
                    .gate
                    .as_mut()
                    .ok_or("No work gate")?
                    .state(now)
                    .map_err(err)?
                    != WorkState::Running
                {
                    return worker_protocol::waiting_quorum(nonce);
                }
                let body = self.hooks.body(&mut self.chain, &binding, unix / 1000)?;
                // Assembly may take time: recalculate clocks and gate immediately
                // before durable issuance. Epoch-boundary races fail closed.
                let (issued_now, issued_unix) = self.now()?;
                self.synchronize(issued_now)?;
                let decision_basis = self.time.clone();
                let decision_started = self.started;
                let (work, lifetime) = self.coordinator.issue(
                    &mut self.chain,
                    self.gate.as_mut().ok_or("No work gate")?,
                    MiningRequest {
                        worker,
                        license: binding.license,
                        body,
                        timestamp: unix / 1000,
                        now_ms: issued_now,
                        unix_ms: issued_unix,
                        observation_sequence: sequence,
                        observation_chain: chain,
                    },
                    &self.physical,
                    &self.verifier,
                    || {
                        let unix = decision_basis.lower_bound_ms().ok_or_else(|| {
                            "Qualified clock unavailable: no new work is issued".to_string()
                        })?;
                        // The provider may block on its own lock: sample lease
                        // elapsed time after it returns, never before that wait.
                        let now =
                            u64::try_from(decision_started.elapsed().as_millis()).map_err(err)?;
                        Ok((now, unix))
                    },
                )?;
                worker_protocol::offer(&work, nonce, lifetime)
            }
            WorkerMessage::Result(submission) => {
                let Ok(bound_unix) = qualified else {
                    return self.unqualified_result(worker, submission);
                };
                if !self.result_clock_still_current(bound_unix)? {
                    // Same bounded holding/exact retransmission behavior on loss or an epoch
                    // change during binding, even if the first reading was qualified.
                    return self.unqualified_result(worker, submission);
                }
                let result = self.coordinator.result(worker, &submission.encode())?;
                self.hooks
                    .preserve(&mut self.chain, &result, &self.physical, &self.verifier)?;
                Ok(worker_protocol::receipt(&result.receipt))
            }
        }
    }
}
