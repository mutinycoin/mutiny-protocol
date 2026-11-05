//! Candidate hybrid work issuance adapter. No sockets or production activation.
//! Transport must call `release` immediately before delivery, then enforce the
//! returned duration from the miner's original request start, never receipt.
use crate::{
    hybrid_runtime_v2::{HybridRuntime, WorkRequest},
    node_custody_v2::EncryptedNodeKey,
    work_journal_v2::Journal,
};
use mutiny_consensus_v8::{
    Hash,
    anchors::FinalizedAnchor,
    blocks::BlockBody,
    certificates::Decision,
    liveness_v2::{Proof, WorkGate, WorkState},
    pow::{WorkAuthority, WorkContext, mining_epoch},
    work_authority_v2::Authority,
};
use mutiny_crypto_v2::HybridSignature;
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Debug) -> String {
    format!("Hybrid coordinator: {e:?}")
}

#[derive(Clone, Copy, Debug)]
pub struct Sample {
    pub monotonic_ms: u64,
    pub unix_ms: u64,
}
/// Trusted local clock, never values supplied by a miner or peer.
pub trait Clock {
    fn sample(&mut self) -> Result<Sample>;
}
/// Production `Clock` over the qualified conservative basis (floor of the lower bound). Fails
/// closed while unqualified: no work is prepared without qualified time. There is deliberately no
/// OS-clock `Clock` implementation in non-test code.
pub struct QualifiedClock {
    start: std::time::Instant,
    basis: std::sync::Arc<dyn mutiny_consensus_v8::holdover_clock_v1::TimeBasis>,
}
impl QualifiedClock {
    pub fn new(
        basis: std::sync::Arc<dyn mutiny_consensus_v8::holdover_clock_v1::TimeBasis>,
    ) -> Self {
        Self {
            start: std::time::Instant::now(),
            basis,
        }
    }
}
impl Clock for QualifiedClock {
    fn sample(&mut self) -> Result<Sample> {
        Ok(Sample {
            monotonic_ms: self
                .start
                .elapsed()
                .as_millis()
                .try_into()
                .map_err(|_| "Monotonic clock overflow")?,
            unix_ms: self
                .basis
                .lower_bound_ms()
                .ok_or("Qualified clock unavailable")?,
        })
    }
}
pub struct Request<'a> {
    pub parent: &'a FinalizedAnchor,
    pub license: Hash,
    pub worker: Hash,
    pub request_nonce: Hash,
    pub nonce_start: u64,
    pub nonce_end: u64,
    pub operations: &'a [Vec<u8>],
}
/// Neither signatures nor body are exposed until the final fresh checks pass.
pub struct Pending {
    authority: Authority,
    body: BlockBody,
    context: WorkContext,
    parent: FinalizedAnchor,
    nonce: Hash,
    deadline: u64,
    token: std::sync::Arc<()>,
}
pub struct Delivery {
    pub authority: Authority,
    pub body: BlockBody,
    pub request_nonce: Hash,
    pub valid_for_ms: u64,
    /// Queue immediately under the original local deadline. Encoding this
    /// packet does not renew request/epoch/quorum lifetime.
    pub wire: Vec<u8>,
}
/// Worker-advertised checkpoint is untrusted until compared with the durable
/// receipt journal. Callers own the canonical/issuance/accounting actor.
pub struct Accounting<'a> {
    pub journal: &'a crate::observation_journal_v2::Journal,
    pub sequence: u64,
    pub chain: Hash,
}
pub struct AccountedPending {
    pending: Pending,
    sequence: u64,
    chain: Hash,
}
enum WorkSigner<'a> {
    Physical(&'a EncryptedNodeKey),
    Software(&'a crate::software_coordinator_custody_v2::EncryptedCoordinatorKey),
}
pub struct Coordinator {
    gate: Option<WorkGate>,
    context: Option<(FinalizedAnchor, Hash)>,
    run: bool,
    previous: Option<Sample>,
    token: std::sync::Arc<()>,
}
impl Default for Coordinator {
    fn default() -> Self {
        Self {
            gate: None,
            context: None,
            run: false,
            previous: None,
            token: std::sync::Arc::new(()),
        }
    }
}
impl Coordinator {
    fn check_accounting(issued: &Journal, accounting: &Accounting<'_>, worker: Hash) -> Result<()> {
        if !accounting.journal.matches_issuance(issued)
            || !accounting.journal.matches_checkpoint(
                worker,
                accounting.sequence,
                accounting.chain,
            )?
        {
            return Err("Worker receipt checkpoint not synchronized".into());
        }
        Ok(())
    }
    /// Reject a missing receipt acknowledgement before consuming a new ticket.
    /// The returned opaque pending object requires the same checkpoint again
    /// immediately before publication. Existing work deadlines are preserved.
    pub fn prepare_accounted(
        &mut self,
        runtime: &mut HybridRuntime,
        issued: &mut Journal,
        key: &crate::observation_custody_v2::Custody<'_>,
        request: Request<'_>,
        accounting: Accounting<'_>,
        candidates: &mut crate::candidate_journal_v2::Journal,
        clock: &mut impl Clock,
    ) -> Result<AccountedPending> {
        let worker = request.worker;
        if issued.uses_a2() || accounting.journal.uses_a2() {
            return Err("Legacy accounted work requires matching legacy journals".into());
        }
        Self::check_accounting(issued, &accounting, worker)?;
        // A Worker can calculate its next chain hash without receiving the
        // receipt. Checkpoint equality alone must not let it replace the last
        // durable outbox candidate before that candidate has been retained.
        if let Some(committed) = accounting.journal.load(worker)? {
            let (header, authority, body) = committed.candidate();
            candidates.preserve(
                runtime,
                &crate::candidate_journal_v2::Record {
                    header: header.clone(),
                    authority: authority.clone(),
                    body: body.clone(),
                },
            )?;
        }
        let pending = match key {
            crate::observation_custody_v2::Custody::Physical(k) => {
                self.prepare(runtime, issued, k, request, clock)
            }
            crate::observation_custody_v2::Custody::Software(k) => {
                self.prepare_software(runtime, issued, k, request, clock)
            }
        }?;
        Self::check_accounting(issued, &accounting, worker)?;
        Ok(AccountedPending {
            pending,
            sequence: accounting.sequence,
            chain: accounting.chain,
        })
    }
    /// Successor proposal retention uses its explicit bounded schema. Work and
    /// observation journals must also be opened through their A2 entry points.
    pub fn prepare_accounted_a2(
        &mut self,
        runtime: &mut HybridRuntime,
        issued: &mut Journal,
        key: &crate::observation_custody_v2::Custody<'_>,
        request: Request<'_>,
        accounting: Accounting<'_>,
        candidates: &mut crate::candidate_journal_v3::Journal,
        clock: &mut impl Clock,
    ) -> Result<AccountedPending> {
        let worker = request.worker;
        if !issued.uses_a2() || !accounting.journal.uses_a2() {
            return Err("A2 accounted work requires matching successor journals".into());
        }
        Self::check_accounting(issued,&accounting,worker)?;
        if let Some(committed) = accounting.journal.load(worker)? {
            let (header,authority,body) = committed.candidate();
            candidates.preserve(runtime,&crate::candidate_journal_v3::Record {
                header: header.clone(), authority: authority.clone(), body: body.clone(),
            })?;
        }
        let pending = match key {
            crate::observation_custody_v2::Custody::Physical(k) => self.prepare(runtime,issued,k,request,clock),
            crate::observation_custody_v2::Custody::Software(k) => self.prepare_software(runtime,issued,k,request,clock),
        }?;
        Self::check_accounting(issued,&accounting,worker)?;
        Ok(AccountedPending { pending,sequence: accounting.sequence,chain: accounting.chain })
    }
    pub fn release_accounted(
        &mut self,
        runtime: &HybridRuntime,
        issued: &Journal,
        observations: &crate::observation_journal_v2::Journal,
        pending: AccountedPending,
        clock: &mut impl Clock,
    ) -> Result<Delivery> {
        Self::check_accounting(
            issued,
            &Accounting {
                journal: observations,
                sequence: pending.sequence,
                chain: pending.chain,
            },
            pending.pending.context.worker,
        )?;
        // Release samples the clock after all journal/canonical reads. Do not
        // perform another slow operation and reuse its advertised duration.
        self.release(runtime, issued, pending.pending, clock)
    }
    pub fn set_run(&mut self, run: bool) {
        if self.run != run {
            self.token = std::sync::Arc::new(());
        }
        self.run = run;
        if let Some(gate) = self.gate.as_mut() {
            gate.set_run(run);
        }
    }
    fn sample(&mut self, clock: &mut impl Clock) -> Result<Sample> {
        let sample = match clock.sample() {
            Ok(v) => v,
            Err(e) => {
                self.invalidate();
                return Err(e);
            }
        };
        if self
            .previous
            .is_some_and(|p| sample.monotonic_ms < p.monotonic_ms || sample.unix_ms < p.unix_ms)
        {
            self.invalidate();
            return Err("Local clock regressed".into());
        }
        self.previous = Some(sample);
        Ok(sample)
    }
    fn invalidate(&mut self) {
        self.token = std::sync::Arc::new(());
        self.gate = None;
        self.context = None;
    }
    fn synchronize(
        &mut self,
        runtime: &HybridRuntime,
        parent: &FinalizedAnchor,
        now: u64,
    ) -> Result<()> {
        let (authority, root) = match runtime.chain.current_liveness(parent) {
            Ok(v) => v,
            Err(e) => {
                self.invalidate();
                return Err(err(e));
            }
        };
        if self.context.as_ref() != Some(&(parent.clone(), root)) {
            self.invalidate();
            let mut gate = WorkGate::new(authority, root, now).map_err(err)?;
            gate.set_run(self.run);
            self.gate = Some(gate);
            self.context = Some((parent.clone(), root));
        }
        Ok(())
    }
    pub fn request_probe(
        &mut self,
        runtime: &HybridRuntime,
        parent: &FinalizedAnchor,
        clock: &mut impl Clock,
    ) -> Result<Option<Decision>> {
        let sample = self.sample(clock)?;
        self.synchronize(runtime, parent, sample.monotonic_ms)?;
        let mut challenge = [0; 32];
        mutiny_crypto_v2::fill_os_random(&mut challenge)
            .map_err(|_| "OS challenge entropy unavailable")?;
        self.gate
            .as_mut()
            .ok_or("Missing gate")?
            .request(sample.monotonic_ms, challenge)
            .map_err(err)
    }
    pub fn accept_probe(
        &mut self,
        runtime: &HybridRuntime,
        parent: &FinalizedAnchor,
        proof: &Proof,
        clock: &mut impl Clock,
    ) -> Result<WorkState> {
        let before = self.sample(clock)?;
        self.synchronize(runtime, parent, before.monotonic_ms)?;
        self.gate
            .as_mut()
            .ok_or("Missing gate")?
            .accept(before.monotonic_ms, proof)
            .map_err(err)?;
        // Signature verification can take time. Read both clocks AGAIN after it.
        self.synchronize(runtime, parent, before.monotonic_ms)?;
        let after = self.sample(clock)?;
        self.gate
            .as_mut()
            .ok_or("Missing gate")?
            .state(after.monotonic_ms)
            .map_err(err)
    }
    fn remaining(
        &mut self,
        runtime: &HybridRuntime,
        parent: &FinalizedAnchor,
        context: &WorkContext,
        epoch: u64,
        deadline: u64,
        clock: &mut impl Clock,
    ) -> Result<u64> {
        // Canonical replay may also be slow; sample after the authenticated read.
        let previous = self.previous.ok_or("Clock not initialized")?;
        self.synchronize(runtime, parent, previous.monotonic_ms)?;
        let now = self.sample(clock)?;
        let lease = self
            .gate
            .as_mut()
            .ok_or("Missing gate")?
            .work_lease(now.monotonic_ms, context)
            .map_err(err)?;
        remaining_duration(now, context.t0, epoch, deadline, lease)
    }
    pub fn prepare(
        &mut self,
        runtime: &mut HybridRuntime,
        journal: &mut Journal,
        key: &EncryptedNodeKey,
        request: Request<'_>,
        clock: &mut impl Clock,
    ) -> Result<Pending> {
        self.prepare_with_signer(runtime, journal, WorkSigner::Physical(key), request, clock)
    }
    pub fn prepare_software(
        &mut self,
        runtime: &mut HybridRuntime,
        journal: &mut Journal,
        key: &crate::software_coordinator_custody_v2::EncryptedCoordinatorKey,
        request: Request<'_>,
        clock: &mut impl Clock,
    ) -> Result<Pending> {
        self.prepare_with_signer(runtime, journal, WorkSigner::Software(key), request, clock)
    }
    fn prepare_with_signer(
        &mut self,
        runtime: &mut HybridRuntime,
        journal: &mut Journal,
        key: WorkSigner<'_>,
        request: Request<'_>,
        clock: &mut impl Clock,
    ) -> Result<Pending> {
        if request.request_nonce == [0; 32] || request.nonce_start > request.nonce_end {
            return Err("Invalid work request".into());
        }
        let start = self.sample(clock)?;
        let timestamp = start.unix_ms / 1000;
        let (context, descriptor) = runtime
            .chain
            .current_work_context(request.parent, request.license, request.worker, timestamp)
            .map_err(err)?;
        if !journal.matches_context(context.genesis, context.fingerprint, &descriptor) {
            return Err("Journal context mismatch".into());
        }
        let epoch = mining_epoch(timestamp, context.t0).map_err(err)?;
        let limit = start
            .monotonic_ms
            .checked_add(60_000)
            .ok_or("Request deadline overflow")?;
        self.remaining(runtime, request.parent, &context, epoch, limit, clock)?;
        // Commit reservation BEFORE execution; a later failure consumes it.
        let reservation = journal.reserve(request.worker, context.last_accepted_ticket)?;
        let prepared = runtime
            .prepare(WorkRequest {
                expected_parent: request.parent,
                license: request.license,
                worker: request.worker,
                timestamp,
                ticket: reservation.ticket(),
                operations: request.operations,
            })
            .map_err(err)?;
        let mut authority = Authority {
            work: WorkAuthority {
                candidate: prepared.candidate,
                assignment_sequence: context.assignment_sequence,
                ticket_sequence: reservation.ticket(),
                coordinator: context.coordinator,
                nonce_start: request.nonce_start,
                nonce_end: request.nonce_end,
                epoch,
            },
            node_descriptor: descriptor,
            signature: HybridSignature {
                ed448: [0; 114],
                fndsa: [0; 1280],
            },
        };
        self.remaining(runtime, request.parent, &context, epoch, limit, clock)?;
        match key {
            WorkSigner::Physical(k) => k.authorize_work(
                &runtime.chain,
                request.parent,
                &mut authority,
                &prepared.body,
            )?,
            WorkSigner::Software(k) => k.authorize_work(
                &runtime.chain,
                request.parent,
                &mut authority,
                &prepared.body,
            )?,
        }
        self.remaining(runtime, request.parent, &context, epoch, limit, clock)?;
        journal.bind_body_capacity(runtime,&authority)?;
        journal.finish(&reservation, &authority, &prepared.body)?;
        Ok(Pending {
            authority,
            body: prepared.body,
            context,
            parent: request.parent.clone(),
            nonce: request.request_nonce,
            deadline: limit,
            token: self.token.clone(),
        })
    }
    pub fn release(
        &mut self,
        runtime: &HybridRuntime,
        journal: &Journal,
        pending: Pending,
        clock: &mut impl Clock,
    ) -> Result<Delivery> {
        if !std::sync::Arc::ptr_eq(&pending.token, &self.token) {
            return Err("Work request retired".into());
        }
        // A newer reservation invalidates an older prepared response. Restart
        // restores no Pending or quorum lease, even when the journal has bytes.
        if !journal.matches_context(
            pending.context.genesis,
            pending.context.fingerprint,
            &pending.authority.node_descriptor,
        ) || journal.lookup(pending.context.worker)?.as_ref()
            != Some(&(pending.authority.clone(), pending.body.clone()))
        {
            return Err("Work publication superseded or unavailable".into());
        }
        // Encode before the final slow-read/clock boundary. Only the fixed
        // lifetime bytes are patched after the final deadline check.
        let mut wire = crate::worker_protocol_v2::offer(&pending.authority, pending.nonce, 1)
            .map_err(|_| "Work offer encoding")?;
        let duration = self.remaining(
            runtime,
            &pending.parent,
            &pending.context,
            pending.authority.work.epoch,
            pending.deadline,
            clock,
        )?;
        if !std::sync::Arc::ptr_eq(&pending.token, &self.token) {
            return Err("Work context retired".into());
        }
        wire[42..50].copy_from_slice(&duration.to_be_bytes());
        Ok(Delivery {
            authority: pending.authority,
            body: pending.body,
            request_nonce: pending.nonce,
            valid_for_ms: duration,
            wire,
        })
    }
}
fn remaining_duration(now: Sample, t0: u64, epoch: u64, deadline: u64, lease: u64) -> Result<u64> {
    if mining_epoch(now.unix_ms / 1000, t0).map_err(err)? != epoch {
        return Err("MiningEpoch changed".into());
    }
    let end = epoch
        .checked_add(1)
        .and_then(|e| e.checked_mul(60))
        .and_then(|e| e.checked_add(t0))
        .and_then(|e| e.checked_mul(1000))
        .ok_or("Epoch boundary overflow")?;
    let remaining = deadline
        .checked_sub(now.monotonic_ms)
        .ok_or("Work request expired")?
        .min(end.checked_sub(now.unix_ms).ok_or("Epoch expired")?)
        .min(lease)
        .min(60_000);
    if remaining == 0 {
        return Err("Work lease expired".into());
    }
    Ok(remaining)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn qualified_clock_uses_the_conservative_basis_and_fails_closed() {
        use mutiny_consensus_v8::holdover_clock_v1::FixedBasis;
        let basis = FixedBasis::at_ms(1_234_567);
        let mut clock = QualifiedClock::new(basis.clone());
        assert_eq!(clock.sample().unwrap().unix_ms, 1_234_567);
        basis.set(1_234_999);
        assert_eq!(clock.sample().unwrap().unix_ms, 1_234_999);
        basis.set_qualified(false);
        assert!(clock.sample().is_err(), "no sample while unqualified");
    }
    #[test]
    fn deadlines_never_extend_for_slow_signing_epoch_change_or_expired_quorum() {
        let sample = Sample {
            monotonic_ms: 200,
            unix_ms: 1_059_000,
        };
        assert_eq!(
            remaining_duration(sample, 1000, 0, 60_000, 30_000).unwrap(),
            1000
        );
        assert_eq!(
            remaining_duration(sample, 1000, 0, 60_000, 500).unwrap(),
            500
        );
        assert_eq!(
            remaining_duration(sample, 1000, 0, 250, 30_000).unwrap(),
            50
        );
        for lease in [0] {
            assert!(remaining_duration(sample, 1000, 0, 60_000, lease).is_err());
        }
        assert!(remaining_duration(sample, 1000, 0, 200, 30_000).is_err());
        assert!(
            remaining_duration(
                Sample {
                    unix_ms: 1_060_000,
                    ..sample
                },
                1000,
                0,
                60_000,
                30_000
            )
            .is_err()
        );
        assert!(
            remaining_duration(
                Sample {
                    unix_ms: 999_999,
                    ..sample
                },
                1000,
                0,
                60_000,
                30_000
            )
            .is_err()
        );
        assert!(
            remaining_duration(
                Sample {
                    unix_ms: u64::MAX,
                    ..sample
                },
                u64::MAX / 1000,
                0,
                60_000,
                30_000
            )
            .is_err()
        );
    }
    #[test]
    fn clock_failures_drop_context_preserve_run_and_require_clock_recovery() {
        struct TestClock(Result<Sample>);
        impl Clock for TestClock {
            fn sample(&mut self) -> Result<Sample> {
                self.0.clone()
            }
        }
        let mut coordinator = Coordinator::default();
        coordinator.set_run(true);
        coordinator
            .sample(&mut TestClock(Ok(Sample {
                monotonic_ms: 100,
                unix_ms: 1000,
            })))
            .unwrap();
        for (mono, wall) in [(99, 1001), (101, 999)] {
            assert!(
                coordinator
                    .sample(&mut TestClock(Ok(Sample {
                        monotonic_ms: mono,
                        unix_ms: wall
                    })))
                    .is_err()
            );
            assert!(coordinator.gate.is_none());
            assert!(coordinator.run);
        }
        assert!(
            coordinator
                .sample(&mut TestClock(Err("Unavailable".into())))
                .is_err()
        );
        coordinator
            .sample(&mut TestClock(Ok(Sample {
                monotonic_ms: 100,
                unix_ms: 1000,
            })))
            .unwrap();
        assert!(coordinator.gate.is_none());
    }
}
