//! Persistent chain/voter reconciliation. A canonical commit precedes advancing
//! the TPM snapshot; restart revalidates committed evidence to finish that step.
use crate::{
    Error, Hash,
    anchors::FinalizedAnchor,
    bft::Step,
    block_envelope::BlockEnvelope,
    canonical_store::{CanonicalStore, ChainError},
    counter_voter::{CounterSigningBackend, CounterVoter, CounterVoterError},
    execution::{LicensedExecution, State, WorkParent},
    freshness::{PhysicalAttestationVerifier, PhysicalMember},
    votes::{HeightAuthority, Vote},
};
use std::{
    collections::BTreeMap,
    path::Path,
    time::{Duration, Instant},
};

#[derive(Debug)]
pub enum ActorError {
    Chain(ChainError),
    Voter(CounterVoterError),
    Invalid(Error),
    Ingress(crate::votes::IngressError),
    Rollback,
    Halted,
    /// A block vote (or the completion of an unmarked legacy reservation) was withheld ONLY for
    /// local time reasons: the qualified clock is behind the block's timestamp, or there is no
    /// qualified clock. This is an explicit, NONFATAL result. It is produced only by the pure
    /// pre-check that runs before the halting latch is set and before any custody, reducer or
    /// counter state is touched, so returning it never changes `halted`, and no path clears
    /// `halted` on its account. A halted actor reports `Halted` instead, whatever the clock says.
    TimeDeferred(crate::vote_clock_v1::TimeStatus),
    /// A vote request decided for a (height, round) context this actor has since left (Architect
    /// decision V4: clock recovery revalidates the current context instead of signing for an
    /// expired round). Explicit and NONFATAL: `sign_for` raises it after the backend check and
    /// before the clock, the latch, the reducer and custody, so it signs, writes, poisons and halts
    /// nothing. The caller re-derives its decision from `context()`.
    StaleContext {
        requested: VoteContext,
        current: VoteContext,
    },
}
/// The (height, round) a vote request is decided for. A caller reads it with `VoterActor::context`
/// when it decides, and `VoterActor::sign_for` signs only while the actor is still in exactly that
/// context (Architect decision V4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VoteContext {
    pub height: u64,
    pub round: u64,
}
impl ActorError {
    /// The time status behind an explicit nonfatal deferral; `None` for every other error.
    pub fn time_deferral(&self) -> Option<crate::vote_clock_v1::TimeStatus> {
        match self {
            Self::TimeDeferred(status) => Some(*status),
            _ => None,
        }
    }
    /// True when a vote was withheld only for local time reasons (defer/abstain; never a fault).
    pub fn is_time_deferral(&self) -> bool {
        self.time_deferral().is_some()
    }
}
impl From<ChainError> for ActorError {
    fn from(e: ChainError) -> Self {
        Self::Chain(e)
    }
}
impl From<CounterVoterError> for ActorError {
    fn from(e: CounterVoterError) -> Self {
        Self::Voter(e)
    }
}
impl From<Error> for ActorError {
    fn from(e: Error) -> Self {
        Self::Invalid(e)
    }
}
impl From<crate::votes::IngressError> for ActorError {
    fn from(e: crate::votes::IngressError) -> Self {
        Self::Ingress(e)
    }
}
type Result<T> = std::result::Result<T, ActorError>;

pub fn authority(parent: &WorkParent, state: &State) -> Result<HeightAuthority> {
    let registry = state
        .continuity
        .as_ref()
        .ok_or(Error::UnqualifiedPhysical)?;
    let (membership, reputation, attestation) = registry.roots()?;
    Ok(HeightAuthority {
        parent: FinalizedAnchor {
            network: crate::NETWORK_ID,
            genesis: parent.genesis,
            fingerprint: parent.fingerprint,
            height: parent.height,
            block: parent.block,
        },
        membership,
        reputation,
        attestation,
        voters: registry.voters()?,
    })
}
/// Trusted local monotonic source for the actor's elapsed precommit interval.
/// The default is the OS monotonic Instant; software fixtures can share the
/// driver's controlled source without changing the ordinary timeout duration.
#[cfg(any(test, feature = "actor-timer-test-fixtures"))]
pub trait MonotonicTimer: Send + Sync {
    fn now(&self) -> Instant;
}
#[cfg(any(test, feature = "actor-timer-test-fixtures"))]
struct RealMonotonicTimer;
#[cfg(any(test, feature = "actor-timer-test-fixtures"))]
impl MonotonicTimer for RealMonotonicTimer {
    fn now(&self) -> Instant {
        Instant::now()
    }
}
/// One owner of the canonical store, the voter custody and the halting latch.
///
/// `halted` is a one-way safety latch, held in memory. `check_backend`, `reconcile`, and `sign` and
/// `replay` after their pure pre-checks, set it BEFORE any step that may touch custody, the counter
/// or the reducer's locks, and clear it only on their own success, after starting with it clear
/// (what each call latches, and what it does not, is listed in docs/OS-CLOCK-CLASSIFICATION-V1.md,
/// 9.2). A genuine failure (counter inconsistency, backend corruption, an interrupted signature),
/// and a request conflict or a halted reducer found by the pure pre-check (`refusal`), therefore
/// leave THIS in-memory actor halted: every later call, including `tick`-driven `replay`/`sign`,
/// reports `Halted`, and only reopening (full revalidation of both durable stores) can produce a
/// working actor. The latch itself is never written. A reopen re-derives every cause that lives in
/// durable state (the backend and its counter, the counter-protected record, the canonical
/// integrity halt). A request conflict is a refused REQUEST, not evidence of two durable decisions
/// (Architect decision V1): it is held in memory only, writes nothing and uses no counter value,
/// and the reopened actor can complete only the ORIGINAL stored decision and refuses the
/// conflicting request again (docs/OS-CLOCK-CLASSIFICATION-V1.md, 9.3 and 9.10).
///
/// Local TIME reasons are not failures and never use the latch. The pure pre-checks in `sign` and
/// `replay` run BEFORE it is set, judge ONE clock reading that the voter then reuses, and return the
/// explicit result `ActorError::TimeDeferred` with the latch untouched. No code in this file resets
/// `halted` on account of a time deferral.
pub struct VoterActor {
    voter: CounterVoter,
    halted: bool,
    precommit_deadline: Option<(u64, u64, Instant)>,
    #[cfg(any(test, feature = "actor-timer-test-fixtures"))]
    timer: std::sync::Arc<dyn MonotonicTimer>,
}
/// An executed mining candidate has no certificate yet. Its parent authority is
/// always loaded by the actor, never supplied by the caller.
pub struct Proposal<'a> {
    pub header: &'a crate::pow::WorkHeader,
    pub body: &'a crate::blocks::BlockBody,
    pub authority: &'a crate::pow::WorkAuthority,
    pub signature: &'a [u8; 64],
}
impl VoterActor {
    /// Install before any precommit timer is armed. This does not retime an
    /// existing reservation/deadline or change production interval arithmetic.
    #[cfg(any(test, feature = "actor-timer-test-fixtures"))]
    pub fn set_monotonic_timer(&mut self, timer: std::sync::Arc<dyn MonotonicTimer>) -> Result<()> {
        if self.precommit_deadline.is_some() {
            return Err(ActorError::Invalid(Error::Duplicate));
        }
        self.timer = timer;
        Ok(())
    }
    fn monotonic_now(&self) -> Instant {
        #[cfg(any(test, feature = "actor-timer-test-fixtures"))]
        {
            self.timer.now()
        }
        #[cfg(not(any(test, feature = "actor-timer-test-fixtures")))]
        {
            Instant::now()
        }
    }
    /// Install the qualified local clock consulted before every fresh block vote.
    pub fn set_vote_clock(&mut self, clock: std::sync::Arc<dyn crate::vote_clock_v1::VoteClock>) {
        self.voter.set_vote_clock(clock);
    }
    /// Pure local time eligibility of voting for an executed proposal right now.
    pub fn time_status(&self, block: Hash) -> crate::vote_clock_v1::TimeStatus {
        self.voter.time_status(block)
    }
    /// Time eligibility of a bare candidate timestamp under this voter's clock: exactly the
    /// comparison `time_status` applies to an executed proposal (`timestamp <= qualified now`).
    pub fn timestamp_status(&self, timestamp: u64) -> crate::vote_clock_v1::TimeStatus {
        self.voter.timestamp_status(timestamp)
    }
    pub fn open(
        path: &Path,
        node: Hash,
        initial: Option<u64>,
        chain: &mut CanonicalStore,
        backend: &mut impl CounterSigningBackend,
        physical: &BTreeMap<Hash, PhysicalMember>,
        verifier: &impl PhysicalAttestationVerifier,
    ) -> Result<Self> {
        if chain.integrity_halted()? {
            return Err(ActorError::Halted);
        }
        let (tip, _) = chain.load_effective()?;
        let (parent, state) = chain.execution_parent(tip.height)?;
        let current = authority(&parent, &state)?;
        let height = if initial.is_some() {
            // Fresh voter custody may only bootstrap at height zero. Explicit
            // physical recovery has its own ceremony and is not this interface.
            if tip.height != 0 {
                return Err(ActorError::Rollback);
            }
            1
        } else {
            let current = crate::votes::AuthenticatedRound::new(current)?;
            CounterVoter::stored_height(path, current.signing_context(node)?, backend)?
        };
        if height == 0 || height > tip.height.checked_add(1).ok_or(Error::Overflow)? {
            return Err(ActorError::Rollback);
        }
        let (parent, state) = chain.execution_parent(height - 1)?;
        let voter = CounterVoter::open(path, authority(&parent, &state)?, node, initial, backend)?;
        let mut actor = Self {
            voter,
            halted: false,
            precommit_deadline: None,
            #[cfg(any(test, feature = "actor-timer-test-fixtures"))]
            timer: std::sync::Arc::new(RealMonotonicTimer),
        };
        actor.reconcile(chain, backend, physical, verifier)?;
        Ok(actor)
    }
    pub fn node(&self) -> Hash {
        self.voter.node()
    }
    pub fn height(&self) -> u64 {
        self.voter.height()
    }
    /// Local scheduler inspection only. No vote is published from this view;
    /// all reuse/completion still passes through the counter-backed sign path.
    pub fn progress(&self) -> Result<(crate::bft::LockState, Option<Vote>, Option<Vote>)> {
        if self.halted {
            return Err(ActorError::Halted);
        }
        Ok(self.voter.progress()?)
    }
    /// True once the halting latch is set. Read-only; nothing resets it.
    pub fn is_halted(&self) -> bool {
        self.halted
    }
    /// True once the voter custody refuses every further operation: the poison that `refusal`, or a
    /// failure after custody was touched, sets. Read-only; only a reopen unpoisons the voter.
    pub fn voter_poisoned(&self) -> bool {
        self.voter.is_poisoned()
    }
    /// The armed precommit timeout as (height, round, monotonic deadline). Read-only.
    pub fn precommit_deadline(&self) -> Option<(u64, u64, Instant)> {
        self.precommit_deadline
    }
    /// The (height, round) this actor votes in now, read from the counter-protected record.
    /// Read-only; `Halted` for a halted actor.
    pub fn context(&self) -> Result<VoteContext> {
        let (state, _, _) = self.progress()?;
        Ok(VoteContext {
            height: self.height(),
            round: state.round,
        })
    }
    /// Classify a refusal raised by a PURE pre-check, i.e. before the latch was set and before any
    /// custody, reducer or counter state was touched.
    ///
    /// * Local time reasons are the explicit nonfatal result `TimeDeferred`; the latch is not
    ///   consulted or changed.
    /// * A request conflict (the request contradicts the sole durable decision stored for its
    ///   slot) or a halted reducer is a genuine safety condition: it halts the actor and poisons
    ///   the voter, exactly as it did when the same check ran after the latch. The latch and the
    ///   poison are in memory: nothing is written and no counter value is used. A request
    ///   conflict's only cause is the request, so a reopen resumes the intact stored decision; a
    ///   halted reducer's cause is the durable `LockState.halted` bit, which a reopen finds again
    ///   (Architect decision V1).
    /// * Anything else (a proposal that is not re-executed yet, a malformed request) touched
    ///   nothing and stays recoverable.
    fn refusal(&mut self, e: CounterVoterError) -> ActorError {
        use crate::{bft::BftError, vote_clock_v1::TimeStatus, votes::IngressError};
        match e {
            CounterVoterError::Ingress(IngressError::FutureTimestamp { ahead_seconds }) => {
                ActorError::TimeDeferred(TimeStatus::Future { ahead_seconds })
            }
            CounterVoterError::Ingress(IngressError::ClockUnqualified) => {
                ActorError::TimeDeferred(TimeStatus::Unqualified)
            }
            CounterVoterError::ConflictingVote
            | CounterVoterError::Ingress(IngressError::Bft(BftError::IntegrityHalt)) => {
                self.halted = true;
                self.voter.poison();
                ActorError::Voter(e)
            }
            e => ActorError::Voter(e),
        }
    }
    pub fn replay(
        &mut self,
        chain: &mut CanonicalStore,
        step: Step,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<Option<Vote>> {
        // Rejects an already-halted actor first, so everything below starts with the latch clear.
        self.check_backend(chain, backend)?;
        // A legacy UNMARKED unsigned reservation needs a qualified, eligible clock to complete. That
        // verdict is taken here, BEFORE the latch, from one reading that `replay_at` reuses: a
        // refusal for time is an explicit nonfatal result, so the latch is never set for it and
        // never has to be cleared again.
        let reading = self.voter.clock_reading();
        if let Err(e) = self.voter.replay_gate_at(&reading, step) {
            return Err(self.refusal(e));
        }
        self.halted = true;
        let vote = self.voter.replay_at(&reading, step, backend)?;
        if let Some(vote) = &vote {
            self.arm_precommit(step, vote);
        }
        self.halted = false;
        Ok(vote)
    }
    pub fn check_backend(
        &mut self,
        chain: &mut CanonicalStore,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<()> {
        if self.halted
            || chain.integrity_halted()?
            || chain.load_effective()?.0.height.checked_add(1) != Some(self.height())
        {
            self.halted = true;
            return Err(ActorError::Halted);
        }
        self.halted = true;
        let (tip, _) = chain.load_effective()?;
        let (parent, state) = chain.execution_parent(tip.height)?;
        if !self.voter.matches_authority(&authority(&parent, &state)?) {
            return Err(ActorError::Rollback);
        }
        self.voter.check_backend(backend)?;
        self.halted = false;
        Ok(())
    }
    /// No peer supplies old authority. Every replayed block is loaded from the
    /// durable canonical store and fully revalidated against its historical state.
    pub fn reconcile(
        &mut self,
        chain: &mut CanonicalStore,
        backend: &mut impl CounterSigningBackend,
        physical: &BTreeMap<Hash, PhysicalMember>,
        verifier: &impl PhysicalAttestationVerifier,
    ) -> Result<()> {
        if self.halted || chain.integrity_halted()? {
            self.halted = true;
            return Err(ActorError::Halted);
        }
        self.halted = true;
        let (tip, _) = chain.load_effective()?;
        if self.voter.height() > tip.height.checked_add(1).ok_or(Error::Overflow)? {
            return Err(ActorError::Rollback);
        }
        while self.voter.height() <= tip.height {
            let height = self.voter.height();
            let raw = chain.block_bytes(height)?.ok_or(Error::WrongAnchor)?;
            let block = BlockEnvelope::decode(&raw)?;
            chain.commit_integrated(&block, physical, verifier)?;
            let (parent, state) = chain.execution_parent(height - 1)?;
            let history = chain.evidence_history(&block.body)?;
            let round = self.voter.round_mut()?;
            round.validate_proposal_with_history(
                &state,
                LicensedExecution {
                    parent: &parent,
                    header: &block.header,
                    authority: &block.authority,
                    signature: &block.authority_signature,
                    body: &block.body,
                },
                physical,
                verifier,
                &history,
            )?;
            for signer in &block.certificate.signers {
                round.observe(&Vote {
                    nil: false,
                    decision: block.certificate.decision.clone(),
                    node: signer.node,
                    key_version: signer.key_version,
                    signature: signer.signature,
                })?;
            }
            round.commit(block.certificate.decision.round, block.block_hash())?;
            let (parent, state) = chain.execution_parent(height)?;
            self.voter.advance(authority(&parent, &state)?, backend)?;
        }
        self.halted = false;
        Ok(())
    }
    pub fn validate_proposal(
        &mut self,
        chain: &mut CanonicalStore,
        block: &BlockEnvelope,
        physical: &BTreeMap<Hash, PhysicalMember>,
        verifier: &impl PhysicalAttestationVerifier,
    ) -> Result<()> {
        self.validate_candidate(
            chain,
            Proposal {
                header: &block.header,
                body: &block.body,
                authority: &block.authority,
                signature: &block.authority_signature,
            },
            physical,
            verifier,
        )
    }
    pub fn validate_candidate(
        &mut self,
        chain: &mut CanonicalStore,
        proposal: Proposal<'_>,
        physical: &BTreeMap<Hash, PhysicalMember>,
        verifier: &impl PhysicalAttestationVerifier,
    ) -> Result<()> {
        if self.halted || chain.integrity_halted()? {
            self.halted = true;
            return Err(ActorError::Halted);
        }
        let (tip, _) = chain.load_effective()?;
        if self.height() != tip.height.checked_add(1).ok_or(Error::Overflow)? {
            return Err(ActorError::Rollback);
        }
        let (parent, state) = chain.execution_parent(tip.height)?;
        let history = chain.evidence_history(proposal.body)?;
        self.voter.round_mut()?.validate_proposal_with_history(
            &state,
            LicensedExecution {
                parent: &parent,
                header: proposal.header,
                authority: proposal.authority,
                signature: proposal.signature,
                body: proposal.body,
            },
            physical,
            verifier,
            &history,
        )?;
        Ok(())
    }
    pub fn observe(&mut self, vote: &Vote) -> Result<()> {
        if self.halted {
            return Err(ActorError::Halted);
        }
        self.voter.round_mut()?.observe(vote)?;
        Ok(())
    }
    pub fn sign(
        &mut self,
        chain: &mut CanonicalStore,
        step: Step,
        block: Option<Hash>,
        pol_round: Option<u64>,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<Vote> {
        // Rejects an already-halted actor first, so everything below starts with the latch clear.
        self.check_backend(chain, backend)?;
        // A time deferral/abstention must not halt the actor: the pure pre-check runs BEFORE the
        // latch, from ONE clock reading that `sign_at` reuses, so no time verdict can arise after
        // custody was touched and nothing has to be cleared again.
        let reading = self.voter.clock_reading();
        if let Err(e) = self.voter.time_gate_with(&reading, step, block, pol_round) {
            return Err(self.refusal(e));
        }
        self.halted = true;
        let vote = self
            .voter
            .sign_at(&reading, step, block, pol_round, backend)?;
        self.arm_precommit(step, &vote);
        self.halted = false;
        Ok(vote)
    }
    /// `sign` for a request decided in `requested` (Architect decision V4). After the backend
    /// check (which refuses a halted actor), the request is compared with the actor's CURRENT
    /// context before anything else: a request decided for a round or height the actor has left,
    /// for example a vote that was deferred while the clock was unqualified and is presented again
    /// after the round timed out, is refused with the explicit, nonfatal `StaleContext`. It is never
    /// signed in the current round, never compared with the current round's stored decision (so it
    /// cannot be mistaken for a request conflict), and it reads no clock and touches no latch,
    /// poison, reducer, counter or record.
    pub fn sign_for(
        &mut self,
        chain: &mut CanonicalStore,
        requested: VoteContext,
        step: Step,
        block: Option<Hash>,
        pol_round: Option<u64>,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<Vote> {
        self.check_backend(chain, backend)?;
        let current = self.context()?;
        if current != requested {
            return Err(ActorError::StaleContext { requested, current });
        }
        self.sign(chain, step, block, pol_round, backend)
    }
    fn arm_precommit(&mut self, step: Step, vote: &Vote) {
        if step == Step::Precommit
            && self
                .precommit_deadline
                .as_ref()
                .is_none_or(|(h, r, _)| (*h, *r) != (vote.decision.height, vote.decision.round))
        {
            // Local scheduling only: 3, 6, 12, ... seconds, capped at 120.
            // Retransmitting the cached vote must not extend the deadline.
            let seconds = 3u64
                .saturating_mul(1u64 << vote.decision.round.min(6))
                .min(120);
            self.precommit_deadline = Some((
                vote.decision.height,
                vote.decision.round,
                self.monotonic_now() + Duration::from_secs(seconds),
            ));
        }
    }
    /// A deadline is established by a successfully persisted local precommit.
    /// Restart safely starts a fresh wait when that cached precommit is replayed.
    pub fn timeout_precommit(
        &mut self,
        chain: &mut CanonicalStore,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<Option<u64>> {
        if self.halted || chain.integrity_halted()? {
            self.halted = true;
            return Err(ActorError::Halted);
        }
        let Some((height, round, deadline)) = self.precommit_deadline else {
            return Ok(None);
        };
        if chain.load_effective()?.0.height.checked_add(1) != Some(self.height()) {
            self.halted = true;
            return Err(ActorError::Rollback);
        }
        if height != self.height() {
            self.precommit_deadline = None;
            return Ok(None);
        }
        if self.monotonic_now() < deadline {
            return Ok(None);
        }
        self.check_backend(chain, backend)?;
        if self.voter.round_mut()?.machine().state().round != round {
            self.precommit_deadline = None;
            return Ok(None);
        }
        let next = self.voter.timeout_precommit(backend)?;
        self.precommit_deadline = None;
        Ok(Some(next))
    }
}
