//! Local event-loop step for the existing counter-backed BFT actor.
//! Socket waits and message publication happen outside this serialized step.
use crate::{
    candidate_journal::CandidateJournal, proposer_cursor::ProposerCursor,
    round_proposal::RoundProposal, vote_journal::VoteJournal,
};
use mutiny_consensus_v8::{
    Error, Hash,
    bft::{BftError, Step},
    canonical_store::CanonicalStore,
    certificates::{Certificate, Signer},
    counter_voter::{CounterSigningBackend, CounterVoterError},
    freshness::{PhysicalAttestationVerifier, PhysicalMember},
    vote_clock_v1::TimeStatus,
    voter_actor::{self, ActorError, VoteContext, VoterActor},
    votes::{IngressError, Vote},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Debug) -> String {
    format!("Voter driver: {e:?}")
}
/// Ordinary round delay before this validator votes nil: 3 s * 2^round, capped at 120 s. The base
/// delay is also the budget that pairwise clock skew between honest nodes must stay inside.
pub(crate) const BASE_ROUND_DELAY_SECS: u64 = 3;
const MAX_ROUND_DELAY_SECS: u64 = 120;
pub(crate) fn round_delay(round: u64) -> Duration {
    Duration::from_secs(
        BASE_ROUND_DELAY_SECS
            .saturating_mul(1u64 << round.min(6))
            .min(MAX_ROUND_DELAY_SECS),
    )
}
/// Upper bound on full candidate executions (`validate_candidate`) in ONE tick. A burst or a restart
/// can leave up to the journal's 1,024 stored candidates unvalidated; each validation is a full
/// body execution, so an unbounded loop would hold the actor mutex for the whole backlog. The
/// blocks this tick would act on (proposal, recovered reservation) are validated first and count
/// against the cap; every other
/// candidate waits at most `ceil(1024 / 16) = 64` ticks (about 16 s at the 250 ms actor period).
/// Validation results are memoised per height, so a steady state costs nothing.
pub(crate) const MAX_VALIDATIONS_PER_TICK: usize = 16;
/// True when a candidate was refused by deterministic validity rules (or the round's bounded
/// proposal table): a verdict about THAT candidate, never about this node's custody or chain.
fn candidate_refused(e: &ActorError) -> bool {
    use mutiny_consensus_v8::votes::IngressError as I;
    matches!(
        e,
        ActorError::Invalid(_)
            | ActorError::Ingress(I::Invalid(_) | I::Execution(_) | I::Capacity)
            | ActorError::Voter(CounterVoterError::Ingress(
                I::Invalid(_) | I::Execution(_) | I::Capacity
            ))
    )
}
/// The time status carried by a vote withheld for local time reasons (never a fault). Only the
/// actor's explicit `TimeDeferred` result counts: it is raised before the halting latch and leaves
/// the actor exactly as it was. Every other error, including a halted actor, is a fault.
fn defer_status(e: &ActorError) -> Option<TimeStatus> {
    e.time_deferral()
}
/// True when a prevote for a proposal was refused because the proof of lock the proposal names is
/// not verified in this validator's own authenticated vote table (its votes have not reached this
/// node, or do not exist). The pure pre-check raised it and touched nothing: a verdict that the
/// proposal is not votable NOW, never a fault (Architect decision V3).
fn stale_context(e: &ActorError) -> bool {
    matches!(e, ActorError::StaleContext { .. })
}
fn unverified_proof(e: &ActorError) -> bool {
    matches!(
        e,
        ActorError::Voter(CounterVoterError::Ingress(IngressError::Bft(
            BftError::InvalidProof
        )))
    )
}
/// The propose-timeout prevote (Architect decision V4). An unlocked validator signs nil. A LOCKED
/// validator's request is a vote for its locked block in a new (round, step) slot, i.e. a FRESH
/// block vote: while local time defers it, this validator WITHHOLDS its prevote. It does not sign
/// nil instead (that would escape its lock) and its lock is untouched (the time pre-check runs
/// before the reducer). `None` tells the caller that the prevote step was taken without a vote, so
/// the round's precommit step and precommit timeout still proceed.
fn timeout_prevote(
    chain: &mut CanonicalStore,
    actor: &mut VoterActor,
    backend: &mut impl CounterSigningBackend,
    context: VoteContext,
    result: &mut Tick,
) -> Result<Option<Vote>> {
    match actor.sign_for(chain, context, Step::Prevote, None, None, backend) {
        Ok(vote) => Ok(Some(vote)),
        Err(e) => match defer_status(&e) {
            Some(status) => {
                result.time_deferred = Some(status);
                result.prevote_withheld = true;
                Ok(None)
            }
            // The actor left the context this tick decided in: nothing was signed, and the next
            // tick re-derives everything (independent review MINOR-2). Not a fault.
            None if stale_context(&e) => {
                result.stale_context = true;
                Ok(None)
            }
            None => Err(err(e)),
        },
    }
}
#[derive(Default)]
pub struct Driver {
    cursor: ProposerCursor,
    context: Option<(u64, u64)>,
    started: Option<Instant>,
    prevote_started: Option<Instant>,
    validated: BTreeSet<Hash>,
    /// Current-height candidates that failed validation. They are skipped, never voted, and kept
    /// in the journal untouched; cleared with `validated` when the height changes.
    refused: BTreeSet<Hash>,
    #[cfg(test)]
    test_round_delay: Option<Duration>,
    #[cfg(test)]
    test_time: Option<std::sync::Arc<std::sync::Mutex<Instant>>>,
}
#[derive(Default)]
pub struct Tick {
    pub publish: Vec<Vote>,
    pub finalized: Option<Hash>,
    pub advanced_round: Option<u64>,
    pub equivocation_observations: usize,
    /// Set when a block vote was withheld this tick for local time reasons (the proposal is ahead
    /// of the qualified clock, or no qualified clock exists). Nothing blocks: the round keeps its
    /// ordinary timeouts and the next tick re-evaluates from current state.
    pub time_deferred: Option<TimeStatus>,
    /// Set when this validator took the current round's prevote step WITHOUT a prevote: its
    /// propose-timeout prevote would be a fresh block vote for its locked block and local time
    /// defers it (Architect decision V4). No nil vote replaces it; the precommit step, the precommit
    /// timeout and round progress proceed. Also set on later ticks of that round, after its
    /// precommit step: the passed prevote step is never signed afterwards.
    pub prevote_withheld: bool,
    /// Set when the actor refused a signature because it had left the (height, round) this tick
    /// derived (`ActorError::StaleContext`). Nonfatal: nothing was signed and the tick ends; the
    /// next tick re-derives its decisions. Defence in depth: within one tick the round cannot
    /// change before a signature, so the driver does not reach this today.
    pub stale_context: bool,
    /// Full candidate validations executed this tick (at most `MAX_VALIDATIONS_PER_TICK`).
    pub validations: usize,
    /// Current-height candidates still waiting for validation because the per-tick cap was reached.
    pub awaiting_validation: usize,
    /// Current-height candidates skipped because validation refused them (cumulative this height).
    pub refused_candidates: usize,
}
impl Driver {
    /// Test support only: replace the ordinary round delay (3 s * 2^round) with a fixed value so a
    /// controlled-time test is independent of how long slow debug-profile ticks take. The field
    /// and this setter do not exist in any non-test build, so production always uses the ordinary
    /// delay.
    #[cfg(test)]
    pub(crate) fn set_round_delay_for_test(&mut self, delay: Duration) {
        self.test_round_delay = Some(delay);
    }
    #[cfg(test)]
    pub(crate) fn set_time_for_test(&mut self, time: std::sync::Arc<std::sync::Mutex<Instant>>) {
        self.test_time = Some(time);
    }
    fn instant(&self) -> Instant {
        #[cfg(test)]
        if let Some(time) = &self.test_time { return *time.lock().unwrap(); }
        Instant::now()
    }
    pub fn tick<V: PhysicalAttestationVerifier>(
        &mut self,
        chain: &mut CanonicalStore,
        actor: &mut VoterActor,
        backend: &mut impl CounterSigningBackend,
        candidates: &CandidateJournal,
        received: &mut VoteJournal,
        proposal: Option<&RoundProposal>,
        physical: &BTreeMap<Hash, PhysicalMember>,
        verifier: &V,
    ) -> Result<Tick> {
        actor
            .reconcile(chain, backend, physical, verifier)
            .map_err(err)?;
        actor.check_backend(chain, backend).map_err(err)?;
        let (progress, prevote_intent, precommit_intent) = actor.progress().map_err(err)?;
        let context = (actor.height(), progress.round);
        // Every fresh signature of this tick is bound to the context derived here (Architect
        // decision V4): the actor refuses it once it has left this (height, round).
        let vote_context = VoteContext {
            height: context.0,
            round: context.1,
        };
        if self.context != Some(context) {
            if self.context.is_none_or(|c| c.0 != context.0) {
                self.validated.clear();
                self.refused.clear();
            }
            self.context = Some(context);
            self.started = Some(self.instant());
            self.prevote_started = None;
        }
        let delay = round_delay(progress.round);
        #[cfg(test)]
        let delay = self.test_round_delay.unwrap_or(delay);
        let records = candidates.records()?;
        let mut result = Tick::default();
        // The blocks this node would act on (the proposal, any block named by a durable
        // reservation it must recover, and its locked block, which its propose-timeout prevote
        // names) are validated first, so a flood of other candidates cannot delay them; the rest
        // follow in journal order.
        let priority: BTreeSet<Hash> = proposal
            .map(|p| p.block)
            .into_iter()
            .chain(prevote_intent.iter().map(|v| v.decision.block))
            .chain(precommit_intent.iter().map(|v| v.decision.block))
            .chain(progress.locked.iter().map(|l| l.block))
            .collect();
        let mut current: Vec<&crate::candidate_journal::CandidateRecord> = records
            .iter()
            .filter(|r| r.header.candidate.height == actor.height())
            .collect();
        current.sort_by_key(|r| !priority.contains(&r.header.block_hash()));
        let mut budget = MAX_VALIDATIONS_PER_TICK;
        for record in current {
            let block = record.header.block_hash();
            if self.validated.contains(&block) || self.refused.contains(&block) {
                continue;
            }
            if budget == 0 {
                result.awaiting_validation += 1;
                continue;
            }
            budget -= 1;
            result.validations += 1;
            let verdict = actor.validate_candidate(
                chain,
                voter_actor::Proposal {
                    header: &record.header,
                    body: &record.body,
                    authority: &record.authority,
                    signature: &record.signature,
                },
                physical,
                verifier,
            );
            match verdict {
                Ok(()) => {
                    self.validated.insert(block);
                }
                // One stored candidate that fails validation must not abort the tick (and with it
                // the node's retransmission, nil timeouts and finalization). It is never voted;
                // validation itself is unchanged. Chain, custody, halt and rollback failures stay
                // hard errors.
                Err(e) if candidate_refused(&e) => {
                    self.refused.insert(block);
                }
                Err(e) => return Err(err(e)),
            }
        }
        result.refused_candidates = self.refused.len();
        let (parent, state) = chain.execution_parent(actor.height() - 1).map_err(err)?;
        let authority = voter_actor::authority(&parent, &state).map_err(err)?;
        for vote in received.height(actor.height())? {
            let d = &vote.decision;
            if d.membership != authority.membership
                || d.reputation != authority.reputation
                || d.attestation != authority.attestation
                || d.previous_finalized_anchor != authority.parent.id()
            {
                continue;
            }
            match actor.observe(&vote) {
                Ok(()) => (),
                Err(ActorError::Ingress(IngressError::Bft(BftError::Equivocation))) => {
                    result.equivocation_observations += 1
                }
                Err(e) => return Err(err(e)),
            }
        }
        if let Some(block) = received.finalize_ready(chain, &records, physical, verifier)? {
            actor
                .reconcile(chain, backend, physical, verifier)
                .map_err(err)?;
            result.finalized = Some(block.block_hash());
            return Ok(result);
        }
        // Zero-weight admitted participants may maintain custody and ACK/quote
        // freshness, but must not request even a nil BFT signature.
        if authority
            .voters
            .get(&actor.node())
            .is_none_or(|v| v.weight.is_zero())
        {
            return Ok(result);
        }
        // The prevote step: `Some(vote)` to publish, or `None` when this validator takes the step
        // without a prevote (decision V4) and still continues to the precommit step.
        let prevote = if prevote_intent.is_some() {
            // Completing / retransmitting the exact stored decision. It can never create a new
            // vote: a legacy UNMARKED unsigned reservation still needs a qualified, eligible clock
            // and is then DEFERRED (nothing signed) rather than failing the tick.
            match actor.replay(chain, Step::Prevote, backend) {
                Ok(v) => Some(v.ok_or("Missing persisted prevote")?),
                Err(e) => {
                    if let Some(s) = defer_status(&e) {
                        result.time_deferred = Some(s);
                        return Ok(result);
                    }
                    return Err(err(e));
                }
            }
        } else if precommit_intent.is_some() {
            // This validator already took the precommit step of this round after withholding its
            // prevote: the prevote step has passed, and nothing is signed for it afterwards,
            // whatever the clock says now (decision V4: clock recovery revalidates the current
            // context instead of signing for a step or round that has passed).
            result.prevote_withheld = true;
            None
        } else if let Some(proposal) = proposal {
            let Some(selected) = self.cursor.selected(chain, progress.round)? else {
                return Ok(result);
            };
            proposal.verify_current(chain, selected)?;
            if !self.validated.contains(&proposal.block) {
                return Ok(result);
            }
            // Everything above is re-derived from current chain state on every tick, so a block
            // that was deferred for its timestamp is revalidated (height, round, parent,
            // membership, lock) before it can ever be voted: a due timer authorizes nothing.
            let status = actor.time_status(proposal.block);
            let voted = if status.is_eligible() {
                match actor.sign_for(
                    chain,
                    vote_context,
                    Step::Prevote,
                    Some(proposal.block),
                    proposal.pol_round,
                    backend,
                ) {
                    Ok(v) => Some(v),
                    Err(e) => {
                        // Withheld for local time reasons only: defer without a fault.
                        if let Some(s) = defer_status(&e) {
                            result.time_deferred = Some(s);
                            return Ok(result);
                        }
                        // A proof of lock this validator has not verified makes the proposal
                        // unvotable for now, not a fault (decision V3): its round timeouts
                        // proceed exactly as for a missing proposal.
                        if stale_context(&e) {
                            result.stale_context = true;
                            return Ok(result);
                        }
                        if !unverified_proof(&e) {
                            return Err(err(e));
                        }
                        None
                    }
                }
            } else {
                // Defer without blocking. Round timeouts proceed exactly as for a missing
                // proposal: after the ordinary delay this validator prevotes nil, or, holding a
                // lock, withholds its prevote (decision V4).
                result.time_deferred = Some(status);
                None
            };
            match voted {
                Some(vote) => Some(vote),
                None if self.instant().saturating_duration_since(self.started.unwrap()) >= delay => {
                    timeout_prevote(chain, actor, backend, vote_context, &mut result)?
                }
                None => return Ok(result),
            }
        } else if self.instant().saturating_duration_since(self.started.unwrap()) >= delay {
            timeout_prevote(chain, actor, backend, vote_context, &mut result)?
        } else {
            return Ok(result);
        };
        if result.stale_context {
            return Ok(result);
        }
        if let Some(prevote) = prevote {
            let selected = records
                .iter()
                .find(|p| p.header.block_hash() == prevote.decision.block);
            received.admit(chain, &prevote, selected, physical, verifier)?;
            actor.observe(&prevote).map_err(err)?;
            result.publish.push(prevote);
        }
        // The prevote step was taken, with a vote or withheld: the precommit step's timer runs.
        let instant = self.instant();
        self.prevote_started.get_or_insert(instant);

        // Quorum candidates come only from authenticated durable ingress.
        // The signing reducer independently checks the same quorum/lock again.
        let mut groups: BTreeMap<Hash, BTreeMap<Hash, Vote>> = BTreeMap::new();
        for vote in received.height(actor.height())? {
            let d = &vote.decision;
            if !vote.nil
                && d.round == progress.round
                && d.step == 2
                && d.membership == authority.membership
                && d.reputation == authority.reputation
                && d.attestation == authority.attestation
                && d.previous_finalized_anchor == authority.parent.id()
            {
                groups
                    .entry(d.id())
                    .or_default()
                    .entry(vote.node)
                    .or_insert(vote);
            }
        }
        let mut quorum = None;
        for group in groups.into_values() {
            let decision = group.values().next().unwrap().decision.clone();
            let cert = Certificate {
                decision: decision.clone(),
                signers: group
                    .into_values()
                    .map(|v| Signer {
                        node: v.node,
                        key_version: v.key_version,
                        signature: v.signature,
                    })
                    .collect(),
            };
            match cert.verify_quorum(&decision, &authority.voters) {
                Ok(()) => {
                    quorum = Some(decision.block);
                    break;
                }
                Err(Error::NoQuorum) => (),
                Err(e) => return Err(err(e)),
            }
        }
        // A prevote quorum for a block this validator may not yet vote for (timestamp ahead of its
        // qualified clock, or no qualified clock) cannot be precommitted; it waits for the ordinary
        // delay and then precommits nil. Its weight stays in the denominator either way.
        let quorum_status = quorum.map(|b| (b, actor.time_status(b)));
        let quorum = match quorum_status {
            Some((b, s)) if s.is_eligible() => Some(b),
            Some((_, s)) => {
                result.time_deferred = Some(s);
                None
            }
            None => None,
        };
        let quorum_withheld = quorum_status.is_some() && quorum.is_none();
        let precommit = if precommit_intent.is_some() {
            match actor.replay(chain, Step::Precommit, backend) {
                Ok(v) => v.ok_or("Missing persisted precommit")?,
                Err(e) => {
                    if let Some(s) = defer_status(&e) {
                        result.time_deferred = Some(s);
                        return Ok(result);
                    }
                    return Err(err(e));
                }
            }
        } else if (quorum.is_some() && !quorum_withheld)
            || self.instant().saturating_duration_since(self.prevote_started.unwrap()) >= delay
        {
            match actor.sign_for(chain, vote_context, Step::Precommit, quorum, None, backend) {
                Ok(v) => v,
                Err(e) => {
                    // Withheld for local time reasons only: defer without a fault.
                    if let Some(s) = defer_status(&e) {
                        result.time_deferred = Some(s);
                        return Ok(result);
                    }
                    if stale_context(&e) {
                        result.stale_context = true;
                        return Ok(result);
                    }
                    return Err(err(e));
                }
            }
        } else {
            return Ok(result);
        };
        let selected = records
            .iter()
            .find(|p| p.header.block_hash() == precommit.decision.block);
        received.admit(chain, &precommit, selected, physical, verifier)?;
        actor.observe(&precommit).map_err(err)?;
        result.publish.push(precommit);
        if let Some(block) = received.finalize_ready(chain, &records, physical, verifier)? {
            actor
                .reconcile(chain, backend, physical, verifier)
                .map_err(err)?;
            result.finalized = Some(block.block_hash());
        } else {
            match actor.timeout_precommit(chain, backend) {
                Ok(next) => result.advanced_round = next,
                Err(ActorError::Voter(CounterVoterError::Ingress(IngressError::Bft(
                    BftError::NoQuorum,
                )))) => (),
                Err(e) => return Err(err(e)),
            }
        }
        Ok(result)
    }
}
