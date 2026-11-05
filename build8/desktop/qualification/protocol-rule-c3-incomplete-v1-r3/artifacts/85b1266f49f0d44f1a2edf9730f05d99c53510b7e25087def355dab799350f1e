//! Deterministic round/lock reducer. Its caller MUST authenticate votes against
//! the committed registry and validate proposed blocks before feeding events.
//! No network deserializer may construct trusted reducer inputs directly.
use crate::Hash;
use primitive_types::U256;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    Prevote,
    Precommit,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BftError {
    UnknownVoter,
    Overflow,
    Equivocation,
    NoQuorum,
    StaleRound,
    InvalidProof,
    IntegrityHalt,
    AlreadyFinalized,
    Capacity,
}
type Result<T> = std::result::Result<T, BftError>;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Observation {
    Added,
    Duplicate,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lock {
    pub round: u64,
    pub block: Hash,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockState {
    pub round: u64,
    pub locked: Option<Lock>,
    pub finalized: Option<Hash>,
    pub halted: bool,
}
pub struct RoundMachine {
    state: LockState,
    weights: BTreeMap<Hash, U256>,
    total: U256,
    votes: BTreeMap<(u64, Step, Hash), Option<Hash>>,
}
impl RoundMachine {
    /// Weights include offline voters; zero-weight cloud peers cannot vote.
    pub fn new(weights: BTreeMap<Hash, U256>) -> Result<Self> {
        let total = weights.values().try_fold(U256::zero(), |a, b| {
            a.checked_add(*b).ok_or(BftError::Overflow)
        })?;
        if total.is_zero() {
            return Err(BftError::NoQuorum);
        }
        total.checked_mul(U256::from(3)).ok_or(BftError::Overflow)?;
        Ok(Self {
            state: LockState {
                round: 0,
                locked: None,
                finalized: None,
                halted: false,
            },
            weights,
            total,
            votes: BTreeMap::new(),
        })
    }
    pub fn state(&self) -> &LockState {
        &self.state
    }
    /// Restart restores the DURABLY stored lock. Votes must be reverified/replayed.
    pub fn restore(weights: BTreeMap<Hash, U256>, state: LockState) -> Result<Self> {
        if state.locked.as_ref().is_some_and(|l| l.round > state.round) {
            return Err(BftError::InvalidProof);
        }
        let mut m = Self::new(weights)?;
        m.state = state;
        Ok(m)
    }
    pub fn observe_authenticated(
        &mut self,
        round: u64,
        step: Step,
        voter: Hash,
        block: Option<Hash>,
    ) -> Result<Observation> {
        if self.state.halted {
            return Err(BftError::IntegrityHalt);
        }
        if self.weights.get(&voter).is_none_or(U256::is_zero) {
            return Err(BftError::UnknownVoter);
        }
        let key = (round, step, voter);
        if let Some(old) = self.votes.get(&key) {
            return if *old == block {
                Ok(Observation::Duplicate)
            } else {
                Err(BftError::Equivocation)
            };
        }
        // Local backpressure, not proof of an invalid vote or a reason to shrink
        // quorum. Runtime archival/replay must preserve authenticated evidence.
        if self.votes.len() >= 100_000 {
            return Err(BftError::Capacity);
        }
        self.votes.insert(key, block);
        Ok(Observation::Added)
    }
    fn quorum(&self, round: u64, step: Step, selection: Option<Option<Hash>>) -> Result<bool> {
        let mut sum = U256::zero();
        for ((r, s, node), block) in &self.votes {
            if *r == round && *s == step && selection.is_none_or(|v| v == *block) {
                sum = sum
                    .checked_add(self.weights[node])
                    .ok_or(BftError::Overflow)?;
            }
        }
        Ok(sum.checked_mul(U256::from(3)).ok_or(BftError::Overflow)?
            > self
                .total
                .checked_mul(U256::from(2))
                .ok_or(BftError::Overflow)?)
    }
    pub fn enter_round(&mut self, round: u64) -> Result<()> {
        if self.state.finalized.is_some() {
            return Err(BftError::AlreadyFinalized);
        }
        if self.state.halted {
            return Err(BftError::IntegrityHalt);
        }
        if round < self.state.round {
            return Err(BftError::StaleRound);
        }
        self.state.round = round;
        Ok(())
    }
    /// Proposal was independently validated. A supplied PoLC must be present in
    /// authenticated prevotes, newer than the lock and older than current round.
    /// Pure plan shared by `prevote` and `preview_prevote`: (unlock?, block that would be voted).
    fn prevote_plan(
        &self,
        proposal: Option<Hash>,
        pol_round: Option<u64>,
    ) -> Result<(bool, Option<Hash>)> {
        if self.state.finalized.is_some() {
            return Err(BftError::AlreadyFinalized);
        }
        if self.state.halted {
            return Err(BftError::IntegrityHalt);
        }
        let mut unlock = false;
        if let Some(r) = pol_round {
            let b = proposal.ok_or(BftError::InvalidProof)?;
            if r >= self.state.round || !self.quorum(r, Step::Prevote, Some(Some(b)))? {
                return Err(BftError::InvalidProof);
            }
            unlock = self
                .state
                .locked
                .as_ref()
                .is_some_and(|l| r > l.round && l.block != b);
        }
        let locked = if unlock { None } else { self.state.locked.as_ref() };
        Ok((unlock, locked.map(|l| l.block).or(proposal)))
    }
    pub fn prevote(
        &mut self,
        proposal: Option<Hash>,
        pol_round: Option<u64>,
    ) -> Result<Option<Hash>> {
        let (unlock, block) = self.prevote_plan(proposal, pol_round)?;
        if unlock {
            self.state.locked = None;
        }
        Ok(block)
    }
    /// The block `prevote` WOULD return, without mutating anything. A local policy gate (the vote
    /// time guard) must judge this block, not the caller's `proposal` argument: a validator that
    /// holds a lock votes its locked block even when called with no proposal.
    pub fn preview_prevote(
        &self,
        proposal: Option<Hash>,
        pol_round: Option<u64>,
    ) -> Result<Option<Hash>> {
        Ok(self.prevote_plan(proposal, pol_round)?.1)
    }
    /// The block `precommit` WOULD return, without mutating anything.
    pub fn preview_precommit(&self, block: Option<Hash>) -> Result<Option<Hash>> {
        if self.state.finalized.is_some() {
            return Err(BftError::AlreadyFinalized);
        }
        if self.state.halted {
            return Err(BftError::IntegrityHalt);
        }
        if !self.quorum(self.state.round, Step::Prevote, Some(block))? {
            return Ok(None);
        }
        Ok(block)
    }
    /// The new lock MUST be durably persisted before signing the returned vote.
    pub fn precommit(&mut self, block: Option<Hash>) -> Result<Option<Hash>> {
        if self.state.finalized.is_some() {
            return Err(BftError::AlreadyFinalized);
        }
        if self.state.halted {
            return Err(BftError::IntegrityHalt);
        }
        if !self.quorum(self.state.round, Step::Prevote, Some(block))? {
            // Timeout without a PoLC keeps the old lock; a nil vote does not unlock.
            return Ok(None);
        }
        self.state.locked = block.map(|block| Lock {
            round: self.state.round,
            block,
        });
        Ok(block)
    }
    /// Called only after the round's timeout actually elapsed. ANY precommit
    /// quorum is necessary; lack of peers never shrinks the denominator.
    pub fn timeout_precommit(&mut self) -> Result<u64> {
        if self.state.finalized.is_some() {
            return Err(BftError::AlreadyFinalized);
        }
        if self.state.halted {
            return Err(BftError::IntegrityHalt);
        }
        if !self.quorum(self.state.round, Step::Precommit, None)? {
            return Err(BftError::NoQuorum);
        }
        let next = self.state.round.checked_add(1).ok_or(BftError::Overflow)?;
        self.state.round = next;
        Ok(next)
    }
    /// Can consume delayed proof from an earlier round. Same block is idempotent;
    /// conflicting certified blocks halt rather than choosing a round.
    pub fn commit(&mut self, round: u64, block: Hash) -> Result<bool> {
        if self.state.halted {
            return Err(BftError::IntegrityHalt);
        }
        if !self.quorum(round, Step::Precommit, Some(Some(block)))? {
            return Err(BftError::NoQuorum);
        }
        if let Some(old) = self.state.finalized {
            if old == block {
                return Ok(false);
            }
            self.state.halted = true;
            return Err(BftError::IntegrityHalt);
        }
        self.state.finalized = Some(block);
        Ok(true)
    }
}
