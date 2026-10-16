//! Bounded reconstruction of the existing canonical weighted proposer schedule.
//! Certificate round/signer representation never enters this cache.
use mutiny_consensus_v8::{
    Hash,
    canonical_store::CanonicalStore,
    proposer::{ProposerSchedule, RoundSchedule},
};
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Debug) -> String {
    format!("Proposer cursor: {e:?}")
}
const MAX_STEPS: usize = 32;
pub struct ProposerCursor {
    height: Option<u64>,
    effective_root: Option<Hash>,
    schedule: Option<ProposerSchedule>,
    rounds: Option<RoundSchedule>,
}
impl Default for ProposerCursor {
    fn default() -> Self {
        Self {
            height: None,
            effective_root: None,
            schedule: None,
            rounds: None,
        }
    }
}
impl ProposerCursor {
    /// Returns None while bounded reconstruction is in progress. A caller must
    /// not sign or invent a proposer while this derived cache is incomplete.
    /// `round` is the locally persisted voter round, never a peer request.
    pub fn selected(
        &mut self,
        chain: &mut CanonicalStore,
        round: u64,
    ) -> Result<Option<(u64, Hash)>> {
        if chain.integrity_halted().map_err(err)? {
            return Err("Canonical integrity halt".into());
        }
        let (tip, state) = chain.load_effective().map_err(err)?;
        let effective_root = state.root().map_err(err)?;
        if self.height.is_some_and(|h| h > tip.height) {
            return Err("Canonical height rollback".into());
        }
        if self.height == Some(tip.height) && self.effective_root != Some(effective_root) {
            // Authenticated recovery changes effective authority at the same
            // anchor. Rebuild; never reuse the old generation's proposer cache.
            *self = Self::default();
        }
        let mut steps = 0;
        if self.schedule.is_none() {
            let (_, genesis) = chain.execution_parent(0).map_err(err)?;
            let registry = genesis
                .continuity
                .as_ref()
                .ok_or("Missing Genesis voter registry")?;
            let weights = registry
                .voters()
                .map_err(err)?
                .into_iter()
                .map(|(n, v)| (n, v.weight))
                .collect();
            self.schedule = Some(ProposerSchedule::genesis(&weights).map_err(err)?);
            self.height = Some(0);
            self.effective_root = Some(genesis.root().map_err(err)?);
            self.rounds = None;
            steps += 1;
        }
        while self.height.unwrap() < tip.height && steps < MAX_STEPS {
            let height = self
                .height
                .unwrap()
                .checked_add(1)
                .ok_or("Height exhausted")?;
            let (_, state) = chain.execution_parent(height).map_err(err)?;
            let registry = state
                .continuity
                .as_ref()
                .ok_or("Missing canonical voter registry")?;
            let weights = registry
                .voters()
                .map_err(err)?
                .into_iter()
                .map(|(n, v)| (n, v.weight))
                .collect();
            let next = self
                .schedule
                .as_ref()
                .unwrap()
                .next_height(&weights)
                .map_err(err)?;
            self.schedule = Some(next);
            self.height = Some(height);
            self.effective_root = Some(state.root().map_err(err)?);
            self.rounds = None;
            steps += 1;
        }
        if self.height != Some(tip.height) {
            return Ok(None);
        }
        let rounds = self
            .rounds
            .get_or_insert_with(|| self.schedule.as_ref().unwrap().rounds());
        if rounds.current().is_some_and(|(r, _)| r > round) {
            return Err("Local round rollback".into());
        }
        while rounds.current().is_none_or(|(r, _)| r < round) && steps < MAX_STEPS {
            rounds.advance().map_err(err)?;
            steps += 1;
        }
        Ok(rounds.current().filter(|(r, _)| *r == round))
    }
}
