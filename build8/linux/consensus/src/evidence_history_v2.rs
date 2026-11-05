//! Historical evidence contexts are distinct from live voting authority.
//! A recovered height retains both its original parent authority and the exact
//! accepted replacement context. Registries/weights are never merged.
use crate::{
    Error, Hash, Result, anchors::FinalizedAnchor, penalties_v2::Settlement, votes_v2::HeightAuthority,
};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Default)]
pub struct History {
    canonical: BTreeMap<u64, HeightAuthority>,
    recovered: BTreeMap<u64, HeightAuthority>,
    /// Canonical block hash of every height an operation envelope of the block references
    /// (P-LANE-DESIGN-V1 1.a.3). Supplied only by the local canonical store.
    anchors: BTreeMap<u64, Hash>,
}
impl FromIterator<(u64, HeightAuthority)> for History {
    fn from_iter<T: IntoIterator<Item = (u64, HeightAuthority)>>(items: T) -> Self {
        Self {
            canonical: items.into_iter().collect(),
            recovered: BTreeMap::new(),
            anchors: BTreeMap::new(),
        }
    }
}
impl History {
    pub fn canonical_entries(&self) -> impl Iterator<Item = (&u64, &HeightAuthority)> {
        self.canonical.iter()
    }
    pub fn contains_key(&self, height: &u64) -> bool {
        self.canonical.contains_key(height)
    }
    pub fn insert(&mut self, height: u64, authority: HeightAuthority) -> Option<HeightAuthority> {
        // Replacing the base context cannot retain a previously attached overlay.
        self.recovered.remove(&height);
        self.canonical.insert(height, authority)
    }
    pub(crate) fn attach_recovery(
        &mut self,
        height: u64,
        proof: &crate::recovery_transition_v2::Prepared,
    ) -> Result<()> {
        let canonical = self.canonical.get(&height).ok_or(Error::WrongAnchor)?;
        if canonical.parent != *proof.parent()
            || canonical.parent.height.checked_add(1) != Some(height)
        {
            return Err(Error::WrongAnchor);
        }
        if self.recovered.contains_key(&height) {
            return Err(Error::Duplicate);
        }
        self.recovered.insert(height, proof.authority()?);
        Ok(())
    }
    /// Records the canonical block hash of `height` for operation-envelope reference checks
    /// (`op_envelope_v1::Envelope::check_inclusion`). A second, different hash for the same
    /// height is `Error::Duplicate`; the same hash again changes nothing.
    pub fn insert_anchor(&mut self, height: u64, block: Hash) -> Result<()> {
        match self.anchors.get(&height) {
            Some(existing) if *existing != block => Err(Error::Duplicate),
            Some(_) => Ok(()),
            None => {
                self.anchors.insert(height, block);
                Ok(())
            }
        }
    }
    /// The canonical block hash recorded for `height`, if any.
    pub fn anchor(&self, height: u64) -> Option<Hash> {
        self.anchors.get(&height).copied()
    }
    pub fn settlement(
        &self,
        evidence: &crate::equivocation_v2::Evidence,
        inclusion: &FinalizedAnchor,
    ) -> Result<Settlement> {
        let height = evidence.a.decision.height;
        let canonical = self.canonical.get(&height).ok_or(Error::WrongAnchor)?;
        if canonical.parent.height.checked_add(1) != Some(height) {
            return Err(Error::WrongAnchor);
        }
        let roots = [
            evidence.a.decision.membership,
            evidence.a.decision.reputation,
            evidence.a.decision.attestation,
        ];
        let authority = if canonical.roots() == roots {
            canonical
        } else {
            self.recovered
                .get(&height)
                .filter(|a| a.parent == canonical.parent && a.roots() == roots)
                .ok_or(Error::WrongAnchor)?
        };
        // Both complete votes must validate against this single context. A peer
        // cannot combine an old membership root with new keys or weights.
        Settlement::new(
            evidence,
            inclusion,
            &crate::equivocation_v2::HistoricalAuthority {
                parent: &authority.parent,
                roots: authority.roots(),
                registry: &authority.voters,
            },
        )
    }
}
