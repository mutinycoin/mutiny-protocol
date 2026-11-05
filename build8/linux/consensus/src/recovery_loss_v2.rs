//! Pure candidate preflight. Loss is a supervised declaration, never inferred
//! from silence. This returns no installable admission or recovery token.
use crate::{
    Error, Hash, Result, anchors::FinalizedAnchor, execution::State, recovery::loss_commitment,
    reputation::quorum, votes_v2::HeightAuthority,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Assessment {
    pub membership: Hash,
    pub declaration: Hash,
    pub node: Hash,
    pub hardware_generation: u64,
    pub key_generation: u64,
}
pub fn preflight(
    state: &State,
    parent: &FinalizedAnchor,
    root: Hash,
    sequence: u64,
    lineage: Hash,
    lost: &[(Hash, u64)],
    existing_valid_descendant: bool,
) -> Result<Assessment> {
    // The enclosing durable canonical store must supply this fact while holding
    // the same transaction/lock used for prospective recovery acceptance.
    if existing_valid_descendant {
        return Err(Error::ExistingFinality);
    }
    let registry = state.continuity.as_ref().ok_or(Error::UnknownSigner)?;
    if !registry.recovery_enabled() {
        return Err(Error::RecoveryDisabled);
    }
    let recovery = state
        .recovery_authority_v2
        .as_ref()
        .ok_or(Error::RecoveryDisabled)?;
    parent.validate_context(recovery.genesis, recovery.fingerprint)?;
    if registry.sequence().checked_add(1).ok_or(Error::Overflow)? != sequence {
        return Err(Error::StaleSequence);
    }
    let declaration = loss_commitment(lost)?;
    let authority =
        HeightAuthority::from_state(state, parent.clone(), root).map_err(|_| Error::WrongAnchor)?;
    let member = registry
        .members
        .iter()
        .find(|m| m.lineage == lineage)
        .ok_or(Error::InvalidLineage)?;
    if !lost.contains(&(lineage, member.generation)) {
        return Err(Error::WrongGeneration);
    }
    let control = state
        .membership_v2
        .get(member.node)
        .ok_or(Error::UnknownSigner)?;
    if !member.physical
        || !member.eligible
        || control.exit_boundary().is_some()
        || state.penalties.revoked(lineage)
        || state.penalties_v2.revoked(lineage)
    {
        return Err(Error::UnqualifiedPhysical);
    }
    for &(lost_lineage, generation) in lost {
        let matched = registry
            .members
            .iter()
            .find(|m| m.lineage == lost_lineage && m.generation == generation)
            .ok_or(Error::WrongGeneration)?;
        let voter = authority
            .voters
            .get(&matched.node)
            .ok_or(Error::UnqualifiedPhysical)?;
        if !voter.admitted || !voter.physical || !voter.eligible || voter.revoked {
            return Err(Error::UnqualifiedPhysical);
        }
    }
    // Keep the ORIGINAL denominator. Removing lost weights before testing the
    // threshold would manufacture quorum and invalidate the recovery decision.
    let weights = authority
        .voters
        .values()
        .map(|v| v.weight())
        .collect::<Result<Vec<_>>>()?;
    let survivors = authority
        .voters
        .values()
        .enumerate()
        .filter(|(_, v)| !lost.contains(&(v.lineage, v.hardware_generation)))
        .map(|(i, _)| i)
        .collect::<Vec<_>>();
    if quorum(&weights, &survivors)? {
        return Err(Error::NormalQuorumAvailable);
    }
    let current = authority
        .voters
        .get(&member.node)
        .ok_or(Error::UnknownSigner)?;
    Ok(Assessment {
        membership: authority.membership,
        declaration,
        node: member.node,
        hardware_generation: member.generation,
        key_generation: current.key_generation,
    })
}
