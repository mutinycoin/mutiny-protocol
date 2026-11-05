//! Certificate construction from fully authenticated votes and executed proposals.
//! This collector has no signing key, lock authority, or configurable quorum.
use crate::candidate_journal::CandidateRecord;
use mutiny_consensus_v8::{
    Error, Hash,
    block_envelope::BlockEnvelope,
    canonical_store::CanonicalStore,
    certificates::{Certificate, Signer},
    execution::LicensedExecution,
    freshness::{PhysicalAttestationVerifier, PhysicalMember},
    voter_actor,
    votes::{AuthenticatedRound, Vote},
};
use std::collections::BTreeMap;
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Debug) -> String {
    format!("Certificate assembly: {e:?}")
}

/// Reconstructs authority from canonical parent state on every call. The caller
/// persists and bounds ingress; this function never trusts an incoming registry.
/// A valid but insufficient signer set returns None, not a weaker certificate.
pub fn assemble<V: PhysicalAttestationVerifier>(
    chain: &mut CanonicalStore,
    proposal: &CandidateRecord,
    votes: &[Vote],
    physical: &BTreeMap<Hash, PhysicalMember>,
    verifier: &V,
) -> Result<Option<BlockEnvelope>> {
    if chain.integrity_halted().map_err(err)? {
        return Err("Canonical integrity halt".into());
    }
    if votes.len() > 1024 {
        return Err("Certificate signer bound".into());
    }
    let (tip, _) = chain.load_effective().map_err(err)?;
    if tip.height.checked_add(1) != Some(proposal.header.candidate.height)
        || tip.block != proposal.header.candidate.parent
    {
        return Err("Certificate proposal is not current".into());
    }
    let (parent, state) = chain.execution_parent(tip.height).map_err(err)?;
    let authority = voter_actor::authority(&parent, &state).map_err(err)?;
    let mut ingress = AuthenticatedRound::new(authority.clone()).map_err(err)?;
    let history = chain.evidence_history(&proposal.body).map_err(err)?;
    ingress
        .validate_proposal_with_history(
            &state,
            LicensedExecution {
                parent: &parent,
                header: &proposal.header,
                body: &proposal.body,
                authority: &proposal.authority,
                signature: &proposal.signature,
            },
            physical,
            verifier,
            &history,
        )
        .map_err(err)?;
    let mut signers = BTreeMap::new();
    let mut decision = None;
    for vote in votes {
        if vote.nil
            || vote.decision.step != 3
            || vote.decision.block != proposal.header.block_hash()
        {
            return Err("Certificate requires non-nil precommits for the exact candidate".into());
        }
        if decision.as_ref().is_some_and(|d| d != &vote.decision) {
            return Err("Certificate mixed decisions/rounds".into());
        }
        ingress.observe(vote).map_err(err)?;
        let signer = Signer {
            node: vote.node,
            key_version: vote.key_version,
            signature: vote.signature,
        };
        if let Some(old) = signers.insert(vote.node, signer.clone()) {
            if old != signer {
                return Err("Conflicting duplicate signer".into());
            }
        }
        decision = Some(vote.decision.clone());
    }
    let Some(decision) = decision else {
        return Ok(None);
    };
    let certificate = Certificate {
        decision: decision.clone(),
        signers: signers.into_values().collect(),
    };
    match certificate.verify_quorum(&decision, &authority.voters) {
        Ok(()) => (),
        Err(Error::NoQuorum) => return Ok(None),
        Err(e) => return Err(err(e)),
    }
    // Independently require the authenticated reducer's precommit threshold.
    ingress
        .commit(decision.round, decision.block)
        .map_err(err)?;
    Ok(Some(BlockEnvelope {
        header: proposal.header.clone(),
        body: proposal.body.clone(),
        authority: proposal.authority.clone(),
        authority_signature: proposal.signature,
        certificate,
    }))
}

/// The normal atomic store transition revalidates the entire block before
/// publishing finality. Callers advance voter custody only after this succeeds.
pub fn finalize<V: PhysicalAttestationVerifier>(
    chain: &mut CanonicalStore,
    proposal: &CandidateRecord,
    votes: &[Vote],
    physical: &BTreeMap<Hash, PhysicalMember>,
    verifier: &V,
) -> Result<Option<BlockEnvelope>> {
    let Some(block) = assemble(chain, proposal, votes, physical, verifier)? else {
        return Ok(None);
    };
    chain
        .commit_integrated(&block, physical, verifier)
        .map_err(err)?;
    Ok(Some(block))
}
