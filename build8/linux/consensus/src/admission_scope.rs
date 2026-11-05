//! Architect's Continuation Order of 4 Oct 2026, decision A8 (design `qualification/candidate-3/A-ADMISSION-DESIGN-V1.md`
//! section 9): the supervised admission authority (V1: `AdmissionPolicy.authority`; V2: the policy-owner wallet and its
//! succession) is CEREMONY-SCOPED. Its unilateral power to admit hardware ends at sealing; Treasury custody grants no
//! hardware-admission authority.
//!
//! "Sealing" needs no new commitment: every Genesis admission is built without a parent (V1 `initial_state`, V2
//! `membership_v2::Book::genesis`), and every parent-bound block operation is post-sealing by construction. In the
//! Production class every post-sealing HARDWARE admission (V1 JOIN, V1 hardware rotation, V1 recovery material, V2 JOIN, V2
//! hardware rotation, V2 recovery replacement) is refused with `Error::AdmissionAuthorityEnded`, checked AFTER the path's
//! complete verification so that malformed material still fails for its own reason. Consequence, a launch dependency: no
//! hardware can join, rotate or be replaced after sealing in the Production class until a decentralized enrollment
//! protocol exists (design A3-Q1, K2). The Legacy/Test class is unchanged (tests and replay). V2 continuity-key rotation
//! (same TPM profile, no hardware admitted) and owner-or-node exits are NOT changed here (design questions A8-Q1, A8-Q2).
use crate::{Error, Result, execution::State, provenance::AdmissionClass};
use mutiny_crypto_v2::PublicKey;

/// Where an admission happens relative to sealing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionStage {
    /// Inside the supervised Genesis ceremony: the initial state, built without a parent.
    GenesisCeremony,
    /// A parent-bound block operation.
    PostSealing,
}
/// Why an authority-signed admission is outside the authority's scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScopeFailure {
    /// Production class, after sealing: the ceremony-scoped authority no longer admits hardware.
    AuthorityEndedAtSealing,
}
/// The scope rule.
pub fn check_authority_scope(
    class: AdmissionClass,
    stage: AdmissionStage,
) -> std::result::Result<(), ScopeFailure> {
    match (class, stage) {
        (AdmissionClass::Production, AdmissionStage::PostSealing) => {
            Err(ScopeFailure::AuthorityEndedAtSealing)
        }
        _ => Ok(()),
    }
}
/// Called by every post-sealing hardware-admission path after its complete verification; `class` comes from the same
/// committed parent state as the policy (`State::admission_class`).
pub fn require_post_sealing_admission(class: AdmissionClass) -> Result<()> {
    check_authority_scope(class, AdmissionStage::PostSealing).map_err(|_| Error::AdmissionAuthorityEnded)
}
/// Treasury custody grants no hardware-admission authority: the admission owner and the Treasury share no key half.
pub fn reject_treasury_alias(admission_owner_descriptor: &[u8], treasury_descriptor: &[u8]) -> Result<()> {
    let (owner, _) = PublicKey::decode_descriptor(admission_owner_descriptor).map_err(|_| Error::Codec)?;
    let (treasury, _) = PublicKey::decode_descriptor(treasury_descriptor).map_err(|_| Error::Codec)?;
    if owner.ed448 == treasury.ed448 || owner.fndsa == treasury.fndsa {
        return Err(Error::Duplicate);
    }
    Ok(())
}
/// Production-class committed-state backstop (every StateRoot): the V2 admission policy owner, initial and current, is
/// not the Treasury wallet (Genesis descriptor or its current WalletBook descriptor). V1 cannot alias: its authority is an
/// Ed25519 key and the Treasury a hybrid descriptor.
pub(crate) fn check_state_roles(state: &State, class: AdmissionClass) -> Result<()> {
    if class != AdmissionClass::Production {
        return Ok(());
    }
    let (Some(policy), Some(treasury)) = (&state.admission_policy_v2, state.dividends.treasury()) else {
        return Ok(());
    };
    let initial = policy.initial();
    let mut owners = vec![initial.owner_descriptor.clone()];
    if let Ok(current) = policy.current(&state.wallets, initial.genesis, initial.fingerprint) {
        owners.push(current.owner_descriptor);
    }
    let mut treasuries = vec![treasury.descriptor().to_vec()];
    if let Some(current) = state.wallets.current(treasury.authority()) {
        treasuries.push(current.to_vec());
    }
    for owner in &owners {
        for t in &treasuries {
            reject_treasury_alias(owner, t)?;
        }
    }
    Ok(())
}
