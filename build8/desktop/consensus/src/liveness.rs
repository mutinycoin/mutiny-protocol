//! Coordinator work-assignment failure detector, never finality authority.
use crate::{
    Error, Hash, Result,
    certificates::{Certificate, Decision},
    votes::HeightAuthority,
};
use std::collections::VecDeque;
pub const REFRESH_MS: u64 = 120_000;
pub const EXPIRY_MS: u64 = 360_000;
/// Sign only the exact purpose-3/step-0 canonical-parent challenge. This cannot
/// produce a BFT prevote/precommit and does not alter any BFT lock or NV counter.
/// Caller retains exclusive TPM custody and verifies its counter journal first.
pub fn sign_probe(
    request: &Decision,
    authority: &HeightAuthority,
    parent_root: Hash,
    node: Hash,
    backend: &mut impl crate::counter_voter::CounterSigningBackend,
) -> Result<crate::certificates::Signer> {
    use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
    let mut expected = WorkGate::new(authority.clone(), parent_root, 0)?;
    let expected = expected
        .request(0, request.block)?
        .ok_or(Error::WrongAnchor)?;
    if request != &expected {
        return Err(Error::WrongAnchor);
    }
    let voter = authority.voters.get(&node).ok_or(Error::UnknownSigner)?;
    if voter.weight.is_zero() || voter.public_key != backend.public_key() {
        return Err(Error::WrongGeneration);
    }
    let digest = request.signing_digest(node, voter.key_version);
    let raw = backend
        .sign_digest(digest)
        .map_err(|_| Error::BadSignature)?;
    let signature = Signature::from_slice(&raw).map_err(|_| Error::BadSignature)?;
    if signature.normalize_s().is_some() {
        return Err(Error::NonCanonical);
    }
    VerifyingKey::from_sec1_bytes(&voter.public_key)
        .map_err(|_| Error::BadSignature)?
        .verify_prehash(&digest, &signature)
        .map_err(|_| Error::BadSignature)?;
    Ok(crate::certificates::Signer {
        node,
        key_version: voter.key_version,
        signature: raw,
    })
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkState {
    Stopped,
    WaitingQuorum,
    Running,
}
pub struct WorkGate {
    authority: HeightAuthority,
    parent_root: Hash,
    pending: VecDeque<(u64, Decision)>,
    last_probe: Option<u64>,
    accepted_issue: Option<u64>,
    last_clock: u64,
    run: bool,
}
impl WorkGate {
    pub fn new(authority: HeightAuthority, parent_root: Hash, now_ms: u64) -> Result<Self> {
        authority
            .parent
            .validate_context(authority.parent.genesis, authority.parent.fingerprint)?;
        Ok(Self {
            authority,
            parent_root,
            pending: VecDeque::new(),
            last_probe: None,
            accepted_issue: None,
            last_clock: now_ms,
            run: false,
        })
    }
    fn clock(&mut self, now: u64) -> Result<()> {
        if now < self.last_clock {
            self.accepted_issue = None;
            return Err(Error::InvalidCounter);
        }
        self.last_clock = now;
        self.pending.retain(|(issued, _)| now - *issued < EXPIRY_MS);
        Ok(())
    }
    pub fn set_run(&mut self, run: bool) {
        self.run = run;
    }
    pub fn state(&mut self, now: u64) -> Result<WorkState> {
        self.clock(now)?;
        Ok(if !self.run {
            WorkState::Stopped
        } else if self
            .accepted_issue
            .is_some_and(|issued| now - issued < EXPIRY_MS)
        {
            WorkState::Running
        } else {
            WorkState::WaitingQuorum
        })
    }
    /// Remaining local lease for this exact committed parent. A caller must cap
    /// device work lifetime by this value and the remaining MiningEpoch.
    pub fn work_lease(&mut self, now: u64, context: &crate::pow::WorkContext) -> Result<u64> {
        if self.state(now)? != WorkState::Running {
            return Err(Error::WrongAnchor);
        }
        let parent = &self.authority.parent;
        if context.genesis != parent.genesis
            || context.fingerprint != parent.fingerprint
            || context.parent != parent.block
            || context.parent_height != parent.height
        {
            return Err(Error::WrongAnchor);
        }
        Ok(EXPIRY_MS - (now - self.accepted_issue.ok_or(Error::WrongAnchor)?))
    }
    /// Caller supplies a new unpredictable challenge from the OS CSPRNG. The
    /// response window is measured from issuance, not receipt of delayed proof.
    pub fn request(&mut self, now: u64, challenge: Hash) -> Result<Option<Decision>> {
        self.clock(now)?;
        if self.last_probe.is_some_and(|old| now - old < REFRESH_MS) {
            return Ok(None);
        }
        if challenge == [0; 32] || self.pending.iter().any(|(_, d)| d.block == challenge) {
            return Err(Error::Duplicate);
        }
        if self.pending.len() >= 3 {
            return Err(Error::Capacity);
        }
        let parent = &self.authority.parent;
        let height = parent.height.checked_add(1).ok_or(Error::Overflow)?;
        let request = Decision {
            network: parent.network,
            genesis: parent.genesis,
            fingerprint: parent.fingerprint,
            purpose: 3,
            height,
            mining_epoch: 0,
            continuity_period: (height - 1) / 60,
            round: 0,
            step: 0,
            previous_finalized_anchor: parent.id(),
            parent: parent.block,
            block: challenge,
            state: self.parent_root,
            membership: self.authority.membership,
            reputation: self.authority.reputation,
            attestation: self.authority.attestation,
        };
        self.pending.push_back((now, request.clone()));
        self.last_probe = Some(now);
        Ok(Some(request))
    }
    pub fn accept(&mut self, now: u64, proof: &Certificate) -> Result<()> {
        self.clock(now)?;
        let (issued, expected) = self
            .pending
            .iter()
            .find(|(_, d)| d == &proof.decision)
            .ok_or(Error::WrongAnchor)?;
        proof.verify_quorum(expected, &self.authority.voters)?;
        self.accepted_issue = Some(self.accepted_issue.map_or(*issued, |old| old.max(*issued)));
        Ok(())
    }
    /// Parent/membership changes and restart invalidate prior liveness. RUN is
    /// preserved across parent changes; no local event changes voter weights.
    pub fn parent_changed(
        &mut self,
        authority: HeightAuthority,
        parent_root: Hash,
        now: u64,
    ) -> Result<()> {
        self.clock(now)?;
        let run = self.run;
        *self = Self::new(authority, parent_root, now)?;
        self.run = run;
        Ok(())
    }
}
