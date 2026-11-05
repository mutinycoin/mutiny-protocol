//! Ordered crash-durable signing gate. Production signing backend is deliberately
//! absent until TPM signing AND journal anti-rollback protection are qualified.
use crate::{
    Error, Hash,
    bft::Step,
    bft_store::{LockStore, StoreError},
    journal::{JournalError, Reservation, VoteJournal},
    votes::{AuthenticatedRound, HeightAuthority, IngressError, Vote},
};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use std::path::Path;
#[derive(Debug)]
pub enum VoterError {
    Invalid(Error),
    Ingress(IngressError),
    Store(StoreError),
    Journal(JournalError),
    Backend,
    WrongHeight,
}
impl From<Error> for VoterError {
    fn from(e: Error) -> Self {
        Self::Invalid(e)
    }
}
impl From<IngressError> for VoterError {
    fn from(e: IngressError) -> Self {
        Self::Ingress(e)
    }
}
impl From<StoreError> for VoterError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}
impl From<JournalError> for VoterError {
    fn from(e: JournalError) -> Self {
        Self::Journal(e)
    }
}
type Result<T> = std::result::Result<T, VoterError>;

/// Only a qualified backend may implement this for production. It must bind the
/// exact journal context/reservation to an anti-rollback mechanism before TPM
/// signing, and return failure when rollback status is unknown. Test software
/// keys implement it solely in tests and confer no physical qualification.
pub trait GuardedSigner {
    fn public_key(&self) -> [u8; 33];
    fn sign_reserved(
        &mut self,
        context: Hash,
        message: &[u8],
        digest: Hash,
    ) -> std::result::Result<[u8; 64], String>;
}
pub struct DurableVoter {
    round: AuthenticatedRound,
    locks: LockStore,
    journal: VoteJournal,
    revision: u64,
    node: Hash,
    context: Hash,
    /// Qualified local clock for fresh block votes. Fail-closed until one is installed.
    clock: std::sync::Arc<dyn crate::vote_clock_v1::VoteClock>,
}
impl DurableVoter {
    /// Install the qualified local clock consulted before every fresh block vote.
    pub fn set_vote_clock(&mut self, clock: std::sync::Arc<dyn crate::vote_clock_v1::VoteClock>) {
        self.clock = clock;
    }
    pub fn open(
        lock_path: &Path,
        journal_path: &Path,
        authority: HeightAuthority,
        node: Hash,
    ) -> Result<Self> {
        let initial = AuthenticatedRound::new(authority)?;
        let context = initial.signing_context(node)?;
        let height = initial.height()?;
        let locks = LockStore::open(lock_path, context, height)?;
        let (stored_height, revision, state) = locks.load()?;
        if stored_height != height {
            return Err(VoterError::WrongHeight);
        }
        let round = initial.restore_state(state)?;
        let journal = VoteJournal::open(journal_path, context)?;
        Ok(Self {
            round,
            locks,
            journal,
            revision,
            node,
            context,
            clock: crate::vote_clock_v1::unqualified(),
        })
    }
    /// No method on AuthenticatedRound signs or publishes a vote by itself.
    pub fn round_mut(&mut self) -> &mut AuthenticatedRound {
        &mut self.round
    }
    pub fn sign(
        &mut self,
        step: Step,
        proposal: Option<Hash>,
        pol_round: Option<u64>,
        backend: &mut impl GuardedSigner,
    ) -> Result<Vote> {
        let expected = self.round.voter(self.node)?.public_key;
        if backend.public_key() != expected {
            return Err(Error::WrongGeneration.into());
        }
        let mut vote = self
            .round
            .prepare_vote(
                self.node,
                step,
                proposal,
                pol_round,
                crate::vote_clock_v1::VoteGate::Fresh(&*self.clock),
            )?;
        self.revision = self.locks.save(
            vote.decision.height,
            self.revision,
            self.round.machine().state(),
        )?;
        let message = vote.unsigned_bytes();
        let journal_step = match step {
            Step::Prevote => crate::journal::Step::Prevote,
            Step::Precommit => crate::journal::Step::Precommit,
        };
        let reservation = self.journal.reserve(
            vote.decision.height,
            vote.decision.round,
            journal_step,
            &message,
        )?;
        vote.signature = match reservation {
            Reservation::AlreadySigned(signature) => signature,
            Reservation::ReadyToSign => backend
                .sign_reserved(self.context, &message, vote.signing_digest())
                .map_err(|_| VoterError::Backend)?,
        };
        let signature = Signature::from_slice(&vote.signature).map_err(|_| Error::BadSignature)?;
        if signature.normalize_s().is_some() {
            return Err(Error::NonCanonical.into());
        }
        VerifyingKey::from_sec1_bytes(&expected)
            .map_err(|_| Error::BadSignature)?
            .verify_prehash(&vote.signing_digest(), &signature)
            .map_err(|_| Error::BadSignature)?;
        self.journal.record_signature(
            vote.decision.height,
            vote.decision.round,
            journal_step,
            &message,
            vote.signature,
        )?;
        // Only after both durable commits may these bytes leave the signing gate.
        Ok(vote)
    }
}
