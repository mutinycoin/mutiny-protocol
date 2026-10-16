//! Authenticated vote ingress for one trusted height. Block votes enter the
//! reducer only after work/body/state validation. Nil has an explicit signed
//! domain and never means a zero-hash block. This is not a timer/proposer actor.
use crate::{
    Error, Hash,
    anchors::FinalizedAnchor,
    bft::{BftError, Observation, RoundMachine, Step},
    blocks::BlockBody,
    certificates::{Decision, Voter},
    domain_hash,
    execution::{Execution, ExecutionError, State, WorkParent},
    pow::{WorkAuthority, WorkHeader, meets_target, mining_epoch},
};
use minicbor::{Decoder, Encoder};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vote {
    pub nil: bool,
    pub decision: Decision,
    pub node: Hash,
    pub key_version: u64,
    pub signature: [u8; 64],
}
impl Vote {
    pub fn unsigned_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(1)
            .unwrap()
            .bool(self.nil)
            .unwrap()
            .bytes(&self.decision.encode())
            .unwrap()
            .bytes(&self.node)
            .unwrap()
            .u64(self.key_version)
            .unwrap();
        e.into_writer()
    }
    pub fn signing_digest(&self) -> Hash {
        if !self.nil {
            return self.decision.signing_digest(self.node, self.key_version);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(3)
            .unwrap()
            .bytes(&self.decision.encode())
            .unwrap()
            .bytes(&self.node)
            .unwrap()
            .u64(self.key_version)
            .unwrap();
        domain_hash(b"MUTINY-BUILD8-CONTINUITY-NIL-VOTE-V1", &e.into_writer())
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(6)
            .unwrap()
            .u8(1)
            .unwrap()
            .bool(self.nil)
            .unwrap()
            .bytes(&self.decision.encode())
            .unwrap()
            .bytes(&self.node)
            .unwrap()
            .u64(self.key_version)
            .unwrap()
            .bytes(&self.signature)
            .unwrap();
        e.into_writer()
    }
    pub fn decode(raw: &[u8]) -> crate::Result<Self> {
        crate::blocks::canonical(raw, 2048)?;
        let mut d = Decoder::new(raw);
        let vote = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            if d.array()? != Some(6) || d.u8()? != 1 {
                return Err(minicbor::decode::Error::message("vote"));
            }
            let nil = d.bool()?;
            let decision = Decision::decode(d.bytes()?)
                .map_err(|_| minicbor::decode::Error::message("decision"))?;
            let node = d
                .bytes()?
                .try_into()
                .map_err(|_| minicbor::decode::Error::message("node"))?;
            let key_version = d.u64()?;
            let signature = d
                .bytes()?
                .try_into()
                .map_err(|_| minicbor::decode::Error::message("signature"))?;
            Ok(Self {
                nil,
                decision,
                node,
                key_version,
                signature,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if vote.encode() != raw {
            return Err(Error::NonCanonical);
        }
        Ok(vote)
    }
}
#[derive(Debug)]
pub enum IngressError {
    Invalid(Error),
    Execution(ExecutionError),
    Bft(BftError),
    UnknownProposal,
    Capacity,
    /// Fresh vote refused: the block timestamp is ahead of the qualified local clock.
    /// Temporary and not a validity verdict: the proposal may become eligible later.
    FutureTimestamp { ahead_seconds: u64 },
    /// Fresh vote refused: no qualified local clock. The validator abstains.
    ClockUnqualified,
}
impl IngressError {
    /// True when a vote was withheld only for local time reasons (defer/abstain, never invalid).
    pub fn is_time_deferral(&self) -> bool {
        matches!(self, Self::FutureTimestamp { .. } | Self::ClockUnqualified)
    }
}
impl From<Error> for IngressError {
    fn from(e: Error) -> Self {
        Self::Invalid(e)
    }
}
impl From<BftError> for IngressError {
    fn from(e: BftError) -> Self {
        Self::Bft(e)
    }
}
impl From<ExecutionError> for IngressError {
    fn from(e: ExecutionError) -> Self {
        Self::Execution(e)
    }
}
type Result<T> = std::result::Result<T, IngressError>;

/// These roots/keys/weights must be derived from committed authority. In
/// particular an incoming proposal/certificate cannot supply its own registry.
#[derive(Clone)]
pub struct HeightAuthority {
    pub parent: FinalizedAnchor,
    pub membership: Hash,
    pub reputation: Hash,
    pub attestation: Hash,
    pub voters: BTreeMap<Hash, Voter>,
}
pub struct AuthenticatedRound {
    authority: HeightAuthority,
    machine: RoundMachine,
    proposals: BTreeMap<Hash, (Hash, u64)>,
    /// Block timestamp of each executed proposal, for the local vote-time gate only.
    stamps: BTreeMap<Hash, u64>,
}
impl AuthenticatedRound {
    pub fn height(&self) -> crate::Result<u64> {
        self.authority
            .parent
            .height
            .checked_add(1)
            .ok_or(Error::Overflow)
    }
    pub(crate) fn authority(&self) -> &HeightAuthority {
        &self.authority
    }
    /// Custody identity survives a temporary zero voting weight. This accessor
    /// grants no authority to prepare, sign, authenticate or count a BFT vote.
    pub(crate) fn custody_member(&self, node: Hash) -> crate::Result<&Voter> {
        self.authority.voters.get(&node).ok_or(Error::UnknownSigner)
    }
    pub fn voter(&self, node: Hash) -> crate::Result<&Voter> {
        let voter = self
            .authority
            .voters
            .get(&node)
            .ok_or(Error::UnknownSigner)?;
        if voter.weight.is_zero() {
            return Err(Error::WrongGeneration);
        }
        Ok(voter)
    }
    pub fn signing_context(&self, node: Hash) -> crate::Result<Hash> {
        let voter = self.custody_member(node)?;
        let parent = &self.authority.parent;
        let mut e = Encoder::new(Vec::new());
        e.array(7)
            .unwrap()
            .u8(1)
            .unwrap()
            .u32(parent.network)
            .unwrap()
            .bytes(&parent.genesis)
            .unwrap()
            .bytes(&parent.fingerprint)
            .unwrap()
            .bytes(&node)
            .unwrap()
            .u64(voter.key_version)
            .unwrap()
            .bytes(&voter.public_key)
            .unwrap();
        Ok(domain_hash(
            b"MUTINY-BUILD8-VOTE-JOURNAL-CONTEXT-V1",
            &e.into_writer(),
        ))
    }
    /// Caller must durably save machine state and reserve unsigned_bytes before
    /// invoking its rollback-protected TPM signer. This does not sign or publish.
    /// Local time eligibility of voting for `block` now. Pure: changes no state.
    pub fn time_status(
        &self,
        clock: &dyn crate::vote_clock_v1::VoteClock,
        block: Hash,
    ) -> crate::vote_clock_v1::TimeStatus {
        match self.stamps.get(&block) {
            Some(ts) => crate::vote_clock_v1::evaluate(clock, *ts),
            None => crate::vote_clock_v1::TimeStatus::UnknownProposal,
        }
    }
    /// The block this round WOULD vote for, computed without any mutation. The time guard must
    /// judge this block, not the caller's `proposal` argument: a validator holding a lock votes
    /// its locked block even when called with no proposal, and `None` here means a nil vote.
    pub fn vote_block(
        &self,
        step: Step,
        proposal: Option<Hash>,
        pol_round: Option<u64>,
    ) -> Result<Option<Hash>> {
        match step {
            Step::Prevote => {
                if proposal.is_some_and(|p| !self.proposals.contains_key(&p)) {
                    return Err(IngressError::UnknownProposal);
                }
                Ok(self.machine.preview_prevote(proposal, pol_round)?)
            }
            Step::Precommit => {
                if pol_round.is_some() {
                    return Err(Error::WrongOperation.into());
                }
                Ok(self.machine.preview_precommit(proposal)?)
            }
        }
    }
    /// Gate for a FRESH vote. It judges the block the reducer would actually return (see
    /// `vote_block`); nil votes are not time-dependent. Runs before any reducer or custody
    /// mutation so a refusal leaves no trace.
    pub fn time_gate(
        &self,
        gate: crate::vote_clock_v1::VoteGate<'_>,
        step: Step,
        proposal: Option<Hash>,
        pol_round: Option<u64>,
    ) -> Result<()> {
        use crate::vote_clock_v1::{TimeStatus, VoteGate};
        let VoteGate::Fresh(clock) = gate else {
            return Ok(());
        };
        let Some(block) = self.vote_block(step, proposal, pol_round)? else {
            return Ok(());
        };
        match self.time_status(clock, block) {
            TimeStatus::Eligible => Ok(()),
            TimeStatus::Future { ahead_seconds } => {
                Err(IngressError::FutureTimestamp { ahead_seconds })
            }
            TimeStatus::Unqualified => Err(IngressError::ClockUnqualified),
            TimeStatus::UnknownProposal => Err(IngressError::UnknownProposal),
        }
    }
    pub fn prepare_vote(
        &mut self,
        node: Hash,
        step: Step,
        proposal: Option<Hash>,
        pol_round: Option<u64>,
        gate: crate::vote_clock_v1::VoteGate<'_>,
    ) -> Result<Vote> {
        let key_version = self.voter(node)?.key_version;
        self.time_gate(gate, step, proposal, pol_round)?;
        let block = match step {
            Step::Prevote => self.prevote(proposal, pol_round)?,
            Step::Precommit => {
                if pol_round.is_some() {
                    return Err(Error::WrongOperation.into());
                }
                self.precommit(proposal)?
            }
        };
        let (state, mining_epoch) = if let Some(block) = block {
            *self
                .proposals
                .get(&block)
                .ok_or(IngressError::UnknownProposal)?
        } else {
            ([0; 32], 0)
        };
        let parent = &self.authority.parent;
        let height = self.height()?;
        Ok(Vote {
            nil: block.is_none(),
            node,
            key_version,
            signature: [0; 64],
            decision: Decision {
                network: parent.network,
                genesis: parent.genesis,
                fingerprint: parent.fingerprint,
                purpose: 2,
                height,
                mining_epoch,
                continuity_period: (height - 1) / 60,
                round: self.machine.state().round,
                step: match step {
                    Step::Prevote => 2,
                    Step::Precommit => 3,
                },
                previous_finalized_anchor: parent.id(),
                parent: parent.block,
                block: block.unwrap_or([0; 32]),
                state,
                membership: self.authority.membership,
                reputation: self.authority.reputation,
                attestation: self.authority.attestation,
            },
        })
    }
    pub(crate) fn restore_state(mut self, state: crate::bft::LockState) -> Result<Self> {
        let weights = self
            .authority
            .voters
            .iter()
            .map(|(id, v)| (*id, v.weight))
            .collect();
        self.machine = RoundMachine::restore(weights, state)?;
        Ok(self)
    }
    /// Restores a durably saved lock before ingesting/replaying authenticated
    /// messages. Proposals must be revalidated; signatures cannot bypass this.
    pub fn restore(authority: HeightAuthority, state: crate::bft::LockState) -> Result<Self> {
        let mut restored = Self::new(authority)?;
        let weights = restored
            .authority
            .voters
            .iter()
            .map(|(id, v)| (*id, v.weight))
            .collect();
        restored.machine = RoundMachine::restore(weights, state)?;
        Ok(restored)
    }
    pub fn new(authority: HeightAuthority) -> Result<Self> {
        authority
            .parent
            .validate_context(authority.parent.genesis, authority.parent.fingerprint)?;
        if authority.voters.len() > 1024 {
            return Err(IngressError::Capacity);
        }
        let mut keys = std::collections::BTreeSet::new();
        for voter in authority.voters.values() {
            if !voter.weight.is_zero() && !keys.insert(voter.public_key) {
                return Err(Error::Duplicate.into());
            }
        }
        let weights = authority
            .voters
            .iter()
            .map(|(id, v)| (*id, v.weight))
            .collect();
        Ok(Self {
            authority,
            machine: RoundMachine::new(weights)?,
            proposals: BTreeMap::new(),
            stamps: BTreeMap::new(),
        })
    }
    /// Local cache cap is backpressure, not consensus invalidity. Callers may
    /// archive/revalidate proposals; they must never shrink quorum on capacity.
    pub fn validate_proposal(
        &mut self,
        state: &State,
        parent: &WorkParent,
        header: &WorkHeader,
        work: &WorkAuthority,
        signature: &[u8; 64],
        body: &BlockBody,
    ) -> Result<Execution> {
        self.validate_proposal_with_attestation(
            state,
            crate::execution::LicensedExecution {
                parent,
                header,
                authority: work,
                signature,
                body,
            },
            &BTreeMap::new(),
            &crate::execution::RejectAttestation,
        )
    }
    pub fn validate_proposal_with_attestation<V: crate::freshness::PhysicalAttestationVerifier>(
        &mut self,
        state: &State,
        input: crate::execution::LicensedExecution<'_>,
        physical: &BTreeMap<Hash, crate::freshness::PhysicalMember>,
        verifier: &V,
    ) -> Result<Execution> {
        self.validate_proposal_with_history(state, input, physical, verifier, &BTreeMap::new())
    }
    pub fn validate_proposal_with_history<V: crate::freshness::PhysicalAttestationVerifier>(
        &mut self,
        state: &State,
        input: crate::execution::LicensedExecution<'_>,
        physical: &BTreeMap<Hash, crate::freshness::PhysicalMember>,
        verifier: &V,
        history: &crate::equivocation::EvidenceHistory,
    ) -> Result<Execution> {
        let parent = input.parent;
        let header = input.header;
        let trusted = &self.authority.parent;
        if parent.genesis != trusted.genesis
            || parent.fingerprint != trusted.fingerprint
            || parent.block != trusted.block
            || parent.height != trusted.height
        {
            return Err(Error::WrongAnchor.into());
        }
        if !meets_target(&header.digest(), &header.candidate.target) {
            return Err(Error::InvalidCounter.into());
        }
        let block = header.block_hash();
        if self.proposals.len() >= 1024 && !self.proposals.contains_key(&block) {
            return Err(IngressError::Capacity);
        }
        let executed = state.execute_with_history(input, physical, verifier, history)?;
        self.proposals.insert(
            block,
            (
                executed.root,
                mining_epoch(header.candidate.timestamp, parent.t0)?,
            ),
        );
        self.stamps.insert(block, header.candidate.timestamp);
        Ok(executed)
    }
    pub fn observe(&mut self, vote: &Vote) -> Result<Observation> {
        let d = &vote.decision;
        d.verify_parent(&self.authority.parent)?;
        if d.purpose != 2
            || d.membership != self.authority.membership
            || d.reputation != self.authority.reputation
            || d.attestation != self.authority.attestation
            || d.continuity_period != (d.height - 1) / 60
        {
            return Err(Error::WrongAnchor.into());
        }
        let step = match d.step {
            2 => Step::Prevote,
            3 => Step::Precommit,
            _ => return Err(Error::WrongOperation.into()),
        };
        if vote.nil {
            if d.block != [0; 32] || d.state != [0; 32] || d.mining_epoch != 0 {
                return Err(Error::NonCanonical.into());
            }
        } else if self.proposals.get(&d.block) != Some(&(d.state, d.mining_epoch)) {
            return Err(IngressError::UnknownProposal);
        }
        let voter = self
            .authority
            .voters
            .get(&vote.node)
            .ok_or(Error::UnknownSigner)?;
        if voter.weight.is_zero() || voter.key_version != vote.key_version {
            return Err(Error::WrongGeneration.into());
        }
        let signature = Signature::from_slice(&vote.signature).map_err(|_| Error::BadSignature)?;
        if signature.normalize_s().is_some() {
            return Err(Error::NonCanonical.into());
        }
        VerifyingKey::from_sec1_bytes(&voter.public_key)
            .map_err(|_| Error::BadSignature)?
            .verify_prehash(&vote.signing_digest(), &signature)
            .map_err(|_| Error::BadSignature)?;
        Ok(self.machine.observe_authenticated(
            d.round,
            step,
            vote.node,
            if vote.nil { None } else { Some(d.block) },
        )?)
    }
    pub fn machine(&self) -> &RoundMachine {
        &self.machine
    }
    pub fn enter_round(&mut self, round: u64) -> Result<()> {
        Ok(self.machine.enter_round(round)?)
    }
    pub fn prevote(
        &mut self,
        proposal: Option<Hash>,
        pol_round: Option<u64>,
    ) -> Result<Option<Hash>> {
        if proposal.is_some_and(|p| !self.proposals.contains_key(&p)) {
            return Err(IngressError::UnknownProposal);
        }
        Ok(self.machine.prevote(proposal, pol_round)?)
    }
    pub fn precommit(&mut self, block: Option<Hash>) -> Result<Option<Hash>> {
        Ok(self.machine.precommit(block)?)
    }
    pub fn timeout_precommit(&mut self) -> Result<u64> {
        Ok(self.machine.timeout_precommit()?)
    }
    pub fn commit(&mut self, round: u64, block: Hash) -> Result<bool> {
        Ok(self.machine.commit(round, block)?)
    }
}
