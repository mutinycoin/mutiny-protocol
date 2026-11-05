//! Candidate hybrid canonical-chain/counter custody owner. Canonical installation
//! precedes counter advancement. Recovery reexecutes canonical history; it never
//! trusts a peer's voter map or imports an unrecorded local signature.
use crate::{
    Error, Hash,
    bft::Step,
    block_envelope_v2::BlockEnvelope,
    canonical_store_v2::CanonicalStore,
    continuity_v2::Vote,
    counter_voter::CounterVoterError,
    counter_voter_v2::{CounterSigningBackend, CounterVoter, MigrationReceipt},
    finality_v2::StoreError,
    votes::IngressError,
    votes_v2::{AuthenticatedRound, HeightAuthority},
};
use std::{
    path::Path,
    time::{Duration, Instant},
};

#[derive(Debug)]
pub enum ActorError {
    Chain(StoreError),
    Voter(CounterVoterError),
    Invalid(Error),
    Ingress(IngressError),
    Rollback,
    Halted,
    /// A block vote (or the completion of an unmarked legacy reservation) was withheld ONLY for
    /// local time reasons: the qualified clock is behind the block's timestamp, or there is no
    /// qualified clock. This is an explicit, NONFATAL result. It is produced only by the pure
    /// pre-check that runs before the halting latch is set and before any custody, reducer or
    /// counter state is touched, so returning it never changes `halted`, and no path clears
    /// `halted` on its account. A halted actor reports `Halted` instead, whatever the clock says.
    TimeDeferred(crate::vote_clock_v1::TimeStatus),
    /// A vote request decided for a (height, round) context this actor has since left (Architect
    /// decision V4), exactly as in `voter_actor::ActorError::StaleContext`: explicit, NONFATAL,
    /// raised by `sign_for` before the clock, the latch, the reducer and custody.
    StaleContext {
        requested: crate::voter_actor::VoteContext,
        current: crate::voter_actor::VoteContext,
    },
}
impl ActorError {
    /// The time status behind an explicit nonfatal deferral; `None` for every other error.
    pub fn time_deferral(&self) -> Option<crate::vote_clock_v1::TimeStatus> {
        match self {
            Self::TimeDeferred(status) => Some(*status),
            _ => None,
        }
    }
    /// True when a vote was withheld only for local time reasons (defer/abstain; never a fault).
    pub fn is_time_deferral(&self) -> bool {
        self.time_deferral().is_some()
    }
}
impl From<StoreError> for ActorError {
    fn from(e: StoreError) -> Self {
        Self::Chain(e)
    }
}
impl From<CounterVoterError> for ActorError {
    fn from(e: CounterVoterError) -> Self {
        Self::Voter(e)
    }
}
impl From<Error> for ActorError {
    fn from(e: Error) -> Self {
        Self::Invalid(e)
    }
}
impl From<IngressError> for ActorError {
    fn from(e: IngressError) -> Self {
        Self::Ingress(e)
    }
}
type Result<T> = std::result::Result<T, ActorError>;

fn current(chain: &CanonicalStore) -> Result<HeightAuthority> {
    Ok(chain.current_actor_authority()?)
}
pub struct Proposal<'a> {
    pub header: &'a crate::pow::WorkHeader,
    pub body: &'a crate::blocks::BlockBody,
    pub authority: &'a crate::work_authority_v2::Authority,
}
/// One owner of the canonical store, the voter custody and the halting latch.
///
/// `halted` is a one-way safety latch, held in memory. `check_backend`, `reconcile`,
/// `rotate_finalized_generation`, and `sign` and `replay` after their pure pre-checks, set it
/// BEFORE any step that may touch custody, the counter or the reducer's locks, and clear it only on
/// their own success, after starting with it clear (what each call latches, and what it does not,
/// is listed in docs/OS-CLOCK-CLASSIFICATION-V1.md, 9.2). A genuine failure (counter
/// inconsistency, backend corruption, an interrupted signature), and a request conflict or a halted
/// reducer found by the pure pre-check (`refusal`), therefore leave THIS in-memory actor halted (the
/// latch itself is never written), and only reopening (full revalidation of both durable stores)
/// can produce a working actor. A reopen re-derives every cause that lives in durable state,
/// including the DURABLE halt bit the voter writes for an own certificate vote that was never
/// durably issued here. A request conflict is a refused REQUEST, not evidence of two durable
/// decisions (Architect decision V1): it is held in memory only, writes nothing and uses no counter
/// value, so the reopened actor can complete only the ORIGINAL stored decision and refuses the
/// conflicting request again (docs/OS-CLOCK-CLASSIFICATION-V1.md, 9.3 and 9.10).
///
/// Local TIME reasons are not failures and never use the latch. The pure pre-checks in `sign` and
/// `replay` run BEFORE it is set, judge ONE clock reading that the voter then reuses, and return the
/// explicit result `ActorError::TimeDeferred` with the latch untouched. No code in this file resets
/// `halted` on account of a time deferral.
pub struct VoterActor {
    voter: CounterVoter,
    halted: bool,
    precommit_deadline: Option<(u64, u64, Instant)>,
}
pub enum ExistingActorCustody {
    Store(std::mem::ManuallyDrop<crate::counter_store_v2::CounterStore>),
    Actor(std::mem::ManuallyDrop<VoterActor>),
}
pub struct ExistingActorRefusal {cause:ActorError,custody:ExistingActorCustody}
impl ExistingActorRefusal {
    pub fn cause(&self)->&ActorError{&self.cause}
    pub fn into_retained(self)->(ActorError,ExistingActorCustody){(self.cause,self.custody)}
}
pub struct ExistingActorShutdownRefusal {cause:ActorError,actor:std::mem::ManuallyDrop<VoterActor>}
impl ExistingActorShutdownRefusal {
    pub fn into_retained(self)->(ActorError,std::mem::ManuallyDrop<VoterActor>){(self.cause,self.actor)}
}
impl VoterActor {
    /// Return only the exact settled counter store, never a signing backend.
    /// Current canonical authority is checked without reconciliation/writes.
    /// Any fault retains the whole actor; no SQLite/native close is attempted.
    pub fn into_existing_store(self,chain:&CanonicalStore,backend:&mut impl CounterSigningBackend)
        ->std::result::Result<std::mem::ManuallyDrop<crate::counter_store_v2::CounterStore>,ExistingActorShutdownRefusal>{
        let actor=std::mem::ManuallyDrop::new(self);
        let checked=(||->Result<()>{
            if actor.halted{return Err(ActorError::Halted);}
            if !actor.voter.matches_authority(&current(chain)?){return Err(ActorError::Rollback);}
            Ok(())
        })();
        if let Err(cause)=checked{return Err(ExistingActorShutdownRefusal{cause,actor});}
        let Self{voter,halted,precommit_deadline}=std::mem::ManuallyDrop::into_inner(actor);
        match voter.into_existing_store(backend){Ok(store)=>Ok(store),Err(refusal)=>{
            let(cause,voter)=refusal.into_retained();
            Err(ExistingActorShutdownRefusal{cause:cause.into(),actor:std::mem::ManuallyDrop::new(Self{
                voter:std::mem::ManuallyDrop::into_inner(voter),halted,precommit_deadline})})
        }}
    }
    /// Existing native-store factory route. The same recovered store is read
    /// once for height, retained through historical authority and reconciliation.
    /// No by-name second store open, initialization or default clock is issued.
    pub fn from_existing_store(store:std::mem::ManuallyDrop<crate::counter_store_v2::CounterStore>,
        node:Hash,chain:&mut CanonicalStore,backend:&mut impl CounterSigningBackend)
        ->std::result::Result<Self,ExistingActorRefusal>{
        let authority=(||->Result<_>{
            let now=current(chain)?;
            let context=AuthenticatedRound::new(now.clone())?.signing_context(node)?;
            if store.context()!=context{return Err(ActorError::Rollback);}
            let height=CounterVoter::existing_store_height(&store)?;
            if height==0||height>now.parent.height.checked_add(1).ok_or(Error::Overflow)?{
                return Err(ActorError::Rollback);}
            Ok(chain.voting_authority_at(height-1)?)
        })();
        let authority=match authority{Ok(value)=>value,Err(cause)=>return Err(ExistingActorRefusal{
            cause,custody:ExistingActorCustody::Store(store)})};
        let voter=match CounterVoter::from_existing_store(store,authority,node,backend){
            Ok(voter)=>voter,Err(error)=>{let(cause,store)=error.into_retained();
                return Err(ExistingActorRefusal{cause:cause.into(),custody:ExistingActorCustody::Store(store)});}
        };
        let mut actor=std::mem::ManuallyDrop::new(Self{voter,halted:false,precommit_deadline:None});
        if let Err(cause)=actor.reconcile(chain,backend){return Err(ExistingActorRefusal{
            cause,custody:ExistingActorCustody::Actor(actor)});}
        Ok(std::mem::ManuallyDrop::into_inner(actor))
    }
    /// Install the qualified local clock consulted before every fresh block vote.
    pub fn set_vote_clock(&mut self, clock: std::sync::Arc<dyn crate::vote_clock_v1::VoteClock>) {
        self.voter.set_vote_clock(clock);
    }
    pub fn configure_activation(&mut self,lifetime:Duration,
        elapsed:std::sync::Arc<dyn crate::activation_attestation_v1::Elapsed>)->Result<()> {
        if self.halted{return Err(ActorError::Halted);}
        self.voter.configure_activation(lifetime,elapsed)?;Ok(())
    }
    pub fn cancel_activation(&mut self){self.voter.cancel_activation();}
    pub fn activation_request(&self,step:Step,block:Option<Hash>,pol:Option<u64>)
        ->Result<Option<crate::activation_attestation_v1::Request>> {
        if self.halted{return Err(ActorError::Halted);}
        Ok(self.voter.activation_request(step,block,pol)?)
    }
    pub fn begin_activation(&mut self,chain:&CanonicalStore,step:Step,block:Option<Hash>,pol:Option<u64>,
        materials:&[crate::activation_attestation_v1::Material],
        provider:&mut dyn crate::activation_attestation_v1::CurrentContext,
        adapter:&mut dyn crate::activation_attestation_v1::MakeCredential,
        backend:&mut impl CounterSigningBackend)->Result<crate::activation_attestation_v1::Exchange> {
        self.check_backend(chain,backend)?;
        let exchange=self.voter.begin_activation(step,block,pol,materials,provider,adapter)?;
        self.check_backend(chain,backend)?;Ok(exchange)
    }
    pub fn complete_activation(&mut self,chain:&CanonicalStore,session:Hash,
        request:&crate::activation_attestation_v1::Request,
        responses:Vec<crate::activation_attestation_v1::RecoveryResponse>,
        provider:&mut dyn crate::activation_attestation_v1::CurrentContext,
        backend:&mut impl CounterSigningBackend)->Result<()> {
        self.check_backend(chain,backend)?;
        self.voter.complete_activation(session,request,responses,provider)?;
        self.check_backend(chain,backend)?;Ok(())
    }
    /// Pure local time eligibility of voting for an executed proposal right now.
    pub fn time_status(&self, block: Hash) -> crate::vote_clock_v1::TimeStatus {
        self.voter.time_status(block)
    }
    /// Explicit initialization of fresh replacement custody, never a repair of
    /// a missing old journal. The host must first make its create-only ceremony
    /// reservation and independently pin the replacement hardware's counter.
    pub fn initialize_recovery(
        path: &Path,
        node: Hash,
        expected: &crate::anchors::FinalizedAnchor,
        commitment: Hash,
        pinned_counter: u64,
        chain: &mut CanonicalStore,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<Self> {
        if pinned_counter == 0 {
            return Err(Error::InvalidCounter.into());
        }
        let authority = chain.recovery_initialization_authority(expected, node, commitment)?;
        let voter = CounterVoter::open(path, authority, node, Some(pinned_counter), backend)?;
        let mut actor = Self {
            voter,
            halted: false,
            precommit_deadline: None,
        };
        actor.reconcile(chain, backend)?;
        Ok(actor)
    }
    /// Host-owned liveness request. A lagging actor must reconcile separately;
    /// this path never advances canonical/voter state or a counter itself.
    pub fn sign_work_probe(
        &mut self,
        chain: &CanonicalStore,
        decision: &crate::certificates::Decision,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<crate::liveness_v2::Fragment> {
        self.check_backend(chain, backend)?;
        let now = current(chain)?;
        let (_, _, root) = chain.execution_parent(now.parent.height)?;
        let fragment = self.voter.sign_work_probe(decision, root, backend)?;
        self.check_backend(chain, backend)?;
        Ok(fragment)
    }
    /// Explicit recovery of a finalized software-generation migration. The
    /// journal must already exist; predecessor authority comes from canonical
    /// history. This cannot initialize missing custody or replace hardware.
    pub fn open_after_rotation(
        path: &Path,
        node: Hash,
        height: u64,
        chain: &mut CanonicalStore,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<Self> {
        let voter = CounterVoter::resume_rotation(path, chain, node, height, backend)?;
        let mut actor = Self {
            voter,
            halted: false,
            precommit_deadline: None,
        };
        actor.reconcile(chain, backend)?;
        Ok(actor)
    }
    /// Must precede ordinary reconciliation of the generation-changing block.
    /// The caller activates the prepared key using the returned durable receipt
    /// while retaining exclusive backend ownership, then reconciles again.
    pub fn rotate_finalized_generation(
        &mut self,
        chain: &mut CanonicalStore,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<MigrationReceipt> {
        if self.halted {
            return Err(ActorError::Halted);
        }
        self.halted = true;
        let receipt = self.voter.rotate_finalized(chain, backend)?;
        self.precommit_deadline = None;
        self.halted = false;
        Ok(receipt)
    }
    pub fn open(
        path: &Path,
        node: Hash,
        initial: Option<u64>,
        chain: &mut CanonicalStore,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<Self> {
        let now = current(chain)?;
        let height = if initial.is_some() {
            // Fresh post-Genesis admission/recovery has a separate policy gate.
            if now.parent.height != 0 {
                return Err(ActorError::Rollback);
            }
            1
        } else {
            let context = AuthenticatedRound::new(now.clone())?.signing_context(node)?;
            CounterVoter::stored_height(path, context, backend)?
        };
        if height == 0 || height > now.parent.height.checked_add(1).ok_or(Error::Overflow)? {
            return Err(ActorError::Rollback);
        }
        let voter = CounterVoter::open(
            path,
            chain.voting_authority_at(height - 1)?,
            node,
            initial,
            backend,
        )?;
        let mut actor = Self {
            voter,
            halted: false,
            precommit_deadline: None,
        };
        actor.reconcile(chain, backend)?;
        Ok(actor)
    }
    pub fn node(&self) -> Hash {
        self.voter.node()
    }
    pub fn height(&self) -> u64 {
        self.voter.height()
    }
    pub fn progress(&self) -> Result<(crate::bft::LockState, Option<Vote>, Option<Vote>)> {
        if self.halted {
            return Err(ActorError::Halted);
        }
        Ok(self.voter.progress()?)
    }
    /// Caller retains exclusive host/backend ownership. A stale chain or custody
    /// fault halts this actor; restarting must revalidate both durable stores.
    pub fn check_backend(
        &mut self,
        chain: &CanonicalStore,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<()> {
        if self.halted {
            return Err(ActorError::Halted);
        }
        self.halted = true;
        let now = current(chain)?;
        if !self.voter.matches_authority(&now) {
            return Err(ActorError::Rollback);
        }
        self.voter.check_backend(backend)?;
        self.halted = false;
        Ok(())
    }
    /// Normal NodeWork follows the SAME owned voter/counter and actor latch.
    pub fn sign_reserved_node_work(&mut self,chain:&CanonicalStore,
        authority:crate::work_authority_v2::Authority,body:&crate::blocks::BlockBody,
        backend:&mut impl CounterSigningBackend)->Result<crate::work_authority_v2::Authority>{
        self.check_backend(chain,backend)?;
        self.halted=true;
        let signed=self.voter.sign_node_work(chain,authority,body,backend)?;
        let now=current(chain)?;
        if !self.voter.matches_authority(&now){return Err(ActorError::Rollback);}
        self.voter.check_backend(backend)?;
        self.halted=false;
        Ok(signed)
    }
    pub fn node_work_high_water(&mut self,chain:&CanonicalStore,
        backend:&mut impl CounterSigningBackend)->Result<u64>{
        self.check_backend(chain,backend)?;
        self.halted=true;
        let value=self.voter.node_work_high_water(backend)?;
        self.halted=false;Ok(value)
    }
    pub fn reconcile(
        &mut self,
        chain: &mut CanonicalStore,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<()> {
        if self.halted {
            return Err(ActorError::Halted);
        }
        self.halted = true;
        self.voter.check_backend(backend)?;
        let now = current(chain)?;
        if self.height() > now.parent.height.checked_add(1).ok_or(Error::Overflow)? {
            return Err(ActorError::Rollback);
        }
        while self.height() <= now.parent.height {
            let height = self.height();
            let block = chain.canonical_block(height)?.ok_or(Error::WrongAnchor)?;
            // Fully revalidate the canonical envelope, but never insert anything
            // new merely because local custody needs reconciliation.
            if chain.commit(&block)? {
                return Err(ActorError::Rollback);
            }
            for vote in &block.certificate.votes {
                self.voter.require_local_vote(vote, backend)?;
            }
            let round = self.voter.round_mut()?;
            chain.validate_round_proposal(round, &block.header, &block.authority, &block.body)?;
            for vote in &block.certificate.votes {
                round.observe(vote)?;
            }
            if !round.commit(block.certificate.decision.round, block.block_hash())? {
                return Err(ActorError::Rollback);
            }
            self.voter
                .advance(chain.voting_authority_at(height)?, backend)?;
            self.precommit_deadline = None;
        }
        // A concurrent canonical writer cannot leave this actor signing under
        // the stale tip sampled before reconciliation.
        if !self.voter.matches_authority(&current(chain)?) {
            return Err(ActorError::Rollback);
        }
        self.halted = false;
        Ok(())
    }
    pub fn validate_candidate(
        &mut self,
        chain: &CanonicalStore,
        proposal: Proposal<'_>,
    ) -> Result<()> {
        if self.halted {
            return Err(ActorError::Halted);
        }
        let now = current(chain)?;
        if !self.voter.matches_authority(&now) {
            self.halted = true;
            return Err(ActorError::Rollback);
        }
        chain.proposal_body_capacity(proposal.header)?.encode(proposal.body)?;
        chain.validate_round_proposal(
            self.voter.round_mut()?,
            proposal.header,
            proposal.authority,
            proposal.body,
        )?;
        Ok(())
    }
    pub fn validate_proposal(
        &mut self,
        chain: &CanonicalStore,
        block: &BlockEnvelope,
    ) -> Result<()> {
        self.validate_candidate(
            chain,
            Proposal {
                header: &block.header,
                body: &block.body,
                authority: &block.authority,
            },
        )
    }
    pub fn observe(
        &mut self,
        chain: &CanonicalStore,
        vote: &Vote,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<()> {
        self.check_backend(chain, backend)?;
        // Invalid peer bytes must not manufacture a local custody alarm. Only
        // an individually valid own signature can contradict our durable log.
        let now = current(chain)?;
        vote.verify(&now.parent, now.roots(), &now.voters)?;
        // Unrecorded own votes are a custody fault, even with valid signatures.
        if let Err(e) = self.voter.require_local_vote(vote, backend) {
            self.halted = true;
            return Err(e.into());
        }
        self.voter.round_mut()?.observe(vote)?;
        Ok(())
    }
    /// True once the halting latch is set. Read-only; nothing resets it.
    pub fn is_halted(&self) -> bool {
        self.halted
    }
    /// True once the voter custody refuses every further operation: the poison that `refusal`, or a
    /// failure after custody was touched, sets. Read-only; only a reopen unpoisons the voter.
    pub fn voter_poisoned(&self) -> bool {
        self.voter.is_poisoned()
    }
    /// The armed precommit timeout as (height, round, monotonic deadline). Read-only.
    pub fn precommit_deadline(&self) -> Option<(u64, u64, Instant)> {
        self.precommit_deadline
    }
    /// The (height, round) this actor votes in now, read from the counter-protected record.
    /// Read-only; `Halted` for a halted actor.
    pub fn context(&self) -> Result<crate::voter_actor::VoteContext> {
        let (state, _, _) = self.progress()?;
        Ok(crate::voter_actor::VoteContext {
            height: self.height(),
            round: state.round,
        })
    }
    /// Classify a refusal raised by a PURE pre-check, i.e. before the latch was set and before any
    /// custody, reducer or counter state was touched.
    ///
    /// * Local time reasons are the explicit nonfatal result `TimeDeferred`; the latch is not
    ///   consulted or changed.
    /// * A request conflict (the request contradicts the sole durable decision stored for its
    ///   slot) or a halted reducer is a genuine safety condition: it halts the actor and poisons
    ///   the voter, exactly as it did when the same check ran after the latch. The latch and the
    ///   poison are in memory: nothing is written and no counter value is used. A request
    ///   conflict's only cause is the request, so a reopen resumes the intact stored decision; a
    ///   halted reducer's cause is durable (the record's `locks.halted` bit, which `check()`
    ///   refuses on every later open) (Architect decision V1).
    /// * Anything else (a proposal that is not re-executed yet, a malformed request) touched
    ///   nothing and stays recoverable.
    fn refusal(&mut self, e: CounterVoterError) -> ActorError {
        use crate::{bft::BftError, vote_clock_v1::TimeStatus};
        match e {
            CounterVoterError::Ingress(IngressError::FutureTimestamp { ahead_seconds }) => {
                ActorError::TimeDeferred(TimeStatus::Future { ahead_seconds })
            }
            CounterVoterError::Ingress(IngressError::ClockUnqualified) => {
                ActorError::TimeDeferred(TimeStatus::Unqualified)
            }
            CounterVoterError::ConflictingVote
            | CounterVoterError::Ingress(IngressError::Bft(BftError::IntegrityHalt)) => {
                self.halted = true;
                self.voter.poison();
                ActorError::Voter(e)
            }
            e => ActorError::Voter(e),
        }
    }
    fn activation_call_result<T>(&mut self,result:std::result::Result<T,CounterVoterError>)->Result<T>{
        match result {
            // Only CounterVoter's PURE activation refusal can reach this arm
            // without its poison latch. Post-mutation failures remain halted.
            Err(e @ CounterVoterError::Activation(_)) if !self.voter.is_poisoned()=>{
                self.halted=false;Err(ActorError::Voter(e))
            }
            result=>Ok(result?),
        }
    }
    /// Advisory scheduling only: classify through the SAME native pure gate.
    /// This mints no permission. The eventual sign repeats current authority,
    /// custody and time checks after the asynchronous installed-owner request.
    pub fn clock_query_required(
        &mut self,
        chain: &CanonicalStore,
        step: Step,
        block: Option<Hash>,
        pol: Option<u64>,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<bool> {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct Probe(AtomicBool);
        impl crate::vote_clock_v1::VoteClock for Probe {
            fn reading(&self) -> crate::vote_clock_v1::ClockReading {
                self.0.store(true, Ordering::SeqCst);
                crate::vote_clock_v1::ClockReading::Unqualified
            }
        }
        self.check_backend(chain, backend)?;
        let probe = Probe(AtomicBool::new(false));
        match self.voter.time_gate_with(&probe, step, block, pol) {
            Ok(()) => Ok(probe.0.load(Ordering::SeqCst)),
            Err(CounterVoterError::Ingress(IngressError::ClockUnqualified))
                if probe.0.load(Ordering::SeqCst) => Ok(true),
            Err(error) => Err(self.refusal(error)),
        }
    }
    pub fn sign(
        &mut self,
        chain: &CanonicalStore,
        step: Step,
        block: Option<Hash>,
        pol: Option<u64>,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<Vote> {
        let reading = self.voter.clock_reading();
        self.sign_using_clock(chain, step, block, pol, backend, &reading)
    }
    /// Scoped source owned only by this synchronous signing attempt. It is not
    /// installed as a reusable voter clock or persisted qualification Boolean.
    pub fn sign_with_clock(
        &mut self,
        chain: &CanonicalStore,
        step: Step,
        block: Option<Hash>,
        pol: Option<u64>,
        backend: &mut impl CounterSigningBackend,
        clock: std::sync::Arc<dyn crate::vote_clock_v1::VoteClock>,
    ) -> Result<Vote> {
        let reading = crate::vote_clock_v1::AttemptClock::new(clock);
        self.sign_using_clock(chain, step, block, pol, backend, &reading)
    }
    fn sign_using_clock(
        &mut self,
        chain: &CanonicalStore,
        step: Step,
        block: Option<Hash>,
        pol: Option<u64>,
        backend: &mut impl CounterSigningBackend,
        reading: &dyn crate::vote_clock_v1::VoteClock,
    ) -> Result<Vote> {
        // Rejects an already-halted actor first, so everything below starts with the latch clear.
        self.check_backend(chain, backend)?;
        // A time deferral/abstention must not halt the actor: the pure pre-check runs BEFORE the
        // latch, from ONE clock reading that `sign_at` reuses, so no time verdict can arise after
        // custody was touched and nothing has to be cleared again.
        if let Err(e) = self.voter.time_gate_with(reading, step, block, pol) {
            return Err(self.refusal(e));
        }
        if let Err(e)=self.voter.activation_gate(step,block,pol){return Err(self.refusal(e));}
        self.halted = true;
        let result=self.voter.sign_at(reading,step,block,pol,backend);
        let vote=self.activation_call_result(result)?;
        if !self.voter.matches_authority(&current(chain)?) {
            return Err(ActorError::Rollback);
        }
        self.arm_precommit(step, &vote);
        self.halted = false;
        Ok(vote)
    }
    /// `sign` for a request decided in `requested` (Architect decision V4), exactly as
    /// `voter_actor::VoterActor::sign_for`: after the backend check, a request for a context the
    /// actor has left is refused with the explicit, nonfatal `StaleContext`, before the clock, the
    /// latch, the reducer and custody are consulted.
    pub fn sign_for(
        &mut self,
        chain: &CanonicalStore,
        requested: crate::voter_actor::VoteContext,
        step: Step,
        block: Option<Hash>,
        pol: Option<u64>,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<Vote> {
        self.check_backend(chain, backend)?;
        let current = self.context()?;
        if current != requested {
            return Err(ActorError::StaleContext { requested, current });
        }
        self.sign(chain, step, block, pol, backend)
    }
    pub fn replay(
        &mut self,
        chain: &CanonicalStore,
        step: Step,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<Option<Vote>> {
        // Rejects an already-halted actor first, so everything below starts with the latch clear.
        self.check_backend(chain, backend)?;
        // A legacy UNMARKED unsigned reservation needs a qualified, eligible clock to complete. That
        // verdict is taken here, BEFORE the latch, from one reading that `replay_at` reuses: a
        // refusal for time is an explicit nonfatal result, so the latch is never set for it and
        // never has to be cleared again.
        let reading = self.voter.clock_reading();
        if let Err(e) = self.voter.replay_gate_at(&reading, step) {
            return Err(self.refusal(e));
        }
        if let Err(e)=self.voter.replay_activation_gate(step){return Err(self.refusal(e));}
        self.halted = true;
        let result=self.voter.replay_at(&reading,step,backend);
        let vote=self.activation_call_result(result)?;
        if !self.voter.matches_authority(&current(chain)?) {
            return Err(ActorError::Rollback);
        }
        if let Some(v) = &vote {
            self.arm_precommit(step, v);
        }
        self.halted = false;
        Ok(vote)
    }
    fn arm_precommit(&mut self, step: Step, vote: &Vote) {
        if step == Step::Precommit
            && self
                .precommit_deadline
                .as_ref()
                .is_none_or(|(h, r, _)| (*h, *r) != (vote.decision.height, vote.decision.round))
        {
            let seconds = 3u64
                .saturating_mul(1u64 << vote.decision.round.min(6))
                .min(120);
            self.precommit_deadline = Some((
                vote.decision.height,
                vote.decision.round,
                Instant::now() + Duration::from_secs(seconds),
            ));
        }
    }
    pub fn timeout_precommit(
        &mut self,
        chain: &CanonicalStore,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<Option<u64>> {
        self.check_backend(chain, backend)?;
        let Some((height, round, deadline)) = self.precommit_deadline else {
            return Ok(None);
        };
        if height != self.height() || self.voter.progress()?.0.round != round {
            self.precommit_deadline = None;
            return Ok(None);
        }
        if Instant::now() < deadline {
            return Ok(None);
        }
        // The reducer still requires quorum. Missing quorum is liveness
        // backpressure; backend failure poisons custody inside CounterVoter.
        let next = self.voter.timeout_precommit(backend)?;
        self.precommit_deadline = None;
        Ok(Some(next))
    }
}
#[cfg(test)]
mod activation_boundary_controls {
    //! Actual lower replay and latch response, modeled protected classification.
    //! No public native admission/canonical-chain/physical activation claim.
    use super::*;
    use std::sync::{Arc,atomic::{AtomicU64,Ordering}};
    struct Elapsed(AtomicU64);
    impl crate::activation_attestation_v1::Elapsed for Elapsed {
        fn elapsed(&self)->std::result::Result<Duration,crate::activation_attestation_v1::Failure>{
            Ok(Duration::from_secs(self.0.load(Ordering::SeqCst)))
        }
    }
    #[test]
    fn expiry_between_actor_precheck_and_lower_precheck_is_nonfatal_unchanged(){
        let (path,mut voter,mut backend)=crate::counter_voter_v2::activation_signer_tests::expiry_boundary_fixture();
        let elapsed=Arc::new(Elapsed(AtomicU64::new(0)));
        voter.install_software_activation_gate(crate::activation_attestation_v1::completed_software_gate(
            [9;32],[21;32],2,elapsed.clone()));
        let before=std::fs::read(path.join("voter.sqlite")).unwrap();let counter=backend.counter;
        let mut actor=VoterActor{voter,halted:false,precommit_deadline:None};
        actor.voter.replay_activation_gate(Step::Prevote).unwrap();
        actor.halted=true;elapsed.0.store(10,Ordering::SeqCst);
        let result=actor.voter.replay(Step::Prevote,&mut backend);
        assert!(matches!(actor.activation_call_result(result),Err(ActorError::Voter(
            CounterVoterError::Activation(crate::activation_attestation_v1::Failure::Expired)))));
        assert!(!actor.halted&&!actor.voter.is_poisoned());assert_eq!(backend.calls,0);assert_eq!(backend.counter,counter);
        assert_eq!(std::fs::read(path.join("voter.sqlite")).unwrap(),before);
        println!("PUBLIC TEST expiry-boundary evidence retained: {}",path.display());
        // Distinct post-mutation poison must never be cleared by this response.
        actor.halted=true;actor.voter.poison();
        let late:std::result::Result<(),CounterVoterError>=Err(CounterVoterError::Activation(
            crate::activation_attestation_v1::Failure::Expired));
        assert!(actor.activation_call_result(late).is_err());assert!(actor.halted&&actor.voter.is_poisoned());
    }
}
