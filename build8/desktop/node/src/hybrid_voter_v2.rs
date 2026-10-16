//! Candidate node owner for canonical state plus hybrid signing custody.
//! Production startup remains separately gated. The backend is consumed here,
//! retained exclusively and never exposed through the validator/transport API.
use crate::hybrid_runtime_v2::{HybridRuntime, Installation, RuntimeError};
use mutiny_consensus_v8::{
    Hash,
    bft::Step,
    block_envelope_v2::BlockEnvelope,
    continuity_v2::Vote,
    counter_voter_v2::{CounterSigningBackend, MigrationReceipt},
    voter_actor_v2::{ActorError, VoterActor},
};
use std::path::Path;
#[cfg(test)]
#[path = "hybrid_voter_v2_tests.rs"]
mod tests;
#[derive(Debug)]
pub enum VotingError {
    Runtime(RuntimeError),
    Actor(ActorError),
    Initialization(String),
    CandidateIngress(String),
}
impl From<RuntimeError> for VotingError {
    fn from(e: RuntimeError) -> Self {
        Self::Runtime(e)
    }
}
impl From<ActorError> for VotingError {
    fn from(e: ActorError) -> Self {
        Self::Actor(e)
    }
}
impl VotingError {
    /// True when a vote was withheld only for local time reasons (defer or abstain, never invalid).
    pub fn is_time_deferral(&self) -> bool {
        matches!(self, Self::Actor(e) if e.is_time_deferral())
    }
}
type Result<T> = std::result::Result<T, VotingError>;
#[derive(Debug)]
pub enum CustodyProgress {
    Ready { next_height: u64 },
    Stopped(ActorError),
}
#[derive(Debug)]
pub struct VotingInstallation {
    /// Canonical success remains visible even if subsequent custody work fails.
    pub canonical: Installation,
    pub custody: CustodyProgress,
}
/// Optional typed NodeWork custody capability. This grants no arbitrary signing
/// API. The application validates its exact current canonical candidate before
/// entry; the independently owned backend repeats validation at private-key entry.
pub trait NodeWorkSigningBackend: CounterSigningBackend {
    fn sign_current_node_work(&mut self, authority:mutiny_consensus_v8::work_authority_v2::Authority,
        body:&mutiny_consensus_v8::blocks::BlockBody)
        ->std::result::Result<mutiny_consensus_v8::work_authority_v2::Authority,String>;
}
pub struct VotingRuntime<B: CounterSigningBackend> {
    runtime: HybridRuntime,
    actor: VoterActor,
    backend: B,
    rotation_stopped: bool,
}
pub(crate) struct ExistingVotingRefusal<B:CounterSigningBackend>{cause:VotingError,
    owner:std::mem::ManuallyDrop<VotingRuntime<B>>}
impl<B:CounterSigningBackend> ExistingVotingRefusal<B>{
    pub(crate) fn cause(&self)->&VotingError{&self.cause}
    pub(crate) fn into_retained(self)->(VotingError,std::mem::ManuallyDrop<VotingRuntime<B>>){(self.cause,self.owner)}
}
/// Private factory-only settled ownership transfer, not public key access.
/// Each owner remains ManuallyDrop until its own consuming close succeeds.
pub(crate) struct ExistingVotingParts<B:CounterSigningBackend>{
    pub(crate) runtime:std::mem::ManuallyDrop<HybridRuntime>,
    pub(crate) store:std::mem::ManuallyDrop<mutiny_consensus_v8::counter_store_v2::CounterStore>,
    pub(crate) backend:std::mem::ManuallyDrop<B>,
}
impl<B: CounterSigningBackend> VotingRuntime<B> {
    /// Factory shutdown after the original private worker stops admission.
    /// This issues no join/close proof and performs no new signing operation.
    /// Unknown canonical/counter/backend state retains all original owners.
    pub(crate) fn into_existing_parts(self)
        ->std::result::Result<ExistingVotingParts<B>,ExistingVotingRefusal<B>>{
        let owner=std::mem::ManuallyDrop::new(self);
        if owner.rotation_stopped{return Err(ExistingVotingRefusal{cause:ActorError::Halted.into(),owner});}
        let Self{runtime,actor,backend,rotation_stopped}=std::mem::ManuallyDrop::into_inner(owner);
        let runtime=std::mem::ManuallyDrop::new(runtime);
        let mut backend=std::mem::ManuallyDrop::new(backend);
        match actor.into_existing_store(&runtime.chain,&mut *backend){
            Ok(store)=>Ok(ExistingVotingParts{runtime,store,backend}),
            Err(refusal)=>{let(cause,actor)=refusal.into_retained();
                Err(ExistingVotingRefusal{cause:cause.into(),owner:std::mem::ManuallyDrop::new(Self{
                    runtime:std::mem::ManuallyDrop::into_inner(runtime),actor:std::mem::ManuallyDrop::into_inner(actor),
                    backend:std::mem::ManuallyDrop::into_inner(backend),rotation_stopped})})}
        }
    }
    /// Factory composition of exclusively retained existing owners. Incoming
    /// runtime/actor/backend stay rooted on reconciliation error or unwind.
    /// This is no installed issuer: actual native leases/clock/custody remain
    /// owned by the private factory, and no key or backend is exported here.
    pub(crate) fn from_existing_actor(runtime:std::mem::ManuallyDrop<HybridRuntime>,
        actor:std::mem::ManuallyDrop<VoterActor>,backend:std::mem::ManuallyDrop<B>)
        ->std::result::Result<Self,ExistingVotingRefusal<B>>{
        let mut out=std::mem::ManuallyDrop::new(Self{
            runtime:std::mem::ManuallyDrop::into_inner(runtime),
            actor:std::mem::ManuallyDrop::into_inner(actor),
            backend:std::mem::ManuallyDrop::into_inner(backend),rotation_stopped:false});
        if let Err(cause)=out.reconcile(){return Err(ExistingVotingRefusal{cause,owner:out});}
        Ok(std::mem::ManuallyDrop::into_inner(out))
    }
    /// Normal backend route; every new NodeWork reservation and signature is
    /// committed through the SAME complete voter snapshot/NV counter.
    pub fn sign_reserved_node_work(&mut self,authority:mutiny_consensus_v8::work_authority_v2::Authority,
        body:&mutiny_consensus_v8::blocks::BlockBody)
        ->Result<mutiny_consensus_v8::work_authority_v2::Authority>{
        self.reconcile()?;
        if self.rotation_stopped{return Err(ActorError::Halted.into());}
        Ok(self.actor.sign_reserved_node_work(&self.runtime.chain,authority,body,&mut self.backend)?)
    }
    pub fn node_work_high_water(&mut self)->Result<u64>{
        self.reconcile()?;
        if self.rotation_stopped{return Err(ActorError::Halted.into());}
        Ok(self.actor.node_work_high_water(&self.runtime.chain,&mut self.backend)?)
    }
    /// Separate supervised host action. No network request can initialize or
    /// repair custody through the ordinary validator/install interface.
    pub fn initialize_after_recovery(
        mut runtime: HybridRuntime,
        path: &Path,
        node: Hash,
        parent: &mutiny_consensus_v8::anchors::FinalizedAnchor,
        commitment: Hash,
        pinned_counter: u64,
        mut backend: B,
    ) -> Result<Self> {
        // Authenticate the public ceremony context before reserving any file.
        runtime
            .chain
            .recovery_initialization_authority(parent, node, commitment)
            .map_err(ActorError::from)?;
        let actor = crate::custody_initialization::initialize(
            path,
            pinned_counter,
            &mut backend,
            |backend| {
                VoterActor::initialize_recovery(
                    path,
                    node,
                    parent,
                    commitment,
                    pinned_counter,
                    &mut runtime.chain,
                    backend,
                )
                .map_err(|e| format!("Recovery custody initialization: {e:?}"))
            },
        )
        .map_err(VotingError::Initialization)?;
        Ok(Self {
            runtime,
            actor,
            backend,
            rotation_stopped: false,
        })
    }
    /// Install the qualified local clock consulted before every fresh block vote
    /// (`block.timestamp <= qualified_local_UTC_now`). Fail-closed until one is installed.
    pub fn set_vote_clock(
        &mut self,
        clock: std::sync::Arc<dyn mutiny_consensus_v8::vote_clock_v1::VoteClock>,
    ) {
        self.actor.set_vote_clock(clock);
    }
    /// Pure local time eligibility of voting for an executed proposal right now. The caller owns
    /// scheduling: a deferred block must pass full current-context revalidation (this type's
    /// `sign` reconciles with canonical state first) before any vote; a due timer authorizes none.
    pub fn time_status(&self, block: Hash) -> mutiny_consensus_v8::vote_clock_v1::TimeStatus {
        self.actor.time_status(block)
    }
    pub fn signer_node(&self) -> Hash {
        self.actor.node()
    }
    pub fn sign_work_probe(
        &mut self,
        decision: &mutiny_consensus_v8::certificates::Decision,
    ) -> Result<mutiny_consensus_v8::liveness_v2::Fragment> {
        if self.rotation_stopped {
            return Err(ActorError::Halted.into());
        }
        Ok(self
            .actor
            .sign_work_probe(&self.runtime.chain, decision, &mut self.backend)?)
    }
    pub fn open_after_rotation(
        mut runtime: HybridRuntime,
        path: &Path,
        node: Hash,
        height: u64,
        mut backend: B,
    ) -> Result<Self> {
        let actor =
            VoterActor::open_after_rotation(path, node, height, &mut runtime.chain, &mut backend)?;
        Ok(Self {
            runtime,
            actor,
            backend,
            rotation_stopped: false,
        })
    }
    /// Host-local generation handoff. Prepared custody stays outside transport
    /// objects. Canonical success remains visible if migration/activation fails.
    pub fn install_with_rotation(
        &mut self,
        raw: &[u8],
        activate: impl FnOnce(&mut B, MigrationReceipt) -> std::result::Result<(), String>,
    ) -> Result<VotingInstallation> {
        let canonical = self.runtime.install(raw)?;
        let result = (|| -> std::result::Result<(), ActorError> {
            if self.rotation_stopped {
                return Err(ActorError::Halted);
            }
            // A retry after completed custody advancement must verify current
            // custody, but must not activate or increment the generation twice.
            if !canonical.inserted && canonical.finalized.height < self.actor.height() {
                return self.reconcile_actor();
            }
            // Remain stopped if a backend/callback unwinds. Only completion of
            // migration, activation and reconciliation clears this latch.
            self.rotation_stopped = true;
            let receipt = self
                .actor
                .rotate_finalized_generation(&mut self.runtime.chain, &mut self.backend)?;
            activate(&mut self.backend, receipt).map_err(|_| {
                ActorError::Voter(mutiny_consensus_v8::counter_voter::CounterVoterError::Backend)
            })?;
            self.actor
                .reconcile(&mut self.runtime.chain, &mut self.backend)
        })();
        let custody = match result {
            Ok(()) => {
                self.rotation_stopped = false;
                CustodyProgress::Ready {
                    next_height: self.actor.height(),
                }
            }
            Err(e) => {
                self.rotation_stopped = true;
                CustodyProgress::Stopped(e)
            }
        };
        Ok(VotingInstallation { canonical, custody })
    }
    pub fn open(
        mut runtime: HybridRuntime,
        path: &Path,
        node: Hash,
        initial: Option<u64>,
        mut backend: B,
    ) -> Result<Self> {
        let actor = VoterActor::open(path, node, initial, &mut runtime.chain, &mut backend)?;
        Ok(Self {
            runtime,
            actor,
            backend,
            rotation_stopped: false,
        })
    }
    /// Authenticated transport may update public canonical state. Every private
    /// operation below first reconciles against that state, including any block
    /// installed through this public interface between signing requests.
    pub fn validator(&mut self) -> &mut HybridRuntime {
        &mut self.runtime
    }
    pub fn reconcile(&mut self) -> Result<()> {
        self.reconcile_actor()?;
        Ok(())
    }
    fn reconcile_actor(&mut self) -> std::result::Result<(), ActorError> {
        // Activation callbacks may fail after changing their backend. Only an
        // explicit reopen with verified durable recovery may resume signing.
        if self.rotation_stopped {
            return Err(ActorError::Halted);
        }
        self.actor
            .reconcile(&mut self.runtime.chain, &mut self.backend)
    }
    pub fn install(&mut self, raw: &[u8]) -> Result<VotingInstallation> {
        let canonical = self.runtime.install(raw)?;
        let custody = match self.reconcile_actor() {
            Ok(()) => CustodyProgress::Ready {
                next_height: self.actor.height(),
            },
            Err(e) => CustodyProgress::Stopped(e),
        };
        Ok(VotingInstallation { canonical, custody })
    }
    pub fn validate_proposal(&mut self, block: &BlockEnvelope) -> Result<()> {
        self.reconcile()?;
        self.actor.validate_proposal(&self.runtime.chain, block)?;
        Ok(())
    }
    /// Restore at most one durably retained current-height proposal. This
    /// performs ordinary executed ingress and requests no vote or signature.
    pub fn restore_candidate(
        &mut self,
        journal: &crate::candidate_journal_v2::Journal,
        after: Option<Hash>,
    ) -> Result<Option<Hash>> {
        self.reconcile()?;
        let Some(record) = journal
            .next_current(&self.runtime, after)
            .map_err(VotingError::CandidateIngress)?
        else {
            return Ok(None);
        };
        self.actor.validate_candidate(
            &self.runtime.chain,
            mutiny_consensus_v8::voter_actor_v2::Proposal {
                header: &record.header,
                authority: &record.authority,
                body: &record.body,
            },
        )?;
        Ok(Some(record.header.block_hash()))
    }
    /// Restore one explicitly selected successor proposal through the same
    /// executed actor gate. Journal schema and transport kind grant no vote.
    pub fn restore_a2_candidate(
        &mut self,
        journal: &crate::candidate_journal_v3::Journal,
        after: Option<Hash>,
    ) -> Result<Option<Hash>> {
        self.reconcile()?;
        let Some(record) = journal
            .next_current(&self.runtime, after)
            .map_err(VotingError::CandidateIngress)?
        else {
            return Ok(None);
        };
        self.actor.validate_candidate(
            &self.runtime.chain,
            mutiny_consensus_v8::voter_actor_v2::Proposal {
                header: &record.header,
                authority: &record.authority,
                body: &record.body,
            },
        )?;
        Ok(Some(record.header.block_hash()))
    }
    pub fn sign(&mut self, step: Step, block: Option<Hash>, pol: Option<u64>) -> Result<Vote> {
        self.reconcile()?;
        Ok(self
            .actor
            .sign(&self.runtime.chain, step, block, pol, &mut self.backend)?)
    }
    /// Schedule a fresh owner request through the native gate, including its
    /// existing exact-replay exemptions and conflict response. No authorization
    /// or time value is returned by this advisory classification.
    pub(crate) fn clock_query_required(&mut self, step:Step, block:Option<Hash>, pol:Option<u64>)
        ->Result<bool> {
        self.reconcile()?;
        Ok(self.actor.clock_query_required(&self.runtime.chain,step,block,pol,&mut self.backend)?)
    }
    /// Exclusive ordinary-worker route. The connection is consumed while an
    /// authenticated request is pending, and returned only after exact current
    /// receipt closure. Nil and durable exact replay do not issue an RPC.
    /// Dropping this future invokes the installed channel's sticky quarantine.
    pub(crate) async fn sign_with_installed_clock(
        &mut self,
        query: crate::host_clock::InstalledNodeClockQuery,
        step:Step,
        block:Option<Hash>,
        pol:Option<u64>,
    )->InstalledVoteOutcome {
        use std::sync::{Arc,Mutex};
        use mutiny_consensus_v8::vote_clock_v1::{ClockReading,VoteClock};
        struct CurrentAttempt {
            inner:Mutex<crate::host_clock::PreparedNodeClockAttempt>,
        }
        impl VoteClock for CurrentAttempt {
            fn reading(&self)->ClockReading {
                match self.inner.lock() {
                    Ok(mut attempt)=>attempt.reading().unwrap_or(ClockReading::Unqualified),
                    Err(_)=>ClockReading::Unqualified,
                }
            }
        }
        match self.clock_query_required(step,block,pol) {
            Ok(false)=>return InstalledVoteOutcome{vote:self.sign(step,block,pol),query:Some(query)},
            Err(error)=>return InstalledVoteOutcome{vote:Err(error),query:Some(query)},
            Ok(true)=>{},
        }
        let prepared=match query.prepare().await {
            Ok(prepared)=>prepared,
            Err(error)=>return InstalledVoteOutcome{vote:Err(VotingError::Initialization(
                format!("installed clock request: {}",error.description()))),query:None},
        };
        let current=Arc::new(CurrentAttempt{inner:Mutex::new(prepared)});
        // No suspension occurs between this source's current reconstruction and
        // the native synchronous gate/custody route. Native signing repeats the
        // canonical/backend checks after the request, using one lazy sample.
        let vote=match self.reconcile() {
            Ok(())=>self.actor.sign_with_clock(&self.runtime.chain,step,block,pol,
                &mut self.backend,current.clone()).map_err(VotingError::from),
            Err(error)=>Err(error),
        };
        // The scoped native source is not installed on the voter. No external
        // Arc escapes; inability to recover exclusive receipt custody refuses.
        let prepared=match Arc::try_unwrap(current) {
            Ok(current)=>match current.inner.into_inner() {
                Ok(prepared)=>prepared,
                Err(poisoned)=>{
                    drop(poisoned.into_inner());
                    return InstalledVoteOutcome{vote:Err(VotingError::Initialization(
                        "installed clock attempt mutex poisoned; channel quarantined".into())),query:None};
                },
            },
            Err(retained)=>{
                drop(retained);
                return InstalledVoteOutcome{vote:Err(VotingError::Initialization(
                    "installed clock attempt exclusivity lost; channel quarantined".into())),query:None};
            },
        };
        match prepared.finish() {
            Ok(query)=>InstalledVoteOutcome{vote,query:Some(query)},
            Err(error)=>InstalledVoteOutcome{vote:Err(VotingError::Initialization(
                format!("installed clock attempt final recheck: {}",error.description()))),query:None},
        }
    }
    pub fn configure_activation(&mut self,lifetime:std::time::Duration,
        elapsed:std::sync::Arc<dyn mutiny_consensus_v8::activation_attestation_v1::Elapsed>)->Result<()> {
        self.reconcile()?;self.actor.configure_activation(lifetime,elapsed)?;Ok(())
    }
    pub fn cancel_activation(&mut self){self.actor.cancel_activation();}
    pub fn activation_request(&mut self,step:Step,block:Option<Hash>,pol:Option<u64>)
        ->Result<Option<mutiny_consensus_v8::activation_attestation_v1::Request>> {
        self.reconcile()?;Ok(self.actor.activation_request(step,block,pol)?)
    }
    pub fn begin_activation(&mut self,step:Step,block:Option<Hash>,pol:Option<u64>,
        materials:&[mutiny_consensus_v8::activation_attestation_v1::Material],
        provider:&mut dyn mutiny_consensus_v8::activation_attestation_v1::CurrentContext,
        adapter:&mut dyn mutiny_consensus_v8::activation_attestation_v1::MakeCredential)
        ->Result<mutiny_consensus_v8::activation_attestation_v1::Exchange> {
        self.reconcile()?;
        Ok(self.actor.begin_activation(&self.runtime.chain,step,block,pol,materials,provider,adapter,&mut self.backend)?)
    }
    pub fn complete_activation(&mut self,session:Hash,
        request:&mutiny_consensus_v8::activation_attestation_v1::Request,
        responses:Vec<mutiny_consensus_v8::activation_attestation_v1::RecoveryResponse>,
        provider:&mut dyn mutiny_consensus_v8::activation_attestation_v1::CurrentContext)->Result<()> {
        self.reconcile()?;
        self.actor.complete_activation(&self.runtime.chain,session,request,responses,provider,&mut self.backend)?;Ok(())
    }
    pub fn replay(&mut self, step: Step) -> Result<Option<Vote>> {
        self.reconcile()?;
        Ok(self
            .actor
            .replay(&self.runtime.chain, step, &mut self.backend)?)
    }
    pub fn observe(&mut self, vote: &Vote) -> Result<()> {
        self.reconcile()?;
        self.actor
            .observe(&self.runtime.chain, vote, &mut self.backend)?;
        Ok(())
    }
    pub fn timeout_precommit(&mut self) -> Result<Option<u64>> {
        self.reconcile()?;
        Ok(self
            .actor
            .timeout_precommit(&self.runtime.chain, &mut self.backend)?)
    }
}

/// A signed outcome may already be durable even if the later installed-clock
/// final recheck refuses. Such refusal never erases its native reservation;
/// the next exact replay follows the established durable replay path.
pub(crate) struct InstalledVoteOutcome {
    pub(crate) vote:Result<Vote>,
    pub(crate) query:Option<crate::host_clock::InstalledNodeClockQuery>,
}

impl<B:NodeWorkSigningBackend> VotingRuntime<B> {
    /// Actual exclusive worker route: public preparation is revalidated against
    /// this owner's current canonical state before durable private Node custody.
    pub fn sign_node_work(&mut self,authority:mutiny_consensus_v8::work_authority_v2::Authority,
        body:&mutiny_consensus_v8::blocks::BlockBody)
        ->Result<mutiny_consensus_v8::work_authority_v2::Authority>{
        self.reconcile()?;
        if self.rotation_stopped{return Err(ActorError::Halted.into());}
        let parent=self.runtime.head()?;
        self.runtime.chain.validate_node_work(&parent,self.actor.node(),&authority,body)
            .map_err(ActorError::from)?;
        let message=authority.unsigned().map_err(|e|VotingError::Initialization(format!("NodeWork request: {e:?}")))?;
        let descriptor=authority.node_descriptor.clone();
        let signed=self.backend.sign_current_node_work(authority,body)
            .map_err(|e|VotingError::Initialization(format!("NodeWork custody: {e}")))?;
        if signed.unsigned().map_err(|e|VotingError::Initialization(format!("NodeWork response: {e:?}")))?!=message{
            return Err(VotingError::Initialization("NodeWork custody changed exact request".into()));
        }
        // Signature verification and a fresh canonical check precede reporting
        // success; a durable stale reservation remains recorded on refusal.
        self.runtime.chain.validate_node_work(&parent,self.actor.node(),&signed,body)
            .map_err(ActorError::from)?;
        let(context,_)=self.runtime.chain.current_work_context(&parent,signed.work.candidate.license,
            signed.work.candidate.worker,signed.work.candidate.timestamp).map_err(ActorError::from)?;
        let header=mutiny_consensus_v8::pow::WorkHeader{candidate:signed.work.candidate.clone(),
            authority:signed.id().map_err(|e|VotingError::Initialization(format!("NodeWork response identity: {e:?}")))?,
            nonce:signed.work.nonce_start};
        signed.verify(&header,&context,&descriptor)
            .map_err(|e|VotingError::Initialization(format!("NodeWork signature/context: {e:?}")))?;
        Ok(signed)
    }
}
