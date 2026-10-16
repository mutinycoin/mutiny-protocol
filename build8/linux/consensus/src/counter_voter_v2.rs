//! Candidate hybrid voter custody. Locks, sequence and complete dual signatures
//! share ONE TPM-counter-protected snapshot; no separately rollbackable journal.
//! No production signing backend or canonical registry migration is enabled here.
use crate::{
    Error, Hash,
    bft::{LockState, Step},
    bft_store,
    continuity_v2::Vote,
    counter_store_v2::{CounterStore, MonotonicCounter},
    counter_voter::CounterVoterError,
    votes_v2::{AuthenticatedRound, HeightAuthority},
};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::{HybridSignature, PublicKey};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};
type Result<T> = std::result::Result<T, CounterVoterError>;
const MAX_SNAPSHOT: usize = 4 * 1024 * 1024;
const MAX_RESERVATIONS: usize = 1024;
#[path="node_work_state.rs"]
mod node_work_state;
pub use node_work_state::NodeWorkPermit;
use node_work_state::WorkState;
pub trait CounterSigningBackend: MonotonicCounter {
    fn public_key(&self) -> &PublicKey;
    /// Continuity-only software keys, bound to the admitted TPM identity.
    /// The backend retains the exclusive host lock and qualified encrypted
    /// custody. It signs Domain::ContinuityVote with BOTH algorithms.
    fn sign_vote(&mut self, message: &[u8]) -> std::result::Result<HybridSignature, String>;
    /// Normal custody overrides this opaque-permit boundary. Compatibility
    /// backends are trusted TEST adapters; no caller flag can construct permit.
    fn sign_reserved_vote(&mut self,message:&[u8],_permit:&crate::activation_attestation_v1::PrivateSignPermit)
        ->std::result::Result<HybridSignature,String>{self.sign_vote(message)}
    /// Optional, separately domain-bound liveness capability. Existing backends
    /// fail closed until explicitly qualified. It must not increment the counter.
    fn sign_work_probe(
        &mut self,
        _decision: &crate::certificates::Decision,
        _fragment: &crate::liveness_v2::Fragment,
    ) -> std::result::Result<HybridSignature, String> {
        Err("Hybrid work-liveness signing unavailable".into())
    }
    /// Normal NodeWork custody accepts only a permit from this same complete
    /// counter-protected snapshot. Existing adapters get no raw-sign fallback.
    fn sign_reserved_node_work(&mut self,_authority:crate::work_authority_v2::Authority,
        _body:&crate::blocks::BlockBody,_permit:&NodeWorkPermit)
        ->std::result::Result<crate::work_authority_v2::Authority,String>{
        Err("Reserved NodeWork custody unavailable".into())
    }
}
/// Version 5 adds local NodeWork reservations to the SAME NV-anchored snapshot.
/// Versions 2/3/4 remain byte-exact; absent work history is unknown for new work.
/// Version 4 adds counter-protected PUBLIC executed admission classification,
/// never a private activation cache. Versions 2/3 remain byte-exactly readable.
/// Version 3 adds the per-slot `gated` marker: the reservation was created only after the fresh
/// qualified-clock guard passed for exactly the stored decision. Version 2 records stay readable
/// but carry no marker, so an unsigned legacy reservation gets no clock exemption.
struct Snapshot {
    height: u64,
    last_sequence: u64,
    parent: Hash,
    roots: [Hash; 3],
    locks: LockState,
    votes: BTreeMap<(u64, u8), (Vote, bool)>,
    gated: BTreeSet<(u64, u8)>,
    classifications: BTreeMap<(u64,u8),crate::activation_attestation_v1::Classification>,
    successor: bool,
    work:Option<WorkState>,
    /// Decoded from a version-2 record; re-encoded byte-exactly as version 2 until rewritten.
    legacy: bool,
}
fn zero_signature() -> HybridSignature {
    HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    }
}
impl Snapshot {
    fn empty(round: &AuthenticatedRound, last_sequence: u64) -> crate::Result<Self> {
        Ok(Self {
            height: round.height()?,
            last_sequence,
            parent: round.authority().parent.id(),
            roots: round.authority().roots(),
            locks: round.machine().state().clone(),
            votes: BTreeMap::new(),
            gated: BTreeSet::new(),
            classifications:BTreeMap::new(),
            successor:round.authority().activation_rule.is_some(),
            work:round.authority().activation_rule.map(|_|WorkState::new()),
            legacy: false,
        })
    }
    /// Exempt from today's clock only if the reservation passed the fresh guard (marker) or is
    /// already completely signed (retransmission).
    fn clock_exempt(&self, slot: &(u64, u8)) -> bool {
        match self.votes.get(slot) {
            Some((_, signed)) => *signed || self.gated.contains(slot),
            None => false,
        }
    }
    fn encode(&self) -> crate::Result<Vec<u8>> {
        if self.votes.len() > MAX_RESERVATIONS {
            return Err(Error::Capacity);
        }
        let mut e = Encoder::new(Vec::new());
        if self.work.is_some() && (self.legacy||!self.successor){return Err(Error::Codec);}
        e.array(if self.work.is_some(){8}else{7})
            .unwrap()
            .u8(if self.work.is_some(){5}else if self.legacy { 2 } else if self.successor {4} else { 3 })
            .unwrap()
            .u64(self.height)
            .unwrap()
            .u64(self.last_sequence)
            .unwrap()
            .bytes(&self.parent)
            .unwrap()
            .array(3)
            .unwrap();
        for r in &self.roots {
            e.bytes(r).unwrap();
        }
        e.bytes(&bft_store::encode(&self.locks))
            .unwrap()
            .array(self.votes.len() as u64)
            .unwrap();
        for ((round, step), (vote, signed)) in &self.votes {
            e.array(if self.legacy { 4 } else if self.successor {6} else { 5 })
                .unwrap()
                .u64(*round)
                .unwrap()
                .u8(*step)
                .unwrap()
                .bytes(&vote.encode()?)
                .unwrap()
                .bool(*signed)
                .unwrap();
            if !self.legacy {
                e.bool(self.gated.contains(&(*round, *step))).unwrap();
            }
            if self.successor {
                use crate::activation_attestation_v1::Classification;
                match self.classifications.get(&(*round,*step)).copied().unwrap_or(Classification::Unknown){
                    Classification::Unknown=>{e.array(1).unwrap().u8(0).unwrap();},
                    Classification::NoAdmission=>{e.array(1).unwrap().u8(1).unwrap();},
                    Classification::Required(scope)=>{e.array(2).unwrap().u8(2).unwrap().bytes(&scope).unwrap();},
                }
            }
        }
        if let Some(work)=&self.work{e.bytes(&work.encode()?).unwrap();}
        let raw = e.into_writer();
        if raw.len() > MAX_SNAPSHOT {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    fn decode(raw: &[u8]) -> crate::Result<Self> {
        crate::blocks::canonical(raw, MAX_SNAPSHOT)?;
        let mut d = Decoder::new(raw);
        let s = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("hybrid voter snapshot");
            let array=d.array()?;
            let (legacy,successor,has_work) = match (array,d.u8()?) {
                (Some(7),2) => (true,false,false),
                (Some(7),3) => (false,false,false),
                (Some(7),4) => (false,true,false),
                (Some(8),5) => (false,true,true),
                _ => return Err(bad()),
            };
            let height = d.u64()?;
            let last_sequence = d.u64()?;
            let parent = d.bytes()?.try_into().map_err(|_| bad())?;
            if d.array()? != Some(3) {
                return Err(bad());
            }
            let roots = [
                d.bytes()?.try_into().map_err(|_| bad())?,
                d.bytes()?.try_into().map_err(|_| bad())?,
                d.bytes()?.try_into().map_err(|_| bad())?,
            ];
            let locks = bft_store::decode(d.bytes()?).map_err(|_| bad())?;
            let count = d.array()?.ok_or_else(bad)?;
            if count > MAX_RESERVATIONS as u64 || height == 0 {
                return Err(bad());
            }
            let mut votes = BTreeMap::new();
            let mut gated = BTreeSet::new();
            let mut classifications=BTreeMap::new();
            let mut sequences = BTreeSet::new();
            for _ in 0..count {
                if d.array()? != Some(if legacy { 4 } else if successor {6} else { 5 }) {
                    return Err(bad());
                }
                let round = d.u64()?;
                let step = d.u8()?;
                let vote = Vote::decode(d.bytes()?).map_err(|_| bad())?;
                let signed = d.bool()?;
                if !legacy && d.bool()? {
                    gated.insert((round, step));
                }
                if successor {
                    use crate::activation_attestation_v1::Classification;
                    let count=d.array()?.ok_or_else(bad)?;
                    let classification=match (count,d.u8()?){
                        (1,0)=>Classification::Unknown,(1,1)=>Classification::NoAdmission,
                        (2,2)=>Classification::Required(d.bytes()?.try_into().map_err(|_|bad())?),
                        _=>return Err(bad()),
                    };
                    classifications.insert((round,step),classification);
                }
                if !matches!(step, 2 | 3)
                    || vote.decision.height != height
                    || vote.decision.round != round
                    || vote.decision.step != step
                    || vote.sequence > last_sequence
                    || !sequences.insert(vote.sequence)
                    || round > locks.round
                    || (!signed && vote.signature != zero_signature())
                    || votes.insert((round, step), (vote, signed)).is_some()
                {
                    return Err(bad());
                }
            }
            let work=if has_work{Some(WorkState::decode(d.bytes()?).map_err(|_|bad())?)}else{None};
            Ok(Self {
                height,
                last_sequence,
                parent,
                roots,
                locks,
                votes,
                gated,
                legacy,
                successor,
                classifications,
                work,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if d.position() != raw.len() || s.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(s)
    }
    fn validate(&self, authority: &HeightAuthority, node: Hash) -> crate::Result<()> {
        if authority.parent.height.checked_add(1) != Some(self.height)
            || self.parent != authority.parent.id()
            || self.roots != authority.roots()
            || (self.successor && authority.activation_rule.is_none())
        {
            return Err(Error::WrongAnchor);
        }
        if let Some(work)=&self.work{work.validate(&authority.parent)?;}
        for (v, signed) in self.votes.values() {
            if v.node != node {
                return Err(Error::UnknownSigner);
            }
            v.validate_authority(&authority.parent, authority.roots(), &authority.voters)?;
            if *signed {
                v.verify(&authority.parent, authority.roots(), &authority.voters)?;
            }
        }
        if self.classifications.keys().any(|slot|!self.votes.contains_key(slot))
            || self.classifications.iter().any(|(slot,c)|{
                self.votes.get(slot).is_some_and(|(v,_)|v.nil)
                    && matches!(c,crate::activation_attestation_v1::Classification::Required(_))
            }){return Err(Error::Codec);}
        Ok(())
    }
}
/// Unforgeable through the public API; issued only after verified canonical
/// rotation and durable counter/context installation. Consumed by activation.
pub struct MigrationReceipt {
    previous: Hash,
    current: Hash,
    counter: u64,
}
impl MigrationReceipt {
    pub fn previous(&self) -> Hash {
        self.previous
    }
    pub fn current(&self) -> Hash {
        self.current
    }
    pub fn counter(&self) -> u64 {
        self.counter
    }
}
fn slot_of(round: &AuthenticatedRound, step: Step) -> (u64, u8) {
    (
        round.machine().state().round,
        match step {
            Step::Prevote => 2,
            Step::Precommit => 3,
        },
    )
}
pub struct CounterVoter {
    round: AuthenticatedRound,
    store: CounterStore,
    snapshot: Snapshot,
    node: Hash,
    context: Hash,
    poisoned: bool,
    /// Qualified local clock for fresh block votes. Fail-closed until one is installed.
    clock: std::sync::Arc<dyn crate::vote_clock_v1::VoteClock>,
    activation:crate::activation_attestation_v1::Gate,
    activation_rule:Option<Hash>,
}
pub struct ExistingVoterRefusal {cause:CounterVoterError,store:std::mem::ManuallyDrop<CounterStore>}
impl ExistingVoterRefusal {
    pub fn cause(&self)->&CounterVoterError{&self.cause}
    pub fn into_retained(self)->(CounterVoterError,std::mem::ManuallyDrop<CounterStore>){(self.cause,self.store)}
}
pub struct ExistingVoterShutdownRefusal {cause:CounterVoterError,voter:std::mem::ManuallyDrop<CounterVoter>}
impl ExistingVoterShutdownRefusal {
    pub fn into_retained(self)->(CounterVoterError,std::mem::ManuallyDrop<CounterVoter>){(self.cause,self.voter)}
}
impl CounterVoter {
    /// Consume the settled voter only after its owning private worker has
    /// stopped admitting requests. This checks the same backend and durable
    /// snapshot; it grants no worker-join or native-close receipt.
    pub fn into_existing_store(self,backend:&mut impl CounterSigningBackend)
        ->std::result::Result<std::mem::ManuallyDrop<CounterStore>,ExistingVoterShutdownRefusal>{
        let mut voter=std::mem::ManuallyDrop::new(self);
        if let Err(cause)=voter.check(backend){return Err(ExistingVoterShutdownRefusal{cause,voter});}
        let Self{store,clock,activation,..}=std::mem::ManuallyDrop::into_inner(voter);
        let store=std::mem::ManuallyDrop::new(store);
        // Release only local clock/gate references. The native session remains
        // owned by the factory until its original I/O worker is joined/closed.
        drop(activation);drop(clock);Ok(store)
    }
    /// Resume an already recovered exact V2 store owned by the native factory.
    /// No filename/CREATE/initial counter or caller-provided snapshot is used.
    pub fn from_existing_store(mut store:std::mem::ManuallyDrop<CounterStore>,
        authority:HeightAuthority,node:Hash,backend:&mut impl CounterSigningBackend)
        ->std::result::Result<Self,ExistingVoterRefusal>{
        let inspected=(||->Result<_>{
            let round=AuthenticatedRound::new(authority.clone())?;
            let context=round.signing_context(node)?;
            if store.context()!=context{return Err(Error::WrongGeneration.into());}
            if &authority.voters.get(&node).ok_or(Error::UnknownSigner)?.public!=backend.public_key(){
                return Err(Error::WrongGeneration.into());}
            store.verify_current(backend)?;
            let snapshot=Snapshot::decode(store.snapshot())?;
            snapshot.validate(&authority,node)?;
            let activation_rule=authority.activation_rule;
            let round=AuthenticatedRound::restore(authority,snapshot.locks.clone())?;
            Ok((round,context,snapshot,activation_rule))
        })();
        let(round,context,snapshot,activation_rule)=match inspected{Ok(value)=>value,
            Err(cause)=>return Err(ExistingVoterRefusal{cause,store})};
        Ok(Self{round,store:std::mem::ManuallyDrop::into_inner(store),snapshot,node,context,
            poisoned:false,clock:crate::vote_clock_v1::unqualified(),activation:Default::default(),activation_rule})
    }
    /// Bounded canonical snapshot decoding only, not an authority or NV check.
    pub fn existing_store_height(store:&CounterStore)->Result<u64>{
        Ok(Snapshot::decode(store.snapshot())?.height)
    }
    /// Install the qualified local clock consulted before every FRESH block vote
    /// (`block.timestamp <= qualified_local_UTC_now`; zero additional allowance).
    pub fn set_vote_clock(&mut self, clock: std::sync::Arc<dyn crate::vote_clock_v1::VoteClock>) {
        self.clock = clock;
    }
    /// Time gate for a FRESH block vote: changes no reducer, custody or counter state and does not
    /// poison. A slot that already holds a durable reservation was gated when it was created and is
    /// not a fresh vote. Nil votes are not time-dependent.
    pub fn time_gate(
        &self,
        step: Step,
        proposal: Option<Hash>,
        pol_round: Option<u64>,
    ) -> Result<()> {
        let reading = self.clock_reading();
        self.time_gate_with(&reading, step, proposal, pol_round)
    }
    /// One lazy attempt-local sample. A signing or completion attempt reads the clock AT MOST ONCE and
    /// judges every gate of that attempt, including the owning actor's pre-latch check, with this
    /// same reading, so a clock that changes between two reads can neither defer after custody was
    /// touched nor admit what the pre-check refused.
    pub(crate) fn clock_reading(&self) -> crate::vote_clock_v1::AttemptClock {
        crate::vote_clock_v1::AttemptClock::new(self.clock.clone())
    }
    /// Fail closed after a pure pre-check found a request conflict (a request that contradicts the
    /// stored durable decision of its slot) or a halted reducer: the voter refuses every further
    /// operation until it is reopened and revalidated. In memory only: nothing is written and no
    /// counter value is used (Architect decision V1). The durable halt bit written by
    /// `require_local_vote` for a valid own vote that custody never issued is a different cause.
    pub(crate) fn poison(&mut self) {
        self.poisoned = true;
    }
    /// True while this voter refuses every operation for the in-memory poison. Read-only: only a
    /// reopen, which revalidates the durable record, yields an unpoisoned voter. A durable halt
    /// bit (`progress().0.halted`) refuses every operation as well and is re-derived on every open.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    /// The gate judges the block the reducer would actually vote (a held lock included), against
    /// one fixed clock reading supplied by the caller. Pure: it never mutates the reducer or custody.
    pub(crate) fn time_gate_with(
        &self,
        clock: &dyn crate::vote_clock_v1::VoteClock,
        step: Step,
        proposal: Option<Hash>,
        pol_round: Option<u64>,
    ) -> Result<()> {
        let slot = slot_of(&self.round, step);
        // ANY existing reservation (guard-marked, signed, or an unmarked legacy record) is compared
        // with the decision the reducer would produce now BEFORE the clock is consulted, so a
        // request that contradicts it is a request conflict under every clock (the one durable
        // decision stands and the request is refused; it is not evidence of two durable
        // decisions), never a time deferral. A matching request is exempt from the clock only when
        // the reservation carries the durable guard marker (or is signed); a matching unmarked
        // legacy block reservation still needs a qualified, eligible clock (nil needs none).
        let exempt = if self.snapshot.votes.contains_key(&slot) {
            let would = self.round.vote_block(step, proposal, pol_round)?;
            if !self.bound_to(&slot, would) {
                return Err(CounterVoterError::ConflictingVote);
            }
            self.snapshot.clock_exempt(&slot)
        } else {
            false
        };
        self.round.time_gate(
            if exempt {
                crate::vote_clock_v1::VoteGate::reserved()
            } else {
                crate::vote_clock_v1::VoteGate::Fresh(clock)
            },
            step,
            proposal,
            pol_round,
        )?;
        Ok(())
    }
    /// The stored decision names exactly this block (or nil).
    fn bound_to(&self, slot: &(u64, u8), block: Option<Hash>) -> bool {
        self.snapshot.votes.get(slot).is_some_and(|(v, _)| {
            v.nil == block.is_none() && v.decision.block == block.unwrap_or([0; 32])
        })
    }
    /// Pure local eligibility of voting for an executed proposal right now.
    pub fn time_status(&self, block: Hash) -> crate::vote_clock_v1::TimeStatus {
        self.round.time_status(&*self.clock, block)
    }
    fn activation_classification(&self,slot:(u64,u8),block:Option<Hash>)
        ->Result<crate::activation_attestation_v1::Classification>{
        use crate::activation_attestation_v1::Classification;
        if self.round.authority().activation_rule.is_none() || block.is_none(){return Ok(Classification::NoAdmission);}
        let block=block.unwrap();
        match self.round.activation_scope(block){
            Ok(scope)=>Ok(scope.map_or(Classification::NoAdmission,|s|Classification::Required(s.commitment()))),
            Err(_)=>Ok(self.snapshot.classifications.get(&slot).copied().unwrap_or(Classification::Unknown)),
        }
    }
    fn activation_check_block(&mut self,slot:(u64,u8),block:Option<Hash>)->Result<()> {
        use crate::activation_attestation_v1::{Classification,Failure};
        if self.snapshot.votes.get(&slot).is_some_and(|(_,signed)|*signed){return Ok(());}
        match self.activation_classification(slot,block)?{
            Classification::NoAdmission=>Ok(()),
            Classification::Unknown=>Err(CounterVoterError::Activation(Failure::Missing)),
            Classification::Required(scope)=>self.activation.check(self.node,scope,slot.0,slot.1)
                .map_err(CounterVoterError::Activation),
        }
    }
    /// Pure with respect to reducer/reservations/counter. Elapsed failure may
    /// cancel LOCAL private material; refusal cannot manufacture a vote/NIL.
    pub(crate) fn activation_gate(&mut self,step:Step,proposal:Option<Hash>,pol:Option<u64>)->Result<()> {
        let slot=slot_of(&self.round,step);
        let block=self.round.vote_block(step,proposal,pol)?;
        self.activation_check_block(slot,block)
    }
    pub(crate) fn replay_activation_gate(&mut self,step:Step)->Result<()> {
        let slot=self.replay_slot(step);
        let Some((vote,_))=self.snapshot.votes.get(&slot) else{return Ok(());};
        let block=(!vote.nil).then_some(vote.decision.block);
        self.activation_check_block(slot,block)
    }
    pub fn configure_activation(&mut self,lifetime:std::time::Duration,
        elapsed:std::sync::Arc<dyn crate::activation_attestation_v1::Elapsed>)->Result<()> {
        if self.poisoned||self.snapshot.locks.halted{return Err(CounterVoterError::Poisoned);}
        self.activation.configure(lifetime,elapsed).map_err(CounterVoterError::Activation)
    }
    /// Owner-local cancellation only. It neither edits reservations/locks nor
    /// revokes any canonical key or discards previous failed evidence.
    pub fn cancel_activation(&mut self){self.activation.invalidate();}
    #[cfg(test)]
    pub(crate) fn install_software_activation_gate(&mut self,gate:crate::activation_attestation_v1::Gate){
        self.activation=gate;
    }
    /// Only an independently native-executed proposal can yield this request.
    /// The actual reducer lock, not the requested proposal, selects its scope.
    pub fn activation_request(&self,step:Step,proposal:Option<Hash>,pol:Option<u64>)
        ->Result<Option<crate::activation_attestation_v1::Request>> {
        if self.poisoned||self.snapshot.locks.halted{return Err(CounterVoterError::Poisoned);}
        let Some(block)=self.round.vote_block(step,proposal,pol)? else{return Ok(None);};
        let Some(scope)=self.round.activation_scope(block)? else{return Ok(None);};
        let slot=slot_of(&self.round,step);
        Ok(Some(crate::activation_attestation_v1::Request::new(scope.clone(),self.node,slot.0,slot.1)))
    }
    pub fn begin_activation(&mut self,step:Step,proposal:Option<Hash>,pol:Option<u64>,
        materials:&[crate::activation_attestation_v1::Material],
        provider:&mut dyn crate::activation_attestation_v1::CurrentContext,
        adapter:&mut dyn crate::activation_attestation_v1::MakeCredential)
        ->Result<crate::activation_attestation_v1::Exchange> {
        let request=self.activation_request(step,proposal,pol)?
            .ok_or(CounterVoterError::Activation(crate::activation_attestation_v1::Failure::Scope))?;
        self.activation.begin(request,materials,provider,adapter).map_err(CounterVoterError::Activation)
    }
    pub fn complete_activation(&mut self,session:Hash,request:&crate::activation_attestation_v1::Request,
        responses:Vec<crate::activation_attestation_v1::RecoveryResponse>,
        provider:&mut dyn crate::activation_attestation_v1::CurrentContext)->Result<()> {
        // Request must still be native-known in this exact local round. Public
        // request bytes/cache after restart cannot authorize completion.
        let step=match request.step(){2=>Step::Prevote,3=>Step::Precommit,_=>{
            self.activation.invalidate();return Err(CounterVoterError::Activation(crate::activation_attestation_v1::Failure::Scope));
        }};
        let slot=slot_of(&self.round,step);
        let actual=self.round.activation_scope(request.scope().block()).ok().flatten()
            .map(|scope|crate::activation_attestation_v1::Request::new(scope.clone(),self.node,slot.0,slot.1));
        if actual.as_ref()!=Some(request){
            self.activation.invalidate();return Err(CounterVoterError::Activation(crate::activation_attestation_v1::Failure::Scope));
        }
        self.activation.complete(session,request,responses,provider).map_err(CounterVoterError::Activation)
    }
    /// Prototype: migrate exactly at the canonical software-rotation tip. The
    /// chain supplies both authorities; arbitrary descriptors cannot rebind a
    /// journal. Old own certificate votes must already be durably reserved.
    pub fn rotate_finalized(
        &mut self,
        chain: &mut crate::canonical_store_v2::CanonicalStore,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<MigrationReceipt> {
        self.check(backend)?;
        let result = self.rotate_finalized_inner(chain, backend);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    fn rotation_contexts(
        chain: &crate::canonical_store_v2::CanonicalStore,
        node: Hash,
        height: u64,
    ) -> Result<(
        HeightAuthority,
        HeightAuthority,
        crate::block_envelope_v2::BlockEnvelope,
    )> {
        let fail = |_| CounterVoterError::Invalid(Error::WrongAnchor);
        let (head, _) = chain.load().map_err(fail)?;
        if height == 0 || head.height < height {
            return Err(CounterVoterError::WrongHeight);
        }
        let block = chain
            .canonical_block(height)
            .map_err(fail)?
            .ok_or(Error::WrongAnchor)?;
        let (old_parent, old_state, old_root) = chain.execution_parent(height - 1).map_err(fail)?;
        let before =
            HeightAuthority::from_state(&old_state, old_parent_anchor(&old_parent), old_root)?;
        let (new_parent, new_state, new_root) = chain.execution_parent(height).map_err(fail)?;
        let after =
            HeightAuthority::from_state(&new_state, old_parent_anchor(&new_parent), new_root)?;
        let a = before.voters.get(&node).ok_or(Error::UnknownSigner)?;
        let b = after.voters.get(&node).ok_or(Error::UnknownSigner)?;
        if a.lineage != b.lineage
            || a.hardware_generation != b.hardware_generation
            || a.tpm_identity() != b.tpm_identity()
            || a.profile != b.profile
            || a.key_generation.checked_add(1) != Some(b.key_generation)
            || a.public.ed448 == b.public.ed448
            || a.public.fndsa == b.public.fndsa
        {
            return Err(Error::WrongGeneration.into());
        }
        let mut count = 0;
        for raw in &block.body.operations {
            // Trading items are recognized by their namespace first (as in every block path);
            // `operation_kind` refuses them (found by the WP-T1 entry-point matrix row).
            if crate::trading_host_v1::operation(raw)? {
                continue;
            }
            if crate::blocks::operation_kind(raw)? == 21 {
                let rotation = crate::continuity_key_rotate_v2::KeyRotate::decode(raw)?;
                if rotation.binding.admission.node == node {
                    rotation.verify(&old_state, &before.parent, old_root)?;
                    count += 1;
                }
            }
        }
        if count != 1 {
            return Err(Error::WrongOperation.into());
        }
        Ok((before, after, block))
    }
    fn rotate_finalized_inner(
        &mut self,
        chain: &mut crate::canonical_store_v2::CanonicalStore,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<MigrationReceipt> {
        let (before, after, block) = Self::rotation_contexts(chain, self.node, self.height())?;
        if self.round.authority() != &before {
            return Err(Error::WrongAnchor.into());
        }
        if chain.commit(&block).map_err(|_| Error::WrongAnchor)? {
            return Err(Error::WrongAnchor.into());
        }
        for vote in &block.certificate.votes {
            self.require_local_vote(vote, backend)?;
        }
        let (parent, state, _) = chain
            .execution_parent(self.height() - 1)
            .map_err(|_| Error::WrongAnchor)?;
        // The whole body: envelope reference anchors of transactions and operations (AM-4).
        let history = chain
            .evidence_history(self.height(), &block.body)
            .map_err(|_| Error::WrongAnchor)?;
        self.round.validate_proposal_with_history(
            &state,
            &parent,
            &block.header,
            &block.authority,
            &block.body,
            &history,
        )?;
        for vote in &block.certificate.votes {
            self.round.observe(vote)?;
        }
        if !self
            .round
            .commit(block.certificate.decision.round, block.block_hash())?
        {
            return Err(CounterVoterError::WrongHeight);
        }
        let next = AuthenticatedRound::new(after)?;
        let context = next.signing_context(self.node)?;
        if context == self.context {
            return Err(Error::WrongGeneration.into());
        }
        let mut snapshot = Snapshot::empty(&next, self.snapshot.last_sequence)?;
        snapshot.work=self.snapshot.work.as_ref().map(WorkState::next_height);
        self.poisoned = true;
        self.store.rebind(context, &snapshot.encode()?, backend)?;
        self.store.verify_current(backend)?;
        let receipt = MigrationReceipt {
            previous: self.context,
            current: context,
            counter: self.store.counter_value(),
        };
        self.context = context;
        self.activation.invalidate();
        self.activation_rule=next.authority().activation_rule;
        self.snapshot = snapshot;
        self.round = next;
        // Successful storage migration still requires replacing/unlocking the
        // software key under this same exclusive counter owner before signing.
        self.poisoned = false;
        Ok(receipt)
    }
    pub fn resume_rotation(
        path: &Path,
        chain: &crate::canonical_store_v2::CanonicalStore,
        node: Hash,
        height: u64,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<Self> {
        let (before, after, _) = Self::rotation_contexts(chain, node, height)?;
        let predecessor = AuthenticatedRound::new(before)?.signing_context(node)?;
        let round = AuthenticatedRound::new(after.clone())?;
        let context = round.signing_context(node)?;
        if &after.voters.get(&node).ok_or(Error::UnknownSigner)?.public != backend.public_key() {
            return Err(Error::WrongGeneration.into());
        }
        let store = CounterStore::resume_rebind(path, context, predecessor, backend)?;
        let snapshot = Snapshot::decode(store.snapshot())?;
        snapshot.validate(&after, node)?;
        let activation_rule=after.activation_rule;
        let round = AuthenticatedRound::restore(after, snapshot.locks.clone())?;
        Ok(Self {
            round,
            store,
            snapshot,
            node,
            context,
            poisoned: false,
            clock: crate::vote_clock_v1::unqualified(),
            activation:Default::default(),
            activation_rule,
        })
    }
    /// Recovery never creates missing custody. Retain the exclusive backend
    /// lock throughout inspection, opening and every subsequent operation.
    pub fn stored_height(
        path: &Path,
        context: Hash,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<u64> {
        let store = CounterStore::open(path, context, None, None, backend)?;
        Ok(Snapshot::decode(store.snapshot())?.height)
    }
    pub fn node(&self) -> Hash {
        self.node
    }
    pub fn matches_authority(&self, current: &HeightAuthority) -> bool {
        self.round.authority() == current
    }
    pub fn check_backend(&mut self, backend: &mut impl CounterSigningBackend) -> Result<()> {
        self.check(backend)
    }
    /// Local durable high-water suggestion, not a reservation or canonical
    /// ticket authority. Old snapshots without NodeWork history refuse.
    pub fn node_work_high_water(&mut self,backend:&mut impl CounterSigningBackend)->Result<u64>{
        self.check(backend)?;
        Ok(self.snapshot.work.as_ref().ok_or(Error::WrongAnchor)?.high_water())
    }
    /// Validate against this voter's own exact canonical parent before touching
    /// custody. Reservation and complete outcome share the existing NV snapshot.
    pub fn sign_node_work(&mut self,chain:&crate::canonical_store_v2::CanonicalStore,
        authority:crate::work_authority_v2::Authority,body:&crate::blocks::BlockBody,
        backend:&mut impl CounterSigningBackend)->Result<crate::work_authority_v2::Authority>{
        self.check(backend)?;
        let parent=self.round.authority().parent.clone();
        chain.validate_node_work(&parent,self.node,&authority,body)
            .map_err(|_|CounterVoterError::Backend)?;
        let encoded=chain.body_capacity(&parent).and_then(|capacity|capacity.encode(body).map_err(Into::into))
            .map_err(|_|CounterVoterError::Backend)?;
        use sha2::{Digest,Sha256};
        let commitment:Hash=Sha256::digest(&encoded).into();
        if self.snapshot.work.is_none(){return Err(Error::WrongAnchor.into());}
        self.poisoned=true;
        let work=self.snapshot.work.as_mut().ok_or(Error::WrongAnchor)?;
        let new=work.reserve(&authority,commitment)?;
        if let Some(cached)=work.cached(authority.work.ticket_sequence){
            // Complete exact retransmission never re-enters private signing.
            let cached=cached.clone();
            chain.validate_node_work(&parent,self.node,&cached,body)
                .map_err(|_|CounterVoterError::Backend)?;
            self.poisoned=false;
            return Ok(cached);
        }
        self.poisoned=true;
        let result=(||->Result<crate::work_authority_v2::Authority>{
            if new{self.store.commit(&self.snapshot.encode()?,backend)?;}
            self.store.verify_current(backend)?;
            chain.validate_node_work(&parent,self.node,&authority,body)
                .map_err(|_|CounterVoterError::Backend)?;
            let expected=authority.unsigned()?;
            let permit=NodeWorkPermit::after_commit(self.store.counter_value(),&authority,commitment)?;
            let signed=backend.sign_reserved_node_work(authority,body,&permit)
                .map_err(|_|CounterVoterError::Backend)?;
            if signed.unsigned()?!=expected{return Err(Error::WrongAnchor.into());}
            chain.validate_node_work(&parent,self.node,&signed,body)
                .map_err(|_|CounterVoterError::Backend)?;
            self.store.verify_current(backend)?;
            self.snapshot.work.as_mut().ok_or(Error::WrongAnchor)?.finish(signed.clone(),commitment)?;
            self.store.commit(&self.snapshot.encode()?,backend)?;
            self.store.verify_current(backend)?;
            chain.validate_node_work(&parent,self.node,&signed,body)
                .map_err(|_|CounterVoterError::Backend)?;
            Ok(signed)
        })();
        if result.is_ok(){self.poisoned=false;}
        result
    }
    /// Liveness only: leaves the complete voter snapshot, sequence, locks and
    /// NV counter unchanged. Challenge freshness is enforced by the coordinator.
    pub fn sign_work_probe(
        &mut self,
        decision: &crate::certificates::Decision,
        parent_root: Hash,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<crate::liveness_v2::Fragment> {
        self.check(backend)?;
        let authority = self.round.authority();
        let member = authority
            .voters
            .get(&self.node)
            .ok_or(Error::UnknownSigner)?;
        let mut fragment = crate::liveness_v2::Fragment {
            node: self.node,
            hardware_generation: member.hardware_generation,
            key_generation: member.key_generation,
            vote_sequence: self.snapshot.last_sequence,
            tpm_identity: member.tpm_identity(),
            profile: member.profile,
            signature: zero_signature(),
        };
        fragment.validate_authority(decision, authority, parent_root)?;
        // A panic/failure after private operations may not leave a live signer.
        self.poisoned = true;
        fragment.signature = backend
            .sign_work_probe(decision, &fragment)
            .map_err(|_| CounterVoterError::Backend)?;
        fragment.verify(decision, authority, parent_root)?;
        self.store.verify_current(backend)?;
        self.poisoned = false;
        Ok(fragment)
    }
    /// Scheduler inspection only: returned reservations are not publishable.
    /// Publication must pass through replay/sign with current custody checks.
    pub fn progress(&self) -> Result<(LockState, Option<Vote>, Option<Vote>)> {
        if self.poisoned {
            return Err(CounterVoterError::Poisoned);
        }
        let round = self.snapshot.locks.round;
        Ok((
            self.snapshot.locks.clone(),
            self.snapshot.votes.get(&(round, 2)).map(|(v, _)| v.clone()),
            self.snapshot.votes.get(&(round, 3)).map(|(v, _)| v.clone()),
        ))
    }
    /// A peer/canonical certificate cannot import this custody's own sequence.
    /// An own vote must match a complete durably signed reservation exactly.
    /// Failure is a LOCAL custody fault, not a new consensus invalidity rule.
    pub fn require_local_vote(
        &mut self,
        vote: &Vote,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<()> {
        self.check(backend)?;
        if vote.node == self.node {
            let a = self.round.authority();
            vote.verify(&a.parent, a.roots(), &a.voters)?;
        }
        if vote.node == self.node
            && !self
                .snapshot
                .votes
                .get(&(vote.decision.round, vote.decision.step))
                .is_some_and(|(saved, signed)| *signed && saved == vote)
        {
            self.poisoned = true;
            // Reuse the durable local reducer halt bit: this does not mark the
            // canonical chain halted or create slashing evidence. A restart
            // must not forget a detected private-custody inconsistency.
            self.snapshot.locks.halted = true;
            self.store.commit(&self.snapshot.encode()?, backend)?;
            self.store.verify_current(backend)?;
            return Err(CounterVoterError::ConflictingVote);
        }
        Ok(())
    }
    pub fn open(
        path: &Path,
        authority: HeightAuthority,
        node: Hash,
        initial_counter: Option<u64>,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<Self> {
        let round = AuthenticatedRound::new(authority.clone())?;
        let context = round.signing_context(node)?;
        if &round
            .authority()
            .voters
            .get(&node)
            .ok_or(Error::UnknownSigner)?
            .public
            != backend.public_key()
        {
            return Err(Error::WrongGeneration.into());
        }
        let initial = Snapshot::empty(&round, 0)?.encode()?;
        let store = CounterStore::open(
            path,
            context,
            None,
            initial_counter.map(|n| (n, initial.as_slice())),
            backend,
        )?;
        let snapshot = Snapshot::decode(store.snapshot())?;
        snapshot.validate(&authority, node)?;
        let activation_rule=authority.activation_rule;
        let round = AuthenticatedRound::restore(authority, snapshot.locks.clone())?;
        Ok(Self {
            round,
            store,
            snapshot,
            node,
            context,
            poisoned: false,
            clock: crate::vote_clock_v1::unqualified(),
            activation:Default::default(),
            activation_rule,
        })
    }
    fn check(&mut self, backend: &mut impl CounterSigningBackend) -> Result<()> {
        if self.poisoned || self.snapshot.locks.halted {
            return Err(CounterVoterError::Poisoned);
        }
        if self.round.authority().activation_rule!=self.activation_rule
            ||self.round.signing_context(self.node)?!=self.context{
            self.poisoned=true;return Err(Error::WrongAnchor.into());
        }
        if &self
            .round
            .authority()
            .voters
            .get(&self.node)
            .ok_or(Error::UnknownSigner)?
            .public
            != backend.public_key()
        {
            self.poisoned = true;
            return Err(Error::WrongGeneration.into());
        }
        if let Err(e) = self.store.verify_current(backend) {
            self.poisoned = true;
            return Err(e.into());
        }
        Ok(())
    }
    pub fn round_mut(&mut self) -> Result<&mut AuthenticatedRound> {
        if self.poisoned {
            return Err(CounterVoterError::Poisoned);
        }
        Ok(&mut self.round)
    }
    pub fn height(&self) -> u64 {
        self.snapshot.height
    }
    pub fn last_sequence(&self) -> u64 {
        self.snapshot.last_sequence
    }
    /// Exact persisted bytes; replay cannot select another payload or sequence.
    pub fn replay(
        &mut self,
        step: Step,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<Option<Vote>> {
        let reading = self.clock_reading();
        self.replay_at(&reading, step, backend)
    }
    fn replay_slot(&self, step: Step) -> (u64, u8) {
        (
            self.snapshot.locks.round,
            match step {
                Step::Prevote => 2,
                Step::Precommit => 3,
            },
        )
    }
    /// The PURE pre-check of `replay_at`, judged against one caller-supplied clock reading. It
    /// changes no reducer, custody or counter state and does not poison, so the owning actor can
    /// run it BEFORE its halting latch is set: a refusal here (local time reasons, or a proposal not
    /// yet re-executed) is an explicit nonfatal result and never a halt.
    ///
    /// Completing an interrupted reservation needs no current clock only if it passed the fresh
    /// guard (or is already signed). An unmarked unsigned record needs the guard now.
    pub(crate) fn replay_gate_at(
        &self,
        reading: &dyn crate::vote_clock_v1::VoteClock,
        step: Step,
    ) -> Result<()> {
        if self.poisoned || self.snapshot.locks.halted {
            return Err(CounterVoterError::Poisoned);
        }
        let slot = self.replay_slot(step);
        let Some((vote, _)) = self.snapshot.votes.get(&slot) else {
            return Ok(());
        };
        if !self.snapshot.clock_exempt(&slot) && !vote.nil {
            use crate::{vote_clock_v1::TimeStatus, votes::IngressError};
            match self.round.time_status(reading, vote.decision.block) {
                TimeStatus::Eligible => {}
                TimeStatus::Future { ahead_seconds } => {
                    return Err(IngressError::FutureTimestamp { ahead_seconds }.into());
                }
                TimeStatus::UnknownProposal => {
                    return Err(IngressError::UnknownProposal.into());
                }
                TimeStatus::Unqualified => {
                    return Err(IngressError::ClockUnqualified.into());
                }
            }
        }
        Ok(())
    }
    /// `replay` against one caller-supplied clock reading (see `clock_reading`). The pre-check
    /// repeats against the same reading and the same state, so it cannot fail once the owning
    /// actor's own pre-check passed: after the latch is set there is no time verdict left.
    pub(crate) fn replay_at(
        &mut self,
        reading: &dyn crate::vote_clock_v1::VoteClock,
        step: Step,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<Option<Vote>> {
        self.check(backend)?;
        self.replay_gate_at(reading, step)?;
        self.replay_activation_gate(step)?;
        let slot = self.replay_slot(step);
        let Some((vote, signed)) = self.snapshot.votes.get(&slot).cloned() else {
            return Ok(None);
        };
        self.poisoned = true;
        let result = self.finish(slot, vote, signed, backend);
        if result.is_ok() {
            self.poisoned = false;
        }
        result.map(Some)
    }
    fn finish(
        &mut self,
        slot: (u64, u8),
        mut vote: Vote,
        signed: bool,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<Vote> {
        let message=vote.unsigned()?;
        let permit=if signed {None} else {
            use crate::activation_attestation_v1::{Classification,Failure,PrivateSignPermit};
            Some(match self.activation_classification(slot,(!vote.nil).then_some(vote.decision.block))?{
                Classification::NoAdmission=>PrivateSignPermit::ordinary(self.node,self.activation_rule,message.clone()),
                Classification::Unknown=>return Err(CounterVoterError::Activation(Failure::Missing)),
                Classification::Required(scope)=>self.activation.consume(self.node,scope,slot.0,slot.1,message.clone())
                    .map_err(CounterVoterError::Activation)?,
            })
        };
        let a = self.round.authority();
        vote.validate_authority(&a.parent, a.roots(), &a.voters)?;
        self.store.verify_current(backend)?;
        if !signed {
            vote.signature = backend
                .sign_reserved_vote(&message,permit.as_ref().ok_or(CounterVoterError::Backend)?)
                .map_err(|_| CounterVoterError::Backend)?;
            self.activation.post_sign(permit.as_ref().ok_or(CounterVoterError::Backend)?)
                .map_err(CounterVoterError::Activation)?;
        }
        vote.verify(&a.parent, a.roots(), &a.voters)?;
        if !signed {
            self.snapshot.votes.insert(slot, (vote.clone(), true));
            self.snapshot.gated.insert(slot);
            self.snapshot.legacy = false;
            self.store.commit(&self.snapshot.encode()?, backend)?;
        }
        self.store.verify_current(backend)?;
        Ok(vote)
    }
    pub fn sign(
        &mut self,
        step: Step,
        proposal: Option<Hash>,
        pol_round: Option<u64>,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<Vote> {
        let reading = self.clock_reading();
        self.sign_at(&reading, step, proposal, pol_round, backend)
    }
    /// `sign` against one caller-supplied clock reading (see `clock_reading`).
    pub(crate) fn sign_at(
        &mut self,
        reading: &dyn crate::vote_clock_v1::VoteClock,
        step: Step,
        proposal: Option<Hash>,
        pol_round: Option<u64>,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<Vote> {
        self.check(backend)?;
        // Time gate BEFORE any reducer, custody or counter mutation and before the poison latch:
        // a deferral or abstention leaves no trace and does not poison custody.
        // One clock reading serves the pre-latch gate and prepare_vote, so a clock change between
        // two reads cannot poison custody after the gate has passed.
        if let Err(e) = self.time_gate_with(reading, step, proposal, pol_round) {
            // A request conflict keeps its established safety response: the in-memory poison.
            // Nothing is written and no counter value is used (Architect decision V1).
            if matches!(e, CounterVoterError::ConflictingVote) {
                self.poisoned = true;
            }
            return Err(e);
        }
        self.activation_gate(step,proposal,pol_round)?;
        self.poisoned = true;
        let result = self.sign_inner(step, proposal, pol_round, reading, backend);
        if result.is_ok() {
            self.poisoned = false;
        }
        result
    }
    fn sign_inner(
        &mut self,
        step: Step,
        proposal: Option<Hash>,
        pol_round: Option<u64>,
        clock: &dyn crate::vote_clock_v1::VoteClock,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<Vote> {
        let slot = (
            self.round.machine().state().round,
            match step {
                Step::Prevote => 2,
                Step::Precommit => 3,
            },
        );
        let sequence = match self.snapshot.votes.get(&slot) {
            Some((v, _)) => v.sequence,
            None => self
                .snapshot
                .last_sequence
                .checked_add(1)
                .ok_or(Error::Overflow)?,
        };
        let gate = if self.snapshot.clock_exempt(&slot) {
            crate::vote_clock_v1::VoteGate::reserved()
        } else {
            crate::vote_clock_v1::VoteGate::Fresh(clock)
        };
        let mut vote = self
            .round
            .prepare_vote(self.node, step, proposal, pol_round, sequence, gate)?;
        let signed = if let Some((old, signed)) = self.snapshot.votes.get(&slot) {
            if old.unsigned()? != vote.unsigned()? {
                return Err(CounterVoterError::ConflictingVote);
            }
            vote.signature = old.signature.clone();
            *signed
        } else {
            if self.snapshot.votes.len() >= MAX_RESERVATIONS {
                return Err(CounterVoterError::Capacity);
            }
            self.snapshot.last_sequence = sequence;
            false
        };
        self.snapshot.locks = self.round.machine().state().clone();
        if self.round.authority().activation_rule.is_some(){
            let classification=self.activation_classification(slot,(!vote.nil).then_some(vote.decision.block))?;
            self.snapshot.classifications.insert(slot,classification);
            self.snapshot.successor=true;
        }
        self.snapshot.votes.insert(slot, (vote.clone(), signed));
        // The fresh guard (or an exact bound exemption) passed for exactly this decision: the
        // durable marker is written in the same commit as the reservation.
        self.snapshot.gated.insert(slot);
        self.snapshot.legacy = false;
        self.store.commit(&self.snapshot.encode()?, backend)?;
        self.finish(slot, vote, signed, backend)
    }
    pub fn timeout_precommit(&mut self, backend: &mut impl CounterSigningBackend) -> Result<u64> {
        self.check(backend)?;
        let next = self.round.timeout_precommit()?;
        self.poisoned = true;
        self.snapshot.locks = self.round.machine().state().clone();
        self.store.commit(&self.snapshot.encode()?, backend)?;
        self.store.verify_current(backend)?;
        self.poisoned = false;
        Ok(next)
    }
    pub fn advance(
        &mut self,
        authority: HeightAuthority,
        backend: &mut impl CounterSigningBackend,
    ) -> Result<()> {
        self.check(backend)?;
        self.poisoned = true;
        if authority.parent.height != self.snapshot.height
            || self.round.machine().state().halted
            || self.round.machine().state().finalized != Some(authority.parent.block)
        {
            return Err(CounterVoterError::WrongHeight);
        }
        let next = AuthenticatedRound::new(authority)?;
        if next.signing_context(self.node)? != self.context
            || &next
                .authority()
                .voters
                .get(&self.node)
                .ok_or(Error::UnknownSigner)?
                .public
                != backend.public_key()
        {
            return Err(Error::WrongGeneration.into());
        }
        let mut snapshot = Snapshot::empty(&next, self.snapshot.last_sequence)?;
        snapshot.work=self.snapshot.work.as_ref().map(WorkState::next_height);
        self.store.commit(&snapshot.encode()?, backend)?;
        self.store.verify_current(backend)?;
        self.activation_rule=next.authority().activation_rule;
        self.round = next;
        self.snapshot = snapshot;
        self.activation.invalidate();
        self.poisoned = false;
        Ok(())
    }
}
fn old_parent_anchor(p: &crate::execution::WorkParent) -> crate::anchors::FinalizedAnchor {
    crate::anchors::FinalizedAnchor {
        network: crate::NETWORK_ID,
        genesis: p.genesis,
        fingerprint: p.fingerprint,
        height: p.height,
        block: p.block,
    }
}
#[cfg(test)]
#[path="activation_signer_tests_v1.rs"]
pub(crate) mod activation_signer_tests;

#[cfg(test)]
mod marker_tests {
    //! F3: the durable "fresh guard passed" marker and the legacy (unmarked) record format.
    use super::*;
    use crate::certificates::Decision;

    fn vote(height: u64, round: u64, step: u8, sequence: u64, signed: bool) -> Vote {
        let mut signature = zero_signature();
        if signed {
            signature.ed448[0] = 1;
        }
        Vote {
            decision: Decision {
                network: crate::NETWORK_ID,
                genesis: [1; 32],
                fingerprint: [2; 32],
                purpose: 2,
                height,
                mining_epoch: 0,
                continuity_period: 0,
                round,
                step,
                previous_finalized_anchor: [3; 32],
                parent: [4; 32],
                block: [5; 32],
                state: [6; 32],
                membership: [7; 32],
                reputation: [8; 32],
                attestation: [9; 32],
            },
            nil: false,
            node: [9; 32],
            hardware_generation: 1,
            key_generation: 1,
            sequence,
            tpm_identity: [10; 32],
            profile: [11; 32],
            signature,
        }
    }
    fn snapshot(legacy: bool, signed: bool, marked: bool) -> Snapshot {
        let mut votes = BTreeMap::new();
        votes.insert((0, 2), (vote(5, 0, 2, 1, signed), signed));
        let mut gated = BTreeSet::new();
        if marked {
            gated.insert((0, 2));
        }
        Snapshot {
            height: 5,
            last_sequence: 1,
            parent: [4; 32],
            roots: [[1; 32], [2; 32], [3; 32]],
            locks: LockState {
                round: 0,
                locked: None,
                finalized: None,
                halted: false,
            },
            votes,
            gated,
            legacy,
            successor:false,
            classifications:BTreeMap::new(),
            work:None,
        }
    }
    #[test]
    fn unmarked_unsigned_reservation_gets_no_clock_exemption() {
        let slot = (0, 2);
        // Version 2 (legacy) bytes decode, re-encode byte-exactly, and carry no marker.
        let raw = snapshot(true, false, false).encode().unwrap();
        let legacy = Snapshot::decode(&raw).unwrap();
        assert!(legacy.legacy && legacy.gated.is_empty());
        assert!(!legacy.clock_exempt(&slot), "legacy unsigned: fresh guard required");
        assert_eq!(legacy.encode().unwrap(), raw);
        // A version 3 record WITHOUT the marker is also not exempt.
        let raw = snapshot(false, false, false).encode().unwrap();
        let v3 = Snapshot::decode(&raw).unwrap();
        assert!(!v3.legacy && !v3.clock_exempt(&slot));
        // Marked version 3 reservation: exempt, and the marker survives a round trip.
        let raw = snapshot(false, false, true).encode().unwrap();
        let marked = Snapshot::decode(&raw).unwrap();
        assert!(marked.clock_exempt(&slot));
        assert_eq!(marked.encode().unwrap(), raw);
        // A signature already exists (legacy or not): retransmission only, no new clock check.
        let raw = snapshot(true, true, false).encode().unwrap();
        assert!(Snapshot::decode(&raw).unwrap().clock_exempt(&slot));
        // The two formats are distinct canonical encodings; an unknown version is refused.
        assert_ne!(
            snapshot(true, false, false).encode().unwrap(),
            snapshot(false, false, false).encode().unwrap()
        );
        let mut bad = snapshot(false, false, true).encode().unwrap();
        bad[1] = 4;
        assert!(Snapshot::decode(&bad).is_err());
        // An absent slot is never exempt.
        assert!(!marked.clock_exempt(&(0, 3)));
    }
    #[test]
    fn successor_public_classification_is_not_an_activation_cache(){
        use crate::activation_attestation_v1::{Classification,Failure,Gate};
        let mut s=snapshot(false,false,true);s.successor=true;
        s.classifications.insert((0,2),Classification::Required([21;32]));
        let raw=s.encode().unwrap();let decoded=Snapshot::decode(&raw).unwrap();
        assert_eq!(decoded.classifications.get(&(0,2)),Some(&Classification::Required([21;32])));
        assert!(decoded.clock_exempt(&(0,2))); // clock alone cannot authorize completion
        assert_eq!(Gate::default().check([9;32],[21;32],0,2),Err(Failure::Missing));
        assert_eq!(decoded.encode().unwrap(),raw);
        // Each format is explicit: selected snapshots never silently serialize
        // a local capability/deadline or claim a physical activation occurred.
        assert_ne!(raw,snapshot(false,false,true).encode().unwrap());
        s.classifications.insert((0,2),Classification::NoAdmission);
        let no_admission=Snapshot::decode(&s.encode().unwrap()).unwrap();
        assert_eq!(no_admission.classifications.get(&(0,2)),Some(&Classification::NoAdmission));
    }
}
