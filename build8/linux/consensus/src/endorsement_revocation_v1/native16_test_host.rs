//! Private cfg(test) modeled host; four V7 foundation controls qualified separately.
//! Intended child of endorsement_revocation_v1::route_tests; no production API.
//! This successor's native121 chain remains uncompiled; no physical/shipping credit.
use crate::{Error, Hash, Result, anchors::FinalizedAnchor, blocks::BlockBody,
    canonical_store_v2::CanonicalStore, execution::{CandidatePreparation, Execution, State, WorkParent},
    join_v2::Join, pow::{Candidate, WorkHeader}, work_authority_v2::Authority};
use std::{cell::RefCell, collections::BTreeSet, rc::Rc};

const MAX_MODELLED_JOINS: usize = 15;

// Private capability source is the fixed independent native Genesis constructor;
// no caller can supply a state, class, roots, approval boolean or arbitrary PKI.
struct ModelHost {
    fixture: super::Rig,
    prepared_count: usize,
    capacity_join_pki: Option<super::test_value_x509::X509Pki>,
    maximum_profile: bool, // Fixed private TEST profile; no caller-supplied budgets.
}
impl ModelHost {
    fn new() -> Self { Self { fixture: super::rig(), prepared_count: 0, capacity_join_pki: None, maximum_profile: false } }
    fn with_current_activation() -> Self { Self { fixture: super::rig_current_activation(), prepared_count: 0, capacity_join_pki: None, maximum_profile: false } }

    // Fixed TEST-only constructor. Native Genesis authenticates the long-path
    // original voter and the distinct short-path root used by all modeled joins.
    fn genuine_capacity() -> (Self, super::super::Evidence) { Self::capacity_at(121,false) }
    fn maximum_capacity() -> (Self, super::super::Evidence) { Self::capacity_at(1081,true) }
    // Only the fixed maximum TEST profile follows the existing PoW retarget
    // cadence: 3600 seconds per 60 heights. The ordinary15/121 clock is intact.
    fn elapsed_at(height:u64,maximum_profile:bool)->u64 {
        if maximum_profile {height.checked_mul(3600/60).expect("bounded TEST maximum time")}
        else {height}
    }
    fn timestamp_at(&self,height:u64)->u64 {
        super::test_value_x509::T_REF.checked_add(Self::elapsed_at(height,self.maximum_profile))
            .expect("bounded TEST fixture time")
    }
    fn max_joins(&self)->usize { if self.maximum_profile {1023}else{MAX_MODELLED_JOINS} }
    fn max_rows(&self)->usize { if self.maximum_profile {1081}else{121} }
    fn capacity_at(height:u64,maximum_profile:bool) -> (Self, super::super::Evidence) {
        use super::genuine_long_path_pki_tests::LongPathPki;
        use super::{software_tpm,test_value_x509,TestTpm};
        use crate::ek_chain::CertificateSyntax;
        let mut pki=LongPathPki::new();
        let original=TestTpm::with_identity("a2-native16-capacity-original-EK");
        let chain=pki.maximize_path(&original.simulator_ek(),4096);
        let serial=crate::x509_syntax::X509Syntax.parse_certificate(&chain[0]).unwrap().serial;
        let historical=pki.historical_crls();
        pki.verify(&chain,&historical,test_value_x509::T_REF).unwrap();
        let mut crls=Vec::new();
        for issuer in 0..4 {
            let (raw,population)=pki.maximize_crl_at(issuer,
                if issuer==0 {Some(serial.as_slice())} else {None},32768,
                test_value_x509::T_REF+Self::elapsed_at(height,maximum_profile),
                test_value_x509::T_REF+Self::elapsed_at(height,maximum_profile)+60);
            assert!((32700..=32768).contains(&raw.len()));
            assert!(!population.is_empty());crls.push(raw);
        }
        let evidence=super::super::Evidence::Crl {target_certificate:chain[0].clone(),
            signer_chain:chain[1..].to_vec(),crls};
        let join_pki=test_value_x509::X509Pki::new("a2-native16-capacity-modeled-join-root");
        let tpm=original.strip(software_tpm::Strip::ConsistentProvenance(pki.pki.root_hash()));
        let anchor=pki.anchor();
        let fixture=super::rig_with_authenticated_material(pki.pki,
            std::slice::from_ref(&join_pki),tpm,chain,historical,anchor);
        (Self {fixture,prepared_count:0,capacity_join_pki:Some(join_pki),maximum_profile},evidence)
    }
    fn trusted_parent(&self, store: &CanonicalStore)
        -> Result<(WorkParent, State, Hash, crate::body_capacity_v3::BodyCapacity)> {
        let (genesis_parent, genesis_state, genesis_root) = store.execution_parent(0)
            .map_err(|_| Error::WrongAnchor)?;
        if genesis_parent.height != 0
            || genesis_parent.block != self.fixture.parent.block
            || genesis_parent.genesis != self.fixture.parent.genesis
            || genesis_parent.fingerprint != self.fixture.parent.fingerprint
            || genesis_root != self.fixture.root
            || genesis_state.records().map_err(|_| Error::WrongAnchor)?
                != self.fixture.state.records().map_err(|_| Error::WrongAnchor)? {
            return Err(Error::WrongAnchor);
        }
        let (tip, _) = store.load().map_err(|_| Error::WrongAnchor)?;
        // Until a complete independently reverified historical prefix exists,
        // this foundation grants ONLY the fixed verified Genesis parent. A
        // matching current StateRoot alone must never create a later grant.
        if tip.height != 0 || tip.block != self.fixture.parent.block
            || tip.root != self.fixture.root {
            return Err(Error::WrongAnchor);
        }
        let (parent, state, root) = store.execution_parent(tip.height)
            .map_err(|_| Error::WrongAnchor)?;
        if (parent.block,root)!=(tip.block,tip.root)
            || state.root().map_err(|_| Error::WrongAnchor)?!=root
            || parent.genesis!=self.fixture.parent.genesis
            || parent.fingerprint!=self.fixture.parent.fingerprint {
            return Err(Error::WrongAnchor);
        }
        let params=self.fixture.parameters.encode().map_err(|_| Error::Codec)?;
        if state.protocol_records.get(&crate::genesis_v2::parameters_key())!=Some(&params)
            || state.admission_class()?!=crate::provenance::AdmissionClass::Production {
            return Err(Error::WrongAnchor);
        }
        let anchor=FinalizedAnchor { height:parent.height,block:parent.block,
            ..self.fixture.parent.clone() };
        let capacity=store.body_capacity(&anchor).map_err(|_| Error::WrongAnchor)?;
        Ok((parent,state,root,capacity))
    }

    fn verify_pins(&self,state:&State,parent:&WorkParent,body:&BlockBody)
        -> Result<Vec<VerifiedJoinPin>> {
        let anchor=FinalizedAnchor {height:parent.height,block:parent.block,
            ..self.fixture.parent.clone()};
        let reference=crate::execution_v2::admission_parent_time(parent)?;
        let mut pins=Vec::new();let mut nodes=BTreeSet::new();
        // This foundation supports only the15 Join grants, not recovery/rotation
        // or an arbitrary carrier allowlist. All monetary transaction bytes still
        // enter exact full body/native execution; no result is granted here.
        for raw in &body.operations {
            let carrier=crate::admission_public_v3::Carrier::decode(raw)?;
            if carrier.kind()!=15 {return Err(Error::WrongOperation);}
            let join=Join::decode(carrier.signed())?;
            if join.parent!=anchor || !nodes.insert(join.binding.admission.node) {
                return Err(Error::WrongAnchor);
            }
            let policy=state.current_admission_policy_v2(anchor.genesis,anchor.fingerprint)?;
            let (_,generation)=mutiny_crypto_v2::PublicKey::decode_descriptor(
                &join.binding.node_descriptor).map_err(|_| Error::Codec)?;
            if generation!=1 {return Err(Error::WrongGeneration);}
            let expected=crate::admission_v2::Expected {node:join.binding.admission.node,
                hardware_generation:1,key_generation:1,supervised_nonce:join.admission_nonce()?};
            // Full original material verification, not catching AdmissionAuthorityEnded.
            join.binding.verify(&policy,&expected,&state.wallets,state.admission_class()?)?;
            // Complete independent available witness/constraints/PCR/root/class/
            // certified EK key/profile commitment verification at real parent time.
            // Native lifecycle stages this again after its scope check; this does
            // not insert membership/dependencies or authenticate through structure.
            crate::endorsement_dependencies_v1::Book::default().stage_authenticated(
                &join.binding,join.binding.admission.node,reference,carrier.witness(),
                &self.fixture.parameters)?;
            pins.push(VerifiedJoinPin {inner:carrier.signed().to_vec(),outer:raw.clone(),
                witness:carrier.witness().to_vec(),node:join.binding.admission.node});
        }
        if pins.is_empty() || pins.len()>self.max_joins() {
            return Err(Error::Capacity);
        }
        Ok(pins)
    }

    fn prepare_exact(&mut self,store:&CanonicalStore,candidate:&Candidate,ticket:u64,
        body:&BlockBody) -> crate::execution::Result<ModelPrepared> {
        let (parent,state,root,capacity)=self.trusted_parent(store)?;
        if candidate.state_root!=[0;32] || candidate.body_root!=capacity.root(body)? {
            return Err(Error::WrongAnchor.into());
        }
        state.work_context_v2(&parent,candidate)?;
        let joins=self.verify_pins(&state,&parent,body)?;
        if self.prepared_count.checked_add(joins.len()).is_none_or(|n|n>self.max_joins()) {
            return Err(Error::Capacity.into());
        }
        let pin=Rc::new(PreparationPin {parent:ParentPin::capture(&parent),root,
            candidate:candidate.clone(),ticket,body:capacity.encode(body)?,joins});
        let _lease=Lease::install(Mode::Prepare(pin.clone()))?;
        let execution=state.prepare_candidate_with_history_v2(CandidatePreparation {
            parent:&parent,candidate,ticket_sequence:ticket,body},&Default::default())?;
        let records=execution.state.records()?;
        self.prepared_count+=pin.joins.len();
        Ok(ModelPrepared {pin,computed_root:execution.root,records})
    }

    fn execute_exact(&self,prepared:&ModelPrepared,store:&CanonicalStore,
        header:&WorkHeader,authority:&Authority,body:&BlockBody)
        -> crate::execution::Result<Execution> {
        let (parent,state,root,capacity)=self.trusted_parent(store)?;
        let mut expected=prepared.pin.candidate.clone();expected.state_root=prepared.computed_root;
        if header.candidate!=expected || !prepared.pin.parent.matches(&parent)
            || root!=prepared.pin.root || capacity.encode(body)?!=prepared.pin.body
            || authority.work.ticket_sequence!=prepared.pin.ticket {
            return Err(Error::WrongAnchor.into());
        }
        // Both native work authorization and target remain actual checks. X is
        // not a signature/finality source, and creates no quorum/canonical publish.
        let (context,_,node)=state.work_context_v2(&parent,&header.candidate)?;
        authority.verify(header,&context,&node)?;
        if !crate::pow::meets_target(&header.digest(),&header.candidate.target) {
            return Err(Error::WrongAnchor.into());
        }
        let _lease=Lease::install(Mode::Execute(ExecutionPin {
            prepared:prepared.pin.clone(),computed_root:prepared.computed_root,
            header:header.encode(),authority:authority.encode()?}))?;
        let execution=state.execute_licensed_with_history_v2(
            &parent,header,authority,body,&Default::default())?;
        if execution.root!=prepared.computed_root
            || execution.root!=header.candidate.state_root
            || execution.state.records()?!=prepared.records {
            return Err(Error::WrongAnchor.into());
        }
        Ok(execution)
    }
}

struct ParentPin {
    genesis:Hash,fingerprint:Hash,block:Hash,height:u64,t0:u64,target:Hash,times:Vec<u64>,
}
impl ParentPin {
    fn as_work_parent(&self)->WorkParent { WorkParent {genesis:self.genesis,
        fingerprint:self.fingerprint,block:self.block,height:self.height,t0:self.t0,
        target:self.target,ancestor_timestamps:self.times.clone()} }
    fn capture(p:&WorkParent)->Self {Self {genesis:p.genesis,fingerprint:p.fingerprint,
        block:p.block,height:p.height,t0:p.t0,target:p.target,times:p.ancestor_timestamps.clone()}}
    fn matches(&self,p:&WorkParent)->bool {
        // The native timestamp-window contract is order-independent. Preserve
        // every value and multiplicity; live SQL and replay traverse oppositely.
        let mut expected=self.times.clone();let mut actual=p.ancestor_timestamps.clone();
        expected.sort_unstable();actual.sort_unstable();
        (self.genesis,self.fingerprint,self.block,
        self.height,self.t0,self.target)==(p.genesis,p.fingerprint,p.block,p.height,p.t0,p.target)
        && expected==actual}
}
struct VerifiedJoinPin {inner:Vec<u8>,outer:Vec<u8>,witness:Vec<u8>,node:Hash}
struct PreparationPin {parent:ParentPin,root:Hash,candidate:Candidate,ticket:u64,
    body:Vec<u8>,joins:Vec<VerifiedJoinPin>}
struct ModelPrepared {pin:Rc<PreparationPin>,computed_root:Hash,records:Vec<(Hash,Vec<u8>)>}
struct ExecutionPin {prepared:Rc<PreparationPin>,computed_root:Hash,header:Vec<u8>,authority:Vec<u8>}
enum Mode {Prepare(Rc<PreparationPin>),Execute(ExecutionPin),Replay(verified_prefix::ReplayPins)}
struct Active {mode:Mode,inside_prepare:bool,inside_execute:bool,replay_index:Option<usize>}
thread_local! {static ACTIVE:RefCell<Option<Active>>=const {RefCell::new(None)};}

// Rc marker prohibits cross-thread use. No clone, public setter, boolean or
// wildcard grant; distinct modes and lifetime guards bind the actual call.
struct Lease { _same_thread:Rc<()> }
impl Lease {
    fn install(mode:Mode)->Result<Self> {
        ACTIVE.with(|s| {
            let mut active=s.try_borrow_mut().map_err(|_| Error::WrongOperation)?;
            if active.is_some() {return Err(Error::WrongOperation);}
            *active=Some(Active {mode,inside_prepare:false,inside_execute:false,replay_index:None});
            Ok(Self {_same_thread:Rc::new(())})
        })
    }
}
impl Drop for Lease {fn drop(&mut self) {ACTIVE.with(|s| {*s.borrow_mut()=None;});}}
enum Entered {Prepare,Execute}
pub(crate) struct Entry {entered:Entered,_same_thread:Rc<()>}
impl Drop for Entry {
    fn drop(&mut self) {ACTIVE.with(|s| {if let Some(a)=s.borrow_mut().as_mut() {
        match self.entered {Entered::Prepare=>a.inside_prepare=false,Entered::Execute=> {
            a.inside_execute=false;a.replay_index=None;
        }}
    }});}
}

// Private TEST-only callbacks. A normal call with no host returns None and retains all
// existing behavior; stage mismatch refuses rather than using a shared grant.
pub(crate) fn enter_prepare(state:&State,input:&CandidatePreparation<'_>,has_recovery:bool)
    -> Result<Option<Entry>> {
    ACTIVE.with(|slot| {
        let mut slot=slot.try_borrow_mut().map_err(|_| Error::WrongOperation)?;
        let Some(a)=slot.as_mut() else {return Ok(None)};
        if has_recovery || a.inside_prepare {return Err(Error::WrongOperation);}
        let (pin,expected)=match &a.mode {
            Mode::Prepare(pin)=> {
                if a.inside_execute {return Err(Error::WrongOperation);}
                (&**pin,pin.candidate.clone())
            }
            Mode::Execute(pin)=> {
                if !a.inside_execute {return Err(Error::WrongOperation);}
                let mut expected=pin.prepared.candidate.clone();expected.state_root=pin.computed_root;
                (&*pin.prepared,expected)
            }
            Mode::Replay(pins)=> {
                if !a.inside_execute {return Err(Error::WrongOperation);}
                let pin=pins.pin(a.replay_index.ok_or(Error::WrongOperation)?)
                    .ok_or(Error::WrongOperation)?;
                let mut expected=pin.prepared.candidate.clone();expected.state_root=pin.computed_root;
                (&*pin.prepared,expected)
            }
        };
        if !pin.parent.matches(input.parent) || *input.candidate!=expected
            || input.ticket_sequence!=pin.ticket || state.root().map_err(|_| Error::WrongAnchor)?!=pin.root {
            return Err(Error::WrongAnchor);
        }
        let anchor=FinalizedAnchor {network:crate::NETWORK_ID,genesis:input.parent.genesis,
            fingerprint:input.parent.fingerprint,height:input.parent.height,block:input.parent.block};
        let capacity=crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(state,anchor,pin.root)?;
        if capacity.encode(input.body)?!=pin.body {return Err(Error::WrongAnchor);}
        a.inside_prepare=true;
        Ok(Some(Entry {entered:Entered::Prepare,_same_thread:Rc::new(())}))
    })
}
pub(crate) fn enter_execute(state:&State,parent:&WorkParent,header:&WorkHeader,
    authority:&Authority,body:&BlockBody)->Result<Option<Entry>> {
    ACTIVE.with(|slot| {
        let mut slot=slot.try_borrow_mut().map_err(|_| Error::WrongOperation)?;
        let Some(a)=slot.as_mut() else {return Ok(None)};
        if a.inside_prepare || a.inside_execute {return Err(Error::WrongOperation);}
        let selected=match &a.mode {
            Mode::Execute(_)=>None,
            Mode::Replay(pins)=>Some(pins.select(state,parent,header,authority,body)?),
            Mode::Prepare(_)=>return Err(Error::WrongOperation),
        };
        let x=match &a.mode {
            Mode::Execute(x)=>x,
            Mode::Replay(pins)=>pins.pin(selected.ok_or(Error::WrongOperation)?)
                .ok_or(Error::WrongOperation)?,
            Mode::Prepare(_)=>return Err(Error::WrongOperation),
        };
        if !x.prepared.parent.matches(parent) || state.root().map_err(|_| Error::WrongAnchor)?!=x.prepared.root
            || header.encode()!=x.header || authority.encode()?!=x.authority {
            return Err(Error::WrongAnchor);
        }
        let anchor=FinalizedAnchor {network:crate::NETWORK_ID,genesis:parent.genesis,
            fingerprint:parent.fingerprint,height:parent.height,block:parent.block};
        let capacity=crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(state,anchor,x.prepared.root)?;
        if capacity.encode(body)?!=x.prepared.body {return Err(Error::WrongAnchor);}
        a.inside_execute=true;
        a.replay_index=selected;
        Ok(Some(Entry {entered:Entered::Execute,_same_thread:Rc::new(())}))
    })
}
pub(crate) fn permits_join(join:&Join,context:crate::parent_context_v2::ParentContext<'_>)
    -> Result<bool> {
    ACTIVE.with(|slot| {
        let slot=slot.try_borrow().map_err(|_| Error::WrongOperation)?;
        let Some(a)=slot.as_ref() else {return Ok(false)};
        if !a.inside_prepare {return Err(Error::WrongOperation);}
        let pin=match &a.mode {Mode::Prepare(p)=>&**p,Mode::Execute(x)=> {
            if !a.inside_execute {return Err(Error::WrongOperation);} &*x.prepared
        },Mode::Replay(pins)=> {
            if !a.inside_execute {return Err(Error::WrongOperation);}
            &*pins.pin(a.replay_index.ok_or(Error::WrongOperation)?)
                .ok_or(Error::WrongOperation)?.prepared
        }};
        if context.root()!=pin.root || context.parent()!=&join.parent
            || join.parent.block!=pin.parent.block || join.parent.height!=pin.parent.height
            || join.parent.genesis!=pin.parent.genesis || join.parent.fingerprint!=pin.parent.fingerprint {
            return Err(Error::WrongAnchor);
        }
        let inner=join.encode()?;
        let matching:Vec<_>=pin.joins.iter().filter(|p|p.inner==inner&&p.node==join.binding.admission.node).collect();
        if matching.len()!=1 {return Err(Error::WrongAnchor);}
        let p=matching[0];
        // Outer/witness bytes were independently verified and matched by whole
        // capacity-encoded body at canonical entry; verify the exact pairing again.
        let carrier=crate::admission_public_v3::Carrier::decode(&p.outer)?;
        if carrier.signed()!=p.inner || carrier.witness()!=p.witness {return Err(Error::WrongAnchor);}
        Ok(true)
    })
}

#[path = "native16_foundation_tests.rs"]
mod foundation_tests;

#[path = "native16_verified_prefix.rs"]
mod verified_prefix;
