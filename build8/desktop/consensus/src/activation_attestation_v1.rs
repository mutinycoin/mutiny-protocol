//! Adopted successor: the ordinary parent certificate attests private activation
//! by its honest signers. Public records do not prove a TPM command occurred.
//! Private completion is owned by the local workflow; Production material and
//! unqualified/missing providers fail closed. No production adapter ships.
use crate::{Error, Hash, Result, NETWORK_ID, anchors::FinalizedAnchor,
    blocks::BlockBody, execution::State, node_admission_v2::Binding,
    pow::WorkHeader, tpm::TpmProfile};
use minicbor::Encoder;
#[path="activation_private_workflow_v1.rs"]
mod private_workflow;
pub use private_workflow::{Material, MakeCredential, EncryptedCredential, CurrentContext,
    Challenge, Exchange, RecoveryResponse};

pub const RULE_ENTRY: &[u8] = b"AdmissionActivationParentQuorumV1";
pub const RULE_DOMAIN: &[u8] = b"MUTINY-BUILD8-ADMISSION-ACTIVATION-RULE-V1";
pub const SCOPE_DOMAIN: &[u8] = b"MUTINY-BUILD8-ADMISSION-ACTIVATION-BLOCK-SCOPE-V1";
pub fn rule_commitment() -> Hash {
    crate::domain_hash(RULE_DOMAIN,b"existing-parent-strict-quorum;independent-private-activation;all-accepted-bindings-and-EK-classes;exact-whole-block-and-body;signer-phase-bound;finite-local-elapsed-no-default;unsigned-restart-renews;exact-durable-signed-retransmit;offline-public-history;no-physical-uniqueness-inference;no-production-factory")
}
pub(crate) fn selected(state:&State) -> Result<bool> {
    let Some(raw)=state.protocol_records.get(&crate::genesis_v2::parameters_key()) else {return Ok(false);};
    let parameters=crate::genesis_v2::Parameters::decode(raw).map_err(|_|Error::Codec)?;
    let Some((_,commitment))=parameters.rules.commitments.iter().find(|(name,_)|name.as_slice()==RULE_ENTRY) else {return Ok(false);};
    if *commitment!=rule_commitment(){return Err(Error::WrongFingerprint);}
    if state.continuity.as_ref().is_some_and(|registry|
        parameters.fingerprint().ok()!=Some(registry.fingerprint)){
        return Err(Error::WrongFingerprint);
    }
    Ok(true)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose { Join, HardwareReplacement, ContinuityBinding, Recovery }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Position { Operation(u32), Recovery }
/// Read-only native-execution receipt. There is no public constructor/decoder.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admission {
    position:Position,
    purpose:Purpose,
    wire:Hash,
    binding_wire:Vec<u8>,
    node:Hash,
    hardware_generation:u64,
    key_generation:u64,
    profile:Hash,
    ak_name:[u8;34],
    endorsements:Vec<Hash>,
}
impl Admission {
    pub fn position(&self)->Position{self.position}
    pub fn purpose(&self)->Purpose{self.purpose}
    pub fn node(&self)->Hash{self.node}
    pub fn binding_bytes(&self)->&[u8]{&self.binding_wire}
    pub fn ak_name(&self)->&[u8;34]{&self.ak_name}
    pub fn endorsements(&self)->&[Hash]{&self.endorsements}
    fn accepted(post:&State,height:u64,position:Position,purpose:Purpose,wire:Hash,binding:&Binding)->Result<Self>{
        // A recovery replacement may itself rotate during the successful first
        // resumed block. The exact newly retired binding at H is then retained
        // by native execution even though the final active binding differs.
        if post.membership_v2.get(binding.admission.node).map(|c|c.binding())!=Some(binding)
            && !post.retired_continuity_v2.entries().any(|r|r.retired_height==height && &r.binding==binding){
            return Err(Error::WrongAnchor);
        }
        let profile=TpmProfile::decode(&binding.admission.profile)?;
        let endorsements=crate::endorsement_identity::committed_identities(&profile);
        if endorsements.is_empty() || endorsements.iter().copied().collect::<std::collections::BTreeSet<_>>().len()!=endorsements.len(){return Err(Error::Duplicate);}
        Ok(Self {position,purpose,wire,binding_wire:binding.encode()?,node:binding.admission.node,
            hardware_generation:binding.admission.hardware_generation,key_generation:binding.admission.key_generation,
            profile:profile.commitment()?,ak_name:crate::provenance::ak_name(&profile.ak_public)?,endorsements})
    }
}
/// Exact executed whole-block scope. Proposer/public audit observations cannot
/// construct this value or supply an activation result for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    parent:FinalizedAnchor,
    block:Hash,
    body:Vec<u8>,
    rule:Hash,
    class:crate::provenance::AdmissionClass,
    admissions:Vec<Admission>,
    commitment:Hash,
}
impl Scope {
    pub fn parent(&self)->&FinalizedAnchor{&self.parent}
    pub fn block(&self)->Hash{self.block}
    pub fn body_bytes(&self)->&[u8]{&self.body}
    pub fn admissions(&self)->&[Admission]{&self.admissions}
    pub fn commitment(&self)->Hash{self.commitment}
    /// Call only AFTER successful native full execution. No parsed/prepared
    /// material is sufficient. Recovery need not have an operation in the body.
    pub(crate) fn executed(before:&State,post:&State,parent:&FinalizedAnchor,header:&WorkHeader,
        body:&BlockBody,recovery:Option<&crate::recovery_transition_v2::Prepared>)->Result<Option<Self>> {
        if !selected(before)? {return Ok(None);}
        if parent.network!=NETWORK_ID || (parent.genesis,parent.fingerprint,parent.block,parent.height.checked_add(1))
            !=(header.candidate.genesis,header.candidate.fingerprint,header.candidate.parent,Some(header.candidate.height)){
            return Err(Error::WrongAnchor);
        }
        let parameters=before.protocol_records.get(&crate::genesis_v2::parameters_key())
            .map(|raw|crate::genesis_v2::Parameters::decode(raw).map_err(|_|Error::Codec))
            .transpose()?;
        let mut admissions=Vec::new();
        for (index,raw) in body.operations.iter().enumerate(){
            if crate::trading_host_v1::operation(raw)?{continue;}
            let position=Position::Operation(u32::try_from(index).map_err(|_|Error::Capacity)?);
            let wire=crate::domain_hash(crate::operation_index_v2::WIRE_DOMAIN,raw);
            let admission=match crate::blocks::operation_kind(raw)?{
                15=>{
                    // Native execution has already authenticated the outer V3
                    // carrier, included witness and exact inner authorization.
                    // Retain OUTER wire identity; do not classify a parsed carrier
                    // or caller-selected rule as an accepted admission.
                    let (signed,_)=crate::admission_public_v3::item(raw,parameters.as_ref())?;
                    Some(Admission::accepted(post,header.candidate.height,position,Purpose::Join,wire,&crate::join_v2::Join::decode(&signed)?.binding)?)
                },
                16=>{
                    let (signed,_)=crate::admission_public_v3::item(raw,parameters.as_ref())?;
                    Some(Admission::accepted(post,header.candidate.height,position,Purpose::HardwareReplacement,wire,&crate::hardware_rotate_v2::HardwareRotate::decode(&signed)?.binding)?)
                },
                21=>Some(Admission::accepted(post,header.candidate.height,position,Purpose::ContinuityBinding,wire,&crate::continuity_key_rotate_v2::KeyRotate::decode(raw)?.binding)?),
                // NodeKeyRotate (22) updates node_current without admitting a
                // new Binding/AK/profile. Wallet/value transactions likewise
                // add no activation requirement of their own.
                _=>None,
            };
            if let Some(admission)=admission {admissions.push(admission);}
        }
        if let Some(recovery)=recovery {
            admissions.push(Admission::accepted(post,header.candidate.height,Position::Recovery,Purpose::Recovery,
                recovery.commitment()?,recovery.activation_binding())?);
        }
        if admissions.is_empty(){return Ok(None);}
        // The authenticated parent selects the same shared capacity rules used
        // by native execution. Legacy encode would reject a valid oversized A2
        // admission after execution and lose its mandatory signing gate.
        let capacity=crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(
            before,parent.clone(),before.root().map_err(|_|Error::WrongAnchor)?)?;
        let body=capacity.encode(body)?;
        let rule=rule_commitment();let block=header.block_hash();
        let mut e=Encoder::new(Vec::new());
        e.array(8).unwrap().u8(1).unwrap().u32(NETWORK_ID).unwrap().bytes(&parent.encode()).unwrap()
            .bytes(&block).unwrap().bytes(&header.encode()).unwrap().bytes(&body).unwrap().bytes(&rule).unwrap()
            .array(admissions.len() as u64).unwrap();
        for a in &admissions {
            e.array(3).unwrap();
            match a.position {Position::Operation(p)=>{e.array(2).unwrap().u8(1).unwrap().u32(p).unwrap();},Position::Recovery=>{e.array(1).unwrap().u8(2).unwrap();}}
            e.bytes(&a.wire).unwrap().bytes(&a.binding_wire).unwrap();
        }
        let commitment=crate::domain_hash(SCOPE_DOMAIN,&e.into_writer());
        Ok(Some(Self{parent:parent.clone(),block,body,rule,class:before.admission_class()?,admissions,commitment}))
    }
}

/// Authenticated PUBLIC reservation classification, not a private activation
/// success marker. It may survive restart only inside counter-protected storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Classification { Unknown, NoAdmission, Required(Hash) }
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure { Missing, Expired, Scope, Elapsed, Deadline, ProviderUnavailable,
    Material, Classes, Randomness, Adapter, Bounds, Response, SecretMismatch, UnknownAttempt }

/// Local trusted elapsed continuity, independently of qualified UTC eligibility.
/// A caller-selected finite local limit is required; no consensus TTL is added.
pub trait Elapsed: Send + Sync {
    /// Legacy exact-point software TEST source. Qualified native owners override
    /// capture(), and their scalar elapsed() route must remain unavailable.
    fn elapsed(&self)->std::result::Result<std::time::Duration,Failure>;
    fn capture(&self)->std::result::Result<ElapsedCapture,Failure> {
        let point=self.elapsed()?;
        Ok(ElapsedCapture {lower:point,upper:point,boot:0,context:[0;32],drift_ppb:0})
    }
}
/// A trusted elapsed-source observation, never a public proof or qualification
/// token. The installed-owner adapter must preserve native sandwich uncertainty,
/// exact selected drift and current owner identity before returning this value.
/// Constructor access confers no installed authority; production factories must
/// accept only the independently selected, revocable owner proxy.
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct ElapsedCapture { lower:std::time::Duration,upper:std::time::Duration,
    boot:u128,context:Hash,drift_ppb:u64 }
impl ElapsedCapture {
    pub fn from_current_owner(lower:std::time::Duration,upper:std::time::Duration,
        boot:u128,context:Hash,drift_ppb:u64)->std::result::Result<Self,Failure>{
        if lower>upper||boot==0||context==[0;32]||drift_ppb>=1_000_000_000 {
            return Err(Failure::Elapsed);
        }
        Ok(Self {lower,upper,boot,context,drift_ppb})
    }
    fn follows(self,previous:Self)->bool {
        self.lower<=self.upper&&self.lower>=previous.lower&&self.upper>=previous.upper
            &&(self.boot,self.context,self.drift_ppb)==(previous.boot,previous.context,previous.drift_ppb)
            &&self.drift_ppb<1_000_000_000
    }
    fn deadline(self,lifetime:std::time::Duration)->std::result::Result<std::time::Duration,Failure>{
        // Compare now.upper against start.lower plus a rounded-down counter
        // lifetime. This includes start-capture uncertainty and slow-oscillator
        // undercount, equivalent to a rounded-up bound on real elapsed age.
        let ns=lifetime.as_nanos().checked_mul(u128::from(1_000_000_000-self.drift_ppb))
            .ok_or(Failure::Deadline)?/1_000_000_000;
        let seconds=u64::try_from(ns/1_000_000_000).map_err(|_|Failure::Deadline)?;
        let offset=std::time::Duration::new(seconds,(ns%1_000_000_000) as u32);
        self.lower.checked_add(offset).ok_or(Failure::Deadline)
    }
}
/// A private owned completion token. No public constructor, Clone, Debug,
/// deserializer or conversion from public LocalObservation exists.
struct Capability {
    signer:Hash,
    scope:Hash,
    round:u64,
    step:u8,
    deadline:std::time::Duration,
}
/// Native executed request, including the actual locked block and signing phase.
/// No public constructor or decoder permits peer-provided admission scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request { scope:Scope, signer:Hash, round:u64, step:u8 }
impl Request {
    pub fn scope(&self)->&Scope{&self.scope}
    pub fn signer(&self)->Hash{self.signer}
    pub fn round(&self)->u64{self.round}
    pub fn step(&self)->u8{self.step}
    pub(crate) fn new(scope:Scope,signer:Hash,round:u64,step:u8)->Self{Self{scope,signer,round,step}}
}
/// A custody-call permit; minted only by the counter voter after native
/// classification and, when required, consumption of private activation.
/// It is neither clonable nor constructible/decodable through public APIs.
struct PermitElapsed {
    source:std::sync::Arc<dyn Elapsed>,
    deadline:std::time::Duration,
    // Owned by the permit so custody cannot rely on an earlier counter-voter check.
    last:std::sync::Mutex<std::result::Result<ElapsedCapture,Failure>>,
}
pub struct PrivateSignPermit { signer:Hash, rule:Option<Hash>, message:Vec<u8>, elapsed:Option<PermitElapsed> }
impl PrivateSignPermit {
    /// Check at native custody entry and again immediately before private signing.
    /// An unavailable/backward elapsed source permanently invalidates this permit.
    /// Ordinary non-admission permits acquire no clock/provider dependency.
    pub fn check_at_custody_entry(&self,signer:Hash,rule:Option<Hash>,message:&[u8])
        ->std::result::Result<(),Failure>{
        if self.signer!=signer || self.rule!=rule || self.message.as_slice()!=message{return Err(Failure::Scope);}
        if let Some(elapsed)=&self.elapsed {
            let mut last=elapsed.last.lock().map_err(|_|Failure::Elapsed)?;
            let previous=match *last {Ok(value)=>value,Err(error)=>return Err(error)};
            let now=match elapsed.source.capture(){
                Ok(now) if now.follows(previous)=>now,
                _=>{*last=Err(Failure::Elapsed);return Err(Failure::Elapsed);}
            };
            if now.upper>=elapsed.deadline{*last=Err(Failure::Expired);return Err(Failure::Expired);}
            *last=Ok(now);
        }
        Ok(())
    }
    pub fn authorizes(&self,signer:Hash,rule:Option<Hash>,message:&[u8])->bool{
        self.check_at_custody_entry(signer,rule,message).is_ok()
    }
    pub(crate) fn ordinary(signer:Hash,rule:Option<Hash>,message:Vec<u8>)->Self{Self{signer,rule,message,elapsed:None}}
}
struct Pending { session:Hash, request:Request, expected:Vec<Hash>, deadline:std::time::Duration }
/// Normal source deliberately refuses Production material while the vetted
/// actual-activation/class/current-context adapter remains unavailable. Missing
/// configuration/capability refuses a selected admission; ordinary blocks do not
/// acquire a verifier dependency. Private software controls may exercise it.
pub(crate) struct Gate {
    capability:Option<Capability>,
    elapsed:Option<std::sync::Arc<dyn Elapsed>>,
    last:Option<std::time::Duration>,
    last_capture:Option<ElapsedCapture>,
    failed:bool,
    lifetime:Option<std::time::Duration>,
    pending:Option<Pending>,
}
impl Default for Gate {
    fn default()->Self {Self{capability:None,elapsed:None,last:None,last_capture:None,failed:false,lifetime:None,pending:None}}
}
impl Gate {
    fn now(&mut self)->std::result::Result<std::time::Duration,Failure>{
        if self.failed{return Err(Failure::Elapsed);}
        let capture=match self.elapsed.as_ref().ok_or(Failure::Missing)?.capture(){
            Ok(now) if now.lower<=now.upper&&now.drift_ppb<1_000_000_000
                &&self.last_capture.is_none_or(|last|now.follows(last))
                &&self.last.is_none_or(|last|now.upper>=last)=>now,
            _=>{self.failed=true;self.capability=None;self.pending=None;return Err(Failure::Elapsed);}
        };
        self.last=Some(capture.upper);self.last_capture=Some(capture);Ok(capture.upper)
    }
    fn capture_deadline(&self)->std::result::Result<std::time::Duration,Failure>{
        self.last_capture.ok_or(Failure::Elapsed)?.deadline(self.lifetime.ok_or(Failure::Missing)?)
    }
    pub(crate) fn check(&mut self,signer:Hash,scope:Hash,round:u64,step:u8)
        ->std::result::Result<(),Failure> {
        let now=self.now()?;
        let cap=self.capability.as_ref().ok_or(Failure::Missing)?;
        if now>=cap.deadline {self.capability=None;return Err(Failure::Expired);}
        if (cap.signer,cap.scope,cap.round,cap.step)!=(signer,scope,round,step){
            self.capability=None;return Err(Failure::Scope);
        }
        Ok(())
    }
    pub(crate) fn consume(&mut self,signer:Hash,scope:Hash,round:u64,step:u8,message:Vec<u8>)
        ->std::result::Result<PrivateSignPermit,Failure> {
        self.check(signer,scope,round,step)?;
        let cap=self.capability.take().ok_or(Failure::Missing)?;
        Ok(PrivateSignPermit{signer,rule:Some(rule_commitment()),message,elapsed:Some(PermitElapsed{
            source:self.elapsed.as_ref().ok_or(Failure::Missing)?.clone(),deadline:cap.deadline,
            last:std::sync::Mutex::new(Ok(self.last_capture.ok_or(Failure::Elapsed)?)),
        })})
    }
    pub(crate) fn post_sign(&mut self,permit:&PrivateSignPermit)->std::result::Result<(),Failure>{
        if let Err(error)=permit.check_at_custody_entry(permit.signer,permit.rule,&permit.message){
            if error==Failure::Elapsed{self.failed=true;self.invalidate();}
            return Err(error);
        }
        if let Some(elapsed)=&permit.elapsed {
            if self.now()?>=elapsed.deadline{return Err(Failure::Expired);}
        }
        Ok(())
    }
    pub(crate) fn invalidate(&mut self){self.capability=None;self.pending=None;}
    pub(crate) fn configure(&mut self,lifetime:std::time::Duration,elapsed:std::sync::Arc<dyn Elapsed>)
        ->std::result::Result<(),Failure>{
        self.invalidate();
        // A lost elapsed basis cannot be repaired inside a live signer.
        if self.failed{return Err(Failure::Elapsed);}
        if lifetime.is_zero(){return Err(Failure::Deadline);}
        if self.elapsed.is_some(){return Err(Failure::Scope);}
        self.lifetime=Some(lifetime);self.elapsed=Some(elapsed);self.now()?;Ok(())
    }
}
#[cfg(test)]
pub(crate) fn completed_software_gate(signer:Hash,scope:Hash,step:u8,
    elapsed:std::sync::Arc<dyn Elapsed>)->Gate{
    private_workflow::software_models::completed_gate(signer,scope,step,elapsed)
}

#[cfg(test)]
mod elapsed_interval_controls {
    use super::*;
    use std::time::Duration;
    #[test]
    fn uncertain_start_and_selected_slow_drift_cannot_extend_freshness() {
        let start=ElapsedCapture::from_current_owner(Duration::from_nanos(90),Duration::from_nanos(110),
            1,[1;32],100_000_000).unwrap();
        let deadline=start.deadline(Duration::from_nanos(100)).unwrap();
        assert_eq!(deadline,Duration::from_nanos(180));
        // Scalar upper-end subtraction would falsely give 80 ns age here.
        // The conservative native interval has already expired at 190 ns.
        let now=ElapsedCapture::from_current_owner(Duration::from_nanos(170),Duration::from_nanos(190),
            1,[1;32],100_000_000).unwrap();
        assert!(now.follows(start));assert!(now.upper>=deadline);
        assert!(ElapsedCapture::from_current_owner(Duration::from_nanos(2),Duration::from_nanos(1),1,[1;32],0).is_err());
        assert!(ElapsedCapture::from_current_owner(Duration::ZERO,Duration::ZERO,1,[1;32],1_000_000_000).is_err());
        assert!(ElapsedCapture {drift_ppb:0,..start}.deadline(Duration::MAX).is_err());
    }
    #[test]
    fn native_capture_identity_or_interval_rollback_refuses() {
        let start=ElapsedCapture::from_current_owner(Duration::from_nanos(90),Duration::from_nanos(110),1,[1;32],7).unwrap();
        for changed in [ElapsedCapture {boot:2,..start},ElapsedCapture {context:[2;32],..start},
            ElapsedCapture {drift_ppb:8,..start},ElapsedCapture {lower:Duration::from_nanos(89),..start},
            ElapsedCapture {upper:Duration::from_nanos(109),..start}] { assert!(!changed.follows(start)); }
    }
}
