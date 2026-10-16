//! Private local protocol. Production material is deliberately refused until
//! actual adapter/class qualification exists; software TEST exchanges only.
use super::*;
use zeroize::Zeroizing;
type LocalResult<T>=std::result::Result<T,Failure>;
const SECRET_DOMAIN:&[u8]=b"MUTINY-BUILD8-ACTIVATION-SECRET-V1";
const MAX_ENCRYPTED:usize=4096;

/// Complete class material linked to one native accepted receipt. Exact public
/// witness verification is mandatory; caller flags/digests alone cannot mint it.
pub struct Material { admission:Admission, endorsements:Vec<(Hash,Vec<u8>)> }
impl Material {
    pub fn validate(admission:&Admission,witness:&[u8],
        context:&crate::attestation_witness::WitnessContext<'_>,
        syntax:&dyn crate::ek_chain::CertificateSyntax)->LocalResult<Self>{
        Self::validate_inner(admission,witness,context,syntax,None)
    }
    /// The selected immutable parameter policy. No applicant alias or class flag.
    pub fn validate_with_policy(admission:&Admission,witness:&[u8],
        policy:&crate::test_value_root_alias_v1::WitnessPolicy,reference_time:u64,
        syntax:&dyn crate::ek_chain::CertificateSyntax)->LocalResult<Self>{
        let context=policy.context(reference_time);
        Self::validate_inner(admission,witness,&context,syntax,Some(policy))
    }
    fn validate_inner(admission:&Admission,witness:&[u8],
        context:&crate::attestation_witness::WitnessContext<'_>,
        syntax:&dyn crate::ek_chain::CertificateSyntax,
        policy:Option<&crate::test_value_root_alias_v1::WitnessPolicy>)->LocalResult<Self>{
        // This is an implementation/TEST successor, not an enabled physical
        // admission service. No class-pinned genuine production adapter exists.
        if context.chain.class==crate::provenance::AdmissionClass::Production{
            return Err(Failure::ProviderUnavailable);
        }
        let binding=Binding::decode(admission.binding_bytes()).map_err(|_|Failure::Material)?;
        let profile=TpmProfile::decode(&binding.admission.profile).map_err(|_|Failure::Material)?;
        let statement=profile.provenance.as_ref().ok_or(Failure::Material)?;
        match policy {
            None=>crate::attestation_witness::verify_witness(statement,Some(witness),context,syntax),
            Some(policy)=>crate::attestation_witness::verify_witness_with_policy(
                statement,Some(witness),policy,context.chain.reference_time,syntax),
        }.map_err(|_|Failure::Material)?;
        if profile.commitment().map_err(|_|Failure::Material)?!=admission.profile
            || crate::provenance::ak_name(&profile.ak_public).map_err(|_|Failure::Material)?!=admission.ak_name
            || crate::endorsement_identity::committed_identities(&profile)!=admission.endorsements{
            return Err(Failure::Scope);
        }
        let evidence=crate::attestation_witness::AttestationWitness::decode(witness).map_err(|_|Failure::Material)?;
        if evidence.endorsements.len()!=admission.endorsements.len(){return Err(Failure::Classes);}
        let mut endorsements=Vec::new();
        for (identity,item) in admission.endorsements.iter().zip(evidence.endorsements){
            let parsed=crate::endorsement_identity::parse_ek_public_area(&item.ek_public_area)
                .map_err(|_|Failure::Classes)?;
            if parsed.key.identity().map_err(|_|Failure::Classes)?!=*identity{return Err(Failure::Classes);}
            endorsements.push((*identity,item.ek_public_area));
        }
        Ok(Self{admission:admission.clone(),endorsements})
    }
}
/// Explicit trusted adapter boundary. An honest configured verifier must use a
/// vetted MakeCredential implementation for the exact EK public area and AK
/// Name, never return a public fixed value. No production implementation ships.
pub trait MakeCredential {
    fn make_credential(&mut self,ek:&[u8],ak_name:&[u8;34],secret:&[u8;32])
        ->LocalResult<EncryptedCredential>;
}
pub struct EncryptedCredential { credential:Vec<u8>,seed:Vec<u8> }
impl EncryptedCredential {
    pub fn new(credential:Vec<u8>,seed:Vec<u8>)->LocalResult<Self>{
        if credential.is_empty()||seed.is_empty()||credential.len()>MAX_ENCRYPTED||seed.len()>MAX_ENCRYPTED{
            return Err(Failure::Bounds);
        }
        Ok(Self{credential,seed})
    }
    pub fn credential(&self)->&[u8]{&self.credential}
    pub fn encrypted_seed(&self)->&[u8]{&self.seed}
}
/// Independently own-canonical current provider. It must enforce exact signer,
/// rule, round/phase, accepted binding, revocation and qualified class policy.
/// Returning a peer checkpoint/audit flag violates the trusted adapter contract.
pub trait CurrentContext {
    fn current_parent(&mut self,request:&Request)->LocalResult<FinalizedAnchor>;
}
pub struct Challenge { pub admission_index:u32,pub class_index:u8,pub identity:Hash,pub encrypted:EncryptedCredential }
pub struct Exchange { pub session:Hash,pub request:Request,pub challenges:Vec<Challenge> }
/// Private returned value, never Debug/Clone/serialization. Caller must erase
/// the private-channel receive buffer as well as transferring this owned value.
pub struct RecoveryResponse { admission_index:u32,class_index:u8,secret:Zeroizing<[u8;32]> }
impl RecoveryResponse {
    pub fn new(admission_index:u32,class_index:u8,secret:Zeroizing<[u8;32]>)->Self{
        Self{admission_index,class_index,secret}
    }
}
fn check_current(request:&Request,provider:&mut dyn CurrentContext)->LocalResult<()> {
    if provider.current_parent(request)?!=request.scope.parent{return Err(Failure::Scope);}
    Ok(())
}
impl Gate {
    pub(crate) fn begin(&mut self,request:Request,materials:&[Material],
        provider:&mut dyn CurrentContext,adapter:&mut dyn MakeCredential)->LocalResult<Exchange>{
        // At most one local in-flight attempt. A new challenge explicitly
        // cancels the previous private attempt/grant, never changes BFT state.
        self.invalidate();
        if request.scope.class==crate::provenance::AdmissionClass::Production{
            return Err(Failure::ProviderUnavailable);
        }
        self.now()?;
        let deadline=self.capture_deadline()?;
        if request.scope.admissions.is_empty()||materials.len()!=request.scope.admissions.len(){return Err(Failure::Material);}
        check_current(&request,provider)?;
        let mut session=[0;32];
        mutiny_crypto_v2::fill_os_random(&mut session).map_err(|_|Failure::Randomness)?;
        if session==[0;32]{return Err(Failure::Randomness);}
        let mut challenges=Vec::new();let mut expected=Vec::new();let mut unique=std::collections::BTreeSet::new();
        for (i,(receipt,material)) in request.scope.admissions.iter().zip(materials).enumerate(){
            if receipt!=&material.admission||material.endorsements.len()!=receipt.endorsements.len(){return Err(Failure::Scope);}
            for (j,(identity,ek)) in material.endorsements.iter().enumerate(){
                if receipt.endorsements.get(j)!=Some(identity){return Err(Failure::Classes);}
                let mut secret=Zeroizing::new([0;32]);
                mutiny_crypto_v2::fill_os_random(secret.as_mut()).map_err(|_|Failure::Randomness)?;
                let commitment=crate::domain_hash(SECRET_DOMAIN,secret.as_ref());
                if *secret==[0;32]||!unique.insert(commitment){return Err(Failure::Randomness);}
                let encrypted=adapter.make_credential(ek,&receipt.ak_name,&secret)?;
                // Enforce this boundary even if the trusted adapter changes.
                if encrypted.credential.is_empty()||encrypted.seed.is_empty()
                    ||encrypted.credential.len()>MAX_ENCRYPTED||encrypted.seed.len()>MAX_ENCRYPTED{return Err(Failure::Bounds);}
                expected.push(commitment);
                challenges.push(Challenge{admission_index:u32::try_from(i).map_err(|_|Failure::Bounds)?,
                    class_index:u8::try_from(j).map_err(|_|Failure::Bounds)?,identity:*identity,encrypted});
            }
        }
        check_current(&request,provider)?;
        if self.now()?>=deadline{return Err(Failure::Expired);}
        self.pending=Some(Pending{session,request:request.clone(),expected,deadline});
        Ok(Exchange{session,request,challenges})
    }
    pub(crate) fn complete(&mut self,session:Hash,request:&Request,responses:Vec<RecoveryResponse>,
        provider:&mut dyn CurrentContext)->LocalResult<()> {
        // Consume first, including wrong session/context/results; no guessing,
        // partial success, retries or restart authority from public markers.
        let pending=self.pending.take().ok_or(Failure::UnknownAttempt)?;
        self.capability=None;
        if pending.session!=session||pending.request!=*request{return Err(Failure::Scope);}
        if self.now()?>=pending.deadline{return Err(Failure::Expired);}
        check_current(request,provider)?;
        if responses.len()!=pending.expected.len(){return Err(Failure::Response);}
        let mut n=0;
        for (i,receipt) in request.scope.admissions.iter().enumerate(){
            for j in 0..receipt.endorsements.len(){
                let response=&responses[n];
                if response.admission_index as usize!=i||response.class_index as usize!=j{return Err(Failure::Response);}
                if crate::domain_hash(SECRET_DOMAIN,response.secret.as_ref())!=pending.expected[n]{return Err(Failure::SecretMismatch);}
                n+=1;
            }
        }
        check_current(request,provider)?;
        if self.now()?>=pending.deadline{return Err(Failure::Expired);}
        self.capability=Some(Capability{signer:request.signer,scope:request.scope.commitment,
            round:request.round,step:request.step,deadline:pending.deadline});
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod software_models {
    //! Private modeled protocol controls only. Synthetic Material/Scope below
    //! cannot pass native Material::validate or prove TPM/class qualification.
    //! OS randomness is REAL; modeled adapter keeps private buffers in memory.
    use super::*;
    use std::{sync::{Arc,atomic::{AtomicU64,Ordering}},time::Duration};
    struct Clock(AtomicU64);
    impl Elapsed for Clock {
        fn elapsed(&self)->LocalResult<Duration>{
            let value=self.0.load(Ordering::SeqCst);
            if value==u64::MAX{Err(Failure::Elapsed)}else{Ok(Duration::from_secs(value))}
        }
    }
    struct Provider { parent:FinalizedAnchor,calls:usize,change_at:Option<usize> }
    impl CurrentContext for Provider {
        fn current_parent(&mut self,_:&Request)->LocalResult<FinalizedAnchor>{
            self.calls+=1;
            if self.change_at==Some(self.calls){return Err(Failure::ProviderUnavailable);}
            Ok(self.parent.clone())
        }
    }
    struct Adapter { returned:Vec<Zeroizing<[u8;32]>>,fail_at:Option<usize>,calls:usize }
    impl MakeCredential for Adapter {
        fn make_credential(&mut self,ek:&[u8],name:&[u8;34],secret:&[u8;32])->LocalResult<EncryptedCredential>{
            assert_eq!(name,&[8;34]);assert!(ek==[1]||ek==[2]);
            self.calls+=1;
            if self.fail_at==Some(self.calls){return Err(Failure::Adapter);}
            self.returned.push(Zeroizing::new(*secret));
            EncryptedCredential::new(vec![self.calls as u8],vec![7])
        }
    }
    fn request()->Request{
        let parent=FinalizedAnchor{network:NETWORK_ID,genesis:[1;32],fingerprint:[2;32],height:4,block:[3;32]};
        let receipts=(0..2).map(|i|Admission{position:Position::Operation(i),purpose:Purpose::Join,
            wire:[4+i as u8;32],binding_wire:vec![10+i as u8],node:[5+i as u8;32],hardware_generation:1,
            key_generation:1,profile:[6;32],ak_name:[8;34],endorsements:vec![[1;32],[2;32]]}).collect();
        Request::new(Scope{parent,block:[4;32],body:vec![12,13],rule:rule_commitment(),
            class:crate::provenance::AdmissionClass::LegacyTest,admissions:receipts,commitment:[9;32]},[20;32],0,2)
    }
    fn setup()->(Gate,Request,Vec<Material>,Provider,Adapter,Arc<Clock>){
        let request=request();let clock=Arc::new(Clock(AtomicU64::new(0)));
        let mut gate=Gate::default();gate.configure(Duration::from_secs(10),clock.clone()).unwrap();
        let materials=request.scope.admissions.iter().map(|a|Material{admission:a.clone(),
            endorsements:vec![([1;32],vec![1]),([2;32],vec![2])]}).collect();
        let provider=Provider{parent:request.scope.parent.clone(),calls:0,change_at:None};
        let adapter=Adapter{returned:Vec::new(),fail_at:None,calls:0};
        (gate,request,materials,provider,adapter,clock)
    }
    fn responses(adapter:&mut Adapter)->Vec<RecoveryResponse>{
        std::mem::take(&mut adapter.returned).into_iter().enumerate()
            .map(|(n,secret)|RecoveryResponse::new((n/2) as u32,(n%2) as u8,secret)).collect()
    }
    /// Private unit-test boundary fixture uses the actual fresh-secret protocol;
    /// synthetic scope/material do not establish native/physical admission.
    pub(crate) fn completed_gate(signer:Hash,scope:Hash,step:u8,
        elapsed:Arc<dyn Elapsed>)->Gate{
        let (_,mut r,m,mut p,mut a,_)=setup();r.signer=signer;r.scope.commitment=scope;r.step=step;
        let mut gate=Gate::default();gate.configure(Duration::from_secs(10),elapsed).unwrap();
        let exchange=gate.begin(r.clone(),&m,&mut p,&mut a).unwrap();
        gate.complete(exchange.session,&r,responses(&mut a),&mut p).unwrap();gate
    }
    #[test]
    fn all_private_classes_complete_once_then_exact_signer_message_permit(){
        let (mut gate,r,m,mut p,mut a,_)=setup();let exchange=gate.begin(r.clone(),&m,&mut p,&mut a).unwrap();
        assert_eq!(exchange.challenges.len(),4);
        let returned=responses(&mut a);gate.complete(exchange.session,&r,returned,&mut p).unwrap();
        let permit=gate.consume(r.signer,r.scope.commitment,0,2,vec![1,2,3]).unwrap();
        assert!(permit.authorizes(r.signer,Some(rule_commitment()),&[1,2,3]));
        assert!(!permit.authorizes([21;32],Some(rule_commitment()),&[1,2,3]));
        assert!(!permit.authorizes(r.signer,None,&[1,2,3]));
        assert!(!permit.authorizes(r.signer,Some(rule_commitment()),&[1,2,4]));
        gate.post_sign(&permit).unwrap();
        assert_eq!(gate.check(r.signer,r.scope.commitment,0,2),Err(Failure::Missing));
    }
    #[test]
    fn public_empty_results_and_partial_classes_cannot_complete(){
        for count in [0,1,3]{
            let (mut gate,r,m,mut p,mut a,_)=setup();let exchange=gate.begin(r.clone(),&m,&mut p,&mut a).unwrap();
            let mut returned=responses(&mut a);returned.truncate(count);
            assert_eq!(gate.complete(exchange.session,&r,returned,&mut p),Err(Failure::Response));
            assert!(gate.capability.is_none()&&gate.pending.is_none());
            assert_eq!(gate.complete(exchange.session,&r,Vec::new(),&mut p),Err(Failure::UnknownAttempt));
        }
    }
    #[test]
    fn wrong_private_result_consumes_entire_attempt(){
        let (mut gate,r,m,mut p,mut a,_)=setup();let exchange=gate.begin(r.clone(),&m,&mut p,&mut a).unwrap();
        let mut returned=responses(&mut a);returned[2].secret[0]^=1;
        assert_eq!(gate.complete(exchange.session,&r,returned,&mut p),Err(Failure::SecretMismatch));
        assert!(gate.capability.is_none()&&gate.pending.is_none());
    }
    #[test]
    fn duplicate_or_reordered_response_indices_refuse(){
        let (mut gate,r,m,mut p,mut a,_)=setup();let exchange=gate.begin(r.clone(),&m,&mut p,&mut a).unwrap();
        let mut returned=responses(&mut a);returned.swap(0,1);
        assert_eq!(gate.complete(exchange.session,&r,returned,&mut p),Err(Failure::Response));
    }
    #[test]
    fn exact_whole_request_context_cannot_be_substituted(){
        for field in 0..9{
            let (mut gate,r,m,mut p,mut a,_)=setup();let exchange=gate.begin(r.clone(),&m,&mut p,&mut a).unwrap();
            let mut changed=r.clone();match field{
                0=>changed.signer[0]^=1,1=>changed.round+=1,2=>changed.step=3,
                3=>changed.scope.parent.genesis[0]^=1,4=>changed.scope.parent.fingerprint[0]^=1,
                5=>changed.scope.block[0]^=1,6=>changed.scope.body.push(99),
                7=>changed.scope.admissions[0].binding_wire.push(99),_=>changed.scope.rule[0]^=1,
            }
            assert_eq!(gate.complete(exchange.session,&changed,responses(&mut a),&mut p),Err(Failure::Scope));
            assert!(gate.capability.is_none()&&gate.pending.is_none());
        }
    }
    #[test]
    fn context_checked_before_and_after_preparation(){
        for change in [1,2]{
            let (mut gate,r,m,mut p,mut a,_)=setup();p.change_at=Some(change);
            assert!(matches!(gate.begin(r,&m,&mut p,&mut a),Err(Failure::ProviderUnavailable)));
            assert_eq!(a.calls,if change==1{0}else{4});assert!(gate.pending.is_none());
        }
    }
    #[test]
    fn context_checked_before_and_after_completion(){
        for change in [3,4]{
            let (mut gate,r,m,mut p,mut a,_)=setup();let exchange=gate.begin(r.clone(),&m,&mut p,&mut a).unwrap();
            p.change_at=Some(change);
            assert_eq!(gate.complete(exchange.session,&r,responses(&mut a),&mut p),Err(Failure::ProviderUnavailable));
            assert!(gate.capability.is_none());
        }
    }
    #[test]
    fn adapter_partial_failure_leaves_no_pending_permission(){
        let (mut gate,r,m,mut p,mut a,_)=setup();a.fail_at=Some(3);
        assert!(matches!(gate.begin(r,&m,&mut p,&mut a),Err(Failure::Adapter)));
        assert!(gate.pending.is_none()&&gate.capability.is_none());
    }
    #[test]
    fn production_material_never_starts_adapter(){
        let (mut gate,mut r,m,mut p,mut a,_)=setup();r.scope.class=crate::provenance::AdmissionClass::Production;
        assert!(matches!(gate.begin(r,&m,&mut p,&mut a),Err(Failure::ProviderUnavailable)));assert_eq!(a.calls,0);
    }
    #[test]
    fn deadline_expiry_consumes_pending_without_sleep(){
        let (mut gate,r,m,mut p,mut a,clock)=setup();let exchange=gate.begin(r.clone(),&m,&mut p,&mut a).unwrap();
        clock.0.store(10,Ordering::SeqCst);
        assert_eq!(gate.complete(exchange.session,&r,responses(&mut a),&mut p),Err(Failure::Expired));
        assert!(gate.pending.is_none()&&gate.capability.is_none());
    }
    #[test]
    fn deadline_expiry_between_completion_and_sign_refuses(){
        let (mut gate,r,m,mut p,mut a,clock)=setup();let exchange=gate.begin(r.clone(),&m,&mut p,&mut a).unwrap();
        gate.complete(exchange.session,&r,responses(&mut a),&mut p).unwrap();clock.0.store(10,Ordering::SeqCst);
        assert_eq!(gate.check(r.signer,r.scope.commitment,0,2),Err(Failure::Expired));
    }
    #[test]
    fn lost_or_backward_elapsed_erases_private_authority(){
        for value in [0,u64::MAX]{
            let (mut gate,r,m,mut p,mut a,clock)=setup();clock.0.store(1,Ordering::SeqCst);
            let exchange=gate.begin(r.clone(),&m,&mut p,&mut a).unwrap();clock.0.store(value,Ordering::SeqCst);
            assert_eq!(gate.complete(exchange.session,&r,responses(&mut a),&mut p),Err(Failure::Elapsed));
            assert!(gate.failed&&gate.capability.is_none()&&gate.pending.is_none());
        }
    }
    #[test]
    fn finite_positive_config_required_and_overflow_refuses(){
        let (mut gate,r,m,mut p,mut a,_)=setup();gate.lifetime=Some(Duration::MAX);
        gate.last=Some(Duration::from_secs(1));gate.elapsed=Some(Arc::new(Clock(AtomicU64::new(1))));
        assert!(matches!(gate.begin(r,&m,&mut p,&mut a),Err(Failure::Deadline)));assert_eq!(a.calls,0);
        assert_eq!(Gate::default().configure(Duration::ZERO,Arc::new(Clock(AtomicU64::new(0)))),Err(Failure::Deadline));
        assert_eq!(Gate::default().check([1;32],[2;32],0,2),Err(Failure::Missing));
    }
    #[test]
    fn grant_new_phase_requires_new_private_attempt(){
        let (mut gate,r,m,mut p,mut a,_)=setup();let exchange=gate.begin(r.clone(),&m,&mut p,&mut a).unwrap();
        gate.complete(exchange.session,&r,responses(&mut a),&mut p).unwrap();
        assert_eq!(gate.check(r.signer,r.scope.commitment,0,3),Err(Failure::Scope));
        assert!(gate.capability.is_none());
    }
    #[test]
    fn restart_has_no_permission_and_expiry_after_private_work_refuses_output(){
        let (mut gate,r,m,mut p,mut a,clock)=setup();let exchange=gate.begin(r.clone(),&m,&mut p,&mut a).unwrap();
        gate.complete(exchange.session,&r,responses(&mut a),&mut p).unwrap();
        assert_eq!(Gate::default().check(r.signer,r.scope.commitment,0,2),Err(Failure::Missing));
        let permit=gate.consume(r.signer,r.scope.commitment,0,2,vec![1]).unwrap();clock.0.store(10,Ordering::SeqCst);
        assert_eq!(gate.post_sign(&permit),Err(Failure::Expired));
    }
    #[test]
    fn permit_owns_elapsed_continuity_and_latches_refusal_at_custody_entry(){
        for (value,expected) in [(10,Failure::Expired),(0,Failure::Elapsed),(u64::MAX,Failure::Elapsed)]{
            let (mut gate,r,m,mut p,mut a,clock)=setup();clock.0.store(1,Ordering::SeqCst);
            let exchange=gate.begin(r.clone(),&m,&mut p,&mut a).unwrap();
            gate.complete(exchange.session,&r,responses(&mut a),&mut p).unwrap();
            let permit=gate.consume(r.signer,r.scope.commitment,0,2,vec![1]).unwrap();
            let value=if value==10{11}else{value};clock.0.store(value,Ordering::SeqCst);
            assert_eq!(permit.check_at_custody_entry(r.signer,Some(rule_commitment()),&[1]),Err(expected));
            clock.0.store(1,Ordering::SeqCst);
            assert_eq!(permit.check_at_custody_entry(r.signer,Some(rule_commitment()),&[1]),Err(expected));
            assert!(!permit.authorizes(r.signer,Some(rule_commitment()),&[1]));
        }
        let ordinary=PrivateSignPermit::ordinary([1;32],Some(rule_commitment()),vec![2]);
        assert_eq!(ordinary.check_at_custody_entry([1;32],Some(rule_commitment()),&[2]),Ok(()));
        assert_eq!(ordinary.check_at_custody_entry([1;32],None,&[2]),Err(Failure::Scope));
    }
}
