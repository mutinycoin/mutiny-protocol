//! Own-replica class-pinned context/material resolver. No peer root, cached PASS
//! or class change supplies eligibility. Native Request remains opaque.
use super::{Error,Result};
use mutiny_consensus_v8::{
    activation_attestation_v1::{self as activation,CurrentContext,Failure,Material,Position,Request},
    anchors::FinalizedAnchor,canonical_store_v2::CanonicalStore,
    genesis_v2::{self,Parameters},node_admission_v2::Binding,
    provenance::AdmissionClass, tpm::TpmProfile,
};
pub struct OwnContext<'a> {chain:&'a CanonicalStore,signer:mutiny_consensus_v8::Hash,expected_class:AdmissionClass}
impl<'a> OwnContext<'a> {
    /// The caller supplies its already trusted Genesis-pinned canonical store;
    /// an arbitrary peer SQLite database is not a bootstrap trust source.
    pub fn test_only(chain:&'a CanonicalStore,signer:mutiny_consensus_v8::Hash)->Result<Self>{
        if signer==[0;32]{return Err(Error::Authority);}
        let(_,state)=chain.load().map_err(|_|Error::Current)?;
        let expected_class=state.admission_class().map_err(|_|Error::Context)?;
        if expected_class==AdmissionClass::Production{return Err(Error::Production);}
        Ok(Self{chain,signer,expected_class})
    }
    /// Internal NORMAL material path from the factory's own already Genesis-
    /// pinned canonical replica. This creates no counter, provider, clock or
    /// physical qualification. Only Production class may enter this constructor;
    /// all current member/witness/PCR/activation checks still run below.
    pub(super) fn production_only(chain:&'a CanonicalStore,signer:mutiny_consensus_v8::Hash)->Result<Self>{
        if signer==[0;32]{return Err(Error::Authority);}
        let(_,state)=chain.load().map_err(|_|Error::Current)?;
        if state.admission_class().map_err(|_|Error::Context)?!=AdmissionClass::Production{
            return Err(Error::Production);
        }
        Ok(Self{chain,signer,expected_class:AdmissionClass::Production})
    }
    pub fn material(&mut self,request:&Request)->Result<Vec<Material>>{
        self.current_parent(request).map_err(|_|Error::Current)?;
        let (_,state)=self.chain.verified_activation_parent(request.scope().parent()).map_err(|_|Error::Current)?;
        let params=Parameters::decode(state.protocol_records.get(&genesis_v2::parameters_key()).ok_or(Error::Context)?)
            .map_err(|_|Error::Context)?;
        if params.class.admission_class()!=self.expected_class{return Err(Error::Context);}
        let capacity=self.chain.body_capacity(request.scope().parent()).map_err(|_|Error::Current)?;
        let body=capacity.decode(request.scope().body_bytes()).map_err(|_|Error::Context)?;
        let (parent,_,_)=self.chain.execution_parent(request.scope().parent().height).map_err(|_|Error::Current)?;
        // work_parent_from_head returns DESC timestamps and validates the first
        // against the exact canonical head. Do not use a proposed block time.
        let parent_time=*parent.ancestor_timestamps.first().ok_or(Error::Current)?;
        let mut material=Vec::new();
        for admission in request.scope().admissions(){
            let binding=Binding::decode(admission.binding_bytes()).map_err(|_|Error::Context)?;
            let (time,witness)=match admission.position(){
                Position::Operation(position) if matches!(admission.purpose(),activation::Purpose::Join|activation::Purpose::HardwareReplacement)=>{
                    let raw=body.operations.get(position as usize).ok_or(Error::Context)?;
                    let carrier=mutiny_consensus_v8::admission_public_v3::Carrier::decode(raw).map_err(|_|Error::Context)?;
                    let exact=match (admission.purpose(),carrier.kind()) {
                        (activation::Purpose::Join,15)=>mutiny_consensus_v8::join_v2::Join::decode(carrier.signed()).map_err(|_|Error::Context)?.binding,
                        (activation::Purpose::HardwareReplacement,16)=>mutiny_consensus_v8::hardware_rotate_v2::HardwareRotate::decode(carrier.signed()).map_err(|_|Error::Context)?.binding,
                        _=>return Err(Error::Context),
                    };
                    if exact!=binding{return Err(Error::Context);}
                    (parent_time,carrier.witness().to_vec())
                },
                Position::Recovery if admission.purpose()==activation::Purpose::Recovery=>{
                    let authority=state.recovery_authority_v2.as_ref().ok_or(Error::Context)?;
                    let raw=self.chain.recovery_record(parent.height).map_err(|_|Error::Current)?.ok_or(Error::Context)?;
                    let carrier=mutiny_consensus_v8::recovery_public_v3::Carrier::decode(&raw,authority).map_err(|_|Error::Context)?;
                    let record=carrier.record(authority).map_err(|_|Error::Context)?;
                    if record.material.parent!=*request.scope().parent() || record.material.binding!=binding {
                        return Err(Error::Context);
                    }
                    (parent_time,carrier.witness().to_vec())
                },
                Position::Operation(_) if admission.purpose()==activation::Purpose::ContinuityBinding=>state.endorsement_dependencies_v1.activation_witness(&state,&binding)
                    .map_err(|_|Error::Context)?.ok_or(Error::Context)?,
                _=>return Err(Error::Context),
            };
            let policy=params.witness_policy().map_err(|_|Error::Context)?;
            // Native accepted binding and class-complete X.509 witness are both
            // mandatory; no synthetic Material constructor is exposed here.
            let profile=TpmProfile::decode(&binding.admission.profile).map_err(|_|Error::Context)?;
            params.pcr_profiles.check_accepted(profile.pcr_bitmap,profile.pcr_digest).map_err(|_|Error::Context)?;
            material.push(Material::validate_with_policy(admission,&witness,&policy,time,&mutiny_consensus_v8::x509_syntax::X509Syntax)
                .map_err(|_|Error::Context)?);
        }
        self.current_parent(request).map_err(|_|Error::Current)?; Ok(material)
    }
}
impl CurrentContext for OwnContext<'_>{
    fn current_parent(&mut self,request:&Request)->std::result::Result<FinalizedAnchor,Failure>{
        if request.signer()!=self.signer{return Err(Failure::Scope);}
        let (authority,state)=self.chain.verified_activation_parent(request.scope().parent())
            .map_err(|_|Failure::ProviderUnavailable)?;
        if authority.activation_rule!=Some(activation::rule_commitment()) {return Err(Failure::Scope);}
        let member=authority.voters.get(&self.signer).ok_or(Failure::ProviderUnavailable)?;
        if !member.admitted || !member.physical || !member.eligible || member.revoked{return Err(Failure::ProviderUnavailable);}
        if state.admission_class().map_err(|_|Failure::Material)?!=self.expected_class{return Err(Failure::ProviderUnavailable);}
        Ok(authority.parent)
    }
}
