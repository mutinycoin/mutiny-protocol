//! Explicit selected TEST-VALUE policy. Logical root IDs never replace DER
//! path hashes. No applicant/ambient mapping, activation or signing authority.
use crate::{Error, Hash, Result, attestation_witness::WitnessContext,
    ek_chain::{ChainContext, TrustAnchor}, endorsement_identity::IdentityClasses,
    genesis_v2::{GenesisClass, Parameters, test_value_root}, provenance::AdmissionClass};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const RULE_ENTRY: &[u8] = b"TestValueEndorsementDerAliasV1";
pub const LABEL_PREFIX: &[u8] = b"BUILD8-TEST-DER-ALIAS-V1\0";
/// Ordinary RuleManifest artifact hash, no new hash domain or wire allocation.
pub fn rule_commitment() -> Hash {
    Sha256::digest(include_bytes!("../../spec/TESTVALUE-ENDORSEMENT-DER-ALIAS-V1.md")).into()
}

/// Constructible only through validated immutable Parameters. Fields are
/// private; a caller cannot substitute an alias or select one with a boolean.
pub struct WitnessPolicy {
    class: AdmissionClass,
    classes: IdentityClasses,
    anchors: Vec<TrustAnchor>,
    aliases: Option<BTreeMap<Hash, Hash>>, // exact DER hash -> logical RootID
}
impl WitnessPolicy {
    pub(crate) fn from_parameters(parameters: &Parameters) -> Result<Self> {
        let selected = parameters.rules.commitments.iter()
            .find(|(name,_)| name.as_slice()==RULE_ENTRY);
        let mut result = Self { class:parameters.class.admission_class(),
            classes:parameters.identity_classes.clone(), anchors:parameters.roots.anchors(), aliases:None };
        let Some((_,commitment)) = selected else { return Ok(result); };
        if *commitment != rule_commitment() || parameters.class != GenesisClass::TestValue {
            return Err(Error::WrongFingerprint);
        }
        let mut aliases = BTreeMap::new();
        let mut anchors = Vec::new();
        for (logical,entry) in &parameters.roots.roots {
            let label = entry.test_value_label.as_deref().ok_or(Error::UnqualifiedPhysical)?;
            if label.len()!=LABEL_PREFIX.len()+32 || !label.starts_with(LABEL_PREFIX)
                || test_value_root(label)!=*logical {
                return Err(Error::WrongAnchor);
            }
            let der:Hash=label[LABEL_PREFIX.len()..].try_into().map_err(|_|Error::Codec)?;
            if der==[0;32] || aliases.insert(der,*logical).is_some() { return Err(Error::Duplicate); }
            anchors.push(TrustAnchor {root_cert_der_sha256:der,constraints:entry.constraints.clone()});
        }
        if aliases.is_empty() { return Err(Error::UnqualifiedPhysical); }
        result.anchors=anchors;
        result.aliases=Some(aliases);
        Ok(result)
    }
    /// The exact DER policy for the unchanged chain/CRL procedure, borrowed
    /// immutably from this authenticated Parameters-derived view.
    pub fn anchors(&self) -> &[TrustAnchor] { &self.anchors }
    pub fn context(&self, reference_time:u64) -> WitnessContext<'_> {
        WitnessContext {chain:ChainContext {class:self.class,reference_time,anchors:&self.anchors},
            identity_classes:&self.classes}
    }
    pub(crate) fn check_primary_root(&self, statement:&crate::provenance::Provenance)
        -> std::result::Result<(),crate::attestation_witness::WitnessFailure> {
        if self.aliases.is_some() && statement.endorsement.as_ref()
            .and_then(|e| e.identities.first()).map(|(root,_)| *root) != Some(statement.endorsement_root) {
            return Err(crate::attestation_witness::WitnessFailure::RootMismatch(0));
        }
        Ok(())
    }
    pub(crate) fn logical_root(&self, der:Hash) -> Option<Hash> {
        match &self.aliases {None=>Some(der),Some(aliases)=>aliases.get(&der).copied()}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{genesis_v2::{EndorsementRoot,EndorsementRootSet,binding_entries},
        ek_chain::{AnchorConstraints,RevocationMode,SignatureAlgorithm},
        endorsement_identity::{IdentityClass,ECC_TAG,TPM_ECC_NIST_P256},
        pcr_profiles::{AcceptedPcrProfiles,PcrProfile,SHA256_BANK,INTERPRETATION_QUOTE_COMPOSITE,UPDATE_FROZEN_AT_GENESIS},
        protocol_manifest::RuleManifest};
    fn parameters(selected:bool)->Parameters {
        let der=[7;32];let mut label=LABEL_PREFIX.to_vec();label.extend(der);
        let roots=EndorsementRootSet {roots:[(test_value_root(&label),EndorsementRoot{
            constraints:AnchorConstraints{max_intermediates:1,signature_algorithms:[SignatureAlgorithm::EcdsaP256Sha256].into(),
                ek_classes:[(ECC_TAG,TPM_ECC_NIST_P256)].into(),revocation:RevocationMode::CrlRequired},test_value_label:Some(label)})].into()};
        let classes=IdentityClasses::new(vec![IdentityClass {algorithm:ECC_TAG,size:TPM_ECC_NIST_P256,template_sha256:[9;32]}]).unwrap();
        let pcr=AcceptedPcrProfiles::new(UPDATE_FROZEN_AT_GENESIS,vec![PcrProfile{bank:SHA256_BANK,selection:[1,0,0],digest:[5;32],interpretation:INTERPRETATION_QUOTE_COMPOSITE}]).unwrap();
        let mut p=Parameters{class:GenesisClass::TestValue,initial_target:[255;32],rules:RuleManifest{commitments:binding_entries(GenesisClass::TestValue,&roots,&pcr,&classes).unwrap()},roots,pcr_profiles:pcr,identity_classes:classes};
        if selected {p.rules.commitments.push((RULE_ENTRY.to_vec(),rule_commitment()));p.rules.commitments.sort();}
        p
    }
    fn rebind(p:&mut Parameters) {
        p.rules.commitments.retain(|(name,_)|name.as_slice()==RULE_ENTRY);
        p.rules.commitments.extend(binding_entries(p.class,&p.roots,&p.pcr_profiles,&p.identity_classes).unwrap());p.rules.commitments.sort();
    }
    #[test]
    fn explicit_policy_keeps_logical_and_exact_der_namespaces_distinct() {
        let p=parameters(true);let encoded=p.encode().unwrap();let policy=p.witness_policy().unwrap();
        let logical=*p.roots.roots.keys().next().unwrap();assert_ne!(logical,[7;32]);
        assert_eq!(policy.anchors()[0].root_cert_der_sha256,[7;32]);
        assert_eq!(policy.logical_root([7;32]),Some(logical));assert_eq!(policy.logical_root([8;32]),None);
        assert_eq!(Parameters::decode(&encoded).unwrap().encode().unwrap(),encoded);
    }
    #[test]
    fn absent_selector_never_reinterprets_even_a_distinguished_label() {
        let p=parameters(false);let raw=p.encode().unwrap();let logical=*p.roots.roots.keys().next().unwrap();
        let policy=p.witness_policy().unwrap();assert_eq!(policy.anchors(),p.roots.anchors());
        assert_eq!(policy.logical_root([7;32]),Some([7;32]));assert_eq!(policy.anchors()[0].root_cert_der_sha256,logical);
        assert_eq!(Parameters::decode(&raw).unwrap().encode().unwrap(),raw);
    }
    #[test]
    fn production_and_changed_selector_refuse_before_alias_policy() {
        let mut p=parameters(true);p.class=GenesisClass::Production;rebind(&mut p);
        assert_eq!(p.encode().err(),Some(crate::genesis_v2::GenesisV2Error::TestRootAliasPolicy));
        // The selector itself is forbidden, even without any TEST label.
        p.roots.roots.values_mut().for_each(|entry|entry.test_value_label=None);rebind(&mut p);
        assert_eq!(p.encode().err(),Some(crate::genesis_v2::GenesisV2Error::TestRootAliasPolicy));
        let mut p=parameters(true);p.rules.commitments.iter_mut().find(|(n,_)|n.as_slice()==RULE_ENTRY).unwrap().1[0]^=1;
        assert!(p.encode().is_err());assert!(p.witness_policy().is_err());
    }
    #[test]
    fn root_key_label_der_zero_and_label_width_substitution_refuse() {
        let mut p=parameters(true);let (_,entry)=p.roots.roots.pop_first().unwrap();p.roots.roots.insert([8;32],entry);rebind(&mut p);assert!(p.encode().is_err());
        for length in [0,24,56,58,64] {
            let mut p=parameters(true);let (_,mut entry)=p.roots.roots.pop_first().unwrap();entry.test_value_label=Some(vec![b'x';length]);
            let key=test_value_root(entry.test_value_label.as_ref().unwrap());p.roots.roots.insert(key,entry);rebind(&mut p);assert!(p.encode().is_err());
        }
        let mut p=parameters(true);let (_,mut entry)=p.roots.roots.pop_first().unwrap();let mut label=LABEL_PREFIX.to_vec();label.extend([0;32]);entry.test_value_label=Some(label.clone());
        p.roots.roots.insert(test_value_root(&label),entry);rebind(&mut p);assert!(p.encode().is_err());
    }
    #[test]
    fn replacing_committed_der_changes_root_identity_and_fingerprint() {
        let p=parameters(true);let before=p.fingerprint().unwrap();let old_root=*p.roots.roots.keys().next().unwrap();
        let mut changed=p.clone();let (_,mut entry)=changed.roots.roots.pop_first().unwrap();let label=entry.test_value_label.as_mut().unwrap();*label.last_mut().unwrap()^=1;
        let new_root=test_value_root(label);changed.roots.roots.insert(new_root,entry);rebind(&mut changed);
        assert_ne!(old_root,new_root);assert_ne!(before,changed.fingerprint().unwrap());
        assert_eq!(changed.witness_policy().unwrap().logical_root([7;32]),None);
    }
}
