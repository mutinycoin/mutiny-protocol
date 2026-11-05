//! Complete pre-state Genesis inputs. No Worker or derived Node identity occurs here.
use crate::{
    Error, Hash, Result,
    blocks::{GenesisDescriptor, canonical},
    protocol_manifest::RuleManifest,
    tpm::TpmProfile,
};
use ed25519_dalek::VerifyingKey;
use minicbor::{Decoder, Encoder};
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameters {
    pub initial_target: Hash,
    /// Commits all fixed protocol parameters/rules, independently of this instance.
    pub rules: RuleManifest,
    /// Authenticated Treasury identity (version 3 encoding). Production Genesis requires it;
    /// the version 2 encoding without it is accepted only by the Test profile.
    pub treasury: Option<crate::treasury_v1::Treasury>,
}
impl Parameters {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.initial_target == [0; 32] {
            return Err(Error::InvalidCounter);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(if self.treasury.is_some() { 5 } else { 4 })
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(if self.treasury.is_some() { 3 } else { 2 })
            .unwrap()
            .bytes(&self.initial_target)
            .unwrap()
            .bytes(&self.rules.encode()?)
            .unwrap();
        if let Some(treasury) = &self.treasury {
            e.bytes(&treasury.encode()?).unwrap();
        }
        let raw = e.into_writer();
        if raw.len() > 65536 {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        canonical(raw, 65536)?;
        let mut d = Decoder::new(raw);
        let value = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("Genesis parameters");
            let count = d.array()?;
            if d.u8()? != 1 {
                return Err(bad());
            }
            let version = d.u8()?;
            if !matches!((count, version), (Some(4), 2) | (Some(5), 3)) {
                return Err(bad());
            }
            let initial_target = d.bytes()?.try_into().map_err(|_| bad())?;
            let rules = RuleManifest::decode(d.bytes()?).map_err(|_| bad())?;
            let treasury = if version == 3 {
                Some(crate::treasury_v1::Treasury::decode(d.bytes()?).map_err(|_| bad())?)
            } else {
                None
            };
            Ok(Self { initial_target, rules, treasury })
        })()
        .map_err(|_| Error::Codec)?;
        if value.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
}
/// Initial physical voter input. Generation zero follows ordinary admission.
/// Its NodeID/lineage derive only after GenesisID has become fixed.
#[derive(Clone, Debug)]
pub struct PhysicalAdmissionInput {
    pub owner: Hash,
    pub node_authentication: Hash,
    pub endorsement_root: Hash,
    pub profile: TpmProfile,
}
impl PhysicalAdmissionInput {
    pub fn encode(&self) -> Result<Vec<u8>> {
        for key in [self.owner, self.node_authentication] {
            VerifyingKey::from_bytes(&key).map_err(|_| Error::BadSignature)?;
        }
        if self.owner == self.node_authentication
            || self.endorsement_root == [0; 32]
            || self.profile.admission_trust_manifest == [0; 32]
        {
            return Err(Error::UnqualifiedPhysical);
        }
        self.profile.verify_certified_key()?;
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&self.owner)
            .unwrap()
            .bytes(&self.node_authentication)
            .unwrap()
            .bytes(&self.endorsement_root)
            .unwrap()
            .bytes(&self.profile.encode()?)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > 16384 {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        canonical(raw, 16384)?;
        let mut d = Decoder::new(raw);
        let value = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("Genesis physical admission");
            if d.array()? != Some(5) || d.u8()? != 1 {
                return Err(bad());
            }
            Ok(Self {
                owner: d.bytes()?.try_into().map_err(|_| bad())?,
                node_authentication: d.bytes()?.try_into().map_err(|_| bad())?,
                endorsement_root: d.bytes()?.try_into().map_err(|_| bad())?,
                profile: TpmProfile::decode(d.bytes()?).map_err(|_| bad())?,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if value.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
}
/// The caller independently pins the qualified rule manifest and fleet target.
/// Embedded manifests and self-described physical profiles are not trust roots.
pub fn validate_descriptor(
    descriptor: &GenesisDescriptor,
    locked_rules: &RuleManifest,
    qualified_target: Hash,
) -> Result<(Parameters, PhysicalAdmissionInput)> {
    descriptor.encode()?;
    let parameters = Parameters::decode(&descriptor.parameters)?;
    if parameters.rules != *locked_rules || locked_rules.fingerprint()? != descriptor.fingerprint {
        return Err(Error::WrongFingerprint);
    }
    if parameters.initial_target != qualified_target {
        return Err(Error::WrongAnchor);
    }
    if descriptor.admission_records.len() != 1 {
        return Err(Error::UnqualifiedPhysical);
    }
    let input = PhysicalAdmissionInput::decode(&descriptor.admission_records[0])?;
    if crate::transactions::address(&input.owner) != descriptor.owner {
        return Err(Error::BadSignature);
    }
    VerifyingKey::from_bytes(&descriptor.recovery).map_err(|_| Error::BadSignature)?;
    if descriptor.recovery == input.owner
        || descriptor.recovery == input.node_authentication
        || descriptor.nonce == [0; 32]
        || descriptor.timestamp == 0
    {
        return Err(Error::InvalidCounter);
    }
    Ok((parameters, input))
}

/// Fixed text of `Error::V1NotProductionGenesis` (Order A9): V2 (`genesis_v2`) is the Production
/// Genesis implementation target; V1 stays for test/replay only, with no V1 production fallback.
pub const V1_PRODUCTION_REFUSAL: &str = "V1 is not a Production Genesis implementation (Order A9)";

/// Which Genesis the caller is constructing. TEST-VALUE Treasury descriptors are valid only
/// under `Test`; `Production` rejects a missing, invalid or TEST-VALUE descriptor.
/// Order A9: every V1 construction path refuses `Production` (`validate_production_descriptor`,
/// `initial_state`); it remains only for test/replay class-rule evaluation
/// (`genesis_admission_class`, which builds nothing).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GenesisProfile {
    Production,
    Test,
}

/// Dividend component of the Genesis state, from the authenticated Treasury input.
pub fn dividend_state(
    parameters: &Parameters,
    profile: GenesisProfile,
) -> Result<crate::dividend_state_v1::DividendState> {
    use crate::dividend_state_v1::DividendState;
    match (&parameters.treasury, profile) {
        (Some(treasury), GenesisProfile::Production) => {
            treasury.require_production()?;
            Ok(DividendState::genesis(treasury.clone()))
        }
        (None, GenesisProfile::Production) => Err(Error::WrongOperation),
        (Some(treasury), GenesisProfile::Test) => {
            treasury.require_test()?;
            Ok(DividendState::genesis(treasury.clone()))
        }
        (None, GenesisProfile::Test) => Ok(DividendState::default()),
    }
}

/// Software-simulator TEST-VALUE TPM profiles are never valid Production Genesis input. The marker
/// is an accidental-use guard only: Production Genesis ALSO requires the Production admission
/// class and a verified typed provenance statement (`genesis_admission_class`), so a profile with
/// the marker stripped gains nothing from its absence.
pub fn require_not_test_value(input: &PhysicalAdmissionInput, profile: GenesisProfile) -> Result<()> {
    if profile == GenesisProfile::Production && input.profile.is_test_value() {
        return Err(Error::UnqualifiedPhysical);
    }
    Ok(())
}

/// Admission class of the Genesis being constructed, from its committed parameters (rule
/// manifest) and the Genesis admission policy roots (V1: exactly the input's endorsement root).
/// `Production` Genesis requires the Production class (the rule manifest commits to that root
/// set) AND a verified provenance statement; `Test` Genesis requires the Legacy/Test class, so a
/// Production-class descriptor cannot be constructed as a test chain either. With no committed
/// root set (the root-set content is an open Architect decision) no Production Genesis exists.
pub fn genesis_admission_class(
    descriptor: &GenesisDescriptor,
    input: &PhysicalAdmissionInput,
    profile: GenesisProfile,
) -> Result<crate::provenance::AdmissionClass> {
    use crate::provenance::{self, AdmissionClass};
    let roots: std::collections::BTreeSet<Hash> = [input.endorsement_root].into();
    let class = provenance::class_for(Some(&descriptor.parameters), Some(&roots))?;
    match (profile, class) {
        (GenesisProfile::Production, AdmissionClass::Production)
        | (GenesisProfile::Test, AdmissionClass::LegacyTest) => {}
        _ => return Err(Error::UnqualifiedPhysical),
    }
    provenance::check_profile(class, &input.profile, input.endorsement_root, &roots)?;
    Ok(class)
}

/// Former Production Genesis validation: everything `validate_descriptor` checks plus a mandatory,
/// valid, production-class Treasury descriptor. Order A9: it now ALWAYS refuses. The checks still
/// run first, so each precise refusal keeps its reason; whatever passes them is refused with
/// `Error::V1NotProductionGenesis`.
pub fn validate_production_descriptor(
    descriptor: &GenesisDescriptor,
    locked_rules: &RuleManifest,
    qualified_target: Hash,
) -> Result<(Parameters, PhysicalAdmissionInput)> {
    let validated = validate_descriptor(descriptor, locked_rules, qualified_target)?;
    require_not_test_value(&validated.1, GenesisProfile::Production)?;
    genesis_admission_class(descriptor, &validated.1, GenesisProfile::Production)?;
    dividend_state(&validated.0, GenesisProfile::Production)?;
    Err(Error::V1NotProductionGenesis)
}

pub fn parameters_key() -> Hash {
    crate::domain_hash(b"MUTINY-BUILD8-GENESIS-PARAMETERS-KEY-V1", &[])
}
/// Construct the entire approved initial state; caller-supplied extra records,
/// premined coins, history, bonds, or prior Worker identities cannot enter here.
pub fn initial_state(
    descriptor: &GenesisDescriptor,
    locked_rules: &RuleManifest,
    qualified_target: Hash,
    bindings: &[crate::licenses::BindWorker],
    approved: &crate::admission::ApprovedProfile,
    supervised_nonce: Hash,
    evidence: &[u8],
    profile: GenesisProfile,
) -> Result<crate::execution::State> {
    use crate::{
        admission::AdmissionPolicy,
        freshness::{PhysicalMember, validate_genesis},
        membership::NodeControl,
        recovery::{Anchor, ContinuityState, Member},
        tpm::PinnedTpmVerifier,
    };
    use std::collections::BTreeMap;
    let (parameters, input) = validate_descriptor(descriptor, locked_rules, qualified_target)?;
    require_not_test_value(&input, profile)?;
    let class = genesis_admission_class(descriptor, &input, profile)?;
    let dividends = dividend_state(&parameters, profile)?;
    // Order A9: no V1 Production Genesis is ever built (validation above keeps its precise reasons).
    if profile == GenesisProfile::Production {
        return Err(Error::V1NotProductionGenesis);
    }
    let genesis = descriptor.id()?;
    let policy = AdmissionPolicy {
        genesis,
        fingerprint: descriptor.fingerprint,
        authority: input.owner,
        endorsement_roots: [input.endorsement_root].into(),
    };
    if approved.profile != input.profile.encode()? || supervised_nonce == [0; 32] {
        return Err(Error::UnqualifiedPhysical);
    }
    let profile = approved.verify(&policy, class)?;
    let node = crate::join::node_id(genesis, input.node_authentication);
    let member = PhysicalMember {
        node,
        generation: 0,
        continuity_key: crate::tpm::public_key(&profile.voting_public, false)?,
        hardware: profile.hardware,
        admission_commitment: profile.commitment()?,
        attestation_key: profile.ak_public.clone(),
    };
    let verifier = PinnedTpmVerifier {
        profiles: BTreeMap::from([(member.admission_commitment, profile)]),
    };
    let fresh = validate_genesis(genesis, supervised_nonce, &member, evidence, &verifier)?;
    let mut state = crate::execution::State {
        licenses: crate::genesis::GenesisIdentity::new(descriptor.clone())?
            .bind_workers(bindings)?,
        dividends,
        ..Default::default()
    };
    state
        .protocol_records
        .insert(parameters_key(), descriptor.parameters.clone());
    state.admission.policy = Some(policy);
    state
        .admission
        .profiles
        .insert(member.admission_commitment, approved.clone());
    state.membership.controls.insert(
        node,
        NodeControl {
            node,
            generation: 0,
            owner: input.owner,
            node_authentication: input.node_authentication,
            sequence: 0,
            exit_boundary: None,
            admitted_height: 0,
            admission_boundary: None,
            hardware_since_height: 0,
        },
    );
    state.continuity = Some(ContinuityState::bootstrap(
        genesis,
        descriptor.fingerprint,
        Anchor {
            height: 0,
            tip: [0; 32],
            state_root: [0; 32],
            registry_root: [0; 32],
        },
        descriptor.recovery,
        vec![Member {
            lineage: node,
            node,
            hardware: member.hardware,
            generation: 0,
            voting_key: member.continuity_key,
            attestation: member.admission_commitment,
            history: Default::default(),
            physical: true,
            eligible: true,
            genesis_member: true,
        }],
    )?);
    state.accounting.freshness.insert(node, fresh);
    state.records().map_err(|_| Error::Codec)?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::treasury_v1::{Class, Treasury};
    use mutiny_crypto_v2::{HybridKey, Role};

    /// TEST-VALUE key from a public all-"zoo" mnemonic. Never a production identity.
    fn test_descriptor() -> Vec<u8> {
        HybridKey::wallet_restore(&("zoo ".repeat(23) + "vote"), Role::WalletOwner)
            .unwrap()
            .public()
            .descriptor(1)
            .unwrap()
    }
    fn rules() -> RuleManifest {
        RuleManifest { commitments: vec![(b"rule-a".to_vec(), [7; 32])] }
    }
    fn params(treasury: Option<Treasury>) -> Parameters {
        Parameters { initial_target: [255; 32], rules: rules(), treasury }
    }

    #[test]
    fn parameters_v2_and_v3_roundtrip_canonically_and_reject_tampering() {
        let legacy = params(None);
        let raw2 = legacy.encode().unwrap();
        assert_eq!(Parameters::decode(&raw2).unwrap(), legacy);
        let test = params(Some(Treasury::new(Class::TestValue, test_descriptor()).unwrap()));
        let raw3 = test.encode().unwrap();
        assert_ne!(raw2, raw3);
        assert_eq!(Parameters::decode(&raw3).unwrap(), test);
        // Truncation, trailing bytes and a version/arity mismatch are all rejected.
        assert!(Parameters::decode(&raw3[..raw3.len() - 1]).is_err());
        let mut trailing = raw3.clone();
        trailing.push(0);
        assert!(Parameters::decode(&trailing).is_err());
        let mut wrong_version = raw3.clone();
        let version_at = 2; // array header, version 1, then the encoding version byte
        assert_eq!(wrong_version[version_at], 3);
        wrong_version[version_at] = 2;
        assert!(Parameters::decode(&wrong_version).is_err(), "v2 label with a Treasury member");
        // The class marker is authenticated bytes: flipping it changes the encoding, never
        // silently reinterprets a TEST-VALUE descriptor as production.
        let production_class = params(Some(Treasury::new(Class::Production, test_descriptor()).unwrap()));
        assert_ne!(production_class.encode().unwrap(), raw3);
    }

    #[test]
    fn production_genesis_requires_a_production_class_treasury_and_test_genesis_forbids_it() {
        let none = params(None);
        let test = params(Some(Treasury::new(Class::TestValue, test_descriptor()).unwrap()));
        let production = params(Some(Treasury::new(Class::Production, test_descriptor()).unwrap()));
        // Production: missing and TEST-VALUE descriptors are rejected.
        assert!(dividend_state(&none, GenesisProfile::Production).is_err());
        assert!(dividend_state(&test, GenesisProfile::Production).is_err());
        let state = dividend_state(&production, GenesisProfile::Production).unwrap();
        assert!(state.treasury().is_some());
        // Test: TEST-VALUE accepted, a production-class descriptor refused, and the legacy
        // no-Treasury form yields an empty dividend state (no records, unchanged roots).
        assert!(dividend_state(&test, GenesisProfile::Test).unwrap().treasury().is_some());
        assert!(dividend_state(&production, GenesisProfile::Test).is_err());
        assert!(dividend_state(&none, GenesisProfile::Test).unwrap().treasury().is_none());
        // A non-generation-one or malformed descriptor is not a Treasury at all.
        let gen2 = HybridKey::wallet_restore(&("zoo ".repeat(23) + "vote"), Role::WalletOwner)
            .unwrap()
            .public()
            .descriptor(2)
            .unwrap();
        assert!(Treasury::new(Class::TestValue, gen2).is_err());
        assert!(Treasury::new(Class::TestValue, vec![1, 2, 3]).is_err());
    }
}
