//! Authenticated historical public admission paths for A2, not physical host proof.
//! Constructors are crate-private and bind complete witnesses to signed canonical admissions.
//! A pinned StateRoot authenticates reconstructed historical metadata; it never admits hardware.
use crate::{
    Error, Hash, NETWORK_ID, Result, blocks, domain_hash,
    endorsement_revocation_v1::{Target, TargetClass, TargetScope},
    execution::State,
};
use minicbor::{Decoder, Encoder};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
pub const RECORD_TAG: u8 = 65;
pub const MAX_RECORD_BYTES: usize = crate::attestation_witness::MAX_WITNESS_BYTES + 256;
pub const RECORD_KEY_DOMAIN: &[u8] = b"MUTINY-BUILD8-ENDORSEMENT-DEPENDENCY-KEY-V1";
#[derive(Clone, Debug, PartialEq, Eq)]
struct Record {
    node: Hash,
    lineage: Hash,
    generation: u64,
    profile: Hash,
    reference_time: u64,
    witness: Vec<u8>,
}
fn record_key(node:Hash,generation:u64,profile:Hash)->Hash {
        let mut e = Encoder::new(Vec::new());
        e.array(3)
            .unwrap()
            .bytes(&node)
            .unwrap()
            .u64(generation)
            .unwrap()
            .bytes(&profile)
            .unwrap();
        domain_hash(RECORD_KEY_DOMAIN, &e.into_writer())
}
impl Record {
    fn key(&self) -> Hash {
        record_key(self.node,self.generation,self.profile)
    }
    fn encode(&self) -> Result<Vec<u8>> {
        if [self.node, self.lineage, self.profile].contains(&[0; 32])
            || self.generation == 0
            || self.reference_time == 0
            || self.witness.is_empty()
            || self.witness.len() > crate::attestation_witness::MAX_WITNESS_BYTES
        {
            return Err(Error::Codec);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(9)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(RECORD_TAG)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.node)
            .unwrap()
            .bytes(&self.lineage)
            .unwrap()
            .u64(self.generation)
            .unwrap()
            .bytes(&self.profile)
            .unwrap()
            .u64(self.reference_time)
            .unwrap()
            .bytes(&self.witness)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_RECORD_BYTES {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    fn decode(raw: &[u8]) -> Result<Self> {
        blocks::canonical(raw, MAX_RECORD_BYTES)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(codec)? != Some(9)
            || d.u8().map_err(codec)? != 2
            || d.u8().map_err(codec)? != RECORD_TAG
            || d.u32().map_err(codec)? != NETWORK_ID
        {
            return Err(Error::Codec);
        }
        let node = hash(&mut d)?;
        let lineage = hash(&mut d)?;
        let generation = d.u64().map_err(codec)?;
        let profile = hash(&mut d)?;
        let reference_time = d.u64().map_err(codec)?;
        let witness = d.bytes().map_err(codec)?;
        if witness.is_empty() || witness.len() > crate::attestation_witness::MAX_WITNESS_BYTES {
            return Err(Error::Oversize);
        }
        let value = Self {
            node,
            lineage,
            generation,
            profile,
            reference_time,
            witness: witness.to_vec(),
        };
        if d.position() != raw.len() || value.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
    fn verified_targets(
        &self,
        profile: &crate::tpm::TpmProfile,
        parameters: &crate::genesis_v2::Parameters,
    ) -> Result<BTreeSet<Target>> {
        if profile.commitment()? != self.profile {
            return Err(Error::WrongAnchor);
        }
        let statement = profile
            .provenance
            .as_ref()
            .ok_or(Error::UnqualifiedPhysical)?;
        crate::provenance::check_profile(
            parameters.class.admission_class(),
            profile,
            statement.endorsement_root,
            &parameters.roots.hashes(),
        )?;
        parameters
            .pcr_profiles
            .check_accepted(profile.pcr_bitmap, profile.pcr_digest)
            .map_err(|_| Error::UnqualifiedPhysical)?;
        let policy = parameters.witness_policy()?;
        let paths = crate::attestation_witness::verify_witness_paths_with_policy(
            statement,Some(&self.witness),&policy,self.reference_time,&crate::x509_syntax::X509Syntax,
        )
        .map_err(|_| Error::UnqualifiedPhysical)?;
        let witness = crate::attestation_witness::AttestationWitness::decode(&self.witness)?;
        let mut targets = BTreeSet::new();
        for (i, (path, evidence)) in paths.iter().zip(&witness.endorsements).enumerate() {
            if i == 0
                && crate::x509_syntax::certified_public_key_sha256(&evidence.certificates[0])
                    .map_err(|_| Error::UnqualifiedPhysical)?
                    != statement.ek_public_sha256
            {
                return Err(Error::UnqualifiedPhysical);
            }
            for (position, (cert, cert_id)) in
                evidence.certificates.iter().zip(&path.path).enumerate()
            {
                let class = if position == 0 {
                    TargetClass::Ek
                } else if position + 1 == evidence.certificates.len() {
                    TargetClass::Root
                } else {
                    TargetClass::Intermediate
                };
                targets.insert(Target {
                    class,
                    scope: TargetScope::Certificate,
                    identity: *cert_id,
                });
                let identity = if class == TargetClass::Ek {
                    path.leaf_key
                        .identity()
                        .map_err(|_| Error::UnqualifiedPhysical)?
                } else {
                    crate::x509_syntax::certified_public_key_sha256(cert)
                        .map_err(|_| Error::UnqualifiedPhysical)?
                };
                targets.insert(Target {
                    class,
                    scope: TargetScope::Key,
                    identity,
                });
            }
        }
        Ok(targets)
    }
}
pub(crate) fn is_record(raw: &[u8]) -> bool {
    let mut d = Decoder::new(raw);
    d.array().ok().flatten().is_some() && d.u8().ok() == Some(2) && d.u8().ok() == Some(RECORD_TAG)
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Book {
    records: BTreeMap<Hash, Record>,
}
/// Only this module can construct a path returned after full retained witness
/// authentication. The A2 route verifier cannot accept a peer path assertion.
pub(crate) struct ResolvedPath {
    certificates: Vec<Vec<u8>>,
    position: usize,
}
impl ResolvedPath {
    pub(crate) fn certificates(&self) -> &[Vec<u8>] {
        &self.certificates
    }
    pub(crate) fn position(&self) -> usize {
        self.position
    }
}
impl Book {
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
    /// Return exact retained PUBLIC witness only after authenticating this whole
    /// dependency book against the supplied own-canonical state and exact binding.
    /// The caller still performs fresh private activation; this is not a grant.
    pub fn activation_witness(&self,state:&State,binding:&crate::node_admission_v2::Binding)
        ->Result<Option<(u64,Vec<u8>)>> {
        self.records(state)?;
        let a=&binding.admission;
        let profile=crate::tpm::TpmProfile::decode(&a.profile)?.commitment()?;
        let key=record_key(a.node,a.hardware_generation,profile);
        let Some(record)=self.records.get(&key) else{return Ok(None);};
        if record.node!=a.node || record.generation!=a.hardware_generation || record.profile!=profile {
            return Err(Error::WrongAnchor);
        }
        Ok(Some((record.reference_time,record.witness.clone())))
    }
    /// Called after the unchanged signed V2 item has passed its actual parent
    /// authorization. A public wrapper alone never reaches this constructor.
    pub(crate) fn stage_authenticated(
        &self,
        binding: &crate::node_admission_v2::Binding,
        lineage: Hash,
        reference_time: u64,
        witness: &[u8],
        parameters: &crate::genesis_v2::Parameters,
    ) -> Result<Self> {
        if !crate::endorsement_revocation_v1::enabled(parameters)? {
            return Err(Error::WrongOperation);
        }
        let a = &binding.admission;
        let profile = crate::tpm::TpmProfile::decode(&a.profile)?;
        let record = Record {
            node: a.node,
            lineage,
            generation: a.hardware_generation,
            profile: profile.commitment()?,
            reference_time,
            witness: witness.to_vec(),
        };
        record.encode()?;
        record.verified_targets(&profile, parameters)?;
        let mut next = self.clone();
        if next.records.insert(record.key(), record).is_some() {
            return Err(Error::Duplicate);
        }
        Ok(next)
    }
    /// Called only after the existing signed Genesis enrollment constructors.
    pub(crate) fn genesis(
        state: &State,
        inputs: &crate::genesis_v2::Inputs,
        bundle_raw: &[u8],
    ) -> Result<Self> {
        let bundle = crate::admission_evidence_v1::PublicWitnessBundle::decode(bundle_raw)?;
        if bundle.genesis != inputs.identity().map_err(|_| Error::Codec)?
            || bundle.fingerprint != inputs.parameters.fingerprint().map_err(|_| Error::Codec)?
        {
            return Err(Error::WrongAnchor);
        }
        let registry = state.continuity.as_ref().ok_or(Error::UnknownSigner)?;
        if registry.members.len() != 1 || bundle.entries.len() != 1 {
            return Err(Error::Capacity);
        }
        let member = &registry.members[0];
        if bundle.entries[0].0 != member.node
            || member.lineage != member.node
            || member.generation != 1
        {
            return Err(Error::WrongAnchor);
        }
        let binding = state
            .continuity_keys_v2
            .get(member.node)
            .ok_or(Error::UnknownSigner)?;
        let profile = binding.verify_historical_evidence()?;
        if binding.admission().profile != inputs.member.profile {
            return Err(Error::WrongAnchor);
        }
        let record = Record {
            node: member.node,
            lineage: member.lineage,
            generation: 1,
            profile: profile.commitment()?,
            reference_time: inputs.timestamp,
            witness: bundle.entries[0].1.clone(),
        };
        record.verified_targets(&profile, &inputs.parameters)?;
        Ok(Self {
            records: [(record.key(), record)].into(),
        })
    }
    /// Every current/pending physical binding must have an authenticated index entry.
    /// Historical entries stay tied to retained signed bindings; no claimed affected-member list.
    pub(crate) fn records(&self, state: &State) -> Result<BTreeMap<Hash, Vec<u8>>> {
        let parameters = crate::genesis_v2::Parameters::decode(
            state
                .protocol_records
                .get(&crate::genesis_v2::parameters_key())
                .ok_or(Error::UnqualifiedPhysical)?,
        )
        .map_err(|_| Error::Codec)?;
        let registry = state.continuity.as_ref().ok_or(Error::UnknownSigner)?;
        let mut profiles = BTreeMap::new();
        for member in &registry.members {
            if !member.physical {
                continue;
            }
            let binding = state
                .continuity_keys_v2
                .get(member.node)
                .ok_or(Error::UnknownSigner)?;
            let profile = binding.verify_historical_evidence()?;
            let commitment = profile.commitment()?;
            if binding.admission().hardware_generation != member.generation
                || commitment != member.attestation
            {
                return Err(Error::WrongGeneration);
            }
            let expected = Record {
                node: member.node,
                lineage: member.lineage,
                generation: member.generation,
                profile: commitment,
                reference_time: 1,
                witness: vec![1],
            };
            let record = self
                .records
                .get(&expected.key())
                .ok_or(Error::UnqualifiedPhysical)?;
            if record.lineage != member.lineage {
                return Err(Error::InvalidLineage);
            }
            profiles.insert((member.node, member.generation, commitment), profile);
        }
        for raw in state.retired_continuity_v2.records()?.values() {
            let retired = crate::retired_continuity_v2::Record::decode(raw)?;
            let a = &retired.binding.admission;
            let profile = crate::tpm::TpmProfile::decode(&a.profile)?;
            let commitment = profile.commitment()?;
            let expected = Record {
                node: a.node,
                lineage: a.node,
                generation: a.hardware_generation,
                profile: commitment,
                reference_time: 1,
                witness: vec![1],
            };
            if !self.records.contains_key(&expected.key()) {
                return Err(Error::UnqualifiedPhysical);
            }
            profiles.insert((a.node, a.hardware_generation, commitment), profile);
        }
        let mut result = BTreeMap::new();
        for (key, record) in &self.records {
            if *key != record.key()
                || !registry
                    .members
                    .iter()
                    .any(|m| m.lineage == record.lineage && record.generation <= m.generation)
            {
                return Err(Error::InvalidLineage);
            }
            let profile = profiles
                .get(&(record.node, record.generation, record.profile))
                .ok_or(Error::UnknownSigner)?;
            record.verified_targets(profile, &parameters)?;
            result.insert(*key, record.encode()?);
        }
        Ok(result)
    }
    pub(crate) fn from_records(rows: &BTreeMap<Hash, Vec<u8>>, state: &State) -> Result<Self> {
        let mut records = BTreeMap::new();
        for (key, raw) in rows {
            let record = Record::decode(raw)?;
            if *key != record.key() {
                return Err(Error::WrongAnchor);
            }
            records.insert(*key, record);
        }
        let book = Self { records };
        if book.records(state)? != *rows {
            return Err(Error::NonCanonical);
        }
        Ok(book)
    }
    fn profile_for(record: &Record, state: &State) -> Result<crate::tpm::TpmProfile> {
        if let Some(binding) = state.continuity_keys_v2.get(record.node) {
            let a = binding.admission();
            let profile = crate::tpm::TpmProfile::decode(&a.profile)?;
            if a.hardware_generation == record.generation && profile.commitment()? == record.profile
            {
                return Ok(profile);
            }
        }
        for raw in state.retired_continuity_v2.records()?.values() {
            let retired = crate::retired_continuity_v2::Record::decode(raw)?;
            let a = &retired.binding.admission;
            let profile = crate::tpm::TpmProfile::decode(&a.profile)?;
            if a.node == record.node
                && a.hardware_generation == record.generation
                && profile.commitment()? == record.profile
            {
                return Ok(profile);
            }
        }
        Err(Error::UnknownSigner)
    }
    /// Current/pending root/intermediate dependencies, plus retained EK lineage.
    /// Called with a full projected state after signed component staging; verifies
    /// complete coverage before deriving any affected-lineage set.
    pub(crate) fn affected(&self, state: &State, target: &Target) -> Result<BTreeSet<Hash>> {
        self.records(state)?;
        let parameters = crate::genesis_v2::Parameters::decode(
            state
                .protocol_records
                .get(&crate::genesis_v2::parameters_key())
                .ok_or(Error::UnqualifiedPhysical)?,
        )
        .map_err(|_| Error::Codec)?;
        let registry = state.continuity.as_ref().ok_or(Error::UnknownSigner)?;
        let mut lineages = BTreeSet::new();
        for record in self.records.values() {
            let profile = Self::profile_for(record, state)?;
            let current = registry.members.iter().any(|m| {
                m.node == record.node
                    && m.generation == record.generation
                    && m.attestation == record.profile
            });
            if (current || target.class == TargetClass::Ek)
                && record
                    .verified_targets(&profile, &parameters)?
                    .contains(target)
            {
                lineages.insert(record.lineage);
            }
        }
        Ok(lineages)
    }
    /// Resolve exact historical path bytes only after the signed profile's full
    /// witness, complete identity-class coverage and immutable anchors verify.
    pub(crate) fn resolve(&self, state: &State, target: &Target) -> Result<Vec<ResolvedPath>> {
        self.records(state)?;
        let parameters = crate::genesis_v2::Parameters::decode(
            state
                .protocol_records
                .get(&crate::genesis_v2::parameters_key())
                .ok_or(Error::UnqualifiedPhysical)?,
        )
        .map_err(|_| Error::Codec)?;
        let mut result = Vec::new();
        for record in self.records.values() {
            let profile = Self::profile_for(record, state)?;
            if !record
                .verified_targets(&profile, &parameters)?
                .contains(target)
            {
                continue;
            }
            let witness = crate::attestation_witness::AttestationWitness::decode(&record.witness)?;
            for evidence in witness.endorsements {
                for (position, certificate) in evidence.certificates.iter().enumerate() {
                    let class = if position == 0 {
                        TargetClass::Ek
                    } else if position + 1 == evidence.certificates.len() {
                        TargetClass::Root
                    } else {
                        TargetClass::Intermediate
                    };
                    if class != target.class {
                        continue;
                    }
                    let identity = match target.scope {
                        TargetScope::Certificate => Sha256::digest(certificate).into(),
                        TargetScope::Key if class == TargetClass::Ek => {
                            use crate::ek_chain::CertificateSyntax;
                            crate::x509_syntax::X509Syntax
                                .parse_certificate(certificate)
                                .map_err(|_| Error::UnqualifiedPhysical)?
                                .public_key
                                .identity()
                                .map_err(|_| Error::UnqualifiedPhysical)?
                        }
                        TargetScope::Key => {
                            crate::x509_syntax::certified_public_key_sha256(certificate)
                                .map_err(|_| Error::UnqualifiedPhysical)?
                        }
                    };
                    if identity == target.identity {
                        result.push(ResolvedPath {
                            certificates: evidence.certificates.clone(),
                            position,
                        });
                    }
                }
            }
        }
        if result.is_empty() {
            return Err(Error::UnknownSigner);
        }
        Ok(result)
    }
}
fn codec(_: minicbor::decode::Error) -> Error {
    Error::Codec
}
fn hash(d: &mut Decoder<'_>) -> Result<Hash> {
    d.bytes()
        .map_err(codec)?
        .try_into()
        .map_err(|_| Error::Codec)
}
