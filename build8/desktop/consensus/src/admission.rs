//! The explicitly approved wallet admission-trust role. This authorizes a
//! supervised physical profile; it never supplies ordinary BFT quorum weight.
use crate::{
    Error, Hash, NETWORK_ID, Result, domain_hash,
    provenance::{self, AdmissionClass},
    tpm::TpmProfile,
};
use ed25519_dalek::{Signature, VerifyingKey};
use minicbor::{Decoder, Encoder};
use std::collections::BTreeMap;
use std::collections::BTreeSet;

pub fn policy_key() -> Hash {
    domain_hash(b"MUTINY-BUILD8-ADMISSION-POLICY-KEY-V1", &[])
}
pub fn profile_key(commitment: Hash) -> Hash {
    domain_hash(b"MUTINY-BUILD8-APPROVED-PROFILE-KEY-V1", &commitment)
}

/// Authenticated admission records. An absent policy is permitted only for
/// legacy qualification fixtures; it is not a production Genesis admission.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AdmissionBook {
    pub policy: Option<AdmissionPolicy>,
    pub profiles: BTreeMap<Hash, ApprovedProfile>,
}
impl AdmissionBook {
    /// True for the empty book; an orphaned profile without a policy fails as in `records`.
    pub fn is_empty(&self) -> Result<bool> {
        match &self.policy {
            None if self.profiles.is_empty() => Ok(true),
            None => Err(Error::UnqualifiedPhysical),
            Some(_) => Ok(false),
        }
    }
    /// Canonical records. Every approved profile is re-verified under `class`, which the caller
    /// takes from the same committed state (`State::admission_class`).
    pub fn records(&self, class: AdmissionClass) -> Result<BTreeMap<Hash, Vec<u8>>> {
        let Some(policy) = &self.policy else {
            return if self.profiles.is_empty() {
                Ok(BTreeMap::new())
            } else {
                Err(Error::UnqualifiedPhysical)
            };
        };
        if self.profiles.len() > crate::participation::MAX_ACKS {
            return Err(Error::Capacity);
        }
        let mut records = BTreeMap::from([(policy_key(), policy.encode()?)]);
        for (commitment, approved) in &self.profiles {
            let profile = approved.verify(policy, class)?;
            if profile.commitment()? != *commitment {
                return Err(Error::WrongAnchor);
            }
            records.insert(profile_key(*commitment), approved.encode()?);
        }
        Ok(records)
    }
    /// Reconstruction. `parameters` is the committed Genesis parameters record of the same state
    /// (or None); the admission class is derived from it and this book's committed policy, so the
    /// same class rule applies on restore as on admission.
    pub fn from_records(
        records: &BTreeMap<Hash, Vec<u8>>,
        parameters: Option<&[u8]>,
    ) -> Result<Self> {
        if records.is_empty() {
            return Ok(Self::default());
        }
        if records.len() > crate::participation::MAX_ACKS + 1 {
            return Err(Error::Capacity);
        }
        let policy = AdmissionPolicy::decode(records.get(&policy_key()).ok_or(Error::Codec)?)?;
        let class = provenance::class_for(parameters, Some(&policy.endorsement_roots))?;
        let mut profiles = BTreeMap::new();
        for (key, raw) in records {
            if *key == policy_key() {
                continue;
            }
            let approved = ApprovedProfile::decode(raw)?;
            let commitment = approved.verify(&policy, class)?.commitment()?;
            if *key != profile_key(commitment) {
                return Err(Error::WrongAnchor);
            }
            if profiles.insert(commitment, approved).is_some() {
                return Err(Error::Duplicate);
            }
        }
        let book = Self {
            policy: Some(policy),
            profiles,
        };
        if book.records(class)? != *records {
            return Err(Error::NonCanonical);
        }
        Ok(book)
    }
    /// Derive the native verifier and physical registry from authenticated state.
    /// Caller-supplied profile maps cannot override a committed admission policy.
    /// `class` comes from the same state (`State::admission_class`).
    pub fn physical_context(
        &self,
        registry: &crate::recovery::ContinuityState,
        class: AdmissionClass,
    ) -> Result<(
        BTreeMap<Hash, crate::freshness::PhysicalMember>,
        crate::tpm::PinnedTpmVerifier,
    )> {
        self.records(class)?;
        let policy = self.policy.as_ref().ok_or(Error::UnqualifiedPhysical)?;
        if policy.genesis != registry.genesis {
            return Err(Error::WrongGenesis);
        }
        if policy.fingerprint != registry.fingerprint {
            return Err(Error::WrongFingerprint);
        }
        let mut members = BTreeMap::new();
        let mut profiles = BTreeMap::new();
        for member in registry.members.iter().filter(|m| m.physical && m.eligible) {
            let profile = self
                .profiles
                .get(&member.attestation)
                .ok_or(Error::UnqualifiedPhysical)?
                .verify(policy, class)?;
            if profile.hardware != member.hardware
                || crate::tpm::public_key(&profile.voting_public, false)? != member.voting_key
            {
                return Err(Error::UnqualifiedPhysical);
            }
            members.insert(
                member.node,
                crate::freshness::PhysicalMember {
                    node: member.node,
                    generation: member.generation,
                    continuity_key: member.voting_key,
                    hardware: member.hardware,
                    admission_commitment: member.attestation,
                    attestation_key: profile.ak_public.clone(),
                },
            );
            profiles.insert(member.attestation, profile);
        }
        Ok((members, crate::tpm::PinnedTpmVerifier { profiles }))
    }
}

pub(crate) fn is_record(key: Hash, raw: &[u8]) -> bool {
    key == policy_key()
        || ApprovedProfile::decode(raw).is_ok_and(|a| {
            TpmProfile::decode(&a.profile)
                .and_then(|p| p.commitment())
                .is_ok_and(|c| profile_key(c) == key)
        })
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionPolicy {
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub authority: Hash,
    pub endorsement_roots: BTreeSet<Hash>,
}
fn hash(d: &mut Decoder<'_>) -> std::result::Result<Hash, minicbor::decode::Error> {
    d.bytes()?
        .try_into()
        .map_err(|_| minicbor::decode::Error::message("hash"))
}
impl AdmissionPolicy {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.endorsement_roots.is_empty() || self.endorsement_roots.len() > 1024 {
            return Err(Error::Capacity);
        }
        VerifyingKey::from_bytes(&self.authority).map_err(|_| Error::BadSignature)?;
        let mut e = Encoder::new(Vec::new());
        e.array(6)
            .unwrap()
            .u8(1)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .bytes(&self.authority)
            .unwrap()
            .array(self.endorsement_roots.len() as u64)
            .unwrap();
        for root in &self.endorsement_roots {
            if *root == [0; 32] {
                return Err(Error::UnqualifiedPhysical);
            }
            e.bytes(root).unwrap();
        }
        Ok(e.into_writer())
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, 65536)?;
        let mut d = Decoder::new(raw);
        let p = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("admission policy");
            if d.array()? != Some(6) || d.u8()? != 1 || d.u32()? != NETWORK_ID {
                return Err(bad());
            }
            let genesis = hash(&mut d)?;
            let fingerprint = hash(&mut d)?;
            let authority = hash(&mut d)?;
            let count = d.array()?.ok_or_else(bad)?;
            if count == 0 || count > 1024 {
                return Err(bad());
            }
            let mut endorsement_roots = BTreeSet::new();
            for _ in 0..count {
                if !endorsement_roots.insert(hash(&mut d)?) {
                    return Err(bad());
                }
            }
            Ok(Self {
                genesis,
                fingerprint,
                authority,
                endorsement_roots,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if p.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(p)
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovedProfile {
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub endorsement_root: Hash,
    pub profile: Vec<u8>,
    pub signature: [u8; 64],
}
impl ApprovedProfile {
    fn bytes(&self, signed: bool) -> Result<Vec<u8>> {
        if self.profile.len() > 8192 {
            return Err(Error::Oversize);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(if signed { 7 } else { 6 })
            .unwrap()
            .u8(1)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .bytes(&self.endorsement_root)
            .unwrap()
            .bytes(&self.profile)
            .unwrap();
        if signed {
            e.bytes(&self.signature).unwrap();
        }
        Ok(e.into_writer())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.bytes(true)
    }
    pub fn signing_digest(&self) -> Result<Hash> {
        Ok(domain_hash(
            b"MUTINY-BUILD8-PHYSICAL-ADMISSION-AUTHORIZATION-V1",
            &self.bytes(false)?,
        ))
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, 16384)?;
        let mut d = Decoder::new(raw);
        let a = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("approved profile");
            if d.array()? != Some(7) || d.u8()? != 1 || d.u32()? != NETWORK_ID {
                return Err(bad());
            }
            Ok(Self {
                genesis: hash(&mut d)?,
                fingerprint: hash(&mut d)?,
                endorsement_root: hash(&mut d)?,
                profile: d.bytes()?.to_vec(),
                signature: d.bytes()?.try_into().map_err(|_| bad())?,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if a.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(a)
    }
    /// THE V1 admission choke point (Genesis, JOIN, ROTATION, RECOVERY, reconstruction and the
    /// physical verifier all pass through it). `class` must come from consensus-committed state;
    /// in the Production class the typed provenance rule (`provenance::check_profile`, C1..C5) and
    /// the TEST-VALUE rejection apply in addition to every Legacy/Test check.
    pub fn verify(&self, policy: &AdmissionPolicy, class: AdmissionClass) -> Result<TpmProfile> {
        policy.encode()?;
        if self.genesis != policy.genesis {
            return Err(Error::WrongGenesis);
        }
        if self.fingerprint != policy.fingerprint {
            return Err(Error::WrongFingerprint);
        }
        if !policy.endorsement_roots.contains(&self.endorsement_root) {
            return Err(Error::UnqualifiedPhysical);
        }
        VerifyingKey::from_bytes(&policy.authority)
            .map_err(|_| Error::BadSignature)?
            .verify_strict(
                &self.signing_digest()?,
                &Signature::from_bytes(&self.signature),
            )
            .map_err(|_| Error::BadSignature)?;
        let profile = TpmProfile::decode(&self.profile)?;
        if profile.admission_trust_manifest == [0; 32] {
            return Err(Error::UnqualifiedPhysical);
        }
        provenance::check_profile(class, &profile, self.endorsement_root, &policy.endorsement_roots)?;
        // EK chain, ActivateCredential and supervised platform association are facts attested by
        // the authorized wallet's signature (in Production: over a typed provenance statement
        // bound to this AK and PCR profile). They are not proven here: the authority attestation
        // is the anchor. Native certified-key properties and all fresh quotes are verified.
        Ok(profile)
    }
}
