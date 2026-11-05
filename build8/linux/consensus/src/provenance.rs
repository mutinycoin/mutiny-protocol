//! PROPOSED / UNFROZEN schema (TPM admission package). Typed physical-admission provenance and
//! the admission class taken from consensus-committed Genesis data.
//!
//! What this is NOT: a hardware proof. No predicate a validator can evaluate distinguishes a
//! correct software simulator from a TPM. Under the locked policy the anchor is the supervised
//! admission ceremony plus the admission authority's signature (V1 ApprovedProfile, V2 owner
//! authorization), and every byte checked here lies inside bytes that signature already covers.
//! What Rust checks here, in the Production class only: the authority's statement is typed, it is
//! the statement the trust manifest commits to, and it names THIS profile's attestation key, THIS
//! profile's device (PCR) profile and an endorsement root of the committed policy; and the
//! profile does not carry the TEST-VALUE marker. EK-chain validation, ActivateCredential, host
//! association, measured-boot replay and revocation remain supervised, off-chain facts that the
//! five evidence digests only reference.
//!
//! Version 2 of the statement (candidate 3, Order of 4 Oct 2026, decisions A4 and A7; PROPOSED /
//! UNFROZEN; design `qualification/candidate-3/A-ADMISSION-DESIGN-V1.md` section 5) keeps every
//! version-1 field and appends the committed endorsement identities (one per identity class) and
//! the commitment to the attestation witness. In the Production class only a version-2 statement
//! is accepted and the profile's `hardware` must equal the class-1 identity (C6), so a label can no
//! longer differ from the committed endorsement identity. The identity VALUES remain the
//! authority's statement until the witness is verified (`attestation_witness::verify_witness`).
//!
//! Class: `Production` iff the Genesis parameters record carries the rule-manifest commitment
//! `physical-admission-trust-roots-v1` and the state's admission policy roots hash to it; with no
//! such commitment the class is `LegacyTest` (unchanged behaviour). A declared commitment that the
//! policy roots do not match, or a declared commitment without any policy, is an error (fail
//! closed), never a fallback to `LegacyTest`. The root-set CONTENT is not decided here (Q1).
use crate::{Error, Hash, Result, domain_hash, tpm::TpmProfile};
use minicbor::{Decoder, Encoder};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Trust-manifest commitment over the canonical provenance bytes (check C1).
pub const PROVENANCE_DOMAIN: &[u8] = b"MUTINY-BUILD8-ADMISSION-PROVENANCE-V1";
/// Device-profile digest over `pcr_bitmap || pcr_digest` (check C4).
pub const PLATFORM_PROFILE_DOMAIN: &[u8] = b"MUTINY-BUILD8-PLATFORM-PROFILE-V1";
/// Commitment to the approved manufacturer endorsement-root set (class, E1).
pub const TRUST_ROOTS_DOMAIN: &[u8] = b"MUTINY-BUILD8-PHYSICAL-TRUST-ROOTS-V1";
/// Rule-manifest entry name carrying the trust-roots commitment in the Genesis parameters.
pub const TRUST_ROOTS_COMMITMENT: &[u8] = b"physical-admission-trust-roots-v1";
/// Canonical provenance encoding length (fixed: every field has a fixed size).
pub const PROVENANCE_BYTES: usize = 321;
/// Trust-manifest commitment over the canonical version-2 statement (check C1 for version 2).
pub const PROVENANCE_V2_DOMAIN: &[u8] = b"MUTINY-BUILD8-ADMISSION-PROVENANCE-V2";
/// Committed endorsement identities per version-2 statement (one per identity class, design A4).
pub const MAX_IDENTITIES: usize = 4;
/// Largest canonical version-2 statement.
pub const MAX_PROVENANCE_V2_BYTES: usize = 640;

/// The five supervised evidence reports, in this fixed order (kinds 1..5). They are the reports the
/// supervised Desktop review already requires (`ek-chain-verification.json`,
/// `external-credential-verified.json`, `platform-observations.json`,
/// `post-reboot/restart-verification.json`, `profile-check/candidate-platform-profile.json`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EvidenceKind {
    EkChainVerification = 1,
    ActivateCredential = 2,
    HostAssociation = 3,
    RestartVerification = 4,
    CandidatePlatformProfile = 5,
}
pub const EVIDENCE_KINDS: [EvidenceKind; 5] = [
    EvidenceKind::EkChainVerification,
    EvidenceKind::ActivateCredential,
    EvidenceKind::HostAssociation,
    EvidenceKind::RestartVerification,
    EvidenceKind::CandidatePlatformProfile,
];

/// Provenance statement v1, signed (inside the profile bytes) by the admission authority.
/// Canonical CBOR: `[1, endorsement_root, ek_public_sha256, ak_name, platform_profile_sha256,
/// [[1, d1], [2, d2], [3, d3], [4, d4], [5, d5]]]`; byte strings of 32 bytes except `ak_name`
/// (34 bytes: 0x000b || SHA-256(TPMT_PUBLIC of the AK)). Version 2 appends
/// `[[root_1, ek_identity_1], ..., [root_k, ek_identity_k]]` (1 <= k <= 4) and `witness_sha256`
/// (8 elements, version 2; PROPOSED / UNFROZEN).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provenance {
    pub endorsement_root: Hash,
    /// SHA-256 of the DER-encoded EK public key (SubjectPublicKeyInfo) only; raw EK material
    /// stays off-chain (locked text).
    pub ek_public_sha256: Hash,
    pub ak_name: [u8; 34],
    pub platform_profile_sha256: Hash,
    /// Evidence report digests, index i = kind i+1.
    pub evidence: [Hash; 5],
    /// Version 2 (Order A4/A7): the committed endorsement identities and the witness commitment.
    /// `None` is a version-1 statement (321 bytes, unchanged), refused in the Production class.
    pub endorsement: Option<Endorsement>,
}
/// The version-2 extension of the statement (PROPOSED / UNFROZEN).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Endorsement {
    /// One `(endorsement root, EK identity)` per committed identity class, in class order; the first
    /// is the primary identity, which the profile's `hardware` must equal (C6). An EK identity is
    /// `endorsement_identity::ek_identity` of the key's canonical encoding.
    pub identities: Vec<(Hash, Hash)>,
    /// `H(attestation_witness::WITNESS_DOMAIN, witness bytes)`.
    pub witness_sha256: Hash,
}
impl Provenance {
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        let (fields, version) = if self.endorsement.is_some() { (8, 2) } else { (6, 1) };
        e.array(fields)
            .unwrap()
            .u8(version)
            .unwrap()
            .bytes(&self.endorsement_root)
            .unwrap()
            .bytes(&self.ek_public_sha256)
            .unwrap()
            .bytes(&self.ak_name)
            .unwrap()
            .bytes(&self.platform_profile_sha256)
            .unwrap()
            .array(5)
            .unwrap();
        for (kind, digest) in EVIDENCE_KINDS.iter().zip(&self.evidence) {
            e.array(2).unwrap().u8(*kind as u8).unwrap().bytes(digest).unwrap();
        }
        if let Some(endorsement) = &self.endorsement {
            e.array(endorsement.identities.len() as u64).unwrap();
            for (root, identity) in &endorsement.identities {
                e.array(2).unwrap().bytes(root).unwrap().bytes(identity).unwrap();
            }
            e.bytes(&endorsement.witness_sha256).unwrap();
        }
        e.into_writer()
    }
    /// Version 1 (`[6, 1, ..]`, exactly 321 bytes) or version 2 (`[8, 2, ..]`), canonical only.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        match raw.get(..2) {
            Some([0x86, 0x01]) => Self::decode_v1(raw),
            Some([0x88, 0x02]) => Self::decode_v2(raw),
            _ => Err(Error::Codec),
        }
    }
    fn decode_v2(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_PROVENANCE_V2_BYTES)?;
        let mut d = Decoder::new(raw);
        let p = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("provenance v2");
            let fixed = |d: &mut Decoder<'_>| -> std::result::Result<Hash, minicbor::decode::Error> {
                d.bytes()?.try_into().map_err(|_| bad())
            };
            if d.array()? != Some(8) || d.u8()? != 2 {
                return Err(bad());
            }
            let endorsement_root = fixed(&mut d)?;
            let ek_public_sha256 = fixed(&mut d)?;
            let ak_name: [u8; 34] = d.bytes()?.try_into().map_err(|_| bad())?;
            let platform_profile_sha256 = fixed(&mut d)?;
            if d.array()? != Some(5) {
                return Err(bad());
            }
            let mut evidence = [[0u8; 32]; 5];
            for (i, kind) in EVIDENCE_KINDS.iter().enumerate() {
                if d.array()? != Some(2) || d.u8()? != *kind as u8 {
                    return Err(bad());
                }
                evidence[i] = fixed(&mut d)?;
            }
            let n = d.array()?.ok_or_else(bad)?;
            if n == 0 || n > MAX_IDENTITIES as u64 {
                return Err(bad());
            }
            let mut identities = Vec::new();
            for _ in 0..n {
                if d.array()? != Some(2) {
                    return Err(bad());
                }
                identities.push((fixed(&mut d)?, fixed(&mut d)?));
            }
            let witness_sha256 = fixed(&mut d)?;
            Ok(Self {
                endorsement_root,
                ek_public_sha256,
                ak_name,
                platform_profile_sha256,
                evidence,
                endorsement: Some(Endorsement { identities, witness_sha256 }),
            })
        })()
        .map_err(|_| Error::Codec)?;
        if d.position() != raw.len() || p.encode() != raw {
            return Err(Error::NonCanonical);
        }
        Ok(p)
    }
    fn decode_v1(raw: &[u8]) -> Result<Self> {
        if raw.len() != PROVENANCE_BYTES {
            return Err(Error::Codec);
        }
        crate::blocks::canonical(raw, PROVENANCE_BYTES)?;
        let mut d = Decoder::new(raw);
        let p = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("provenance");
            let fixed = |d: &mut Decoder<'_>| -> std::result::Result<Hash, minicbor::decode::Error> {
                d.bytes()?.try_into().map_err(|_| bad())
            };
            if d.array()? != Some(6) || d.u8()? != 1 {
                return Err(bad());
            }
            let endorsement_root = fixed(&mut d)?;
            let ek_public_sha256 = fixed(&mut d)?;
            let ak_name: [u8; 34] = d.bytes()?.try_into().map_err(|_| bad())?;
            let platform_profile_sha256 = fixed(&mut d)?;
            if d.array()? != Some(5) {
                return Err(bad());
            }
            let mut evidence = [[0u8; 32]; 5];
            for (i, kind) in EVIDENCE_KINDS.iter().enumerate() {
                if d.array()? != Some(2) || d.u8()? != *kind as u8 {
                    return Err(bad());
                }
                evidence[i] = fixed(&mut d)?;
            }
            Ok(Self {
                endorsement_root,
                ek_public_sha256,
                ak_name,
                platform_profile_sha256,
                evidence,
                endorsement: None,
            })
        })()
        .map_err(|_| Error::Codec)?;
        if d.position() != raw.len() || p.encode() != raw {
            return Err(Error::NonCanonical);
        }
        Ok(p)
    }
    /// The value a version-2 profile's `admission_trust_manifest` must equal (C1).
    pub fn commitment(&self) -> Hash {
        let domain = if self.endorsement.is_some() { PROVENANCE_V2_DOMAIN } else { PROVENANCE_DOMAIN };
        domain_hash(domain, &self.encode())
    }
}

/// TPM Name of an attestation key: 0x000b (SHA-256) || SHA-256(TPMT_PUBLIC), the same computation
/// `tpm::TpmProfile::verify_certified_key` applies to the certified voting key.
pub fn ak_name(ak_public: &[u8]) -> Result<[u8; 34]> {
    let inner = crate::tpm::unboxed_public(ak_public)?;
    let mut name = [0u8; 34];
    name[..2].copy_from_slice(&[0, 0xb]);
    name[2..].copy_from_slice(&Sha256::digest(inner));
    Ok(name)
}
/// Device (PCR) profile digest (C4): H(PLATFORM_PROFILE_DOMAIN, pcr_bitmap || pcr_digest).
pub fn platform_profile(pcr_bitmap: [u8; 3], pcr_digest: Hash) -> Hash {
    let mut body = pcr_bitmap.to_vec();
    body.extend_from_slice(&pcr_digest);
    domain_hash(PLATFORM_PROFILE_DOMAIN, &body)
}
/// Commitment to an endorsement-root set: H(TRUST_ROOTS_DOMAIN, CBOR array of the roots as
/// 32-byte byte strings in ascending order). The set must be non-empty and contain no zero root.
pub fn trust_roots_commitment(roots: &BTreeSet<Hash>) -> Result<Hash> {
    if roots.is_empty() || roots.len() > 1024 || roots.contains(&[0; 32]) {
        return Err(Error::UnqualifiedPhysical);
    }
    let mut e = Encoder::new(Vec::new());
    e.array(roots.len() as u64).unwrap();
    for root in roots {
        e.bytes(root).unwrap();
    }
    Ok(domain_hash(TRUST_ROOTS_DOMAIN, &e.into_writer()))
}

/// Admission class of a chain, derived only from consensus-committed data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdmissionClass {
    /// No trust-roots commitment in the Genesis parameters: legacy fixtures, isolated tests and
    /// every existing vector. Behaviour is exactly the pre-package behaviour.
    LegacyTest,
    /// The Genesis rule manifest commits to the policy's endorsement-root set.
    Production,
}
/// Trust-roots commitment declared by the committed Genesis parameters record, if any.
pub fn declared_trust_roots(parameters: Option<&[u8]>) -> Result<Option<Hash>> {
    let Some(raw) = parameters else {
        return Ok(None);
    };
    let parameters = crate::genesis_inputs::Parameters::decode(raw)?;
    let mut found = parameters
        .rules
        .commitments
        .iter()
        .filter(|(name, _)| name.as_slice() == TRUST_ROOTS_COMMITMENT);
    let first = found.next().map(|(_, h)| *h);
    if found.next().is_some() {
        return Err(Error::Duplicate);
    }
    Ok(first)
}
/// Class from the committed Genesis parameters record and the committed policy root set.
pub fn class_for(parameters: Option<&[u8]>, roots: Option<&BTreeSet<Hash>>) -> Result<AdmissionClass> {
    match declared_trust_roots(parameters)? {
        None => Ok(AdmissionClass::LegacyTest),
        Some(declared) => {
            let roots = roots.ok_or(Error::UnqualifiedPhysical)?;
            if trust_roots_commitment(roots)? != declared {
                return Err(Error::UnqualifiedPhysical);
            }
            Ok(AdmissionClass::Production)
        }
    }
}
impl crate::execution::State {
    /// The admission class of this state, from its committed Genesis parameters record and its
    /// committed (V1 or V2) admission policy. Never from an operation or profile label.
    pub fn admission_class(&self) -> Result<AdmissionClass> {
        // A V2 Genesis commits its class as an explicit byte of the immutable GenesisParametersV2
        // record (Order A10); a state that carries that record never falls back to the V1 rule.
        if let Some(class) = crate::genesis_v2::committed_class(self)? {
            return Ok(class);
        }
        let parameters = self
            .protocol_records
            .get(&crate::genesis_inputs::parameters_key())
            .map(Vec::as_slice);
        let roots = match (&self.admission.policy, &self.admission_policy_v2) {
            (Some(policy), None) => Some(&policy.endorsement_roots),
            (None, Some(record)) => Some(&record.initial().endorsement_roots),
            (None, None) => None,
            (Some(_), Some(_)) => return Err(Error::UnqualifiedPhysical),
        };
        class_for(parameters, roots)
    }
}

/// Why a profile fails the Production-class rule (distinct per check; tests assert these).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The profile carries a TEST-VALUE marker (accidental-use guard on simulator material).
    TestValueMarker,
    /// Version-1 profile: no typed provenance statement.
    MissingProvenance,
    /// C1: `admission_trust_manifest` is not the commitment to this provenance statement.
    ManifestMismatch,
    /// C2: the statement's endorsement root differs from the approval's endorsement root.
    RootMismatch,
    /// C2: the endorsement root is not in the committed policy root set.
    RootNotInPolicy,
    /// C3: `ak_name` is not the Name of THIS profile's attestation key.
    AttestationKeyMismatch,
    /// C4: empty PCR selection.
    EmptyPcrSelection,
    /// C4: `platform_profile_sha256` does not commit to this profile's PCR selection and digest.
    PlatformProfileMismatch,
    /// C5: an evidence digest (or the EK public hash) is zero.
    ZeroEvidence,
    /// C5: two evidence digests are equal.
    DuplicateEvidence,
    /// A4: a version-1 statement (no committed endorsement identity), or a version-2 statement
    /// with no or more than `MAX_IDENTITIES` identities.
    MissingEndorsementIdentity,
    /// A4: the first identity's root differs from the statement's endorsement root.
    IdentityRootMismatch,
    /// A4: two committed endorsement identities are equal.
    DuplicateIdentity,
    /// A4, C6: the profile's `hardware` is not the class-1 endorsement identity (a label).
    HardwareMismatch,
}
/// The single Production-class rule (C1..C5, the TEST-VALUE marker and, since candidate 3, the
/// version-2 endorsement identity checks of decision A4 with C6) with a precise failure.
/// `endorsement_root` is the root named by the authority's approval (V1 ApprovedProfile, V2
/// Admission); `roots` is the committed policy root set. LegacyTest class: no additional check.
pub fn check_profile_detailed(
    class: AdmissionClass,
    profile: &TpmProfile,
    endorsement_root: Hash,
    roots: &BTreeSet<Hash>,
) -> std::result::Result<(), Failure> {
    if class == AdmissionClass::LegacyTest {
        return Ok(());
    }
    if profile.is_test_value() {
        return Err(Failure::TestValueMarker);
    }
    let p = profile.provenance.as_ref().ok_or(Failure::MissingProvenance)?;
    // A4: only a version-2 statement commits to endorsement identities.
    let e = p.endorsement.as_ref().ok_or(Failure::MissingEndorsementIdentity)?;
    if e.identities.is_empty() || e.identities.len() > MAX_IDENTITIES {
        return Err(Failure::MissingEndorsementIdentity);
    }
    if profile.admission_trust_manifest != p.commitment() {
        return Err(Failure::ManifestMismatch);
    }
    if p.endorsement_root != endorsement_root {
        return Err(Failure::RootMismatch);
    }
    if !roots.contains(&p.endorsement_root) {
        return Err(Failure::RootNotInPolicy);
    }
    if ak_name(&profile.ak_public).map_err(|_| Failure::AttestationKeyMismatch)? != p.ak_name {
        return Err(Failure::AttestationKeyMismatch);
    }
    if profile.pcr_bitmap == [0; 3] {
        return Err(Failure::EmptyPcrSelection);
    }
    if platform_profile(profile.pcr_bitmap, profile.pcr_digest) != p.platform_profile_sha256 {
        return Err(Failure::PlatformProfileMismatch);
    }
    if p.ek_public_sha256 == [0; 32] || p.evidence.iter().any(|d| *d == [0; 32]) {
        return Err(Failure::ZeroEvidence);
    }
    let distinct: BTreeSet<&Hash> = p.evidence.iter().collect();
    if distinct.len() != p.evidence.len() {
        return Err(Failure::DuplicateEvidence);
    }
    // A4 / A7: identities and the witness commitment are present, rooted in the policy, distinct,
    // and the profile's `hardware` IS the class-1 identity (C6).
    if e.witness_sha256 == [0; 32] || e.identities.iter().any(|(r, id)| *r == [0; 32] || *id == [0; 32]) {
        return Err(Failure::ZeroEvidence);
    }
    if e.identities[0].0 != p.endorsement_root {
        return Err(Failure::IdentityRootMismatch);
    }
    if e.identities.iter().any(|(r, _)| !roots.contains(r)) {
        return Err(Failure::RootNotInPolicy);
    }
    let identities: BTreeSet<&Hash> = e.identities.iter().map(|(_, id)| id).collect();
    if identities.len() != e.identities.len() {
        return Err(Failure::DuplicateIdentity);
    }
    if profile.hardware != e.identities[0].1 {
        return Err(Failure::HardwareMismatch);
    }
    Ok(())
}
/// `check_profile_detailed` mapped to the consensus error used by every admission path.
pub fn check_profile(
    class: AdmissionClass,
    profile: &TpmProfile,
    endorsement_root: Hash,
    roots: &BTreeSet<Hash>,
) -> Result<()> {
    check_profile_detailed(class, profile, endorsement_root, roots)
        .map_err(|_| Error::UnqualifiedPhysical)
}
