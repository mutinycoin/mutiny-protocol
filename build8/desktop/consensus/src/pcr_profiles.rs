//! PROPOSED / UNFROZEN (Architect's Continuation Order of 4 Oct 2026, decision A5; design
//! `qualification/candidate-3/A-ADMISSION-DESIGN-V1.md` section 6). The versioned accepted PCR-profile set and the
//! deterministic requalification check.
//!
//! The set is committed by the rules (Lane A1's Genesis slot; this module defines the record and its commitment). A
//! profile's identifier is the C4 platform-profile digest `provenance::platform_profile(selection, digest)`, so the
//! provenance statement's `platform_profile_sha256` IS the identifier. Actual PCR values, selections and their
//! interpretation are platform evidence (inventory I7); no value is built in.
//!
//! Requalification (prepared, NOT wired into a block operation: that needs a new operation kind, design question A5-Q1):
//! a member whose measurements change legitimately proves its new state with a fresh quote by its ALREADY ADMITTED
//! attestation key over a profile of the committed set. No owner, authority or local override takes part.
use crate::{Hash, domain_hash, provenance::platform_profile, tpm::TpmProfile};
use minicbor::{Decoder, Encoder};
use std::collections::BTreeMap;

pub const ACCEPTED_PCR_PROFILES_DOMAIN: &[u8] = b"MUTINY-BUILD8-ACCEPTED-PCR-PROFILES-V1";
/// TPM_ALG_SHA256: the only bank the quote verifier accepts (`tpm::TpmProfile::verify_quote`).
pub const SHA256_BANK: u16 = 0x000b;
/// "TPM2_Quote composite: SHA-256 over the selected PCR values in ascending index order equals `digest`."
pub const INTERPRETATION_QUOTE_COMPOSITE: u8 = 1;
/// "Frozen at Genesis; a member may requalify only to a profile of this set." Other values are reserved.
pub const UPDATE_FROZEN_AT_GENESIS: u8 = 1;
pub const MAX_PROFILES: usize = 64;

/// One accepted profile: PCR bank, 3-byte selection bitmap (PCR 0-23), expected composite digest, interpretation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PcrProfile {
    pub bank: u16,
    pub selection: [u8; 3],
    pub digest: Hash,
    pub interpretation: u8,
}
impl PcrProfile {
    /// The C4 platform-profile digest of this profile.
    pub fn id(&self) -> Hash {
        platform_profile(self.selection, self.digest)
    }
}
/// Why a set or a profile is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PcrFailure {
    /// Not a canonical encoding.
    Codec,
    /// No profile, or more than `MAX_PROFILES`.
    Count,
    UnsupportedBank,
    EmptySelection,
    UnknownInterpretation,
    UnknownUpdateRule,
    /// Two entries with the same identifier.
    Duplicate,
    /// The profile is not in the committed set.
    NotAccepted,
    /// The requalification quote is not a valid quote of the admitted attestation key over the new profile.
    Quote,
}
/// Canonical CBOR `[1, update_rule, [[bank, selection, digest, interpretation] ...]]`, entries in ascending identifier
/// order, unique, 1..=64.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedPcrProfiles {
    update_rule: u8,
    profiles: BTreeMap<Hash, PcrProfile>,
}
impl AcceptedPcrProfiles {
    pub fn new(update_rule: u8, profiles: Vec<PcrProfile>) -> Result<Self, PcrFailure> {
        if update_rule != UPDATE_FROZEN_AT_GENESIS {
            return Err(PcrFailure::UnknownUpdateRule);
        }
        if profiles.is_empty() || profiles.len() > MAX_PROFILES {
            return Err(PcrFailure::Count);
        }
        let mut map = BTreeMap::new();
        for p in profiles {
            if p.bank != SHA256_BANK {
                return Err(PcrFailure::UnsupportedBank);
            }
            if p.selection == [0; 3] {
                return Err(PcrFailure::EmptySelection);
            }
            if p.interpretation != INTERPRETATION_QUOTE_COMPOSITE {
                return Err(PcrFailure::UnknownInterpretation);
            }
            if map.insert(p.id(), p).is_some() {
                return Err(PcrFailure::Duplicate);
            }
        }
        Ok(Self { update_rule, profiles: map })
    }
    pub fn update_rule(&self) -> u8 {
        self.update_rule
    }
    /// The accepted profiles in ascending identifier order (read by Genesis V2 input validation).
    pub fn profiles(&self) -> impl Iterator<Item = &PcrProfile> {
        self.profiles.values()
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(3).unwrap().u8(1).unwrap().u8(self.update_rule).unwrap();
        e.array(self.profiles.len() as u64).unwrap();
        for p in self.profiles.values() {
            e.array(4)
                .unwrap()
                .u16(p.bank)
                .unwrap()
                .bytes(&p.selection)
                .unwrap()
                .bytes(&p.digest)
                .unwrap()
                .u8(p.interpretation)
                .unwrap();
        }
        e.into_writer()
    }
    pub fn decode(raw: &[u8]) -> Result<Self, PcrFailure> {
        crate::blocks::canonical(raw, 8192).map_err(|_| PcrFailure::Codec)?;
        let mut d = Decoder::new(raw);
        let (rule, profiles) = (|| -> std::result::Result<(u8, Vec<PcrProfile>), minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("accepted PCR profiles");
            if d.array()? != Some(3) || d.u8()? != 1 {
                return Err(bad());
            }
            let rule = d.u8()?;
            let n = d.array()?.ok_or_else(bad)?;
            if n > MAX_PROFILES as u64 {
                return Err(bad());
            }
            let mut profiles = Vec::new();
            for _ in 0..n {
                if d.array()? != Some(4) {
                    return Err(bad());
                }
                profiles.push(PcrProfile {
                    bank: d.u16()?,
                    selection: d.bytes()?.try_into().map_err(|_| bad())?,
                    digest: d.bytes()?.try_into().map_err(|_| bad())?,
                    interpretation: d.u8()?,
                });
            }
            Ok((rule, profiles))
        })()
        .map_err(|_| PcrFailure::Codec)?;
        let set = Self::new(rule, profiles)?;
        if d.position() != raw.len() || set.encode() != raw {
            return Err(PcrFailure::Codec);
        }
        Ok(set)
    }
    /// The value Lane A1's Genesis slot commits to.
    pub fn commitment(&self) -> Hash {
        domain_hash(ACCEPTED_PCR_PROFILES_DOMAIN, &self.encode())
    }
    /// The admitted (bitmap, digest) is a profile of the committed set; returns its identifier.
    pub fn check_accepted(&self, pcr_bitmap: [u8; 3], pcr_digest: Hash) -> Result<Hash, PcrFailure> {
        let id = platform_profile(pcr_bitmap, pcr_digest);
        if !self.profiles.contains_key(&id) {
            return Err(PcrFailure::NotAccepted);
        }
        Ok(id)
    }
    /// Deterministic requalification check: `quote` is a valid TPM2_Quote over `challenge` by the attestation key of the
    /// ADMITTED profile (same AK, same certified voting key, same qualified signer) over the NEW selection and digest, and
    /// the new profile is in the committed set. The caller binds `challenge` to the parent and the node. Returns the new
    /// profile identifier. Firmware change on the same TPM: requalification; physical TPM replacement: hardware rotation.
    pub fn check_requalification(
        &self,
        admitted: &TpmProfile,
        new_bitmap: [u8; 3],
        new_digest: Hash,
        challenge: Hash,
        quote: &[u8],
    ) -> Result<Hash, PcrFailure> {
        let id = self.check_accepted(new_bitmap, new_digest)?;
        let mut requalified = admitted.clone();
        requalified.pcr_bitmap = new_bitmap;
        requalified.pcr_digest = new_digest;
        requalified
            .verify_quote(challenge, quote)
            .map_err(|_| PcrFailure::Quote)?;
        Ok(id)
    }
}
