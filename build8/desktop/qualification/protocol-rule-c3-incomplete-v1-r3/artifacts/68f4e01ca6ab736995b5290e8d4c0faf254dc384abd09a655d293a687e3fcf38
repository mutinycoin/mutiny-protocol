//! BUILD8-CLOCK-ANCHOR-V2: the durable clock anchor and its write-ahead lineage mark.
//!
//! The authoritative description of the on-disk format, the verification rules and the threat model
//! is docs/CLOCK-PROFILE-V1.md, section "Persistent clock anchor". This module is pure: it encodes,
//! decodes and classifies bytes and performs no I/O.
//!
//! Principles (Architect ruling 5, 3 Oct 2026; Order C4 and C6, 4 Oct 2026):
//! * The record carries the calibration EVIDENCE (profile, calibration interval, elapsed-source
//!   readings, boot identity, drift rules, leap claim), never a "qualified" flag and never a current
//!   uncertainty.
//! * The record NEVER grants qualification after a restart (Order C4): its hash is unkeyed and its
//!   file is writable by the node's own account, so it is neither integrity nor rollback
//!   protection. `HoldoverClock::assess_restart` verifies it as diagnostic evidence only; a
//!   restarted engine is unqualified until a fresh authenticated calibration.
//! * The encoding is canonical (one valid byte string per value), versioned and of fixed length.
//! * The integrity hash is an UNKEYED domain-separated SHA-256. It detects corruption and
//!   unintended edits; it does not authenticate (see the threat model in the document). A MAC alone
//!   would not be rollback protection either, and a key beside the writable file is not that
//!   boundary.
//! * An old (v1) or unknown-version record is refused outright and nothing in it is imported or
//!   ratcheted (Order C6). A v1 record may be inspected for a log line only (`inspect_legacy_v1`).
use super::{ClockProfile, Elapsed, LeapClaim, LeapKind, LeapView, Unqualified};
use crate::{Hash, domain_hash};

/// Every anchor version starts with this prefix; the eighth magic byte is the ASCII version digit.
const MAGIC_PREFIX: &[u8; 7] = b"MCLKANC";
const MAGIC_V2: &[u8; 8] = b"MCLKANC2";
/// Format version field of the v2 record (redundant with the magic digit; both must agree).
pub const ANCHOR_VERSION: u16 = 2;
/// Domain of the v2 anchor integrity hash: `SHA-256(domain || 0x00 || bytes[0 .. LEN - 32])`.
pub const ANCHOR_DOMAIN: &[u8] = b"MUTINY-CLOCK-ANCHOR-V2";
/// Domain of the retired v1 anchor checksum (read only to log a refused v1 file).
const LEGACY_DOMAIN: &[u8] = b"MUTINY-CLOCK-ANCHOR-V1";
const LEGACY_LEN: usize = 128;
const LINEAGE_MAGIC: &[u8; 8] = b"MCLKSEQ2";
/// Domain of the lineage mark integrity hash.
pub const LINEAGE_DOMAIN: &[u8] = b"MUTINY-CLOCK-LINEAGE-V2";

/// Why stored bytes could not even serve as evidence. Since Order C4 no stored record is adopted
/// at all: every outcome, these variants and a successful `assess_restart` alike, means no anchor
/// and unqualified until an authenticated recalibration. There is no variant that grants
/// qualification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorError {
    /// Shorter than a record, or not exactly the fixed record length.
    Length,
    /// Not an anchor of any known format (bad magic).
    Magic,
    /// A known OLD format (version 1): refused, never adopted. `inspect_legacy_v1` may read it for
    /// a log line.
    Legacy,
    /// A format version this build does not know (the ASCII digit of the magic).
    Version(u8),
    /// The integrity hash does not match the bytes.
    Integrity,
    /// A valid hash over bytes that are not the canonical encoding: reserved field set, unknown
    /// tag, zero sequence, a profile identity that is not the hash of the carried parameters.
    Canonical,
    /// Written under a different profile (identity or any explicit parameter differs).
    Profile,
    /// A derived field does not match its recomputation, or the persist instant is inconsistent
    /// with the calibration instant.
    Inconsistent,
    /// The record is older than the lineage mark: a stale anchor was put back (rollback), or the
    /// process died between writing the mark and writing the record. Refused either way.
    Rollback,
    /// The record is newer than the lineage mark: the mark was lost or rolled back.
    Ahead,
    /// A record exists but there is no valid lineage mark to prove it is the latest.
    LineageMissing,
    /// The engine's own holdover checks failed on the state recomputed from the record: boot
    /// change, suspend, elapsed-source regression or unavailability, expiry, width.
    Unqualified(Unqualified),
}

/// What stored bytes claim to be, from their magic alone (no integrity is implied).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorFormat {
    V2,
    /// Version 1 (`MCLKANC1`): refused.
    LegacyV1,
    /// Anything else, including versions this build does not know.
    Unknown,
}
pub fn classify_anchor(raw: &[u8]) -> AnchorFormat {
    match version_of(raw) {
        Ok(b'2') => AnchorFormat::V2,
        Ok(b'1') => AnchorFormat::LegacyV1,
        _ => AnchorFormat::Unknown,
    }
}
/// The ASCII version digit of the magic, or `Length` / `Magic`.
fn version_of(raw: &[u8]) -> Result<u8, AnchorError> {
    if raw.len() < 8 {
        return Err(AnchorError::Length);
    }
    if &raw[..7] != MAGIC_PREFIX || !raw[7].is_ascii_digit() {
        return Err(AnchorError::Magic);
    }
    Ok(raw[7])
}

/// Durable anchor. Decoding or assessing it never grants qualification (Order C4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PersistedAnchor {
    /// The profile the anchor was calibrated and persisted under: all nine identity fields in
    /// explicit form. The identity (`ClockProfile::id()`) is written beside them and verified.
    pub params: ClockProfile,
    /// Strictly increasing per anchor file lineage (>= 1); see `LineageMark`.
    pub sequence: u64,
    /// The calibration interval as ADOPTED: `[lower_ms, upper_ms]` at the instant `at`, after the
    /// capture-age roll (so it already includes the source uncertainty and every engine term).
    pub lower_ms: u64,
    pub upper_ms: u64,
    /// Calibration uncertainty: `ceil((upper - lower) / 2)`, at most the profile calibration cap.
    pub half_width_ms: u64,
    /// The calibration instant on the elapsed source (monotonic, boottime, boot identity).
    pub at: Elapsed,
    /// Elapsed milliseconds since the calibration after which the profile's holdover or
    /// interval-width limit ends the anchor (derived from the drift rule; verified by
    /// `HoldoverClock::assess_restart`).
    pub validity_horizon_ms: u64,
    /// Elapsed-source readings at persist time (same boot as `at`): continuity is checked from
    /// here as well as from the calibration.
    pub persisted_monotonic_ns: u64,
    pub persisted_boottime_ns: u64,
    /// Highest lower bound ever reported when the record was written (a ratchet, never lowered).
    pub high_water_ms: u64,
    /// The leap information the writer stood behind: a claim about the past.
    pub leap: LeapClaim,
}

const KIND_NONE: u8 = 0;
const KIND_CLEAR: u8 = 1;
const KIND_INSERT: u8 = 2;
const KIND_DELETE: u8 = 3;

impl PersistedAnchor {
    /// Total length of the fixed record in bytes (also the length limit a reader applies).
    pub const LEN: usize = 255;
    const BODY: usize = Self::LEN - 32;

    /// The elapsed-source reading at persist time.
    pub fn persisted_at(&self) -> Elapsed {
        Elapsed {
            monotonic_ns: self.persisted_monotonic_ns,
            boottime_ns: self.persisted_boottime_ns,
            boot_id: self.at.boot_id,
        }
    }
    /// True when `other` carries the same calibration evidence and leap claim (everything except
    /// the sequence, the persist-time readings and the high-water mark).
    pub fn same_evidence(&self, other: &Self) -> bool {
        self.params == other.params
            && self.lower_ms == other.lower_ms
            && self.upper_ms == other.upper_ms
            && self.at == other.at
            && self.leap == other.leap
    }

    /// Canonical encoding (all integers big-endian, fixed layout):
    ///
    /// ```text
    ///   0   8  magic "MCLKANC2"            10  32 profile id (ClockProfile::id())
    ///   8   2  version = 2                 42  72 nine profile fields, id-preimage order
    /// 114   8  sequence                   122   8 calibration lower_ms
    /// 130   8  calibration upper_ms       138   8 calibration half_width_ms
    /// 146   8  calibration monotonic_ns   154   8 calibration boottime_ns
    /// 162  16  boot_id                    178   8 validity_horizon_ms
    /// 186   8  persist monotonic_ns       194   8 persist boottime_ns
    /// 202   8  high_water_ms              210   4 leap policy version
    /// 214   1  leap kind (0 none, 1 clear, 2 insert, 3 delete)
    /// 215   8  leap_ms (clear: valid_until, pending: boundary, none: 0)
    /// 223  32  SHA-256("MUTINY-CLOCK-ANCHOR-V2" || 0x00 || bytes[0..223])
    /// ```
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(Self::LEN);
        b.extend_from_slice(MAGIC_V2);
        b.extend_from_slice(&ANCHOR_VERSION.to_be_bytes());
        b.extend_from_slice(&self.params.id());
        for v in self.params.fields() {
            b.extend_from_slice(&v.to_be_bytes());
        }
        for v in [
            self.sequence,
            self.lower_ms,
            self.upper_ms,
            self.half_width_ms,
            self.at.monotonic_ns,
            self.at.boottime_ns,
        ] {
            b.extend_from_slice(&v.to_be_bytes());
        }
        b.extend_from_slice(&self.at.boot_id.to_be_bytes());
        for v in [
            self.validity_horizon_ms,
            self.persisted_monotonic_ns,
            self.persisted_boottime_ns,
            self.high_water_ms,
        ] {
            b.extend_from_slice(&v.to_be_bytes());
        }
        b.extend_from_slice(&self.leap.policy.to_be_bytes());
        let (kind, ms) = match self.leap.view {
            LeapView::Unassessed => (KIND_NONE, 0),
            LeapView::Clear { valid_until_ms } => (KIND_CLEAR, valid_until_ms),
            LeapView::Pending {
                kind: LeapKind::Insert,
                boundary_ms,
            } => (KIND_INSERT, boundary_ms),
            LeapView::Pending {
                kind: LeapKind::Delete,
                boundary_ms,
            } => (KIND_DELETE, boundary_ms),
        };
        b.push(kind);
        b.extend_from_slice(&ms.to_be_bytes());
        debug_assert_eq!(b.len(), Self::BODY);
        let sum = domain_hash(ANCHOR_DOMAIN, &b);
        b.extend_from_slice(&sum);
        b
    }

    /// Strict decode: length, magic, version, integrity, canonical form. A v1 record is
    /// `Err(Legacy)`, any other version `Err(Version)`. No decoded record is ever adopted either
    /// (Order C4): semantic verification against the profile and the elapsed source is
    /// `HoldoverClock::assess_restart`, which reports evidence only.
    pub fn decode(raw: &[u8]) -> Result<Self, AnchorError> {
        let digit = version_of(raw)?;
        match digit {
            b'2' => {}
            b'1' => return Err(AnchorError::Legacy),
            d => return Err(AnchorError::Version(d - b'0')),
        }
        if raw.len() != Self::LEN {
            return Err(AnchorError::Length);
        }
        let (body, sum) = raw.split_at(Self::BODY);
        if domain_hash(ANCHOR_DOMAIN, body) != sum {
            return Err(AnchorError::Integrity);
        }
        let u16_at = |i: usize| u16::from_be_bytes(body[i..i + 2].try_into().unwrap());
        let u64_at = |i: usize| u64::from_be_bytes(body[i..i + 8].try_into().unwrap());
        if u16_at(8) != ANCHOR_VERSION {
            return Err(AnchorError::Canonical);
        }
        let id: Hash = body[10..42].try_into().unwrap();
        let mut fields = [0u64; 9];
        for (i, f) in fields.iter_mut().enumerate() {
            *f = u64_at(42 + 8 * i);
        }
        let params = ClockProfile::from_fields(&fields).ok_or(AnchorError::Canonical)?;
        if params.id() != id {
            return Err(AnchorError::Canonical);
        }
        let sequence = u64_at(114);
        if sequence == 0 {
            return Err(AnchorError::Canonical);
        }
        let boot_id = u128::from_be_bytes(body[162..178].try_into().unwrap());
        let policy = u32::from_be_bytes(body[210..214].try_into().unwrap());
        let ms = u64_at(215);
        let view = match body[214] {
            KIND_NONE if ms == 0 => LeapView::Unassessed,
            KIND_CLEAR => LeapView::Clear { valid_until_ms: ms },
            KIND_INSERT => LeapView::Pending {
                kind: LeapKind::Insert,
                boundary_ms: ms,
            },
            KIND_DELETE => LeapView::Pending {
                kind: LeapKind::Delete,
                boundary_ms: ms,
            },
            _ => return Err(AnchorError::Canonical),
        };
        Ok(Self {
            params,
            sequence,
            lower_ms: u64_at(122),
            upper_ms: u64_at(130),
            half_width_ms: u64_at(138),
            at: Elapsed {
                monotonic_ns: u64_at(146),
                boottime_ns: u64_at(154),
                boot_id,
            },
            validity_horizon_ms: u64_at(178),
            persisted_monotonic_ns: u64_at(186),
            persisted_boottime_ns: u64_at(194),
            high_water_ms: u64_at(202),
            leap: LeapClaim { policy, view },
        })
    }
}

/// What a version-1 file said, for a log line ONLY. It is never an input to `assess_restart`: a
/// v1 record carries no persist-time readings, no explicit parameters, no leap information and no
/// lineage, so it cannot even serve as evidence, and nothing in it is imported (Order C6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegacySummary {
    pub profile: Hash,
    pub lower_ms: u64,
    pub upper_ms: u64,
    pub high_water_ms: u64,
}
/// Read a v1 anchor (`MCLKANC1`, 128 bytes, checksum domain `MUTINY-CLOCK-ANCHOR-V1`) for logging.
pub fn inspect_legacy_v1(raw: &[u8]) -> Option<LegacySummary> {
    if raw.len() != LEGACY_LEN || &raw[..8] != b"MCLKANC1" {
        return None;
    }
    let (body, sum) = raw.split_at(LEGACY_LEN - 32);
    if domain_hash(LEGACY_DOMAIN, body) != sum {
        return None;
    }
    let u = |i: usize| u64::from_be_bytes(body[i..i + 8].try_into().unwrap());
    Some(LegacySummary {
        profile: body[8..40].try_into().unwrap(),
        lower_ms: u(40),
        upper_ms: u(48),
        high_water_ms: u(88),
    })
}

/// The write-ahead lineage mark ("rollback high-water mark"): the highest anchor sequence number
/// for which a write was ever STARTED, plus the high-water lower bound at that time. The writer
/// stores (and syncs) the mark BEFORE the anchor, so the anchor on disk is current only if its
/// sequence equals the mark's. Replacing the anchor with an older valid record is therefore
/// detected; invalidating the anchor needs only a new mark.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LineageMark {
    pub sequence: u64,
    pub high_water_ms: u64,
}
impl LineageMark {
    /// Fixed length: magic 8, version 2, sequence 8, high-water 8, SHA-256 32.
    pub const LEN: usize = 58;
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(Self::LEN);
        b.extend_from_slice(LINEAGE_MAGIC);
        b.extend_from_slice(&ANCHOR_VERSION.to_be_bytes());
        b.extend_from_slice(&self.sequence.to_be_bytes());
        b.extend_from_slice(&self.high_water_ms.to_be_bytes());
        let sum = domain_hash(LINEAGE_DOMAIN, &b);
        b.extend_from_slice(&sum);
        b
    }
    pub fn decode(raw: &[u8]) -> Result<Self, AnchorError> {
        if raw.len() != Self::LEN {
            return Err(AnchorError::Length);
        }
        if &raw[..8] != LINEAGE_MAGIC {
            return Err(AnchorError::Magic);
        }
        let (body, sum) = raw.split_at(Self::LEN - 32);
        if domain_hash(LINEAGE_DOMAIN, body) != sum {
            return Err(AnchorError::Integrity);
        }
        if u16::from_be_bytes(body[8..10].try_into().unwrap()) != ANCHOR_VERSION {
            return Err(AnchorError::Canonical);
        }
        let sequence = u64::from_be_bytes(body[10..18].try_into().unwrap());
        if sequence == 0 {
            return Err(AnchorError::Canonical);
        }
        Ok(Self {
            sequence,
            high_water_ms: u64::from_be_bytes(body[18..26].try_into().unwrap()),
        })
    }
}
/// The anti-rollback rule. A record is the latest durable one only if a valid mark exists and its
/// sequence equals the record's. (A crash between "mark written" and "anchor written" leaves the
/// mark one ahead of the previous record; that is refused too, because it cannot be told from a
/// rollback. The node then recalibrates: fail closed, never extending the budget.)
pub fn lineage_check(record_sequence: u64, mark: Option<&LineageMark>) -> Result<(), AnchorError> {
    match mark {
        None => Err(AnchorError::LineageMissing),
        Some(m) if record_sequence < m.sequence => Err(AnchorError::Rollback),
        Some(m) if record_sequence > m.sequence => Err(AnchorError::Ahead),
        Some(_) => Ok(()),
    }
}

/// The retired v1 encoding, byte for byte, so tests can prove a genuine v1 file never qualifies.
#[cfg(test)]
pub(crate) fn legacy_v1_encode(
    profile: Hash,
    lower_ms: u64,
    upper_ms: u64,
    at: &Elapsed,
    high_water_ms: u64,
) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"MCLKANC1");
    b.extend_from_slice(&profile);
    for v in [lower_ms, upper_ms, at.monotonic_ns, at.boottime_ns] {
        b.extend_from_slice(&v.to_be_bytes());
    }
    b.extend_from_slice(&at.boot_id.to_be_bytes());
    b.extend_from_slice(&high_water_ms.to_be_bytes());
    let sum = domain_hash(LEGACY_DOMAIN, &b);
    b.extend_from_slice(&sum);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn profile() -> ClockProfile {
        ClockProfile {
            max_source_uncertainty_ms: 248,
            max_calibration_half_width_ms: 250,
            min_sources: 1,
            max_faulty_sources: 0,
            drift_bound_ppb: 8680,
            max_holdover_ms: 86_400_000,
            max_interval_half_width_ms: 1000,
            max_suspend_gap_ms: 50,
            confirm_calibrations: 1,
        }
    }
    pub(crate) fn record() -> PersistedAnchor {
        PersistedAnchor {
            params: profile(),
            sequence: 7,
            lower_ms: 1_790_899_299_987,
            upper_ms: 1_790_899_300_014,
            half_width_ms: 14,
            at: Elapsed {
                monotonic_ns: 1_000_000_000,
                boottime_ns: 1_000_000_000,
                boot_id: 0x0123_4567_89ab_cdef_0123_4567_89ab_cdef,
            },
            validity_horizon_ms: 86_400_000,
            persisted_monotonic_ns: 61_000_000_000,
            persisted_boottime_ns: 61_000_000_000,
            high_water_ms: 1_790_899_299_990,
            leap: LeapClaim {
                policy: 1,
                view: LeapView::Clear {
                    valid_until_ms: 1_798_761_599_000,
                },
            },
        }
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
    /// Re-seal modified bytes so a test reaches the CANONICAL check rather than the hash check.
    fn reseal(mut raw: Vec<u8>) -> Vec<u8> {
        raw.truncate(PersistedAnchor::BODY);
        let sum = domain_hash(ANCHOR_DOMAIN, &raw);
        raw.extend_from_slice(&sum);
        raw
    }

    #[test]
    fn layout_is_fixed_and_offsets_match_the_specification() {
        let raw = record().encode();
        assert_eq!(raw.len(), PersistedAnchor::LEN);
        assert_eq!(PersistedAnchor::LEN, 255);
        assert_eq!(&raw[..8], b"MCLKANC2");
        assert_eq!(&raw[8..10], &[0, 2]);
        assert_eq!(&raw[10..42], &profile().id());
        assert_eq!(&raw[42..50], &248u64.to_be_bytes());
        assert_eq!(&raw[106..114], &1u64.to_be_bytes(), "confirm_calibrations is the ninth field");
        assert_eq!(&raw[114..122], &7u64.to_be_bytes());
        assert_eq!(&raw[122..130], &1_790_899_299_987u64.to_be_bytes());
        assert_eq!(&raw[162..178], &0x0123_4567_89ab_cdef_0123_4567_89ab_cdefu128.to_be_bytes());
        assert_eq!(&raw[178..186], &86_400_000u64.to_be_bytes());
        assert_eq!(&raw[202..210], &1_790_899_299_990u64.to_be_bytes());
        assert_eq!(&raw[210..214], &1u32.to_be_bytes());
        assert_eq!(raw[214], KIND_CLEAR);
        assert_eq!(&raw[215..223], &1_798_761_599_000u64.to_be_bytes());
        assert_eq!(&raw[223..], &domain_hash(ANCHOR_DOMAIN, &raw[..223]));
        assert_eq!(LineageMark::LEN, 58);
        let mark = LineageMark {
            sequence: 7,
            high_water_ms: 9,
        };
        assert_eq!(mark.encode().len(), LineageMark::LEN);
        assert_eq!(LineageMark::decode(&mark.encode()), Ok(mark));
    }

    #[test]
    fn frozen_vector_for_the_v2_format() {
        // Any change to these bytes is a format change: it needs a new version (magic digit).
        assert_eq!(hex(&record().encode()), FROZEN_V2_HEX, "the v2 byte layout changed");
        assert_eq!(hex(&profile().id()), FROZEN_PROFILE_ID);
    }
    /// The reference-budget profile identity (docs/reference-budget-profile-v1.json), unchanged.
    const FROZEN_PROFILE_ID: &str = "1aac4fe452dfb6b11dac6ddf18aa9507e730b0d5caac6102e8a368b47fccc81c";
    const FROZEN_V2_HEX: &str = "4d434c4b414e433200021aac4fe452dfb6b11dac6ddf18aa9507e730b0d5caac\
        6102e8a368b47fccc81c00000000000000f800000000000000fa000000000000\
        0001000000000000000000000000000021e80000000005265c00000000000000\
        03e8000000000000003200000000000000010000000000000007000001a0f9ea\
        a693000001a0f9eaa6ae000000000000000e000000003b9aca00000000003b9a\
        ca000123456789abcdef0123456789abcdef0000000005265c000000000e33e2\
        22000000000e33e22200000001a0f9eaa6960000000101000001a2ce8bd018b3\
        d886993c04c5a30cc9680cc3d841830a0f59f82de0bed20957d1df328bcf93";

    #[test]
    fn encode_decode_round_trip_is_canonical_for_every_leap_shape() {
        for view in [
            LeapView::Unassessed,
            LeapView::Clear { valid_until_ms: 5 },
            LeapView::Pending {
                kind: LeapKind::Insert,
                boundary_ms: 6,
            },
            LeapView::Pending {
                kind: LeapKind::Delete,
                boundary_ms: u64::MAX,
            },
        ] {
            let mut r = record();
            r.leap.view = view;
            let raw = r.encode();
            let back = PersistedAnchor::decode(&raw).unwrap();
            assert_eq!(back, r);
            assert_eq!(back.encode(), raw, "encoding is canonical");
        }
    }

    #[test]
    fn every_truncation_every_extension_and_every_flipped_bit_is_refused() {
        let raw = record().encode();
        for n in 0..raw.len() {
            assert!(PersistedAnchor::decode(&raw[..n]).is_err(), "prefix {n}");
        }
        for extra in 1..4 {
            let mut longer = raw.clone();
            longer.extend(std::iter::repeat_n(0u8, extra));
            assert_eq!(PersistedAnchor::decode(&longer), Err(AnchorError::Length));
        }
        for i in 0..raw.len() {
            for bit in 0..8 {
                let mut bad = raw.clone();
                bad[i] ^= 1 << bit;
                assert!(
                    PersistedAnchor::decode(&bad).is_err(),
                    "a flipped bit at byte {i} bit {bit} must never decode"
                );
            }
        }
        assert_eq!(PersistedAnchor::decode(&[]), Err(AnchorError::Length));
    }

    #[test]
    fn arbitrary_bytes_never_panic_and_never_decode() {
        // Deterministic xorshift: random buffers of every plausible length, and random multi-byte
        // corruptions of a valid record (the hash makes any accepted result astronomically unlikely;
        // this guards against panics and against a decoder that stops checking something).
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..4_000 {
            let len = (next() % 300) as usize;
            let mut buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            if len >= 8 && next() % 2 == 0 {
                buf[..8].copy_from_slice(MAGIC_V2);
            }
            assert!(PersistedAnchor::decode(&buf).is_err());
            assert!(LineageMark::decode(&buf).is_err());
            let _ = classify_anchor(&buf);
            let _ = inspect_legacy_v1(&buf);
        }
        let good = record().encode();
        for _ in 0..4_000 {
            let mut bad = good.clone();
            for _ in 0..(1 + next() % 6) {
                let i = (next() as usize) % bad.len();
                bad[i] = next() as u8;
            }
            if bad != good {
                assert!(PersistedAnchor::decode(&bad).is_err());
            }
        }
    }

    #[test]
    fn old_and_unknown_versions_never_decode() {
        let raw = record().encode();
        let mut v1 = raw.clone();
        v1[7] = b'1';
        assert_eq!(PersistedAnchor::decode(&v1), Err(AnchorError::Legacy));
        assert_eq!(classify_anchor(&v1), AnchorFormat::LegacyV1);
        for d in [b'0', b'3', b'9'] {
            let mut other = raw.clone();
            other[7] = d;
            assert_eq!(PersistedAnchor::decode(&other), Err(AnchorError::Version(d - b'0')));
            assert_eq!(classify_anchor(&other), AnchorFormat::Unknown);
        }
        let mut junk = raw.clone();
        junk[0] = b'X';
        assert_eq!(PersistedAnchor::decode(&junk), Err(AnchorError::Magic));
        let mut letter = raw.clone();
        letter[7] = b'A';
        assert_eq!(PersistedAnchor::decode(&letter), Err(AnchorError::Magic));
        assert_eq!(classify_anchor(&raw), AnchorFormat::V2);
        assert_eq!(classify_anchor(b"MCL"), AnchorFormat::Unknown);
        // A v1-looking string of ANY length is the legacy refusal, never a decode.
        assert_eq!(PersistedAnchor::decode(b"MCLKANC1"), Err(AnchorError::Legacy));
        assert_eq!(PersistedAnchor::decode(b"MCLKANC1 short"), Err(AnchorError::Legacy));
        // A header-only v2 prefix is a length error.
        assert_eq!(PersistedAnchor::decode(b"MCLKANC2"), Err(AnchorError::Length));
    }

    #[test]
    fn valid_hash_over_non_canonical_bytes_is_refused() {
        let good = record().encode();
        // Version field disagrees with the magic digit.
        let mut b = good.clone();
        b[9] = 3;
        assert_eq!(PersistedAnchor::decode(&reseal(b)), Err(AnchorError::Canonical));
        // Profile identity is not the hash of the carried parameters.
        let mut b = good.clone();
        b[10] ^= 1;
        assert_eq!(PersistedAnchor::decode(&reseal(b)), Err(AnchorError::Canonical));
        // Carried parameters changed without the identity: also inconsistent.
        let mut b = good.clone();
        b[49] ^= 1;
        assert_eq!(PersistedAnchor::decode(&reseal(b)), Err(AnchorError::Canonical));
        // A profile field that cannot be a u32 (min_sources) is not canonical.
        let mut b = good.clone();
        b[42 + 16] = 1;
        assert_eq!(PersistedAnchor::decode(&reseal(b)), Err(AnchorError::Canonical));
        // Zero sequence.
        let mut b = good.clone();
        b[114..122].copy_from_slice(&0u64.to_be_bytes());
        assert_eq!(PersistedAnchor::decode(&reseal(b)), Err(AnchorError::Canonical));
        // Unknown leap tag, and a "none" claim carrying a horizon.
        let mut b = good.clone();
        b[214] = 9;
        assert_eq!(PersistedAnchor::decode(&reseal(b)), Err(AnchorError::Canonical));
        let mut b = good.clone();
        b[214] = KIND_NONE;
        assert_eq!(PersistedAnchor::decode(&reseal(b)), Err(AnchorError::Canonical));
        let mut b = good;
        b[214] = KIND_NONE;
        b[215..223].copy_from_slice(&0u64.to_be_bytes());
        assert!(PersistedAnchor::decode(&reseal(b)).is_ok(), "a none claim with no horizon is canonical");
    }

    #[test]
    fn legacy_v1_files_can_be_inspected_for_a_log_line_only() {
        let at = Elapsed {
            monotonic_ns: 33,
            boottime_ns: 44,
            boot_id: 5,
        };
        let b = legacy_v1_encode(profile().id(), 11, 22, &at, 66);
        assert_eq!(b.len(), LEGACY_LEN);
        let s = inspect_legacy_v1(&b).unwrap();
        assert_eq!((s.lower_ms, s.upper_ms, s.high_water_ms), (11, 22, 66));
        assert_eq!(s.profile, profile().id());
        assert_eq!(PersistedAnchor::decode(&b), Err(AnchorError::Legacy));
        let mut bad = b.clone();
        bad[50] ^= 1;
        assert_eq!(inspect_legacy_v1(&bad), None);
        assert_eq!(inspect_legacy_v1(&b[..100]), None);
        assert_eq!(inspect_legacy_v1(&record().encode()), None);
    }

    #[test]
    fn lineage_mark_round_trip_and_rollback_rule() {
        let m = LineageMark {
            sequence: 5,
            high_water_ms: 1234,
        };
        let raw = m.encode();
        assert_eq!(LineageMark::decode(&raw), Ok(m));
        for n in 0..raw.len() {
            assert!(LineageMark::decode(&raw[..n]).is_err());
        }
        for i in 0..raw.len() {
            for bit in 0..8 {
                let mut bad = raw.clone();
                bad[i] ^= 1 << bit;
                assert!(LineageMark::decode(&bad).is_err(), "byte {i} bit {bit}");
            }
        }
        let mut zero = LineageMark {
            sequence: 1,
            high_water_ms: 0,
        }
        .encode();
        zero[10..18].copy_from_slice(&0u64.to_be_bytes());
        zero.truncate(26);
        let sum = domain_hash(LINEAGE_DOMAIN, &zero);
        zero.extend_from_slice(&sum);
        assert_eq!(LineageMark::decode(&zero), Err(AnchorError::Canonical));
        assert_eq!(lineage_check(5, Some(&m)), Ok(()));
        assert_eq!(lineage_check(4, Some(&m)), Err(AnchorError::Rollback));
        assert_eq!(lineage_check(6, Some(&m)), Err(AnchorError::Ahead));
        assert_eq!(lineage_check(5, None), Err(AnchorError::LineageMissing));
    }
}
