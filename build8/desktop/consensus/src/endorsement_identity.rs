//! PROPOSED / UNFROZEN (Architect's Continuation Order of 4 Oct 2026, decision A4; design
//! `qualification/candidate-3/A-ADMISSION-DESIGN-V1.md` section 5). Canonical endorsement-key identity.
//!
//! The `hardware` field of a profile is derived from an endorsement key (EK), never chosen: `hardware =
//! ek_identity(the EK of identity class 1)`, with `ek_identity(EK) = H(HARDWARE_ID_DOMAIN, NetworkID_u32_be ||
//! EKPUB-CANON-V1(EK))`. EKPUB-CANON-V1 is the frozen, typed raw encoding of the KEY (one encoding per key), not the
//! certificate's SubjectPublicKeyInfo DER (several valid encodings of one key) and not the TPM object's TPMT_PUBLIC (the
//! object's template would become part of the identity). Templates are checked separately (`parse_ek_public_area`).
//!
//! What this module does NOT establish: that a key belongs to a genuine TPM (that is the certificate chain, `ek_chain`, and
//! credential activation, design A3), or that two different certified keys are on two different chips (design A4: an
//! endorsement-seed change gives the same chip a new key). Every identity a profile commits to is compared for
//! duplicates, not only `hardware` (`reject_shared_identity`, `continuity_keys_v2::Book::validate`).
use crate::{Error, Hash, NETWORK_ID, Result, domain_hash, tpm::TpmProfile};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Identity domain (the unadopted "V1" proposal hashed a SubjectPublicKeyInfo digest; it is not used).
pub const HARDWARE_ID_DOMAIN: &[u8] = b"MUTINY-BUILD8-PHYSICAL-HARDWARE-ID-V2";
/// Commitment over an ordered identity-class list (the network-wide classes every admission presents).
pub const IDENTITY_CLASSES_DOMAIN: &[u8] = b"MUTINY-BUILD8-EK-IDENTITY-CLASSES-V1";
pub const RSA_TAG: u8 = 0x01;
pub const ECC_TAG: u8 = 0x02;
/// RSA modulus sizes the canonical encoding accepts (the TCG EK template sizes).
pub const RSA_BITS: [u16; 3] = [2048, 3072, 4096];
/// TCG TPM_ECC_CURVE identifiers.
pub const TPM_ECC_NIST_P256: u16 = 0x0003;
pub const TPM_ECC_NIST_P384: u16 = 0x0004;
pub const TPM_ECC_NIST_P521: u16 = 0x0005;
/// At most four identity classes per admission (design A4).
pub const MAX_IDENTITY_CLASSES: usize = 4;
/// Largest EK public area (TPM2B_PUBLIC) a witness may carry.
pub const MAX_EK_PUBLIC_AREA: usize = 1024;

/// Why an endorsement key or public area is refused (distinct per rule; tests assert these).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityFailure {
    /// Neither the RSA nor the ECC tag.
    UnknownAlgorithm,
    /// Wrong total length, or trailing bytes.
    Length,
    /// Modulus size not in `RSA_BITS`, or the modulus does not have exactly that many bits.
    RsaModulusSize,
    /// An even modulus is not an RSA modulus.
    RsaModulusEven,
    /// The public exponent is even or below 3.
    RsaExponent,
    /// A curve other than P-256: defined by the encoding, refused until a reviewed crate validates it (A11).
    UnsupportedCurve,
    /// The coordinates are not a point of the curve (or the identity point).
    PointNotOnCurve,
    /// The public area is not a well-formed TPM2B_PUBLIC of an RSA or ECC key.
    PublicAreaMalformed,
    /// The public area's template (everything but the key) differs from the committed class template.
    TemplateMismatch,
    /// The key's algorithm or size differs from the committed class.
    ClassMismatch,
    /// The class list is empty, too long, repeated or malformed.
    ClassList,
}

/// An endorsement public key in canonical form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EkPublicKey {
    /// `bits` in `RSA_BITS`; `modulus` exactly `bits / 8` bytes, big-endian, top bit set, odd; `exponent` odd and >= 3.
    Rsa { bits: u16, exponent: u32, modulus: Vec<u8> },
    /// `curve` a TPM_ECC_CURVE value; `x` and `y` big-endian of exactly the field size.
    Ecc { curve: u16, x: Vec<u8>, y: Vec<u8> },
}
fn field_bytes(curve: u16) -> Option<usize> {
    match curve {
        TPM_ECC_NIST_P256 => Some(32),
        TPM_ECC_NIST_P384 => Some(48),
        TPM_ECC_NIST_P521 => Some(66),
        _ => None,
    }
}
impl EkPublicKey {
    /// The class of this key: (algorithm tag, modulus bits or curve).
    pub fn class(&self) -> (u8, u16) {
        match self {
            Self::Rsa { bits, .. } => (RSA_TAG, *bits),
            Self::Ecc { curve, .. } => (ECC_TAG, *curve),
        }
    }
    /// Every rule of EKPUB-CANON-V1 except the encoding itself.
    pub fn validate(&self) -> std::result::Result<(), IdentityFailure> {
        match self {
            Self::Rsa { bits, exponent, modulus } => {
                if !RSA_BITS.contains(bits) || modulus.len() != *bits as usize / 8 || modulus[0] & 0x80 == 0 {
                    return Err(IdentityFailure::RsaModulusSize);
                }
                if modulus[modulus.len() - 1] & 1 == 0 {
                    return Err(IdentityFailure::RsaModulusEven);
                }
                if *exponent < 3 || exponent & 1 == 0 {
                    return Err(IdentityFailure::RsaExponent);
                }
                Ok(())
            }
            Self::Ecc { curve, x, y } => {
                let size = field_bytes(*curve).ok_or(IdentityFailure::UnsupportedCurve)?;
                if *curve != TPM_ECC_NIST_P256 {
                    return Err(IdentityFailure::UnsupportedCurve);
                }
                if x.len() != size || y.len() != size {
                    return Err(IdentityFailure::Length);
                }
                let mut point = vec![4u8];
                point.extend_from_slice(x);
                point.extend_from_slice(y);
                p256::PublicKey::from_sec1_bytes(&point).map_err(|_| IdentityFailure::PointNotOnCurve)?;
                Ok(())
            }
        }
    }
    /// EKPUB-CANON-V1 bytes: `0x01 || u16_be(bits) || u32_be(e) || n` or `0x02 || u16_be(curve) || x || y`.
    pub fn encode(&self) -> std::result::Result<Vec<u8>, IdentityFailure> {
        self.validate()?;
        let mut out = Vec::new();
        match self {
            Self::Rsa { bits, exponent, modulus } => {
                out.push(RSA_TAG);
                out.extend_from_slice(&bits.to_be_bytes());
                out.extend_from_slice(&exponent.to_be_bytes());
                out.extend_from_slice(modulus);
            }
            Self::Ecc { curve, x, y } => {
                out.push(ECC_TAG);
                out.extend_from_slice(&curve.to_be_bytes());
                out.extend_from_slice(x);
                out.extend_from_slice(y);
            }
        }
        Ok(out)
    }
    /// Strict decoding: exactly one byte string per key; anything else is refused.
    pub fn decode(raw: &[u8]) -> std::result::Result<Self, IdentityFailure> {
        let (&tag, rest) = raw.split_first().ok_or(IdentityFailure::Length)?;
        let key = match tag {
            RSA_TAG => {
                if rest.len() < 6 {
                    return Err(IdentityFailure::Length);
                }
                let bits = u16::from_be_bytes([rest[0], rest[1]]);
                let exponent = u32::from_be_bytes([rest[2], rest[3], rest[4], rest[5]]);
                if !RSA_BITS.contains(&bits) {
                    return Err(IdentityFailure::RsaModulusSize);
                }
                if rest.len() != 6 + bits as usize / 8 {
                    return Err(IdentityFailure::Length);
                }
                Self::Rsa { bits, exponent, modulus: rest[6..].to_vec() }
            }
            ECC_TAG => {
                if rest.len() < 2 {
                    return Err(IdentityFailure::Length);
                }
                let curve = u16::from_be_bytes([rest[0], rest[1]]);
                let size = field_bytes(curve).ok_or(IdentityFailure::UnsupportedCurve)?;
                if rest.len() != 2 + 2 * size {
                    return Err(IdentityFailure::Length);
                }
                Self::Ecc { curve, x: rest[2..2 + size].to_vec(), y: rest[2 + size..].to_vec() }
            }
            _ => return Err(IdentityFailure::UnknownAlgorithm),
        };
        key.validate()?;
        if key.encode()? != raw {
            return Err(IdentityFailure::Length);
        }
        Ok(key)
    }
    /// The endorsement identity of this key on this network.
    pub fn identity(&self) -> std::result::Result<Hash, IdentityFailure> {
        Ok(ek_identity(&self.encode()?))
    }
}
/// `H(HARDWARE_ID_DOMAIN, u32_be(NETWORK_ID) || canonical)` over EKPUB-CANON-V1 bytes.
pub fn ek_identity(canonical: &[u8]) -> Hash {
    let mut body = NETWORK_ID.to_be_bytes().to_vec();
    body.extend_from_slice(canonical);
    domain_hash(HARDWARE_ID_DOMAIN, &body)
}

/// One committed identity class: the algorithm and size or curve of the endorsement key, and the SHA-256 of the frozen
/// template bytes of its TPM public area (every byte of the TPMT_PUBLIC before the key). Values are an Architect/evidence
/// input (design A4-Q1); none is built in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IdentityClass {
    pub algorithm: u8,
    pub size: u16,
    pub template_sha256: Hash,
}
/// The ordered, network-wide identity-class list. Class 1 is the primary class (`hardware`). Canonical CBOR
/// `[1, [[algorithm, size, template_sha256], ...]]`, 1..=4 classes, no class repeated; the ORDER is significant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityClasses {
    classes: Vec<IdentityClass>,
}
impl IdentityClasses {
    pub fn new(classes: Vec<IdentityClass>) -> std::result::Result<Self, IdentityFailure> {
        if classes.is_empty() || classes.len() > MAX_IDENTITY_CLASSES {
            return Err(IdentityFailure::ClassList);
        }
        let mut seen = std::collections::BTreeSet::new();
        for c in &classes {
            let valid = match c.algorithm {
                RSA_TAG => RSA_BITS.contains(&c.size),
                ECC_TAG => field_bytes(c.size).is_some(),
                _ => false,
            };
            if !valid || c.template_sha256 == [0; 32] || !seen.insert((c.algorithm, c.size, c.template_sha256)) {
                return Err(IdentityFailure::ClassList);
            }
        }
        Ok(Self { classes })
    }
    pub fn classes(&self) -> &[IdentityClass] {
        &self.classes
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(2).unwrap().u8(1).unwrap().array(self.classes.len() as u64).unwrap();
        for c in &self.classes {
            e.array(3).unwrap().u8(c.algorithm).unwrap().u16(c.size).unwrap().bytes(&c.template_sha256).unwrap();
        }
        e.into_writer()
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, 512)?;
        let mut d = minicbor::Decoder::new(raw);
        let parsed = (|| -> std::result::Result<Vec<IdentityClass>, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("identity classes");
            if d.array()? != Some(2) || d.u8()? != 1 {
                return Err(bad());
            }
            let n = d.array()?.ok_or_else(bad)?;
            if n == 0 || n > MAX_IDENTITY_CLASSES as u64 {
                return Err(bad());
            }
            let mut classes = Vec::new();
            for _ in 0..n {
                if d.array()? != Some(3) {
                    return Err(bad());
                }
                classes.push(IdentityClass {
                    algorithm: d.u8()?,
                    size: d.u16()?,
                    template_sha256: d.bytes()?.try_into().map_err(|_| bad())?,
                });
            }
            Ok(classes)
        })()
        .map_err(|_| Error::Codec)?;
        let list = Self::new(parsed).map_err(|_| Error::Codec)?;
        if d.position() != raw.len() || list.encode() != raw {
            return Err(Error::NonCanonical);
        }
        Ok(list)
    }
    /// The value Lane A1's Genesis record commits to.
    pub fn commitment(&self) -> Hash {
        domain_hash(IDENTITY_CLASSES_DOMAIN, &self.encode())
    }
}

/// An EK public area (TPM2B_PUBLIC) split into the SHA-256 of its template bytes and its canonical key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EkPublicArea {
    pub template_sha256: Hash,
    pub key: EkPublicKey,
}
struct Reader<'a> {
    raw: &'a [u8],
    pos: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> std::result::Result<&'a [u8], IdentityFailure> {
        let end = self.pos.checked_add(n).ok_or(IdentityFailure::PublicAreaMalformed)?;
        let v = self.raw.get(self.pos..end).ok_or(IdentityFailure::PublicAreaMalformed)?;
        self.pos = end;
        Ok(v)
    }
    fn u16(&mut self) -> std::result::Result<u16, IdentityFailure> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> std::result::Result<u32, IdentityFailure> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn blob(&mut self) -> std::result::Result<&'a [u8], IdentityFailure> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}
const TPM_ALG_RSA: u16 = 0x0001;
const TPM_ALG_ECC: u16 = 0x0023;
const TPM_ALG_NULL: u16 = 0x0010;
/// Parse a TPM2B_PUBLIC holding an RSA or ECC key (TPM 2.0 Part 2 marshalling: type, nameAlg, objectAttributes,
/// authPolicy, type-specific parameters, unique). The template is every TPMT_PUBLIC byte before `unique`; the caller
/// compares its SHA-256 with the committed class (`check_public_area`). A TPMT_PUBLIC `exponent` of 0 means 65537.
/// Bounded (`MAX_EK_PUBLIC_AREA`), no trailing bytes.
pub fn parse_ek_public_area(boxed: &[u8]) -> std::result::Result<EkPublicArea, IdentityFailure> {
    if boxed.len() > MAX_EK_PUBLIC_AREA {
        return Err(IdentityFailure::PublicAreaMalformed);
    }
    let mut outer = Reader { raw: boxed, pos: 0 };
    let inner = outer.blob()?;
    if outer.pos != boxed.len() {
        return Err(IdentityFailure::PublicAreaMalformed);
    }
    let mut r = Reader { raw: inner, pos: 0 };
    let kind = r.u16()?;
    r.u16()?; // nameAlg
    r.u32()?; // objectAttributes
    r.blob()?; // authPolicy
    let symmetric = r.u16()?;
    if symmetric != TPM_ALG_NULL {
        r.u16()?; // keyBits
        r.u16()?; // mode
    }
    let scheme = r.u16()?;
    if scheme != TPM_ALG_NULL {
        r.u16()?; // scheme hash
    }
    let (template_end, key) = match kind {
        TPM_ALG_RSA => {
            let bits = r.u16()?;
            let exponent = match r.u32()? {
                0 => 65537,
                e => e,
            };
            let template_end = r.pos;
            let modulus = r.blob()?.to_vec();
            (template_end, EkPublicKey::Rsa { bits, exponent, modulus })
        }
        TPM_ALG_ECC => {
            let curve = r.u16()?;
            let kdf = r.u16()?;
            if kdf != TPM_ALG_NULL {
                r.u16()?; // kdf hash
            }
            let template_end = r.pos;
            let x = r.blob()?.to_vec();
            let y = r.blob()?.to_vec();
            (template_end, EkPublicKey::Ecc { curve, x, y })
        }
        _ => return Err(IdentityFailure::UnknownAlgorithm),
    };
    if r.pos != inner.len() {
        return Err(IdentityFailure::PublicAreaMalformed);
    }
    key.validate()?;
    Ok(EkPublicArea { template_sha256: Sha256::digest(&inner[..template_end]).into(), key })
}
/// The public area matches the committed class: same template bytes, same algorithm and size or curve.
pub fn check_public_area(area: &EkPublicArea, class: &IdentityClass) -> std::result::Result<(), IdentityFailure> {
    if area.template_sha256 != class.template_sha256 {
        return Err(IdentityFailure::TemplateMismatch);
    }
    if area.key.class() != (class.algorithm, class.size) {
        return Err(IdentityFailure::ClassMismatch);
    }
    Ok(())
}

/// Every endorsement identity a profile commits to (a version-2 statement); none for a version-1 statement or none at all.
pub fn committed_identities(profile: &TpmProfile) -> Vec<Hash> {
    profile
        .provenance
        .as_ref()
        .and_then(|p| p.endorsement.as_ref())
        .map(|e| e.identities.iter().map(|(_, id)| *id).collect())
        .unwrap_or_default()
}
/// Rule M coverage against the identity-class list committed in V2 Genesis. This
/// checks one identity per class; class membership/order and EK authenticity need
/// `attestation_witness::verify_witness`, which is a separate verification boundary.
pub fn check_class_coverage(profile: &TpmProfile, classes: &IdentityClasses) -> Result<()> {
    let committed = profile.provenance.as_ref().and_then(|p| p.endorsement.as_ref()).map(|e| e.identities.len());
    if committed != Some(classes.classes().len()) {
        return Err(Error::UnqualifiedPhysical);
    }
    Ok(())
}

/// Duplicate-live-lineage rejection over EVERY committed identity (design A4 rule M): `incoming` is refused with
/// `Error::Duplicate` when any of its committed identities is committed by one of `others`.
pub fn reject_shared_identity<'a>(
    incoming: &TpmProfile,
    others: impl IntoIterator<Item = &'a TpmProfile>,
) -> Result<()> {
    let mine = committed_identities(incoming);
    if mine.is_empty() {
        return Ok(());
    }
    for other in others {
        if committed_identities(other).iter().any(|id| mine.contains(id)) {
            return Err(Error::Duplicate);
        }
    }
    Ok(())
}

/// Production-class committed-state backstop (every StateRoot, `execution.rs` `State::records`): no endorsement identity
/// is committed by two different lineages, over the V1 approved profiles of the registry's physical members and the
/// current V2 bindings; and no retired V2 binding shares an identity with the current binding of ANOTHER node. (The
/// current V2 bindings are also checked among themselves in every class by `continuity_keys_v2::Book::validate`.)
pub(crate) fn check_state(
    state: &crate::execution::State,
    class: crate::provenance::AdmissionClass,
) -> Result<()> {
    if class != crate::provenance::AdmissionClass::Production {
        return Ok(());
    }
    // Coverage is enforced on every current and retired V2 binding before an
    // accepted state can acquire a StateRoot or be reconstructed on replay.
    // Legacy V1 chains have no identity-class representation and keep their rule.
    let classes = state.protocol_records.get(&crate::genesis_v2::parameters_key())
        .map(|raw| crate::genesis_v2::Parameters::decode(raw).map(|p| p.identity_classes).map_err(|_| Error::Codec))
        .transpose()?;
    if let Some(classes) = &classes {
        for binding in state.continuity_keys_v2.bindings() {
            check_class_coverage(&TpmProfile::decode(&binding.admission().profile)?, classes)?;
        }
        for retired in state.retired_continuity_v2.entries() {
            check_class_coverage(&TpmProfile::decode(&retired.binding.admission.profile)?, classes)?;
        }
    }
    let mut owner: BTreeMap<Hash, Hash> = BTreeMap::new();
    let mut claim = |identity: Hash, lineage: Hash| -> Result<()> {
        match owner.insert(identity, lineage) {
            Some(previous) if previous != lineage => Err(Error::Duplicate),
            _ => Ok(()),
        }
    };
    if let Some(registry) = &state.continuity {
        for member in registry.members.iter().filter(|m| m.physical) {
            if let Some(approved) = state.admission.profiles.get(&member.attestation) {
                let profile = TpmProfile::decode(&approved.profile)?;
                if let Some(classes) = &classes {
                    check_class_coverage(&profile, classes)?;
                }
                for id in committed_identities(&profile) {
                    claim(id, member.lineage)?;
                }
            }
            if let Some(binding) = state.continuity_keys_v2.get(member.node) {
                let profile = TpmProfile::decode(&binding.admission().profile)?;
                for id in committed_identities(&profile) {
                    claim(id, member.lineage)?;
                }
            }
        }
    }
    // Retired identities indexed once (identity -> nodes that retired it): linear in records, not quadratic.
    let mut retired: BTreeMap<Hash, std::collections::BTreeSet<Hash>> = BTreeMap::new();
    for r in state.retired_continuity_v2.entries() {
        let old = TpmProfile::decode(&r.binding.admission.profile)?;
        for id in committed_identities(&old) {
            retired.entry(id).or_default().insert(r.binding.admission.node);
        }
    }
    if !retired.is_empty() {
        for binding in state.continuity_keys_v2.bindings() {
            let node = binding.admission().node;
            let current = TpmProfile::decode(&binding.admission().profile)?;
            for id in committed_identities(&current) {
                if retired.get(&id).is_some_and(|nodes| nodes.iter().any(|n| *n != node)) {
                    return Err(Error::Duplicate);
                }
            }
        }
    }
    Ok(())
}
