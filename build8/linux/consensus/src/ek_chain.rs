//! PROPOSED / UNFROZEN (Architect's Continuation Order of 4 Oct 2026, decisions A1, A2, A11; design
//! `qualification/candidate-3/A-ADMISSION-DESIGN-V1.md` sections 2, 3 and 10). The restricted EK-certificate
//! validation PROCEDURE over pre-parsed certificates and CRLs.
//!
//! The parser and the signature primitives sit behind `CertificateSyntax`: a hand-checked trait boundary, so that what is
//! committed, what is checked and every failure are complete here and independent of the parser. Implementations: the
//! reviewed X.509 DER syntax `X509Syntax` in `consensus/src/x509_syntax.rs` (A11 promotion and pinned
//! RSA/ECDSA dependency review: `CODEX-A11-PROMOTION-20261004.md`). Test support reexports that executable parser,
//! and a TEST-VALUE syntax under `consensus/tests/support/` (not X.509, never shipped). Available Genesis public
//! evidence calls this procedure; post-sealing Production enrollment remains disabled. A Production-class
//! verification with any syntax other than the reviewed one fails closed
//! (`ChainFailure::ParserUnavailable`).
//!
//! No network, no OS trust store, no clock: the reference time is an input taken from committed chain data (design
//! section 3), the anchors are committed hashes with committed constraints (Lane A1's root SET representation), and the
//! revocation evidence is committed bytes. What this does NOT establish: possession of the EK (a certificate is public;
//! only credential activation shows possession, design A3) or where the node executes (design A6).
use crate::{
    Hash,
    endorsement_identity::{ECC_TAG, EkPublicKey, IdentityFailure, RSA_TAG},
    provenance::AdmissionClass,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Largest committed certificate.
pub const MAX_CERTIFICATE_BYTES: usize = 4096;
/// Largest committed CRL.
pub const MAX_CRL_BYTES: usize = 32768;
/// Leaf plus anchor at least; leaf, at most three intermediates and the anchor at most.
pub const MIN_CHAIN: usize = 2;
pub const MAX_CHAIN: usize = 5;
/// At most one CRL per issued certificate of the longest chain.
pub const MAX_CRLS: usize = MAX_CHAIN - 1;
/// Upper bound of `AnchorConstraints::max_intermediates`.
pub const MAX_INTERMEDIATES: u8 = 3;
/// Longest serial number (RFC 5280: at most 20 octets).
pub const MAX_SERIAL_BYTES: usize = 20;

/// DER content octets of the object identifiers this procedure names.
pub mod oid {
    /// tcg-kp-EKCertificate, 2.23.133.8.1.
    pub const TCG_KP_EK_CERTIFICATE: &[u8] = &[0x67, 0x81, 0x05, 0x08, 0x01];
    /// anyExtendedKeyUsage, 2.5.29.37.0.
    pub const ANY_EXTENDED_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25, 0x00];
    /// tcg-at-tpmManufacturer, 2.23.133.2.1.
    pub const TCG_TPM_MANUFACTURER: &[u8] = &[0x67, 0x81, 0x05, 0x02, 0x01];
    /// tcg-at-tpmModel, 2.23.133.2.2.
    pub const TCG_TPM_MODEL: &[u8] = &[0x67, 0x81, 0x05, 0x02, 0x02];
    /// tcg-at-tpmVersion, 2.23.133.2.3.
    pub const TCG_TPM_VERSION: &[u8] = &[0x67, 0x81, 0x05, 0x02, 0x03];
}
/// X.509 KeyUsage bits (bit i of the BIT STRING as `1 << i`).
pub mod key_usage {
    pub const DIGITAL_SIGNATURE: u16 = 1 << 0;
    pub const KEY_ENCIPHERMENT: u16 = 1 << 2;
    pub const KEY_AGREEMENT: u16 = 1 << 4;
    pub const KEY_CERT_SIGN: u16 = 1 << 5;
    pub const CRL_SIGN: u16 = 1 << 6;
}

/// Signature algorithms of profile rule P6. Which of them an anchor allows is a committed constraint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SignatureAlgorithm {
    RsaPkcs1Sha256,
    RsaPkcs1Sha384,
    RsaPssSha256,
    RsaPssSha384,
    EcdsaP256Sha256,
    EcdsaP384Sha384,
}

/// basicConstraints as parsed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BasicConstraints {
    pub critical: bool,
    pub ca: bool,
    pub path_len: Option<u8>,
}
/// subjectAltName as parsed: the directoryName entries (each a list of (attribute OID, value bytes)) and the count of
/// every other GeneralName form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubjectAltName {
    pub critical: bool,
    pub directory_names: Vec<Vec<(Vec<u8>, Vec<u8>)>>,
    pub other_forms: u32,
}
/// What a strict certificate parser reports (P1-P3 are the parser's: strict encoding, version, serial form, and the
/// inner signature algorithm equal to the outer one). Names are the exact encoded Name bytes; an EMPTY `subject` means an
/// empty Name. Times are Unix seconds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedCertificate {
    pub version: u8,
    /// Big-endian magnitude of a positive serial number, no leading zero octet.
    pub serial: Vec<u8>,
    pub signature_algorithm: SignatureAlgorithm,
    pub issuer: Vec<u8>,
    pub subject: Vec<u8>,
    pub not_before: u64,
    pub not_after: u64,
    pub public_key: EkPublicKey,
    pub basic_constraints: Option<BasicConstraints>,
    pub key_usage: Option<u16>,
    pub extended_key_usage: Option<Vec<Vec<u8>>>,
    pub subject_key_id: Option<Vec<u8>>,
    pub authority_key_id: Option<Vec<u8>>,
    pub subject_alt_name: Option<SubjectAltName>,
    /// OIDs of critical extensions the parser does not recognise (P12 refuses any).
    pub unrecognised_critical: Vec<Vec<u8>>,
    /// The signed bytes and the signature, for `CertificateSyntax::verify_signature`.
    pub tbs: Vec<u8>,
    pub signature: Vec<u8>,
}
/// What a strict CRL parser reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedCrl {
    pub version: u8,
    pub signature_algorithm: SignatureAlgorithm,
    pub issuer: Vec<u8>,
    pub this_update: u64,
    pub next_update: Option<u64>,
    pub revoked_serials: Vec<Vec<u8>>,
    /// deltaCRLIndicator present.
    pub delta: bool,
    /// issuingDistributionPoint with indirectCRL.
    pub indirect: bool,
    /// issuingDistributionPoint with onlySomeReasons.
    pub partial: bool,
    pub unrecognised_critical: Vec<Vec<u8>>,
    pub tbs: Vec<u8>,
    pub signature: Vec<u8>,
}

/// The parser and signature primitives. The X.509 implementation is `X509Syntax` (strict DER with the reviewed crates),
/// test-only in `consensus/tests/support/x509_syntax.rs` until promoted (design section 10).
pub trait CertificateSyntax {
    /// True only for the reviewed production X.509 implementation. Production-class verification refuses every other.
    fn production(&self) -> bool;
    fn parse_certificate(&self, raw: &[u8]) -> Result<ParsedCertificate, ChainFailure>;
    fn parse_crl(&self, raw: &[u8]) -> Result<ParsedCrl, ChainFailure>;
    /// Verify `signature` over `tbs` with `issuer_key` under `algorithm`.
    fn verify_signature(
        &self,
        issuer_key: &EkPublicKey,
        algorithm: SignatureAlgorithm,
        tbs: &[u8],
        signature: &[u8],
    ) -> bool;
}

/// How revocation evidence is required below an anchor (a committed constraint).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationMode {
    /// Every certificate below the anchor needs a current CRL from its issuer.
    CrlRequired,
    /// The manufacturer publishes no EK CRL; supplied CRLs are still evaluated.
    NoCrlPublished,
}
/// The validation constraints of one anchor (design A1). Values are an Architect/evidence input; none is built in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorConstraints {
    pub max_intermediates: u8,
    pub signature_algorithms: BTreeSet<SignatureAlgorithm>,
    /// (algorithm tag, modulus bits or curve) of the EK classes this anchor may certify.
    pub ek_classes: BTreeSet<(u8, u16)>,
    pub revocation: RevocationMode,
}
/// One committed trust anchor: the SHA-256 of the exact root certificate bytes and its constraints. The REPRESENTATION
/// of the committed set is Lane A1's; this is the view the procedure consumes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustAnchor {
    pub root_cert_der_sha256: Hash,
    pub constraints: AnchorConstraints,
}
/// Committed inputs of one verification.
pub struct ChainContext<'a> {
    pub class: AdmissionClass,
    /// Unix seconds from committed chain data (design section 3), never a wall clock.
    pub reference_time: u64,
    pub anchors: &'a [TrustAnchor],
}
/// The result: the anchor hash, the canonical leaf key and the SHA-256 of every certificate of the path (leaf first).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEndorsement {
    pub anchor: Hash,
    pub leaf_key: EkPublicKey,
    pub path: Vec<Hash>,
}

/// Why a chain is refused (one variant per rule; tests assert these).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChainFailure {
    /// Production class without the reviewed production syntax: fail closed.
    ParserUnavailable,
    /// Fewer than 2 or more than 5 certificates, or a certificate repeated.
    ChainLength,
    /// A certificate, CRL or list exceeds its bound, or is empty.
    Oversize,
    /// Not strictly encoded, wrong version, or a malformed serial (P1-P3).
    Malformed,
    /// The last certificate's SHA-256 is not a committed anchor (P4).
    UntrustedRoot,
    /// More intermediates than the anchor allows (P4).
    PathTooLong,
    /// Issuer Name or key identifier linkage broken (P5).
    IssuerMismatch,
    /// A signature algorithm the anchor does not allow (P6).
    UnsupportedAlgorithm,
    /// A signature does not verify under the issuer's key (P6).
    BadSignature,
    /// The reference time precedes notBefore (P7).
    NotYetValid,
    /// The reference time follows notAfter (P7).
    Expired,
    /// An issuer is not a critical cA=TRUE certificate (P8).
    NotCa,
    /// An issuer's pathLenConstraint is exceeded (P8).
    PathLength,
    /// keyUsage missing or wrong for an issuer (keyCertSign) or the EK (P8, P9).
    KeyUsage,
    /// The EK certificate claims cA=TRUE (P9).
    LeafIsCa,
    /// The EK certificate lacks tcg-kp-EKCertificate or carries anyExtendedKeyUsage (P10).
    MissingEkEku,
    /// Subject or subjectAltName outside the TCG EK form (P11).
    NameForm,
    /// A critical extension the parser does not recognise (P12).
    UnsupportedCriticalExtension,
    /// The EK key fails the canonical key rules (P13).
    UnsupportedKey(IdentityFailure),
    /// The EK key's class is not one this anchor certifies (P13).
    ClassNotAllowed,
    /// `CrlRequired` and no CRL from a certificate's issuer (P14).
    RevocationMissing,
    /// A supplied CRL matches no issuer of the chain (P14: no unused material in a witness).
    RevocationUnused,
    /// thisUpdate after, or nextUpdate before, the reference time (P14).
    StaleRevocation,
    /// The CRL is not signed by the certificate's issuer, or the issuer may not sign CRLs (P14).
    RevocationIssuer,
    /// A delta, indirect or partial CRL, a wrong version, two CRLs for one issuer, or an unrecognised critical CRL
    /// extension (P14).
    RevocationUnsupported,
    /// The certificate's serial is listed (P14).
    Revoked,
}

fn sha256(raw: &[u8]) -> Hash {
    Sha256::digest(raw).into()
}
fn serial_ok(serial: &[u8]) -> bool {
    !serial.is_empty()
        && serial.len() <= MAX_SERIAL_BYTES
        && serial[0] != 0
}

/// THE validation procedure P4-P15 (design section 3) over committed bytes. `chain` is leaf first, anchor last; `crls`
/// is the revocation evidence of this chain. Deterministic: the result depends only on its inputs.
pub fn validate_endorsement_chain(
    syntax: &dyn CertificateSyntax,
    chain: &[Vec<u8>],
    crls: &[Vec<u8>],
    ctx: &ChainContext<'_>,
) -> Result<VerifiedEndorsement, ChainFailure> {
    use ChainFailure as F;
    if ctx.class == AdmissionClass::Production && !syntax.production() {
        return Err(F::ParserUnavailable);
    }
    if chain.len() < MIN_CHAIN || chain.len() > MAX_CHAIN {
        return Err(F::ChainLength);
    }
    if chain.iter().any(|c| c.is_empty() || c.len() > MAX_CERTIFICATE_BYTES)
        || crls.len() > MAX_CRLS
        || crls.iter().any(|c| c.is_empty() || c.len() > MAX_CRL_BYTES)
    {
        return Err(F::Oversize);
    }
    let path: Vec<Hash> = chain.iter().map(|c| sha256(c)).collect();
    if path.iter().collect::<BTreeSet<_>>().len() != path.len() {
        return Err(F::ChainLength);
    }
    let certs = chain
        .iter()
        .map(|c| syntax.parse_certificate(c))
        .collect::<Result<Vec<_>, _>>()?;
    if certs.iter().any(|c| c.version != 3 || !serial_ok(&c.serial)) {
        return Err(F::Malformed);
    }
    // P4: the anchor is the committed hash of the last certificate's exact bytes.
    let anchor_hash = *path.last().ok_or(F::ChainLength)?;
    let anchor = ctx
        .anchors
        .iter()
        .find(|a| a.root_cert_der_sha256 == anchor_hash)
        .ok_or(F::UntrustedRoot)?;
    let k = &anchor.constraints;
    if k.max_intermediates > MAX_INTERMEDIATES || chain.len() - 2 > usize::from(k.max_intermediates) {
        return Err(F::PathTooLong);
    }
    // P12 on every certificate, the anchor included.
    if certs.iter().any(|c| !c.unrecognised_critical.is_empty()) {
        return Err(F::UnsupportedCriticalExtension);
    }
    // P5-P8 over every (issued, issuer) pair.
    for i in 0..certs.len() - 1 {
        let (child, parent) = (&certs[i], &certs[i + 1]);
        if child.issuer != parent.subject {
            return Err(F::IssuerMismatch);
        }
        if let (Some(aki), Some(ski)) = (&child.authority_key_id, &parent.subject_key_id) {
            if aki != ski {
                return Err(F::IssuerMismatch);
            }
        }
        if !k.signature_algorithms.contains(&child.signature_algorithm) {
            return Err(F::UnsupportedAlgorithm);
        }
        if !syntax.verify_signature(&parent.public_key, child.signature_algorithm, &child.tbs, &child.signature) {
            return Err(F::BadSignature);
        }
        if ctx.reference_time < child.not_before {
            return Err(F::NotYetValid);
        }
        if ctx.reference_time > child.not_after {
            return Err(F::Expired);
        }
        let constraints = match &parent.basic_constraints {
            Some(bc) if bc.critical && bc.ca => bc,
            _ => return Err(F::NotCa),
        };
        // The intermediates below `parent` (the leaf excluded) are certs[1..=i]: i of them.
        if constraints.path_len.is_some_and(|limit| i > usize::from(limit)) {
            return Err(F::PathLength);
        }
        if parent.key_usage.is_none_or(|ku| ku & key_usage::KEY_CERT_SIGN == 0) {
            return Err(F::KeyUsage);
        }
    }
    // P9-P13 on the EK certificate.
    let leaf = &certs[0];
    if leaf.basic_constraints.as_ref().is_some_and(|bc| bc.ca) {
        return Err(F::LeafIsCa);
    }
    let needed = match leaf.public_key.class().0 {
        RSA_TAG => key_usage::KEY_ENCIPHERMENT,
        ECC_TAG => key_usage::KEY_AGREEMENT,
        _ => return Err(F::UnsupportedKey(IdentityFailure::UnknownAlgorithm)),
    };
    match leaf.key_usage {
        Some(ku) if ku & needed != 0 && ku & (key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN) == 0 => {}
        _ => return Err(F::KeyUsage),
    }
    match &leaf.extended_key_usage {
        Some(ekus)
            if ekus.iter().any(|o| o == oid::TCG_KP_EK_CERTIFICATE)
                && !ekus.iter().any(|o| o == oid::ANY_EXTENDED_KEY_USAGE) => {}
        _ => return Err(F::MissingEkEku),
    }
    check_names(leaf)?;
    leaf.public_key.validate().map_err(F::UnsupportedKey)?;
    if !k.ek_classes.contains(&leaf.public_key.class()) {
        return Err(F::ClassNotAllowed);
    }
    // P14: revocation evidence.
    let parsed = crls
        .iter()
        .map(|c| syntax.parse_crl(c))
        .collect::<Result<Vec<_>, _>>()?;
    let mut used = vec![false; parsed.len()];
    for i in 0..certs.len() - 1 {
        let (cert, issuer) = (&certs[i], &certs[i + 1]);
        let mut matching = parsed.iter().enumerate().filter(|(_, c)| c.issuer == cert.issuer);
        let Some((j, crl)) = matching.next() else {
            if k.revocation == RevocationMode::CrlRequired {
                return Err(F::RevocationMissing);
            }
            continue;
        };
        if matching.next().is_some()
            || crl.version != 2
            || crl.delta
            || crl.indirect
            || crl.partial
            || !crl.unrecognised_critical.is_empty()
        {
            return Err(F::RevocationUnsupported);
        }
        used[j] = true;
        if !k.signature_algorithms.contains(&crl.signature_algorithm) {
            return Err(F::UnsupportedAlgorithm);
        }
        if issuer.key_usage.is_none_or(|ku| ku & key_usage::CRL_SIGN == 0)
            || !syntax.verify_signature(&issuer.public_key, crl.signature_algorithm, &crl.tbs, &crl.signature)
        {
            return Err(F::RevocationIssuer);
        }
        if crl.this_update > ctx.reference_time
            || crl.next_update.is_some_and(|next| ctx.reference_time > next)
        {
            return Err(F::StaleRevocation);
        }
        if crl.revoked_serials.iter().any(|s| *s == cert.serial) {
            return Err(F::Revoked);
        }
    }
    if used.iter().any(|u| !u) {
        return Err(F::RevocationUnused);
    }
    Ok(VerifiedEndorsement {
        anchor: anchor_hash,
        leaf_key: leaf.public_key.clone(),
        path,
    })
}
/// P11: an empty subject requires a critical subjectAltName; a subjectAltName holds exactly one directoryName carrying
/// exactly the TCG manufacturer, model and version attributes (each once, non-empty, bounded) and no other form. Names
/// never enter an identity (design A4).
fn check_names(leaf: &ParsedCertificate) -> Result<(), ChainFailure> {
    match &leaf.subject_alt_name {
        None if leaf.subject.is_empty() => Err(ChainFailure::NameForm),
        None => Ok(()),
        Some(san) => {
            if (leaf.subject.is_empty() && !san.critical) || san.other_forms != 0 || san.directory_names.len() != 1 {
                return Err(ChainFailure::NameForm);
            }
            let attributes = &san.directory_names[0];
            let wanted = [oid::TCG_TPM_MANUFACTURER, oid::TCG_TPM_MODEL, oid::TCG_TPM_VERSION];
            if attributes.len() != wanted.len()
                || wanted.iter().any(|w| attributes.iter().filter(|(o, _)| o == w).count() != 1)
                || attributes.iter().any(|(_, v)| v.is_empty() || v.len() > 64)
            {
                return Err(ChainFailure::NameForm);
            }
            Ok(())
        }
    }
}
