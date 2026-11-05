//! TEST-VALUE ENDORSEMENT MATERIAL - TEST VALUE ONLY (candidate 3, Order of 4 Oct 2026, decisions A1, A2, A4, A7, A11).
//!
//! A deterministic, labelled certificate SYNTAX for `ek_chain::CertificateSyntax`: canonical CBOR "certificates" and
//! "CRLs" with genuine P-256 ECDSA signatures (RFC 6979) from keys derived from public seed labels. It is NOT X.509, NOT
//! DER, and contains no manufacturer, EK or host material of any kind: it exists so that the consensus-side validation
//! procedure (anchors, linkage, validity at a committed time, CA constraints, EKU, names, critical extensions, revocation)
//! is exercised independently of any DER parser (the X.509 syntax has its own tests, `endorsement_x509.rs`, with
//! TEST-VALUE DER from `test_value_x509.rs`). `production()` is false, so every
//! Production-class verification refuses it (`ChainFailure::ParserUnavailable`). Compiled only into tests via `#[path]`.
#![allow(dead_code)]
use minicbor::{Decoder, Encoder, data::Type};
use mutiny_consensus_v8::{
    Hash,
    attestation_witness::{ActivationRecord, AttestationWitness, EndorsementEvidence},
    ek_chain::*,
    endorsement_identity::*,
};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer, signature::Verifier};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const CERT_TAG: &str = "MUTINY-BUILD8-TEST-VALUE-CERTIFICATE-V1";
pub const CRL_TAG: &str = "MUTINY-BUILD8-TEST-VALUE-CRL-V1";
pub const SEED_LABEL: &str = "MUTINY-BUILD8-TEST-VALUE-EK-PKI-V1";
/// Domain prefix of every TEST-VALUE signature (never the bytes of any real certificate).
pub const SIGNING_PREFIX: &[u8] = b"MUTINY-BUILD8-TEST-VALUE-SIGNED-V1\0";
/// The committed reference time of these tests (Unix seconds, 2027-01-15).
pub const T_REF: u64 = 1_800_000_000;
/// "No expiry" of TEST-VALUE EK certificates (9999-12-31T23:59:59Z, as some EK certificates use).
pub const NO_EXPIRY: u64 = 253_402_300_799;

fn sha256(b: &[u8]) -> Hash {
    Sha256::digest(b).into()
}
/// Deterministic P-256 key from `SEED_LABEL/<label>`.
pub fn key(label: &str) -> SigningKey {
    for counter in 0u8..=255 {
        let mut h = Sha256::new();
        h.update(format!("{SEED_LABEL}/{label}").as_bytes());
        h.update([counter]);
        let d: [u8; 32] = h.finalize().into();
        if let Ok(k) = SigningKey::from_bytes((&d).into()) {
            return k;
        }
    }
    unreachable!()
}
pub fn ecc_public(key: &SigningKey) -> EkPublicKey {
    let p = key.verifying_key().to_encoded_point(false);
    EkPublicKey::Ecc { curve: TPM_ECC_NIST_P256, x: p.x().unwrap().to_vec(), y: p.y().unwrap().to_vec() }
}
/// A TEST-VALUE "RSA" endorsement key: NOT an RSA key (no primes exist). A canonical-form modulus (top bit set, odd)
/// expanded from a public label; identity derivation never uses a key mathematically.
pub fn rsa_like_public(label: &str, bits: u16) -> EkPublicKey {
    let mut modulus = Vec::new();
    let mut counter = 0u32;
    while modulus.len() < bits as usize / 8 {
        let mut h = Sha256::new();
        h.update(format!("{SEED_LABEL}/rsa-modulus/{label}").as_bytes());
        h.update(counter.to_be_bytes());
        modulus.extend_from_slice(&h.finalize());
        counter += 1;
    }
    modulus.truncate(bits as usize / 8);
    modulus[0] |= 0x80;
    *modulus.last_mut().unwrap() |= 1;
    EkPublicKey::Rsa { bits, exponent: 65537, modulus }
}
/// Raw (NON-validating) EKPUB-CANON-V1-shaped bytes: lets a negative test carry a key the procedure must refuse.
fn raw_key(k: &EkPublicKey) -> Vec<u8> {
    let mut out = Vec::new();
    match k {
        EkPublicKey::Rsa { bits, exponent, modulus } => {
            out.push(RSA_TAG);
            out.extend(bits.to_be_bytes());
            out.extend(exponent.to_be_bytes());
            out.extend(modulus);
        }
        EkPublicKey::Ecc { curve, x, y } => {
            out.push(ECC_TAG);
            out.extend(curve.to_be_bytes());
            out.extend(x);
            out.extend(y);
        }
    }
    out
}
fn raw_key_decode(raw: &[u8]) -> Option<EkPublicKey> {
    let (&tag, rest) = raw.split_first()?;
    match tag {
        RSA_TAG if rest.len() >= 6 => Some(EkPublicKey::Rsa {
            bits: u16::from_be_bytes([rest[0], rest[1]]),
            exponent: u32::from_be_bytes([rest[2], rest[3], rest[4], rest[5]]),
            modulus: rest[6..].to_vec(),
        }),
        ECC_TAG if rest.len() >= 2 && (rest.len() - 2) % 2 == 0 => {
            let half = (rest.len() - 2) / 2;
            Some(EkPublicKey::Ecc {
                curve: u16::from_be_bytes([rest[0], rest[1]]),
                x: rest[2..2 + half].to_vec(),
                y: rest[2 + half..].to_vec(),
            })
        }
        _ => None,
    }
}
fn alg_code(a: SignatureAlgorithm) -> u8 {
    match a {
        SignatureAlgorithm::RsaPkcs1Sha256 => 1,
        SignatureAlgorithm::RsaPkcs1Sha384 => 2,
        SignatureAlgorithm::RsaPssSha256 => 3,
        SignatureAlgorithm::RsaPssSha384 => 4,
        SignatureAlgorithm::EcdsaP256Sha256 => 5,
        SignatureAlgorithm::EcdsaP384Sha384 => 6,
    }
}
fn alg_from(code: u8) -> Option<SignatureAlgorithm> {
    Some(match code {
        1 => SignatureAlgorithm::RsaPkcs1Sha256,
        2 => SignatureAlgorithm::RsaPkcs1Sha384,
        3 => SignatureAlgorithm::RsaPssSha256,
        4 => SignatureAlgorithm::RsaPssSha384,
        5 => SignatureAlgorithm::EcdsaP256Sha256,
        6 => SignatureAlgorithm::EcdsaP384Sha384,
        _ => return None,
    })
}
fn sign(signer: &SigningKey, tbs: &[u8]) -> Vec<u8> {
    let mut m = SIGNING_PREFIX.to_vec();
    m.extend_from_slice(tbs);
    let s: Signature = signer.sign(&m);
    s.to_bytes().to_vec()
}

/// Everything a TEST-VALUE certificate states (the fields of `ParsedCertificate` minus the signed bytes).
#[derive(Clone, Debug)]
pub struct CertSpec {
    pub version: u8,
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
    pub unrecognised_critical: Vec<Vec<u8>>,
}
fn opt_bytes(e: &mut Encoder<Vec<u8>>, v: &Option<Vec<u8>>) {
    match v {
        Some(b) => e.bytes(b).unwrap(),
        None => e.null().unwrap(),
    };
}
fn bytes_list(e: &mut Encoder<Vec<u8>>, v: &[Vec<u8>]) {
    e.array(v.len() as u64).unwrap();
    for b in v {
        e.bytes(b).unwrap();
    }
}
impl CertSpec {
    pub fn tbs(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(15).unwrap();
        e.u8(self.version).unwrap().bytes(&self.serial).unwrap().u8(alg_code(self.signature_algorithm)).unwrap();
        e.bytes(&self.issuer).unwrap().bytes(&self.subject).unwrap();
        e.u64(self.not_before).unwrap().u64(self.not_after).unwrap();
        e.bytes(&raw_key(&self.public_key)).unwrap();
        match &self.basic_constraints {
            Some(bc) => {
                e.array(3).unwrap().bool(bc.critical).unwrap().bool(bc.ca).unwrap();
                match bc.path_len {
                    Some(n) => e.u8(n).unwrap(),
                    None => e.null().unwrap(),
                };
            }
            None => {
                e.null().unwrap();
            }
        }
        match self.key_usage {
            Some(ku) => e.u16(ku).unwrap(),
            None => e.null().unwrap(),
        };
        match &self.extended_key_usage {
            Some(list) => bytes_list(&mut e, list),
            None => {
                e.null().unwrap();
            }
        }
        opt_bytes(&mut e, &self.subject_key_id);
        opt_bytes(&mut e, &self.authority_key_id);
        match &self.subject_alt_name {
            Some(san) => {
                e.array(3).unwrap().bool(san.critical).unwrap();
                e.array(san.directory_names.len() as u64).unwrap();
                for dn in &san.directory_names {
                    e.array(dn.len() as u64).unwrap();
                    for (oid, value) in dn {
                        e.array(2).unwrap().bytes(oid).unwrap().bytes(value).unwrap();
                    }
                }
                e.u32(san.other_forms).unwrap();
            }
            None => {
                e.null().unwrap();
            }
        }
        bytes_list(&mut e, &self.unrecognised_critical);
        e.into_writer()
    }
    /// The encoded TEST-VALUE certificate, signed by `issuer`.
    pub fn sign(&self, issuer: &SigningKey) -> Vec<u8> {
        let tbs = self.tbs();
        let signature = sign(issuer, &tbs);
        let mut e = Encoder::new(Vec::new());
        e.array(3).unwrap().str(CERT_TAG).unwrap().bytes(&tbs).unwrap().bytes(&signature).unwrap();
        e.into_writer()
    }
}
/// Everything a TEST-VALUE CRL states.
#[derive(Clone, Debug)]
pub struct CrlSpec {
    pub version: u8,
    pub signature_algorithm: SignatureAlgorithm,
    pub issuer: Vec<u8>,
    pub this_update: u64,
    pub next_update: Option<u64>,
    pub revoked_serials: Vec<Vec<u8>>,
    pub delta: bool,
    pub indirect: bool,
    pub partial: bool,
    pub unrecognised_critical: Vec<Vec<u8>>,
}
impl CrlSpec {
    pub fn tbs(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(10).unwrap();
        e.u8(self.version).unwrap().u8(alg_code(self.signature_algorithm)).unwrap().bytes(&self.issuer).unwrap();
        e.u64(self.this_update).unwrap();
        match self.next_update {
            Some(n) => e.u64(n).unwrap(),
            None => e.null().unwrap(),
        };
        bytes_list(&mut e, &self.revoked_serials);
        e.bool(self.delta).unwrap().bool(self.indirect).unwrap().bool(self.partial).unwrap();
        bytes_list(&mut e, &self.unrecognised_critical);
        e.into_writer()
    }
    pub fn sign(&self, issuer: &SigningKey) -> Vec<u8> {
        let tbs = self.tbs();
        let signature = sign(issuer, &tbs);
        let mut e = Encoder::new(Vec::new());
        e.array(3).unwrap().str(CRL_TAG).unwrap().bytes(&tbs).unwrap().bytes(&signature).unwrap();
        e.into_writer()
    }
}

/// The TEST-VALUE syntax. `production()` is false.
pub struct TestValueSyntax;
fn outer<'a>(raw: &'a [u8], tag: &str) -> Option<(&'a [u8], &'a [u8])> {
    let mut d = Decoder::new(raw);
    if d.array().ok()? != Some(3) || d.str().ok()? != tag {
        return None;
    }
    let tbs = d.bytes().ok()?;
    let sig = d.bytes().ok()?;
    if d.position() != raw.len() {
        return None;
    }
    Some((tbs, sig))
}
fn opt_u8(d: &mut Decoder<'_>) -> Option<Option<u8>> {
    if d.datatype().ok()? == Type::Null {
        d.null().ok()?;
        Some(None)
    } else {
        Some(Some(d.u8().ok()?))
    }
}
fn opt_bytes_dec(d: &mut Decoder<'_>) -> Option<Option<Vec<u8>>> {
    if d.datatype().ok()? == Type::Null {
        d.null().ok()?;
        Some(None)
    } else {
        Some(Some(d.bytes().ok()?.to_vec()))
    }
}
fn list_dec(d: &mut Decoder<'_>) -> Option<Vec<Vec<u8>>> {
    let n = d.array().ok()??;
    (0..n).map(|_| d.bytes().ok().map(<[u8]>::to_vec)).collect()
}
fn parse_cert_spec(tbs: &[u8]) -> Option<CertSpec> {
    let mut d = Decoder::new(tbs);
    if d.array().ok()? != Some(15) {
        return None;
    }
    let version = d.u8().ok()?;
    let serial = d.bytes().ok()?.to_vec();
    let signature_algorithm = alg_from(d.u8().ok()?)?;
    let issuer = d.bytes().ok()?.to_vec();
    let subject = d.bytes().ok()?.to_vec();
    let not_before = d.u64().ok()?;
    let not_after = d.u64().ok()?;
    let public_key = raw_key_decode(d.bytes().ok()?)?;
    let basic_constraints = if d.datatype().ok()? == Type::Null {
        d.null().ok()?;
        None
    } else {
        if d.array().ok()? != Some(3) {
            return None;
        }
        let critical = d.bool().ok()?;
        let ca = d.bool().ok()?;
        Some(BasicConstraints { critical, ca, path_len: opt_u8(&mut d)? })
    };
    let key_usage = if d.datatype().ok()? == Type::Null {
        d.null().ok()?;
        None
    } else {
        Some(d.u16().ok()?)
    };
    let extended_key_usage = if d.datatype().ok()? == Type::Null {
        d.null().ok()?;
        None
    } else {
        Some(list_dec(&mut d)?)
    };
    let subject_key_id = opt_bytes_dec(&mut d)?;
    let authority_key_id = opt_bytes_dec(&mut d)?;
    let subject_alt_name = if d.datatype().ok()? == Type::Null {
        d.null().ok()?;
        None
    } else {
        if d.array().ok()? != Some(3) {
            return None;
        }
        let critical = d.bool().ok()?;
        let n = d.array().ok()??;
        let mut directory_names = Vec::new();
        for _ in 0..n {
            let m = d.array().ok()??;
            let mut dn = Vec::new();
            for _ in 0..m {
                if d.array().ok()? != Some(2) {
                    return None;
                }
                dn.push((d.bytes().ok()?.to_vec(), d.bytes().ok()?.to_vec()));
            }
            directory_names.push(dn);
        }
        Some(SubjectAltName { critical, directory_names, other_forms: d.u32().ok()? })
    };
    let unrecognised_critical = list_dec(&mut d)?;
    if d.position() != tbs.len() {
        return None;
    }
    Some(CertSpec {
        version,
        serial,
        signature_algorithm,
        issuer,
        subject,
        not_before,
        not_after,
        public_key,
        basic_constraints,
        key_usage,
        extended_key_usage,
        subject_key_id,
        authority_key_id,
        subject_alt_name,
        unrecognised_critical,
    })
}
fn parse_crl_spec(tbs: &[u8]) -> Option<CrlSpec> {
    let mut d = Decoder::new(tbs);
    if d.array().ok()? != Some(10) {
        return None;
    }
    let version = d.u8().ok()?;
    let signature_algorithm = alg_from(d.u8().ok()?)?;
    let issuer = d.bytes().ok()?.to_vec();
    let this_update = d.u64().ok()?;
    let next_update = if d.datatype().ok()? == Type::Null {
        d.null().ok()?;
        None
    } else {
        Some(d.u64().ok()?)
    };
    let revoked_serials = list_dec(&mut d)?;
    let delta = d.bool().ok()?;
    let indirect = d.bool().ok()?;
    let partial = d.bool().ok()?;
    let unrecognised_critical = list_dec(&mut d)?;
    if d.position() != tbs.len() {
        return None;
    }
    Some(CrlSpec {
        version,
        signature_algorithm,
        issuer,
        this_update,
        next_update,
        revoked_serials,
        delta,
        indirect,
        partial,
        unrecognised_critical,
    })
}
impl CertificateSyntax for TestValueSyntax {
    fn production(&self) -> bool {
        false
    }
    fn parse_certificate(&self, raw: &[u8]) -> Result<ParsedCertificate, ChainFailure> {
        let (tbs, signature) = outer(raw, CERT_TAG).ok_or(ChainFailure::Malformed)?;
        let s = parse_cert_spec(tbs).ok_or(ChainFailure::Malformed)?;
        // Strict: the TEST-VALUE encoding is canonical (re-encoding equality), standing in for strict DER.
        if s.tbs() != tbs {
            return Err(ChainFailure::Malformed);
        }
        Ok(ParsedCertificate {
            version: s.version,
            serial: s.serial,
            signature_algorithm: s.signature_algorithm,
            issuer: s.issuer,
            subject: s.subject,
            not_before: s.not_before,
            not_after: s.not_after,
            public_key: s.public_key,
            basic_constraints: s.basic_constraints,
            key_usage: s.key_usage,
            extended_key_usage: s.extended_key_usage,
            subject_key_id: s.subject_key_id,
            authority_key_id: s.authority_key_id,
            subject_alt_name: s.subject_alt_name,
            unrecognised_critical: s.unrecognised_critical,
            tbs: tbs.to_vec(),
            signature: signature.to_vec(),
        })
    }
    fn parse_crl(&self, raw: &[u8]) -> Result<ParsedCrl, ChainFailure> {
        let (tbs, signature) = outer(raw, CRL_TAG).ok_or(ChainFailure::Malformed)?;
        let s = parse_crl_spec(tbs).ok_or(ChainFailure::Malformed)?;
        if s.tbs() != tbs {
            return Err(ChainFailure::Malformed);
        }
        Ok(ParsedCrl {
            version: s.version,
            signature_algorithm: s.signature_algorithm,
            issuer: s.issuer,
            this_update: s.this_update,
            next_update: s.next_update,
            revoked_serials: s.revoked_serials,
            delta: s.delta,
            indirect: s.indirect,
            partial: s.partial,
            unrecognised_critical: s.unrecognised_critical,
            tbs: tbs.to_vec(),
            signature: signature.to_vec(),
        })
    }
    /// Only TEST-VALUE ECDSA P-256 over `SIGNING_PREFIX || tbs`; every other algorithm or key is refused.
    fn verify_signature(&self, issuer_key: &EkPublicKey, algorithm: SignatureAlgorithm, tbs: &[u8], signature: &[u8]) -> bool {
        let EkPublicKey::Ecc { curve: TPM_ECC_NIST_P256, x, y } = issuer_key else {
            return false;
        };
        if algorithm != SignatureAlgorithm::EcdsaP256Sha256 || x.len() != 32 || y.len() != 32 {
            return false;
        }
        let mut point = vec![4u8];
        point.extend_from_slice(x);
        point.extend_from_slice(y);
        let (Ok(key), Ok(sig)) = (VerifyingKey::from_sec1_bytes(&point), Signature::from_slice(signature)) else {
            return false;
        };
        let mut m = SIGNING_PREFIX.to_vec();
        m.extend_from_slice(tbs);
        key.verify(&m, &sig).is_ok()
    }
}

/// A TEST-VALUE Name (stands for encoded Name bytes).
pub fn name(label: &str) -> Vec<u8> {
    format!("TEST-VALUE Name {label}").into_bytes()
}
pub fn key_id(k: &SigningKey) -> Vec<u8> {
    sha256(&raw_key(&ecc_public(k)))[..20].to_vec()
}
/// A CA certificate spec (critical cA=TRUE, keyCertSign and cRLSign) for `subject_key`, named `subject`, issued by
/// `issuer` (name) with key identifier of `issuer_key`.
pub fn ca_spec(subject: &str, subject_key: &SigningKey, issuer: &str, issuer_key: &SigningKey, serial: u8) -> CertSpec {
    CertSpec {
        version: 3,
        serial: vec![serial],
        signature_algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        issuer: name(issuer),
        subject: name(subject),
        not_before: 1_700_000_000,
        not_after: 2_000_000_000,
        public_key: ecc_public(subject_key),
        basic_constraints: Some(BasicConstraints { critical: true, ca: true, path_len: None }),
        key_usage: Some(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN),
        extended_key_usage: None,
        subject_key_id: Some(key_id(subject_key)),
        authority_key_id: Some(key_id(issuer_key)),
        subject_alt_name: None,
        unrecognised_critical: vec![],
    }
}
/// The TCG EK SAN form: one directoryName with manufacturer, model and version.
pub fn tcg_san() -> SubjectAltName {
    SubjectAltName {
        critical: true,
        directory_names: vec![vec![
            (oid::TCG_TPM_MANUFACTURER.to_vec(), b"id:54455354".to_vec()),
            (oid::TCG_TPM_MODEL.to_vec(), b"TEST-VALUE".to_vec()),
            (oid::TCG_TPM_VERSION.to_vec(), b"id:00010000".to_vec()),
        ]],
        other_forms: 0,
    }
}
/// The EK certificate spec for `ek`, issued by `issuer` (name and key).
pub fn ek_spec(ek: &EkPublicKey, issuer: &str, issuer_key: &SigningKey, serial: &[u8]) -> CertSpec {
    let usage = match ek {
        EkPublicKey::Rsa { .. } => key_usage::KEY_ENCIPHERMENT,
        EkPublicKey::Ecc { .. } => key_usage::KEY_AGREEMENT,
    };
    CertSpec {
        version: 3,
        serial: serial.to_vec(),
        signature_algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        issuer: name(issuer),
        subject: vec![],
        not_before: 1_750_000_000,
        not_after: NO_EXPIRY,
        public_key: ek.clone(),
        basic_constraints: Some(BasicConstraints { critical: true, ca: false, path_len: None }),
        key_usage: Some(usage),
        extended_key_usage: Some(vec![oid::TCG_KP_EK_CERTIFICATE.to_vec()]),
        subject_key_id: None,
        authority_key_id: Some(key_id(issuer_key)),
        subject_alt_name: Some(tcg_san()),
        unrecognised_critical: vec![],
    }
}
pub fn crl_spec(issuer: &str, revoked: &[&[u8]]) -> CrlSpec {
    CrlSpec {
        version: 2,
        signature_algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        issuer: name(issuer),
        this_update: 1_790_000_000,
        next_update: Some(1_810_000_000),
        revoked_serials: revoked.iter().map(|s| s.to_vec()).collect(),
        delta: false,
        indirect: false,
        partial: false,
        unrecognised_critical: vec![],
    }
}
/// A complete TEST-VALUE PKI: root (self-signed), one intermediate, and builders around them.
pub struct Pki {
    pub label: String,
    pub root_key: SigningKey,
    pub intermediate_key: SigningKey,
    pub root_spec: CertSpec,
    pub intermediate_spec: CertSpec,
}
impl Pki {
    pub fn new(label: &str) -> Self {
        let root_key = key(&format!("{label}/root"));
        let intermediate_key = key(&format!("{label}/intermediate"));
        let root_spec = ca_spec(&format!("{label} root"), &root_key, &format!("{label} root"), &root_key, 1);
        let intermediate_spec = ca_spec(&format!("{label} intermediate"), &intermediate_key, &format!("{label} root"), &root_key, 2);
        Self { label: label.to_string(), root_key, intermediate_key, root_spec, intermediate_spec }
    }
    pub fn root_name(&self) -> String {
        format!("{} root", self.label)
    }
    pub fn intermediate_name(&self) -> String {
        format!("{} intermediate", self.label)
    }
    pub fn root(&self) -> Vec<u8> {
        self.root_spec.sign(&self.root_key)
    }
    pub fn intermediate(&self) -> Vec<u8> {
        self.intermediate_spec.sign(&self.root_key)
    }
    pub fn root_hash(&self) -> Hash {
        sha256(&self.root())
    }
    pub fn ek_spec(&self, ek: &EkPublicKey, serial: &[u8]) -> CertSpec {
        ek_spec(ek, &self.intermediate_name(), &self.intermediate_key, serial)
    }
    /// [EK leaf, intermediate, root].
    pub fn chain(&self, ek: &EkPublicKey, serial: &[u8]) -> Vec<Vec<u8>> {
        vec![self.ek_spec(ek, serial).sign(&self.intermediate_key), self.intermediate(), self.root()]
    }
    /// The two CRLs of `chain` (intermediate's CRL for the leaf, root's CRL for the intermediate).
    pub fn crls(&self, revoked_by_intermediate: &[&[u8]], revoked_by_root: &[&[u8]]) -> Vec<Vec<u8>> {
        vec![
            crl_spec(&self.intermediate_name(), revoked_by_intermediate).sign(&self.intermediate_key),
            crl_spec(&self.root_name(), revoked_by_root).sign(&self.root_key),
        ]
    }
    pub fn anchor(&self, revocation: RevocationMode, classes: &[(u8, u16)]) -> TrustAnchor {
        TrustAnchor {
            root_cert_der_sha256: self.root_hash(),
            constraints: AnchorConstraints {
                max_intermediates: 1,
                signature_algorithms: BTreeSet::from([SignatureAlgorithm::EcdsaP256Sha256]),
                ek_classes: classes.iter().copied().collect(),
                revocation,
            },
        }
    }
}
pub const ECC_CLASS: (u8, u16) = (ECC_TAG, TPM_ECC_NIST_P256);
pub const RSA_CLASS: (u8, u16) = (RSA_TAG, 2048);

/// TEST-VALUE TPMT_PUBLIC template bytes (everything before `unique`) for an ECC P-256 or RSA-2048 endorsement key.
/// The attribute and policy values are labelled TEST-VALUE; they are not asserted to be any TCG template.
pub fn template(algorithm: u8, attributes: u32) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend((if algorithm == RSA_TAG { 0x0001u16 } else { 0x0023u16 }).to_be_bytes());
    b.extend(0x000bu16.to_be_bytes());
    b.extend(attributes.to_be_bytes());
    let policy = sha256(b"MUTINY-BUILD8-TEST-VALUE-EK-POLICY-V1");
    b.extend((policy.len() as u16).to_be_bytes());
    b.extend(policy);
    b.extend(0x0006u16.to_be_bytes()); // AES
    b.extend(128u16.to_be_bytes());
    b.extend(0x0043u16.to_be_bytes()); // CFB
    b.extend(0x0010u16.to_be_bytes()); // scheme NULL
    if algorithm == RSA_TAG {
        b.extend(2048u16.to_be_bytes());
        b.extend(0u32.to_be_bytes()); // exponent 0 = 65537
    } else {
        b.extend(TPM_ECC_NIST_P256.to_be_bytes());
        b.extend(0x0010u16.to_be_bytes()); // kdf NULL
    }
    b
}
pub const TEST_ATTRIBUTES: u32 = 0x0003_00b2;
fn blob(b: &[u8]) -> Vec<u8> {
    let mut out = (b.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(b);
    out
}
/// TPM2B_PUBLIC of `key` under `template_bytes`.
pub fn public_area(template_bytes: &[u8], key: &EkPublicKey) -> Vec<u8> {
    let mut inner = template_bytes.to_vec();
    match key {
        EkPublicKey::Rsa { modulus, .. } => inner.extend(blob(modulus)),
        EkPublicKey::Ecc { x, y, .. } => {
            inner.extend(blob(x));
            inner.extend(blob(y));
        }
    }
    blob(&inner)
}
pub fn class_of(algorithm: u8, attributes: u32) -> IdentityClass {
    let size = if algorithm == RSA_TAG { 2048 } else { TPM_ECC_NIST_P256 };
    IdentityClass { algorithm, size, template_sha256: sha256(&template(algorithm, attributes)) }
}
/// One endorsement of a witness: public area, standard chain and its two CRLs.
pub fn endorsement(pki: &Pki, ek: &EkPublicKey, serial: &[u8]) -> EndorsementEvidence {
    let algorithm = ek.class().0;
    EndorsementEvidence {
        ek_public_area: public_area(&template(algorithm, TEST_ATTRIBUTES), ek),
        certificates: pki.chain(ek, serial),
        crls: pki.crls(&[], &[]),
    }
}
/// The retained public part of a TEST-VALUE activation transcript (labels; no secret is ever kept).
pub fn activation(index: u8, ak_name: [u8; 34], label: &str) -> ActivationRecord {
    let l = |part: &str| sha256(format!("MUTINY-BUILD8-TEST-VALUE-ACTIVATION-V1/{label}/{part}").as_bytes());
    ActivationRecord {
        ek_index: index,
        ak_name,
        credential_blob_sha256: l("credential-blob"),
        encrypted_seed_sha256: l("encrypted-seed"),
        secret_commitment: l("secret-commitment"),
    }
}
pub fn witness(endorsements: Vec<EndorsementEvidence>, activation: Vec<ActivationRecord>) -> AttestationWitness {
    AttestationWitness { reference_time: T_REF, endorsements, activation }
}
