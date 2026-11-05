//! TEST-VALUE X.509 DER ENDORSEMENT MATERIAL - TEST VALUE ONLY (candidate 3, Order of 4 Oct 2026, decisions A1, A2, A11).
//!
//! Deterministic DER certificates and CRLs for `x509_syntax::X509Syntax`: a P-384 root, a P-256 intermediate and EK
//! leaves, every key derived from a PUBLIC seed label and every signature RFC 6979 (deterministic). Names, serials and
//! TCG attribute values are labelled TEST-VALUE. Nothing here is manufacturer, EK or host material; the root is not any
//! real CA. `TbsParts` assembles a signed part from separately encoded fields so that a negative test can carry a
//! non-canonical form the struct encoder would never produce. Compiled only into tests via `#[path]`.
#![allow(dead_code)]
use mutiny_consensus_v8::{
    Hash,
    ek_chain::{AnchorConstraints, RevocationMode, SignatureAlgorithm, TrustAnchor},
    endorsement_identity::*,
};
use crate::x509_syntax::oids;
use sha2::{Digest, Sha256, Sha384};
use std::{collections::BTreeSet, time::Duration};
use x509_cert::{
    TbsCertificate, Version,
    attr::AttributeTypeAndValue,
    crl::{RevokedCert, TbsCertList},
    der::{
        Any, Decode, Encode, Tag,
        asn1::{BitString, GeneralizedTime, ObjectIdentifier, OctetString, Uint, UtcTime},
    },
    ext::{
        Extension,
        pkix::{
            AuthorityKeyIdentifier, BasicConstraints, CrlNumber, ExtendedKeyUsage, KeyUsage, KeyUsages, SubjectAltName,
            SubjectKeyIdentifier, name::GeneralName,
        },
    },
    name::{Name, RdnSequence, RelativeDistinguishedName},
    serial_number::SerialNumber,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    time::{Time, Validity},
};

pub const X509_SEED_LABEL: &str = "MUTINY-BUILD8-TEST-VALUE-X509-EK-PKI-V1";
/// The committed reference time of these tests (Unix seconds, 2027-01-15), as in `test_value_ek`.
pub const T_REF: u64 = 1_800_000_000;
/// 2025-01-01T00:00:00Z, 2045-01-01T00:00:00Z, 9999-12-31T23:59:59Z.
pub const CA_NOT_BEFORE: u64 = 1_735_689_600;
pub const CA_NOT_AFTER: u64 = 2_366_841_600;
pub const NO_EXPIRY: u64 = 253_402_300_799;
/// First second that RFC 5280 encodes as GeneralizedTime (2050-01-01T00:00:00Z).
pub const GENERALIZED_FROM: u64 = 2_524_608_000;
pub const TCG_MANUFACTURER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.2.1");
pub const TCG_MODEL: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.2.2");
pub const TCG_VERSION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.2.3");
pub const TCG_KP_EK_CERTIFICATE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.8.1");
pub const SUBJECT_DIRECTORY_ATTRIBUTES: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.9");
pub const CERTIFICATE_POLICIES: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.32");
pub const COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
pub const ORGANIZATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");

pub fn sha256(b: &[u8]) -> Hash {
    Sha256::digest(b).into()
}

// ---- minimal DER writer (for hand-assembled negative cases) ----
pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let n = content.len();
    if n < 0x80 {
        out.push(n as u8);
    } else if n <= 0xff {
        out.extend([0x81, n as u8]);
    } else {
        out.extend([0x82, (n >> 8) as u8, n as u8]);
    }
    out.extend_from_slice(content);
    out
}
/// DER INTEGER of a big-endian magnitude.
pub fn der_uint(magnitude: &[u8]) -> Vec<u8> {
    let mut m = magnitude;
    while m.len() > 1 && m[0] == 0 {
        m = &m[1..];
    }
    let mut content = Vec::new();
    if m.is_empty() || m[0] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(m);
    tlv(0x02, &content)
}
pub fn ecdsa_der(r: &[u8], s: &[u8]) -> Vec<u8> {
    tlv(0x30, &[der_uint(r), der_uint(s)].concat())
}
fn sec1(x: &[u8], y: &[u8]) -> Vec<u8> {
    [&[0x04u8][..], x, y].concat()
}

// ---- keys (public seed labels) ----
pub fn p256_key(label: &str) -> p256::ecdsa::SigningKey {
    for counter in 0u8..=255 {
        let mut h = Sha256::new();
        h.update(format!("{X509_SEED_LABEL}/{label}").as_bytes());
        h.update([counter]);
        if let Ok(k) = p256::ecdsa::SigningKey::from_bytes(&h.finalize()) {
            return k;
        }
    }
    unreachable!()
}
pub fn p384_key(label: &str) -> p384::ecdsa::SigningKey {
    for counter in 0u8..=255 {
        let mut h = Sha384::new();
        h.update(format!("{X509_SEED_LABEL}/{label}").as_bytes());
        h.update([counter]);
        if let Ok(k) = p384::ecdsa::SigningKey::from_bytes(&h.finalize()) {
            return k;
        }
    }
    unreachable!()
}
/// A TEST-VALUE CA key.
pub enum CaKey {
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    Rsa { key: rsa::RsaPrivateKey, algorithm: SignatureAlgorithm },
}
pub fn ecdsa_sha256() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned { oid: oids::ECDSA_WITH_SHA256, parameters: None }
}
pub fn ecdsa_sha384() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned { oid: oids::ECDSA_WITH_SHA384, parameters: None }
}
impl CaKey {
    pub fn public(&self) -> EkPublicKey {
        match self {
            CaKey::P256(k) => {
                let p = k.verifying_key().to_encoded_point(false);
                EkPublicKey::Ecc { curve: TPM_ECC_NIST_P256, x: p.x().unwrap().to_vec(), y: p.y().unwrap().to_vec() }
            }
            CaKey::P384(k) => {
                let p = k.verifying_key().to_encoded_point(false);
                EkPublicKey::Ecc { curve: TPM_ECC_NIST_P384, x: p.x().unwrap().to_vec(), y: p.y().unwrap().to_vec() }
            }
            CaKey::Rsa { key, .. } => {
                use rsa::traits::PublicKeyParts;
                EkPublicKey::Rsa { bits: key.n().bits() as u16, exponent: 65537, modulus: key.n().to_bytes_be() }
            }
        }
    }
    /// The algorithm this key signs with (key and hash paired).
    pub fn algorithm(&self) -> AlgorithmIdentifierOwned {
        match self {
            CaKey::P256(_) => ecdsa_sha256(),
            CaKey::P384(_) => ecdsa_sha384(),
            CaKey::Rsa { algorithm, .. } => rsa_algorithm(*algorithm),
        }
    }
    /// DER ECDSA-Sig-Value over `message` (RFC 6979).
    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        match self {
            CaKey::P256(k) => {
                let s: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(k, message);
                let (r, s) = s.split_bytes();
                ecdsa_der(&r, &s)
            }
            CaKey::P384(k) => {
                let s: p384::ecdsa::Signature = p384::ecdsa::signature::Signer::sign(k, message);
                let (r, s) = s.split_bytes();
                ecdsa_der(&r, &s)
            }
            CaKey::Rsa { key, algorithm } => {
                let mut rng = PublicTestRng(0);
                match algorithm {
                    SignatureAlgorithm::RsaPkcs1Sha256 => key.sign(rsa::Pkcs1v15Sign::new::<Sha256>(), &Sha256::digest(message)).unwrap(),
                    SignatureAlgorithm::RsaPkcs1Sha384 => key.sign(rsa::Pkcs1v15Sign::new::<Sha384>(), &Sha384::digest(message)).unwrap(),
                    SignatureAlgorithm::RsaPssSha256 => key.sign_with_rng(&mut rng, rsa::Pss::new_with_salt::<Sha256>(32), &Sha256::digest(message)).unwrap(),
                    SignatureAlgorithm::RsaPssSha384 => key.sign_with_rng(&mut rng, rsa::Pss::new_with_salt::<Sha384>(48), &Sha384::digest(message)).unwrap(),
                    _ => panic!("not a TEST-VALUE RSA algorithm"),
                }
            }
        }
    }
    pub fn key_id(&self) -> Vec<u8> {
        match self.public() {
            EkPublicKey::Ecc { x, y, .. } => sha256(&sec1(&x, &y))[..20].to_vec(),
            EkPublicKey::Rsa { modulus, .. } => sha256(&modulus)[..20].to_vec(),
        }
    }
}

// ---- encoders ----
pub fn time(t: u64) -> Time {
    if t < GENERALIZED_FROM {
        Time::UtcTime(UtcTime::from_unix_duration(Duration::from_secs(t)).unwrap())
    } else {
        Time::GeneralTime(GeneralizedTime::from_unix_duration(Duration::from_secs(t)).unwrap())
    }
}
pub fn generalized(t: u64) -> Time {
    Time::GeneralTime(GeneralizedTime::from_unix_duration(Duration::from_secs(t)).unwrap())
}
pub fn atv(oid: ObjectIdentifier, tag: Tag, value: &str) -> AttributeTypeAndValue {
    AttributeTypeAndValue { oid, value: Any::new(tag, value.as_bytes()).unwrap() }
}
/// `O=Mutiny TEST-VALUE, CN=<cn>` as two single-valued RDNs.
pub fn name(cn: &str) -> Name {
    RdnSequence(vec![
        RelativeDistinguishedName::try_from(vec![atv(ORGANIZATION, Tag::Utf8String, "Mutiny TEST-VALUE")]).unwrap(),
        RelativeDistinguishedName::try_from(vec![atv(COMMON_NAME, Tag::Utf8String, cn)]).unwrap(),
    ])
}
/// The TCG directoryName of an EK subjectAltName: one RDN with manufacturer, model and version (TEST-VALUE values).
pub fn tcg_attributes(manufacturer_tag: Tag) -> Vec<AttributeTypeAndValue> {
    vec![
        atv(TCG_MANUFACTURER, manufacturer_tag, "id:54455354"),
        atv(TCG_MODEL, Tag::Utf8String, "TEST-VALUE-MODEL"),
        atv(TCG_VERSION, Tag::Utf8String, "id:00010002"),
    ]
}
pub fn tcg_name(manufacturer_tag: Tag) -> Name {
    RdnSequence(vec![RelativeDistinguishedName::try_from(tcg_attributes(manufacturer_tag)).unwrap()])
}
pub fn curve_oid(curve: u16) -> ObjectIdentifier {
    match curve {
        TPM_ECC_NIST_P256 => oids::SECP256R1,
        TPM_ECC_NIST_P384 => oids::SECP384R1,
        _ => oids::SECP521R1,
    }
}
pub fn ec_spki(curve: ObjectIdentifier, point: &[u8]) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: oids::EC_PUBLIC_KEY,
            parameters: Some(Any::new(Tag::ObjectIdentifier, curve.as_bytes()).unwrap()),
        },
        subject_public_key: BitString::from_bytes(point).unwrap(),
    }
}
pub fn rsa_spki(modulus: &[u8], exponent: &[u8]) -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned { oid: oids::RSA_ENCRYPTION, parameters: Some(Any::null()) },
        subject_public_key: BitString::from_bytes(&tlv(0x30, &[der_uint(modulus), der_uint(exponent)].concat())).unwrap(),
    }
}
pub fn spki(key: &EkPublicKey) -> SubjectPublicKeyInfoOwned {
    match key {
        EkPublicKey::Ecc { curve, x, y } => ec_spki(curve_oid(*curve), &sec1(x, y)),
        EkPublicKey::Rsa { exponent, modulus, .. } => rsa_spki(modulus, &exponent.to_be_bytes()),
    }
}
pub fn ext<T: Encode>(oid: ObjectIdentifier, critical: bool, value: &T) -> Extension {
    raw_ext(oid, critical, value.to_der().unwrap())
}
pub fn raw_ext(oid: ObjectIdentifier, critical: bool, value: Vec<u8>) -> Extension {
    Extension { extn_id: oid, critical, extn_value: OctetString::new(value).unwrap() }
}
pub fn key_usage(flags: impl Into<x509_cert::der::flagset::FlagSet<KeyUsages>>) -> KeyUsage {
    KeyUsage(flags.into())
}
/// Sign the DER `tbs` and assemble `SEQUENCE { tbs, outer algorithm, BIT STRING signature }` (certificate or CRL).
pub fn assemble(tbs: &[u8], outer: &[u8], signature: &[u8]) -> Vec<u8> {
    tlv(0x30, &[tbs.to_vec(), outer.to_vec(), tlv(0x03, &[&[0u8][..], signature].concat())].concat())
}

/// A signed part assembled from separately encoded fields (the struct encoder's output by default).
#[derive(Clone)]
pub struct TbsParts {
    pub version: Vec<u8>,
    pub serial: Vec<u8>,
    pub signature: Vec<u8>,
    pub issuer: Vec<u8>,
    pub validity: Vec<u8>,
    pub subject: Vec<u8>,
    pub spki: Vec<u8>,
    pub unique_ids: Vec<u8>,
    pub extensions: Option<Vec<Vec<u8>>>,
}
impl TbsParts {
    pub fn of(t: &TbsCertificate) -> Self {
        TbsParts {
            version: tlv(0xA0, &t.version.to_der().unwrap()),
            serial: t.serial_number.to_der().unwrap(),
            signature: t.signature.to_der().unwrap(),
            issuer: t.issuer.to_der().unwrap(),
            validity: t.validity.to_der().unwrap(),
            subject: t.subject.to_der().unwrap(),
            spki: t.subject_public_key_info.to_der().unwrap(),
            unique_ids: Vec::new(),
            extensions: t.extensions.as_ref().map(|l| l.iter().map(|e| e.to_der().unwrap()).collect()),
        }
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut body = [
            &self.version[..],
            &self.serial,
            &self.signature,
            &self.issuer,
            &self.validity,
            &self.subject,
            &self.spki,
            &self.unique_ids,
        ]
        .concat();
        if let Some(list) = &self.extensions {
            body.extend(tlv(0xA3, &tlv(0x30, &list.concat())));
        }
        tlv(0x30, &body)
    }
}

/// The TEST-VALUE PKI: a P-384 root (self-signed, ecdsa-with-SHA384), a P-256 intermediate (pathLen 0) signed by the
/// root, and EK leaves signed by the intermediate (ecdsa-with-SHA256).
pub struct X509Pki {
    pub label: String,
    pub root_key: CaKey,
    pub intermediate_key: CaKey,
    pub root: Vec<u8>,
    pub intermediate: Vec<u8>,
}
pub fn ca_extensions(subject: &CaKey, issuer: Option<&CaKey>, path_len: Option<u8>) -> Vec<Extension> {
    let mut list = vec![
        ext(oids::BASIC_CONSTRAINTS, true, &BasicConstraints { ca: true, path_len_constraint: path_len }),
        ext(oids::KEY_USAGE, true, &key_usage(KeyUsages::KeyCertSign | KeyUsages::CRLSign)),
        ext(oids::SUBJECT_KEY_IDENTIFIER, false, &SubjectKeyIdentifier(OctetString::new(subject.key_id()).unwrap())),
    ];
    if let Some(issuer) = issuer {
        list.push(ext(
            oids::AUTHORITY_KEY_IDENTIFIER,
            false,
            &AuthorityKeyIdentifier { key_identifier: Some(OctetString::new(issuer.key_id()).unwrap()), ..Default::default() },
        ));
    }
    list
}
impl X509Pki {
    pub fn new(label: &str) -> Self {
        let root_key = CaKey::P384(p384_key(&format!("{label}/root")));
        let intermediate_key = CaKey::P256(p256_key(&format!("{label}/intermediate")));
        Self::with_ca_keys(label, root_key, intermediate_key)
    }
    pub fn with_ca_keys(label: &str, root_key: CaKey, intermediate_key: CaKey) -> Self {
        let root_name = name(&format!("TEST-VALUE {label} EK Root CA"));
        let root_tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[0x01]).unwrap(),
            signature: root_key.algorithm(),
            issuer: root_name.clone(),
            validity: Validity { not_before: time(CA_NOT_BEFORE), not_after: time(CA_NOT_AFTER) },
            subject: root_name,
            subject_public_key_info: spki(&root_key.public()),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(ca_extensions(&root_key, None, None)),
        };
        let root = sign_tbs(&root_tbs, &root_key);
        let mut pki = X509Pki { label: label.to_string(), root_key, intermediate_key, root, intermediate: Vec::new() };
        let intermediate_tbs = pki.intermediate_tbs();
        pki.intermediate = sign_tbs(&intermediate_tbs, &pki.root_key);
        pki
    }
    pub fn root_name(&self) -> Name {
        name(&format!("TEST-VALUE {} EK Root CA", self.label))
    }
    pub fn intermediate_name(&self) -> Name {
        name(&format!("TEST-VALUE {} EK Intermediate CA", self.label))
    }
    pub fn root_hash(&self) -> Hash {
        sha256(&self.root)
    }
    /// The intermediate's signed part (re-signable by the root after an edit).
    pub fn intermediate_tbs(&self) -> TbsCertificate {
        TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[0x02]).unwrap(),
            signature: self.root_key.algorithm(),
            issuer: self.root_name(),
            validity: Validity { not_before: time(CA_NOT_BEFORE), not_after: time(CA_NOT_AFTER) },
            subject: self.intermediate_name(),
            subject_public_key_info: spki(&self.intermediate_key.public()),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(ca_extensions(&self.intermediate_key, Some(&self.root_key), Some(0))),
        }
    }
    /// The standard EK leaf's signed part: empty subject, critical TCG subjectAltName, critical keyUsage (keyAgreement
    /// for ECC, keyEncipherment for RSA), cA FALSE, tcg-kp-EKCertificate, the issuer's key identifier and one
    /// non-critical extension this syntax does not process (subjectDirectoryAttributes, TEST-VALUE content).
    pub fn ek_tbs(&self, ek: &EkPublicKey, serial: &[u8]) -> TbsCertificate {
        let usage = match ek {
            EkPublicKey::Ecc { .. } => key_usage(KeyUsages::KeyAgreement),
            EkPublicKey::Rsa { .. } => key_usage(KeyUsages::KeyEncipherment),
        };
        TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(serial).unwrap(),
            signature: self.intermediate_key.algorithm(),
            issuer: self.intermediate_name(),
            validity: Validity { not_before: time(CA_NOT_BEFORE + 86_400 * 151), not_after: time(NO_EXPIRY) },
            subject: RdnSequence::default(),
            subject_public_key_info: spki(ek),
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(vec![
                ext(oids::KEY_USAGE, true, &usage),
                ext(oids::BASIC_CONSTRAINTS, true, &BasicConstraints { ca: false, path_len_constraint: None }),
                ext(oids::EXT_KEY_USAGE, false, &ExtendedKeyUsage(vec![TCG_KP_EK_CERTIFICATE])),
                ext(oids::SUBJECT_ALT_NAME, true, &SubjectAltName(vec![GeneralName::DirectoryName(tcg_name(Tag::Utf8String))])),
                ext(
                    oids::AUTHORITY_KEY_IDENTIFIER,
                    false,
                    &AuthorityKeyIdentifier {
                        key_identifier: Some(OctetString::new(self.intermediate_key.key_id()).unwrap()),
                        ..Default::default()
                    },
                ),
                raw_ext(SUBJECT_DIRECTORY_ATTRIBUTES, false, vec![0x30, 0x00]),
            ]),
        }
    }
    /// Sign an EK signed part with the intermediate (outer algorithm = inner algorithm).
    pub fn issue(&self, tbs: &TbsCertificate) -> Vec<u8> {
        sign_tbs(tbs, &self.intermediate_key)
    }
    /// Sign raw signed-part bytes with the intermediate and assemble with the given outer algorithm.
    pub fn issue_raw(&self, tbs: &[u8], outer: &AlgorithmIdentifierOwned) -> Vec<u8> {
        assemble(tbs, &outer.to_der().unwrap(), &self.intermediate_key.sign(tbs))
    }
    pub fn ek_cert(&self, ek: &EkPublicKey, serial: &[u8]) -> Vec<u8> {
        self.issue(&self.ek_tbs(ek, serial))
    }
    /// Leaf first, anchor last.
    pub fn chain(&self, ek: &EkPublicKey, serial: &[u8]) -> Vec<Vec<u8>> {
        vec![self.ek_cert(ek, serial), self.intermediate.clone(), self.root.clone()]
    }
    /// A CRL signed part of the intermediate (`by_root` false: covers EK certificates) or of the root (covers the
    /// intermediate), current at `T_REF`.
    pub fn crl_tbs(&self, by_root: bool, revoked: &[&[u8]]) -> TbsCertList {
        let (signer, issuer) = if by_root {
            (&self.root_key, self.root_name())
        } else {
            (&self.intermediate_key, self.intermediate_name())
        };
        let entries: Vec<RevokedCert> = revoked
            .iter()
            .map(|s| RevokedCert {
                serial_number: SerialNumber::new(s).unwrap(),
                revocation_date: time(T_REF - 172_800),
                crl_entry_extensions: None,
            })
            .collect();
        TbsCertList {
            version: Version::V2,
            signature: signer.algorithm(),
            issuer,
            this_update: time(T_REF - 86_400),
            next_update: Some(time(T_REF + 30 * 86_400)),
            revoked_certificates: if entries.is_empty() { None } else { Some(entries) },
            crl_extensions: Some(vec![
                ext(oids::CRL_NUMBER, false, &CrlNumber(Uint::new(&[0x01]).unwrap())),
                ext(
                    oids::AUTHORITY_KEY_IDENTIFIER,
                    false,
                    &AuthorityKeyIdentifier { key_identifier: Some(OctetString::new(signer.key_id()).unwrap()), ..Default::default() },
                ),
            ]),
        }
    }
    pub fn sign_crl(&self, tbs: &TbsCertList, by_root: bool) -> Vec<u8> {
        let signer = if by_root { &self.root_key } else { &self.intermediate_key };
        let t = tbs.to_der().unwrap();
        assemble(&t, &tbs.signature.to_der().unwrap(), &signer.sign(&t))
    }
    /// The intermediate's CRL (revoking `ek_revoked`) and the root's CRL (revoking `intermediate_revoked`).
    pub fn crls(&self, ek_revoked: &[&[u8]], intermediate_revoked: &[&[u8]]) -> Vec<Vec<u8>> {
        vec![
            self.sign_crl(&self.crl_tbs(false, ek_revoked), false),
            self.sign_crl(&self.crl_tbs(true, intermediate_revoked), true),
        ]
    }
    pub fn anchor(&self, revocation: RevocationMode, classes: &[(u8, u16)], algorithms: &[SignatureAlgorithm]) -> TrustAnchor {
        TrustAnchor {
            root_cert_der_sha256: self.root_hash(),
            constraints: AnchorConstraints {
                max_intermediates: 1,
                signature_algorithms: algorithms.iter().copied().collect::<BTreeSet<_>>(),
                ek_classes: classes.iter().copied().collect(),
                revocation,
            },
        }
    }
}
/// Sign a struct signed part with `signer`; the outer algorithm is the inner one.
pub fn sign_tbs(tbs: &TbsCertificate, signer: &CaKey) -> Vec<u8> {
    let t = tbs.to_der().unwrap();
    assemble(&t, &tbs.signature.to_der().unwrap(), &signer.sign(&t))
}

/// PUBLIC TEST VALUE. Components are deterministically derived from a public seed
/// label; this is not a user key, manufacturer root, EK, or custody credential.
pub fn public_rsa_fixture(algorithm: SignatureAlgorithm) -> CaKey {
    let v: serde_json::Value = serde_json::from_str(include_str!("public_test_value_rsa_v1.json")).unwrap();
    assert_eq!(v["synthetic_only"], true);
    assert_eq!(v["production_authorized"], false);
    let number = |name: &str| rsa::BigUint::from_bytes_be(&hex::decode(v[name].as_str().unwrap()).unwrap());
    let key = rsa::RsaPrivateKey::from_components(number("n_hex"), rsa::BigUint::from(65537u32), number("d_hex"), vec![number("p_hex"), number("q_hex")]).unwrap();
    key.validate().unwrap();
    CaKey::Rsa { key, algorithm }
}
pub fn rsa_algorithm(algorithm: SignatureAlgorithm) -> AlgorithmIdentifierOwned {
    let (oid, parameters) = match algorithm {
        SignatureAlgorithm::RsaPkcs1Sha256 => (oids::SHA256_WITH_RSA, Any::null()),
        SignatureAlgorithm::RsaPkcs1Sha384 => (oids::SHA384_WITH_RSA, Any::null()),
        SignatureAlgorithm::RsaPssSha256 => (oids::RSA_PSS, Any::from_der(&rsa::pkcs1::RsaPssParams::new::<Sha256>(32).to_der().unwrap()).unwrap()),
        SignatureAlgorithm::RsaPssSha384 => (oids::RSA_PSS, Any::from_der(&rsa::pkcs1::RsaPssParams::new::<Sha384>(48).to_der().unwrap()).unwrap()),
        _ => panic!("not a TEST-VALUE RSA algorithm"),
    };
    AlgorithmIdentifierOwned { oid, parameters: Some(parameters) }
}
/// Deliberately public deterministic fixture randomness, never production entropy.
pub struct PublicTestRng(pub u64);
impl rsa::rand_core::RngCore for PublicTestRng {
    fn next_u32(&mut self) -> u32 { let mut b=[0;4];self.fill_bytes(&mut b);u32::from_le_bytes(b) }
    fn next_u64(&mut self) -> u64 { let mut b=[0;8];self.fill_bytes(&mut b);u64::from_le_bytes(b) }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(32) {
            let hash=Sha256::digest([b"MUTINY-BUILD8-PUBLIC-TEST-RSA-RNG-V1".as_slice(), &self.0.to_be_bytes()].concat());
            chunk.copy_from_slice(&hash[..chunk.len()]);self.0+=1;
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> { self.fill_bytes(dest);Ok(()) }
}
impl rsa::rand_core::CryptoRng for PublicTestRng {}
