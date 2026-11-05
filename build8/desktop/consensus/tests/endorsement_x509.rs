//! Candidate 3, Lane A2 (Order of 4 Oct 2026, decisions A1, A2, A7, A11): the reviewed X.509 DER syntax
//! (`X509Syntax`, test-only `tests/support/x509_syntax.rs`, dev-dependencies) under the unchanged EK-chain procedure, and the
//! attestation witness verified with it in the Production class. Design: `qualification/candidate-3/A-ADMISSION-DESIGN-V1.md`
//! section 10; dependency review: `qualification/candidate-3/A-ADMISSION-DEPS-REVIEW.md`.
//!
//! SIMULATED != PHYSICAL. Every certificate and CRL here is TEST-VALUE DER built from public seed labels (a P-384 root, a
//! P-256 intermediate, P-256 / RSA-shaped EK keys); none is manufacturer or EK material and the root is no real CA. A
//! passing test proves software behaviour only. Every negative test asserts the exact failure next to a positive
//! control; where the DER reader itself accepts a form this syntax refuses, the test shows the reader's acceptance first.
//!
//! Run: cargo test --offline --locked --test endorsement_x509
#[path = "support/software_tpm.rs"]
mod software_tpm;
#[path = "support/test_value_ek.rs"]
mod test_value_ek;
#[path = "support/test_value_x509.rs"]
mod test_value_x509;
#[path = "support/x509_syntax.rs"]
mod x509_syntax;
use mutiny_consensus_v8::{
    domain_hash,
    attestation_witness::{AttestationWitness, EndorsementEvidence, WITNESS_DOMAIN, WitnessContext, WitnessFailure, verify_witness},
    ek_chain::*,
    endorsement_identity::*,
    provenance::AdmissionClass,
};
use software_tpm::{Strip, TestTpm};
use test_value_ek::{ECC_CLASS, RSA_CLASS, TEST_ATTRIBUTES, TestValueSyntax, activation, class_of, public_area, rsa_like_public, template};
use test_value_x509::*;
use x509_syntax::{X509Syntax, oids};
use x509_cert::{
    Certificate, TbsCertificate,
    crl::TbsCertList,
    der::{
        Any, Decode, Encode, Tag,
        asn1::{BitString, Ia5String, ObjectIdentifier, OctetString, Uint},
    },
    ext::pkix::{
        BaseCrlNumber, BasicConstraints as DerBasicConstraints, ExtendedKeyUsage, IssuingDistributionPoint, KeyUsage,
        SubjectAltName as DerSubjectAltName, SubjectKeyIdentifier, name::GeneralName,
    },
    name::RelativeDistinguishedName,
    spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned},
    time::Validity,
};

const BOTH_ECDSA: [SignatureAlgorithm; 2] = [SignatureAlgorithm::EcdsaP256Sha256, SignatureAlgorithm::EcdsaP384Sha384];
use ChainFailure as F;

fn ek() -> EkPublicKey {
    CaKey::P256(p256_key("leaf-ek")).public()
}
fn ctx(class: AdmissionClass, anchors: &[TrustAnchor]) -> ChainContext<'_> {
    ChainContext { class, reference_time: T_REF, anchors }
}
/// The Production class throughout: the X.509 syntax is the one a Production verification may use.
fn verify(chain: &[Vec<u8>], crls: &[Vec<u8>], anchors: &[TrustAnchor]) -> Result<VerifiedEndorsement, ChainFailure> {
    validate_endorsement_chain(&X509Syntax, chain, crls, &ctx(AdmissionClass::Production, anchors))
}
fn parse(raw: &[u8]) -> Result<ParsedCertificate, ChainFailure> {
    X509Syntax.parse_certificate(raw)
}
struct Standard {
    pki: X509Pki,
    chain: Vec<Vec<u8>>,
    crls: Vec<Vec<u8>>,
    anchors: Vec<TrustAnchor>,
}
fn standard() -> Standard {
    let pki = X509Pki::new("vendor-x");
    let chain = pki.chain(&ek(), &[0x21]);
    let crls = pki.crls(&[], &[]);
    let anchors = vec![pki.anchor(RevocationMode::CrlRequired, &[ECC_CLASS, RSA_CLASS], &BOTH_ECDSA)];
    Standard { pki, chain, crls, anchors }
}
fn with_leaf(s: &Standard, leaf: Vec<u8>) -> Vec<Vec<u8>> {
    let mut chain = s.chain.clone();
    chain[0] = leaf;
    chain
}
/// The three TCG attributes encoded, in REVERSED DER order (a SET OF the DER reader accepts and sorts).
fn unsorted_tcg_set() -> Vec<u8> {
    let mut encoded: Vec<Vec<u8>> = tcg_attributes(Tag::Utf8String).iter().map(|a| a.to_der().unwrap()).collect();
    encoded.sort();
    encoded.reverse();
    let unsorted = tlv(0x31, &encoded.concat());
    let sorted = RelativeDistinguishedName::try_from(tcg_attributes(Tag::Utf8String)).unwrap().to_der().unwrap();
    assert_ne!(unsorted, sorted);
    assert_eq!(unsorted.len(), sorted.len());
    unsorted
}

/// A11 positive control: a DER chain (P-256 EK <- P-256 intermediate <- P-384 root, both CRLs current) verifies in the
/// Production and the LegacyTest class, yields the anchor, the canonical EK and the path, and is deterministic.
#[test]
fn x509_der_chain_verifies_and_yields_the_anchor_the_canonical_ek_and_the_path() {
    let s = standard();
    assert!(X509Syntax.production());
    let v = verify(&s.chain, &s.crls, &s.anchors).unwrap();
    assert_eq!(v.anchor, s.pki.root_hash());
    assert_eq!(v.leaf_key, ek());
    assert_eq!(v.path, s.chain.iter().map(|c| sha256(c)).collect::<Vec<_>>());
    assert_eq!(
        validate_endorsement_chain(&X509Syntax, &s.chain, &s.crls, &ctx(AdmissionClass::LegacyTest, &s.anchors)),
        Ok(v)
    );
    // TEST-VALUE material from public labels: rebuilt, byte-identical.
    let again = standard();
    assert_eq!((again.chain, again.crls), (s.chain.clone(), s.crls.clone()));
    // What the parser reports is what the procedure consumes.
    let leaf = parse(&s.chain[0]).unwrap();
    let issuer = parse(&s.chain[1]).unwrap();
    assert_eq!((leaf.version, leaf.serial.clone(), leaf.signature_algorithm), (3, vec![0x21], SignatureAlgorithm::EcdsaP256Sha256));
    assert!(leaf.subject.is_empty());
    assert_eq!(leaf.not_after, NO_EXPIRY);
    assert_eq!(leaf.key_usage, Some(key_usage::KEY_AGREEMENT));
    assert_eq!(leaf.extended_key_usage, Some(vec![oid::TCG_KP_EK_CERTIFICATE.to_vec()]));
    let san = leaf.subject_alt_name.clone().unwrap();
    assert!(san.critical && san.other_forms == 0 && san.directory_names.len() == 1 && san.directory_names[0].len() == 3);
    assert!(leaf.unrecognised_critical.is_empty(), "the non-critical subjectDirectoryAttributes is ignored");
    assert_eq!(leaf.issuer, issuer.subject);
    assert_eq!(leaf.authority_key_id, issuer.subject_key_id);
    assert_eq!(issuer.basic_constraints, Some(BasicConstraints { critical: true, ca: true, path_len: Some(0) }));
    assert_eq!(issuer.key_usage, Some(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN));
    assert_eq!(issuer.public_key, s.pki.intermediate_key.public());
    // `TbsParts` reproduces the struct encoder exactly (the hand-built negatives below change one part each).
    let tbs = s.pki.ek_tbs(&ek(), &[0x21]);
    assert_eq!(TbsParts::of(&tbs).encode(), tbs.to_der().unwrap());
}

/// An RSA EK key is parsed (rsaEncryption, NULL parameters, exponent at most 32 bits) and certified by an ECDSA CA it
/// verifies. RSA SIGNATURES are refused: the `rsa` crate is not declared (its closure's build scripts await a decision).
#[test]
fn rsa_endorsement_keys_parse_and_rsa_signatures_fail_closed() {
    let s = standard();
    let rsa = rsa_like_public("x509-rsa-ek", 2048);
    let v = verify(&s.pki.chain(&rsa, &[0x22]), &s.crls, &s.anchors).unwrap();
    assert_eq!(v.leaf_key, rsa);
    let EkPublicKey::Rsa { modulus, .. } = &rsa else { unreachable!() };
    let mut tbs = s.pki.ek_tbs(&rsa, &[0x22]);
    tbs.subject_public_key_info = rsa_spki(modulus, &[1, 0, 0, 0, 1]);
    assert_eq!(parse(&s.pki.issue(&tbs)).err(), Some(F::UnsupportedKey(IdentityFailure::RsaExponent)));
    let mut tbs = s.pki.ek_tbs(&rsa, &[0x22]);
    tbs.subject_public_key_info.algorithm.parameters = None;
    assert_eq!(parse(&s.pki.issue(&tbs)).err(), Some(F::Malformed));
    // An EK certificate labelled sha256WithRSAEncryption: the identifier parses, the signature never verifies, even
    // under an anchor that allows the algorithm.
    let rsa_alg = AlgorithmIdentifierOwned { oid: oids::SHA256_WITH_RSA, parameters: Some(Any::null()) };
    let mut tbs = s.pki.ek_tbs(&ek(), &[0x23]);
    tbs.signature = rsa_alg.clone();
    let t = tbs.to_der().unwrap();
    let leaf = assemble(&t, &rsa_alg.to_der().unwrap(), &[0x5a; 256]);
    assert_eq!(parse(&leaf).unwrap().signature_algorithm, SignatureAlgorithm::RsaPkcs1Sha256);
    let mut algorithms = BOTH_ECDSA.to_vec();
    algorithms.push(SignatureAlgorithm::RsaPkcs1Sha256);
    let anchors = vec![s.pki.anchor(RevocationMode::CrlRequired, &[ECC_CLASS], &algorithms)];
    assert_eq!(verify(&with_leaf(&s, leaf), &s.crls, &anchors), Err(F::BadSignature));
    verify(&s.chain, &s.crls, &anchors).unwrap();
}

/// What the DER reader itself refuses (trailing data, truncation, a non-minimal length) is `Malformed`.
#[test]
fn der_reader_failures_are_malformed() {
    let s = standard();
    let leaf = &s.chain[0];
    let mut trailing = leaf.clone();
    trailing.push(0);
    assert_eq!(parse(&trailing).err(), Some(F::Malformed));
    assert_eq!(parse(&leaf[..leaf.len() - 1]).err(), Some(F::Malformed));
    assert_eq!(leaf[1], 0x82, "the leaf's outer length uses the two-octet form");
    let mut long = vec![0x30, 0x83, 0x00, leaf[2], leaf[3]];
    long.extend_from_slice(&leaf[4..]);
    assert_eq!(parse(&long).err(), Some(F::Malformed));
    assert_eq!(verify(&with_leaf(&s, trailing), &s.crls, &s.anchors), Err(F::Malformed));
    verify(&s.chain, &s.crls, &s.anchors).unwrap();
}

/// The DER reader ACCEPTS and normalises some forms DER forbids; re-encoding equality refuses them, for the whole
/// certificate (an unsorted SET OF in the subject) and for an extension value (an unsorted SET OF inside the
/// subjectAltName, nonzero padding bits in keyUsage).
#[test]
fn non_canonical_forms_the_der_reader_accepts_are_refused_by_re_encoding() {
    let s = standard();
    let tbs = s.pki.ek_tbs(&ek(), &[0x24]);
    // Whole certificate: a multi-valued RDN in reversed order in the subject.
    let mut parts = TbsParts::of(&tbs);
    parts.subject = tlv(0x30, &unsorted_tcg_set());
    let leaf = s.pki.issue_raw(&parts.encode(), &ecdsa_sha256());
    assert!(Certificate::from_der(&leaf).is_ok(), "the reader accepts (and sorts) the SET OF");
    assert_eq!(parse(&leaf).err(), Some(F::Malformed));
    // Whole certificate: an extension whose DEFAULT critical FALSE is encoded explicitly (01 01 00).
    let mut parts = TbsParts::of(&tbs);
    let directory = &tbs.extensions.as_ref().unwrap()[5];
    let explicit = tlv(0x30, &[directory.extn_id.to_der().unwrap(), vec![0x01, 0x01, 0x00], directory.extn_value.to_der().unwrap()].concat());
    parts.extensions.as_mut().unwrap()[5] = explicit;
    let leaf = s.pki.issue_raw(&parts.encode(), &ecdsa_sha256());
    assert!(Certificate::from_der(&leaf).is_ok(), "the reader accepts an explicit DEFAULT");
    assert_eq!(parse(&leaf).err(), Some(F::Malformed));
    // Extension value: the same SET OF inside the subjectAltName directoryName.
    let san = tlv(0x30, &tlv(0xA4, &tlv(0x30, &unsorted_tcg_set())));
    assert!(DerSubjectAltName::from_der(&san).is_ok(), "the reader accepts the extension value");
    let mut t = tbs.clone();
    t.extensions.as_mut().unwrap()[3] = raw_ext(oids::SUBJECT_ALT_NAME, true, san);
    let leaf = s.pki.issue(&t);
    assert!(Certificate::from_der(&leaf).is_ok());
    assert_eq!(parse(&leaf).err(), Some(F::Malformed));
    // Extension value: keyAgreement with a padding bit set (03 02 03 09 instead of 03 02 03 08).
    let padded = vec![0x03, 0x02, 0x03, 0x09];
    assert!(KeyUsage::from_der(&padded).is_ok(), "the reader ignores padding bits");
    let mut t = tbs.clone();
    t.extensions.as_mut().unwrap()[0] = raw_ext(oids::KEY_USAGE, true, padded);
    assert_eq!(parse(&s.pki.issue(&t)).err(), Some(F::Malformed));
    // Control: the canonical encodings.
    let mut t = tbs.clone();
    t.extensions.as_mut().unwrap()[0] = raw_ext(oids::KEY_USAGE, true, vec![0x03, 0x02, 0x03, 0x08]);
    verify(&with_leaf(&s, s.pki.issue(&t)), &s.crls, &s.anchors).unwrap();
}

/// P3: the signature algorithm inside the signed part equals the outer one; each identifier has one encoding;
/// unsupported identifiers are refused.
#[test]
fn the_signed_algorithm_equals_the_outer_one_and_identifiers_have_one_encoding() {
    let s = standard();
    let tbs = s.pki.ek_tbs(&ek(), &[0x25]);
    let mismatch = s.pki.issue_raw(&tbs.to_der().unwrap(), &ecdsa_sha384());
    assert!(Certificate::from_der(&mismatch).is_ok());
    assert_eq!(parse(&mismatch).err(), Some(F::Malformed));
    let with = |algorithm: AlgorithmIdentifierOwned| {
        let mut t = tbs.clone();
        t.signature = algorithm;
        parse(&s.pki.issue(&t)).err()
    };
    let oid = ObjectIdentifier::new_unwrap;
    assert_eq!(with(AlgorithmIdentifierOwned { oid: oids::ECDSA_WITH_SHA256, parameters: Some(Any::null()) }), Some(F::Malformed));
    assert_eq!(with(AlgorithmIdentifierOwned { oid: oids::SHA256_WITH_RSA, parameters: None }), Some(F::Malformed));
    assert_eq!(with(AlgorithmIdentifierOwned { oid: oid("1.2.840.10045.4.3.4"), parameters: None }), Some(F::UnsupportedAlgorithm));
    let pss = Any::new(Tag::Sequence, Vec::<u8>::new()).unwrap();
    assert_eq!(with(AlgorithmIdentifierOwned { oid: oid("1.2.840.113549.1.1.10"), parameters: Some(pss) }), Some(F::UnsupportedAlgorithm));
    assert_eq!(with(ecdsa_sha256()), None);
}

/// Serial numbers are positive; the parser reports the magnitude.
#[test]
fn serial_numbers_are_positive_and_reported_as_magnitudes() {
    let s = standard();
    assert_eq!(parse(&s.pki.issue(&s.pki.ek_tbs(&ek(), &[0x00]))).err(), Some(F::Malformed));
    let mut parts = TbsParts::of(&s.pki.ek_tbs(&ek(), &[0x26]));
    parts.serial = vec![0x02, 0x01, 0x86];
    let negative = s.pki.issue_raw(&parts.encode(), &ecdsa_sha256());
    assert!(Certificate::from_der(&negative).is_ok(), "the reader accepts a negative serial");
    assert_eq!(parse(&negative).err(), Some(F::Malformed));
    assert_eq!(parse(&s.pki.issue(&s.pki.ek_tbs(&ek(), &[0x86]))).unwrap().serial, vec![0x86]);
    assert_eq!(parse(&s.pki.issue(&s.pki.ek_tbs(&ek(), &[0x7f; 20]))).unwrap().serial, vec![0x7f; 20]);

    // Actual signed DER, not SerialNumber::new (which already enforces the creation bound).
    let signed_serial = |magnitude: &[u8]| {
        let mut tbs = TbsParts::of(&s.pki.ek_tbs(&ek(), &[0x26]));
        tbs.serial = der_uint(magnitude);
        s.pki.issue_raw(&tbs.encode(), &ecdsa_sha256())
    };
    let high_19 = [0x86; 19]; // required leading sign zero makes exactly 20 content octets.
    let positive = signed_serial(&high_19);
    let decoded = Certificate::from_der(&positive).unwrap();
    assert_eq!(decoded.tbs_certificate.serial_number.as_bytes().len(), 20);
    assert_eq!(parse(&positive).unwrap().serial, high_19.to_vec());
    let mut chain = s.chain.clone();
    chain[0] = positive;
    verify(&chain, &s.crls, &s.anchors).unwrap();
    for magnitude in [vec![0x7f; 21], vec![0x86; 20]] {
        let too_long = signed_serial(&magnitude);
        let decoded = Certificate::from_der(&too_long).unwrap();
        assert_eq!(decoded.tbs_certificate.serial_number.as_bytes().len(), 21);
        assert_eq!(parse(&too_long).err(), Some(F::Malformed));
        chain[0] = too_long;
        assert_eq!(verify(&chain, &s.crls, &s.anchors), Err(F::Malformed));
    }
}

/// RFC 5280 4.1.2.5: a time before 2050 is UTCTime; GeneralizedTime from 2050 (the standard EK notAfter 9999-12-31).
#[test]
fn times_use_the_rfc5280_encoding_for_their_year() {
    let s = standard();
    let mut tbs = s.pki.ek_tbs(&ek(), &[0x27]);
    tbs.validity = Validity { not_before: generalized(CA_NOT_BEFORE), not_after: time(NO_EXPIRY) };
    let leaf = s.pki.issue(&tbs);
    assert!(Certificate::from_der(&leaf).is_ok());
    assert_eq!(parse(&leaf).err(), Some(F::Malformed));
    let mut crl = s.pki.crl_tbs(false, &[]);
    crl.this_update = generalized(T_REF - 86_400);
    assert_eq!(X509Syntax.parse_crl(&s.pki.sign_crl(&crl, false)).err(), Some(F::Malformed));
    assert_eq!(parse(&s.chain[0]).unwrap().not_after, NO_EXPIRY);
    assert_eq!(X509Syntax.parse_crl(&s.crls[0]).unwrap().this_update, T_REF - 86_400);
}

/// Public keys: an uncompressed point on a named curve, or rsaEncryption; P-384 parses (a CA key) but is not an EK.
#[test]
fn public_keys_are_uncompressed_named_curve_points_or_rsa() {
    let s = standard();
    let key = ek();
    let EkPublicKey::Ecc { x, y, .. } = &key else { unreachable!() };
    let point = [&[0x04u8][..], x, y].concat();
    let with = |spki: SubjectPublicKeyInfoOwned| {
        let mut t = s.pki.ek_tbs(&key, &[0x28]);
        t.subject_public_key_info = spki;
        parse(&s.pki.issue(&t)).err()
    };
    let compressed = [&[0x02 | (y[31] & 1)][..], x].concat();
    assert_eq!(with(ec_spki(oids::SECP256R1, &compressed)), Some(F::UnsupportedKey(IdentityFailure::Length)));
    let hybrid = [&[0x06 | (y[31] & 1)][..], x, y].concat();
    assert_eq!(with(ec_spki(oids::SECP256R1, &hybrid)), Some(F::UnsupportedKey(IdentityFailure::Length)));
    assert_eq!(
        with(ec_spki(ObjectIdentifier::new_unwrap("1.3.36.3.3.2.8.1.1.7"), &point)),
        Some(F::UnsupportedKey(IdentityFailure::UnsupportedCurve))
    );
    let mut absent = ec_spki(oids::SECP256R1, &point);
    absent.algorithm.parameters = None;
    assert_eq!(with(absent), Some(F::Malformed));
    let ed25519 = SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned { oid: ObjectIdentifier::new_unwrap("1.3.101.112"), parameters: None },
        subject_public_key: BitString::from_bytes(&[7u8; 32]).unwrap(),
    };
    assert_eq!(with(ed25519), Some(F::UnsupportedKey(IdentityFailure::UnknownAlgorithm)));
    let p384_ek = CaKey::P384(p384_key("p384-ek")).public();
    assert_eq!(
        verify(&with_leaf(&s, s.pki.ek_cert(&p384_ek, &[0x28])), &s.crls, &s.anchors),
        Err(F::UnsupportedKey(IdentityFailure::UnsupportedCurve))
    );
    assert_eq!(with(ec_spki(oids::SECP256R1, &point)), None);
}

/// Extension lists: present means non-empty, each OID once; key identifiers non-critical; keyUsage nonzero; EKU
/// non-empty; no pathLenConstraint without cA; no unique identifiers.
#[test]
fn extension_lists_are_non_empty_distinct_and_well_formed() {
    let s = standard();
    let base = s.pki.ek_tbs(&ek(), &[0x29]);
    let with = |edit: &dyn Fn(&mut TbsCertificate)| {
        let mut t = base.clone();
        edit(&mut t);
        parse(&s.pki.issue(&t)).err()
    };
    assert_eq!(
        with(&|t| {
            let first = t.extensions.as_ref().unwrap()[0].clone();
            t.extensions.as_mut().unwrap().push(first)
        }),
        Some(F::Malformed)
    );
    assert_eq!(with(&|t| t.extensions = Some(vec![])), Some(F::Malformed));
    let ski = SubjectKeyIdentifier(OctetString::new(vec![1u8; 20]).unwrap());
    assert_eq!(with(&|t| t.extensions.as_mut().unwrap().push(ext(oids::SUBJECT_KEY_IDENTIFIER, true, &ski))), Some(F::Malformed));
    let not_ca = DerBasicConstraints { ca: false, path_len_constraint: Some(0) };
    assert_eq!(with(&|t| t.extensions.as_mut().unwrap()[1] = ext(oids::BASIC_CONSTRAINTS, true, &not_ca)), Some(F::Malformed));
    assert_eq!(with(&|t| t.extensions.as_mut().unwrap()[2] = ext(oids::EXT_KEY_USAGE, false, &ExtendedKeyUsage(vec![]))), Some(F::Malformed));
    assert_eq!(with(&|t| t.extensions.as_mut().unwrap()[0] = raw_ext(oids::KEY_USAGE, true, vec![0x03, 0x01, 0x00])), Some(F::Malformed));
    assert_eq!(with(&|t| t.issuer_unique_id = Some(BitString::from_bytes(&[1]).unwrap())), Some(F::Malformed));
    assert_eq!(with(&|t| t.extensions.as_mut().unwrap().push(ext(oids::SUBJECT_KEY_IDENTIFIER, false, &ski))), None);
}

/// P12: a critical extension this syntax does not process is reported and refused; non-critical ones are ignored.
#[test]
fn critical_extensions_this_syntax_does_not_process_are_refused() {
    let s = standard();
    let mut tbs = s.pki.ek_tbs(&ek(), &[0x2a]);
    tbs.extensions.as_mut().unwrap().push(raw_ext(CERTIFICATE_POLICIES, true, vec![0x30, 0x00]));
    let leaf = s.pki.issue(&tbs);
    assert_eq!(parse(&leaf).unwrap().unrecognised_critical, vec![CERTIFICATE_POLICIES.as_bytes().to_vec()]);
    assert_eq!(verify(&with_leaf(&s, leaf), &s.crls, &s.anchors), Err(F::UnsupportedCriticalExtension));
    let mut tbs = s.pki.ek_tbs(&ek(), &[0x2a]);
    tbs.extensions.as_mut().unwrap().push(raw_ext(CERTIFICATE_POLICIES, false, vec![0x30, 0x00]));
    verify(&with_leaf(&s, s.pki.issue(&tbs)), &s.crls, &s.anchors).unwrap();
}

/// P11 with DER names: TCG attributes are UTF8String; an empty subject needs a critical subjectAltName holding only
/// the TCG directoryName; an empty subjectAltName is malformed.
#[test]
fn tcg_alternative_names_are_utf8_and_follow_the_ek_form() {
    let s = standard();
    let with = |critical: bool, names: Vec<GeneralName>| {
        let mut t = s.pki.ek_tbs(&ek(), &[0x2b]);
        t.extensions.as_mut().unwrap()[3] = ext(oids::SUBJECT_ALT_NAME, critical, &DerSubjectAltName(names));
        s.pki.issue(&t)
    };
    let printable = with(true, vec![GeneralName::DirectoryName(tcg_name(Tag::PrintableString))]);
    assert_eq!(parse(&printable).err(), Some(F::NameForm));
    let non_critical = with(false, vec![GeneralName::DirectoryName(tcg_name(Tag::Utf8String))]);
    assert_eq!(verify(&with_leaf(&s, non_critical), &s.crls, &s.anchors), Err(F::NameForm));
    let dns = GeneralName::DnsName(Ia5String::new("ek.test-value.invalid").unwrap());
    let extra = with(true, vec![GeneralName::DirectoryName(tcg_name(Tag::Utf8String)), dns]);
    assert_eq!(verify(&with_leaf(&s, extra), &s.crls, &s.anchors), Err(F::NameForm));
    assert_eq!(parse(&with(true, vec![])).err(), Some(F::Malformed));
    let control = with(true, vec![GeneralName::DirectoryName(tcg_name(Tag::Utf8String))]);
    verify(&with_leaf(&s, control), &s.crls, &s.anchors).unwrap();
}

/// P6 with ECDSA: the signature covers the exact signed bytes, is strict DER, and the key is paired with its hash
/// (a valid P-256/SHA-256 signature labelled ecdsa-with-SHA384 is refused).
#[test]
fn signatures_are_strict_der_paired_with_the_key_and_over_the_exact_bytes() {
    let s = standard();
    let tbs = s.pki.ek_tbs(&ek(), &[0x2c]);
    let t = tbs.to_der().unwrap();
    let CaKey::P256(key) = &s.pki.intermediate_key else { unreachable!() };
    let signature: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(key, &t);
    let (r, s_scalar) = signature.split_bytes();
    let alg = ecdsa_sha256().to_der().unwrap();
    let good = ecdsa_der(&r, &s_scalar);
    verify(&with_leaf(&s, assemble(&t, &alg, &good)), &s.crls, &s.anchors).unwrap();
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(verify(&with_leaf(&s, assemble(&t, &alg, &trailing)), &s.crls, &s.anchors), Err(F::BadSignature));
    let mut flipped = good.clone();
    *flipped.last_mut().unwrap() ^= 1;
    assert_eq!(verify(&with_leaf(&s, assemble(&t, &alg, &flipped)), &s.crls, &s.anchors), Err(F::BadSignature));
    let mut parts = TbsParts::of(&tbs);
    parts.serial = der_uint(&[0x2d]);
    assert_eq!(
        verify(&with_leaf(&s, assemble(&parts.encode(), &alg, &good)), &s.crls, &s.anchors),
        Err(F::BadSignature)
    );
    let r_padded = tlv(0x02, &[&[0u8][..], &der_uint(&r)[2..]].concat());
    let non_minimal = tlv(0x30, &[r_padded, der_uint(&s_scalar)].concat());
    assert_eq!(verify(&with_leaf(&s, assemble(&t, &alg, &non_minimal)), &s.crls, &s.anchors), Err(F::BadSignature));
    // The same valid P-256/SHA-256 signature, both identifiers relabelled ecdsa-with-SHA384 (the anchor allows it).
    let mut relabelled = tbs.clone();
    relabelled.signature = ecdsa_sha384();
    let t384 = relabelled.to_der().unwrap();
    let signature: p256::ecdsa::Signature = p256::ecdsa::signature::Signer::sign(key, &t384);
    let (r, s_scalar) = signature.split_bytes();
    let leaf = assemble(&t384, &ecdsa_sha384().to_der().unwrap(), &ecdsa_der(&r, &s_scalar));
    assert_eq!(parse(&leaf).unwrap().signature_algorithm, SignatureAlgorithm::EcdsaP384Sha384);
    assert_eq!(verify(&with_leaf(&s, leaf), &s.crls, &s.anchors), Err(F::BadSignature));
}

/// P14 with DER CRLs: current CRLs of both issuers verify; a listed serial is revoked; delta, scope-restricted and
/// indirect CRLs and critical entry extensions are unsupported; malformed or misattributed CRLs are refused.
#[test]
fn crls_are_strict_complete_for_their_issuer_and_listed_serials_are_revoked() {
    let s = standard();
    assert_eq!(verify(&s.chain, &s.pki.crls(&[&[0x21]], &[]), &s.anchors), Err(F::Revoked));
    assert_eq!(verify(&s.chain, &s.pki.crls(&[], &[&[0x02]]), &s.anchors), Err(F::Revoked));
    verify(&s.chain, &s.pki.crls(&[&[0x99]], &[&[0x98]]), &s.anchors).unwrap();
    let with = |edit: &dyn Fn(&mut TbsCertList)| {
        let mut t = s.pki.crl_tbs(false, &[&[0x99]]);
        edit(&mut t);
        verify(&s.chain, &[s.pki.sign_crl(&t, false), s.crls[1].clone()], &s.anchors)
    };

    // CRL entries use the same content bound/positive INTEGER policy and genuine issuer signature.
    let entry_serial = |encoded: &[u8]| {
        let value = x509_cert::serial_number::SerialNumber::from_der(encoded).unwrap();
        with(&|t| t.revoked_certificates.as_mut().unwrap()[0].serial_number = value.clone())
    };
    entry_serial(&der_uint(&[0x7f; 20])).unwrap();
    entry_serial(&der_uint(&[0x86; 19])).unwrap(); // sign zero + 19 magnitude octets = 20.
    for encoded in [der_uint(&[0x7f; 21]), der_uint(&[0x86; 20]), vec![0x02, 0x01, 0x00], vec![0x02, 0x01, 0x86]] {
        assert_eq!(entry_serial(&encoded), Err(F::Malformed));
    }
    let high_19 = [0x86; 19];
    let certificate = s.pki.issue(&s.pki.ek_tbs(&ek(), &high_19));
    let mut chain = s.chain.clone();
    chain[0] = certificate;
    assert_eq!(verify(&chain, &s.pki.crls(&[&high_19], &[]), &s.anchors), Err(F::Revoked));
    let delta = ext(oids::DELTA_CRL_INDICATOR, true, &BaseCrlNumber(Uint::new(&[1]).unwrap()));
    assert_eq!(with(&|t| t.crl_extensions.as_mut().unwrap().push(delta.clone())), Err(F::RevocationUnsupported));
    let idp = |user: bool, indirect: bool| IssuingDistributionPoint {
        distribution_point: None,
        only_contains_user_certs: user,
        only_contains_ca_certs: false,
        only_some_reasons: None,
        indirect_crl: indirect,
        only_contains_attribute_certs: false,
    };
    let scoped = ext(oids::ISSUING_DISTRIBUTION_POINT, true, &idp(true, false));
    assert_eq!(with(&|t| t.crl_extensions.as_mut().unwrap().push(scoped.clone())), Err(F::RevocationUnsupported));
    let indirect = ext(oids::ISSUING_DISTRIBUTION_POINT, true, &idp(false, true));
    assert_eq!(with(&|t| t.crl_extensions.as_mut().unwrap().push(indirect.clone())), Err(F::RevocationUnsupported));
    let unscoped = ext(oids::ISSUING_DISTRIBUTION_POINT, true, &idp(false, false));
    assert_eq!(with(&|t| t.crl_extensions.as_mut().unwrap().push(unscoped.clone())), Ok(with(&|_| {}).unwrap()));
    let certificate_issuer = raw_ext(ObjectIdentifier::new_unwrap("2.5.29.29"), true, vec![0x30, 0x00]);
    assert_eq!(
        with(&|t| t.revoked_certificates.as_mut().unwrap()[0].crl_entry_extensions = Some(vec![certificate_issuer.clone()])),
        Err(F::RevocationUnsupported)
    );
    let reason = raw_ext(ObjectIdentifier::new_unwrap("2.5.29.21"), false, vec![0x0a, 0x01, 0x01]);
    with(&|t| t.revoked_certificates.as_mut().unwrap()[0].crl_entry_extensions = Some(vec![reason.clone()])).unwrap();
    assert_eq!(with(&|t| t.revoked_certificates = Some(vec![])), Err(F::Malformed));
    assert_eq!(with(&|t| t.crl_extensions.as_mut().unwrap()[0].critical = true), Err(F::Malformed));
    let t = s.pki.crl_tbs(false, &[]).to_der().unwrap();
    let mismatch = assemble(&t, &ecdsa_sha384().to_der().unwrap(), &s.pki.intermediate_key.sign(&t));
    assert_eq!(verify(&s.chain, &[mismatch, s.crls[1].clone()], &s.anchors), Err(F::Malformed));
    let mut by_root = s.pki.crl_tbs(false, &[]);
    by_root.signature = ecdsa_sha384();
    let wrong_signer = s.pki.sign_crl(&by_root, true);
    assert_eq!(verify(&s.chain, &[wrong_signer, s.crls[1].clone()], &s.anchors), Err(F::RevocationIssuer));
}

/// A7 + A11 end to end: the simulator's version-2 statement (identity = H(network, canonical simulator EK)) is supported
/// by a witness whose EK chain is DER, verified in the PRODUCTION class with the X.509 syntax. The TEST-VALUE syntax
/// cannot stand in for it, and a certificate for another key under the same public area is a key mismatch.
#[test]
fn x509_witness_binds_the_statement_identity_to_the_certified_simulator_ek_in_the_production_class() {
    let pki = X509Pki::new("vendor-x");
    let tpm = TestTpm::stripped(Strip::ConsistentProvenance(pki.root_hash()));
    let simulator_ek = tpm.simulator_ek();
    let ak_name = tpm.consistent_provenance(pki.root_hash()).ak_name;
    let witness = AttestationWitness {
        reference_time: T_REF,
        endorsements: vec![EndorsementEvidence {
            ek_public_area: public_area(&template(ECC_TAG, TEST_ATTRIBUTES), &simulator_ek),
            certificates: pki.chain(&simulator_ek, &[0x31]),
            crls: pki.crls(&[], &[]),
        }],
        activation: vec![activation(0, ak_name, "tpm-x509")],
    };
    let commit = |w: &AttestationWitness| {
        let raw = w.encode().unwrap();
        let mut statement = tpm.consistent_provenance(pki.root_hash());
        statement.endorsement.as_mut().unwrap().witness_sha256 = domain_hash(WITNESS_DOMAIN, &raw);
        (statement, raw)
    };
    let (statement, raw) = commit(&witness);
    assert_eq!(statement.endorsement.as_ref().unwrap().identities, vec![(pki.root_hash(), tpm.ek_identity())]);
    let classes = IdentityClasses::new(vec![class_of(ECC_TAG, TEST_ATTRIBUTES)]).unwrap();
    let anchors = vec![pki.anchor(RevocationMode::CrlRequired, &[ECC_CLASS], &BOTH_ECDSA)];
    let ctx = WitnessContext {
        chain: ChainContext { class: AdmissionClass::Production, reference_time: T_REF, anchors: &anchors },
        identity_classes: &classes,
    };
    verify_witness(&statement, Some(&raw), &ctx, &X509Syntax).unwrap();
    assert_eq!(
        verify_witness(&statement, Some(&raw), &ctx, &TestValueSyntax),
        Err(WitnessFailure::Chain(0, F::ParserUnavailable))
    );
    let mut other = witness.clone();
    other.endorsements[0].certificates = pki.chain(&CaKey::P256(p256_key("other-ek")).public(), &[0x31]);
    let (s2, raw2) = commit(&other);
    assert_eq!(verify_witness(&s2, Some(&raw2), &ctx, &X509Syntax), Err(WitnessFailure::KeyMismatch(0)));
    let mut revoked = witness.clone();
    revoked.endorsements[0].crls = pki.crls(&[&[0x31]], &[]);
    let (s3, raw3) = commit(&revoked);
    assert_eq!(verify_witness(&s3, Some(&raw3), &ctx, &X509Syntax), Err(WitnessFailure::Chain(0, F::Revoked)));
}
