//! Candidate 3, Lane A2 (Order of 4 Oct 2026, decisions A1, A2, A3, A5, A7, A11): the EK-chain validation procedure behind
//! the `CertificateSyntax` trait boundary, the committed attestation witness, the accepted PCR-profile set and its
//! requalification check. Design: `qualification/candidate-3/A-ADMISSION-DESIGN-V1.md`.
//!
//! SIMULATED != PHYSICAL. Every certificate here is TEST-VALUE syntax (canonical CBOR, P-256, public seeds; not X.509),
//! every key is public, nothing is manufacturer or EK material. A passing test proves software behaviour only. Every
//! negative test asserts the exact failure, next to a positive control built the same way.
#[path = "support/software_tpm.rs"]
mod software_tpm;
#[path = "support/test_value_ek.rs"]
mod test_value_ek;
use mutiny_consensus_v8::{
    Error, Hash, domain_hash,
    attestation_witness::{AttestationWitness, WITNESS_DOMAIN, WitnessContext, WitnessFailure, verify_witness},
    ek_chain::*,
    endorsement_identity::*,
    pcr_profiles::*,
    provenance::{AdmissionClass, Provenance},
};
use sha2::{Digest, Sha256};
use software_tpm::{Strip, TestTpm};
use test_value_ek::*;

fn context<'a>(anchors: &'a [TrustAnchor]) -> ChainContext<'a> {
    ChainContext { class: AdmissionClass::LegacyTest, reference_time: T_REF, anchors }
}
fn validate(chain: &[Vec<u8>], crls: &[Vec<u8>], anchors: &[TrustAnchor]) -> Result<VerifiedEndorsement, ChainFailure> {
    validate_endorsement_chain(&TestValueSyntax, chain, crls, &context(anchors))
}
fn ek() -> EkPublicKey {
    ecc_public(&key("leaf-ek"))
}
fn standard() -> (Pki, Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<TrustAnchor>) {
    let pki = Pki::new("vendor-a");
    let chain = pki.chain(&ek(), &[0x11]);
    let crls = pki.crls(&[], &[]);
    let anchors = vec![pki.anchor(RevocationMode::CrlRequired, &[ECC_CLASS, RSA_CLASS])];
    (pki, chain, crls, anchors)
}

// ------------------------------------------------------------------------------------------------
// A1, A2, A11: the procedure P4-P15
// ------------------------------------------------------------------------------------------------
/// Positive: a TEST-VALUE chain to a committed anchor verifies at the committed reference time and yields the canonical
/// EK key, the anchor hash and the SHA-256 of every certificate; the result does not depend on anything else.
#[test]
fn test_value_chain_verifies_to_a_committed_anchor_and_yields_the_canonical_ek() {
    let (pki, chain, crls, anchors) = standard();
    let verified = validate(&chain, &crls, &anchors).unwrap();
    assert_eq!(verified.anchor, pki.root_hash());
    assert_eq!(verified.leaf_key, ek());
    let path: Vec<Hash> = chain.iter().map(|c| Sha256::digest(c).into()).collect();
    assert_eq!(verified.path, path);
    assert_eq!(validate(&chain, &crls, &anchors), Ok(verified));
    // An RSA-class EK under the same PKI, and an anchor that publishes no CRL with no CRL supplied.
    let rsa = rsa_like_public("tpm-1/rsa", 2048);
    assert_eq!(validate(&pki.chain(&rsa, &[0x12]), &crls, &anchors).unwrap().leaf_key, rsa);
    let no_crl = vec![pki.anchor(RevocationMode::NoCrlPublished, &[ECC_CLASS])];
    validate(&chain, &[], &no_crl).unwrap();
}

/// A11 fail-closed: in the Production class only the reviewed production syntax may run; the TEST-VALUE syntax (the only
/// implementation this branch has) is refused before anything is parsed, so an admission supported only by an authority
/// signature can never pass a Production witness verification.
#[test]
fn production_class_refuses_the_test_value_syntax() {
    let (_, chain, crls, anchors) = standard();
    let production = ChainContext { class: AdmissionClass::Production, reference_time: T_REF, anchors: &anchors };
    assert_eq!(
        validate_endorsement_chain(&TestValueSyntax, &chain, &crls, &production),
        Err(ChainFailure::ParserUnavailable)
    );
}

/// P4: the anchor is the committed hash of the exact last certificate; another root (even with the same name and key,
/// re-signed with a different serial) is not an anchor; too many intermediates for the anchor are refused.
#[test]
fn chain_to_an_uncommitted_root_is_refused() {
    let (pki, chain, crls, anchors) = standard();
    let other = Pki::new("vendor-b");
    assert_eq!(validate(&chain, &crls, &[other.anchor(RevocationMode::CrlRequired, &[ECC_CLASS])]), Err(ChainFailure::UntrustedRoot));
    let mut lookalike = pki.root_spec.clone();
    lookalike.serial = vec![0x7f];
    let mut forged = chain.clone();
    forged[2] = lookalike.sign(&pki.root_key);
    assert_eq!(validate(&forged, &crls, &anchors), Err(ChainFailure::UntrustedRoot));
    let mut strict = anchors.clone();
    strict[0].constraints.max_intermediates = 0;
    assert_eq!(validate(&chain, &crls, &strict), Err(ChainFailure::PathTooLong));
    validate(&[chain[0].clone(), chain[1].clone(), chain[2].clone()], &crls, &anchors).unwrap();
}

/// P7 at the committed reference time, endpoints inclusive: an expired EK certificate and a not-yet-valid intermediate are
/// refused; the same certificates verify when the reference time lies inside their validity.
#[test]
fn expired_and_not_yet_valid_certificates_are_refused_at_the_reference_time() {
    let (pki, _, crls, anchors) = standard();
    let mut expired = pki.ek_spec(&ek(), &[0x11]);
    expired.not_after = T_REF - 1;
    let chain = vec![expired.sign(&pki.intermediate_key), pki.intermediate(), pki.root()];
    assert_eq!(validate(&chain, &crls, &anchors), Err(ChainFailure::Expired));
    let mut boundary = pki.ek_spec(&ek(), &[0x11]);
    boundary.not_after = T_REF;
    boundary.not_before = T_REF;
    let chain = vec![boundary.sign(&pki.intermediate_key), pki.intermediate(), pki.root()];
    validate(&chain, &crls, &anchors).unwrap();
    let mut early = pki.intermediate_spec.clone();
    early.not_before = T_REF + 1;
    let chain = vec![pki.ek_spec(&ek(), &[0x11]).sign(&pki.intermediate_key), early.sign(&pki.root_key), pki.root()];
    assert_eq!(validate(&chain, &crls, &anchors), Err(ChainFailure::NotYetValid));
}

/// The reference time is an input from committed chain data: the same chain is valid at one committed time and refused
/// at another; the witness must name exactly the committed time (`ReferenceTimeMismatch`, see the witness tests).
#[test]
fn the_result_depends_on_the_committed_reference_time_only() {
    let (_, chain, crls, anchors) = standard();
    validate(&chain, &crls, &anchors).unwrap();
    let later = ChainContext { class: AdmissionClass::LegacyTest, reference_time: 2_000_000_001, anchors: &anchors };
    assert_eq!(validate_endorsement_chain(&TestValueSyntax, &chain, &crls, &later), Err(ChainFailure::Expired));
}

/// P14: a CRL from the EK certificate's issuer listing its serial, or from the root listing the intermediate, revokes the
/// chain; stale, future, wrongly signed, unauthorised, missing, unused, delta, indirect, partial and duplicated CRLs are
/// each refused for their own reason.
#[test]
fn revoked_certificates_and_bad_revocation_evidence_are_refused() {
    let (pki, chain, crls, anchors) = standard();
    validate(&chain, &crls, &anchors).unwrap();
    assert_eq!(validate(&chain, &pki.crls(&[&[0x11]], &[]), &anchors), Err(ChainFailure::Revoked));
    assert_eq!(validate(&chain, &pki.crls(&[], &[&[0x02]]), &anchors), Err(ChainFailure::Revoked));
    validate(&chain, &pki.crls(&[&[0x99]], &[&[0x98]]), &anchors).unwrap();
    let with = |edit: &dyn Fn(&mut CrlSpec)| {
        let mut spec = crl_spec(&pki.intermediate_name(), &[]);
        edit(&mut spec);
        vec![spec.sign(&pki.intermediate_key), crls[1].clone()]
    };
    assert_eq!(validate(&chain, &with(&|s| s.next_update = Some(T_REF - 1)), &anchors), Err(ChainFailure::StaleRevocation));
    assert_eq!(validate(&chain, &with(&|s| s.this_update = T_REF + 1), &anchors), Err(ChainFailure::StaleRevocation));
    validate(&chain, &with(&|s| s.next_update = None), &anchors).unwrap();
    assert_eq!(validate(&chain, &with(&|s| s.delta = true), &anchors), Err(ChainFailure::RevocationUnsupported));
    assert_eq!(validate(&chain, &with(&|s| s.indirect = true), &anchors), Err(ChainFailure::RevocationUnsupported));
    assert_eq!(validate(&chain, &with(&|s| s.partial = true), &anchors), Err(ChainFailure::RevocationUnsupported));
    assert_eq!(validate(&chain, &with(&|s| s.version = 1), &anchors), Err(ChainFailure::RevocationUnsupported));
    assert_eq!(
        validate(&chain, &with(&|s| s.unrecognised_critical = vec![vec![0x2a]]), &anchors),
        Err(ChainFailure::RevocationUnsupported)
    );
    // Signed by a key that is not the issuer's.
    let wrong_signer = vec![crl_spec(&pki.intermediate_name(), &[]).sign(&key("intruder")), crls[1].clone()];
    assert_eq!(validate(&chain, &wrong_signer, &anchors), Err(ChainFailure::RevocationIssuer));
    // The issuer may not sign CRLs (no cRLSign).
    let mut no_crl_sign = pki.intermediate_spec.clone();
    no_crl_sign.key_usage = Some(key_usage::KEY_CERT_SIGN);
    let chain_no_crl_sign = vec![chain[0].clone(), no_crl_sign.sign(&pki.root_key), pki.root()];
    assert_eq!(validate(&chain_no_crl_sign, &crls, &anchors), Err(ChainFailure::RevocationIssuer));
    // Missing under CrlRequired; unused material; two CRLs for one issuer.
    assert_eq!(validate(&chain, &crls[..1], &anchors), Err(ChainFailure::RevocationMissing));
    let stranger = crl_spec("stranger", &[]).sign(&key("stranger"));
    let mut extra = crls.clone();
    extra.push(stranger);
    assert_eq!(validate(&chain, &extra, &anchors), Err(ChainFailure::RevocationUnused));
    let mut doubled = crls.clone();
    doubled.push(crl_spec(&pki.intermediate_name(), &[&[0x77]]).sign(&pki.intermediate_key));
    assert_eq!(validate(&chain, &doubled, &anchors), Err(ChainFailure::RevocationUnsupported));
}

/// P5, P6: issuer Name and key-identifier linkage, the signature under the issuer's key, and the algorithm allowed by the
/// anchor.
#[test]
fn issuer_linkage_signatures_and_algorithms_are_enforced() {
    let (pki, chain, crls, anchors) = standard();
    let mut renamed = pki.ek_spec(&ek(), &[0x11]);
    renamed.issuer = name("someone else");
    let c = vec![renamed.sign(&pki.intermediate_key), chain[1].clone(), chain[2].clone()];
    assert_eq!(validate(&c, &crls, &anchors), Err(ChainFailure::IssuerMismatch));
    let mut wrong_aki = pki.ek_spec(&ek(), &[0x11]);
    wrong_aki.authority_key_id = Some(vec![9; 20]);
    let c = vec![wrong_aki.sign(&pki.intermediate_key), chain[1].clone(), chain[2].clone()];
    assert_eq!(validate(&c, &crls, &anchors), Err(ChainFailure::IssuerMismatch));
    let c = vec![pki.ek_spec(&ek(), &[0x11]).sign(&key("intruder")), chain[1].clone(), chain[2].clone()];
    assert_eq!(validate(&c, &crls, &anchors), Err(ChainFailure::BadSignature));
    let mut rsa_signed = pki.ek_spec(&ek(), &[0x11]);
    rsa_signed.signature_algorithm = SignatureAlgorithm::RsaPkcs1Sha256;
    let c = vec![rsa_signed.sign(&pki.intermediate_key), chain[1].clone(), chain[2].clone()];
    assert_eq!(validate(&c, &crls, &anchors), Err(ChainFailure::UnsupportedAlgorithm));
    let mut rsa_allowed = anchors.clone();
    rsa_allowed[0].constraints.signature_algorithms.insert(SignatureAlgorithm::RsaPkcs1Sha256);
    // Allowed by the anchor, but the TEST-VALUE syntax verifies only P-256: a bad signature, never a pass.
    assert_eq!(validate(&c, &crls, &rsa_allowed), Err(ChainFailure::BadSignature));
}

/// P2, P3, P8-P13 and the bounds, one rule at a time.
#[test]
fn ca_constraints_key_usage_eku_names_extensions_keys_and_bounds_are_enforced() {
    let (pki, chain, crls, anchors) = standard();
    let leaf = |edit: &dyn Fn(&mut CertSpec)| {
        let mut s = pki.ek_spec(&ek(), &[0x11]);
        edit(&mut s);
        vec![s.sign(&pki.intermediate_key), chain[1].clone(), chain[2].clone()]
    };
    let issuer = |edit: &dyn Fn(&mut CertSpec)| {
        let mut s = pki.intermediate_spec.clone();
        edit(&mut s);
        vec![chain[0].clone(), s.sign(&pki.root_key), chain[2].clone()]
    };
    use ChainFailure as F;
    let cases: Vec<(&str, Vec<Vec<u8>>, F)> = vec![
        ("P2 version 2", leaf(&|s| s.version = 2), F::Malformed),
        ("P2 empty serial", leaf(&|s| s.serial = vec![]), F::Malformed),
        ("P2 serial with a leading zero octet", leaf(&|s| s.serial = vec![0, 0x11]), F::Malformed),
        ("P2 serial longer than 20 octets", leaf(&|s| s.serial = vec![1; 21]), F::Malformed),
        ("P8 issuer not a CA", issuer(&|s| s.basic_constraints.as_mut().unwrap().ca = false), F::NotCa),
        ("P8 issuer basicConstraints not critical", issuer(&|s| s.basic_constraints.as_mut().unwrap().critical = false), F::NotCa),
        ("P8 issuer without basicConstraints", issuer(&|s| s.basic_constraints = None), F::NotCa),
        ("P8 issuer without keyCertSign", issuer(&|s| s.key_usage = Some(key_usage::CRL_SIGN)), F::KeyUsage),
        ("P8 issuer without keyUsage", issuer(&|s| s.key_usage = None), F::KeyUsage),
        ("P9 EK certificate claims cA", leaf(&|s| s.basic_constraints.as_mut().unwrap().ca = true), F::LeafIsCa),
        ("P9 ECC EK without keyAgreement", leaf(&|s| s.key_usage = Some(key_usage::KEY_ENCIPHERMENT)), F::KeyUsage),
        ("P9 EK with keyCertSign", leaf(&|s| s.key_usage = Some(key_usage::KEY_AGREEMENT | key_usage::KEY_CERT_SIGN)), F::KeyUsage),
        ("P9 EK without keyUsage", leaf(&|s| s.key_usage = None), F::KeyUsage),
        ("P10 no extendedKeyUsage", leaf(&|s| s.extended_key_usage = None), F::MissingEkEku),
        ("P10 EKU without tcg-kp-EKCertificate", leaf(&|s| s.extended_key_usage = Some(vec![vec![0x2b, 6, 1]])), F::MissingEkEku),
        ("P10 anyExtendedKeyUsage", leaf(&|s| s.extended_key_usage.as_mut().unwrap().push(oid::ANY_EXTENDED_KEY_USAGE.to_vec())), F::MissingEkEku),
        ("P11 empty subject without SAN", leaf(&|s| s.subject_alt_name = None), F::NameForm),
        ("P11 empty subject, SAN not critical", leaf(&|s| s.subject_alt_name.as_mut().unwrap().critical = false), F::NameForm),
        ("P11 SAN with another GeneralName form", leaf(&|s| s.subject_alt_name.as_mut().unwrap().other_forms = 1), F::NameForm),
        ("P11 SAN without the model attribute", leaf(&|s| { s.subject_alt_name.as_mut().unwrap().directory_names[0].remove(1); }), F::NameForm),
        ("P11 SAN with a repeated attribute", leaf(&|s| { let dn = &mut s.subject_alt_name.as_mut().unwrap().directory_names[0]; dn[1] = dn[0].clone(); }), F::NameForm),
        ("P11 two directoryNames", leaf(&|s| { let san = s.subject_alt_name.as_mut().unwrap(); let dn = san.directory_names[0].clone(); san.directory_names.push(dn); }), F::NameForm),
        ("P12 unrecognised critical extension (EK)", leaf(&|s| s.unrecognised_critical = vec![vec![0x2a, 3]]), F::UnsupportedCriticalExtension),
        ("P12 unrecognised critical extension (issuer)", issuer(&|s| s.unrecognised_critical = vec![vec![0x2a, 3]]), F::UnsupportedCriticalExtension),
        ("P13 P-384 EK key", leaf(&|s| s.public_key = EkPublicKey::Ecc { curve: TPM_ECC_NIST_P384, x: vec![1; 48], y: vec![2; 48] }), F::UnsupportedKey(IdentityFailure::UnsupportedCurve)),
        ("P13 point not on the curve", leaf(&|s| s.public_key = EkPublicKey::Ecc { curve: TPM_ECC_NIST_P256, x: vec![1; 32], y: vec![2; 32] }), F::UnsupportedKey(IdentityFailure::PointNotOnCurve)),
        ("P13 RSA modulus of the wrong size", leaf(&|s| { s.public_key = rsa_like_public("small", 2048); if let EkPublicKey::Rsa { bits, .. } = &mut s.public_key { *bits = 1024 } s.key_usage = Some(key_usage::KEY_ENCIPHERMENT); }), F::UnsupportedKey(IdentityFailure::RsaModulusSize)),
    ];
    for (label, c, expected) in cases {
        assert_eq!(validate(&c, &crls, &anchors), Err(expected), "{label}");
    }
    // P13: an anchor that certifies only RSA EKs refuses this ECC EK.
    let rsa_only = vec![pki.anchor(RevocationMode::CrlRequired, &[RSA_CLASS])];
    assert_eq!(validate(&chain, &crls, &rsa_only), Err(F::ClassNotAllowed));
    // P8: pathLenConstraint 0 on the root forbids the intermediate below it.
    let mut root = pki.root_spec.clone();
    root.basic_constraints.as_mut().unwrap().path_len = Some(0);
    let root_bytes = root.sign(&pki.root_key);
    let mut pinned = anchors.clone();
    pinned[0].root_cert_der_sha256 = Sha256::digest(&root_bytes).into();
    let c = vec![chain[0].clone(), chain[1].clone(), root_bytes];
    assert_eq!(validate(&c, &crls, &pinned), Err(F::PathLength));
    // Bounds and shape.
    assert_eq!(validate(&chain[..1], &crls, &anchors), Err(F::ChainLength));
    let six = vec![chain[0].clone(), chain[1].clone(), chain[1].clone(), chain[1].clone(), chain[1].clone(), chain[2].clone()];
    assert_eq!(validate(&six, &crls, &anchors), Err(F::ChainLength));
    let repeated = vec![chain[0].clone(), chain[1].clone(), chain[1].clone(), chain[2].clone()];
    assert_eq!(validate(&repeated, &crls, &anchors), Err(F::ChainLength));
    let mut oversize = chain.clone();
    oversize[0] = vec![0; MAX_CERTIFICATE_BYTES + 1];
    assert_eq!(validate(&oversize, &crls, &anchors), Err(F::Oversize));
    let mut garbage = chain.clone();
    garbage[0] = b"not a certificate".to_vec();
    assert_eq!(validate(&garbage, &crls, &anchors), Err(F::Malformed));
    let five_crls = vec![crls[0].clone(); MAX_CRLS + 1];
    assert_eq!(validate(&chain, &five_crls, &anchors), Err(F::Oversize));
    // Positive control for every case above.
    validate(&chain, &crls, &anchors).unwrap();
}

// ------------------------------------------------------------------------------------------------
// A7: the committed attestation witness; A3: what a transcript cannot show
// ------------------------------------------------------------------------------------------------
struct Case {
    tpm: TestTpm,
    statement: Provenance,
    witness: AttestationWitness,
    raw: Vec<u8>,
    anchors: Vec<TrustAnchor>,
    classes: IdentityClasses,
}
/// A one-class (ECC) TEST-VALUE admission: the simulator profile, its version-2 statement whose identity is the
/// simulator EK and whose witness commitment is the real commitment of the witness built here.
fn case() -> Case {
    let pki = Pki::new("vendor-a");
    let tpm = TestTpm::stripped(Strip::ConsistentProvenance(pki.root_hash()));
    let ek = tpm.simulator_ek();
    let witness = witness(vec![endorsement(&pki, &ek, &[0x21])], vec![activation(0, tpm.consistent_provenance(pki.root_hash()).ak_name, "tpm-1")]);
    let raw = witness.encode().unwrap();
    let mut statement = tpm.consistent_provenance(pki.root_hash());
    statement.endorsement.as_mut().unwrap().witness_sha256 = domain_hash(WITNESS_DOMAIN, &raw);
    let classes = IdentityClasses::new(vec![class_of(ECC_TAG, TEST_ATTRIBUTES)]).unwrap();
    Case { tpm, statement, witness, raw, anchors: vec![pki.anchor(RevocationMode::CrlRequired, &[ECC_CLASS])], classes }
}
fn check(c: &Case, statement: &Provenance, raw: Option<&[u8]>) -> Result<(), WitnessFailure> {
    let ctx = WitnessContext { chain: context(&c.anchors), identity_classes: &c.classes };
    verify_witness(statement, raw, &ctx, &TestValueSyntax)
}
/// Re-commit an edited witness so that a single later check fails.
fn recommitted(c: &Case, edit: &dyn Fn(&mut AttestationWitness)) -> (Provenance, Vec<u8>) {
    let mut w = c.witness.clone();
    edit(&mut w);
    let raw = w.encode().unwrap();
    let mut s = c.statement.clone();
    s.endorsement.as_mut().unwrap().witness_sha256 = domain_hash(WITNESS_DOMAIN, &raw);
    (s, raw)
}

/// A7 codec: canonical, bounded, committed by `H(WITNESS_DOMAIN, bytes)`; one activation record per endorsement.
#[test]
fn witness_codec_is_canonical_bounded_and_committed() {
    let c = case();
    assert_eq!(AttestationWitness::decode(&c.raw).unwrap(), c.witness);
    assert_eq!(c.witness.commitment().unwrap(), domain_hash(WITNESS_DOMAIN, &c.raw));
    let mut manual = Sha256::new();
    manual.update(b"MUTINY-BUILD8-ATTESTATION-WITNESS-V1\0");
    manual.update(&c.raw);
    assert_eq!(c.witness.commitment().unwrap(), <[u8; 32]>::from(manual.finalize()));
    let mut trailing = c.raw.clone();
    trailing.push(0);
    assert!(AttestationWitness::decode(&trailing).is_err());
    assert!(AttestationWitness::decode(&c.raw[..c.raw.len() - 1]).is_err());
    let bad = |edit: &dyn Fn(&mut AttestationWitness)| {
        let mut w = c.witness.clone();
        edit(&mut w);
        w.encode()
    };
    assert_eq!(bad(&|w| w.reference_time = 0), Err(Error::InvalidCounter));
    assert_eq!(bad(&|w| w.endorsements.clear()), Err(Error::Capacity));
    assert_eq!(bad(&|w| w.activation.clear()), Err(Error::Capacity));
    assert_eq!(bad(&|w| { let e = w.endorsements[0].clone(); for _ in 0..4 { w.endorsements.push(e.clone()); } }), Err(Error::Capacity));
    assert_eq!(bad(&|w| w.endorsements[0].ek_public_area = vec![0; 1025]), Err(Error::Oversize));
    assert_eq!(bad(&|w| w.endorsements[0].certificates.truncate(1)), Err(Error::Oversize));
    assert_eq!(bad(&|w| w.endorsements[0].crls = vec![vec![1; 32769]]), Err(Error::Oversize));
    assert_eq!(bad(&|w| w.endorsements[0].crls = vec![vec![1]; 5]), Err(Error::Oversize));
    // Whole-witness bound: four endorsements of five 4096-byte certificates and four 32768-byte CRLs exceed 128 KiB.
    assert_eq!(
        bad(&|w| {
            let e = mutiny_consensus_v8::attestation_witness::EndorsementEvidence {
                ek_public_area: vec![1; 64],
                certificates: vec![vec![1; 4096]; 5],
                crls: vec![vec![2; 32768]; 4],
            };
            w.endorsements = vec![e; 4];
            w.activation = vec![w.activation[0].clone(); 4];
        }),
        Err(Error::Oversize)
    );
}

/// A7 verification: absent, oversize, non-canonical, uncommitted and version-1 cases are refused for their own reason;
/// a consistent witness verifies.
#[test]
fn witness_absent_oversize_noncanonical_or_uncommitted_is_refused() {
    let c = case();
    check(&c, &c.statement, Some(&c.raw)).unwrap();
    assert_eq!(check(&c, &c.statement, None), Err(WitnessFailure::Missing));
    assert_eq!(check(&c, &c.statement, Some(&vec![0x80; 131_073])), Err(WitnessFailure::Encoding(Error::Oversize)));
    let mut trailing = c.raw.clone();
    trailing.push(0);
    assert!(matches!(check(&c, &c.statement, Some(&trailing)), Err(WitnessFailure::Encoding(_))));
    // Same structure, the last byte (inside the last activation digest) changed: a canonical witness, but not the
    // committed one.
    let mut other = c.raw.clone();
    *other.last_mut().unwrap() ^= 1;
    AttestationWitness::decode(&other).unwrap();
    assert_eq!(check(&c, &c.statement, Some(&other)), Err(WitnessFailure::CommitmentMismatch));
    let v1 = c.tpm.consistent_provenance_v1(c.statement.endorsement_root);
    assert_eq!(check(&c, &v1, Some(&c.raw)), Err(WitnessFailure::NotVersion2));
}

/// A7/A4: the witness binds the statement's identities to certified keys: the statement identity must be the identity of
/// the certified key, the TPM public area must carry the same key in the committed class template, the identity root must
/// be the chain's anchor, the counts must match the committed class list, and the reference time must be the committed one.
#[test]
fn witness_binds_statement_identities_to_certified_keys() {
    let c = case();
    // Identity of another key.
    let mut s = c.statement.clone();
    s.endorsement.as_mut().unwrap().identities[0].1 = TestTpm::with_identity("other").ek_identity();
    assert_eq!(check(&c, &s, Some(&c.raw)), Err(WitnessFailure::IdentityMismatch(0)));
    // Root other than the anchor.
    let mut s = c.statement.clone();
    s.endorsement.as_mut().unwrap().identities[0].0 = [0x55; 32];
    assert_eq!(check(&c, &s, Some(&c.raw)), Err(WitnessFailure::RootMismatch(0)));
    let pki = Pki::new("vendor-a");
    // The TPM public area carries a different key than the certificate.
    let other_key = TestTpm::with_identity("other").simulator_ek();
    let (s, raw) = recommitted(&c, &|w| w.endorsements[0].ek_public_area = public_area(&template(ECC_TAG, TEST_ATTRIBUTES), &other_key));
    assert_eq!(check(&c, &s, Some(&raw)), Err(WitnessFailure::KeyMismatch(0)));
    // A template other than the committed class template.
    let ek = c.tpm.simulator_ek();
    let (s, raw) = recommitted(&c, &|w| w.endorsements[0].ek_public_area = public_area(&template(ECC_TAG, TEST_ATTRIBUTES ^ 0x40), &ek));
    assert_eq!(check(&c, &s, Some(&raw)), Err(WitnessFailure::PublicArea(0, IdentityFailure::TemplateMismatch)));
    // A malformed public area.
    let (s, raw) = recommitted(&c, &|w| w.endorsements[0].ek_public_area = vec![0, 2, 0, 0x23]);
    assert_eq!(check(&c, &s, Some(&raw)), Err(WitnessFailure::PublicArea(0, IdentityFailure::PublicAreaMalformed)));
    // The certificate chain fails (revoked EK).
    let (s, raw) = recommitted(&c, &|w| w.endorsements[0].crls = pki.crls(&[&[0x21]], &[]));
    assert_eq!(check(&c, &s, Some(&raw)), Err(WitnessFailure::Chain(0, ChainFailure::Revoked)));
    // Class count: two committed classes, one endorsement.
    let two = IdentityClasses::new(vec![class_of(RSA_TAG, TEST_ATTRIBUTES), class_of(ECC_TAG, TEST_ATTRIBUTES)]).unwrap();
    let ctx = WitnessContext { chain: context(&c.anchors), identity_classes: &two };
    assert_eq!(verify_witness(&c.statement, Some(&c.raw), &ctx, &TestValueSyntax), Err(WitnessFailure::ClassCount));
    // Reference time other than the committed one.
    let (s, raw) = recommitted(&c, &|w| w.reference_time = T_REF + 1);
    assert_eq!(check(&c, &s, Some(&raw)), Err(WitnessFailure::ReferenceTimeMismatch));
    // Activation record of another attestation key, another index, or with a zero digest.
    let (s, raw) = recommitted(&c, &|w| w.activation[0].ak_name[33] ^= 1);
    assert_eq!(check(&c, &s, Some(&raw)), Err(WitnessFailure::Activation(0)));
    let (s, raw) = recommitted(&c, &|w| w.activation[0].ek_index = 1);
    assert_eq!(check(&c, &s, Some(&raw)), Err(WitnessFailure::Activation(0)));
    let (s, raw) = recommitted(&c, &|w| w.activation[0].secret_commitment = [0; 32]);
    assert_eq!(check(&c, &s, Some(&raw)), Err(WitnessFailure::Activation(0)));
    // Production class: no reviewed syntax exists, verification fails closed.
    let ctx = WitnessContext {
        chain: ChainContext { class: AdmissionClass::Production, reference_time: T_REF, anchors: &c.anchors },
        identity_classes: &c.classes,
    };
    assert_eq!(
        verify_witness(&c.statement, Some(&c.raw), &ctx, &TestValueSyntax),
        Err(WitnessFailure::Chain(0, ChainFailure::ParserUnavailable))
    );
    // Positive control.
    check(&c, &c.statement, Some(&c.raw)).unwrap();
}

/// A3, DEMONSTRATED LIMIT: a saved transcript is not sound against a colluding verifier. The simulator has no TPM at all;
/// a "verifier" that knows the secret (it chose it) simply hands it to the software actor and records the exchange. Every
/// check a validator can run on the retained record (index, attestation-key Name, nonzero digests, the commitment of the
/// witness, the certified EK chain, which is public) passes. Only an honest challenger whose secret the prover cannot learn
/// shows possession of the EK, and after sealing no such challenger exists in the protocol (design A3-Q1).
#[test]
fn colluding_verifier_transcript_is_accepted_by_every_transcript_check() {
    let c = case();
    let secret = b"secret chosen and leaked by a colluding verifier (TEST-VALUE)";
    let (s, raw) = recommitted(&c, &|w| {
        w.activation[0].secret_commitment = domain_hash(b"MUTINY-BUILD8-ACTIVATION-SECRET-V1", secret);
        w.activation[0].credential_blob_sha256 = domain_hash(b"MUTINY-BUILD8-TEST-VALUE-NO-TPM-V1", b"blob");
        w.activation[0].encrypted_seed_sha256 = domain_hash(b"MUTINY-BUILD8-TEST-VALUE-NO-TPM-V1", b"seed");
    });
    check(&c, &s, Some(&raw)).unwrap();
}

// ------------------------------------------------------------------------------------------------
// A5: the accepted PCR-profile set and the requalification check
// ------------------------------------------------------------------------------------------------
fn profile(selection: [u8; 3], digest: Hash) -> PcrProfile {
    PcrProfile { bank: SHA256_BANK, selection, digest, interpretation: INTERPRETATION_QUOTE_COMPOSITE }
}
#[test]
fn accepted_profile_set_codec_commitment_and_membership() {
    let tpm = TestTpm::new();
    let admitted = profile(tpm.profile().pcr_bitmap, tpm.profile().pcr_digest);
    let other = profile([0x80, 0, 0], [7; 32]);
    let set = AcceptedPcrProfiles::new(UPDATE_FROZEN_AT_GENESIS, vec![other, admitted]).unwrap();
    let raw = set.encode();
    assert_eq!(AcceptedPcrProfiles::decode(&raw).unwrap(), set);
    assert_eq!(set.commitment(), domain_hash(ACCEPTED_PCR_PROFILES_DOMAIN, &raw));
    // Insertion order does not matter: entries are ordered by identifier.
    assert_eq!(AcceptedPcrProfiles::new(UPDATE_FROZEN_AT_GENESIS, vec![admitted, other]).unwrap().encode(), raw);
    // The identifier is the C4 platform-profile digest the statement already carries.
    let statement = TestTpm::stripped(Strip::ConsistentProvenance([1; 32])).consistent_provenance([1; 32]);
    assert_eq!(set.check_accepted(tpm.profile().pcr_bitmap, tpm.profile().pcr_digest), Ok(statement.platform_profile_sha256));
    assert_eq!(set.check_accepted([0x95, 0, 0], [8; 32]), Err(PcrFailure::NotAccepted));
    use PcrFailure as F;
    assert_eq!(AcceptedPcrProfiles::new(2, vec![admitted]), Err(F::UnknownUpdateRule));
    assert_eq!(AcceptedPcrProfiles::new(UPDATE_FROZEN_AT_GENESIS, vec![]), Err(F::Count));
    assert_eq!(AcceptedPcrProfiles::new(UPDATE_FROZEN_AT_GENESIS, (0..65u8).map(|i| profile([1, 0, 0], [i; 32])).collect()), Err(F::Count));
    assert_eq!(AcceptedPcrProfiles::new(UPDATE_FROZEN_AT_GENESIS, vec![PcrProfile { bank: 0x0004, ..admitted }]), Err(F::UnsupportedBank));
    assert_eq!(AcceptedPcrProfiles::new(UPDATE_FROZEN_AT_GENESIS, vec![profile([0; 3], [1; 32])]), Err(F::EmptySelection));
    assert_eq!(AcceptedPcrProfiles::new(UPDATE_FROZEN_AT_GENESIS, vec![PcrProfile { interpretation: 2, ..admitted }]), Err(F::UnknownInterpretation));
    assert_eq!(AcceptedPcrProfiles::new(UPDATE_FROZEN_AT_GENESIS, vec![admitted, admitted]), Err(F::Duplicate));
    let mut trailing = raw.clone();
    trailing.push(0);
    assert_eq!(AcceptedPcrProfiles::decode(&trailing), Err(F::Codec));
}

/// A5 day-one requalification: a fresh quote by the ADMITTED attestation key over a profile of the committed set
/// requalifies without any owner or authority; a quote over another challenge, by another key, over the old digest, or
/// to a profile outside the set is refused.
#[test]
fn requalification_requires_the_admitted_ak_a_fresh_quote_and_an_accepted_profile() {
    let tpm = TestTpm::new();
    let updated_digest: Hash = Sha256::digest(b"TEST-VALUE PCR digest after a firmware update").into();
    let updated = tpm.edited(|p| p.pcr_digest = updated_digest);
    let set = AcceptedPcrProfiles::new(
        UPDATE_FROZEN_AT_GENESIS,
        vec![profile(tpm.profile().pcr_bitmap, tpm.profile().pcr_digest), profile(tpm.profile().pcr_bitmap, updated_digest)],
    )
    .unwrap();
    let challenge = domain_hash(b"MUTINY-BUILD8-TEST-VALUE-REQUALIFICATION-V1", b"parent and node");
    let quote = updated.quote(challenge);
    let bitmap = tpm.profile().pcr_bitmap;
    assert_eq!(
        set.check_requalification(tpm.profile(), bitmap, updated_digest, challenge, &quote),
        Ok(mutiny_consensus_v8::provenance::platform_profile(bitmap, updated_digest))
    );
    assert_eq!(set.check_requalification(tpm.profile(), bitmap, updated_digest, [9; 32], &quote), Err(PcrFailure::Quote));
    let stranger = TestTpm::with_identity("stranger").edited(|p| p.pcr_digest = updated_digest);
    assert_eq!(set.check_requalification(tpm.profile(), bitmap, updated_digest, challenge, &stranger.quote(challenge)), Err(PcrFailure::Quote));
    assert_eq!(set.check_requalification(tpm.profile(), bitmap, updated_digest, challenge, &tpm.quote(challenge)), Err(PcrFailure::Quote));
    let narrow = AcceptedPcrProfiles::new(UPDATE_FROZEN_AT_GENESIS, vec![profile(bitmap, tpm.profile().pcr_digest)]).unwrap();
    assert_eq!(narrow.check_requalification(tpm.profile(), bitmap, updated_digest, challenge, &quote), Err(PcrFailure::NotAccepted));
}
