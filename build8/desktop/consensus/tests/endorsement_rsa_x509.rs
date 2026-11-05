//! PUBLIC TEST-VALUE RSA certificate/CRL verification. No manufacturer roots,
//! hardware custody material or Mutiny RSA signing authority is used or claimed.
#[path = "support/x509_syntax.rs"]
mod x509_syntax;
#[path = "support/test_value_x509.rs"]
mod test_value_x509;
use mutiny_consensus_v8::{ek_chain::*, endorsement_identity::*, provenance::AdmissionClass};
use test_value_x509::*;
use x509_syntax::X509Syntax;
use x509_cert::der::{Any, Encode};
const ALGORITHMS: [SignatureAlgorithm; 4] = [
    SignatureAlgorithm::RsaPkcs1Sha256, SignatureAlgorithm::RsaPkcs1Sha384,
    SignatureAlgorithm::RsaPssSha256, SignatureAlgorithm::RsaPssSha384,
];
fn leaf() -> EkPublicKey { CaKey::P256(p256_key("public-rsa-leaf-ek")).public() }
fn verify(chain: &[Vec<u8>], crls: &[Vec<u8>], anchors: &[TrustAnchor]) -> Result<VerifiedEndorsement, ChainFailure> {
    validate_endorsement_chain(&X509Syntax, chain, crls, &ChainContext { class: AdmissionClass::Production, reference_time: T_REF, anchors })
}
#[test]
fn rsa_ca_chains_and_crls_verify_exact_bytes_for_each_locked_algorithm() {
    for algorithm in ALGORITHMS {
        let pki = X509Pki::with_ca_keys("PUBLIC-RSA-X509-TEST", public_rsa_fixture(algorithm), public_rsa_fixture(algorithm));
        let chain=pki.chain(&leaf(), &[0x21]);let crls=pki.crls(&[], &[]);
        let anchors=vec![pki.anchor(RevocationMode::CrlRequired, &[(ECC_TAG, TPM_ECC_NIST_P256)], &[algorithm])];
        assert_eq!(verify(&chain,&crls,&anchors).unwrap().leaf_key,leaf());
        let mut bad=chain.clone();*bad[0].last_mut().unwrap()^=1;
        assert_eq!(verify(&bad,&crls,&anchors),Err(ChainFailure::BadSignature));
        let mut bad_crl=crls.clone();*bad_crl[0].last_mut().unwrap()^=1;
        assert_eq!(verify(&chain,&bad_crl,&anchors),Err(ChainFailure::RevocationIssuer));
        assert_eq!(verify(&chain,&pki.crls(&[&[0x21]], &[]),&anchors),Err(ChainFailure::Revoked));
        let mut foreign=anchors.clone();foreign[0].root_cert_der_sha256[0]^=1;
        assert_eq!(verify(&chain,&crls,&foreign),Err(ChainFailure::UntrustedRoot));
    }
}
#[test]
fn rsa_signatures_are_bounded_exact_width_hash_and_padding_bound() {
    let message=b"PUBLIC TEST RSA CERTIFICATE SIGNED BYTES";
    for algorithm in ALGORITHMS {
        let ca=public_rsa_fixture(algorithm);let key=ca.public();let sig=ca.sign(message);
        assert!(X509Syntax.verify_signature(&key,algorithm,message,&sig));
        assert!(!X509Syntax.verify_signature(&key,algorithm,b"altered",&sig));
        assert!(!X509Syntax.verify_signature(&key,algorithm,message,&sig[1..]));
        let oversized=[vec![0],sig.clone()].concat();
        assert!(!X509Syntax.verify_signature(&key,algorithm,message,&oversized));
        for other in ALGORITHMS.into_iter().filter(|a|*a!=algorithm) {
            assert!(!X509Syntax.verify_signature(&key,other,message,&sig));
        }
        assert!(!X509Syntax.verify_signature(&leaf(),algorithm,message,&sig));
        let EkPublicKey::Rsa { bits, exponent, mut modulus }=key else { unreachable!() };
        modulus[0]&=0x7f;
        assert!(!X509Syntax.verify_signature(&EkPublicKey::Rsa { bits, exponent, modulus },algorithm,message,&sig));
    }
}
#[test]
fn pss_parameters_require_exact_hash_mgf_salt_and_canonical_defaults() {
    use sha2::{Sha256,Sha384};
    let pki=X509Pki::new("PUBLIC-PSS-PARAMETER-TEST");
    let parse=|algorithm| {
        let mut tbs=pki.ek_tbs(&leaf(), &[0x21]);tbs.signature=algorithm;
        X509Syntax.parse_certificate(&pki.issue(&tbs))
    };
    for algorithm in [SignatureAlgorithm::RsaPssSha256,SignatureAlgorithm::RsaPssSha384] {
        assert_eq!(parse(rsa_algorithm(algorithm)).unwrap().signature_algorithm,algorithm);
    }
    let mut a=rsa_algorithm(SignatureAlgorithm::RsaPssSha256);a.parameters=None;
    assert_eq!(parse(a).err(),Some(ChainFailure::Malformed));
    let mut p=rsa::pkcs1::RsaPssParams::new::<Sha256>(33);
    let make=|p: &rsa::pkcs1::RsaPssParams<'_>| {
        use x509_cert::der::Decode;
        let mut a=rsa_algorithm(SignatureAlgorithm::RsaPssSha256);
        a.parameters=Some(Any::from_der(&p.to_der().unwrap()).unwrap());a
    };
    assert_eq!(parse(make(&p)).err(),Some(ChainFailure::UnsupportedAlgorithm));
    p.salt_len=32;p.mask_gen=rsa::pkcs1::RsaPssParams::new::<Sha384>(48).mask_gen;
    assert_eq!(parse(make(&p)).err(),Some(ChainFailure::UnsupportedAlgorithm));
    p=Default::default();
    assert_eq!(parse(make(&p)).err(),Some(ChainFailure::UnsupportedAlgorithm));
}


// PUBLIC TEST-VALUE only. This tests RSA representative bounds, not a new-message
// forgery: s and s+n exponentiate to the same encoded PSS message.
fn pss_same_width_representative_is_refused(algorithm: SignatureAlgorithm) {
    use sha2::{Digest, Sha256};
    let ca = public_rsa_fixture(algorithm);
    let key = ca.public();
    let EkPublicKey::Rsa { bits, ref modulus, .. } = key else { unreachable!() };
    let n = rsa::BigUint::from_bytes_be(modulus);
    let width = usize::from(bits) / 8;
    let mut candidate = None;
    for counter in 0u32..256 {
        let message = [b"PUBLIC TEST PSS REPRESENTATIVE BOUND V1".as_slice(), &counter.to_be_bytes()].concat();
        let canonical = ca.sign(&message);
        let s = rsa::BigUint::from_bytes_be(&canonical);
        assert!(s < n, "the public fixture signer must emit a canonical representative");
        assert!(X509Syntax.verify_signature(&key, algorithm, &message, &canonical));
        let alternate = (&s + &n).to_bytes_be();
        if alternate.len() == width {
            candidate = Some((counter, message, canonical, alternate));
            break;
        }
    }
    let (counter, message, canonical, alternate) = candidate.expect("public fixture must exhibit a same-width s+n");
    assert_eq!(canonical.len(), width);
    assert_eq!(alternate.len(), width);
    assert!(rsa::BigUint::from_bytes_be(&alternate) >= n);
    println!("PUBLIC TEST-VALUE {:?}: counter={} width={} message_sha256={} canonical_signature_sha256={} alternate_signature_sha256={}",
        algorithm, counter, width, hex::encode(Sha256::digest(&message)),
        hex::encode(Sha256::digest(&canonical)), hex::encode(Sha256::digest(&alternate)));
    assert!(!X509Syntax.verify_signature(&key, algorithm, &message, &alternate),
        "same-width out-of-range PSS s+n must be refused before RSA reduction");
}
#[test]
fn pss_same_width_representative_sha256_is_refused() {
    pss_same_width_representative_is_refused(SignatureAlgorithm::RsaPssSha256);
}
#[test]
fn pss_same_width_representative_sha384_is_refused() {
    pss_same_width_representative_is_refused(SignatureAlgorithm::RsaPssSha384);
}
