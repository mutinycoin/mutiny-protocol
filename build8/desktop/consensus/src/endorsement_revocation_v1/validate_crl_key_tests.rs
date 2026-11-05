//! Native issuer-signature path tests using genuine public software DER/CRLs.
//! CA keys are not EK templates. No physical enrollment/activation claim.
use super::*;
#[path = "../../tests/support/test_value_x509.rs"]
mod pki_fixture;
use crate::ek_chain::SignatureAlgorithm;
use x509_cert::der::asn1::BitString;
fn fixture(root384:bool, intermediate384:bool) -> (pki_fixture::X509Pki,Vec<Vec<u8>>,TrustAnchor) {
    let label="a2-public-ca-key-role";
    let key=|suffix:&str,p384:bool| if p384 {
        pki_fixture::CaKey::P384(pki_fixture::p384_key(&format!("{label}/{suffix}")))
    } else {pki_fixture::CaKey::P256(pki_fixture::p256_key(&format!("{label}/{suffix}")))};
    let pki=pki_fixture::X509Pki::with_ca_keys(label,key("root",root384),key("intermediate",intermediate384));
    let leaf=key("public-EK",false).public();
    let chain=pki.chain(&leaf,&[0x51]);
    let anchor=pki.anchor(RevocationMode::CrlRequired,&[leaf.class()],&[SignatureAlgorithm::EcdsaP256Sha256,SignatureAlgorithm::EcdsaP384Sha384]);
    (pki,chain,anchor)
}
fn parsed(raw:&[Vec<u8>])->Vec<ParsedCertificate> {
    raw.iter().map(|raw|X509Syntax.parse_certificate(raw).unwrap()).collect()
}
#[test]
fn signed_p256_and_p384_ca_paths_use_actual_permitted_crypto() {
    for (root384,intermediate384) in [(false,false),(false,true),(true,false),(true,true)] {
        let (pki,chain,anchor)=fixture(root384,intermediate384);
        let signed=parsed(&chain[1..]);
        verify_path(&signed,&chain[1..],&anchor,pki_fixture::T_REF+60).unwrap();
        let raw=pki.crls(&[&[0x51]],&[]);
        let crls=raw.iter().map(|raw|crl::parse(raw).unwrap()).collect::<Vec<_>>();
        let target=X509Syntax.parse_certificate(&chain[0]).unwrap();let mut used=BTreeSet::new();
        assert_eq!(status(&target,&chain[0],&signed[0],true,&crls,&anchor,pki_fixture::T_REF+60,&mut used).unwrap(),Some(0));
        assert_eq!(status(&signed[0],&chain[1],&signed[1],true,&crls,&anchor,pki_fixture::T_REF+60,&mut used).unwrap(),None);
        assert_eq!(used.len(),crls.len());
    }
}
#[test]
fn invalid_ca_point_in_exact_der_cannot_verify_genuine_child_signature() {
    for root384 in [false,true] {
        let (_,chain,mut anchor)=fixture(root384,false);
        let mut signer_raw=chain[1..].to_vec();
        let mut cert=Certificate::from_der(&signer_raw[1]).unwrap();
        let original=cert.tbs_certificate.subject_public_key_info.subject_public_key.as_bytes().unwrap();
        let mut invalid=vec![0;original.len()];invalid[0]=4; // wrong curve point, same canonical SPKI width
        cert.tbs_certificate.subject_public_key_info.subject_public_key=BitString::from_bytes(&invalid).unwrap();
        signer_raw[1]=cert.to_der().unwrap();
        anchor.root_cert_der_sha256=Sha256::digest(&signer_raw[1]).into();
        let signed=parsed(&signer_raw);
        assert_eq!(verify_path(&signed,&signer_raw,&anchor,pki_fixture::T_REF+60),Err(Error::UnqualifiedPhysical));
    }
}
#[test]
fn authentic_issuer_key_does_not_bypass_bad_signature_or_disallowed_algorithm() {
    let (pki,chain,anchor)=fixture(true,false);
    let signer_raw=chain[1..].to_vec();let signed=parsed(&signer_raw);
    let mut disallowed=anchor.clone();
    disallowed.constraints.signature_algorithms=[SignatureAlgorithm::EcdsaP256Sha256].into();
    assert_eq!(verify_path(&signed,&signer_raw,&disallowed,pki_fixture::T_REF+60),Err(Error::UnqualifiedPhysical));
    let mut tampered=signer_raw.clone();let mut cert=Certificate::from_der(&tampered[0]).unwrap();
    let mut sig=cert.signature.as_bytes().unwrap().to_vec();*sig.last_mut().unwrap()^=1;
    cert.signature=BitString::from_bytes(&sig).unwrap();tampered[0]=cert.to_der().unwrap();
    assert_eq!(verify_path(&parsed(&tampered),&tampered,&anchor,pki_fixture::T_REF+60),Err(Error::UnqualifiedPhysical));
    let target=X509Syntax.parse_certificate(&chain[0]).unwrap();
    let mut raw=pki.crls(&[&[0x51]],&[]);*raw[0].last_mut().unwrap()^=1;
    let crls=raw.iter().map(|raw|crl::parse(raw).unwrap()).collect::<Vec<_>>();
    assert!(status(&target,&chain[0],&signed[0],true,&crls,&anchor,pki_fixture::T_REF+60,&mut BTreeSet::new()).is_err());
}

#[test]
fn genuine_signature_under_another_key_does_not_authenticate_trusted_issuer() {
    for root384 in [false, true] {
        let (pki, chain, anchor) = fixture(root384, false);
        let other = if root384 { pki_fixture::CaKey::P384(pki_fixture::p384_key("a2-public-distinct-root-P384")) }
            else { pki_fixture::CaKey::P256(pki_fixture::p256_key("a2-public-distinct-root-P256")) };
        let tbs = Certificate::from_der(&chain[1]).unwrap().tbs_certificate;
        let substituted = pki_fixture::sign_tbs(&tbs, &other);
        let c = X509Syntax.parse_certificate(&substituted).unwrap();
        let trusted = X509Syntax.parse_certificate(&chain[2]).unwrap();
        assert!(X509Syntax.verify_signature(&other.public(), c.signature_algorithm, &c.tbs, &c.signature));
        assert!(!X509Syntax.verify_signature(&trusted.public_key, c.signature_algorithm, &c.tbs, &c.signature));
        let raw = vec![substituted, chain[2].clone()];
        assert_eq!(verify_path(&parsed(&raw), &raw, &anchor, pki_fixture::T_REF+60), Err(Error::UnqualifiedPhysical));
        assert_eq!(anchor.root_cert_der_sha256, pki.root_hash());
        verify_path(&parsed(&chain[1..]), &chain[1..], &anchor, pki_fixture::T_REF+60).unwrap();
    }
}
#[test]
fn genuine_trusted_signature_does_not_authorize_wrong_issuer_name() {
    for root384 in [false, true] {
        let (pki, chain, anchor) = fixture(root384, false);
        let mut tbs = Certificate::from_der(&chain[1]).unwrap().tbs_certificate;
        tbs.issuer = pki_fixture::name("TEST-VALUE unrelated issuer name");
        let raw = vec![pki_fixture::sign_tbs(&tbs, &pki.root_key), chain[2].clone()];
        let c = X509Syntax.parse_certificate(&raw[0]).unwrap();
        assert!(X509Syntax.verify_signature(&pki.root_key.public(), c.signature_algorithm, &c.tbs, &c.signature));
        assert_eq!(verify_path(&parsed(&raw), &raw, &anchor, pki_fixture::T_REF+60), Err(Error::UnqualifiedPhysical));
        verify_path(&parsed(&chain[1..]), &chain[1..], &anchor, pki_fixture::T_REF+60).unwrap();
    }
}
