//! Genuine public software signatures only. No physical/hardware authority.
use super::*;
use x509_cert::der::Decode;
#[test]
fn genuine_high_msb_serial_crl_uses_positive_magnitude_and_exact_issuer() {
    let r = rig_with_pki(false,&[0x80],test_value_x509::X509Pki::new("a2-public-high-msb-serial"));
    let mut op = direct(&r);
    if let Evidence::Crl {crls,..} = &mut op.evidence {
        *crls = r.pki.crls(&[&[0x80]],&[]);
    }
    let cert = crate::ek_chain::CertificateSyntax::parse_certificate(&crate::x509_syntax::X509Syntax,&r.chain[0]).unwrap();
    let Evidence::Crl {crls,..}=&op.evidence else {unreachable!()};
    let parsed = super::super::crl::parse(&crls[0]).unwrap();
    assert_eq!(cert.serial,vec![0x80]);
    assert_eq!(parsed.entries[0].serial,cert.serial);
    assert!(transition(&r,&op).unwrap().endorsement_revocations_v1.terminal_no_quorum());
    if let Evidence::Crl {crls,..}=&mut op.evidence {
        *crls=r.pki.crls(&[&[0x81]],&[]);
    }
    assert_eq!(transition(&r,&op).err(),Some(Error::UnqualifiedPhysical));
    assert_eq!(r.state.root().unwrap(),r.root);
}
#[test]
fn crl_zero_or_negative_serial_is_refused_without_altering_signed_der() {
    let pki=test_value_x509::X509Pki::new("a2-public-invalid-serial");
    let zero=pki.crls(&[&[0]],&[]);
    assert!(super::super::crl::parse(&zero[0]).is_err());
    let mut tbs=pki.crl_tbs(false,&[&[0x80]]);
    // Public intentionally invalid signed ASN.1 INTEGER; never an admitted EK.
    match x509_cert::serial_number::SerialNumber::from_der(&[2,1,0x80]) {
        Ok(serial) => {
            tbs.revoked_certificates.as_mut().unwrap()[0].serial_number=serial;
            let negative=pki.sign_crl(&tbs,false);
            assert!(super::super::crl::parse(&negative).is_err());
        }
        Err(_) => eprintln!("PUBLIC negative serial refused by upstream exact DER decoder"),
    }
}
