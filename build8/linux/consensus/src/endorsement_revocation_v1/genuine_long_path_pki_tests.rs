//! SOURCE-ONLY TEST-VALUE foundation. All keys are derived from public labels.
//! A real five-certificate path and four actually used issuer CRLs. No ignored
//! extension padding, manufacturer evidence, activation or production authority.
use super::*;
use crate::ek_chain::{CertificateSyntax, ChainContext, ChainFailure, TrustAnchor};
use crate::endorsement_identity::EkPublicKey;
use crate::provenance::AdmissionClass;
use crate::x509_syntax::{X509Syntax, oids};
use test_value_x509::{CaKey, T_REF};
use x509_cert::{Certificate, TbsCertificate, Version};
use x509_cert::crl::{RevokedCert, TbsCertList};
use x509_cert::der::{Decode, Tag};
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::Validity;

// Every RDN identifies an explicit synthetic hierarchy unit. The repeated OU
// components are part of the authenticated issuer/subject Name, not extensions
// ignored by the verifier. CN/O/OU values stay within RFC5280's 64-character bound.
fn hierarchy_name(role: &str, units: usize, tail: usize) -> Name {
    assert!(role.len() <= 64 && units <= 64 && tail <= 64);
    let ou = ObjectIdentifier::new_unwrap("2.5.4.11");
    let mut values = vec![
        (test_value_x509::ORGANIZATION, "Mutiny synthetic A2 TEST-VALUE PKI".to_owned()),
        (test_value_x509::COMMON_NAME, role.to_owned()),
    ];
    for i in 0..units {
        values.push((ou, format!("A2 synthetic issued hierarchy unit {i:02}; scope TEST-VALUE ONLY")));
    }
    if tail != 0 {
        // A genuine additional organizational unit, not an opaque extension.
        let text = format!("A2-test-unit-{tail:02}-{}", "X".repeat(tail));
        values.push((ou, text.chars().take(64).collect()));
    }
    RdnSequence(values.into_iter().map(|(oid, text)| {
        assert!(!text.is_empty() && text.len() <= 64);
        RelativeDistinguishedName::try_from(vec![test_value_x509::atv(oid, Tag::Utf8String, &text)]).unwrap()
    }).collect())
}

/// Root is last. Keys/names are CA1 (EK issuer), CA2, CA3, Root.
pub(super) struct LongPathPki {
    pub(super) pki: test_value_x509::X509Pki,
    ca2: CaKey,
    ca3: CaKey,
    names: Vec<Name>,
    pub(super) ca_chain: Vec<Vec<u8>>,
}
impl LongPathPki {
    pub(super) fn new() -> Self {
        let root_key = CaKey::P384(test_value_x509::p384_key("a2-long-path-public/root"));
        let ca3 = CaKey::P384(test_value_x509::p384_key("a2-long-path-public/ca3"));
        let ca2 = CaKey::P256(test_value_x509::p256_key("a2-long-path-public/ca2"));
        let ca1 = CaKey::P256(test_value_x509::p256_key("a2-long-path-public/ca1"));
        let names: Vec<_> = ["A2 TEST-VALUE CA1", "A2 TEST-VALUE CA2", "A2 TEST-VALUE CA3", "A2 TEST-VALUE Root"]
            .into_iter().map(|s| hierarchy_name(s, 0, 0)).collect();
        let keys = [&ca1, &ca2, &ca3, &root_key];
        let mut ca_chain = Vec::new();
        for i in 0..4 {
            let issuer = (i + 1).min(3);
            let tbs = TbsCertificate {
                version: Version::V3,
                serial_number: SerialNumber::new(&[0x10 + i as u8]).unwrap(),
                signature: keys[issuer].algorithm(),
                issuer: names[issuer].clone(),
                validity: Validity { not_before: test_value_x509::time(test_value_x509::CA_NOT_BEFORE),
                    not_after: test_value_x509::time(test_value_x509::CA_NOT_AFTER) },
                subject: names[i].clone(),
                subject_public_key_info: test_value_x509::spki(&keys[i].public()),
                issuer_unique_id: None, subject_unique_id: None,
                extensions: Some(test_value_x509::ca_extensions(keys[i], Some(keys[issuer]), Some(i as u8))),
            };
            ca_chain.push(test_value_x509::sign_tbs(&tbs, keys[issuer]));
        }
        let pki = test_value_x509::X509Pki { label: "a2-long-path-public".into(), root_key,
            intermediate_key: ca1, root: ca_chain[3].clone(), intermediate: ca_chain[0].clone() };
        Self { pki, ca2, ca3, names, ca_chain }
    }
    fn key(&self, i: usize) -> &CaKey {
        match i { 0 => &self.pki.intermediate_key, 1 => &self.ca2, 2 => &self.ca3, 3 => &self.pki.root_key, _ => panic!("issuer index") }
    }
    pub(super) fn anchor(&self) -> TrustAnchor {
        let mut anchor = self.pki.anchor(RevocationMode::CrlRequired, &[test_value_ek::ECC_CLASS],
            &[SignatureAlgorithm::EcdsaP256Sha256, SignatureAlgorithm::EcdsaP384Sha384]);
        anchor.constraints.max_intermediates = 3;
        anchor
    }
    pub(super) fn leaf_tbs(&self, ek: &EkPublicKey, serial: &[u8]) -> TbsCertificate {
        let mut tbs = self.pki.ek_tbs(ek, serial);
        tbs.issuer = self.names[0].clone();
        // Retain only the defined EK extensions. No ignored extension filler.
        tbs.extensions.as_mut().unwrap().retain(|e| e.extn_id != test_value_x509::SUBJECT_DIRECTORY_ATTRIBUTES);
        tbs
    }
    pub(super) fn chain(&self, ek: &EkPublicKey, serial: &[u8]) -> Vec<Vec<u8>> {
        let mut chain = vec![test_value_x509::sign_tbs(&self.leaf_tbs(ek, serial), self.key(0))];
        chain.extend(self.ca_chain.clone());
        chain
    }
    /// Bounded search over authenticated Name and positive serial fields. The
    /// resulting complete DER size is measured, never padded or assumed exact.
    /// Root first, then rebuild each child against its exact changed issuer Name.
    pub(super) fn maximize_path(&mut self, ek: &EkPublicKey, limit: usize) -> Vec<Vec<u8>> {
        assert!((4096..=4097).contains(&limit));
        for i in (0..4).rev() {
            let issuer = (i + 1).min(3);
            let mut tbs = Certificate::from_der(&self.ca_chain[i]).unwrap().tbs_certificate;
            tbs.issuer = self.names[issuer].clone();
            let (chosen, raw) = maximize_certificate(tbs, self.key(issuer),
                &["A2 TEST-VALUE CA1", "A2 TEST-VALUE CA2", "A2 TEST-VALUE CA3", "A2 TEST-VALUE Root"][i], limit, i == 3);
            self.names[i] = chosen.subject;
            self.ca_chain[i] = raw;
        }
        self.pki.root = self.ca_chain[3].clone();
        self.pki.intermediate = self.ca_chain[0].clone();
        let (_, leaf) = maximize_certificate(self.leaf_tbs(ek, &[0x51]), self.key(0),
            "A2 TEST-VALUE EK issued device", limit, false);
        let mut chain = vec![leaf]; chain.extend(self.ca_chain.clone()); chain
    }
    fn crl_tbs(&self, issuer: usize, serials: &[Vec<u8>], at: u64, until: u64) -> TbsCertList {
        let key = self.key(issuer);
        let entries: Vec<_> = serials.iter().map(|s| RevokedCert {
            serial_number: SerialNumber::new(s).unwrap(), revocation_date: test_value_x509::time(at - 1),
            crl_entry_extensions: None,
        }).collect();
        TbsCertList { version: Version::V2, signature: key.algorithm(), issuer: self.names[issuer].clone(),
            this_update: test_value_x509::time(at), next_update: Some(test_value_x509::time(until)),
            revoked_certificates: (!entries.is_empty()).then_some(entries),
            crl_extensions: Some(vec![
                test_value_x509::ext(oids::CRL_NUMBER, false, &CrlNumber(Uint::new(&[1]).unwrap())),
                test_value_x509::ext(oids::AUTHORITY_KEY_IDENTIFIER, false,
                    &AuthorityKeyIdentifier { key_identifier: Some(OctetString::new(key.key_id()).unwrap()), ..Default::default() }),
            ]),
        }
    }
    pub(super) fn crl(&self, issuer: usize, serials: &[Vec<u8>], at: u64, until: u64) -> Vec<u8> {
        let tbs = self.crl_tbs(issuer, serials, at, until);
        let raw = tbs.to_der().unwrap();
        test_value_x509::assemble(&raw, &tbs.signature.to_der().unwrap(), &self.key(issuer).sign(&raw))
    }
    pub(super) fn historical_crls(&self) -> Vec<Vec<u8>> {
        (0..4).map(|i| self.crl(i, &[], T_REF - 60, T_REF + 30)).collect()
    }
    pub(super) fn withdrawal_crls(&self, target_serial: &[u8]) -> Vec<Vec<u8>> {
        (0..4).map(|i| {
            let serials = if i == 0 { vec![target_serial.to_vec()] } else { vec![] };
            self.crl(i, &serials, T_REF + 60, T_REF + 120)
        }).collect()
    }
    pub(super) fn verify(&self, chain: &[Vec<u8>], crls: &[Vec<u8>], at: u64) -> std::result::Result<crate::ek_chain::VerifiedEndorsement, ChainFailure> {
        crate::ek_chain::validate_endorsement_chain(&X509Syntax, chain, crls,
            &ChainContext { class: AdmissionClass::Production, reference_time: at, anchors: &[self.anchor()] })
    }
    /// Off-path revoked entries refer to genuinely issued synthetic certificates.
    /// Return the certificate population separately, so each entry's actual
    /// serial, issuer and signature can be independently checked. No fleet claim.
    fn issued_population(&self, issuer: usize, count: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
        assert!(count <= 2048);
        let serials: Vec<_> = (0..count).map(|i| {
            // Positive unique 20-octet magnitudes; the first octet never needs a
            // sign-padding byte and these serials cannot collide with path nodes.
            let mut serial = vec![0x40; 20];
            serial[16..].copy_from_slice(&(i as u32).to_be_bytes());
            serial
        }).collect();
        self.issued_serials(issuer, &serials)
    }
    fn issued_serials(&self, issuer: usize, serials: &[Vec<u8>]) -> Vec<(Vec<u8>, Vec<u8>)> {
        serials.iter().map(|serial| {
            let mut cert = self.leaf_tbs(&self.key(issuer).public(), &serial);
            cert.issuer = self.names[issuer].clone();
            cert.signature = self.key(issuer).algorithm();
            cert.extensions.as_mut().unwrap().retain(|e| e.extn_id != oids::AUTHORITY_KEY_IDENTIFIER);
            cert.extensions.as_mut().unwrap().push(test_value_x509::ext(oids::AUTHORITY_KEY_IDENTIFIER, false,
                &AuthorityKeyIdentifier { key_identifier: Some(OctetString::new(self.key(issuer).key_id()).unwrap()), ..Default::default() }));
            let raw = test_value_x509::sign_tbs(&cert, self.key(issuer));
            let parsed = X509Syntax.parse_certificate(&raw).unwrap();
            assert_eq!(&parsed.serial, serial);
            assert!(X509Syntax.verify_signature(&self.key(issuer).public(), parsed.signature_algorithm, &parsed.tbs, &parsed.signature));
            (serial.clone(), raw)
        }).collect()
    }
    /// Tune only supported CRL fields: real issued serials, CRL number and
    /// revocation date. Every selected off-path entry is subsequently issued and
    /// verified, before this fixture is returned. Search estimates are not evidence.
    pub(super) fn maximize_crl(&self, issuer: usize, target: Option<&[u8]>, limit: usize)
        -> (Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>)
    {
        self.maximize_crl_at(issuer, target, limit, T_REF + 60, T_REF + 120)
    }
    // Exact signed fixture times; retained default controls keep their old inputs.
    pub(super) fn maximize_crl_at(&self, issuer: usize, target: Option<&[u8]>, limit: usize,
        this_update: u64, next_update: u64) -> (Vec<u8>, Vec<(Vec<u8>, Vec<u8>)>)
    {
        assert!(this_update >= T_REF && next_update > this_update);
        assert!((32768..=32769).contains(&limit));
        let mut selected = Vec::new();
        if let Some(serial) = target { selected.push(serial.to_vec()); }
        let mut best_raw = self.crl(issuer, &selected, this_update, next_update);
        let mut best_serials = selected.clone();
        let mut population_count = 0;
        // At most2048 entries, including the actual path target if any. Append
        // long positive serials until the first unsigned encoded upper estimate
        // reaches the complete-DER boundary. Only candidates near it are signed.
        loop {
            assert!(selected.len() < 2048);
            let mut serial = vec![0x40; 20];
            serial[16..].copy_from_slice(&(population_count as u32).to_be_bytes());
            selected.push(serial); population_count += 1;
            let tbs = self.crl_tbs(issuer, &selected, this_update, next_update);
            let maximum_signature = if matches!(self.key(issuer), CaKey::P384(_)) { 104 } else { 72 };
            let estimate = test_value_x509::assemble(&tbs.to_der().unwrap(),
                &tbs.signature.to_der().unwrap(), &vec![0; maximum_signature]).len();
            if estimate + 48 < limit { continue; }
            let original_tail = selected.last().unwrap().clone();
            // Vary the last genuinely issued certificate serial and monotone
            // CRL number to bridge entry/DER size transitions; no extension filler.
            for serial_len in 1..=20 {
                let mut tail = vec![0x60; serial_len];
                // Different length or prefix distinguishes it from all previous
                // population serials and the retained target/path CA serials.
                if serial_len >= 4 {
                    tail[serial_len - 3..].copy_from_slice(&[0x01, (population_count >> 8) as u8, population_count as u8]);
                }
                *selected.last_mut().unwrap() = tail;
                for number_len in 1..=20 {
                    let mut candidate = self.crl_tbs(issuer, &selected, this_update, next_update);
                    candidate.crl_extensions.as_mut().unwrap()[0] = test_value_x509::ext(oids::CRL_NUMBER,
                        false, &CrlNumber(Uint::new(&vec![0x21; number_len]).unwrap()));
                    for age in 1..=8 {
                        candidate.revoked_certificates.as_mut().unwrap().last_mut().unwrap().revocation_date =
                            test_value_x509::time(this_update - age);
                        let unsigned = candidate.to_der().unwrap();
                        let estimate = test_value_x509::assemble(&unsigned,
                            &candidate.signature.to_der().unwrap(), &vec![0; maximum_signature]).len();
                        if estimate + 8 < limit || estimate > limit + 8 { continue; }
                        let raw = test_value_x509::assemble(&unsigned, &candidate.signature.to_der().unwrap(),
                            &self.key(issuer).sign(&unsigned));
                        if raw.len() <= limit && raw.len() > best_raw.len() {
                            best_raw = raw; best_serials = selected.clone();
                            if best_raw.len() == limit { break; }
                        }
                    }
                    if best_raw.len() == limit { break; }
                }
                if best_raw.len() == limit { break; }
            }
            *selected.last_mut().unwrap() = original_tail;
            if best_raw.len() == limit || estimate > limit + 64 { break; }
        }
        let population = self.issued_serials(issuer,
            &best_serials[usize::from(target.is_some())..]);
        let parsed = super::super::crl::parse(&best_raw);
        if limit == 32768 {
            let parsed = parsed.unwrap();
            assert_eq!(parsed.entries.len(), best_serials.len());
            for (entry, serial) in parsed.entries.iter().zip(&best_serials) {
                assert_eq!(&entry.serial, serial);
            }
            assert!(X509Syntax.verify_signature(&self.key(issuer).public(), parsed.signed.signature_algorithm,
                &parsed.signed.tbs, &parsed.signed.signature));
        }
        (best_raw, population)
    }
}

fn maximize_certificate(tbs: TbsCertificate, signer: &CaKey, role: &str, limit: usize, self_signed: bool)
    -> (TbsCertificate, Vec<u8>)
{
    let original = test_value_x509::sign_tbs(&tbs, signer);
    assert!(original.len() <= limit);
    let mut best = (tbs.clone(), original);
    let signature_width = match signer { CaKey::P256(_) => 72, CaKey::P384(_) => 104, _ => panic!("ECDSA fixture only") };
    // Fixed upper bound:65*49*20 cheap encodes, signatures only in an eight-byte
    // neighborhood of the target. An exact result exits early. Not a timing test.
    for units in 0..=64 {
        for tail in 0..=48 {
            let mut candidate = tbs.clone();
            candidate.subject = hierarchy_name(role, units, tail);
            if self_signed { candidate.issuer = candidate.subject.clone(); }
            for magnitude in 1..=20 {
                let mut serial = vec![0x20; magnitude];
                // Distinguished by role/name/key as well as serial; population
                // serials start0x40 and cannot accidentally revoke this path.
                serial[magnitude - 1] = *tbs.serial_number.as_bytes().last().unwrap();
                candidate.serial_number = SerialNumber::new(&serial).unwrap();
                let raw_tbs = candidate.to_der().unwrap();
                let predicted = test_value_x509::assemble(&raw_tbs,
                    &candidate.signature.to_der().unwrap(), &vec![0; signature_width]).len();
                if predicted + 8 < limit || predicted > limit + 8 { continue; }
                let raw = test_value_x509::sign_tbs(&candidate, signer);
                if raw.len() <= limit && raw.len() > best.1.len() {
                    best = (candidate.clone(), raw);
                    if best.1.len() == limit { return best; }
                }
            }
        }
    }
    best
}

// RFC6979 is deterministic for one TBS. Vary a genuine positive certificate
// serial (never repeated-sign one message), retaining all issuer/subject/key/
// validity/extensions. Measure the complete signed DER, not an upper estimate.
// This is a bounded TEST-only attainment search; None is a failed fixture, not
// proof of native oversize rejection. No policy/capacity or PKI input changes.
fn signed_certificate_one_over(tbs: &TbsCertificate, signer: &CaKey) -> Option<Vec<u8>> {
    let algorithm = match signer {
        CaKey::P256(_) => SignatureAlgorithm::EcdsaP256Sha256,
        CaKey::P384(_) => SignatureAlgorithm::EcdsaP384Sha384,
        _ => panic!("ECDSA fixture only"),
    };
    for magnitude in 1..=20 {
        for variant in 0x20..=0x3f {
            let mut candidate = tbs.clone();
            let mut serial = vec![0x20; magnitude];
            serial[0] = variant;
            candidate.serial_number = SerialNumber::new(&serial).unwrap();
            let raw = test_value_x509::sign_tbs(&candidate, signer);
            if raw.len() != crate::ek_chain::MAX_CERTIFICATE_BYTES + 1 { continue; }
            let parsed = Certificate::from_der(&raw).unwrap();
            let signed = parsed.tbs_certificate.to_der().unwrap();
            let signature = parsed.signature.as_bytes().unwrap();
            assert_eq!(parsed.signature_algorithm, candidate.signature);
            assert_eq!(parsed.tbs_certificate, candidate);
            assert_eq!(parsed.tbs_certificate.serial_number.as_bytes(), serial);
            assert!(X509Syntax.verify_signature(&signer.public(), algorithm, &signed, signature));
            eprintln!("A2 PUBLIC measured genuine one-over certificate bytes={} tbsBytes={} signatureBytes={} serialOctets={}; native size refusal follows, no physical claim",
                raw.len(), signed.len(), signature.len(), serial.len());
            return Some(raw);
        }
    }
    None
}

#[test]
fn attained_large_certificates_remain_a_genuine_used_five_path() {
    let mut pki = LongPathPki::new();
    let ek = pki.key(0).public();
    let chain = pki.maximize_path(&ek, crate::ek_chain::MAX_CERTIFICATE_BYTES);
    let crls = pki.historical_crls();
    pki.verify(&chain, &crls, T_REF).unwrap();
    let sizes: Vec<_> = chain.iter().map(Vec::len).collect();
    eprintln!("A2 PUBLIC attained signed certificate sizes={sizes:?}; cap=4096; no physical qualification");
    assert!(sizes.iter().all(|n| *n <= 4096 && *n >= 4000), "report actual attainable size, not a padded maximum");
    for i in 0..5 {
        let cert = Certificate::from_der(&chain[i]).unwrap();
        let signer = pki.key(if i == 0 { 0 } else { i.min(3) });
        let over = signed_certificate_one_over(&cert.tbs_certificate, signer)
            .expect("genuine serial-content search must actually attain signed 4097 DER; otherwise retain fixture failure");
        assert_eq!(over.len(), 4097, "the freshly signed one-over control must actually reach the boundary");
        let mut over_chain = chain.clone(); over_chain[i] = over;
        assert_eq!(pki.verify(&over_chain, &crls, T_REF), Err(ChainFailure::Oversize));
    }
    pki.verify(&chain, &crls, T_REF).unwrap();
}

#[test]
fn genuine_five_certificate_path_uses_four_current_issuer_crls() {
    let pki = LongPathPki::new();
    let tpm = TestTpm::with_identity("a2-long-path-genesis").strip(software_tpm::Strip::ConsistentProvenance(pki.pki.root_hash()));
    let chain = pki.chain(&tpm.simulator_ek(), &[0x51]);
    let crls = pki.historical_crls();
    let verified = pki.verify(&chain, &crls, T_REF).unwrap();
    assert_eq!(verified.path.len(), 5);
    assert_eq!(verified.anchor, pki.pki.root_hash());
    for missing in 0..4 {
        let mut absent = crls.clone(); absent.remove(missing);
        assert_eq!(pki.verify(&chain, &absent, T_REF), Err(ChainFailure::RevocationMissing));
    }
    let mut duplicate = crls.clone(); duplicate[3] = duplicate[0].clone();
    assert!(pki.verify(&chain, &duplicate, T_REF).is_err());
    let mut wrong_signature = crls.clone(); *wrong_signature[2].last_mut().unwrap() ^= 1;
    assert_eq!(pki.verify(&chain, &wrong_signature, T_REF), Err(ChainFailure::RevocationIssuer));
    assert_eq!(pki.verify(&chain, &crls, T_REF + 60), Err(ChainFailure::StaleRevocation));
    assert_eq!(pki.verify(&chain, &crls, T_REF).unwrap(), verified);
}

#[test]
fn genuine_long_path_full_genesis_and_containing_h_withdrawal_replay() {
    let pki = LongPathPki::new();
    let tpm = TestTpm::with_identity("a2-long-path-genesis").strip(software_tpm::Strip::ConsistentProvenance(pki.pki.root_hash()));
    let chain = pki.chain(&tpm.simulator_ek(), &[0x51]);
    let historical = pki.historical_crls();
    pki.verify(&chain, &historical, T_REF).unwrap();
    let new_crls = pki.withdrawal_crls(&[0x51]);
    let anchor = pki.anchor();
    let r = rig_with_authenticated_material(pki.pki, &[], tpm, chain, historical, anchor);
    assert_canonical_state_roundtrip(&r.state);
    let op = operation(&r, Target { class: TargetClass::Ek, scope: TargetScope::Certificate,
        identity: test_value_x509::sha256(&r.chain[0]) }, Evidence::Crl {
        target_certificate: r.chain[0].clone(), signer_chain: r.chain[1..].to_vec(), crls: new_crls });
    let before = r.state.records().unwrap();
    let next = transition(&r, &op).unwrap();
    assert!(next.endorsement_revocations_v1.terminal_no_quorum());
    assert!(!next.continuity.as_ref().unwrap().members[0].eligible);
    assert_eq!(r.state.records().unwrap(), before);
    assert_eq!(r.state.root().unwrap(), r.root);
    assert_canonical_state_roundtrip(&next);
    // Component transition/replay only. Complete certified Store and Runtime
    // install/catchup/reopen are separate G04/G05/G21 controls, still pending.
}

#[test]
fn genuine_five_path_rejects_fourth_intermediate_and_changed_linkage() {
    let pki = LongPathPki::new();
    let chain = pki.chain(&pki.key(0).public(), &[0x51]);
    let crls = pki.historical_crls();
    pki.verify(&chain, &crls, T_REF).unwrap();
    let mut six = chain.clone(); six.insert(1, chain[1].clone());
    assert_eq!(pki.verify(&six, &crls, T_REF), Err(ChainFailure::ChainLength));
    let mut swapped = chain.clone(); swapped.swap(1, 2);
    assert_eq!(pki.verify(&swapped, &crls, T_REF), Err(ChainFailure::IssuerMismatch));
    let mut leaf = Certificate::from_der(&chain[0]).unwrap().tbs_certificate;
    leaf.issuer = pki.names[1].clone();
    let mut wrong_name = chain.clone(); wrong_name[0] = test_value_x509::sign_tbs(&leaf, pki.key(0));
    assert_eq!(pki.verify(&wrong_name, &crls, T_REF), Err(ChainFailure::IssuerMismatch));
}

#[test]
fn crl_entries_correspond_to_real_issued_public_certificate_population() {
    let pki = LongPathPki::new();
    for issuer in 0..4 {
        let population = pki.issued_population(issuer, 3);
        let serials: Vec<_> = population.iter().map(|(s, _)| s.clone()).collect();
        let raw = pki.crl(issuer, &serials, T_REF + 60, T_REF + 120);
        let parsed = super::super::crl::parse(&raw).unwrap();
        assert_eq!(parsed.entries.len(), population.len());
        for (entry, (serial, cert)) in parsed.entries.iter().zip(population.iter()) {
            assert_eq!(&entry.serial, serial);
            assert_eq!(entry.issuer, pki.names[issuer].to_der().unwrap());
            assert_eq!(X509Syntax.parse_certificate(cert).unwrap().serial, *serial);
        }
        assert!(X509Syntax.verify_signature(&pki.key(issuer).public(), parsed.signed.signature_algorithm,
            &parsed.signed.tbs, &parsed.signed.signature));
    }
}

#[test]
fn attained_large_used_crls_and_signed_certificate_path_withdraw_through_native_transition() {
    let mut pki = LongPathPki::new();
    let original_tpm = TestTpm::with_identity("a2-long-path-largest-public-EK");
    let chain = pki.maximize_path(&original_tpm.simulator_ek(), 4096);
    let serial = X509Syntax.parse_certificate(&chain[0]).unwrap().serial;
    let historical = pki.historical_crls();
    pki.verify(&chain, &historical, T_REF).unwrap();
    let mut large_crls = Vec::new();
    let mut population_counts = Vec::new();
    for issuer in 0..4 {
        let (raw, population) = pki.maximize_crl(issuer,
            if issuer == 0 { Some(serial.as_slice()) } else { None }, 32768);
        assert!(raw.len() <= 32768 && raw.len() >= 32700);
        assert!(!population.is_empty());
        population_counts.push(population.len()); large_crls.push(raw);
        let (over, _) = pki.maximize_crl(issuer,
            if issuer == 0 { Some(serial.as_slice()) } else { None }, 32769);
        assert_eq!(over.len(), 32769, "fresh genuinely signed overbound list must actually reach the bound");
        assert_eq!(super::super::crl::parse(&over).err(), Some(super::super::crl::Failure::Bounds));
    }
    let crl_sizes: Vec<_> = large_crls.iter().map(Vec::len).collect();
    let certificate_sizes: Vec<_> = chain.iter().map(Vec::len).collect();
    let tpm = original_tpm.strip(software_tpm::Strip::ConsistentProvenance(pki.pki.root_hash()));
    let anchor = pki.anchor();
    let r = rig_with_authenticated_material(pki.pki, &[], tpm, chain, historical, anchor);
    let op = operation(&r, Target { class: TargetClass::Ek, scope: TargetScope::Certificate,
        identity: test_value_x509::sha256(&r.chain[0]) }, Evidence::Crl {
        target_certificate: r.chain[0].clone(), signer_chain: r.chain[1..].to_vec(), crls: large_crls });
    let exact = op.encode().unwrap();
    eprintln!("A2 PUBLIC attained certificates={certificate_sizes:?}, used CRLs={crl_sizes:?}, genuinely issued off-path populations={population_counts:?}, operationBytes={}; initial-height structural ceiling151785; conservative approved cap196608", exact.len());
    // Reaching a second fragment window is an actual fixture requirement. A
    // failure here reports non-attainment; it cannot substitute padding or be
    // converted to a two-window transport/finality result.
    assert!(exact.len() > 151_200, "authenticated size search did not attain the second transport window");
    assert!(exact.len() <= 151_785);
    assert!(Operation::decode(&exact).unwrap() == op);
    let before = r.state.records().unwrap();
    let next = transition(&r, &op).unwrap();
    assert!(next.endorsement_revocations_v1.terminal_no_quorum());
    assert_eq!(r.state.records().unwrap(), before);
    assert_canonical_state_roundtrip(&next);
    // Also execute actual licensed native work, dual signatures, a genuine
    // parent certificate, finality, exact certified BLOB/index export and reopen,
    // then typed terminal unsigned-preparation refusal with all SQL unchanged.
    super::canonical_store_tests::assert_terminal_store(r, op);
    // Node Runtime and authenticated transport/catchup remain separate G06/G21
    // controls; this test cannot substitute for their actual host campaign.
}
