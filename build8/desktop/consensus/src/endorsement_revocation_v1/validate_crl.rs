//! A2 applicability over fully authenticated retained target paths. No live web
//! or wall clock, no OS trust store, and no root self-withdrawal authority.
use super::{Target, TargetClass, crl};
use crate::{
    Error, Result,
    ek_chain::{CertificateSyntax, ParsedCertificate, RevocationMode, TrustAnchor, key_usage},
    endorsement_dependencies_v1::ResolvedPath,
    x509_syntax::X509Syntax,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use x509_cert::{
    Certificate,
    der::{Decode, Encode, asn1::ObjectIdentifier},
    ext::pkix::{
        crl::dp::DistributionPoint,
        name::{DistributionPointName, GeneralName},
    },
};

const CRL_POINTS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.31");

pub(super) fn verify(
    target: &Target,
    paths: &[ResolvedPath],
    target_der: &[u8],
    signer_chain: &[Vec<u8>],
    raw_crls: &[Vec<u8>],
    parameters: &crate::genesis_v2::Parameters,
    timestamp: u64,
) -> Result<()> {
    if target.class == TargetClass::Root
        || timestamp == 0
        || signer_chain.is_empty()
        || signer_chain.len() > crate::ek_chain::MAX_CHAIN
        || raw_crls.is_empty()
        || raw_crls.len() > crate::ek_chain::MAX_CRLS
    {
        return Err(Error::UnqualifiedPhysical);
    }
    let policy = parameters.witness_policy()?;
    let anchors = policy.anchors();
    let signed = signer_chain
        .iter()
        .map(|raw| {
            X509Syntax
                .parse_certificate(raw)
                .map_err(|_| Error::UnqualifiedPhysical)
        })
        .collect::<Result<Vec<_>>>()?;
    let crls = raw_crls
        .iter()
        .map(|raw| crl::parse(raw).map_err(|_| Error::UnqualifiedPhysical))
        .collect::<Result<Vec<_>>>()?;
    // One successful *complete* same-anchor path, never one unchecked name match.
    for path in paths {
        let certs = path.certificates();
        if certs.get(path.position()).map(Vec::as_slice) != Some(target_der)
            || path.position() + 1 >= certs.len()
            || certs.last() != signer_chain.last()
        {
            continue;
        }
        let anchor_hash: crate::Hash = Sha256::digest(certs.last().ok_or(Error::Codec)?).into();
        let anchor = anchors
            .iter()
            .find(|a| a.root_cert_der_sha256 == anchor_hash)
            .ok_or(Error::UnqualifiedPhysical)?;
        let target_cert = X509Syntax
            .parse_certificate(target_der)
            .map_err(|_| Error::UnqualifiedPhysical)?;
        let issuer_der = &certs[path.position() + 1];
        let direct = signer_chain[0] == *issuer_der;
        if verify_path(&signed, signer_chain, anchor, timestamp).is_err() {
            continue;
        }
        let mut used = BTreeSet::new();
        if let Ok(Some(reason)) = status(
            &target_cert,
            target_der,
            &signed[0],
            direct,
            &crls,
            anchor,
            timestamp,
            &mut used,
        ) {
            if !matches!(reason, 0 | 1 | 2 | 3 | 4 | 5 | 9 | 10) {
                continue;
            }
            // A delegated or intermediate signer cannot conceal its own current
            // revocation where this anchor requires CRLs. Below-anchor checks
            // use the same signed evidence with exact issuer-key linkage.
            let mut valid = true;
            for i in 0..signed.len().saturating_sub(1) {
                let relevant = crls
                    .iter()
                    .any(|c| c.signed.issuer == signed[i + 1].subject);
                if anchor.constraints.revocation == RevocationMode::CrlRequired || relevant {
                    match status(
                        &signed[i],
                        &signer_chain[i],
                        &signed[i + 1],
                        true,
                        &crls,
                        anchor,
                        timestamp,
                        &mut used,
                    ) {
                        Ok(None) | Ok(Some(8)) => {}
                        _ => {
                            valid = false;
                            break;
                        }
                    }
                }
            }
            if valid && used.len() == crls.len() {
                return Ok(());
            }
        }
    }
    Err(Error::UnqualifiedPhysical)
}

fn verify_path(
    certs: &[ParsedCertificate],
    raw: &[Vec<u8>],
    anchor: &TrustAnchor,
    time: u64,
) -> Result<()> {
    let k = &anchor.constraints;
    if certs.len().saturating_sub(2) > usize::from(k.max_intermediates)
        || raw
            .iter()
            .map(|c| <crate::Hash>::from(Sha256::digest(c)))
            .collect::<BTreeSet<_>>()
            .len()
            != raw.len()
        || certs.iter().any(|c| {
            c.version != 3
                || !c.unrecognised_critical.is_empty()
                || time < c.not_before
                || time > c.not_after
        })
    {
        return Err(Error::UnqualifiedPhysical);
    }
    // CA/delegated issuer keys are authenticated by the actual permitted
    // certificate and CRL signature backend, including point/key validation.
    // EKPUB-CANON identity-template eligibility applies to EK leaves, not CAs.
    for i in 0..certs.len().saturating_sub(1) {
        let (child, issuer) = (&certs[i], &certs[i + 1]);
        if child.issuer != issuer.subject
            || child
                .authority_key_id
                .as_ref()
                .zip(issuer.subject_key_id.as_ref())
                .is_some_and(|(a, b)| a != b)
            || !k.signature_algorithms.contains(&child.signature_algorithm)
            || !X509Syntax.verify_signature(
                &issuer.public_key,
                child.signature_algorithm,
                &child.tbs,
                &child.signature,
            )
            || issuer.basic_constraints.as_ref().is_none_or(|bc| {
                !bc.critical || !bc.ca || bc.path_len.is_some_and(|limit| i > usize::from(limit))
            })
            || issuer
                .key_usage
                .is_none_or(|ku| ku & key_usage::KEY_CERT_SIGN == 0)
        {
            return Err(Error::UnqualifiedPhysical);
        }
    }
    if certs[0]
        .key_usage
        .is_none_or(|ku| ku & key_usage::CRL_SIGN == 0)
    {
        return Err(Error::UnqualifiedPhysical);
    }
    Ok(())
}

fn scope(
    cert: &ParsedCertificate,
    raw: &[u8],
    signer: &ParsedCertificate,
    direct: bool,
    crl: &crl::Parsed,
) -> Result<()> {
    let idp = crl.distribution.as_ref();
    let ca = cert.basic_constraints.as_ref().is_some_and(|bc| bc.ca);
    if idp.is_some_and(|d| {
        d.only_some_reasons.is_some()
            || d.only_contains_attribute_certs
            || (d.only_contains_ca_certs && !ca)
            || (d.only_contains_user_certs && ca)
    }) || (!direct && !idp.is_some_and(|d| d.indirect_crl))
    {
        return Err(Error::UnqualifiedPhysical);
    }
    let typed = Certificate::from_der(raw).map_err(|_| Error::Codec)?;
    if typed.to_der().map_err(|_| Error::Codec)? != raw {
        return Err(Error::NonCanonical);
    }
    let points = typed
        .tbs_certificate
        .extensions
        .as_ref()
        .and_then(|xs| xs.iter().find(|ext| ext.extn_id == CRL_POINTS));
    let Some(points) = points else {
        return if direct && idp.is_none_or(|d| d.distribution_point.is_none()) {
            Ok(())
        } else {
            Err(Error::UnqualifiedPhysical)
        };
    };
    let values = Vec::<DistributionPoint>::from_der(points.extn_value.as_bytes())
        .map_err(|_| Error::Codec)?;
    if values.to_der().map_err(|_| Error::Codec)? != points.extn_value.as_bytes()
        || values.is_empty()
        || values.len() > 16
    {
        return Err(Error::UnqualifiedPhysical);
    }
    for point in values {
        if point.reasons.is_some() {
            continue;
        }
        if point.crl_issuer.is_some() && !idp.is_some_and(|d| d.indirect_crl) {
            continue;
        }
        let authorized = match point.crl_issuer.as_deref() {
            None => direct,
            Some([GeneralName::DirectoryName(name)]) => {
                name.to_der().map_err(|_| Error::Codec)? == signer.subject
            }
            _ => false,
        };
        if !authorized {
            continue;
        }
        // Full-name DER equality is the supported bounded profile. Relative
        // names or ambiguous issuer lists are explicitly refused, never guessed.
        if let Some(DistributionPointName::NameRelativeToCRLIssuer(_)) = &point.distribution_point {
            continue;
        }
        if let Some(name) = idp.and_then(|d| d.distribution_point.as_ref()) {
            if !matches!(name, DistributionPointName::FullName(_))
                || point.distribution_point.as_ref() != Some(name)
            {
                continue;
            }
        }
        return Ok(());
    }
    Err(Error::UnqualifiedPhysical)
}

fn status(
    cert: &ParsedCertificate,
    raw: &[u8],
    signer: &ParsedCertificate,
    direct: bool,
    crls: &[crl::Parsed],
    anchor: &TrustAnchor,
    time: u64,
    used: &mut BTreeSet<usize>,
) -> Result<Option<u8>> {
    if signer
        .key_usage
        .is_none_or(|ku| ku & key_usage::CRL_SIGN == 0)
    {
        return Err(Error::UnqualifiedPhysical);
    }
    let matches: Vec<_> = crls
        .iter()
        .enumerate()
        .filter(|(_, c)| c.signed.issuer == signer.subject)
        .collect();
    if matches.is_empty() || matches.len() > 2 {
        return Err(Error::UnqualifiedPhysical);
    }
    let mut base = None;
    let mut delta = None;
    for (i, c) in matches {
        scope(cert, raw, signer, direct, c)?;
        if c.signed.version != 2
            || c.signed.this_update > time
            || c.signed
                .next_update
                .is_none_or(|next| next < time || next < c.signed.this_update)
            || c.entries
                .iter()
                .any(|entry| entry.date > c.signed.this_update)
            || c.authority_key
                .as_ref()
                .is_some_and(|key| signer.subject_key_id.as_ref() != Some(key))
            || !anchor
                .constraints
                .signature_algorithms
                .contains(&c.signed.signature_algorithm)
            || !X509Syntax.verify_signature(
                &signer.public_key,
                c.signed.signature_algorithm,
                &c.signed.tbs,
                &c.signed.signature,
            )
        {
            return Err(Error::UnqualifiedPhysical);
        }
        if c.base_number.is_some() {
            if delta.replace((i, c)).is_some() {
                return Err(Error::Duplicate);
            }
        } else if base.replace((i, c)).is_some() {
            return Err(Error::Duplicate);
        }
    }
    let (index, base) = base.ok_or(Error::UnqualifiedPhysical)?;
    used.insert(index);
    let key = |entry: &&crl::Entry| entry.issuer == cert.issuer && entry.serial == cert.serial;
    let mut entry = base.entries.iter().find(key);
    if let Some((index, delta)) = delta {
        let (b, d, min) = (
            base.number.as_ref(),
            delta.number.as_ref(),
            delta.base_number.as_ref(),
        );
        let (Some(b), Some(d), Some(min)) = (b, d, min) else {
            return Err(Error::UnqualifiedPhysical);
        };
        if compare_number(b, min).is_lt()
            || !compare_number(b, d).is_lt()
            || base.signed.this_update > delta.signed.this_update
            || base.authority_key != delta.authority_key
            || base.distribution_der != delta.distribution_der
        {
            return Err(Error::UnqualifiedPhysical);
        }
        used.insert(index);
        if let Some(changed) = delta.entries.iter().find(key) {
            if changed.reason == 8 && !entry.is_some_and(|old| old.reason == 6) {
                return Err(Error::UnqualifiedPhysical);
            }
            entry = Some(changed);
        }
    }
    // A future entry is never usable new H evidence; removeFromCRL is represented
    // distinctly so it cannot authorize a terminal exclusion or reinstatement.
    match entry {
        Some(entry) if entry.date > time => Err(Error::UnqualifiedPhysical),
        Some(entry) => Ok(Some(entry.reason)),
        None => Ok(None),
    }
}
fn compare_number(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    a.len().cmp(&b.len()).then(a.cmp(b))
}

#[cfg(test)]
#[path = "validate_crl_key_tests.rs"]
mod key_tests;
