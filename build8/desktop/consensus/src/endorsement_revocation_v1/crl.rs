//! Separate A2 CRL syntax. Historical admission CRL behavior stays unchanged.
//! Parsing retains reason/date/issuer/scope; it does not authenticate a signer.
use crate::ek_chain::{CertificateSyntax, MAX_CRL_BYTES, ParsedCrl};
use crate::x509_syntax::{X509Syntax, oids};
use std::collections::BTreeSet;
use x509_cert::{
    crl::CertificateList,
    der::{
        Decode, Encode,
        asn1::{ObjectIdentifier, Uint},
    },
    ext::pkix::{
        AuthorityKeyIdentifier, IssuingDistributionPoint,
        crl::CrlReason,
        name::{GeneralName, GeneralNames},
    },
};
pub(super) const MAX_ENTRIES: usize = 2048;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Failure {
    Bounds,
    Encoding,
    Extension,
    EntryIssuer,
    Duplicate,
    Number,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Entry {
    pub issuer: Vec<u8>,
    pub serial: Vec<u8>,
    pub date: u64,
    pub reason: u8,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Parsed {
    pub signed: ParsedCrl,
    pub authority_key: Option<Vec<u8>>,
    pub number: Option<Vec<u8>>,
    pub base_number: Option<Vec<u8>>,
    pub distribution: Option<IssuingDistributionPoint>,
    pub distribution_der: Option<Vec<u8>>,
    pub entries: Vec<Entry>,
}
const REASON: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.21");
const CERTIFICATE_ISSUER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.29");
fn strict<'a, T: Decode<'a> + Encode>(raw: &'a [u8]) -> Result<T, Failure> {
    let value = T::from_der(raw).map_err(|_| Failure::Encoding)?;
    if value.to_der().map_err(|_| Failure::Encoding)? != raw {
        return Err(Failure::Encoding);
    }
    Ok(value)
}
fn number(raw: &[u8]) -> Result<Vec<u8>, Failure> {
    let value: Uint = strict(raw)?;
    if value.as_bytes().len() > 20 {
        return Err(Failure::Number);
    }
    Ok(value.as_bytes().to_vec())
}
fn issuer(raw: &[u8]) -> Result<Vec<u8>, Failure> {
    let names: GeneralNames = strict(raw)?;
    let [GeneralName::DirectoryName(name)] = names.as_slice() else {
        return Err(Failure::EntryIssuer);
    };
    if name.is_empty() {
        return Err(Failure::EntryIssuer);
    }
    name.to_der().map_err(|_| Failure::Encoding)
}
pub(super) fn parse(raw: &[u8]) -> Result<Parsed, Failure> {
    if raw.is_empty() || raw.len() > MAX_CRL_BYTES {
        return Err(Failure::Bounds);
    }
    // Reuse only the reviewed DER/signature-algorithm structural checks. The old
    // procedure's admission status interpretation is deliberately not called.
    let signed = X509Syntax.parse_crl(raw).map_err(|_| Failure::Encoding)?;
    let crl: CertificateList = strict(raw)?;
    let tbs = &crl.tbs_cert_list;
    if !matches!(signed.version, 1 | 2)
        || (signed.version == 1
            && (tbs.crl_extensions.is_some()
                || tbs.revoked_certificates.as_ref().is_some_and(|entries| {
                    entries
                        .iter()
                        .any(|entry| entry.crl_entry_extensions.is_some())
                })))
    {
        return Err(Failure::Encoding);
    }
    let mut value = Parsed {
        signed,
        authority_key: None,
        number: None,
        base_number: None,
        distribution: None,
        distribution_der: None,
        entries: Vec::new(),
    };
    if let Some(extensions) = &tbs.crl_extensions {
        for ext in extensions {
            let bytes = ext.extn_value.as_bytes();
            if ext.extn_id == oids::AUTHORITY_KEY_IDENTIFIER {
                if ext.critical {
                    return Err(Failure::Extension);
                }
                let aki: AuthorityKeyIdentifier = strict(bytes)?;
                // Certificate-issuer/serial AKI alternatives need a separately
                // reviewed exact matching rule; never ignore them as key authority.
                if aki.authority_cert_issuer.is_some() || aki.authority_cert_serial_number.is_some()
                {
                    return Err(Failure::Extension);
                }
                value.authority_key = aki.key_identifier.map(|id| id.as_bytes().to_vec());
                if value
                    .authority_key
                    .as_ref()
                    .is_none_or(|key| key.is_empty() || key.len() > 64)
                {
                    return Err(Failure::Extension);
                }
            } else if ext.extn_id == oids::CRL_NUMBER {
                if ext.critical {
                    return Err(Failure::Extension);
                }
                value.number = Some(number(bytes)?);
            } else if ext.extn_id == oids::DELTA_CRL_INDICATOR {
                if !ext.critical {
                    return Err(Failure::Extension);
                }
                value.base_number = Some(number(bytes)?);
            } else if ext.extn_id == oids::ISSUING_DISTRIBUTION_POINT {
                if !ext.critical {
                    return Err(Failure::Extension);
                }
                // Use the actual RFC OID explicitly: x509-cert0.2.5's IDP
                // AssociatedOid constant is unrelated; no generic OID dispatch.
                let idp: IssuingDistributionPoint = strict(bytes)?;
                if [
                    idp.only_contains_user_certs,
                    idp.only_contains_ca_certs,
                    idp.only_contains_attribute_certs,
                ]
                .iter()
                .filter(|flag| **flag)
                .count()
                    > 1
                {
                    return Err(Failure::Extension);
                }
                value.distribution = Some(idp);
                value.distribution_der = Some(bytes.to_vec());
            } else if ext.critical {
                return Err(Failure::Extension);
            }
        }
    }
    if value.base_number.is_some() && value.number.is_none() {
        return Err(Failure::Number);
    }
    let mut current_issuer = value.signed.issuer.clone();
    let mut seen = BTreeSet::new();
    if let Some(entries) = &tbs.revoked_certificates {
        if entries.len() > MAX_ENTRIES {
            return Err(Failure::Bounds);
        }
        for entry in entries {
            let mut reason = 0;
            if let Some(extensions) = &entry.crl_entry_extensions {
                for ext in extensions {
                    if ext.extn_id == REASON {
                        if ext.critical {
                            return Err(Failure::Extension);
                        }
                        reason = strict::<CrlReason>(ext.extn_value.as_bytes())? as u8;
                    } else if ext.extn_id == CERTIFICATE_ISSUER {
                        if !ext.critical
                            || !value
                                .distribution
                                .as_ref()
                                .is_some_and(|idp| idp.indirect_crl)
                        {
                            return Err(Failure::EntryIssuer);
                        }
                        // RFC issuer inheritance applies to following entries too.
                        current_issuer = issuer(ext.extn_value.as_bytes())?;
                    } else if ext.critical {
                        return Err(Failure::Extension);
                    }
                }
            }
            // Compare positive serial magnitudes exactly as certificate parsing
            // does; DER's required sign-padding 00 is not part of the identity.
            // Exact signed DER is retained and verified separately unchanged.
            let serial = match entry.serial_number.as_bytes() {
                [] | [0] => return Err(Failure::Encoding),
                [first, ..] if first & 0x80 != 0 => return Err(Failure::Encoding),
                [0, rest @ ..] => rest.to_vec(),
                all => all.to_vec(),
            };
            if !seen.insert((current_issuer.clone(), serial.clone())) {
                return Err(Failure::Duplicate);
            }
            value.entries.push(Entry {
                issuer: current_issuer.clone(),
                serial,
                date: entry.revocation_date.to_unix_duration().as_secs(),
                reason,
            });
        }
    }
    Ok(value)
}
