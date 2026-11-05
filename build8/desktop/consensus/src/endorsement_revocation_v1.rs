//! A2 candidate carrier. Decoding is structural only and never authorizes removal.
//! Full execution must authenticate its evidence, exact context and dependency index;
//! canonical installation still requires the unchanged finalized-parent certificate.
use crate::{Error, Hash, NETWORK_ID, Result, blocks, domain_hash};
use minicbor::{Decoder, Encoder};
mod book;
mod crl;
mod validate_crl;
pub use book::Book;
pub(crate) use book::is_record;
#[cfg(test)]
#[path = "endorsement_revocation_v1/tests.rs"]
mod route_tests;
// Exact-context private modeled host: absent from every normal library graph.
#[cfg(test)]
pub(crate) use route_tests::native16_test_host;
pub use book::{MAX_EXCLUDED_LINEAGES, MAX_RECORD_BYTES, RECORD_KEY_DOMAIN, RECORD_TAG};

pub const OPERATION_KIND: u8 = 25;
pub const MAX_OPERATION_BYTES: usize = 196_608;
pub const MAX_CONTEXT_BYTES: usize = 256;
pub const MAX_TARGET_BYTES: usize = 64;
pub const MAX_EVIDENCE_BYTES: usize = 196_096;
pub const MAX_JUDGMENT_BYTES: usize = 131_072;
pub const MAX_JUDGMENT_ITEMS: usize = 16;
pub const MAX_REASON_BYTES: usize = 512;
pub const OPERATION_ID_DOMAIN: &[u8] = b"MUTINY-BUILD8-ENDORSEMENT-WITHDRAWAL-ID-V1";
pub const RULE_ENTRY: &[u8] = b"terminal-endorsement-withdrawal-v1";
pub const RULE_DOMAIN: &[u8] = b"MUTINY-BUILD8-ENDORSEMENT-WITHDRAWAL-RULE-V1";
/// The candidate fingerprint commits to this exact description; no local enable flag.
pub fn rule_commitment() -> Hash {
    let mut e = Encoder::new(Vec::new());
    e.array(29)
        .unwrap()
        .u8(2)
        .unwrap()
        .u8(OPERATION_KIND)
        .unwrap()
        .u8(65)
        .unwrap()
        .u8(RECORD_TAG)
        .unwrap()
        .u64(MAX_OPERATION_BYTES as u64)
        .unwrap()
        .u64(MAX_CONTEXT_BYTES as u64)
        .unwrap()
        .u64(MAX_TARGET_BYTES as u64)
        .unwrap()
        .u64(MAX_EVIDENCE_BYTES as u64)
        .unwrap()
        .u64(MAX_JUDGMENT_BYTES as u64)
        .unwrap()
        .u64(MAX_JUDGMENT_ITEMS as u64)
        .unwrap()
        .u64(MAX_REASON_BYTES as u64)
        .unwrap()
        .u8(crate::admission_public_v3::VERSION)
        .unwrap()
        .u64(crate::admission_public_v3::MAX_OPERATION_BYTES as u64)
        .unwrap()
        .u64(crate::admission_public_v3::MAX_SIGNED_BYTES as u64)
        .unwrap()
        .u64(crate::attestation_witness::MAX_WITNESS_BYTES as u64)
        .unwrap()
        .u64(MAX_RECORD_BYTES as u64)
        .unwrap()
        .u64(MAX_EXCLUDED_LINEAGES as u64)
        .unwrap()
        .u8(1) // derived terminal-NoQuorum metadata scheme; never a carrier flag
        .unwrap()
        .u8(crate::recovery_public_v3::VERSION)
        .unwrap()
        .u64(crate::recovery_public_v3::MAX_BYTES as u64)
        .unwrap()
        .u64(crate::body_capacity_v3::MAX_ORDINARY_ITEM_BYTES as u64)
        .unwrap()
        .u64(crate::body_capacity_v3::MAX_LEGACY_BODY_BYTES as u64)
        .unwrap()
        .u64(crate::body_capacity_v3::MAX_ITEMS as u64)
        .unwrap()
        .u64(crate::body_capacity_v3::MAX_OVERSIZED_A2_ITEMS as u64)
        .unwrap()
        .u64(crate::body_capacity_v3::MAX_BODY_BYTES as u64)
        .unwrap()
        .u64(crate::body_capacity_v3::MAX_ENVELOPE_BYTES as u64)
        .unwrap()
        .u64(crate::body_capacity_v3::MAX_PROPOSAL_BYTES as u64)
        .unwrap()
        .u64(2_097_152) // unchanged transport object ceiling
        .unwrap()
        .u8(1) // exact remove-one/reencode projection; legacy quotas unchanged
        .unwrap();
    domain_hash(RULE_DOMAIN, &e.into_writer())
}
pub(crate) fn enabled(parameters: &crate::genesis_v2::Parameters) -> Result<bool> {
    let Some((_, hash)) = parameters
        .rules
        .commitments
        .iter()
        .find(|(name, _)| name == RULE_ENTRY)
    else {
        return Ok(false);
    };
    if *hash != rule_commitment() {
        return Err(Error::WrongFingerprint);
    }
    Ok(true)
}
/// Component/projection gate with no StateRoot recursion. A projected authority
/// must retain the complete authenticated index and terminal exclusions even
/// when canonical history has not yet been installed.
pub(crate) fn check_components(state: &crate::execution::State) -> Result<()> {
    let parameters = state
        .protocol_records
        .get(&crate::genesis_v2::parameters_key())
        .map(|raw| crate::genesis_v2::Parameters::decode(raw).map_err(|_| Error::Codec))
        .transpose()?;
    let selected = parameters
        .as_ref()
        .map(enabled)
        .transpose()?
        .unwrap_or(false);
    if selected {
        if state.endorsement_dependencies_v1.is_empty() {
            return Err(Error::UnqualifiedPhysical);
        }
        state.endorsement_dependencies_v1.records(state)?;
        state.endorsement_revocations_v1.records(state)?;
    } else if !state.endorsement_dependencies_v1.is_empty()
        || !state.endorsement_revocations_v1.is_empty()
    {
        return Err(Error::WrongOperation);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Context {
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub parent_height: u64,
    pub parent_block: Hash,
    pub parent_state: Hash,
    pub height: u64,
    pub timestamp: u64,
}
impl Context {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if [
            self.genesis,
            self.fingerprint,
            self.parent_block,
            self.parent_state,
        ]
        .contains(&[0; 32])
            || self.parent_height.checked_add(1) != Some(self.height)
            || self.timestamp == 0
        {
            return Err(Error::WrongAnchor);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(9)
            .unwrap()
            .u8(1)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .u64(self.parent_height)
            .unwrap()
            .bytes(&self.parent_block)
            .unwrap()
            .bytes(&self.parent_state)
            .unwrap()
            .u64(self.height)
            .unwrap()
            .u64(self.timestamp)
            .unwrap();
        Ok(e.into_writer())
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        blocks::canonical(raw, MAX_CONTEXT_BYTES)?;
        let mut d = Decoder::new(raw);
        array(&mut d, 9)?;
        if d.u8().map_err(codec)? != 1 || d.u32().map_err(codec)? != NETWORK_ID {
            return Err(Error::WrongNetwork);
        }
        let value = Self {
            genesis: hash(&mut d)?,
            fingerprint: hash(&mut d)?,
            parent_height: d.u64().map_err(codec)?,
            parent_block: hash(&mut d)?,
            parent_state: hash(&mut d)?,
            height: d.u64().map_err(codec)?,
            timestamp: d.u64().map_err(codec)?,
        };
        exact(&d, raw, &value.encode()?)?;
        Ok(value)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum TargetClass {
    Root = 1,
    Intermediate = 2,
    Ek = 3,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum TargetScope {
    Certificate = 1,
    Key = 2,
}
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Target {
    pub class: TargetClass,
    pub scope: TargetScope,
    pub identity: Hash,
}
impl Target {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.identity == [0; 32] {
            return Err(Error::Codec);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(self.class as u8)
            .unwrap()
            .u8(self.scope as u8)
            .unwrap()
            .bytes(&self.identity)
            .unwrap();
        Ok(e.into_writer())
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        blocks::canonical(raw, MAX_TARGET_BYTES)?;
        let mut d = Decoder::new(raw);
        array(&mut d, 4)?;
        if d.u8().map_err(codec)? != 1 {
            return Err(Error::Codec);
        }
        let class = match d.u8().map_err(codec)? {
            1 => TargetClass::Root,
            2 => TargetClass::Intermediate,
            3 => TargetClass::Ek,
            _ => return Err(Error::Codec),
        };
        let scope = match d.u8().map_err(codec)? {
            1 => TargetScope::Certificate,
            2 => TargetScope::Key,
            _ => return Err(Error::Codec),
        };
        let value = Self {
            class,
            scope,
            identity: hash(&mut d)?,
        };
        exact(&d, raw, &value.encode()?)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Evidence {
    /// Exact target certificate, signer chain and base/optional delta. No parser result is trusted here.
    Crl {
        target_certificate: Vec<u8>,
        signer_chain: Vec<Vec<u8>>,
        crls: Vec<Vec<u8>>,
    },
    /// Explicit terminal quorum judgment, not cryptographic proof of the allegation.
    Judgment {
        reason: Vec<u8>,
        evidence: Vec<Vec<u8>>,
    },
}
impl Evidence {
    fn bounds(&self) -> Result<()> {
        match self {
            Self::Crl {
                target_certificate,
                signer_chain,
                crls,
            } => {
                bounded(target_certificate, crate::ek_chain::MAX_CERTIFICATE_BYTES)?;
                if signer_chain.is_empty()
                    || signer_chain.len() > crate::ek_chain::MAX_CHAIN
                    || crls.is_empty()
                    || crls.len() > crate::ek_chain::MAX_CRLS
                {
                    return Err(Error::Capacity);
                }
                for c in signer_chain {
                    bounded(c, crate::ek_chain::MAX_CERTIFICATE_BYTES)?;
                }
                for c in crls {
                    bounded(c, crate::ek_chain::MAX_CRL_BYTES)?;
                }
            }
            Self::Judgment { reason, evidence } => {
                bounded(reason, MAX_REASON_BYTES)?;
                if evidence.is_empty() || evidence.len() > MAX_JUDGMENT_ITEMS {
                    return Err(Error::Capacity);
                }
                let mut total = 0usize;
                for item in evidence {
                    bounded(item, MAX_JUDGMENT_BYTES)?;
                    total = total.checked_add(item.len()).ok_or(Error::Oversize)?;
                    if total > MAX_JUDGMENT_BYTES {
                        return Err(Error::Oversize);
                    }
                }
            }
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.bounds()?;
        let mut e = Encoder::new(Vec::new());
        match self {
            Self::Crl {
                target_certificate,
                signer_chain,
                crls,
            } => {
                e.array(5)
                    .unwrap()
                    .u8(1)
                    .unwrap()
                    .u8(1)
                    .unwrap()
                    .bytes(target_certificate)
                    .unwrap();
                e.array(signer_chain.len() as u64).unwrap();
                for cert in signer_chain {
                    e.bytes(cert).unwrap();
                }
                e.array(crls.len() as u64).unwrap();
                for crl in crls {
                    e.bytes(crl).unwrap();
                }
            }
            Self::Judgment { reason, evidence } => {
                e.array(5)
                    .unwrap()
                    .u8(1)
                    .unwrap()
                    .u8(2)
                    .unwrap()
                    .bool(true)
                    .unwrap()
                    .bytes(reason)
                    .unwrap();
                e.array(evidence.len() as u64).unwrap();
                for item in evidence {
                    e.bytes(item).unwrap();
                }
            }
        }
        let raw = e.into_writer();
        if raw.len() > MAX_EVIDENCE_BYTES {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        blocks::canonical(raw, MAX_EVIDENCE_BYTES)?;
        let mut d = Decoder::new(raw);
        array(&mut d, 5)?;
        if d.u8().map_err(codec)? != 1 {
            return Err(Error::Codec);
        }
        let value = match d.u8().map_err(codec)? {
            1 => Self::Crl {
                target_certificate: bytes(&mut d, crate::ek_chain::MAX_CERTIFICATE_BYTES)?,
                signer_chain: items(
                    &mut d,
                    crate::ek_chain::MAX_CHAIN,
                    crate::ek_chain::MAX_CERTIFICATE_BYTES,
                )?,
                crls: items(
                    &mut d,
                    crate::ek_chain::MAX_CRLS,
                    crate::ek_chain::MAX_CRL_BYTES,
                )?,
            },
            2 => {
                if !d.bool().map_err(codec)? {
                    return Err(Error::WrongOperation);
                }
                Self::Judgment {
                    reason: bytes(&mut d, MAX_REASON_BYTES)?,
                    evidence: items(&mut d, MAX_JUDGMENT_ITEMS, MAX_JUDGMENT_BYTES)?,
                }
            }
            _ => return Err(Error::WrongOperation),
        };
        exact(&d, raw, &value.encode()?)?;
        Ok(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation {
    pub context: Context,
    pub target: Target,
    pub evidence: Evidence,
}
impl Operation {
    pub fn encode(&self) -> Result<Vec<u8>> {
        if self.target.class == TargetClass::Root && matches!(self.evidence, Evidence::Crl { .. }) {
            return Err(Error::WrongOperation);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(OPERATION_KIND)
            .unwrap()
            .bytes(&self.context.encode()?)
            .unwrap()
            .bytes(&self.target.encode()?)
            .unwrap()
            .bytes(&self.evidence.encode()?)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_OPERATION_BYTES {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        blocks::canonical(raw, MAX_OPERATION_BYTES)?;
        let mut d = Decoder::new(raw);
        array(&mut d, 5)?;
        if d.u8().map_err(codec)? != 2 || d.u8().map_err(codec)? != OPERATION_KIND {
            return Err(Error::WrongOperation);
        }
        let context = Context::decode(&borrowed(&mut d, MAX_CONTEXT_BYTES)?)?;
        let target = Target::decode(&borrowed(&mut d, MAX_TARGET_BYTES)?)?;
        let evidence = Evidence::decode(&borrowed(&mut d, MAX_EVIDENCE_BYTES)?)?;
        let value = Self {
            context,
            target,
            evidence,
        };
        exact(&d, raw, &value.encode()?)?;
        Ok(value)
    }
    pub fn id(&self) -> Result<Hash> {
        Ok(domain_hash(OPERATION_ID_DOMAIN, &self.encode()?))
    }
}
fn codec(_: minicbor::decode::Error) -> Error {
    Error::Codec
}
fn array(d: &mut Decoder<'_>, n: u64) -> Result<()> {
    if d.array().map_err(codec)? != Some(n) {
        return Err(Error::Codec);
    }
    Ok(())
}
fn hash(d: &mut Decoder<'_>) -> Result<Hash> {
    d.bytes()
        .map_err(codec)?
        .try_into()
        .map_err(|_| Error::Codec)
}
fn bounded(raw: &[u8], limit: usize) -> Result<()> {
    if raw.is_empty() || raw.len() > limit {
        return Err(Error::Oversize);
    }
    Ok(())
}
fn borrowed<'b>(d: &mut Decoder<'b>, limit: usize) -> Result<&'b [u8]> {
    let raw = d.bytes().map_err(codec)?;
    bounded(raw, limit)?;
    Ok(raw)
}
fn bytes(d: &mut Decoder<'_>, limit: usize) -> Result<Vec<u8>> {
    Ok(borrowed(d, limit)?.to_vec())
}
fn items(d: &mut Decoder<'_>, max: usize, item_limit: usize) -> Result<Vec<Vec<u8>>> {
    let n = d.array().map_err(codec)?.ok_or(Error::Codec)?;
    if n == 0 || n > max as u64 {
        return Err(Error::Capacity);
    }
    let mut values = Vec::with_capacity(n as usize);
    for _ in 0..n {
        values.push(bytes(d, item_limit)?);
    }
    Ok(values)
}
fn exact(d: &Decoder<'_>, raw: &[u8], encoded: &[u8]) -> Result<()> {
    if d.position() != raw.len() || encoded != raw {
        return Err(Error::NonCanonical);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn operation() -> Operation {
        Operation {
            context: Context {
                genesis: [1; 32],
                fingerprint: [2; 32],
                parent_height: 9,
                parent_block: [3; 32],
                parent_state: [4; 32],
                height: 10,
                timestamp: 1_000,
            },
            target: Target {
                class: TargetClass::Root,
                scope: TargetScope::Certificate,
                identity: [5; 32],
            },
            evidence: Evidence::Judgment {
                reason: b"TEST-VALUE explicit trust withdrawal".to_vec(),
                evidence: vec![
                    b"Public software fixture report; no manufacturer or physical claim".to_vec(),
                ],
            },
        }
    }
    #[test]
    fn structural_carrier_roundtrip_has_explicit_scope_context_and_judgment() {
        let op = operation();
        let raw = op.encode().unwrap();
        assert_eq!(Operation::decode(&raw).unwrap(), op);
        let mut key_scope = op.clone();
        key_scope.target.scope = TargetScope::Key;
        assert_ne!(op.id().unwrap(), key_scope.id().unwrap());
        let mut next_context = op.clone();
        next_context.context.timestamp += 1;
        assert_ne!(op.id().unwrap(), next_context.id().unwrap());
        // Signature/certificate/native installation is not tested by this codec fixture.
        assert_eq!(raw[0..3], [0x85, 0x02, 0x18]);
        assert_eq!(raw[3], OPERATION_KIND);
    }
    #[test]
    fn structural_carrier_refuses_implicit_root_crl_scope_widening_and_alternate_bytes() {
        let op = operation();
        let raw = op.encode().unwrap();
        let mut trailing = raw.clone();
        trailing.push(0);
        assert_eq!(Operation::decode(&trailing), Err(Error::NonCanonical));
        let mut wrong_kind = raw.clone();
        wrong_kind[3] = 23;
        // Two-byte encoding of 23 is alternate CBOR; preserve that refusal separately.
        assert_eq!(Operation::decode(&wrong_kind), Err(Error::NonCanonical));
        wrong_kind.remove(2); // canonical single-byte kind23, same OP namespace.
        assert_eq!(Operation::decode(&wrong_kind), Err(Error::WrongOperation));
        let mut root_crl = op.clone();
        root_crl.evidence = Evidence::Crl {
            target_certificate: vec![1],
            signer_chain: vec![vec![2]],
            crls: vec![vec![3]],
        };
        assert_eq!(root_crl.encode(), Err(Error::WrongOperation));
        let mut nonterminal = op.evidence.encode().unwrap();
        assert_eq!(&nonterminal[..4], &[0x85, 1, 2, 0xf5]);
        nonterminal[3] = 0xf4;
        assert_eq!(Evidence::decode(&nonterminal), Err(Error::WrongOperation));
        assert_eq!(
            Operation::decode(&vec![0; MAX_OPERATION_BYTES + 1]),
            Err(Error::Oversize)
        );
        let mut reason = op.clone();
        reason.evidence = Evidence::Judgment {
            reason: vec![1; MAX_REASON_BYTES + 1],
            evidence: vec![vec![2]],
        };
        assert_eq!(reason.encode(), Err(Error::Oversize));
        let mut overflow = op.clone();
        overflow.context.parent_height = u64::MAX;
        assert_eq!(overflow.encode(), Err(Error::WrongAnchor));
        let mut empty = op;
        empty.target.identity = [0; 32];
        assert_eq!(empty.encode(), Err(Error::Codec));
    }
}
