//! Monotone exact terminal targets. New entries are tentative until the normal
//! parent-set block certificate and canonical installation authenticate them.
use super::{
    Context, Evidence, Operation, Target, TargetClass, TargetScope, enabled, validate_crl,
};
use crate::{Error, Hash, Result, blocks, domain_hash, execution::State};
use minicbor::{Decoder, Encoder};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
pub const RECORD_TAG: u8 = 66;
pub const MAX_EXCLUDED_LINEAGES: usize = 1024;
pub const MAX_RECORD_BYTES: usize = super::MAX_OPERATION_BYTES + MAX_EXCLUDED_LINEAGES * 34 + 64;
pub const RECORD_KEY_DOMAIN: &[u8] = b"MUTINY-BUILD8-ENDORSEMENT-WITHDRAWAL-KEY-V1";
fn key(target: &Target) -> Result<Hash> {
    Ok(domain_hash(RECORD_KEY_DOMAIN, &target.encode()?))
}
pub(crate) fn is_record(raw: &[u8]) -> bool {
    let mut d = Decoder::new(raw);
    d.array().ok().flatten().is_some() && d.u8().ok() == Some(2) && d.u8().ok() == Some(RECORD_TAG)
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Record {
    operation: Operation,
    lineages: BTreeSet<Hash>,
    terminal_no_quorum: bool,
}
fn encode(record: &Record) -> Result<Vec<u8>> {
    if record.lineages.len() > MAX_EXCLUDED_LINEAGES || record.lineages.contains(&[0; 32]) {
        return Err(Error::Capacity);
    }
    let mut e = Encoder::new(Vec::new());
    e.array(5)
        .unwrap()
        .u8(2)
        .unwrap()
        .u8(RECORD_TAG)
        .unwrap()
        .bytes(&record.operation.encode()?)
        .unwrap()
        .array(record.lineages.len() as u64)
        .unwrap();
    for lineage in &record.lineages {
        e.bytes(lineage).unwrap();
    }
    e.bool(record.terminal_no_quorum).unwrap();
    let raw = e.into_writer();
    if raw.len() > MAX_RECORD_BYTES {
        return Err(Error::Oversize);
    }
    Ok(raw)
}
fn decode(raw: &[u8]) -> Result<Record> {
    blocks::canonical(raw, MAX_RECORD_BYTES)?;
    let mut d = Decoder::new(raw);
    if d.array().map_err(|_| Error::Codec)? != Some(5)
        || d.u8().map_err(|_| Error::Codec)? != 2
        || d.u8().map_err(|_| Error::Codec)? != RECORD_TAG
    {
        return Err(Error::Codec);
    }
    let operation = Operation::decode(d.bytes().map_err(|_| Error::Codec)?)?;
    let count = d.array().map_err(|_| Error::Codec)?.ok_or(Error::Codec)?;
    if count > MAX_EXCLUDED_LINEAGES as u64 {
        return Err(Error::Capacity);
    }
    let mut lineages = BTreeSet::new();
    let mut previous = None;
    for _ in 0..count {
        let lineage: Hash = d
            .bytes()
            .map_err(|_| Error::Codec)?
            .try_into()
            .map_err(|_| Error::Codec)?;
        if lineage == [0; 32] || previous.is_some_and(|p| p >= lineage) {
            return Err(Error::NonCanonical);
        }
        lineages.insert(lineage);
        previous = Some(lineage);
    }
    let record = Record {
        operation,
        lineages,
        terminal_no_quorum: d.bool().map_err(|_| Error::Codec)?,
    };
    if d.position() != raw.len() || encode(&record)? != raw {
        return Err(Error::NonCanonical);
    }
    Ok(record)
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Book {
    entries: BTreeMap<Target, Record>,
}
impl Book {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub(crate) fn terminal_no_quorum(&self) -> bool {
        self.entries
            .values()
            .any(|record| record.terminal_no_quorum)
    }
    /// Derived only after the complete H lifecycle: a historical withdrawal
    /// alone does not cause a halt when unrelated participation later hits zero.
    /// Exact full execution/replay recomputes this metadata before StateRoot;
    /// neither operation callers nor structural codecs can set it as authority.
    pub(crate) fn finish_transition(
        &self,
        height: u64,
        registry: &crate::recovery::ContinuityState,
    ) -> Result<Self> {
        let zero = registry.weights()?.iter().all(|weight| weight.is_zero());
        if self.terminal_no_quorum() && !zero {
            return Err(Error::NoQuorum);
        }
        let mut next = self.clone();
        for record in next
            .entries
            .values_mut()
            .filter(|r| r.operation.context.height == height)
        {
            record.terminal_no_quorum |= zero;
        }
        Ok(next)
    }
    /// No public import/mutator, caller affected list, eligibility flag, delete,
    /// replacement-root or reinstatement method exists.
    pub(crate) fn stage(
        &self,
        parent: &State,
        state: &State,
        expected: &Context,
        operations: &[Operation],
    ) -> Result<Self> {
        let parameters = parameters(state)?;
        if !enabled(&parameters)? {
            return Err(Error::WrongOperation);
        }
        let mut next = self.clone();
        for op in operations {
            if &op.context != expected {
                return Err(Error::WrongAnchor);
            }
            verify_evidence(state, op, &parameters)?;
            let mut lineages = parent
                .endorsement_dependencies_v1
                .affected(parent, &op.target)?;
            lineages.extend(
                state
                    .endorsement_dependencies_v1
                    .affected(state, &op.target)?,
            );
            let record = Record {
                operation: op.clone(),
                lineages,
                terminal_no_quorum: false,
            };
            encode(&record)?;
            if next.entries.insert(op.target.clone(), record).is_some() {
                return Err(Error::Duplicate);
            }
        }
        Ok(next)
    }
    pub(crate) fn affected(&self, state: &State) -> Result<BTreeSet<Hash>> {
        let mut lineages = BTreeSet::new();
        for (target, record) in &self.entries {
            lineages.extend(&record.lineages);
            lineages.extend(state.endorsement_dependencies_v1.affected(state, target)?);
        }
        Ok(lineages)
    }
    /// The independently pinned historical StateRoot authenticates inclusion
    /// metadata on restoration; the supplied record does not supply finality.
    pub(crate) fn records(&self, state: &State) -> Result<BTreeMap<Hash, Vec<u8>>> {
        if self.entries.is_empty() {
            return Ok(BTreeMap::new());
        }
        let parameters = parameters(state)?;
        if !enabled(&parameters)? {
            return Err(Error::WrongOperation);
        }
        let registry = state.continuity.as_ref().ok_or(Error::UnknownSigner)?;
        let zero = registry.weights()?.iter().all(|weight| weight.is_zero());
        if self.terminal_no_quorum() && !zero {
            return Err(Error::UnqualifiedPhysical);
        }
        let mut rows = BTreeMap::new();
        for (target, record) in &self.entries {
            let op = &record.operation;
            if target != &op.target
                || op.context.genesis != registry.genesis
                || op.context.fingerprint != registry.fingerprint
                || op.context.height > state.accounting.slots.last_height
                || (op.context.height == state.accounting.slots.last_height
                    && record.terminal_no_quorum != zero)
            {
                return Err(Error::WrongAnchor);
            }
            verify_evidence(state, op, &parameters)?;
            if record
                .lineages
                .iter()
                .any(|lineage| !registry.members.iter().any(|m| m.lineage == *lineage))
            {
                return Err(Error::InvalidLineage);
            }
            if rows.insert(key(target)?, encode(record)?).is_some() {
                return Err(Error::Duplicate);
            }
        }
        let affected = self.affected(state)?;
        let nodes: BTreeSet<_> = registry
            .members
            .iter()
            .filter(|m| affected.contains(&m.lineage))
            .map(|m| m.node)
            .collect();
        if registry
            .members
            .iter()
            .any(|m| affected.contains(&m.lineage) && m.eligible)
            || !state.membership_v2.endorsement_exclusions_clear(&nodes)?
        {
            return Err(Error::UnqualifiedPhysical);
        }
        Ok(rows)
    }
    pub(crate) fn from_records(rows: &BTreeMap<Hash, Vec<u8>>, state: &State) -> Result<Self> {
        let mut book = Self::default();
        for (stored_key, raw) in rows {
            let record = decode(raw)?;
            if *stored_key != key(&record.operation.target)? {
                return Err(Error::WrongAnchor);
            }
            if book
                .entries
                .insert(record.operation.target.clone(), record)
                .is_some()
            {
                return Err(Error::Duplicate);
            }
        }
        if book.records(state)? != *rows {
            return Err(Error::NonCanonical);
        }
        Ok(book)
    }
}
fn parameters(state: &State) -> Result<crate::genesis_v2::Parameters> {
    crate::genesis_v2::Parameters::decode(
        state
            .protocol_records
            .get(&crate::genesis_v2::parameters_key())
            .ok_or(Error::UnqualifiedPhysical)?,
    )
    .map_err(|_| Error::Codec)
}
fn verify_evidence(
    state: &State,
    op: &Operation,
    parameters: &crate::genesis_v2::Parameters,
) -> Result<()> {
    op.encode()?;
    state.endorsement_dependencies_v1.records(state)?;
    let resolved = state.endorsement_dependencies_v1.resolve(state, &op.target);
    match &op.evidence {
        Evidence::Crl {
            target_certificate,
            signer_chain,
            crls,
        } => validate_crl::verify(
            &op.target,
            &resolved?,
            target_certificate,
            signer_chain,
            crls,
            parameters,
            op.context.timestamp,
        ),
        Evidence::Judgment { evidence, .. } => {
            // The explicit finality-authorized judgment is not a proof of the
            // allegation. Target identity still requires authenticated provenance.
            if resolved.is_ok() {
                return Ok(());
            }
            // A not-yet-used frozen root may still be withdrawn. Exact DER is
            // authenticated by the committed root hash, not by a self-signature.
            if op.target.class != TargetClass::Root {
                return Err(Error::UnknownSigner);
            }
            for raw in evidence {
                if raw.len() > crate::ek_chain::MAX_CERTIFICATE_BYTES {
                    continue;
                }
                let hash: Hash = Sha256::digest(raw).into();
                if !parameters.witness_policy()?.anchors().iter()
                    .any(|anchor| anchor.root_cert_der_sha256==hash) {
                    continue;
                }
                let identity = match op.target.scope {
                    TargetScope::Certificate => hash,
                    TargetScope::Key => crate::x509_syntax::certified_public_key_sha256(raw)
                        .map_err(|_| Error::UnqualifiedPhysical)?,
                };
                if identity == op.target.identity {
                    return Ok(());
                }
            }
            Err(Error::UnknownSigner)
        }
    }
}
