//! PROPOSED / UNFROZEN (Architect's Continuation Order of 4 Oct 2026, decision A7; design
//! `qualification/candidate-3/A-ADMISSION-DESIGN-V1.md` section 8). The committed attestation witness.
//!
//! Persistent state keeps only the identities and the witness commitment inside the version-2 provenance statement
//! (`provenance::Endorsement`); the witness itself carries what a validator needs to check those values: the EK public
//! areas, the certificate chains with their revocation lists, and the retained (public) part of the supervised
//! credential-activation transcript. Hashes alone prove nothing; `verify_witness` checks the bytes.
//!
//! The user's K1 amendment permits authenticated distribution of the identifying public EK certificates/areas,
//! CRLs and nonsecret activation records; private material remains excluded. Available Genesis public evidence
//! authenticates this witness under committed historical context. Production post-sealing admission remains disabled
//! under hard stop E; witness success supplies neither enforceable locality nor activation proof.
//! NEVER contains private keys or the activation secret (only its commitment).
//!
//! What a passing witness does NOT establish: possession of the EK by the admitted TPM (the activation record is a
//! transcript that a colluding verifier can produce for a software key: design A3) or the host the node runs on (A6).
use crate::{
    Error, Hash, Result, domain_hash,
    ek_chain::{CertificateSyntax, ChainContext, ChainFailure, validate_endorsement_chain},
    endorsement_identity::{IdentityClasses, IdentityFailure, check_public_area, parse_ek_public_area},
    provenance::Provenance,
};
use minicbor::{Decoder, Encoder};

/// Commitment domain: `witness_sha256 = H(WITNESS_DOMAIN, canonical witness bytes)`.
pub const WITNESS_DOMAIN: &[u8] = b"MUTINY-BUILD8-ATTESTATION-WITNESS-V1";
/// Whole canonical witness (PROPOSED bound; real sizes are evidence inputs I3/I4).
pub const MAX_WITNESS_BYTES: usize = 131_072;
/// One endorsement per identity class, at most four classes.
pub const MAX_ENDORSEMENTS: usize = crate::endorsement_identity::MAX_IDENTITY_CLASSES;

/// One endorsement key's evidence: the TPM's public area, the certificate chain (leaf first, anchor last) and the CRLs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndorsementEvidence {
    pub ek_public_area: Vec<u8>,
    pub certificates: Vec<Vec<u8>>,
    pub crls: Vec<Vec<u8>>,
}
/// The retained, public part of a supervised credential-activation exchange for endorsement `ek_index` (design A3). The
/// secret is NEVER retained: `secret_commitment = H("MUTINY-BUILD8-ACTIVATION-SECRET-V1", secret)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationRecord {
    pub ek_index: u8,
    pub ak_name: [u8; 34],
    pub credential_blob_sha256: Hash,
    pub encrypted_seed_sha256: Hash,
    pub secret_commitment: Hash,
}
/// Canonical CBOR `[1, reference_time, [[ek_public_area, [certificate...], [crl...]] ...], [[ek_index, ak_name,
/// credential_blob_sha256, encrypted_seed_sha256, secret_commitment] ...]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationWitness {
    /// Unix seconds; must equal the committed reference time (design section 3).
    pub reference_time: u64,
    pub endorsements: Vec<EndorsementEvidence>,
    pub activation: Vec<ActivationRecord>,
}
impl AttestationWitness {
    fn check_bounds(&self) -> Result<()> {
        use crate::ek_chain::{MAX_CERTIFICATE_BYTES, MAX_CHAIN, MAX_CRL_BYTES, MAX_CRLS, MIN_CHAIN};
        if self.reference_time == 0 {
            return Err(Error::InvalidCounter);
        }
        if self.endorsements.is_empty()
            || self.endorsements.len() > MAX_ENDORSEMENTS
            || self.activation.len() != self.endorsements.len()
        {
            return Err(Error::Capacity);
        }
        for e in &self.endorsements {
            if e.ek_public_area.is_empty()
                || e.ek_public_area.len() > crate::endorsement_identity::MAX_EK_PUBLIC_AREA
                || e.certificates.len() < MIN_CHAIN
                || e.certificates.len() > MAX_CHAIN
                || e.certificates.iter().any(|c| c.is_empty() || c.len() > MAX_CERTIFICATE_BYTES)
                || e.crls.len() > MAX_CRLS
                || e.crls.iter().any(|c| c.is_empty() || c.len() > MAX_CRL_BYTES)
            {
                return Err(Error::Oversize);
            }
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.check_bounds()?;
        let mut e = Encoder::new(Vec::new());
        e.array(4).unwrap().u8(1).unwrap().u64(self.reference_time).unwrap();
        e.array(self.endorsements.len() as u64).unwrap();
        for ev in &self.endorsements {
            e.array(3).unwrap().bytes(&ev.ek_public_area).unwrap();
            e.array(ev.certificates.len() as u64).unwrap();
            for c in &ev.certificates {
                e.bytes(c).unwrap();
            }
            e.array(ev.crls.len() as u64).unwrap();
            for c in &ev.crls {
                e.bytes(c).unwrap();
            }
        }
        e.array(self.activation.len() as u64).unwrap();
        for a in &self.activation {
            e.array(5)
                .unwrap()
                .u8(a.ek_index)
                .unwrap()
                .bytes(&a.ak_name)
                .unwrap()
                .bytes(&a.credential_blob_sha256)
                .unwrap()
                .bytes(&a.encrypted_seed_sha256)
                .unwrap()
                .bytes(&a.secret_commitment)
                .unwrap();
        }
        let raw = e.into_writer();
        if raw.len() > MAX_WITNESS_BYTES {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    /// Strict: bounded before parsing, definite lengths only, exact re-encoding, no trailing bytes.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_WITNESS_BYTES {
            return Err(Error::Oversize);
        }
        crate::blocks::canonical(raw, MAX_WITNESS_BYTES)?;
        let mut d = Decoder::new(raw);
        let w = (|| -> std::result::Result<Self, minicbor::decode::Error> {
            let bad = || minicbor::decode::Error::message("attestation witness");
            let count = |d: &mut Decoder<'_>, max: usize| -> std::result::Result<usize, minicbor::decode::Error> {
                let n = d.array()?.ok_or_else(bad)?;
                if n > max as u64 {
                    return Err(bad());
                }
                Ok(n as usize)
            };
            if d.array()? != Some(4) || d.u8()? != 1 {
                return Err(bad());
            }
            let reference_time = d.u64()?;
            let n = count(&mut d, MAX_ENDORSEMENTS)?;
            let mut endorsements = Vec::with_capacity(n);
            for _ in 0..n {
                if d.array()? != Some(3) {
                    return Err(bad());
                }
                let ek_public_area = d.bytes()?.to_vec();
                let certificates = (0..count(&mut d, crate::ek_chain::MAX_CHAIN)?)
                    .map(|_| d.bytes().map(<[u8]>::to_vec))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                let crls = (0..count(&mut d, crate::ek_chain::MAX_CRLS)?)
                    .map(|_| d.bytes().map(<[u8]>::to_vec))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                endorsements.push(EndorsementEvidence { ek_public_area, certificates, crls });
            }
            let m = count(&mut d, MAX_ENDORSEMENTS)?;
            let mut activation = Vec::with_capacity(m);
            for _ in 0..m {
                if d.array()? != Some(5) {
                    return Err(bad());
                }
                activation.push(ActivationRecord {
                    ek_index: d.u8()?,
                    ak_name: d.bytes()?.try_into().map_err(|_| bad())?,
                    credential_blob_sha256: d.bytes()?.try_into().map_err(|_| bad())?,
                    encrypted_seed_sha256: d.bytes()?.try_into().map_err(|_| bad())?,
                    secret_commitment: d.bytes()?.try_into().map_err(|_| bad())?,
                });
            }
            Ok(Self { reference_time, endorsements, activation })
        })()
        .map_err(|_| Error::Codec)?;
        if d.position() != raw.len() || w.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(w)
    }
    /// The value a version-2 statement's `witness_sha256` must equal.
    pub fn commitment(&self) -> Result<Hash> {
        Ok(domain_hash(WITNESS_DOMAIN, &self.encode()?))
    }
}

/// Why a witness does not support its statement (index = the endorsement / identity class position).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WitnessFailure {
    /// The statement is not version 2 (no committed identities, no witness commitment).
    NotVersion2,
    /// No witness bytes.
    Missing,
    /// Bytes that are not a canonical, bounded witness.
    Encoding(Error),
    /// `H(WITNESS_DOMAIN, bytes)` differs from the statement's `witness_sha256`.
    CommitmentMismatch,
    /// The witness names a reference time other than the committed one.
    ReferenceTimeMismatch,
    /// Endorsements, activation records and statement identities are not one per committed identity class.
    ClassCount,
    /// The EK public area is malformed or not the committed class template.
    PublicArea(u8, IdentityFailure),
    /// The certificate chain fails the procedure.
    Chain(u8, ChainFailure),
    /// The certified key differs from the TPM's public area key.
    KeyMismatch(u8),
    /// The statement's identity is not the identity of the certified key.
    IdentityMismatch(u8),
    /// The statement's identity root is not the chain's anchor.
    RootMismatch(u8),
    /// The activation record names another endorsement or attestation key, or a zero digest.
    Activation(u8),
}
/// Committed inputs of a witness verification: the chain context (class, committed reference time, anchors) and the
/// committed identity-class list (Lane A1's representation).
pub struct WitnessContext<'a> {
    pub chain: ChainContext<'a>,
    pub identity_classes: &'a IdentityClasses,
}
/// The statement's committed identities and witness commitment are supported by `witness` (design section 8).
pub fn verify_witness(
    statement: &Provenance,
    witness: Option<&[u8]>,
    ctx: &WitnessContext<'_>,
    syntax: &dyn CertificateSyntax,
) -> std::result::Result<(), WitnessFailure> {
    verify_witness_paths(statement, witness, ctx, syntax).map(|_| ())
}
/// The same authenticated witness checks, retaining exact certified paths for
/// the terminal-withdrawal dependency index. This proves neither activation nor locality.
pub(crate) fn verify_witness_paths(
    statement: &Provenance,
    witness: Option<&[u8]>,
    ctx: &WitnessContext<'_>,
    syntax: &dyn CertificateSyntax,
) -> std::result::Result<Vec<crate::ek_chain::VerifiedEndorsement>, WitnessFailure> {
    verify_witness_paths_inner(statement,witness,ctx,syntax,None)
}
/// The selected parameter-derived policy; path/anchor outputs remain exact DER.
pub fn verify_witness_with_policy(
    statement:&Provenance,witness:Option<&[u8]>,
    policy:&crate::test_value_root_alias_v1::WitnessPolicy,reference_time:u64,
    syntax:&dyn CertificateSyntax,
) -> std::result::Result<(),WitnessFailure> {
    verify_witness_paths_with_policy(statement,witness,policy,reference_time,syntax).map(|_|())
}
pub(crate) fn verify_witness_paths_with_policy(
    statement:&Provenance,witness:Option<&[u8]>,
    policy:&crate::test_value_root_alias_v1::WitnessPolicy,reference_time:u64,
    syntax:&dyn CertificateSyntax,
) -> std::result::Result<Vec<crate::ek_chain::VerifiedEndorsement>,WitnessFailure> {
    let context=policy.context(reference_time);
    verify_witness_paths_inner(statement,witness,&context,syntax,Some(policy))
}
fn verify_witness_paths_inner(
    statement:&Provenance,witness:Option<&[u8]>,ctx:&WitnessContext<'_>,
    syntax:&dyn CertificateSyntax,policy:Option<&crate::test_value_root_alias_v1::WitnessPolicy>,
) -> std::result::Result<Vec<crate::ek_chain::VerifiedEndorsement>,WitnessFailure> {
    use WitnessFailure as F;
    let endorsement = statement.endorsement.as_ref().ok_or(F::NotVersion2)?;
    if let Some(policy)=policy {policy.check_primary_root(statement)?;}
    let raw = witness.ok_or(F::Missing)?;
    let w = AttestationWitness::decode(raw).map_err(F::Encoding)?;
    if domain_hash(WITNESS_DOMAIN, raw) != endorsement.witness_sha256 {
        return Err(F::CommitmentMismatch);
    }
    if w.reference_time != ctx.chain.reference_time {
        return Err(F::ReferenceTimeMismatch);
    }
    let classes = ctx.identity_classes.classes();
    if w.endorsements.len() != classes.len() || endorsement.identities.len() != classes.len() {
        return Err(F::ClassCount);
    }
    let mut paths = Vec::with_capacity(classes.len());
    for (i, ((ev, class), (root, identity))) in
        w.endorsements.iter().zip(classes).zip(&endorsement.identities).enumerate()
    {
        let index = i as u8;
        let area = parse_ek_public_area(&ev.ek_public_area).map_err(|e| F::PublicArea(index, e))?;
        check_public_area(&area, class).map_err(|e| F::PublicArea(index, e))?;
        let verified = validate_endorsement_chain(syntax, &ev.certificates, &ev.crls, &ctx.chain)
            .map_err(|e| F::Chain(index, e))?;
        if verified.leaf_key != area.key {
            return Err(F::KeyMismatch(index));
        }
        if area.key.identity().map_err(|e| F::PublicArea(index, e))? != *identity {
            return Err(F::IdentityMismatch(index));
        }
        let logical = match policy {
            None=>Some(verified.anchor),Some(policy)=>policy.logical_root(verified.anchor),
        };
        if logical != Some(*root) {
            return Err(F::RootMismatch(index));
        }
        let a = &w.activation[i];
        if usize::from(a.ek_index) != i
            || a.ak_name != statement.ak_name
            || [a.credential_blob_sha256, a.encrypted_seed_sha256, a.secret_commitment].contains(&[0; 32])
        {
            return Err(F::Activation(index));
        }
        paths.push(verified);
    }
    Ok(paths)
}
