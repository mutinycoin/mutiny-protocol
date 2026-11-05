//! A container for an operation that other parties still have to sign.
//!
//! Several operations (License DvP, hash locks, fiat locks) need two wallet approvals and possibly
//! a maker's proof. A wallet signs its own part and hands the rest on. This container carries
//! ONLY PUBLIC data (Q12: file or QR exchange of public partial operations is acceptable): the
//! operation's own partial encoding, which signatures are still missing, its validity and the
//! coins it reserves. It never contains a key, a phrase or a preimage.
//!
//! The encoding is canonical CBOR with definite lengths inside a checksummed envelope, bounded in
//! every dimension. [`PartialApproval::import`] accepts exactly the bytes [`export`] produces and
//! nothing else: truncation, trailing data, any flipped bit and non-canonical encodings are all
//! refused. Importing proves only that the container is well formed; what the operation inside
//! actually does is established by [`PartialApproval::explain_for`], which runs the same review a
//! proposer would see.
//!
//! [`export`]: PartialApproval::export
use crate::{
    authorize::SignedOperation,
    authorize::SignerIdentity,
    context::{ChainContext, ChainView},
    outbox::OutboxRecord,
    plan::{
        OperationKind, OperationPlan, RequiredSigner, Requirement, RequirementStatus, Slot,
        Validity,
    },
    refusal::{ContextField, Refusal},
    review::Review,
    units,
};
use minicbor::{Decoder, Encoder, data::Type};
use mutiny_consensus_v8::{Hash, domain_hash, transactions::OutPoint};
use std::fmt;

/// Label inside the container.
pub const LABEL: &str = "MUTINY-BUILD8-WALLET-PARTIAL-V1";
/// Container layout version.
pub const VERSION: u8 = 1;
/// Largest accepted container, in bytes.
pub const MAX_CONTAINER_BYTES: usize = 128 * 1024;
/// Largest accepted operation inside a container, in bytes.
pub const MAX_OPERATION_BYTES: usize = 64 * 1024;
/// Most requirements a container may list.
pub const MAX_REQUIREMENTS: usize = 64;
/// Most reserved inputs a container may list.
pub const MAX_RESERVED: usize = 256;

const CHECKSUM_DOMAIN: &[u8] = b"MUTINY-BUILD8-WALLET-PARTIAL-CHECKSUM-V1";

fn invalid(what: &'static str) -> Refusal {
    Refusal::PartialInvalid(what)
}

/// A partially signed operation in transit.
#[derive(Clone, PartialEq, Eq)]
pub struct PartialApproval {
    kind: OperationKind,
    context: ChainContext,
    id: Hash,
    bytes: Vec<u8>,
    missing: Vec<Requirement>,
    validity: Validity,
    reserved: Vec<OutPoint>,
}

impl PartialApproval {
    /// Wrap a partial signing result. Complete operations are not partial.
    pub fn from_signed(signed: &SignedOperation, context: ChainContext) -> Result<Self, Refusal> {
        match signed {
            SignedOperation::Partial {
                kind,
                id,
                bytes,
                missing,
                validity,
                reserved,
            } => {
                let value = Self {
                    kind: *kind,
                    context,
                    id: *id,
                    bytes: bytes.clone(),
                    missing: missing.clone(),
                    validity: *validity,
                    reserved: reserved.clone(),
                };
                value.check_bounds()?;
                Ok(value)
            }
            SignedOperation::Complete { .. } => {
                Err(invalid("a complete operation is not a partial approval"))
            }
        }
    }

    /// Wrap a queued PARTIAL outbox record for export, with the metadata the outbox derived from
    /// its bytes when it admitted them, so a host's export never assembles a `SignedOperation` by
    /// hand. A record whose checksum fails, and a complete one, are refused.
    pub fn from_record(record: &OutboxRecord, context: ChainContext) -> Result<Self, Refusal> {
        record.verify()?;
        if record.complete {
            return Err(invalid("a complete operation is not a partial approval"));
        }
        let value = Self {
            kind: record.kind,
            context,
            id: record.id,
            bytes: record.bytes.clone(),
            missing: record.missing.clone(),
            validity: record.validity,
            reserved: record.reserved.clone(),
        };
        value.check_bounds()?;
        Ok(value)
    }

    /// The signing result this container carries.
    pub fn to_signed(&self) -> SignedOperation {
        SignedOperation::Partial {
            kind: self.kind,
            id: self.id,
            bytes: self.bytes.clone(),
            missing: self.missing.clone(),
            validity: self.validity,
            reserved: self.reserved.clone(),
        }
    }

    pub fn kind(&self) -> OperationKind {
        self.kind
    }
    pub fn context(&self) -> &ChainContext {
        &self.context
    }
    pub fn id(&self) -> Hash {
        self.id
    }
    /// The operation's own partial encoding.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn missing(&self) -> &[Requirement] {
        &self.missing
    }
    pub fn validity(&self) -> &Validity {
        &self.validity
    }
    pub fn reserved(&self) -> &[OutPoint] {
        &self.reserved
    }

    /// The review a counterparty sees for the operation inside, as seen from `me`, against the
    /// counterparty's own verified view. Refuses a container for another chain.
    pub fn explain_for(
        &self,
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<Review, Refusal> {
        self.check_context(view)?;
        let review = crate::review::explain(&self.bytes, view, me)?;
        // The label must describe what the bytes actually are: a container that calls itself a
        // License sale but carries a payment is refused, never explained as the one or the other.
        if review.kind() != self.kind {
            return Err(invalid(
                "the kind label does not match the operation inside",
            ));
        }
        Ok(review)
    }

    /// Build the plan for the part this wallet must sign, from the operation inside. The same
    /// review, approval and authorization steps apply as for any plan.
    pub fn adopt_for(
        &self,
        view: &ChainView<'_>,
        me: &SignerIdentity,
    ) -> Result<OperationPlan, Refusal> {
        self.check_context(view)?;
        let plan = crate::plan::adopt(&self.bytes, view, me)?;
        if plan.kind() != self.kind {
            return Err(invalid(
                "the kind label does not match the operation inside",
            ));
        }
        Ok(plan)
    }

    fn check_context(&self, view: &ChainView<'_>) -> Result<(), Refusal> {
        let ours = view.context();
        if ours == self.context {
            return Ok(());
        }
        Err(Refusal::WrongContext(
            if ours.network != self.context.network {
                ContextField::Network
            } else if ours.genesis != self.context.genesis {
                ContextField::Genesis
            } else {
                ContextField::Fingerprint
            },
        ))
    }

    fn check_bounds(&self) -> Result<(), Refusal> {
        if self.bytes.is_empty() || self.bytes.len() > MAX_OPERATION_BYTES {
            return Err(invalid("operation size"));
        }
        if self.missing.len() > MAX_REQUIREMENTS {
            return Err(invalid("too many requirements"));
        }
        if self.reserved.len() > MAX_RESERVED {
            return Err(invalid("too many reserved inputs"));
        }
        if self.validity.expiry < self.validity.created {
            return Err(invalid("validity window"));
        }
        Ok(())
    }

    fn encode_body(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(10).unwrap();
        e.str(LABEL).unwrap();
        e.u8(VERSION).unwrap();
        e.u16(self.kind.code()).unwrap();
        e.u32(self.context.network).unwrap();
        e.bytes(&self.context.genesis).unwrap();
        e.bytes(&self.context.fingerprint).unwrap();
        e.bytes(&self.id).unwrap();
        e.bytes(&self.bytes).unwrap();
        put_requirements(&mut e, &self.missing);
        put_validity(&mut e, &self.validity);
        put_points(&mut e, &self.reserved);
        e.into_writer()
    }

    fn checksum(body: &[u8]) -> Hash {
        domain_hash(CHECKSUM_DOMAIN, body)
    }

    /// Canonical bytes for a file or QR code.
    pub fn export(&self) -> Result<Vec<u8>, Refusal> {
        self.check_bounds()?;
        let body = self.encode_body();
        let mut e = Encoder::new(Vec::new());
        e.array(2)
            .unwrap()
            .bytes(&body)
            .unwrap()
            .bytes(&Self::checksum(&body))
            .unwrap();
        let out = e.into_writer();
        if out.len() > MAX_CONTAINER_BYTES {
            return Err(invalid("container size"));
        }
        Ok(out)
    }

    /// Strict import of exactly what [`Self::export`] produces.
    pub fn import(raw: &[u8]) -> Result<Self, Refusal> {
        if raw.is_empty() || raw.len() > MAX_CONTAINER_BYTES {
            return Err(invalid("container size"));
        }
        let mut outer = Decoder::new(raw);
        if outer.array().map_err(|_| invalid("envelope"))? != Some(2) {
            return Err(invalid("envelope"));
        }
        let body = outer.bytes().map_err(|_| invalid("envelope"))?;
        let checksum: [u8; 32] = outer
            .bytes()
            .map_err(|_| invalid("envelope"))?
            .try_into()
            .map_err(|_| invalid("checksum"))?;
        if outer.position() != raw.len() {
            return Err(invalid("trailing data"));
        }
        if checksum != Self::checksum(body) {
            return Err(invalid("checksum"));
        }
        // The envelope itself must be the canonical (minimal-length) encoding too: accept exactly the
        // bytes `export` produces and nothing else.
        let mut canonical = Encoder::new(Vec::new());
        canonical
            .array(2)
            .unwrap()
            .bytes(body)
            .unwrap()
            .bytes(&checksum)
            .unwrap();
        if canonical.into_writer() != raw {
            return Err(invalid("not canonical"));
        }
        let value = Self::decode_body(body)?;
        if value.encode_body() != body {
            return Err(invalid("not canonical"));
        }
        value.check_bounds()?;
        Ok(value)
    }

    fn decode_body(body: &[u8]) -> Result<Self, Refusal> {
        let d = &mut Decoder::new(body);
        let bad = |_| invalid("body");
        if d.array().map_err(bad)? != Some(10)
            || d.str().map_err(bad)? != LABEL
            || d.u8().map_err(bad)? != VERSION
        {
            return Err(invalid("label or version"));
        }
        let kind =
            OperationKind::from_code(d.u16().map_err(bad)?).ok_or(invalid("operation kind"))?;
        let network = d.u32().map_err(bad)?;
        let genesis = hash(d)?;
        let fingerprint = hash(d)?;
        let id = hash(d)?;
        let bytes = d.bytes().map_err(bad)?.to_vec();
        let missing = get_requirements(d)?;
        let validity = get_validity(d)?;
        let reserved = get_points(d)?;
        if d.position() != body.len() {
            return Err(invalid("trailing data"));
        }
        Ok(Self {
            kind,
            context: ChainContext {
                network,
                genesis,
                fingerprint,
            },
            id,
            bytes,
            missing,
            validity,
            reserved,
        })
    }
}

fn hash(d: &mut Decoder<'_>) -> Result<Hash, Refusal> {
    d.bytes()
        .map_err(|_| invalid("body"))?
        .try_into()
        .map_err(|_| invalid("identifier length"))
}

// Shared canonical wire pieces: used by the container above and by durable outbox storage, so the
// two can never disagree about how a requirement, a validity window or a reservation is encoded.

pub(crate) fn put_requirements(e: &mut Encoder<Vec<u8>>, requirements: &[Requirement]) {
    e.array(requirements.len() as u64).unwrap();
    for requirement in requirements {
        let (slot_tag, slot_param) = slot_to_wire(requirement.slot);
        let (signer_tag, signer_id) = match requirement.signer {
            RequiredSigner::Wallet(address) => (0u8, address),
            RequiredSigner::Maker(identity) => (1u8, identity),
        };
        e.array(5).unwrap();
        e.u8(slot_tag).unwrap();
        e.u32(slot_param).unwrap();
        e.u8(signer_tag).unwrap();
        e.bytes(&signer_id).unwrap();
        e.u8(status_to_wire(requirement.status)).unwrap();
    }
}

pub(crate) fn get_requirements(d: &mut Decoder<'_>) -> Result<Vec<Requirement>, Refusal> {
    let bad = |_| invalid("body");
    let count = d
        .array()
        .map_err(bad)?
        .ok_or(invalid("indefinite length"))?;
    if count > MAX_REQUIREMENTS as u64 {
        return Err(invalid("too many requirements"));
    }
    let mut requirements = Vec::new();
    for _ in 0..count {
        if d.array().map_err(bad)? != Some(5) {
            return Err(invalid("requirement"));
        }
        let slot = slot_from_wire(d.u8().map_err(bad)?, d.u32().map_err(bad)?)?;
        let signer_tag = d.u8().map_err(bad)?;
        let signer_id = hash(d)?;
        let signer = match signer_tag {
            0 => RequiredSigner::Wallet(signer_id),
            1 => RequiredSigner::Maker(signer_id),
            _ => return Err(invalid("signer")),
        };
        let status = status_from_wire(d.u8().map_err(bad)?)?;
        requirements.push(Requirement {
            slot,
            signer,
            status,
        });
    }
    Ok(requirements)
}

pub(crate) fn put_validity(e: &mut Encoder<Vec<u8>>, validity: &Validity) {
    e.array(4).unwrap();
    e.u64(validity.created).unwrap();
    e.u64(validity.expiry).unwrap();
    match validity.valid_only_at {
        None => e.array(0).unwrap(),
        Some(height) => e.array(1).unwrap().u64(height).unwrap(),
    };
    e.bool(validity.bound_to_parent).unwrap();
}

pub(crate) fn get_validity(d: &mut Decoder<'_>) -> Result<Validity, Refusal> {
    let bad = |_| invalid("body");
    if d.array().map_err(bad)? != Some(4) {
        return Err(invalid("validity"));
    }
    let created = d.u64().map_err(bad)?;
    let expiry = d.u64().map_err(bad)?;
    let valid_only_at = match d.array().map_err(bad)? {
        Some(0) => None,
        Some(1) => Some(d.u64().map_err(bad)?),
        _ => return Err(invalid("validity")),
    };
    if d.datatype().map_err(bad)? != Type::Bool {
        return Err(invalid("validity"));
    }
    let bound_to_parent = d.bool().map_err(bad)?;
    Ok(Validity {
        created,
        expiry,
        valid_only_at,
        bound_to_parent,
    })
}

pub(crate) fn put_points(e: &mut Encoder<Vec<u8>>, points: &[OutPoint]) {
    e.array(points.len() as u64).unwrap();
    for point in points {
        e.array(2)
            .unwrap()
            .bytes(&point.transaction)
            .unwrap()
            .u32(point.index)
            .unwrap();
    }
}

pub(crate) fn get_points(d: &mut Decoder<'_>) -> Result<Vec<OutPoint>, Refusal> {
    let bad = |_| invalid("body");
    let count = d
        .array()
        .map_err(bad)?
        .ok_or(invalid("indefinite length"))?;
    if count > MAX_RESERVED as u64 {
        return Err(invalid("too many reserved inputs"));
    }
    let mut points = Vec::new();
    for _ in 0..count {
        if d.array().map_err(bad)? != Some(2) {
            return Err(invalid("reserved input"));
        }
        points.push(OutPoint {
            transaction: hash(d)?,
            index: d.u32().map_err(bad)?,
        });
    }
    Ok(points)
}

fn slot_to_wire(slot: Slot) -> (u8, u32) {
    match slot {
        Slot::Input(index) => (0, index),
        Slot::Approval(slot) => (1, u32::from(slot)),
        Slot::OfferSignature => (2, 0),
        Slot::FillSignature => (3, 0),
        Slot::RotationAuthorization => (4, 0),
        Slot::RotationPossession => (5, 0),
        Slot::Claim => (6, 0),
        Slot::BondOwner => (7, 0),
        Slot::TreasuryFreeze => (8, 0),
        Slot::AssignmentOwner => (9, 0),
    }
}

fn slot_from_wire(tag: u8, param: u32) -> Result<Slot, Refusal> {
    Ok(match (tag, param) {
        (0, index) => Slot::Input(index),
        (1, slot) => Slot::Approval(u8::try_from(slot).map_err(|_| invalid("approval slot"))?),
        (2, 0) => Slot::OfferSignature,
        (3, 0) => Slot::FillSignature,
        (4, 0) => Slot::RotationAuthorization,
        (5, 0) => Slot::RotationPossession,
        (6, 0) => Slot::Claim,
        (7, 0) => Slot::BondOwner,
        (8, 0) => Slot::TreasuryFreeze,
        (9, 0) => Slot::AssignmentOwner,
        _ => return Err(invalid("slot")),
    })
}

fn status_to_wire(status: RequirementStatus) -> u8 {
    match status {
        RequirementStatus::ThisWallet => 0,
        RequirementStatus::Counterparty => 1,
        RequirementStatus::Maker => 2,
        RequirementStatus::Provided => 3,
    }
}

fn status_from_wire(tag: u8) -> Result<RequirementStatus, Refusal> {
    Ok(match tag {
        0 => RequirementStatus::ThisWallet,
        1 => RequirementStatus::Counterparty,
        2 => RequirementStatus::Maker,
        3 => RequirementStatus::Provided,
        _ => return Err(invalid("requirement status")),
    })
}

impl fmt::Debug for PartialApproval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartialApproval")
            .field("kind", &self.kind)
            .field("id", &units::short_hex(&self.id))
            .field("bytes", &self.bytes.len())
            .field("missing", &self.missing.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PartialApproval {
        PartialApproval {
            kind: OperationKind::LicenseDvp,
            context: ChainContext {
                network: mutiny_consensus_v8::NETWORK_ID,
                genesis: [1; 32],
                fingerprint: [2; 32],
            },
            id: [7; 32],
            bytes: (0..=255u8).cycle().take(900).collect(),
            missing: vec![
                Requirement {
                    slot: Slot::Approval(1),
                    signer: RequiredSigner::Wallet([4; 32]),
                    status: RequirementStatus::Counterparty,
                },
                Requirement {
                    slot: Slot::FillSignature,
                    signer: RequiredSigner::Maker([5; 32]),
                    status: RequirementStatus::Maker,
                },
            ],
            validity: Validity {
                created: 10,
                expiry: 100,
                valid_only_at: Some(55),
                bound_to_parent: false,
            },
            reserved: vec![
                OutPoint {
                    transaction: [9; 32],
                    index: 3,
                },
                OutPoint {
                    transaction: [8; 32],
                    index: 0,
                },
            ],
        }
    }

    #[test]
    fn export_import_round_trips() {
        let value = sample();
        let raw = value.export().unwrap();
        assert_eq!(PartialApproval::import(&raw).unwrap(), value);
        let mut no_only = value.clone();
        no_only.validity.valid_only_at = None;
        no_only.validity.bound_to_parent = true;
        assert_eq!(
            PartialApproval::import(&no_only.export().unwrap()).unwrap(),
            no_only
        );
    }

    #[test]
    fn every_truncation_and_every_flipped_bit_is_refused() {
        let raw = sample().export().unwrap();
        for cut in 0..raw.len() {
            assert!(
                PartialApproval::import(&raw[..cut]).is_err(),
                "truncated to {cut}"
            );
        }
        let mut longer = raw.clone();
        longer.push(0);
        assert!(PartialApproval::import(&longer).is_err());
        for (index, byte) in raw.iter().enumerate() {
            for bit in 0..8 {
                let mut damaged = raw.clone();
                damaged[index] = byte ^ (1 << bit);
                assert!(
                    PartialApproval::import(&damaged).is_err(),
                    "flip byte {index} bit {bit}"
                );
            }
        }
    }

    #[test]
    fn non_minimal_encodings_of_the_envelope_are_refused() {
        let raw = sample().export().unwrap();
        // The envelope is `[body, checksum]`: a two-element array header, then the body header.
        assert_eq!(raw[0], 0x82);
        assert_eq!(
            raw[1], 0x59,
            "the body is a byte string with a two-byte length"
        );
        // The array header written in its one-byte-length form (0x98 0x02) instead of 0x82.
        let mut wide_array = vec![0x98, 0x02];
        wide_array.extend_from_slice(&raw[1..]);
        assert!(PartialApproval::import(&wide_array).is_err());
        // The body length written with four bytes instead of two.
        let mut wide_length = vec![0x82, 0x5a, 0x00, 0x00, raw[2], raw[3]];
        wide_length.extend_from_slice(&raw[4..]);
        assert!(PartialApproval::import(&wide_length).is_err());
        // Control: the original still imports.
        assert!(PartialApproval::import(&raw).is_ok());
    }

    #[test]
    fn bounds_are_enforced_on_both_sides() {
        let mut big = sample();
        big.bytes = vec![0; MAX_OPERATION_BYTES + 1];
        assert!(big.export().is_err());
        let mut many = sample();
        many.missing = vec![sample().missing[0]; MAX_REQUIREMENTS + 1];
        assert!(many.export().is_err());
        let mut backwards = sample();
        backwards.validity.expiry = 1;
        assert!(backwards.export().is_err());
        assert!(PartialApproval::import(&vec![0u8; MAX_CONTAINER_BYTES + 1]).is_err());
        assert!(PartialApproval::import(&[]).is_err());
    }

    #[test]
    fn a_complete_operation_is_not_partial() {
        let complete = SignedOperation::Complete {
            kind: OperationKind::Payment,
            id: [1; 32],
            bytes: vec![1],
            validity: Validity {
                created: 1,
                expiry: 2,
                valid_only_at: None,
                bound_to_parent: false,
            },
            reserved: vec![],
        };
        let context = ChainContext {
            network: 1,
            genesis: [1; 32],
            fingerprint: [2; 32],
        };
        assert!(PartialApproval::from_signed(&complete, context).is_err());
    }

    #[test]
    fn container_converts_to_and_from_the_signing_result() {
        let value = sample();
        let signed = value.to_signed();
        assert!(!signed.is_complete());
        assert_eq!(
            PartialApproval::from_signed(&signed, value.context).unwrap(),
            value
        );
    }
}
