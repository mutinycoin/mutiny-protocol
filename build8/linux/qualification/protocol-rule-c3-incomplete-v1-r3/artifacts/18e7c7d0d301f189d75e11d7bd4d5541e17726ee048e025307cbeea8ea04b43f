//! Funded BondCreate: block OPERATION kind 24 (Lane P design
//! `qualification/candidate-3/P-LANE-DESIGN-V1.md` sections 2, 1.b and 1.c, amended by
//! `P-LANE-DESIGN-AMENDMENTS-V1.md` AM-1(d), AM-9 m6/m11 and AM-11; Order of 4 October 2026,
//! decision P1). Normative text: `spec/HYBRID-BOND-SETTLEMENT-V2.md` (candidate-3 amendment).
//!
//! One canonical operation carries the complete funded bond creation: the inputs it consumes, the
//! principal it locks, the change it returns and the fee it pays, under ONE commitment that the
//! owner signs twice: under the existing `Domain::BondCreate` (authorization of the lot) and under
//! the existing `Domain::Transaction` (the spend of every input). Input consumption, bond creation,
//! principal lock, change and fee are applied together in one function on the tentative state, or
//! the whole block fails: no partial effect exists and the funding cannot execute independently.
//! No address is ever recognized as an escrow: the retired kind 18 and its escrow-funding transfer
//! are refused by `blocks::operation_kind` (design 2.4).
//!
//! ```text
//! unsigned   = [2, 24, network u32, genesis b32, fingerprint b32, Envelope,
//!               owner b32, owner_descriptor bytes, [node b32, node_generation u64, nonce b32],
//!               principal u64, fee u64, [[txid b32, index u32] ...], null | [destination b32, atoms u64]]
//! op         = [2, 24, unsigned bytes, create_sig, funding_sig]       at most 16,384 bytes
//! signature  = [ed448 bytes(114), fndsa bytes(1280)]                  (a PARTIAL object may carry null)
//! commitment = SHA-256("MUTINY-BUILD8-FUNDED-BOND-CREATE-COMMITMENT-V1" || 0x00 || unsigned)
//! id         = SHA-256("MUTINY-BUILD8-FUNDED-BOND-CREATE-ID-V1" || 0x00 || unsigned)
//! create_sig : owner key, Domain::BondCreate,  [bytes "MUTINY-BUILD8-FUNDED-BOND-CREATE-AUTHORIZE-V1", commitment]
//! funding_sig: owner key, Domain::Transaction, [bytes "MUTINY-BUILD8-FUNDED-BOND-CREATE-FUNDING-V1", commitment, 0]
//! lot id     = SHA-256("MUTINY-BUILD8-BOND-ID-V2" || 0x00 || [2, NetworkID, genesis, node, owner, nonce])  (unchanged)
//! ```
//!
//! Validity at inclusion height `H = parent.height + 1`, in this order (design 2.3): V1 codec
//! (`decode`), V2 context, V3 envelope window and finalized reference (plus any optional
//! precondition, evaluated in the bond-create phase), V4 owner authority from the PARENT WalletBook
//! (a same-block wallet rotation does not authorize), V5 both signatures, V6 node and lineage
//! eligibility (the checks of the retired `apply_bond_creates_v2`, unchanged), V7 inputs (present in
//! the running state, created strictly before `H`, coinbase maturity, owner lineage), V8 change
//! destination in the owner lineage, V9 exact conservation `inputs = principal + change + fee` and
//! `fee >= length of the complete signed operation`. Effects, only after V1-V9: remove the inputs,
//! insert the lot (`atoms = principal`, `created_height = H`, the ACTUAL inclusion height, never a
//! signed or reference height), insert the change coin at `OutPoint{id, 0}` created at `H`, and
//! recompute the reputation lots.
//!
//! Fee: 1 atom per byte of the complete signed operation, the existing rule every transaction and
//! the funded rotation already follow (AM-9 m11); no surcharge and no new recipient. The executor
//! adds the DECLARED fee to the block's fee total before the payment phase (the coinbase exists
//! before the bond-create phase runs) and V9 then verifies it; a lying fee fails the whole block, so
//! the coinbase can never contain an unpaid fee (design 1.c).
//!
//! Status: PROPOSED-UNFROZEN, pre-Genesis, candidate 3. Nothing here is qualified or activated.
use crate::{
    Error, Hash, NETWORK_ID, domain_hash,
    anchors::FinalizedAnchor,
    bonds::{BondLot, LotStatus, MINIMUM_ATOMS},
    bonds_v2::Lot,
    evidence_history_v2::History,
    execution::{ExecutionError, State},
    op_envelope_v1::{Envelope, EnvelopeError},
    trading_v1::Context,
    transactions::{Coin, MATURITY, OutPoint, Output},
};
use minicbor::{Decoder, Encoder, data::Type};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, PublicKey, Role};
use std::collections::BTreeSet;
use std::fmt;

/// Block operation kind of the funded BondCreate. The escrow-funded kind 18 is retired.
pub const OPERATION_KIND: u8 = 24;
/// Codec generation of the outer operation and of the unsigned body (V2 hybrid generation).
pub const CODEC_VERSION: u8 = 2;
/// The existing per-operation byte bound (`blocks::BlockBody::encode`). No new bound.
pub const MAX_OPERATION_BYTES: usize = 16 * 1024;
/// The existing input-count bound of the hybrid Transfer (`transactions_v2.rs`). No new bound.
pub const MAX_INPUTS: usize = 128;
/// The crypto-v2 descriptor decoding bound.
pub const MAX_DESCRIPTOR_BYTES: usize = 2048;
/// `domain_hash` domain of what both signatures commit to. PROPOSED-UNFROZEN.
pub const COMMITMENT_DOMAIN: &[u8] = b"MUTINY-BUILD8-FUNDED-BOND-CREATE-COMMITMENT-V1";
/// `domain_hash` domain of the operation identity (replay identity, change OutPoint, index key).
pub const ID_DOMAIN: &[u8] = b"MUTINY-BUILD8-FUNDED-BOND-CREATE-ID-V1";
/// Payload label of the lot authorization signed under `Domain::BondCreate`. PROPOSED-UNFROZEN.
pub const AUTHORIZE_LABEL: &[u8] = b"MUTINY-BUILD8-FUNDED-BOND-CREATE-AUTHORIZE-V1";
/// Payload label of the input spend signed under `Domain::Transaction`. PROPOSED-UNFROZEN.
pub const FUNDING_LABEL: &[u8] = b"MUTINY-BUILD8-FUNDED-BOND-CREATE-FUNDING-V1";
/// Lot identity domain, UNCHANGED from the retired kind 18.
pub const LOT_ID_DOMAIN: &[u8] = b"MUTINY-BUILD8-BOND-ID-V2";
/// Payer tag of the funding payload. A BondCreate has exactly one payer, the owner: sponsored
/// inputs exist only in the funded wallet rotation (design 10.2), and a BondCreate cannot be
/// funded or paid out by a third party (V7, V8).
pub const OWNER_PAYER: u8 = 0;
const ED448_BYTES: usize = 114;
const FNDSA_BYTES: usize = 1280;

/// The two signature slots of a funded BondCreate, in their wire order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Slot {
    /// The owner key under `Domain::BondCreate`: authorizes this exact lot.
    Create,
    /// The owner key under `Domain::Transaction`: authorizes the spend of every input.
    Funding,
}
impl Slot {
    pub const ALL: [Slot; 2] = [Slot::Create, Slot::Funding];
    pub fn domain(self) -> Domain {
        match self {
            Self::Create => Domain::BondCreate,
            Self::Funding => Domain::Transaction,
        }
    }
}

/// Every refusal of a funded BondCreate. The variant names the rule (design 2.3 V1-V9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BondError {
    /// V1: not the kind-24 structure (wrong type, array length, version, kind or network, a hash
    /// that is not 32 bytes, a signature of the wrong size, bytes after the operation).
    Codec,
    /// V1: a non-canonical encoding of a valid value (indefinite length, non-minimal integer).
    NonCanonical,
    /// V1: longer than `MAX_OPERATION_BYTES`, or nested deeper than the canonical walker allows.
    Oversize,
    /// V1: principal below 100 MUT, node generation 0, no inputs or more than 128, inputs not
    /// strictly ascending, a zero genesis, fingerprint, owner or node, or change of 0 atoms
    /// (absence of change is `null`, never a zero amount).
    Bounds,
    /// V1 (Order P3): the change destination is the zero address; never an implicit burn.
    ZeroDestination,
    /// V1: `owner_descriptor` is not a canonical wallet-owner hybrid descriptor.
    Descriptor,
    /// V1: a complete operation lacks this signature (a partial object is not a block item).
    MissingSignature(Slot),
    /// V1 envelope codec (E1-E7) or V3 at inclusion: `Future`, `Expired`,
    /// `ReferenceNotCanonical`, or `Stale(tag)` for an optional precondition.
    Envelope(EnvelopeError),
    /// V2: the operation names another Genesis or protocol fingerprint than the parent
    /// (`Error::WrongNetwork`, `WrongGenesis`, `WrongFingerprint`).
    Context(Error),
    /// V4: `owner_descriptor` is not the current authority of `owner` in the PARENT WalletBook.
    Authority(Error),
    /// V5: this slot's signature does not verify over its payload under its domain.
    Signature(Slot),
    /// V6: node and lineage eligibility, the unchanged checks of the retired
    /// `apply_bond_creates_v2` (`Duplicate` lot, `UnknownSigner` node, `UnqualifiedPhysical`,
    /// a Production-class binding failure) and the 64-locked-lots-per-lineage `Capacity`.
    Eligibility(Error),
    /// V7: an input is not in the running state (spent, never existed, or spent earlier in
    /// this block).
    MissingInput,
    /// V7: an input was created at or after the inclusion height, or is an immature coinbase.
    Immature,
    /// V7/V8: an input's owner or the change destination is outside the owner's wallet lineage
    /// (`WalletBook::authorize` of the parent WalletBook).
    Lineage(Error),
    /// V9: input atoms differ from `principal + change + fee`.
    Conservation,
    /// V9: `fee` is below the length of the complete signed operation (1 atom per byte).
    Fee,
    /// Checked arithmetic overflow.
    Overflow,
    /// The bond-create phase itself cannot run: no Continuity registry, the parent membership is
    /// not valid at the parent height, or a resulting record could not be written.
    State(Error),
}
impl From<BondError> for ExecutionError {
    fn from(e: BondError) -> Self {
        ExecutionError::BondCreate(e)
    }
}

/// A typed signing intent (Order W4): which slot, under which domain, over which exact payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningIntent {
    pub slot: Slot,
    pub domain: Domain,
    pub payload: Vec<u8>,
}

/// The unsigned body: everything every signature commits to (design 2.2 field order).
#[derive(Clone, PartialEq, Eq)]
pub struct UnsignedBondCreate {
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub envelope: Envelope,
    /// Lot owner AddressID; must be the node's admission owner (V6).
    pub owner: Hash,
    /// The owner authority's CURRENT descriptor (V4).
    pub owner_descriptor: Vec<u8>,
    pub node: Hash,
    pub node_generation: u64,
    pub nonce: Hash,
    /// Atoms locked in the lot, at least `bonds::MINIMUM_ATOMS` (100 MUT).
    pub principal: u64,
    /// Declared fee, at least the length of the complete signed operation.
    pub fee: u64,
    /// 1..=128 existing coins of the owner lineage, strictly ascending.
    pub inputs: Vec<OutPoint>,
    /// Change back to the owner lineage, or none.
    pub change: Option<Output>,
}

/// A complete funded BondCreate: the only form that is a block operation.
#[derive(Clone, PartialEq, Eq)]
pub struct FundedBondCreate {
    pub unsigned: UnsignedBondCreate,
    pub create: HybridSignature,
    pub funding: HybridSignature,
}

/// The PARTIAL exchange object (AM-9 m6; Order W12): the unsigned body plus any subset of the two
/// signatures, with the operation's own canonical encoding and `null` in an absent slot. With both
/// slots present its bytes are exactly the operation; with any slot absent it is never a valid
/// block item (`FundedBondCreate::decode` refuses it with `MissingSignature`).
#[derive(Clone, PartialEq, Eq)]
pub struct PartialBondCreate {
    pub unsigned: UnsignedBondCreate,
    pub create: Option<HybridSignature>,
    pub funding: Option<HybridSignature>,
}

/// Diagnostic identifiers are abbreviated; descriptors and signatures are never dumped.
struct DebugId(Hash);
impl fmt::Debug for DebugId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("..")
    }
}
impl fmt::Debug for UnsignedBondCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnsignedBondCreate")
            .field("genesis", &DebugId(self.genesis))
            .field("fingerprint", &DebugId(self.fingerprint))
            .field(
                "window",
                &(self.envelope.first_height, self.envelope.last_height),
            )
            .field("reference_height", &self.envelope.reference_height)
            .field("reference_block", &DebugId(self.envelope.reference_block))
            .field("preconditions", &self.envelope.preconditions.len())
            .field("owner", &DebugId(self.owner))
            .field("owner_descriptor_bytes", &self.owner_descriptor.len())
            .field("node", &DebugId(self.node))
            .field("node_generation", &self.node_generation)
            .field("nonce", &DebugId(self.nonce))
            .field("principal", &self.principal)
            .field("fee", &self.fee)
            .field("inputs", &self.inputs.len())
            .field(
                "change_owner",
                &self.change.as_ref().map(|c| DebugId(c.owner)),
            )
            .field("change_atoms", &self.change.as_ref().map(|c| c.atoms))
            .finish()
    }
}
impl fmt::Debug for FundedBondCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FundedBondCreate")
            .field("unsigned", &self.unsigned)
            .field("create_present", &true)
            .field("funding_present", &true)
            .finish()
    }
}
impl fmt::Debug for PartialBondCreate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PartialBondCreate")
            .field("unsigned", &self.unsigned)
            .field("create_present", &self.create.is_some())
            .field("funding_present", &self.funding.is_some())
            .finish()
    }
}

// ---------------------------------------------------------------------------------------------
// Payloads and codec helpers
// ---------------------------------------------------------------------------------------------

/// The lot-authorization payload `[bytes AUTHORIZE_LABEL, bytes commitment]`, an array(2) of two
/// byte strings: no other `Domain::BondCreate` payload has this shape (the retired kind-18 body was
/// an array(10)).
pub fn authorize_payload(commitment: &Hash) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(2).unwrap().bytes(AUTHORIZE_LABEL).unwrap().bytes(commitment).unwrap();
    e.into_writer()
}
/// The funding payload `[bytes FUNDING_LABEL, bytes commitment, 0]`, an array(3) whose third item
/// is an unsigned integer: disjoint from every other `Domain::Transaction` payload (transfer input
/// array(2); trading approval array(4); dividend claim array(3) of three byte strings; Treasury
/// freeze array(14); funded-rotation funding carries another label).
pub fn funding_payload(commitment: &Hash) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .bytes(FUNDING_LABEL)
        .unwrap()
        .bytes(commitment)
        .unwrap()
        .u8(OWNER_PAYER)
        .unwrap();
    e.into_writer()
}
fn payload(slot: Slot, commitment: &Hash) -> Vec<u8> {
    match slot {
        Slot::Create => authorize_payload(commitment),
        Slot::Funding => funding_payload(commitment),
    }
}
fn owner_public(raw: &[u8]) -> Result<PublicKey, BondError> {
    if raw.len() > MAX_DESCRIPTOR_BYTES {
        return Err(BondError::Descriptor);
    }
    let (public, _) = PublicKey::decode_descriptor(raw).map_err(|_| BondError::Descriptor)?;
    if public.role != Role::WalletOwner {
        return Err(BondError::Descriptor);
    }
    Ok(public)
}
fn verify_slot(
    public: &PublicKey,
    commitment: &Hash,
    slot: Slot,
    signature: &HybridSignature,
) -> Result<(), BondError> {
    public
        .verify(slot.domain(), &payload(slot, commitment), signature)
        .map_err(|_| BondError::Signature(slot))
}
/// The repository's canonical walker (definite lengths, minimal integers, only
/// uint/bytes/array/null/bool, depth <= 16, exact re-encoding), mapped to `BondError`.
fn canonical(raw: &[u8]) -> Result<(), BondError> {
    crate::blocks::canonical(raw, MAX_OPERATION_BYTES).map_err(|e| match e {
        Error::Oversize => BondError::Oversize,
        Error::NonCanonical => BondError::NonCanonical,
        _ => BondError::Codec,
    })
}
fn array_len(d: &mut Decoder<'_>) -> Result<u64, BondError> {
    d.array().map_err(|_| BondError::Codec)?.ok_or(BondError::NonCanonical)
}
fn expect_array(d: &mut Decoder<'_>, n: u64) -> Result<(), BondError> {
    if array_len(d)? != n {
        return Err(BondError::Codec);
    }
    Ok(())
}
fn uint(d: &mut Decoder<'_>) -> Result<u64, BondError> {
    d.u64().map_err(|_| BondError::Codec)
}
fn hash(d: &mut Decoder<'_>) -> Result<Hash, BondError> {
    d.bytes()
        .map_err(|_| BondError::Codec)?
        .try_into()
        .map_err(|_| BondError::Codec)
}
fn put_signature(e: &mut Encoder<Vec<u8>>, signature: &Option<HybridSignature>) {
    match signature {
        Some(s) => {
            e.array(2).unwrap().bytes(&s.ed448).unwrap().bytes(&s.fndsa).unwrap();
        }
        None => {
            e.null().unwrap();
        }
    }
}
fn optional_signature(d: &mut Decoder<'_>) -> Result<Option<HybridSignature>, BondError> {
    if d.datatype().map_err(|_| BondError::Codec)? == Type::Null {
        d.null().map_err(|_| BondError::Codec)?;
        return Ok(None);
    }
    expect_array(d, 2)?;
    let ed448: [u8; ED448_BYTES] = d
        .bytes()
        .map_err(|_| BondError::Codec)?
        .try_into()
        .map_err(|_| BondError::Codec)?;
    let fndsa: [u8; FNDSA_BYTES] = d
        .bytes()
        .map_err(|_| BondError::Codec)?
        .try_into()
        .map_err(|_| BondError::Codec)?;
    Ok(Some(HybridSignature { ed448, fndsa }))
}

// ---------------------------------------------------------------------------------------------
// Unsigned body
// ---------------------------------------------------------------------------------------------

impl UnsignedBondCreate {
    /// The V1 value rules (everything except the length bound, which `encode` checks).
    pub fn validate(&self) -> Result<(), BondError> {
        if [self.genesis, self.fingerprint, self.owner, self.node].contains(&[0; 32])
            || self.node_generation == 0
            || self.principal < MINIMUM_ATOMS
            || self.inputs.is_empty()
            || self.inputs.len() > MAX_INPUTS
            || self.inputs.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(BondError::Bounds);
        }
        if let Some(change) = &self.change {
            if change.owner == [0; 32] {
                return Err(BondError::ZeroDestination);
            }
            if change.atoms == 0 {
                return Err(BondError::Bounds);
            }
        }
        self.envelope.validate().map_err(BondError::Envelope)?;
        owner_public(&self.owner_descriptor)?;
        Ok(())
    }
    /// The canonical unsigned bytes (array(13), design 2.2). A violating value is unrepresentable.
    pub fn encode(&self) -> Result<Vec<u8>, BondError> {
        self.validate()?;
        let mut e = Encoder::new(Vec::new());
        e.array(13)
            .unwrap()
            .u8(CODEC_VERSION)
            .unwrap()
            .u8(OPERATION_KIND)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap();
        self.envelope.encode(&mut e).map_err(BondError::Envelope)?;
        e.bytes(&self.owner).unwrap().bytes(&self.owner_descriptor).unwrap();
        e.array(3)
            .unwrap()
            .bytes(&self.node)
            .unwrap()
            .u64(self.node_generation)
            .unwrap()
            .bytes(&self.nonce)
            .unwrap();
        e.u64(self.principal)
            .unwrap()
            .u64(self.fee)
            .unwrap()
            .array(self.inputs.len() as u64)
            .unwrap();
        for point in &self.inputs {
            e.array(2)
                .unwrap()
                .bytes(&point.transaction)
                .unwrap()
                .u32(point.index)
                .unwrap();
        }
        match &self.change {
            Some(change) => {
                e.array(2)
                    .unwrap()
                    .bytes(&change.owner)
                    .unwrap()
                    .u64(change.atoms)
                    .unwrap();
            }
            None => {
                e.null().unwrap();
            }
        }
        let raw = e.into_writer();
        if raw.len() > MAX_OPERATION_BYTES {
            return Err(BondError::Oversize);
        }
        Ok(raw)
    }
    /// Decodes unsigned bytes: separately canonical-checked (the walker does not recurse into the
    /// enclosing operation's byte string, AM-9 n1), every V1 rule, exact re-encoding.
    pub fn decode(raw: &[u8]) -> Result<Self, BondError> {
        canonical(raw)?;
        let mut d = Decoder::new(raw);
        expect_array(&mut d, 13)?;
        if d.u8().map_err(|_| BondError::Codec)? != CODEC_VERSION
            || d.u8().map_err(|_| BondError::Codec)? != OPERATION_KIND
            || d.u32().map_err(|_| BondError::Codec)? != NETWORK_ID
        {
            return Err(BondError::Codec);
        }
        let genesis = hash(&mut d)?;
        let fingerprint = hash(&mut d)?;
        let envelope = Envelope::decode(&mut d).map_err(BondError::Envelope)?;
        let owner = hash(&mut d)?;
        let owner_descriptor = d.bytes().map_err(|_| BondError::Codec)?.to_vec();
        expect_array(&mut d, 3)?;
        let node = hash(&mut d)?;
        let node_generation = uint(&mut d)?;
        let nonce = hash(&mut d)?;
        let principal = uint(&mut d)?;
        let fee = uint(&mut d)?;
        let count = array_len(&mut d)?;
        if count == 0 || count > MAX_INPUTS as u64 {
            return Err(BondError::Bounds);
        }
        let mut inputs = Vec::new();
        for _ in 0..count {
            expect_array(&mut d, 2)?;
            inputs.push(OutPoint {
                transaction: hash(&mut d)?,
                index: d.u32().map_err(|_| BondError::Codec)?,
            });
        }
        let change = if d.datatype().map_err(|_| BondError::Codec)? == Type::Null {
            d.null().map_err(|_| BondError::Codec)?;
            None
        } else {
            expect_array(&mut d, 2)?;
            Some(Output {
                owner: hash(&mut d)?,
                atoms: uint(&mut d)?,
            })
        };
        if d.position() != raw.len() {
            return Err(BondError::Codec);
        }
        let unsigned = Self {
            genesis,
            fingerprint,
            envelope,
            owner,
            owner_descriptor,
            node,
            node_generation,
            nonce,
            principal,
            fee,
            inputs,
            change,
        };
        if unsigned.encode()? != raw {
            return Err(BondError::NonCanonical);
        }
        Ok(unsigned)
    }
    /// What both signatures commit to. A function of the unsigned bytes only (design 1.b B1).
    pub fn commitment(&self) -> Result<Hash, BondError> {
        Ok(domain_hash(COMMITMENT_DOMAIN, &self.encode()?))
    }
    /// The operation identity: replay identity, the change OutPoint `{id, 0}`, the index key.
    /// Excludes the signatures, so the wallet knows it before signing.
    pub fn id(&self) -> Result<Hash, BondError> {
        Ok(domain_hash(ID_DOMAIN, &self.encode()?))
    }
    /// The lot identity, UNCHANGED: `[2, NetworkID, genesis, node, owner, nonce]` under the V2
    /// bond-ID domain. It does not depend on the funding, the window or the fee.
    pub fn lot_id(&self) -> Hash {
        let mut e = Encoder::new(Vec::new());
        e.array(6)
            .unwrap()
            .u8(2)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.node)
            .unwrap()
            .bytes(&self.owner)
            .unwrap()
            .bytes(&self.nonce)
            .unwrap();
        domain_hash(LOT_ID_DOMAIN, &e.into_writer())
    }
    /// The two payloads of design 1.b, in slot order: what the owner signs, under which domain.
    pub fn signing_intents(&self) -> Result<Vec<SigningIntent>, BondError> {
        let commitment = self.commitment()?;
        Ok(Slot::ALL
            .iter()
            .map(|&slot| SigningIntent {
                slot,
                domain: slot.domain(),
                payload: payload(slot, &commitment),
            })
            .collect())
    }
    /// The length of the COMPLETE signed operation, known before signing because both signatures
    /// have fixed sizes (AM-9 m6). The fee rule is `fee >= signed_len()`; since `fee` is inside the
    /// body, a caller choosing the minimum fee recomputes until the value is stable.
    pub fn signed_len(&self) -> Result<usize, BondError> {
        let placeholder = HybridSignature {
            ed448: [0; ED448_BYTES],
            fndsa: [0; FNDSA_BYTES],
        };
        PartialBondCreate {
            unsigned: self.clone(),
            create: Some(placeholder.clone()),
            funding: Some(placeholder),
        }
        .encode()
        .map(|raw| raw.len())
    }
}

// ---------------------------------------------------------------------------------------------
// Partial and complete objects
// ---------------------------------------------------------------------------------------------

impl PartialBondCreate {
    pub fn new(unsigned: UnsignedBondCreate) -> Self {
        Self {
            unsigned,
            create: None,
            funding: None,
        }
    }
    /// `[2, 24, unsigned bytes, null | [ed448, fndsa], null | [ed448, fndsa]]`.
    pub fn encode(&self) -> Result<Vec<u8>, BondError> {
        let unsigned = self.unsigned.encode()?;
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(CODEC_VERSION)
            .unwrap()
            .u8(OPERATION_KIND)
            .unwrap()
            .bytes(&unsigned)
            .unwrap();
        put_signature(&mut e, &self.create);
        put_signature(&mut e, &self.funding);
        let raw = e.into_writer();
        if raw.len() > MAX_OPERATION_BYTES {
            return Err(BondError::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self, BondError> {
        canonical(raw)?;
        let mut d = Decoder::new(raw);
        expect_array(&mut d, 5)?;
        if d.u8().map_err(|_| BondError::Codec)? != CODEC_VERSION
            || d.u8().map_err(|_| BondError::Codec)? != OPERATION_KIND
        {
            return Err(BondError::Codec);
        }
        let unsigned = UnsignedBondCreate::decode(d.bytes().map_err(|_| BondError::Codec)?)?;
        let create = optional_signature(&mut d)?;
        let funding = optional_signature(&mut d)?;
        if d.position() != raw.len() {
            return Err(BondError::Codec);
        }
        let partial = Self {
            unsigned,
            create,
            funding,
        };
        if partial.encode()? != raw {
            return Err(BondError::NonCanonical);
        }
        Ok(partial)
    }
    fn slot(&self, slot: Slot) -> &Option<HybridSignature> {
        match slot {
            Slot::Create => &self.create,
            Slot::Funding => &self.funding,
        }
    }
    /// Signs one slot with the owner key. The key must be the key of `owner_descriptor`. Signing
    /// only: nothing about state or authority is established by it.
    pub fn sign(&mut self, slot: Slot, key: &HybridKey) -> Result<(), BondError> {
        let public = owner_public(&self.unsigned.owner_descriptor)?;
        if key.public() != &public {
            return Err(BondError::Signature(slot));
        }
        let commitment = self.unsigned.commitment()?;
        let signature = key
            .sign(slot.domain(), &payload(slot, &commitment))
            .map_err(|_| BondError::Signature(slot))?;
        match slot {
            Slot::Create => self.create = Some(signature),
            Slot::Funding => self.funding = Some(signature),
        }
        Ok(())
    }
    /// Attaches a signature obtained elsewhere (for example from a file exchange) after
    /// verifying it for this slot.
    pub fn attach(&mut self, slot: Slot, signature: HybridSignature) -> Result<(), BondError> {
        let public = owner_public(&self.unsigned.owner_descriptor)?;
        verify_slot(&public, &self.unsigned.commitment()?, slot, &signature)?;
        match slot {
            Slot::Create => self.create = Some(signature),
            Slot::Funding => self.funding = Some(signature),
        }
        Ok(())
    }
    /// Every PROVIDED signature verifies (absent slots are not an error here).
    pub fn verify_provided_signatures(&self) -> Result<(), BondError> {
        let public = owner_public(&self.unsigned.owner_descriptor)?;
        let commitment = self.unsigned.commitment()?;
        for slot in Slot::ALL {
            if let Some(signature) = self.slot(slot) {
                verify_slot(&public, &commitment, slot, signature)?;
            }
        }
        Ok(())
    }
    /// The complete operation, or `MissingSignature` for the first absent slot.
    pub fn complete(self) -> Result<FundedBondCreate, BondError> {
        let create = self.create.ok_or(BondError::MissingSignature(Slot::Create))?;
        let funding = self.funding.ok_or(BondError::MissingSignature(Slot::Funding))?;
        Ok(FundedBondCreate {
            unsigned: self.unsigned,
            create,
            funding,
        })
    }
    /// Read-only PREFLIGHT for a reviewer of a partial object (AM-9 m6; Order W12): every rule
    /// V2-V9 for inclusion at `parent.height + 1` on `state` as the block's only bond creation,
    /// every PROVIDED signature verified, missing signatures not an error. `state` must be the
    /// verified state at `parent`; the fee rule uses the complete signed length.
    pub fn preflight(
        &self,
        state: &State,
        parent: &FinalizedAnchor,
        history: &History,
    ) -> Result<(), BondError> {
        single(state, parent, history, &self.unsigned, &|| {
            self.verify_provided_signatures()
        })
    }
}

impl FundedBondCreate {
    /// Signs both slots with the owner key (the key of `owner_descriptor`).
    pub fn sign(unsigned: UnsignedBondCreate, key: &HybridKey) -> Result<Self, BondError> {
        let mut partial = PartialBondCreate::new(unsigned);
        partial.sign(Slot::Create, key)?;
        partial.sign(Slot::Funding, key)?;
        partial.complete()
    }
    pub fn as_partial(&self) -> PartialBondCreate {
        PartialBondCreate {
            unsigned: self.unsigned.clone(),
            create: Some(self.create.clone()),
            funding: Some(self.funding.clone()),
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>, BondError> {
        self.as_partial().encode()
    }
    /// Decodes a complete kind-24 operation: canonical, every V1 rule, both signature slots present.
    pub fn decode(raw: &[u8]) -> Result<Self, BondError> {
        PartialBondCreate::decode(raw)?.complete()
    }
    pub fn id(&self) -> Result<Hash, BondError> {
        self.unsigned.id()
    }
    pub fn lot_id(&self) -> Hash {
        self.unsigned.lot_id()
    }
    /// AM-1(d): the STATELESS check (V5): both signatures verify under the owner descriptor over
    /// the commitment. A pool may cache a success for this exact id and wire hash.
    pub fn verify_signatures(&self) -> Result<(), BondError> {
        let public = owner_public(&self.unsigned.owner_descriptor)?;
        let commitment = self.unsigned.commitment()?;
        verify_slot(&public, &commitment, Slot::Create, &self.create)?;
        verify_slot(&public, &commitment, Slot::Funding, &self.funding)
    }
    /// AM-1(d): every STATE-dependent rule (V2-V4, V6-V9) for inclusion at `parent.height + 1` on
    /// `state` (the verified state at `parent`) as the block's only bond creation. No signature
    /// is verified here.
    pub fn verify_state(
        &self,
        state: &State,
        parent: &FinalizedAnchor,
        history: &History,
    ) -> Result<(), BondError> {
        single(state, parent, history, &self.unsigned, &|| Ok(()))
    }
    /// `verify_state` and `verify_signatures` in the design's order (signatures after the cheap
    /// checks V2-V4 and before V6-V9).
    pub fn verify(
        &self,
        state: &State,
        parent: &FinalizedAnchor,
        history: &History,
    ) -> Result<(), BondError> {
        single(state, parent, history, &self.unsigned, &|| self.verify_signatures())
    }
}

/// Read-only admission entry point (design 5.4, section 13): decodes `raw` and applies every rule
/// for inclusion at `parent.height + 1` on `state` (the verified state at `parent`) as the block's
/// only bond creation. It changes nothing.
pub fn check(
    state: &State,
    parent: &FinalizedAnchor,
    history: &History,
    raw: &[u8],
) -> Result<(), BondError> {
    FundedBondCreate::decode(raw)?.verify(state, parent, history)
}

/// The DECLARED fee total of the kind-24 items in `operations` (decode only, checked arithmetic).
/// The executor adds the same total to the block's fee before the payment phase; the bond-create
/// phase verifies every declared fee (V9), so a lie fails the block (design 1.c).
pub fn declared_fees(operations: &[Vec<u8>]) -> Result<u64, BondError> {
    let mut total = 0u64;
    for raw in operations {
        if crate::blocks::operation_kind(raw) != Ok(OPERATION_KIND) {
            continue;
        }
        let create = FundedBondCreate::decode(raw)?;
        total = total
            .checked_add(create.unsigned.fee)
            .ok_or(BondError::Overflow)?;
    }
    Ok(total)
}

/// The envelope of a kind-24 operation (`op_envelope_v1::operation_envelope`, design 1.a.3), read
/// without decoding the rest. None for anything else or anything malformed; execution rejects a
/// malformed item.
pub fn envelope_of(raw: &[u8]) -> Option<Envelope> {
    let mut d = Decoder::new(raw);
    if d.array().ok()? != Some(5)
        || d.u8().ok()? != CODEC_VERSION
        || d.u8().ok()? != OPERATION_KIND
    {
        return None;
    }
    crate::op_envelope_v1::envelope_at(d.bytes().ok()?, 5)
}

// ---------------------------------------------------------------------------------------------
// Validity and effects
// ---------------------------------------------------------------------------------------------

/// What one validated create changes (design 2.3 effects), computed before anything changes.
struct Plan {
    lot: Lot,
    change: Option<(OutPoint, Coin)>,
}

/// V2-V9 for one create at `H = parent.height + 1`. `parent_state` holds the authenticated parent
/// components (WalletBook, membership, registry, admission class); `running` is the tentative
/// state at the bond-create phase (post-payment coins; post-lifecycle registry, penalties and
/// bonds). `signatures` is V5 as the caller requires it. Read-only.
#[allow(clippy::too_many_arguments)]
fn plan(
    unsigned: &UnsignedBondCreate,
    signatures: &dyn Fn() -> Result<(), BondError>,
    parent_state: &State,
    running: &State,
    parent: &FinalizedAnchor,
    history: &History,
    seen: &BTreeSet<Hash>,
) -> Result<Plan, BondError> {
    let u = unsigned;
    let height = parent.height.checked_add(1).ok_or(BondError::Overflow)?;
    // V2 context.
    parent
        .validate_context(u.genesis, u.fingerprint)
        .map_err(BondError::Context)?;
    // V3 window and finalized reference at H; optional preconditions at this phase.
    u.envelope
        .check_inclusion(parent, history)
        .map_err(BondError::Envelope)?;
    let context = Context {
        network: NETWORK_ID,
        genesis: u.genesis,
        fingerprint: u.fingerprint,
    };
    u.envelope
        .check_preconditions(running, &context)
        .map_err(BondError::Envelope)?;
    // V4 owner authority from the PARENT WalletBook: a same-block rotation does not authorize.
    parent_state
        .wallets
        .authorize(u.owner, &u.owner_descriptor)
        .map_err(BondError::Authority)?;
    // V5 signatures, after the cheap checks.
    signatures()?;
    // V6 node and lineage eligibility: the checks of the retired apply_bond_creates_v2, unchanged.
    let registry = parent_state
        .continuity
        .as_ref()
        .ok_or(BondError::Eligibility(Error::UnqualifiedPhysical))?;
    let id = u.lot_id();
    if seen.contains(&id) || running.bonds_v2.lots.contains_key(&id) {
        return Err(BondError::Eligibility(Error::Duplicate));
    }
    let control = parent_state
        .membership_v2
        .get(u.node)
        .ok_or(BondError::Eligibility(Error::UnknownSigner))?;
    let old = registry
        .members
        .iter()
        .find(|m| m.node == u.node)
        .ok_or(BondError::Eligibility(Error::UnknownSigner))?;
    let current = running
        .continuity
        .as_ref()
        .ok_or(BondError::Eligibility(Error::UnqualifiedPhysical))?
        .members
        .iter()
        .find(|m| m.node == u.node)
        .ok_or(BondError::Eligibility(Error::UnknownSigner))?;
    if control.binding().admission.owner != u.owner
        || control.generation() != u.node_generation
        || old.generation != u.node_generation
        || !old.physical
        || !old.eligible
        || !current.physical
        || !current.eligible
        || current.lineage != old.lineage
        || running.penalties_v2.revoked(old.lineage)
    {
        return Err(BondError::Eligibility(Error::UnqualifiedPhysical));
    }
    // E5, defense in depth (no separate eligibility flag): in the Production class the member's
    // COMMITTED hybrid binding must still pass the admission rule.
    if parent_state
        .admission_class()
        .map_err(BondError::Eligibility)?
        == crate::provenance::AdmissionClass::Production
    {
        let record = parent_state
            .admission_policy_v2
            .as_ref()
            .ok_or(BondError::Eligibility(Error::UnqualifiedPhysical))?;
        parent_state
            .continuity_keys_v2
            .get(u.node)
            .ok_or(BondError::Eligibility(Error::UnknownSigner))?
            .check_class(
                crate::provenance::AdmissionClass::Production,
                &record.initial().endorsement_roots,
            )
            .map_err(BondError::Eligibility)?;
    }
    // V7 inputs: present in the running state, created strictly before H (no same-block output),
    // coinbase maturity, and inside the owner's lineage (any generation of it, Order P9).
    let mut incoming = 0u128;
    for point in &u.inputs {
        let coin = running.coins.get(point).ok_or(BondError::MissingInput)?;
        if coin.created_height >= height
            || (coin.coinbase && height - coin.created_height < MATURITY)
        {
            return Err(BondError::Immature);
        }
        parent_state
            .wallets
            .authorize(coin.output.owner, &u.owner_descriptor)
            .map_err(BondError::Lineage)?;
        incoming = incoming
            .checked_add(u128::from(coin.output.atoms))
            .ok_or(BondError::Overflow)?;
    }
    // V8 change only back to the owner's lineage: a BondCreate cannot pay a third party.
    if let Some(change) = &u.change {
        parent_state
            .wallets
            .authorize(change.owner, &u.owner_descriptor)
            .map_err(BondError::Lineage)?;
    }
    // V9 exact conservation and 1 atom per byte of the complete signed operation.
    let outgoing = u128::from(u.principal)
        + u.change.as_ref().map_or(0, |c| u128::from(c.atoms))
        + u128::from(u.fee);
    if incoming != outgoing {
        return Err(BondError::Conservation);
    }
    if u.fee < u.signed_len()? as u64 {
        return Err(BondError::Fee);
    }
    let lot = Lot(BondLot {
        id,
        node: u.node,
        lineage: old.lineage,
        owner: u.owner,
        atoms: u.principal,
        created_height: height,
        sequence: 0,
        unbond_height: None,
        settled_height: None,
        status: LotStatus::Active,
        evidence: [0; 32],
    });
    let change = match &u.change {
        Some(change) => Some((
            OutPoint {
                transaction: u.id()?,
                index: 0,
            },
            Coin {
                output: change.clone(),
                created_height: height,
                coinbase: false,
            },
        )),
        None => None,
    };
    Ok(Plan { lot, change })
}

/// One create on `state` as the block's only bond creation (read-only entry points).
fn single(
    state: &State,
    parent: &FinalizedAnchor,
    history: &History,
    unsigned: &UnsignedBondCreate,
    signatures: &dyn Fn() -> Result<(), BondError>,
) -> Result<(), BondError> {
    let registry = state
        .continuity
        .as_ref()
        .ok_or(BondError::State(Error::UnqualifiedPhysical))?;
    state
        .membership_v2
        .validate_at_height(registry, &state.continuity_keys_v2, parent.height)
        .map_err(BondError::State)?;
    let plan = plan(unsigned, signatures, state, state, parent, history, &BTreeSet::new())?;
    let mut bonds = state.bonds_v2.clone();
    bonds.lots.insert(plan.lot.0.id, plan.lot);
    bonds.records().map_err(BondError::Eligibility)?;
    Ok(())
}

/// The bond-create phase of the V2 executor (design 2.7): runs after the payment and lifecycle
/// phases, in the position of the retired `apply_bond_creates_v2`, so same-block evidence and exits
/// keep their effect on a create. `parent_state` is the economic parent (the recovery components
/// in a first resumed block); `next` is the tentative post-state. Creates are applied in body
/// order; each is completely validated before any of its effects, and any error aborts the whole
/// candidate (the caller drops the tentative clone).
pub(crate) fn apply_bond_creates_v3(
    parent_state: &State,
    parent: &FinalizedAnchor,
    history: &History,
    creates: &[FundedBondCreate],
    next: &mut State,
) -> Result<(), BondError> {
    let registry = parent_state
        .continuity
        .as_ref()
        .ok_or(BondError::State(Error::UnqualifiedPhysical))?;
    let height = parent.height.checked_add(1).ok_or(BondError::Overflow)?;
    parent_state
        .membership_v2
        .validate_at_height(registry, &parent_state.continuity_keys_v2, parent.height)
        .map_err(BondError::State)?;
    let mut seen = BTreeSet::new();
    for create in creates {
        let plan = plan(
            &create.unsigned,
            &|| create.verify_signatures(),
            parent_state,
            next,
            parent,
            history,
            &seen,
        )?;
        let id = plan.lot.0.id;
        seen.insert(id);
        // Effects, in the design's order, only after V1-V9 passed.
        for point in &create.unsigned.inputs {
            next.coins.remove(point).ok_or(BondError::MissingInput)?;
        }
        next.bonds_v2.lots.insert(id, plan.lot);
        next.bonds_v2.records().map_err(BondError::Eligibility)?;
        if let Some((point, coin)) = plan.change
            && next.coins.insert(point, coin).is_some()
        {
            return Err(BondError::State(Error::Duplicate));
        }
    }
    if let Some(registry) = next.continuity.as_mut() {
        for member in &mut registry.members {
            member.history.bonds = next
                .bonds_v2
                .reputation_lots(member.lineage, height)
                .map_err(BondError::State)?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "bond_create_v3_tests.rs"]
mod tests;
