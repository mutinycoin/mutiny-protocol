//! Operation envelope V1: the signed inclusion-height window, the finalized reference context and
//! the committed state preconditions that an eligible multiparty value operation carries (Lane P
//! design `qualification/candidate-3/P-LANE-DESIGN-V1.md` section 1.a; Order of 4 October 2026,
//! decision P4). Normative text: `spec/OPERATION-ENVELOPE-AND-CONFIRMATION-V1.md`.
//!
//! ```text
//! Envelope     = [1, first_height, last_height, [reference_height, reference_block32], [Precondition...]]
//! Precondition = [1, license32, [[award_epoch, share, remaining, claims]...]]                LicenseEntitlements
//!              | [2, license32, assignment_sequence, active_worker32 | null, pending32 | null]  LicenseAssignment
//!              | [3, treasury32, generation, address32]                                       TreasuryHead
//! ```
//!
//! The codec invariants E1-E7 hold in BOTH directions: `encode` refuses a violating value and
//! `decode` refuses a violating value or any non-canonical encoding of a valid one, so a violating
//! envelope can be neither signed nor admitted nor executed. At inclusion height
//! `H = parent.height + 1` the carrying kind checks the window W (`first <= H <= last`), the
//! reference R (the parent itself, or the canonical block hash that the local canonical store
//! supplies through `History` anchors) and, at that kind's own validation point, the
//! preconditions P (exact equality with the facts recomputed from state; no tolerance).
//!
//! The envelope is never replay protection (design 1.a.8): that remains the consumed resources of
//! the carrying kind. Nothing here rewrites, re-windows, re-bases or re-signs reviewed bytes.
//! Status: PROPOSED-UNFROZEN. A kind that adopts the envelope (design 1.a.4) adds its arm to
//! `transaction_envelope` or `operation_envelope`, which is how the canonical store learns which
//! reference anchors a block needs; the funded BondCreate (kind 24) and the bond commands of body
//! version 3 (kinds 19/20) carry one.
use crate::{
    Hash, domain_hash,
    anchors::FinalizedAnchor,
    blocks::BlockBody,
    evidence_history_v2::History,
    execution::State,
    license_assignment_v2::Assignment,
    trading_v1::Context,
    transactions::EXPIRY_HORIZON,
};
use minicbor::{Decoder, Encoder, data::Type};
use std::collections::BTreeSet;

/// Envelope format version (the first array element).
pub const ENVELOPE_VERSION: u8 = 1;
/// Precondition tags; their numeric order is the first component of the E4 ordering key.
pub const TAG_LICENSE_ENTITLEMENTS: u8 = 1;
pub const TAG_LICENSE_ASSIGNMENT: u8 = 2;
pub const TAG_TREASURY_HEAD: u8 = 3;
/// A standalone envelope can never be larger than the item that carries it: the existing
/// 16 KiB per-transaction / per-operation bound (`transactions.rs`, `blocks.rs`). No new count
/// constant exists: the precondition list is bounded by this byte bound alone (design 1.a.1).
pub const MAX_ENVELOPE_BYTES: usize = 16 * 1024;
/// Identity of a Worker assignment (design 9.1): SHA-256 over this domain, NUL and the unsigned
/// 16-element enrollment binding (`mutiny_crypto_v2::enrollment::Binding::bytes`). PROPOSED-UNFROZEN.
pub const ASSIGNMENT_ID_DOMAIN: &[u8] = b"MUTINY-BUILD8-LICENSE-ASSIGNMENT-ID-V2";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Not the envelope structure: wrong CBOR type, array length, version or precondition tag,
    /// a hash that is not 32 bytes, missing items, or bytes after a standalone envelope.
    Codec,
    /// A structurally valid value in a non-canonical encoding (indefinite length, non-minimal
    /// integer or length head).
    NonCanonical,
    /// A standalone encoding longer than `MAX_ENVELOPE_BYTES` (or nested deeper than the
    /// canonical walker allows).
    Oversize,
    /// E1: `reference_block` is zero.
    ZeroReference,
    /// E2: not `reference_height < first_height <= last_height`.
    WindowOrder,
    /// E3: `last_height - first_height > EXPIRY_HORIZON`.
    Horizon,
    /// E4: preconditions not strictly ascending by `(tag, subject)` (a duplicate included).
    PreconditionOrder,
    /// E5: LicenseEntitlements accounts not strictly ascending by `award_epoch`.
    AccountOrder,
    /// E5: an account violates the dividend ledger's structural rule.
    Account,
    /// E5, E6, E7: a zero License, Treasury or Treasury-address subject.
    ZeroSubject,
    /// E6: `assignment_sequence == 0` (every V2 License starts at 1).
    ZeroSequence,
    /// E7: `generation == 0`.
    ZeroGeneration,
    /// `Envelope::from_head`: `validity_blocks` outside `1..=EXPIRY_HORIZON`.
    ValidityBlocks,
    /// A height computation would overflow u64.
    Overflow,
    /// W: the inclusion height precedes `first_height`.
    Future,
    /// W: the inclusion height follows `last_height`.
    Expired,
    /// R: `reference_block` is not the canonical block at `reference_height`.
    ReferenceNotCanonical,
    /// P: the committed precondition with this tag differs from the facts at the validation point.
    Stale(u8),
    /// Fact functions: the facts of this precondition tag cannot be derived from the state (no
    /// such License, no Treasury head, or a Treasury head of another context).
    Unavailable(u8),
}

/// One live award account of a License, `[award_epoch, share, remaining, claims]`
/// (`dividends_v1::Account` plus its award epoch). `share - remaining` is the claimed amount and
/// `claims` the per-award/per-License claim sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AwardAccount {
    pub award_epoch: u64,
    pub share: u64,
    pub remaining: u64,
    pub claims: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Precondition {
    /// Tag 1: the COMPLETE list of live award accounts of `license`, ascending by award epoch.
    /// An empty list commits "no live entitlement".
    LicenseEntitlements { license: Hash, accounts: Vec<AwardAccount> },
    /// Tag 2: the License's assignment sequence, active Worker and pending assignment id.
    LicenseAssignment {
        license: Hash,
        assignment_sequence: u64,
        active_worker: Option<Hash>,
        pending: Option<Hash>,
    },
    /// Tag 3: the trading Treasury destination head.
    TreasuryHead { treasury: Hash, generation: u64, address: Hash },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope {
    pub first_height: u64,
    pub last_height: u64,
    pub reference_height: u64,
    pub reference_block: Hash,
    pub preconditions: Vec<Precondition>,
}

// ---------------------------------------------------------------------------------------------
// Decoding helpers. Every structural mismatch is `Codec`; an indefinite length is `NonCanonical`.
// Non-minimal integers and length heads are caught by the exact re-encoding check of `decode`.
// ---------------------------------------------------------------------------------------------
fn array_len(d: &mut Decoder<'_>) -> Result<u64, EnvelopeError> {
    match d.datatype().map_err(|_| EnvelopeError::Codec)? {
        Type::Array => d.array().map_err(|_| EnvelopeError::Codec)?.ok_or(EnvelopeError::NonCanonical),
        Type::ArrayIndef => Err(EnvelopeError::NonCanonical),
        _ => Err(EnvelopeError::Codec),
    }
}
fn expect_array(d: &mut Decoder<'_>, n: u64) -> Result<(), EnvelopeError> {
    if array_len(d)? != n {
        return Err(EnvelopeError::Codec);
    }
    Ok(())
}
fn uint(d: &mut Decoder<'_>) -> Result<u64, EnvelopeError> {
    d.u64().map_err(|_| EnvelopeError::Codec)
}
fn hash(d: &mut Decoder<'_>) -> Result<Hash, EnvelopeError> {
    if d.datatype().map_err(|_| EnvelopeError::Codec)? == Type::BytesIndef {
        return Err(EnvelopeError::NonCanonical);
    }
    d.bytes()
        .map_err(|_| EnvelopeError::Codec)?
        .try_into()
        .map_err(|_| EnvelopeError::Codec)
}
fn optional_hash(d: &mut Decoder<'_>) -> Result<Option<Hash>, EnvelopeError> {
    if d.datatype().map_err(|_| EnvelopeError::Codec)? == Type::Null {
        d.null().map_err(|_| EnvelopeError::Codec)?;
        return Ok(None);
    }
    hash(d).map(Some)
}
fn put_optional(e: &mut Encoder<Vec<u8>>, value: &Option<Hash>) {
    match value {
        Some(h) => e.bytes(h).unwrap(),
        None => e.null().unwrap(),
    };
}

impl AwardAccount {
    /// E5 per account: the dividend ledger's own structural rule (`Award::from_parts`):
    /// `award_epoch > 0`, `share > 0`, `remaining <= share`, `(share - remaining == 0) ==
    /// (claims == 0)` and `claims <= share - remaining`.
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        if self.award_epoch == 0 || self.share == 0 || self.remaining > self.share {
            return Err(EnvelopeError::Account);
        }
        let paid = self.share - self.remaining;
        if (paid == 0) != (self.claims == 0) || self.claims > paid {
            return Err(EnvelopeError::Account);
        }
        Ok(())
    }
}

impl Precondition {
    pub fn tag(&self) -> u8 {
        match self {
            Self::LicenseEntitlements { .. } => TAG_LICENSE_ENTITLEMENTS,
            Self::LicenseAssignment { .. } => TAG_LICENSE_ASSIGNMENT,
            Self::TreasuryHead { .. } => TAG_TREASURY_HEAD,
        }
    }
    /// The subject the precondition is about: the License, or the Treasury identity.
    pub fn subject(&self) -> Hash {
        match self {
            Self::LicenseEntitlements { license, .. } | Self::LicenseAssignment { license, .. } => *license,
            Self::TreasuryHead { treasury, .. } => *treasury,
        }
    }
    /// E4 ordering key: preconditions are strictly ascending by `(tag, subject)`.
    pub fn key(&self) -> (u8, Hash) {
        (self.tag(), self.subject())
    }
    /// E5 (LicenseEntitlements), E6 (LicenseAssignment), E7 (TreasuryHead). A zero License subject
    /// is refused for both License tags (E6 states it; design Appendix A also applies it to E5).
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        match self {
            Self::LicenseEntitlements { license, accounts } => {
                if *license == [0; 32] {
                    return Err(EnvelopeError::ZeroSubject);
                }
                for pair in accounts.windows(2) {
                    if pair[0].award_epoch >= pair[1].award_epoch {
                        return Err(EnvelopeError::AccountOrder);
                    }
                }
                for account in accounts {
                    account.validate()?;
                }
            }
            Self::LicenseAssignment { license, assignment_sequence, .. } => {
                if *license == [0; 32] {
                    return Err(EnvelopeError::ZeroSubject);
                }
                if *assignment_sequence == 0 {
                    return Err(EnvelopeError::ZeroSequence);
                }
            }
            Self::TreasuryHead { treasury, generation, address } => {
                if *treasury == [0; 32] || *address == [0; 32] {
                    return Err(EnvelopeError::ZeroSubject);
                }
                if *generation == 0 {
                    return Err(EnvelopeError::ZeroGeneration);
                }
            }
        }
        Ok(())
    }
    /// Writes the canonical form. The caller (`Envelope::to_bytes`) has validated the value.
    fn encode_into(&self, e: &mut Encoder<Vec<u8>>) {
        match self {
            Self::LicenseEntitlements { license, accounts } => {
                e.array(3).unwrap().u8(TAG_LICENSE_ENTITLEMENTS).unwrap().bytes(license).unwrap();
                e.array(accounts.len() as u64).unwrap();
                for a in accounts {
                    e.array(4)
                        .unwrap()
                        .u64(a.award_epoch)
                        .unwrap()
                        .u64(a.share)
                        .unwrap()
                        .u64(a.remaining)
                        .unwrap()
                        .u64(a.claims)
                        .unwrap();
                }
            }
            Self::LicenseAssignment { license, assignment_sequence, active_worker, pending } => {
                e.array(5)
                    .unwrap()
                    .u8(TAG_LICENSE_ASSIGNMENT)
                    .unwrap()
                    .bytes(license)
                    .unwrap()
                    .u64(*assignment_sequence)
                    .unwrap();
                put_optional(e, active_worker);
                put_optional(e, pending);
            }
            Self::TreasuryHead { treasury, generation, address } => {
                e.array(4)
                    .unwrap()
                    .u8(TAG_TREASURY_HEAD)
                    .unwrap()
                    .bytes(treasury)
                    .unwrap()
                    .u64(*generation)
                    .unwrap()
                    .bytes(address)
                    .unwrap();
            }
        }
    }
    /// Structure only; `Envelope::decode` validates E4-E7 and canonical form afterwards. Nothing
    /// is preallocated from an untrusted length: each element consumes input or fails.
    fn decode_fields(d: &mut Decoder<'_>) -> Result<Self, EnvelopeError> {
        let n = array_len(d)?;
        let tag = d.u8().map_err(|_| EnvelopeError::Codec)?;
        match (tag, n) {
            (TAG_LICENSE_ENTITLEMENTS, 3) => {
                let license = hash(d)?;
                let count = array_len(d)?;
                let mut accounts = Vec::new();
                for _ in 0..count {
                    expect_array(d, 4)?;
                    accounts.push(AwardAccount {
                        award_epoch: uint(d)?,
                        share: uint(d)?,
                        remaining: uint(d)?,
                        claims: uint(d)?,
                    });
                }
                Ok(Self::LicenseEntitlements { license, accounts })
            }
            (TAG_LICENSE_ASSIGNMENT, 5) => Ok(Self::LicenseAssignment {
                license: hash(d)?,
                assignment_sequence: uint(d)?,
                active_worker: optional_hash(d)?,
                pending: optional_hash(d)?,
            }),
            (TAG_TREASURY_HEAD, 4) => Ok(Self::TreasuryHead {
                treasury: hash(d)?,
                generation: uint(d)?,
                address: hash(d)?,
            }),
            _ => Err(EnvelopeError::Codec),
        }
    }
}

impl Envelope {
    /// The signer-side window built from the verified finalized head (design section 13; Order
    /// W22): `first = head.height + 1`, `last = first + validity_blocks`, reference = head. This is
    /// the wallet's existing meaning of `validity_blocks` (`wallet-core/src/plan.rs`: valid in
    /// the next block and the N blocks after it), N in `1..=EXPIRY_HORIZON`; anything else is an
    /// explicit refusal, never a silent cap.
    pub fn from_head(
        head: &FinalizedAnchor,
        validity_blocks: u64,
        preconditions: Vec<Precondition>,
    ) -> Result<Self, EnvelopeError> {
        if validity_blocks == 0 || validity_blocks > EXPIRY_HORIZON {
            return Err(EnvelopeError::ValidityBlocks);
        }
        let first_height = head.height.checked_add(1).ok_or(EnvelopeError::Overflow)?;
        let last_height = first_height
            .checked_add(validity_blocks)
            .ok_or(EnvelopeError::Overflow)?;
        let envelope = Self {
            first_height,
            last_height,
            reference_height: head.height,
            reference_block: head.block,
            preconditions,
        };
        envelope.validate()?;
        Ok(envelope)
    }
    /// The codec invariants E1-E7, in that order.
    pub fn validate(&self) -> Result<(), EnvelopeError> {
        if self.reference_block == [0; 32] {
            return Err(EnvelopeError::ZeroReference);
        }
        if !(self.reference_height < self.first_height && self.first_height <= self.last_height) {
            return Err(EnvelopeError::WindowOrder);
        }
        // E3 reuses the existing transfer horizon (transactions.rs); no new TTL is introduced.
        if self.last_height - self.first_height > EXPIRY_HORIZON {
            return Err(EnvelopeError::Horizon);
        }
        for pair in self.preconditions.windows(2) {
            if pair[0].key() >= pair[1].key() {
                return Err(EnvelopeError::PreconditionOrder);
            }
        }
        for precondition in &self.preconditions {
            precondition.validate()?;
        }
        Ok(())
    }
    /// The canonical encoding of a valid envelope (at most `MAX_ENVELOPE_BYTES`).
    pub fn to_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        self.validate()?;
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(ENVELOPE_VERSION)
            .unwrap()
            .u64(self.first_height)
            .unwrap()
            .u64(self.last_height)
            .unwrap();
        e.array(2)
            .unwrap()
            .u64(self.reference_height)
            .unwrap()
            .bytes(&self.reference_block)
            .unwrap();
        e.array(self.preconditions.len() as u64).unwrap();
        for precondition in &self.preconditions {
            precondition.encode_into(&mut e);
        }
        let raw = e.into_writer();
        if raw.len() > MAX_ENVELOPE_BYTES {
            return Err(EnvelopeError::Oversize);
        }
        Ok(raw)
    }
    /// Appends the canonical encoding to an enclosing item's encoder; a violating value is refused
    /// before anything is written.
    pub fn encode(&self, e: &mut Encoder<Vec<u8>>) -> Result<(), EnvelopeError> {
        let raw = self.to_bytes()?;
        e.writer_mut().extend_from_slice(&raw);
        Ok(())
    }
    /// Decodes one envelope at the decoder's position inside an enclosing item. The value must
    /// satisfy E1-E7 and its bytes must be exactly its canonical encoding, independently of any
    /// canonical check the enclosing item performs.
    pub fn decode(d: &mut Decoder<'_>) -> Result<Self, EnvelopeError> {
        let start = d.position();
        expect_array(d, 5)?;
        if d.u8().map_err(|_| EnvelopeError::Codec)? != ENVELOPE_VERSION {
            return Err(EnvelopeError::Codec);
        }
        let first_height = uint(d)?;
        let last_height = uint(d)?;
        expect_array(d, 2)?;
        let reference_height = uint(d)?;
        let reference_block = hash(d)?;
        let count = array_len(d)?;
        let mut preconditions = Vec::new();
        for _ in 0..count {
            preconditions.push(Precondition::decode_fields(d)?);
        }
        let envelope = Self {
            first_height,
            last_height,
            reference_height,
            reference_block,
            preconditions,
        };
        envelope.validate()?;
        let consumed = d.input().get(start..d.position()).ok_or(EnvelopeError::Codec)?;
        if envelope.to_bytes()? != consumed {
            return Err(EnvelopeError::NonCanonical);
        }
        Ok(envelope)
    }
    /// Decodes a standalone envelope (vectors, wallet review): bounded, nothing after it.
    pub fn from_bytes(raw: &[u8]) -> Result<Self, EnvelopeError> {
        if raw.len() > MAX_ENVELOPE_BYTES {
            return Err(EnvelopeError::Oversize);
        }
        let mut d = Decoder::new(raw);
        let envelope = Self::decode(&mut d)?;
        if d.position() != raw.len() {
            return Err(EnvelopeError::Codec);
        }
        Ok(envelope)
    }
    /// W and R at inclusion height `H = parent.height + 1` (design 1.a.2). `parent` is the locally
    /// authenticated parent anchor; `history` must come from the local canonical store (its anchors
    /// are the canonical block hashes of the referenced heights). A caller with an empty History can
    /// only include an envelope whose reference is the parent itself: it fails closed otherwise.
    pub fn check_inclusion(&self, parent: &FinalizedAnchor, history: &History) -> Result<(), EnvelopeError> {
        self.validate()?;
        let height = parent.height.checked_add(1).ok_or(EnvelopeError::Overflow)?;
        if height < self.first_height {
            return Err(EnvelopeError::Future);
        }
        if height > self.last_height {
            return Err(EnvelopeError::Expired);
        }
        // E2 and W imply reference_height <= parent.height: a reference is finalized history.
        let canonical = if self.reference_height == parent.height {
            Some(parent.block)
        } else {
            history.anchor(self.reference_height)
        };
        if canonical != Some(self.reference_block) {
            return Err(EnvelopeError::ReferenceNotCanonical);
        }
        Ok(())
    }
    /// P (design 1.a.2): every committed precondition must EQUAL the facts recomputed from `state`,
    /// which the caller reads at the carrying kind's validation point (design 1.a.5). Any
    /// difference, including facts that no longer exist, is `Stale(tag)`. Nothing is re-based.
    pub fn check_preconditions(&self, state: &State, context: &Context) -> Result<(), EnvelopeError> {
        self.validate()?;
        for committed in &self.preconditions {
            let facts = match committed {
                Precondition::LicenseEntitlements { license, .. } => Ok(entitlement_facts(state, *license)),
                Precondition::LicenseAssignment { license, .. } => assignment_facts(state, *license),
                Precondition::TreasuryHead { treasury, .. } => treasury_head_facts(state, context, *treasury),
            };
            if facts.as_ref() != Ok(committed) {
                return Err(EnvelopeError::Stale(committed.tag()));
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------------------------
// Fact functions (pure; consensus, pool and wallet use the same ones). The wallet must call them on
// VERIFIED state only.
// ---------------------------------------------------------------------------------------------

/// Every live award account of `license`, ascending by award epoch (an empty list when none).
pub fn entitlement_facts(state: &State, license: Hash) -> Precondition {
    let accounts = state
        .dividends
        .ledger()
        .awards_iter()
        .filter_map(|award| {
            award.account(&license).map(|a| AwardAccount {
                award_epoch: award.epoch(),
                share: a.share,
                remaining: a.remaining,
                claims: a.claims,
            })
        })
        .collect();
    Precondition::LicenseEntitlements { license, accounts }
}

/// The License's assignment sequence, active Worker and pending assignment id.
pub fn assignment_facts(state: &State, license: Hash) -> Result<Precondition, EnvelopeError> {
    let record = state
        .licenses_v2
        .license(license)
        .ok_or(EnvelopeError::Unavailable(TAG_LICENSE_ASSIGNMENT))?;
    let pending = state
        .licenses_v2
        .pending_assignment(license)
        .map(assignment_id)
        .transpose()?;
    let facts = Precondition::LicenseAssignment {
        license,
        assignment_sequence: record.assignment_sequence,
        active_worker: record.active_worker,
        pending,
    };
    facts.validate()?;
    Ok(facts)
}

/// The trading Treasury destination head (`trading_v1::treasury_current`) in `context`.
pub fn treasury_head_facts(state: &State, context: &Context, treasury: Hash) -> Result<Precondition, EnvelopeError> {
    let head = crate::trading_v1::treasury_current(state, context, treasury)
        .map_err(|_| EnvelopeError::Unavailable(TAG_TREASURY_HEAD))?;
    let facts = Precondition::TreasuryHead {
        treasury,
        generation: head.generation,
        address: head.address,
    };
    facts.validate()?;
    Ok(facts)
}

/// Assignment identity (design 9.1): `domain_hash(ASSIGNMENT_ID_DOMAIN, binding.bytes())` over the
/// unsigned binding. Signatures are excluded: two valid signature sets share one id.
pub fn assignment_id(assignment: &Assignment) -> Result<Hash, EnvelopeError> {
    let unsigned = assignment
        .enrollment
        .binding
        .bytes()
        .map_err(|_| EnvelopeError::Codec)?;
    Ok(domain_hash(ASSIGNMENT_ID_DOMAIN, &unsigned))
}

// ---------------------------------------------------------------------------------------------
// Reference heights of a block (design 1.a.3).
// ---------------------------------------------------------------------------------------------

/// The `reference_height` of every envelope that an item of `body` carries. The canonical store
/// inserts the canonical block hash of each such height (below the block) into the History it
/// executes the block with. Only envelopes are decoded; a malformed item is skipped here and
/// rejected by execution.
pub fn referenced_heights(body: &BlockBody) -> BTreeSet<u64> {
    referenced_heights_in(&body.transactions, &body.operations)
}

/// `referenced_heights` over item lists that are not (yet) a block body: the caller's operations
/// before assembly, or a pool's candidates.
pub fn referenced_heights_in(transactions: &[Vec<u8>], operations: &[Vec<u8>]) -> BTreeSet<u64> {
    transactions
        .iter()
        .filter_map(|raw| transaction_envelope(raw))
        .chain(operations.iter().filter_map(|raw| operation_envelope(raw)))
        .map(|envelope| envelope.reference_height)
        .collect()
}

/// The envelope of an envelope-bearing TRANSACTION, if `raw` is one: the funded wallet rotation
/// (transaction tag 25, design 3.2, WP-R; only its envelope is decoded, `funded_rotation_v2::
/// envelope_of`). Unit-test builds also recognize the TEST-ONLY carrier in the transaction list (it
/// can never execute there: it is not a hybrid transaction).
pub fn transaction_envelope(raw: &[u8]) -> Option<Envelope> {
    #[cfg(test)]
    if let Some(envelope) = carrier::envelope(raw) {
        return Some(envelope);
    }
    crate::funded_rotation_v2::envelope_of(raw)
}

/// The envelope of an envelope-bearing OPERATION, if `raw` is one: the funded BondCreate (kind 24) and
/// the bond commands of body version 3 (kinds 19/20) (WP-B) and a trading NativeOperation of body
/// version 2 (WP-T1). Unit-test builds also recognize the TEST-ONLY carrier.
pub fn operation_envelope(raw: &[u8]) -> Option<Envelope> {
    #[cfg(test)]
    if let Some(envelope) = carrier::envelope(raw) {
        return Some(envelope);
    }
    if let Some(envelope) = crate::bond_create_v3::envelope_of(raw).or_else(|| crate::bond_ops_v2::envelope_of(raw)) {
        return Some(envelope);
    }
    // Trading NativeOperation, body version 2 (WP-T1).
    crate::trading_v1::envelope_of(raw)
}

/// The envelope that is element `index` of the definite CBOR array `raw` (for example the
/// unsigned body of an adopting kind). None when `raw` is not such an array or the element is not
/// a valid canonical envelope.
pub fn envelope_at(raw: &[u8], index: u64) -> Option<Envelope> {
    let mut d = Decoder::new(raw);
    let count = d.array().ok()??;
    if index >= count {
        return None;
    }
    for _ in 0..index {
        d.skip().ok()?;
    }
    Envelope::decode(&mut d).ok()
}

/// Hook for `CanonicalStore::prepare_pending` (design 1.a.3, 5.5): the assembler trial-adds pending
/// pool candidates, so the History it executes them with must also hold the anchors of every
/// height those candidates reference. WP-POOL's pending source implements this.
pub trait PendingReferences {
    /// Every `reference_height` of an envelope a pending candidate carries.
    fn reference_heights(&self) -> BTreeSet<u64> {
        BTreeSet::new()
    }
}

/// `mempool_v2` holds hybrid Transfers and funded wallet rotations (tag 25, WP-R); a rotation
/// carries an envelope, so the pool reports the reference height of every pending one. A pool that
/// cannot be read reports no height: the assembler's trial of such an item then fails closed and
/// skips it. Unit-test builds also report the heights a test injects (`carrier::POOL_REFERENCES`),
/// to prove that `CanonicalStore::prepare_pending` gives the assembler those anchors.
impl PendingReferences for crate::mempool_v2::Mempool {
    fn reference_heights(&self) -> BTreeSet<u64> {
        #[allow(unused_mut)]
        let mut heights = self.pending_reference_heights().unwrap_or_default();
        #[cfg(test)]
        carrier::POOL_REFERENCES.with(|injected| heights.extend(injected.borrow().iter().copied()));
        heights
    }
}

/// TEST-ONLY envelope-bearing operation `[2, KIND, Envelope]`, compiled ONLY into this crate's own
/// unit tests (`#[cfg(test)]`): it never exists in a library, node or wallet build, where
/// `blocks::operation_kind` refuses it like any unknown kind. It has no state effect. In unit-test
/// builds the executor checks it at its classification point (after due activations and epoch
/// events): W and R against the parent and the store-supplied History, then P against the
/// tentative state. It exists so that the History plumbing can be exercised through real blocks
/// before the production kinds that adopt the envelope exist.
#[cfg(test)]
pub(crate) mod carrier {
    use super::{Envelope, EnvelopeError};
    use crate::{Error, NETWORK_ID, anchors::FinalizedAnchor, execution::ExecutionError};
    use minicbor::{Decoder, Encoder};

    /// Never a wire identifier: outside every production kind range.
    pub(crate) const KIND: u8 = 254;

    std::thread_local! {
        /// Reference heights the unit-test pool reports through `PendingReferences` (per thread).
        pub(crate) static POOL_REFERENCES: std::cell::RefCell<std::collections::BTreeSet<u64>> =
            std::cell::RefCell::new(std::collections::BTreeSet::new());
    }

    /// `[2, KIND, Envelope]`: the block-visible form (`operation_envelope` / `transaction_envelope`).
    pub(crate) fn encode(envelope: &Envelope) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(3).unwrap().u8(2).unwrap().u8(KIND).unwrap();
        envelope.encode(&mut e).unwrap();
        e.into_writer()
    }
    /// `[2, KIND, Envelope, null]`: the POOL-ONLY form. Executed exactly like the visible form, but
    /// no block-level extraction sees its reference: only a pool report (`POOL_REFERENCES`) can
    /// supply the anchor, so it isolates the pool hook of `prepare_pending`. Block validation never
    /// trusts a pool report, so such a block can never be committed.
    pub(crate) fn encode_pool_only(envelope: &Envelope) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(4).unwrap().u8(2).unwrap().u8(KIND).unwrap();
        envelope.encode(&mut e).unwrap();
        e.null().unwrap();
        e.into_writer()
    }
    fn form(raw: &[u8]) -> Option<u64> {
        let mut d = Decoder::new(raw);
        let count = d.array().ok().flatten()?;
        (matches!(count, 3 | 4) && d.u8().ok() == Some(2) && d.u8().ok() == Some(KIND)).then_some(count)
    }
    /// Either form (the item kind recognized by `blocks::operation_kind` in unit-test builds).
    pub(crate) fn is_carrier(raw: &[u8]) -> bool {
        form(raw).is_some()
    }
    /// The envelope of the block-visible form only.
    pub(crate) fn envelope(raw: &[u8]) -> Option<Envelope> {
        if form(raw) == Some(3) { decode(raw).ok() } else { None }
    }
    pub(crate) fn decode(raw: &[u8]) -> Result<Envelope, EnvelopeError> {
        crate::blocks::canonical(raw, super::MAX_ENVELOPE_BYTES).map_err(|_| EnvelopeError::NonCanonical)?;
        let count = form(raw).ok_or(EnvelopeError::Codec)?;
        let mut d = Decoder::new(raw);
        d.array().map_err(|_| EnvelopeError::Codec)?;
        d.u8().map_err(|_| EnvelopeError::Codec)?;
        d.u8().map_err(|_| EnvelopeError::Codec)?;
        let envelope = Envelope::decode(&mut d)?;
        if count == 4 {
            d.null().map_err(|_| EnvelopeError::Codec)?;
        }
        if d.position() != raw.len() {
            return Err(EnvelopeError::Codec);
        }
        Ok(envelope)
    }
    /// Executor check. Block-level errors are coarse (the executor has no envelope variant):
    /// decode `Codec(Error::Codec)`, W or R `Codec(Error::WrongAnchor)`, P
    /// `Codec(Error::StaleSequence)`; tests assert the exact `EnvelopeError` separately.
    pub(crate) fn check(
        raw: &[u8],
        parent: &crate::execution::WorkParent,
        history: &crate::evidence_history_v2::History,
        state: &crate::execution::State,
    ) -> crate::execution::Result<()> {
        let envelope = decode(raw).map_err(|_| ExecutionError::Codec(Error::Codec))?;
        let anchor = FinalizedAnchor {
            network: NETWORK_ID,
            genesis: parent.genesis,
            fingerprint: parent.fingerprint,
            height: parent.height,
            block: parent.block,
        };
        envelope
            .check_inclusion(&anchor, history)
            .map_err(|_| ExecutionError::Codec(Error::WrongAnchor))?;
        let context = crate::trading_v1::Context {
            network: NETWORK_ID,
            genesis: parent.genesis,
            fingerprint: parent.fingerprint,
        };
        envelope
            .check_preconditions(state, &context)
            .map_err(|_| ExecutionError::Codec(Error::StaleSequence))
    }
}

#[cfg(test)]
#[path = "op_envelope_v1_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "op_envelope_v1_store_tests.rs"]
mod store_tests;
