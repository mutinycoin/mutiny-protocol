//! P2: the funded wallet-rotation bundle, hybrid transaction wrapper tag 25 (Lane P design
//! `qualification/candidate-3/P-LANE-DESIGN-V1.md` sections 1.b, 1.c and 3, with amendments AM-1(d)
//! and AM-9 m6 of `P-LANE-DESIGN-AMENDMENTS-V1.md`; Order of 4 October 2026, decision P2).
//! Normative text: `spec/FUNDED-WALLET-ROTATION-V1.md` (integration copy, amended). Status:
//! PROPOSED-UNFROZEN, pre-Genesis candidate; nothing here is qualified or deployed.
//!
//! ONE transaction carries the complete rotation AND its funding. Every party signs the same
//! commitment over the UNSIGNED body, each under its own domain:
//!
//! ```text
//! unsigned   = [1, network, genesis32, fingerprint32, Envelope, authority32,
//!               current_descriptor, proposed_descriptor,
//!               null | [sponsor_address32, sponsor_descriptor], fee,
//!               [[txid32, index, payer] ...],     ; 1..=128, strictly ascending by (txid, index)
//!               [[owner32, atoms] ...]]           ; 0..=128 destinations and change
//! tx         = [2, 25, unsigned_bytes, authorize, possession,
//!               null | authority_funding, null | sponsor_funding]
//! partial    = [1, 25, unsigned_bytes, null | authorize, null | possession,
//!               null | authority_funding, null | sponsor_funding]      ; exchange object, never a block item
//! signature  = [ed448_114_bytes, fndsa_1280_bytes]
//! commitment = SHA-256("MUTINY-BUILD8-FUNDED-ROTATION-COMMITMENT-V2" || 0x00 || unsigned)
//! id         = SHA-256("MUTINY-BUILD8-FUNDED-ROTATION-ID-V2"         || 0x00 || unsigned)
//! authorize         : old key,     Domain::WalletRotate,           ["...-AUTHORIZE-V2",  commitment]
//! possession        : new key,     Domain::WalletRotatePossession, ["...-POSSESSION-V2", commitment]
//! authority_funding : old key,     Domain::Transaction, ["...-FUNDING-V2", commitment, 0]  iff a payer-0 input exists
//! sponsor_funding   : sponsor key, Domain::Transaction, ["...-FUNDING-V2", commitment, 1]  iff a sponsor is named
//! ```
//!
//! * No cycle (design 1.b B1): the commitment and the id are functions of the unsigned bytes only;
//!   the unsigned body contains no signature and no other object's identifier that could depend on
//!   this one (inputs name EXISTING coins). Nobody signs a signature, so signing order is free.
//! * Complete binding (B2): old/new authority, generation (inside both descriptors), sponsor,
//!   inputs with their payer tags, output amounts, change and destinations, fee, window, finalized
//!   reference and network/Genesis/fingerprint are all inside the unsigned body, so changing any of
//!   them invalidates every signature.
//! * Respective domains (B3): the rotation is authorized under the existing role domains; every
//!   spend is authorized ONLY by a `Domain::Transaction` signature of that input's payer over the
//!   labelled funding payload. No crypto-v2 domain or role is added.
//! * No standalone component (B4): the retired `[2, 21, rotation, transfer]` wrapper no longer
//!   decodes (`hybrid_transaction_v2`), the funding payload `[label, commitment, payer]` has a shape
//!   no other `Domain::Transaction` verifier accepts, inputs are consumed at first execution and the
//!   rotation is compare-and-replace.
//!
//! Verification (design 3.5) runs in the payment phase against the RUNNING state, so a later
//! transaction of the same block sees the completed rotation. Every authority for the transition
//! comes from the PRE-rotation book: the old key authorizes the rotation and its own inputs; the
//! new key only proves possession of the exact plan.
use crate::{
    Error, Hash, NETWORK_ID, domain_hash,
    anchors::FinalizedAnchor,
    evidence_history_v2::History,
    execution::State,
    hybrid_transaction_v2::{Inclusion, VerifiedTransaction},
    op_envelope_v1::{Envelope, EnvelopeError},
    transactions::{MATURITY, MAX_TX_BYTES, OutPoint, Output, TxError},
    wallet_authority_v1::WalletBook,
};
use minicbor::{Decoder, Encoder, data::Type};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, PublicKey, Role};
use std::borrow::Cow;

type Result<T> = std::result::Result<T, TxError>;

/// Outer version of every hybrid transaction (`[2, ...]`, as the hybrid Transfer).
pub const TRANSACTION_VERSION: u8 = 2;
/// Transaction wrapper tag of the funded rotation bundle (design 3.1).
pub const TRANSACTION_TAG: u8 = 25;
/// First element of the unsigned body.
pub const UNSIGNED_VERSION: u8 = 1;
/// First element of the partial exchange object (AM-9 m6). It differs from
/// `TRANSACTION_VERSION`, so a partial object can never decode as a transaction.
pub const PARTIAL_VERSION: u8 = 1;
/// Existing input/output count bound of the hybrid Transfer (`transactions_v2.rs`), reused.
pub const MAX_INPUTS: usize = 128;
pub const MAX_OUTPUTS: usize = 128;
/// `domain_hash` domain of the commitment that every party signs (PROPOSED-UNFROZEN).
pub const COMMITMENT_DOMAIN: &[u8] = b"MUTINY-BUILD8-FUNDED-ROTATION-COMMITMENT-V2";
/// `domain_hash` domain of the replay identity and output namespace (PROPOSED-UNFROZEN).
pub const ID_DOMAIN: &[u8] = b"MUTINY-BUILD8-FUNDED-ROTATION-ID-V2";
/// Payload label of the old key's rotation authorization (signed under `Domain::WalletRotate`).
pub const AUTHORIZE_LABEL: &[u8] = b"MUTINY-BUILD8-FUNDED-ROTATION-AUTHORIZE-V2";
/// Payload label of the new key's possession proof (`Domain::WalletRotatePossession`).
pub const POSSESSION_LABEL: &[u8] = b"MUTINY-BUILD8-FUNDED-ROTATION-POSSESSION-V2";
/// Payload label of both funding signatures (`Domain::Transaction`).
pub const FUNDING_LABEL: &[u8] = b"MUTINY-BUILD8-FUNDED-ROTATION-FUNDING-V2";

/// Who pays an input: the rotating authority (its OLD key signs `authority_funding`) or the named
/// sponsor (its current key signs `sponsor_funding`). Encoded as the unsigned integer 0 or 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Payer {
    RotatingAuthority = 0,
    Sponsor = 1,
}

/// The reviewed plan. Every field is bound by every signature through `commitment`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnsignedRotation {
    pub genesis: Hash,
    pub fingerprint: Hash,
    /// Signed window, finalized reference and optional preconditions (`op_envelope_v1`).
    pub envelope: Envelope,
    /// The rotating wallet authority id (its generation-one AddressID).
    pub authority: Hash,
    /// The old key, generation g: must be the authority's CURRENT descriptor at the validation point.
    pub current_descriptor: Vec<u8>,
    /// The new key, generation g + 1.
    pub proposed_descriptor: Vec<u8>,
    /// Explicitly reviewed sponsor `(address, current descriptor)`. Present iff a payer-1 input exists.
    pub sponsor: Option<(Hash, Vec<u8>)>,
    /// Declared fee: exact conservation `sum(inputs) == sum(outputs) + fee`, and
    /// `fee >= length of the complete signed transaction` (1 atom per byte, no surcharge).
    pub fee: u64,
    /// Bare OutPoints with payer tags, strictly ascending by OutPoint.
    pub inputs: Vec<(OutPoint, Payer)>,
    /// Destinations and change. Absence of change is absence, never a zero amount or owner.
    pub outputs: Vec<Output>,
}

/// The complete signed bundle (transaction wrapper tag 25).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundedRotation {
    pub unsigned: UnsignedRotation,
    pub authorize: HybridSignature,
    pub possession: HybridSignature,
    pub authority_funding: Option<HybridSignature>,
    pub sponsor_funding: Option<HybridSignature>,
}

/// AM-9 m6: the unsigned body plus any subset of the four signatures, for file exchange between the
/// rotating wallet, the new-key device and a sponsor (Order W12). It is never a block item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialRotation {
    pub unsigned: UnsignedRotation,
    pub authorize: Option<HybridSignature>,
    pub possession: Option<HybridSignature>,
    pub authority_funding: Option<HybridSignature>,
    pub sponsor_funding: Option<HybridSignature>,
}

/// The four signature slots, in their fixed wire order.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Slot {
    Authorize,
    Possession,
    AuthorityFunding,
    SponsorFunding,
}

/// The key that signs a slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Party {
    /// The rotating authority's OLD (current) key.
    RotatingAuthority,
    /// The proposed new key.
    NewKey,
    /// The named sponsor's current key.
    Sponsor,
}

/// One typed signing request (design section 13; Order W4): the wallet signs `payload` under
/// `domain` with the key whose public descriptor is `descriptor`, and nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigningIntent {
    pub slot: Slot,
    pub party: Party,
    pub domain: Domain,
    pub descriptor: Vec<u8>,
    pub payload: Vec<u8>,
}

// ---------------------------------------------------------------------------------------------
// Codec helpers. Structural mismatches are `Codec`; value rules have their own variants.
// ---------------------------------------------------------------------------------------------

fn codec<E>(_: E) -> TxError {
    TxError::Codec
}
fn expect_array(d: &mut Decoder<'_>, n: u64) -> Result<()> {
    if d.array().map_err(codec)? != Some(n) {
        return Err(TxError::Codec);
    }
    Ok(())
}
fn definite_array(d: &mut Decoder<'_>) -> Result<u64> {
    d.array().map_err(codec)?.ok_or(TxError::Codec)
}
fn fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N]> {
    d.bytes().map_err(codec)?.try_into().map_err(codec)
}
fn signature(d: &mut Decoder<'_>) -> Result<HybridSignature> {
    expect_array(d, 2)?;
    Ok(HybridSignature {
        ed448: fixed(d)?,
        fndsa: fixed(d)?,
    })
}
fn optional_signature(d: &mut Decoder<'_>) -> Result<Option<HybridSignature>> {
    if d.datatype().map_err(codec)? == Type::Null {
        d.null().map_err(codec)?;
        return Ok(None);
    }
    signature(d).map(Some)
}
fn put_signature(e: &mut Encoder<Vec<u8>>, s: &HybridSignature) {
    e.array(2).unwrap().bytes(&s.ed448).unwrap().bytes(&s.fndsa).unwrap();
}
fn put_optional_signature(e: &mut Encoder<Vec<u8>>, s: &Option<HybridSignature>) {
    match s {
        Some(s) => put_signature(e, s),
        None => {
            e.null().unwrap();
        }
    }
}
/// A rotation descriptor: an exact crypto-v2 descriptor of the WalletOwner role.
fn wallet_key(raw: &[u8]) -> Result<(PublicKey, u64)> {
    let (key, generation) = PublicKey::decode_descriptor(raw).map_err(codec)?;
    if key.role != Role::WalletOwner {
        return Err(TxError::Owner);
    }
    Ok((key, generation))
}
/// Envelope codec invariants (E1-E7) are value rules of this transaction (`Bounds`), structural
/// envelope errors are `Codec`.
fn envelope_codec_error(e: EnvelopeError) -> TxError {
    match e {
        EnvelopeError::Codec | EnvelopeError::NonCanonical | EnvelopeError::Oversize => TxError::Codec,
        EnvelopeError::Overflow => TxError::Overflow,
        _ => TxError::Bounds,
    }
}
/// Inclusion-time envelope errors. `TxError` has no reference/precondition variant (it is shared
/// with the Transfer and the wallet): a non-canonical reference and a stale precondition are a
/// broken chain-context binding (`Binding`); `UnsignedRotation::check_envelope` exposes the exact
/// `EnvelopeError` for diagnostics.
fn inclusion_error(e: EnvelopeError) -> TxError {
    match e {
        EnvelopeError::Future => TxError::Future,
        EnvelopeError::Expired => TxError::Expired,
        EnvelopeError::ReferenceNotCanonical | EnvelopeError::Stale(_) | EnvelopeError::Unavailable(_) => {
            TxError::Binding
        }
        other => envelope_codec_error(other),
    }
}

/// Role payload `[bytes label, bytes32 commitment]` (array(2)).
fn role_payload(label: &[u8], commitment: &Hash) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(2).unwrap().bytes(label).unwrap().bytes(commitment).unwrap();
    e.into_writer()
}
/// Funding payload `[bytes FUNDING_LABEL, bytes32 commitment, uint payer]` (array(3); its third
/// element is an unsigned integer, so it differs structurally from every other
/// `Domain::Transaction` payload: Transfer input array(2) [bytes, uint], dividend claim array(3)
/// [bytes, bytes, bytes], trading approval array(4), Treasury freeze array(14)).
pub fn funding_payload(commitment: &Hash, payer: Payer) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .bytes(FUNDING_LABEL)
        .unwrap()
        .bytes(commitment)
        .unwrap()
        .u8(payer as u8)
        .unwrap();
    e.into_writer()
}
/// The `Domain::WalletRotate` payload of the old key.
pub fn authorize_payload(commitment: &Hash) -> Vec<u8> {
    role_payload(AUTHORIZE_LABEL, commitment)
}
/// The `Domain::WalletRotatePossession` payload of the new key.
pub fn possession_payload(commitment: &Hash) -> Vec<u8> {
    role_payload(POSSESSION_LABEL, commitment)
}

// ---------------------------------------------------------------------------------------------
// The unsigned body.
// ---------------------------------------------------------------------------------------------

impl UnsignedRotation {
    /// True iff at least one input is paid by `payer`.
    pub fn pays(&self, payer: Payer) -> bool {
        self.inputs.iter().any(|(_, p)| *p == payer)
    }
    /// The descriptor whose key signs the funding of `payer`'s inputs.
    pub fn payer_descriptor(&self, payer: Payer) -> Option<&[u8]> {
        match payer {
            Payer::RotatingAuthority => Some(&self.current_descriptor),
            Payer::Sponsor => self.sponsor.as_ref().map(|(_, d)| d.as_slice()),
        }
    }
    /// The codec rules of design 3.2. A value that violates one of them is unrepresentable: it can
    /// be neither encoded (hence not signed) nor decoded (hence not admitted or executed).
    pub fn validate(&self) -> Result<()> {
        if self.authority == [0; 32] {
            return Err(TxError::Bounds);
        }
        // Both rotation descriptors are WalletOwner descriptors, the proposed generation is exactly
        // the current one plus one, and both key halves change (wallet_rotation_v1 rules).
        let (old, old_generation) = wallet_key(&self.current_descriptor)?;
        let (new, new_generation) = wallet_key(&self.proposed_descriptor)?;
        if old_generation.checked_add(1) != Some(new_generation) {
            return Err(TxError::Owner);
        }
        if old.ed448 == new.ed448 || old.fndsa == new.fndsa {
            return Err(TxError::Duplicate);
        }
        // A sponsor is a different party: its descriptor is neither rotation descriptor.
        if let Some((_, descriptor)) = &self.sponsor
            && (*descriptor == self.current_descriptor || *descriptor == self.proposed_descriptor)
        {
            return Err(TxError::Bounds);
        }
        // Stripped funding is unrepresentable: at least one input.
        if self.inputs.is_empty() || self.inputs.len() > MAX_INPUTS {
            return Err(TxError::Bounds);
        }
        for pair in self.inputs.windows(2) {
            match pair[0].0.cmp(&pair[1].0) {
                std::cmp::Ordering::Less => {}
                std::cmp::Ordering::Equal => return Err(TxError::Duplicate),
                std::cmp::Ordering::Greater => return Err(TxError::Codec),
            }
        }
        // A named sponsor must contribute, and no input may claim an absent sponsor.
        if self.pays(Payer::Sponsor) != self.sponsor.is_some() {
            return Err(TxError::Bounds);
        }
        if self.outputs.len() > MAX_OUTPUTS {
            return Err(TxError::Bounds);
        }
        // P3: no zero destination (never an implicit burn) and no zero amount (absence is absence).
        for output in &self.outputs {
            if output.atoms == 0 || output.owner == [0; 32] {
                return Err(TxError::Bounds);
            }
        }
        self.envelope.validate().map_err(envelope_codec_error)?;
        Ok(())
    }
    /// The canonical unsigned bytes (what the commitment and the id hash).
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut e = Encoder::new(Vec::new());
        e.array(12)
            .unwrap()
            .u8(UNSIGNED_VERSION)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap();
        self.envelope.encode(&mut e).map_err(envelope_codec_error)?;
        e.bytes(&self.authority)
            .unwrap()
            .bytes(&self.current_descriptor)
            .unwrap()
            .bytes(&self.proposed_descriptor)
            .unwrap();
        match &self.sponsor {
            Some((address, descriptor)) => {
                e.array(2).unwrap().bytes(address).unwrap().bytes(descriptor).unwrap();
            }
            None => {
                e.null().unwrap();
            }
        }
        e.u64(self.fee).unwrap().array(self.inputs.len() as u64).unwrap();
        for (point, payer) in &self.inputs {
            e.array(3)
                .unwrap()
                .bytes(&point.transaction)
                .unwrap()
                .u32(point.index)
                .unwrap()
                .u8(*payer as u8)
                .unwrap();
        }
        e.array(self.outputs.len() as u64).unwrap();
        for output in &self.outputs {
            e.array(2).unwrap().bytes(&output.owner).unwrap().u64(output.atoms).unwrap();
        }
        let raw = e.into_writer();
        if raw.len() > MAX_TX_BYTES {
            return Err(TxError::Bounds);
        }
        Ok(raw)
    }
    /// Decodes canonical unsigned bytes (separately canonical-checked: the walker does not recurse
    /// into byte strings, AM-9 n1) and re-validates every codec rule.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_TX_BYTES).map_err(codec)?;
        let mut d = Decoder::new(raw);
        expect_array(&mut d, 12)?;
        if d.u8().map_err(codec)? != UNSIGNED_VERSION {
            return Err(TxError::Codec);
        }
        if d.u32().map_err(codec)? != NETWORK_ID {
            return Err(TxError::Binding);
        }
        let genesis = fixed(&mut d)?;
        let fingerprint = fixed(&mut d)?;
        let envelope = Envelope::decode(&mut d).map_err(envelope_codec_error)?;
        let authority = fixed(&mut d)?;
        let current_descriptor = d.bytes().map_err(codec)?.to_vec();
        let proposed_descriptor = d.bytes().map_err(codec)?.to_vec();
        let sponsor = if d.datatype().map_err(codec)? == Type::Null {
            d.null().map_err(codec)?;
            None
        } else {
            expect_array(&mut d, 2)?;
            Some((fixed(&mut d)?, d.bytes().map_err(codec)?.to_vec()))
        };
        let fee = d.u64().map_err(codec)?;
        // Nothing is preallocated from an untrusted count: each element consumes input or fails.
        let mut inputs = Vec::new();
        for _ in 0..definite_array(&mut d)? {
            expect_array(&mut d, 3)?;
            let point = OutPoint {
                transaction: fixed(&mut d)?,
                index: d.u32().map_err(codec)?,
            };
            let payer = match d.u8().map_err(codec)? {
                0 => Payer::RotatingAuthority,
                1 => Payer::Sponsor,
                _ => return Err(TxError::Codec),
            };
            inputs.push((point, payer));
        }
        let mut outputs = Vec::new();
        for _ in 0..definite_array(&mut d)? {
            expect_array(&mut d, 2)?;
            outputs.push(Output {
                owner: fixed(&mut d)?,
                atoms: d.u64().map_err(codec)?,
            });
        }
        if d.position() != raw.len() {
            return Err(TxError::Codec);
        }
        let unsigned = Self {
            genesis,
            fingerprint,
            envelope,
            authority,
            current_descriptor,
            proposed_descriptor,
            sponsor,
            fee,
            inputs,
            outputs,
        };
        if unsigned.encode()? != raw {
            return Err(TxError::Codec);
        }
        Ok(unsigned)
    }
    /// What every party signs. A function of the unsigned bytes only (no cycle).
    pub fn commitment(&self) -> Result<Hash> {
        Ok(domain_hash(COMMITMENT_DOMAIN, &self.encode()?))
    }
    /// Replay identity, output namespace (`OutPoint{id, i}`) and confirmation key.
    pub fn id(&self) -> Result<Hash> {
        Ok(domain_hash(ID_DOMAIN, &self.encode()?))
    }
    /// W and R at inclusion height `parent.height + 1`, then the optional preconditions against
    /// `state` (the validation point: the running state of the payment phase). Exact
    /// `EnvelopeError` for diagnostics; `verify` maps it with `inclusion_error`.
    pub fn check_envelope(
        &self,
        parent: &FinalizedAnchor,
        history: &History,
        state: &State,
    ) -> std::result::Result<(), EnvelopeError> {
        self.envelope.check_inclusion(parent, history)?;
        self.envelope.check_preconditions(
            state,
            &crate::trading_v1::Context {
                network: NETWORK_ID,
                genesis: self.genesis,
                fingerprint: self.fingerprint,
            },
        )
    }
    /// Steps 1 to 5 of design 3.5 (everything that precedes the signatures).
    fn check_authority<'s>(&self, at: &Inclusion<'_>, state: &'s State) -> Result<Checked<'s>> {
        // 1. Codec rules (a decoded value satisfies them; a constructed one is checked here).
        self.validate()?;
        // 2. Context: the parent's network, Genesis and fingerprint.
        at.parent
            .validate_context(self.genesis, self.fingerprint)
            .map_err(|_| TxError::Binding)?;
        let height = at.height()?;
        // 3. Envelope: window, finalized reference, optional preconditions.
        self.check_envelope(at.parent, at.history, state)
            .map_err(inclusion_error)?;
        // 4. Authority. An unregistered authority must be the generation-one AddressID of the
        //    current descriptor; then that descriptor must be the CURRENT one (else a stale
        //    generation); the proposed address must be new. The compare-and-replace itself runs on
        //    a separate copy (`post`); `pre` stays the pre-rotation book.
        let mut pre = Cow::Borrowed(&state.wallets);
        if pre.current(self.authority).is_none() {
            let id = pre
                .to_mut()
                .register(&self.current_descriptor)
                .map_err(|_| TxError::Owner)?;
            if id != self.authority {
                return Err(TxError::Owner);
            }
        }
        if pre.current(self.authority) != Some(self.current_descriptor.as_slice()) {
            return Err(TxError::Owner);
        }
        let mut post = pre.as_ref().clone();
        post.apply_verified_rotation(self.authority, &self.current_descriptor, &self.proposed_descriptor)
            .map_err(|e| match e {
                Error::Duplicate => TxError::Duplicate,
                Error::Capacity => TxError::Bounds,
                _ => TxError::Owner,
            })?;
        // 5. Sponsor.
        self.check_sponsor(&pre)?;
        Ok(Checked { height, pre, post })
    }
    /// Step 5: the named sponsor's descriptor is the current authority of `sponsor_address` in the
    /// PRE-rotation book, and the sponsor's wallet authority differs from the rotating authority.
    fn check_sponsor(&self, pre: &WalletBook) -> Result<()> {
        if let Some((address, descriptor)) = &self.sponsor {
            pre.authorize(*address, descriptor).map_err(|_| TxError::Owner)?;
            if pre.authority_of(*address) == self.authority {
                return Err(TxError::Owner);
            }
        }
        Ok(())
    }
}

/// The result of steps 1-5: the pre-rotation book every input and the sponsor are authorized
/// against, and the post-rotation book the transaction installs.
struct Checked<'s> {
    height: u64,
    pre: Cow<'s, WalletBook>,
    post: WalletBook,
}

impl Checked<'_> {
    /// Steps 7 to 9 of design 3.5 (everything after the signatures).
    fn finish(self, u: &UnsignedRotation, state: &State, signed_len: usize) -> Result<VerifiedTransaction> {
        // 7. Inputs: present, Transfer maturity rules, owned by the payer's lineage in the
        //    PRE-rotation book (payer 0 through the OLD descriptor, payer 1 through the sponsor's).
        let mut incoming = 0u128;
        for (point, payer) in &u.inputs {
            let coin = state.coins.get(point).ok_or(TxError::MissingInput)?;
            if coin.created_height > self.height
                || (coin.coinbase && self.height - coin.created_height < MATURITY)
            {
                return Err(TxError::Immature);
            }
            let descriptor = u.payer_descriptor(*payer).ok_or(TxError::Bounds)?;
            self.pre
                .authorize(coin.output.owner, descriptor)
                .map_err(|_| TxError::Owner)?;
            incoming = incoming
                .checked_add(coin.output.atoms as u128)
                .ok_or(TxError::Overflow)?;
        }
        // 8. Exact conservation, then 1 atom per byte of the complete signed transaction.
        let outgoing = u.outputs.iter().try_fold(0u128, |sum, o| {
            sum.checked_add(o.atoms as u128).ok_or(TxError::Overflow)
        })?;
        let spent = outgoing
            .checked_add(u.fee as u128)
            .ok_or(TxError::Overflow)?;
        if incoming != spent {
            return Err(TxError::Conservation);
        }
        if (u.fee as u128) < signed_len as u128 {
            return Err(TxError::Fee);
        }
        // 9. Install the rotated book, then the existing generation-one registration of the payer
        //    descriptors (hybrid_transaction_v2 registers every paying generation-one wallet).
        let mut wallets = self.post;
        for payer in [Payer::RotatingAuthority, Payer::Sponsor] {
            if u.pays(payer)
                && let Some(descriptor) = u.payer_descriptor(payer)
            {
                register_generation_one(&mut wallets, descriptor)?;
            }
        }
        Ok(VerifiedTransaction {
            id: u.id()?,
            fee: u.fee,
            inputs: u.inputs.iter().map(|(point, _)| point.clone()).collect(),
            outputs: u.outputs.clone(),
            wallets,
        })
    }
}

fn register_generation_one(book: &mut WalletBook, descriptor: &[u8]) -> Result<()> {
    let (key, generation) = PublicKey::decode_descriptor(descriptor).map_err(codec)?;
    let id = key.address_id(generation).map_err(|_| TxError::Owner)?;
    if generation == 1 && book.current(id).is_none() {
        book.register(descriptor).map_err(|_| TxError::Owner)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Signatures.
// ---------------------------------------------------------------------------------------------

/// The four slots of `unsigned` as `(slot, party, domain, descriptor, payload)`, in wire order;
/// only the REQUIRED slots appear: `authorize` and `possession` always, `authority_funding` iff a
/// payer-0 input exists, `sponsor_funding` iff a sponsor is named (design section 13).
pub fn signing_intents(unsigned: &UnsignedRotation) -> Result<Vec<SigningIntent>> {
    let commitment = unsigned.commitment()?;
    let mut intents = vec![
        SigningIntent {
            slot: Slot::Authorize,
            party: Party::RotatingAuthority,
            domain: Domain::WalletRotate,
            descriptor: unsigned.current_descriptor.clone(),
            payload: authorize_payload(&commitment),
        },
        SigningIntent {
            slot: Slot::Possession,
            party: Party::NewKey,
            domain: Domain::WalletRotatePossession,
            descriptor: unsigned.proposed_descriptor.clone(),
            payload: possession_payload(&commitment),
        },
    ];
    if unsigned.pays(Payer::RotatingAuthority) {
        intents.push(SigningIntent {
            slot: Slot::AuthorityFunding,
            party: Party::RotatingAuthority,
            domain: Domain::Transaction,
            descriptor: unsigned.current_descriptor.clone(),
            payload: funding_payload(&commitment, Payer::RotatingAuthority),
        });
    }
    if let Some((_, descriptor)) = &unsigned.sponsor {
        intents.push(SigningIntent {
            slot: Slot::SponsorFunding,
            party: Party::Sponsor,
            domain: Domain::Transaction,
            descriptor: descriptor.clone(),
            payload: funding_payload(&commitment, Payer::Sponsor),
        });
    }
    Ok(intents)
}

/// Step 6 of design 3.5 over the slots of `unsigned`. A present signature must verify under its
/// slot's key, domain and payload; a present signature in a slot that is not required is refused;
/// a missing required signature is refused unless `allow_missing` (the partial-object preflight).
fn verify_slots(
    unsigned: &UnsignedRotation,
    slots: [Option<&HybridSignature>; 4],
    allow_missing: bool,
) -> Result<()> {
    let intents = signing_intents(unsigned)?;
    for (slot, signature) in [
        Slot::Authorize,
        Slot::Possession,
        Slot::AuthorityFunding,
        Slot::SponsorFunding,
    ]
    .into_iter()
    .zip(slots)
    {
        match (intents.iter().find(|i| i.slot == slot), signature) {
            (Some(intent), Some(signature)) => {
                let (key, _) =
                    PublicKey::decode_descriptor(&intent.descriptor).map_err(|_| TxError::Signature)?;
                key.verify(intent.domain, &intent.payload, signature)
                    .map_err(|_| TxError::Signature)?;
            }
            (Some(_), None) if allow_missing => {}
            (Some(_), None) | (None, Some(_)) => return Err(TxError::Signature),
            (None, None) => {}
        }
    }
    Ok(())
}

/// Complete signed length of the transaction `unsigned` becomes once every required slot is
/// filled (AM-9 m6): the fee rule needs it before anything is signed. Signatures have fixed sizes.
pub fn signed_len(unsigned: &UnsignedRotation) -> Result<usize> {
    let zero = HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    };
    FundedRotation {
        unsigned: unsigned.clone(),
        authorize: zero.clone(),
        possession: zero.clone(),
        authority_funding: unsigned.pays(Payer::RotatingAuthority).then(|| zero.clone()),
        sponsor_funding: unsigned.sponsor.is_some().then(|| zero.clone()),
    }
    .encode()
    .map(|raw| raw.len())
}

// ---------------------------------------------------------------------------------------------
// The signed bundle.
// ---------------------------------------------------------------------------------------------

impl FundedRotation {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let body = self.unsigned.encode()?;
        let mut e = Encoder::new(Vec::new());
        e.array(7)
            .unwrap()
            .u8(TRANSACTION_VERSION)
            .unwrap()
            .u8(TRANSACTION_TAG)
            .unwrap()
            .bytes(&body)
            .unwrap();
        put_signature(&mut e, &self.authorize);
        put_signature(&mut e, &self.possession);
        put_optional_signature(&mut e, &self.authority_funding);
        put_optional_signature(&mut e, &self.sponsor_funding);
        let raw = e.into_writer();
        if raw.len() > MAX_TX_BYTES {
            return Err(TxError::Bounds);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_TX_BYTES).map_err(codec)?;
        let mut d = Decoder::new(raw);
        expect_array(&mut d, 7)?;
        if d.u8().map_err(codec)? != TRANSACTION_VERSION || d.u8().map_err(codec)? != TRANSACTION_TAG {
            return Err(TxError::Codec);
        }
        let unsigned = UnsignedRotation::decode(d.bytes().map_err(codec)?)?;
        let rotation = Self {
            unsigned,
            authorize: signature(&mut d)?,
            possession: signature(&mut d)?,
            authority_funding: optional_signature(&mut d)?,
            sponsor_funding: optional_signature(&mut d)?,
        };
        if d.position() != raw.len() || rotation.encode()? != raw {
            return Err(TxError::Codec);
        }
        Ok(rotation)
    }
    pub fn id(&self) -> Result<Hash> {
        self.unsigned.id()
    }
    /// STATELESS part (AM-1(d)): the codec rules and step 6 (every required signature present and
    /// valid over the commitment under its own domain, no unrequired one). The keys are the
    /// bundle's own descriptors; whether they are the CURRENT authorities is `verify_state`.
    pub fn verify_signatures(&self) -> Result<()> {
        verify_slots(
            &self.unsigned,
            [
                Some(&self.authorize),
                Some(&self.possession),
                self.authority_funding.as_ref(),
                self.sponsor_funding.as_ref(),
            ],
            false,
        )
    }
    /// STATE-ONLY part (AM-1(d)): steps 1-5 and 7-9 of design 3.5, without step 6. Only for a
    /// caller that already holds a successful `verify_signatures` result for these exact bytes.
    pub fn verify_state(&self, at: &Inclusion<'_>, state: &State) -> Result<VerifiedTransaction> {
        let signed_len = self.encode()?.len();
        self.unsigned
            .check_authority(at, state)?
            .finish(&self.unsigned, state, signed_len)
    }
    /// The complete verification of design 3.5 in its order: steps 1-5 (`verify_state`'s first
    /// half), step 6 (`verify_signatures`), steps 7-9 (`verify_state`'s second half).
    pub fn verify(&self, at: &Inclusion<'_>, state: &State) -> Result<VerifiedTransaction> {
        let signed_len = self.encode()?.len();
        let checked = self.unsigned.check_authority(at, state)?;
        self.verify_signatures()?;
        checked.finish(&self.unsigned, state, signed_len)
    }
}

/// The envelope of a funded-rotation transaction, decoding nothing but its envelope (design 1.a.3:
/// `op_envelope_v1::transaction_envelope`). A malformed item yields None here and is rejected by
/// execution.
pub fn envelope_of(raw: &[u8]) -> Option<Envelope> {
    let mut d = Decoder::new(raw);
    if d.array().ok()?? != 7 || d.u8().ok()? != TRANSACTION_VERSION || d.u8().ok()? != TRANSACTION_TAG {
        return None;
    }
    crate::op_envelope_v1::envelope_at(d.bytes().ok()?, 4)
}

// ---------------------------------------------------------------------------------------------
// The partial exchange object (AM-9 m6).
// ---------------------------------------------------------------------------------------------

impl PartialRotation {
    /// A fresh partial object without signatures.
    pub fn new(unsigned: UnsignedRotation) -> Self {
        Self {
            unsigned,
            authorize: None,
            possession: None,
            authority_funding: None,
            sponsor_funding: None,
        }
    }
    fn slot_mut(&mut self, slot: Slot) -> &mut Option<HybridSignature> {
        match slot {
            Slot::Authorize => &mut self.authorize,
            Slot::Possession => &mut self.possession,
            Slot::AuthorityFunding => &mut self.authority_funding,
            Slot::SponsorFunding => &mut self.sponsor_funding,
        }
    }
    fn slots(&self) -> [Option<&HybridSignature>; 4] {
        [
            self.authorize.as_ref(),
            self.possession.as_ref(),
            self.authority_funding.as_ref(),
            self.sponsor_funding.as_ref(),
        ]
    }
    /// Signs one REQUIRED slot with `key`, which must be the key of the slot's descriptor
    /// (TEST-VALUE and wallet tooling; consensus never signs).
    pub fn sign(&mut self, slot: Slot, key: &HybridKey) -> Result<()> {
        let intent = signing_intents(&self.unsigned)?
            .into_iter()
            .find(|i| i.slot == slot)
            .ok_or(TxError::Bounds)?;
        let (public, _) = PublicKey::decode_descriptor(&intent.descriptor).map_err(codec)?;
        if key.public() != &public {
            return Err(TxError::Owner);
        }
        let signature = key
            .sign(intent.domain, &intent.payload)
            .map_err(|_| TxError::Signature)?;
        *self.slot_mut(slot) = Some(signature);
        Ok(())
    }
    /// The required slots that are still empty, in wire order.
    pub fn missing(&self) -> Result<Vec<Slot>> {
        let slots = self.slots();
        Ok(signing_intents(&self.unsigned)?
            .into_iter()
            .map(|i| i.slot)
            .filter(|slot| slots[*slot as usize].is_none())
            .collect())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let body = self.unsigned.encode()?;
        let mut e = Encoder::new(Vec::new());
        e.array(7)
            .unwrap()
            .u8(PARTIAL_VERSION)
            .unwrap()
            .u8(TRANSACTION_TAG)
            .unwrap()
            .bytes(&body)
            .unwrap();
        for slot in [
            &self.authorize,
            &self.possession,
            &self.authority_funding,
            &self.sponsor_funding,
        ] {
            put_optional_signature(&mut e, slot);
        }
        let raw = e.into_writer();
        if raw.len() > MAX_TX_BYTES {
            return Err(TxError::Bounds);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_TX_BYTES).map_err(codec)?;
        let mut d = Decoder::new(raw);
        expect_array(&mut d, 7)?;
        if d.u8().map_err(codec)? != PARTIAL_VERSION || d.u8().map_err(codec)? != TRANSACTION_TAG {
            return Err(TxError::Codec);
        }
        let unsigned = UnsignedRotation::decode(d.bytes().map_err(codec)?)?;
        let partial = Self {
            unsigned,
            authorize: optional_signature(&mut d)?,
            possession: optional_signature(&mut d)?,
            authority_funding: optional_signature(&mut d)?,
            sponsor_funding: optional_signature(&mut d)?,
        };
        if d.position() != raw.len() || partial.encode()? != raw {
            return Err(TxError::Codec);
        }
        Ok(partial)
    }
    /// Read-only review check for the sponsor and the new-key holder (AM-9 m6; Order W12): every
    /// check of `FundedRotation::verify` at inclusion height `parent.height + 1` against `state`,
    /// except that missing required signatures are allowed; every PRESENT signature is verified
    /// and an unrequired one is refused. The fee is checked against `signed_len` (the complete
    /// transaction's length). Nothing is changed.
    pub fn preflight(&self, state: &State, parent: &FinalizedAnchor, history: &History) -> Result<()> {
        let at = Inclusion { parent, history };
        let checked = self.unsigned.check_authority(&at, state)?;
        verify_slots(&self.unsigned, self.slots(), true)?;
        checked.finish(&self.unsigned, state, signed_len(&self.unsigned)?)?;
        Ok(())
    }
    /// The complete transaction once every required slot (and no other) is filled. The
    /// signatures themselves are verified by `FundedRotation::verify_signatures`/`verify`.
    pub fn complete(self) -> Result<FundedRotation> {
        let required = signing_intents(&self.unsigned)?;
        let slots = self.slots();
        for slot in [
            Slot::Authorize,
            Slot::Possession,
            Slot::AuthorityFunding,
            Slot::SponsorFunding,
        ] {
            if required.iter().any(|i| i.slot == slot) != slots[slot as usize].is_some() {
                return Err(TxError::Signature);
            }
        }
        let (Some(authorize), Some(possession)) = (self.authorize, self.possession) else {
            return Err(TxError::Signature);
        };
        Ok(FundedRotation {
            unsigned: self.unsigned,
            authorize,
            possession,
            authority_funding: self.authority_funding,
            sponsor_funding: self.sponsor_funding,
        })
    }
}

#[cfg(test)]
#[path = "funded_rotation_v2_tests.rs"]
mod tests;
