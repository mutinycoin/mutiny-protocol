//! Native trading integration. Validation is always compiled (no Cargo feature); the
//! parameters (denomination/fee constants, MAINNET_ACTIVATION=false) remain candidate pending
//! the pre-Genesis lock packet; no Mainnet allocation.
//! Ports qualified V2 wire/offer verification into the existing consensus crate
//! to avoid a dependency cycle. Uses actual State coins/WalletBook/proof APIs;
//! no OfflineState or duplicate balance ledger. Shared runtime hooks remain gated.
//! Codec source SHA256: 9249c21ca11c67d0767562c5b37d533573f1f10511b9ccb60931f4412ca25bfb
//! Offer source SHA256: e435abf5e04f0c40262260c42241ed2f8d60183f7391851c31074a6c71850e2f
mod codec {
    use super::OfferProof;
    use crate::op_envelope_v1::Envelope;
    use minicbor::{Decoder, Encoder};
    use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, PublicKey, Role};
    use sha2::{Digest, Sha256};
    use std::collections::BTreeSet;

    pub type Hash = [u8; 32];
    pub const NAMESPACE: &[u8] = b"MUTINY-OFFLINE-TRADING-CANDIDATE-V2-20261001";
    pub const MAX_BYTES: usize = 16_384;
    pub const MAX_INPUTS: usize = 16;
    pub const MAX_STATE_ITEMS: usize = 1024;
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Error {
        Codec,
        Bounds,
        Context,
        Signature,
        Authority,
        Generation,
        Expired,
        Time,
        Fee,
        Unit,
        Missing,
        Duplicate,
        Conflict,
        Conservation,
        Overflow,
        Condition,
        Locked,
        Capacity,
        Production,
        FiatRecoveryUnspecified,
        OfferBinding,
    }
    pub type Result<T> = std::result::Result<T, Error>;
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Strikes(pub u64);
    /// Single source of truth: `native_units_v1::MINIMUM_TRADE_FEE_STRIKES` (Restart Order section 3).
    pub const MINIMUM_TRADE_FEE: Strikes = Strikes(crate::native_units_v1::MINIMUM_TRADE_FEE_STRIKES);
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Unit {
        Strikes,
        Mut,
        UnresolvedNativeAtoms,
    }
    pub fn required_fee(unit: Unit, canonical_requirement: u64) -> Result<Strikes> {
        if unit != Unit::Strikes {
            return Err(Error::Unit);
        }
        Ok(Strikes(canonical_requirement.max(MINIMUM_TRADE_FEE.0)))
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Context {
        pub network: u32,
        pub genesis: Hash,
        pub fingerprint: Hash,
    }
    /// Trading operation body version (the second body element). Version 2 (P-LANE-DESIGN-V1
    /// 1.a and 5.1; Order P4): the operation envelope (signed inclusion window, finalized
    /// reference, committed preconditions) replaces the `created`/`expiry` heights of version 1,
    /// and LicenseDvp no longer carries an exact effective height. Version 1 bodies are refused.
    pub const BODY_VERSION: u8 = 2;
    /// `Body = [NAMESPACE, 2, network, genesis, fingerprint, trade, contract, generation,
    /// Envelope, fee, [input...], action]`; the envelope is bound by every approval, the fill
    /// proof and the operation id because all of them are computed over `body()`.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Meta {
        pub context: Context,
        pub trade: Hash,
        pub contract: Hash,
        pub generation: u64,
        pub envelope: Envelope,
        pub fee: Strikes,
        pub inputs: Vec<Hash>,
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Action {
        HashLock {
            offer: Hash,
            maker: Hash,
            sender: Hash,
            recipient: Hash,
            amount: Strikes,
            condition: Hash,
            refund_height: u64,
            change: Strikes,
        },
        Claim {
            output: Hash,
            recipient: Hash,
            amount: Strikes,
            preimage: Hash,
            change: Strikes,
        },
        Refund {
            output: Hash,
            owner: Hash,
            amount: Strikes,
            change: Strikes,
        },
        LicenseDvp {
            offer: Hash,
            maker: Hash,
            license: Hash,
            license_generation: u64,
            seller: Hash,
            buyer: Hash,
            price: Strikes,
            payment_destination: Hash,
            change: Strikes,
        },
        FiatLock {
            offer: Hash,
            maker: Hash,
            seller: Hash,
            buyer: Hash,
            amount: Strikes,
            payment_terms: Hash,
            change: Strikes,
        },
        FiatRelease {
            output: Hash,
            buyer: Hash,
            seller: Hash,
            amount: Strikes,
            payment_terms: Hash,
            change: Strikes,
        },
        TreasuryRotate {
            treasury: Hash,
            current_generation: u64,
            current_address: Hash,
            current_descriptor: Hash,
            new_generation: u64,
            new_address: Hash,
            new_descriptor: Vec<u8>,
            change: Strikes,
        },
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Approval {
        pub slot: u8,
        pub descriptor: Vec<u8>,
        pub signature: HybridSignature,
    }
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct Operation {
        pub meta: Meta,
        pub action: Action,
        pub approvals: Vec<Approval>,
        pub offer_proof: Option<OfferProof>,
    }

    pub fn hash(domain: &[u8], raw: &[u8]) -> Hash {
        let mut h = Sha256::new();
        h.update(NAMESPACE);
        h.update([0]);
        h.update(domain);
        h.update([0]);
        h.update(raw);
        h.finalize().into()
    }
    pub fn preimage_hash(raw: &Hash) -> Hash {
        Sha256::digest(raw).into()
    }
    pub fn descriptor_hash(raw: &[u8]) -> Hash {
        hash(b"descriptor", raw)
    }
    pub fn single_fill_key(context: &Context, _maker: Hash, offer: Hash) -> Hash {
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u32(context.network)
            .unwrap()
            .bytes(&context.genesis)
            .unwrap()
            .bytes(&context.fingerprint)
            .unwrap()
            .bytes(&offer)
            .unwrap();
        hash(b"single-fill", &e.into_writer())
    }
    /// P3 (Order of 4 Oct 2026; P-LANE-DESIGN-V1 4.1 rows 4-9 and 4.3): a zero address is never a
    /// monetary destination. Every address that consensus credits, that receives change or a
    /// refund, or that later receives a locked principal is refused here, in the codec: a zero
    /// destination can then be neither encoded, signed (every approval and fill payload is built
    /// from `body()`), decoded nor executed, and it is never turned into an implicit burn.
    /// LicenseDvp `seller` is not a destination (the price goes to `payment_destination`, the
    /// change to `buyer`). Zero values that name no destination stay legal (design 4.2):
    /// `change = 0` (no output is created), `HashLock.condition`, `Claim.preimage`, offer, maker
    /// and output identifiers, the generation and heights.
    fn refuse_zero_destinations(action: &Action) -> Result<()> {
        let zero = |address: &Hash| *address == [0; 32];
        let refused = match action {
            Action::HashLock {
                sender, recipient, ..
            } => zero(sender) || zero(recipient),
            Action::Claim { recipient, .. } => zero(recipient),
            Action::Refund { owner, .. } => zero(owner),
            Action::LicenseDvp {
                buyer,
                payment_destination,
                ..
            } => zero(buyer) || zero(payment_destination),
            Action::FiatLock { seller, buyer, .. } => zero(seller) || zero(buyer),
            Action::FiatRelease { buyer, seller, .. } => zero(buyer) || zero(seller),
            Action::TreasuryRotate {
                current_address,
                new_address,
                ..
            } => zero(current_address) || zero(new_address),
        };
        if refused {
            return Err(Error::Bounds);
        }
        Ok(())
    }
    impl Operation {
        pub fn body(&self) -> Result<Vec<u8>> {
            let m = &self.meta;
            if m.generation == 0
                || m.inputs.len() > MAX_INPUTS
                || m.inputs.windows(2).any(|w| w[0] >= w[1])
            {
                return Err(Error::Bounds);
            }
            refuse_zero_destinations(&self.action)?;
            let mut e = Encoder::new(Vec::new());
            e.array(12)
                .unwrap()
                .bytes(NAMESPACE)
                .unwrap()
                .u8(BODY_VERSION)
                .unwrap()
                .u32(m.context.network)
                .unwrap()
                .bytes(&m.context.genesis)
                .unwrap()
                .bytes(&m.context.fingerprint)
                .unwrap()
                .bytes(&m.trade)
                .unwrap()
                .bytes(&m.contract)
                .unwrap()
                .u64(m.generation)
                .unwrap();
            // The envelope codec enforces E1-E7 (a violating window, reference or precondition
            // list is unrepresentable and therefore unsignable).
            m.envelope.encode(&mut e).map_err(|_| Error::Bounds)?;
            e.u64(m.fee.0)
                .unwrap()
                .array(m.inputs.len() as u64)
                .unwrap();
            for id in &m.inputs {
                e.bytes(id).unwrap();
            }
            match &self.action {
                Action::HashLock {
                    offer,
                    maker,
                    sender,
                    recipient,
                    amount,
                    condition,
                    refund_height,
                    change,
                } => {
                    e.array(9)
                        .unwrap()
                        .u8(0)
                        .unwrap()
                        .bytes(offer)
                        .unwrap()
                        .bytes(maker)
                        .unwrap()
                        .bytes(sender)
                        .unwrap()
                        .bytes(recipient)
                        .unwrap()
                        .u64(amount.0)
                        .unwrap()
                        .bytes(condition)
                        .unwrap()
                        .u64(*refund_height)
                        .unwrap()
                        .u64(change.0)
                        .unwrap();
                }
                Action::Claim {
                    output,
                    recipient,
                    amount,
                    preimage,
                    change,
                } => {
                    e.array(6)
                        .unwrap()
                        .u8(1)
                        .unwrap()
                        .bytes(output)
                        .unwrap()
                        .bytes(recipient)
                        .unwrap()
                        .u64(amount.0)
                        .unwrap()
                        .bytes(preimage)
                        .unwrap()
                        .u64(change.0)
                        .unwrap();
                }
                Action::Refund {
                    output,
                    owner,
                    amount,
                    change,
                } => {
                    e.array(5)
                        .unwrap()
                        .u8(2)
                        .unwrap()
                        .bytes(output)
                        .unwrap()
                        .bytes(owner)
                        .unwrap()
                        .u64(amount.0)
                        .unwrap()
                        .u64(change.0)
                        .unwrap();
                }
                Action::LicenseDvp {
                    offer,
                    maker,
                    license,
                    license_generation,
                    seller,
                    buyer,
                    price,
                    payment_destination,
                    change,
                } => {
                    e.array(10)
                        .unwrap()
                        .u8(3)
                        .unwrap()
                        .bytes(offer)
                        .unwrap()
                        .bytes(maker)
                        .unwrap()
                        .bytes(license)
                        .unwrap()
                        .u64(*license_generation)
                        .unwrap()
                        .bytes(seller)
                        .unwrap()
                        .bytes(buyer)
                        .unwrap()
                        .u64(price.0)
                        .unwrap()
                        .bytes(payment_destination)
                        .unwrap()
                        .u64(change.0)
                        .unwrap();
                }
                Action::FiatLock {
                    offer,
                    maker,
                    seller,
                    buyer,
                    amount,
                    payment_terms,
                    change,
                } => {
                    e.array(8)
                        .unwrap()
                        .u8(4)
                        .unwrap()
                        .bytes(offer)
                        .unwrap()
                        .bytes(maker)
                        .unwrap()
                        .bytes(seller)
                        .unwrap()
                        .bytes(buyer)
                        .unwrap()
                        .u64(amount.0)
                        .unwrap()
                        .bytes(payment_terms)
                        .unwrap()
                        .u64(change.0)
                        .unwrap();
                }
                Action::FiatRelease {
                    output,
                    buyer,
                    seller,
                    amount,
                    payment_terms,
                    change,
                } => {
                    e.array(7)
                        .unwrap()
                        .u8(5)
                        .unwrap()
                        .bytes(output)
                        .unwrap()
                        .bytes(buyer)
                        .unwrap()
                        .bytes(seller)
                        .unwrap()
                        .u64(amount.0)
                        .unwrap()
                        .bytes(payment_terms)
                        .unwrap()
                        .u64(change.0)
                        .unwrap();
                }
                Action::TreasuryRotate {
                    treasury,
                    current_generation,
                    current_address,
                    current_descriptor,
                    new_generation,
                    new_address,
                    new_descriptor,
                    change,
                } => {
                    validate_descriptor(new_descriptor)?;
                    e.array(9)
                        .unwrap()
                        .u8(6)
                        .unwrap()
                        .bytes(treasury)
                        .unwrap()
                        .u64(*current_generation)
                        .unwrap()
                        .bytes(current_address)
                        .unwrap()
                        .bytes(current_descriptor)
                        .unwrap()
                        .u64(*new_generation)
                        .unwrap()
                        .bytes(new_address)
                        .unwrap()
                        .bytes(new_descriptor)
                        .unwrap()
                        .u64(change.0)
                        .unwrap();
                }
            }
            let b = e.into_writer();
            if b.len() > MAX_BYTES {
                return Err(Error::Bounds);
            }
            Ok(b)
        }
        pub fn id(&self) -> Result<Hash> {
            Ok(hash(b"operation", &self.body()?))
        }
        pub fn output_id(&self, index: u8) -> Result<Hash> {
            Ok(hash(b"output", &[self.id()?.as_slice(), &[index]].concat()))
        }
        pub fn signing_payload(&self, slot: u8, descriptor: &[u8]) -> Result<Vec<u8>> {
            validate_descriptor(descriptor)?;
            let mut e = Encoder::new(Vec::new());
            e.array(4)
                .unwrap()
                .bytes(NAMESPACE)
                .unwrap()
                .bytes(&self.body()?)
                .unwrap()
                .u8(slot)
                .unwrap()
                .bytes(descriptor)
                .unwrap();
            Ok(e.into_writer())
        }
        /// Test/offline signing only: caller must supply its own synthetic key. No key creation here.
        pub fn approve(&mut self, slot: u8, key: &HybridKey, generation: u64) -> Result<()> {
            if self.approvals.iter().any(|a| a.slot == slot) {
                return Err(Error::Duplicate);
            }
            let descriptor = key
                .public()
                .descriptor(generation)
                .map_err(|_| Error::Authority)?;
            let signature = key
                .sign(
                    Domain::Transaction,
                    &self.signing_payload(slot, &descriptor)?,
                )
                .map_err(|_| Error::Signature)?;
            self.approvals.push(Approval {
                slot,
                descriptor,
                signature,
            });
            self.approvals.sort_by_key(|a| a.slot);
            Ok(())
        }
        pub fn encode(&self) -> Result<Vec<u8>> {
            if self.approvals.len() > 2 || self.approvals.windows(2).any(|w| w[0].slot >= w[1].slot)
            {
                return Err(Error::Bounds);
            }
            let mut e = Encoder::new(Vec::new());
            e.array(3)
                .unwrap()
                .bytes(&self.body()?)
                .unwrap()
                .array(self.approvals.len() as u64)
                .unwrap();
            for a in &self.approvals {
                validate_descriptor(&a.descriptor)?;
                e.array(4)
                    .unwrap()
                    .u8(a.slot)
                    .unwrap()
                    .bytes(&a.descriptor)
                    .unwrap()
                    .bytes(&a.signature.ed448)
                    .unwrap()
                    .bytes(&a.signature.fndsa)
                    .unwrap();
            }
            match &self.offer_proof {
                Some(p) => {
                    e.bytes(&p.encode()?).unwrap();
                }
                None => {
                    e.null().unwrap();
                }
            }
            let out = e.into_writer();
            if out.len() > MAX_BYTES {
                return Err(Error::Bounds);
            }
            Ok(out)
        }
        pub fn decode(raw: &[u8]) -> Result<Self> {
            if raw.len() > MAX_BYTES {
                return Err(Error::Bounds);
            }
            let mut d = Decoder::new(raw);
            arr(&mut d, 3)?;
            let body = d.bytes().map_err(|_| Error::Codec)?;
            let mut op = Self::decode_body(body)?;
            let n = d.array().map_err(|_| Error::Codec)?.ok_or(Error::Codec)?;
            if n > 2 {
                return Err(Error::Bounds);
            }
            for _ in 0..n {
                arr(&mut d, 4)?;
                let slot = u8v(&mut d)?;
                let descriptor = desc(&mut d)?;
                let ed448 = fixed(&mut d)?;
                let fndsa = fixed(&mut d)?;
                op.approvals.push(Approval {
                    slot,
                    descriptor,
                    signature: HybridSignature { ed448, fndsa },
                });
            }
            op.offer_proof =
                if d.datatype().map_err(|_| Error::Codec)? == minicbor::data::Type::Null {
                    d.null().map_err(|_| Error::Codec)?;
                    None
                } else {
                    Some(OfferProof::decode(d.bytes().map_err(|_| Error::Codec)?)?)
                };
            if d.position() != raw.len() || op.encode()? != raw {
                return Err(Error::Codec);
            }
            Ok(op)
        }
        pub fn decode_body(raw: &[u8]) -> Result<Self> {
            if raw.len() > MAX_BYTES {
                return Err(Error::Bounds);
            }
            let mut d = Decoder::new(raw);
            arr(&mut d, 12)?;
            if d.bytes().map_err(|_| Error::Codec)? != NAMESPACE || u8v(&mut d)? != BODY_VERSION {
                return Err(Error::Codec);
            }
            let context = Context {
                network: d.u32().map_err(|_| Error::Codec)?,
                genesis: fixed(&mut d)?,
                fingerprint: fixed(&mut d)?,
            };
            let trade = fixed(&mut d)?;
            let contract = fixed(&mut d)?;
            let generation = u(&mut d)?;
            // E1-E7 and the envelope's own canonical form; any violation is a codec refusal.
            let envelope = Envelope::decode(&mut d).map_err(|_| Error::Codec)?;
            let fee = Strikes(u(&mut d)?);
            let n = d.array().map_err(|_| Error::Codec)?.ok_or(Error::Codec)?;
            if n > MAX_INPUTS as u64 {
                return Err(Error::Bounds);
            }
            let mut inputs = Vec::new();
            for _ in 0..n {
                inputs.push(fixed(&mut d)?);
            }
            let fields = d.array().map_err(|_| Error::Codec)?.ok_or(Error::Codec)?;
            let kind = u8v(&mut d)?;
            let action = match (kind, fields) {
                (0, 9) => Action::HashLock {
                    offer: fixed(&mut d)?,
                    maker: fixed(&mut d)?,
                    sender: fixed(&mut d)?,
                    recipient: fixed(&mut d)?,
                    amount: Strikes(u(&mut d)?),
                    condition: fixed(&mut d)?,
                    refund_height: u(&mut d)?,
                    change: Strikes(u(&mut d)?),
                },
                (1, 6) => Action::Claim {
                    output: fixed(&mut d)?,
                    recipient: fixed(&mut d)?,
                    amount: Strikes(u(&mut d)?),
                    preimage: fixed(&mut d)?,
                    change: Strikes(u(&mut d)?),
                },
                (2, 5) => Action::Refund {
                    output: fixed(&mut d)?,
                    owner: fixed(&mut d)?,
                    amount: Strikes(u(&mut d)?),
                    change: Strikes(u(&mut d)?),
                },
                (3, 10) => Action::LicenseDvp {
                    offer: fixed(&mut d)?,
                    maker: fixed(&mut d)?,
                    license: fixed(&mut d)?,
                    license_generation: u(&mut d)?,
                    seller: fixed(&mut d)?,
                    buyer: fixed(&mut d)?,
                    price: Strikes(u(&mut d)?),
                    payment_destination: fixed(&mut d)?,
                    change: Strikes(u(&mut d)?),
                },
                (4, 8) => Action::FiatLock {
                    offer: fixed(&mut d)?,
                    maker: fixed(&mut d)?,
                    seller: fixed(&mut d)?,
                    buyer: fixed(&mut d)?,
                    amount: Strikes(u(&mut d)?),
                    payment_terms: fixed(&mut d)?,
                    change: Strikes(u(&mut d)?),
                },
                (5, 7) => Action::FiatRelease {
                    output: fixed(&mut d)?,
                    buyer: fixed(&mut d)?,
                    seller: fixed(&mut d)?,
                    amount: Strikes(u(&mut d)?),
                    payment_terms: fixed(&mut d)?,
                    change: Strikes(u(&mut d)?),
                },
                (6, 9) => Action::TreasuryRotate {
                    treasury: fixed(&mut d)?,
                    current_generation: u(&mut d)?,
                    current_address: fixed(&mut d)?,
                    current_descriptor: fixed(&mut d)?,
                    new_generation: u(&mut d)?,
                    new_address: fixed(&mut d)?,
                    new_descriptor: desc(&mut d)?,
                    change: Strikes(u(&mut d)?),
                },
                _ => return Err(Error::Codec),
            };
            let op = Self {
                meta: Meta {
                    context,
                    trade,
                    contract,
                    generation,
                    envelope,
                    fee,
                    inputs,
                },
                action,
                approvals: Vec::new(),
                offer_proof: None,
            };
            if d.position() != raw.len() || op.body()? != raw {
                return Err(Error::Codec);
            }
            Ok(op)
        }
        /// The approval slots this action requires. Consensus demands exactly this set, so a
        /// missing slot and an extra slot are both refused: {0, 1} for HashLock, FiatLock,
        /// FiatRelease and LicenseDvp, {0} for Claim, Refund and TreasuryRotate. Read-only;
        /// `slot_address` names who must authorize each slot.
        pub fn expected_slots(&self) -> BTreeSet<u8> {
            match self.action {
                Action::HashLock { .. }
                | Action::FiatLock { .. }
                | Action::LicenseDvp { .. }
                | Action::FiatRelease { .. } => BTreeSet::from([0, 1]),
                _ => BTreeSet::from([0]),
            }
        }
        /// The AddressID that must authorize `slot`, or `None` when the action does not use that
        /// slot. Read-only mirror of the `authorize` calls of `apply_one`; the wallet authority
        /// currently resolved for that address is the one that must sign (`verify_approval`).
        pub fn slot_address(&self, slot: u8) -> Option<Hash> {
            let (first, second) = match &self.action {
                Action::HashLock {
                    sender, recipient, ..
                } => (*sender, Some(*recipient)),
                Action::FiatLock { seller, buyer, .. } => (*seller, Some(*buyer)),
                Action::Claim { recipient, .. } => (*recipient, None),
                Action::Refund { owner, .. } => (*owner, None),
                Action::FiatRelease { buyer, seller, .. } => (*buyer, Some(*seller)),
                // P6 (design 7.3 R2-3): the canonical Treasury authority T authorizes a
                // TreasuryRotate, never the trading destination address.
                Action::TreasuryRotate { treasury, .. } => (*treasury, None),
                Action::LicenseDvp { seller, buyer, .. } => (*seller, Some(*buyer)),
            };
            match slot {
                0 => Some(first),
                1 => second,
                _ => None,
            }
        }
        /// The AddressID that funds this operation: its wallet lineage owns every input (any
        /// authenticated generation whose current descriptor approves the payer's slot, P9), it
        /// pays the fee and receives the change (and it also pays the principal or price of a
        /// HashLock, FiatLock or LicenseDvp). Read-only mirror of the payer `apply_one` debits:
        /// the sender of a HashLock, the seller of a FiatLock, the recipient of a Claim, the
        /// owner of a Refund, the buyer of a FiatRelease or LicenseDvp and the current Treasury
        /// address of a TreasuryRotate.
        pub fn fee_payer(&self) -> Hash {
            match &self.action {
                Action::HashLock { sender, .. } => *sender,
                Action::FiatLock { seller, .. } => *seller,
                Action::Claim { recipient, .. } => *recipient,
                Action::Refund { owner, .. } => *owner,
                Action::FiatRelease { buyer, .. } => *buyer,
                Action::TreasuryRotate {
                    current_address, ..
                } => *current_address,
                Action::LicenseDvp { buyer, .. } => *buyer,
            }
        }
    }
    pub(crate) fn validate_descriptor(raw: &[u8]) -> Result<PublicKey> {
        if raw.len() > 2048 {
            return Err(Error::Bounds);
        }
        let (p, _) = PublicKey::decode_descriptor(raw).map_err(|_| Error::Codec)?;
        if p.role != Role::WalletOwner {
            return Err(Error::Authority);
        }
        Ok(p)
    }
    fn desc(d: &mut Decoder<'_>) -> Result<Vec<u8>> {
        let b = d.bytes().map_err(|_| Error::Codec)?;
        validate_descriptor(b)?;
        Ok(b.to_vec())
    }
    pub(crate) fn arr(d: &mut Decoder<'_>, n: u64) -> Result<()> {
        if d.array().map_err(|_| Error::Codec)? != Some(n) {
            return Err(Error::Codec);
        }
        Ok(())
    }
    pub(crate) fn fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N]> {
        d.bytes()
            .map_err(|_| Error::Codec)?
            .try_into()
            .map_err(|_| Error::Codec)
    }
    pub(crate) fn u(d: &mut Decoder<'_>) -> Result<u64> {
        d.u64().map_err(|_| Error::Codec)
    }
    pub(crate) fn u8v(d: &mut Decoder<'_>) -> Result<u8> {
        d.u8().map_err(|_| Error::Codec)
    }
}
use crate::{
    anchors::FinalizedAnchor,
    evidence_history_v2::History,
    execution::State,
    op_envelope_v1::{Envelope, EnvelopeError, Precondition, TAG_LICENSE_ASSIGNMENT},
    transactions::{Coin, EXPIRY_HORIZON, MATURITY, OutPoint, Output},
    wallet_authority_v1::WalletBook,
};
pub use codec::*;
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::Domain;
// P7 (Lane P design 8, AM-6): the canonical maker-offer format lives in `trading_offer_v2`.
pub use crate::trading_offer_v2::{
    MAKER_OFFER_LABEL, MakerOffer, OFFER_BODY_VERSION, OfferBody, OfferProof, OfferTerms, SignedOffer,
};
use std::collections::{BTreeMap, BTreeSet};

pub const NATIVE_NAMESPACE: &[u8] = b"MUTINY-NATIVE-TRADE-CANDIDATE-V1";
pub const MAX_NATIVE_BYTES: usize = 16_384;
pub const MAX_NATIVE_RECORD: usize = 8192;
pub const MAX_BATCH: usize = 64;
pub const MAINNET_ACTIVATION: bool = false;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeError {
    Codec,
    Context,
    Gate,
    UnitUnresolved,
    Bounds,
    Authority,
    Immature,
    Missing,
    Duplicate,
    Conflict,
    Conservation,
    Overflow,
    Fee,
    Time,
    Record,
    FiatRecoveryUnspecified,
    LicenseLocked,
    Candidate(Error),
    /// P4 window W or reference R at the inclusion height (`Envelope::check_inclusion`):
    /// `Future`, `Expired` or `ReferenceNotCanonical` (design 1.a.2).
    Envelope(EnvelopeError),
    /// P4 committed precondition with this tag differs from the facts at the trading validation
    /// point (design 1.a.2, 1.a.5 and 6.2): 1 LicenseEntitlements, 2 LicenseAssignment,
    /// 3 TreasuryHead. Nothing is re-based; the operation needs fresh review and signatures.
    Stale(u8),
}
impl From<Error> for NativeError {
    fn from(e: Error) -> Self {
        Self::Candidate(e)
    }
}
pub type NativeResult<T> = std::result::Result<T, NativeError>;
#[derive(Clone, Debug)]
pub struct CandidatePolicy {
    candidate: bool,
    synthetic_unit_alias: bool,
}
impl CandidatePolicy {
    pub fn disabled() -> Self {
        Self {
            candidate: false,
            synthetic_unit_alias: false,
        }
    }
    pub fn nonproduction_unresolved() -> Self {
        Self {
            candidate: true,
            synthetic_unit_alias: false,
        }
    }
    /// Architect-locked denomination (Restart Order, 2 Oct 2026, section 2): 1 STRIKE is one
    /// native atom and 1 MUT is 100,000,000 STRIKES. The candidate gate still applies;
    /// this does not enable Mainnet activation or any production path.
    pub fn native_denomination_locked() -> Self {
        Self {
            candidate: true,
            synthetic_unit_alias: true,
        }
    }
    /// Retained for existing vectors; superseded by `native_denomination_locked`.
    /// Formerly an explicit synthetic assumption, not an Architect denomination lock.
    #[cfg(test)]
    pub fn synthetic_one_atom_per_strike() -> Self {
        Self {
            candidate: true,
            synthetic_unit_alias: true,
        }
    }
    /// Enforce the same candidate and unresolved-unit gates in host adapters.
    pub fn check(&self) -> NativeResult<()> {
        if !self.candidate {
            return Err(NativeError::Gate);
        }
        if !self.synthetic_unit_alias {
            return Err(NativeError::UnitUnresolved);
        }
        Ok(())
    }
}
/// Locator witnesses are bound by the signed canonical native UTXO keys.
/// They never supply balances/owners, and have one unique ordering.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeOperation {
    pub operation: Operation,
    pub inputs: Vec<OutPoint>,
}
pub fn native_input_id(point: &OutPoint) -> Hash {
    crate::state_proof::utxo_key(point)
}
impl NativeOperation {
    pub fn encode(&self) -> NativeResult<Vec<u8>> {
        if self.inputs.len() != self.operation.meta.inputs.len() || self.inputs.len() > MAX_INPUTS {
            return Err(NativeError::Bounds);
        }
        for (p, id) in self.inputs.iter().zip(&self.operation.meta.inputs) {
            if native_input_id(p) != *id {
                return Err(NativeError::Context);
            }
        }
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .bytes(NATIVE_NAMESPACE)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&self.operation.encode()?)
            .unwrap()
            .array(self.inputs.len() as u64)
            .unwrap();
        for p in &self.inputs {
            e.array(2)
                .unwrap()
                .bytes(&p.transaction)
                .unwrap()
                .u32(p.index)
                .unwrap();
        }
        let raw = e.into_writer();
        if raw.len() > MAX_NATIVE_BYTES {
            return Err(NativeError::Bounds);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> NativeResult<Self> {
        if raw.len() > MAX_NATIVE_BYTES {
            return Err(NativeError::Bounds);
        }
        let mut d = Decoder::new(raw);
        array(&mut d, 4)?;
        if bytes(&mut d)? != NATIVE_NAMESPACE || uint(&mut d)? != 1 {
            return Err(NativeError::Codec);
        }
        let operation = Operation::decode(bytes(&mut d)?)?;
        let n = d
            .array()
            .map_err(|_| NativeError::Codec)?
            .ok_or(NativeError::Codec)?;
        if n > MAX_INPUTS as u64 {
            return Err(NativeError::Bounds);
        }
        let mut inputs = Vec::new();
        for _ in 0..n {
            array(&mut d, 2)?;
            inputs.push(OutPoint {
                transaction: native_fixed(&mut d)?,
                index: d.u32().map_err(|_| NativeError::Codec)?,
            });
        }
        let out = Self { operation, inputs };
        if d.position() != raw.len() || out.encode()? != raw {
            return Err(NativeError::Codec);
        }
        Ok(out)
    }
}
fn array(d: &mut Decoder<'_>, n: u64) -> NativeResult<()> {
    if d.array().map_err(|_| NativeError::Codec)? != Some(n) {
        Err(NativeError::Codec)
    } else {
        Ok(())
    }
}
fn bytes<'a>(d: &mut Decoder<'a>) -> NativeResult<&'a [u8]> {
    d.bytes().map_err(|_| NativeError::Codec)
}
fn native_fixed(d: &mut Decoder<'_>) -> NativeResult<Hash> {
    bytes(d)?.try_into().map_err(|_| NativeError::Codec)
}
fn uint(d: &mut Decoder<'_>) -> NativeResult<u64> {
    d.u64().map_err(|_| NativeError::Codec)
}
fn native_hash(label: &[u8], value: &[u8]) -> Hash {
    crate::domain_hash(&[NATIVE_NAMESPACE, b"/", label].concat(), value)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeLock {
    pub context: Context,
    pub trade: Hash,
    pub contract: Hash,
    pub generation: u64,
    pub sender: Hash,
    pub recipient: Hash,
    pub amount: Strikes,
    pub created_height: u64,
    pub kind: NativeLockKind,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeLockKind {
    Hash { condition: Hash, refund_height: u64 },
    Fiat { terms: Hash },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreasuryDestination {
    pub generation: u64,
    pub address: Hash,
    pub descriptor: Vec<u8>,
    pub effective_height: u64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeRecord {
    License {
        context: Context,
        generation: u64,
        owner: Hash,
        previous_owner: Hash,
        transfer: Hash,
        inclusion_height: u64,
        rights_from_height: u64,
        assignment_sequence: u64,
    },
    Lock(NativeLock),
    Consumed {
        context: Context,
        offer: Hash,
        trade: Hash,
        contract: Hash,
    },
    Applied {
        wire_hash: Hash,
        height: u64,
        fee_atoms: u64,
    },
    /// Tag 3: the HEAD of a Treasury's destination history (its latest generation). The full
    /// history is never held in one record: generation `g` lives in its own `TreasuryGeneration`
    /// record, so every operation reads and writes a bounded number of records whatever the
    /// number of rotations. There is no lifetime rotation limit and no pruning.
    Treasury {
        context: Context,
        current: TreasuryDestination,
    },
    /// Tag 5: one immutable, generation-indexed destination. Frozen commitments and reserves that
    /// still name an older generation keep resolving it, whatever its present balance.
    TreasuryGeneration {
        context: Context,
        treasury: Hash,
        destination: TreasuryDestination,
    },
    /// Tag 6: address -> generation index (a destination address is used by one generation only).
    TreasuryAddress {
        context: Context,
        treasury: Hash,
        address: Hash,
        generation: u64,
    },
}
impl NativeRecord {
    fn tag(&self) -> u8 {
        match self {
            Self::Lock(_) => 0,
            Self::Consumed { .. } => 1,
            Self::Applied { .. } => 2,
            Self::Treasury { .. } => 3,
            Self::License { .. } => 4,
            Self::TreasuryGeneration { .. } => 5,
            Self::TreasuryAddress { .. } => 6,
        }
    }
    pub fn encode(&self, id: Hash) -> NativeResult<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .bytes(NATIVE_NAMESPACE)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(self.tag())
            .unwrap()
            .bytes(&id)
            .unwrap();
        let ctx = |e: &mut Encoder<Vec<u8>>, c: &Context| {
            e.array(3)
                .unwrap()
                .u32(c.network)
                .unwrap()
                .bytes(&c.genesis)
                .unwrap()
                .bytes(&c.fingerprint)
                .unwrap();
        };
        match self {
            Self::License {
                context,
                generation,
                owner,
                previous_owner,
                transfer,
                inclusion_height,
                rights_from_height,
                assignment_sequence,
            } => {
                if *generation < 2
                    || owner == previous_owner
                    || *transfer == [0; 32]
                    || inclusion_height.checked_add(1) != Some(*rights_from_height)
                    || *assignment_sequence == 0
                {
                    return Err(NativeError::Record);
                }
                e.array(8).unwrap();
                ctx(&mut e, context);
                e.u64(*generation)
                    .unwrap()
                    .bytes(owner)
                    .unwrap()
                    .bytes(previous_owner)
                    .unwrap()
                    .bytes(transfer)
                    .unwrap()
                    .u64(*inclusion_height)
                    .unwrap()
                    .u64(*rights_from_height)
                    .unwrap()
                    .u64(*assignment_sequence)
                    .unwrap();
            }
            Self::Lock(l) => {
                e.array(9).unwrap();
                ctx(&mut e, &l.context);
                e.bytes(&l.trade)
                    .unwrap()
                    .bytes(&l.contract)
                    .unwrap()
                    .u64(l.generation)
                    .unwrap()
                    .bytes(&l.sender)
                    .unwrap()
                    .bytes(&l.recipient)
                    .unwrap()
                    .u64(l.amount.0)
                    .unwrap()
                    .u64(l.created_height)
                    .unwrap();
                match l.kind {
                    NativeLockKind::Hash {
                        condition,
                        refund_height,
                    } => {
                        e.array(3)
                            .unwrap()
                            .u8(0)
                            .unwrap()
                            .bytes(&condition)
                            .unwrap()
                            .u64(refund_height)
                            .unwrap();
                    }
                    NativeLockKind::Fiat { terms } => {
                        e.array(2).unwrap().u8(1).unwrap().bytes(&terms).unwrap();
                    }
                }
            }
            Self::Consumed {
                context,
                offer,
                trade,
                contract,
            } => {
                e.array(4).unwrap();
                ctx(&mut e, context);
                e.bytes(offer)
                    .unwrap()
                    .bytes(trade)
                    .unwrap()
                    .bytes(contract)
                    .unwrap();
            }
            Self::Applied {
                wire_hash,
                height,
                fee_atoms,
            } => {
                e.array(3)
                    .unwrap()
                    .bytes(wire_hash)
                    .unwrap()
                    .u64(*height)
                    .unwrap()
                    .u64(*fee_atoms)
                    .unwrap();
            }
            Self::Treasury { context, current } => {
                validate_destination(current)?;
                e.array(2).unwrap();
                ctx(&mut e, context);
                encode_destination(&mut e, current);
            }
            Self::TreasuryGeneration {
                context,
                treasury,
                destination,
            } => {
                validate_destination(destination)?;
                if id != treasury_generation_id(*treasury, destination.generation) {
                    return Err(NativeError::Record);
                }
                e.array(3).unwrap();
                ctx(&mut e, context);
                e.bytes(treasury).unwrap();
                encode_destination(&mut e, destination);
            }
            Self::TreasuryAddress {
                context,
                treasury,
                address,
                generation,
            } => {
                if *generation == 0 || id != treasury_address_id(*treasury, *address) {
                    return Err(NativeError::Record);
                }
                e.array(4).unwrap();
                ctx(&mut e, context);
                e.bytes(treasury).unwrap().bytes(address).unwrap().u64(*generation).unwrap();
            }
        }
        let raw = e.into_writer();
        if raw.len() > MAX_NATIVE_RECORD {
            return Err(NativeError::Bounds);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> NativeResult<(Hash, Self)> {
        if raw.len() > MAX_NATIVE_RECORD {
            return Err(NativeError::Bounds);
        }
        let mut d = Decoder::new(raw);
        array(&mut d, 5)?;
        if bytes(&mut d)? != NATIVE_NAMESPACE || uint(&mut d)? != 1 {
            return Err(NativeError::Codec);
        }
        let tag = uint(&mut d)?;
        let id = native_fixed(&mut d)?;
        fn context(d: &mut Decoder<'_>) -> NativeResult<Context> {
            array(d, 3)?;
            Ok(Context {
                network: d.u32().map_err(|_| NativeError::Codec)?,
                genesis: native_fixed(d)?,
                fingerprint: native_fixed(d)?,
            })
        }
        let r = match tag {
            0 => {
                array(&mut d, 9)?;
                let context = context(&mut d)?;
                let trade = native_fixed(&mut d)?;
                let contract = native_fixed(&mut d)?;
                let generation = uint(&mut d)?;
                let sender = native_fixed(&mut d)?;
                let recipient = native_fixed(&mut d)?;
                let amount = Strikes(uint(&mut d)?);
                let created_height = uint(&mut d)?;
                let n = d.array().map_err(|_| NativeError::Codec)?;
                let tag = uint(&mut d)?;
                let kind = match (n, tag) {
                    (Some(3), 0) => NativeLockKind::Hash {
                        condition: native_fixed(&mut d)?,
                        refund_height: uint(&mut d)?,
                    },
                    (Some(2), 1) => NativeLockKind::Fiat {
                        terms: native_fixed(&mut d)?,
                    },
                    _ => return Err(NativeError::Codec),
                };
                if generation == 0 || amount.0 == 0 || sender == recipient {
                    return Err(NativeError::Record);
                }
                if let NativeLockKind::Hash { refund_height, .. } = kind
                    && refund_height <= created_height
                {
                    return Err(NativeError::Time);
                }
                Self::Lock(NativeLock {
                    context,
                    trade,
                    contract,
                    generation,
                    sender,
                    recipient,
                    amount,
                    created_height,
                    kind,
                })
            }
            1 => {
                array(&mut d, 4)?;
                Self::Consumed {
                    context: context(&mut d)?,
                    offer: native_fixed(&mut d)?,
                    trade: native_fixed(&mut d)?,
                    contract: native_fixed(&mut d)?,
                }
            }
            2 => {
                array(&mut d, 3)?;
                Self::Applied {
                    wire_hash: native_fixed(&mut d)?,
                    height: uint(&mut d)?,
                    fee_atoms: uint(&mut d)?,
                }
            }
            3 => {
                array(&mut d, 2)?;
                let context = context(&mut d)?;
                let current = decode_destination(&mut d)?;
                validate_destination(&current)?;
                Self::Treasury { context, current }
            }
            5 => {
                array(&mut d, 3)?;
                let context = context(&mut d)?;
                let treasury = native_fixed(&mut d)?;
                let destination = decode_destination(&mut d)?;
                validate_destination(&destination)?;
                if id != treasury_generation_id(treasury, destination.generation) {
                    return Err(NativeError::Record);
                }
                Self::TreasuryGeneration {
                    context,
                    treasury,
                    destination,
                }
            }
            6 => {
                array(&mut d, 4)?;
                let context = context(&mut d)?;
                let treasury = native_fixed(&mut d)?;
                let address = native_fixed(&mut d)?;
                let generation = uint(&mut d)?;
                if generation == 0 || id != treasury_address_id(treasury, address) {
                    return Err(NativeError::Record);
                }
                Self::TreasuryAddress {
                    context,
                    treasury,
                    address,
                    generation,
                }
            }
            4 => {
                array(&mut d, 8)?;
                Self::License {
                    context: context(&mut d)?,
                    generation: uint(&mut d)?,
                    owner: native_fixed(&mut d)?,
                    previous_owner: native_fixed(&mut d)?,
                    transfer: native_fixed(&mut d)?,
                    inclusion_height: uint(&mut d)?,
                    rights_from_height: uint(&mut d)?,
                    assignment_sequence: uint(&mut d)?,
                }
            }
            _ => return Err(NativeError::Codec),
        };
        if d.position() != raw.len() || r.encode(id)? != raw {
            return Err(NativeError::Codec);
        }
        Ok((id, r))
    }
}
fn encode_destination(e: &mut Encoder<Vec<u8>>, t: &TreasuryDestination) {
    e.array(4)
        .unwrap()
        .u64(t.generation)
        .unwrap()
        .bytes(&t.address)
        .unwrap()
        .bytes(&t.descriptor)
        .unwrap()
        .u64(t.effective_height)
        .unwrap();
}
fn decode_destination(d: &mut Decoder<'_>) -> NativeResult<TreasuryDestination> {
    array(d, 4)?;
    Ok(TreasuryDestination {
        generation: uint(d)?,
        address: native_fixed(d)?,
        descriptor: bytes(d)?.to_vec(),
        effective_height: uint(d)?,
    })
}
/// One destination in isolation: a non-zero address (P3, design 4.1 row 14), generation >= 1 and
/// the address is exactly the one derived from its hybrid descriptor. Ordering between
/// generations is checked where two are in hand.
fn validate_destination(t: &TreasuryDestination) -> NativeResult<()> {
    if t.address == [0; 32] {
        return Err(NativeError::Bounds);
    }
    let p = validate_descriptor(&t.descriptor)?;
    let (_, g) = mutiny_crypto_v2::PublicKey::decode_descriptor(&t.descriptor)
        .map_err(|_| NativeError::Codec)?;
    if t.generation == 0 || p.address_id(g).map_err(|_| NativeError::Codec)? != t.address {
        return Err(NativeError::Record);
    }
    Ok(())
}
/// Identity of generation `generation` of `treasury`.
pub fn treasury_generation_id(treasury: Hash, generation: u64) -> Hash {
    native_hash(
        b"treasury-generation",
        &[treasury.as_slice(), generation.to_be_bytes().as_slice()].concat(),
    )
}
/// Identity of the address-index entry of `address` within `treasury`.
pub fn treasury_address_id(treasury: Hash, address: Hash) -> Hash {
    native_hash(
        b"treasury-address",
        &[treasury.as_slice(), address.as_slice()].concat(),
    )
}
/// Genesis/test construction of generation one: head, generation record and address index.
/// Each rotation later adds exactly one generation record, one address entry and replaces the head.
pub fn treasury_genesis_records(
    context: &Context,
    treasury: Hash,
    descriptor: Vec<u8>,
) -> NativeResult<Vec<(Hash, Vec<u8>)>> {
    let p = validate_descriptor(&descriptor)?;
    let (_, g) = mutiny_crypto_v2::PublicKey::decode_descriptor(&descriptor)
        .map_err(|_| NativeError::Codec)?;
    let destination = TreasuryDestination {
        generation: 1,
        address: p.address_id(g).map_err(|_| NativeError::Codec)?,
        descriptor,
        effective_height: 0,
    };
    treasury_records(context, treasury, &destination, true)
}
fn treasury_records(
    context: &Context,
    treasury: Hash,
    destination: &TreasuryDestination,
    with_head: bool,
) -> NativeResult<Vec<(Hash, Vec<u8>)>> {
    let mut out = Vec::new();
    let gid = treasury_generation_id(treasury, destination.generation);
    out.push((
        record_key(5, gid),
        NativeRecord::TreasuryGeneration {
            context: context.clone(),
            treasury,
            destination: destination.clone(),
        }
        .encode(gid)?,
    ));
    let aid = treasury_address_id(treasury, destination.address);
    out.push((
        record_key(6, aid),
        NativeRecord::TreasuryAddress {
            context: context.clone(),
            treasury,
            address: destination.address,
            generation: destination.generation,
        }
        .encode(aid)?,
    ));
    if with_head {
        out.push((
            record_key(3, treasury),
            NativeRecord::Treasury {
                context: context.clone(),
                current: destination.clone(),
            }
            .encode(treasury)?,
        ));
    }
    Ok(out)
}
fn treasury_generation_opt(
    state: &State,
    context: &Context,
    treasury: Hash,
    generation: u64,
) -> NativeResult<Option<TreasuryDestination>> {
    if generation == 0 {
        return Err(NativeError::Missing);
    }
    let id = treasury_generation_id(treasury, generation);
    let Some(raw) = state.protocol_records.get(&record_key(5, id)) else {
        return Ok(None);
    };
    let (found, r) = NativeRecord::decode(raw)?;
    let NativeRecord::TreasuryGeneration {
        context: c,
        treasury: t,
        destination,
    } = r
    else {
        return Err(NativeError::Record);
    };
    if found != id || t != treasury || destination.generation != generation {
        return Err(NativeError::Record);
    }
    if c != *context {
        return Err(NativeError::Context);
    }
    Ok(Some(destination))
}
/// O(1) lookup of one generation. A generation is never discarded because its balance or reserve
/// is zero: a frozen trade or an unclaimed award may still settle to it.
pub fn treasury_generation(
    state: &State,
    context: &Context,
    treasury: Hash,
    generation: u64,
) -> NativeResult<TreasuryDestination> {
    treasury_generation_opt(state, context, treasury, generation)?.ok_or(NativeError::Missing)
}
/// The latest generation (the head record).
pub fn treasury_current(
    state: &State,
    context: &Context,
    treasury: Hash,
) -> NativeResult<TreasuryDestination> {
    let (id, r) = NativeRecord::decode(
        state
            .protocol_records
            .get(&record_key(3, treasury))
            .ok_or(NativeError::Missing)?,
    )?;
    let NativeRecord::Treasury { context: c, current } = r else {
        return Err(NativeError::Record);
    };
    if id != treasury || c != *context {
        return Err(NativeError::Context);
    }
    Ok(current)
}
/// Audit/test view: every generation, oldest first. Consensus never walks the history.
pub fn treasury_generations(
    state: &State,
    context: &Context,
    treasury: Hash,
) -> NativeResult<Vec<TreasuryDestination>> {
    let head = treasury_current(state, context, treasury)?;
    (1..=head.generation)
        .map(|g| treasury_generation(state, context, treasury, g))
        .collect()
}
/// Structural and cross-record validation of one Treasury record, constant work per record.
/// P6 (Order of 4 Oct 2026; P-LANE-DESIGN-V1 7.1): the one canonical MUT Treasury authority T, the
/// generation-one AddressID of the Genesis-authenticated Treasury descriptor
/// (`state.dividends.treasury().authority()`), with that descriptor and T's wallet lineage (every
/// address the WalletBook records under authority T, plus T). `None` when dividends are inactive:
/// then no trading Treasury record may exist and no Treasury operation is valid.
struct TreasuryAuthority {
    authority: Hash,
    descriptor: Vec<u8>,
    lineage: BTreeMap<Hash, Vec<u8>>,
}
fn treasury_authority(state: &State) -> Option<TreasuryAuthority> {
    let t = state.dividends.treasury()?;
    Some(TreasuryAuthority {
        authority: t.authority(),
        descriptor: t.descriptor().to_vec(),
        lineage: state.treasury_owner_set().into_iter().filter_map(|address| {
            state.wallets.registered_descriptor(address).map(|raw| (address, raw.to_vec()))
        }).collect(),
    })
}
/// P6 (design 7.2): a trading Treasury head, generation or address record names T. Generation 1
/// carries exactly the Genesis descriptor (address T); every generation >= 2 carries a destination
/// whose address the WalletBook records under authority T (an address of T's lineage other than T,
/// so it was registered by a rotation of T, R1); `validate_destination` binds that address to the
/// descriptor. `Record` otherwise, including any Treasury record while dividends are inactive.
fn validate_treasury_binding(
    authority: Option<&TreasuryAuthority>,
    treasury: Hash,
    destination: Option<&TreasuryDestination>,
) -> NativeResult<()> {
    let t = authority.ok_or(NativeError::Record)?;
    if treasury != t.authority {
        return Err(NativeError::Record);
    }
    if let Some(d) = destination {
        validate_destination(d)?;
        let bound = if d.generation == 1 {
            d.address == t.authority && d.descriptor == t.descriptor
        } else {
            // Compare the descriptor recorded for THIS historical address, never today's
            // signing descriptor. R2 routing generations and wallet-key generations are
            // distinct counters; several R1 changes can precede the next R2.
            d.address != t.authority && t.lineage.get(&d.address) == Some(&d.descriptor)
        };
        if !bound {
            return Err(NativeError::Record);
        }
    }
    Ok(())
}
fn validate_treasury_record(
    state: &State,
    context: &Context,
    id: Hash,
    r: &NativeRecord,
    authority: Option<&TreasuryAuthority>,
) -> NativeResult<()> {
    match r {
        NativeRecord::Treasury { current, .. } => validate_treasury_binding(authority, id, Some(current))?,
        NativeRecord::TreasuryGeneration { treasury, destination, .. } => {
            validate_treasury_binding(authority, *treasury, Some(destination))?
        }
        NativeRecord::TreasuryAddress { treasury, .. } => validate_treasury_binding(authority, *treasury, None)?,
        _ => {}
    }
    match r {
        NativeRecord::Treasury { current, .. } => {
            let stored = treasury_generation(state, context, id, current.generation)?;
            if stored != *current {
                return Err(NativeError::Record);
            }
            // The head is the LATEST generation: nothing exists beyond it.
            if treasury_generation_opt(state, context, id, current.generation + 1)?.is_some() {
                return Err(NativeError::Record);
            }
        }
        NativeRecord::TreasuryGeneration {
            treasury,
            destination,
            ..
        } => {
            let head = treasury_current(state, context, *treasury)?;
            if destination.generation > head.generation {
                return Err(NativeError::Record);
            }
            if destination.generation > 1 {
                let previous =
                    treasury_generation(state, context, *treasury, destination.generation - 1)?;
                if previous.effective_height >= destination.effective_height
                    || previous.address == destination.address
                {
                    return Err(NativeError::Record);
                }
            }
            let aid = treasury_address_id(*treasury, destination.address);
            let (found, entry) = NativeRecord::decode(
                state
                    .protocol_records
                    .get(&record_key(6, aid))
                    .ok_or(NativeError::Missing)?,
            )?;
            let NativeRecord::TreasuryAddress { generation, .. } = entry else {
                return Err(NativeError::Record);
            };
            if found != aid || generation != destination.generation {
                return Err(NativeError::Record);
            }
        }
        NativeRecord::TreasuryAddress {
            treasury,
            address,
            generation,
            ..
        } => {
            let d = treasury_generation(state, context, *treasury, *generation)?;
            if d.address != *address {
                return Err(NativeError::Record);
            }
        }
        _ => {}
    }
    Ok(())
}
pub fn record_key(tag: u8, id: Hash) -> Hash {
    native_hash(b"record", &[&[tag], id.as_slice()].concat())
}
/// Shared State restoration must reserve this prefix, including malformed tags.
pub fn is_candidate_record(raw: &[u8]) -> bool {
    let mut d = Decoder::new(raw);
    // Classification is deliberately permissive about encoding. The strict
    // decoder rejects indefinite/nonminimal forms after the namespace has been
    // reserved; such objects must never fall through as opaque state.
    if d.array().is_err() {
        return false;
    }
    let Ok(parts) = d.bytes_iter() else {
        return false;
    };
    let mut matched = 0usize;
    for part in parts {
        let Ok(part) = part else {
            return matched == NATIVE_NAMESPACE.len();
        };
        let Some(end) = matched.checked_add(part.len()) else {
            return false;
        };
        if end > NATIVE_NAMESPACE.len() || NATIVE_NAMESPACE[matched..end] != *part {
            return false;
        }
        matched = end;
    }
    matched == NATIVE_NAMESPACE.len()
}
fn validate_license_transfer_record(
    state: &State,
    context: &Context,
    id: Hash,
    raw: &[u8],
) -> NativeResult<()> {
    let (found, record) = NativeRecord::decode(raw)?;
    let NativeRecord::License {
        context: bound_context,
        owner,
        assignment_sequence,
        ..
    } = record
    else {
        return Err(NativeError::Record);
    };
    let license = state.licenses_v2.license(id).ok_or(NativeError::Missing)?;
    if found != id || bound_context != *context || license.genesis != context.genesis {
        return Err(NativeError::Context);
    }
    if license.owner != owner
        || license.assignment_sequence < assignment_sequence
        || (license.assignment_sequence == assignment_sequence && license.active_worker.is_some())
    {
        return Err(NativeError::Record);
    }
    Ok(())
}
pub fn validate_records(state: &State, context: &Context) -> NativeResult<()> {
    // The coordinated Book hook permits an unassigned historical Worker
    // generation only with an authenticated native ownership-transfer record.
    for raw in state
        .licenses_v2
        .records()
        .map_err(|_| NativeError::Record)?
        .values()
    {
        let mut d = Decoder::new(raw);
        d.array().map_err(|_| NativeError::Record)?;
        if d.u8().map_err(|_| NativeError::Record)? == 2
            && d.u8().map_err(|_| NativeError::Record)? == 40
        {
            let l =
                crate::licenses::LicenseRecord::decode(d.bytes().map_err(|_| NativeError::Record)?)
                    .map_err(|_| NativeError::Record)?;
            if l.genesis != context.genesis {
                return Err(NativeError::Record);
            }
            // A known License reserves its transfer key even if the bytes at
            // that key do not classify as candidate data. Opaque values cannot
            // satisfy the detached-Worker restoration invariant.
            match state.protocol_records.get(&record_key(4, l.id)) {
                Some(raw) => validate_license_transfer_record(state, context, l.id, raw)?,
                None if l.active_worker.is_none() && l.assignment_sequence != 0 => {
                    return Err(NativeError::Record);
                }
                None => {}
            }
        }
    }
    // P6: computed once per validation (the lineage scan is linear in the WalletBook).
    let authority = treasury_authority(state);
    for (key, raw) in &state.protocol_records {
        if !is_candidate_record(raw) {
            continue;
        }
        let (id, r) = NativeRecord::decode(raw)?;
        if record_key(r.tag(), id) != *key {
            return Err(NativeError::Record);
        }
        let c = match &r {
            NativeRecord::Lock(l) => Some(&l.context),
            NativeRecord::Consumed { context, .. }
            | NativeRecord::Treasury { context, .. }
            | NativeRecord::TreasuryGeneration { context, .. }
            | NativeRecord::TreasuryAddress { context, .. }
            | NativeRecord::License { context, .. } => Some(context),
            _ => None,
        };
        if c.is_some_and(|c| c != context) {
            return Err(NativeError::Context);
        }
        if matches!(r, NativeRecord::License { .. }) {
            validate_license_transfer_record(state, context, id, raw)?;
        }
        validate_treasury_record(state, context, id, &r, authority.as_ref())?;
        if let NativeRecord::Consumed { context, offer, .. } = &r
            && id != single_fill_key(context, [0; 32], *offer)
        {
            return Err(NativeError::Record);
        }
    }
    Ok(())
}
fn insert(state: &mut State, id: Hash, r: NativeRecord) -> NativeResult<()> {
    let key = record_key(r.tag(), id);
    if state.protocol_records.contains_key(&key) {
        return Err(NativeError::Duplicate);
    }
    state.protocol_records.insert(key, r.encode(id)?);
    Ok(())
}
pub fn locked(state: &State, id: Hash) -> NativeResult<NativeLock> {
    let raw = state
        .protocol_records
        .get(&record_key(0, id))
        .ok_or(NativeError::Missing)?;
    let (found, r) = NativeRecord::decode(raw)?;
    if found != id {
        return Err(NativeError::Record);
    }
    if let NativeRecord::Lock(l) = r {
        Ok(l)
    } else {
        Err(NativeError::Record)
    }
}
pub fn verify_lock_proof(
    raw: &[u8],
    anchor: &FinalizedAnchor,
    root: Hash,
    id: Hash,
) -> NativeResult<NativeLock> {
    let p = crate::state_tree::StateProof::decode_bounded(
        raw,
        MAX_NATIVE_RECORD + 9 * 1024,
        MAX_NATIVE_RECORD,
    )
    .map_err(|_| NativeError::Record)?;
    let r = p
        .verify(anchor, root, record_key(0, id))
        .map_err(|_| NativeError::Context)?
        .ok_or(NativeError::Missing)?;
    let (found, r) = NativeRecord::decode(r)?;
    if found != id {
        return Err(NativeError::Context);
    }
    let NativeRecord::Lock(l) = r else {
        return Err(NativeError::Record);
    };
    if l.context.network != anchor.network
        || l.context.genesis != anchor.genesis
        || l.context.fingerprint != anchor.fingerprint
        || l.created_height > anchor.height
    {
        return Err(NativeError::Context);
    }
    Ok(l)
}
/// Read-only: the License generation a `LicenseDvp` for `license` must name in its
/// `license_generation` field: the generation recorded by the License's last native transfer, or 1
/// while it has never been transferred. This is the lookup `apply_one` performs; it grants no
/// authority and changes nothing. `Missing` if `state` has no such License, `Record` if the
/// License's transfer key holds a record of another kind.
pub fn license_generation(state: &State, license: Hash) -> NativeResult<u64> {
    state
        .licenses_v2
        .license(license)
        .ok_or(NativeError::Missing)?;
    match state.protocol_records.get(&record_key(4, license)) {
        Some(raw) => match NativeRecord::decode(raw)?.1 {
            NativeRecord::License { generation, .. } => Ok(generation),
            _ => Err(NativeError::Record),
        },
        None => Ok(1),
    }
}
/// Which checks `apply_one` runs. Block execution and every consensus entry point use `Full`;
/// `StateOnly` (amendment AM-1(d)) skips exactly the cryptographic signature verifications that
/// `verify_signatures` performs statelessly, and is reachable only through `verify_state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Verification {
    Full,
    StateOnly,
}
fn authorize(
    wallets: &WalletBook,
    op: &Operation,
    slot: u8,
    address: Hash,
    verification: Verification,
) -> NativeResult<()> {
    let a = op
        .approvals
        .iter()
        .find(|a| a.slot == slot)
        .ok_or(NativeError::Authority)?;
    wallets
        .authorize(address, &a.descriptor)
        .map_err(|_| NativeError::Authority)?;
    if verification == Verification::StateOnly {
        return Ok(());
    }
    verify_approval_signature(op, a)
}
/// The stateless part of an approval: its BOTH_REQUIRED hybrid signature under its own
/// descriptor over `signing_payload(slot, descriptor)`. Whether that descriptor is the current
/// authority of the slot's address is state (`WalletBook::authorize`).
fn verify_approval_signature(op: &Operation, a: &Approval) -> NativeResult<()> {
    validate_descriptor(&a.descriptor)?
        .verify(
            Domain::Transaction,
            &op.signing_payload(a.slot, &a.descriptor)?,
            &a.signature,
        )
        .map_err(|_| NativeError::Authority)
}
/// Verification only: it signs nothing and takes no key. Confirms that `op` carries an approval
/// for `slot` that consensus accepts: the approval's descriptor is the current wallet authority
/// in `wallets` of the address `op.slot_address(slot)`, and its BOTH_REQUIRED hybrid signature
/// verifies over `op.signing_payload(slot, descriptor)`. This is the `authorize` step of
/// `prepare_batch`, which reads the parent State's WalletBook; pass the verified parent State's
/// `wallets`. A TreasuryRotate's approval must also hash to the operation's `current_descriptor`,
/// exactly as `prepare_batch` requires. `Authority` when the slot is not used by the action or
/// the approval is absent, stale or invalid.
pub fn verify_approval(wallets: &WalletBook, op: &Operation, slot: u8) -> NativeResult<()> {
    let address = op.slot_address(slot).ok_or(NativeError::Authority)?;
    authorize(wallets, op, slot, address, Verification::Full)?;
    if let Action::TreasuryRotate {
        current_descriptor, ..
    } = &op.action
    {
        let a = op
            .approvals
            .iter()
            .find(|a| a.slot == slot)
            .ok_or(NativeError::Authority)?;
        if descriptor_hash(&a.descriptor) != *current_descriptor {
            return Err(NativeError::Authority);
        }
    }
    Ok(())
}
/// Debits the operation's inputs for `principal + change + fee`. P9 (Order of 4 Oct 2026;
/// P-LANE-DESIGN-V1 10.1): every input must be owned by an address that the approval descriptor of
/// the payer's slot authorizes under the PARENT WalletBook (`WalletBook::authorize`): any
/// authenticated generation of the payer's wallet lineage, whose CURRENT descriptor that approval
/// is (the caller has already authorized the payer's own address with it). An unrelated wallet's
/// address never passes, nor does an address of the payer's lineage under a rotated-out key.
/// Amounts, maturity and exact conservation are unchanged.
fn debit(
    state: &mut State,
    authority: &WalletBook,
    wire: &NativeOperation,
    payer_slot: u8,
    principal: Strikes,
    change: Strikes,
    height: u64,
) -> NativeResult<()> {
    if wire.inputs.is_empty() {
        return Err(NativeError::Missing);
    }
    let payer = wire
        .operation
        .approvals
        .iter()
        .find(|a| a.slot == payer_slot)
        .ok_or(NativeError::Authority)?;
    let mut total = 0u128;
    for p in &wire.inputs {
        let c = state.coins.get(p).ok_or(NativeError::Missing)?;
        authority
            .authorize(c.output.owner, &payer.descriptor)
            .map_err(|_| NativeError::Authority)?;
        if c.created_height >= height
            || c.coinbase
                && height
                    .checked_sub(c.created_height)
                    .ok_or(NativeError::Time)?
                    < MATURITY
        {
            return Err(NativeError::Immature);
        }
        total = total
            .checked_add(c.output.atoms as u128)
            .ok_or(NativeError::Overflow)?;
    }
    if total != principal.0 as u128 + change.0 as u128 + wire.operation.meta.fee.0 as u128 {
        return Err(NativeError::Conservation);
    }
    for p in &wire.inputs {
        state.coins.remove(p);
    }
    Ok(())
}
fn credit(
    state: &mut State,
    op: &Operation,
    index: u32,
    owner: Hash,
    amount: Strikes,
    height: u64,
) -> NativeResult<()> {
    // P3 defensive check at every credit site (design 4.3): the codec already refuses a zero
    // destination, so this never fires for a decoded operation; a zero owner is refused, never
    // credited as a burn, whatever the amount.
    if owner == [0; 32] {
        return Err(NativeError::Bounds);
    }
    if amount.0 == 0 {
        return Ok(());
    }
    let p = OutPoint {
        transaction: op.id()?,
        index,
    };
    if state.coins.contains_key(&p) {
        return Err(NativeError::Duplicate);
    }
    state.coins.insert(
        p,
        Coin {
            output: Output {
                owner,
                atoms: amount.0,
            },
            created_height: height,
            coinbase: false,
        },
    );
    Ok(())
}
fn consume(
    state: &mut State,
    op: &Operation,
    offer: Hash,
    height: u64,
    verification: Verification,
) -> NativeResult<()> {
    op.check_offer(height, verification == Verification::Full)?;
    insert(
        state,
        single_fill_key(&op.meta.context, [0; 32], offer),
        NativeRecord::Consumed {
            context: op.meta.context.clone(),
            offer,
            trade: op.meta.trade,
            contract: op.meta.contract,
        },
    )
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeReceipt {
    pub operation: Hash,
    pub wire_hash: Hash,
    pub height: u64,
    pub fee_atoms: u64,
}
pub fn reconcile(state: &State, raw: &[u8]) -> NativeResult<Option<NativeReceipt>> {
    let w = NativeOperation::decode(raw)?;
    let id = w.operation.id()?;
    let Some(record) = state.protocol_records.get(&record_key(2, id)) else {
        return Ok(None);
    };
    let (found, r) = NativeRecord::decode(record)?;
    let NativeRecord::Applied {
        wire_hash,
        height,
        fee_atoms,
    } = r
    else {
        return Err(NativeError::Record);
    };
    if found != id || wire_hash != native_hash(b"signed", raw) {
        return Err(NativeError::Conflict);
    }
    Ok(Some(NativeReceipt {
        operation: id,
        wire_hash,
        height,
        fee_atoms,
    }))
}
/// Pure native-state result; only host canonical execution/finality may commit it.
#[derive(Debug)]
pub struct Prepared {
    state: State,
    root: Hash,
    fees: u64,
    receipts: Vec<NativeReceipt>,
}
impl Prepared {
    pub fn state(&self) -> &State {
        &self.state
    }
    pub fn root(&self) -> Hash {
        self.root
    }
    pub fn fee_atoms(&self) -> u64 {
        self.fees
    }
    pub fn receipts(&self) -> &[NativeReceipt] {
        &self.receipts
    }
    pub fn into_state(self) -> State {
        self.state
    }
}
/// No finality or admission authority is granted by a caller-constructed anchor.
/// Host must source the exact parent/root from CanonicalStore's authenticated view.
/// Without a History it can only include operations whose envelope references the parent
/// itself: any older reference fails closed (`Envelope(ReferenceNotCanonical)`, design 1.a.3).
pub fn prepare_batch(
    parent_state: &State,
    parent: &FinalizedAnchor,
    parent_root: Hash,
    operations: &[Vec<u8>],
    policy: &CandidatePolicy,
) -> NativeResult<Prepared> {
    prepare_batch_with_history(
        parent_state,
        parent,
        parent_root,
        &History::default(),
        operations,
        policy,
    )
}
/// `prepare_batch` with the canonical block hashes of the heights the operations' envelopes
/// reference (`History` anchors). The History must come from the local canonical store, never
/// from a peer (design 1.a.3).
pub fn prepare_batch_with_history(
    parent_state: &State,
    parent: &FinalizedAnchor,
    parent_root: Hash,
    history: &History,
    operations: &[Vec<u8>],
    policy: &CandidatePolicy,
) -> NativeResult<Prepared> {
    prepare_candidate_phase(
        parent_state,
        parent_state,
        parent,
        parent_root,
        history,
        operations,
        policy,
    )
}
/// AM-1(d), stateless half: decodes `raw` and verifies every cryptographic signature it carries
/// (each wallet approval under its own descriptor, the maker's offer signature and fill
/// signature) and that the approval slots are exactly the action's set. It reads no state:
/// whether each approval's descriptor is the CURRENT authority of its slot's address is state and
/// is checked by `verify_state` (and by every full verification).
pub fn verify_signatures(raw: &[u8]) -> NativeResult<()> {
    let wire = NativeOperation::decode(raw)?;
    let op = &wire.operation;
    if op.approvals.iter().map(|a| a.slot).collect::<BTreeSet<_>>() != op.expected_slots() {
        return Err(NativeError::Authority);
    }
    for a in &op.approvals {
        verify_approval_signature(op, a)?;
    }
    op.verify_offer_signatures()?;
    Ok(())
}
/// AM-1(d), state-only half: every check `prepare_batch_with_history` makes for inclusion at
/// `parent.height + 1` EXCEPT the signature verifications of `verify_signatures` (window,
/// reference, preconditions, fee, replay, slot authority under the parent WalletBook, offer terms
/// and single fill, inputs, amounts and every action rule). NEVER a consensus path: block
/// execution always verifies everything. A pool may use it only for the exact bytes (same
/// operation id and wire hash) whose `verify_signatures` it has already recorded as passed.
pub fn verify_state(
    parent_state: &State,
    parent: &FinalizedAnchor,
    parent_root: Hash,
    history: &History,
    raw: &[u8],
    policy: &CandidatePolicy,
) -> NativeResult<()> {
    prepare_phase(
        parent_state,
        parent_state,
        parent,
        parent_root,
        history,
        &[raw.to_vec()],
        policy,
        Verification::StateOnly,
    )
    .map(|_| ())
}
/// Pool preview at the expected containing block epoch. Due activations and dividend
/// boundaries are processed on a clone; authority still comes from committed parent state.
pub fn verify_state_at_epoch(
    parent_state: &State, parent: &FinalizedAnchor, parent_root: Hash,
    history: &History, raw: &[u8], policy: &CandidatePolicy, epoch: u64,
) -> NativeResult<()> {
    let mut tentative = parent_state.clone();
    tentative.licenses_v2.activate_due(epoch).map_err(|_|NativeError::Record)?;
    tentative.advance_dividends(epoch).map_err(|_|NativeError::Record)?;
    prepare_phase(parent_state, &tentative, parent, parent_root, history,
        &[raw.to_vec()], policy, Verification::StateOnly).map(|_| ())
}
/// AM-3: the DECLARED fee of a trading item (decode only; no state, no signature). The assembler
/// previews it; the complete trial execution validates it (`max(240, len)`, conservation), so a
/// preview never executes trades on the parent state and never rejects a valid sale.
pub fn declared_fee(raw: &[u8]) -> NativeResult<u64> {
    Ok(NativeOperation::decode(raw)?.operation.meta.fee.0)
}
/// The operation envelope a trading item carries (reference extraction, design 1.a.3), or None
/// when `raw` is not a well-formed trading item (execution then rejects it).
pub fn envelope_of(raw: &[u8]) -> Option<Envelope> {
    NativeOperation::decode(raw)
        .ok()
        .map(|w| w.operation.meta.envelope)
}
/// Executor hook after authorized work/lifecycle preparation, before ordinary
/// payments and coinbase. `tentative` is HOST-VALIDATED state, never peer input.
/// Spending authority remains the committed parent WalletBook. The host must
/// commit the complete block atomically and add returned fees exactly once.
/// `history` supplies the canonical block hashes of older envelope references (design 1.a.3).
pub fn prepare_candidate_phase(
    parent_state: &State,
    tentative: &State,
    parent: &FinalizedAnchor,
    parent_root: Hash,
    history: &History,
    operations: &[Vec<u8>],
    policy: &CandidatePolicy,
) -> NativeResult<Prepared> {
    prepare_phase(
        parent_state,
        tentative,
        parent,
        parent_root,
        history,
        operations,
        policy,
        Verification::Full,
    )
}
#[allow(clippy::too_many_arguments)]
fn prepare_phase(
    parent_state: &State,
    tentative: &State,
    parent: &FinalizedAnchor,
    parent_root: Hash,
    history: &History,
    operations: &[Vec<u8>],
    policy: &CandidatePolicy,
    verification: Verification,
) -> NativeResult<Prepared> {
    policy.check()?;
    if parent.network != crate::NETWORK_ID
        || parent.genesis == [0; 32]
        || parent.fingerprint == [0; 32]
        || parent_state.root().map_err(|_| NativeError::Record)? != parent_root
    {
        return Err(NativeError::Context);
    }
    if operations.is_empty() || operations.len() > MAX_BATCH {
        return Err(NativeError::Bounds);
    }
    // The inclusion height parent.height + 1 must exist; apply_one derives it per operation.
    parent.height.checked_add(1).ok_or(NativeError::Overflow)?;
    let context = Context {
        network: parent.network,
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
    };
    validate_records(parent_state, &context)?;
    validate_records(tentative, &context)?;
    let mut state = tentative.clone();
    let mut fees = 0u64;
    let mut receipts = Vec::new();
    for raw in operations {
        let receipt = apply_one(
            &mut state,
            &parent_state.wallets,
            &context,
            parent,
            history,
            raw,
            verification,
        )?;
        fees = fees
            .checked_add(receipt.fee_atoms)
            .ok_or(NativeError::Overflow)?;
        receipts.push(receipt);
    }
    validate_records(&state, &context)?;
    let root = state.root().map_err(|_| NativeError::Record)?;
    Ok(Prepared {
        state,
        root,
        fees,
        receipts,
    })
}
/// A precondition mismatch is `Stale(tag)`; any other envelope failure keeps its exact variant.
fn precondition_error(e: EnvelopeError) -> NativeError {
    match e {
        EnvelopeError::Stale(tag) => NativeError::Stale(tag),
        other => NativeError::Envelope(other),
    }
}
fn apply_one(
    state: &mut State,
    authority: &WalletBook,
    context: &Context,
    parent: &FinalizedAnchor,
    history: &History,
    raw: &[u8],
    verification: Verification,
) -> NativeResult<NativeReceipt> {
    let height = parent.height.checked_add(1).ok_or(NativeError::Overflow)?;
    let wire = NativeOperation::decode(raw)?;
    let op = &wire.operation;
    let m = &op.meta;
    if &m.context != context {
        return Err(NativeError::Context);
    }
    // Replay identity is the Applied record of the operation id (design 1.a.8), never the window:
    // the same reviewed bytes stay applied once whatever their window still allows.
    if state
        .protocol_records
        .contains_key(&record_key(2, op.id()?))
    {
        return Err(NativeError::Duplicate);
    }
    // P4 (design 1.a.2 and 1.a.5): the signed window W and the finalized reference R at the
    // inclusion height H = parent.height + 1, then every committed precondition P against `state`,
    // the tentative state at the trading validation point (after this block's epoch events and
    // Worker assignments and the earlier trading items of the block, before any claim). Head
    // advancement alone never invalidates an otherwise unchanged operation; nothing is re-based.
    m.envelope
        .check_inclusion(parent, history)
        .map_err(NativeError::Envelope)?;
    // P5 (design 6.1): a License sale must commit the sold License's remaining dividend rights
    // and assignment state (structural, `Bounds`); `check_preconditions` below is the sale-
    // validation point that compares them with the tentative state (design 6.2).
    let committed_pending = match &op.action {
        Action::LicenseDvp { license, .. } => sale_commitment(&m.envelope, *license)?,
        _ => None,
    };
    m.envelope
        .check_preconditions(state, context)
        .map_err(precondition_error)?;
    if m.fee.0 < 240u64.max(raw.len() as u64) {
        return Err(NativeError::Fee);
    }
    if op.approvals.iter().map(|a| a.slot).collect::<BTreeSet<_>>() != op.expected_slots() {
        return Err(NativeError::Authority);
    }
    op.check_offer(height, verification == Verification::Full)?;
    // Human takeover decision: first funding requires the maker's current
    // canonical authority at the existing trading phase, before payments.
    // Unfunded offers remain above consensus; old references prove no funding.
    // Claim/refund/release carry no offer proof and retain lock authority.
    if let Some(proof) = &op.offer_proof {
        authority.authorize(proof.offer.body.maker_wallet,
            &proof.offer.body.maker_descriptor).map_err(|_| NativeError::Authority)?;
    }
    match &op.action {
        Action::HashLock {
            offer,
            sender,
            recipient,
            amount,
            condition,
            refund_height,
            change,
            ..
        } => {
            // The refund height lies beyond the whole signed window (replaces `expiry < R` of
            // body version 1): the lock cannot be created at or after its own refund height.
            if amount.0 == 0 || sender == recipient || *refund_height <= m.envelope.last_height {
                return Err(NativeError::Bounds);
            }
            authorize(authority, op, 0, *sender, verification)?;
            authorize(authority, op, 1, *recipient, verification)?;
            debit(state, authority, &wire, 0, *amount, *change, height)?;
            consume(state, op, *offer, height, verification)?;
            insert(
                state,
                op.output_id(0)?,
                NativeRecord::Lock(NativeLock {
                    context: context.clone(),
                    trade: m.trade,
                    contract: m.contract,
                    generation: m.generation,
                    sender: *sender,
                    recipient: *recipient,
                    amount: *amount,
                    created_height: height,
                    kind: NativeLockKind::Hash {
                        condition: *condition,
                        refund_height: *refund_height,
                    },
                }),
            )?;
            credit(state, op, 1, *sender, *change, height)?;
        }
        Action::FiatLock {
            offer,
            seller,
            buyer,
            amount,
            payment_terms,
            change,
            ..
        } => {
            if amount.0 == 0 || seller == buyer {
                return Err(NativeError::Bounds);
            }
            authorize(authority, op, 0, *seller, verification)?;
            authorize(authority, op, 1, *buyer, verification)?;
            debit(state, authority, &wire, 0, *amount, *change, height)?;
            consume(state, op, *offer, height, verification)?;
            insert(
                state,
                op.output_id(0)?,
                NativeRecord::Lock(NativeLock {
                    context: context.clone(),
                    trade: m.trade,
                    contract: m.contract,
                    generation: m.generation,
                    sender: *seller,
                    recipient: *buyer,
                    amount: *amount,
                    created_height: height,
                    kind: NativeLockKind::Fiat {
                        terms: *payment_terms,
                    },
                }),
            )?;
            credit(state, op, 1, *seller, *change, height)?;
        }
        Action::Claim {
            output,
            recipient,
            amount,
            preimage,
            change,
        } => {
            let l = bound_lock(state, op, *output, *amount, height)?;
            let NativeLockKind::Hash {
                condition,
                refund_height,
            } = l.kind
            else {
                return Err(NativeError::FiatRecoveryUnspecified);
            };
            if *recipient != l.recipient || preimage_hash(preimage) != condition {
                return Err(NativeError::Authority);
            }
            if height >= refund_height {
                return Err(NativeError::Time);
            }
            authorize(authority, op, 0, *recipient, verification)?;
            // The fee may come from the recipient's lineage; the payout and the change go to the
            // lock's authorized recipient (design 10.3).
            debit(state, authority, &wire, 0, Strikes(0), *change, height)?;
            state.protocol_records.remove(&record_key(0, *output));
            credit(state, op, 0, *recipient, *amount, height)?;
            credit(state, op, 1, *recipient, *change, height)?;
        }
        Action::Refund {
            output,
            owner,
            amount,
            change,
        } => {
            let l = bound_lock(state, op, *output, *amount, height)?;
            let NativeLockKind::Hash { refund_height, .. } = l.kind else {
                return Err(NativeError::FiatRecoveryUnspecified);
            };
            if *owner != l.sender {
                return Err(NativeError::Authority);
            }
            if height < refund_height {
                return Err(NativeError::Time);
            }
            authorize(authority, op, 0, *owner, verification)?;
            debit(state, authority, &wire, 0, Strikes(0), *change, height)?;
            state.protocol_records.remove(&record_key(0, *output));
            credit(state, op, 0, *owner, *amount, height)?;
            credit(state, op, 1, *owner, *change, height)?;
        }
        Action::FiatRelease {
            output,
            buyer,
            seller,
            amount,
            payment_terms,
            change,
        } => {
            let l = bound_lock(state, op, *output, *amount, height)?;
            if l.kind
                != (NativeLockKind::Fiat {
                    terms: *payment_terms,
                })
                || l.recipient != *buyer
                || l.sender != *seller
            {
                return Err(NativeError::Context);
            }
            authorize(authority, op, 0, *buyer, verification)?;
            authorize(authority, op, 1, *seller, verification)?;
            debit(state, authority, &wire, 0, Strikes(0), *change, height)?;
            state.protocol_records.remove(&record_key(0, *output));
            credit(state, op, 0, *buyer, *amount, height)?;
            credit(state, op, 1, *buyer, *change, height)?;
        }
        Action::TreasuryRotate {
            treasury,
            current_generation,
            current_address,
            current_descriptor,
            new_generation,
            new_address,
            new_descriptor,
            change,
        } => {
            // R2-1 (P6, design 7.3): only the canonical Treasury authority T is rotated.
            let t = state
                .dividends
                .treasury()
                .map(|t| t.authority())
                .ok_or(NativeError::Authority)?;
            if *treasury != t {
                return Err(NativeError::Authority);
            }
            let key = record_key(3, *treasury);
            // O(1): the head is the latest generation. Immediate rotation: the finalized
            // inclusion height IS the effective boundary, and the head already includes any
            // earlier same-block rotation, so a competing successor naming the old generation
            // fails deterministically.
            let active = treasury_current(state, context, *treasury)?;
            if active.effective_height > height {
                return Err(NativeError::Time);
            }
            if active.generation != *current_generation
                || active.address != *current_address
                || current_generation.checked_add(1) != Some(*new_generation)
            {
                return Err(NativeError::Context);
            }
            // R2-3: approval slot 0 is T's CURRENT descriptor under the parent WalletBook (the
            // generation-1 Genesis descriptor while T was never rotated), never the trading
            // address's key; `current_descriptor` names that descriptor.
            authorize(authority, op, 0, t, verification)?;
            if descriptor_hash(&op.approvals[0].descriptor) != *current_descriptor {
                return Err(NativeError::Authority);
            }
            // R2-4: the new destination is T's current wallet generation (registered by R1), so
            // an unrelated fresh generation-one key can never be routed to. Its address is
            // derived from the descriptor (`validate_destination`) and unused (below).
            if authority.current(t) != Some(new_descriptor.as_slice()) {
                return Err(NativeError::Authority);
            }
            let successor = TreasuryDestination {
                generation: *new_generation,
                address: *new_address,
                descriptor: new_descriptor.clone(),
                effective_height: height,
            };
            validate_destination(&successor)?;
            // Strictly later than the previous generation, and an address is used once.
            if active.effective_height >= height {
                return Err(NativeError::Record);
            }
            if state
                .protocol_records
                .contains_key(&record_key(6, treasury_address_id(*treasury, *new_address)))
            {
                return Err(NativeError::Record);
            }
            // Exactly three record writes whatever the history length: the new generation, its
            // address entry and the replaced head. All-or-nothing with the rest of the block
            // because `state` is the tentative copy that a failing operation discards.
            for (record_key_, raw) in treasury_records(context, *treasury, &successor, false)? {
                if state.protocol_records.insert(record_key_, raw).is_some() {
                    return Err(NativeError::Duplicate);
                }
            }
            let encoded = NativeRecord::Treasury {
                context: context.clone(),
                current: successor,
            }
            .encode(*treasury)?;
            debit(state, authority, &wire, 0, Strikes(0), *change, height)?;
            state.protocol_records.insert(key, encoded);
            credit(state, op, 0, *current_address, *change, height)?;
        }
        Action::LicenseDvp {
            offer,
            license,
            license_generation,
            seller,
            buyer,
            price,
            payment_destination,
            change,
            ..
        } => {
            // The exact `effective_height == H` rule of body version 1 is replaced by the signed
            // window (design 5.1); the transfer is recorded at the actual inclusion height H.
            if price.0 == 0 || seller == buyer {
                return Err(NativeError::Bounds);
            }
            let l = state
                .licenses_v2
                .license(*license)
                .ok_or(NativeError::Missing)?;
            if l.genesis != context.genesis || l.owner != *seller {
                return Err(NativeError::Authority);
            }
            let generation = match state.protocol_records.get(&record_key(4, *license)) {
                Some(raw) => {
                    let (_, record) = NativeRecord::decode(raw)?;
                    let NativeRecord::License {
                        generation,
                        rights_from_height,
                        ..
                    } = record
                    else {
                        return Err(NativeError::Record);
                    };
                    if rights_from_height > height {
                        return Err(NativeError::Time);
                    }
                    generation
                }
                None => 1,
            };
            if generation != *license_generation {
                return Err(NativeError::Conflict);
            }
            authorize(authority, op, 0, *seller, verification)?;
            authorize(authority, op, 1, *buyer, verification)?;
            let request = VerifiedLicenseTransferCandidate {
                license: *license,
                genesis: context.genesis,
                from: *seller,
                to: *buyer,
                expected_assignment_sequence: l.assignment_sequence,
                new_assignment_sequence: l
                    .assignment_sequence
                    .checked_add(1)
                    .ok_or(NativeError::Overflow)?,
                inclusion_height: height,
                rights_from_height: height.checked_add(1).ok_or(NativeError::Overflow)?,
                operation: op.id()?,
                trade: m.trade,
                contract: m.contract,
                generation,
                payment_commitment: native_hash(b"license-payment", raw),
            };
            // This operation does not create a transferable License lock. Any
            // future License-lock primitive must join the host Book's exclusion
            // check before activation. A pending old-owner assignment is cancelled
            // only when it is exactly the one the sale committed (design 6.6).
            transfer_license_candidate(&mut state.licenses_v2, &request, committed_pending)?;
            debit(state, authority, &wire, 1, *price, *change, height)?;
            consume(state, op, *offer, height, verification)?;
            let record = NativeRecord::License {
                context: context.clone(),
                generation: generation.checked_add(1).ok_or(NativeError::Overflow)?,
                owner: *buyer,
                previous_owner: *seller,
                transfer: request.operation,
                inclusion_height: height,
                rights_from_height: request.rights_from_height,
                assignment_sequence: request.new_assignment_sequence,
            };
            state
                .protocol_records
                .insert(record_key(4, *license), record.encode(*license)?);
            credit(state, op, 0, *payment_destination, *price, height)?;
            credit(state, op, 1, *buyer, *change, height)?;
        }
    }
    let r = NativeReceipt {
        operation: op.id()?,
        wire_hash: native_hash(b"signed", raw),
        height,
        fee_atoms: m.fee.0,
    };
    insert(
        state,
        r.operation,
        NativeRecord::Applied {
            wire_hash: r.wire_hash,
            height,
            fee_atoms: r.fee_atoms,
        },
    )?;
    Ok(r)
}
fn bound_lock(
    state: &State,
    op: &Operation,
    id: Hash,
    amount: Strikes,
    height: u64,
) -> NativeResult<NativeLock> {
    let l = locked(state, id)?;
    if l.context != op.meta.context
        || l.trade != op.meta.trade
        || l.contract != op.meta.contract
        || l.generation != op.meta.generation
        || l.amount != amount
    {
        return Err(NativeError::Context);
    }
    if l.created_height >= height {
        return Err(NativeError::Time);
    }
    Ok(l)
}

#[cfg(test)]
#[path = "trading_v1_tests.rs"]
mod tests;
#[cfg(test)]
#[path = "trading_dvp_entitlements_tests.rs"]
mod dvp_entitlements_tests;

/// Opaque capability for the coordinated native Book hook. Only the DvP
/// validator constructs it after exact parent wallet/offer authorization.
/// Host still validates current owner/sequence/pending assignment atomically.
#[derive(Debug)]
pub(crate) struct VerifiedLicenseTransferCandidate {
    license: Hash,
    genesis: Hash,
    from: Hash,
    to: Hash,
    expected_assignment_sequence: u64,
    new_assignment_sequence: u64,
    inclusion_height: u64,
    rights_from_height: u64,
    operation: Hash,
    trade: Hash,
    contract: Hash,
    generation: u64,
    payment_commitment: Hash,
}
impl VerifiedLicenseTransferCandidate {
    pub(crate) fn license(&self) -> Hash {
        self.license
    }
    pub(crate) fn genesis(&self) -> Hash {
        self.genesis
    }
    pub(crate) fn from(&self) -> Hash {
        self.from
    }
    pub(crate) fn to(&self) -> Hash {
        self.to
    }
    pub(crate) fn expected_assignment_sequence(&self) -> u64 {
        self.expected_assignment_sequence
    }
    pub(crate) fn new_assignment_sequence(&self) -> u64 {
        self.new_assignment_sequence
    }
    pub(crate) fn inclusion_height(&self) -> u64 {
        self.inclusion_height
    }
    pub(crate) fn rights_from_height(&self) -> u64 {
        self.rights_from_height
    }
    pub(crate) fn operation(&self) -> Hash {
        self.operation
    }
    pub(crate) fn trade(&self) -> Hash {
        self.trade
    }
    pub(crate) fn contract(&self) -> Hash {
        self.contract
    }
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn payment_commitment(&self) -> Hash {
        self.payment_commitment
    }
}
/// P5 (P-LANE-DESIGN-V1 6.1, 6.6): the envelope of a LicenseDvp carries exactly one
/// `LicenseEntitlements` and exactly one `LicenseAssignment` precondition, both naming the sold
/// License; anything else (either absent, a second one, one for another License) is `Bounds`.
/// Their equality with the facts at the sale-validation point is `Envelope::check_preconditions`
/// (`Stale(tag)`). Returns the committed pending assignment id, the only one the sale may cancel.
fn sale_commitment(envelope: &Envelope, license: Hash) -> NativeResult<Option<Hash>> {
    let (mut entitlements, mut assignments, mut pending) = (0usize, 0usize, None);
    for committed in &envelope.preconditions {
        match committed {
            Precondition::LicenseEntitlements { license: subject, .. } => {
                if *subject != license {
                    return Err(NativeError::Bounds);
                }
                entitlements += 1;
            }
            Precondition::LicenseAssignment {
                license: subject,
                pending: committed_pending,
                ..
            } => {
                if *subject != license {
                    return Err(NativeError::Bounds);
                }
                assignments += 1;
                pending = *committed_pending;
            }
            Precondition::TreasuryHead { .. } => {}
        }
    }
    if entitlements != 1 || assignments != 1 {
        return Err(NativeError::Bounds);
    }
    Ok(pending)
}
/// The Book cancels an old-owner pending assignment and returns its canonical id (Q17, Restart
/// Order L64). The cancelled id must EQUAL the committed `LicenseAssignment.pending` (design 6.6):
/// a mismatch is `Stale(2)` and leaves `book` untouched (no silent cancellation); any refusal of
/// the Book itself stays `LicenseLocked`.
fn transfer_license_candidate(
    book: &mut crate::license_book_v2::Book,
    request: &VerifiedLicenseTransferCandidate,
    committed_pending: Option<Hash>,
) -> NativeResult<()> {
    let mut next = book.clone();
    let cancelled = next
        .transfer_candidate(request)
        .map_err(|_| NativeError::LicenseLocked)?;
    if cancelled != committed_pending {
        return Err(NativeError::Stale(TAG_LICENSE_ASSIGNMENT));
    }
    *book = next;
    Ok(())
}

/// Public exact terms for Architect authorization. No private key enters this
/// object or node helper. Only explicitly nonproduction BTC environments qualify.
#[derive(Clone, Debug)]
pub struct TreasuryOfferRequest {
    pub treasury: Hash,
    pub generation: u64,
    pub address: Hash,
    pub trade: Hash,
    pub contract: Hash,
    pub offer: SignedOffer,
    pub wallet_descriptor: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct TreasuryFreezeBody {
    context: Context,
    anchor: FinalizedAnchor,
    root: Hash,
    treasury: Hash,
    generation: u64,
    address: Hash,
    trade: Hash,
    contract: Hash,
    offer: OfferBody,
    wallet_descriptor: Vec<u8>,
}
impl TreasuryFreezeBody {
    fn encode(&self) -> NativeResult<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(14)
            .unwrap()
            .bytes(NATIVE_NAMESPACE)
            .unwrap()
            .bytes(b"treasury-freeze")
            .unwrap()
            .u8(1)
            .unwrap();
        e.array(3)
            .unwrap()
            .u32(self.context.network)
            .unwrap()
            .bytes(&self.context.genesis)
            .unwrap()
            .bytes(&self.context.fingerprint)
            .unwrap();
        e.u64(self.anchor.height)
            .unwrap()
            .bytes(&self.anchor.block)
            .unwrap()
            .bytes(&self.root)
            .unwrap()
            .bytes(&self.treasury)
            .unwrap()
            .u64(self.generation)
            .unwrap()
            .bytes(&self.address)
            .unwrap()
            .bytes(&self.trade)
            .unwrap()
            .bytes(&self.contract)
            .unwrap()
            .bytes(&self.offer.encode()?)
            .unwrap()
            .bytes(&self.wallet_descriptor)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_NATIVE_RECORD {
            return Err(NativeError::Bounds);
        }
        Ok(raw)
    }
    fn decode(raw: &[u8]) -> NativeResult<Self> {
        if raw.len() > MAX_NATIVE_RECORD {
            return Err(NativeError::Bounds);
        }
        let mut d = Decoder::new(raw);
        array(&mut d, 14)?;
        if bytes(&mut d)? != NATIVE_NAMESPACE
            || bytes(&mut d)? != b"treasury-freeze"
            || uint(&mut d)? != 1
        {
            return Err(NativeError::Codec);
        }
        array(&mut d, 3)?;
        let context = Context {
            network: d.u32().map_err(|_| NativeError::Codec)?,
            genesis: native_fixed(&mut d)?,
            fingerprint: native_fixed(&mut d)?,
        };
        let anchor = FinalizedAnchor {
            network: context.network,
            genesis: context.genesis,
            fingerprint: context.fingerprint,
            height: uint(&mut d)?,
            block: native_fixed(&mut d)?,
        };
        let out = Self {
            context,
            anchor,
            root: native_fixed(&mut d)?,
            treasury: native_fixed(&mut d)?,
            generation: uint(&mut d)?,
            address: native_fixed(&mut d)?,
            trade: native_fixed(&mut d)?,
            contract: native_fixed(&mut d)?,
            offer: OfferBody::decode(bytes(&mut d)?)?,
            wallet_descriptor: bytes(&mut d)?.to_vec(),
        };
        if d.position() != raw.len() || out.encode()? != raw {
            return Err(NativeError::Codec);
        }
        Ok(out)
    }
}
#[derive(Debug)]
pub struct PreparedTreasuryOffer {
    body: TreasuryFreezeBody,
}
impl PreparedTreasuryOffer {
    pub fn signing_payload(&self) -> NativeResult<Vec<u8>> {
        self.body.encode()
    }
    /// Signature obtained outside the engine from the distinct MUT Treasury
    /// wallet. This is not a Bitcoin transaction-signing API.
    pub fn attach_authorization(
        self,
        signature: mutiny_crypto_v2::HybridSignature,
    ) -> NativeResult<FrozenTreasuryOffer> {
        let out = FrozenTreasuryOffer {
            body: self.body,
            signature,
        };
        out.verify_signature()?;
        Ok(out)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FrozenTreasuryOffer {
    body: TreasuryFreezeBody,
    signature: mutiny_crypto_v2::HybridSignature,
}
impl FrozenTreasuryOffer {
    pub fn trade(&self) -> Hash {
        self.body.trade
    }
    pub fn contract(&self) -> Hash {
        self.body.contract
    }
    pub fn offer(&self) -> &OfferBody {
        &self.body.offer
    }

    pub fn offer_id(&self) -> NativeResult<Hash> {
        Ok(self.body.offer.id()?)
    }
    pub fn treasury(&self) -> Hash {
        self.body.treasury
    }
    pub fn generation(&self) -> u64 {
        self.body.generation
    }
    pub fn address(&self) -> Hash {
        self.body.address
    }
    pub fn creation_anchor(&self) -> &FinalizedAnchor {
        &self.body.anchor
    }
    pub fn creation_root(&self) -> Hash {
        self.body.root
    }
    pub fn encode(&self) -> NativeResult<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(3)
            .unwrap()
            .bytes(&self.body.encode()?)
            .unwrap()
            .bytes(&self.signature.ed448)
            .unwrap()
            .bytes(&self.signature.fndsa)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_NATIVE_RECORD {
            return Err(NativeError::Bounds);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> NativeResult<Self> {
        if raw.len() > MAX_NATIVE_RECORD {
            return Err(NativeError::Bounds);
        }
        let mut d = Decoder::new(raw);
        array(&mut d, 3)?;
        let body = TreasuryFreezeBody::decode(bytes(&mut d)?)?;
        let signature = mutiny_crypto_v2::HybridSignature {
            ed448: bytes(&mut d)?.try_into().map_err(|_| NativeError::Codec)?,
            fndsa: bytes(&mut d)?.try_into().map_err(|_| NativeError::Codec)?,
        };
        let out = Self { body, signature };
        if d.position() != raw.len() || out.encode()? != raw {
            return Err(NativeError::Codec);
        }
        out.verify_signature()?;
        Ok(out)
    }
    fn verify_signature(&self) -> NativeResult<()> {
        validate_descriptor(&self.body.wallet_descriptor)?
            .verify(Domain::Transaction, &self.body.encode()?, &self.signature)
            .map_err(|_| NativeError::Authority)
    }
}
fn validate_treasury_creation(
    state: &State,
    anchor: &FinalizedAnchor,
    root: Hash,
    b: &TreasuryFreezeBody,
    policy: &CandidatePolicy,
) -> NativeResult<()> {
    policy.check()?;
    if b.anchor != *anchor
        || b.root != root
        || state.root().map_err(|_| NativeError::Record)? != root
        || b.context.network != crate::NETWORK_ID
        || b.context.genesis != anchor.genesis
        || b.context.fingerprint != anchor.fingerprint
        || b.context.network != anchor.network
        || b.offer.context != b.context
        || b.trade == [0; 32]
        || b.contract == [0; 32]
    {
        return Err(NativeError::Context);
    }
    validate_records(state, &b.context)?;
    // P6 (design 7.6): a Treasury offer is frozen only for the canonical Treasury authority T.
    if state.dividends.treasury().map(|t| t.authority()) != Some(b.treasury) {
        return Err(NativeError::Authority);
    }
    // The generation named by the commitment, in O(1), active at the anchor height: it took effect
    // at or before it and its successor, if any, took effect strictly after it.
    let current = treasury_generation(state, &b.context, b.treasury, b.generation)
        .map_err(|_| NativeError::Conflict)?;
    if current.effective_height > anchor.height {
        return Err(NativeError::Time);
    }
    if current.address != b.address
        || treasury_generation_opt(state, &b.context, b.treasury, b.generation + 1)?
            .is_some_and(|next| next.effective_height <= anchor.height)
    {
        return Err(NativeError::Conflict);
    }
    if b.offer.created != anchor.height
        || b.offer.expiry <= anchor.height
        || b.offer.expiry - b.offer.created > EXPIRY_HORIZON
        || b.offer.maker_side != 1
    {
        return Err(NativeError::Time);
    }
    // No minimum/maximum Treasury policy, reserve, oracle or slippage formula.
    // These checks are only positive integer quantities and explicit test rail.
    match b.offer.terms {
        OfferTerms::HashLinked {
            amount,
            bitcoin_satoshis,
            bitcoin_network,
        } if amount.0 > 0 && bitcoin_satoshis > 0 && (1..=3).contains(&bitcoin_network) => {}
        _ => return Err(NativeError::Bounds),
    }
    state
        .wallets
        .authorize(b.address, &b.wallet_descriptor)
        .map_err(|_| NativeError::Authority)?;
    validate_descriptor(&b.wallet_descriptor)?;
    Ok(())
}
/// Creation against CURRENT authenticated canonical state. Off-chain authorization
/// is immutable and auditable, but is not a Byzantine timestamp or consensus
/// listing. No offer fee/consensus order book is introduced.
pub fn prepare_treasury_offer(
    state: &State,
    anchor: &FinalizedAnchor,
    root: Hash,
    request: TreasuryOfferRequest,
    policy: &CandidatePolicy,
) -> NativeResult<PreparedTreasuryOffer> {
    policy.check()?;
    request.offer.verify()?;
    let body = TreasuryFreezeBody {
        context: request.offer.body.context.clone(),
        anchor: anchor.clone(),
        root,
        treasury: request.treasury,
        generation: request.generation,
        address: request.address,
        trade: request.trade,
        contract: request.contract,
        offer: request.offer.body,
        wallet_descriptor: request.wallet_descriptor,
    };
    validate_treasury_creation(state, anchor, root, &body, policy)?;
    Ok(PreparedTreasuryOffer { body })
}
/// Capability from exact authenticated historical creation state, not a peer's
/// self-asserted root. It does not prove global creation/publication time. The
/// dedicated signer must retain/reconcile its exact authorized creation journal.
#[derive(Debug)]
pub struct VerifiedFrozenTreasuryOffer {
    frozen: FrozenTreasuryOffer,
}
pub fn verify_frozen_treasury_offer_at_creation(
    frozen: FrozenTreasuryOffer,
    state: &State,
    anchor: &FinalizedAnchor,
    root: Hash,
    policy: &CandidatePolicy,
) -> NativeResult<VerifiedFrozenTreasuryOffer> {
    policy.check()?;
    frozen.verify_signature()?;
    validate_treasury_creation(state, anchor, root, &frozen.body, policy)?;
    Ok(VerifiedFrozenTreasuryOffer { frozen })
}
impl VerifiedFrozenTreasuryOffer {
    /// Exact profile binding; does not establish funding/finality by itself.
    pub fn verify_funding_binding(&self, wire: &NativeOperation) -> NativeResult<()> {
        self.funding(wire)
    }

    fn funding(&self, wire: &NativeOperation) -> NativeResult<()> {
        let f = &self.frozen.body;
        let op = &wire.operation;
        if op.meta.context != f.context
            || op.meta.trade != f.trade
            || op.meta.contract != f.contract
        {
            return Err(NativeError::Context);
        }
        let OfferTerms::HashLinked { amount, .. } = f.offer.terms else {
            return Err(NativeError::Bounds);
        };
        let Action::HashLock {
            offer,
            recipient,
            amount: funded,
            ..
        } = op.action
        else {
            return Err(NativeError::Conflict);
        };
        if offer != f.offer.id()?
            || recipient != f.address
            || funded != amount
            || op
                .offer_proof
                .as_ref()
                .is_none_or(|p| p.offer.body != f.offer)
        {
            return Err(NativeError::Conflict);
        }
        Ok(())
    }
}
/// Treasury profile wrapper; generic consensus execution still verifies both
/// wallet signatures/offer, exact UTXOs, one fill and fees. Bitcoin signer and
/// receipt integration must require this profile capability, never infer it from
/// an ordinary payment with the same recipient.
pub fn prepare_treasury_funding(
    state: &State,
    parent: &FinalizedAnchor,
    root: Hash,
    creation: &VerifiedFrozenTreasuryOffer,
    wire: &NativeOperation,
    policy: &CandidatePolicy,
) -> NativeResult<Prepared> {
    prepare_treasury_funding_with_history(
        state,
        parent,
        root,
        &History::default(),
        creation,
        wire,
        policy,
    )
}
/// `prepare_treasury_funding` for a funding operation whose envelope references a finalized
/// height below the parent: `history` carries that height's canonical block hash (design 1.a.3).
pub fn prepare_treasury_funding_with_history(
    state: &State,
    parent: &FinalizedAnchor,
    root: Hash,
    history: &History,
    creation: &VerifiedFrozenTreasuryOffer,
    wire: &NativeOperation,
    policy: &CandidatePolicy,
) -> NativeResult<Prepared> {
    creation.funding(wire)?;
    let f = &creation.frozen.body;
    // O(1): the frozen generation still resolves after any number of later rotations.
    let frozen = treasury_generation(state, &f.context, f.treasury, f.generation)
        .map_err(|_| NativeError::Context)?;
    if parent.height < f.anchor.height
        || frozen.address != f.address
        || frozen.effective_height > f.anchor.height
    {
        return Err(NativeError::Context);
    }
    prepare_batch_with_history(state, parent, root, history, &[wire.encode()?], policy)
}
/// Exact direct credit from real native state. Requires BOTH accepted receipts
/// and the exact principal output; a different offer credit is never evidence.
/// This establishes only the MUT leg, never BTC settlement or conversion COMPLETE.
pub fn verify_treasury_direct_credit(
    state: &State,
    creation: &VerifiedFrozenTreasuryOffer,
    funding: &NativeOperation,
    claim: &NativeOperation,
) -> NativeResult<()> {
    creation.funding(funding)?;
    let f = &creation.frozen.body;
    let op = &claim.operation;
    if op.meta.context != f.context
        || op.meta.trade != f.trade
        || op.meta.contract != f.contract
        || op.meta.generation != funding.operation.meta.generation
    {
        return Err(NativeError::Context);
    }
    let OfferTerms::HashLinked { amount, .. } = f.offer.terms else {
        return Err(NativeError::Bounds);
    };
    let Action::Claim {
        output,
        recipient,
        amount: received,
        ..
    } = op.action
    else {
        return Err(NativeError::Conflict);
    };
    if output != funding.operation.output_id(0)? || recipient != f.address || received != amount {
        return Err(NativeError::Conflict);
    }
    let funded = reconcile(state, &funding.encode()?)?.ok_or(NativeError::Missing)?;
    let claimed = reconcile(state, &claim.encode()?)?.ok_or(NativeError::Missing)?;
    if funded.height >= claimed.height
        || state.protocol_records.contains_key(&record_key(0, output))
    {
        return Err(NativeError::Context);
    }
    let coin = state
        .coins
        .get(&OutPoint {
            transaction: op.id()?,
            index: 0,
        })
        .ok_or(NativeError::Missing)?;
    if coin.output.owner != f.address
        || coin.output.atoms != amount.0
        || coin.created_height != claimed.height
        || coin.coinbase
    {
        return Err(NativeError::Conflict);
    }
    Ok(())
}

pub struct TreasuryCreditProofs<'a> {
    pub funding: &'a [u8],
    pub claim: &'a [u8],
    pub principal: &'a [u8],
}
/// Compact native evidence for the exact MUT leg. The caller independently
/// authenticates anchor/root; neither a supplied proof nor a TXID grants finality.
pub fn verify_treasury_credit_proofs(
    creation: &VerifiedFrozenTreasuryOffer,
    funding: &NativeOperation,
    claim: &NativeOperation,
    proofs: TreasuryCreditProofs<'_>,
    anchor: &FinalizedAnchor,
    root: Hash,
) -> NativeResult<()> {
    creation.funding(funding)?;
    let f = &creation.frozen.body;
    let c = &claim.operation;
    if c.meta.context != f.context
        || c.meta.trade != f.trade
        || c.meta.contract != f.contract
        || c.meta.generation != funding.operation.meta.generation
        || anchor.network != f.context.network
        || anchor.genesis != f.context.genesis
        || anchor.fingerprint != f.context.fingerprint
    {
        return Err(NativeError::Context);
    }
    let OfferTerms::HashLinked { amount, .. } = f.offer.terms else {
        return Err(NativeError::Bounds);
    };
    let Action::Claim {
        output,
        recipient,
        amount: received,
        ..
    } = c.action
    else {
        return Err(NativeError::Conflict);
    };
    if output != funding.operation.output_id(0)? || recipient != f.address || received != amount {
        return Err(NativeError::Conflict);
    }
    let receipt = |raw: &[u8], wire: &NativeOperation| -> NativeResult<u64> {
        let id = wire.operation.id()?;
        let proof = crate::state_tree::StateProof::decode_bounded(
            raw,
            MAX_NATIVE_RECORD + 9 * 1024,
            MAX_NATIVE_RECORD,
        )
        .map_err(|_| NativeError::Record)?;
        let record = proof
            .verify(anchor, root, record_key(2, id))
            .map_err(|_| NativeError::Context)?
            .ok_or(NativeError::Missing)?;
        let (found, r) = NativeRecord::decode(record)?;
        let NativeRecord::Applied {
            wire_hash,
            height,
            fee_atoms,
        } = r
        else {
            return Err(NativeError::Record);
        };
        if found != id
            || wire_hash != native_hash(b"signed", &wire.encode()?)
            || fee_atoms != wire.operation.meta.fee.0
            || height > anchor.height
        {
            return Err(NativeError::Conflict);
        }
        Ok(height)
    };
    let funding_height = receipt(proofs.funding, funding)?;
    let claim_height = receipt(proofs.claim, claim)?;
    if funding_height >= claim_height {
        return Err(NativeError::Time);
    }
    let coin = crate::state_proof::verify_utxo(
        proofs.principal,
        anchor,
        root,
        &OutPoint {
            transaction: c.id()?,
            index: 0,
        },
        f.address,
    )
    .map_err(|_| NativeError::Context)?
    .ok_or(NativeError::Missing)?;
    if coin.output.atoms != amount.0 || coin.created_height != claim_height || coin.coinbase {
        return Err(NativeError::Conflict);
    }
    Ok(())
}
