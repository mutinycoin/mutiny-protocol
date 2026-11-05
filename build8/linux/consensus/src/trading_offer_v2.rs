//! P7 (Order of 4 Oct 2026; Lane P design section 8 with amendment AM-6): THE canonical maker-offer
//! format, owned by the trading specification (`spec/BUILD8-TRADING-D1-LOCK-PACKET-V1.md`, section
//! "Candidate 3 amendments: T4").
//!
//! * `OfferBody` version 2 = `[NAMESPACE, 2, network, genesis, fingerprint, [maker_descriptor,
//!   maker_wallet, maker_side], nonce, created_height, expiry_height, terms, destination,
//!   condition|null, max_fee]` (CBOR definite array of 13 items, shortest form).
//! * `MakerOffer` = `[bytes "MUTINY-BUILD8-MAKER-OFFER-V2", body bytes, ed448 (114), fndsa (1280)]`:
//!   the ONE wire object of a signed maker offer (wallet, node and consensus share it).
//! * `OfferProof` (the optional fourth part of a trading `Operation`) = `[MakerOffer bytes, fill
//!   ed448, fill fndsa]`: it embeds the maker's exact MakerOffer bytes, so no second encoding of a
//!   signed offer exists.
//! * Offer id = `hash("offer", body)` and the single-fill key `(context, offer id)` are unchanged
//!   (`trading_v1::single_fill_key`; one `Consumed` record, consumed atomically with the funding).
//! * Signatures (AM-6 DEFAULT, ARCHITECT question C.3): the maker's WALLET OWNER key (the
//!   `maker_descriptor`) signs
//!   `[NAMESPACE, "signed-offer", body]` under crypto-v2 `Domain::TradeOffer` and the fill
//!   `[NAMESPACE, "offer-fill", operation body]` under `Domain::TradeFill`. The role is decided
//!   in exactly one place, `mutiny_crypto_v2::Domain::role()`.
//!
//! Offers and negotiation stay above consensus (no order book, storage or gossip); consensus only
//! checks a filled offer inside a settlement operation (`Operation::verify_offer`). Version-1
//! bodies and the two legacy forms never settle: see `legacy` (compiled only for tests).
use crate::trading_v1::{Action, Context, Error, Hash, NAMESPACE, Operation, Result, Strikes, hash};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, PublicKey, Role};

/// The body version byte of a canonical maker offer. Only version 2 settles.
pub const OFFER_BODY_VERSION: u8 = 2;
/// The label of the MakerOffer wire object (a CBOR BYTE string: the consensus canonical walker
/// refuses text strings).
pub const MAKER_OFFER_LABEL: &[u8] = b"MUTINY-BUILD8-MAKER-OFFER-V2";
/// Upper bound of an encoded OfferBody (a wallet descriptor is at most 2,048 bytes).
pub const MAX_OFFER_BODY: usize = 4096;
/// Upper bound of an encoded MakerOffer and of an encoded OfferProof.
pub const MAX_MAKER_OFFER: usize = 8192;
/// Payload label of the maker's offer signature (under `Domain::TradeOffer`).
pub const OFFER_SIGNATURE_LABEL: &[u8] = b"signed-offer";
/// Payload label of the maker's fill signature (under `Domain::TradeFill`).
pub const FILL_SIGNATURE_LABEL: &[u8] = b"offer-fill";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OfferTerms {
    /// `[0, amount, bitcoin_satoshis, bitcoin_network]`
    HashLinked {
        amount: Strikes,
        bitcoin_satoshis: u64,
        bitcoin_network: u8,
    },
    /// `[1, license, generation, price]`
    License {
        license: Hash,
        generation: u64,
        price: Strikes,
    },
    /// `[2, amount, payment_terms]`
    Fiat { amount: Strikes, payment_terms: Hash },
}

/// OfferBody version 2 (design 8.2). Field names `created`/`expiry` are the encoded
/// `created_height`/`expiry_height` (certified heights).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferBody {
    pub context: Context,
    /// The maker's wallet owner descriptor (AM-6) that signs the offer and the fill. The settlement
    /// slot of `maker_wallet` is approved separately by that address's CURRENT authority.
    pub maker_descriptor: Vec<u8>,
    /// The AddressID that settles for the maker: it must be the operation's slot address of
    /// `maker_side`.
    pub maker_wallet: Hash,
    /// 0 = sender/seller; 1 = recipient/buyer.
    pub maker_side: u8,
    pub nonce: Hash,
    pub created: u64,
    pub expiry: u64,
    pub terms: OfferTerms,
    /// Where the maker receives (or, as a HashLock sender, gets its change/refund); never zero.
    pub destination: Hash,
    /// HashLinked only: a maker-fixed hash condition (`None` = the condition is not fixed by the
    /// maker). Must be `None` for License and Fiat terms.
    pub condition: Option<Hash>,
    /// The largest operation fee the maker accepts when the maker's slot pays the fee.
    pub max_fee: Strikes,
}

/// The signed maker offer; its encoding is the MakerOffer wire object.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MakerOffer {
    pub body: OfferBody,
    pub signature: HybridSignature,
}
/// The earlier name of the signed maker offer, kept for the Treasury freeze API
/// (`trading_v1::TreasuryOfferRequest`). It IS `MakerOffer`: there is one signed-offer type.
pub type SignedOffer = MakerOffer;

/// A filled offer inside a trading operation: the maker's MakerOffer and the maker's fill
/// signature over the exact operation body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferProof {
    pub offer: MakerOffer,
    pub fill_signature: HybridSignature,
}

/// The maker's public key from a wallet owner descriptor of a nonzero generation.
fn maker_key(raw: &[u8]) -> Result<PublicKey> {
    if raw.len() > 2048 {
        return Err(Error::Bounds);
    }
    let (p, generation) = PublicKey::decode_descriptor(raw).map_err(|_| Error::Codec)?;
    if p.role != Role::WalletOwner || generation == 0 {
        return Err(Error::Authority);
    }
    Ok(p)
}
/// `[NAMESPACE, label, body]`: the exact bytes each maker signature covers (before the crypto-v2
/// domain framing).
pub fn signature_payload(label: &[u8], body: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .bytes(NAMESPACE)
        .unwrap()
        .bytes(label)
        .unwrap()
        .bytes(body)
        .unwrap();
    e.into_writer()
}
fn arr(d: &mut Decoder<'_>, n: u64) -> Result<()> {
    if d.array().map_err(|_| Error::Codec)? != Some(n) {
        return Err(Error::Codec);
    }
    Ok(())
}
fn fixed<const N: usize>(d: &mut Decoder<'_>) -> Result<[u8; N]> {
    d.bytes()
        .map_err(|_| Error::Codec)?
        .try_into()
        .map_err(|_| Error::Codec)
}
fn u64v(d: &mut Decoder<'_>) -> Result<u64> {
    d.u64().map_err(|_| Error::Codec)
}
fn u8v(d: &mut Decoder<'_>) -> Result<u8> {
    d.u8().map_err(|_| Error::Codec)
}

impl OfferTerms {
    fn encode(&self, e: &mut Encoder<Vec<u8>>) -> Result<()> {
        match self {
            OfferTerms::HashLinked {
                amount,
                bitcoin_satoshis,
                bitcoin_network,
            } => {
                // Candidate environment identifiers: 0 mainnet, 1 testnet, 2 signet, 3 regtest.
                // They are not registry allocations.
                if amount.0 == 0 || *bitcoin_satoshis == 0 || *bitcoin_network > 3 {
                    return Err(Error::Bounds);
                }
                e.array(4)
                    .unwrap()
                    .u8(0)
                    .unwrap()
                    .u64(amount.0)
                    .unwrap()
                    .u64(*bitcoin_satoshis)
                    .unwrap()
                    .u8(*bitcoin_network)
                    .unwrap();
            }
            OfferTerms::License {
                license,
                generation,
                price,
            } => {
                if *generation == 0 || price.0 == 0 {
                    return Err(Error::Bounds);
                }
                e.array(4)
                    .unwrap()
                    .u8(1)
                    .unwrap()
                    .bytes(license)
                    .unwrap()
                    .u64(*generation)
                    .unwrap()
                    .u64(price.0)
                    .unwrap();
            }
            OfferTerms::Fiat {
                amount,
                payment_terms,
            } => {
                if amount.0 == 0 {
                    return Err(Error::Bounds);
                }
                e.array(3)
                    .unwrap()
                    .u8(2)
                    .unwrap()
                    .u64(amount.0)
                    .unwrap()
                    .bytes(payment_terms)
                    .unwrap();
            }
        }
        Ok(())
    }
    fn decode(d: &mut Decoder<'_>) -> Result<Self> {
        let n = d.array().map_err(|_| Error::Codec)?.ok_or(Error::Codec)?;
        Ok(match (u8v(d)?, n) {
            (0, 4) => OfferTerms::HashLinked {
                amount: Strikes(u64v(d)?),
                bitcoin_satoshis: u64v(d)?,
                bitcoin_network: u8v(d)?,
            },
            (1, 4) => OfferTerms::License {
                license: fixed(d)?,
                generation: u64v(d)?,
                price: Strikes(u64v(d)?),
            },
            (2, 3) => OfferTerms::Fiat {
                amount: Strikes(u64v(d)?),
                payment_terms: fixed(d)?,
            },
            _ => return Err(Error::Codec),
        })
    }
}

impl OfferBody {
    /// The canonical bytes. Refuses (`Bounds`) a window with `created > expiry`, a side other than
    /// 0/1, a zero `maker_wallet` or `destination` (P3), a condition on non-HashLinked terms and
    /// out-of-range terms; refuses (`Authority`/`Codec`) a maker descriptor that is not a wallet
    /// owner descriptor of a nonzero generation.
    pub fn encode(&self) -> Result<Vec<u8>> {
        maker_key(&self.maker_descriptor)?;
        if self.created > self.expiry
            || self.maker_side > 1
            || self.maker_wallet == [0; 32]
            || self.destination == [0; 32]
            || (self.condition.is_some() && !matches!(self.terms, OfferTerms::HashLinked { .. }))
        {
            return Err(Error::Bounds);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(13)
            .unwrap()
            .bytes(NAMESPACE)
            .unwrap()
            .u8(OFFER_BODY_VERSION)
            .unwrap()
            .u32(self.context.network)
            .unwrap()
            .bytes(&self.context.genesis)
            .unwrap()
            .bytes(&self.context.fingerprint)
            .unwrap();
        e.array(3)
            .unwrap()
            .bytes(&self.maker_descriptor)
            .unwrap()
            .bytes(&self.maker_wallet)
            .unwrap()
            .u8(self.maker_side)
            .unwrap();
        e.bytes(&self.nonce)
            .unwrap()
            .u64(self.created)
            .unwrap()
            .u64(self.expiry)
            .unwrap();
        self.terms.encode(&mut e)?;
        e.bytes(&self.destination).unwrap();
        match &self.condition {
            Some(c) => e.bytes(c).unwrap(),
            None => e.null().unwrap(),
        };
        e.u64(self.max_fee.0).unwrap();
        let out = e.into_writer();
        if out.len() > MAX_OFFER_BODY {
            return Err(Error::Bounds);
        }
        Ok(out)
    }
    /// Offer id: `hash("offer", body)` (derivation unchanged from body version 1).
    pub fn id(&self) -> Result<Hash> {
        Ok(hash(b"offer", &self.encode()?))
    }
    /// The maker identity bound by the action's `maker` field: `hash("trade-identity",
    /// maker_descriptor)` (derivation unchanged).
    pub fn maker(&self) -> Result<Hash> {
        maker_key(&self.maker_descriptor)?;
        Ok(hash(b"trade-identity", &self.maker_descriptor))
    }
    /// Strict decoding: exactly the bytes `encode` produces. A body of version 1 (the retired
    /// format) is refused with `OfferBinding` (design 8.2: only version-2 bodies settle); any other
    /// malformed body is `Codec`.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_OFFER_BODY {
            return Err(Error::Bounds);
        }
        let mut d = Decoder::new(raw);
        let n = d.array().map_err(|_| Error::Codec)?.ok_or(Error::Codec)?;
        if d.bytes().map_err(|_| Error::Codec)? != NAMESPACE {
            return Err(Error::Codec);
        }
        match (u8v(&mut d)?, n) {
            (OFFER_BODY_VERSION, 13) => {}
            (1, _) => return Err(Error::OfferBinding),
            _ => return Err(Error::Codec),
        }
        let context = Context {
            network: d.u32().map_err(|_| Error::Codec)?,
            genesis: fixed(&mut d)?,
            fingerprint: fixed(&mut d)?,
        };
        arr(&mut d, 3)?;
        let maker_descriptor = d.bytes().map_err(|_| Error::Codec)?.to_vec();
        let maker_wallet = fixed(&mut d)?;
        let maker_side = u8v(&mut d)?;
        let nonce = fixed(&mut d)?;
        let created = u64v(&mut d)?;
        let expiry = u64v(&mut d)?;
        let terms = OfferTerms::decode(&mut d)?;
        let destination = fixed(&mut d)?;
        let condition = if d.datatype().map_err(|_| Error::Codec)? == minicbor::data::Type::Null {
            d.null().map_err(|_| Error::Codec)?;
            None
        } else {
            Some(fixed(&mut d)?)
        };
        let max_fee = Strikes(u64v(&mut d)?);
        let out = Self {
            context,
            maker_descriptor,
            maker_wallet,
            maker_side,
            nonce,
            created,
            expiry,
            terms,
            destination,
            condition,
            max_fee,
        };
        if d.position() != raw.len() || out.encode()? != raw {
            return Err(Error::Codec);
        }
        Ok(out)
    }
}

impl MakerOffer {
    /// Sign `body` with the maker's wallet owner key (`Domain::TradeOffer`). The key must be the
    /// key of `body.maker_descriptor`. Test/offline signing: the caller supplies its own key.
    pub fn sign(body: OfferBody, key: &HybridKey) -> Result<Self> {
        if maker_key(&body.maker_descriptor)? != *key.public() {
            return Err(Error::Authority);
        }
        let signature = key
            .sign(
                Domain::TradeOffer,
                &signature_payload(OFFER_SIGNATURE_LABEL, &body.encode()?),
            )
            .map_err(|_| Error::Signature)?;
        Ok(Self { body, signature })
    }
    /// The maker's signature under `maker_descriptor` (stateless; the settlement slot of
    /// `maker_wallet` is approved separately by its current authority).
    pub fn verify(&self) -> Result<()> {
        maker_key(&self.body.maker_descriptor)?
            .verify(
                Domain::TradeOffer,
                &signature_payload(OFFER_SIGNATURE_LABEL, &self.body.encode()?),
                &self.signature,
            )
            .map_err(|_| Error::Signature)
    }
    /// The MakerOffer wire object.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .bytes(MAKER_OFFER_LABEL)
            .unwrap()
            .bytes(&self.body.encode()?)
            .unwrap()
            .bytes(&self.signature.ed448)
            .unwrap()
            .bytes(&self.signature.fndsa)
            .unwrap();
        let out = e.into_writer();
        if out.len() > MAX_MAKER_OFFER {
            return Err(Error::Bounds);
        }
        Ok(out)
    }
    /// Strict decoding of the MakerOffer wire object (format only; `verify` checks the signature).
    /// This is the only maker-offer decoder of production builds.
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_MAKER_OFFER {
            return Err(Error::Bounds);
        }
        let mut d = Decoder::new(raw);
        arr(&mut d, 4)?;
        if d.bytes().map_err(|_| Error::Codec)? != MAKER_OFFER_LABEL {
            return Err(Error::Codec);
        }
        let body = OfferBody::decode(d.bytes().map_err(|_| Error::Codec)?)?;
        let signature = HybridSignature {
            ed448: fixed(&mut d)?,
            fndsa: fixed(&mut d)?,
        };
        let out = Self { body, signature };
        if d.position() != raw.len() || out.encode()? != raw {
            return Err(Error::Codec);
        }
        Ok(out)
    }
}
/// Decode AND verify a MakerOffer (taker import: format, then the maker's signature). The chain
/// context, the window and the single-fill status are the caller's state checks.
pub fn decode_maker_offer(raw: &[u8]) -> Result<MakerOffer> {
    let offer = MakerOffer::decode(raw)?;
    offer.verify()?;
    Ok(offer)
}

impl OfferProof {
    /// The maker's fill signature over `op.body()` (`Domain::TradeFill`), with the key of the
    /// offer's maker descriptor. Test/offline signing: the caller supplies its own key.
    pub fn sign(offer: MakerOffer, op: &Operation, key: &HybridKey) -> Result<Self> {
        offer.verify()?;
        if maker_key(&offer.body.maker_descriptor)? != *key.public() {
            return Err(Error::Authority);
        }
        let fill_signature = key
            .sign(
                Domain::TradeFill,
                &signature_payload(FILL_SIGNATURE_LABEL, &op.body()?),
            )
            .map_err(|_| Error::Signature)?;
        Ok(Self {
            offer,
            fill_signature,
        })
    }
    /// `[MakerOffer bytes, fill ed448, fill fndsa]`.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(3)
            .unwrap()
            .bytes(&self.offer.encode()?)
            .unwrap()
            .bytes(&self.fill_signature.ed448)
            .unwrap()
            .bytes(&self.fill_signature.fndsa)
            .unwrap();
        let out = e.into_writer();
        if out.len() > MAX_MAKER_OFFER {
            return Err(Error::Bounds);
        }
        Ok(out)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_MAKER_OFFER {
            return Err(Error::Bounds);
        }
        let mut d = Decoder::new(raw);
        arr(&mut d, 3)?;
        let offer = MakerOffer::decode(d.bytes().map_err(|_| Error::Codec)?)?;
        let fill_signature = HybridSignature {
            ed448: fixed(&mut d)?,
            fndsa: fixed(&mut d)?,
        };
        let out = Self {
            offer,
            fill_signature,
        };
        if d.position() != raw.len() || out.encode()? != raw {
            return Err(Error::Codec);
        }
        Ok(out)
    }
    fn verify_fill(&self, op: &Operation) -> Result<()> {
        maker_key(&self.offer.body.maker_descriptor)?
            .verify(
                Domain::TradeFill,
                &signature_payload(FILL_SIGNATURE_LABEL, &op.body()?),
                &self.fill_signature,
            )
            .map_err(|_| Error::Signature)
    }
}

/// The address a maker on `side` receives at under `action` (design 8.2 destination rule):
/// HashLock sender (refund/change) or recipient; LicenseDvp seller -> `payment_destination`,
/// buyer -> `buyer`; FiatLock seller or buyer. `None` for actions that fill no offer.
fn maker_destination(action: &Action, side: u8) -> Option<Hash> {
    match (action, side) {
        (Action::HashLock { sender, .. }, 0) => Some(*sender),
        (Action::HashLock { recipient, .. }, 1) => Some(*recipient),
        (
            Action::LicenseDvp {
                payment_destination,
                ..
            },
            0,
        ) => Some(*payment_destination),
        (Action::LicenseDvp { buyer, .. }, 1) => Some(*buyer),
        (Action::FiatLock { seller, .. }, 0) => Some(*seller),
        (Action::FiatLock { buyer, .. }, 1) => Some(*buyer),
        _ => None,
    }
}

impl Operation {
    /// Called before any single-fill consumption. Wallet authorizations are additionally
    /// required; this witness never grants wallet spending power.
    pub fn verify_offer(&self, height: u64) -> Result<()> {
        self.check_offer(height, true)
    }
    /// The consensus checks of a filled offer (design 8.2; nothing else about offers enters
    /// consensus), in this order: binding (offer id, maker identity), context, maker authority,
    /// destination, maker-fixed condition, fee terms, validity window, exact terms, then (with
    /// `signatures`) the maker's offer and fill signatures. With `signatures == false` it skips
    /// exactly those two verifications, which `verify_offer_signatures` covers (AM-1(d)).
    pub(crate) fn check_offer(&self, height: u64, signatures: bool) -> Result<()> {
        let (offer, maker) = match self.action {
            Action::HashLock { offer, maker, .. }
            | Action::LicenseDvp { offer, maker, .. }
            | Action::FiatLock { offer, maker, .. } => (offer, maker),
            _ => {
                return if self.offer_proof.is_none() {
                    Ok(())
                } else {
                    Err(Error::OfferBinding)
                };
            }
        };
        let p = self.offer_proof.as_ref().ok_or(Error::OfferBinding)?;
        let b = &p.offer.body;
        if b.context != self.meta.context {
            return Err(Error::Context);
        }
        if b.id()? != offer || b.maker()? != maker {
            return Err(Error::OfferBinding);
        }
        // Maker side/address and exact offer terms are structural here. Native
        // state validation separately requires the maker descriptor to be current
        // at first funding. Previously funded locks retain their own authority;
        // an unfunded old-key offer has no canonical pre-rotation existence.
        if self.slot_address(b.maker_side) != Some(b.maker_wallet) {
            return Err(Error::Authority);
        }
        // Destination: the taker cannot redirect the maker's proceeds.
        if maker_destination(&self.action, b.maker_side) != Some(b.destination) {
            return Err(Error::OfferBinding);
        }
        // A maker-fixed hash condition.
        if let (Some(c), Action::HashLock { condition, .. }) = (&b.condition, &self.action)
            && condition != c
        {
            return Err(Error::Condition);
        }
        // Fee terms: the maker never pays more than `max_fee`.
        if self.fee_payer() == b.maker_wallet && self.meta.fee > b.max_fee {
            return Err(Error::Fee);
        }
        // The operation window and the inclusion height lie inside the offer window.
        if height < b.created || self.meta.envelope.first_height < b.created {
            return Err(Error::Time);
        }
        if height > b.expiry || self.meta.envelope.last_height > b.expiry {
            return Err(Error::Expired);
        }
        let exact = match (&b.terms, &self.action) {
            (OfferTerms::HashLinked { amount, .. }, Action::HashLock { amount: a, .. }) => {
                amount == a
            }
            (
                OfferTerms::License {
                    license,
                    generation,
                    price,
                },
                Action::LicenseDvp {
                    license: l,
                    license_generation: g,
                    price: p,
                    ..
                },
            ) => license == l && generation == g && price == p,
            (
                OfferTerms::Fiat {
                    amount,
                    payment_terms,
                },
                Action::FiatLock {
                    amount: a,
                    payment_terms: p,
                    ..
                },
            ) => amount == a && payment_terms == p,
            _ => false,
        };
        if !exact {
            return Err(Error::OfferBinding);
        }
        if !signatures {
            return Ok(());
        }
        p.offer.verify()?;
        p.verify_fill(self)
    }
    /// The stateless half of `verify_offer` (AM-1(d)): the maker's offer signature and fill
    /// signature over this exact body. An offer proof on an action that fills no offer, or a
    /// missing one on an action that does, is `OfferBinding` exactly as in `verify_offer`.
    pub(crate) fn verify_offer_signatures(&self) -> Result<()> {
        let fills = matches!(
            self.action,
            Action::HashLock { .. } | Action::LicenseDvp { .. } | Action::FiatLock { .. }
        );
        let p = match (&self.offer_proof, fills) {
            (None, false) => return Ok(()),
            (Some(p), true) => p,
            _ => return Err(Error::OfferBinding),
        };
        p.offer.verify()?;
        p.verify_fill(self)
    }
}

/// Decode-and-verify-only adapters for the two retired version-1 forms (design 8.3): Form A, the
/// wallet container `[text "MUTINY-BUILD8-WALLET-MAKER-OFFER-V1", body v1, ed448, fndsa]`, and
/// Form B, a version-1 consensus OfferProof `[body v1, ed448, fndsa, fill ed448, fill fndsa]` with
/// an all-zero fill signature. They exist to read version-1 TEST vectors: they return a
/// `LegacyOffer` that cannot be converted into a `MakerOffer` or an `OfferProof`, re-encoded, or
/// settled (consensus decodes only version 2). Compiled only for tests (no consensus Cargo feature may be added: Architect decision of 3 Oct 2026).
// Test builds only: the Architect decision of 3 Oct 2026 (tests/rule_set_build_independence.rs) admits no
// new consensus Cargo feature, so the brief's `legacy-offer-import` feature is NOT declared (see the
// WP-T4 notes, open point 4).
#[cfg(test)]
pub mod legacy {
    use super::{arr, fixed, signature_payload, u8v, u64v, OfferTerms, OFFER_SIGNATURE_LABEL};
    use crate::trading_v1::{Context, Error, NAMESPACE, Result};
    use minicbor::{Decoder, Encoder};
    use mutiny_crypto_v2::{Domain, HybridSignature, PublicKey, Role};

    /// The label of Form A (a CBOR TEXT string, which the consensus canonical walker refuses).
    pub const WALLET_CONTAINER_LABEL: &str = "MUTINY-BUILD8-WALLET-MAKER-OFFER-V1";

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum LegacyForm {
        WalletContainer,
        ZeroFillProof,
    }
    /// A version-1 maker offer read from a legacy form. Read-only: no encoder, no conversion.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct LegacyOffer {
        form: LegacyForm,
        context: Context,
        descriptor: Vec<u8>,
        nonce: [u8; 32],
        created: u64,
        expiry: u64,
        maker_side: u8,
        terms: OfferTerms,
        body: Vec<u8>,
        signature: HybridSignature,
    }
    impl LegacyOffer {
        pub fn form(&self) -> LegacyForm {
            self.form
        }
        pub fn context(&self) -> &Context {
            &self.context
        }
        pub fn terms(&self) -> &OfferTerms {
            &self.terms
        }
        pub fn window(&self) -> (u64, u64) {
            (self.created, self.expiry)
        }
        pub fn maker_side(&self) -> u8 {
            self.maker_side
        }
        pub fn nonce(&self) -> [u8; 32] {
            self.nonce
        }
        /// The version-1 maker signature: a Transport-role key under
        /// `Domain::TransportInitiator` over `[NAMESPACE, "signed-offer", body v1]`.
        pub fn verify(&self) -> Result<()> {
            let (p, generation) =
                PublicKey::decode_descriptor(&self.descriptor).map_err(|_| Error::Codec)?;
            if p.role != Role::Transport || generation == 0 {
                return Err(Error::Authority);
            }
            p.verify(
                Domain::TransportInitiator,
                &signature_payload(OFFER_SIGNATURE_LABEL, &self.body),
                &self.signature,
            )
            .map_err(|_| Error::Signature)
        }
    }
    struct BodyV1 {
        context: Context,
        descriptor: Vec<u8>,
        nonce: [u8; 32],
        created: u64,
        expiry: u64,
        maker_side: u8,
        terms: OfferTerms,
    }
    fn reencode_v1(b: &BodyV1) -> Result<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(11)
            .unwrap()
            .bytes(NAMESPACE)
            .unwrap()
            .u8(1)
            .unwrap()
            .u32(b.context.network)
            .unwrap()
            .bytes(&b.context.genesis)
            .unwrap()
            .bytes(&b.context.fingerprint)
            .unwrap()
            .bytes(&b.descriptor)
            .unwrap()
            .bytes(&b.nonce)
            .unwrap()
            .u64(b.created)
            .unwrap()
            .u64(b.expiry)
            .unwrap()
            .u8(b.maker_side)
            .unwrap();
        b.terms.encode(&mut e)?;
        Ok(e.into_writer())
    }
    fn decode_body_v1(raw: &[u8]) -> Result<BodyV1> {
        if raw.len() > 4096 {
            return Err(Error::Bounds);
        }
        let mut d = Decoder::new(raw);
        arr(&mut d, 11)?;
        if d.bytes().map_err(|_| Error::Codec)? != NAMESPACE || u8v(&mut d)? != 1 {
            return Err(Error::Codec);
        }
        let b = BodyV1 {
            context: Context {
                network: d.u32().map_err(|_| Error::Codec)?,
                genesis: fixed(&mut d)?,
                fingerprint: fixed(&mut d)?,
            },
            descriptor: d.bytes().map_err(|_| Error::Codec)?.to_vec(),
            nonce: fixed(&mut d)?,
            created: u64v(&mut d)?,
            expiry: u64v(&mut d)?,
            maker_side: u8v(&mut d)?,
            terms: OfferTerms::decode(&mut d)?,
        };
        if b.created > b.expiry || b.maker_side > 1 || d.position() != raw.len() || reencode_v1(&b)? != raw {
            return Err(Error::Codec);
        }
        Ok(b)
    }
    fn offer(form: LegacyForm, body: &[u8], signature: HybridSignature) -> Result<LegacyOffer> {
        let b = decode_body_v1(body)?;
        Ok(LegacyOffer {
            form,
            context: b.context,
            descriptor: b.descriptor,
            nonce: b.nonce,
            created: b.created,
            expiry: b.expiry,
            maker_side: b.maker_side,
            terms: b.terms,
            body: body.to_vec(),
            signature,
        })
    }
    /// Form A, strictly canonical (definite lengths, shortest form, nothing after the end).
    pub fn decode_wallet_container(raw: &[u8]) -> Result<LegacyOffer> {
        if raw.is_empty() || raw.len() > 8192 {
            return Err(Error::Bounds);
        }
        let mut d = Decoder::new(raw);
        arr(&mut d, 4)?;
        if d.str().map_err(|_| Error::Codec)? != WALLET_CONTAINER_LABEL {
            return Err(Error::Codec);
        }
        let body = d.bytes().map_err(|_| Error::Codec)?.to_vec();
        let signature = HybridSignature {
            ed448: fixed(&mut d)?,
            fndsa: fixed(&mut d)?,
        };
        let out = offer(LegacyForm::WalletContainer, &body, signature)?;
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .str(WALLET_CONTAINER_LABEL)
            .unwrap()
            .bytes(&body)
            .unwrap()
            .bytes(&out.signature.ed448)
            .unwrap()
            .bytes(&out.signature.fndsa)
            .unwrap();
        if d.position() != raw.len() || e.into_writer() != raw {
            return Err(Error::Codec);
        }
        Ok(out)
    }
    /// Form B: accepted only with an all-zero fill signature (a filled version-1 proof is not an
    /// offer to import).
    pub fn decode_zero_fill_proof(raw: &[u8]) -> Result<LegacyOffer> {
        if raw.is_empty() || raw.len() > 8192 {
            return Err(Error::Bounds);
        }
        let mut d = Decoder::new(raw);
        arr(&mut d, 5)?;
        let body = d.bytes().map_err(|_| Error::Codec)?.to_vec();
        let signature = HybridSignature {
            ed448: fixed(&mut d)?,
            fndsa: fixed(&mut d)?,
        };
        let fill = HybridSignature {
            ed448: fixed(&mut d)?,
            fndsa: fixed(&mut d)?,
        };
        if fill.ed448 != [0; 114] || fill.fndsa != [0; 1280] {
            return Err(Error::OfferBinding);
        }
        let out = offer(LegacyForm::ZeroFillProof, &body, signature)?;
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .bytes(&body)
            .unwrap()
            .bytes(&out.signature.ed448)
            .unwrap()
            .bytes(&out.signature.fndsa)
            .unwrap()
            .bytes(&fill.ed448)
            .unwrap()
            .bytes(&fill.fndsa)
            .unwrap();
        if d.position() != raw.len() || e.into_writer() != raw {
            return Err(Error::Codec);
        }
        Ok(out)
    }
    /// Either legacy form, then the version-1 maker signature.
    pub fn import_and_verify(raw: &[u8]) -> Result<LegacyOffer> {
        let o = decode_wallet_container(raw).or_else(|_| decode_zero_fill_proof(raw))?;
        o.verify()?;
        Ok(o)
    }
}

#[cfg(test)]
#[path = "trading_offer_v2_tests.rs"]
mod tests;
