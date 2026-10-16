// Phase 6 test kit (Treasury profile). NATIVE, TEST-VALUE: public deterministic wallet keys only;
// maker keys are public WalletOwner keys at an explicit current generation. The HOST side of a
// freeze (preparing the freeze body with consensus
// `prepare_treasury_offer`) and hand-signed consensus operations for differential checks are
// played by the test here. The approval helpers are the shared `flow.rs` (since phase 8 it types
// the confirmation phrase of a high-risk review too).
//
// Owned by phase 6. Declared by a test file as:
//     #[path = "support/treasury_kit.rs"]
//     mod kit;
#![allow(dead_code)]

#[path = "flow.rs"]
mod flow;

use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    anchors::FinalizedAnchor,
    execution::State,
    trading_v1::{
        self, Action, CandidatePolicy, Context, Meta, NativeError, NativeOperation, OfferBody,
        OfferProof, OfferTerms, Operation, SignedOffer, Strikes, TreasuryOfferRequest,
        native_input_id,
    },
    transactions::OutPoint,
};
use mutiny_crypto_v2::{HybridKey, HybridSignature, Role};
use mutiny_wallet_core_v8::{
    ChainClass, ChainView, SignerIdentity,
    ops::treasury::freeze_proposal,
    profile::{self, TreasuryDeclaration},
};

/// Immutable TEST-VALUE Treasury authority T (public all-zoo key, generation one).
/// Exact public address also occurs in tests/golden/address-format-v1.json. The current
/// descriptor/destination may rotate; this identity remains the Genesis Treasury authority.
pub const TRADING_TREASURY: Hash = [
    0xeb, 0x92, 0x73, 0xa9, 0x00, 0x97, 0x1e, 0xc8, 0x81, 0xef, 0xfb, 0xb7, 0x19, 0xf8, 0x4b, 0x01,
    0xc1, 0xff, 0x7b, 0x59, 0xf4, 0x09, 0x04, 0x6d, 0x52, 0x13, 0x85, 0x5a, 0x32, 0x78, 0xf2, 0xd6,
];

pub fn zero() -> HybridSignature {
    HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    }
}

/// Signed TEST state-model transition through the ordinary WalletBook API. This supplies
/// current-key/lineage facts only: it creates no block, receipt, or canonical confirmation.
#[allow(clippy::too_many_arguments)]
pub fn apply_wallet_rotation_model(
    state: &mut State,
    anchor: &FinalizedAnchor,
    authority: Hash,
    from: &HybridKey,
    from_generation: u64,
    to: &HybridKey,
    to_generation: u64,
    included: u64,
) {
    assert!(included <= anchor.height);
    let current = from.public().descriptor(from_generation).unwrap();
    let proposed = to.public().descriptor(to_generation).unwrap();
    assert_eq!(state.wallets.current(authority).unwrap(), current);
    let mut rotation = mutiny_consensus_v8::wallet_rotation_v1::Rotation {
        network: anchor.network,
        genesis: anchor.genesis,
        fingerprint: anchor.fingerprint,
        authority,
        current,
        proposed: proposed.clone(),
        created_height: included,
        expiry_height: anchor.height.checked_add(100).unwrap(),
        authorization: zero(),
        possession: zero(),
    };
    rotation.sign(from, to).unwrap();
    state
        .wallets
        .apply(&rotation, anchor.genesis, anchor.fingerprint, included)
        .unwrap();
    assert_eq!(state.wallets.current(authority).unwrap(), proposed);
}

pub fn context_of(anchor: &FinalizedAnchor) -> Context {
    Context {
        network: NETWORK_ID,
        genesis: anchor.genesis,
        fingerprint: anchor.fingerprint,
    }
}

/// Public initial Treasury wallet. An unfunded offer must be reviewed and signed again
/// by the current settlement authority after rotation; this key is never a freeze exception.
pub fn maker_key() -> HybridKey {
    HybridKey::wallet_restore(&format!("{}vote", "zoo ".repeat(23)), Role::WalletOwner).unwrap()
}

/// The maker signs a hash-linked Treasury offer (the maker is the recipient side, as consensus
/// requires of a Treasury offer).
#[allow(clippy::too_many_arguments)]
pub fn treasury_offer(
    maker: &HybridKey,
    context: Context,
    created: u64,
    expiry: u64,
    amount: u64,
    satoshis: u64,
    network: u8,
    nonce: u8,
) -> SignedOffer {
    treasury_offer_at_generation(
        maker,
        1,
        maker.public().address_id(1).unwrap(),
        context,
        created,
        expiry,
        amount,
        satoshis,
        network,
        nonce,
    )
}

/// Newly reviewed maker witness at the settlement wallet's CURRENT authority generation.
/// `destination` is the actual Treasury settlement address, which may be a historic address
/// controlled by this descriptor. This helper does not grant a retired offer funding authority.
#[allow(clippy::too_many_arguments)]
pub fn treasury_offer_at_generation(
    maker: &HybridKey,
    maker_generation: u64,
    destination: Hash,
    context: Context,
    created: u64,
    expiry: u64,
    amount: u64,
    satoshis: u64,
    network: u8,
    nonce: u8,
) -> SignedOffer {
    SignedOffer::sign(
        OfferBody {
            context,
            maker_descriptor: maker.public().descriptor(maker_generation).unwrap(),
            maker_wallet: destination,
            destination,
            condition: None,
            max_fee: Strikes(100_000),
            nonce: [nonce; 32],
            created,
            expiry,
            maker_side: 1,
            terms: OfferTerms::HashLinked {
                amount: Strikes(amount),
                bitcoin_satoshis: satoshis,
                bitcoin_network: network,
            },
        },
        maker,
    )
    .unwrap()
}

/// The sole canonical maker-offer import form; a zero-fill legacy container is refused.
pub fn offer_import(offer: &SignedOffer) -> Vec<u8> {
    offer.encode().unwrap()
}

/// What a freeze names besides the offer.
#[derive(Clone)]
pub struct FreezeTerms {
    pub treasury: Hash,
    pub generation: u64,
    pub address: Hash,
    pub trade: Hash,
    pub contract: Hash,
    pub wallet_descriptor: Vec<u8>,
}

/// The HOST side: consensus prepares the freeze body at the view's head
/// (`trading_v1::prepare_treasury_offer`); the result is the exact signing payload.
pub fn prepare_freeze(
    view: &ChainView<'_>,
    terms: &FreezeTerms,
    offer: &SignedOffer,
) -> Result<Vec<u8>, NativeError> {
    trading_v1::prepare_treasury_offer(
        view.state(),
        view.anchor(),
        view.state_root(),
        TreasuryOfferRequest {
            treasury: terms.treasury,
            generation: terms.generation,
            address: terms.address,
            trade: terms.trade,
            contract: terms.contract,
            offer: offer.clone(),
            wallet_descriptor: terms.wallet_descriptor.clone(),
        },
        &CandidatePolicy::native_denomination_locked(),
    )?
    .signing_payload()
}

/// The freeze proposal the wallet plans from: the host's payload and the maker's offer.
pub fn proposal(view: &ChainView<'_>, terms: &FreezeTerms, offer: &SignedOffer) -> Vec<u8> {
    let payload = prepare_freeze(view, terms, offer).expect("consensus prepares the freeze");
    freeze_proposal(&payload, &offer_import(offer)).unwrap()
}

/// Everything a person must do before the approval exists: present, type every destination check,
/// give every acknowledgement and, for a high-risk review, type the confirmation phrase (the shared
/// `support/flow.rs`). Not every test binary uses both.
#[allow(unused_imports)]
pub use flow::{approve, approve_on};

/// The Treasury-profile identity of `key` (generation `generation`, authority `authority`),
/// declared for the roles given and checked against the view.
pub fn declared(
    key: &HybridKey,
    generation: u64,
    authority: Option<Hash>,
    view: &ChainView<'_>,
    authority_role: bool,
    destination_of: Option<Hash>,
) -> SignerIdentity {
    let mut declaration = TreasuryDeclaration::new(view.context().genesis, ChainClass::TestValue);
    if authority_role {
        declaration = declaration.with_authority();
    }
    if let Some(id) = destination_of {
        declaration = declaration.with_destination_of(id);
    }
    let identity = SignerIdentity::from_public(key.public(), generation, authority).unwrap();
    profile::declare(identity, &declaration, view).unwrap()
}

/// A hash lock funding a Treasury offer, built and signed with the consensus helpers (the funder,
/// the Treasury as recipient and the maker are played by the test), with an exact fee.
#[allow(clippy::too_many_arguments)]
pub fn funding_lock(
    view: &ChainView<'_>,
    offer: &SignedOffer,
    maker: &HybridKey,
    trade: Hash,
    contract: Hash,
    sender: &HybridKey,
    coin: (OutPoint, u64),
    recipient_key: &HybridKey,
    recipient: Hash,
    amount: u64,
) -> NativeOperation {
    funding_lock_at_generation(
        view,
        offer,
        maker,
        trade,
        contract,
        sender,
        sender.public().address_id(1).unwrap(),
        1,
        coin,
        recipient_key,
        recipient,
        1,
        amount,
    )
}

/// Exact native funding with explicit wallet addresses and CURRENT signing generations.
/// No authority is inferred from possessing an old wallet key or an old offer signature.
#[allow(clippy::too_many_arguments)]
pub fn funding_lock_at_generation(
    view: &ChainView<'_>,
    offer: &SignedOffer,
    maker: &HybridKey,
    trade: Hash,
    contract: Hash,
    sender: &HybridKey,
    sender_address: Hash,
    sender_generation: u64,
    coin: (OutPoint, u64),
    recipient_key: &HybridKey,
    recipient: Hash,
    recipient_generation: u64,
    amount: u64,
) -> NativeOperation {
    let next = view.anchor().height + 1;
    let condition = trading_v1::preimage_hash(&[0x42; 32]);
    let mut fee = 240u64;
    for _ in 0..8 {
        let mut op = Operation {
            meta: Meta {
                context: context_of(view.anchor()),
                trade,
                contract,
                generation: 1,
                envelope: mutiny_consensus_v8::op_envelope_v1::Envelope::from_head(
                    view.anchor(),
                    10,
                    Vec::new(),
                )
                .unwrap(),
                fee: Strikes(fee),
                inputs: vec![native_input_id(&coin.0)],
            },
            action: Action::HashLock {
                offer: offer.body.id().unwrap(),
                maker: offer.body.maker().unwrap(),
                sender: sender_address,
                recipient,
                amount: Strikes(amount),
                condition,
                refund_height: next + 20,
                change: Strikes(coin.1 - amount - fee),
            },
            approvals: Vec::new(),
            offer_proof: None,
        };
        op.offer_proof = Some(OfferProof::sign(offer.clone(), &op, maker).unwrap());
        op.approve(0, sender, sender_generation).unwrap();
        op.approve(1, recipient_key, recipient_generation).unwrap();
        let wire = NativeOperation {
            operation: op,
            inputs: vec![coin.0.clone()],
        };
        let size = wire.encode().unwrap().len() as u64;
        if fee >= size.max(240) {
            return wire;
        }
        fee = size.max(240);
    }
    panic!("fee did not converge");
}

/// Decode a native trading operation.
pub fn wire(raw: &[u8]) -> NativeOperation {
    NativeOperation::decode(raw).unwrap()
}

/// Consensus' verdict on `raw` as the only operation of the next block.
pub fn consensus(
    state: &State,
    anchor: &FinalizedAnchor,
    root: Hash,
    raw: &[u8],
) -> Result<(), NativeError> {
    trading_v1::prepare_batch(
        state,
        anchor,
        root,
        &[raw.to_vec()],
        &CandidatePolicy::native_denomination_locked(),
    )
    .map(|_| ())
}

/// Consensus' verdict against a view's state and head.
pub fn consensus_in(view: &ChainView<'_>, raw: &[u8]) -> Result<(), NativeError> {
    consensus(view.state(), view.anchor(), view.state_root(), raw)
}

/// The fields of a `TreasuryRotate` built by hand.
#[derive(Clone)]
pub struct HandRotation {
    pub reference: FinalizedAnchor,
    pub treasury: Hash,
    pub current_generation: u64,
    pub current_address: Hash,
    /// The descriptor whose hash the body commits to (the signing key's, normally).
    pub current_descriptor: Vec<u8>,
    pub new_generation: u64,
    pub new_address: Hash,
    pub new_descriptor: Vec<u8>,
    pub inputs: Vec<(OutPoint, u64)>,
    pub created: u64,
    pub expiry: u64,
}

/// The unsigned operation of `hand` with `fee` (change = inputs - fee, inputs in native order).
pub fn hand_operation(context: Context, hand: &HandRotation, fee: u64) -> NativeOperation {
    let mut inputs = hand.inputs.clone();
    inputs.sort_by_key(|(point, _)| native_input_id(point));
    let total: u64 = inputs.iter().map(|(_, atoms)| atoms).sum();
    NativeOperation {
        operation: Operation {
            meta: Meta {
                context,
                trade: [0; 32],
                contract: [0; 32],
                generation: 1,
                envelope: mutiny_consensus_v8::op_envelope_v1::Envelope {
                    first_height: hand.created,
                    last_height: hand.expiry,
                    reference_height: hand.reference.height,
                    reference_block: hand.reference.block,
                    preconditions: Vec::new(),
                },
                fee: Strikes(fee),
                inputs: inputs
                    .iter()
                    .map(|(point, _)| native_input_id(point))
                    .collect(),
            },
            action: Action::TreasuryRotate {
                treasury: hand.treasury,
                current_generation: hand.current_generation,
                current_address: hand.current_address,
                current_descriptor: trading_v1::descriptor_hash(&hand.current_descriptor),
                new_generation: hand.new_generation,
                new_address: hand.new_address,
                new_descriptor: hand.new_descriptor.clone(),
                change: Strikes(total.saturating_sub(fee)),
            },
            approvals: Vec::new(),
            offer_proof: None,
        },
        inputs: inputs.into_iter().map(|(point, _)| point).collect(),
    }
}

/// Sign approval `slot` of `wire` with `key` at `generation` through the consensus helper
/// (`Operation::approve`, test and offline use only) and encode.
pub fn signed_with(
    mut wire: NativeOperation,
    slot: u8,
    key: &HybridKey,
    generation: u64,
) -> Vec<u8> {
    wire.operation.approve(slot, key, generation).unwrap();
    wire.encode().unwrap()
}

/// Authentic Treasury head facts from this explicit TEST view, with a complete-size fee.
/// The empty-facts `hand_rotation` remains for intentional malformed-envelope probes.
/// A synthetic view is still a TEST model; this helper manufactures no canonical history.
pub fn hand_rotation_in_view(
    view: &ChainView<'_>,
    hand: &HandRotation,
    key: &HybridKey,
    generation: u64,
) -> Vec<u8> {
    let context = context_of(view.anchor());
    let facts = mutiny_consensus_v8::op_envelope_v1::treasury_head_facts(
        view.state(),
        &context,
        hand.treasury,
    )
    .unwrap();
    let mut fee = 240;
    for _ in 0..8 {
        let mut wire = hand_operation(context.clone(), hand, fee);
        wire.operation.meta.envelope.preconditions = vec![facts.clone()];
        let raw = signed_with(wire, 0, key, generation);
        let required = (raw.len() as u64).max(240);
        if fee >= required {
            return raw;
        }
        fee = required;
    }
    panic!("the hand-built exact-facts fee did not converge");
}
/// A fully signed hand-built rotation whose fee is exactly the minimum for its signed size
/// (`max(240, size)`, a fixed point over the encoded length).
pub fn hand_rotation(
    context: Context,
    hand: &HandRotation,
    key: &HybridKey,
    generation: u64,
) -> Vec<u8> {
    let mut fee = 240u64;
    for _ in 0..8 {
        let raw = signed_with(
            hand_operation(context.clone(), hand, fee),
            0,
            key,
            generation,
        );
        let size = raw.len() as u64;
        if fee >= size.max(240) {
            return raw;
        }
        fee = size.max(240);
    }
    panic!("the hand-built fee did not converge");
}

/// Re-encode `raw` after `edit` of the unsigned operation, re-signed with `key` (generation
/// `generation`). The approvals are dropped first, so the result carries exactly the new one.
pub fn resigned(
    raw: &[u8],
    key: &HybridKey,
    generation: u64,
    edit: impl FnOnce(&mut NativeOperation),
) -> Vec<u8> {
    let mut wire = wire(raw);
    wire.operation.approvals.clear();
    edit(&mut wire);
    signed_with(wire, 0, key, generation)
}

/// A freeze body encoded by the TEST, independently of the wallet: a mirror of the private consensus
/// `TreasuryFreezeBody::encode`, used to hand the wallet bodies consensus would never prepare
/// (`kit_body_equals_the_consensus_payload` pins it to consensus for a valid freeze).
pub fn freeze_body(
    context: &Context,
    anchor: &FinalizedAnchor,
    root: Hash,
    terms: &FreezeTerms,
    offer: &OfferBody,
) -> Vec<u8> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(14)
        .unwrap()
        .bytes(trading_v1::NATIVE_NAMESPACE)
        .unwrap()
        .bytes(b"treasury-freeze")
        .unwrap()
        .u8(1)
        .unwrap();
    e.array(3)
        .unwrap()
        .u32(context.network)
        .unwrap()
        .bytes(&context.genesis)
        .unwrap()
        .bytes(&context.fingerprint)
        .unwrap();
    e.u64(anchor.height)
        .unwrap()
        .bytes(&anchor.block)
        .unwrap()
        .bytes(&root)
        .unwrap()
        .bytes(&terms.treasury)
        .unwrap()
        .u64(terms.generation)
        .unwrap()
        .bytes(&terms.address)
        .unwrap()
        .bytes(&terms.trade)
        .unwrap()
        .bytes(&terms.contract)
        .unwrap()
        .bytes(&offer.encode().unwrap())
        .unwrap()
        .bytes(&terms.wallet_descriptor)
        .unwrap();
    e.into_writer()
}

/// The consensus `FrozenTreasuryOffer` encoding of `body` signed by `key` in `Domain::Transaction`,
/// built by the TEST (for transplant and tamper cases).
pub fn frozen_by_hand(body: &[u8], key: &HybridKey) -> Vec<u8> {
    let signature = key
        .sign(mutiny_crypto_v2::Domain::Transaction, body)
        .unwrap();
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .bytes(body)
        .unwrap()
        .bytes(&signature.ed448)
        .unwrap()
        .bytes(&signature.fndsa)
        .unwrap();
    e.into_writer()
}
