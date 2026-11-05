// Phase 5A test kit. NATIVE, TEST-VALUE.
//
// The MAKER side of a trade is played by the TEST here (the wallet core imports and verifies
// offers and fill signatures; it never creates them, Q7): a fresh random Transport key signs an
// offer and, once the operation exists, its fill. Consensus helpers (`Operation::approve`) build
// fully signed operations for the consensus side of differential checks. The approval helpers are
// the shared `flow.rs` (since phase 8 it types the confirmation phrase of a high-risk review too).
//
// Declared by a test file as:
//     #[path = "support/conditional_kit.rs"]
//     mod kit;
#![allow(dead_code)]

#[path = "flow.rs"]
mod flow;

use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    anchors::FinalizedAnchor,
    execution::State,
    trading_v1::{
        self, CandidatePolicy, Context, NativeError, NativeOperation, OfferBody, OfferProof,
        OfferTerms, Operation, SignedOffer, Strikes,
    },
    transactions::OutPoint,
};
use mutiny_crypto_v2::{HybridKey, HybridSignature, Role};
use mutiny_wallet_core_v8::{
    Blob, ChainView, HashLockRequest, KeySigner, OperationRequest, PartialApproval,
    SignedOperation, Signer, ops::conditional, plan,
};

pub fn zero() -> HybridSignature {
    HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    }
}

/// Public synthetic recipient B, acting as the current settlement wallet. Actual-chain
/// tests must explicitly select their own actual recipient or sender as the maker.
pub fn maker_key() -> HybridKey {
    HybridKey::wallet_restore(&format!("{}vote", "zoo ".repeat(23)), Role::WalletOwner).unwrap()
}

pub fn context_of(anchor: &FinalizedAnchor) -> Context {
    Context {
        network: NETWORK_ID,
        genesis: anchor.genesis,
        fingerprint: anchor.fingerprint,
    }
}

/// The maker signs a hash-linked offer.
#[allow(clippy::too_many_arguments)]
pub fn signed_offer(
    maker: &HybridKey,
    context: Context,
    created: u64,
    expiry: u64,
    amount: u64,
    maker_side: u8,
    nonce: u8,
) -> SignedOffer {
    SignedOffer::sign(
        OfferBody {
            context,
            maker_descriptor: maker.public().descriptor(1).unwrap(),
            maker_wallet: maker.public().address_id(1).unwrap(),
            destination: maker.public().address_id(1).unwrap(),
            condition: None,
            max_fee: Strikes(100_000),
            nonce: [nonce; 32],
            created,
            expiry,
            maker_side,
            terms: OfferTerms::HashLinked {
                amount: Strikes(amount),
                bitcoin_satoshis: 50_000,
                bitcoin_network: 3,
            },
        },
        maker,
    )
    .unwrap()
}

/// The canonical signed maker offer imported before the operation-specific fill exists.
pub fn offer_bytes(offer: &SignedOffer) -> Vec<u8> {
    offer.encode().unwrap()
}

/// The maker's fill over the exact operation in `raw` (any encoding of it: the fill signs the body).
pub fn fill_for(raw: &[u8], offer: &SignedOffer, maker: &HybridKey) -> Vec<u8> {
    let wire = NativeOperation::decode(raw).unwrap();
    OfferProof::sign(offer.clone(), &wire.operation, maker)
        .unwrap()
        .encode()
        .unwrap()
}

/// A fully signed operation built with the consensus helpers only (approvals by `signers` in slot
/// order, the maker's proof over the exact body when `maker` is given).
pub fn consensus_signed(
    mut op: Operation,
    inputs: Vec<OutPoint>,
    signers: &[(u8, &HybridKey)],
    maker: Option<(&SignedOffer, &HybridKey)>,
) -> Vec<u8> {
    op.approvals.clear();
    op.offer_proof = None;
    if let Some((offer, key)) = maker {
        op.offer_proof = Some(OfferProof::sign(offer.clone(), &op, key).unwrap());
    }
    for (slot, key) in signers {
        op.approve(*slot, key, 1).unwrap();
    }
    NativeOperation {
        operation: op,
        inputs,
    }
    .encode()
    .unwrap()
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

/// Explicit TEST-only reference history. The caller supplies the unchanged earlier
/// anchor for a synthetic unit model, or history returned by its own canonical chain.
/// No peer-provided anchor is accepted by a real wallet replica.
pub fn consensus_with_history(
    state: &State,
    anchor: &FinalizedAnchor,
    root: Hash,
    raw: &[u8],
    history: &mutiny_consensus_v8::evidence_history_v2::History,
) -> Result<(), NativeError> {
    trading_v1::prepare_batch_with_history(
        state,
        anchor,
        root,
        history,
        &[raw.to_vec()],
        &CandidatePolicy::native_denomination_locked(),
    )
    .map(|_| ())
}

/// Consensus' verdict against a view's state and head.
pub fn consensus_in(view: &ChainView<'_>, raw: &[u8]) -> Result<(), NativeError> {
    consensus(view.state(), view.anchor(), view.state_root(), raw)
}

/// Everything a person must do before the approval exists: present, type every destination check,
/// give every acknowledgement and, for a high-risk review, type the confirmation phrase (the shared
/// `support/flow.rs`). Not every test binary uses both.
#[allow(unused_imports)]
pub use flow::{approve, approve_on};

/// One funded hash lock: the complete operation, the sender's partial and the lock (output 0).
pub struct Lock {
    pub complete: SignedOperation,
    pub sender_partial: SignedOperation,
    pub id: Hash,
}

/// The whole multi-party funding of one lock at `view`'s head: the sender plans and signs a PARTIAL
/// operation (trade `0x21..`, contract `0x22..`), the recipient adopts it from the public container
/// and signs its own approval, the maker fills over the same body, and the parts are completed.
#[allow(clippy::too_many_arguments)]
pub fn fund_lock(
    view: &ChainView<'_>,
    sender_signer: &KeySigner,
    recipient_signer: &KeySigner,
    maker: &HybridKey,
    offer: &SignedOffer,
    condition: Hash,
    amount: u64,
    refund_height: u64,
) -> Lock {
    let recipient = recipient_signer.identity().address();
    let request = HashLockRequest::new(
        Blob::new(offer_bytes(offer)),
        recipient,
        amount,
        condition,
        refund_height,
    )
    .with_trade([0x21; 32])
    .with_contract([0x22; 32]);
    let planned = plan(
        &OperationRequest::HashLock(request),
        view,
        sender_signer.identity(),
    )
    .unwrap();
    let sender_partial = flow::sign(planned, sender_signer, view).unwrap();
    let container = PartialApproval::from_signed(&sender_partial, view.context()).unwrap();
    let adopted = container
        .adopt_for(view, recipient_signer.identity())
        .unwrap();
    let recipient_partial = flow::sign(adopted, recipient_signer, view).unwrap();
    let fill = fill_for(sender_partial.bytes(), offer, maker);
    let complete = conditional::complete(
        &[sender_partial.bytes(), recipient_partial.bytes()],
        Some(&fill),
        view,
    )
    .unwrap();
    let id = wire(complete.bytes()).operation.output_id(0).unwrap();
    Lock {
        complete,
        sender_partial,
        id,
    }
}

/// Decode a native trading operation.
pub fn wire(raw: &[u8]) -> NativeOperation {
    NativeOperation::decode(raw).unwrap()
}
