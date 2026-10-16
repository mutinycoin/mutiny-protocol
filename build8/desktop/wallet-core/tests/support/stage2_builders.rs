//! Shared TEST-VALUE integration builders. Every byte passes the actual wallet review gate.
//! These functions do not deliver, admit or confirm anything; callers supply those real paths.
#![allow(dead_code)]
#[path = "flow.rs"]
mod flow;
use mutiny_consensus_v8::{
    Hash,
    trading_offer_v2::{MakerOffer, OfferBody, OfferTerms},
    trading_v1::Strikes,
};
use mutiny_crypto_v2::HybridKey;
use mutiny_wallet_core_v8::*;

fn identity(key: &HybridKey) -> SignerIdentity {
    SignerIdentity::from_public(key.public(), 1, None).unwrap()
}

pub fn atomic_bond(
    view: &ChainView<'_>,
    key: HybridKey,
    node: Hash,
    node_generation: u64,
    principal: u64,
    nonce: Hash,
) -> SignedOperation {
    let me = identity(&key);
    let request =
        BondCreateRequest::new(node, node_generation, principal, nonce).with_validity_blocks(8);
    let p = plan(&OperationRequest::BondCreate(request), view, &me).unwrap();
    flow::sign(p, &KeySigner::for_test(key).unwrap(), view).unwrap()
}

/// Independent authorization/possession and named sponsor reviews, then exact canonical merge.
pub fn sponsored_rotation(
    view: &ChainView<'_>,
    current: HybridKey,
    proposed: HybridKey,
    sponsor: HybridKey,
) -> SignedOperation {
    let me = identity(&current);
    let sponsor_identity = identity(&sponsor);
    let descriptor = proposed.public().descriptor(2).unwrap();
    let fingerprint = ops::rotation::descriptor_fingerprint(&descriptor);
    let request = RotationRequest::new(
        Blob::new(descriptor),
        FeeSource::OtherWallet(sponsor_identity.clone()),
    )
    .with_restore_verified(fingerprint)
    .with_validity_blocks(8);
    let p = plan(&OperationRequest::WalletRotation(request), view, &me).unwrap();
    let approval = flow::approve(&review(&p, view).unwrap(), view);
    let first = ops::rotation::RotationSigner::for_test(current, me, proposed)
        .unwrap()
        .authorize(p, approval, view)
        .unwrap();
    assert!(!first.is_complete());
    let p = adopt(first.bytes(), view, &sponsor_identity).unwrap();
    let other = flow::sign(p, &KeySigner::for_test(sponsor).unwrap(), view).unwrap();
    let complete = ops::rotation::combine(&[first.bytes(), other.bytes()], view).unwrap();
    assert!(complete.is_complete());
    complete
}

pub fn native_hash_lock(
    view: &ChainView<'_>,
    key: HybridKey,
    recipient: HybridKey,
    amount: u64,
    nonce: Hash,
    condition: Hash,
    refund: u64,
) -> SignedOperation {
    let me = identity(&key);
    let created = view.next_height().unwrap();
    let body = OfferBody {
        context: mutiny_consensus_v8::trading_v1::Context {
            network: view.anchor().network,
            genesis: view.anchor().genesis,
            fingerprint: view.anchor().fingerprint,
        },
        maker_descriptor: me.descriptor().to_vec(),
        maker_wallet: me.address(),
        maker_side: 0,
        nonce,
        created,
        expiry: created + 8,
        terms: OfferTerms::HashLinked {
            amount: Strikes(amount),
            bitcoin_satoshis: 17,
            bitcoin_network: 1,
        },
        destination: me.address(),
        condition: Some(condition),
        max_fee: Strikes(100_000),
    };
    let p = plan(
        &OperationRequest::MakerOffer(MakerOfferRequest::new(Blob::new(body.encode().unwrap()))),
        view,
        &me,
    )
    .unwrap();
    let signer = KeySigner::for_test(key).unwrap();
    let offer = flow::sign(p, &signer, view).unwrap();
    let request = HashLockRequest::new(
        Blob::new(offer.bytes().to_vec()),
        identity(&recipient).address(),
        amount,
        condition,
        refund,
    )
    .with_trade(nonce)
    .with_contract(condition)
    .with_validity_blocks(8);
    let p = plan(&OperationRequest::HashLock(request), view, &me).unwrap();
    let first = flow::sign(p, &signer, view).unwrap();
    assert!(
        !first.is_complete(),
        "recipient approval is independently reviewed"
    );
    let recipient_identity = identity(&recipient);
    let p = adopt(first.bytes(), view, &recipient_identity).unwrap();
    let second = flow::sign(p, &KeySigner::for_test(recipient).unwrap(), view).unwrap();
    let complete =
        ops::conditional::complete(&[first.bytes(), second.bytes()], None, view).unwrap();
    assert!(complete.is_complete());
    complete
}

/// The wallet imports only public Worker possession; a device key never enters the planner.
pub fn fresh_worker_assignment(
    view: &ChainView<'_>,
    key: HybridKey,
    public: &mutiny_consensus_v8::license_assignment_v2::Assignment,
) -> SignedOperation {
    let me = identity(&key);
    let request = WorkerAssignmentRequest::new(
        Blob::new(public.enrollment.binding.bytes().unwrap()),
        Blob::new(public.node_descriptor.clone()),
        Blob::new(public.enrollment.worker_signature.to_vec()),
    );
    let p = plan(&OperationRequest::WorkerAssignment(request), view, &me).unwrap();
    assert_eq!(
        view.class(),
        ChainClass::TestValue,
        "actual fixture must declare its chain class"
    );
    let reviewed = review(&p, view).unwrap();
    assert!(
        reviewed
            .warnings()
            .iter()
            .any(|w| w.code == "TEST_VALUE_CHAIN")
    );
    assert!(reviewed.acknowledgements().contains(&AckKind::Conditions));
    assert_eq!(reviewed.net_debit(), Some(0));
    flow::sign(p, &KeySigner::for_test(key).unwrap(), view).unwrap()
}
/// Actual reviewed sale: current seller makes the exact offer and fill; buyer funds the
/// existing DVP carrier and both current wallet authorities authorize their respective slots.
pub fn license_sale(
    view: &ChainView<'_>,
    seller: HybridKey,
    buyer: HybridKey,
    license: Hash,
    price: u64,
    nonce: Hash,
) -> SignedOperation {
    let seller_me = identity(&seller);
    let buyer_me = identity(&buyer);
    let body = OfferBody {
        context: mutiny_consensus_v8::trading_v1::Context {
            network: view.anchor().network,
            genesis: view.anchor().genesis,
            fingerprint: view.anchor().fingerprint,
        },
        maker_descriptor: seller_me.descriptor().to_vec(),
        maker_wallet: seller_me.address(),
        maker_side: 0,
        nonce,
        created: view.next_height().unwrap(),
        expiry: view.next_height().unwrap() + 8,
        terms: OfferTerms::License {
            license,
            generation: mutiny_consensus_v8::trading_v1::license_generation(view.state(), license)
                .unwrap(),
            price: Strikes(price),
        },
        destination: seller_me.address(),
        condition: None,
        max_fee: Strikes(100_000),
    };
    let offer_plan = plan(
        &OperationRequest::MakerOffer(MakerOfferRequest::new(Blob::new(body.encode().unwrap()))),
        view,
        &seller_me,
    )
    .unwrap();
    let seller_signer = KeySigner::for_test(seller).unwrap();
    let offer = flow::sign(offer_plan, &seller_signer, view).unwrap();
    // Planning imports the signed offer. The seller's later approval creates the fill proof
    // over the exact buyer-built carrier; a zero-signature OfferProof is not an offer.
    let offer_bytes = offer.bytes().to_vec();
    let request = LicenseDvpRequest::new(Blob::new(offer_bytes), license)
        .with_commitments([0x7b; 32], [0x7c; 32])
        .with_seller_descriptor(Blob::new(seller_me.descriptor().to_vec()));
    let buyer_plan = plan(&OperationRequest::LicenseDvp(request), view, &buyer_me).unwrap();
    let buyer_part = flow::sign(buyer_plan, &KeySigner::for_test(buyer).unwrap(), view).unwrap();
    let seller_plan = adopt(buyer_part.bytes(), view, &seller_me).unwrap();
    let seller_part = flow::sign(seller_plan, &seller_signer, view).unwrap();
    let complete =
        mutiny_wallet_core_v8::offers::combine(&[buyer_part.bytes(), seller_part.bytes()], view)
            .unwrap();
    assert!(
        complete.is_complete(),
        "sale requires both wallet approvals and seller fill proof"
    );
    complete
}
