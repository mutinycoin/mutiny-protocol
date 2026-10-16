//! The refusal table of conditional MUT funding (phase 5A). Each refusal changes no state: no
//! outbox row, no signed bytes. Each is paired with consensus' verdict on the equivalent fully
//! signed operation (`trading_v1::prepare_batch`), so the wallet never refuses what consensus would
//! accept for the same reason, nor accepts what it refuses:
//!
//! | case | wallet | consensus |
//! |---|---|---|
//! | amount zero | `INVALID_AMOUNT` | `Candidate(OfferBinding)` (an offer never has a zero amount) |
//! | sender == recipient | `INVALID_RECIPIENT` | `Bounds` |
//! | refund height not above H | `INVALID_REQUEST` | `Bounds` |
//! | expiry not below the refund height | `INVALID_REQUEST` | `Bounds` |
//! | wrong preimage | `PREIMAGE_MISMATCH` | `Authority` |
//! | wrong recipient | `NOT_REQUIRED_SIGNER` / `INVALID_RECIPIENT` | `Authority` |
//! | claim at or after R | `WINDOW_CLOSED` | `Time` |
//! | refund before R | `NOT_YET_ELIGIBLE` | `Time` |
//! | missing counterparty approval | `COUNTERPARTY_APPROVAL_INVALID` | `Authority` |
//! | tampered counterparty approval | `COUNTERPARTY_APPROVAL_INVALID` | `Authority` |
//! | missing / invalid offer proof | `OFFER_PROOF_INVALID` | `Candidate(OfferBinding / Signature)` |
//! | offer bytes in neither accepted form | `MALFORMED` (W19; `OFFER_PROOF_INVALID` before) | (not an operation) |
//! | offer proof on a claim or refund | `OFFER_PROOF_INVALID` | `Candidate(OfferBinding)` |
//! | offer consumed | `OFFER_CONSUMED` | `Duplicate` |
//! | lock not found | `LOCK_NOT_FOUND` (`INPUT_UNAVAILABLE` before phase 8) | `Missing` |
//! | stale authority | `STALE_AUTHORITY` | `Authority` |
//! | fee below max(240, wire length) | `FEE_BELOW_MINIMUM` | `Fee` |
//! | inputs not sorted | not decodable (`UNKNOWN_OPERATION`) | not decodable |
//! | inputs != principal + change + fee | `CONSERVATION` | `Conservation` |
//! | input not a coin of the paying address | `INVALID_REQUEST` | `Authority` |
//! | input coin missing / immature coinbase | `INPUT_UNAVAILABLE` / `IMMATURE_INPUT` | `Missing` / `Immature` |
//! | refund owner is not the lock sender | `INVALID_REQUEST` | `Authority` |
//! | operation outside its validity window | `WINDOW_CLOSED` / `WINDOW_NOT_OPEN` | `Time` |
//! | wrong network / Genesis / fingerprint | `WRONG_CONTEXT` | `Context` |
//! | already applied | `REPLAY` | `Duplicate` |
//! | fiat lock claimed / refunded | `INVALID_REQUEST` / `CANCEL_NOT_AVAILABLE` | `FiatRecoveryUnspecified` |
//! | every cancellation but the hash-lock refund | `CANCEL_NOT_AVAILABLE` | (no such operation) |
//!
//! NATIVE, TEST-VALUE; public test keys; the maker is played by the test (Q7).
#[path = "support/conditional_kit.rs"]
mod kit;
#[path = "support/synthetic.rs"]
mod synthetic;

use mutiny_consensus_v8::{
    Hash,
    dividend_state_v1::DividendState,
    trading_v1::{
        self, Action, CandidatePolicy, Context, Error as TradeError, Meta, NativeError, NativeLock,
        NativeLockKind, NativeOperation, NativeRecord, OfferProof, Operation, SignedOffer, Strikes,
        native_input_id,
    },
    transactions::OutPoint,
    treasury_v1::{Class, Treasury},
};
use mutiny_crypto_v2::HybridKey;
use mutiny_wallet_core_v8::{
    ops::conditional::{self, LOCK_NAMESPACE, OFFER_NAMESPACE},
    *,
};
use std::collections::BTreeSet;
use synthetic::{World, address, descriptor, identity, key_a, key_b, key_c};

const AMOUNT: u64 = 1_000_000;
const REFUND: u64 = 150;

fn point(tag: u8) -> OutPoint {
    OutPoint {
        transaction: [tag; 32],
        index: 0,
    }
}

/// Head 100: A (the wallet, sender) holds 2,000,000 and 1,500,000; B (recipient) 500,000; C 400,000.
struct Scene {
    world: World,
    maker: HybridKey,
    offer: SignedOffer,
    preimage: [u8; 32],
}

impl Scene {
    fn new() -> Self {
        let mut world = World::with_wallets(100);
        world.coin(address(&key_a(), 1), 2_000_000, 1, false, 1, 0);
        world.coin(address(&key_a(), 1), 1_500_000, 1, false, 3, 0);
        world.coin(address(&key_b(), 1), 500_000, 1, false, 2, 0);
        world.coin(address(&key_c(), 1), 400_000, 1, false, 4, 0);
        let maker = kit::maker_key();
        let offer = kit::signed_offer(
            &maker,
            kit::context_of(&world.anchor),
            1,
            1000,
            AMOUNT,
            1,
            0x41,
        );
        Self {
            world,
            maker,
            offer,
            preimage: [0x42; 32],
        }
    }
    fn condition(&self) -> Hash {
        trading_v1::preimage_hash(&self.preimage)
    }
    fn context(&self) -> Context {
        kit::context_of(&self.world.anchor)
    }
    fn request(&self) -> HashLockRequest {
        HashLockRequest::new(
            Blob::new(kit::offer_bytes(&self.offer)),
            address(&key_b(), 1),
            AMOUNT,
            self.condition(),
            REFUND,
        )
        .with_trade([0x21; 32])
        .with_contract([0x22; 32])
    }
    /// A fully signed operation (consensus helpers only) for the consensus side of a case.
    fn signed(
        &self,
        op: Operation,
        inputs: Vec<OutPoint>,
        signers: &[(u8, &HybridKey)],
    ) -> Vec<u8> {
        let maker =
            matches!(op.action, Action::HashLock { .. }).then_some((&self.offer, &self.maker));
        kit::consensus_signed(op, inputs, signers, maker)
    }
    fn consensus(&self, raw: &[u8]) -> Result<(), NativeError> {
        kit::consensus_in(&self.world.view(), raw)
    }
}

/// The hash lock body consensus expects for this scene, with explicit fields.
#[allow(clippy::too_many_arguments)]
fn lock_op(
    scene: &Scene,
    sender: Hash,
    recipient: Hash,
    amount: u64,
    refund_height: u64,
    expiry: u64,
    fee: u64,
    change: u64,
    inputs: &[OutPoint],
) -> (Operation, Vec<OutPoint>) {
    let mut sorted = inputs.to_vec();
    sorted.sort_by_key(native_input_id);
    (
        Operation {
            meta: Meta {
                context: scene.context(),
                trade: [0x21; 32],
                contract: [0x22; 32],
                generation: 1,
                envelope: mutiny_consensus_v8::op_envelope_v1::Envelope {
                    first_height: 101, last_height: expiry,
                    reference_height: (101) - 1, reference_block: [3; 32],
                    preconditions: Vec::new(),
                },
                fee: Strikes(fee),
                inputs: sorted.iter().map(native_input_id).collect(),
            },
            action: Action::HashLock {
                offer: scene.offer.body.id().unwrap(),
                maker: scene.offer.body.maker().unwrap(),
                sender,
                recipient,
                amount: Strikes(amount),
                condition: scene.condition(),
                refund_height,
                change: Strikes(change),
            },
            approvals: vec![],
            offer_proof: None,
        },
        sorted,
    )
}

fn signer_a() -> KeySigner {
    KeySigner::for_test(key_a()).unwrap()
}
fn signer_b() -> KeySigner {
    KeySigner::for_test(key_b()).unwrap()
}

/// The whole pipeline: plan, review, every acknowledgement, authorize, queue. A refusal anywhere
/// must leave the outbox empty and return no signed bytes.
fn attempt(
    request: OperationRequest,
    view: &ChainView<'_>,
    signer: &KeySigner,
) -> Result<Hash, Refusal> {
    let mut outbox = MemoryOutbox::new();
    let result = (|| {
        let planned = plan(&request, view, signer.identity())?;
        let reviewed = review(&planned, view)?;
        let approval = kit::approve(&reviewed, view);
        let signed = signer.authorize(planned, approval, view)?;
        outbox.commit(&signed, view)
    })();
    if result.is_err() {
        assert!(
            outbox.records().unwrap().is_empty(),
            "a refusal queued something"
        );
        assert!(
            outbox.reserved().unwrap().is_empty(),
            "a refusal reserved something"
        );
    }
    result
}

/// Bytes refused on every entry point: explain, adopt and import (so they can never be queued).
fn assert_bytes_refused(raw: &[u8], view: &ChainView<'_>, me: &SignerIdentity, expected: &Refusal) {
    assert_eq!(&explain(raw, view, me).unwrap_err(), expected, "explain");
    assert_eq!(&adopt(raw, view, me).unwrap_err(), expected, "adopt");
    let mut outbox = MemoryOutbox::new();
    if let Ok(signed) = SignedOperation::import(raw, view) {
        assert!(outbox.commit(&signed, view).is_err());
    }
    assert!(outbox.records().unwrap().is_empty());
}

/// The sender's partial, the recipient's partial and the maker's fill for the scene's request.
fn parts(scene: &Scene) -> (SignedOperation, SignedOperation, Vec<u8>) {
    let view = scene.world.view();
    let planned = plan(
        &OperationRequest::HashLock(scene.request()),
        &view,
        &identity(&key_a()),
    )
    .unwrap();
    let reviewed = review(&planned, &view).unwrap();
    let sender = signer_a()
        .authorize(planned, kit::approve(&reviewed, &view), &view)
        .unwrap();
    let adopted = adopt(sender.bytes(), &view, &identity(&key_b())).unwrap();
    let reviewed = review(&adopted, &view).unwrap();
    let recipient = signer_b()
        .authorize(adopted, kit::approve(&reviewed, &view), &view)
        .unwrap();
    let fill = kit::fill_for(sender.bytes(), &scene.offer, &scene.maker);
    (sender, recipient, fill)
}

/// The scene one block later, with the scene's lock applied by consensus at height 101.
fn locked(scene: &Scene) -> (World, Hash, Vec<u8>) {
    let (sender, recipient, fill) = parts(scene);
    let view = scene.world.view();
    let complete =
        conditional::complete(&[sender.bytes(), recipient.bytes()], Some(&fill), &view).unwrap();
    let prepared = trading_v1::prepare_batch(
        &scene.world.state,
        &scene.world.anchor,
        view.state_root(),
        &[complete.bytes().to_vec()],
        &CandidatePolicy::native_denomination_locked(),
    )
    .unwrap();
    let mut next = scene.world.advanced();
    next.state = prepared.into_state();
    let id = kit::wire(complete.bytes()).operation.output_id(0).unwrap();
    (next, id, complete.bytes().to_vec())
}

fn at_height(world: &World, head: u64) -> World {
    let mut moved = World::with_wallets(head);
    moved.state = world.state.clone();
    moved
}

fn claim_op(
    lock: &NativeLock,
    id: Hash,
    recipient: Hash,
    preimage: [u8; 32],
    created: u64,
    parent: &mutiny_consensus_v8::anchors::FinalizedAnchor,
    input: &OutPoint,
    atoms: u64,
) -> (Operation, Vec<OutPoint>) {
    let fee = 10_000;
    (
        Operation {
            meta: Meta {
                context: lock.context.clone(),
                trade: lock.trade,
                contract: lock.contract,
                generation: lock.generation,
                envelope: mutiny_consensus_v8::op_envelope_v1::Envelope {
                    first_height: created, last_height: created + 20,
                    reference_height: parent.height, reference_block: parent.block,
                    preconditions: Vec::new(),
                },
                fee: Strikes(fee),
                inputs: vec![native_input_id(input)],
            },
            action: Action::Claim {
                output: id,
                recipient,
                amount: lock.amount,
                preimage,
                change: Strikes(atoms - fee),
            },
            approvals: vec![],
            offer_proof: None,
        },
        vec![input.clone()],
    )
}

fn refund_op(
    lock: &NativeLock,
    id: Hash,
    owner: Hash,
    created: u64,
    parent: &mutiny_consensus_v8::anchors::FinalizedAnchor,
    input: &OutPoint,
    atoms: u64,
) -> (Operation, Vec<OutPoint>) {
    let fee = 10_000;
    (
        Operation {
            meta: Meta {
                context: lock.context.clone(),
                trade: lock.trade,
                contract: lock.contract,
                generation: lock.generation,
                envelope: mutiny_consensus_v8::op_envelope_v1::Envelope {
                    first_height: created, last_height: created + 20,
                    reference_height: parent.height, reference_block: parent.block,
                    preconditions: Vec::new(),
                },
                fee: Strikes(fee),
                inputs: vec![native_input_id(input)],
            },
            action: Action::Refund {
                output: id,
                owner,
                amount: lock.amount,
                change: Strikes(atoms - fee),
            },
            approvals: vec![],
            offer_proof: None,
        },
        vec![input.clone()],
    )
}

/// The unsigned encoding of an operation (no approval, an all-zero fill if it has an offer).
fn unsigned(scene: &Scene, op: Operation, inputs: Vec<OutPoint>) -> Vec<u8> {
    let mut op = op;
    op.approvals.clear();
    if matches!(op.action, Action::HashLock { .. }) {
        op.offer_proof = Some(OfferProof {
            offer: scene.offer.clone(),
            fill_signature: kit::zero(),
        });
    }
    NativeOperation {
        operation: op,
        inputs,
    }
    .encode()
    .unwrap()
}

/// The scene's planned hash lock as an editable operation (unsigned form).
fn planned_wire(scene: &Scene) -> NativeOperation {
    let view = scene.world.view();
    let planned = plan(
        &OperationRequest::HashLock(scene.request()),
        &view,
        &identity(&key_a()),
    )
    .unwrap();
    kit::wire(&planned.objects()[0].bytes)
}

// ---------------------------------------------------------------------------------------------

#[test]
fn amount_zero_is_refused() {
    let scene = Scene::new();
    let view = scene.world.view();
    let mut request = scene.request();
    request.amount_atoms = 0;
    assert_eq!(
        attempt(OperationRequest::HashLock(request), &view, &signer_a()).unwrap_err(),
        Refusal::InvalidAmount
    );
    let a = address(&key_a(), 1);
    let (op, inputs) = lock_op(
        &scene,
        a,
        address(&key_b(), 1),
        0,
        REFUND,
        140,
        20_000,
        1_980_000,
        &[point(1)],
    );
    let raw = scene.signed(op, inputs, &[(0, &key_a()), (1, &key_b())]);
    assert_eq!(
        scene.consensus(&raw).unwrap_err(),
        NativeError::Candidate(TradeError::OfferBinding)
    );
}

#[test]
fn sender_equal_to_recipient_is_refused() {
    let mut scene = Scene::new();
    let mut body = scene.offer.body.clone();
    body.maker_descriptor = descriptor(&key_a(), 1);
    body.maker_wallet = address(&key_a(), 1);
    body.destination = address(&key_a(), 1);
    scene.maker = key_a();
    scene.offer = SignedOffer::sign(body, &scene.maker).unwrap();
    let view = scene.world.view();
    let a = address(&key_a(), 1);
    let mut request = scene.request();
    request.recipient = a;
    assert_eq!(
        attempt(OperationRequest::HashLock(request), &view, &signer_a()).unwrap_err(),
        Refusal::InvalidRecipient
    );
    let (op, inputs) = lock_op(
        &scene,
        a,
        a,
        AMOUNT,
        REFUND,
        140,
        20_000,
        980_000,
        &[point(1)],
    );
    let raw = scene.signed(op, inputs, &[(0, &key_a()), (1, &key_a())]);
    assert_eq!(scene.consensus(&raw).unwrap_err(), NativeError::Bounds);
}

#[test]
fn a_refund_height_not_above_the_inclusion_height_is_refused() {
    let scene = Scene::new();
    let view = scene.world.view();
    for refund in [100, 101] {
        let mut request = scene.request();
        request.refund_height = refund;
        assert_eq!(
            attempt(OperationRequest::HashLock(request), &view, &signer_a()).unwrap_err(),
            Refusal::InvalidRequest(
                "the refund height must be above the block that includes the lock"
            )
        );
    }
    let (op, inputs) = lock_op(
        &scene,
        address(&key_a(), 1),
        address(&key_b(), 1),
        AMOUNT,
        101,
        101,
        20_000,
        980_000,
        &[point(1)],
    );
    let raw = scene.signed(op, inputs, &[(0, &key_a()), (1, &key_b())]);
    assert_eq!(scene.consensus(&raw).unwrap_err(), NativeError::Bounds);
}

#[test]
fn an_operation_that_outlives_the_refund_height_is_refused() {
    let scene = Scene::new();
    let view = scene.world.view();
    let mut wire = planned_wire(&scene);
    wire.operation.meta.envelope.last_height = REFUND;
    let raw = wire.encode().unwrap();
    assert_bytes_refused(
        &raw,
        &view,
        &identity(&key_b()),
        &Refusal::InvalidRequest("the lock operation must expire before its refund height"),
    );
    let (op, inputs) = lock_op(
        &scene,
        address(&key_a(), 1),
        address(&key_b(), 1),
        AMOUNT,
        REFUND,
        REFUND,
        20_000,
        980_000,
        &[point(1)],
    );
    let raw = scene.signed(op, inputs, &[(0, &key_a()), (1, &key_b())]);
    assert_eq!(scene.consensus(&raw).unwrap_err(), NativeError::Bounds);
}

#[test]
fn a_wrong_preimage_is_refused() {
    let scene = Scene::new();
    let (world, id, _) = locked(&scene);
    let view = world.view();
    let request = ClaimRequest::new(id, Preimage::from_bytes([0x43; 32]));
    assert_eq!(
        attempt(
            OperationRequest::ConditionalClaim(request),
            &view,
            &signer_b()
        )
        .unwrap_err(),
        Refusal::PreimageMismatch
    );
    let lock = trading_v1::locked(&world.state, id).unwrap();
    let (op, inputs) = claim_op(
        &lock,
        id,
        address(&key_b(), 1),
        [0x43; 32],
        102, view.anchor(),
        &point(2),
        500_000,
    );
    let raw = scene.signed(op, inputs, &[(0, &key_b())]);
    assert_eq!(
        kit::consensus_in(&view, &raw).unwrap_err(),
        NativeError::Authority
    );
}

#[test]
fn a_claim_for_another_recipient_is_refused() {
    let scene = Scene::new();
    let (world, id, _) = locked(&scene);
    let view = world.view();
    let c = address(&key_c(), 1);
    // C is not the lock's recipient: it is not the required signer.
    let request = ClaimRequest::new(id, Preimage::from_bytes(scene.preimage));
    let signer_c = KeySigner::for_test(key_c()).unwrap();
    assert_eq!(
        attempt(
            OperationRequest::ConditionalClaim(request),
            &view,
            &signer_c
        )
        .unwrap_err(),
        Refusal::NotRequiredSigner(Slot::Approval(0))
    );
    // Claim bytes that name C as the recipient are refused as such.
    let lock = trading_v1::locked(&world.state, id).unwrap();
    let (op, inputs) = claim_op(&lock, id, c, scene.preimage, 102, view.anchor(), &point(4), 400_000);
    assert_bytes_refused(
        &unsigned(&scene, op.clone(), inputs.clone()),
        &view,
        &identity(&key_c()),
        &Refusal::InvalidRecipient,
    );
    let raw = scene.signed(op, inputs, &[(0, &key_c())]);
    assert_eq!(
        kit::consensus_in(&view, &raw).unwrap_err(),
        NativeError::Authority
    );
}

#[test]
fn a_claim_at_or_after_the_refund_height_is_refused() {
    let scene = Scene::new();
    let (world, id, _) = locked(&scene);
    let lock = trading_v1::locked(&world.state, id).unwrap();
    for head in [REFUND - 1, REFUND, REFUND + 10] {
        let late = at_height(&world, head);
        let view = late.view();
        let request = ClaimRequest::new(id, Preimage::from_bytes(scene.preimage));
        assert_eq!(
            attempt(
                OperationRequest::ConditionalClaim(request),
                &view,
                &signer_b()
            )
            .unwrap_err(),
            Refusal::WindowClosed {
                expiry: REFUND - 1,
                next_height: head + 1
            },
            "head {head}"
        );
        let (op, inputs) = claim_op(
            &lock,
            id,
            address(&key_b(), 1),
            scene.preimage,
            head + 1, view.anchor(),
            &point(2),
            500_000,
        );
        let raw = scene.signed(op, inputs, &[(0, &key_b())]);
        assert_eq!(
            kit::consensus_in(&view, &raw).unwrap_err(),
            NativeError::Time,
            "head {head}"
        );
    }
    // One block earlier both accept.
    let in_time = at_height(&world, REFUND - 2);
    let view = in_time.view();
    let request = ClaimRequest::new(id, Preimage::from_bytes(scene.preimage));
    assert!(
        attempt(
            OperationRequest::ConditionalClaim(request),
            &view,
            &signer_b()
        )
        .is_ok()
    );
    let (op, inputs) = claim_op(
        &lock,
        id,
        address(&key_b(), 1),
        scene.preimage,
        REFUND - 1, view.anchor(),
        &point(2),
        500_000,
    );
    kit::consensus_in(&view, &scene.signed(op, inputs, &[(0, &key_b())])).unwrap();
}

#[test]
fn a_refund_before_the_refund_height_is_refused() {
    let scene = Scene::new();
    let (world, id, _) = locked(&scene);
    let lock = trading_v1::locked(&world.state, id).unwrap();
    for head in [101, REFUND - 2] {
        let early = at_height(&world, head);
        let view = early.view();
        assert_eq!(
            attempt(
                OperationRequest::ConditionalRefund(RefundRequest::new(id)),
                &view,
                &signer_a()
            )
            .unwrap_err(),
            Refusal::NotYetEligible {
                what: "Refunding this hash lock",
                height: REFUND
            },
            "head {head}"
        );
        let (op, inputs) = refund_op(
            &lock,
            id,
            address(&key_a(), 1),
            head + 1, view.anchor(),
            &point(3),
            1_500_000,
        );
        let raw = scene.signed(op, inputs, &[(0, &key_a())]);
        assert_eq!(
            kit::consensus_in(&view, &raw).unwrap_err(),
            NativeError::Time,
            "head {head}"
        );
    }
    // From the refund height on both accept.
    let due = at_height(&world, REFUND - 1);
    let view = due.view();
    assert!(
        attempt(
            OperationRequest::ConditionalRefund(RefundRequest::new(id)),
            &view,
            &signer_a()
        )
        .is_ok()
    );
    let (op, inputs) = refund_op(
        &lock,
        id,
        address(&key_a(), 1),
        REFUND, view.anchor(),
        &point(3),
        1_500_000,
    );
    kit::consensus_in(&view, &scene.signed(op, inputs, &[(0, &key_a())])).unwrap();
}

#[test]
fn a_missing_counterparty_approval_is_refused() {
    let scene = Scene::new();
    let view = scene.world.view();
    let (sender, _, fill) = parts(&scene);
    assert_eq!(
        conditional::complete(&[sender.bytes()], Some(&fill), &view).unwrap_err(),
        Refusal::CounterpartyApprovalInvalid
    );
    // The partial alone is honestly partial: it can be queued only as what it is.
    let imported = SignedOperation::import(sender.bytes(), &view).unwrap();
    assert!(!imported.is_complete());
    let mut outbox = MemoryOutbox::new();
    let lie = SignedOperation::Complete {
        kind: OperationKind::HashLock,
        id: imported.id(),
        bytes: sender.bytes().to_vec(),
        validity: *imported.validity(),
        reserved: imported.reserved().to_vec(),
    };
    assert!(matches!(
        outbox.commit(&lie, &view),
        Err(Refusal::VerificationFailed(_))
    ));
    assert!(outbox.records().unwrap().is_empty());
    // Consensus: the slot set must be exactly {0, 1}.
    let mut op = kit::wire(sender.bytes()).operation;
    op.offer_proof = Some(OfferProof::decode(&fill).unwrap());
    let raw = NativeOperation {
        operation: op,
        inputs: kit::wire(sender.bytes()).inputs,
    }
    .encode()
    .unwrap();
    assert_eq!(scene.consensus(&raw).unwrap_err(), NativeError::Authority);
}

/// Every signature a completion is offered must verify, as `offers::combine` requires: a tampered
/// approval is refused even NEXT TO a valid one for the same slot, and a part's fill signature that
/// does not verify is refused next to the maker's valid fill (both were silently dropped before
/// the fixes of the independent wallet review). Without the stray signatures the same parts
/// complete.
#[test]
fn an_invalid_signature_beside_a_valid_one_for_the_same_slot_is_refused() {
    let scene = Scene::new();
    let view = scene.world.view();
    let (sender, recipient, fill) = parts(&scene);
    let mut wire = kit::wire(recipient.bytes());
    wire.operation.approvals[0].signature.fndsa[9] ^= 1;
    let tampered = wire.encode().unwrap();
    for order in [
        [sender.bytes(), recipient.bytes(), tampered.as_slice()],
        [sender.bytes(), tampered.as_slice(), recipient.bytes()],
    ] {
        assert_eq!(
            conditional::complete(&order, Some(&fill), &view).unwrap_err(),
            Refusal::CounterpartyApprovalInvalid
        );
    }
    let mut bad = OfferProof::decode(&fill).unwrap();
    bad.fill_signature.ed448[0] ^= 1;
    let mut with_bad_fill = kit::wire(recipient.bytes());
    with_bad_fill.operation.offer_proof = Some(bad);
    let with_bad_fill = with_bad_fill.encode().unwrap();
    assert_eq!(
        conditional::complete(&[sender.bytes(), &with_bad_fill], Some(&fill), &view).unwrap_err(),
        Refusal::OfferProofInvalid
    );
    assert!(
        conditional::complete(&[sender.bytes(), recipient.bytes()], Some(&fill), &view)
            .unwrap()
            .is_complete()
    );
}

#[test]
fn a_tampered_counterparty_approval_is_refused() {
    let scene = Scene::new();
    let view = scene.world.view();
    let (sender, recipient, fill) = parts(&scene);
    for half in 0..2 {
        let mut wire = kit::wire(recipient.bytes());
        let signature = &mut wire.operation.approvals[0].signature;
        if half == 0 {
            signature.ed448[7] ^= 1;
        } else {
            signature.fndsa[9] ^= 1;
        }
        let tampered = wire.encode().unwrap();
        assert_eq!(
            conditional::complete(&[sender.bytes(), &tampered], Some(&fill), &view).unwrap_err(),
            Refusal::CounterpartyApprovalInvalid
        );
        assert_eq!(
            explain(&tampered, &view, &identity(&key_a())).unwrap_err(),
            Refusal::CounterpartyApprovalInvalid
        );
        assert_eq!(
            adopt(&tampered, &view, &identity(&key_a())).unwrap_err(),
            Refusal::CounterpartyApprovalInvalid
        );
        assert!(SignedOperation::import(&tampered, &view).is_err());
        // Consensus: the slot-1 authorization fails.
        let mut op = kit::wire(&tampered).operation;
        op.approvals
            .insert(0, kit::wire(sender.bytes()).operation.approvals[0].clone());
        op.offer_proof = Some(OfferProof::decode(&fill).unwrap());
        let raw = NativeOperation {
            operation: op,
            inputs: wire.inputs.clone(),
        }
        .encode()
        .unwrap();
        assert_eq!(scene.consensus(&raw).unwrap_err(), NativeError::Authority);
    }
}

#[test]
fn a_missing_or_invalid_offer_proof_is_refused() {
    let scene = Scene::new();
    let view = scene.world.view();
    let me = identity(&key_a());
    let refused = |offer: Vec<u8>| {
        let mut request = scene.request();
        request.offer = Blob::new(offer);
        attempt(OperationRequest::HashLock(request), &view, &signer_a()).unwrap_err()
    };
    // Not an offer, a damaged offer signature, a fill signature already present. Bytes in neither
    // accepted offer form are MALFORMED on every path since W19 (before: OFFER_PROOF_INVALID here).
    assert_eq!(refused(vec![1, 2, 3]).code(), "MALFORMED");
    let mut damaged = scene.offer.clone();
    damaged.signature.fndsa[3] ^= 1;
    assert_eq!(
        refused(kit::offer_bytes(&damaged)),
        Refusal::Malformed("not a canonical maker offer")
    );
    let prefilled = OfferProof {
        offer: scene.offer.clone(),
        fill_signature: scene.offer.signature.clone(),
    }
    .encode()
    .unwrap();
    assert_eq!(refused(prefilled).code(), "MALFORMED");
    // Hash-lock bytes without any offer proof.
    let mut wire = planned_wire(&scene);
    wire.operation.offer_proof = None;
    assert_bytes_refused(
        &wire.encode().unwrap(),
        &view,
        &me,
        &Refusal::OfferProofInvalid,
    );
    // Completion without a fill, or with one that does not verify.
    let (sender, recipient, fill) = parts(&scene);
    // B is now the current maker and signs the fill as part of its reviewed approval.
    // Its valid fill needs no separate external copy. Remove only that fill to
    // construct the missing-fill negative; approval commitments stay unchanged.
    assert!(conditional::complete(&[sender.bytes(), recipient.bytes()], None, &view).is_ok());
    let mut unfilled = kit::wire(recipient.bytes());
    unfilled.operation.offer_proof.as_mut().unwrap().fill_signature = kit::zero();
    let unfilled = unfilled.encode().unwrap();
    assert_eq!(
        conditional::complete(&[sender.bytes(), &unfilled], None, &view).unwrap_err(),
        Refusal::OfferProofInvalid
    );
    let mut bad = OfferProof::decode(&fill).unwrap();
    bad.fill_signature.ed448[0] ^= 1;
    assert_eq!(
        conditional::complete(
            &[sender.bytes(), recipient.bytes()],
            Some(&bad.encode().unwrap()),
            &view
        )
        .unwrap_err(),
        Refusal::OfferProofInvalid
    );
    // Consensus: no proof at all, and a fill that does not verify.
    let (op, inputs) = lock_op(
        &scene,
        address(&key_a(), 1),
        address(&key_b(), 1),
        AMOUNT,
        REFUND,
        140,
        20_000,
        980_000,
        &[point(1)],
    );
    let none = kit::consensus_signed(
        op.clone(),
        inputs.clone(),
        &[(0, &key_a()), (1, &key_b())],
        None,
    );
    assert_eq!(
        scene.consensus(&none).unwrap_err(),
        NativeError::Candidate(TradeError::OfferBinding)
    );
    let mut wire = kit::wire(&scene.signed(op, inputs, &[(0, &key_a()), (1, &key_b())]));
    wire.operation
        .offer_proof
        .as_mut()
        .unwrap()
        .fill_signature
        .ed448[0] ^= 1;
    assert_eq!(
        scene.consensus(&wire.encode().unwrap()).unwrap_err(),
        NativeError::Candidate(TradeError::Signature)
    );
}

#[test]
fn an_offer_proof_on_a_claim_or_a_refund_is_refused() {
    let scene = Scene::new();
    let (world, id, _) = locked(&scene);
    let lock = trading_v1::locked(&world.state, id).unwrap();
    let view = world.view();
    let proof = OfferProof {
        offer: scene.offer.clone(),
        fill_signature: kit::zero(),
    };
    let (mut claim, inputs) = claim_op(
        &lock,
        id,
        address(&key_b(), 1),
        scene.preimage,
        102, view.anchor(),
        &point(2),
        500_000,
    );
    claim.offer_proof = Some(proof.clone());
    let raw = NativeOperation {
        operation: claim.clone(),
        inputs: inputs.clone(),
    }
    .encode()
    .unwrap();
    assert_bytes_refused(
        &raw,
        &view,
        &identity(&key_b()),
        &Refusal::OfferProofInvalid,
    );
    let mut signed = claim;
    signed.approve(0, &key_b(), 1).unwrap();
    let raw = NativeOperation {
        operation: signed,
        inputs,
    }
    .encode()
    .unwrap();
    assert_eq!(
        kit::consensus_in(&view, &raw).unwrap_err(),
        NativeError::Candidate(TradeError::OfferBinding)
    );
    // The same for a refund (at its height).
    let due = at_height(&world, REFUND);
    let view = due.view();
    let (mut refund, inputs) = refund_op(
        &lock,
        id,
        address(&key_a(), 1),
        REFUND + 1, view.anchor(),
        &point(3),
        1_500_000,
    );
    refund.offer_proof = Some(proof);
    let raw = NativeOperation {
        operation: refund.clone(),
        inputs: inputs.clone(),
    }
    .encode()
    .unwrap();
    assert_bytes_refused(
        &raw,
        &view,
        &identity(&key_a()),
        &Refusal::OfferProofInvalid,
    );
    refund.approve(0, &key_a(), 1).unwrap();
    let raw = NativeOperation {
        operation: refund,
        inputs,
    }
    .encode()
    .unwrap();
    assert_eq!(
        kit::consensus_in(&view, &raw).unwrap_err(),
        NativeError::Candidate(TradeError::OfferBinding)
    );
}

#[test]
fn a_consumed_offer_is_refused() {
    let scene = Scene::new();
    let (world, _, _) = locked(&scene);
    let view = world.view();
    assert_eq!(
        attempt(
            OperationRequest::HashLock(scene.request()),
            &view,
            &signer_a()
        )
        .unwrap_err(),
        Refusal::OfferConsumed
    );
    // Consensus: the single-fill record exists; a second funding with good coins is a duplicate.
    let (mut op, inputs) = lock_op(
        &scene,
        address(&key_a(), 1),
        address(&key_b(), 1),
        AMOUNT,
        REFUND,
        140,
        20_000,
        480_000,
        &[point(3)],
    );
    op.meta.envelope.first_height = view.anchor().height + 1;
    op.meta.envelope.reference_height = view.anchor().height;
    op.meta.envelope.reference_block = view.anchor().block;
    op.meta.trade = [0x51; 32];
    let raw = scene.signed(op, inputs, &[(0, &key_a()), (1, &key_b())]);
    assert_eq!(
        kit::consensus_in(&view, &raw).unwrap_err(),
        NativeError::Duplicate
    );
    // The same funding received as bytes (fully signed, every signature valid) is refused too.
    assert_eq!(
        explain(&raw, &view, &identity(&key_b())).unwrap_err(),
        Refusal::OfferConsumed
    );
    assert!(SignedOperation::import(&raw, &view).is_err());
}

#[test]
fn a_lock_that_does_not_exist_is_refused() {
    let scene = Scene::new();
    let (world, id, _) = locked(&scene);
    let lock = trading_v1::locked(&world.state, id).unwrap();
    let view = world.view();
    let ghost = [0x99; 32];
    assert_eq!(
        attempt(
            OperationRequest::ConditionalClaim(ClaimRequest::new(
                ghost,
                Preimage::from_bytes(scene.preimage)
            )),
            &view,
            &signer_b()
        )
        .unwrap_err(),
        Refusal::LockNotFound
    );
    assert_eq!(
        attempt(
            OperationRequest::ConditionalRefund(RefundRequest::new(ghost)),
            &view,
            &signer_a()
        )
        .unwrap_err(),
        Refusal::LockNotFound
    );
    assert_eq!(
        attempt(
            OperationRequest::Cancel(CancelRequest::new(CancelTarget::HashLockRefund(ghost))),
            &view,
            &signer_a()
        )
        .unwrap_err(),
        Refusal::LockNotFound
    );
    let (op, inputs) = claim_op(
        &lock,
        ghost,
        address(&key_b(), 1),
        scene.preimage,
        102, view.anchor(),
        &point(2),
        500_000,
    );
    assert_bytes_refused(
        &unsigned(&scene, op.clone(), inputs.clone()),
        &view,
        &identity(&key_b()),
        &Refusal::LockNotFound,
    );
    let raw = scene.signed(op, inputs, &[(0, &key_b())]);
    assert_eq!(
        kit::consensus_in(&view, &raw).unwrap_err(),
        NativeError::Missing
    );
}

#[test]
fn a_rotated_away_key_is_refused() {
    let scene = Scene::new();
    let mut world = at_height(&scene.world, 100);
    let a = address(&key_a(), 1);
    assert_eq!(world.state.wallets.current(a), Some(descriptor(&key_a(), 1).as_slice()));
    let mut rotation = mutiny_consensus_v8::wallet_rotation_v1::Rotation {
        network: world.anchor.network,
        genesis: world.anchor.genesis,
        fingerprint: world.anchor.fingerprint,
        authority: a,
        current: descriptor(&key_a(), 1),
        proposed: descriptor(&key_c(), 2),
        created_height: 90,
        expiry_height: 120,
        authorization: kit::zero(),
        possession: kit::zero(),
    };
    rotation.sign(&key_a(), &key_c()).unwrap();
    world
        .state
        .wallets
        .apply(
            &rotation,
            world.anchor.genesis,
            world.anchor.fingerprint,
            100,
        )
        .unwrap();
    let view = world.view();
    assert_eq!(
        attempt(
            OperationRequest::HashLock(scene.request()),
            &view,
            &signer_a()
        )
        .unwrap_err(),
        Refusal::StaleAuthority
    );
    // A plan made before the rotation is stale at the new head.
    let before = scene.world.view();
    let planned = plan(
        &OperationRequest::HashLock(scene.request()),
        &before,
        &identity(&key_a()),
    )
    .unwrap();
    assert_eq!(
        review(&planned, &view).unwrap_err(),
        Refusal::StaleAuthority
    );
    // Consensus: the old descriptor no longer authorizes the sender address.
    let (op, inputs) = lock_op(
        &scene,
        a,
        address(&key_b(), 1),
        AMOUNT,
        REFUND,
        140,
        20_000,
        980_000,
        &[point(1)],
    );
    let raw = scene.signed(op, inputs, &[(0, &key_a()), (1, &key_b())]);
    assert_eq!(
        kit::consensus_in(&view, &raw).unwrap_err(),
        NativeError::Authority
    );
}

#[test]
fn a_fee_below_the_wire_length_is_refused() {
    let scene = Scene::new();
    let view = scene.world.view();
    let mut wire = planned_wire(&scene);
    let fee = wire.operation.meta.fee.0;
    wire.operation.meta.fee = Strikes(240);
    if let Action::HashLock { change, .. } = &mut wire.operation.action {
        change.0 += fee - 240;
    }
    let raw = wire.encode().unwrap();
    let refusal = explain(&raw, &view, &identity(&key_a())).unwrap_err();
    assert!(
        matches!(refusal, Refusal::FeeBelowMinimum { fee: 240, minimum } if minimum > 240 && minimum <= fee),
        "{refusal:?}"
    );
    assert_bytes_refused(&raw, &view, &identity(&key_a()), &refusal);
    let (op, inputs) = lock_op(
        &scene,
        address(&key_a(), 1),
        address(&key_b(), 1),
        AMOUNT,
        REFUND,
        140,
        240,
        999_760,
        &[point(1)],
    );
    let raw = scene.signed(op, inputs, &[(0, &key_a()), (1, &key_b())]);
    assert_eq!(scene.consensus(&raw).unwrap_err(), NativeError::Fee);
    // Exactly the minimum is accepted by both (the wallet's own fee is that fixed point).
    assert!(fee >= 240);
}

#[test]
fn inputs_out_of_native_order_cannot_even_be_decoded() {
    // A lock that needs two coins of A.
    let mut scene = Scene::new();
    scene.world = World::with_wallets(100);
    scene
        .world
        .coin(address(&key_a(), 1), 600_000, 1, false, 1, 0);
    scene
        .world
        .coin(address(&key_a(), 1), 500_000, 1, false, 3, 0);
    let wire = planned_wire(&scene);
    assert_eq!(wire.inputs.len(), 2);
    let raw = wire.encode().unwrap();
    let (first, second) = (wire.operation.meta.inputs[0], wire.operation.meta.inputs[1]);
    assert!(first < second);
    // Swap the two identifiers inside the signed body: same lengths, wrong order.
    let at_first = raw.windows(32).position(|w| w == first).unwrap();
    let at_second = raw.windows(32).position(|w| w == second).unwrap();
    let mut swapped = raw.clone();
    swapped[at_first..at_first + 32].copy_from_slice(&second);
    swapped[at_second..at_second + 32].copy_from_slice(&first);
    let view = scene.world.view();
    assert!(
        NativeOperation::decode(&swapped).is_err(),
        "consensus refuses the encoding"
    );
    assert!(kit::consensus_in(&view, &swapped).is_err());
    assert_bytes_refused(
        &swapped,
        &view,
        &identity(&key_a()),
        &Refusal::UnknownOperation,
    );
}

#[test]
fn inputs_that_do_not_equal_principal_change_and_fee_are_refused() {
    let scene = Scene::new();
    let view = scene.world.view();
    for delta in [1i64, -1] {
        let mut wire = planned_wire(&scene);
        if let Action::HashLock { change, .. } = &mut wire.operation.action {
            change.0 = (change.0 as i64 + delta) as u64;
        }
        assert_bytes_refused(
            &wire.encode().unwrap(),
            &view,
            &identity(&key_a()),
            &Refusal::Conservation,
        );
    }
    let (op, inputs) = lock_op(
        &scene,
        address(&key_a(), 1),
        address(&key_b(), 1),
        AMOUNT,
        REFUND,
        140,
        20_000,
        980_001,
        &[point(1)],
    );
    let raw = scene.signed(op, inputs, &[(0, &key_a()), (1, &key_b())]);
    assert_eq!(
        scene.consensus(&raw).unwrap_err(),
        NativeError::Conservation
    );
}

#[test]
fn another_network_genesis_or_fingerprint_is_refused() {
    let scene = Scene::new();
    let view = scene.world.view();
    let me = identity(&key_a());
    for field in 0..3 {
        let mut wire = planned_wire(&scene);
        let context = &mut wire.operation.meta.context;
        let expected = match field {
            0 => {
                context.network ^= 1;
                ContextField::Network
            }
            1 => {
                context.genesis[0] ^= 1;
                ContextField::Genesis
            }
            _ => {
                context.fingerprint[0] ^= 1;
                ContextField::Fingerprint
            }
        };
        assert_bytes_refused(
            &wire.encode().unwrap(),
            &view,
            &me,
            &Refusal::WrongContext(expected),
        );
        let (mut op, inputs) = lock_op(
            &scene,
            address(&key_a(), 1),
            address(&key_b(), 1),
            AMOUNT,
            REFUND,
            140,
            20_000,
            980_000,
            &[point(1)],
        );
        op.meta.context = wire.operation.meta.context.clone();
        let raw = kit::consensus_signed(op, inputs, &[(0, &key_a()), (1, &key_b())], None);
        assert_eq!(scene.consensus(&raw).unwrap_err(), NativeError::Context);
    }
    // An offer made for another chain is refused at import.
    let mut other = scene.context();
    other.genesis[1] ^= 1;
    let foreign = kit::signed_offer(&scene.maker, other, 1, 1000, AMOUNT, 1, 0x44);
    let mut request = scene.request();
    request.offer = Blob::new(kit::offer_bytes(&foreign));
    assert_eq!(
        attempt(OperationRequest::HashLock(request), &view, &signer_a()).unwrap_err(),
        Refusal::WrongContext(ContextField::Genesis)
    );
}

#[test]
fn an_operation_already_applied_is_a_replay() {
    let scene = Scene::new();
    let (world, _, complete) = locked(&scene);
    let mut history = mutiny_consensus_v8::evidence_history_v2::History::default();
    history.insert_anchor(scene.world.anchor.height, scene.world.anchor.block).unwrap();
    let view = world.view().with_history(&history);
    assert_eq!(
        explain(&complete, &view, &identity(&key_a())).unwrap_err(),
        Refusal::Replay
    );
    assert!(SignedOperation::import(&complete, &view).is_err());
    assert_eq!(
        kit::consensus_with_history(view.state(), view.anchor(), view.state_root(), &complete, &history).unwrap_err(),
        NativeError::Duplicate
    );
}

#[test]
fn a_fiat_lock_can_be_neither_claimed_nor_refunded() {
    let scene = Scene::new();
    let mut world = at_height(&scene.world, 100);
    let a = address(&key_a(), 1);
    let b = address(&key_b(), 1);
    let id = [0x5f; 32];
    let lock = NativeLock {
        context: scene.context(),
        trade: [0x21; 32],
        contract: [0x22; 32],
        generation: 1,
        sender: a,
        recipient: b,
        amount: Strikes(5_000),
        created_height: 50,
        kind: NativeLockKind::Fiat { terms: [9; 32] },
    };
    world.state.protocol_records.insert(
        trading_v1::record_key(0, id),
        NativeRecord::Lock(lock.clone()).encode(id).unwrap(),
    );
    let view = world.view();
    assert_eq!(
        attempt(
            OperationRequest::ConditionalClaim(ClaimRequest::new(
                id,
                Preimage::from_bytes(scene.preimage)
            )),
            &view,
            &signer_b()
        )
        .unwrap_err(),
        Refusal::InvalidRequest(
            "a fiat lock has no hash condition: it is released by both parties, never claimed"
        )
    );
    assert_eq!(
        attempt(
            OperationRequest::ConditionalRefund(RefundRequest::new(id)),
            &view,
            &signer_a()
        )
        .unwrap_err(),
        Refusal::CancelNotAvailable(CancelTarget::FiatLock)
    );
    let (op, inputs) = claim_op(&lock, id, b, scene.preimage, 101, view.anchor(), &point(2), 500_000);
    let raw = scene.signed(op, inputs, &[(0, &key_b())]);
    assert_eq!(
        kit::consensus_in(&view, &raw).unwrap_err(),
        NativeError::FiatRecoveryUnspecified
    );
    let (op, inputs) = refund_op(&lock, id, a, 101, view.anchor(), &point(3), 1_500_000);
    let raw = scene.signed(op, inputs, &[(0, &key_a())]);
    assert_eq!(
        kit::consensus_in(&view, &raw).unwrap_err(),
        NativeError::FiatRecoveryUnspecified
    );
}

#[test]
fn every_cancellation_but_the_hash_lock_refund_is_refused_and_the_refund_is_routed() {
    let scene = Scene::new();
    let (world, id, _) = locked(&scene);
    let due = at_height(&world, REFUND);
    let view = due.view();
    for target in [
        CancelTarget::Offer,
        CancelTarget::Reservation,
        CancelTarget::SignedOperation,
        CancelTarget::Unbond,
        CancelTarget::FiatLock,
        CancelTarget::DividendClaim,
        CancelTarget::LicenseDvp,
    ] {
        let refusal = attempt(
            OperationRequest::Cancel(CancelRequest::new(target)),
            &view,
            &signer_a(),
        )
        .unwrap_err();
        assert_eq!(refusal, Refusal::CancelNotAvailable(target));
        assert_eq!(refusal.code(), "CANCEL_NOT_AVAILABLE");
    }
    let routed = plan(
        &OperationRequest::Cancel(CancelRequest::new(CancelTarget::HashLockRefund(id))),
        &view,
        &identity(&key_a()),
    )
    .unwrap();
    let direct = plan(
        &OperationRequest::ConditionalRefund(RefundRequest::new(id)),
        &view,
        &identity(&key_a()),
    )
    .unwrap();
    assert_eq!(routed.kind(), OperationKind::ConditionalRefund);
    assert_eq!(routed.id(), direct.id());
    // Before the refund height the routed cancellation is refused exactly like the refund.
    let early = world.view();
    assert_eq!(
        attempt(
            OperationRequest::Cancel(CancelRequest::new(CancelTarget::HashLockRefund(id))),
            &early,
            &signer_a()
        )
        .unwrap_err(),
        Refusal::NotYetEligible {
            what: "Refunding this hash lock",
            height: REFUND
        }
    );
}

#[test]
fn reserved_coins_offers_and_locks_are_refused() {
    let scene = Scene::new();
    // The offer is reserved by another pending plan.
    let mut world = at_height(&scene.world, 100);
    world.reserved = BTreeSet::from([resource_key(
        OFFER_NAMESPACE,
        &scene.offer.body.id().unwrap(),
    )]);
    assert_eq!(
        attempt(
            OperationRequest::HashLock(scene.request()),
            &world.view(),
            &signer_a()
        )
        .unwrap_err(),
        Refusal::ReservedInput
    );
    // A reserved coin is never selected: with both of A's coins reserved nothing is spendable.
    world.reserved = BTreeSet::from([point(1), point(3)]);
    assert_eq!(
        attempt(
            OperationRequest::HashLock(scene.request()),
            &world.view(),
            &signer_a()
        )
        .unwrap_err(),
        Refusal::NothingSpendable
    );
    // A plan whose coin became reserved is refused at review.
    let planned = plan(
        &OperationRequest::HashLock(scene.request()),
        &scene.world.view(),
        &identity(&key_a()),
    )
    .unwrap();
    world.reserved = BTreeSet::from([planned.inputs()[0].clone()]);
    assert_eq!(
        review(&planned, &world.view()).unwrap_err(),
        Refusal::ReservedInput
    );
    // The lock is reserved by a pending claim or refund: neither can be planned again.
    let (locked_world, id, _) = locked(&scene);
    let mut held = at_height(&locked_world, REFUND);
    held.reserved = BTreeSet::from([resource_key(LOCK_NAMESPACE, &id)]);
    assert_eq!(
        attempt(
            OperationRequest::ConditionalRefund(RefundRequest::new(id)),
            &held.view(),
            &signer_a()
        )
        .unwrap_err(),
        Refusal::ReservedInput
    );
    let mut held = at_height(&locked_world, 101);
    held.reserved = BTreeSet::from([resource_key(LOCK_NAMESPACE, &id)]);
    assert_eq!(
        attempt(
            OperationRequest::ConditionalClaim(ClaimRequest::new(
                id,
                Preimage::from_bytes(scene.preimage)
            )),
            &held.view(),
            &signer_b()
        )
        .unwrap_err(),
        Refusal::ReservedInput
    );
}

#[test]
fn request_fields_out_of_range_are_refused() {
    let scene = Scene::new();
    let view = scene.world.view();
    let refused = |request: HashLockRequest| {
        attempt(OperationRequest::HashLock(request), &view, &signer_a()).unwrap_err()
    };
    assert_eq!(
        refused(scene.request().with_validity_blocks(0)),
        Refusal::InvalidValidity
    );
    assert_eq!(
        refused(scene.request().with_validity_blocks(10_081)),
        Refusal::InvalidValidity
    );
    assert_eq!(
        refused(scene.request().with_generation(0)),
        Refusal::InvalidRequest("the trade generation must be at least 1")
    );
    let mut other_amount = scene.request();
    other_amount.amount_atoms = AMOUNT + 1;
    assert_eq!(
        refused(other_amount),
        Refusal::InvalidRequest("the amount must equal the amount of the maker's offer")
    );
    let mut zero_recipient = scene.request();
    zero_recipient.recipient = [0; 32];
    assert_eq!(refused(zero_recipient), Refusal::InvalidRecipient);
    // The offer's own window.
    let mut request = scene.request();
    request.offer = Blob::new(kit::offer_bytes(&kit::signed_offer(
        &scene.maker,
        scene.context(),
        200,
        1000,
        AMOUNT,
        1,
        0x45,
    )));
    assert_eq!(
        refused(request),
        Refusal::OfferNotYetValid {
            created: 200,
            next_height: 101
        }
    );
    let mut request = scene.request();
    request.offer = Blob::new(kit::offer_bytes(&kit::signed_offer(
        &scene.maker,
        scene.context(),
        1,
        100,
        AMOUNT,
        1,
        0x46,
    )));
    assert_eq!(
        refused(request),
        Refusal::OfferExpired {
            expiry: 100,
            next_height: 101
        }
    );
    let claims = |validity: u64| {
        ClaimRequest::new([1; 32], Preimage::from_bytes([2; 32])).with_validity_blocks(validity)
    };
    assert_eq!(
        attempt(
            OperationRequest::ConditionalClaim(claims(0)),
            &view,
            &signer_b()
        )
        .unwrap_err(),
        Refusal::InvalidValidity
    );
    assert_eq!(
        attempt(
            OperationRequest::ConditionalRefund(
                RefundRequest::new([1; 32]).with_validity_blocks(0)
            ),
            &view,
            &signer_a()
        )
        .unwrap_err(),
        Refusal::InvalidValidity
    );
}

#[test]
fn only_the_required_signer_can_plan_or_adopt() {
    let scene = Scene::new();
    let (world, id, _) = locked(&scene);
    let due = at_height(&world, REFUND);
    let signer_c = KeySigner::for_test(key_c()).unwrap();
    // Only the lock's sender refunds.
    assert_eq!(
        attempt(
            OperationRequest::ConditionalRefund(RefundRequest::new(id)),
            &due.view(),
            &signer_b()
        )
        .unwrap_err(),
        Refusal::NotRequiredSigner(Slot::Approval(0))
    );
    // A funding address the wallet does not control.
    let view = scene.world.view();
    assert_eq!(
        attempt(
            OperationRequest::HashLock(scene.request().with_sender(address(&key_c(), 1))),
            &view,
            &signer_a()
        )
        .unwrap_err(),
        Refusal::NotRequiredSigner(Slot::Approval(0))
    );
    // A third wallet has nothing to sign in the sender's partial; the sender has nothing left.
    let (sender, _, _) = parts(&scene);
    assert_eq!(
        adopt(sender.bytes(), &view, signer_c.identity()).unwrap_err(),
        Refusal::NotRequiredSigner(Slot::Approval(0))
    );
    assert!(matches!(
        adopt(sender.bytes(), &view, &identity(&key_a())).unwrap_err(),
        Refusal::Malformed(_)
    ));
    // Another wallet's key cannot authorize the sender's plan.
    let planned = plan(
        &OperationRequest::HashLock(scene.request()),
        &view,
        &identity(&key_a()),
    )
    .unwrap();
    let approval = kit::approve(&review(&planned, &view).unwrap(), &view);
    assert_eq!(
        signer_c.authorize(planned, approval, &view).unwrap_err(),
        Refusal::NotRequiredSigner(Slot::Approval(0))
    );
}

#[test]
fn funding_refusals_are_typed() {
    let scene = Scene::new();
    let a = address(&key_a(), 1);
    // A claimant without any coin of the recipient address cannot pay the claim fee.
    let (world, id, _) = locked(&scene);
    let mut poor = at_height(&world, 101);
    poor.state.coins.remove(&point(2));
    assert_eq!(
        attempt(
            OperationRequest::ConditionalClaim(ClaimRequest::new(
                id,
                Preimage::from_bytes(scene.preimage)
            )),
            &poor.view(),
            &signer_b()
        )
        .unwrap_err(),
        Refusal::NothingSpendable
    );
    // Too little for the amount and the fee.
    let mut small = World::with_wallets(100);
    small.coin(a, AMOUNT + 100, 1, false, 1, 0);
    let small_scene = Scene {
        world: small,
        maker: scene.maker,
        offer: scene.offer.clone(),
        preimage: scene.preimage,
    };
    let refusal = attempt(
        OperationRequest::HashLock(small_scene.request()),
        &small_scene.world.view(),
        &signer_a(),
    )
    .unwrap_err();
    assert!(
        matches!(refusal, Refusal::InsufficientFunds { available, requested } if available == AMOUNT + 100 && requested > available),
        "{refusal:?}"
    );
    // More coins than one trading operation may spend.
    let mut dust = World::with_wallets(100);
    for index in 0..20 {
        dust.coin(a, 60_000, 1, false, 7, index);
    }
    let maker = kit::maker_key();
    let offer = kit::signed_offer(
        &maker,
        kit::context_of(&dust.anchor),
        1,
        1000,
        AMOUNT,
        1,
        0x47,
    );
    let dust_scene = Scene {
        world: dust,
        maker,
        offer,
        preimage: [3; 32],
    };
    assert_eq!(
        attempt(
            OperationRequest::HashLock(dust_scene.request()),
            &dust_scene.world.view(),
            &signer_a()
        )
        .unwrap_err(),
        Refusal::TooManyInputs { limit: 16 }
    );
}

#[test]
fn the_treasury_authority_needs_the_treasury_profile() {
    let scene = Scene::new();
    let mut world = at_height(&scene.world, 100);
    world.state.dividends =
        DividendState::genesis(Treasury::new(Class::TestValue, descriptor(&key_a(), 1)).unwrap());
    let view = world.view();
    assert_eq!(
        attempt(
            OperationRequest::HashLock(scene.request()),
            &view,
            &signer_a()
        )
        .unwrap_err(),
        Refusal::TreasuryProfileRequired
    );
    // An unsigned proposal adopted by the same ordinary identity is held to the same rule.
    let proposal = plan(
        &OperationRequest::HashLock(scene.request()),
        &scene.world.view(),
        &identity(&key_a()),
    )
    .unwrap();
    assert_eq!(
        adopt(&proposal.objects()[0].bytes, &view, &identity(&key_a())).unwrap_err(),
        Refusal::TreasuryProfileRequired
    );
    // Through the Treasury profile it is planned, and the review asks for the Treasury acknowledgement.
    let treasury = identity(&key_a()).with_treasury_roles_for_test(TreasuryRoles {
        authority: true,
        destination_of: None,
    });
    let planned = plan(
        &OperationRequest::HashLock(scene.request()),
        &view,
        &treasury,
    )
    .unwrap();
    let reviewed = review(&planned, &view).unwrap();
    assert!(
        reviewed
            .warnings()
            .iter()
            .any(|w| w.code == "TREASURY_FUNDS")
    );
    assert!(
        reviewed
            .acknowledgements()
            .contains(&AckKind::TreasuryAuthority)
    );
}

#[test]
fn inputs_that_are_not_good_coins_of_the_paying_address_are_refused() {
    let scene = Scene::new();
    let mut world = at_height(&scene.world, 100);
    // An immature coinbase coin of A, created at 50 (maturity 100).
    world.coin(address(&key_a(), 1), 3_000_000, 50, true, 8, 0);
    let view = world.view();
    let me = identity(&key_a());
    let a = address(&key_a(), 1);
    let b = address(&key_b(), 1);
    let cases: [(&str, OutPoint, u64, Refusal, NativeError); 3] = [
        (
            "a coin of another address",
            point(4),
            400_000,
            Refusal::InvalidRequest("an input is not a coin of the paying address"),
            NativeError::Authority,
        ),
        (
            "a coin that does not exist",
            point(0x77),
            2_000_000,
            Refusal::InputUnavailable,
            NativeError::Missing,
        ),
        (
            "an immature coinbase coin",
            point(8),
            3_000_000,
            Refusal::ImmatureInput,
            NativeError::Immature,
        ),
    ];
    for (what, input, atoms, wallet, consensus) in cases {
        // Everything else is right; the coin check comes before the conservation check.
        let change = atoms.saturating_sub(AMOUNT + 20_000);
        let (op, inputs) = lock_op(
            &scene,
            a,
            b,
            AMOUNT,
            REFUND,
            140,
            20_000,
            change,
            std::slice::from_ref(&input),
        );
        let raw = unsigned(&scene, op.clone(), inputs.clone());
        assert_eq!(explain(&raw, &view, &me).unwrap_err(), wallet, "{what}");
        let signed = scene.signed(op, inputs, &[(0, &key_a()), (1, &key_b())]);
        assert_eq!(
            kit::consensus_in(&view, &signed).unwrap_err(),
            consensus,
            "{what}"
        );
    }
    // The planner never selects such coins: with only the immature coin, nothing is spendable.
    let mut young = World::with_wallets(100);
    young.coin(a, 3_000_000, 50, true, 8, 0);
    assert_eq!(
        attempt(
            OperationRequest::HashLock(scene.request()),
            &young.view(),
            &signer_a()
        )
        .unwrap_err(),
        Refusal::NothingSpendable
    );
}

#[test]
fn a_refund_for_another_owner_than_the_lock_sender_is_refused() {
    let scene = Scene::new();
    let (world, id, _) = locked(&scene);
    let lock = trading_v1::locked(&world.state, id).unwrap();
    let due = at_height(&world, REFUND);
    let view = due.view();
    let c = address(&key_c(), 1);
    let (op, inputs) = refund_op(&lock, id, c, REFUND + 1, view.anchor(), &point(4), 400_000);
    assert_bytes_refused(
        &unsigned(&scene, op.clone(), inputs.clone()),
        &view,
        &identity(&key_c()),
        &Refusal::InvalidRequest("the refund owner is not the lock's sender"),
    );
    let raw = scene.signed(op, inputs, &[(0, &key_c())]);
    assert_eq!(
        kit::consensus_in(&view, &raw).unwrap_err(),
        NativeError::Authority
    );
}

#[test]
fn an_operation_outside_its_validity_window_is_refused() {
    let scene = Scene::new();
    let planned = plan(
        &OperationRequest::HashLock(scene.request()),
        &scene.world.view(),
        &identity(&key_a()),
    )
    .unwrap();
    assert_eq!(
        (planned.validity().created, planned.validity().expiry),
        (101, REFUND - 2)
    );
    let (sender, recipient, fill) = parts(&scene);
    let complete = conditional::complete(
        &[sender.bytes(), recipient.bytes()],
        Some(&fill),
        &scene.world.view(),
    )
    .unwrap();
    // Too late: the next block is past the expiry.
    let late = at_height(&scene.world, REFUND - 2);
    let view = late.view();
    assert_eq!(
        review(&planned, &view).unwrap_err(),
        Refusal::WindowClosed {
            expiry: REFUND - 2,
            next_height: REFUND - 1
        }
    );
    assert_eq!(
        kit::consensus_in(&view, complete.bytes()).unwrap_err(),
        NativeError::Envelope(mutiny_consensus_v8::op_envelope_v1::EnvelopeError::Expired)
    );
    // Too early: the next block is before the creation height.
    let early = at_height(&scene.world, 98);
    let view = early.view();
    assert_eq!(
        review(&planned, &view).unwrap_err(),
        Refusal::WindowNotOpen {
            created: 101,
            next_height: 99
        }
    );
    assert_eq!(
        kit::consensus_in(&view, complete.bytes()).unwrap_err(),
        NativeError::Envelope(mutiny_consensus_v8::op_envelope_v1::EnvelopeError::Future)
    );
}
