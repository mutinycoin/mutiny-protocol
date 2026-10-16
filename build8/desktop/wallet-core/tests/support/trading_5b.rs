// Phase 5B test support (owned by phase 5B; the phase 1 support files are used read-only): the public
// synthetic License Book, a TEST-VALUE dividend award, maker offers and fill proofs, and helpers that
// play EVERY party through the CONSENSUS API for differential checks. The wallet never creates offers
// or fill proofs (Q7); only these tests do, with fresh random `Role::Transport` keys.
// NATIVE, TEST-VALUE: public BIP-39 test-vector keys and random transport keys only; nothing here is
// production or physical evidence.
//
// Declared by a test file as:
//     #[path = "support/trading_5b.rs"]
//     mod trading;
#![allow(dead_code)]

#[path = "flow.rs"]
mod flow;

use minicbor::{Decoder, Encoder};
use mutiny_consensus_v8::{
    Hash,
    anchors::FinalizedAnchor,
    dividend_state_v1::DividendState,
    dividends_v1::AWARD_PERIOD_EPOCHS,
    execution::State,
    license_assignment_v2::Assignment,
    license_book_v2::Book,
    licenses::LicenseRecord,
    trading_v1::{
        self, CandidatePolicy, Context, NativeError, NativeOperation, OfferBody, OfferProof,
        OfferTerms, Prepared, SignedOffer, Strikes,
    },
    transactions::{Coin, OutPoint, Output},
    treasury_v1::{Class, Treasury},
};
use mutiny_crypto_v2::{HybridKey, HybridSignature, Role};
use mutiny_wallet_core_v8::{
    ChainView, FiatReleaseRequest, KeySigner, OperationRequest, ReviewDigest, SignedOperation,
    Signer, adopt, offers, plan, review,
};
use std::collections::BTreeMap;

const LICENSE_TAG: u8 = 40;
const WORKER_TAG: u8 = 41;
const PENDING_TAG: u8 = 42;

pub fn zero() -> HybridSignature {
    HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    }
}

/// Deliberately forged TEST host model, never a valid canonical chain: an Applied row alone
/// must not confirm a queued DvP/Fiat item, even with a coherent wire hash and claimed height.
pub fn assert_forged_applied_receipt_cannot_confirm(
    signed: &SignedOperation,
    view: &ChainView<'_>,
) {
    use mutiny_wallet_core_v8::{MemoryOutbox, Outbox, OutboxStatus};
    use std::collections::BTreeSet;
    let id = NativeOperation::decode(signed.bytes())
        .unwrap()
        .operation
        .id()
        .unwrap();
    let exact_wire_hash = mutiny_consensus_v8::domain_hash(
        &[trading_v1::NATIVE_NAMESPACE, b"/signed"].concat(),
        signed.bytes(),
    );
    assert_eq!(
        view.state().root().unwrap(),
        view.state_root(),
        "genuine pre-state"
    );
    for wire_hash in [exact_wire_hash, [0xee; 32]] {
        let mut state = view.state().clone();
        state.protocol_records.insert(
            trading_v1::record_key(2, id),
            trading_v1::NativeRecord::Applied {
                wire_hash,
                height: view.next_height().unwrap(),
                fee_atoms: NativeOperation::decode(signed.bytes())
                    .unwrap()
                    .operation
                    .meta
                    .fee
                    .0,
            }
            .encode(id)
            .unwrap(),
        );
        // Keep the genuine head while corrupting only the host-supplied state. This is
        // explicitly an inconsistent adapter model, not a valid StateRoot or canonical
        // chain. An orphan Applied row may also fail native structural context validation.
        let head = view.head().clone();
        let none = BTreeSet::new();
        let forged = ChainView::new(head, &state, &none);
        let mut queue = MemoryOutbox::new();
        queue.commit(signed, view).unwrap();
        let report = queue.reconcile(&forged).unwrap();
        assert_eq!(
            report.confirmed, 0,
            "Applied row is not own-replay evidence"
        );
        assert_eq!(report.still_pending, 1);
        assert_eq!(
            queue.get(&signed.id()).unwrap().unwrap().status,
            OutboxStatus::Queued
        );
    }
}

pub fn descriptor_of(key: &HybridKey, generation: u64) -> Vec<u8> {
    key.public().descriptor(generation).unwrap()
}

pub fn address_of(key: &HybridKey, generation: u64) -> Hash {
    key.public().address_id(generation).unwrap()
}

fn fixture_records() -> BTreeMap<Hash, Vec<u8>> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../qualification/license-book-v2-public-v1.json"
    ))
    .unwrap();
    assert_eq!(fixture["synthetic_only"], true);
    fixture["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            let key: Hash = hex::decode(entry["key"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            (key, hex::decode(entry["record"].as_str().unwrap()).unwrap())
        })
        .collect()
}

fn wrap(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .u8(2)
        .unwrap()
        .u8(tag)
        .unwrap()
        .bytes(payload)
        .unwrap();
    e.into_writer()
}

/// (tag, payload) of a typed Book record.
fn unwrap_record(raw: &[u8]) -> (u8, Vec<u8>) {
    let mut d = Decoder::new(raw);
    d.array().unwrap();
    assert_eq!(d.u8().unwrap(), 2);
    let tag = d.u8().unwrap();
    (tag, d.bytes().unwrap().to_vec())
}

/// The public License Book fixture (twelve Genesis Licenses of Genesis [1;32] / fingerprint [2;32])
/// with its own pending assignment dropped and the first License in record-key order owned by
/// `owner`. With `pending`, that License's active Worker assignment is moved to the pending set (a
/// scheduled re-assignment that blocks a sale). Returns the Book and that License's identifier.
pub fn license_book(owner: Hash, pending: bool) -> (Book, Hash) {
    let mut records = BTreeMap::new();
    let mut selected = None;
    for (key, raw) in fixture_records() {
        let (tag, payload) = unwrap_record(&raw);
        if tag == LICENSE_TAG && selected.is_none() {
            let mut license = LicenseRecord::decode(&payload).unwrap();
            license.owner = owner;
            selected = Some(license.id);
            records.insert(key, wrap(LICENSE_TAG, &license.encode()));
        } else if tag != PENDING_TAG {
            records.insert(key, raw);
        }
    }
    let id = selected.unwrap();
    if pending {
        let mut moved = None;
        let mut gone = Vec::new();
        for (key, raw) in records.iter_mut() {
            let (tag, payload) = unwrap_record(raw);
            match tag {
                LICENSE_TAG => {
                    let mut license = LicenseRecord::decode(&payload).unwrap();
                    if license.id == id {
                        license.active_worker = None;
                        license.assignment_sequence = 0;
                        *raw = wrap(LICENSE_TAG, &license.encode());
                    }
                }
                WORKER_TAG => {
                    let assignment = Assignment::decode(&payload).unwrap();
                    if assignment.enrollment.binding.license == id {
                        if assignment.enrollment.binding.assignment_generation == 1 {
                            moved = Some(assignment);
                        }
                        gone.push(*key);
                    }
                }
                _ => {}
            }
        }
        for key in gone {
            records.remove(&key);
        }
        records.insert(
            mutiny_consensus_v8::domain_hash(b"MUTINY-BUILD8-PENDING-BIND-KEY-V2", &id),
            wrap(PENDING_TAG, &moved.unwrap().encode().unwrap()),
        );
    }
    (Book::from_records(&records).unwrap(), id)
}

/// Install the License Book in `state`, the License owned by `owner`.
pub fn install_licenses(state: &mut State, owner: Hash, pending: bool) -> Hash {
    let (book, id) = license_book(owner, pending);
    state.licenses_v2 = book;
    id
}

/// A TEST-VALUE Treasury owned by `treasury` holding `atoms` (coin `[tag; 32]:0`), and the first
/// award boundary processed, so every Genesis bootstrap License has an outstanding award.
pub fn install_award(state: &mut State, treasury: &HybridKey, atoms: u64, tag: u8) {
    let address = address_of(treasury, 1);
    state.wallets.register(&descriptor_of(treasury, 1)).unwrap();
    state.coins.insert(
        OutPoint {
            transaction: [tag; 32],
            index: 0,
        },
        Coin {
            output: Output {
                owner: address,
                atoms,
            },
            created_height: 0,
            coinbase: false,
        },
    );
    state.dividends = DividendState::genesis(
        Treasury::new(Class::TestValue, descriptor_of(treasury, 1)).unwrap(),
    );
    let licenses: Vec<(Hash, Hash, Option<u64>)> = state
        .licenses_v2
        .licenses()
        .map(|l| {
            (
                l.id,
                l.owner,
                state.licenses_v2.dividend_activation_epoch(l.id),
            )
        })
        .collect();
    state
        .dividends
        .advance(AWARD_PERIOD_EPOCHS, atoms, &licenses)
        .unwrap();
}

pub fn context_of(anchor: &FinalizedAnchor) -> Context {
    Context {
        network: anchor.network,
        genesis: anchor.genesis,
        fingerprint: anchor.fingerprint,
    }
}

/// Public synthetic seller A, acting as the current settlement wallet. Tests with a
/// different settlement party must explicitly choose that party's current wallet key.
pub fn maker() -> HybridKey {
    HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner).unwrap()
}

/// A maker offer signed through the consensus API (the test plays the maker).
pub fn offer(
    maker: &HybridKey,
    context: Context,
    terms: OfferTerms,
    created: u64,
    expiry: u64,
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
            terms,
        },
        maker,
    )
    .unwrap()
}

pub fn license_terms(license: Hash, generation: u64, price: u64) -> OfferTerms {
    OfferTerms::License {
        license,
        generation,
        price: Strikes(price),
    }
}

pub fn fiat_terms(amount: u64, payment_terms: Hash) -> OfferTerms {
    OfferTerms::Fiat {
        amount: Strikes(amount),
        payment_terms,
    }
}

pub fn offer_bytes(offer: &SignedOffer) -> Vec<u8> {
    offers::encode_offer(offer).unwrap()
}

/// The maker's fill proof over the exact body of `raw` (the test plays the maker).
pub fn fill_proof(maker: &HybridKey, offer: &SignedOffer, raw: &[u8]) -> Vec<u8> {
    let wire = NativeOperation::decode(raw).unwrap();
    OfferProof::sign(offer.clone(), &wire.operation, maker)
        .unwrap()
        .encode()
        .unwrap()
}

/// Decode, change, re-encode (the change must keep the operation encodable).
pub fn mutate(raw: &[u8], change: impl FnOnce(&mut NativeOperation)) -> Vec<u8> {
    let mut wire = NativeOperation::decode(raw).unwrap();
    change(&mut wire);
    wire.encode().unwrap()
}

/// Every approval signed by the given (slot, key, generation) through the consensus API and, with
/// `fill`, the maker's fill over the final body: the test plays every party, independently of the
/// wallet's own signing path.
pub fn sign_all(
    raw: &[u8],
    approvals: &[(u8, &HybridKey, u64)],
    fill: Option<(&HybridKey, &SignedOffer)>,
) -> Vec<u8> {
    let mut wire = NativeOperation::decode(raw).unwrap();
    wire.operation.approvals.clear();
    for (slot, key, generation) in approvals {
        wire.operation.approve(*slot, key, *generation).unwrap();
    }
    if let Some((maker, offer)) = fill {
        wire.operation.offer_proof =
            Some(OfferProof::sign(offer.clone(), &wire.operation, maker).unwrap());
    }
    wire.encode().unwrap()
}

/// Consensus' verdict on `raw` included alone in the block after the view's head.
pub fn consensus(view: &ChainView<'_>, raw: &[u8]) -> Result<Prepared, NativeError> {
    trading_v1::prepare_batch(
        view.state(),
        view.anchor(),
        view.state_root(),
        &[raw.to_vec()],
        &CandidatePolicy::native_denomination_locked(),
    )
}

/// Everything a person must do before an approval exists for a HIGH-RISK review (every License sale
/// and fiat lock or release is one): present it, type every destination check, give every
/// acknowledgement and type the confirmation phrase derived from the review digest (the shared
/// `support/flow.rs`, which types the phrase since phase 8).
pub use flow::approve as approve_high_risk;

/// Review, approve (high risk) and authorize `plan` with `signer`.
pub fn sign_plan(
    plan: mutiny_wallet_core_v8::OperationPlan,
    signer: &mutiny_wallet_core_v8::KeySigner,
    view: &ChainView<'_>,
) -> Result<mutiny_wallet_core_v8::SignedOperation, mutiny_wallet_core_v8::Refusal> {
    use mutiny_wallet_core_v8::Signer;
    let reviewed = mutiny_wallet_core_v8::review(&plan, view)?;
    let approval = approve_high_risk(&reviewed, view);
    signer.authorize(plan, approval, view)
}

/// One License sale through the whole wallet flow at `view`'s head: the buyer plans and signs its
/// slot, the maker fills over the exact body, the seller adopts the buyer's part and co-signs ONLY
/// its slot, and the parts are combined. Returns (buyer part, part with the fill, seller part,
/// complete operation, the buyer's review digest).
pub fn sale(
    view: &ChainView<'_>,
    maker: &HybridKey,
    offer: &SignedOffer,
    request: &OperationRequest,
    buyer: &KeySigner,
    seller: &KeySigner,
) -> (
    SignedOperation,
    Vec<u8>,
    SignedOperation,
    SignedOperation,
    ReviewDigest,
) {
    let planned = plan(request, view, buyer.identity()).unwrap();
    let digest = review(&planned, view).unwrap().binding();
    let buyer_part = sign_plan(planned, buyer, view).unwrap();
    let proof = fill_proof(maker, offer, buyer_part.bytes());
    let with_fill = offers::attach_fill_proof(buyer_part.bytes(), &proof, view).unwrap();
    let adopted = adopt(buyer_part.bytes(), view, seller.identity()).unwrap();
    let seller_part = sign_plan(adopted, seller, view).unwrap();
    let complete = offers::combine(&[&with_fill, seller_part.bytes()], view).unwrap();
    (buyer_part, with_fill, seller_part, complete, digest)
}

/// One fiat-settled lock through the whole wallet flow at `view`'s head: the seller plans, funds and
/// signs slot 0, the maker's fill is attached, the buyer adopts it and signs slot 1, and the parts
/// are combined. Returns (seller part, complete operation).
pub fn fiat_lock(
    view: &ChainView<'_>,
    maker: &HybridKey,
    offer: &SignedOffer,
    request: &OperationRequest,
    seller: &KeySigner,
    buyer: &KeySigner,
) -> (SignedOperation, SignedOperation) {
    let planned = plan(request, view, seller.identity()).unwrap();
    let seller_part = sign_plan(planned, seller, view).unwrap();
    let proof = fill_proof(maker, offer, seller_part.bytes());
    let with_fill = offers::attach_fill_proof(seller_part.bytes(), &proof, view).unwrap();
    let adopted = adopt(&with_fill, view, buyer.identity()).unwrap();
    let buyer_part = sign_plan(adopted, buyer, view).unwrap();
    let complete = offers::combine(&[&with_fill, buyer_part.bytes()], view).unwrap();
    (seller_part, complete)
}

/// The release of fiat lock `lock` through the whole wallet flow: the buyer plans it (paying the
/// fee) and signs slot 0, the seller adopts it and signs slot 1, and the parts are combined.
/// Returns (buyer part, complete operation).
pub fn fiat_release(
    view: &ChainView<'_>,
    lock: Hash,
    buyer: &KeySigner,
    seller: &KeySigner,
) -> (SignedOperation, SignedOperation) {
    let planned = plan(
        &OperationRequest::FiatRelease(FiatReleaseRequest::new(lock)),
        view,
        buyer.identity(),
    )
    .unwrap();
    let buyer_part = sign_plan(planned, buyer, view).unwrap();
    let adopted = adopt(buyer_part.bytes(), view, seller.identity()).unwrap();
    let seller_part = sign_plan(adopted, seller, view).unwrap();
    let complete = offers::combine(&[buyer_part.bytes(), seller_part.bytes()], view).unwrap();
    (buyer_part, complete)
}

/// Sign only the given approval slots (through the consensus signing payload, as any other
/// implementation would) and keep every other slot and the fill exactly as they are.
pub fn sign_some(raw: &[u8], approvals: &[(u8, &HybridKey, u64)]) -> Vec<u8> {
    let mut wire = NativeOperation::decode(raw).unwrap();
    for (slot, key, generation) in approvals {
        let descriptor = key.public().descriptor(*generation).unwrap();
        let payload = wire.operation.signing_payload(*slot, &descriptor).unwrap();
        let signature = key
            .sign(mutiny_crypto_v2::Domain::Transaction, &payload)
            .unwrap();
        let approval = wire
            .operation
            .approvals
            .iter_mut()
            .find(|a| a.slot == *slot)
            .unwrap();
        approval.descriptor = descriptor;
        approval.signature = signature;
    }
    wire.encode().unwrap()
}
