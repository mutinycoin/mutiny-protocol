//! Phase 5B: maker-offer import and verification, hostile decoding of every imported object (offer,
//! fill proof, partial container, operation bytes), `Debug` output without secrets or byte dumps,
//! outbox reservations of coins and `resource_key` resources across plans with reconciliation from
//! verified state, and randomised properties of the fee fixed point, change and input order.
//! NATIVE, TEST-VALUE; public test keys and random transport keys only.
#[path = "support/synthetic.rs"]
mod synthetic;
#[path = "support/tempdir.rs"]
mod tempdir;
#[path = "support/trading_5b.rs"]
mod trading;
#[path = "support/trading_rig_5b.rs"]
mod trading_rig;

use mutiny_consensus_v8::{
    Hash,
    trading_v1::{self, Action, NativeOperation, OfferProof, SignedOffer},
    transactions::MATURITY,
};
use mutiny_crypto_v2::HybridKey;
use mutiny_wallet_core_v8::*;
use std::collections::BTreeSet;
use synthetic::{World, address, descriptor, identity, key_a, key_b, key_c};

const PRICE: u64 = 2_000_000;
const TRADE: [u8; 32] = [0x71; 32];
const CONTRACT: [u8; 32] = [0x72; 32];

fn world_with_license(head: u64) -> (World, Hash) {
    let mut world = World::new(head);
    for key in [key_a(), key_b()] {
        world.state.wallets.register(&descriptor(&key, 1)).unwrap();
    }
    let license = trading::install_licenses(&mut world.state, address(&key_a(), 1), false);
    world.coin(address(&key_b(), 1), 5_000_000, 1, false, 0xb1, 0);
    world.coin(address(&key_b(), 1), 3_000_000, 1, false, 0xb2, 0);
    (world, license)
}

fn license_offer(world: &World, maker: &HybridKey, license: Hash, nonce: u8) -> SignedOffer {
    trading::offer(
        maker,
        trading::context_of(&world.anchor),
        trading::license_terms(license, 1, PRICE),
        50,
        200,
        0,
        nonce,
    )
}

fn request(offer: &SignedOffer, license: Hash) -> OperationRequest {
    OperationRequest::LicenseDvp(
        LicenseDvpRequest::new(Blob::new(trading::offer_bytes(offer)), license)
            .with_commitments(TRADE, CONTRACT),
    )
}

// ---------------------------------------------------------------------------------------------
// Offer import and verification
// ---------------------------------------------------------------------------------------------

#[test]
fn an_offer_round_trips_and_reports_its_terms_window_and_single_fill_status() {
    let (world, license) = world_with_license(100);
    let maker = trading::maker();
    let offer = license_offer(&world, &maker, license, 0x31);
    let raw = trading::offer_bytes(&offer);
    let view = world.view();
    let verified = offers::import_offer(&raw, &view).unwrap();
    assert_eq!(verified.id(), offer.body.id().unwrap());
    assert_eq!(verified.maker(), offer.body.maker().unwrap());
    assert_eq!(
        verified.encode(),
        raw,
        "canonical: exactly the imported bytes"
    );
    assert_eq!(
        (verified.created(), verified.expiry(), verified.maker_side()),
        (50, 200, 0)
    );
    assert_eq!(verified.terms(), &trading::license_terms(license, 1, PRICE));
    assert_eq!(verified.signed_offer(), &offer);
    assert_eq!(
        verified.window(&view).unwrap(),
        offers::OfferWindow::Open { until: 200 }
    );
    assert!(!verified.is_consumed(&view));
    assert_eq!(
        verified.window(&World::new(10).view()).unwrap(),
        offers::OfferWindow::NotYetValid { from: 50 }
    );
    assert_eq!(
        verified.window(&World::new(200).view()).unwrap(),
        offers::OfferWindow::Expired { at: 200 }
    );
    // Once a sale is applied the offer is consumed.
    let planned = plan(&request(&offer, license), &view, &identity(&key_b())).unwrap();
    let complete = trading::sign_all(
        &planned.objects()[0].bytes,
        &[(0, &key_a(), 1), (1, &key_b(), 1)],
        Some((&maker, &offer)),
    );
    let mut after = World::new(101);
    after.state = trading::consensus(&view, &complete).unwrap().into_state();
    assert!(verified.is_consumed(&after.view()));
    // A SignedMakerOffer is the canonical offer. Bare bodies and fill-proof containers are refused,
    // including all-zero fill placeholders: they are operation proofs, not offers.
    assert!(offers::import_offer(&offer.body.encode().unwrap(), &view).is_err());
    let proof_bytes = trading::fill_proof(&maker, &offer, &planned.objects()[0].bytes);
    assert!(offers::import_offer(&proof_bytes, &view).is_err());
    let zero_fill = OfferProof {
        offer: offer.clone(),
        fill_signature: trading::zero(),
    }
    .encode()
    .unwrap();
    assert!(offers::import_offer(&zero_fill, &view).is_err());
}

#[test]
fn every_truncation_extension_and_bit_flip_of_an_offer_is_refused_without_a_panic() {
    let (world, license) = world_with_license(100);
    let view = world.view();
    let maker = trading::maker();
    let raw = trading::offer_bytes(&license_offer(&world, &maker, license, 0x31));
    for cut in 0..raw.len() {
        assert!(
            offers::import_offer(&raw[..cut], &view).is_err(),
            "cut {cut}"
        );
    }
    for extra in [1usize, 2, 9, 4096] {
        let mut longer = raw.clone();
        longer.extend(std::iter::repeat_n(0u8, extra));
        assert!(offers::import_offer(&longer, &view).is_err());
    }
    for index in 0..raw.len() {
        for bit in 0..8 {
            let mut damaged = raw.clone();
            damaged[index] ^= 1 << bit;
            assert!(
                offers::import_offer(&damaged, &view).is_err(),
                "byte {index} bit {bit}"
            );
        }
    }
    for size in [0usize, 1, 3, 64, 5000, 9000] {
        for fill in [0x00u8, 0xff, 0x84, 0x9f] {
            assert!(offers::import_offer(&vec![fill; size], &view).is_err());
        }
    }
}

#[test]
fn every_truncation_and_bit_flip_of_a_fill_proof_is_refused_without_a_panic() {
    let (world, license) = world_with_license(100);
    let view = world.view();
    let maker = trading::maker();
    let offer = license_offer(&world, &maker, license, 0x31);
    let planned = plan(&request(&offer, license), &view, &identity(&key_b())).unwrap();
    let part = trading::sign_plan(planned, &KeySigner::for_test(key_b()).unwrap(), &view).unwrap();
    let proof = trading::fill_proof(&maker, &offer, part.bytes());
    assert!(offers::attach_fill_proof(part.bytes(), &proof, &view).is_ok());
    for cut in 0..proof.len() {
        assert!(offers::attach_fill_proof(part.bytes(), &proof[..cut], &view).is_err());
    }
    // One bit per byte (the bit position rotates), over the whole proof.
    for index in 0..proof.len() {
        let mut damaged = proof.clone();
        damaged[index] ^= 1 << (index % 8);
        assert!(
            offers::attach_fill_proof(part.bytes(), &damaged, &view).is_err(),
            "byte {index}"
        );
    }
}

#[test]
fn every_truncation_and_bit_flip_of_a_partial_container_or_a_signed_part_is_refused() {
    let (world, license) = world_with_license(100);
    let view = world.view();
    let maker = trading::maker();
    let offer = license_offer(&world, &maker, license, 0x31);
    let planned = plan(&request(&offer, license), &view, &identity(&key_b())).unwrap();
    let part = trading::sign_plan(planned, &KeySigner::for_test(key_b()).unwrap(), &view).unwrap();
    // The public container: canonical, checksummed, bounded.
    let container = PartialApproval::from_signed(&part, view.context())
        .unwrap()
        .export()
        .unwrap();
    let imported = PartialApproval::import(&container).unwrap();
    assert_eq!(imported.to_signed(), part);
    assert_eq!(imported.kind(), OperationKind::LicenseDvp);
    for cut in 0..container.len() {
        assert!(PartialApproval::import(&container[..cut]).is_err());
    }
    for index in 0..container.len() {
        let mut damaged = container.clone();
        damaged[index] ^= 1 << (index % 8);
        assert!(PartialApproval::import(&damaged).is_err(), "byte {index}");
    }
    // The operation bytes themselves: truncations are not an operation at all ...
    let bytes = part.bytes().to_vec();
    for cut in (0..bytes.len()).step_by(7) {
        assert_eq!(
            SignedOperation::import(&bytes[..cut], &view).unwrap_err(),
            Refusal::UnknownOperation
        );
        assert_eq!(
            adopt(&bytes[..cut], &view, &identity(&key_a())).unwrap_err(),
            Refusal::UnknownOperation
        );
        assert!(offers::combine(&[&bytes[..cut]], &view).is_err());
    }
    // ... and no flipped bit survives as a valid part: it breaks the encoding, the context, a rule,
    // or the buyer's signature (every byte, one bit each).
    for index in 0..bytes.len() {
        let mut damaged = bytes.clone();
        damaged[index] ^= 1 << (index % 8);
        assert!(
            SignedOperation::import(&damaged, &view).is_err(),
            "byte {index} of the signed part"
        );
    }
}

#[test]
fn garbage_of_any_shape_is_never_an_operation() {
    let (world, _) = world_with_license(100);
    let view = world.view();
    for size in [0usize, 1, 2, 3, 9, 64, 1000, 17_000] {
        for fill in [0x00u8, 0xff, 0x84, 0x9f, 0x58] {
            let garbage = vec![fill; size];
            assert!(explain(&garbage, &view, &identity(&key_a())).is_err());
            assert!(adopt(&garbage, &view, &identity(&key_a())).is_err());
            assert!(SignedOperation::import(&garbage, &view).is_err());
            assert!(offers::combine(&[&garbage], &view).is_err());
            assert!(offers::attach_fill_proof(&garbage, &garbage, &view).is_err());
        }
    }
    assert!(offers::combine(&[], &view).is_err());
}

// ---------------------------------------------------------------------------------------------
// Debug output
// ---------------------------------------------------------------------------------------------

fn assert_compact(label: &str, text: &str) {
    for word in ["abandon", "zoo", "vote", "legal", "winner"] {
        assert!(
            !text.to_ascii_lowercase().contains(word),
            "{label}: contains a phrase word"
        );
    }
    let mut run = 0usize;
    let mut best = 0usize;
    for c in text.chars() {
        if c.is_ascii_hexdigit() && !c.is_ascii_uppercase() {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    assert!(
        best < 64,
        "{label}: prints a full identifier or a byte dump: {text}"
    );
    assert!(text.len() < 2000, "{label}: {} characters", text.len());
}

#[test]
fn debug_output_of_phase_5b_values_is_compact_and_secret_free() {
    let (world, license) = world_with_license(100);
    let view = world.view();
    let maker = trading::maker();
    let offer = license_offer(&world, &maker, license, 0x31);
    let verified = offers::import_offer(&trading::offer_bytes(&offer), &view).unwrap();
    let planned = plan(&request(&offer, license), &view, &identity(&key_b())).unwrap();
    let part = trading::sign_plan(
        planned.clone(),
        &KeySigner::for_test(key_b()).unwrap(),
        &view,
    )
    .unwrap();
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&part, &view).unwrap();
    let record = outbox.records().unwrap().remove(0);
    let container = PartialApproval::from_signed(&part, view.context()).unwrap();
    let reviewed = review(&planned, &view).unwrap();
    let requests = [
        format!("{:?}", request(&offer, license)),
        format!(
            "{:?}",
            OperationRequest::LicenseDvp(
                LicenseDvpRequest::new(Blob::new(trading::offer_bytes(&offer)), license)
                    .with_seller_descriptor(Blob::new(descriptor(&key_a(), 1)))
                    .with_payment_destination([0x5e; 32])
            )
        ),
        format!(
            "{:?}",
            OperationRequest::FiatLock(
                FiatLockRequest::new(Blob::new(vec![7; 3000]), [1; 32], 5, [2; 32])
                    .with_buyer_descriptor(Blob::new(descriptor(&key_b(), 1)))
            )
        ),
        format!(
            "{:?}",
            OperationRequest::FiatRelease(
                FiatReleaseRequest::new([3; 32])
                    .with_seller_descriptor(Blob::new(descriptor(&key_a(), 1)))
            )
        ),
    ];
    let shown = [
        ("verified offer", format!("{verified:?}")),
        (
            "offer window",
            format!("{:?}", verified.window(&view).unwrap()),
        ),
        ("plan", format!("{planned:?}")),
        ("review", format!("{reviewed:?}")),
        ("signed part", format!("{part:?}")),
        ("record", format!("{record:?}")),
        ("container", format!("{container:?}")),
        ("requirement", format!("{:?}", part.missing()[1])),
    ];
    for (label, text) in shown.iter() {
        assert_compact(label, text);
    }
    for text in &requests {
        assert_compact("request", text);
    }
    assert!(format!("{verified:?}").starts_with("VerifiedOffer"));
}

// ---------------------------------------------------------------------------------------------
// Outbox: reservations across plans, release on forget, reconciliation from verified state
// ---------------------------------------------------------------------------------------------

#[test]
fn queued_parts_reserve_coins_the_license_and_the_offer_until_forgotten_or_settled() {
    let (mut world, license) = world_with_license(100);
    let maker = trading::maker();
    let offer = license_offer(&world, &maker, license, 0x31);
    let view = world.view();
    let buyer = identity(&key_b());
    let signer = KeySigner::for_test(key_b()).unwrap();
    let planned = plan(&request(&offer, license), &view, &buyer).unwrap();
    let coin = planned
        .inputs()
        .iter()
        .find(|point| point.index != u32::MAX)
        .unwrap()
        .clone();
    let part = trading::sign_plan(planned, &signer, &view).unwrap();
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&part, &view).unwrap();
    // Idempotent for the same bytes while open.
    assert_eq!(outbox.commit(&part, &view).unwrap(), part.id());
    let reserved = outbox.reserved().unwrap();
    assert_eq!(
        reserved,
        BTreeSet::from([
            coin.clone(),
            resource_key("license", &license),
            resource_key("offer", &offer.body.id().unwrap()),
        ])
    );
    // Across plans: the same sale is refused, a second sale of the same License with another offer
    // is refused, and the coin is not selected by an ordinary payment either.
    let mut held = World::new(100);
    held.state = world.state.clone();
    held.reserved = reserved.clone();
    assert_eq!(
        plan(&request(&offer, license), &held.view(), &buyer).unwrap_err(),
        Refusal::ReservedInput
    );
    let other_maker = trading::maker();
    let other_offer = license_offer(&world, &other_maker, license, 0x32);
    assert_eq!(
        plan(&request(&other_offer, license), &held.view(), &buyer).unwrap_err(),
        Refusal::ReservedInput
    );
    let payment = plan(
        &OperationRequest::Payment(PaymentRequest::new([9; 32], 10_000)),
        &held.view(),
        &buyer,
    )
    .unwrap();
    assert!(
        !payment.inputs().contains(&coin),
        "a reserved coin is never selected"
    );
    // A different bytes version of the same operation identifier is refused while the part is open.
    let seller_part = trading::sign_plan(
        adopt(part.bytes(), &view, &identity(&key_a())).unwrap(),
        &KeySigner::for_test(key_a()).unwrap(),
        &view,
    )
    .unwrap();
    assert_eq!(seller_part.id(), part.id());
    assert_eq!(
        outbox.commit(&seller_part, &view).unwrap_err(),
        Refusal::OutboxIntegrity
    );
    // Forget releases every reservation; the sale can be planned again. The record keeps its bytes:
    // another version of the same identifier is still refused (an upgrade path is a change
    // request, see docs/PHASE-5B-DVP.md).
    outbox.forget(&part.id()).unwrap();
    assert!(outbox.reserved().unwrap().is_empty());
    assert_eq!(
        outbox.commit(&seller_part, &view).unwrap_err(),
        Refusal::OutboxIntegrity
    );
    assert!(plan(&request(&offer, license), &world.view(), &buyer).is_ok());

    // Expiry follows the complete signed inclusion window, not its first eligible block.
    let mut fresh = MemoryOutbox::new();
    fresh.commit(&part, &view).unwrap();
    let mut later = World::new(102);
    later.state = world.state.clone();
    assert_eq!(fresh.reconcile(&later.view()).unwrap().expired, 1);
    assert!(fresh.reserved().unwrap().is_empty());
    // Inputs spent: the buyer's coin is gone at the same head.
    let mut spent = MemoryOutbox::new();
    spent.commit(&part, &view).unwrap();
    world.state.coins.remove(&coin);
    assert_eq!(spent.reconcile(&world.view()).unwrap().inputs_spent, 1);
}

#[test]
fn a_part_survives_the_durable_outbox_byte_for_byte_and_reconciles_as_confirmed() {
    use trading_rig::chain::{TradeChain, address_of, buyer_key, license_id, seller_key};
    let buyer = buyer_key();
    let seller = seller_key();
    let mut chain = TradeChain::new(
        "dvp-durable-finality",
        1_200_000,
        &[(0xb1, address_of(&buyer), 5_000_000)],
        &[],
    );
    let license = license_id(3);
    let maker = seller_key();
    let offer = trading::offer(
        &maker,
        trading::context_of(&chain.anchor()),
        trading::license_terms(license, 1, PRICE),
        1,
        200,
        0,
        0x31,
    );
    let none = BTreeSet::new();
    let view = chain.view(&none);
    let me = SignerIdentity::from_public(buyer.public(), 1, None).unwrap();
    let planned = plan(&request(&offer, license), &view, &me).unwrap();
    let part =
        trading::sign_plan(planned, &KeySigner::for_test(buyer_key()).unwrap(), &view).unwrap();
    let dir = tempdir::TempDir::new("w5b-outbox");
    let path = dir.file("outbox.sqlite");
    {
        let mut outbox = SqliteOutbox::open(&path, view.context()).unwrap();
        outbox.commit(&part, &view).unwrap();
    }
    let mut reopened = SqliteOutbox::open(&path, view.context()).unwrap();
    let record = reopened.get(&part.id()).unwrap().unwrap();
    assert_eq!(record.bytes, part.bytes(), "exact bytes");
    assert_eq!(record.kind, OperationKind::LicenseDvp);
    assert!(!record.complete);
    assert_eq!(record.missing, part.missing());
    assert_eq!(record.validity.valid_only_at, None);
    assert_eq!((record.validity.created, record.validity.expiry), (1, 2));
    // The completed sale (other parties' signatures, same body) is included: the queued PART
    // settles as confirmed, because the operation identifier commits to the whole body.
    let complete = trading::sign_all(
        part.bytes(),
        &[(0, &seller, 1), (1, &buyer, 1)],
        Some((&maker, &offer)),
    );
    chain.step(&[complete]);
    let confirmations = chain.confirmations();
    let report = reopened
        .reconcile(&chain.view(&none).with_confirmations(&confirmations))
        .unwrap();
    assert_eq!(report.confirmed, 1, "{report:?}");
    assert_eq!(
        reopened.get(&part.id()).unwrap().unwrap().status,
        OutboxStatus::Confirmed(1)
    );
    drop(confirmations);
    drop(reopened);
    let chain = chain.restart();
    let mut reopened = SqliteOutbox::open(&path, chain.view(&none).context()).unwrap();
    assert_eq!(
        reopened.get(&part.id()).unwrap().unwrap().status,
        OutboxStatus::Confirmed(1)
    );
    let confirmations = chain.confirmations();
    assert_eq!(
        reopened
            .reconcile(&chain.view(&none).with_confirmations(&confirmations))
            .unwrap()
            .confirmed,
        0
    );
    drop(confirmations);
    chain.finish();
}

// ---------------------------------------------------------------------------------------------
// Randomised properties
// ---------------------------------------------------------------------------------------------

/// xorshift64*: small, deterministic, good enough for test data.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }
}

#[test]
fn any_funding_yields_a_consensus_shaped_sale_or_a_typed_refusal_that_matches_the_chain() {
    let maker = trading::maker();
    let mut rng = Rng(0x5b5b_1234_9e37_79b9);
    let buyer = address(&key_b(), 1);
    let (mut planned_count, mut checked_by_consensus) = (0, 0);
    for case in 0..120 {
        let (mut world, license) = world_with_license(150 + rng.below(40));
        world.state.coins.clear();
        let coins = rng.below(20);
        for index in 0..coins {
            let atoms = match rng.below(4) {
                0 => 1 + rng.below(20_000),
                1 => 20_000 + rng.below(3_000_000),
                2 => 1_000_000 + rng.below(1 << 36),
                _ => 1 + rng.below(1 << 22),
            };
            let (created, coinbase) = if rng.below(8) == 0 {
                (60 + rng.below(100), true)
            } else {
                (1 + rng.below(40), false)
            };
            let owner = if rng.below(10) == 0 {
                address(&key_c(), 1)
            } else {
                buyer
            };
            world.coin(
                owner,
                atoms,
                created,
                coinbase,
                0x40 + (index as u8),
                index as u32,
            );
        }
        let price = 1 + rng.below(1 << 24);
        let offer = trading::offer(
            &maker,
            trading::context_of(&world.anchor),
            trading::license_terms(license, 1, price),
            1,
            1_000,
            0,
            case as u8,
        );
        let view = world.view();
        let next = world.anchor.height + 1;
        // Independently computed: the coins of exactly the buyer address the sale may spend.
        let mut spendable: Vec<u64> = world
            .state
            .coins
            .values()
            .filter(|coin| {
                coin.output.owner == buyer
                    && coin.created_height < next
                    && (!coin.coinbase || next - coin.created_height >= MATURITY)
            })
            .map(|coin| coin.output.atoms)
            .collect();
        spendable.sort_unstable_by(|a, b| b.cmp(a));
        let total: u128 = spendable.iter().map(|a| u128::from(*a)).sum();
        match plan(&request(&offer, license), &view, &identity(&key_b())) {
            Ok(planned) => {
                planned_count += 1;
                let raw = &planned.objects()[0].bytes;
                let wire = NativeOperation::decode(raw).unwrap();
                let op = &wire.operation;
                let Action::LicenseDvp {
                    price: p,
                    change,
                    buyer: named,
                    ..
                } = &op.action
                else {
                    panic!("a License sale")
                };
                assert_eq!((p.0, *named), (price, buyer));
                assert_eq!(op.meta.envelope.first_height, next);
                assert_eq!(
                    op.meta.envelope.last_height,
                    (next + 1).min(offer.body.expiry)
                );
                assert_eq!(op.meta.envelope.reference_height, world.anchor.height);
                assert_eq!(op.meta.envelope.reference_block, world.anchor.block);
                // At most 16 inputs, all coins of exactly the buyer, sorted by native input id,
                // locators in the same order.
                assert!(!wire.inputs.is_empty() && wire.inputs.len() <= 16);
                let ids: Vec<Hash> = wire
                    .inputs
                    .iter()
                    .map(trading_v1::native_input_id)
                    .collect();
                assert_eq!(ids, op.meta.inputs);
                assert!(ids.windows(2).all(|w| w[0] < w[1]));
                let mut sum: u128 = 0;
                for point in &wire.inputs {
                    let coin = &world.state.coins[point];
                    assert_eq!(coin.output.owner, buyer);
                    sum += u128::from(coin.output.atoms);
                }
                // Conservation and the fee fixed point on the final length.
                assert_eq!(
                    sum,
                    u128::from(price) + u128::from(change.0) + u128::from(op.meta.fee.0)
                );
                assert_eq!(op.meta.fee.0, (raw.len() as u64).max(240));
                // The completed operation has exactly the planned length and consensus accepts it.
                if case % 6 == 0 {
                    let complete = trading::sign_all(
                        raw,
                        &[(0, &key_a(), 1), (1, &key_b(), 1)],
                        Some((&maker, &offer)),
                    );
                    assert_eq!(complete.len(), raw.len());
                    trading::consensus(&view, &complete)
                        .expect("consensus accepts the planned sale");
                    checked_by_consensus += 1;
                }
            }
            Err(Refusal::NothingSpendable) => assert!(spendable.is_empty(), "case {case}"),
            Err(Refusal::InsufficientFunds {
                available,
                requested,
            }) => {
                assert_eq!(u128::from(available), total, "case {case}");
                assert!(u128::from(requested) > total, "case {case}");
                assert!(requested > price, "the request includes a fee");
            }
            Err(Refusal::TooManyInputs { limit }) => {
                assert_eq!(limit, 16);
                assert!(spendable.len() > 16, "case {case}");
                let best: u128 = spendable.iter().take(16).map(|a| u128::from(*a)).sum();
                assert!(best <= u128::from(price) + 20_000, "case {case}");
            }
            Err(other) => panic!("case {case}: unexpected refusal {other:?}"),
        }
    }
    assert!(
        planned_count >= 20 && checked_by_consensus >= 3,
        "{planned_count} {checked_by_consensus}"
    );
}
