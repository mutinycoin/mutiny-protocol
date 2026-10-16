//! Unit and property tests of conditional MUT funding (phase 5A): the fee fixed point, the change
//! and the native input order over random coin sets (each checked against the COMPLETED operation
//! and against consensus); the preimage store; `Debug` output without the preimage or any other
//! secret; hostile decoding of every imported object (offer, fill proof, partial operation, partial
//! container, lock proof); outbox reservation and reconciliation from verified state; discovery.
//! NATIVE, TEST-VALUE; public test keys; the maker is played by the test (Q7).
#[path = "support/conditional_kit.rs"]
mod kit;
#[path = "support/synthetic.rs"]
mod synthetic;

use mutiny_consensus_v8::{
    Hash,
    state_tree::StateTree,
    trading_v1::{
        self, CandidatePolicy, NativeLock, NativeLockKind, NativeRecord, SignedOffer, Strikes,
        native_input_id,
    },
    transactions::OutPoint,
};
use mutiny_crypto_v2::HybridKey;
use mutiny_wallet_core_v8::{
    discovery::locks::{self, Finality, LockPhase},
    ops::conditional::{self, MemoryPreimageStore, OFFER_NAMESPACE, PreimageStore},
    *,
};
use std::collections::BTreeSet;
use synthetic::{World, address, identity, key_a, key_b, key_c};

const REFUND: u64 = 150;
/// Executed TEST-model state and its real Applied receipt do not constitute own Genesis replay.
fn assert_synthetic_applied_is_not_final(world: &World, raw: &[u8]) {
    let id = kit::wire(raw).operation.id().unwrap();
    let receipt = &world.state.protocol_records[&trading_v1::record_key(2, id)];
    assert!(matches!(NativeRecord::decode(receipt).unwrap(),
        (found, NativeRecord::Applied { .. }) if found == id));
    assert_eq!(world.view().confirmed_height(&id), None);
    assert_eq!(
        locks::finality(&world.view(), raw).unwrap(),
        Finality::NotFinal
    );
}

fn point(tag: u8, index: u32) -> OutPoint {
    OutPoint {
        transaction: [tag; 32],
        index,
    }
}

/// A small deterministic generator (SplitMix64): reproducible random cases without a dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

fn request(offer: &SignedOffer, amount: u64, condition: Hash) -> HashLockRequest {
    HashLockRequest::new(
        Blob::new(kit::offer_bytes(offer)),
        address(&key_b(), 1),
        amount,
        condition,
        REFUND,
    )
}

/// Sign the sender's part, the recipient's part and the maker's fill, and complete.
fn complete_of(
    world: &World,
    planned: OperationPlan,
    offer: &SignedOffer,
    maker: &HybridKey,
) -> (SignedOperation, SignedOperation) {
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    let sender = KeySigner::for_test(key_a())
        .unwrap()
        .authorize(planned, kit::approve(&reviewed, &view), &view)
        .unwrap();
    let adopted = adopt(sender.bytes(), &view, &identity(&key_b())).unwrap();
    let reviewed = review(&adopted, &view).unwrap();
    let recipient = KeySigner::for_test(key_b())
        .unwrap()
        .authorize(adopted, kit::approve(&reviewed, &view), &view)
        .unwrap();
    let fill = kit::fill_for(sender.bytes(), offer, maker);
    let complete =
        conditional::complete(&[sender.bytes(), recipient.bytes()], Some(&fill), &view).unwrap();
    (sender, complete)
}

#[test]
#[ignore = "generator: prints a fresh fixed offer for tests/golden/conditional_offer.hex"]
fn regenerate_the_fixed_offer() {
    let world = World::with_wallets(100);
    let maker = kit::maker_key();
    let offer = kit::signed_offer(
        &maker,
        kit::context_of(&world.anchor),
        1,
        1000,
        1_000_000,
        1,
        0x5a,
    );
    println!("{}", hex::encode(kit::offer_bytes(&offer)));
}

/// The retained current public offer is an independently imported canonical witness;
/// the old zero-fill container remains a historical rejected import fixture.
#[test]
fn canonical_fixed_maker_offer_has_exact_terms_and_current_public_authority() {
    let raw =
        hex::decode(include_str!("golden/conditional_maker_offer_candidate3.hex").trim()).unwrap();
    let offer = SignedOffer::decode(&raw).unwrap();
    assert_eq!(offer.encode().unwrap(), raw);
    offer.verify().unwrap();
    let world = World::with_wallets(100);
    assert_eq!(offer.body.context, kit::context_of(&world.anchor));
    assert_eq!(
        offer.body.maker_descriptor,
        synthetic::descriptor(&key_b(), 1)
    );
    assert_eq!(offer.body.maker_wallet, address(&key_b(), 1));
    assert_eq!(offer.body.destination, address(&key_b(), 1));
    assert_eq!(offer.body.condition, None);
    assert_eq!(offer.body.max_fee, Strikes(100_000));
    assert_eq!(offer.body.nonce, [0x5a; 32]);
    assert_eq!(
        (offer.body.created, offer.body.expiry, offer.body.maker_side),
        (1, 1000, 1)
    );
    assert_eq!(
        offer.body.terms,
        trading_v1::OfferTerms::HashLinked {
            amount: Strikes(1_000_000),
            bitcoin_satoshis: 50_000,
            bitcoin_network: 3,
        }
    );
    world
        .state
        .wallets
        .authorize(offer.body.maker_wallet, &offer.body.maker_descriptor)
        .unwrap();
    let mut corrupt = offer.clone();
    corrupt.signature.ed448[0] ^= 1;
    assert!(corrupt.verify().is_err());
    assert!(
        SignedOffer::decode(
            &hex::decode(include_str!("golden/conditional_offer.hex").trim()).unwrap()
        )
        .is_err()
    );
}

#[test]
fn random_coin_sets_give_an_exact_fee_exact_change_and_native_input_order() {
    let maker = kit::maker_key();
    let mut rng = Rng(0x5a_2026_1003);
    let (mut accepted, mut refused) = (0, 0);
    for case in 0..24 {
        let mut world = World::with_wallets(100);
        let count = 1 + rng.below(20) as u32;
        let mut coins = Vec::new();
        for index in 0..count {
            let atoms = match rng.below(4) {
                0 => 1 + rng.below(5_000),
                1 => 1 + rng.below(400_000),
                2 => 100_000 + rng.below(2_000_000),
                _ => 1_000_000 + rng.below(50_000_000),
            };
            coins.push((
                world.coin(address(&key_a(), 1), atoms, 1, false, 9, index),
                atoms,
            ));
        }
        let total: u64 = coins.iter().map(|(_, atoms)| atoms).sum();
        let amount = 1 + rng.below(total + total / 4);
        let offer = kit::signed_offer(
            &maker,
            kit::context_of(&world.anchor),
            1,
            1000,
            amount,
            1,
            case as u8,
        );
        let view = world.view();
        let result = plan(
            &OperationRequest::HashLock(request(&offer, amount, [7; 32])),
            &view,
            &identity(&key_a()),
        );
        let planned = match result {
            Ok(planned) => planned,
            Err(Refusal::InsufficientFunds {
                available,
                requested,
            }) => {
                assert!(requested > available, "case {case}");
                assert!(available <= total);
                refused += 1;
                continue;
            }
            Err(Refusal::TooManyInputs { limit }) => {
                assert!(count as usize > limit, "case {case}");
                refused += 1;
                continue;
            }
            Err(other) => panic!("case {case}: unexpected refusal {other:?}"),
        };
        accepted += 1;
        let unsigned = kit::wire(&planned.objects()[0].bytes);
        let meta = &unsigned.operation.meta;
        // Native input order, and the witness in the same order.
        assert!(
            meta.inputs.windows(2).all(|pair| pair[0] < pair[1]),
            "case {case}"
        );
        let ids: Vec<Hash> = unsigned.inputs.iter().map(native_input_id).collect();
        assert_eq!(ids, meta.inputs, "case {case}");
        // The fewest LARGEST coins (value descending, outpoint ascending).
        let mut ranked = coins.clone();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        let chosen: BTreeSet<OutPoint> = unsigned.inputs.iter().cloned().collect();
        let top: BTreeSet<OutPoint> = ranked[..chosen.len()]
            .iter()
            .map(|(p, _)| p.clone())
            .collect();
        assert_eq!(chosen, top, "case {case}");
        let spent: u64 = ranked[..chosen.len()].iter().map(|(_, atoms)| atoms).sum();
        let fee = meta.fee.0;
        let change = match unsigned.operation.action {
            trading_v1::Action::HashLock { change, .. } => change.0,
            _ => unreachable!(),
        };
        assert_eq!(
            spent,
            amount + change + fee,
            "case {case}: inputs = principal + change + fee"
        );
        if chosen.len() > 1 {
            let fewer: u64 = ranked[..chosen.len() - 1]
                .iter()
                .map(|(_, atoms)| atoms)
                .sum();
            assert!(
                fewer < amount + fee,
                "case {case}: one coin fewer would not have paid"
            );
        }
        // The fee covers the COMPLETED operation exactly (fixed point, at most a few atoms over).
        let size = review(&planned, &view).unwrap().fee().size_bytes.unwrap();
        let (_, complete) = complete_of(&world, planned, &offer, &maker);
        assert_eq!(
            complete.bytes().len() as u64,
            size,
            "case {case}: the placeholder widths are exact"
        );
        assert!(fee >= size.max(240), "case {case}");
        assert!(
            fee <= size.max(240) + 8,
            "case {case}: fee {fee} for size {size}"
        );
        kit::consensus_in(&view, complete.bytes()).unwrap();
    }
    assert!(
        accepted >= 8 && refused >= 2,
        "accepted {accepted}, refused {refused}"
    );
}

#[test]
fn the_fee_fixed_point_holds_across_every_integer_width_of_the_change() {
    let maker = kit::maker_key();
    let amount = 1_000_000;
    // Learn the fee of the one-coin shape, then aim the change at each width boundary.
    let probe = {
        let mut world = World::with_wallets(100);
        world.coin(address(&key_a(), 1), 50_000_000, 1, false, 1, 0);
        let offer = kit::signed_offer(
            &maker,
            kit::context_of(&world.anchor),
            1,
            1000,
            amount,
            1,
            1,
        );
        let planned = plan(
            &OperationRequest::HashLock(request(&offer, amount, [7; 32])),
            &world.view(),
            &identity(&key_a()),
        )
        .unwrap();
        kit::wire(&planned.objects()[0].bytes).operation.meta.fee.0
    };
    for (nonce, change) in [
        0u64,
        1,
        23,
        24,
        255,
        256,
        65_535,
        65_536,
        4_294_967_295,
        4_294_967_296,
    ]
    .into_iter()
    .enumerate()
    {
        let mut world = World::with_wallets(100);
        world.coin(
            address(&key_a(), 1),
            amount + probe + change,
            1,
            false,
            1,
            0,
        );
        let offer = kit::signed_offer(
            &maker,
            kit::context_of(&world.anchor),
            1,
            1000,
            amount,
            1,
            10 + nonce as u8,
        );
        let view = world.view();
        let planned = match plan(
            &OperationRequest::HashLock(request(&offer, amount, [7; 32])),
            &view,
            &identity(&key_a()),
        ) {
            Ok(planned) => planned,
            // A change below the fee's own growth cannot be paid: refused, never signed short.
            Err(Refusal::InsufficientFunds { .. }) if change < 8 => continue,
            Err(other) => panic!("change {change}: {other:?}"),
        };
        let size = review(&planned, &view).unwrap().fee().size_bytes.unwrap();
        let unsigned = kit::wire(&planned.objects()[0].bytes);
        let fee = unsigned.operation.meta.fee.0;
        let (_, complete) = complete_of(&world, planned, &offer, &maker);
        assert_eq!(complete.bytes().len() as u64, size, "change {change}");
        assert!(
            fee >= size && fee <= size + 8,
            "change {change}: fee {fee}, size {size}"
        );
        kit::consensus_in(&view, complete.bytes()).unwrap();
    }
}

#[test]
fn claim_fee_coins_are_the_fewest_largest_of_the_recipient_address_only() {
    let maker = kit::maker_key();
    let mut world = World::with_wallets(100);
    world.coin(address(&key_a(), 1), 3_000_000, 1, false, 1, 0);
    // The recipient holds dust and one usable coin; another wallet's big coin is never touched.
    world.coin(address(&key_b(), 1), 900, 1, false, 2, 0);
    world.coin(address(&key_b(), 1), 70_000, 1, false, 2, 1);
    world.coin(address(&key_c(), 1), 9_000_000, 1, false, 4, 0);
    let mut store = MemoryPreimageStore::new();
    let condition = store.create().unwrap();
    let offer = kit::signed_offer(
        &maker,
        kit::context_of(&world.anchor),
        1,
        1000,
        1_000_000,
        1,
        3,
    );
    let planned = plan(
        &OperationRequest::HashLock(request(&offer, 1_000_000, condition)),
        &world.view(),
        &identity(&key_a()),
    )
    .unwrap();
    let (_, complete) = complete_of(&world, planned, &offer, &maker);
    let prepared = trading_v1::prepare_batch(
        &world.state,
        &world.anchor,
        world.view().state_root(),
        &[complete.bytes().to_vec()],
        &CandidatePolicy::native_denomination_locked(),
    )
    .unwrap();
    let mut next = world.advanced();
    next.state = prepared.into_state();
    let lock = kit::wire(complete.bytes()).operation.output_id(0).unwrap();
    let view = next.view();
    let claim = plan(
        &OperationRequest::ConditionalClaim(
            conditional::claim_request(&store, lock, &view).unwrap(),
        ),
        &view,
        &identity(&key_b()),
    )
    .unwrap();
    let wire = kit::wire(&claim.objects()[0].bytes);
    assert_eq!(
        wire.inputs,
        vec![point(2, 1)],
        "one coin of the recipient address pays the fee"
    );
    let (fee, change) = match wire.operation.action {
        trading_v1::Action::Claim { change, amount, .. } => {
            assert_eq!(amount, Strikes(1_000_000), "the whole principal is claimed");
            (wire.operation.meta.fee.0, change.0)
        }
        _ => unreachable!(),
    };
    assert_eq!(fee + change, 70_000);
    assert_eq!(
        claim.validity().expiry,
        REFUND - 1,
        "a claim never outlives its window"
    );
}

#[test]
fn the_preimage_store_holds_fresh_values_and_a_claim_finds_its_preimage_by_condition() {
    let mut store = MemoryPreimageStore::new();
    let first = store.create().unwrap();
    let second = store.create().unwrap();
    assert_ne!(first, second);
    assert_eq!(store.conditions().unwrap().len(), 2);
    // A preimage obtained elsewhere is kept under its own condition; inserting it twice is one entry.
    let outside = Preimage::from_bytes([0x61; 32]);
    let condition = outside.condition();
    assert_eq!(store.insert(outside).unwrap(), condition);
    assert_eq!(
        store.insert(Preimage::from_bytes([0x61; 32])).unwrap(),
        condition
    );
    assert_eq!(store.len(), 3);
    assert_eq!(
        store.preimage(&condition).unwrap().unwrap().condition(),
        condition
    );
    assert!(store.erase(&condition).unwrap());
    assert!(store.preimage(&condition).unwrap().is_none());

    // claim_request reads the lock's condition from verified state and the preimage from the store.
    let mut world = World::with_wallets(100);
    let id = [0x6c; 32];
    let lock = NativeLock {
        context: kit::context_of(&world.anchor),
        trade: [1; 32],
        contract: [2; 32],
        generation: 1,
        sender: address(&key_a(), 1),
        recipient: address(&key_b(), 1),
        amount: Strikes(10_000),
        created_height: 50,
        kind: NativeLockKind::Hash {
            condition: first,
            refund_height: REFUND,
        },
    };
    world.state.protocol_records.insert(
        trading_v1::record_key(0, id),
        NativeRecord::Lock(lock).encode(id).unwrap(),
    );
    let request = conditional::claim_request(&store, id, &world.view()).unwrap();
    assert_eq!(request.lock, id);
    assert_eq!(request.preimage.condition(), first);
    // Without the preimage, or without the lock, there is no request.
    store.erase(&first).unwrap();
    assert!(matches!(
        conditional::claim_request(&store, id, &world.view()),
        Err(Refusal::InvalidRequest(_))
    ));
    assert_eq!(
        conditional::claim_request(&store, [0x6d; 32], &world.view()).unwrap_err(),
        Refusal::LockNotFound
    );
}

#[test]
fn debug_output_never_shows_the_preimage_or_dumps_bytes() {
    let maker = kit::maker_key();
    let mut world = World::with_wallets(100);
    world.coin(address(&key_a(), 1), 3_000_000, 1, false, 1, 0);
    world.coin(address(&key_b(), 1), 70_000, 1, false, 2, 0);
    let secret = [0x3e; 32];
    let preimage_hex = hex::encode(secret);
    let condition = trading_v1::preimage_hash(&secret);
    let offer = kit::signed_offer(
        &maker,
        kit::context_of(&world.anchor),
        1,
        1000,
        1_000_000,
        1,
        4,
    );
    let planned = plan(
        &OperationRequest::HashLock(request(&offer, 1_000_000, condition)),
        &world.view(),
        &identity(&key_a()),
    )
    .unwrap();
    let (sender, complete) = complete_of(&world, planned, &offer, &maker);
    let prepared = trading_v1::prepare_batch(
        &world.state,
        &world.anchor,
        world.view().state_root(),
        &[complete.bytes().to_vec()],
        &CandidatePolicy::native_denomination_locked(),
    )
    .unwrap();
    let mut next = world.advanced();
    next.state = prepared.into_state();
    let lock = kit::wire(complete.bytes()).operation.output_id(0).unwrap();
    let view = next.view();
    let mut store = MemoryPreimageStore::new();
    store.insert(Preimage::from_bytes(secret)).unwrap();
    let request = conditional::claim_request(&store, lock, &view).unwrap();
    let request_text = format!("{request:?}");
    let operation = OperationRequest::ConditionalClaim(request);
    let claim = plan(&operation, &view, &identity(&key_b())).unwrap();
    let reviewed = review(&claim, &view).unwrap();
    let signed = KeySigner::for_test(key_b())
        .unwrap()
        .authorize(claim.clone(), kit::approve(&reviewed, &view), &view)
        .unwrap();
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&signed, &view).unwrap();
    let record = outbox.get(&signed.id()).unwrap().unwrap();
    let container = PartialApproval::from_signed(&sender, world.view().context()).unwrap();
    let entry = locks::hash_locks(&view, &identity(&key_b()))
        .unwrap()
        .remove(0);
    let imported = conditional::import_offer(&kit::offer_bytes(&offer), &world.view()).unwrap();
    let texts = [
        ("request", request_text),
        ("operation request", format!("{operation:?}")),
        ("plan", format!("{claim:?}")),
        ("plan objects", format!("{:?}", claim.objects())),
        ("review", format!("{reviewed:?}")),
        ("signed", format!("{signed:?}")),
        ("record", format!("{record:?}")),
        ("store", format!("{store:?}")),
        ("container", format!("{container:?}")),
        ("lock entry", format!("{entry:?}")),
        (
            "finality",
            format!("{:?}", locks::finality(&view, complete.bytes()).unwrap()),
        ),
        ("offer", format!("{imported:?}")),
        ("refusal", format!("{:?}", Refusal::PreimageMismatch)),
    ];
    for (label, text) in &texts {
        assert!(!text.is_empty(), "{label}");
        assert!(
            !text.to_ascii_lowercase().contains(&preimage_hex),
            "{label} shows the preimage: {text}"
        );
        assert!(text.len() < 2000, "{label}: {} characters", text.len());
        let longest_hex = text
            .split(|c: char| !c.is_ascii_hexdigit())
            .map(str::len)
            .max()
            .unwrap_or(0);
        assert!(
            longest_hex < 64,
            "{label} prints a whole 32-byte value: {text}"
        );
    }
    assert!(texts[0].1.contains("Preimage(<redacted>)"));
    // The review a person reads shows the condition, never the preimage itself.
    let rendered = reviewed.render_text();
    assert!(rendered.contains(&hex::encode(condition)));
    assert!(!rendered.contains(&preimage_hex));
}

#[test]
fn every_truncation_and_bit_flip_of_an_imported_offer_is_refused() {
    let world = World::with_wallets(100);
    let maker = kit::maker_key();
    let offer = kit::signed_offer(
        &maker,
        kit::context_of(&world.anchor),
        1,
        1000,
        1_000_000,
        1,
        5,
    );
    let raw = kit::offer_bytes(&offer);
    let view = world.view();
    assert!(conditional::import_offer(&raw, &view).is_ok());
    for cut in 0..raw.len() {
        assert!(
            conditional::import_offer(&raw[..cut], &view).is_err(),
            "prefix {cut}"
        );
    }
    for (index, byte) in raw.iter().enumerate() {
        let mut flipped = raw.clone();
        flipped[index] = byte ^ (1 << (index % 8));
        assert!(
            conditional::import_offer(&flipped, &view).is_err(),
            "byte {index}"
        );
    }
    let mut longer = raw.clone();
    longer.push(0);
    assert!(conditional::import_offer(&longer, &view).is_err());
}

/// The scene shared by the partial and fill hostile-decoding tests.
fn partial_scene() -> (
    World,
    SignedOffer,
    HybridKey,
    SignedOperation,
    SignedOperation,
    Vec<u8>,
) {
    let maker = kit::maker_key();
    let mut world = World::with_wallets(100);
    world.coin(address(&key_a(), 1), 3_000_000, 1, false, 1, 0);
    let offer = kit::signed_offer(
        &maker,
        kit::context_of(&world.anchor),
        1,
        1000,
        1_000_000,
        1,
        6,
    );
    let view = world.view();
    let planned = plan(
        &OperationRequest::HashLock(request(&offer, 1_000_000, [9; 32])),
        &view,
        &identity(&key_a()),
    )
    .unwrap();
    let reviewed = review(&planned, &view).unwrap();
    let sender = KeySigner::for_test(key_a())
        .unwrap()
        .authorize(planned, kit::approve(&reviewed, &view), &view)
        .unwrap();
    let adopted = adopt(sender.bytes(), &view, &identity(&key_b())).unwrap();
    let reviewed = review(&adopted, &view).unwrap();
    let recipient = KeySigner::for_test(key_b())
        .unwrap()
        .authorize(adopted, kit::approve(&reviewed, &view), &view)
        .unwrap();
    let fill = kit::fill_for(sender.bytes(), &offer, &maker);
    (world, offer, maker, sender, recipient, fill)
}

#[test]
fn every_truncation_and_bit_flip_of_a_partial_operation_is_refused() {
    let (world, _, _, sender, _, _) = partial_scene();
    let view = world.view();
    let me = identity(&key_b());
    let raw = sender.bytes().to_vec();
    assert!(explain(&raw, &view, &me).is_ok());
    for cut in (0..raw.len()).step_by(3) {
        assert!(explain(&raw[..cut], &view, &me).is_err(), "prefix {cut}");
        assert!(SignedOperation::import(&raw[..cut], &view).is_err());
    }
    // A signed partial cannot be altered into anything at all: every flipped bit is refused.
    for (index, byte) in raw.iter().enumerate() {
        let mut flipped = raw.clone();
        flipped[index] = byte ^ (1 << (index % 8));
        assert!(
            SignedOperation::import(&flipped, &view).is_err(),
            "byte {index}"
        );
    }
}

#[test]
fn every_truncation_and_bit_flip_of_a_maker_fill_is_refused() {
    let (world, _, _, sender, recipient, fill) = partial_scene();
    let view = world.view();
    let parts = [sender.bytes(), recipient.bytes()];
    assert!(conditional::complete(&parts, Some(&fill), &view).is_ok());
    for cut in (0..fill.len()).step_by(5) {
        assert!(
            conditional::complete(&parts, Some(&fill[..cut]), &view).is_err(),
            "prefix {cut}"
        );
    }
    for (index, byte) in fill.iter().enumerate().step_by(2) {
        let mut flipped = fill.clone();
        flipped[index] = byte ^ (1 << (index % 8));
        assert!(
            conditional::complete(&parts, Some(&flipped), &view).is_err(),
            "byte {index}"
        );
    }
    // Parts of two different operations are never merged.
    let other = {
        let mut wire = kit::wire(sender.bytes());
        wire.operation.meta.trade[0] ^= 1;
        wire.operation.approvals.clear();
        wire.encode().unwrap()
    };
    assert_eq!(
        conditional::complete(&[sender.bytes(), &other], Some(&fill), &view).unwrap_err(),
        Refusal::PartialInvalid("the parts are not encodings of one and the same operation")
    );
}

#[test]
fn every_truncation_and_bit_flip_of_a_partial_container_is_refused() {
    let (world, _, _, sender, _, _) = partial_scene();
    let raw = PartialApproval::from_signed(&sender, world.view().context())
        .unwrap()
        .export()
        .unwrap();
    assert!(PartialApproval::import(&raw).is_ok());
    for cut in 0..raw.len() {
        assert!(
            PartialApproval::import(&raw[..cut]).is_err(),
            "prefix {cut}"
        );
    }
    for (index, byte) in raw.iter().enumerate() {
        let mut flipped = raw.clone();
        flipped[index] = byte ^ (1 << (index % 8));
        assert!(PartialApproval::import(&flipped).is_err(), "byte {index}");
    }
}

#[test]
fn a_lock_proof_verifies_and_every_damaged_proof_is_refused() {
    let (world, _, _, sender, recipient, fill) = partial_scene();
    let view = world.view();
    let complete =
        conditional::complete(&[sender.bytes(), recipient.bytes()], Some(&fill), &view).unwrap();
    let prepared = trading_v1::prepare_batch(
        &world.state,
        &world.anchor,
        view.state_root(),
        &[complete.bytes().to_vec()],
        &CandidatePolicy::native_denomination_locked(),
    )
    .unwrap();
    let mut anchor = world.anchor.clone();
    anchor.height = 101;
    let mut tree = StateTree::default();
    for (key, record) in prepared.state().records().unwrap() {
        tree.insert(key, record).unwrap();
    }
    let id = kit::wire(complete.bytes()).operation.output_id(0).unwrap();
    let proof = tree
        .proof(anchor.clone(), trading_v1::record_key(0, id))
        .encode()
        .unwrap();
    let lock = locks::lock_from_proof(&proof, &anchor, prepared.root(), id).unwrap();
    assert_eq!(
        (lock.recipient, lock.amount),
        (address(&key_b(), 1), Strikes(1_000_000))
    );
    assert!(
        locks::lock_from_proof(&proof, &anchor, [0; 32], id).is_err(),
        "another root"
    );
    assert!(
        locks::lock_from_proof(&proof, &anchor, prepared.root(), [1; 32]).is_err(),
        "another lock"
    );
    for cut in (0..proof.len()).step_by(7) {
        assert!(
            locks::lock_from_proof(&proof[..cut], &anchor, prepared.root(), id).is_err(),
            "prefix {cut}"
        );
    }
    for (index, byte) in proof.iter().enumerate() {
        let mut flipped = proof.clone();
        flipped[index] = byte ^ (1 << (index % 8));
        assert!(
            locks::lock_from_proof(&flipped, &anchor, prepared.root(), id).is_err(),
            "byte {index}"
        );
    }
}

#[test]
fn a_queued_partial_reserves_its_coins_and_its_offer_and_reconciles_from_verified_state() {
    let (world, offer, _maker, sender, recipient, fill) = partial_scene();
    let mut outbox = MemoryOutbox::new();
    let offer_key = resource_key(OFFER_NAMESPACE, &offer.body.id().unwrap());
    {
        let view = world.view();
        let id = outbox.commit(&sender, &view).unwrap();
        assert_eq!(id, sender.id());
        assert_eq!(outbox.commit(&sender, &view).unwrap(), id, "idempotent");
    }
    let reserved = outbox.reserved().unwrap();
    assert_eq!(reserved, BTreeSet::from([point(1, 0), offer_key.clone()]));
    // Another plan of the same offer is refused while the partial is open; forgetting releases it.
    let mut held = World::with_wallets(100);
    held.state = world.state.clone();
    held.reserved = reserved.clone();
    assert_eq!(
        plan(
            &OperationRequest::HashLock(request(&offer, 1_000_000, [9; 32])),
            &held.view(),
            &identity(&key_a())
        )
        .unwrap_err(),
        Refusal::ReservedInput
    );

    // Reconciliation: still pending at the same head; expired after its window.
    let report = outbox.reconcile(&world.view()).unwrap();
    assert_eq!(report.still_pending, 1);
    let mut late = World::with_wallets(sender.validity().expiry);
    late.state = world.state.clone();
    let mut expired = MemoryOutbox::new();
    expired.commit(&sender, &world.view()).unwrap();
    assert_eq!(expired.reconcile(&late.view()).unwrap().expired, 1);

    // Another completion of the SAME operation was applied to this synthetic TEST model;
    // its raw Applied row still cannot prove canonical inclusion.
    let complete = conditional::complete(
        &[sender.bytes(), recipient.bytes()],
        Some(&fill),
        &world.view(),
    )
    .unwrap();
    // Deliberately forged TEST host model: even a coherent wire hash/claimed height in an
    // Applied row cannot confirm an item while no own canonical replay source exists.
    for wire_hash in [
        mutiny_consensus_v8::domain_hash(
            &[trading_v1::NATIVE_NAMESPACE, b"/signed"].concat(),
            complete.bytes(),
        ),
        [0xee; 32],
    ] {
        let mut forged = world.advanced();
        forged.state.protocol_records.insert(
            trading_v1::record_key(2, complete.id()),
            NativeRecord::Applied {
                wire_hash,
                height: 101,
                fee_atoms: kit::wire(complete.bytes()).operation.meta.fee.0,
            }
            .encode(complete.id())
            .unwrap(),
        );
        assert_eq!(
            locks::finality(&forged.view(), complete.bytes()).unwrap(),
            Finality::NotFinal
        );
        let mut queue = MemoryOutbox::new();
        queue.commit(&complete, &world.view()).unwrap();
        let report = queue.reconcile(&forged.view()).unwrap();
        assert_eq!((report.confirmed, report.still_pending), (0, 1));
    }
    let applied = trading_v1::prepare_batch(
        &world.state,
        &world.anchor,
        world.view().state_root(),
        &[complete.bytes().to_vec()],
        &CandidatePolicy::native_denomination_locked(),
    )
    .unwrap();
    let mut after = world.advanced();
    after.state = applied.into_state();
    assert_synthetic_applied_is_not_final(&after, complete.bytes());
    let report = outbox.reconcile(&after.view()).unwrap();
    assert_eq!(
        report.confirmed, 0,
        "synthetic Applied state supplies no own-chain proof"
    );
    assert_eq!(
        outbox.get(&sender.id()).unwrap().unwrap().status,
        OutboxStatus::InputsSpent
    );
    assert!(
        outbox.reserved().unwrap().is_empty(),
        "a settled record holds nothing"
    );

    // A DIFFERENT operation consumed the offer with another coin: the partial can never complete,
    // although its own coin is still there.
    let (world, offer, maker, sender, _, _) = partial_scene();
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&sender, &world.view()).unwrap();
    let mut rich = World::with_wallets(100);
    rich.state = world.state.clone();
    rich.coin(address(&key_a(), 1), 4_000_000, 1, false, 3, 0);
    let rival_request = request(&offer, 1_000_000, [9; 32]).with_trade([0x77; 32]);
    let planned = plan(
        &OperationRequest::HashLock(rival_request),
        &rich.view(),
        &identity(&key_a()),
    )
    .unwrap();
    assert_eq!(
        planned.inputs(),
        &[point(3, 0)],
        "the rival spends another coin"
    );
    let (_, rival) = complete_of(&rich, planned, &offer, &maker);
    let applied = trading_v1::prepare_batch(
        &rich.state,
        &rich.anchor,
        rich.view().state_root(),
        &[rival.bytes().to_vec()],
        &CandidatePolicy::native_denomination_locked(),
    )
    .unwrap();
    let mut after = rich.advanced();
    after.state = applied.into_state();
    assert!(
        after.state.coins.contains_key(&point(1, 0)),
        "the partial's own coin is untouched"
    );
    let report = outbox.reconcile(&after.view()).unwrap();
    assert_eq!(
        (report.inputs_spent, report.confirmed),
        (1, 0),
        "the offer is consumed by another operation"
    );
}

#[test]
fn claims_and_refunds_reconcile_and_discovery_follows_the_refund_height() {
    let maker = kit::maker_key();
    let mut world = World::with_wallets(100);
    world.coin(address(&key_a(), 1), 3_000_000, 1, false, 1, 0);
    world.coin(address(&key_b(), 1), 500_000, 1, false, 2, 0);
    world.coin(address(&key_c(), 1), 500_000, 1, false, 4, 0);
    let mut store = MemoryPreimageStore::new();
    let condition = store.create().unwrap();
    let offer = kit::signed_offer(
        &maker,
        kit::context_of(&world.anchor),
        1,
        1000,
        1_000_000,
        1,
        7,
    );
    let planned = plan(
        &OperationRequest::HashLock(request(&offer, 1_000_000, condition)),
        &world.view(),
        &identity(&key_a()),
    )
    .unwrap();
    let (_, complete) = complete_of(&world, planned, &offer, &maker);
    assert_eq!(
        locks::finality(&world.view(), complete.bytes()).unwrap(),
        Finality::NotFinal
    );
    let applied = trading_v1::prepare_batch(
        &world.state,
        &world.anchor,
        world.view().state_root(),
        &[complete.bytes().to_vec()],
        &CandidatePolicy::native_denomination_locked(),
    )
    .unwrap();
    let mut locked = world.advanced();
    locked.state = applied.into_state();
    assert_synthetic_applied_is_not_final(&locked, complete.bytes());
    let id = kit::wire(complete.bytes()).operation.output_id(0).unwrap();
    let at = |head: u64| {
        let mut moved = World::with_wallets(head);
        moved.state = locked.state.clone();
        moved
    };

    // Discovery: the sender sees a lock it may refund later, the recipient one it may claim now,
    // a third wallet nothing.
    let view = locked.view();
    assert_eq!(
        locks::finality(&view, complete.bytes()).unwrap(),
        Finality::NotFinal
    );
    let theirs = locks::hash_locks(&view, &identity(&key_b())).unwrap();
    assert_eq!(theirs.len(), 1);
    assert!(
        theirs[0].may_claim() && theirs[0].this_wallet_receives && !theirs[0].this_wallet_sends
    );
    assert_eq!(theirs[0].condition, condition);
    let mine = locks::hash_locks(&view, &identity(&key_a())).unwrap();
    assert!(mine[0].this_wallet_sends && !mine[0].may_refund());
    assert!(
        locks::hash_locks(&view, &identity(&key_c()))
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        locks::hash_lock(&view, id, &identity(&key_c())).unwrap().id,
        id
    );
    assert_eq!(
        locks::hash_lock(&view, [0x0f; 32], &identity(&key_a())).unwrap_err(),
        Refusal::LockNotFound
    );
    // The phase turns exactly at the refund height.
    assert_eq!(
        locks::hash_lock(&at(REFUND - 2).view(), id, &identity(&key_b()))
            .unwrap()
            .phase,
        LockPhase::ClaimWindow {
            last_claim_height: REFUND - 1
        }
    );
    let due = locks::hash_lock(&at(REFUND - 1).view(), id, &identity(&key_a())).unwrap();
    assert_eq!(due.phase, LockPhase::RefundWindow { since: REFUND });
    assert!(due.may_refund());

    // Two claims of one lock: the one applied is confirmed, the other sees its lock spent.
    let claim = |validity: u64| {
        let view = locked.view();
        let request = conditional::claim_request(&store, id, &view)
            .unwrap()
            .with_validity_blocks(validity);
        let planned = plan(
            &OperationRequest::ConditionalClaim(request),
            &view,
            &identity(&key_b()),
        )
        .unwrap();
        let reviewed = review(&planned, &view).unwrap();
        KeySigner::for_test(key_b())
            .unwrap()
            .authorize(planned, kit::approve(&reviewed, &view), &view)
            .unwrap()
    };
    let (first, second) = (claim(20), claim(30));
    assert_ne!(first.id(), second.id());
    let mut first_box = MemoryOutbox::new();
    let mut second_box = MemoryOutbox::new();
    first_box.commit(&first, &locked.view()).unwrap();
    second_box.commit(&second, &locked.view()).unwrap();
    let applied = trading_v1::prepare_batch(
        &locked.state,
        &locked.anchor,
        locked.view().state_root(),
        &[first.bytes().to_vec()],
        &CandidatePolicy::native_denomination_locked(),
    )
    .unwrap();
    let mut claimed = locked.advanced();
    claimed.state = applied.into_state();
    assert_synthetic_applied_is_not_final(&claimed, first.bytes());
    let report = first_box.reconcile(&claimed.view()).unwrap();
    assert_eq!(
        first_box.get(&first.id()).unwrap().unwrap().status,
        OutboxStatus::InputsSpent
    );
    assert_eq!(
        second_box.reconcile(&claimed.view()).unwrap().inputs_spent,
        1,
        "same fee coin and the lock is gone"
    );
    assert_eq!(
        locks::finality(&claimed.view(), complete.bytes()).unwrap(),
        Finality::NotFinal
    );
    assert!(
        locks::hash_locks(&claimed.view(), &identity(&key_b()))
            .unwrap()
            .is_empty()
    );

    // A refund changes this synthetic state at eligibility, but supplies no canonical proof.
    let due = at(REFUND - 1);
    let view = due.view();
    let planned = plan(
        &OperationRequest::ConditionalRefund(RefundRequest::new(id)),
        &view,
        &identity(&key_a()),
    )
    .unwrap();
    let reviewed = review(&planned, &view).unwrap();
    let refund = KeySigner::for_test(key_a())
        .unwrap()
        .authorize(planned, kit::approve(&reviewed, &view), &view)
        .unwrap();
    let mut refund_box = MemoryOutbox::new();
    refund_box.commit(&refund, &view).unwrap();
    assert_eq!(
        refund_box.reserved().unwrap(),
        kit::wire(refund.bytes())
            .inputs
            .into_iter()
            .chain([resource_key(conditional::LOCK_NAMESPACE, &id)])
            .collect::<BTreeSet<_>>()
    );
    let applied = trading_v1::prepare_batch(
        &due.state,
        &due.anchor,
        view.state_root(),
        &[refund.bytes().to_vec()],
        &CandidatePolicy::native_denomination_locked(),
    )
    .unwrap();
    let mut refunded = due.advanced();
    refunded.state = applied.into_state();
    assert_synthetic_applied_is_not_final(&refunded, refund.bytes());
    let report = refund_box.reconcile(&refunded.view()).unwrap();
    assert_eq!(
        refund_box.get(&refund.id()).unwrap().unwrap().status,
        OutboxStatus::InputsSpent
    );
}

#[test]
fn fiat_locks_are_not_listed_as_hash_locks() {
    let mut world = World::with_wallets(100);
    let id = [0x5f; 32];
    let lock = NativeLock {
        context: kit::context_of(&world.anchor),
        trade: [1; 32],
        contract: [2; 32],
        generation: 1,
        sender: address(&key_a(), 1),
        recipient: address(&key_b(), 1),
        amount: Strikes(5_000),
        created_height: 50,
        kind: NativeLockKind::Fiat { terms: [9; 32] },
    };
    world.state.protocol_records.insert(
        trading_v1::record_key(0, id),
        NativeRecord::Lock(lock).encode(id).unwrap(),
    );
    let view = world.view();
    assert!(
        locks::hash_locks(&view, &identity(&key_a()))
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        locks::hash_lock(&view, id, &identity(&key_a())),
        Err(Refusal::InvalidRequest(_))
    ));
}

/// A wallet book in which the authority of `first` (its generation-one address) has rotated through
/// every generation up to `generation`, `current` being the key of generations 2 and above. Built
/// from records: the book requires every generation from 1 to the current one to be present.
fn rotated_book(
    first: &HybridKey,
    current: &HybridKey,
    generation: u64,
) -> mutiny_consensus_v8::wallet_authority_v1::WalletBook {
    use mutiny_consensus_v8::wallet_authority_v1::{WalletBook, address_key, current_key};
    let authority = address(first, 1);
    let record = |kind: u8, raw: &[u8]| {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(kind)
            .unwrap()
            .bytes(&authority)
            .unwrap()
            .bytes(raw)
            .unwrap();
        e.into_writer()
    };
    let mut records = std::collections::BTreeMap::new();
    for g in 1..=generation {
        let (at, raw) = if g == 1 {
            (authority, synthetic::descriptor(first, 1))
        } else {
            (address(current, g), synthetic::descriptor(current, g))
        };
        records.insert(address_key(at), record(31, &raw));
    }
    records.insert(
        current_key(authority),
        record(30, &synthetic::descriptor(current, generation)),
    );
    WalletBook::from_records(&records).unwrap()
}

#[test]
fn the_fee_counts_the_exact_descriptor_width_of_a_counterparty_at_generation_24() {
    // Generation 24 is the first one whose descriptor is a byte longer (integer width).
    assert_eq!(
        synthetic::descriptor(&key_b(), 24).len(),
        synthetic::descriptor(&key_b(), 23).len() + 1
    );
    let maker = kit::maker_key();
    let authority = address(&key_a(), 1);
    // The recipient named by its authority's first address, then by its generation-24 address
    // (found only through the wallet book's address records).
    for (case, recipient) in [authority, address(&key_b(), 24)].into_iter().enumerate() {
        let mut world = World::with_wallets(100);
        world.state.wallets = rotated_book(&key_a(), &key_b(), 24);
        world.coin(address(&key_c(), 1), 3_000_000, 1, false, 1, 0);
        let mut offer = kit::signed_offer(
            &maker,
            kit::context_of(&world.anchor),
            1,
            1000,
            1_000_000,
            1,
            20 + case as u8,
        );
        // The recipient settlement wallet is A or its D24 address, so the maker
        // witness must use the same current D24 descriptor and receiving address.
        offer.body.maker_descriptor = synthetic::descriptor(&maker, 24);
        offer.body.maker_wallet = recipient;
        offer.body.destination = recipient;
        offer = SignedOffer::sign(offer.body, &maker).unwrap();
        world
            .state
            .wallets
            .register(&synthetic::descriptor(&key_c(), 1))
            .unwrap();
        let view = world.view();
        let request = HashLockRequest::new(
            Blob::new(kit::offer_bytes(&offer)),
            recipient,
            1_000_000,
            [7; 32],
            REFUND,
        );
        let planned = plan(
            &OperationRequest::HashLock(request),
            &view,
            &identity(&key_c()),
        )
        .unwrap();
        let reviewed = review(&planned, &view).unwrap();
        let size = reviewed.fee().size_bytes.unwrap();
        let sender = KeySigner::for_test(key_c())
            .unwrap()
            .authorize(planned, kit::approve(&reviewed, &view), &view)
            .unwrap();
        // The recipient signs with its CURRENT key: generation 24 of the rotated authority.
        let them = SignerIdentity::from_public(key_b().public(), 24, Some(authority)).unwrap();
        let signer =
            KeySigner::new_rotated(key_b(), 24, authority, SigningGate::test_value().unwrap())
                .unwrap();
        let adopted = adopt(sender.bytes(), &view, &them).unwrap();
        let reviewed = review(&adopted, &view).unwrap();
        let part = signer
            .authorize(adopted, kit::approve(&reviewed, &view), &view)
            .unwrap();
        let fill = kit::fill_for(sender.bytes(), &offer, &maker);
        let complete =
            conditional::complete(&[sender.bytes(), part.bytes()], Some(&fill), &view).unwrap();
        assert_eq!(
            complete.bytes().len() as u64,
            size,
            "case {case}: the placeholder had the generation-24 width"
        );
        kit::consensus_in(&view, complete.bytes()).unwrap();
    }
}

#[test]
fn one_digest_binds_the_plan_every_partial_and_the_complete_operation() {
    let (world, _, _, sender, recipient, fill) = partial_scene();
    let view = world.view();
    let me = identity(&key_a());
    let digest = explain(sender.bytes(), &view, &me).unwrap().binding();
    let unsigned = &kit::wire(sender.bytes());
    let mut bare = unsigned.clone();
    bare.operation.approvals.clear();
    assert_eq!(
        explain(&bare.encode().unwrap(), &view, &me)
            .unwrap()
            .binding(),
        digest,
        "the unsigned form"
    );
    assert_eq!(
        explain(recipient.bytes(), &view, &me).unwrap().binding(),
        digest,
        "the recipient's part"
    );
    let complete =
        conditional::complete(&[sender.bytes(), recipient.bytes()], Some(&fill), &view).unwrap();
    let whole = explain(complete.bytes(), &view, &me).unwrap();
    assert_eq!(
        whole.binding(),
        digest,
        "the complete operation, fill signature included"
    );
    assert!(
        whole
            .authorizations()
            .iter()
            .all(|r| r.status == RequirementStatus::Provided)
    );
}

#[test]
fn the_validity_window_only_ever_shrinks_to_the_refund_height_and_the_offer() {
    let maker = kit::maker_key();
    // (offer expiry, refund height, requested validity, expected expiry) at head 100 (next 101).
    // The refund height caps the expiry two blocks below it: a lock included in its last valid
    // block still leaves its recipient one block to claim in (the worst-case claim window).
    for (nonce, (offer_expiry, refund, validity, expected)) in [
        (1000, 150, 144, 148),
        (120, 150, 144, 120),
        (1000, 400, 144, 245),
        (1000, 400, 5, 106),
        (101, 150, 144, 101),
        (1000, 103, 144, 101),
    ]
    .into_iter()
    .enumerate()
    {
        let mut world = World::with_wallets(100);
        world.coin(address(&key_a(), 1), 3_000_000, 1, false, 1, 0);
        let offer = kit::signed_offer(
            &maker,
            kit::context_of(&world.anchor),
            1,
            offer_expiry,
            1_000_000,
            1,
            40 + nonce as u8,
        );
        let request = HashLockRequest::new(
            Blob::new(kit::offer_bytes(&offer)),
            address(&key_b(), 1),
            1_000_000,
            [7; 32],
            refund,
        )
        .with_validity_blocks(validity);
        let planned = plan(
            &OperationRequest::HashLock(request),
            &world.view(),
            &identity(&key_a()),
        )
        .unwrap();
        assert_eq!(
            (planned.validity().created, planned.validity().expiry),
            (101, expected),
            "offer expiry {offer_expiry}, refund {refund}, validity {validity}"
        );
    }
    // A claim never outlives the claim window either.
    let mut world = World::with_wallets(100);
    let id = [0x6e; 32];
    let preimage = [0x45; 32];
    let lock = NativeLock {
        context: kit::context_of(&world.anchor),
        trade: [1; 32],
        contract: [2; 32],
        generation: 1,
        sender: address(&key_a(), 1),
        recipient: address(&key_b(), 1),
        amount: Strikes(10_000),
        created_height: 50,
        kind: NativeLockKind::Hash {
            condition: trading_v1::preimage_hash(&preimage),
            refund_height: REFUND,
        },
    };
    world.state.protocol_records.insert(
        trading_v1::record_key(0, id),
        NativeRecord::Lock(lock).encode(id).unwrap(),
    );
    world.coin(address(&key_b(), 1), 100_000, 1, false, 2, 0);
    for (validity, expected) in [(144, REFUND - 1), (5, 106)] {
        let request =
            ClaimRequest::new(id, Preimage::from_bytes(preimage)).with_validity_blocks(validity);
        let planned = plan(
            &OperationRequest::ConditionalClaim(request),
            &world.view(),
            &identity(&key_b()),
        )
        .unwrap();
        assert_eq!(
            planned.validity().expiry,
            expected,
            "claim validity {validity}"
        );
    }
}

#[path = "support/tempdir.rs"]
mod tempdir;

#[test]
fn the_durable_outbox_keeps_a_partial_and_then_its_completion_exactly() {
    let (world, offer, _maker, sender, recipient, fill) = partial_scene();
    let dir = tempdir::TempDir::new("w5a-durable");
    let path = dir.file("outbox.sqlite");
    let context = world.view().context();
    {
        let mut outbox = SqliteOutbox::open(&path, context).unwrap();
        assert_eq!(outbox.commit(&sender, &world.view()).unwrap(), sender.id());
    }
    let complete = conditional::complete(
        &[sender.bytes(), recipient.bytes()],
        Some(&fill),
        &world.view(),
    )
    .unwrap();
    {
        // Reopened: the exact partial bytes, its derived metadata and its reservations survive.
        let mut outbox = SqliteOutbox::open(&path, context).unwrap();
        let record = outbox.get(&sender.id()).unwrap().unwrap();
        assert_eq!(record.bytes, sender.bytes());
        assert!(!record.complete);
        assert_eq!(record.missing, sender.missing());
        assert_eq!(
            outbox.reserved().unwrap(),
            BTreeSet::from([
                point(1, 0),
                resource_key(OFFER_NAMESPACE, &offer.body.id().unwrap())
            ])
        );
        // The completion cannot be queued while the partial holds the same coin and offer ...
        assert_eq!(
            outbox.commit(&complete, &world.view()).unwrap_err(),
            Refusal::ReservedInput
        );
        // ... and can once the partial is forgotten.
        outbox.forget(&sender.id()).unwrap();
        assert_eq!(
            outbox.commit(&complete, &world.view()).unwrap(),
            complete.id()
        );
    }
    let applied = trading_v1::prepare_batch(
        &world.state,
        &world.anchor,
        world.view().state_root(),
        &[complete.bytes().to_vec()],
        &CandidatePolicy::native_denomination_locked(),
    )
    .unwrap();
    let mut after = world.advanced();
    after.state = applied.into_state();
    assert_synthetic_applied_is_not_final(&after, complete.bytes());
    let mut outbox = SqliteOutbox::open(&path, context).unwrap();
    let report = outbox.reconcile(&after.view()).unwrap();
    assert_eq!(
        outbox.get(&complete.id()).unwrap().unwrap().status,
        OutboxStatus::InputsSpent
    );
    assert_eq!(
        outbox.get(&sender.id()).unwrap().unwrap().status,
        OutboxStatus::Forgotten
    );
    assert!(outbox.reserved().unwrap().is_empty());
}

#[test]
fn the_paying_address_is_the_consensus_fee_payer_for_every_kind() {
    // A hash lock: the sender pays, and owns every input.
    let (world, _, _, sender, _, _) = partial_scene();
    let lock = kit::wire(sender.bytes());
    assert_eq!(lock.operation.fee_payer(), address(&key_a(), 1));
    assert!(
        lock.inputs
            .iter()
            .all(|p| world.state.coins[p].output.owner == lock.operation.fee_payer())
    );
    // A claim (by the recipient) and a refund (by the sender) of a lock placed in the state.
    let mut world = World::with_wallets(100);
    let id = [0x70; 32];
    let preimage = [0x46; 32];
    let record = NativeLock {
        context: kit::context_of(&world.anchor),
        trade: [1; 32],
        contract: [2; 32],
        generation: 1,
        sender: address(&key_a(), 1),
        recipient: address(&key_b(), 1),
        amount: Strikes(10_000),
        created_height: 50,
        kind: NativeLockKind::Hash {
            condition: trading_v1::preimage_hash(&preimage),
            refund_height: REFUND,
        },
    };
    world.state.protocol_records.insert(
        trading_v1::record_key(0, id),
        NativeRecord::Lock(record).encode(id).unwrap(),
    );
    world.coin(address(&key_b(), 1), 100_000, 1, false, 2, 0);
    world.coin(address(&key_a(), 1), 100_000, 1, false, 3, 0);
    let claim = plan(
        &OperationRequest::ConditionalClaim(ClaimRequest::new(id, Preimage::from_bytes(preimage))),
        &world.view(),
        &identity(&key_b()),
    )
    .unwrap();
    let wire = kit::wire(&claim.objects()[0].bytes);
    assert_eq!(wire.operation.fee_payer(), address(&key_b(), 1));
    assert!(
        wire.inputs
            .iter()
            .all(|p| world.state.coins[p].output.owner == wire.operation.fee_payer())
    );
    let mut due = World::with_wallets(REFUND - 1);
    due.state = world.state.clone();
    let refund = plan(
        &OperationRequest::ConditionalRefund(RefundRequest::new(id)),
        &due.view(),
        &identity(&key_a()),
    )
    .unwrap();
    let wire = kit::wire(&refund.objects()[0].bytes);
    assert_eq!(wire.operation.fee_payer(), address(&key_a(), 1));
    assert!(
        wire.inputs
            .iter()
            .all(|p| due.state.coins[p].output.owner == wire.operation.fee_payer())
    );
}
