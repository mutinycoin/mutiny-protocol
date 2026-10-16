//! The Treasury operations in the outbox, their reconciliation from verified state, the durable
//! outbox, `Debug` output without secrets, and randomised properties (phase 6).
//!
//!  * A rotation reserves its fee coins and its Treasury generation (`resource_key`, one rotation per
//!    Treasury and generation) across plans; `forget` releases them; reconciliation reads verified
//!    state only: only an own-replay inclusion confirms it; a synthetic `Applied` receipt cannot.
//!    The window ending expires it, a spent coin or a
//!    generation taken by another rotation settles it as `InputsSpent`, an older view says nothing.
//!  * A freeze reserves its offer (one pending freeze per offer); it is never "confirmed" by itself
//!    and settles when the offer is consumed or closes.
//!  * Both survive the durable outbox byte for byte.
//!  * No Treasury value prints a secret or a long byte dump in `Debug`.
//!  * Random coin sets: the rotation fee is exactly `max(240, signed size)`, inputs equal change plus
//!    fee, inputs are in native order, and consensus accepts the result; random freezes round-trip
//!    through the proposal and equal the consensus payload.
//!
//! NATIVE, TEST-VALUE; public test keys.
#[path = "support/treasury_kit.rs"]
mod kit;
#[path = "support/synthetic.rs"]
mod synthetic;
#[path = "support/tempdir.rs"]
mod tempdir;

use kit::{FreezeTerms, TRADING_TREASURY};
use mutiny_consensus_v8::{
    Hash,
    dividend_state_v1::DividendState,
    trading_v1::{self, Action, CandidatePolicy, NativeRecord, native_input_id, record_key},
    transactions::OutPoint,
    treasury_v1::{Class, Treasury},
};
use mutiny_crypto_v2::{HybridKey, Role};
use mutiny_wallet_core_v8::{
    ops::treasury::{self, freeze_resource, rotation_resource},
    profile::{self, TreasuryDeclaration},
    *,
};
use std::collections::BTreeSet;
use synthetic::{World, address, descriptor, identity, key_a, key_b, key_c};

const T: Hash = TRADING_TREASURY;

fn key_d() -> HybridKey {
    let phrase = mutiny_crypto_v2::rehearsal_keys_v1::label_phrase("w6-outbox-key-d").unwrap();
    HybridKey::wallet_restore(&phrase, Role::WalletOwner).unwrap()
}

fn point(tag: u8) -> OutPoint {
    OutPoint {
        transaction: [tag; 32],
        index: 0,
    }
}

fn world_at(head: u64) -> World {
    let mut world = World::new(head);
    world
        .state
        .wallets
        .register(&descriptor(&key_b(), 1))
        .unwrap();
    world.state.dividends =
        DividendState::genesis(Treasury::new(Class::TestValue, descriptor(&key_b(), 1)).unwrap());
    world.coin(address(&key_b(), 1), 5_000_000, 1, false, 0xd1, 0);
    world.coin(address(&key_b(), 1), 300_000, 1, false, 0xd2, 0);
    let context = kit::context_of(&world.anchor);
    for (key, raw) in
        trading_v1::treasury_genesis_records(&context, T, descriptor(&key_b(), 1)).unwrap()
    {
        world.state.protocol_records.insert(key, raw);
    }
    // Signed TEST model: B1 is retired in WalletBook while routing still names B1.
    // This is no canonical block/history/confirmation source.
    kit::apply_wallet_rotation_model(
        &mut world.state,
        &world.anchor,
        T,
        &key_b(),
        1,
        &key_c(),
        2,
        head - 1,
    );
    world
}

fn world() -> World {
    world_at(100)
}

fn treasury_me() -> SignerIdentity {
    SignerIdentity::from_public(key_c().public(), 2, Some(T))
        .unwrap()
        .with_treasury_roles_for_test(TreasuryRoles {
            authority: true,
            destination_of: Some(T),
        })
}

fn signer() -> KeySigner {
    KeySigner::with_identity(
        key_c(),
        treasury_me(),
        SigningGate::test_value().unwrap(),
        DEFAULT_IDLE_LIMIT,
    )
    .unwrap()
}

fn rotate_to(key: &HybridKey, generation: u64) -> OperationRequest {
    let descriptor = descriptor(key, generation);
    let fingerprint = trading_v1::descriptor_hash(&descriptor);
    OperationRequest::TreasuryRotate(
        TreasuryRotateRequest::new(Blob::new(descriptor)).with_verified_restore(T, fingerprint),
    )
}

fn sign(planned: OperationPlan, view: &ChainView<'_>) -> SignedOperation {
    let reviewed = review(&planned, view).unwrap();
    signer()
        .authorize(planned, kit::approve(&reviewed, view), view)
        .unwrap()
}

fn signed_rotation(world: &World) -> SignedOperation {
    let view = world.view();
    sign(
        plan(&rotate_to(&key_c(), 2), &view, &treasury_me()).unwrap(),
        &view,
    )
}

fn freeze_terms() -> FreezeTerms {
    FreezeTerms {
        treasury: T,
        generation: 1,
        address: address(&key_b(), 1),
        trade: [0x21; 32],
        contract: [0x22; 32],
        wallet_descriptor: descriptor(&key_c(), 2),
    }
}

fn signed_freeze(world: &World, nonce: u8) -> (SignedOperation, Hash) {
    let view = world.view();
    let maker = key_c();
    let head = world.anchor.height;
    let offer = kit::treasury_offer_at_generation(
        &maker,
        2,
        T,
        kit::context_of(&world.anchor),
        head,
        head + 40,
        100_000,
        5_000,
        3,
        nonce,
    );
    let planned = plan(
        &OperationRequest::TreasuryFreezeOffer(TreasuryFreezeOfferRequest::new(Blob::new(
            kit::proposal(&view, &freeze_terms(), &offer),
        ))),
        &view,
        &treasury_me(),
    )
    .unwrap();
    (sign(planned, &view), offer.body.id().unwrap())
}

/// The same chain at another head and state (the next block, or a later one).
fn at(head: u64, state: mutiny_consensus_v8::execution::State) -> World {
    let mut world = World::new(head);
    world.state = state;
    world
}

#[test]
fn a_rotation_reserves_its_coins_and_its_generation_until_it_settles_or_is_forgotten() {
    let world = world();
    let view = world.view();
    let signed = signed_rotation(&world);
    assert!(signed.is_complete());
    assert_eq!(
        signed.reserved(),
        &{
            let mut expected = vec![point(0xd1), rotation_resource(&T, 1)];
            expected.sort();
            expected
        }[..]
    );
    let mut outbox = MemoryOutbox::new();
    let id = outbox.commit(&signed, &view).unwrap();
    assert_eq!(id, signed.id());
    assert_eq!(
        id,
        kit::wire(signed.bytes()).operation.id().unwrap(),
        "the identifier is the consensus operation id"
    );
    // Idempotent while open.
    assert_eq!(outbox.commit(&signed, &view).unwrap(), id);
    let reserved = outbox.reserved().unwrap();
    // A second rotation of the same generation (from the other coin) waits for the first.
    let mut busy = World::new(100);
    busy.state = world.state.clone();
    busy.reserved = reserved.clone();
    assert_eq!(
        plan(&rotate_to(&key_c(), 2), &busy.view(), &treasury_me()).unwrap_err(),
        Refusal::ReservedInput
    );
    // A payment of the Treasury cannot select the reserved coin either.
    let payment = plan(
        &OperationRequest::Payment(PaymentRequest::new(address(&key_a(), 1), 100_000)),
        &busy.view(),
        &treasury_me(),
    )
    .unwrap();
    assert!(!payment.inputs().contains(&point(0xd1)));
    // Forgetting releases everything (the signed bytes stay valid elsewhere: there is no revoke).
    outbox.forget(&id).unwrap();
    assert!(outbox.reserved().unwrap().is_empty());
    assert_eq!(
        outbox.get(&id).unwrap().unwrap().status,
        OutboxStatus::Forgotten
    );
    let mut free = World::new(100);
    free.state = world.state.clone();
    free.reserved = outbox.reserved().unwrap();
    assert!(plan(&rotate_to(&key_c(), 2), &free.view(), &treasury_me()).is_ok());
    // Commit again after forgetting: admitted afresh.
    assert_eq!(outbox.commit(&signed, &view).unwrap(), id);
    assert!(outbox.get(&id).unwrap().unwrap().status.is_open());
}

#[test]
fn rotation_records_reconcile_from_verified_state_only() {
    let world = world();
    let view = world.view();
    let signed = signed_rotation(&world);
    let queue = |outbox: &mut MemoryOutbox| {
        outbox.commit(&signed, &view).unwrap();
    };
    for wire_hash in [
        mutiny_consensus_v8::domain_hash(
            &[trading_v1::NATIVE_NAMESPACE, b"/signed"].concat(),
            signed.bytes(),
        ),
        [0xee; 32],
    ] {
        // Deliberately forged TEST host receipt, without canonical execution or index.
        let mut forged = at(101, world.state.clone());
        forged.state.protocol_records.insert(
            record_key(2, signed.id()),
            NativeRecord::Applied {
                wire_hash,
                height: 101,
                fee_atoms: kit::wire(signed.bytes()).operation.meta.fee.0,
            }
            .encode(signed.id())
            .unwrap(),
        );
        let mut outbox = MemoryOutbox::new();
        queue(&mut outbox);
        let report = outbox.reconcile(&forged.view()).unwrap();
        assert_eq!((report.confirmed, report.still_pending), (0, 1));
    }
    // The synthetic execution holds an Applied receipt, but no own canonical inclusion index.
    let after = trading_v1::prepare_batch(
        &world.state,
        view.anchor(),
        view.state_root(),
        &[signed.bytes().to_vec()],
        &CandidatePolicy::native_denomination_locked(),
    )
    .unwrap()
    .into_state();
    let mut outbox = MemoryOutbox::new();
    queue(&mut outbox);
    let included = at(101, after.clone());
    let report = outbox.reconcile(&included.view()).unwrap();
    assert_eq!(report.confirmed, 0);
    assert_eq!(report.inputs_spent, 1);
    let receipt = after
        .protocol_records
        .get(&record_key(2, signed.id()))
        .unwrap();
    assert!(
        matches!(NativeRecord::decode(receipt).unwrap(), (id, NativeRecord::Applied { height: 101, .. }) if id == signed.id())
    );
    assert_eq!(included.view().confirmed_height(&signed.id()), None);
    assert_eq!(
        outbox.get(&signed.id()).unwrap().unwrap().status,
        OutboxStatus::InputsSpent
    );
    assert!(outbox.reserved().unwrap().is_empty());
    // A view OLDER than the queue head says nothing.
    let mut outbox = MemoryOutbox::new();
    queue(&mut outbox);
    let older = at(99, world.state.clone());
    assert_eq!(outbox.reconcile(&older.view()).unwrap().still_pending, 1);
    // Still pending at the same state one block later.
    let later = at(101, world.state.clone());
    assert_eq!(outbox.reconcile(&later.view()).unwrap().still_pending, 1);
    // The window ended without inclusion.
    let expiry = signed.validity().expiry;
    let past = at(expiry, world.state.clone());
    assert_eq!(outbox.reconcile(&past.view()).unwrap().expired, 1);
    // The fee coin was spent by something else.
    let mut outbox = MemoryOutbox::new();
    queue(&mut outbox);
    let mut spent = world.state.clone();
    spent.coins.remove(&point(0xd1));
    assert_eq!(
        outbox
            .reconcile(&at(101, spent).view())
            .unwrap()
            .inputs_spent,
        1
    );
    // Another rotation took generation 1 (from the other coin): this one can never apply.
    let mut outbox = MemoryOutbox::new();
    queue(&mut outbox);
    let competitor = {
        let next = view.anchor().height + 1;
        let hand = kit::HandRotation {
            reference: view.anchor().clone(),
            treasury: T,
            current_generation: 1,
            current_address: address(&key_b(), 1),
            current_descriptor: descriptor(&key_c(), 2),
            new_generation: 2,
            new_address: address(&key_c(), 2),
            new_descriptor: descriptor(&key_c(), 2),
            inputs: vec![(point(0xd2), 300_000)],
            created: next,
            expiry: next + 10,
        };
        kit::hand_rotation_in_view(&view, &hand, &key_c(), 2)
    };
    let taken = trading_v1::prepare_batch(
        &world.state,
        view.anchor(),
        view.state_root(),
        &[competitor],
        &CandidatePolicy::native_denomination_locked(),
    )
    .unwrap()
    .into_state();
    assert!(
        taken.coins.contains_key(&point(0xd1)),
        "our coin is untouched"
    );
    let report = outbox.reconcile(&at(101, taken).view()).unwrap();
    assert_eq!(report.inputs_spent, 1, "{report:?}");
}

#[test]
fn freeze_records_settle_when_the_offer_is_consumed_or_closes() {
    let world = world();
    let view = world.view();
    let (signed, offer) = signed_freeze(&world, 0x61);
    assert_eq!(signed.reserved(), &[freeze_resource(&offer)]);
    assert_eq!(
        signed.validity(),
        &Validity {
            created: 101,
            expiry: 140,
            valid_only_at: None,
            bound_to_parent: false,
        }
    );
    // The identifier is a hash of the freeze body: the same authorization whatever the signature.
    let body = treasury_body(signed.bytes());
    assert_eq!(
        signed.id(),
        mutiny_consensus_v8::domain_hash(treasury::FREEZE_ID_DOMAIN, &body)
    );
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&signed, &view).unwrap();
    assert_eq!(
        outbox.reserved().unwrap(),
        BTreeSet::from([freeze_resource(&offer)])
    );
    // Never "confirmed" by itself.
    assert_eq!(
        outbox
            .reconcile(&at(120, world.state.clone()).view())
            .unwrap()
            .still_pending,
        1
    );
    // The offer is consumed (by whichever hash lock): settled.
    let mut consumed = world.state.clone();
    let context = kit::context_of(&world.anchor);
    let key = trading_v1::single_fill_key(&context, [0; 32], offer);
    consumed.protocol_records.insert(
        record_key(1, key),
        NativeRecord::Consumed {
            context,
            offer,
            trade: [0x21; 32],
            contract: [0x22; 32],
        }
        .encode(key)
        .unwrap(),
    );
    assert_eq!(
        outbox
            .reconcile(&at(121, consumed).view())
            .unwrap()
            .inputs_spent,
        1
    );
    // Another freeze: the offer closes without being consumed.
    let (signed, _) = signed_freeze(&world, 0x62);
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&signed, &view).unwrap();
    assert_eq!(
        outbox
            .reconcile(&at(140, world.state.clone()).view())
            .unwrap()
            .expired,
        1
    );
    // A freeze can be queued only at its creation head: the head moved, the outbox refuses it.
    let (signed, _) = signed_freeze(&world, 0x63);
    let mut outbox = MemoryOutbox::new();
    assert!(matches!(
        outbox
            .commit(&signed, &world.advanced().view())
            .unwrap_err(),
        Refusal::StaleHead { .. }
    ));
    assert!(outbox.records().unwrap().is_empty());
}

/// The freeze body inside the consensus `FrozenTreasuryOffer` encoding `[body, ed448, fndsa]`.
fn treasury_body(frozen: &[u8]) -> Vec<u8> {
    let mut d = minicbor::Decoder::new(frozen);
    assert_eq!(d.array().unwrap(), Some(3));
    d.bytes().unwrap().to_vec()
}

#[test]
fn treasury_records_survive_the_durable_outbox_byte_for_byte() {
    let world = world();
    let view = world.view();
    let rotation = signed_rotation(&world);
    let (freeze, _) = signed_freeze(&world, 0x64);
    let dir = tempdir::TempDir::new("w6-treasury-outbox");
    let path = dir.file("outbox.sqlite");
    {
        let mut outbox = SqliteOutbox::open(&path, view.context()).unwrap();
        outbox.commit(&rotation, &view).unwrap();
        outbox.commit(&freeze, &view).unwrap();
    }
    let outbox = SqliteOutbox::open(&path, view.context()).unwrap();
    let records = outbox.records().unwrap();
    assert_eq!(records.len(), 2);
    for signed in [&rotation, &freeze] {
        let record = outbox.get(&signed.id()).unwrap().unwrap();
        assert_eq!(record.bytes, signed.bytes(), "exact bytes");
        assert_eq!(record.kind, signed.kind());
        assert_eq!(record.reserved, signed.reserved());
        assert!(record.status.is_open());
    }
    let mut expected: BTreeSet<OutPoint> = rotation.reserved().iter().cloned().collect();
    expected.extend(freeze.reserved().iter().cloned());
    assert_eq!(outbox.reserved().unwrap(), expected);
}

fn longest_run(text: &str, keep: impl Fn(char) -> bool) -> usize {
    let mut best = 0;
    let mut run = 0;
    for c in text.chars() {
        if keep(c) {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    best
}

#[test]
fn no_treasury_value_prints_a_secret_or_a_long_byte_dump() {
    let world = world();
    let view = world.view();
    let rotation_plan = plan(&rotate_to(&key_c(), 2), &view, &treasury_me()).unwrap();
    let rotation_review = review(&rotation_plan, &view).unwrap();
    let rotation = signed_rotation(&world);
    let (freeze, _) = signed_freeze(&world, 0x65);
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&rotation, &view).unwrap();
    let declaration = TreasuryDeclaration::new(view.context().genesis, ChainClass::TestValue)
        .with_authority()
        .with_destination_of(T);
    let declared = profile::declare(
        SignerIdentity::from_public(key_c().public(), 2, Some(T)).unwrap(),
        &declaration,
        &view,
    )
    .unwrap();
    let standing = profile::standing(&view, &declared);
    let treasuries = treasury::trading_treasuries(&view);
    let signer = signer();
    let shown = [
        format!("{rotation_plan:?}"),
        format!("{rotation_review:?}"),
        format!("{rotation:?}"),
        format!("{freeze:?}"),
        format!("{:?}", outbox.records().unwrap()),
        format!("{declaration:?}"),
        format!("{declared:?}"),
        format!("{standing:?}"),
        format!("{treasuries:?}"),
        format!("{signer:?}"),
        format!(
            "{:?}",
            OperationRequest::TreasuryRotate(TreasuryRotateRequest::new(Blob::new(vec![
                0xcd;
                2000
            ])))
        ),
        format!(
            "{:?}",
            OperationRequest::TreasuryFreezeOffer(TreasuryFreezeOfferRequest::new(Blob::new(
                vec![0xcd; 2000]
            )))
        ),
    ];
    for text in &shown {
        assert!(
            longest_run(text, |c| c.is_ascii_hexdigit()) < 64,
            "a long hex run: {text}"
        );
        assert!(
            longest_run(text, |c| c.is_ascii_digit() || c == ',' || c == ' ') < 64,
            "a long number dump: {text}"
        );
        assert!(text.len() < 1_500, "unbounded Debug: {text}");
    }
    assert!(format!("{signer:?}").contains("<redacted>"));
}

/// A small deterministic generator for reproducible random cases.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[test]
fn random_coin_sets_give_an_exact_fee_exact_change_and_native_input_order() {
    let mut rng = Rng(0x6_2026_1003);
    let (mut accepted, mut refused) = (0, 0);
    for case in 0..20 {
        let mut world = world();
        world.state.coins.clear();
        let count = 1 + rng.below(20) as u32;
        let mut total: u128 = 0;
        for index in 0..count {
            let atoms = match rng.below(4) {
                0 => 1 + rng.below(300),
                1 => 1 + rng.below(6_000),
                2 => 5_000 + rng.below(200_000),
                _ => 100_000 + rng.below(9_000_000),
            };
            total += u128::from(atoms);
            world.coin(address(&key_b(), 1), atoms, 1, false, 0x70, index);
        }
        let view = world.view();
        match plan(&rotate_to(&key_c(), 2), &view, &treasury_me()) {
            Ok(planned) => {
                accepted += 1;
                let wire = kit::wire(&planned.objects()[0].bytes);
                let ids = &wire.operation.meta.inputs;
                assert!(ids.windows(2).all(|w| w[0] < w[1]), "case {case}: order");
                assert_eq!(
                    wire.inputs.iter().map(native_input_id).collect::<Vec<_>>(),
                    *ids
                );
                let Action::TreasuryRotate { change, .. } = wire.operation.action else {
                    panic!()
                };
                let fee = wire.operation.meta.fee.0;
                let spent: u64 = wire
                    .inputs
                    .iter()
                    .map(|p| world.state.coins[p].output.atoms)
                    .sum();
                assert_eq!(spent, change.0 + fee, "case {case}: conservation");
                // The fee covers the minimum for the SIGNED size: a fixed point that only rises, so
                // an integer field shrinking by a width step can leave it a few atoms above.
                let signed = kit::signed_with(wire, 0, &key_c(), 2);
                let minimum = (signed.len() as u64).max(240);
                assert!(
                    fee >= minimum && fee - minimum <= 8,
                    "case {case}: fee {fee}, minimum {minimum}"
                );
                kit::consensus_in(&view, &signed).unwrap();
            }
            Err(Refusal::InsufficientFunds {
                available,
                requested,
            }) => {
                refused += 1;
                assert_eq!(u128::from(available), total, "case {case}");
                assert!(u128::from(requested) > total, "case {case}");
            }
            Err(Refusal::TooManyInputs { limit: 16 }) => {
                refused += 1;
                assert!(count > 16);
            }
            Err(other) => panic!("case {case}: {other:?}"),
        }
    }
    assert!(accepted > 0, "accepted {accepted}, refused {refused}");
}

#[test]
fn random_freezes_round_trip_through_the_proposal_and_equal_the_consensus_payload() {
    let mut rng = Rng(0x6_f8ee_2e00);
    let world = world();
    let view = world.view();
    let maker = key_c();
    for case in 0..12 {
        let network = 1 + rng.below(3) as u8;
        let amount = 1 + rng.below(50_000_000);
        let satoshis = 1 + rng.below(10_000_000);
        let expiry = 101 + rng.below(10_000);
        let offer = kit::treasury_offer_at_generation(
            &maker,
            2,
            T,
            kit::context_of(&world.anchor),
            100,
            expiry,
            amount,
            satoshis,
            network,
            case as u8,
        );
        let terms = FreezeTerms {
            trade: [1 + case as u8; 32],
            contract: [0x80 + case as u8; 32],
            ..freeze_terms()
        };
        let payload = kit::prepare_freeze(&view, &terms, &offer).unwrap();
        let independent = kit::freeze_body(
            &kit::context_of(&world.anchor),
            view.anchor(),
            view.state_root(),
            &terms,
            &offer.body,
        );
        assert_eq!(payload, independent, "case {case}: the test mirror");
        let proposal = treasury::freeze_proposal(&payload, &kit::offer_import(&offer)).unwrap();
        let planned = plan(
            &OperationRequest::TreasuryFreezeOffer(TreasuryFreezeOfferRequest::new(Blob::new(
                proposal.clone(),
            ))),
            &view,
            &treasury_me(),
        )
        .unwrap();
        assert_eq!(planned.objects()[0].bytes, payload, "case {case}");
        assert_eq!(planned.validity().expiry, expiry);
        let reviewed = review(&planned, &view).unwrap();
        assert_eq!(reviewed.amount(), Some(amount));
        assert!(
            reviewed
                .render_text()
                .contains(&format!("{satoshis} satoshis"))
        );
        // The adopted proposal is the same plan.
        assert_eq!(
            adopt(&proposal, &view, &treasury_me()).unwrap().objects()[0].bytes,
            payload
        );
    }
}

/// The consensus TreasuryRotate cases of `trading_v1_tests.rs`, through the WALLET path (plan,
/// review, approval, `KeySigner`), each applied by `trading_v1::prepare_batch`: successive rotations
/// are immediate at inclusion and keep the whole history (the first generation still resolves), only
/// the current generation's key can rotate, and two competing successors of one generation have one
/// deterministic winner (in one block the second fails; after the first, the wallet refuses the
/// second as consensus does).
#[test]
fn successive_rotations_and_a_competing_successor_match_consensus_through_the_wallet() {
    let world = world();
    let context = kit::context_of(&world.anchor);
    let policy = CandidatePolicy::native_denomination_locked();
    let view = world.view();
    // Both candidates route to the SAME current authority. Only their fee coins differ.
    let first = signed_rotation(&world);
    let mut other = at(100, world.state.clone());
    let first_inputs = kit::wire(first.bytes()).inputs;
    other.reserved = first_inputs.iter().cloned().collect();
    let second = sign(
        plan(&rotate_to(&key_c(), 2), &other.view(), &treasury_me()).unwrap(),
        &other.view(),
    );
    let second_inputs = kit::wire(second.bytes()).inputs;
    assert!(first_inputs.iter().all(|p| !second_inputs.contains(p)));
    assert_ne!(first.id(), second.id());
    let before = world.state.records().unwrap();
    assert!(
        trading_v1::prepare_batch(
            &world.state,
            view.anchor(),
            view.state_root(),
            &[first.bytes().to_vec(), second.bytes().to_vec()],
            &policy
        )
        .is_err()
    );
    assert_eq!(
        world.state.records().unwrap(),
        before,
        "failed candidate is atomic"
    );
    for (winner, loser) in [(&first, &second), (&second, &first)] {
        let state = trading_v1::prepare_batch(
            view.state(),
            view.anchor(),
            view.state_root(),
            &[winner.bytes().to_vec()],
            &policy,
        )
        .unwrap()
        .into_state();
        let current = trading_v1::treasury_current(&state, &context, T).unwrap();
        assert_eq!(
            (
                current.generation,
                current.address,
                current.effective_height
            ),
            (2, address(&key_c(), 2), 101)
        );
        let next = at(101, state);
        let mut history = mutiny_consensus_v8::evidence_history_v2::History::default();
        history
            .insert_anchor(world.anchor.height, world.anchor.block)
            .unwrap();
        let next_view = next.view().with_history(&history);
        assert_eq!(
            explain(loser.bytes(), &next_view, &treasury_me()).unwrap_err(),
            Refusal::StaleAuthority
        );
        let verdict = trading_v1::prepare_batch_with_history(
            &next.state,
            next_view.anchor(),
            next_view.state_root(),
            &history,
            &[loser.bytes().to_vec()],
            &policy,
        )
        .err()
        .expect("competing signed successor must be stale");
        assert_eq!(
            verdict,
            trading_v1::NativeError::Stale(mutiny_consensus_v8::op_envelope_v1::TAG_TREASURY_HEAD)
        );
    }
    // Synthetic state transitions: ordinary signed WalletBook rotations precede each R2.
    // No synthetic Applied record is qualified as canonical finality.
    let mut current = at(
        101,
        trading_v1::prepare_batch(
            view.state(),
            view.anchor(),
            view.state_root(),
            &[first.bytes().to_vec()],
            &policy,
        )
        .unwrap()
        .into_state(),
    );
    type KeyFn = fn() -> HybridKey;
    let steps: [(KeyFn, u64, KeyFn, u64); 2] = [(key_c, 2, key_a, 3), (key_a, 3, key_d, 4)];
    for (index, (from, from_generation, to, to_generation)) in steps.iter().enumerate() {
        let head = 101 + index as u64;
        assert_eq!(current.anchor.height, head);
        kit::apply_wallet_rotation_model(
            &mut current.state,
            &current.anchor,
            T,
            &from(),
            *from_generation,
            &to(),
            *to_generation,
            head,
        );
        let me = SignerIdentity::from_public(to().public(), *to_generation, Some(T))
            .unwrap()
            .with_treasury_roles_for_test(TreasuryRoles {
                authority: true,
                destination_of: Some(T),
            });
        let stale = SignerIdentity::from_public(from().public(), *from_generation, Some(T))
            .unwrap()
            .with_treasury_roles_for_test(TreasuryRoles {
                authority: true,
                destination_of: Some(T),
            });
        let request = rotate_to(&to(), *to_generation);
        let view = current.view();
        assert!(
            plan(&request, &view, &stale).is_err(),
            "retired key cannot sign R2"
        );
        let planned = plan(&request, &view, &me).unwrap();
        let reviewed = review(&planned, &view).unwrap();
        let signer = KeySigner::with_identity(
            to(),
            me,
            SigningGate::test_value().unwrap(),
            DEFAULT_IDLE_LIMIT,
        )
        .unwrap();
        let signed = signer
            .authorize(planned, kit::approve(&reviewed, &view), &view)
            .unwrap();
        let state = trading_v1::prepare_batch(
            view.state(),
            view.anchor(),
            view.state_root(),
            &[signed.bytes().to_vec()],
            &policy,
        )
        .unwrap()
        .into_state();
        let active = trading_v1::treasury_current(&state, &context, T).unwrap();
        assert_eq!(
            (active.generation, active.address, active.effective_height),
            (index as u64 + 3, address(&to(), *to_generation), head + 1)
        );
        current = at(head + 1, state);
    }
    let history = trading_v1::treasury_generations(&current.state, &context, T).unwrap();
    assert_eq!(
        history.iter().map(|d| d.address).collect::<Vec<_>>(),
        vec![
            address(&key_b(), 1),
            address(&key_c(), 2),
            address(&key_a(), 3),
            address(&key_d(), 4)
        ]
    );
    assert_eq!(
        trading_v1::treasury_generation(&current.state, &context, T, 1)
            .unwrap()
            .address,
        T
    );
}
