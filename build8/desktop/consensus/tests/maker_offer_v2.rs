//! P7: the canonical maker-offer format (Order of 4 October 2026, decision P7; Lane P design
//! `qualification/candidate-3/P-LANE-DESIGN-V1.md` section 8 and test plan 14.7, with amendment AM-6
//! of `P-LANE-DESIGN-AMENDMENTS-V1.md`). Real-block tests: every offer-bound trading item is
//! prepared by the production assembler, executed by the V2 executor and installed by
//! `CanonicalStore::commit`; every negative is one consensus check of design 8.2 violated by an
//! otherwise honest, genuinely signed item, refused (a) with the EXACT `NativeError` at the read-only
//! consensus entry point (`prepare_batch`) on the same parent state, (b) by the assembler/executor
//! path and (c) by `CanonicalStore::commit` of a certified block, each leaving the head, the
//! canonical State records and every store row byte-identical. Also: the public vector file
//! `qualification/trading-maker-offer-v2-vectors.json` (generator and reader) and the domain
//! registry entries. TEST-VALUE only (published BIP39 test phrases); Windows-host software evidence,
//! at most NATIVE-PASS-offline-TEST-VALUE.
#![allow(dead_code, unused_imports)]
#[path = "../../desktop/src/wallet_host_fixture_licenses.rs"]
mod licenses;
#[path = "support/wallet_host_fixture_tpm.rs"]
mod tpm;
include!("support/dividend_rig.rs");
include!("support/trading_rig_v1.rs");

use mutiny_consensus_v8::{
    blocks::BlockBody,
    op_envelope_v1::{assignment_facts, entitlement_facts},
};
use tr::{Error as E, NativeError as N};

/// The third test wallet (not the slot signer of any item below): a published BIP39 test phrase.
fn third_key() -> HybridKey {
    HybridKey::wallet_restore(
        "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        Role::WalletOwner,
    )
    .unwrap()
}
fn raw(op: &tr::NativeOperation) -> Vec<u8> {
    op.encode().unwrap()
}
fn next_window(rig: &Rig) -> Window {
    window_at(rig, rig.height(), rig.height() + 1, rig.height() + 20)
}
fn lock_action(sender: Hash, recipient: Hash) -> tr::Action {
    tr::Action::HashLock {
        offer: [0; 32],
        maker: [0; 32],
        sender,
        recipient,
        amount: tr::Strikes(50_000),
        condition: tr::preimage_hash(&[42; 32]),
        refund_height: 1_000,
        change: tr::Strikes(30_000),
    }
}

/// The maker of an offer: its wallet key, the descriptor generation it signs with, and its side.
#[derive(Clone, Copy)]
struct Maker<'a> {
    key: &'a HybridKey,
    generation: u64,
    side: u8,
}

/// The offer body an honest maker on `maker.side` publishes for `action` (design 8.2: the maker's
/// slot address, its own destination, a fixed hash condition for HashLinked terms, the fee as
/// maximum), before the test's `edit`.
fn honest_body(f: &Fixture, op: &tr::Operation, maker: Maker, window: Window, fee: u64) -> tr::OfferBody {
    let destination = match (&op.action, maker.side) {
        (tr::Action::HashLock { sender, .. }, 0) => *sender,
        (tr::Action::HashLock { recipient, .. }, _) => *recipient,
        (tr::Action::FiatLock { seller, .. }, 0) => *seller,
        (tr::Action::FiatLock { buyer, .. }, _) => *buyer,
        (tr::Action::LicenseDvp { payment_destination, .. }, 0) => *payment_destination,
        (tr::Action::LicenseDvp { buyer, .. }, _) => *buyer,
        _ => unreachable!(),
    };
    let condition = match &op.action {
        tr::Action::HashLock { condition, .. } => Some(*condition),
        _ => None,
    };
    tr::OfferBody {
        context: trade_context(f),
        maker_descriptor: desc(maker.key, maker.generation),
        maker_wallet: op.slot_address(maker.side).unwrap(),
        maker_side: maker.side,
        nonce: [77; 32],
        created: window.first,
        expiry: window.last,
        terms: offer_terms(&op.action).unwrap(),
        destination,
        condition,
        max_fee: tr::Strikes(fee),
    }
}

/// A complete, genuinely signed offer-bound item: the maker's MakerOffer (body from `honest_body`
/// then `edit`), signed by `maker.key`; the operation names the offer id and maker identity; the
/// maker's fill signature over the exact body; one approval per `signers` entry.
#[allow(clippy::too_many_arguments)]
fn filled(
    f: &Fixture,
    action: tr::Action,
    window: Window,
    preconditions: Vec<Precondition>,
    fee: u64,
    inputs: &[OutPoint],
    signers: &[(u8, &HybridKey, u64)],
    maker: Maker,
    edit: impl FnOnce(&mut tr::OfferBody),
) -> tr::NativeOperation {
    let mut inputs = inputs.to_vec();
    inputs.sort_by_key(tr::native_input_id);
    let mut meta = trade_meta(trade_context(f), window, fee, &inputs);
    meta.envelope.preconditions = preconditions;
    let mut operation = tr::Operation { meta, action, approvals: vec![], offer_proof: None };
    let mut body = honest_body(f, &operation, maker, window, fee);
    edit(&mut body);
    let offer = tr::MakerOffer::sign(body, maker.key).unwrap();
    match &mut operation.action {
        tr::Action::HashLock { offer: o, maker: m, .. }
        | tr::Action::FiatLock { offer: o, maker: m, .. }
        | tr::Action::LicenseDvp { offer: o, maker: m, .. } => {
            *o = offer.body.id().unwrap();
            *m = offer.body.maker().unwrap();
        }
        _ => unreachable!(),
    }
    operation.offer_proof = Some(tr::OfferProof::sign(offer, &operation, maker.key).unwrap());
    for (slot, key, generation) in signers {
        operation.approve(*slot, key, *generation).unwrap();
    }
    tr::NativeOperation { operation, inputs }
}

/// (a) exact error at `prepare_batch` on the rig's parent state, (b) the assembler/executor path
/// and (c) `CanonicalStore::commit` of a certified block both refuse it, store byte-identical.
fn refused(rig: &mut Rig, name: &str, item: &[u8], expected: N) {
    let epoch = rig.height() + 1;
    // The History holds every canonical height, so an older envelope reference is resolvable.
    let heights: Vec<u64> = (0..=rig.height()).collect();
    assert_eq!(native_verdict_with(rig, &[item.to_vec()], &heights).err(), Some(expected), "{name}: exact error");
    let text = rejected_unchanged(rig, epoch, &[item.to_vec()]);
    assert!(text.contains("UnsupportedOperation"), "{name}: the trading phase refuses the block: {text}");
    commit_rejected_unchanged(rig, epoch, &[item.to_vec()]);
}

/// Wallets a (maker, generation 1), b (taker, registered) and their coins.
struct Market {
    rig: Rig,
    a: HybridKey,
    b: HybridKey,
    coins: Vec<OutPoint>,
    taker_coins: Vec<OutPoint>,
    /// b's 40,000-atom coin for one wallet-rotation fee (`rotate_in_block`).
    fee_coin: OutPoint,
}
fn market(tag: &str) -> Market {
    let (a, b) = (owner_key(), second_key());
    let mut f = fixture();
    f.state.wallets.register(&desc(&b, 1)).unwrap();
    let coins = (0..6).map(|n| fund(&mut f, 0x30 + n, addr(&a, 1), 100_000)).collect();
    let taker_coins = (0..4).map(|n| fund(&mut f, 0x40 + n, addr(&b, 1), 100_000)).collect();
    let fee_coin = fund(&mut f, 0x50, addr(&b, 1), 40_000);
    Market { rig: Rig::new(f, tag), a, b, coins, taker_coins, fee_coin }
}
fn single_fill_record(op: &tr::NativeOperation) -> Hash {
    let tr::Action::HashLock { offer, .. } = op.operation.action else { unreachable!() };
    tr::record_key(1, tr::single_fill_key(&op.operation.meta.context, [0; 32], offer))
}

/// 14.7 positive + single fill (design 8.2 "single fill", 8.5): a canonical maker offer settles in a
/// real block and records its single fill; a second fill of the SAME offer (another honest item
/// with other inputs) is refused with `Duplicate` in a later block and, together with the first,
/// makes a whole block fail atomically; both refusals leave the store byte-identical.
#[test]
fn maker_offer_settles_once_and_a_second_fill_fails_atomically() {
    let Market { mut rig, a, b, coins, .. } = market("offer-single-fill");
    let (aa, ba) = (addr(&a, 1), addr(&b, 1));
    let maker = Maker { key: &a, generation: 1, side: 0 };
    let w = window_at(&rig, 0, 1, 30);
    let signers = [(0, &a, 1), (1, &b, 1)];
    let first = filled(&rig.f, lock_action(aa, ba), w, vec![], 20_000, &[coins[0].clone()], &signers, maker, |_| {});
    let second = filled(&rig.f, lock_action(aa, ba), w, vec![], 20_000, &[coins[1].clone()], &signers, maker, |_| {});
    let o = |op: &tr::NativeOperation| op.operation.offer_proof.as_ref().unwrap().offer.body.id().unwrap();
    assert_eq!(o(&first), o(&second), "the same offer");
    assert_ne!(first.operation.id().unwrap(), second.operation.id().unwrap(), "two different fills");
    // Both fills in one block: the whole block fails (the second fill), nothing is installed.
    assert_eq!(native_verdict(&rig, &[raw(&first), raw(&second)]).err(), Some(N::Duplicate));
    rejected_unchanged(&mut rig, 1, &[raw(&first), raw(&second)]);
    commit_rejected_unchanged(&mut rig, 1, &[raw(&first), raw(&second)]);
    // The first fill alone settles and records the single fill.
    assert!(!rig.state.protocol_records.contains_key(&single_fill_record(&first)));
    let s1 = rig.step(1, &[raw(&first)]);
    assert!(s1.protocol_records.contains_key(&single_fill_record(&first)), "Consumed record");
    assert_eq!(tr::locked(&s1, first.operation.output_id(0).unwrap()).unwrap().amount, tr::Strikes(50_000));
    // A later second fill of the consumed offer is refused, byte-identical.
    refused(&mut rig, "second fill", &raw(&second), N::Duplicate);
    let rig = rig.restart();
    assert_eq!(rig.state.records().unwrap(), s1.records().unwrap(), "replay reproduces the state");
    rig.finish();
}

/// 8.2 maker authority (`maker_wallet == slot_address(maker_side)`): an offer naming another wallet
/// than the maker side's slot cannot be filled (`Authority`), whether it names the taker's slot or
/// the maker claims the other side.
#[test]
fn maker_wallet_must_be_the_maker_sides_slot_address() {
    let Market { mut rig, a, b, coins, .. } = market("offer-maker-wallet");
    let (aa, ba) = (addr(&a, 1), addr(&b, 1));
    let maker = Maker { key: &a, generation: 1, side: 0 };
    let signers = [(0, &a, 1), (1, &b, 1)];
    let w = next_window(&rig);
    let other = filled(&rig.f, lock_action(aa, ba), w, vec![], 20_000, &[coins[0].clone()], &signers, maker, |b| {
        b.maker_wallet = ba
    });
    refused(&mut rig, "maker wallet names the taker's slot", &raw(&other), N::Candidate(E::Authority));
    let side = filled(&rig.f, lock_action(aa, ba), w, vec![], 20_000, &[coins[0].clone()], &signers, maker, |b| {
        b.maker_side = 1
    });
    refused(&mut rig, "maker key claims the other side", &raw(&side), N::Candidate(E::Authority));
    let honest = filled(&rig.f, lock_action(aa, ba), w, vec![], 20_000, &[coins[0].clone()], &signers, maker, |_| {});
    rig.step(1, &[raw(&honest)]);
    rig.finish();
}

/// At first funding the offer needs current maker authority. An old canonical
/// reference and current settlement approvals cannot grandfather a retired offer.
#[test]
fn rotation_before_funding_refuses_retired_offer_and_requires_current_review() {
    let Market { mut rig, a, b, coins, fee_coin, .. } = market("offer-maker-rotation");
    let (aa, ba) = (addr(&a, 1), addr(&b, 1));
    let c = third_key();
    let old_window = next_window(&rig);
    let old_maker = Maker { key: &a, generation: 1, side: 0 };
    let pending = filled(&rig.f, lock_action(aa, ba), old_window, vec![], 20_000,
        &[coins[0].clone()], &[(0, &a, 1), (1, &b, 1)], old_maker, |_| {});
    let pending_raw = raw(&pending);
    let mut pool = mutiny_consensus_v8::submission_pool_v1::SubmissionPool::open(
        &rig.base.join("complete-pool.sqlite"), rig.parent.genesis, rig.parent.fingerprint,
        64 * 1024 * 1024).unwrap();
    rig.chain.reconcile_submission_pool(&mut pool, 1).unwrap();
    let (pending_id, _) = pool.admit(&rig.parent, &rig.state, &anchors(&rig, &[0]),
        1, 1, &pending_raw).unwrap();
    rotate_in_block(&mut rig, 1, aa, (&a, 1), (&c, 2), &b, fee_coin, &[]);
    rig.chain.reconcile_submission_pool(&mut pool, 2).unwrap();
    assert!(matches!(pool.status(pending_id).unwrap(),
        mutiny_consensus_v8::submission_v1::Status::Conflicting {
            reason: mutiny_consensus_v8::submission_v1::Reason::AuthorityChanged, .. }));
    assert_eq!(pool.exact_bytes(pending_id).unwrap().unwrap().1, pending_raw);
    refused(&mut rig, "old pending offer after rotation", &pending_raw, N::Authority);
    let stale_slot = filled(&rig.f, lock_action(aa, ba), old_window, vec![], 20_000, &[coins[0].clone()], &[(0, &a, 1), (1, &b, 1)],
        old_maker, |_| {});
    refused(&mut rig, "slot approved by the rotated-out key", &raw(&stale_slot), N::Authority);
    let filled_after_rotation = filled(&rig.f, lock_action(aa, ba), old_window, vec![], 20_000, &[coins[0].clone()],
        &[(0, &c, 2), (1, &b, 1)], old_maker, |_| {});
    refused(&mut rig, "retired offer with current settlement approvals", &raw(&filled_after_rotation), N::Authority);
    let current = filled(&rig.f, lock_action(aa, ba), next_window(&rig), vec![], 20_000,
        &[coins[0].clone()], &[(0, &c, 2), (1, &b, 1)],
        Maker { key: &c, generation: 2, side: 0 }, |_| {});
    native_verdict(&rig, &[raw(&current)]).unwrap();
    rig.step(2, &[raw(&current)]);
    drop(pool);
    rig.finish();
}

/// Trading precedes payments: current-key funding before that block's rotation
/// creates a durable lock. Later refund preserves its terms and needs current authority.
#[test]
fn first_funding_before_same_block_rotation_preserves_lock_and_current_refund() {
    let Market { mut rig, a, b, coins, fee_coin, .. } = market("offer-funded-then-rotation");
    let (aa, ba) = (addr(&a, 1), addr(&b, 1));
    let c = third_key();
    let w = window_at(&rig, 0, 1, 2);
    let mut action = lock_action(aa, ba);
    if let tr::Action::HashLock { refund_height, .. } = &mut action {*refund_height=5;}
    let funded = filled(&rig.f, action, w, vec![], 20_000, &[coins[0].clone()],
        &[(0, &a, 1), (1, &b, 1)], Maker {key:&a,generation:1,side:0}, |_| {});
    let output=funded.operation.output_id(0).unwrap();
    let after=rotate_in_block(&mut rig,1,aa,(&a,1),(&c,2),&b,fee_coin,&[raw(&funded)]);
    let exact_lock=tr::locked(&after,output).unwrap();
    assert_eq!((exact_lock.sender,exact_lock.recipient,exact_lock.amount.0),(aa,ba,50_000));
    assert_eq!(exact_lock.kind,tr::NativeLockKind::Hash {
        condition:tr::preimage_hash(&[42;32]),refund_height:5 });
    rig.step(2,&[]);rig.step(3,&[]);rig.step(4,&[]);
    assert_eq!(tr::locked(&rig.state,output).unwrap(),exact_lock);
    let w=next_window(&rig);
    let refund=|key:&HybridKey,generation| trade(&rig.f,
        tr::Action::Refund{output,owner:aa,amount:tr::Strikes(50_000),change:tr::Strikes(80_000)},
        w,20_000,&[coins[1].clone()],&[(0,key,generation)]);
    let stale=refund(&a,1);let current=refund(&c,2);
    refused(&mut rig,"retired-key funded lock refund",&raw(&stale),N::Authority);
    rig.step(5,&[raw(&current)]);
    assert!(tr::locked(&rig.state,output).is_err());
    let payout=&rig.state.coins[&OutPoint{transaction:current.operation.id().unwrap(),index:0}];
    assert_eq!((payout.output.owner,payout.output.atoms),(aa,50_000));
    rig.finish();
}

/// 8.2 destination and 8.5: the taker cannot redirect the maker's proceeds. A HashLock whose maker
/// (sender) receives refund/change at another address than the offer's destination, and a License
/// sale whose taker substitutes its own `payment_destination` for the seller-maker's destination,
/// are both refused with `OfferBinding`; the honest sale pays the offer's destination.
#[test]
fn taker_cannot_redirect_the_makers_destination() {
    let Market { mut rig, a, b, coins, taker_coins, .. } = market("offer-destination");
    let (aa, ba) = (addr(&a, 1), addr(&b, 1));
    let maker = Maker { key: &a, generation: 1, side: 0 };
    let w = next_window(&rig);
    let lock = filled(&rig.f, lock_action(aa, ba), w, vec![], 20_000, &[coins[0].clone()], &[(0, &a, 1), (1, &b, 1)],
        maker, |b| b.destination = [0x5e; 32]);
    refused(&mut rig, "HashLock maker destination", &raw(&lock), N::Candidate(E::OfferBinding));
    // License sale: maker = seller a (slot 0), destination = a; the taker (buyer b) pays itself.
    let sold = license(3);
    let facts = vec![entitlement_facts(&rig.state, sold), assignment_facts(&rig.state, sold).unwrap()];
    let sale = |payment_destination: Hash, destination: Hash| {
        filled(
            &rig.f,
            tr::Action::LicenseDvp {
                offer: [0; 32],
                maker: [0; 32],
                license: sold,
                license_generation: 1,
                seller: aa,
                buyer: ba,
                price: tr::Strikes(50_000),
                payment_destination,
                change: tr::Strikes(30_000),
            },
            w,
            facts.clone(),
            20_000,
            &[taker_coins[0].clone()],
            &[(0, &a, 1), (1, &b, 1)],
            maker,
            move |body| body.destination = destination,
        )
    };
    let (redirected, honest) = (sale(ba, aa), sale(aa, aa));
    refused(&mut rig, "DvP payment redirected by the taker", &raw(&redirected), N::Candidate(E::OfferBinding));
    let s1 = rig.step(1, &[raw(&honest)]);
    assert_eq!(s1.licenses_v2.license(sold).unwrap().owner, ba);
    let paid = &s1.coins[&OutPoint { transaction: honest.operation.id().unwrap(), index: 0 }];
    assert_eq!((paid.output.owner, paid.output.atoms), (aa, 50_000), "the price reaches the offer's destination");
    rig.finish();
}

/// 8.2 condition: a maker-fixed hash condition cannot be swapped by the taker (`Condition`); an
/// offer that fixes no condition leaves it to the operation.
#[test]
fn maker_fixed_condition_cannot_be_swapped() {
    let Market { mut rig, a, b, coins, .. } = market("offer-condition");
    let (aa, ba) = (addr(&a, 1), addr(&b, 1));
    let maker = Maker { key: &a, generation: 1, side: 0 };
    let signers = [(0, &a, 1), (1, &b, 1)];
    let w = next_window(&rig);
    let swapped = filled(&rig.f, lock_action(aa, ba), w, vec![], 20_000, &[coins[0].clone()], &signers, maker, |b| {
        b.condition = Some(tr::preimage_hash(&[43; 32]))
    });
    refused(&mut rig, "swapped condition", &raw(&swapped), N::Candidate(E::Condition));
    let open = filled(&rig.f, lock_action(aa, ba), w, vec![], 20_000, &[coins[0].clone()], &signers, maker, |b| {
        b.condition = None
    });
    native_verdict(&rig, &[raw(&open)]).unwrap();
    rig.step(1, &[raw(&open)]);
    rig.finish();
}

/// 8.2 fee terms: when the maker's slot pays the fee, the operation fee may not exceed `max_fee`
/// (`Fee`); a maker that does not pay (the recipient of a HashLock) is not bound by it.
#[test]
fn maker_never_pays_more_than_max_fee() {
    let Market { mut rig, a, b, coins, .. } = market("offer-max-fee");
    let (aa, ba) = (addr(&a, 1), addr(&b, 1));
    let signers = [(0, &a, 1), (1, &b, 1)];
    let w = next_window(&rig);
    let over = filled(&rig.f, lock_action(aa, ba), w, vec![], 20_000, &[coins[0].clone()], &signers,
        Maker { key: &a, generation: 1, side: 0 }, |b| b.max_fee = tr::Strikes(19_999));
    refused(&mut rig, "fee above the maker's max_fee", &raw(&over), N::Candidate(E::Fee));
    // Exactly max_fee is accepted; a recipient-maker with a lower max_fee does not pay, so it binds nothing.
    let exact = filled(&rig.f, lock_action(aa, ba), w, vec![], 20_000, &[coins[0].clone()], &signers,
        Maker { key: &a, generation: 1, side: 0 }, |b| b.max_fee = tr::Strikes(20_000));
    native_verdict(&rig, &[raw(&exact)]).unwrap();
    let recipient_maker = filled(&rig.f, lock_action(aa, ba), w, vec![], 20_000, &[coins[1].clone()], &signers,
        Maker { key: &b, generation: 1, side: 1 }, |b| b.max_fee = tr::Strikes(240));
    native_verdict(&rig, &[raw(&recipient_maker)]).unwrap();
    rig.step(1, &[raw(&exact), raw(&recipient_maker)]);
    rig.finish();
}

/// 8.2 validity: the operation window (and the inclusion height) lie inside the offer window; an
/// offer created after the window opens is `Time`, one expiring before it closes is `Expired`.
#[test]
fn operation_window_must_lie_inside_the_offer_window() {
    let Market { mut rig, a, b, coins, .. } = market("offer-window");
    let (aa, ba) = (addr(&a, 1), addr(&b, 1));
    let maker = Maker { key: &a, generation: 1, side: 0 };
    let signers = [(0, &a, 1), (1, &b, 1)];
    let w = next_window(&rig);
    let late = filled(&rig.f, lock_action(aa, ba), w, vec![], 20_000, &[coins[0].clone()], &signers, maker, |b| {
        b.created = w.first + 1
    });
    refused(&mut rig, "offer created after the window opens", &raw(&late), N::Candidate(E::Time));
    let short = filled(&rig.f, lock_action(aa, ba), w, vec![], 20_000, &[coins[0].clone()], &signers, maker, |b| {
        b.expiry = w.last - 1
    });
    refused(&mut rig, "offer expires before the window closes", &raw(&short), N::Candidate(E::Expired));
    // The window opened BEFORE the offer existed, although the inclusion height is inside the offer
    // window: still `Time` (the signed window itself must lie inside the offer window).
    advance(&mut rig, 1);
    let early = filled(&rig.f, lock_action(aa, ba), w, vec![], 20_000, &[coins[1].clone()], &signers, maker, |b| {
        b.created = w.first + 1
    });
    refused(&mut rig, "window opens before the offer was created", &raw(&early), N::Candidate(E::Time));
    let inside = filled(&rig.f, lock_action(aa, ba), w, vec![], 20_000, &[coins[0].clone()], &signers, maker, |b| {
        b.created = w.first;
        b.expiry = w.last
    });
    rig.step(3, &[raw(&inside)]);
    rig.finish();
}

/// 8.2 version and 8.3: an item whose MakerOffer carries a version-1 body cannot be decoded
/// (`OfferBinding`), so no block body can carry it (`BlockBody::encode` refuses it, AM-11) and a
/// real block proposing it is refused with the store byte-identical.
#[test]
fn version_one_offer_body_cannot_settle() {
    let Market { mut rig, a, b, coins, .. } = market("offer-version-one");
    let (aa, ba) = (addr(&a, 1), addr(&b, 1));
    let honest = raw(&filled(&rig.f, lock_action(aa, ba), next_window(&rig), vec![], 20_000, &[coins[0].clone()],
        &[(0, &a, 1), (1, &b, 1)], Maker { key: &a, generation: 1, side: 0 }, |_| {}));
    // NAMESPACE occurs in the trading body and then in the offer body; the byte after the second
    // occurrence is the offer body's version.
    let at: Vec<usize> = honest.windows(tr::NAMESPACE.len()).enumerate().filter(|(_, w)| *w == tr::NAMESPACE).map(|(i, _)| i).collect();
    assert_eq!(at.len(), 2);
    let v = at[1] + tr::NAMESPACE.len();
    assert_eq!(honest[v], tr::OFFER_BODY_VERSION);
    let mut crafted = honest.clone();
    crafted[v] = 1;
    assert_eq!(tr::NativeOperation::decode(&crafted), Err(N::Candidate(E::OfferBinding)));
    let body = BlockBody { height: rig.height() + 1, reward_owner: [1; 32], fees: 0, transactions: vec![], operations: vec![crafted.clone()] };
    assert_eq!(body.encode(), Err(mutiny_consensus_v8::Error::WrongOperation));
    let text = rejected_unchanged(&mut rig, 1, &[crafted.clone()]);
    assert!(text.contains("WrongOperation"), "{text}");
    assert_eq!(native_verdict(&rig, &[crafted]).err(), Some(N::Candidate(E::OfferBinding)));
    rig.step(1, &[honest]);
    rig.finish();
}

/// The maker's fill signature binds the exact operation body: a fill signature of another body of
/// the same offer is refused (`Signature`), and so is an offer signature made under the wallet's
/// Transaction domain instead of TRADE-OFFER-V1 (AM-6 domain separation).
#[test]
fn fill_and_offer_signatures_bind_body_and_domain() {
    let Market { mut rig, a, b, coins, .. } = market("offer-signatures");
    let (aa, ba) = (addr(&a, 1), addr(&b, 1));
    let maker = Maker { key: &a, generation: 1, side: 0 };
    let signers = [(0, &a, 1), (1, &b, 1)];
    let w = next_window(&rig);
    let one = filled(&rig.f, lock_action(aa, ba), w, vec![], 20_000, &[coins[0].clone()], &signers, maker, |_| {});
    let two = filled(&rig.f, lock_action(aa, ba), w, vec![], 20_000, &[coins[1].clone()], &signers, maker, |_| {});
    let mut moved = one.clone();
    moved.operation.offer_proof.as_mut().unwrap().fill_signature =
        two.operation.offer_proof.as_ref().unwrap().fill_signature.clone();
    refused(&mut rig, "fill signature of another body", &raw(&moved), N::Candidate(E::Signature));
    let mut wrong_domain = one.clone();
    let p = wrong_domain.operation.offer_proof.as_mut().unwrap();
    p.offer.signature = a
        .sign(
            mutiny_crypto_v2::Domain::Transaction,
            &mutiny_consensus_v8::trading_offer_v2::signature_payload(b"signed-offer", &p.offer.body.encode().unwrap()),
        )
        .unwrap();
    refused(&mut rig, "offer signed under the Transaction domain", &raw(&wrong_domain), N::Candidate(E::Signature));
    rig.step(1, &[raw(&one)]);
    rig.finish();
}

/// Design 12.2 / AM-6: the wire label and the two crypto-v2 domains are registered exactly once,
/// PROPOSED-UNFROZEN.
#[test]
fn maker_offer_domains_are_registered_as_proposed_and_unfrozen() {
    let registry: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("../spec/DOMAIN-REGISTRY-V1.json").unwrap()).unwrap();
    let listed = registry["domains"].as_array().unwrap();
    for (ascii, role) in [
        (std::str::from_utf8(tr::MAKER_OFFER_LABEL).unwrap(), None),
        (std::str::from_utf8(mutiny_crypto_v2::Domain::TradeOffer.bytes()).unwrap(), Some("WalletOwner")),
        (std::str::from_utf8(mutiny_crypto_v2::Domain::TradeFill.bytes()).unwrap(), Some("WalletOwner")),
    ] {
        let entries: Vec<_> = listed.iter().filter(|e| e["ascii"] == ascii).collect();
        assert_eq!(entries.len(), 1, "{ascii} registered exactly once");
        assert_eq!(entries[0]["status"], "PROPOSED-UNFROZEN", "{ascii}");
        assert_eq!(entries[0]["length"], ascii.len(), "{ascii}");
        if let Some(role) = role {
            assert_eq!(entries[0]["role"], role, "{ascii}");
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Public vectors (design 8.6): qualification/trading-maker-offer-v2-vectors.json
// ---------------------------------------------------------------------------------------------

const VECTORS: &str = "qualification/trading-maker-offer-v2-vectors.json";
const V_GENESIS: Hash = [11; 32];
const V_FINGERPRINT: Hash = [12; 32];

fn v_context() -> tr::Context {
    tr::Context { network: NETWORK_ID, genesis: V_GENESIS, fingerprint: V_FINGERPRINT }
}
/// A self-contained offer-bound HashLock at a synthetic chain (no state needed for `verify_offer`):
/// maker = sender a (slot 0), taker = recipient b, window [10, 40], fee 20,000.
fn v_item(edit: impl FnOnce(&mut tr::OfferBody)) -> tr::NativeOperation {
    let (a, b) = (owner_key(), second_key());
    let (aa, ba) = (addr(&a, 1), addr(&b, 1));
    let input = OutPoint { transaction: [0x61; 32], index: 0 };
    let meta = tr::Meta {
        context: v_context(),
        trade: [21; 32],
        contract: [22; 32],
        generation: 1,
        envelope: mutiny_consensus_v8::op_envelope_v1::Envelope {
            first_height: 10,
            last_height: 40,
            reference_height: 9,
            reference_block: [13; 32],
            preconditions: vec![],
        },
        fee: tr::Strikes(20_000),
        inputs: vec![tr::native_input_id(&input)],
    };
    let mut operation = tr::Operation { meta, action: lock_action(aa, ba), approvals: vec![], offer_proof: None };
    let mut body = tr::OfferBody {
        context: v_context(),
        maker_descriptor: desc(&a, 1),
        maker_wallet: aa,
        maker_side: 0,
        nonce: [77; 32],
        created: 5,
        expiry: 50,
        terms: tr::OfferTerms::HashLinked { amount: tr::Strikes(50_000), bitcoin_satoshis: 10_000, bitcoin_network: 3 },
        destination: aa,
        condition: Some(tr::preimage_hash(&[42; 32])),
        max_fee: tr::Strikes(20_000),
    };
    edit(&mut body);
    // A body the codec refuses cannot be signed; the caller wants that refusal itself.
    let offer = tr::MakerOffer::sign(body, &a).unwrap();
    if let tr::Action::HashLock { offer: o, maker: m, .. } = &mut operation.action {
        *o = offer.body.id().unwrap();
        *m = offer.body.maker().unwrap();
    }
    operation.offer_proof = Some(tr::OfferProof::sign(offer, &operation, &a).unwrap());
    operation.approve(0, &a, 1).unwrap();
    operation.approve(1, &b, 1).unwrap();
    tr::NativeOperation { operation, inputs: vec![input] }
}
/// The inclusion height of every vector item.
const V_HEIGHT: u64 = 12;

/// The negative vectors: one per consensus check of design 8.2 (plus the signature bindings), each
/// with the exact refusal of `NativeOperation::decode` + `Operation::verify_offer(V_HEIGHT)`.
fn v_negatives() -> Vec<(&'static str, &'static str, Vec<u8>, &'static str)> {
    let b_addr = addr(&second_key(), 1);
    let mut out: Vec<(&str, &str, Vec<u8>, &str)> = vec![
        ("maker-wallet-not-maker-slot", "maker authority: maker_wallet == slot_address(maker_side)",
            raw(&v_item(|b| b.maker_wallet = b_addr)), "Authority"),
        ("destination-redirected", "destination: HashLock maker sender -> sender == destination",
            raw(&v_item(|b| b.destination = [0x5e; 32])), "OfferBinding"),
        ("condition-swapped", "condition: HashLinked condition == HashLock.condition",
            raw(&v_item(|b| b.condition = Some([43; 32]))), "Condition"),
        ("fee-above-max-fee", "fee terms: maker pays the fee -> meta.fee <= max_fee",
            raw(&v_item(|b| b.max_fee = tr::Strikes(19_999))), "Fee"),
        ("offer-created-after-window-opens", "validity: first_height >= created_height",
            raw(&v_item(|b| b.created = 11)), "Time"),
        ("offer-expires-before-window-closes", "validity: last_height <= expiry_height",
            raw(&v_item(|b| b.expiry = 39)), "Expired"),
    ];
    // Version 1: the offer body's version byte (after the second NAMESPACE occurrence) set to 1.
    let honest = raw(&v_item(|_| {}));
    let at: Vec<usize> = honest.windows(tr::NAMESPACE.len()).enumerate().filter(|(_, w)| *w == tr::NAMESPACE).map(|(i, _)| i).collect();
    let mut v1 = honest.clone();
    v1[at[1] + tr::NAMESPACE.len()] = 1;
    out.push(("offer-body-version-1", "version: only version-2 bodies settle", v1, "OfferBinding"));
    // Fill signature of another operation body.
    let mut moved = v_item(|_| {});
    let other = {
        let mut o = v_item(|_| {});
        o.operation.meta.trade = [23; 32];
        o.operation.approvals.clear();
        let p = o.operation.offer_proof.clone().unwrap();
        tr::OfferProof::sign(p.offer, &o.operation, &owner_key()).unwrap()
    };
    moved.operation.offer_proof.as_mut().unwrap().fill_signature = other.fill_signature;
    out.push(("fill-signature-other-body", "fill proof: TRADE-FILL-V1 signature over this exact operation body", raw(&moved), "Signature"));
    out
}
fn verdict(raw: &[u8]) -> String {
    match tr::NativeOperation::decode(raw) {
        Err(N::Candidate(e)) => format!("{e:?}"),
        Err(e) => format!("{e:?}"),
        Ok(w) => match w.operation.verify_offer(V_HEIGHT) {
            Ok(()) => "Ok".into(),
            Err(e) => format!("{e:?}"),
        },
    }
}

/// 14.7 `maker_offer_v2_codec_and_vectors_export`: builds the vector set (deterministic bodies, ids
/// and keys; FN-DSA signatures are randomized, so readers VERIFY signatures rather than compare
/// them) and checks every expectation. With BUILD8_EXPORT_MAKER_OFFER_V2=1 it writes the committed
/// file and refuses to overwrite an existing one (delete it first, deliberately).
#[test]
fn maker_offer_v2_codec_and_vectors_export() {
    let item = v_item(|_| {});
    let proof = item.operation.offer_proof.clone().unwrap();
    let offer = proof.offer.clone();
    let body = offer.body.encode().unwrap();
    let wire = offer.encode().unwrap();
    let id = offer.body.id().unwrap();
    assert_eq!(tr::MakerOffer::decode(&wire).unwrap(), offer);
    offer.verify().unwrap();
    assert_eq!(verdict(&raw(&item)), "Ok");
    let negatives = v_negatives();
    assert_eq!(negatives.len(), 8);
    for (name, _, bytes, expected) in &negatives {
        assert_eq!(verdict(bytes), *expected, "{name}");
    }
    let op_body = item.operation.body().unwrap();
    let export = serde_json::json!({
        "schema": "BUILD8-TRADING-MAKER-OFFER-V2-VECTORS",
        "TEST_VALUE": true,
        "synthetic_only": true,
        "production_authorized": false,
        "frozen": false,
        "status": "PROPOSED-UNFROZEN (Lane P design 8.2 with AM-6; ARCHITECT question C.3 open)",
        "warning": "TEST-VALUE keys from published BIP39 test phrases; synthetic chain context; never production material. FN-DSA signatures are randomized: verify them, never compare them.",
        "generator": "consensus/tests/maker_offer_v2.rs::maker_offer_v2_codec_and_vectors_export (BUILD8_EXPORT_MAKER_OFFER_V2=1)",
        "context": {"network": NETWORK_ID, "genesis": hex::encode(V_GENESIS), "fingerprint": hex::encode(V_FINGERPRINT)},
        "domains": {
            "maker_offer_label": std::str::from_utf8(tr::MAKER_OFFER_LABEL).unwrap(),
            "offer_signature": std::str::from_utf8(mutiny_crypto_v2::Domain::TradeOffer.bytes()).unwrap(),
            "fill_signature": std::str::from_utf8(mutiny_crypto_v2::Domain::TradeFill.bytes()).unwrap(),
            "role": "WalletOwner"
        },
        "maker": {"descriptor": hex::encode(desc(&owner_key(), 1)), "wallet": hex::encode(addr(&owner_key(), 1))},
        "offer": {
            "body": hex::encode(&body),
            "offer_id": hex::encode(id),
            "maker_identity": hex::encode(offer.body.maker().unwrap()),
            "single_fill_key": hex::encode(tr::single_fill_key(&v_context(), [0; 32], id)),
            "offer_signature_payload": hex::encode(mutiny_consensus_v8::trading_offer_v2::signature_payload(b"signed-offer", &body)),
            "maker_offer": hex::encode(&wire)
        },
        "fill": {
            "inclusion_height": V_HEIGHT,
            "operation_body": hex::encode(&op_body),
            "fill_signature_payload": hex::encode(mutiny_consensus_v8::trading_offer_v2::signature_payload(b"offer-fill", &op_body)),
            "offer_proof": hex::encode(proof.encode().unwrap()),
            "native_operation": hex::encode(raw(&item)),
            "expected": "Ok"
        },
        "negatives": negatives.iter().map(|(name, check, bytes, expected)| serde_json::json!({
            "name": name, "check": check, "native_operation": hex::encode(bytes), "inclusion_height": V_HEIGHT, "expected": expected
        })).collect::<Vec<_>>()
    });
    if std::env::var("BUILD8_EXPORT_MAKER_OFFER_V2").as_deref() == Ok("1") {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(VECTORS);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .expect("the vector file already exists: delete it deliberately before regenerating");
        use std::io::Write as _;
        file.write_all(&serde_json::to_vec_pretty(&export).unwrap()).unwrap();
        file.write_all(b"\n").unwrap();
    }
}

/// Reader of the committed vector file: every positive decodes, re-encodes identically, its id,
/// maker identity and single-fill key recompute, both signatures verify under the registered
/// domains and the filled item passes `verify_offer`; every negative is refused exactly as stated.
#[test]
fn maker_offer_v2_vectors_reader() {
    let text = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(VECTORS)).unwrap();
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    let h = |s: &serde_json::Value| hex::decode(s.as_str().unwrap()).unwrap();
    assert_eq!(v["TEST_VALUE"], true);
    assert_eq!(v["production_authorized"], false);
    assert_eq!(v["domains"]["maker_offer_label"], "MUTINY-BUILD8-MAKER-OFFER-V2");
    let wire = h(&v["offer"]["maker_offer"]);
    let offer = tr::MakerOffer::decode(&wire).unwrap();
    offer.verify().unwrap();
    assert_eq!(offer.encode().unwrap(), wire);
    assert_eq!(offer.body.encode().unwrap(), h(&v["offer"]["body"]));
    assert_eq!(tr::OfferBody::decode(&h(&v["offer"]["body"])).unwrap(), offer.body);
    let id = offer.body.id().unwrap();
    assert_eq!(id.to_vec(), h(&v["offer"]["offer_id"]));
    assert_eq!(offer.body.maker().unwrap().to_vec(), h(&v["offer"]["maker_identity"]));
    assert_eq!(tr::single_fill_key(&v_context(), [0; 32], id).to_vec(), h(&v["offer"]["single_fill_key"]));
    assert_eq!(offer.body.maker_descriptor, h(&v["maker"]["descriptor"]));
    // The deterministic body is exactly what this build produces from the TEST-VALUE inputs.
    assert_eq!(v_item(|_| {}).operation.offer_proof.unwrap().offer.body.encode().unwrap(), h(&v["offer"]["body"]));
    let public = mutiny_crypto_v2::PublicKey::decode_descriptor(&offer.body.maker_descriptor).unwrap().0;
    public
        .verify(mutiny_crypto_v2::Domain::TradeOffer, &h(&v["offer"]["offer_signature_payload"]), &offer.signature)
        .unwrap();
    let item = tr::NativeOperation::decode(&h(&v["fill"]["native_operation"])).unwrap();
    assert_eq!(item.operation.body().unwrap(), h(&v["fill"]["operation_body"]));
    let proof = item.operation.offer_proof.clone().unwrap();
    assert_eq!(proof.encode().unwrap(), h(&v["fill"]["offer_proof"]));
    assert_eq!(proof.offer, offer);
    public
        .verify(mutiny_crypto_v2::Domain::TradeFill, &h(&v["fill"]["fill_signature_payload"]), &proof.fill_signature)
        .unwrap();
    assert_eq!(verdict(&h(&v["fill"]["native_operation"])), "Ok");
    let negatives = v["negatives"].as_array().unwrap();
    assert_eq!(negatives.len(), 8);
    for n in negatives {
        assert_eq!(n["inclusion_height"], V_HEIGHT);
        assert_eq!(verdict(&h(&n["native_operation"])), n["expected"].as_str().unwrap(), "{}", n["name"]);
    }
}
