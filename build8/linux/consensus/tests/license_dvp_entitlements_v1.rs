//! WP-T2 (Order P5, lines 174-185; P-LANE-DESIGN-V1 6.1-6.8 and test plan 14.5; amendments AM-10 and
//! AM-11): a License DvP commits the sold License's remaining dividend rights (`LicenseEntitlements`:
//! every live award account `[award_epoch, share, remaining, claims]`) and its assignment state
//! (`LicenseAssignment`: sequence, active Worker, pending assignment id) in its signed envelope. The
//! committed facts are compared at the sale-validation point: the tentative state after this block's
//! activations, dividend epoch events (expiries and award boundaries), same-block Worker assignments
//! and earlier trading items, BEFORE any dividend claim of the block. A difference is
//! `NativeError::Stale(tag)` (1 entitlements, 2 assignment); absence of either precondition is
//! `NativeError::Bounds`. Nothing is re-based.
//!
//! Every negative goes through REAL blocks: the production assembler + V2 executor + canonical store
//! (`rejected_unchanged`) and a certified block offered to `CanonicalStore::commit` itself
//! (`commit_rejected_unchanged`), both proving the head, the canonical State records and every
//! durable store row byte-identical. The block-level error of a refused trading item is opaque
//! (`UnsupportedOperation`), so the EXACT `NativeError` is asserted at the read-only consensus entry
//! point on the same parent (`prepare_batch_with_history`) or, where staleness comes from the sale
//! block's own epoch events (AM-11), on the tentative state built the way the executor builds it
//! (`activate_due`, then the epoch's dividend events) through `prepare_candidate_phase`.
//! Synthetic TEST-VALUE fixtures only (published BIP39 phrases, TEST-VALUE Treasury): Windows-host
//! software evidence, not Linux, physical or production evidence.
#![allow(dead_code, unused_imports)]
mod licenses {
    include!("../../desktop/src/wallet_host_fixture_licenses.rs");
}
mod tpm {
    include!("support/wallet_host_fixture_tpm.rs");
}
include!("support/dividend_rig.rs");
include!("support/trading_rig_v1.rs");
use mutiny_consensus_v8::{
    evidence_history_v2::History,
    license_assignment_v2::Assignment,
    op_envelope_v1::{AwardAccount, assignment_facts, assignment_id, entitlement_facts},
};
use mutiny_crypto_v2::enrollment::{Binding, owner_descriptor_id};
use tr::NativeError as N;

const SOLD: u64 = 3;
const OTHER: u64 = 4;
const PRICE: u64 = 50_000;

fn sold() -> Hash {
    license(SOLD)
}
/// The License facts a sale of `license` commits to, read from `state`.
fn facts(state: &State, license: Hash) -> Vec<Precondition> {
    vec![entitlement_facts(state, license), assignment_facts(state, license).unwrap()]
}
fn sale_action(license: Hash, seller: Hash, buyer: Hash) -> tr::Action {
    tr::Action::LicenseDvp {
        offer: [0; 32],
        maker: [0; 32],
        license,
        license_generation: 1,
        seller,
        buyer,
        price: tr::Strikes(PRICE),
        payment_destination: seller,
        change: tr::Strikes(30_000),
    }
}
/// A sale of License `SOLD` from the owner key (seller, generation 1) to the second key (buyer),
/// funded by the buyer's 100,000-atom `coin` (price 50,000, fee 20,000, change 30,000), committing
/// `preconditions`.
fn sale(rig: &Rig, window: Window, preconditions: Vec<Precondition>, coin: &OutPoint) -> Vec<u8> {
    let (a, b) = (owner_key(), second_key());
    trade_with(
        &rig.f,
        sale_action(sold(), addr(&a, 1), addr(&b, 1)),
        window,
        preconditions,
        20_000,
        std::slice::from_ref(coin),
        &[(0, &a, 1), (1, &b, 1)],
    )
    .encode()
    .unwrap()
}
/// The fixture with a TEST-VALUE Treasury (1,200,000 atoms) and `coins` buyer coins of 100,000.
fn setup(coins: u8) -> (Fixture, Vec<OutPoint>) {
    let mut f = fixture_with_treasury(&treasury_key(), 1_200_000);
    let buyer = addr(&second_key(), 1);
    let points = (0..coins).map(|i| fund(&mut f, 0xa0 + i, buyer, 100_000)).collect();
    (f, points)
}
/// The tentative state the executor builds for a block at `epoch` before any item: activations,
/// then the epoch's dividend events (AM-11; test-fixture feature only).
#[cfg(feature = "dividend-test-fixtures")]
fn tentative(rig: &Rig, epoch: u64) -> State {
    let mut t = rig.state.clone();
    t.licenses_v2.activate_due(epoch).unwrap();
    t.fixture_advance_dividends(epoch).unwrap();
    t
}
/// The exact trading verdict on an executor-built tentative state, with the anchors of `heights`.
fn phase(rig: &Rig, tentative: &State, ops: &[Vec<u8>], heights: &[u64]) -> tr::NativeResult<tr::Prepared> {
    tr::prepare_candidate_phase(
        &rig.state,
        tentative,
        &rig.parent,
        rig.state.root().unwrap(),
        &anchors(rig, heights),
        ops,
        &tr::CandidatePolicy::native_denomination_locked(),
    )
}
/// `n` empty real blocks at the consecutive epochs `from, from + 1, ...`.
fn advance_epochs(rig: &mut Rig, from: u64, n: u64) {
    for k in 0..n {
        rig.step(from + k, &[]);
    }
}
fn account(state: &State, epoch: u64, license: Hash) -> Option<(u64, u64, u64)> {
    let a = state.dividends.ledger().award(epoch)?.account(&license)?;
    Some((a.share, a.remaining, a.claims))
}
fn assert_sold(state: &State) {
    let l = state.licenses_v2.license(sold()).unwrap();
    assert_eq!(l.owner, addr(&second_key(), 1), "the buyer owns the License");
}
fn assert_unsold(state: &State) {
    let l = state.licenses_v2.license(sold()).unwrap();
    assert_eq!(l.owner, addr(&owner_key(), 1), "the seller still owns the License");
}

/// 14.5 / 6.3 row 1: a seller claim of ANY amount of the sold License included after the review
/// makes the committed entitlements stale (`remaining` and `claims` changed): `Stale(1)`, the block
/// is refused and the store is byte-identical; nothing is re-based. A claim of ANOTHER License
/// (6.3 row 5) does not stale the sale. A fresh review and signatures over the new facts succeed.
#[test]
fn seller_claim_makes_sale_stale_byte_identical() {
    let (f, coins) = setup(2);
    let mut rig = Rig::new(f, "p5-seller-claim");
    let (a, aa) = (owner_key(), addr(&owner_key(), 1));
    rig.step(P, &[]);
    assert_eq!(account(&rig.state, P, sold()), Some((50_000, 50_000, 0)));
    let reviewed = facts(&rig.state, sold());
    let signed = sale(&rig, window_at(&rig, 1, 2, 40), reviewed.clone(), &coins[0]);
    // Another License's claim: the sale's facts are unchanged, its verdict stays valid.
    rig.step(P + 1, &[claim_op(&rig.f, &a, OTHER, P, 1_000, 0, aa)]);
    assert_eq!(facts(&rig.state, sold()), reviewed);
    native_verdict_with(&rig, &[signed.clone()], &[1]).unwrap();
    // The seller claims 1 atom of the sold License: remaining and claims change.
    rig.step(P + 2, &[claim_op(&rig.f, &a, SOLD, P, 1, 0, aa)]);
    assert_eq!(account(&rig.state, P, sold()), Some((50_000, 49_999, 1)));
    assert!(matches!(native_verdict_with(&rig, &[signed.clone()], &[1]), Err(N::Stale(1))));
    let text = rejected_unchanged(&mut rig, P + 3, &[signed.clone()]);
    assert!(text.contains("UnsupportedOperation"), "{text}");
    commit_rejected_unchanged(&mut rig, P + 3, &[signed]);
    assert_unsold(&rig.state);
    // Fresh review: the remaining 49,999 transfer with the License.
    let fresh = sale(&rig, window_at(&rig, 3, 4, 40), facts(&rig.state, sold()), &coins[1]);
    let s = rig.step(P + 3, &[fresh]);
    assert_sold(&s);
    assert_eq!(account(&s, P, sold()), Some((50_000, 49_999, 1)), "the sale does not touch the ledger");
    rig.finish();
}

/// 14.5 / 6.3 row 2 (AM-11): the award reviewed at the sale expires at the sale block's OWN epoch
/// (P + W, the first epoch outside the claim window). The parent-state view still holds the account,
/// so the exact error is asserted on the executor-built tentative state; the block is refused
/// byte-identical, and the fresh sale committing the empty list is valid in that same epoch.
#[cfg(feature = "dividend-test-fixtures")]
#[test]
fn expiry_at_the_sale_blocks_own_epoch_makes_sale_stale() {
    let (f, coins) = setup(2);
    let mut rig = Rig::new(f, "p5-expiry");
    rig.step(P, &[]);
    let reviewed = facts(&rig.state, sold());
    let signed = sale(&rig, window_at(&rig, 1, 2, 40), reviewed.clone(), &coins[0]);
    // One epoch before the expiry the sale is valid at the validation point.
    phase(&rig, &tentative(&rig, P + W - 1), &[signed.clone()], &[1]).unwrap();
    let t = tentative(&rig, P + W);
    let after = facts(&t, sold());
    assert_ne!(after, reviewed, "the award of epoch P expires at epoch P + W");
    assert_eq!(after[0], Precondition::LicenseEntitlements { license: sold(), accounts: vec![] });
    native_verdict_with(&rig, &[signed.clone()], &[1]).unwrap();
    assert!(matches!(phase(&rig, &t, &[signed.clone()], &[1]), Err(N::Stale(1))));
    rejected_unchanged(&mut rig, P + W, &[signed.clone()]);
    commit_rejected_unchanged(&mut rig, P + W, &[signed]);
    let fresh = sale(&rig, window_at(&rig, 1, 2, 40), after, &coins[1]);
    phase(&rig, &t, &[fresh.clone()], &[1]).unwrap();
    let s = rig.step(P + W, &[fresh]);
    assert_sold(&s);
    assert_eq!(s.dividends.ledger().award(P).map(|a| a.account(&sold())), None, "expired, not recreated");
    rig.finish();
}

/// 14.5 / 6.3 row 3: a new award boundary at which the License is eligible creates a new account,
/// so a sale reviewed before it is stale when included at (or after) the boundary epoch. Here the
/// boundary 2P also expires the earlier award; the second case isolates the new account alone:
/// a sale reviewed at Genesis (no account) included at epoch P.
#[cfg(feature = "dividend-test-fixtures")]
#[test]
fn new_award_makes_sale_stale() {
    let (f, coins) = setup(3);
    let mut rig = Rig::new(f, "p5-new-award");
    let at_genesis = facts(&rig.state, sold());
    assert_eq!(at_genesis[0], Precondition::LicenseEntitlements { license: sold(), accounts: vec![] });
    let early = sale(&rig, window_at(&rig, 0, 1, 40), at_genesis, &coins[0]);
    let t = tentative(&rig, P);
    let after = facts(&t, sold());
    assert_eq!(
        after[0],
        Precondition::LicenseEntitlements {
            license: sold(),
            accounts: vec![AwardAccount { award_epoch: P, share: 50_000, remaining: 50_000, claims: 0 }]
        }
    );
    assert_eq!(after[1], facts(&rig.state, sold())[1], "only the entitlements changed");
    native_verdict(&rig, &[early.clone()]).unwrap();
    assert!(matches!(phase(&rig, &t, &[early.clone()], &[]), Err(N::Stale(1))));
    rejected_unchanged(&mut rig, P, &[early.clone()]);
    commit_rejected_unchanged(&mut rig, P, &[early]);
    // The same block without the sale: the new award exists, and a sale reviewed now is valid.
    rig.step(P, &[]);
    let reviewed = facts(&rig.state, sold());
    let late = sale(&rig, window_at(&rig, 1, 2, 40), reviewed, &coins[1]);
    // ... until the next boundary 2P (a new account; the award of P has expired by then).
    let t2 = tentative(&rig, 2 * P);
    assert!(matches!(&facts(&t2, sold())[0], Precondition::LicenseEntitlements { accounts, .. } if accounts.len() == 1 && accounts[0].award_epoch == 2 * P));
    assert!(matches!(phase(&rig, &t2, &[late.clone()], &[1]), Err(N::Stale(1))));
    rejected_unchanged(&mut rig, 2 * P, &[late.clone()]);
    let fresh = sale(&rig, window_at(&rig, 1, 2, 40), facts(&t2, sold()), &coins[2]);
    let s = rig.step(2 * P, &[fresh]);
    assert_sold(&s);
    assert_eq!(account(&s, 2 * P, sold()), Some((50_000, 50_000, 0)));
    rig.finish();
}

/// 14.5 / 6.3 row 4: a new award boundary at which the sold License is NOT eligible (suspended by
/// the TEST-VALUE fixture) adds no account for it: the committed facts are unchanged and the sale
/// reviewed before the boundary is valid in the boundary block, although other Licenses received
/// accounts in that same block.
#[cfg(feature = "dividend-test-fixtures")]
#[test]
fn ineligible_new_award_not_stale() {
    let (mut f, coins) = setup(1);
    f.state.dividends.fixture_suspend(sold(), P + 10).unwrap();
    let mut rig = Rig::new(f, "p5-ineligible");
    let reviewed = facts(&rig.state, sold());
    let signed = sale(&rig, window_at(&rig, 0, 1, 40), reviewed.clone(), &coins[0]);
    let t = tentative(&rig, P);
    assert_eq!(facts(&t, sold()), reviewed, "no account for the suspended License");
    assert!(account(&t, P, license(OTHER)).is_some(), "the boundary did award the other Licenses");
    phase(&rig, &t, &[signed.clone()], &[]).unwrap();
    let s = rig.step(P, &[signed]);
    assert_sold(&s);
    assert_eq!(account(&s, P, sold()), None);
    assert!(account(&s, P, license(OTHER)).is_some());
    rig.finish();
}

/// 14.5 / 6.1: the sale commitment is mandatory. A LicenseDvp without the LicenseEntitlements or
/// without the LicenseAssignment precondition, with both for another License, or with a second
/// entitlement list, is `Bounds`; each block is refused byte-identical; the complete commitment
/// (plus an unrelated TreasuryHead precondition, which is permitted) is valid.
#[test]
fn sale_without_entitlement_precondition_rejected() {
    let (f, coins) = setup(8);
    let mut rig = Rig::new(f, "p5-bounds");
    rig.step(P, &[]);
    let [entitlements, assignment] = <[Precondition; 2]>::try_from(facts(&rig.state, sold())).unwrap();
    let other = facts(&rig.state, license(OTHER));
    let w = window_at(&rig, 1, 2, 40);
    let cases: Vec<(&str, Vec<Precondition>)> = vec![
        ("no precondition", vec![]),
        ("entitlements only", vec![entitlements.clone()]),
        ("assignment only", vec![assignment.clone()]),
        ("both for another License", other.clone()),
        ("entitlements of another License", vec![other[0].clone(), assignment.clone()]),
        ("assignment of another License", vec![entitlements.clone(), other[1].clone()]),
        ("a second entitlement list", vec![entitlements.clone(), other[0].clone(), assignment.clone()]),
    ];
    for (i, (name, mut preconditions)) in cases.into_iter().enumerate() {
        preconditions.sort_by_key(Precondition::key);
        let op = sale(&rig, w, preconditions, &coins[i]);
        assert!(matches!(native_verdict_with(&rig, &[op.clone()], &[1]), Err(N::Bounds)), "{name}");
        rejected_unchanged(&mut rig, P + 1, &[op.clone()]);
        if i == 0 {
            commit_rejected_unchanged(&mut rig, P + 1, &[op]);
        }
    }
    // The Treasury head of this fixture is not a trading Treasury; a TreasuryHead precondition of
    // an unknown Treasury is Unavailable, so the positive control commits exactly the pair.
    let s = rig.step(P + 1, &[sale(&rig, w, vec![entitlements, assignment], &coins[7])]);
    assert_sold(&s);
    rig.finish();
}

/// 14.5 / 6.2 trades before claims: in the sale block, a claim by the SELLER of the sold License is
/// executed after the sale whatever the listing order, so it fails (StaleOwner) and the whole block
/// is refused byte-identical; a claim by the BUYER in the sale block is valid and draws on the
/// committed remaining amount.
#[test]
fn same_block_seller_claim_after_sale_invalid_buyer_claim_valid() {
    let (f, coins) = setup(1);
    let mut rig = Rig::new(f, "p5-same-block");
    let (a, b) = (owner_key(), second_key());
    let (aa, ba) = (addr(&a, 1), addr(&b, 1));
    rig.step(P, &[]);
    let signed = sale(&rig, window_at(&rig, 1, 2, 40), facts(&rig.state, sold()), &coins[0]);
    let seller_claim = claim_op(&rig.f, &a, SOLD, P, 1_000, 0, aa);
    let text = rejected_unchanged(&mut rig, P + 1, &[seller_claim.clone(), signed.clone()]);
    assert!(text.contains("StaleOwner"), "the seller claim runs after the sale: {text}");
    let text = commit_rejected_at(&mut rig, at(P + 1), &[seller_claim, signed.clone()]);
    assert!(text.contains("StaleOwner"), "{text}");
    assert_unsold(&rig.state);
    let before = held_by(&rig.state, ba);
    let s = rig.step(P + 1, &[claim_op(&rig.f, &b, SOLD, P, 20_000, 0, ba), signed]);
    assert_sold(&s);
    assert_eq!(account(&s, P, sold()), Some((50_000, 30_000, 1)));
    assert_eq!(held_by(&s, ba), before - 100_000 + 30_000 + 20_000, "coin spent, change and claim received");
    rig.finish();
}

/// A generation-`generation` reassignment of License `SOLD` by its owner (owner key, generation 1)
/// to synthetic Worker `seed`, effective at `effective_epoch` (inclusion deadline height 100).
fn reassignment(rig: &Rig, seed: u8, generation: u64, effective_epoch: u64) -> Assignment {
    let owner = owner_key();
    let node = rig.f.coordinator.public().descriptor(1).unwrap();
    let mut b = Binding {
        genesis: rig.f.genesis.genesis,
        fingerprint: rig.f.genesis.fingerprint,
        license: sold(),
        owner_descriptor: owner_descriptor_id(owner.public(), 1).unwrap(),
        owner_generation: 1,
        worker_public: licenses::worker(seed),
        worker_id: [0; 32],
        coordinator: mutiny_consensus_v8::work_authority_v2::node_identity(&node).unwrap(),
        configuration_generation: 2,
        device_mac: [2, 0, 0, 0, 3, seed],
        assignment_generation: generation,
        effective_epoch,
        valid_until_height: 100,
    };
    b.worker_id = b.derived_worker_id();
    licenses::sign(b, &owner, &node, seed)
}
/// The real block for the next height at an explicit `timestamp` (two blocks in one MiningEpoch).
fn try_step_at(rig: &mut Rig, timestamp: u64, ops: &[Vec<u8>]) -> Result<State, String> {
    let prepared = rig
        .chain
        .prepare_pending(Preparation {
            expected_parent: &rig.parent,
            pool: &rig.pool,
            license: rig.f.license,
            worker: rig.f.worker,
            timestamp,
            ticket: rig.ticket,
            operations: ops,
        })
        .map_err(|e| format!("{e:?}"))?;
    Ok(rig.commit_prepared(prepared))
}
/// `commit_rejected_unchanged` (support/trading_rig_v1.rs) at an explicit timestamp and for bodies
/// that also carry non-trading items (fee-exempt claims, Worker assignments): a CERTIFIED block whose
/// body carries `ops` must be refused by `CanonicalStore::commit`, leaving the store byte-identical.
fn commit_rejected_at(rig: &mut Rig, timestamp: u64, ops: &[Vec<u8>]) -> String {
    let before = snapshot(rig);
    let mut prepared = rig
        .chain
        .prepare_pending(Preparation {
            expected_parent: &rig.parent,
            pool: &rig.pool,
            license: rig.f.license,
            worker: rig.f.worker,
            timestamp,
            ticket: rig.ticket,
            operations: &[],
        })
        .unwrap();
    for raw in ops {
        if tr::NativeOperation::decode(raw).is_ok() {
            prepared.body.fees += tr::declared_fee(raw).unwrap();
        }
    }
    prepared.body.operations.extend(ops.iter().cloned());
    prepared.candidate.body_root = prepared.body.root().unwrap();
    let envelope = certify_at(prepared, &rig.f, &rig.parent, &rig.state, rig.ticket);
    let outcome = rig.chain.commit(&envelope);
    assert!(outcome.is_err(), "commit must refuse the certified block");
    assert_eq!(snapshot(rig), before, "a refused commit leaves the store byte-identical");
    format!("{:?}", outcome.unwrap_err())
}
fn rejected_at(rig: &mut Rig, timestamp: u64, ops: &[Vec<u8>]) -> String {
    let before = snapshot(rig);
    let in_memory = rig.state.records().unwrap();
    let outcome = try_step_at(rig, timestamp, ops);
    assert!(outcome.is_err(), "the block must be rejected");
    assert_eq!(snapshot(rig), before, "a rejected block leaves the store byte-identical");
    assert_eq!(rig.state.records().unwrap(), in_memory);
    outcome.unwrap_err()
}

/// 14.5 / 6.6 (Restart Order L64, Q17 a): a sale whose LicenseAssignment commits the pending
/// old-owner assignment cancels it (the cancelled id equals the committed one), detaches the active
/// Worker, and the cancelled assignment never activates. A sale that committed no pending
/// assignment (reviewed before it was scheduled), or a different id, is `Stale(2)`, refused
/// byte-identical, and the pending assignment survives. Also within one block: an assignment
/// scheduled earlier in the sale block is cancelled only if the sale committed its id.
#[test]
fn committed_pending_assignment_cancelled_uncommitted_one_stales_sale() {
    let (f, coins) = setup(5);
    let mut rig = Rig::new(f, "p5-pending");
    rig.step(P, &[]);
    let before_assignment = facts(&rig.state, sold());
    // Height 2, still epoch P (a later timestamp): the seller schedules a reassignment effective at epoch P + 1.
    let pending = reassignment(&rig, 61, 2, P + 1);
    let id = assignment_id(&pending).unwrap();
    try_step_at(&mut rig, at(P) + 1, &[pending.encode().unwrap()]).unwrap();
    assert_eq!(rig.state.licenses_v2.pending_assignment(sold()), Some(&pending));
    let reviewed = facts(&rig.state, sold());
    assert!(matches!(reviewed[1], Precondition::LicenseAssignment { pending: Some(p), .. } if p == id));
    let w = window_at(&rig, 2, 3, 40);
    let unaware = sale(&rig, w, vec![reviewed[0].clone(), before_assignment[1].clone()], &coins[0]);
    let mut wrong = reviewed[1].clone();
    if let Precondition::LicenseAssignment { pending, .. } = &mut wrong {
        *pending = Some([0x66; 32]);
    }
    let wrong = sale(&rig, w, vec![reviewed[0].clone(), wrong], &coins[1]);
    for op in [&unaware, &wrong] {
        assert!(matches!(native_verdict_with(&rig, &[op.clone()], &[2]), Err(N::Stale(2))));
        rejected_at(&mut rig, at(P) + 2, &[op.clone()]);
    }
    let text = commit_rejected_at(&mut rig, at(P) + 2, &[unaware]);
    assert!(text.contains("UnsupportedOperation"), "{text}");
    assert_eq!(rig.state.licenses_v2.pending_assignment(sold()), Some(&pending), "still pending");
    // The committed one: the sale cancels exactly that assignment (height 3, still epoch P).
    let committed = sale(&rig, w, reviewed, &coins[2]);
    native_verdict_with(&rig, &[committed.clone()], &[2]).unwrap();
    let s = try_step_at(&mut rig, at(P) + 2, &[committed]).unwrap();
    assert_sold(&s);
    assert_eq!(s.licenses_v2.pending_assignment(sold()), None, "cancelled by the sale");
    let l = s.licenses_v2.license(sold()).unwrap();
    assert_eq!((l.active_worker, l.assignment_sequence), (None, 2), "Worker detached, sequence advanced");
    // Epoch P + 1: the cancelled assignment does not activate.
    let s = rig.step(P + 1, &[]);
    assert_eq!(s.licenses_v2.license(sold()).unwrap().active_worker, None);
    assert!(s.licenses_v2.active(sold(), pending.enrollment.binding.worker_id, P + 1).is_err());
    rig.finish();

    // Same block: assignment listed first, then the sale. Only a sale committing its id is valid.
    let (f, coins) = setup(2);
    let mut rig = Rig::new(f, "p5-pending-same-block");
    rig.step(P, &[]);
    let pending = reassignment(&rig, 62, 2, P + 1);
    let mut committed = facts(&rig.state, sold());
    let none = sale(&rig, window_at(&rig, 1, 2, 40), committed.clone(), &coins[0]);
    if let Precondition::LicenseAssignment { pending: p, .. } = &mut committed[1] {
        *p = Some(assignment_id(&pending).unwrap());
    }
    let with_id = sale(&rig, window_at(&rig, 1, 2, 40), committed, &coins[1]);
    rejected_at(&mut rig, at(P) + 1, &[pending.encode().unwrap(), none]);
    let s = try_step_at(&mut rig, at(P) + 1, &[pending.encode().unwrap(), with_id]).unwrap();
    assert_sold(&s);
    assert_eq!(s.licenses_v2.pending_assignment(sold()), None);
    rig.finish();
}

/// 14.5 / 6.3 row 6 (activated): a sale reviewed while the License had its Genesis Worker and nothing
/// pending is stale once a reassignment scheduled after the review has ACTIVATED (sequence and active
/// Worker changed, nothing pending any more): `Stale(2)` at the validation point, although the Book
/// itself would accept the transfer (it reads the current sequence) and no pending assignment is
/// cancelled. Refused byte-identical; a fresh review over the new facts is valid.
#[test]
fn activated_assignment_after_review_stales_sale() {
    let (f, coins) = setup(2);
    let mut rig = Rig::new(f, "p5-activated");
    rig.step(P, &[]);
    let reviewed = facts(&rig.state, sold());
    let signed = sale(&rig, window_at(&rig, 1, 2, 40), reviewed.clone(), &coins[0]);
    let assignment = reassignment(&rig, 63, 2, P + 1);
    try_step_at(&mut rig, at(P) + 1, &[assignment.encode().unwrap()]).unwrap();
    rig.step(P + 1, &[]);
    let now = facts(&rig.state, sold());
    assert_eq!(now[0], reviewed[0], "the entitlements are unchanged");
    assert!(matches!(
        &now[1],
        Precondition::LicenseAssignment { assignment_sequence: 2, active_worker: Some(w), pending: None, .. }
            if *w == assignment.enrollment.binding.worker_id
    ));
    assert!(matches!(native_verdict_with(&rig, &[signed.clone()], &[1]), Err(N::Stale(2))));
    rejected_unchanged(&mut rig, P + 2, &[signed.clone()]);
    commit_rejected_unchanged(&mut rig, P + 2, &[signed]);
    let fresh = sale(&rig, window_at(&rig, 3, 4, 40), now, &coins[1]);
    let s = rig.step(P + 2, &[fresh]);
    assert_sold(&s);
    let l = s.licenses_v2.license(sold()).unwrap();
    assert_eq!((l.active_worker, l.assignment_sequence), (None, 3));
    rig.finish();
}

/// 14.5 / 6.4: the License's rights travel with it and no award is recreated. The seller claims part
/// of the award, the sale commits the remainder, and the buyer claims exactly that remainder with
/// the next per-award/per-License sequence (a sequence-0 replay is refused). The sale block leaves
/// the award ledger unchanged (same awards, same accounts), and nothing remains to claim afterwards.
#[test]
fn buyer_claims_remainder_no_award_recreated() {
    let (f, coins) = setup(1);
    let mut rig = Rig::new(f, "p5-remainder");
    let (a, b) = (owner_key(), second_key());
    let (aa, ba) = (addr(&a, 1), addr(&b, 1));
    rig.step(P, &[]);
    rig.step(P + 1, &[claim_op(&rig.f, &a, SOLD, P, 10_000, 0, aa)]);
    assert_eq!(account(&rig.state, P, sold()), Some((50_000, 40_000, 1)));
    let ledger = |s: &State| -> Vec<(u64, Vec<(Hash, u64, u64, u64)>)> {
        s.dividends
            .ledger()
            .awards_iter()
            .map(|w| (w.epoch(), w.accounts_iter().map(|(l, x)| (*l, x.share, x.remaining, x.claims)).collect()))
            .collect()
    };
    let before = ledger(&rig.state);
    let signed = sale(&rig, window_at(&rig, 2, 3, 40), facts(&rig.state, sold()), &coins[0]);
    let s = rig.step(P + 2, &[signed]);
    assert_sold(&s);
    assert_eq!(ledger(&s), before, "the sale neither recreates nor changes an award");
    let c = claim_op(&rig.f, &b, SOLD, P, 40_000, 0, ba);
    let text = rejected_unchanged(&mut rig, P + 3, &[c]);
    assert!(text.contains("Replay"), "the sequence continues across the sale: {text}");
    let c = claim_op(&rig.f, &b, SOLD, P, 40_001, 1, ba);
    let text = rejected_unchanged(&mut rig, P + 3, &[c]);
    assert!(!text.is_empty(), "no more than the remainder");
    let held = held_by(&rig.state, ba);
    let s = rig.step(P + 3, &[claim_op(&rig.f, &b, SOLD, P, 40_000, 1, ba)]);
    assert_eq!(account(&s, P, sold()), Some((50_000, 0, 2)));
    assert_eq!(held_by(&s, ba), held + 40_000);
    let c = claim_op(&rig.f, &a, SOLD, P, 1, 2, aa);
    rejected_unchanged(&mut rig, P + 4, &[c]);
    rig.finish();
}

/// 14.5 / 6.3 row 7: head advance alone never invalidates the sale. Reviewed at head 1, included 20
/// blocks later inside its unchanged window (other Licenses' claims in between), it is valid and its
/// committed facts are exactly the facts at the validation point.
#[test]
fn head_advance_alone_does_not_invalidate() {
    let (f, coins) = setup(1);
    let mut rig = Rig::new(f, "p5-head-advance");
    let (a, aa) = (owner_key(), addr(&owner_key(), 1));
    rig.step(P, &[]);
    let reviewed = facts(&rig.state, sold());
    let signed = sale(&rig, window_at(&rig, 1, 2, 60), reviewed.clone(), &coins[0]);
    rig.step(P + 1, &[claim_op(&rig.f, &a, OTHER, P, 5_000, 0, aa)]);
    advance_epochs(&mut rig, P + 2, 19);
    assert_eq!(rig.height(), 21);
    assert_eq!(facts(&rig.state, sold()), reviewed);
    native_verdict_with(&rig, &[signed.clone()], &[1]).unwrap();
    let s = rig.step(P + 21, &[signed]);
    assert_sold(&s);
    assert_eq!(account(&s, P, sold()), Some((50_000, 50_000, 0)));
    rig.finish();
}
