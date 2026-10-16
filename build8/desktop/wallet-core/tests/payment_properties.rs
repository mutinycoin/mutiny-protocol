//! Randomised properties of the payment planner and the threading contract of the public types.
//! A fixed seed makes every run identical. NATIVE, TEST-VALUE; public test keys only.
//!
//! Property: for ANY funding, a plan either exists and is a payment consensus accepts (conservation,
//! fee at least the signed size, positive outputs, distinct mature unreserved coins of this key,
//! change to this wallet, within 16 KiB), or the planner refuses with a typed refusal whose numbers
//! agree with an independent computation of what was spendable.
#[path = "support/flow.rs"]
mod flow;
#[path = "support/synthetic.rs"]
mod synthetic;

use mutiny_consensus_v8::{
    transactions::{MATURITY, MAX_TX_BYTES, OutPoint},
    transactions_v2::Transfer,
};
use mutiny_wallet_core_v8::*;
use std::collections::{BTreeMap, BTreeSet};
use synthetic::{World, address, identity, key_a, key_b};

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

/// The spendable coins, computed independently of the planner.
fn spendable(world: &World, owner: [u8; 32]) -> Vec<(OutPoint, u64)> {
    let next = world.anchor.height + 1;
    world
        .state
        .coins
        .iter()
        .filter(|(point, coin)| {
            coin.output.owner == owner
                && !world.reserved.contains(*point)
                && coin.created_height <= world.anchor.height
                && (!coin.coinbase || next - coin.created_height >= MATURITY)
        })
        .map(|(point, coin)| (point.clone(), coin.output.atoms))
        .collect()
}

#[test]
fn any_funding_yields_a_consensus_valid_payment_or_a_typed_refusal_that_matches_the_chain() {
    let key = key_a();
    let me = identity(&key);
    let owner = address(&key, 1);
    let signer = KeySigner::for_test(key_a()).unwrap();
    let recipient = address(&key_b(), 1);
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut outcomes: BTreeMap<String, usize> = BTreeMap::new();
    let mut signed = 0;

    for case in 0..400 {
        let mut world = World::new(100 + rng.below(40));
        let coins = rng.below(9);
        for index in 0..coins {
            let atoms = match rng.below(4) {
                0 => 1 + rng.below(5_000),
                1 => 5_000 + rng.below(5_000_000),
                2 => 1_000_000 + rng.below(1 << 40),
                _ => 1 + rng.below(1 << 20),
            };
            let (created, coinbase) = if rng.below(10) == 0 {
                (50 + rng.below(70), true)
            } else {
                (1 + rng.below(40), false)
            };
            let created = created.min(world.anchor.height);
            let holder = if rng.below(6) == 0 {
                address(&key_b(), 1)
            } else {
                owner
            };
            let point = world.coin(
                holder,
                atoms,
                created,
                coinbase,
                1 + index as u8,
                rng.below(3) as u32,
            );
            if rng.below(7) == 0 {
                world.reserved.insert(point);
            }
        }
        let available = spendable(&world, owner);
        let total: u128 = available.iter().map(|(_, atoms)| u128::from(*atoms)).sum();
        let amount = match rng.below(4) {
            0 => 1 + rng.below(10_000),
            1 => 1 + rng.below((total as u64).max(1)),
            2 => (total as u64).saturating_sub(rng.below(8_000)).max(1),
            _ => 1 + rng.below(1 << 36),
        };
        let view = world.view();
        let request = OperationRequest::Payment(PaymentRequest::new(recipient, amount));
        match plan(&request, &view, &me) {
            Ok(planned) => {
                *outcomes.entry("planned".into()).or_default() += 1;
                let transfer = Transfer::decode(&planned.objects()[0].bytes).unwrap();
                // Inputs: distinct, spendable, this key's, sorted as the plan reports them.
                let points: BTreeSet<&OutPoint> =
                    transfer.inputs.iter().map(|input| &input.point).collect();
                assert_eq!(
                    points.len(),
                    transfer.inputs.len(),
                    "case {case}: duplicate input"
                );
                for input in &transfer.inputs {
                    assert!(
                        available.iter().any(|(point, _)| *point == input.point),
                        "case {case}: spends a coin that was not spendable"
                    );
                }
                assert_eq!(planned.inputs().len(), transfer.inputs.len());
                // Value: conservation, minimal-or-better fee, positive outputs, change to this wallet.
                let incoming: u128 = transfer
                    .inputs
                    .iter()
                    .map(|input| u128::from(world.state.coins[&input.point].output.atoms))
                    .sum();
                let outgoing: u128 = transfer.outputs.iter().map(|o| u128::from(o.atoms)).sum();
                assert_eq!(
                    incoming,
                    outgoing + u128::from(transfer.fee),
                    "case {case}: conservation"
                );
                let size = planned.objects()[0].bytes.len();
                assert!(size <= MAX_TX_BYTES, "case {case}: size {size}");
                assert!(transfer.fee >= size as u64, "case {case}: fee below size");
                assert!(
                    transfer.fee - size as u64 <= 4,
                    "case {case}: the fee is the size up to width effects"
                );
                assert!(transfer.outputs.iter().all(|o| o.atoms > 0));
                assert_eq!(
                    (transfer.outputs[0].owner, transfer.outputs[0].atoms),
                    (recipient, amount)
                );
                if let Some(change) = transfer.outputs.get(1) {
                    assert_eq!(
                        change.owner, owner,
                        "case {case}: change goes to this wallet"
                    );
                }
                assert!(transfer.outputs.len() <= 2);
                // The review accepts it, and every eighth plan is signed and verified by consensus.
                let reviewed = review(&planned, &view).unwrap();
                assert_eq!(reviewed.amount(), Some(amount));
                if case % 8 == 0 {
                    let signed_op = flow::sign(planned, &signer, &view).unwrap();
                    Transfer::decode(signed_op.bytes())
                        .unwrap()
                        .verify(
                            world.anchor.genesis,
                            world.anchor.fingerprint,
                            world.anchor.height + 1,
                            &world.state.coins,
                            &world.state.wallets,
                        )
                        .unwrap_or_else(|e| panic!("case {case}: consensus rejected: {e:?}"));
                    signed += 1;
                }
            }
            Err(refusal) => {
                *outcomes.entry(refusal.code().to_string()).or_default() += 1;
                match refusal {
                    Refusal::NothingSpendable => {
                        assert!(available.is_empty(), "case {case}: coins were spendable")
                    }
                    Refusal::InsufficientFunds {
                        available: reported,
                        requested,
                    } => {
                        assert_eq!(
                            u128::from(reported),
                            total.min(u128::from(u64::MAX)),
                            "case {case}: reported funds"
                        );
                        assert!(
                            u128::from(requested) > total,
                            "case {case}: requested {requested} but {total} was spendable"
                        );
                    }
                    Refusal::SizeLimit { limit } => {
                        assert_eq!(limit, MAX_TX_BYTES);
                        assert!(available.len() >= 5, "case {case}: five coins are needed");
                    }
                    other => panic!("case {case}: unexpected refusal {other}"),
                }
                // No spurious refusal: a single coin that clearly covers amount and fee must plan.
                let single = available.iter().map(|(_, atoms)| *atoms).max().unwrap_or(0);
                assert!(
                    u128::from(single) < u128::from(amount) + 4_000,
                    "case {case}: refused although one coin of {single} covers {amount}"
                );
            }
        }
    }
    // The generator exercises success, every funding refusal and the signing path.
    assert!(outcomes["planned"] > 60, "{outcomes:?}");
    for code in ["NOTHING_SPENDABLE", "INSUFFICIENT_FUNDS"] {
        assert!(
            outcomes.contains_key(code),
            "{code} never occurred: {outcomes:?}"
        );
    }
    assert!(signed >= 8, "{signed} signed and verified");
}

fn is_send_and_sync<T: Send + Sync>() {}
fn is_send<T: Send>() {}

#[test]
fn the_public_types_have_the_threading_contract_a_threaded_host_needs() {
    // Plain data may cross threads freely.
    is_send_and_sync::<Refusal>();
    is_send_and_sync::<OperationKind>();
    is_send_and_sync::<OperationPlan>();
    is_send_and_sync::<Review>();
    is_send_and_sync::<SignerIdentity>();
    is_send_and_sync::<SignedOperation>();
    is_send_and_sync::<PartialApproval>();
    is_send_and_sync::<OutboxRecord>();
    is_send_and_sync::<HeadInfo>();
    // The single-use approval and the session state move between threads but are never shared.
    is_send::<Approval>();
    is_send::<ReviewGate>();
    is_send::<PlanSession>();
    // A key holder is shared behind its own lock; outboxes are owned by one thread at a time.
    is_send_and_sync::<KeySigner>();
    is_send::<MemoryOutbox>();
    is_send::<SqliteOutbox>();
}

#[test]
fn a_key_signer_can_be_used_from_several_threads_at_once() {
    let mut world = World::new(100);
    let owner = address(&key_a(), 1);
    for tag in 1..=4u8 {
        world.coin(owner, 2_000_000, 1, false, tag, 0);
    }
    let signer = KeySigner::for_test(key_a()).unwrap();
    let me = identity(&key_a());
    let view = world.view();
    let plans: Vec<OperationPlan> = (1..=4u64)
        .map(|n| {
            plan(
                &OperationRequest::Payment(PaymentRequest::new(address(&key_b(), 1), n * 100_000)),
                &view,
                &me,
            )
            .unwrap()
        })
        .collect();
    let approvals: Vec<Approval> = plans
        .iter()
        .map(|p| flow::approve(&review(p, &view).unwrap(), &view))
        .collect();
    let results: Vec<Result<SignedOperation, Refusal>> = std::thread::scope(|scope| {
        let handles: Vec<_> = plans
            .into_iter()
            .zip(approvals)
            .map(|(p, a)| {
                let (signer, world) = (&signer, &world);
                // A view is built per thread from the shared verified state.
                scope.spawn(move || signer.authorize(p, a, &world.view()))
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    assert!(results.iter().all(Result::is_ok), "{results:?}");
    let ids: BTreeSet<_> = results.iter().map(|r| r.as_ref().unwrap().id()).collect();
    assert_eq!(ids.len(), 4);
}
