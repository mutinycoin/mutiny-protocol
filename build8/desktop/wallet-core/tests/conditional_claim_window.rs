//! The WORST-CASE claim window of a hash lock (fixes of the independent wallet review, MAJOR-1).
//! Consensus accepts a claim only in a block above the lock's and below the refund height R, and a
//! lock may be included as late as its own expiry E: the recipient can rely on the blocks E + 1 to
//! R - 1 only, R - E - 1 of them. Before the fix the builder set E = min(next + validity, R - 1,
//! offer expiry), so with R = next + 50 and the default validity of 144 the lock could be included
//! at R - 1 and leave NO claim block while the review promised about 50 and warned of nothing.
//!
//! Now: the rows, the warning and the summary state the worst case; a lock whose worst case is
//! zero is refused for every reader (`INVALID_REQUEST`, `conditional::REASON_NO_CLAIM_WINDOW`),
//! built here or adopted; the builder ends a lock at least two blocks before R; and a SHORT worst
//! case (below 10 blocks, or shorter than the span the lock may be included in) is a Caution that
//! requires the Conditions acknowledgement. NATIVE, TEST-VALUE; public test keys.
#[path = "support/conditional_kit.rs"]
mod kit;
#[path = "support/synthetic.rs"]
mod synthetic;

use mutiny_consensus_v8::trading_v1::NativeOperation;
use mutiny_wallet_core_v8::{ops::conditional, *};
use synthetic::{World, address, identity, key_a, key_b};

/// Head 100 (the next block is 101): key A holds a coin; a maker offers 1,000,000 atoms, fillable
/// in blocks 1 to 1000.
fn world() -> (World, Vec<u8>) {
    let mut world = World::with_wallets(100);
    world.coin(address(&key_a(), 1), 5_000_000, 1, false, 1, 0);
    let maker = kit::maker_key();
    let offer = kit::signed_offer(
        &maker,
        kit::context_of(&world.anchor),
        1,
        1000,
        1_000_000,
        1,
        6,
    );
    (world, kit::offer_bytes(&offer))
}

fn lock(offer: &[u8], refund_height: u64, validity: Option<u64>) -> OperationRequest {
    let mut request = HashLockRequest::new(
        Blob::new(offer.to_vec()),
        address(&key_b(), 1),
        1_000_000,
        [9; 32],
        refund_height,
    );
    if let Some(blocks) = validity {
        request = request.with_validity_blocks(blocks);
    }
    OperationRequest::HashLock(request)
}

fn condition<'r>(review: &'r Review, label: &str) -> &'r str {
    &review
        .conditions()
        .iter()
        .find(|c| c.label == label)
        .unwrap_or_else(|| panic!("no condition {label:?}"))
        .detail
}

fn short_warning(review: &Review) -> Option<&Warning> {
    review
        .warnings()
        .iter()
        .find(|w| w.code == "SHORT_CLAIM_WINDOW")
}

/// The same unsigned lock with another expiry (what another builder could hand over).
fn with_expiry(raw: &[u8], expiry: u64) -> Vec<u8> {
    let mut wire = NativeOperation::decode(raw).unwrap();
    wire.operation.meta.envelope.last_height = expiry;
    wire.encode().unwrap()
}

#[test]
fn the_review_scenario_r_at_next_plus_fifty_with_the_default_validity() {
    let (world, offer) = world();
    let view = world.view();
    let refund = 101 + 50;
    // The builder ends the lock two blocks before R: the worst case leaves one claim block, which
    // every reading of it states and warns of.
    let planned = plan(&lock(&offer, refund, None), &view, &identity(&key_a())).unwrap();
    assert_eq!(planned.validity().expiry, refund - 2);
    assert_eq!(conditional::worst_case_claim_window(refund - 2, refund), 1);
    let raw = planned.objects()[0].bytes.clone();
    let sender = review(&planned, &view).unwrap();
    let recipient = review(&adopt(&raw, &view, &identity(&key_b())).unwrap(), &view).unwrap();
    for reviewed in [&sender, &recipient] {
        let window = condition(reviewed, "Claim window");
        assert!(
            window.starts_with("At least 1 block(s), the worst case")
                && window.contains("blocks 150 to 150"),
            "{window}"
        );
        let warning = short_warning(reviewed).expect("a one-block worst case is short");
        assert_eq!(warning.severity, Severity::Caution);
        assert_eq!(warning.requires, Some(AckKind::Conditions));
        assert!(
            warning
                .text
                .starts_with("The claim window can be as short as 1 block(s)")
        );
        assert!(reviewed.acknowledgements().contains(&AckKind::Conditions));
        assert!(
            reviewed
                .summary()
                .contains("in at least 1 block(s) after the lock's inclusion"),
            "{}",
            reviewed.summary()
        );
        assert!(
            !reviewed.render_text().contains("about 50"),
            "no optimistic promise"
        );
    }
    // The bytes the builder made before the fix (E = R - 1): no claim block at all. Refused for
    // the recipient adopting them, for the sender's offline signer and for anybody explaining them.
    let old = with_expiry(&raw, refund - 1);
    let refused = Refusal::InvalidRequest(conditional::REASON_NO_CLAIM_WINDOW);
    for reader in [identity(&key_b()), identity(&key_a())] {
        assert_eq!(adopt(&old, &view, &reader).unwrap_err(), refused);
        assert_eq!(explain(&old, &view, &reader).unwrap_err(), refused);
    }
    // The sender cannot build a lock that has no claim block even if included at once.
    assert_eq!(
        plan(&lock(&offer, 102, None), &view, &identity(&key_a())).unwrap_err(),
        refused
    );
    // One block more and it can: included at once, the recipient has block 102.
    let tight = plan(&lock(&offer, 103, None), &view, &identity(&key_a())).unwrap();
    assert_eq!(tight.validity().expiry, 101);
    assert!(
        condition(&review(&tight, &view).unwrap(), "Claim window")
            .starts_with("At least 1 block(s)")
    );
    // An expiry at or after R is the earlier refusal.
    assert_eq!(
        adopt(&with_expiry(&raw, refund), &view, &identity(&key_b())).unwrap_err(),
        Refusal::InvalidRequest("the lock operation must expire before its refund height")
    );
}

#[test]
fn the_short_window_rule_is_exact_at_its_two_boundaries() {
    let (world, offer) = world();
    let view = world.view();
    let me = identity(&key_a());
    // (refund height, expiry, worst case, short): the relative rule (worst case below the span of
    // blocks 101..=E the lock may be included in) and the absolute floor of 10 blocks.
    for (refund, expiry, window, short) in [
        (140, 120, 19, true),  // span 20 > 19
        (140, 119, 20, false), // span 19 <= 20, and 20 >= 10
        (113, 102, 10, false), // span 2, at the floor
        (112, 102, 9, true),   // below the floor
        (1000, 102, 897, false),
        (1000, 551, 448, true), // span 451 > 448
        (1000, 549, 450, false),
    ] {
        let planned = plan(&lock(&offer, refund, Some(expiry - 101)), &view, &me).unwrap();
        assert_eq!(planned.validity().expiry, expiry, "R {refund}");
        assert_eq!(conditional::worst_case_claim_window(expiry, refund), window);
        let reviewed = review(&planned, &view).unwrap();
        assert!(
            condition(&reviewed, "Claim window")
                .starts_with(&format!("At least {window} block(s), the worst case")),
            "R {refund} E {expiry}"
        );
        assert_eq!(
            short_warning(&reviewed).is_some(),
            short,
            "R {refund} E {expiry}"
        );
    }
}

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
fn for_random_refund_heights_and_windows_every_reading_states_the_worst_case_and_never_zero() {
    let (world, offer) = world();
    let view = world.view();
    let (sender, recipient) = (identity(&key_a()), identity(&key_b()));
    let mut rng = Rng(0x0c1a_1111_5eed_0002);
    let (mut planned_count, mut refused_count) = (0, 0);
    for _ in 0..120 {
        let refund = 102 + rng.below(400);
        let validity = 1 + rng.below(300);
        match plan(&lock(&offer, refund, Some(validity)), &view, &sender) {
            Err(refusal) => {
                assert_eq!(refund, 102, "only R = next + 1 leaves no window: {refusal}");
                refused_count += 1;
            }
            Ok(planned) => {
                planned_count += 1;
                let expiry = planned.validity().expiry;
                assert_eq!(expiry, (101 + validity).min(refund - 2).min(1000));
                let window = refund - expiry - 1;
                assert!(window >= 1);
                let raw = planned.objects()[0].bytes.clone();
                let as_recipient = review(&adopt(&raw, &view, &recipient).unwrap(), &view).unwrap();
                for reviewed in [review(&planned, &view).unwrap(), as_recipient] {
                    assert!(
                        condition(&reviewed, "Claim window")
                            .starts_with(&format!("At least {window} block(s)"))
                    );
                    let span = expiry - 101 + 1;
                    assert_eq!(
                        short_warning(&reviewed).is_some(),
                        window < 10 || window < span
                    );
                }
                // The latest expiry another builder could choose still leaves one block.
                // (Only where the expiry keeps its encoded width: the fee is the exact minimum.)
                if refund >= 103 && (expiry > 255) == (refund - 2 > 255) {
                    assert!(adopt(&with_expiry(&raw, refund - 2), &view, &recipient).is_ok());
                }
                assert!(adopt(&with_expiry(&raw, refund - 1), &view, &recipient).is_err());
            }
        }
    }
    assert!(
        planned_count > 100 && refused_count <= 5,
        "{planned_count} {refused_count}"
    );
}
