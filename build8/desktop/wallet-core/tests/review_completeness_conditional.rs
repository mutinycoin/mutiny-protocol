//! Review completeness for conditional MUT funding (phase 5A): the hash lock, the claim and the
//! refund each show destination(s) with labels and the typed check, amount, fee (rule, payer,
//! size), change, conditions (hash condition, claim window, refund height with an approximate time,
//! offer, maker, opaque trade commitments, finality, approvals still required), timing, every
//! irreversible effect marked, and the warnings with their acknowledgements; the recipient sees the
//! same operation (same digest) from its side; no byte or field of the unsigned operation can change
//! without the review noticing; the text is pinned by golden snapshots.
//!
//! Determinism of the snapshots: the hash lock uses a FIXED public offer
//! (`golden/conditional_maker_offer_candidate3.hex`, a verified canonical offer from the public
//! current WalletOwner B; the old zero-fill container is retained as a historical fixture), and the claim
//! and refund use a lock record placed directly in the synthetic state.
//! NATIVE, TEST-VALUE; public test keys.
#[path = "support/conditional_kit.rs"]
mod kit;
#[path = "support/synthetic.rs"]
mod synthetic;

use mutiny_consensus_v8::{
    Hash,
    trading_v1::{
        self, Action, NativeLock, NativeLockKind, NativeOperation, NativeRecord, SignedOffer,
        Strikes, native_input_id,
    },
    transactions::OutPoint,
};
use mutiny_wallet_core_v8::*;
use synthetic::{World, address, identity, key_a, key_b, key_c};

const OFFER_HEX: &str = include_str!("golden/conditional_maker_offer_candidate3.hex");
const PREIMAGE: [u8; 32] = [0x42; 32];
const REFUND: u64 = 150;
const LOCK_ID: [u8; 32] = [0x6c; 32];

fn fixed_offer() -> SignedOffer {
    let raw = hex::decode(OFFER_HEX.trim()).unwrap();
    let offer = SignedOffer::decode(&raw).unwrap();
    offer.verify().unwrap();
    assert_eq!(offer.encode().unwrap(), raw);
    offer
}

fn condition() -> Hash {
    trading_v1::preimage_hash(&PREIMAGE)
}

/// Key A locks 1,000,000 atoms (the fixed offer's amount) for key B from one 5,000,000 coin at head
/// 100; A also holds a second coin for field mutations.
fn lock_scenario() -> (World, OperationPlan) {
    let mut world = World::with_wallets(100);
    world.coin(address(&key_a(), 1), 5_000_000, 1, false, 1, 0);
    world.coin(address(&key_a(), 1), 4_000_000, 1, false, 3, 0);
    let request = HashLockRequest::new(
        Blob::new(kit::offer_bytes(&fixed_offer())),
        address(&key_b(), 1),
        1_000_000,
        condition(),
        REFUND,
    )
    .with_trade([0x21; 32])
    .with_contract([0x22; 32]);
    let planned = plan(
        &OperationRequest::HashLock(request),
        &world.view(),
        &identity(&key_a()),
    )
    .unwrap();
    (world, planned)
}

/// A hash lock from A to B, placed directly in the state, created at height 90.
fn lock_record(world: &mut World) {
    let lock = NativeLock {
        context: kit::context_of(&world.anchor),
        trade: [0x21; 32],
        contract: [0x22; 32],
        generation: 1,
        sender: address(&key_a(), 1),
        recipient: address(&key_b(), 1),
        amount: Strikes(1_000_000),
        created_height: 90,
        kind: NativeLockKind::Hash {
            condition: condition(),
            refund_height: REFUND,
        },
    };
    world.state.protocol_records.insert(
        trading_v1::record_key(0, LOCK_ID),
        NativeRecord::Lock(lock).encode(LOCK_ID).unwrap(),
    );
}

/// B claims the lock at head 100 with fee coins of its own.
fn claim_scenario() -> (World, OperationPlan) {
    let mut world = World::with_wallets(100);
    lock_record(&mut world);
    world.coin(address(&key_b(), 1), 500_000, 1, false, 2, 0);
    world.coin(address(&key_b(), 1), 300_000, 1, false, 4, 0);
    let request = ClaimRequest::new(LOCK_ID, Preimage::from_bytes(PREIMAGE));
    let planned = plan(
        &OperationRequest::ConditionalClaim(request),
        &world.view(),
        &identity(&key_b()),
    )
    .unwrap();
    (world, planned)
}

/// A refunds the lock at head 149 (the next block is the refund height).
fn refund_scenario() -> (World, OperationPlan) {
    let mut world = World::with_wallets(REFUND - 1);
    lock_record(&mut world);
    world.coin(address(&key_a(), 1), 300_000, 1, false, 3, 0);
    let planned = plan(
        &OperationRequest::ConditionalRefund(RefundRequest::new(LOCK_ID)),
        &world.view(),
        &identity(&key_a()),
    )
    .unwrap();
    (world, planned)
}

fn rows_of(review: &Review, section: Section) -> Vec<Row> {
    review
        .rows()
        .into_iter()
        .filter(|row| row.section == section)
        .collect()
}

fn has(rows: &[Row], label: &str, fragment: &str) -> bool {
    rows.iter()
        .any(|row| row.label == label && row.value.contains(fragment))
}

/// What a person READS: every row except the binding digest (which changes with any byte) and the
/// phrase derived from it.
fn read(review: &Review) -> Vec<Row> {
    review
        .rows()
        .into_iter()
        .filter(|row| row.section != Section::Binding && row.label != "Type to confirm")
        .collect()
}

/// An address as the review rows show it (Order W2): the checksummed form of the review's chain
/// class first, then the label and the legacy hexadecimal identifier.
fn shown(review: &Review, address: &[u8; 32], label: &str) -> String {
    format!(
        "{} ({label}; legacy hex {})",
        mutiny_wallet_core_v8::address_format::encode(address, review.chain().class),
        hex::encode(address)
    )
}

#[test]
fn a_hash_lock_review_shows_every_required_row() {
    let (world, planned) = lock_scenario();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    let (recipient, sender) = (address(&key_b(), 1), address(&key_a(), 1));
    let fee = reviewed.fee().atoms;

    let money = rows_of(&reviewed, Section::Money);
    assert!(has(
        &money,
        "Locks",
        &format!(
            "0.01000000 MUT (1000000 STRIKES) to {}",
            shown(&reviewed, &recipient, "an external address")
        )
    ));
    assert!(has(&money, "Locks", "an external address"));
    assert!(has(
        &money,
        "Type to confirm destination",
        &reviewed.destination_check_text(0)
    ));
    assert!(has(&money, "Returns to this wallet", &hex::encode(sender)));
    assert!(has(&money, "Amount", "0.01000000 MUT (1000000 STRIKES)"));
    let fee_row = money.iter().find(|r| r.label == "Network fee").unwrap();
    for fragment in [
        "the greater of 240 STRIKES",
        "paid by this wallet",
        "signed size",
    ] {
        assert!(fee_row.value.contains(fragment), "{}", fee_row.value);
    }
    assert!(has(
        &money,
        "Total leaving this wallet",
        &units::format_mut(1_000_000 + fee)
    ));
    assert!(has(&money, "Inputs", "1 coin(s) worth 0.05000000 MUT"));

    let conditions = rows_of(&reviewed, Section::Conditions);
    assert!(has(
        &conditions,
        "Hash condition",
        &hex::encode(condition())
    ));
    // The worst case, not the best: the lock may be included as late as its expiry (148), and a
    // claim counts only in a later block below the refund height (150), so one block is certain.
    for fragment in [
        "At least 1 block(s), the worst case",
        "below the refund height 150 (50 blocks after the verified block; about 50 min, approximate at the 60 s target interval)",
        "(last claim block 149)",
        "as late as block 148, which leaves blocks 149 to 149",
        "Included earlier, the lock leaves more",
        "Claim and refund are mutually exclusive",
    ] {
        assert!(has(&conditions, "Claim window", fragment), "{fragment}");
    }
    assert!(
        reviewed
            .summary()
            .contains("in at least 1 block(s) after the lock's inclusion"),
        "{}",
        reviewed.summary()
    );
    assert!(has(
        &conditions,
        "Refund height",
        "refund eligibility does not execute a refund"
    ));
    assert!(has(
        &conditions,
        "Offer",
        &hex::encode(fixed_offer().body.id().unwrap())
    ));
    assert!(has(&conditions, "Offer", "single-fill"));
    // The native offer commits its WalletOwner to the actual recipient settlement slot.
    assert!(has(
        &conditions,
        "Offer",
        "signed maker WalletOwner is bound to the recipient settlement slot"
    ));
    for fragment in [
        address_format::encode_for(&recipient, &view),
        "maximum fee 100000 STRIKES".into(),
        "condition none".into(),
        "Current maker authority is required at first canonical funding".into(),
    ] {
        assert!(has(&conditions, "Offer", &fragment), "{fragment}");
    }
    assert!(has(&conditions, "Offer terms", "50000 satoshis"));
    assert!(has(&conditions, "Offer terms", "network code 3 (regtest)"));
    assert!(has(
        &conditions,
        "Offer terms",
        "this wallet does not verify the external leg"
    ));
    assert!(has(
        &conditions,
        "Maker",
        &hex::encode(fixed_offer().body.maker().unwrap())
    ));
    assert!(has(&conditions, "Maker", "not a wallet address"));
    assert!(has(
        &conditions,
        "Finality",
        "Inclusion in a proposed, uncertified block is not finality"
    ));
    assert!(has(
        &conditions,
        "Trade commitments",
        &hex::encode([0x21; 32])
    ));
    assert!(has(
        &conditions,
        "Trade commitments",
        &hex::encode([0x22; 32])
    ));
    assert!(has(&conditions, "Trade generation", "1."));
    assert!(has(
        &conditions,
        "Validity window",
        "Valid only for blocks 101 to 148"
    ));
    assert!(has(
        &conditions,
        "Inputs",
        &format!(
            "unspent coins of the sender address {}",
            address_format::encode_for(&sender, &view)
        )
    ));
    assert!(has(&conditions, "Fee rule", "the maker's offer proof"));
    assert!(has(
        &conditions,
        "Approvals still required",
        "the approval of the recipient (slot 1, a counterparty)"
    ));
    assert!(has(
        &conditions,
        "Approvals still required",
        "the maker's fill signature"
    ));

    let timing = rows_of(&reviewed, Section::Timing);
    assert!(has(&timing, "Valid from block", "101"));
    assert!(has(&timing, "Valid until block", "approximate"));

    let effects = rows_of(&reviewed, Section::Effects);
    let irreversible: Vec<&Row> = effects
        .iter()
        .filter(|r| r.emphasis == Emphasis::Irreversible)
        .collect();
    for fragment in [
        "Spends 1 coin(s)",
        "Locks 0.01000000 MUT",
        "Consumes the maker's single-fill offer",
        "network fee",
        "cannot be revoked",
    ] {
        assert!(
            irreversible.iter().any(|r| r.value.contains(fragment)),
            "{fragment}"
        );
    }
    assert!(
        effects
            .iter()
            .any(|r| r.emphasis == Emphasis::Normal && r.value.contains("only the sender"))
    );

    let codes: Vec<&str> = reviewed.warnings().iter().map(|w| w.code).collect();
    for code in [
        "EXTERNAL_LEG_NOT_VERIFIED",
        "NOT_FINAL_UNTIL_CERTIFIED",
        "OPAQUE_TRADE_COMMITMENTS",
        "SHORT_CLAIM_WINDOW",
    ] {
        assert!(codes.contains(&code), "{code}");
    }
    let short = reviewed
        .warnings()
        .iter()
        .find(|w| w.code == "SHORT_CLAIM_WINDOW")
        .unwrap();
    assert_eq!(
        (short.severity, short.requires),
        (Severity::Caution, Some(AckKind::Conditions))
    );
    for fragment in [
        "as short as 1 block(s) (blocks 149 to 149)",
        "as late as block 148",
        "below the refund height 150",
        "any of 48 block(s)",
    ] {
        assert!(short.text.contains(fragment), "{fragment}: {}", short.text);
    }
    assert!(
        !codes.contains(&"TEST_VALUE_CHAIN"),
        "a chain without a Treasury declares no class"
    );

    let authorizations = rows_of(&reviewed, Section::Authorizations);
    assert_eq!(authorizations.len(), 3);
    assert!(authorizations[0].value.starts_with("this wallet signs"));
    assert!(
        authorizations[1]
            .value
            .starts_with("a counterparty must sign")
    );
    assert!(authorizations[2].value.starts_with("the maker must sign"));
    assert_eq!(authorizations[2].label, "The maker's fill signature");

    assert_eq!(
        reviewed.acknowledgements(),
        &[
            AckKind::Destination,
            AckKind::Amount,
            AckKind::Fee,
            AckKind::Conditions,
            AckKind::Irreversible,
            AckKind::ExternalEvidence
        ]
    );
    assert!(reviewed.requires_phrase());
    assert!(reviewed.render_text().contains("Type to confirm: CONFIRM "));
    assert_eq!(reviewed.parties()[0].role, PartyRole::LockSender);
    assert_eq!(reviewed.parties()[1].role, PartyRole::LockRecipient);
    assert_eq!(reviewed.net_debit(), Some(u128::from(1_000_000 + fee)));
    assert_eq!(reviewed.fee().rule, FeeRule::TradingMinimum { floor: 240 });
    assert!(
        reviewed
            .rows()
            .iter()
            .all(|r| !r.label.is_empty() && !r.value.is_empty())
    );
}

#[test]
fn the_recipient_reads_the_same_operation_from_its_side() {
    let (world, planned) = lock_scenario();
    let view = world.view();
    let sender_review = review(&planned, &view).unwrap();
    let approval = kit::approve(&sender_review, &view);
    let partial = KeySigner::for_test(key_a())
        .unwrap()
        .authorize(planned, approval, &view)
        .unwrap();
    let seen = explain(partial.bytes(), &view, &identity(&key_b())).unwrap();
    assert_eq!(
        seen.binding(),
        sender_review.binding(),
        "the digest binds the unsigned form"
    );
    assert_eq!(seen.title(), "Approve a hash lock for this wallet");
    assert_eq!(
        seen.fee().payer,
        FeePayer::Counterparty(address(&key_a(), 1))
    );
    assert_eq!(seen.net_debit(), Some(0), "nothing leaves the recipient");
    assert_eq!(seen.returned(), 0);
    assert!(
        seen.destinations_needing_check().is_empty(),
        "the lock is for this wallet; the sender's change is not a destination of it"
    );
    assert_eq!(seen.destinations().len(), 1);
    assert_eq!(seen.destinations()[0].label, AddressLabel::ThisWallet);
    let statuses: Vec<RequirementStatus> = seen.authorizations().iter().map(|r| r.status).collect();
    assert_eq!(
        statuses,
        [
            RequirementStatus::Provided,
            RequirementStatus::ThisWallet,
            RequirementStatus::ThisWallet
        ]
    );
    assert!(
        seen.effects()
            .iter()
            .any(|e| e.text.starts_with("This wallet may claim 0.01000000 MUT"))
    );
    assert!(
        seen.effects()
            .iter()
            .any(|e| e.text.contains("of change to the sender address"))
    );
    // A third wallet sees a lock between other wallets.
    let third = explain(partial.bytes(), &view, &identity(&key_c())).unwrap();
    assert_eq!(third.title(), "Hash lock between other wallets");
    assert_eq!(third.binding(), sender_review.binding());
}

#[test]
fn a_claim_review_shows_the_disclosure_the_deadline_and_the_external_preimage() {
    let (world, planned) = claim_scenario();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    let recipient = address(&key_b(), 1);
    let money = rows_of(&reviewed, Section::Money);
    assert!(has(
        &money,
        "The protocol pays",
        &format!(
            "0.01000000 MUT (1000000 STRIKES) to {}",
            shown(&reviewed, &recipient, "this wallet")
        )
    ));
    assert!(has(
        &money,
        "Returns to this wallet",
        &hex::encode(recipient)
    ));
    assert!(has(&money, "Network fee", "paid by this wallet"));
    let conditions = rows_of(&reviewed, Section::Conditions);
    assert!(has(&conditions, "Lock", &hex::encode(LOCK_ID)));
    assert!(has(&conditions, "Hash condition", "hashes to it (checked)"));
    assert!(has(
        &conditions,
        "Claim deadline",
        "below the refund height 150 (50 blocks after the verified block; about 50 min, approximate"
    ));
    assert!(has(
        &conditions,
        "Preimage origin",
        "preimage supplied externally; Bitcoin settlement not verified by this wallet"
    ));
    assert!(has(
        &conditions,
        "Fee coins",
        "separate coin(s) of the recipient address"
    ));
    assert!(has(&conditions, "Finality", "not finality"));
    assert_eq!(
        reviewed.timing().expiry_height,
        Some(REFUND - 1),
        "the claim never outlives its window"
    );
    let effects = rows_of(&reviewed, Section::Effects);
    assert!(
        effects.iter().any(|r| r.emphasis == Emphasis::Irreversible
            && r.value.starts_with("Publishes the preimage"))
    );
    assert!(effects.iter().any(|r| {
        r.emphasis == Emphasis::Irreversible
            && r.value
                .contains("ends the lock: it can no longer be refunded")
    }));
    let disclosure = reviewed
        .warnings()
        .iter()
        .find(|w| w.code == "DISCLOSES_PREIMAGE")
        .unwrap();
    assert_eq!(
        (disclosure.severity, disclosure.requires),
        (Severity::Danger, Some(AckKind::DisclosesPreimage))
    );
    let external = reviewed
        .warnings()
        .iter()
        .find(|w| w.code == "PREIMAGE_SUPPLIED_EXTERNALLY")
        .unwrap();
    assert_eq!(external.requires, Some(AckKind::ExternalEvidence));
    for ack in [
        AckKind::Amount,
        AckKind::Fee,
        AckKind::Conditions,
        AckKind::Irreversible,
        AckKind::ExternalEvidence,
        AckKind::DisclosesPreimage,
    ] {
        assert!(reviewed.acknowledgements().contains(&ack), "{ack:?}");
    }
    assert!(
        !reviewed.acknowledgements().contains(&AckKind::Destination),
        "everything goes to this wallet"
    );
    assert!(reviewed.requires_phrase());
    assert_eq!(reviewed.parties()[0].role, PartyRole::Claimant);
    assert!(
        !reviewed.render_text().contains(&hex::encode(PREIMAGE)),
        "the preimage itself is not shown"
    );
}

#[test]
fn a_refund_review_shows_the_refund_height_and_that_it_ends_the_lock() {
    let (world, planned) = refund_scenario();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    let sender = address(&key_a(), 1);
    let money = rows_of(&reviewed, Section::Money);
    assert!(has(
        &money,
        "The protocol pays",
        &format!("to {}", shown(&reviewed, &sender, "this wallet"))
    ));
    let conditions = rows_of(&reviewed, Section::Conditions);
    assert!(has(
        &conditions,
        "Refund height",
        "Refund allowed from block 150 on; the next block is 150."
    ));
    assert!(has(
        &conditions,
        "Exclusivity",
        "Refund eligibility does not execute a refund"
    ));
    assert!(has(
        &conditions,
        "Fee coins",
        "separate coin(s) of the sender address"
    ));
    let timing = rows_of(&reviewed, Section::Timing);
    assert!(
        has(&timing, "Earliest height", "150 (reached)")
            || has(&timing, "Earliest height", "150 (1 blocks")
    );
    let effects = rows_of(&reviewed, Section::Effects);
    assert!(effects.iter().any(|r| r.emphasis == Emphasis::Irreversible
        && r.value.contains("the recipient can no longer claim it")));
    assert!(
        !reviewed.requires_phrase(),
        "a refund returns funds to this wallet"
    );
    assert!(reviewed.acknowledgements().contains(&AckKind::Conditions));
    assert_eq!(reviewed.parties()[0].role, PartyRole::Owner);
}

fn assert_every_flip_is_refused_or_visible(
    world: &World,
    planned: &OperationPlan,
    me: &SignerIdentity,
) {
    let view = world.view();
    let base = review(planned, &view).unwrap();
    let base_rows = read(&base);
    let bytes = planned.objects()[0].bytes.clone();
    let (mut refused, mut visible) = (0usize, 0usize);
    for index in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[index] ^= 1 << (index % 8);
        match explain(&changed, &view, me) {
            Err(_) => refused += 1,
            Ok(other) => {
                assert_ne!(
                    read(&other),
                    base_rows,
                    "byte {index} changed the operation but nothing a person reads"
                );
                assert_ne!(other.binding(), base.binding(), "byte {index}");
                visible += 1;
            }
        }
    }
    assert!(
        refused > 0 && visible > 0,
        "refused {refused}, visible {visible}"
    );
}

#[test]
fn no_byte_of_an_unsigned_hash_lock_changes_without_the_review_noticing() {
    let (world, planned) = lock_scenario();
    assert_every_flip_is_refused_or_visible(&world, &planned, &identity(&key_a()));
}

#[test]
fn no_byte_of_an_unsigned_claim_or_refund_changes_without_the_review_noticing() {
    let (world, planned) = claim_scenario();
    assert_every_flip_is_refused_or_visible(&world, &planned, &identity(&key_b()));
    let (world, planned) = refund_scenario();
    assert_every_flip_is_refused_or_visible(&world, &planned, &identity(&key_a()));
}

/// Explain a mutated copy of `planned` and require that it is refused or reads differently.
fn noticed(
    world: &World,
    planned: &OperationPlan,
    me: &SignerIdentity,
    what: &str,
    edit: impl FnOnce(&mut NativeOperation),
) {
    let view = world.view();
    let base = read(&review(planned, &view).unwrap());
    let mut wire = kit::wire(&planned.objects()[0].bytes);
    edit(&mut wire);
    let Ok(raw) = wire.encode() else {
        return; // not even encodable
    };
    if let Ok(other) = explain(&raw, &view, me) {
        assert_ne!(
            read(&other),
            base,
            "{what} changed but nothing a person reads"
        );
    }
}

#[test]
fn each_field_of_a_hash_lock_shows_up_in_the_review_or_is_refused() {
    let (world, planned) = lock_scenario();
    let me = identity(&key_a());
    let change_of = |wire: &mut NativeOperation, delta: i64| {
        if let Action::HashLock { change, .. } = &mut wire.operation.action {
            change.0 = (change.0 as i64 + delta) as u64;
        }
    };
    noticed(&world, &planned, &me, "recipient", |w| {
        if let Action::HashLock { recipient, .. } = &mut w.operation.action {
            *recipient = address(&key_c(), 1);
        }
    });
    noticed(&world, &planned, &me, "condition", |w| {
        if let Action::HashLock { condition, .. } = &mut w.operation.action {
            condition[5] ^= 1;
        }
    });
    noticed(&world, &planned, &me, "refund height", |w| {
        if let Action::HashLock { refund_height, .. } = &mut w.operation.action {
            *refund_height += 7;
        }
    });
    noticed(&world, &planned, &me, "amount", |w| {
        if let Action::HashLock { amount, .. } = &mut w.operation.action {
            amount.0 += 1;
        }
        change_of(w, -1);
    });
    noticed(&world, &planned, &me, "sender", |w| {
        if let Action::HashLock { sender, .. } = &mut w.operation.action {
            *sender = address(&key_c(), 1);
        }
    });
    noticed(&world, &planned, &me, "offer id", |w| {
        if let Action::HashLock { offer, .. } = &mut w.operation.action {
            offer[0] ^= 1;
        }
    });
    noticed(&world, &planned, &me, "maker", |w| {
        if let Action::HashLock { maker, .. } = &mut w.operation.action {
            maker[0] ^= 1;
        }
    });
    noticed(&world, &planned, &me, "fee up, change down", |w| {
        w.operation.meta.fee.0 += 9;
        change_of(w, -9);
    });
    noticed(&world, &planned, &me, "trade", |w| {
        w.operation.meta.trade[3] ^= 1
    });
    noticed(&world, &planned, &me, "contract", |w| {
        w.operation.meta.contract[3] ^= 1
    });
    noticed(&world, &planned, &me, "generation", |w| {
        w.operation.meta.generation += 1
    });
    noticed(&world, &planned, &me, "expiry", |w| {
        w.operation.meta.envelope.last_height -= 10
    });
    noticed(&world, &planned, &me, "creation", |w| {
        w.operation.meta.envelope.first_height -= 1
    });
    noticed(&world, &planned, &me, "another input", |w| {
        // The 4,000,000 coin instead of the 5,000,000 one: change shrinks by 1,000,000.
        let other = OutPoint {
            transaction: [3; 32],
            index: 0,
        };
        w.inputs = vec![other.clone()];
        w.operation.meta.inputs = vec![native_input_id(&other)];
        change_of(w, -1_000_000);
    });
    noticed(&world, &planned, &me, "context", |w| {
        w.operation.meta.context.fingerprint[0] ^= 1
    });
    // Each visible change really is visible: spot-check the rendered values.
    let view = world.view();
    let mut wire = kit::wire(&planned.objects()[0].bytes);
    if let Action::HashLock {
        condition,
        refund_height,
        ..
    } = &mut wire.operation.action
    {
        condition[0] = 0xee;
        *refund_height = 170;
    }
    let shown = explain(&wire.encode().unwrap(), &view, &me)
        .unwrap()
        .render_text();
    assert!(shown.contains(&hex::encode({
        let mut c = trading_v1::preimage_hash(&PREIMAGE);
        c[0] = 0xee;
        c
    })));
    assert!(shown.contains("before block 170"));
}

#[test]
fn each_field_of_a_claim_shows_up_in_the_review_or_is_refused() {
    let (world, planned) = claim_scenario();
    let me = identity(&key_b());
    let change_of = |wire: &mut NativeOperation, delta: i64| {
        if let Action::Claim { change, .. } = &mut wire.operation.action {
            change.0 = (change.0 as i64 + delta) as u64;
        }
    };
    noticed(&world, &planned, &me, "lock", |w| {
        if let Action::Claim { output, .. } = &mut w.operation.action {
            output[0] ^= 1;
        }
    });
    noticed(&world, &planned, &me, "recipient", |w| {
        if let Action::Claim { recipient, .. } = &mut w.operation.action {
            *recipient = address(&key_c(), 1);
        }
    });
    noticed(&world, &planned, &me, "amount", |w| {
        if let Action::Claim { amount, .. } = &mut w.operation.action {
            amount.0 -= 1;
        }
    });
    noticed(&world, &planned, &me, "preimage", |w| {
        if let Action::Claim { preimage, .. } = &mut w.operation.action {
            preimage[0] ^= 1;
        }
    });
    noticed(&world, &planned, &me, "fee up, change down", |w| {
        w.operation.meta.fee.0 += 3;
        change_of(w, -3);
    });
    noticed(&world, &planned, &me, "trade", |w| {
        w.operation.meta.trade[0] ^= 1
    });
    noticed(&world, &planned, &me, "contract", |w| {
        w.operation.meta.contract[0] ^= 1
    });
    noticed(&world, &planned, &me, "generation", |w| {
        w.operation.meta.generation += 1
    });
    noticed(&world, &planned, &me, "expiry", |w| {
        w.operation.meta.envelope.last_height -= 5
    });
    noticed(&world, &planned, &me, "creation", |w| {
        w.operation.meta.envelope.first_height -= 1
    });
    noticed(&world, &planned, &me, "another fee coin", |w| {
        let other = OutPoint {
            transaction: [4; 32],
            index: 0,
        };
        w.inputs = vec![other.clone()];
        w.operation.meta.inputs = vec![native_input_id(&other)];
        change_of(w, -200_000);
    });
}

#[test]
fn each_field_of_a_refund_shows_up_in_the_review_or_is_refused() {
    let (world, planned) = refund_scenario();
    let me = identity(&key_a());
    noticed(&world, &planned, &me, "lock", |w| {
        if let Action::Refund { output, .. } = &mut w.operation.action {
            output[0] ^= 1;
        }
    });
    noticed(&world, &planned, &me, "owner", |w| {
        if let Action::Refund { owner, .. } = &mut w.operation.action {
            *owner = address(&key_c(), 1);
        }
    });
    noticed(&world, &planned, &me, "amount", |w| {
        if let Action::Refund { amount, .. } = &mut w.operation.action {
            amount.0 += 1;
        }
    });
    noticed(&world, &planned, &me, "fee up, change down", |w| {
        w.operation.meta.fee.0 += 3;
        if let Action::Refund { change, .. } = &mut w.operation.action {
            change.0 -= 3;
        }
    });
    noticed(&world, &planned, &me, "trade", |w| {
        w.operation.meta.trade[0] ^= 1
    });
    noticed(&world, &planned, &me, "expiry", |w| {
        w.operation.meta.envelope.last_height -= 5
    });
}

#[test]
fn every_truncation_and_extension_of_the_unsigned_bytes_is_refused_without_a_panic() {
    for (world, planned, me) in [
        {
            let (w, p) = lock_scenario();
            (w, p, identity(&key_a()))
        },
        {
            let (w, p) = claim_scenario();
            (w, p, identity(&key_b()))
        },
    ] {
        let view = world.view();
        let bytes = planned.objects()[0].bytes.clone();
        for cut in 0..bytes.len() {
            assert_eq!(
                explain(&bytes[..cut], &view, &me).unwrap_err(),
                Refusal::UnknownOperation,
                "prefix {cut}"
            );
            assert_eq!(
                adopt(&bytes[..cut], &view, &me).unwrap_err(),
                Refusal::UnknownOperation
            );
        }
        for extra in [1usize, 2, 17, 4096] {
            let mut longer = bytes.clone();
            longer.extend(std::iter::repeat_n(0u8, extra));
            assert!(
                explain(&longer, &view, &me).is_err(),
                "{extra} trailing bytes"
            );
            assert!(adopt(&longer, &view, &me).is_err());
        }
    }
}

fn golden(name: &str, expected: &str, text: &str) {
    assert!(
        text == expected,
        "review text differs from tests/golden/{name}; if the change is deliberate, replace the file with:\n{text}"
    );
}

#[test]
fn golden_text_snapshots() {
    let (world, planned) = lock_scenario();
    golden(
        "hash_lock_review.txt",
        include_str!("golden/hash_lock_review.txt"),
        &review(&planned, &world.view()).unwrap().render_text(),
    );
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    let partial = KeySigner::for_test(key_a())
        .unwrap()
        .authorize(planned, kit::approve(&reviewed, &view), &view)
        .unwrap();
    golden(
        "hash_lock_recipient_review.txt",
        include_str!("golden/hash_lock_recipient_review.txt"),
        &explain(partial.bytes(), &view, &identity(&key_b()))
            .unwrap()
            .render_text(),
    );
    let (world, planned) = claim_scenario();
    golden(
        "claim_review.txt",
        include_str!("golden/claim_review.txt"),
        &review(&planned, &world.view()).unwrap().render_text(),
    );
    let (world, planned) = refund_scenario();
    golden(
        "refund_review.txt",
        include_str!("golden/refund_review.txt"),
        &review(&planned, &world.view()).unwrap().render_text(),
    );
}

#[test]
#[ignore = "prints the current review texts for the golden files"]
fn print_review_texts() {
    let (world, planned) = lock_scenario();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    println!(
        "=====hash_lock_review.txt\n{}=====end",
        reviewed.render_text()
    );
    let partial = KeySigner::for_test(key_a())
        .unwrap()
        .authorize(planned, kit::approve(&reviewed, &view), &view)
        .unwrap();
    println!(
        "=====hash_lock_recipient_review.txt\n{}=====end",
        explain(partial.bytes(), &view, &identity(&key_b()))
            .unwrap()
            .render_text()
    );
    let (world, planned) = claim_scenario();
    println!(
        "=====claim_review.txt\n{}=====end",
        review(&planned, &world.view()).unwrap().render_text()
    );
    let (world, planned) = refund_scenario();
    println!(
        "=====refund_review.txt\n{}=====end",
        review(&planned, &world.view()).unwrap().render_text()
    );
}
