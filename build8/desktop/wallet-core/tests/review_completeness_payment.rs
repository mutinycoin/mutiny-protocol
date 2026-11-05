//! Review completeness for ordinary payments: destination, amount, fee, change, conditions, timing
//! and irreversible effects are all present, no field of the unsigned bytes can be hidden, and the
//! text rendering is pinned by a golden snapshot. NATIVE, TEST-VALUE; public test keys only.
#[path = "support/synthetic.rs"]
mod synthetic;

use mutiny_consensus_v8::{
    dividend_state_v1::DividendState,
    transactions::{OutPoint, Output},
    transactions_v2::{Input, Transfer},
    treasury_v1::{Class, Treasury},
};
use mutiny_wallet_core_v8::*;
use synthetic::{World, address, descriptor, identity, key_a, key_b, key_c};

fn pay(recipient: [u8; 32], amount: u64) -> OperationRequest {
    OperationRequest::Payment(PaymentRequest::new(recipient, amount))
}

/// Key A (the wallet) pays key B 1,000,000 atoms from one 5,000,000 atom coin at head 100.
fn scenario() -> (World, SignerIdentity, OperationPlan, [u8; 32]) {
    let mut world = World::with_wallets(100);
    world.coin(address(&key_a(), 1), 5_000_000, 1, false, 1, 0);
    let me = identity(&key_a());
    let recipient = address(&key_b(), 1);
    let planned = plan(&pay(recipient, 1_000_000), &world.view(), &me).unwrap();
    (world, me, planned, recipient)
}

fn rows_of(review: &Review, section: Section) -> Vec<Row> {
    review
        .rows()
        .into_iter()
        .filter(|row| row.section == section)
        .collect()
}

#[test]
fn a_payment_review_shows_destination_amount_fee_change_conditions_timing_and_effects() {
    let (world, _me, planned, recipient) = scenario();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    let rows = reviewed.rows();

    // Destination, with the typed re-entry text.
    let money = rows_of(&reviewed, Section::Money);
    assert!(money.iter().any(|r| r.label == "Pays"
        && r.value.contains(&hex::encode(recipient))
        && r.value.contains("an external address")));
    assert!(
        money
            .iter()
            .any(|r| r.label == "Type to confirm destination"
                && r.value == reviewed.destination_check_text(0))
    );
    // Amount, fee (with rule, payer and size), change, total.
    assert!(money.iter().any(|r| r.label == "Amount" && r.value.starts_with("0.01000000 MUT (1000000 STRIKES)")));
    let fee_row = money
        .iter()
        .find(|r| r.label == "Network fee")
        .expect("fee row");
    assert!(
        fee_row.value.contains("at least one atom per byte"),
        "{}",
        fee_row.value
    );
    assert!(
        fee_row.value.contains("paid by this wallet"),
        "{}",
        fee_row.value
    );
    assert!(fee_row.value.contains("signed size"), "{}", fee_row.value);
    assert!(money.iter().any(|r| r.label == "Returns to this wallet"
        && r.value.contains(&hex::encode(address(&key_a(), 1)))));
    assert!(money.iter().any(|r| r.label == "Total leaving this wallet"));
    assert!(
        money
            .iter()
            .any(|r| r.label == "Inputs" && r.value.starts_with("1 coin(s) worth 0.05000000 MUT"))
    );
    assert!(money.iter().any(|r| r.label == "Input 0"));
    // Conditions.
    let conditions = rows_of(&reviewed, Section::Conditions);
    for label in ["Validity window", "Inputs", "Fee rule"] {
        assert!(
            conditions.iter().any(|r| r.label == label),
            "condition {label}"
        );
    }
    // Timing, with heights and the approximation caveat.
    let timing = rows_of(&reviewed, Section::Timing);
    assert!(
        timing
            .iter()
            .any(|r| r.label == "Valid from block" && r.value == "101")
    );
    let until = timing
        .iter()
        .find(|r| r.label == "Valid until block")
        .expect("expiry row");
    assert!(
        until.value.starts_with("245 (145 blocks"),
        "{}",
        until.value
    );
    assert!(until.value.contains("approximate"), "{}", until.value);
    // Irreversible effects are marked.
    let effects = rows_of(&reviewed, Section::Effects);
    assert!(
        effects
            .iter()
            .filter(|r| r.emphasis == Emphasis::Irreversible)
            .count()
            >= 3
    );
    assert!(
        effects
            .iter()
            .any(|r| r.value.contains("cannot be revoked"))
    );
    // Chain context and signer.
    for label in [
        "Network",
        "Genesis",
        "Protocol fingerprint",
        "Verified block height",
        "Verified block",
        "State root",
        "Chain class",
    ] {
        assert!(
            rows.iter()
                .any(|r| r.section == Section::Chain && r.label == label),
            "chain row {label}"
        );
    }
    assert!(
        rows.iter()
            .any(|r| r.section == Section::Signer && r.label == "Signing address")
    );
    // Authorizations: who signs what.
    let auth = rows_of(&reviewed, Section::Authorizations);
    assert_eq!(auth.len(), 1);
    assert!(auth[0].value.starts_with("this wallet signs"));
    // Acknowledgements and binding.
    assert_eq!(
        rows_of(&reviewed, Section::Acknowledgements).len(),
        reviewed.acknowledgements().len()
    );
    assert_eq!(
        rows_of(&reviewed, Section::Binding)[0].value,
        reviewed.binding().to_hex()
    );

    // Structured access matches the rows.
    assert_eq!(reviewed.kind(), OperationKind::Payment);
    assert!(!reviewed.title().is_empty() && !reviewed.summary().is_empty());
    assert_eq!(reviewed.chain().head_height, 100);
    assert_eq!(reviewed.signer().address, address(&key_a(), 1));
    assert_eq!(reviewed.parties().len(), 2);
    assert_eq!(reviewed.parties()[0].role, PartyRole::Sender);
    assert_eq!(reviewed.parties()[1].role, PartyRole::Recipient);
    assert!(
        reviewed
            .warnings()
            .iter()
            .any(|w| w.code == "TEST_VALUE_CHAIN")
            == (view.class() == ChainClass::TestValue)
    );
}

#[test]
fn every_row_is_filled_and_sections_appear_in_display_order() {
    let (world, _me, planned, _) = scenario();
    let reviewed = review(&planned, &world.view()).unwrap();
    let rows = reviewed.rows();
    assert!(
        rows.iter()
            .all(|r| !r.label.is_empty() && !r.value.is_empty())
    );
    let mut last = Section::Summary;
    for row in &rows {
        assert!(row.section >= last, "{:?} after {:?}", row.section, last);
        last = row.section;
    }
    let text = reviewed.render_text();
    assert!(text.starts_with("== Summary ==\n"));
    for title in [
        "== Chain ==",
        "== Money ==",
        "== Conditions ==",
        "== Timing ==",
        "== Effects ==",
        "== You must acknowledge ==",
        "== Binding ==",
    ] {
        assert!(text.contains(title), "{title}");
    }
    assert!(
        text.lines().all(|line| !line.ends_with(' ')),
        "no trailing spaces"
    );
    assert!(!text.contains('\r'));
    assert_eq!(text, reviewed.render_text(), "rendering is deterministic");
}

#[test]
fn only_destinations_that_are_not_this_wallet_need_the_typed_check() {
    let mut world = World::new(100);
    let wallet = key_a();
    let treasury = key_c();
    world
        .state
        .wallets
        .register(&descriptor(&treasury, 1))
        .unwrap();
    world.state.dividends =
        DividendState::genesis(Treasury::new(Class::TestValue, descriptor(&treasury, 1)).unwrap());
    world.coin(address(&wallet, 1), 5_000_000, 1, false, 1, 0);
    let me = identity(&wallet);
    let view = world.view();

    let to_treasury = review(
        &plan(&pay(address(&treasury, 1), 100_000), &view, &me).unwrap(),
        &view,
    )
    .unwrap();
    let labels: Vec<(DestinationRole, AddressLabel)> = to_treasury
        .destinations()
        .iter()
        .map(|d| (d.role, d.label))
        .collect();
    assert_eq!(
        labels,
        [
            (DestinationRole::Payment, AddressLabel::Treasury),
            (DestinationRole::Change, AddressLabel::ThisWallet)
        ]
    );
    assert_eq!(
        to_treasury.destinations_needing_check(),
        vec![0],
        "the Treasury needs the check; the change does not"
    );
    assert!(
        to_treasury
            .acknowledgements()
            .contains(&AckKind::Destination)
    );

    let to_self = review(
        &plan(&pay(address(&wallet, 1), 100_000), &view, &me).unwrap(),
        &view,
    )
    .unwrap();
    assert!(to_self.destinations_needing_check().is_empty());
    assert!(
        !to_self.acknowledgements().contains(&AckKind::Destination),
        "nothing leaves the wallet"
    );
    assert!(!to_self.acknowledgements().contains(&AckKind::Amount));
    assert!(to_self.acknowledgements().contains(&AckKind::Fee));
}

#[test]
fn no_byte_of_the_unsigned_operation_can_change_without_the_review_noticing() {
    let (world, me, planned, _) = scenario();
    let view = world.view();
    let base = review(&planned, &view).unwrap();
    // What a person READS: every row except the binding digest, which changes with any byte and so
    // would make this comparison vacuous.
    let read = |review: &Review| -> Vec<Row> {
        review
            .rows()
            .into_iter()
            .filter(|row| row.section != Section::Binding)
            .collect()
    };
    let base_rows = read(&base);
    let bytes = planned.objects()[0].bytes.clone();
    let (mut refused, mut visible) = (0usize, 0usize);
    for index in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[index] ^= 0x01;
        match explain(&changed, &view, &me) {
            Err(_) => refused += 1,
            Ok(other) => {
                // The digest binds the UNSIGNED form, so a byte inside a signature placeholder keeps the
                // digest but must then show up as a signature that does not verify.
                assert_ne!(
                    read(&other),
                    base_rows,
                    "byte {index} changed the operation but nothing a person reads"
                );
                if other.binding() == base.binding() {
                    assert!(
                        other.warnings().iter().any(|w| w.code == "BAD_SIGNATURE"),
                        "byte {index}"
                    );
                }
                visible += 1;
            }
        }
    }
    // Both outcomes occur: structural bytes are refused, value bytes show up in the rows.
    assert!(
        refused > 0 && visible > 0,
        "refused {refused}, visible {visible}"
    );
    assert_eq!(refused + visible, bytes.len());
}

#[test]
fn each_field_of_the_transfer_shows_up_in_the_review() {
    let (world, me, planned, recipient) = scenario();
    let view = world.view();
    let base = Transfer::decode(&planned.objects()[0].bytes).unwrap();
    let base_review = review(&planned, &view).unwrap();
    let show = |transfer: &Transfer| explain(&transfer.encode().unwrap(), &view, &me);

    // Recipient.
    let mut other_recipient = base.clone();
    other_recipient.outputs[0].owner = address(&key_c(), 1);
    let changed = show(&other_recipient).unwrap();
    assert!(
        changed
            .render_text()
            .contains(&hex::encode(address(&key_c(), 1)))
    );
    assert!(!changed.render_text().contains(&hex::encode(recipient)));

    // Amount (change adjusts so conservation still holds).
    let mut more = base.clone();
    more.outputs[0].atoms += 1;
    more.outputs[1].atoms -= 1;
    let changed = show(&more).unwrap();
    assert_eq!(changed.amount(), Some(1_000_001));
    assert_ne!(changed.render_text(), base_review.render_text());

    // Change address: the change now goes to a stranger, so the review says so loudly.
    let mut diverted = base.clone();
    diverted.outputs[1].owner = address(&key_c(), 1);
    let changed = show(&diverted).unwrap();
    assert_eq!(
        changed
            .destinations()
            .iter()
            .filter(|d| d.label == AddressLabel::External)
            .count(),
        2
    );
    assert!(changed.destinations_needing_check().len() == 2);
    assert!(
        changed
            .render_text()
            .contains(&hex::encode(address(&key_c(), 1)))
    );

    // Fee up, change down: the fee row and a warning show it.
    let mut greedy = base.clone();
    greedy.fee += 7;
    greedy.outputs[1].atoms -= 7;
    let changed = show(&greedy).unwrap();
    assert_eq!(changed.fee().atoms, base.fee + 7);
    assert!(
        changed
            .warnings()
            .iter()
            .any(|w| w.code == "FEE_ABOVE_MINIMUM")
    );

    // Validity window.
    let mut later = base.clone();
    later.expiry_height -= 50;
    let changed = show(&later).unwrap();
    assert_eq!(changed.timing().expiry_height, Some(195));
    let mut earlier = base.clone();
    earlier.created_height -= 1;
    assert_eq!(show(&earlier).unwrap().timing().created_height, Some(100));

    // The input set.
    let mut second_world = World::new(100);
    second_world.coin(address(&key_a(), 1), 5_000_000, 1, false, 1, 0);
    second_world.coin(address(&key_a(), 1), 3_000_000, 1, false, 2, 0);
    let second_view = second_world.view();
    let two_inputs = Transfer {
        inputs: vec![
            base.inputs[0].clone(),
            Input::unsigned(
                OutPoint {
                    transaction: [2; 32],
                    index: 0,
                },
                key_a().public(),
                1,
            )
            .unwrap(),
        ],
        outputs: vec![
            base.outputs[0].clone(),
            Output {
                owner: base.outputs[1].owner,
                atoms: base.outputs[1].atoms + 3_000_000 - 3_400,
            },
        ],
        fee: base.fee + 3_400,
        ..base.clone()
    };
    let changed = explain(&two_inputs.encode().unwrap(), &second_view, &me).unwrap();
    assert_eq!(changed.inputs().len(), 2);
    assert!(changed.render_text().matches("Input ").count() >= 2);

    // Genesis and fingerprint are context fields: another chain's bytes are refused outright.
    let mut foreign = base.clone();
    foreign.genesis = [0x70; 32];
    assert_eq!(
        show(&foreign).unwrap_err(),
        Refusal::WrongContext(ContextField::Genesis)
    );
    let mut foreign = base.clone();
    foreign.fingerprint = [0x71; 32];
    assert_eq!(
        show(&foreign).unwrap_err(),
        Refusal::WrongContext(ContextField::Fingerprint)
    );
}

#[test]
fn a_transfer_between_other_wallets_is_described_as_such_and_cannot_be_signed_by_me() {
    let mut world = World::new(100);
    world.coin(address(&key_b(), 1), 5_000_000, 1, false, 1, 0);
    let b_view = world.view();
    let planned = plan(
        &pay(address(&key_c(), 1), 1_000_000),
        &b_view,
        &identity(&key_b()),
    )
    .unwrap();
    // Seen from wallet A, who owns nothing in it.
    let seen_by_a = explain(&planned.objects()[0].bytes, &b_view, &identity(&key_a())).unwrap();
    assert_eq!(seen_by_a.title(), "Payment between other wallets");
    assert_eq!(
        seen_by_a.fee().payer,
        FeePayer::Counterparty(address(&key_b(), 1))
    );
    assert!(
        seen_by_a
            .authorizations()
            .iter()
            .all(|r| r.status == RequirementStatus::Counterparty)
    );
    assert_eq!(seen_by_a.net_debit(), Some(0), "nothing leaves wallet A");
    assert_eq!(seen_by_a.returned(), 0);
    assert!(seen_by_a.inputs().iter().all(|i| !i.owned_by_signer));
    // Seen from the recipient C: it receives the payment.
    let seen_by_c = explain(&planned.objects()[0].bytes, &b_view, &identity(&key_c())).unwrap();
    assert!(
        seen_by_c
            .effects()
            .iter()
            .any(|e| e.text.starts_with("This wallet receives 0.01000000 MUT"))
    );
    assert_eq!(seen_by_c.returned(), 0, "a received payment is not change");
    assert_eq!(seen_by_c.net_debit(), None);
    assert!(
        seen_by_c
            .destinations()
            .iter()
            .all(|d| d.role == DestinationRole::Payment)
    );
}

#[test]
fn warnings_cover_dust_expiry_and_signatures_that_do_not_verify() {
    let mut world = World::new(100);
    world.coin(address(&key_a(), 1), 1_000_000, 1, false, 1, 0);
    let me = identity(&key_a());
    let view = world.view();

    // Change smaller than the cost of spending it.
    let probe = plan(&pay([9; 32], 10_000), &view, &me).unwrap();
    let fee = review(&probe, &view).unwrap().fee().atoms;
    let dusty = plan(&pay([9; 32], 1_000_000 - fee - 100), &view, &me).unwrap();
    let reviewed = review(&dusty, &view).unwrap();
    assert!(
        reviewed.warnings().iter().any(|w| w.code == "DUST_CHANGE"),
        "{:?}",
        reviewed.warnings()
    );

    // A payment that is about to expire.
    let short = plan(
        &OperationRequest::Payment(PaymentRequest::new([9; 32], 10_000).with_validity_blocks(2)),
        &view,
        &me,
    )
    .unwrap();
    assert!(
        review(&short, &view)
            .unwrap()
            .warnings()
            .iter()
            .any(|w| w.code == "EXPIRES_SOON")
    );

    // A signature that does not verify is a danger, never "provided".
    let mut transfer = Transfer::decode(&probe.objects()[0].bytes).unwrap();
    transfer.inputs[0].signature.ed448[0] = 1;
    transfer.inputs[0].signature.fndsa[0] = 0x3a;
    let shown = explain(&transfer.encode().unwrap(), &view, &me).unwrap();
    assert!(
        shown
            .warnings()
            .iter()
            .any(|w| w.code == "BAD_SIGNATURE" && w.severity == Severity::Danger)
    );
    assert!(
        shown
            .authorizations()
            .iter()
            .all(|r| r.status == RequirementStatus::ThisWallet)
    );
}

/// The pinned text of the whole review for the standard scenario. A deliberate change of the
/// rendering or of any review content must update this snapshot in the same commit.
const GOLDEN: &str = include_str!("golden/payment_review.txt");

#[test]
fn golden_text_snapshot() {
    let (world, _me, planned, _) = scenario();
    let text = review(&planned, &world.view()).unwrap().render_text();
    assert!(
        text == GOLDEN,
        "review text differs from tests/golden/payment_review.txt; if the change is deliberate, replace the file with:
{text}"
    );
}

#[test]
fn every_truncation_and_extension_of_the_unsigned_bytes_is_refused_without_a_panic() {
    let (world, me, planned, _) = scenario();
    let view = world.view();
    let bytes = planned.objects()[0].bytes.clone();
    for cut in 0..bytes.len() {
        assert_eq!(
            explain(&bytes[..cut], &view, &me).unwrap_err(),
            Refusal::UnknownOperation,
            "prefix of {cut} bytes"
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
    // Garbage of assorted sizes and shapes.
    for size in [0usize, 1, 2, 3, 9, 64, 1000, 20_000] {
        for fill in [0x00u8, 0xff, 0x55, 0x9f] {
            let garbage = vec![fill; size];
            assert!(explain(&garbage, &view, &me).is_err());
            assert!(adopt(&garbage, &view, &me).is_err());
        }
    }
}
