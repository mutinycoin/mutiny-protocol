//! Review completeness for dividend claims: every row the person must read is present (License,
//! award, share, remaining before and after, claims so far and the sequence signed, amount,
//! destination with the typed check, no fee, deadline epoch and the time left as an upper bound,
//! validity heights, License status, the stale-owner risk and the epoch basis), no field or byte of
//! the unsigned claim can change unnoticed, and the text rendering is pinned by a golden snapshot.
//! Also: hostile decoding of every imported claim object, `Debug` without secrets, and randomised
//! properties of amounts, sequences, validity windows and award-window edges.
//! NATIVE, TEST-VALUE; public test keys only; synthetic state built through public consensus APIs.
#[path = "support/dividend_world.rs"]
mod dividend_world;
#[path = "support/flow.rs"]
mod flow;

use dividend_world::*;
use mutiny_consensus_v8::{
    NETWORK_ID,
    dividend_claim_v1::{ClaimError, SignedClaim},
};
use mutiny_wallet_core_v8::{
    discovery::{
        dividends::{self as entitlements, Claimability},
        licenses,
    },
    *,
};
use std::collections::BTreeSet;

const TREASURY: u64 = 1_200_000;
const SHARE: u64 = 200_000;

fn recipient() -> [u8; 32] {
    address(&other_key(), 1)
}

fn op(request: DividendClaimRequest) -> OperationRequest {
    OperationRequest::DividendClaim(request)
}

/// The owner (key A) claims 12,345 atoms of License 1's 200,000 share for another wallet, at head
/// 100 in epoch P + 10.
fn scenario() -> (ClaimWorld, SignerIdentity, OperationPlan) {
    let world = ClaimWorld::new(3, TREASURY);
    let me = identity(&owner_key());
    let planned = plan(
        &op(DividendClaimRequest::new(
            license_id(1),
            P,
            12_345,
            recipient(),
        )),
        &world.view(),
        &me,
    )
    .unwrap();
    (world, me, planned)
}

fn rows_of(review: &Review, section: Section) -> Vec<Row> {
    review
        .rows()
        .into_iter()
        .filter(|row| row.section == section)
        .collect()
}

fn row<'a>(rows: &'a [Row], label: &str) -> &'a Row {
    rows.iter()
        .find(|row| row.label == label)
        .unwrap_or_else(|| panic!("no row {label:?}"))
}

/// What a person READS: every row except the binding digest (which changes with any byte).
fn read(review: &Review) -> Vec<Row> {
    review
        .rows()
        .into_iter()
        .filter(|row| row.section != Section::Binding)
        .collect()
}

#[test]
fn a_claim_review_shows_every_row_a_person_must_read() {
    let (world, _me, planned) = scenario();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    let license = license_id(1);
    let owner = address(&owner_key(), 1);

    assert_eq!(reviewed.kind(), OperationKind::DividendClaim);
    assert_eq!(reviewed.title(), "Claim a dividend");
    // Money: destination with the typed check, amount, no fee, nothing leaves the wallet.
    let money = rows_of(&reviewed, Section::Money);
    let pays = row(&money, "The protocol pays");
    assert!(pays.value.contains(&hex::encode(recipient())));
    assert!(pays.value.contains("an external address"));
    assert_eq!(pays.emphasis, Emphasis::Important);
    assert_eq!(
        row(&money, "Type to confirm destination").value,
        reviewed.destination_check_text(0)
    );
    assert_eq!(
        row(&money, "Amount").value,
        "0.00012345 MUT (12345 STRIKES)"
    );
    let fee = &row(&money, "Network fee").value;
    assert!(fee.starts_with("0.00000000 MUT (0 STRIKES)"), "{fee}");
    assert!(
        fee.contains("exempt") && fee.contains("paid by nobody"),
        "{fee}"
    );
    assert_eq!(
        row(&money, "Total leaving this wallet").value,
        "0.00000000 MUT"
    );
    assert!(money.iter().all(|r| !r.label.starts_with("Input")));

    // Conditions: License, status, award, entitlement before and after, the sequence, the epoch
    // basis, the time left, the owner rule, the payment source, the key and the window.
    let conditions = rows_of(&reviewed, Section::Conditions);
    let text = |label: &str| row(&conditions, label).value.clone();
    assert!(text("License").contains(&hex::encode(license)));
    assert!(text("License").contains("index 1"));
    assert!(text("License").contains(&address_format::encode_for(&owner, &view)));
    assert!(text("License").contains("License generation 1"));
    assert!(text("License status").starts_with("active at the processed epoch 131072"));
    assert!(text("License status").contains("Genesis bootstrap License"));
    assert!(text("Award").contains("Award of epoch 131072"));
    assert!(text("Award").contains("share 0.00200000 MUT (200000 STRIKES)"));
    assert!(text("Award").contains("from 131072 to 196607"));
    assert!(text("Entitlement").contains("Remaining before this claim: 0.00200000 MUT"));
    assert!(text("Entitlement").contains("After it: 0.00187655 MUT"));
    assert!(text("Entitlement").contains("Claims already applied: 0"));
    assert!(text("Claim sequence").contains("This claim carries sequence 0"));
    assert!(text("Epoch basis").contains("The verified block is in epoch 131082"));
    assert!(text("Epoch basis").contains("Not valid in a block whose epoch is before 131072"));
    assert!(text("Time left").starts_with("At most 65526 epochs"));
    assert!(text("Time left").contains("approximate"));
    assert!(text("Time left").contains("the real margin can be shorter"));
    assert!(text("Owner at inclusion").contains("If the License is sold first"));
    assert!(text("Payment source").starts_with("No fee."));
    assert!(text("Payment source").contains("1 coin(s) worth 0.01200000 MUT"));
    assert!(text("Claim key").contains(&address_format::encode_for(&owner, &view)));
    assert!(text("Validity window").starts_with("Valid only for blocks 101 to 245"));

    // Timing: heights, and the deadline epoch.
    let timing = rows_of(&reviewed, Section::Timing);
    assert_eq!(row(&timing, "Valid from block").value, "101");
    assert!(
        row(&timing, "Valid until block")
            .value
            .starts_with("245 (145 blocks")
    );
    assert_eq!(
        row(&timing, "Deadline epoch").value,
        (P + W - 1).to_string()
    );
    assert_eq!(reviewed.timing().deadline_epoch, Some(P + W - 1));

    // Effects: the payout, the entitlement change and "cannot be revoked" are irreversible.
    let effects = rows_of(&reviewed, Section::Effects);
    let irreversible: Vec<&Row> = effects
        .iter()
        .filter(|r| r.emphasis == Emphasis::Irreversible)
        .collect();
    assert_eq!(irreversible.len(), 3);
    assert!(
        irreversible
            .iter()
            .any(|r| r.value.contains("there is no recall"))
    );
    assert!(irreversible.iter().any(|r| {
        r.value
            .contains("falls from 0.00200000 MUT to 0.00187655 MUT")
    }));
    assert!(
        irreversible
            .iter()
            .any(|r| r.value.contains("cannot be revoked"))
    );
    assert!(effects.iter().any(|r| {
        r.value
            .contains("Treasury reserve falls from 0.00600000 MUT to 0.00587655 MUT")
    }));

    // Parties and authorizations.
    let roles: Vec<(PartyRole, AddressLabel)> = reviewed
        .parties()
        .iter()
        .map(|p| (p.role, p.label))
        .collect();
    assert_eq!(
        roles,
        [
            (PartyRole::Owner, AddressLabel::ThisWallet),
            (PartyRole::Treasury, AddressLabel::Treasury),
            (PartyRole::Recipient, AddressLabel::External)
        ]
    );
    assert_eq!(
        reviewed.authorizations(),
        &[Requirement {
            slot: Slot::Claim,
            signer: RequiredSigner::Wallet(owner),
            status: RequirementStatus::ThisWallet,
        }]
    );
    let auth = rows_of(&reviewed, Section::Authorizations);
    assert_eq!(auth.len(), 1);
    assert_eq!(auth[0].label, "The claim signature");
    assert!(auth[0].value.starts_with("this wallet signs"));

    // Warnings and acknowledgements.
    let codes: Vec<&str> = reviewed.warnings().iter().map(|w| w.code).collect();
    assert_eq!(codes, ["TEST_VALUE_CHAIN", "DESTINATION_NOT_OWNER"]);
    assert_eq!(reviewed.warnings()[1].severity, Severity::Caution);
    assert_eq!(
        reviewed.acknowledgements(),
        &[
            AckKind::Destination,
            AckKind::Amount,
            AckKind::Conditions,
            AckKind::Irreversible
        ]
    );
    assert!(
        !reviewed.requires_phrase(),
        "a claim is not among the highest-risk operations"
    );
    assert_eq!(
        rows_of(&reviewed, Section::Binding)[0].value,
        reviewed.binding().to_hex()
    );
}

#[test]
fn every_row_is_filled_and_sections_appear_in_display_order() {
    let (world, _me, planned) = scenario();
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
    assert!(text.lines().all(|line| !line.ends_with(' ')));
    assert!(!text.contains('\r'));
    assert_eq!(text, reviewed.render_text(), "rendering is deterministic");
}

#[test]
fn the_destination_check_and_owner_warnings_follow_the_address() {
    let world = ClaimWorld::new(3, TREASURY);
    let me = identity(&owner_key());
    let view = world.view();
    let reviewed = |destination: [u8; 32]| {
        review(
            &plan(
                &op(DividendClaimRequest::new(
                    license_id(1),
                    P,
                    1_000,
                    destination,
                )),
                &view,
                &me,
            )
            .unwrap(),
            &view,
        )
        .unwrap()
    };
    // The License owner's own address: no typed check, no owner warning.
    let own = reviewed(address(&owner_key(), 1));
    assert!(own.destinations_needing_check().is_empty());
    assert!(!own.acknowledgements().contains(&AckKind::Destination));
    assert!(
        !own.warnings()
            .iter()
            .any(|w| w.code == "DESTINATION_NOT_OWNER")
    );
    // The Treasury: checked, flagged twice.
    let treasury = reviewed(address(&treasury_key(), 1));
    assert_eq!(treasury.destinations()[0].label, AddressLabel::Treasury);
    assert_eq!(treasury.destinations_needing_check(), vec![0]);
    assert!(
        treasury
            .warnings()
            .iter()
            .any(|w| w.code == "TREASURY_DESTINATION")
    );
    assert!(
        treasury
            .warnings()
            .iter()
            .any(|w| w.code == "DESTINATION_NOT_OWNER" && w.severity == Severity::Caution)
    );
    // Another address of THIS wallet (after a rotation): no typed check, but a notice that it is
    // not the License owner address.
    let mut rotated_world = ClaimWorld::new(3, TREASURY);
    rotated_world.rotate_owner();
    let rotated = SignerIdentity::new(
        &descriptor(&rotated_key(), 2),
        Some(address(&owner_key(), 1)),
    )
    .unwrap();
    let rotated_view = rotated_world.view();
    let other_own = review(
        &plan(
            &op(DividendClaimRequest::new(
                license_id(1),
                P,
                1_000,
                rotated.address(),
            )),
            &rotated_view,
            &rotated,
        )
        .unwrap(),
        &rotated_view,
    )
    .unwrap();
    assert!(other_own.destinations_needing_check().is_empty());
    assert!(
        other_own
            .warnings()
            .iter()
            .any(|w| w.code == "DESTINATION_NOT_OWNER" && w.severity == Severity::Notice)
    );
    // The whole remainder is flagged.
    let all = reviewed(recipient());
    assert!(!all.warnings().iter().any(|w| w.code == "FULL_CLAIM"));
    let full = review(
        &plan(
            &op(DividendClaimRequest::new(
                license_id(1),
                P,
                SHARE,
                recipient(),
            )),
            &view,
            &me,
        )
        .unwrap(),
        &view,
    )
    .unwrap();
    assert!(full.warnings().iter().any(|w| w.code == "FULL_CLAIM"));
}

#[test]
fn each_field_of_the_claim_shows_up_in_the_review_or_is_refused() {
    let (world, me, planned) = scenario();
    let view = world.view();
    let base = SignedClaim::decode(&planned.objects()[0].bytes).unwrap();
    let base_rows = read(&review(&planned, &view).unwrap());
    let show = |claim: &SignedClaim| explain(&claim.encode(), &view, &me);
    let mutate = |edit: &dyn Fn(&mut SignedClaim)| {
        let mut claim = base.clone();
        edit(&mut claim);
        claim
    };

    // Destination.
    let changed = show(&mutate(&|c| {
        c.body.destination = address(&treasury_key(), 1)
    }))
    .unwrap();
    assert!(
        changed
            .render_text()
            .contains(&hex::encode(address(&treasury_key(), 1)))
    );
    assert!(!changed.render_text().contains(&hex::encode(recipient())));
    // Amount.
    let changed = show(&mutate(&|c| c.body.amount += 1)).unwrap();
    assert_eq!(changed.amount(), Some(12_346));
    assert_ne!(read(&changed), base_rows);
    // License.
    let changed = show(&mutate(&|c| c.body.license = license_id(2))).unwrap();
    assert!(changed.render_text().contains(&hex::encode(license_id(2))));
    // Validity window.
    let changed = show(&mutate(&|c| c.body.expiry_height -= 50)).unwrap();
    assert_eq!(changed.timing().expiry_height, Some(195));
    let changed = show(&mutate(&|c| c.body.created_height -= 1)).unwrap();
    assert_eq!(changed.timing().created_height, Some(100));
    // Fields consensus would reject outright are refused, never shown as something else.
    let refused: Vec<(&str, SignedClaim, Refusal)> = vec![
        (
            "award",
            mutate(&|c| c.body.award_epoch += P),
            Refusal::AwardNotYetOpen {
                award_epoch: 2 * P,
                head_epoch: P + 10,
            },
        ),
        (
            "sequence",
            mutate(&|c| c.body.sequence += 1),
            Refusal::WrongSequence { expected: 0 },
        ),
        (
            "network",
            mutate(&|c| c.body.network = NETWORK_ID ^ 1),
            Refusal::WrongContext(ContextField::Network),
        ),
        (
            "genesis",
            mutate(&|c| c.body.genesis[0] ^= 1),
            Refusal::WrongContext(ContextField::Genesis),
        ),
        (
            "fingerprint",
            mutate(&|c| c.body.fingerprint[0] ^= 1),
            Refusal::WrongContext(ContextField::Fingerprint),
        ),
        (
            "key",
            mutate(&|c| c.descriptor = descriptor(&other_key(), 1)),
            Refusal::NotRequiredSigner(Slot::Claim),
        ),
    ];
    for (name, claim, expected) in refused {
        assert_eq!(show(&claim).unwrap_err(), expected, "{name}");
    }
}

#[test]
fn no_byte_of_the_unsigned_claim_can_change_without_the_review_noticing() {
    let (world, me, planned) = scenario();
    let view = world.view();
    let base = review(&planned, &view).unwrap();
    let base_rows = read(&base);
    let bytes = planned.objects()[0].bytes.clone();
    let (mut refused, mut visible) = (0usize, 0usize);
    for index in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[index] ^= 0x01;
        match explain(&changed, &view, &me) {
            Err(_) => refused += 1,
            Ok(other) => {
                assert_ne!(
                    read(&other),
                    base_rows,
                    "byte {index} changed the claim but nothing a person reads"
                );
                if other.binding() == base.binding() {
                    // Only a byte of the signature placeholder keeps the unsigned form: it must
                    // show as a signature that does not verify.
                    assert!(
                        other.warnings().iter().any(|w| w.code == "BAD_SIGNATURE"),
                        "byte {index}"
                    );
                }
                visible += 1;
            }
        }
    }
    assert!(
        refused > 0 && visible > 0,
        "refused {refused}, visible {visible}"
    );
    assert_eq!(refused + visible, bytes.len());
}

#[test]
fn a_signed_claim_explains_to_the_same_digest_and_a_bad_signature_is_a_danger() {
    let (world, me, planned) = scenario();
    let view = world.view();
    let digest = review(&planned, &view).unwrap().binding();
    let unsigned = planned.objects()[0].bytes.clone();
    let signer = KeySigner::for_test(owner_key()).unwrap();
    let signed = flow::sign(planned, &signer, &view).unwrap();
    // Signed bytes are not a proposal: nothing is left for this wallet to sign.
    assert_eq!(
        adopt(signed.bytes(), &view, &me).unwrap_err(),
        Refusal::Malformed("these bytes are already signed: there is nothing left to sign")
    );
    // An unsigned claim can be neither imported nor queued.
    assert_eq!(
        SignedOperation::import(&unsigned, &view).unwrap_err(),
        Refusal::Malformed("a dividend claim must be signed to be queued")
    );
    let shown = explain(signed.bytes(), &view, &me).unwrap();
    assert_eq!(
        shown.binding(),
        digest,
        "the digest binds the unsigned form"
    );
    assert_eq!(
        shown.authorizations()[0].status,
        RequirementStatus::Provided
    );
    assert!(!shown.warnings().iter().any(|w| w.code == "BAD_SIGNATURE"));

    let mut damaged = signed.bytes().to_vec();
    let at = damaged.len() - 3;
    damaged[at] ^= 0x40;
    let shown = explain(&damaged, &view, &me).unwrap();
    assert!(
        shown
            .warnings()
            .iter()
            .any(|w| w.code == "BAD_SIGNATURE" && w.severity == Severity::Danger)
    );
    assert_eq!(
        shown.authorizations()[0].status,
        RequirementStatus::ThisWallet
    );
    assert_eq!(
        SignedOperation::import(&damaged, &view).unwrap_err(),
        Refusal::VerificationFailed("the claim signature does not verify")
    );

    // Seen by another wallet: described as somebody else's claim it cannot sign.
    let stranger = identity(&other_key());
    let seen = explain(signed.bytes(), &view, &stranger).unwrap();
    assert_eq!(seen.title(), "Dividend claim by another wallet");
    assert!(seen.warnings().iter().any(|w| w.code == "NOT_THIS_WALLET"));
    assert_eq!(seen.parties()[0].label, AddressLabel::External);
    let unsigned = explain(
        &SignedClaim {
            signature: mutiny_crypto_v2::HybridSignature {
                ed448: [0; 114],
                fndsa: [0; 1280],
            },
            ..SignedClaim::decode(signed.bytes()).unwrap()
        }
        .encode(),
        &view,
        &stranger,
    )
    .unwrap();
    assert_eq!(
        unsigned.authorizations()[0].status,
        RequirementStatus::Counterparty
    );
}

/// The pinned text of the whole review for the standard scenario. A deliberate change of the
/// rendering or of any review content must update this snapshot in the same commit.
const GOLDEN: &str = include_str!("golden/dividend_review.txt");

#[test]
fn golden_text_snapshot() {
    let (world, _me, planned) = scenario();
    let text = review(&planned, &world.view()).unwrap().render_text();
    assert!(
        text == GOLDEN,
        "review text differs from tests/golden/dividend_review.txt; if the change is deliberate, replace the file with the text between the markers:\nBEGIN-GOLDEN\n{text}END-GOLDEN"
    );
}

// ---------------------------------------------------------------------------------------------
// Hostile decoding
// ---------------------------------------------------------------------------------------------

#[test]
fn every_truncation_extension_and_garbage_of_the_unsigned_claim_is_refused() {
    let (world, me, planned) = scenario();
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
    for size in [0usize, 1, 5, 64, 3_000, 20_000] {
        for fill in [0x00u8, 0xff, 0x85, 0x02] {
            let garbage = vec![fill; size];
            assert!(explain(&garbage, &view, &me).is_err());
            assert!(adopt(&garbage, &view, &me).is_err());
        }
    }
    // The claim's own envelope with another operation kind is not a claim.
    let mut other_kind = bytes.clone();
    assert_eq!(other_kind[2], 23, "[2, 23, ...]");
    other_kind[2] = 18;
    assert!(explain(&other_kind, &view, &me).is_err());
}

#[test]
fn every_truncation_and_every_flipped_bit_of_a_signed_claim_is_refused() {
    let (world, _me, planned) = scenario();
    let view = world.view();
    let signer = KeySigner::for_test(owner_key()).unwrap();
    let signed = flow::sign(planned, &signer, &view).unwrap();
    let raw = signed.bytes().to_vec();
    assert!(SignedOperation::import(&raw, &view).is_ok(), "control");
    assert!(world.admit(&raw).is_ok(), "control");
    for cut in 0..raw.len() {
        assert!(
            SignedOperation::import(&raw[..cut], &view).is_err(),
            "prefix of {cut} bytes"
        );
        // Consensus agrees: a truncated claim does not decode.
        assert_eq!(
            world.admit(&raw[..cut]),
            Err(ClaimError::Codec),
            "prefix of {cut} bytes"
        );
    }
    // Every bit of the envelope, the body and the start of the descriptor; one bit of every other
    // byte (the descriptor and signature are long and every one of their bits is bound by the
    // hybrid signature).
    for (index, byte) in raw.iter().enumerate() {
        let bits: Vec<u8> = if index < 200 {
            (0..8).collect()
        } else {
            vec![(index % 8) as u8]
        };
        for bit in bits {
            let mut damaged = raw.clone();
            damaged[index] = byte ^ (1 << bit);
            assert!(
                SignedOperation::import(&damaged, &view).is_err(),
                "flip byte {index} bit {bit}"
            );
            // Consensus refuses every one of them too.
            assert!(
                world.admit(&damaged).is_err(),
                "consensus: flip byte {index} bit {bit}"
            );
        }
    }
    let mut longer = raw.clone();
    longer.push(0);
    assert!(SignedOperation::import(&longer, &view).is_err());
    // A claim is never a partial operation, so it has no partial container.
    assert!(PartialApproval::from_signed(&signed, view.context()).is_err());
    // A damaged queued record is an integrity failure, not a reinterpretation.
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&signed, &view).unwrap();
    outbox.corrupt_for_test(&signed.id());
    assert_eq!(outbox.records().unwrap_err(), Refusal::OutboxIntegrity);
}

// ---------------------------------------------------------------------------------------------
// Debug output
// ---------------------------------------------------------------------------------------------

/// The BIP-39 words of the public test phrases; none may ever appear in any output.
const PHRASE_WORDS: [&str; 5] = ["abandon", "zoo", "vote", "legal", "winner"];

fn longest_number_run(text: &str) -> usize {
    let (mut best, mut run) = (0usize, 0usize);
    for token in text
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
    {
        if token.len() <= 3
            && token.bytes().all(|b| b.is_ascii_digit())
            && token.parse::<u16>().is_ok_and(|n| n <= 255)
        {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    best
}

fn longest_hex_run(text: &str) -> usize {
    let (mut best, mut run) = (0usize, 0usize);
    for c in text.chars() {
        if c.is_ascii_hexdigit() && !c.is_ascii_uppercase() {
            run += 1;
            best = best.max(run);
        } else {
            run = 0;
        }
    }
    best
}

#[test]
fn debug_output_of_claim_types_has_no_secret_and_no_byte_dump() {
    let (world, me, planned) = scenario();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    let signer = KeySigner::for_test(owner_key()).unwrap();
    let signed = flow::sign(planned.clone(), &signer, &view).unwrap();
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&signed, &view).unwrap();
    let record = outbox.records().unwrap().remove(0);
    let entitlement = entitlements::entitlement(&view, P, license_id(1)).unwrap();
    let info = licenses::license(view.state(), license_id(1)).unwrap();
    let request =
        DividendClaimRequest::new(license_id(1), P, 1, recipient()).with_validity_blocks(9);
    let shown: Vec<(&str, String)> = vec![
        ("request", format!("{request:?}")),
        ("operation request", format!("{:?}", op(request))),
        ("plan", format!("{planned:?}")),
        ("review", format!("{reviewed:?}")),
        ("signed", format!("{signed:?}")),
        ("record", format!("{record:?}")),
        ("entitlement", format!("{entitlement:?}")),
        ("license", format!("{info:?}")),
        (
            "claimability",
            format!("{:?}", Claimability::Suspended { until: 7 }),
        ),
        ("standing", format!("{:?}", info.standing)),
        ("requirement", format!("{:?}", reviewed.authorizations()[0])),
        ("destination", format!("{:?}", reviewed.destinations()[0])),
        ("party", format!("{:?}", reviewed.parties()[2])),
        ("timing", format!("{:?}", reviewed.timing())),
        ("fee", format!("{:?}", reviewed.fee())),
        ("signer", format!("{signer:?}")),
        ("identity", format!("{me:?}")),
    ];
    for (label, text) in &shown {
        assert!(!text.is_empty(), "{label}");
        for word in PHRASE_WORDS {
            assert!(!text.to_ascii_lowercase().contains(word), "{label}: {word}");
        }
        assert!(
            longest_number_run(text) < 8,
            "{label}: a byte array dump: {text}"
        );
        assert!(
            longest_hex_run(text) < 64,
            "{label}: a full identifier: {text}"
        );
        assert!(text.len() < 2000, "{label}: {} characters", text.len());
    }
    assert!(format!("{signer:?}").contains("<redacted>"));
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
fn random_partial_claims_keep_amounts_and_sequences_exact_and_agree_with_consensus() {
    let mut rng = Rng(0x5eed_d1d0_c1a1_0003);
    let mut world = ClaimWorld::new(3, TREASURY);
    let owner = owner_key();
    let me = identity(&owner);
    let signer = KeySigner::for_test(owner_key()).unwrap();
    let license = license_id(1);
    let (mut remaining, mut claims) = (SHARE, 0u64);
    let mut signed_count = 0;
    for round in 0..60 {
        let roll = rng.below(10);
        let amount = match roll {
            0 => 0,
            1 => remaining + 1 + rng.below(1_000),
            _ => 1 + rng.below(remaining.clamp(1, 30_000)),
        };
        let view = world.view();
        let result = plan(
            &op(DividendClaimRequest::new(license, P, amount, recipient())),
            &view,
            &me,
        );
        let hand = world.hand_claim(&owner, 1, license, P, amount, claims, recipient());
        let consensus = outcome(&world.admit(&hand));
        match result {
            Ok(planned) => {
                assert!(amount > 0 && amount <= remaining, "round {round}");
                assert_eq!(consensus, "Ok", "round {round}");
                let claim = SignedClaim::decode(&planned.objects()[0].bytes).unwrap();
                assert_eq!(
                    claim.body.sequence, claims,
                    "the sequence is the confirmed count"
                );
                let reviewed = review(&planned, &view).unwrap();
                let entitlement = rows_of(&reviewed, Section::Conditions)
                    .into_iter()
                    .find(|r| r.label == "Entitlement")
                    .unwrap()
                    .value;
                assert!(
                    entitlement.contains(&format!(
                        "After it: {}.",
                        units::format_amount(remaining - amount)
                    )),
                    "round {round}: {entitlement}"
                );
                assert_eq!(
                    reviewed.warnings().iter().any(|w| w.code == "FULL_CLAIM"),
                    amount == remaining
                );
                // Sign every third claim and check consensus accepts the wallet's own bytes.
                if round % 3 == 0 {
                    let signed = flow::sign(planned, &signer, &view).unwrap();
                    assert!(world.admit(signed.bytes()).is_ok(), "round {round}");
                    signed_count += 1;
                }
                // Apply it to the confirmed state.
                remaining -= amount;
                claims += 1;
                world.set_account(P, license, remaining, claims);
            }
            Err(refusal) => {
                let expected = if amount == 0 {
                    Refusal::InvalidAmount
                } else {
                    Refusal::Overdrawn { remaining }
                };
                assert_eq!(refusal, expected, "round {round}");
                assert!(
                    agreeing_codes(&consensus).contains(&refusal.code()),
                    "round {round}: {} vs {consensus}",
                    refusal.code()
                );
            }
        }
        if remaining == 0 {
            break;
        }
    }
    assert!(
        claims > 5 && signed_count > 1,
        "claims {claims}, signed {signed_count}"
    );
    let account = world.account(P, &license).unwrap();
    assert_eq!((account.remaining, account.claims), (remaining, claims));
}

#[test]
fn random_validity_windows_and_award_window_edges_are_classified_exactly() {
    let mut rng = Rng(0x0dd5_ea5e_d1d0_0003);
    let owner = owner_key();
    let me = identity(&owner);
    for _ in 0..200 {
        // The request's validity: 1 to 10,080 blocks only.
        let blocks = match rng.below(4) {
            0 => rng.below(3),
            1 => 10_078 + rng.below(6),
            _ => 1 + rng.below(10_080),
        };
        // The head's epoch around both edges of the award window.
        let epoch = match rng.below(3) {
            0 => P - 3 + rng.below(6),
            1 => P + W - 3 + rng.below(6),
            _ => P + rng.below(W),
        };
        let world = ClaimWorld::new(3, TREASURY).at(epoch);
        let view = world.view();
        let request = DividendClaimRequest::new(license_id(2), P, 1_000, recipient())
            .with_validity_blocks(blocks);
        let result = plan(&op(request), &view, &me);
        let consensus = outcome(&world.admit(&world.hand_claim(
            &owner,
            1,
            license_id(2),
            P,
            1_000,
            0,
            recipient(),
        )));
        if blocks == 0 || blocks > 10_080 {
            assert_eq!(result.unwrap_err(), Refusal::InvalidValidity, "{blocks}");
            continue;
        }
        if epoch < P {
            assert_eq!(
                result.unwrap_err(),
                Refusal::AwardNotYetOpen {
                    award_epoch: P,
                    head_epoch: epoch
                }
            );
            assert_eq!(consensus, "Dividend(NotYetClaimable)");
        } else if epoch >= P + W {
            assert_eq!(result.unwrap_err(), Refusal::AwardExpired, "{epoch}");
            assert_eq!(consensus, "Dividend(Expired)");
        } else {
            let planned = result.unwrap();
            assert_eq!(consensus, "Ok");
            assert_eq!(
                planned.validity().expiry - planned.validity().created,
                blocks
            );
            let reviewed = review(&planned, &view).unwrap();
            let left = P + W - epoch;
            let closing = reviewed
                .warnings()
                .iter()
                .any(|w| w.code == "CLAIM_WINDOW_CLOSING");
            let window = planned.validity().expiry - HEIGHT;
            assert_eq!(
                closing,
                left <= ops::dividend::NEAR_DEADLINE_EPOCHS || left <= window,
                "epoch {epoch}, blocks {blocks}"
            );
            let time_left = rows_of(&reviewed, Section::Conditions)
                .into_iter()
                .find(|r| r.label == "Time left")
                .unwrap()
                .value;
            assert!(
                time_left.starts_with(&format!("At most {left} epochs")),
                "{time_left}"
            );
        }
    }
}

#[test]
fn claim_slots_are_distinct_per_award_and_license_and_never_a_coin() {
    let mut rng = Rng(0x5107_5107);
    let mut seen = BTreeSet::new();
    for _ in 0..500 {
        let award = rng.next();
        let mut license = [0u8; 32];
        for chunk in license.chunks_mut(8) {
            chunk.copy_from_slice(&rng.next().to_be_bytes());
        }
        let slot = entitlements::claim_slot(award, &license);
        assert_eq!(slot.index, u32::MAX, "no real output has this index");
        assert_eq!(
            slot,
            entitlements::claim_slot(award, &license),
            "deterministic"
        );
        assert_ne!(slot, entitlements::claim_slot(award ^ 1, &license));
        assert!(seen.insert(slot));
    }
    // The slot is in its own namespace: not the License's, not a resource key of another kind.
    let license = license_id(1);
    assert_ne!(
        entitlements::claim_slot(P, &license),
        resource_key("license", &license)
    );
    assert_ne!(
        entitlements::claim_slot(P, &license),
        resource_key(entitlements::CLAIM_SLOT_NAMESPACE, &license)
    );
}

#[test]
fn the_window_closing_warning_starts_exactly_at_its_thresholds() {
    let owner = owner_key();
    let me = identity(&owner);
    let near = ops::dividend::NEAR_DEADLINE_EPOCHS;
    assert_eq!(near, 1_440);
    // (epochs left after the head's epoch, the claim's validity in blocks, warning expected)
    let cases = [
        (near + 1, 10, false),
        (near, 10, true),
        (12, 10, true),
        (5_002, 5_000, false),
        (5_001, 5_000, true),
    ];
    for (left, blocks, expected) in cases {
        let world = ClaimWorld::new(3, TREASURY).at(P + W - left);
        let view = world.view();
        let planned = plan(
            &op(
                DividendClaimRequest::new(license_id(1), P, 1_000, recipient())
                    .with_validity_blocks(blocks),
            ),
            &view,
            &me,
        )
        .unwrap();
        let reviewed = review(&planned, &view).unwrap();
        let warning = reviewed
            .warnings()
            .iter()
            .find(|w| w.code == "CLAIM_WINDOW_CLOSING");
        assert_eq!(warning.is_some(), expected, "left {left}, blocks {blocks}");
        if let Some(warning) = warning {
            assert_eq!(warning.requires, Some(AckKind::Conditions));
            assert!(warning.text.contains(&format!("at most {left} epochs")));
        }
        assert!(
            rows_of(&reviewed, Section::Conditions)
                .iter()
                .any(|r| r.label == "Time left"
                    && r.value.starts_with(&format!("At most {left} epochs")))
        );
    }
}
