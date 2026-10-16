//! Review completeness for the native wallet-authority rotation (phase 2): the review shows the
//! authority, both generations, both descriptor fingerprints, the new AddressID with its typed
//! re-entry check, the exact irreversible statement, the window, the fee with its size and payer, the
//! funding coins, the restore-check status and the chain class; no byte and no field of the unsigned
//! rotation or of its funding can change without the review noticing (or the operation being
//! refused); the restore evidence is bound into the digest; hostile bytes are refused without a panic;
//! and no `Debug` output carries a secret of either key. The text rendering is pinned by a golden
//! snapshot. NATIVE, TEST-VALUE; public test keys only (BIP-39 vectors and public labelled-seed keys).
#[path = "support/flow.rs"]
mod flow;
#[path = "support/synthetic.rs"]
mod synthetic;

use flow::approve;
use mutiny_consensus_v8::{
    dividend_state_v1::DividendState,
    funded_rotation_v2::{FundedRotation, PartialRotation, Payer, UnsignedRotation},
    hybrid_transaction_v2::Transaction,
    transactions::{OutPoint, Output},
    transactions_v2::{Input, Transfer},
    treasury_v1::{Class, Treasury},
};
use mutiny_crypto_v2::{HybridKey, PublicKey, Role, rehearsal_keys_v1};
use mutiny_wallet_core_v8::{
    ops::rotation::{self, RotationSigner},
    *,
};
use synthetic::{World, address, descriptor, identity, key_a, key_b, key_c};

/// A public TEST-VALUE key derived from a public label (labelled-seed mode: public by construction).
fn new_key(label: &str) -> HybridKey {
    let phrase = rehearsal_keys_v1::label_phrase(label).unwrap();
    HybridKey::wallet_restore(&phrase, Role::WalletOwner).unwrap()
}

fn rotate(new: &HybridKey, generation: u64, fee: FeeSource) -> OperationRequest {
    let proposed = new.public().descriptor(generation).unwrap();
    OperationRequest::WalletRotation(
        RotationRequest::new(Blob::new(proposed.clone()), fee)
            .with_restore_verified(rotation::descriptor_fingerprint(&proposed)),
    )
}

/// A TEST-VALUE chain at head 100 (its Treasury is key C) where key A (generation one) holds one
/// 5,000,000 atom coin, and the plan that rotates A to the labelled key "w2-review-new" at
/// generation two, funded by A itself.
fn scenario() -> (World, SignerIdentity, OperationPlan, HybridKey) {
    let mut world = World::new(100);
    world
        .state
        .wallets
        .register(&descriptor(&key_c(), 1))
        .unwrap();
    world.state.dividends =
        DividendState::genesis(Treasury::new(Class::TestValue, descriptor(&key_c(), 1)).unwrap());
    world.coin(address(&key_a(), 1), 5_000_000, 1, false, 1, 0);
    let me = identity(&key_a());
    let new = new_key("w2-review-new");
    let planned = plan(
        &rotate(&new, 2, FeeSource::RotatingAuthority),
        &world.view(),
        &me,
    )
    .unwrap();
    (world, me, planned, new)
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
        .find(|r| r.label == label)
        .unwrap_or_else(|| panic!("no row {label:?}"))
}

fn envelope(raw: &[u8]) -> PartialRotation {
    if let Ok(p) = PartialRotation::decode(raw) {
        return p;
    }
    let f = FundedRotation::decode(raw).unwrap();
    PartialRotation {
        unsigned: f.unsigned,
        authorize: Some(f.authorize),
        possession: Some(f.possession),
        authority_funding: f.authority_funding,
        sponsor_funding: f.sponsor_funding,
    }
}
fn encode(u: &UnsignedRotation) -> Vec<u8> {
    PartialRotation::new(u.clone()).encode().unwrap()
}
#[test]
fn a_rotation_review_shows_every_required_row() {
    let (world, me, planned, new) = scenario();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    let authority = address(&key_a(), 1);
    let new_address = new.public().address_id(2).unwrap();
    let size = mutiny_consensus_v8::funded_rotation_v2::signed_len(
        &envelope(&planned.objects()[0].bytes).unsigned,
    )
    .unwrap() as u64;

    // Summary and the chain class banner.
    assert_eq!(reviewed.kind(), OperationKind::WalletRotation);
    assert_eq!(reviewed.title(), "Rotate wallet key");
    let summary = rows_of(&reviewed, Section::Summary);
    assert!(
        summary
            .iter()
            .any(|r| r.label == "Chain class" && r.value.starts_with("TEST-VALUE chain"))
    );
    assert!(
        reviewed
            .warnings()
            .iter()
            .any(|w| w.code == "TEST_VALUE_CHAIN")
    );

    // Authority, generations, fingerprints, new address, restore status, window, fee rule.
    let conditions = rows_of(&reviewed, Section::Conditions);
    assert!(
        row(&conditions, "Wallet authority")
            .value
            .starts_with(&hex::encode(authority))
    );
    assert_eq!(
        row(&conditions, "Key generation").value,
        "from generation 1 (current key) to generation 2 (new key)"
    );
    assert!(
        row(&conditions, "Current key fingerprint")
            .value
            .starts_with(&hex::encode(rotation::descriptor_fingerprint(&descriptor(
                &key_a(),
                1
            ))))
    );
    assert!(
        row(&conditions, "New key fingerprint")
            .value
            .starts_with(&hex::encode(rotation::descriptor_fingerprint(
                &new.public().descriptor(2).unwrap()
            )))
    );
    assert!(
        row(&conditions, "New key address")
            .value
            .starts_with(&hex::encode(new_address))
    );
    assert!(
        row(&conditions, "New key restore check")
            .value
            .starts_with("Verified by this wallet's host before planning")
    );
    assert!(
        row(&conditions, "Validity window")
            .value
            .contains("approximate")
    );
    assert!(
        row(&conditions, "One pending rotation")
            .value
            .contains("Only one rotation")
    );
    assert!(row(&conditions, "Funding").value.contains("OLD key"));
    assert!(
        row(&conditions, "Fee rule")
            .value
            .contains(&format!("{size} bytes, so {size} atoms"))
    );

    // The new AddressID needs the typed re-entry check.
    assert_eq!(reviewed.destinations()[0].address, new_address);
    assert_eq!(reviewed.destinations()[0].label, AddressLabel::NewKey);
    assert_eq!(reviewed.destinations_needing_check(), vec![0]);
    let money = rows_of(&reviewed, Section::Money);
    assert_eq!(
        row(&money, "Type to confirm destination").value,
        mutiny_wallet_core_v8::address_format::encode_for(&new_address, &view)
            .chars()
            .rev()
            .take(8)
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>()
    );
    // Fee with its rule, payer and size; the funding coins.
    let fee_row = row(&money, "Network fee");
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
    assert!(
        fee_row.value.contains(&format!("signed size {size} bytes")),
        "{}",
        fee_row.value
    );
    assert_eq!(reviewed.fee().size_bytes, Some(size));
    assert!(reviewed.fee().atoms >= size);
    assert_eq!(reviewed.fee().payer, FeePayer::ThisWallet);
    assert!(
        row(&money, "Inputs")
            .value
            .starts_with("1 coin(s) worth 0.05000000 MUT")
    );
    assert!(row(&money, "Input 0").value.contains("(this wallet)"));
    assert_eq!(reviewed.amount(), None, "a rotation moves no principal");
    assert_eq!(reviewed.returned() + reviewed.fee().atoms, 5_000_000);
    assert_eq!(reviewed.net_debit(), Some(u128::from(reviewed.fee().atoms)));

    // Timing: heights and the approximate duration, labelled approximate.
    let timing = rows_of(&reviewed, Section::Timing);
    assert_eq!(row(&timing, "Valid from block").value, "101");
    let until = &row(&timing, "Valid until block").value;
    assert!(until.starts_with("245 (145 blocks"), "{until}");
    assert!(until.contains("approximate"), "{until}");

    // The exact irreversible statement, marked irreversible, and the other effects.
    let effects = rows_of(&reviewed, Section::Effects);
    assert!(effects.iter().any(|r| r.emphasis == Emphasis::Irreversible
        && r.label == "Irreversible"
        && r.value == rotation::IRREVERSIBLE_KEY_LOSS));
    assert_eq!(
        rotation::IRREVERSIBLE_KEY_LOSS,
        "the old key loses all spending authority at inclusion; funds are controlled only by the new key; if the new key cannot be restored from its backup the funds are unrecoverable"
    );
    assert!(
        effects
            .iter()
            .any(|r| r.value.starts_with("Old addresses keep their coins"))
    );
    assert!(
        effects
            .iter()
            .any(|r| r.value.starts_with("Pays a network fee"))
    );
    assert!(
        effects
            .iter()
            .any(|r| r.value.contains("cannot be revoked"))
    );

    // Who signs what: current key authorizes and funds; new key proves possession of the identical atomic commitment.
    assert_eq!(
        reviewed
            .authorizations()
            .iter()
            .map(|r| (r.slot, r.status))
            .collect::<Vec<_>>(),
        vec![
            (Slot::RotationAuthorization, RequirementStatus::ThisWallet),
            (Slot::RotationPossession, RequirementStatus::ThisWallet),
            (Slot::Input(0), RequirementStatus::ThisWallet),
        ]
    );
    assert_eq!(
        reviewed.authorizations()[1].signer,
        RequiredSigner::Wallet(new_address)
    );
    assert_eq!(reviewed.parties()[0].role, PartyRole::Owner);
    assert_eq!(reviewed.parties()[0].address, authority);

    // Highest risk: typed phrase, key-loss and conditions acknowledgements; no amount to confirm.
    assert!(reviewed.requires_phrase());
    assert_eq!(
        reviewed.acknowledgements(),
        &[
            AckKind::Destination,
            AckKind::Fee,
            AckKind::Conditions,
            AckKind::Irreversible,
            AckKind::KeyLoss
        ]
    );
    for code in ["KEY_ROTATION", "FUNDING_BOUND"] {
        assert!(reviewed.warnings().iter().any(|w| w.code == code), "{code}");
    }
    assert!(
        !reviewed
            .warnings()
            .iter()
            .any(|w| w.code == "TREASURY_ROTATION" || w.code == "TREASURY_FUNDS")
    );
    assert_eq!(reviewed.signer().address, authority);
    let _ = me;
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
    assert!(text.lines().all(|line| !line.ends_with(' ')));
    assert!(!text.contains('\r'));
    assert_eq!(text, reviewed.render_text());
}

/// The pinned text of the whole rotation review for the standard scenario. A deliberate change of
/// the rendering or of any review content must update this snapshot in the same commit.
const GOLDEN: &str = include_str!("golden/rotation_review.txt");

#[test]
fn golden_text_snapshot() {
    let (world, _me, planned, _) = scenario();
    let text = review(&planned, &world.view()).unwrap().render_text();
    assert!(
        text == GOLDEN,
        "review text differs from tests/golden/rotation_review.txt; if the change is deliberate, replace the file with:
{text}"
    );
}

#[test]
fn the_restore_evidence_is_a_bound_object_of_the_plan() {
    let (world, _me, planned, new) = scenario();
    let view = world.view();
    let proposed = new.public().descriptor(2).unwrap();
    let fingerprint = rotation::descriptor_fingerprint(&proposed);
    assert_eq!(planned.objects().len(), 2);
    assert_eq!(planned.objects()[0].label, rotation::OBJECT_LABEL);
    assert_eq!(
        planned.objects()[1],
        rotation::restore_evidence(&fingerprint)
    );
    // The digest an approval binds covers the evidence object: another fingerprint in it gives
    // another digest (and so another confirmation phrase).
    let reviewed = review(&planned, &view).unwrap();
    assert_eq!(
        reviewed.binding(),
        binding_digest(
            OperationKind::WalletRotation,
            rotation::SCHEMA,
            planned.objects(),
            view.anchor(),
            &view.state_root()
        )
    );
    let mut other = planned.objects().to_vec();
    other[1] = rotation::restore_evidence(&[0x11; 32]);
    assert_ne!(
        reviewed.binding(),
        binding_digest(
            OperationKind::WalletRotation,
            rotation::SCHEMA,
            &other,
            view.anchor(),
            &view.state_root()
        )
    );
    // Bytes explained elsewhere bind the same objects, so a counterparty's digest is the same.
    let seen = explain(&planned.objects()[0].bytes, &view, &identity(&key_b())).unwrap();
    assert_eq!(seen.binding(), reviewed.binding());
}

/// What a person READS: every row except the binding digest.
fn read(review: &Review) -> Vec<Row> {
    review
        .rows()
        .into_iter()
        .filter(|row| row.section != Section::Binding)
        .collect()
}

#[test]
fn no_byte_of_the_unsigned_rotation_can_change_without_the_review_noticing() {
    let (world, me, planned, _) = scenario();
    let view = world.view();
    let bytes = planned.objects()[0].bytes.clone();
    let base = explain(&bytes, &view, &me).unwrap();
    let base_rows = read(&base);
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
                    "byte {index} changed the rotation but nothing a person reads"
                );
                if other.binding() == base.binding() {
                    // Only a signature placeholder keeps the unsigned form: it must show up as a
                    // signature that does not verify.
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
fn each_field_of_the_atomic_rotation_and_its_funding_shows_up_or_is_refused() {
    let (world, me, planned, new) = scenario();
    let view = world.view();
    let original = envelope(&planned.objects()[0].bytes).unsigned;
    let base = explain(&planned.objects()[0].bytes, &view, &me).unwrap();
    let assert_visible = |label: &str, u: UnsignedRotation| match PartialRotation::new(u)
        .encode()
        .ok()
        .and_then(|raw| explain(&raw, &view, &me).ok())
    {
        None => (),
        Some(changed) => {
            assert_ne!(changed.binding(), base.binding(), "{label}");
            assert_ne!(
                read(&changed),
                read(&base),
                "{label} changes reviewed commitment but nothing the person reads"
            );
        }
    };
    let other = new_key("w2-review-other-new");
    let mut u = original.clone();
    u.proposed_descriptor = other.public().descriptor(2).unwrap();
    u.outputs[0].owner = other.public().address_id(2).unwrap();
    let changed = explain(&encode(&u), &view, &me).unwrap();
    assert!(
        changed
            .render_text()
            .contains(&hex::encode(other.public().address_id(2).unwrap()))
    );
    assert!(
        changed
            .render_text()
            .contains(&hex::encode(rotation::descriptor_fingerprint(
                &u.proposed_descriptor
            )))
    );
    assert_ne!(changed.binding(), base.binding());
    let mut u = original.clone();
    u.proposed_descriptor = other.public().descriptor(2).unwrap();
    assert_visible("proposed descriptor", u);
    let mut u = original.clone();
    u.authority = address(&key_b(), 1);
    assert!(explain(&encode(&u), &view, &me).is_err());
    let mut u = original.clone();
    u.current_descriptor = descriptor(&key_b(), 1);
    assert!(explain(&encode(&u), &view, &me).is_err());
    for (name, edit) in [
        ("first height", 0),
        ("last height", 1),
        ("reference height", 2),
        ("reference block", 3),
        ("genesis", 4),
        ("fingerprint", 5),
        ("fee and change", 6),
        ("input", 7),
        ("payer tag", 8),
        ("sponsor", 9),
        ("destination", 10),
        ("output amount", 11),
    ] {
        let mut u = original.clone();
        match edit {
            0 => u.envelope.first_height += 1,
            1 => u.envelope.last_height -= 1,
            2 => u.envelope.reference_height -= 1,
            3 => u.envelope.reference_block[0] ^= 1,
            4 => u.genesis[0] ^= 1,
            5 => u.fingerprint[0] ^= 1,
            6 => {
                u.fee += 9;
                u.outputs[0].atoms -= 9;
            }
            7 => u.inputs[0].0.transaction[0] ^= 1,
            8 => u.inputs[0].1 = Payer::Sponsor,
            9 => u.sponsor = Some((address(&key_b(), 1), descriptor(&key_b(), 1))),
            10 => u.outputs[0].owner = address(&key_b(), 1),
            11 => u.outputs[0].atoms -= 1,
            _ => unreachable!(),
        }
        assert_visible(name, u);
    }
    let mut leaky = original.clone();
    leaky.outputs[0].atoms -= 1;
    assert_eq!(
        explain(&encode(&leaky), &view, &me).unwrap_err(),
        Refusal::Conservation
    );
    let mut foreign = original.clone();
    foreign.outputs[0].owner = address(&key_b(), 1);
    assert_eq!(
        explain(&encode(&foreign), &view, &me).unwrap_err(),
        Refusal::RotationFunding(rotation::REASON_OUTPUT_NOT_FUNDER)
    );
    let mut split = original.clone();
    split.outputs[0].atoms -= 1000;
    split.outputs.push(Output {
        owner: address(&key_c(), 1),
        atoms: 1000,
    });
    assert!(explain(&encode(&split), &view, &me).is_err());
    let mut two = World::new(100);
    two.state = world.state.clone();
    let point = two.coin(address(&key_a(), 1), 3_000_000, 1, false, 2, 0);
    let mut multiple = original.clone();
    multiple.inputs.push((point, Payer::RotatingAuthority));
    multiple.inputs.sort();
    multiple.fee += 3500;
    multiple.outputs[0].atoms += 3_000_000 - 3500;
    let changed = explain(&encode(&multiple), &two.view(), &me).unwrap();
    assert_eq!(changed.inputs().len(), 2);
    assert!(changed.render_text().contains("Input 1"));
    assert_eq!(
        new.public().descriptor(2).unwrap(),
        original.proposed_descriptor
    );
}

#[test]
fn the_payer_and_an_observer_read_the_same_digest_with_their_own_rows() {
    let mut world = World::new(100);
    world.coin(address(&key_b(), 1), 3_000_000, 1, false, 2, 0);
    let view = world.view();
    let me = identity(&key_a());
    let payer = identity(&key_b());
    let new = new_key("w2-review-payer-new");
    let planned = plan(
        &rotate(&new, 2, FeeSource::OtherWallet(payer.clone())),
        &view,
        &me,
    )
    .unwrap();
    let own = review(&planned, &view).unwrap();
    // The rotating wallet: nothing of its own leaves, the payer's change is not its destination.
    assert_eq!(
        own.fee().payer,
        FeePayer::Counterparty(address(&key_b(), 1))
    );
    assert_eq!(own.net_debit(), Some(0));
    assert_eq!(own.destinations().len(), 1, "only the new key's address");
    assert_eq!(own.destinations()[0].atoms, 0);
    assert!(
        own.warnings()
            .iter()
            .any(|w| w.code == "COUNTERPARTY_FUNDED")
    );
    assert!(
        own.effects()
            .iter()
            .any(|e| e.text.starts_with("Returns") && e.text.contains("to the fee payer"))
    );
    assert_eq!(
        own.authorizations()[2].status,
        RequirementStatus::Counterparty
    );

    // The payer: the same digest, a fee to pay, its own change, no typed check, no phrase.
    let as_payer = explain(&planned.objects()[0].bytes, &view, &payer).unwrap();
    assert_eq!(as_payer.binding(), own.binding());
    assert_eq!(as_payer.title(), "Pay the fee of a wallet key rotation");
    assert_eq!(as_payer.fee().payer, FeePayer::ThisWallet);
    assert_eq!(as_payer.net_debit(), Some(u128::from(as_payer.fee().atoms)));
    assert!(as_payer.destinations_needing_check().is_empty());
    assert!(!as_payer.requires_phrase());
    assert!(
        as_payer
            .warnings()
            .iter()
            .any(|w| w.code == "FUNDING_BOUND" && w.text.contains("atomic"))
    );
    assert!(
        as_payer
            .warnings()
            .iter()
            .any(|w| w.code == "ROTATION_OF_ANOTHER_WALLET")
    );
    assert!(as_payer.conditions().iter().any(|c| {
        c.label == "New key restore check"
            && c.detail
                .starts_with("Asserted by the rotating wallet's host")
    }));
    assert!(
        !as_payer
            .effects()
            .iter()
            .any(|e| e.text == rotation::IRREVERSIBLE_KEY_LOSS),
        "the payer's key does not change"
    );

    // An uninvolved wallet signs nothing.
    let observer = explain(&planned.objects()[0].bytes, &view, &identity(&key_c())).unwrap();
    assert_eq!(observer.binding(), own.binding());
    assert_eq!(observer.title(), "Key rotation of another wallet");
    assert!(
        observer
            .authorizations()
            .iter()
            .all(|r| r.status == RequirementStatus::Counterparty)
    );
}

#[test]
fn hostile_bytes_are_refused_without_a_panic() {
    let (world, me, planned, new) = scenario();
    let view = world.view();
    let payer = identity(&key_b());
    let bytes = planned.objects()[0].bytes.clone();
    for cut in 0..bytes.len() {
        let prefix = &bytes[..cut];
        assert_eq!(
            explain(prefix, &view, &me).unwrap_err(),
            Refusal::UnknownOperation,
            "prefix of {cut} bytes"
        );
        assert!(adopt(prefix, &view, &payer).is_err());
        assert!(SignedOperation::import(prefix, &view).is_err());
    }
    for extra in [1usize, 2, 17, 4096] {
        let mut longer = bytes.clone();
        longer.extend(std::iter::repeat_n(0u8, extra));
        assert!(
            explain(&longer, &view, &me).is_err(),
            "{extra} trailing bytes"
        );
        assert!(adopt(&longer, &view, &payer).is_err());
        assert!(SignedOperation::import(&longer, &view).is_err());
    }
    for size in [0usize, 1, 9, 64, 1000, 20_000] {
        for fill in [0x00u8, 0xff, 0x84, 0x9f] {
            let garbage = vec![fill; size];
            assert!(explain(&garbage, &view, &me).is_err());
            assert!(adopt(&garbage, &view, &payer).is_err());
        }
    }
    // Canonical unsigned native bytes may be retained as a PARTIAL operation. Import must
    // derive the missing approvals; it must never claim a complete or executable transaction.
    let imported = SignedOperation::import(&bytes, &view).unwrap();
    assert!(!imported.is_complete());
    assert_eq!(imported.missing().len(), 3);
    assert_eq!(imported.bytes(), bytes);
    assert!(FundedRotation::decode(imported.bytes()).is_err());
    // The rotating wallet still cannot adopt someone else's restore assertion.
    assert_eq!(
        adopt(&bytes, &view, &me).unwrap_err(),
        Refusal::InvalidRequest(rotation::REASON_ADOPT_ROTATION)
    );

    // A partial container of a real rotation: every truncation and flipped bit is refused.
    let mut co_funded = World::new(100);
    co_funded.coin(address(&key_b(), 1), 3_000_000, 1, false, 2, 0);
    let view = co_funded.view();
    let planned = plan(
        &rotate(&new, 2, FeeSource::OtherWallet(payer.clone())),
        &view,
        &me,
    )
    .unwrap();
    let reviewed = review(&planned, &view).unwrap();
    let session = RotationSigner::for_test(key_a(), me.clone(), new_key("w2-review-new")).unwrap();
    let partial = session
        .authorize(planned, approve(&reviewed, &view), &view)
        .unwrap();
    assert!(!partial.is_complete());
    let raw = PartialApproval::from_signed(&partial, view.context())
        .unwrap()
        .export()
        .unwrap();
    assert!(PartialApproval::import(&raw).is_ok());
    for cut in (0..raw.len()).step_by(97) {
        assert!(PartialApproval::import(&raw[..cut]).is_err(), "cut {cut}");
    }
    for index in (0..raw.len()).step_by(61) {
        for bit in [0u8, 3, 7] {
            let mut damaged = raw.clone();
            damaged[index] ^= 1 << bit;
            assert!(
                PartialApproval::import(&damaged).is_err(),
                "byte {index} bit {bit}"
            );
        }
    }
    // The operation inside, damaged: refused, or explained as a different rotation (never with the
    // reviewed digest).
    let mut flipped = partial.bytes().to_vec();
    let last = flipped.len() - 1;
    flipped[last] ^= 1;
    match explain(&flipped, &view, &payer) {
        Err(_) => {}
        Ok(other) => assert_ne!(other.binding(), reviewed.binding()),
    }
    // Every truncation of the partially signed bytes is refused by import and by adoption.
    let signed_bytes = partial.bytes().to_vec();
    for cut in (0..signed_bytes.len()).step_by(53) {
        assert!(SignedOperation::import(&signed_bytes[..cut], &view).is_err());
        assert!(adopt(&signed_bytes[..cut], &view, &payer).is_err());
    }
    assert!(SignedOperation::import(&signed_bytes, &view).is_ok());
}

#[test]
fn every_damaged_proposed_descriptor_is_refused_because_the_restore_evidence_binds_its_bytes() {
    let (world, me, _planned, new) = scenario();
    let view = world.view();
    let proposed = new.public().descriptor(2).unwrap();
    let fingerprint = rotation::descriptor_fingerprint(&proposed);
    let with = |descriptor: Vec<u8>| {
        OperationRequest::WalletRotation(
            RotationRequest::new(Blob::new(descriptor), FeeSource::RotatingAuthority)
                .with_restore_verified(fingerprint),
        )
    };
    assert!(plan(&with(proposed.clone()), &view, &me).is_ok());
    for cut in (0..proposed.len()).step_by(29) {
        assert!(
            plan(&with(proposed[..cut].to_vec()), &view, &me).is_err(),
            "cut {cut}"
        );
    }
    let mut longer = proposed.clone();
    longer.push(0);
    assert!(plan(&with(longer), &view, &me).is_err());
    for index in (0..proposed.len()).step_by(13) {
        for bit in [0u8, 5] {
            let mut damaged = proposed.clone();
            damaged[index] ^= 1 << bit;
            // A damaged descriptor is malformed, or another key whose fingerprint was never
            // verified: refused either way, never planned.
            assert!(
                plan(&with(damaged), &view, &me).is_err(),
                "byte {index} bit {bit}"
            );
        }
    }
}

/// What must never appear in any output: the words of the fixed BIP-39 test phrases, and every
/// pair of adjacent words of the labelled phrases (single words of a random phrase are ordinary
/// English words such as "object"; a leaked phrase shows its words in sequence).
fn phrase_markers(labels: &[&str]) -> Vec<String> {
    let mut markers: Vec<String> = ["abandon", "zoo ", "vote", "legal winner", "winner thank"]
        .into_iter()
        .map(String::from)
        .collect();
    for label in labels {
        let phrase = rehearsal_keys_v1::label_phrase(label).unwrap();
        let words: Vec<&str> = phrase.split(' ').collect();
        markers.extend(words.windows(2).map(|pair| pair.join(" ")));
    }
    markers
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
fn no_debug_output_shows_a_secret_of_either_key() {
    let (world, me, planned, _) = scenario();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    let session = RotationSigner::for_test(key_a(), me.clone(), new_key("w2-review-new")).unwrap();
    let approval = approve(&reviewed, &view);
    let approval_text = format!("{approval:?}");
    let signed = session.authorize(planned.clone(), approval, &view).unwrap();
    let request = rotate(
        &new_key("w2-review-new"),
        2,
        FeeSource::OtherWallet(identity(&key_b())),
    );
    let shown: Vec<(&str, String)> = vec![
        ("session", format!("{session:?}")),
        ("approval", approval_text),
        ("plan", format!("{planned:?}")),
        ("review", format!("{reviewed:?}")),
        ("signed", format!("{signed:?}")),
        ("request", format!("{request:?}")),
        ("evidence", format!("{:?}", planned.objects()[1])),
        (
            "refusal",
            format!(
                "{:?}",
                Refusal::RotationKeyReused(rotation::REASON_REUSED_ED448)
            ),
        ),
    ];
    let markers = phrase_markers(&["w2-review-new"]);
    for (label, text) in &shown {
        assert!(!text.is_empty(), "{label}");
        let lower = text.to_ascii_lowercase();
        for marker in &markers {
            assert!(
                !lower.contains(marker.as_str()),
                "{label}: contains phrase words {marker:?}: {text}"
            );
        }
        assert!(
            longest_hex_run(text) < 64,
            "{label}: prints a full identifier: {text}"
        );
        assert!(text.len() < 2000, "{label}: {} characters", text.len());
    }
    assert!(format!("{session:?}").contains("<redacted>"));
    // Locking erases both keys at once; the redaction does not depend on the state.
    session.lock();
    assert!(session.is_locked());
    assert!(format!("{session:?}").contains("<redacted>"));
    // The session's public parts are what the plan rotates to.
    let fresh = RotationSigner::for_test(key_a(), me, new_key("w2-review-new")).unwrap();
    let rotation_plan = envelope(&planned.objects()[0].bytes).unsigned;
    assert_eq!(
        fresh.proposed_descriptor(),
        rotation_plan.proposed_descriptor.as_slice()
    );
    assert_eq!(
        fresh.proposed_address(),
        PublicKey::decode_descriptor(&rotation_plan.proposed_descriptor)
            .unwrap()
            .0
            .address_id(2)
            .unwrap()
    );
}
