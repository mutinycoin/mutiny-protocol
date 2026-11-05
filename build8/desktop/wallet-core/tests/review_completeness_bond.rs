//! Review completeness for bond creation, unbond and withdrawal: immutable principal lot and current-owner change, amount, fee (rule, payer, size), change, conditions, timing with approximate durations,
//! irreversible effects and warnings are all present; no field or byte of the unsigned objects can
//! change without the review noticing or the bytes being refused; golden text snapshots; hostile
//! decoding of every imported object; `Debug` without secrets; and the locked timing arithmetic
//! over random lock-start and notice heights. NATIVE, TEST-VALUE; public keys and fixtures only.
#[path = "support/bond_support.rs"]
mod bond_support;

use bond_support::{
    flow,
    world::{BondWorld, address, descriptor, identity, key_a, key_b, key_c},
};
use mutiny_consensus_v8::{
    Hash,
    bond_create_v3::{FundedBondCreate, PartialBondCreate, UnsignedBondCreate},
    bond_ops_v2::{Action, Operation},
    bonds::{EVIDENCE_HEIGHTS, LOCK_HEIGHTS, LotStatus, MINIMUM_ATOMS, withdrawal_floor},
    transactions::OutPoint,
};
use mutiny_wallet_core_v8::{discovery::bonds as discovery, ops::bond::export_unsigned, *};

const FUNDS: u64 = 30_000_000_000;
const PRINCIPAL: u64 = 15_000_000_000;
const HEAD: u64 = 100;

fn create(node: Hash, nonce: Hash) -> OperationRequest {
    OperationRequest::BondCreate(BondCreateRequest::new(node, 1, PRINCIPAL, nonce))
}
fn unbond(lot: Hash) -> OperationRequest {
    OperationRequest::BondUnbond(BondUnbondRequest::new(lot))
}
fn withdraw(lot: Hash) -> OperationRequest {
    OperationRequest::BondWithdraw(BondWithdrawRequest::new(lot))
}

/// Key A bonds 150 MUT for the fixture node from one 300 MUT coin at head 100.
fn create_scenario() -> (BondWorld, SignerIdentity, OperationPlan) {
    let mut world = BondWorld::new(HEAD);
    world.coin(address(&key_a(), 1), FUNDS, 1, false, 0x31, 0);
    let me = identity(&key_a());
    let planned = plan(&create(world.node(), [0x42; 32]), &world.view(), &me).unwrap();
    (world, me, planned)
}

/// Key A's lot (B = 10) is Active at head 100.
fn unbond_scenario() -> (BondWorld, SignerIdentity, OperationPlan, Hash) {
    let mut world = BondWorld::new(HEAD);
    let lot = world.lot(
        0x51,
        address(&key_a(), 1),
        PRINCIPAL,
        10,
        0,
        None,
        None,
        LotStatus::Active,
    );
    let me = identity(&key_a());
    let planned = plan(&unbond(lot), &world.view(), &me).unwrap();
    (world, me, planned, lot)
}

/// Key A's lot (B = 10, U = 20) is withdrawn at exactly its floor 259,210.
fn withdraw_scenario() -> (BondWorld, SignerIdentity, OperationPlan, Hash) {
    let mut world = BondWorld::new(259_209);
    let lot = world.lot(
        0x51,
        address(&key_a(), 1),
        PRINCIPAL,
        10,
        1,
        Some(20),
        None,
        LotStatus::Unbonding,
    );
    let me = identity(&key_a());
    let planned = plan(&withdraw(lot), &world.view(), &me).unwrap();
    (world, me, planned, lot)
}

/// The unbond and the withdrawal of a lot the TREASURY owns (key A is the TEST-VALUE Genesis
/// Treasury here) are acts of Treasury authority: the review warns `TREASURY_LOT` and requires the
/// `TreasuryAuthority` acknowledgement (fixes of the independent wallet review, additive); an
/// ordinary owner's review has neither.
#[test]
fn a_treasury_owned_lot_is_unbonded_and_withdrawn_with_the_treasury_acknowledgement() {
    use mutiny_consensus_v8::{
        dividend_state_v1::DividendState,
        treasury_v1::{Class, Treasury},
    };
    let treasury_me = identity(&key_a()).with_treasury_roles_for_test(TreasuryRoles {
        authority: true,
        destination_of: None,
    });
    for (head, created, sequence, unbonded, status, request) in [
        (
            HEAD,
            10,
            0,
            None,
            LotStatus::Active,
            unbond as fn(Hash) -> OperationRequest,
        ),
        (259_209, 10, 1, Some(20), LotStatus::Unbonding, withdraw),
    ] {
        let mut world = BondWorld::new(head);
        world
            .state
            .wallets
            .register(&descriptor(&key_a(), 1))
            .unwrap();
        world.state.dividends = DividendState::genesis(
            Treasury::new(Class::TestValue, descriptor(&key_a(), 1)).unwrap(),
        );
        let lot = world.lot(
            0x51,
            address(&key_a(), 1),
            PRINCIPAL,
            created,
            sequence,
            unbonded,
            None,
            status,
        );
        let planned = plan(&request(lot), &world.view(), &treasury_me).unwrap();
        let reviewed = review(&planned, &world.view()).unwrap();
        let warning = reviewed
            .warnings()
            .iter()
            .find(|w| w.code == "TREASURY_LOT")
            .unwrap_or_else(|| panic!("{:?}: no TREASURY_LOT", reviewed.kind()));
        assert_eq!(
            (warning.severity, warning.requires),
            (Severity::Caution, Some(AckKind::TreasuryAuthority))
        );
        assert!(
            warning.text.contains("owned by the Treasury"),
            "{}",
            warning.text
        );
        assert!(
            reviewed
                .acknowledgements()
                .contains(&AckKind::TreasuryAuthority)
        );
    }
    // An ordinary owner's lot: no Treasury warning, no Treasury acknowledgement.
    for (world, _, planned, _) in [unbond_scenario(), withdraw_scenario()] {
        let reviewed = review(&planned, &world.view()).unwrap();
        assert!(reviewed.warnings().iter().all(|w| w.code != "TREASURY_LOT"));
        assert!(
            !reviewed
                .acknowledgements()
                .contains(&AckKind::TreasuryAuthority)
        );
    }
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

/// What a person READS: every row except the binding digest and the phrase derived from it.
fn read(review: &Review) -> Vec<Row> {
    review
        .rows()
        .into_iter()
        .filter(|row| row.section != Section::Binding && row.label != "Type to confirm")
        .collect()
}

#[test]
fn a_creation_review_shows_atomic_principal_fee_change_context_timing_and_effects() {
    let (world, _me, planned) = create_scenario();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    assert_eq!(planned.objects().len(), 1);
    let u = PartialBondCreate::decode(&planned.objects()[0].bytes)
        .unwrap()
        .unsigned;
    assert_eq!(reviewed.amount(), Some(PRINCIPAL));
    assert_eq!(reviewed.fee().atoms, u.fee);
    assert_eq!(
        reviewed.fee().size_bytes,
        Some(u.signed_len().unwrap() as u64)
    );
    assert_eq!(reviewed.fee().payer, FeePayer::ThisWallet);
    assert_eq!(reviewed.returned(), u.change.as_ref().unwrap().atoms);
    assert_eq!(
        reviewed.net_debit(),
        Some(u128::from(PRINCIPAL) + u128::from(u.fee))
    );
    assert_eq!(
        reviewed.destinations(),
        &[Destination {
            role: DestinationRole::Change,
            address: u.owner,
            label: AddressLabel::ThisWallet,
            atoms: u.change.as_ref().unwrap().atoms
        }]
    );
    let money = rows_of(&reviewed, Section::Money);
    assert!(row(&money, "Amount").value.starts_with("150.00000000 MUT"));
    for needle in [
        "at least one atom per byte",
        "paid by this wallet",
        "signed size",
    ] {
        assert!(row(&money, "Network fee").value.contains(needle));
    }
    assert!(
        row(&money, "Returns to this wallet")
            .value
            .contains(&u.change.as_ref().unwrap().atoms.to_string())
    );
    assert!(row(&money, "Input 0").value.contains("this wallet"));
    let conditions = rows_of(&reviewed, Section::Conditions);
    for label in [
        "Atomic funding",
        "Lot",
        "Node",
        "Bond authority",
        "Minimum",
        "Canonical reference",
        "Inclusion window",
        "Withdrawal rule",
        "Earliest withdrawal",
        "Burn exposure",
        "Weight",
        "Inputs",
        "Fee rule",
    ] {
        assert!(
            conditions.iter().any(|r| r.label == label),
            "missing {label}"
        );
    }
    for needle in [
        hex::encode(world.node()),
        hex::encode(world.lineage()),
        "hardware generation 1".into(),
    ] {
        assert!(row(&conditions, "Node").value.contains(&needle));
    }
    for needle in [
        hex::encode(u.lot_id()),
        hex::encode(u.nonce),
        hex::encode(u.owner),
    ] {
        assert!(row(&conditions, "Lot").value.contains(&needle));
    }
    assert!(
        row(&conditions, "Bond authority")
            .value
            .contains(&hex::encode(
                mutiny_wallet_core_v8::ops::rotation::descriptor_fingerprint(&u.owner_descriptor)
            ))
    );
    assert!(
        row(&conditions, "Canonical reference")
            .value
            .contains(&hex::encode(u.envelope.reference_block))
    );
    for needle in [
        "actual certified inclusion height",
        "approximate",
        "not the review height",
    ] {
        assert!(row(&conditions, "Inclusion window").value.contains(needle));
    }
    for needle in ["B + 259200", "U + 43200", "both clocks"] {
        assert!(row(&conditions, "Withdrawal rule").value.contains(needle));
    }
    let earliest = HEAD + 1 + LOCK_HEIGHTS;
    assert_eq!(reviewed.timing().earliest_height, Some(earliest));
    assert!(
        row(&conditions, "Earliest withdrawal")
            .value
            .contains(&earliest.to_string())
    );
    assert!(
        row(&conditions, "Earliest withdrawal")
            .value
            .contains("later inclusion shifts")
    );
    assert!(
        row(&conditions, "Earliest withdrawal")
            .value
            .contains("about 180 days")
    );
    assert_eq!(
        reviewed.timing().created_height,
        Some(u.envelope.first_height)
    );
    assert_eq!(
        reviewed.timing().expiry_height,
        Some(u.envelope.last_height)
    );
    assert_eq!(reviewed.timing().valid_only_at, None);
    assert!(!reviewed.timing().bound_to_parent);
    assert!(
        !reviewed.acknowledgements().contains(&AckKind::Destination),
        "native principal has no external escrow destination; owner change is already this wallet"
    );
    let irreversible: Vec<_> = reviewed
        .effects()
        .iter()
        .filter(|e| e.irreversible)
        .collect();
    assert!(irreversible.len() >= 5);
    for needle in [
        "There is no cancel",
        "burning",
        "cannot be revoked",
        "Locks 150.00000000 MUT",
        "Spends",
        "Pays a network fee",
    ] {
        assert!(
            irreversible.iter().any(|e| e.text.contains(needle)),
            "missing {needle}"
        );
    }
    for code in ["FUNDING_BOUND", "BURN_EXPOSURE"] {
        assert!(
            reviewed.warnings().iter().any(|w| w.code == code),
            "missing {code}"
        );
    }
    assert_eq!(
        reviewed
            .warnings()
            .iter()
            .any(|w| w.code == "TEST_VALUE_CHAIN"),
        view.class() == ChainClass::TestValue
    );
    for ack in [
        AckKind::Amount,
        AckKind::Fee,
        AckKind::Conditions,
        AckKind::Irreversible,
    ] {
        assert!(reviewed.acknowledgements().contains(&ack));
    }
    assert!(
        !reviewed
            .acknowledgements()
            .contains(&AckKind::SingleBlockWindow)
    );
    assert!(reviewed.requires_phrase());
    assert_eq!(reviewed.authorizations().len(), 2);
    assert!(
        reviewed
            .authorizations()
            .iter()
            .all(|a| a.status == RequirementStatus::ThisWallet)
    );
    assert_eq!(reviewed.parties()[0].role, PartyRole::NodeOwner);
    assert_eq!(reviewed.parties()[0].address, u.owner);
}

#[test]
fn unbond_and_withdrawal_reviews_show_sequence_timing_payout_and_effects() {
    let (world, _me, planned, lot) = unbond_scenario();
    let reviewed = review(&planned, &world.view()).unwrap();
    assert_eq!(reviewed.kind(), OperationKind::BondUnbond);
    assert!(reviewed.destinations().is_empty(), "an unbond moves no MUT");
    assert_eq!(reviewed.amount(), None);
    assert_eq!(
        (
            reviewed.fee().atoms,
            reviewed.fee().rule,
            reviewed.fee().payer
        ),
        (0, FeeRule::None, FeePayer::NotApplicable)
    );
    assert_eq!(
        row(&rows_of(&reviewed, Section::Money), "Network fee").value,
        "0.00000000 MUT (0 STRIKES); the protocol defines no fee for this operation; not applicable"
    );
    let conditions = rows_of(&reviewed, Section::Conditions);
    assert!(
        row(&conditions, "Sequence")
            .value
            .starts_with("This operation carries sequence 1")
    );
    let floor = withdrawal_floor(10, HEAD + 1).unwrap();
    assert_eq!(floor, 10 + LOCK_HEIGHTS);
    assert!(
        row(&conditions, "Earliest withdrawal")
            .value
            .starts_with(&format!(
                "Block {floor} = max(10 + 259200, 101 + 43200) if inclusion is U = 101"
            ))
    );
    assert!(
        row(&conditions, "Burn exposure")
            .value
            .contains(&format!("until block {}", HEAD + 1 + EVIDENCE_HEIGHTS))
    );
    assert!(
        row(&conditions, "Burn exposure")
            .value
            .contains("actual exposure")
    );
    assert!(
        row(&conditions, "Earliest withdrawal")
            .value
            .contains("actual finalized inclusion")
    );
    assert!(
        reviewed
            .warnings()
            .iter()
            .any(|w| w.code == "SIGNED_WINDOW" && w.requires == Some(AckKind::Conditions))
    );
    assert!(!reviewed.warnings().iter().any(|w| w.code == "SINGLE_BLOCK"));
    assert!(row(&conditions, "Lot").value.contains(&hex::encode(lot)));
    let effects = rows_of(&reviewed, Section::Effects);
    assert!(effects.iter().any(|r| {
        r.emphasis == Emphasis::Irreversible
            && r.value
                .contains("There is no way back: an unbond cannot be cancelled")
    }));
    assert!(reviewed.warnings().iter().any(|w| w.code == "NO_CANCEL"
        && w.severity == Severity::Danger
        && w.requires == Some(AckKind::Irreversible)));
    assert!(reviewed.requires_phrase());
    assert_eq!(
        reviewed.acknowledgements(),
        &[AckKind::Conditions, AckKind::Irreversible,]
    );

    let (world, _me, planned, lot) = withdraw_scenario();
    let reviewed = review(&planned, &world.view()).unwrap();
    assert_eq!(reviewed.kind(), OperationKind::BondWithdraw);
    assert_eq!(
        reviewed.destinations(),
        &[Destination {
            role: DestinationRole::ProtocolPayout,
            address: address(&key_a(), 1),
            label: AddressLabel::ThisWallet,
            atoms: PRINCIPAL
        }]
    );
    assert_eq!(reviewed.amount(), Some(PRINCIPAL));
    assert_eq!(reviewed.timing().earliest_height, Some(259_210));
    assert_eq!(
        row(&rows_of(&reviewed, Section::Timing), "Earliest height").value,
        "259210 (1 blocks after the verified block; about 1 min, approximate at the 60 s target interval)"
    );
    let conditions = rows_of(&reviewed, Section::Conditions);
    let op = Operation::decode(&planned.objects()[0].bytes).unwrap();
    assert!(
        row(&conditions, "Payout")
            .value
            .contains(&format!("{}:0", hex::encode(op.payout_id().unwrap())))
    );
    assert!(
        row(&conditions, "Withdrawal rule")
            .value
            .contains("the floor is block 259210 = max(10 + 259200, 20 + 43200)")
    );
    assert!(row(&conditions, "Lot").value.contains(&hex::encode(lot)));
    assert!(reviewed.requires_phrase());
    assert!(
        reviewed
            .effects()
            .iter()
            .any(|e| e.text == "This wallet receives 150.00000000 MUT." && !e.irreversible)
    );
}

#[test]
fn every_row_is_filled_and_sections_appear_in_display_order() {
    let reviews = [
        {
            let (world, _, planned) = create_scenario();
            review(&planned, &world.view()).unwrap()
        },
        {
            let (world, _, planned, _) = unbond_scenario();
            review(&planned, &world.view()).unwrap()
        },
        {
            let (world, _, planned, _) = withdraw_scenario();
            review(&planned, &world.view()).unwrap()
        },
    ];
    for reviewed in reviews {
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
        assert!(text.contains(&format!(
            "Type to confirm: {}",
            reviewed.confirmation_phrase().unwrap()
        )));
        assert_eq!(text, reviewed.render_text());
    }
}

fn native_bytes(u: &UnsignedBondCreate) -> Vec<u8> {
    PartialBondCreate::new(u.clone()).encode().unwrap()
}

#[test]
fn each_field_of_a_creation_shows_up_in_the_review_or_is_refused() {
    let (world, me, planned) = create_scenario();
    let view = world.view();
    let u = PartialBondCreate::decode(&planned.objects()[0].bytes)
        .unwrap()
        .unsigned;
    let base = review(&planned, &view).unwrap();
    let show = |u: &UnsignedBondCreate| explain(&native_bytes(u), &view, &me);
    assert_eq!(show(&u).unwrap().binding(), base.binding());
    let mut changed = u.clone();
    changed.fee += 7;
    changed.change.as_mut().unwrap().atoms -= 7;
    let r = show(&changed).unwrap();
    assert_eq!(r.fee().atoms, u.fee + 7);
    assert!(r.warnings().iter().any(|w| w.code == "FEE_ABOVE_MINIMUM"));
    assert_ne!(read(&r), read(&base));
    let mut changed = u.clone();
    changed.principal += 1;
    changed.change.as_mut().unwrap().atoms -= 1;
    let r = show(&changed).unwrap();
    assert_eq!(r.amount(), Some(PRINCIPAL + 1));
    assert_ne!(read(&r), read(&base));
    let mut changed = u.clone();
    changed.nonce[0] ^= 1;
    let r = show(&changed).unwrap();
    assert_ne!(read(&r), read(&base));
    assert!(r.render_text().contains(&hex::encode(changed.lot_id())));
    assert!(!r.render_text().contains(&hex::encode(u.lot_id())));
    // Native V8 requires any change to the same immutable authority; external change refuses.
    let mut changed = u.clone();
    changed.change.as_mut().unwrap().owner = address(&key_c(), 1);
    assert!(show(&changed).is_err());
    let mut two = world.clone();
    let point = two.coin(u.owner, 1_000_000, 1, false, 0x32, 0);
    let mut changed = u.clone();
    changed.inputs.push(point);
    changed.inputs.sort();
    changed.fee += 4000;
    changed.change.as_mut().unwrap().atoms += 1_000_000 - 4000;
    let r = explain(&native_bytes(&changed), &two.view(), &me).unwrap();
    assert_eq!(r.inputs().len(), 2);
    assert!(r.render_text().contains("Input 1"));
    type Edit = Box<dyn Fn(&mut UnsignedBondCreate)>;
    let refused: Vec<(&str, Edit)> = vec![
        ("node", Box::new(|u| u.node[0] ^= 1)),
        ("hardware generation", Box::new(|u| u.node_generation += 1)),
        ("input index", Box::new(|u| u.inputs[0].index += 1)),
        (
            "input transaction",
            Box::new(|u| u.inputs[0].transaction[0] ^= 1),
        ),
        ("future window", Box::new(|u| u.envelope.first_height += 1)),
        (
            "reference",
            Box::new(|u| u.envelope.reference_block[0] ^= 1),
        ),
        ("owner", Box::new(|u| u.owner[0] ^= 1)),
        (
            "descriptor",
            Box::new(|u| u.owner_descriptor = descriptor(&key_b(), 1)),
        ),
        ("genesis", Box::new(|u| u.genesis[0] ^= 1)),
        ("fingerprint", Box::new(|u| u.fingerprint[0] ^= 1)),
        ("conservation", Box::new(|u| u.fee += 1)),
    ];
    for (label, edit) in refused {
        let mut changed = u.clone();
        edit(&mut changed);
        assert!(show(&changed).is_err(), "{label}");
        assert!(
            PartialBondCreate::new(changed)
                .preflight(&world.state, &world.anchor, &Default::default())
                .is_err(),
            "consensus {label}"
        );
    }
    // A changed finite upper bound is legal, but must be visible and bind a different review.
    let mut changed = u.clone();
    changed.envelope.last_height += 1;
    let r = show(&changed).unwrap();
    assert_ne!(read(&r), read(&base));
    assert_ne!(r.binding(), base.binding());
}

#[test]
fn each_field_of_an_unbond_or_withdrawal_shows_up_or_is_refused() {
    for kind in [OperationKind::BondUnbond, OperationKind::BondWithdraw] {
        let (mut world, me, planned, lot) = if kind == OperationKind::BondUnbond {
            unbond_scenario()
        } else {
            withdraw_scenario()
        };
        let base_op = Operation::decode(&planned.objects()[0].bytes).unwrap();
        // A second lot in the same state as the first: a valid operation that must read differently.
        let other = world.lot(
            0x52,
            address(&key_a(), 1),
            PRINCIPAL,
            10,
            base_op_sequence(&base_op) - 1,
            if kind == OperationKind::BondUnbond {
                None
            } else {
                Some(20)
            },
            None,
            if kind == OperationKind::BondUnbond {
                LotStatus::Active
            } else {
                LotStatus::Unbonding
            },
        );
        let view = world.view();
        let base = review(&planned, &view).unwrap();
        let show = |op: &Operation| explain(&op.encode().unwrap(), &view, &me);
        let mut o = base_op.clone();
        match &mut o.action {
            Action::Unbond { lot, .. } | Action::Withdraw { lot, .. } => *lot = other,
        }
        let changed = show(&o).unwrap();
        assert_ne!(read(&changed), read(&base), "{kind:?}: the lot");
        assert!(changed.render_text().contains(&hex::encode(other)));
        assert!(!changed.render_text().contains(&hex::encode(lot)));

        type Edit = Box<dyn Fn(&mut Operation)>;
        let refused: Vec<(&str, Edit)> = vec![
            (
                "sequence",
                Box::new(|o| match &mut o.action {
                    Action::Unbond { sequence, .. } | Action::Withdraw { sequence, .. } => {
                        *sequence += 1
                    }
                }),
            ),
            (
                "unknown lot",
                Box::new(|o| match &mut o.action {
                    Action::Unbond { lot, .. } | Action::Withdraw { lot, .. } => lot[0] ^= 1,
                }),
            ),
            ("height", Box::new(|o| o.envelope.first_height += 1)),
            (
                "parent anchor",
                Box::new(|o| o.envelope.reference_block[0] ^= 1),
            ),
            ("owner", Box::new(|o| o.owner[0] ^= 1)),
            (
                "authorizer",
                Box::new(|o| o.authorizer = descriptor(&key_b(), 1)),
            ),
            ("genesis", Box::new(|o| o.genesis[0] ^= 1)),
            ("fingerprint", Box::new(|o| o.fingerprint[0] ^= 1)),
        ];
        for (label, edit) in refused {
            let mut o = base_op.clone();
            edit(&mut o);
            assert!(show(&o).is_err(), "{kind:?}: {label} must be refused");
        }
        let _ = lot;
    }
}

fn base_op_sequence(op: &Operation) -> u64 {
    match &op.action {
        Action::Unbond { sequence, .. } | Action::Withdraw { sequence, .. } => *sequence,
    }
}

/// Flip one bit of every byte of the unsigned bytes: each change is refused or shows up in what a
/// person reads; a flip inside a signature placeholder keeps the digest (it binds the unsigned
/// form) but must then show a signature that does not verify.
fn no_byte_can_change_unnoticed(raw: &[u8], view: &ChainView<'_>, me: &SignerIdentity) {
    let base = explain(raw, view, me).unwrap();
    let base_rows = read(&base);
    let (mut refused, mut visible) = (0usize, 0usize);
    for index in 0..raw.len() {
        let mut changed = raw.to_vec();
        changed[index] ^= 1 << (index % 8);
        match explain(&changed, view, me) {
            Err(_) => refused += 1,
            Ok(other) => {
                assert_ne!(
                    read(&other),
                    base_rows,
                    "byte {index} changed nothing a person reads"
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
    assert!(
        refused > 0 && visible > 0,
        "refused {refused}, visible {visible}"
    );
    assert_eq!(refused + visible, raw.len());
}

#[test]
fn no_byte_of_the_unsigned_objects_can_change_without_the_review_noticing() {
    let (world, me, planned) = create_scenario();
    no_byte_can_change_unnoticed(&export_unsigned(&planned).unwrap(), &world.view(), &me);
    let (world, me, planned, _) = unbond_scenario();
    no_byte_can_change_unnoticed(&export_unsigned(&planned).unwrap(), &world.view(), &me);
    let (world, me, planned, _) = withdraw_scenario();
    no_byte_can_change_unnoticed(&export_unsigned(&planned).unwrap(), &world.view(), &me);
}

/// The pinned texts. A deliberate change of the rendering or of any review content must update the
/// snapshot in the same commit.
const GOLDEN_CREATE: &str = include_str!("golden/bond_create_review.txt");
const GOLDEN_UNBOND: &str = include_str!("golden/bond_unbond_review.txt");
const GOLDEN_WITHDRAW: &str = include_str!("golden/bond_withdraw_review.txt");

#[test]
fn golden_text_snapshots() {
    let (world, _, planned) = create_scenario();
    let create = review(&planned, &world.view()).unwrap().render_text();
    let (world, _, planned, _) = unbond_scenario();
    let unbond = review(&planned, &world.view()).unwrap().render_text();
    let (world, _, planned, _) = withdraw_scenario();
    let withdraw = review(&planned, &world.view()).unwrap().render_text();
    let mut differences = Vec::new();
    for (name, text, golden) in [
        ("bond_create_review.txt", create, GOLDEN_CREATE),
        ("bond_unbond_review.txt", unbond, GOLDEN_UNBOND),
        ("bond_withdraw_review.txt", withdraw, GOLDEN_WITHDRAW),
    ] {
        if text != golden {
            differences.push(format!("review text differs from tests/golden/{name}; review the deliberate change before replacing it:\n{text}"));
        }
    }
    assert!(differences.is_empty(), "{}", differences.join("\n"));
}

#[test]
fn the_offline_signer_sees_the_same_review_and_signs_exactly_the_proposal() {
    for which in 0..3 {
        let (world, me, planned) = match which {
            0 => create_scenario(),
            1 => {
                let (w, m, p, _) = unbond_scenario();
                (w, m, p)
            }
            _ => {
                let (w, m, p, _) = withdraw_scenario();
                (w, m, p)
            }
        };
        let view = world.view();
        let exported = export_unsigned(&planned).unwrap();
        let adopted = adopt(&exported, &view, &me).unwrap();
        assert_eq!(adopted.id(), planned.id());
        assert_eq!(adopted.objects(), planned.objects());
        assert_eq!(adopted.validity(), planned.validity());
        assert_eq!(adopted.inputs(), planned.inputs());
        let own = review(&planned, &view).unwrap();
        assert_eq!(review(&adopted, &view).unwrap().binding(), own.binding());
        let signer = KeySigner::for_test(key_a()).unwrap();
        let signed = flow::sign(adopted, &signer, &view).unwrap();
        // The signed bytes explain to the same digest as the unsigned proposal.
        assert_eq!(
            explain(signed.bytes(), &view, &me).unwrap().binding(),
            own.binding()
        );
        assert!(
            explain(signed.bytes(), &view, &me)
                .unwrap()
                .authorizations()
                .iter()
                .all(|r| r.status == RequirementStatus::Provided)
        );
        // Seen by a stranger: the same digest, but nothing for it to sign.
        let stranger = explain(&exported, &view, &identity(&key_b())).unwrap();
        assert_eq!(stranger.binding(), own.binding());
        assert!(
            stranger
                .authorizations()
                .iter()
                .all(|r| r.status == RequirementStatus::Counterparty)
        );
    }
}

#[test]
fn hostile_bytes_are_refused_without_a_panic() {
    let (world, me, planned) = create_scenario();
    let view = world.view();
    let signer = KeySigner::for_test(key_a()).unwrap();
    let mut objects = vec![(
        view_bytes(&planned),
        flow::sign(planned, &signer, &view).unwrap(),
    )];
    let (uworld, _, uplan, _) = unbond_scenario();
    let uview = uworld.view();
    objects.push((
        view_bytes(&uplan),
        flow::sign(uplan, &signer, &uview).unwrap(),
    ));
    let (wworld, _, wplan, _) = withdraw_scenario();
    let wview = wworld.view();
    objects.push((
        view_bytes(&wplan),
        flow::sign(wplan, &signer, &wview).unwrap(),
    ));
    let views = [&view, &uview, &wview];
    for ((unsigned, signed), view) in objects.iter().zip(views) {
        assert!(SignedOperation::import(signed.bytes(), view).is_ok());
        for raw in [unsigned.as_slice(), signed.bytes()] {
            for cut in 0..raw.len() {
                assert!(explain(&raw[..cut], view, &me).is_err(), "prefix {cut}");
                assert!(adopt(&raw[..cut], view, &me).is_err());
                assert!(SignedOperation::import(&raw[..cut], view).is_err());
            }
            for extra in [1usize, 2, 4096] {
                let mut longer = raw.to_vec();
                longer.extend(std::iter::repeat_n(0u8, extra));
                assert!(explain(&longer, view, &me).is_err());
                assert!(SignedOperation::import(&longer, view).is_err());
            }
        }
        // Every byte of the signed bytes, one bit each: never accepted for queueing.
        let raw = signed.bytes();
        for index in 0..raw.len() {
            let mut changed = raw.to_vec();
            changed[index] ^= 1 << (index % 8);
            assert!(
                SignedOperation::import(&changed, view).is_err(),
                "{:?}: flipped byte {index} was accepted",
                signed.kind()
            );
        }
    }
    // The native outer array and both domain-separated proofs must be canonical and exact.
    let signed = &objects[0].1;
    let full = FundedBondCreate::decode(signed.bytes()).unwrap();
    assert_eq!(full.encode().unwrap(), signed.bytes());
    let raw = signed.bytes();
    assert_eq!(raw[0], 0x85);
    let mut wide = vec![0x98, 0x05];
    wide.extend_from_slice(&raw[1..]);
    assert!(FundedBondCreate::decode(&wide).is_err());
    assert!(SignedOperation::import(&wide, &view).is_err());
    let mut swapped = full.clone();
    std::mem::swap(&mut swapped.create, &mut swapped.funding);
    assert!(SignedOperation::import(&swapped.encode().unwrap(), &view).is_err());
    for slot in [0, 1] {
        let mut partial = full.as_partial();
        if slot == 0 {
            partial.create = None;
        } else {
            partial.funding = None;
        }
        assert!(FundedBondCreate::decode(&partial.encode().unwrap()).is_err());
        assert!(SignedOperation::import(&partial.encode().unwrap(), &view).is_err());
    }
    // Garbage of assorted sizes and shapes.
    for size in [0usize, 1, 3, 64, 1000, 25_000] {
        for fill in [0x00u8, 0xff, 0x83, 0x85] {
            let garbage = vec![fill; size];
            assert!(explain(&garbage, &view, &me).is_err());
            assert!(adopt(&garbage, &view, &me).is_err());
            assert!(SignedOperation::import(&garbage, &view).is_err());
            assert!(FundedBondCreate::decode(&garbage).is_err());
        }
    }
}

fn view_bytes(plan: &OperationPlan) -> Vec<u8> {
    export_unsigned(plan).unwrap()
}

// ---------------------------------------------------------------------------------------------
// Debug without secrets
// ---------------------------------------------------------------------------------------------

const PHRASE_WORDS: [&str; 3] = ["abandon", "zoo", "vote"];

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
fn bond_values_print_compactly_and_without_secrets() {
    let (world, me, planned) = create_scenario();
    let view = world.view();
    let signer = KeySigner::for_test(key_a()).unwrap();
    let reviewed = review(&planned, &view).unwrap();
    let signed = flow::sign(planned.clone(), &signer, &view).unwrap();
    let native = FundedBondCreate::decode(signed.bytes()).unwrap();
    let before_debug = native.encode().unwrap();
    let mut partial = native.as_partial();
    partial.funding = None;
    let partial_debug = format!("{partial:?}");
    assert!(partial_debug.contains("create_present: true"));
    assert!(partial_debug.contains("funding_present: false"));
    assert!(partial_debug.contains(&format!(
        "owner_descriptor_bytes: {}",
        native.unsigned.owner_descriptor.len()
    )));
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&signed, &view).unwrap();
    let record = outbox.records().unwrap().remove(0);
    let lots = {
        let (w, _, _, _) = withdraw_scenario();
        discovery::lots_controlled_by(&w.state, me.descriptor())
    };
    let nodes = discovery::nodes_controlled_by(&world.state, me.descriptor());
    assert_eq!(nodes.len(), 1);
    let shown = [
        format!("{planned:?}"),
        format!("{reviewed:?}"),
        format!("{signed:?}"),
        format!("{record:?}"),
        format!("{signer:?}"),
        format!("{:?}", FundedBondCreate::decode(signed.bytes()).unwrap()),
        format!("{:?}", native.unsigned),
        partial_debug,
        format!("{:?}", lots[0]),
        format!("{:?}", nodes[0]),
        format!(
            "{:?}",
            OperationRequest::BondCreate(BondCreateRequest::new(
                [0x5a; 32], 1, PRINCIPAL, [0x5b; 32]
            ))
        ),
        format!(
            "{:?}",
            OperationRequest::BondUnbond(BondUnbondRequest::new([0x5a; 32]))
        ),
        format!(
            "{:?}",
            OperationRequest::BondWithdraw(BondWithdrawRequest::new([0x5a; 32]))
        ),
        format!("{:?}", planned.objects()[0]),
        format!("{:?}", planned.requirements()),
        format!("{:?}", reviewed.destinations()),
        format!("{:?}", reviewed.timing()),
    ];
    for text in &shown {
        assert!(!text.is_empty());
        for word in PHRASE_WORDS {
            assert!(!text.to_ascii_lowercase().contains(word), "{text}");
        }
        assert!(longest_number_run(text) < 8, "a dumped byte array: {text}");
        assert!(longest_hex_run(text) < 64, "a full identifier: {text}");
        assert!(text.len() < 2000, "{} characters: {text}", text.len());
    }
    assert!(format!("{signer:?}").contains("<redacted>"));
    assert_eq!(
        native.encode().unwrap(),
        before_debug,
        "formatting does not change canonical bytes"
    );
}

// ---------------------------------------------------------------------------------------------
// The locked timing over random lock-start and notice heights
// ---------------------------------------------------------------------------------------------

/// xorshift64*: deterministic, so every run checks the same cases.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

#[test]
fn the_withdrawal_floor_is_max_of_both_rules_for_random_heights() {
    let mut rng = Rng(0x00b0_4d5f_100e_0001);
    for _ in 0..20_000 {
        let created = 1 + rng.below(1 << 40);
        let unbond = created + 1 + rng.below(400_000);
        let expected = (created + LOCK_HEIGHTS).max(unbond + EVIDENCE_HEIGHTS);
        assert_eq!(withdrawal_floor(created, unbond).unwrap(), expected);
        assert_eq!(
            discovery::earliest_withdrawal(created, unbond),
            Some(expected)
        );
        // Consensus' Lot::withdraw agrees at the floor and one block earlier.
        let mut lot = mutiny_consensus_v8::bonds_v2::Lot(mutiny_consensus_v8::bonds::BondLot {
            id: [1; 32],
            node: [2; 32],
            lineage: [3; 32],
            owner: [4; 32],
            atoms: MINIMUM_ATOMS,
            created_height: created,
            sequence: 1,
            unbond_height: Some(unbond),
            settled_height: None,
            status: LotStatus::Unbonding,
            evidence: [0; 32],
        });
        assert!(lot.clone().withdraw(expected - 1, 2).is_err());
        assert_eq!(lot.withdraw(expected, 2).unwrap(), MINIMUM_ATOMS);
    }
    // Overflow is refused, never wrapped.
    assert_eq!(
        discovery::earliest_withdrawal(u64::MAX - LOCK_HEIGHTS + 1, u64::MAX),
        None
    );
    assert_eq!(
        discovery::earliest_withdrawal(1, u64::MAX - EVIDENCE_HEIGHTS + 1),
        None
    );
    assert!(withdrawal_floor(u64::MAX - LOCK_HEIGHTS + 1, u64::MAX).is_err());
}

#[test]
fn the_wallet_refuses_one_block_before_the_floor_and_accepts_at_it_for_random_heights() {
    let mut rng = Rng(0x00b0_4d5f_100e_0002);
    let base = BondWorld::new(1);
    let me = identity(&key_a());
    for case in 0..48 {
        let created = 1 + rng.below(1 << 30);
        // Half the notices bind (late notice), half leave the minimum hold binding.
        let unbond = if case % 2 == 0 {
            created + 1 + rng.below(LOCK_HEIGHTS - EVIDENCE_HEIGHTS)
        } else {
            created + LOCK_HEIGHTS - EVIDENCE_HEIGHTS + 1 + rng.below(1 << 20)
        };
        let floor = withdrawal_floor(created, unbond).unwrap();
        let mut ready = base.at(floor - 1);
        let lot = ready.lot(
            0x61,
            address(&key_a(), 1),
            PRINCIPAL,
            created,
            1,
            Some(unbond),
            None,
            LotStatus::Unbonding,
        );
        let planned = plan(&withdraw(lot), &ready.view(), &me).unwrap();
        assert_eq!(planned.validity().valid_only_at, None);
        assert_eq!(
            review(&planned, &ready.view())
                .unwrap()
                .timing()
                .earliest_height,
            Some(floor)
        );
        let early = ready.at(floor - 2);
        assert_eq!(
            plan(&withdraw(lot), &early.view(), &me).unwrap_err(),
            Refusal::NotYetEligible {
                what: "Withdrawing this lot",
                height: floor
            },
            "B {created} U {unbond}"
        );
        // An unbond planned at the notice height shows the floor it will lead to.
        let mut active = base.at(unbond - 1);
        let lot = active.lot(
            0x62,
            address(&key_a(), 1),
            PRINCIPAL,
            created,
            0,
            None,
            None,
            LotStatus::Active,
        );
        let planned = plan(&unbond_request(lot), &active.view(), &me).unwrap();
        let text = review(&planned, &active.view()).unwrap().render_text();
        assert!(
            text.contains(&format!(
                "Earliest withdrawal: Block {floor} = max({created} + {LOCK_HEIGHTS}, {unbond} + {EVIDENCE_HEIGHTS})"
            )),
            "B {created} U {unbond}:\n{text}"
        );
    }
}

fn unbond_request(lot: Hash) -> OperationRequest {
    unbond(lot)
}

#[test]
fn the_funding_fee_is_a_fixed_point_and_value_is_conserved_for_random_amounts_and_coins() {
    let mut rng = Rng(0x00b0_4d5f_100e_0003);
    let me = identity(&key_a());
    let base = BondWorld::new(HEAD);
    let signer = KeySigner::for_test(key_a()).unwrap();
    let (mut planned_count, mut signed_count) = (0, 0);
    for case in 0..64u8 {
        let mut world = base.clone();
        let coins = 1 + rng.below(3) as usize;
        let mut total = 0u64;
        for index in 0..coins {
            let atoms = MINIMUM_ATOMS / 2 + rng.below(MINIMUM_ATOMS);
            total += atoms;
            world.coin(
                address(&key_a(), 1),
                atoms,
                1,
                false,
                0x80 + case,
                index as u32,
            );
        }
        let amount = MINIMUM_ATOMS + rng.below(MINIMUM_ATOMS);
        let mut nonce = [0xaa; 32];
        nonce[0] = case;
        let request =
            OperationRequest::BondCreate(BondCreateRequest::new(world.node(), 1, amount, nonce));
        let view = world.view();
        match plan(&request, &view, &me) {
            Ok(planned) => {
                planned_count += 1;
                let u = PartialBondCreate::decode(&planned.objects()[0].bytes)
                    .unwrap()
                    .unsigned;
                let size = u.signed_len().unwrap() as u64;
                assert!(u.fee >= size, "case {case}");
                let spent: u64 = u
                    .inputs
                    .iter()
                    .map(|point| world.state.coins[point].output.atoms)
                    .sum();
                assert_eq!(
                    spent,
                    u.principal + u.fee + u.change.as_ref().map_or(0, |c| c.atoms),
                    "case {case}"
                );
                assert_eq!(u.principal, amount);
                assert_eq!(u.envelope.first_height, HEAD + 1);
                assert_eq!(u.envelope.last_height, HEAD + 1 + 144);
                if let Some(change) = &u.change {
                    assert_eq!(change.owner, u.owner);
                    assert!(change.atoms > 0);
                    assert!(u.fee - size < 16, "case {case}");
                }
                if signed_count < 3 {
                    signed_count += 1;
                    let signed = flow::sign(planned, &signer, &view).unwrap();
                    assert_eq!(
                        signed.bytes().len() as u64,
                        size,
                        "case {case}: complete signed size"
                    );
                    FundedBondCreate::decode(signed.bytes())
                        .unwrap()
                        .verify(&world.state, &world.anchor, &Default::default())
                        .unwrap();
                }
            }
            Err(Refusal::InsufficientFunds {
                available,
                requested,
            }) => {
                assert_eq!(available, total, "case {case}");
                assert!(requested > available, "case {case}");
            }
            Err(other) => panic!("case {case}: {other:?}"),
        }
    }
    assert!(planned_count >= 16 && signed_count == 3, "{planned_count}");
}
