//! The audit of every adopt (co-sign or offline-sign) path for the class of the review's BLOCKER-1
//! (fixes of the independent wallet review): can a plan built by SOMEBODY ELSE contain a signed
//! output or input, or move value, that the adopting wallet's review does not show as a
//! destination, an amount or an effect?
//!
//! Method, the same for every kind with coin flows (payment, wallet rotation, hash lock, claim,
//! refund, License sale, fiat lock, fiat release, bond creation, Treasury destination rotation,
//! dividend claim): the counterparty's UNSIGNED plan (an unsigned plan is what a counterparty that
//! signs its own part could hand over as well) is mutated field by field: every output's owner and
//! amount, the fee, every input (removed, another coin of the payer added), every party and amount
//! field of a trading action. Each mutation is adopted by the reading wallet. It is either REFUSED,
//! or the review it gives (a) differs in what it shows about money (destinations, amount, net debit,
//! fee, change, inputs) from the review of the unmutated plan, and (b) passes the value-accounting
//! predicate [`hidden`], computed by THIS test from the bytes and the verified view, never from the
//! review: the stated net debit is never below what really leaves the reader; beyond the fee the
//! reader pays, everything that leaves the reader is a shown destination to another address; and
//! every amount that ends at another address appears in what the person reads. The predicate is
//! checked to catch the review's BLOCKER shape (`the_predicate_catches_the_blocker_shape`).
//!
//! Kinds without a coin input or output in their signed bytes are not mutated here and are cited
//! in the report: bond unbond and withdrawal (the payout goes to the lot's immutable owner,
//! consensus `bond_ops_v2`) and the Treasury offer freeze (a signature over the freeze body only).
//! NATIVE, TEST-VALUE; public test keys; makers are fresh random keys played by the test (Q7).
#![allow(clippy::duplicate_mod)]
#[path = "support/bond_support.rs"]
mod bond_support;
#[path = "support/conditional_kit.rs"]
mod ckit;
#[path = "support/dividend_world.rs"]
mod dividend;
#[path = "support/synthetic.rs"]
mod synthetic;
#[path = "support/treasury_kit.rs"]
mod tkit;
#[path = "support/trading_5b.rs"]
mod trading;

use mutiny_consensus_v8::{
    Hash,
    bond_create_v3::PartialBondCreate,
    dividend_claim_v1::SignedClaim,
    dividend_state_v1::DividendState,
    funded_rotation_v2::{PartialRotation, Payer},
    trading_v1::{
        self, Action, NativeLock, NativeLockKind, NativeOperation, NativeRecord, Strikes,
        native_input_id,
    },
    transactions::{OutPoint, Output},
    transactions_v2::{Input, Transfer},
    treasury_v1::{Class, Treasury},
};
use mutiny_crypto_v2::{HybridKey, Role, rehearsal_keys_v1};
use mutiny_wallet_core_v8::{
    ops::rotation,
    profile::{self, TreasuryDeclaration},
    *,
};
use synthetic::{World, address, descriptor, identity, key_a, key_b, key_c};

fn new_key(label: &str) -> HybridKey {
    let phrase = rehearsal_keys_v1::label_phrase(label).unwrap();
    HybridKey::wallet_restore(&phrase, Role::WalletOwner).unwrap()
}

/// An address nobody in any world below controls (derived once: key derivation is slow).
fn stranger() -> Hash {
    static STRANGER: std::sync::OnceLock<Hash> = std::sync::OnceLock::new();
    *STRANGER.get_or_init(|| {
        new_key("w-fix-audit-stranger")
            .public()
            .address_id(1)
            .unwrap()
    })
}

// ---------------------------------------------------------------------------------------------
// The predicate
// ---------------------------------------------------------------------------------------------

/// What the bytes do with value, computed by this test from the bytes and the view.
#[derive(Debug)]
struct Truth {
    /// The reader's coins the bytes spend.
    mine_in: u128,
    /// What the bytes give the reader (outputs, credits from a lock or the protocol).
    mine_back: u128,
    /// Every amount that ends at an address the reader does not control.
    to_others: Vec<(Hash, u64)>,
    fee: u64,
    /// The reader pays the fee.
    fee_mine: bool,
}

/// What a review shows about money.
#[derive(Debug, PartialEq)]
struct Shown {
    destinations: Vec<(DestinationRole, Hash, u64)>,
    amount: Option<u64>,
    net_debit: Option<u128>,
    fee: u64,
    returned: u64,
    inputs: Vec<(OutPoint, u64, bool)>,
}

fn shown(review: &Review) -> Shown {
    Shown {
        destinations: review
            .destinations()
            .iter()
            .map(|d| (d.role, d.address, d.atoms))
            .collect(),
        amount: review.amount(),
        net_debit: review.net_debit(),
        fee: review.fee().atoms,
        returned: review.returned(),
        inputs: review
            .inputs()
            .iter()
            .map(|i| (i.point.clone(), i.atoms, i.owned_by_signer))
            .collect(),
    }
}

/// `Some(problem)` when a review hides value: it understates what leaves the reader, value leaves
/// the reader beyond the fee it pays without being a shown destination to another address, or an
/// amount that ends at another address is not in what the person reads.
fn hidden(
    truth: &Truth,
    shown: &Shown,
    text: &str,
    mine: &dyn Fn(&Hash) -> bool,
) -> Option<String> {
    if truth.mine_in > truth.mine_back {
        let real = truth.mine_in - truth.mine_back;
        match shown.net_debit {
            Some(stated) if stated >= real => {}
            other => return Some(format!("net debit shown {other:?}, really {real}")),
        }
        let fee = if truth.fee_mine {
            u128::from(truth.fee)
        } else {
            0
        };
        let out: u128 = shown
            .destinations
            .iter()
            .filter(|(role, address, _)| *role != DestinationRole::Change && !mine(address))
            .map(|(_, _, atoms)| u128::from(*atoms))
            .sum();
        if real > fee + out {
            return Some(format!(
                "{real} atoms leave the reader, but only the fee {fee} and destinations of {out} are shown"
            ));
        }
    }
    for (address, atoms) in &truth.to_others {
        if *atoms > 0 && !text.contains(&hex::encode(address)) {
            return Some(format!(
                "{atoms} atoms to {} are not shown",
                hex::encode(address)
            ));
        }
    }
    None
}

#[test]
fn the_predicate_catches_the_blocker_shape() {
    // The fee payer's review at 93aaa81 (the review's probe): 3,000,000 atoms in, 85,799 back, the
    // fee 14,202, no destination but its own change, the attacker's 2,900,000 shown only as
    // "Returns ... to the fee payer".
    let (me, attacker) = ([0xb0; 32], [0xc0; 32]);
    let truth = Truth {
        mine_in: 3_000_000,
        mine_back: 85_799,
        to_others: vec![(attacker, 2_900_000)],
        fee: 14_202,
        fee_mine: true,
    };
    let old = Shown {
        destinations: vec![(DestinationRole::Change, me, 85_799)],
        amount: None,
        net_debit: Some(2_914_201),
        fee: 14_202,
        returned: 85_799,
        inputs: Vec::new(),
    };
    let text = format!(
        "Returns 0.02900000 MUT to the fee payer {}.",
        hex::encode(attacker)
    );
    let mine = |address: &Hash| *address == me;
    assert!(
        hidden(&truth, &old, &text, &mine).is_some(),
        "the BLOCKER shape must be caught"
    );
    // The same value shown as a payment destination passes.
    let mut fixed = old;
    fixed
        .destinations
        .push((DestinationRole::Payment, attacker, 2_899_999));
    assert_eq!(hidden(&truth, &fixed, &text, &mine), None);
    // An understated net debit, and an amount to another address that is nowhere in the text.
    let mut understated = fixed;
    understated.net_debit = Some(14_202);
    assert!(hidden(&truth, &understated, &text, &mine).is_some());
    assert!(hidden(&truth, &understated, "", &|_: &Hash| false).is_some());
}

// ---------------------------------------------------------------------------------------------
// The engine
// ---------------------------------------------------------------------------------------------

/// Adopt every mutation as `reader` and require: refused, or a review whose money differs from the
/// unmutated plan's and that hides nothing. Returns (refused, shown).
fn audit(
    name: &str,
    view: &ChainView<'_>,
    reader: &SignerIdentity,
    base: &[u8],
    mutations: Vec<(String, Vec<u8>)>,
    truth: &dyn Fn(&[u8]) -> Truth,
) -> (usize, usize) {
    let mine = |address: &Hash| {
        view.state()
            .wallets
            .authorize(*address, reader.descriptor())
            .is_ok()
    };
    let read = |raw: &[u8]| adopt(raw, view, reader).and_then(|planned| review(&planned, view));
    let base_review = read(base).unwrap_or_else(|e| panic!("{name}: the counterparty's plan: {e}"));
    let base_shown = shown(&base_review);
    if let Some(problem) = hidden(&truth(base), &base_shown, &base_review.render_text(), &mine) {
        panic!("{name}: the unmutated plan: {problem}");
    }
    let (mut refused, mut visible) = (0, 0);
    assert!(mutations.len() >= 4, "{name}: too few mutations");
    for (what, raw) in mutations {
        match read(&raw) {
            Err(_) => refused += 1,
            Ok(changed) => {
                let now = shown(&changed);
                assert_ne!(
                    now, base_shown,
                    "{name}: {what}: the signed money changed but not the money the review shows"
                );
                if let Some(problem) = hidden(&truth(&raw), &now, &changed.render_text(), &mine) {
                    panic!("{name}: {what}: {problem}");
                }
                visible += 1;
            }
        }
    }
    println!(
        "AUDIT {name} read by {}: {refused} mutation(s) refused, {visible} shown and hiding nothing",
        hex::encode(&reader.address()[..4])
    );
    (refused, visible)
}

/// The value flow of a transfer (payments, rotation funding, bond funding) for `mine`.
fn transfer_truth(
    transfer: &Transfer,
    view: &ChainView<'_>,
    mine: &dyn Fn(&Hash) -> bool,
) -> Truth {
    let coins = &view.state().coins;
    let mut truth = Truth {
        mine_in: 0,
        mine_back: 0,
        to_others: Vec::new(),
        fee: transfer.fee,
        fee_mine: false,
    };
    for input in &transfer.inputs {
        if let Some(coin) = coins.get(&input.point)
            && mine(&coin.output.owner)
        {
            truth.mine_in += u128::from(coin.output.atoms);
            truth.fee_mine = true;
        }
    }
    for output in &transfer.outputs {
        if mine(&output.owner) {
            truth.mine_back += u128::from(output.atoms);
        } else {
            truth.to_others.push((output.owner, output.atoms));
        }
    }
    truth
}

/// Money mutations of a transfer: every output's owner (to a stranger, to the reader, to a funder of
/// the plan), value moved between outputs and into the fee, an output added and removed, an input
/// removed and `extra` (another coin) added.
fn transfer_mutations(
    base: &Transfer,
    reader_address: Hash,
    extra: Option<(OutPoint, u64, Input)>,
) -> Vec<(String, Transfer)> {
    let mut out = Vec::new();
    for index in 0..base.outputs.len() {
        for (label, owner) in [("a stranger", stranger()), ("the reader", reader_address)] {
            if base.outputs[index].owner != owner {
                let mut t = base.clone();
                t.outputs[index].owner = owner;
                out.push((format!("output {index} to {label}"), t));
            }
        }
        let delta = (base.outputs[index].atoms / 3).max(1);
        if base.outputs[index].atoms > delta {
            let mut t = base.clone();
            t.outputs[index].atoms -= delta;
            t.fee += delta;
            out.push((format!("{delta} atoms of output {index} into the fee"), t));
            for other in 0..base.outputs.len() {
                if other != index {
                    let mut t = base.clone();
                    t.outputs[index].atoms -= delta;
                    t.outputs[other].atoms += delta;
                    out.push((
                        format!("{delta} atoms from output {index} to output {other}"),
                        t,
                    ));
                }
            }
            let mut t = base.clone();
            t.outputs[index].atoms -= delta;
            t.outputs.push(Output {
                owner: stranger(),
                atoms: delta,
            });
            out.push((
                format!("{delta} atoms of output {index} to a new output"),
                t,
            ));
        }
        if base.outputs.len() > 1 {
            let mut t = base.clone();
            let gone = t.outputs.remove(index);
            t.fee += gone.atoms;
            out.push((format!("output {index} removed into the fee"), t));
        }
    }
    if base.inputs.len() > 1 {
        let mut t = base.clone();
        t.inputs.pop();
        let last = t.outputs.len() - 1;
        t.outputs[last].atoms = t.outputs[last].atoms.saturating_sub(1);
        out.push(("the last input removed".into(), t));
    }
    if let Some((_, atoms, input)) = extra {
        let mut t = base.clone();
        t.inputs.push(input.clone());
        t.outputs.push(Output {
            owner: stranger(),
            atoms,
        });
        out.push(("an input added, its value to a stranger".into(), t));
        let mut t = base.clone();
        t.inputs.push(input);
        t.outputs[0].atoms += atoms;
        out.push(("an input added, its value to output 0".into(), t));
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Transfers
// ---------------------------------------------------------------------------------------------

#[test]
fn a_payment_built_elsewhere_hides_no_output_or_input_from_its_offline_signer() {
    let mut world = World::new(100);
    world.coin(address(&key_a(), 1), 5_000_000, 1, false, 1, 0);
    world.coin(address(&key_a(), 1), 3_000_000, 1, false, 2, 0);
    let spare = world.coin(address(&key_a(), 1), 700_000, 1, false, 3, 0);
    world.coin(address(&key_b(), 1), 900_000, 1, false, 4, 0);
    let view = world.view();
    let me = identity(&key_a());
    let planned = plan(
        &OperationRequest::Payment(PaymentRequest::new(address(&key_b(), 1), 6_000_000)),
        &view,
        &me,
    )
    .unwrap();
    let base = Transfer::decode(&planned.objects()[0].bytes).unwrap();
    let extra = Input::unsigned(spare.clone(), key_a().public(), 1).unwrap();
    let mut mutations: Vec<(String, Vec<u8>)> =
        transfer_mutations(&base, address(&key_a(), 1), Some((spare, 700_000, extra)))
            .into_iter()
            .map(|(what, t)| (what, t.encode().unwrap()))
            .collect();
    // Another wallet's coin as an input: never this offline signer's to sign.
    let mut foreign = base.clone();
    foreign.inputs.push(
        Input::unsigned(
            OutPoint {
                transaction: [4; 32],
                index: 0,
            },
            key_b().public(),
            1,
        )
        .unwrap(),
    );
    foreign.outputs[0].atoms += 900_000;
    mutations.push(("another wallet's input".into(), foreign.encode().unwrap()));
    let mine = |a: &Hash| *a == address(&key_a(), 1);
    let (refused, visible) = audit(
        "payment",
        &view,
        &me,
        &planned.objects()[0].bytes,
        mutations,
        &|raw| transfer_truth(&Transfer::decode(raw).unwrap(), &view, &mine),
    );
    assert!(refused > 0 && visible > 5, "{refused} {visible}");
}

#[test]
fn a_rotation_funding_built_elsewhere_hides_nothing_from_its_fee_payer() {
    let mut world = World::new(100);
    world.coin(address(&key_b(), 1), 3_000_000, 1, false, 2, 0);
    let spare = world.coin(address(&key_b(), 1), 400_000, 1, false, 5, 0);
    let unrelated = world.coin(address(&key_c(), 1), 50_000, 1, false, 3, 0);
    let view = world.view();
    let payer = identity(&key_b());
    let new = new_key("w-fix-audit-rotation-new");
    let proposed = new.public().descriptor(2).unwrap();
    let planned = plan(
        &OperationRequest::WalletRotation(
            RotationRequest::new(
                Blob::new(proposed.clone()),
                FeeSource::OtherWallet(payer.clone()),
            )
            .with_restore_verified(rotation::descriptor_fingerprint(&proposed)),
        ),
        &view,
        &identity(&key_a()),
    )
    .unwrap();
    let base = PartialRotation::decode(&planned.objects()[0].bytes)
        .unwrap()
        .unsigned;
    let mut mutations = Vec::new();
    for index in 0..base.outputs.len() {
        for (label, owner) in [
            ("stranger", stranger()),
            ("rotating authority", address(&key_a(), 1)),
            ("new key", new.public().address_id(2).unwrap()),
        ] {
            let mut u = base.clone();
            u.outputs[index].owner = owner;
            if let Ok(raw) = PartialRotation::new(u).encode() {
                mutations.push((format!("output {index} to {label}"), raw));
            }
        }
        for delta in [1u64, 500, 1000] {
            let mut u = base.clone();
            u.fee += delta;
            u.outputs[index].atoms -= delta;
            mutations.push((
                format!("{delta} change into fee"),
                PartialRotation::new(u).encode().unwrap(),
            ));
        }
        let mut u = base.clone();
        u.outputs[index].atoms -= 1000;
        u.outputs.push(Output {
            owner: stranger(),
            atoms: 1000,
        });
        mutations.push((
            "new stranger output".into(),
            PartialRotation::new(u).encode().unwrap(),
        ));
    }
    let mut u = base.clone();
    u.inputs.push((spare, Payer::Sponsor));
    u.inputs.sort();
    u.outputs[0].atoms += 400_000;
    mutations.push((
        "additional current sponsor input".into(),
        PartialRotation::new(u).encode().unwrap(),
    ));
    let mut u = base.clone();
    u.inputs.push((unrelated, Payer::Sponsor));
    u.inputs.sort();
    u.outputs[0].atoms += 50_000;
    mutations.push((
        "unrelated wallet coin falsely tagged Sponsor".into(),
        PartialRotation::new(u).encode().unwrap(),
    ));
    let mine = |a: &Hash| *a == address(&key_b(), 1);
    let (refused, visible) = audit(
        "atomic rotation funding (current sponsor)",
        &view,
        &payer,
        &planned.objects()[0].bytes,
        mutations,
        &|raw| {
            let u = PartialRotation::decode(raw).unwrap().unsigned;
            let mut truth = Truth {
                mine_in: 0,
                mine_back: 0,
                to_others: Vec::new(),
                fee: u.fee,
                fee_mine: false,
            };
            for (point, _) in &u.inputs {
                if let Some(coin) = view.state().coins.get(point) {
                    if mine(&coin.output.owner) {
                        truth.mine_in += u128::from(coin.output.atoms);
                        truth.fee_mine = true;
                    }
                }
            }
            for out in &u.outputs {
                if mine(&out.owner) {
                    truth.mine_back += u128::from(out.atoms);
                } else {
                    truth.to_others.push((out.owner, out.atoms));
                }
            }
            truth
        },
    );
    assert!(refused >= 4 && visible >= 1, "{refused} {visible}");
}

#[test]
fn a_bond_creation_built_elsewhere_hides_nothing_from_its_offline_signer() {
    use bond_support::world::{BondWorld, address as bond_address, identity as bond_identity};
    let a = bond_support::world::key_a();
    let mut world = BondWorld::new(100);
    let funds = world.coin(bond_address(&a, 1), 30_000_000_000, 1, false, 0x31, 0);
    let spare = world.coin(bond_address(&a, 1), 2_000_000_000, 1, false, 0x32, 0);
    let _ = funds;
    let view = world.view();
    let me = bond_identity(&a);
    let planned = plan(
        &OperationRequest::BondCreate(BondCreateRequest::new(
            world.node(),
            1,
            15_000_000_000,
            [0x42; 32],
        )),
        &view,
        &me,
    )
    .unwrap();
    let raw = ops::bond::export_unsigned(&planned).unwrap();
    let base = PartialBondCreate::decode(&raw).unwrap().unsigned;
    let mut mutations = Vec::new();
    let mut changed = base.clone();
    changed.change.as_mut().unwrap().owner = stranger();
    mutations.push((
        "change to stranger".into(),
        PartialBondCreate::new(changed).encode().unwrap(),
    ));
    let mut changed = base.clone();
    changed.inputs[0] = spare.clone();
    mutations.push((
        "replace funding input without balancing value".into(),
        PartialBondCreate::new(changed).encode().unwrap(),
    ));
    let mut changed = base.clone();
    changed.inputs.push(spare);
    changed.inputs.sort();
    changed.change.as_mut().unwrap().atoms += 2_000_000_000;
    mutations.push((
        "add current owner funding input".into(),
        PartialBondCreate::new(changed).encode().unwrap(),
    ));
    for delta in [1, 500, 1000, 2000] {
        let mut changed = base.clone();
        changed.fee += delta;
        changed.change.as_mut().unwrap().atoms -= delta;
        mutations.push((
            format!("{delta} change into fee"),
            PartialBondCreate::new(changed).encode().unwrap(),
        ));
        let mut changed = base.clone();
        changed.principal += delta;
        changed.change.as_mut().unwrap().atoms -= delta;
        mutations.push((
            format!("{delta} change into principal"),
            PartialBondCreate::new(changed).encode().unwrap(),
        ));
    }
    let mine = |x: &Hash| *x == bond_address(&a, 1);
    let (refused, visible) = audit("bond creation", &view, &me, &raw, mutations, &|raw| {
        let u = PartialBondCreate::decode(raw).unwrap().unsigned;
        // The native principal becomes the immutable owner's lot, not a transfer to an
        // escrow address. Account for this retained value independently and check the
        // locked amount in the review separately below.
        let mut truth = Truth {
            mine_in: 0,
            mine_back: u128::from(u.principal),
            to_others: Vec::new(),
            fee: u.fee,
            fee_mine: true,
        };
        for point in &u.inputs {
            if let Some(coin) = view.state().coins.get(point) {
                if mine(&coin.output.owner) {
                    truth.mine_in += u128::from(coin.output.atoms);
                }
            }
        }
        for out in &u.change {
            if mine(&out.owner) {
                truth.mine_back += u128::from(out.atoms);
            } else {
                truth.to_others.push((out.owner, out.atoms));
            }
        }
        let rendered = review(&adopt(raw, &view, &me).unwrap(), &view).unwrap();
        assert_eq!(rendered.amount(), Some(u.principal));
        assert_eq!(
            rendered.net_debit(),
            Some(u128::from(u.principal) + u128::from(u.fee))
        );
        assert!(rendered.render_text().contains("bond lot"));
        truth
    });
    assert!(refused > 0 && visible > 3, "{refused} {visible}");
    let observer = bond_identity(&bond_support::world::key_b());
    let offline = explain(&raw, &view, &observer).unwrap();
    assert_eq!(offline.returned(), 0);
    assert_eq!(offline.net_debit(), Some(0));
    assert!(offline.inputs().iter().all(|i| !i.owned_by_signer));
    assert!(matches!(offline.fee().payer, FeePayer::Counterparty(owner) if owner == base.owner));
}

// ---------------------------------------------------------------------------------------------
// Native trading operations
// ---------------------------------------------------------------------------------------------

/// The credits of a trading action: (address, atoms) for every amount it gives an address.
fn credits(action: &Action) -> Vec<(Hash, u64)> {
    match action {
        Action::HashLock {
            sender,
            recipient,
            amount,
            change,
            ..
        } => vec![(*recipient, amount.0), (*sender, change.0)],
        Action::Claim {
            recipient,
            amount,
            change,
            ..
        } => vec![(*recipient, amount.0), (*recipient, change.0)],
        Action::Refund {
            owner,
            amount,
            change,
            ..
        } => vec![(*owner, amount.0), (*owner, change.0)],
        Action::LicenseDvp {
            buyer,
            price,
            payment_destination,
            change,
            ..
        } => vec![(*payment_destination, price.0), (*buyer, change.0)],
        Action::FiatLock {
            seller,
            buyer,
            amount,
            change,
            ..
        } => vec![(*buyer, amount.0), (*seller, change.0)],
        Action::FiatRelease {
            buyer,
            amount,
            change,
            ..
        } => vec![(*buyer, amount.0), (*buyer, change.0)],
        Action::TreasuryRotate {
            current_address,
            change,
            ..
        } => vec![(*current_address, change.0)],
    }
}

fn native_truth(raw: &[u8], view: &ChainView<'_>, mine: &dyn Fn(&Hash) -> bool) -> Truth {
    let wire = NativeOperation::decode(raw).unwrap();
    let op = &wire.operation;
    let coins = &view.state().coins;
    let mut truth = Truth {
        mine_in: 0,
        mine_back: 0,
        to_others: Vec::new(),
        fee: op.meta.fee.0,
        fee_mine: mine(&op.fee_payer()),
    };
    for point in &wire.inputs {
        if let Some(coin) = coins.get(point)
            && mine(&coin.output.owner)
        {
            truth.mine_in += u128::from(coin.output.atoms);
        }
    }
    for (address, atoms) in credits(&op.action) {
        if mine(&address) {
            truth.mine_back += u128::from(atoms);
        } else {
            truth.to_others.push((address, atoms));
        }
    }
    truth
}

/// The party and amount fields of an action, as mutable references for mutation.
fn party_fields(action: &mut Action) -> Vec<(&'static str, &mut Hash)> {
    match action {
        Action::HashLock {
            sender, recipient, ..
        } => vec![("sender", sender), ("recipient", recipient)],
        Action::Claim { recipient, .. } => vec![("recipient", recipient)],
        Action::Refund { owner, .. } => vec![("owner", owner)],
        Action::LicenseDvp {
            seller,
            buyer,
            payment_destination,
            ..
        } => vec![
            ("seller", seller),
            ("buyer", buyer),
            ("payment destination", payment_destination),
        ],
        Action::FiatLock { seller, buyer, .. } | Action::FiatRelease { seller, buyer, .. } => {
            vec![("seller", seller), ("buyer", buyer)]
        }
        Action::TreasuryRotate {
            current_address,
            new_address,
            ..
        } => vec![
            ("current address", current_address),
            ("new address", new_address),
        ],
    }
}

fn amount_fields(action: &mut Action) -> Vec<(&'static str, &mut Strikes)> {
    match action {
        Action::HashLock { amount, change, .. }
        | Action::Claim { amount, change, .. }
        | Action::Refund { amount, change, .. }
        | Action::FiatLock { amount, change, .. }
        | Action::FiatRelease { amount, change, .. } => {
            vec![("amount", amount), ("change", change)]
        }
        Action::LicenseDvp { price, change, .. } => vec![("price", price), ("change", change)],
        Action::TreasuryRotate { change, .. } => vec![("change", change)],
    }
}

fn change_of(action: &mut Action) -> &mut Strikes {
    match action {
        Action::HashLock { change, .. }
        | Action::Claim { change, .. }
        | Action::Refund { change, .. }
        | Action::LicenseDvp { change, .. }
        | Action::FiatLock { change, .. }
        | Action::FiatRelease { change, .. }
        | Action::TreasuryRotate { change, .. } => change,
    }
}

/// Re-point the native input identifiers at `inputs` (strictly increasing, as consensus requires).
fn set_inputs(wire: &mut NativeOperation, mut inputs: Vec<OutPoint>) {
    inputs.sort_by_key(native_input_id);
    wire.operation.meta.inputs = inputs.iter().map(native_input_id).collect();
    wire.inputs = inputs;
}

/// Money mutations of an unsigned native operation: every party field to a stranger and to the
/// reader, every amount up and down (with and without the fee or the change making up for it), the
/// fee against the change, an input removed and `spare` (another coin of the payer) added.
fn native_mutations(
    raw: &[u8],
    reader_address: Hash,
    spare: Option<(OutPoint, u64)>,
) -> Vec<(String, Vec<u8>)> {
    let base = NativeOperation::decode(raw).unwrap();
    let mut out = Vec::new();
    let mut push = |what: String, wire: NativeOperation| {
        if let Ok(bytes) = wire.encode() {
            out.push((what, bytes));
        }
    };
    let parties = {
        let mut copy = base.clone();
        party_fields(&mut copy.operation.action).len()
    };
    for index in 0..parties {
        for (label, to) in [("a stranger", stranger()), ("the reader", reader_address)] {
            let mut wire = base.clone();
            let mut fields = party_fields(&mut wire.operation.action);
            let (name, field) = &mut fields[index];
            if **field == to {
                continue;
            }
            let name = *name;
            **field = to;
            push(format!("{name} to {label}"), wire);
        }
    }
    let amounts = {
        let mut copy = base.clone();
        amount_fields(&mut copy.operation.action).len()
    };
    for index in 0..amounts {
        for delta in [-1_000i64, 1_000] {
            for compensate in [false, true] {
                let mut wire = base.clone();
                let fee = wire.operation.meta.fee.0;
                let mut fields = amount_fields(&mut wire.operation.action);
                let (name, field) = &mut fields[index];
                let name = *name;
                let Some(value) = field.0.checked_add_signed(delta) else {
                    continue;
                };
                field.0 = value;
                if compensate {
                    let Some(fee) = fee.checked_add_signed(-delta) else {
                        continue;
                    };
                    wire.operation.meta.fee = Strikes(fee);
                }
                push(
                    format!(
                        "{name} {delta:+}{}",
                        if compensate { " against the fee" } else { "" }
                    ),
                    wire,
                );
            }
        }
    }
    for delta in [-500i64, 500] {
        let mut wire = base.clone();
        let fee = wire.operation.meta.fee.0;
        let change = change_of(&mut wire.operation.action);
        let (Some(fee), Some(rest)) = (
            fee.checked_add_signed(delta),
            change.0.checked_add_signed(-delta),
        ) else {
            continue;
        };
        change.0 = rest;
        wire.operation.meta.fee = Strikes(fee);
        push(format!("fee {delta:+} against the change"), wire);
    }
    if base.inputs.len() > 1 {
        let mut wire = base.clone();
        let mut inputs = wire.inputs.clone();
        inputs.pop();
        set_inputs(&mut wire, inputs);
        push("an input removed".into(), wire);
    }
    if let Some((point, atoms)) = spare {
        for (label, to_change) in [
            ("the value unaccounted", false),
            ("the value as change", true),
        ] {
            let mut wire = base.clone();
            let mut inputs = wire.inputs.clone();
            inputs.push(point.clone());
            set_inputs(&mut wire, inputs);
            if to_change {
                change_of(&mut wire.operation.action).0 += atoms;
            }
            push(format!("an input added, {label}"), wire);
        }
    }
    out
}

fn lock_offer_world() -> (World, Vec<u8>, OutPoint) {
    let mut world = World::new(100);
    for key in [key_a(), key_b()] {
        world.state.wallets.register(&descriptor(&key, 1)).unwrap();
    }
    world.coin(address(&key_a(), 1), 5_000_000, 1, false, 1, 0);
    let spare = world.coin(address(&key_a(), 1), 300_000, 1, false, 3, 0);
    let maker = ckit::maker_key();
    let offer = ckit::signed_offer(
        &maker,
        ckit::context_of(&world.anchor),
        1,
        1000,
        1_000_000,
        1,
        6,
    );
    (world, ckit::offer_bytes(&offer), spare)
}

#[test]
fn a_hash_lock_built_elsewhere_hides_nothing_from_the_recipient_or_the_senders_offline_signer() {
    let (world, offer, spare) = lock_offer_world();
    let view = world.view();
    let planned = plan(
        &OperationRequest::HashLock(HashLockRequest::new(
            Blob::new(offer),
            address(&key_b(), 1),
            1_000_000,
            [9; 32],
            150,
        )),
        &view,
        &identity(&key_a()),
    )
    .unwrap();
    let raw = planned.objects()[0].bytes.clone();
    for (reader, reader_address) in [
        (identity(&key_b()), address(&key_b(), 1)),
        (identity(&key_a()), address(&key_a(), 1)),
    ] {
        let mine = |x: &Hash| *x == reader_address;
        let (refused, visible) = audit(
            "hash lock",
            &view,
            &reader,
            &raw,
            native_mutations(&raw, reader_address, Some((spare.clone(), 300_000))),
            &|raw| native_truth(raw, &view, &mine),
        );
        assert!(refused > 0 && visible > 0, "{refused} {visible}");
    }
}

#[test]
fn a_claim_and_a_refund_built_elsewhere_hide_nothing_from_their_offline_signers() {
    let lock_id = [0x6c; 32];
    let preimage = [0x42; 32];
    let lock = |world: &mut World| {
        for key in [key_a(), key_b()] {
            world.state.wallets.register(&descriptor(&key, 1)).unwrap();
        }
        world.state.protocol_records.insert(
            trading_v1::record_key(0, lock_id),
            NativeRecord::Lock(NativeLock {
                context: ckit::context_of(&world.anchor),
                trade: [0x21; 32],
                contract: [0x22; 32],
                generation: 1,
                sender: address(&key_a(), 1),
                recipient: address(&key_b(), 1),
                amount: Strikes(1_000_000),
                created_height: 90,
                kind: NativeLockKind::Hash {
                    condition: trading_v1::preimage_hash(&preimage),
                    refund_height: 150,
                },
            })
            .encode(lock_id)
            .unwrap(),
        );
    };
    // The claim, at head 100, by B.
    let mut world = World::new(100);
    lock(&mut world);
    world.coin(address(&key_b(), 1), 500_000, 1, false, 2, 0);
    let spare = world.coin(address(&key_b(), 1), 300_000, 1, false, 4, 0);
    let view = world.view();
    let claim = plan(
        &OperationRequest::ConditionalClaim(ClaimRequest::new(
            lock_id,
            Preimage::from_bytes(preimage),
        )),
        &view,
        &identity(&key_b()),
    )
    .unwrap();
    let raw = claim.objects()[0].bytes.clone();
    let mine = |x: &Hash| *x == address(&key_b(), 1);
    audit(
        "claim",
        &view,
        &identity(&key_b()),
        &raw,
        native_mutations(&raw, address(&key_b(), 1), Some((spare, 300_000))),
        &|raw| native_truth(raw, &view, &mine),
    );
    // The refund, at head 149, by A.
    let mut world = World::new(149);
    lock(&mut world);
    world.coin(address(&key_a(), 1), 300_000, 1, false, 3, 0);
    let spare = world.coin(address(&key_a(), 1), 200_000, 1, false, 5, 0);
    let view = world.view();
    let refund = plan(
        &OperationRequest::ConditionalRefund(RefundRequest::new(lock_id)),
        &view,
        &identity(&key_a()),
    )
    .unwrap();
    let raw = refund.objects()[0].bytes.clone();
    let mine = |x: &Hash| *x == address(&key_a(), 1);
    audit(
        "refund",
        &view,
        &identity(&key_a()),
        &raw,
        native_mutations(&raw, address(&key_a(), 1), Some((spare, 200_000))),
        &|raw| native_truth(raw, &view, &mine),
    );
}

#[test]
fn a_license_sale_built_elsewhere_hides_nothing_from_the_seller_or_the_buyers_offline_signer() {
    let mut world = World::new(100);
    for key in [key_a(), key_b()] {
        world.state.wallets.register(&descriptor(&key, 1)).unwrap();
    }
    let license = trading::install_licenses(&mut world.state, address(&key_a(), 1), false);
    trading::install_award(&mut world.state, &key_c(), 1_200_000, 0xd1);
    world.coin(address(&key_b(), 1), 5_000_000, 1, false, 0xb1, 0);
    let spare = world.coin(address(&key_b(), 1), 3_000_000, 1, false, 0xb2, 0);
    let maker = trading::maker();
    let offer = trading::offer(
        &maker,
        trading::context_of(&world.anchor),
        trading::license_terms(license, 1, 2_000_000),
        50,
        200,
        0,
        0x31,
    );
    let view = world.view();
    let planned = plan(
        &OperationRequest::LicenseDvp(
            LicenseDvpRequest::new(Blob::new(trading::offer_bytes(&offer)), license)
                .with_commitments([0x71; 32], [0x72; 32]),
        ),
        &view,
        &identity(&key_b()),
    )
    .unwrap();
    let raw = planned.objects()[0].bytes.clone();
    for (reader, reader_address) in [
        (identity(&key_a()), address(&key_a(), 1)),
        (identity(&key_b()), address(&key_b(), 1)),
    ] {
        let mine = |x: &Hash| *x == reader_address;
        let (refused, visible) = audit(
            "License sale",
            &view,
            &reader,
            &raw,
            native_mutations(&raw, reader_address, Some((spare.clone(), 3_000_000))),
            &|raw| native_truth(raw, &view, &mine),
        );
        assert!(refused > 0 && visible > 0, "{refused} {visible}");
    }
}

#[test]
fn a_fiat_lock_and_release_built_elsewhere_hide_nothing_from_either_party() {
    let mut world = World::new(100);
    for key in [key_a(), key_b()] {
        world.state.wallets.register(&descriptor(&key, 1)).unwrap();
    }
    world.coin(address(&key_a(), 1), 5_000_000, 1, false, 0xa1, 0);
    let seller_spare = world.coin(address(&key_a(), 1), 400_000, 1, false, 0xa2, 0);
    world.coin(address(&key_b(), 1), 1_000_000, 1, false, 0xb1, 0);
    let buyer_spare = world.coin(address(&key_b(), 1), 200_000, 1, false, 0xb2, 0);
    let maker = trading::maker();
    let offer = trading::offer(
        &maker,
        trading::context_of(&world.anchor),
        trading::fiat_terms(1_500_000, [0x77; 32]),
        50,
        200,
        0,
        0x41,
    );
    // The lock: the seller (A) plans it; the buyer (B) adopts, and A's offline signer too.
    {
        let view = world.view();
        let planned = plan(
            &OperationRequest::FiatLock(
                FiatLockRequest::new(
                    Blob::new(trading::offer_bytes(&offer)),
                    address(&key_b(), 1),
                    1_500_000,
                    [0x77; 32],
                )
                .with_commitments([0x71; 32], [0x72; 32]),
            ),
            &view,
            &identity(&key_a()),
        )
        .unwrap();
        let raw = planned.objects()[0].bytes.clone();
        for (reader, reader_address, spare) in [
            (identity(&key_b()), address(&key_b(), 1), &buyer_spare),
            (identity(&key_a()), address(&key_a(), 1), &seller_spare),
        ] {
            let mine = |x: &Hash| *x == reader_address;
            audit(
                "fiat lock",
                &view,
                &reader,
                &raw,
                native_mutations(&raw, reader_address, Some((spare.clone(), 1))),
                &|raw| native_truth(raw, &view, &mine),
            );
        }
    }
    // The release of a fiat lock on chain: the buyer (B) plans and pays the fee; the seller (A)
    // adopts, and B's offline signer too.
    let lock_id = [0x6a; 32];
    let context = trading::context_of(&world.anchor);
    world.state.protocol_records.insert(
        trading_v1::record_key(0, lock_id),
        NativeRecord::Lock(NativeLock {
            context: context.clone(),
            trade: [0x71; 32],
            contract: [0x72; 32],
            generation: 1,
            sender: address(&key_a(), 1),
            recipient: address(&key_b(), 1),
            amount: Strikes(1_500_000),
            created_height: 50,
            kind: NativeLockKind::Fiat { terms: [0x77; 32] },
        })
        .encode(lock_id)
        .unwrap(),
    );
    let consumed = trading_v1::single_fill_key(&context, [0; 32], [0x6f; 32]);
    world.state.protocol_records.insert(
        trading_v1::record_key(1, consumed),
        NativeRecord::Consumed {
            context,
            offer: [0x6f; 32],
            trade: [0x71; 32],
            contract: [0x72; 32],
        }
        .encode(consumed)
        .unwrap(),
    );
    let view = world.view();
    let planned = plan(
        &OperationRequest::FiatRelease(FiatReleaseRequest::new(lock_id)),
        &view,
        &identity(&key_b()),
    )
    .unwrap();
    let raw = planned.objects()[0].bytes.clone();
    for (reader, reader_address, spare) in [
        (identity(&key_a()), address(&key_a(), 1), &seller_spare),
        (identity(&key_b()), address(&key_b(), 1), &buyer_spare),
    ] {
        let mine = |x: &Hash| *x == reader_address;
        audit(
            "fiat release",
            &view,
            &reader,
            &raw,
            native_mutations(&raw, reader_address, Some((spare.clone(), 1))),
            &|raw| native_truth(raw, &view, &mine),
        );
    }
}

#[test]
fn a_treasury_destination_rotation_built_elsewhere_hides_nothing_from_its_offline_signer() {
    let mut world = World::new(100);
    world
        .state
        .wallets
        .register(&descriptor(&key_b(), 1))
        .unwrap();
    world.state.dividends =
        DividendState::genesis(Treasury::new(Class::TestValue, descriptor(&key_b(), 1)).unwrap());
    world.coin(address(&key_b(), 1), 5_000_000, 1, false, 0xd1, 0);
    let spare = world.coin(address(&key_b(), 1), 300_000, 1, false, 0xd2, 0);
    let treasury_authority = address(&key_b(), 1);
    let mut fixture_rotation = mutiny_consensus_v8::wallet_rotation_v1::Rotation {
        network: world.anchor.network,
        genesis: world.anchor.genesis,
        fingerprint: world.anchor.fingerprint,
        authority: treasury_authority,
        current: descriptor(&key_b(), 1),
        proposed: descriptor(&key_c(), 2),
        created_height: 90,
        expiry_height: 200,
        authorization: mutiny_crypto_v2::HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
        possession: mutiny_crypto_v2::HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
    };
    fixture_rotation.sign(&key_b(), &key_c()).unwrap();
    world
        .state
        .wallets
        .apply(
            &fixture_rotation,
            world.anchor.genesis,
            world.anchor.fingerprint,
            101,
        )
        .unwrap();
    let context = tkit::context_of(&world.anchor);
    for (key, raw) in
        trading_v1::treasury_genesis_records(&context, treasury_authority, descriptor(&key_b(), 1))
            .unwrap()
    {
        world.state.protocol_records.insert(key, raw);
    }
    let view = world.view();
    let me = profile::declare(
        SignerIdentity::from_public(key_c().public(), 2, Some(treasury_authority)).unwrap(),
        &TreasuryDeclaration::new(view.context().genesis, ChainClass::TestValue)
            .with_authority()
            .with_destination_of(treasury_authority),
        &view,
    )
    .unwrap();
    let planned = plan(
        &OperationRequest::TreasuryRotate(
            TreasuryRotateRequest::new(Blob::new(descriptor(&key_c(), 2))).with_verified_restore(
                treasury_authority,
                rotation::descriptor_fingerprint(&descriptor(&key_c(), 2)),
            ),
        ),
        &view,
        &me,
    )
    .unwrap();
    let raw = planned.objects()[0].bytes.clone();
    let mine = |x: &Hash| *x == address(&key_b(), 1);
    // R2 requires fresh host restore evidence in a locally reviewed plan.
    // Bare wire bytes carry no such assertion, so offline adoption cannot
    // silently manufacture it. Still audit every money row of the valid plan.
    let reviewed = review(&planned, &view).unwrap();
    assert_eq!(
        hidden(
            &native_truth(&raw, &view, &mine),
            &shown(&reviewed),
            &reviewed.render_text(),
            &mine
        ),
        None
    );
    let mutations = native_mutations(&raw, address(&key_b(), 1), Some((spare, 300_000)));
    assert!(mutations.len() >= 4);
    for (label, bytes) in std::iter::once(("unmodified bare R2".to_string(), raw)).chain(mutations)
    {
        assert!(
            adopt(&bytes, &view, &me).is_err(),
            "R2 bare adoption requires fresh host restore evidence: {label}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Protocol payouts
// ---------------------------------------------------------------------------------------------

#[test]
fn a_dividend_claim_built_elsewhere_shows_its_destination_and_amount_to_its_offline_signer() {
    let world = dividend::ClaimWorld::new(3, 1_200_000);
    let view = world.view();
    let me = dividend::identity(&dividend::owner_key());
    let planned = plan(
        &OperationRequest::DividendClaim(DividendClaimRequest::new(
            dividend::license_id(1),
            dividend::P,
            12_345,
            dividend::address(&dividend::other_key(), 1),
        )),
        &view,
        &me,
    )
    .unwrap();
    let raw = planned.objects()[0].bytes.clone();
    let base = SignedClaim::decode(&raw).unwrap();
    let mut mutations = Vec::new();
    for (what, destination) in [
        ("destination to a stranger", stranger()),
        (
            "destination to the owner",
            dividend::address(&dividend::owner_key(), 1),
        ),
    ] {
        let mut claim = base.clone();
        claim.body.destination = destination;
        mutations.push((what.to_string(), claim.encode()));
    }
    for delta in [-345i64, 1_000] {
        let mut claim = base.clone();
        claim.body.amount = claim.body.amount.checked_add_signed(delta).unwrap();
        mutations.push((format!("amount {delta:+}"), claim.encode()));
    }
    let owner = dividend::address(&dividend::owner_key(), 1);
    let (refused, visible) = audit("dividend claim", &view, &me, &raw, mutations, &|raw| {
        let claim = SignedClaim::decode(raw).unwrap();
        let mut truth = Truth {
            mine_in: 0,
            mine_back: 0,
            to_others: Vec::new(),
            fee: 0,
            fee_mine: false,
        };
        if claim.body.destination == owner {
            truth.mine_back += u128::from(claim.body.amount);
        } else {
            truth
                .to_others
                .push((claim.body.destination, claim.body.amount));
        }
        truth
    });
    assert!(visible >= 3, "{refused} {visible}");
}
