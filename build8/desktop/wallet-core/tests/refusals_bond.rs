//! The bond refusal table: every refusal of the wallet core that applies to bond creation, unbond
//! and withdrawal, and every consensus rejection reason of those operations. Each refusal changes no
//! state and returns no signed bytes; where consensus has a public pure check (`FundedBondCreate::verify`,
//! `verify_command`, `Lot::start_unbond`, `Lot::withdraw`, `settle_commands`) the test asserts that
//! consensus refuses the equivalent hand-signed bytes too. Creation rules that only full block
//! execution enforces (atomic funding, node, minimum) are compared with consensus block execution
//! in `e2e_bond.rs`. NATIVE, TEST-VALUE; public test keys and public synthetic fixtures only.
#[path = "support/bond_support.rs"]
mod bond_support;

use bond_support::{
    flow,
    world::{BondWorld, address, descriptor, identity, key_a, key_b},
};
use mutiny_consensus_v8::{
    Hash,
    anchors::FinalizedAnchor,
    bond_create_v3::{FundedBondCreate, PartialBondCreate, UnsignedBondCreate},
    bond_ops_v2::{Action, Operation, settle_commands},
    bonds::{LotStatus, MINIMUM_ATOMS},
    dividend_state_v1::DividendState,
    evidence_history_v2::History,
    op_envelope_v1::Envelope,
    transactions::{Coin, OutPoint, Output},
    treasury_v1::{Class, Treasury},
    wallet_rotation_v1::Rotation,
};
use mutiny_crypto_v2::{HybridKey, HybridSignature};
use mutiny_wallet_core_v8::{
    ops::bond::{
        ALREADY_SIGNED, LOT_CAPACITY, NONCE_REQUIRED, OWNER_MISMATCH, export_unsigned, lot_resource,
    },
    *,
};
use std::collections::BTreeSet;

const FUNDS: u64 = 30_000_000_000;
const PRINCIPAL: u64 = 15_000_000_000;
const HEAD: u64 = 100;

fn zero() -> HybridSignature {
    HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    }
}

fn create(node: Hash, nonce: Hash) -> OperationRequest {
    OperationRequest::BondCreate(BondCreateRequest::new(node, 1, PRINCIPAL, nonce))
}
fn unbond(lot: Hash) -> OperationRequest {
    OperationRequest::BondUnbond(BondUnbondRequest::new(lot))
}
fn withdraw(lot: Hash) -> OperationRequest {
    OperationRequest::BondWithdraw(BondWithdrawRequest::new(lot))
}

/// The fixture world at HEAD with one 300 MUT coin of key A.
fn funded() -> BondWorld {
    let mut world = BondWorld::new(HEAD);
    world.coin(address(&key_a(), 1), FUNDS, 1, false, 0x31, 0);
    world
}

/// The lot identifier a creation by `owner` for `node` with `nonce` derives (consensus code).
fn lot_id_of(world: &BondWorld, owner: Hash, nonce: Hash) -> Hash {
    UnsignedBondCreate {
        genesis: world.anchor.genesis,
        fingerprint: world.anchor.fingerprint,
        envelope: Envelope::from_head(&world.anchor, 144, Vec::new()).unwrap(),
        owner,
        owner_descriptor: descriptor(&key_a(), 1),
        node: world.node(),
        node_generation: 1,
        nonce,
        principal: PRINCIPAL,
        fee: 0,
        inputs: vec![world_first()],
        change: None,
    }
    .lot_id()
}

/// An unbond or withdrawal for the block after `parent`, signed with consensus' own signer.
fn command(
    parent: &FinalizedAnchor,
    key: &HybridKey,
    generation: u64,
    owner: Hash,
    action: Action,
) -> Operation {
    let mut op = Operation {
        genesis: parent.genesis,
        fingerprint: parent.fingerprint,
        envelope: Envelope::from_head(parent, 144, Vec::new()).unwrap(),
        owner,
        authorizer: descriptor(key, generation),
        action,
        signature: zero(),
    };
    op.sign(key).unwrap();
    op
}

/// Nothing was queued and nothing is reserved.
fn assert_untouched(outbox: &MemoryOutbox) {
    assert!(outbox.records().unwrap().is_empty());
    assert!(outbox.reserved().unwrap().is_empty());
}

// ---------------------------------------------------------------------------------------------
// Creation
// ---------------------------------------------------------------------------------------------

#[test]
fn creation_requests_are_refused_with_typed_reasons() {
    let a = key_a();
    let me = identity(&a);
    let world = funded();
    let node = world.node();
    let view = world.view();
    let outbox = MemoryOutbox::new();

    // Below the 100 MUT minimum (consensus: the funding coin must hold bonds::MINIMUM_ATOMS).
    let mut small = BondCreateRequest::new(node, 1, MINIMUM_ATOMS - 1, [1; 32]);
    assert_eq!(
        plan(&OperationRequest::BondCreate(small), &view, &me).unwrap_err(),
        Refusal::BelowMinimumBond {
            minimum: MINIMUM_ATOMS
        }
    );
    small = BondCreateRequest::new(node, 1, MINIMUM_ATOMS, [1; 32]);
    assert!(
        plan(&OperationRequest::BondCreate(small), &view, &me).is_ok(),
        "exactly the minimum is accepted"
    );
    // A zero nonce (wallet policy: a lot identifier must come from a fresh nonce).
    assert_eq!(
        plan(&create(node, [0; 32]), &view, &me).unwrap_err(),
        Refusal::InvalidRequest(NONCE_REQUIRED)
    );
    // Wrong node, wrong generation.
    assert_eq!(
        plan(&create([0x98; 32], [1; 32]), &view, &me).unwrap_err(),
        Refusal::NodeNotEligible
    );
    assert_eq!(
        plan(
            &OperationRequest::BondCreate(BondCreateRequest::new(node, 2, PRINCIPAL, [1; 32])),
            &view,
            &me
        )
        .unwrap_err(),
        Refusal::NodeNotEligible
    );
    // Q16: a node this wallet does not own (the node owner is key A; key B asks).
    let mut b_funded = funded();
    b_funded.coin(address(&key_b(), 1), FUNDS, 1, false, 0x41, 0);
    assert_eq!(
        plan(
            &create(node, [1; 32]),
            &b_funded.view(),
            &identity(&key_b())
        )
        .unwrap_err(),
        Refusal::NotRequiredSigner(Slot::BondOwner)
    );
    // Funds.
    let empty = BondWorld::new(HEAD);
    assert_eq!(
        plan(&create(node, [1; 32]), &empty.view(), &me).unwrap_err(),
        Refusal::NothingSpendable
    );
    let mut poor = BondWorld::new(HEAD);
    poor.coin(address(&a, 1), PRINCIPAL, 1, false, 0x31, 0);
    assert!(matches!(
        plan(&create(node, [1; 32]), &poor.view(), &me).unwrap_err(),
        Refusal::InsufficientFunds { available, requested }
            if available == PRINCIPAL && requested > PRINCIPAL
    ));
    // The lot identifier is taken (consensus: Duplicate).
    let mut taken = funded();
    let id = lot_id_of(&taken, address(&a, 1), [7; 32]);
    taken.lot(
        0,
        address(&a, 1),
        MINIMUM_ATOMS,
        5,
        0,
        None,
        None,
        LotStatus::Active,
    );
    let lot = taken.state.bonds_v2.lots.remove(&[0; 32]).unwrap();
    let mut lot = lot;
    lot.0.id = id;
    taken.state.bonds_v2.lots.insert(id, lot);
    assert_eq!(
        plan(&create(node, [7; 32]), &taken.view(), &me).unwrap_err(),
        Refusal::Replay
    );
    // The lot is reserved by another queued operation.
    let mut held = funded();
    held.reserved
        .insert(lot_resource(&lot_id_of(&held, address(&a, 1), [7; 32])));
    assert_eq!(
        plan(&create(node, [7; 32]), &held.view(), &me).unwrap_err(),
        Refusal::ReservedInput
    );
    // The node's lineage already holds 64 locked lots (consensus: bonds_v2 capacity).
    let mut full = funded();
    for tag in 0..64u8 {
        full.lot(
            tag,
            address(&a, 1),
            MINIMUM_ATOMS,
            5,
            0,
            None,
            None,
            LotStatus::Active,
        );
    }
    assert_eq!(
        plan(&create(node, [1; 32]), &full.view(), &me).unwrap_err(),
        Refusal::InvalidRequest(LOT_CAPACITY)
    );
    // Not physical, not eligible.
    for flag in ["physical", "eligible"] {
        let mut world = funded();
        let member = &mut world.state.continuity.as_mut().unwrap().members[0];
        if flag == "physical" {
            member.physical = false;
        } else {
            member.eligible = false;
        }
        assert_eq!(
            plan(&create(node, [1; 32]), &world.view(), &me).unwrap_err(),
            Refusal::NodeNotEligible,
            "{flag}"
        );
    }
    // The Treasury authority bonds only through the Treasury profile.
    let mut treasury = funded();
    treasury.state.wallets.register(&descriptor(&a, 1)).unwrap();
    treasury.state.dividends =
        DividendState::genesis(Treasury::new(Class::TestValue, descriptor(&a, 1)).unwrap());
    assert_eq!(
        plan(&create(node, [1; 32]), &treasury.view(), &me).unwrap_err(),
        Refusal::TreasuryProfileRequired
    );
    let treasury_me = identity(&a).with_treasury_roles_for_test(TreasuryRoles {
        authority: true,
        destination_of: None,
    });
    let planned = plan(&create(node, [1; 32]), &treasury.view(), &treasury_me).unwrap();
    let reviewed = review(&planned, &treasury.view()).unwrap();
    assert!(
        reviewed
            .warnings()
            .iter()
            .any(|w| w.code == "TREASURY_FUNDS")
    );
    assert!(
        reviewed
            .acknowledgements()
            .contains(&AckKind::TreasuryAuthority)
    );
    assert_eq!(
        adopt(&export_unsigned(&planned).unwrap(), &treasury.view(), &me).unwrap_err(),
        Refusal::TreasuryProfileRequired,
        "adoption holds the plan to the same rule"
    );
    // Nothing above produced a signature or touched an outbox.
    assert_untouched(&outbox);
}

#[test]
fn a_rotated_away_key_cannot_bond_and_the_new_key_can() {
    let a = key_a();
    let b = key_b();
    let mut world = funded();
    let owner = address(&a, 1);
    world.state.wallets.register(&descriptor(&a, 1)).unwrap();
    let node = world.node();
    // Planned and approved before the rotation.
    let before = plan(&create(node, [3; 32]), &world.view(), &identity(&a)).unwrap();
    let mut rotation = Rotation {
        network: world.anchor.network,
        genesis: world.anchor.genesis,
        fingerprint: world.anchor.fingerprint,
        authority: owner,
        current: descriptor(&a, 1),
        proposed: descriptor(&b, 2),
        created_height: 90,
        expiry_height: 120,
        authorization: zero(),
        possession: zero(),
    };
    rotation.sign(&a, &b).unwrap();
    world
        .state
        .wallets
        .apply(
            &rotation,
            world.anchor.genesis,
            world.anchor.fingerprint,
            HEAD,
        )
        .unwrap();
    let view = world.view();
    // The old key: refused at planning and at review of the earlier plan.
    assert_eq!(
        plan(&create(node, [4; 32]), &view, &identity(&a)).unwrap_err(),
        Refusal::StaleAuthority
    );
    assert_eq!(review(&before, &view).unwrap_err(), Refusal::StaleAuthority);
    // The new key of the same authority bonds for the node (the node owner is the authority's
    // original AddressID, which now resolves to the new key).
    let rotated = SignerIdentity::from_public(b.public(), 2, Some(owner)).unwrap();
    let planned = plan(&create(node, [4; 32]), &view, &rotated).unwrap();
    let signer =
        KeySigner::new_rotated(key_b(), 2, owner, SigningGate::test_value().unwrap()).unwrap();
    let signed = flow::sign(planned, &signer, &view).unwrap();
    let native = FundedBondCreate::decode(signed.bytes()).unwrap();
    assert_eq!(
        native.unsigned.owner, owner,
        "the immutable original AddressID owns the lot"
    );
    native
        .verify(&world.state, &world.anchor, &History::default())
        .unwrap();
    let mut old = native.unsigned.clone();
    old.owner_descriptor = descriptor(&a, 1);
    let old = FundedBondCreate::sign(old, &a).unwrap();
    assert!(
        old.verify(&world.state, &world.anchor, &History::default())
            .is_err()
    );
}

/// A valid unsigned creation of key A in the funded world, as (plan, transfer, operation).
fn base_creation(world: &BondWorld) -> (OperationPlan, UnsignedBondCreate) {
    let planned = plan(
        &create(world.node(), [5; 32]),
        &world.view(),
        &identity(&key_a()),
    )
    .unwrap();
    let u = PartialBondCreate::decode(&planned.objects()[0].bytes)
        .unwrap()
        .unsigned;
    (planned, u)
}
fn native_bytes(u: &UnsignedBondCreate) -> Vec<u8> {
    PartialBondCreate::new(u.clone()).encode().unwrap()
}

#[test]
fn creation_bytes_from_elsewhere_are_refused_field_by_field() {
    let world = funded();
    let view = world.view();
    let me = identity(&key_a());
    let (_, base) = base_creation(&world);
    type Edit = Box<dyn Fn(&mut UnsignedBondCreate)>;
    let cases: Vec<(&str, Edit)> = vec![
        (
            "missing input",
            Box::new(|u| u.inputs[0].transaction = [0xee; 32]),
        ),
        ("wrong input index", Box::new(|u| u.inputs[0].index += 1)),
        (
            "change to another wallet",
            Box::new(|u| u.change.as_mut().unwrap().owner = address(&key_b(), 1)),
        ),
        (
            "conservation",
            Box::new(|u| u.change.as_mut().unwrap().atoms -= 1),
        ),
        (
            "fee below complete signed size",
            Box::new(|u| {
                u.fee -= 1;
                u.change.as_mut().unwrap().atoms += 1;
            }),
        ),
        (
            "canonical reference",
            Box::new(|u| u.envelope.reference_block[3] ^= 1),
        ),
        (
            "future first height",
            Box::new(|u| u.envelope.first_height += 1),
        ),
        ("genesis", Box::new(|u| u.genesis[0] ^= 1)),
        ("fingerprint", Box::new(|u| u.fingerprint[0] ^= 1)),
        (
            "wrong immutable owner",
            Box::new(|u| u.owner = address(&key_b(), 1)),
        ),
        (
            "wrong current descriptor",
            Box::new(|u| u.owner_descriptor = descriptor(&key_b(), 1)),
        ),
        ("unknown node", Box::new(|u| u.node = [0x98; 32])),
        (
            "stale hardware generation",
            Box::new(|u| u.node_generation = 2),
        ),
    ];
    for (label, edit) in cases {
        let mut u = base.clone();
        edit(&mut u);
        let raw = native_bytes(&u);
        assert!(explain(&raw, &view, &me).is_err(), "explain: {label}");
        assert!(adopt(&raw, &view, &me).is_err(), "adopt: {label}");
        assert!(
            PartialBondCreate::new(u)
                .preflight(&world.state, &world.anchor, &History::default())
                .is_err(),
            "native consensus: {label}"
        );
    }
    // Native unrepresentable classes cannot become a signed/reviewed object at all.
    let mut u = base.clone();
    u.principal = MINIMUM_ATOMS - 1;
    assert!(u.encode().is_err());
    let mut u = base.clone();
    u.inputs.clear();
    assert!(u.encode().is_err());
    let mut u = base.clone();
    u.inputs.push(u.inputs[0].clone());
    assert!(u.encode().is_err());
    let mut u = base.clone();
    u.change.as_mut().unwrap().owner = [0; 32];
    assert!(u.encode().is_err());
    assert_eq!(
        adopt(&native_bytes(&base), &view, &identity(&key_b())).unwrap_err(),
        Refusal::NotRequiredSigner(Slot::BondOwner)
    );
}

#[test]
fn creation_signature_parity_with_verify_owner_for_every_field() {
    let world = funded();
    let view = world.view();
    let (planned, base) = base_creation(&world);
    let signer = KeySigner::for_test(key_a()).unwrap();
    let signed = flow::sign(planned, &signer, &view).unwrap();
    let native = FundedBondCreate::decode(signed.bytes()).unwrap();
    native
        .verify(&world.state, &world.anchor, &History::default())
        .unwrap();
    assert!(SignedOperation::import(signed.bytes(), &view).is_ok());
    type Edit = Box<dyn Fn(&mut UnsignedBondCreate)>;
    let edits: Vec<(&str, Edit)> = vec![
        ("genesis", Box::new(|u| u.genesis[1] ^= 1)),
        ("fingerprint", Box::new(|u| u.fingerprint[1] ^= 1)),
        ("first height", Box::new(|u| u.envelope.first_height += 1)),
        ("last height", Box::new(|u| u.envelope.last_height += 1)),
        (
            "reference height",
            Box::new(|u| u.envelope.reference_height -= 1),
        ),
        (
            "reference block",
            Box::new(|u| u.envelope.reference_block[1] ^= 1),
        ),
        ("owner", Box::new(|u| u.owner = address(&key_b(), 1))),
        (
            "descriptor",
            Box::new(|u| u.owner_descriptor = descriptor(&key_b(), 1)),
        ),
        ("node", Box::new(|u| u.node[0] ^= 1)),
        ("hardware generation", Box::new(|u| u.node_generation += 1)),
        ("nonce", Box::new(|u| u.nonce[0] ^= 1)),
        (
            "principal",
            Box::new(|u| {
                u.principal += 1;
                u.change.as_mut().unwrap().atoms -= 1;
            }),
        ),
        (
            "fee",
            Box::new(|u| {
                u.fee += 1;
                u.change.as_mut().unwrap().atoms -= 1;
            }),
        ),
        ("input", Box::new(|u| u.inputs[0].index += 1)),
        (
            "change",
            Box::new(|u| u.change.as_mut().unwrap().atoms -= 1),
        ),
    ];
    for (label, edit) in edits {
        let mut changed = native.clone();
        edit(&mut changed.unsigned);
        assert!(
            changed
                .verify(&world.state, &world.anchor, &History::default())
                .is_err(),
            "native consensus: {label}"
        );
        assert!(
            SignedOperation::import(&changed.encode().unwrap(), &view).is_err(),
            "wallet: {label}"
        );
    }
    for slot in 0..2 {
        for half in 0..2 {
            let mut changed = native.clone();
            let signature = if slot == 0 {
                &mut changed.create
            } else {
                &mut changed.funding
            };
            if half == 0 {
                signature.ed448[7] ^= 1;
            } else {
                signature.fndsa[600] ^= 1;
            }
            assert!(
                changed
                    .verify(&world.state, &world.anchor, &History::default())
                    .is_err()
            );
            assert!(SignedOperation::import(&changed.encode().unwrap(), &view).is_err());
        }
    }
    for slot in 0..2 {
        let mut stripped = native.as_partial();
        if slot == 0 {
            stripped.create = None;
        } else {
            stripped.funding = None;
        }
        assert!(FundedBondCreate::decode(&stripped.encode().unwrap()).is_err());
        assert!(SignedOperation::import(&stripped.encode().unwrap(), &view).is_err());
    }
    let fresh = FundedBondCreate::sign(base, &key_a()).unwrap();
    assert!(
        fresh
            .verify(&world.state, &world.anchor, &History::default())
            .is_ok()
    );
}

// ---------------------------------------------------------------------------------------------
// Unbond and withdrawal
// ---------------------------------------------------------------------------------------------

/// A world at `head` holding one lot of key A with the given state.
fn with_lot(
    head: u64,
    created: u64,
    sequence: u64,
    unbond: Option<u64>,
    settled: Option<u64>,
    status: LotStatus,
) -> (BondWorld, Hash) {
    let mut world = BondWorld::new(head);
    let id = world.lot(
        0x51,
        address(&key_a(), 1),
        PRINCIPAL,
        created,
        sequence,
        unbond,
        settled,
        status,
    );
    (world, id)
}

fn unbond_action(lot: Hash, sequence: u64) -> Action {
    Action::Unbond { lot, sequence }
}
fn withdraw_action(lot: Hash, sequence: u64) -> Action {
    Action::Withdraw { lot, sequence }
}

/// The wallet refuses at planning and on import of the hand-signed equivalent; consensus refuses
/// the same bytes through `verify_command` (and, when the lot exists, `settle_commands`).
fn refused_everywhere(
    world: &BondWorld,
    request: &OperationRequest,
    action: Action,
    expected: Refusal,
) {
    let a = key_a();
    let view = world.view();
    let lot_id = match &action {
        Action::Unbond { lot, .. } | Action::Withdraw { lot, .. } => *lot,
    };
    assert_eq!(
        plan(request, &view, &identity(&a)).unwrap_err(),
        expected,
        "planning"
    );
    let op = command(&world.anchor, &a, 1, address(&a, 1), action);
    assert_eq!(
        SignedOperation::import(&op.encode().unwrap(), &view).unwrap_err(),
        expected,
        "import of the hand-signed bytes"
    );
    match world.state.bonds_v2.lots.get(&lot_id) {
        Some(lot) => {
            assert!(
                op.verify_command(
                    &world.anchor,
                    &History::default(),
                    &world.state.wallets,
                    lot
                )
                .is_err(),
                "verify_command must refuse ({expected:?})"
            );
            assert!(
                settle_commands(
                    &world.anchor,
                    &History::default(),
                    &world.state.wallets,
                    &world.state.bonds_v2,
                    &world.state.penalties_v2,
                    &[op],
                    &[]
                )
                .is_err(),
                "settle_commands must refuse ({expected:?})"
            );
        }
        None => assert!(
            settle_commands(
                &world.anchor,
                &History::default(),
                &world.state.wallets,
                &world.state.bonds_v2,
                &world.state.penalties_v2,
                &[op],
                &[]
            )
            .is_err(),
            "settle_commands must refuse an unknown lot"
        ),
    }
}

#[test]
fn unbond_refusals_agree_with_consensus() {
    // Active lot created at 10, sequence 0, head 100.
    let (world, lot) = with_lot(HEAD, 10, 0, None, None, LotStatus::Active);
    // Wrong sequence (only for bytes: a plan always derives the sequence).
    let op = command(
        &world.anchor,
        &key_a(),
        1,
        address(&key_a(), 1),
        unbond_action(lot, 2),
    );
    assert_eq!(
        SignedOperation::import(&op.encode().unwrap(), &world.view()).unwrap_err(),
        Refusal::WrongSequence { expected: 1 }
    );
    assert!(
        op.verify_command(
            &world.anchor,
            &History::default(),
            &world.state.wallets,
            &world.state.bonds_v2.lots[&lot]
        )
        .is_err()
    );
    // Not Active: already unbonding, withdrawn, burned.
    let (unbonding, lot) = with_lot(HEAD, 10, 1, Some(20), None, LotStatus::Unbonding);
    refused_everywhere(
        &unbonding,
        &unbond(lot),
        unbond_action(lot, 2),
        Refusal::LotNotActive("unbonding"),
    );
    let (withdrawn, lot) = with_lot(
        300_000,
        10,
        2,
        Some(20),
        Some(259_210),
        LotStatus::Withdrawn,
    );
    refused_everywhere(
        &withdrawn,
        &unbond(lot),
        unbond_action(lot, 3),
        Refusal::LotNotActive("withdrawn"),
    );
    let (burned, lot) = with_lot(HEAD, 10, 0, None, Some(50), LotStatus::Burned);
    refused_everywhere(
        &burned,
        &unbond(lot),
        unbond_action(lot, 1),
        Refusal::LotBurned,
    );
    // Not above the lock start (consensus: Lot::start_unbond needs height > created).
    let (fresh, lot) = with_lot(HEAD, HEAD + 1, 0, None, None, LotStatus::Active);
    refused_everywhere(
        &fresh,
        &unbond(lot),
        unbond_action(lot, 1),
        Refusal::NotYetEligible {
            what: "Unbonding this lot",
            height: HEAD + 2,
        },
    );
    // An unknown lot.
    let (world, _) = with_lot(HEAD, 10, 0, None, None, LotStatus::Active);
    refused_everywhere(
        &world,
        &unbond([0x77; 32]),
        unbond_action([0x77; 32], 1),
        Refusal::LotUnknown,
    );
}

#[test]
fn withdrawal_refusals_agree_with_consensus() {
    // B = 10, U = 20: floor = max(10 + 259,200, 20 + 43,200) = 259,210.
    let floor = 259_210;
    // One block early (the head is floor - 2, so the next block is floor - 1).
    let (early, lot) = with_lot(floor - 2, 10, 1, Some(20), None, LotStatus::Unbonding);
    refused_everywhere(
        &early,
        &withdraw(lot),
        withdraw_action(lot, 2),
        Refusal::NotYetEligible {
            what: "Withdrawing this lot",
            height: floor,
        },
    );
    let mut copy = early.state.bonds_v2.lots[&lot].clone();
    assert!(copy.withdraw(floor - 1, 2).is_err());
    assert_eq!(copy.withdraw(floor, 2).unwrap(), PRINCIPAL);
    // At the floor it is accepted by both.
    let (ready, lot) = with_lot(floor - 1, 10, 1, Some(20), None, LotStatus::Unbonding);
    assert!(plan(&withdraw(lot), &ready.view(), &identity(&key_a())).is_ok());
    let op = command(
        &ready.anchor,
        &key_a(),
        1,
        address(&key_a(), 1),
        withdraw_action(lot, 2),
    );
    op.verify_command(
        &ready.anchor,
        &History::default(),
        &ready.state.wallets,
        &ready.state.bonds_v2.lots[&lot],
    )
    .unwrap();
    assert!(SignedOperation::import(&op.encode().unwrap(), &ready.view()).is_ok());
    // Not unbonding: Active, withdrawn, burned.
    let (active, lot) = with_lot(floor, 10, 0, None, None, LotStatus::Active);
    refused_everywhere(
        &active,
        &withdraw(lot),
        withdraw_action(lot, 1),
        Refusal::LotNotUnbonding("active"),
    );
    let (done, lot) = with_lot(
        floor + 5,
        10,
        2,
        Some(20),
        Some(floor),
        LotStatus::Withdrawn,
    );
    refused_everywhere(
        &done,
        &withdraw(lot),
        withdraw_action(lot, 3),
        Refusal::LotNotUnbonding("withdrawn"),
    );
    let (burned, lot) = with_lot(floor, 10, 1, Some(20), Some(30), LotStatus::Burned);
    refused_everywhere(
        &burned,
        &withdraw(lot),
        withdraw_action(lot, 2),
        Refusal::LotBurned,
    );
    // Wrong sequence.
    let (ready, lot) = with_lot(floor, 10, 1, Some(20), None, LotStatus::Unbonding);
    let op = command(
        &ready.anchor,
        &key_a(),
        1,
        address(&key_a(), 1),
        withdraw_action(lot, 3),
    );
    assert_eq!(
        SignedOperation::import(&op.encode().unwrap(), &ready.view()).unwrap_err(),
        Refusal::WrongSequence { expected: 2 }
    );
    assert!(
        op.verify_command(
            &ready.anchor,
            &History::default(),
            &ready.state.wallets,
            &ready.state.bonds_v2.lots[&lot]
        )
        .is_err()
    );
    // A payout coin that already exists (a replay of an applied withdrawal's bytes).
    let (mut replayed, lot) = with_lot(floor, 10, 1, Some(20), None, LotStatus::Unbonding);
    let op = command(
        &replayed.anchor,
        &key_a(),
        1,
        address(&key_a(), 1),
        withdraw_action(lot, 2),
    );
    replayed.state.coins.insert(
        OutPoint {
            transaction: op.payout_id().unwrap(),
            index: 0,
        },
        Coin {
            output: Output {
                owner: address(&key_a(), 1),
                atoms: PRINCIPAL,
            },
            created_height: floor,
            coinbase: false,
        },
    );
    assert_eq!(
        SignedOperation::import(&op.encode().unwrap(), &replayed.view()).unwrap_err(),
        Refusal::Replay
    );
}

#[test]
fn the_lot_owner_signs_and_nobody_else() {
    let floor = 259_210;
    let (mut world, lot) = with_lot(floor, 10, 1, Some(20), None, LotStatus::Unbonding);
    // A lot of key B: key A cannot plan for it, and its bytes naming A as owner are refused by both.
    let b_lot = world.lot(
        0x52,
        address(&key_b(), 1),
        PRINCIPAL,
        10,
        1,
        Some(20),
        None,
        LotStatus::Unbonding,
    );
    let view = world.view();
    assert_eq!(
        plan(&withdraw(b_lot), &view, &identity(&key_a())).unwrap_err(),
        Refusal::NotRequiredSigner(Slot::BondOwner)
    );
    let op = command(
        &world.anchor,
        &key_a(),
        1,
        address(&key_a(), 1),
        withdraw_action(b_lot, 2),
    );
    assert_eq!(
        SignedOperation::import(&op.encode().unwrap(), &view).unwrap_err(),
        Refusal::InvalidRequest(OWNER_MISMATCH)
    );
    assert!(
        op.verify_command(
            &world.anchor,
            &History::default(),
            &world.state.wallets,
            &world.state.bonds_v2.lots[&b_lot]
        )
        .is_err()
    );
    // A plan of key A authorized by key B's signer: refused before anything is signed.
    let planned = plan(&withdraw(lot), &view, &identity(&key_a())).unwrap();
    let stranger = KeySigner::for_test(key_b()).unwrap();
    let outbox = MemoryOutbox::new();
    let approval = flow::approve(&review(&planned, &view).unwrap(), &view);
    assert_eq!(
        stranger.authorize(planned, approval, &view).unwrap_err(),
        Refusal::NotRequiredSigner(Slot::BondOwner)
    );
    assert_untouched(&outbox);
    // Adoption by a wallet that is not the authorizer.
    let planned = plan(&withdraw(lot), &view, &identity(&key_a())).unwrap();
    let raw = export_unsigned(&planned).unwrap();
    assert_eq!(
        adopt(&raw, &view, &identity(&key_b())).unwrap_err(),
        Refusal::NotRequiredSigner(Slot::BondOwner)
    );
}

#[test]
fn stale_authority_after_a_wallet_rotation_for_unbond_and_withdrawal() {
    let a = key_a();
    let b = key_b();
    let owner = address(&a, 1);
    let (mut world, lot) = with_lot(HEAD, 10, 0, None, None, LotStatus::Active);
    world.state.wallets.register(&descriptor(&a, 1)).unwrap();
    let before = plan(&unbond(lot), &world.view(), &identity(&a)).unwrap();
    let mut rotation = Rotation {
        network: world.anchor.network,
        genesis: world.anchor.genesis,
        fingerprint: world.anchor.fingerprint,
        authority: owner,
        current: descriptor(&a, 1),
        proposed: descriptor(&b, 2),
        created_height: 90,
        expiry_height: 120,
        authorization: zero(),
        possession: zero(),
    };
    rotation.sign(&a, &b).unwrap();
    world
        .state
        .wallets
        .apply(
            &rotation,
            world.anchor.genesis,
            world.anchor.fingerprint,
            HEAD,
        )
        .unwrap();
    let view = world.view();
    assert_eq!(
        plan(&unbond(lot), &view, &identity(&a)).unwrap_err(),
        Refusal::StaleAuthority
    );
    assert_eq!(review(&before, &view).unwrap_err(), Refusal::StaleAuthority);
    let old = command(&world.anchor, &a, 1, owner, unbond_action(lot, 1));
    assert!(
        old.verify_command(
            &world.anchor,
            &History::default(),
            &world.state.wallets,
            &world.state.bonds_v2.lots[&lot]
        )
        .is_err()
    );
    assert_eq!(
        SignedOperation::import(&old.encode().unwrap(), &view).unwrap_err(),
        Refusal::StaleAuthority
    );
    // The new key signs for the immutable owner, and consensus agrees.
    let rotated = SignerIdentity::from_public(b.public(), 2, Some(owner)).unwrap();
    let planned = plan(&unbond(lot), &view, &rotated).unwrap();
    let signer =
        KeySigner::new_rotated(key_b(), 2, owner, SigningGate::test_value().unwrap()).unwrap();
    let signed = flow::sign(planned, &signer, &view).unwrap();
    let op = Operation::decode(signed.bytes()).unwrap();
    assert_eq!(op.owner, owner);
    op.verify_command(
        &world.anchor,
        &History::default(),
        &world.state.wallets,
        &world.state.bonds_v2.lots[&lot],
    )
    .unwrap();
}

#[test]
fn signed_window_context_refusals_for_unbond_and_withdrawal() {
    let (world, lot) = with_lot(HEAD, 10, 0, None, None, LotStatus::Active);
    let view = world.view();
    let me = identity(&key_a());
    let planned = plan(&unbond(lot), &view, &me).unwrap();
    let base = Operation::decode(&planned.objects()[0].bytes).unwrap();
    type Edit = Box<dyn Fn(&mut Operation)>;
    let cases: Vec<(&str, Edit, Refusal)> = vec![
        (
            "parent anchor",
            Box::new(|o| o.envelope.reference_block[0] ^= 1),
            Refusal::StaleAuthority,
        ),
        (
            "later height",
            Box::new(|o| o.envelope.first_height += 1),
            Refusal::WindowNotOpen {
                created: HEAD + 2,
                next_height: HEAD + 1,
            },
        ),
        (
            "Genesis",
            Box::new(|o| o.genesis[0] ^= 1),
            Refusal::WrongContext(ContextField::Genesis),
        ),
        (
            "fingerprint",
            Box::new(|o| o.fingerprint[0] ^= 1),
            Refusal::WrongContext(ContextField::Fingerprint),
        ),
        (
            "owner",
            Box::new(|o| o.owner = address(&key_b(), 1)),
            Refusal::InvalidRequest(OWNER_MISMATCH),
        ),
    ];
    for (label, edit, refusal) in cases {
        let mut op = base.clone();
        edit(&mut op);
        assert_eq!(
            explain(&op.encode().unwrap(), &view, &me).unwrap_err(),
            refusal,
            "{label}"
        );
        op.sign(&key_a()).unwrap();
        assert!(
            op.verify_command(
                &world.anchor,
                &History::default(),
                &world.state.wallets,
                &world.state.bonds_v2.lots[&lot]
            )
            .is_err(),
            "consensus refuses the {label}"
        );
    }
    // Another network cannot even be decoded: the operation encodes NETWORK_ID.
    let mut raw = base.encode().unwrap();
    let network = mutiny_consensus_v8::NETWORK_ID.to_be_bytes();
    let at = raw
        .windows(4)
        .position(|w| w == network)
        .expect("the body carries the network");
    raw[at] ^= 1;
    assert_eq!(
        explain(&raw, &view, &me).unwrap_err(),
        Refusal::UnknownOperation
    );
    // A valid signed window can survive another head, but requires this fixture's own
    // reference history. This synthetic anchor tests window rules, not canonical finality.
    let next = world.at(HEAD + 1);
    assert_eq!(
        review(&planned, &next.view()).unwrap_err(),
        Refusal::StaleAuthority
    );
    let mut history = History::default();
    history
        .insert_anchor(world.anchor.height, world.anchor.block)
        .unwrap();
    assert!(review(&planned, &next.view().with_history(&history)).is_ok());
    let expired = world.at(base.envelope.last_height);
    assert_eq!(
        review(&planned, &expired.view().with_history(&history)).unwrap_err(),
        Refusal::WindowClosed {
            expiry: base.envelope.last_height,
            next_height: base.envelope.last_height + 1
        }
    );
    let mut invalid = base;
    invalid.envelope.first_height = invalid.envelope.reference_height;
    assert!(
        invalid.encode().is_err(),
        "reference must precede the first signed height"
    );
}

#[test]
fn adoption_and_cancellation_refusals() {
    let (world, lot) = with_lot(HEAD, 10, 0, None, None, LotStatus::Active);
    let view = world.view();
    let me = identity(&key_a());
    let planned = plan(&unbond(lot), &view, &me).unwrap();
    let raw = export_unsigned(&planned).unwrap();
    assert_eq!(adopt(&raw, &view, &me).unwrap().id(), planned.id());
    let signer = KeySigner::for_test(key_a()).unwrap();
    let signed = flow::sign(planned, &signer, &view).unwrap();
    assert_eq!(
        adopt(signed.bytes(), &view, &me).unwrap_err(),
        Refusal::Malformed(ALREADY_SIGNED)
    );
    assert_eq!(
        adopt(&raw[..raw.len() - 1], &view, &me).unwrap_err(),
        Refusal::UnknownOperation
    );
    // Q3: there is no cancel of an unbond, and none of a signed bond operation.
    for target in [CancelTarget::Unbond, CancelTarget::SignedOperation] {
        assert_eq!(
            plan(
                &OperationRequest::Cancel(CancelRequest::new(target)),
                &view,
                &me
            )
            .unwrap_err(),
            Refusal::CancelNotAvailable(target)
        );
    }
    // A bond operation is never partial.
    let partial = SignedOperation::Partial {
        kind: OperationKind::BondUnbond,
        id: signed.id(),
        bytes: signed.bytes().to_vec(),
        missing: vec![],
        validity: *signed.validity(),
        reserved: signed.reserved().to_vec(),
    };
    let mut outbox = MemoryOutbox::new();
    assert!(outbox.commit(&partial, &view).is_err());
    assert_untouched(&outbox);
}

// ---------------------------------------------------------------------------------------------
// Outbox: reservations, metadata and reconciliation
// ---------------------------------------------------------------------------------------------

#[test]
fn the_outbox_reserves_funding_coins_and_the_lot_across_plans() {
    let mut world = funded();
    let second = world.coin(address(&key_a(), 1), FUNDS, 1, false, 0x32, 0);
    let me = identity(&key_a());
    let signer = KeySigner::for_test(key_a()).unwrap();
    let node = world.node();
    let nonce = [9; 32];
    let signed = {
        let view = world.view();
        flow::sign(
            plan(&create(node, nonce), &view, &me).unwrap(),
            &signer,
            &view,
        )
        .unwrap()
    };
    let lot = lot_id_of(&world, address(&key_a(), 1), nonce);
    let mut outbox = MemoryOutbox::new();
    // Metadata that disagrees with the bytes (the lot left out) is refused.
    let lying = SignedOperation::Complete {
        kind: OperationKind::BondCreate,
        id: signed.id(),
        bytes: signed.bytes().to_vec(),
        validity: *signed.validity(),
        reserved: signed
            .reserved()
            .iter()
            .filter(|point| **point != lot_resource(&lot))
            .cloned()
            .collect(),
    };
    assert!(matches!(
        outbox.commit(&lying, &world.view()),
        Err(Refusal::VerificationFailed(_))
    ));
    assert_untouched(&outbox);
    outbox.commit(&signed, &world.view()).unwrap();
    let reserved = outbox.reserved().unwrap();
    let spent = FundedBondCreate::decode(signed.bytes())
        .unwrap()
        .unsigned
        .inputs[0]
        .clone();
    assert_eq!(
        reserved,
        BTreeSet::from([spent.clone(), lot_resource(&lot)])
    );
    world.reserved = reserved.clone();
    // The same lot again: reserved. Another lot: funded by the other coin only.
    assert_eq!(
        plan(&create(node, nonce), &world.view(), &me).unwrap_err(),
        Refusal::ReservedInput
    );
    let other = plan(&create(node, [10; 32]), &world.view(), &me).unwrap();
    let other_inputs: Vec<&OutPoint> = other
        .inputs()
        .iter()
        .filter(|point| point.index != u32::MAX)
        .collect();
    assert_eq!(
        spent,
        world_first(),
        "the first coin funded the queued creation"
    );
    assert_eq!(other_inputs, vec![&second]);
    // Committing the same signed bytes against a view that already reserves them is refused, the
    // same bytes into the same outbox are idempotent.
    assert_eq!(outbox.commit(&signed, &world.view()).unwrap(), signed.id());
    let mut fresh = MemoryOutbox::new();
    assert_eq!(
        fresh.commit(&signed, &world.view()).unwrap_err(),
        Refusal::ReservedInput
    );
    // Forget releases the reservations (and does not revoke the bytes).
    outbox.forget(&signed.id()).unwrap();
    assert!(outbox.reserved().unwrap().is_empty());
    world.reserved.clear();
    assert!(plan(&create(node, nonce), &world.view(), &me).is_ok());
}

fn world_first() -> OutPoint {
    OutPoint {
        transaction: [0x31; 32],
        index: 0,
    }
}

#[test]
fn reconciliation_reads_verified_state_only() {
    let me = identity(&key_a());
    let signer = KeySigner::for_test(key_a()).unwrap();
    // A creation that never makes it: expired only after its last allowed inclusion.
    let world = funded();
    let signed = {
        let view = world.view();
        flow::sign(
            plan(&create(world.node(), [11; 32]), &view, &me).unwrap(),
            &signer,
            &view,
        )
        .unwrap()
    };
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&signed, &world.view()).unwrap();
    assert_eq!(outbox.reconcile(&world.view()).unwrap().still_pending, 1);
    let later = world.at(signed.validity().expiry);
    assert_eq!(outbox.reconcile(&later.view()).unwrap().expired, 1);
    // A creation whose funding coin was spent by something else.
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&signed, &world.view()).unwrap();
    let mut spent = world.clone();
    spent.state.coins.clear();
    assert_eq!(outbox.reconcile(&spent.view()).unwrap().inputs_spent, 1);

    // An unbond whose lot sequence was advanced by another operation.
    let (world, lot) = with_lot(HEAD, 10, 0, None, None, LotStatus::Active);
    let signed = {
        let view = world.view();
        flow::sign(plan(&unbond(lot), &view, &me).unwrap(), &signer, &view).unwrap()
    };
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&signed, &world.view()).unwrap();
    assert_eq!(
        outbox.reserved().unwrap(),
        BTreeSet::from([lot_resource(&lot)])
    );
    // A synthetic lot transition is not evidence that these exact bytes executed.
    let mut applied = world.at(HEAD + 1);
    applied
        .state
        .bonds_v2
        .lots
        .get_mut(&lot)
        .unwrap()
        .start_unbond(HEAD + 1, 1)
        .unwrap();
    let mut confirmed = MemoryOutbox::new();
    confirmed.commit(&signed, &world.view()).unwrap();
    let result = confirmed.reconcile(&applied.view()).unwrap();
    assert_eq!(result.confirmed, 0);
    assert_eq!(result.inputs_spent, 1);
    assert_eq!(
        confirmed.get(&signed.id()).unwrap().unwrap().status,
        OutboxStatus::InputsSpent
    );
    // Applied by another operation at another height: the sequence is consumed.
    let mut other = world.at(HEAD + 3);
    other
        .state
        .bonds_v2
        .lots
        .get_mut(&lot)
        .unwrap()
        .start_unbond(HEAD + 3, 1)
        .unwrap();
    assert_eq!(outbox.reconcile(&other.view()).unwrap().inputs_spent, 1);
    assert!(outbox.reserved().unwrap().is_empty());
}

#[test]
fn no_refusal_leaves_a_trace() {
    let (world, lot) = with_lot(HEAD, 10, 0, None, None, LotStatus::Active);
    let view = world.view();
    let planned = plan(&unbond(lot), &view, &identity(&key_a())).unwrap();
    let outbox = MemoryOutbox::new();
    // Approval without the typed phrase is impossible; with it, the wrong signer is refused.
    let reviewed = review(&planned, &view).unwrap();
    let mut gate = ReviewGate::new();
    gate.present(&reviewed, &view);
    for ack in reviewed.acknowledgements() {
        gate.acknowledge(*ack).unwrap();
    }
    assert_eq!(
        gate.approve(&view).unwrap_err(),
        Refusal::ConfirmationPhraseMissing,
        "a bond unbond needs the typed confirmation phrase"
    );
    assert_eq!(
        gate.confirm_phrase("CONFIRM 00000000").unwrap_err(),
        Refusal::ConfirmationPhraseMismatch
    );
    let stranger = KeySigner::for_test(key_b()).unwrap();
    let approval = flow::approve(&reviewed, &view);
    assert!(
        stranger
            .authorize(planned.clone(), approval, &view)
            .is_err()
    );
    assert_untouched(&outbox);
    assert_eq!(
        review(&planned, &view).unwrap().binding(),
        reviewed.binding(),
        "nothing about the world moved"
    );
}

#[test]
fn command_signature_parity_with_verify_command_for_every_field() {
    // Unbond of an Active lot at head 100; withdrawal of an Unbonding lot at its floor 259,210. Each
    // world also holds a second lot in the same state, so a different but valid lot is accepted by
    // both.
    let floor = 259_210;
    for unbonding in [false, true] {
        let (mut world, lot) = if unbonding {
            with_lot(floor - 1, 10, 1, Some(20), None, LotStatus::Unbonding)
        } else {
            with_lot(HEAD, 10, 0, None, None, LotStatus::Active)
        };
        let other = world.lot(
            0x52,
            address(&key_a(), 1),
            PRINCIPAL,
            10,
            if unbonding { 1 } else { 0 },
            if unbonding { Some(20) } else { None },
            None,
            if unbonding {
                LotStatus::Unbonding
            } else {
                LotStatus::Active
            },
        );
        let sequence = if unbonding { 2 } else { 1 };
        let action = move |lot: Hash, sequence: u64| {
            if unbonding {
                withdraw_action(lot, sequence)
            } else {
                unbond_action(lot, sequence)
            }
        };
        let view = world.view();
        let base = command(
            &world.anchor,
            &key_a(),
            1,
            address(&key_a(), 1),
            action(lot, sequence),
        );
        let verdicts = |op: &Operation| {
            let target = match &op.action {
                Action::Unbond { lot, .. } | Action::Withdraw { lot, .. } => *lot,
            };
            // Consensus is asked about the lot the operation names, or, for an unknown lot, about
            // the original lot (which it must then refuse as a mismatch).
            let consensus_lot = world
                .state
                .bonds_v2
                .lots
                .get(&target)
                .unwrap_or(&world.state.bonds_v2.lots[&lot]);
            (
                op.verify_command(
                    &world.anchor,
                    &History::default(),
                    &world.state.wallets,
                    consensus_lot,
                )
                .is_ok(),
                SignedOperation::import(&op.encode().unwrap(), &view).is_ok(),
            )
        };
        assert_eq!(verdicts(&base), (true, true), "the base operation");
        type Edit = Box<dyn Fn(&mut Operation)>;
        let a = key_a();
        let resigned: Vec<(&str, Edit, bool)> = vec![
            ("genesis", Box::new(|o| o.genesis[2] ^= 1), false),
            ("fingerprint", Box::new(|o| o.fingerprint[2] ^= 1), false),
            ("height", Box::new(|o| o.envelope.first_height += 1), false),
            (
                "parent anchor",
                Box::new(|o| o.envelope.reference_block[2] ^= 1),
                false,
            ),
            ("owner", Box::new(|o| o.owner = address(&key_b(), 1)), false),
            (
                "sequence",
                Box::new(move |o| o.action = action(lot, sequence + 1)),
                false,
            ),
            (
                "unknown lot",
                Box::new(move |o| o.action = action([0x7e; 32], sequence)),
                false,
            ),
            (
                "another valid lot",
                Box::new(move |o| o.action = action(other, sequence)),
                true,
            ),
            (
                "the other action",
                Box::new(move |o| {
                    o.action = if unbonding {
                        unbond_action(lot, sequence)
                    } else {
                        withdraw_action(lot, sequence)
                    }
                }),
                false,
            ),
        ];
        for (label, edit, accepted) in resigned {
            let mut op = base.clone();
            edit(&mut op);
            op.sign(&a).unwrap();
            assert_eq!(
                verdicts(&op),
                (accepted, accepted),
                "{label} (unbonding lot: {unbonding})"
            );
        }
        // Another key as authorizer, signing for itself.
        let mut stranger = base.clone();
        stranger.authorizer = descriptor(&key_b(), 1);
        stranger.sign(&key_b()).unwrap();
        assert_eq!(verdicts(&stranger), (false, false), "stranger authorizer");
        // Signature damage, not re-signed.
        let damaged: Vec<(&str, Edit)> = vec![
            ("ed448 bit", Box::new(|o| o.signature.ed448[9] ^= 1)),
            ("fn-dsa bit", Box::new(|o| o.signature.fndsa[900] ^= 1)),
            (
                "ed448 half missing",
                Box::new(|o| o.signature.ed448 = [0; 114]),
            ),
            (
                "fn-dsa half missing",
                Box::new(|o| o.signature.fndsa = [0; 1280]),
            ),
        ];
        for (label, edit) in damaged {
            let mut op = base.clone();
            edit(&mut op);
            assert_eq!(verdicts(&op), (false, false), "{label}");
        }
    }
}

#[test]
fn generic_authorization_refusals_apply_to_bond_plans() {
    use std::time::{Duration, Instant};
    let mut world = BondWorld::new(HEAD);
    let first = world.lot(
        0x51,
        address(&key_a(), 1),
        PRINCIPAL,
        10,
        0,
        None,
        None,
        LotStatus::Active,
    );
    let second = world.lot(
        0x52,
        address(&key_a(), 1),
        PRINCIPAL,
        10,
        0,
        None,
        None,
        LotStatus::Active,
    );
    let view = world.view();
    let me = identity(&key_a());
    let outbox = MemoryOutbox::new();
    let one = plan(&unbond(first), &view, &me).unwrap();
    let two = plan(&unbond(second), &view, &me).unwrap();
    let signer = KeySigner::for_test(key_a()).unwrap();
    // An approval given for another bond plan.
    let approval = flow::approve(&review(&two, &view).unwrap(), &view);
    assert_eq!(
        signer.authorize(one.clone(), approval, &view).unwrap_err(),
        Refusal::PlanChanged
    );
    // An approval older than its limit.
    let reviewed = review(&one, &view).unwrap();
    let mut gate = ReviewGate::new();
    gate.present(&reviewed, &view);
    for ack in reviewed.acknowledgements() {
        gate.acknowledge(*ack).unwrap();
    }
    gate.confirm_phrase(&reviewed.confirmation_phrase().unwrap())
        .unwrap();
    let then = Instant::now()
        .checked_sub(MAX_APPROVAL_AGE + Duration::from_secs(5))
        .expect("monotonic clock has history");
    let old = gate.approve_at(&view, then).unwrap();
    assert_eq!(
        signer.authorize(one.clone(), old, &view).unwrap_err(),
        Refusal::Expired(ExpiryKind::Approval)
    );
    // A locked signer.
    let locked = KeySigner::for_test(key_a()).unwrap();
    locked.lock();
    let approval = flow::approve(&reviewed, &view);
    assert_eq!(
        locked.authorize(one.clone(), approval, &view).unwrap_err(),
        Refusal::Locked
    );
    // A TEST-VALUE signer on a production-class chain.
    let mut production = world.clone();
    production.state.dividends =
        DividendState::genesis(Treasury::new(Class::Production, descriptor(&key_b(), 1)).unwrap());
    let production_view = production.view();
    assert_eq!(production_view.class(), ChainClass::Production);
    let on_production = plan(&unbond(first), &production_view, &me).unwrap();
    let approval = flow::approve(
        &review(&on_production, &production_view).unwrap(),
        &production_view,
    );
    assert_eq!(
        signer
            .authorize(on_production, approval, &production_view)
            .unwrap_err(),
        Refusal::ChainClassMismatch {
            gate: ChainClass::TestValue,
            chain: ChainClass::Production
        }
    );
    // The production gate stays closed.
    if !mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED {
        assert_eq!(SigningGate::production().unwrap_err(), Refusal::GateClosed);
    }
    assert_untouched(&outbox);
}

#[test]
fn the_treasury_authority_unbonds_and_withdraws_only_through_the_treasury_profile() {
    let a = key_a();
    let floor = 259_210;
    for unbonding in [false, true] {
        let (mut world, lot) = if unbonding {
            with_lot(floor - 1, 10, 1, Some(20), None, LotStatus::Unbonding)
        } else {
            with_lot(HEAD, 10, 0, None, None, LotStatus::Active)
        };
        world.state.wallets.register(&descriptor(&a, 1)).unwrap();
        world.state.dividends =
            DividendState::genesis(Treasury::new(Class::TestValue, descriptor(&a, 1)).unwrap());
        let view = world.view();
        let request = if unbonding {
            withdraw(lot)
        } else {
            unbond(lot)
        };
        assert_eq!(
            plan(&request, &view, &identity(&a)).unwrap_err(),
            Refusal::TreasuryProfileRequired
        );
        let treasury = identity(&a).with_treasury_roles_for_test(TreasuryRoles {
            authority: true,
            destination_of: None,
        });
        let planned = plan(&request, &view, &treasury).unwrap();
        assert_eq!(
            adopt(&export_unsigned(&planned).unwrap(), &view, &identity(&a)).unwrap_err(),
            Refusal::TreasuryProfileRequired,
            "adoption holds the plan to the same rule"
        );
    }
}
