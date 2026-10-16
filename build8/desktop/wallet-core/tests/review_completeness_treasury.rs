//! Review completeness for the Treasury profile (phase 6). The destination rotation and the offer
//! freeze each show the destination(s) with labels and the typed check, the amount, the fee (rule,
//! payer, size) and the change, the conditions (Treasury, generations, current and new destination,
//! descriptor hashes, the already-exists precondition, address reuse, effective height, new versus
//! frozen offers, the Bitcoin-custody statement; for a freeze: exactly what is signed, the creation
//! head, the offer and its integer Bitcoin terms, the maker's signature, the commitments), timing,
//! every irreversible effect marked, and warnings with their acknowledgements; both are high risk.
//! Other wallets read the same bytes to the same digest; no byte or field of the unsigned forms can
//! change without the review noticing; hostile bytes (truncations, extensions, bit flips) of every
//! imported form are refused without a panic; the text is pinned by golden snapshots.
//!
//! Determinism of the snapshots: the rotation is planned in a synthetic world from public keys; the
//! freeze uses the verified canonical candidate-3 MakerOffer (`golden/conditional_maker_offer_candidate3.hex`: created at
//! height 1, so the freeze is made at head 1). NATIVE, TEST-VALUE; public test keys.
#[path = "support/treasury_kit.rs"]
mod kit;
#[path = "support/synthetic.rs"]
mod synthetic;

use kit::{FreezeTerms, TRADING_TREASURY};
use mutiny_consensus_v8::{
    Hash,
    dividend_state_v1::DividendState,
    trading_v1::{
        self, Action, NativeOperation, OfferBody, OfferProof, OfferTerms, SignedOffer, Strikes,
        native_input_id,
    },
    transactions::OutPoint,
    treasury_v1::{Class, Treasury},
};
use mutiny_wallet_core_v8::{ops::treasury::freeze_proposal, *};
use synthetic::{World, address, descriptor, identity, key_a, key_b, key_c};

const T: Hash = TRADING_TREASURY;
const OFFER_HEX: &str = include_str!("golden/conditional_maker_offer_candidate3.hex");

fn fixed_offer() -> SignedOffer {
    let raw = hex::decode(OFFER_HEX.trim()).unwrap();
    let offer = SignedOffer::decode(&raw).unwrap();
    offer.verify().unwrap();
    assert_eq!(offer.encode().unwrap(), raw);
    offer
}

fn treasury_world(head: u64) -> World {
    let mut world = World::new(head);
    world
        .state
        .wallets
        .register(&descriptor(&key_b(), 1))
        .unwrap();
    world.state.dividends =
        DividendState::genesis(Treasury::new(Class::TestValue, descriptor(&key_b(), 1)).unwrap());
    world.coin(address(&key_b(), 1), 5_000_000, 1, false, 0xd1, 0);
    world.coin(address(&key_b(), 1), 300_000, 1, false, 0xd2, 0);
    let context = kit::context_of(&world.anchor);
    for (key, raw) in
        trading_v1::treasury_genesis_records(&context, T, descriptor(&key_b(), 1)).unwrap()
    {
        world.state.protocol_records.insert(key, raw);
    }
    world
}

fn treasury_me() -> SignerIdentity {
    identity(&key_b()).with_treasury_roles_for_test(TreasuryRoles {
        authority: true,
        destination_of: Some(T),
    })
}

/// Signed TEST model of B1 -> C2 WalletBook authority; no canonical history is fabricated.
fn rotation_world() -> World {
    let mut world = treasury_world(100);
    world
        .state
        .wallets
        .register(&descriptor(&key_a(), 1))
        .unwrap();
    kit::apply_wallet_rotation_model(
        &mut world.state,
        &world.anchor,
        T,
        &key_b(),
        1,
        &key_c(),
        2,
        99,
    );
    world
}

fn rotation_me() -> SignerIdentity {
    SignerIdentity::from_public(key_c().public(), 2, Some(T))
        .unwrap()
        .with_treasury_roles_for_test(TreasuryRoles {
            authority: true,
            destination_of: Some(T),
        })
}

/// Current C2 authority routes Treasury T from its historic B1 address to its current C2 address.
fn rotation_scenario() -> (World, OperationPlan) {
    let world = rotation_world();
    let planned = plan(
        &OperationRequest::TreasuryRotate(
            TreasuryRotateRequest::new(Blob::new(descriptor(&key_c(), 2)))
                .with_verified_restore(T, trading_v1::descriptor_hash(&descriptor(&key_c(), 2))),
        ),
        &world.view(),
        &rotation_me(),
    )
    .unwrap();
    (world, planned)
}

fn freeze_terms() -> FreezeTerms {
    FreezeTerms {
        treasury: T,
        generation: 1,
        address: address(&key_b(), 1),
        trade: [0x21; 32],
        contract: [0x22; 32],
        wallet_descriptor: descriptor(&key_b(), 1),
    }
}

/// Key B freezes the fixed public offer at head 1.
fn freeze_scenario() -> (World, OperationPlan, Vec<u8>) {
    let world = treasury_world(1);
    let view = world.view();
    let proposal = kit::proposal(&view, &freeze_terms(), &fixed_offer());
    let planned = plan(
        &OperationRequest::TreasuryFreezeOffer(TreasuryFreezeOfferRequest::new(Blob::new(
            proposal.clone(),
        ))),
        &view,
        &treasury_me(),
    )
    .unwrap();
    (world, planned, proposal)
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

#[test]
fn a_rotation_review_shows_every_required_row() {
    let (world, planned) = rotation_scenario();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    let (current, new) = (address(&key_b(), 1), address(&key_c(), 2));
    let wire = kit::wire(&planned.objects()[0].bytes);
    let fee = wire.operation.meta.fee.0;
    let Action::TreasuryRotate { change, .. } = wire.operation.action else {
        panic!()
    };
    assert_eq!(reviewed.title(), "Rotate the Treasury destination");
    assert!(reviewed.summary().contains("Bitcoin custody is untouched"));
    assert_eq!(reviewed.signer().profile, WalletProfile::Treasury);
    assert_eq!(
        reviewed.authorizations(),
        &[Requirement {
            slot: Slot::Approval(0),
            signer: RequiredSigner::Wallet(current),
            status: RequirementStatus::ThisWallet,
        }]
    );
    assert_eq!(reviewed.parties()[0].role, PartyRole::Treasury);
    // Destinations: the new destination first (typed check), then the change.
    let destinations = reviewed.destinations();
    assert_eq!(
        (
            destinations[0].role,
            destinations[0].address,
            destinations[0].atoms
        ),
        (DestinationRole::ProtocolPayout, new, 0)
    );
    assert_eq!(destinations[0].label, AddressLabel::ThisWallet);
    assert_eq!(
        (
            destinations[1].role,
            destinations[1].address,
            destinations[1].atoms
        ),
        (DestinationRole::Change, current, change.0)
    );
    assert!(reviewed.destinations_needing_check().is_empty());
    let money = rows_of(&reviewed, Section::Money);
    assert!(
        !money
            .iter()
            .any(|row| row.label == "Type to confirm destination")
    );
    assert!(reviewed.amount().is_none(), "no principal moves");
    assert_eq!(reviewed.returned(), change.0);
    assert_eq!(
        reviewed.fee().rule,
        FeeRule::TradingMinimum { floor: 240 },
        "the trading fee rule"
    );
    assert_eq!(reviewed.fee().payer, FeePayer::ThisWallet);
    assert_eq!(reviewed.fee().atoms, fee);
    assert!(fee >= reviewed.fee().size_bytes.unwrap().max(240));
    assert_eq!(reviewed.net_debit(), Some(u128::from(fee)));
    assert_eq!(reviewed.inputs().len(), 1);
    assert_eq!(reviewed.inputs()[0].atoms, change.0 + fee);
    let conditions = rows_of(&reviewed, Section::Conditions);
    for (label, fragment) in [
        ("Treasury", hex::encode(T)),
        ("Generation", "1 to 2".to_string()),
        (
            "Current destination",
            address_format::encode_for(&current, &view),
        ),
        (
            "Current descriptor",
            hex::encode(trading_v1::descriptor_hash(&descriptor(&key_c(), 2))),
        ),
        ("New destination", address_format::encode_for(&new, &view)),
        (
            "New destination",
            hex::encode(trading_v1::descriptor_hash(&descriptor(&key_c(), 2))),
        ),
        (
            "New destination precondition",
            "The new wallet authority generation must already exist".to_string(),
        ),
        (
            "Address used once",
            "serves one generation only".to_string(),
        ),
        ("Effective height", "The inclusion height".to_string()),
        ("New offers", "must name generation 2".to_string()),
        (
            "Frozen offers",
            "keep their exact signed destination".to_string(),
        ),
        (
            "Frozen offers",
            "no historical authority exception".to_string(),
        ),
        (
            "Bitcoin custody",
            "changes MUT Treasury authority and destination ONLY".to_string(),
        ),
        ("Fee coins", "current destination".to_string()),
        ("Dividend reserve", "after this fee".to_string()),
        (
            "Unused trade fields",
            "not used by a Treasury rotation".to_string(),
        ),
        ("Validity window", "approximate".to_string()),
        ("Fee rule", "240 STRIKES".to_string()),
        ("One pending rotation", "generation 1".to_string()),
        (
            "Approvals still required",
            "slot 0, this wallet".to_string(),
        ),
        ("Finality", "final only when a certified block".to_string()),
    ] {
        assert!(has(&conditions, label, &fragment), "{label}: {fragment}");
    }
    let timing = reviewed.timing();
    assert_eq!(
        (timing.created_height, timing.expiry_height),
        (Some(101), Some(245))
    );
    let effects = rows_of(&reviewed, Section::Effects);
    assert!(
        effects
            .iter()
            .any(|row| row.emphasis == Emphasis::Irreversible
                && row.value.contains("the active destination of Treasury"))
    );
    assert!(
        effects
            .iter()
            .any(|row| row.emphasis == Emphasis::Irreversible
                && row.value.contains("can never again become a destination"))
    );
    assert!(
        effects
            .iter()
            .any(|row| row.emphasis == Emphasis::Irreversible && row.value.contains("network fee"))
    );
    for code in [
        "TEST_VALUE_CHAIN",
        "TREASURY_AUTHORITY_ONLY",
        "NEW_DESTINATION_KEY",
        "FROZEN_OFFERS_KEEP_DESTINATION",
        "TREASURY_FUNDS",
    ] {
        assert!(reviewed.warnings().iter().any(|w| w.code == code), "{code}");
    }
    assert_eq!(
        reviewed.acknowledgements(),
        &[
            AckKind::Fee,
            AckKind::Conditions,
            AckKind::Irreversible,
            AckKind::TreasuryAuthority,
        ]
    );
    assert!(reviewed.requires_phrase(), "a Treasury action is high risk");
    assert!(reviewed.render_text().contains(
        "I understand this changes MUT Treasury authority only and does not touch Bitcoin custody"
    ));
}

#[test]
fn a_freeze_review_shows_exactly_what_is_signed_and_every_required_row() {
    let (world, planned, _) = freeze_scenario();
    let view = world.view();
    let reviewed = review(&planned, &view).unwrap();
    let offer = fixed_offer();
    let destination = address(&key_b(), 1);
    assert_eq!(reviewed.title(), "Authorize a Treasury offer freeze");
    assert!(reviewed.summary().contains("Signs no Bitcoin transaction"));
    assert_eq!(
        reviewed.authorizations(),
        &[Requirement {
            slot: Slot::TreasuryFreeze,
            signer: RequiredSigner::Wallet(destination),
            status: RequirementStatus::ThisWallet,
        }]
    );
    assert_eq!(
        (
            reviewed.destinations()[0].role,
            reviewed.destinations()[0].address,
            reviewed.destinations()[0].atoms,
            reviewed.destinations()[0].label
        ),
        (
            DestinationRole::LockedOutput,
            destination,
            1_000_000,
            AddressLabel::ThisWallet
        )
    );
    assert_eq!(reviewed.amount(), Some(1_000_000));
    assert_eq!(
        (
            reviewed.fee().atoms,
            reviewed.fee().rule,
            reviewed.fee().payer
        ),
        (0, FeeRule::None, FeePayer::NotApplicable)
    );
    assert!(reviewed.inputs().is_empty());
    let conditions = rows_of(&reviewed, Section::Conditions);
    for (label, fragment) in [
        (
            "What is signed",
            "One Domain::Transaction signature".to_string(),
        ),
        (
            "What is signed",
            hex::encode(trading_v1::descriptor_hash(&descriptor(&key_b(), 1))),
        ),
        (
            "What is signed",
            "not the maker's offer signature".to_string(),
        ),
        ("Creation head", "Prepared against block 1".to_string()),
        (
            "Treasury destination",
            address_format::encode_for(&destination, &view),
        ),
        ("Offer", hex::encode(offer.body.id().unwrap())),
        ("Offer", hex::encode(offer.body.maker().unwrap())),
        ("Offer terms", "1000000 STRIKES".to_string()),
        ("Offer terms", "50000 satoshis".to_string()),
        ("Offer terms", "network code 3 (regtest)".to_string()),
        (
            "Offer terms",
            "Bitcoin settlement not verified by this wallet".to_string(),
        ),
        (
            "Maker's offer signature",
            "Verified by this wallet".to_string(),
        ),
        ("Trade commitments", hex::encode([0x21; 32])),
        ("Trade commitments", hex::encode([0x22; 32])),
        (
            "Use",
            "funded lock keeps its exact terms and destination".to_string(),
        ),
        ("Signing wallet", "(this wallet)".to_string()),
        (
            "Bitcoin custody",
            "authorizes the MUT destination of a Treasury offer ONLY".to_string(),
        ),
        (
            "Finality",
            "never included in a block by itself".to_string(),
        ),
    ] {
        assert!(has(&conditions, label, &fragment), "{label}: {fragment}");
    }
    assert_eq!(
        (
            reviewed.timing().created_height,
            reviewed.timing().expiry_height
        ),
        (Some(2), Some(1000))
    );
    let effects = rows_of(&reviewed, Section::Effects);
    assert!(effects.iter().any(|row| {
        row.emphasis == Emphasis::Irreversible
            && row
                .value
                .contains("valid only under current authority at first canonical funding")
    }));
    assert!(effects.iter().any(|row| row.emphasis == Emphasis::Normal
        && row.value.contains("Signs no Bitcoin transaction")));
    for code in [
        "TEST_VALUE_CHAIN",
        "TREASURY_AUTHORITY_ONLY",
        "BITCOIN_SETTLEMENT_NOT_VERIFIED",
        "OPAQUE_TRADE_COMMITMENTS",
        "SIGNABLE_AT_CREATION_HEAD_ONLY",
    ] {
        assert!(reviewed.warnings().iter().any(|w| w.code == code), "{code}");
    }
    assert_eq!(
        reviewed.acknowledgements(),
        &[
            AckKind::Amount,
            AckKind::Conditions,
            AckKind::Irreversible,
            AckKind::ExternalEvidence,
            AckKind::TreasuryAuthority,
        ]
    );
    assert!(reviewed.requires_phrase());
}

#[test]
fn other_wallets_read_the_same_bytes_to_the_same_digest() {
    let (world, planned) = rotation_scenario();
    let view = world.view();
    let digest = review(&planned, &view).unwrap().binding();
    let raw = &planned.objects()[0].bytes;
    // The current authority owns the new destination and signs slot 0.
    let seen = explain(raw, &view, &rotation_me()).unwrap();
    assert_eq!(seen.binding(), digest);
    assert_eq!(seen.title(), "Rotate the Treasury destination");
    assert_eq!(
        seen.authorizations()[0].status,
        RequirementStatus::ThisWallet
    );
    assert_eq!(seen.fee().payer, FeePayer::ThisWallet);
    // An observer.
    let observer = explain(raw, &view, &identity(&key_a())).unwrap();
    assert_eq!(observer.binding(), digest);
    assert_eq!(
        observer.title(),
        "Treasury destination rotation by another wallet"
    );
    // The signed rotation explains to the same digest, with the approval provided.
    let signed = kit::signed_with(kit::wire(raw), 0, &key_c(), 2);
    let after = explain(&signed, &view, &rotation_me()).unwrap();
    assert_eq!(after.binding(), digest);
    assert_eq!(
        after.authorizations()[0].status,
        RequirementStatus::Provided
    );

    // A freeze, from the proposal, the bare body and the signed bytes.
    let (world, planned, proposal) = freeze_scenario();
    let view = world.view();
    let digest = review(&planned, &view).unwrap().binding();
    let body = planned.objects()[0].bytes.clone();
    let from_proposal = explain(&proposal, &view, &treasury_me()).unwrap();
    assert_eq!(from_proposal.binding(), digest);
    assert!(
        !from_proposal
            .warnings()
            .iter()
            .any(|w| w.code == "MAKER_SIGNATURE_NOT_CHECKED")
    );
    let bare = explain(&body, &view, &identity(&key_a())).unwrap();
    assert_eq!(bare.binding(), digest);
    assert_eq!(bare.title(), "Treasury offer freeze of another wallet");
    assert!(
        bare.warnings()
            .iter()
            .any(|w| w.code == "MAKER_SIGNATURE_NOT_CHECKED")
    );
    let frozen = kit::frozen_by_hand(&body, &key_b());
    let signed = explain(&frozen, &view, &treasury_me()).unwrap();
    assert_eq!(signed.binding(), digest);
    assert_eq!(
        signed.authorizations()[0].status,
        RequirementStatus::Provided
    );
}

/// Every single-bit change (one per byte) of `raw`, explained by `me`, is refused or reads
/// differently with another digest.
fn every_flip_is_refused_or_visible(world: &World, raw: &[u8], me: &SignerIdentity) {
    let view = world.view();
    let base = explain(raw, &view, me).unwrap();
    let base_rows = read(&base);
    let (mut refused, mut visible) = (0usize, 0usize);
    for index in 0..raw.len() {
        let mut changed = raw.to_vec();
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
fn no_byte_of_an_unsigned_rotation_changes_without_the_review_noticing() {
    let (world, planned) = rotation_scenario();
    every_flip_is_refused_or_visible(&world, &planned.objects()[0].bytes, &rotation_me());
}

#[test]
fn no_byte_of_a_freeze_body_changes_without_the_review_noticing() {
    let (world, planned, _) = freeze_scenario();
    every_flip_is_refused_or_visible(&world, &planned.objects()[0].bytes, &treasury_me());
}

/// Explain a mutated copy of the planned rotation and require that it is refused or reads
/// differently.
fn rotation_noticed(
    world: &World,
    planned: &OperationPlan,
    what: &str,
    edit: impl FnOnce(&mut NativeOperation),
) -> bool {
    let view = world.view();
    let base = read(&review(planned, &view).unwrap());
    let mut wire = kit::wire(&planned.objects()[0].bytes);
    edit(&mut wire);
    let Ok(raw) = wire.encode() else {
        return false; // not even encodable
    };
    match explain(&raw, &view, &rotation_me()) {
        Ok(other) => {
            assert_ne!(
                read(&other),
                base,
                "{what} changed but nothing a person reads"
            );
            true
        }
        Err(_) => false,
    }
}

#[test]
fn each_field_of_a_rotation_shows_up_in_the_review_or_is_refused() {
    let (world, planned) = rotation_scenario();
    let change_by = |wire: &mut NativeOperation, delta: i64| {
        if let Action::TreasuryRotate { change, .. } = &mut wire.operation.action {
            change.0 = (change.0 as i64 + delta) as u64;
        }
    };
    let action =
        |wire: &mut NativeOperation, f: &dyn Fn(&mut Action)| f(&mut wire.operation.action);
    let mut visible = Vec::new();
    for (what, edit) in [
        (
            "treasury",
            Box::new(|w: &mut NativeOperation| {
                action(w, &|a| {
                    if let Action::TreasuryRotate { treasury, .. } = a {
                        treasury[0] ^= 1;
                    }
                })
            }) as Box<dyn Fn(&mut NativeOperation)>,
        ),
        (
            "current generation",
            Box::new(|w: &mut NativeOperation| {
                action(w, &|a| {
                    if let Action::TreasuryRotate {
                        current_generation, ..
                    } = a
                    {
                        *current_generation += 1;
                    }
                })
            }),
        ),
        (
            "current address",
            Box::new(|w: &mut NativeOperation| {
                action(w, &|a| {
                    if let Action::TreasuryRotate {
                        current_address, ..
                    } = a
                    {
                        current_address[0] ^= 1;
                    }
                })
            }),
        ),
        (
            "current descriptor hash",
            Box::new(|w: &mut NativeOperation| {
                action(w, &|a| {
                    if let Action::TreasuryRotate {
                        current_descriptor, ..
                    } = a
                    {
                        current_descriptor[0] ^= 1;
                    }
                })
            }),
        ),
        (
            "new generation",
            Box::new(|w: &mut NativeOperation| {
                action(w, &|a| {
                    if let Action::TreasuryRotate { new_generation, .. } = a {
                        *new_generation += 1;
                    }
                })
            }),
        ),
        (
            "new destination (another resolvable key)",
            Box::new(|w: &mut NativeOperation| {
                action(w, &|a| {
                    if let Action::TreasuryRotate {
                        new_address,
                        new_descriptor,
                        ..
                    } = a
                    {
                        *new_address = address(&key_a(), 1);
                        *new_descriptor = descriptor(&key_a(), 1);
                    }
                })
            }),
        ),
        (
            "new address only",
            Box::new(|w: &mut NativeOperation| {
                action(w, &|a| {
                    if let Action::TreasuryRotate { new_address, .. } = a {
                        new_address[0] ^= 1;
                    }
                })
            }),
        ),
        (
            "fee up, change down",
            Box::new(move |w: &mut NativeOperation| {
                w.operation.meta.fee.0 += 9;
                change_by(w, -9);
            }),
        ),
        (
            "trade",
            Box::new(|w: &mut NativeOperation| w.operation.meta.trade[3] ^= 1),
        ),
        (
            "contract",
            Box::new(|w: &mut NativeOperation| w.operation.meta.contract[3] ^= 1),
        ),
        (
            "trade generation",
            Box::new(|w: &mut NativeOperation| w.operation.meta.generation += 1),
        ),
        (
            "expiry",
            Box::new(|w: &mut NativeOperation| w.operation.meta.envelope.last_height -= 10),
        ),
        (
            "creation",
            Box::new(|w: &mut NativeOperation| w.operation.meta.envelope.first_height -= 1),
        ),
        (
            "another fee coin",
            Box::new(move |w: &mut NativeOperation| {
                let other = OutPoint {
                    transaction: [0xd2; 32],
                    index: 0,
                };
                w.inputs = vec![other.clone()];
                w.operation.meta.inputs = vec![native_input_id(&other)];
                change_by(w, 300_000 - 5_000_000);
            }),
        ),
        (
            "context",
            Box::new(|w: &mut NativeOperation| w.operation.meta.context.fingerprint[0] ^= 1),
        ),
    ] {
        if rotation_noticed(&world, &planned, what, edit) {
            visible.push(what);
        }
    }
    // The fields a person must be able to see change are visible, not merely refused.
    for what in [
        "fee up, change down",
        "trade",
        "contract",
        "trade generation",
        "expiry",
        "another fee coin",
    ] {
        assert!(
            visible.contains(&what),
            "{what} should be visible: {visible:?}"
        );
    }
    // A foreign registered key is still not the current Treasury authority. This altered
    // destination must be refused rather than rendered as an authorized R2 alternative.
    let view = world.view();
    let mut wire = kit::wire(&planned.objects()[0].bytes);
    if let Action::TreasuryRotate {
        new_address,
        new_descriptor,
        ..
    } = &mut wire.operation.action
    {
        *new_address = address(&key_a(), 1);
        *new_descriptor = descriptor(&key_a(), 1);
    }
    assert!(explain(&wire.encode().unwrap(), &view, &rotation_me()).is_err());
    assert!(!visible.contains(&"new destination (another resolvable key)"));
    assert!(
        !visible.contains(&"creation"),
        "reference 100 must strictly precede first height"
    );
    let _ = Strikes(0);
}

/// The freeze body of the fixed offer with `terms` and `offer` edited, explained as a bare body.
fn freeze_noticed(
    world: &World,
    planned: &OperationPlan,
    what: &str,
    terms: FreezeTerms,
    offer: OfferBody,
) -> bool {
    let view = world.view();
    // Compare the SAME bare-body form. Its missing maker evidence must not make an
    // unchanged body appear different merely from the planner's evidence-bearing review.
    let base = read(&explain(&planned.objects()[0].bytes, &view, &treasury_me()).unwrap());
    let Ok(_) = offer.encode() else {
        return false;
    };
    let body = kit::freeze_body(
        &kit::context_of(&world.anchor),
        view.anchor(),
        view.state_root(),
        &terms,
        &offer,
    );
    match explain(&body, &view, &treasury_me()) {
        Ok(other) => {
            assert_ne!(
                read(&other),
                base,
                "{what} changed but nothing a person reads"
            );
            true
        }
        Err(_) => false,
    }
}

#[test]
fn each_field_of_a_freeze_shows_up_in_the_review_or_is_refused() {
    let (world, planned, _) = freeze_scenario();
    let offer = fixed_offer().body;
    let terms = freeze_terms();
    let mut visible = Vec::new();
    let mut check = |what: &'static str, terms: FreezeTerms, offer: OfferBody| {
        if freeze_noticed(&world, &planned, what, terms, offer) {
            visible.push(what);
        }
    };
    check(
        "trade",
        FreezeTerms {
            trade: [0x41; 32],
            ..terms.clone()
        },
        offer.clone(),
    );
    check(
        "contract",
        FreezeTerms {
            contract: [0x42; 32],
            ..terms.clone()
        },
        offer.clone(),
    );
    check(
        "treasury",
        FreezeTerms {
            treasury: [0x91; 32],
            ..terms.clone()
        },
        offer.clone(),
    );
    check(
        "generation",
        FreezeTerms {
            generation: 2,
            ..terms.clone()
        },
        offer.clone(),
    );
    check(
        "address",
        FreezeTerms {
            address: address(&key_a(), 1),
            ..terms.clone()
        },
        offer.clone(),
    );
    check(
        "wallet descriptor",
        FreezeTerms {
            wallet_descriptor: descriptor(&key_a(), 1),
            ..terms.clone()
        },
        offer.clone(),
    );
    let mut edited = offer.clone();
    edited.nonce[0] ^= 1;
    check("offer nonce", terms.clone(), edited);
    let mut edited = offer.clone();
    edited.expiry -= 1;
    check("offer expiry", terms.clone(), edited);
    let mut edited = offer.clone();
    edited.created += 1;
    check("offer creation", terms.clone(), edited);
    let mut edited = offer.clone();
    edited.maker_side = 0;
    check("maker side", terms.clone(), edited);
    for (what, amount, satoshis, network) in [
        ("amount", 999_999u64, 50_000u64, 3u8),
        ("satoshis", 1_000_000, 50_001, 3),
        ("network code", 1_000_000, 50_000, 2),
        ("mainnet", 1_000_000, 50_000, 0),
    ] {
        let mut edited = offer.clone();
        edited.terms = OfferTerms::HashLinked {
            amount: Strikes(amount),
            bitcoin_satoshis: satoshis,
            bitcoin_network: network,
        };
        check(what, terms.clone(), edited);
    }
    let mut edited = offer.clone();
    edited.maker_descriptor = key_c().public().descriptor(1).unwrap();
    check("maker", terms.clone(), edited);
    for what in [
        "trade",
        "contract",
        "offer nonce",
        "offer expiry",
        "amount",
        "satoshis",
        "network code",
        "maker",
    ] {
        assert!(
            visible.contains(&what),
            "{what} should be visible: {visible:?}"
        );
    }
    for what in [
        "treasury",
        "generation",
        "address",
        "wallet descriptor",
        "offer creation",
        "maker side",
        "mainnet",
    ] {
        assert!(
            !visible.contains(&what),
            "{what} must be refused at this head"
        );
    }
}

#[test]
fn hostile_bytes_of_every_imported_form_are_refused_without_a_panic() {
    let (world, planned) = rotation_scenario();
    let view = world.view();
    let me = rotation_me();
    let rotation = planned.objects()[0].bytes.clone();
    let signed_rotation = kit::signed_with(kit::wire(&rotation), 0, &key_c(), 2);
    let (freeze_world, freeze_plan, proposal) = freeze_scenario();
    let freeze_view = freeze_world.view();
    let body = freeze_plan.objects()[0].bytes.clone();
    let frozen = kit::frozen_by_hand(&body, &key_b());
    for (name, raw, view) in [
        ("rotation", &rotation, &view),
        ("signed rotation", &signed_rotation, &view),
        ("freeze proposal", &proposal, &freeze_view),
        ("freeze body", &body, &freeze_view),
        ("frozen offer", &frozen, &freeze_view),
    ] {
        for cut in 0..raw.len() {
            let prefix = &raw[..cut];
            assert!(explain(prefix, view, &me).is_err(), "{name} prefix {cut}");
            assert!(adopt(prefix, view, &me).is_err(), "{name} prefix {cut}");
            assert!(
                SignedOperation::import(prefix, view).is_err(),
                "{name} prefix {cut}"
            );
        }
        for extra in [1usize, 2, 17, 4096] {
            let mut longer = raw.clone();
            longer.extend(std::iter::repeat_n(0u8, extra));
            assert!(explain(&longer, view, &me).is_err(), "{name} +{extra}");
            assert!(adopt(&longer, view, &me).is_err(), "{name} +{extra}");
            assert!(SignedOperation::import(&longer, view).is_err());
        }
        // A bit flip at every 7th byte never panics; signed forms never verify after a flip.
        for index in (0..raw.len()).step_by(7) {
            let mut flipped = raw.clone();
            flipped[index] ^= 0x10;
            let _ = explain(&flipped, view, &me);
            let _ = adopt(&flipped, view, &me);
            if name == "frozen offer" || name == "signed rotation" {
                assert!(
                    SignedOperation::import(&flipped, view).is_err(),
                    "{name} flip at {index}"
                );
            }
        }
    }
    // A plan object with the wrong label or two objects is refused by validation (the plan type has
    // no public constructor, so this is the defence-in-depth path through `adopt` only).
    assert!(freeze_proposal(&rotation, &kit::offer_import(&fixed_offer())).is_err());
    assert!(freeze_proposal(&body, &rotation).is_err());
}

fn golden(name: &str, expected: &str, text: &str) {
    assert!(
        text == expected,
        "review text differs from tests/golden/{name}; if the change is deliberate, replace the file with:\n{text}"
    );
}

#[test]
fn golden_text_snapshots() {
    let (world, planned) = rotation_scenario();
    golden(
        "treasury_rotate_review.txt",
        include_str!("golden/treasury_rotate_review.txt"),
        &review(&planned, &world.view()).unwrap().render_text(),
    );
    let (world, planned, _) = freeze_scenario();
    golden(
        "treasury_freeze_review.txt",
        include_str!("golden/treasury_freeze_review.txt"),
        &review(&planned, &world.view()).unwrap().render_text(),
    );
}

#[test]
#[ignore = "prints the current review texts for the golden files"]
fn print_review_texts() {
    let (world, planned) = rotation_scenario();
    println!(
        "=====treasury_rotate_review.txt\n{}=====end",
        review(&planned, &world.view()).unwrap().render_text()
    );
    let (world, planned, _) = freeze_scenario();
    println!(
        "=====treasury_freeze_review.txt\n{}=====end",
        review(&planned, &world.view()).unwrap().render_text()
    );
}
