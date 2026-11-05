//! The Treasury ROLE SET (fixes of the independent wallet review, MINOR-2 and MINOR-3): an identity
//! carries exactly the roles `profile::declare` checked, and every Treasury kind checks the role it
//! needs at use: spending Genesis Treasury coins and rotating the Genesis Treasury authority (R1)
//! need `Authority`; the `TreasuryRotate` of a trading Treasury (R2) and the freeze of an offer to
//! it need `Destination` for exactly that TreasuryID. One test per (role set, kind) pair, through
//! the real `profile::declare` (no test constructor), plus the review's probe (an identity declared
//! only for R1 planned R2) made permanent.
//!
//! Synthetic state at head 100: key B is the TEST-VALUE Genesis Treasury and the initial
//! destination of its sole canonical trading Treasury T. R2 cases use a separate signed WalletBook
//! model with current C2 authority and unchanged B1 routing. T2 and T3 are nonexistent foreign
//! Treasury negatives. These public TEST-VALUE models have no certified history or inclusion index.
#[path = "support/treasury_kit.rs"]
mod kit;
#[path = "support/synthetic.rs"]
mod synthetic;

use kit::{FreezeTerms, TRADING_TREASURY};
use mutiny_consensus_v8::{
    Hash,
    dividend_state_v1::DividendState,
    trading_v1,
    treasury_v1::{Class, Treasury},
};
use mutiny_crypto_v2::{HybridKey, Role, rehearsal_keys_v1};
use mutiny_wallet_core_v8::{
    ops::{rotation, treasury},
    *,
};
use synthetic::{World, address, descriptor, identity, key_a, key_b, key_c};

const T: Hash = TRADING_TREASURY;
const T2: Hash = [0x92; 32];
const T3: Hash = [0x93; 32];

fn new_key(label: &str) -> HybridKey {
    let phrase = rehearsal_keys_v1::label_phrase(label).unwrap();
    HybridKey::wallet_restore(&phrase, Role::WalletOwner).unwrap()
}

fn world() -> World {
    let mut world = World::new(100);
    for key in [key_a(), key_b()] {
        world.state.wallets.register(&descriptor(&key, 1)).unwrap();
    }
    world.state.dividends =
        DividendState::genesis(Treasury::new(Class::TestValue, descriptor(&key_b(), 1)).unwrap());
    world.coin(address(&key_b(), 1), 5_000_000, 1, false, 0xd1, 0);
    world.coin(address(&key_c(), 1), 800_000, 1, false, 0xc1, 0);
    let context = kit::context_of(&world.anchor);
    // P6 permits only the canonical Genesis Treasury's records. Foreign records would
    // make the supposedly positive state fail native validation before role checks.
    for (treasury, destination) in [(T, key_b())] {
        for (key, raw) in
            trading_v1::treasury_genesis_records(&context, treasury, descriptor(&destination, 1))
                .unwrap()
        {
            world.state.protocol_records.insert(key, raw);
        }
    }
    trading_v1::validate_records(&world.state, &context).unwrap();
    world
}

fn rotation_world() -> World {
    let mut world = world();
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
    trading_v1::validate_records(&world.state, &kit::context_of(&world.anchor)).unwrap();
    world
}

/// The initial B1 or current C2 identity checked by `profile::declare` for the roles given.
fn declared(
    key: &HybridKey,
    world: &World,
    authority: bool,
    destination_of: Option<Hash>,
) -> SignerIdentity {
    let current2 = world.state.wallets.current(T).unwrap() == descriptor(&key_c(), 2);
    kit::declared(
        key,
        if current2 { 2 } else { 1 },
        if current2 { Some(T) } else { None },
        &world.view(),
        authority,
        destination_of,
    )
}

/// R1: the wallet rotation of key B (the Genesis Treasury authority), paying its own fee.
fn r1() -> OperationRequest {
    let proposed = new_key("w8-roles-r1-new").public().descriptor(2).unwrap();
    OperationRequest::WalletRotation(
        RotationRequest::new(Blob::new(proposed.clone()), FeeSource::RotatingAuthority)
            .with_restore_verified(rotation::descriptor_fingerprint(&proposed)),
    )
}

/// Spending: a payment from the signer's coins.
fn spend() -> OperationRequest {
    OperationRequest::Payment(PaymentRequest::new(address(&key_a(), 1), 100_000))
}

/// R2 routes to the exact current C2 authority descriptor after its clean TEST rehearsal.
fn r2(treasury: Hash) -> OperationRequest {
    OperationRequest::TreasuryRotate(
        TreasuryRotateRequest::new(Blob::new(descriptor(&key_c(), 2)))
            .with_treasury(treasury)
            .with_verified_restore(
                treasury,
                trading_v1::descriptor_hash(&descriptor(&key_c(), 2)),
            ),
    )
}

/// A canonical current-maker freeze uses consensus preparation; a foreign negative is only a
/// syntactically valid witness whose use must be refused before any delivery or confirmation.
fn freeze(world: &World, treasury: Hash, wallet: &HybridKey) -> OperationRequest {
    let view = world.view();
    let maker = if world.state.wallets.current(T).unwrap() == descriptor(&key_c(), 2) {
        key_c()
    } else {
        key_b()
    };
    let generation = if world.state.wallets.current(T).unwrap() == descriptor(&key_c(), 2) {
        2
    } else {
        1
    };
    let head = world.anchor.height;
    let offer = kit::treasury_offer_at_generation(
        &maker,
        generation,
        T,
        kit::context_of(&world.anchor),
        head,
        head + 40,
        100_000,
        5_000,
        3,
        0x51,
    );
    let terms = FreezeTerms {
        treasury,
        generation: 1,
        address: T,
        trade: [0x21; 32],
        contract: [0x22; 32],
        wallet_descriptor: descriptor(wallet, generation),
    };
    let proposal = if treasury == T {
        kit::proposal(&view, &terms, &offer)
    } else {
        // Syntactically valid foreign negative; consensus never prepares this witness.
        let body = kit::freeze_body(
            &kit::context_of(&world.anchor),
            view.anchor(),
            view.state_root(),
            &terms,
            &offer.body,
        );
        treasury::freeze_proposal(&body, &kit::offer_import(&offer)).unwrap()
    };
    OperationRequest::TreasuryFreezeOffer(TreasuryFreezeOfferRequest::new(Blob::new(proposal)))
}

fn refused_for(role: TreasuryRole) -> Refusal {
    Refusal::TreasuryRoleNotDeclared(role)
}

/// What each (role set, kind) pair gives for the initial B1 or current C2 authority of T.
/// Nonexistent foreign destination roles cannot be declared. A rotation's fee and a payment spend
/// Genesis Treasury coins (the `Authority` role); R2 and a freeze act for one trading Treasury (its
/// `Destination` role); a freeze spends nothing.
#[test]
fn each_kind_needs_exactly_its_declared_role() {
    type Case = (
        &'static str,
        bool,
        Option<Hash>,
        &'static str,
        Result<(), Refusal>,
    );
    let cases: [Case; 18] = [
        // Authority only: R1 and spending, never R2 or a freeze.
        ("A", true, None, "r1", Ok(())),
        ("A", true, None, "spend", Ok(())),
        (
            "A",
            true,
            None,
            "r2 T",
            Err(refused_for(TreasuryRole::Destination)),
        ),
        (
            "A",
            true,
            None,
            "freeze T",
            Err(refused_for(TreasuryRole::Destination)),
        ),
        // Destination of T only: the freeze of T, nothing that spends Genesis Treasury coins.
        (
            "D(T)",
            false,
            Some(T),
            "r1",
            Err(refused_for(TreasuryRole::Authority)),
        ),
        (
            "D(T)",
            false,
            Some(T),
            "spend",
            Err(refused_for(TreasuryRole::Authority)),
        ),
        (
            "D(T)",
            false,
            Some(T),
            "r2 T",
            Err(refused_for(TreasuryRole::Authority)),
        ),
        ("D(T)", false, Some(T), "freeze T", Ok(())),
        (
            "D(T)",
            false,
            Some(T),
            "freeze T3",
            Err(Refusal::TreasuryGeneration(
                treasury::REASON_FREEZE_GENERATION,
            )),
        ),
        // Both, for T: everything for T, no canonical authority for nonexistent T3.
        ("A+D(T)", true, Some(T), "r1", Ok(())),
        ("A+D(T)", true, Some(T), "spend", Ok(())),
        ("A+D(T)", true, Some(T), "r2 T", Ok(())),
        ("A+D(T)", true, Some(T), "freeze T", Ok(())),
        (
            "A+D(T)",
            true,
            Some(T),
            "r2 T3",
            Err(Refusal::InvalidRequest(
                "only the canonical Genesis Treasury is authorized",
            )),
        ),
        (
            "A+D(T)",
            true,
            Some(T),
            "freeze T3",
            Err(Refusal::TreasuryGeneration(
                treasury::REASON_FREEZE_GENERATION,
            )),
        ),
        // A nonexistent foreign destination role is refused at declaration for every kind.
        (
            "A+D(T3)",
            true,
            Some(T3),
            "r2 T3",
            Err(Refusal::InvalidRequest(
                treasury::REASON_NO_TRADING_TREASURY,
            )),
        ),
        (
            "A+D(T3)",
            true,
            Some(T3),
            "r2 T",
            Err(Refusal::InvalidRequest(
                treasury::REASON_NO_TRADING_TREASURY,
            )),
        ),
        (
            "A+D(T3)",
            true,
            Some(T3),
            "freeze T",
            Err(Refusal::InvalidRequest(
                treasury::REASON_NO_TRADING_TREASURY,
            )),
        ),
    ];
    for (roles, authority, destination_of, kind, expected) in cases {
        let world = if kind.starts_with("r2") {
            rotation_world()
        } else {
            world()
        };
        let view = world.view();
        let b = if kind.starts_with("r2") {
            key_c()
        } else {
            key_b()
        };
        if destination_of == Some(T3) {
            let mut declaration =
                profile::TreasuryDeclaration::new(view.context().genesis, ChainClass::TestValue)
                    .with_destination_of(T3);
            if authority {
                declaration = declaration.with_authority();
            }
            let base = if kind.starts_with("r2") {
                SignerIdentity::from_public(b.public(), 2, Some(T)).unwrap()
            } else {
                identity(&b)
            };
            assert_eq!(
                profile::declare(base, &declaration, &view).map(|_| ()),
                expected,
                "{roles} {kind}: nonexistent foreign role cannot be declared"
            );
            continue;
        }
        let me = declared(&b, &world, authority, destination_of);
        assert_eq!(me.profile(), WalletProfile::Treasury);
        assert_eq!(
            me.treasury_roles(),
            TreasuryRoles {
                authority,
                destination_of
            }
        );
        let request = match kind {
            "r1" => r1(),
            "spend" => spend(),
            "r2 T" => r2(T),
            "r2 T3" => r2(T3),
            "freeze T" => freeze(&world, T, &b),
            "freeze T3" => freeze(&world, T3, &b),
            _ => unreachable!(),
        };
        let planned = plan(&request, &view, &me);
        assert_eq!(
            planned.as_ref().map(|_| ()).map_err(Clone::clone),
            expected,
            "{roles} {kind}"
        );
        // A plan that exists is reviewed under the same roles: the use-time check holds there too.
        if let Ok(planned) = planned {
            review(&planned, &view).unwrap_or_else(|e| panic!("{roles} {kind}: review {e:?}"));
        }
    }
}

/// A foreign Treasury cannot acquire a declared role or become a routable destination; genuine
/// unrelated A likewise cannot declare the canonical Treasury's authority or destination roles.
#[test]
fn a_foreign_destination_cannot_declare_or_rotate_a_non_genesis_treasury() {
    let world = rotation_world();
    let view = world.view();
    let c = key_c();
    let me = declared(&c, &world, true, Some(T));
    assert_eq!(
        plan(&r2(T2), &view, &me).unwrap_err(),
        Refusal::InvalidRequest("only the canonical Genesis Treasury is authorized")
    );
    assert_eq!(
        plan(&freeze(&world, T2, &c), &view, &me).unwrap_err(),
        Refusal::TreasuryGeneration(treasury::REASON_FREEZE_GENERATION)
    );
    let foreign = profile::TreasuryDeclaration::new(view.context().genesis, ChainClass::TestValue)
        .with_destination_of(T2);
    assert_eq!(
        profile::declare(
            SignerIdentity::from_public(c.public(), 2, Some(T)).unwrap(),
            &foreign,
            &view
        )
        .unwrap_err(),
        Refusal::InvalidRequest(treasury::REASON_NO_TRADING_TREASURY)
    );
    // Genuine unrelated registered A holds neither canonical Treasury role.
    let ordinary = identity(&key_a());
    for (authority, destination_of, refusal) in [
        (
            true,
            None,
            Refusal::NotRequiredSigner(Slot::RotationAuthorization),
        ),
        (
            false,
            Some(T),
            Refusal::NotRequiredSigner(Slot::Approval(0)),
        ),
    ] {
        let mut declaration =
            profile::TreasuryDeclaration::new(view.context().genesis, ChainClass::TestValue);
        if authority {
            declaration = declaration.with_authority();
        }
        if let Some(id) = destination_of {
            declaration = declaration.with_destination_of(id);
        }
        assert_eq!(
            profile::declare(ordinary.clone(), &declaration, &view).unwrap_err(),
            refusal
        );
    }
}

/// The review's probe made permanent: an identity declared ONLY for the Genesis Treasury
/// authority (R1) planned the R2 rotation of trading Treasury T. Now refused at plan and at adopt,
/// and a plan made under the right roles is refused to another role set at adoption.
#[test]
fn the_review_probe_an_r1_only_declaration_no_longer_reaches_r2_or_a_freeze() {
    let world = rotation_world();
    let view = world.view();
    let b = key_c();
    let r1_only = declared(&b, &world, true, None);
    assert!(r1_only.treasury_roles().destination_of.is_none());
    assert_eq!(
        plan(&r2(T), &view, &r1_only).unwrap_err(),
        refused_for(TreasuryRole::Destination)
    );
    // Without a name the one controlled Treasury is chosen, and refused the same way.
    let unnamed = OperationRequest::TreasuryRotate(
        TreasuryRotateRequest::new(Blob::new(descriptor(&key_c(), 2)))
            .with_verified_restore(T, trading_v1::descriptor_hash(&descriptor(&key_c(), 2))),
    );
    let both = declared(&b, &world, true, Some(T));
    assert!(plan(&unnamed, &view, &r1_only).is_err());
    let planned = plan(&r2(T), &view, &both).unwrap();
    assert_eq!(
        adopt(&planned.objects()[0].bytes, &view, &r1_only).unwrap_err(),
        refused_for(TreasuryRole::Destination)
    );
    assert_eq!(
        adopt(&planned.objects()[0].bytes, &view, &both).unwrap_err(),
        Refusal::RestoreNotVerified(
            "R2 must be planned with fresh host restore evidence; bare wire adoption is unavailable"
        )
    );
    assert_eq!(
        plan(&freeze(&world, T, &b), &view, &r1_only).unwrap_err(),
        refused_for(TreasuryRole::Destination)
    );
}

/// An ordinary identity keeps its own refusal (`TREASURY_PROFILE_REQUIRED`), whatever the kind, and
/// the role set it carries is empty.
#[test]
fn an_ordinary_identity_holds_no_role_and_is_refused_as_before() {
    let world = world();
    let view = world.view();
    let b = key_b();
    let ordinary = identity(&b);
    assert_eq!(ordinary.treasury_roles(), TreasuryRoles::default());
    assert!(!ordinary.treasury_roles().any());
    for request in [r1(), spend(), r2(T), freeze(&world, T, &b)] {
        assert_eq!(
            plan(&request, &view, &ordinary).unwrap_err(),
            Refusal::TreasuryProfileRequired
        );
    }
}
