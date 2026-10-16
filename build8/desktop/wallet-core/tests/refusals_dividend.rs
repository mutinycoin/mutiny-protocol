//! The refusal table for dividend claims. Each refusal: the wallet refuses with an exact typed
//! code, consensus' own `dividend_claim_v1::admit` refuses the equivalent hand-signed claim with an
//! agreeing reason, and nothing is signed or queued (the signed equivalent is refused by
//! `SignedOperation::import` and by the outbox, which stays empty). Plus the outbox behaviour of
//! claims: reservation of the (award, License) slot across plans, release on forget, and
//! reconciliation from verified state. NATIVE, TEST-VALUE; public test keys only; synthetic state
//! built through public consensus APIs (no fixture feature).
#[path = "support/dividend_world.rs"]
mod dividend_world;
#[path = "support/flow.rs"]
mod flow;

use dividend_world::*;
use mutiny_consensus_v8::{
    NETWORK_ID,
    dividend_claim_v1::SignedClaim,
    dividend_state_v1::DividendState,
    transactions::{Coin, OutPoint, Output},
    treasury_v1::{Class, Treasury},
};
use mutiny_wallet_core_v8::{
    discovery::{
        dividends::{self as entitlements, Claimability},
        licenses::{self, Standing},
    },
    *,
};
use std::time::Duration;

/// 1,200,000 atoms of Treasury: the first award reserves half, 200,000 for each of three Licenses.
const TREASURY: u64 = 1_200_000;
const SHARE: u64 = 200_000;

/// An edit of one field of a claim body.
type BodyEdit = fn(&mut mutiny_consensus_v8::dividend_claim_v1::ClaimBody);

fn fresh() -> ClaimWorld {
    ClaimWorld::new(3, TREASURY)
}

fn me() -> SignerIdentity {
    identity(&owner_key())
}

fn recipient() -> [u8; 32] {
    address(&other_key(), 1)
}

fn request(index: u64, amount: u64) -> DividendClaimRequest {
    DividendClaimRequest::new(license_id(index), P, amount, recipient())
}

fn op(request: DividendClaimRequest) -> OperationRequest {
    OperationRequest::DividendClaim(request)
}

/// The signed claim with metadata that matches its bytes, as an offline signer would hand it in.
fn as_signed(raw: &[u8]) -> SignedOperation {
    let claim = SignedClaim::decode(raw).unwrap();
    SignedOperation::Complete {
        kind: OperationKind::DividendClaim,
        id: claim.id(),
        bytes: raw.to_vec(),
        validity: Validity {
            created: claim.body.created_height,
            expiry: claim.body.expiry_height,
            valid_only_at: None,
            bound_to_parent: false,
        },
        reserved: vec![entitlements::claim_slot(
            claim.body.award_epoch,
            &claim.body.license,
        )],
    }
}

/// Consensus refuses `equivalent` with a reason that agrees with the wallet's `refusal`, and the
/// signed equivalent can neither be imported nor queued: no signature leaves, no row appears.
fn assert_consensus_agrees(world: &ClaimWorld, refusal: &Refusal, equivalent: &[u8]) {
    let consensus = outcome(&world.admit(equivalent));
    assert_ne!(consensus, "Ok", "consensus accepts what the wallet refused");
    assert!(
        agreeing_codes(&consensus).contains(&refusal.code()),
        "wallet {} vs consensus {consensus}",
        refusal.code()
    );
    let view = world.view();
    let imported = SignedOperation::import(equivalent, &view).unwrap_err();
    assert!(
        agreeing_codes(&consensus).contains(&imported.code()),
        "import {} vs consensus {consensus}",
        imported.code()
    );
    let mut outbox = MemoryOutbox::new();
    assert!(outbox.commit(&as_signed(equivalent), &view).is_err());
    assert!(outbox.records().unwrap().is_empty());
    assert!(outbox.reserved().unwrap().is_empty());
}

/// The wallet refuses to plan `request` for `me` with exactly `expected`; consensus agrees on the
/// hand-signed `equivalent`.
fn assert_refused(
    world: &ClaimWorld,
    me: &SignerIdentity,
    request: DividendClaimRequest,
    expected: Refusal,
    equivalent: &[u8],
) {
    let refusal = plan(&op(request), &world.view(), me).unwrap_err();
    assert_eq!(refusal, expected);
    assert_consensus_agrees(world, &refusal, equivalent);
}

/// The unsigned claim of `body` for the owner key, through `adopt` (an offline signer) and `explain`
/// (a reviewer): both must refuse with `expected`.
fn assert_bytes_refused(
    world: &ClaimWorld,
    body: mutiny_consensus_v8::dividend_claim_v1::ClaimBody,
    expected: Refusal,
) {
    let view = world.view();
    let raw = unsigned_claim(body, descriptor(&owner_key(), 1));
    assert_eq!(adopt(&raw, &view, &me()).unwrap_err(), expected);
    assert_eq!(explain(&raw, &view, &me()).unwrap_err(), expected);
}

// ---------------------------------------------------------------------------------------------
// Amount and sequence
// ---------------------------------------------------------------------------------------------

#[test]
fn an_over_claim_is_refused_like_consensus() {
    let mut world = fresh();
    let owner = owner_key();
    let hand = world.hand_claim(&owner, 1, license_id(1), P, SHARE + 1, 0, recipient());
    assert_refused(
        &world,
        &me(),
        request(1, SHARE + 1),
        Refusal::Overdrawn { remaining: SHARE },
        &hand,
    );
    // The whole share is fine; after a partial claim only the rest is.
    assert!(plan(&op(request(1, SHARE)), &world.view(), &me()).is_ok());
    world.set_account(P, license_id(1), 150_000, 1);
    let hand = world.hand_claim(&owner, 1, license_id(1), P, 150_001, 1, recipient());
    assert_refused(
        &world,
        &me(),
        request(1, 150_001),
        Refusal::Overdrawn { remaining: 150_000 },
        &hand,
    );
    assert!(plan(&op(request(1, 150_000)), &world.view(), &me()).is_ok());
}

#[test]
fn an_amount_of_zero_is_refused_like_consensus() {
    let world = fresh();
    let hand = world.hand_claim(&owner_key(), 1, license_id(1), P, 0, 0, recipient());
    assert_refused(&world, &me(), request(1, 0), Refusal::InvalidAmount, &hand);
    // The same rule holds for bytes prepared elsewhere.
    assert_bytes_refused(
        &world,
        claim_body(license_id(1), P, 0, 0, recipient()),
        Refusal::InvalidAmount,
    );
}

#[test]
fn a_replayed_sequence_is_refused_like_consensus() {
    let mut world = fresh();
    // One claim of 50,000 was applied: the account now expects sequence 1.
    world.set_account(P, license_id(1), 150_000, 1);
    let owner = owner_key();
    let replay = world.hand_claim(&owner, 1, license_id(1), P, 1_000, 0, recipient());
    let view = world.view();
    let refusal = SignedOperation::import(&replay, &view).unwrap_err();
    assert_eq!(refusal, Refusal::Replay);
    assert_consensus_agrees(&world, &refusal, &replay);
    // An unsigned proposal with the used sequence is refused before anyone signs it.
    assert_bytes_refused(
        &world,
        claim_body(license_id(1), P, 1_000, 0, recipient()),
        Refusal::Replay,
    );
    // The wallet's own plan never replays: it reads the sequence from confirmed state.
    let planned = plan(&op(request(1, 1_000)), &view, &me()).unwrap();
    let claim = SignedClaim::decode(&planned.objects()[0].bytes).unwrap();
    assert_eq!(claim.body.sequence, 1);
}

#[test]
fn a_sequence_ahead_or_behind_is_refused_like_consensus() {
    let mut world = fresh();
    world.set_account(P, license_id(1), 150_000, 1);
    let owner = owner_key();
    // Ahead: not yet valid.
    let ahead = world.hand_claim(&owner, 1, license_id(1), P, 1_000, 2, recipient());
    let refusal = SignedOperation::import(&ahead, &world.view()).unwrap_err();
    assert_eq!(refusal, Refusal::WrongSequence { expected: 1 });
    assert_consensus_agrees(&world, &refusal, &ahead);
    assert_bytes_refused(
        &world,
        claim_body(license_id(1), P, 1_000, 2, recipient()),
        Refusal::WrongSequence { expected: 1 },
    );
    // Behind: already used.
    let behind = world.hand_claim(&owner, 1, license_id(1), P, 1_000, 0, recipient());
    let refusal = SignedOperation::import(&behind, &world.view()).unwrap_err();
    assert_eq!(refusal, Refusal::Replay);
    assert_consensus_agrees(&world, &refusal, &behind);
    // The right sequence passes both.
    let right = world.hand_claim(&owner, 1, license_id(1), P, 1_000, 1, recipient());
    assert!(world.admit(&right).is_ok());
    assert!(SignedOperation::import(&right, &world.view()).is_ok());
}

// ---------------------------------------------------------------------------------------------
// Award window and eligibility
// ---------------------------------------------------------------------------------------------

#[test]
fn an_expired_award_is_refused_like_consensus() {
    let owner = owner_key();
    // (a) The head's epoch reached the end of the window while the award is still recorded.
    let world = fresh().at(P + W);
    let hand = world.hand_claim(&owner, 1, license_id(1), P, 1_000, 0, recipient());
    assert_eq!(outcome(&world.admit(&hand)), "Dividend(Expired)");
    assert_refused(
        &world,
        &me(),
        request(1, 1_000),
        Refusal::AwardExpired,
        &hand,
    );
    // (b) Boundary processing removed it: consensus no longer knows the award at all; the wallet
    // still says why.
    let mut processed = fresh().at(P + W);
    let owner_address = address(&owner, 1);
    let triples: Vec<_> = (0..3)
        .map(|index| (license_id(index), owner_address, Some(0)))
        .collect();
    processed
        .state
        .dividends
        .advance(P + W, TREASURY, &triples)
        .unwrap();
    assert!(processed.state.dividends.ledger().award(P).is_none());
    let hand = processed.hand_claim(&owner, 1, license_id(1), P, 1_000, 0, recipient());
    assert_eq!(outcome(&processed.admit(&hand)), "Dividend(UnknownAward)");
    assert_refused(
        &processed,
        &me(),
        request(1, 1_000),
        Refusal::AwardExpired,
        &hand,
    );
    // The last epoch of the window is still claimable, with a warning.
    let last = fresh().at(P + W - 1);
    let planned = plan(&op(request(1, 1_000)), &last.view(), &me()).unwrap();
    let reviewed = review(&planned, &last.view()).unwrap();
    assert!(
        reviewed
            .warnings()
            .iter()
            .any(|w| w.code == "CLAIM_WINDOW_CLOSING")
    );
    assert!(
        last.admit(&last.hand_claim(&owner, 1, license_id(1), P, 1_000, 0, recipient()))
            .is_ok()
    );
}

#[test]
fn an_award_not_yet_reached_is_refused_like_consensus() {
    let owner = owner_key();
    // (a) The head's epoch is before the award's (only a synthetic state can show this: on a real
    // chain the award is created by a block at or after its epoch).
    let early = fresh().at(P - 1);
    let hand = early.hand_claim(&owner, 1, license_id(1), P, 1_000, 0, recipient());
    assert_eq!(outcome(&early.admit(&hand)), "Dividend(NotYetClaimable)");
    assert_refused(
        &early,
        &me(),
        request(1, 1_000),
        Refusal::AwardNotYetOpen {
            award_epoch: P,
            head_epoch: P - 1,
        },
        &hand,
    );
    // (b) A later award that does not exist yet.
    let world = fresh();
    let future = DividendClaimRequest::new(license_id(1), 2 * P, 1_000, recipient());
    let hand = world.hand_claim(&owner, 1, license_id(1), 2 * P, 1_000, 0, recipient());
    assert_eq!(outcome(&world.admit(&hand)), "Dividend(UnknownAward)");
    assert_refused(
        &world,
        &me(),
        future,
        Refusal::AwardNotYetOpen {
            award_epoch: 2 * P,
            head_epoch: P + 10,
        },
        &hand,
    );
    // (c) An epoch that is not an award boundary at all.
    let odd = DividendClaimRequest::new(license_id(1), P + 1, 1_000, recipient());
    let hand = world.hand_claim(&owner, 1, license_id(1), P + 1, 1_000, 0, recipient());
    assert_refused(&world, &me(), odd, Refusal::NotEntitled, &hand);
    // (d) The boundary: the next award, exactly one epoch after the head's, does not exist yet.
    let boundary = fresh().at(2 * P - 1);
    let next_award = DividendClaimRequest::new(license_id(1), 2 * P, 1_000, recipient());
    let hand = boundary.hand_claim(&owner, 1, license_id(1), 2 * P, 1_000, 0, recipient());
    assert_eq!(outcome(&boundary.admit(&hand)), "Dividend(UnknownAward)");
    assert_refused(
        &boundary,
        &me(),
        next_award,
        Refusal::AwardNotYetOpen {
            award_epoch: 2 * P,
            head_epoch: 2 * P - 1,
        },
        &hand,
    );
}

#[test]
fn inactive_dividends_are_refused_like_consensus() {
    let world = ClaimWorld::inactive(3);
    assert_eq!(world.view().class(), ChainClass::Undeclared);
    let hand = world.hand_claim(&owner_key(), 1, license_id(1), P, 1_000, 0, recipient());
    assert_eq!(outcome(&world.admit(&hand)), "Inactive");
    assert_refused(
        &world,
        &me(),
        request(1, 1_000),
        Refusal::DividendInactive,
        &hand,
    );
    assert!(entitlements::entitlements(&world.view(), me().descriptor()).is_empty());
}

#[test]
fn a_suspended_or_revoked_license_is_refused_like_consensus() {
    let owner = owner_key();
    for (status, consensus) in [
        (Some(P + 100), "Dividend(Suspended)"),
        (None, "Dividend(Revoked)"),
    ] {
        let mut world = fresh();
        world.set_status(license_id(1), status);
        let hand = world.hand_claim(&owner, 1, license_id(1), P, 1_000, 0, recipient());
        assert_eq!(outcome(&world.admit(&hand)), consensus);
        assert_refused(
            &world,
            &me(),
            request(1, 1_000),
            Refusal::LicenseSuspendedOrRevoked,
            &hand,
        );
        // Discovery shows the standing and why nothing can be claimed.
        let view = world.view();
        let shown = entitlements::entitlement(&view, P, license_id(1)).unwrap();
        match status {
            Some(until) => {
                assert_eq!(shown.license.standing, Standing::Suspended { until });
                assert_eq!(shown.claimability, Claimability::Suspended { until });
            }
            None => {
                assert_eq!(shown.license.standing, Standing::Revoked);
                assert_eq!(shown.claimability, Claimability::Revoked);
            }
        }
        // Other Licenses are unaffected.
        assert!(plan(&op(request(2, 1_000)), &view, &me()).is_ok());
    }
    // A suspension that ended at the processed epoch no longer applies.
    let mut ended = fresh();
    ended.set_status(license_id(1), Some(P));
    assert_eq!(
        licenses::license(&ended.state, license_id(1))
            .unwrap()
            .standing,
        Standing::Active
    );
    assert!(plan(&op(request(1, 1_000)), &ended.view(), &me()).is_ok());
}

#[test]
fn an_unknown_license_or_one_without_an_account_is_not_entitled() {
    let world = fresh();
    let owner = owner_key();
    let unknown = DividendClaimRequest::new([0x55; 32], P, 1_000, recipient());
    let hand = world.hand_claim(&owner, 1, [0x55; 32], P, 1_000, 0, recipient());
    assert_eq!(outcome(&world.admit(&hand)), "UnknownLicense");
    assert_refused(&world, &me(), unknown, Refusal::NotEntitled, &hand);
    // A fourth License that was not in the award's snapshot.
    let mut later = fresh();
    let owner_address = address(&owner, 1);
    later.state.licenses_v2 = license_book(&[
        (0, owner_address),
        (1, owner_address),
        (2, owner_address),
        (3, owner_address),
    ]);
    let hand = later.hand_claim(&owner, 1, license_id(3), P, 1_000, 0, recipient());
    assert_eq!(outcome(&later.admit(&hand)), "Dividend(NotEntitled)");
    assert_refused(
        &later,
        &me(),
        request(3, 1_000),
        Refusal::NotEntitled,
        &hand,
    );
}

// ---------------------------------------------------------------------------------------------
// Authority
// ---------------------------------------------------------------------------------------------

#[test]
fn a_rotated_away_key_or_a_stranger_cannot_claim() {
    let mut world = fresh();
    let owner = owner_key();
    // A claim signed before the rotation.
    let before = world.hand_claim(&owner, 1, license_id(1), P, 1_000, 0, recipient());
    assert!(world.admit(&before).is_ok());
    world.rotate_owner();

    // The old key is stale for the wallet and for consensus.
    let hand = world.hand_claim(&owner, 1, license_id(1), P, 1_000, 0, recipient());
    assert_eq!(outcome(&world.admit(&hand)), "StaleOwner");
    assert_refused(
        &world,
        &me(),
        request(1, 1_000),
        Refusal::StaleAuthority,
        &hand,
    );
    let refusal = SignedOperation::import(&before, &world.view()).unwrap_err();
    assert_eq!(refusal, Refusal::StaleAuthority);
    assert_consensus_agrees(&world, &refusal, &before);
    assert!(licenses::controlled(&world.state, &descriptor(&owner, 1)).is_empty());

    // The new key controls every License recorded under the OLD address and can claim.
    let authority = address(&owner, 1);
    let rotated = SignerIdentity::new(&descriptor(&rotated_key(), 2), Some(authority)).unwrap();
    let controlled = licenses::controlled(&world.state, rotated.descriptor());
    assert_eq!(controlled.len(), 3);
    assert!(controlled.iter().all(|info| info.owner == authority));
    let view = world.view();
    let mine = entitlements::entitlements(&view, rotated.descriptor());
    assert_eq!(mine.len(), 3);
    let planned = plan(&op(request(1, 1_000)), &view, &rotated).unwrap();
    let reviewed = review(&planned, &view).unwrap();
    assert_eq!(reviewed.parties()[0].label, AddressLabel::ThisWallet);
    let signer = KeySigner::with_identity(
        rotated_key(),
        rotated.clone(),
        SigningGate::test_value().unwrap(),
        DEFAULT_IDLE_LIMIT,
    )
    .unwrap();
    let signed = flow::sign(planned, &signer, &view).unwrap();
    assert!(
        world.admit(signed.bytes()).is_ok(),
        "consensus admits the new key's claim"
    );

    // A stranger is not the required signer.
    let stranger = identity(&other_key());
    let hand = world.hand_claim(&other_key(), 1, license_id(1), P, 1_000, 0, recipient());
    assert_eq!(outcome(&world.admit(&hand)), "StaleOwner");
    assert_refused(
        &world,
        &stranger,
        request(1, 1_000),
        Refusal::NotRequiredSigner(Slot::Claim),
        &hand,
    );
}

#[test]
fn the_treasury_wallet_claims_only_through_the_treasury_profile() {
    let treasury = address(&treasury_key(), 1);
    let owner = address(&owner_key(), 1);
    let world = ClaimWorld::with_owners(&[(0, treasury), (1, owner)], TREASURY);
    let ordinary = identity(&treasury_key());
    let hand = world.hand_claim(&treasury_key(), 1, license_id(0), P, 1_000, 0, recipient());
    assert!(world.admit(&hand).is_ok(), "consensus has no profile rule");
    // Wallet policy (Q15): the Treasury authority never acts through an ordinary profile.
    let refusal = plan(
        &op(DividendClaimRequest::new(
            license_id(0),
            P,
            1_000,
            recipient(),
        )),
        &world.view(),
        &ordinary,
    )
    .unwrap_err();
    assert_eq!(refusal, Refusal::TreasuryProfileRequired);
    // Through the Treasury profile it plans, reviews with the Treasury acknowledgement, and signs.
    let profiled = ordinary.with_treasury_roles_for_test(TreasuryRoles {
        authority: true,
        destination_of: None,
    });
    let view = world.view();
    let planned = plan(
        &op(DividendClaimRequest::new(
            license_id(0),
            P,
            1_000,
            recipient(),
        )),
        &view,
        &profiled,
    )
    .unwrap();
    let reviewed = review(&planned, &view).unwrap();
    assert!(
        reviewed
            .acknowledgements()
            .contains(&AckKind::TreasuryAuthority)
    );
    assert!(
        reviewed
            .warnings()
            .iter()
            .any(|w| w.code == "TREASURY_CLAIMANT")
    );
    let signer = KeySigner::with_identity(
        treasury_key(),
        profiled,
        SigningGate::test_value().unwrap(),
        DEFAULT_IDLE_LIMIT,
    )
    .unwrap();
    let signed = flow::sign(planned, &signer, &view).unwrap();
    assert!(world.admit(signed.bytes()).is_ok());
}

#[test]
fn signer_and_approval_refusals_apply_to_claims() {
    let world = fresh();
    let view = world.view();
    let planned = plan(&op(request(1, 1_000)), &view, &me()).unwrap();
    // Another wallet's signer.
    let stranger = KeySigner::for_test(other_key()).unwrap();
    let approval = flow::approve(&review(&planned, &view).unwrap(), &view);
    assert_eq!(
        stranger
            .authorize(planned.clone(), approval, &view)
            .unwrap_err(),
        Refusal::NotRequiredSigner(Slot::Claim)
    );
    // The head moved.
    let signer = KeySigner::for_test(owner_key()).unwrap();
    let approval = flow::approve(&review(&planned, &view).unwrap(), &view);
    let next = world.later(1, 1);
    assert_eq!(
        signer
            .authorize(planned.clone(), approval, &next.view())
            .unwrap_err(),
        Refusal::StaleHead {
            reviewed: HEIGHT,
            current: HEIGHT + 1
        }
    );
    // An approval for another claim.
    let other = plan(&op(request(2, 1_000)), &view, &me()).unwrap();
    let approval = flow::approve(&review(&other, &view).unwrap(), &view);
    assert_eq!(
        signer
            .authorize(planned.clone(), approval, &view)
            .unwrap_err(),
        Refusal::PlanChanged
    );
    // A locked signer.
    let approval = flow::approve(&review(&planned, &view).unwrap(), &view);
    signer.lock();
    assert_eq!(
        signer
            .authorize(planned.clone(), approval, &view)
            .unwrap_err(),
        Refusal::Locked
    );
    // An idle-expired signer.
    let idle = KeySigner::with_identity(
        owner_key(),
        me(),
        SigningGate::test_value().unwrap(),
        Duration::from_millis(0),
    )
    .unwrap();
    let approval = flow::approve(&review(&planned, &view).unwrap(), &view);
    assert_eq!(
        idle.authorize(planned.clone(), approval, &view)
            .unwrap_err(),
        Refusal::Locked
    );
    // A TEST-VALUE signer on a production-class chain.
    let mut production = fresh();
    production.state.dividends = DividendState::genesis(
        Treasury::new(Class::Production, descriptor(&treasury_key(), 1)).unwrap(),
    );
    let triples: Vec<_> = (0..3)
        .map(|index| (license_id(index), address(&owner_key(), 1), Some(0)))
        .collect();
    production
        .state
        .dividends
        .advance(P, TREASURY, &triples)
        .unwrap();
    let production_view = production.view();
    assert_eq!(production_view.class(), ChainClass::Production);
    let planned = plan(&op(request(1, 1_000)), &production_view, &me()).unwrap();
    let signer = KeySigner::for_test(owner_key()).unwrap();
    let approval = flow::approve(
        &review(&planned, &production_view).unwrap(),
        &production_view,
    );
    assert_eq!(
        signer
            .authorize(planned, approval, &production_view)
            .unwrap_err(),
        Refusal::ChainClassMismatch {
            gate: ChainClass::TestValue,
            chain: ChainClass::Production
        }
    );
    // A signed claim cannot be cancelled: the protocol has no such object.
    assert_eq!(
        plan(
            &OperationRequest::Cancel(CancelRequest::new(CancelTarget::DividendClaim)),
            &view,
            &me()
        )
        .unwrap_err(),
        Refusal::CancelNotAvailable(CancelTarget::DividendClaim)
    );
}

// ---------------------------------------------------------------------------------------------
// Context, window and policy
// ---------------------------------------------------------------------------------------------

#[test]
fn a_foreign_context_is_refused_field_by_field_like_consensus() {
    let world = fresh();
    let owner = owner_key();
    let edits: [(BodyEdit, ContextField); 3] = [
        (|b| b.network = NETWORK_ID ^ 1, ContextField::Network),
        (|b| b.genesis[0] ^= 1, ContextField::Genesis),
        (|b| b.fingerprint[31] ^= 1, ContextField::Fingerprint),
    ];
    for (edit, field) in edits {
        let mut body = claim_body(license_id(1), P, 1_000, 0, recipient());
        edit(&mut body);
        assert_bytes_refused(&world, body.clone(), Refusal::WrongContext(field));
        let hand = sign_claim(body, &owner, 1);
        assert_eq!(outcome(&world.admit(&hand)), "Context");
        assert_consensus_agrees(&world, &Refusal::WrongContext(field), &hand);
    }
}

#[test]
fn validity_windows_are_bounded_and_enforced_like_consensus() {
    let world = fresh();
    let owner = owner_key();
    // The request: at least one block, at most the protocol horizon of 10,080.
    for blocks in [0u64, 10_081, u64::MAX] {
        assert_eq!(
            plan(
                &op(request(1, 1_000).with_validity_blocks(blocks)),
                &world.view(),
                &me()
            )
            .unwrap_err(),
            Refusal::InvalidValidity,
            "{blocks}"
        );
    }
    for blocks in [1u64, 144, 10_080] {
        let planned = plan(
            &op(request(1, 1_000).with_validity_blocks(blocks)),
            &world.view(),
            &me(),
        )
        .unwrap();
        assert_eq!(planned.validity().created, HEIGHT + 1);
        assert_eq!(planned.validity().expiry, HEIGHT + 1 + blocks);
    }
    // Bytes from elsewhere: a window wider than the horizon, not yet open, already closed.
    let cases: [(u64, u64, Refusal); 3] = [
        (1, 10_082, Refusal::InvalidValidity),
        (
            HEIGHT + 2,
            HEIGHT + 20,
            Refusal::WindowNotOpen {
                created: HEIGHT + 2,
                next_height: HEIGHT + 1,
            },
        ),
        (
            1,
            HEIGHT,
            Refusal::WindowClosed {
                expiry: HEIGHT,
                next_height: HEIGHT + 1,
            },
        ),
    ];
    for (created, expiry, expected) in cases {
        let mut body = claim_body(license_id(1), P, 1_000, 0, recipient());
        body.created_height = created;
        body.expiry_height = expiry;
        assert_bytes_refused(&world, body.clone(), expected.clone());
        let hand = sign_claim(body, &owner, 1);
        assert_eq!(outcome(&world.admit(&hand)), "Window");
        assert_consensus_agrees(&world, &expected, &hand);
    }
}

#[test]
fn a_claim_to_the_zero_address_is_refused_by_wallet_policy() {
    let world = fresh();
    let zero = DividendClaimRequest::new(license_id(1), P, 1_000, [0; 32]);
    assert_eq!(
        plan(&op(zero), &world.view(), &me()).unwrap_err(),
        Refusal::InvalidRecipient
    );
    let body = claim_body(license_id(1), P, 1_000, 0, [0; 32]);
    let raw = unsigned_claim(body.clone(), descriptor(&owner_key(), 1));
    assert!(
        SignedClaim::decode(&raw).is_err(),
        "native codec excludes a zero destination"
    );
    // The low-level helper signs arbitrary bodies; canonical decoding and admission
    // still refuse these bytes before a zero-destination claim can execute.
    let malformed = SignedClaim::sign(body, descriptor(&owner_key(), 1), &owner_key()).unwrap();
    assert_eq!(
        SignedClaim::decode(&malformed.encode()).unwrap_err(),
        mutiny_consensus_v8::dividend_claim_v1::ClaimError::Destination
    );
    assert_eq!(
        world.admit(&malformed.encode()).unwrap_err(),
        mutiny_consensus_v8::dividend_claim_v1::ClaimError::Destination
    );
    assert_eq!(
        adopt(&raw, &world.view(), &me()).unwrap_err(),
        Refusal::UnknownOperation
    );
    assert_eq!(
        explain(&raw, &world.view(), &me()).unwrap_err(),
        Refusal::UnknownOperation
    );
    assert_eq!(
        SignedOperation::import(&raw, &world.view()).unwrap_err(),
        Refusal::UnknownOperation
    );
    // Pair the codec negative with an otherwise identical real positive.
    let hand = world.hand_claim(&owner_key(), 1, license_id(1), P, 1_000, 0, recipient());
    world.admit(&hand).unwrap();
    SignedOperation::import(&hand, &world.view()).unwrap();
}

#[test]
fn an_exhausted_treasury_has_no_coin_plan_like_consensus() {
    let owner = owner_key();
    // The ledger reserves 600,000 but the Treasury's coins hold only 100 atoms (a state that
    // could never be a verified one: every state root checks the backing).
    let mut poor = fresh();
    poor.state.coins.insert(
        treasury_coin(),
        Coin {
            output: Output {
                owner: address(&treasury_key(), 1),
                atoms: 100,
            },
            created_height: 0,
            coinbase: false,
        },
    );
    let hand = poor.hand_claim(&owner, 1, license_id(1), P, 1_000, 0, recipient());
    assert_eq!(outcome(&poor.admit(&hand)), "Backing");
    assert_refused(
        &poor,
        &me(),
        request(1, 1_000),
        Refusal::ReserveBackingViolation {
            reserved: 600_000,
            backing_after: 100,
        },
        &hand,
    );
    // Coinbase coins never pay a claim.
    let mut coinbase = fresh();
    coinbase.state.coins.insert(
        treasury_coin(),
        Coin {
            output: Output {
                owner: address(&treasury_key(), 1),
                atoms: TREASURY,
            },
            created_height: 0,
            coinbase: true,
        },
    );
    let hand = coinbase.hand_claim(&owner, 1, license_id(1), P, 1_000, 0, recipient());
    assert_eq!(outcome(&coinbase.admit(&hand)), "Backing");
    assert_refused(
        &coinbase,
        &me(),
        request(1, 1_000),
        Refusal::ReserveBackingViolation {
            reserved: 600_000,
            backing_after: 0,
        },
        &hand,
    );
}

#[test]
fn a_claim_whose_identity_is_already_used_is_a_replay_like_consensus() {
    // Only an unauthenticated state can hold a coin at a fresh claim's identity (the identity
    // includes the sequence, which advances whenever a claim applies); consensus checks it anyway.
    let mut world = fresh();
    let hand = world.hand_claim(&owner_key(), 1, license_id(1), P, 1_000, 0, recipient());
    assert!(world.admit(&hand).is_ok());
    let id = SignedClaim::decode(&hand).unwrap().id();
    world.state.coins.insert(
        OutPoint {
            transaction: id,
            index: 0,
        },
        Coin {
            output: Output {
                owner: recipient(),
                atoms: 1,
            },
            created_height: 1,
            coinbase: false,
        },
    );
    assert_eq!(outcome(&world.admit(&hand)), "Duplicate");
    let refusal = SignedOperation::import(&hand, &world.view()).unwrap_err();
    assert_eq!(refusal, Refusal::Replay);
    assert_consensus_agrees(&world, &refusal, &hand);
}

// ---------------------------------------------------------------------------------------------
// Outbox: one outstanding claim per (award, License), release, reconciliation
// ---------------------------------------------------------------------------------------------

#[test]
fn a_second_outstanding_claim_for_the_same_award_and_license_is_refused() {
    let world = fresh();
    let view = world.view();
    let signer = KeySigner::for_test(owner_key()).unwrap();
    // Two claims for the same pair planned at the same head carry the same sequence.
    let first = plan(&op(request(1, 1_000)), &view, &me()).unwrap();
    let second = plan(&op(request(1, 2_000)), &view, &me()).unwrap();
    let sequence = |p: &OperationPlan| {
        SignedClaim::decode(&p.objects()[0].bytes)
            .unwrap()
            .body
            .sequence
    };
    assert_eq!((sequence(&first), sequence(&second)), (0, 0));
    let first = flow::sign(first, &signer, &view).unwrap();
    let second = flow::sign(second, &signer, &view).unwrap();
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&first, &view).unwrap();
    // The outbox refuses the second while the first is open: one row only.
    assert_eq!(
        outbox.commit(&second, &view).unwrap_err(),
        Refusal::ReservedInput
    );
    assert_eq!(outbox.records().unwrap().len(), 1);
    // A plan over a view that merges the outbox's reservations is refused, for any amount or
    // destination; another License is unaffected.
    let mut held = ClaimWorld::new(3, TREASURY);
    held.reserved = outbox.reserved().unwrap();
    let held_view = held.view();
    for amount in [1u64, 1_000, SHARE] {
        assert_eq!(
            plan(&op(request(1, amount)), &held_view, &me()).unwrap_err(),
            Refusal::ReservedInput
        );
    }
    assert_eq!(
        plan(
            &op(DividendClaimRequest::new(
                license_id(1),
                P,
                5,
                address(&owner_key(), 1)
            )),
            &held_view,
            &me()
        )
        .unwrap_err(),
        Refusal::ReservedInput
    );
    assert!(plan(&op(request(2, 1_000)), &held_view, &me()).is_ok());
    assert_eq!(
        entitlements::entitlement(&held_view, P, license_id(1))
            .unwrap()
            .claimability,
        Claimability::Outstanding
    );
    // Forgetting the record releases the slot; the sequence still comes from confirmed state (0),
    // never from the outbox.
    outbox.forget(&first.id()).unwrap();
    held.reserved = outbox.reserved().unwrap();
    assert!(held.reserved.is_empty());
    let again = plan(&op(request(1, 3_000)), &held.view(), &me()).unwrap();
    assert_eq!(sequence(&again), 0);
    // On chain only one claim with a given sequence can ever apply: once one is applied, the other
    // is a replay for consensus and for the wallet.
    let mut applied = fresh();
    applied.set_account(P, license_id(1), SHARE - 1_000, 1);
    assert_eq!(outcome(&applied.admit(second.bytes())), "Dividend(Replay)");
    assert_eq!(
        SignedOperation::import(second.bytes(), &applied.view()).unwrap_err(),
        Refusal::Replay
    );
}

#[test]
fn reconciliation_reads_only_verified_state() {
    let world = fresh();
    let view = world.view();
    let signer = KeySigner::for_test(owner_key()).unwrap();
    let signed = flow::sign(
        plan(&op(request(1, 1_000)), &view, &me()).unwrap(),
        &signer,
        &view,
    )
    .unwrap();
    let queue = || {
        let mut outbox = MemoryOutbox::new();
        outbox.commit(&signed, &view).unwrap();
        outbox
    };
    let settle = |outbox: &mut MemoryOutbox, world: &ClaimWorld| {
        outbox.reconcile(&world.view()).unwrap();
        outbox.get(&signed.id()).unwrap().unwrap().status
    };

    // Nothing happened: pending, slot still held.
    let mut outbox = queue();
    assert_eq!(
        settle(&mut outbox, &world.later(1, 1)),
        OutboxStatus::Queued
    );
    assert_eq!(outbox.reserved().unwrap().len(), 1);

    // Included: the payout coin (claim id, 0) exists, and the account advanced.
    let mut included = world.later(1, 1);
    included.set_account(P, license_id(1), SHARE - 1_000, 1);
    included.state.coins.insert(
        OutPoint {
            transaction: signed.id(),
            index: 0,
        },
        Coin {
            output: Output {
                owner: recipient(),
                atoms: 1_000,
            },
            created_height: HEIGHT + 1,
            coinbase: false,
        },
    );
    let mut outbox = queue();
    assert_eq!(
        settle(&mut outbox, &included),
        OutboxStatus::Confirmed(HEIGHT + 1)
    );
    assert!(outbox.reserved().unwrap().is_empty());

    // Replaced: the sequence was used but no coin of this claim exists (another claim with the same
    // sequence, or this one with its payout spent again).
    let mut replaced = world.later(1, 1);
    replaced.set_account(P, license_id(1), SHARE - 7, 1);
    let mut outbox = queue();
    assert_eq!(settle(&mut outbox, &replaced), OutboxStatus::InputsSpent);
    assert!(outbox.reserved().unwrap().is_empty());

    // Expired by height.
    let mut outbox = queue();
    let expiry = signed.validity().expiry;
    assert_eq!(
        settle(&mut outbox, &world.later(expiry - HEIGHT, 1)),
        OutboxStatus::Expired
    );

    // Expired with the award: every later block is past the window.
    let mut outbox = queue();
    assert_eq!(
        settle(&mut outbox, &world.later(1, W)),
        OutboxStatus::Expired
    );

    // A view older than the queueing head says nothing.
    let mut outbox = queue();
    let mut older = ClaimWorld::new(3, TREASURY);
    older.anchor.height = HEIGHT - 1;
    older.set_account(P, license_id(1), SHARE - 7, 1);
    assert_eq!(settle(&mut outbox, &older), OutboxStatus::Queued);
}

/// Order W20: the "at most" wording for the time left rests on consensus' timestamp rule. A block's
/// timestamp must be above the median of its ancestors AND not below its parent's
/// (`pow::validate_timestamp`), so along a chain that extends the verified head the epoch
/// `mining_epoch(timestamp, t0)` never falls: the including block's epoch is at least the head's,
/// and the epochs left at inclusion are at most those left at the head. A timestamp above the
/// median but below the parent's (what the earlier median-only rule allowed, letting epochs
/// regress) is refused. If consensus ever dropped the rule this test fails, and the wording must
/// change with it.
#[test]
fn the_at_most_wording_rests_on_consensus_refusing_a_regressing_timestamp() {
    use mutiny_consensus_v8::pow::{mining_epoch, validate_timestamp};
    let t0 = 1_000_u64;
    // Eleven ancestors, one minute apart; the parent is the latest.
    let ancestors: Vec<u64> = (0..11).map(|i| t0 + 60 * i).collect();
    let parent = *ancestors.last().unwrap();
    let median = ancestors[ancestors.len() / 2];
    // Above the median, below the parent: refused.
    let regressing = parent - 61;
    assert!(regressing > median);
    assert!(mining_epoch(regressing, t0).unwrap() < mining_epoch(parent, t0).unwrap());
    assert!(validate_timestamp(12, regressing, t0, &ancestors).is_err());
    assert!(validate_timestamp(12, parent - 1, t0, &ancestors).is_err());
    // The parent's own timestamp and anything later: accepted, and the epoch never falls.
    for timestamp in [parent, parent + 1, parent + 60, parent + 86_400] {
        assert!(validate_timestamp(12, timestamp, t0, &ancestors).is_ok());
        assert!(mining_epoch(timestamp, t0).unwrap() >= mining_epoch(parent, t0).unwrap());
    }
    // The review states the bound at the head's epoch, and the threshold of its warning is the
    // display constant (not the consensus claim window, not a claim time-to-live).
    assert_eq!(review::CLAIM_DEADLINE_WARNING_EPOCHS, 1_440);
    assert_eq!(
        ops::dividend::NEAR_DEADLINE_EPOCHS,
        review::CLAIM_DEADLINE_WARNING_EPOCHS
    );
    assert_ne!(
        review::CLAIM_DEADLINE_WARNING_EPOCHS,
        mutiny_consensus_v8::dividends_v1::CLAIM_WINDOW_EPOCHS
    );
    let world = fresh();
    let view = world.view();
    let reviewed = review(&plan(&op(request(1, 1_000)), &view, &me()).unwrap(), &view).unwrap();
    let head_epoch = view.epoch().unwrap();
    let time_left = reviewed
        .rows()
        .into_iter()
        .find(|row| row.label == "Time left")
        .unwrap();
    assert!(
        time_left.value.starts_with("At most ")
            && time_left
                .value
                .contains(&format!("after the verified block's epoch ({head_epoch})")),
        "{}",
        time_left.value
    );
}

/// Order W20: an ordinary claim needs its owner's signature and nothing else (no Treasury
/// co-signature, no Treasury acknowledgement), and consensus admits it as signed.
#[test]
fn an_ordinary_claim_needs_only_its_owner_and_no_treasury_signature() {
    let world = fresh();
    let view = world.view();
    let planned = plan(&op(request(1, 1_000)), &view, &me()).unwrap();
    assert_eq!(planned.requirements().len(), 1);
    assert_eq!(planned.requirements()[0].slot, Slot::Claim);
    assert_eq!(
        planned.requirements()[0].status,
        RequirementStatus::ThisWallet
    );
    let reviewed = review(&planned, &view).unwrap();
    assert!(
        !reviewed
            .acknowledgements()
            .contains(&AckKind::TreasuryAuthority)
    );
    assert!(
        !reviewed
            .warnings()
            .iter()
            .any(|w| w.code == "TREASURY_CLAIMANT")
    );
    let signer = KeySigner::for_test(owner_key()).unwrap();
    let signed = flow::sign(planned, &signer, &view).unwrap();
    assert!(signed.is_complete());
    assert!(signed.missing().is_empty());
    assert!(
        world.admit(signed.bytes()).is_ok(),
        "consensus admits the claim with the owner's signature alone"
    );
}
