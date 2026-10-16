//! The refusal table of phase 5B (License DvP, fiat lock, fiat release, offers): one test per
//! applicable refusal. Encodable cases check the wallet's refusal AND consensus' verdict on the signed
//! equivalent (`trading_v1::prepare_batch` on the same synthetic state, every party played through
//! the consensus API), and that nothing was queued or signed. Unsignable zero-destination bodies
//! are checked at the native codec boundary without fabricating a complete signature.
//! NATIVE, TEST-VALUE; public test keys only, with synthetic unit histories explicitly scoped.
#[path = "support/synthetic.rs"]
mod synthetic;
#[path = "support/trading_5b.rs"]
mod trading;

use mutiny_consensus_v8::{
    Hash,
    trading_v1::{
        self, Action, NativeError, NativeOperation, OfferBody, OfferProof, Prepared, SignedOffer,
        Strikes,
    },
    transactions::OutPoint,
    wallet_rotation_v1::Rotation,
};
use mutiny_crypto_v2::HybridKey;
use mutiny_wallet_core_v8::*;
use std::collections::BTreeSet;
use synthetic::{World, address, descriptor, identity, key_a, key_b, key_c};

const PRICE: u64 = 2_000_000;
const TRADE: [u8; 32] = [0x71; 32];
const CONTRACT: [u8; 32] = [0x72; 32];
const HEAD: u64 = 100;

/// A synthetic chain at `head`: wallets A (the seller) and B (the buyer) registered; the public
/// License Book with its first License owned by `owner`; two coins of B.
fn world_at(head: u64, owner: Hash, pending: bool) -> (World, Hash) {
    let mut world = World::new(head);
    for key in [key_a(), key_b()] {
        world.state.wallets.register(&descriptor(&key, 1)).unwrap();
    }
    let license = trading::install_licenses(&mut world.state, owner, pending);
    world.coin(address(&key_b(), 1), 5_000_000, 1, false, 0xb1, 0);
    world.coin(address(&key_b(), 1), 3_000_000, 1, false, 0xb2, 0);
    assert!(
        world.state.root().is_ok(),
        "a consensus-valid synthetic state"
    );
    (world, license)
}

struct Sale {
    world: World,
    license: Hash,
    maker: HybridKey,
    offer: SignedOffer,
}

fn sale() -> Sale {
    let (world, license) = world_at(HEAD, address(&key_a(), 1), false);
    let maker = trading::maker();
    let offer = license_offer(&world, &maker, license, 1, PRICE);
    Sale {
        world,
        license,
        maker,
        offer,
    }
}

fn license_offer(
    world: &World,
    maker: &HybridKey,
    license: Hash,
    generation: u64,
    price: u64,
) -> SignedOffer {
    trading::offer(
        maker,
        trading::context_of(&world.anchor),
        trading::license_terms(license, generation, price),
        50,
        200,
        0,
        0x31,
    )
}

fn request(offer: &SignedOffer, license: Hash) -> OperationRequest {
    OperationRequest::LicenseDvp(
        LicenseDvpRequest::new(Blob::new(trading::offer_bytes(offer)), license)
            .with_commitments(TRADE, CONTRACT),
    )
}

/// The buyer's plan of the standard sale and its unsigned bytes.
fn unsigned(sale: &Sale) -> Vec<u8> {
    plan(
        &request(&sale.offer, sale.license),
        &sale.world.view(),
        &identity(&key_b()),
    )
    .unwrap()
    .objects()[0]
        .bytes
        .clone()
}

/// The same bytes signed by every party through the consensus API.
fn complete(sale: &Sale, raw: &[u8]) -> Vec<u8> {
    trading::sign_all(
        raw,
        &[(0, &key_a(), 1), (1, &key_b(), 1)],
        Some((&sale.maker, &sale.offer)),
    )
}

fn set_action(raw: &[u8], change: impl FnOnce(&mut Action)) -> Vec<u8> {
    trading::mutate(raw, |wire| change(&mut wire.operation.action))
}

fn native<T: std::fmt::Debug>(verdict: Result<T, NativeError>) -> NativeError {
    verdict.expect_err("consensus must refuse")
}

/// No row queued anywhere and nothing reserved.
fn no_trace(outbox: &MemoryOutbox) {
    assert!(outbox.records().unwrap().is_empty());
    assert!(outbox.reserved().unwrap().is_empty());
}

fn explain_as(raw: &[u8], world: &World, key: &HybridKey) -> Result<Review, Refusal> {
    explain(raw, &world.view(), &identity(key))
}

#[test]
fn the_unmodified_sale_is_accepted_by_the_wallet_and_by_consensus() {
    let sale = sale();
    let raw = unsigned(&sale);
    let view = sale.world.view();
    assert!(explain_as(&raw, &sale.world, &key_a()).is_ok());
    let signed = complete(&sale, &raw);
    trading::consensus(&view, &signed).expect("control: consensus accepts the planned sale");
    // The paying address is the consensus accessor's: the buyer pays price, change and fee.
    let wire = NativeOperation::decode(&raw).unwrap();
    assert_eq!(wire.operation.fee_payer(), address(&key_b(), 1));
    assert_eq!(
        explain_as(&raw, &sale.world, &key_a()).unwrap().fee().payer,
        FeePayer::Counterparty(wire.operation.fee_payer())
    );
    for point in &wire.inputs {
        assert_eq!(
            sale.world.state.coins[point].output.owner,
            wire.operation.fee_payer()
        );
    }
    let imported = SignedOperation::import(&signed, &view).unwrap();
    assert!(imported.is_complete());
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&imported, &view).unwrap();
    assert_eq!(outbox.pending().unwrap().len(), 1);
}

#[test]
fn a_stale_license_generation_is_refused_by_both() {
    let sale = sale();
    // A first sale A -> B is applied: the License is at generation 2, owned by B.
    let first = complete(&sale, &unsigned(&sale));
    let state = trading::consensus(&sale.world.view(), &first)
        .unwrap()
        .into_state();
    let mut next = World::new(HEAD + 1);
    next.state = state;
    next.coin(address(&key_a(), 1), 5_000_000, 1, false, 0xa1, 0);
    assert_eq!(
        trading_v1::license_generation(&next.state, sale.license),
        Ok(2)
    );
    // B now sells to A, but the offer still names generation 1.
    let stale_offer = license_offer(&next, &key_b(), sale.license, 1, PRICE);
    let mut outbox = MemoryOutbox::new();
    assert_eq!(
        plan(
            &request(&stale_offer, sale.license),
            &next.view(),
            &identity(&key_a())
        )
        .unwrap_err(),
        Refusal::LicenseGenerationStale
    );
    // The same sale built for generation 2, then rewritten to name generation 1 (with the matching
    // generation-1 offer): the wallet and consensus refuse it.
    let fresh_offer = license_offer(&next, &key_b(), sale.license, 2, PRICE);
    let good = plan(
        &request(&fresh_offer, sale.license),
        &next.view(),
        &identity(&key_a()),
    )
    .unwrap()
    .objects()[0]
        .bytes
        .clone();
    let stale = trading::mutate(&good, |wire| {
        let id = stale_offer.body.id().unwrap();
        let maker = stale_offer.body.maker().unwrap();
        if let Action::LicenseDvp {
            license_generation,
            offer,
            maker: named,
            ..
        } = &mut wire.operation.action
        {
            *license_generation = 1;
            *offer = id;
            *named = maker;
        }
        wire.operation.offer_proof = Some(OfferProof {
            offer: stale_offer.clone(),
            fill_signature: trading::zero(),
        });
    });
    assert_eq!(
        explain_as(&stale, &next, &key_b()).unwrap_err(),
        Refusal::LicenseGenerationStale
    );
    let signed = trading::sign_all(
        &stale,
        &[(0, &key_b(), 1), (1, &key_a(), 1)],
        Some((&key_b(), &stale_offer)),
    );
    assert_eq!(
        native(trading::consensus(&next.view(), &signed)),
        NativeError::Conflict
    );
    no_trace(&outbox);
    let _ = &mut outbox;
}

#[test]
fn an_unrepresentable_zero_sequence_assignment_and_changed_signed_facts_are_refused() {
    let sale = sale();
    let raw = unsigned(&sale);
    let (pending, license) = world_at(HEAD, address(&key_a(), 1), true);
    assert_eq!(license, sale.license);
    assert_eq!(pending.state.licenses_v2.license(license).unwrap().assignment_sequence, 0,
        "this fixture is the zero-sequence envelope refusal, not a ban on all pending assignments");
    assert!(
        pending
            .state
            .licenses_v2
            .pending_assignment(license)
            .is_some()
    );
    assert_eq!(
        plan(
            &request(&sale.offer, license),
            &pending.view(),
            &identity(&key_b())
        )
        .unwrap_err(),
        Refusal::PendingAssignmentOrLock
    );
    assert_eq!(
        explain_as(&raw, &pending, &key_a()).unwrap_err(),
        Refusal::LicenseGenerationStale
    );
    assert_eq!(
        native(trading::consensus(&pending.view(), &complete(&sale, &raw))),
        NativeError::Stale(mutiny_consensus_v8::op_envelope_v1::TAG_LICENSE_ASSIGNMENT)
    );
}

#[test]
fn a_license_not_owned_by_the_seller_is_refused_by_both() {
    let sale = sale();
    let raw = unsigned(&sale);
    // The same License owned by C: the operation names A as the seller.
    let (other, _) = world_at(HEAD, address(&key_c(), 1), false);
    assert_eq!(
        explain_as(&raw, &other, &key_b()).unwrap_err(),
        Refusal::LicenseNotOwned
    );
    assert_eq!(
        native(trading::consensus(&other.view(), &complete(&sale, &raw))),
        NativeError::Authority
    );
}

#[test]
fn seller_equal_to_buyer_and_a_price_other_than_the_offer_are_refused_by_both() {
    let sale = sale();
    let raw = unsigned(&sale);
    let view = sale.world.view();
    // The seller's own address as the buyer.
    let to_self = trading::mutate(&raw, |wire| {
        if let Action::LicenseDvp { buyer, .. } = &mut wire.operation.action {
            *buyer = address(&key_a(), 1);
        }
        wire.operation.approvals[1].descriptor = descriptor(&key_a(), 1);
    });
    assert!(matches!(
        explain_as(&to_self, &sale.world, &key_a()).unwrap_err(),
        Refusal::InvalidRequest(_)
    ));
    let signed = trading::sign_all(
        &to_self,
        &[(0, &key_a(), 1), (1, &key_a(), 1)],
        Some((&sale.maker, &sale.offer)),
    );
    assert_eq!(
        native(trading::consensus(&view, &signed)),
        NativeError::Bounds
    );
    // Price zero cannot even be offered: an offer of price zero does not encode, so no maker can
    // sign one ...
    let zero_price = OfferBody {
        terms: trading::license_terms(sale.license, 1, 0),
        ..sale.offer.body.clone()
    };
    assert_eq!(zero_price.encode(), Err(trading_v1::Error::Bounds));
    // ... and a sale whose price differs from the offer's (zero or any other) is refused at the
    // exact-terms rule, before the price rule, by both.
    for price in [0, PRICE - 1] {
        let changed = set_action(&raw, |action| {
            if let Action::LicenseDvp {
                price: p, change, ..
            } = action
            {
                change.0 += p.0 - price;
                *p = Strikes(price);
            }
        });
        assert_eq!(
            explain_as(&changed, &sale.world, &key_a()).unwrap_err(),
            Refusal::OfferProofInvalid
        );
        assert_eq!(
            native(trading::consensus(&view, &complete(&sale, &changed))),
            NativeError::Candidate(trading_v1::Error::OfferBinding)
        );
    }
}

#[test]
fn a_zero_payment_destination_cannot_redirect_the_signed_maker_offer() {
    let sale = sale();
    let raw = unsigned(&sale);
    let mut wire = NativeOperation::decode(&raw).unwrap();
    assert!(wire.operation.body().is_ok(), "unmodified signable native control");
    if let Action::LicenseDvp {
        payment_destination,
        ..
    } = &mut wire.operation.action {
        *payment_destination = [0; 32];
    }
    // Wallet policy, as for payments: never pay to the zero address.
    assert_eq!(
        plan(
            &OperationRequest::LicenseDvp(
                LicenseDvpRequest::new(Blob::new(trading::offer_bytes(&sale.offer)), sale.license)
                    .with_commitments(TRADE, CONTRACT)
                    .with_payment_destination([0; 32])
            ),
            &sale.world.view(),
            &identity(&key_b())
        )
        .unwrap_err(),
        Refusal::InvalidRecipient
    );
    // Version-2 offers commit a nonzero destination. A redirected operation cannot obtain a
    // signable native body or a valid fill proof; do not manufacture a complete signed object.
    let mut zero_body = sale.offer.body.clone();
    zero_body.destination = [0; 32];
    assert_eq!(zero_body.encode(), Err(trading_v1::Error::Bounds));
    assert_eq!(
        OfferProof::sign(sale.offer.clone(), &wire.operation, &sale.maker),
        Err(trading_v1::Error::Bounds)
    );
    assert_eq!(wire.operation.body(), Err(trading_v1::Error::Bounds));
    assert_eq!(wire.encode(), Err(NativeError::Candidate(trading_v1::Error::Bounds)));
}

#[test]
fn inclusion_outside_the_signed_window_is_refused_by_both() {
    let sale = sale();
    let raw = unsigned(&sale);
    let view = sale.world.view();
    for (inclusion, expected, native_expected) in [
        (
            HEAD + 2,
            Refusal::WindowNotOpen {
                created: HEAD + 2,
                next_height: HEAD + 1,
            },
            mutiny_consensus_v8::op_envelope_v1::EnvelopeError::Future,
        ),
        (
            HEAD,
            Refusal::WindowClosed {
                expiry: HEAD,
                next_height: HEAD + 1,
            },
            mutiny_consensus_v8::op_envelope_v1::EnvelopeError::Expired,
        ),
    ] {
        let moved = trading::mutate(&raw, |wire| {
            wire.operation.meta.envelope.first_height = inclusion;
            wire.operation.meta.envelope.last_height = inclusion;
            if inclusion <= HEAD {
                wire.operation.meta.envelope.reference_height = inclusion - 1;
            }
        });
        assert_eq!(
            explain_as(&moved, &sale.world, &key_a()).unwrap_err(),
            expected
        );
        assert_eq!(
            native(trading::consensus(&view, &complete(&sale, &moved))),
            NativeError::Envelope(native_expected)
        );
    }
}

#[test]
fn a_consumed_offer_is_refused_by_both() {
    // A fiat offer can be consumed without changing anything else the second fill depends on, so
    // the single-fill rule is isolated there.
    let mut world = World::new(HEAD);
    for key in [key_a(), key_b()] {
        world.state.wallets.register(&descriptor(&key, 1)).unwrap();
    }
    world.coin(address(&key_a(), 1), 5_000_000, 1, false, 0xa1, 0);
    world.coin(address(&key_a(), 1), 4_000_000, 1, false, 0xa2, 0);
    let maker = trading::maker();
    let offer = trading::offer(
        &maker,
        trading::context_of(&world.anchor),
        trading::fiat_terms(1_000_000, [0x77; 32]),
        50,
        200,
        0,
        0x41,
    );
    let lock = |world: &World| {
        plan(
            &OperationRequest::FiatLock(
                FiatLockRequest::new(
                    Blob::new(trading::offer_bytes(&offer)),
                    address(&key_b(), 1),
                    1_000_000,
                    [0x77; 32],
                )
                .with_commitments(TRADE, CONTRACT),
            ),
            &world.view(),
            &identity(&key_a()),
        )
    };
    let first = lock(&world).unwrap().objects()[0].bytes.clone();
    let first_signed = trading::sign_all(
        &first,
        &[(0, &key_a(), 1), (1, &key_b(), 1)],
        Some((&maker, &offer)),
    );
    let state = trading::consensus(&world.view(), &first_signed)
        .unwrap()
        .into_state();
    let mut next = World::new(HEAD + 1);
    next.state = state;
    // The planner refuses at once; a second lock built before the first was applied (other coin)
    // is refused by the wallet and by consensus.
    assert_eq!(lock(&next).unwrap_err(), Refusal::OfferConsumed);
    let mut reserved_first = World::new(HEAD);
    reserved_first.state = world.state.clone();
    reserved_first.reserved = BTreeSet::from([OutPoint {
        transaction: [0xa1; 32],
        index: 0,
    }]);
    let original_second = lock(&reserved_first).unwrap().objects()[0].bytes.clone();
    assert_eq!(explain_as(&original_second, &next, &key_b()).unwrap_err(),
        Refusal::StaleAuthority, "no historical anchor attached to this synthetic view");
    // A separately reviewed unsigned candidate at the new synthetic head isolates consumption;
    // no already-signed operation is rebased.
    let second = trading::mutate(&original_second, |wire| {
        wire.operation.meta.envelope.first_height = next.anchor.height + 1;
        wire.operation.meta.envelope.last_height = next.anchor.height + 1;
        wire.operation.meta.envelope.reference_height = next.anchor.height;
        wire.operation.meta.envelope.reference_block = next.anchor.block;
    });
    assert_eq!(
        explain_as(&second, &next, &key_b()).unwrap_err(),
        Refusal::OfferConsumed
    );
    let second_signed = trading::sign_all(
        &second,
        &[(0, &key_a(), 1), (1, &key_b(), 1)],
        Some((&maker, &offer)),
    );
    assert_eq!(
        native(trading::consensus(&next.view(), &second_signed)),
        NativeError::Duplicate
    );
    // A License offer, once filled, is refused too (consensus reaches the generation rule first,
    // because the sale that consumed it moved the License's generation on).
    let sale = sale();
    let applied = trading::consensus(&sale.world.view(), &complete(&sale, &unsigned(&sale)))
        .unwrap()
        .into_state();
    let mut after = World::new(HEAD + 1);
    after.state = applied;
    assert!(
        plan(
            &request(&sale.offer, sale.license),
            &after.view(),
            &identity(&key_b())
        )
        .is_err()
    );
    assert_eq!(
        native(trading::consensus(
            &after.view(),
            &complete(
                &sale,
                &trading::mutate(&unsigned(&sale), |wire| {
                    wire.operation.meta.envelope.first_height = HEAD + 2;
                    wire.operation.meta.envelope.last_height = HEAD + 2;
                    wire.operation.meta.envelope.reference_height = after.anchor.height;
                    wire.operation.meta.envelope.reference_block = after.anchor.block;
                })
            )
        )),
        NativeError::Stale(mutiny_consensus_v8::op_envelope_v1::TAG_LICENSE_ASSIGNMENT),
        "a newly signed distinct sale still carries the old assignment facts"
    );
}

#[test]
fn an_offer_outside_its_window_is_refused_by_both() {
    let sale = sale();
    let raw = unsigned(&sale);
    // Expired: the offer is fillable up to block 200.
    let (late, _) = world_at(200, address(&key_a(), 1), false);
    assert_eq!(
        plan(
            &request(&sale.offer, sale.license),
            &late.view(),
            &identity(&key_b())
        )
        .unwrap_err(),
        Refusal::OfferExpired {
            expiry: 200,
            next_height: 201
        }
    );
    let moved = |parent: &World| {
        let height = parent.anchor.height + 1;
        trading::mutate(&raw, |wire| {
            wire.operation.meta.envelope.first_height = height;
            wire.operation.meta.envelope.last_height = height;
            wire.operation.meta.envelope.reference_height = parent.anchor.height;
            wire.operation.meta.envelope.reference_block = parent.anchor.block;
        })
    };
    let at_201 = moved(&late);
    assert_eq!(
        explain_as(&at_201, &late, &key_a()).unwrap_err(),
        Refusal::OfferExpired {
            expiry: 200,
            next_height: 201
        }
    );
    assert_eq!(
        native(trading::consensus(&late.view(), &complete(&sale, &at_201))),
        NativeError::Candidate(trading_v1::Error::Expired)
    );
    // Not yet valid: the offer opens at block 50.
    let (early, _) = world_at(40, address(&key_a(), 1), false);
    assert_eq!(
        plan(
            &request(&sale.offer, sale.license),
            &early.view(),
            &identity(&key_b())
        )
        .unwrap_err(),
        Refusal::OfferNotYetValid {
            created: 50,
            next_height: 41
        }
    );
    let at_41 = moved(&early);
    assert_eq!(
        explain_as(&at_41, &early, &key_a()).unwrap_err(),
        Refusal::OfferNotYetValid {
            created: 50,
            next_height: 41
        }
    );
    assert_eq!(
        native(trading::consensus(&early.view(), &complete(&sale, &at_41))),
        NativeError::Candidate(trading_v1::Error::Time)
    );
}

#[test]
fn offer_proofs_that_are_invalid_missing_or_from_another_maker_are_refused_by_both() {
    let sale = sale();
    let raw = unsigned(&sale);
    let view = sale.world.view();
    let good = complete(&sale, &raw);
    // A fill signature that does not verify.
    let bad_fill = trading::mutate(&good, |wire| {
        wire.operation
            .offer_proof
            .as_mut()
            .unwrap()
            .fill_signature
            .ed448[3] ^= 1;
    });
    // Since W19 the one offer check refuses it for every reader (before: explained with a
    // BAD_SIGNATURE warning).
    assert_eq!(
        explain_as(&bad_fill, &sale.world, &key_a()).unwrap_err(),
        Refusal::OfferProofInvalid
    );
    assert_eq!(
        SignedOperation::import(&bad_fill, &view).unwrap_err(),
        Refusal::OfferProofInvalid
    );
    assert_eq!(
        offers::combine(&[&bad_fill], &view).unwrap_err(),
        Refusal::OfferProofInvalid
    );
    assert_eq!(
        native(trading::consensus(&view, &bad_fill)),
        NativeError::Candidate(trading_v1::Error::Signature)
    );
    // The fill is missing: the operation is a part, never complete.
    let no_fill = trading::sign_all(&raw, &[(0, &key_a(), 1), (1, &key_b(), 1)], None);
    let imported = SignedOperation::import(&no_fill, &view).unwrap();
    assert!(!imported.is_complete());
    assert_eq!(imported.missing().len(), 1);
    assert_eq!(imported.missing()[0].slot, Slot::FillSignature);
    assert_eq!(
        native(trading::consensus(&view, &no_fill)),
        NativeError::Candidate(trading_v1::Error::Signature)
    );
    // No offer proof at all: OFFER_PROOF_INVALID, the one code of this failure on every path since
    // W19 (before: MALFORMED here), and consensus refuses the binding.
    let stripped = trading::mutate(&no_fill, |wire| wire.operation.offer_proof = None);
    assert_eq!(
        explain_as(&stripped, &sale.world, &key_a()).unwrap_err(),
        Refusal::OfferProofInvalid
    );
    assert_eq!(
        native(trading::consensus(&view, &stripped)),
        NativeError::Candidate(trading_v1::Error::OfferBinding)
    );
    // The maker's OFFER signature tampered.
    let bad_offer = trading::mutate(&raw, |wire| {
        wire.operation
            .offer_proof
            .as_mut()
            .unwrap()
            .offer
            .signature
            .fndsa[9] ^= 1;
    });
    assert_eq!(
        explain_as(&bad_offer, &sale.world, &key_a()).unwrap_err(),
        Refusal::OfferProofInvalid
    );
    // A proof carrying another maker's offer for the same terms.
    let impostor = key_c();
    assert_ne!(impostor.public().address_id(1).unwrap(), sale.offer.body.maker_wallet);
    let impostor_offer = license_offer(&sale.world, &impostor, sale.license, 1, PRICE);
    let wrong_maker = trading::mutate(&raw, |wire| {
        wire.operation.offer_proof = Some(OfferProof {
            offer: impostor_offer.clone(),
            fill_signature: trading::zero(),
        });
    });
    assert_eq!(
        explain_as(&wrong_maker, &sale.world, &key_a()).unwrap_err(),
        Refusal::OfferProofInvalid
    );
    let signed = trading::sign_all(
        &wrong_maker,
        &[(0, &key_a(), 1), (1, &key_b(), 1)],
        Some((&impostor, &impostor_offer)),
    );
    assert_eq!(
        native(trading::consensus(&view, &signed)),
        NativeError::Candidate(trading_v1::Error::OfferBinding)
    );
}

#[test]
fn missing_and_tampered_counterparty_approvals_are_refused_by_both() {
    let sale = sale();
    let raw = unsigned(&sale);
    let view = sale.world.view();
    let buyer_signer = KeySigner::for_test(key_b()).unwrap();
    let planned = plan(
        &request(&sale.offer, sale.license),
        &view,
        &identity(&key_b()),
    )
    .unwrap();
    let part = trading::sign_plan(planned, &buyer_signer, &view).unwrap();
    // Missing: the buyer's part alone is partial, and consensus refuses it.
    let alone = offers::combine(&[part.bytes()], &view).unwrap();
    assert!(!alone.is_complete());
    let claim_complete = SignedOperation::Complete {
        kind: OperationKind::LicenseDvp,
        id: part.id(),
        bytes: part.bytes().to_vec(),
        validity: *part.validity(),
        reserved: part.reserved().to_vec(),
    };
    let mut outbox = MemoryOutbox::new();
    assert!(outbox.commit(&claim_complete, &view).is_err());
    no_trace(&outbox);
    // With the maker's fill in place (consensus checks the offer before the approvals), the
    // missing seller approval is what consensus refuses.
    let with_fill = trading::mutate(part.bytes(), |wire| {
        wire.operation.offer_proof =
            Some(OfferProof::decode(&trading::fill_proof(&sale.maker, &sale.offer, &raw)).unwrap());
    });
    assert!(
        !SignedOperation::import(&with_fill, &view)
            .unwrap()
            .is_complete()
    );
    assert_eq!(
        native(trading::consensus(&view, &with_fill)),
        NativeError::Authority
    );
    // Tampered: one bit of the buyer's approval flipped.
    let tampered = trading::mutate(part.bytes(), |wire| {
        wire.operation.approvals[1].signature.fndsa[17] ^= 1;
    });
    assert_eq!(
        adopt(&tampered, &view, &identity(&key_a())).unwrap_err(),
        Refusal::CounterpartyApprovalInvalid
    );
    assert_eq!(
        SignedOperation::import(&tampered, &view).unwrap_err(),
        Refusal::CounterpartyApprovalInvalid
    );
    assert_eq!(
        offers::combine(&[&tampered], &view).unwrap_err(),
        Refusal::CounterpartyApprovalInvalid
    );
    // A tampered part refuses the whole combination, even next to a good part that carries a valid
    // signature for the same slot: it is never silently dropped.
    assert_eq!(
        offers::combine(&[part.bytes(), &tampered], &view).unwrap_err(),
        Refusal::CounterpartyApprovalInvalid
    );
    let completed = trading::sign_some(&tampered, &[(0, &key_a(), 1)]);
    let completed = trading::mutate(&completed, |wire| {
        wire.operation.offer_proof =
            Some(OfferProof::decode(&trading::fill_proof(&sale.maker, &sale.offer, &raw)).unwrap());
    });
    assert_eq!(
        native(trading::consensus(&view, &completed)),
        NativeError::Authority
    );
    // A third wallet has nothing to sign in it.
    assert_eq!(
        adopt(part.bytes(), &view, &identity(&key_c())).unwrap_err(),
        Refusal::NotRequiredSigner(Slot::Approval(0))
    );
    // The buyer has nothing LEFT to sign in it.
    assert!(matches!(
        adopt(part.bytes(), &view, &identity(&key_b())).unwrap_err(),
        Refusal::Malformed(_)
    ));
}

fn rotate(world: &mut World, old: &HybridKey, new: &HybridKey) {
    let mut rotation = Rotation {
        network: world.anchor.network,
        genesis: world.anchor.genesis,
        fingerprint: world.anchor.fingerprint,
        authority: address(old, 1),
        current: descriptor(old, 1),
        proposed: descriptor(new, 2),
        created_height: 90,
        expiry_height: 120,
        authorization: trading::zero(),
        possession: trading::zero(),
    };
    rotation.sign(old, new).unwrap();
    let (genesis, fingerprint, height) = (
        world.anchor.genesis,
        world.anchor.fingerprint,
        world.anchor.height,
    );
    world
        .state
        .wallets
        .apply(&rotation, genesis, fingerprint, height)
        .unwrap();
}

#[test]
fn a_rotated_away_seller_or_buyer_key_is_stale_for_both() {
    let sale = sale();
    let raw = unsigned(&sale);
    let view = sale.world.view();
    let planned = plan(
        &request(&sale.offer, sale.license),
        &view,
        &identity(&key_b()),
    )
    .unwrap();
    let approval = trading::approve_high_risk(&review(&planned, &view).unwrap(), &view);
    // The seller rotates its key after the buyer planned.
    let mut seller_rotated = World::new(HEAD);
    seller_rotated.state = sale.world.state.clone();
    rotate(&mut seller_rotated, &key_a(), &key_c());
    assert_eq!(
        explain_as(&raw, &seller_rotated, &key_b()).unwrap_err(),
        Refusal::OfferProofInvalid
    );
    assert_eq!(
        adopt(&raw, &seller_rotated.view(), &identity(&key_a())).unwrap_err(),
        Refusal::StaleAuthority
    );
    assert_eq!(
        native(trading::consensus(
            &seller_rotated.view(),
            &complete(&sale, &raw)
        )),
        NativeError::Authority
    );
    // The buyer rotates: its own plan and its approval are stale.
    let mut buyer_rotated = World::new(HEAD);
    buyer_rotated.state = sale.world.state.clone();
    rotate(&mut buyer_rotated, &key_b(), &key_c());
    assert_eq!(
        review(&planned, &buyer_rotated.view()).unwrap_err(),
        Refusal::StaleAuthority
    );
    let signer = KeySigner::for_test(key_b()).unwrap();
    assert!(
        signer
            .authorize(planned, approval, &buyer_rotated.view())
            .is_err()
    );
    assert_eq!(
        native(trading::consensus(
            &buyer_rotated.view(),
            &complete(&sale, &raw)
        )),
        NativeError::Authority
    );
}

#[test]
fn a_fee_below_the_floor_and_a_part_whose_fee_became_too_low_are_refused_by_both() {
    let sale = sale();
    let raw = unsigned(&sale);
    let view = sale.world.view();
    let size = raw.len() as u64;
    let short = trading::mutate(&raw, |wire| {
        wire.operation.meta.fee.0 -= 1;
        if let Action::LicenseDvp { change, .. } = &mut wire.operation.action {
            change.0 += 1;
        }
    });
    assert_eq!(short.len() as u64, size, "same widths, so the same floor");
    assert_eq!(
        explain_as(&short, &sale.world, &key_a()).unwrap_err(),
        Refusal::FeeBelowMinimum {
            fee: size - 1,
            minimum: size
        }
    );
    // A buyer part signed elsewhere with that short fee: never co-signed, never queued, never
    // combined.
    let part = trading::sign_some(&short, &[(1, &key_b(), 1)]);
    assert!(matches!(
        adopt(&part, &view, &identity(&key_a())).unwrap_err(),
        Refusal::FeeBelowMinimum { .. }
    ));
    assert!(matches!(
        SignedOperation::import(&part, &view).unwrap_err(),
        Refusal::FeeBelowMinimum { .. }
    ));
    assert!(matches!(
        offers::combine(&[&part], &view).unwrap_err(),
        Refusal::FeeBelowMinimum { .. }
    ));
    assert_eq!(
        native(trading::consensus(&view, &complete(&sale, &short))),
        NativeError::Fee
    );
    // The fee the planner chose is exactly the floor of the final length.
    let complete_raw = complete(&sale, &raw);
    assert_eq!(complete_raw.len(), raw.len());
    let fee = NativeOperation::decode(&raw).unwrap().operation.meta.fee.0;
    assert_eq!(fee, (complete_raw.len() as u64).max(240));
}

#[test]
fn unsorted_or_unbalanced_inputs_are_refused_by_both() {
    let (world, license) = world_at(HEAD, address(&key_a(), 1), false);
    let maker = trading::maker();
    // A price only both coins can pay: two inputs.
    let offer = license_offer(&world, &maker, license, 1, 6_000_000);
    let sale = Sale {
        world,
        license,
        maker,
        offer,
    };
    let raw = unsigned(&sale);
    let wire = NativeOperation::decode(&raw).unwrap();
    assert_eq!(wire.inputs.len(), 2);
    let view = sale.world.view();
    // Swap the two input identifiers inside the body: the bytes are no longer canonical.
    let (first, second) = (wire.operation.meta.inputs[0], wire.operation.meta.inputs[1]);
    let mut swapped = raw.clone();
    let at = |needle: &[u8; 32]| {
        swapped
            .windows(32)
            .position(|window| window == needle)
            .unwrap()
    };
    let (i, j) = (at(&first), at(&second));
    swapped[i..i + 32].copy_from_slice(&second);
    swapped[j..j + 32].copy_from_slice(&first);
    assert!(NativeOperation::decode(&swapped).is_err());
    assert_eq!(
        explain_as(&swapped, &sale.world, &key_a()).unwrap_err(),
        Refusal::UnknownOperation
    );
    assert!(matches!(
        native(trading::consensus(&view, &swapped)),
        NativeError::Codec | NativeError::Candidate(_)
    ));
    // Inputs that do not equal price + change + fee.
    let leaky = set_action(&raw, |action| {
        if let Action::LicenseDvp { change, .. } = action {
            change.0 -= 1;
        }
    });
    assert_eq!(
        explain_as(&leaky, &sale.world, &key_a()).unwrap_err(),
        Refusal::Conservation
    );
    assert_eq!(
        native(trading::consensus(&view, &complete(&sale, &leaky))),
        NativeError::Conservation
    );
    // An input that is not the buyer's.
    let mut foreign = World::new(HEAD);
    foreign.state = sale.world.state.clone();
    foreign.coin(address(&key_c(), 1), 9_000_000, 1, false, 0xb1, 0);
    assert!(matches!(
        explain_as(&raw, &foreign, &key_a()).unwrap_err(),
        Refusal::InvalidRequest(_)
    ));
    assert_eq!(
        native(trading::consensus(&foreign.view(), &complete(&sale, &raw))),
        NativeError::Authority
    );
}

#[test]
fn immature_coinbase_and_too_new_buyer_coins_are_refused_by_both() {
    let sale = sale();
    let raw = unsigned(&sale);
    for (created, coinbase) in [(50, true), (HEAD + 1, false)] {
        let mut young = World::new(HEAD);
        young.state = sale.world.state.clone();
        young.coin(address(&key_b(), 1), 5_000_000, created, coinbase, 0xb1, 0);
        assert_eq!(
            explain_as(&raw, &young, &key_a()).unwrap_err(),
            Refusal::ImmatureInput
        );
        assert_eq!(
            native(trading::consensus(&young.view(), &complete(&sale, &raw))),
            NativeError::Immature
        );
    }
    // The planner never selects such a coin.
    let mut only_young = World::new(HEAD);
    only_young.state = sale.world.state.clone();
    only_young.state.coins.clear();
    only_young.coin(address(&key_b(), 1), 5_000_000, 50, true, 0xb1, 0);
    assert_eq!(
        plan(
            &request(&sale.offer, sale.license),
            &only_young.view(),
            &identity(&key_b())
        )
        .unwrap_err(),
        Refusal::NothingSpendable
    );
}

#[test]
fn a_foreign_network_genesis_or_fingerprint_is_refused_by_both() {
    let sale = sale();
    let raw = unsigned(&sale);
    for (field, edit) in [
        (
            ContextField::Network,
            Box::new(|wire: &mut NativeOperation| wire.operation.meta.context.network ^= 1)
                as Box<dyn Fn(&mut NativeOperation)>,
        ),
        (
            ContextField::Genesis,
            Box::new(|wire: &mut NativeOperation| wire.operation.meta.context.genesis = [0x61; 32]),
        ),
        (
            ContextField::Fingerprint,
            Box::new(|wire: &mut NativeOperation| {
                wire.operation.meta.context.fingerprint = [0x62; 32]
            }),
        ),
    ] {
        let foreign = trading::mutate(&raw, |wire| edit(wire));
        assert_eq!(
            explain_as(&foreign, &sale.world, &key_a()).unwrap_err(),
            Refusal::WrongContext(field)
        );
        assert_eq!(
            native(trading::consensus(
                &sale.world.view(),
                &complete(&sale, &foreign)
            )),
            NativeError::Context
        );
    }
    // A chain of another Genesis refuses the original bytes.
    let mut other = World::new(HEAD);
    other.state = sale.world.state.clone();
    other.anchor.genesis = [0x61; 32];
    assert_eq!(
        explain_as(&raw, &other, &key_a()).unwrap_err(),
        Refusal::WrongContext(ContextField::Genesis)
    );
    assert!(trading::consensus(&other.view(), &complete(&sale, &raw)).is_err());
    // An offer of another chain is refused at import.
    let foreign_offer = trading::offer(
        &sale.maker,
        trading_v1::Context {
            genesis: [0x61; 32],
            ..trading::context_of(&sale.world.anchor)
        },
        trading::license_terms(sale.license, 1, PRICE),
        50,
        200,
        0,
        0x31,
    );
    assert_eq!(
        offers::import_offer(&trading::offer_bytes(&foreign_offer), &sale.world.view())
            .unwrap_err(),
        Refusal::WrongContext(ContextField::Genesis)
    );
}

#[test]
fn zero_trade_commitments_are_refused_by_both() {
    let sale = sale();
    let raw = unsigned(&sale);
    assert!(matches!(
        plan(
            &OperationRequest::LicenseDvp(LicenseDvpRequest::new(
                Blob::new(trading::offer_bytes(&sale.offer)),
                sale.license
            )),
            &sale.world.view(),
            &identity(&key_b())
        )
        .unwrap_err(),
        Refusal::InvalidRequest(_)
    ));
    let zero_trade = trading::mutate(&raw, |wire| wire.operation.meta.trade = [0; 32]);
    assert!(matches!(
        explain_as(&zero_trade, &sale.world, &key_a()).unwrap_err(),
        Refusal::InvalidRequest(_)
    ));
    assert_eq!(
        native(trading::consensus(
            &sale.world.view(),
            &complete(&sale, &zero_trade)
        )),
        NativeError::LicenseLocked,
        "the License book refuses a transfer without its commitments"
    );
}

#[test]
fn planner_refusals_are_typed_and_leave_no_trace() {
    let sale = sale();
    let view = sale.world.view();
    let buyer = identity(&key_b());
    let outbox = MemoryOutbox::new();
    // Not an offer, a fiat offer, an offer for another License, a License that does not exist.
    assert!(matches!(
        plan(
            &OperationRequest::LicenseDvp(
                LicenseDvpRequest::new(Blob::new(vec![1, 2, 3]), sale.license)
                    .with_commitments(TRADE, CONTRACT)
            ),
            &view,
            &buyer
        )
        .unwrap_err(),
        Refusal::Malformed(_)
    ));
    let fiat = trading::offer(
        &sale.maker,
        trading::context_of(&sale.world.anchor),
        trading::fiat_terms(5, [1; 32]),
        50,
        200,
        0,
        0x32,
    );
    assert!(matches!(
        plan(&request(&fiat, sale.license), &view, &buyer).unwrap_err(),
        Refusal::InvalidRequest(_)
    ));
    assert!(matches!(
        plan(&request(&sale.offer, [0xee; 32]), &view, &buyer).unwrap_err(),
        Refusal::InvalidRequest(_)
    ));
    let missing = license_offer(&sale.world, &sale.maker, [0xee; 32], 1, PRICE);
    assert!(matches!(
        plan(&request(&missing, [0xee; 32]), &view, &buyer).unwrap_err(),
        Refusal::InvalidRequest(_)
    ));
    // The seller cannot buy its own License (same address).
    assert!(matches!(
        plan(
            &request(&sale.offer, sale.license),
            &view,
            &identity(&key_a())
        )
        .unwrap_err(),
        Refusal::InvalidRequest(_)
    ));
    // Funds: nothing at all, too little, more coins than one operation may carry.
    let (mut poor, _) = world_at(HEAD, address(&key_a(), 1), false);
    poor.state.coins.clear();
    assert_eq!(
        plan(&request(&sale.offer, sale.license), &poor.view(), &buyer).unwrap_err(),
        Refusal::NothingSpendable
    );
    poor.coin(address(&key_b(), 1), 1_000, 1, false, 0xb9, 0);
    assert!(matches!(
        plan(&request(&sale.offer, sale.license), &poor.view(), &buyer).unwrap_err(),
        Refusal::InsufficientFunds {
            available: 1_000,
            ..
        }
    ));
    let (mut dust, _) = world_at(HEAD, address(&key_a(), 1), false);
    dust.state.coins.clear();
    // Sixteen coins (the input limit) do not reach the price; twenty would.
    for index in 0..20 {
        dust.coin(address(&key_b(), 1), 120_000, 1, false, 0xc0, index);
    }
    assert_eq!(
        plan(&request(&sale.offer, sale.license), &dust.view(), &buyer).unwrap_err(),
        Refusal::TooManyInputs { limit: 16 }
    );
    // Reserved coins, the reserved License and the reserved offer.
    let mut held = World::new(HEAD);
    held.state = sale.world.state.clone();
    held.reserved = BTreeSet::from([resource_key("license", &sale.license)]);
    assert_eq!(
        plan(&request(&sale.offer, sale.license), &held.view(), &buyer).unwrap_err(),
        Refusal::ReservedInput
    );
    held.reserved = BTreeSet::from([resource_key("offer", &sale.offer.body.id().unwrap())]);
    assert_eq!(
        plan(&request(&sale.offer, sale.license), &held.view(), &buyer).unwrap_err(),
        Refusal::ReservedInput
    );
    // The Treasury identity buys only through the Treasury profile.
    let mut treasury_world = World::new(HEAD);
    treasury_world.state = sale.world.state.clone();
    trading::install_award(&mut treasury_world.state, &key_c(), 1_200_000, 0xd1);
    treasury_world.coin(address(&key_c(), 1), 5_000_000, 1, false, 0xc1, 0);
    assert_eq!(
        plan(
            &request(&sale.offer, sale.license),
            &treasury_world.view(),
            &identity(&key_c())
        )
        .unwrap_err(),
        Refusal::TreasuryProfileRequired
    );
    // A cancellation of a signed License sale does not exist.
    assert_eq!(
        plan(
            &OperationRequest::Cancel(CancelRequest::new(CancelTarget::LicenseDvp)),
            &view,
            &buyer
        )
        .unwrap_err(),
        Refusal::CancelNotAvailable(CancelTarget::LicenseDvp)
    );
    no_trace(&outbox);
}

/// A fiat world: A (seller) and B (buyer) registered and funded, a fiat offer, and the lock applied
/// at block HEAD + 1 when `applied`.
fn fiat_world() -> (World, HybridKey, SignedOffer) {
    let mut world = World::new(HEAD);
    for key in [key_a(), key_b()] {
        world.state.wallets.register(&descriptor(&key, 1)).unwrap();
    }
    world.coin(address(&key_a(), 1), 5_000_000, 1, false, 0xa1, 0);
    world.coin(address(&key_b(), 1), 1_000_000, 1, false, 0xb1, 0);
    let maker = trading::maker();
    let offer = trading::offer(
        &maker,
        trading::context_of(&world.anchor),
        trading::fiat_terms(2_000_000, [0x77; 32]),
        50,
        200,
        0,
        0x41,
    );
    (world, maker, offer)
}

fn fiat_request(offer: &SignedOffer, amount: u64, terms: Hash) -> OperationRequest {
    OperationRequest::FiatLock(
        FiatLockRequest::new(
            Blob::new(trading::offer_bytes(offer)),
            address(&key_b(), 1),
            amount,
            terms,
        )
        .with_commitments(TRADE, CONTRACT),
    )
}

#[test]
fn fiat_lock_and_release_refusals_agree_with_consensus() {
    let (world, maker, offer) = fiat_world();
    let seller = identity(&key_a());
    let view = world.view();
    // The request must restate the offer's amount and payment terms.
    assert!(matches!(
        plan(&fiat_request(&offer, 2_000_001, [0x77; 32]), &view, &seller).unwrap_err(),
        Refusal::InvalidRequest(_)
    ));
    assert!(matches!(
        plan(&fiat_request(&offer, 2_000_000, [0x78; 32]), &view, &seller).unwrap_err(),
        Refusal::InvalidRequest(_)
    ));
    // The buyer cannot plan the lock (it does not fund it; slot 0 is the seller).
    let raw = plan(&fiat_request(&offer, 2_000_000, [0x77; 32]), &view, &seller)
        .unwrap()
        .objects()[0]
        .bytes
        .clone();
    // Seller == buyer, refused by both.
    let to_self = trading::mutate(&raw, |wire| {
        if let Action::FiatLock { buyer, .. } = &mut wire.operation.action {
            *buyer = address(&key_a(), 1);
        }
        wire.operation.approvals[1].descriptor = descriptor(&key_a(), 1);
    });
    assert!(matches!(
        explain_as(&to_self, &world, &key_a()).unwrap_err(),
        Refusal::InvalidRequest(_)
    ));
    let signed = trading::sign_all(
        &to_self,
        &[(0, &key_a(), 1), (1, &key_a(), 1)],
        Some((&maker, &offer)),
    );
    assert_eq!(
        native(trading::consensus(&view, &signed)),
        NativeError::Bounds
    );
    // The lock applied at HEAD + 1.
    let lock = trading::sign_all(
        &raw,
        &[(0, &key_a(), 1), (1, &key_b(), 1)],
        Some((&maker, &offer)),
    );
    let state = trading::consensus(&view, &lock).unwrap().into_state();
    let lock_id = NativeOperation::decode(&lock)
        .unwrap()
        .operation
        .output_id(0)
        .unwrap();
    let mut next = World::new(HEAD + 1);
    next.state = state;
    // Attach the earlier anchor from this unit test's own synthetic execution context;
    // this is not canonical-store or physical evidence. Signed bytes remain unchanged.
    let mut history = mutiny_consensus_v8::evidence_history_v2::History::default();
    history.insert_anchor(world.anchor.height, world.anchor.block).unwrap();
    let historical_view = next.view().with_history(&history);
    // The same lock again: a replay, refused by both.
    assert_eq!(
        explain(&lock, &historical_view, &identity(&key_a())).unwrap_err(),
        Refusal::Replay
    );
    assert_eq!(
        native(trading::consensus(&next.view(), &lock)),
        NativeError::Duplicate
    );
    // The release: planned by the buyer only; an unknown lock is refused.
    let buyer = identity(&key_b());
    assert_eq!(
        plan(
            &OperationRequest::FiatRelease(FiatReleaseRequest::new(lock_id)),
            &next.view(),
            &identity(&key_a())
        )
        .unwrap_err(),
        Refusal::NotRequiredSigner(Slot::Approval(0))
    );
    assert!(matches!(
        plan(
            &OperationRequest::FiatRelease(FiatReleaseRequest::new([0x99; 32])),
            &next.view(),
            &buyer
        )
        .unwrap_err(),
        Refusal::LockNotFound
    ));
    let release = plan(
        &OperationRequest::FiatRelease(FiatReleaseRequest::new(lock_id)),
        &next.view(),
        &buyer,
    )
    .unwrap()
    .objects()[0]
        .bytes
        .clone();
    let full = |raw: &[u8]| trading::sign_all(raw, &[(0, &key_b(), 1), (1, &key_a(), 1)], None);
    trading::consensus(&next.view(), &full(&release)).expect("control: the release is valid");
    // Wrong payment terms, wrong amount, wrong parties: refused by both.
    let wrong_terms = set_action(&release, |action| {
        if let Action::FiatRelease { payment_terms, .. } = action {
            *payment_terms = [0x78; 32];
        }
    });
    let wrong_amount = trading::mutate(&release, |wire| {
        if let Action::FiatRelease { amount, change, .. } = &mut wire.operation.action {
            amount.0 -= 1;
            change.0 += 0;
        }
    });
    let wrong_buyer = trading::mutate(&release, |wire| {
        if let Action::FiatRelease { buyer, .. } = &mut wire.operation.action {
            *buyer = address(&key_c(), 1);
        }
    });
    for (name, bytes) in [
        ("terms", wrong_terms),
        ("amount", wrong_amount),
        ("buyer", wrong_buyer),
    ] {
        assert!(
            explain_as(&bytes, &next, &key_a()).is_err(),
            "{name}: the wallet refuses"
        );
        let signed = trading::sign_all(&bytes, &[(0, &key_b(), 1), (1, &key_a(), 1)], None);
        assert!(
            trading::consensus(&next.view(), &signed).is_err(),
            "{name}: consensus refuses"
        );
    }
    // An offer proof on a release: refused by both.
    let with_proof = trading::mutate(&release, |wire| {
        wire.operation.offer_proof = Some(OfferProof {
            offer: offer.clone(),
            fill_signature: trading::zero(),
        });
    });
    assert_eq!(
        explain_as(&with_proof, &next, &key_a()).unwrap_err(),
        Refusal::OfferProofInvalid
    );
    // The lock cannot be released twice.
    let released = trading::consensus(&next.view(), &full(&release))
        .unwrap()
        .into_state();
    let mut after = World::new(HEAD + 2);
    after.state = released;
    assert!(explain_as(&release, &after, &key_a()).is_err());
    assert!(trading::consensus(&after.view(), &full(&release)).is_err());
    let _: Option<Prepared> = None;
}

#[test]
fn the_shared_pipeline_refusals_apply_to_a_license_sale_and_leave_no_trace() {
    use std::time::{Duration, Instant};
    let sale = sale();
    let view = sale.world.view();
    let planned = plan(
        &request(&sale.offer, sale.license),
        &view,
        &identity(&key_b()),
    )
    .unwrap();
    let reviewed = review(&planned, &view).unwrap();
    let outbox = MemoryOutbox::new();
    // The production gate is closed while production qualification is incomplete.
    if !mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED {
        assert_eq!(SigningGate::production().unwrap_err(), Refusal::GateClosed);
    }
    // Locked.
    let locked = KeySigner::for_test(key_b()).unwrap();
    let approval = trading::approve_high_risk(&reviewed, &view);
    locked.lock();
    assert_eq!(
        locked
            .authorize(planned.clone(), approval, &view)
            .unwrap_err(),
        Refusal::Locked
    );
    // An approval that is too old.
    let signer = KeySigner::for_test(key_b()).unwrap();
    let old = Approval::for_review_for_test(
        &reviewed,
        Instant::now()
            .checked_sub(MAX_APPROVAL_AGE + Duration::from_secs(5))
            .unwrap(),
    );
    assert_eq!(
        signer.authorize(planned.clone(), old, &view).unwrap_err(),
        Refusal::Expired(ExpiryKind::Approval)
    );
    // The head moved: the single-block sale needs a new review.
    let approval = trading::approve_high_risk(&reviewed, &view);
    let next = sale.world.advanced();
    assert!(matches!(
        signer
            .authorize(planned.clone(), approval, &next.view())
            .unwrap_err(),
        Refusal::StaleHead {
            reviewed: 100,
            current: 101
        }
    ));
    // An approval given for another plan (another signed trade commitment).
    let other = plan(
        &OperationRequest::LicenseDvp(
            LicenseDvpRequest::new(Blob::new(trading::offer_bytes(&sale.offer)), sale.license)
                .with_commitments([0x5e; 32], CONTRACT),
        ),
        &view,
        &identity(&key_b()),
    )
    .unwrap();
    let approval_for_other = trading::approve_high_risk(&review(&other, &view).unwrap(), &view);
    assert_eq!(
        signer
            .authorize(planned.clone(), approval_for_other, &view)
            .unwrap_err(),
        Refusal::PlanChanged
    );
    // A withdrawn approval.
    let mut gate = ReviewGate::new();
    gate.present(&reviewed, &view);
    for index in reviewed.destinations_needing_check() {
        gate.confirm_destination(index, &reviewed.destination_check_text(index))
            .unwrap();
    }
    for ack in reviewed.acknowledgements() {
        gate.acknowledge(*ack).unwrap();
    }
    gate.confirm_phrase(&reviewed.confirmation_phrase().unwrap())
        .unwrap();
    let withdrawn = gate.approve(&view).unwrap();
    gate.clear();
    assert_eq!(
        signer
            .authorize(planned.clone(), withdrawn, &view)
            .unwrap_err(),
        Refusal::ApprovalRevoked
    );
    // Without the typed confirmation phrase no approval exists at all (high risk).
    let mut no_phrase = ReviewGate::new();
    no_phrase.present(&reviewed, &view);
    for index in reviewed.destinations_needing_check() {
        no_phrase
            .confirm_destination(index, &reviewed.destination_check_text(index))
            .unwrap();
    }
    for ack in reviewed.acknowledgements() {
        no_phrase.acknowledge(*ack).unwrap();
    }
    assert_eq!(
        no_phrase.approve(&view).unwrap_err(),
        Refusal::ConfirmationPhraseMissing
    );
    // The wrong wallet: the seller cannot sign the buyer's plan.
    let approval = trading::approve_high_risk(&reviewed, &view);
    assert_eq!(
        KeySigner::for_test(key_a())
            .unwrap()
            .authorize(planned.clone(), approval, &view)
            .unwrap_err(),
        Refusal::NotRequiredSigner(Slot::Approval(0))
    );
    // A TEST-VALUE signer refuses a production-class chain.
    let mut production = World::new(HEAD);
    production.state = sale.world.state.clone();
    production.state.dividends = mutiny_consensus_v8::dividend_state_v1::DividendState::genesis(
        mutiny_consensus_v8::treasury_v1::Treasury::new(
            mutiny_consensus_v8::treasury_v1::Class::Production,
            descriptor(&key_c(), 1),
        )
        .unwrap(),
    );
    let on_production = plan(
        &request(&sale.offer, sale.license),
        &production.view(),
        &identity(&key_b()),
    )
    .unwrap();
    let approval = trading::approve_high_risk(
        &review(&on_production, &production.view()).unwrap(),
        &production.view(),
    );
    assert_eq!(
        signer
            .authorize(on_production, approval, &production.view())
            .unwrap_err(),
        Refusal::ChainClassMismatch {
            gate: ChainClass::TestValue,
            chain: ChainClass::Production
        }
    );
    no_trace(&outbox);
    // And the plan itself is unchanged by every refusal.
    assert_eq!(
        review(&planned, &view).unwrap().binding(),
        reviewed.binding()
    );
}

#[test]
fn a_treasury_purchase_below_the_dividend_reserve_is_refused_by_both() {
    let (mut world, license) = world_at(HEAD, address(&key_a(), 1), false);
    // C is the TEST-VALUE Treasury with 1,200,000 atoms; the first award reserves 600,000.
    trading::install_award(&mut world.state, &key_c(), 1_200_000, 0xd1);
    assert_eq!(world.state.dividends.reserved(), 600_000);
    let backed_parent_root = world.state.root().expect("valid backed awarded parent");
    assert_eq!(world.view().state_root(), backed_parent_root,
        "reserve refusal must not be masked by the synthetic fallback for an invalid parent");
    let maker = trading::maker();
    let offer = license_offer(&world, &maker, license, 1, 700_000);
    let treasury = identity(&key_c()).with_treasury_roles_for_test(TreasuryRoles {
        authority: true,
        destination_of: None,
    });
    let refusal = plan(&request(&offer, license), &world.view(), &treasury).unwrap_err();
    assert!(
        matches!(refusal, Refusal::ReserveBackingViolation { reserved: 600_000, backing_after } if backing_after < 600_000),
        "{refusal:?}"
    );
    // The same purchase built by hand: consensus refuses the resulting state (reserve unbacked).
    let ordinary = trading::offer(
        &maker,
        trading::context_of(&world.anchor),
        trading::license_terms(license, 1, 700_000),
        50,
        200,
        0,
        0x33,
    );
    let mut no_award = World::new(HEAD);
    no_award.state = world.state.clone();
    no_award.state.dividends = Default::default();
    let built = plan(
        &request(&ordinary, license),
        &no_award.view(),
        &identity(&key_c()),
    )
    .unwrap()
    .objects()[0]
        .bytes
        .clone();
    let signed = trading::sign_all(
        &built,
        &[(0, &key_a(), 1), (1, &key_c(), 1)],
        Some((&maker, &ordinary)),
    );
    // The control: without the outstanding award the same sale is valid.
    trading::consensus(&no_award.view(), &signed).expect("valid without a reserve to back");
    // Commit the actual awarded entitlement facts to isolate reserve backing, rather than
    // failing earlier on a stale entitlement precondition. Re-sign this distinct candidate.
    let awarded = trading::mutate(&built, |wire| {
        wire.operation.meta.envelope.preconditions = vec![
            mutiny_consensus_v8::op_envelope_v1::entitlement_facts(&world.state, license),
            mutiny_consensus_v8::op_envelope_v1::assignment_facts(&world.state, license).unwrap(),
        ];
        let extra = 50_000 - wire.operation.meta.fee.0;
        wire.operation.meta.fee = Strikes(50_000);
        if let Action::LicenseDvp { change, .. } = &mut wire.operation.action { change.0 -= extra; }
    });
    let awarded_signed = trading::sign_all(&awarded,
        &[(0, &key_a(), 1), (1, &key_c(), 1)], Some((&maker, &ordinary)));
    assert!(awarded_signed.len() <= 50_000, "complete signed-size fee floor");
    // With it, the post-sale state fails the reserve-backing invariant of the state root.
    assert_eq!(
        native(trading::consensus(&world.view(), &awarded_signed)),
        NativeError::Record,
        "consensus refuses a sale that leaves the dividend reserve unbacked"
    );
}

#[test]
fn a_complete_sale_is_verified_by_consensus_against_the_authenticated_state_root() {
    let sale = sale();
    let complete_bytes = complete(&sale, &unsigned(&sale));
    let view = sale.world.view();
    assert!(SignedOperation::import(&complete_bytes, &view).is_ok());
    // The same state under a head whose state root it does not hash to: every rule the wallet
    // mirrors still holds, but consensus code (`prepare_batch`) refuses the parent, so the wallet
    // does not accept the complete operation either.
    let wrong_root = HeadInfo::new(
        sale.world.anchor.clone(),
        sale.world.timestamp,
        synthetic::T0,
        [0x66; 32],
    )
    .unwrap();
    let reserved = BTreeSet::new();
    let unauthenticated = ChainView::new(wrong_root, &sale.world.state, &reserved);
    assert!(explain(&complete_bytes, &unauthenticated, &identity(&key_a())).is_ok());
    assert!(matches!(
        SignedOperation::import(&complete_bytes, &unauthenticated).unwrap_err(),
        Refusal::VerificationFailed(_)
    ));
    assert!(matches!(
        offers::combine(&[&complete_bytes], &unauthenticated).unwrap_err(),
        Refusal::VerificationFailed(_)
    ));
    assert_eq!(
        trading::consensus(&unauthenticated, &complete_bytes).unwrap_err(),
        NativeError::Context
    );
}

/// Order W21: a License the Treasury owns is SOLD only through the Treasury profile with the
/// declared Authority role. The buyer (an ordinary wallet) plans as usual; the Treasury's key with an
/// ordinary identity cannot adopt and review the sale (TREASURY_PROFILE_REQUIRED), nor with a
/// Treasury identity declared without the Authority role (TREASURY_ROLE_NOT_DECLARED); with the
/// role the whole sale completes and consensus accepts it.
#[test]
fn selling_a_treasury_owned_license_needs_the_treasury_profile() {
    let (mut world, license) = world_at(HEAD, address(&key_c(), 1), false);
    trading::install_award(&mut world.state, &key_c(), 1_200_000, 0xd1);
    let view = world.view();
    let maker = key_c();
    let offer = license_offer(&world, &maker, license, 1, PRICE);
    let buyer = KeySigner::for_test(key_b()).unwrap();
    let planned = plan(&request(&offer, license), &view, buyer.identity()).unwrap();
    let buyer_part = trading::sign_plan(planned, &buyer, &view).unwrap();
    let seller_review = |seller: &SignerIdentity| {
        adopt(buyer_part.bytes(), &view, seller).and_then(|adopted| review(&adopted, &view))
    };
    assert_eq!(
        seller_review(&identity(&key_c())).unwrap_err(),
        Refusal::TreasuryProfileRequired
    );
    let trading_only = identity(&key_c()).with_treasury_roles_for_test(TreasuryRoles {
        authority: false,
        destination_of: Some([0x44; 32]),
    });
    assert_eq!(
        seller_review(&trading_only).unwrap_err(),
        Refusal::TreasuryRoleNotDeclared(TreasuryRole::Authority)
    );
    let profiled = identity(&key_c()).with_treasury_roles_for_test(TreasuryRoles {
        authority: true,
        destination_of: None,
    });
    assert!(seller_review(&profiled).is_ok());
    let seller = KeySigner::with_identity(
        key_c(),
        profiled,
        SigningGate::test_value().unwrap(),
        DEFAULT_IDLE_LIMIT,
    )
    .unwrap();
    let (_, _, _, complete, _) = trading::sale(
        &view,
        &maker,
        &offer,
        &request(&offer, license),
        &buyer,
        &seller,
    );
    assert!(complete.is_complete());
    trading::consensus(&view, complete.bytes()).expect("consensus accepts the Treasury's sale");
}

/// The native signed inclusion window is retained, capped by the maker's signed offer, and
/// rejects invalid requests before signing. No retired single-height restriction remains.
#[test]
fn a_license_sale_request_retains_its_native_signed_validity_window() {
    let sale = sale();
    let view = sale.world.view();
    let buyer = identity(&key_b());
    for blocks in [0, 10_081, u64::MAX] {
        let mut asked =
            LicenseDvpRequest::new(Blob::new(trading::offer_bytes(&sale.offer)), sale.license)
                .with_commitments(TRADE, CONTRACT);
        asked.validity_blocks = Some(blocks);
        assert_eq!(
            plan(&OperationRequest::LicenseDvp(asked), &view, &buyer).unwrap_err(),
            Refusal::InvalidValidity,
            "{blocks}"
        );
    }
    for blocks in [1, DEFAULT_VALIDITY_BLOCKS, 10_080] {
        let mut asked =
            LicenseDvpRequest::new(Blob::new(trading::offer_bytes(&sale.offer)), sale.license)
                .with_commitments(TRADE, CONTRACT);
        asked.validity_blocks = Some(blocks);
        let planned = plan(&OperationRequest::LicenseDvp(asked), &view, &buyer).unwrap();
        let wire = NativeOperation::decode(&planned.objects()[0].bytes).unwrap();
        let expected_last = (HEAD + 1 + blocks).min(sale.offer.body.expiry);
        assert_eq!(wire.operation.meta.envelope.first_height, HEAD + 1);
        assert_eq!(wire.operation.meta.envelope.last_height, expected_last);
        assert_eq!(wire.operation.meta.envelope.reference_height, HEAD);
        assert_eq!(planned.validity().created, HEAD + 1);
        assert_eq!(planned.validity().expiry, expected_last);
        assert_eq!(planned.validity().valid_only_at, None);
        let complete = complete(&sale, &planned.objects()[0].bytes);
        trading::consensus(&view, &complete).expect("native window sale accepted at first height");
    }
    // Unset retains the default native bounds in the carrier, rather than ignoring them.
    let request = request(&sale.offer, sale.license);
    let OperationRequest::LicenseDvp(unset) = &request else {
        unreachable!()
    };
    assert_eq!(unset.validity_blocks, None);
    let planned = plan(&request, &view, &buyer).unwrap();
    assert_eq!(planned.validity().created, HEAD + 1);
    assert_eq!(planned.validity().expiry, HEAD + 2);
    assert_eq!(planned.validity().valid_only_at, None);
}
