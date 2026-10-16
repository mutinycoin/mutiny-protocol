//! License DvP end to end on a REAL consensus chain (NATIVE, TEST-VALUE): the buyer plans, reviews
//! and signs its slot; the part travels as a public container (Q12); the maker's fill proof (played
//! by the test through the consensus API, never by the wallet) is attached over the exact body; the
//! seller explains the buyer's part, adopts it and co-signs ONLY its slot; the parts are combined and
//! verified through consensus code; a block built by the production assembler, certified with real
//! hybrid votes and installed by the canonical store transfers the License; the outboxes reconcile
//! from verified state. Also: exact signed inclusion bounds, canonical historical references,
//! refusal before/after the window, and the dividend dependency (a seller claim in the
//! same block as the sale fails `StaleOwner`; the buyer continues the same award account).
#[path = "support/trading_5b.rs"]
mod trading;
#[path = "support/trading_rig_5b.rs"]
mod trading_rig;

use mutiny_consensus_v8::{
    Hash,
    dividend_claim_v1::{ClaimBody, SignedClaim, admit},
    dividends_v1::AWARD_PERIOD_EPOCHS as P,
    trading_v1::{self, NativeOperation, NativeRecord, OfferProof, SignedOffer},
    transactions::OutPoint,
};
use mutiny_crypto_v2::HybridKey;
use mutiny_wallet_core_v8::*;
use std::collections::BTreeSet;
use trading_rig::chain::{TradeChain, address_of, buyer_key, license_id, seller_key};

const PRICE: u64 = 2_000_000;
const TRADE: [u8; 32] = [0x71; 32];
const CONTRACT: [u8; 32] = [0x72; 32];

fn identity(key: &HybridKey) -> SignerIdentity {
    SignerIdentity::from_public(key.public(), 1, None).unwrap()
}

fn request(offer: &SignedOffer, license: Hash) -> OperationRequest {
    OperationRequest::LicenseDvp(
        LicenseDvpRequest::new(Blob::new(trading::offer_bytes(offer)), license)
            .with_commitments(TRADE, CONTRACT),
    )
}

fn license_offer(
    chain: &TradeChain,
    maker: &HybridKey,
    license: Hash,
    generation: u64,
) -> SignedOffer {
    trading::offer(
        maker,
        trading::context_of(chain.genesis()),
        trading::license_terms(license, generation, PRICE),
        1,
        P + 50,
        0,
        0x31,
    )
}

/// The whole wallet flow at the chain's current head: the buyer plans and signs, the maker fills,
/// the seller explains, adopts and signs, the parts are combined. Returns (buyer part, part with the
/// fill, seller part, complete operation, the buyer's review digest).
fn sale(
    chain: &TradeChain,
    maker: &HybridKey,
    offer: &SignedOffer,
    license: Hash,
) -> (
    SignedOperation,
    Vec<u8>,
    SignedOperation,
    SignedOperation,
    ReviewDigest,
) {
    trading::sale(
        &chain.view(&BTreeSet::new()),
        maker,
        offer,
        &request(offer, license),
        &KeySigner::for_test(buyer_key()).unwrap(),
        &KeySigner::for_test(seller_key()).unwrap(),
    )
}

#[test]
fn buyer_plans_seller_cosigns_after_explain_maker_fills_and_a_real_block_transfers_the_license() {
    let seller_wallet = seller_key();
    let buyer_wallet = buyer_key();
    let seller = address_of(&seller_wallet);
    let buyer = address_of(&buyer_wallet);
    let mut chain = TradeChain::new(
        "dvp-e2e",
        1_200_000,
        &[(0xb1, buyer, 5_000_000), (0xb2, buyer, 3_000_000)],
        &[],
    );
    let license = license_id(2);
    let maker = trading::maker();
    let offer = license_offer(&chain, &maker, license, 1);
    let offer_id = offer.body.id().unwrap();
    let none = BTreeSet::new();
    let buyer_signer = KeySigner::for_test(buyer_key()).unwrap();
    let seller_signer = KeySigner::for_test(seller_key()).unwrap();

    // ---- the buyer plans, reviews and signs its own slot
    let (buyer_part, digest) = {
        let view = chain.view(&none);
        assert_eq!(view.class(), ChainClass::TestValue);
        let planned = plan(&request(&offer, license), &view, &identity(&buyer_wallet)).unwrap();
        assert_eq!(planned.kind(), OperationKind::LicenseDvp);
        // Native finite inclusion bounds retain the verified canonical reference.
        assert_eq!(
            *planned.validity(),
            Validity {
                created: 1,
                expiry: 2,
                valid_only_at: None,
                bound_to_parent: false
            }
        );
        // The plan reserves the buyer's coin(s), the License and the offer.
        assert!(
            planned
                .inputs()
                .contains(&resource_key("license", &license))
        );
        assert!(planned.inputs().contains(&resource_key("offer", &offer_id)));
        let reviewed = review(&planned, &view).unwrap();
        assert!(reviewed.title().starts_with("Buy License "));
        assert!(reviewed.requires_phrase(), "a License sale is high risk");
        for ack in [
            AckKind::Destination,
            AckKind::Amount,
            AckKind::Fee,
            AckKind::Conditions,
            AckKind::Irreversible,
        ] {
            assert!(reviewed.acknowledgements().contains(&ack), "{ack:?}");
        }
        // The fee is exactly the floor of the placeholder length, which is the final length.
        let size = planned.objects()[0].bytes.len() as u64;
        assert_eq!(reviewed.fee().atoms, size.max(240));
        assert_eq!(reviewed.fee().size_bytes, Some(size));
        assert_eq!(reviewed.fee().payer, FeePayer::ThisWallet);
        assert_eq!(reviewed.amount(), Some(PRICE));
        assert_eq!(reviewed.timing().valid_only_at, None);
        assert_eq!(reviewed.timing().created_height, Some(1));
        assert_eq!(reviewed.timing().expiry_height, Some(2));
        let text = reviewed.render_text();
        assert!(
            text.contains("Signed inclusion heights 1 through 2"),
            "{text}"
        );
        assert!(text.contains(&hex::encode(offer_id)));
        assert!(text.contains(&hex::encode(TRADE)) && text.contains(&hex::encode(CONTRACT)));
        assert!(text.contains("FRESH Worker assignment"));
        // Payment to the seller's own address: the seller's address needs the typed check.
        assert_eq!(reviewed.destinations()[0].address, seller);
        assert_eq!(
            reviewed.destinations()[0].role,
            DestinationRole::LicensePayment
        );
        let signed = trading::sign_plan(planned, &buyer_signer, &view).unwrap();
        (signed, reviewed.binding())
    };
    assert!(!buyer_part.is_complete());
    let maker_id = offer.body.maker().unwrap();
    assert_eq!(
        buyer_part.missing(),
        &[
            Requirement {
                slot: Slot::Approval(0),
                signer: RequiredSigner::Wallet(seller),
                status: RequirementStatus::Counterparty
            },
            Requirement {
                slot: Slot::FillSignature,
                signer: RequiredSigner::Maker(maker_id),
                status: RequirementStatus::Maker
            }
        ]
    );
    // The buyer's approval verifies through consensus code; the seller's slot is still a placeholder.
    let wire = NativeOperation::decode(buyer_part.bytes()).unwrap();
    trading_v1::verify_approval(&chain.state().wallets, &wire.operation, 1).unwrap();
    assert!(trading_v1::verify_approval(&chain.state().wallets, &wire.operation, 0).is_err());

    // ---- the buyer queues its part: coins, the License and the offer are reserved
    let mut buyer_outbox = MemoryOutbox::new();
    buyer_outbox
        .commit(&buyer_part, &chain.view(&none))
        .unwrap();
    let reserved = buyer_outbox.reserved().unwrap();
    assert!(reserved.contains(&resource_key("license", &license)));
    assert!(reserved.contains(&resource_key("offer", &offer_id)));
    {
        // While it is queued, no second plan can take the same offer or License.
        let view = chain.view(&reserved);
        assert_eq!(
            plan(&request(&offer, license), &view, &identity(&buyer_wallet)).unwrap_err(),
            Refusal::ReservedInput
        );
    }

    // ---- the part travels as a public container (Q12)
    let container = PartialApproval::from_signed(&buyer_part, chain.view(&none).context())
        .unwrap()
        .export()
        .unwrap();

    // ---- the maker signs the fill over the exact body; the wallet verifies and attaches it
    let proof = trading::fill_proof(&maker, &offer, buyer_part.bytes());
    let with_fill =
        offers::attach_fill_proof(buyer_part.bytes(), &proof, &chain.view(&none)).unwrap();

    // ---- the seller explains the buyer's part, adopts it and co-signs ONLY slot 0
    let seller_part = {
        let view = chain.view(&none);
        let imported = PartialApproval::import(&container).unwrap();
        let explained = imported
            .explain_for(&view, &identity(&seller_wallet))
            .unwrap();
        assert_eq!(
            explained.binding(),
            digest,
            "the seller reviews the same digest"
        );
        assert!(explained.title().starts_with("Sell License "));
        let statuses: Vec<(Slot, RequirementStatus)> = explained
            .authorizations()
            .iter()
            .map(|r| (r.slot, r.status))
            .collect();
        assert_eq!(
            statuses,
            [
                (Slot::Approval(0), RequirementStatus::ThisWallet),
                (Slot::Approval(1), RequirementStatus::Provided),
                (Slot::OfferSignature, RequirementStatus::Provided),
                (Slot::FillSignature, RequirementStatus::ThisWallet),
            ]
        );
        let text = explained.render_text();
        assert!(text.contains("This wallet loses License"), "{text}");
        assert!(
            text.contains("is still attributed to this wallet"),
            "{text}"
        );
        assert!(text.contains("This wallet receives the price"), "{text}");
        assert_eq!(explained.fee().payer, FeePayer::Counterparty(buyer));
        // The fill, once attached, is shown as provided.
        let filled = explain(&with_fill, &view, &identity(&seller_wallet)).unwrap();
        assert_eq!(filled.binding(), digest);
        assert!(
            filled
                .authorizations()
                .iter()
                .any(|r| r.slot == Slot::FillSignature && r.status == RequirementStatus::Provided)
        );
        let adopted = imported
            .adopt_for(&view, &identity(&seller_wallet))
            .unwrap();
        assert_eq!(review(&adopted, &view).unwrap().binding(), digest);
        trading::sign_plan(adopted, &seller_signer, &view).unwrap()
    };
    assert!(
        !seller_part.is_complete(),
        "each wallet signs only its own slot"
    );
    let seller_wire = NativeOperation::decode(seller_part.bytes()).unwrap();
    trading_v1::verify_approval(&chain.state().wallets, &seller_wire.operation, 0).unwrap();
    assert!(
        trading_v1::verify_approval(&chain.state().wallets, &seller_wire.operation, 1).is_err()
    );

    // ---- combine: complete, and verified through consensus code
    let complete = offers::combine(&[&with_fill, seller_part.bytes()], &chain.view(&none)).unwrap();
    assert!(complete.is_complete());
    assert_eq!(complete.id(), buyer_part.id());
    {
        let view = chain.view(&none);
        trading::consensus(&view, complete.bytes()).expect("prepare_batch accepts the sale");
        let wire = NativeOperation::decode(complete.bytes()).unwrap();
        for slot in [0, 1] {
            trading_v1::verify_approval(&chain.state().wallets, &wire.operation, slot).unwrap();
        }
        wire.operation.verify_offer(1).unwrap();
        assert!(wire.operation.meta.fee.0 >= complete.bytes().len() as u64);
        // The signed bytes are exactly the reviewed unsigned bytes plus signatures.
        assert_eq!(
            explain(complete.bytes(), &view, &identity(&seller_wallet))
                .unwrap()
                .binding(),
            digest
        );
    }
    let mut seller_outbox = MemoryOutbox::new();
    seller_outbox.commit(&complete, &chain.view(&none)).unwrap();

    // ---- a REAL block at exactly the effective height transfers the License
    assert_eq!(
        chain.prepare(&[complete.bytes().to_vec()]).map(|_| ()),
        Ok(())
    );
    trading::assert_forged_applied_receipt_cannot_confirm(&complete, &chain.view(&none));
    let after = chain.step(&[complete.bytes().to_vec()]);
    assert_eq!(chain.height(), 1);
    let record = after.licenses_v2.license(license).unwrap();
    assert_eq!(
        (
            record.owner,
            record.active_worker,
            record.assignment_sequence
        ),
        (buyer, None, 2)
    );
    assert_eq!(trading_v1::license_generation(&after, license), Ok(2));
    let (_, transfer) =
        NativeRecord::decode(&after.protocol_records[&trading_v1::record_key(4, license)]).unwrap();
    assert!(matches!(
        transfer,
        NativeRecord::License {
            generation: 2,
            inclusion_height: 1,
            rights_from_height: 2,
            ..
        }
    ));
    let id = complete.id();
    let paid = &after.coins[&OutPoint {
        transaction: id,
        index: 0,
    }];
    assert_eq!((paid.output.owner, paid.output.atoms), (seller, PRICE));
    let change = &after.coins[&OutPoint {
        transaction: id,
        index: 1,
    }];
    assert_eq!(change.output.owner, buyer);
    let fee = wire.operation.meta.fee.0;
    let spent: u64 = wire
        .inputs
        .iter()
        .map(|point| chain_coin(&wire, point))
        .sum();
    assert_eq!(change.output.atoms + PRICE + fee, spent);
    assert!(
        after.protocol_records.contains_key(&trading_v1::record_key(
            1,
            trading_v1::single_fill_key(&trading::context_of(chain.genesis()), [0; 32], offer_id)
        )),
        "the single-fill offer is consumed"
    );
    assert_eq!(
        trading_v1::reconcile(&after, complete.bytes())
            .unwrap()
            .map(|receipt| receipt.height),
        Some(1)
    );

    // ---- reconciliation from verified state: the seller's complete record and the buyer's PART
    //      (same operation identifier, other bytes) both settle as confirmed at block 1
    for outbox in [&mut buyer_outbox, &mut seller_outbox] {
        let report = outbox.reconcile(&chain.view(&none)).unwrap();
        assert_eq!(report.confirmed, 1, "{report:?}");
        assert_eq!(
            outbox.get(&id).unwrap().unwrap().status,
            OutboxStatus::Confirmed(1)
        );
        assert!(outbox.reserved().unwrap().is_empty());
    }

    // ---- the consumed offer and the stale generation can never be used again
    {
        let history = chain.operation_history(complete.bytes());
        let view = chain.view(&none).with_history(&history);
        assert_eq!(
            plan(&request(&offer, license), &view, &identity(&buyer_wallet)).unwrap_err(),
            Refusal::LicenseGenerationStale,
            "the offer names generation 1; the License is now at generation 2"
        );
        assert_eq!(
            explain(complete.bytes(), &view, &identity(&seller_wallet)).unwrap_err(),
            Refusal::Replay
        );
        assert!(trading::consensus(&view, complete.bytes()).is_err());
    }
    chain.finish();
}

/// The coin amount of an input of `wire` (all funding coins of these tests are known).
fn chain_coin(_wire: &NativeOperation, point: &OutPoint) -> u64 {
    match point.transaction[0] {
        0xb1 => 5_000_000,
        0xb2 => 3_000_000,
        0xb3 => 1_000_000,
        other => panic!("unexpected input {other:#x}"),
    }
}

#[test]
fn inclusion_retains_exact_historical_reference_and_refuses_outside_the_signed_window() {
    let buyer = address_of(&buyer_key());
    let mut chain = TradeChain::new("dvp-height", 1_200_000, &[(0xb1, buyer, 5_000_000)], &[]);
    let license = license_id(3);
    let maker = trading::maker();
    let offer = license_offer(&chain, &maker, license, 1);
    let none = BTreeSet::new();

    // Built at head 0: signed window 1..=2 with canonical reference at block 0.
    let (_, _, _, complete, _) = sale(&chain, &maker, &offer, license);
    let session_plan = plan(
        &request(&offer, license),
        &chain.view(&none),
        &identity(&buyer_key()),
    )
    .unwrap();
    let mut session = PlanSession::new(session_plan);
    session.present(&chain.view(&none)).unwrap();

    // A new head clears review/approval, while exact already-signed bytes stay eligible.
    chain.step(&[]);
    {
        let history = chain.operation_history(complete.bytes());
        let view = chain.view(&none).with_history(&history);
        let seen = explain(complete.bytes(), &view, &identity(&buyer_key())).unwrap();
        assert_eq!(seen.timing().expiry_height, Some(2));
        assert_eq!(
            NativeOperation::decode(complete.bytes())
                .unwrap()
                .operation
                .meta
                .envelope
                .reference_height,
            0
        );
        assert!(
            chain.prepare(&[complete.bytes().to_vec()]).is_ok(),
            "own canonical history accepts unchanged bytes at the signed last height"
        );
        // Review again at every new head before another signature; no automatic rebasing.
        session.on_head(&view);
        assert_eq!(session.phase(), PlanPhase::Planned);
    }

    // Both sides of the signed window, with independently signed native bodies.
    let fresh = plan(
        &request(&offer, license),
        &chain.view(&none),
        &identity(&buyer_key()),
    )
    .unwrap();
    let base = fresh.objects()[0].bytes.clone();
    let at_window = |first: u64, last: u64| {
        let unsigned = trading::mutate(&base, |wire| {
            wire.operation.meta.envelope.first_height = first;
            wire.operation.meta.envelope.last_height = last;
            if first == 1 {
                wire.operation.meta.envelope.reference_height = 0;
                wire.operation.meta.envelope.reference_block = chain.genesis().block;
            }
        });
        trading::sign_all(
            &unsigned,
            &[(0, &seller_key(), 1), (1, &buyer_key(), 1)],
            Some((&maker, &offer)),
        )
    };
    let early = at_window(3, 4);
    let late = at_window(1, 1);
    {
        let view = chain.view(&none);
        assert_eq!(
            explain(&early, &view, &identity(&buyer_key())).unwrap_err(),
            Refusal::WindowNotOpen {
                created: 3,
                next_height: 2
            }
        );
        assert_eq!(
            explain(&late, &view, &identity(&buyer_key())).unwrap_err(),
            Refusal::WindowClosed {
                expiry: 1,
                next_height: 2
            }
        );
        for (raw, cause) in [
            (
                &early,
                mutiny_consensus_v8::op_envelope_v1::EnvelopeError::Future,
            ),
            (
                &late,
                mutiny_consensus_v8::op_envelope_v1::EnvelopeError::Expired,
            ),
        ] {
            assert_eq!(
                trading::consensus(&view, raw).unwrap_err(),
                trading_v1::NativeError::Envelope(cause),
                "exact signed window is checked before execution"
            );
        }
        assert!(chain.prepare(std::slice::from_ref(&early)).is_err());
    }
    // Empty block 2 advances to the signed first height without changing the carrier.
    chain.step(&[]);
    {
        let history = chain.operation_history(&early);
        let view = chain.view(&none).with_history(&history);
        let explained = explain(&early, &view, &identity(&buyer_key())).unwrap();
        assert_eq!(explained.timing().created_height, Some(3));
        assert_eq!(explained.timing().expiry_height, Some(4));
        assert_eq!(explained.timing().valid_only_at, None);
        let imported = SignedOperation::import(&early, &view).unwrap();
        assert!(imported.is_complete());
    }
    session.on_head(&chain.view(&none));
    assert_eq!(
        session.phase(),
        PlanPhase::Invalidated(Invalidation::Expired)
    );
    // Skip the first eligible height; actual inclusion at the exact last height still succeeds.
    chain.step(&[]);
    let history = chain.operation_history(&early);
    assert!(
        SignedOperation::import(&early, &chain.view(&none).with_history(&history))
            .unwrap()
            .is_complete()
    );
    let after = chain.step(&[early]);
    assert_eq!(
        after.licenses_v2.license(license).unwrap().owner,
        buyer,
        "accepted at the exact signed last height through own canonical history"
    );
    chain.finish();
}

fn claim(
    chain: &TradeChain,
    signer: &HybridKey,
    license: Hash,
    amount: u64,
    sequence: u64,
    destination: Hash,
) -> Vec<u8> {
    let genesis = chain.genesis();
    SignedClaim::sign(
        ClaimBody {
            network: genesis.network,
            genesis: genesis.genesis,
            fingerprint: genesis.fingerprint,
            created_height: 1,
            expiry_height: 10_000,
            award_epoch: P,
            license,
            amount,
            destination,
            sequence,
        },
        signer.public().descriptor(1).unwrap(),
        signer,
    )
    .unwrap()
    .encode()
}

#[test]
fn signed_dividends_transfer_exactly_and_a_seller_claim_in_the_sale_block_fails() {
    let seller_wallet = seller_key();
    let buyer_wallet = buyer_key();
    let buyer = address_of(&buyer_wallet);
    let mut chain = TradeChain::new("dvp-dividends", 1_200_000, &[(0xb1, buyer, 5_000_000)], &[]);
    let license = license_id(4);
    // The first award boundary: every Genesis License gets an award of 50,000 atoms.
    let awarded = chain.step_at(P, &[]);
    let account = awarded
        .dividends
        .ledger()
        .award(P)
        .unwrap()
        .account(&license)
        .unwrap();
    assert_eq!(
        (account.share, account.remaining, account.claims),
        (50_000, 50_000, 0)
    );
    let maker = trading::maker();
    let offer = license_offer(&chain, &maker, license, 1);
    let none = BTreeSet::new();

    // Native P5 binds the exact live award facts; changed claims need a fresh sale and approvals.
    {
        let view = chain.view(&none);
        let planned = plan(&request(&offer, license), &view, &identity(&buyer_wallet)).unwrap();
        let reviewed = review(&planned, &view).unwrap();
        assert!(reviewed.acknowledgements().contains(&AckKind::Conditions));
        let text = reviewed.render_text();
        assert!(
            text.contains("binds the COMPLETE live-account list"),
            "{text}"
        );
        assert!(!text.contains("does NOT bind"), "{text}");
        assert!(text.contains(&format!("award epoch {P}")), "{text}");
        let seen_by_seller = explain(
            &planned.objects()[0].bytes,
            &view,
            &identity(&seller_wallet),
        )
        .unwrap();
        assert!(
            seen_by_seller
                .warnings()
                .iter()
                .any(|w| w.code == "BOUND_DIVIDENDS" && w.severity == Severity::Danger)
        );
    }
    let (_, _, _, complete, _) = sale(&chain, &maker, &offer, license);
    let trade = complete.bytes().to_vec();
    let (destination_seller, destination_buyer) = ([0x51; 32], [0x52; 32]);
    let stale_seller = claim(
        &chain,
        &seller_wallet,
        license,
        3_000,
        0,
        destination_seller,
    );
    let new_buyer = claim(&chain, &buyer_wallet, license, 3_000, 0, destination_buyer);
    let genesis = chain.genesis().clone();
    let epoch = chain.next_epoch();
    assert_eq!(epoch, P + 1);

    // The seller's claim is valid BEFORE the sale (it was valid when signed) ...
    admit(
        chain.state(),
        &stale_seller,
        genesis.genesis,
        genesis.fingerprint,
        2,
        epoch,
    )
    .expect("the seller may claim before the sale");
    // ... but inside the sale's block the claim sees the transferred owner and fails.
    let post_trade = chain.prepare(std::slice::from_ref(&trade)).unwrap();
    assert_eq!(
        post_trade.licenses_v2.license(license).unwrap().owner,
        buyer
    );
    assert_eq!(
        format!(
            "{:?}",
            admit(
                &post_trade,
                &stale_seller,
                genesis.genesis,
                genesis.fingerprint,
                2,
                epoch
            )
            .unwrap_err()
        ),
        "StaleOwner"
    );
    admit(
        &post_trade,
        &new_buyer,
        genesis.genesis,
        genesis.fingerprint,
        2,
        epoch,
    )
    .expect("the buyer holds the claim authority after the transfer");
    // Through real blocks: the sale plus the stale seller claim is refused whatever the listing
    // order, and nothing is applied.
    let before = chain.state().records().unwrap();
    for ops in [
        vec![trade.clone(), stale_seller.clone()],
        vec![stale_seller.clone(), trade.clone()],
    ] {
        assert!(chain.try_step(&ops).is_err());
        assert_eq!(chain.height(), 1);
        assert_eq!(chain.state().records().unwrap(), before);
    }
    // The sale with the buyer's claim is accepted: the award account continues for the buyer.
    let after = chain.step(&[trade, new_buyer]);
    assert_eq!(after.licenses_v2.license(license).unwrap().owner, buyer);
    let account = after
        .dividends
        .ledger()
        .award(P)
        .unwrap()
        .account(&license)
        .unwrap();
    assert_eq!((account.remaining, account.claims), (47_000, 1));
    chain.finish();
}

#[test]
fn a_prior_canonical_claim_invalidates_the_still_open_sale_and_fresh_approvals_bind_the_remainder()
{
    let seller_wallet = seller_key();
    let buyer_wallet = buyer_key();
    let buyer = address_of(&buyer_wallet);
    let mut chain = TradeChain::new(
        "dvp-prior-claim",
        1_200_000,
        &[(0xb1, buyer, 5_000_000)],
        &[],
    );
    let license = license_id(4);
    chain.step_at(P, &[]);
    let maker = trading::maker();
    let offer = license_offer(&chain, &maker, license, 1);
    let (_, _, _, old_sale, _) = sale(&chain, &maker, &offer, license);
    let old_bytes = old_sale.bytes().to_vec();
    let old_wire = NativeOperation::decode(&old_bytes).unwrap();
    let seller_claim = claim(&chain, &seller_wallet, license, 3_000, 0, [0x53; 32]);
    chain.step(&[seller_claim]);
    let none = BTreeSet::new();
    let history = chain.operation_history(&old_bytes);
    let view = chain.view(&none).with_history(&history);
    assert!(old_wire.operation.meta.envelope.first_height <= chain.height() + 1);
    assert!(chain.height() + 1 <= old_wire.operation.meta.envelope.last_height);
    assert_eq!(
        explain(&old_bytes, &view, &identity(&buyer_wallet)).unwrap_err(),
        Refusal::LicenseGenerationStale
    );
    assert!(matches!(
        trading_v1::prepare_batch_with_history(
            view.state(),
            view.anchor(),
            view.state_root(),
            &history,
            &[old_bytes.clone()],
            &trading_v1::CandidatePolicy::native_denomination_locked()
        )
        .unwrap_err(),
        trading_v1::NativeError::Stale(
            mutiny_consensus_v8::op_envelope_v1::TAG_LICENSE_ENTITLEMENTS
        )
    ));
    let before = chain.state().records().unwrap();
    let rows = chain.canonical_rows();
    assert!(chain.try_step(&[old_bytes]).is_err());
    assert_eq!(chain.state().records().unwrap(), before);
    assert_eq!(chain.canonical_rows(), rows);
    assert_eq!(chain.height(), 2);
    // Every party reviews and signs a NEW body, committing the 47,000 remainder and claim sequence1.
    let (_, _, _, new_sale, _) = sale(&chain, &maker, &offer, license);
    assert_ne!(new_sale.id(), old_sale.id());
    let new_wire = NativeOperation::decode(new_sale.bytes()).unwrap();
    let entitlement =
        mutiny_consensus_v8::op_envelope_v1::entitlement_facts(chain.state(), license);
    assert!(
        new_wire
            .operation
            .meta
            .envelope
            .preconditions
            .contains(&entitlement)
    );
    let after = chain.step(&[new_sale.bytes().to_vec()]);
    assert_eq!(after.licenses_v2.license(license).unwrap().owner, buyer);
    let account = after
        .dividends
        .ledger()
        .award(P)
        .unwrap()
        .account(&license)
        .unwrap();
    assert_eq!((account.remaining, account.claims), (47_000, 1));
    chain.finish();
}

#[test]
fn a_maker_proof_for_another_body_or_by_another_maker_is_refused_before_anything_is_combined() {
    let buyer = address_of(&buyer_key());
    let chain = TradeChain::new("dvp-proof", 1_200_000, &[(0xb1, buyer, 5_000_000)], &[]);
    let license = license_id(5);
    let maker = trading::maker();
    let offer = license_offer(&chain, &maker, license, 1);
    let none = BTreeSet::new();
    let view = chain.view(&none);
    let planned = plan(&request(&offer, license), &view, &identity(&buyer_key())).unwrap();
    let part =
        trading::sign_plan(planned, &KeySigner::for_test(buyer_key()).unwrap(), &view).unwrap();

    // A fill over a DIFFERENT body (one atom of the fee moved to the change).
    let other_body = trading::mutate(part.bytes(), |wire| {
        wire.operation.meta.fee.0 += 1;
        if let trading_v1::Action::LicenseDvp { change, .. } = &mut wire.operation.action {
            change.0 -= 1;
        }
    });
    let wrong_body = trading::fill_proof(&maker, &offer, &other_body);
    assert_eq!(
        offers::attach_fill_proof(part.bytes(), &wrong_body, &view).unwrap_err(),
        Refusal::OfferProofInvalid
    );
    // A proof by ANOTHER maker for its own (otherwise identical) offer.
    let impostor = buyer_key();
    let impostor_offer = license_offer(&chain, &impostor, license, 1);
    let impostor_proof = trading::fill_proof(&impostor, &impostor_offer, part.bytes());
    assert_eq!(
        offers::attach_fill_proof(part.bytes(), &impostor_proof, &view).unwrap_err(),
        Refusal::OfferProofInvalid
    );
    // Consensus agrees: the same wrong proofs make the complete operation invalid.
    let signed_wrong = {
        let mut wire = NativeOperation::decode(&trading::sign_all(
            part.bytes(),
            &[(0, &seller_key(), 1), (1, &buyer_key(), 1)],
            None,
        ))
        .unwrap();
        wire.operation.offer_proof = Some(OfferProof::decode(&wrong_body).unwrap());
        wire.encode().unwrap()
    };
    assert!(matches!(
        trading::consensus(&view, &signed_wrong).unwrap_err(),
        trading_v1::NativeError::Candidate(trading_v1::Error::Signature)
    ));
    // The good proof attaches.
    let good = trading::fill_proof(&maker, &offer, part.bytes());
    assert!(offers::attach_fill_proof(part.bytes(), &good, &view).is_ok());
    chain.finish();
}
