//! The Treasury profile end to end on a REAL consensus chain (NATIVE, TEST-VALUE): every block below
//! is built by the production assembler, certified with real hybrid votes and installed by the
//! canonical store with full replay.
//!
//!  * R2 (`TreasuryRotate`): native locks fund at the original current authority BEFORE R1/R2;
//!    the destination then moves to the exact current generation established by R1, with host
//!    restore evidence, review, authorization, bounded pool admission and certified inclusion.
//!    Funded obligations preserve exact destinations and deadlines. The current key claims to the
//!    historic recipient; the sender refunds the other obligation at its original deadline.
//!    An old unfunded maker offer cannot gain authority from fresh settlement approvals.
//!  * R1 (`WalletRotation` of the Genesis Treasury authority, phase 2's handler) under the Treasury
//!    profile, funded by another wallet (the D2 rehearsal shape), into a real block; the profile
//!    gating also through `adopt`.
//!  * The dividend reserve: a Treasury at exactly its reserve cannot pay its own rotation fee (wallet
//!    and block execution agree), another wallet funds it, the reserve backing then counts the new
//!    address, and a Treasury-funded `TreasuryRotate` below the reserve is refused by the wallet and
//!    by block execution alike.
//!  * The Treasury profile declaration checked against the real chain.
#[path = "support/treasury_kit.rs"]
mod kit;
#[path = "support/treasury_rig.rs"]
mod treasury_rig;

use kit::{FreezeTerms, TRADING_TREASURY};
use mutiny_consensus_v8::{
    Hash,
    hybrid_transaction_v2::Transaction,
    trading_v1::{self, CandidatePolicy, FrozenTreasuryOffer, NativeOperation, SignedOffer},
    transactions::OutPoint,
};
use mutiny_crypto_v2::HybridKey;
use mutiny_wallet_core_v8::{
    ops::{
        rotation::{self, RotationSigner, combine},
        treasury::{self, rotation_resource},
    },
    profile::{self, TreasuryDeclaration},
    *,
};
use std::collections::BTreeSet;
use treasury_rig::chain::*;

fn policy() -> CandidatePolicy {
    CandidatePolicy::native_denomination_locked()
}

fn point(tag: u8) -> OutPoint {
    OutPoint {
        transaction: [tag; 32],
        index: 0,
    }
}

fn rotate_to(key: &HybridKey, generation: u64) -> OperationRequest {
    OperationRequest::TreasuryRotate(TreasuryRotateRequest::new(Blob::new(descriptor_of(
        key, generation,
    ))))
}

fn freeze(proposal: Vec<u8>) -> OperationRequest {
    OperationRequest::TreasuryFreezeOffer(TreasuryFreezeOfferRequest::new(Blob::new(proposal)))
}

fn wallet_rotation(new: &HybridKey, generation: u64, fee: FeeSource) -> OperationRequest {
    let proposed = descriptor_of(new, generation);
    OperationRequest::WalletRotation(
        RotationRequest::new(Blob::new(proposed.clone()), fee)
            .with_restore_verified(rotation::descriptor_fingerprint(&proposed)),
    )
}

fn signer_for(key: HybridKey, identity: &SignerIdentity) -> KeySigner {
    KeySigner::with_identity(
        key,
        identity.clone(),
        SigningGate::test_value().unwrap(),
        DEFAULT_IDLE_LIMIT,
    )
    .unwrap()
}

/// The Treasury-profile identity of `key` (generation `generation`, authority `authority`),
/// declared for the roles given and checked against the view.
fn declared(
    key: &HybridKey,
    generation: u64,
    authority: Option<Hash>,
    view: &ChainView<'_>,
    authority_role: bool,
    destination_of: Option<Hash>,
) -> SignerIdentity {
    kit::declared(
        key,
        generation,
        authority,
        view,
        authority_role,
        destination_of,
    )
}

fn condition(review: &Review, label: &str) -> String {
    review
        .conditions()
        .iter()
        .find(|condition| condition.label == label)
        .unwrap_or_else(|| panic!("no condition {label}"))
        .detail
        .clone()
}

/// A hash lock funding a Treasury offer, built and signed with the consensus helpers (the funder,
/// the Treasury as recipient and the maker are played by the test), with an exact fee.
#[allow(clippy::too_many_arguments)]
fn funding_lock(
    view: &ChainView<'_>,
    offer: &SignedOffer,
    maker: &HybridKey,
    trade: Hash,
    contract: Hash,
    sender: &HybridKey,
    coin: (OutPoint, u64),
    recipient_key: &HybridKey,
    recipient: Hash,
    amount: u64,
) -> NativeOperation {
    kit::funding_lock(
        view,
        offer,
        maker,
        trade,
        contract,
        sender,
        coin,
        recipient_key,
        recipient,
        amount,
    )
}

#[test]
fn treasury_rotate_end_to_end_funded_locks_keep_their_destination_and_addresses_are_used_once() {
    let treasury = treasury_wallet_key();
    let a1 = address_of(&treasury, 1);
    let funder = wallet_key();
    let sender = address_of(&funder, 1);
    let next_key = labelled_key("w6-e2e-r2-next-destination");
    let a2 = address_of(&next_key, 2);
    let mut chain = TreasuryChain::new(
        "w6-e2e-current-r2",
        1_200_000,
        Some((TRADING_TREASURY, descriptor_of(&treasury, 1))),
        &[
            (0xa1, sender, 3_000_000),
            (0xa2, sender, 3_000_000),
            (0xa3, sender, 3_000_000),
            (0xd2, a1, 300_000),
        ],
    );
    let none = BTreeSet::new();
    chain.step();
    let context = kit::context_of(&chain.anchor());
    let mut outbox = MemoryOutbox::new();
    let me = declared(
        &treasury,
        1,
        None,
        &chain.view(&none),
        true,
        Some(TRADING_TREASURY),
    );
    let signer = signer_for(treasury_wallet_key(), &me);

    // Freeze witnesses are reviewed above consensus; first funding remains current-authority.
    let view = chain.view(&none);
    let offer = kit::treasury_offer(
        &treasury,
        context.clone(),
        view.anchor().height,
        view.anchor().height + 40,
        100_000,
        5_000,
        3,
        0x51,
    );
    let terms = FreezeTerms {
        treasury: TRADING_TREASURY,
        generation: 1,
        address: a1,
        trade: [0x21; 32],
        contract: [0x22; 32],
        wallet_descriptor: descriptor_of(&treasury, 1),
    };
    let planned = plan(&freeze(kit::proposal(&view, &terms, &offer)), &view, &me).unwrap();
    let reviewed = review(&planned, &view).unwrap();
    assert!(reviewed.requires_phrase());
    for ack in [
        AckKind::TreasuryAuthority,
        AckKind::ExternalEvidence,
        AckKind::Conditions,
    ] {
        assert!(reviewed.acknowledgements().contains(&ack));
    }
    assert!(
        reviewed
            .render_text()
            .contains("Bitcoin settlement not verified by this wallet")
    );
    let frozen = signer
        .authorize(planned, kit::approve(&reviewed, &view), &view)
        .unwrap();
    outbox.commit(&frozen, &view).unwrap();
    let creation = trading_v1::verify_frozen_treasury_offer_at_creation(
        FrozenTreasuryOffer::decode(frozen.bytes()).unwrap(),
        view.state(),
        view.anchor(),
        view.state_root(),
        &policy(),
    )
    .unwrap();
    let lock = kit::funding_lock(
        &view,
        &offer,
        &treasury,
        terms.trade,
        terms.contract,
        &funder,
        (point(0xa1), 3_000_000),
        &treasury,
        a1,
        100_000,
    );
    trading_v1::prepare_treasury_funding(
        view.state(),
        view.anchor(),
        view.state_root(),
        &creation,
        &lock,
        &policy(),
    )
    .unwrap();
    let lock_id = lock.operation.output_id(0).unwrap();
    let mut pool = chain.submission_pool();
    let funding_id = chain
        .admit_submission(&mut pool, 1, &lock.encode().unwrap())
        .unwrap();
    chain.step_submissions(&mut pool);
    assert_eq!(chain.verified_operations(funding_id).len(), 1);
    let original = trading_v1::locked(chain.state(), lock_id).unwrap();
    assert_eq!(original.recipient, a1);
    assert_eq!(
        outbox.reconcile(&chain.view(&none)).unwrap().inputs_spent,
        1
    );
    assert!(
        chain.verified_operations(frozen.id()).is_empty(),
        "freeze witness is never a block item"
    );

    let view = chain.view(&none);
    let refund_offer = kit::treasury_offer(
        &treasury,
        context.clone(),
        chain.height(),
        chain.height() + 40,
        80_000,
        4_000,
        3,
        0x52,
    );
    let refund_lock = kit::funding_lock(
        &view,
        &refund_offer,
        &treasury,
        [0x25; 32],
        [0x26; 32],
        &funder,
        (point(0xa2), 3_000_000),
        &treasury,
        a1,
        80_000,
    );
    let refund_lock_id = refund_lock.operation.output_id(0).unwrap();
    chain
        .admit_submission(&mut pool, 1, &refund_lock.encode().unwrap())
        .unwrap();
    chain.step_submissions(&mut pool);
    let original_refund = trading_v1::locked(chain.state(), refund_lock_id).unwrap();

    // A distinct old maker offer remains genuinely UNFUNDED before the rotation.
    let unfunded = kit::treasury_offer(
        &treasury,
        context.clone(),
        chain.height(),
        chain.height() + 40,
        70_000,
        3_000,
        3,
        0x53,
    );
    // R1 establishes the new descriptor and current authority before R2.
    let view = chain.view(&none);
    let planned = plan(
        &wallet_rotation(&next_key, 2, FeeSource::RotatingAuthority),
        &view,
        &me,
    )
    .unwrap();
    let reviewed = review(&planned, &view).unwrap();
    let rotated = RotationSigner::for_test(
        treasury_wallet_key(),
        me.clone(),
        labelled_key("w6-e2e-r2-next-destination"),
    )
    .unwrap()
    .authorize(planned, kit::approve(&reviewed, &view), &view)
    .unwrap();
    assert!(rotated.is_complete());
    let r1_id = chain
        .admit_submission(&mut pool, 0, rotated.bytes())
        .unwrap();
    chain.step_submissions(&mut pool);
    assert_eq!(
        chain.state().wallets.current(a1).unwrap(),
        descriptor_of(&next_key, 2)
    );
    assert_eq!(chain.verified_operations(r1_id).len(), 1);

    // Old offer + fresh current recipient approval still cannot authorize first funding.
    let view = chain.view(&none);
    let bad = kit::funding_lock_at_generation(
        &view,
        &unfunded,
        &treasury,
        [0x31; 32],
        [0x32; 32],
        &funder,
        sender,
        1,
        (point(0xa3), 3_000_000),
        &next_key,
        a1,
        2,
        70_000,
    );
    let rows = chain.canonical_rows();
    assert!(
        chain
            .admit_submission(&mut pool, 1, &bad.encode().unwrap())
            .is_err()
    );
    assert_eq!(chain.canonical_rows(), rows);
    assert_eq!(
        trading_v1::locked(chain.state(), lock_id).unwrap(),
        original
    );

    let me_now = declared(&next_key, 2, Some(a1), &view, true, Some(TRADING_TREASURY));
    let signer_now = signer_for(labelled_key("w6-e2e-r2-next-destination"), &me_now);
    let r2 = OperationRequest::TreasuryRotate(
        TreasuryRotateRequest::new(Blob::new(descriptor_of(&next_key, 2))).with_verified_restore(
            TRADING_TREASURY,
            rotation::descriptor_fingerprint(&descriptor_of(&next_key, 2)),
        ),
    );
    let planned = plan(&r2, &view, &me_now).unwrap();
    assert!(
        planned
            .inputs()
            .contains(&rotation_resource(&TRADING_TREASURY, 1))
    );
    let reviewed = review(&planned, &view).unwrap();
    assert_eq!(reviewed.title(), "Rotate the Treasury destination");
    assert_eq!(reviewed.destinations()[0].address, a2);
    assert!(reviewed.requires_phrase());
    for label in [
        "Treasury",
        "Generation",
        "Address used once",
        "Effective height",
        "New offers",
        "Frozen offers",
        "Bitcoin custody",
        "Fee coins",
        "Dividend reserve",
        "Finality",
    ] {
        assert!(!condition(&reviewed, label).is_empty());
    }
    assert!(condition(&reviewed, "Frozen offers").contains("current signing authority"));
    let r2_signed = signer_now
        .authorize(planned, kit::approve(&reviewed, &view), &view)
        .unwrap();
    outbox.commit(&r2_signed, &view).unwrap();
    let inclusion = chain.height() + 1;
    let r2_id = chain
        .admit_submission(&mut pool, 1, r2_signed.bytes())
        .unwrap();
    chain.step_submissions(&mut pool);
    let active = trading_v1::treasury_current(chain.state(), &context, TRADING_TREASURY).unwrap();
    assert_eq!(
        (active.generation, active.address, active.effective_height),
        (2, a2, inclusion)
    );
    let generations =
        trading_v1::treasury_generations(chain.state(), &context, TRADING_TREASURY).unwrap();
    assert_eq!(generations.len(), 2);
    assert_eq!((generations[0].generation, generations[0].address), (1, a1));
    assert_eq!(
        trading_v1::locked(chain.state(), lock_id).unwrap(),
        original,
        "funded amount/destination/condition/deadline remain exact across both rotations"
    );
    assert_eq!(
        trading_v1::locked(chain.state(), refund_lock_id).unwrap(),
        original_refund
    );
    let confirmations = chain.confirmations();
    assert_eq!(
        outbox
            .reconcile(&chain.view(&none).with_confirmations(&confirmations))
            .unwrap()
            .confirmed,
        1
    );
    assert_eq!(chain.verified_operations(r2_id).len(), 1);
    chain = chain.restart();

    // Current2 claims the OLD recipient lineage; no retired key signs or redirects the claim.
    let view = chain.view(&none);
    let claim = OperationRequest::ConditionalClaim(ClaimRequest::new(
        lock_id,
        Preimage::from_bytes([0x42; 32]),
    ));
    assert_eq!(
        plan(&claim, &view, &me).unwrap_err(),
        Refusal::StaleAuthority
    );
    let planned = plan(&claim, &view, &me_now).unwrap();
    let reviewed = review(&planned, &view).unwrap();
    let signed = signer_now
        .authorize(planned, kit::approve(&reviewed, &view), &view)
        .unwrap();
    let claim_wire = kit::wire(signed.bytes());
    let trading_v1::Action::Claim { recipient, .. } = claim_wire.operation.action else {
        panic!("claim")
    };
    assert_eq!(recipient, a1, "historic signed destination is immutable");
    let id = chain
        .admit_submission(&mut pool, 1, signed.bytes())
        .unwrap();
    chain.step_submissions(&mut pool);
    assert_eq!(chain.verified_operations(id).len(), 1);
    trading_v1::verify_treasury_direct_credit(chain.state(), &creation, &lock, &claim_wire)
        .unwrap();

    // The other already funded obligation retains its exact refund deadline and sender.
    let trading_v1::NativeLockKind::Hash { refund_height, .. } = original_refund.kind else {
        panic!("hash lock")
    };
    let sender_me = identity_of(&funder);
    let refund = OperationRequest::ConditionalRefund(RefundRequest::new(refund_lock_id));
    assert!(matches!(
        plan(&refund, &chain.view(&none), &sender_me),
        Err(Refusal::NotYetEligible { .. })
    ));
    while chain.height() + 1 < refund_height {
        // Keep the durable complete-object pool pinned to each installed parent.
        chain.step_submissions(&mut pool);
    }
    let view = chain.view(&none);
    let planned = plan(&refund, &view, &sender_me).unwrap();
    let reviewed = review(&planned, &view).unwrap();
    let signed = KeySigner::for_test(wallet_key())
        .unwrap()
        .authorize(planned, kit::approve(&reviewed, &view), &view)
        .unwrap();
    let refund_wire = kit::wire(signed.bytes());
    let trading_v1::Action::Refund { output, owner, .. } = refund_wire.operation.action else {
        panic!("refund")
    };
    assert_eq!(output, refund_lock_id);
    assert_eq!(
        owner, sender,
        "the native refund commits the original sender"
    );
    assert_eq!(
        trading_v1::locked(view.state(), output).unwrap().sender,
        sender
    );
    let refund_id = chain
        .admit_submission(&mut pool, 1, signed.bytes())
        .unwrap();
    chain.step_submissions(&mut pool);
    assert_eq!(
        chain.verified_operations(refund_id)[0].height,
        refund_height
    );

    // Fresh freezes use current maker + current Treasury destination generation.
    let view = chain.view(&none);
    let fresh = kit::treasury_offer_at_generation(
        &next_key,
        2,
        a2,
        context.clone(),
        chain.height(),
        chain.height() + 40,
        70_000,
        3_000,
        3,
        0x54,
    );
    let new_terms = FreezeTerms {
        generation: 2,
        address: a2,
        wallet_descriptor: descriptor_of(&next_key, 2),
        ..terms
    };
    kit::prepare_freeze(&view, &new_terms, &fresh).unwrap();
    let stale = FreezeTerms {
        generation: 1,
        address: a1,
        ..new_terms.clone()
    };
    assert!(kit::prepare_freeze(&view, &stale, &fresh).is_err());
    assert!(
        plan(&r2, &view, &me_now).is_err(),
        "the exact destination is used once"
    );
    // Preserve actual stores, all refused bytes and partials as public TEST-VALUE evidence.
    println!(
        "Treasury canonical evidence retained: {}",
        chain.evidence_directory().display()
    );
}

fn chain_treasury_coin() -> OutPoint {
    point(0xd1)
}

#[test]
fn the_treasury_authority_rotates_under_the_profile_funded_by_another_wallet_and_gating_holds_through_adopt()
 {
    let treasury = treasury_wallet_key();
    let authority = address_of(&treasury, 1);
    let payer_key = wallet_key();
    let payer_address = address_of(&payer_key, 1);
    let new_key = labelled_key("w6-e2e-r1-new-key");
    let mut chain = TreasuryChain::new(
        "w6-e2e-r1",
        1_200_000,
        None,
        &[(0xb1, payer_address, 3_000_000)],
    );
    let none = BTreeSet::new();
    let ordinary = identity_of(&treasury);
    let payer = identity_of(&payer_key);
    let mut outbox = MemoryOutbox::new();

    // An ordinary identity of the Treasury key never rotates the Treasury.
    {
        let view = chain.view(&none);
        assert_eq!(
            plan(
                &wallet_rotation(&new_key, 2, FeeSource::OtherWallet(payer.clone())),
                &view,
                &ordinary
            )
            .unwrap_err(),
            Refusal::TreasuryProfileRequired
        );
    }
    let me = {
        let view = chain.view(&none);
        declared(&treasury, 1, None, &view, true, None)
    };

    // The Treasury signs its part (authorization and possession); the payer signs its funding.
    let (part, context) = {
        let view = chain.view(&none);
        let planned = plan(
            &wallet_rotation(&new_key, 2, FeeSource::OtherWallet(payer.clone())),
            &view,
            &me,
        )
        .unwrap();
        let reviewed = review(&planned, &view).unwrap();
        assert_eq!(reviewed.title(), "Rotate the Treasury wallet key");
        assert!(
            reviewed
                .acknowledgements()
                .contains(&AckKind::TreasuryAuthority)
        );
        let session = RotationSigner::new(
            treasury_wallet_key(),
            me.clone(),
            labelled_key("w6-e2e-r1-new-key"),
            SigningGate::test_value().unwrap(),
            DEFAULT_IDLE_LIMIT,
        )
        .unwrap();
        let part = session
            .authorize(planned, kit::approve(&reviewed, &view), &view)
            .unwrap();
        outbox.commit(&part, &view).unwrap();
        (part, view.context())
    };
    assert!(!part.is_complete());
    let exported = PartialApproval::from_signed(&part, context)
        .unwrap()
        .export()
        .unwrap();
    let funding = {
        let view = chain.view(&none);
        let imported = PartialApproval::import(&exported).unwrap();
        let adopted = imported.adopt_for(&view, &payer).unwrap();
        let reviewed = review(&adopted, &view).unwrap();
        KeySigner::for_test(wallet_key())
            .unwrap()
            .authorize(adopted, kit::approve(&reviewed, &view), &view)
            .unwrap()
    };
    let complete = {
        let view = chain.view(&none);
        combine(&[part.bytes(), funding.bytes()], &view).unwrap()
    };
    outbox
        .replace_partial(&part.id(), &complete, &chain.view(&none))
        .unwrap();
    let transaction = Transaction::decode(complete.bytes()).unwrap();
    chain.admit(&transaction).unwrap();
    let after = chain.step();
    assert_eq!(
        after.wallets.current(authority).unwrap(),
        descriptor_of(&new_key, 2).as_slice(),
        "the new key is the Treasury authority's current key"
    );
    assert!(
        after
            .treasury_owner_set()
            .contains(&address_of(&new_key, 2))
    );
    assert_eq!(
        after.dividends.treasury().unwrap().descriptor(),
        descriptor_of(&treasury, 1).as_slice(),
        "the Genesis Treasury record never changes"
    );
    {
        let confirmations = chain.confirmations();
        let view = chain.view(&none).with_confirmations(&confirmations);
        let report = outbox.reconcile(&view).unwrap();
        assert_eq!(report.confirmed, 1);
        // The old key is stale now, even with the profile.
        assert_eq!(
            profile::standing(&view, &me),
            profile::TreasuryStanding {
                authority: false,
                destinations: Vec::new()
            }
        );
        assert_eq!(
            plan(
                &wallet_rotation(&other_key(), 2, FeeSource::OtherWallet(payer.clone())),
                &view,
                &me
            )
            .unwrap_err(),
            Refusal::StaleAuthority
        );
    }

    // Gating through adopt: an ordinary wallet's rotation that the Treasury would pay for with
    // Treasury coins. The new key, declared for the Treasury authority at generation 2, may pay; an
    // ordinary identity of the same key may not, however the bytes reached it.
    {
        let view = chain.view(&none);
        let treasury_now =
            SignerIdentity::from_public(new_key.public(), 2, Some(authority)).unwrap();
        let profiled_now = declared(&new_key, 2, Some(authority), &view, true, None);
        let rotating = identity_of(&other_key());
        assert_eq!(
            plan(
                &wallet_rotation(
                    &labelled_key("w6-e2e-r1-other-new"),
                    2,
                    FeeSource::OtherWallet(treasury_now.clone())
                ),
                &view,
                &rotating
            )
            .unwrap_err(),
            Refusal::TreasuryProfileRequired,
            "the request names an ordinary Treasury payer"
        );
        let planned = plan(
            &wallet_rotation(
                &labelled_key("w6-e2e-r1-other-new"),
                2,
                FeeSource::OtherWallet(profiled_now.clone()),
            ),
            &view,
            &rotating,
        )
        .unwrap();
        let reviewed = review(&planned, &view).unwrap();
        let part = RotationSigner::for_test(
            other_key(),
            rotating.clone(),
            labelled_key("w6-e2e-r1-other-new"),
        )
        .unwrap()
        .authorize(planned, kit::approve(&reviewed, &view), &view)
        .unwrap();
        assert_eq!(
            adopt(part.bytes(), &view, &treasury_now).unwrap_err(),
            Refusal::TreasuryProfileRequired,
            "an ordinary identity cannot spend Treasury coins, also through adopt()"
        );
        let adopted = adopt(part.bytes(), &view, &profiled_now).unwrap();
        assert!(
            review(&adopted, &view)
                .unwrap()
                .warnings()
                .iter()
                .any(|w| w.code == "TREASURY_FUNDS")
        );
    }
    chain.finish();
}

#[test]
fn the_reserve_rule_holds_end_to_end_for_both_treasury_rotations() {
    let treasury = treasury_wallet_key();
    let a1 = address_of(&treasury, 1);
    let payer_key = wallet_key();
    let payer_address = address_of(&payer_key, 1);
    let outsider = address_of(&other_key(), 1);
    let new_key = labelled_key("w6-e2e-reserve-new-key");
    let a1_new = address_of(&new_key, 2);
    let mut chain = TreasuryChain::new(
        "w6-e2e-reserve",
        1_200_000,
        Some((TRADING_TREASURY, descriptor_of(&treasury, 1))),
        &[(0xc1, payer_address, 3_000_000)],
    );
    let none = BTreeSet::new();
    let award = chain.step_at(AWARD_EPOCH);
    assert_eq!(
        award.dividends.reserved(),
        600_000,
        "half of the backing is reserved"
    );
    let me = {
        let view = chain.view(&none);
        declared(&treasury, 1, None, &view, true, Some(TRADING_TREASURY))
    };
    let signer = signer_for(treasury_wallet_key(), &me);

    // Pay the Treasury down to EXACTLY its reserve (a Treasury payment above the reserve is allowed).
    {
        let view = chain.view(&none);
        // The fee depends on the encoded size only; converge on the amount that leaves exactly
        // 600,000 as change.
        let mut amount = 500_000u64;
        let (planned, reviewed) = loop {
            let planned = plan(
                &OperationRequest::Payment(PaymentRequest::new(outsider, amount)),
                &view,
                &me,
            )
            .unwrap();
            let reviewed = review(&planned, &view).unwrap();
            if reviewed.returned() == 600_000 {
                break (planned, reviewed);
            }
            amount = 1_200_000 - 600_000 - reviewed.fee().atoms;
        };
        assert_eq!(
            reviewed.returned(),
            600_000,
            "the change keeps exactly the reserve"
        );
        let signed = signer
            .authorize(planned, kit::approve(&reviewed, &view), &view)
            .unwrap();
        chain
            .admit(&Transaction::decode(signed.bytes()).unwrap())
            .unwrap();
    }
    let paid = chain.step();
    assert_eq!(
        mutiny_consensus_v8::dividend_state_v1::DividendState::backing(
            &paid.coins,
            &paid.treasury_owner_set()
        )
        .unwrap(),
        600_000
    );
    let reserve_coin = paid
        .coins
        .iter()
        .find(|(_, coin)| coin.output.owner == a1)
        .map(|(point, coin)| (point.clone(), coin.output.atoms))
        .unwrap();
    assert_eq!(reserve_coin.1, 600_000);

    // R1 at exactly the reserve: the Treasury cannot pay its own rotation fee.
    {
        let view = chain.view(&none);
        let refusal = plan(
            &wallet_rotation(&new_key, 2, FeeSource::RotatingAuthority),
            &view,
            &me,
        )
        .unwrap_err();
        assert!(
            matches!(
                refusal,
                Refusal::ReserveBackingViolation {
                    reserved: 600_000,
                    ..
                }
            ),
            "{refusal:?}"
        );
        let fee = 12_000u64;
        use mutiny_consensus_v8::funded_rotation_v2::{
            PartialRotation, Payer, Slot, UnsignedRotation,
        };
        let body = UnsignedRotation {
            genesis: view.anchor().genesis,
            fingerprint: view.anchor().fingerprint,
            envelope: mutiny_consensus_v8::op_envelope_v1::Envelope::from_head(
                view.anchor(),
                10,
                Vec::new(),
            )
            .unwrap(),
            authority: a1,
            current_descriptor: descriptor_of(&treasury, 1),
            proposed_descriptor: descriptor_of(&new_key, 2),
            sponsor: None,
            fee,
            inputs: vec![(reserve_coin.0.clone(), Payer::RotatingAuthority)],
            outputs: vec![mutiny_consensus_v8::transactions::Output {
                owner: a1_new,
                atoms: 600_000 - fee,
            }],
        };
        let mut partial = PartialRotation::new(body);
        partial.sign(Slot::Authorize, &treasury).unwrap();
        partial.sign(Slot::Possession, &new_key).unwrap();
        partial.sign(Slot::AuthorityFunding, &treasury).unwrap();
        let native = partial.complete().unwrap();
        native.verify_signatures().unwrap();
        assert!(fee >= native.encode().unwrap().len() as u64);
        let self_funded = Transaction::FundedRotation(native);
        assert!(
            chain
                .execute_as_block(vec![self_funded.encode().unwrap()])
                .is_err(),
            "block execution refuses a rotation whose own fee leaves the reserve unbacked"
        );
    }

    // Another wallet pays: accepted by the wallet and in a real block.
    {
        let payer = identity_of(&payer_key);
        let view = chain.view(&none);
        let planned = plan(
            &wallet_rotation(&new_key, 2, FeeSource::OtherWallet(payer.clone())),
            &view,
            &me,
        )
        .unwrap();
        let reviewed = review(&planned, &view).unwrap();
        let part = RotationSigner::for_test(
            treasury_wallet_key(),
            me.clone(),
            labelled_key("w6-e2e-reserve-new-key"),
        )
        .unwrap()
        .authorize(planned, kit::approve(&reviewed, &view), &view)
        .unwrap();
        let adopted = adopt(part.bytes(), &view, &payer).unwrap();
        let reviewed = review(&adopted, &view).unwrap();
        let funded = KeySigner::for_test(wallet_key())
            .unwrap()
            .authorize(adopted, kit::approve(&reviewed, &view), &view)
            .unwrap();
        let complete = combine(&[part.bytes(), funded.bytes()], &view).unwrap();
        chain
            .admit(&Transaction::decode(complete.bytes()).unwrap())
            .unwrap();
    }
    let rotated = chain.step();
    assert_eq!(
        rotated.wallets.current(a1).unwrap(),
        descriptor_of(&new_key, 2).as_slice()
    );

    let current_r2 = OperationRequest::TreasuryRotate(
        TreasuryRotateRequest::new(Blob::new(descriptor_of(&new_key, 2))).with_verified_restore(
            TRADING_TREASURY,
            rotation::descriptor_fingerprint(&descriptor_of(&new_key, 2)),
        ),
    );
    let reserve_refused_native = {
        let view = chain.view(&none);
        let me_now = declared(&new_key, 2, Some(a1), &view, true, Some(TRADING_TREASURY));
        assert_eq!(
            view.state().wallets.current(a1).unwrap(),
            descriptor_of(&new_key, 2)
        );
        assert_eq!(view.state().coins[&reserve_coin.0].output.atoms, 600_000);
        assert_eq!(
            mutiny_consensus_v8::dividend_state_v1::DividendState::backing(
                &view.state().coins,
                &view.state().treasury_owner_set()
            )
            .unwrap(),
            600_000
        );
        assert!(matches!(
            plan(&current_r2, &view, &me_now),
            Err(Refusal::ReserveBackingViolation {
                reserved: 600_000,
                ..
            })
        ));
        let next = view.next_height().unwrap();
        let hand = kit::HandRotation {
            reference: view.anchor().clone(),
            treasury: TRADING_TREASURY,
            current_generation: 1,
            current_address: a1,
            current_descriptor: descriptor_of(&new_key, 2),
            new_generation: 2,
            new_address: a1_new,
            new_descriptor: descriptor_of(&new_key, 2),
            inputs: vec![reserve_coin.clone()],
            created: next,
            expiry: next + 10,
        };
        let raw = kit::hand_rotation_in_view(&view, &hand, &new_key, 2);
        // Crypto, current authority and routing destination are all genuine; the reserve is causal.
        let native = kit::wire(&raw);
        assert_eq!(
            native.operation.approvals[0].descriptor,
            descriptor_of(&new_key, 2)
        );
        assert_eq!(
            kit::consensus_in(&view, &raw),
            Err(trading_v1::NativeError::Record)
        );
        let rows = chain.canonical_rows();
        let root = view.state_root();
        let anchor = view.anchor().clone();
        assert!(chain.try_step_with(&[raw.clone()]).is_err());
        assert_eq!(chain.canonical_rows(), rows);
        assert_eq!(chain.state().root().unwrap(), root);
        assert_eq!(chain.anchor(), anchor);
        std::fs::write(
            chain
                .evidence_directory()
                .join("reserve-refused-current2-r2.bin"),
            &raw,
        )
        .unwrap();
        raw
    };

    // The reserve backing counts the NEW address: another wallet pays 50,000 to it, and the Treasury
    // (now the new key at generation 2) may spend exactly that excess, but not the reserve coin.
    {
        let view = chain.view(&none);
        let planned = plan(
            &OperationRequest::Payment(PaymentRequest::new(a1_new, 50_000)),
            &view,
            &identity_of(&payer_key),
        )
        .unwrap();
        let reviewed = review(&planned, &view).unwrap();
        let signed = KeySigner::for_test(wallet_key())
            .unwrap()
            .authorize(planned, kit::approve(&reviewed, &view), &view)
            .unwrap();
        chain
            .admit(&Transaction::decode(signed.bytes()).unwrap())
            .unwrap();
    }
    let topped = chain.step();
    assert_eq!(
        mutiny_consensus_v8::dividend_state_v1::DividendState::backing(
            &topped.coins,
            &topped.treasury_owner_set()
        )
        .unwrap(),
        650_000,
        "consensus counts the new address as Treasury backing"
    );
    let excess_coin = topped
        .coins
        .iter()
        .find(|(_, coin)| coin.output.owner == a1_new)
        .map(|(point, coin)| (point.clone(), coin.output.atoms))
        .unwrap();
    {
        let view = chain.view(&none);
        let me_now = declared(&new_key, 2, Some(a1), &view, true, Some(TRADING_TREASURY));
        // Spending the reserve coin is refused by the wallet and by block execution.
        let below = chain.hand_signed_transfer(
            &new_key,
            2,
            reserve_coin.0.clone(),
            12_000,
            &[(outsider, 600_000 - 12_000)],
        );
        assert!(
            matches!(
                explain(&unsigned_transfer(&below), &view, &me_now).unwrap_err(),
                Refusal::ReserveBackingViolation { .. }
            ),
            "the wallet refuses a spend below the reserve"
        );
        assert!(
            chain
                .execute_as_block(vec![below.encode().unwrap()])
                .is_err()
        );
        // Spending the excess at the new address is accepted by both.
        let within = chain.hand_signed_transfer(
            &new_key,
            2,
            excess_coin.0.clone(),
            12_000,
            &[(outsider, 50_000 - 12_000)],
        );
        let view = chain.view(&none);
        assert!(explain(&unsigned_transfer(&within), &view, &me_now).is_ok());
        assert!(
            chain
                .execute_as_block(vec![within.encode().unwrap()])
                .is_ok()
        );
        {
            let view = chain.view(&none);
            let history = chain.operation_history(&reserve_refused_native);
            trading_v1::prepare_batch_with_history(
                view.state(),
                view.anchor(),
                view.state_root(),
                &history,
                &[reserve_refused_native.clone()],
                &policy(),
            )
            .unwrap();
            let me_now = declared(&new_key, 2, Some(a1), &view, true, Some(TRADING_TREASURY));
            assert_eq!(
                plan(&current_r2, &view, &me).unwrap_err(),
                Refusal::StaleAuthority
            );
            let planned = plan(&current_r2, &view, &me_now).unwrap();
            let reviewed = review(&planned, &view).unwrap();
            let fee = reviewed.fee().atoms;
            assert!(fee > 0 && fee <= 50_000);
            assert!(planned.inputs().contains(&reserve_coin.0));
            assert!(
                condition(&reviewed, "Dividend reserve")
                    .contains(&units::format_mut_wide(u128::from(650_000 - fee)))
            );
            assert!(
                reviewed
                    .warnings()
                    .iter()
                    .any(|w| w.code == "TREASURY_FUNDS")
            );
            let signed = signer_for(labelled_key("w6-e2e-reserve-new-key"), &me_now)
                .authorize(planned, kit::approve(&reviewed, &view), &view)
                .unwrap();
            kit::consensus_in(&view, signed.bytes()).unwrap();
            let mut outbox = MemoryOutbox::new();
            outbox.commit(&signed, &view).unwrap();
            let mut pool = chain.submission_pool();
            let id = chain
                .admit_submission(&mut pool, 1, signed.bytes())
                .unwrap();
            let after = chain.step_submissions(&mut pool);
            assert_eq!(
                mutiny_consensus_v8::dividend_state_v1::DividendState::backing(
                    &after.coins,
                    &after.treasury_owner_set()
                )
                .unwrap(),
                650_000 - fee
            );
            let active = trading_v1::treasury_current(
                &after,
                &kit::context_of(&chain.anchor()),
                TRADING_TREASURY,
            )
            .unwrap();
            assert_eq!((active.generation, active.address), (2, a1_new));
            let confirmations = chain.confirmations();
            assert_eq!(
                outbox
                    .reconcile(&chain.view(&none).with_confirmations(&confirmations))
                    .unwrap()
                    .confirmed,
                1
            );
            assert_eq!(chain.verified_operations(id).len(), 1);
        }
    }
    println!(
        "Reserve canonical evidence retained: {}",
        chain.evidence_directory().display()
    );
}

/// The unsigned form of a one-input transfer (the payment handler adopts and explains unsigned or
/// signed transfers alike; explain is used here for the reserve check only).
fn unsigned_transfer(transaction: &Transaction) -> Vec<u8> {
    let Transaction::Transfer(transfer) = transaction else {
        panic!("this fixture requires an ordinary Transfer")
    };
    let mut transfer = transfer.clone();
    for input in &mut transfer.inputs {
        input.signature = kit::zero();
    }
    transfer.encode().unwrap()
}

#[test]
fn the_profile_declaration_is_checked_against_the_real_chain() {
    let treasury = treasury_wallet_key();
    let mut chain = TreasuryChain::new(
        "w6-e2e-declare",
        1_200_000,
        Some((TRADING_TREASURY, descriptor_of(&treasury, 1))),
        &[],
    );
    chain.step();
    let none = BTreeSet::new();
    let view = chain.view(&none);
    let genesis = view.context().genesis;
    let base = TreasuryDeclaration::new(genesis, ChainClass::TestValue);
    let identity = identity_of(&treasury);
    // Both roles hold.
    let declared = profile::declare(
        identity.clone(),
        &base
            .clone()
            .with_authority()
            .with_destination_of(TRADING_TREASURY),
        &view,
    )
    .unwrap();
    assert_eq!(declared.profile(), WalletProfile::Treasury);
    // The declared class must be the chain's.
    assert_eq!(
        profile::declare(
            identity.clone(),
            &TreasuryDeclaration::new(genesis, ChainClass::Production).with_authority(),
            &view
        )
        .unwrap_err(),
        Refusal::ChainClassMismatch {
            gate: ChainClass::Production,
            chain: ChainClass::TestValue
        }
    );
    assert_eq!(
        profile::declare(
            identity.clone(),
            &TreasuryDeclaration::new(genesis, ChainClass::Undeclared).with_authority(),
            &view
        )
        .unwrap_err(),
        Refusal::TreasuryClassUndeclared
    );
    // Another chain, no role, another key, another Treasury.
    assert_eq!(
        profile::declare(
            identity.clone(),
            &TreasuryDeclaration::new([0x66; 32], ChainClass::TestValue).with_authority(),
            &view
        )
        .unwrap_err(),
        Refusal::WrongContext(ContextField::Genesis)
    );
    assert_eq!(
        profile::declare(identity.clone(), &base, &view).unwrap_err(),
        Refusal::InvalidRequest(profile::REASON_NO_ROLE)
    );
    let stranger = identity_of(&wallet_key());
    assert_eq!(
        profile::declare(stranger.clone(), &base.clone().with_authority(), &view).unwrap_err(),
        Refusal::NotRequiredSigner(Slot::RotationAuthorization)
    );
    assert_eq!(
        profile::declare(
            stranger,
            &base.clone().with_destination_of(TRADING_TREASURY),
            &view
        )
        .unwrap_err(),
        Refusal::NotRequiredSigner(Slot::Approval(0))
    );
    assert_eq!(
        profile::declare(identity, &base.with_destination_of([0x91; 32]), &view).unwrap_err(),
        Refusal::InvalidRequest(treasury::REASON_NO_TRADING_TREASURY)
    );
    chain.finish();
}
