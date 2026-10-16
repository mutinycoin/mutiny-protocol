//! Dividend claims end to end on a REAL consensus chain (NATIVE, TEST-VALUE): discovery, plan,
//! review, typed acknowledgements, approval, authorization, independent verification through
//! consensus code (`SignedClaim::verify_signature`, `dividend_claim_v1::admit`), the durable outbox
//! across a restart, blocks built by the production assembler and certified with real hybrid
//! votes, installed by the canonical store, and outbox reconciliation. The award is reached by
//! stepping blocks to the award epoch; the consensus `dividend-test-fixtures` feature is not used.
#[path = "support/dividend_chain.rs"]
mod dividend_chain;
#[path = "support/flow.rs"]
mod flow;
#[path = "support/tempdir.rs"]
mod tempdir;

use dividend_chain::chain::*;
use mutiny_consensus_v8::{
    NETWORK_ID,
    dividend_claim_v1::{ClaimError, SignedClaim},
    transactions::OutPoint,
};
use mutiny_wallet_core_v8::{
    discovery::{
        dividends::{self as entitlements, Claimability},
        licenses,
    },
    *,
};
use std::collections::BTreeSet;

fn claim(license: [u8; 32], amount: u64, destination: [u8; 32]) -> OperationRequest {
    OperationRequest::DividendClaim(DividendClaimRequest::new(
        license,
        AWARD,
        amount,
        destination,
    ))
}

fn rows_text(review: &Review) -> String {
    review.render_text()
}

/// The consensus outcome as one short name, e.g. `Dividend(Replay)`.
fn outcome(result: &Result<(), ClaimError>) -> String {
    match result {
        Ok(()) => "Ok".to_string(),
        Err(error) => format!("{error:?}"),
    }
}

/// The wallet refusal codes that agree with a consensus outcome (see `support/dividend_world.rs`
/// for the full table; this test only meets the cases below).
fn agrees(consensus: &str, wallet: &str) -> bool {
    let codes: &[&str] = match consensus {
        "Context" => &["WRONG_CONTEXT"],
        "Window" => &["INVALID_VALIDITY", "WINDOW_NOT_OPEN", "WINDOW_CLOSED"],
        "UnknownLicense" => &["NOT_ENTITLED"],
        "Dividend(ZeroAmount)" => &["INVALID_AMOUNT"],
        "Dividend(UnknownAward)" => &["NOT_ENTITLED", "AWARD_EXPIRED", "AWARD_NOT_YET_OPEN"],
        "Dividend(Replay)" | "Duplicate" => &["REPLAY"],
        "Dividend(Sequence)" => &["WRONG_SEQUENCE"],
        "Dividend(Overdrawn)" => &["OVERDRAWN"],
        "StaleOwner" => &["STALE_AUTHORITY", "NOT_REQUIRED_SIGNER"],
        "Signature" => &["VERIFICATION_FAILED"],
        _ => &[],
    };
    codes.contains(&wallet)
}

#[test]
fn partial_claims_n_then_n_plus_1_through_real_blocks_survive_a_restart() {
    let me = identity_of(&owner());
    let signer = KeySigner::for_test(owner()).unwrap();
    let mut chain = ClaimChain::new("p3-e2e-partial", &[]);
    let none = BTreeSet::new();

    // Block 1 in the award epoch: the boundary reserves half of the Treasury, 50,000 atoms for each
    // of the twelve Genesis Licenses.
    let first_block = chain.step(AWARD, &[]);
    assert_eq!(first_block.dividends.reserved(), 600_000);

    // Discovery reads the verified state: twelve Licenses, each with an untouched account.
    let license = license_id(3);
    {
        let view = chain.view(&none);
        assert_eq!(licenses::controlled(view.state(), me.descriptor()).len(), 12);
        let all = entitlements::entitlements(&view, me.descriptor());
        assert_eq!(all.len(), 12);
        let mine = entitlements::entitlement(&view, AWARD, license).unwrap();
        assert_eq!(
            (mine.share, mine.remaining, mine.claims, mine.next_sequence),
            (SHARE, SHARE, 0, 0)
        );
        assert_eq!(mine.claimability, Claimability::Claimable);
        assert_eq!(mine.last_epoch, AWARD + WINDOW - 1);
        assert_eq!(mine.epochs_left_at_most, WINDOW);
        let info = licenses::license(view.state(), license).unwrap();
        assert_eq!(
            (info.index, info.generation, info.dividend_activation_epoch),
            (3, Some(1), Some(0))
        );
        assert_eq!(info.standing, licenses::Standing::Active);
    }

    // Claim n = 0: a partial claim of 3,000 atoms to another wallet's address.
    let destination = address_of(&buyer(), 1);
    let first = {
        let view = chain.view(&none);
        let planned = plan(&claim(license, 3_000, destination), &view, &me).unwrap();
        assert_eq!(planned.kind(), OperationKind::DividendClaim);
        assert_eq!(
            planned.inputs(),
            std::slice::from_ref(&entitlements::claim_slot(AWARD, &license))
        );
        assert_eq!(planned.validity().created, 2);
        assert_eq!(planned.validity().expiry, 2 + DEFAULT_VALIDITY_BLOCKS);
        let reviewed = review(&planned, &view).unwrap();
        assert_eq!(reviewed.amount(), Some(3_000));
        assert_eq!(
            (reviewed.fee().atoms, reviewed.fee().rule, reviewed.fee().payer),
            (0, FeeRule::Exempt, FeePayer::Protocol)
        );
        assert_eq!(reviewed.net_debit(), Some(0));
        let paid = &reviewed.destinations()[0];
        assert_eq!(
            (paid.role, paid.address, paid.label, paid.atoms),
            (
                DestinationRole::ProtocolPayout,
                destination,
                AddressLabel::External,
                3_000
            )
        );
        assert_eq!(reviewed.destinations_needing_check(), vec![0]);
        assert_eq!(reviewed.timing().deadline_epoch, Some(AWARD + WINDOW - 1));
        let text = rows_text(&reviewed);
        assert!(text.contains("This claim carries sequence 0"), "{text}");
        assert!(text.contains("Remaining before this claim: 0.00050000 MUT"), "{text}");
        assert!(text.contains("After it: 0.00047000 MUT"), "{text}");
        assert!(text.contains("TEST-VALUE chain"));
        assert_eq!(
            reviewed.acknowledgements(),
            &[
                AckKind::Destination,
                AckKind::Amount,
                AckKind::Conditions,
                AckKind::Irreversible
            ]
        );
        flow::sign(planned, &signer, &view).unwrap()
    };
    assert!(first.is_complete());

    // Independent verification through consensus code.
    let decoded = SignedClaim::decode(first.bytes()).unwrap();
    decoded.verify_signature().unwrap();
    assert_eq!(decoded.id(), first.id());
    assert_eq!(
        (decoded.body.sequence, decoded.body.amount, decoded.body.destination),
        (0, 3_000, destination)
    );
    let head_epoch = chain.view(&none).epoch().unwrap();
    assert_eq!(head_epoch, AWARD);
    chain
        .admit(first.bytes(), head_epoch)
        .expect("consensus admits the wallet's claim");

    // Durable outbox in a test-owned directory; the claim reserves its (award, License) slot.
    let dir = tempdir::TempDir::new("p3-claim-outbox");
    let path = dir.file("outbox.sqlite");
    let context = chain.view(&none).context();
    {
        let mut outbox = SqliteOutbox::open(&path, context).unwrap();
        let view = chain.view(&none);
        assert_eq!(outbox.commit(&first, &view).unwrap(), first.id());
        let reserved = outbox.reserved().unwrap();
        assert_eq!(
            reserved,
            BTreeSet::from([entitlements::claim_slot(AWARD, &license)])
        );
        // One outstanding claim per (award, License): a second plan for the pair is refused, and
        // discovery says why; another License is unaffected.
        let view = chain.view(&reserved);
        assert_eq!(
            plan(&claim(license, 1_000, destination), &view, &me).unwrap_err(),
            Refusal::ReservedInput
        );
        assert_eq!(
            entitlements::entitlement(&view, AWARD, license)
                .unwrap()
                .claimability,
            Claimability::Outstanding
        );
        assert!(plan(&claim(license_id(4), 1_000, destination), &view, &me).is_ok());
    }

    // Restart: the canonical store and the outbox are closed and reopened.
    let mut chain = chain.restart();
    let queued = {
        let outbox = SqliteOutbox::open(&path, context).unwrap();
        let pending = outbox.pending().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].bytes, first.bytes(), "the exact signed bytes survive");
        assert_eq!(pending[0].kind, OperationKind::DividendClaim);
        pending[0].bytes.clone()
    };
    // The claim is still valid after the restart, at the next block.
    chain
        .admit(&queued, chain.view(&none).epoch().unwrap())
        .unwrap();

    // Block 2 includes the claim from the reopened outbox.
    let second_block = chain.step(AWARD + 1, &[queued]);
    let account = second_block
        .dividends
        .ledger()
        .award(AWARD)
        .unwrap()
        .account(&license)
        .unwrap();
    assert_eq!((account.remaining, account.claims), (47_000, 1));
    let payout = second_block
        .coins
        .get(&OutPoint {
            transaction: first.id(),
            index: 0,
        })
        .expect("the payout coin (claim id, 0)");
    assert_eq!(
        (payout.output.owner, payout.output.atoms, payout.coinbase),
        (destination, 3_000, false)
    );
    assert_eq!(second_block.dividends.reserved(), 597_000);
    let reward: u64 = second_block
        .coins
        .values()
        .filter(|c| c.coinbase && c.created_height == 2)
        .map(|c| c.output.atoms)
        .sum();
    assert_eq!(reward, 100_000_000, "the claim is fee-exempt: no fee reached the block");

    // Reconciliation from verified state: confirmed, reservation released.
    {
        let mut outbox = SqliteOutbox::open(&path, context).unwrap();
        let view = chain.view(&none);
        let report = outbox.reconcile(&view).unwrap();
        assert_eq!((report.confirmed, report.still_pending), (1, 0));
        assert_eq!(
            outbox.get(&first.id()).unwrap().unwrap().status,
            OutboxStatus::Confirmed(2)
        );
        assert!(outbox.reserved().unwrap().is_empty());
    }

    // Claim n + 1: the sequence is read from confirmed state.
    let own = address_of(&owner(), 1);
    let second = {
        let view = chain.view(&none);
        let mine = entitlements::entitlement(&view, AWARD, license).unwrap();
        assert_eq!((mine.remaining, mine.next_sequence), (47_000, 1));
        let planned = plan(&OperationRequest::DividendClaim(mine.request(1_000, own)), &view, &me).unwrap();
        let reviewed = review(&planned, &view).unwrap();
        assert!(rows_text(&reviewed).contains("This claim carries sequence 1"));
        assert!(
            reviewed.destinations_needing_check().is_empty(),
            "the wallet's own address needs no typed check"
        );
        flow::sign(planned, &signer, &view).unwrap()
    };
    let epoch = chain.view(&none).epoch().unwrap();
    assert_eq!(SignedClaim::decode(second.bytes()).unwrap().body.sequence, 1);
    chain.admit(second.bytes(), epoch).unwrap();

    // The first claim again is a replay for both the wallet and consensus, in a block too.
    {
        let view = chain.view(&none);
        assert_eq!(
            SignedOperation::import(first.bytes(), &view).unwrap_err(),
            Refusal::Replay
        );
        let mut outbox = MemoryOutbox::new();
        assert_eq!(
            outbox.commit(&first, &view).unwrap_err(),
            Refusal::Replay
        );
        assert!(outbox.records().unwrap().is_empty());
    }
    assert_eq!(
        chain.admit(first.bytes(), epoch).unwrap_err(),
        ClaimError::Dividend(mutiny_consensus_v8::dividends_v1::DivError::Replay)
    );
    let refused = chain
        .try_step(AWARD + 2, &[first.bytes().to_vec()])
        .unwrap_err();
    assert!(refused.contains("Replay"), "{refused}");

    // Block 3 includes claim n + 1.
    let third_block = chain.step(AWARD + 2, &[second.bytes().to_vec()]);
    let account = third_block
        .dividends
        .ledger()
        .award(AWARD)
        .unwrap()
        .account(&license)
        .unwrap();
    assert_eq!((account.remaining, account.claims), (46_000, 2));
    assert_eq!(third_block.dividends.reserved(), 596_000);
    chain.finish();
}

#[test]
fn a_license_sold_by_dvp_makes_the_sellers_claim_stale_for_the_wallet_and_for_consensus() {
    let seller_me = identity_of(&owner());
    let seller = KeySigner::for_test(owner()).unwrap();
    let buyer_address = address_of(&buyer(), 1);
    let mut chain = ClaimChain::new("p3-e2e-dvp", &[(0xb7, buyer_address, 100_000)]);
    let none = BTreeSet::new();
    chain.step(AWARD, &[]);
    let license = license_id(3);

    // The seller signs a claim while it still owns the License: valid when signed.
    let stale = {
        let view = chain.view(&none);
        let planned = plan(
            &claim(license, 3_000, address_of(&owner(), 1)),
            &view,
            &seller_me,
        )
        .unwrap();
        let text = review(&planned, &view).unwrap().render_text();
        assert!(
            text.contains("If the License is sold first, including by a sale in the same block"),
            "the stale-owner risk is on screen: {text}"
        );
        flow::sign(planned, &seller, &view).unwrap()
    };
    chain.admit(stale.bytes(), AWARD).unwrap();

    // The License DvP, valid only in block 2.
    let trade = chain.license_dvp(
        &owner(),
        &buyer(),
        license,
        outpoint(0xb7),
        50_000,
        30_000,
        20_000,
    );
    // Consensus refuses a block with the sale AND the seller's claim, whatever the listing order:
    // the sale executes first, so the claim sees the buyer as owner.
    for operations in [
        vec![trade.clone(), stale.bytes().to_vec()],
        vec![stale.bytes().to_vec(), trade.clone()],
    ] {
        let refused = chain.try_step(AWARD + 1, &operations).unwrap_err();
        assert!(refused.contains("StaleOwner"), "{refused}");
        assert_eq!(chain.height(), 1, "nothing was installed");
    }
    // The sale alone is accepted.
    let sold = chain.step(AWARD + 1, &[trade]);
    assert_eq!(sold.licenses_v2.license(license).unwrap().owner, buyer_address);

    let view = chain.view(&none);
    let epoch = view.epoch().unwrap();
    // The wallet refuses the seller's signed claim at the new head and never queues it ...
    assert_eq!(
        SignedOperation::import(stale.bytes(), &view).unwrap_err(),
        Refusal::NotRequiredSigner(Slot::Claim)
    );
    let mut outbox = MemoryOutbox::new();
    assert_eq!(
        outbox.commit(&stale, &view).unwrap_err(),
        Refusal::NotRequiredSigner(Slot::Claim)
    );
    assert!(outbox.records().unwrap().is_empty());
    // ... and consensus refuses it with StaleOwner, also in a block.
    assert_eq!(
        chain.admit(stale.bytes(), epoch).unwrap_err(),
        ClaimError::StaleOwner
    );
    // A new plan by the seller is refused; discovery moves the License to the buyer and records
    // the new License generation.
    assert_eq!(
        plan(
            &claim(license, 1_000, address_of(&owner(), 1)),
            &view,
            &seller_me
        )
        .unwrap_err(),
        Refusal::NotRequiredSigner(Slot::Claim)
    );
    assert!(
        !licenses::controlled(view.state(), seller_me.descriptor())
            .iter()
            .any(|info| info.id == license)
    );
    let buyer_me = identity_of(&buyer());
    let bought = licenses::controlled(view.state(), buyer_me.descriptor());
    assert_eq!(bought.len(), 1);
    assert_eq!((bought[0].id, bought[0].generation), (license, Some(2)));

    // The buyer claims the whole untouched entitlement with sequence 0.
    let buyer_signer = KeySigner::for_test(buyer()).unwrap();
    let mine = entitlements::entitlement(&view, AWARD, license).unwrap();
    assert_eq!((mine.remaining, mine.next_sequence), (SHARE, 0));
    let planned = plan(&OperationRequest::DividendClaim(mine.request_all(buyer_address)), &view, &buyer_me).unwrap();
    let reviewed = review(&planned, &view).unwrap();
    assert!(reviewed.warnings().iter().any(|w| w.code == "FULL_CLAIM"));
    let bought_claim = flow::sign(planned, &buyer_signer, &view).unwrap();
    chain.admit(bought_claim.bytes(), epoch).unwrap();
    let refused = chain
        .try_step(AWARD + 2, &[stale.bytes().to_vec()])
        .unwrap_err();
    assert!(refused.contains("StaleOwner"), "{refused}");
    let state = chain.step(AWARD + 2, &[bought_claim.bytes().to_vec()]);
    let account = state
        .dividends
        .ledger()
        .award(AWARD)
        .unwrap()
        .account(&license)
        .unwrap();
    assert_eq!((account.remaining, account.claims), (0, 1));
    assert_eq!(
        state
            .coins
            .get(&OutPoint {
                transaction: bought_claim.id(),
                index: 0
            })
            .map(|coin| (coin.output.owner, coin.output.atoms)),
        Some((buyer_address, SHARE))
    );
    chain.finish();
}

#[test]
fn the_end_of_the_award_window_is_judged_at_the_including_blocks_epoch() {
    let me = identity_of(&owner());
    let signer = KeySigner::for_test(owner()).unwrap();
    let mut chain = ClaimChain::new("p3-e2e-window", &[]);
    let none = BTreeSet::new();
    chain.step(AWARD, &[]);
    let own = address_of(&owner(), 1);

    // Claim A is planned in the award epoch and queued.
    let mut outbox = MemoryOutbox::new();
    let early = {
        let view = chain.view(&none);
        let planned = plan(&claim(license_id(5), 2_000, own), &view, &me).unwrap();
        let signed = flow::sign(planned, &signer, &view).unwrap();
        outbox.commit(&signed, &view).unwrap();
        signed
    };
    // It is included by a block in the LAST epoch of the window.
    chain.step(AWARD + WINDOW - 1, &[early.bytes().to_vec()]);
    {
        let view = chain.view(&none);
        assert_eq!(outbox.reconcile(&view).unwrap().confirmed, 1);
    }

    // Claim B is planned at that head: the review warns that the window is about to close.
    let late = {
        let view = chain.view(&none);
        assert_eq!(view.epoch().unwrap(), AWARD + WINDOW - 1);
        let planned = plan(&claim(license_id(6), 2_000, own), &view, &me).unwrap();
        let reviewed = review(&planned, &view).unwrap();
        let warning = reviewed
            .warnings()
            .iter()
            .find(|w| w.code == "CLAIM_WINDOW_CLOSING")
            .expect("near the window edge");
        assert_eq!(warning.requires, Some(AckKind::Conditions));
        // Since W20 the row names the verified epoch next to the deadline.
        assert!(
            reviewed.render_text().contains(&format!(
                "At most 1 epochs after the verified block's epoch ({}) remain",
                AWARD + WINDOW - 1
            )),
            "{}",
            reviewed.render_text()
        );
        let signed = flow::sign(planned, &signer, &view).unwrap();
        outbox.commit(&signed, &view).unwrap();
        signed
    };

    // The next block's epoch reaches the end of the window: boundary processing removes the award
    // before any claim runs, so claim B can no longer be included.
    let refused = chain
        .try_step(AWARD + WINDOW, &[late.bytes().to_vec()])
        .unwrap_err();
    assert!(refused.contains("UnknownAward"), "{refused}");
    let state = chain.step(AWARD + WINDOW, &[]);
    assert!(state.dividends.ledger().award(AWARD).is_none());
    assert_eq!(state.dividends.reserved(), 0);

    let view = chain.view(&none);
    let epoch = view.epoch().unwrap();
    // The wallet refuses a new claim as expired; consensus agrees (the award no longer exists).
    let refusal = plan(&claim(license_id(7), 2_000, own), &view, &me).unwrap_err();
    assert_eq!(refusal, Refusal::AwardExpired);
    let hand = chain.hand_claim(&owner(), 1, license_id(7), AWARD, 2_000, 0, own);
    let consensus = outcome(&chain.admit(&hand, epoch));
    assert_eq!(consensus, "Dividend(UnknownAward)");
    assert!(agrees(&consensus, refusal.code()));
    // Claim B settles as expired and releases its slot; claim A stays confirmed.
    let report = outbox.reconcile(&view).unwrap();
    assert_eq!(report.expired, 1);
    assert_eq!(
        outbox.get(&late.id()).unwrap().unwrap().status,
        OutboxStatus::Expired
    );
    assert!(matches!(
        outbox.get(&early.id()).unwrap().unwrap().status,
        OutboxStatus::Confirmed(_)
    ));
    assert!(outbox.reserved().unwrap().is_empty());
    chain.finish();
}

#[test]
fn every_case_gets_the_same_verdict_from_the_wallet_and_from_consensus() {
    let me = identity_of(&owner());
    let signer = KeySigner::for_test(owner()).unwrap();
    let mut chain = ClaimChain::new("p3-e2e-parity", &[]);
    let none = BTreeSet::new();
    chain.step(AWARD, &[]);
    let license = license_id(3);
    let own = address_of(&owner(), 1);
    // One applied claim: the account holds 47,000 with one claim.
    let applied = {
        let view = chain.view(&none);
        let planned = plan(&claim(license, 3_000, own), &view, &me).unwrap();
        flow::sign(planned, &signer, &view).unwrap()
    };
    chain.step(AWARD + 1, &[applied.bytes().to_vec()]);

    let view = chain.view(&none);
    let epoch = view.epoch().unwrap();
    let base = chain.claim_body(license, AWARD, 1_000, 1, own);
    let owner_key = owner();
    let with = |edit: &dyn Fn(&mut mutiny_consensus_v8::dividend_claim_v1::ClaimBody)| {
        let mut body = base.clone();
        edit(&mut body);
        sign_claim(body, &owner_key, 1)
    };
    let mut bad_signature = sign_claim(base.clone(), &owner_key, 1);
    let at = bad_signature.len() - 7;
    bad_signature[at] ^= 0x10;
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("valid next claim", with(&|_| {})),
        ("valid exact remainder", with(&|b| b.amount = 47_000)),
        ("replay of sequence 0", with(&|b| b.sequence = 0)),
        ("sequence ahead", with(&|b| b.sequence = 2)),
        ("over-claim", with(&|b| b.amount = 47_001)),
        ("zero amount", with(&|b| b.amount = 0)),
        ("future award", with(&|b| b.award_epoch = 2 * AWARD)),
        ("not an award epoch", with(&|b| b.award_epoch = AWARD + 1)),
        ("unknown License", with(&|b| b.license = [0x55; 32])),
        ("wrong network", with(&|b| b.network = NETWORK_ID ^ 1)),
        ("wrong genesis", with(&|b| b.genesis[0] ^= 1)),
        ("wrong fingerprint", with(&|b| b.fingerprint[0] ^= 1)),
        ("window over 10,080", with(&|b| b.expiry_height = 10_082)),
        ("window not open", with(&|b| b.created_height = 50)),
        ("window closed", with(&|b| {
            b.created_height = 1;
            b.expiry_height = 2;
        })),
        (
            "another wallet's key",
            sign_claim(base.clone(), &buyer(), 1),
        ),
        ("bad signature", bad_signature),
    ];
    let mut agreed = 0;
    for (name, raw) in &cases {
        let consensus = outcome(&chain.admit(raw, epoch));
        let wallet = SignedOperation::import(raw, &view);
        match &wallet {
            Ok(signed) => {
                assert_eq!(consensus, "Ok", "{name}: the wallet accepts what consensus refuses");
                assert_eq!(signed.kind(), OperationKind::DividendClaim);
            }
            Err(refusal) => {
                assert_ne!(consensus, "Ok", "{name}: the wallet refuses what consensus accepts");
                assert!(
                    agrees(&consensus, refusal.code()),
                    "{name}: wallet {} vs consensus {consensus}",
                    refusal.code()
                );
                // Nothing refused can be queued, even with metadata that matches the bytes.
                let decoded = SignedClaim::decode(raw).unwrap();
                let forged = SignedOperation::Complete {
                    kind: OperationKind::DividendClaim,
                    id: decoded.id(),
                    bytes: raw.clone(),
                    validity: Validity {
                        created: decoded.body.created_height,
                        expiry: decoded.body.expiry_height,
                        valid_only_at: None,
                        bound_to_parent: false,
                    },
                    reserved: vec![entitlements::claim_slot(
                        decoded.body.award_epoch,
                        &decoded.body.license,
                    )],
                };
                let mut outbox = MemoryOutbox::new();
                assert!(outbox.commit(&forged, &view).is_err(), "{name}");
                assert!(outbox.records().unwrap().is_empty(), "{name}");
            }
        }
        agreed += 1;
    }
    assert_eq!(agreed, cases.len());
    // The two valid cases really are valid in a block (one at a time: they share sequence 1).
    chain.step(AWARD + 2, &[cases[0].1.clone()]);
    chain.finish();
}

#[test]
fn after_a_real_rotation_the_old_key_is_stale_and_the_new_key_claims_under_the_old_address() {
    let old_me = identity_of(&owner());
    let old_signer = KeySigner::for_test(owner()).unwrap();
    let payer_address = address_of(&buyer(), 1);
    let mut chain = ClaimChain::new("p3-e2e-rotation", &[(0xc1, payer_address, 40_000)]);
    let none = BTreeSet::new();
    chain.step(AWARD, &[]);
    let license = license_id(4);
    let authority = address_of(&owner(), 1);

    // A claim signed by the generation-one key before the rotation.
    let before = {
        let view = chain.view(&none);
        let planned = plan(&claim(license, 2_000, authority), &view, &old_me).unwrap();
        flow::sign(planned, &old_signer, &view).unwrap()
    };
    chain.admit(before.bytes(), AWARD).unwrap();

    // The owner authority rotates to a new key in a real block; another wallet pays the fee.
    let rotate = chain.rotation(&owner(), &rotated(), &buyer(), outpoint(0xc1), 40_000, 39_000);
    chain.admit_transaction(&rotate).expect("the mempool admits the rotation");
    let rotated_state = chain.step(AWARD + 1, &[]);
    assert_eq!(
        rotated_state.wallets.current(authority),
        Some(descriptor_of(&rotated(), 2).as_slice()),
        "the new key is the authority's current key"
    );

    let view = chain.view(&none);
    let epoch = view.epoch().unwrap();
    // The old key: stale for the wallet (plan, import, outbox) and for consensus (also in a block).
    assert_eq!(
        plan(&claim(license, 1_000, authority), &view, &old_me).unwrap_err(),
        Refusal::StaleAuthority
    );
    assert_eq!(
        SignedOperation::import(before.bytes(), &view).unwrap_err(),
        Refusal::StaleAuthority
    );
    let mut outbox = MemoryOutbox::new();
    assert_eq!(
        outbox.commit(&before, &view).unwrap_err(),
        Refusal::StaleAuthority
    );
    assert!(outbox.records().unwrap().is_empty());
    assert_eq!(
        chain.admit(before.bytes(), epoch).unwrap_err(),
        ClaimError::StaleOwner
    );
    assert!(licenses::controlled(view.state(), old_me.descriptor()).is_empty());

    // The new key controls every License recorded under the OLD generation-one address.
    let new_me = SignerIdentity::new(&descriptor_of(&rotated(), 2), Some(authority)).unwrap();
    let controlled = licenses::controlled(view.state(), new_me.descriptor());
    assert_eq!(controlled.len(), 12);
    assert!(controlled.iter().all(|info| info.owner == authority));
    let mine = entitlements::entitlement(&view, AWARD, license).unwrap();
    assert_eq!((mine.remaining, mine.next_sequence), (SHARE, 0));
    let new_signer = KeySigner::with_identity(
        rotated(),
        new_me.clone(),
        SigningGate::test_value().unwrap(),
        DEFAULT_IDLE_LIMIT,
    )
    .unwrap();
    let planned = plan(
        &OperationRequest::DividendClaim(mine.request(2_000, new_me.address())),
        &view,
        &new_me,
    )
    .unwrap();
    let reviewed = review(&planned, &view).unwrap();
    assert!(
        reviewed
            .warnings()
            .iter()
            .any(|w| w.code == "DESTINATION_NOT_OWNER" && w.severity == Severity::Notice),
        "another address of this wallet, not the License owner address"
    );
    let fresh = flow::sign(planned, &new_signer, &view).unwrap();
    chain.admit(fresh.bytes(), epoch).unwrap();
    let refused = chain
        .try_step(AWARD + 2, &[before.bytes().to_vec()])
        .unwrap_err();
    assert!(refused.contains("StaleOwner"), "{refused}");
    let state = chain.step(AWARD + 2, &[fresh.bytes().to_vec()]);
    let account = state
        .dividends
        .ledger()
        .award(AWARD)
        .unwrap()
        .account(&license)
        .unwrap();
    assert_eq!((account.remaining, account.claims), (SHARE - 2_000, 1));
    chain.finish();
}

#[test]
fn suspended_and_revoked_licenses_are_refused_through_real_blocks() {
    let me = identity_of(&owner());
    let (suspended, revoked) = (license_id(5), license_id(6));
    let until = AWARD + 100;
    let mut chain = ClaimChain::with_statuses(
        "p3-e2e-status",
        &[],
        &[(suspended, Some(until)), (revoked, None)],
    );
    let none = BTreeSet::new();
    // At the award boundary neither License is eligible: the pool is split among the other ten.
    let first = chain.step(AWARD, &[]);
    let award = first.dividends.ledger().award(AWARD).unwrap();
    assert_eq!(award.accounts(), 10);
    assert!(award.account(&suspended).is_none() && award.account(&revoked).is_none());
    assert_eq!(award.account(&license_id(3)).unwrap().share, 60_000);

    let own = address_of(&owner(), 1);
    for (license, consensus, standing) in [
        (
            suspended,
            ClaimError::Dividend(mutiny_consensus_v8::dividends_v1::DivError::Suspended),
            licenses::Standing::Suspended { until },
        ),
        (
            revoked,
            ClaimError::Dividend(mutiny_consensus_v8::dividends_v1::DivError::Revoked),
            licenses::Standing::Revoked,
        ),
    ] {
        let view = chain.view(&none);
        assert_eq!(licenses::license(view.state(), license).unwrap().standing, standing);
        assert_eq!(
            plan(&claim(license, 1_000, own), &view, &me).unwrap_err(),
            Refusal::LicenseSuspendedOrRevoked
        );
        let hand = chain.hand_claim(&owner(), 1, license, AWARD, 1_000, 0, own);
        assert_eq!(chain.admit(&hand, view.epoch().unwrap()).unwrap_err(), consensus);
        assert_eq!(
            SignedOperation::import(&hand, &view).unwrap_err(),
            Refusal::LicenseSuspendedOrRevoked
        );
        let refused = chain.try_step(AWARD + 1, &[hand]).unwrap_err();
        assert!(refused.contains(&format!("{consensus:?}")), "{refused}");
    }

    // Once the processed epoch reaches the end of the suspension the License is active again, but
    // it was not in the award's snapshot: nothing to claim, for the wallet and for consensus.
    chain.step(until, &[]);
    let view = chain.view(&none);
    assert_eq!(
        licenses::license(view.state(), suspended).unwrap().standing,
        licenses::Standing::Active
    );
    assert_eq!(
        plan(&claim(suspended, 1_000, own), &view, &me).unwrap_err(),
        Refusal::NotEntitled
    );
    let hand = chain.hand_claim(&owner(), 1, suspended, AWARD, 1_000, 0, own);
    assert_eq!(
        chain.admit(&hand, view.epoch().unwrap()).unwrap_err(),
        ClaimError::Dividend(mutiny_consensus_v8::dividends_v1::DivError::NotEntitled)
    );
    // The revoked License stays refused.
    assert_eq!(
        plan(&claim(revoked, 1_000, own), &view, &me).unwrap_err(),
        Refusal::LicenseSuspendedOrRevoked
    );
    chain.finish();
}
