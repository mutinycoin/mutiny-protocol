//! The cross-operation matrix (phase 8, W2): ONE real consensus chain (production assembler, real
//! hybrid certificates, canonical store with full replay, hybrid mempool) on which every operation
//! kind runs in a realistic order through the full pipeline: plan, review, typed acknowledgements
//! (and the confirmation phrase of a high-risk review), approval, authorization, the outbox (one
//! of them durable), certified inclusion for canonical carriers, and reconciliation from
//! verified state. Maker and Treasury freeze witnesses remain above consensus; bond withdrawal
//! uses the explicitly synthetic parent described below.
//!
//! Every step is differential: before a block includes an operation, the wallet re-verifies the
//! bytes (`SignedOperation::import`) AND consensus accepts them as the next block (`prepare` for a
//! block operation, `execute` for a pool transaction); every negative step is refused by both. The
//! per-kind flows are the phase helpers (`trading::sale`, `trading::fiat_lock`, `ckit::fund_lock`,
//! `tkit::funding_lock`, `tkit::declared`, the shared rig's claims, `hand_withdraw` and
//! `synthetic_parent`), not copies.
//!
//! Order: the award boundary; a payment with change; a License DvP followed by dividend claims (the
//! seller's stale claim refused, the buyer's partial claims n and n + 1); a wallet-authority rotation
//! followed by spending with the new key and refusal of the old one; the bond lifecycle (creation
//! with its funding, unbond, early withdrawal refused, withdrawal at the floor through consensus'
//! own lifecycle at a synthetic parent); a hash lock claimed before its refund height and a second
//! one refunded at it; a fiat lock and its release; canonical Treasury funding BEFORE R1,
//! sponsored R1 then current-key R2, and current-key historical settlement; a post-sale Q17
//! assignment through canonical delivery and next-epoch activation. Negative steps:
//! wrong order, stale head, and a reserved coin used twice across plans.
//!
//! NATIVE, TEST-VALUE: public deterministic wallet and settlement keys (BIP-39 vectors and
//! public labels); nothing here is physical or production evidence.
// Each kit includes the shared `support/flow.rs` so that it works on its own; this file includes
// three kits and the flow itself, so the same (identical) module is loaded four times.
#![allow(clippy::duplicate_mod)]
#[path = "support/conditional_kit.rs"]
mod ckit;
#[path = "support/flow.rs"]
mod flow;
#[path = "support/rig.rs"]
mod rig;
#[path = "support/tempdir.rs"]
mod tempdir;
#[path = "support/treasury_kit.rs"]
mod tkit;
#[path = "support/trading_5b.rs"]
mod trading;

use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    blocks::BlockBody,
    bond_ops_v2::{Operation as BondOperation, settle_commands},
    bonds::{LotStatus, withdrawal_floor},
    continuity_lifecycle_v2::transition,
    dividend_claim_v1::ClaimError,
    execution::State,
    hybrid_transaction_v2::Transaction,
    trading_v1::{
        self, Action, CandidatePolicy, Context as TradeContext, FrozenTreasuryOffer, Meta,
        NativeError, NativeOperation, Operation, SignedOffer, Strikes, native_input_id,
    },
    transactions::{Coin, OutPoint, Output},
};
use mutiny_crypto_v2::HybridKey;
use mutiny_wallet_core_v8::{
    discovery::dividends as entitlements,
    ops::{
        conditional::{self, MemoryPreimageStore, PreimageStore},
        rotation::{self, RotationSigner, combine},
        treasury,
    },
    *,
};
use rig::chain::*;
use std::collections::BTreeSet;
use tkit::{FreezeTerms, TRADING_TREASURY};

const TREASURY_ATOMS: u64 = 1_200_000;
/// Each of the twelve Genesis Licenses' share of the first award (half the Treasury, split twelve
/// ways).
const SHARE: u64 = 50_000;
const PRICE: u64 = 2_000_000;
const PRINCIPAL: u64 = 15_000_000_000;
const BOND_FUNDS: u64 = 30_000_000_000;
const FIAT: u64 = 2_000_000;
const FIAT_TERMS: Hash = [0x77; 32];

/// The payer of payments, hash locks and the fiat lock (a labelled public key, never registered).
fn key_d() -> HybridKey {
    labelled_key("w8-matrix-payer")
}
/// The wallet whose authority rotates (registered at Genesis) and its new key.
fn key_c() -> HybridKey {
    labelled_key("w8-matrix-rotating")
}
fn key_c2() -> HybridKey {
    labelled_key("w8-matrix-rotated")
}
/// The trading Treasury's next destination key (R2) and the Genesis Treasury's new key (R1).
fn key_n() -> HybridKey {
    labelled_key("w8-matrix-r2-next")
}
fn key_t2() -> HybridKey {
    labelled_key("w8-matrix-r1-new")
}

fn pay(recipient: Hash, amount: u64) -> OperationRequest {
    OperationRequest::Payment(PaymentRequest::new(recipient, amount))
}

fn claim(license: Hash, amount: u64, destination: Hash) -> OperationRequest {
    OperationRequest::DividendClaim(DividendClaimRequest::new(
        license,
        AWARD_EPOCH,
        amount,
        destination,
    ))
}

fn rotate(new: &HybridKey, generation: u64, fee: FeeSource) -> OperationRequest {
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

/// Exactly one handler recognises `bytes`, the one of `kind` (no kind can be taken for another).
fn recognised_as(bytes: &[u8], kind: OperationKind) {
    assert_eq!(
        ops::recognizing_kinds_for_test(bytes),
        vec![kind],
        "{kind:?}"
    );
}

/// The wallet and consensus agree that the native block operation `signed` is valid in the next
/// block: the wallet re-verifies the bytes on import, and consensus assembles the next block with
/// them (nothing installed).
fn both_accept_operation(h: &Harness, signed: &SignedOperation) {
    let none = BTreeSet::new();
    let imported = SignedOperation::import(signed.bytes(), &h.view(&none))
        .expect("the wallet re-verifies the bytes");
    assert_eq!(imported.id(), signed.id());
    assert!(imported.is_complete());
    assert_eq!(imported.kind(), signed.kind());
    recognised_as(signed.bytes(), signed.kind());
    h.prepare(&[signed.bytes().to_vec()])
        .expect("consensus accepts the operation in the next block");
}

/// The same for a pool transaction (a payment or a rotation): consensus executes the next block body
/// with it.
fn both_accept_transaction(h: &Harness, signed: &SignedOperation) {
    let none = BTreeSet::new();
    let imported = SignedOperation::import(signed.bytes(), &h.view(&none))
        .expect("the wallet re-verifies the bytes");
    assert_eq!(imported.id(), signed.id());
    assert!(imported.is_complete());
    assert_eq!(imported.kind(), signed.kind());
    recognised_as(signed.bytes(), signed.kind());
    h.execute(vec![signed.bytes().to_vec()], Vec::new())
        .expect("consensus executes the transaction in the next block");
}

/// The wallet and consensus both refuse the block operation `raw` at the head: the wallet with
/// exactly `refusal` on import, consensus when it assembles the next block with it.
fn both_refuse_operation(h: &Harness, raw: &[u8], refusal: Refusal) {
    let none = BTreeSet::new();
    let history = h.operation_history(raw);
    let view = h.view(&none).with_history(&history);
    assert_eq!(SignedOperation::import(raw, &view).unwrap_err(), refusal);
    assert!(
        h.prepare(&[raw.to_vec()]).is_err(),
        "consensus refuses it too"
    );
}

/// Reconcile `outbox` from the verified head (with the node's confirmation index) and return the
/// status of record `id`.
fn settled(h: &Harness, outbox: &mut dyn Outbox, id: &Hash) -> OutboxStatus {
    let none = BTreeSet::new();
    let confirmations = h.confirmations();
    let view = h.view(&none).with_confirmations(&confirmations);
    outbox.reconcile(&view).unwrap();
    outbox.get(id).unwrap().unwrap().status
}

/// The largest non-coinbase coin of `owner` in `state`.
fn largest_coin(state: &State, owner: Hash) -> (OutPoint, u64) {
    state
        .coins
        .iter()
        .filter(|(_, coin)| !coin.coinbase && coin.output.owner == owner)
        .map(|(point, coin)| (point.clone(), coin.output.atoms))
        .max_by_key(|(_, atoms)| *atoms)
        .expect("a coin")
}

#[test]
fn every_kind_on_one_chain_in_realistic_order_with_wallet_and_consensus_agreeing() {
    let (key_a, key_b, key_t) = (wallet_key(), other_key(), treasury_wallet_key());
    let (a, b, c, d) = (
        address_of(&key_a),
        address_of(&key_b),
        address_of(&key_c()),
        address_of(&key_d()),
    );
    let a1 = address_of(&key_t);
    let a2 = address_at(&key_t2(), 2);

    // ---- Genesis: the TEST-VALUE Genesis Treasury (the zoo key), the trading Treasury of phase 6
    //      with the zoo key's generation-one address as its destination, the rotating wallet
    //      registered, and the coins each step spends.
    let mut h = Harness::with_genesis("w8-matrix", TREASURY_ATOMS, |state, genesis| {
        for (tag, owner, atoms) in [
            (0xa1, a, BOND_FUNDS),
            (0xa2, a, 3_000_000),
            (0xa3, a, 3_000_000),
            (0xb1, b, 5_000_000),
            (0xb2, b, 300_000),
            (0xb3, b, 1_000_000),
            (0xc1, c, 5_000_000),
            (0xc2, c, 2_000_000),
            (0xe1, d, 5_000_000),
            (0xe2, d, 3_000_000),
            (0xe3, d, 3_000_000),
            (0xe4, d, 5_000_000),
            (0xf1, a2, 400_000),
        ] {
            state.coins.insert(
                outpoint(tag, 0),
                Coin {
                    output: Output { owner, atoms },
                    created_height: 0,
                    coinbase: false,
                },
            );
        }
        state.wallets.register(&descriptor_of(&key_c(), 1)).unwrap();
        state.wallets.register(&descriptor_of(&key_d(), 1)).unwrap();
        // Every initial signing authority used by an unsigned plan is explicit in
        // this public Genesis fixture's authenticated WalletBook.
        state.wallets.register(&descriptor_of(&key_b, 1)).unwrap();
        let context = TradeContext {
            network: NETWORK_ID,
            genesis: genesis.genesis,
            fingerprint: genesis.fingerprint,
        };
        for (key, raw) in trading_v1::treasury_genesis_records(
            &context,
            TRADING_TREASURY,
            descriptor_of(&treasury_wallet_key(), 1),
        )
        .unwrap()
        {
            state.protocol_records.insert(key, raw);
        }
    });
    let none = BTreeSet::new();
    let context = h.view(&none).context();
    let dir = tempdir::TempDir::new("w8-matrix");
    // The payer's outbox is the durable one; the others are in memory.
    let mut outbox_d = SqliteOutbox::open(&dir.file("payer.sqlite"), context).unwrap();
    let mut outbox_a = MemoryOutbox::new();
    let mut outbox_b = MemoryOutbox::new();
    let mut outbox_c = MemoryOutbox::new();
    let mut outbox_t = MemoryOutbox::new();
    let (me_a, me_b, me_c, me_d) = (
        identity_of(&key_a),
        identity_of(&key_b),
        identity_of(&key_c()),
        identity_of(&key_d()),
    );
    let signer_a = KeySigner::for_test(wallet_key()).unwrap();
    let signer_b = KeySigner::for_test(other_key()).unwrap();
    let signer_d = KeySigner::for_test(key_d()).unwrap();

    // ================================================================ block 1: the award boundary
    let awarded = h.step_at(AWARD_EPOCH);
    assert_eq!(awarded.dividends.reserved(), TREASURY_ATOMS / 2);
    assert_eq!(h.view(&none).class(), ChainClass::TestValue);

    // ================================================================ block 2: a payment with change
    let payment = {
        let view = h.view(&none);
        let planned = plan(&pay(b, 1_000_000), &view, &me_d).unwrap();
        let reviewed = review(&planned, &view).unwrap();
        assert!(reviewed.destinations().iter().any(|dst| {
            dst.role == DestinationRole::Change && dst.label == AddressLabel::ThisWallet
        }));
        // Wrong order: an approval before the acknowledgements does not exist.
        let mut gate = ReviewGate::new();
        assert_eq!(gate.present(&reviewed, &view), Freshness::Fresh);
        assert!(matches!(
            gate.approve(&view),
            Err(Refusal::AcknowledgementMissing(_))
        ));
        signer_d
            .authorize(planned, flow::approve(&reviewed, &view), &view)
            .unwrap()
    };
    both_accept_transaction(&h, &payment);
    outbox_d.commit(&payment, &h.view(&none)).unwrap();
    // A reserved coin used twice across plans: a plan at a view that merges the outbox never selects
    // the queued coin; a second payment signed over the SAME coin (planned without the outbox) is
    // refused by the outbox and by the node's pool.
    let stale_approval = {
        let reserved = outbox_d.reserved().unwrap();
        let view = h.view(&reserved);
        let other = plan(&pay(c, 100_000), &view, &me_d).unwrap();
        assert!(other.inputs().iter().all(|point| !reserved.contains(point)));
        let view = h.view(&none);
        let twice = plan(&pay(b, 900_000), &view, &me_d).unwrap();
        assert!(
            twice
                .inputs()
                .iter()
                .any(|point| payment.reserved().contains(point)),
            "the same coin"
        );
        let reviewed = review(&twice, &view).unwrap();
        let conflicting = signer_d
            .authorize(twice, flow::approve(&reviewed, &view), &view)
            .unwrap();
        assert_eq!(
            outbox_d.commit(&conflicting, &view).unwrap_err(),
            Refusal::ReservedInput
        );
        h.admit(&Transaction::decode(payment.bytes()).unwrap())
            .unwrap();
        assert!(
            h.admit(&Transaction::decode(conflicting.bytes()).unwrap())
                .is_err(),
            "the pool refuses a second spend of the coin"
        );
        // A plan reviewed and approved at THIS head, to be used after the next block.
        let view = h.view(&reserved);
        let later = plan(&pay(c, 100_000), &view, &me_d).unwrap();
        let reviewed = review(&later, &view).unwrap();
        (later, flow::approve(&reviewed, &view))
    };
    let after = h.step();
    assert_eq!(h.height(), 2);
    let paid = &after.coins[&OutPoint {
        transaction: payment.id(),
        index: 0,
    }];
    assert_eq!((paid.output.owner, paid.output.atoms), (b, 1_000_000));
    assert_eq!(
        settled(&h, &mut outbox_d, &payment.id()),
        OutboxStatus::Confirmed(2)
    );
    // Stale head: the approval given at head 1 is refused at head 2.
    {
        let view = h.view(&none);
        let (later, approval) = stale_approval;
        assert_eq!(
            signer_d.authorize(later, approval, &view).unwrap_err(),
            Refusal::StaleHead {
                reviewed: 1,
                current: 2
            }
        );
    }

    // ================================================================ block 3: a License DvP
    let license = license_id(3);
    // Wrong order: the buyer cannot claim for the License before it buys it.
    {
        let view = h.view(&none);
        assert_eq!(
            plan(&claim(license, 1_000, b), &view, &me_b).unwrap_err(),
            Refusal::NotRequiredSigner(Slot::Claim)
        );
        let early = h.hand_claim(&key_b, 1, license, AWARD_EPOCH, 1_000, 0, b);
        assert!(SignedOperation::import(&early, &view).is_err());
        assert!(h.admit_claim(&early, h.next_epoch()).is_err());
    }
    // The seller signs a claim while it still owns the License: valid when signed, for both.
    let stale_claim = {
        let view = h.view(&none);
        let planned = plan(&claim(license, 3_000, a), &view, &me_a).unwrap();
        flow::sign(planned, &signer_a, &view).unwrap()
    };
    both_accept_operation(&h, &stale_claim);
    h.admit_claim(stale_claim.bytes(), h.next_epoch()).unwrap();
    // The buyer plans, the maker fills, the seller co-signs (trading::sale); the buyer queues its
    // part and replaces it by the completion atomically.
    let maker = trading::maker();
    let offer = trading::offer(
        &maker,
        trading::context_of(h.genesis()),
        trading::license_terms(license, 1, PRICE),
        1,
        h.height() + 50,
        0,
        0x31,
    );
    let dvp_request = OperationRequest::LicenseDvp(
        LicenseDvpRequest::new(Blob::new(trading::offer_bytes(&offer)), license)
            .with_commitments([0x71; 32], [0x72; 32]),
    );
    let (buyer_part, _, _, dvp, _) = trading::sale(
        &h.view(&none),
        &maker,
        &offer,
        &dvp_request,
        &signer_b,
        &signer_a,
    );
    recognised_as(buyer_part.bytes(), OperationKind::LicenseDvp);
    both_accept_operation(&h, &dvp);
    {
        let view = h.view(&none);
        outbox_b.commit(&buyer_part, &view).unwrap();
        assert_eq!(
            outbox_b
                .replace_partial(&buyer_part.id(), &dvp, &view)
                .unwrap(),
            dvp.id()
        );
    }
    // The sale and the seller's claim in one block: refused whatever the order (the sale runs first,
    // so the claim sees the buyer as owner); nothing is installed.
    for operations in [
        vec![dvp.bytes().to_vec(), stale_claim.bytes().to_vec()],
        vec![stale_claim.bytes().to_vec(), dvp.bytes().to_vec()],
    ] {
        let refused = h.try_step_with(&operations).unwrap_err();
        assert!(refused.contains("StaleOwner"), "{refused}");
        assert_eq!(h.height(), 2);
    }
    let sold = h.step_with(&[dvp.bytes().to_vec()]);
    assert_eq!(sold.licenses_v2.license(license).unwrap().owner, b);
    assert_eq!(
        settled(&h, &mut outbox_b, &dvp.id()),
        OutboxStatus::Confirmed(3)
    );
    // The seller's signed claim is stale now: refused by the wallet and by consensus.
    both_refuse_operation(
        &h,
        stale_claim.bytes(),
        Refusal::NotRequiredSigner(Slot::Claim),
    );
    assert_eq!(
        h.admit_claim(stale_claim.bytes(), h.next_epoch())
            .unwrap_err(),
        ClaimError::StaleOwner
    );
    // The same exact certified sale remains a replay at a later head; its reference
    // is resolved through our own store, never rebased or supplied by a peer.
    both_refuse_operation(&h, dvp.bytes(), Refusal::Replay);

    // ================================================================ blocks 4, 5: claims n, n + 1
    let mut claims = Vec::new();
    for (amount, sequence) in [(3_000, 0), (1_000, 1)] {
        let signed = {
            let view = h.view(&none);
            let mine = entitlements::entitlement(&view, AWARD_EPOCH, license).unwrap();
            assert_eq!(
                (mine.remaining, mine.next_sequence),
                (SHARE - 3_000 * sequence, sequence)
            );
            let planned = plan(
                &OperationRequest::DividendClaim(mine.request(amount, b)),
                &view,
                &me_b,
            )
            .unwrap();
            flow::sign(planned, &signer_b, &view).unwrap()
        };
        both_accept_operation(&h, &signed);
        h.admit_claim(signed.bytes(), h.next_epoch()).unwrap();
        outbox_b.commit(&signed, &h.view(&none)).unwrap();
        let height = h.height() + 1;
        h.step_with(&[signed.bytes().to_vec()]);
        assert_eq!(
            settled(&h, &mut outbox_b, &signed.id()),
            OutboxStatus::Confirmed(height)
        );
        claims.push(signed);
    }
    {
        let account = h
            .state()
            .dividends
            .ledger()
            .award(AWARD_EPOCH)
            .unwrap()
            .account(&license)
            .unwrap();
        assert_eq!((account.remaining, account.claims), (SHARE - 4_000, 2));
    }
    // Claim n again: a replay for both.
    both_refuse_operation(&h, claims[0].bytes(), Refusal::Replay);

    // ================================================================ blocks 6, 7: a rotation
    let rotated = {
        let view = h.view(&none);
        let planned = plan(
            &rotate(&key_c2(), 2, FeeSource::RotatingAuthority),
            &view,
            &me_c,
        )
        .unwrap();
        let reviewed = review(&planned, &view).unwrap();
        assert_eq!(reviewed.destinations()[0].label, AddressLabel::NewKey);
        assert!(reviewed.requires_phrase());
        RotationSigner::for_test(key_c(), me_c.clone(), key_c2())
            .unwrap()
            .authorize(planned, flow::approve(&reviewed, &view), &view)
            .unwrap()
    };
    both_accept_transaction(&h, &rotated);
    outbox_c.commit(&rotated, &h.view(&none)).unwrap();
    h.admit(&Transaction::decode(rotated.bytes()).unwrap())
        .unwrap();
    let after = h.step();
    assert_eq!(
        after.wallets.current(c).unwrap(),
        descriptor_of(&key_c2(), 2).as_slice()
    );
    assert_eq!(
        settled(&h, &mut outbox_c, &rotated.id()),
        OutboxStatus::Confirmed(6)
    );
    // The old key: refused by the wallet and by consensus (pool and block execution).
    {
        let view = h.view(&none);
        assert_eq!(
            plan(&pay(b, 1_000), &view, &me_c).unwrap_err(),
            Refusal::StaleAuthority
        );
        let old = h.hand_signed_transfer(
            &key_c(),
            outpoint(0xc2, 0),
            4_000,
            &[(b, 2_000_000 - 4_000)],
        );
        assert!(h.admit(&old).is_err());
        assert!(h.execute(vec![old.encode().unwrap()], Vec::new()).is_err());
    }
    // The new key spends the OLD address's coin.
    let me_c2 = SignerIdentity::from_public(key_c2().public(), 2, Some(c)).unwrap();
    let spent = {
        let view = h.view(&none);
        let planned = plan(&pay(b, 6_000_000), &view, &me_c2).unwrap();
        assert!(planned.inputs().contains(&outpoint(0xc2, 0)));
        let signer =
            KeySigner::new_rotated(key_c2(), 2, c, SigningGate::test_value().unwrap()).unwrap();
        flow::sign(planned, &signer, &view).unwrap()
    };
    both_accept_transaction(&h, &spent);
    outbox_c.commit(&spent, &h.view(&none)).unwrap();
    h.admit(&Transaction::decode(spent.bytes()).unwrap())
        .unwrap();
    h.step();
    assert_eq!(
        settled(&h, &mut outbox_c, &spent.id()),
        OutboxStatus::Confirmed(7)
    );

    // ================================================================ blocks 8 to 10: a bond
    let node = h.node();
    let create = |nonce: Hash| {
        OperationRequest::BondCreate(BondCreateRequest::new(node, 1, PRINCIPAL, nonce))
    };
    // Stale head: a creation signed at head 7 is valid only in block 8; after an empty block 8 the
    // wallet and consensus both refuse it.
    let stale_bond = {
        let view = h.view(&none);
        let planned = plan(&create([0x41; 32]), &view, &me_a).unwrap();
        let signed = flow::sign(planned, &signer_a, &view).unwrap();
        // Exact single-inclusion-height negative fixture: native TEST-VALUE re-signing,
        // not an extension of reviewed bytes and not a production capability.
        let mut unsigned =
            mutiny_consensus_v8::bond_create_v3::FundedBondCreate::decode(signed.bytes())
                .unwrap()
                .unsigned;
        unsigned.envelope.last_height = unsigned.envelope.first_height;
        mutiny_consensus_v8::bond_create_v3::FundedBondCreate::sign(unsigned, &key_a)
            .unwrap()
            .encode()
            .unwrap()
    };
    h.step();
    {
        let view = h.view(&none);
        assert!(SignedOperation::import(&stale_bond, &view).is_err());
        assert!(h.prepare(&[stale_bond]).is_err());
    }
    let bond = {
        let view = h.view(&none);
        let planned = plan(&create([0x42; 32]), &view, &me_a).unwrap();
        let reviewed = review(&planned, &view).unwrap();
        assert!(reviewed.requires_phrase());
        assert!(reviewed.render_text().contains("atomic"));
        signer_a
            .authorize(planned, flow::approve(&reviewed, &view), &view)
            .unwrap()
    };
    recognised_as(bond.bytes(), OperationKind::BondCreate);
    let native =
        mutiny_consensus_v8::bond_create_v3::FundedBondCreate::decode(bond.bytes()).unwrap();
    let lot_id = native.unsigned.lot_id();
    both_accept_operation(&h, &bond);
    outbox_a.commit(&bond, &h.view(&none)).unwrap();
    // One complete item, one durable pool record, one operation in its certified block.
    // The diagnostic legacy two-object wrapper cannot enter the canonical decoder.
    let mut retired = minicbor::Encoder::new(Vec::new());
    retired
        .array(3)
        .unwrap()
        .str("MUTINY-BUILD8-WALLET-BOND-CREATE-V1")
        .unwrap()
        .bytes(bond.bytes())
        .unwrap()
        .bytes(bond.bytes())
        .unwrap();
    assert!(
        mutiny_consensus_v8::bond_create_v3::FundedBondCreate::decode(&retired.into_writer())
            .is_err()
    );
    let mut submissions = h.submission_pool();
    assert_eq!(
        h.admit_submission(&mut submissions, 1, bond.bytes())
            .unwrap(),
        bond.id()
    );
    let created = h.step_submissions(&mut submissions);
    let created_height = h.height();
    assert_eq!(created_height, 9);
    assert_eq!(created.bonds_v2.lots[&lot_id].0.status, LotStatus::Active);
    assert_eq!(
        settled(&h, &mut outbox_a, &bond.id()),
        OutboxStatus::Confirmed(9)
    );
    let unbond = {
        let view = h.view(&none);
        let planned = plan(
            &OperationRequest::BondUnbond(BondUnbondRequest::new(lot_id)),
            &view,
            &me_a,
        )
        .unwrap();
        flow::sign(planned, &signer_a, &view).unwrap()
    };
    both_accept_operation(&h, &unbond);
    outbox_a.commit(&unbond, &h.view(&none)).unwrap();
    let unbonded = h.step_with(&[unbond.bytes().to_vec()]);
    assert_eq!(
        unbonded.bonds_v2.lots[&lot_id].0.status,
        LotStatus::Unbonding
    );
    assert_eq!(
        settled(&h, &mut outbox_a, &unbond.id()),
        OutboxStatus::Confirmed(10)
    );
    let floor = withdrawal_floor(created_height, 10).unwrap();
    let withdraw = OperationRequest::BondWithdraw(BondWithdrawRequest::new(lot_id));
    // An early withdrawal: refused by the wallet and by consensus.
    {
        let view = h.view(&none);
        let refusal = Refusal::NotYetEligible {
            what: "Withdrawing this lot",
            height: floor,
        };
        assert_eq!(plan(&withdraw, &view, &me_a).unwrap_err(), refusal);
        let early = hand_withdraw(&key_a, a, lot_id, 2, h.height() + 1, &h.anchor());
        both_refuse_operation(&h, &early.encode().unwrap(), refusal);
    }
    // The withdrawal at exactly the floor, through consensus' own settlement and lifecycle at a
    // synthetic parent (the chain cannot be advanced to the floor in a test).
    {
        let (state, anchor, root) = synthetic_parent(&unbonded, &h.anchor(), floor - 1);
        let head = HeadInfo::new(anchor.clone(), RIG_T0 + 60 * floor, RIG_T0, root).unwrap();
        let view = ChainView::verified(head, &state, &none).unwrap();
        let planned = plan(&withdraw, &view, &me_a).unwrap();
        let signed = flow::sign(planned, &signer_a, &view).unwrap();
        recognised_as(signed.bytes(), OperationKind::BondWithdraw);
        let op = BondOperation::decode(signed.bytes()).unwrap();
        op.verify_command(
            &anchor,
            &mutiny_consensus_v8::evidence_history_v2::History::default(),
            &state.wallets,
            &state.bonds_v2.lots[&lot_id],
        )
        .expect("consensus verifies the withdrawal at the floor");
        let settlement = settle_commands(
            &anchor,
            &mutiny_consensus_v8::evidence_history_v2::History::default(),
            &state.wallets,
            &state.bonds_v2,
            &state.penalties_v2,
            std::slice::from_ref(&op),
            &[],
        )
        .expect("consensus settles it");
        let payout = OutPoint {
            transaction: op.payout_id().unwrap(),
            index: 0,
        };
        assert_eq!(
            (
                settlement.payouts[&payout].output.owner,
                settlement.payouts[&payout].output.atoms
            ),
            (a, PRINCIPAL)
        );
        let lifecycle = transition(
            &state,
            &anchor,
            root,
            &BlockBody {
                height: floor,
                reward_owner: a,
                fees: 0,
                transactions: vec![],
                operations: vec![signed.bytes().to_vec()],
            },
        )
        .expect("the canonical lifecycle transition accepts it");
        assert_eq!(lifecycle.bonds.lots[&lot_id].0.status, LotStatus::Withdrawn);
    }

    // ================================================================ blocks 11, 12: lock and claim
    let lock_maker = other_key();
    let lock_context = ckit::context_of(&h.anchor());
    let mut preimages = MemoryPreimageStore::new();
    let condition = preimages.create().unwrap();
    // The maker is the actual current recipient B. Its reviewed exported
    // witness stays above consensus; first native funding supplies canonical terms.
    let offer_body = ckit::signed_offer(
        &lock_maker,
        lock_context.clone(),
        1,
        500,
        1_000_000,
        1,
        0x31,
    )
    .body;
    let maker_witness = {
        let view = h.view(&none);
        let p = plan(
            &OperationRequest::MakerOffer(MakerOfferRequest::new(Blob::new(
                offer_body.encode().unwrap(),
            ))),
            &view,
            &me_b,
        )
        .unwrap();
        assert!(p.inputs().is_empty());
        flow::sign(p, &signer_b, &view).unwrap()
    };
    recognised_as(maker_witness.bytes(), OperationKind::MakerOffer);
    assert!(
        h.prepare(&[maker_witness.bytes().to_vec()]).is_err(),
        "an exported offer is not a canonical block operation"
    );
    outbox_b.commit(&maker_witness, &h.view(&none)).unwrap();
    let lock_offer = SignedOffer::decode(maker_witness.bytes()).unwrap();
    lock_offer.verify().unwrap();
    let lock = ckit::fund_lock(
        &h.view(&none),
        &signer_d,
        &signer_b,
        &lock_maker,
        &lock_offer,
        condition,
        1_000_000,
        h.height() + 6,
    );
    assert_ne!(lock.complete.id(), lock.sender_partial.id());
    recognised_as(lock.sender_partial.bytes(), OperationKind::HashLock);
    both_accept_operation(&h, &lock.complete);
    {
        // The payer queued its partial; the completion (another identifier) replaces it atomically
        // in the durable outbox.
        let view = h.view(&none);
        outbox_d.commit(&lock.sender_partial, &view).unwrap();
        assert_eq!(
            outbox_d
                .replace_partial(&lock.sender_partial.id(), &lock.complete, &view)
                .unwrap(),
            lock.complete.id()
        );
        assert!(outbox_d.get(&lock.sender_partial.id()).unwrap().is_none());
    }
    h.step_with(&[lock.complete.bytes().to_vec()]);
    assert_eq!(
        settled(&h, &mut outbox_d, &lock.complete.id()),
        OutboxStatus::Confirmed(11)
    );
    assert!(
        h.verified_operations(maker_witness.id()).is_empty(),
        "the witness itself has no canonical operation receipt"
    );
    assert!(
        SignedOperation::import(maker_witness.bytes(), &h.view(&none)).is_err(),
        "actual canonical funding has consumed the exact above-consensus offer"
    );
    assert_eq!(
        settled(&h, &mut outbox_b, &maker_witness.id()),
        OutboxStatus::InputsSpent
    );
    let claimed = {
        let view = h.view(&none);
        let request = conditional::claim_request(&preimages, lock.id, &view).unwrap();
        let planned = plan(&OperationRequest::ConditionalClaim(request), &view, &me_b).unwrap();
        let reviewed = review(&planned, &view).unwrap();
        assert!(
            reviewed
                .acknowledgements()
                .contains(&AckKind::DisclosesPreimage)
        );
        signer_b
            .authorize(planned, flow::approve(&reviewed, &view), &view)
            .unwrap()
    };
    both_accept_operation(&h, &claimed);
    outbox_b.commit(&claimed, &h.view(&none)).unwrap();
    let after = h.step_with(&[claimed.bytes().to_vec()]);
    assert!(
        trading_v1::locked(&after, lock.id).is_err(),
        "the lock is spent"
    );
    assert_eq!(
        settled(&h, &mut outbox_b, &claimed.id()),
        OutboxStatus::Confirmed(12)
    );

    // ================================================================ blocks 13 to 15: refund at R
    let refund_height = h.height() + 3;
    let second = ckit::fund_lock(
        &h.view(&none),
        &signer_d,
        &signer_b,
        &lock_maker,
        &ckit::signed_offer(&lock_maker, lock_context.clone(), 1, 500, 700_000, 1, 0x32),
        [0x5d; 32],
        700_000,
        refund_height,
    );
    both_accept_operation(&h, &second.complete);
    outbox_d.commit(&second.complete, &h.view(&none)).unwrap();
    h.step_with(&[second.complete.bytes().to_vec()]);
    let refund = OperationRequest::ConditionalRefund(RefundRequest::new(second.id));
    // Before R: refused by the wallet and by consensus (a refund built by hand).
    {
        let view = h.view(&none);
        assert_eq!(
            plan(&refund, &view, &me_d).unwrap_err(),
            Refusal::NotYetEligible {
                what: "Refunding this hash lock",
                height: refund_height
            }
        );
        let (fee_coin, fee_atoms) = largest_coin(view.state(), d);
        let next = view.anchor().height + 1;
        let early = ckit::consensus_signed(
            Operation {
                meta: Meta {
                    context: lock_context.clone(),
                    trade: [0x21; 32],
                    contract: [0x22; 32],
                    generation: 1,
                    envelope: mutiny_consensus_v8::op_envelope_v1::Envelope {
                        first_height: next,
                        last_height: next + 8,
                        reference_height: (view.anchor()).height,
                        reference_block: (view.anchor()).block,
                        preconditions: Vec::new(),
                    },
                    fee: Strikes(10_000),
                    inputs: vec![native_input_id(&fee_coin)],
                },
                action: Action::Refund {
                    output: second.id,
                    owner: d,
                    amount: Strikes(700_000),
                    change: Strikes(fee_atoms - 10_000),
                },
                approvals: vec![],
                offer_proof: None,
            },
            vec![fee_coin],
            &[(0, &key_d())],
            None,
        );
        assert_eq!(
            ckit::consensus_in(&view, &early).unwrap_err(),
            NativeError::Time
        );
    }
    h.step();
    let refunded = {
        let view = h.view(&none);
        let planned = plan(&refund, &view, &me_d).unwrap();
        flow::sign(planned, &signer_d, &view).unwrap()
    };
    both_accept_operation(&h, &refunded);
    outbox_d.commit(&refunded, &h.view(&none)).unwrap();
    let after = h.step_with(&[refunded.bytes().to_vec()]);
    assert_eq!(h.height(), refund_height);
    let returned = &after.coins[&OutPoint {
        transaction: refunded.id(),
        index: 0,
    }];
    assert_eq!((returned.output.owner, returned.output.atoms), (d, 700_000));
    for id in [second.complete.id(), refunded.id()] {
        assert!(matches!(
            settled(&h, &mut outbox_d, &id),
            OutboxStatus::Confirmed(_)
        ));
    }

    // ================================================================ blocks 16, 17: fiat
    let fiat_maker = key_d();
    let fiat_offer = trading::offer(
        &fiat_maker,
        trading::context_of(h.genesis()),
        trading::fiat_terms(FIAT, FIAT_TERMS),
        1,
        h.height() + 50,
        0,
        0x41,
    );
    let fiat_request = OperationRequest::FiatLock(
        FiatLockRequest::new(
            Blob::new(trading::offer_bytes(&fiat_offer)),
            b,
            FIAT,
            FIAT_TERMS,
        )
        .with_commitments([0x73; 32], [0x74; 32])
        .with_buyer_descriptor(Blob::new(descriptor_of(&key_b, 1))),
    );
    let (seller_part, fiat_lock) = trading::fiat_lock(
        &h.view(&none),
        &fiat_maker,
        &fiat_offer,
        &fiat_request,
        &signer_d,
        &signer_b,
    );
    let fiat_lock_id = NativeOperation::decode(fiat_lock.bytes())
        .unwrap()
        .operation
        .output_id(0)
        .unwrap();
    recognised_as(seller_part.bytes(), OperationKind::FiatLock);
    // Wrong order: a release before the lock exists finds no lock.
    assert_eq!(
        plan(
            &OperationRequest::FiatRelease(FiatReleaseRequest::new(fiat_lock_id)),
            &h.view(&none),
            &me_b
        )
        .unwrap_err(),
        Refusal::LockNotFound
    );
    both_accept_operation(&h, &fiat_lock);
    {
        // The seller queued its part; the completion (the same identifier) replaces it in place.
        let view = h.view(&none);
        outbox_d.commit(&seller_part, &view).unwrap();
        assert_eq!(seller_part.id(), fiat_lock.id());
        assert_eq!(
            outbox_d
                .replace_partial(&seller_part.id(), &fiat_lock, &view)
                .unwrap(),
            fiat_lock.id()
        );
    }
    h.step_with(&[fiat_lock.bytes().to_vec()]);
    assert_eq!(
        settled(&h, &mut outbox_d, &fiat_lock.id()),
        OutboxStatus::Confirmed(16)
    );
    let (_, release) = trading::fiat_release(&h.view(&none), fiat_lock_id, &signer_b, &signer_d);
    both_accept_operation(&h, &release);
    outbox_b.commit(&release, &h.view(&none)).unwrap();
    let after = h.step_with(&[release.bytes().to_vec()]);
    let released = &after.coins[&OutPoint {
        transaction: release.id(),
        index: 0,
    }];
    assert_eq!((released.output.owner, released.output.atoms), (b, FIAT));
    assert_eq!(
        settled(&h, &mut outbox_b, &release.id()),
        OutboxStatus::Confirmed(17)
    );
    // The released lock is gone for both.
    assert_eq!(
        plan(
            &OperationRequest::FiatRelease(FiatReleaseRequest::new(fiat_lock_id)),
            &h.view(&none),
            &me_b
        )
        .unwrap_err(),
        Refusal::LockNotFound
    );
    assert!(h.prepare(&[release.bytes().to_vec()]).is_err());

    // ================================================================ blocks 18 to 21: funding before R1, current R2, historical settlement
    let policy = CandidatePolicy::native_denomination_locked();
    let treasury_context = tkit::context_of(&h.anchor());
    let me_t = tkit::declared(
        &key_t,
        1,
        None,
        &h.view(&none),
        true,
        Some(TRADING_TREASURY),
    );
    let signer_t = signer_for(treasury_wallet_key(), &me_t);
    let treasury_maker = tkit::maker_key();
    // Generation-one off-chain authorization; it cannot survive retirement unfunded.
    let (frozen, creation_state, creation_anchor, creation_root, treasury_offer) = {
        let view = h.view(&none);
        let h0 = view.anchor().height;
        let treasury_offer = tkit::treasury_offer(
            &treasury_maker,
            treasury_context.clone(),
            h0,
            h0 + 40,
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
            wallet_descriptor: descriptor_of(&key_t, 1),
        };
        let planned = plan(
            &OperationRequest::TreasuryFreezeOffer(TreasuryFreezeOfferRequest::new(Blob::new(
                tkit::proposal(&view, &terms, &treasury_offer),
            ))),
            &view,
            &me_t,
        )
        .unwrap();
        let reviewed = review(&planned, &view).unwrap();
        let signed = signer_t
            .authorize(planned, flow::approve(&reviewed, &view), &view)
            .unwrap();
        recognised_as(signed.bytes(), OperationKind::TreasuryFreezeOffer);
        // Differential: consensus verifies the wallet's freeze at its creation head.
        trading_v1::verify_frozen_treasury_offer_at_creation(
            FrozenTreasuryOffer::decode(signed.bytes()).unwrap(),
            view.state(),
            view.anchor(),
            view.state_root(),
            &policy,
        )
        .expect("consensus verifies the freeze");
        outbox_t.commit(&signed, &view).unwrap();
        (
            signed,
            view.state().clone(),
            view.anchor().clone(),
            view.state_root(),
            treasury_offer,
        )
    };
    let verified = trading_v1::verify_frozen_treasury_offer_at_creation(
        FrozenTreasuryOffer::decode(frozen.bytes()).unwrap(),
        &creation_state,
        &creation_anchor,
        creation_root,
        &policy,
    )
    .unwrap();
    // Canonical first funding BEFORE R1/R2: the exact original terms become obligations.
    let funding = tkit::funding_lock(
        &h.view(&none),
        &treasury_offer,
        &treasury_maker,
        [0x21; 32],
        [0x22; 32],
        &key_a,
        (outpoint(0xa2, 0), 3_000_000),
        &key_t,
        a1,
        100_000,
    );
    trading_v1::prepare_treasury_funding(
        h.state(),
        &h.anchor(),
        h.state().root().unwrap(),
        &verified,
        &funding,
        &policy,
    )
    .unwrap();
    let funding_raw = funding.encode().unwrap();
    let funded_lock = funding.operation.output_id(0).unwrap();
    h.step_with(&[funding_raw]);
    assert_eq!(h.height(), 18);
    let exact_lock = trading_v1::locked(h.state(), funded_lock).unwrap();
    assert_eq!(exact_lock.recipient, a1);
    assert_eq!(
        settled(&h, &mut outbox_t, &frozen.id()),
        OutboxStatus::InputsSpent
    );
    // A distinct still-unfunded old offer is retained as the retired-generation negative.
    let mut old_body = treasury_offer.body.clone();
    old_body.nonce = [0x53; 32];
    let old_unfunded = SignedOffer::sign(old_body, &key_t).unwrap();
    // ================================================================ block 19: Treasury R1
    let me_t1 = tkit::declared(&key_t, 1, None, &h.view(&none), true, None);
    let part = {
        let view = h.view(&none);
        let planned = plan(
            &rotate(&key_t2(), 2, FeeSource::OtherWallet(me_a.clone())),
            &view,
            &me_t1,
        )
        .unwrap();
        let reviewed = review(&planned, &view).unwrap();
        assert!(
            reviewed
                .acknowledgements()
                .contains(&AckKind::TreasuryAuthority)
        );
        RotationSigner::new(
            treasury_wallet_key(),
            me_t1.clone(),
            key_t2(),
            SigningGate::test_value().unwrap(),
            DEFAULT_IDLE_LIMIT,
        )
        .unwrap()
        .authorize(planned, flow::approve(&reviewed, &view), &view)
        .unwrap()
    };
    assert!(!part.is_complete());
    recognised_as(part.bytes(), OperationKind::WalletRotation);
    outbox_t.commit(&part, &h.view(&none)).unwrap();
    let funding_part = {
        let view = h.view(&none);
        let exported = PartialApproval::from_signed(&part, view.context())
            .unwrap()
            .export()
            .unwrap();
        let adopted = PartialApproval::import(&exported)
            .unwrap()
            .adopt_for(&view, &me_a)
            .unwrap();
        flow::sign(adopted, &signer_a, &view).unwrap()
    };
    recognised_as(funding_part.bytes(), OperationKind::WalletRotation);
    let r1 = combine(&[part.bytes(), funding_part.bytes()], &h.view(&none)).unwrap();
    both_accept_transaction(&h, &r1);
    assert_eq!(
        outbox_t
            .replace_partial(&part.id(), &r1, &h.view(&none))
            .unwrap(),
        r1.id()
    );
    h.admit(&Transaction::decode(r1.bytes()).unwrap()).unwrap();
    let after = h.step();
    assert_eq!(
        after.wallets.current(a1).unwrap(),
        descriptor_of(&key_t2(), 2).as_slice()
    );
    assert_eq!(
        settled(&h, &mut outbox_t, &r1.id()),
        OutboxStatus::Confirmed(19)
    );
    // The old Treasury key is stale now, even with the profile.
    assert_eq!(
        plan(
            &rotate(&key_d(), 2, FeeSource::OtherWallet(me_a.clone())),
            &h.view(&none),
            &me_t1
        )
        .unwrap_err(),
        Refusal::StaleAuthority
    );

    assert_eq!(
        trading_v1::locked(h.state(), funded_lock).unwrap(),
        exact_lock
    );
    let me_t2 = tkit::declared(
        &key_t2(),
        2,
        Some(a1),
        &h.view(&none),
        true,
        Some(TRADING_TREASURY),
    );
    let signer_t2 = signer_for(key_t2(), &me_t2);
    // R2 only routes to the now-current T2 authority. The nonsecret exact-descriptor
    // rehearsal assertion is a public TEST host seam, not a physical backup proof.
    let r2 = {
        let view = h.view(&none);
        let desc = descriptor_of(&key_t2(), 2);
        let request = TreasuryRotateRequest::new(Blob::new(desc.clone()))
            .with_treasury(TRADING_TREASURY)
            .with_verified_restore(TRADING_TREASURY, trading_v1::descriptor_hash(&desc));
        let p = plan(&OperationRequest::TreasuryRotate(request), &view, &me_t2).unwrap();
        let rendered = review(&p, &view).unwrap();
        assert!(rendered.requires_phrase());
        assert!(
            rendered
                .acknowledgements()
                .contains(&AckKind::TreasuryAuthority)
        );
        signer_t2
            .authorize(p, flow::approve(&rendered, &view), &view)
            .unwrap()
    };
    both_accept_operation(&h, &r2);
    outbox_t.commit(&r2, &h.view(&none)).unwrap();
    h.step_with(&[r2.bytes().to_vec()]);
    let current =
        trading_v1::treasury_current(h.state(), &treasury_context, TRADING_TREASURY).unwrap();
    assert_eq!(
        (
            current.generation,
            current.address,
            current.effective_height
        ),
        (2, a2, 20)
    );
    assert_eq!(
        settled(&h, &mut outbox_t, &r2.id()),
        OutboxStatus::Confirmed(20)
    );
    assert_eq!(
        trading_v1::locked(h.state(), funded_lock).unwrap(),
        exact_lock
    );
    // Current settlement approvals cannot authorize an old maker's first funding.
    {
        let view = h.view(&none);
        let coin = largest_coin(view.state(), a);
        let mut stale = tkit::funding_lock(
            &view,
            &old_unfunded,
            &treasury_maker,
            [0x31; 32],
            [0x32; 32],
            &key_a,
            coin,
            &key_t,
            a1,
            100_000,
        );
        stale.operation.approvals.clear();
        stale.operation.approve(0, &key_a, 1).unwrap();
        stale.operation.approve(1, &key_t2(), 2).unwrap();
        let before = h.canonical_rows();
        assert!(SignedOperation::import(&stale.encode().unwrap(), &view).is_err());
        assert_eq!(
            ckit::consensus_in(&view, &stale.encode().unwrap()).unwrap_err(),
            NativeError::Authority
        );
        assert_eq!(h.canonical_rows(), before);
    }
    // A current maker cannot newly freeze an obsolete routing generation.
    {
        let view = h.view(&none);
        let mut body = treasury_offer.body.clone();
        body.maker_descriptor = descriptor_of(&key_t2(), 2);
        body.maker_wallet = a2;
        body.destination = a2;
        body.nonce = [0x52; 32];
        body.created = h.height();
        body.expiry = h.height() + 40;
        let current_offer = SignedOffer::sign(body, &key_t2()).unwrap();
        let stale_terms = FreezeTerms {
            treasury: TRADING_TREASURY,
            generation: 1,
            address: a1,
            trade: [0x31; 32],
            contract: [0x32; 32],
            wallet_descriptor: descriptor_of(&key_t2(), 2),
        };
        assert!(tkit::prepare_freeze(&view, &stale_terms, &current_offer).is_err());
        let body = tkit::freeze_body(
            &treasury_context,
            view.anchor(),
            view.state_root(),
            &stale_terms,
            &current_offer.body,
        );
        let proposal =
            treasury::freeze_proposal(&body, &tkit::offer_import(&current_offer)).unwrap();
        assert_eq!(
            plan(
                &OperationRequest::TreasuryFreezeOffer(TreasuryFreezeOfferRequest::new(Blob::new(
                    proposal
                ))),
                &view,
                &me_t2
            )
            .unwrap_err(),
            Refusal::TreasuryGeneration(treasury::REASON_FREEZE_GENERATION)
        );
    }
    // Current authority settles the already-funded historical destination; no term is rewritten.
    let settlement = {
        let view = h.view(&none);
        let p = plan(
            &OperationRequest::ConditionalClaim(ClaimRequest::new(
                funded_lock,
                Preimage::from_bytes([0x42; 32]),
            )),
            &view,
            &me_t2,
        )
        .unwrap();
        flow::sign(p, &signer_t2, &view).unwrap()
    };
    both_accept_operation(&h, &settlement);
    outbox_t.commit(&settlement, &h.view(&none)).unwrap();
    h.step_with(&[settlement.bytes().to_vec()]);
    assert_eq!(h.height(), 21);
    assert_eq!(
        settled(&h, &mut outbox_t, &settlement.id()),
        OutboxStatus::Confirmed(21)
    );
    let payout = &h.state().coins[&OutPoint {
        transaction: settlement.id(),
        index: 0,
    }];
    assert_eq!(
        (payout.output.owner, payout.output.atoms),
        (a1, exact_lock.amount.0)
    );

    // Q17: the actual post-sale buyer supplies a fresh public Worker possession proof.
    // Only owner hybrid signatures enter the wallet; the public device test key stays in fixtures.
    let assignment_epoch = h.view(&none).epoch().unwrap();
    let assignment = {
        let view = h.view(&none);
        let record = view.state().licenses_v2.license(license).unwrap();
        assert_eq!(record.owner, b);
        let desc = view
            .state()
            .membership_v2
            .get(h.node())
            .unwrap()
            .binding()
            .node_descriptor
            .clone();
        let terms = mutiny_consensus_v8::license_assignment_v2::DeliveryTerms::at(
            record,
            view.next_height().unwrap(),
            assignment_epoch,
        )
        .unwrap();
        let mut binding = mutiny_crypto_v2::enrollment::Binding {
            genesis: view.anchor().genesis,
            fingerprint: view.anchor().fingerprint,
            license,
            owner_descriptor: mutiny_crypto_v2::enrollment::owner_descriptor_id(key_b.public(), 1)
                .unwrap(),
            owner_generation: 1,
            worker_public: rig::licenses::worker(0x71),
            worker_id: [0; 32],
            coordinator: mutiny_consensus_v8::work_authority_v2::node_identity(&desc).unwrap(),
            configuration_generation: 1,
            device_mac: [2, 0, 0, 0, 0, 0x71],
            assignment_generation: terms.assignment_generation,
            effective_epoch: terms.effective_epoch,
            valid_until_height: terms.min_valid_until_height,
        };
        binding.worker_id = binding.derived_worker_id();
        let public = rig::licenses::sign(binding, &key_b, &desc, 0x71);
        let request = WorkerAssignmentRequest::new(
            Blob::new(public.enrollment.binding.bytes().unwrap()),
            Blob::new(desc),
            Blob::new(public.enrollment.worker_signature.to_vec()),
        );
        let p = plan(&OperationRequest::WorkerAssignment(request), &view, &me_b).unwrap();
        let signed = flow::sign(p, &signer_b, &view).unwrap();
        recognised_as(signed.bytes(), OperationKind::WorkerAssignment);
        (signed, public.enrollment.binding)
    };
    SignedOperation::import(assignment.0.bytes(), &h.view(&none)).unwrap();
    h.prepare_at_epoch(assignment_epoch, &[assignment.0.bytes().to_vec()])
        .unwrap();
    outbox_b.commit(&assignment.0, &h.view(&none)).unwrap();
    h.step_at_with(assignment_epoch, &[assignment.0.bytes().to_vec()]);
    assert_eq!(
        settled(&h, &mut outbox_b, &assignment.0.id()),
        OutboxStatus::Confirmed(22)
    );
    h.step(); // The existing epoch transition, not local activation, makes it current.
    assert_eq!(
        h.state()
            .licenses_v2
            .license(license)
            .unwrap()
            .active_worker,
        Some(assignment.1.worker_id)
    );

    // ================================================================ the whole run, reconciled
    assert_eq!(h.height(), 23);
    let mut kinds = BTreeSet::new();
    for outbox in [
        &mut outbox_a as &mut dyn Outbox,
        &mut outbox_b,
        &mut outbox_c,
        &mut outbox_d,
        &mut outbox_t,
    ] {
        let confirmations = h.confirmations();
        let view = h.view(&none).with_confirmations(&confirmations);
        let report = outbox.reconcile(&view).unwrap();
        assert_eq!(report.still_pending, 0, "{report:?}");
        assert!(outbox.reserved().unwrap().is_empty());
        for record in outbox.records().unwrap() {
            kinds.insert(record.kind);
        }
    }
    // Every kind is exercised. MakerOffer and TreasuryFreezeOffer stay above-consensus
    // witnesses, consumed by actual first funding; BondWithdraw uses the explicitly
    // synthetic parent above.
    // Every other queued carrier is installed on this one certified chain.
    let queued: BTreeSet<OperationKind> = OperationKind::ALL
        .iter()
        .copied()
        .filter(|kind| *kind != OperationKind::BondWithdraw)
        .collect();
    assert_eq!(kinds, queued);
    drop(outbox_d);
    let h = h.restart();
    assert_eq!(h.height(), 23);
    assert_eq!(
        h.state()
            .licenses_v2
            .license(license)
            .unwrap()
            .active_worker,
        Some(assignment.1.worker_id)
    );
    println!(
        "PUBLIC TEST-VALUE matrix canonical evidence retained: {}",
        h.evidence_directory().display()
    );
    // Preserve the fully replayed store; no cleanup or physical qualification claim.
}
