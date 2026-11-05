//! Review completeness for License DvP, fiat lock and fiat release: every item the phase brief
//! requires is a row (buyer and seller views differ where they must), no field of the unsigned
//! operation can change without the rows a person reads changing (or the bytes being refused), and
//! the text renderings are pinned by golden snapshots. NATIVE, TEST-VALUE; public test keys only.
//!
//! The maker's trade identity is a fresh random transport key in every run, so the golden snapshots
//! replace the four values derived from it (offer identifier, maker identity, review digest and
//! confirmation phrase) with fixed tokens; every other character is pinned.
#[path = "support/synthetic.rs"]
mod synthetic;
#[path = "support/trading_5b.rs"]
mod trading;

use mutiny_consensus_v8::{
    Hash,
    trading_v1::{Action, NativeOperation, SignedOffer},
};
use mutiny_crypto_v2::HybridKey;
use mutiny_wallet_core_v8::*;
use synthetic::{World, address, descriptor, identity, key_a, key_b, key_c};

const PRICE: u64 = 2_000_000;
const TRADE: [u8; 32] = [0x71; 32];
const CONTRACT: [u8; 32] = [0x72; 32];

/// The standard scenario: head 100; seller A owns the first License of the public Book; buyer B
/// holds two coins; C is the TEST-VALUE Treasury and the first award boundary has been processed,
/// so the License has an unclaimed award.
struct Scenario {
    world: World,
    license: Hash,
    offer: SignedOffer,
}

fn scenario() -> Scenario {
    let mut world = World::new(100);
    for key in [key_a(), key_b()] {
        world.state.wallets.register(&descriptor(&key, 1)).unwrap();
    }
    let license = trading::install_licenses(&mut world.state, address(&key_a(), 1), false);
    trading::install_award(&mut world.state, &key_c(), 1_200_000, 0xd1);
    world.coin(address(&key_b(), 1), 5_000_000, 1, false, 0xb1, 0);
    world.coin(address(&key_b(), 1), 3_000_000, 1, false, 0xb2, 0);
    assert!(world.state.root().is_ok());
    let maker = trading::maker();
    let offer = trading::offer(
        &maker,
        trading::context_of(&world.anchor),
        trading::license_terms(license, 1, PRICE),
        50,
        200,
        0,
        0x31,
    );
    Scenario {
        world,
        license,
        offer,
    }
}

fn request(offer: &SignedOffer, license: Hash) -> LicenseDvpRequest {
    LicenseDvpRequest::new(Blob::new(trading::offer_bytes(offer)), license)
        .with_commitments(TRADE, CONTRACT)
}

fn buyer_plan(s: &Scenario) -> OperationPlan {
    plan(
        &OperationRequest::LicenseDvp(request(&s.offer, s.license)),
        &s.world.view(),
        &identity(&key_b()),
    )
    .unwrap()
}

fn rows_of(review: &Review, section: Section) -> Vec<Row> {
    review
        .rows()
        .into_iter()
        .filter(|row| row.section == section)
        .collect()
}

/// What a person READS: every row but the binding digest (which changes with any byte) and the
/// confirmation phrase derived from it.
fn read(review: &Review) -> Vec<Row> {
    review
        .rows()
        .into_iter()
        .filter(|row| row.section != Section::Binding && row.label != "Type to confirm")
        .collect()
}

fn text_has(review: &Review, needle: &str) -> bool {
    review.render_text().contains(needle)
}

#[test]
fn the_buyer_review_shows_everything_a_license_purchase_requires() {
    let s = scenario();
    let view = s.world.view();
    let planned = buyer_plan(&s);
    let reviewed = review(&planned, &view).unwrap();
    let wire = NativeOperation::decode(&planned.objects()[0].bytes).unwrap();
    let op = &wire.operation;
    let Action::LicenseDvp { change, .. } = op.action else {
        panic!("a License sale")
    };
    let seller = address(&key_a(), 1);
    let buyer = address(&key_b(), 1);
    let offer_id = s.offer.body.id().unwrap();
    let maker_id = s.offer.body.maker().unwrap();
    let text = reviewed.render_text();

    assert!(reviewed.title().starts_with("Buy License "));
    // License id and index, CURRENT generation.
    let license_row = rows_of(&reviewed, Section::Conditions)
        .into_iter()
        .find(|r| r.label == "License")
        .unwrap();
    assert!(license_row.value.contains(&hex::encode(s.license)));
    assert!(license_row.value.contains("index "));
    assert!(license_row.value.contains("current native generation 1"));
    // Seller, buyer and maker.
    let parties: Vec<(PartyRole, Hash, AddressLabel)> = reviewed
        .parties()
        .iter()
        .map(|p| (p.role, p.address, p.label))
        .collect();
    assert_eq!(
        parties,
        [
            (PartyRole::Seller, seller, AddressLabel::External),
            (PartyRole::Buyer, buyer, AddressLabel::ThisWallet),
            (PartyRole::Maker, maker_id, AddressLabel::External),
        ]
    );
    // The price in STRIKES and in MUT, to the payment destination, with the typed check.
    assert!(text.contains("0.02000000 MUT (2000000 STRIKES)"));
    assert_eq!(
        reviewed.destinations()[0],
        Destination {
            role: DestinationRole::LicensePayment,
            address: seller,
            label: AddressLabel::External,
            atoms: PRICE
        }
    );
    assert_eq!(reviewed.destinations_needing_check(), vec![0]);
    // Inputs, change and fee with the trading rule and payer = buyer.
    assert_eq!(reviewed.inputs().len(), 1);
    assert!(reviewed.inputs()[0].owned_by_signer);
    assert_eq!(reviewed.returned(), change.0);
    assert_eq!(reviewed.destinations()[1].role, DestinationRole::Change);
    assert_eq!(reviewed.fee().rule, FeeRule::TradingMinimum { floor: 240 });
    assert_eq!(reviewed.fee().payer, FeePayer::ThisWallet);
    let fee_row = rows_of(&reviewed, Section::Money)
        .into_iter()
        .find(|r| r.label == "Network fee")
        .unwrap();
    assert!(fee_row.value.contains("the greater of 240 STRIKES"));
    assert!(fee_row.value.contains("paid by this wallet"));
    // Offer id, maker identity, validity window with the approximate duration labelled.
    let offer_row = rows_of(&reviewed, Section::Conditions)
        .into_iter()
        .find(|r| r.label == "Offer")
        .unwrap();
    assert!(offer_row.value.contains(&hex::encode(offer_id)));
    assert!(offer_row.value.contains(&hex::encode(maker_id)));
    assert!(offer_row.value.contains("fillable in blocks 50 to 200"));
    assert!(offer_row.value.contains("approximate"));
    assert!(
        offer_row
            .value
            .contains("exact settlement slot, destination, condition and maximum fee"),
        "{}",
        offer_row.value
    );
    assert!(
        offer_row
            .value
            .contains("current maker authority is required at first canonical funding")
    );
    // TradeID and ContractHash as opaque commitments with the Q8 warning.
    assert!(text.contains(&hex::encode(TRADE)) && text.contains(&hex::encode(CONTRACT)));
    assert!(
        reviewed
            .warnings()
            .iter()
            .any(|w| w.code == "OPAQUE_COMMITMENTS")
    );
    // The immutable signed window and its canonical reference are prominent.
    assert_eq!(reviewed.timing().valid_only_at, None);
    assert_eq!(reviewed.timing().created_height, Some(101));
    assert_eq!(reviewed.timing().expiry_height, Some(102));
    assert!(
        rows_of(&reviewed, Section::Timing)
            .iter()
            .any(|r| r.label == "Valid from block" && r.value == "101")
    );
    let single = reviewed
        .warnings()
        .iter()
        .find(|w| w.code == "SIGNED_WINDOW")
        .unwrap();
    assert_eq!(
        (single.severity, single.requires),
        (Severity::Caution, Some(AckKind::Conditions))
    );
    assert!(text.contains("Signed inclusion heights 101 through 102"));
    assert!(text.contains("canonical reference height 100"));
    // Which approvals are still missing (before signing, the buyer's own too).
    assert!(text.contains(
        "Still missing: the seller's approval (slot 0), the buyer's approval (slot 1), the maker's fill signature"
    ));
    // Exact native P5 dividend facts, including the amount and claim sequence, are signed.
    let dividends = rows_of(&reviewed, Section::Conditions)
        .into_iter()
        .find(|r| r.label == "Dividends")
        .unwrap();
    assert!(
        dividends
            .value
            .contains("binds the COMPLETE live-account list")
    );
    assert!(dividends.value.contains("after 0 claim(s)"));
    assert!(dividends.value.contains("award epoch 131072"));
    assert!(reviewed.acknowledgements().contains(&AckKind::Conditions));
    // The exact native assignment facts are signed; inclusion clears work and cancels only that
    // committed pending assignment, rather than rejecting every pending assignment.
    assert!(text.contains("Commit assignment sequence"));
    assert!(text.contains("pending assignment none"));
    assert!(text.contains("changed assignment fact requires fresh review"));
    // Irreversible consequences, each marked.
    let irreversible: Vec<String> = reviewed
        .effects()
        .iter()
        .filter(|e| e.irreversible)
        .map(|e| e.text.clone())
        .collect();
    for needle in [
        "moves from",
        "native transfer generation becomes 2",
        "current Worker authority",
        "rights start at H + 1 after actual canonical inclusion",
        "Consumes offer",
        "Pays the price",
        "trading fee",
        "cannot be revoked",
    ] {
        assert!(
            irreversible.iter().any(|t| t.contains(needle)),
            "irreversible effect {needle:?} in {irreversible:#?}"
        );
    }
    assert!(text.contains("FRESH Worker assignment"), "Q17 stated");
    // High risk: a typed confirmation phrase.
    assert!(reviewed.requires_phrase());
    assert!(text.contains("Type to confirm: CONFIRM "));
    // TEST-VALUE chain declared.
    assert_eq!(view.class(), ChainClass::TestValue);
    assert!(
        reviewed
            .warnings()
            .iter()
            .any(|w| w.code == "TEST_VALUE_CHAIN")
    );
}

#[test]
fn the_seller_review_says_what_the_seller_receives_and_loses() {
    let s = scenario();
    let view = s.world.view();
    let planned = buyer_plan(&s);
    let seen = explain(&planned.objects()[0].bytes, &view, &identity(&key_a())).unwrap();
    assert!(seen.title().starts_with("Sell License "));
    assert_eq!(seen.binding(), review(&planned, &view).unwrap().binding());
    let text = seen.render_text();
    assert!(text.contains("This wallet receives the price of 0.02000000 MUT (2000000 STRIKES)"));
    assert!(text.contains("This wallet loses License"));
    assert!(text.contains("its remaining dividend entitlements and its mining rights"));
    assert!(text.contains(
        "The reward of the actual inclusion block H is still attributed to this wallet."
    ));
    // The price goes to the seller's own address: no typed check for the seller.
    assert_eq!(seen.destinations()[0].label, AddressLabel::ThisWallet);
    assert!(seen.destinations_needing_check().is_empty());
    // The buyer's coins are shown (not the seller's), the buyer pays the fee.
    assert!(seen.inputs().iter().all(|i| !i.owned_by_signer));
    assert_eq!(
        seen.fee().payer,
        FeePayer::Counterparty(address(&key_b(), 1))
    );
    assert_eq!(seen.net_debit(), None);
    assert_eq!(seen.returned(), 0);
    let dividends = seen
        .warnings()
        .iter()
        .find(|w| w.code == "BOUND_DIVIDENDS")
        .unwrap();
    assert_eq!(dividends.severity, Severity::Danger);
    assert!(
        dividends
            .text
            .contains("prior claim invalidates this exact signed sale")
    );
    // An observer signs nothing.
    let observer = explain(&planned.objects()[0].bytes, &view, &identity(&key_c())).unwrap();
    assert_eq!(observer.title(), "License sale between other wallets");
    assert!(
        observer
            .authorizations()
            .iter()
            .all(|r| r.status != RequirementStatus::ThisWallet)
    );
}

#[test]
fn a_payment_destination_other_than_the_seller_is_flagged_for_both_sides() {
    let mut s = scenario();
    let elsewhere = [0x5e; 32];
    let mut body = s.offer.body.clone();
    body.destination = elsewhere;
    s.offer = SignedOffer::sign(body, &key_a()).unwrap();
    let view = s.world.view();
    let planned = plan(
        &OperationRequest::LicenseDvp(
            request(&s.offer, s.license).with_payment_destination(elsewhere),
        ),
        &view,
        &identity(&key_b()),
    )
    .unwrap();
    let buyer_view = review(&planned, &view).unwrap();
    let flag = buyer_view
        .warnings()
        .iter()
        .find(|w| w.code == "PAYMENT_NOT_TO_SELLER")
        .unwrap();
    assert_eq!(flag.severity, Severity::Caution);
    assert!(text_has(&buyer_view, &hex::encode(elsewhere)));
    let seller_view = explain(&planned.objects()[0].bytes, &view, &identity(&key_a())).unwrap();
    let flag = seller_view
        .warnings()
        .iter()
        .find(|w| w.code == "PAYMENT_NOT_TO_SELLER")
        .unwrap();
    assert_eq!(flag.severity, Severity::Danger);
    assert_eq!(seller_view.destinations()[0].label, AddressLabel::External);
    assert_eq!(seller_view.destinations_needing_check(), vec![0]);
    assert!(seller_view.summary().contains("(not this wallet)"));
}

/// Every field of the unsigned DvP, changed one at a time: the change is refused or shows up in
/// what the buyer, the seller and an observer read.
#[test]
fn every_field_of_the_unsigned_license_sale_shows_up_or_is_refused() {
    let s = scenario();
    let view = s.world.view();
    let planned = buyer_plan(&s);
    let raw = planned.objects()[0].bytes.clone();
    let viewers = [identity(&key_b()), identity(&key_a()), identity(&key_c())];
    let base: Vec<Vec<Row>> = viewers
        .iter()
        .map(|me| read(&explain(&raw, &view, me).unwrap()))
        .collect();
    type Edit = Box<dyn Fn(&mut NativeOperation)>;
    let dvp = |change: Box<dyn Fn(&mut Action)>| -> Edit {
        Box::new(move |wire: &mut NativeOperation| change(&mut wire.operation.action))
    };
    // (name, edit, the new value must appear in the text)
    let cases: Vec<(&str, Edit, Option<String>)> = vec![
        (
            "network",
            Box::new(|w| w.operation.meta.context.network ^= 1),
            None,
        ),
        (
            "genesis",
            Box::new(|w| w.operation.meta.context.genesis[0] ^= 1),
            None,
        ),
        (
            "fingerprint",
            Box::new(|w| w.operation.meta.context.fingerprint[0] ^= 1),
            None,
        ),
        (
            "trade",
            Box::new(|w| w.operation.meta.trade = [0x7a; 32]),
            Some(hex::encode([0x7a; 32])),
        ),
        (
            "contract",
            Box::new(|w| w.operation.meta.contract = [0x7b; 32]),
            Some(hex::encode([0x7b; 32])),
        ),
        (
            "operation generation",
            Box::new(|w| w.operation.meta.generation = 7),
            Some("Trade operation generation 7".into()),
        ),
        (
            "created",
            Box::new(|w| w.operation.meta.envelope.first_height = 99),
            Some("Valid from block: 99".into()),
        ),
        (
            "expiry",
            Box::new(|w| w.operation.meta.envelope.last_height = 150),
            Some("150".into()),
        ),
        (
            "fee and change",
            Box::new(|w| {
                w.operation.meta.fee.0 += 5;
                if let Action::LicenseDvp { change, .. } = &mut w.operation.action {
                    change.0 -= 5;
                }
            }),
            Some("atoms above the minimum".into()),
        ),
        (
            "inputs",
            Box::new(|w| {
                let extra = mutiny_consensus_v8::transactions::OutPoint {
                    transaction: [0xb2; 32],
                    index: 0,
                };
                let mut points = w.inputs.clone();
                points.push(extra);
                let mut sorted: Vec<_> = points
                    .iter()
                    .map(|p| {
                        (
                            mutiny_consensus_v8::trading_v1::native_input_id(p),
                            p.clone(),
                        )
                    })
                    .collect();
                sorted.sort();
                w.operation.meta.inputs = sorted.iter().map(|(id, _)| *id).collect();
                w.inputs = sorted.into_iter().map(|(_, p)| p).collect();
                // One more input lengthens the bytes: the fee rises with them.
                w.operation.meta.fee.0 += 200;
                if let Action::LicenseDvp { change, .. } = &mut w.operation.action {
                    change.0 += 3_000_000 - 200;
                }
            }),
            Some(hex::encode([0xb2; 32])),
        ),
        (
            "offer",
            dvp(Box::new(|a| {
                if let Action::LicenseDvp { offer, .. } = a {
                    offer[0] ^= 1
                }
            })),
            None,
        ),
        (
            "maker",
            dvp(Box::new(|a| {
                if let Action::LicenseDvp { maker, .. } = a {
                    maker[0] ^= 1
                }
            })),
            None,
        ),
        (
            "license",
            dvp(Box::new(|a| {
                if let Action::LicenseDvp { license, .. } = a {
                    license[0] ^= 1
                }
            })),
            None,
        ),
        (
            "license generation",
            dvp(Box::new(|a| {
                if let Action::LicenseDvp {
                    license_generation, ..
                } = a
                {
                    *license_generation = 2
                }
            })),
            None,
        ),
        (
            "seller",
            dvp(Box::new(|a| {
                if let Action::LicenseDvp { seller, .. } = a {
                    seller[0] ^= 1
                }
            })),
            None,
        ),
        (
            "buyer",
            dvp(Box::new(|a| {
                if let Action::LicenseDvp { buyer, .. } = a {
                    buyer[0] ^= 1
                }
            })),
            None,
        ),
        (
            "price",
            dvp(Box::new(|a| {
                if let Action::LicenseDvp { price, change, .. } = a {
                    price.0 += 1;
                    change.0 -= 1;
                }
            })),
            None,
        ),
        (
            "payment destination",
            dvp(Box::new(|a| {
                if let Action::LicenseDvp {
                    payment_destination,
                    ..
                } = a
                {
                    *payment_destination = [0x5d; 32]
                }
            })),
            None, // Changing the maker-bound destination without a new maker offer is refused.
        ),
        (
            "change",
            dvp(Box::new(|a| {
                if let Action::LicenseDvp { change, .. } = a {
                    change.0 -= 1
                }
            })),
            None,
        ),
        (
            "signed inclusion window",
            Box::new(|w| w.operation.meta.envelope.last_height += 1),
            None,
        ),
        (
            "seller descriptor",
            Box::new(|w| w.operation.approvals[0].descriptor = descriptor(&key_c(), 1)),
            None,
        ),
        (
            "buyer descriptor",
            Box::new(|w| w.operation.approvals[1].descriptor = descriptor(&key_c(), 1)),
            None,
        ),
        (
            "seller signature placeholder",
            Box::new(|w| w.operation.approvals[0].signature.ed448[0] = 1),
            Some("does not verify".into()),
        ),
        (
            "buyer signature placeholder",
            Box::new(|w| w.operation.approvals[1].signature.fndsa[0] = 0x3a),
            Some("does not verify".into()),
        ),
        (
            "fill placeholder",
            Box::new(|w| {
                w.operation
                    .offer_proof
                    .as_mut()
                    .unwrap()
                    .fill_signature
                    .ed448[5] = 9
            }),
            // Since W19 a fill that does not verify is refused by the one offer check (before: shown
            // with a BAD_SIGNATURE warning).
            None,
        ),
        (
            "offer body",
            Box::new(|w| w.operation.offer_proof.as_mut().unwrap().offer.body.nonce[0] ^= 1),
            None,
        ),
        (
            "offer signature",
            Box::new(|w| {
                w.operation
                    .offer_proof
                    .as_mut()
                    .unwrap()
                    .offer
                    .signature
                    .ed448[0] ^= 1
            }),
            None,
        ),
    ];
    let (mut refused, mut visible) = (0, 0);
    for (name, edit, needle) in &cases {
        let mut wire = NativeOperation::decode(&raw).unwrap();
        edit(&mut wire);
        let Ok(changed) = wire.encode() else {
            refused += 1;
            continue;
        };
        for (index, me) in viewers.iter().enumerate() {
            match explain(&changed, &view, me) {
                Err(_) => {
                    assert!(
                        needle.is_none(),
                        "{name}: expected a visible change, got a refusal"
                    );
                    refused += 1;
                }
                Ok(other) => {
                    assert_ne!(
                        read(&other),
                        base[index],
                        "{name}: changed but invisible to viewer {index}"
                    );
                    if let Some(needle) = needle {
                        assert!(
                            other.render_text().contains(needle.as_str()),
                            "{name}: {needle:?} not shown to viewer {index}"
                        );
                    }
                    visible += 1;
                }
            }
        }
    }
    assert!(
        refused > 0 && visible > 0,
        "refused {refused}, visible {visible}"
    );
}

#[test]
fn no_byte_of_the_unsigned_license_sale_can_change_unnoticed() {
    let s = scenario();
    let view = s.world.view();
    let planned = buyer_plan(&s);
    let me = identity(&key_a());
    let bytes = planned.objects()[0].bytes.clone();
    let base = explain(&bytes, &view, &me).unwrap();
    let base_rows = read(&base);
    let (mut refused, mut visible) = (0usize, 0usize);
    for index in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[index] ^= 0x01;
        match explain(&changed, &view, &me) {
            Err(_) => refused += 1,
            Ok(other) => {
                assert_ne!(
                    read(&other),
                    base_rows,
                    "byte {index} changed nothing a person reads"
                );
                if other.binding() == base.binding() {
                    assert!(
                        other.warnings().iter().any(|w| w.code == "BAD_SIGNATURE"),
                        "byte {index}: a signature byte must show as a signature that does not verify"
                    );
                }
                visible += 1;
            }
        }
    }
    assert!(
        refused > 0 && visible > 0,
        "refused {refused}, visible {visible}"
    );
    assert_eq!(refused + visible, bytes.len());
}

#[test]
fn rows_are_filled_in_display_order_and_the_rendering_is_stable() {
    let s = scenario();
    let reviewed = review(&buyer_plan(&s), &s.world.view()).unwrap();
    let rows = reviewed.rows();
    assert!(
        rows.iter()
            .all(|r| !r.label.is_empty() && !r.value.is_empty())
    );
    let mut last = Section::Summary;
    for row in &rows {
        assert!(row.section >= last);
        last = row.section;
    }
    let text = reviewed.render_text();
    assert!(text.lines().all(|line| !line.ends_with(' ')));
    assert_eq!(text, reviewed.render_text());
    assert_eq!(
        rows_of(&reviewed, Section::Acknowledgements).len(),
        reviewed.acknowledgements().len() + 1,
        "every acknowledgement and the confirmation phrase"
    );
}

/// The text with the run-dependent values (all derived from the random maker key) replaced.
fn normalized(review: &Review, s: &Scenario) -> String {
    let phrase = review.confirmation_phrase().unwrap();
    review
        .render_text()
        .replace(&hex::encode(s.offer.body.id().unwrap()), "<OFFER-ID>")
        .replace(&hex::encode(s.offer.body.maker().unwrap()), "<MAKER-ID>")
        .replace(&review.binding().to_hex(), "<REVIEW-DIGEST>")
        .replace(&phrase, "CONFIRM <PHRASE>")
}

/// A License moved between two addresses of ONE rotated wallet: the seller's address is its
/// generation-one authority address, the buyer's its current one, and its current key controls
/// both. The review says "this wallet signs" for both slots, and the plan signs exactly those: both
/// approvals are in the signed part and only the maker's fill is missing. (Before the fixes of the
/// independent wallet review the review said so while the plan signed the buyer's slot only.)
#[test]
fn a_sale_between_two_addresses_of_this_wallet_is_signed_where_the_review_says() {
    use mutiny_consensus_v8::wallet_rotation_v1::Rotation;
    let phrase = mutiny_crypto_v2::rehearsal_keys_v1::label_phrase("w8-dvp-both-new").unwrap();
    let d = HybridKey::wallet_restore(&phrase, mutiny_crypto_v2::Role::WalletOwner).unwrap();
    let mut s = scenario();
    let mut rotation = Rotation {
        network: s.world.anchor.network,
        genesis: s.world.anchor.genesis,
        fingerprint: s.world.anchor.fingerprint,
        authority: address(&key_a(), 1),
        current: descriptor(&key_a(), 1),
        proposed: descriptor(&d, 2),
        created_height: 90,
        expiry_height: 120,
        authorization: trading::zero(),
        possession: trading::zero(),
    };
    rotation.sign(&key_a(), &d).unwrap();
    s.world
        .state
        .wallets
        .apply(
            &rotation,
            s.world.anchor.genesis,
            s.world.anchor.fingerprint,
            95,
        )
        .unwrap();
    let me = SignerIdentity::from_public(d.public(), 2, Some(address(&key_a(), 1))).unwrap();
    s.world.coin(me.address(), 5_000_000, 1, false, 0xd5, 0);
    let mut body = s.offer.body.clone();
    body.maker_descriptor = descriptor(&d, 2);
    // The settlement authority remains A while its current descriptor and new signature are D2.
    s.offer = SignedOffer::sign(body, &d).unwrap();
    let view = s.world.view();
    let planned = plan(
        &OperationRequest::LicenseDvp(request(&s.offer, s.license)),
        &view,
        &me,
    )
    .unwrap();
    let signs: Vec<Slot> = planned
        .requirements()
        .iter()
        .filter(|r| r.status == RequirementStatus::ThisWallet)
        .map(|r| r.slot)
        .collect();
    assert_eq!(
        signs,
        vec![Slot::Approval(0), Slot::Approval(1), Slot::FillSignature]
    );
    let reviewed = review(&planned, &view).unwrap();
    assert!(
        reviewed
            .title()
            .contains("between addresses of this wallet"),
        "{}",
        reviewed.title()
    );
    let rows = rows_of(&reviewed, Section::Authorizations);
    for row in &rows[..2] {
        assert!(row.value.starts_with("this wallet signs"), "{}", row.value);
    }
    let signer = KeySigner::with_identity(
        d,
        me.clone(),
        SigningGate::test_value().unwrap(),
        DEFAULT_IDLE_LIMIT,
    )
    .unwrap();
    let signed = trading::sign_plan(planned, &signer, &view).unwrap();
    assert!(
        signed.is_complete(),
        "the current wallet signs both settlement approvals and its reviewed maker fill"
    );
    assert!(signed.missing().is_empty());
    mutiny_consensus_v8::trading_v1::verify_signatures(signed.bytes()).unwrap();
    trading::consensus(&view, signed.bytes())
        .expect("rotated current maker fills the exact native body");
}

const BUYER_GOLDEN: &str = include_str!("golden/dvp_buyer_review.txt");
const SELLER_GOLDEN: &str = include_str!("golden/dvp_seller_review.txt");

#[test]
fn golden_text_snapshots_of_the_buyer_and_the_seller_reviews() {
    let s = scenario();
    let view = s.world.view();
    let planned = buyer_plan(&s);
    let buyer = normalized(&review(&planned, &view).unwrap(), &s);
    let seller = normalized(
        &explain(&planned.objects()[0].bytes, &view, &identity(&key_a())).unwrap(),
        &s,
    );
    println!("DVP-BUYER-RENDER-BEGIN\n{buyer}DVP-BUYER-RENDER-END");
    println!("DVP-SELLER-RENDER-BEGIN\n{seller}DVP-SELLER-RENDER-END");
    assert!(
        buyer == BUYER_GOLDEN,
        "the buyer review differs from tests/golden/dvp_buyer_review.txt; if deliberate, replace it with:\n{buyer}"
    );
    assert!(
        seller == SELLER_GOLDEN,
        "the seller review differs from tests/golden/dvp_seller_review.txt; if deliberate, replace it with:\n{seller}"
    );
}

// ---------------------------------------------------------------------------------------------
// Fiat lock and release
// ---------------------------------------------------------------------------------------------

const AMOUNT: u64 = 1_500_000;
const TERMS: [u8; 32] = [0x77; 32];

fn fiat_world() -> (World, HybridKey, SignedOffer) {
    let mut world = World::new(100);
    for key in [key_a(), key_b()] {
        world.state.wallets.register(&descriptor(&key, 1)).unwrap();
    }
    world.coin(address(&key_a(), 1), 5_000_000, 1, false, 0xa1, 0);
    world.coin(address(&key_b(), 1), 1_000_000, 1, false, 0xb1, 0);
    let maker = key_b();
    let offer = trading::offer(
        &maker,
        trading::context_of(&world.anchor),
        trading::fiat_terms(AMOUNT, TERMS),
        50,
        200,
        1,
        0x41,
    );
    (world, maker, offer)
}

fn lock_plan(world: &World, offer: &SignedOffer) -> OperationPlan {
    plan(
        &OperationRequest::FiatLock(
            FiatLockRequest::new(
                Blob::new(trading::offer_bytes(offer)),
                address(&key_b(), 1),
                AMOUNT,
                TERMS,
            )
            .with_commitments(TRADE, CONTRACT)
            .with_validity_blocks(20),
        ),
        &world.view(),
        &identity(&key_a()),
    )
    .unwrap()
}

#[test]
fn fiat_reviews_show_the_lock_the_missing_exit_and_the_unverified_settlement() {
    let (world, maker, offer) = fiat_world();
    let view = world.view();
    let planned = lock_plan(&world, &offer);
    let seller_view = review(&planned, &view).unwrap();
    let text = seller_view.render_text();
    assert!(text.contains("0.01500000 MUT (1500000 STRIKES)"));
    assert!(text.contains(&hex::encode(TERMS)));
    assert!(text.contains("No unilateral exit"));
    assert!(text.contains("verifies no fiat"));
    assert!(text.contains("current maker authority is required at first canonical funding"));
    assert!(text.contains("Valid only for blocks 101 to 121"));
    assert_eq!(seller_view.timing().expiry_height, Some(121));
    assert!(
        seller_view
            .acknowledgements()
            .contains(&AckKind::NoUnilateralExit)
    );
    assert!(
        seller_view
            .acknowledgements()
            .contains(&AckKind::ExternalEvidence)
    );
    let buyer_view = explain(&planned.objects()[0].bytes, &view, &identity(&key_b())).unwrap();
    assert_eq!(buyer_view.binding(), seller_view.binding());
    assert_eq!(buyer_view.destinations()[0].label, AddressLabel::ThisWallet);
    // The release, from both sides.
    let lock = trading::sign_all(
        &planned.objects()[0].bytes,
        &[(0, &key_a(), 1), (1, &key_b(), 1)],
        Some((&maker, &offer)),
    );
    let state = trading::consensus(&view, &lock).unwrap().into_state();
    let lock_id = NativeOperation::decode(&lock)
        .unwrap()
        .operation
        .output_id(0)
        .unwrap();
    let mut next = World::new(101);
    next.state = state;
    let release = plan(
        &OperationRequest::FiatRelease(FiatReleaseRequest::new(lock_id)),
        &next.view(),
        &identity(&key_b()),
    )
    .unwrap();
    let buyer_release = review(&release, &next.view()).unwrap();
    assert!(text_has(&buyer_release, &hex::encode(lock_id)));
    assert!(text_has(&buyer_release, "the only way a fiat lock ends"));
    assert_eq!(buyer_release.fee().payer, FeePayer::ThisWallet);
    let seller_release = explain(
        &release.objects()[0].bytes,
        &next.view(),
        &identity(&key_a()),
    )
    .unwrap();
    assert!(text_has(
        &seller_release,
        "Approve only after the fiat payment has reached you"
    ));
    assert!(text_has(&seller_release, "This wallet gives up the locked"));
    assert_eq!(seller_release.destinations_needing_check(), vec![0]);
}

#[test]
fn every_field_of_the_unsigned_fiat_operations_shows_up_or_is_refused() {
    let (world, maker, offer) = fiat_world();
    let view = world.view();
    let planned = lock_plan(&world, &offer);
    let raw = planned.objects()[0].bytes.clone();
    let me = identity(&key_b());
    let base = read(&explain(&raw, &view, &me).unwrap());
    type Edit = Box<dyn Fn(&mut NativeOperation)>;
    let lock_cases: Vec<(&str, Edit)> = vec![
        ("trade", Box::new(|w| w.operation.meta.trade = [0x7a; 32])),
        (
            "contract",
            Box::new(|w| w.operation.meta.contract = [0x7b; 32]),
        ),
        ("generation", Box::new(|w| w.operation.meta.generation = 3)),
        (
            "created",
            Box::new(|w| w.operation.meta.envelope.first_height = 100),
        ),
        (
            "expiry",
            Box::new(|w| w.operation.meta.envelope.last_height = 110),
        ),
        (
            "fee",
            Box::new(|w| {
                w.operation.meta.fee.0 += 5;
                if let Action::FiatLock { change, .. } = &mut w.operation.action {
                    change.0 -= 5;
                }
            }),
        ),
        (
            "offer",
            Box::new(|w| {
                if let Action::FiatLock { offer, .. } = &mut w.operation.action {
                    offer[0] ^= 1
                }
            }),
        ),
        (
            "maker",
            Box::new(|w| {
                if let Action::FiatLock { maker, .. } = &mut w.operation.action {
                    maker[0] ^= 1
                }
            }),
        ),
        (
            "seller",
            Box::new(|w| {
                if let Action::FiatLock { seller, .. } = &mut w.operation.action {
                    seller[0] ^= 1
                }
            }),
        ),
        (
            "buyer",
            Box::new(|w| {
                if let Action::FiatLock { buyer, .. } = &mut w.operation.action {
                    buyer[0] ^= 1
                }
            }),
        ),
        (
            "amount",
            Box::new(|w| {
                if let Action::FiatLock { amount, change, .. } = &mut w.operation.action {
                    amount.0 += 1;
                    change.0 -= 1;
                }
            }),
        ),
        (
            "payment terms",
            Box::new(|w| {
                if let Action::FiatLock { payment_terms, .. } = &mut w.operation.action {
                    payment_terms[0] ^= 1
                }
            }),
        ),
        (
            "change",
            Box::new(|w| {
                if let Action::FiatLock { change, .. } = &mut w.operation.action {
                    change.0 -= 1
                }
            }),
        ),
        (
            "buyer descriptor",
            Box::new(|w| w.operation.approvals[1].descriptor = descriptor(&key_c(), 1)),
        ),
    ];
    for (name, edit) in &lock_cases {
        let mut wire = NativeOperation::decode(&raw).unwrap();
        edit(&mut wire);
        let Ok(changed) = wire.encode() else { continue };
        if let Ok(other) = explain(&changed, &view, &me) {
            assert_ne!(
                read(&other),
                base,
                "fiat lock {name}: changed but invisible"
            );
        }
    }
    // The release.
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
    let mut next = World::new(101);
    next.state = state;
    let release = plan(
        &OperationRequest::FiatRelease(FiatReleaseRequest::new(lock_id)),
        &next.view(),
        &identity(&key_b()),
    )
    .unwrap()
    .objects()[0]
        .bytes
        .clone();
    let seller = identity(&key_a());
    let base = read(&explain(&release, &next.view(), &seller).unwrap());
    let release_cases: Vec<(&str, Edit)> = vec![
        ("trade", Box::new(|w| w.operation.meta.trade = [0x7a; 32])),
        ("generation", Box::new(|w| w.operation.meta.generation = 3)),
        (
            "expiry",
            Box::new(|w| w.operation.meta.envelope.last_height = 110),
        ),
        (
            "fee",
            Box::new(|w| {
                w.operation.meta.fee.0 += 5;
                if let Action::FiatRelease { change, .. } = &mut w.operation.action {
                    change.0 -= 5;
                }
            }),
        ),
        (
            "output",
            Box::new(|w| {
                if let Action::FiatRelease { output, .. } = &mut w.operation.action {
                    output[0] ^= 1
                }
            }),
        ),
        (
            "buyer",
            Box::new(|w| {
                if let Action::FiatRelease { buyer, .. } = &mut w.operation.action {
                    buyer[0] ^= 1
                }
            }),
        ),
        (
            "seller",
            Box::new(|w| {
                if let Action::FiatRelease { seller, .. } = &mut w.operation.action {
                    seller[0] ^= 1
                }
            }),
        ),
        (
            "amount",
            Box::new(|w| {
                if let Action::FiatRelease { amount, .. } = &mut w.operation.action {
                    amount.0 += 1
                }
            }),
        ),
        (
            "payment terms",
            Box::new(|w| {
                if let Action::FiatRelease { payment_terms, .. } = &mut w.operation.action {
                    payment_terms[0] ^= 1
                }
            }),
        ),
        (
            "change",
            Box::new(|w| {
                if let Action::FiatRelease { change, .. } = &mut w.operation.action {
                    change.0 -= 1
                }
            }),
        ),
        (
            "seller signature placeholder",
            Box::new(|w| w.operation.approvals[1].signature.ed448[0] = 1),
        ),
    ];
    for (name, edit) in &release_cases {
        let mut wire = NativeOperation::decode(&release).unwrap();
        edit(&mut wire);
        let Ok(changed) = wire.encode() else { continue };
        if let Ok(other) = explain(&changed, &next.view(), &seller) {
            assert_ne!(
                read(&other),
                base,
                "fiat release {name}: changed but invisible"
            );
        }
    }
}
