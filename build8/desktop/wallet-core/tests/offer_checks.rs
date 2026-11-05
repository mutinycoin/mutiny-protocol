//! Order W19: ONE offer check for every handler that fills a maker's offer (the License sale, the
//! fiat lock and the hash lock; `offers::check_offer`, the hash lock's own mirror merged into it),
//! one request-time rule (`offers::require_fillable`) and one import rule (`offers::import_offer`).
//! The matrix: every failure class, built the same way for each handler, must give the SAME refusal
//! code from every handler and at every entry point that reaches it (a counterparty's `explain` and
//! `adopt` for the bytes, the planner for a request). NATIVE, TEST-VALUE; public test keys, random
//! maker keys.
#[path = "support/conditional_kit.rs"]
mod kit;
#[path = "support/synthetic.rs"]
mod synthetic;
#[path = "support/trading_5b.rs"]
mod trading;

use mutiny_consensus_v8::{
    Hash,
    trading_v1::{
        self, Action, Context, NativeOperation, OfferTerms, SignedOffer, record_key,
        single_fill_key,
    },
};
use mutiny_crypto_v2::HybridKey;
use mutiny_wallet_core_v8::{refusal::ContextField, *};
use synthetic::{World, address, descriptor, identity, key_a, key_b};

const HEAD: u64 = 100;
const TRADE: [u8; 32] = [0x71; 32];
const CONTRACT: [u8; 32] = [0x72; 32];
const OFFER_CREATED: u64 = 50;
const OFFER_EXPIRY: u64 = 200;
const AMOUNT: u64 = 1_000_000;
const PRICE: u64 = 2_000_000;
const REFUND: u64 = 150;
const TERMS: [u8; 32] = [0x77; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Sale,
    FiatLock,
    HashLock,
}

const KINDS: [Kind; 3] = [Kind::Sale, Kind::FiatLock, Kind::HashLock];

/// One handler's base case at head `head` over the same state: A (registered) sells its License
/// to B and owns coins; B (registered) owns coins.
struct Case {
    kind: Kind,
    state: mutiny_consensus_v8::execution::State,
    license: Hash,
    maker: HybridKey,
    offer: SignedOffer,
}

fn base_world(head: u64) -> (World, Hash) {
    let mut world = World::new(head);
    for key in [key_a(), key_b()] {
        world.state.wallets.register(&descriptor(&key, 1)).unwrap();
    }
    let license = trading::install_licenses(&mut world.state, address(&key_a(), 1), false);
    world.coin(address(&key_a(), 1), 5_000_000, 1, false, 0xa1, 0);
    world.coin(address(&key_a(), 1), 4_000_000, 1, false, 0xa2, 0);
    world.coin(address(&key_b(), 1), 5_000_000, 1, false, 0xb1, 0);
    world.coin(address(&key_b(), 1), 3_000_000, 1, false, 0xb2, 0);
    (world, license)
}

fn terms_of(kind: Kind, license: Hash) -> OfferTerms {
    match kind {
        Kind::Sale => trading::license_terms(license, 1, PRICE),
        Kind::FiatLock => trading::fiat_terms(AMOUNT, TERMS),
        Kind::HashLock => OfferTerms::HashLinked {
            amount: trading_v1::Strikes(AMOUNT),
            bitcoin_satoshis: 50_000,
            bitcoin_network: 3,
        },
    }
}

/// The maker side, as the existing tests of each handler use it (0 for a sale and a fiat lock, 1
/// for a hash lock: the maker is the recipient side and the wallet fills as the sender).
fn maker_side(kind: Kind) -> u8 {
    match kind {
        Kind::Sale | Kind::FiatLock => 0,
        Kind::HashLock => 1,
    }
}

fn offer_for(kind: Kind, maker: &HybridKey, context: Context, license: Hash) -> SignedOffer {
    trading::offer(
        maker,
        context,
        terms_of(kind, license),
        OFFER_CREATED,
        OFFER_EXPIRY,
        maker_side(kind),
        0x40 + kind as u8,
    )
}

impl Case {
    fn new(kind: Kind) -> Self {
        let (world, license) = base_world(HEAD);
        let maker = match kind {
            Kind::HashLock => key_b(),
            Kind::Sale | Kind::FiatLock => key_a(),
        };
        let offer = offer_for(kind, &maker, trading::context_of(&world.anchor), license);
        Self {
            kind,
            state: world.state,
            license,
            maker,
            offer,
        }
    }
    fn world(&self, head: u64) -> World {
        World {
            state: self.state.clone(),
            ..World::new(head)
        }
    }
    /// The planner, and the counterparty that explains and adopts the planner's bytes.
    fn planner(&self) -> HybridKey {
        match self.kind {
            Kind::Sale => key_b(),
            Kind::FiatLock | Kind::HashLock => key_a(),
        }
    }
    fn counterparty(&self) -> HybridKey {
        match self.kind {
            Kind::Sale => key_a(),
            Kind::FiatLock | Kind::HashLock => key_b(),
        }
    }
    fn request(&self, offer_bytes: Vec<u8>) -> OperationRequest {
        let offer = Blob::new(offer_bytes);
        match self.kind {
            Kind::Sale => OperationRequest::LicenseDvp(
                LicenseDvpRequest::new(offer, self.license).with_commitments(TRADE, CONTRACT),
            ),
            Kind::FiatLock => OperationRequest::FiatLock(
                FiatLockRequest::new(offer, address(&key_b(), 1), AMOUNT, TERMS)
                    .with_commitments(TRADE, CONTRACT),
            ),
            Kind::HashLock => OperationRequest::HashLock(
                HashLockRequest::new(offer, address(&key_b(), 1), AMOUNT, [0x33; 32], REFUND)
                    .with_trade(TRADE)
                    .with_contract(CONTRACT),
            ),
        }
    }
    fn plan_at(&self, head: u64, offer_bytes: Vec<u8>) -> Result<OperationPlan, Refusal> {
        plan(
            &self.request(offer_bytes),
            &self.world(head).view(),
            &identity(&self.planner()),
        )
    }
    /// The unsigned bytes the planner builds at the standard head.
    fn raw(&self) -> Vec<u8> {
        self.plan_at(HEAD, trading::offer_bytes(&self.offer))
            .unwrap()
            .objects()[0]
            .bytes
            .clone()
    }
    /// The refusal a counterparty gets for `raw` at `head` through `explain` AND through `adopt`
    /// (both must agree).
    fn counterparty_refusal(
        &self,
        raw: &[u8],
        head: u64,
        state: Option<&mut dyn FnMut(&mut World)>,
    ) -> Refusal {
        let mut world = self.world(head);
        if let Some(edit) = state {
            edit(&mut world);
        }
        // Explicit reference facts in this synthetic TEST model isolate offer checks.
        // These anchors are not a fabricated own-replay confirmation source.
        let mut history = mutiny_consensus_v8::evidence_history_v2::History::default();
        let envelope = &NativeOperation::decode(raw)
            .unwrap()
            .operation
            .meta
            .envelope;
        history
            .insert_anchor(envelope.reference_height, envelope.reference_block)
            .unwrap();
        let view = world.view().with_history(&history);
        let me = identity(&self.counterparty());
        let explained = explain(raw, &view, &me).map(|_| ()).unwrap_err();
        let adopted = adopt(raw, &view, &me).map(|_| ()).unwrap_err();
        assert_eq!(
            explained, adopted,
            "{:?}: explain and adopt disagree",
            self.kind
        );
        explained
    }
}

fn mutate(raw: &[u8], change: impl FnOnce(&mut NativeOperation)) -> Vec<u8> {
    trading::mutate(raw, change)
}

/// Mark `offer` as filled in `world`'s state (the single-fill record consensus writes).
fn consume(world: &mut World, offer: &SignedOffer) {
    let id = offer.body.id().unwrap();
    world.state.protocol_records.insert(
        record_key(1, single_fill_key(&offer.body.context, [0; 32], id)),
        Vec::new(),
    );
}

fn action_offer_mut(action: &mut Action) -> &mut Hash {
    match action {
        Action::HashLock { offer, .. }
        | Action::LicenseDvp { offer, .. }
        | Action::FiatLock { offer, .. } => offer,
        _ => unreachable!("an offer-bearing action"),
    }
}

fn bump_terms(action: &mut Action) {
    match action {
        Action::HashLock { amount, .. } | Action::FiatLock { amount, .. } => amount.0 += 1,
        Action::LicenseDvp { price, .. } => price.0 += 1,
        _ => unreachable!("an offer-bearing action"),
    }
}

/// The embedded-offer rules, for every handler: the counterparty's explain and adopt agree, and
/// every handler gives the same refusal.
#[test]
fn every_embedded_offer_failure_has_one_code_for_every_handler() {
    let cases: Vec<Case> = KINDS.into_iter().map(Case::new).collect();
    type Mutation = fn(&Case, &[u8]) -> (Vec<u8>, u64);
    let classes: Vec<(&str, Mutation, &str)> = vec![
        (
            "no offer proof on an offer-bearing action",
            |_, raw| (mutate(raw, |w| w.operation.offer_proof = None), HEAD),
            "OFFER_PROOF_INVALID",
        ),
        (
            "an offer naming another chain",
            |_, raw| {
                let raw = mutate(raw, |w| {
                    w.operation
                        .offer_proof
                        .as_mut()
                        .unwrap()
                        .offer
                        .body
                        .context
                        .genesis = [9; 32]
                });
                (raw, HEAD)
            },
            "WRONG_CONTEXT",
        ),
        (
            "an action naming another offer",
            |_, raw| {
                (
                    mutate(raw, |w| {
                        *action_offer_mut(&mut w.operation.action) = [7; 32]
                    }),
                    HEAD,
                )
            },
            "OFFER_PROOF_INVALID",
        ),
        (
            "the next block before the offer's first block",
            |_, raw| {
                (
                    mutate(raw, |w| {
                        w.operation.meta.envelope.first_height = OFFER_CREATED - 1;
                        w.operation.meta.envelope.reference_height = OFFER_CREATED - 2;
                    }),
                    OFFER_CREATED - 2,
                )
            },
            "OFFER_NOT_YET_VALID",
        ),
        (
            "the next block after the offer's last block",
            |_, raw| {
                (
                    mutate(raw, |w| {
                        w.operation.meta.envelope.last_height = OFFER_EXPIRY + 5
                    }),
                    OFFER_EXPIRY + 2,
                )
            },
            "OFFER_EXPIRED",
        ),
        (
            "an operation window that starts before the offer's",
            |_, raw| {
                (
                    mutate(raw, |w| {
                        w.operation.meta.envelope.first_height = OFFER_CREATED - 1;
                        w.operation.meta.envelope.reference_height = OFFER_CREATED - 2;
                    }),
                    HEAD,
                )
            },
            "OFFER_WINDOW_EXCEEDED",
        ),
        (
            "an operation window that ends after the offer's",
            |_, raw| {
                (
                    mutate(raw, |w| {
                        w.operation.meta.envelope.last_height = OFFER_EXPIRY + 1
                    }),
                    HEAD,
                )
            },
            "OFFER_WINDOW_EXCEEDED",
        ),
        (
            "terms other than the offer's",
            |_, raw| (mutate(raw, |w| bump_terms(&mut w.operation.action)), HEAD),
            "OFFER_PROOF_INVALID",
        ),
        (
            "a maker offer signature that does not verify",
            |_, raw| {
                let raw = mutate(raw, |w| {
                    w.operation
                        .offer_proof
                        .as_mut()
                        .unwrap()
                        .offer
                        .signature
                        .ed448[5] ^= 1
                });
                (raw, HEAD)
            },
            "OFFER_PROOF_INVALID",
        ),
        (
            "a fill signature that does not verify over this body",
            |_, raw| {
                let raw = mutate(raw, |w| {
                    w.operation
                        .offer_proof
                        .as_mut()
                        .unwrap()
                        .fill_signature
                        .ed448[0] = 1
                });
                (raw, HEAD)
            },
            "OFFER_PROOF_INVALID",
        ),
    ];
    for (what, mutation, expected) in &classes {
        let mut seen = Vec::new();
        for case in &cases {
            let (raw, head) = mutation(case, &case.raw());
            let refusal = case.counterparty_refusal(&raw, head, None);
            assert_eq!(
                refusal.code(),
                *expected,
                "{what}: {:?} gave {refusal:?}",
                case.kind
            );
            if *expected == "OFFER_WINDOW_EXCEEDED" {
                // The refusal names both windows exactly: the offer's and the bytes'.
                let meta = NativeOperation::decode(&raw).unwrap().operation.meta;
                assert_eq!(
                    refusal,
                    Refusal::OfferWindowExceeded {
                        offer_created: OFFER_CREATED,
                        offer_expiry: OFFER_EXPIRY,
                        created: meta.envelope.first_height,
                        expiry: meta.envelope.last_height,
                    },
                    "{what}: {:?}",
                    case.kind
                );
            }
            seen.push(refusal);
        }
        // Every handler gives the same refusal (also the same fields where the bytes agree).
        match *expected {
            "WRONG_CONTEXT" => assert!(
                seen.iter()
                    .all(|r| *r == Refusal::WrongContext(ContextField::Genesis))
            ),
            "OFFER_NOT_YET_VALID" => assert!(seen.iter().all(|r| *r
                == Refusal::OfferNotYetValid {
                    created: OFFER_CREATED,
                    next_height: OFFER_CREATED - 1
                })),
            "OFFER_EXPIRED" => assert!(seen.iter().all(|r| *r
                == Refusal::OfferExpired {
                    expiry: OFFER_EXPIRY,
                    next_height: OFFER_EXPIRY + 3
                })),
            "OFFER_PROOF_INVALID" => assert!(seen.iter().all(|r| *r == Refusal::OfferProofInvalid)),
            _ => {}
        }
    }
    // The control: unmodified bytes are accepted by every counterparty.
    for case in &cases {
        let world = case.world(HEAD);
        assert!(explain(&case.raw(), &world.view(), &identity(&case.counterparty())).is_ok());
        assert!(adopt(&case.raw(), &world.view(), &identity(&case.counterparty())).is_ok());
    }
}

#[test]
fn a_filled_offer_is_offer_consumed_for_every_handler_and_entry_point() {
    for kind in KINDS {
        let case = Case::new(kind);
        let raw = case.raw();
        let mut mark = |world: &mut World| consume(world, &case.offer);
        assert_eq!(
            case.counterparty_refusal(&raw, HEAD, Some(&mut mark)),
            Refusal::OfferConsumed,
            "{kind:?}"
        );
        let mut world = case.world(HEAD);
        consume(&mut world, &case.offer);
        assert_eq!(
            plan(
                &case.request(trading::offer_bytes(&case.offer)),
                &world.view(),
                &identity(&case.planner())
            )
            .unwrap_err(),
            Refusal::OfferConsumed,
            "{kind:?}"
        );
    }
}

/// The request-time and import rules: the same refusal from every planner.
#[test]
fn every_request_time_and_import_failure_has_one_code_for_every_planner() {
    for kind in KINDS {
        let case = Case::new(kind);
        let bytes = trading::offer_bytes(&case.offer);
        // The offer's window at the next block.
        assert_eq!(
            case.plan_at(OFFER_CREATED - 2, bytes.clone()).unwrap_err(),
            Refusal::OfferNotYetValid {
                created: OFFER_CREATED,
                next_height: OFFER_CREATED - 1
            },
            "{kind:?}"
        );
        assert_eq!(
            case.plan_at(OFFER_EXPIRY, bytes.clone()).unwrap_err(),
            Refusal::OfferExpired {
                expiry: OFFER_EXPIRY,
                next_height: OFFER_EXPIRY + 1
            },
            "{kind:?}"
        );
        // Bytes in neither accepted offer form.
        for garbage in [vec![0x80], vec![], bytes[..bytes.len() - 1].to_vec()] {
            assert_eq!(
                case.plan_at(HEAD, garbage).unwrap_err().code(),
                "MALFORMED",
                "{kind:?}"
            );
        }
        // An offer for another chain.
        let world = case.world(HEAD);
        let mut foreign = trading::context_of(&world.anchor);
        foreign.genesis = [9; 32];
        let other_chain = offer_for(kind, &case.maker, foreign, case.license);
        assert_eq!(
            case.plan_at(HEAD, trading::offer_bytes(&other_chain))
                .unwrap_err(),
            Refusal::WrongContext(ContextField::Genesis),
            "{kind:?}"
        );
        // A maker signature that does not verify.
        let mut forged = case.offer.clone();
        forged.signature.ed448[3] ^= 1;
        assert_eq!(
            case.plan_at(HEAD, trading::offer_bytes(&forged))
                .unwrap_err(),
            Refusal::Malformed("not a canonical maker offer"),
            "{kind:?}"
        );
        // An offer whose terms are for another kind of operation.
        let other_kind = KINDS.into_iter().find(|k| *k != kind).unwrap();
        let wrong = offer_for(
            other_kind,
            &case.maker,
            trading::context_of(&world.anchor),
            case.license,
        );
        let refusal = case
            .plan_at(HEAD, trading::offer_bytes(&wrong))
            .unwrap_err();
        assert_eq!(
            refusal,
            Refusal::InvalidRequest("the offer's terms are for another kind of operation"),
            "{kind:?}"
        );
    }
}
