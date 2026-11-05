//! Wallet phase 0A: read-only consensus accessors for wallet-core (additive; no rule change).
//!
//! Every accessor is exercised here through the PUBLIC API only (this is an integration test),
//! which is exactly how an external crate reaches it, and each one is cross-checked against the
//! consensus behaviour it mirrors: `prepare_batch`, `admit`, `WalletBook::authorize` and the
//! dividend ledger. All keys are published BIP39 test-vector phrases or fresh random Transport
//! keys; every chain object is a public synthetic fixture. TEST VALUE only; evidence class:
//! NATIVE PASS (offline, TEST-VALUE).
use minicbor::{Decoder, Encoder};
use mutiny_consensus_v8::{
    Hash, NETWORK_ID,
    anchors::FinalizedAnchor,
    dividend_claim_v1::{ClaimBody, ClaimError, SignedClaim, admit, plan_spend},
    dividend_state_v1::DividendState,
    dividends_v1::{AWARD_PERIOD_EPOCHS as P, Claim, DivError, Ledger, LicenseView, Status},
    evidence_history_v2::History,
    execution::State,
    license_assignment_v2::Assignment,
    license_book_v2::Book,
    licenses::LicenseRecord,
    op_envelope_v1::Envelope,
    trading_v1::{
        Action, CandidatePolicy, Context, Meta, NativeError, NativeOperation, NativeResult,
        OfferBody, OfferProof, OfferTerms, Operation, Prepared, SignedOffer, Strikes,
        descriptor_hash, license_generation, native_input_id, preimage_hash,
        treasury_genesis_records, verify_approval,
    },
    transactions::{Coin, OutPoint, Output},
    treasury_v1::{Class, Treasury},
    wallet_authority_v1::WalletBook,
    wallet_rotation_v1::Rotation,
};
use mutiny_crypto_v2::{HybridKey, HybridSignature, Role};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::OnceLock,
};

// ---------------------------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------------------------

struct Keys {
    a: HybridKey,
    b: HybridKey,
    c: HybridKey,
    d: HybridKey,
}
fn keys() -> &'static Keys {
    static K: OnceLock<Keys> = OnceLock::new();
    // Published BIP39 test-vector phrases, never production custody material.
    let restore = |phrase: &str| HybridKey::wallet_restore(phrase, Role::WalletOwner).unwrap();
    K.get_or_init(|| Keys {
        a: restore(&("abandon ".repeat(23) + "art")),
        b: restore(&("zoo ".repeat(23) + "vote")),
        c: restore(
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
        ),
        d: restore(
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        ),
    })
}
fn desc(k: &HybridKey, generation: u64) -> Vec<u8> {
    k.public().descriptor(generation).unwrap()
}
fn addr(k: &HybridKey, generation: u64) -> Hash {
    k.public().address_id(generation).unwrap()
}
fn empty() -> HybridSignature {
    HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    }
}
fn ctx() -> Context {
    Context {
        network: NETWORK_ID,
        genesis: [11; 32],
        fingerprint: [12; 32],
    }
}
/// The Genesis of the public License Book fixture.
fn license_ctx() -> Context {
    Context {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
    }
}
fn point(n: u8) -> OutPoint {
    OutPoint {
        transaction: [n; 32],
        index: 0,
    }
}
fn coin(owner: Hash, atoms: u64, coinbase: bool) -> Coin {
    Coin {
        output: Output { owner, atoms },
        created_height: 0,
        coinbase,
    }
}
/// Wallets a, b, c registered at generation one; six 100,000-atom coins: 1,3,6 -> a; 2,4 -> b; 5 -> c.
fn base_state() -> State {
    let k = keys();
    let mut s = State::default();
    for key in [&k.a, &k.b, &k.c] {
        s.wallets.register(&desc(key, 1)).unwrap();
    }
    for (n, key) in [
        (1, &k.a),
        (2, &k.b),
        (3, &k.a),
        (4, &k.b),
        (5, &k.c),
        (6, &k.a),
    ] {
        s.coins.insert(point(n), coin(addr(key, 1), 100_000, false));
    }
    s
}
fn rotate_wallet(
    wallets: &mut WalletBook,
    authority: Hash,
    from: (&HybridKey, u64),
    to: (&HybridKey, u64),
    height: u64,
) {
    let mut rotation = Rotation {
        network: NETWORK_ID,
        genesis: [11; 32],
        fingerprint: [12; 32],
        authority,
        current: desc(from.0, from.1),
        proposed: desc(to.0, to.1),
        created_height: 1,
        expiry_height: 10_000,
        authorization: empty(),
        possession: empty(),
    };
    rotation.sign(from.0, to.0).unwrap();
    wallets
        .apply(&rotation, [11; 32], [12; 32], height)
        .unwrap();
}

// ---- trading operations -----------------------------------------------------------------------

/// An operation with its offer proof (if the action is offer-bound) but NO wallet approvals yet.
/// Body version 2: the signed window [created, expiry] with the synthetic chain's block `[13; 32]`
/// at `created - 1` as its finalized reference.
fn unsigned(c: &Context, action: Action, created: u64, expiry: u64, input: u8) -> NativeOperation {
    unsigned_full(c, action, created, expiry, input, vec![], None)
}
/// `unsigned` whose offer (if any) is made by `maker` (key, descriptor generation); by default the
/// generation-one test wallet of the slot-0 address (P7, AM-6: the maker signs with its wallet
/// owner key, which must be the slot's current authority), or wallet a for an address of no test
/// wallet.
fn unsigned_by(
    c: &Context,
    action: Action,
    created: u64,
    expiry: u64,
    input: u8,
    maker: Option<(&HybridKey, u64)>,
) -> NativeOperation {
    unsigned_full(c, action, created, expiry, input, vec![], maker)
}
/// `unsigned` whose envelope commits `preconditions` (WP-T2: a LicenseDvp must commit the sold
/// License's entitlements and assignment facts, design 6.1).
fn unsigned_with(
    c: &Context,
    action: Action,
    created: u64,
    expiry: u64,
    input: u8,
    preconditions: Vec<mutiny_consensus_v8::op_envelope_v1::Precondition>,
) -> NativeOperation {
    unsigned_full(c, action, created, expiry, input, preconditions, None)
}
/// The common builder: committed `preconditions` and an optional explicit `maker`.
fn unsigned_full(
    c: &Context,
    action: Action,
    created: u64,
    expiry: u64,
    input: u8,
    preconditions: Vec<mutiny_consensus_v8::op_envelope_v1::Precondition>,
    maker: Option<(&HybridKey, u64)>,
) -> NativeOperation {
    let mut op = Operation {
        meta: Meta {
            context: c.clone(),
            trade: [21; 32],
            contract: [22; 32],
            generation: 1,
            envelope: Envelope {
                first_height: created,
                last_height: expiry,
                reference_height: created - 1,
                reference_block: [13; 32],
                preconditions,
            },
            fee: Strikes(20_000),
            inputs: vec![native_input_id(&point(input))],
        },
        action,
        approvals: vec![],
        offer_proof: None,
    };
    let terms = match &op.action {
        Action::HashLock { amount, .. } => Some(OfferTerms::HashLinked {
            amount: *amount,
            bitcoin_satoshis: 10_000,
            bitcoin_network: 3,
        }),
        Action::FiatLock {
            amount,
            payment_terms,
            ..
        } => Some(OfferTerms::Fiat {
            amount: *amount,
            payment_terms: *payment_terms,
        }),
        Action::LicenseDvp {
            license,
            license_generation,
            price,
            ..
        } => Some(OfferTerms::License {
            license: *license,
            generation: *license_generation,
            price: *price,
        }),
        _ => None,
    };
    if let Some(terms) = terms {
        let maker_wallet = op.slot_address(0).unwrap();
        let (maker, generation) = maker.unwrap_or_else(|| {
            let k = keys();
            let key = [&k.a, &k.b, &k.c]
                .into_iter()
                .find(|key| addr(key, 1) == maker_wallet)
                .unwrap_or(&k.a);
            (key, 1)
        });
        let (destination, condition) = match &op.action {
            Action::HashLock {
                sender, condition, ..
            } => (*sender, Some(*condition)),
            Action::FiatLock { seller, .. } => (*seller, None),
            Action::LicenseDvp {
                payment_destination,
                ..
            } => (*payment_destination, None),
            _ => unreachable!(),
        };
        let body = OfferBody {
            context: op.meta.context.clone(),
            maker_descriptor: desc(maker, generation),
            maker_wallet,
            maker_side: 0,
            nonce: [31; 32],
            created: 1,
            expiry: 10,
            terms,
            destination,
            condition,
            max_fee: op.meta.fee,
        };
        let offer = SignedOffer::sign(body, maker).unwrap();
        match &mut op.action {
            Action::HashLock {
                offer: o, maker, ..
            }
            | Action::FiatLock {
                offer: o, maker, ..
            }
            | Action::LicenseDvp {
                offer: o, maker, ..
            } => {
                *o = offer.body.id().unwrap();
                *maker = offer.body.maker().unwrap();
            }
            _ => unreachable!(),
        }
        op.offer_proof = Some(OfferProof::sign(offer, &op, maker).unwrap());
    }
    NativeOperation {
        operation: op,
        inputs: vec![point(input)],
    }
}
/// The same operation carrying exactly the given (slot, signer) approvals at generation one.
fn approved(w: &NativeOperation, approvals: &[(u8, &HybridKey)]) -> NativeOperation {
    let mut w = w.clone();
    w.operation.approvals.clear();
    for (slot, key) in approvals {
        w.operation.approve(*slot, key, 1).unwrap();
    }
    w
}
/// `approved` with an explicit descriptor generation per signer: (slot, signer, generation).
fn approved_g(w: &NativeOperation, approvals: &[(u8, &HybridKey, u64)]) -> NativeOperation {
    let mut w = w.clone();
    w.operation.approvals.clear();
    for (slot, key, generation) in approvals {
        w.operation.approve(*slot, key, *generation).unwrap();
    }
    w
}
/// The test key and descriptor generation that the WalletBook of `s` accepts for `address`: the
/// address's current wallet authority (P6: the Treasury slot is T's CURRENT key, which after R1 is
/// a later generation; every other test wallet is at generation one).
fn signer_for(s: &State, address: Hash) -> (&'static HybridKey, u64) {
    let k = keys();
    for generation in 1..=3 {
        for key in [&k.a, &k.b, &k.c, &k.d] {
            if s.wallets.authorize(address, &desc(key, generation)).is_ok() {
                return (key, generation);
            }
        }
    }
    panic!("a test wallet")
}
/// P6 (WP-T3): `base_state` with the Genesis Treasury authority T = addr(b, 1) active, the
/// trading Treasury records under T, and R1 applied (T's key rotated from b to c at generation 2).
fn treasury_state_after_r1() -> State {
    let k = keys();
    let mut s = base_state();
    s.dividends = mutiny_consensus_v8::dividend_state_v1::DividendState::genesis(
        mutiny_consensus_v8::treasury_v1::Treasury::new(
            mutiny_consensus_v8::treasury_v1::Class::TestValue,
            desc(&k.b, 1),
        )
        .unwrap(),
    );
    for (key, raw) in treasury_genesis_records(&ctx(), addr(&k.b, 1), desc(&k.b, 1)).unwrap() {
        s.protocol_records.insert(key, raw);
    }
    rotate_wallet(&mut s.wallets, addr(&k.b, 1), (&k.b, 1), (&k.c, 2), 1);
    s
}
fn prepare(s: &State, c: &Context, height: u64, w: &NativeOperation) -> NativeResult<Prepared> {
    prepare_batch_for(s, c, height, &[w.encode().unwrap()])
}
fn prepare_batch_for(
    s: &State,
    c: &Context,
    height: u64,
    raw: &[Vec<u8>],
) -> NativeResult<Prepared> {
    // The synthetic chain's authenticated History: every block below the parent is [13; 32].
    let mut history = History::default();
    for h in 0..height - 1 {
        history.insert_anchor(h, [13; 32]).unwrap();
    }
    mutiny_consensus_v8::trading_v1::prepare_batch_with_history(
        s,
        &FinalizedAnchor {
            network: c.network,
            genesis: c.genesis,
            fingerprint: c.fingerprint,
            height: height - 1,
            block: [13; 32],
        },
        s.root().unwrap(),
        &history,
        raw,
        &CandidatePolicy::native_denomination_locked(),
    )
}
fn key_for(address: Hash) -> &'static HybridKey {
    let k = keys();
    [&k.a, &k.b, &k.c]
        .into_iter()
        .find(|key| addr(key, 1) == address)
        .expect("a test wallet")
}
fn hash_lock(sender: Hash, recipient: Hash) -> Action {
    Action::HashLock {
        offer: [0; 32],
        maker: [0; 32],
        sender,
        recipient,
        amount: Strikes(50_000),
        condition: preimage_hash(&[42; 32]),
        refund_height: 20,
        change: Strikes(30_000),
    }
}
fn fiat_lock(seller: Hash, buyer: Hash) -> Action {
    Action::FiatLock {
        offer: [0; 32],
        maker: [0; 32],
        seller,
        buyer,
        amount: Strikes(50_000),
        payment_terms: [51; 32],
        change: Strikes(30_000),
    }
}

// ---- the public License Book fixture ----------------------------------------------------------

fn fixture_records() -> BTreeMap<Hash, Vec<u8>> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/license-book-v2-public-v1.json"
    ))
    .unwrap();
    assert_eq!(fixture["synthetic_only"], true);
    fixture["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            let key: Hash = hex::decode(e["key"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            (key, hex::decode(e["record"].as_str().unwrap()).unwrap())
        })
        .collect()
}
/// The Book's record key of the pending assignment of `license`.
fn pending_key(license: Hash) -> Hash {
    mutiny_consensus_v8::domain_hash(b"MUTINY-BUILD8-PENDING-BIND-KEY-V2", &license)
}
fn cbor_record(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .u8(2)
        .unwrap()
        .u8(tag)
        .unwrap()
        .bytes(payload)
        .unwrap();
    e.into_writer()
}
/// Licenses (by id) and pending assignments (by License id) decoded from raw typed records,
/// independently of `Book`.
fn decode_records(
    records: &BTreeMap<Hash, Vec<u8>>,
) -> (BTreeMap<Hash, LicenseRecord>, BTreeMap<Hash, Assignment>) {
    let (mut licenses, mut pending) = (BTreeMap::new(), BTreeMap::new());
    for raw in records.values() {
        let mut d = Decoder::new(raw);
        d.array().unwrap();
        assert_eq!(d.u8().unwrap(), 2);
        match d.u8().unwrap() {
            40 => {
                let l = LicenseRecord::decode(d.bytes().unwrap()).unwrap();
                licenses.insert(l.id, l);
            }
            42 => {
                let a = Assignment::decode(d.bytes().unwrap()).unwrap();
                pending.insert(a.enrollment.binding.license, a);
            }
            _ => {}
        }
    }
    (licenses, pending)
}
/// The fixture's raw Book records without its own pending assignments, with the first License (in
/// record-key order) re-owned by wallet `a` exactly as the in-crate DvP tests do (an explicit
/// synthetic pre-state owner mapping). With `pending`, that License's generation-one Worker
/// assignment is moved to the pending set (a scheduled but not yet active re-assignment).
fn license_records(pending: bool) -> (BTreeMap<Hash, Vec<u8>>, Hash) {
    let mut records = BTreeMap::new();
    let mut selected = None;
    for (key, raw) in fixture_records() {
        let mut d = Decoder::new(&raw);
        d.array().unwrap();
        assert_eq!(d.u8().unwrap(), 2);
        let tag = d.u8().unwrap();
        if tag == 40 && selected.is_none() {
            let mut l = LicenseRecord::decode(d.bytes().unwrap()).unwrap();
            l.owner = addr(&keys().a, 1);
            selected = Some(l.id);
            records.insert(key, cbor_record(40, &l.encode()));
        } else if tag != 42 {
            records.insert(key, raw);
        }
    }
    let id = selected.unwrap();
    if pending {
        let mut moved = None;
        let mut gone = Vec::new();
        for (key, raw) in &mut records {
            let mut d = Decoder::new(raw);
            d.array().unwrap();
            d.u8().unwrap();
            match d.u8().unwrap() {
                40 => {
                    let mut l = LicenseRecord::decode(d.bytes().unwrap()).unwrap();
                    if l.id == id {
                        l.active_worker = None;
                        l.assignment_sequence = 0;
                        *raw = cbor_record(40, &l.encode());
                    }
                }
                41 => {
                    let a = Assignment::decode(d.bytes().unwrap()).unwrap();
                    if a.enrollment.binding.license == id {
                        if a.enrollment.binding.assignment_generation == 1 {
                            moved = Some(a);
                        }
                        gone.push(*key);
                    }
                }
                _ => {}
            }
        }
        for key in gone {
            records.remove(&key);
        }
        records.insert(
            pending_key(id),
            cbor_record(42, &moved.unwrap().encode().unwrap()),
        );
    }
    (records, id)
}
fn license_book(pending: bool) -> (Book, Hash) {
    let (records, id) = license_records(pending);
    (Book::from_records(&records).unwrap(), id)
}
/// `base_state` plus the License Book (License owner = wallet a, Genesis [1;32]/[2;32]).
fn license_state(pending: bool) -> (State, Hash) {
    let (book, id) = license_book(pending);
    let mut s = base_state();
    s.licenses_v2 = book;
    (s, id)
}
/// The License facts a sale of `id` commits to (WP-T2, design 6.1), read from `s`.
fn sale_facts(s: &State, id: Hash) -> Vec<mutiny_consensus_v8::op_envelope_v1::Precondition> {
    vec![
        mutiny_consensus_v8::op_envelope_v1::entitlement_facts(s, id),
        mutiny_consensus_v8::op_envelope_v1::assignment_facts(s, id).unwrap(),
    ]
}
/// A sale of `id` committing the License facts of `s`.
fn dvp(
    s: &State,
    id: Hash,
    generation: u64,
    seller: &HybridKey,
    buyer: &HybridKey,
    height: u64,
    input: u8,
) -> NativeOperation {
    unsigned_with(
        &license_ctx(),
        Action::LicenseDvp {
            offer: [0; 32],
            maker: [0; 32],
            license: id,
            license_generation: generation,
            seller: addr(seller, 1),
            buyer: addr(buyer, 1),
            price: Strikes(50_000),
            payment_destination: addr(&keys().c, 1),
            change: Strikes(30_000),
        },
        height,
        10,
        input,
        sale_facts(s, id),
    )
}

// ---------------------------------------------------------------------------------------------
// license_book_v2::Book: enumeration, owner lookup, pending status
// ---------------------------------------------------------------------------------------------

/// Re-own the first two Licenses (in record-key order) to wallets b and c, so the Book has
/// several distinct owners and an owner lookup is not vacuous.
fn reown(records: &mut BTreeMap<Hash, Vec<u8>>) {
    let mut n = 0;
    for raw in records.values_mut() {
        let mut d = Decoder::new(raw);
        d.array().unwrap();
        d.u8().unwrap();
        if d.u8().unwrap() != 40 {
            continue;
        }
        let mut l = LicenseRecord::decode(d.bytes().unwrap()).unwrap();
        match n {
            0 => l.owner = addr(&keys().b, 1),
            1 => l.owner = addr(&keys().c, 1),
            _ => {}
        }
        n += 1;
        *raw = cbor_record(40, &l.encode());
    }
}

/// Restore a Book from raw typed records and compare every accessor with the records decoded
/// independently of `Book`. Returns the number of pending assignments the records carry.
fn check_book_against_records(records: &BTreeMap<Hash, Vec<u8>>) -> usize {
    let (expected, expected_pending) = decode_records(records);
    assert_eq!(expected.len(), 12, "twelve Genesis Licenses");
    let book = Book::from_records(records).expect("the records restore");

    // Every License exactly once, in canonical (LicenseID ascending) order, equal to `license(id)`.
    let listed: Vec<&LicenseRecord> = book.licenses().collect();
    let ids: Vec<Hash> = listed.iter().map(|l| l.id).collect();
    assert_eq!(ids, expected.keys().copied().collect::<Vec<_>>());
    assert!(ids.windows(2).all(|w| w[0] < w[1]));
    for l in &listed {
        assert_eq!(**l, expected[&l.id]);
        assert_eq!(book.license(l.id), Some(*l));
    }

    // Owner lookup partitions the Book; an owner with no License yields nothing.
    let owners: BTreeSet<Hash> = expected.values().map(|l| l.owner).collect();
    let mut total = 0;
    for owner in &owners {
        let found: Vec<Hash> = book.licenses_of(*owner).map(|l| l.id).collect();
        let want: Vec<Hash> = expected
            .values()
            .filter(|l| l.owner == *owner)
            .map(|l| l.id)
            .collect();
        assert!(!found.is_empty());
        assert_eq!(found, want);
        assert!(book.licenses_of(*owner).all(|l| l.owner == *owner));
        total += found.len();
    }
    assert_eq!(total, expected.len());
    assert_eq!(book.licenses_of([0xee; 32]).count(), 0);

    // Pending status mirrors the raw typed records, License by License.
    for id in expected.keys() {
        assert_eq!(book.pending_assignment(*id), expected_pending.get(id));
    }
    assert_eq!(book.pending_assignment([0xee; 32]), None);
    expected_pending.len()
}

#[test]
fn book_enumerates_and_looks_up_licenses_by_id_owner_and_pending_status() {
    // The unmodified public fixture: twelve Genesis Licenses, no pending assignment.
    let mut records = fixture_records();
    assert_eq!(check_book_against_records(&records), 0);
    // Several owners.
    reown(&mut records);
    assert_eq!(check_book_against_records(&records), 0);
    let owners: BTreeSet<Hash> = decode_records(&records)
        .0
        .values()
        .map(|l| l.owner)
        .collect();
    assert!(owners.len() >= 2, "an owner lookup that is not vacuous");
    // The same Book with one License's Worker moved to the pending set: exactly that License
    // reports a pending assignment.
    let (pending_records, id) = license_records(true);
    assert_eq!(check_book_against_records(&pending_records), 1);
    let book = Book::from_records(&pending_records).unwrap();
    assert!(book.pending_assignment(id).is_some());
    assert_eq!(
        book.licenses()
            .filter(|l| book.pending_assignment(l.id).is_some())
            .map(|l| l.id)
            .collect::<Vec<_>>(),
        vec![id]
    );
    assert!(book.licenses_of(addr(&keys().a, 1)).any(|l| l.id == id));
}

#[test]
fn empty_book_has_no_licenses_and_no_pending_assignment() {
    let book = Book::default();
    assert_eq!(book.licenses().count(), 0);
    assert_eq!(book.licenses_of([1; 32]).count(), 0);
    assert_eq!(book.pending_assignment([1; 32]), None);
}

#[test]
fn pending_assignment_accessor_matches_the_consensus_transfer_refusal() {
    let (c, k) = (license_ctx(), keys());
    let sale = |s: &State, id: Hash| approved(&dvp(s, id, 1, &k.a, &k.b, 2, 2), &[(0, &k.a), (1, &k.b)]);

    // An active Worker and no pending assignment: the accessor says so and consensus accepts
    // the DvP.
    let (s, id) = license_state(false);
    assert_eq!(s.licenses_v2.pending_assignment(id), None);
    assert!(prepare(&s, &c, 2, &sale(&s, id)).is_ok());

    // The License detached with a pending (scheduled) assignment: the accessor reports it with
    // its binding fields; consensus binds a sale to it through the committed LicenseAssignment
    // precondition (WP-T2, below).
    let (records, id) = license_records(true);
    let mut locked = base_state();
    locked.licenses_v2 = Book::from_records(&records).unwrap();
    let pending = locked
        .licenses_v2
        .pending_assignment(id)
        .expect("the License has a pending assignment");
    assert_eq!(pending.enrollment.binding.license, id);
    let record = locked.licenses_v2.license(id).unwrap();
    assert_eq!(record.active_worker, None);
    assert_eq!(
        pending.enrollment.binding.assignment_generation,
        record.assignment_sequence + 1,
        "a pending assignment is always the next generation"
    );
    assert!(
        locked
            .licenses_v2
            .licenses()
            .filter(|l| l.id != id)
            .all(|l| locked.licenses_v2.pending_assignment(l.id).is_none())
    );
    let before = locked.records().unwrap();
    // WP-T2 (design 6.6, Restart Order L64) replaces the former LicenseLocked refusal: a sale binds
    // the pending assignment through its committed LicenseAssignment precondition. This synthetic
    // fixture detaches the License to assignment sequence 0, which no canonical path produces
    // (Genesis starts at 1) and which E6 cannot commit: its facts are unrepresentable with or
    // without the pending record, so a sale reviewed against the ordinary state (sequence 1, active
    // Worker, nothing pending) is stale, Stale(2), and changes nothing. The committed-pending
    // positive case runs on canonical state in real blocks:
    // license_dvp_entitlements_v1.rs::committed_pending_assignment_cancelled_uncommitted_one_stales_sale.
    assert_eq!(
        mutiny_consensus_v8::op_envelope_v1::assignment_facts(&locked, id),
        Err(mutiny_consensus_v8::op_envelope_v1::EnvelopeError::ZeroSequence)
    );
    assert!(matches!(
        prepare(&locked, &c, 2, &sale(&s, id)),
        Err(NativeError::Stale(2))
    ));
    assert_eq!(locked.records().unwrap(), before);
    let mut released_records = records.clone();
    released_records.remove(&pending_key(id)).unwrap();
    let mut released = base_state();
    released.licenses_v2 = Book::from_records(&released_records).unwrap();
    assert_eq!(released.licenses_v2.pending_assignment(id), None);
    assert!(matches!(
        prepare(&released, &c, 2, &sale(&s, id)),
        Err(NativeError::Stale(2))
    ));
}

// ---------------------------------------------------------------------------------------------
// trading_v1::Operation: expected_slots / slot_address / fee_payer, and verify_approval
// ---------------------------------------------------------------------------------------------

/// One action together with the state it applies to, the facts the accessors must report and two
/// funding coins: one owned by the payer (accepted) and one owned by somebody else (refused).
struct Case<'a> {
    name: &'static str,
    state: &'a State,
    ctx: Context,
    height: u64,
    action: Action,
    created: u64,
    expiry: u64,
    slots: Vec<(u8, Hash)>,
    payer: Hash,
    good_input: u8,
    bad_input: u8,
}

fn check(case: &Case<'_>) {
    let name = case.name;
    let s = case.state;
    // WP-T2: a LicenseDvp commits the sold License's facts of the case state.
    let preconditions = match &case.action {
        Action::LicenseDvp { license, .. } => sale_facts(s, *license),
        _ => vec![],
    };
    let w = unsigned_with(
        &case.ctx,
        case.action.clone(),
        case.created,
        case.expiry,
        case.good_input,
        preconditions.clone(),
    );
    let op = &w.operation;
    let n = case.slots.len() as u8;

    // The documented table.
    assert_eq!(
        op.expected_slots(),
        case.slots
            .iter()
            .map(|(slot, _)| *slot)
            .collect::<BTreeSet<u8>>(),
        "{name}: expected_slots"
    );
    for (slot, address) in &case.slots {
        assert_eq!(
            op.slot_address(*slot),
            Some(*address),
            "{name}: slot {slot}"
        );
    }
    assert_eq!(op.slot_address(n), None, "{name}: first unused slot");
    assert_eq!(op.slot_address(255), None, "{name}: slot 255");
    assert_eq!(op.fee_payer(), case.payer, "{name}: fee_payer");

    // Consensus agrees: the fully approved operation is accepted and every approval verifies.
    let signers: Vec<(u8, &HybridKey, u64)> = case
        .slots
        .iter()
        .map(|(slot, address)| {
            let (key, generation) = signer_for(s, *address);
            (*slot, key, generation)
        })
        .collect();
    let full = approved_g(&w, &signers);
    prepare(s, &case.ctx, case.height, &full).unwrap_or_else(|e| panic!("{name}: accepted: {e:?}"));
    for (slot, _) in &case.slots {
        verify_approval(&s.wallets, &full.operation, *slot)
            .unwrap_or_else(|e| panic!("{name}: slot {slot} verifies: {e:?}"));
    }
    assert_eq!(
        verify_approval(&s.wallets, &full.operation, n),
        Err(NativeError::Authority),
        "{name}: a slot that is not required never verifies"
    );

    // The required slot set is exact in consensus: leaving out any one slot is refused ...
    for missing in 0..n {
        let rest: Vec<(u8, &HybridKey, u64)> = signers
            .iter()
            .filter(|(slot, _, _)| *slot != missing)
            .cloned()
            .collect();
        let partial = approved_g(&w, &rest);
        assert!(
            matches!(
                prepare(s, &case.ctx, case.height, &partial),
                Err(NativeError::Authority)
            ),
            "{name}: missing slot {missing}"
        );
        assert_eq!(
            verify_approval(&s.wallets, &partial.operation, missing),
            Err(NativeError::Authority),
            "{name}: absent approval"
        );
    }
    // ... and so is an approval for a slot the action does not use.
    if n == 1 {
        let extra = approved_g(&w, &[(0, signers[0].1, signers[0].2), (1, &keys().c, 1)]);
        assert!(
            matches!(
                prepare(s, &case.ctx, case.height, &extra),
                Err(NativeError::Authority)
            ),
            "{name}: extra slot"
        );
        assert_eq!(
            verify_approval(&s.wallets, &extra.operation, 1),
            Err(NativeError::Authority),
            "{name}: a present approval for an unused slot is not verified"
        );
    }
    // The address of each slot matters: the same keys in the other order fail in both.
    if n == 2 {
        let swapped = approved_g(&w, &[(0, signers[1].1, signers[1].2), (1, signers[0].1, signers[0].2)]);
        assert!(
            prepare(s, &case.ctx, case.height, &swapped).is_err(),
            "{name}: swapped"
        );
        for slot in 0..2 {
            assert_eq!(
                verify_approval(&s.wallets, &swapped.operation, slot),
                Err(NativeError::Authority),
                "{name}: swapped slot {slot}"
            );
        }
    }

    // The fee payer is exactly the address whose coins consensus debits.
    assert_eq!(
        s.coins[&point(case.good_input)].output.owner,
        case.payer,
        "{name}"
    );
    assert_ne!(
        s.coins[&point(case.bad_input)].output.owner,
        case.payer,
        "{name}"
    );
    let foreign = approved_g(
        &unsigned_with(
            &case.ctx,
            case.action.clone(),
            case.created,
            case.expiry,
            case.bad_input,
            preconditions,
        ),
        &signers,
    );
    assert!(
        matches!(
            prepare(s, &case.ctx, case.height, &foreign),
            Err(NativeError::Authority)
        ),
        "{name}: an input owned by another address is refused"
    );
}

#[test]
fn expected_slots_slot_address_and_fee_payer_match_consensus_for_every_action() {
    let k = keys();
    let (a, b) = (addr(&k.a, 1), addr(&k.b, 1));
    let base = base_state();
    // The two lock-creating operations, applied once to give Claim, Refund and FiatRelease a
    // real native lock to act on.
    let lock_action = hash_lock(a, b);
    let lock = approved(
        &unsigned(&ctx(), lock_action.clone(), 2, 10, 1),
        &[(0, &k.a), (1, &k.b)],
    );
    let locked = prepare(&base, &ctx(), 2, &lock).unwrap().into_state();
    let fiat_action = fiat_lock(a, b);
    let fiat = approved(
        &unsigned(&ctx(), fiat_action.clone(), 2, 10, 1),
        &[(0, &k.a), (1, &k.b)],
    );
    let fiat_locked = prepare(&base, &ctx(), 2, &fiat).unwrap().into_state();
    let (lock_out, fiat_out) = (
        lock.operation.output_id(0).unwrap(),
        fiat.operation.output_id(0).unwrap(),
    );

    // HashLock: slot 0 = sender (pays), slot 1 = recipient.
    check(&Case {
        name: "HashLock",
        state: &base,
        ctx: ctx(),
        height: 2,
        action: lock_action,
        created: 2,
        expiry: 10,
        slots: vec![(0, a), (1, b)],
        payer: a,
        good_input: 1,
        bad_input: 2,
    });
    // FiatLock: slot 0 = seller (pays), slot 1 = buyer.
    check(&Case {
        name: "FiatLock",
        state: &base,
        ctx: ctx(),
        height: 2,
        action: fiat_action,
        created: 2,
        expiry: 10,
        slots: vec![(0, a), (1, b)],
        payer: a,
        good_input: 1,
        bad_input: 2,
    });
    // Claim: one slot, the lock's recipient, who also pays the fee from separate coins.
    check(&Case {
        name: "Claim",
        state: &locked,
        ctx: ctx(),
        height: 3,
        action: Action::Claim {
            output: lock_out,
            recipient: b,
            amount: Strikes(50_000),
            preimage: [42; 32],
            change: Strikes(80_000),
        },
        created: 3,
        expiry: 25,
        slots: vec![(0, b)],
        payer: b,
        good_input: 2,
        bad_input: 3,
    });
    // Refund: one slot, the lock's sender (eligible at or after the refund height).
    check(&Case {
        name: "Refund",
        state: &locked,
        ctx: ctx(),
        height: 20,
        action: Action::Refund {
            output: lock_out,
            owner: a,
            amount: Strikes(50_000),
            change: Strikes(80_000),
        },
        created: 3,
        expiry: 25,
        slots: vec![(0, a)],
        payer: a,
        good_input: 3,
        bad_input: 2,
    });
    // FiatRelease: slot 0 = buyer (pays), slot 1 = seller; note the order differs from FiatLock.
    check(&Case {
        name: "FiatRelease",
        state: &fiat_locked,
        ctx: ctx(),
        height: 3,
        action: Action::FiatRelease {
            output: fiat_out,
            buyer: b,
            seller: a,
            amount: Strikes(50_000),
            payment_terms: [51; 32],
            change: Strikes(80_000),
        },
        created: 3,
        expiry: 25,
        slots: vec![(0, b), (1, a)],
        payer: b,
        good_input: 2,
        bad_input: 3,
    });
    // TreasuryRotate (P6): one slot, the Treasury authority T = b, approved by T's CURRENT key
    // (c at generation 2 after R1); the current Treasury address (here T itself) pays.
    let treasury = treasury_state_after_r1();
    check(&Case {
        name: "TreasuryRotate",
        state: &treasury,
        ctx: ctx(),
        height: 2,
        action: Action::TreasuryRotate {
            treasury: b,
            current_generation: 1,
            current_address: b,
            current_descriptor: descriptor_hash(&desc(&k.c, 2)),
            new_generation: 2,
            new_address: addr(&k.c, 2),
            new_descriptor: desc(&k.c, 2),
            change: Strikes(80_000),
        },
        created: 2,
        expiry: 10,
        slots: vec![(0, b)],
        payer: b,
        good_input: 4,
        bad_input: 1,
    });
    // LicenseDvp: slot 0 = seller, slot 1 = buyer; the BUYER (slot 1) pays price, change and fee.
    let (licensed, id) = license_state(false);
    check(&Case {
        name: "LicenseDvp",
        state: &licensed,
        ctx: license_ctx(),
        height: 2,
        action: dvp(&licensed, id, 1, &k.a, &k.b, 2, 2).operation.action,
        created: 2,
        expiry: 10,
        slots: vec![(0, a), (1, b)],
        payer: b,
        good_input: 2,
        bad_input: 1,
    });
}

#[test]
fn verify_approval_is_the_consensus_authorization_check() {
    let k = keys();
    let (a, b) = (addr(&k.a, 1), addr(&k.b, 1));
    let base = base_state();
    let w = unsigned(&ctx(), hash_lock(a, b), 2, 10, 1);
    let full = approved(&w, &[(0, &k.a), (1, &k.b)]);
    assert!(prepare(&base, &ctx(), 2, &full).is_ok());
    for slot in 0..2 {
        verify_approval(&base.wallets, &full.operation, slot).unwrap();
    }

    // Either hybrid half of a signature fails verification of exactly that slot (BOTH_REQUIRED).
    for half in 0..2 {
        let mut bad = full.clone();
        if half == 0 {
            bad.operation.approvals[0].signature.ed448[0] ^= 1;
        } else {
            bad.operation.approvals[0].signature.fndsa[0] ^= 1;
        }
        assert_eq!(
            verify_approval(&base.wallets, &bad.operation, 0),
            Err(NativeError::Authority)
        );
        verify_approval(&base.wallets, &bad.operation, 1).unwrap();
        assert!(prepare(&base, &ctx(), 2, &bad).is_err());
    }
    // A valid signature under the wrong wallet's descriptor is not that address's authority.
    let mut wrong = full.clone();
    wrong.operation.approvals[0].descriptor = wrong.operation.approvals[1].descriptor.clone();
    assert_eq!(
        verify_approval(&base.wallets, &wrong.operation, 0),
        Err(NativeError::Authority)
    );
    assert!(prepare(&base, &ctx(), 2, &wrong).is_err());
    // An approval that is not bound to this exact body does not verify (replayed signature).
    let mut other = unsigned(&ctx(), hash_lock(a, b), 2, 10, 3);
    other.operation.approvals = full.operation.approvals.clone();
    assert_eq!(
        verify_approval(&base.wallets, &other.operation, 0),
        Err(NativeError::Authority)
    );
    // No approval at all, and a slot the action does not use.
    assert_eq!(
        verify_approval(&base.wallets, &w.operation, 0),
        Err(NativeError::Authority)
    );
    assert_eq!(
        verify_approval(&base.wallets, &full.operation, 2),
        Err(NativeError::Authority)
    );

    // It reads the WalletBook it is given exactly as consensus does: after wallet a rotates to
    // key d (generation 2) the old key's approval is stale, the new key's is accepted, and
    // consensus reaches the same verdicts on the same book.
    let mut rotated = base.clone();
    rotate_wallet(&mut rotated.wallets, a, (&k.a, 1), (&k.d, 2), 5);
    assert_eq!(
        verify_approval(&rotated.wallets, &full.operation, 0),
        Err(NativeError::Authority)
    );
    verify_approval(&rotated.wallets, &full.operation, 1).unwrap();
    assert!(prepare(&rotated, &ctx(), 6, &full).is_err());
    let mut renewed = full.clone();
    renewed.operation.approvals.remove(0);
    renewed.operation.approve(0, &k.d, 2).unwrap();
    verify_approval(&rotated.wallets, &renewed.operation, 0).unwrap();
    verify_approval(&rotated.wallets, &renewed.operation, 1).unwrap();
    prepare(&rotated, &ctx(), 6, &renewed).unwrap();
    // The new key's approval means nothing against a book that has not seen the rotation.
    assert_eq!(
        verify_approval(&base.wallets, &renewed.operation, 0),
        Err(NativeError::Authority)
    );
}

#[test]
fn verify_approval_applies_the_treasury_rotate_descriptor_binding() {
    let k = keys();
    // P6 (WP-T3): T = b after R1 to c at generation 2; R2 is approved by T's current key.
    let (b, c) = (addr(&k.b, 1), addr(&k.c, 2));
    let treasury = treasury_state_after_r1();
    let rotate = |current_descriptor: Hash| {
        unsigned(
            &ctx(),
            Action::TreasuryRotate {
                treasury: b,
                current_generation: 1,
                current_address: b,
                current_descriptor,
                new_generation: 2,
                new_address: c,
                new_descriptor: desc(&k.c, 2),
                change: Strikes(80_000),
            },
            2,
            10,
            4,
        )
    };
    // The honest operation: the approval hashes to the declared current descriptor.
    let good = approved_g(&rotate(descriptor_hash(&desc(&k.c, 2))), &[(0, &k.c, 2)]);
    verify_approval(&treasury.wallets, &good.operation, 0).unwrap();
    prepare(&treasury, &ctx(), 2, &good).unwrap();
    // The same wallet authority signs, but the operation declares a different descriptor hash:
    // consensus refuses it, so the verification refuses it too although the signature, the
    // address and the WalletBook all check out.
    let wrong = approved_g(&rotate(descriptor_hash(&desc(&k.b, 1))), &[(0, &k.c, 2)]);
    assert!(matches!(
        prepare(&treasury, &ctx(), 2, &wrong),
        Err(NativeError::Authority)
    ));
    assert_eq!(
        verify_approval(&treasury.wallets, &wrong.operation, 0),
        Err(NativeError::Authority)
    );
}

// ---------------------------------------------------------------------------------------------
// trading_v1::license_generation
// ---------------------------------------------------------------------------------------------

#[test]
fn license_generation_tracks_native_transfers_exactly_like_consensus() {
    let (k, c) = (keys(), license_ctx());
    let (s1, id) = license_state(false);
    assert_eq!(license_generation(&s1, id), Ok(1), "never transferred");
    assert_eq!(
        license_generation(&s1, [0xee; 32]),
        Err(NativeError::Missing)
    );

    // First sale a -> b at height 2 names generation 1.
    let first = approved(&dvp(&s1, id, 1, &k.a, &k.b, 2, 2), &[(0, &k.a), (1, &k.b)]);
    let s2 = prepare(&s1, &c, 2, &first).unwrap().into_state();
    assert_eq!(license_generation(&s2, id), Ok(2));
    assert_eq!(s2.licenses_v2.license(id).unwrap().owner, addr(&k.b, 1));

    // Second sale b -> a at height 3: the stale generation is a conflict, the accessor's value
    // is accepted.
    let stale = approved(&dvp(&s2, id, 1, &k.b, &k.a, 3, 1), &[(0, &k.b), (1, &k.a)]);
    assert!(matches!(
        prepare(&s2, &c, 3, &stale),
        Err(NativeError::Conflict)
    ));
    let named = license_generation(&s2, id).unwrap();
    let second = approved(&dvp(&s2, id, named, &k.b, &k.a, 3, 1), &[(0, &k.b), (1, &k.a)]);
    let s3 = prepare(&s2, &c, 3, &second).unwrap().into_state();
    assert_eq!(license_generation(&s3, id), Ok(3));
    // The earlier states are untouched (pure read).
    assert_eq!(license_generation(&s1, id), Ok(1));
    assert_eq!(license_generation(&s2, id), Ok(2));

    // A typed record of the wrong kind at the License's transfer key is reported, not guessed.
    let mut odd = s2.clone();
    let key = mutiny_consensus_v8::trading_v1::record_key(4, id);
    let applied = mutiny_consensus_v8::trading_v1::NativeRecord::Applied {
        wire_hash: [3; 32],
        height: 2,
        fee_atoms: 240,
    }
    .encode(id)
    .unwrap();
    odd.protocol_records.insert(key, applied);
    assert_eq!(license_generation(&odd, id), Err(NativeError::Record));
}

// ---------------------------------------------------------------------------------------------
// dividend_claim_v1: State::treasury_owner_order / treasury_owner_set, plan_spend, claim sequence
// ---------------------------------------------------------------------------------------------

#[test]
fn treasury_owner_order_and_set_follow_wallet_rotations() {
    let k = keys();
    // Treasury authority D (generation 1) -> B (generation 2) -> C (generation 3).
    let (g1, g2, g3) = (addr(&k.d, 1), addr(&k.b, 2), addr(&k.c, 3));
    let mut s = State::default();
    assert!(
        s.treasury_owner_order().is_empty(),
        "no Treasury, no owners"
    );
    assert!(s.treasury_owner_set().is_empty());

    s.dividends = DividendState::genesis(Treasury::new(Class::TestValue, desc(&k.d, 1)).unwrap());
    assert_eq!(s.dividends.treasury().unwrap().authority(), g1);
    // Generation one is an owner even before the WalletBook registers it ...
    assert_eq!(s.treasury_owner_order(), vec![g1]);
    // ... and is not duplicated once it is registered.
    s.wallets.register(&desc(&k.d, 1)).unwrap();
    assert_eq!(s.treasury_owner_order(), vec![g1]);

    rotate_wallet(&mut s.wallets, g1, (&k.d, 1), (&k.b, 2), 5);
    assert_eq!(
        s.treasury_owner_order(),
        vec![g1, g2],
        "oldest generation first"
    );
    rotate_wallet(&mut s.wallets, g1, (&k.b, 2), (&k.c, 3), 6);
    assert_eq!(s.treasury_owner_order(), vec![g1, g2, g3]);
    assert_eq!(s.treasury_owner_set(), BTreeSet::from([g1, g2, g3]));

    // The set is what reserve backing counts: every generation, never coinbase coins, never
    // another wallet. Counting only the authority address would undercount after a rotation.
    s.coins.insert(point(1), coin(g1, 10, false));
    s.coins.insert(point(2), coin(g2, 20, false));
    s.coins.insert(point(3), coin(g3, 30, false));
    s.coins.insert(point(4), coin(g2, 1_000, true));
    s.coins.insert(point(5), coin(addr(&k.a, 1), 5_000, false));
    assert_eq!(
        DividendState::backing(&s.coins, &s.treasury_owner_set()).unwrap(),
        60
    );
    assert_eq!(
        DividendState::backing(&s.coins, &BTreeSet::from([g1])).unwrap(),
        10
    );
}

#[test]
fn plan_spend_is_deterministic_oldest_treasury_address_first() {
    let (g1, g2) = ([0x01; 32], [0x02; 32]);
    let (x, y) = (point(0x31), point(0x20));
    let mut coins = BTreeMap::new();
    coins.insert(x.clone(), coin(g1, 30_000, false)); // older generation, higher OutPoint
    coins.insert(y.clone(), coin(g2, 40_000, false)); // newer generation, lower OutPoint
    coins.insert(point(0x10), coin(g1, 500_000, true)); // coinbase: never spent for a claim
    coins.insert(point(0x01), coin([0x99; 32], 900_000, false)); // not a Treasury address

    // Owners are ranked first (oldest generation), OutPoints only break ties within an owner.
    let plan = plan_spend(&coins, &[g1, g2], 35_000).unwrap();
    assert_eq!(plan.inputs, vec![x.clone(), y.clone()]);
    assert_eq!((plan.change_owner, plan.change), (g2, 35_000));
    // It stops at the first sufficient coin and returns change to that coin's own address.
    let plan = plan_spend(&coins, &[g1, g2], 30_000).unwrap();
    assert_eq!(plan.inputs, vec![x.clone()]);
    assert_eq!((plan.change_owner, plan.change), (g1, 0));
    // The order is part of the rule: the same coins ranked the other way spend the other coin.
    let plan = plan_spend(&coins, &[g2, g1], 35_000).unwrap();
    assert_eq!(plan.inputs, vec![y]);
    assert_eq!((plan.change_owner, plan.change), (g2, 5_000));
    // Coinbase and foreign coins never count towards backing a claim.
    assert!(matches!(
        plan_spend(&coins, &[g1, g2], 70_001),
        Err(ClaimError::Backing)
    ));
    assert!(plan_spend(&coins, &[g1, g2], 70_000).is_ok());
    assert!(matches!(
        plan_spend(&coins, &[], 1),
        Err(ClaimError::Backing)
    ));
}

/// A State with an outstanding award: the public License Book (12 Genesis Licenses, the first
/// owned by wallet a), a TEST-VALUE Treasury D that has rotated to C (generation 2) holding a
/// small generation-one coin and a larger generation-two coin, and one award at epoch `P`.
fn claim_state() -> (State, Hash) {
    let k = keys();
    let (book, license) = license_book(false);
    let mut s = State::default();
    s.licenses_v2 = book;
    s.dividends = DividendState::genesis(Treasury::new(Class::TestValue, desc(&k.d, 1)).unwrap());
    s.wallets.register(&desc(&k.d, 1)).unwrap();
    rotate_wallet(&mut s.wallets, addr(&k.d, 1), (&k.d, 1), (&k.c, 2), 5);
    s.coins.insert(point(1), coin(addr(&k.d, 1), 500, false));
    s.coins.insert(point(2), coin(addr(&k.c, 2), 60_000, false));
    let backing = DividendState::backing(&s.coins, &s.treasury_owner_set()).unwrap();
    assert_eq!(backing, 60_500);
    let triples: Vec<(Hash, Hash, Option<u64>)> = s
        .licenses_v2
        .licenses()
        .map(|l| (l.id, l.owner, s.licenses_v2.dividend_activation_epoch(l.id)))
        .collect();
    assert_eq!(triples.len(), 12);
    assert!(triples.iter().all(|t| t.2 == Some(0)));
    s.dividends.advance(P, backing, &triples).unwrap();
    (s, license)
}
fn signed_claim(license: Hash, amount: u64, sequence: u64) -> Vec<u8> {
    let k = keys();
    SignedClaim::sign(
        ClaimBody {
            network: NETWORK_ID,
            genesis: [1; 32],
            fingerprint: [2; 32],
            created_height: 1,
            expiry_height: 1_000,
            award_epoch: P,
            license,
            amount,
            destination: addr(&k.b, 1),
            sequence,
        },
        desc(&k.a, 1),
        &k.a,
    )
    .unwrap()
    .encode()
}

#[test]
fn claim_admission_uses_the_exposed_treasury_owner_set_and_the_ledger_sequence() {
    let (s, license) = claim_state();
    let (g1, g2) = (addr(&keys().d, 1), addr(&keys().c, 2));
    let (height, epoch) = (10, P + 3);
    let admit_claim = |state: &State, amount: u64, sequence: u64| {
        admit(
            state,
            &signed_claim(license, amount, sequence),
            [1; 32],
            [2; 32],
            height,
            epoch,
        )
    };

    // The sequence the next claim must carry is the confirmed claim count read from the ledger.
    let account = s
        .dividends
        .ledger()
        .award(P)
        .unwrap()
        .account(&license)
        .unwrap();
    assert_eq!((account.claims, account.remaining > 1_000), (0, true));
    admit_claim(&s, 1_000, account.claims).unwrap();
    assert_eq!(
        admit_claim(&s, 1_000, account.claims + 1),
        Err(ClaimError::Dividend(DivError::Sequence))
    );
    assert_eq!(
        admit_claim(&s, account.remaining + 1, account.claims),
        Err(ClaimError::Dividend(DivError::Overdrawn))
    );

    // The Treasury coin plan is exactly plan_spend over treasury_owner_order: oldest generation
    // first, change back to the last coin's own address.
    let order = s.treasury_owner_order();
    assert_eq!(order, vec![g1, g2]);
    let plan = plan_spend(&s.coins, &order, 1_000).unwrap();
    assert_eq!(plan.inputs, vec![point(1), point(2)]);
    assert_eq!((plan.change_owner, plan.change), (g2, 500 + 60_000 - 1_000));

    // Consensus spends from the OLD generation too: with only its 500 atoms left a 400-atom claim
    // is admitted, which a view of just the newest address would call unbacked.
    let mut old_only = s.clone();
    old_only.coins.remove(&point(2));
    admit_claim(&old_only, 400, 0).unwrap();
    assert!(plan_spend(&old_only.coins, &old_only.treasury_owner_order(), 400).is_ok());
    assert!(matches!(
        plan_spend(&old_only.coins, &[g2], 400),
        Err(ClaimError::Backing)
    ));
    // Without enough Treasury coins both refuse the same way.
    assert_eq!(admit_claim(&old_only, 501, 0), Err(ClaimError::Backing));
    assert!(matches!(
        plan_spend(&old_only.coins, &old_only.treasury_owner_order(), 501),
        Err(ClaimError::Backing)
    ));
    let mut none = s.clone();
    none.coins.clear();
    assert_eq!(admit_claim(&none, 1_000, 0), Err(ClaimError::Backing));
    // A Treasury coin that is coinbase does not back a claim in either view.
    let mut coinbase = s.clone();
    coinbase.coins.clear();
    coinbase.coins.insert(point(2), coin(g2, 60_000, true));
    assert_eq!(admit_claim(&coinbase, 1_000, 0), Err(ClaimError::Backing));
    assert!(matches!(
        plan_spend(&coinbase.coins, &coinbase.treasury_owner_order(), 1_000),
        Err(ClaimError::Backing)
    ));
}

#[test]
fn claim_sequence_advances_with_each_confirmed_partial_claim() {
    // The ledger the wallet reads from confirmed state: `claims` is the next sequence and
    // `remaining` the amount still claimable; a stale or skipped sequence is a distinct refusal.
    let (id, owner) = ([7; 32], [9; 32]);
    let view = LicenseView {
        id,
        owner,
        activation_epoch: Some(0),
        status: Status::Active,
    };
    let mut ledger = Ledger::new();
    ledger
        .advance(P, 1_000, std::slice::from_ref(&view))
        .unwrap();
    let claim = |amount: u64, sequence: u64| Claim {
        award_epoch: P,
        license: id,
        claimant: owner,
        amount,
        sequence,
    };
    let read = |l: &Ledger| l.award(P).unwrap().account(&id).unwrap();
    let account = read(&ledger);
    assert_eq!(
        (account.share, account.remaining, account.claims),
        (500, 500, 0)
    );
    for (n, amount) in [(0, 100), (1, 150), (2, 250)] {
        let before = read(&ledger);
        assert_eq!(before.claims, n, "next sequence = confirmed claim count");
        assert_eq!(
            ledger.check_claim(&claim(amount, n + 1), P + 1, &view),
            Err(DivError::Sequence)
        );
        if n > 0 {
            assert_eq!(
                ledger.check_claim(&claim(amount, n - 1), P + 1, &view),
                Err(DivError::Replay)
            );
        }
        ledger
            .claim(&claim(amount, before.claims), P + 1, &view)
            .unwrap();
        let after = read(&ledger);
        assert_eq!(
            (after.claims, after.remaining),
            (n + 1, before.remaining - amount)
        );
    }
    assert_eq!(read(&ledger).remaining, 0);
}
