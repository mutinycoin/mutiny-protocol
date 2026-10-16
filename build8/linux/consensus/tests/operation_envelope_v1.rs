//! Operation envelope V1 through the PUBLIC library API, built WITHOUT `cfg(test)` (Lane P design
//! `qualification/candidate-3/P-LANE-DESIGN-V1.md` sections 1.a and 12.2; work package WP-P0).
//! The codec, window, reference and precondition rules are unit-tested in
//! `consensus/src/op_envelope_v1_tests.rs`; this file checks what only an outside build can show:
//! the committed vectors decode through the public API, the new domain is registered, and the
//! unit-test-only carrier is not an item kind of the library. TEST-VALUE data only.
use mutiny_consensus_v8::{
    Error,
    blocks::{self, BlockBody},
    op_envelope_v1::{self as envelope, Envelope},
};

fn carrier(e: &Envelope) -> Vec<u8> {
    let mut x = minicbor::Encoder::new(Vec::new());
    x.array(3).unwrap().u8(2).unwrap().u8(254).unwrap();
    e.encode(&mut x).unwrap();
    x.into_writer()
}

/// Design 12.2: every new domain string is registered exactly once as PROPOSED-UNFROZEN, with the
/// spec that defines it (sibling of `new_domains_are_registered_as_proposed_and_unfrozen`).
#[test]
fn envelope_domains_are_registered_as_proposed_and_unfrozen() {
    let registry: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string("../spec/DOMAIN-REGISTRY-V1.json").unwrap()).unwrap();
    let listed = registry["domains"].as_array().unwrap();
    for domain in [envelope::ASSIGNMENT_ID_DOMAIN] {
        let ascii = std::str::from_utf8(domain).unwrap();
        let entries: Vec<_> = listed.iter().filter(|e| e["ascii"] == ascii).collect();
        assert_eq!(entries.len(), 1, "{ascii} registered exactly once");
        assert_eq!(entries[0]["status"], "PROPOSED-UNFROZEN", "{ascii}");
        assert_eq!(entries[0]["doc"], "spec/OPERATION-ENVELOPE-AND-CONFIRMATION-V1.md", "{ascii}");
    }
    let ascii: Vec<_> = listed.iter().map(|e| e["ascii"].as_str().unwrap()).collect();
    let mut unique = ascii.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), ascii.len(), "no domain string is registered twice");
}

/// The unit tests drive the History plumbing with a TEST-ONLY carrier `[2, 254, Envelope]`. In the
/// library as every other crate links it, that encoding is not an item kind: the body codec's
/// discriminator refuses it and no reference height is extracted from it.
#[test]
fn the_test_only_carrier_is_not_an_item_kind_of_the_library() {
    let e = Envelope { first_height: 8, last_height: 9, reference_height: 3, reference_block: [3; 32], preconditions: vec![] };
    let raw = carrier(&e);
    assert_eq!(blocks::operation_kind(&raw), Err(Error::WrongOperation));
    assert_eq!(envelope::operation_envelope(&raw), None);
    assert_eq!(envelope::transaction_envelope(&raw), None);
    assert_eq!(envelope::envelope_at(&raw, 2), Some(e), "the bytes do hold a valid envelope");
    let body = BlockBody { height: 9, reward_owner: [1; 32], fees: 0, transactions: vec![raw.clone()], operations: vec![raw] };
    assert!(envelope::referenced_heights(&body).is_empty());
    assert!(body.encode().is_err(), "a block body carrying it cannot even be encoded");
}

/// A second, public-API reader of the committed vectors (the unit reader also checks that the file
/// is byte-identical to its generator).
#[test]
fn committed_envelope_vectors_decode_through_the_public_api() {
    let text = std::fs::read_to_string("../qualification/operation-envelope-v1-vectors.json").unwrap();
    let document: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(document["synthetic_only"], true);
    assert_eq!(document["production_authorized"], false);
    for v in document["valid"].as_array().unwrap() {
        let raw = hex::decode(v["cbor_hex"].as_str().unwrap()).unwrap();
        let decoded = Envelope::from_bytes(&raw).unwrap();
        assert_eq!(decoded.to_bytes().unwrap(), raw, "{}", v["name"]);
        let f = &v["fields"];
        assert_eq!(decoded.first_height, f["first_height"].as_u64().unwrap());
        assert_eq!(decoded.last_height, f["last_height"].as_u64().unwrap());
        assert_eq!(decoded.reference_height, f["reference_height"].as_u64().unwrap());
        assert_eq!(hex::encode(decoded.reference_block), f["reference_block"].as_str().unwrap());
        assert_eq!(decoded.preconditions.len(), f["preconditions"].as_array().unwrap().len());
    }
    let invalid = document["invalid"].as_array().unwrap();
    assert!(invalid.len() >= 30);
    for v in invalid {
        let raw = hex::decode(v["cbor_hex"].as_str().unwrap()).unwrap();
        let error = Envelope::from_bytes(&raw).expect_err(v["name"].as_str().unwrap());
        assert_eq!(format!("{error:?}"), v["error"].as_str().unwrap(), "{}", v["name"]);
    }
}

/// WP-T1: the trading rows of test plan 14.4 (trading body version 2 carries the envelope) and the
/// AM-11 replay negatives, through REAL blocks: the production assembler, the V2 executor and
/// `CanonicalStore::commit`, whose History carries the canonical block hash of every referenced
/// height (WP-P0 plumbing). Some rows additionally drive the executor directly with an explicit
/// History (`prepare_with_anchors`) to show the fail-closed behaviour without it. Every negative
/// asserts the exact `NativeError` at the read-only consensus entry point on the same parent state
/// and the block-level rejection with the store byte-identical. TEST-VALUE only.
#[allow(dead_code, unused_imports)]
mod trading {
    mod licenses {
        include!("../../desktop/src/wallet_host_fixture_licenses.rs");
    }
    mod tpm {
        include!("support/wallet_host_fixture_tpm.rs");
    }
    include!("support/dividend_rig.rs");
    include!("support/trading_rig_v1.rs");
    use mutiny_consensus_v8::op_envelope_v1::{EnvelopeError, assignment_facts, entitlement_facts};
    use tr::NativeError as N;

    const DESTINATION: Hash = [0x5d; 32];

    fn lock_action(sender: Hash, recipient: Hash, refund_height: u64) -> tr::Action {
        tr::Action::HashLock {
            offer: [0; 32],
            maker: [0; 32],
            sender,
            recipient,
            amount: tr::Strikes(50_000),
            condition: tr::preimage_hash(&[42; 32]),
            refund_height,
            change: tr::Strikes(30_000),
        }
    }
    fn sale_action(license: Hash, seller: Hash, buyer: Hash) -> tr::Action {
        tr::Action::LicenseDvp {
            offer: [0; 32],
            maker: [0; 32],
            license,
            license_generation: 1,
            seller,
            buyer,
            price: tr::Strikes(50_000),
            payment_destination: DESTINATION,
            change: tr::Strikes(30_000),
        }
    }
    /// The License facts a sale commits to (entitlements, assignment), read from `state`.
    fn sale_facts(state: &State, license: Hash) -> Vec<Precondition> {
        vec![entitlement_facts(state, license), assignment_facts(state, license).unwrap()]
    }
    fn raw(op: &tr::NativeOperation) -> Vec<u8> {
        op.encode().unwrap()
    }
    fn applied_height(state: &State, op: &tr::NativeOperation) -> u64 {
        let key = tr::record_key(2, op.operation.id().unwrap());
        match tr::NativeRecord::decode(&state.protocol_records[&key]).unwrap().1 {
            tr::NativeRecord::Applied { height, .. } => height,
            other => panic!("not an Applied record: {other:?}"),
        }
    }

    /// 14.4 head advancement: a hash lock and a License DvP signed against head h stay valid when
    /// they are included 20 finalized blocks later, inside their unchanged signed window; their
    /// effects are recorded at the ACTUAL inclusion height.
    #[test]
    fn operation_survives_head_advance_within_window() {
        let (a, b) = (owner_key(), second_key());
        let (aa, ba) = (addr(&a, 1), addr(&b, 1));
        let mut f = fixture();
        let p_lock = fund(&mut f, 0xd1, aa, 100_000);
        let p_sale = fund(&mut f, 0xd2, ba, 100_000);
        let sold = license(3);
        let mut rig = Rig::new(f, "envelope-advance");
        advance(&mut rig, 2);
        let h = rig.height();
        // Both parties review and sign against head h: window [h+1, h+30], reference = block h.
        let window = window_at(&rig, h, h + 1, h + 30);
        let lock = trade(&rig.f, lock_action(aa, ba, h + 31), window, 20_000, &[p_lock], &[(0, &a, 1), (1, &b, 1)]);
        let sale = trade_with(
            &rig.f,
            sale_action(sold, aa, ba),
            window,
            sale_facts(&rig.state, sold),
            20_000,
            &[p_sale],
            &[(0, &a, 1), (1, &b, 1)],
        );
        let ops = vec![raw(&lock), raw(&sale)];
        advance(&mut rig, 20);
        assert_eq!(rig.height(), h + 20);
        // Without the reference anchor an entry point fails closed; a wrong anchor is not canonical.
        assert!(matches!(native_verdict(&rig, &ops), Err(N::Envelope(EnvelopeError::ReferenceNotCanonical))));
        let mut forged = mutiny_consensus_v8::evidence_history_v2::History::default();
        forged.insert_anchor(h, [0xee; 32]).unwrap();
        assert!(matches!(
            tr::prepare_batch_with_history(
                &rig.state,
                &rig.parent,
                rig.state.root().unwrap(),
                &forged,
                &ops,
                &tr::CandidatePolicy::native_denomination_locked()
            ),
            Err(N::Envelope(EnvelopeError::ReferenceNotCanonical))
        ));
        // With the canonical block hash of h, the unchanged bytes are valid 20 heights later.
        native_verdict_with(&rig, &ops, &[h]).unwrap();
        let inclusion = rig.height() + 1;
        let prepared = prepare_with_anchors(&rig, inclusion, &ops, &[h]).unwrap();
        assert_eq!(prepared.body.operations, ops);
        assert_eq!(prepared.body.fees, 40_000, "the declared trading fees reach the coinbase");
        // The real block: assembled, committed and installed by the store at h + 21.
        let committed = rig.step(inclusion, &ops);
        assert_eq!(committed.records().unwrap(), prepared.execution.state.records().unwrap());
        // A reopened store replays the chain, rebuilding the same anchors.
        let rig = rig.restart();
        assert_eq!(rig.state.records().unwrap(), committed.records().unwrap());
        let s = &rig.state;
        let l = tr::locked(s, lock.operation.output_id(0).unwrap()).unwrap();
        assert_eq!(l.created_height, inclusion, "the lock starts at the actual inclusion height");
        assert_eq!(s.licenses_v2.license(sold).unwrap().owner, ba);
        match tr::NativeRecord::decode(&s.protocol_records[&tr::record_key(4, sold)]).unwrap().1 {
            tr::NativeRecord::License { inclusion_height, rights_from_height, .. } => {
                assert_eq!((inclusion_height, rights_from_height), (inclusion, inclusion + 1))
            }
            other => panic!("{other:?}"),
        }
        assert_eq!((applied_height(s, &lock), applied_height(s, &sale)), (inclusion, inclusion));
        rig.finish();
    }

    /// 14.4 windows: a window that has not opened (Future) and one that has passed (Expired) are
    /// refused by the assembler path and by `commit` with the store byte-identical; both inclusive
    /// edges are accepted.
    #[test]
    fn expired_and_future_windows_reject_byte_identical() {
        let (a, b) = (owner_key(), second_key());
        let (aa, ba) = (addr(&a, 1), addr(&b, 1));
        let mut f = fixture();
        let points: Vec<OutPoint> = (0..4).map(|i| fund(&mut f, 0xe0 + i, aa, 100_000)).collect();
        let mut rig = Rig::new(f, "envelope-window");
        let signers = [(0, &a, 1), (1, &b, 1)];
        // Future: reference = the parent (Genesis), window [3, 10], next height 1.
        let future = raw(&trade(&rig.f, lock_action(aa, ba, 20), window_at(&rig, 0, 3, 10), 20_000, &points[0..1], &signers));
        assert!(matches!(native_verdict(&rig, &[future.clone()]), Err(N::Envelope(EnvelopeError::Future))));
        rejected_unchanged(&mut rig, 1, &[future.clone()]);
        commit_rejected_unchanged(&mut rig, 1, &[future]);
        // Inclusive edge first == last == H through the store.
        let exact = raw(&trade(&rig.f, lock_action(aa, ba, 20), window_at(&rig, 0, 1, 1), 20_000, &points[1..2], &signers));
        rig.step(1, &[exact]);
        // Signed against head 1: [2, 3] expires before height 4; [2, 4] is valid exactly at 4.
        let expiring = raw(&trade(&rig.f, lock_action(aa, ba, 20), window_at(&rig, 1, 2, 3), 20_000, &points[2..3], &signers));
        let edge = raw(&trade(&rig.f, lock_action(aa, ba, 20), window_at(&rig, 1, 2, 4), 20_000, &points[3..4], &signers));
        advance(&mut rig, 2);
        assert_eq!(rig.height(), 3);
        assert!(matches!(native_verdict(&rig, &[expiring.clone()]), Err(N::Envelope(EnvelopeError::Expired))));
        assert!(matches!(
            native_verdict_with(&rig, &[expiring.clone()], &[1]),
            Err(N::Envelope(EnvelopeError::Expired))
        ));
        rejected_unchanged(&mut rig, 4, &[expiring.clone()]);
        commit_rejected_unchanged(&mut rig, 4, &[expiring]);
        native_verdict_with(&rig, &[edge.clone()], &[1]).unwrap();
        let prepared = prepare_with_anchors(&rig, 4, &[edge.clone()], &[1]).unwrap();
        assert_eq!(prepared.body.operations, vec![edge.clone()], "H == last is inside the window");
        // One block later the same bytes are expired.
        advance(&mut rig, 1);
        assert!(matches!(native_verdict_with(&rig, &[edge.clone()], &[1]), Err(N::Envelope(EnvelopeError::Expired))));
        executor_rejected(&rig, 5, &[edge.clone()], &[1]);
        rejected_unchanged(&mut rig, 5, &[edge.clone()]);
        commit_rejected_unchanged(&mut rig, 5, &[edge]);
        rig.finish();
    }

    /// 14.4 reference rules for trading items: the parent shortcut needs no History; an older
    /// reference needs its canonical anchor and fails closed without it; a non-canonical block at
    /// the parent or at an older height is refused with the store byte-identical.
    #[test]
    fn reference_rules_for_trading_items() {
        let (a, b) = (owner_key(), second_key());
        let (aa, ba) = (addr(&a, 1), addr(&b, 1));
        let mut f = fixture();
        let points: Vec<OutPoint> = (0..4).map(|i| fund(&mut f, 0xf0 + i, aa, 100_000)).collect();
        let mut rig = Rig::new(f, "envelope-reference");
        let signers = [(0, &a, 1), (1, &b, 1)];
        advance(&mut rig, 2);
        let at_parent = raw(&trade(&rig.f, lock_action(aa, ba, 20), window_at(&rig, 2, 3, 10), 20_000, &points[0..1], &signers));
        let forged_parent = Window { first: 3, last: 10, reference: (2, [0xee; 32]) };
        let forged_parent = raw(&trade(&rig.f, lock_action(aa, ba, 20), forged_parent, 20_000, &points[1..2], &signers));
        let older = raw(&trade(&rig.f, lock_action(aa, ba, 20), window_at(&rig, 1, 2, 10), 20_000, &points[2..3], &signers));
        let forged_older = Window { first: 2, last: 10, reference: (1, [0xee; 32]) };
        let forged_older = raw(&trade(&rig.f, lock_action(aa, ba, 20), forged_older, 20_000, &points[3..4], &signers));
        // The parent shortcut: valid with an empty History.
        native_verdict(&rig, &[at_parent.clone()]).unwrap();
        // A non-canonical block at the parent height.
        assert!(matches!(
            native_verdict(&rig, &[forged_parent.clone()]),
            Err(N::Envelope(EnvelopeError::ReferenceNotCanonical))
        ));
        rejected_unchanged(&mut rig, 3, &[forged_parent.clone()]);
        commit_rejected_unchanged(&mut rig, 3, &[forged_parent]);
        // An older canonical reference: fails closed without its anchor, valid with it.
        assert!(matches!(native_verdict(&rig, &[older.clone()]), Err(N::Envelope(EnvelopeError::ReferenceNotCanonical))));
        native_verdict_with(&rig, &[older.clone()], &[1]).unwrap();
        prepare_with_anchors(&rig, 3, &[older.clone()], &[1]).unwrap();
        // A non-canonical block at an older height, even with the canonical anchor at hand.
        assert!(matches!(
            native_verdict_with(&rig, &[forged_older.clone()], &[1]),
            Err(N::Envelope(EnvelopeError::ReferenceNotCanonical))
        ));
        executor_rejected(&rig, 3, &[forged_older.clone()], &[1]);
        rejected_unchanged(&mut rig, 3, &[forged_older]);
        // Controls: the parent-reference item and the older canonical reference are installed
        // through the store in one block (the store supplies the anchor of height 1).
        let s3 = rig.step(3, &[at_parent.clone(), older.clone()]);
        assert_eq!(rig.height(), 3);
        for item in [&at_parent, &older] {
            let tr::NativeOperation { operation, .. } = tr::NativeOperation::decode(item).unwrap();
            assert!(tr::locked(&s3, operation.output_id(0).unwrap()).is_ok());
        }
        rig.finish();
    }

    /// 5.1 HashLock / Claim / Refund relations: the lock's refund height must exceed the WHOLE
    /// signed window; Claim (H < R) and Refund (H >= R) use the ACTUAL inclusion height H, never a
    /// signed height, so a window that spans R grants no extra eligibility.
    #[test]
    fn hash_lock_refund_relation_uses_the_signed_window_and_the_inclusion_height() {
        let (a, b) = (owner_key(), second_key());
        let (aa, ba) = (addr(&a, 1), addr(&b, 1));
        let mut f = fixture();
        let p = [
            fund(&mut f, 0x91, aa, 100_000),
            fund(&mut f, 0x92, aa, 100_000),
            fund(&mut f, 0x93, aa, 100_000),
            fund(&mut f, 0x94, ba, 100_000),
            fund(&mut f, 0x95, aa, 100_000),
        ];
        let mut rig = Rig::new(f, "envelope-refund");
        let signers = [(0, &a, 1), (1, &b, 1)];
        let w = window_at(&rig, 0, 1, 10);
        let at_last = raw(&trade(&rig.f, lock_action(aa, ba, 10), w, 20_000, &p[0..1], &signers));
        assert!(matches!(native_verdict(&rig, &[at_last.clone()]), Err(N::Bounds)), "R == last_height");
        rejected_unchanged(&mut rig, 1, &[at_last]);
        let beyond = raw(&trade(&rig.f, lock_action(aa, ba, 11), w, 20_000, &p[1..2], &signers));
        let short = trade(&rig.f, lock_action(aa, ba, 5), window_at(&rig, 0, 1, 4), 20_000, &p[2..3], &signers);
        rig.step(1, &[beyond, raw(&short)]);
        let output = short.operation.output_id(0).unwrap();
        // Signed against head 1, both windows [2, 10] span the refund height 5.
        let spanning = window_at(&rig, 1, 2, 10);
        let claim = raw(&trade(
            &rig.f,
            tr::Action::Claim { output, recipient: ba, amount: tr::Strikes(50_000), preimage: [42; 32], change: tr::Strikes(80_000) },
            spanning,
            20_000,
            &p[3..4],
            &[(0, &b, 1)],
        ));
        let refund = raw(&trade(
            &rig.f,
            tr::Action::Refund { output, owner: aa, amount: tr::Strikes(50_000), change: tr::Strikes(80_000) },
            spanning,
            20_000,
            &p[4..5],
            &[(0, &a, 1)],
        ));
        advance(&mut rig, 2);
        // H = 4 < R: the refund is refused although its window reaches past R.
        assert!(matches!(native_verdict_with(&rig, &[refund.clone()], &[1]), Err(N::Time)));
        executor_rejected(&rig, 4, &[refund.clone()], &[1]);
        rejected_unchanged(&mut rig, 4, &[refund.clone()]);
        commit_rejected_unchanged(&mut rig, 4, &[refund.clone()]);
        advance(&mut rig, 1);
        // H = 5 == R: the claim is refused although its window opened before R ...
        assert!(matches!(native_verdict_with(&rig, &[claim.clone()], &[1]), Err(N::Time)));
        executor_rejected(&rig, 5, &[claim.clone()], &[1]);
        rejected_unchanged(&mut rig, 5, &[claim.clone()]);
        commit_rejected_unchanged(&mut rig, 5, &[claim]);
        // ... and the refund is now eligible, in a real block.
        let s5 = rig.step(5, &[refund.clone()]);
        let id = tr::NativeOperation::decode(&refund).unwrap().operation.id().unwrap();
        let paid = &s5.coins[&OutPoint { transaction: id, index: 0 }];
        assert_eq!((paid.output.owner, paid.output.atoms), (aa, 50_000));
        rig.finish();
    }

    /// AM-11: replay under envelopes. A trading item's window does not protect against replay; its
    /// Applied record does: the identical bytes are refused (Duplicate) while their window is still
    /// open, for a funding lock and for its claim.
    #[test]
    fn applied_record_replay_rejected_while_the_window_is_open() {
        let (a, b) = (owner_key(), second_key());
        let (aa, ba) = (addr(&a, 1), addr(&b, 1));
        let mut f = fixture();
        let p_lock = fund(&mut f, 0x81, aa, 100_000);
        let p_claim = fund(&mut f, 0x82, ba, 100_000);
        let mut rig = Rig::new(f, "envelope-replay");
        let lock = trade(&rig.f, lock_action(aa, ba, 50), window_at(&rig, 0, 1, 40), 20_000, &[p_lock], &[(0, &a, 1), (1, &b, 1)]);
        rig.step(1, &[raw(&lock)]);
        assert!(matches!(native_verdict_with(&rig, &[raw(&lock)], &[0]), Err(N::Duplicate)));
        rejected_unchanged(&mut rig, 2, &[raw(&lock)]);
        commit_rejected_unchanged(&mut rig, 2, &[raw(&lock)]);
        let claim = trade(
            &rig.f,
            tr::Action::Claim {
                output: lock.operation.output_id(0).unwrap(),
                recipient: ba,
                amount: tr::Strikes(50_000),
                preimage: [42; 32],
                change: tr::Strikes(80_000),
            },
            window_at(&rig, 1, 2, 40),
            20_000,
            &[p_claim],
            &[(0, &b, 1)],
        );
        rig.step(2, &[raw(&claim)]);
        assert!(matches!(native_verdict_with(&rig, &[raw(&claim)], &[1]), Err(N::Duplicate)));
        rejected_unchanged(&mut rig, 3, &[raw(&claim)]);
        commit_rejected_unchanged(&mut rig, 3, &[raw(&claim)]);
        rig.finish();
    }

    /// AM-11: the dividend claim sequence keeps protecting a claim made in the same block as a
    /// License sale (trades before claims); replaying the sale or the claim while the sale's window
    /// is still open is refused (Applied record, claim sequence) with the store byte-identical.
    #[test]
    fn claim_sequence_and_sale_replay_rejected_under_envelopes() {
        let treasury = treasury_key();
        let (a, b) = (owner_key(), second_key());
        let (aa, ba) = (addr(&a, 1), addr(&b, 1));
        let mut f = fixture_with_treasury(&treasury, 1_200_000);
        let p_sale = fund(&mut f, 0x71, ba, 100_000);
        let mut rig = Rig::new(f, "envelope-claim-replay");
        let sold = license(3);
        rig.step(P, &[]);
        let sale = trade_with(
            &rig.f,
            sale_action(sold, aa, ba),
            window_at(&rig, 1, 2, 40),
            sale_facts(&rig.state, sold),
            20_000,
            &[p_sale],
            &[(0, &a, 1), (1, &b, 1)],
        );
        let claim = claim_op(&rig.f, &b, 3, P, 1_000, 0, [0x77; 32]);
        let s2 = rig.step(P + 1, &[raw(&sale), claim.clone()]);
        assert_eq!(s2.licenses_v2.license(sold).unwrap().owner, ba);
        assert_eq!(s2.dividends.ledger().award(P).unwrap().account(&sold).unwrap().claims, 1);
        assert!(matches!(native_verdict_with(&rig, &[raw(&sale)], &[1]), Err(N::Duplicate)));
        rejected_unchanged(&mut rig, P + 2, &[raw(&sale)]);
        // The per-award/per-License counter is 1 now: sequence 0 is below it, which is a replay.
        let text = rejected_unchanged(&mut rig, P + 2, &[claim]);
        assert!(text.contains("Dividend(Replay)"), "the claim replay fails on its sequence: {text}");
        rig.finish();
    }

    /// 1.a.5 validation point: committed preconditions are compared against the tentative state
    /// AFTER the earlier trading items of the same block. A TreasuryHead precondition is stale once
    /// an earlier item of the block rotated that head (Stale(3)), and valid when listed before it.
    #[test]
    fn preconditions_compare_after_earlier_trading_items_of_the_block() {
        let (a, b, c) = (owner_key(), second_key(), treasury_key());
        let (aa, ba, ca) = (addr(&a, 1), addr(&b, 1), addr(&c, 1));
        let nb = addr(&b, 2);
        let mut f = fixture();
        let p_lock = fund(&mut f, 0x61, aa, 100_000);
        let p_rotate = fund(&mut f, 0x62, ca, 100_000);
        // P6 (WP-T3): T = ca is the Genesis Treasury authority; R1 already moved T's key to b at
        // generation 2, so the honest R2 routes to nb, approved by that current key.
        genesis_treasury_after_r1(&mut f, &c, (&b, 2));
        let mut rig = Rig::new(f, "envelope-head");
        let w = window_at(&rig, 0, 1, 10);
        let rotate = raw(&trade(
            &rig.f,
            tr::Action::TreasuryRotate {
                treasury: ca,
                current_generation: 1,
                current_address: ca,
                current_descriptor: tr::descriptor_hash(&desc(&b, 2)),
                new_generation: 2,
                new_address: nb,
                new_descriptor: desc(&b, 2),
                change: tr::Strikes(80_000),
            },
            w,
            20_000,
            &[p_rotate],
            &[(0, &b, 2)],
        ));
        let head = Precondition::TreasuryHead { treasury: ca, generation: 1, address: ca };
        let lock = raw(&trade_with(&rig.f, lock_action(aa, ba, 20), w, vec![head], 20_000, &[p_lock], &[(0, &a, 1), (1, &b, 1)]));
        native_verdict(&rig, &[lock.clone()]).unwrap();
        let stale = vec![rotate.clone(), lock.clone()];
        assert!(matches!(native_verdict(&rig, &stale), Err(N::Stale(3))));
        rejected_unchanged(&mut rig, 1, &stale);
        commit_rejected_unchanged(&mut rig, 1, &stale);
        let s1 = rig.step(1, &[lock, rotate]);
        assert_eq!(tr::treasury_current(&s1, &trade_context(&rig.f), ca).unwrap().generation, 2);
        rig.finish();
    }

    /// 1.a.5 and 6.2 with AM-3 and AM-11: a sale's committed License facts are compared AFTER the
    /// sale block's own epoch events (here the first award boundary). The exact error is asserted
    /// on the tentative state built the way the executor builds it (activation, then the epoch's
    /// dividend events); the parent-state view gives the opposite verdict for both sales, so the
    /// assembler previews only DECLARED fees (AM-3) and the valid sale is included.
    #[cfg(feature = "dividend-test-fixtures")]
    #[test]
    fn sale_facts_are_compared_after_the_blocks_own_epoch_events() {
        let treasury = treasury_key();
        let (a, b) = (owner_key(), second_key());
        let (aa, ba) = (addr(&a, 1), addr(&b, 1));
        let mut f = fixture_with_treasury(&treasury, 1_200_000);
        let p_stale = fund(&mut f, 0x51, ba, 100_000);
        let p_fresh = fund(&mut f, 0x52, ba, 100_000);
        let mut rig = Rig::new(f, "envelope-epoch");
        let sold = license(3);
        let before = sale_facts(&rig.state, sold);
        let mut tentative = rig.state.clone();
        tentative.licenses_v2.activate_due(P).unwrap();
        tentative.fixture_advance_dividends(P).unwrap();
        let after = sale_facts(&tentative, sold);
        assert_ne!(before, after, "the boundary P creates this License's award account");
        let w = window_at(&rig, 0, 1, 10);
        let signers = [(0, &a, 1), (1, &b, 1)];
        let stale = raw(&trade_with(&rig.f, sale_action(sold, aa, ba), w, before, 20_000, &[p_stale], &signers));
        let fresh = raw(&trade_with(&rig.f, sale_action(sold, aa, ba), w, after, 20_000, &[p_fresh], &signers));
        let phase = |ops: &[Vec<u8>]| {
            tr::prepare_candidate_phase(
                &rig.state,
                &tentative,
                &rig.parent,
                rig.state.root().unwrap(),
                &mutiny_consensus_v8::evidence_history_v2::History::default(),
                ops,
                &tr::CandidatePolicy::native_denomination_locked(),
            )
        };
        assert!(matches!(phase(&[stale.clone()]), Err(N::Stale(1))));
        phase(&[fresh.clone()]).unwrap();
        native_verdict(&rig, &[stale.clone()]).unwrap();
        assert!(matches!(native_verdict(&rig, &[fresh.clone()]), Err(N::Stale(1))));
        rejected_unchanged(&mut rig, P, &[stale.clone()]);
        commit_rejected_unchanged(&mut rig, P, &[stale]);
        let s1 = rig.step(P, &[fresh]);
        assert_eq!(s1.licenses_v2.license(sold).unwrap().owner, ba);
        let account = s1.dividends.ledger().award(P).unwrap().account(&sold).unwrap();
        assert_eq!((account.share, account.remaining, account.claims), (50_000, 50_000, 0));
        rig.finish();
    }
}
