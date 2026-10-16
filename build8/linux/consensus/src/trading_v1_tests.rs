use super::*;
use mutiny_crypto_v2::{HybridKey, Role};
use std::sync::OnceLock;
struct Keys {
    a: HybridKey,
    b: HybridKey,
    c: HybridKey,
}
fn keys() -> &'static Keys {
    static K: OnceLock<Keys> = OnceLock::new();
    // Published BIP39 test-vector phrases, never production custody material.
    let restore = |phrase: &str| HybridKey::wallet_restore(phrase, Role::WalletOwner).unwrap();
    K.get_or_init(|| Keys {
        a: restore(&("abandon ".repeat(23)+"art")),
        b: restore(&("zoo ".repeat(23)+"vote")),
        c: restore("letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"),
    })
}
fn addr(k: &HybridKey) -> Hash {
    k.public().address_id(1).unwrap()
}
fn context() -> Context {
    Context {
        network: crate::NETWORK_ID,
        genesis: [11; 32],
        fingerprint: [12; 32],
    }
}
fn anchor(height: u64) -> FinalizedAnchor {
    FinalizedAnchor {
        network: crate::NETWORK_ID,
        genesis: [11; 32],
        fingerprint: [12; 32],
        height,
        block: [13; 32],
    }
}
fn point(n: u8) -> OutPoint {
    OutPoint {
        transaction: [n; 32],
        index: 0,
    }
}
fn state() -> State {
    let mut s = State::default();
    for k in [&keys().a, &keys().b, &keys().c] {
        s.wallets
            .register(&k.public().descriptor(1).unwrap())
            .unwrap();
    }
    for (n, k) in [
        (1, &keys().a),
        (2, &keys().b),
        (3, &keys().a),
        (4, &keys().b),
        (5, &keys().c),
        (6, &keys().a),
    ] {
        s.coins.insert(
            point(n),
            Coin {
                output: Output {
                    owner: addr(k),
                    atoms: 100_000,
                },
                created_height: 0,
                coinbase: false,
            },
        );
    }
    s
}
fn native(mut op: Operation, input: u8, signers: &[&HybridKey]) -> NativeOperation {
    op.meta.inputs = vec![native_input_id(&point(input))];
    op.approvals.clear();
    let terms = match &op.action {
        Action::HashLock { amount, .. } => Some(OfferTerms::HashLinked {
            amount: *amount,
            bitcoin_satoshis: 10000,
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
        // P7 (WP-T4, AM-6): the maker is the slot-0 party and signs with its wallet owner key.
        let maker: &HybridKey = signers.first().copied().unwrap_or(&keys().a);
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
            maker_descriptor: maker.public().descriptor(1).unwrap(),
            maker_wallet: op.slot_address(0).unwrap(),
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
        };
        op.offer_proof = Some(OfferProof::sign(offer, &op, maker).unwrap());
    }
    for (i, k) in signers.iter().enumerate() {
        op.approve(i as u8, k, 1).unwrap();
    }
    NativeOperation {
        operation: op,
        inputs: vec![point(input)],
    }
}
/// The envelope of a test operation (body version 2): the signed window [first, last] and the
/// synthetic test chain's block `[13; 32]` at `first - 1` as its finalized reference.
fn envelope(first: u64, last: u64) -> Envelope {
    Envelope {
        first_height: first,
        last_height: last,
        reference_height: first - 1,
        reference_block: [13; 32],
        preconditions: vec![],
    }
}
/// The authenticated History of the synthetic test chain below `parent_height`: every block is
/// `[13; 32]` (the parent itself is checked against the anchor, not the History).
fn chain_history(parent_height: u64) -> History {
    let mut history = History::default();
    for height in 0..parent_height {
        history.insert_anchor(height, [13; 32]).unwrap();
    }
    history
}
fn op(action: Action, created: u64, expiry: u64) -> Operation {
    Operation {
        meta: Meta {
            context: context(),
            trade: [21; 32],
            contract: [22; 32],
            generation: 1,
            envelope: envelope(created, expiry),
            fee: Strikes(20_000),
            inputs: vec![],
        },
        action,
        approvals: vec![],
        offer_proof: None,
    }
}
fn lock() -> NativeOperation {
    native(
        op(
            Action::HashLock {
                offer: [0; 32],
                maker: [0; 32],
                sender: addr(&keys().a),
                recipient: addr(&keys().b),
                amount: Strikes(50_000),
                condition: preimage_hash(&[42; 32]),
                refund_height: 20,
                change: Strikes(30_000),
            },
            2,
            10,
        ),
        1,
        &[&keys().a, &keys().b],
    )
}
fn claim(l: &NativeOperation) -> NativeOperation {
    native(
        op(
            Action::Claim {
                output: l.operation.output_id(0).unwrap(),
                recipient: addr(&keys().b),
                amount: Strikes(50_000),
                preimage: [42; 32],
                change: Strikes(80_000),
            },
            3,
            25,
        ),
        2,
        &[&keys().b],
    )
}
fn refund(l: &NativeOperation) -> NativeOperation {
    native(
        op(
            Action::Refund {
                output: l.operation.output_id(0).unwrap(),
                owner: addr(&keys().a),
                amount: Strikes(50_000),
                change: Strikes(80_000),
            },
            3,
            25,
        ),
        3,
        &[&keys().a],
    )
}
fn prepare(s: &State, h: u64, ops: &[NativeOperation]) -> NativeResult<Prepared> {
    prepare_batch_with_history(
        s,
        &anchor(h - 1),
        s.root().unwrap(),
        &chain_history(h - 1),
        &ops.iter().map(|o| o.encode().unwrap()).collect::<Vec<_>>(),
        &CandidatePolicy::synthetic_one_atom_per_strike(),
    )
}
#[test]
fn native_lock_claim_uses_actual_utxos_wallets_and_state_root() {
    let s = state();
    let l = lock();
    let p = prepare(&s, 2, std::slice::from_ref(&l)).unwrap();
    assert!(!p.state().coins.contains_key(&point(1)));
    assert_eq!(p.fee_atoms(), 20_000);
    assert_eq!(
        locked(p.state(), l.operation.output_id(0).unwrap())
            .unwrap()
            .amount,
        Strikes(50_000)
    );
    let restored = State::from_records(&p.state().records().unwrap(), p.root()).unwrap();
    validate_records(&restored, &context()).unwrap();
    let c = claim(&l);
    let next = prepare(&restored, 3, std::slice::from_ref(&c)).unwrap();
    let out = OutPoint {
        transaction: c.operation.id().unwrap(),
        index: 0,
    };
    assert_eq!(next.state().coins[&out].output.atoms, 50_000);
    assert_eq!(next.state().coins[&out].output.owner, addr(&keys().b));
    assert!(locked(next.state(), l.operation.output_id(0).unwrap()).is_err());
    assert!(
        reconcile(next.state(), &c.encode().unwrap())
            .unwrap()
            .is_some()
    );
    assert!(matches!(
        prepare(next.state(), 4, &[c]),
        Err(NativeError::Duplicate)
    ));
}
#[test]
fn claim_refund_boundaries_and_exclusivity_use_one_native_output() {
    let l = lock();
    let p = prepare(&state(), 2, std::slice::from_ref(&l)).unwrap();
    for h in [3, 19, 20, 21] {
        let claim_result = prepare(p.state(), h, &[claim(&l)]);
        let refund_result = prepare(p.state(), h, &[refund(&l)]);
        assert_eq!(claim_result.is_ok(), h < 20);
        assert_eq!(refund_result.is_ok(), h >= 20);
    }
    let done = prepare(p.state(), 20, &[refund(&l)]).unwrap();
    assert!(prepare(done.state(), 21, &[claim(&l)]).is_err());
    assert!(prepare(done.state(), 21, &[refund(&l)]).is_err());
}
#[test]
fn failed_batch_does_not_debit_fee_consume_offer_or_change_root() {
    let s = state();
    let before = s.clone();
    let l = lock();
    assert!(prepare(&s, 2, &[l.clone(), l]).is_err());
    assert_eq!(s, before);
    assert_eq!(s.root().unwrap(), before.root().unwrap());
}
#[test]
fn same_offer_equivocation_cannot_fill_twice_with_different_native_inputs() {
    let l = lock();
    let mut second = l.operation.clone();
    second.meta.trade[0] ^= 1;
    second.meta.contract[0] ^= 1;
    let second = native(second, 6, &[&keys().a, &keys().b]);
    assert_ne!(l.operation.id().unwrap(), second.operation.id().unwrap());
    let p = prepare(&state(), 2, &[l]).unwrap();
    assert!(matches!(
        prepare(p.state(), 3, &[second]),
        Err(NativeError::Duplicate)
    ));
}
#[test]
fn native_input_witness_substitution_rejects() {
    let mut l = lock();
    l.inputs[0] = point(6);
    assert!(matches!(l.encode(), Err(NativeError::Context)));
}
#[test]
fn future_and_immature_coinbase_inputs_reject() {
    for created in [2, 1] {
        let mut s = state();
        let c = s.coins.get_mut(&point(1)).unwrap();
        c.created_height = created;
        c.coinbase = true;
        assert!(matches!(
            prepare(&s, 2, &[lock()]),
            Err(NativeError::Immature)
        ));
    }
}
#[test]
fn either_invalid_wallet_component_and_wrong_owner_fail_without_mutation() {
    for component in 0..2 {
        let s = state();
        let mut l = lock();
        if component == 0 {
            l.operation.approvals[0].signature.ed448[0] ^= 1
        } else {
            l.operation.approvals[0].signature.fndsa[0] ^= 1
        };
        assert!(prepare(&s, 2, &[l]).is_err());
    }
    let mut s = state();
    s.coins.get_mut(&point(1)).unwrap().output.owner = addr(&keys().c);
    assert!(matches!(
        prepare(&s, 2, &[lock()]),
        Err(NativeError::Authority)
    ));
}
#[test]
fn incorrect_amount_recipient_context_generation_or_condition_fail() {
    let l = lock();
    let p = prepare(&state(), 2, std::slice::from_ref(&l)).unwrap();
    for field in 0..7 {
        let mut c = claim(&l).operation;
        match field {
            0 => c.meta.context.genesis[0] ^= 1,
            1 => c.meta.context.fingerprint[0] ^= 1,
            2 => c.meta.trade[0] ^= 1,
            3 => c.meta.contract[0] ^= 1,
            4 => c.meta.generation += 1,
            5 => {
                if let Action::Claim { amount, .. } = &mut c.action {
                    amount.0 += 1
                }
            }
            _ => {
                if let Action::Claim { preimage, .. } = &mut c.action {
                    preimage[0] ^= 1
                }
            }
        }
        let c = native(c, 2, &[&keys().b]);
        assert!(prepare(p.state(), 3, &[c]).is_err());
    }
}
#[test]
fn native_byte_fee_exceeds_240_without_changing_beneficiary() {
    let mut l = lock().operation;
    l.meta.fee = Strikes(240);
    if let Action::HashLock { change, .. } = &mut l.action {
        *change = Strikes(49_760)
    }
    let l = native(l, 1, &[&keys().a, &keys().b]);
    assert!(l.encode().unwrap().len() > 240);
    assert!(matches!(prepare(&state(), 2, &[l]), Err(NativeError::Fee)));
}
#[test]
fn production_and_unresolved_unit_gates_are_closed() {
    let s = state();
    let raw = lock().encode().unwrap();
    assert!(matches!(
        prepare_batch(
            &s,
            &anchor(1),
            s.root().unwrap(),
            std::slice::from_ref(&raw),
            &CandidatePolicy::disabled()
        ),
        Err(NativeError::Gate)
    ));
    assert!(matches!(
        prepare_batch(
            &s,
            &anchor(1),
            s.root().unwrap(),
            &[raw],
            &CandidatePolicy::nonproduction_unresolved()
        ),
        Err(NativeError::UnitUnresolved)
    ));
    assert!(!std::hint::black_box(MAINNET_ACTIVATION));
}
#[test]
fn real_sparse_proof_authenticates_native_lock_and_rejects_wrong_anchor() {
    let l = lock();
    let p = prepare(&state(), 2, std::slice::from_ref(&l)).unwrap();
    let mut tree = crate::state_tree::StateTree::default();
    for (k, v) in p.state().records().unwrap() {
        tree.insert(k, v).unwrap();
    }
    let id = l.operation.output_id(0).unwrap();
    let proof = tree.proof(anchor(2), record_key(0, id)).encode().unwrap();
    assert_eq!(
        verify_lock_proof(&proof, &anchor(2), p.root(), id)
            .unwrap()
            .recipient,
        addr(&keys().b)
    );
    assert!(verify_lock_proof(&proof, &anchor(3), p.root(), id).is_err());
    assert!(verify_lock_proof(&proof, &anchor(2), [0; 32], id).is_err());
}
#[test]
fn typed_restoration_hook_rejects_malformed_candidate_records() {
    let l = lock();
    let p = prepare(&state(), 2, &[l]).unwrap();
    let mut s = p.into_state();
    let (k, raw) = s
        .protocol_records
        .iter()
        .find(|(_, v)| matches!(NativeRecord::decode(v), Ok((_, NativeRecord::Lock(_)))))
        .map(|(k, v)| (*k, v.clone()))
        .unwrap();
    let mut bad = raw;
    bad.push(0);
    s.protocol_records.insert(k, bad);
    assert!(validate_records(&s, &context()).is_err());
}
#[test]
fn canonical_hostile_inputs_are_bounded_without_panic() {
    let raw = lock().encode().unwrap();
    for n in 0..raw.len() {
        assert!(NativeOperation::decode(&raw[..n]).is_err());
    }
    let mut extra = raw.clone();
    extra.push(0);
    assert!(NativeOperation::decode(&extra).is_err());
    let mut x = 71u32;
    for n in 0..1500 {
        let mut v = vec![0; n % 1024];
        for b in &mut v {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = x as u8;
        }
        let _ = NativeOperation::decode(&v);
        let _ = NativeRecord::decode(&v);
        let _ = FrozenTreasuryOffer::decode(&v);
    }
}
#[test]
fn fiat_normal_release_uses_both_current_wallets_and_no_timeout_authority() {
    let l = native(
        op(
            Action::FiatLock {
                offer: [0; 32],
                maker: [0; 32],
                seller: addr(&keys().a),
                buyer: addr(&keys().b),
                amount: Strikes(50_000),
                payment_terms: [51; 32],
                change: Strikes(30_000),
            },
            2,
            10,
        ),
        1,
        &[&keys().a, &keys().b],
    );
    let p = prepare(&state(), 2, std::slice::from_ref(&l)).unwrap();
    let release = op(
        Action::FiatRelease {
            output: l.operation.output_id(0).unwrap(),
            buyer: addr(&keys().b),
            seller: addr(&keys().a),
            amount: Strikes(50_000),
            payment_terms: [51; 32],
            change: Strikes(80_000),
        },
        3,
        25,
    );
    let one = native(release.clone(), 2, &[&keys().b]);
    assert!(prepare(p.state(), 3, &[one]).is_err());
    let both = native(release, 2, &[&keys().b, &keys().a]);
    assert!(prepare(p.state(), 3, &[both]).is_ok());
    assert!(matches!(
        prepare(p.state(), 20, &[refund(&l)]),
        Err(NativeError::FiatRecoveryUnspecified)
    ));
}
// ---------------------------------------------------------------------------------------------
// WP-T3, P6 (Order of 4 Oct 2026; P-LANE-DESIGN-V1 section 7): one canonical MUT Treasury
// authority. The trading Treasury identity is the Genesis Treasury authority T; R1 (a wallet
// rotation of T) changes who signs for T; R2 (TreasuryRotate) routes new Treasury offers only to
// T's current wallet generation and is approved only by T's current key. TEST-VALUE keys only.
// The real-block rows are in consensus/tests/treasury_authority_v1.rs (module `authority`).
// ---------------------------------------------------------------------------------------------

/// P6 (design 7.1): T, the generation-one AddressID of the TEST-VALUE Genesis Treasury
/// descriptor (key b) that `treasury_fixture` activates.
fn tid() -> Hash {
    addr(&keys().b)
}
fn addr_g(k: &HybridKey, generation: u64) -> Hash {
    k.public().address_id(generation).unwrap()
}
/// R1 (design 7.4): a real wallet rotation of T through `WalletBook::apply` (the call the payment
/// phase makes for an executed rotation) from `from` to `to` (key, descriptor generation). The
/// real-block form is `rotate_in_block` in consensus/tests/support/trading_rig_v1.rs.
fn r1(s: &mut State, from: (&HybridKey, u64), to: (&HybridKey, u64)) {
    let empty = mutiny_crypto_v2::HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    };
    let mut r = crate::wallet_rotation_v1::Rotation {
        network: crate::NETWORK_ID,
        genesis: [11; 32],
        fingerprint: [12; 32],
        authority: tid(),
        current: from.0.public().descriptor(from.1).unwrap(),
        proposed: to.0.public().descriptor(to.1).unwrap(),
        created_height: 1,
        expiry_height: 10_000,
        authorization: empty.clone(),
        possession: empty,
    };
    r.sign(from.0, to.0).unwrap();
    // Test fixture only (cfg(test)), the same call integration tests make; canonical execution
    // rotates wallets only through the verified FundedRotation bundle (WP-R).
    crate::wallet_authority_v1::WalletBook::apply(&mut s.wallets, &r, [11; 32], [12; 32], 1).unwrap();
}
/// The Treasury fixture after R1 moved T's signing key from b (generation 1) to c (generation 2).
fn rotated_fixture() -> State {
    let mut s = treasury_fixture();
    r1(&mut s, (&keys().b, 1), (&keys().c, 2));
    s
}
/// R2 from Treasury generation `gen_from` (destination key `from`) to `gen_to` (destination key
/// `to`), approved in slot 0 by `signer`; keys are (key, descriptor generation). Funded by the
/// input `point(input)`; `current_descriptor` names the signer's descriptor.
#[allow(clippy::too_many_arguments)]
fn rotation_signed(
    from: (&HybridKey, u64),
    gen_from: u64,
    to: (&HybridKey, u64),
    gen_to: u64,
    signer: (&HybridKey, u64),
    input: u8,
    created: u64,
    expiry: u64,
) -> NativeOperation {
    let mut o = op(
        Action::TreasuryRotate {
            treasury: tid(),
            current_generation: gen_from,
            current_address: addr_g(from.0, from.1),
            current_descriptor: descriptor_hash(&signer.0.public().descriptor(signer.1).unwrap()),
            new_generation: gen_to,
            new_address: addr_g(to.0, to.1),
            new_descriptor: to.0.public().descriptor(to.1).unwrap(),
            change: Strikes(80_000),
        },
        created,
        expiry,
    );
    o.meta.inputs = vec![native_input_id(&point(input))];
    o.approve(0, signer.0, signer.1).unwrap();
    NativeOperation {
        operation: o,
        inputs: vec![point(input)],
    }
}
/// The honest R2: approved by the new destination's key, which is T's current key (R2-3, R2-4).
fn rotation_op(
    from: (&HybridKey, u64),
    gen_from: u64,
    to: (&HybridKey, u64),
    gen_to: u64,
    input: u8,
    created: u64,
    expiry: u64,
) -> NativeOperation {
    rotation_signed(from, gen_from, to, gen_to, to, input, created, expiry)
}
fn treasury_destinations(s: &State) -> Vec<TreasuryDestination> {
    treasury_generations(s, &context(), tid()).unwrap()
}
/// A coin of T's lineage (owner T) at `point(n)`.
fn treasury_coin(s: &mut State, n: u8) {
    s.coins.insert(
        point(n),
        Coin {
            output: Output {
                owner: tid(),
                atoms: 100_000,
            },
            created_height: 0,
            coinbase: false,
        },
    );
}
#[test]
fn treasury_rotation_uses_current_wallet_and_retains_old_generation() {
    let s = rotated_fixture();
    let r = rotation_op((&keys().b, 1), 1, (&keys().c, 2), 2, 4, 2, 10);
    let p = prepare(&s, 2, &[r]).unwrap();
    let destinations = treasury_destinations(p.state());
    assert_eq!(destinations.len(), 2);
    assert_eq!(destinations[0].address, tid());
    assert_eq!(destinations[1].address, addr_g(&keys().c, 2));
    assert_eq!(destinations[1].effective_height, 2); // inclusion height
}
#[test]
fn treasury_rotation_is_immediate_at_inclusion_with_deterministic_same_block_winner() {
    let s = rotated_fixture();
    let before = s.records().unwrap();
    // Two competing successors of generation 1 (both to T's current generation, each valid alone,
    // different inputs of T's lineage): the first in execution order wins.
    let first = rotation_op((&keys().b, 1), 1, (&keys().c, 2), 2, 2, 2, 10);
    let second = rotation_op((&keys().b, 1), 1, (&keys().c, 2), 2, 4, 2, 10);
    assert!(
        matches!(prepare(&s, 2, &[first.clone(), second.clone()]), Err(NativeError::Context)),
        "the whole block fails when its second operation names a superseded generation"
    );
    let one = prepare(&s, 2, std::slice::from_ref(&first)).unwrap().into_state();
    let d = treasury_destinations(&one);
    assert_eq!(
        (d.len(), d[1].generation, d[1].address, d[1].effective_height),
        (2, 2, addr_g(&keys().c, 2), 2)
    );
    assert!(!one.coins.contains_key(&point(2)) && one.coins.contains_key(&point(4)));
    assert!(matches!(prepare(&one, 3, std::slice::from_ref(&second)), Err(NativeError::Context)));
    let other = prepare(&s, 2, std::slice::from_ref(&second)).unwrap().into_state();
    assert!(other.coins.contains_key(&point(2)) && !other.coins.contains_key(&point(4)));
    // Generation skip and stale generation are rejected.
    let skip = rotation_op((&keys().b, 1), 1, (&keys().c, 2), 3, 2, 2, 10);
    assert!(matches!(prepare(&s, 2, &[skip]), Err(NativeError::Context)));
    let stale = rotation_op((&keys().b, 1), 0, (&keys().c, 2), 1, 2, 2, 10);
    assert!(matches!(prepare(&s, 2, &[stale]), Err(NativeError::Context)));
    // R2-3/R2-4: a fresh generation-one key (c's own registered wallet) cannot appoint itself.
    let fresh = rotation_signed((&keys().b, 1), 1, (&keys().c, 1), 2, (&keys().c, 1), 2, 2, 10);
    assert!(matches!(prepare(&s, 2, &[fresh]), Err(NativeError::Authority)));
    // R2-3: the rotated-out key b cannot authorize, even a route to T's current generation.
    let old = rotation_signed((&keys().b, 1), 1, (&keys().c, 2), 2, (&keys().b, 1), 2, 2, 10);
    assert!(matches!(prepare(&s, 2, &[old]), Err(NativeError::Authority)));
    assert_eq!(s.records().unwrap(), before);
    // Without a further R1 the current generation cannot be routed to again (address used once).
    let again = rotation_op((&keys().c, 2), 2, (&keys().c, 2), 3, 4, 3, 10);
    assert!(matches!(prepare(&one, 3, &[again]), Err(NativeError::Record)));
    // After R1 c -> a (generation 3), a routes generation 3.
    let mut one = one;
    r1(&mut one, (&keys().c, 2), (&keys().a, 3));
    let next = rotation_op((&keys().c, 2), 2, (&keys().a, 3), 3, 4, 3, 10);
    let n = prepare(&one, 3, &[next]).unwrap().into_state();
    let d = treasury_destinations(&n);
    assert_eq!((d.len(), d[2].generation, d[2].effective_height), (3, 3, 3));
}
#[test]
fn treasury_rotation_enforces_signed_validity_window() {
    let s = rotated_fixture();
    let r = |created, expiry| rotation_op((&keys().b, 1), 1, (&keys().c, 2), 2, 2, created, expiry);
    // created in the future relative to the inclusion height, and already expired.
    assert!(prepare(&s, 2, &[r(3, 10)]).is_err());
    assert!(prepare(&s, 11, &[r(2, 10)]).is_err());
    // Inclusive edges are accepted.
    assert!(prepare(&s, 2, &[r(2, 10)]).is_ok());
    assert!(prepare(&s, 10, &[r(2, 10)]).is_ok());
}
/// P6 (design 7.2): `validate_records` binds every trading Treasury record to T. Records under
/// another identity, records while dividends are inactive, a generation-1 destination that is not
/// the Genesis descriptor, and a generation >= 2 destination outside T's wallet lineage are all
/// `Record`; the honest R1 + R2 state validates (and survives a restart).
#[test]
fn trading_treasury_records_bind_to_the_genesis_authority() {
    let honest = rotated_fixture();
    validate_records(&honest, &context()).unwrap();
    // Another identity, with a valid generation-one destination of its own.
    let mut other = honest.clone();
    for (k, v) in
        treasury_genesis_records(&context(), [91; 32], keys().b.public().descriptor(1).unwrap()).unwrap()
    {
        other.protocol_records.insert(k, v);
    }
    assert_eq!(validate_records(&other, &context()), Err(NativeError::Record));
    // T's identity, but generation 1 is a different key (address = T is then impossible).
    let mut wrong_key = State::default();
    wrong_key.dividends = honest.dividends.clone();
    for (k, v) in
        treasury_genesis_records(&context(), tid(), keys().a.public().descriptor(1).unwrap()).unwrap()
    {
        wrong_key.protocol_records.insert(k, v);
    }
    assert_eq!(validate_records(&wrong_key, &context()), Err(NativeError::Record));
    // No Genesis Treasury at all.
    let mut inactive = honest.clone();
    inactive.dividends = Default::default();
    assert_eq!(validate_records(&inactive, &context()), Err(NativeError::Record));
    // A generation-2 destination recorded without R1 (a fresh generation-one key) is refused even
    // though every per-record link (head, generation, address entry) is consistent.
    let routed = prepare(&honest, 2, &[rotation_op((&keys().b, 1), 1, (&keys().c, 2), 2, 2, 2, 10)])
        .unwrap()
        .into_state();
    validate_records(&routed, &context()).unwrap();
    let restored = State::from_records(&routed.records().unwrap(), routed.root().unwrap()).unwrap();
    validate_records(&restored, &context()).unwrap();
    let mut unbound = treasury_fixture();
    let fresh = TreasuryDestination {
        generation: 2,
        address: addr(&keys().c),
        descriptor: keys().c.public().descriptor(1).unwrap(),
        effective_height: 2,
    };
    for (k, v) in treasury_records(&context(), tid(), &fresh, true).unwrap() {
        unbound.protocol_records.insert(k, v);
    }
    assert_eq!(validate_records(&unbound, &context()), Err(NativeError::Record));
    // The same destination is accepted once R1 registered it under T (the per-record checks were
    // not what refused it).
    let mut bound = treasury_fixture();
    r1(&mut bound, (&keys().b, 1), (&keys().c, 2));
    let current = TreasuryDestination {
        generation: 2,
        address: addr_g(&keys().c, 2),
        descriptor: keys().c.public().descriptor(2).unwrap(),
        effective_height: 2,
    };
    for (k, v) in treasury_records(&context(), tid(), &current, true).unwrap() {
        bound.protocol_records.insert(k, v);
    }
    validate_records(&bound, &context()).unwrap();
    // Exact historical bytes are required, even in the presence of a named lineage address.
    let mut authoritative = treasury_authority(&bound).unwrap();
    assert_eq!(authoritative.lineage.get(&current.address), Some(&current.descriptor));
    validate_treasury_binding(Some(&authoritative), tid(), Some(&current)).unwrap();
    authoritative.lineage.insert(current.address, keys().a.public().descriptor(2).unwrap());
    assert_eq!(validate_treasury_binding(Some(&authoritative), tid(), Some(&current)),
               Err(NativeError::Record));
    // Further R1 changes must not replace the descriptor of a historical R2 destination.
    r1(&mut bound, (&keys().c, 2), (&keys().a, 3));
    assert_eq!(bound.wallets.registered_descriptor(current.address), Some(current.descriptor.as_slice()));
    validate_records(&bound, &context()).unwrap();
    // R2-1: a TreasuryRotate naming another identity is `Authority` at execution.
    let mut foreign = rotation_op((&keys().b, 1), 1, (&keys().c, 2), 2, 2, 2, 10);
    if let Action::TreasuryRotate { treasury, .. } = &mut foreign.operation.action {
        *treasury = [91; 32];
    }
    foreign.operation.approvals.clear();
    foreign.operation.approve(0, &keys().c, 2).unwrap();
    let before = honest.records().unwrap();
    assert!(matches!(prepare(&honest, 2, &[foreign]), Err(NativeError::Authority)));
    assert_eq!(honest.records().unwrap(), before);
}
/// P6 (design 7.3 R2-3): slot 0 of a TreasuryRotate is the Treasury authority T, not the trading
/// head address, and the head address still funds it (change). Checked with a head other than T.
#[test]
fn treasury_rotate_slot_zero_is_the_authority_not_the_head_address() {
    let r = rotation_op((&keys().c, 2), 2, (&keys().a, 3), 3, 4, 3, 10);
    assert_eq!(r.operation.slot_address(0), Some(tid()));
    assert_eq!(r.operation.slot_address(1), None);
    assert_eq!(r.operation.fee_payer(), addr_g(&keys().c, 2));
    assert_ne!(addr_g(&keys().c, 2), tid());
}
/// P6 (design 7.3 R2-3): the slot-0 approval of T's current key is VERIFIED, not only looked up
/// in the WalletBook: the honest R2 with one flipped signature byte (either half) is `Authority`.
#[test]
fn treasury_rotate_requires_a_valid_signature_of_the_current_key() {
    let s = rotated_fixture();
    let before = s.records().unwrap();
    let honest = rotation_op((&keys().b, 1), 1, (&keys().c, 2), 2, 2, 2, 10);
    for half in 0..2 {
        let mut bad = honest.clone();
        let sig = &mut bad.operation.approvals[0].signature;
        if half == 0 {
            sig.ed448[0] ^= 1
        } else {
            sig.fndsa[0] ^= 1
        }
        assert!(matches!(prepare(&s, 2, &[bad]), Err(NativeError::Authority)), "half {half}");
    }
    assert_eq!(s.records().unwrap(), before);
    assert!(prepare(&s, 2, &[honest]).is_ok(), "control");
}
/// P6 (design 7.6): the Treasury freeze is refused for any identity other than T, even when that
/// identity's records would otherwise be complete.
#[test]
fn treasury_freeze_requires_the_genesis_authority() {
    let s = treasury_fixture();
    let w = treasury_funding();
    let mut req = treasury_request(&w);
    req.treasury = [91; 32];
    assert!(matches!(
        prepare_treasury_offer(
            &s,
            &anchor(1),
            s.root().unwrap(),
            req,
            &CandidatePolicy::synthetic_one_atom_per_strike()
        ),
        Err(NativeError::Authority)
    ));
    assert!(
        prepare_treasury_offer(
            &s,
            &anchor(1),
            s.root().unwrap(),
            treasury_request(&w),
            &CandidatePolicy::synthetic_one_atom_per_strike()
        )
        .is_ok(),
        "control"
    );
}
#[test]
fn license_transfer_without_native_license_fails_closed() {
    let d = native(
        op(
            Action::LicenseDvp {
                offer: [0; 32],
                maker: [0; 32],
                license: [80; 32],
                license_generation: 1,
                seller: addr(&keys().a),
                buyer: addr(&keys().b),
                price: Strikes(50_000),
                payment_destination: addr(&keys().a),
                change: Strikes(30_000),
            },
            2,
            10,
        ),
        2,
        &[&keys().a, &keys().b],
    );
    // WP-T2 (design 6.1): without the mandatory sale commitment the sale is Bounds; committing
    // facts of a License that does not exist fails closed at the validation point (Stale(2): the
    // assignment facts are unavailable). Formerly Missing, which the precondition check now precedes.
    assert!(matches!(
        prepare(&state(), 2, &[d.clone()]),
        Err(NativeError::Bounds)
    ));
    let mut committed = d.operation;
    committed.meta.envelope.preconditions = vec![
        crate::op_envelope_v1::Precondition::LicenseEntitlements { license: [80; 32], accounts: vec![] },
        crate::op_envelope_v1::Precondition::LicenseAssignment {
            license: [80; 32],
            assignment_sequence: 1,
            active_worker: None,
            pending: None,
        },
    ];
    let committed = native(committed, 2, &[&keys().a, &keys().b]);
    assert!(matches!(
        prepare(&state(), 2, &[committed]),
        Err(NativeError::Stale(2))
    ));
}

#[test]
fn executor_hook_preserves_prior_host_tentative_changes() {
    let parent = state();
    let mut tentative = parent.clone();
    tentative.protocol_records.insert([99; 32], vec![0x81, 1]);
    let p = prepare_candidate_phase(
        &parent,
        &tentative,
        &anchor(1),
        parent.root().unwrap(),
        &History::default(),
        &[lock().encode().unwrap()],
        &CandidatePolicy::synthetic_one_atom_per_strike(),
    )
    .unwrap();
    assert_eq!(
        p.state().protocol_records.get(&[99; 32]),
        Some(&vec![0x81, 1])
    );
    assert!(!parent.protocol_records.contains_key(&[99; 32]));
}

#[test]
fn native_envelope_record_vectors_export() {
    let l = lock();
    let encoded = l.encode().unwrap();
    let p = prepare(&state(), 2, std::slice::from_ref(&l)).unwrap();
    let id = l.operation.output_id(0).unwrap();
    let data = serde_json::json!({"namespace":String::from_utf8(NATIVE_NAMESPACE.to_vec()).unwrap(),"network":crate::NETWORK_ID,"operation_envelope":hex::encode(l.operation.encode().unwrap()),"native_envelope":hex::encode(&encoded),"input_key":hex::encode(native_input_id(&point(1))),"sender":hex::encode(addr(&keys().a)),"recipient":hex::encode(addr(&keys().b)),"operation_id":hex::encode(l.operation.id().unwrap()),"locked_id":hex::encode(id),"lock_key":hex::encode(record_key(0,id)),"lock_record":hex::encode(&p.state().protocol_records[&record_key(0,id)]),"applied_record":hex::encode(&p.state().protocol_records[&record_key(2,l.operation.id().unwrap())]),"source":"public synthetic fixtures only; native atom/STRIKE alias is explicit test assumption"});
    let root = std::path::PathBuf::from(
        std::env::var_os("NATIVE_TRADING_EVIDENCE_DIR").expect("fresh evidence directory"),
    );
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("native-vectors.json"),
        serde_json::to_vec_pretty(&data).unwrap(),
    )
    .unwrap();
}

#[test]
fn reserved_namespace_indefinite_outer_must_not_be_opaque() {
    let s = prepare(&state(), 2, &[lock()]).unwrap().into_state();
    let (key, raw) = s
        .protocol_records
        .iter()
        .find(|(_, r)| matches!(NativeRecord::decode(r), Ok((_, NativeRecord::Lock(_)))))
        .unwrap();
    let mut hostile = raw.clone();
    assert_eq!(hostile[0], 0x85);
    hostile[0] = 0x9f;
    hostile.push(0xff);
    assert!(
        is_candidate_record(&hostile),
        "reserved namespace classification bypass"
    );
    let key = *key;
    let mut changed = s;
    changed.protocol_records.insert(key, hostile);
    assert!(validate_records(&changed, &context()).is_err());
}

#[test]
fn reserved_namespace_noncanonical_forms_are_recognized_when_disabled() {
    let raw = NativeRecord::Applied {
        wire_hash: [8; 32],
        height: 2,
        fee_atoms: 240,
    }
    .encode([9; 32])
    .unwrap();
    let prefix = 2 + NATIVE_NAMESPACE.len() + 1; // array byte + bytes(29) two-byte header
    assert_eq!(&raw[3..prefix], NATIVE_NAMESPACE);
    let mut chunked = vec![0x9f, 0x5f, 0x40, 0x58, NATIVE_NAMESPACE.len() as u8];
    chunked.extend_from_slice(NATIVE_NAMESPACE);
    chunked.push(0xff);
    chunked.extend_from_slice(&raw[prefix..]);
    chunked.push(0xff);
    let mut nonminimal = vec![0x98, 0x05];
    nonminimal.extend_from_slice(&raw[1..]);
    for hostile in [chunked, nonminimal] {
        assert!(is_candidate_record(&hostile)); // disabled host must reject this prefix
        assert!(NativeRecord::decode(&hostile).is_err());
        let mut s = state();
        s.protocol_records.insert(record_key(2, [9; 32]), hostile);
        assert!(validate_records(&s, &context()).is_err());
        // Gate check precedes root parsing; no forged-root acceptance asserted.
        assert!(matches!(
            prepare_batch(
                &s,
                &anchor(1),
                [0; 32],
                &[lock().encode().unwrap()],
                &CandidatePolicy::disabled()
            ),
            Err(NativeError::Gate)
        ));
    }
    assert!(!is_candidate_record(&[0x81, 0x41, 0]));
}

fn license_fixture() -> (State, Hash) {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/license-book-v2-public-v1.json"
    ))
    .unwrap();
    assert_eq!(fixture["synthetic_only"], true);
    let mut records = std::collections::BTreeMap::new();
    let mut selected = None;
    for entry in fixture["records"].as_array().unwrap() {
        let key: Hash = hex::decode(entry["key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let mut raw = hex::decode(entry["record"].as_str().unwrap()).unwrap();
        let mut d = Decoder::new(&raw);
        let n = d.array().unwrap();
        let v = d.u8().unwrap();
        let tag = d.u8().unwrap();
        if v == 2 && tag == 40 && selected.is_none() {
            assert_eq!(n, Some(3));
            let mut l = crate::licenses::LicenseRecord::decode(d.bytes().unwrap()).unwrap();
            // Explicit synthetic pre-state owner mapping, not a production
            // Genesis/enrollment attestation. Historical Worker bytes retained.
            l.owner = addr(&keys().a);
            selected = Some(l.id);
            let mut e = Encoder::new(Vec::new());
            e.array(3)
                .unwrap()
                .u8(2)
                .unwrap()
                .u8(40)
                .unwrap()
                .bytes(&l.encode())
                .unwrap();
            raw = e.into_writer();
        }
        // Fixture's pending assignment is removed to create the normal-flow
        // fixture; a separate test restores it to qualify exclusion.
        if tag != 42 {
            records.insert(key, raw);
        }
    }
    let mut s = state();
    s.licenses_v2 = crate::license_book_v2::Book::from_records(&records).unwrap();
    (s, selected.unwrap())
}
fn license_context() -> Context {
    Context {
        network: crate::NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
    }
}
fn license_anchor(height: u64) -> FinalizedAnchor {
    FinalizedAnchor {
        network: crate::NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        height,
        block: [13; 32],
    }
}
/// WP-T2 (design 6.1): a sale commits the sold License's entitlements and assignment facts. `dvp`
/// commits those of the unmodified `license_fixture` state; `dvp_committing` those of `s`.
fn dvp(license: Hash, generation: u64, height: u64) -> NativeOperation {
    dvp_committing(&license_fixture().0, license, generation, height)
}
fn dvp_committing(s: &State, license: Hash, generation: u64, height: u64) -> NativeOperation {
    let mut o = op(
        Action::LicenseDvp {
            offer: [0; 32],
            maker: [0; 32],
            license,
            license_generation: generation,
            seller: addr(&keys().a),
            buyer: addr(&keys().b),
            price: Strikes(50_000),
            payment_destination: addr(&keys().c),
            change: Strikes(30_000),
        },
        height,
        10,
    );
    o.meta.context = license_context();
    o.meta.envelope.preconditions = vec![
        crate::op_envelope_v1::entitlement_facts(s, license),
        crate::op_envelope_v1::assignment_facts(s, license).unwrap(),
    ];
    native(o, 2, &[&keys().a, &keys().b])
}
fn prepare_license(s: &State, height: u64, ops: &[NativeOperation]) -> NativeResult<Prepared> {
    prepare_batch_with_history(
        s,
        &license_anchor(height - 1),
        s.root().unwrap(),
        &chain_history(height - 1),
        &ops.iter().map(|o| o.encode().unwrap()).collect::<Vec<_>>(),
        &CandidatePolicy::synthetic_one_atom_per_strike(),
    )
}
#[test]
fn license_dvp_moves_real_payment_and_owner_atomically_preserving_workers() {
    let (s, id) = license_fixture();
    let before = s.records().unwrap();
    let historic = s.licenses_v2.records().unwrap();
    let worker = s.licenses_v2.license(id).unwrap().active_worker.unwrap();
    let sequence = s.licenses_v2.license(id).unwrap().assignment_sequence;
    let op = dvp(id, 1, 2);
    let p = prepare_license(&s, 2, std::slice::from_ref(&op)).unwrap();
    let l = p.state().licenses_v2.license(id).unwrap();
    assert_eq!(l.owner, addr(&keys().b));
    assert_eq!(l.active_worker, None);
    assert_eq!(l.assignment_sequence, sequence + 1);
    assert_eq!(
        s.licenses_v2.license(id).unwrap().active_worker,
        Some(worker)
    );
    for (k, v) in historic {
        let mut d = Decoder::new(&v);
        d.array().unwrap();
        d.u8().unwrap();
        if d.u8().unwrap() == 41 {
            assert_eq!(p.state().licenses_v2.records().unwrap().get(&k), Some(&v));
        }
    }
    assert_eq!(
        p.state().coins[&OutPoint {
            transaction: op.operation.id().unwrap(),
            index: 0
        }]
            .output,
        Output {
            owner: addr(&keys().c),
            atoms: 50_000
        }
    );
    assert_eq!(p.state().coins.get(&point(1)), s.coins.get(&point(1)));
    let (_, r) = NativeRecord::decode(&p.state().protocol_records[&record_key(4, id)]).unwrap();
    assert!(matches!(
        r,
        NativeRecord::License {
            generation: 2,
            inclusion_height: 2,
            rights_from_height: 3,
            ..
        }
    ));
    assert!(p.state().licenses_v2.active(id, worker, 1).is_err());
    assert_eq!(s.records().unwrap(), before);
    assert!(prepare_license(p.state(), 3, &[op]).is_err());
}
#[test]
fn license_dvp_rejects_each_authority_generation_and_value_mismatch_without_effects() {
    let (s, id) = license_fixture();
    let original = s.records().unwrap();
    for variant in 0..8 {
        let mut o = dvp(id, 1, 2);
        match variant {
            0 => o.operation.approvals.remove(0),
            1 => o.operation.approvals.remove(1),
            _ => {
                match variant {
                    2 => {
                        if let Action::LicenseDvp {
                            license_generation, ..
                        } = &mut o.operation.action
                        {
                            *license_generation = 2
                        }
                    }
                    3 => {
                        if let Action::LicenseDvp { price, .. } = &mut o.operation.action {
                            *price = Strikes(50_001)
                        }
                    }
                    // Body version 2 has no exact effective height (design 5.1/6.1): the timing
                    // variant is a signed window that opens after the inclusion height.
                    4 => o.operation.meta.envelope = envelope(3, 10),
                    5 => {
                        if let Action::LicenseDvp { seller, .. } = &mut o.operation.action {
                            *seller = addr(&keys().c)
                        }
                    }
                    6 => o.operation.meta.contract = [77; 32],
                    _ => {
                        o.operation.meta.context.genesis = [88; 32];
                    }
                };
                o.operation.approvals[0].clone()
            }
        };
        if (2..=5).contains(&variant) {
            o = native(o.operation, 2, &[&keys().a, &keys().b]);
        }
        assert!(prepare_license(&s, 2, &[o]).is_err());
        assert_eq!(s.records().unwrap(), original);
    }
    let mut nofunds = s.clone();
    nofunds.coins.remove(&point(2));
    assert!(prepare_license(&nofunds, 2, &[dvp(id, 1, 2)]).is_err());
    assert_eq!(nofunds.licenses_v2, s.licenses_v2);
    let mut two = dvp(id, 1, 2);
    two.operation.meta.trade = [66; 32];
    two = native(two.operation, 4, &[&keys().a, &keys().b]);
    assert!(prepare_license(&s, 2, &[dvp(id, 1, 2), two]).is_err());
    assert_eq!(s.records().unwrap(), original);
}
#[test]
fn license_transfer_has_one_deterministic_result_in_the_single_build() {
    // The License DvP rule is not selected by any build flag: the former
    // "hook disabled" fail-closed result no longer exists. The same request must
    // yield the same accepted state every time, and an orphaned detachment
    // (no typed transfer record) must still be rejected.
    let (s, id) = license_fixture();
    let op = dvp(id, 1, 2);
    let a = prepare_license(&s, 2, std::slice::from_ref(&op)).unwrap();
    let b = prepare_license(&s, 2, std::slice::from_ref(&op)).unwrap();
    assert_eq!(a.state().records().unwrap(), b.state().records().unwrap());
    assert_eq!(a.state().root().unwrap(), b.state().root().unwrap());
    let mut orphan = a.state().clone();
    orphan.protocol_records.remove(&record_key(4, id));
    assert!(orphan.records().is_err());
}
fn treasury_fixture() -> State {
    let mut s = state();
    // P6: the trading Treasury records exist only under the Genesis Treasury authority T.
    s.dividends = crate::dividend_state_v1::DividendState::genesis(
        crate::treasury_v1::Treasury::new(
            crate::treasury_v1::Class::TestValue,
            keys().b.public().descriptor(1).unwrap(),
        )
        .unwrap(),
    );
    for (k, v) in treasury_genesis_records(
        &context(),
        tid(),
        keys().b.public().descriptor(1).unwrap(),
    )
    .unwrap()
    {
        s.protocol_records.insert(k, v);
    }
    s
}
fn treasury_funding() -> NativeOperation {
    let mut w = lock();
    let mut body = w.operation.offer_proof.as_ref().unwrap().offer.body.clone();
    // The Treasury (wallet B, the recipient: slot 1) is the maker (AM-6: its wallet key signs).
    body.maker_side = 1;
    body.maker_descriptor = keys().b.public().descriptor(1).unwrap();
    body.maker_wallet = addr(&keys().b);
    body.destination = addr(&keys().b);
    let offer = SignedOffer::sign(body, &keys().b).unwrap();
    if let Action::HashLock {
        offer: o, maker, ..
    } = &mut w.operation.action
    {
        *o = offer.body.id().unwrap();
        *maker = offer.body.maker().unwrap();
    }
    w.operation.offer_proof = Some(OfferProof::sign(offer, &w.operation, &keys().b).unwrap());
    w.operation.approvals.clear();
    w.operation.approve(0, &keys().a, 1).unwrap();
    w.operation.approve(1, &keys().b, 1).unwrap();
    w
}
fn treasury_request(w: &NativeOperation) -> TreasuryOfferRequest {
    TreasuryOfferRequest {
        treasury: tid(),
        generation: 1,
        address: addr(&keys().b),
        trade: w.operation.meta.trade,
        contract: w.operation.meta.contract,
        offer: w.operation.offer_proof.as_ref().unwrap().offer.clone(),
        wallet_descriptor: keys().b.public().descriptor(1).unwrap(),
    }
}
fn freeze(s: &State, w: &NativeOperation) -> FrozenTreasuryOffer {
    let prepared = prepare_treasury_offer(
        s,
        &anchor(1),
        s.root().unwrap(),
        treasury_request(w),
        &CandidatePolicy::synthetic_one_atom_per_strike(),
    )
    .unwrap();
    let sig = keys()
        .b
        .sign(Domain::Transaction, &prepared.signing_payload().unwrap())
        .unwrap();
    prepared.attach_authorization(sig).unwrap()
}
#[test]
fn treasury_current_creation_immutable_authorization_and_canonical_codec() {
    let s = treasury_fixture();
    let w = treasury_funding();
    let f = freeze(&s, &w);
    let encoded = f.encode().unwrap();
    assert_eq!(FrozenTreasuryOffer::decode(&encoded).unwrap(), f);
    for variant in 0..7 {
        let mut bad = f.clone();
        match variant {
            0 => bad.body.address = addr(&keys().c),
            1 => bad.body.generation = 2,
            2 => bad.body.contract = [77; 32],
            3 => bad.body.trade = [77; 32],
            4 => {
                if let OfferTerms::HashLinked {
                    bitcoin_satoshis, ..
                } = &mut bad.body.offer.terms
                {
                    *bitcoin_satoshis += 1
                }
            }
            5 => bad.signature.ed448[0] ^= 1,
            _ => bad.signature.fndsa[0] ^= 1,
        };
        assert!(FrozenTreasuryOffer::decode(&bad.encode().unwrap()).is_err());
    }
    let mut bad = encoded.clone();
    bad.push(0);
    assert!(FrozenTreasuryOffer::decode(&bad).is_err());
    let mut req = treasury_request(&w);
    req.address = addr(&keys().c);
    assert!(
        prepare_treasury_offer(
            &s,
            &anchor(1),
            s.root().unwrap(),
            req,
            &CandidatePolicy::synthetic_one_atom_per_strike()
        )
        .is_err()
    );
    assert!(
        prepare_treasury_offer(
            &s,
            &anchor(1),
            s.root().unwrap(),
            treasury_request(&w),
            &CandidatePolicy::disabled()
        )
        .is_err()
    );
    assert!(
        prepare_treasury_offer(
            &s,
            &anchor(1),
            s.root().unwrap(),
            treasury_request(&w),
            &CandidatePolicy::nonproduction_unresolved()
        )
        .is_err()
    );
}
/// `op` with its approvals replaced by `(slot, key, descriptor generation)` (the operation id and
/// the frozen commitment exclude approvals): a Treasury-side approval re-made by T's current key.
fn resign(w: &NativeOperation, signers: &[(u8, &HybridKey, u64)]) -> NativeOperation {
    let mut w = w.clone();
    w.operation.approvals.clear();
    for (slot, key, generation) in signers {
        w.operation.approve(*slot, key, *generation).unwrap();
    }
    w
}
/// P6 adaptation (design 14.6 row 3, R1 + R2): R1 moves T's key from b to c (generation 2) and R2
/// routes new Treasury offers to c's generation-2 address. Creation against generation 1 is then
/// refused. AM-12: an unfunded retired-key offer cannot first fund even with current settlement
/// approvals. A lock funded through the actual trading phase BEFORE rotation retains all exact
/// obligations and settles at T's historical address under its CURRENT key. These are phase unit
/// fixtures, not certified-block/store or physical evidence.
#[test]
fn treasury_rotation_rejects_old_generation_for_creation_but_retains_frozen_funding() {
    let s = treasury_fixture();
    let w = treasury_funding();
    let f = freeze(&s, &w);
    let verified = verify_frozen_treasury_offer_at_creation(
        f.clone(),
        &s,
        &anchor(1),
        s.root().unwrap(),
        &CandidatePolicy::synthetic_one_atom_per_strike(),
    )
    .unwrap();
    let mut s1 = s.clone();
    r1(&mut s1, (&keys().b, 1), (&keys().c, 2));
    let rotation = rotation_op((&keys().b, 1), 1, (&keys().c, 2), 2, 4, 2, 10);
    let rotated = prepare(&s1, 2, std::slice::from_ref(&rotation)).unwrap().into_state();
    let root = rotated.root().unwrap();
    let mut req = treasury_request(&w);
    req.offer.body.created = 4;
    req.offer = SignedOffer::sign(req.offer.body, &keys().b).unwrap();
    assert!(matches!(
        prepare_treasury_offer(
            &rotated,
            &anchor(4),
            root,
            req,
            &CandidatePolicy::synthetic_one_atom_per_strike()
        ),
        Err(NativeError::Conflict)
    ));
    assert!(
        verify_frozen_treasury_offer_at_creation(
            f,
            &rotated,
            &anchor(4),
            root,
            &CandidatePolicy::synthetic_one_atom_per_strike()
        )
        .is_err()
    );
    // The rotated-out key's approval of the frozen funding is no longer T's authority.
    assert!(matches!(
        prepare_treasury_funding_with_history(
            &rotated,
            &anchor(4),
            root,
            &chain_history(4),
            &verified,
            &w,
            &CandidatePolicy::synthetic_one_atom_per_strike(),
        ),
        Err(NativeError::Authority)
    ));
    // Current settlement approval does not make the retired, never-funded offer current.
    let current_approval = resign(&w, &[(0, &keys().a, 1), (1, &keys().c, 2)]);
    let unfunded_before = rotated.records().unwrap();
    assert!(matches!(
        prepare_treasury_funding_with_history(
            &rotated, &anchor(4), root, &chain_history(4), &verified, &current_approval,
            &CandidatePolicy::synthetic_one_atom_per_strike(),
        ),
        Err(NativeError::Authority)
    ));
    assert_eq!(rotated.records().unwrap(), unfunded_before);

    // Positive: actual funding precedes BOTH R1 and R2, so the resulting lock is already applied.
    let mut funded = prepare_treasury_funding_with_history(
        &s, &anchor(1), s.root().unwrap(), &chain_history(1), &verified, &w,
        &CandidatePolicy::synthetic_one_atom_per_strike(),
    ).unwrap().into_state();
    let lock_id = w.operation.output_id(0).unwrap();
    let obligations = locked(&funded, lock_id).unwrap();
    r1(&mut funded, (&keys().b, 1), (&keys().c, 2));
    let funded_rotated = prepare(&funded, 3, &[rotation]).unwrap().into_state();
    assert_eq!(locked(&funded_rotated, lock_id).unwrap(), obligations);
    let before_claim = funded_rotated.records().unwrap();
    assert!(matches!(prepare(&funded_rotated, 6, &[claim(&w)]), Err(NativeError::Authority)));
    assert_eq!(funded_rotated.records().unwrap(), before_claim);
    let refund = refund(&w);
    assert!(matches!(prepare(&funded_rotated, 19, std::slice::from_ref(&refund)), Err(NativeError::Time)));
    assert_eq!(funded_rotated.records().unwrap(), before_claim);
    let refunded = prepare(&funded_rotated, 20, std::slice::from_ref(&refund)).unwrap().into_state();
    assert_eq!(refunded.coins[&OutPoint { transaction: refund.operation.id().unwrap(), index: 0 }].output.owner, addr(&keys().a));
    assert!(locked(&refunded, lock_id).is_err());
    let c = resign(&claim(&w), &[(0, &keys().c, 2)]);
    let final_state = prepare(&funded_rotated, 6, std::slice::from_ref(&c))
        .unwrap()
        .into_state();
    verify_treasury_direct_credit(&final_state, &verified, &w, &c).unwrap();
    // The frozen trade settled at T's generation-1 address, which stays in T's lineage.
    let paid = OutPoint {
        transaction: c.operation.id().unwrap(),
        index: 0,
    };
    assert_eq!(final_state.coins[&paid].output.owner, tid());
    let mut wrong = w.clone();
    if let Action::HashLock { offer, .. } = &mut wrong.operation.action {
        *offer = [77; 32];
    }
    assert!(verify_treasury_direct_credit(&final_state, &verified, &wrong, &c).is_err());
    let mut missing = final_state.clone();
    missing
        .protocol_records
        .remove(&record_key(2, w.operation.id().unwrap()));
    assert!(verify_treasury_direct_credit(&missing, &verified, &w, &c).is_err());
}
/// Treasury history is canonical generation-indexed state, not a bounded list: the number of
/// successive finalized rotations is not a consensus limit, a lock actually funded against
/// generation 1 BEFORE rotation still settles after five later rotations (and record replay), and stale or forged
/// successors fail atomically. P6 adaptation (design 14.6 row 3): every generation is one R1 of
/// T's key followed by one R2 to T's new current generation, approved by that current key; a
/// rotated-out key and a fresh generation-one key can neither authorize nor be routed to. Test
/// fixtures only (published BIP39 vectors).
#[test]
fn treasury_history_is_unbounded_and_old_generation_still_settles_after_many_rotations() {
    let restore = |phrase: &str| HybridKey::wallet_restore(phrase, Role::WalletOwner).unwrap();
    let d = restore("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title");
    let e = restore("hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length");
    let f = restore("panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside");
    let mut s = treasury_fixture();
    for n in 30u8..36 {
        treasury_coin(&mut s, n);
    }
    let w = treasury_funding();
    let frozen = freeze(&s, &w);
    let policy = CandidatePolicy::synthetic_one_atom_per_strike();
    let verified = verify_frozen_treasury_offer_at_creation(frozen, &s, &anchor(1), s.root().unwrap(), &policy).unwrap();
    // T's keys by wallet generation: b(1) -> c(2) -> a(3) -> d(4) -> e(5) -> f(6); five R1 + R2
    // pairs (> four), each R2 funded by a coin of T's lineage.
    let chain: [(&HybridKey, &HybridKey, u8); 5] = [
        (&keys().b, &keys().c, 30),
        (&keys().c, &keys().a, 31),
        (&keys().a, &d, 32),
        (&d, &e, 33),
        (&e, &f, 34),
    ];
    let mut st = prepare_treasury_funding_with_history(
        &s, &anchor(1), s.root().unwrap(), &chain_history(1), &verified, &w, &policy,
    ).unwrap().into_state();
    let lock_id = w.operation.output_id(0).unwrap();
    let obligations = locked(&st, lock_id).unwrap();
    for (i, (from, to, input)) in chain.iter().enumerate() {
        let (g, h) = (1 + i as u64, 3 + i as u64);
        r1(&mut st, (from, g), (to, g + 1));
        st = prepare(&st, h, &[rotation_op((from, g), g, (to, g + 1), g + 1, *input, h, 40)]).unwrap().into_state();
        assert_eq!(locked(&st, lock_id).unwrap(), obligations);
    }
    let all = treasury_generations(&st, &context(), tid()).unwrap();
    assert_eq!(all.len(), 6);
    assert_eq!(all[0].address, tid());
    assert_eq!(all[5].address, addr_g(&f, 6));
    assert_eq!(treasury_current(&st, &context(), tid()).unwrap().generation, 6);
    // The original destination is retained and still resolves in O(1).
    assert_eq!(treasury_generation(&st, &context(), tid(), 1).unwrap().address, tid());
    // New creation against the old generation is refused; previously funded obligations survive.
    let root = st.root().unwrap();
    let mut req = treasury_request(&w);
    req.offer.body.created = 7;
    req.offer = SignedOffer::sign(req.offer.body, &keys().b).unwrap();
    assert!(matches!(prepare_treasury_offer(&st, &anchor(7), root, req, &policy), Err(NativeError::Conflict)));
    // Reload exact canonical-format records: no second funding, and the same complete lock terms.
    let restored = State::from_records(&st.records().unwrap(), st.root().unwrap()).unwrap();
    validate_records(&restored, &context()).unwrap();
    assert_eq!(locked(&restored, lock_id).unwrap(), obligations);
    let before_claim = restored.records().unwrap();
    assert!(matches!(prepare(&restored, 8, &[claim(&w)]), Err(NativeError::Authority)));
    assert_eq!(restored.records().unwrap(), before_claim);
    let c = resign(&claim(&w), &[(0, &f, 6)]);
    let done = prepare(&restored, 8, std::slice::from_ref(&c)).unwrap().into_state();
    verify_treasury_direct_credit(&done, &verified, &w, &c).unwrap();
    // Stale, forged and replayed successors fail, atomically.
    let before = st.records().unwrap();
    let stale = rotation_op((&keys().b, 1), 1, (&keys().c, 2), 2, 35, 7, 40);
    assert!(matches!(prepare(&st, 8, &[stale]), Err(NativeError::Context)));
    // The original key claiming the head generation: not T's current key.
    let forged = rotation_signed((&f, 6), 6, (&f, 6), 7, (&keys().b, 1), 35, 7, 40);
    assert!(matches!(prepare(&st, 8, &[forged]), Err(NativeError::Authority)));
    // A fresh generation-one key cannot be routed to, even approved by T's current key.
    let fresh = rotation_signed((&f, 6), 6, (&keys().c, 1), 7, (&f, 6), 35, 7, 40);
    assert!(matches!(prepare(&st, 8, &[fresh]), Err(NativeError::Authority)));
    // Without a new R1, the only routable destination is the current one: addresses are used once.
    let reuse = rotation_op((&f, 6), 6, (&f, 6), 7, 35, 7, 40);
    assert!(matches!(prepare(&st, 8, &[reuse]), Err(NativeError::Record)));
    assert_eq!(st.records().unwrap(), before);
}
#[test]
fn license_pending_assignment_and_unanchored_detachment_reject() {
    let (mut s, id) = license_fixture();
    let mut records = s.licenses_v2.records().unwrap();
    let mut pending = None;
    let mut remove = Vec::new();
    // Explicit synthetic pending-state fixture. Preserve an existing signed
    // public enrollment; this does NOT qualify admission/scheduling of it.
    for (key, raw) in &mut records {
        let mut d = Decoder::new(raw);
        d.array().unwrap();
        d.u8().unwrap();
        match d.u8().unwrap() {
            40 => {
                let mut l = crate::licenses::LicenseRecord::decode(d.bytes().unwrap()).unwrap();
                if l.id == id {
                    l.active_worker = None;
                    l.assignment_sequence = 0;
                    let mut e = Encoder::new(Vec::new());
                    e.array(3)
                        .unwrap()
                        .u8(2)
                        .unwrap()
                        .u8(40)
                        .unwrap()
                        .bytes(&l.encode())
                        .unwrap();
                    *raw = e.into_writer();
                }
            }
            41 => {
                let a =
                    crate::license_assignment_v2::Assignment::decode(d.bytes().unwrap()).unwrap();
                if a.enrollment.binding.license == id {
                    if a.enrollment.binding.assignment_generation == 1 {
                        pending = Some(a);
                    }
                    remove.push(*key);
                }
            }
            _ => {}
        }
    }
    for key in remove {
        records.remove(&key);
    }
    let a = pending.unwrap();
    let mut e = Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .u8(2)
        .unwrap()
        .u8(42)
        .unwrap()
        .bytes(&a.encode().unwrap())
        .unwrap();
    records.insert(
        crate::domain_hash(b"MUTINY-BUILD8-PENDING-BIND-KEY-V2", &id),
        e.into_writer(),
    );
    s.licenses_v2 = crate::license_book_v2::Book::from_records(&records).unwrap();
    let before = s.records().unwrap();
    // WP-T2 (design 6.6, Restart Order L64) replaces the interim LicenseLocked refusal: a sale that
    // did not commit this pending assignment is stale. This synthetic License has assignment
    // sequence 0, which no canonical path produces (Genesis starts at 1) and which E6 cannot commit,
    // so no sale of it can be valid; the committed-pending positive case is the real-block test
    // license_dvp_entitlements_v1.rs::committed_pending_assignment_cancelled_uncommitted_one_stales_sale.
    assert!(matches!(
        prepare_license(&s, 2, &[dvp(id, 1, 2)]),
        Err(NativeError::Stale(2))
    ));
    assert_eq!(
        crate::op_envelope_v1::assignment_facts(&s, id),
        Err(crate::op_envelope_v1::EnvelopeError::ZeroSequence)
    );
    assert_eq!(s.records().unwrap(), before);
    let (s, id) = license_fixture();
    let p = prepare_license(&s, 2, &[dvp(id, 1, 2)]).unwrap();
    let mut lost = p.into_state();
    lost.protocol_records.remove(&record_key(4, id));
    assert!(validate_records(&lost, &license_context()).is_err());
}
#[test]
fn treasury_credit_proofs_bind_exact_native_receipts_principal_and_anchor() {
    let s = treasury_fixture();
    let w = treasury_funding();
    let f = freeze(&s, &w);
    let cap = verify_frozen_treasury_offer_at_creation(
        f,
        &s,
        &anchor(1),
        s.root().unwrap(),
        &CandidatePolicy::synthetic_one_atom_per_strike(),
    )
    .unwrap();
    let funded = prepare_treasury_funding(
        &s,
        &anchor(1),
        s.root().unwrap(),
        &cap,
        &w,
        &CandidatePolicy::synthetic_one_atom_per_strike(),
    )
    .unwrap();
    let c = claim(&w);
    let settled = prepare(funded.state(), 3, std::slice::from_ref(&c)).unwrap();
    let a = anchor(3);
    let mut tree = crate::state_tree::StateTree::default();
    for (k, v) in settled.state().records().unwrap() {
        tree.insert(k, v).unwrap();
    }
    let funding = tree
        .proof(a.clone(), record_key(2, w.operation.id().unwrap()))
        .encode()
        .unwrap();
    let claim = tree
        .proof(a.clone(), record_key(2, c.operation.id().unwrap()))
        .encode()
        .unwrap();
    let principal = tree
        .proof(
            a.clone(),
            native_input_id(&OutPoint {
                transaction: c.operation.id().unwrap(),
                index: 0,
            }),
        )
        .encode()
        .unwrap();
    let proofs = || TreasuryCreditProofs {
        funding: &funding,
        claim: &claim,
        principal: &principal,
    };
    verify_treasury_credit_proofs(&cap, &w, &c, proofs(), &a, settled.root()).unwrap();
    assert!(
        verify_treasury_credit_proofs(&cap, &w, &c, proofs(), &anchor(4), settled.root()).is_err()
    );
    assert!(verify_treasury_credit_proofs(&cap, &w, &c, proofs(), &a, [0; 32]).is_err());
    assert!(
        verify_treasury_credit_proofs(
            &cap,
            &w,
            &c,
            TreasuryCreditProofs {
                funding: &claim,
                claim: &funding,
                principal: &principal
            },
            &a,
            settled.root()
        )
        .is_err()
    );
}
#[test]
fn treasury_stale_authority_amount_and_native_recipient_do_not_substitute() {
    let s = treasury_fixture();
    let w = treasury_funding();
    let f = freeze(&s, &w);
    let cap = verify_frozen_treasury_offer_at_creation(
        f.clone(),
        &s,
        &anchor(1),
        s.root().unwrap(),
        &CandidatePolicy::synthetic_one_atom_per_strike(),
    )
    .unwrap();
    for variant in 0..5 {
        let mut wrong = w.clone();
        match variant {
            0 => {
                if let Action::HashLock { recipient, .. } = &mut wrong.operation.action {
                    *recipient = addr(&keys().c)
                }
            }
            1 => {
                if let Action::HashLock { amount, .. } = &mut wrong.operation.action {
                    *amount = Strikes(50_001)
                }
            }
            2 => wrong.operation.meta.contract = [78; 32],
            3 => wrong.operation.meta.trade = [78; 32],
            _ => {
                if let OfferTerms::HashLinked {
                    bitcoin_satoshis, ..
                } = &mut wrong
                    .operation
                    .offer_proof
                    .as_mut()
                    .unwrap()
                    .offer
                    .body
                    .terms
                {
                    *bitcoin_satoshis += 1
                }
            }
        };
        assert!(
            prepare_treasury_funding(
                &s,
                &anchor(1),
                s.root().unwrap(),
                &cap,
                &wrong,
                &CandidatePolicy::synthetic_one_atom_per_strike()
            )
            .is_err()
        );
    }
    let mut request = treasury_request(&w);
    request.wallet_descriptor = keys().a.public().descriptor(1).unwrap();
    assert!(
        prepare_treasury_offer(
            &s,
            &anchor(1),
            s.root().unwrap(),
            request,
            &CandidatePolicy::synthetic_one_atom_per_strike()
        )
        .is_err()
    );
    assert!(
        verify_frozen_treasury_offer_at_creation(
            f,
            &s,
            &anchor(1),
            [0; 32],
            &CandidatePolicy::synthetic_one_atom_per_strike()
        )
        .is_err()
    );
}
#[test]
fn native_license_and_treasury_independent_vectors_export() {
    let (s, id) = license_fixture();
    let p = prepare_license(&s, 2, &[dvp(id, 1, 2)]).unwrap();
    let record = &p.state().protocol_records[&record_key(4, id)];
    let (_, r) = NativeRecord::decode(record).unwrap();
    let NativeRecord::License {
        generation,
        owner,
        previous_owner,
        transfer,
        inclusion_height,
        rights_from_height,
        assignment_sequence,
        ..
    } = r
    else {
        panic!()
    };
    let s = treasury_fixture();
    let w = treasury_funding();
    let f = freeze(&s, &w);
    let b = &f.body;
    let value = serde_json::json!({"namespace":String::from_utf8(NATIVE_NAMESPACE.to_vec()).unwrap(),"license":{"id":hex::encode(id),"record":hex::encode(record),"key":hex::encode(record_key(4,id)),"network":crate::NETWORK_ID,"genesis":hex::encode([1;32]),"fingerprint":hex::encode([2;32]),"generation":generation,"owner":hex::encode(owner),"previous_owner":hex::encode(previous_owner),"transfer":hex::encode(transfer),"inclusion_height":inclusion_height,"rights_from_height":rights_from_height,"assignment_sequence":assignment_sequence},"treasury":{"body":hex::encode(b.encode().unwrap()),"frozen":hex::encode(f.encode().unwrap()),"network":b.context.network,"genesis":hex::encode(b.context.genesis),"fingerprint":hex::encode(b.context.fingerprint),"height":b.anchor.height,"block":hex::encode(b.anchor.block),"root":hex::encode(b.root),"treasury":hex::encode(b.treasury),"generation":b.generation,"address":hex::encode(b.address),"trade":hex::encode(b.trade),"contract":hex::encode(b.contract),"offer_body":hex::encode(b.offer.encode().unwrap()),"wallet_descriptor":hex::encode(&b.wallet_descriptor),"ed448":hex::encode(f.signature.ed448),"fndsa":hex::encode(f.signature.fndsa)}});
    let root = std::path::PathBuf::from(std::env::var_os("NATIVE_TRADING_EVIDENCE_DIR").unwrap());
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(
        root.join("native-license-treasury-vectors.json"),
        serde_json::to_vec_pretty(&value).unwrap(),
    )
    .unwrap();
}

#[test]
fn license_required_transfer_record_is_typed_and_bound() {
    let (s, id) = license_fixture();
    let p = prepare_license(&s, 2, &[dvp(id, 1, 2)]).unwrap();
    let valid = p.into_state();
    validate_records(&valid, &license_context()).unwrap();
    let key = record_key(4, id);
    let (_, record) = NativeRecord::decode(&valid.protocol_records[&key]).unwrap();
    let mut cases = vec![
        vec![0x01],
        b"opaque noncandidate record".to_vec(),
        NativeRecord::Applied {
            wire_hash: [3; 32],
            height: 2,
            fee_atoms: 240,
        }
        .encode(id)
        .unwrap(),
        record.encode([77; 32]).unwrap(),
    ];
    for field in 0..4 {
        let mut r = record.clone();
        if let NativeRecord::License {
            context,
            owner,
            assignment_sequence,
            ..
        } = &mut r
        {
            match field {
                0 => context.genesis = [9; 32],
                1 => context.fingerprint = [8; 32],
                2 => *owner = [7; 32],
                _ => *assignment_sequence += 1,
            }
        }
        cases.push(r.encode(id).unwrap());
    }
    for raw in cases {
        let mut malformed = valid.clone();
        malformed.protocol_records.insert(key, raw);
        // Other valid candidate records remain: no empty-namespace shortcut.
        assert!(
            malformed
                .protocol_records
                .values()
                .filter(|r| is_candidate_record(r))
                .count()
                > 1
        );
        assert!(
            validate_records(&malformed, &license_context()).is_err(),
            "required transfer key must contain its exact typed, bound record"
        );
    }
}

/// Regression for the Architect shipping-configuration decision: trading, License-transfer and
/// dividend validation are part of the always-on rule set. This test is compiled and run in the
/// ONE default build; there is no feature on which its expected results depend. It would have
/// failed (WrongOperation / LicenseHookRequired / WrongAnchor) in the former default build.
#[test]
fn rule_set_is_one_build_trading_license_transfer_and_restore() {
    let (s, id) = license_fixture();
    let op = dvp(id, 1, 2);
    // Host dispatch: a reserved-namespace trading operation is a VALID operation.
    assert!(crate::trading_host_v1::operation(&op.encode().unwrap()).unwrap());
    // Execution: the License DvP is applied, payment and ownership atomically.
    let state = prepare_license(&s, 2, std::slice::from_ref(&op))
        .unwrap()
        .into_state();
    let root = state.root().unwrap();
    // The detached, DvP-transferred License (non-zero assignment sequence, no active worker)
    // is a valid state: it serializes, restores and reproduces the identical StateRoot.
    let rows = state.records().unwrap();
    let restored = State::from_records(&rows, root).unwrap();
    assert_eq!(restored.root().unwrap(), root);
    assert_eq!(restored.records().unwrap(), rows);
    // Protected property retained: removing the typed transfer record is still invalid.
    let mut orphan = state.clone();
    orphan.protocol_records.remove(&record_key(4, id));
    assert!(orphan.records().is_err());
    // Dividend operation kind is dispatched unconditionally (not behind any feature).
    assert_ne!(crate::dividend_claim_v1::OPERATION_KIND, 0);
}

// ---------------------------------------------------------------------------------------------
// WP-T1, P3: zero monetary destinations (P-LANE-DESIGN-V1 4.1-4.3; test plan 14.3 with AM-11).
// The real-block rows are in consensus/tests/zero_destinations_v1.rs.
// ---------------------------------------------------------------------------------------------

/// The crafted raw item: the single occurrence of `value` in `raw` replaced by zeros.
fn zero_field(raw: &[u8], value: &Hash) -> Vec<u8> {
    let at: Vec<usize> = raw
        .windows(32)
        .enumerate()
        .filter(|(_, w)| *w == value)
        .map(|(i, _)| i)
        .collect();
    // WP-T4 (P7): a maker offer (OfferProof, encoded after the body and the approvals) repeats the
    // maker address as maker_wallet/destination; the FIRST occurrence is the trading-body field.
    assert!(!at.is_empty(), "the field value occurs in the item");
    let mut out = raw.to_vec();
    out[at[0]..at[0] + 32].copy_from_slice(&[0; 32]);
    out
}
fn fiat_lock_op() -> NativeOperation {
    native(
        op(
            Action::FiatLock {
                offer: [0; 32],
                maker: [0; 32],
                seller: addr(&keys().a),
                buyer: addr(&keys().b),
                amount: Strikes(50_000),
                payment_terms: [51; 32],
                change: Strikes(30_000),
            },
            2,
            10,
        ),
        1,
        &[&keys().a, &keys().b],
    )
}
fn fiat_release_op(l: &NativeOperation) -> NativeOperation {
    native(
        op(
            Action::FiatRelease {
                output: l.operation.output_id(0).unwrap(),
                buyer: addr(&keys().b),
                seller: addr(&keys().a),
                amount: Strikes(50_000),
                payment_terms: [51; 32],
                change: Strikes(80_000),
            },
            3,
            25,
        ),
        2,
        &[&keys().b, &keys().a],
    )
}
/// One case per destination field of every trading action: the honest operation, the value of
/// the field in it and the in-memory mutation that zeroes it.
fn zero_destination_cases() -> Vec<(&'static str, NativeOperation, Hash, fn(&mut Action))> {
    let (a, b, c) = (addr(&keys().a), addr(&keys().b), addr(&keys().c));
    let l = lock();
    let fiat = fiat_lock_op();
    let (_, license) = license_fixture();
    let sale = dvp(license, 1, 2);
    // A head other than T itself, so each address occurs once in the item (the `treasury` field is T).
    let rotation = rotation_op((&keys().c, 2), 2, (&keys().a, 3), 3, 4, 2, 10);
    vec![
        ("HashLock sender", l.clone(), a, |x| {
            if let Action::HashLock { sender, .. } = x {
                *sender = [0; 32]
            }
        }),
        ("HashLock recipient", l.clone(), b, |x| {
            if let Action::HashLock { recipient, .. } = x {
                *recipient = [0; 32]
            }
        }),
        ("Claim recipient", claim(&l), b, |x| {
            if let Action::Claim { recipient, .. } = x {
                *recipient = [0; 32]
            }
        }),
        ("Refund owner", refund(&l), a, |x| {
            if let Action::Refund { owner, .. } = x {
                *owner = [0; 32]
            }
        }),
        ("LicenseDvp buyer", sale.clone(), b, |x| {
            if let Action::LicenseDvp { buyer, .. } = x {
                *buyer = [0; 32]
            }
        }),
        ("LicenseDvp payment_destination", sale, c, |x| {
            if let Action::LicenseDvp {
                payment_destination,
                ..
            } = x
            {
                *payment_destination = [0; 32]
            }
        }),
        ("FiatLock seller", fiat.clone(), a, |x| {
            if let Action::FiatLock { seller, .. } = x {
                *seller = [0; 32]
            }
        }),
        ("FiatLock buyer", fiat.clone(), b, |x| {
            if let Action::FiatLock { buyer, .. } = x {
                *buyer = [0; 32]
            }
        }),
        ("FiatRelease buyer", fiat_release_op(&fiat), b, |x| {
            if let Action::FiatRelease { buyer, .. } = x {
                *buyer = [0; 32]
            }
        }),
        ("FiatRelease seller", fiat_release_op(&fiat), a, |x| {
            if let Action::FiatRelease { seller, .. } = x {
                *seller = [0; 32]
            }
        }),
        ("TreasuryRotate current_address", rotation.clone(), addr_g(&keys().c, 2), |x| {
            if let Action::TreasuryRotate {
                current_address, ..
            } = x
            {
                *current_address = [0; 32]
            }
        }),
        ("TreasuryRotate new_address", rotation, addr_g(&keys().a, 3), |x| {
            if let Action::TreasuryRotate { new_address, .. } = x {
                *new_address = [0; 32]
            }
        }),
    ]
}
#[test]
fn every_trading_destination_field_refuses_zero_in_the_codec() {
    let cases = zero_destination_cases();
    assert_eq!(cases.len(), 12, "every monetary destination of every action");
    for (name, honest, value, zero) in cases {
        let raw = honest.encode().unwrap();
        assert_eq!(NativeOperation::decode(&raw).unwrap(), honest, "{name}: control decodes");
        // In memory: unrepresentable, so it has no id and no approval payload (unsignable).
        let mut o = honest.operation.clone();
        zero(&mut o.action);
        assert_eq!(o.body(), Err(Error::Bounds), "{name}: body");
        assert_eq!(o.id(), Err(Error::Bounds), "{name}: id");
        let d = keys().a.public().descriptor(1).unwrap();
        assert_eq!(o.signing_payload(0, &d), Err(Error::Bounds), "{name}: payload");
        o.approvals.clear();
        assert_eq!(o.approve(0, &keys().a, 1), Err(Error::Bounds), "{name}: approve");
        // As crafted bytes (the same item with only that field zeroed): the decoder refuses.
        assert_eq!(
            NativeOperation::decode(&zero_field(&raw, &value)),
            Err(NativeError::Candidate(Error::Bounds)),
            "{name}: decode"
        );
    }
}
#[test]
fn crafted_zero_destination_is_refused_by_prepare_batch_without_effects() {
    let s = state();
    let before = s.records().unwrap();
    let l = lock();
    let crafted = zero_field(&l.encode().unwrap(), &addr(&keys().b));
    assert!(matches!(
        prepare_batch(
            &s,
            &anchor(1),
            s.root().unwrap(),
            &[crafted],
            &CandidatePolicy::synthetic_one_atom_per_strike()
        ),
        Err(NativeError::Candidate(Error::Bounds))
    ));
    assert_eq!(s.records().unwrap(), before);
    assert!(prepare(&s, 2, &[l]).is_ok(), "control");
}
#[test]
fn credit_refuses_a_zero_owner_whatever_the_amount() {
    let l = lock();
    let mut s = state();
    let before = s.clone();
    for amount in [Strikes(1), Strikes(0)] {
        assert_eq!(
            credit(&mut s, &l.operation, 0, [0; 32], amount, 2),
            Err(NativeError::Bounds)
        );
    }
    assert_eq!(s, before, "nothing credited, nothing burned");
    // Control: a non-zero owner is credited; a zero amount creates no output.
    credit(&mut s, &l.operation, 0, addr(&keys().a), Strikes(7), 2).unwrap();
    let id = l.operation.id().unwrap();
    assert_eq!(
        s.coins[&OutPoint {
            transaction: id,
            index: 0
        }]
        .output,
        Output {
            owner: addr(&keys().a),
            atoms: 7
        }
    );
    credit(&mut s, &l.operation, 1, addr(&keys().a), Strikes(0), 2).unwrap();
    assert!(!s.coins.contains_key(&OutPoint {
        transaction: id,
        index: 1
    }));
}
#[test]
fn treasury_destination_refuses_a_zero_address() {
    let good = TreasuryDestination {
        generation: 1,
        address: addr(&keys().b),
        descriptor: keys().b.public().descriptor(1).unwrap(),
        effective_height: 0,
    };
    validate_destination(&good).unwrap();
    let zero = TreasuryDestination {
        address: [0; 32],
        ..good.clone()
    };
    assert_eq!(validate_destination(&zero), Err(NativeError::Bounds));
    // A wrong non-zero address is a Record mismatch: the Bounds verdict is the zero rule itself.
    let other = TreasuryDestination {
        address: addr(&keys().c),
        ..good
    };
    assert_eq!(validate_destination(&other), Err(NativeError::Record));
}
// ---------------------------------------------------------------------------------------------
// WP-T1, P4 with AM-1(d) and AM-3 (P-LANE-DESIGN-AMENDMENTS-V1). The real-block envelope rows are in
// consensus/tests/operation_envelope_v1.rs (module `trading`).
// ---------------------------------------------------------------------------------------------

/// The state-only half at the next height of the synthetic chain (parent = anchor(1)).
fn state_only(s: &State, raw: &[u8]) -> NativeResult<()> {
    verify_state(
        s,
        &anchor(1),
        s.root().unwrap(),
        &History::default(),
        raw,
        &CandidatePolicy::synthetic_one_atom_per_strike(),
    )
}
#[test]
fn signature_and_state_halves_partition_the_full_verification() {
    let s = state();
    let l = lock();
    let raw = l.encode().unwrap();
    verify_signatures(&raw).unwrap();
    state_only(&s, &raw).unwrap();
    prepare(&s, 2, std::slice::from_ref(&l)).unwrap();
    // Every signature the item carries: refused by the stateless half and by full verification,
    // never read by the state-only half (whose caller verified these exact bytes before).
    for case in 0..4 {
        let mut bad = l.clone();
        let proof = bad.operation.offer_proof.as_mut().unwrap();
        match case {
            0 => bad.operation.approvals[0].signature.ed448[0] ^= 1,
            1 => bad.operation.approvals[1].signature.fndsa[0] ^= 1,
            2 => proof.offer.signature.ed448[0] ^= 1,
            _ => proof.fill_signature.fndsa[0] ^= 1,
        }
        let bad_raw = bad.encode().unwrap();
        let expected = if case < 2 {
            NativeError::Authority
        } else {
            NativeError::Candidate(Error::Signature)
        };
        assert_eq!(verify_signatures(&bad_raw), Err(expected.clone()), "case {case}");
        state_only(&s, &bad_raw).unwrap();
        assert_eq!(prepare(&s, 2, &[bad]).map(|_| ()), Err(expected), "case {case}");
    }
    // State: a spent input and a rotated-out signer. Refused by the state-only half and by full
    // verification; the signatures themselves stay valid.
    let mut spent = s.clone();
    spent.coins.remove(&point(1));
    assert_eq!(state_only(&spent, &raw), Err(NativeError::Missing));
    assert_eq!(prepare(&spent, 2, std::slice::from_ref(&l)).map(|_| ()), Err(NativeError::Missing));
    let mut rotated = s.clone();
    let mut rotation = crate::wallet_rotation_v1::Rotation {
        network: crate::NETWORK_ID,
        genesis: [11; 32],
        fingerprint: [12; 32],
        authority: addr(&keys().a),
        current: keys().a.public().descriptor(1).unwrap(),
        proposed: keys().c.public().descriptor(2).unwrap(),
        created_height: 1,
        expiry_height: 100,
        authorization: mutiny_crypto_v2::HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
        possession: mutiny_crypto_v2::HybridSignature {
            ed448: [0; 114],
            fndsa: [0; 1280],
        },
    };
    rotation.sign(&keys().a, &keys().c).unwrap();
    rotated
        .wallets
        .apply(&rotation, [11; 32], [12; 32], 1)
        .unwrap();
    verify_signatures(&raw).unwrap();
    assert_eq!(state_only(&rotated, &raw), Err(NativeError::Authority));
    assert_eq!(prepare(&rotated, 2, std::slice::from_ref(&l)).map(|_| ()), Err(NativeError::Authority));
    // Structure both halves agree on: the exact approval slot set, and no offer proof on an
    // action that fills no offer.
    let mut missing = l.clone();
    missing.operation.approvals.remove(1);
    let missing = missing.encode().unwrap();
    assert_eq!(verify_signatures(&missing), Err(NativeError::Authority));
    assert_eq!(state_only(&s, &missing), Err(NativeError::Authority));
    let mut stray = claim(&l);
    stray.operation.offer_proof = l.operation.offer_proof.clone();
    assert_eq!(
        verify_signatures(&stray.encode().unwrap()),
        Err(NativeError::Candidate(Error::OfferBinding))
    );
}
#[test]
fn assembler_preview_sums_declared_fees_without_executing() {
    let l = lock();
    let raw = l.encode().unwrap();
    // No state is read: an item that cannot execute anywhere (its input does not exist) previews
    // its declared fee; complete execution is where it fails.
    let mut spent = state();
    spent.coins.remove(&point(1));
    assert_eq!(prepare(&spent, 2, std::slice::from_ref(&l)).map(|_| ()), Err(NativeError::Missing));
    assert_eq!(declared_fee(&raw), Ok(20_000));
    let mut other = lock().operation;
    other.meta.fee = Strikes(25_000);
    if let Action::HashLock { change, .. } = &mut other.action {
        *change = Strikes(25_000);
    }
    let other = native(other, 3, &[&keys().a, &keys().b]).encode().unwrap();
    assert_eq!(
        crate::trading_host_v1::preview_fees(&[raw.clone(), other]).unwrap(),
        45_000
    );
    assert_eq!(crate::trading_host_v1::preview_fees(&[]).unwrap(), 0);
    // A reserved-namespace item that does not decode is refused (never previewed as zero).
    let mut malformed = raw;
    let last = malformed.len() - 1;
    malformed[last] ^= 0xff;
    assert!(crate::trading_host_v1::preview_fees(&[malformed]).is_err());
}
#[test]
fn trading_items_expose_their_envelope_for_reference_extraction() {
    let l = lock();
    let raw = l.encode().unwrap();
    assert_eq!(envelope_of(&raw), Some(envelope(2, 10)));
    assert_eq!(crate::op_envelope_v1::operation_envelope(&raw), Some(envelope(2, 10)));
    let body = crate::blocks::BlockBody {
        height: 2,
        reward_owner: [1; 32],
        fees: 0,
        transactions: vec![],
        operations: vec![raw.clone()],
    };
    assert_eq!(
        crate::op_envelope_v1::referenced_heights(&body),
        std::collections::BTreeSet::from([1])
    );
    let mut malformed = raw;
    malformed.push(0);
    assert_eq!(envelope_of(&malformed), None, "malformed items are skipped, execution rejects them");
}
#[test]
fn body_version_one_and_window_violations_do_not_decode() {
    let l = lock();
    let body = l.operation.body().unwrap();
    // Body version 2 layout: 12 elements, version byte 2 right after the namespace.
    let mut d = Decoder::new(&body);
    assert_eq!(d.array().unwrap(), Some(12));
    assert_eq!(d.bytes().unwrap(), NAMESPACE);
    assert_eq!(d.u8().unwrap(), BODY_VERSION);
    assert_eq!(BODY_VERSION, 2);
    // The same body with version byte 1 is refused.
    // array(12) head, bytes(44) head (2 bytes), the namespace, then the version byte.
    let at = 1 + 2 + NAMESPACE.len();
    assert_eq!(body[at], 2);
    let mut v1 = body.clone();
    v1[at] = 1;
    assert_eq!(Operation::decode_body(&v1), Err(Error::Codec));
    // An envelope violating E2/E3 cannot be encoded (so it cannot be signed) ...
    for bad in [
        Envelope {
            first_height: 5,
            last_height: 4,
            ..envelope(5, 5)
        },
        Envelope {
            last_height: 2 + EXPIRY_HORIZON + 1,
            ..envelope(2, 2)
        },
        Envelope {
            reference_block: [0; 32],
            ..envelope(2, 10)
        },
    ] {
        let mut o = l.operation.clone();
        o.meta.envelope = bad;
        assert_eq!(o.body(), Err(Error::Bounds));
    }
    // ... and a crafted body carrying one is refused by the decoder.
    let mut o = l.operation.clone();
    o.meta.envelope = envelope(2, 2 + EXPIRY_HORIZON);
    let horizon = o.body().unwrap();
    // last_height = 10,082 is the CBOR uint 0x19 0x27 0x62; 0x63 makes it 10,083 (span 10,081).
    assert_eq!(2 + EXPIRY_HORIZON, 0x2762);
    let needle = [0x19, 0x27, 0x62];
    assert_eq!(horizon.windows(3).filter(|w| *w == needle).count(), 1);
    let at = horizon.windows(3).position(|w| w == needle).unwrap();
    let mut crafted = horizon.clone();
    crafted[at + 2] = 0x63;
    assert_eq!(Operation::decode_body(&horizon).unwrap().meta.envelope.last_height, 2 + EXPIRY_HORIZON);
    assert_eq!(Operation::decode_body(&crafted), Err(Error::Codec));
}
#[test]
fn legitimate_zero_trading_fields_are_not_destinations() {
    let s = state();
    // change = 0 (no change output) and a zero-preimage condition.
    let mut o = lock().operation;
    if let Action::HashLock {
        amount,
        change,
        condition,
        ..
    } = &mut o.action
    {
        *amount = Strikes(80_000);
        *change = Strikes(0);
        *condition = preimage_hash(&[0; 32]);
    }
    let zero_change = native(o, 1, &[&keys().a, &keys().b]);
    // A literal zero condition and zero fiat payment terms.
    let mut o = lock().operation;
    if let Action::HashLock { condition, .. } = &mut o.action {
        *condition = [0; 32];
    }
    let zero_condition = native(o, 3, &[&keys().a, &keys().b]);
    let mut o = fiat_lock_op().operation;
    if let Action::FiatLock { payment_terms, .. } = &mut o.action {
        *payment_terms = [0; 32];
    }
    let zero_terms = native(o, 6, &[&keys().a, &keys().b]);
    let p = prepare(
        &s,
        2,
        &[zero_change.clone(), zero_condition.clone(), zero_terms.clone()],
    )
    .unwrap();
    for w in [&zero_change, &zero_condition, &zero_terms] {
        assert!(locked(p.state(), w.operation.output_id(0).unwrap()).is_ok());
    }
    let id = zero_change.operation.id().unwrap();
    assert!(!p.state().coins.keys().any(|q| q.transaction == id), "no change output");
    // A zero preimage is a legal value; a claim paying its whole fee input (change = 0).
    let mut c = claim(&zero_change).operation;
    if let Action::Claim {
        amount,
        preimage,
        change,
        ..
    } = &mut c.action
    {
        *amount = Strikes(80_000);
        *preimage = [0; 32];
        *change = Strikes(0);
    }
    c.meta.fee = Strikes(100_000);
    let c = native(c, 2, &[&keys().b]);
    let done = prepare(p.state(), 3, &[c.clone()]).unwrap();
    let id = c.operation.id().unwrap();
    assert_eq!(
        done.state().coins[&OutPoint {
            transaction: id,
            index: 0
        }]
        .output,
        Output {
            owner: addr(&keys().b),
            atoms: 80_000
        }
    );
    assert!(!done.state().coins.contains_key(&OutPoint {
        transaction: id,
        index: 1
    }));
}
