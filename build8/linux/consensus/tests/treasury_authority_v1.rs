//! Treasury authority and reserve through REAL blocks (Lane P design
//! `qualification/candidate-3/P-LANE-DESIGN-V1.md` test plan 14.6). WP-T1 provides the two reserve
//! rows that do not need P6 (`r2_fee_from_lineage_preserves_reserve`,
//! `treasury_at_exact_reserve_cannot_pay_until_topped_up`; Order Q15 and P9, design 10.4-10.5);
//! WP-T3 appends the P6 authority rows. Each scenario is built so that it is valid under the rules
//! of this base AND under P6 (design 7.3): the trading Treasury identity is the Genesis Treasury
//! authority T, the rotation (R2) is approved by T's CURRENT key after a real wallet rotation (R1)
//! and routes to T's current generation. TEST-VALUE only; at most NATIVE-PASS-offline-TEST-VALUE.
#[allow(dead_code, unused_imports)]
mod reserve {
    mod licenses {
        include!("../../desktop/src/wallet_host_fixture_licenses.rs");
    }
    mod tpm {
        include!("support/wallet_host_fixture_tpm.rs");
    }
    include!("support/dividend_rig.rs");
    include!("support/trading_rig_v1.rs");
    use mutiny_consensus_v8::dividends_v1::DivError;
    use tr::NativeError as N;

    fn next_key() -> HybridKey {
        HybridKey::wallet_restore(
            "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
            Role::WalletOwner,
        )
        .unwrap()
    }

    /// The Treasury T with 1,200,000 atoms and trading destination records under identity T; block
    /// at epoch P reserves 600,000; an ordinary surplus spend leaves `backing` at T's generation-1
    /// address; R1 rotates T to its generation-2 key. Returns the rig, the backing coin and the
    /// generation-2 key.
    fn treasury(tag: &str, backing: u64, extra: &[(u8, u64)]) -> (Rig, OutPoint, HybridKey, Vec<OutPoint>) {
        let (t, next, a) = (treasury_key(), next_key(), owner_key());
        let ta = addr(&t, 1);
        let mut f = fixture_with_treasury(&t, 1_200_000);
        for (key, raw) in tr::treasury_genesis_records(&trade_context(&f), ta, desc(&t, 1)).unwrap() {
            f.state.protocol_records.insert(key, raw);
        }
        let rotation_fee = fund(&mut f, 0x21, addr(&a, 1), 40_000);
        let extra: Vec<OutPoint> = extra.iter().map(|(n, atoms)| fund(&mut f, *n, addr(&a, 1), *atoms)).collect();
        let mut rig = Rig::new(f, tag);
        let s1 = rig.step(P, &[]);
        assert_eq!(s1.dividends.reserved(), 600_000);
        let coin = s1.coins.iter().find(|(_, c)| c.output.owner == ta).map(|(p, _)| p.clone()).unwrap();
        let spend = transfer(
            &rig.f,
            &t,
            1,
            coin,
            7_000,
            vec![Output { owner: [0x78; 32], atoms: 1_193_000 - backing }, Output { owner: ta, atoms: backing }],
        );
        let id = spend.id().unwrap();
        transfer_in_block(&mut rig, P + 1, spend, &[]);
        rotate_in_block(&mut rig, P + 2, ta, (&t, 1), (&next, 2), &a, rotation_fee, &[]);
        (rig, OutPoint { transaction: id, index: 1 }, next, extra)
    }
    /// R2: route the trading Treasury T from generation 1 to T's current generation-2 descriptor,
    /// approved by that current key and funded from `inputs` of T's lineage (P9), change to T.
    fn r2(rig: &Rig, next: &HybridKey, inputs: &[OutPoint], fee: u64, change: u64) -> Vec<u8> {
        let ta = addr(&treasury_key(), 1);
        trade(
            &rig.f,
            tr::Action::TreasuryRotate {
                treasury: ta,
                current_generation: 1,
                current_address: ta,
                current_descriptor: tr::descriptor_hash(&desc(next, 2)),
                new_generation: 2,
                new_address: addr(next, 2),
                new_descriptor: desc(next, 2),
                change: tr::Strikes(change),
            },
            window_at(rig, rig.height(), rig.height() + 1, rig.height() + 20),
            fee,
            inputs,
            &[(0, next, 2)],
        )
        .encode()
        .unwrap()
    }
    /// The would-be post-state of an R2 that spends `input` and returns `change` to T.
    fn would_be_backing(rig: &Rig, raw: &[u8], input: &OutPoint, change: u64) -> u64 {
        let ta = addr(&treasury_key(), 1);
        let mut s = rig.state.clone();
        s.coins.remove(input);
        let id = tr::NativeOperation::decode(raw).unwrap().operation.id().unwrap();
        s.coins.insert(
            OutPoint { transaction: id, index: 0 },
            Coin { output: Output { owner: ta, atoms: change }, created_height: rig.height() + 1, coinbase: false },
        );
        DividendState::backing(&s.coins, &s.treasury_owner_set()).unwrap()
    }

    /// 14.6 (Q15, P9): R2's fee comes from T's lineage (the generation-1 coin, spent by T's current
    /// key). A fee that would take the backing below the reserve fails the block (would-be
    /// post-state: `DivError::Backing`); the fee that leaves the backing exactly at the reserve
    /// succeeds, and the reserve is untouched.
    #[test]
    fn r2_fee_from_lineage_preserves_reserve() {
        let (mut rig, coin, next, _) = treasury("treasury-r2-fee", 620_000, &[]);
        let ta = addr(&treasury_key(), 1);
        let too_much = r2(&rig, &next, &[coin.clone()], 30_000, 590_000);
        let enough = r2(&rig, &next, &[coin.clone()], 20_000, 600_000);
        assert!(matches!(native_verdict(&rig, &[too_much.clone()]), Err(N::Record)));
        let backing = would_be_backing(&rig, &too_much, &coin, 590_000);
        assert_eq!(backing, 590_000);
        assert_eq!(rig.state.dividends.ledger().check_invariants(backing), Err(DivError::Backing));
        rejected_unchanged(&mut rig, P + 3, &[too_much.clone()]);
        commit_rejected_unchanged(&mut rig, P + 3, &[too_much]);
        let s = rig.step(P + 3, &[enough]);
        assert_eq!(tr::treasury_current(&s, &trade_context(&rig.f), ta).unwrap().address, addr(&next, 2));
        assert_eq!(s.dividends.reserved(), 600_000);
        assert_eq!(DividendState::backing(&s.coins, &s.treasury_owner_set()).unwrap(), 600_000);
        rig.finish();
    }

    /// 14.6 and 10.5 (Q15): a Treasury whose backing equals its reserve cannot pay any fee: R2 is
    /// refused; a top-up to T's lineage in the SAME block does not help (trading inputs must exist
    /// before the block); after an ordinary transfer to T's current address in an EARLIER block,
    /// the same rotation funded by that unreserved coin succeeds and the reserve stays backed.
    #[test]
    fn treasury_at_exact_reserve_cannot_pay_until_topped_up() {
        let (mut rig, coin, next, extra) = treasury("treasury-exact-reserve", 600_000, &[(0x22, 40_000)]);
        let (a, ta, na) = (owner_key(), addr(&treasury_key(), 1), addr(&next, 2));
        let from_reserve = r2(&rig, &next, &[coin.clone()], 20_000, 580_000);
        assert!(matches!(native_verdict(&rig, &[from_reserve.clone()]), Err(N::Record)));
        let backing = would_be_backing(&rig, &from_reserve, &coin, 580_000);
        assert_eq!(rig.state.dividends.ledger().check_invariants(backing), Err(DivError::Backing));
        rejected_unchanged(&mut rig, P + 3, &[from_reserve.clone()]);
        commit_rejected_unchanged(&mut rig, P + 3, &[from_reserve]);
        // The top-up: 30,000 atoms from wallet A to T's current address.
        let top_up = transfer(&rig.f, &a, 1, extra[0].clone(), 6_000, vec![Output { owner: na, atoms: 30_000 }, Output { owner: addr(&a, 1), atoms: 4_000 }]);
        let topped = OutPoint { transaction: top_up.id().unwrap(), index: 0 };
        let funded = r2(&rig, &next, &[topped.clone()], 20_000, 10_000);
        // In the same block the top-up executes in the payment phase, after the trading phase.
        rig.pool.admit(&top_up, &rig.parent, &rig.state).unwrap();
        assert!(matches!(native_verdict(&rig, &[funded.clone()]), Err(N::Missing)));
        rejected_unchanged(&mut rig, P + 3, &[funded.clone()]);
        // An EARLIER block tops up; then the rotation pays from the unreserved coin.
        let s = rig.step(P + 3, &[]);
        assert!(s.coins.contains_key(&topped));
        let s = rig.step(P + 4, &[funded]);
        assert_eq!(tr::treasury_current(&s, &trade_context(&rig.f), ta).unwrap().generation, 2);
        assert!(s.coins.contains_key(&coin), "the reserved coin was not touched");
        assert_eq!(s.dividends.reserved(), 600_000);
        assert_eq!(DividendState::backing(&s.coins, &s.treasury_owner_set()).unwrap(), 610_000);
        rig.finish();
    }
}

/// WP-T3 (P6, Order of 4 Oct 2026; Lane P design 7 and test plan 14.6): one canonical MUT Treasury
/// authority through REAL blocks. The trading Treasury identity is the Genesis Treasury authority
/// T = addr(treasury_key, 1). R1 is a real wallet rotation of T as WP-R's FundedRotation (tx tag 25), through
/// the rig helper `rotate_in_block` or the builder `r1_tx` (T self-funded or sponsored); R2 is the trading TreasuryRotate. Every negative asserts the exact
/// `NativeError` at `prepare_batch` on the same parent state and the rejection of the real block
/// (production assembler + executor + store; and, where named, a certified block refused by
/// `CanonicalStore::commit`) with the store and the canonical State byte-identical.
/// TEST-VALUE only; at most NATIVE-PASS-offline-TEST-VALUE on a Windows host.
#[allow(dead_code, unused_imports)]
mod authority {
    mod licenses {
        include!("../../desktop/src/wallet_host_fixture_licenses.rs");
    }
    mod tpm {
        include!("support/wallet_host_fixture_tpm.rs");
    }
    include!("support/dividend_rig.rs");
    include!("support/trading_rig_v1.rs");
    use mutiny_consensus_v8::mempool_v2::Status;
    use tr::NativeError as N;

    fn next_key() -> HybridKey {
        HybridKey::wallet_restore(
            "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
            Role::WalletOwner,
        )
        .unwrap()
    }
    fn ta() -> Hash {
        addr(&treasury_key(), 1)
    }
    /// The Genesis Treasury T (1,200,000 atoms at T's generation-1 address), the trading Treasury
    /// records under T, and wallet A with two 40,000-atom coins (rotation fees) and one 100,000-atom
    /// coin. No award boundary is crossed (no reserve) unless a test steps to epoch P.
    fn chain(tag: &str) -> (Rig, [OutPoint; 3]) {
        let (t, a) = (treasury_key(), owner_key());
        let mut f = fixture_with_treasury(&t, 1_200_000);
        for (key, raw) in tr::treasury_genesis_records(&trade_context(&f), ta(), desc(&t, 1)).unwrap() {
            f.state.protocol_records.insert(key, raw);
        }
        let coins = [
            fund(&mut f, 0x21, addr(&a, 1), 40_000),
            fund(&mut f, 0x22, addr(&a, 1), 40_000),
            fund(&mut f, 0x23, addr(&a, 1), 100_000),
        ];
        (Rig::new(f, tag), coins)
    }
    /// The largest ordinary coin of T's lineage in the rig's current state.
    fn treasury_coin(rig: &Rig) -> (OutPoint, u64) {
        let lineage = rig.state.treasury_owner_set();
        rig.state
            .coins
            .iter()
            .filter(|(_, c)| !c.coinbase && lineage.contains(&c.output.owner))
            .max_by_key(|(_, c)| c.output.atoms)
            .map(|(p, c)| (p.clone(), c.output.atoms))
            .unwrap()
    }
    /// A TreasuryRotate (R2) of `treasury` from its head `(current_generation, current_address)` to
    /// `to` (key, descriptor generation) as generation `new_generation`, approved in slot 0 by
    /// `signer`, funded by `input` (`atoms`), fee 20,000, change to the current address.
    #[allow(clippy::too_many_arguments)]
    fn r2(
        rig: &Rig,
        treasury: Hash,
        head: (u64, Hash),
        to: (&HybridKey, u64),
        new_generation: u64,
        signer: (&HybridKey, u64),
        input: &(OutPoint, u64),
    ) -> Vec<u8> {
        trade(
            &rig.f,
            tr::Action::TreasuryRotate {
                treasury,
                current_generation: head.0,
                current_address: head.1,
                current_descriptor: tr::descriptor_hash(&desc(signer.0, signer.1)),
                new_generation,
                new_address: addr(to.0, to.1),
                new_descriptor: desc(to.0, to.1),
                change: tr::Strikes(input.1 - 20_000),
            },
            window_at(rig, rig.height(), rig.height() + 1, rig.height() + 20),
            20_000,
            std::slice::from_ref(&input.0),
            &[(0, signer.0, signer.1)],
        )
        .encode()
        .unwrap()
    }
    fn head(rig: &Rig) -> tr::TreasuryDestination {
        tr::treasury_current(&rig.state, &trade_context(&rig.f), ta()).unwrap()
    }
    /// The exact verdict on the parent state, then the real block through the production path and
    /// a certified block through `commit`: both refused, everything byte-identical.
    fn refused(rig: &mut Rig, raw: Vec<u8>, expected: N) {
        let verdict = native_verdict(rig, std::slice::from_ref(&raw));
        assert!(matches!(&verdict, Err(e) if *e == expected), "expected {expected:?}, got {:?}", verdict.err());
        let epoch = rig.height() + 1;
        rejected_unchanged(rig, epoch, std::slice::from_ref(&raw));
        commit_rejected_unchanged(rig, epoch, &[raw]);
    }

    /// 14.6 (P6, forged succession): an unrelated fresh generation-one wallet cannot rotate the
    /// Treasury, neither T's records (R2-3: not T's current key) nor by naming itself as the
    /// Treasury identity (R2-1). Both blocks are rejected byte-identically; the head is unchanged.
    #[test]
    fn fresh_generation_one_wallet_cannot_rotate_treasury_byte_identical() {
        let (mut rig, coins) = chain("p6-fresh-wallet");
        let a = owner_key();
        rig.step(1, &[]);
        let own = (coins[2].clone(), 100_000);
        // Routing T's trading Treasury to itself, funded by its own coin, approved by its own key.
        let forged = r2(&rig, ta(), (1, ta()), (&a, 1), 2, (&a, 1), &own);
        refused(&mut rig, forged, N::Authority);
        // Naming itself as the Treasury identity (its own address as `treasury` and head).
        let self_named = r2(&rig, addr(&a, 1), (1, addr(&a, 1)), (&a, 1), 2, (&a, 1), &own);
        refused(&mut rig, self_named, N::Authority);
        assert_eq!((head(&rig).generation, head(&rig).address), (1, ta()));
        rig.finish();
    }

    /// 14.6 (P6, R2-3 and R2-4): R2 needs T's CURRENT key. Before any R1, T's current generation is
    /// its Genesis generation (already routed: `Record`) and an unregistered successor is refused
    /// (`Authority`). After R1 (T -> N at generation 2) the Genesis key is no longer T's authority
    /// (`Authority`), and N's approval routes generation 2 to N.
    #[test]
    fn r2_requires_current_genesis_authority() {
        let (mut rig, coins) = chain("p6-current-authority");
        let (t, n, a) = (treasury_key(), next_key(), owner_key());
        rig.step(1, &[]);
        let x = treasury_coin(&rig);
        let genesis_again = r2(&rig, ta(), (1, ta()), (&t, 1), 2, (&t, 1), &x);
        refused(&mut rig, genesis_again, N::Record);
        let before_r1 = r2(&rig, ta(), (1, ta()), (&n, 2), 2, (&t, 1), &x);
        refused(&mut rig, before_r1, N::Authority);
        let epoch = rig.height() + 1;
        rotate_in_block(&mut rig, epoch, ta(), (&t, 1), (&n, 2), &a, coins[0].clone(), &[]);
        let x = treasury_coin(&rig);
        let by_genesis_key = r2(&rig, ta(), (1, ta()), (&n, 2), 2, (&t, 1), &x);
        refused(&mut rig, by_genesis_key, N::Authority);
        let honest = r2(&rig, ta(), (1, ta()), (&n, 2), 2, (&n, 2), &x);
        assert!(native_verdict(&rig, std::slice::from_ref(&honest)).is_ok());
        let epoch = rig.height() + 1;
        rig.step(epoch, &[honest]);
        assert_eq!((head(&rig).generation, head(&rig).address), (2, addr(&n, 2)));
        // The Genesis destination stays generation 1 of T's history.
        let g1 = tr::treasury_generation(&rig.state, &trade_context(&rig.f), ta(), 1).unwrap();
        assert_eq!(g1.address, ta());
        rig.finish();
    }

    /// 14.6 (P6): the key of an old destination cannot route after R1. T -> N (R1), R2 to N; then
    /// T -> S (R1). N still holds the CURRENT trading destination address but is no longer T's key:
    /// its R2 to S, and to itself, are `Authority`; S's R2 to S is accepted (generation 3).
    #[test]
    fn old_destination_key_cannot_route_after_r1() {
        let (mut rig, coins) = chain("p6-old-destination");
        let (t, n, s, a) = (treasury_key(), next_key(), second_key(), owner_key());
        rig.step(1, &[]);
        rotate_in_block(&mut rig, 2, ta(), (&t, 1), (&n, 2), &a, coins[0].clone(), &[]);
        let x = treasury_coin(&rig);
        rig.step(3, &[r2(&rig, ta(), (1, ta()), (&n, 2), 2, (&n, 2), &x)]);
        rotate_in_block(&mut rig, 4, ta(), (&n, 2), (&s, 3), &a, coins[1].clone(), &[]);
        let current = (2, addr(&n, 2));
        assert_eq!(head(&rig).address, current.1);
        let x = treasury_coin(&rig);
        let by_old_destination = r2(&rig, ta(), current, (&s, 3), 3, (&n, 2), &x);
        refused(&mut rig, by_old_destination, N::Authority);
        let to_itself = r2(&rig, ta(), current, (&n, 2), 3, (&n, 2), &x);
        refused(&mut rig, to_itself, N::Authority);
        let honest = r2(&rig, ta(), current, (&s, 3), 3, (&s, 3), &x);
        rig.step(5, &[honest]);
        assert_eq!((head(&rig).generation, head(&rig).address), (3, addr(&s, 3)));
        rig.finish();
    }

    /// 14.6 (P6, R2-4): after R1 (T -> N at generation 2), T's current key N can route ONLY to N's
    /// generation-2 destination: a fresh generation-one key, an unregistered later generation of
    /// N, and T's old Genesis destination are each `Authority`; the current generation is accepted.
    #[test]
    fn r2_routes_only_to_current_generation() {
        let (mut rig, coins) = chain("p6-current-generation");
        let (t, n, a) = (treasury_key(), next_key(), owner_key());
        rig.step(1, &[]);
        rotate_in_block(&mut rig, 2, ta(), (&t, 1), (&n, 2), &a, coins[0].clone(), &[]);
        let x = treasury_coin(&rig);
        for (to, label) in [((&a, 1), "fresh generation-one key"), ((&n, 3), "unregistered generation"), ((&t, 1), "old Genesis destination")] {
            let raw = r2(&rig, ta(), (1, ta()), to, 2, (&n, 2), &x);
            let verdict = native_verdict(&rig, std::slice::from_ref(&raw));
            assert!(matches!(verdict, Err(N::Authority)), "{label}: {:?}", verdict.err());
            let epoch = rig.height() + 1;
            rejected_unchanged(&mut rig, epoch, &[raw]);
        }
        let raw = r2(&rig, ta(), (1, ta()), (&a, 1), 2, (&n, 2), &x);
        commit_rejected_unchanged(&mut rig, 3, &[raw]);
        rig.step(3, &[r2(&rig, ta(), (1, ta()), (&n, 2), 2, (&n, 2), &x)]);
        assert_eq!(head(&rig).address, addr(&n, 2));
        rig.finish();
    }

    /// 14.6 (P6, design 7.2): trading Treasury records must name the Genesis authority T. A Genesis
    /// state whose trading Treasury records name another identity, or name T with another
    /// generation-one descriptor, or exist while dividends are inactive, has no StateRoot (so no block
    /// or trusted store can be built on it); the honest state has one. On a running chain, a TreasuryRotate that
    /// names another identity is refused byte-identically (`Authority`).
    #[test]
    fn trading_treasury_records_must_name_genesis_authority() {
        let (t, a) = (treasury_key(), owner_key());
        let bad = |records: &[(Hash, Vec<u8>)], active: bool| {
            let mut f = if active { fixture_with_treasury(&t, 1_200_000) } else { fixture() };
            for (k, v) in records {
                f.state.protocol_records.insert(*k, v.clone());
            }
            f
        };
        let context = trade_context(&fixture());
        let foreign = tr::treasury_genesis_records(&context, addr(&a, 1), desc(&a, 1)).unwrap();
        let wrong_key = tr::treasury_genesis_records(&context, ta(), desc(&a, 1)).unwrap();
        let honest = tr::treasury_genesis_records(&context, ta(), desc(&t, 1)).unwrap();
        for (label, f) in [
            ("foreign identity", bad(&foreign, true)),
            ("T with another generation-one key", bad(&wrong_key, true)),
            ("dividends inactive", bad(&honest, false)),
        ] {
            // The StateRoot hook (`trading_host_v1`) maps every trading record failure to WrongAnchor.
            let root = f.state.root();
            assert!(matches!(root, Err(mutiny_consensus_v8::execution::ExecutionError::Codec(mutiny_consensus_v8::Error::WrongAnchor))), "{label}: {root:?}");
        }
        assert!(bad(&honest, true).state.root().is_ok(), "control");
        let (mut rig, coins) = chain("p6-foreign-identity");
        rig.step(1, &[]);
        let raw = r2(&rig, addr(&a, 1), (1, ta()), (&t, 1), 2, (&t, 1), &(coins[2].clone(), 100_000));
        refused(&mut rig, raw, N::Authority);
        rig.finish();
    }

    /// AM-9 m9 (documented limitation): claims spend Treasury coins implicitly, oldest generation
    /// first, and execute before payments. A pending R1 funded by T's own coin and a dividend claim
    /// that selects the same coin meet in one block: the claim wins, the assembler leaves R1 out,
    /// the pool reports R1 as INPUT_SPENT, T's key is unchanged and the reserve stays backed. The
    /// wallet re-signs R1 over the claim's change coin and it confirms in the next block.
    #[test]
    fn claim_and_r1_in_one_block() {
        let (t, n, owner) = (treasury_key(), next_key(), owner_key());
        let mut rig = Rig::new(fixture_with_treasury(&t, 1_200_000), "p6-claim-r1");
        let s = rig.step(P, &[]);
        assert_eq!(s.dividends.reserved(), 600_000);
        let x = treasury_coin(&rig);
        // R1 = WP-R's FundedRotation, self-funded by T: the input is T's own coin, authorized by T's
        // rotating (pre-rotation) key; change returns to T.
        let r1_over = |rig: &Rig, input: &(OutPoint, u64)| {
            r1_tx(rig, None, input.0.clone(), 39_000, vec![Output { owner: ta(), atoms: input.1 - 39_000 }])
        };
        let first = r1_over(&rig, &x);
        let first_id = first.id().unwrap();
        rig.pool.admit(&first, &rig.parent, &rig.state).unwrap();
        let claim = claim_op(&rig.f, &owner, 0, P, 10_000, 0, [0x77; 32]);
        let s = rig.step(P + 1, &[claim]);
        assert!(!s.coins.contains_key(&x.0), "the claim spent the coin R1 was funded by");
        assert_eq!(held_by(&s, [0x77; 32]), 10_000);
        assert_eq!(rig.chain.confirmed_height(first_id).unwrap(), None, "R1 was left out");
        assert_eq!(rig.pool.status(first_id).unwrap(), Some(Status::InputSpent));
        assert_eq!(s.wallets.current(ta()), Some(desc(&t, 1).as_slice()), "T's key is unchanged");
        assert_eq!(s.dividends.reserved(), 590_000);
        assert_eq!(DividendState::backing(&s.coins, &s.treasury_owner_set()).unwrap(), 1_190_000);
        // Re-signed over the claim's change coin, R1 confirms in the next block.
        let change = treasury_coin(&rig);
        assert_eq!(change.1, 1_190_000);
        let second = r1_over(&rig, &change);
        let second_id = second.id().unwrap();
        rig.pool.admit(&second, &rig.parent, &rig.state).unwrap();
        let s = rig.step(P + 2, &[]);
        assert_eq!(rig.chain.confirmed_height(second_id).unwrap(), Some(rig.height()));
        assert_eq!(s.wallets.current(ta()), Some(desc(&n, 2).as_slice()));
        assert_eq!(DividendState::backing(&s.coins, &s.treasury_owner_set()).unwrap(), 1_151_000);
        rig.finish();
    }

    /// R1 of T from `t` (generation 1) to `n` (generation 2) as WP-R's FundedRotation (tx tag 25),
    /// with one funding input: T's own coin (`sponsor` None: Payer::RotatingAuthority, authorized by
    /// T's rotating key under the PRE-rotation WalletBook) or a sponsor's coin (Payer::Sponsor).
    fn r1_tx(rig: &Rig, sponsor: Option<&HybridKey>, input: OutPoint, fee: u64, outputs: Vec<Output>) -> Transaction {
        use mutiny_consensus_v8::{
            funded_rotation_v2::{Party, PartialRotation, Payer, UnsignedRotation, signing_intents},
            op_envelope_v1::Envelope,
        };
        let (t, n) = (treasury_key(), next_key());
        let mut partial = PartialRotation::new(UnsignedRotation {
            genesis: rig.f.genesis.genesis,
            fingerprint: rig.f.genesis.fingerprint,
            envelope: Envelope::from_head(&rig.parent, 10_000, vec![]).unwrap(),
            authority: ta(),
            current_descriptor: desc(&t, 1),
            proposed_descriptor: desc(&n, 2),
            sponsor: sponsor.map(|k| (addr(k, 1), desc(k, 1))),
            fee,
            inputs: vec![(input, if sponsor.is_some() { Payer::Sponsor } else { Payer::RotatingAuthority })],
            outputs,
        });
        for intent in signing_intents(&partial.unsigned).unwrap() {
            let key = match intent.party {
                Party::RotatingAuthority => &t,
                Party::NewKey => &n,
                Party::Sponsor => sponsor.unwrap(),
            };
            partial.sign(intent.slot, key).unwrap();
        }
        Transaction::FundedRotation(partial.complete().unwrap())
    }

    /// AM-11 (same-block R1 + R2) and design 7.6: in one block, R2 (trading phase) sees the
    /// PRE-R1 authority because R1 executes later (payment phase). An R2 to the new key in the
    /// block that carries R1 is `Authority` on the parent state and the real block carrying both
    /// is rejected byte-identically (R1 stays pending); R1 alone confirms, and the same routing
    /// is accepted in the next block.
    #[test]
    fn r1_and_r2_in_one_block() {
        let (mut rig, coins) = chain("p6-r1-r2-same-block");
        let (n, a) = (next_key(), owner_key());
        rig.step(1, &[]);
        let r1 = r1_tx(&rig, Some(&a), coins[0].clone(), 39_000, vec![Output { owner: addr(&a, 1), atoms: 1_000 }]);
        let r1_id = r1.id().unwrap();
        rig.pool.admit(&r1, &rig.parent, &rig.state).unwrap();
        let x = treasury_coin(&rig);
        let r2_same = r2(&rig, ta(), (1, ta()), (&n, 2), 2, (&n, 2), &x);
        assert!(matches!(native_verdict(&rig, std::slice::from_ref(&r2_same)), Err(N::Authority)));
        rejected_unchanged(&mut rig, 2, &[r2_same]);
        assert_eq!(rig.pool.status(r1_id).unwrap(), Some(Status::Pending), "R1 is still pending");
        let s = rig.step(2, &[]);
        assert_eq!(rig.chain.confirmed_height(r1_id).unwrap(), Some(2));
        assert_eq!(s.wallets.current(ta()), Some(desc(&n, 2).as_slice()));
        rig.step(3, &[r2(&rig, ta(), (1, ta()), (&n, 2), 2, (&n, 2), &x)]);
        assert_eq!(head(&rig).address, addr(&n, 2));
        rig.finish();
    }

    /// AM-11 (a Treasury R1 spending reserve) and design 10.4-10.5: T's R1 funded from T's own coin
    /// may pay only from value above the reserve. An R1 whose funding transfer would take the
    /// backing below the reserve never confirms (the would-be post-state violates the backing
    /// invariant: `DivError::Backing`) and leaves T's key, the reserve and the backing unchanged;
    /// R1 paying from surplus confirms in `claim_and_r1_in_one_block`.
    #[test]
    fn treasury_r1_cannot_spend_reserve() {
        use mutiny_consensus_v8::dividends_v1::DivError;
        let mut rig = Rig::new(fixture_with_treasury(&treasury_key(), 1_200_000), "p6-r1-reserve");
        let s = rig.step(P, &[]);
        assert_eq!(s.dividends.reserved(), 600_000);
        let x = treasury_coin(&rig);
        assert_eq!(x.1, 1_200_000);
        // 611,000 leaves T's lineage: backing 550,000 < reserve 600,000.
        let draining = r1_tx(&rig, None, x.0.clone(), 39_000, vec![Output { owner: ta(), atoms: 550_000 }, Output { owner: [0x78; 32], atoms: 611_000 }]);
        assert_eq!(rig.state.dividends.ledger().check_invariants(550_000), Err(DivError::Backing));
        let before = rig.state.records().unwrap();
        let drain_id = draining.id().unwrap();
        // The pool admits it (admission does not evaluate the reserve); the block trial leaves it out.
        assert!(matches!(rig.pool.admit(&draining, &rig.parent, &rig.state), Ok(Status::Pending)));
        let s = rig.step(P + 1, &[]);
        assert_eq!(rig.chain.confirmed_height(drain_id).unwrap(), None, "the draining R1 never confirms");
        assert_eq!(rig.pool.status(drain_id).unwrap(), Some(Status::Pending));
        assert_eq!(s.wallets.current(ta()), Some(desc(&treasury_key(), 1).as_slice()), "T's key is unchanged");
        assert!(s.coins.contains_key(&x.0));
        assert_eq!(s.dividends.reserved(), 600_000);
        assert_eq!(DividendState::backing(&s.coins, &s.treasury_owner_set()).unwrap(), 1_200_000);
        let _ = before;
        rig.finish();
    }
}
