//! P9 funding from authenticated wallet history, through REAL blocks (Order of 4 Oct 2026 decision
//! P9 and Q15; Lane P design `qualification/candidate-3/P-LANE-DESIGN-V1.md` sections 10.1-10.6 and
//! test plan 14.9; amendment AM-11 "trading items with older-generation payer inputs"). A trading
//! payer may combine inputs from every authenticated generation of its wallet lineage, authorized by
//! the lineage's CURRENT descriptor under the parent WalletBook; an unrelated wallet never counts,
//! a rotated-out key spends nothing, the conditional payout stays with the lock's recipient, and the
//! Treasury reserve stays backed. Every wallet rotation is a real funded rotation executed in an
//! earlier real block; every block is prepared by the production assembler, executed by the V2
//! executor and installed by `CanonicalStore::commit`; a rejected block leaves the head, the State
//! and every store row byte-identical, and each negative also asserts the exact `NativeError` at the
//! read-only consensus entry point on the same parent state. TEST-VALUE only (published BIP39 test
//! phrases, random Transport maker keys); evidence class at most NATIVE-PASS-offline-TEST-VALUE.
#[allow(dead_code, unused_imports)]
mod lineage {
    mod licenses {
        include!("../../desktop/src/wallet_host_fixture_licenses.rs");
    }
    mod tpm {
        include!("support/wallet_host_fixture_tpm.rs");
    }
    include!("support/dividend_rig.rs");
    include!("support/trading_rig_v1.rs");
    use mutiny_consensus_v8::{
        dividends_v1::DivError,
        op_envelope_v1::{assignment_facts, entitlement_facts},
    };
    use tr::NativeError as N;

    /// The rotated wallet's next key (generation 2): a published BIP39 test phrase.
    fn next_key() -> HybridKey {
        HybridKey::wallet_restore(
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
            Role::WalletOwner,
        )
        .unwrap()
    }
    /// The rotated Treasury's next key (generation 2): a published BIP39 test phrase.
    fn treasury_next_key() -> HybridKey {
        HybridKey::wallet_restore(
            "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
            Role::WalletOwner,
        )
        .unwrap()
    }
    fn lock_action(sender: Hash, recipient: Hash, amount: u64, change: u64) -> tr::Action {
        tr::Action::HashLock {
            offer: [0; 32],
            maker: [0; 32],
            sender,
            recipient,
            amount: tr::Strikes(amount),
            condition: tr::preimage_hash(&[42; 32]),
            refund_height: 100,
            change: tr::Strikes(change),
        }
    }
    fn raw(op: &tr::NativeOperation) -> Vec<u8> {
        op.encode().unwrap()
    }
    fn next_window(rig: &Rig) -> Window {
        window_at(rig, rig.height(), rig.height() + 1, rig.height() + 20)
    }

    /// Wallet B (generation 1, registered) holds an old-generation coin; a coin already waits at the
    /// address of its next generation; wallet A pays the rotation fee and owns a foreign coin.
    struct Lineage {
        rig: Rig,
        a: HybridKey,
        b: HybridKey,
        e: HybridKey,
        old: OutPoint,
        new: OutPoint,
        foreign: OutPoint,
        stranger: OutPoint,
        extra: Vec<OutPoint>,
    }
    fn lineage(tag: &str, rotate: bool, before_rotation: impl FnOnce(&Fixture) -> Vec<Vec<u8>>) -> Lineage {
        let (a, b, e) = (owner_key(), second_key(), next_key());
        let mut f = fixture();
        f.state.wallets.register(&desc(&b, 1)).unwrap();
        let old = fund(&mut f, 0x11, addr(&b, 1), 60_000);
        let new = fund(&mut f, 0x12, addr(&e, 2), 40_000);
        let fee = fund(&mut f, 0x13, addr(&a, 1), 40_000);
        let foreign = fund(&mut f, 0x14, addr(&a, 1), 40_000);
        let stranger = fund(&mut f, 0x15, [0x99; 32], 40_000);
        let extra = vec![fund(&mut f, 0x16, addr(&e, 2), 40_000), fund(&mut f, 0x17, addr(&a, 1), 100_000)];
        let mut rig = Rig::new(f, tag);
        let ops = before_rotation(&rig.f);
        if rotate {
            rotate_in_block(&mut rig, 1, addr(&b, 1), (&b, 1), (&e, 2), &a, fee, &ops);
        }
        Lineage { rig, a, b, e, old, new, foreign, stranger, extra }
    }

    /// 14.9: a hash lock funded from TWO generations of the sender's lineage after a real rotation:
    /// the old-generation coin (B, generation 1) and the new-generation coin (E, generation 2),
    /// approved by the CURRENT descriptor. Without P9 the new-generation input was refused.
    #[test]
    fn hash_lock_funded_from_two_generations_after_rotation() {
        let Lineage { mut rig, a, b, e, old, new, .. } = lineage("lineage-two-generations", true, |_| vec![]);
        let (aa, ba) = (addr(&a, 1), addr(&b, 1));
        let lock = trade(
            &rig.f,
            lock_action(ba, aa, 50_000, 30_000),
            next_window(&rig),
            20_000,
            &[old.clone(), new.clone()],
            &[(0, &e, 2), (1, &a, 1)],
        );
        native_verdict(&rig, &[raw(&lock)]).unwrap();
        let s2 = rig.step(2, &[raw(&lock)]);
        assert!(!s2.coins.contains_key(&old) && !s2.coins.contains_key(&new), "both generations spent");
        let l = tr::locked(&s2, lock.operation.output_id(0).unwrap()).unwrap();
        assert_eq!((l.sender, l.amount, l.created_height), (ba, tr::Strikes(50_000), 2));
        let change = &s2.coins[&OutPoint { transaction: lock.operation.id().unwrap(), index: 1 }];
        assert_eq!((change.output.owner, change.output.atoms), (ba, 30_000), "change to the signed sender");
        // A reopened store replays both blocks to the identical State.
        let rig = rig.restart();
        assert_eq!(rig.state.records().unwrap(), s2.records().unwrap());
        rig.finish();
    }

    /// 14.9 and 10.6: an input owned by an unrelated wallet (a registered wallet, and an address
    /// with no wallet relation at all) is never the payer's lineage: Authority, block refused,
    /// store byte-identical. So is the same old-generation input under the rotated-out key.
    #[test]
    fn unrelated_wallet_input_rejected_byte_identical() {
        let Lineage { mut rig, a, b, e, old, new, foreign, stranger, .. } =
            lineage("lineage-unrelated", true, |_| vec![]);
        let (aa, ba) = (addr(&a, 1), addr(&b, 1));
        let w = next_window(&rig);
        for (name, inputs) in [("registered other wallet", [old.clone(), foreign]), ("no wallet at all", [old.clone(), stranger])] {
            let lock = raw(&trade(&rig.f, lock_action(ba, aa, 50_000, 30_000), w, 20_000, &inputs, &[(0, &e, 2), (1, &a, 1)]));
            assert!(matches!(native_verdict(&rig, &[lock.clone()]), Err(N::Authority)), "{name}");
            rejected_unchanged(&mut rig, 2, &[lock.clone()]);
            commit_rejected_unchanged(&mut rig, 2, &[lock]);
        }
        // Control: the lineage-only inputs are accepted at the same parent.
        let lineage_only = raw(&trade(&rig.f, lock_action(ba, aa, 50_000, 30_000), w, 20_000, &[old, new], &[(0, &e, 2), (1, &a, 1)]));
        native_verdict(&rig, &[lineage_only]).unwrap();
        rig.finish();
    }

    /// 10.6: a rotated-out key cannot spend the old addresses any more: its approval of the payer
    /// slot fails (the CURRENT descriptor is required), whether it names the old or the new address.
    #[test]
    fn rotated_out_key_cannot_spend_old_addresses() {
        let Lineage { mut rig, a, b, e, old, new, .. } = lineage("lineage-rotated-out", true, |_| vec![]);
        let (aa, ba, ea) = (addr(&a, 1), addr(&b, 1), addr(&e, 2));
        let w = next_window(&rig);
        for sender in [ba, ea] {
            let lock = raw(&trade(&rig.f, lock_action(sender, aa, 50_000, 30_000), w, 20_000, &[old.clone(), new.clone()], &[(0, &b, 1), (1, &a, 1)]));
            assert!(matches!(native_verdict(&rig, &[lock.clone()]), Err(N::Authority)));
            rejected_unchanged(&mut rig, 2, &[lock]);
        }
        // The current key spends both generations, naming either lineage address as the sender.
        let lock = raw(&trade(&rig.f, lock_action(ea, aa, 50_000, 30_000), w, 20_000, &[old, new], &[(0, &e, 2), (1, &a, 1)]));
        let s2 = rig.step(2, &[lock]);
        assert!(s2.coins.values().any(|c| c.output.owner == ea && c.output.atoms == 30_000));
        rig.finish();
    }

    /// 14.9 and 10.3: the hash-lock claim's fee comes from the recipient's lineage (a coin at the
    /// recipient's NEW generation, approved by the current key), while the payout and the change go
    /// to the lock's authorized recipient. A fee payer cannot redirect the payout to its own address.
    #[test]
    fn claim_fee_from_recipient_lineage_payout_to_recipient() {
        let (a, b) = (owner_key(), second_key());
        let (aa, ba) = (addr(&a, 1), addr(&b, 1));
        let mut lock = None;
        let Lineage { mut rig, e, new, extra, .. } = lineage("lineage-claim", true, |f| {
            // Block 1 also locks a principal for recipient B, approved by B's generation-1 key (the
            // trading phase reads the parent WalletBook, before this block's rotation). Its input is
            // A's 100,000-atom coin `extra[1]`.
            let op = trade(
                f,
                lock_action(aa, ba, 50_000, 30_000),
                Window { first: 1, last: 20, reference: (0, f.genesis.block) },
                20_000,
                &[OutPoint { transaction: [0x17; 32], index: 0 }],
                &[(0, &a, 1), (1, &b, 1)],
            );
            let bytes = raw(&op);
            lock = Some(op);
            vec![bytes]
        });
        let lock = lock.unwrap();
        let output = lock.operation.output_id(0).unwrap();
        assert!(tr::locked(&rig.state, output).is_ok());
        let ea = addr(&e, 2);
        let claim = |recipient: Hash, input: &OutPoint| {
            raw(&trade(
                &rig.f,
                tr::Action::Claim { output, recipient, amount: tr::Strikes(50_000), preimage: [42; 32], change: tr::Strikes(20_000) },
                next_window(&rig),
                20_000,
                &[input.clone()],
                &[(0, &e, 2)],
            ))
        };
        // The fee payer's own (new) address is not the lock's recipient: the payout cannot move there.
        let captured = claim(ea, &new);
        let honest = claim(ba, &new);
        assert!(matches!(native_verdict(&rig, &[captured.clone()]), Err(N::Authority)));
        rejected_unchanged(&mut rig, 2, &[captured]);
        let s2 = rig.step(2, &[honest.clone()]);
        let id = tr::NativeOperation::decode(&honest).unwrap().operation.id().unwrap();
        let out = |i: u32| s2.coins[&OutPoint { transaction: id, index: i }].output.clone();
        assert_eq!(out(0), Output { owner: ba, atoms: 50_000 }, "payout to the authorized recipient");
        assert_eq!(out(1), Output { owner: ba, atoms: 20_000 }, "change to the recipient as well");
        assert!(!s2.coins.contains_key(&new), "the fee came from the new generation");
        assert!(s2.coins.contains_key(&extra[0]));
        rig.finish();
    }

    /// 14.9: a License DvP whose buyer pays from two generations of its lineage after a rotation;
    /// the License goes to the buyer address named in the signed sale.
    #[test]
    fn dvp_buyer_lineage_funding() {
        let Lineage { mut rig, a, b, e, old, new, .. } = lineage("lineage-dvp", true, |_| vec![]);
        let (aa, ba) = (addr(&a, 1), addr(&b, 1));
        let sold = license(3);
        let facts = vec![entitlement_facts(&rig.state, sold), assignment_facts(&rig.state, sold).unwrap()];
        let sale = trade_with(
            &rig.f,
            tr::Action::LicenseDvp {
                offer: [0; 32],
                maker: [0; 32],
                license: sold,
                license_generation: 1,
                seller: aa,
                buyer: ba,
                price: tr::Strikes(50_000),
                payment_destination: aa,
                change: tr::Strikes(30_000),
            },
            next_window(&rig),
            facts,
            20_000,
            &[old.clone(), new.clone()],
            &[(0, &a, 1), (1, &e, 2)],
        );
        native_verdict(&rig, &[raw(&sale)]).unwrap();
        let s2 = rig.step(2, &[raw(&sale)]);
        assert_eq!(s2.licenses_v2.license(sold).unwrap().owner, ba);
        assert!(!s2.coins.contains_key(&old) && !s2.coins.contains_key(&new));
        let id = sale.operation.id().unwrap();
        assert_eq!(s2.coins[&OutPoint { transaction: id, index: 1 }].output, Output { owner: ba, atoms: 30_000 });
        rig.finish();
    }

    /// 14.9 with Q15 (10.4): a Treasury that rotated (R1, a real wallet rotation) funds a trading
    /// item from its OLD generation with its current key (P9), but no lineage spend can take the
    /// backing below the reserve: the block is refused, the would-be post-state violates
    /// `check_invariants` with `DivError::Backing`, and the surplus spend that leaves the backing
    /// exactly at the reserve is accepted.
    #[test]
    fn treasury_lineage_fee_cannot_touch_reserve() {
        let (t, next, a) = (treasury_key(), treasury_next_key(), owner_key());
        let (ta, aa) = (addr(&t, 1), addr(&a, 1));
        let mut f = fixture_with_treasury(&t, 1_200_000);
        let rotation_fee = fund(&mut f, 0x21, aa, 40_000);
        let mut rig = Rig::new(f, "lineage-treasury");
        let s1 = rig.step(P, &[]);
        assert_eq!(s1.dividends.reserved(), 600_000);
        // An ordinary surplus spend leaves 693,000 of backing at the generation-1 address.
        let coin = s1.coins.iter().find(|(_, c)| c.output.owner == ta).map(|(p, _)| p.clone()).unwrap();
        let spend = transfer(&rig.f, &t, 1, coin, 7_000, vec![Output { owner: [0x78; 32], atoms: 500_000 }, Output { owner: ta, atoms: 693_000 }]);
        let spend_id = spend.id().unwrap();
        transfer_in_block(&mut rig, P + 1, spend, &[]);
        let backing_coin = OutPoint { transaction: spend_id, index: 1 };
        rotate_in_block(&mut rig, P + 2, ta, (&t, 1), (&next, 2), &a, rotation_fee, &[]);
        let lock = |amount: u64, change: u64| {
            raw(&trade(
                &rig.f,
                lock_action(ta, aa, amount, change),
                next_window(&rig),
                20_000,
                &[backing_coin.clone()],
                &[(0, &next, 2), (1, &a, 1)],
            ))
        };
        let reserved = rig.state.dividends.reserved();
        assert_eq!(reserved, 600_000);
        // One atom below the reserve: refused.
        let bad = lock(73_001, 599_999);
        let good = lock(73_000, 600_000);
        assert!(matches!(native_verdict(&rig, &[bad.clone()]), Err(N::Record)), "StateRoot validation refuses it");
        let mut would_be = rig.state.clone();
        would_be.coins.remove(&backing_coin);
        let bad_id = tr::NativeOperation::decode(&bad).unwrap().operation.id().unwrap();
        would_be.coins.insert(
            OutPoint { transaction: bad_id, index: 1 },
            Coin { output: Output { owner: ta, atoms: 599_999 }, created_height: rig.height() + 1, coinbase: false },
        );
        let backing = DividendState::backing(&would_be.coins, &would_be.treasury_owner_set()).unwrap();
        assert_eq!(backing, 599_999);
        assert_eq!(rig.state.dividends.ledger().check_invariants(backing), Err(DivError::Backing));
        rejected_unchanged(&mut rig, P + 3, &[bad.clone()]);
        commit_rejected_unchanged(&mut rig, P + 3, &[bad]);
        // Exactly at the reserve: accepted, the reserve is untouched and fully backed.
        let s = rig.step(P + 3, &[good]);
        assert_eq!(s.dividends.reserved(), 600_000);
        assert_eq!(DividendState::backing(&s.coins, &s.treasury_owner_set()).unwrap(), 600_000);
        rig.finish();
    }
}
