#![cfg(feature = "dividend-test-fixtures")]
//! Stage C acceptance: dividends through real canonical block execution (NATIVE, TEST-VALUE).
//! Every block is prepared by the production assembler, certified with real hybrid votes and
//! installed by the canonical store, which re-executes it. The Treasury is a TEST-VALUE
//! descriptor under the test Genesis; nothing here is a production identity or default.
#[path = "../../desktop/src/wallet_host_fixture_licenses.rs"]
mod licenses;
#[path = "support/wallet_host_fixture_tpm.rs"]
mod tpm;
include!("support/dividend_rig.rs");
#[test]
fn award_partial_full_claims_expiry_replay_competition_and_restart_through_real_blocks() {
    let treasury = treasury_key();
    let owner = owner_key();
    let dest = [0x77; 32];
    let mut rig = Rig::new(fixture_with_treasury(&treasury, 1_200_000), "claims");
    // Block 1 crosses the first award boundary directly from epoch 0: epoch 0 itself created none.
    assert!(rig.state.dividends.ledger().award(0).is_none());
    let s1 = rig.step(P, &[]);
    let award = s1.dividends.ledger().award(P).expect("first award epoch is 131072");
    assert_eq!((award.accounts(), award.deadline()), (12, P + W));
    assert_eq!(award.account(&license(0)).unwrap().share, 50_000);
    assert_eq!(s1.dividends.reserved(), 600_000);
    // Deterministic reconstruction from the canonical records.
    let rows = s1.records().unwrap();
    assert_eq!(State::from_records(&rows, s1.root().unwrap()).unwrap(), s1);
    // Block 2: a partial claim. Zero fee, exact payment, value neutral, reserve reduced.
    let op = claim_op(&rig.f, &owner, 0, P, 10_000, 0, dest);
    let s2 = rig.step(P + 10, &[op.clone()]);
    assert_eq!(total(&s2), total(&s1) + SUBSIDY, "claim is value-neutral and fee-free");
    assert_eq!(held_by(&s2, dest), 10_000);
    assert_eq!(held_by(&s2, addr(&treasury, 1)), 1_190_000);
    assert_eq!(s2.dividends.reserved(), 590_000);
    let reward = s2.coins.values().filter(|c| c.coinbase && c.created_height == 2).map(|c| c.output.atoms).sum::<u64>();
    assert_eq!(reward, SUBSIDY, "no fee was charged or paid to the miner");
    // Replay, overclaim and competing claims are rejected and leave the chain untouched.
    assert!(rig.try_step(P + 11, &[op.clone()]).is_err(), "replay");
    assert!(rig.try_step(P + 11, &[claim_op(&rig.f, &owner, 0, P, 40_001, 1, dest)]).is_err(), "overclaim");
    assert!(
        rig.try_step(P + 11, &[claim_op(&rig.f, &owner, 0, P, 30_000, 1, dest), claim_op(&rig.f, &owner, 0, P, 30_000, 2, dest)]).is_err(),
        "competing claims exceeding the entitlement"
    );
    assert_eq!(rig.height(), 2);
    assert_eq!(rig.state, s2);
    // Full claim of the remainder; two Licenses in one block.
    let s3 = rig.step(P + 12, &[claim_op(&rig.f, &owner, 0, P, 40_000, 1, dest)]);
    assert_eq!(s3.dividends.ledger().award(P).unwrap().account(&license(0)).unwrap().remaining, 0);
    let s4 = rig.step(
        P + 13,
        &[claim_op(&rig.f, &owner, 5, P, 12_345, 0, dest), claim_op(&rig.f, &owner, 6, P, 50_000, 0, dest)],
    );
    assert_eq!(s4.dividends.reserved(), 600_000 - 10_000 - 40_000 - 12_345 - 50_000);
    // Last claimable epoch, then the exclusive deadline.
    let s5 = rig.step(P + W - 1, &[claim_op(&rig.f, &owner, 7, P, 777, 0, dest)]);
    assert!(s5.dividends.ledger().award(P).is_some());
    assert!(
        rig.try_step(P + W, &[claim_op(&rig.f, &owner, 8, P, 1, 0, dest)]).is_err(),
        "expiry is processed before any claim of the block that reaches the deadline"
    );
    let s6 = rig.step(P + W, &[]);
    assert_eq!(s6.dividends.reserved(), 0);
    assert!(s6.dividends.ledger().award(P).is_none());
    assert!(rig.try_step(P + W + 1, &[claim_op(&rig.f, &owner, 8, P, 1, 0, dest)]).is_err());
    // Exact conservation of the Treasury principal across every claim.
    assert_eq!(held_by(&s6, addr(&treasury, 1)) + held_by(&s6, dest), 1_200_000);
    assert_eq!(held_by(&s6, dest), 10_000 + 40_000 + 12_345 + 50_000 + 777);
    // Restart recovery: durable store reopened from Genesis reproduces the identical state.
    let before = rig.state.clone();
    let mut rig = rig.restart();
    assert_eq!(rig.state, before);
    assert_eq!(rig.state.records().unwrap(), before.records().unwrap());
    assert_eq!(rig.state.root().unwrap(), before.root().unwrap());
    let s7 = rig.step(P + W + 5, &[]);
    assert_eq!(s7.dividends.reserved(), 0);
    rig.finish();
}

#[test]
fn ordinary_spend_cannot_consume_reserved_backing_but_surplus_remains_spendable() {
    let treasury = treasury_key();
    let owner = owner_key();
    let dest = [0x78; 32];
    let mut rig = Rig::new(fixture_with_treasury(&treasury, 1_200_000), "spend");
    let s1 = rig.step(P, &[]);
    assert_eq!(s1.dividends.reserved(), 600_000);
    let point = s1
        .coins
        .iter()
        .find(|(_, c)| !c.coinbase && c.output.owner == addr(&treasury, 1))
        .map(|(p, _)| p.clone())
        .unwrap();
    let spend = |keep: u64| {
        transfer(
            &rig.f,
            &treasury,
            1,
            point.clone(),
            7_000,
            vec![
                Output { owner: dest, atoms: 1_200_000 - 7_000 - keep },
                Output { owner: addr(&treasury, 1), atoms: keep },
            ],
        )
    };
    let good = spend(650_000);
    let bad = spend(599_999);
    rig.pool.admit(&good, &rig.parent, &rig.state).unwrap();
    let prepared = rig
        .chain
        .prepare_pending(Preparation {
            expected_parent: &rig.parent,
            pool: &rig.pool,
            license: rig.f.license,
            worker: rig.f.worker,
            timestamp: at(P + 1),
            ticket: rig.ticket,
            operations: &[],
        })
        .unwrap();
    assert_eq!(prepared.body.transactions, vec![good.encode().unwrap()]);
    // The same block with the violating transfer substituted fails full execution.
    let (work_parent, _, _) = rig.chain.execution_parent(rig.height()).unwrap();
    let mut body = prepared.body.clone();
    body.transactions = vec![bad.encode().unwrap()];
    let mut candidate = prepared.candidate.clone();
    candidate.body_root = body.root().unwrap();
    let rejected = rig.state.prepare_candidate_v2(CandidatePreparation {
        parent: &work_parent,
        candidate: &candidate,
        ticket_sequence: rig.ticket,
        body: &body,
    });
    assert!(rejected.is_err(), "spending below the reserved backing must be rejected: {:?}", rejected.err());
    // Control: the unmodified body (backing preserved) executes and commits.
    let s2 = rig.commit_prepared(prepared);
    assert_eq!(held_by(&s2, addr(&treasury, 1)), 650_000);
    assert_eq!(s2.dividends.reserved(), 600_000);
    // A claim after the ordinary spend still draws from the retained Treasury change coin.
    let s3 = rig.step(P + 2, &[claim_op(&rig.f, &owner, 1, P, 5_000, 0, dest)]);
    assert_eq!(held_by(&s3, addr(&treasury, 1)), 645_000);
    assert_eq!(s3.dividends.reserved(), 595_000);
    rig.finish();
}

#[test]
fn suspension_revocation_effects_and_automatic_suspension_end() {
    let treasury = treasury_key();
    let owner = owner_key();
    let dest = [0x79; 32];
    // Genesis-time statuses exclude Licenses from the very first snapshot.
    let mut f = fixture_with_treasury(&treasury, 1_200_000);
    f.state.dividends.fixture_suspend(license(2), P + 100).unwrap();
    f.state.dividends.fixture_revoke(license(3)).unwrap();
    let mut rig = Rig::new(f, "status-a");
    let s1 = rig.step(P, &[]);
    let a = s1.dividends.ledger().award(P).unwrap();
    assert_eq!(a.accounts(), 10);
    assert!(a.account(&license(2)).is_none() && a.account(&license(3)).is_none());
    rig.finish();
    // Statuses applied after an award exists: allocation preserved, claims blocked.
    let mut f = fixture_with_treasury(&treasury, 1_200_000);
    f.state.fixture_advance_dividends(P).unwrap();
    f.state.dividends.fixture_suspend(license(0), P + 50).unwrap();
    f.state.dividends.fixture_revoke(license(1)).unwrap();
    let mut rig = Rig::new(f, "status-b");
    assert!(rig.try_step(P + 10, &[claim_op(&rig.f, &owner, 0, P, 100, 0, dest)]).is_err(), "suspended");
    assert!(rig.try_step(P + 10, &[claim_op(&rig.f, &owner, 1, P, 100, 0, dest)]).is_err(), "revoked");
    let s1 = rig.step(P + 10, &[claim_op(&rig.f, &owner, 2, P, 100, 0, dest)]);
    let a = s1.dividends.ledger().award(P).unwrap();
    assert_eq!(a.account(&license(0)).unwrap().remaining, 50_000, "suspension does not delete the allocation");
    assert_eq!(a.deadline(), P + W, "the original deadline continues");
    // The suspension ends automatically at its expiry epoch; revocation stays terminal.
    let s2 = rig.step(P + 50, &[claim_op(&rig.f, &owner, 0, P, 100, 0, dest)]);
    assert_eq!(s2.dividends.ledger().award(P).unwrap().account(&license(0)).unwrap().remaining, 49_900);
    assert!(rig.try_step(P + 51, &[claim_op(&rig.f, &owner, 1, P, 100, 0, dest)]).is_err());
    rig.finish();
}

#[test]
fn treasury_rotation_keeps_outstanding_reserves_and_old_generation_backing() {
    let treasury = treasury_key();
    let next = second_key();
    let owner = owner_key();
    let dest = [0x7a; 32];
    let mut f = fixture_with_treasury(&treasury, 1_200_000);
    // An ordinary funding coin for the owner pays the rotation and new-offer transactions.
    for (n, atoms) in [(0xe1u8, 40_000u64), (0xe2, 600_000)] {
        f.state.coins.insert(
            OutPoint { transaction: [n; 32], index: 0 },
            Coin { output: Output { owner: addr(&owner, 1), atoms }, created_height: 0, coinbase: false },
        );
    }
    let fund_rotation = OutPoint { transaction: [0xe1; 32], index: 0 };
    let fund_offer = OutPoint { transaction: [0xe2; 32], index: 0 };
    let mut rig = Rig::new(f, "rotation");
    let s1 = rig.step(P, &[]);
    assert_eq!(s1.dividends.reserved(), 600_000);
    let old_coin = s1
        .coins
        .iter()
        .find(|(_, c)| c.output.owner == addr(&treasury, 1))
        .map(|(p, _)| p.clone())
        .unwrap();
    // Funded Treasury wallet rotation (bundle tag 25), explicitly sponsored by the owner's coin. It
    // moves no Treasury value and cannot erase or free a reserve.
    let rotate = sponsored_rotation(&rig, addr(&treasury, 1), (&treasury, 1), (&next, 2), &owner, fund_rotation, 39_000, 1_000);
    rig.pool.admit(&rotate, &rig.parent, &rig.state).unwrap();
    let s2 = rig.step(P + 1, &[]);
    assert_eq!(s2.dividends.reserved(), 600_000, "rotation alone never changes a reserve");
    assert_eq!(held_by(&s2, addr(&treasury, 1)), 1_200_000, "rotation moves no funds");
    // A new offer settles into the NEW Treasury address.
    let offer = transfer(
        &rig.f,
        &owner,
        1,
        fund_offer,
        6_000,
        vec![Output { owner: addr(&next, 2), atoms: 590_000 }, Output { owner: addr(&owner, 1), atoms: 4_000 }],
    );
    rig.pool.admit(&offer, &rig.parent, &rig.state).unwrap();
    let s3 = rig.step(P + 2, &[]);
    assert_eq!(held_by(&s3, addr(&next, 2)), 590_000);
    // The old-generation coin, now authorized by the new key, cannot be spent below the reserve
    // even though both generations belong to the same Treasury authority.
    let drain = |keep: u64| {
        transfer(
            &rig.f,
            &next,
            2,
            old_coin.clone(),
            7_000,
            vec![
                Output { owner: dest, atoms: 1_200_000 - 7_000 - keep },
                Output { owner: addr(&treasury, 1), atoms: keep },
            ],
        )
    };
    // total Treasury backing after the spend = keep + 590_000 must stay >= 600_000
    let bad = drain(9_999);
    let good = drain(30_000);
    rig.pool.admit(&good, &rig.parent, &rig.state).unwrap();
    let prepared = rig
        .chain
        .prepare_pending(Preparation {
            expected_parent: &rig.parent,
            pool: &rig.pool,
            license: rig.f.license,
            worker: rig.f.worker,
            timestamp: at(P + 3),
            ticket: rig.ticket,
            operations: &[],
        })
        .unwrap();
    let (work_parent, _, _) = rig.chain.execution_parent(rig.height()).unwrap();
    let mut body = prepared.body.clone();
    body.transactions = vec![bad.encode().unwrap()];
    let mut candidate = prepared.candidate.clone();
    candidate.body_root = body.root().unwrap();
    assert!(
        rig.state
            .prepare_candidate_v2(CandidatePreparation {
                parent: &work_parent,
                candidate: &candidate,
                ticket_sequence: rig.ticket,
                body: &body,
            })
            .is_err(),
        "backing across both generations would fall below the reserve"
    );
    let s4 = rig.commit_prepared(prepared);
    assert_eq!(held_by(&s4, addr(&treasury, 1)), 30_000);
    assert_eq!(held_by(&s4, addr(&next, 2)), 590_000);
    // Claims still execute: oldest generation first, change stays at the old address.
    let s5 = rig.step(P + 4, &[claim_op(&rig.f, &owner, 4, P, 20_000, 0, dest)]);
    assert_eq!(held_by(&s5, addr(&treasury, 1)), 10_000);
    assert_eq!(held_by(&s5, addr(&next, 2)), 590_000);
    assert_eq!(held_by(&s5, dest), 1_200_000 - 7_000 - 30_000 + 20_000);
    assert_eq!(s5.dividends.reserved(), 580_000);
    // A claim larger than the oldest generation's remainder spans both generations; change
    // stays with the last coin's generation, so no value migrates between generations.
    let s6 = rig.step(P + 5, &[claim_op(&rig.f, &owner, 9, P, 50_000, 0, dest)]);
    assert_eq!(held_by(&s6, addr(&treasury, 1)), 0);
    assert_eq!(held_by(&s6, addr(&next, 2)), 590_000 - 40_000);
    assert_eq!(s6.dividends.reserved(), 530_000);
    // Restart keeps every outstanding reserve and both generations' coins.
    let before = rig.state.clone();
    let rig = rig.restart();
    assert_eq!(rig.state, before);
    rig.finish();
}

#[test]
fn fee_exemption_is_scoped_to_the_dedicated_claim_and_never_extends_to_other_transactions() {
    let treasury = treasury_key();
    let owner = owner_key();
    let payer = second_key();
    let dest = [0x79; 32];
    let mut f = fixture_with_treasury(&treasury, 1_200_000);
    f.state.coins.insert(
        OutPoint { transaction: [0xd2; 32], index: 0 },
        Coin { output: Output { owner: addr(&payer, 1), atoms: 100_000 }, created_height: 0, coinbase: false },
    );
    f.state.wallets.register(&desc(&payer, 1)).unwrap();
    let mut rig = Rig::new(f, "fees");
    rig.step(P, &[]);
    let point = OutPoint { transaction: [0xd2; 32], index: 0 };
    let pay = |rig: &Rig, fee: u64| {
        transfer(&rig.f, &payer, 1, point.clone(), fee, vec![Output { owner: dest, atoms: 100_000 - fee }])
    };
    // Ordinary transfers pay at least one atom per encoded byte (native_units: the byte-rate
    // minimum; the 240 STRIKES floor governs trading/value operations and is covered by the
    // trading suites). Below-minimum transfers are refused at admission.
    const FEE: u64 = 10_000;
    let len = pay(&rig, FEE).encode().unwrap().len() as u64;
    assert!(len > 2_000 && len < FEE, "fixture transfer size {len} keeps the test non-vacuous");
    let sub = len - 100;
    assert!(rig.pool.admit(&pay(&rig, 0), &rig.parent, &rig.state).is_err(), "fee 0 transfer");
    assert!(rig.pool.admit(&pay(&rig, sub), &rig.parent, &rig.state).is_err(), "sub-minimum fee transfer");
    // Control: a transfer paying the minimum is admitted and rides in the same block as a claim.
    let good = pay(&rig, FEE);
    rig.pool.admit(&good, &rig.parent, &rig.state).unwrap();
    let claim = claim_op(&rig.f, &owner, 0, P, 1_000, 0, dest);
    let prepared = rig
        .chain
        .prepare_pending(Preparation {
            expected_parent: &rig.parent,
            pool: &rig.pool,
            license: rig.f.license,
            worker: rig.f.worker,
            timestamp: at(P + 1),
            ticket: rig.ticket,
            operations: &[claim.clone()],
        })
        .unwrap();
    assert_eq!(prepared.body.transactions, vec![good.encode().unwrap()]);
    // The same block with a fee-0 or sub-floor transfer substituted fails full execution: the
    // claim in the batch does not exempt any other transaction from the floor.
    let (work_parent, _, _) = rig.chain.execution_parent(rig.height()).unwrap();
    for fee in [0u64, sub] {
        let mut body = prepared.body.clone();
        body.transactions = vec![pay(&rig, fee).encode().unwrap()];
        let mut candidate = prepared.candidate.clone();
        candidate.body_root = body.root().unwrap();
        let rejected = rig.state.prepare_candidate_v2(CandidatePreparation {
            parent: &work_parent,
            candidate: &candidate,
            ticket_sequence: rig.ticket,
            body: &body,
        });
        assert!(rejected.is_err(), "mixed batch with fee {fee} must be rejected: the claim exempts nothing else");
    }
    // Control commits: the miner is paid exactly the transfer fee; the claim added none and
    // charged none, and the claimant destination received exactly the authorized amount.
    let before = held_by(&rig.state, dest);
    let s = rig.commit_prepared(prepared);
    let reward: u64 = s.coins.values().filter(|c| c.coinbase && c.created_height == 2).map(|c| c.output.atoms).sum();
    assert_eq!(reward, SUBSIDY + FEE);
    assert_eq!(held_by(&s, dest), before + 1_000 + (100_000 - FEE));
    rig.finish();
}

#[test]
fn fixtures_refuse_production_class_state_and_are_not_a_status_setting_path() {
    let treasury = treasury_key();
    let mut production = DividendState::genesis(Treasury::new(Class::Production, desc(&treasury, 1)).unwrap());
    assert!(production.fixture_suspend(license(0), 5).is_err());
    assert!(production.fixture_revoke(license(0)).is_err());
    let mut none = DividendState::default();
    assert!(none.fixture_revoke(license(0)).is_err(), "no Treasury means no fixture authority");
}

#[test]
fn more_than_eight_partial_claims_then_exact_remainder_with_bounded_replay_state() {
    let treasury = treasury_key();
    let owner = owner_key();
    let dest = [0x7b; 32];
    let mut rig = Rig::new(fixture_with_treasury(&treasury, 1_200_000), "many-claims");
    let s1 = rig.step(P, &[]);
    let record_bytes = |s: &State| s.dividends.records().unwrap().values().map(Vec::len).sum::<usize>();
    let base = record_bytes(&s1);
    let one = claim_op(&rig.f, &owner, 0, P, 1_000, 0, dest);
    // Block capacity (body bytes and item limits) bounds a block; the number of claims per
    // License or per award is not bounded.
    let per_block = (40_000 / one.len()).clamp(1, 12);
    let mut sequence = 0u64;
    let mut epoch = P + 1;
    while sequence < 21 {
        let take = per_block.min((21 - sequence) as usize);
        let ops: Vec<Vec<u8>> = (0..take as u64).map(|i| claim_op(&rig.f, &owner, 0, P, 1_000, sequence + i, dest)).collect();
        let s = rig.step(epoch, &ops);
        sequence += take as u64;
        epoch += 1;
        let account = s.dividends.ledger().award(P).unwrap().account(&license(0)).unwrap();
        assert_eq!((account.claims, account.remaining), (sequence, 50_000 - 1_000 * sequence));
        assert!(record_bytes(&s) <= base + 16, "replay state is O(1) per account, not per claim");
    }
    assert!(sequence > 8, "more than eight successful partial claims");
    // The final claim takes exactly the remainder; it is not required to, but may.
    let last = claim_op(&rig.f, &owner, 0, P, 50_000 - 21_000, 21, dest);
    let s_last = rig.step(epoch, &[last]);
    let account = s_last.dividends.ledger().award(P).unwrap().account(&license(0)).unwrap();
    assert_eq!((account.claims, account.remaining), (22, 0));
    assert_eq!(held_by(&s_last, dest), 50_000);
    assert_eq!(s_last.dividends.reserved(), 550_000);
    // Replay of an earlier claim number and any further claim are rejected without effect.
    assert!(rig.try_step(epoch + 1, &[claim_op(&rig.f, &owner, 0, P, 1_000, 3, dest)]).is_err(), "replay");
    assert!(rig.try_step(epoch + 1, &[claim_op(&rig.f, &owner, 0, P, 1, 22, dest)]).is_err(), "nothing remains");
    assert_eq!(rig.state, s_last);
    // A claim number that skips ahead is not valid either.
    assert!(rig.try_step(epoch + 1, &[claim_op(&rig.f, &owner, 1, P, 10, 5, dest)]).is_err(), "sequence gap");
    // Restart keeps the counters.
    let before = rig.state.clone();
    let rig = rig.restart();
    assert_eq!(rig.state, before);
    rig.finish();
}

#[test]
fn forward_jumps_never_recreate_reopen_or_revise_and_claims_use_the_actual_epoch() {
    let treasury = treasury_key();
    let owner = owner_key();
    let dest = [0x7c; 32];
    let mut rig = Rig::new(fixture_with_treasury(&treasury, 1_200_000), "jumps");
    // D3 (3 Oct 2026): a block timestamp must not precede its parent's, so a block can no longer
    // carry a smaller epoch than its parent (before D3 only median-time-past applied and this test
    // exercised such regressions at block level). Regression handling is now covered at the state
    // level by `epoch_regression_never_revises_recreates_or_double_reserves_at_the_state_level`.
    for e in 1..=6 {
        rig.step(e, &[]);
    }
    // Forward jump across the first award boundary in one block.
    let s_jump = rig.step(P + 3, &[]);
    let award = s_jump.dividends.ledger().award(P).expect("award created by the forward jump").clone();
    assert_eq!(s_jump.dividends.reserved(), 600_000);
    let cursor = s_jump.dividends.ledger().cursor();
    assert!(cursor >= P);
    // Consensus now rejects any block that precedes its parent, with or without a claim. (Before
    // D3 these were accepted by the timestamp rule and judged by the dividend rules.)
    assert!(rig.try_step(P - 1, &[claim_op(&rig.f, &owner, 0, P, 100, 0, dest)]).is_err(), "regressing claim block");
    assert!(rig.try_step(P - 1, &[]).is_err(), "regressing block precedes its parent");
    assert!(rig.try_step(P + 2, &[]).is_err(), "one epoch behind the parent is rejected");
    // A valid claim in a block at the parent's own epoch (an equal timestamp is allowed) works
    // against the award; a completed claim cannot be undone.
    let s_claim = rig.step(P + 3, &[claim_op(&rig.f, &owner, 0, P, 100, 0, dest)]);
    assert_eq!(held_by(&s_claim, dest), 100);
    let s_after = rig.step(P + 3, &[]);
    assert_eq!(s_after.dividends.ledger().award(P).unwrap().account(&license(0)).unwrap().remaining, 49_900);
    assert_eq!(held_by(&s_after, dest), 100);
    assert_eq!(s_after.dividends.ledger().award(P).unwrap(), s_claim.dividends.ledger().award(P).unwrap());
    // Expiry: jump beyond the deadline. An entitlement that expired is not reopened by a later
    // claim, and the award is never recreated.
    let s_expired = rig.step(P + W + 1, &[]);
    assert!(s_expired.dividends.ledger().award(P).is_none());
    assert_eq!(s_expired.dividends.reserved(), 0);
    assert!(
        rig.try_step(P + W + 2, &[claim_op(&rig.f, &owner, 1, P, 100, 0, dest)]).is_err(),
        "an expired entitlement is not reopened"
    );
    let s_next = rig.step(P + W + 2, &[]);
    assert!(s_next.dividends.ledger().award(P).is_none());
    assert_eq!(s_next.dividends.reserved(), 0);
    assert_eq!(held_by(&s_next, dest), 100);
    rig.finish();
}
#[test]
fn epoch_regression_never_revises_recreates_or_double_reserves_at_the_state_level() {
    // D3 makes a regressing BLOCK impossible, but the dividend state machine must not depend on
    // that: given any lower epoch it processes nothing, never moves the cursor backward, never
    // revises or recreates an award and never double-reserves. This is the same invariant the
    // former block-level test checked, now asserted directly on the state transition.
    let treasury = treasury_key();
    let mut rig = Rig::new(fixture_with_treasury(&treasury, 1_200_000), "regress-state");
    for e in 1..=6 {
        rig.step(e, &[]);
    }
    let s_jump = rig.step(P + 3, &[]);
    let award = s_jump.dividends.ledger().award(P).expect("award created by the forward jump").clone();
    let cursor = s_jump.dividends.ledger().cursor();
    assert!(cursor >= P);
    for lower in [P + 2, P, P - 1, 1, 0] {
        let mut d = s_jump.dividends.clone();
        let events = d.advance(lower, 1_200_000, &[]).unwrap();
        assert!(events.is_empty(), "epoch {lower}: nothing new is processed");
        assert_eq!(d.ledger().award(P).unwrap(), &award, "epoch {lower}: snapshot not revised");
        assert_eq!(d.reserved(), 600_000, "epoch {lower}: not recreated or double-reserved");
        assert_eq!(d.ledger().cursor(), cursor, "epoch {lower}: cursor never moves backward");
        assert_eq!(d, s_jump.dividends, "epoch {lower}: state is unchanged");
    }
    let s_expired = rig.step(P + W + 1, &[]);
    let expired_cursor = s_expired.dividends.ledger().cursor();
    for lower in [P + W, P + W - 1, P, 0] {
        let mut d = s_expired.dividends.clone();
        let events = d.advance(lower, 1_200_000, &[]).unwrap();
        assert!(events.is_empty(), "epoch {lower}: nothing new is processed");
        assert!(d.ledger().award(P).is_none(), "epoch {lower}: expired award is not recreated");
        assert_eq!(d.reserved(), 0, "epoch {lower}: nothing re-reserved");
        assert_eq!(d.ledger().cursor(), expired_cursor, "epoch {lower}: cursor never moves backward");
        assert_eq!(d, s_expired.dividends, "epoch {lower}: state is unchanged");
    }
    rig.finish();
}

#[test]
fn treasury_membership_is_authenticated_and_unrelated_wallets_add_no_backing() {
    let treasury = treasury_key();
    let attacker = second_key();
    let owner = owner_key();
    let mut f = fixture_with_treasury(&treasury, 1_200_000);
    // An unrelated registered wallet holding a large balance, and a funding coin for a forged
    // rotation transaction.
    f.state.coins.insert(
        OutPoint { transaction: [0xd3; 32], index: 0 },
        Coin { output: Output { owner: addr(&attacker, 1), atoms: 5_000_000 }, created_height: 0, coinbase: false },
    );
    f.state.coins.insert(
        OutPoint { transaction: [0xd4; 32], index: 0 },
        Coin { output: Output { owner: addr(&owner, 1), atoms: 50_000 }, created_height: 0, coinbase: false },
    );
    f.state.wallets.register(&desc(&attacker, 1)).unwrap();
    let mut rig = Rig::new(f, "membership");
    // A forged Treasury rotation: the Treasury authority, but the current descriptor and both
    // signatures come from an unrelated key.
    let forged_tx = sponsored_rotation(
        &rig,
        addr(&treasury, 1),
        (&attacker, 1),
        (&owner, 2),
        &owner,
        OutPoint { transaction: [0xd4; 32], index: 0 },
        49_000,
        1_000,
    );
    assert!(
        matches!(
            rig.pool.admit(&forged_tx, &rig.parent, &rig.state),
            Err(mutiny_consensus_v8::mempool_v2::PoolError::Invalid(mutiny_consensus_v8::transactions::TxError::Owner))
        ),
        "forged Treasury rotation: the attacker's descriptor is not the Treasury's current one"
    );
    // Backing and shares count only the authenticated Treasury addresses.
    let s1 = rig.step(P, &[]);
    assert_eq!(s1.dividends.reserved(), 600_000, "5,000,000 held by an unrelated wallet adds no backing");
    assert_eq!(s1.dividends.ledger().award(P).unwrap().account(&license(0)).unwrap().share, 50_000);
    rig.finish();
}

fn walk_canonical_cbor(d: &mut minicbor::Decoder<'_>) {
    use minicbor::data::Type;
    match d.datatype().unwrap() {
        Type::Tag => panic!("CBOR semantic tags are prohibited by the encoding profile"),
        Type::ArrayIndef | Type::MapIndef | Type::BytesIndef | Type::StringIndef => panic!("indefinite length is prohibited"),
        Type::Array => {
            let n = d.array().unwrap().unwrap();
            for _ in 0..n {
                walk_canonical_cbor(d);
            }
        }
        Type::Map => {
            let n = d.map().unwrap().unwrap();
            for _ in 0..2 * n {
                walk_canonical_cbor(d);
            }
        }
        Type::F16 | Type::F32 | Type::F64 => panic!("floats are not used"),
        _ => d.skip().unwrap(),
    }
}

fn hx(b: &[u8]) -> String {
    hex::encode(b)
}

/// Dividend registry: numeric application identifiers, a mechanical collision check against the
/// lifecycle operation classifier and every populated state record, a scan proving no CBOR
/// semantic tags, and the cross-language vector set (positive and negative).
#[test]
fn registry_identifiers_are_unique_no_semantic_tags_and_vectors_round_trip() {
    use minicbor::{Decoder, Encoder};
    use mutiny_consensus_v8::{blocks::{operation_kind, state_root}, dividend_claim_v1::{OPERATION_KIND, is_claim}};
    let treasury = treasury_key();
    let owner = owner_key();
    let dest = [0x7d; 32];
    let mut f = fixture_with_treasury(&treasury, 1_200_000);
    f.state.fixture_advance_dividends(P).unwrap();
    f.state.dividends.fixture_suspend(license(0), P + 50).unwrap();
    f.state.dividends.fixture_revoke(license(1)).unwrap();
    let mut rig = Rig::new(f, "registry");
    let claim_raw = claim_op(&rig.f, &owner, 2, P, 100, 0, dest);
    let s = rig.step(P + 10, &[claim_raw.clone()]);
    let rows = s.records().unwrap();
    // 1. Operation kinds: the claim kind is not recognized by the lifecycle classifier for any
    // version or element count, and is_claim accepts no lifecycle shape.
    assert_eq!(OPERATION_KIND, 23);
    let mut lifecycle = std::collections::BTreeSet::new();
    for version in [1u8, 2] {
        for kind in 0u8..=255 {
            for count in 0u64..=20 {
                let mut e = Encoder::new(Vec::new());
                e.array(count).unwrap().u8(version).unwrap().u8(kind).unwrap();
                let raw = e.into_writer();
                if let Ok(k) = operation_kind(&raw) {
                    lifecycle.insert((version, k));
                    // The block-operation envelope classifier recognizes the claim class as kind 23
                    // (version 2, five elements) and nothing else beyond the lifecycle kinds.
                    if (version, k) == (2, OPERATION_KIND) {
                        assert_eq!(count, 5);
                        assert!(is_claim(&raw));
                    } else {
                        assert!(!is_claim(&raw), "a lifecycle shape must never classify as a claim");
                    }
                } else if is_claim(&raw) {
                    panic!("is_claim accepts a shape the envelope classifier rejects: {version} {kind} {count}");
                }
            }
        }
    }
    // Candidate 3 (Lane P design 2.2): the funded BondCreate class (2, 24) is recognized too, and
    // the retired kind 18 is not; neither collides with the claim class.
    assert!(
        lifecycle.iter().all(|(v, k)| (10..=22).contains(k)
            || (*v, *k) == (2, OPERATION_KIND)
            || (*v, *k) == (2, mutiny_consensus_v8::bond_create_v3::OPERATION_KIND)),
        "lifecycle kinds are within 10..=22, the claim class is only (2, 23) and the funded BondCreate class only (2, 24): {lifecycle:?}"
    );
    assert!(lifecycle.contains(&(2, 24)) && !lifecycle.contains(&(2, 18)));
    assert_eq!(lifecycle.iter().filter(|(_, k)| *k == OPERATION_KIND).count(), 1);
    // 2. Record identifiers: exactly one family owns each application tag, with the counts the
    // canonical state implies, and every record decodes with no semantic tag or indefinite item.
    let mut tags: std::collections::BTreeMap<u8, usize> = Default::default();
    for (_, raw) in &rows {
        walk_canonical_cbor(&mut Decoder::new(raw));
        let mut d = Decoder::new(raw);
        if d.array().ok().flatten().is_some() && d.u8().ok() == Some(2) {
            if let Ok(tag) = d.u8() {
                if (60..=63).contains(&tag) {
                    *tags.entry(tag).or_default() += 1;
                }
            }
        }
    }
    let live_awards = s.dividends.ledger().live_awards();
    assert_eq!(live_awards, 1);
    assert_eq!(tags, [(60u8, 1usize), (61, 2), (62, 1), (63, live_awards)].into_iter().collect(), "tags 60..=63 are used only by their own records");
    walk_canonical_cbor(&mut Decoder::new(&claim_raw));
    let claim = SignedClaim::decode(&claim_raw).unwrap();
    walk_canonical_cbor(&mut Decoder::new(&claim.body.encode()));
    walk_canonical_cbor(&mut Decoder::new(&claim.signing_payload()));
    // 3. Vectors. Positives: the exact bytes; negatives: mutations that must each be rejected.
    let by_tag = |tag: u8| -> Vec<(Hash, Vec<u8>)> {
        rows.iter()
            .filter(|(_, raw)| {
                let mut d = Decoder::new(raw);
                d.array().ok().flatten().is_some() && d.u8().ok() == Some(2) && d.u8().ok() == Some(tag)
            })
            .cloned()
            .collect()
    };
    let reject_record = |key: Hash, mutated: Vec<u8>| -> bool {
        let mut next: Vec<(Hash, Vec<u8>)> = rows.iter().filter(|(k, _)| *k != key).cloned().collect();
        next.push((key, mutated));
        next.sort();
        match state_root(&next) {
            Ok(root) => State::from_records(&next, root).is_err(),
            Err(_) => true,
        }
    };
    let (award_key, award_raw) = by_tag(63).remove(0);
    let (header_key, header_raw) = by_tag(62).remove(0);
    let (treasury_key_id, treasury_raw) = by_tag(60).remove(0);
    let status_rows = by_tag(61);
    let award = s.dividends.ledger().award(P).unwrap().clone();
    let accounts: Vec<(Hash, mutiny_consensus_v8::dividends_v1::Account)> =
        award.accounts_iter().map(|(l, a)| (*l, *a)).collect();
    let build_award = |tag: u8, version: u8, accounts: &[(Hash, u64, u64, u64)]| -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(4).unwrap().u8(version).unwrap().u8(tag).unwrap().u64(award.epoch()).unwrap().array(accounts.len() as u64).unwrap();
        for (l, share, remaining, claims) in accounts {
            e.array(4).unwrap().bytes(l).unwrap().u64(*share).unwrap().u64(*remaining).unwrap().u64(*claims).unwrap();
        }
        e.into_writer()
    };
    let base: Vec<(Hash, u64, u64, u64)> = accounts.iter().map(|(l, a)| (*l, a.share, a.remaining, a.claims)).collect();
    assert_eq!(build_award(63, 2, &base), award_raw, "independent builder reproduces the canonical award record");
    let mut negatives: Vec<(String, String, Vec<u8>)> = Vec::new(); // (name, family, bytes)
    let mut swapped = base.clone();
    swapped.swap(0, 1);
    negatives.push(("award-accounts-not-ascending".into(), "award".into(), build_award(63, 2, &swapped)));
    let mut dup = base.clone();
    dup[1] = dup[0];
    negatives.push(("award-duplicate-license".into(), "award".into(), build_award(63, 2, &dup)));
    let mut inconsistent = base.clone();
    let paid_idx = base.iter().position(|a| a.3 > 0).unwrap();
    inconsistent[paid_idx].3 = 0; // paid > 0 but claims == 0
    negatives.push(("award-paid-without-claims".into(), "award".into(), build_award(63, 2, &inconsistent)));
    let mut ghost = base.clone();
    let unpaid_idx = base.iter().position(|a| a.3 == 0).unwrap();
    ghost[unpaid_idx].3 = 1; // claims > 0 but nothing paid
    negatives.push(("award-claims-without-payment".into(), "award".into(), build_award(63, 2, &ghost)));
    let mut over = base.clone();
    over[0].2 = over[0].1 + 1;
    negatives.push(("award-remaining-exceeds-share".into(), "award".into(), build_award(63, 2, &over)));
    negatives.push(("award-wrong-tag".into(), "award".into(), build_award(64, 2, &base)));
    negatives.push(("award-wrong-version".into(), "award".into(), build_award(63, 3, &base)));
    let mut trailing = award_raw.clone();
    trailing.push(0);
    negatives.push(("award-trailing-byte".into(), "award".into(), trailing));
    let header_with = |reserved: u64, cursor: u64| -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(4).unwrap().u8(2).unwrap().u8(62).unwrap().u64(reserved).unwrap().u64(cursor).unwrap();
        e.into_writer()
    };
    let (reserved_now, cursor_now) = (s.dividends.reserved(), s.dividends.ledger().cursor());
    assert_eq!(header_with(reserved_now, cursor_now), header_raw, "independent builder reproduces the header record");
    negatives.push(("header-reserve-differs-from-awards".into(), "header".into(), header_with(reserved_now + 1, cursor_now)));
    negatives.push(("header-cursor-before-live-award".into(), "header".into(), header_with(reserved_now, P - 1)));
    let mut treasury_bad = treasury_raw.clone();
    let last = treasury_bad.len() - 1;
    treasury_bad[last] ^= 1;
    negatives.push(("treasury-altered".into(), "treasury".into(), treasury_bad));
    for (name, family, raw) in &negatives {
        let key = match family.as_str() {
            "award" => award_key,
            "header" => header_key,
            _ => treasury_key_id,
        };
        assert!(reject_record(key, raw.clone()), "negative vector {name} must be rejected");
    }
    // Claim negatives.
    let claim_negatives: Vec<(String, Vec<u8>)> = {
        let mut v = Vec::new();
        let mut t = claim_raw.clone();
        t.push(0);
        v.push(("claim-trailing-byte".to_string(), t));
        let mut k = claim_raw.clone();
        k[2] = 22;
        v.push(("claim-wrong-kind".to_string(), k));
        let mut ver = claim_raw.clone();
        ver[1] = 1;
        v.push(("claim-wrong-version".to_string(), ver));
        let body = claim.body.encode();
        let mut padded = body.clone();
        *padded.last_mut().unwrap() = 0x18; // sequence 0 as a non-minimal two-byte integer
        padded.push(0);
        let mut e = Encoder::new(Vec::new());
        e.array(5).unwrap().u8(2).unwrap().u8(23).unwrap().bytes(&padded).unwrap().bytes(&claim.descriptor).unwrap();
        let mut sig = claim.signature.ed448.to_vec();
        sig.extend_from_slice(&claim.signature.fndsa);
        e.bytes(&sig).unwrap();
        v.push(("claim-non-minimal-integer".to_string(), e.into_writer()));
        let mut short = Encoder::new(Vec::new());
        short.array(5).unwrap().u8(2).unwrap().u8(23).unwrap().bytes(&body).unwrap().bytes(&claim.descriptor).unwrap().bytes(&sig[..sig.len() - 1]).unwrap();
        v.push(("claim-short-signature".to_string(), short.into_writer()));
        let mut indef = claim_raw.clone();
        indef[0] = 0x9f;
        v.push(("claim-indefinite-array".to_string(), indef));
        v
    };
    for (name, raw) in &claim_negatives {
        assert!(SignedClaim::decode(raw).is_err(), "negative vector {name} must be rejected");
    }
    // Emit the machine-readable vector file when a directory is supplied.
    if let Some(dir) = std::env::var_os("NATIVE_DIVIDEND_VECTOR_DIR") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        let q = |s: &str| format!("\"{s}\"");
        let mut out = String::from("{\n");
        out += "\"schema\": \"mutiny-dividend-vectors-v1\",\n\"evidence_class\": \"TEST-VALUE native vectors; not a production identity\",\n";
        out += "\"registry\": {\"record_version\": 2, \"treasury\": 60, \"license_status\": 61, \"ledger_header\": 62, \"award\": 63, \"claim_operation\": {\"version\": 2, \"kind\": 23, \"array\": 5}, \"cbor_semantic_tags\": \"prohibited\", \"lifecycle_operation_kinds\": \"10..=22\"},\n";
        out += &format!("\"claim_id_domain\": {},\n\"claim_intent_label\": {},\n", q("MUTINY-BUILD8-DIVIDEND-CLAIM-ID-V1"), q("MUTINY-BUILD8-DIVIDEND-CLAIM-INTENT-V1"));
        out += &format!(
            "\"claim\": {{\"operation_hex\": {}, \"body_hex\": {}, \"preimage_hex\": {}, \"claim_id_hex\": {}, \"descriptor_hex\": {}, \"fields\": {{\"network\": {}, \"genesis\": {}, \"fingerprint\": {}, \"created_height\": {}, \"expiry_height\": {}, \"award_epoch\": {}, \"license\": {}, \"amount\": {}, \"destination\": {}, \"sequence\": {}}}}},\n",
            q(&hx(&claim_raw)), q(&hx(&claim.body.encode())), q(&hx(&claim.signing_payload())), q(&hx(&claim.id())), q(&hx(&claim.descriptor)),
            claim.body.network, q(&hx(&claim.body.genesis)), q(&hx(&claim.body.fingerprint)), claim.body.created_height, claim.body.expiry_height,
            claim.body.award_epoch, q(&hx(&claim.body.license)), claim.body.amount, q(&hx(&claim.body.destination)), claim.body.sequence
        );
        // Public state context, taken from the live State and from the key (NOT from the record bytes
        // under test), so an independent verifier can judge the cross-record negatives.
        out += &format!(
            "\"public_context\": {{\"treasury_authority_address\": {}, \"address_domain\": {}, \"reserved\": {}, \"cursor\": {}, \"live_award_epochs\": [{}], \"award_period_epochs\": {}}},\n",
            q(&hx(&addr(&treasury, 1))), q("MUTINY-BUILD8-HYBRID-ADDRESS-V1"), reserved_now, cursor_now, award.epoch(), P
        );
        let mut records = Vec::new();
        records.push(format!("{{\"name\": \"treasury\", \"tag\": 60, \"key_hex\": {}, \"hex\": {}}}", q(&hx(&treasury_key_id)), q(&hx(&treasury_raw))));
        for (k, raw) in &status_rows {
            records.push(format!("{{\"name\": \"license_status\", \"tag\": 61, \"key_hex\": {}, \"hex\": {}}}", q(&hx(k)), q(&hx(raw))));
        }
        records.push(format!("{{\"name\": \"ledger_header\", \"tag\": 62, \"key_hex\": {}, \"hex\": {}}}", q(&hx(&header_key)), q(&hx(&header_raw))));
        records.push(format!("{{\"name\": \"award\", \"tag\": 63, \"key_hex\": {}, \"hex\": {}, \"epoch\": {}}}", q(&hx(&award_key)), q(&hx(&award_raw)), award.epoch()));
        out += &format!("\"records\": [\n{}\n],\n", records.join(",\n"));
        let mut neg: Vec<String> = negatives
            .iter()
            .map(|(n, fam, raw)| format!("{{\"name\": {}, \"family\": {}, \"hex\": {}, \"expect\": \"reject\"}}", q(n), q(fam), q(&hx(raw))))
            .collect();
        neg.extend(claim_negatives.iter().map(|(n, raw)| format!("{{\"name\": {}, \"family\": \"claim\", \"hex\": {}, \"expect\": \"reject\"}}", q(n), q(&hx(raw)))));
        out += &format!("\"negative\": [\n{}\n]\n}}\n", neg.join(",\n"));
        std::fs::write(dir.join("dividend-vectors-v1.json"), out).unwrap();
    }
    rig.finish();
}

#[test]
fn conflicting_finalized_block_retains_both_proofs_halts_durably_and_never_switches_chain() {
    let mut rig = Rig::new(fixture(), "conflict");
    rig.step(1, &[]);
    assert_eq!(rig.height(), 1);
    let build = |rig: &Rig, epoch: u64| {
        rig.chain
            .prepare_pending(Preparation {
                expected_parent: &rig.parent,
                pool: &rig.pool,
                license: rig.f.license,
                worker: rig.f.worker,
                timestamp: at(epoch),
                ticket: rig.ticket,
                operations: &[],
            })
            .unwrap()
    };
    let first = certify_at(build(&rig, 2), &rig.f, &rig.parent, &rig.state, rig.ticket);
    let rival = certify_at(build(&rig, 3), &rig.f, &rig.parent, &rig.state, rig.ticket);
    let forged_source = certify_at(build(&rig, 4), &rig.f, &rig.parent, &rig.state, rig.ticket);
    assert_ne!(first.block_hash(), rival.block_hash());
    // Signature validation is not bypassed: a corrupted vote is refused, stores no evidence
    // and does not halt the chain.
    let mut forged = forged_source.clone();
    forged.certificate.votes[0].signature.ed448[0] ^= 1;
    let error = rig.chain.commit(&forged).unwrap_err();
    assert!(!format!("{error:?}").contains("Halted"), "forged vote must fail verification, not halt: {error:?}");
    assert!(!rig.chain.halted().unwrap());
    // The first fully valid block at height 2 is finalized normally.
    assert!(rig.chain.commit(&first).unwrap());
    // A second fully valid, certified block at the same height is a durable fault.
    let error = rig.chain.commit(&rival).unwrap_err();
    assert!(format!("{error:?}").contains("Halted"), "{error:?}");
    assert!(rig.chain.halted().unwrap());
    // Restart: reopen the durable store from the same trusted Genesis. The halt persists and
    // nothing can extend, repeat or replace the finalized history.
    let Rig { f, base, chain, pool, initial, initial_root, .. } = rig;
    drop(chain);
    drop(pool);
    {
        let mut chain = CanonicalStore::open_trusted_genesis(&base.join("chain.sqlite"), &f.genesis, &initial, initial_root, T0, [255; 32]).unwrap();
        assert!(chain.halted().unwrap(), "halt is durable across restart");
        assert!(chain.commit(&rival).is_err());
        assert!(chain.commit(&first).is_err(), "halted store accepts nothing, not even a repeat");
    }
    // Both authenticated proofs are retained in the durable evidence store.
    {
        let store = mutiny_consensus_v8::finality_v2::FinalityEvidenceStore::open(&base.join("chain.sqlite"), &f.genesis).unwrap();
        assert!(store.halted().unwrap());
        assert_eq!(store.evidence(2, first.block_hash()).unwrap().unwrap(), first);
        assert_eq!(store.evidence(2, rival.block_hash()).unwrap().unwrap(), rival);
        assert!(store.evidence(2, forged_source.block_hash()).unwrap().is_none());
        assert_eq!(store.anchor(2).unwrap().unwrap(), first.certificate.decision.anchor());
    }
    assert!(base.starts_with(std::env::temp_dir()));
    std::fs::remove_dir_all(base).unwrap();
}
