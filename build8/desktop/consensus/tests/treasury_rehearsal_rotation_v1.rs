#![cfg(feature = "dividend-test-fixtures")]
#![allow(dead_code, unused_imports)]
//! D2 Treasury ceremony REHEARSAL, rotation harness: the native Treasury wallet-authority
//! rotation, generation 1 -> 2, on a NON-production test chain (SIMULATED / TEST-VALUE).
//!
//! The Treasury is a TEST-VALUE record built from the rehearsal credential K1 and the rotation
//! proposes the separate rehearsal credential K2 stamped generation 2. Every block is prepared by
//! the production assembler, certified with real hybrid votes and installed by the canonical store
//! (shared rig: tests/support/dividend_rig.rs, extracted verbatim from dividends_v1.rs).
//!
//! Exercised: reserves preserved through rotation, historical (old-generation) destinations still
//! settle and are authorized by the new key only, the old key loses spend authority, an already
//! signed claim and the award deadline are unaffected, stale/duplicate rotation retries are
//! rejected without effect, an uncommitted preparation and a dropped-and-reopened store leave no
//! trace, and a proof of control of K2 verifies against the post-rotation descriptor read from
//! canonical state. Frozen trade offers belong to the trading candidate, which this harness does
//! not depend on: see docs/TREASURY-REHEARSAL-TOOLING-V1.md.
#[path = "../../desktop/src/wallet_host_fixture_licenses.rs"]
mod licenses;
#[path = "support/wallet_host_fixture_tpm.rs"]
mod tpm;
include!("support/dividend_rig.rs");

use crate::{
    treasury_admission_v1::AdmissionStore,
    treasury_rehearsal_v1::{self as rehearsal, CeremonyConfig, Denylist, Expect, Refusal},
};
use mutiny_crypto_v2::{PublicKey, rehearsal_keys_v1::Credential, treasury_proof_v1 as proof};

/// The Treasury wallet-authority rotation as a funded bundle (tag 25), explicitly sponsored by the
/// owner's coin `fund` (Order P2: reviewed sponsorship; the Treasury itself moves no value).
fn rotation_tx(rig: &Rig, authority: Hash, from: &HybridKey, from_generation: u64, to: &HybridKey, to_generation: u64, fund: OutPoint) -> Transaction {
    sponsored_rotation(rig, authority, (from, from_generation), (to, to_generation), &owner_key(), fund, 39_000, 1_000)
}
/// Run a block body that must fail full execution (the assembler would never build it).
fn must_fail_execution(rig: &Rig, prepared: &mutiny_consensus_v8::assembler_v2::Prepared, transactions: Vec<Vec<u8>>) -> bool {
    let (work_parent, _, _) = rig.chain.execution_parent(rig.height()).unwrap();
    let mut body = prepared.body.clone();
    body.transactions = transactions;
    let mut candidate = prepared.candidate.clone();
    candidate.body_root = body.root().unwrap();
    rig.state
        .prepare_candidate_v2(CandidatePreparation { parent: &work_parent, candidate: &candidate, ticket_sequence: rig.ticket, body: &body })
        .is_err()
}

#[test]
fn treasury_rotation_rehearsal_gen1_to_gen2_with_preserved_reserves_restart_and_retry() {
    let k1 = Credential::from_label("d2-rot-k1", 1).unwrap();
    let k2 = Credential::from_label("d2-rot-k2", 2).unwrap();
    let k3 = Credential::from_label("d2-rot-k3", 2).unwrap();
    let (treasury_key, next, stranger) = (k1.key(), k2.key(), k3.key());
    assert_ne!(treasury_key.public(), next.public(), "K2 is an independent credential");
    let owner = owner_key();
    let dest = [0x7d; 32];

    // ---- TEST-VALUE Treasury record from the rehearsal key; a proof of control binds it.
    let record = Treasury::new(Class::TestValue, desc(treasury_key, 1)).unwrap();
    assert_eq!(record.class(), Class::TestValue);
    let config = CeremonyConfig::rehearsal(mutiny_crypto_v2::NETWORK, record.clone(), "d2-rehearsal-rotation-2026").unwrap();
    let nonce1 = [0x51; 32];
    let challenge1 = rehearsal::build_challenge(&config, &desc(treasury_key, 1), nonce1).unwrap();
    let sig1 = proof::sign_challenge(treasury_key, &desc(treasury_key, 1), &challenge1).unwrap();
    let mut store = AdmissionStore::in_memory(&config).unwrap();
    store
        .admit(&Expect::genesis_key(&config), &desc(treasury_key, 1), &challenge1.encode().unwrap(), &sig1, &Denylist::default())
        .expect("K1 proves control of the Treasury descriptor before the rotation");

    // ---- Non-production chain: TEST-VALUE Treasury (genesis state) with funded old generation.
    let mut f = fixture_with_treasury(treasury_key, 1_200_000);
    assert!(f.state.dividends.treasury().is_some_and(|t| t.class() == Class::TestValue));
    for (n, atoms) in [(0xe1u8, 40_000u64), (0xe2, 600_000), (0xe3, 40_000), (0xe4, 40_000)] {
        f.state.coins.insert(
            OutPoint { transaction: [n; 32], index: 0 },
            Coin { output: Output { owner: addr(&owner, 1), atoms }, created_height: 0, coinbase: false },
        );
    }
    let (fund_rotation, fund_offer, fund_stale, fund_dup) = (
        OutPoint { transaction: [0xe1; 32], index: 0 },
        OutPoint { transaction: [0xe2; 32], index: 0 },
        OutPoint { transaction: [0xe3; 32], index: 0 },
        OutPoint { transaction: [0xe4; 32], index: 0 },
    );
    let mut rig = Rig::new(f, "d2-rotation");
    let s1 = rig.step(P, &[]);
    let reserved = s1.dividends.reserved();
    assert_eq!(reserved, 600_000);
    let award_deadline = s1.dividends.ledger().award(P).unwrap().deadline();
    assert_eq!(award_deadline, P + W);
    let old_coin = s1.coins.iter().find(|(_, c)| c.output.owner == addr(treasury_key, 1)).map(|(p, _)| p.clone()).unwrap();
    // A claim signed BEFORE the rotation (frozen destination and amount) must survive it.
    let early_claim = claim_op(&rig.f, &owner, 3, P, 10_000, 0, dest);

    // ---- Rotation admitted, then an uncommitted preparation and a dropped-and-reopened store.
    let rotate = rotation_tx(&rig, addr(treasury_key, 1), treasury_key, 1, next, 2, fund_rotation.clone());
    rig.pool.admit(&rotate, &rig.parent, &rig.state).unwrap();
    assert_eq!(rig.pool.pending().unwrap().len(), 1);
    let prepared = rig
        .chain
        .prepare_pending(Preparation { expected_parent: &rig.parent, pool: &rig.pool, license: rig.f.license, worker: rig.f.worker, timestamp: at(P + 1), ticket: rig.ticket, operations: &[] })
        .unwrap();
    assert_eq!(prepared.body.transactions.len(), 1, "the rotation is in the prepared block");
    drop(prepared); // simulated crash before commit: nothing durable
    let before_restart = rig.state.clone();
    let mut rig = rig.restart();
    assert_eq!(rig.state, before_restart, "reopened store equals the pre-rotation state");
    assert_eq!(rig.height(), 1);
    assert_eq!(rig.state.wallets.current(addr(treasury_key, 1)).unwrap(), desc(treasury_key, 1).as_slice(), "no rotation was applied");
    // Retry: the pool either kept the rotation or the operator re-admits it; never twice.
    if rig.pool.pending().unwrap().is_empty() {
        rig.pool.admit(&rotate, &rig.parent, &rig.state).unwrap();
    } else {
        let _ = rig.pool.admit(&rotate, &rig.parent, &rig.state);
    }
    assert_eq!(rig.pool.pending().unwrap().len(), 1, "exactly one pending rotation");

    // ---- Rotation executes through canonical block execution.
    let s2 = rig.step(P + 1, &[]);
    assert_eq!(s2.wallets.current(addr(treasury_key, 1)).unwrap(), desc(next, 2).as_slice(), "K2 is now the Treasury authority's current key");
    assert_eq!(s2.dividends.reserved(), reserved, "rotation alone never changes a reserve");
    assert_eq!(held_by(&s2, addr(treasury_key, 1)), 1_200_000, "rotation moves no funds");
    assert_eq!(s2.dividends.ledger().award(P).unwrap().deadline(), award_deadline, "the award deadline is unchanged");
    assert_eq!(s2.dividends.treasury().unwrap().class(), Class::TestValue);
    assert_eq!(s2.dividends.treasury().unwrap().descriptor(), desc(treasury_key, 1).as_slice(), "the Genesis record never changes");

    // ---- Retry and stale attempts after the rotation are rejected without any effect.
    // The pool is idempotent per transaction id: re-submitting the applied rotation reports its
    // recorded lifecycle status and never re-queues it.
    let replay = rig.pool.admit(&rotate, &rig.parent, &rig.state);
    assert!(replay.as_ref().map_or(true, |status| format!("{status:?}") != "Pending"), "replay of the applied rotation must not be pending: {replay:?}");
    let stale = rotation_tx(&rig, addr(treasury_key, 1), treasury_key, 1, stranger, 2, fund_stale.clone());
    assert!(rig.pool.admit(&stale, &rig.parent, &rig.state).is_err(), "rotation authorized by the retired K1");
    // A proposal that does not advance the generation by exactly one cannot even be signed: the
    // bundle codec refuses it before any signing intent exists.
    let Transaction::FundedRotation(stale_bundle) = &stale else { unreachable!() };
    let mut same_generation = stale_bundle.unsigned.clone();
    same_generation.current_descriptor = desc(next, 2);
    same_generation.proposed_descriptor = desc(stranger, 2);
    assert_eq!(
        mutiny_consensus_v8::funded_rotation_v2::signing_intents(&same_generation),
        Err(mutiny_consensus_v8::transactions::TxError::Owner)
    );
    let _ = &fund_dup;
    assert!(rig.pool.pending().unwrap().is_empty());
    assert_eq!(rig.state, s2);

    // ---- The retired K1 can no longer spend the old-generation coin; K2 can.
    let spend = |rig: &Rig, signer: &HybridKey, generation: u64, keep: u64| {
        transfer(
            &rig.f,
            signer,
            generation,
            old_coin.clone(),
            7_000,
            vec![Output { owner: dest, atoms: 1_200_000 - 7_000 - keep }, Output { owner: addr(treasury_key, 1), atoms: keep }],
        )
    };
    assert!(rig.pool.admit(&spend(&rig, treasury_key, 1, 600_000), &rig.parent, &rig.state).is_err(), "old key no longer authorizes the old address");

    // ---- Historical destination: the old address still receives value, and a new offer settles
    //      into the new address.
    let to_old = transfer(&rig.f, &owner, 1, fund_offer, 6_000, vec![Output { owner: addr(treasury_key, 1), atoms: 300_000 }, Output { owner: addr(next, 2), atoms: 290_000 }, Output { owner: addr(&owner, 1), atoms: 4_000 }]);
    rig.pool.admit(&to_old, &rig.parent, &rig.state).unwrap();
    let s3 = rig.step(P + 2, &[]);
    assert_eq!(held_by(&s3, addr(treasury_key, 1)), 1_500_000, "the historical generation address still settles");
    assert_eq!(held_by(&s3, addr(next, 2)), 290_000);

    // ---- Reserve floor holds across both generations: backing = old + new >= reserved.
    // total backing after the spend = keep + 290_000 + 300_000 retained below must stay >= 600_000
    // The old coin holds 1_200_000; the extra 300_000 arrived in a separate coin. Spending the old
    // coin and keeping X leaves total backing X + 300_000 + 290_000.
    let drain = |rig: &Rig, keep: u64| spend(rig, next, 2, keep);
    let below = drain(&rig, 9_999); // 9_999 + 590_000 = 599_999 < 600_000
    let above = drain(&rig, 10_000); // exactly the reserve
    rig.pool.admit(&above, &rig.parent, &rig.state).unwrap();
    let prepared = rig
        .chain
        .prepare_pending(Preparation { expected_parent: &rig.parent, pool: &rig.pool, license: rig.f.license, worker: rig.f.worker, timestamp: at(P + 3), ticket: rig.ticket, operations: &[] })
        .unwrap();
    assert_eq!(prepared.body.transactions, vec![above.encode().unwrap()]);
    assert!(must_fail_execution(&rig, &prepared, vec![below.encode().unwrap()]), "backing across both generations would fall below the reserve");
    let s4 = rig.commit_prepared(prepared);
    assert_eq!(held_by(&s4, addr(treasury_key, 1)), 10_000 + 300_000);
    assert_eq!(held_by(&s4, addr(next, 2)), 290_000);
    assert_eq!(s4.dividends.reserved(), reserved, "reserve unchanged by the spend");

    // ---- The claim signed before the rotation is still valid after it, drawing from the
    //      historical generation first; the destination was frozen in the claim.
    let s5 = rig.step(P + 4, &[early_claim.clone()]);
    assert_eq!(held_by(&s5, dest), 1_200_000 - 7_000 - 10_000 + 10_000);
    assert_eq!(s5.dividends.reserved(), reserved - 10_000);
    assert_eq!(held_by(&s5, addr(next, 2)), 290_000, "oldest generation settles first");
    assert!(rig.try_step(P + 5, &[early_claim]).is_err(), "claim replay");

    // ---- Dropped-and-reopened store after the rotation: identical state, claims continue.
    let before = rig.state.clone();
    let mut rig = rig.restart();
    assert_eq!(rig.state, before);
    assert_eq!(rig.state.records().unwrap(), before.records().unwrap());
    assert_eq!(rig.state.wallets.current(addr(treasury_key, 1)).unwrap(), desc(next, 2).as_slice());
    assert_eq!(rig.state.dividends.reserved(), reserved - 10_000);
    let s6 = rig.step(P + 6, &[claim_op(&rig.f, &owner, 4, P, 20_000, 0, dest)]);
    assert_eq!(s6.dividends.reserved(), reserved - 30_000);
    let rows = s6.records().unwrap();
    assert_eq!(State::from_records(&rows, s6.root().unwrap()).unwrap(), s6, "state reloads from canonical records");

    // ---- A11: K2 proves control against the post-rotation descriptor read from canonical state. The
    //      canonical lineage (never the proof) names the successor: the stranger K3, also a
    //      generation-2 key, signing the Treasury's public identifiers is refused.
    let current = s6.wallets.current(addr(treasury_key, 1)).unwrap().to_vec();
    assert_eq!(current, desc(next, 2));
    // The lineage is authenticated: the records must reproduce the trusted StateRoot (here the root the
    // executed chain committed), and a state whose records do not reproduce it establishes nothing.
    let trusted = config.clone().with_canonical_root(s6.root().unwrap()).unwrap();
    let canonical = Expect::canonical_current(&trusted, &rows).unwrap();
    assert_eq!(canonical.generation(), 2);
    let mut stale = config.clone().with_canonical_root(before.root().unwrap()).unwrap();
    assert_eq!(Expect::canonical_current(&stale, &rows), Err(Refusal::SuccessionUnproven), "records of another root");
    stale = config.clone();
    assert_eq!(Expect::canonical_current(&stale, &rows), Err(Refusal::SuccessionUnproven), "no trusted root");
    let challenge2 = rehearsal::build_challenge(&config, &current, [0x52; 32]).unwrap();
    let sig2 = proof::sign_challenge(next, &current, &challenge2).unwrap();
    store
        .admit(&canonical, &current, &challenge2.encode().unwrap(), &sig2, &Denylist::default())
        .expect("K2 proves control of the post-rotation descriptor");
    let impostor = rehearsal::build_challenge(&config, &desc(stranger, 2), [0x53; 32]).unwrap();
    let sig3 = proof::sign_challenge(stranger, &desc(stranger, 2), &impostor).unwrap();
    assert_eq!(
        store.admit(&canonical, &desc(stranger, 2), &impostor.encode().unwrap(), &sig3, &Denylist::default()),
        Err(Refusal::UnauthorizedSuccessor),
        "an impostor generation-2 key is not the canonical successor"
    );
    // K1's proof is not a proof of the rotated key, and the replayed challenge is refused.
    assert_eq!(
        store.admit(&canonical, &current, &challenge1.encode().unwrap(), &sig1, &Denylist::default()),
        Err(Refusal::Proof(proof::ProofError::WrongKeyVersion))
    );
    assert_eq!(store.admit(&canonical, &current, &challenge2.encode().unwrap(), &sig2, &Denylist::default()), Err(Refusal::Replay), "replay");
    rig.finish();
}

#[test]
fn rehearsal_credentials_are_independent_test_value_keys_and_the_rotation_needs_both_possessions() {
    let k1 = Credential::from_label("d2-rot-k1", 1).unwrap();
    let k2 = Credential::from_label("d2-rot-k2", 2).unwrap();
    let k3 = Credential::from_label("d2-rot-k3", 2).unwrap();
    // Distinct keys, distinct stamps, none is a public fixture key.
    assert_ne!(k1.key_sha256(), k2.key_sha256());
    assert_ne!(k2.key_sha256(), k3.key_sha256());
    assert_eq!(PublicKey::decode_descriptor(&k1.descriptor().unwrap()).unwrap().1, 1);
    assert_eq!(PublicKey::decode_descriptor(&k2.descriptor().unwrap()).unwrap().1, 2);
    for fixture in [owner_key(), treasury_key(), second_key()] {
        assert_ne!(fixture.public(), k1.key().public());
        assert_ne!(fixture.public(), k2.key().public());
    }
    // A rotation to the same key (re-stamped generation 2) is refused at signing: a new key is required.
    let mut same = Rotation {
        network: NETWORK_ID,
        genesis: [1; 32],
        fingerprint: [2; 32],
        authority: addr(k1.key(), 1),
        current: desc(k1.key(), 1),
        proposed: desc(k1.key(), 2),
        created_height: 1,
        expiry_height: 100,
        authorization: empty(),
        possession: empty(),
    };
    assert!(same.sign(k1.key(), k1.key()).is_err());
    // Possession by the wrong new key is refused: K3 cannot sign for a K2 proposal.
    let mut wrong = Rotation { proposed: desc(k2.key(), 2), ..same.clone() };
    assert!(wrong.sign(k1.key(), k3.key()).is_err());
    assert!(wrong.sign(k1.key(), k2.key()).is_ok());
}

// Historical V1/V2 software model only. Superseded unrestricted admission is
// compiled in this test crate, never exported by the shipping library graph.
// Only paths required by the isolated frozen model are supplied here.
pub use mutiny_consensus_v8::{domain_hash, blocks, execution, genesis_inputs, protocol_manifest, treasury_v1, wallet_rotation_v1, dividend_state_v1};
#[path = "../src/treasury_rehearsal_v1.rs"]
mod treasury_rehearsal_v1;
#[path = "../src/treasury_admission_v1.rs"]
mod treasury_admission_v1;
