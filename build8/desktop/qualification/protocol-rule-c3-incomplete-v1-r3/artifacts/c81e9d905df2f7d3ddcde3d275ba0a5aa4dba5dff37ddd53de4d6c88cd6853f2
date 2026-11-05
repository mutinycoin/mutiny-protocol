//! Real-block tests of the operation-envelope History plumbing (P-LANE-DESIGN-V1 section 1.a.3, test
//! T6 of section 14.4 and amendment AM-4 of P-LANE-DESIGN-AMENDMENTS-V1; work package WP-P0). Every
//! block is prepared by the production assembler (`CanonicalStore::prepare_pending`) or, for a block
//! the assembler would refuse, crafted from a prepared candidate; it is certified with real hybrid
//! votes and installed by `CanonicalStore::commit`, which re-executes it; `restart` closes the store
//! and reopens it, which re-executes the whole chain in `verify_replay`. The envelope is carried by
//! the TEST-ONLY carrier `[2, 254, Envelope]` (`op_envelope_v1::carrier`), which exists only in this
//! crate's unit-test build: no production item kind carries an envelope yet. A rejected block must
//! leave every table of the store byte-identical. TEST-VALUE data only.
//!
//! Declared once at file scope of `op_envelope_v1.rs`. The shared rig (tests/support/dividend_rig.rs)
//! and its two fixture modules are declared at THIS file's scope (never inside an inline module).
#![allow(dead_code, unused_imports)]
use super::{AwardAccount, Envelope, EnvelopeError, Precondition, assignment_facts, carrier, entitlement_facts, referenced_heights};
use crate::{
    Error, assembler_v2::Prepared, bft::Step, blocks::BlockBody, execution::ExecutionError, finality_v2::StoreError,
    votes::IngressError,
};
use std::collections::BTreeSet;

#[path = "../../desktop/src/wallet_host_fixture_licenses.rs"]
mod licenses;
#[path = "../tests/support/wallet_host_fixture_tpm.rs"]
mod tpm;
include!("../tests/support/dividend_rig.rs");

fn envelope(first_height: u64, last_height: u64, reference: &FinalizedAnchor) -> Envelope {
    Envelope {
        first_height,
        last_height,
        reference_height: reference.height,
        reference_block: reference.block,
        preconditions: vec![],
    }
}
fn prepare(rig: &Rig, epoch: u64, operations: &[Vec<u8>]) -> Prepared {
    rig.chain
        .prepare_pending(Preparation {
            expected_parent: &rig.parent,
            pool: &rig.pool,
            license: rig.f.license,
            worker: rig.f.worker,
            timestamp: at(epoch),
            ticket: rig.ticket,
            operations,
        })
        .unwrap()
}
/// A block certified with real votes that the production assembler would never build: a prepared
/// candidate with `operations` substituted and the body root recomputed.
fn craft(rig: &Rig, mut prepared: Prepared, operations: Vec<Vec<u8>>) -> BlockEnvelope {
    prepared.body.operations = operations;
    prepared.candidate.body_root = prepared.body.root().unwrap();
    certify_at(prepared, &rig.f, &rig.parent, &rig.state, rig.ticket)
}
/// Every row of every table of the durable store, read through a separate read-only connection:
/// head, state_v2, undo_v2, confirmations_v2, finality and evidence rows, the proof index, ...
fn store_rows(rig: &Rig) -> Vec<(String, Vec<String>)> {
    let db = rusqlite::Connection::open_with_flags(rig.base.join("chain.sqlite"), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap();
    let tables: Vec<String> = {
        let mut q = db.prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name").unwrap();
        q.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
    };
    tables
        .into_iter()
        .map(|table| {
            let mut q = db.prepare(&format!("SELECT * FROM \"{table}\"")).unwrap();
            let n = q.column_count();
            let mut rows: Vec<String> = q
                .query_map([], |r| {
                    Ok((0..n).map(|i| format!("{:?}", r.get_ref(i).unwrap())).collect::<Vec<_>>().join("|"))
                })
                .unwrap()
                .map(Result::unwrap)
                .collect();
            rows.sort();
            (table, rows)
        })
        .collect()
}
/// Commits a block that must be rejected; asserts the store is byte-identical afterwards.
fn rejected_without_effect(rig: &mut Rig, block: &BlockEnvelope) -> StoreError {
    let rows = store_rows(rig);
    let loaded = rig.chain.load().unwrap();
    let error = rig.chain.commit(block).unwrap_err();
    assert_eq!(store_rows(rig), rows, "a rejected block leaves every store table byte-identical");
    assert_eq!(rig.chain.load().unwrap(), loaded);
    error
}
fn execution_error(error: &StoreError) -> Option<Error> {
    match error {
        StoreError::Verification(IngressError::Execution(ExecutionError::Codec(e))) => Some(*e),
        _ => None,
    }
}

/// Design 14.4 T6. A block whose envelope references an OLDER height than its parent is prepared
/// and committed (both build the History through `operation_history`), and a reopened store
/// replays it (`verify_replay` builds the same anchors inline). Without the store's History the
/// same block fails closed. Mutant "replay copy without anchors": `restart` panics.
#[test]
fn commit_and_replay_share_reference_history() {
    let mut rig = Rig::new(fixture(), "envelope-t6");
    rig.step(1, &[]);
    let one = rig.parent.clone();
    rig.step(2, &[]);
    let two = rig.parent.clone();
    let older = carrier::encode(&envelope(3, 10, &one));
    let prepared = prepare(&rig, 3, &[older.clone()]);
    assert_eq!(prepared.body.operations, vec![older.clone()]);
    assert_eq!(referenced_heights(&prepared.body), BTreeSet::from([1]));
    // The executor with an empty History (prepare_candidate_v2) fails closed for this reference.
    let (work_parent, _, _) = rig.chain.execution_parent(rig.height()).unwrap();
    let fail_closed = rig.state.prepare_candidate_v2(CandidatePreparation {
        parent: &work_parent,
        candidate: &prepared.candidate,
        ticket_sequence: rig.ticket,
        body: &prepared.body,
    });
    assert!(matches!(fail_closed, Err(ExecutionError::Codec(Error::WrongAnchor))), "{:?}", fail_closed.err());
    // The store's History holds the canonical hash of height 1 and nothing else.
    let history = rig.chain.evidence_history(3, &prepared.body).unwrap();
    assert_eq!(history.anchor(1), Some(one.block));
    assert_eq!(history.anchor(2), None, "only referenced heights are inserted");
    rig.commit_prepared(prepared);
    assert_eq!(rig.height(), 3);
    assert_eq!(rig.chain.canonical_block(3).unwrap().unwrap().body.operations, vec![older]);
    // Close and reopen: verify_replay re-executes block 3 with the same reference anchors.
    let before = rig.state.clone();
    let mut rig = rig.restart();
    assert_eq!(rig.height(), 3);
    assert_eq!(rig.state, before);
    // The chain continues: block 4 references height 2 (older than its parent 3), and a second
    // reopen replays both reference blocks.
    rig.step(4, &[carrier::encode(&envelope(4, 4, &two))]);
    let rig = rig.restart();
    assert_eq!(rig.height(), 4);
    rig.finish();
}

/// `CanonicalStore::evidence_history` takes the whole body (AM-4): the same bounds as before over
/// BOTH item lists, the body height must be the requested height, and the height must be at most
/// the tip plus one.
#[test]
fn evidence_history_bounds_the_whole_body_and_its_height() {
    let mut rig = Rig::new(fixture(), "envelope-bounds");
    rig.step(1, &[]);
    let one = rig.parent.clone();
    let body = |height: u64, transactions: Vec<Vec<u8>>, operations: Vec<Vec<u8>>| BlockBody {
        height,
        reward_owner: [0; 32],
        fees: 0,
        transactions,
        operations,
    };
    let older = carrier::encode(&envelope(2, 9, &rig.f.genesis));
    for (case, b) in [
        ("4097 items over both lists", body(2, vec![vec![0]; 2000], vec![vec![0]; 2097])),
        ("an item above 16 KiB", body(2, vec![vec![0; 16385]], vec![])),
        ("more than 64 KiB in all", body(2, vec![vec![0; 16384]; 3], vec![vec![0; 16384]; 2])),
    ] {
        assert!(matches!(rig.chain.evidence_history(2, &b), Err(StoreError::Invalid(Error::Capacity))), "{case}");
    }
    assert!(matches!(rig.chain.evidence_history(3, &body(2, vec![], vec![older.clone()])), Err(StoreError::WrongParent)));
    assert!(matches!(rig.chain.evidence_history(0, &body(0, vec![], vec![])), Err(StoreError::WrongParent)));
    assert!(matches!(rig.chain.evidence_history(3, &body(3, vec![], vec![older.clone()])), Err(StoreError::WrongParent)));
    // Reference anchors from either list (a unit-test build recognizes the carrier in both).
    let genesis_block = rig.f.genesis.block;
    let from_operations = rig.chain.evidence_history(2, &body(2, vec![], vec![older.clone()])).unwrap();
    assert_eq!(from_operations.anchor(0), Some(genesis_block));
    let from_transactions = rig.chain.evidence_history(2, &body(2, vec![older], vec![])).unwrap();
    assert_eq!(from_transactions.anchor(0), Some(genesis_block));
    // A reference below the block height is inserted (height 1 for block 2); one at the block
    // height itself is never inserted (it cannot be finalized history of that block).
    let below = rig.chain.evidence_history(2, &body(2, vec![], vec![carrier::encode(&envelope(2, 9, &one))])).unwrap();
    assert_eq!(below.anchor(1), Some(one.block));
    let at_height = FinalizedAnchor { height: 2, block: [0x22; 32], ..one.clone() };
    let ahead = rig.chain.evidence_history(2, &body(2, vec![], vec![carrier::encode(&envelope(3, 9, &at_height))])).unwrap();
    assert_eq!(ahead.anchor(2), None);
    rig.finish();
}

/// Rule R through the real `CanonicalStore::commit` (AM-4): a non-canonical reference is refused by
/// the production assembler and, in a certified block, by commit (exact error, store
/// byte-identical); the exact `ReferenceNotCanonical` is shown with the very History commit builds;
/// a parent reference needs no History anchor at all.
#[test]
fn reference_must_be_canonical_through_real_blocks() {
    let mut rig = Rig::new(fixture(), "envelope-ref");
    rig.step(1, &[]);
    let one = rig.parent.clone();
    rig.step(2, &[]);
    let two = rig.parent.clone();
    let mut forged = envelope(3, 9, &one);
    forged.reference_block = [0xEE; 32];
    let error = rig.try_step(3, &[carrier::encode(&forged)]).unwrap_err();
    assert!(error.contains("WrongAnchor"), "{error}");
    assert_eq!(rig.height(), 2);
    let block = craft(&rig, prepare(&rig, 3, &[]), vec![carrier::encode(&forged)]);
    let error = rejected_without_effect(&mut rig, &block);
    assert_eq!(execution_error(&error), Some(Error::WrongAnchor), "{error:?}");
    let history = rig.chain.evidence_history(3, &block.body).unwrap();
    assert_eq!(history.anchor(1), Some(one.block), "the canonical hash, not the forged one");
    assert_eq!(forged.check_inclusion(&two, &history), Err(EnvelopeError::ReferenceNotCanonical));
    // A reference to the parent itself: accepted with an empty History, and committed.
    let at_parent = carrier::encode(&envelope(3, 9, &two));
    let prepared = prepare(&rig, 3, &[at_parent.clone()]);
    let (work_parent, _, _) = rig.chain.execution_parent(rig.height()).unwrap();
    rig.state
        .prepare_candidate_v2(CandidatePreparation {
            parent: &work_parent,
            candidate: &prepared.candidate,
            ticket_sequence: rig.ticket,
            body: &prepared.body,
        })
        .unwrap();
    rig.commit_prepared(prepared);
    assert_eq!(rig.height(), 3);
    rig.finish();
}

/// Window W through real blocks at inclusion height 3: one height before `first` and one after
/// `last` are refused (exact errors, store byte-identical); both exact ends are accepted.
#[test]
fn expired_and_future_windows_reject_byte_identical() {
    let mut rig = Rig::new(fixture(), "envelope-window");
    rig.step(1, &[]);
    let one = rig.parent.clone();
    rig.step(2, &[]);
    let two = rig.parent.clone();
    let future = envelope(4, 9, &two);
    let expired = envelope(2, 2, &one);
    for (case, e, exact) in [("future", &future, EnvelopeError::Future), ("expired", &expired, EnvelopeError::Expired)] {
        let item = carrier::encode(e);
        assert!(rig.try_step(3, &[item.clone()]).unwrap_err().contains("WrongAnchor"), "{case}");
        let block = craft(&rig, prepare(&rig, 3, &[]), vec![item]);
        let error = rejected_without_effect(&mut rig, &block);
        assert_eq!(execution_error(&error), Some(Error::WrongAnchor), "{case}: {error:?}");
        let history = rig.chain.evidence_history(3, &block.body).unwrap();
        assert_eq!(e.check_inclusion(&two, &history), Err(exact), "{case}");
    }
    // first == H (and last == H) at height 3; last == H with an older first at height 4.
    rig.step(3, &[carrier::encode(&envelope(3, 3, &two))]);
    rig.step(4, &[carrier::encode(&envelope(2, 4, &one))]);
    assert_eq!(rig.height(), 4);
    rig.finish();
}

/// Preconditions P through real blocks: committed entitlement and assignment facts survive a head
/// advance; after a claim changes the License's account the same reviewed bytes are stale
/// (refused by the assembler and, in a certified block, by commit; store byte-identical).
#[test]
fn preconditions_are_checked_again_at_inclusion_through_real_blocks() {
    let treasury = treasury_key();
    let owner = owner_key();
    let mut rig = Rig::new(fixture_with_treasury(&treasury, 1_200_000), "envelope-pre");
    let s1 = rig.step(P, &[]);
    let one = rig.parent.clone();
    let reviewed = vec![entitlement_facts(&s1, license(0)), assignment_facts(&s1, license(0)).unwrap()];
    assert_eq!(
        reviewed[0],
        Precondition::LicenseEntitlements {
            license: license(0),
            accounts: vec![AwardAccount { award_epoch: P, share: 50_000, remaining: 50_000, claims: 0 }],
        }
    );
    let committed = Envelope { preconditions: reviewed, ..envelope(2, 20, &one) };
    let item = carrier::encode(&committed);
    // Head advance alone does not invalidate the unchanged operation.
    rig.step(P + 1, &[]);
    rig.step(P + 2, &[item.clone()]);
    assert_eq!(rig.height(), 3);
    // A claim of License 0 changes its account.
    rig.step(P + 3, &[claim_op(&rig.f, &owner, 0, P, 10_000, 0, [0x77; 32])]);
    assert!(rig.try_step(P + 4, &[item.clone()]).unwrap_err().contains("StaleSequence"));
    let block = craft(&rig, prepare(&rig, P + 4, &[]), vec![item]);
    let error = rejected_without_effect(&mut rig, &block);
    assert_eq!(execution_error(&error), Some(Error::StaleSequence), "{error:?}");
    // Exact error at the validation point (no epoch event between P + 3 and P + 4).
    let context = crate::trading_v1::Context { network: NETWORK_ID, genesis: rig.f.genesis.genesis, fingerprint: rig.f.genesis.fingerprint };
    assert_eq!(committed.check_preconditions(&rig.state, &context), Err(EnvelopeError::Stale(1)));
    let refreshed = Envelope {
        preconditions: vec![entitlement_facts(&rig.state, license(0)), assignment_facts(&rig.state, license(0)).unwrap()],
        ..committed.clone()
    };
    refreshed.check_preconditions(&rig.state, &context).unwrap();
    rig.step(P + 4, &[carrier::encode(&refreshed)]);
    assert_eq!(rig.height(), 5);
    rig.finish();
}

// ---------------------------------------------------------------------------------------------
// AM-4 entry-point matrix.
// ---------------------------------------------------------------------------------------------

/// Synthetic counter custody for the voter (TEST-VALUE key; counter in memory).
struct Custody<'a> {
    key: &'a HybridKey,
    counter: u64,
}
impl crate::counter_store::MonotonicCounter for Custody<'_> {
    fn read(&mut self) -> std::result::Result<u64, String> {
        Ok(self.counter)
    }
    fn increment(&mut self) -> std::result::Result<(), String> {
        self.counter = self.counter.checked_add(1).ok_or("counter overflow")?;
        Ok(())
    }
}
impl crate::counter_voter_v2::CounterSigningBackend for Custody<'_> {
    fn public_key(&self) -> &mutiny_crypto_v2::PublicKey {
        self.key.public()
    }
    fn sign_vote(&mut self, message: &[u8]) -> std::result::Result<HybridSignature, String> {
        self.key
            .sign(mutiny_crypto_v2::Domain::ContinuityVote, message)
            .map_err(|_| "synthetic vote signer".into())
    }
}
/// A Continuity key rotation (kind 21) of the rig's only voter, child of the current tip: the
/// counter-voter migration re-validates exactly such a finalized block.
fn continuity_key_rotation(rig: &Rig, new: &HybridKey) -> crate::continuity_key_rotate_v2::KeyRotate {
    let node = rig.state.continuity.as_ref().unwrap().members[0].node;
    let control = rig.state.membership_v2.get(node).unwrap();
    let mut binding = control.binding().clone();
    binding.admission.key_generation = 2;
    let mut rotation = crate::continuity_key_rotate_v2::KeyRotate {
        parent: rig.parent.clone(),
        nonce: [7; 32],
        sequence: control.sequence() + 1,
        old_key_generation: 1,
        binding: binding.clone(),
    };
    binding.admission.continuity_descriptor = new.public().descriptor(2).unwrap();
    binding.admission.supervised_nonce = rotation.admission_nonce().unwrap();
    binding.admission.prove_continuity(new).unwrap();
    let ak = p256::ecdsa::SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
    let profile = tpm::profile(&ak);
    binding.admission.quote = tpm::quote(&ak, &profile, binding.admission.challenge().unwrap());
    binding.admission.authorize(&owner_key(), 1).unwrap();
    binding.sign(&rig.f.coordinator).unwrap();
    rotation.binding = binding;
    rotation
}

/// AM-4 ENTRY-POINT MATRIX. ONE block (height 3) carries an envelope item whose reference is height
/// 1, older than its parent 2, plus a Continuity key rotation of the only voter. The same block is
/// accepted by every store entry point that executes a block: `prepare_pending` (caller items),
/// `validate_node_work` (`validate_work_custody`), `evidence_history`, `validate_round_proposal`
/// (inside a real counter voter's round, whose own prevote/precommit certify the block), `commit`,
/// `validate_observation_v2`, the counter-voter migration `rotate_finalized` (re-validates the
/// finalized block through `evidence_history`) and `verify_replay` (reopen). Each step is labelled:
/// a mutant "entry point without anchors" fails this test at its label.
#[test]
fn entry_point_matrix_accepts_an_older_reference() {
    let mut rig = Rig::new(fixture(), "envelope-matrix");
    rig.step(1, &[]);
    let one = rig.parent.clone();
    rig.step(2, &[]);
    let node = rig.state.continuity.as_ref().unwrap().members[0].node;
    let new_key = HybridKey::generate(Role::Continuity).unwrap();
    let rotation = continuity_key_rotation(&rig, &new_key);
    let older = carrier::encode(&envelope(3, 9, &one));
    let operations = vec![rotation.encode().unwrap(), older];
    let prepared = rig
        .chain
        .prepare_pending(Preparation {
            expected_parent: &rig.parent,
            pool: &rig.pool,
            license: rig.f.license,
            worker: rig.f.worker,
            timestamp: at(3),
            ticket: rig.ticket,
            operations: &operations,
        })
        .expect("prepare_pending (caller items)");
    assert_eq!(prepared.body.operations, operations);
    // Header, work authority and body of the proposal; its rig-signed certificate is replaced by the
    // counter voter's own votes below.
    let proposal = certify_at(prepared, &rig.f, &rig.parent, &rig.state, rig.ticket);
    rig.chain
        .validate_node_work(&rig.parent, node, &proposal.authority, &proposal.body)
        .expect("validate_work_custody (validate_node_work)");
    assert_eq!(
        rig.chain.evidence_history(3, &proposal.body).expect("evidence_history").anchor(1),
        Some(one.block),
        "evidence_history"
    );
    // Later rig blocks are certified with the rotated key; this voter keeps the old one.
    let old_key = std::mem::replace(&mut rig.f.continuity, new_key);
    let mut custody = Custody { key: &old_key, counter: 100 };
    let mut voter = crate::counter_voter_v2::CounterVoter::open(
        &rig.base.join("voter.sqlite"),
        rig.chain.voting_authority_at(2).unwrap(),
        node,
        Some(100),
        &mut custody,
    )
    .unwrap();
    voter.set_vote_clock(crate::vote_clock_v1::ControlledClock::at(u64::MAX));
    rig.chain
        .validate_round_proposal(voter.round_mut().unwrap(), &proposal.header, &proposal.authority, &proposal.body)
        .expect("validate_round_proposal");
    let hash = proposal.block_hash();
    let prevote = voter.sign(Step::Prevote, Some(hash), None, &mut custody).unwrap();
    voter.round_mut().unwrap().observe(&prevote).unwrap();
    let precommit = voter.sign(Step::Precommit, Some(hash), None, &mut custody).unwrap();
    voter.round_mut().unwrap().observe(&precommit).unwrap();
    let block = BlockEnvelope {
        certificate: Certificate { decision: precommit.decision.clone(), votes: vec![precommit] },
        ..proposal
    };
    assert!(rig.chain.commit(&block).expect("commit"));
    rig.parent = block.certificate.decision.anchor();
    rig.ticket += 1;
    rig.state = rig.chain.load().unwrap().1;
    rig.chain.reconcile_pool(&mut rig.pool).unwrap();
    rig.chain
        .validate_observation_v2(&block.header, &block.authority, &block.body)
        .expect("validate_observation_v2");
    voter
        .rotate_finalized(&mut rig.chain, &mut custody)
        .expect("counter-voter migration (rotate_finalized)");
    drop(voter);
    // verify_replay: reopen the store (`restart` panics if the replay rejects the chain).
    let mut rig = rig.restart();
    assert_eq!(rig.height(), 3);
    // The chain continues under the rotated key.
    rig.step(4, &[]);
    rig.finish();
}

/// AM-4, `prepare_pending` POOL items: the assembler trial-adds pool candidates, so the History it
/// receives must hold the anchors that the pool's `PendingReferences` hook reports. The POOL-ONLY
/// carrier form hides its reference from every block-level extraction, so only the hook can supply
/// it. Block validation never trusts a pool report: the same block is refused by commit.
#[test]
fn prepare_pending_takes_pool_reference_heights_from_the_hook() {
    let mut rig = Rig::new(fixture(), "envelope-pool");
    rig.step(1, &[]);
    let one = rig.parent.clone();
    rig.step(2, &[]);
    let pool_only = carrier::encode_pool_only(&envelope(3, 9, &one));
    let hidden = BlockBody { height: 3, reward_owner: [0; 32], fees: 0, transactions: vec![pool_only.clone()], operations: vec![pool_only.clone()] };
    assert_eq!(referenced_heights(&hidden), BTreeSet::new(), "no block-level extraction sees it");
    // No pool report: the assembler has no anchor for height 1 and fails closed.
    assert!(rig.try_step(3, &[pool_only.clone()]).unwrap_err().contains("WrongAnchor"));
    // The pool reports height 1: prepare_pending hands the assembler that anchor.
    carrier::POOL_REFERENCES.with(|heights| *heights.borrow_mut() = BTreeSet::from([1]));
    let prepared = rig
        .chain
        .prepare_pending(Preparation {
            expected_parent: &rig.parent,
            pool: &rig.pool,
            license: rig.f.license,
            worker: rig.f.worker,
            timestamp: at(3),
            ticket: rig.ticket,
            operations: &[pool_only.clone()],
        })
        .expect("prepare_pending (pool items through the hook)");
    assert_eq!(prepared.body.operations, vec![pool_only]);
    // Even while the pool still reports height 1, commit derives anchors from the block alone.
    let block = certify_at(prepared, &rig.f, &rig.parent, &rig.state, rig.ticket);
    let error = rejected_without_effect(&mut rig, &block);
    carrier::POOL_REFERENCES.with(|heights| heights.borrow_mut().clear());
    assert_eq!(execution_error(&error), Some(Error::WrongAnchor), "{error:?}");
    rig.finish();
}

/// WP-T1 rows of the AM-4 entry-point matrix: the same matrix with a PRODUCTION item kind, a
/// trading HashLock (body version 2) whose envelope references height 1 while the block's parent is
/// height 2. The shared trading rig is declared in this submodule so that its helpers do not clash
/// with this file's.
mod trading_matrix {
    use super::*;
    include!("../tests/support/trading_rig_v1.rs");

    #[test]
    fn entry_point_matrix_accepts_a_trading_item_with_an_older_reference() {
        let (a, b) = (owner_key(), second_key());
        let (aa, ba) = (addr(&a, 1), addr(&b, 1));
        let mut f = fixture();
        let input = fund(&mut f, 0x3c, aa, 100_000);
        let mut rig = Rig::new(f, "envelope-matrix-trading");
        rig.step(1, &[]);
        let one = rig.parent.clone();
        let lock = trade(
            &rig.f,
            tr::Action::HashLock {
                offer: [0; 32],
                maker: [0; 32],
                sender: aa,
                recipient: ba,
                amount: tr::Strikes(50_000),
                condition: tr::preimage_hash(&[42; 32]),
                refund_height: 20,
                change: tr::Strikes(30_000),
            },
            Window { first: 2, last: 9, reference: (1, one.block) },
            20_000,
            &[input],
            &[(0, &a, 1), (1, &b, 1)],
        );
        rig.step(2, &[]);
        let node = rig.state.continuity.as_ref().unwrap().members[0].node;
        let new_key = HybridKey::generate(Role::Continuity).unwrap();
        let rotation = continuity_key_rotation(&rig, &new_key);
        let older = lock.encode().unwrap();
        // Without the store's anchor of height 1 the trading phase fails closed.
        assert!(matches!(
            native_verdict(&rig, &[older.clone()]),
            Err(tr::NativeError::Envelope(EnvelopeError::ReferenceNotCanonical))
        ));
        let operations = vec![rotation.encode().unwrap(), older];
        let prepared = rig
            .chain
            .prepare_pending(Preparation {
                expected_parent: &rig.parent,
                pool: &rig.pool,
                license: rig.f.license,
                worker: rig.f.worker,
                timestamp: at(3),
                ticket: rig.ticket,
                operations: &operations,
            })
            .expect("prepare_pending (caller items)");
        assert_eq!(prepared.body.operations, operations);
        assert_eq!(prepared.body.fees, 20_000, "the trading fee is previewed from its declared value");
        let proposal = certify_at(prepared, &rig.f, &rig.parent, &rig.state, rig.ticket);
        rig.chain
            .validate_node_work(&rig.parent, node, &proposal.authority, &proposal.body)
            .expect("validate_work_custody (validate_node_work)");
        assert_eq!(
            rig.chain.evidence_history(3, &proposal.body).expect("evidence_history").anchor(1),
            Some(one.block),
            "evidence_history"
        );
        let old_key = std::mem::replace(&mut rig.f.continuity, new_key);
        let mut custody = Custody { key: &old_key, counter: 100 };
        let mut voter = crate::counter_voter_v2::CounterVoter::open(
            &rig.base.join("voter.sqlite"),
            rig.chain.voting_authority_at(2).unwrap(),
            node,
            Some(100),
            &mut custody,
        )
        .unwrap();
        voter.set_vote_clock(crate::vote_clock_v1::ControlledClock::at(u64::MAX));
        rig.chain
            .validate_round_proposal(voter.round_mut().unwrap(), &proposal.header, &proposal.authority, &proposal.body)
            .expect("validate_round_proposal");
        let hash = proposal.block_hash();
        let prevote = voter.sign(Step::Prevote, Some(hash), None, &mut custody).unwrap();
        voter.round_mut().unwrap().observe(&prevote).unwrap();
        let precommit = voter.sign(Step::Precommit, Some(hash), None, &mut custody).unwrap();
        voter.round_mut().unwrap().observe(&precommit).unwrap();
        let block = BlockEnvelope {
            certificate: Certificate { decision: precommit.decision.clone(), votes: vec![precommit] },
            ..proposal
        };
        assert!(rig.chain.commit(&block).expect("commit"));
        rig.parent = block.certificate.decision.anchor();
        rig.ticket += 1;
        rig.state = rig.chain.load().unwrap().1;
        rig.chain.reconcile_pool(&mut rig.pool).unwrap();
        let installed = tr::locked(&rig.state, lock.operation.output_id(0).unwrap()).unwrap();
        assert_eq!(installed.created_height, 3, "effects at the actual inclusion height");
        rig.chain
            .validate_observation_v2(&block.header, &block.authority, &block.body)
            .expect("validate_observation_v2");
        voter
            .rotate_finalized(&mut rig.chain, &mut custody)
            .expect("counter-voter migration (rotate_finalized)");
        drop(voter);
        // verify_replay: reopen the store (`restart` panics if the replay rejects the chain).
        let mut rig = rig.restart();
        assert_eq!(rig.height(), 3);
        assert!(tr::locked(&rig.state, lock.operation.output_id(0).unwrap()).is_ok());
        rig.step(4, &[]);
        rig.finish();
    }
}

/// The anchor of a referenced height is its canonical row only while that row equals the height's
/// finalized anchor: a tampered canonical row makes every History that needs it fail with
/// `StoreError::Integrity` instead of supplying a forged anchor.
#[test]
fn a_tampered_canonical_row_is_never_used_as_a_reference_anchor() {
    let mut rig = Rig::new(fixture(), "envelope-tamper");
    rig.step(1, &[]);
    let one = rig.parent.clone();
    rig.step(2, &[]);
    let body = BlockBody {
        height: 3,
        reward_owner: [0; 32],
        fees: 0,
        transactions: vec![],
        operations: vec![carrier::encode(&envelope(3, 9, &one))],
    };
    assert_eq!(rig.chain.evidence_history(3, &body).unwrap().anchor(1), Some(one.block));
    let db = rusqlite::Connection::open(rig.base.join("chain.sqlite")).unwrap();
    db.execute(
        "UPDATE canonical_v2 SET block=?1 WHERE height=?2",
        rusqlite::params![[0xEE_u8; 32].as_slice(), 1u64.to_be_bytes().as_slice()],
    )
    .unwrap();
    drop(db);
    let error = rig.chain.evidence_history(3, &body).unwrap_err();
    assert!(matches!(error, StoreError::Integrity), "{error:?}");
    rig.finish();
}

/// AM-4 ENTRY-POINT MATRIX, kind-24 row (WP-B): the same steps as
/// `entry_point_matrix_accepts_an_older_reference`, with a REAL funded BondCreate (operation kind
/// 24) whose envelope references height 1, older than its parent 2, instead of the test carrier. The
/// store learns the reference through `op_envelope_v1::operation_envelope` (the kind-24 arm). Every
/// entry point accepts the block and the lot exists after commit and after `verify_replay`; without
/// the store's anchors the executor refuses the same item (fail closed).
#[test]
fn entry_point_matrix_accepts_a_kind_24_older_reference() {
    use crate::bond_create_v3::{BondError, FundedBondCreate, UnsignedBondCreate};
    use crate::transactions::{Coin, OutPoint, Output};
    let owner = owner_key();
    let mut f = fixture();
    let input = OutPoint { transaction: [0xB4; 32], index: 0 };
    let funding = crate::bonds::MINIMUM_ATOMS + 30_000;
    f.state.coins.insert(
        input.clone(),
        Coin { output: Output { owner: addr(&owner, 1), atoms: funding }, created_height: 0, coinbase: false },
    );
    let mut rig = Rig::new(f, "envelope-matrix-kind24");
    rig.step(1, &[]);
    let one = rig.parent.clone();
    rig.step(2, &[]);
    let node = rig.state.continuity.as_ref().unwrap().members[0].node;
    let create = FundedBondCreate::sign(
        UnsignedBondCreate {
            genesis: rig.parent.genesis,
            fingerprint: rig.parent.fingerprint,
            envelope: envelope(3, 9, &one),
            owner: addr(&owner, 1),
            owner_descriptor: desc(&owner, 1),
            node,
            node_generation: 1,
            nonce: [0xB5; 32],
            principal: crate::bonds::MINIMUM_ATOMS,
            fee: 20_000,
            inputs: vec![input.clone()],
            change: Some(Output { owner: addr(&owner, 1), atoms: 10_000 }),
        },
        &owner,
    )
    .unwrap();
    let item = create.encode().unwrap();
    assert_eq!(super::operation_envelope(&item), Some(envelope(3, 9, &one)));
    // Fail closed without the store's History: the executor alone has no anchor for height 1.
    assert!(matches!(
        crate::bond_create_v3::check(&rig.state, &rig.parent, &Default::default(), &item),
        Err(BondError::Envelope(EnvelopeError::ReferenceNotCanonical))
    ));
    let new_key = HybridKey::generate(Role::Continuity).unwrap();
    let rotation = continuity_key_rotation(&rig, &new_key);
    let operations = vec![rotation.encode().unwrap(), item];
    let prepared = rig
        .chain
        .prepare_pending(Preparation {
            expected_parent: &rig.parent,
            pool: &rig.pool,
            license: rig.f.license,
            worker: rig.f.worker,
            timestamp: at(3),
            ticket: rig.ticket,
            operations: &operations,
        })
        .expect("prepare_pending (caller items)");
    assert_eq!(prepared.body.operations, operations);
    assert_eq!(prepared.body.fees, 20_000, "the declared create fee is the block fee");
    let proposal = certify_at(prepared, &rig.f, &rig.parent, &rig.state, rig.ticket);
    rig.chain
        .validate_node_work(&rig.parent, node, &proposal.authority, &proposal.body)
        .expect("validate_work_custody (validate_node_work)");
    assert_eq!(
        rig.chain.evidence_history(3, &proposal.body).expect("evidence_history").anchor(1),
        Some(one.block),
        "evidence_history"
    );
    let old_key = std::mem::replace(&mut rig.f.continuity, new_key);
    let mut custody = Custody { key: &old_key, counter: 100 };
    let mut voter = crate::counter_voter_v2::CounterVoter::open(
        &rig.base.join("voter.sqlite"),
        rig.chain.voting_authority_at(2).unwrap(),
        node,
        Some(100),
        &mut custody,
    )
    .unwrap();
    voter.set_vote_clock(crate::vote_clock_v1::ControlledClock::at(u64::MAX));
    rig.chain
        .validate_round_proposal(voter.round_mut().unwrap(), &proposal.header, &proposal.authority, &proposal.body)
        .expect("validate_round_proposal");
    let hash = proposal.block_hash();
    let prevote = voter.sign(Step::Prevote, Some(hash), None, &mut custody).unwrap();
    voter.round_mut().unwrap().observe(&prevote).unwrap();
    let precommit = voter.sign(Step::Precommit, Some(hash), None, &mut custody).unwrap();
    voter.round_mut().unwrap().observe(&precommit).unwrap();
    let block = BlockEnvelope {
        certificate: Certificate { decision: precommit.decision.clone(), votes: vec![precommit] },
        ..proposal
    };
    assert!(rig.chain.commit(&block).expect("commit"));
    rig.parent = block.certificate.decision.anchor();
    rig.ticket += 1;
    rig.state = rig.chain.load().unwrap().1;
    let lot = &rig.state.bonds_v2.lots[&create.lot_id()].0;
    assert_eq!((lot.created_height, lot.atoms), (3, crate::bonds::MINIMUM_ATOMS), "B = actual inclusion");
    assert!(!rig.state.coins.contains_key(&input));
    rig.chain.reconcile_pool(&mut rig.pool).unwrap();
    rig.chain
        .validate_observation_v2(&block.header, &block.authority, &block.body)
        .expect("validate_observation_v2");
    voter
        .rotate_finalized(&mut rig.chain, &mut custody)
        .expect("counter-voter migration (rotate_finalized)");
    drop(voter);
    let mut rig = rig.restart();
    assert_eq!(rig.height(), 3);
    assert!(rig.chain.load().unwrap().1.bonds_v2.lots.contains_key(&create.lot_id()), "verify_replay");
    rig.step(4, &[]);
    rig.finish();
}

/// AM-4 ENTRY-POINT MATRIX, kind-25 row (WP-R): ONE block (height 3) carries a REAL funded
/// wallet-rotation bundle (transaction tag 25) whose envelope references height 1, older than its
/// parent 2, plus a Continuity key rotation of the only voter. The bundle reaches the block as a POOL
/// item (admitted with the store's anchor; `prepare_pending` gets that anchor through the pool's
/// `PendingReferences` report). The same block is accepted by `prepare_pending`,
/// `validate_node_work` (`validate_work_custody`), `evidence_history`, `validate_round_proposal`,
/// `commit`, `validate_observation_v2`, the counter-voter migration `rotate_finalized` and
/// `verify_replay` (reopen). The executor with an empty History refuses it (fail closed).
#[test]
fn entry_point_matrix_accepts_a_funded_rotation_with_an_older_reference() {
    use crate::{
        funded_rotation_v2::{Party, PartialRotation, Payer, UnsignedRotation, signing_intents},
        hybrid_transaction_v2::Transaction as Tx,
    };
    use mutiny_crypto_v2::rehearsal_keys_v1::Credential;
    let (old, new) = (Credential::from_label("wp-r-matrix-old", 1).unwrap(), Credential::from_label("wp-r-matrix-new", 1).unwrap());
    let authority = old.key().public().address_id(1).unwrap();
    let funding = OutPoint { transaction: [0xa7; 32], index: 0 };
    let mut f = fixture();
    f.state.coins.insert(funding.clone(), Coin { output: Output { owner: authority, atoms: 1_000_000 }, created_height: 0, coinbase: false });
    let mut rig = Rig::new(f, "envelope-matrix-25");
    rig.step(1, &[]);
    let one = rig.parent.clone();
    rig.step(2, &[]);
    let node = rig.state.continuity.as_ref().unwrap().members[0].node;
    let mut partial = PartialRotation::new(UnsignedRotation {
        genesis: one.genesis,
        fingerprint: one.fingerprint,
        envelope: envelope(2, 9, &one),
        authority,
        current_descriptor: old.key().public().descriptor(1).unwrap(),
        proposed_descriptor: new.key().public().descriptor(2).unwrap(),
        sponsor: None,
        fee: 20_000,
        inputs: vec![(funding.clone(), Payer::RotatingAuthority)],
        outputs: vec![Output { owner: new.key().public().address_id(2).unwrap(), atoms: 980_000 }],
    });
    for intent in signing_intents(&partial.unsigned).unwrap() {
        let key = if intent.party == Party::NewKey { new.key() } else { old.key() };
        partial.sign(intent.slot, key).unwrap();
    }
    let bundle = Tx::FundedRotation(partial.complete().unwrap());
    let wire = bundle.encode().unwrap();
    // Admission with the store's anchor of height 1 (an empty History would fail closed).
    let store_history = rig
        .chain
        .evidence_history(3, &BlockBody { height: 3, reward_owner: [0; 32], fees: 0, transactions: vec![wire.clone()], operations: vec![] })
        .unwrap();
    assert_eq!(store_history.anchor(1), Some(one.block));
    assert!(rig.pool.admit(&bundle, &rig.parent, &rig.state).is_err(), "no anchor: fail closed");
    rig.pool.admit_with_history(&bundle, &rig.parent, &rig.state, &store_history).unwrap();
    let new_key = HybridKey::generate(Role::Continuity).unwrap();
    let rotation = continuity_key_rotation(&rig, &new_key);
    let operations = vec![rotation.encode().unwrap()];
    let prepared = rig
        .chain
        .prepare_pending(Preparation {
            expected_parent: &rig.parent,
            pool: &rig.pool,
            license: rig.f.license,
            worker: rig.f.worker,
            timestamp: at(3),
            ticket: rig.ticket,
            operations: &operations,
        })
        .expect("prepare_pending (pool item through the hook)");
    assert_eq!(prepared.body.transactions, vec![wire.clone()], "prepare_pending includes the bundle");
    assert_eq!(referenced_heights(&prepared.body), BTreeSet::from([1]));
    // The executor without the store's History fails closed on the reference (fee/coinbase aside).
    let (work_parent, _, _) = rig.chain.execution_parent(rig.height()).unwrap();
    let fail_closed = rig.state.prepare_candidate_v2(CandidatePreparation {
        parent: &work_parent,
        candidate: &prepared.candidate,
        ticket_sequence: rig.ticket,
        body: &prepared.body,
    });
    assert!(
        matches!(fail_closed, Err(ExecutionError::Transfer(crate::transactions::TxError::Binding))),
        "{:?}",
        fail_closed.err()
    );
    let proposal = certify_at(prepared, &rig.f, &rig.parent, &rig.state, rig.ticket);
    rig.chain
        .validate_node_work(&rig.parent, node, &proposal.authority, &proposal.body)
        .expect("validate_work_custody (validate_node_work)");
    assert_eq!(rig.chain.evidence_history(3, &proposal.body).expect("evidence_history").anchor(1), Some(one.block));
    let old_voter_key = std::mem::replace(&mut rig.f.continuity, new_key);
    let mut custody = Custody { key: &old_voter_key, counter: 100 };
    let mut voter = crate::counter_voter_v2::CounterVoter::open(
        &rig.base.join("voter.sqlite"),
        rig.chain.voting_authority_at(2).unwrap(),
        node,
        Some(100),
        &mut custody,
    )
    .unwrap();
    voter.set_vote_clock(crate::vote_clock_v1::ControlledClock::at(u64::MAX));
    rig.chain
        .validate_round_proposal(voter.round_mut().unwrap(), &proposal.header, &proposal.authority, &proposal.body)
        .expect("validate_round_proposal");
    let hash = proposal.block_hash();
    let prevote = voter.sign(Step::Prevote, Some(hash), None, &mut custody).unwrap();
    voter.round_mut().unwrap().observe(&prevote).unwrap();
    let precommit = voter.sign(Step::Precommit, Some(hash), None, &mut custody).unwrap();
    voter.round_mut().unwrap().observe(&precommit).unwrap();
    let block = BlockEnvelope { certificate: Certificate { decision: precommit.decision.clone(), votes: vec![precommit] }, ..proposal };
    assert!(rig.chain.commit(&block).expect("commit"));
    rig.parent = block.certificate.decision.anchor();
    rig.ticket += 1;
    rig.state = rig.chain.load().unwrap().1;
    rig.chain.reconcile_pool(&mut rig.pool).unwrap();
    assert_eq!(rig.state.wallets.current(authority), Some(new.key().public().descriptor(2).unwrap().as_slice()));
    assert_eq!(rig.chain.confirmed_height(bundle.id().unwrap()).unwrap(), Some(3));
    rig.chain
        .validate_observation_v2(&block.header, &block.authority, &block.body)
        .expect("validate_observation_v2");
    voter
        .rotate_finalized(&mut rig.chain, &mut custody)
        .expect("counter-voter migration (rotate_finalized)");
    drop(voter);
    let mut rig = rig.restart();
    assert_eq!(rig.height(), 3);
    assert_eq!(rig.state.wallets.current(authority), Some(new.key().public().descriptor(2).unwrap().as_slice()));
    rig.step(4, &[]);
    rig.finish();
}
