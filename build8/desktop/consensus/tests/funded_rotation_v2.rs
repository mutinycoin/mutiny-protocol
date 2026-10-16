//! Lane P work package WP-R: the P2 funded wallet-rotation bundle (hybrid transaction wrapper tag 25)
//! through REAL blocks. Design `qualification/candidate-3/P-LANE-DESIGN-V1.md` sections 1.b, 1.c, 3,
//! 4.1 row 2 and 14.2; amendments AM-1(d), AM-9 m6 and AM-11 of `P-LANE-DESIGN-AMENDMENTS-V1.md`;
//! Order of 4 October 2026, decisions P2, P3 and P9. NATIVE, TEST-VALUE, Windows-host software
//! evidence only: nothing here is physical, Linux or production evidence.
//!
//! Harness H-B (`tests/support/dividend_rig.rs`): positive blocks are prepared by the production
//! assembler from the pool (or built from the assembler's candidate with an explicit body), certified
//! with real hybrid votes and installed by `CanonicalStore::commit`, which re-executes them; a
//! `restart` re-verifies the whole chain from trusted Genesis. Every negative builds the block through
//! the real V2 executor (`State::prepare_candidate_with_history_v2`), asserts the EXACT error and that
//! `State::records()` of the parent (and of the canonical store) is identical; the key negatives are
//! also certified and handed to `CanonicalStore::commit`, which must refuse them with the same error
//! while every row of every table of the store database stays byte-identical.
//! Wallet keys are labelled-seed TEST-VALUE keys (`rehearsal_keys_v1`): public by construction.
#![allow(dead_code, unused_imports)]
#[path = "../../desktop/src/wallet_host_fixture_licenses.rs"]
mod licenses;
#[path = "support/wallet_host_fixture_tpm.rs"]
mod tpm;
include!("support/dividend_rig.rs");

use mutiny_consensus_v8::{
    Error,
    assembler_v2::Prepared,
    dividends_v1::DivError,
    evidence_history_v2::History,
    execution::{Execution, ExecutionError},
    finality_v2::StoreError,
    funded_rotation_v2::{self as fr, FundedRotation, Party, PartialRotation, Payer, Slot, UnsignedRotation},
    hybrid_transaction_v2::Inclusion,
    mempool_v2::{PoolError, Status},
    op_envelope_v1::{Envelope, EnvelopeError},
    transactions::TxError,
    votes::IngressError,
};
use mutiny_crypto_v2::{Domain, PublicKey, rehearsal_keys_v1::Credential};
use std::sync::OnceLock;

const FEE: u64 = 20_000;
const BIG: u64 = 10_000_000;
/// A third-party destination that never spends (P3: a real, non-zero address).
const DEST: Hash = [0x0d; 32];

struct Keys {
    a1: Credential,
    a2: Credential,
    a3: Credential,
    a4: Credential,
    b1: Credential,
    b2: Credential,
    s1: Credential,
    s2: Credential,
    x: Credential,
    t: Credential,
    tn: Credential,
    m: Credential,
}
fn keys() -> &'static Keys {
    static K: OnceLock<Keys> = OnceLock::new();
    let c = |label: &str| Credential::from_label(label, 1).unwrap();
    K.get_or_init(|| Keys {
        a1: c("wp-r-a1"),
        a2: c("wp-r-a2"),
        a3: c("wp-r-a3"),
        a4: c("wp-r-a4"),
        b1: c("wp-r-b1"),
        b2: c("wp-r-b2"),
        s1: c("wp-r-s1"),
        s2: c("wp-r-s2"),
        x: c("wp-r-x"),
        t: c("wp-r-t"),
        tn: c("wp-r-treasury-next"),
        m: c("wp-r-matrix"),
    })
}
fn point(n: u8) -> OutPoint {
    OutPoint { transaction: [n; 32], index: 0 }
}
fn coin(owner: Hash, atoms: u64) -> Coin {
    Coin { output: Output { owner, atoms }, created_height: 0, coinbase: false }
}
/// The H-B fixture with its TEST-VALUE Treasury plus the listed genesis coins. The listed wallets
/// stay UNREGISTERED: their first bundle registers their generation-one authority.
fn rig(tag: &str, coins: &[(u8, Hash, u64)]) -> Rig {
    let mut f = fixture_with_treasury(&treasury_key(), 1_200_000);
    for (n, owner, atoms) in coins {
        f.state.coins.insert(point(*n), coin(*owner, *atoms));
    }
    Rig::new(f, tag)
}

/// A reviewed rotation plan signed at `head`: window `[head + 1, head + 1 + validity]`, reference
/// `head` (the wallet's `Envelope::from_head`).
struct Plan<'a> {
    head: FinalizedAnchor,
    validity: u64,
    authority: Hash,
    old: (&'a HybridKey, u64),
    new: (&'a HybridKey, u64),
    sponsor: Option<(Hash, &'a HybridKey, u64)>,
    inputs: Vec<(OutPoint, Payer)>,
    outputs: Vec<Output>,
    fee: u64,
}
fn plan<'a>(head: &FinalizedAnchor, authority: Hash, old: (&'a HybridKey, u64), new: (&'a HybridKey, u64)) -> Plan<'a> {
    Plan { head: head.clone(), validity: 10, authority, old, new, sponsor: None, inputs: vec![], outputs: vec![], fee: FEE }
}
impl Plan<'_> {
    fn unsigned(&self) -> UnsignedRotation {
        let mut inputs = self.inputs.clone();
        inputs.sort();
        UnsignedRotation {
            genesis: self.head.genesis,
            fingerprint: self.head.fingerprint,
            envelope: Envelope::from_head(&self.head, self.validity, vec![]).unwrap(),
            authority: self.authority,
            current_descriptor: desc(self.old.0, self.old.1),
            proposed_descriptor: desc(self.new.0, self.new.1),
            sponsor: self.sponsor.map(|(address, key, generation)| (address, desc(key, generation))),
            fee: self.fee,
            inputs,
            outputs: self.outputs.clone(),
        }
    }
    fn sign(&self) -> FundedRotation {
        sign(self.unsigned(), self.old.0, self.new.0, self.sponsor.map(|s| s.1))
    }
}
/// Signs every REQUIRED slot through the typed signing intents and completes the bundle.
fn sign(unsigned: UnsignedRotation, old: &HybridKey, new: &HybridKey, sponsor: Option<&HybridKey>) -> FundedRotation {
    let mut partial = PartialRotation::new(unsigned);
    for intent in fr::signing_intents(&partial.unsigned).unwrap() {
        let key = match intent.party {
            Party::RotatingAuthority => old,
            Party::NewKey => new,
            Party::Sponsor => sponsor.expect("a sponsored plan needs the sponsor key"),
        };
        partial.sign(intent.slot, key).unwrap();
    }
    partial.complete().unwrap()
}
fn ftx(tx: &FundedRotation) -> Transaction {
    Transaction::FundedRotation(tx.clone())
}
fn wire(tx: &FundedRotation) -> Vec<u8> {
    tx.encode().unwrap()
}
fn id(tx: &FundedRotation) -> Hash {
    tx.id().unwrap()
}
fn out(tx: &FundedRotation, index: u32) -> OutPoint {
    OutPoint { transaction: id(tx), index }
}

// ---------------------------------------------------------------------------------------------
// Block builders.
// ---------------------------------------------------------------------------------------------

/// The rig's next block for `epoch`, holding exactly `txs` with `fees` declared, built on the real
/// assembler's candidate (no operations; the body's transactions are replaced).
fn block(rig: &Rig, epoch: u64, txs: &[Vec<u8>], fees: u64) -> Prepared {
    let base = rig
        .chain
        .prepare_pending(Preparation {
            expected_parent: &rig.parent,
            pool: &rig.pool,
            license: rig.f.license,
            worker: rig.f.worker,
            timestamp: at(epoch),
            ticket: rig.ticket,
            operations: &[],
        })
        .unwrap();
    let mut body = base.body;
    body.transactions = txs.to_vec();
    body.fees = fees;
    let mut candidate = base.candidate;
    candidate.body_root = body.root().unwrap();
    Prepared { candidate, body, execution: base.execution }
}
/// Executes the block through the real V2 executor with `history`; the parent state and the
/// canonical store's state must be record-identical afterwards, whatever the outcome.
fn execute(rig: &Rig, prepared: &Prepared, history: &History) -> Result<Execution, ExecutionError> {
    let (work_parent, _, _) = rig.chain.execution_parent(rig.height()).unwrap();
    let before = rig.state.records().unwrap();
    let result = rig.state.prepare_candidate_with_history_v2(
        CandidatePreparation {
            parent: &work_parent,
            candidate: &prepared.candidate,
            ticket_sequence: rig.ticket,
            body: &prepared.body,
        },
        history,
    );
    assert_eq!(rig.state.records().unwrap(), before, "the parent state is record-identical");
    assert_eq!(rig.chain.load().unwrap().1.records().unwrap(), before, "the canonical state is record-identical");
    result
}
/// The exact transaction error of a block the executor must reject (records identity asserted).
fn rejected(rig: &Rig, epoch: u64, txs: &[Vec<u8>], fees: u64, history: &History) -> TxError {
    match execute(rig, &block(rig, epoch, txs, fees), history) {
        Ok(_) => panic!("the block must be rejected"),
        Err(ExecutionError::Transfer(e)) => e,
        Err(other) => panic!("not a transaction error: {other:?}"),
    }
}
/// Every row of every table of the canonical store database (byte-identity of the whole store).
fn store_rows(rig: &Rig) -> Vec<String> {
    let db = rusqlite::Connection::open_with_flags(rig.base.join("chain.sqlite"), rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .unwrap();
    let tables: Vec<String> = {
        let mut q = db.prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name").unwrap();
        q.query_map([], |r| r.get(0)).unwrap().map(|r| r.unwrap()).collect()
    };
    let mut out = Vec::new();
    for table in tables {
        let mut q = db.prepare(&format!("SELECT * FROM \"{table}\"")).unwrap();
        let n = q.column_count();
        let mut rows: Vec<String> = q
            .query_map([], |r| (0..n).map(|i| r.get::<_, rusqlite::types::Value>(i)).collect::<Result<Vec<_>, _>>())
            .unwrap()
            .map(|r| format!("{table}: {:?}", r.unwrap()))
            .collect();
        rows.sort();
        out.push(format!("table {table}: {} rows", rows.len()));
        out.extend(rows);
    }
    out
}
/// Certifies the block and hands it to `CanonicalStore::commit`, which re-executes it: it must be
/// refused with a transaction error, and the store database must stay byte-identical.
fn commit_rejected(rig: &mut Rig, epoch: u64, txs: &[Vec<u8>], fees: u64) -> TxError {
    let envelope = certify_at(block(rig, epoch, txs, fees), &rig.f, &rig.parent, &rig.state, rig.ticket);
    let before = store_rows(rig);
    let head = rig.chain.load().unwrap().0;
    let error = rig.chain.commit(&envelope).expect_err("commit must refuse the block");
    assert_eq!(store_rows(rig), before, "a refused commit leaves every store row byte-identical");
    assert_eq!(rig.chain.load().unwrap().0, head);
    match error {
        StoreError::Verification(IngressError::Execution(ExecutionError::Transfer(e))) => e,
        other => panic!("unexpected store error {other:?}"),
    }
}
/// Commits an explicit valid body (same-block combinations the id-ordered assembler would not
/// produce): executed first, then certified and installed through `CanonicalStore::commit`.
fn commit_block(rig: &mut Rig, epoch: u64, txs: &[Vec<u8>], fees: u64) -> State {
    let mut prepared = block(rig, epoch, txs, fees);
    // The History the store itself builds for this block (evidence_history: same anchors as commit).
    let history = rig.chain.evidence_history(rig.height() + 1, &prepared.body).unwrap();
    prepared.execution = execute(rig, &prepared, &history).expect("the block must be valid");
    prepared.candidate.state_root = prepared.execution.root;
    rig.commit_prepared(prepared)
}
/// Admits `txs` to the pool at the tip and lets the production assembler include them.
fn include(rig: &mut Rig, epoch: u64, txs: &[Transaction]) -> State {
    for tx in txs {
        assert_eq!(rig.pool.admit(tx, &rig.parent, &rig.state).unwrap(), Status::Pending);
    }
    let state = rig.step(epoch, &[]);
    for tx in txs {
        assert_eq!(rig.chain.confirmed_height(tx.id().unwrap()).unwrap(), Some(rig.height()), "included");
        assert_eq!(rig.pool.status(tx.id().unwrap()).unwrap(), Some(Status::Confirmed));
    }
    state
}
fn coinbase_at(s: &State, height: u64) -> u64 {
    s.coins.values().filter(|c| c.coinbase && c.created_height == height).map(|c| c.output.atoms).sum()
}

// ---------------------------------------------------------------------------------------------
// Hostile raw encodings: an independent re-implementation of the design 3.2 layout WITHOUT any
// validation (it also cross-checks the library encoder byte for byte).
// ---------------------------------------------------------------------------------------------

fn raw_unsigned(u: &UnsignedRotation, network: u32) -> Vec<u8> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(12).unwrap().u8(1).unwrap().u32(network).unwrap().bytes(&u.genesis).unwrap().bytes(&u.fingerprint).unwrap();
    e.writer_mut().extend_from_slice(&u.envelope.to_bytes().unwrap());
    e.bytes(&u.authority).unwrap().bytes(&u.current_descriptor).unwrap().bytes(&u.proposed_descriptor).unwrap();
    match &u.sponsor {
        Some((address, descriptor)) => {
            e.array(2).unwrap().bytes(address).unwrap().bytes(descriptor).unwrap();
        }
        None => {
            e.null().unwrap();
        }
    }
    e.u64(u.fee).unwrap().array(u.inputs.len() as u64).unwrap();
    for (p, payer) in &u.inputs {
        e.array(3).unwrap().bytes(&p.transaction).unwrap().u32(p.index).unwrap().u8(*payer as u8).unwrap();
    }
    e.array(u.outputs.len() as u64).unwrap();
    for o in &u.outputs {
        e.array(2).unwrap().bytes(&o.owner).unwrap().u64(o.atoms).unwrap();
    }
    e.into_writer()
}
fn raw_tx(version: u8, tag: u8, unsigned: &[u8], slots: [Option<&HybridSignature>; 4]) -> Vec<u8> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(7).unwrap().u8(version).unwrap().u8(tag).unwrap().bytes(unsigned).unwrap();
    for slot in slots {
        match slot {
            Some(s) => {
                e.array(2).unwrap().bytes(&s.ed448).unwrap().bytes(&s.fndsa).unwrap();
            }
            None => {
                e.null().unwrap();
            }
        }
    }
    e.into_writer()
}
fn slots(tx: &FundedRotation) -> [Option<&HybridSignature>; 4] {
    [Some(&tx.authorize), Some(&tx.possession), tx.authority_funding.as_ref(), tx.sponsor_funding.as_ref()]
}

// =============================================================================================
// 14.2 rows
// =============================================================================================

/// 14.2 `self_funded_bundle_rotates_and_pays_atomically`: one item rotates the (unregistered,
/// generation-one) authority, consumes its funding, creates the outputs and pays exactly its declared
/// fee to the licensed owner's coinbase; the old key loses authority over the lineage's coins; the
/// chain replays identically from Genesis.
#[test]
fn self_funded_bundle_rotates_and_pays_atomically() {
    let k = keys();
    let (a1, a2) = (k.a1.key(), k.a2.key());
    let authority = addr(a1, 1);
    let mut rig = rig("wpr-self", &[(0xa1, authority, BIG), (0xa2, authority, BIG)]);
    let s1 = rig.step(1, &[]);
    assert!(s1.wallets.current(authority).is_none(), "the authority starts unregistered");
    let mut p = plan(&rig.parent, authority, (a1, 1), (a2, 2));
    p.inputs = vec![(point(0xa1), Payer::RotatingAuthority)];
    p.outputs = vec![Output { owner: DEST, atoms: 1_000_000 }, Output { owner: addr(a2, 2), atoms: BIG - 1_000_000 - FEE }];
    let tx = p.sign();
    let raw = wire(&tx);
    assert_eq!(fr::signed_len(&tx.unsigned).unwrap(), raw.len(), "signed_len predicts the complete length");
    assert!((raw.len() as u64) <= FEE && raw.len() > 8_000, "1 atom per complete signed byte: {}", raw.len());
    assert_eq!(Transaction::decode(&raw).unwrap(), ftx(&tx));
    let s2 = include(&mut rig, 2, &[ftx(&tx)]);
    assert_eq!(s2.wallets.current(authority), Some(desc(a2, 2).as_slice()), "generation g + 1 is current");
    assert!(!s2.coins.contains_key(&point(0xa1)), "the funding input is consumed");
    assert_eq!(s2.coins[&out(&tx, 0)], Coin { output: Output { owner: DEST, atoms: 1_000_000 }, created_height: 2, coinbase: false });
    assert_eq!(s2.coins[&out(&tx, 1)].output, Output { owner: addr(a2, 2), atoms: BIG - 1_000_000 - FEE });
    assert_eq!(coinbase_at(&s2, 2), SUBSIDY + FEE, "the declared fee goes to the licensed owner's coinbase");
    assert_eq!(total(&s2), total(&s1) + SUBSIDY, "value is conserved");
    // The retired key no longer authorizes the lineage's old-address coin; the new key does.
    let by_old = transfer(&rig.f, a1, 1, point(0xa2), 7_000, vec![Output { owner: DEST, atoms: BIG - 7_000 }]);
    assert!(matches!(rig.pool.admit(&by_old, &rig.parent, &rig.state), Err(PoolError::Invalid(TxError::Owner))));
    let by_new = transfer(&rig.f, a2, 2, point(0xa2), 7_000, vec![Output { owner: DEST, atoms: BIG - 7_000 }]);
    let s3 = include(&mut rig, 3, &[by_new]);
    assert!(!s3.coins.contains_key(&point(0xa2)));
    // Durable replay from trusted Genesis re-executes the bundle and reproduces the state exactly.
    let before = rig.state.clone();
    let rig = rig.restart();
    assert_eq!(rig.state, before);
    assert_eq!(rig.state.root().unwrap(), before.root().unwrap());
    rig.finish();
}

/// 14.2 `explicit_sponsor_bundle_executes`: an explicitly reviewed sponsor funds part of the rotation
/// (both payers sign the same commitment), and a sponsored-only bundle (the rotating authority pays
/// nothing, so no `authority_funding`) also executes. The sponsor's generation-one descriptor is
/// registered like any paying wallet's.
#[test]
fn explicit_sponsor_bundle_executes() {
    let k = keys();
    let (a1, a2, b1, b2, s1) = (k.a1.key(), k.a2.key(), k.b1.key(), k.b2.key(), k.s1.key());
    let (authority, sponsor) = (addr(a1, 1), addr(s1, 1));
    let mut rig = rig("wpr-sponsor", &[(0xa1, authority, BIG), (0x51, sponsor, BIG), (0x52, sponsor, BIG)]);
    rig.step(1, &[]);
    let mut p = plan(&rig.parent, authority, (a1, 1), (a2, 2));
    p.sponsor = Some((sponsor, s1, 1));
    p.inputs = vec![(point(0xa1), Payer::RotatingAuthority), (point(0x51), Payer::Sponsor)];
    p.outputs = vec![Output { owner: sponsor, atoms: BIG - 3_000_000 }, Output { owner: addr(a2, 2), atoms: BIG + 3_000_000 - FEE }];
    let tx = p.sign();
    assert!(tx.authority_funding.is_some() && tx.sponsor_funding.is_some());
    let s2 = include(&mut rig, 2, &[ftx(&tx)]);
    assert_eq!(s2.wallets.current(authority), Some(desc(a2, 2).as_slice()));
    assert!(!s2.coins.contains_key(&point(0xa1)) && !s2.coins.contains_key(&point(0x51)));
    assert_eq!(s2.coins[&out(&tx, 0)].output, Output { owner: sponsor, atoms: BIG - 3_000_000 });
    assert_eq!(s2.coins[&out(&tx, 1)].output, Output { owner: addr(a2, 2), atoms: BIG + 3_000_000 - FEE });
    assert_eq!(s2.wallets.current(sponsor), Some(desc(s1, 1).as_slice()), "the paying sponsor is registered");
    assert_eq!(coinbase_at(&s2, 2), SUBSIDY + FEE);
    // Sponsored-only: B (unregistered, no coins) rotates; the sponsor pays everything.
    let b = addr(b1, 1);
    let mut q = plan(&rig.parent, b, (b1, 1), (b2, 2));
    q.sponsor = Some((sponsor, s1, 1));
    q.inputs = vec![(point(0x52), Payer::Sponsor)];
    q.outputs = vec![Output { owner: sponsor, atoms: BIG - FEE }];
    let only = q.sign();
    assert!(only.authority_funding.is_none() && only.sponsor_funding.is_some());
    let s3 = include(&mut rig, 3, &[ftx(&only)]);
    assert_eq!(s3.wallets.current(b), Some(desc(b2, 2).as_slice()));
    assert_eq!(s3.coins[&out(&only, 0)].output, Output { owner: sponsor, atoms: BIG - FEE });
    let rig = rig.restart();
    assert_eq!(rig.state.wallets.current(b), Some(desc(b2, 2).as_slice()));
    rig.finish();
}

/// 14.2 `stripped_funding_rejects`: no inputs is unrepresentable (codec `Bounds`); removing the
/// sponsor, an input or changing an output changes the commitment (`Signature`); a dropped funding
/// signature and an unrequired one are `Signature`. Every case: exact error, identical records; the
/// sponsor-removed block is also refused by `commit` with the store byte-identical.
#[test]
fn stripped_funding_rejects() {
    let k = keys();
    let (a1, a2, s1) = (k.a1.key(), k.a2.key(), k.s1.key());
    let (authority, sponsor) = (addr(a1, 1), addr(s1, 1));
    let mut rig = rig("wpr-strip", &[(0xa1, authority, BIG), (0xa2, authority, BIG), (0x51, sponsor, BIG)]);
    rig.step(1, &[]);
    let mut p = plan(&rig.parent, authority, (a1, 1), (a2, 2));
    p.sponsor = Some((sponsor, s1, 1));
    p.inputs = vec![(point(0xa1), Payer::RotatingAuthority), (point(0xa2), Payer::RotatingAuthority), (point(0x51), Payer::Sponsor)];
    p.outputs = vec![Output { owner: sponsor, atoms: BIG - 1_000_000 }, Output { owner: addr(a2, 2), atoms: 2 * BIG + 1_000_000 - FEE }];
    let full = p.sign();
    let none = History::default();
    // Control: the complete bundle is valid in this very block.
    execute(&rig, &block(&rig, 2, &[wire(&full)], FEE), &none).expect("the complete bundle is valid");
    // No inputs at all: unrepresentable, and the crafted raw item fails decoding inside a block.
    let mut empty = full.unsigned.clone();
    empty.inputs.clear();
    empty.sponsor = None;
    assert_eq!(empty.encode(), Err(TxError::Bounds));
    let raw = raw_tx(2, 25, &raw_unsigned(&empty, NETWORK_ID), [Some(&full.authorize), Some(&full.possession), None, None]);
    assert_eq!(Transaction::decode(&raw), Err(TxError::Bounds));
    assert_eq!(rejected(&rig, 2, &[raw.clone()], FEE, &none), TxError::Bounds);
    assert_eq!(commit_rejected(&mut rig, 2, &[raw], FEE), TxError::Bounds);
    // Sponsor removed (with its input and signature): the old key signed a different commitment.
    let mut v = full.clone();
    v.unsigned.sponsor = None;
    v.unsigned.inputs.retain(|(_, payer)| *payer == Payer::RotatingAuthority);
    v.sponsor_funding = None;
    assert_eq!(v.verify_signatures(), Err(TxError::Signature));
    assert_eq!(rejected(&rig, 2, &[wire(&v)], FEE, &none), TxError::Signature);
    assert_eq!(commit_rejected(&mut rig, 2, &[wire(&v)], FEE), TxError::Signature);
    // One input removed.
    let mut v = full.clone();
    v.unsigned.inputs.retain(|(pt, _)| *pt != point(0xa2));
    assert_eq!(rejected(&rig, 2, &[wire(&v)], FEE, &none), TxError::Signature);
    // An output changed (conservation kept, so only the signatures can refuse it).
    let mut v = full.clone();
    v.unsigned.outputs[0].atoms -= 1;
    v.unsigned.outputs[1].atoms += 1;
    assert_eq!(rejected(&rig, 2, &[wire(&v)], FEE, &none), TxError::Signature);
    // A required funding signature dropped.
    let mut v = full.clone();
    v.authority_funding = None;
    assert_eq!(rejected(&rig, 2, &[wire(&v)], FEE, &none), TxError::Signature);
    let mut v = full.clone();
    v.sponsor_funding = None;
    assert_eq!(rejected(&rig, 2, &[wire(&v)], FEE, &none), TxError::Signature);
    // The possession slot alone wrong (every other signature valid): a different key, or corrupted.
    let c = full.unsigned.commitment().unwrap();
    let mut v = full.clone();
    v.possession = a1.sign(Domain::WalletRotatePossession, &fr::possession_payload(&c)).unwrap();
    assert_eq!(v.verify_signatures(), Err(TxError::Signature), "possession by the old key");
    assert_eq!(rejected(&rig, 2, &[wire(&v)], FEE, &none), TxError::Signature);
    let mut v = full.clone();
    v.possession.ed448[3] ^= 1;
    assert_eq!(rejected(&rig, 2, &[wire(&v)], FEE, &none), TxError::Signature);
    // Exact conservation of a correctly signed bundle: neither overpaid (value would vanish) nor
    // underfunded.
    for (delta_name, delta) in [("overpaid", -1i64), ("underfunded", 1i64)] {
        let mut q = plan(&rig.parent, authority, (a1, 1), (a2, 2));
        q.inputs = vec![(point(0xa1), Payer::RotatingAuthority)];
        q.outputs = vec![Output { owner: addr(a2, 2), atoms: (BIG as i64 - FEE as i64 + delta) as u64 }];
        assert_eq!(rejected(&rig, 2, &[wire(&q.sign())], FEE, &none), TxError::Conservation, "{delta_name}");
    }
    // An unrequired funding signature (no sponsor named) is refused too.
    let mut q = plan(&rig.parent, authority, (a1, 1), (a2, 2));
    q.inputs = vec![(point(0xa1), Payer::RotatingAuthority)];
    q.outputs = vec![Output { owner: addr(a2, 2), atoms: BIG - FEE }];
    let mut v = q.sign();
    v.sponsor_funding = Some(full.sponsor_funding.clone().unwrap());
    assert_eq!(v.verify_signatures(), Err(TxError::Signature));
    assert_eq!(rejected(&rig, 2, &[wire(&v)], FEE, &none), TxError::Signature);
    assert_eq!(rig.height(), 1);
    rig.finish();
}

/// 14.2 `sponsor_substitution_rejects_at_authority_signature`: an attacker who replaces the sponsor
/// and its inputs, re-signs `sponsor_funding` AND obtains a fresh possession signature from a
/// colluding new-key holder still fails: the OLD key's `authorize` covers the original sponsor. The
/// same forged bundle with a fresh `authorize` from the old key verifies, so `authorize` is exactly
/// the signature that refuses it.
#[test]
fn sponsor_substitution_rejects_at_authority_signature() {
    let k = keys();
    let (a1, a2, s1, x) = (k.a1.key(), k.a2.key(), k.s1.key(), k.x.key());
    let (authority, sponsor, attacker) = (addr(a1, 1), addr(s1, 1), addr(x, 1));
    let mut rig = rig("wpr-subst", &[(0xa1, authority, BIG), (0x51, sponsor, BIG), (0x71, attacker, BIG)]);
    rig.step(1, &[]);
    // A sponsored-only plan: the rotating authority contributes no input, so `authorize` is its only
    // signature over the plan.
    let mut p = plan(&rig.parent, authority, (a1, 1), (a2, 2));
    p.sponsor = Some((sponsor, s1, 1));
    p.inputs = vec![(point(0x51), Payer::Sponsor)];
    p.outputs = vec![Output { owner: addr(a2, 2), atoms: 1_000_000 }, Output { owner: sponsor, atoms: BIG - 1_000_000 - FEE }];
    let genuine = p.sign();
    let mut forged = genuine.clone();
    forged.unsigned.sponsor = Some((attacker, desc(x, 1)));
    forged.unsigned.inputs = vec![(point(0x71), Payer::Sponsor)];
    forged.unsigned.outputs = vec![Output { owner: addr(a2, 2), atoms: 1_000_000 }, Output { owner: attacker, atoms: BIG - 1_000_000 - FEE }];
    let c = forged.unsigned.commitment().unwrap();
    assert_ne!(c, genuine.unsigned.commitment().unwrap(), "the sponsor is bound by the commitment");
    forged.possession = a2.sign(Domain::WalletRotatePossession, &fr::possession_payload(&c)).unwrap();
    forged.sponsor_funding = Some(x.sign(Domain::Transaction, &fr::funding_payload(&c, Payer::Sponsor)).unwrap());
    assert_eq!(forged.verify_signatures(), Err(TxError::Signature));
    let none = History::default();
    assert_eq!(rejected(&rig, 2, &[wire(&forged)], FEE, &none), TxError::Signature);
    assert_eq!(commit_rejected(&mut rig, 2, &[wire(&forged)], FEE), TxError::Signature);
    let mut repaired = forged.clone();
    repaired.authorize = a1.sign(Domain::WalletRotate, &fr::authorize_payload(&c)).unwrap();
    repaired.verify_signatures().expect("every other slot of the forged bundle is valid");
    execute(&rig, &block(&rig, 2, &[wire(&repaired)], FEE), &none).expect("only the old key's authorize was missing");
    // With a payer-0 input as well, both of the old key's signatures cover the original sponsor.
    let mut both = plan(&rig.parent, authority, (a1, 1), (a2, 2));
    both.sponsor = Some((sponsor, s1, 1));
    both.inputs = vec![(point(0xa1), Payer::RotatingAuthority), (point(0x51), Payer::Sponsor)];
    both.outputs = vec![Output { owner: addr(a2, 2), atoms: 2 * BIG - FEE }];
    let mut forged = both.sign();
    forged.unsigned.sponsor = Some((attacker, desc(x, 1)));
    forged.unsigned.inputs = vec![(point(0x71), Payer::Sponsor), (point(0xa1), Payer::RotatingAuthority)];
    forged.unsigned.inputs.sort();
    let c = forged.unsigned.commitment().unwrap();
    forged.sponsor_funding = Some(x.sign(Domain::Transaction, &fr::funding_payload(&c, Payer::Sponsor)).unwrap());
    assert_eq!(rejected(&rig, 2, &[wire(&forged)], FEE, &none), TxError::Signature);
    rig.finish();
}

/// 14.2 `standalone_funding_replay_impossible`: a funding signature verifies only over
/// `[FUNDING-V2, commitment, payer]`: as a Transfer input signature (even for the bundle's own coin)
/// and inside another bundle it is `Signature`; after execution the bundle replays as `Owner` (stale
/// generation), its spent inputs as `MissingInput`, and the pool reports its recorded status.
#[test]
fn standalone_funding_replay_impossible() {
    let k = keys();
    let (a1, a2, a3) = (k.a1.key(), k.a2.key(), k.a3.key());
    let authority = addr(a1, 1);
    let mut rig = rig("wpr-replay", &[(0xa1, authority, BIG), (0xa2, authority, BIG)]);
    rig.step(1, &[]);
    let signed_at = rig.parent.clone();
    let mut anchors = History::default();
    anchors.insert_anchor(signed_at.height, signed_at.block).unwrap();
    let mut p = plan(&rig.parent, authority, (a1, 1), (a2, 2));
    p.inputs = vec![(point(0xa1), Payer::RotatingAuthority)];
    p.outputs = vec![Output { owner: addr(a2, 2), atoms: BIG - FEE }];
    let tx = p.sign();
    let funding = tx.authority_funding.clone().unwrap();
    let none = History::default();
    for spent in [point(0xa2), point(0xa1)] {
        let mut t = Transfer {
            network: NETWORK_ID,
            genesis: rig.f.genesis.genesis,
            fingerprint: rig.f.genesis.fingerprint,
            created_height: 1,
            expiry_height: 100,
            fee: 7_000,
            inputs: vec![Input::unsigned(spent, a1.public(), 1).unwrap()],
            outputs: vec![Output { owner: DEST, atoms: BIG - 7_000 }],
        };
        t.inputs[0].signature = funding.clone();
        assert_eq!(t.verify_signatures(), Err(TxError::Signature));
        let raw = Transaction::Transfer(t).encode().unwrap();
        assert_eq!(rejected(&rig, 2, &[raw], 7_000, &none), TxError::Signature);
    }
    // Lifted into a different bundle of the same authority.
    let mut other = plan(&rig.parent, authority, (a1, 1), (a2, 2));
    other.inputs = vec![(point(0xa1), Payer::RotatingAuthority)];
    other.outputs = vec![Output { owner: DEST, atoms: BIG - FEE }];
    let mut lifted = other.sign();
    lifted.authority_funding = Some(funding.clone());
    assert_eq!(rejected(&rig, 2, &[wire(&lifted)], FEE, &none), TxError::Signature);
    // Execute, then replay.
    include(&mut rig, 2, &[ftx(&tx)]);
    assert_eq!(rejected(&rig, 3, &[wire(&tx)], FEE, &anchors), TxError::Owner, "the old descriptor is no longer current");
    assert_eq!(rejected(&rig, 3, &[wire(&tx)], FEE, &none), TxError::Binding, "without the anchor: fail closed first");
    assert_eq!(rig.pool.admit(&ftx(&tx), &rig.parent, &rig.state).unwrap(), Status::Confirmed, "never re-queued");
    // The current key cannot spend the consumed input again.
    let mut again = plan(&rig.parent, authority, (a2, 2), (a3, 3));
    again.inputs = vec![(point(0xa1), Payer::RotatingAuthority)];
    again.outputs = vec![Output { owner: addr(a3, 3), atoms: BIG - FEE }];
    assert_eq!(rejected(&rig, 3, &[wire(&again.sign())], FEE, &none), TxError::MissingInput);
    rig.finish();
}

/// 14.2 `old_rotate_wrapper_rejected`: the retired `[2, 21, rotation, transfer]` wrapper is
/// `TxError::Codec` at decoding, in a real block (executor and `commit`), and the pool cannot hold it.
#[test]
fn old_rotate_wrapper_rejected() {
    let k = keys();
    let (a1, a2) = (k.a1.key(), k.a2.key());
    let authority = addr(a1, 1);
    let mut rig = rig("wpr-wrapper", &[(0xa1, authority, BIG)]);
    rig.step(1, &[]);
    let mut rotation = Rotation {
        network: NETWORK_ID,
        genesis: rig.f.genesis.genesis,
        fingerprint: rig.f.genesis.fingerprint,
        authority,
        current: desc(a1, 1),
        proposed: desc(a2, 2),
        created_height: 1,
        expiry_height: 100,
        authorization: empty(),
        possession: empty(),
    };
    rotation.sign(a1, a2).unwrap();
    let Transaction::Transfer(funding) = transfer(&rig.f, a2, 2, point(0xa1), 30_000, vec![Output { owner: addr(a2, 2), atoms: BIG - 30_000 }]) else {
        unreachable!()
    };
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(4).unwrap().u8(2).unwrap().u8(21).unwrap();
    e.bytes(&rotation.encode().unwrap()).unwrap().bytes(&funding.encode().unwrap()).unwrap();
    let old = e.into_writer();
    assert_eq!(Transaction::decode(&old), Err(TxError::Codec));
    let none = History::default();
    assert_eq!(rejected(&rig, 2, &[old.clone()], 30_000, &none), TxError::Codec);
    assert_eq!(commit_rejected(&mut rig, 2, &[old.clone()], 30_000), TxError::Codec);
    // Neither does an array(7) with the old tag decode, nor a partial exchange object as a transaction.
    let mut p = plan(&rig.parent, authority, (a1, 1), (a2, 2));
    p.inputs = vec![(point(0xa1), Payer::RotatingAuthority)];
    p.outputs = vec![Output { owner: addr(a2, 2), atoms: BIG - FEE }];
    let tx = p.sign();
    let body = tx.unsigned.encode().unwrap();
    assert_eq!(Transaction::decode(&raw_tx(2, 21, &body, slots(&tx))), Err(TxError::Codec));
    assert_eq!(Transaction::decode(&PartialRotation::new(tx.unsigned.clone()).encode().unwrap()), Err(TxError::Codec));
    // The pool: its only entry is a decoded Transaction; a row injected with the old bytes makes every
    // read of the pending set fail instead of carrying it.
    let db = rusqlite::Connection::open(rig.base.join("pool.sqlite")).unwrap();
    db.execute("INSERT INTO lifecycle_v2 VALUES(?1,?2,'PENDING')", rusqlite::params![[0x99u8; 32].as_slice(), old]).unwrap();
    assert!(matches!(rig.pool.pending(), Err(PoolError::Invalid(TxError::Codec))));
    assert!(matches!(rig.pool.pending_at(&rig.parent, &rig.state), Err(PoolError::Invalid(TxError::Codec))));
    db.execute("DELETE FROM lifecycle_v2 WHERE id=?1", [[0x99u8; 32].as_slice()]).unwrap();
    drop(db);
    assert!(rig.pool.pending().unwrap().is_empty());
    rig.finish();
}

/// 14.2 `competing_bundles_second_fails` (+ AM-11 same-block combinations): two bundles for the same
/// `(authority, g)`: the pool keeps the first; a block with both is invalid (`Owner`, store
/// byte-identical); after the first executes the second is a stale generation (`Owner`). Two
/// SEQUENTIAL rotations of one authority (g -> g+1 -> g+2) in one block are valid in that order and
/// invalid in the reverse order.
#[test]
fn competing_bundles_second_fails() {
    let k = keys();
    let (a1, a2, a3, a4) = (k.a1.key(), k.a2.key(), k.a3.key(), k.a4.key());
    let authority = addr(a1, 1);
    let mut rig = rig("wpr-compete", &[(0xa1, authority, BIG), (0xa2, authority, BIG), (0xa3, authority, BIG)]);
    rig.step(1, &[]);
    let rotate = |rig: &Rig, old: (&HybridKey, u64), new: (&HybridKey, u64), input: u8| {
        let mut p = plan(&rig.parent, authority, old, new);
        p.inputs = vec![(point(input), Payer::RotatingAuthority)];
        p.outputs = vec![Output { owner: addr(new.0, new.1), atoms: BIG - FEE }];
        p.sign()
    };
    let first = rotate(&rig, (a1, 1), (a2, 2), 0xa1);
    let rival = rotate(&rig, (a1, 1), (a4, 2), 0xa2);
    let none = History::default();
    let mut anchors = History::default();
    anchors.insert_anchor(rig.parent.height, rig.parent.block).unwrap();
    assert_eq!(rejected(&rig, 2, &[wire(&first), wire(&rival)], 2 * FEE, &none), TxError::Owner);
    assert_eq!(commit_rejected(&mut rig, 2, &[wire(&first), wire(&rival)], 2 * FEE), TxError::Owner);
    // Pool: one pending rotation per authority, first seen wins.
    assert_eq!(rig.pool.admit(&ftx(&first), &rig.parent, &rig.state).unwrap(), Status::Pending);
    assert!(matches!(rig.pool.admit(&ftx(&rival), &rig.parent, &rig.state), Err(PoolError::Conflict)));
    let s2 = rig.step(2, &[]);
    assert_eq!(s2.wallets.current(authority), Some(desc(a2, 2).as_slice()));
    assert_eq!(rejected(&rig, 3, &[wire(&rival)], FEE, &anchors), TxError::Owner, "stale generation after the first");
    // Sequential g -> g+1 -> g+2 in one block: valid in order, invalid reversed.
    let next = rotate(&rig, (a2, 2), (a3, 3), 0xa2);
    let after = rotate(&rig, (a3, 3), (a4, 4), 0xa3);
    assert_eq!(rejected(&rig, 3, &[wire(&after), wire(&next)], 2 * FEE, &none), TxError::Owner);
    let s3 = commit_block(&mut rig, 3, &[wire(&next), wire(&after)], 2 * FEE);
    assert_eq!(s3.wallets.current(authority), Some(desc(a4, 4).as_slice()));
    assert_eq!(coinbase_at(&s3, 3), SUBSIDY + 2 * FEE);
    let rig = rig.restart();
    assert_eq!(rig.state.wallets.current(authority), Some(desc(a4, 4).as_slice()));
    rig.finish();
}

/// 14.2 `bundle_valid_across_head_advance_within_window`: signed at head h (reference h, window
/// [h+1, h+11]) and included at h+4 with the canonical anchor of h supplied through `History`. The
/// same block without the anchor (no store supplies it) fails closed (`Binding`, exactly
/// `ReferenceNotCanonical`). The pool admits it with the anchor and keeps it pending as the head
/// advances (reconciliation does not re-evaluate the finalized reference), then expires it.
#[test]
fn bundle_valid_across_head_advance_within_window() {
    let k = keys();
    let (a1, a2) = (k.a1.key(), k.a2.key());
    let authority = addr(a1, 1);
    let mut rig = rig("wpr-advance", &[(0xa1, authority, BIG)]);
    rig.step(1, &[]);
    let signed_at = rig.parent.clone();
    let mut p = plan(&signed_at, authority, (a1, 1), (a2, 2));
    p.inputs = vec![(point(0xa1), Payer::RotatingAuthority)];
    p.outputs = vec![Output { owner: addr(a2, 2), atoms: BIG - FEE }];
    let tx = p.sign();
    for epoch in 2..=4 {
        rig.step(epoch, &[]);
    }
    assert_eq!(rig.height(), 4);
    let mut anchors = History::default();
    anchors.insert_anchor(signed_at.height, signed_at.block).unwrap();
    let executed = execute(&rig, &block(&rig, 5, &[wire(&tx)], FEE), &anchors).expect("valid at h+4 inside the window");
    assert_eq!(executed.state.wallets.current(authority), Some(desc(a2, 2).as_slice()));
    assert_eq!(executed.state.coins[&out(&tx, 0)].created_height, 5);
    let none = History::default();
    assert_eq!(rejected(&rig, 5, &[wire(&tx)], FEE, &none), TxError::Binding, "no anchor: fail closed");
    assert_eq!(tx.unsigned.check_envelope(&rig.parent, &none, &rig.state), Err(EnvelopeError::ReferenceNotCanonical));
    assert_eq!(tx.unsigned.check_envelope(&rig.parent, &anchors, &rig.state), Ok(()));
    // Pool: refused without the anchor, admitted with it, kept pending across further heights.
    assert!(matches!(rig.pool.admit(&ftx(&tx), &rig.parent, &rig.state), Err(PoolError::Invalid(TxError::Binding))));
    assert_eq!(rig.pool.admit_with_history(&ftx(&tx), &rig.parent, &rig.state, &anchors).unwrap(), Status::Pending);
    assert_eq!(rig.pool.pending_reference_heights().unwrap(), [signed_at.height].into_iter().collect());
    // A block that does not include it: reconciliation keeps it pending (its finalized reference
    // was verified at admission and is not re-evaluated), never rejected or rewritten.
    commit_block(&mut rig, 5, &[], 0);
    assert_eq!(rig.pool.status(id(&tx)).unwrap(), Some(Status::Pending), "still pending at height 5");
    assert_eq!(rig.pool.pending().unwrap(), vec![ftx(&tx)]);
    // prepare_pending takes the pool's reference heights (PendingReferences hook, WP-P0 stage 2),
    // so the production assembler includes the head-advanced bundle; commit derives the same anchor
    // from the block itself.
    let s6 = rig.step(6, &[]);
    assert_eq!(rig.chain.confirmed_height(id(&tx)).unwrap(), Some(6));
    assert_eq!(rig.pool.status(id(&tx)).unwrap(), Some(Status::Confirmed));
    assert_eq!(s6.wallets.current(authority), Some(desc(a2, 2).as_slice()));
    assert!(!s6.coins.contains_key(&point(0xa1)));
    rig.finish();
}

/// Store-level counterpart of the previous test: once `CanonicalStore::operation_history` supplies the
/// referenced anchors (WP-P0 stage 2, amendment AM-4), the same head-advanced bundle commits and
/// replays (the store builds the History in commit and in verify_replay).
#[test]
fn head_advanced_bundle_commits_and_replays_once_the_store_supplies_anchors() {
    let k = keys();
    let (a1, a2) = (k.a1.key(), k.a2.key());
    let authority = addr(a1, 1);
    let mut rig = rig("wpr-advance-store", &[(0xa1, authority, BIG)]);
    rig.step(1, &[]);
    let mut p = plan(&rig.parent, authority, (a1, 1), (a2, 2));
    p.inputs = vec![(point(0xa1), Payer::RotatingAuthority)];
    p.outputs = vec![Output { owner: addr(a2, 2), atoms: BIG - FEE }];
    let tx = p.sign();
    for epoch in 2..=4 {
        rig.step(epoch, &[]);
    }
    let s = commit_block(&mut rig, 5, &[wire(&tx)], FEE);
    assert_eq!(s.wallets.current(authority), Some(desc(a2, 2).as_slice()));
    let rig = rig.restart();
    assert_eq!(rig.state.wallets.current(authority), Some(desc(a2, 2).as_slice()));
    rig.finish();
}

/// 14.2 `bundle_after_last_height_rejected` (and the window's other end): included after
/// `last_height` is `Expired`, before `first_height` is `Future`; exact errors, identical records,
/// and `commit` refuses the expired block with the store byte-identical.
#[test]
fn bundle_after_last_height_rejected() {
    let k = keys();
    let (a1, a2) = (k.a1.key(), k.a2.key());
    let authority = addr(a1, 1);
    let mut rig = rig("wpr-expiry", &[(0xa1, authority, BIG)]);
    rig.step(1, &[]);
    let signed_at = rig.parent.clone();
    let mut p = plan(&signed_at, authority, (a1, 1), (a2, 2));
    p.validity = 1; // window [2, 3]
    p.inputs = vec![(point(0xa1), Payer::RotatingAuthority)];
    p.outputs = vec![Output { owner: addr(a2, 2), atoms: BIG - FEE }];
    let tx = p.sign();
    let mut late = tx.unsigned.clone();
    late.envelope.first_height = 3;
    late.envelope.last_height = 4;
    let future = sign(late, a1, a2, None);
    let mut anchors = History::default();
    anchors.insert_anchor(signed_at.height, signed_at.block).unwrap();
    assert_eq!(rejected(&rig, 2, &[wire(&future)], FEE, &anchors), TxError::Future, "inclusion at 2 < first 3");
    for epoch in 2..=3 {
        rig.step(epoch, &[]);
    }
    assert_eq!(rig.height(), 3);
    assert_eq!(rejected(&rig, 4, &[wire(&tx)], FEE, &anchors), TxError::Expired, "inclusion at 4 > last 3");
    assert_eq!(rejected(&rig, 4, &[wire(&tx)], FEE, &History::default()), TxError::Expired, "the window precedes the reference check");
    assert_eq!(commit_rejected(&mut rig, 4, &[wire(&tx)], FEE), TxError::Expired);
    assert_eq!(tx.unsigned.check_envelope(&rig.parent, &anchors, &rig.state), Err(EnvelopeError::Expired));
    rig.finish();
}

/// Reference not canonical: a reference to the parent height with another block hash, or an older
/// reference whose anchor differs from the canonical one, is `Binding` (exactly
/// `ReferenceNotCanonical`), refused by `commit` with the store byte-identical.
#[test]
fn reference_not_canonical_rejected() {
    let k = keys();
    let (a1, a2) = (k.a1.key(), k.a2.key());
    let authority = addr(a1, 1);
    let mut rig = rig("wpr-reference", &[(0xa1, authority, BIG)]);
    rig.step(1, &[]);
    let older = rig.parent.clone();
    rig.step(2, &[]);
    let mut forged_head = rig.parent.clone();
    forged_head.block = [0xee; 32];
    let mut p = plan(&forged_head, authority, (a1, 1), (a2, 2));
    p.inputs = vec![(point(0xa1), Payer::RotatingAuthority)];
    p.outputs = vec![Output { owner: addr(a2, 2), atoms: BIG - FEE }];
    let tx = p.sign();
    let none = History::default();
    assert_eq!(rejected(&rig, 3, &[wire(&tx)], FEE, &none), TxError::Binding);
    assert_eq!(tx.unsigned.check_envelope(&rig.parent, &none, &rig.state), Err(EnvelopeError::ReferenceNotCanonical));
    assert_eq!(commit_rejected(&mut rig, 3, &[wire(&tx)], FEE), TxError::Binding);
    // An older reference: the supplied anchor must be the canonical block at that height.
    let mut p = plan(&older, authority, (a1, 1), (a2, 2));
    p.inputs = vec![(point(0xa1), Payer::RotatingAuthority)];
    p.outputs = vec![Output { owner: addr(a2, 2), atoms: BIG - FEE }];
    let tx = p.sign();
    let mut wrong = History::default();
    wrong.insert_anchor(older.height, [0xef; 32]).unwrap();
    assert_eq!(rejected(&rig, 3, &[wire(&tx)], FEE, &wrong), TxError::Binding);
    let mut right = History::default();
    right.insert_anchor(older.height, older.block).unwrap();
    execute(&rig, &block(&rig, 3, &[wire(&tx)], FEE), &right).expect("the canonical anchor verifies");
    rig.finish();
}

/// 14.2 brief rows: unregistered-authority registration rule and stale generations (`Owner`).
#[test]
fn authority_registration_rule_and_stale_generation() {
    let k = keys();
    let (a1, a2, a3, x) = (k.a1.key(), k.a2.key(), k.a3.key(), k.x.key());
    let authority = addr(a1, 1);
    let mut rig = rig("wpr-authority", &[(0xa1, authority, BIG), (0xa2, authority, BIG)]);
    rig.step(1, &[]);
    let none = History::default();
    // An unregistered authority must be the generation-one AddressID of the current descriptor.
    let mut p = plan(&rig.parent, addr(x, 1), (a1, 1), (a2, 2));
    p.inputs = vec![(point(0xa1), Payer::RotatingAuthority)];
    p.outputs = vec![Output { owner: addr(a2, 2), atoms: BIG - FEE }];
    assert_eq!(rejected(&rig, 2, &[wire(&p.sign())], FEE, &none), TxError::Owner);
    // An unregistered authority cannot start at a later generation.
    let mut p = plan(&rig.parent, authority, (a1, 2), (a2, 3));
    p.inputs = vec![(point(0xa1), Payer::RotatingAuthority)];
    p.outputs = vec![Output { owner: addr(a2, 3), atoms: BIG - FEE }];
    assert_eq!(rejected(&rig, 2, &[wire(&p.sign())], FEE, &none), TxError::Owner);
    // Rotate once, then the retired generation cannot rotate again (stale old generation).
    let mut p = plan(&rig.parent, authority, (a1, 1), (a2, 2));
    p.inputs = vec![(point(0xa1), Payer::RotatingAuthority)];
    p.outputs = vec![Output { owner: addr(a2, 2), atoms: BIG - FEE }];
    include(&mut rig, 2, &[ftx(&p.sign())]);
    let mut stale = plan(&rig.parent, authority, (a1, 1), (a3, 2));
    stale.inputs = vec![(point(0xa2), Payer::RotatingAuthority)];
    stale.outputs = vec![Output { owner: addr(a3, 2), atoms: BIG - FEE }];
    assert_eq!(rejected(&rig, 3, &[wire(&stale.sign())], FEE, &none), TxError::Owner);
    assert_eq!(commit_rejected(&mut rig, 3, &[wire(&stale.sign())], FEE), TxError::Owner);
    rig.finish();
}

/// 14.2 brief row: a later transaction of the SAME block sees the completed rotation: the new key
/// spends an old-address coin after the bundle; the same transfer before the bundle, and the OLD key
/// after it, are refused (`Owner`): there is never simultaneous old/new authorization.
#[test]
fn same_block_later_transaction_sees_the_completed_rotation() {
    let k = keys();
    let (a1, a2) = (k.a1.key(), k.a2.key());
    let authority = addr(a1, 1);
    let mut rig = rig("wpr-sameblock", &[(0xa1, authority, BIG), (0xa2, authority, BIG)]);
    rig.step(1, &[]);
    let mut p = plan(&rig.parent, authority, (a1, 1), (a2, 2));
    p.inputs = vec![(point(0xa1), Payer::RotatingAuthority)];
    p.outputs = vec![Output { owner: addr(a2, 2), atoms: BIG - FEE }];
    let tx = p.sign();
    let pay = |key: &HybridKey, generation: u64| {
        transfer(&rig.f, key, generation, point(0xa2), 7_000, vec![Output { owner: DEST, atoms: BIG - 7_000 }]).encode().unwrap()
    };
    let (by_new, by_old) = (pay(a2, 2), pay(a1, 1));
    let none = History::default();
    assert_eq!(rejected(&rig, 2, &[by_new.clone(), wire(&tx)], FEE + 7_000, &none), TxError::Owner);
    assert_eq!(rejected(&rig, 2, &[wire(&tx), by_old], FEE + 7_000, &none), TxError::Owner);
    let s = commit_block(&mut rig, 2, &[wire(&tx), by_new], FEE + 7_000);
    assert_eq!(s.wallets.current(authority), Some(desc(a2, 2).as_slice()));
    assert!(!s.coins.contains_key(&point(0xa2)));
    assert_eq!(coinbase_at(&s, 2), SUBSIDY + FEE + 7_000);
    let rig = rig.restart();
    assert_eq!(rig.state, s);
    rig.finish();
}

/// 14.2 brief row and Order P9: third-party coins are never accepted without that wallet's own
/// signature: as a payer-0 input (`Owner`), as a sponsor input without or with a wrong
/// `sponsor_funding` (`Signature`), or a named sponsor's slot funded with another wallet's coin
/// (`Owner`).
#[test]
fn third_party_coins_need_their_owners_signature() {
    let k = keys();
    let (a1, a2, t, x) = (k.a1.key(), k.a2.key(), k.t.key(), k.x.key());
    let (authority, third) = (addr(a1, 1), addr(t, 1));
    let mut rig = rig("wpr-third", &[(0xa1, authority, BIG), (0x81, third, BIG), (0x71, addr(x, 1), BIG)]);
    rig.step(1, &[]);
    let none = History::default();
    // T's coin listed as the rotating authority's own input.
    let mut p = plan(&rig.parent, authority, (a1, 1), (a2, 2));
    p.inputs = vec![(point(0xa1), Payer::RotatingAuthority), (point(0x81), Payer::RotatingAuthority)];
    p.outputs = vec![Output { owner: addr(a2, 2), atoms: 2 * BIG - FEE }];
    assert_eq!(rejected(&rig, 2, &[wire(&p.sign())], FEE, &none), TxError::Owner);
    // T named as sponsor, but T did not sign: missing, or signed by the rotating authority's key.
    let mut q = plan(&rig.parent, authority, (a1, 1), (a2, 2));
    q.sponsor = Some((third, t, 1));
    q.inputs = vec![(point(0xa1), Payer::RotatingAuthority), (point(0x81), Payer::Sponsor)];
    q.outputs = vec![Output { owner: addr(a2, 2), atoms: 2 * BIG - FEE }];
    let signed = q.sign();
    let mut missing = signed.clone();
    missing.sponsor_funding = None;
    assert_eq!(rejected(&rig, 2, &[wire(&missing)], FEE, &none), TxError::Signature);
    let mut wrong = signed.clone();
    let c = wrong.unsigned.commitment().unwrap();
    wrong.sponsor_funding = Some(a1.sign(Domain::Transaction, &fr::funding_payload(&c, Payer::Sponsor)).unwrap());
    assert_eq!(rejected(&rig, 2, &[wire(&wrong)], FEE, &none), TxError::Signature);
    // T signs, but the "sponsor" input is X's coin.
    let mut r = plan(&rig.parent, authority, (a1, 1), (a2, 2));
    r.sponsor = Some((third, t, 1));
    r.inputs = vec![(point(0xa1), Payer::RotatingAuthority), (point(0x71), Payer::Sponsor)];
    r.outputs = vec![Output { owner: addr(a2, 2), atoms: 2 * BIG - FEE }];
    assert_eq!(rejected(&rig, 2, &[wire(&r.sign())], FEE, &none), TxError::Owner);
    // Control: properly signed by T, the bundle executes.
    execute(&rig, &block(&rig, 2, &[wire(&signed)], FEE), &none).expect("T's own signature authorizes T's coin");
    rig.finish();
}

/// 14.2 brief row: a sponsor whose wallet authority IS the rotating authority is refused. Through the
/// codec it is unrepresentable (`Bounds`); a crafted raw item is refused inside a real block. (The
/// step-5 `authority_of` rule behind it is unit-tested in `funded_rotation_v2_tests.rs`.)
#[test]
fn sponsor_equal_to_the_rotating_authority_refused() {
    let k = keys();
    let (a1, a2) = (k.a1.key(), k.a2.key());
    let authority = addr(a1, 1);
    let mut rig = rig("wpr-selfsponsor", &[(0xa1, authority, BIG), (0xa2, authority, BIG)]);
    rig.step(1, &[]);
    let mut p = plan(&rig.parent, authority, (a1, 1), (a2, 2));
    p.sponsor = Some((authority, a1, 1));
    p.inputs = vec![(point(0xa1), Payer::RotatingAuthority), (point(0xa2), Payer::Sponsor)];
    p.outputs = vec![Output { owner: addr(a2, 2), atoms: 2 * BIG - FEE }];
    let u = p.unsigned();
    assert_eq!(u.encode(), Err(TxError::Bounds));
    let zero = HybridSignature { ed448: [0; 114], fndsa: [0; 1280] };
    let raw = raw_tx(2, 25, &raw_unsigned(&u, NETWORK_ID), [Some(&zero), Some(&zero), Some(&zero), Some(&zero)]);
    assert_eq!(Transaction::decode(&raw), Err(TxError::Bounds));
    assert_eq!(rejected(&rig, 2, &[raw], FEE, &History::default()), TxError::Bounds);
    rig.finish();
}

// =============================================================================================
// AM-11 additions
// =============================================================================================

/// AM-11 (Order P9): payer-0 AND payer-1 inputs from OLDER generations of their own lineages fund a
/// bundle: the rotating authority (now at generation 2) spends a coin still held at its generation-1
/// address, and the sponsor (also rotated to generation 2) funds from its generation-1 address under
/// its current descriptor. A retired sponsor descriptor is refused (`Owner`).
#[test]
fn historic_generation_inputs_of_both_payers_fund_a_bundle() {
    let k = keys();
    let (a1, a2, a3, s1, s2) = (k.a1.key(), k.a2.key(), k.a3.key(), k.s1.key(), k.s2.key());
    let (authority, sponsor) = (addr(a1, 1), addr(s1, 1));
    let mut rig = rig(
        "wpr-historic",
        &[(0xa1, authority, BIG), (0xa2, authority, BIG), (0x51, sponsor, BIG), (0x52, sponsor, BIG)],
    );
    rig.step(1, &[]);
    let rotate = |rig: &Rig, who: Hash, old: (&HybridKey, u64), new: (&HybridKey, u64), input: u8| {
        let mut p = plan(&rig.parent, who, old, new);
        p.inputs = vec![(point(input), Payer::RotatingAuthority)];
        p.outputs = vec![Output { owner: addr(new.0, new.1), atoms: BIG - FEE }];
        ftx(&p.sign())
    };
    let first = rotate(&rig, authority, (a1, 1), (a2, 2), 0xa1);
    let sponsor_rotation = rotate(&rig, sponsor, (s1, 1), (s2, 2), 0x51);
    let s2_state = include(&mut rig, 2, &[first, sponsor_rotation]);
    assert_eq!(s2_state.wallets.current(authority), Some(desc(a2, 2).as_slice()));
    assert_eq!(s2_state.wallets.current(sponsor), Some(desc(s2, 2).as_slice()));
    // Both remaining inputs sit at generation-1 addresses of their lineages.
    let mut p = plan(&rig.parent, authority, (a2, 2), (a3, 3));
    p.sponsor = Some((sponsor, s2, 2));
    p.inputs = vec![(point(0xa2), Payer::RotatingAuthority), (point(0x52), Payer::Sponsor)];
    p.outputs = vec![Output { owner: addr(a3, 3), atoms: BIG + 500_000 }, Output { owner: addr(s2, 2), atoms: BIG - 500_000 - FEE }];
    let tx = p.sign();
    // The sponsor's retired generation-1 descriptor no longer authorizes its lineage.
    let mut retired = plan(&rig.parent, authority, (a2, 2), (a3, 3));
    retired.sponsor = Some((sponsor, s1, 1));
    retired.inputs = p.inputs.clone();
    retired.outputs = p.outputs.clone();
    assert_eq!(rejected(&rig, 3, &[wire(&retired.sign())], FEE, &History::default()), TxError::Owner);
    let s3 = include(&mut rig, 3, &[ftx(&tx)]);
    assert_eq!(s3.wallets.current(authority), Some(desc(a3, 3).as_slice()));
    assert!(!s3.coins.contains_key(&point(0xa2)) && !s3.coins.contains_key(&point(0x52)));
    assert_eq!(s3.coins[&out(&tx, 1)].output, Output { owner: addr(s2, 2), atoms: BIG - 500_000 - FEE });
    rig.finish();
}

/// AM-11 (Order P9, Q15; design 10.4-10.5): a Treasury R1 (the funded rotation of the Genesis
/// Treasury authority) that would spend reserved backing fails its block, and the would-be post-state
/// violates the reserve invariant exactly (`DivError::Backing`); an R1 that keeps the backing at the
/// reserve executes and changes no reserve. Rotation is no permission to consume the reserve.
#[test]
fn treasury_r1_cannot_spend_reserved_backing() {
    let k = keys();
    let treasury = treasury_key();
    let next = k.tn.key();
    let authority = addr(&treasury, 1);
    let mut rig = rig("wpr-r1-reserve", &[]);
    let s1 = rig.step(P, &[]);
    assert_eq!(s1.dividends.reserved(), 600_000);
    let (point_t, coin_t) = s1
        .coins
        .iter()
        .find(|(_, c)| !c.coinbase && c.output.owner == authority)
        .map(|(p, c)| (p.clone(), c.clone()))
        .unwrap();
    assert_eq!(coin_t.output.atoms, 1_200_000);
    let r1 = |keep: u64| {
        let mut p = plan(&rig.parent, authority, (&treasury, 1), (next, 2));
        p.inputs = vec![(point_t.clone(), Payer::RotatingAuthority)];
        p.outputs = vec![Output { owner: DEST, atoms: 1_200_000 - FEE - keep }, Output { owner: addr(next, 2), atoms: keep }];
        p.sign()
    };
    let draining = r1(599_999);
    let Err(error) = execute(&rig, &block(&rig, P + 1, &[wire(&draining)], FEE), &History::default()) else {
        panic!("spending reserved backing must fail the block")
    };
    assert!(matches!(error, ExecutionError::Codec(Error::WrongAnchor)), "{error:?}");
    // The would-be post-state: inputs removed, outputs created, the new address joins the lineage.
    let mut post = rig.state.clone();
    post.coins.remove(&point_t);
    for (i, o) in draining.unsigned.outputs.iter().enumerate() {
        post.coins.insert(out(&draining, i as u32), Coin { output: o.clone(), created_height: P + 1, coinbase: false });
    }
    let mut owners = post.treasury_owner_set();
    owners.insert(addr(next, 2));
    let backing = DividendState::backing(&post.coins, &owners).unwrap();
    assert_eq!(backing, 599_999);
    assert_eq!(post.dividends.ledger().check_invariants(backing), Err(DivError::Backing));
    // Exactly the reserve stays: valid; the reserve and the award are untouched.
    let keeping = r1(600_000);
    let s2 = include(&mut rig, P + 1, &[ftx(&keeping)]);
    assert_eq!(s2.wallets.current(authority), Some(desc(next, 2).as_slice()));
    assert_eq!(s2.dividends.reserved(), 600_000);
    assert_eq!(held_by(&s2, addr(next, 2)), 600_000);
    rig.finish();
}

// =============================================================================================
// Pool, partial object, codec, cross-verify matrix, source guard, vectors
// =============================================================================================

/// mempool_v2 path for the bundle (design 3.1/3.7; AM-9 m3): admission reserves the inputs AND the
/// wallet authority; first seen wins; reconciliation confirms, rejects a bundle whose authority
/// rotated, marks spent inputs, and never rewrites bytes.
#[test]
fn pool_reserves_inputs_and_authority_and_reconciles_bundles() {
    let k = keys();
    let (a1, a2, a3, b1, b2) = (k.a1.key(), k.a2.key(), k.a3.key(), k.b1.key(), k.b2.key());
    let (authority, b) = (addr(a1, 1), addr(b1, 1));
    let mut rig = rig("wpr-pool", &[(0xa1, authority, BIG), (0xa2, authority, BIG), (0xb1, b, BIG)]);
    rig.step(1, &[]);
    let bundle = |rig: &Rig, who: Hash, old: (&HybridKey, u64), new: (&HybridKey, u64), input: u8| {
        let mut p = plan(&rig.parent, who, old, new);
        p.inputs = vec![(point(input), Payer::RotatingAuthority)];
        p.outputs = vec![Output { owner: addr(new.0, new.1), atoms: BIG - FEE }];
        p.sign()
    };
    let tx = bundle(&rig, authority, (a1, 1), (a2, 2), 0xa1);
    assert_eq!(rig.pool.admit(&ftx(&tx), &rig.parent, &rig.state).unwrap(), Status::Pending);
    assert_eq!(rig.pool.admit(&ftx(&tx), &rig.parent, &rig.state).unwrap(), Status::Pending, "idempotent");
    assert_eq!(rig.pool.reserved_inputs().unwrap(), [point(0xa1)].into_iter().collect());
    // Same id, different signature bytes: a local conflict, never a replacement.
    let mut resigned = tx.clone();
    resigned.possession = a2.sign(Domain::WalletRotatePossession, &fr::possession_payload(&tx.unsigned.commitment().unwrap())).unwrap();
    assert_eq!(id(&resigned), id(&tx));
    assert!(matches!(rig.pool.admit(&ftx(&resigned), &rig.parent, &rig.state), Err(PoolError::Conflict)));
    // Input resource: a Transfer spending the reserved coin.
    let spend = transfer(&rig.f, a1, 1, point(0xa1), 7_000, vec![Output { owner: DEST, atoms: BIG - 7_000 }]);
    assert!(matches!(rig.pool.admit(&spend, &rig.parent, &rig.state), Err(PoolError::Conflict)));
    // Authority resource: another rotation of the same authority with other inputs.
    let rival = bundle(&rig, authority, (a1, 1), (a3, 2), 0xa2);
    assert!(matches!(rig.pool.admit(&ftx(&rival), &rig.parent, &rig.state), Err(PoolError::Conflict)));
    // A pending old-key payment of another coin is rejected once the rotation is final.
    let old_pay = transfer(&rig.f, a1, 1, point(0xa2), 7_000, vec![Output { owner: DEST, atoms: BIG - 7_000 }]);
    assert_eq!(rig.pool.admit(&old_pay, &rig.parent, &rig.state).unwrap(), Status::Pending);
    let other = bundle(&rig, b, (b1, 1), (b2, 2), 0xb1);
    assert_eq!(rig.pool.admit(&ftx(&other), &rig.parent, &rig.state).unwrap(), Status::Pending);
    let raw_before: Vec<Vec<u8>> = rig.pool.pending().unwrap().iter().map(|t| t.encode().unwrap()).collect();
    assert_eq!(raw_before.len(), 3);
    assert!(raw_before.contains(&wire(&tx)) && raw_before.contains(&wire(&other)), "stored bytes are the submitted bytes");
    // Both rotations become final in one block; reconciliation then sees the rotated authority.
    let s2 = commit_block(&mut rig, 2, &[wire(&tx), wire(&other)], 2 * FEE);
    assert_eq!(s2.wallets.current(authority), Some(desc(a2, 2).as_slice()));
    assert_eq!(s2.wallets.current(b), Some(desc(b2, 2).as_slice()));
    assert_eq!(rig.pool.status(id(&tx)).unwrap(), Some(Status::Confirmed));
    assert_eq!(rig.pool.status(id(&other)).unwrap(), Some(Status::Confirmed));
    assert_eq!(rig.pool.status(old_pay.id().unwrap()).unwrap(), Some(Status::Rejected), "a finalized rotation rejects pending old-key payments");
    assert!(rig.state.coins.contains_key(&point(0xa2)), "the coin itself is untouched");
    assert!(rig.pool.reserved_inputs().unwrap().is_empty());
    assert!(rig.pool.pending_reference_heights().unwrap().is_empty());
    rig.finish();
}

/// AM-9 m6 partial object and read-only preflight: canonical encoding of any subset of slots,
/// `missing`, `complete`, and a preflight that verifies every present signature (refusing a wrong
/// or unrequired one) and every state rule, but tolerates missing required signatures.
#[test]
fn partial_object_and_preflight_for_sponsor_and_new_key_review() {
    let k = keys();
    let (a1, a2, s1) = (k.a1.key(), k.a2.key(), k.s1.key());
    let (authority, sponsor) = (addr(a1, 1), addr(s1, 1));
    let mut rig = rig("wpr-partial", &[(0xa1, authority, BIG), (0x51, sponsor, BIG)]);
    rig.step(1, &[]);
    let records_before = rig.state.records().unwrap();
    let mut anchors = History::default();
    anchors.insert_anchor(rig.parent.height, rig.parent.block).unwrap();
    let mut p = plan(&rig.parent, authority, (a1, 1), (a2, 2));
    p.sponsor = Some((sponsor, s1, 1));
    p.inputs = vec![(point(0xa1), Payer::RotatingAuthority), (point(0x51), Payer::Sponsor)];
    p.outputs = vec![Output { owner: addr(a2, 2), atoms: 2 * BIG - FEE }];
    let none = History::default();
    let mut partial = PartialRotation::new(p.unsigned());
    assert_eq!(partial.missing().unwrap(), vec![Slot::Authorize, Slot::Possession, Slot::AuthorityFunding, Slot::SponsorFunding]);
    partial.preflight(&rig.state, &rig.parent, &none).expect("an unsigned plan passes every state rule");
    // The rotating wallet signs its two slots and exports the partial object.
    partial.sign(Slot::Authorize, a1).unwrap();
    partial.sign(Slot::AuthorityFunding, a1).unwrap();
    assert_eq!(partial.sign(Slot::Possession, a1), Err(TxError::Owner), "only the slot's key may sign it");
    let exported = partial.encode().unwrap();
    assert_eq!(PartialRotation::decode(&exported).unwrap(), partial);
    assert_eq!(Transaction::decode(&exported), Err(TxError::Codec), "never a transaction");
    // The sponsor and the new-key holder review it read-only.
    let mut review = PartialRotation::decode(&exported).unwrap();
    review.preflight(&rig.state, &rig.parent, &none).unwrap();
    assert_eq!(review.missing().unwrap(), vec![Slot::Possession, Slot::SponsorFunding]);
    assert_eq!(review.clone().complete(), Err(TxError::Signature), "incomplete");
    let mut tampered = review.clone();
    tampered.authorize.as_mut().unwrap().fndsa[9] ^= 1;
    assert_eq!(tampered.preflight(&rig.state, &rig.parent, &none), Err(TxError::Signature), "present signatures are verified");
    let mut own = plan(&rig.parent, authority, (a1, 1), (a2, 2));
    own.inputs = vec![(point(0xa1), Payer::RotatingAuthority)];
    own.outputs = vec![Output { owner: addr(a2, 2), atoms: BIG - FEE }];
    let mut unrequired = PartialRotation::new(own.unsigned());
    unrequired.preflight(&rig.state, &rig.parent, &none).expect("the plan itself is valid");
    unrequired.sponsor_funding = Some(review.authorize.clone().unwrap());
    assert_eq!(unrequired.preflight(&rig.state, &rig.parent, &none), Err(TxError::Signature), "no sponsor: the slot is unrequired");
    review.sign(Slot::SponsorFunding, s1).unwrap();
    review.sign(Slot::Possession, a2).unwrap();
    assert!(review.missing().unwrap().is_empty());
    let complete = review.clone().complete().unwrap();
    complete.verify_signatures().unwrap();
    assert_eq!(complete.encode().unwrap().len(), fr::signed_len(&complete.unsigned).unwrap());
    // State rules apply to a partial object exactly as to the transaction.
    let mut wrong_input = PartialRotation::new(p.unsigned());
    wrong_input.unsigned.inputs[0].0 = point(0x7f);
    wrong_input.unsigned.inputs.sort();
    assert_eq!(wrong_input.preflight(&rig.state, &rig.parent, &none), Err(TxError::MissingInput));
    let mut cheap = p.unsigned();
    cheap.fee = (fr::signed_len(&cheap).unwrap() - 1) as u64;
    cheap.outputs[0].atoms = 2 * BIG - cheap.fee;
    assert_eq!(PartialRotation::new(cheap).preflight(&rig.state, &rig.parent, &none), Err(TxError::Fee), "fee against the complete signed length");
    // Every preflight above was read-only; the completed bundle then executes.
    assert_eq!(rig.state.records().unwrap(), records_before);
    let s = include(&mut rig, 2, &[ftx(&complete)]);
    assert_eq!(s.wallets.current(authority), Some(desc(a2, 2).as_slice()));
    // After execution the same review fails on the stale generation (anchor of the signing head
    // supplied; without it, the reference check fails closed first).
    assert_eq!(review.preflight(&rig.state, &rig.parent, &anchors), Err(TxError::Owner));
    assert_eq!(review.preflight(&rig.state, &rig.parent, &none), Err(TxError::Binding));
    rig.finish();
}

/// Codec rules of design 3.2 with their exact errors, canonical-form refusals, and the binding of
/// every reviewed field (each change alters the commitment and invalidates every role signature).
#[test]
fn codec_rules_canonical_form_and_complete_binding() {
    let k = keys();
    let (a1, a2, a3, s1) = (k.a1.key(), k.a2.key(), k.a3.key(), k.s1.key());
    let head = FinalizedAnchor { network: NETWORK_ID, genesis: [1; 32], fingerprint: [2; 32], height: 9, block: [3; 32] };
    let authority = addr(a1, 1);
    let mut p = plan(&head, authority, (a1, 1), (a2, 2));
    p.sponsor = Some((addr(s1, 1), s1, 1));
    p.inputs = vec![(point(0xa1), Payer::RotatingAuthority), (point(0xa2), Payer::RotatingAuthority), (point(0x51), Payer::Sponsor)];
    p.outputs = vec![Output { owner: addr(a2, 2), atoms: 5 }, Output { owner: DEST, atoms: 6 }];
    let base = p.unsigned();
    let raw = base.encode().unwrap();
    assert_eq!(raw, raw_unsigned(&base, NETWORK_ID), "the library layout is the design 3.2 layout");
    assert_eq!(UnsignedRotation::decode(&raw).unwrap(), base);
    let rule = |f: &dyn Fn(&mut UnsignedRotation)| {
        let mut u = base.clone();
        f(&mut u);
        u.encode()
    };
    assert_eq!(rule(&|u| u.proposed_descriptor = desc(a2, 3)), Err(TxError::Owner), "generation must be g + 1");
    assert_eq!(rule(&|u| u.proposed_descriptor = desc(a1, 2)), Err(TxError::Duplicate), "both key halves change");
    let node = HybridKey::generate(Role::Node).unwrap();
    assert_eq!(rule(&|u| u.proposed_descriptor = node.public().descriptor(2).unwrap()), Err(TxError::Owner), "WalletOwner role");
    assert_eq!(rule(&|u| u.current_descriptor = vec![0x80]), Err(TxError::Codec));
    assert_eq!(rule(&|u| u.authority = [0; 32]), Err(TxError::Bounds));
    assert_eq!(rule(&|u| u.sponsor = None), Err(TxError::Bounds), "a payer-1 input needs the named sponsor");
    assert_eq!(rule(&|u| u.inputs.retain(|(_, payer)| *payer == Payer::RotatingAuthority)), Err(TxError::Bounds), "a named sponsor must contribute");
    assert_eq!(rule(&|u| u.sponsor = Some((addr(s1, 1), desc(a1, 1)))), Err(TxError::Bounds), "sponsor descriptor differs from the current one");
    assert_eq!(rule(&|u| u.sponsor = Some((addr(s1, 1), desc(a2, 2)))), Err(TxError::Bounds), "and from the proposed one");
    assert_eq!(rule(&|u| u.inputs.clear()), Err(TxError::Bounds), "stripped funding is unrepresentable");
    assert_eq!(rule(&|u| u.inputs.swap(0, 1)), Err(TxError::Codec), "strictly ascending inputs");
    assert_eq!(rule(&|u| u.inputs[1] = u.inputs[0].clone()), Err(TxError::Duplicate));
    assert_eq!(rule(&|u| u.inputs = (0..129u32).map(|i| (OutPoint { transaction: [0x10; 32], index: i }, Payer::RotatingAuthority)).collect()), Err(TxError::Bounds));
    assert_eq!(rule(&|u| u.outputs[0].atoms = 0), Err(TxError::Bounds), "absence of change is absence");
    assert_eq!(rule(&|u| u.outputs[1].owner = [0; 32]), Err(TxError::Bounds), "P3: no zero destination");
    assert_eq!(rule(&|u| u.outputs = vec![Output { owner: DEST, atoms: 1 }; 129]), Err(TxError::Bounds));
    assert_eq!(rule(&|u| u.envelope.last_height = u.envelope.first_height + 10_081), Err(TxError::Bounds), "E3 horizon");
    assert!(rule(&|u| u.outputs.clear()).is_ok(), "zero outputs is legal (all value to the fee)");
    // Hostile raw forms of the valid body.
    assert_eq!(UnsignedRotation::decode(&raw_unsigned(&base, NETWORK_ID ^ 1)), Err(TxError::Binding));
    let mut trailing = raw.clone();
    trailing.push(0);
    assert_eq!(UnsignedRotation::decode(&trailing), Err(TxError::Codec));
    let mut nonminimal = vec![raw[0], 0x18, 0x01];
    nonminimal.extend_from_slice(&raw[2..]);
    assert_eq!(UnsignedRotation::decode(&nonminimal), Err(TxError::Codec));
    let mut indefinite = vec![0x9f];
    indefinite.extend_from_slice(&raw[1..]);
    indefinite.push(0xff);
    assert_eq!(UnsignedRotation::decode(&indefinite), Err(TxError::Codec));
    for n in 0..raw.len() {
        assert!(UnsignedRotation::decode(&raw[..n]).is_err(), "truncated at {n}");
    }
    let mut payer_two = base.clone();
    payer_two.sponsor = None;
    payer_two.inputs = vec![(point(0xa1), Payer::RotatingAuthority)];
    assert!(payer_two.encode().is_ok());
    let mut bad = raw_unsigned(&payer_two, NETWORK_ID);
    // The payer byte of the single input: `[txid32, 0, 0]` encodes as 83 5820<txid> 00 00.
    let mut marker = vec![0x83, 0x58, 0x20];
    marker.extend_from_slice(&[0xa1; 32]);
    marker.extend_from_slice(&[0x00, 0x00]);
    let pos = bad.windows(marker.len()).position(|w| w == marker.as_slice()).unwrap() + marker.len() - 1;
    bad[pos] = 0x02;
    assert_eq!(UnsignedRotation::decode(&bad), Err(TxError::Codec), "payer is 0 or 1");
    // Every reviewed field is bound by every role signature (design 1.b B2).
    let signed = sign(base.clone(), a1, a2, Some(s1));
    signed.verify_signatures().unwrap();
    let mutants: Vec<(&str, Box<dyn Fn(&mut UnsignedRotation)>)> = vec![
        ("genesis", Box::new(|u| u.genesis[0] ^= 1)),
        ("fingerprint", Box::new(|u| u.fingerprint[0] ^= 1)),
        ("first", Box::new(|u| u.envelope.first_height += 1)),
        ("last", Box::new(|u| u.envelope.last_height += 1)),
        ("reference block", Box::new(|u| u.envelope.reference_block[0] ^= 1)),
        ("reference height", Box::new(|u| u.envelope.reference_height -= 1)),
        ("authority", Box::new(|u| u.authority[0] ^= 1)),
        ("current", Box::new(|u| u.current_descriptor = desc(a3, 1))),
        ("proposed", Box::new(|u| u.proposed_descriptor = desc(a3, 2))),
        ("sponsor address", Box::new(|u| u.sponsor.as_mut().unwrap().0[0] ^= 1)),
        ("fee", Box::new(|u| u.fee += 1)),
        ("input index", Box::new(|u| u.inputs[2].0.index += 7)),
        ("input payer", Box::new(|u| {
            u.inputs[1].1 = Payer::Sponsor;
        })),
        ("output atoms", Box::new(|u| u.outputs[0].atoms += 1)),
        ("output owner", Box::new(|u| u.outputs[1].owner[0] ^= 1)),
        ("output removed", Box::new(|u| {
            u.outputs.pop();
        })),
    ];
    let commitment = base.commitment().unwrap();
    for (name, m) in mutants {
        let mut changed = signed.clone();
        m(&mut changed.unsigned);
        assert!(changed.unsigned.encode().is_ok(), "{name}: the mutant must be representable to test the binding");
        assert_ne!(changed.unsigned.commitment().unwrap(), commitment, "{name} changes the commitment");
        assert_eq!(changed.verify_signatures(), Err(TxError::Signature), "{name}");
    }
    // Commitment and id are distinct functions of the unsigned bytes only (no cycle).
    let mut resigned = signed.clone();
    resigned.authorize = a1.sign(Domain::WalletRotate, &fr::authorize_payload(&commitment)).unwrap();
    assert_ne!(resigned.encode().unwrap(), signed.encode().unwrap(), "randomized signatures");
    assert_eq!(resigned.id().unwrap(), signed.id().unwrap());
    assert_ne!(signed.unsigned.commitment().unwrap(), signed.id().unwrap());
    // Signed-transaction hostile forms.
    let wire = signed.encode().unwrap();
    assert_eq!(FundedRotation::decode(&wire).unwrap(), signed);
    let mut trailing = wire.clone();
    trailing.push(0);
    assert_eq!(FundedRotation::decode(&trailing), Err(TxError::Codec));
    assert_eq!(FundedRotation::decode(&raw_tx(2, 25, &raw, [Some(&signed.authorize), None, signed.authority_funding.as_ref(), signed.sponsor_funding.as_ref()])), Err(TxError::Codec), "role signatures are never null");
    // Stateless verification also applies the fee rule (1 atom per complete signed byte).
    let mut cheap = base.clone();
    cheap.fee = 1;
    let cheap = sign(cheap, a1, a2, Some(s1));
    cheap.verify_signatures().unwrap();
    assert_eq!(Transaction::FundedRotation(cheap).verify_signatures(head.genesis, head.fingerprint, 10), Err(TxError::Fee));
    assert_eq!(Transaction::FundedRotation(signed.clone()).verify_signatures(head.genesis, head.fingerprint, 21), Err(TxError::Expired));
    assert_eq!(Transaction::FundedRotation(signed.clone()).verify_signatures(head.genesis, head.fingerprint, 9), Err(TxError::Future));
    assert_eq!(Transaction::FundedRotation(signed.clone()).verify_signatures([9; 32], head.fingerprint, 10), Err(TxError::Binding));
}

/// AM-11 CROSS-VERIFY MATRIX: every real `Domain::Transaction` payload builder on this branch (hybrid
/// Transfer input, trading approval, dividend claim, Treasury freeze, and both funded-rotation funding
/// payloads), each signed by the SAME wallet key: a signature made for one payload verifies under its
/// own real verifier and fails every other verifier.
#[test]
fn cross_verify_matrix_of_every_transaction_domain_payload() {
    use mutiny_consensus_v8::trading_v1 as tr;
    let k = keys();
    let key = k.m.key();
    let (other_old, other_new, a2) = (k.b1.key(), k.b2.key(), k.a2.key());
    let d1 = desc(key, 1);
    let owner = addr(key, 1);
    let context = tr::Context { network: NETWORK_ID, genesis: [11; 32], fingerprint: [12; 32] };
    let anchor = FinalizedAnchor { network: NETWORK_ID, genesis: [11; 32], fingerprint: [12; 32], height: 7, block: [13; 32] };
    let zero = HybridSignature { ed448: [0; 114], fndsa: [0; 1280] };
    // 1. Hybrid Transfer input.
    let mut transfer = Transfer {
        network: NETWORK_ID,
        genesis: [11; 32],
        fingerprint: [12; 32],
        created_height: 1,
        expiry_height: 10,
        fee: 9_000,
        inputs: vec![Input::unsigned(point(1), key.public(), 1).unwrap()],
        outputs: vec![Output { owner: DEST, atoms: 1_000 }],
    };
    // 2. Trading approval (a hash-lock Refund, slot 0 = the owner).
    let mut refund = tr::Operation {
        meta: tr::Meta {
            context: context.clone(),
            trade: [21; 32],
            contract: [22; 32],
            generation: 1,
            envelope: Envelope::from_head(&anchor, 10, vec![]).unwrap(),
            fee: tr::Strikes(20_000),
            inputs: vec![tr::native_input_id(&point(2))],
        },
        action: tr::Action::Refund { output: [23; 32], owner, amount: tr::Strikes(50_000), change: tr::Strikes(80_000) },
        approvals: vec![],
        offer_proof: None,
    };
    // 3. Dividend claim.
    let body = ClaimBody {
        network: NETWORK_ID,
        genesis: [11; 32],
        fingerprint: [12; 32],
        created_height: 1,
        expiry_height: 100,
        award_epoch: P,
        license: [24; 32],
        amount: 5,
        destination: DEST,
        sequence: 0,
    };
    let mut claim = SignedClaim { body, descriptor: d1.clone(), signature: zero.clone() };
    // 4. Treasury freeze (the frozen Treasury offer authorization).
    // P7 (WP-T4, AM-6): the Treasury wallet itself makes the frozen offer with its wallet key.
    // P6 (WP-T3): the trading Treasury is the Genesis MUT Treasury authority T = owner.
    let mut treasury_state = State::default();
    treasury_state.dividends = mutiny_consensus_v8::dividend_state_v1::DividendState::genesis(
        mutiny_consensus_v8::treasury_v1::Treasury::new(mutiny_consensus_v8::treasury_v1::Class::TestValue, d1.clone()).unwrap(),
    );
    for (key_id, record) in tr::treasury_genesis_records(&context, owner, d1.clone()).unwrap() {
        treasury_state.protocol_records.insert(key_id, record);
    }
    let offer = tr::SignedOffer::sign(
        tr::OfferBody {
            context: context.clone(),
            maker_descriptor: d1.clone(),
            maker_wallet: owner,
            destination: owner,
            condition: None,
            max_fee: tr::Strikes(240),
            nonce: [31; 32],
            created: anchor.height,
            expiry: anchor.height + 10,
            maker_side: 1,
            terms: tr::OfferTerms::HashLinked { amount: tr::Strikes(50_000), bitcoin_satoshis: 10_000, bitcoin_network: 3 },
        },
        key,
    )
    .unwrap();
    let freeze = || {
        tr::prepare_treasury_offer(
            &treasury_state,
            &anchor,
            treasury_state.root().unwrap(),
            tr::TreasuryOfferRequest {
                treasury: owner,
                generation: 1,
                address: owner,
                trade: [21; 32],
                contract: [22; 32],
                offer: offer.clone(),
                wallet_descriptor: d1.clone(),
            },
            &tr::CandidatePolicy::native_denomination_locked(),
        )
        .unwrap()
    };
    // 5/6. Funded-rotation funding: `key` as the rotating authority (payer 0) and as a sponsor (payer 1).
    let mut as_authority = plan(&anchor, owner, (key, 1), (a2, 2));
    as_authority.inputs = vec![(point(3), Payer::RotatingAuthority)];
    as_authority.outputs = vec![Output { owner: DEST, atoms: 1 }];
    let rot0 = as_authority.sign();
    let mut as_sponsor = plan(&anchor, addr(other_old, 1), (other_old, 1), (other_new, 2));
    as_sponsor.sponsor = Some((owner, key, 1));
    as_sponsor.inputs = vec![(point(4), Payer::Sponsor)];
    as_sponsor.outputs = vec![Output { owner: DEST, atoms: 1 }];
    let rot1 = as_sponsor.sign();
    let funding0 = fr::funding_payload(&rot0.unsigned.commitment().unwrap(), Payer::RotatingAuthority);
    let funding1 = fr::funding_payload(&rot1.unsigned.commitment().unwrap(), Payer::Sponsor);
    // Combined integration matrix: kind-24 funding must also remain distinct from
    // both tag-25 funding parties after all T-series merges.
    use mutiny_consensus_v8::bond_create_v3 as bc;
    let bond = bc::FundedBondCreate::sign(bc::UnsignedBondCreate {
        genesis: anchor.genesis,
        fingerprint: anchor.fingerprint,
        envelope: Envelope::from_head(&anchor, 10, vec![]).unwrap(),
        owner,
        owner_descriptor: d1.clone(),
        node: [41; 32],
        node_generation: 1,
        nonce: [42; 32],
        principal: mutiny_consensus_v8::bonds::MINIMUM_ATOMS,
        fee: 20_000,
        inputs: vec![point(5)],
        change: None,
    }, key).unwrap();
    let payloads: Vec<(&str, Vec<u8>)> = vec![
        ("transfer input", transfer.signing_payload(0).unwrap()),
        ("trading approval", refund.signing_payload(0, &d1).unwrap()),
        ("dividend claim", claim.signing_payload()),
        ("treasury freeze", freeze().signing_payload().unwrap()),
        ("rotation funding payer 0", funding0),
        ("rotation funding payer 1", funding1),
        ("bond funding", bc::funding_payload(&bond.unsigned.commitment().unwrap())),
    ];
    for (i, (a, x)) in payloads.iter().enumerate() {
        for (b, y) in payloads.iter().skip(i + 1) {
            assert_ne!(x, y, "{a} vs {b}: distinct payload bytes");
        }
    }
    let wallets = mutiny_consensus_v8::wallet_authority_v1::WalletBook::default();
    let mut verifiers: Vec<(&str, Box<dyn FnMut(&HybridSignature) -> bool>)> = vec![
        ("transfer input", Box::new(|s| {
            transfer.inputs[0].signature = s.clone();
            transfer.verify_signatures().is_ok()
        })),
        ("trading approval", Box::new(|s| {
            refund.approvals = vec![tr::Approval { slot: 0, descriptor: d1.clone(), signature: s.clone() }];
            tr::verify_approval(&wallets, &refund, 0).is_ok()
        })),
        ("dividend claim", Box::new(|s| {
            claim.signature = s.clone();
            claim.verify_signature().is_ok()
        })),
        ("treasury freeze", Box::new(|s| freeze().attach_authorization(s.clone()).is_ok())),
        ("rotation funding payer 0", Box::new(|s| {
            let mut r = rot0.clone();
            r.authority_funding = Some(s.clone());
            r.verify_signatures().is_ok()
        })),
        ("rotation funding payer 1", Box::new(|s| {
            let mut r = rot1.clone();
            r.sponsor_funding = Some(s.clone());
            r.verify_signatures().is_ok()
        })),
    ];
    verifiers.push(("bond funding", Box::new(|s| {
        let mut b = bond.clone();
        b.funding = s.clone();
        b.verify_signatures().is_ok()
    })));
    assert_eq!(verifiers.len(), payloads.len());
    for (i, (signed_name, payload)) in payloads.iter().enumerate() {
        let signature = key.sign(Domain::Transaction, payload).unwrap();
        for (j, (verifier_name, verify)) in verifiers.iter_mut().enumerate() {
            assert_eq!(verify(&signature), i == j, "signature for {signed_name} under the {verifier_name} verifier");
        }
    }
}

/// Design 3.7: `WalletBook::apply_verified_rotation` is reachable from canonical execution only
/// through the verified bundle, and no consensus source applies a standalone Rotation to a book.
#[test]
fn only_the_verified_bundle_rotates_a_wallet_authority() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut callers = Vec::new();
    for entry in std::fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_none_or(|e| e != "rs") {
            continue;
        }
        let name = path.file_name().unwrap().to_str().unwrap().to_string();
        let text = std::fs::read_to_string(&path).unwrap();
        if text.contains(".apply_verified_rotation(") {
            callers.push(name.clone());
        }
        assert!(!text.contains("wallets.apply(") && !text.contains("wallets\n            .apply("), "{name} applies a standalone rotation");
    }
    callers.sort();
    assert_eq!(callers, ["funded_rotation_v2.rs", "funded_rotation_v2_tests.rs", "wallet_authority_v1.rs"]);
}

// ---------------------------------------------------------------------------------------------
// Public TEST-VALUE vectors: qualification/funded-rotation-v2-public.json
// ---------------------------------------------------------------------------------------------

const VECTORS: &str = "../qualification/funded-rotation-v2-public.json";

fn intent_sha512(domain: Domain, payload: &[u8]) -> String {
    use sha2::{Digest, Sha512};
    let mut h = Sha512::new();
    h.update(domain.bytes());
    h.update([0]);
    h.update(payload);
    hex::encode(h.finalize())
}
fn vector_case(name: &str, tx: &FundedRotation, note: &str) -> serde_json::Value {
    let intents: Vec<serde_json::Value> = fr::signing_intents(&tx.unsigned)
        .unwrap()
        .iter()
        .map(|i| {
            serde_json::json!({
                "slot": format!("{:?}", i.slot), "party": format!("{:?}", i.party),
                "domain_ascii": std::str::from_utf8(i.domain.bytes()).unwrap(),
                "descriptor_hex": hex::encode(&i.descriptor), "payload_hex": hex::encode(&i.payload),
                "intent_sha512_hex": intent_sha512(i.domain, &i.payload),
            })
        })
        .collect();
    let mut partial = PartialRotation::new(tx.unsigned.clone());
    partial.authorize = Some(tx.authorize.clone());
    serde_json::json!({
        "name": name, "note": note,
        "unsigned_hex": hex::encode(tx.unsigned.encode().unwrap()),
        "commitment_hex": hex::encode(tx.unsigned.commitment().unwrap()),
        "id_hex": hex::encode(tx.id().unwrap()),
        "signed_len": fr::signed_len(&tx.unsigned).unwrap(),
        "fee": tx.unsigned.fee,
        "intents": intents,
        "transaction_hex": hex::encode(tx.encode().unwrap()),
        "partial_authorize_only_hex": hex::encode(partial.encode().unwrap()),
    })
}
fn vector_cases() -> (FinalizedAnchor, Vec<(String, FundedRotation, String)>) {
    let k = keys();
    let (a1, a2, s1) = (k.a1.key(), k.a2.key(), k.s1.key());
    let head = FinalizedAnchor { network: NETWORK_ID, genesis: [0x11; 32], fingerprint: [0x22; 32], height: 100, block: [0x33; 32] };
    let authority = addr(a1, 1);
    let mut own = plan(&head, authority, (a1, 1), (a2, 2));
    own.validity = 144;
    own.inputs = vec![(point(0xa1), Payer::RotatingAuthority)];
    own.outputs = vec![Output { owner: DEST, atoms: 1_000_000 }, Output { owner: addr(a2, 2), atoms: BIG - 1_000_000 - FEE }];
    let mut sponsored = plan(&head, authority, (a1, 1), (a2, 2));
    sponsored.validity = 144;
    sponsored.sponsor = Some((addr(s1, 1), s1, 1));
    sponsored.inputs = vec![(point(0xa1), Payer::RotatingAuthority), (point(0x51), Payer::Sponsor)];
    sponsored.outputs = vec![Output { owner: addr(s1, 1), atoms: BIG - 3_000_000 }, Output { owner: addr(a2, 2), atoms: BIG + 3_000_000 - FEE }];
    (
        head,
        vec![
            ("self_funded_1_in_2_out".into(), own.sign(), "the rotating authority pays: authority_funding present, sponsor_funding null".into()),
            ("sponsored_2_in_2_out".into(), sponsored.sign(), "explicit sponsor: both funding slots present".into()),
        ],
    )
}

/// Generator (TEST-VALUE): `BUILD8_EXPORT_FUNDED_ROTATION_V2=1 cargo test --offline --locked --test
/// funded_rotation_v2 export_funded_rotation_v2_vectors` writes the file with `create_new` (it refuses
/// to overwrite: delete the file first). Signatures are randomized, so a regeneration has new
/// signature bytes; the reader checks every recomputable value and every signature.
#[test]
fn export_funded_rotation_v2_vectors() {
    if std::env::var("BUILD8_EXPORT_FUNDED_ROTATION_V2").as_deref() != Ok("1") {
        return;
    }
    let (head, cases) = vector_cases();
    let doc = serde_json::json!({
        "schema": "BUILD8-FUNDED-ROTATION-V2-PUBLIC",
        "status": "PROPOSED-UNFROZEN",
        "synthetic_only": true, "test_value": true, "production_authorized": false,
        "design": "qualification/candidate-3/P-LANE-DESIGN-V1.md sections 1.b and 3 (amendments AM-1(d), AM-9 m6)",
        "spec": "spec/FUNDED-WALLET-ROTATION-V1.md (integration copy, amended)",
        "generator": "consensus: BUILD8_EXPORT_FUNDED_ROTATION_V2=1 cargo test --offline --locked --test funded_rotation_v2 export_funded_rotation_v2_vectors (create_new: refuses to overwrite; delete the file first)",
        "reader": "consensus: cargo test --offline --locked --test funded_rotation_v2 committed_funded_rotation_v2_vectors_verify",
        "note": "Public synthetic data only. Keys are labelled-seed TEST-VALUE wallet keys (crypto-v2 rehearsal_keys_v1 labels wp-r-a1, wp-r-a2, wp-r-s1): public by construction, never production identities. Heights, hashes and coins are arbitrary TEST-VALUE patterns; no chain state is asserted. Signatures are randomized hybrid Ed448 + FN-DSA BOTH_REQUIRED signatures over SHA-512(domain || 0x00 || payload).",
        "layout": "unsigned = [1, network, genesis32, fingerprint32, Envelope, authority32, current_descriptor, proposed_descriptor, null | [sponsor_address32, sponsor_descriptor], fee, [[txid32, index, payer]...], [[owner32, atoms]...]]; tx = [2, 25, unsigned, [ed448, fndsa], [ed448, fndsa], null | [ed448, fndsa], null | [ed448, fndsa]]; partial = [1, 25, unsigned, four null | [ed448, fndsa] slots]",
        "domains": {
            "commitment": "MUTINY-BUILD8-FUNDED-ROTATION-COMMITMENT-V2", "id": "MUTINY-BUILD8-FUNDED-ROTATION-ID-V2",
            "authorize_label": "MUTINY-BUILD8-FUNDED-ROTATION-AUTHORIZE-V2", "possession_label": "MUTINY-BUILD8-FUNDED-ROTATION-POSSESSION-V2",
            "funding_label": "MUTINY-BUILD8-FUNDED-ROTATION-FUNDING-V2"
        },
        "signing_head": {"height": head.height, "block_hex": hex::encode(head.block), "genesis_hex": hex::encode(head.genesis), "fingerprint_hex": hex::encode(head.fingerprint)},
        "cases": cases.iter().map(|(name, tx, note)| vector_case(name, tx, note)).collect::<Vec<_>>(),
    });
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(VECTORS);
    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&path).expect("refusing to overwrite: delete the vector file first");
    use std::io::Write;
    file.write_all(&serde_json::to_vec_pretty(&doc).unwrap()).unwrap();
    file.write_all(b"\n").unwrap();
}

/// Reader of the committed vectors: every case decodes, re-encodes byte-identically, its commitment,
/// id, signed length and every intent payload/SHA-512 recompute exactly, every signature verifies, and
/// the authorize-only partial object decodes with exactly the possession/funding slots missing.
#[test]
fn committed_funded_rotation_v2_vectors_verify() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(VECTORS);
    let doc: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(doc["synthetic_only"], true);
    assert_eq!(doc["test_value"], true);
    assert_eq!(doc["production_authorized"], false);
    assert_eq!(doc["status"], "PROPOSED-UNFROZEN");
    let cases = doc["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    let hx = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    for case in cases {
        let raw = hx(&case["transaction_hex"]);
        let Transaction::FundedRotation(tx) = Transaction::decode(&raw).unwrap() else {
            panic!("tag 25 expected")
        };
        assert_eq!(tx.encode().unwrap(), raw);
        assert_eq!(tx.unsigned.encode().unwrap(), hx(&case["unsigned_hex"]));
        assert_eq!(tx.unsigned.commitment().unwrap().to_vec(), hx(&case["commitment_hex"]));
        assert_eq!(tx.id().unwrap().to_vec(), hx(&case["id_hex"]));
        assert_eq!(fr::signed_len(&tx.unsigned).unwrap() as u64, case["signed_len"].as_u64().unwrap());
        assert_eq!(raw.len() as u64, case["signed_len"].as_u64().unwrap());
        assert!(tx.unsigned.fee >= raw.len() as u64);
        tx.verify_signatures().unwrap();
        let intents = fr::signing_intents(&tx.unsigned).unwrap();
        let listed = case["intents"].as_array().unwrap();
        assert_eq!(intents.len(), listed.len());
        for (intent, v) in intents.iter().zip(listed) {
            assert_eq!(format!("{:?}", intent.slot), v["slot"].as_str().unwrap());
            assert_eq!(intent.domain.bytes(), v["domain_ascii"].as_str().unwrap().as_bytes());
            assert_eq!(intent.payload, hx(&v["payload_hex"]));
            assert_eq!(intent.descriptor, hx(&v["descriptor_hex"]));
            assert_eq!(intent_sha512(intent.domain, &intent.payload), v["intent_sha512_hex"].as_str().unwrap());
        }
        let partial = PartialRotation::decode(&hx(&case["partial_authorize_only_hex"])).unwrap();
        assert_eq!(partial.unsigned, tx.unsigned);
        assert_eq!(partial.authorize.as_ref(), Some(&tx.authorize));
        let missing = partial.missing().unwrap();
        assert_eq!(missing.first(), Some(&Slot::Possession));
        assert!(!missing.contains(&Slot::Authorize));
    }
}

/// Design 12.2: every P2 domain and payload label is registered exactly once as PROPOSED-UNFROZEN,
/// documented by the funded-rotation spec, with the bytes the code uses; the retired
/// FUNDED-WALLET-ROTATION-ID-V1 is not used by any consensus source.
#[test]
fn funded_rotation_domains_are_registered_as_proposed_and_unfrozen() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let registry: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("../spec/DOMAIN-REGISTRY-V1.json")).unwrap()).unwrap();
    let listed = registry["domains"].as_array().unwrap();
    for domain in [fr::COMMITMENT_DOMAIN, fr::ID_DOMAIN, fr::AUTHORIZE_LABEL, fr::POSSESSION_LABEL, fr::FUNDING_LABEL] {
        let ascii = std::str::from_utf8(domain).unwrap();
        let entries: Vec<_> = listed.iter().filter(|e| e["ascii"] == ascii).collect();
        assert_eq!(entries.len(), 1, "{ascii} registered exactly once");
        assert_eq!(entries[0]["status"], "PROPOSED-UNFROZEN", "{ascii}");
        assert_eq!(entries[0]["doc"], "spec/FUNDED-WALLET-ROTATION-V1.md", "{ascii}");
    }
    let ascii: Vec<_> = listed.iter().map(|e| e["ascii"].as_str().unwrap()).collect();
    let mut unique = ascii.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), ascii.len(), "no domain string is registered twice");
    for entry in std::fs::read_dir(root.join("src")).unwrap() {
        let path = entry.unwrap().path();
        let text = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(!text.contains("FUNDED-WALLET-ROTATION-ID-V1\""), "{path:?} uses the retired identity domain");
    }
}
