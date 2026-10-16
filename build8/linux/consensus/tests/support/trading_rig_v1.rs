// Shared trading builders for the WP-T1 real-block tests (Lane P design P-LANE-DESIGN-V1 sections
// 4, 5.1, 10 and 14; TEST-VALUE, synthetic only: published BIP39 phrases, never production
// identities; the maker of an offer is the slot-0 wallet signer, WP-T4 / AM-6). Included with include! AFTER support/dividend_rig.rs,
// whose Fixture, Rig, keys and helpers it uses; the including module declares `licenses` and `tpm`.
use mutiny_consensus_v8::{
    op_envelope_v1::{Envelope, Precondition},
    trading_v1 as tr,
};

/// The signed inclusion window of a trading operation and its finalized reference.
#[derive(Clone, Copy, Debug)]
struct Window {
    first: u64,
    last: u64,
    reference: (u64, Hash),
}

fn trade_context(f: &Fixture) -> tr::Context {
    tr::Context { network: NETWORK_ID, genesis: f.genesis.genesis, fingerprint: f.genesis.fingerprint }
}

/// The offer terms an offer-bound action settles (None for the completion actions and rotation).
fn offer_terms(action: &tr::Action) -> Option<tr::OfferTerms> {
    match action {
        tr::Action::HashLock { amount, .. } => Some(tr::OfferTerms::HashLinked {
            amount: *amount,
            bitcoin_satoshis: 10_000,
            bitcoin_network: 3,
        }),
        tr::Action::FiatLock { amount, payment_terms, .. } => {
            Some(tr::OfferTerms::Fiat { amount: *amount, payment_terms: *payment_terms })
        }
        tr::Action::LicenseDvp { license, license_generation, price, .. } => Some(tr::OfferTerms::License {
            license: *license,
            generation: *license_generation,
            price: *price,
        }),
        _ => None,
    }
}

/// The operation envelope (body version 2) of a window, with optional committed preconditions.
fn envelope_of(window: Window, preconditions: Vec<Precondition>) -> Envelope {
    Envelope {
        first_height: window.first,
        last_height: window.last,
        reference_height: window.reference.0,
        reference_block: window.reference.1,
        preconditions,
    }
}
/// The trading metadata of one operation (body version 2: the envelope carries the window).
fn trade_meta(context: tr::Context, window: Window, fee: u64, inputs: &[OutPoint]) -> tr::Meta {
    tr::Meta {
        context,
        trade: [21; 32],
        contract: [22; 32],
        generation: 1,
        envelope: envelope_of(window, vec![]),
        fee: tr::Strikes(fee),
        inputs: inputs.iter().map(tr::native_input_id).collect(),
    }
}

/// A complete native trading operation: metadata, the action, a maker offer and fill proof whose
/// window covers the operation window (offer-bound actions only), and one approval per signer
/// `(slot, key, descriptor generation)`. `inputs` must be ascending by native input id.
fn trade(
    f: &Fixture,
    action: tr::Action,
    window: Window,
    fee: u64,
    inputs: &[OutPoint],
    signers: &[(u8, &HybridKey, u64)],
) -> tr::NativeOperation {
    trade_with(f, action, window, vec![], fee, inputs, signers)
}
/// `trade` whose envelope also commits to `preconditions` (ascending by tag and subject).
fn trade_with(
    f: &Fixture,
    action: tr::Action,
    window: Window,
    preconditions: Vec<Precondition>,
    fee: u64,
    inputs: &[OutPoint],
    signers: &[(u8, &HybridKey, u64)],
) -> tr::NativeOperation {
    let context = trade_context(f);
    let mut inputs = inputs.to_vec();
    inputs.sort_by_key(tr::native_input_id);
    let mut meta = trade_meta(context.clone(), window, fee, &inputs);
    meta.envelope.preconditions = preconditions;
    let mut operation = tr::Operation {
        meta,
        action,
        approvals: vec![],
        offer_proof: None,
    };
    if let Some(terms) = offer_terms(&operation.action) {
        // P7 (WP-T4, AM-6): the maker is the slot-0 party and signs with its wallet owner key (the
        // slot-0 approval descriptor); without a slot-0 signer a fresh random wallet key stands in
        // (the operation then fails authorization anyway).
        let fresh;
        let (maker, generation) = match signers.iter().find(|(slot, _, _)| *slot == 0) {
            Some((_, key, generation)) => (*key, *generation),
            None => {
                fresh = HybridKey::generate(Role::WalletOwner).unwrap();
                (&fresh, 1)
            }
        };
        let (destination, condition) = match &operation.action {
            tr::Action::HashLock { sender, condition, .. } => (*sender, Some(*condition)),
            tr::Action::FiatLock { seller, .. } => (*seller, None),
            tr::Action::LicenseDvp { payment_destination, .. } => (*payment_destination, None),
            _ => unreachable!(),
        };
        let offer = tr::SignedOffer::sign(
            tr::OfferBody {
                context,
                maker_descriptor: maker.public().descriptor(generation).unwrap(),
                maker_wallet: operation.slot_address(0).unwrap(),
                maker_side: 0,
                // One offer per item (the fixture keys are deterministic, so a fixed nonce would make two
                // items of one signer fill the SAME offer): the nonce is the first input id.
                nonce: inputs.first().map(tr::native_input_id).unwrap_or([31; 32]),
                created: window.first,
                expiry: window.last,
                terms,
                destination,
                condition,
                max_fee: tr::Strikes(fee),
            },
            maker,
        )
        .unwrap();
        match &mut operation.action {
            tr::Action::HashLock { offer: o, maker: m, .. }
            | tr::Action::FiatLock { offer: o, maker: m, .. }
            | tr::Action::LicenseDvp { offer: o, maker: m, .. } => {
                *o = offer.body.id().unwrap();
                *m = offer.body.maker().unwrap();
            }
            _ => unreachable!(),
        }
        operation.offer_proof = Some(tr::OfferProof::sign(offer, &operation, maker).unwrap());
    }
    for (slot, key, generation) in signers {
        operation.approve(*slot, key, *generation).unwrap();
    }
    tr::NativeOperation { operation, inputs }
}

/// A coin owned by `owner`, created at Genesis (height 0), inserted before the store opens.
fn fund(f: &mut Fixture, n: u8, owner: Hash, atoms: u64) -> OutPoint {
    let point = OutPoint { transaction: [n; 32], index: 0 };
    f.state.coins.insert(point.clone(), Coin { output: Output { owner, atoms }, created_height: 0, coinbase: false });
    point
}

/// The crafted raw item of design 14.3: the single occurrence of `value` in `raw` replaced by
/// zeros (same length, so only that field changes; signatures no longer matter, decoding refuses
/// the item first).
fn zero_field(raw: &[u8], value: &Hash) -> Vec<u8> {
    let at: Vec<usize> = raw.windows(32).enumerate().filter(|(_, w)| *w == value).map(|(i, _)| i).collect();
    // WP-T4 (P7): a maker offer (OfferProof, encoded after the body and the approvals) repeats the
    // maker address as maker_wallet/destination; the FIRST occurrence is the trading-body field.
    assert!(!at.is_empty(), "the field value occurs in the item");
    let mut out = raw.to_vec();
    out[at[0]..at[0] + 32].copy_from_slice(&[0; 32]);
    out
}

/// The exact trading verdict on the rig's current parent state, as the read-only consensus entry
/// point (`prepare_batch`) computes it for inclusion at the next height.
fn native_verdict(rig: &Rig, raw: &[Vec<u8>]) -> tr::NativeResult<tr::Prepared> {
    tr::prepare_batch(
        &rig.state,
        &rig.parent,
        rig.state.root().unwrap(),
        raw,
        &tr::CandidatePolicy::native_denomination_locked(),
    )
}

/// Every row of every table the canonical store keeps (canonical_v2, state_v2, undo_v2,
/// confirmations_v2, evidence and the other derived tables, including an operation index when one
/// exists), read through a separate read-only connection, each row as the SHA-256 of its exact
/// typed column bytes. Used to prove a rejected block left the durable store byte-identical.
fn store_rows(rig: &Rig) -> Vec<(String, Vec<[u8; 32]>)> {
    use sha2::{Digest, Sha256};
    let db = rusqlite::Connection::open_with_flags(
        rig.base.join("chain.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let mut tables: Vec<String> = db
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    tables.sort();
    tables
        .into_iter()
        .map(|table| {
            let mut q = db.prepare(&format!("SELECT * FROM \"{table}\"")).unwrap();
            let n = q.column_count();
            let mut rows: Vec<[u8; 32]> = q
                .query_map([], |r| {
                    let mut h = Sha256::new();
                    for i in 0..n {
                        match r.get_ref(i)? {
                            rusqlite::types::ValueRef::Null => h.update([0]),
                            rusqlite::types::ValueRef::Integer(v) => {
                                h.update([1]);
                                h.update(v.to_be_bytes())
                            }
                            rusqlite::types::ValueRef::Real(v) => {
                                h.update([2]);
                                h.update(v.to_be_bytes())
                            }
                            rusqlite::types::ValueRef::Text(v) => {
                                h.update([3]);
                                h.update((v.len() as u64).to_be_bytes());
                                h.update(v)
                            }
                            rusqlite::types::ValueRef::Blob(v) => {
                                h.update([4]);
                                h.update((v.len() as u64).to_be_bytes());
                                h.update(v)
                            }
                        }
                    }
                    Ok(h.finalize().into())
                })
                .unwrap()
                .map(Result::unwrap)
                .collect();
            rows.sort();
            (table, rows)
        })
        .collect()
}

/// Head, complete canonical State records and every durable store row.
type Snapshot = (u64, Hash, Vec<(Hash, Vec<u8>)>, Vec<(String, Vec<[u8; 32]>)>);
fn snapshot(rig: &Rig) -> Snapshot {
    let (head, state) = rig.chain.load().unwrap();
    (head.height, head.block, state.records().unwrap(), store_rows(rig))
}

/// The canonical block hash at `height` of the rig's chain (the trusted Genesis block at 0).
fn canonical_hash(rig: &Rig, height: u64) -> Hash {
    if height == 0 {
        return rig.f.genesis.block;
    }
    rig.chain.canonical_block(height).unwrap().expect("a canonical height").block_hash()
}
/// The window [first, last] whose finalized reference is the canonical block at `reference`.
fn window_at(rig: &Rig, reference: u64, first: u64, last: u64) -> Window {
    Window { first, last, reference: (reference, canonical_hash(rig, reference)) }
}
/// An authenticated History holding the canonical block hash of each height (what the local
/// canonical store supplies to block execution, design 1.a.3).
fn anchors(rig: &Rig, heights: &[u64]) -> mutiny_consensus_v8::evidence_history_v2::History {
    let mut history = mutiny_consensus_v8::evidence_history_v2::History::default();
    for height in heights {
        history.insert_anchor(*height, canonical_hash(rig, *height)).unwrap();
    }
    history
}
/// The real block for the next height built by the PRODUCTION assembler and executed by the V2
/// executor with an authenticated History of the given reference heights (not installed).
fn prepare_with_anchors(
    rig: &Rig,
    epoch: u64,
    ops: &[Vec<u8>],
    heights: &[u64],
) -> Result<mutiny_consensus_v8::assembler_v2::Prepared, String> {
    let (work_parent, _, _) = rig.chain.execution_parent(rig.height()).unwrap();
    mutiny_consensus_v8::assembler_v2::prepare_with_history(
        mutiny_consensus_v8::assembler_v2::Request {
            parent: &work_parent,
            state: &rig.state,
            pool: &rig.pool,
            license: rig.f.license,
            worker: rig.f.worker,
            timestamp: at(epoch),
            ticket: rig.ticket,
            operations: ops,
        },
        &anchors(rig, heights),
    )
}
/// The executor path (production assembler + V2 executor with the given anchors) must refuse a
/// block carrying `ops`; nothing is installed, and the store stays byte-identical.
fn executor_rejected(rig: &Rig, epoch: u64, ops: &[Vec<u8>], heights: &[u64]) -> String {
    let before = snapshot(rig);
    let outcome = prepare_with_anchors(rig, epoch, ops, heights);
    assert!(outcome.is_err(), "the executor must refuse the block");
    assert_eq!(snapshot(rig), before);
    outcome.err().unwrap()
}
/// The exact trading verdict with an authenticated History of the given reference heights.
fn native_verdict_with(rig: &Rig, raw: &[Vec<u8>], heights: &[u64]) -> tr::NativeResult<tr::Prepared> {
    tr::prepare_batch_with_history(
        &rig.state,
        &rig.parent,
        rig.state.root().unwrap(),
        &anchors(rig, heights),
        raw,
        &tr::CandidatePolicy::native_denomination_locked(),
    )
}
/// A REAL wallet rotation of `authority` from `from` to `to` (key, descriptor generation), admitted
/// to the pool and executed in the next real block at `epoch` together with `ops` (trading items
/// run before the payment phase, so they still see the pre-rotation authority). Its fee is paid by
/// `payer` (generation 1) from `fund` (40,000 atoms: fee 39,000, change 1,000), as the funded
/// wallet-rotation bundle (tag 25, WP-R): when `payer` is the rotating key itself it pays as payer 0
/// (self-funded), otherwise it is the explicitly reviewed sponsor (payer 1).
fn rotate_in_block(
    rig: &mut Rig,
    epoch: u64,
    authority: Hash,
    from: (&HybridKey, u64),
    to: (&HybridKey, u64),
    payer: &HybridKey,
    fund: OutPoint,
    ops: &[Vec<u8>],
) -> State {
    use mutiny_consensus_v8::{
        funded_rotation_v2::{Party, PartialRotation, Payer, UnsignedRotation, signing_intents},
        op_envelope_v1::Envelope,
    };
    let self_funded = desc(payer, 1) == desc(from.0, from.1);
    let mut partial = PartialRotation::new(UnsignedRotation {
        genesis: rig.f.genesis.genesis,
        fingerprint: rig.f.genesis.fingerprint,
        envelope: Envelope::from_head(&rig.parent, 10_000, vec![]).unwrap(),
        authority,
        current_descriptor: desc(from.0, from.1),
        proposed_descriptor: desc(to.0, to.1),
        sponsor: (!self_funded).then(|| (addr(payer, 1), desc(payer, 1))),
        fee: 39_000,
        inputs: vec![(fund, if self_funded { Payer::RotatingAuthority } else { Payer::Sponsor })],
        outputs: vec![Output { owner: addr(payer, 1), atoms: 1_000 }],
    });
    for intent in signing_intents(&partial.unsigned).unwrap() {
        let key = match intent.party {
            Party::RotatingAuthority => from.0,
            Party::NewKey => to.0,
            Party::Sponsor => payer,
        };
        partial.sign(intent.slot, key).unwrap();
    }
    let tx = Transaction::FundedRotation(partial.complete().unwrap());
    rig.pool.admit(&tx, &rig.parent, &rig.state).unwrap();
    let s = rig.step(epoch, ops);
    assert_eq!(s.wallets.current(authority), Some(desc(to.0, to.1).as_slice()), "the rotation executed");
    s
}
/// An ordinary transfer admitted to the pool and executed in the next real block at `epoch`.
fn transfer_in_block(rig: &mut Rig, epoch: u64, tx: Transaction, ops: &[Vec<u8>]) -> State {
    let id = tx.id().unwrap();
    rig.pool.admit(&tx, &rig.parent, &rig.state).unwrap();
    let s = rig.step(epoch, ops);
    assert_eq!(rig.chain.confirmed_height(id).unwrap(), Some(rig.height()), "the transfer executed");
    s
}
/// `n` empty real blocks, one MiningEpoch apart (the next epoch is the next height).
fn advance(rig: &mut Rig, n: u64) {
    for _ in 0..n {
        let epoch = rig.height() + 1;
        rig.step(epoch, &[]);
    }
}
/// A CERTIFIED block whose body carries `ops` (fees = declared trading fees) must be refused by
/// `CanonicalStore::commit` itself (re-execution), leaving the store byte-identical. The block is
/// an honest empty block of the production assembler with `ops` substituted into its body and a
/// re-computed body root, then certified with real hybrid votes, so only the operations are wrong.
fn commit_rejected_unchanged(rig: &mut Rig, epoch: u64, ops: &[Vec<u8>]) -> String {
    let before = snapshot(rig);
    let mut prepared = rig
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
    for raw in ops {
        prepared.body.fees += tr::declared_fee(raw).unwrap();
    }
    prepared.body.operations.extend(ops.iter().cloned());
    prepared.candidate.body_root = prepared.body.root().unwrap();
    let envelope = certify_at(prepared, &rig.f, &rig.parent, &rig.state, rig.ticket);
    let outcome = rig.chain.commit(&envelope);
    assert!(outcome.is_err(), "commit must refuse the certified block");
    assert_eq!(snapshot(rig), before, "a refused commit leaves the store byte-identical");
    format!("{:?}", outcome.unwrap_err())
}
/// A real block carrying `ops` must be refused by the production assembler + executor + store path,
/// leaving the head, the canonical State and every store row byte-identical. Returns the error text.
fn rejected_unchanged(rig: &mut Rig, epoch: u64, ops: &[Vec<u8>]) -> String {
    let before = snapshot(rig);
    let in_memory = rig.state.records().unwrap();
    let outcome = rig.try_step(epoch, ops);
    assert!(outcome.is_err(), "the block must be rejected");
    assert_eq!(snapshot(rig), before, "a rejected block leaves the store byte-identical");
    assert_eq!(rig.state.records().unwrap(), in_memory, "the rig's parent State is untouched");
    outcome.unwrap_err()
}

// ---- WP-T3 (P6) -------------------------------------------------------------------------------

/// P6 Genesis construction for tests whose subject is not P6 (WP-T3; Lane P design 7): makes the
/// Genesis MUT Treasury authority T = addr(t, 1) active (dividends, TEST-VALUE class), puts the
/// trading Treasury records under T (generation 1 = T's Genesis descriptor), and applies ONE
/// signed wallet rotation of T to `next` in the Genesis WalletBook (`WalletBook::apply`), so that
/// an R2 to `next` is valid in the first block. Coins are kept. The real-block R1 is
/// `rotate_in_block` (consensus/tests/treasury_authority_v1.rs uses it for every P6 row).
fn genesis_treasury_after_r1(f: &mut Fixture, t: &HybridKey, next: (&HybridKey, u64)) {
    let ta = addr(t, 1);
    f.state.dividends = DividendState::genesis(Treasury::new(Class::TestValue, desc(t, 1)).unwrap());
    if f.state.wallets.current(ta).is_none() {
        f.state.wallets.register(&desc(t, 1)).unwrap();
    }
    let mut rotation = Rotation {
        network: NETWORK_ID,
        genesis: f.genesis.genesis,
        fingerprint: f.genesis.fingerprint,
        authority: ta,
        current: desc(t, 1),
        proposed: desc(next.0, next.1),
        created_height: 0,
        expiry_height: 10_000,
        authorization: empty(),
        possession: empty(),
    };
    rotation.sign(t, next.0).unwrap();
    f.state.wallets.apply(&rotation, f.genesis.genesis, f.genesis.fingerprint, 0).unwrap();
    for (key, raw) in tr::treasury_genesis_records(&trade_context(f), ta, desc(t, 1)).unwrap() {
        f.state.protocol_records.insert(key, raw);
    }
}
/// `zero_field` for a value that occurs exactly twice in the item: zeroes the SECOND occurrence.
/// P6: a TreasuryRotate's `treasury` field is T, which is also its generation-1 head address
/// (`current_address`, encoded after it).
fn zero_second(raw: &[u8], value: &Hash) -> Vec<u8> {
    let at: Vec<usize> = raw.windows(32).enumerate().filter(|(_, w)| *w == value).map(|(i, _)| i).collect();
    assert_eq!(at.len(), 2, "the value occurs exactly twice in the item");
    let mut out = raw.to_vec();
    out[at[1]..at[1] + 32].copy_from_slice(&[0; 32]);
    out
}
