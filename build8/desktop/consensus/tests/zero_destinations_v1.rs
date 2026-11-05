//! P3: zero monetary destinations are refused in consensus (Order of 4 October 2026, decision P3;
//! Lane P design `qualification/candidate-3/P-LANE-DESIGN-V1.md` section 4 and test plan 14.3).
//! This file holds the rows outside trading (work package WP-P3a): the hybrid Transfer output owner
//! (design 4.1 row 1) and the dividend claim destination (row 10). Later work packages append their
//! rows here. Every block is prepared by the production assembler or crafted from a prepared
//! candidate, certified with real hybrid votes and installed by `CanonicalStore::commit`, which
//! re-executes it; a rejected block leaves every table of the store byte-identical. The crafted
//! items carry GENUINE signatures over their own bytes, so the refusal is the destination rule and
//! nothing else. TEST-VALUE data only (public mnemonic seeds).
#![allow(dead_code, unused_imports)]
#[path = "../../desktop/src/wallet_host_fixture_licenses.rs"]
mod licenses;
#[path = "support/wallet_host_fixture_tpm.rs"]
mod tpm;
include!("support/dividend_rig.rs");

use mutiny_consensus_v8::{
    dividend_claim_v1::ClaimError, execution::ExecutionError, finality_v2::StoreError, transactions::TxError,
    votes::IngressError,
};
use mutiny_crypto_v2::Domain;

fn prepare(rig: &Rig, epoch: u64, operations: &[Vec<u8>]) -> mutiny_consensus_v8::assembler_v2::Prepared {
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
/// candidate with its item lists substituted, the declared fees adjusted and the body root
/// recomputed.
fn craft(
    rig: &Rig,
    mut prepared: mutiny_consensus_v8::assembler_v2::Prepared,
    transactions: Vec<Vec<u8>>,
    operations: Vec<Vec<u8>>,
    fees: u64,
) -> BlockEnvelope {
    prepared.body.transactions = transactions;
    prepared.body.operations = operations;
    prepared.body.fees = fees;
    prepared.candidate.body_root = prepared.body.root().unwrap();
    certify_at(prepared, &rig.f, &rig.parent, &rig.state, rig.ticket)
}
/// Every row of every table of the durable store, through a separate read-only connection.
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
/// The HybridTransferV2 layout (spec WALLET-HYBRID-TRANSACTION-V2: `[2, NetworkID, GenesisID,
/// ProtocolFingerprint, created_height, expiry_height, fee_atoms, inputs, outputs]`; signed inputs
/// `[txid, index, descriptor, ed448, fndsa]`, unsigned `[txid, index, descriptor]`, outputs
/// `[AddressID, atoms]`), written WITHOUT the codec's checks so that a crafted transfer can carry a
/// zero owner. Pinned to the real encoder for a valid transfer below.
fn raw_transfer(t: &Transfer, signed: bool) -> Vec<u8> {
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(9)
        .unwrap()
        .u8(2)
        .unwrap()
        .u32(t.network)
        .unwrap()
        .bytes(&t.genesis)
        .unwrap()
        .bytes(&t.fingerprint)
        .unwrap()
        .u64(t.created_height)
        .unwrap()
        .u64(t.expiry_height)
        .unwrap()
        .u64(t.fee)
        .unwrap()
        .array(t.inputs.len() as u64)
        .unwrap();
    for input in &t.inputs {
        e.array(if signed { 5 } else { 3 })
            .unwrap()
            .bytes(&input.point.transaction)
            .unwrap()
            .u32(input.point.index)
            .unwrap()
            .bytes(&input.descriptor)
            .unwrap();
        if signed {
            e.bytes(&input.signature.ed448).unwrap().bytes(&input.signature.fndsa).unwrap();
        }
    }
    e.array(t.outputs.len() as u64).unwrap();
    for output in &t.outputs {
        e.array(2).unwrap().bytes(&output.owner).unwrap().u64(output.atoms).unwrap();
    }
    e.into_writer()
}
/// Signs every input over `[unsigned_transfer_bytes, input_index]` under the wallet-transaction
/// intent domain, exactly as `Transfer::sign_input` does, but over the crafted unsigned bytes.
fn sign_crafted(t: &mut Transfer, key: &HybridKey) {
    let unsigned = raw_transfer(t, false);
    for index in 0..t.inputs.len() {
        let mut payload = minicbor::Encoder::new(Vec::new());
        payload.array(2).unwrap().bytes(&unsigned).unwrap().u32(index as u32).unwrap();
        t.inputs[index].signature = key.sign(Domain::Transaction, &payload.into_writer()).unwrap();
    }
}

/// Design 14.3 `transfer_zero_owner_rejected` (design 4.1 row 1).
#[test]
fn transfer_zero_owner_rejected() {
    let treasury = treasury_key();
    let destination = [0x91; 32];
    let mut rig = Rig::new(fixture_with_treasury(&treasury, 1_200_000), "zero-owner");
    let point = OutPoint { transaction: [0xd1; 32], index: 0 };
    let base = |owner: Hash| Transfer {
        network: NETWORK_ID,
        genesis: rig.f.genesis.genesis,
        fingerprint: rig.f.genesis.fingerprint,
        created_height: 1,
        expiry_height: 10_000,
        fee: 7_000,
        inputs: vec![Input::unsigned(point.clone(), treasury.public(), 1).unwrap()],
        outputs: vec![Output { owner, atoms: 1_200_000 - 7_000 }],
    };
    // Oracle: the crafted writer and signer reproduce the codec exactly for a valid transfer.
    let mut good = base(destination);
    sign_crafted(&mut good, &treasury);
    assert_eq!(raw_transfer(&good, true), good.encode().unwrap());
    good.verify_signatures().unwrap();
    // The codec refuses a zero owner in every direction, so it cannot be signed through the API.
    let mut zero = base([0; 32]);
    assert_eq!(zero.encode(), Err(TxError::Bounds));
    assert_eq!(zero.id(), Err(TxError::Bounds));
    assert_eq!(zero.signing_payload(0), Err(TxError::Bounds));
    assert_eq!(zero.sign_input(0, &treasury), Err(TxError::Bounds));
    // A crafted, genuinely signed zero-owner transfer cannot be decoded ...
    sign_crafted(&mut zero, &treasury);
    let raw = raw_transfer(&zero, true);
    assert_eq!(raw.len(), good.encode().unwrap().len(), "only the owner bytes and the signatures differ");
    assert_eq!(Transfer::decode(&raw), Err(TxError::Bounds));
    assert_eq!(Transaction::decode(&raw), Err(TxError::Bounds));
    // ... and makes a certified block invalid at commit: exact error, store byte-identical.
    let block = craft(&rig, prepare(&rig, 1, &[]), vec![raw], vec![], 7_000);
    let error = rejected_without_effect(&mut rig, &block);
    assert!(
        matches!(error, StoreError::Verification(IngressError::Execution(ExecutionError::Transfer(TxError::Bounds)))),
        "{error:?}"
    );
    // Control: the same transfer to a nonzero owner is admitted, assembled and committed.
    rig.pool.admit(&Transaction::Transfer(good), &rig.parent, &rig.state).unwrap();
    let s1 = rig.step(1, &[]);
    assert_eq!(held_by(&s1, destination), 1_200_000 - 7_000);
    rig.finish();
}

/// Design 14.3 `claim_zero_destination_rejected` (design 4.1 row 10).
#[test]
fn claim_zero_destination_rejected() {
    let treasury = treasury_key();
    let owner = owner_key();
    let destination = [0x92; 32];
    let mut rig = Rig::new(fixture_with_treasury(&treasury, 1_200_000), "zero-claim");
    rig.step(P, &[]);
    let body = |destination: Hash| ClaimBody {
        network: NETWORK_ID,
        genesis: rig.f.genesis.genesis,
        fingerprint: rig.f.genesis.fingerprint,
        created_height: 1,
        expiry_height: 10_000,
        award_epoch: P,
        license: license(0),
        amount: 10_000,
        destination,
        sequence: 0,
    };
    // The codec refuses a zero destination; the same body with a real destination decodes.
    assert_eq!(ClaimBody::decode(&body([0; 32]).encode()), Err(ClaimError::Destination));
    assert_eq!(ClaimBody::decode(&body(destination).encode()), Ok(body(destination)));
    // A genuinely signed zero-destination claim (signing is a client helper; consensus refuses it in
    // the codec and in `check`).
    let zero = SignedClaim::sign(body([0; 32]), desc(&owner, 1), &owner).unwrap();
    zero.verify_signature().unwrap();
    let raw = zero.encode();
    assert_eq!(SignedClaim::decode(&raw), Err(ClaimError::Destination));
    let epoch = P + 1;
    let (genesis, fingerprint) = (rig.f.genesis.genesis, rig.f.genesis.fingerprint);
    assert_eq!(
        mutiny_consensus_v8::dividend_claim_v1::admit(&rig.state, &raw, genesis, fingerprint, rig.height() + 1, epoch),
        Err(ClaimError::Destination)
    );
    // The assembler refuses it; a certified block carrying it is refused by commit with the exact
    // error and the store stays byte-identical.
    let assembled = rig.try_step(epoch, &[raw.clone()]).unwrap_err();
    assert!(assembled.contains("Dividend(Destination)"), "{assembled}");
    let block = craft(&rig, prepare(&rig, epoch, &[]), vec![], vec![raw], 0);
    let error = rejected_without_effect(&mut rig, &block);
    assert!(
        matches!(error, StoreError::Verification(IngressError::Execution(ExecutionError::Dividend(ClaimError::Destination)))),
        "{error:?}"
    );
    // Control: the identical claim with a nonzero destination is accepted.
    let s = rig.step(epoch, &[claim_op(&rig.f, &owner, 0, P, 10_000, 0, destination)]);
    assert_eq!(held_by(&s, destination), 10_000);
    rig.finish();
}

/// Design 14.3 `legitimate_zero_fields_still_accepted`, for the fields WP-P3a touches (design 4.2):
/// zero values that are not monetary destinations stay legal. A transfer created at height 0 that
/// spends the output 0 of an all-zero transaction id; a claim created at height 0 with sequence 0.
#[test]
fn legitimate_zero_fields_still_accepted() {
    let treasury = treasury_key();
    let owner = owner_key();
    let spender = second_key();
    let mut f = fixture_with_treasury(&treasury, 1_200_000);
    let zero_point = OutPoint { transaction: [0; 32], index: 0 };
    f.state.coins.insert(
        zero_point.clone(),
        Coin { output: Output { owner: addr(&spender, 1), atoms: 50_000 }, created_height: 0, coinbase: false },
    );
    let mut rig = Rig::new(f, "zero-legit");
    let mut t = Transfer {
        network: NETWORK_ID,
        genesis: rig.f.genesis.genesis,
        fingerprint: rig.f.genesis.fingerprint,
        created_height: 0,
        expiry_height: 10_000,
        fee: 7_000,
        inputs: vec![Input::unsigned(zero_point, spender.public(), 1).unwrap()],
        outputs: vec![Output { owner: [0x93; 32], atoms: 43_000 }],
    };
    t.sign_input(0, &spender).unwrap();
    rig.pool.admit(&Transaction::Transfer(t), &rig.parent, &rig.state).unwrap();
    let s1 = rig.step(P, &[]);
    assert_eq!(held_by(&s1, [0x93; 32]), 43_000);
    let claim = SignedClaim::sign(
        ClaimBody {
            network: NETWORK_ID,
            genesis: rig.f.genesis.genesis,
            fingerprint: rig.f.genesis.fingerprint,
            created_height: 0,
            expiry_height: 10_000,
            award_epoch: P,
            license: license(0),
            amount: 10_000,
            destination: [0x94; 32],
            sequence: 0,
        },
        desc(&owner, 1),
        &owner,
    )
    .unwrap();
    let s2 = rig.step(P + 1, &[claim.encode()]);
    assert_eq!(held_by(&s2, [0x94; 32]), 10_000);
    rig.finish();
}

// P3 zero monetary destinations through REAL blocks (Order of 4 Oct 2026 decision P3; Lane P design
// `qualification/candidate-3/P-LANE-DESIGN-V1.md` sections 4.1-4.3 and test plan 14.3 with
// amendment AM-11). Every block is prepared by the production assembler, executed by the V2
// executor and installed only through `CanonicalStore::commit`; a rejected block must leave the
// head, the canonical State and every store row byte-identical. TEST-VALUE fixtures only (public
// BIP39 phrases, fresh random Transport maker keys); evidence class at most
// NATIVE-PASS-offline-TEST-VALUE on the host that runs it.
//
// The rows are grouped by work package: the trading rows (WP-T1) live in the self-contained
// `mod trading` below; the transfer and claim rows of WP-P3a are the file-scope items above.

/// WP-T1: trading fields (design 4.1 rows 4-9 and 14). A trading item that fails
/// `NativeOperation::decode` cannot even be carried by a `BlockBody` (`BlockBody::encode` refuses
/// it), so "no block exists" (AM-11 (ii)); the production preparation path refuses a block
/// proposing it with the store byte-identical; the read-only consensus entry point reports the exact
/// error (`Candidate(Bounds)`) on the same parent state; and the in-memory operation can be neither
/// encoded nor signed. The defensive `credit` refusal (AM-11 (iii)) is a unit test in
/// `consensus/src/trading_v1_tests.rs` (`credit_refuses_a_zero_owner_whatever_the_amount`).
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
    use mutiny_consensus_v8::{Error, blocks::BlockBody};

    const DESTINATION: Hash = [0x5d; 32];

    fn genesis_window(rig: &Rig, last: u64) -> Window {
        Window { first: rig.height() + 1, last, reference: (rig.parent.height, rig.parent.block) }
    }

    /// (i) the codec refuses the crafted item with the exact error, (ii) no block body can carry
    /// it, (iii) a real block proposing it is refused with the store byte-identical, (iv) the
    /// read-only consensus entry point reports the exact error on the same parent state.
    fn refused_everywhere(rig: &mut Rig, name: &str, crafted: &[u8], epoch: u64) {
        assert_eq!(
            tr::NativeOperation::decode(crafted),
            Err(tr::NativeError::Candidate(tr::Error::Bounds)),
            "{name}: codec refusal"
        );
        let body = BlockBody {
            height: rig.height() + 1,
            reward_owner: [1; 32],
            fees: 0,
            transactions: vec![],
            operations: vec![crafted.to_vec()],
        };
        assert_eq!(body.encode(), Err(Error::WrongOperation), "{name}: no block body can carry it");
        assert!(body.root().is_err(), "{name}: no body root, so no candidate or certificate exists");
        let text = rejected_unchanged(rig, epoch, &[crafted.to_vec()]);
        assert!(text.contains("WrongOperation"), "{name}: assembly refuses the item itself: {text}");
        assert!(
            matches!(native_verdict(rig, &[crafted.to_vec()]), Err(tr::NativeError::Candidate(tr::Error::Bounds))),
            "{name}: exact error at prepare_batch on the same parent state"
        );
    }

    /// The same operation with one destination field zeroed IN MEMORY: unrepresentable and unsignable.
    fn unsignable(name: &str, honest: &tr::NativeOperation, zero: impl Fn(&mut tr::Action), signer: &HybridKey) {
        let mut op = honest.operation.clone();
        zero(&mut op.action);
        op.approvals.clear();
        assert_eq!(op.body(), Err(tr::Error::Bounds), "{name}: body");
        assert_eq!(op.id(), Err(tr::Error::Bounds), "{name}: no operation id");
        assert_eq!(
            op.signing_payload(0, &signer.public().descriptor(1).unwrap()),
            Err(tr::Error::Bounds),
            "{name}: no approval payload exists, so nobody can sign it"
        );
        assert_eq!(op.approve(0, signer, 1), Err(tr::Error::Bounds), "{name}: approve refuses");
        let wire = tr::NativeOperation { operation: op, inputs: honest.inputs.clone() };
        assert_eq!(wire.encode(), Err(tr::NativeError::Candidate(tr::Error::Bounds)), "{name}: encode");
    }

    #[test]
    fn dvp_zero_payment_destination_rejected() {
        let (seller, buyer) = (owner_key(), second_key());
        let mut f = fixture();
        let pay = fund(&mut f, 0xa5, addr(&buyer, 1), 100_000);
        let sold = license(3);
        let mut rig = Rig::new(f, "zero-dvp");
        let window = genesis_window(&rig, 10);
        let dvp = trade_with(
            &rig.f,
            tr::Action::LicenseDvp {
                offer: [0; 32],
                maker: [0; 32],
                license: sold,
                license_generation: 1,
                seller: addr(&seller, 1),
                buyer: addr(&buyer, 1),
                price: tr::Strikes(50_000),
                payment_destination: DESTINATION,
                change: tr::Strikes(30_000),
            },
            window,
            // WP-T2 (design 6.1): the sale commits the License facts it was reviewed against.
            vec![
                mutiny_consensus_v8::op_envelope_v1::entitlement_facts(&rig.state, sold),
                mutiny_consensus_v8::op_envelope_v1::assignment_facts(&rig.state, sold).unwrap(),
            ],
            20_000,
            &[pay.clone()],
            &[(0, &seller, 1), (1, &buyer, 1)],
        );
        let honest = dvp.encode().unwrap();
        let crafted = zero_field(&honest, &DESTINATION);
        refused_everywhere(&mut rig, "LicenseDvp payment_destination", &crafted, 1);
        unsignable(
            "LicenseDvp payment_destination",
            &dvp,
            |a| {
                if let tr::Action::LicenseDvp { payment_destination, .. } = a {
                    *payment_destination = [0; 32]
                }
            },
            &seller,
        );
        // Control: the identical sale with its signed non-zero destination is accepted and pays it.
        let s1 = rig.step(1, &[honest]);
        assert_eq!(s1.licenses_v2.license(sold).unwrap().owner, addr(&buyer, 1));
        let paid = s1.coins[&OutPoint { transaction: dvp.operation.id().unwrap(), index: 0 }].clone();
        assert_eq!((paid.output.owner, paid.output.atoms), (DESTINATION, 50_000));
        rig.finish();
    }

    #[test]
    fn trading_zero_address_per_field_rejected() {
        let (a, b, c) = (owner_key(), second_key(), treasury_key());
        let (aa, ba, ca) = (addr(&a, 1), addr(&b, 1), addr(&c, 1));
        let nb = addr(&b, 2);
        let mut f = fixture();
        let p_lock = fund(&mut f, 0xb1, aa, 100_000);
        let p_fiat = fund(&mut f, 0xb2, aa, 100_000);
        let p_claim = fund(&mut f, 0xb3, ba, 100_000);
        let p_release = fund(&mut f, 0xb4, ba, 100_000);
        let p_dvp = fund(&mut f, 0xb5, ba, 100_000);
        let p_rotate = fund(&mut f, 0xb6, ca, 100_000);
        let p_refund = fund(&mut f, 0xb7, aa, 100_000);
        let p_lock2 = fund(&mut f, 0xb8, aa, 100_000);
        // P6 (WP-T3): T = ca is the Genesis Treasury authority; R1 already moved T's key to b at
        // generation 2, so the honest R2 routes to nb, approved by that current key.
        genesis_treasury_after_r1(&mut f, &c, (&b, 2));
        let mut rig = Rig::new(f, "zero-fields");
        let w1 = genesis_window(&rig, 10);
        let hash_lock = |input: &OutPoint, refund_height: u64, window: Window, rig: &Rig| {
            trade(
                &rig.f,
                tr::Action::HashLock {
                    offer: [0; 32],
                    maker: [0; 32],
                    sender: aa,
                    recipient: ba,
                    amount: tr::Strikes(50_000),
                    condition: tr::preimage_hash(&[42; 32]),
                    refund_height,
                    change: tr::Strikes(30_000),
                },
                window,
                20_000,
                &[input.clone()],
                &[(0, &a, 1), (1, &b, 1)],
            )
        };
        let lock = hash_lock(&p_lock, 20, w1, &rig);
        let lock2 = hash_lock(&p_lock2, 3, Window { last: 2, ..w1 }, &rig);
        let fiat = trade(
            &rig.f,
            tr::Action::FiatLock {
                offer: [0; 32],
                maker: [0; 32],
                seller: aa,
                buyer: ba,
                amount: tr::Strikes(50_000),
                payment_terms: [51; 32],
                change: tr::Strikes(30_000),
            },
            w1,
            20_000,
            &[p_fiat],
            &[(0, &a, 1), (1, &b, 1)],
        );
        // Block 1: the honest locks (the crafted lock rows below are refused at this same parent).
        let lock_rows: [(&str, &tr::NativeOperation, Hash, &dyn Fn(&mut tr::Action)); 4] = [
            ("HashLock sender", &lock, aa, &|x| if let tr::Action::HashLock { sender, .. } = x { *sender = [0; 32] }),
            ("HashLock recipient", &lock, ba, &|x| if let tr::Action::HashLock { recipient, .. } = x { *recipient = [0; 32] }),
            ("FiatLock seller", &fiat, aa, &|x| if let tr::Action::FiatLock { seller, .. } = x { *seller = [0; 32] }),
            ("FiatLock buyer", &fiat, ba, &|x| if let tr::Action::FiatLock { buyer, .. } = x { *buyer = [0; 32] }),
        ];
        for (name, honest, value, zero) in lock_rows {
            refused_everywhere(&mut rig, name, &zero_field(&honest.encode().unwrap(), &value), 1);
            unsignable(name, honest, zero, &a);
        }
        rig.step(1, &[lock.encode().unwrap(), lock2.encode().unwrap(), fiat.encode().unwrap()]);
        let w2 = genesis_window(&rig, 10);
        let claim = trade(
            &rig.f,
            tr::Action::Claim {
                output: lock.operation.output_id(0).unwrap(),
                recipient: ba,
                amount: tr::Strikes(50_000),
                preimage: [42; 32],
                change: tr::Strikes(80_000),
            },
            w2,
            20_000,
            &[p_claim],
            &[(0, &b, 1)],
        );
        let release = trade(
            &rig.f,
            tr::Action::FiatRelease {
                output: fiat.operation.output_id(0).unwrap(),
                buyer: ba,
                seller: aa,
                amount: tr::Strikes(50_000),
                payment_terms: [51; 32],
                change: tr::Strikes(80_000),
            },
            w2,
            20_000,
            &[p_release],
            &[(0, &b, 1), (1, &a, 1)],
        );
        let dvp = trade_with(
            &rig.f,
            tr::Action::LicenseDvp {
                offer: [0; 32],
                maker: [0; 32],
                license: license(4),
                license_generation: 1,
                seller: aa,
                buyer: ba,
                price: tr::Strikes(50_000),
                payment_destination: DESTINATION,
                change: tr::Strikes(30_000),
            },
            w2,
            // WP-T2 (design 6.1): the sale commits the License facts it was reviewed against.
            vec![
                mutiny_consensus_v8::op_envelope_v1::entitlement_facts(&rig.state, license(4)),
                mutiny_consensus_v8::op_envelope_v1::assignment_facts(&rig.state, license(4)).unwrap(),
            ],
            20_000,
            &[p_dvp],
            &[(0, &a, 1), (1, &b, 1)],
        );
        let rotate = trade(
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
            w2,
            20_000,
            &[p_rotate],
            &[(0, &b, 2)],
        );
        let refund = trade(
            &rig.f,
            tr::Action::Refund {
                output: lock2.operation.output_id(0).unwrap(),
                owner: aa,
                amount: tr::Strikes(50_000),
                change: tr::Strikes(80_000),
            },
            Window { first: 3, last: 10, reference: w2.reference },
            20_000,
            &[p_refund.clone()],
            &[(0, &a, 1)],
        );
        let rows: [(&str, &tr::NativeOperation, Hash, &dyn Fn(&mut tr::Action)); 8] = [
            ("Claim recipient", &claim, ba, &|x| if let tr::Action::Claim { recipient, .. } = x { *recipient = [0; 32] }),
            ("Refund owner", &refund, aa, &|x| if let tr::Action::Refund { owner, .. } = x { *owner = [0; 32] }),
            ("FiatRelease buyer", &release, ba, &|x| if let tr::Action::FiatRelease { buyer, .. } = x { *buyer = [0; 32] }),
            ("FiatRelease seller", &release, aa, &|x| if let tr::Action::FiatRelease { seller, .. } = x { *seller = [0; 32] }),
            ("LicenseDvp buyer", &dvp, ba, &|x| if let tr::Action::LicenseDvp { buyer, .. } = x { *buyer = [0; 32] }),
            ("LicenseDvp payment_destination", &dvp, DESTINATION, &|x| if let tr::Action::LicenseDvp { payment_destination, .. } = x { *payment_destination = [0; 32] }),
            ("TreasuryRotate current_address", &rotate, ca, &|x| if let tr::Action::TreasuryRotate { current_address, .. } = x { *current_address = [0; 32] }),
            ("TreasuryRotate new_address", &rotate, nb, &|x| if let tr::Action::TreasuryRotate { new_address, .. } = x { *new_address = [0; 32] }),
        ];
        for (name, honest, value, zero) in rows {
            // P6: the rotation's `treasury` field is T = ca, also its head address (zero_second).
            let raw = honest.encode().unwrap();
            let crafted = if name == "TreasuryRotate current_address" { zero_second(&raw, &value) } else { zero_field(&raw, &value) };
            refused_everywhere(&mut rig, name, &crafted, 2);
            unsignable(name, honest, zero, &a);
        }
        // Controls: the identical honest items are accepted in real blocks, so each refusal above is
        // the zero field and nothing else.
        let s2 = rig.step(
            2,
            &[claim.encode().unwrap(), release.encode().unwrap(), dvp.encode().unwrap(), rotate.encode().unwrap()],
        );
        let paid = |id: Hash, i: u32, s: &State| s.coins.get(&OutPoint { transaction: id, index: i }).cloned();
        assert_eq!(paid(claim.operation.id().unwrap(), 0, &s2).unwrap().output.owner, ba);
        assert_eq!(paid(release.operation.id().unwrap(), 0, &s2).unwrap().output.owner, ba);
        assert_eq!(paid(dvp.operation.id().unwrap(), 0, &s2).unwrap().output.owner, DESTINATION);
        assert_eq!(tr::treasury_current(&s2, &trade_context(&rig.f), ca).unwrap().address, nb);
        let refund_ok = trade(
            &rig.f,
            tr::Action::Refund {
                output: lock2.operation.output_id(0).unwrap(),
                owner: aa,
                amount: tr::Strikes(50_000),
                change: tr::Strikes(80_000),
            },
            genesis_window(&rig, 10),
            20_000,
            &[p_refund],
            &[(0, &a, 1)],
        );
        let s3 = rig.step(3, &[refund_ok.encode().unwrap()]);
        assert_eq!(paid(refund_ok.operation.id().unwrap(), 0, &s3).unwrap().output.owner, aa);
        rig.finish();
    }

    #[test]
    fn legitimate_zero_fields_still_accepted() {
        let (a, b, c) = (owner_key(), second_key(), treasury_key());
        let (aa, ba, ca) = (addr(&a, 1), addr(&b, 1), addr(&c, 1));
        let nb = addr(&b, 2);
        let mut f = fixture();
        let p_lock = fund(&mut f, 0xc1, aa, 100_000);
        let p_fiat = fund(&mut f, 0xc2, aa, 100_000);
        let p_claim = fund(&mut f, 0xc3, ba, 20_000);
        let p_rotate = fund(&mut f, 0xc4, ca, 20_000);
        let p_zero_condition = fund(&mut f, 0xc5, aa, 100_000);
        // P6 (WP-T3): T = ca is the Genesis Treasury authority; R1 already moved T's key to b at
        // generation 2, so the honest R2 routes to nb, approved by that current key.
        genesis_treasury_after_r1(&mut f, &c, (&b, 2));
        let mut rig = Rig::new(f, "zero-legit");
        let w1 = genesis_window(&rig, 10);
        // change = 0 (absence: no change output), a zero-preimage condition, zero payment terms.
        let lock = trade(
            &rig.f,
            tr::Action::HashLock {
                offer: [0; 32],
                maker: [0; 32],
                sender: aa,
                recipient: ba,
                amount: tr::Strikes(80_000),
                condition: tr::preimage_hash(&[0; 32]),
                refund_height: 20,
                change: tr::Strikes(0),
            },
            w1,
            20_000,
            &[p_lock],
            &[(0, &a, 1), (1, &b, 1)],
        );
        let fiat = trade(
            &rig.f,
            tr::Action::FiatLock {
                offer: [0; 32],
                maker: [0; 32],
                seller: aa,
                buyer: ba,
                amount: tr::Strikes(80_000),
                payment_terms: [0; 32],
                change: tr::Strikes(0),
            },
            w1,
            20_000,
            &[p_fiat],
            &[(0, &a, 1), (1, &b, 1)],
        );
        let rotate = trade(
            &rig.f,
            tr::Action::TreasuryRotate {
                treasury: ca,
                current_generation: 1,
                current_address: ca,
                current_descriptor: tr::descriptor_hash(&desc(&b, 2)),
                new_generation: 2,
                new_address: nb,
                new_descriptor: desc(&b, 2),
                change: tr::Strikes(0),
            },
            w1,
            20_000,
            &[p_rotate],
            &[(0, &b, 2)],
        );
        // A literal zero condition is a hash commitment, not a destination: such a lock can only be
        // refunded, and it is accepted.
        let zero_condition = trade(
            &rig.f,
            tr::Action::HashLock {
                offer: [0; 32],
                maker: [0; 32],
                sender: aa,
                recipient: ba,
                amount: tr::Strikes(50_000),
                condition: [0; 32],
                refund_height: 20,
                change: tr::Strikes(30_000),
            },
            w1,
            20_000,
            &[p_zero_condition],
            &[(0, &a, 1), (1, &b, 1)],
        );
        let s1 = rig.step(
            1,
            &[lock.encode().unwrap(), fiat.encode().unwrap(), rotate.encode().unwrap(), zero_condition.encode().unwrap()],
        );
        assert!(tr::locked(&s1, zero_condition.operation.output_id(0).unwrap()).is_ok(), "zero condition is legal");
        for op in [&lock, &fiat, &rotate] {
            let id = op.operation.id().unwrap();
            assert!(!s1.coins.keys().any(|p| p.transaction == id), "change = 0 creates no output");
        }
        assert_eq!(tr::locked(&s1, lock.operation.output_id(0).unwrap()).unwrap().amount, tr::Strikes(80_000));
        assert!(tr::locked(&s1, fiat.operation.output_id(0).unwrap()).is_ok(), "zero payment terms are legal");
        // The single-fill key keeps its fixed zero maker argument (design 4.2).
        let tr::Action::HashLock { offer, .. } = lock.operation.action else { unreachable!() };
        let key = tr::record_key(1, tr::single_fill_key(&trade_context(&rig.f), [0; 32], offer));
        assert!(s1.protocol_records.contains_key(&key));
        // A zero preimage is a legal value, and a claim with change = 0 pays the locked principal.
        let claim = trade(
            &rig.f,
            tr::Action::Claim {
                output: lock.operation.output_id(0).unwrap(),
                recipient: ba,
                amount: tr::Strikes(80_000),
                preimage: [0; 32],
                change: tr::Strikes(0),
            },
            genesis_window(&rig, 10),
            20_000,
            &[p_claim],
            &[(0, &b, 1)],
        );
        let s2 = rig.step(2, &[claim.encode().unwrap()]);
        let id = claim.operation.id().unwrap();
        assert_eq!(s2.coins[&OutPoint { transaction: id, index: 0 }].output, Output { owner: ba, atoms: 80_000 });
        assert!(!s2.coins.contains_key(&OutPoint { transaction: id, index: 1 }), "no change output");
        rig.finish();
    }
}
