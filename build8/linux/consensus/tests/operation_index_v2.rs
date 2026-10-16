#![cfg(feature = "dividend-test-fixtures")]
//! Windows software TEST-VALUE real-block confirmation/replay tests. No production keys.
#[path = "../../desktop/src/wallet_host_fixture_licenses.rs"]
mod licenses;
#[path = "support/wallet_host_fixture_tpm.rs"]
mod tpm;
include!("support/dividend_rig.rs");
use mutiny_consensus_v8::{
    finality_v2::StoreError,
    operation_index_v2::{self as index, IndexError, OperationRecord},
};
use rusqlite::{Connection, types::Value};
use std::collections::BTreeMap;

fn rows(rig: &Rig, id: Hash) -> Vec<OperationRecord> {
    rig.chain.operation_records(id).unwrap()
}
fn database(path: &std::path::Path) -> Vec<(String, Vec<Vec<Value>>)> {
    let db = Connection::open(path).unwrap();
    let names: Vec<String> = db
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .collect();
    names
        .into_iter()
        .map(|name| {
            let mut q = db
                .prepare(&format!("SELECT * FROM {name} ORDER BY 1"))
                .unwrap();
            let count = q.column_count();
            let values = q
                .query_map([], |r| {
                    (0..count)
                        .map(|i| r.get(i))
                        .collect::<rusqlite::Result<Vec<Value>>>()
                })
                .unwrap()
                .map(|r| r.unwrap())
                .collect();
            (name, values)
        })
        .collect()
}
fn claim_rig(tag: &str) -> (Rig, Vec<u8>, Hash) {
    let mut rig = Rig::new(fixture_with_treasury(&treasury_key(), 1_200_000), tag);
    rig.step(P, &[]);
    let raw = claim_op(
        &rig.f,
        &owner_key(),
        0,
        P,
        10_000,
        0,
        addr(&second_key(), 1),
    );
    let id = index::operation_id(1, &raw).unwrap().1;
    rig.step(P + 1, &[raw.clone()]);
    (rig, raw, id)
}
#[test]
fn every_wallet_kind_has_a_stable_unsigned_identity_and_typed_receipt() {
    use mutiny_consensus_v8::{
        bond_create_v3::FundedBondCreate,
        bond_ops_v2,
        license_assignment_v2::Assignment,
        op_envelope_v1::Envelope,
        trading_v1::{Action, Context, Meta, NativeOperation, Operation, Strikes, native_input_id},
    };
    let f = fixture();
    let point = OutPoint {
        transaction: [0xc1; 32],
        index: 0,
    };
    let tx = transfer(
        &f,
        &owner_key(),
        1,
        point.clone(),
        5000,
        vec![Output {
            owner: addr(&second_key(), 1),
            atoms: 5000,
        }],
    );
    let rotation: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/funded-rotation-v2-public.json"
    ))
    .unwrap();
    let bond: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/funded-bond-create-v1-public.json"
    ))
    .unwrap();
    let assignment: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/license-assignment-v2-public-v1.json"
    ))
    .unwrap();
    let commands: serde_json::Value = serde_json::from_str(include_str!(
        "../../qualification/hybrid-bond-public-v1.json"
    ))
    .unwrap();
    let bytes = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let mut trade = Operation {
        meta: Meta {
            context: Context {
                network: NETWORK_ID,
                genesis: f.genesis.genesis,
                fingerprint: f.genesis.fingerprint,
            },
            trade: [0xc2; 32],
            contract: [0xc3; 32],
            generation: 1,
            envelope: Envelope::from_head(&f.genesis, 20, vec![]).unwrap(),
            fee: Strikes(5000),
            inputs: vec![native_input_id(&point)],
        },
        action: Action::Refund {
            output: [0xc4; 32],
            owner: addr(&owner_key(), 1),
            amount: Strikes(5000),
            change: Strikes(5000),
        },
        approvals: vec![],
        offer_proof: None,
    };
    trade.approve(0, &owner_key(), 1).unwrap();
    let trade = NativeOperation {
        operation: trade,
        inputs: vec![point],
    };
    let cases = vec![
        (0, 1, tx.encode().unwrap()),
        (0, 2, bytes(&rotation["cases"][0]["transaction_hex"])),
        (1, 10, bytes(&assignment["assignments"][0])),
        (1, 19, bytes(&commands["new_unbond"])),
        (1, 20, bytes(&commands["withdraw"])),
        (
            1,
            23,
            claim_op(&f, &owner_key(), 0, P, 10_000, 0, addr(&second_key(), 1)),
        ),
        (1, 24, bytes(&bond["valid"][0]["op_hex"])),
        (1, 30, trade.encode().unwrap()),
    ];
    for (list, kind, raw) in cases {
        let (actual, id) = index::operation_id(list, &raw).unwrap();
        assert_eq!(actual, kind);
        let altered = match kind {
            1 | 2 => {
                let mut t = Transaction::decode(&raw).unwrap();
                match &mut t {
                    Transaction::Transfer(t) => t.inputs[0].signature.ed448[0] ^= 1,
                    Transaction::FundedRotation(t) => t.authorize.ed448[0] ^= 1,
                };
                t.encode().unwrap()
            }
            10 => {
                let mut a = Assignment::decode(&raw).unwrap();
                a.enrollment.owner_signature.ed448[0] ^= 1;
                a.encode().unwrap()
            }
            19 | 20 => {
                let mut a = bond_ops_v2::Operation::decode(&raw).unwrap();
                a.signature.ed448[0] ^= 1;
                a.encode().unwrap()
            }
            23 => {
                let mut a = SignedClaim::decode(&raw).unwrap();
                a.signature.ed448[0] ^= 1;
                a.encode()
            }
            24 => {
                let mut a = FundedBondCreate::decode(&raw).unwrap();
                a.create.ed448[0] ^= 1;
                a.encode().unwrap()
            }
            30 => {
                let mut a = NativeOperation::decode(&raw).unwrap();
                a.operation.approvals[0].signature.ed448[0] ^= 1;
                a.encode().unwrap()
            }
            _ => unreachable!(),
        };
        assert_ne!(raw, altered);
        assert_eq!(index::operation_id(list, &altered).unwrap(), (kind, id));
        let body = mutiny_consensus_v8::blocks::BlockBody {
            height: 1,
            reward_owner: [1; 32],
            fees: 0,
            transactions: if list == 0 { vec![raw.clone()] } else { vec![] },
            operations: if list == 1 { vec![raw] } else { vec![] },
        };
        let outcomes = [(id, bond_ops_v2::CommandOutcome::Applied)]
            .into_iter()
            .collect();
        let r = index::records(&body, [2; 32], &outcomes).unwrap().remove(0);
        assert!(r.receipt.is_some());
        r.verify_in_block(&body, [2; 32]).unwrap();
        assert_eq!(OperationRecord::decode(&r.encode().unwrap()).unwrap(), r);
    }
    // These are codec vectors, not executable multi-kind block evidence.
    assert_eq!(index::operation_id(2, &[0x80]), Err(IndexError::Bounds));
    assert_eq!(
        index::operation_id(1, &[0x83, 2, 18, 0]),
        Err(IndexError::Codec)
    );
    for (kind, len, version) in [
        (11, 10, 1),
        (12, 10, 1),
        (14, 5, 2),
        (15, 5, 2),
        (16, 9, 2),
        (17, 4, 2),
        (21, 7, 2),
        (22, 7, 2),
    ] {
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(len).unwrap().u8(version).unwrap().u8(kind).unwrap();
        for _ in 2..len {
            e.u8(0).unwrap();
        }
        let raw = e.into_writer();
        let identity = index::operation_id(1, &raw).unwrap();
        let mut other = raw.clone();
        *other.last_mut().unwrap() = 1;
        assert_eq!(identity.0, kind);
        assert_ne!(identity.1, index::operation_id(1, &other).unwrap().1);
    }
}
#[test]
fn confirmed_claim_stays_confirmed_after_payout_spent() {
    let (mut rig, raw, id) = claim_rig("idx-spent");
    let before = rows(&rig, id);
    assert_eq!(before.len(), 1);
    let record = &before[0];
    assert_eq!(
        (record.kind, record.height, record.list, record.position),
        (23, 2, 1, 0)
    );
    assert_eq!(record.op_id, SignedClaim::decode(&raw).unwrap().id());
    let point = OutPoint {
        transaction: id,
        index: 0,
    };
    assert!(rig.state.coins.contains_key(&point));
    let pay = transfer(
        &rig.f,
        &second_key(),
        1,
        point.clone(),
        5000,
        vec![Output {
            owner: addr(&owner_key(), 1),
            atoms: 5000,
        }],
    );
    let transfer_id = pay.id().unwrap();
    rig.pool.admit(&pay, &rig.parent, &rig.state).unwrap();
    rig.step(P + 2, &[]);
    assert!(!rig.state.coins.contains_key(&point));
    assert_eq!(rows(&rig, id), before);
    let transfer_record = rows(&rig, transfer_id);
    assert_eq!(
        (
            transfer_record[0].kind,
            transfer_record[0].height,
            transfer_record[0].list
        ),
        (1, 3, 0)
    );
    let rig = rig.restart();
    assert_eq!(rows(&rig, id), before);
    assert_eq!(rows(&rig, transfer_id), transfer_record);
    rig.finish();
}
#[test]
fn record_verifies_against_replica_block_and_refuses_wrong_fields() {
    let (rig, _, id) = claim_rig("idx-verify");
    let r = rows(&rig, id)[0].clone();
    let block = rig.chain.canonical_block(r.height).unwrap().unwrap();
    r.verify_in_block(&block.body, block.block_hash()).unwrap();
    r.verify_against_replica(
        &rig.chain
            .operation_record_at(r.height, r.list, r.position)
            .unwrap()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(OperationRecord::decode(&r.encode().unwrap()).unwrap(), r);
    let mut wrong = r.clone();
    wrong.block = [91; 32];
    assert_eq!(
        wrong.verify_in_block(&block.body, block.block_hash()),
        Err(IndexError::Identity)
    );
    let mut wrong = r.clone();
    wrong.height += 1;
    assert_eq!(
        wrong.verify_in_block(&block.body, block.block_hash()),
        Err(IndexError::Identity)
    );
    let mut wrong = r.clone();
    wrong.position = 1;
    assert_eq!(
        wrong.verify_in_block(&block.body, block.block_hash()),
        Err(IndexError::Bounds)
    );
    let mut wrong = r.clone();
    wrong.wire = [92; 32];
    assert_eq!(
        wrong.verify_in_block(&block.body, block.block_hash()),
        Err(IndexError::Identity)
    );
    let mut wrong = r.clone();
    wrong.op_id = [93; 32];
    assert_eq!(
        wrong.verify_in_block(&block.body, block.block_hash()),
        Err(IndexError::Identity)
    );
    let mut wrong = r.clone();
    let mut e = minicbor::Encoder::new(Vec::new());
    e.array(3)
        .unwrap()
        .u64(P)
        .unwrap()
        .bytes(&license(0))
        .unwrap()
        .u64(1)
        .unwrap();
    wrong.receipt = Some(e.into_writer());
    assert_eq!(
        wrong.verify_in_block(&block.body, block.block_hash()),
        Err(IndexError::Receipt)
    );
    assert_eq!(wrong.verify_against_replica(&r), Err(IndexError::Receipt));
    let mut extra = r.encode().unwrap();
    extra.push(0);
    assert_eq!(OperationRecord::decode(&extra), Err(IndexError::Codec));
    let mut wide = r.encode().unwrap();
    wide.splice(1..2, [0x18, 1]);
    assert_eq!(OperationRecord::decode(&wide), Err(IndexError::Codec));
    rig.finish();
}
#[test]
fn index_rebuilds_on_replay_and_tamper_is_detected() {
    let (mut rig, _, id) = claim_rig("idx-tamper");
    let expected = rows(&rig, id);
    let path = rig.base.join("chain.sqlite");
    let genesis = rig.f.genesis.clone();
    let initial = rig.initial.clone();
    let root = rig.initial_root;
    let open =
        || CanonicalStore::open_trusted_genesis(&path, &genesis, &initial, root, T0, [255; 32]);
    let db = Connection::open(&path).unwrap();
    db.execute(
        "DELETE FROM operation_index_v2 WHERE id=?1",
        [id.as_slice()],
    )
    .unwrap();
    assert!(matches!(open(), Err(StoreError::Integrity)));
    rig.chain.rebuild_operation_index(&rig.initial).unwrap();
    assert_eq!(rows(&rig, id), expected);
    for orphan_height in [0u64, 3] {
        let r = &expected[0];
        db.execute(
            "INSERT INTO operation_index_v2 VALUES(?1,?2,?3,?4,?5)",
            rusqlite::params![
                orphan_height.to_be_bytes().as_slice(),
                r.list,
                r.position,
                r.op_id.as_slice(),
                r.encode().unwrap()
            ],
        )
        .unwrap();
        assert!(
            matches!(open(), Err(StoreError::Integrity)),
            "orphan rows cannot survive total-count validation"
        );
        rig.chain.rebuild_operation_index(&rig.initial).unwrap();
        assert_eq!(rows(&rig, id), expected);
    }
    // A self-consistent SQL row/record can only be authenticated by replay.
    let mut forged = expected[0].clone();
    forged.wire = [0xe1; 32];
    db.execute(
        "UPDATE operation_index_v2 SET record=?1 WHERE id=?2",
        rusqlite::params![forged.encode().unwrap(), id.as_slice()],
    )
    .unwrap();
    assert!(matches!(open(), Err(StoreError::Integrity)));
    rig.chain.rebuild_operation_index(&rig.initial).unwrap();
    for sql in [
        "UPDATE operation_index_v2 SET id=zeroblob(32)",
        "UPDATE operation_index_v2 SET position=1",
        "UPDATE operation_index_v2 SET record=x'80'",
    ] {
        db.execute(sql, []).unwrap();
        assert!(matches!(open(), Err(StoreError::Integrity)));
        rig.chain.rebuild_operation_index(&rig.initial).unwrap();
        assert_eq!(rows(&rig, id), expected);
    }
    db.execute(
        "UPDATE operation_index_v2 SET height=?1",
        [0u64.to_be_bytes().as_slice()],
    )
    .unwrap();
    assert!(matches!(open(), Err(StoreError::Integrity)));
    rig.chain.rebuild_operation_index(&rig.initial).unwrap();
    let before = database(&path);
    let wrong = State::default();
    assert!(rig.chain.rebuild_operation_index(&wrong).is_err());
    assert_eq!(
        database(&path),
        before,
        "failed rebuild rolls back derived rows"
    );
    drop(db);
    drop(open().unwrap());
    rig.finish();
}
#[test]
fn v3_store_migrates_to_v4_and_failed_replay_rolls_back() {
    let (rig, _, id) = claim_rig("idx-migrate");
    let expected = rows(&rig, id);
    let path = rig.base.join("chain.sqlite");
    let db = Connection::open(&path).unwrap();
    db.execute_batch("DROP TABLE operation_index_v2; PRAGMA user_version=3")
        .unwrap();
    let open = || {
        CanonicalStore::open_trusted_genesis(
            &path,
            &rig.f.genesis,
            &rig.initial,
            rig.initial_root,
            T0,
            [255; 32],
        )
    };
    // The old state is invalid: migration must not commit before replay checks it.
    let saved: Vec<u8> = db
        .query_row("SELECT value FROM state_v2 LIMIT 1", [], |r| r.get(0))
        .unwrap();
    let key: Vec<u8> = db
        .query_row("SELECT key FROM state_v2 LIMIT 1", [], |r| r.get(0))
        .unwrap();
    db.execute("UPDATE state_v2 SET value=x'80' WHERE key=?1", [&key])
        .unwrap();
    let before = database(&path);
    assert!(open().is_err());
    assert_eq!(database(&path), before);
    assert_eq!(
        db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        3
    );
    let present: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='operation_index_v2')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(!present);
    db.execute(
        "UPDATE state_v2 SET value=?1 WHERE key=?2",
        rusqlite::params![saved, key],
    )
    .unwrap();
    let migrated = open().unwrap();
    assert_eq!(migrated.operation_records(id).unwrap(), expected);
    assert_eq!(
        db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        4
    );
    assert_eq!(
        db.query_row::<i64, _, _>("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
            .unwrap(),
        20
    );
    drop(migrated);
    drop(db);
    rig.finish();
}
#[test]
fn rejected_block_leaves_index_unchanged_and_index_write_is_atomic() {
    let mut rig = Rig::new(
        fixture_with_treasury(&treasury_key(), 1_200_000),
        "idx-atomic",
    );
    let path = rig.base.join("chain.sqlite");
    let db = Connection::open(&path).unwrap();
    rig.step(P, &[]);
    let raw = claim_op(
        &rig.f,
        &owner_key(),
        0,
        P,
        10_000,
        0,
        addr(&second_key(), 1),
    );
    let prepared = rig
        .chain
        .prepare_pending(Preparation {
            expected_parent: &rig.parent,
            pool: &rig.pool,
            license: rig.f.license,
            worker: rig.f.worker,
            timestamp: at(P + 1),
            ticket: rig.ticket,
            operations: &[raw],
        })
        .unwrap();
    let envelope = certify_at(prepared, &rig.f, &rig.parent, &rig.state, rig.ticket);
    let before = database(&path);
    let mut bad = envelope.clone();
    bad.certificate.votes[0].signature.ed448[0] ^= 1;
    assert!(matches!(
        rig.chain.commit(&bad),
        Err(StoreError::Verification(_))
    ));
    assert_eq!(database(&path), before);
    let expected = index::records(&envelope.body, envelope.block_hash(), &BTreeMap::new()).unwrap();
    let row = &expected[0];
    // A corrupt future position forces the INSERT to fail after undo/state writes.
    // Keeping the exact schema lets this exercise write rollback, not schema refusal.
    db.execute(
        "INSERT INTO operation_index_v2 VALUES(?1,?2,?3,?4,?5)",
        rusqlite::params![
            row.height.to_be_bytes().as_slice(),
            row.list,
            row.position,
            row.op_id.as_slice(),
            row.encode().unwrap()
        ],
    )
    .unwrap();
    let before_insert = database(&path);
    assert!(matches!(
        rig.chain.commit(&envelope),
        Err(StoreError::Storage(_))
    ));
    assert_eq!(database(&path), before_insert);
    db.execute(
        "DELETE FROM operation_index_v2 WHERE height=?1",
        [row.height.to_be_bytes().as_slice()],
    )
    .unwrap();
    assert!(rig.chain.commit(&envelope).unwrap());
    for r in expected {
        assert_eq!(
            rig.chain
                .operation_record_at(r.height, r.list, r.position)
                .unwrap(),
            Some(r)
        );
    }
    drop(db);
    rig.finish();
}
