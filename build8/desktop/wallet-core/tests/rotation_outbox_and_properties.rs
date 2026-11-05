//! Wallet rotation (phase 2): randomised fee and size properties against an independent model, the
//! outbox reservations of the funding coins and of the authority's rotation slot (reserve, refuse a
//! second, release on forget, reconcile from verified state only), the co-funded parts in the outbox,
//! and the two-key session's lifecycle. A fixed seed makes every run identical.
//! NATIVE, TEST-VALUE; public test keys only.
#[path = "support/flow.rs"]
mod flow;
#[path = "support/synthetic.rs"]
mod synthetic;

use flow::approve;
use mutiny_consensus_v8::{
    Hash,
    evidence_history_v2::History,
    funded_rotation_v2::{self, PartialRotation, Payer, UnsignedRotation},
    hybrid_transaction_v2::Inclusion,
    hybrid_transaction_v2::Transaction,
    op_envelope_v1::Envelope,
    transactions::{Coin, MATURITY, MAX_TX_BYTES, OutPoint, Output},
};
use mutiny_crypto_v2::{HybridKey, Role, rehearsal_keys_v1};
use mutiny_wallet_core_v8::{
    ops::rotation::{self, RotationSigner, combine, rotation_resource},
    outbox::settle,
    *,
};
use std::collections::{BTreeMap, BTreeSet};
use synthetic::{World, address, descriptor, identity, key_a, key_b};

fn new_key(label: &str) -> HybridKey {
    let phrase = rehearsal_keys_v1::label_phrase(label).unwrap();
    HybridKey::wallet_restore(&phrase, Role::WalletOwner).unwrap()
}

fn rotate(new: &HybridKey, generation: u64, fee: FeeSource) -> OperationRequest {
    let proposed = new.public().descriptor(generation).unwrap();
    OperationRequest::WalletRotation(
        RotationRequest::new(Blob::new(proposed.clone()), fee)
            .with_restore_verified(rotation::descriptor_fingerprint(&proposed)),
    )
}

fn body(raw: &[u8]) -> UnsignedRotation {
    PartialRotation::decode(raw)
        .map(|p| p.unsigned)
        .or_else(|_| funded_rotation_v2::FundedRotation::decode(raw).map(|f| f.unsigned))
        .unwrap()
}

/// xorshift64*: small, deterministic, good enough for test data.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound.max(1)
    }
}

/// Encoded width of a CBOR unsigned integer.
fn width(value: u64) -> u64 {
    match value {
        0..=23 => 1,
        24..=0xff => 2,
        0x100..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

/// The INDEPENDENT size model: the encoded size of a funded rotation with `inputs` inputs (index 0
/// each) and one change output, built with the consensus encoder, minus the widths of the fee and of
/// the change amount. `None` when the shape does not fit in 16 KiB.
fn base_size(created: u64, expiry: u64, new: &HybridKey, inputs: usize) -> Option<u64> {
    let unsigned = UnsignedRotation {
        genesis: [1; 32],
        fingerprint: [2; 32],
        envelope: Envelope {
            first_height: created,
            last_height: expiry,
            reference_height: created - 1,
            reference_block: [3; 32],
            preconditions: Vec::new(),
        },
        authority: address(&key_a(), 1),
        current_descriptor: descriptor(&key_a(), 1),
        proposed_descriptor: descriptor(new, 2),
        sponsor: None,
        fee: 1,
        inputs: (0..inputs)
            .map(|tag| {
                (
                    OutPoint {
                        transaction: [tag as u8 + 1; 32],
                        index: 0,
                    },
                    Payer::RotatingAuthority,
                )
            })
            .collect(),
        outputs: vec![Output {
            owner: address(new, 2),
            atoms: 1,
        }],
    };
    Some(funded_rotation_v2::signed_len(&unsigned).ok()? as u64 - 2)
}

/// The least fee an input set worth `incoming` can pay for the shape with size `base` (fee and change
/// widths added), keeping a positive change: brute force over the few widths that can occur.
fn least_fee(base: u64, incoming: u64) -> Option<u64> {
    (base + 2..=base + 18)
        .find(|&fee| fee < incoming && fee >= base + width(fee) + width(incoming - fee))
}

#[test]
fn any_funding_yields_a_consensus_valid_rotation_or_a_typed_refusal_that_matches_the_model() {
    let me = identity(&key_a());
    let owner = address(&key_a(), 1);
    let new = new_key("w2-prop-new");
    let new_address = new.public().address_id(2).unwrap();
    let request = rotate(&new, 2, FeeSource::RotatingAuthority);
    let mut rng = Rng(0x51ed_270b_7f4a_9c15);
    let mut outcomes: BTreeMap<String, usize> = BTreeMap::new();
    let mut signed = 0;
    let mut largest_overshoot = 0;
    let mut bases: BTreeMap<(u64, u64, usize), Option<u64>> = BTreeMap::new();

    for case in 0..320u64 {
        let height = 100 + rng.below(60);
        let mut world = World::new(height);
        // One case in four scatters the funds over several coins that are each too small, so the
        // compact tag-25 input encoding is exercised beyond the retired two-input limit.
        let scattered = rng.below(4) == 0;
        let coins = if scattered {
            3 + rng.below(3)
        } else {
            rng.below(6)
        };
        for index in 0..coins {
            let atoms = if scattered {
                3_000 + rng.below(3_800)
            } else {
                match rng.below(5) {
                    0 => 1 + rng.below(5_000),
                    1 => 5_000 + rng.below(9_000),
                    2 => 9_000 + rng.below(9_000),
                    3 => 1_000_000 + rng.below(1 << 40),
                    _ => 1 + rng.below(1 << 20),
                }
            };
            let (created, coinbase) = if rng.below(8) == 0 {
                (height.saturating_sub(rng.below(150)), true)
            } else {
                (1 + rng.below(40), false)
            };
            let point = world.coin(owner, atoms, created, coinbase, index as u8 + 1, 0);
            if rng.below(10) == 0 {
                world.reserved.insert(point);
            }
        }
        // A stranger's coin is never a candidate.
        world.coin(address(&key_b(), 1), 1 << 30, 1, false, 0x77, 0);
        let view = world.view();
        let next = height + 1;
        let (created, expiry) = (next, next + DEFAULT_VALIDITY_BLOCKS);

        // The independent picture of what is spendable, largest first, ties by outpoint.
        let mut spendable: Vec<(OutPoint, Coin)> = world
            .state
            .coins
            .iter()
            .filter(|(point, coin)| {
                coin.output.owner == owner
                    && !world.reserved.contains(*point)
                    && coin.created_height <= height
                    && (!coin.coinbase || next - coin.created_height >= MATURITY)
            })
            .map(|(point, coin)| (point.clone(), coin.clone()))
            .collect();
        spendable.sort_by(|(pa, ca), (pb, cb)| {
            cb.output
                .atoms
                .cmp(&ca.output.atoms)
                .then_with(|| pa.cmp(pb))
        });
        let total: u128 = spendable
            .iter()
            .map(|(_, c)| u128::from(c.output.atoms))
            .sum();
        let mut base_of = |inputs: usize| {
            *bases
                .entry((created, expiry, inputs))
                .or_insert_with(|| base_size(created, expiry, &new, inputs))
        };
        let mut expected_inputs = None;
        let mut prefix = 0u64;
        for (count, (_, coin)) in spendable.iter().enumerate() {
            let Some(base) = base_of(count + 1) else {
                break;
            };
            prefix += coin.output.atoms;
            if least_fee(base, prefix).is_some() {
                expected_inputs = Some(count + 1);
                break;
            }
        }

        match plan(&request, &view, &me) {
            Ok(planned) => {
                *outcomes.entry("planned".into()).or_default() += 1;
                let transfer = body(&planned.objects()[0].bytes);
                let size = funded_rotation_v2::signed_len(&transfer).unwrap() as u64;
                let inputs = transfer.inputs.len();
                assert_eq!(Some(inputs), expected_inputs, "case {case}: input count");
                assert!(size <= MAX_TX_BYTES as u64);
                // Selection uses largest coins; the signed body serializes those OutPoints
                // in canonical order, with funding assigned to the OLD authority key.
                let mut selected: Vec<_> =
                    spendable[..inputs].iter().map(|(p, _)| p.clone()).collect();
                selected.sort();
                assert_eq!(
                    transfer
                        .inputs
                        .iter()
                        .map(|(p, _)| p.clone())
                        .collect::<Vec<_>>(),
                    selected
                );
                assert!(
                    transfer
                        .inputs
                        .iter()
                        .all(|(_, payer)| *payer == Payer::RotatingAuthority)
                );
                assert_eq!(transfer.current_descriptor, descriptor(&key_a(), 1));
                let incoming: u64 = spendable[..inputs]
                    .iter()
                    .map(|(_, c)| c.output.atoms)
                    .sum();
                // Fee at least the whole envelope, and the model's least fee give or take the
                // fixed point's overshoot at a width boundary.
                let least = least_fee(base_of(inputs).unwrap(), incoming).unwrap();
                assert!(transfer.fee >= size, "case {case}: fee below size");
                assert!(transfer.fee >= least, "case {case}");
                largest_overshoot = largest_overshoot.max(transfer.fee - least);
                assert!(
                    transfer.fee - least <= 8,
                    "case {case}: overshoot {}",
                    transfer.fee - least
                );
                // One change output to the new key's address; conservation.
                assert_eq!(transfer.outputs.len(), 1);
                assert_eq!(transfer.outputs[0].owner, new_address);
                assert_eq!(transfer.outputs[0].atoms + transfer.fee, incoming);
                assert!(transfer.outputs[0].atoms > 0);
                // The review states the same fee and size.
                let reviewed = review(&planned, &view).unwrap();
                assert_eq!(reviewed.fee().atoms, transfer.fee);
                assert_eq!(reviewed.fee().size_bytes, Some(size));
                if signed < 3 {
                    signed += 1;
                    let session =
                        RotationSigner::for_test(key_a(), me.clone(), new_key("w2-prop-new"))
                            .unwrap();
                    let result = session
                        .authorize(planned, approve(&reviewed, &view), &view)
                        .unwrap();
                    assert_eq!(
                        result.bytes().len() as u64,
                        size,
                        "signatures have fixed width"
                    );
                    Transaction::decode(result.bytes())
                        .unwrap()
                        .verify(
                            &Inclusion {
                                parent: &world.anchor,
                                history: &History::default(),
                            },
                            &world.state,
                        )
                        .map(|_| ())
                        .unwrap_or_else(|e| panic!("case {case}: consensus refused {e:?}"));
                }
            }
            Err(refusal) => {
                *outcomes.entry(refusal.code().to_string()).or_default() += 1;
                assert_eq!(expected_inputs, None, "case {case}: {refusal}");
                match refusal {
                    Refusal::NothingSpendable => assert!(spendable.is_empty(), "case {case}"),
                    Refusal::InsufficientFunds {
                        available,
                        requested,
                    } => {
                        assert_eq!(u128::from(available), total, "case {case}");
                        // What was asked is the least fee of the largest shape tried, and all the
                        // spendable value does not reach it.
                        assert!(u128::from(requested) >= total, "case {case}");
                        assert!(
                            base_size(created, expiry, &new, 3).is_some(),
                            "compact tag25 supports three inputs"
                        );
                        let tried = spendable.len().min(funded_rotation_v2::MAX_INPUTS);
                        let base = base_of(tried).unwrap();
                        assert!(
                            (base..=base + 18).contains(&requested),
                            "case {case}: requested {requested}, model {base}"
                        );
                    }
                    Refusal::SizeLimit { limit } => {
                        assert_eq!(limit, MAX_TX_BYTES);
                        assert!(spendable.len() >= 3, "case {case}");
                        let two = base_of(2).unwrap();
                        assert!(total > u128::from(two), "case {case}: funds exist");
                    }
                    other => panic!("case {case}: unexpected refusal {other}"),
                }
            }
        }
    }
    // Every outcome occurred, so the property was exercised on both sides.
    for code in ["planned", "NOTHING_SPENDABLE", "INSUFFICIENT_FUNDS"] {
        assert!(
            outcomes.get(code).copied().unwrap_or(0) > 0,
            "{code}: {outcomes:?}"
        );
    }
    assert_eq!(signed, 3);
    assert!(largest_overshoot <= 8, "{largest_overshoot}");
}

/// Key A holds one 5,000,000 atom coin at head 100.
fn world() -> World {
    let mut world = World::new(100);
    world.coin(address(&key_a(), 1), 5_000_000, 1, false, 1, 0);
    world
}

struct Index(Hash, u64);

impl ConfirmationSource for Index {
    fn confirmed_height(&self, id: &Hash) -> Option<u64> {
        (*id == self.0).then_some(self.1)
    }
}

#[test]
fn the_outbox_reserves_the_coins_and_the_rotation_slot_and_settles_from_verified_state_only() {
    let world = world();
    let view = world.view();
    let me = identity(&key_a());
    let authority = address(&key_a(), 1);
    let new = new_key("w2-prop-outbox-new");
    let request = OperationRequest::WalletRotation(
        RotationRequest::new(
            Blob::new(new.public().descriptor(2).unwrap()),
            FeeSource::RotatingAuthority,
        )
        .with_restore_verified(rotation::descriptor_fingerprint(
            &new.public().descriptor(2).unwrap(),
        ))
        .with_validity_blocks(10),
    );
    let planned = plan(&request, &view, &me).unwrap();
    let session =
        RotationSigner::for_test(key_a(), me.clone(), new_key("w2-prop-outbox-new")).unwrap();
    let signed = session
        .authorize(
            planned.clone(),
            approve(&review(&planned, &view).unwrap(), &view),
            &view,
        )
        .unwrap();
    assert_eq!(signed.reserved(), planned.inputs());
    let coin = OutPoint {
        transaction: [1; 32],
        index: 0,
    };
    let slot = rotation_resource(&authority);

    let mut outbox = MemoryOutbox::new();
    assert_eq!(outbox.commit(&signed, &view).unwrap(), signed.id());
    assert_eq!(
        outbox.commit(&signed, &view).unwrap(),
        signed.id(),
        "idempotent"
    );
    assert_eq!(
        outbox.reserved().unwrap(),
        BTreeSet::from([coin.clone(), slot.clone()])
    );
    // A second outbox whose view already reserves the slot refuses the same bytes.
    let mut held = World::new(100);
    held.state = world.state.clone();
    held.reserved = BTreeSet::from([slot.clone()]);
    assert_eq!(
        MemoryOutbox::new()
            .commit(&signed, &held.view())
            .unwrap_err(),
        Refusal::ReservedInput
    );
    assert_eq!(
        plan(&request, &held.view(), &me).unwrap_err(),
        Refusal::RotationPending,
        "the planner's one-pending-authority-slot refusal precedes coin selection"
    );
    // A metadata lie about the reservations is refused (dropping the slot would free it).
    let lie = SignedOperation::Complete {
        kind: OperationKind::WalletRotation,
        id: signed.id(),
        bytes: signed.bytes().to_vec(),
        validity: *signed.validity(),
        reserved: vec![coin.clone()],
    };
    assert!(matches!(
        MemoryOutbox::new().commit(&lie, &view),
        Err(Refusal::VerificationFailed(_))
    ));

    let record = outbox.get(&signed.id()).unwrap().unwrap();
    assert_eq!(record.validity.created, 101);
    assert_eq!(record.validity.expiry, 111);
    let later = |height: u64, edit: &dyn Fn(&mut World)| {
        let mut w = World::new(height);
        w.state = world.state.clone();
        edit(&mut w);
        w
    };
    // Pending at the same head and while nothing happened.
    assert_eq!(settle(&record, &view).unwrap(), Settlement::Pending);
    assert_eq!(
        settle(&record, &later(105, &|_| {}).view()).unwrap(),
        Settlement::Pending
    );
    // Confirmed from the host's confirmation index ...
    let index = Index(signed.id(), 103);
    let indexed = later(105, &|_| {});
    assert_eq!(
        settle(&record, &indexed.view().with_confirmations(&index)).unwrap(),
        Settlement::Confirmed(103)
    );
    // An output-shaped coin alone is not an authenticated operation-index result.
    let with_change = later(105, &|w| {
        w.state.coins.remove(&OutPoint {
            transaction: [1; 32],
            index: 0,
        });
        w.state.coins.insert(
            OutPoint {
                transaction: signed.id(),
                index: 0,
            },
            Coin {
                output: Output {
                    owner: new.public().address_id(2).unwrap(),
                    atoms: 1,
                },
                created_height: 102,
                coinbase: false,
            },
        );
    });
    assert_eq!(
        settle(&record, &with_change.view()).unwrap(),
        Settlement::InputsSpent
    );
    // The funding coin gone without such evidence: inputs spent, not confirmed.
    let spent = later(105, &|w| {
        w.state.coins.clear();
    });
    assert_eq!(
        settle(&record, &spent.view()).unwrap(),
        Settlement::InputsSpent
    );
    // Only the atomic funded carrier can change the current wallet. Applying those exact
    // signed bytes through the real public executor consumes funding and changes authority.
    // Even current-key state alone is not a canonical inclusion record.
    let tx = Transaction::decode(signed.bytes()).unwrap();
    let block = mutiny_consensus_v8::blocks::BlockBody {
        height: 101,
        reward_owner: authority,
        fees: tx.fee(),
        transactions: vec![signed.bytes().to_vec()],
        operations: Vec::new(),
    };
    let executed = world
        .state
        .execute_hybrid_transfers(
            world.anchor.genesis,
            world.anchor.fingerprint,
            world.anchor.block,
            authority,
            &block,
        )
        .unwrap();
    let mut rotated = later(105, &|_| {});
    rotated.state = executed.state;
    assert_eq!(
        rotated.state.wallets.current(authority).unwrap(),
        descriptor(&new, 2).as_slice()
    );
    assert_eq!(
        settle(&record, &rotated.view()).unwrap(),
        Settlement::InputsSpent
    );
    // Expired after its window.
    assert_eq!(
        settle(&record, &later(111, &|_| {}).view()).unwrap(),
        Settlement::Expired
    );
    // A view older than the queueing head says nothing.
    assert_eq!(
        settle(&record, &World::new(99).view()).unwrap(),
        Settlement::Pending
    );

    // Reconciliation applies it and releases the reservations; forget does not revoke anything.
    let report = outbox.reconcile(&later(111, &|_| {}).view()).unwrap();
    assert_eq!(report.expired, 1);
    assert!(outbox.reserved().unwrap().is_empty());
    let mut second = MemoryOutbox::new();
    second.commit(&signed, &view).unwrap();
    second.forget(&signed.id()).unwrap();
    assert!(
        second.reserved().unwrap().is_empty(),
        "forget releases the slot and the coin"
    );
    assert_eq!(
        second.get(&signed.id()).unwrap().unwrap().status,
        OutboxStatus::Forgotten
    );
}

#[test]
fn the_parts_of_a_co_funded_rotation_in_the_outbox() {
    let mut world = World::new(100);
    world.coin(address(&key_b(), 1), 3_000_000, 1, false, 2, 0);
    let view = world.view();
    let me = identity(&key_a());
    let payer = identity(&key_b());
    let new = new_key("w2-prop-cofund-new");
    let planned = plan(
        &rotate(&new, 2, FeeSource::OtherWallet(payer.clone())),
        &view,
        &me,
    )
    .unwrap();
    let session =
        RotationSigner::for_test(key_a(), me.clone(), new_key("w2-prop-cofund-new")).unwrap();
    let part_rotation = session
        .authorize(
            planned.clone(),
            approve(&review(&planned, &view).unwrap(), &view),
            &view,
        )
        .unwrap();
    let adopted = adopt(&planned.objects()[0].bytes, &view, &payer).unwrap();
    let part_funding = KeySigner::for_test(key_b())
        .unwrap()
        .authorize(
            adopted.clone(),
            approve(&review(&adopted, &view).unwrap(), &view),
            &view,
        )
        .unwrap();
    // Partial byte identities differ, while both sign exactly the same unsigned commitment.
    assert_eq!(body(part_rotation.bytes()), body(part_funding.bytes()));
    assert_eq!(
        part_rotation.reserved(),
        &{
            let mut r = vec![
                OutPoint {
                    transaction: [2; 32],
                    index: 0,
                },
                rotation_resource(&address(&key_a(), 1)),
            ];
            r.sort();
            r
        }[..]
    );
    // The rotating wallet queues its part: it holds the rotation slot while it waits for the payer.
    let mut outbox = MemoryOutbox::new();
    outbox.commit(&part_rotation, &view).unwrap();
    assert!(
        outbox
            .reserved()
            .unwrap()
            .contains(&rotation_resource(&address(&key_a(), 1)))
    );
    let pending = outbox.pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert!(!pending[0].complete);
    assert_eq!(pending[0].missing.len(), 1);
    // Completion takes over the exact unsigned plan's reservations atomically and replaces
    // the partial byte identity with the canonical complete operation ID.
    let complete = combine(&[part_rotation.bytes(), part_funding.bytes()], &view).unwrap();
    assert_eq!(
        outbox
            .replace_partial(&part_rotation.id(), &complete, &view)
            .unwrap(),
        complete.id()
    );
    assert_eq!(
        outbox.get(&complete.id()).unwrap().unwrap().bytes,
        complete.bytes()
    );
    let pending = outbox.pending().unwrap();
    assert!(pending[0].complete && pending[0].missing.is_empty());
    // The payer's part, imported elsewhere, is verified signature by signature.
    let imported = SignedOperation::import(part_funding.bytes(), &view).unwrap();
    assert!(!imported.is_complete());
    assert_eq!(imported, part_funding);
}

#[test]
fn the_two_key_session_locks_erases_and_reports_its_state() {
    // Threading contract: a session can be shared with a signing thread like a `KeySigner`.
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RotationSigner>();
    let me = identity(&key_a());
    let session =
        RotationSigner::for_test(key_a(), me.clone(), new_key("w2-prop-session")).unwrap();
    assert_eq!(session.gate_mode(), GateMode::TestValue);
    assert!(!session.is_locked());
    session.touch().unwrap();
    assert_eq!(session.identity(), &me);
    assert_eq!(
        session.proposed_descriptor(),
        new_key("w2-prop-session")
            .public()
            .descriptor(2)
            .unwrap()
            .as_slice()
    );
    session.lock();
    assert!(session.is_locked());
    assert_eq!(session.touch().unwrap_err(), Refusal::Locked);
    // A rotated identity at generation two rotates to generation three.
    let new = new_key("w2-prop-session");
    let rotated = SignerIdentity::from_public(new.public(), 2, Some(address(&key_a(), 1))).unwrap();
    let next = RotationSigner::for_test(new, rotated, new_key("w2-prop-session-3")).unwrap();
    assert_eq!(
        next.proposed_descriptor(),
        new_key("w2-prop-session-3")
            .public()
            .descriptor(3)
            .unwrap()
            .as_slice()
    );
}
