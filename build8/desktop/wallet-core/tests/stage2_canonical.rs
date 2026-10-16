//! Wallet-built final carriers through real bounded pool, certified blocks and own Genesis replay.
//! This target establishes local canonical execution; authenticated NODE transport is separate.
#[path = "support/stage2_builders.rs"]
mod builders;
#[path = "support/rig.rs"]
mod rig;
use mutiny_consensus_v8::{bonds::MINIMUM_ATOMS, submission_v1::Status};
use mutiny_wallet_core_v8::{
    ChainView, ContextField, HeadInfo, MemoryOutbox, Outbox, OutboxStatus, Refusal, SignedOperation,
};
use rig::chain::*;
use std::collections::BTreeSet;

#[test]
fn wallet_carriers_finalize_exact_bytes_reopen_and_preserve_failed_block_tables() {
    for carrier in 0..3 {
        let current = wallet_key();
        let sponsor = labelled_key("candidate3-public-stage2-sponsor");
        let recipient = other_key();
        let mut h = Harness::new(
            &format!("wallet-stage2-canonical-{carrier}"),
            50_000_000_000,
            &[
                Funding::plain(11, address_of(&current), 50_000_000_000),
                Funding::plain(12, address_of(&sponsor), 1_000_000),
            ],
        );
        println!(
            "PUBLIC TEST-VALUE canonical evidence retained: {}",
            h.evidence_directory().display()
        );
        let reserved = BTreeSet::new();
        let view = h.view(&reserved);
        let signed = match carrier {
            0 => {
                let node = mutiny_wallet_core_v8::discovery::bonds::nodes_controlled_by(
                    h.state(),
                    identity_of(&current).descriptor(),
                )
                .into_iter()
                .next()
                .unwrap();
                builders::atomic_bond(
                    &view,
                    current,
                    node.node,
                    node.generation,
                    MINIMUM_ATOMS,
                    [31; 32],
                )
            }
            1 => builders::sponsored_rotation(
                &view,
                current,
                labelled_key("candidate3-public-stage2-proposed"),
                sponsor,
            ),
            _ => builders::native_hash_lock(
                &view, current, recipient, 50_000, [32; 32], [33; 32], 30,
            ),
        };
        let list = if carrier == 1 { 0 } else { 1 };
        let mut maker_outbox = MemoryOutbox::new();
        let maker_id = if carrier == 2 {
            let trade =
                mutiny_consensus_v8::trading_v1::NativeOperation::decode(signed.bytes()).unwrap();
            let offer = trade.operation.offer_proof.unwrap().offer;
            let witness = SignedOperation::import(&offer.encode().unwrap(), &view).unwrap();
            assert_eq!(
                witness.kind(),
                mutiny_wallet_core_v8::OperationKind::MakerOffer
            );
            let id = maker_outbox.commit(&witness, &view).unwrap();
            assert_eq!(
                maker_outbox.reconcile(&view).unwrap().still_pending,
                1,
                "an unconsumed offer witness remains pending; it is not a block item"
            );
            Some(id)
        } else {
            None
        };
        let mut pool = h.submission_pool();
        let before = h.canonical_rows();
        let anchor = h.anchor();
        let root = h.state().root().unwrap();
        let bad = match carrier {
            0 => {
                let mut b =
                    mutiny_consensus_v8::bond_create_v3::FundedBondCreate::decode(signed.bytes())
                        .unwrap();
                b.unsigned.nonce[0] ^= 1;
                b.encode().unwrap()
            }
            1 => {
                let mut t =
                    mutiny_consensus_v8::hybrid_transaction_v2::Transaction::decode(signed.bytes())
                        .unwrap();
                let mutiny_consensus_v8::hybrid_transaction_v2::Transaction::FundedRotation(b) =
                    &mut t
                else {
                    panic!("tag25 required")
                };
                b.authorize.ed448[0] ^= 1;
                t.encode().unwrap()
            }
            _ => {
                let mut b =
                    mutiny_consensus_v8::trading_v1::NativeOperation::decode(signed.bytes())
                        .unwrap();
                b.operation.meta.contract[0] ^= 1;
                b.encode().unwrap()
            }
        };
        std::fs::write(
            h.evidence_directory().join("wallet-produced.bin"),
            signed.bytes(),
        )
        .unwrap();
        std::fs::write(h.evidence_directory().join("refused-corruption.bin"), &bad).unwrap();
        assert!(h.admit_submission(&mut pool, list, &bad).is_err());
        let failure = if list == 1 {
            h.try_step_with(&[bad.clone()]).map(|_| ())
        } else {
            h.execute_as_block(vec![bad.clone()])
        };
        assert!(failure.is_err(), "invalid signed carrier cannot execute");
        assert_eq!(h.anchor(), anchor);
        assert_eq!(h.state().root().unwrap(), root);
        assert_eq!(
            h.canonical_rows(),
            before,
            "every canonical/finality/lifecycle/outcome row unchanged"
        );
        assert_eq!(
            h.admit_submission(&mut pool, list, signed.bytes()).unwrap(),
            signed.id()
        );
        assert_eq!(
            pool.exact_bytes(signed.id()).unwrap(),
            Some((list, signed.bytes().to_vec()))
        );
        assert_eq!(pool.status(signed.id()).unwrap(), Status::Pending);
        h.step_submissions(&mut pool);
        let records = h.verified_operations(signed.id());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].height, 1);
        assert_eq!(records[0].list, list);
        assert_eq!(
            records[0].wire,
            mutiny_consensus_v8::submission_v1::Submission::decode(list, signed.bytes())
                .unwrap()
                .wire
        );
        assert_eq!(
            pool.status(signed.id()).unwrap(),
            Status::Finalized(records[0].clone())
        );
        if let Some(id) = maker_id {
            let record_before = maker_outbox.get(&id).unwrap().unwrap();
            // A foreign context cannot settle this local witness, even when its
            // state contains the original chain's exact consumed-offer record.
            let mut foreign = h.anchor();
            foreign.genesis[0] ^= 1;
            let head = h.head();
            let foreign_head = HeadInfo::new(
                foreign,
                head.timestamp(),
                head.t0(),
                h.state().root().unwrap(),
            )
            .unwrap();
            let wrong = ChainView::new(foreign_head, h.state(), &reserved);
            assert_eq!(
                maker_outbox.reconcile(&wrong).unwrap_err(),
                Refusal::WrongContext(ContextField::Genesis)
            );
            assert_eq!(maker_outbox.get(&id).unwrap().unwrap(), record_before);
            let report = maker_outbox.reconcile(&h.view(&reserved)).unwrap();
            assert_eq!(
                (report.inputs_spent, report.confirmed, report.still_pending),
                (1, 0, 0)
            );
            assert_eq!(
                maker_outbox.get(&id).unwrap().unwrap().status,
                OutboxStatus::InputsSpent
            );
            assert!(
                h.verified_operations(id).is_empty(),
                "maker witness itself never becomes an indexed block item"
            );
        }
        let h = h.restart();
        assert_eq!(
            h.verified_operations(signed.id()),
            records,
            "reopened own Genesis replay establishes same finality"
        );
        // Keep all stores and failed/partial inputs as evidence; no fixture finish/removal.
    }
}
