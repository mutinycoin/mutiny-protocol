//! Current tag-25 rotation funding, audited from coins and outputs independently of review code.
//! There are exactly two eligible funding parties: the rotating OLD authority and the named
//! current sponsor. Every signature binds the complete funding. The historical three-funder,
//! standalone-funding and separate-window probes are retained in external hashed evidence;
//! their current counterparts require refusal for every reader and one atomic expiry.
//! NATIVE, TEST-VALUE; deterministic public keys only.
#[path = "support/flow.rs"]
mod flow;
#[path = "support/synthetic.rs"]
mod synthetic;
use mutiny_consensus_v8::{
    Hash,
    funded_rotation_v2::{PartialRotation, Payer, Slot as NativeSlot},
    transactions::Output,
};
use mutiny_crypto_v2::{HybridKey, Role, rehearsal_keys_v1};
use mutiny_wallet_core_v8::{ops::rotation, *};
use synthetic::{World, address, descriptor, identity, key_a, key_b, key_c};
fn new_key(label: &str) -> HybridKey {
    HybridKey::wallet_restore(
        &rehearsal_keys_v1::label_phrase(label).unwrap(),
        Role::WalletOwner,
    )
    .unwrap()
}
fn request(new: &HybridKey, fee: FeeSource) -> OperationRequest {
    let proposed = new.public().descriptor(2).unwrap();
    OperationRequest::WalletRotation(
        RotationRequest::new(Blob::new(proposed.clone()), fee)
            .with_restore_verified(rotation::descriptor_fingerprint(&proposed)),
    )
}
fn probe_world() -> World {
    let mut w = World::new(100);
    w.coin(address(&key_a(), 1), 1, 1, false, 1, 0);
    w.coin(address(&key_b(), 1), 3_000_000, 1, false, 2, 0);
    w
}
fn attack(view: &ChainView<'_>, new: &HybridKey) -> PartialRotation {
    let plan = plan(
        &request(new, FeeSource::OtherWallet(identity(&key_b()))),
        view,
        &identity(&key_a()),
    )
    .unwrap();
    let mut p = PartialRotation::decode(&plan.objects()[0].bytes).unwrap();
    p.unsigned.inputs.push((
        mutiny_consensus_v8::transactions::OutPoint {
            transaction: [1; 32],
            index: 0,
        },
        Payer::RotatingAuthority,
    ));
    p.unsigned.inputs.sort();
    p.unsigned.fee += 4000;
    p.unsigned.outputs = vec![
        Output {
            owner: new.public().address_id(2).unwrap(),
            atoms: 2_900_000,
        },
        Output {
            owner: address(&key_b(), 1),
            atoms: 3_000_001 - 2_900_000 - p.unsigned.fee,
        },
    ];
    p
}
#[test]
fn the_review_probe_a_fee_payer_is_refused_a_funding_that_pays_another_funder() {
    let w = probe_world();
    let view = w.view();
    let new = new_key("w2-prop-cofund-new");
    let raw = attack(&view, &new).encode().unwrap();
    let expected = Refusal::RotationFunding(rotation::REASON_NET_DEBIT_ABOVE_FEE);
    assert_eq!(
        adopt(&raw, &view, &identity(&key_b())).unwrap_err(),
        expected
    );
    assert_eq!(
        explain(&raw, &view, &identity(&key_b())).unwrap_err(),
        expected
    );
    assert_eq!(expected.code(), "ROTATION_FUNDING");
    let honest = plan(
        &request(&new, FeeSource::OtherWallet(identity(&key_b()))),
        &view,
        &identity(&key_a()),
    )
    .unwrap();
    let adopted = adopt(&honest.objects()[0].bytes, &view, &identity(&key_b())).unwrap();
    let reviewed = review(&adopted, &view).unwrap();
    assert!(
        KeySigner::for_test(key_b())
            .unwrap()
            .authorize(adopted, flow::approve(&reviewed, &view), &view)
            .is_ok()
    );
}
#[test]
fn the_rotating_wallet_an_observer_and_the_gainer_refuse_the_same_pooled_payment() {
    let w = probe_world();
    let view = w.view();
    let new = new_key("w2-prop-cofund-new");
    let p = attack(&view, &new);
    let raw = p.encode().unwrap();
    let sponsor_spent = 3_000_000u64;
    let sponsor_return = p.unsigned.outputs[1].atoms;
    assert!(sponsor_spent - sponsor_return > p.unsigned.fee);
    for reader in [
        identity(&key_a()),
        identity(&key_b()),
        identity(&key_c()),
        identity(&new_key("w-fix-netflow-observer")),
    ] {
        assert_eq!(
            explain(&raw, &view, &reader).unwrap_err(),
            Refusal::RotationFunding(rotation::REASON_NET_DEBIT_ABOVE_FEE)
        );
    }
    // A third wallet cannot insert a coin under either permitted payer's authority.
    let mut third = World::new(100);
    third.state = w.state.clone();
    let point = third.coin(address(&key_c(), 1), 1, 1, false, 3, 0);
    let honest = plan(
        &request(&new, FeeSource::OtherWallet(identity(&key_b()))),
        &third.view(),
        &identity(&key_a()),
    )
    .unwrap();
    let mut p = PartialRotation::decode(&honest.objects()[0].bytes).unwrap();
    p.unsigned.inputs.push((point, Payer::Sponsor));
    p.unsigned.inputs.sort();
    p.unsigned.outputs[0].atoms += 1;
    assert!(explain(&p.encode().unwrap(), &third.view(), &identity(&key_b())).is_err());
}
#[test]
fn the_payer_and_uninvolved_observer_read_only_their_own_net_debit_and_bound_funding() {
    let w = probe_world();
    let view = w.view();
    let new = new_key("w-fix-netflow-honest");
    let own = identity(&key_a());
    let payer = identity(&key_b());
    let planned = plan(
        &request(&new, FeeSource::OtherWallet(payer.clone())),
        &view,
        &own,
    )
    .unwrap();
    let raw = &planned.objects()[0].bytes;
    let payer_review = review(&adopt(raw, &view, &payer).unwrap(), &view).unwrap();
    assert_eq!(
        payer_review.net_debit(),
        Some(u128::from(payer_review.fee().atoms))
    );
    assert_eq!(payer_review.fee().payer, FeePayer::ThisWallet);
    assert!(
        payer_review
            .warnings()
            .iter()
            .any(|w| w.code == "FUNDING_BOUND")
    );
    assert_eq!(review(&planned, &view).unwrap().net_debit(), Some(0));
    let observer = explain(raw, &view, &identity(&key_c())).unwrap();
    assert_eq!(observer.net_debit(), Some(0));
    assert_eq!(observer.returned(), 0);
    assert!(observer.inputs().iter().all(|i| !i.owned_by_signer));
    assert_eq!(
        observer.fee().payer,
        FeePayer::Counterparty(address(&key_b(), 1))
    );
    assert!(
        observer
            .authorizations()
            .iter()
            .all(|r| r.status == RequirementStatus::Counterparty)
    );
    assert_eq!(observer.binding(), payer_review.binding());
    assert!(!observer.requires_phrase());
}
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
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}
#[test]
fn random_funders_and_outputs_the_net_debit_is_the_true_change_and_no_output_is_hidden() {
    let (a, b, c) = (key_a(), key_b(), key_c());
    let new = new_key("w-fix-netflow-random-new");
    let na = new.public().address_id(2).unwrap();
    let addresses = [address(&a, 1), address(&b, 1), address(&c, 1)];
    let readers = [identity(&a), identity(&b), identity(&c)];
    let mut rng = Rng(0x0f1f_2a3b_4c5d_6e7f);
    let (mut accepted, mut denied, mut unencodable) = (0, 0, 0);
    for round in 0..240 {
        let (mut w, own_atoms, sponsor_atoms) = (
            World::new(100),
            100_000 + rng.below(4_000_000),
            100_000 + rng.below(4_000_000),
        );
        let pa = w.coin(addresses[0], own_atoms, 1, false, 1, 0);
        let pb = w.coin(addresses[1], sponsor_atoms, 1, false, 2, 0);
        let planned = plan(
            &request(&new, FeeSource::OtherWallet(readers[1].clone())),
            &w.view(),
            &readers[0],
        )
        .unwrap();
        let mut p = PartialRotation::decode(&planned.objects()[0].bytes).unwrap();
        let fee = 30_000 + rng.below(3000);
        p.unsigned.inputs = vec![(pa, Payer::RotatingAuthority), (pb, Payer::Sponsor)];
        p.unsigned.fee = fee;
        let own_fee = rng.below(fee + 1);
        p.unsigned.outputs = vec![
            Output {
                owner: na,
                atoms: own_atoms - own_fee,
            },
            Output {
                owner: addresses[1],
                atoms: sponsor_atoms - (fee - own_fee),
            },
        ];
        let good = round % 6 <= 1;
        match round % 6 {
            0 | 1 => (),
            2 => {
                p.unsigned.outputs[0].atoms += fee + 1;
                p.unsigned.outputs[1].atoms -= fee + 1;
            }
            3 => p.unsigned.outputs[0].owner = addresses[2],
            4 => p.unsigned.inputs[1].0.transaction = [0xee; 32],
            _ => p.unsigned.outputs[0].owner = [0; 32],
        }
        let Ok(raw) = p.encode() else {
            assert_eq!(round % 6, 5);
            unencodable += 1;
            continue;
        };
        let view = w.view();
        for (index, reader) in readers.iter().enumerate() {
            let result = explain(&raw, &view, reader);
            if !good {
                assert!(result.is_err(), "round {round} reader {index}");
                denied += 1;
                continue;
            }
            let r = result.unwrap();
            let mine = |owner: Hash| owner == addresses[index] || (index == 0 && owner == na);
            let spent: u128 = p
                .unsigned
                .inputs
                .iter()
                .filter_map(|(point, _)| w.state.coins.get(point))
                .filter(|coin| mine(coin.output.owner))
                .map(|coin| u128::from(coin.output.atoms))
                .sum();
            let returned: u128 = p
                .unsigned
                .outputs
                .iter()
                .filter(|out| mine(out.owner))
                .map(|out| u128::from(out.atoms))
                .sum();
            assert_eq!(
                r.net_debit(),
                Some(spent.saturating_sub(returned)),
                "round {round} reader {index}"
            );
            assert_eq!(u128::from(r.returned()), returned);
            assert_eq!(r.amount(), None);
            assert_eq!(
                r.inputs()
                    .iter()
                    .filter(|i| i.owned_by_signer)
                    .map(|i| u128::from(i.atoms))
                    .sum::<u128>(),
                spent
            );
            for output in &p.unsigned.outputs {
                assert!(r.render_text().contains(&hex::encode(output.owner)));
            }
            accepted += 1;
        }
    }
    assert_eq!(accepted, 240);
    assert_eq!(denied, 360);
    assert_eq!(unencodable, 40);
}
#[test]
fn a_rotation_this_wallet_builds_never_pays_anyone_but_the_fee() {
    let new = new_key("w-fix-netflow-built-new");
    let rotating = identity(&key_a());
    let payer = identity(&key_b());
    let mut rng = Rng(0x6b75_696c_745f_6f6e);
    for round in 0..24 {
        let mut w = World::new(100);
        for tag in 0..1 + rng.below(3) {
            w.coin(
                address(&key_a(), 1),
                30_000 + rng.below(9_000_000),
                1,
                false,
                0x10 + tag as u8,
                0,
            );
            w.coin(
                address(&key_b(), 1),
                30_000 + rng.below(9_000_000),
                1,
                false,
                0x20 + tag as u8,
                0,
            );
        }
        let view = w.view();
        for (source, funder) in [
            (FeeSource::RotatingAuthority, &rotating),
            (FeeSource::OtherWallet(payer.clone()), &payer),
        ] {
            let planned = plan(&request(&new, source), &view, &rotating).unwrap();
            let p = PartialRotation::decode(&planned.objects()[0].bytes).unwrap();
            let r = if funder == &rotating {
                review(&planned, &view).unwrap()
            } else {
                review(
                    &adopt(&planned.objects()[0].bytes, &view, funder).unwrap(),
                    &view,
                )
                .unwrap()
            };
            assert_eq!(r.amount(), None);
            assert!(
                r.destinations()
                    .iter()
                    .all(|d| d.role == DestinationRole::Change)
            );
            assert_eq!(
                r.net_debit(),
                Some(u128::from(p.unsigned.fee)),
                "round {round}"
            );
        }
    }
}
#[test]
fn a_payers_coins_stay_reserved_until_the_atomic_bundle_expires() {
    let mut w = World::new(100);
    let coin = w.coin(address(&key_b(), 1), 3_000_000, 1, false, 2, 0);
    let view = w.view();
    let new = new_key("w-fix-netflow-window-new");
    let own = identity(&key_a());
    let payer = identity(&key_b());
    let planned = plan(
        &request(&new, FeeSource::OtherWallet(payer.clone())),
        &view,
        &own,
    )
    .unwrap();
    let mut p = PartialRotation::decode(&planned.objects()[0].bytes).unwrap();
    p.unsigned.envelope.last_height = 150;
    let adopted = adopt(&p.encode().unwrap(), &view, &payer).unwrap();
    assert_eq!(
        (adopted.validity().created, adopted.validity().expiry),
        (101, 150)
    );
    let signed = KeySigner::for_test(key_b())
        .unwrap()
        .authorize(
            adopted.clone(),
            flow::approve(&review(&adopted, &view).unwrap(), &view),
            &view,
        )
        .unwrap();
    let mut outbox = MemoryOutbox::new();
    let id = outbox.commit(&signed, &view).unwrap();
    for (head, open) in [(149, true), (150, false), (200, false), (245, false)] {
        let mut later = World::new(head);
        later.state = w.state.clone();
        outbox.reconcile(&later.view()).unwrap();
        assert_eq!(
            outbox.get(&id).unwrap().unwrap().status.is_open(),
            open,
            "head {head}"
        );
        assert_eq!(outbox.reserved().unwrap().contains(&coin), open);
    }
    assert_eq!(
        outbox.get(&id).unwrap().unwrap().status,
        OutboxStatus::Expired
    );
    // The authority signatures bind exactly that SAME shorter window; there is no independent funding expiry.
    p.sign(NativeSlot::Authorize, &key_a()).unwrap();
    p.sign(NativeSlot::Possession, &new).unwrap();
    let authority_part = SignedOperation::import(&p.encode().unwrap(), &view).unwrap();
    assert_eq!(
        (
            authority_part.validity().created,
            authority_part.validity().expiry
        ),
        (101, 150)
    );
    let imported = SignedOperation::import(signed.bytes(), &view).unwrap();
    assert_eq!(imported.validity().expiry, 150);
}
