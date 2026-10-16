// Native TEST-only helper extraction from frozen Q17 certified-block fixture.
// No historical test count transferred; public LegacyTest TPM model only.
use mutiny_consensus_v8::{
    Error, Hash, NETWORK_ID,
    anchors::FinalizedAnchor,
    block_envelope_v2::BlockEnvelope,
    blocks::BlockBody,
    canonical_store_v2::{CanonicalStore, Preparation},
    certificates::Decision,
    continuity_v2::{Certificate, Vote},
    execution::{CandidatePreparation, Execution, ExecutionError, State},
    finality_v2::StoreError,
    license_assignment_v2::Assignment,
    mempool_v2::Mempool,
    pow::{Candidate, WorkAuthority, WorkHeader},
    trading_v1::*,
    transactions::{Coin, OutPoint, Output},
    votes::IngressError,
    work_authority_v2::Authority,
};
use mutiny_crypto_v2::{
    HybridKey, HybridSignature, Role,
    enrollment::{Binding, owner_descriptor_id},
};
use std::path::PathBuf;
#[path = "canonical_support/license_v2.rs"]
mod licenses;
#[path = "canonical_support/wallet_host_fixture_tpm.rs"]
mod tpm;

/// The buyer's only coin: it funds every sale attempt (price 50,000, fee 20,000, change 30,000).
const BUYER_COIN: OutPoint = OutPoint {
    transaction: [173; 32],
    index: 0,
};
/// The third party's only coin: it funds a re-sale by the buyer.
const THIRD_COIN: OutPoint = OutPoint {
    transaction: [174; 32],
    index: 0,
};

fn empty() -> HybridSignature {
    HybridSignature {
        ed448: [0; 114],
        fndsa: [0; 1280],
    }
}

#[test]
fn real_current_assignment_routes_actual_c_stream_signed_work_and_queued_revocation() {
    canonical_runtime_route(false);
}
#[cfg(target_os="linux")]
#[test]
fn real_current_assignment_routes_actual_posix_owned_socket_and_queued_revocation() {
    canonical_runtime_route(true);
}
fn canonical_runtime_route(socket:bool) {
    use super::journal_fixture::Journal;
    for revoked in [false,true] {
        let f=fixture();let chain=std::rc::Rc::new(std::cell::RefCell::new(Chain::open(&f)));
        let clock=std::rc::Rc::new(std::cell::Cell::new(1101));
        let anchor1=chain.borrow_mut().mine(&f,&f.genesis,f.license,f.worker,1100,1,&[sale_operation(&f,&f.state,&f.genesis)]);
        let (mut worker,a)=ordinary_assignment(&f,&f.buyer,3,2,2);
        let mut journal=Journal::model(&worker,4);
        let (candidate,active)=journal_rules(chain.clone(),clock.clone(),f.genesis.clone(),f.backup_license,f.backup_worker,worker.binding.clone());
        journal.rules(candidate,active);assert_eq!(journal.put(&a).0,1);
        let anchor2=chain.borrow_mut().mine(&f,&anchor1,f.backup_license,f.backup_worker,1101,1,&[a.encode().unwrap()]);
        clock.set(1120);
        let (work,binding,node,epoch)=chain.borrow().store.current_worker_session(&anchor2,f.license,a.enrollment.binding.worker_id,clock.get()).unwrap();
        assert_eq!(binding,a.enrollment.binding);assert_eq!(node,a.node_descriptor);assert_eq!(epoch,2);
        assert_eq!(journal.activate(&a,work.parent_height+1,epoch),3);
        if revoked {
            let mut change=||{
                let (_,state)=chain.borrow().store.load().unwrap();
                // AM-3 execution applies due assignments before trading at epoch 2.
                // The parent still has a pending assignment; it is not the inclusion-phase
                // assignment snapshot. Only this review projection changes, never the store.
                let mut reviewed=state.clone();reviewed.licenses_v2.activate_due(2).unwrap();
                assert!(state.licenses_v2.pending_assignment(f.license).is_some());
                assert!(reviewed.licenses_v2.pending_assignment(f.license).is_none());
                assert_eq!(reviewed.licenses_v2.license(f.license).unwrap().active_worker,Some(binding.worker_id));
                let stale=dvp(&f,&state,&f.buyer,&f.third,THIRD_COIN,2,&anchor2,0x51);
                let stale_result=mutiny_consensus_v8::trading_v1::prepare_candidate_phase(&state,&reviewed,&anchor2,
                    state.root().unwrap(),&mutiny_consensus_v8::evidence_history_v2::History::default(),&[stale],
                    &mutiny_consensus_v8::trading_v1::CandidatePolicy::native_denomination_locked()).err().unwrap();
                assert_eq!(stale_result,mutiny_consensus_v8::trading_v1::NativeError::Stale(
                    mutiny_consensus_v8::op_envelope_v1::TAG_LICENSE_ASSIGNMENT));
                let sale=dvp(&f,&reviewed,&f.buyer,&f.third,THIRD_COIN,2,&anchor2,0x51);
                let anchor3=chain.borrow_mut().mine(&f,&anchor2,f.backup_license,f.backup_worker,1121,2,&[sale]);
                clock.set(1121);
                let (_,state)=chain.borrow().store.load().unwrap();
                assert_eq!(state.licenses_v2.license(f.license).unwrap().owner,address(&f.third));
                assert!(chain.borrow().store.current_worker_session(&anchor3,f.license,binding.worker_id,clock.get()).is_err());
            };
            if socket{
                #[cfg(target_os="linux")] journal.runtime_socket_route(&mut worker,&binding,&f.coordinator,&work,epoch,None,6,Some(&mut change));
                #[cfg(not(target_os="linux"))] panic!("Linux-only socket test");
            }else{journal.runtime_route(&mut worker,&binding,&f.coordinator,&work,epoch,None,6,Some(&mut change));}
        } else {
            let prepared=chain.borrow().store.prepare_pending(Preparation{expected_parent:&anchor2,pool:&chain.borrow().pool,
                license:f.license,worker:binding.worker_id,timestamp:1120,ticket:1,operations:&[]}).unwrap();
            let mut authority=Authority{work:WorkAuthority{candidate:prepared.candidate,assignment_sequence:binding.assignment_generation,
                ticket_sequence:1,coordinator:binding.coordinator,nonce_start:7,nonce_end:8,epoch},node_descriptor:node,signature:empty()};
            authority.sign(&f.coordinator).unwrap();
            let id=authority.id().unwrap();let header=WorkHeader{candidate:authority.work.candidate.clone(),authority:id,nonce:7};
            authority.verify(&header,&work,&a.node_descriptor).unwrap();
            let signed=authority.encode().unwrap();
            let mut offer=vec![5,2];offer.extend_from_slice(&[9;32]);offer.extend_from_slice(&epoch.to_be_bytes());
            offer.extend_from_slice(&1000u64.to_be_bytes());offer.extend_from_slice(&(signed.len() as u16).to_be_bytes());offer.extend_from_slice(&signed);
            if socket{
                #[cfg(target_os="linux")] journal.runtime_socket_route(&mut worker,&binding,&f.coordinator,&work,epoch,Some((&offer,id,1)),0,None);
                #[cfg(not(target_os="linux"))] panic!("Linux-only socket test");
            }else{journal.runtime_route(&mut worker,&binding,&f.coordinator,&work,epoch,Some((&offer,id,1)),0,None);}
        }
        worker.assert_birth_unchanged();drop(journal);
        std::rc::Rc::try_unwrap(chain).ok().unwrap().into_inner().close();
    }
}

/// Trusted LOCAL TEST adapter: callbacks read the actual store, not a packet's
/// claimed status. Activated/retired identities and still-pending identities
/// are excluded from fresh proof production. This is a public native model,
/// not a device provider or a physical storage qualification.
fn journal_rules(chain: std::rc::Rc<std::cell::RefCell<Chain>>, clock: std::rc::Rc<std::cell::Cell<u64>>,
    genesis: FinalizedAnchor, backup_license: Hash, backup_worker: Hash, birth: Binding)
    -> (super::journal_fixture::CandidateRule, super::journal_fixture::ActiveRule)
{
    let candidate_chain = chain.clone(); let candidate_clock = clock.clone(); let candidate_genesis = genesis.clone();
    let candidate = Box::new(move |raw: &[u8], owner: &[u8], node: &[u8]| -> bool {
        let Ok(binding) = Binding::decode(raw) else { return false; };
        if binding.genesis != birth.genesis || binding.fingerprint != birth.fingerprint || binding.license != birth.license
            || binding.device_mac != birth.device_mac || binding.worker_public != birth.worker_public
            || binding.worker_id != birth.worker_id || binding.assignment_generation < birth.assignment_generation { return false; }
        let chain = candidate_chain.borrow();
        let Ok((head, state)) = chain.store.load() else { return false; };
        let anchor = FinalizedAnchor { height: head.height, block: head.block, ..candidate_genesis.clone() };
        // Own work-clock and coordinator authority, including halted-store and
        // current descriptor checks, come from the ordinary verified API.
        let Ok((work, _, descriptor, epoch)) = chain.store.current_worker_session(&anchor,
            backup_license, backup_worker, candidate_clock.get()) else { return false; };
        let Some(license) = state.licenses_v2.license(binding.license) else { return false; };
        let Ok(terms) = mutiny_consensus_v8::license_assignment_v2::DeliveryTerms::at(license,
            work.parent_height + 1, epoch) else { return false; };
        let Ok((owner_key, generation)) = mutiny_crypto_v2::PublicKey::decode_descriptor(owner) else { return false; };
        if binding.genesis != candidate_genesis.genesis || binding.fingerprint != candidate_genesis.fingerprint
            || !terms.admits(&binding) || descriptor != node
            || state.wallets.authorize(license.owner, owner).is_err()
            || generation != binding.owner_generation
            || owner_descriptor_id(&owner_key, generation).ok() != Some(binding.owner_descriptor)
            || mutiny_consensus_v8::work_authority_v2::node_identity(node).ok() != Some(binding.coordinator)
        { return false; }
        let Ok(records) = state.licenses_v2.records() else { return false; };
        for raw in records.values() {
            let mut d = minicbor::Decoder::new(raw);
            let Ok(Some(count)) = d.array() else { return false; };
            if d.u8().ok() != Some(2) { return false; }
            match d.u8() {
                Ok(40) if count == 3 => {},
                Ok(tag @ (41 | 42)) if count == (if tag == 41 { 4 } else { 3 }) => {
                    let Ok(encoded) = d.bytes() else { return false; };
                    let Ok(a) = Assignment::decode(encoded) else { return false; };
                    if a.enrollment.binding.worker_public == binding.worker_public { return false; }
                },
                _ => return false,
            }
        }
        // A separately readable store must not change its head across the
        // adapter's verified reads. The device's provider must also serialize.
        chain.store.load().is_ok_and(|(now, _)| now.height == head.height && now.block == head.block && now.root == head.root)
    });
    let active = Box::new(move |raw: &[u8], height: u64, epoch: u64| -> bool {
        let Ok(a) = Assignment::decode(raw) else { return false; };
        let b = &a.enrollment.binding; let chain = chain.borrow();
        let Ok((head, state)) = chain.store.load() else { return false; };
        let anchor = FinalizedAnchor { height: head.height, block: head.block, ..genesis.clone() };
        let Ok((work, binding, node, due_epoch)) = chain.store.current_worker_session(&anchor,
            b.license, b.worker_id, clock.get()) else { return false; };
        if height != work.parent_height + 1 || epoch != due_epoch || binding != *b || node != a.node_descriptor { return false; }
        let mut book = state.licenses_v2.clone();
        if book.activate_due(epoch).is_err() { return false; }
        let Ok((_, own)) = book.active(b.license, b.worker_id, epoch) else { return false; };
        if own.assignment.encode().ok().as_deref() != Some(raw) { return false; }
        chain.store.load().is_ok_and(|(now, _)| now.height == head.height && now.block == head.block && now.root == head.root)
    });
    (candidate, active)
}

#[test]
fn real_missed_window_journal_reproves_birth_key_and_uses_exact_current_canonical_assignment() {
    use mutiny_crypto_v2::{Domain, enrollment::Enrollment};
    use super::journal_fixture::Journal;
    let f = fixture(); let chain = std::rc::Rc::new(std::cell::RefCell::new(Chain::open(&f)));
    let clock = std::rc::Rc::new(std::cell::Cell::new(1101));
    let anchor1 = chain.borrow_mut().mine(&f, &f.genesis, f.license, f.worker, 1100, 1,
        &[sale_operation(&f, &f.state, &f.genesis)]);
    let (mut worker, missed) = ordinary_assignment(&f, &f.buyer, 3, 2, 2);
    let mut journal = Journal::model(&worker, 4);
    let (candidate, active) = journal_rules(chain.clone(), clock.clone(), f.genesis.clone(), f.backup_license, f.backup_worker, worker.binding.clone());
    journal.rules(candidate, active);
    assert_eq!(journal.put(&missed).0, 1); let old_records = journal.records();
    assert_eq!(journal.activate(&missed, 2, 1), -1); // epoch before the signed activation boundary
    assert_eq!(journal.restore(&missed, 2, 2).0, -4); // no canonical inclusion
    let anchor2 = chain.borrow_mut().mine(&f, &anchor1, f.backup_license, f.backup_worker, 1120, 1, &[]);
    clock.set(1121);
    // Cryptographic validity is insufficient once the one-epoch window passed.
    assert_eq!(journal.reprove(&mut worker, &missed.enrollment.binding, &missed.owner_descriptor).0, 0);
    let mut binding = missed.enrollment.binding.clone(); binding.effective_epoch = 3; binding.valid_until_height = 3;
    let (status, proof) = journal.reprove(&mut worker, &binding, &missed.owner_descriptor);
    assert_eq!(status, 1); assert_eq!(proof.worker, missed.enrollment.binding.worker_public);
    assert_eq!(Binding::decode(&proof.unsigned[..proof.un]).unwrap(), binding);
    binding.verify_worker_possession(&proof.proof).unwrap();
    let fresh = Assignment { enrollment: Enrollment { owner_signature: f.buyer.sign(Domain::MinerEnrollment,
        &binding.bytes().unwrap()).unwrap(), worker_signature: proof.proof, binding: binding.clone() },
        owner_descriptor: missed.owner_descriptor.clone(), node_descriptor: missed.node_descriptor.clone() };
    assert_ne!(mutiny_consensus_v8::op_envelope_v1::assignment_id(&fresh).unwrap(),
        mutiny_consensus_v8::op_envelope_v1::assignment_id(&missed).unwrap());
    assert_eq!(journal.put(&fresh).0, 1); assert_eq!(journal.records()[0], old_records[0]);
    assert_eq!(journal.activate(&fresh, 3, 3), -4);
    let anchor3 = chain.borrow_mut().mine(&f, &anchor2, f.backup_license, f.backup_worker, 1121, 2, &[fresh.encode().unwrap()]);
    assert_eq!(journal.restore(&fresh, 4, 3).0, -4); // own clock has not crossed epoch3
    clock.set(1180); // (1180 - t0=1000) / 60 = epoch3
    let (work, current, descriptor, epoch) = chain.borrow().store.current_worker_session(&anchor3,
        f.license, binding.worker_id, clock.get()).unwrap();
    assert_eq!(current, binding); assert_eq!(descriptor, fresh.node_descriptor); assert_eq!(epoch, 3);
    assert_eq!(journal.restore(&fresh, work.parent_height + 1, epoch).0, 2);
    assert_eq!(journal.activate(&fresh, work.parent_height + 1, epoch), 3);
    assert_eq!(journal.restore(&fresh, work.parent_height + 1, epoch), (3, fresh.encode().unwrap()));
    let alternate = (0..8).find_map(|_| {
        let mut a = fresh.clone(); a.enrollment.owner_signature = f.buyer.sign(Domain::MinerEnrollment,
            &binding.bytes().unwrap()).unwrap(); (a.encode().unwrap() != fresh.encode().unwrap()).then_some(a)
    }).expect("different genuinely valid owner signature in bounded attempts");
    assert_eq!(mutiny_consensus_v8::op_envelope_v1::assignment_id(&alternate).unwrap(),
        mutiny_consensus_v8::op_envelope_v1::assignment_id(&fresh).unwrap());
    let saved_records = journal.records();
    journal.coherent_public_edit_for_test(1, &alternate);
    assert_eq!(journal.restore(&fresh, work.parent_height + 1, epoch).0, -4);
    // Restore only the explicitly owned RAM fault fixture, preserving saved
    // original/alternate public objects; never repairs user/device records.
    journal.coherent_public_edit_for_test(1, &fresh); assert_eq!(journal.records(), saved_records);
    assert_eq!(journal.restore(&missed, work.parent_height + 1, epoch).0, -4);
    // NEVER-active policy prevents proof reuse once due activation is canonical
    // history, even though the immutable seed itself still exists locally.
    assert_eq!(journal.reprove(&mut worker, &binding, &fresh.owner_descriptor).0, 0);
    journal.handshake(&mut worker, &binding, &f.coordinator, work.parent_height + 1, epoch);
    let anchor4 = chain.borrow_mut().mine(&f, &anchor3, f.license, binding.worker_id, 1180, 1, &[]);
    clock.set(1181);
    {
        let mut chain = chain.borrow_mut();
        chain.store = CanonicalStore::open_trusted_genesis(&chain.base.join("chain.sqlite"),
            &f.genesis, &f.state, f.state.root().unwrap(), 1000, [255; 32]).unwrap();
        let (_, replayed, _, _) = chain.store.current_worker_session(&anchor4, f.license, binding.worker_id, clock.get()).unwrap();
        assert_eq!(replayed, binding);
    }
    assert_eq!(journal.restore(&fresh, 5, 3), (3, fresh.encode().unwrap()));
    let mut reuse = binding.clone(); reuse.assignment_generation = 4; reuse.effective_epoch = 4; reuse.valid_until_height = 5;
    assert_eq!(journal.reprove(&mut worker, &reuse, &fresh.owner_descriptor).0, 0);
    worker.assert_birth_unchanged();
    drop(journal);
    std::rc::Rc::try_unwrap(chain).ok().unwrap().into_inner().close();
}

#[test]
fn real_cancelled_pending_journal_keeps_old_bytes_and_reproves_for_new_current_owner() {
    use mutiny_crypto_v2::{Domain, enrollment::Enrollment};
    use super::journal_fixture::Journal;
    let f = fixture(); let chain = std::rc::Rc::new(std::cell::RefCell::new(Chain::open(&f)));
    let clock = std::rc::Rc::new(std::cell::Cell::new(1101));
    let anchor1 = chain.borrow_mut().mine(&f, &f.genesis, f.license, f.worker, 1100, 1,
        &[sale_operation(&f, &f.state, &f.genesis)]);
    let (mut worker, cancelled) = ordinary_assignment(&f, &f.buyer, 3, 2, 2);
    let mut journal = Journal::model(&worker, 4);
    let (candidate, active) = journal_rules(chain.clone(), clock.clone(), f.genesis.clone(), f.backup_license, f.backup_worker, worker.binding.clone());
    journal.rules(candidate, active); assert_eq!(journal.put(&cancelled).0, 1);
    let old_records = journal.records();
    let anchor2 = chain.borrow_mut().mine(&f, &anchor1, f.backup_license, f.backup_worker, 1101, 1,
        &[cancelled.encode().unwrap()]);
    clock.set(1110);
    let (_, state2) = chain.borrow().store.load().unwrap();
    let sale = dvp(&f, &state2, &f.buyer, &f.third, THIRD_COIN, 2, &anchor2, 0x41);
    let anchor3 = chain.borrow_mut().mine(&f, &anchor2, f.backup_license, f.backup_worker, 1110, 2, &[sale]);
    clock.set(1111);
    let (_, state3) = chain.borrow().store.load().unwrap();
    let license = state3.licenses_v2.license(f.license).unwrap();
    assert_eq!(license.owner, address(&f.third)); assert_eq!(state3.licenses_v2.pending_assignment(f.license), None);
    let terms = mutiny_consensus_v8::license_assignment_v2::DeliveryTerms::at(license, 4, 1).unwrap();
    assert_eq!(terms.assignment_generation, 4);
    assert_eq!(journal.restore(&cancelled, 4, 2).0, -4);
    assert_eq!(journal.put(&cancelled).0, 1); assert_eq!(journal.records(), old_records);
    let mut old_owner = cancelled.enrollment.binding.clone();
    old_owner.assignment_generation = terms.assignment_generation; old_owner.effective_epoch = terms.effective_epoch;
    old_owner.valid_until_height = terms.min_valid_until_height;
    // Same eligible sequence/window, wrong CURRENT owner: refusal is isolated.
    assert_eq!(journal.reprove(&mut worker, &old_owner, &cancelled.owner_descriptor).0, 0);
    let third_descriptor = f.third.public().descriptor(1).unwrap();
    let mut binding = old_owner; binding.owner_descriptor = owner_descriptor_id(f.third.public(), 1).unwrap();
    let (status, proof) = journal.reprove(&mut worker, &binding, &third_descriptor); assert_eq!(status, 1);
    assert_eq!(proof.worker, cancelled.enrollment.binding.worker_public); binding.verify_worker_possession(&proof.proof).unwrap();
    let fresh = Assignment { enrollment: Enrollment { owner_signature: f.third.sign(Domain::MinerEnrollment,
        &binding.bytes().unwrap()).unwrap(), worker_signature: proof.proof, binding: binding.clone() },
        owner_descriptor: third_descriptor, node_descriptor: cancelled.node_descriptor.clone() };
    assert_eq!(journal.put(&fresh).0, 1); assert_eq!(journal.records()[0], old_records[0]);
    let anchor4 = chain.borrow_mut().mine(&f, &anchor3, f.backup_license, f.backup_worker, 1111, 3, &[fresh.encode().unwrap()]);
    clock.set(1120);
    let (work, own, _, epoch) = chain.borrow().store.current_worker_session(&anchor4,
        f.license, binding.worker_id, clock.get()).unwrap();
    assert_eq!(own, binding); assert_eq!((work.parent_height + 1, epoch), (5, 2));
    assert_eq!(journal.activate(&fresh, 5, 2), 3); assert_eq!(journal.restore(&cancelled, 5, 2).0, -4);
    journal.handshake(&mut worker, &binding, &f.coordinator, 5, 2);
    let anchor5 = chain.borrow_mut().mine(&f, &anchor4, f.license, binding.worker_id, 1120, 1, &[]);
    clock.set(1121);
    let mut reuse = binding.clone(); reuse.assignment_generation = 5; reuse.effective_epoch = 3; reuse.valid_until_height = 6;
    assert_eq!(journal.reprove(&mut worker, &reuse, &fresh.owner_descriptor).0, 0); // activated key, otherwise fresh terms
    let (_, current, _, _) = chain.borrow().store.current_worker_session(&anchor5, f.license, binding.worker_id, clock.get()).unwrap();
    assert_eq!(current, binding); assert_eq!(journal.restore(&fresh, 6, 2), (3, fresh.encode().unwrap()));
    worker.assert_birth_unchanged(); drop(journal);
    std::rc::Rc::try_unwrap(chain).ok().unwrap().into_inner().close();
}

/// PUBLIC TEST-VALUE only: the C Worker is born under a buyer's actual current
/// authority after a certified sale. Only the store's independently verified
/// current session read supplies activation/handshake authority. Its delivery
/// deadline is H2; real work at H4 must remain usable after canonical activation.
#[test]
fn real_post_sale_c_assignment_uses_own_canonical_binding_after_delivery_deadline() {
    use mutiny_consensus_v8::license_assignment_v2::{DeliveryTerms, ParentContext};
    use mutiny_crypto_v2::{Domain, enrollment::Enrollment};
    let f = fixture();
    let mut chain = Chain::open(&f);
    let anchor1 = chain.mine(&f, &f.genesis, f.license, f.worker, 1100, 1,
        &[sale_operation(&f, &f.state, &f.genesis)]);
    let (_, state1) = chain.store.load().unwrap();
    let license = state1.licenses_v2.license(f.license).unwrap();
    assert_eq!(license.owner, address(&f.buyer));
    assert_eq!(license.assignment_sequence, 2);
    let terms = DeliveryTerms::at(license, 2, 1).unwrap();
    assert_eq!((terms.assignment_generation, terms.effective_epoch, terms.min_valid_until_height), (3, 2, 2));
    let node_descriptor = f.coordinator.public().descriptor(1).unwrap();
    let context = super::Context {
        genesis: f.genesis.genesis, fingerprint: f.genesis.fingerprint, license: f.license,
        owner_descriptor: owner_descriptor_id(f.buyer.public(), 1).unwrap(), owner_generation: 1,
        coordinator: mutiny_consensus_v8::work_authority_v2::node_identity(&node_descriptor).unwrap(),
        configuration_generation: 1, device_mac: [2, 0, 0, 0, 0, 13],
        assignment_generation: terms.assignment_generation, effective_epoch: terms.effective_epoch,
        valid_until_height: terms.min_valid_until_height,
    };
    let mut worker = super::ordinary_fixture::Ordinary::prepare(context, &f.buyer, &f.coordinator);
    worker.assert_pending_cannot_begin();
    let binding = worker.binding.clone();
    let assignment = Assignment {
        enrollment: Enrollment {
            owner_signature: f.buyer.sign(Domain::MinerEnrollment, &binding.bytes().unwrap()).unwrap(),
            worker_signature: worker.possession, binding: binding.clone(),
        },
        owner_descriptor: f.buyer.public().descriptor(1).unwrap(), node_descriptor: node_descriptor.clone(),
    };
    assignment.verify_next_epoch(&ParentContext { genesis: f.genesis.genesis,
        fingerprint: f.genesis.fingerprint, height: 2, epoch: 1, license,
        wallets: &state1.wallets }).unwrap();
    assert!(chain.store.current_worker_session(&anchor1, f.license, binding.worker_id, 1101).is_err());
    let raw = assignment.encode().unwrap();
    let anchor2 = chain.mine(&f, &anchor1, f.backup_license, f.backup_worker, 1101, 1, &[raw]);
    assert!(chain.store.current_worker_session(&anchor2, f.license, binding.worker_id, 1110).is_err());
    assert!(chain.store.current_worker_session(&anchor2, f.license, f.worker, 1110).is_err());
    let anchor3 = chain.mine(&f, &anchor2, f.backup_license, f.backup_worker, 1110, 2, &[]);
    let (work, canonical, descriptor, epoch) = chain.store
        .current_worker_session(&anchor3, f.license, binding.worker_id, 1120).unwrap();
    assert_eq!(canonical, binding);
    assert_eq!(descriptor, node_descriptor);
    assert_eq!((work.parent_height + 1, epoch), (4, 2));
    worker.assert_bad_activation_refused(&assignment.enrollment);
    worker.activate_current(&canonical, &descriptor, &assignment.enrollment);
    worker.assert_strict_genesis_refuses(&assignment.enrollment);
    worker.assert_active_refusal_boundaries();
    worker.assert_mixed_flights_refused(&f.coordinator);
    // Re-read the own canonical head after activation, before using the session.
    let (_, fresh, fresh_descriptor, fresh_epoch) = chain.store
        .current_worker_session(&anchor3, f.license, binding.worker_id, 1120).unwrap();
    assert_eq!((fresh, fresh_descriptor, fresh_epoch), (canonical.clone(), descriptor, epoch));
    worker.handshake(&f.coordinator, &canonical, work.parent_height + 1, epoch);
    worker.assert_birth_unchanged();
    let anchor4 = chain.mine(&f, &anchor3, f.license, binding.worker_id, 1120, 1, &[]);
    // Reopening performs actual complete canonical replay; local ACTIVE alone
    // is never accepted as evidence of ownership/assignment finality.
    drop(chain.store);
    chain.store = CanonicalStore::open_trusted_genesis(&chain.base.join("chain.sqlite"),
        &f.genesis, &f.state, f.state.root().unwrap(), 1000, [255; 32]).unwrap();
    let (_, reopened, reopened_descriptor, reopened_epoch) = chain.store
        .current_worker_session(&anchor4, f.license, binding.worker_id, 1121).unwrap();
    assert_eq!(reopened, binding);
    assert_eq!(reopened_descriptor, node_descriptor);
    assert_eq!(reopened_epoch, 2);
    worker.assert_birth_unchanged();
    chain.close();
}

fn ordinary_assignment(f: &Fixture, owner: &HybridKey, generation: u64, epoch: u64, deadline: u64)
    -> (super::ordinary_fixture::Ordinary, Assignment)
{
    use mutiny_crypto_v2::{Domain, enrollment::Enrollment};
    let node_descriptor = f.coordinator.public().descriptor(1).unwrap();
    let context = super::Context {
        genesis: f.genesis.genesis, fingerprint: f.genesis.fingerprint, license: f.license,
        owner_descriptor: owner_descriptor_id(owner.public(), 1).unwrap(), owner_generation: 1,
        coordinator: mutiny_consensus_v8::work_authority_v2::node_identity(&node_descriptor).unwrap(),
        configuration_generation: 1, device_mac: [2, 0, 0, 0, 0, 13], assignment_generation: generation,
        effective_epoch: epoch, valid_until_height: deadline,
    };
    // A fresh distinct PUBLIC RAM backend for each TEST candidate, never an
    // overwrite of an existing private record or a physical entropy claim.
    let worker = super::ordinary_fixture::Ordinary::prepare(context, owner, &f.coordinator);
    let binding = worker.binding.clone();
    let a = Assignment {
        enrollment: Enrollment { owner_signature: owner.sign(Domain::MinerEnrollment,
            &binding.bytes().unwrap()).unwrap(), worker_signature: worker.possession, binding },
        owner_descriptor: owner.public().descriptor(1).unwrap(), node_descriptor,
    };
    a.verify_signatures().unwrap();
    (worker, a)
}

/// Delivery expiry is still enforced at inclusion. Independently current
/// canonical state also cancels a pending buyer assignment on the next sale;
/// no local signed proof may turn that cancelled identity into ACTIVE.
#[test]
fn expired_delivery_and_canonically_cancelled_c_assignment_never_activate() {
    use mutiny_consensus_v8::license_assignment_v2::ParentContext;
    let f = fixture();
    let mut chain = Chain::open(&f);
    let anchor1 = chain.mine(&f, &f.genesis, f.license, f.worker, 1100, 1,
        &[sale_operation(&f, &f.state, &f.genesis)]);
    let (_, state1) = chain.store.load().unwrap();
    let license = state1.licenses_v2.license(f.license).unwrap();
    assert_eq!(license.assignment_sequence, 2);
    let (expired_worker, expired) = ordinary_assignment(&f, &f.buyer, 3, 2, 1);
    assert!(matches!(expired.verify_next_epoch(&ParentContext { genesis: f.genesis.genesis,
        fingerprint: f.genesis.fingerprint, height: 2, epoch: 1, license, wallets: &state1.wallets }),
        Err(Error::StaleSequence)));
    let operations = [expired.encode().unwrap()];
    let tables = chain.tables();
    assert!(matches!(chain.execute(f.backup_license, f.backup_worker, 1101, 1,
        address(&f.seller), 0, &operations), Err(ExecutionError::Codec(Error::StaleSequence))));
    assert_eq!(chain.refusal(&anchor1, f.backup_license, f.backup_worker, 1101, 1, &operations),
        "Hybrid candidate execution: Codec(StaleSequence)");
    assert!(matches!(chain.commit_refused(&f, &anchor1, f.backup_license, f.backup_worker,
        1101, 1, address(&f.seller), 0, &operations),
        StoreError::Verification(IngressError::Execution(ExecutionError::Codec(Error::StaleSequence)))));
    assert_eq!(chain.tables(), tables);
    expired_worker.assert_pending_cannot_begin();
    expired_worker.assert_birth_unchanged();
    let (worker, pending) = ordinary_assignment(&f, &f.buyer, 3, 2, 2);
    let worker_id = pending.enrollment.binding.worker_id;
    let anchor2 = chain.mine(&f, &anchor1, f.backup_license, f.backup_worker, 1101, 1,
        &[pending.encode().unwrap()]);
    let (_, state2) = chain.store.load().unwrap();
    assert_eq!(state2.licenses_v2.pending_assignment(f.license), Some(&pending));
    let sale = dvp(&f, &state2, &f.buyer, &f.third, THIRD_COIN, 2, &anchor2, 0x41);
    let anchor3 = chain.mine(&f, &anchor2, f.backup_license, f.backup_worker, 1110, 2, &[sale]);
    let (_, state3) = chain.store.load().unwrap();
    assert_eq!(state3.licenses_v2.license(f.license).unwrap().owner, address(&f.third));
    assert_eq!(state3.licenses_v2.pending_assignment(f.license), None);
    assert!(chain.store.current_worker_session(&anchor3, f.license, worker_id, 1120).is_err());
    // The trusted adapter cannot obtain a current canonical binding. It never
    // calls activation with the cancelled packet's self-supplied expected bytes.
    worker.assert_pending_cannot_begin();
    let anchor4 = chain.mine(&f, &anchor3, f.backup_license, f.backup_worker, 1120, 3, &[]);
    assert!(chain.store.current_worker_session(&anchor4, f.license, worker_id, 1121).is_err());
    worker.assert_pending_cannot_begin();
    worker.assert_birth_unchanged();
    chain.close();
}
fn address(k: &HybridKey) -> Hash {
    k.public().address_id(1).unwrap()
}

struct Fixture {
    state: State,
    genesis: FinalizedAnchor,
    coordinator: HybridKey,
    continuity: HybridKey,
    expected: Vec<Binding>,
    seller: HybridKey,
    buyer: HybridKey,
    /// Buys License 0 from the buyer in the re-sale test.
    third: HybridKey,
    /// Genesis License 0: the License that is sold.
    license: Hash,
    /// Its Genesis Worker (synthetic seed 1).
    worker: Hash,
    /// Genesis License 1, never sold: it mines while License 0 cannot.
    backup_license: Hash,
    backup_worker: Hash,
}
/// The trading_host_v1.rs fixture (lines 287-394 there), plus a registered buyer holding
/// BUYER_COIN. Twelve Genesis Licenses owned by the seller, one Continuity voter.
fn fixture() -> Fixture {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../hybrid-canonical-store-public-v1.json"
    ))
    .unwrap();
    assert_eq!(f["synthetic_only"], true);
    assert_eq!(f["production_authorized"], false);
    let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
    let records: Vec<_> = f["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
        .collect();
    let initial = State::from_records(&records, raw(&f["root"]).try_into().unwrap()).unwrap();
    let mut state = State {
        coins: initial.coins.clone(),
        wallets: initial.wallets.clone(),
        continuity: initial.continuity.clone(),
        ..Default::default()
    };
    let genesis = FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
    let (owner, assignments, expected, licenses, coordinator) = licenses::fixtures();
    state
        .wallets
        .register(&owner.public().descriptor(1).unwrap())
        .unwrap();
    let continuity = HybridKey::generate(Role::Continuity).unwrap();
    let old_node = state.continuity.as_ref().unwrap().members[0].node;
    let mut binding = initial
        .membership_v2
        .get(old_node)
        .unwrap()
        .binding()
        .clone();
    binding.node_descriptor = coordinator.public().descriptor(1).unwrap();
    binding.admission.node =
        mutiny_consensus_v8::node_admission_v2::node_id(genesis.genesis, &binding.node_descriptor)
            .unwrap();
    binding.admission.continuity_descriptor = continuity.public().descriptor(1).unwrap();
    let ak = p256::ecdsa::SigningKey::from_bytes((&[9u8; 32]).into()).unwrap();
    let profile = tpm::profile(&ak);
    assert_eq!(binding.admission.profile, profile.encode().unwrap());
    binding.admission.prove_continuity(&continuity).unwrap();
    binding.admission.quote = tpm::quote(&ak, &profile, binding.admission.challenge().unwrap());
    binding.admission.authorize(&owner, 1).unwrap();
    binding.sign(&coordinator).unwrap();
    let policy = mutiny_consensus_v8::admission_v2::Policy {
        genesis: genesis.genesis,
        fingerprint: genesis.fingerprint,
        owner_descriptor: owner.public().descriptor(1).unwrap(),
        endorsement_roots: [binding.admission.endorsement_root].into_iter().collect(),
    };
    let admission_expected = mutiny_consensus_v8::admission_v2::Expected {
        node: binding.admission.node,
        hardware_generation: 1,
        key_generation: 1,
        supervised_nonce: binding.admission.supervised_nonce,
    };
    (state.membership_v2, state.continuity_keys_v2) =
        mutiny_consensus_v8::membership_v2::Book::genesis(
            &binding,
            &policy,
            &admission_expected,
            &state.wallets,
            mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest,
        )
        .unwrap();
    state.continuity.as_mut().unwrap().members[0].node = binding.admission.node;
    state.licenses_v2 = mutiny_consensus_v8::license_book_v2::Book::genesis(
        &assignments,
        &expected,
        &licenses,
        &state.wallets,
        genesis.genesis,
        genesis.fingerprint,
    )
    .unwrap();
    state.admission_policy_v2 =
        Some(mutiny_consensus_v8::admission_policy_v2::Record::new(policy).unwrap());
    let buyer =
        HybridKey::wallet_restore(&("zoo ".repeat(23) + "vote"), Role::WalletOwner).unwrap();
    state
        .wallets
        .register(&buyer.public().descriptor(1).unwrap())
        .unwrap();
    let third = HybridKey::wallet_restore(
        "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
        Role::WalletOwner,
    )
    .unwrap();
    state
        .wallets
        .register(&third.public().descriptor(1).unwrap())
        .unwrap();
    state.coins.clear();
    for (point, owner) in [(BUYER_COIN, address(&buyer)), (THIRD_COIN, address(&third))] {
        state.coins.insert(
            point,
            Coin {
                output: Output {
                    owner,
                    atoms: 100_000,
                },
                created_height: 0,
                coinbase: false,
            },
        );
    }
    let rows = state.records().expect("fixture records");
    State::from_records(&rows, state.root().unwrap()).expect("fixture restore");
    Fixture {
        state,
        genesis,
        coordinator,
        continuity,
        license: licenses[0].id,
        worker: expected[0].worker_id,
        backup_license: licenses[1].id,
        backup_worker: expected[1].worker_id,
        expected,
        seller: owner,
        buyer,
        third,
    }
}

/// LicenseDvp (trading body version 2): License 0 from the seller to the buyer for 50,000 atoms,
/// fee 20,000, change 30,000, valid only at the height after `parent`.
fn sale_operation(f: &Fixture, reviewed: &State, parent: &FinalizedAnchor) -> Vec<u8> {
    dvp(f, reviewed, &f.seller, &f.buyer, BUYER_COIN, 1, parent, 175)
}
/// License 0 from `from` to `to` (funded by `coin`) at License generation `generation`. Its
/// envelope window is the single height after `parent` and its reference is `parent` (the
/// finalized parent anchor); `tag` separates offer nonces and trade/contract ids of sales.
fn dvp(
    f: &Fixture,
    reviewed: &State,
    from: &HybridKey,
    to: &HybridKey,
    coin: OutPoint,
    generation: u64,
    parent: &FinalizedAnchor,
    tag: u8,
) -> Vec<u8> {
    let height = parent.height + 1;
    let (seller, buyer) = (address(from), address(to));
    let context = Context {
        network: NETWORK_ID,
        genesis: f.genesis.genesis,
        fingerprint: f.genesis.fingerprint,
    };
    // P7 (WP-T4, AM-6): the seller (slot 0) makes the offer with its wallet key.
    let maker = from;
    let offer = SignedOffer::sign(
        OfferBody {
            context: context.clone(),
            maker_descriptor: maker.public().descriptor(1).unwrap(),
            maker_wallet: seller,
            destination: seller,
            condition: None,
            max_fee: Strikes(20_000),
            nonce: [tag; 32],
            created: 1,
            expiry: 10,
            maker_side: 0,
            terms: OfferTerms::License {
                license: f.license,
                generation,
                price: Strikes(50_000),
            },
        },
        maker,
    )
    .unwrap();
    let mut operation = Operation {
        meta: Meta {
            context,
            trade: [tag.wrapping_add(1); 32],
            contract: [tag.wrapping_add(2); 32],
            generation: 1,
            envelope: mutiny_consensus_v8::op_envelope_v1::Envelope {
                first_height: height,
                last_height: height,
                reference_height: parent.height,
                reference_block: parent.block,
                // WP-T2 (design 6.1): the License facts the sale was reviewed against.
                preconditions: vec![
                    mutiny_consensus_v8::op_envelope_v1::entitlement_facts(reviewed, f.license),
                    mutiny_consensus_v8::op_envelope_v1::assignment_facts(reviewed, f.license).unwrap(),
                ],
            },
            fee: Strikes(20_000),
            inputs: vec![native_input_id(&coin)],
        },
        action: Action::LicenseDvp {
            offer: offer.body.id().unwrap(),
            maker: offer.body.maker().unwrap(),
            license: f.license,
            license_generation: generation,
            seller,
            buyer,
            price: Strikes(50_000),
            payment_destination: seller,
            change: Strikes(30_000),
        },
        approvals: vec![],
        offer_proof: None,
    };
    operation.offer_proof = Some(OfferProof::sign(offer, &operation, maker).unwrap());
    operation.approve(0, from, 1).unwrap();
    operation.approve(1, to, 1).unwrap();
    NativeOperation {
        operation,
        inputs: vec![coin],
    }
    .encode()
    .unwrap()
}

/// A reassignment of Genesis License `index` to synthetic Worker `seed`, authorized by `owner`,
/// with the given generation and effective epoch (inclusion deadline height 100).
fn reassignment(
    f: &Fixture,
    index: usize,
    owner: &HybridKey,
    seed: u8,
    generation: u64,
    effective_epoch: u64,
) -> Assignment {
    let mut b = f.expected[index].clone();
    b.owner_descriptor = owner_descriptor_id(owner.public(), 1).unwrap();
    b.owner_generation = 1;
    b.worker_public = licenses::worker(seed);
    b.worker_id = b.derived_worker_id();
    b.assignment_generation = generation;
    b.configuration_generation = 2;
    b.device_mac = [2, 0, 0, 0, 0, seed];
    b.effective_epoch = effective_epoch;
    b.valid_until_height = 100;
    licenses::sign(b, owner, &f.coordinator.public().descriptor(1).unwrap(), seed)
}

fn certify_at(
    prepared: mutiny_consensus_v8::assembler_v2::Prepared,
    f: &Fixture,
    parent: &FinalizedAnchor,
    state: &State,
    ticket: u64,
) -> BlockEnvelope {
    let root = prepared.execution.root;
    certify_parts(prepared.candidate, prepared.body, root, f, parent, state, ticket)
}
/// trading_host_v1.rs certify_at (lines 399-487) on explicit parts, so that a block that the
/// executor refuses can still be certified and offered to `CanonicalStore::commit`.
fn certify_parts(
    candidate: Candidate,
    body: BlockBody,
    state_root: Hash,
    f: &Fixture,
    parent: &FinalizedAnchor,
    state: &State,
    ticket: u64,
) -> BlockEnvelope {
    let height = candidate.height;
    let epoch = mutiny_consensus_v8::pow::mining_epoch(candidate.timestamp, 1000).unwrap();
    let mut book = state.licenses_v2.clone();
    book.activate_due(epoch).unwrap();
    let assignment = book
        .active(candidate.license, candidate.worker, epoch)
        .unwrap()
        .0
        .assignment_sequence;
    let mut authority = Authority {
        work: WorkAuthority {
            candidate: candidate.clone(),
            assignment_sequence: assignment,
            ticket_sequence: ticket,
            coordinator: mutiny_consensus_v8::work_authority_v2::node_identity(
                &f.coordinator.public().descriptor(1).unwrap(),
            )
            .unwrap(),
            nonce_start: 0,
            nonce_end: 100,
            epoch,
        },
        node_descriptor: f.coordinator.public().descriptor(1).unwrap(),
        signature: empty(),
    };
    authority.sign(&f.coordinator).unwrap();
    let header = WorkHeader {
        candidate,
        authority: authority.id().unwrap(),
        nonce: 1,
    };
    assert!(mutiny_consensus_v8::pow::meets_target(
        &header.block_hash(),
        &[255; 32]
    ));
    let height_authority = mutiny_consensus_v8::votes_v2::HeightAuthority::from_state(
        state,
        parent.clone(),
        state.root().unwrap(),
    )
    .unwrap();
    let (node, voter) = height_authority.voters.iter().next().unwrap();
    let decision = Decision {
        network: f.genesis.network,
        genesis: f.genesis.genesis,
        fingerprint: f.genesis.fingerprint,
        purpose: 2,
        height,
        mining_epoch: epoch,
        continuity_period: (height - 1) / 60,
        round: 0,
        step: 3,
        previous_finalized_anchor: parent.id(),
        parent: parent.block,
        block: header.block_hash(),
        state: state_root,
        membership: height_authority.membership,
        reputation: height_authority.reputation,
        attestation: height_authority.attestation,
    };
    let mut vote = Vote {
        decision: decision.clone(),
        nil: false,
        node: *node,
        hardware_generation: voter.hardware_generation,
        key_generation: voter.key_generation,
        sequence: height * 10,
        tpm_identity: voter.tpm_identity(),
        profile: voter.profile,
        signature: empty(),
    };
    vote.sign(&f.continuity).unwrap();
    BlockEnvelope {
        header,
        body,
        authority,
        certificate: Certificate {
            decision,
            votes: vec![vote],
        },
    }
}

/// A canonical store and pool in a unique, atomically created temporary directory.
struct Chain {
    base: PathBuf,
    store: CanonicalStore,
    pool: Mempool,
}
impl Chain {
    fn open(f: &Fixture) -> Self {
        let base = (0..16)
            .find_map(|_| {
                let mut nonce = [0; 16];
                mutiny_crypto_v2::fill_os_random(&mut nonce).unwrap();
                let path =
                    std::env::temp_dir().join(format!("build8-q17-sale-{}", hex::encode(nonce)));
                match mutiny_consensus_v8::submission_pool_v1::private_directory(&path) {
                    Ok(true) => Some(path),
                    Ok(false) => None,
                    Err(e) => panic!("{e:?}"),
                }
            })
            .expect("a unique temporary directory");
        let store = CanonicalStore::open_trusted_genesis(
            &base.join("chain.sqlite"),
            &f.genesis,
            &f.state,
            f.state.root().unwrap(),
            1000,
            [255; 32],
        )
        .unwrap();
        let mut pool = Mempool::open(
            &base.join("pool.sqlite"),
            f.genesis.genesis,
            f.genesis.fingerprint,
            64 * 1024 * 1024,
        )
        .unwrap();
        store.reconcile_pool(&mut pool).unwrap();
        Self { base, store, pool }
    }
    fn close(self) {
        let Self { base, store, pool } = self;
        drop(store);
        drop(pool);
        assert!(base.starts_with(std::env::temp_dir()));
        eprintln!("Q17 native canonical public fixture retained: {}", base.display());
    }
    /// Prepare through the store, certify and commit one real block over `parent` (the tip).
    #[allow(clippy::too_many_arguments)]
    fn mine(
        &mut self,
        f: &Fixture,
        parent: &FinalizedAnchor,
        license: Hash,
        worker: Hash,
        timestamp: u64,
        ticket: u64,
        operations: &[Vec<u8>],
    ) -> FinalizedAnchor {
        let (_, parent_state) = self.store.load().unwrap();
        let prepared = self
            .store
            .prepare_pending(Preparation {
                expected_parent: parent,
                pool: &self.pool,
                license,
                worker,
                timestamp,
                ticket,
                operations,
            })
            .unwrap();
        let block = certify_at(prepared, f, parent, &parent_state, ticket);
        assert!(self.store.commit(&block).unwrap());
        self.store.reconcile_pool(&mut self.pool).unwrap();
        block.certificate.decision.anchor()
    }
    /// The executor's own verdict on a candidate block over the committed tip, with the parent
    /// the store gives the executor (`execution_parent`).
    #[allow(clippy::too_many_arguments)]
    fn execute(
        &self,
        license: Hash,
        worker: Hash,
        timestamp: u64,
        ticket: u64,
        reward_owner: Hash,
        fees: u64,
        operations: &[Vec<u8>],
    ) -> std::result::Result<Execution, ExecutionError> {
        let (candidate, body) = self.candidate(license, worker, timestamp, reward_owner, fees, operations);
        let (head, _) = self.store.load().unwrap();
        let (parent, state, _) = self.store.execution_parent(head.height).unwrap();
        state.prepare_candidate_v2(CandidatePreparation {
            parent: &parent,
            candidate: &candidate,
            ticket_sequence: ticket,
            body: &body,
        })
    }
    fn candidate(
        &self,
        license: Hash,
        worker: Hash,
        timestamp: u64,
        reward_owner: Hash,
        fees: u64,
        operations: &[Vec<u8>],
    ) -> (Candidate, BlockBody) {
        let (head, _) = self.store.load().unwrap();
        let (parent, _, root) = self.store.execution_parent(head.height).unwrap();
        let body = BlockBody {
            height: parent.height + 1,
            reward_owner,
            fees,
            transactions: vec![],
            operations: operations.to_vec(),
        };
        let candidate = Candidate {
            network: NETWORK_ID,
            genesis: parent.genesis,
            fingerprint: parent.fingerprint,
            parent: parent.block,
            height: parent.height + 1,
            timestamp,
            body_root: body.root().unwrap(),
            state_root: root,
            license,
            worker,
            target: parent.target,
        };
        (candidate, body)
    }
    /// The store's refusal to prepare a block: the assembler's text of the executor error.
    fn refusal(
        &self,
        parent: &FinalizedAnchor,
        license: Hash,
        worker: Hash,
        timestamp: u64,
        ticket: u64,
        operations: &[Vec<u8>],
    ) -> String {
        match self.store.prepare_pending(Preparation {
            expected_parent: parent,
            pool: &self.pool,
            license,
            worker,
            timestamp,
            ticket,
            operations,
        }) {
            Err(StoreError::Assembly(reason)) => reason,
            Err(other) => panic!("expected an assembly refusal, got {other:?}"),
            Ok(_) => panic!("the store prepared a block that must be refused"),
        }
    }
    /// Offer `commit` a CERTIFIED block over `parent` whose body the executor refuses (state
    /// root = the parent's); return its error.
    #[allow(clippy::too_many_arguments)]
    fn commit_refused(
        &mut self,
        f: &Fixture,
        parent: &FinalizedAnchor,
        license: Hash,
        worker: Hash,
        timestamp: u64,
        ticket: u64,
        reward_owner: Hash,
        fees: u64,
        operations: &[Vec<u8>],
    ) -> StoreError {
        let (_, state) = self.store.load().unwrap();
        let (candidate, body) = self.candidate(license, worker, timestamp, reward_owner, fees, operations);
        let root = candidate.state_root;
        let block = certify_parts(candidate, body, root, f, parent, &state, ticket);
        self.store.commit(&block).expect_err("a refused block must not commit")
    }
    /// Every row of every table of the canonical store database (state_v2, undo_v2,
    /// confirmations_v2, canonical_v2, finalized_v2, evidence_v2, proof index, ...), read through
    /// an independent read-only connection and sorted.
    fn tables(&self) -> Vec<String> {
        let db = rusqlite::Connection::open_with_flags(
            self.base.join("chain.sqlite"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .unwrap();
        let names: Vec<String> = db
            .prepare("SELECT name FROM sqlite_schema WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert!(names.iter().any(|n| n == "state_v2") && names.iter().any(|n| n == "undo_v2"));
        let mut rows = Vec::new();
        for name in names {
            let mut statement = db.prepare(&format!("SELECT * FROM \"{name}\"")).unwrap();
            let columns = statement.column_count();
            let mut query = statement.query([]).unwrap();
            while let Some(row) = query.next().unwrap() {
                let values: Vec<rusqlite::types::Value> =
                    (0..columns).map(|i| row.get(i).unwrap()).collect();
                rows.push(format!("{name}:{values:?}"));
            }
        }
        assert!(!rows.is_empty());
        rows.sort();
        rows
    }
}

