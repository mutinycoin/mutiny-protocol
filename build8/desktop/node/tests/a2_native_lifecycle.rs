//! Source-only candidate TESTS until independently reviewed and compiled.
//! Genuine assigned Worker, hybrid Node work/Continuity certificate, own replay
//! and actual authenticated loopback. No physical TPM or production claim.
#[path="support/a2_native/mod.rs"]
mod support;
use support::{fixture::{self,Fixture,T_REF,exact_index,private_root,sha,zero},peer::Pair};
use mutinyd_v8::{
    a2_operation_pool_v1::{Pool,Context},a2_operation_relay_v1::Relay,
    candidate_journal_v3::{Journal as Candidates,Record},hybrid_a2_dispatch_v1,
    hybrid_coordinator_v2::{Coordinator,Clock,Sample,Accounting,Request},
    observation_journal_v2::Journal as Observations,work_journal_v2::Journal as Issued,
    observation_custody_v2::Custody,
};
use mutiny_consensus_v8::{Hash,anchors::FinalizedAnchor,pow::WorkHeader};
use mutiny_transport_v2::objects::{ObjectKind,ObjectQueue,object_id};
use std::path::Path;

fn context<'a>(f:&Fixture,parent:&'a FinalizedAnchor,timestamp:u64,ticket:u64) -> Context<'a> {
    Context {parent,license:f.license,worker:f.worker,timestamp,ticket}
}
struct PublicClock(Sample);
impl Clock for PublicClock {fn sample(&mut self)->Result<Sample,String>{Ok(self.0)}}
fn ticket_rows(path:&Path) -> Vec<(Vec<u8>,Vec<u8>,Vec<u8>,Option<Vec<u8>>,Option<Vec<u8>>)> {
    let db=rusqlite::Connection::open_with_flags(path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let mut q=db.prepare("SELECT worker,ticket,reservation,offer,body FROM tickets ORDER BY worker").unwrap();
    q.query_map([],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap().collect::<Result<Vec<_>,_>>().unwrap()
}
/// Snapshot every public canonical SQLite table in one read transaction. This
/// checks failed commit atomicity across evidence, undo, state and IDX, rather
/// than treating unchanged StateRoot alone as proof that no table changed.
fn canonical_rows(path:&Path) -> Vec<(String,Vec<String>)> {
    let db=rusqlite::Connection::open_with_flags(path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let _snapshot=db.unchecked_transaction().unwrap();
    let mut names=db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").unwrap();
    let names=names.query_map([],|r|r.get::<_,String>(0)).unwrap().collect::<Result<Vec<_>,_>>().unwrap();
    names.into_iter().map(|name|{
        let quoted=name.replace('"',"\"\"");
        let mut q=db.prepare(&format!("SELECT * FROM \"{quoted}\"")).unwrap();let count=q.column_count();
        let mut values=q.query_map([],|r|{
            let columns=(0..count).map(|i|r.get::<_,rusqlite::types::Value>(i)).collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(format!("{columns:?}"))
        }).unwrap().collect::<Result<Vec<_>,_>>().unwrap();
        values.sort();(name,values)
    }).collect()
}
fn submission(header:&WorkHeader,sequence:u64,previous:Hash) -> mutinyd_v8::worker_protocol_v2::Submission {
    let mut wire=vec![3,2];wire.extend(sequence.to_be_bytes());wire.extend(previous);wire.extend(header.work_bytes());
    let scope=mutinyd_v8::worker_protocol_v2::Scope {genesis:header.candidate.genesis,fingerprint:header.candidate.fingerprint,
        license:header.candidate.license,worker:header.candidate.worker};
    let mutinyd_v8::worker_protocol_v2::Incoming::Result(result)=mutinyd_v8::worker_protocol_v2::decode(&wire,scope).unwrap() else {panic!("actual result codec")};
    result
}

/// Native admitted public bytes, not the in-memory pool storage model. All failed
/// fixtures are retained. SQL abort is a transaction-control fault, not a claim
/// about disk-full, power loss, foreign accounts or physical TPMs.
fn archive_boundaries(f:&Fixture,runtime:&fixture::HybridRuntime,base:&Path) {
    let parent=runtime.head().unwrap();let ctx=context(f,&parent,T_REF+60,1);
    let raw=[f.judgment(runtime,0,T_REF+60,false),f.judgment(runtime,1,T_REF+60,false),f.judgment(runtime,0,T_REF+60,true)];
    let path=base.join("native-archive-bound.sqlite");let mut pool=Pool::open(runtime,&path,true).unwrap();
    for bytes in &raw[..2] {
        pool.submit(runtime,&ctx,bytes).unwrap();
        assert!(pool.archive_and_cancel(sha(bytes),"public TEST owner cancellation").unwrap());
    }
    pool.submit(runtime,&ctx,&raw[2]).unwrap();let before=canonical_rows(&path);
    assert!(pool.archive_and_cancel(sha(&raw[2]),"archive full must preserve").is_err());
    assert_eq!(canonical_rows(&path),before);drop(pool);
    let pool=Pool::open(runtime,&path,false).unwrap();
    assert_eq!(pool.pending(runtime,&ctx).unwrap(),Some(raw[2].clone()));
    for bytes in &raw[..2] {assert_eq!(pool.archived(sha(bytes)).unwrap().unwrap().0,*bytes);}
    let path=base.join("native-archive-abort.sqlite");let mut pool=Pool::open(runtime,&path,true).unwrap();
    pool.submit(runtime,&ctx,&raw[0]).unwrap();
    let db=rusqlite::Connection::open(&path).unwrap();
    db.execute_batch("CREATE TRIGGER public_test_refuse_cancel BEFORE DELETE ON pending BEGIN SELECT RAISE(ABORT,'public TEST cancellation abort'); END").unwrap();
    let before=canonical_rows(&path);
    assert_eq!(pool.archive_and_cancel(sha(&raw[0]),"retain failed transaction").unwrap_err(),"A2 queue storage failure");
    assert_eq!(canonical_rows(&path),before);
    assert!(pool.archived(sha(&raw[0])).unwrap().is_none());
    assert_eq!(pool.pending(runtime,&ctx).unwrap(),Some(raw[0].clone()));
    // The extra trigger deliberately makes this preserved fault DB ineligible
    // for normal reopen. No trigger is dropped to manufacture a passing reopen.
}

/// An unACKed old public operation is archived before a new item can be relayed.
/// Reopen has no trusted volatile reservation; exact durable bytes and current
/// peer/network gates must decide release. Nothing here marks an item delivered.
fn owner_archive_recovery(f:&Fixture,runtime:&fixture::HybridRuntime,base:&Path) {
    let root=base.join("owner-recovery");assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&root).unwrap());
    let parent=runtime.head().unwrap();let ctx=context(f,&parent,T_REF+60,1);
    let a=f.judgment(runtime,0,T_REF+60,false);let b=f.judgment(runtime,1,T_REF+60,false);
    let path=root.join("owner-a2.sqlite");let mut pool=Pool::open(runtime,&path,true).unwrap();
    let mut peers=Pair::open(f,&root,true);let mut relay=Relay::new(peers.send.peer_id()).unwrap();
    pool.submit(runtime,&ctx,&a).unwrap();
    let (offer,_)=relay.prepare_peer(runtime,&pool,&ctx,&mut peers.send).unwrap().unwrap();
    assert_eq!(peers.send.with_current(|l|l.completed(&offer.id)).unwrap().unwrap().1,a);
    assert!(pool.archive_and_cancel(sha(&a),"unACKed owner cancellation").unwrap());
    drop(relay);drop(peers);drop(pool);
    let mut pool=Pool::open(runtime,&path,false).unwrap();let mut peers=Pair::open(f,&root,false);
    let mut relay=Relay::new(peers.send.peer_id()).unwrap();
    assert!(relay.release_archived_peer(runtime,&pool,fixture::label("other-operation"),&mut peers.send).is_err());
    let mut wrong_peer=Relay::new(peers.recv.peer_id()).unwrap();
    assert!(wrong_peer.release_archived_peer(runtime,&pool,sha(&a),&mut peers.send).is_err());
    pool.submit(runtime,&ctx,&a).unwrap();
    assert!(relay.release_archived_peer(runtime,&pool,sha(&a),&mut peers.send).is_err());
    assert_eq!(peers.send.with_current(|l|l.completed(&offer.id)).unwrap().unwrap().1,a);
    assert!(pool.archive_and_cancel(sha(&a),"unACKed owner cancellation").unwrap());
    // A genuine externally held SQLite write transaction lets reads succeed but
    // makes the durable DELETE fail. Assert its exact stage rather than counting
    // schema rejection as an atomic-deletion probe.
    let mut held=rusqlite::Connection::open(root.join("send-objects.sqlite")).unwrap();
    let hold=held.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).unwrap();
    let before=canonical_rows(&root.join("send-objects.sqlite"));
    assert_eq!(relay.release_archived_peer(runtime,&pool,sha(&a),&mut peers.send).unwrap_err(),"A2 cancellation transport release");
    assert_eq!(canonical_rows(&root.join("send-objects.sqlite")),before);
    assert_eq!(pool.archived(sha(&a)).unwrap().unwrap().0,a);drop(hold);drop(held);
    assert!(relay.release_archived_peer(runtime,&pool,sha(&a),&mut peers.send).unwrap());
    assert!(!relay.release_archived_peer(runtime,&pool,sha(&a),&mut peers.send).unwrap());
    assert!(peers.send.with_current(|l|l.describe(&offer.id)).unwrap().is_err());
    assert_eq!(pool.archived(sha(&a)).unwrap().unwrap().0,a);
    pool.submit(runtime,&ctx,&b).unwrap();let mut ingress=Pool::open(runtime,&root.join("ingress-a2.sqlite"),true).unwrap();
    let (next,have)=relay.prepare_peer(runtime,&pool,&ctx,&mut peers.send).unwrap().unwrap();assert_ne!(next.id,offer.id);
    let complete=peers.deliver_advertised(next.clone(),&have);
    assert!(matches!(hybrid_a2_dispatch_v1::dispatch_peer(runtime,&mut ingress,&ctx,&mut peers.recv,complete.event).unwrap(),
        hybrid_a2_dispatch_v1::Outcome::Accepted{digest,..} if digest==sha(&b)));
    peers.publish_after_durable(complete.acknowledgments);
    assert!(relay.prepare_peer(runtime,&pool,&ctx,&mut peers.send).unwrap().is_none());
    assert_eq!(ingress.pending(runtime,&ctx).unwrap(),Some(b.clone()));
    let unrelated=root.join("other-item");assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&unrelated).unwrap());
    let mut unrelated_peers=Pair::open(f,&unrelated,true);
    let (other,_)=unrelated_peers.send.with_current(|l|l.enqueue(ObjectKind::A2EvidenceOperation,&b,0)).unwrap().unwrap();
    let mut unrelated_relay=Relay::new(unrelated_peers.send.peer_id()).unwrap();
    assert!(unrelated_relay.release_archived_peer(runtime,&pool,sha(&a),&mut unrelated_peers.send).is_err());
    assert_eq!(unrelated_peers.send.with_current(|l|l.completed(&other.id)).unwrap().unwrap().1,b);
    // Partial receiver state is genuine: authenticated HAVE dispatched, zero
    // fragments received. It must not be mistaken for an absent complete queue.
    let partial=root.join("partial");assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&partial).unwrap());
    let mut peers=Pair::open(f,&partial,true);
    let (partial_offer,have)=peers.send.with_current(|l|l.enqueue(ObjectKind::A2EvidenceOperation,&a,0)).unwrap().unwrap();
    peers.send.send(&have,support::peer::limit()).unwrap();let received=peers.recv.receive(support::peer::limit()).unwrap();
    assert!(peers.recv.dispatch_received(received,|_,event|matches!(event,mutiny_transport_v2::object_link::Event::Offered(_))).unwrap());
    let before=canonical_rows(&partial.join("recv-objects.sqlite"));let mut relay=Relay::new(peers.recv.peer_id()).unwrap();
    assert_eq!(relay.release_archived_peer(runtime,&pool,sha(&a),&mut peers.recv).unwrap_err(),
        "A2 cancellation partial or invalid evidence retained");
    assert_eq!(canonical_rows(&partial.join("recv-objects.sqlite")),before);
    assert_eq!(peers.recv.with_current(|l|l.describe(&partial_offer.id)).unwrap().unwrap(),(partial_offer,false));
    let foreign=root.join("other-network");assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&foreign).unwrap());
    let mut genesis=f.parent.genesis;genesis[0]^=1;
    let mut peers=Pair::open_network(f,&foreign,true,genesis,f.parent.fingerprint);
    let (offer,_)=peers.send.with_current(|l|l.enqueue(ObjectKind::A2EvidenceOperation,&a,0)).unwrap().unwrap();
    let mut relay=Relay::new(peers.send.peer_id()).unwrap();
    assert!(relay.release_archived_peer(runtime,&pool,sha(&a),&mut peers.send).is_err());
    assert_eq!(peers.send.with_current(|l|l.completed(&offer.id)).unwrap().unwrap().1,a);
}

#[test]
fn a2_native_pool_relay_successive_certified_blocks_and_exact_idx_reopen() {
    let f=Fixture::load();let base=private_root("successive");let mut runtime=f.runtime(&base);
    let mut local=Pool::open(&runtime,&base.join("local-a2.sqlite"),true).unwrap();
    let mut ingress=Pool::open(&runtime,&base.join("ingress-a2.sqlite"),true).unwrap();
    let mut peers=Pair::open(&f,&base,true);let mut relay=Relay::new(peers.send.peer_id()).unwrap();
    let mut finalized=Vec::new();
    for (index,timestamp,large) in [(0,T_REF+60,true),(1,T_REF+120,false)] {
        let parent=runtime.head().unwrap();let ticket=index as u64+1;
        let raw=f.judgment(&runtime,index,timestamp,large);let ctx=context(&f,&parent,timestamp,ticket);
        if large {
            let second=f.judgment(&runtime,1,timestamp,true);
            let before=canonical_rows(&base.join("canonical.sqlite"));
            assert!(runtime.prepare(mutinyd_v8::hybrid_runtime_v2::WorkRequest {expected_parent:&parent,
                license:f.license,worker:f.worker,timestamp,ticket,operations:&[raw.clone(),second]}).is_err());
            assert_eq!(canonical_rows(&base.join("canonical.sqlite")),before);
        }
        local.submit(&runtime,&ctx,&raw).unwrap();
        assert_eq!(local.pending(&runtime,&ctx).unwrap(),Some(raw.clone()));
        let (offer,have)=relay.prepare_peer(&runtime,&local,&ctx,&mut peers.send).unwrap().unwrap();
        let complete=peers.deliver_advertised(offer,&have);
        let offer=complete.offer.clone();
        assert!(matches!(hybrid_a2_dispatch_v1::dispatch_peer(&runtime,&mut ingress,&ctx,&mut peers.recv,complete.event).unwrap(),
            hybrid_a2_dispatch_v1::Outcome::Accepted{digest,..} if digest==sha(&raw)));
        assert_eq!(ingress.pending(&runtime,&ctx).unwrap(),Some(raw.clone()));
        assert!(peers.recv.with_current(|l|l.completed(&offer.id)).unwrap().is_err());
        // Full native insertion committed before any ACK bytes are published.
        peers.publish_after_durable(complete.acknowledgments);
        assert!(relay.prepare_peer(&runtime,&local,&ctx,&mut peers.send).unwrap().is_none());
        assert!(peers.send.with_current(|l|l.completed(&offer.id)).unwrap().is_err());
        let op=mutiny_consensus_v8::endorsement_revocation_v1::Operation::decode(&raw).unwrap();
        assert!(runtime.chain.verified_operation_records(op.id().unwrap()).unwrap().is_empty());
        let record=f.candidate(&mut runtime,&raw,timestamp,ticket);
        let envelope=f.certify(&runtime,&record);
        let before_tables=canonical_rows(&base.join("canonical.sqlite"));
        let before=runtime.chain.load().unwrap();let mut bad=envelope.clone();bad.certificate.votes[0].signature.fndsa[0]^=1;
        let capacity=runtime.chain.proposal_body_capacity(&bad.header).unwrap();
        assert!(runtime.install(&bad.encode_with_capacity(&capacity).unwrap()).is_err());assert_eq!(runtime.chain.load().unwrap(),before);
        assert_eq!(canonical_rows(&base.join("canonical.sqlite")),before_tables);
        assert_eq!(ingress.pending(&runtime,&ctx).unwrap(),Some(raw.clone()));
        f.install(&mut runtime,&envelope);exact_index(&runtime,&raw,&envelope);
        // Unused-anchor withdrawal leaves genuine successor voting authority.
        // Inspect the public authenticated authority rather than a private flag.
        let successor=runtime.chain.current_authority(&runtime.head().unwrap()).unwrap();
        assert!(!successor.voters[&f.node].weight().unwrap().is_zero());
        assert!(local.reconcile_finalized(&runtime).unwrap());assert!(ingress.reconcile_finalized(&runtime).unwrap());
        finalized.push((raw,envelope));
        eprintln!("PUBLIC genuine A2 carrier bytes={} oversized={} structural_max={}",finalized.last().unwrap().0.len(),large,
            mutiny_consensus_v8::endorsement_revocation_v1::MAX_OPERATION_BYTES);
    }
    drop(peers);drop(local);drop(ingress);drop(runtime);
    let runtime=f.runtime(&base);assert_eq!(runtime.head().unwrap().height,2);
    let local=Pool::open(&runtime,&base.join("local-a2.sqlite"),false).unwrap();
    let ingress=Pool::open(&runtime,&base.join("ingress-a2.sqlite"),false).unwrap();
    let parent=runtime.head().unwrap();let ctx=context(&f,&parent,T_REF+180,3);
    assert!(local.pending(&runtime,&ctx).unwrap().is_none());assert!(ingress.pending(&runtime,&ctx).unwrap().is_none());
    for (raw,envelope) in &finalized {exact_index(&runtime,raw,envelope);}
    // The actual bounded catch-up path installs these exact certified carriers
    // from its own pinned Genesis and reconciles its own native pending caches.
    struct History(std::collections::BTreeMap<u64,Vec<u8>>);
    impl mutinyd_v8::hybrid_sync_v2::HistorySource for History {
        fn recovery(&mut self,_:u64,maximum:usize)->Result<Option<Vec<u8>>,String>{
            assert_eq!(maximum,mutiny_consensus_v8::state_tree::MAX_RECORD);Ok(None)
        }
        fn block(&mut self,height:u64,maximum:usize)->Result<Vec<u8>,String>{
            assert_eq!(maximum,mutiny_consensus_v8::body_capacity_v3::MAX_ENVELOPE_BYTES);
            let bytes=self.0[&height].clone();assert!(bytes.len()<=maximum);Ok(bytes)
        }
    }
    let bytes=finalized.iter().map(|(_,envelope)|{
        let cap=runtime.chain.proposal_body_capacity(&envelope.header).unwrap();
        (envelope.body.height,envelope.encode_with_capacity(&cap).unwrap())
    }).collect();
    let mut history=History(bytes);let catchup_base=private_root("catch-up");let mut catchup=f.runtime(&catchup_base);
    let target=runtime.head().unwrap();
    let progress=mutinyd_v8::hybrid_sync_v2::catch_up(&mut catchup,&mut history,&target,2).unwrap();
    assert_eq!(progress.installed,2);assert!(progress.target_reached && progress.pending_cache_available);
    for (raw,envelope) in &finalized {exact_index(&catchup,raw,envelope);}
}

#[test]
fn a2_native_v3_work_observation_reopen_old_retry_and_mixed_modes_before_ticket() {
    let f=Fixture::load();let base=private_root("journals");let mut runtime=f.runtime(&base);let parent=runtime.head().unwrap();
    let descriptor=f.node_key(&runtime).public().descriptor(1).unwrap();let key=f.custody(&runtime);let custody=Custody::Physical(&key);
    let wp=base.join("work-v3.sqlite");let op=base.join("observations-v3.sqlite");let cp=base.join("candidates-v3.sqlite");
    let mut issued=Issued::open_a2(&runtime,&wp,&descriptor,true).unwrap();
    let mut observations=Observations::open_a2(&runtime,&op,&descriptor,true).unwrap();
    let mut candidates=Candidates::open(&runtime,&cp,2*1024*1024,true).unwrap();
    let lp=base.join("work-v2.sqlite");let mut legacy=Issued::initialize(&lp,parent.genesis,parent.fingerprint,&descriptor).unwrap();
    let legacy_obs=Observations::open(&base.join("observations-v2.sqlite"),parent.genesis,parent.fingerprint,&descriptor,true).unwrap();
    let mut legacy_candidates=mutinyd_v8::candidate_journal_v2::Journal::open(&base.join("candidates-v2.sqlite"),parent.genesis,parent.fingerprint,1024*1024,true).unwrap();
    let raw=f.judgment(&runtime,0,T_REF+60,true);let operations=vec![raw];
    let request=||Request {parent:&parent,license:f.license,worker:f.worker,request_nonce:fixture::label("journal-request"),
        nonce_start:0,nonce_end:100,operations:&operations};
    let mut coordinator=Coordinator::default();coordinator.set_run(true);
    let mut clock=PublicClock(Sample {monotonic_ms:100,unix_ms:(T_REF+60)*1000});
    let before_a2=ticket_rows(&wp);let before_legacy=ticket_rows(&lp);
    assert!(coordinator.prepare_accounted_a2(&mut runtime,&mut legacy,&custody,request(),
        Accounting {journal:&observations,sequence:0,chain:[0;32]},&mut candidates,&mut clock).is_err());
    assert!(coordinator.prepare_accounted_a2(&mut runtime,&mut issued,&custody,request(),
        Accounting {journal:&legacy_obs,sequence:0,chain:[0;32]},&mut candidates,&mut clock).is_err());
    assert!(coordinator.prepare_accounted(&mut runtime,&mut issued,&custody,request(),
        Accounting {journal:&observations,sequence:0,chain:[0;32]},&mut legacy_candidates,&mut clock).is_err());
    assert_eq!(ticket_rows(&wp),before_a2);assert_eq!(ticket_rows(&lp),before_legacy);
    let decision=coordinator.request_probe(&runtime,&parent,&mut clock).unwrap().unwrap();
    let authority=runtime.chain.current_authority(&parent).unwrap();let voter=&authority.voters[&f.node];
    let mut fragment=mutiny_consensus_v8::liveness_v2::Fragment {node:f.node,hardware_generation:voter.hardware_generation,
        key_generation:voter.key_generation,vote_sequence:0,tpm_identity:voter.tpm_identity(),profile:voter.profile,signature:zero()};
    fragment.sign(&decision,&f.continuity).unwrap();
    coordinator.accept_probe(&runtime,&parent,&mutiny_consensus_v8::liveness_v2::Proof {decision,fragments:vec![fragment]},&mut clock).unwrap();
    let pending=coordinator.prepare_accounted_a2(&mut runtime,&mut issued,&custody,request(),
        Accounting {journal:&observations,sequence:0,chain:[0;32]},&mut candidates,&mut clock).unwrap();
    let delivery=coordinator.release_accounted(&runtime,&issued,&observations,pending,&mut clock).unwrap();
    assert_eq!(delivery.authority.work.ticket_sequence,1);assert!(delivery.valid_for_ms>0 && delivery.valid_for_ms<=60_000);
    let header=WorkHeader {candidate:delivery.authority.work.candidate.clone(),authority:delivery.authority.id().unwrap(),nonce:1};
    let submitted=submission(&header,1,[0;32]);
    let committed=observations.accept(&runtime.chain,&issued,&custody,&parent,T_REF+60,&submitted).unwrap();
    assert_eq!((committed.sequence(),committed.total()),(1,1));
    let record=Record {header,authority:delivery.authority.clone(),body:delivery.body.clone()};
    let exact=record.encode(&runtime).unwrap();assert_eq!(Record::decode(&runtime,&exact).unwrap(),record);
    assert!(mutinyd_v8::candidate_journal_v2::Record::decode(&exact).is_err());
    let receipt=committed.release(candidates.preserve(&runtime,&record).unwrap().into()).unwrap();
    assert_eq!(runtime.head().unwrap(),parent);assert_eq!(candidates.next_current(&runtime,None).unwrap(),Some(record.clone()));
    drop(observations);drop(issued);drop(candidates);
    assert!(Issued::reopen(&wp,parent.genesis,parent.fingerprint,&descriptor).is_err());
    assert!(Observations::open(&op,parent.genesis,parent.fingerprint,&descriptor,false).is_err());
    let mut issued=Issued::open_a2(&runtime,&wp,&descriptor,false).unwrap();
    let mut observations=Observations::open_a2(&runtime,&op,&descriptor,false).unwrap();
    let mut candidates=Candidates::open(&runtime,&cp,2*1024*1024,false).unwrap();
    assert_eq!(issued.lookup(f.worker).unwrap(),Some((delivery.authority.clone(),delivery.body.clone())));
    let reserved=issued.reserve(f.worker,0).unwrap();assert_eq!(reserved.ticket(),2);assert!(issued.lookup(f.worker).unwrap().is_none());
    // Exact historical retry survives a newer reservation with no finished offer.
    let retry=observations.accept(&runtime.chain,&issued,&custody,&parent,T_REF+60,&submitted).unwrap();
    assert_eq!(retry.total(),1);assert_eq!(retry.release(candidates.preserve(&runtime,&record).unwrap().into()).unwrap(),receipt);
    let mut conflict=record.header.clone();conflict.nonce=2;
    assert!(observations.accept(&runtime.chain,&issued,&custody,&parent,T_REF+60,&submission(&conflict,1,[0;32])).is_err());
    assert_eq!(observations.load(f.worker).unwrap().unwrap().total(),1);
    assert_eq!(candidates.next_current(&runtime,None).unwrap(),Some(record.clone()));
    // Preserve each corrupt copy separately. Never overwrite the failed row to
    // restore a positive fixture, and never infer validity from cached metadata.
    drop(observations);
    for (name,offset) in [("ed448",278usize),("fndsa",392usize)] {
        let path=base.join(format!("corrupt-observation-{name}.sqlite"));std::fs::copy(&op,&path).unwrap();
        let mut changed=receipt.clone();changed[offset]^=1;
        let db=rusqlite::Connection::open(&path).unwrap();
        db.execute("UPDATE checkpoints SET receipt=?1 WHERE worker=?2",rusqlite::params![changed,f.worker.as_slice()]).unwrap();drop(db);
        assert!(Observations::open_a2(&runtime,&path,&descriptor,false).is_err());
    }
    let mut observations=Observations::open_a2(&runtime,&op,&descriptor,false).unwrap();
    assert_eq!(observations.load(f.worker).unwrap().unwrap().total(),1);
    let envelope=f.certify(&runtime,&record);f.install(&mut runtime,&envelope);
    exact_index(&runtime,&operations[0],&envelope);
    // Historical receipt retry is not a grant for new work. It remains the exact
    // signed checkpoint after canonical head advance and successor-mode reopen.
    drop(observations);drop(issued);drop(candidates);
    let issued=Issued::open_a2(&runtime,&wp,&descriptor,false).unwrap();
    let mut observations=Observations::open_a2(&runtime,&op,&descriptor,false).unwrap();
    let mut candidates=Candidates::open(&runtime,&cp,2*1024*1024,false).unwrap();
    let retry=observations.accept(&runtime.chain,&issued,&custody,&parent,T_REF+60,&submitted).unwrap();
    assert_eq!(retry.release(candidates.preserve(&runtime,&record).unwrap().into()).unwrap(),receipt);
    assert_eq!(observations.load(f.worker).unwrap().unwrap().total(),1);
    assert!(candidates.next_current(&runtime,None).unwrap().is_none());
}

#[test]
fn a2_native_current_pin_refuses_pending_ingress_and_relay_without_losing_bytes() {
    let f=Fixture::load();let base=private_root("current-pin");let runtime=f.runtime(&base);let parent=runtime.head().unwrap();
    let ctx=context(&f,&parent,T_REF+60,1);let raw=f.judgment(&runtime,0,T_REF+60,false);
    let mut pool=Pool::open(&runtime,&base.join("a2.sqlite"),true).unwrap();let mut peers=Pair::open(&f,&base,true);
    let complete=peers.deliver(ObjectKind::A2EvidenceOperation,&raw);let offer=complete.offer.clone();let peer=peers.recv.peer_id();
    peers.incoming.replace_peers(vec![]).unwrap();
    assert!(hybrid_a2_dispatch_v1::dispatch_peer(&runtime,&mut pool,&ctx,&mut peers.recv,complete.event).is_err());
    assert!(pool.pending(&runtime,&ctx).unwrap().is_none());assert_eq!(runtime.head().unwrap(),parent);
    drop(peers.recv);
    let queue=ObjectQueue::open_a2(&base.join("recv-objects.sqlite"),peer,false).unwrap();
    assert_eq!(queue.read_complete(&offer.id).unwrap(),raw);drop(queue);
    pool.submit(&runtime,&ctx,&raw).unwrap();let mut relay=Relay::new(peers.send.peer_id()).unwrap();
    peers.outgoing.replace_peers(vec![]).unwrap();
    assert!(relay.prepare_peer(&runtime,&pool,&ctx,&mut peers.send).is_err());
    assert_eq!(pool.pending(&runtime,&ctx).unwrap(),Some(raw));assert_eq!(runtime.head().unwrap(),parent);
}

#[test]
fn a2_native_typed_refusal_preserves_complete_transport_and_proposal_boundaries() {
    let f=Fixture::load();let base=private_root("typed-refusal");let mut runtime=f.runtime(&base);let parent=runtime.head().unwrap();
    let good=f.judgment(&runtime,0,T_REF+60,false);let mut bad=mutiny_consensus_v8::endorsement_revocation_v1::Operation::decode(&good).unwrap();
    bad.context.parent_state[0]^=1;let bad=bad.encode().unwrap();
    let ctx=context(&f,&parent,T_REF+60,1);let mut pool=Pool::open(&runtime,&base.join("a2.sqlite"),true).unwrap();
    let mut peers=Pair::open(&f,&base,true);let completed=peers.deliver(ObjectKind::A2EvidenceOperation,&bad);let id=completed.offer.id;
    assert!(hybrid_a2_dispatch_v1::dispatch_peer(&runtime,&mut pool,&ctx,&mut peers.recv,completed.event).is_err());
    assert_eq!(peers.recv.with_current(|l|l.completed(&id)).unwrap().unwrap().1,bad);
    assert!(pool.pending(&runtime,&ctx).unwrap().is_none());assert_eq!(runtime.head().unwrap(),parent);
    archive_boundaries(&f,&runtime,&base);
    owner_archive_recovery(&f,&runtime,&base);
    // Successful native V3 proposal transport is separate from certified finality.
    let proposal_base=base.join("proposal");assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&proposal_base).unwrap());
    let mut proposals=Pair::open(&f,&proposal_base,true);let record=f.candidate(&mut runtime,&good,T_REF+60,1);
    let mut journal=Candidates::open(&runtime,&base.join("proposals-v3.sqlite"),2*1024*1024,true).unwrap();
    // Exact unsigned identity/body/header are unchanged. Each authenticated
    // transport object must fail the indicated real hybrid signature half.
    // Separate queues retain both failed complete candidates, without eviction.
    for name in ["ed448","fndsa"] {
        let mut changed=record.clone();
        if name=="ed448" {changed.authority.signature.ed448[0]^=1;} else {changed.authority.signature.fndsa[0]^=1;}
        assert_eq!(changed.authority.id().unwrap(),record.authority.id().unwrap());
        assert_eq!(changed.header,record.header);assert_eq!(changed.body,record.body);
        let bytes=changed.encode(&runtime).unwrap();assert!(Record::decode(&runtime,&bytes).is_err());
        let failure_root=base.join(format!("proposal-{name}-failure"));
        assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&failure_root).unwrap());
        let mut failed=Pair::open(&f,&failure_root,true);
        let complete=failed.deliver(ObjectKind::A2BlockProposal,&bytes);let id=complete.offer.id;
        assert!(mutinyd_v8::hybrid_proposal_dispatch_v3::dispatch_peer(&runtime,&mut journal,&mut failed.recv,complete.event).is_err());
        assert_eq!(failed.recv.with_current(|l|l.completed(&id)).unwrap().unwrap().1,bytes);
        assert!(journal.next_current(&runtime,None).unwrap().is_none());assert_eq!(runtime.head().unwrap(),parent);
    }
    let bytes=record.encode(&runtime).unwrap();let complete=proposals.deliver(ObjectKind::A2BlockProposal,&bytes);let offer=complete.offer.clone();
    assert!(matches!(mutinyd_v8::hybrid_proposal_dispatch_v3::dispatch_peer(&runtime,&mut journal,&mut proposals.recv,complete.event).unwrap(),
        mutinyd_v8::hybrid_proposal_dispatch_v3::Outcome::Retained{block,..} if block==record.header.block_hash()));
    assert!(proposals.recv.with_current(|l|l.completed(&offer.id)).unwrap().is_err());
    proposals.publish_after_durable(complete.acknowledgments);
    assert_eq!(runtime.head().unwrap(),parent);assert_eq!(journal.next_current(&runtime,None).unwrap(),Some(record));
}

#[test]
fn a2_native_pool_handoff_child() {
    // Child helper has no qualification assertion when absent. It is not ignored
    // and must be reported separately from the five meaningful parent controls.
    let Some(path)=std::env::var_os("BUILD8_A2_HANDOFF_CHILD_PATH") else {return;};
    let root=std::path::PathBuf::from(path);assert!(root.is_absolute());
    assert!(!mutiny_consensus_v8::submission_pool_v1::private_directory(&root).unwrap());
    let f=Fixture::load();let runtime=f.runtime(&root);let parent=runtime.head().unwrap();
    let raw=f.judgment(&runtime,0,T_REF+60,true);let ctx=context(&f,&parent,T_REF+60,1);
    let mut pool=Pool::open(&runtime,&root.join("a2.sqlite"),false).unwrap();let mut peers=Pair::open(&f,&root,true);
    let complete=peers.deliver(ObjectKind::A2EvidenceOperation,&raw);
    assert_eq!(peers.recv.with_current(|l|l.completed(&complete.offer.id)).unwrap().unwrap().1,raw);
    pool.submit(&runtime,&ctx,&raw).unwrap();
    assert_eq!(pool.pending(&runtime,&ctx).unwrap(),Some(raw));
    // Exact natural process exit after FULL native durable insertion but before
    // publishing ACK or removing the complete transport row. Not power-loss proof.
    std::process::exit(93);
}

#[test]
fn a2_native_abrupt_handoff_reopens_and_finalized_exact_retry_releases_transport() {
    let f=Fixture::load();let base=private_root("abrupt-handoff");let runtime=f.runtime(&base);
    let pool=Pool::open(&runtime,&base.join("a2.sqlite"),true).unwrap();drop(pool);drop(runtime);
    fixture::capture_handoff_child(&base,"a2_native_pool_handoff_child","BUILD8_A2_HANDOFF_CHILD_PATH",93,"handoff-child");
    let mut runtime=f.runtime(&base);let parent=runtime.head().unwrap();let raw=f.judgment(&runtime,0,T_REF+60,true);
    let ctx=context(&f,&parent,T_REF+60,1);let mut pool=Pool::open(&runtime,&base.join("a2.sqlite"),false).unwrap();
    assert_eq!(pool.pending(&runtime,&ctx).unwrap(),Some(raw.clone()));let mut peers=Pair::open(&f,&base,false);
    let id=object_id(ObjectKind::A2EvidenceOperation,&raw).unwrap();
    let (offer,retained)=peers.recv.with_current(|l|l.completed(&id)).unwrap().unwrap();assert_eq!(retained,raw);
    let acknowledgments=peers.encode_all_receipts(&offer);
    let record=f.candidate(&mut runtime,&raw,T_REF+60,1);let envelope=f.certify(&runtime,&record);
    f.install(&mut runtime,&envelope);assert!(pool.reconcile_finalized(&runtime).unwrap());
    exact_index(&runtime,&raw,&envelope);
    // Recovery is own replay plus exact full envelope, even though ordinary
    // prospective preview of this old parent operation would now refuse.
    assert!(matches!(hybrid_a2_dispatch_v1::retry_completed(&runtime,&mut pool,&ctx,&mut peers.recv,&id).unwrap(),
        hybrid_a2_dispatch_v1::Outcome::Finalized{digest,..} if digest==sha(&raw)));
    assert!(peers.recv.with_current(|l|l.completed(&id)).unwrap().is_err());
    peers.publish_after_durable(acknowledgments);
    let mut relay=Relay::new(peers.send.peer_id()).unwrap();
    assert!(relay.prepare_peer(&runtime,&pool,&ctx,&mut peers.send).unwrap().is_none());
    assert!(peers.send.with_current(|l|l.completed(&id)).unwrap().is_err());
    drop(peers);drop(pool);drop(runtime);let runtime=f.runtime(&base);exact_index(&runtime,&raw,&envelope);
}

/// Both pools/parents are independently native software fixtures. Deliberately
/// pair a fully ACKed A-network transport copy with the B-network pool owner;
/// no caller-edited Genesis, private storage row or synthetic acceptance flag.
/// The foreign operation itself is real native-admitted B evidence. Transport
/// completion/ACK alone must not retire A's durable copy against the wrong pool.
#[test]
fn a2_native_foreign_pool_completed_ack_refuses_release_without_queue_mutation() {
    let a=Fixture::load();let b=Fixture::load_foreign();
    assert_ne!(a.parent.genesis,b.parent.genesis,
        "requires independently generated foreign Genesis; no same-context PASS");
    let root_a=private_root("foreign-pool-local");let root_b=private_root("foreign-pool-other");
    let runtime_a=a.runtime(&root_a);let runtime_b=b.runtime(&root_b);
    assert_ne!(runtime_a.network_context(),runtime_b.network_context());
    let parent_a=runtime_a.head().unwrap();let parent_b=runtime_b.head().unwrap();
    let context_a=context(&a,&parent_a,T_REF+60,1);let context_b=context(&b,&parent_b,T_REF+60,1);
    let raw=b.judgment(&runtime_b,0,T_REF+60,false);
    let mut foreign_pool=Pool::open(&runtime_b,&root_b.join("foreign-a2.sqlite"),true).unwrap();
    foreign_pool.submit(&runtime_b,&context_b,&raw).unwrap();
    assert_eq!(foreign_pool.pending(&runtime_b,&context_b).unwrap(),Some(raw.clone()));
    let mut peers=Pair::open(&a,&root_a,true);
    let completed=peers.deliver(ObjectKind::A2EvidenceOperation,&raw);let offer=completed.offer.clone();
    // Intentional wrong-owner negative: a complete copy is acknowledged, but
    // the only native durable admission is in B, never A. No A ingress grant is
    // claimed or called here. Both exact queue copies remain during the probe.
    peers.publish_after_durable(completed.acknowledgments);
    let total=u16::try_from(offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD)).unwrap();
    let mut start=0u16;
    while start<total {
        let count=(total-start).min(mutiny_transport_v2::objects::MAX_BITMAP_BITS);
        let ack=peers.send.with_current(|link|link.acknowledged(&offer.id,start,count)).unwrap().unwrap();
        assert!(ack.bits.into_iter().all(|bit|bit));start=start.checked_add(count).unwrap();
    }
    let sender_before=canonical_rows(&root_a.join("send-objects.sqlite"));
    let receiver_before=canonical_rows(&root_a.join("recv-objects.sqlite"));
    let pool_before=canonical_rows(&root_b.join("foreign-a2.sqlite"));
    let chain_a_before=canonical_rows(&root_a.join("canonical.sqlite"));
    let chain_b_before=canonical_rows(&root_b.join("canonical.sqlite"));
    let mut relay=Relay::new(peers.send.peer_id()).unwrap();
    for _ in 0..2 {
        assert_eq!(relay.prepare_peer(&runtime_a,&foreign_pool,&context_a,&mut peers.send).unwrap_err(),
            "A2 retention canonical network changed");
        assert_eq!(canonical_rows(&root_a.join("send-objects.sqlite")),sender_before);
        assert_eq!(canonical_rows(&root_a.join("recv-objects.sqlite")),receiver_before);
        assert_eq!(canonical_rows(&root_b.join("foreign-a2.sqlite")),pool_before);
        assert_eq!(canonical_rows(&root_a.join("canonical.sqlite")),chain_a_before);
        assert_eq!(canonical_rows(&root_b.join("canonical.sqlite")),chain_b_before);
        assert_eq!(peers.send.with_current(|link|link.completed(&offer.id)).unwrap().unwrap().1,raw);
        assert_eq!(peers.recv.with_current(|link|link.completed(&offer.id)).unwrap().unwrap().1,raw);
        assert_eq!(foreign_pool.pending(&runtime_b,&context_b).unwrap(),Some(raw.clone()));
        assert_eq!(runtime_a.head().unwrap(),parent_a);assert_eq!(runtime_b.head().unwrap(),parent_b);
    }
}
