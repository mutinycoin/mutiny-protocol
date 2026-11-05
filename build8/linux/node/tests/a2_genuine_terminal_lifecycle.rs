//! SOURCE ONLY / UNRUN. Genuine signed software PKI and real native authority;
//! physical TPM activation and production eligibility are not tested here.
#[path="support/a2_native/mod.rs"]
mod support;
use support::{fixture::{self,Fixture,T_REF,exact_index,private_root,sha},peer::Pair};
use mutinyd_v8::{a2_operation_pool_v1::{Pool,Context},a2_operation_relay_v1::Relay,
    candidate_journal_v3::Journal as Candidates,hybrid_a2_dispatch_v1,
    hybrid_proposal_dispatch_v3,hybrid_dispatch_v2,hybrid_runtime_v2::{WorkRequest,RuntimeError}};
use mutiny_consensus_v8::{anchors::FinalizedAnchor,endorsement_revocation_v1::{Operation,Evidence},
    finality_v2::StoreError};
use mutiny_transport_v2::{objects::{ObjectKind,MAX_BITMAP_BITS,object_id},MAX_PAYLOAD};
use std::{path::{Path,PathBuf},time::Instant};

fn leaf(root:&Path,name:&str)->PathBuf {
    let p=root.join(name);assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&p).unwrap());p
}
fn context<'a>(f:&Fixture,parent:&'a FinalizedAnchor)->Context<'a> {
    Context {parent,license:f.license,worker:f.worker,timestamp:T_REF+60,ticket:1}
}
// Exact public table contents, including identity, state, undo, evidence, IDX,
// pending and candidate rows. Complete transport insertion occurs before this
// snapshot; semantic refusal must not delete or change that retained object.
fn rows(path:&Path)->Vec<(String,Vec<String>)> {
    let db=rusqlite::Connection::open_with_flags(path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let _snapshot=db.unchecked_transaction().unwrap();
    let mut names=db.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name").unwrap();
    let names=names.query_map([],|r|r.get::<_,String>(0)).unwrap().collect::<Result<Vec<_>,_>>().unwrap();
    names.into_iter().map(|name|{
        let quoted=name.replace('"',"\"\"");let mut q=db.prepare(&format!("SELECT * FROM \"{quoted}\"")).unwrap();let count=q.column_count();
        let mut values=q.query_map([],|r|{
            let columns=(0..count).map(|i|r.get::<_,rusqlite::types::Value>(i)).collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(format!("{columns:?}"))
        }).unwrap().collect::<Result<Vec<_>,_>>().unwrap();values.sort();(name,values)
    }).collect()
}
fn snapshot(base:&Path,queue:&Path)->Vec<Vec<(String,Vec<String>)>> {
    [base.join("canonical.sqlite"),base.join("a2.sqlite"),base.join("proposals.sqlite"),
        queue.join("send-objects.sqlite"),queue.join("recv-objects.sqlite")].iter().map(|p|rows(p)).collect()
}
fn measured(phase:&str,raw:&[u8],elapsed:std::time::Duration,acks:usize) {
    let fragments=raw.len().div_ceil(MAX_PAYLOAD);let windows=fragments.div_ceil(MAX_BITMAP_BITS as usize);
    assert_eq!(acks,windows);
    eprintln!("PUBLIC A2 genuine phase={phase} bytes={} fragments={fragments} windows={windows} elapsed_ms={} per_frame_deadline_seconds=5 handshake_deadline_seconds=30",
        raw.len(),elapsed.as_millis());
    // Observed elapsed is not production latency or a new overall deadline.
}
fn terminal_readable_and_unsigned_refused(f:&Fixture,runtime:&mut fixture::HybridRuntime,raw:&[u8],
    envelope:&mutiny_consensus_v8::block_envelope_v2::BlockEnvelope,base:&Path) {
    exact_index(runtime,raw,envelope);let parent=runtime.head().unwrap();assert_eq!(parent.height,1);
    let (_,state)=runtime.chain.load().unwrap();assert!(state.endorsement_revocations_v1.terminal_no_quorum());
    assert!(!runtime.chain.halted().unwrap(),"terminal eligibility is not integrity conflict");
    let before=rows(&base.join("canonical.sqlite"));
    let refused=runtime.prepare(WorkRequest {expected_parent:&parent,license:f.license,worker:f.worker,
        timestamp:T_REF+61,ticket:2,operations:&[]});
    assert!(matches!(refused,Err(RuntimeError::Chain(StoreError::Assembly(ref why))) if why.contains("NoQuorum")),
        "terminal must refuse for actual NoQuorum, not unrelated setup failure");
    assert_eq!(rows(&base.join("canonical.sqlite")),before);exact_index(runtime,raw,envelope);
    // No next block is constructed or certified after terminal NoQuorum.
}

#[test]
fn a2_genuine_terminal_mult_window_relay_proposal_certified_wire_and_reopen() {
    let f=Fixture::load_genuine_terminal();let raw=f.genuine_terminal_operation();
    let base=private_root("genuine-terminal-wire");let sender=leaf(&base,"sender");let receiver=leaf(&base,"receiver");
    let queue=leaf(&base,"loopback");let mut source=f.runtime(&sender);let mut runtime=f.runtime(&receiver);
    let parent=runtime.head().unwrap();assert_eq!(source.head().unwrap(),parent);let ctx=context(&f,&parent);
    let mut local=Pool::open(&source,&sender.join("a2.sqlite"),true).unwrap();
    let mut ingress=Pool::open(&runtime,&receiver.join("a2.sqlite"),true).unwrap();
    let mut journal=Candidates::open(&runtime,&receiver.join("proposals.sqlite"),2*1024*1024,true).unwrap();
    let mut peers=Pair::open(&f,&queue,true);let mut relay=Relay::new(peers.send.peer_id()).unwrap();
    local.submit(&source,&ctx,&raw).unwrap();
    let (offer,have)=relay.prepare_peer(&source,&local,&ctx,&mut peers.send).unwrap().unwrap();
    assert_eq!(offer.length,raw.len());assert!(offer.length>MAX_PAYLOAD*MAX_BITMAP_BITS as usize);
    let start=Instant::now();let complete=peers.deliver_advertised(offer,&have);
    measured("kind13",&raw,start.elapsed(),complete.acknowledgments.len());assert_eq!(complete.acknowledgments.len(),2);
    assert!(matches!(hybrid_a2_dispatch_v1::dispatch_peer(&runtime,&mut ingress,&ctx,&mut peers.recv,complete.event).unwrap(),
        hybrid_a2_dispatch_v1::Outcome::Accepted{digest,..} if digest==sha(&raw)));
    assert_eq!(ingress.pending(&runtime,&ctx).unwrap(),Some(raw.clone()));
    peers.publish_after_durable(complete.acknowledgments);
    assert!(relay.prepare_peer(&source,&local,&ctx,&mut peers.send).unwrap().is_none());
    let record=f.candidate(&mut source,&raw,T_REF+60,1);let envelope=f.certify(&source,&record);
    let proposal=record.encode(&source).unwrap();let start=Instant::now();let complete=peers.deliver(ObjectKind::A2BlockProposal,&proposal);
    measured("kind12",&proposal,start.elapsed(),complete.acknowledgments.len());
    assert!(matches!(hybrid_proposal_dispatch_v3::dispatch_peer(&runtime,&mut journal,&mut peers.recv,complete.event).unwrap(),
        hybrid_proposal_dispatch_v3::Outcome::Retained{block,..} if block==record.header.block_hash()));
    peers.publish_after_durable(complete.acknowledgments);
    assert_eq!(journal.next_current(&runtime,None).unwrap(),Some(record.clone()));
    assert_eq!(runtime.head().unwrap(),parent,"uncertified retention creates no finality");
    drop(peers);drop(journal);drop(ingress);drop(runtime);
    let mut runtime=f.runtime(&receiver);let mut ingress=Pool::open(&runtime,&receiver.join("a2.sqlite"),false).unwrap();
    let journal=Candidates::open(&runtime,&receiver.join("proposals.sqlite"),2*1024*1024,false).unwrap();
    assert_eq!(ingress.pending(&runtime,&ctx).unwrap(),Some(raw.clone()));
    assert_eq!(journal.next_current(&runtime,None).unwrap(),Some(record));
    let mut peers=Pair::open(&f,&queue,false);let capacity=source.chain.proposal_body_capacity(&envelope.header).unwrap();
    let certified=envelope.encode_with_capacity(&capacity).unwrap();let start=Instant::now();let complete=peers.deliver(ObjectKind::CertifiedBlock,&certified);
    measured("kind3",&certified,start.elapsed(),complete.acknowledgments.len());let offer=complete.offer.clone();
    assert!(matches!(hybrid_dispatch_v2::dispatch_peer(&mut runtime,&mut peers.recv,complete.event).unwrap(),
        hybrid_dispatch_v2::DispatchEvent::BlockInstalled{result,..} if result.inserted && result.finalized.height==1));
    assert_eq!(peers.recv.with_current(|l|l.completed(&offer.id)).unwrap().unwrap().1,certified);
    // Generic certified dispatch retains the exact wire object; no unsupported
    // automatic transport pruning is asserted. ACK follows native commit only.
    peers.publish_after_durable(complete.acknowledgments);assert!(ingress.reconcile_finalized(&runtime).unwrap());
    terminal_readable_and_unsigned_refused(&f,&mut runtime,&raw,&envelope,&receiver);
    drop(peers);drop(journal);drop(ingress);drop(runtime);let mut runtime=f.runtime(&receiver);
    let ingress=Pool::open(&runtime,&receiver.join("a2.sqlite"),false).unwrap();
    let journal=Candidates::open(&runtime,&receiver.join("proposals.sqlite"),2*1024*1024,false).unwrap();
    assert!(journal.next_current(&runtime,None).unwrap().is_none());
    assert!(ingress.pending(&runtime,&context(&f,&runtime.head().unwrap())).unwrap().is_none());
    let mut peers=Pair::open(&f,&queue,false);
    assert_eq!(peers.recv.with_current(|l|l.completed(&offer.id)).unwrap().unwrap().1,certified);
    terminal_readable_and_unsigned_refused(&f,&mut runtime,&raw,&envelope,&receiver);
}

#[test]
fn a2_genuine_terminal_bad_crl_and_both_certificate_halves_are_atomic_and_retained() {
    let f=Fixture::load_genuine_terminal();let raw=f.genuine_terminal_operation();
    let base=private_root("genuine-terminal-refusals");let mut runtime=f.runtime(&base);let parent=runtime.head().unwrap();let ctx=context(&f,&parent);
    let mut pool=Pool::open(&runtime,&base.join("a2.sqlite"),true).unwrap();
    let journal=Candidates::open(&runtime,&base.join("proposals.sqlite"),2*1024*1024,true).unwrap();
    let mut bad=Operation::decode(&raw).unwrap();
    let Evidence::Crl{crls,..}=&mut bad.evidence else {panic!("genuine CRL fixture required")};
    *crls[0].last_mut().unwrap()^=1;let bad=bad.encode().unwrap();assert_ne!(bad,raw);
    let queue=leaf(&base,"bad-crl");let mut peers=Pair::open(&f,&queue,true);let complete=peers.deliver(ObjectKind::A2EvidenceOperation,&bad);let id=complete.offer.id;
    let before=snapshot(&base,&queue);
    assert!(hybrid_a2_dispatch_v1::dispatch_peer(&runtime,&mut pool,&ctx,&mut peers.recv,complete.event).is_err());
    assert_eq!(snapshot(&base,&queue),before);assert_eq!(peers.recv.with_current(|l|l.completed(&id)).unwrap().unwrap().1,bad);
    assert!(pool.pending(&runtime,&ctx).unwrap().is_none());drop(peers);
    let mut peers=Pair::open(&f,&queue,false);assert_eq!(peers.recv.with_current(|l|l.completed(&id)).unwrap().unwrap().1,bad);drop(peers);
    let record=f.candidate(&mut runtime,&raw,T_REF+60,1);let envelope=f.certify(&runtime,&record);
    // Genuine valid certificate with a real competing SQLite writer. This is
    // transaction refusal/atomicity, not a schema failure or simulated disk I/O.
    let queue=leaf(&base,"held-canonical-writer");let mut peers=Pair::open(&f,&queue,true);
    let capacity=runtime.chain.proposal_body_capacity(&envelope.header).unwrap();
    let certified=envelope.encode_with_capacity(&capacity).unwrap();
    let complete=peers.deliver(ObjectKind::CertifiedBlock,&certified);let held_id=complete.offer.id;
    let mut writer=rusqlite::Connection::open(base.join("canonical.sqlite")).unwrap();
    let hold=writer.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate).unwrap();
    let before=snapshot(&base,&queue);
    let refused=hybrid_dispatch_v2::dispatch_peer(&mut runtime,&mut peers.recv,complete.event);
    assert!(matches!(refused,Err(hybrid_dispatch_v2::DispatchError::Runtime(RuntimeError::Chain(
        StoreError::Storage(rusqlite::Error::SqliteFailure(ref error,_))))) if error.code==rusqlite::ErrorCode::DatabaseBusy),
        "valid carrier must reach actual competing-writer SQLite BUSY refusal");
    assert_eq!(snapshot(&base,&queue),before);assert_eq!(runtime.head().unwrap(),parent);
    assert_eq!(peers.recv.with_current(|l|l.completed(&held_id)).unwrap().unwrap().1,certified);
    drop(hold);drop(writer);drop(peers);
    let mut peers=Pair::open(&f,&queue,false);
    assert_eq!(peers.recv.with_current(|l|l.completed(&held_id)).unwrap().unwrap().1,certified);drop(peers);
    for half in ["ed448","fndsa"] {
        let mut changed=envelope.clone();if half=="ed448" {changed.certificate.votes[0].signature.ed448[0]^=1;}
        else {changed.certificate.votes[0].signature.fndsa[0]^=1;}
        assert_eq!(changed.header,envelope.header);assert_eq!(changed.body,envelope.body);
        let capacity=runtime.chain.proposal_body_capacity(&changed.header).unwrap();let bad=changed.encode_with_capacity(&capacity).unwrap();
        let queue=leaf(&base,&format!("bad-certificate-{half}"));let mut peers=Pair::open(&f,&queue,true);
        let complete=peers.deliver(ObjectKind::CertifiedBlock,&bad);let id=complete.offer.id;let before=snapshot(&base,&queue);
        assert!(hybrid_dispatch_v2::dispatch_peer(&mut runtime,&mut peers.recv,complete.event).is_err());
        assert_eq!(snapshot(&base,&queue),before);assert_eq!(runtime.head().unwrap(),parent);
        assert_eq!(peers.recv.with_current(|l|l.completed(&id)).unwrap().unwrap().1,bad);drop(peers);
        let mut peers=Pair::open(&f,&queue,false);assert_eq!(peers.recv.with_current(|l|l.completed(&id)).unwrap().unwrap().1,bad);
    }
    assert!(journal.next_current(&runtime,None).unwrap().is_none());
    assert!(runtime.chain.verified_operation_records(Operation::decode(&raw).unwrap().id().unwrap()).unwrap().is_empty());
}

#[test]
fn a2_genuine_terminal_pool_handoff_child() {
    let Some(path)=std::env::var_os("BUILD8_A2_GENUINE_HANDOFF_CHILD_PATH") else {return;};
    // Env-absent helper is zero qualification credit, with zero ignored tests.
    let root=PathBuf::from(path);assert!(root.is_absolute());assert!(!mutiny_consensus_v8::submission_pool_v1::private_directory(&root).unwrap());
    let f=Fixture::load_genuine_terminal();let raw=f.genuine_terminal_operation();let runtime=f.runtime(&root);let parent=runtime.head().unwrap();let ctx=context(&f,&parent);
    let mut pool=Pool::open(&runtime,&root.join("a2.sqlite"),false).unwrap();let mut peers=Pair::open(&f,&root,true);
    let start=Instant::now();let complete=peers.deliver(ObjectKind::A2EvidenceOperation,&raw);
    measured("kind13-child",&raw,start.elapsed(),complete.acknowledgments.len());
    pool.submit(&runtime,&ctx,&raw).unwrap();assert_eq!(pool.pending(&runtime,&ctx).unwrap(),Some(raw));
    // Natural abrupt process exit after full native durable insertion, before
    // transport deletion/ACK. It simulates this process boundary, not power loss.
    std::process::exit(94);
}

#[test]
fn a2_genuine_terminal_abrupt_handoff_finalized_retry_and_terminal_reopen() {
    let f=Fixture::load_genuine_terminal();let raw=f.genuine_terminal_operation();let base=private_root("genuine-terminal-handoff");
    let runtime=f.runtime(&base);let pool=Pool::open(&runtime,&base.join("a2.sqlite"),true).unwrap();drop(pool);drop(runtime);
    fixture::capture_handoff_child(&base,"a2_genuine_terminal_pool_handoff_child","BUILD8_A2_GENUINE_HANDOFF_CHILD_PATH",94,"genuine-child");
    let mut runtime=f.runtime(&base);let parent=runtime.head().unwrap();let ctx=context(&f,&parent);
    let mut pool=Pool::open(&runtime,&base.join("a2.sqlite"),false).unwrap();assert_eq!(pool.pending(&runtime,&ctx).unwrap(),Some(raw.clone()));
    let mut peers=Pair::open(&f,&base,false);let id=object_id(ObjectKind::A2EvidenceOperation,&raw).unwrap();
    let (offer,bytes)=peers.recv.with_current(|l|l.completed(&id)).unwrap().unwrap();assert_eq!(bytes,raw);
    let acks=peers.encode_all_receipts(&offer);assert_eq!(acks.len(),2);
    let record=f.candidate(&mut runtime,&raw,T_REF+60,1);let envelope=f.certify(&runtime,&record);
    let capacity=runtime.chain.proposal_body_capacity(&envelope.header).unwrap();let bytes=envelope.encode_with_capacity(&capacity).unwrap();
    let complete=peers.deliver(ObjectKind::CertifiedBlock,&bytes);
    assert!(matches!(hybrid_dispatch_v2::dispatch_peer(&mut runtime,&mut peers.recv,complete.event).unwrap(),
        hybrid_dispatch_v2::DispatchEvent::BlockInstalled{result,..} if result.inserted));
    peers.publish_after_durable(complete.acknowledgments);assert!(pool.reconcile_finalized(&runtime).unwrap());
    assert!(matches!(hybrid_a2_dispatch_v1::retry_completed(&runtime,&mut pool,&ctx,&mut peers.recv,&id).unwrap(),
        hybrid_a2_dispatch_v1::Outcome::Finalized{digest,..} if digest==sha(&raw)));
    assert!(peers.recv.with_current(|l|l.completed(&id)).unwrap().is_err());peers.publish_after_durable(acks);
    let mut relay=Relay::new(peers.send.peer_id()).unwrap();assert!(relay.prepare_peer(&runtime,&pool,&ctx,&mut peers.send).unwrap().is_none());
    assert!(peers.send.with_current(|l|l.completed(&id)).unwrap().is_err());
    terminal_readable_and_unsigned_refused(&f,&mut runtime,&raw,&envelope,&base);
    drop(peers);drop(pool);drop(runtime);let mut runtime=f.runtime(&base);
    terminal_readable_and_unsigned_refused(&f,&mut runtime,&raw,&envelope,&base);
}
