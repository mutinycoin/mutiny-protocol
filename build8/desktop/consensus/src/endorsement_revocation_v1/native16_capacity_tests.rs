//! Incremental large-carrier control: sixteen cryptographic parent signers.
//! Enrollment activation is the bounded private model; not physical qualification,
//! a 1,024-voter maximum, or the standalone Node Runtime application route.
use super::*;
use super::canonical_chain_tests::{anchor,certified_next,directory,install_incremental,database_rows};
use super::super::foundation_tests::genuine_material_at;
use super::super::super::test_value_x509;
use mutiny_crypto_v2::{HybridKey,Role};
use mutiny_transport_v2::{Context,Endpoint,tcp::Carrier,
    object_link::{ObjectLink,Event},objects::{ObjectKind,ObjectQueue,MAX_BITMAP_BITS}};
use std::{net::{TcpListener,TcpStream},path::Path,time::{Duration,Instant}};
pub(super) fn deadline()->Instant {Instant::now()+Duration::from_secs(5)}

pub(super) struct Delivered {
    pub(super) send:ObjectLink,pub(super) recv:ObjectLink,pub(super) tx:Carrier,pub(super) rx:Carrier,
    pub(super) offer:mutiny_transport_v2::objects::Offer,pub(super) receipts:Vec<Vec<u8>>,pub(super) bytes:Vec<u8>,
}
fn deliver(root:&Path,parent:&FinalizedAnchor,raw:&[u8])->Delivered {deliver_count(root,parent,raw,16)}
pub(super) fn deliver_count(root:&Path,parent:&FinalizedAnchor,raw:&[u8],signers:usize)->Delivered {
    assert!(signers==16||signers==1024);
    let a=HybridKey::generate(Role::Transport).unwrap();
    let b=HybridKey::generate(Role::Transport).unwrap();
    let context=Context::pinned(parent.genesis,parent.fingerprint,
        Endpoint::pinned(a.public().clone(),1).unwrap(),
        Endpoint::pinned(b.public().clone(),1).unwrap()).unwrap();
    let listener=TcpListener::bind("127.0.0.1:0").unwrap();
    let client=TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let socket=listener.accept().unwrap().0;drop(listener);
    let other=context.clone();
    let responder=std::thread::spawn(move||Carrier::respond(socket,other,&b,Duration::from_secs(30)).unwrap());
    let (mut tx,session)=Carrier::initiate(client,context,&a,Duration::from_secs(30)).unwrap();
    let (mut rx,remote)=responder.join().unwrap();
    let peer=session.peer_id();let remote_peer=remote.peer_id();
    let mut send=ObjectLink::new(session,
        ObjectQueue::open_a2(&root.join("capacity-send.sqlite"),peer,true).unwrap()).unwrap();
    let mut recv=ObjectLink::new(remote,
        ObjectQueue::open_a2(&root.join("capacity-recv.sqlite"),remote_peer,true).unwrap()).unwrap();
    let (offer,have)=send.enqueue(ObjectKind::CertifiedBlock,raw,0).unwrap();
    let measured=Instant::now();
    tx.send_frame(&have,deadline()).unwrap();
    assert!(matches!(recv.receive(&rx.receive_frame(deadline()).unwrap()).unwrap(),Event::Offered(ref got) if got==&offer));
    let total=u16::try_from(offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD)).unwrap();
    let mut start=0u16;let mut receipts=Vec::new();
    while start<total {
        let request=recv.next_missing_request(&offer.id,0,false).unwrap().unwrap();
        assert_eq!(request.start,start);assert_eq!(request.count,(total-start).min(MAX_BITMAP_BITS));
        rx.send_frame(&request.frame,deadline()).unwrap();
        assert!(matches!(send.receive(&tx.receive_frame(deadline()).unwrap()).unwrap(),Event::Requested));
        for n in 0..request.count {
            let frame=send.send_one().unwrap().unwrap();
            tx.send_frame(&frame,deadline()).unwrap();
            let event=recv.receive(&rx.receive_frame(deadline()).unwrap()).unwrap();
            if start+n+1==total {
                assert!(matches!(event,Event::Completed {offer:ref got,ref bytes} if got==&offer && bytes==raw));
            }else{assert!(matches!(event,Event::FragmentReceived));}
        }
        receipts.push(recv.receipt(&offer.id,start,request.count,0).unwrap());
        start=start.checked_add(request.count).unwrap();
    }
    let (actual,bytes)=recv.completed(&offer.id).unwrap();assert_eq!(actual,offer);
    assert_eq!(bytes,raw);assert_eq!(receipts.len(),usize::from(total).div_ceil(usize::from(MAX_BITMAP_BITS)));
    let marker=if signers==16 {"PUBLIC-A2-NATIVE16-CAPACITY"}else{"PUBLIC-A2-MAXIMUM-CAPACITY"};
    println!("{marker} complete_envelope_bytes={} fragments={} bitmap_windows={} elapsed_ms={} per_frame_deadline_seconds=5 handshake_deadline_seconds=30 enrolled_activation=MODELED parent_crypto_signers={} configured_ceiling_NOT_ATTAINED",
        raw.len(),total,receipts.len(),measured.elapsed().as_millis(),signers);
    Delivered {send,recv,tx,rx,offer,receipts,bytes}
}

#[test]
fn genuine_sixteen_parent_signatures_large_crl_carrier_tcp_finality_index_export_reopen() {
    let (host,evidence)=ModelHost::genuine_capacity();
    let base=directory();let path=base.join("canonical.sqlite");
    let mut chain=CanonicalStore::open_trusted_genesis(&path,&host.fixture.parent,&host.fixture.state,
        host.fixture.root,test_value_x509::T_REF,[255;32]).unwrap();
    let mut rows=Vec::new();let mut materials=Vec::new();
    let mut prefix=VerifiedPrefix::verify(&host,&rows).unwrap();
    for height in 1..=120 {
        let operations=if height<=15 {
            let m=genuine_material_at(&host,height as u8,&anchor(&host,&prefix),prefix.parent.t0+prefix.parent.height);
            let raw=m.outer.clone();materials.push(m);vec![raw]
        }else{super::canonical_chain_tests::lifecycle(&host,&prefix,&materials,height)};
        let raw=certified_next(&host,&prefix,operations,&materials);
        prefix=install_incremental(&host,&mut chain,&mut rows,prefix,raw);
    }
    let authority=HeightAuthority::from_state(&prefix.state,anchor(&host,&prefix),prefix.root).unwrap();
    assert_eq!(authority.voters.values().filter(|v|!v.weight().unwrap().is_zero()).count(),16);
    let operation=crate::endorsement_revocation_v1::Operation {
        context:crate::endorsement_revocation_v1::Context {
            genesis:prefix.parent.genesis,fingerprint:prefix.parent.fingerprint,
            parent_height:120,parent_block:prefix.parent.block,parent_state:prefix.root,
            height:121,timestamp:test_value_x509::T_REF+121},
        target:crate::endorsement_revocation_v1::Target {
            class:crate::endorsement_revocation_v1::TargetClass::Ek,
            scope:crate::endorsement_revocation_v1::TargetScope::Certificate,
            identity:test_value_x509::sha256(&host.fixture.chain[0])},evidence};
    let op=operation.encode().unwrap();assert!(op.len()>150_000);
    let raw=certified_next(&host,&prefix,vec![op.clone()],&materials);
    let capacity=crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(
        &prefix.state,anchor(&host,&prefix),prefix.root).unwrap();
    let block=BlockEnvelope::decode_with_capacity(&raw,&capacity).unwrap();
    assert_eq!(block.certificate.votes.len(),16);
    let before=database_rows(&path);
    let mut delivered=deliver(&base,&anchor(&host,&prefix),&raw);
    assert_eq!(delivered.bytes,raw);
    // Opaque reassembly supplies no consensus authority or receipt publication.
    assert!(database_rows(&path)==before);
    prefix=install_incremental(&host,&mut chain,&mut rows,prefix,delivered.bytes.clone());
    let (kind,id)=capacity.operation_id(&op).unwrap();assert_eq!(kind,25);
    {let _scope=prefix.replay().unwrap();
        let records=chain.verified_operation_records(id).unwrap();
        assert_eq!(records.len(),1);assert_eq!(records[0].kind,25);
        assert_eq!(records[0].height,121);assert_eq!(records[0].position,0);
        assert_eq!(chain.certified_envelope_bytes(121,prefix.parent.block).unwrap(),Some(raw.clone()));
    }
    assert_eq!(prefix.state.continuity.as_ref().unwrap().weights().unwrap()
        .iter().filter(|w|!w.is_zero()).count(),15);
    assert!(!prefix.state.endorsement_revocations_v1.terminal_no_quorum());
    // Every bitmap receipt is published only after matching canonical commit.
    for receipt in delivered.receipts {
        delivered.rx.send_frame(&receipt,deadline()).unwrap();
        assert!(matches!(delivered.send.receive(&delivered.tx.receive_frame(deadline()).unwrap()).unwrap(),Event::ReceiptRecorded));
    }
    assert_eq!(delivered.recv.completed(&delivered.offer.id).unwrap().1,raw);
    drop(chain);
    VerifiedPrefix::with_reverified_store(&host,&path,&rows,|reopened| {
        let (tip,state)=reopened.load().unwrap();assert_eq!(tip.height,121);
        assert_eq!(state.records().unwrap(),prefix.state.records().unwrap());
        assert_eq!(reopened.verified_operation_records(id).unwrap().len(),1);
        assert_eq!(reopened.certified_envelope_bytes(121,tip.block).unwrap(),Some(raw.clone()));
    }).unwrap();
}
