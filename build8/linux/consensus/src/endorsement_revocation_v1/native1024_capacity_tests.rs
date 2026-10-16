//! Fixed private TEST maximum-parent carrier. Enrollment activation is modeled;
//! hybrid signatures, normal codecs/execution, canonical SQLite and TCP are real.
//! No production/physical qualification or configured ceiling attainment claim.
use super::*;
use super::canonical_chain_tests::{anchor,certified_next,certified_minimal,directory,install_incremental,database_rows,prepare_body};
use super::super::foundation_tests::{maximum_material_at,Material};
use super::super::super::{test_value_x509,software_tpm,TestTpm};
use crate::{freshness::AttestationRefresh,participation::ParticipationAck};
use std::time::Instant;

fn ordinal(host:&ModelHost,materials:&[Material],node:Hash)->usize {
    if node==host.fixture.node {0}else{
        materials.iter().position(|m|m.join.binding.admission.node==node).unwrap()+1
    }
}
fn genesis_tpm(host:&ModelHost)->TestTpm {
    TestTpm::with_identity("a2-native16-capacity-original-EK")
        .strip(software_tpm::Strip::ConsistentProvenance(host.fixture.pki.root_hash()))
}
fn lifecycle(host:&ModelHost,prefix:&VerifiedPrefix,materials:&[Material],height:u64)->Vec<Vec<u8>> {
    let parent=anchor(host,prefix);let original=genesis_tpm(host);let mut operations=Vec::new();
    for member in prefix.state.continuity.as_ref().unwrap().members.iter().filter(|m|m.physical&&m.eligible) {
        let index=ordinal(host,materials,member.node);
        let tpm=if index==0 {&original}else{&materials[index-1].tpm};
        assert_eq!(tpm.voting_point(),member.voting_key);
        // Bounded staggered genuine refreshes, preserving the native60-height
        // freshness rule. At most22 enrolled identities share any one bucket.
        if height%48==u64::try_from(index%48).unwrap() {
            let mut refresh=AttestationRefresh {network:parent.network,genesis:parent.genesis,
                fingerprint:parent.fingerprint,node:member.node,generation:member.generation,
                height,parent_anchor:parent.id(),evidence:Vec::new()};
            refresh.evidence=tpm.quote(refresh.challenge());operations.push(refresh.encode().unwrap());
        }
        // Real Genesis participation makes economical old quorum selection
        // possible. Other members earn unchanged completed-period age a.
        if index==0 {
            let mut ack=ParticipationAck {network:parent.network,genesis:parent.genesis,
                fingerprint:parent.fingerprint,node:member.node,height,parent:parent.id(),
                generation:member.generation,signature:[0;64]};
            ack.signature=tpm.possession(ack.signing_digest());operations.push(ack.encode());
        }
    }
    operations
}

#[test]
fn genuine_maximum_parent_1024_crypto_carrier_tcp_finality_index_export_reopen() {
    let measured=Instant::now();let (host,evidence)=ModelHost::maximum_capacity();
    let base=directory();let path=base.join("canonical.sqlite");
    let mut chain=CanonicalStore::open_trusted_genesis(&path,&host.fixture.parent,&host.fixture.state,
        host.fixture.root,test_value_x509::T_REF,[255;32]).unwrap();
    let mut rows=Vec::new();let mut materials=Vec::new();let mut prefix=VerifiedPrefix::verify(&host,&rows).unwrap();
    let mut joins=0u16;let mut largest_join=0usize;let mut aggregate=0usize;
    assert_eq!(ModelHost::elapsed_at(121,false),121);
    assert_eq!(host.timestamp_at(1081),test_value_x509::T_REF+64_860);
    assert_eq!(crate::pow::target_after_height(60,[255;32],test_value_x509::T_REF,
        host.timestamp_at(60)).unwrap(),[255;32]);
    for height in 1..=1080 {
        let mut operations=lifecycle(&host,&prefix,&materials,height);
        // Three early double-join blocks complete1023 admissions by1020.
        // Each complete body still passes native ordinary/A2 projection limits.
        let count=if height<=3 {2}else if height<=1020 {1}else{0};
        for _ in 0..count {
            joins=joins.checked_add(1).unwrap();
            let reference=crate::execution_v2::admission_parent_time(&prefix.parent).unwrap();
            let material=maximum_material_at(&host,joins,&anchor(&host,&prefix),reference);
            largest_join=largest_join.max(material.outer.len());operations.push(material.outer.clone());materials.push(material);
        }
        let capacity=crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(&prefix.state,anchor(&host,&prefix),prefix.root).unwrap();
        capacity.preflight_lists(&[],&operations).unwrap();
        let raw=certified_minimal(&host,&prefix,operations,&materials);
        aggregate=aggregate.checked_add(raw.len()).unwrap();assert!(aggregate<=MAX_PREFIX_RAW_BYTES);
        prefix=install_incremental(&host,&mut chain,&mut rows,prefix,raw);
        assert_eq!(prefix.parent.target,[255;32],"maximum TEST cadence changed native PoW target");
        assert_eq!(crate::execution_v2::admission_parent_time(&prefix.parent).unwrap(),host.timestamp_at(height));
        if height%60==0 || height==1020 {
            println!("PUBLIC-A2-MAXIMUM-STAGE height={height} canonical_joins={joins} retained_bytes={aggregate} largest_join_bytes={largest_join} elapsed_ms={} enrollment_activation=MODELED",measured.elapsed().as_millis());
        }
    }
    assert_eq!(joins,1023);assert_eq!(materials.len(),1023);
    let authority=HeightAuthority::from_state(&prefix.state,anchor(&host,&prefix),prefix.root).unwrap();
    assert_eq!(authority.voters.values().filter(|v|!v.weight().unwrap().is_zero()).count(),1024);
    let operation=crate::endorsement_revocation_v1::Operation {
        context:crate::endorsement_revocation_v1::Context {genesis:prefix.parent.genesis,
            fingerprint:prefix.parent.fingerprint,parent_height:1080,parent_block:prefix.parent.block,
            parent_state:prefix.root,height:1081,timestamp:host.timestamp_at(1081)},
        target:crate::endorsement_revocation_v1::Target {class:crate::endorsement_revocation_v1::TargetClass::Ek,
            scope:crate::endorsement_revocation_v1::TargetScope::Certificate,
            identity:test_value_x509::sha256(&host.fixture.chain[0])},evidence};
    let op=operation.encode().unwrap();assert!(op.len()>150_000);
    let parent=anchor(&host,&prefix);
    let capacity=crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(&prefix.state,parent.clone(),prefix.root).unwrap();
    let (_,mut body,_)=prepare_body(&host,&prefix,vec![op.clone()]).unwrap();
    let original=genesis_tpm(&host);let mut refused_next=false;
    // Fill only with genuine current-parent acknowledgments. No arbitrary
    // padding or duplicate operation supplies largest-body acceptance credit.
    for member in prefix.state.continuity.as_ref().unwrap().members.iter().filter(|m|m.physical&&m.eligible) {
        let index=ordinal(&host,&materials,member.node);
        let tpm=if index==0 {&original}else{&materials[index-1].tpm};
        let mut ack=ParticipationAck {network:parent.network,genesis:parent.genesis,
            fingerprint:parent.fingerprint,node:member.node,height:1081,parent:parent.id(),
            generation:member.generation,signature:[0;64]};
        ack.signature=tpm.possession(ack.signing_digest());
        let mut trial=body.clone();trial.operations.push(ack.encode());trial.normalize_participation().unwrap();
        if capacity.root(&trial).is_err(){refused_next=true;break;}body=trial;
    }
    assert!(refused_next,"fixture did not exhaust actual ordinary projection with genuine ACKs");
    let raw=certified_next(&host,&prefix,body.operations.clone(),&materials);
    let block=BlockEnvelope::decode_with_capacity(&raw,&capacity).unwrap();assert_eq!(block.certificate.votes.len(),1024);
    aggregate=aggregate.checked_add(raw.len()).unwrap();assert!(aggregate<=MAX_PREFIX_RAW_BYTES);
    println!("PUBLIC-A2-MAXIMUM-OBJECT operation_bytes={} body_bytes={} certificate_bytes={} envelope_bytes={} retained_prefix_bytes={} actual_parent_signers=1024 configured_ceiling_NOT_ATTAINED",
        op.len(),capacity.encode(&block.body).unwrap().len(),block.certificate.encode().unwrap().len(),raw.len(),aggregate);
    let before=database_rows(&path);
    let mut delivered=super::capacity_tests::deliver_count(&base,&parent,&raw,1024);
    assert_eq!(delivered.bytes,raw);assert_eq!(database_rows(&path),before);
    prefix=install_incremental(&host,&mut chain,&mut rows,prefix,delivered.bytes.clone());
    let (kind,id)=capacity.operation_id(&op).unwrap();assert_eq!(kind,25);
    {let _scope=prefix.replay().unwrap();
        let records=chain.verified_operation_records(id).unwrap();assert_eq!(records.len(),1);assert_eq!(records[0].kind,25);
        assert_eq!(records[0].height,1081);assert_eq!(records[0].position,0);
        assert_eq!(chain.certified_envelope_bytes(1081,prefix.parent.block).unwrap(),Some(raw.clone()));
    }
    // Publish all bitmap receipts only after matching native canonical commit.
    for receipt in delivered.receipts {
        delivered.rx.send_frame(&receipt,super::capacity_tests::deadline()).unwrap();
        assert!(matches!(delivered.send.receive(&delivered.tx.receive_frame(super::capacity_tests::deadline()).unwrap()).unwrap(),mutiny_transport_v2::object_link::Event::ReceiptRecorded));
    }
    drop(chain);
    VerifiedPrefix::with_reverified_store(&host,&path,&rows,|reopened| {
        let (tip,state)=reopened.load().unwrap();assert_eq!(tip.height,1081);
        assert_eq!(state.records().unwrap(),prefix.state.records().unwrap());
        assert_eq!(reopened.verified_operation_records(id).unwrap().len(),1);
        assert_eq!(reopened.certified_envelope_bytes(1081,tip.block).unwrap(),Some(raw.clone()));
    }).unwrap();
    println!("PUBLIC-A2-MAXIMUM-CLOSED elapsed_ms={} enrollment_activation=MODELED canonical_joins=1023 actual_parent_signers=1024",measured.elapsed().as_millis());
}
