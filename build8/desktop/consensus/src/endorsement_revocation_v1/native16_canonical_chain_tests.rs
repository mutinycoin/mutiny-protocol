//! Private synthetic canonical chain; uncompiled successor of four foundations.
//! Native enrollment/earnings/certificates remain real checks; no physical claim.
use super::*;
use super::super::foundation_tests::{genuine_material_at,Material};
use super::super::super::{software_tpm,test_value_x509,TestTpm,zero};
use crate::{pow::WorkAuthority,participation::ParticipationAck,freshness::AttestationRefresh};

pub(super) fn anchor(host:&ModelHost,prefix:&VerifiedPrefix)->FinalizedAnchor {
    FinalizedAnchor {height:prefix.parent.height,block:prefix.parent.block,
        ..host.fixture.parent.clone()}
}

// Builder normalization only. The ordinary wire codec still rejects alternate
// ACK order, and native parent/freshness/signature checks remain mandatory.
fn canonical_builder_body(mut body:BlockBody,operations:Vec<Vec<u8>>) -> Result<BlockBody> {
    body.operations=operations;
    body.normalize_participation()?;
    Ok(body)
}

// Only a complete privately verified prefix supplies the parent/state. An
// ordinary lifecycle item gains no Join permission merely by being in this body.
pub(super) fn prepare_body(host:&ModelHost,prefix:&VerifiedPrefix,operations:Vec<Vec<u8>>)
    -> crate::execution::Result<(Candidate,BlockBody,ModelPrepared)> {
    let binding=host.fixture.state.licenses_v2.assignments().next().unwrap().enrollment.binding.clone();
    let height=prefix.parent.height+1;let timestamp=host.timestamp_at(height);
    let capacity=crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(
        &prefix.state,anchor(host,prefix),prefix.root)?;
    capacity.preflight_lists(&[],&operations)?;
    let positive=crate::assembler_v2::prepare_with_history(crate::assembler_v2::Request {
        parent:&prefix.parent,state:&prefix.state,pool:&super::tests::Empty,
        license:binding.license,worker:binding.worker_id,timestamp,ticket:height,
        operations:&[] },&prefix.history)
        .map_err(|_|crate::execution::ExecutionError::Codec(Error::WrongOperation))?;
    let body=canonical_builder_body(positive.body,operations)?;
    let mut candidate=positive.candidate;candidate.state_root=[0;32];
    candidate.body_root=capacity.root(&body)?;
    let mut projected=body.clone();projected.transactions.clear();projected.operations.clear();
    for raw in &body.operations {
        if !crate::trading_host_v1::operation(raw)? && crate::blocks::operation_kind(raw)?==15 {
            projected.operations.push(raw.clone());
        }
    }
    let joins=if projected.operations.is_empty(){Vec::new()}else{
        host.verify_pins(&prefix.state,&prefix.parent,&projected)?};
    if prefix.admitted_joins.checked_add(joins.len()).is_none_or(|n|n>host.max_joins()) {
        return Err(Error::Capacity.into());
    }
    let pin=Rc::new(PreparationPin {parent:ParentPin::capture(&prefix.parent),root:prefix.root,
        candidate:candidate.clone(),ticket:height,body:capacity.encode(&body)?,joins});
    let result={let _p=Lease::install(Mode::Prepare(pin.clone()))?;
        prefix.state.prepare_candidate_with_history_v2(CandidatePreparation {
            parent:&prefix.parent,candidate:&candidate,ticket_sequence:height,body:&body},&prefix.history)?};
    let prepared=ModelPrepared {pin,computed_root:result.root,records:result.state.records()?};
    Ok((candidate,body,prepared))
}

pub(super) fn certified_next(host:&ModelHost,prefix:&VerifiedPrefix,operations:Vec<Vec<u8>>,
    materials:&[Material])->Vec<u8> {
    certified_with_signers(host,prefix,operations,materials,false)
}
pub(super) fn certified_minimal(host:&ModelHost,prefix:&VerifiedPrefix,operations:Vec<Vec<u8>>,
    materials:&[Material])->Vec<u8> {
    assert!(host.maximum_profile);
    certified_with_signers(host,prefix,operations,materials,true)
}
fn certified_with_signers(host:&ModelHost,prefix:&VerifiedPrefix,operations:Vec<Vec<u8>>,
    materials:&[Material],minimal:bool)->Vec<u8> {
    println!("PUBLIC-NATIVE121-STAGE stage=before-prepare height={} parent_height={} operation_count={}",
        prefix.parent.height+1,prefix.parent.height,operations.len());
    let (mut candidate,body,prepared)=prepare_body(host,prefix,operations).unwrap();
    candidate.state_root=prepared.computed_root;
    let (context,_,node)=prefix.state.work_context_v2(&prefix.parent,&candidate).unwrap();
    let epoch=crate::pow::mining_epoch(candidate.timestamp,prefix.parent.t0).unwrap();
    let (license,_)=prefix.state.licenses_v2.active(candidate.license,candidate.worker,epoch).unwrap();
    let mut work=Authority {work:WorkAuthority {candidate:candidate.clone(),
        assignment_sequence:license.assignment_sequence,ticket_sequence:candidate.height,
        coordinator:crate::work_authority_v2::node_identity(
            &host.fixture.node_key.public().descriptor(1).unwrap()).unwrap(),
        nonce_start:0,nonce_end:100_000,epoch},
        node_descriptor:host.fixture.node_key.public().descriptor(1).unwrap(),signature:zero()};
    work.sign(&host.fixture.node_key).unwrap();
    let mut header=WorkHeader {candidate,authority:work.id().unwrap(),nonce:0};
    let nonce=(0..100_000).find(|n|{header.nonce=*n;
        crate::pow::meets_target(&header.digest(),&header.candidate.target)}).expect("bounded TEST work nonce");
    header.nonce=nonce;work.verify(&header,&context,&node).unwrap();
    let pin=ExecutionPin {prepared:prepared.pin,computed_root:prepared.computed_root,
        header:header.encode(),authority:work.encode().unwrap()};
    let execution={let _x=Lease::install(Mode::Execute(pin)).unwrap();
        prefix.state.execute_licensed_with_history_v2(&prefix.parent,&header,&work,&body,&prefix.history).unwrap()};
    assert_eq!(execution.root,prepared.computed_root);
    assert_eq!(execution.state.records().unwrap(),prepared.records);
    let old=HeightAuthority::from_state(&prefix.state,anchor(host,prefix),prefix.root).unwrap();
    let decision=crate::certificates::Decision {network:old.parent.network,
        genesis:old.parent.genesis,fingerprint:old.parent.fingerprint,purpose:2,
        height:header.candidate.height,mining_epoch:epoch,
        continuity_period:(header.candidate.height-1)/60,round:0,step:3,
        previous_finalized_anchor:old.parent.id(),parent:old.parent.block,block:header.block_hash(),
        state:execution.root,membership:old.membership,reputation:old.reputation,attestation:old.attestation};
    let mut votes=Vec::new();
    let selected=if minimal {
        let mut weighted=old.voters.iter().map(|(id,v)|(*id,v.weight().unwrap())).collect::<Vec<_>>();
        weighted.sort_by(|a,b|b.1.cmp(&a.1).then_with(||a.0.cmp(&b.0)));
        let weights=weighted.iter().map(|row|row.1).collect::<Vec<_>>();
        let mut indexes=Vec::new();
        for (index,(_,weight)) in weighted.iter().enumerate() {
            if weight.is_zero(){continue;}indexes.push(index);
            if crate::reputation::quorum(&weights,&indexes).unwrap(){break;}
        }
        assert!(crate::reputation::quorum(&weights,&indexes).unwrap());
        Some(indexes.into_iter().map(|i|weighted[i].0).collect::<std::collections::BTreeSet<_>>())
    }else{None};
    for (node,voter) in &old.voters {
        if selected.as_ref().is_some_and(|ids|!ids.contains(node)){continue;}
        if voter.weight().unwrap().is_zero(){continue;}
        let key=if *node==host.fixture.node {&host.fixture.continuity}else{
            &materials.iter().find(|m|m.join.binding.admission.node==*node).expect("owned synthetic signer").continuity};
        let mut vote=crate::continuity_v2::Vote {decision:decision.clone(),nil:false,node:*node,
            hardware_generation:voter.hardware_generation,key_generation:voter.key_generation,
            sequence:header.candidate.height,tpm_identity:voter.tpm_identity(),profile:voter.profile,signature:zero()};
        vote.sign(key).unwrap();votes.push(vote);
    }
    let certificate=crate::continuity_v2::Certificate {decision,votes};
    certificate.verify_quorum(&certificate.decision,&old.parent,&old.voters).unwrap();
    let capacity=crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(
        &prefix.state,anchor(host,prefix),prefix.root).unwrap();
    BlockEnvelope {header,body,authority:work,certificate}.encode_with_capacity(&capacity).unwrap()
}

pub(super) fn install(host:&ModelHost,chain:&mut CanonicalStore,rows:&mut Vec<Vec<u8>>,raw:Vec<u8>)->VerifiedPrefix {
    rows.push(raw.clone());let verified=VerifiedPrefix::verify(host,rows).unwrap();
    {let _scope=verified.replay().unwrap();
        let header=BlockEnvelope::untrusted_header(&raw).unwrap();
        let capacity=chain.proposal_body_capacity(&header).unwrap();
        let block=BlockEnvelope::decode_with_capacity(&raw,&capacity).unwrap();
        assert!(chain.commit(&block).unwrap());
        assert_eq!(chain.load().unwrap().1.records().unwrap(),verified.state.records().unwrap());}
    assert!(ACTIVE.with(|slot|slot.borrow().is_none()));verified
}

// Selected capacity fixtures append only from a private already checked prefix.
// The original full-prefix install remains for existing controls; final reopen
// independently runs every row from fixed Genesis plus native canonical replay.
pub(super) fn install_incremental(host:&ModelHost,chain:&mut CanonicalStore,
    rows:&mut Vec<Vec<u8>>,prior:VerifiedPrefix,raw:Vec<u8>)->VerifiedPrefix {
    assert_eq!(prior.rows.len(),rows.len());
    assert!(prior.rows.iter().zip(rows.iter()).all(|(a,b)|a.exact_envelope==*b));
    let verified=prior.append(host,raw.clone()).unwrap();
    {let _scope=verified.replay().unwrap();
        let header=BlockEnvelope::untrusted_header(&raw).unwrap();
        let capacity=chain.proposal_body_capacity(&header).unwrap();
        let block=BlockEnvelope::decode_with_capacity(&raw,&capacity).unwrap();
        assert!(chain.commit(&block).unwrap());
        assert_eq!(chain.load().unwrap().1.records().unwrap(),verified.state.records().unwrap());}
    rows.push(raw);
    assert!(ACTIVE.with(|slot|slot.borrow().is_none()));verified
}

// Derive authenticated invalid candidates from a genuinely executed positive.
// The retained positive StateRoot is deliberately NOT an execution result for
// the altered body. No preparation/execution grant is minted for invalid bytes.
// All outer body/work/Decision/signature bindings are recomputed with owned
// synthetic keys so a stale signature/body hash cannot explain the refusal.
pub(super) fn signed_invalid_variant(host:&ModelHost,prefix:&VerifiedPrefix,valid_raw:&[u8],
    operations:Vec<Vec<u8>>,materials:&[Material])->BlockEnvelope {
    let capacity=crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(
        &prefix.state,anchor(host,prefix),prefix.root).unwrap();
    let mut block=BlockEnvelope::decode_with_capacity(valid_raw,&capacity).unwrap();
    block.body.operations=operations;
    block.header.candidate.body_root=capacity.root(&block.body).unwrap();
    block.authority.work.candidate=block.header.candidate.clone();
    block.authority.sign(&host.fixture.node_key).unwrap();
    block.header.authority=block.authority.id().unwrap();
    block.header.nonce=(0..100_000).find(|n| {
        let mut header=block.header.clone();header.nonce=*n;
        crate::pow::meets_target(&header.digest(),&header.candidate.target)
    }).expect("bounded invalid-variant TEST work nonce");
    let (context,_,node)=prefix.state.work_context_v2(&prefix.parent,&block.header.candidate).unwrap();
    block.authority.verify(&block.header,&context,&node).unwrap();
    block.certificate.decision.block=block.header.block_hash();
    let old=HeightAuthority::from_state(&prefix.state,anchor(host,prefix),prefix.root).unwrap();
    for vote in &mut block.certificate.votes {
        vote.decision=block.certificate.decision.clone();
        let key=if vote.node==host.fixture.node {&host.fixture.continuity}else{
            &materials.iter().find(|m|m.join.binding.admission.node==vote.node).unwrap().continuity};
        vote.sign(key).unwrap();
    }
    block.certificate.verify_quorum(&block.certificate.decision,&old.parent,&old.voters).unwrap();
    capacity.encode(&block.body).unwrap();block
}

pub(super) fn directory()->std::path::PathBuf {
    let mut r=[0;16];mutiny_crypto_v2::fill_os_random(&mut r).unwrap();
    let p=std::env::temp_dir().join(format!("build8-public-private-native121-{}",hex::encode(r)));
    assert!(crate::submission_pool_v1::private_directory(&p).unwrap());p
}

// Read-only typed contents, including every persisted journal/index table.
// Refusals below are native unsigned execution checks, not invalid certified
// Store.commit controls. No secret/debug byte serialization is produced.
pub(super) fn database_rows(path:&std::path::Path)->Vec<(String,Vec<Vec<rusqlite::types::Value>>)> {
    let db=rusqlite::Connection::open_with_flags(path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let tables=db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").unwrap()
        .query_map([],|row|row.get::<_,String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
    tables.into_iter().map(|name| {
        let quoted=name.replace('"',"\"\"");let sql=format!("SELECT * FROM \"{quoted}\"");
        let count=db.prepare(&sql).unwrap().column_count();
        let order=(1..=count).map(|n|n.to_string()).collect::<Vec<_>>().join(",");
        let mut stmt=db.prepare(&format!("{sql} ORDER BY {order}")).unwrap();
        let rows=stmt.query_map([],|row|(0..count).map(|i|row.get::<_,rusqlite::types::Value>(i)).collect())
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        (name,rows)
    }).collect()
}

#[test]
fn exact_private_parent_pin_preserves_window_multiset_and_all_other_fields() {
    let mut p=WorkParent {genesis:[1;32],fingerprint:[2;32],block:[3;32],height:3,t0:10,target:[255;32],
        ancestor_timestamps:vec![10,11,12]};let pin=ParentPin::capture(&p);
    p.ancestor_timestamps.reverse();assert!(pin.matches(&p));
    p.ancestor_timestamps[1]=12;assert!(!pin.matches(&p));
    p.ancestor_timestamps=vec![12,11];assert!(!pin.matches(&p));
    p.ancestor_timestamps=vec![12,11,10];p.block=[4;32];assert!(!pin.matches(&p));
    p.block=[3;32];p.fingerprint=[5;32];assert!(!pin.matches(&p));
    p.fingerprint=[2;32];
    // TEST snapshot uses the established seven-field WorkParent API; no production Clone.
    let snapshot=|value:&WorkParent| WorkParent {genesis:value.genesis,
        fingerprint:value.fingerprint,block:value.block,height:value.height,
        t0:value.t0,target:value.target,ancestor_timestamps:value.ancestor_timestamps.clone()};
    let positive=snapshot(&p);
    p.genesis=[6;32];assert!(!pin.matches(&p));p=snapshot(&positive);
    p.height=4;assert!(!pin.matches(&p));p=snapshot(&positive);
    p.t0=11;assert!(!pin.matches(&p));p=snapshot(&positive);
    p.target=[254;32];assert!(!pin.matches(&p));
    assert!(pin.matches(&positive));
}

#[test]
fn genuine_two_row_join_prefix_commits_and_reopens_across_native_window_orders() {
    let host=ModelHost::new();let path=directory().join("canonical.sqlite");
    let mut chain=CanonicalStore::open_trusted_genesis(&path,&host.fixture.parent,&host.fixture.state,
        host.fixture.root,test_value_x509::T_REF,[255;32]).unwrap();
    let mut rows=Vec::new();let mut materials=Vec::new();
    let mut prefix=VerifiedPrefix::verify(&host,&rows).unwrap();
    for ordinal in 1..=2 {
        let m=genuine_material_at(&host,ordinal,&anchor(&host,&prefix),prefix.parent.t0+prefix.parent.height);
        let operation=m.outer.clone();materials.push(m);
        let raw=certified_next(&host,&prefix,vec![operation],&materials);
        prefix=install(&host,&mut chain,&mut rows,raw);
    }
    assert_eq!(prefix.parent.height,2);assert_eq!(prefix.admitted_joins,2);
    assert_eq!(prefix.state.continuity.as_ref().unwrap().members.len(),3);
    drop(chain);VerifiedPrefix::with_reverified_store(&host,&path,&rows,|s|{
        assert_eq!(s.load().unwrap().0.height,2);
        assert_eq!(s.load().unwrap().1.records().unwrap(),prefix.state.records().unwrap());
    }).unwrap();
}

// Two genuine joins exercise the same row predicate both incrementally and
// from fixed private Genesis. Corrupt signed input never gains a next-row pin.
#[test]
fn checked_append_matches_full_genuine_join_replay_and_refuses_corrupt_next_row() {
    let host=ModelHost::new();let path=directory().join("canonical.sqlite");
    let mut chain=CanonicalStore::open_trusted_genesis(&path,&host.fixture.parent,&host.fixture.state,
        host.fixture.root,test_value_x509::T_REF,[255;32]).unwrap();
    let mut rows=Vec::new();let mut materials=Vec::new();
    let mut full=VerifiedPrefix::verify(&host,&[]).unwrap();
    let mut incremental=VerifiedPrefix::verify(&host,&[]).unwrap();
    for ordinal in 1..=2 {
        let material=genuine_material_at(&host,ordinal,&anchor(&host,&full),full.parent.t0+full.parent.height);
        let operation=material.outer.clone();materials.push(material);
        let raw=certified_next(&host,&full,vec![operation],&materials);
        full=install(&host,&mut chain,&mut rows,raw.clone());
        incremental=incremental.append(&host,raw).unwrap();
        assert_eq!(incremental.root,full.root);
        assert_eq!(incremental.state.records().unwrap(),full.state.records().unwrap());
        assert!(ParentPin::capture(&incremental.parent).matches(&full.parent));
        assert_eq!(incremental.timestamps,full.timestamps);
        assert_eq!(incremental.aggregate_raw_bytes,rows.iter().map(Vec::len).sum::<usize>());
        assert_eq!(incremental.admitted_joins,full.admitted_joins);
        assert_eq!(incremental.rows.len(),full.rows.len());
        for (a,b) in incremental.rows.iter().zip(full.rows.iter()) {
            assert_eq!(a.exact_envelope,b.exact_envelope);
            assert_eq!(a.resulting_root,b.resulting_root);
            assert_eq!(a.execution.header,b.execution.header);
            assert_eq!(a.execution.authority,b.execution.authority);
            assert_eq!(a.execution.prepared.body,b.execution.prepared.body);
        }
    }
    let mut corrupt=rows[1].clone();*corrupt.last_mut().unwrap()^=1;
    let previous=VerifiedPrefix::verify(&host,&rows[..1]).unwrap();
    assert!(previous.append(&host,corrupt).is_err());
    drop(chain);
    VerifiedPrefix::with_reverified_store(&host,&path,&rows,|reopened| {
        assert_eq!(reopened.load().unwrap().1.records().unwrap(),full.state.records().unwrap());
    }).unwrap();
}

pub(super) fn lifecycle(host:&ModelHost,prefix:&VerifiedPrefix,materials:&[Material],height:u64)->Vec<Vec<u8>> {
    let parent=anchor(host,prefix);let mut operations=Vec::new();
    // Genesis simulator reconstruction is checked against the authenticated
    // current voting public; it cannot supply admission authority or history.
    let genesis_tpm=if host.capacity_join_pki.is_some() {
        TestTpm::with_identity("a2-native16-capacity-original-EK")
            .strip(software_tpm::Strip::ConsistentProvenance(host.fixture.pki.root_hash()))
    }else{TestTpm::stripped(software_tpm::Strip::ConsistentProvenance(host.fixture.pki.root_hash()))};
    let registry=prefix.state.continuity.as_ref().unwrap();
    for member in registry.members.iter().filter(|m|m.physical && m.eligible) {
        let tpm=if member.node==host.fixture.node {&genesis_tpm}else{
            &materials.iter().find(|m|m.join.binding.admission.node==member.node).unwrap().tpm};
        assert_eq!(tpm.voting_point(),member.voting_key);
        if height==61 {
            let mut refresh=AttestationRefresh {network:parent.network,genesis:parent.genesis,fingerprint:parent.fingerprint,
                node:member.node,generation:member.generation,height,parent_anchor:parent.id(),evidence:vec![]};
            refresh.evidence=tpm.quote(refresh.challenge());operations.push(refresh.encode().unwrap());
        }else if (62..=120).contains(&height) {
            let mut ack=ParticipationAck {network:parent.network,genesis:parent.genesis,fingerprint:parent.fingerprint,
                node:member.node,height,parent:parent.id(),generation:member.generation,signature:[0;64]};
            ack.signature=tpm.possession(ack.signing_digest());operations.push(ack.encode());
        }
    }
    operations
}

#[test]
fn genuine_fifteen_canonical_joins_earn_sixteen_voters_before_h121_activation_and_reopen() {
    let host=ModelHost::new();let path=directory().join("canonical.sqlite");
    let mut chain=CanonicalStore::open_trusted_genesis(&path,&host.fixture.parent,&host.fixture.state,
        host.fixture.root,test_value_x509::T_REF,[255;32]).unwrap();
    let mut rows=Vec::new();let mut materials=Vec::new();
    let mut prefix=VerifiedPrefix::verify(&host,&rows).unwrap();
    for height in 1..=120 {
        let operations=if height<=15 {
            let m=genuine_material_at(&host,height as u8,&anchor(&host,&prefix),prefix.parent.t0+prefix.parent.height);
            let raw=m.outer.clone();materials.push(m);vec![raw]
        }else{lifecycle(&host,&prefix,&materials,height)};
        let raw=certified_next(&host,&prefix,operations,&materials);
        prefix=install(&host,&mut chain,&mut rows,raw);
        if height==59 {assert_eq!(prefix.state.continuity.as_ref().unwrap().members.iter().filter(|m|m.eligible).count(),1);}
        if height==119 {
            assert_eq!(prefix.state.accounting.slots.bits.len(),16);
            assert!(prefix.state.accounting.slots.bits.values().all(|bits|bits.count_ones()==58));
        }
        if height==60 {let r=prefix.state.continuity.as_ref().unwrap();
            assert_eq!(r.members.iter().filter(|m|m.eligible).count(),16);
            assert_eq!(r.weights().unwrap().iter().filter(|w|!w.is_zero()).count(),1);
            let parent=anchor(&host,&prefix);let roots=r.roots().unwrap();
            let early=crate::activation::DecentralizedActivation {network:parent.network,
                genesis:parent.genesis,fingerprint:parent.fingerprint,height:61,parent:parent.id(),
                membership:roots.0,reputation:roots.1};
            // Exact genuine insufficient parent authority, not an edited weight.
            assert_eq!(early.validate(&parent,r),Err(Error::RedundancyNotMet));
            let persisted=database_rows(&path);
            assert!(matches!(prepare_body(&host,&prefix,vec![early.encode()]),
                Err(crate::execution::ExecutionError::Codec(Error::RedundancyNotMet))));
            assert!(database_rows(&path)==persisted,"unqualified unsigned preparation changed persisted contents");
        }
    }
    let registry=prefix.state.continuity.as_ref().unwrap();
    assert_eq!(registry.weights().unwrap().iter().filter(|w|!w.is_zero()).count(),16);
    assert!(registry.members.iter().all(|m|m.history.p>0 && m.history.s>0 && m.history.h>0));
    assert!(registry.metrics().unwrap().survival_redundancy_met);
    let roots=registry.roots().unwrap();let parent=anchor(&host,&prefix);
    let activation=crate::activation::DecentralizedActivation {network:parent.network,genesis:parent.genesis,
        fingerprint:parent.fingerprint,height:121,parent:parent.id(),membership:roots.0,reputation:roots.1};
    let before_root=prefix.root;let before_records=prefix.state.records().unwrap();
    let persisted=database_rows(&path);
    let mut wrong=activation.clone();wrong.parent=[0;32];
    assert!(matches!(prepare_body(&host,&prefix,vec![wrong.encode()]),
        Err(crate::execution::ExecutionError::Codec(Error::WrongAnchor))));
    assert!(matches!(prepare_body(&host,&prefix,vec![activation.encode(),activation.encode()]),
        Err(crate::execution::ExecutionError::Codec(Error::Duplicate))));
    assert_eq!(prefix.state.root().unwrap(),before_root);
    assert_eq!(prefix.state.records().unwrap(),before_records);
    assert!(database_rows(&path)==persisted,"wrong-context/duplicate unsigned preparation changed persisted contents");
    {let _scope=prefix.replay().unwrap();let (tip,state)=chain.load().unwrap();
        assert_eq!(tip.height,120);assert_eq!(tip.root,before_root);
        assert_eq!(state.records().unwrap(),before_records);}
    // This is the genuine pre-fix RED site: kind13 must reach unchanged typed
    // old-parent checks, not be manufactured by editing a registry field.
    let raw=certified_next(&host,&prefix,vec![activation.encode()],&materials);
    for operations in [vec![wrong.encode()],vec![activation.encode(),activation.encode()]] {
        let invalid=signed_invalid_variant(&host,&prefix,&raw,operations,&materials);
        let persisted=database_rows(&path);
        {let _scope=prefix.replay().unwrap();
            // The private historical X capability contains ONLY genuinely
            // verified earlier rows. It cannot authorize this altered header.
            // This is real canonical atomic rejection at the private exact-X
            // boundary; it is not wrong-parent/duplicate typed execution credit.
            assert!(matches!(chain.commit(&invalid),
                Err(crate::finality_v2::StoreError::Verification(
                    IngressError::Execution(crate::execution::ExecutionError::Codec(Error::WrongAnchor))))));
            let (tip,state)=chain.load().unwrap();
            assert_eq!(tip.height,120);assert_eq!(tip.root,before_root);
            assert_eq!(state.records().unwrap(),before_records);
        }
        assert!(database_rows(&path)==persisted,"invalid certified variant changed canonical SQLite contents");
        assert!(ACTIVE.with(|slot|slot.borrow().is_none()));
    }
    prefix=install(&host,&mut chain,&mut rows,raw);
    assert_eq!(prefix.state.continuity.as_ref().unwrap().mode(),"DECENTRALIZED");
    assert!(!prefix.state.continuity.as_ref().unwrap().recovery_enabled());
    let (kind,id)=crate::operation_index_v2::operation_id(1,&activation.encode()).unwrap();
    assert_eq!(kind,13);
    {let _scope=prefix.replay().unwrap();
        let indexed=chain.verified_operation_records(id).unwrap();
        assert_eq!(indexed.len(),1);assert_eq!(indexed[0].kind,13);
        assert_eq!(indexed[0].height,121);assert_eq!(indexed[0].position,0);
        assert!(indexed[0].receipt.is_none());
        assert_eq!(indexed[0].wire,crate::domain_hash(crate::operation_index_v2::WIRE_DOMAIN,&activation.encode()));
        assert_eq!(chain.certified_envelope_bytes(121,prefix.parent.block).unwrap(),Some(rows[120].clone()));}
    drop(chain);VerifiedPrefix::with_reverified_store(&host,&path,&rows,|s|{
        let (tip,state)=s.load().unwrap();assert_eq!(tip.height,121);
        assert_eq!(state.records().unwrap(),prefix.state.records().unwrap());
        assert_eq!(state.continuity.as_ref().unwrap().mode(),"DECENTRALIZED");
        assert_eq!(s.verified_operation_records(id).unwrap().len(),1);
        assert_eq!(s.certified_envelope_bytes(121,tip.block).unwrap(),Some(rows[120].clone()));
    }).unwrap();
}

// Codec/cryptographic controls only: these two software signers are not admitted
// members and confer no canonical parent-state, weight or private P/X authority.
fn deliberately_descending_signed_ack_body(host:&ModelHost) -> BlockBody {
    use p256::ecdsa::{Signature,VerifyingKey,signature::hazmat::PrehashVerifier};
    let parent=&host.fixture.parent;
    let mut operations=Vec::new();
    for tag in ["public-native121-codec-ack-a","public-native121-codec-ack-b"] {
        let tpm=TestTpm::with_identity(tag);
        let key=tpm.voting_point();
        let mut ack=ParticipationAck {network:parent.network,genesis:parent.genesis,
            fingerprint:parent.fingerprint,node:crate::domain_hash(b"PUBLIC-NATIVE121-CODEC-ACK-V1",&key),
            height:parent.height+1,parent:parent.id(),generation:0,signature:[0;64]};
        ack.signature=tpm.possession(ack.signing_digest());
        let signature=Signature::from_slice(&ack.signature).unwrap();
        assert!(signature.normalize_s().is_none());
        VerifyingKey::from_sec1_bytes(&key).unwrap()
            .verify_prehash(&ack.signing_digest(),&signature).unwrap();
        let raw=ack.encode();assert_eq!(ParticipationAck::decode(&raw).unwrap(),ack);
        operations.push(raw);
    }
    operations.sort_by_key(|raw|ParticipationAck::decode(raw).unwrap().node);
    operations.reverse();
    assert!(ParticipationAck::decode(&operations[0]).unwrap().node
        >ParticipationAck::decode(&operations[1]).unwrap().node);
    BlockBody {height:parent.height+1,reward_owner:[4;32],fees:0,
        transactions:vec![],operations}
}

#[test]
fn test_builder_normalizes_signed_ack_order_and_preserves_exact_bytes() {
    let host=ModelHost::new();let descending=deliberately_descending_signed_ack_body(&host);
    let exact=descending.operations.iter().cloned().collect::<BTreeSet<_>>();
    assert_eq!(exact.len(),2);
    let capacity=crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(
        &host.fixture.state,host.fixture.parent.clone(),host.fixture.root).unwrap();
    assert_eq!(capacity.root(&descending),Err(Error::NonCanonical));
    let body=canonical_builder_body(descending.clone(),descending.operations.clone()).unwrap();
    assert_eq!(body.height,descending.height);assert_eq!(body.reward_owner,descending.reward_owner);
    assert_eq!(body.fees,descending.fees);assert_eq!(body.transactions,descending.transactions);
    assert_eq!(body.operations.len(),2);
    assert_eq!(body.operations.iter().cloned().collect::<BTreeSet<_>>(),exact);
    assert!(ParticipationAck::decode(&body.operations[0]).unwrap().node
        <ParticipationAck::decode(&body.operations[1]).unwrap().node);
    let raw=capacity.encode(&body).unwrap();
    assert_eq!(capacity.decode(&raw).unwrap(),body);
    assert_eq!(capacity.root(&body).unwrap(),crate::domain_hash(b"MUTINY-BUILD8-BODY-V1",&raw));
    // Same-node conflicting context is refused, rather than chosen by arrival.
    let mut conflict=ParticipationAck::decode(&descending.operations[0]).unwrap();
    conflict.parent=[99;32];
    let mut invalid=descending.operations.clone();invalid.push(conflict.encode());
    assert_eq!(canonical_builder_body(descending,invalid),Err(Error::Duplicate));
}

#[test]
fn wire_codec_still_refuses_deliberately_unsorted_signed_ack_body() {
    let host=ModelHost::new();let descending=deliberately_descending_signed_ack_body(&host);
    assert_eq!(descending.encode(),Err(Error::NonCanonical));
    // Encode the alternate ordering explicitly; do not use the refusing builder
    // to manufacture wire bytes and never submit these as certified authority.
    let mut e=minicbor::Encoder::new(Vec::new());
    e.array(5).unwrap().u8(1).unwrap().u64(descending.height).unwrap()
        .array(3).unwrap().bytes(&descending.reward_owner).unwrap()
        .u64(100_000_000).unwrap().u64(descending.fees).unwrap()
        .array(0).unwrap().array(2).unwrap();
    for raw in &descending.operations {e.bytes(raw).unwrap();}
    let raw=e.into_writer();
    assert_eq!(BlockBody::decode(&raw),Err(Error::NonCanonical));
    let capacity=crate::body_capacity_v3::BodyCapacity::from_authenticated_parent(
        &host.fixture.state,host.fixture.parent.clone(),host.fixture.root).unwrap();
    assert_eq!(capacity.decode(&raw),Err(Error::NonCanonical));
    let normalized=canonical_builder_body(descending.clone(),descending.operations.clone()).unwrap();
    assert_eq!(BlockBody::decode(&normalized.encode().unwrap()).unwrap(),normalized);
    assert!(ACTIVE.with(|slot|slot.borrow().is_none()));
}
