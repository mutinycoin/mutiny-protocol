//! PUBLIC software-generated fixture only: no production keys or hardware proof.
//! Actual Store prepare/execution, work signature, parent certificate, finality,
//! exact evidence export, authenticated index replay and reopen are exercised.
use super::*;
use crate::{
    assembler_v2::PendingSource,
    block_envelope_v2::BlockEnvelope,
    canonical_store_v2::{CanonicalStore, Preparation},
    pow::{WorkAuthority, WorkHeader},
    work_authority_v2::Authority,
};
struct EmptyPending;
impl crate::op_envelope_v1::PendingReferences for EmptyPending {}
impl PendingSource for EmptyPending {
    fn pending_items_at(&self, _: &FinalizedAnchor, _: &State)
        -> std::result::Result<Vec<crate::submission_v1::Submission>, String>
    { Ok(vec![]) }
}
// Read-only exact typed SQLite contents: refusal must not mutate any journal/record.
fn database_rows(path:&std::path::Path) -> Vec<(String,Vec<Vec<rusqlite::types::Value>>)> {
    let db=rusqlite::Connection::open_with_flags(path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    let tables=db.prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name").unwrap()
        .query_map([],|row|row.get::<_,String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
    tables.into_iter().map(|name| {
        let quoted=name.replace('"',"\"\"");
        let sql=format!("SELECT * FROM \"{quoted}\"");
        let count=db.prepare(&sql).unwrap().column_count();
        let order=(1..=count).map(|n|n.to_string()).collect::<Vec<_>>().join(",");
        let mut stmt=db.prepare(&format!("{sql} ORDER BY {order}")).unwrap();
        let rows=stmt.query_map([],|row|(0..count).map(|i|row.get::<_,rusqlite::types::Value>(i)).collect())
            .unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        (name,rows)
    }).collect()
}

#[test]
fn signed_root_judgment_finality_reopens_with_evidence_and_refuses_new_work() {
    let r = rig();
    let op = operation(&r, Target {
        class: TargetClass::Root, scope: TargetScope::Certificate,
        identity: r.pki.root_hash(),
    }, Evidence::Judgment {
        reason: b"PUBLIC SOFTWARE TEST terminal Root judgment".to_vec(),
        evidence: vec![r.pki.root.clone(), b"PUBLIC synthetic evidence; not a physical allegation or proof".to_vec()],
    });
    assert!(op.encode().unwrap().len() <= crate::body_capacity_v3::MAX_ORDINARY_ITEM_BYTES);
    assert_terminal_store(r, op);
}
// TEST-only shared assertion path; the original small signed judgment and the
// new real used-CRL maximum fixture execute the same native certified Store path.
pub(super) fn assert_terminal_store(r: Rig, op: Operation) {
    let operations = vec![op.encode().unwrap()];
    let assignment = r.state.licenses_v2.assignments().next().unwrap().enrollment.binding.clone();
    let license = assignment.license;
    let worker = assignment.worker_id;
    let epoch = crate::pow::mining_epoch(op.context.timestamp, test_value_x509::T_REF).unwrap();
    let (active, _) = r.state.licenses_v2.active(license, worker, epoch).unwrap();
    let sequence = active.assignment_sequence;
    let mut unique = [0; 16]; mutiny_crypto_v2::fill_os_random(&mut unique).unwrap();
    let directory = std::env::temp_dir().join(format!("build8-public-a2-terminal-store-{}",hex::encode(unique)));
    assert!(crate::submission_pool_v1::private_directory(&directory).unwrap());
    let path = directory.join("canonical.sqlite");
    assert!(!path.exists());
    eprintln!("PUBLIC A2 canonical evidence retained at {}", directory.display());
    let empty = EmptyPending;
    let mut chain = CanonicalStore::open_trusted_genesis(&path,&r.parent,&r.state,r.root,test_value_x509::T_REF,[255;32]).unwrap();
    let cap = chain.body_capacity(&r.parent).unwrap();
    assert!(cap.allows_a2());
    // Genuine nonterminal companion uses the same native licensed work path.
    let positive = chain.prepare_pending(Preparation {
        expected_parent:&r.parent,pool:&empty,license,worker,
        timestamp:op.context.timestamp+1,ticket:2,operations:&[],
    }).unwrap();
    assert!(!positive.execution.state.endorsement_revocations_v1.terminal_no_quorum());
    assert_eq!(chain.load().unwrap().0.height,0);
    let prepared = chain.prepare_pending(Preparation {
        expected_parent: &r.parent, pool: &empty, license, worker,
        timestamp: op.context.timestamp, ticket: 1, operations: &operations,
    }).unwrap();
    assert!(prepared.execution.state.endorsement_revocations_v1.terminal_no_quorum());
    let mut authority = Authority {
        work: WorkAuthority {
            candidate: prepared.candidate.clone(), assignment_sequence: sequence,
            ticket_sequence: 1, coordinator: crate::work_authority_v2::node_identity(&r.node_key.public().descriptor(1).unwrap()).unwrap(),
            nonce_start: 0, nonce_end: 100, epoch,
        },
        node_descriptor: r.node_key.public().descriptor(1).unwrap(), signature: zero(),
    };
    authority.sign(&r.node_key).unwrap();
    let header = WorkHeader {candidate:prepared.candidate,authority:authority.id().unwrap(),nonce:1};
    assert!(crate::pow::meets_target(&header.digest(),&[255;32]));
    let parent_authority = chain.current_authority(&r.parent).unwrap();
    let voter = &parent_authority.voters[&r.node];
    assert!(!voter.weight().unwrap().is_zero());
    let decision = crate::certificates::Decision {
        network:r.parent.network,genesis:r.parent.genesis,fingerprint:r.parent.fingerprint,
        purpose:2,height:1,mining_epoch:epoch,continuity_period:0,round:0,step:3,
        previous_finalized_anchor:r.parent.id(),parent:r.parent.block,block:header.block_hash(),
        state:prepared.execution.root,membership:parent_authority.membership,
        reputation:parent_authority.reputation,attestation:parent_authority.attestation,
    };
    let mut vote = crate::continuity_v2::Vote {
        decision:decision.clone(),nil:false,node:r.node,hardware_generation:voter.hardware_generation,
        key_generation:voter.key_generation,sequence:1,tpm_identity:voter.tpm_identity(),
        profile:voter.profile,signature:zero(),
    };
    vote.sign(&r.continuity).unwrap();
    let certificate = crate::continuity_v2::Certificate {decision:decision.clone(),votes:vec![vote]};
    certificate.verify_quorum(&decision,&r.parent,&parent_authority.voters).unwrap();
    let envelope = BlockEnvelope {header,body:prepared.body,authority,certificate};
    let exact = envelope.encode_with_capacity(&cap).unwrap();
    let (kind, id) = cap.operation_id(&operations[0]).unwrap(); assert_eq!(kind,25);
    assert!(chain.commit(&envelope).unwrap());
    let assert_evidence = |chain:&CanonicalStore| {
        let (head, state) = chain.load().unwrap();
        assert_eq!(head.height,1); assert_eq!(head.block,envelope.block_hash());
        assert!(state.endorsement_revocations_v1.terminal_no_quorum());
        // Terminal eligibility halt must not invent an integrity conflict latch.
        assert!(!chain.halted().unwrap());
        assert_eq!(chain.certified_envelope_bytes(1,head.block).unwrap(),Some(exact.clone()));
        assert_eq!(chain.canonical_block(1).unwrap().unwrap().encode_with_capacity(&cap).unwrap(),exact);
        assert!(chain.certified_envelope_bytes(1,label("wrong-public-block")).is_err());
        let historic = chain.proposal_body_capacity(&envelope.header).unwrap();
        assert_eq!(historic.parent(),&r.parent);
        assert_eq!(historic.parent_state_root(),r.root);
        let records = chain.verified_operation_records(id).unwrap();
        assert_eq!(records.len(),1); assert_eq!(records[0].kind,25);
        assert_eq!(records[0].list,1); assert_eq!(records[0].position,0);
        assert_eq!(records[0].wire,crate::domain_hash(crate::operation_index_v2::WIRE_DOMAIN,&operations[0]));
        records[0].verify_in_block_with_capacity(&envelope.body,head.block,&historic).unwrap();
        let at = FinalizedAnchor {height:1,block:head.block,..r.parent.clone()};
        let prospective = chain.current_authority(&at).unwrap();
        assert!(matches!(crate::votes_v2::AuthenticatedRound::new(prospective),Err(crate::votes::IngressError::Bft(crate::bft::BftError::NoQuorum))));
    };
    assert_evidence(&chain);
    drop(chain);
    let reopened = CanonicalStore::open_trusted_genesis(&path,&r.parent,&r.state,r.root,test_value_x509::T_REF,[255;32]).unwrap();
    assert_evidence(&reopened);
    // Do not let a prospective-preparation RED prevent actual reopened evidence checks.
    let (head, _) = reopened.load().unwrap();
    let at = FinalizedAnchor {height:1,block:head.block,..r.parent.clone()};
    let before_rows=database_rows(&path);
    let (_,before_state)=reopened.load().unwrap();
    let before_root=before_state.root().unwrap(); let before_records=before_state.records().unwrap();
    let refused = reopened.prepare_pending(Preparation {
        expected_parent:&at,pool:&empty,license,worker,timestamp:op.context.timestamp+1,
        ticket:2,operations:&[],
    });
    assert!(matches!(refused, Err(crate::finality_v2::StoreError::Assembly(ref reason)) if reason.contains("NoQuorum")),
        "durable terminal NoQuorum must refuse unsigned preparation for the actual NoQuorum reason");
    assert_evidence(&reopened);
    let (_,after_state)=reopened.load().unwrap();
    assert_eq!(after_state.root().unwrap(),before_root);
    assert!(after_state.records().unwrap()==before_records,"NoQuorum refusal changed canonical records");
    assert!(database_rows(&path)==before_rows,"NoQuorum refusal changed canonical journal rows");
    // Preserve the entire public fixture and SQLite sidecars; no destructive cleanup.
}
