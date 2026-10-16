//! NONSHIPPING, explicitly selected protected native-owner TEST application.
//! Bootstrap persists matching role providers and native voter state before H0.
//! A distinct existing-only process publishes H0 and uses actual Node work/votes.
//! Software TEST counters/elapsed time convey no TPM, clock or antirollback qualification.
#![cfg(all(windows,feature="native-owner-test"))]
use super::{image_pin::{ImagePin,DatabasePin,DirectoryPin},process_auth::{Identity,VerifiedProcess},
    test_signer_store::{Binding,create_new_private_leaf,native_owner_test::{NativeOwnerStore,Backend,JournalPin,JournalObserver},
        sqlite_reconciliation::{FrozenInspection,ExpectedSnapshot,RecoveryNeed}}};
use mutinyd_v8::{genesis_artifact_v2::{TrustV2,VerifiedGenesisV2},hybrid_runtime_v2::{HybridRuntime,WorkRequest},
    hybrid_voter_v2::VotingRuntime,activation_private_owner_v1::Owner,hybrid_application_v2::A2Services,
    candidate_journal_v3::Record};
use mutiny_consensus_v8::{Hash,anchors::FinalizedAnchor,genesis_v2::{Approved,GenesisClass},
    protocol_manifest::RuleManifest,canonical_store_v2::CanonicalStore,mempool_v2::Mempool,
    work_authority_v2::Authority,pow::{WorkAuthority,WorkHeader},bft::Step,
    continuity_v2::Certificate,block_envelope_v2::BlockEnvelope,activation_attestation_v1 as activation};
use mutiny_crypto_v2::HybridSignature;
use std::{path::{Path,PathBuf},sync::Arc,time::{Duration,Instant},io::Write};
use sha2::{Digest,Sha256};
use super::own_native_receiver::{NativeRunOwner,require_prepared_context};
type Result<T>=std::result::Result<T,String>;
const MARKER:&str="BUILD8-NATIVE-OWNER-TEST-PREPARED-V2";
const FILES:[&str;7]=["native-canonical.sqlite","native-mempool.sqlite","native-voter.sqlite",
    "native-a2-pool.sqlite","native-candidates.sqlite","native-owner-roles.sqlite","native-owner.guard"];
fn err(e:impl std::fmt::Debug)->String{format!("{e:?}")}
fn hash(raw:&[u8])->Hash{Sha256::digest(raw).into()}
fn create(path:&Path,raw:&[u8])->Result<()>{
    if raw.is_empty()||raw.len()>mutinyd_v8::genesis_artifact_v2::MAX_ARTIFACT{return Err("Native TEST public output bound".into());}
    let mut f=std::fs::OpenOptions::new().write(true).create_new(true).open(path).map_err(err)?;
    f.write_all(raw).map_err(err)?;f.sync_all().map_err(err)
}
fn current()->Result<VerifiedProcess>{let id=VerifiedProcess::observe_created_process(std::process::id())?;VerifiedProcess::open(&id)}
fn fresh(before:&Identity,now:&Identity)->Result<()>{
    if before.pid==now.pid||before.start_filetime>=now.start_filetime||before.session!=now.session
        ||before.authentication_luid!=now.authentication_luid||before.user_sid!=now.user_sid
        ||before.image_path!=now.image_path||before.image_sha256!=now.image_sha256{return Err("Distinct matching native TEST process required".into());}
    super::process_auth::historical_process_closed(before)
}
#[derive(Clone,serde::Serialize,serde::Deserialize)]#[serde(deny_unknown_fields)]
struct FilePin{native:Hash,sha:Hash}
fn file_pins(base:&Path,user:&[u8])->Result<Vec<FilePin>>{
    FILES.iter().map(|name|{let p=base.join(name);let db=DatabasePin::open(&p,user)?;
        let image=ImagePin::open(&p,user)?;db.recheck()?;image.recheck()?;
        Ok(FilePin{native:db.native_id_hash(),sha:image.hash()})}).collect()
}
#[derive(Clone,serde::Serialize,serde::Deserialize)]#[serde(deny_unknown_fields)]
struct Prepared{
    format:String,phase:u64,base:PathBuf,campaign:Hash,source_path:PathBuf,source_sha:Hash,source_git:String,
    previous_process:Identity,files:Vec<FilePin>,artifact_sha:Hash,evidence_sha:Hash,
    genesis_block:Hash,manifest:Vec<u8>,initial_target:Hash,initial_root:Hash,
    node:Hash,node_descriptor:Vec<u8>,continuity_descriptor:Vec<u8>,license:Hash,worker:Hash,
    original_store_identities:Hash,journal:JournalPin,lifetime_ms:u64,
}
impl Prepared{
    fn binding(&self)->Result<Binding>{
        if self.format!=MARKER||self.files.len()!=FILES.len()||self.lifetime_ms==0||self.campaign==[0;32]
            ||self.source_sha==[0;32]||self.source_git.len()!=40||!self.source_git.bytes().all(|c|c.is_ascii_hexdigit()){
            return Err("Native TEST prepared identity/mode".into());
        }
        let genesis=self.verified_genesis()?.genesis.anchor();
        Ok(Binding{campaign:self.campaign,source:self.source_sha,genesis:genesis.genesis,fingerprint:genesis.fingerprint,
            initial_root:self.initial_root,original_store_identities:self.original_store_identities,
            native_custody_identity:self.files[5].native,native_guard_identity:self.files[6].native,
            node_descriptor:self.node_descriptor.clone(),continuity_descriptor:self.continuity_descriptor.clone()})
    }
    fn verified_genesis(&self)->Result<VerifiedGenesisV2>{
        let user=&self.previous_process.user_sid;
        let source=ImagePin::open(&self.source_path,user)?;if source.hash()!=self.source_sha{return Err("Native TEST source pin".into());}
        let artifact=ImagePin::open(&self.base.join("native-h0-private-draft.json"),user)?;
        let evidence=ImagePin::open(&self.base.join("native-public-witness.cbor"),user)?;
        if artifact.hash()!=self.artifact_sha||evidence.hash()!=self.evidence_sha{return Err("Native TEST public Genesis/evidence pin".into());}
        let trust=TrustV2{artifact_sha256:self.artifact_sha,genesis_block_hash:self.genesis_block,
            approved:Approved{manifest:RuleManifest::decode(&self.manifest).map_err(err)?,class:GenesisClass::TestValue,initial_target:self.initial_target}};
        let g=VerifiedGenesisV2::verify_with_public_evidence(&artifact.read_bounded(mutinyd_v8::genesis_artifact_v2::MAX_ARTIFACT as u64)?,
            &trust,&evidence.read_bounded(mutiny_consensus_v8::admission_evidence_v1::MAX_BUNDLE as u64)?)?;
        if g.genesis.root!=self.initial_root||mutiny_consensus_v8::node_admission_v2::node_id(g.genesis.identity,&self.node_descriptor).map_err(err)?!=self.node{
            return Err("Native TEST retained Genesis/provider identity".into());
        }
        source.recheck()?;artifact.recheck()?;evidence.recheck()?;Ok(g)
    }
}
struct TestElapsed(Instant);
impl activation::Elapsed for TestElapsed{fn elapsed(&self)->std::result::Result<Duration,activation::Failure>{Ok(self.0.elapsed())}}
struct NoCredential;
impl activation::MakeCredential for NoCredential{
    fn make_credential(&mut self,_:&[u8],_:&[u8;34],_:&[u8;32])->std::result::Result<activation::EncryptedCredential,activation::Failure>{Err(activation::Failure::Adapter)}
}
fn open_chain(base:&Path,g:&VerifiedGenesisV2)->Result<CanonicalStore>{CanonicalStore::open_trusted_genesis(&base.join(FILES[0]),
    &g.genesis.anchor(),&g.genesis.state,g.genesis.root,g.genesis.t0,g.genesis.target).map_err(err)}
fn runtime(base:&Path,g:&VerifiedGenesisV2,timestamp:u64)->Result<HybridRuntime>{
    let chain=open_chain(base,g)?;let pool=Mempool::open(&base.join(FILES[1]),g.genesis.identity,g.genesis.fingerprint,
        mutiny_consensus_v8::submission_pool_v1::MAX_BYTES).map_err(err)?;
    HybridRuntime::from_pinned_chain_with_time_source(chain,pool,Arc::new(move||timestamp)).map_err(err)
}
/// Trusted create-new bootstrap only. Caller/runner owns a fresh protected parent.
/// This function cannot reopen/repair an old provider or publish H0.
fn prepare(execution:&NativeRunOwner,base:&Path,campaign:Hash,source:&Path,source_sha:Hash,source_git:String,lifetime_ms:u64)->Result<PathBuf>{
    execution.require(&source_sha,&campaign)?;let owner=current()?;let user=&owner.identity().user_sid;let directory=DirectoryPin::open(base,user)?;
    let source_pin=ImagePin::open(source,user)?;
    if source_pin.hash()!=source_sha||lifetime_ms==0||campaign==[0;32]||source_git.len()!=40
        ||!source_git.bytes().all(|c|c.is_ascii_hexdigit()){return Err("Explicit native TEST input pins".into());}
    if std::fs::read_dir(base).map_err(err)?.next().is_some(){return Err("Native TEST fresh empty workspace required".into());}
    for name in [FILES[0],FILES[1],FILES[2],FILES[5],FILES[6]]{create_new_private_leaf(&base.join(name),user)?;}
    execution.require(&source_sha,&campaign)?;let f=super::native_owner_fixture::fresh();
    let approved=Approved{manifest:f.inputs.parameters.rules.clone(),class:GenesisClass::TestValue,initial_target:f.inputs.parameters.initial_target};
    let (artifact,g)=mutinyd_v8::genesis_artifact_v2::freeze_with_public_evidence(&f.inputs,&f.enrollment,&approved,&f.public_evidence)?;
    if g.root!=f.state.root().map_err(err)?||g.anchor()!=f.parent{return Err("Native TEST genuine reconstruction changed".into());}
    create(&base.join("native-h0-private-draft.json"),&artifact)?;create(&base.join("native-public-witness.cbor"),&f.public_evidence)?;
    let trust=TrustV2{artifact_sha256:hash(&artifact),genesis_block_hash:g.block_hash,approved};
    let verified=VerifiedGenesisV2::verify_with_public_evidence(&artifact,&trust,&f.public_evidence)?;
    let r=runtime(base,&verified,g.t0.checked_add(1).ok_or("TEST timestamp overflow")?)?;
    let services=A2Services::open(&r,&base.join(FILES[3]),&base.join(FILES[4]),mutinyd_v8::candidate_journal_v3::MAX_QUEUE_BYTES,true)?;
    let ids=FILES.iter().take(5).map(|name|DatabasePin::open(&base.join(name),user)).collect::<Result<Vec<_>>>()?;
    let mut ih=Sha256::new();ih.update(b"BUILD8-NATIVE-OWNER-TEST-ORIGINAL-STORES-V2");for p in &ids{ih.update(p.native_id_hash());}
    let original_store_identities:Hash=ih.finalize().into();
    let custody=DatabasePin::open(&base.join(FILES[5]),user)?;let guard=DatabasePin::open(&base.join(FILES[6]),user)?;
    let node=f.node;let license=f.license;let worker=f.worker;let evidence_sha=hash(&f.public_evidence);
    let node_descriptor=f.node_key.public().descriptor(1).map_err(err)?;let continuity_descriptor=f.continuity.public().descriptor(1).map_err(err)?;
    let binding=Binding{campaign,source:source_sha,genesis:g.identity,fingerprint:g.fingerprint,initial_root:g.root,original_store_identities,
        native_custody_identity:custody.native_id_hash(),native_guard_identity:guard.native_id_hash(),
        node_descriptor:node_descriptor.clone(),continuity_descriptor:continuity_descriptor.clone()};
    drop(custody);drop(guard);
    let store=NativeOwnerStore::initialize_qualified_before_h0(execution.provider()?,&base.join(FILES[5]),&base.join(FILES[6]),user,binding,&f.node_key,&f.continuity)?;
    let journal=store.journal_pin()?;
    let backend=store.backend(open_chain(base,&verified)?,DatabasePin::open(&base.join(FILES[0]),user)?,g.anchor())?;
    let voter=VotingRuntime::open(r,&base.join(FILES[2]),f.node,Some(0),backend).map_err(err)?;
    // Role-provider and voter SQLite commits returned success. These owners
    // are released by RAII before hashing; this is no explicit native/VFS close
    // or power-loss qualification receipt.
    drop(voter);drop(services);drop(ids);drop(f);
    let files=file_pins(base,user)?;
    let p=Prepared{format:MARKER.into(),phase:0,base:base.into(),campaign,source_path:source.into(),source_sha,source_git,
        previous_process:owner.identity().clone(),files,artifact_sha:trust.artifact_sha256,evidence_sha,
        genesis_block:g.block_hash,manifest:trust.approved.manifest.encode().map_err(err)?,initial_target:g.target,initial_root:g.root,
        node,node_descriptor,continuity_descriptor,license,worker,original_store_identities,journal,lifetime_ms};
    directory.recheck()?;source_pin.recheck()?;owner.recheck()?;
    let path=base.join("native-owner-prepared.json");create(&path,&serde_json::to_vec(&p).map_err(err)?)?;Ok(path)
}

/// Exactly one actual native TEST block in a distinct existing-only process.
/// Continuation receives the predecessor's exact checkpoint hash and cannot
/// bootstrap missing providers/counters/stores or select a different mode.
fn run(execution:&NativeRunOwner,prepared_path:&Path,prepared_sha:Hash)->Result<PathBuf>{
    let process=current()?;let user=&process.identity().user_sid;
    let receipt=ImagePin::open(prepared_path,user)?;
    if receipt.hash()!=prepared_sha{return Err("Native TEST exact prepared/checkpoint receipt required".into());}
    let mut p:Prepared=serde_json::from_slice(&receipt.read_bounded(128*1024)?).map_err(err)?;
    let expected=if p.phase==0{p.base.join("native-owner-prepared.json")}else{p.base.join(format!("native-owner-checkpoint-{}.json",p.phase))};
    if prepared_path!=expected||p.previous_process.user_sid!=*user{return Err("Native TEST fixed receipt/current principal".into());}
    require_prepared_context(execution,&p.source_sha,&p.campaign,&p.base)?;fresh(&p.previous_process,process.identity())?;
    let directory=DirectoryPin::open(&p.base,user)?;
    let binding=p.binding()?;let g=p.verified_genesis()?;
    // A predecessor checkpoint is not authoritative history of an unreported
    // counter/work/vote transition. Inspect exact artifacts without opening
    // SQLite or decrypting keys; never roll back the journal to resume signing.
    let provider=p.base.join(FILES[5]);
    let journal=PathBuf::from(format!("{}-journal",provider.to_str().ok_or("Native TEST original journal namespace")?));
    match std::fs::symlink_metadata(&journal){
        Err(e)if e.kind()==std::io::ErrorKind::NotFound=>{},
        Err(e)=>return Err(format!("Native TEST hot-journal observation unknown; provider remains frozen: {e:?}")),
        Ok(_)=>{
            let frozen=FrozenInspection::capture(&provider,&p.base.join(FILES[6]),user,&binding,
                ExpectedSnapshot::Native(p.journal.clone()),&p.previous_process)
                .map_err(|e|format!("Native TEST hot-journal inspection refused; provider remains frozen: {e}"))?;
            let need=frozen.need();let closed=frozen.close_checked();
            return match(need,closed){
                (Ok(RecoveryNeed::ExactAuthorizedTransitionUnavailable),Ok(()))=>Err(
                    "Native TEST hot journal preserved; exact authorized counter/reservation/consumption transition unavailable; provider remains frozen".into()),
                (need,closed)=>Err(format!("Native TEST hot-journal reconciliation unavailable; provider remains frozen: need={need:?}, owned-read-close={closed:?}")),
            };
        }
    }
    let current=file_pins(&p.base,user)?;
    if current.len()!=p.files.len()||current.iter().zip(&p.files).any(|(a,b)|a.native!=b.native||a.sha!=b.sha){
        return Err("Native TEST original file/journal snapshot differs; never repair/reset".into());
    }
    // Every no-follow native database identity is retained across opening and
    // private use. Content preflight above happens before any writable open.
    let holds=FILES.iter().map(|name|DatabasePin::open(&p.base.join(name),user)).collect::<Result<Vec<_>>>()?;
    let store=NativeOwnerStore::reopen_qualified_existing(execution.provider()?,&p.base.join(FILES[5]),&p.base.join(FILES[6]),user,binding,&p.journal)?;
    let mut observer=store.journal_observer()?;
    if p.phase==0{
        if p.journal.counter!=0||p.journal.records!=0||p.journal.work_records!=0{return Err("Native TEST unused initial providers required".into());}
        let(a,b)=store.possession_before_h0()?;let context=store.possession_context();
        for(raw,descriptor,domain)in[(a.as_slice(),p.node_descriptor.as_slice(),mutiny_crypto_v2::Domain::NodeAdmissionPossession),
            (b.as_slice(),p.continuity_descriptor.as_slice(),mutiny_crypto_v2::Domain::ContinuityPossession)]{
            if raw.len()!=1394{return Err("Native TEST initial possession extent".into());}
            let public=mutiny_crypto_v2::PublicKey::decode_descriptor(descriptor).map_err(err)?.0;
            let signature=HybridSignature{ed448:raw[..114].try_into().map_err(err)?,fndsa:raw[114..].try_into().map_err(err)?};
            public.verify(domain,&context,&signature).map_err(err)?;
        }
        if observer.journal_pin()?!=p.journal{return Err("Native TEST possession changed durable provider state".into());}
    }
    let chain=open_chain(&p.base,&g)?;let(head,_)=chain.load().map_err(err)?;
    if head.height!=p.phase{return Err("Native TEST exact continuation height required".into());}
    let timestamp=g.genesis.t0.checked_add(head.height).and_then(|n|n.checked_add(1)).ok_or("Native TEST timestamp overflow")?;
    let runtime=runtime(&p.base,&g,timestamp)?;
    let mut services=A2Services::open(&runtime,&p.base.join(FILES[3]),&p.base.join(FILES[4]),
        mutinyd_v8::candidate_journal_v3::MAX_QUEUE_BYTES,false)?;
    let backend=store.backend(chain,DatabasePin::open(&p.base.join(FILES[0]),user)?,g.genesis.anchor())?;
    let voter=VotingRuntime::open(runtime,&p.base.join(FILES[2]),p.node,None,backend).map_err(err)?;
    let mut owner=Owner::from_existing_test(voter,open_chain(&p.base,&g)?,Duration::from_millis(p.lifetime_ms),
        Arc::new(TestElapsed(Instant::now())),mutiny_consensus_v8::vote_clock_v1::ControlledClock::at(timestamp)).map_err(err)?;
    // Only successful existing-only provider/snapshot reopening in a distinct
    // process may publish H0. No fixture or key generation occurs in this path.
    if p.phase==0{
        receipt.recheck()?;process.recheck()?;directory.recheck()?;
        for hold in &holds{hold.recheck()?;}
        if observer.journal_pin()?!=p.journal{return Err("Native TEST provider changed before H0".into());}
        let draft=ImagePin::open(&p.base.join("native-h0-private-draft.json"),user)?;
        if draft.hash()!=p.artifact_sha{return Err("Native TEST H0 exact draft pin".into());}
        execution.require(&p.source_sha,&p.campaign)?;create(&p.base.join("native-h0-public.json"),&draft.read_bounded(mutinyd_v8::genesis_artifact_v2::MAX_ARTIFACT as u64)?)?;
    }else{
        let h0=ImagePin::open(&p.base.join("native-h0-public.json"),user)?;
        if h0.hash()!=p.artifact_sha{return Err("Native TEST retained H0 changed".into());}h0.recheck()?;
    }
    let parent=owner.voter_mut().validator().head().map_err(err)?;
    let ticket=observer.next_work_ticket()?;
    let prepared=owner.voter_mut().validator().prepare(WorkRequest{expected_parent:&parent,license:p.license,
        worker:p.worker,timestamp,ticket,operations:&[]}).map_err(err)?;
    let(context,_)=owner.voter_mut().validator().current_work_context(&parent,p.license,p.worker,timestamp).map_err(err)?;
    let authority=Authority{work:WorkAuthority{candidate:prepared.candidate.clone(),assignment_sequence:context.assignment_sequence,
        ticket_sequence:ticket,coordinator:context.coordinator,nonce_start:0,nonce_end:0,
        epoch:mutiny_consensus_v8::pow::mining_epoch(timestamp,context.t0).map_err(err)?},
        node_descriptor:p.node_descriptor.clone(),signature:HybridSignature{ed448:[0;114],fndsa:[0;1280]}};
    let signed=owner.voter_mut().sign_node_work(authority,&prepared.body).map_err(err)?;
    let header=WorkHeader{candidate:prepared.candidate,authority:signed.id().map_err(err)?,nonce:0};
    if !mutiny_consensus_v8::pow::meets_target(&header.block_hash(),&header.candidate.target){return Err("Native TEST actual nonce missed target".into());}
    let record=Record{header,authority:signed,body:prepared.body};
    services.preserve(owner.voter_mut().validator(),&record)?;
    let block=record.header.block_hash();
    if owner.voter_mut().restore_a2_candidate(services.journal(),None).map_err(err)?!=Some(block){return Err("Native TEST actual candidate restore differs".into());}
    let mut maker=NoCredential;
    let prevote=owner.fresh_sign(&mut maker,Step::Prevote,Some(block),None,None).map_err(err)?;
    owner.voter_mut().observe(&prevote).map_err(err)?;
    let precommit=owner.fresh_sign(&mut maker,Step::Precommit,Some(block),None,None).map_err(err)?;
    let before_replay=observer.journal_pin()?;
    if owner.replay(Step::Precommit).map_err(err)?.as_ref()!=Some(&precommit)||observer.journal_pin()?!=before_replay{
        return Err("Native TEST exact durable retransmission changed provider state".into());
    }
    let certificate=Certificate{decision:precommit.decision.clone(),votes:vec![precommit]};
    let envelope=BlockEnvelope{header:record.header,authority:record.authority,body:record.body,certificate};
    let capacity=owner.voter_mut().validator().body_capacity(&parent).map_err(err)?;
    let wire=envelope.encode_with_capacity(&capacity).map_err(err)?;
    let installation=owner.voter_mut().install(&wire).map_err(err)?;
    if !installation.canonical.inserted||installation.canonical.finalized.height!=p.phase+1
        ||!matches!(installation.custody,mutinyd_v8::hybrid_voter_v2::CustodyProgress::Ready{..}){
        return Err("Native TEST canonical/custody installation incomplete".into());
    }
    services.reconcile_finalized(owner.voter_mut().validator())?;
    p.journal=observer.journal_pin()?;
    receipt.recheck()?;process.recheck()?;directory.recheck()?;for hold in &holds{hold.recheck()?;}
    // RAII releases these owners before hashing the next exact checkpoint.
    // The next process separately verifies this process has exited; native/VFS
    // close and power-loss qualification remain independent requirements.
    drop(owner);drop(services);drop(observer);drop(holds);
    p.files=file_pins(&p.base,user)?;p.phase=p.phase.checked_add(1).ok_or("Native TEST phase overflow")?;
    p.previous_process=process.identity().clone();
    let output=p.base.join(format!("native-owner-checkpoint-{}.json",p.phase));
    execution.require(&p.source_sha,&p.campaign)?;create(&output,&serde_json::to_vec(&p).map_err(err)?)?;Ok(output)
}
fn decode_hash(text:&str)->Result<Hash>{
    if text.len()!=64{return Err("Native TEST exact hash argument".into());}
    hex::decode(text).map_err(err)?.try_into().map_err(err)
}
/// Sole explicitly selected CLI. Fixed wallet and normal shipping modes never
/// call this module; malformed native-owner flags refuse without UI fallback.
pub(crate) fn run_if_requested()->Option<Result<()>>{
    if !std::env::args().nth(1).is_some_and(|s|s.starts_with("--native-owner-test-")){return None;}
    // A plain CLI has no authenticated Root-selected native receiver. The
    // trusted launcher must call dispatch_selected with admitted actual inputs;
    // no environment hash, GUI request or fallback selects one here.
    Some(Err("Root-selected live native execution receiver required before provider effects".into()))
}
pub(super) fn run_with_receiver(execution:&NativeRunOwner)->Result<()>{
    let args:Vec<String>=std::env::args().collect();
    let output=match args.get(1).map(String::as_str){
        Some("--native-owner-test-prepare")if args.len()==8=>prepare(execution,Path::new(&args[2]),decode_hash(&args[3])?,
            Path::new(&args[4]),decode_hash(&args[5])?,args[6].clone(),args[7].parse().map_err(err)?)?,
        Some("--native-owner-test-run")if args.len()==4=>run(execution,Path::new(&args[2]),decode_hash(&args[3])?)?,
        _=>return Err("Exact native-owner TEST command arguments required".into())
    };
    println!("NativeOwnerTest durable public receipt: {}",output.display());Ok(())
}