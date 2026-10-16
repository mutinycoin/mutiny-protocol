//! EXTERNAL SOURCE ONLY / UNCOMPILED. Immutable public native-boundary records.
//! A live-process snapshot is NOT an exit, wallet approval or finality substitute.
//! External supervisor must observe all four original processes naturally closed,
//! then pin this actual checkpoint before any existing-only startup.
use super::{control_codec::Context,process_auth::{Identity,VerifiedProcess},
 continuous_passive::{VaultPin,WirePin,HeadPin},test_signer_store::{Binding,JournalPin},cache_snapshot::Snapshot};
use mutiny_consensus_v8::Hash;
use std::{path::{Path,PathBuf},io::Write};
type Result<T>=std::result::Result<T,String>;
pub(super) const MARKER:&str="MUTINY-W15-NONSHIPPING-ACTUAL-COMPLETED-SHUTDOWN-V1";
#[derive(Clone,serde::Serialize,serde::Deserialize)] #[serde(deny_unknown_fields)]
pub(super) struct ProviderPin {pub initial_root:Hash,pub original_store_identities:Hash,pub native_custody_identity:Hash,pub native_guard_identity:Hash,
 pub node_descriptor:Vec<u8>,pub continuity_descriptor:Vec<u8>,pub journal:JournalPin}
impl ProviderPin {pub(super) fn observed(b:&Binding,journal:JournalPin)->Self{Self{initial_root:b.initial_root,original_store_identities:b.original_store_identities,native_custody_identity:b.native_custody_identity,native_guard_identity:b.native_guard_identity,node_descriptor:b.node_descriptor.clone(),continuity_descriptor:b.continuity_descriptor.clone(),journal}}}
#[derive(Clone,serde::Serialize,serde::Deserialize)] #[serde(deny_unknown_fields)]
pub(super) struct ServiceSnapshot {pub format:String,pub context:super::bootstrap::ContextPin,pub actual_process:Identity,
 pub completed_between_actions:bool,pub observed_head:HeadPin,pub canonical_paths:[PathBuf;6],pub canonical_native:[Hash;6],
 pub transports:[super::cache_snapshot::Object;3],pub caches:[Snapshot;4],pub provider:ProviderPin,pub license:Hash,pub backup_license:Hash,pub buyer_authority:Hash,pub worker_published:bool,
 pub own_replay_confirmed:Vec<WirePin>}
#[derive(Clone,serde::Serialize,serde::Deserialize)] #[serde(deny_unknown_fields)]
pub(super) struct RoleSnapshot {pub format:String,pub context:super::bootstrap::ContextPin,pub actual_process:Identity,
 pub transport:super::cache_snapshot::Object,pub observed_head:HeadPin,pub vault:VaultPin,pub marker_sha256:Hash,pub canonical_native:Hash,pub side_native:[Hash;4]}
pub(super) fn pin_context(c:Context)->super::bootstrap::ContextPin{super::bootstrap::ContextPin{campaign:c.campaign,source:c.source,h0:c.h0,genesis:c.genesis,fingerprint:c.fingerprint}}
/// Sole write path is create-new public JSON; never serialized secret envelope,
/// password, sealed preimage or private key. Caller supplies actual observations.
pub(super) fn publish<T:serde::Serialize>(root:&Path,label:&str,value:&T)->Result<PathBuf>{
 if !root.is_absolute()||!matches!(label,"service"|"role1"|"role2"|"role3"){return Err("Exact native shutdown public namespace required".into());}
 let actual=VerifiedProcess::observe_created_process(std::process::id())?;let owner=VerifiedProcess::open(&actual)?;owner.recheck()?;
 let path=root.join(format!("shutdown-{label}-{}-{}.json",actual.pid,actual.start_filetime));
 let raw=serde_json::to_vec_pretty(value).map_err(|e|e.to_string())?;if raw.len()>2*1024*1024{return Err("Public shutdown snapshot byte quota".into());}
 let mut out=std::fs::OpenOptions::new().write(true).create_new(true).open(&path).map_err(|e|e.to_string())?;out.write_all(&raw).map_err(|e|e.to_string())?;out.sync_all().map_err(|e|e.to_string())?;owner.recheck()?;Ok(path)
}
/// Checkpoint assembly uses independently hash-pinned actual records, never
/// request fields. It refuses any disagreement rather than repairing histories.
pub(super) fn assemble(service:&ServiceSnapshot,roles:&[RoleSnapshot;3],mut external:super::restart_spec::RestartSpec)->Result<super::restart_spec::RestartSpec>{
 if service.format!=MARKER||!service.completed_between_actions||service.own_replay_confirmed.is_empty(){return Err("Actual completed-action service checkpoint with own replay required".into());}
 let c=service.context.context();let h=&service.observed_head;
 if external.context.context()!=c||external.previous_processes[0]!=service.actual_process||external.height!=h.height||external.block!=h.block||external.root!=h.root
  ||external.canonical_native!=service.canonical_native||external.six_pins().paths!=service.canonical_paths||external.license!=service.license||external.backup_license!=service.backup_license||external.buyer_authority!=service.buyer_authority||external.worker_published!=service.worker_published{
  return Err("External originals differ from actual service shutdown record".into());
 }
 for i in 0..6{let actual=if i<3{&service.transports[i]}else{&roles[i-3].transport};if external.transports[i]!=*actual{return Err("Actual original transport-cache peer/fragment/ack rows differ".into());}}
 let p=&service.provider;let expected=external.binding();
 if expected.initial_root!=p.initial_root||expected.original_store_identities!=p.original_store_identities||expected.native_custody_identity!=p.native_custody_identity||expected.native_guard_identity!=p.native_guard_identity||expected.node_descriptor!=p.node_descriptor||expected.continuity_descriptor!=p.continuity_descriptor||external.provider.journal!=p.journal{
  return Err("Actual original provider/counter/lock journal differs from checkpoint".into());
 }
 if serde_json::to_vec(&external.confirmed).map_err(|e|e.to_string())?!=serde_json::to_vec(&service.own_replay_confirmed).map_err(|e|e.to_string())?{return Err("Exact raw wire/replay list differs from actual service snapshot".into());}
 for (i,r) in roles.iter().enumerate(){
  if r.format!=MARKER||r.context.context()!=c||r.observed_head.height!=h.height||r.observed_head.block!=h.block||r.observed_head.root!=h.root||r.actual_process!=external.previous_processes[i+1]||r.vault.role!=i as u8+1
   ||serde_json::to_vec(&r.vault).map_err(|e|e.to_string())?!=serde_json::to_vec(&external.roles[i].saved).map_err(|e|e.to_string())?||r.marker_sha256!=external.roles[i].marker_sha256||r.canonical_native!=external.roles[i].canonical_native||r.side_native!=external.roles[i].side_native{
   return Err("Actual initialized role/head/queue/conditions/pointers/reservations differ".into());
  }
 }
 // A subsequent reader still authenticates all original files and all own replays.
 // Assembly itself neither opens private custody nor establishes process closure.
 external.cache_snapshots=service.caches.clone();external.validate()?;Ok(external)
}
#[cfg(test)] mod tests {
 use super::*;
 #[test] fn source_snapshot_records_do_not_treat_live_process_as_natural_exit(){let actual=VerifiedProcess::observe_created_process(std::process::id()).unwrap();assert!(super::super::process_auth::historical_process_closed(&actual).is_err());}
}

// EXTERNAL SOURCE-ONLY successor. Assemble only independently hash-pinned
// PUBLIC shutdown records, after all original processes naturally closed.
// This caller has no Controller, wallet signing, provider key, provisioner,
// canonical mutable-open or service-creation capability.
pub(super) const ASSEMBLY_MARKER:&str="MUTINY-W15-NONSHIPPING-PUBLIC-SHUTDOWN-ASSEMBLER-V1";
struct AssemblyArgs {
    service:super::continuous_passive::PathPin,
    roles:[super::continuous_passive::PathPin;3],
    draft:super::continuous_passive::PathPin,
    output:PathBuf,
}
fn assembly_args(values:&[std::ffi::OsString])->Result<AssemblyArgs>{
    let [s_flag,s,s_sha_flag,s_sha,a_flag,a,a_sha_flag,a_sha,c_flag,c,c_sha_flag,c_sha,t_flag,t,t_sha_flag,t_sha,d_flag,d,d_sha_flag,d_sha,o_flag,o]=values
        else{return Err("Exact four public snapshot pins, draft pin and NEW output pairs required".into());};
    if s_flag!="--service-snapshot"||s_sha_flag!="--service-snapshot-sha"
        ||a_flag!="--role1-snapshot"||a_sha_flag!="--role1-snapshot-sha"
        ||c_flag!="--role2-snapshot"||c_sha_flag!="--role2-snapshot-sha"
        ||t_flag!="--role3-snapshot"||t_sha_flag!="--role3-snapshot-sha"
        ||d_flag!="--checkpoint-draft"||d_sha_flag!="--checkpoint-draft-sha"||o_flag!="--new-output"{
        return Err("Unexpected public shutdown assembly selector".into());
    }
    let pin=|path:&std::ffi::OsStr,sha:&std::ffi::OsStr|->Result<super::continuous_passive::PathPin>{
        let path=PathBuf::from(path);
        let sha256=super::control_files::hash(sha.to_str().ok_or("Public pin Unicode")?)?;
        if !path.is_absolute()||path.to_str().is_none_or(|s|s.len()>4096)
            ||path.components().any(|p|matches!(p,std::path::Component::CurDir|std::path::Component::ParentDir))||sha256==[0;32]{
            return Err("Bounded absolute public path/exact SHA required".into());
        }
        Ok(super::continuous_passive::PathPin{path,sha256})
    };
    let args=AssemblyArgs{service:pin(s,s_sha)?,roles:[pin(a,a_sha)?,pin(c,c_sha)?,pin(t,t_sha)?],draft:pin(d,d_sha)?,output:PathBuf::from(o)};
    let mut paths=std::collections::BTreeSet::new();
    for p in std::iter::once(&args.service).chain(args.roles.iter()).chain(std::iter::once(&args.draft)){
        if !paths.insert(p.path.clone()){return Err("All independently pinned records must be distinct".into());}
    }
    if !args.output.is_absolute()||args.output.to_str().is_none_or(|s|s.len()>4096)
        ||args.output.components().any(|p|matches!(p,std::path::Component::CurDir|std::path::Component::ParentDir))
        ||!paths.insert(args.output.clone())||args.output.file_name().is_none(){return Err("Distinct NEW public output path required".into());}
    Ok(args)
}
fn closed_originals(previous:&[Identity;4])->Result<()>{
    for original in previous{super::process_auth::historical_process_closed(original)?;}Ok(())
}
fn read_public<T:serde::de::DeserializeOwned>(pin:&super::continuous_passive::PathPin,own:&VerifiedProcess)->Result<T>{
    // The same held actual-image/ancestor path contract used by the native
    // application bounds size BEFORE allocation, verifies hash, and rechecks.
    let raw=super::bootstrap::bounded(&pin.path,Some(pin.sha256),2*1024*1024,own)?;
    serde_json::from_slice(&raw).map_err(|e|format!("Bounded public shutdown record: {e}"))
}
fn assemble_public(args:AssemblyArgs)->Result<()> {
    let observed=VerifiedProcess::observe_created_process(std::process::id())?;
    let own=VerifiedProcess::open(&observed)?;own.recheck()?;
    let service:ServiceSnapshot=read_public(&args.service,&own)?;
    let roles:[RoleSnapshot;3]=[
        read_public(&args.roles[0],&own)?,read_public(&args.roles[1],&own)?,read_public(&args.roles[2],&own)?];
    let draft:super::restart_spec::RestartSpec=read_public(&args.draft,&own)?;
    // Missing/live/wrong original tuples are refusals. No process signal,
    // numerical sleep, fake exit or copy of a private provider is used.
    closed_originals(&draft.previous_processes)?;
    // Keep every original cache/archive handle pinned through publication.
    let cache_holds=service.caches.iter().map(|c|c.preflight(&observed.user_sid)).collect::<Result<Vec<_>>>()?;
    let captured=actual_pending(&service,&observed.user_sid)?;
    if serde_json::to_vec(&captured).map_err(|e|e.to_string())?!=serde_json::to_vec(&draft.caches).map_err(|e|e.to_string())?{
        return Err("Checkpoint pending cache inputs differ from actual read-only original rows".into());
    }
    let complete=assemble(&service,&roles,draft)?;
    // A historical nonempty queue alone is insufficient for this acceptance
    // checkpoint. Each original role must retain an actual Pending row; exact
    // status/raw/pointers are independently checked again at native reopen.
    if complete.roles.iter().any(|r|!r.saved.queued.iter().any(|q|q.status=="Pending"))
        ||complete.roles.iter().all(|r|r.saved.reserved_inputs.is_empty())
        ||complete.roles.iter().all(|r|r.saved.payment_wire_commitments.is_empty())
        ||complete.provider.journal.tip==0{
        return Err("Actual Pending rows/raw payment/reserved inputs and nonempty durable provider journal required".into());
    }
    closed_originals(&complete.previous_processes)?;own.recheck()?;
    let directory=args.output.parent().ok_or("Existing public output parent")?;
    let held_directory=super::image_pin::DirectoryPin::open(directory,&observed.user_sid)?;
    match std::fs::symlink_metadata(&args.output){
        Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{},
        Ok(_)=>return Err("Output already exists; preserve it".into()),
        Err(e)=>return Err(format!("Public output absence not established: {e}")),
    }
    let raw=serde_json::to_vec_pretty(&complete).map_err(|e|e.to_string())?;
    if raw.len()>2*1024*1024{return Err("Public checkpoint byte quota".into());}
    let mut output=std::fs::OpenOptions::new().write(true).create_new(true).open(&args.output).map_err(|e|e.to_string())?;
    output.write_all(&raw).map_err(|e|e.to_string())?;output.sync_all().map_err(|e|e.to_string())?;drop(output);
    let held_output=super::image_pin::ImagePin::open(&args.output,&observed.user_sid)?;
    use sha2::Digest;
    let sha:[u8;32]=sha2::Sha256::digest(&raw).into();
    if held_output.hash()!=sha{return Err("CreateNew public checkpoint readback differs".into());}
    // Re-read exact source records before publication credit; originals remain
    // immutable, and consumer separately repeats all six own-Genesis replays.
    let again:ServiceSnapshot=read_public(&args.service,&own)?;
    let again_roles:[RoleSnapshot;3]=[read_public(&args.roles[0],&own)?,read_public(&args.roles[1],&own)?,read_public(&args.roles[2],&own)?];
    let again_draft:super::restart_spec::RestartSpec=read_public(&args.draft,&own)?;
    let again=assemble(&again,&again_roles,again_draft)?;
    if serde_json::to_vec_pretty(&again).map_err(|e|e.to_string())?!=raw{return Err("Pinned public records changed during assembly; retain partial output".into());}
    let actual_again=actual_pending(&service,&observed.user_sid)?;
    if serde_json::to_vec(&actual_again).map_err(|e|e.to_string())?!=serde_json::to_vec(&captured).map_err(|e|e.to_string())?{
        return Err("Actual pending cache rows changed during assembly; retain partial output".into());
    }
    for held in &cache_holds{held.recheck()?;}
    closed_originals(&complete.previous_processes)?;held_directory.recheck()?;held_output.recheck()?;own.recheck()?;
    println!("{} {}",ASSEMBLY_MARKER,hex::encode(sha));
    Ok(())
}
pub(super) fn assembly_if_requested()->Option<Result<()>>{
    let args=std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.first().and_then(|s|s.to_str())==Some("--continuous-capture-public-restart-caches"){
        return Some(cache_capture_args(&args[1..]).and_then(capture_public_caches));
    }
    if args.first().and_then(|s|s.to_str())!=Some("--continuous-assemble-public-restart"){return None;}
    Some(assembly_args(&args[1..]).and_then(assemble_public))
}
#[cfg(test)] mod assembly_boundary_tests {
    use super::*;
    #[test] fn actual_live_original_process_never_qualifies_as_closed_for_assembly(){
        let actual=VerifiedProcess::observe_created_process(std::process::id()).unwrap();
        assert!(closed_originals(&std::array::from_fn(|_|actual.clone())).is_err());
    }
    #[test] fn exact_public_assembly_selector_bounds_do_not_open_or_initialize_any_store(){
        assert!(assembly_args(&[]).is_err());
        assert!(assembly_args(&["--service-snapshot".into(),"relative".into()]).is_err());
    }
}

// Exact read-only pending inventory companion. Cache status is never finality.
// No writable pool/runtime constructor or migration is used in this capture.
fn capture_pending(cache:&super::cache_snapshot::Snapshot,user:&[u8],genesis:Hash,fingerprint:Hash)->Result<super::restart_spec::CacheResume>{
    let held=cache.preflight(user)?;
    let native=super::image_pin::DatabasePin::open(&cache.main.path,user)?;
    if native.native_id_hash()!=cache.main.native_id{return Err("Original pending cache native identity differs".into());}
    let file=std::fs::OpenOptions::new().read(true).open(&cache.main.path).map_err(|e|e.to_string())?;
    native.check_opened(&file)?;drop(file);
    let db=rusqlite::Connection::open_with_flags(&cache.main.path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).map_err(|e|e.to_string())?;
    db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON; BEGIN;").map_err(|e|e.to_string())?;
    let table=if cache.submission{"context"}else{"context_v2"};
    let (g,f):(Vec<u8>,Vec<u8>)=db.query_row(&format!("SELECT CASE WHEN typeof(genesis)='blob' AND length(genesis)=32 THEN genesis ELSE NULL END,CASE WHEN typeof(fingerprint)='blob' AND length(fingerprint)=32 THEN fingerprint ELSE NULL END FROM {table} WHERE id=1"),[],|r|Ok((r.get(0)?,r.get(1)?))).map_err(|e|e.to_string())?;
    let n:i64=db.query_row(&format!("SELECT count(*) FROM {table}"),[],|r|r.get(0)).map_err(|e|e.to_string())?;
    if n!=1||g!=genesis||f!=fingerprint{return Err("Pending capture exact original network context required".into());}
    let bounds=if cache.submission{
        "SELECT count(*),coalesce(sum(length(raw)),0),coalesce(sum(CASE WHEN typeof(id)!='blob' OR length(id)!=32 OR typeof(class)!='integer' OR class NOT IN(0,1) OR typeof(raw)!='blob' OR length(raw) NOT BETWEEN 1 AND 16384 OR typeof(status)!='blob' OR length(status) NOT BETWEEN 1 AND 768 THEN 1 ELSE 0 END),0) FROM entries"
    }else{
        "SELECT count(*),coalesce(sum(length(raw)),0),coalesce(sum(CASE WHEN typeof(id)!='blob' OR length(id)!=32 OR typeof(raw)!='blob' OR length(raw) NOT BETWEEN 1 AND 16384 THEN 1 ELSE 0 END),0) FROM lifecycle_v2 WHERE status='PENDING'"
    };
    let (count,bytes,bad):(i64,i64,i64)=db.query_row(bounds,[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|e|e.to_string())?;
    if !(0..=65536).contains(&count)||!(0..=64*1024*1024).contains(&bytes)||bad!=0{return Err("Pending capture pre-fetch type/count/whole-byte bounds".into());}
    let query=if cache.submission{"SELECT id,class,raw,status FROM entries ORDER BY id"}else{"SELECT id,0,raw,NULL FROM lifecycle_v2 WHERE status='PENDING' ORDER BY id"};
    let mut statement=db.prepare(query).map_err(|e|e.to_string())?;
    let mut rows=statement.query([]).map_err(|e|e.to_string())?;
    let mut pending=Vec::new();let mut observed=0i64;
    while let Some(row)=rows.next().map_err(|e|e.to_string())?{
        observed+=1;
        let id:Vec<u8>=row.get(0).map_err(|e|e.to_string())?;
        let id:Hash=id.try_into().map_err(|_|"Actual pending ID width")?;
        let list:i64=row.get(1).map_err(|e|e.to_string())?;
        let raw:Vec<u8>=row.get(2).map_err(|e|e.to_string())?;
        let active=if cache.submission{
            let status:Vec<u8>=row.get(3).map_err(|e|e.to_string())?;
            let report=mutiny_consensus_v8::submission_v1::StatusReport::decode(&status).map_err(|e|format!("Actual pool status decode: {e:?}"))?;
            if report.entries.len()!=1||report.entries[0].id!=id{return Err("Actual status belongs to another pending ID".into());}
            matches!(report.entries[0].status,mutiny_consensus_v8::submission_v1::Status::Pending|mutiny_consensus_v8::submission_v1::Status::Unfinalized{..})
        }else{true};
        if active{
            if pending.len()>=64||!matches!(list,0|1){return Err("Finite pending checkpoint list quota/class".into());}
            let(_,actual)=mutiny_consensus_v8::operation_index_v2::operation_id(list as u8,&raw).map_err(|e|format!("Actual signed public carrier: {e:?}"))?;
            if actual!=id{return Err("Pending raw native ID differs".into());}
            pending.push(super::restart_spec::CacheEntry{id,wire_commitment:mutiny_consensus_v8::domain_hash(mutiny_consensus_v8::operation_index_v2::WIRE_DOMAIN,&raw)});
        }
    }
    if observed!=count{return Err("Stable pending capture row count differs".into());}
    drop(rows);drop(statement);db.execute_batch("ROLLBACK;").map_err(|e|e.to_string())?;drop(db);
    native.recheck()?;held.recheck()?;let after=cache.preflight(user)?;after.recheck()?;
    Ok(super::restart_spec::CacheResume{path:cache.main.path.clone(),native_id:cache.main.native_id,submission:cache.submission,pending})
}

// Public cache preparation only. These local statuses are NEVER finality.
const CACHE_CAPTURE_MARKER:&str="MUTINY-W15-NONSHIPPING-PUBLIC-READONLY-PENDING-CACHE-CAPTURE-V1";
#[derive(serde::Serialize)]
struct CacheCapture {format:&'static str,context:super::bootstrap::ContextPin,
    original_service_process:Identity,caches:[super::restart_spec::CacheResume;4]}
fn actual_pending(service:&ServiceSnapshot,user:&[u8])->Result<[super::restart_spec::CacheResume;4]>{
    let c=service.context.context();
    let values=service.caches.iter().map(|cache|capture_pending(cache,user,c.genesis,c.fingerprint)).collect::<Result<Vec<_>>>()?;
    values.try_into().map_err(|_|"Exactly four retained cache snapshots required".into())
}
struct CacheCaptureArgs {service:super::continuous_passive::PathPin,output:PathBuf}
fn cache_capture_args(values:&[std::ffi::OsString])->Result<CacheCaptureArgs>{
    let [flag,path,sha_flag,sha,out_flag,out]=values else{return Err("Exact public service SHA pin and NEW output required".into());};
    if flag!="--service-snapshot"||sha_flag!="--service-snapshot-sha"||out_flag!="--new-output"{
        return Err("Unexpected read-only cache capture selector".into());
    }
    let path=PathBuf::from(path);let output=PathBuf::from(out);
    for p in [&path,&output]{if !p.is_absolute()||p.to_str().is_none_or(|s|s.len()>4096)
        ||p.components().any(|p|matches!(p,std::path::Component::CurDir|std::path::Component::ParentDir))||p.file_name().is_none(){return Err("Bounded absolute public cache capture paths required".into());}}
    let sha256=super::control_files::hash(sha.to_str().ok_or("Exact public cache pin Unicode")?)?;
    if sha256==[0;32]||path==output{return Err("Distinct NEW cache capture and exact service SHA pin required".into());}
    Ok(CacheCaptureArgs{service:super::continuous_passive::PathPin{path,sha256},output})
}
fn capture_public_caches(args:CacheCaptureArgs)->Result<()> {
    let observed=VerifiedProcess::observe_created_process(std::process::id())?;
    let own=VerifiedProcess::open(&observed)?;own.recheck()?;
    let service:ServiceSnapshot=read_public(&args.service,&own)?;
    if service.format!=MARKER||!service.completed_between_actions||service.own_replay_confirmed.is_empty(){
        return Err("Exact completed public service shutdown snapshot required for read-only cache capture".into());
    }
    // Only the service closure is checked by this PREPARATION mode. Assembly
    // still requires all four actual original processes naturally closed.
    super::process_auth::historical_process_closed(&service.actual_process)?;
    let held=service.caches.iter().map(|c|c.preflight(&observed.user_sid)).collect::<Result<Vec<_>>>()?;
    let caches=actual_pending(&service,&observed.user_sid)?;
    let result=CacheCapture{format:CACHE_CAPTURE_MARKER,context:service.context.clone(),original_service_process:service.actual_process.clone(),caches};
    let raw=serde_json::to_vec_pretty(&result).map_err(|e|e.to_string())?;
    if raw.len()>2*1024*1024{return Err("Bounded public cache capture byte quota".into());}
    let parent=args.output.parent().ok_or("Existing capture output parent")?;
    let directory=super::image_pin::DirectoryPin::open(parent,&observed.user_sid)?;
    match std::fs::symlink_metadata(&args.output){Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{},Ok(_)=>return Err("Capture output exists; preserve it".into()),Err(e)=>return Err(format!("Capture output absence not established: {e}"))}
    let mut output=std::fs::OpenOptions::new().write(true).create_new(true).open(&args.output).map_err(|e|e.to_string())?;
    output.write_all(&raw).map_err(|e|e.to_string())?;output.sync_all().map_err(|e|e.to_string())?;drop(output);
    let readback=super::image_pin::ImagePin::open(&args.output,&observed.user_sid)?;
    use sha2::Digest;
    let hash:[u8;32]=sha2::Sha256::digest(&raw).into();
    if readback.hash()!=hash{return Err("Public cache capture CreateNew readback differs".into());}
    let again:ServiceSnapshot=read_public(&args.service,&own)?;
    if serde_json::to_vec(&again).map_err(|e|e.to_string())?!=serde_json::to_vec(&service).map_err(|e|e.to_string())?
        ||serde_json::to_vec(&actual_pending(&again,&observed.user_sid)?).map_err(|e|e.to_string())?!=serde_json::to_vec(&result.caches).map_err(|e|e.to_string())?{
        return Err("Original cache snapshot or actual pending rows changed; retain partial capture".into());
    }
    for h in &held{h.recheck()?;}
    super::process_auth::historical_process_closed(&service.actual_process)?;
    directory.recheck()?;readback.recheck()?;own.recheck()?;
    println!("{} {}",CACHE_CAPTURE_MARKER,hex::encode(hash));Ok(())
}
#[cfg(test)] mod actual_public_capture_tests {
    use super::*;
    use mutiny_consensus_v8::{transactions_v2::{Transfer,Input},transactions::{OutPoint,Output},submission_v1::{Status,StatusEntry,StatusReport}};
    fn owned()->(PathBuf,Vec<u8>){
        let actual=VerifiedProcess::observe_created_process(std::process::id()).unwrap();
        let nonce=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let root=std::env::temp_dir().join(format!("w15-public-cache-capture-{}-{nonce}",actual.pid));
        assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&root).unwrap());(root,actual.user_sid)
    }
    fn signed()->(Hash,Vec<u8>){
        // Fixed PUBLIC TEST phrase only. This proves actual signed-carrier
        // decoding, not UTXO authority, pool admission or canonical execution.
        let key=mutiny_crypto_v2::HybridKey::wallet_restore(&("abandon ".repeat(23)+"art"),mutiny_crypto_v2::Role::WalletOwner).unwrap();
        let mut tx=Transfer{network:mutiny_consensus_v8::NETWORK_ID,genesis:[11;32],fingerprint:[12;32],created_height:1,expiry_height:145,fee:50_000,
            inputs:vec![Input::unsigned(OutPoint{transaction:[21;32],index:0},key.public(),1).unwrap()],
            outputs:vec![Output{owner:key.public().address_id(1).unwrap(),atoms:1_000_000}]};
        tx.sign_input(0,&key).unwrap();tx.verify_signatures().unwrap();
        let raw=tx.encode().unwrap();let(_,id)=mutiny_consensus_v8::operation_index_v2::operation_id(0,&raw).unwrap();(id,raw)
    }
    fn payment(path:&Path,user:&[u8],id:Hash,raw:&[u8]){
        super::super::test_signer_store::create_new_private_leaf(path,user).unwrap();
        let db=rusqlite::Connection::open(path).unwrap();
        db.execute_batch("PRAGMA application_id=1297435954;PRAGMA user_version=2;CREATE TABLE context_v2(id INTEGER PRIMARY KEY,genesis BLOB,fingerprint BLOB);CREATE TABLE lifecycle_v2(id BLOB PRIMARY KEY,raw BLOB,status TEXT);").unwrap();
        db.execute("INSERT INTO context_v2 VALUES(1,?1,?2)",rusqlite::params![[11u8;32],[12u8;32]]).unwrap();
        db.execute("INSERT INTO lifecycle_v2 VALUES(?1,?2,'PENDING')",rusqlite::params![id,raw]).unwrap();
    }
    fn pool(path:&Path,user:&[u8],id:Hash,raw:&[u8],status:Status){
        super::super::test_signer_store::create_new_private_leaf(path,user).unwrap();
        let db=rusqlite::Connection::open(path).unwrap();
        db.execute_batch("PRAGMA application_id=1297437520;PRAGMA user_version=1;CREATE TABLE context(id INTEGER PRIMARY KEY,genesis BLOB,fingerprint BLOB);CREATE TABLE entries(id BLOB PRIMARY KEY,class INTEGER,raw BLOB,status BLOB);").unwrap();
        db.execute("INSERT INTO context VALUES(1,?1,?2)",rusqlite::params![[11u8;32],[12u8;32]]).unwrap();
        let report=StatusReport{tip_height:1,tip_block:[23;32],entries:vec![StatusEntry{id,status}]}.encode().unwrap();
        db.execute("INSERT INTO entries VALUES(?1,0,?2,?3)",rusqlite::params![id,raw,report]).unwrap();
    }
    #[test] fn actual_signed_public_payment_pending_capture_and_wrong_context_refusal_leave_rows_unchanged(){
        let(root,user)=owned();let path=root.join("original-payment.sqlite");let(id,raw)=signed();payment(&path,&user,id,&raw);
        let(snapshot,held)=super::super::cache_snapshot::Snapshot::observe(&path,false,&user).unwrap();
        let good=capture_pending(&snapshot,&user,[11;32],[12;32]).unwrap();
        assert_eq!(good.pending.len(),1);assert_eq!(good.pending[0].id,id);
        assert_eq!(good.pending[0].wire_commitment,mutiny_consensus_v8::domain_hash(mutiny_consensus_v8::operation_index_v2::WIRE_DOMAIN,&raw));
        assert_eq!(good.native_id,snapshot.main.native_id);assert_eq!(good.path,path);assert!(!good.submission);
        let bad=capture_pending(&snapshot,&user,[99;32],[12;32]).err().expect("Wrong actual context accepted");assert!(bad.contains("network context"));
        snapshot.preflight(&user).unwrap();held.recheck().unwrap();
    }
    #[test] fn actual_pool_status_id_and_whole_snapshot_pending_capture_controls(){
        let(root,user)=owned();let path=root.join("original-pool.sqlite");let(id,raw)=signed();pool(&path,&user,id,&raw,Status::Pending);
        let(snapshot,held)=super::super::cache_snapshot::Snapshot::observe(&path,true,&user).unwrap();
        assert_eq!(capture_pending(&snapshot,&user,[11;32],[12;32]).unwrap().pending[0].id,id);
        snapshot.preflight(&user).unwrap();held.recheck().unwrap();
        let db=rusqlite::Connection::open(&path).unwrap();
        let wrong=StatusReport{tip_height:1,tip_block:[23;32],entries:vec![StatusEntry{id:[99;32],status:Status::Pending}]}.encode().unwrap();
        db.execute("UPDATE entries SET status=?1",[wrong]).unwrap();drop(db);
        assert!(capture_pending(&snapshot,&user,[11;32],[12;32]).is_err(),"Changed whole original snapshot accepted");
        let(bad,held_bad)=super::super::cache_snapshot::Snapshot::observe(&path,true,&user).unwrap();
        let refusal=capture_pending(&bad,&user,[11;32],[12;32]).err().expect("Wrong status ID accepted");assert!(refusal.contains("another pending ID"));held_bad.recheck().unwrap();
        let db=rusqlite::Connection::open(&path).unwrap();
        let unfinalized=StatusReport{tip_height:1,tip_block:[23;32],entries:vec![StatusEntry{id,status:Status::Unfinalized{height:2,block:[23;32]}}]}.encode().unwrap();
        db.execute("UPDATE entries SET status=?1",[unfinalized]).unwrap();drop(db);
        let(unfinalized,held_next)=super::super::cache_snapshot::Snapshot::observe(&path,true,&user).unwrap();
        assert_eq!(capture_pending(&unfinalized,&user,[11;32],[12;32]).unwrap().pending.len(),1,"Unfinalized is retained pending, never finality");held_next.recheck().unwrap();
        let db=rusqlite::Connection::open(&path).unwrap();db.execute("UPDATE entries SET raw=?1",[vec![7u8;16385]]).unwrap();drop(db);
        let(oversized,held_last)=super::super::cache_snapshot::Snapshot::observe(&path,true,&user).unwrap();
        let refusal=capture_pending(&oversized,&user,[11;32],[12;32]).err().expect("Oversized raw accepted");assert!(refusal.contains("pre-fetch"));held_last.recheck().unwrap();
    }
}
#[cfg(test)] mod public_assembly_structure_model_tests {
    use super::*;
    // Explicit structural MODEL only: no original process closure, native
    // files, actual own replay, custody reopening or mounted approval claimed.
    #[test] fn matching_public_structure_model_assembles_and_each_record_disagreement_refuses(){
        let draft=super::super::restart_spec::model_for_shutdown_assembly();
        let service=ServiceSnapshot{format:MARKER.into(),context:draft.context.clone(),actual_process:draft.previous_processes[0].clone(),completed_between_actions:true,
            observed_head:HeadPin{height:draft.height,block:draft.block,root:draft.root},canonical_paths:draft.six_pins().paths,canonical_native:draft.canonical_native,
            transports:std::array::from_fn(|i|draft.transports[i].clone()),caches:draft.cache_snapshots.clone(),
            provider:ProviderPin::observed(&draft.binding(),draft.provider.journal.clone()),license:draft.license,backup_license:draft.backup_license,buyer_authority:draft.buyer_authority,
            worker_published:draft.worker_published,own_replay_confirmed:draft.confirmed.clone()};
        let roles:[RoleSnapshot;3]=std::array::from_fn(|i|RoleSnapshot{format:MARKER.into(),context:draft.context.clone(),actual_process:draft.previous_processes[i+1].clone(),transport:draft.transports[i+3].clone(),
            observed_head:service.observed_head.clone(),vault:draft.roles[i].saved.clone(),marker_sha256:draft.roles[i].marker_sha256,canonical_native:draft.roles[i].canonical_native,side_native:draft.roles[i].side_native});
        let complete=assemble(&service,&roles,draft.clone()).unwrap();
        assert_eq!(serde_json::to_vec(&complete).unwrap(),serde_json::to_vec(&draft).unwrap());
        for fault in 0..12{let mut s=service.clone();let mut r=roles.clone();match fault{
            0=>s.completed_between_actions=false,1=>s.own_replay_confirmed.clear(),2=>s.observed_head.root=[99;32],3=>s.context.fingerprint=[99;32],
            4=>s.provider.journal.tip+=1,5=>s.transports[0].rows=[99;32],6=>s.canonical_native[0]=[99;32],7=>r[0].actual_process.start_filetime+=1,
            8=>r[1].vault.queued[0].status="Replaced".into(),9=>r[2].side_native[0]=[99;32],10=>r[0].transport.rows=[99;32],_=>r[2].observed_head.height+=1
        }assert!(assemble(&s,&r,draft.clone()).is_err(),"Public structural disagreement{fault}");}
    }
}