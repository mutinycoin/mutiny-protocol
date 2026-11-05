//! EXTERNAL SOURCE ONLY. Read-only native child observation and create-new
//! PUBLIC bootstrap publication for an independently launched TEST campaign.
//! The trusted launcher supplies the four actual Child PIDs and source-linked
//! artifact identities. Ready-file PID/role fields alone never authorize a peer.
use super::{bootstrap::{Bootstrap,ContextPin,PeerPin,BOOT_MARKER},
    continuous_launch::{Ready,LauncherPin,LAUNCH_MARKER},process_auth::{Identity,VerifiedProcess},
    image_pin::ImagePin,control_codec::Role};
use std::{path::{Path,PathBuf},io::Write};
use sha2::{Sha256,Digest};
type Result<T>=std::result::Result<T,String>;
pub const SUPERVISOR_MARKER:&str="MUTINY-W15-NONSHIPPING-CONTINUOUS-SUPERVISOR-V1";
#[derive(serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildPin {pub role:u8,pub pid:u32,pub start_filetime:u64,pub image_path:PathBuf,pub image_sha256:[u8;32],pub root:PathBuf}
#[derive(serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {pub format:String,pub source_git:String,pub source_manifest:PathBuf,pub source_sha256:[u8;32],
    pub campaign:[u8;32],pub service:ChildPin,pub roles:[ChildPin;3],
    pub bootstrap_output:PathBuf,pub launcher_pin_output:PathBuf}
fn create(path:&Path,raw:&[u8])->Result<()> {
    if path.exists(){return Err("Public bootstrap destination already exists; preserved".into());}
    let mut f=std::fs::OpenOptions::new().create_new(true).write(true).open(path).map_err(|e|e.to_string())?;
    f.write_all(raw).map_err(|e|e.to_string())?;f.sync_all().map_err(|e|e.to_string())
}
fn observe(input:&ChildPin,owner:&VerifiedProcess,source:[u8;32],campaign:[u8;32])->Result<(Identity,Ready,VerifiedProcess)> {
    if input.pid==0||input.pid==std::process::id()||input.start_filetime==0||input.image_sha256==[0;32]||!input.root.is_absolute(){return Err("Explicit independently launched child identity required".into());}
    let identity=VerifiedProcess::observe_created_process(input.pid)?;
    if identity.pid!=input.pid||identity.start_filetime!=input.start_filetime||identity.image_path!=input.image_path||identity.image_sha256!=input.image_sha256{return Err("Native Child PID/start/image differs from trusted launcher pins".into());}
    let held=VerifiedProcess::open(&identity)?;held.recheck()?;
    let file=ImagePin::open(&input.root.join(format!("ready-public-{}-{}.json",input.pid,input.start_filetime)),&owner.identity().user_sid)?;
    let ready:Ready=serde_json::from_slice(&file.read_bounded(16*1024)?).map_err(|e|e.to_string())?;
    if ready.format!=LAUNCH_MARKER||ready.source!=source||ready.campaign!=campaign||ready.role!=input.role||ready.observed_process!=identity||ready.finality_authority{
        return Err("Public readiness differs from independently observed child/source/role".into());
    }
    if ready.transport_descriptor_hex.is_empty()||ready.transport_descriptor_hex.len()>4096{return Err("Ready public transport descriptor bound".into());}
    let raw=hex::decode(&ready.transport_descriptor_hex).map_err(|_|"Ready transport hex")?;
    let (key,generation)=mutiny_crypto_v2::PublicKey::decode_descriptor(&raw).map_err(|e|format!("{e:?}"))?;
    if generation!=1{return Err("Fresh TEST transport generation required".into());}
    mutiny_transport_v2::Endpoint::pinned(key,generation).map_err(|e|format!("{e:?}"))?;
    held.recheck()?;Ok((identity,ready,held))
}
pub fn publish(path:&Path,input_sha:[u8;32])->Result<serde_json::Value> {
    let owner=VerifiedProcess::open(&VerifiedProcess::observe_created_process(std::process::id())?)?;
    let input_file=ImagePin::open(path,&owner.identity().user_sid)?;
    if input_file.hash()!=input_sha{return Err("Trusted supervisor input hash differs".into());}
    let input:Input=serde_json::from_slice(&input_file.read_bounded(32*1024)?).map_err(|e|e.to_string())?;
    if input.format!=SUPERVISOR_MARKER||input.campaign==[0;32]||input.source_sha256==[0;32]||input.service.role!=0||
        input.source_git.len()!=40||!input.source_git.bytes().all(|b|b.is_ascii_hexdigit())||input.bootstrap_output==input.launcher_pin_output{
        return Err("Explicit trusted TEST supervisor format/source/campaign/output pins".into());
    }
    let parent=input.bootstrap_output.parent().ok_or("Bootstrap parent required")?;
    if !parent.is_dir()||path.parent()!=Some(parent)||!input.bootstrap_output.is_absolute()||input.launcher_pin_output.parent()!=Some(parent)||
        mutiny_consensus_v8::submission_pool_v1::private_directory(parent).map_err(|e|format!("{e:?}"))?{
        return Err("Both create-new public outputs require one already-private launcher parent; no implicit provisioning".into());
    }
    let source=super::bootstrap::bounded(&input.source_manifest,Some(input.source_sha256),16*1024*1024,&owner)?;
    let manifest:serde_json::Value=serde_json::from_slice(&source).map_err(|e|e.to_string())?;
    if manifest["head"]!=input.source_git||manifest["files"].as_array().is_none_or(|r|r.is_empty()||r.len()>4096){return Err("Exact full execution-source manifest required".into());}
    let (service,ready,service_held)=observe(&input.service,&owner,input.source_sha256,input.campaign)?;
    let h0_file=ready.h0_file.ok_or("Actual service H0 path required")?;
    let h0_hash=ready.h0_sha256.ok_or("Actual service H0 hash required")?;
    if ready.listener.is_some()||h0_file!=input.service.root.join("continuous-h0-public.json"){return Err("Exact actual service-ready H0 path required".into());}
    let h0=super::bootstrap::bounded(&h0_file,Some(h0_hash),8*1024*1024,&owner)?;
    let public:serde_json::Value=serde_json::from_slice(&h0).map_err(|e|e.to_string())?;
    let genesis=mutiny_consensus_v8::anchors::FinalizedAnchor::decode(&hex::decode(public["genesis"].as_str().ok_or("H0 anchor hex")?).map_err(|_|"H0 anchor hex")?).map_err(|e|format!("{e:?}"))?;
    if genesis.height!=0||public["format"]!=super::native_service::SERVICE_MARKER||public["source"]!=hex::encode(input.source_sha256)||public["campaign"]!=hex::encode(input.campaign){return Err("Actual service H0 context differs".into());}
    let context=ContextPin{campaign:input.campaign,source:input.source_sha256,h0:h0_hash,genesis:genesis.genesis,fingerprint:genesis.fingerprint};
    let mut roles=Vec::new();let mut held=Vec::new();let mut pids=std::collections::BTreeSet::from([service.pid]);
    for (role,pin) in [Role::WalletA,Role::WalletC,Role::Treasury].into_iter().zip(&input.roles){
        if pin.role!=role as u8||!pids.insert(pin.pid){return Err("Three fixed, distinct actual child roles required".into());}
        let (identity,ready,process)=observe(pin,&owner,input.source_sha256,input.campaign)?;
        let listener=ready.listener.ok_or("Role actual loopback listener required")?;
        if ready.h0_file.is_some()||ready.h0_sha256.is_some()||listener.ip()!=&std::net::Ipv4Addr::LOCALHOST||listener.port()==0{return Err("Exact role readiness shape/local listener required".into());}
        roles.push(PeerPin{role:role as u8,process:identity,transport_descriptor_hex:ready.transport_descriptor_hex,listener});held.push(process);
    }
    let roles:[PeerPin;3]=roles.try_into().map_err(|_|"Exactly three roles")?;
    let boot=Bootstrap{format:BOOT_MARKER.into(),context,service,roles,
        service_descriptor_hex:ready.transport_descriptor_hex,service_root:input.service.root,
        h0_file,source_git:input.source_git,source_manifest:input.source_manifest,source_manifest_sha256:input.source_sha256};
    let raw=serde_json::to_vec_pretty(&boot).map_err(|e|e.to_string())?;if raw.len()>16*1024{return Err("Bootstrap serialized allocation bound".into());}
    service_held.recheck()?;for p in &held{p.recheck()?;}
    create(&input.bootstrap_output,&raw)?;
    let hash=Sha256::digest(&raw).into();
    // Independently reread the create-new output through all native process,
    // source and endpoint checks before publishing its ready pin to the children.
    Bootstrap::read(&input.bootstrap_output,hash,&owner)?;
    let pin=LauncherPin{format:LAUNCH_MARKER.into(),source:boot.context.source,campaign:boot.context.campaign,bootstrap_sha256:hash};
    create(&input.launcher_pin_output,&serde_json::to_vec_pretty(&pin).map_err(|e|e.to_string())?)?;
    service_held.recheck()?;for p in &held{p.recheck()?;}owner.recheck()?;
    Ok(serde_json::json!({"format":SUPERVISOR_MARKER,"trusted_launcher_input_sha256":hex::encode(input_sha),"bootstrap_sha256":hex::encode(hash),"four_actual_native_pids":pids,"confirmation_authority":false,"physical_TPM_qualification":false}))
}
pub fn run_if_requested()->Option<Result<()>> {
    let args=std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.first().is_none_or(|a|a!="--continuous-bootstrap-publish"){return None;}
    Some((||{
        let [_,flag,path,hash_flag,hash]=args.as_slice()else{return Err("Exact trusted supervisor input/hash pairs required".into());};
        if flag!="--input"||hash_flag!="--input-sha"{return Err("Supervisor selector identity".into());}
        let path=PathBuf::from(path);let hash=super::control_files::hash(hash.to_str().ok_or("Supervisor hash Unicode")?)?;
        let result=publish(&path,hash)?;
        create(&path.parent().ok_or("Supervisor receipt parent")?.join(format!("native-supervisor-result-{}.json",std::process::id())),&serde_json::to_vec_pretty(&result).map_err(|e|e.to_string())?)
    })())
}
