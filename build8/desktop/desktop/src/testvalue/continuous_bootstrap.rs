//! EXTERNAL SOURCE ONLY. Externally pinned public process/role bootstrap.
//! Native identity observations, transport pins and host-head hints are NOT
//! wallet approval, physical TPM qualification or canonical inclusion evidence.
use super::{control_codec::{Context,Head,Role},process_auth::{Identity,VerifiedProcess},image_pin::ImagePin};
use std::{path::{Path,PathBuf},io::Read};
use sha2::{Digest,Sha256};
type Result<T>=std::result::Result<T,String>;
pub const BOOT_MARKER:&str="MUTINY-W15-NONSHIPPING-CONTINUOUS-BOOTSTRAP-V1";
#[derive(Clone,serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextPin{pub campaign:[u8;32],pub source:[u8;32],pub h0:[u8;32],pub genesis:[u8;32],pub fingerprint:[u8;32]}
impl ContextPin{pub fn context(&self)->Context{Context{campaign:self.campaign,source:self.source,h0:self.h0,genesis:self.genesis,fingerprint:self.fingerprint}}}
#[derive(Clone,serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PeerPin{pub role:u8,pub process:Identity,pub transport_descriptor_hex:String,pub listener:std::net::SocketAddrV4}
#[derive(Clone,serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bootstrap{
    pub format:String,pub context:ContextPin,pub service:Identity,pub roles:[PeerPin;3],
    pub service_descriptor_hex:String,pub service_root:PathBuf,pub h0_file:PathBuf,
    pub source_git:String,pub source_manifest:PathBuf,pub source_manifest_sha256:[u8;32],
}
fn role(n:u8)->Result<Role>{match n{1=>Ok(Role::WalletA),2=>Ok(Role::WalletC),3=>Ok(Role::Treasury),_=>Err("Bootstrap role bound".into())}}
pub(crate) fn bounded(path:&Path,pin:Option<[u8;32]>,limit:u64,owner:&VerifiedProcess)->Result<Vec<u8>>{
    let held=ImagePin::open(path,&owner.identity().user_sid)?;
    if pin.is_some_and(|h|held.hash()!=h){return Err("Bootstrap externally pinned public file differs".into());}
    held.read_bounded(limit)
}
fn endpoint(raw:&str)->Result<mutiny_transport_v2::Endpoint>{
    if raw.is_empty()||raw.len()>4096{return Err("Bootstrap transport descriptor bound".into());}
    let raw=hex::decode(raw).map_err(|_|"Bootstrap transport descriptor hex")?;
    let(public,generation)=mutiny_crypto_v2::PublicKey::decode_descriptor(&raw).map_err(|e|format!("{e:?}"))?;
    if generation!=1{return Err("Fresh TEST transport generation must be one".into());}
    mutiny_transport_v2::Endpoint::pinned(public,generation).map_err(|e|format!("{e:?}"))
}
impl Bootstrap{
    pub fn read(path:&Path,externally_pinned_sha:[u8;32],owner:&VerifiedProcess)->Result<Self>{
        let raw=bounded(path,Some(externally_pinned_sha),16*1024,owner)?;
        let boot:Self=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
        if boot.format!=BOOT_MARKER||boot.context.context().campaign==[0;32]||boot.context.source==[0;32]||boot.context.h0==[0;32]||boot.context.genesis==[0;32]||boot.context.fingerprint==[0;32]{return Err("Exact nonshipping bootstrap format/context".into());}
        if boot.service.pid==0||boot.service.source_path_too_long(){return Err("Service native bootstrap path bound".into());}
        let source=bounded(&boot.source_manifest,Some(boot.source_manifest_sha256),16*1024*1024,owner)?;
        let manifest:serde_json::Value=serde_json::from_slice(&source).map_err(|e|e.to_string())?;
        if boot.context.source!=boot.source_manifest_sha256||boot.source_git.len()!=40||!boot.source_git.bytes().all(|b|b.is_ascii_hexdigit())||manifest["head"]!=boot.source_git||manifest["files"].as_array().is_none_or(|r|r.is_empty()||r.len()>4096){return Err("Exact complete source manifest/Git baseline required".into());}
        if boot.h0_file!=boot.service_root.join("continuous-h0-public.json"){return Err("Bootstrap public H0 must be exact service-owned path".into());}
        let h0=bounded(&boot.h0_file,Some(boot.context.h0),8*1024*1024,owner)?;
        let public:serde_json::Value=serde_json::from_slice(&h0).map_err(|e|e.to_string())?;
        if public["format"]!=super::native_service::SERVICE_MARKER||public["source"]!=hex::encode(boot.context.source)||public["campaign"]!=hex::encode(boot.context.campaign){return Err("New campaign H0 source/context differs".into());}
        let current=VerifiedProcess::open(&boot.service)?;current.recheck()?;
        let service_endpoint=endpoint(&boot.service_descriptor_hex)?;
        let mut pids=std::collections::BTreeSet::from([boot.service.pid]);let mut endpoints=std::collections::BTreeSet::from([service_endpoint.id()]);
        for (expected,peer) in [1,2,3].into_iter().zip(&boot.roles){
            if peer.role!=expected||!pids.insert(peer.process.pid)||peer.process.source_path_too_long()||peer.listener.ip()!=&std::net::Ipv4Addr::LOCALHOST||peer.listener.port()==0{return Err("Three actual fixed-role processes/local endpoints required".into());}
            let pin=VerifiedProcess::open(&peer.process)?;pin.recheck()?;
            if !endpoints.insert(endpoint(&peer.transport_descriptor_hex)?.id()){return Err("Duplicate role transport identity refused".into());}
        }
        Ok(boot)
    }
    pub fn peer(&self,r:Role)->&PeerPin{&self.roles[r as usize-1]}
    pub fn service_endpoint(&self)->Result<mutiny_transport_v2::Endpoint>{endpoint(&self.service_descriptor_hex)}
    pub fn role_endpoint(&self,r:Role)->Result<mutiny_transport_v2::Endpoint>{endpoint(&self.peer(r).transport_descriptor_hex)}
    /// A bounded, immutable public host observation used ONLY to form a local
    /// RPC expected-head guard. Never supplied to Controller's approval view.
    pub fn observed_head(&self,owner:&VerifiedProcess)->Result<Head>{
        let service=VerifiedProcess::open(&self.service)?;service.recheck()?;
        let mut ctx=Vec::with_capacity(160);let c=self.context.context();for h in [c.campaign,c.source,c.h0,c.genesis,c.fingerprint]{ctx.extend_from_slice(&h);}
        let expected=hex::encode(Sha256::digest(&ctx));
        for height in (0..=384u64).rev(){
            let path=self.service_root.join(format!("host-observed-{}-{}-{height:08}.json",self.service.pid,self.service.start_filetime));
            match std::fs::symlink_metadata(&path){Ok(_)=>{},Err(e) if e.kind()==std::io::ErrorKind::NotFound=>continue,Err(e)=>return Err(format!("Current process host observation metadata refusal: {e}"))}
            let raw=bounded(&path,None,2048,owner)?;
            let v:serde_json::Value=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
            if v["format"]!="MUTINY-W15-NONSHIPPING-HOST-OBSERVATION-V1"||v["context_sha256"]!=expected||v["pid"]!=self.service.pid||v["start_filetime"]!=self.service.start_filetime||v["image_sha256"]!=hex::encode(self.service.image_sha256)||v["height"]!=height||v["confirmed"]!=false{return Err("Host observation differs from pinned process/context".into());}
            let hash=|k|super::control_files::hash(v[k].as_str().ok_or("Host observation hash type")?);
            let result=Head{height,block:hash("block")?,root:hash("root")?};service.recheck()?;return Ok(result);
        }Err("No actual service-owned bounded host observation".into())
    }
}
trait IdentityBound{fn source_path_too_long(&self)->bool;}
impl IdentityBound for Identity{fn source_path_too_long(&self)->bool{self.image_path.to_str().is_none_or(|s|s.is_empty()||s.len()>4096)}}
pub fn parse_role(n:u8)->Result<Role>{role(n)}
