//! EXTERNAL SOURCE ONLY. Trusted, hash-pinned NEW synthetic campaign path plan.
//! This is a local launcher input, never an RPC role or custody capability.
use super::{continuous_passive::PathPin,image_pin::ImagePin,process_auth::VerifiedProcess};
use std::path::{Path,PathBuf};
use mutiny_consensus_v8::Hash;
type Result<T>=std::result::Result<T,String>;
pub(super) const MARKER:&str="MUTINY-W15-NONSHIPPING-NEW-ORIGINAL-ROLE-ROOTS-V1";
#[derive(Clone,serde::Serialize,serde::Deserialize)] #[serde(deny_unknown_fields)]
pub(super) struct Roots {pub format:String,pub source:Hash,pub campaign:Hash,pub service:PathBuf,pub roles:[PathBuf;3]}
pub(super) struct HeldRoots {pub roots:Roots,pin:ImagePin}
fn absolute(p:&Path)->bool{p.is_absolute()&&!p.components().any(|c|matches!(c,std::path::Component::ParentDir|std::path::Component::CurDir))&&p.to_str().is_some_and(|s|!s.is_empty()&&s.len()<=4096)}
impl Roots {
 fn validate(&self,source:Hash,campaign:Hash)->Result<()>{
  if self.format!=MARKER||self.source!=source||self.campaign!=campaign||[source,campaign].contains(&[0;32]){return Err("Exact new campaign/source root plan required".into());}
  let paths=[&self.service,&self.roles[0],&self.roles[1],&self.roles[2]];
  for (i,p) in paths.iter().enumerate(){if !absolute(p)||paths.iter().skip(i+1).any(|q|p.starts_with(q)||q.starts_with(p)){return Err("Four exact distinct nonoverlapping original roots required".into());}}
  Ok(())
 }
}
impl HeldRoots {
 pub(super) fn read(input:&PathPin,owner:&VerifiedProcess,source:Hash,campaign:Hash)->Result<Self>{
  if !absolute(&input.path)||input.sha256==[0;32]{return Err("Explicit new path plan pin required".into());}
  let pin=ImagePin::open(&input.path,&owner.identity().user_sid)?;if pin.hash()!=input.sha256{return Err("New original root plan changed".into());}
  let roots:Roots=serde_json::from_slice(&pin.read_bounded(16384)?).map_err(|e|e.to_string())?;roots.validate(source,campaign)?;
  if [&roots.service,&roots.roles[0],&roots.roles[1],&roots.roles[2]].iter().any(|p|input.path.starts_with(p)){return Err("Path plan must be outside every new private root".into());}
  owner.recheck()?;pin.recheck()?;Ok(Self{roots,pin})
 }
 pub(super) fn all_absent_before_bootstrap(&self)->Result<()>{self.pin.recheck()?;for p in std::iter::once(&self.roots.service).chain(self.roots.roles.iter()){
  match std::fs::symlink_metadata(p){Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{},Ok(_)=>return Err("Bootstrap original root already exists; never initialize replacement".into()),Err(e)=>return Err(e.to_string())}
 }Ok(())}
 pub(super) fn recheck(&self)->Result<()>{self.pin.recheck()}
}
#[cfg(test)] mod tests {
 use super::*;
 #[test] fn immutable_new_path_plan_has_no_existing_mode_or_alias_fallback(){let good=Roots{format:MARKER.into(),source:[1;32],campaign:[2;32],service:r"C:\PUBLIC-MODEL\service".into(),roles:[r"C:\PUBLIC-MODEL\A".into(),r"C:\PUBLIC-MODEL\C".into(),r"C:\PUBLIC-MODEL\T".into()]};good.validate([1;32],[2;32]).unwrap();for fault in 0..5{let mut p=good.clone();match fault{0=>p.roles[0]=p.service.clone(),1=>p.roles[1]=p.roles[0].join("nested"),2=>p.campaign=[9;32],3=>p.source=[9;32],_=>p.roles[2]=PathBuf::from("relative")};assert!(p.validate([1;32],[2;32]).is_err());}}
}
