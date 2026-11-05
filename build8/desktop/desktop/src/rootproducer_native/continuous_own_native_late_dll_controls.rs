//! NONSHIPPING TEST only: one fixed, Root-selected installed VERSION original.
//! No new declaration, rebaseline, provider, export call or normal capability.
#![cfg(all(test,windows,target_arch="x86_64",feature="testvalue-window"))]
use super::{plan,hex,own1001,Pin,Result,OriginalPublicFile,PublicClass,OwnLoadedModules,own_native_token};
use super::super::{Handle,Reference,metadata,release,retain,unknown,UNKNOWN,spelling,snapshot};
use serde::Deserialize;
use sha2::{Digest,Sha256};
use std::{ffi::c_void,fs::File,io::Read,path::PathBuf,sync::atomic::Ordering};
const VERSION:&str=r"C:\Windows\System32\version.dll";
const OS_SELECTION:&str="880548e14b9cd2e2e229d20fb285fa5500bdbdeb9be46b982e8294da834fb291";
const ABI_SELECTION:&str="96cca38bdfa0ee1b71c7b69ab704fa660208482580ecc59165a9015ec745a8b8";
const PRIOR_ABI_PLAN:&str="3d426eaf4af451a5503ddcd8863c4552a8257fe5db5b3d67d3359b416f678a15";
#[link(name="kernel32")]
unsafe extern "system"{fn LoadLibraryExW(path:*const u16,file:Handle,flags:u32)->Handle;}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
struct LatePlan{
 scope:String,source_sha256:String,abi_plan_sha256:String,
 os_selection_sha256:String,prior_abi_selection_sha256:String,prior_abi_plan_sha256:String,
 loader_action_authorized:bool,version:Pin,
}
fn late_plan()->Result<LatePlan>{
 let path=std::env::var_os("MUTINY_TEST1001_FIXED_VERSION_LATE_PLAN").ok_or("Root-held fixed VERSION late plan absent")?;
 let expected=std::env::var("MUTINY_TEST1001_FIXED_VERSION_LATE_PLAN_SHA256").map_err(|_|"Root-held fixed VERSION late plan hash absent")?;
 let expected=hex::<32>(&expected)?;let mut file=File::open(path).map_err(|e|e.to_string())?;
 let length=file.metadata().map_err(|e|e.to_string())?.len();
 if !(2..=16384).contains(&length){return Err("fixed VERSION late plan bound".into());}
 let mut bytes=Vec::with_capacity(length as usize);file.by_ref().take(length+1).read_to_end(&mut bytes).map_err(|e|e.to_string())?;
 if bytes.len()!=length as usize||<[u8;32]>::from(Sha256::digest(&bytes))!=expected
  ||file.metadata().map_err(|e|e.to_string())?.len()!=length{return Err("fixed VERSION late plan exact bytes/EOF".into());}
 let p:LatePlan=serde_json::from_slice(&bytes).map_err(|e|e.to_string())?;
 let source=std::env::var("MUTINY_TEST1001_ABI_SOURCE_SHA256").map_err(|_|"closed TEST build context absent")?;
 let abi=std::env::var("MUTINY_TEST1001_ABI_PLAN_SHA256").map_err(|_|"Root-held ABI plan binding absent")?;
 if p.scope!="ROOT_ADMITTED_TEST1001_FIXED_VERSION_LATE_LOAD_NEGATIVE_ONLY"||!p.loader_action_authorized
  ||hex::<32>(&p.source_sha256).is_err()||p.source_sha256!=source||hex::<32>(&abi).is_err()||p.abi_plan_sha256!=abi
  ||p.os_selection_sha256!=OS_SELECTION||p.prior_abi_selection_sha256!=ABI_SELECTION||p.prior_abi_plan_sha256!=PRIOR_ABI_PLAN{
  return Err("fixed VERSION late loader action/current source/ABI/selection binding absent".into());
 }
 // Historical selection restricts the sole TEST input; it does not attest
 // current identity/security. The existing original-file guard checks it again.
 if p.version.path!=PathBuf::from(VERSION)||p.version.bytes!=55192||p.version.links!=2
  ||p.version.volume!=6396246999083557628||p.version.file_id!="29980000000001000000000000000000"
  ||p.version.sha256!="cea99f212af557a9613150c5509631403ed0f05f5d9a06ac42039bd59b40e39a"
  ||p.version.owner_sid_hex!="010600000000000550000000b589fb381984c2cb5c6c236d5700776ec0026487"
  ||p.version.dacl_sha256!="55aa2c1fc5f357b52e7082a9798eaa585bc78463e8fb82be87067d34ffbee51d"{
  return Err("fixed VERSION differs from exact already-selected public original".into());
 }Ok(p)
}
// Preallocated custody records the actual returned loader reference before any
// fallible metadata check. Existing release/quarantine is consumed once only.
struct FixedLateLibrary{record:Option<Box<Reference>>,closed:bool,load_attempted:bool}
impl FixedLateLibrary{
 fn new(pid:u32)->Self{Self{record:Some(Box::new(Reference{next:0,original_pid:pid,requested_base:0,base:0,
  path:PathBuf::from(VERSION),extent:0,own_executable:false,acquired:false,uncertain:false,attempted:false,outcome:None,error:0})),closed:false,load_attempted:false}}
 fn load(&mut self,name:&[u16])->Result<()>{
  unknown()?;if self.closed||self.load_attempted{return Err("fixed late loader custody closed/already attempted; no retry".into());}
  let record=self.record.as_mut().ok_or("fixed late loader record absent")?;
  if record.acquired||record.attempted||record.base!=0{return Err("fixed late loader already consumed; no retry".into());}
  self.load_attempted=true;
  let returned=unsafe{LoadLibraryExW(name.as_ptr(),std::ptr::null_mut::<c_void>(),0x800)};
  let error=if returned.is_null(){unsafe{super::super::GetLastError()}}else{0};
  record.base=returned as usize;record.requested_base=record.base;record.acquired=!returned.is_null();record.error=error;
  if returned.is_null(){return Err(format!("fixed late VERSION LoadLibraryExW refused {error}; no fallback"));}
  let observed=metadata(returned)?;
  if observed.path!=record.path||observed.base!=record.base{return Err("fixed late VERSION returned original metadata differs".into());}
  record.extent=observed.image_bytes;Ok(())
 }
 fn close_checked(&mut self)->Result<()>{
  if self.closed{return Err("fixed late loader closure already consumed; no retry".into());}self.closed=true;
  let mut record=self.record.take().ok_or("fixed late loader closure record absent")?;
  if let Err(e)=release(&mut record){retain(record);return Err(e);}Ok(())
 }
}
impl Drop for FixedLateLibrary{fn drop(&mut self){
 if !self.closed{if let Some(record)=self.record.take(){if record.acquired||record.uncertain{
  UNKNOWN.store(true,Ordering::Release);retain(record);}}}
}}
fn run()->Result<()>{
 // Root retains both complete plan originals/context through the whole process.
 let selected=plan()?;let late=late_plan()?;let fixed=PathBuf::from(VERSION);
 if selected.approved_own_roster.iter().filter(|p|p.as_path()==fixed.as_path()).count()!=1{
  return Err("fixed VERSION not exactly once in current already-approved ABI roster".into());}
 let before=own_native_token::observe_own()?;
 if before.user_sid!=own1001()||before.app_container||before.restricted{return Err("exact TEST1001 token profile required".into());}
 let own_path=selected.own.path.clone();
 OwnLoadedModules::preflight_declared_metadata(&selected.approved_own_roster,&own_path)?;
 let(mut own,mut nt,mut version)=(None,None,None);
 let mut modules:Option<OwnLoadedModules>=None;let mut library:Option<FixedLateLibrary>=None;
 let operation=(||{
  // Legitimate full selected-original checks precede the single authoritative
  // owner. This opens only already-approved own/ntdll/fixed VERSION originals.
  own=Some(OriginalPublicFile::open_declared(selected.own.into_spec(PublicClass::OwnTestImage)?,&before.user_sid)?);
  nt=Some(OriginalPublicFile::open_declared(selected.ntdll.into_spec(PublicClass::System32Dll)?,&before.user_sid)?);
  version=Some(OriginalPublicFile::open_declared(late.version.into_spec(PublicClass::System32Dll)?,&before.user_sid)?);
  modules=Some(OwnLoadedModules::observe_declared(&selected.approved_own_roster,&own_path)?);
  let owner=modules.as_ref().ok_or("single actual original module owner absent")?;
  owner.require_selected_comparator(selected.comparator_direct_rva)?;
  if owner.observations.len()>=super::super::CAP{return Err("late VERSION needs one row within unchanged CAP".into());}
  if owner.observations.iter().any(|m|spelling(&m.path).ok()==spelling(&fixed).ok()){
   return Err("fixed VERSION already loaded at authoritative acquisition; no alternative/retry".into());}
  let text=owner.observations.iter().map(|m|m.path.to_str().unwrap().len()).sum::<usize>()+VERSION.len();
  if text>262144{return Err("late VERSION exceeds unchanged aggregate metadata text bound".into());}
  let names:Vec<u16>=VERSION.encode_utf16().chain(std::iter::once(0)).collect();
  library=Some(FixedLateLibrary::new(owner.pid));
  owner.recheck()?;own.as_ref().unwrap().recheck()?;nt.as_ref().unwrap().recheck()?;version.as_ref().unwrap().recheck()?;
  if own_native_token::observe_own()?!=before{return Err("token/context changed before fixed late load".into());}
  // Sole explicit TEST loader action: fixed absolute selected installed DLL,
  // search restricted to SYSTEM32 dependencies; no export/provider invocation.
  library.as_mut().unwrap().load(&names)?;
  version.as_ref().unwrap().recheck()?;
  let actual=snapshot()?;let late_row=metadata(library.as_ref().unwrap().record.as_ref().unwrap().base as Handle)?;
  let mut expected=owner.observations.clone();expected.push(late_row);expected.sort_by_key(|m|m.base);
  if actual!=expected{return Err("fixed late VERSION changed more than the exact one original module; no admission/rebaseline".into());}
  // This calls the unchanged real snapshot/reference check, not a supplied row.
  match owner.recheck(){
   Err(e)if e.starts_with("Own complete module roster changed;")&&e.contains("missing_count=0 added_count=1")=>{},
   Err(e)=>return Err(format!("actual late VERSION wrong refusal: {e}")),
   Ok(())=>return Err("actual post-acquisition VERSION unexpectedly accepted".into())
  }
  own.as_ref().unwrap().recheck()?;nt.as_ref().unwrap().recheck()?;version.as_ref().unwrap().recheck()?;
  if own_native_token::observe_own()?!=before{return Err("token/context changed during fixed late load".into());}Ok(())
 })();
 // Check every independent original/reference closure even on failure. Release
 // the one new DLL first; the original owner must then restore its exact saved
 // roster without reacquisition, mutation, retry or refreshing observations.
 let mut errors=Vec::new();
 if let Some(library)=library.as_mut(){if let Err(e)=library.close_checked(){errors.push(e)}}
 for file in [&mut version,&mut nt,&mut own]{if let Some(file)=file.as_mut(){
  if let Err(e)=file.recheck(){errors.push(e)}if let Err(e)=file.close_checked(){errors.push(e)}}}
 if let Err(e)=own_native_token::observe_own().and_then(|after|if after==before{Ok(())}else{Err("token/context changed after late cleanup".into())}){errors.push(e)}
 if let Some(owner)=modules.as_mut(){if let Err(e)=owner.recheck(){errors.push(e)}if let Err(e)=owner.close_checked(){errors.push(e)}}
 if !errors.is_empty(){return Err(format!("actual late VERSION independent closure/restoration refused {errors:?}; original={operation:?}"));}
 operation?;println!("MUTINY_TESTVALUE_ACTUAL_FIXED_VERSION_LATE_DLL_REFUSED_AND_CHECKED_UNLOADED");Ok(())
}
#[test]fn actual_fixed_selected_version_late_load_refused_by_original_owner(){run().unwrap();}
