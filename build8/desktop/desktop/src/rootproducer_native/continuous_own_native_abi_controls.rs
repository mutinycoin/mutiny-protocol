//! Finite fresh-process TEST1001 actual Rust extern-system ABI controls.
//! No SQLite, provider, key, counter, TPM, service or normal issuer entry.
//! This is a child module of own_native_modules, with reviewed token/files
//! sibling modules at testvalue root. The parent holds the exact public plan,
//! original harness image and named approved inputs for the entire process.
#![cfg(all(test,windows,target_arch="x86_64",feature="testvalue-window"))]
use super::{section,selected_index,Handle,OwnLoadedModules};
use super::super::{own_native_files::{OriginalPublicFile,PublicObjectSpec,PublicClass},own_native_token};
use serde::Deserialize;
use std::{ffi::c_void,fs::File,io::Read,path::PathBuf};
use sha2::{Digest,Sha256};
type Result<T>=std::result::Result<T,String>;
#[link(name="kernel32")]
unsafe extern "system"{fn GetProcAddress(module:Handle,name:*const u8)->*mut c_void;}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
struct Pin{path:PathBuf,bytes:u64,sha256:String,volume:u64,file_id:String,links:u32,owner_sid_hex:String,dacl_sha256:String,native_raw_dacl_witness:NativeRawDaclWitnessV1}
// Managed custody and raw native ACL digests are separate domains. This input
// witness never permits canonicalization or either-hash acceptance in Rust.
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
struct NativeRawDaclWitnessV1{schema:String,domain:String,version:u32,path:PathBuf,object_class:String,
 bytes:u64,sha256:String,volume:u64,file_id:String,links:u32,owner_sid_hex:String,
 managed_dacl_sha256:String,raw_dacl_sha256:String}
impl NativeRawDaclWitnessV1{
 fn exact_raw_digest(&self,p:&Pin,class:PublicClass)->Result<[u8;32]>{
  let expected_class=match class{PublicClass::OwnTestImage=>"OwnTestImage",PublicClass::System32Dll=>"System32Dll",_=>return Err("native ABI witness unsupported class".into())};
  if self.schema!="OWN_NATIVE_RAW_DACL_WITNESS_V1"||self.domain!="windows-getsecurityinfo-raw-dacl"||self.version!=1{return Err("native raw witness exact domain/version required".into());}
  if self.path!=p.path||self.object_class!=expected_class||self.bytes!=p.bytes||self.sha256!=p.sha256
   ||self.volume!=p.volume||self.file_id!=p.file_id||self.links!=p.links||self.owner_sid_hex!=p.owner_sid_hex
   ||self.managed_dacl_sha256!=p.dacl_sha256{return Err("native raw witness differs from managed original binding".into());}
  // Preserve validation of the managed field even though it is never the raw digest.
  let _managed=hex::<32>(&p.dacl_sha256)?;hex::<32>(&self.raw_dacl_sha256)
 }
}
#[derive(Deserialize)]#[serde(deny_unknown_fields)]
struct Plan{scope:String,source_sha256:String,own:Pin,ntdll:Pin,approved_own_roster:Vec<PathBuf>,comparator_direct_rva:u32}
fn hex<const N:usize>(text:&str)->Result<[u8;N]>{
 if text.len()!=2*N||text.bytes().any(|b|!b.is_ascii_digit()&&!(b'a'..=b'f').contains(&b)){return Err("exact lowercase native pin hex".into());}
 let mut out=[0;N];for(i,b)in out.iter_mut().enumerate(){*b=u8::from_str_radix(&text[2*i..2*i+2],16).map_err(|_|"hex native pin")?;}Ok(out)
}
fn sid(text:&str)->Result<Vec<u8>>{if text.len()<16||text.len()>136||text.len()%2!=0{return Err("bounded actual SID hex".into());}
 let mut out=Vec::with_capacity(text.len()/2);for pair in text.as_bytes().chunks_exact(2){let part=std::str::from_utf8(pair).map_err(|_|"SID ASCII")?;if part.bytes().any(|b|!b.is_ascii_digit()&&!(b'a'..=b'f').contains(&b)){return Err("SID lowercase hex".into());}out.push(u8::from_str_radix(part,16).map_err(|_|"SID hex")?);}Ok(out)}
fn own1001()->Vec<u8>{crate::policy::SID.to_vec()}
impl Pin{fn validate_native_witness(&self,class:PublicClass)->Result<[u8;32]>{self.native_raw_dacl_witness.exact_raw_digest(self,class)}
fn into_spec(self,class:PublicClass)->Result<PublicObjectSpec>{let raw_dacl=self.validate_native_witness(class)?;Ok(PublicObjectSpec{path:self.path,class,bytes:self.bytes,sha256:hex(&self.sha256)?,volume:self.volume,file_id:hex(&self.file_id)?,links:self.links,owner_sid:sid(&self.owner_sid_hex)?,dacl_sha256:raw_dacl})}}
fn plan()->Result<Plan>{
 let path=std::env::var_os("MUTINY_TEST1001_ABI_PLAN").ok_or("Root-held exact TEST ABI plan absent")?;
 let expected=std::env::var("MUTINY_TEST1001_ABI_PLAN_SHA256").map_err(|_|"Root-admitted TEST ABI plan hash absent")?;let expected=hex::<32>(&expected)?;
 let mut file=File::open(path).map_err(|e|e.to_string())?;let length=file.metadata().map_err(|e|e.to_string())?.len();if !(2..=131072).contains(&length){return Err("finite TEST ABI plan bound".into());}
 let mut bytes=Vec::with_capacity(length as usize);file.by_ref().take(length+1).read_to_end(&mut bytes).map_err(|e|e.to_string())?;
 if bytes.len()!=length as usize||<[u8;32]>::from(Sha256::digest(&bytes))!=expected||file.metadata().map_err(|e|e.to_string())?.len()!=length{return Err("exact TEST ABI plan bytes/EOF".into());}
 let plan:Plan=serde_json::from_slice(&bytes).map_err(|e|e.to_string())?;
 let expected_source=std::env::var("MUTINY_TEST1001_ABI_SOURCE_SHA256").map_err(|_|"exact closed build source context absent")?;
 if plan.scope!="ROOT_ADMITTED_TEST1001_RUST_NATIVE_ABI_EXPERIMENT_ONLY"||hex::<32>(&plan.source_sha256).is_err()||plan.source_sha256!=expected_source||plan.approved_own_roster.is_empty()||plan.approved_own_roster.len()>512||plan.comparator_direct_rva<4096{return Err("finite Root-admitted experiment scope".into());}
 if std::env::current_exe().map_err(|e|e.to_string())?!=plan.own.path||plan.ntdll.path!=PathBuf::from(r"C:\Windows\System32\ntdll.dll"){return Err("exact OWN harness/selected ntdll path".into());}Ok(plan)
}
enum Control{Positive,DistinctObject,AbsentExport,SyntheticLateSnapshot}
fn run(control:Control)->Result<()>{
 let plan=plan()?;plan.own.validate_native_witness(PublicClass::OwnTestImage)?;plan.ntdll.validate_native_witness(PublicClass::System32Dll)?;let before=own_native_token::observe_own()?;
 if before.user_sid!=own1001()||before.app_container||before.restricted{return Err("exact Architect TEST1001 actual primary-token profile".into());}
 if plan.own.volume==plan.ntdll.volume&&plan.own.file_id==plan.ntdll.file_id{return Err("distinct original native object identities required".into());}
 let own_path=plan.own.path.clone();let ntdll_path=plan.ntdll.path.clone();let comparator_rva=plan.comparator_direct_rva;
 // Unknown complete OWN metadata is refused before any corresponding file open.
 OwnLoadedModules::preflight_declared_metadata(&plan.approved_own_roster,&own_path)?;
 let mut own=None;let mut ntdll=None;let mut modules:Option<OwnLoadedModules>=None;
 let operation=(||{
  own=Some(OriginalPublicFile::open_declared(plan.own.into_spec(PublicClass::OwnTestImage)?,&before.user_sid)?);
  ntdll=Some(OriginalPublicFile::open_declared(plan.ntdll.into_spec(PublicClass::System32Dll)?,&before.user_sid)?);
  // These are the two legitimate declared original validations, not warmup.
  // Acquire the single authoritative DLL owner only after their full checks.
  modules=Some(OwnLoadedModules::observe_declared(&plan.approved_own_roster,&own_path)?);
  let modules=modules.as_mut().ok_or("Authoritative OWN module owner absent")?;
  let index=selected_index(&modules.observations,&ntdll_path)?;
  let original=modules.records[index].as_ref().ok_or("OWN original ntdll reference")?;
  let address=unsafe{GetProcAddress(original.base as Handle,c"NtAreMappedFilesTheSame".as_ptr().cast())} as usize;
  if comparator_rva>=original.extent||address==0||address!=original.base.checked_add(comparator_rva as usize).ok_or("comparator RVA overflow")?{return Err("actual selected native comparator differs from held direct PE export".into());}
  modules.recheck()?;own.as_ref().unwrap().recheck()?;ntdll.as_ref().unwrap().recheck()?;
  match control{
   Control::Positive=>{
    // Authorized isolated ABI experiment: selected original ntdll File and
    // genuine OWN live SEC_IMAGE/reference remain held. This does not call
    // require_original_file_backing or manufacture a normal ABI capability.
    unsafe{section::compare_original(ntdll.as_ref().unwrap().original_file()?,original.base)}.map_err(|e|format!("actual Rust extern-system positive refused {e:?}"))?;
    let own_index=selected_index(&modules.observations,&own_path)?;
    let own_base=modules.records[own_index].as_ref().ok_or("original OWN executable lifetime")?.base;
    unsafe{section::compare_original(own.as_ref().unwrap().original_file()?,own_base)}.map_err(|e|format!("actual Rust OWN executable positive refused {e:?}"))?;
   }
   Control::DistinctObject=>{
    let own_file=own.as_ref().unwrap().original_file()?;let selected=ntdll.as_ref().unwrap().original_file()?;
    // The whole plan validates distinct full native IDs/paths before this
    // experiment; same bytes or a guessed pointer supplies no evidence.
    if own_path==ntdll_path||own_file.metadata().map_err(|e|e.to_string())?.len()==0||selected.metadata().map_err(|e|e.to_string())?.len()==0{return Err("genuine original object inputs absent".into());}
    let result=unsafe{section::compare_original(own_file,original.base)};
    match result{Err(error)if error.stage=="mapped backing object differs or unsupported"&&error.code!=0&&!error.quarantined=>println!("MUTINY_TEST1001_ABI_NONZERO_STATUS {}",error.code),other=>return Err(format!("distinct original object failed exact Rust refusal {other:?}"))}
   }
   Control::SyntheticLateSnapshot=>{
    // TEST seam only: one synthetic metadata row is never loaded, opened,
    // referenced, dereferenced or admitted. The saved real owner is unchanged.
    if modules.observations.len()>=super::CAP{return Err("synthetic later metadata needs room within existing roster CAP".into());}
    let mut later=modules.observations.clone();
    let path=own_path.with_file_name("UNEXPECTED_TEST_METADATA_ONLY_3ead6e0f2c48446e8c9f654dc5938682.dll");
    if later.iter().any(|m|m.path==path){return Err("synthetic metadata marker overlaps actual roster".into());}
    let text_bytes=later.iter().map(|m|m.path.to_str().unwrap().len()).sum::<usize>()+path.to_str().ok_or("synthetic bounded ASCII metadata path")?.len();
    if text_bytes>262144{return Err("synthetic later metadata exceeds existing aggregate text bound".into());}
    let base=later.iter().map(|m|m.base).max().ok_or("actual saved roster empty")?.checked_add(0x1000000).ok_or("synthetic metadata distinct number overflow")?;
    later.push(super::ModuleObservation{path,image_bytes:4096,base});later.sort_by_key(|m|m.base);
    match modules.require_exact_observed_roster(later){
     Err(e) if e.starts_with("Own complete module roster changed;")&&e.contains("missing_count=0 added_count=1")=>{},
     Err(e)=>return Err(format!("synthetic later snapshot wrong refusal: {e}")),
     Ok(())=>return Err("synthetic unexpected later metadata accepted".into())
    }
    modules.recheck()?;
    println!("MUTINY_TESTVALUE_SYNTHETIC_LATER_METADATA_REFUSED_NO_DLL_LOAD");
   }
   Control::AbsentExport=>{
    let absent=unsafe{GetProcAddress(original.base as Handle,c"MutinyQualificationAbsent_NtAreMappedFilesTheSame".as_ptr().cast())};
    if !absent.is_null(){return Err("genuinely absent comparator export was not refused".into());}
   }
  }
  modules.recheck()?;own.as_ref().unwrap().recheck()?;ntdll.as_ref().unwrap().recheck()?;
  let after=own_native_token::observe_own()?;if before!=after{return Err("original OWN process/primary-token changed during experiment".into());}
  println!("MUTINY_TEST1001_ABI_OWN_PROFILE {:?}",before);Ok(())
 })();
 // Every acquired original file/reference is closed independently once, even
 // when the experiment refuses. The accepted owners quarantine uncertainty.
 let mut errors=Vec::new();if let Some(file)=ntdll.as_mut(){if let Err(e)=file.recheck(){errors.push(e)}if let Err(e)=file.close_checked(){errors.push(e)}}
 if let Some(file)=own.as_mut(){if let Err(e)=file.recheck(){errors.push(e)}if let Err(e)=file.close_checked(){errors.push(e)}}
 if let Some(modules)=modules.as_mut(){if let Err(e)=modules.recheck(){errors.push(e)}if let Err(e)=modules.close_checked(){errors.push(e)}}
 if !errors.is_empty(){return Err(format!("ABI experiment independent closure refused {errors:?}; original={operation:?}"));}operation
}
#[test]fn actual_rust_selected_original_ntdll_positive(){run(Control::Positive).unwrap();}
#[test]fn actual_rust_distinct_original_object_nonzero_refused(){run(Control::DistinctObject).unwrap();}
#[test]fn actual_rust_genuinely_absent_comparator_export_refused(){run(Control::AbsentExport).unwrap();}
#[test]fn current_owner_synthetic_later_metadata_refused_without_dll_load(){run(Control::SyntheticLateSnapshot).unwrap();}
#[path="continuous_own_native_late_dll_controls.rs"] mod late_dll_controls;
