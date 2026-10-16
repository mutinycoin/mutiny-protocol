//! Private TEST1001 lifetime composition; no public constructor, bool admission,
//! NORMAL issuer or independent monetary/signing authority.
//! The unsafe constructor is a trusted application-factory boundary. Its caller
//! must authenticate actual Root-selected evidence and complete PE context, not
//! deserialize these internal inputs from a peer/GUI DTO or accept a receipt SHA
//! as proof that the selected native ABI/bindings were qualified.
#![cfg(all(windows,target_arch="x86_64",feature="native-owner-test"))]
use super::{own_native_token::{self,OwnTokenFacts},
 own_native_files::{OriginalPublicFile,PublicObjectSpec,PublicClass},
 own_native_modules::{OwnLoadedModules,DeclaredImport,CompleteSlot,ParsedRequestedExport}};
use std::{cell::Cell,collections::BTreeSet,path::PathBuf};
type Result<T>=std::result::Result<T,String>;
// Exact compile-time TEST profile selected by policy; no runtime override.
const SELECTED_TEST_SID:[u8;28]=super::policy::SID;
/// Internal owned inputs for the independently authenticated application
/// factory. No exported constructor/serde/Clone; no scalar eligibility flag.
pub(super) struct AdmittedTestInputs{
 pub(super) own_image:PathBuf,
 pub(super) original_objects:Vec<PublicObjectSpec>,
 pub(super) installed_crt:Option<crate::installed_vcruntime::Authority>,
 pub(super) complete_slots:Vec<CompleteSlot>,
 pub(super) full_parsed_exports:Vec<ParsedRequestedExport>,
 pub(super) selected_comparator_direct_rva:u32,
 pub(super) source_sha256:[u8;32],
 pub(super) immutable_campaign:[u8;32],
 pub(super) expected_primary_token:OwnTokenFacts,
}
/// Opaque, consuming lifetime owner retained until every provider worker joins.
/// Its backing/module references are not serialized or transferable to a PID.
pub(super) struct OwnExecutionLease{
 modules:OwnLoadedModules,originals:Vec<OriginalPublicFile>,
 token:OwnTokenFacts,bindings:Vec<DeclaredImport>,comparator_rva:u32,
 source:[u8;32],campaign:[u8;32],revoked:Cell<bool>,closed:bool,
}
impl OwnExecutionLease{
 /// # Safety
 /// Trusted factory MUST verify Root's installation-selected exact original
 /// artifact/source, current original-object witness set, independently admitted
 /// actual Rust extern-system ABI evidence for selected ntdll/platform/profile,
 /// and complete actual OWN PE imports/physical-direct-export bindings. Every
 /// normal AND delayed slot requires a freshly verified binding; any unresolved
 /// delayed slot refuses this constructor. Input lengths/hashes and internal
 /// DTO types alone do not establish that completeness/authentication.
 /// The expected token comes from independently observed original OWN process
 /// identity/primary token and selected TEST1001 role; not parent flag inference.
 /// Constructor supplies no NORMAL issuer, TPM proof or private COW guarantee.
 pub(super) unsafe fn open_admitted_test(inputs:AdmittedTestInputs)->Result<Self>{
  let before=own_native_token::observe_own()?;
  if before!=inputs.expected_primary_token||before.user_sid!=SELECTED_TEST_SID
   ||before.app_container||before.restricted{
   return Err("Exact independently selected OWN TEST1001 token/profile mismatch".into());}
  if inputs.source_sha256==[0;32]||inputs.immutable_campaign==[0;32]
   ||inputs.original_objects.is_empty()||inputs.original_objects.len()>512
   ||inputs.complete_slots.len()>131072||inputs.full_parsed_exports.len()>262144
   ||inputs.selected_comparator_direct_rva<4096{
   return Err("Exact scoped TEST source/campaign/object/binding inputs required".into());}
  let own=std::env::current_exe().map_err(|e|e.to_string())?;
  if own!=inputs.own_image{return Err("OWN executable differs from authenticated TEST artifact".into());}
  let mut paths=BTreeSet::new();let mut aggregate=0u64;
  for spec in &inputs.original_objects{
   let path=spec.path.to_str().ok_or("OWN original ASCII path required")?;
   if path.len()>4096||!path.is_ascii()||!paths.insert(path.replace('/',"\\").to_ascii_lowercase()){
    return Err("Exact unique OWN original object roster".into());}
   aggregate=aggregate.checked_add(spec.bytes).ok_or("OWN original byte budget overflow")?;
   if aggregate>2147483648{return Err("OWN original byte budget".into());}
   if spec.path==own{if spec.class!=PublicClass::OwnTestImage||spec.links!=1{
    return Err("Exactly one selected OWN TEST image class/link".into());}}
   else if spec.class!=PublicClass::System32Dll&&spec.class!=PublicClass::InstalledSystem32Vcruntime{
    return Err("Only literal selected System32 DLLs accompany OWN TEST image".into());}
  }
  if inputs.original_objects.iter().filter(|s|s.path==own).count()!=1{
   return Err("OWN image must occur exactly once in original object roster".into());}
  for spec in &inputs.original_objects{if spec.class==PublicClass::InstalledSystem32Vcruntime{
   let authority=inputs.installed_crt.as_ref().ok_or("A-only installed CRT registered provenance absent")?;
   authority.require_context(&inputs.source_sha256,&inputs.original_objects.iter().find(|s|s.path==own).ok_or("OWN original absent")?.sha256)?;
   authority.require_spec(spec)?;
  }}
  let approved=inputs.original_objects.iter().map(|s|s.path.clone()).collect::<Vec<_>>();
  let modules=OwnLoadedModules::observe_declared(&approved,&own)?;
  // This is the exact actual roster, not a candidate universe or implicit roots.
  if modules.observations().len()!=approved.len(){
   // Diagnostic metadata only: use the existing complete retained OWN snapshot.
   // Its paths/count are already bounded; no file opens or roster admission.
   let observed=modules.observations().iter()
    .map(|m|(m.path.clone(),m.image_bytes)).collect::<Vec<_>>();
   let observed_paths=observed.iter().map(|(path,_)|
    path.to_str().unwrap().replace('/',"\\").to_ascii_lowercase()).collect::<BTreeSet<_>>();
   let absent=approved.iter().filter(|path|!observed_paths.contains(
    &path.to_str().unwrap().replace('/',"\\").to_ascii_lowercase()))
    .cloned().collect::<Vec<_>>();
   let mut modules=modules;let closure=modules.close_checked();
   return Err(format!("Admitted original roster contains absent OWN module; declared_count={}; own_count={}; own_module_paths_and_image_bytes={observed:?}; absent_declared_paths={absent:?}; metadata_only=true; close={closure:?}",approved.len(),observed.len()));}
  let mut owner=Self{modules,originals:Vec::with_capacity(approved.len()),token:before,
   bindings:Vec::new(),comparator_rva:inputs.selected_comparator_direct_rva,source:inputs.source_sha256,
   campaign:inputs.immutable_campaign,revoked:Cell::new(false),closed:false};
  let operation=(||{
   // Hold every original, including the selected native comparator DLL, before
   // executing any backing comparison. Candidate modules are never opened.
   for spec in inputs.original_objects{
    owner.originals.push(OriginalPublicFile::open_registered(spec,&owner.token.user_sid,inputs.installed_crt.as_ref())?);
   }
   // Check every actual native import, including the imported loader/mapping
   // calls, before the first backing comparison. Section111 dynamically
   // resolves its comparator; the trusted factory must separately authenticate
   // that exact selected Nt export/ABI. This IAT check does not qualify it.
   // Authenticate the original requested name/ordinal chain against retained
   // parsed tables and current OWN loader references. No version rewrite.
   owner.bindings=unsafe{owner.modules.resolve_requested_imports(&inputs.complete_slots,&inputs.full_parsed_exports)}?;
   owner.modules.require_declared_bindings(&owner.bindings)?;
   owner.modules.require_selected_comparator(owner.comparator_rva)?;
   for file in &owner.originals{file.recheck()?;}
   if own_native_token::observe_own()?!=owner.token{
    return Err("OWN process/token changed before selected backing comparison".into());
   }
   for(i,path)in approved.iter().enumerate(){
    let index=super::own_native_modules::selected_index(owner.modules.observations(),path)?;
    let original=owner.originals[i].original_file()?;
    // Original File+OWN live reference and selected ABI caller contract remain
    // explicit. No caller-provided raw image base reaches the comparator.
    owner.modules.require_selected_comparator(owner.comparator_rva)?;
    unsafe{owner.modules.require_original_file_backing(index,original)}?;
   }
   owner.require_custody_context(&owner.source,&owner.campaign)
  })();
  if let Err(primary)=operation{let closure=owner.close_checked();
   return Err(format!("OWN TEST qualification refused {primary}; closure={closure:?}"));}
  Ok(owner)
 }
 /// Called immediately before every custody entry with the provider's immutable
 /// prepared source/campaign. Consensus/counter/private-permit checks remain in
 /// the existing backend; this lease adds no spending or admission permission.
 pub(super) fn require_custody_context(&self,source:&[u8;32],campaign:&[u8;32])->Result<()>{
  let outcome=(||{
   if self.closed||self.revoked.get()||source!=&self.source||campaign!=&self.campaign{
    return Err("OWN execution lease revoked or wrong immutable provider context".into());}
   if own_native_token::observe_own()?!=self.token{return Err("OWN original primary token/process changed".into());}
   self.modules.recheck()?;for file in &self.originals{file.recheck()?;}
   self.modules.require_declared_bindings(&self.bindings)?;
   self.modules.require_selected_comparator(self.comparator_rva)?;
   self.modules.recheck()?;for file in &self.originals{file.recheck()?;}
   if own_native_token::observe_own()?!=self.token{return Err("OWN token/process changed during custody recheck".into());}
   Ok(())
  })();
  if outcome.is_err(){self.revoked.set(true);}outcome
 }
 pub(super) fn revoke(&self){self.revoked.set(true);}
 /// Consumed only after all providers/workers join. Each retained original and
 /// each original module reference receives an independent once-only close.
 pub(super) fn close_checked(&mut self)->Result<()>{
  if self.closed{return Err("OWN execution closure already consumed; no retry".into());}
  self.closed=true;self.revoked.set(true);let mut errors=Vec::new();
  for file in self.originals.iter_mut().rev(){if let Err(e)=file.recheck(){errors.push(e)}
   if let Err(e)=file.close_checked(){errors.push(e)}}
  if let Err(e)=self.modules.recheck(){errors.push(e)}
  if let Err(e)=self.modules.close_checked(){errors.push(e)}
  if errors.is_empty(){Ok(())}else{Err(format!("Independent OWN execution closures refused {errors:?}"))}
 }
}
impl Drop for OwnExecutionLease{fn drop(&mut self){if !self.closed{let _=self.close_checked();}}}
