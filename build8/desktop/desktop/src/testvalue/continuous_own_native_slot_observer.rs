//! Experimental OWN IAT observations from a complete independently admitted PE
//! slot/direct-export projection. Observations do not admit a loader capability.
//! Original API-contract names and requested symbols remain in the input; no
//! revision rewriting, basename resolution, LoadLibrary or target invocation.
use super::{OwnLoadedModules,Handle,ModuleObservation,metadata,spelling,Result};
use std::{collections::{BTreeMap,BTreeSet},ffi::{c_void,CString},path::PathBuf};
#[link(name="kernel32")]
unsafe extern "system" {
 fn GetCurrentProcess()->Handle;
 fn ReadProcessMemory(process:Handle,address:*const c_void,buffer:*mut c_void,
  bytes:usize,read:*mut usize)->i32;
 fn GetProcAddress(module:Handle,name:*const u8)->*mut c_void;
}
#[derive(Clone,Debug)]
pub(in super::super) enum RequestedSymbol{Named(String),Ordinal(u16)}
#[derive(Clone,Debug)]
pub(in super::super) struct CompleteSlot{
 pub(in super::super) importer:PathBuf,
 pub(in super::super) original_library:String,
 pub(in super::super) original_symbol:RequestedSymbol,
 pub(in super::super) iat_rva:u32,
 pub(in super::super) delayed:bool,
}
#[derive(Clone,Debug)]
pub(in super::super) struct ParsedDirectExport{
 pub(in super::super) module:PathBuf,
 pub(in super::super) symbol:RequestedSymbol,
 pub(in super::super) rva:u32,
}
#[derive(Clone,Debug)]
pub(in super::super) enum SlotState{
 Direct{target_module:u16,target_rva:u32,verified_export_indices:Vec<u32>},
 /// The address remains within its importer and has no parsed direct export.
 /// This is observed delay state, not permission to accept a future mapping.
 UnresolvedDelayedImporterAddress{importer_rva:u32},
}
#[derive(Clone,Debug)]
pub(in super::super) struct ObservedSlot{
 pub(in super::super) declared_slot:u32,
 pub(in super::super) importer_module:u16,
 pub(in super::super) state:SlotState,
}
#[derive(Clone,Debug)]
pub(in super::super) struct OwnSlotEvidence{
 pub(in super::super) original_modules:Vec<ModuleObservation>,
 pub(in super::super) slots:Vec<ObservedSlot>,
 pub(in super::super) unresolved_delayed:u32,
}
fn symbol_key(symbol:&RequestedSymbol,text:&mut usize)->Result<String>{
 match symbol{
  RequestedSymbol::Ordinal(n) if *n!=0=>Ok(format!("O:{n}")),
  RequestedSymbol::Named(name) if !name.is_empty()&&name.len()<=4096
   &&name.is_ascii()&&name.bytes().all(|b|(32..127).contains(&b))=>{
    *text=text.checked_add(name.len()).ok_or("Own slot symbol text overflow")?;
    if *text>16*1024*1024{return Err("Own slot symbol text budget".into());}
    Ok(format!("N:{name}"))},
  _=>Err("Own slot symbol bound/zero ordinal".into()),
 }
}
impl OwnLoadedModules{
 /// # Safety
 /// Caller independently authenticates the complete current original-file PE
 /// slot projection and DIRECT export tables against held input bytes/source,
 /// exact OWN roster and selected TEST role. DTOs and receipt hashes alone are
 /// insufficient. Original files and native guards remain held throughout.
 /// This is a finite observation only; it never constructs a qualified owner.
 pub(in super::super) unsafe fn observe_complete_iat_projection(&self,
  slots:&[CompleteSlot],exports:&[ParsedDirectExport])->Result<OwnSlotEvidence>{
  self.recheck()?;
  if slots.len()>131072||exports.len()>262144{return Err("Own slot/export budget".into());}
  let mut paths=BTreeMap::new();let mut text=0usize;
  for(i,module)in self.observations.iter().enumerate(){
   let path=spelling(&module.path)?;
   text=text.checked_add(path.len()).ok_or("Own module text overflow")?;
   if text>16*1024*1024||paths.insert(path,i).is_some(){return Err("Own module path/text ambiguity".into());}
  }
  let mut parsed=BTreeMap::<(usize,u32),Vec<usize>>::new();let mut unique_exports=BTreeSet::new();
  let mut export_modules=Vec::with_capacity(exports.len());
  // Bound and validate the entire input before any native export lookup/read.
  for(i,export)in exports.iter().enumerate(){
   let module=*paths.get(&spelling(&export.module)?).ok_or("Parsed export outside original OWN roster")?;
   if export.rva<4096||export.rva>=self.observations[module].image_bytes{
    return Err("Parsed direct export image range".into());}
   let key=symbol_key(&export.symbol,&mut text)?;
   if !unique_exports.insert((module,key)){return Err("Parsed direct export duplicate symbol".into());}
   parsed.entry((module,export.rva)).or_default().push(i);export_modules.push(module);
  }
  let mut imported=Vec::with_capacity(slots.len());let mut unique_slots=BTreeSet::new();
  for slot in slots{
   let module=*paths.get(&spelling(&slot.importer)?).ok_or("Declared importer outside original OWN roster")?;
   let library=&slot.original_library;
   if library.is_empty()||library.len()>260||!library.is_ascii()
    ||!library.bytes().all(|b|b.is_ascii_alphanumeric()||matches!(b,b'-'|b'_'|b'.')){
    return Err("Exact original imported module name bound".into());}
   text=text.checked_add(library.len()).ok_or("Own imported module text overflow")?;
   let _=symbol_key(&slot.original_symbol,&mut text)?;
   if text>16*1024*1024||slot.iat_rva<4096||slot.iat_rva%8!=0
    ||slot.iat_rva.checked_add(8).is_none_or(|end|end>self.observations[module].image_bytes)
    ||!unique_slots.insert((module,slot.iat_rva)){
    return Err("Complete OWN IAT slot/text/range/uniqueness refused".into());}
   imported.push(module);
  }
  let mut result=Vec::with_capacity(slots.len());let mut unresolved=0u32;
  let mut verified=BTreeSet::new();let mut alias_records=0usize;
  for(i,slot)in slots.iter().enumerate(){
   self.recheck()?;let importer=imported[i];let image=&self.observations[importer];
   let address=image.base.checked_add(slot.iat_rva as usize).ok_or("OWN IAT address overflow")?;
   let mut buffer=[0u8;8];let mut copied=0usize;
   if unsafe{ReadProcessMemory(GetCurrentProcess(),address as *const c_void,
    buffer.as_mut_ptr().cast(),8,&mut copied)}==0||copied!=8{
    return Err("Complete OWN IAT read refused".into());}
   let pointer=usize::try_from(u64::from_le_bytes(buffer)).map_err(|_|"OWN IAT pointer width")?;
   let matches:Vec<_>=self.observations.iter().enumerate().filter(|(_,module)|
    module.base<=pointer&&module.base.checked_add(module.image_bytes as usize)
     .is_some_and(|end|pointer<end)).collect();
   if matches.len()!=1{return Err("OWN IAT points outside or ambiguously into held original modules; no target file opened".into());}
   let(target,module)=matches[0];let rva=u32::try_from(pointer-module.base).map_err(|_|"OWN target RVA width")?;
   let state=if let Some(aliases)=parsed.get(&(target,rva)){
    alias_records=alias_records.checked_add(aliases.len()).ok_or("OWN observed alias count overflow")?;
    if alias_records>262144{return Err("OWN observed alias budget".into());}
    for index in aliases{if verified.insert(*index){
     let export=&exports[*index];let export_module=export_modules[*index];
     if export_module!=target{return Err("OWN parsed direct export identity drift".into());}
     let named=match &export.symbol{RequestedSymbol::Named(name)=>Some(CString::new(name.as_str()).map_err(|_|"OWN export symbol NUL")?),_=>None};
     let symbol=match &export.symbol{RequestedSymbol::Named(_)=>named.as_ref().unwrap().as_ptr().cast(),RequestedSymbol::Ordinal(n)=>(*n as usize)as*const u8};
     let actual=unsafe{GetProcAddress(module.base as Handle,symbol)}as usize;
     if actual!=pointer||metadata(module.base as Handle)?!=*module{
      return Err("OWN IAT physical target differs from actual held direct export/RVA".into());}
    }}
    SlotState::Direct{target_module:target as u16,target_rva:rva,
     verified_export_indices:aliases.iter().map(|index|*index as u32).collect()}
   }else if slot.delayed&&target==importer{
    unresolved=unresolved.checked_add(1).ok_or("OWN unresolved delay count overflow")?;
    SlotState::UnresolvedDelayedImporterAddress{importer_rva:rva}
   }else{return Err("OWN IAT physical destination has no authenticated parsed direct export; no fallback".into());};
   // A row cannot retain a pointer changed while its direct export was queried.
   // Cross-row observations are not an atomic snapshot or a custody capability.
   let mut after=[0u8;8];let mut after_copied=0usize;
   if unsafe{ReadProcessMemory(GetCurrentProcess(),address as *const c_void,
    after.as_mut_ptr().cast(),8,&mut after_copied)}==0||after_copied!=8||after!=buffer{
    return Err("OWN IAT slot changed during physical export observation".into());}
   result.push(ObservedSlot{declared_slot:i as u32,importer_module:importer as u16,state});
   self.recheck()?;
  }
  self.recheck()?;
  Ok(OwnSlotEvidence{original_modules:self.observations.clone(),slots:result,unresolved_delayed:unresolved})
 }
}
