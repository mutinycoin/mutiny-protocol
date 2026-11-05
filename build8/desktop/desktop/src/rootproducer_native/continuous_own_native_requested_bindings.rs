//! Private OWN requested import identity -> held physical direct export.
//! No API-set revision rewrite, schema alias, manual load or target invocation.
//! An unavailable exact already-loaded name is a refusal, not a fallback.
use super::{OwnLoadedModules,Handle,metadata,spelling,Result,DeclaredImport,Symbol};
use super::slot_observer::{CompleteSlot,RequestedSymbol};
use std::{collections::{BTreeMap,BTreeSet},path::PathBuf};
#[link(name="kernel32")]
unsafe extern "system" {
 fn GetModuleHandleW(name:*const u16)->Handle;
}
#[derive(Clone,Debug)]
pub(in super::super) struct ParsedRequestedExport{
 pub(in super::super) module:PathBuf,
 pub(in super::super) symbol:RequestedSymbol,
 pub(in super::super) rva:u32,
 pub(in super::super) forwarder:Option<String>,
}
fn symbol_key(symbol:&RequestedSymbol)->Result<String>{
 match symbol{
  RequestedSymbol::Ordinal(n) if *n!=0=>Ok(format!("O:{n}")),
  RequestedSymbol::Named(name) if !name.is_empty()&&name.len()<=4096
   &&name.is_ascii()&&name.bytes().all(|b|(33..127).contains(&b))=>Ok(format!("N:{name}")),
  _=>Err("Exact requested export symbol bound/zero ordinal".into()),
 }
}
pub(super) fn record_visit(visited:&mut BTreeSet<(usize,String)>,module:usize,key:&str)->bool{
 visited.insert((module,key.into()))
}
fn bare(name:&str)->Result<()>{
 if name.is_empty()||name.len()>260||!name.is_ascii()
  ||!name.bytes().all(|b|b.is_ascii_alphanumeric()||matches!(b,b'-'|b'_'|b'.'))
  ||name=="."||name==".."||name.ends_with('.')
  ||(name.contains('.')&&!name.to_ascii_lowercase().ends_with(".dll")){
  return Err("Only exact bounded bare DLL name or documented no-extension name".into());
 }Ok(())
}
fn forwarder(value:&str)->Result<(String,RequestedSymbol)>{
 if value.len()>4367||!value.is_ascii(){return Err("Bounded retained forwarder".into());}
 let (module,symbol)=value.rsplit_once('.').ok_or("Exact retained forwarder delimiter")?;
 bare(module)?;
 let symbol=if let Some(decimal)=symbol.strip_prefix('#'){
  if decimal.is_empty()||decimal.len()>5||!decimal.bytes().all(|b|b.is_ascii_digit()){
   return Err("Exact retained forwarder ordinal".into());
  }
  RequestedSymbol::Ordinal(decimal.parse::<u16>().map_err(|_|"Retained forwarder ordinal range")?)
 }else{RequestedSymbol::Named(symbol.into())};
 symbol_key(&symbol)?;
 Ok((module.into(),symbol))
}
impl OwnLoadedModules{
 /// # Safety
 /// Caller authenticates ALL slots and full exports/forwarders of every exact
 /// OWN importer/target against original held PE bytes, using the selected
 /// Windows loader context. The internal DTOs are not an authenticity boundary.
 /// All original files and this owner’s references remain held throughout.
 /// No unresolved delay slot or omitted import may be accepted by the factory.
 /// This creates binding observations only, never an application capability.
 pub(in super::super) unsafe fn resolve_requested_imports(
  &self,slots:&[CompleteSlot],exports:&[ParsedRequestedExport])->Result<Vec<DeclaredImport>>{
  self.recheck()?;
  if slots.len()>131072||exports.len()>262144{return Err("Requested slot/export bound".into());}
  let mut paths=BTreeMap::new();let mut indexed=BTreeMap::new();let mut text=0usize;
  for(i,module)in self.observations.iter().enumerate(){
   let path=spelling(&module.path)?;
   text=text.checked_add(path.len()).ok_or("Requested module text overflow")?;
   if text>16*1024*1024||paths.insert(path,i).is_some(){
    return Err("Exact requested OWN roster ambiguity/text budget".into());
   }
  }
  // Entire authenticated DTO input is bounded before the first native query.
  for(i,export)in exports.iter().enumerate(){
   text=text.checked_add(export.module.as_os_str().len()).ok_or("Per-export original path text overflow")?;
   let module=*paths.get(&spelling(&export.module)?).ok_or("Requested export outside held OWN roster")?;
   let symbol=symbol_key(&export.symbol)?;
   text=text.checked_add(symbol.len()).ok_or("Requested export text overflow")?;
   if export.rva<4096||export.rva>=self.observations[module].image_bytes{
    return Err("Requested export RVA outside original image".into());
   }
   if let Some(value)=&export.forwarder{
    let _=forwarder(value)?;
    text=text.checked_add(value.len()).ok_or("Retained forwarder text overflow")?;
   }
   if text>16*1024*1024||indexed.insert((module,symbol),i).is_some(){
    return Err("Requested export table ambiguity/text budget".into());
   }
  }
  let mut unique=BTreeSet::new();
  for slot in slots{
   text=text.checked_add(slot.importer.as_os_str().len()).ok_or("Per-slot original path text overflow")?;
   let module=*paths.get(&spelling(&slot.importer)?).ok_or("Requested importer outside held OWN roster")?;
   bare(&slot.original_library)?;
   let symbol=symbol_key(&slot.original_symbol)?;
   text=text.checked_add(slot.original_library.len()).and_then(|n|n.checked_add(symbol.len()))
    .ok_or("Requested import text overflow")?;
   if text>16*1024*1024||slot.iat_rva<4096||slot.iat_rva%8!=0
    ||slot.iat_rva.checked_add(8).is_none_or(|n|n>self.observations[module].image_bytes)
    ||!unique.insert((module,slot.iat_rva)){
    return Err("Complete unique requested IAT/text/image range".into());
   }
  }
  let mut context:Option<super::api_set_context::ApiSetContext>=None;
  let mut bindings=Vec::with_capacity(slots.len());let mut steps=0usize;
  let mut output_text=0usize;
  for(slot_ordinal,slot)in slots.iter().enumerate(){
   let mut name=slot.original_library.clone();let mut symbol=slot.original_symbol.clone();
   let importer=paths[&spelling(&slot.importer)?];
   let mut referrer=importer;
   let mut visited=BTreeSet::new();let mut selected=None;
   let mut trace=Vec::with_capacity(64);
   for _ in 0..64{
    steps=steps.checked_add(1).ok_or("Requested forwarder step overflow")?;
    if steps>262144{return Err("Aggregate requested forwarder step budget".into());}
    self.recheck()?;bare(&name)?;
    let wide=name.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    // Query only an already-loaded exact name. No LoadLibrary or invented API
    // contract version. References for every admitted OWN module are already
    // held by this owner, so a returned known base remains live through use.
    let queried=if super::api_set_context::is_contract(&name){
     if context.is_none(){
      // Safety extends the existing selected OWN loader-context prerequisite:
      // exact Windows x64 PEB 0x68/namespace-v6 normal trusted configuration.
      context=Some(unsafe{super::api_set_context::ApiSetContext::observe(self)}?);
     }
     let host=context.as_ref().unwrap().resolve(self,referrer,&name).map_err(|error|{
      // Diagnostic only: existing validated names<=260, symbols<=4096,
      // paths<=4096 and prior trace<=64 bound this public text below 1 MiB.
      // No namespace bytes, new query, guessed host or failed hop is added.
      format!(
       "Exact API set lookup refused: slot_ordinal={slot_ordinal}, importer_index={importer}, importer_path={:?}, iat_rva={:#x}, original_library={:?}, original_symbol={:?}, requested_contract={name:?}, requested_symbol={symbol:?}, referrer_index={referrer}, referrer_module={:?}, previous_resolved_trace={trace:?}; cause={error}",
       slot.importer,slot.iat_rva,slot.original_library,slot.original_symbol,self.observations[referrer].path)
     })?;
     self.observations[host].base
    }else{(unsafe{GetModuleHandleW(wide.as_ptr())}) as usize};
    if queried==0{return Err(format!("Exact requested already-loaded module unavailable: {name}"));}
    let matches=self.observations.iter().enumerate().filter(|(_,m)|m.base==queried).collect::<Vec<_>>();
    if matches.len()!=1{
     // Do not obtain metadata or open a file for an unknown returned module.
     return Err("Requested native module handle outside held OWN roster".into());
    }
    let(module,observation)=matches[0];self.recheck()?;
    if metadata(queried as Handle)?!=*observation{
     return Err("Requested original module lifetime/identity changed".into());
    }
    let key=symbol_key(&symbol)?;
    trace.push((module,referrer,name.clone(),key.clone()));
    if !record_visit(&mut visited,module,&key){
     let importer=paths[&spelling(&slot.importer)?];
     return Err(format!(
      "Exact requested forwarder cycle: slot_ordinal={slot_ordinal}, importer_index={importer}, iat_rva={:#x}, original_library={:?}, original_symbol_key={:?}, trace={trace:?}",
      slot.iat_rva,slot.original_library,trace[0].3));
    }
    let export=&exports[*indexed.get(&(module,key)).ok_or("Requested symbol absent from authenticated original export table")?];
    if let Some(value)=&export.forwarder{
     (name,symbol)=forwarder(value)?;referrer=module;continue;
    }
    // Repeated forwarders may share one large input symbol. Bound expanded
    // retained output before cloning that symbol/path for another IAT slot.
    let symbol_bytes=match &export.symbol{RequestedSymbol::Named(n)=>n.len(),RequestedSymbol::Ordinal(_)=>0};
    output_text=output_text.checked_add(slot.importer.as_os_str().len())
     .and_then(|n|n.checked_add(observation.path.as_os_str().len()))
     .and_then(|n|n.checked_add(symbol_bytes)).ok_or("Requested binding output text overflow")?;
    if output_text>16*1024*1024{return Err("Requested expanded binding output text budget".into());}
    let physical_symbol=match &export.symbol{
     RequestedSymbol::Named(n)=>Symbol::Named(n.clone()),
     RequestedSymbol::Ordinal(n)=>Symbol::Ordinal(*n),
    };
    selected=Some(DeclaredImport{importer:slot.importer.clone(),target:observation.path.clone(),
     symbol:physical_symbol,iat_rva:slot.iat_rva,direct_export_rva:export.rva});break;
   }
   bindings.push(selected.ok_or("Exact requested forwarder depth bound")?);
  }
  // Genuine actual GetProcAddress on the retained DIRECT export plus the IAT
  // must agree for every requested chain. GetProcAddress never receives a
  // parsed forwarder here. Unresolved delayed importer addresses therefore
  // refuse; no lazy-slot escape or future mapping permission is introduced.
  if let Some(context)=&context{context.recheck(self)?;}
  self.require_declared_bindings(&bindings)?;
  if let Some(context)=&context{context.recheck(self)?;}
  self.recheck()?;
  Ok(bindings)
 }
}
