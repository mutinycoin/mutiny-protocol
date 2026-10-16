//! Private OWN loader configuration, not a caller-supplied mapping authority.
//! Proposed selected layout: Windows x64 PEB ApiSetMap at 0x68, namespace v6.
//! No loader operation, module acquisition, original file open or target call.
use super::{OwnLoadedModules, ModuleObservation, Handle, Region, Result};
use std::{collections::{BTreeMap,BTreeSet}, ffi::c_void, mem::{size_of,zeroed}};

const MAX_BYTES:usize=16*1024*1024;
const MAX_ENTRIES:usize=65536;
const MAX_VALUES:usize=262144;
const PEB_API_SET_MAP:usize=0x68;
const HEADER:usize=28;
#[link(name="kernel32")]
unsafe extern "system" {
 fn ReadProcessMemory(process:Handle,address:*const c_void,buffer:*mut c_void,
  bytes:usize,read:*mut usize)->i32;
}
#[derive(Debug)]
struct Values{default:Option<Option<String>>,parents:BTreeMap<String,Option<String>>}
#[derive(Debug)]
struct Namespace{contracts:BTreeMap<String,Values>}
fn range(bytes:&[u8],offset:u32,length:usize)->Result<&[u8]>{
 let start=offset as usize;let end=start.checked_add(length).ok_or("API set span overflow")?;
 if start<HEADER||end>bytes.len(){return Err("API set span outside retained namespace".into());}
 Ok(&bytes[start..end])
}
fn word(bytes:&[u8],offset:usize)->Result<u32>{
 let end=offset.checked_add(4).ok_or("API set word overflow")?;
 let value=bytes.get(offset..end).ok_or("API set word outside retained namespace")?;
 Ok(u32::from_le_bytes(value.try_into().unwrap()))
}
fn ascii_utf16(bytes:&[u8],offset:u32,length:u32,empty:bool)->Result<String>{
 if length==0&&empty{return Ok(String::new());}
 if length==0||length%2!=0||length>520{return Err("API set exact UTF16 text bound".into());}
 let raw=range(bytes,offset,length as usize)?;let mut text=String::with_capacity(raw.len()/2);
 for pair in raw.chunks_exact(2){let c=u16::from_le_bytes([pair[0],pair[1]]);
  if !(33..127).contains(&c){return Err("API set bounded ASCII spelling required".into());}
  text.push(char::from_u32(c as u32).unwrap());
 }Ok(text)
}
fn basename(name:&str)->Result<String>{
 if name.is_empty()||name.len()>260||!name.is_ascii()
  ||!name.bytes().all(|b|b.is_ascii_alphanumeric()||matches!(b,b'-'|b'_'|b'.'))
  ||name=="."||name==".."||name.ends_with('.'){
  return Err("API set exact bounded basename".into());
 }Ok(name.to_ascii_lowercase())
}
fn contract(name:&str)->Result<String>{
 let lower=basename(name)?;
 // Only the documented optional .dll spelling is normalized; the complete
 // version and all contract components remain part of the equality key.
 let key=lower.strip_suffix(".dll").unwrap_or(&lower);
 if !(key.starts_with("api-")||key.starts_with("ext-"))||key.contains('.'){
  return Err("Exact API set contract spelling required".into());
 }Ok(key.into())
}
pub(super) fn is_contract(name:&str)->bool{
 name.get(..4).is_some_and(|prefix|prefix.eq_ignore_ascii_case("api-")||prefix.eq_ignore_ascii_case("ext-"))
}
impl Namespace{
 fn parse(bytes:&[u8])->Result<Self>{
  if bytes.len()<HEADER||bytes.len()>MAX_BYTES||word(bytes,0)?!=6
   ||word(bytes,4)? as usize!=bytes.len()||word(bytes,8)?!=0{
   return Err("Unsupported selected API set namespace v6/header/flags".into());
  }
  let count=word(bytes,12)? as usize;
  if count==0||count>MAX_ENTRIES{return Err("API set namespace entry cap".into());}
  let entry_offset=word(bytes,16)?;let hash_offset=word(bytes,20)?;
  if entry_offset%4!=0||hash_offset%4!=0{return Err("API set table alignment".into());}
  let entries=range(bytes,entry_offset,count.checked_mul(24).ok_or("API set entry span overflow")?)?;
  let hashes=range(bytes,hash_offset,count.checked_mul(8).ok_or("API set hash span overflow")?)?;
  // Lookup uses full contract equality, not the version-truncated hash key.
  let mut hash_indices=BTreeSet::new();
  for hash in hashes.chunks_exact(8){let i=u32::from_le_bytes(hash[4..8].try_into().unwrap()) as usize;
   if i>=count||!hash_indices.insert(i){return Err("API set hash index ambiguity/range".into());}}
  let mut contracts=BTreeMap::new();let mut values_total=0usize;let mut expanded_text=0usize;
  for entry in entries.chunks_exact(24){
   if word(entry,0)?>1{return Err("Unsupported selected API set entry flags".into());}
   let name_length=word(entry,8)?;let hashed_length=word(entry,12)?;
   if hashed_length==0||hashed_length%2!=0||hashed_length>name_length{
    return Err("API set hashed name length bound".into());
   }
   let name=contract(&ascii_utf16(bytes,word(entry,4)?,name_length,false)?)?;
   expanded_text=expanded_text.checked_add(name.len()).ok_or("API set expanded text overflow")?;
   if expanded_text>MAX_BYTES{return Err("API set expanded text budget".into());}
   let value_count=word(entry,20)? as usize;
   values_total=values_total.checked_add(value_count).ok_or("API set value count overflow")?;
   if values_total>MAX_VALUES{return Err("API set aggregate value cap".into());}
   let value_offset=word(entry,16)?;
   let values=if value_count==0{&[][..]}else{
    if value_offset%4!=0{return Err("API set value table alignment".into());}
    range(bytes,value_offset,value_count.checked_mul(20).ok_or("API set value span overflow")?)?
   };
   let mut selected=Values{default:None,parents:BTreeMap::new()};
   for value in values.chunks_exact(20){
    if word(value,0)?!=0{return Err("Unsupported selected API set value flags".into());}
    let parent=ascii_utf16(bytes,word(value,4)?,word(value,8)?,true)?;
    let host=ascii_utf16(bytes,word(value,12)?,word(value,16)?,true)?;
    expanded_text=expanded_text.checked_add(parent.len()).and_then(|n|n.checked_add(host.len()))
     .ok_or("API set expanded text overflow")?;
    if expanded_text>MAX_BYTES{return Err("API set expanded text budget".into());}
    let host=if host.is_empty(){None}else{Some(basename(&host)?)};
    if parent.is_empty(){if selected.default.replace(host).is_some(){return Err("API set duplicate default".into());}}
    else if selected.parents.insert(basename(&parent)?,host).is_some(){return Err("API set duplicate referring module".into());}
   }
   if contracts.insert(name,selected).is_some(){return Err("API set duplicate exact contract".into());}
  }Ok(Self{contracts})
 }
 fn host(&self,name:&str,referrer:&str)->Result<&str>{
  let values=self.contracts.get(&contract(name)?).ok_or("Exact API set contract absent")?;
  let parent=basename(referrer)?;
  // A named entry, including an explicitly unmapped entry, takes precedence.
  let selected=values.parents.get(&parent).or(values.default.as_ref())
   .ok_or("API set exact referring module/default absent")?;
  selected.as_deref().ok_or_else(||"API set selected host unavailable".into())
 }
}
fn held_host(observations:&[ModuleObservation],host:&str)->Result<usize>{
 let key=basename(host)?;let mut selected=None;
 for(index,module)in observations.iter().enumerate(){
  let name=module.path.file_name().and_then(|n|n.to_str()).ok_or("Held OWN basename spelling")?;
  if basename(name)?==key&&selected.replace(index).is_some(){return Err("API set host ambiguous in held OWN roster".into());}
 }
 selected.ok_or_else(||"API set host outside held OWN roster; no query/open/load".into())
}
fn user_span(address:usize,bytes:usize)->Result<usize>{
 let end=address.checked_add(bytes).ok_or("OWN API set address overflow")?;
 if address<0x10000||bytes==0||bytes>MAX_BYTES||end>0x0000_8000_0000_0000{
  return Err("Selected x64 OWN API set user address bound".into());
 }Ok(end)
}
fn read_current(owner:&OwnLoadedModules,address:usize,bytes:usize)->Result<Vec<u8>>{
 owner.recheck()?;let end=user_span(address,bytes)?;let mut cursor=address;let mut regions=0usize;
 while cursor<end{
  regions+=1;if regions>8192{return Err("OWN API set region cap".into());}
  let mut region:Region=unsafe{zeroed()};
  if unsafe{super::VirtualQuery(cursor as *const c_void,&mut region,size_of::<Region>())}!=size_of::<Region>()
   ||region.state!=0x1000||region.protect&0x100!=0
   ||!matches!(region.protect&0xff,0x02|0x04|0x08|0x20|0x40|0x80){
   return Err("OWN API set committed readable nonguard region required".into());
  }
  let start=region.base as usize;let next=start.checked_add(region.region_size).ok_or("OWN API set region overflow")?;
  if start>cursor||next<=cursor{return Err("OWN API set region progress/range".into());}
  cursor=next.min(end);
 }
 let mut result=vec![0u8;bytes];let mut copied=0usize;
 // Only this owner's current process pseudo-handle; no PID reopen/foreign read.
 if unsafe{ReadProcessMemory(super::GetCurrentProcess(),address as *const c_void,
  result.as_mut_ptr().cast(),bytes,&mut copied)}==0||copied!=bytes{
  return Err("Exact bounded current OWN loader configuration read refused".into());
 }
 owner.recheck()?;Ok(result)
}
struct Snapshot{peb:usize,map:usize,bytes:Vec<u8>}
unsafe fn snapshot(owner:&OwnLoadedModules)->Result<Snapshot>{
 let peb:usize;
 unsafe{core::arch::asm!("mov {}, gs:[0x60]",out(reg) peb,options(nostack,readonly,preserves_flags));}
 let pointer=read_current(owner,peb.checked_add(PEB_API_SET_MAP).ok_or("OWN PEB field overflow")?,8)?;
 let map=u64::from_le_bytes(pointer.try_into().unwrap()) as usize;
 let header=read_current(owner,map,HEADER)?;
 if word(&header,0)?!=6{return Err("Unsupported selected current OWN API set layout".into());}
 let size=word(&header,4)? as usize;
 if !(HEADER..=MAX_BYTES).contains(&size){return Err("OWN API set namespace size cap".into());}
 let bytes=read_current(owner,map,size)?;
 if bytes[..HEADER]!=header[..]{return Err("OWN API set header changed during snapshot".into());}
 Ok(Snapshot{peb,map,bytes})
}
pub(super) struct ApiSetContext{snapshot:Snapshot,namespace:Namespace}
impl ApiSetContext{
 /// # Safety
 /// Caller selects the Windows x64 PEB ApiSetMap offset 0x68/namespace-v6
 /// layout and normal trusted local OWN loader-configuration domain. This is
 /// not established merely by receiving a public receipt or untrusted DTO.
 /// No adversarial own-memory writer is admitted. The mapping is retained and
 /// byte-rechecked, but this does not claim an atomic OS namespace read lease.
 pub(super) unsafe fn observe(owner:&OwnLoadedModules)->Result<Self>{
  let observed=unsafe{snapshot(owner)}?;let namespace=Namespace::parse(&observed.bytes)?;
  let result=Self{snapshot:observed,namespace};result.recheck(owner)?;Ok(result)
 }
 pub(super) fn recheck(&self,owner:&OwnLoadedModules)->Result<()>{
  let current=unsafe{snapshot(owner)}?;
  if current.peb!=self.snapshot.peb||current.map!=self.snapshot.map||current.bytes!=self.snapshot.bytes{
   return Err("Retained OWN API set context changed".into());
  }Ok(())
 }
 pub(super) fn resolve(&self,owner:&OwnLoadedModules,referrer:usize,name:&str)->Result<usize>{
  self.recheck(owner)?;
  let module=owner.observations.get(referrer).ok_or("API set referrer outside held OWN roster")?;
  let parent=module.path.file_name().and_then(|n|n.to_str()).ok_or("API set held referrer spelling")?;
  let host=self.namespace.host(name,parent)?;
  let index=held_host(&owner.observations,host)?;
  self.recheck(owner)?;Ok(index)
 }
}

#[cfg(test)]
mod pure_controls{
 use super::*;
 use std::path::PathBuf;
 fn put(bytes:&mut[u8],at:usize,value:u32){bytes[at..at+4].copy_from_slice(&value.to_le_bytes());}
 fn text(bytes:&mut Vec<u8>,value:&str)->(u32,u32){let start=bytes.len() as u32;
  for c in value.encode_utf16(){bytes.extend_from_slice(&c.to_le_bytes());}(start,bytes.len() as u32-start)}
 fn fixture_contracts(entries:&[(&str,&[(&str,&str)])])->Vec<u8>{
  let hash_offset=HEADER+entries.len()*24;let value_start=hash_offset+entries.len()*8;
  let value_count:usize=entries.iter().map(|(_,values)|values.len()).sum();
  let mut b=vec![0;value_start+value_count*20];put(&mut b,0,6);put(&mut b,12,entries.len() as u32);
  put(&mut b,16,HEADER as u32);put(&mut b,20,hash_offset as u32);let mut value_cursor=value_start;
  for(i,(name,values))in entries.iter().enumerate(){let at=HEADER+i*24;let(n,l)=text(&mut b,name);
   put(&mut b,at+4,n);put(&mut b,at+8,l);put(&mut b,at+12,l);put(&mut b,at+16,value_cursor as u32);put(&mut b,at+20,values.len() as u32);
   put(&mut b,hash_offset+i*8+4,i as u32);
   for(parent,host)in *values{let(p,pl)=text(&mut b,parent);let(h,hl)=text(&mut b,host);put(&mut b,value_cursor+4,p);put(&mut b,value_cursor+8,pl);put(&mut b,value_cursor+12,h);put(&mut b,value_cursor+16,hl);value_cursor+=20;}
  }let size=b.len() as u32;put(&mut b,4,size);b
 }
 fn fixture(values:&[(&str,&str)])->Vec<u8>{fixture_contracts(&[("api-ms-fixture-l1-1-0",values)])}
 #[test] fn default_host_and_exact_version(){let n=Namespace::parse(&fixture(&[("","default.dll")])).unwrap();
  assert_eq!(n.host("API-MS-FIXTURE-L1-1-0.dll","client.exe").unwrap(),"default.dll");
  assert!(n.host("api-ms-fixture-l1-1-1","client.exe").is_err());}
 #[test] fn referring_module_overrides_default(){let n=Namespace::parse(&fixture(&[("","default.dll"),("origin.dll","specific.dll")])).unwrap();
  assert_eq!(n.host("api-ms-fixture-l1-1-0","ORIGIN.DLL").unwrap(),"specific.dll");
  assert_eq!(n.host("api-ms-fixture-l1-1-0","other.dll").unwrap(),"default.dll");}
 #[test] fn explicit_unmapped_parent_does_not_fall_back(){let n=Namespace::parse(&fixture(&[("","default.dll"),("origin.dll","")])).unwrap();
  assert!(n.host("api-ms-fixture-l1-1-0","origin.dll").is_err());}
 #[test] fn duplicates_refuse(){assert!(Namespace::parse(&fixture(&[("","a.dll"),("","b.dll")])).is_err());
  assert!(Namespace::parse(&fixture(&[("origin.dll","a.dll"),("ORIGIN.DLL","b.dll")])).is_err());}
 #[test] fn malformed_spans_versions_and_lengths_refuse(){let good=fixture(&[("","host.dll")]);
  let mut b=good.clone();put(&mut b,32,u32::MAX);assert!(Namespace::parse(&b).is_err());
  let mut b=good.clone();put(&mut b,36,3);assert!(Namespace::parse(&b).is_err());
  let mut b=good.clone();put(&mut b,0,7);assert!(Namespace::parse(&b).is_err());
  let mut b=good.clone();put(&mut b,48,262145);assert!(Namespace::parse(&b).is_err());
  let mut b=good;put(&mut b,20,u32::MAX);assert!(Namespace::parse(&b).is_err());}
 #[test] fn known_host_required_and_duplicate_basename_refuses(){let make=|p:&str,base|ModuleObservation{path:PathBuf::from(p),image_bytes:8192,base};
  let one=vec![make(r"C:\Windows\System32\host.dll",0x1000)];assert_eq!(held_host(&one,"HOST.DLL").unwrap(),0);
  assert!(held_host(&one,"unknown.dll").is_err());let two=vec![make(r"C:\Windows\System32\host.dll",0x1000),make(r"C:\Elsewhere\host.dll",0x2000)];
  assert!(held_host(&two,"host.dll").is_err());}
 #[test] fn absent_named_and_default_and_empty_host_refuse(){let n=Namespace::parse(&fixture(&[("origin.dll","host.dll")])).unwrap();assert!(n.host("api-ms-fixture-l1-1-0","other.dll").is_err());
  let n=Namespace::parse(&fixture(&[("","")])).unwrap();assert!(n.host("api-ms-fixture-l1-1-0","other.dll").is_err());}
 #[test] fn duplicate_exact_contract_refuses(){let values=[("","host.dll")];
  assert!(Namespace::parse(&fixture_contracts(&[("api-ms-fixture-l1-1-0",&values),("API-MS-FIXTURE-L1-1-0",&values)])).is_err());}
 #[test] fn unsupported_flags_and_hash_indices_refuse(){let good=fixture(&[("","host.dll")]);
  let mut b=good.clone();put(&mut b,8,2);assert!(Namespace::parse(&b).is_err());
  let mut b=good.clone();put(&mut b,28,2);assert!(Namespace::parse(&b).is_err());
  let mut b=good;put(&mut b,56,1);assert!(Namespace::parse(&b).is_err());}
 #[test] fn current_own_user_span_refuses_bad_ranges(){assert!(user_span(0x10000,28).is_ok());
  assert!(user_span(0,28).is_err());assert!(user_span(0x10000,0).is_err());
  assert!(user_span(0x10000,MAX_BYTES+1).is_err());assert!(user_span(usize::MAX,28).is_err());}
 #[test] fn valid_context_forwarding_preserves_physical_cycle_key(){let n=Namespace::parse(&fixture(&[("","forwarder.dll"),("forwarder.dll","host.dll")])).unwrap();
  let modules=vec![ModuleObservation{path:PathBuf::from(r"C:\Fixture\client.exe"),image_bytes:8192,base:0x1000},
   ModuleObservation{path:PathBuf::from(r"C:\Fixture\forwarder.dll"),image_bytes:8192,base:0x2000},
   ModuleObservation{path:PathBuf::from(r"C:\Fixture\host.dll"),image_bytes:8192,base:0x3000}];
  let mut visited=BTreeSet::new();assert!(super::super::requested_bindings::record_visit(&mut visited,1,"N:Fixture"));
  let host=held_host(&modules,n.host("api-ms-fixture-l1-1-0","forwarder.dll").unwrap()).unwrap();
  assert_eq!(host,2);assert!(super::super::requested_bindings::record_visit(&mut visited,host,"N:Fixture"));}
 #[test] fn genuine_same_physical_node_cycle_still_refuses(){let n=Namespace::parse(&fixture(&[("","forwarder.dll")])).unwrap();
  let modules=vec![ModuleObservation{path:PathBuf::from(r"C:\Fixture\forwarder.dll"),image_bytes:8192,base:0x1000}];
  let mut visited=BTreeSet::new();assert!(super::super::requested_bindings::record_visit(&mut visited,0,"N:Fixture"));
  let host=held_host(&modules,n.host("api-ms-fixture-l1-1-0","forwarder.dll").unwrap()).unwrap();
  assert!(!super::super::requested_bindings::record_visit(&mut visited,host,"N:Fixture"));}
}
