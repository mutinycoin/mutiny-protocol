//! Counter OWN-process current full mapped/backing boundary. No remote image,
//! physical NV/time qualification, Clock role, or caller-selected address.
#![cfg(windows)]
use crate::host_clock::{RetainedWindowsPublicObject,CurrentWindowsPrincipal,RetainedCloseReport,require_own_process_boundary};
use mutiny_consensus_v8::Hash;
use serde_json::{Map,Value};
use sha2::{Digest,Sha256};
use std::{collections::{BTreeMap,BTreeSet},ffi::c_void,mem::ManuallyDrop,path::Path};
#[derive(Debug)]
enum Error{UnsupportedCurrentFacts,Bound}
type Result<T>=std::result::Result<T,Error>;
fn bad()->Error{Error::UnsupportedCurrentFacts}
struct Object{file:ManuallyDrop<RetainedWindowsPublicObject>,size:u64,pin:Hash,regions:Vec<Region>}
fn exact<'a>(value:&'a Value,keys:&[&str])->Result<&'a Map<String,Value>> {
    let map=value.as_object().ok_or_else(bad)?;
    if map.len()!=keys.len()||map.keys().any(|key|!keys.contains(&key.as_str())){return Err(bad());}Ok(map)
}
fn digest(value:&Value)->Result<Hash>{
    let text=value.as_str().ok_or_else(bad)?;let mut hash=[0;32];
    if text.len()!=64||!text.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
        ||hex::decode_to_slice(text,&mut hash).is_err()||hash==[0;32]{return Err(bad());}Ok(hash)
}
fn canonical(raw:&[u8])->Result<Value>{
    if raw.is_empty()||raw.len()>65536{return Err(Error::Bound);}
    let value:Value=serde_json::from_slice(raw).map_err(|_|bad())?;
    if serde_json::to_vec(&value).map_err(|_|bad())?!=raw{return Err(bad());}Ok(value)
}
const ROOT:&str=r"C:\ProgramData\Mutiny\CustodyV2\public";
struct CurrentState {
    context:Hash,role:String,release_pin:Hash,source_pin:Hash,loaded_pin:Hash,
    documents:Vec<ManuallyDrop<RetainedWindowsPublicObject>>,
    objects:BTreeMap<String,Object>,executable:String,
    principal:Option<CurrentWindowsPrincipal>,expected_sid:Vec<u8>,session:u32,authentication:u64,frozen:bool,
}
pub(crate) struct CounterOwnWindowsCurrent{state:ManuallyDrop<Box<CurrentState>>}
impl CounterOwnWindowsCurrent {
    /// Pure bounded descriptor validation. This issues no current-code or
    /// remote-provider capability and performs no path or native operation.
    pub(crate) fn validate_selected_release(value:&Value,path:&str,pin:Hash)->std::result::Result<(),String>{
        selected_release(value,path,pin).map_err(|_|"counter loaded descriptor release link invalid".to_owned())
    }
    pub(crate) fn open(context:Hash,role:&str,release_pin:Hash,sid:&[u8],session:u32,authentication:u64)
        ->std::result::Result<Self,String>{
        if context==[0;32]||release_pin==[0;32]||!matches!(role,"consumer"|"provider")||sid.len()>68 {
            return Err("counter current selected context/role bound".into());
        }
        let mut documents=Vec::new();documents.reserve_exact(3);
        let mut current=Self{state:ManuallyDrop::new(Box::new(CurrentState{context,role:role.to_owned(),
            release_pin,source_pin:[0;32],loaded_pin:[0;32],documents,objects:BTreeMap::new(),
            executable:String::new(),principal:None,expected_sid:sid.to_vec(),session,authentication,frozen:false}))};
        current.initialize().map_err(|_|"counter exact OWN current software selection unavailable".to_owned())?;
        current.recheck()?;Ok(current)
    }
    fn document(&mut self,pin:Hash,suffix:&str)->Result<Vec<u8>> {
        let path=Path::new(ROOT).join(format!("{}.{suffix}",hex::encode(pin)));
        let file=RetainedWindowsPublicObject::open(&path,false,1).map_err(|_|bad())?;
        self.state.documents.push(ManuallyDrop::new(file));
        let raw=self.state.documents.last_mut().ok_or_else(bad)?.bounded_bytes(65536).map_err(|_|bad())?;
        if Hash::from(Sha256::digest(&raw))!=pin{return Err(bad());}Ok(raw)
    }
    fn initialize(&mut self)->Result<()> {
        self.state.principal=Some(CurrentWindowsPrincipal::capture_own().map_err(|_|bad())?);
        self.check_principal()?;
        let raw=self.document(self.state.release_pin,"release.json")?;
        let release=canonical(&raw)?;
        let r=exact(&release,&["format","target","context","role","executable_path","executable_sha256","source_receipt_sha256","loaded_sha256"])?;
        if r["format"]!="build8/counter/windows-release-v1"||r["target"]!="windows-x86_64"
            ||digest(&r["context"])?!=self.state.context||r["role"].as_str()!=Some(self.state.role.as_str()) {return Err(bad());}
        let executable=r["executable_path"].as_str().ok_or_else(bad)?.to_ascii_lowercase();
        let handle=unsafe{GetModuleHandleW(std::ptr::null())};
        if handle.is_null()||module_path(handle)?!=executable{return Err(bad());}
        let executable_pin=digest(&r["executable_sha256"])?;
        self.state.source_pin=digest(&r["source_receipt_sha256"])?;
        self.state.loaded_pin=digest(&r["loaded_sha256"])?;
        let source_raw=self.document(self.state.source_pin,"source.json")?;
        let source=canonical(&source_raw)?;
        let s=exact(&source,&["format","target","context","role","source_tree_sha256","build_recipe_sha256","toolchain_sha256","executable_sha256"])?;
        if s["format"]!="build8/counter/release-source-v1"||s["target"]!=r["target"]
            ||s["role"]!=r["role"]||digest(&s["context"])?!=self.state.context
            ||digest(&s["executable_sha256"])?!=executable_pin{return Err(bad());}
        for name in ["source_tree_sha256","build_recipe_sha256","toolchain_sha256"]{digest(&s[name])?;}
        let loaded_raw=self.document(self.state.loaded_pin,"loaded.json")?;
        let loaded=canonical(&loaded_raw)?;
        let l=exact(&loaded,&["format","target","context","role","source_receipt_sha256","objects","backing_identity"])?;
        if l["format"]!="build8/counter/windows-loaded-v1"||l["backing_identity"]!="nt-are-mapped-files-the-same-v1"
            ||l["target"]!=r["target"]||l["role"]!=r["role"]||digest(&l["context"])?!=self.state.context
            ||digest(&l["source_receipt_sha256"])?!=self.state.source_pin{return Err(bad());}
        selected_release(&l["objects"],&executable,executable_pin)?;
        let rows=l["objects"].as_array().ok_or_else(bad)?;
        if rows.is_empty()||rows.len()>256{return Err(Error::Bound);}
        let mut identities=BTreeSet::new();
        for row in rows {
            let o=exact(row,&["path","class","bytes","sha256","volume","file_id","links","regions"])?;
            let path=o["path"].as_str().ok_or_else(bad)?;let key=path.to_ascii_lowercase();
            let os=match o["class"].as_str(){Some("OS_SYSTEM32_DLL_EXACT_LINKS")=>true,Some("ADMIN_SELECTED_CURRENT_IMAGE")=>false,_=>return Err(bad())};
            let links=u32::try_from(o["links"].as_u64().ok_or_else(bad)?).map_err(|_|bad())?;
            let mut file=ManuallyDrop::new(RetainedWindowsPublicObject::open(Path::new(path),os,links).map_err(|_|bad())?);
            let(volume,id,_)=file.file_identity();
            if o["volume"].as_u64()!=Some(volume)||o["file_id"].as_str()!=Some(hex::encode(id).as_str())
                ||!identities.insert((volume,id)){return Err(bad());}
            let size=o["bytes"].as_u64().ok_or_else(bad)?;let pin=digest(&o["sha256"])?;
            if file.hash_exact(size).map_err(|_|bad())?!=pin{return Err(bad());}
            let regions=selected_regions(&o["regions"])?;
            if self.state.objects.insert(key,Object{file,size,pin,regions}).is_some(){return Err(bad());}
        }
        if self.state.objects.get(&executable).is_none_or(|object|object.pin!=executable_pin){return Err(bad());}
        self.state.executable=executable;Ok(())
    }
    fn check_principal(&self)->Result<()> {
        let principal=self.state.principal.as_ref().ok_or_else(bad)?;
        principal.recheck().map_err(|_|bad())?;
        if principal.user_sid()!=self.state.expected_sid.as_slice()||principal.session_id()!=self.state.session
            ||principal.authentication_luid()!=self.state.authentication{return Err(bad());}Ok(())
    }
    pub(crate) fn recheck(&mut self)->std::result::Result<(),String> {
        if self.state.frozen{return Err("counter OWN current boundary frozen".into());}
        self.state.frozen=true;
        self.current().map_err(|_|"counter exact OWN current software/principal changed".to_owned())?;
        self.state.frozen=false;Ok(())
    }
    pub(crate) fn retained_file_count(&self)->Option<usize>{
        self.state.documents.iter().map(|file|file.retained_file_count())
            .chain(self.state.objects.values().map(|object|object.file.retained_file_count()))
            .try_fold(0usize,|sum,count|sum.checked_add(count))
    }
    pub(crate) fn close_retained_into(mut self,report:&mut RetainedCloseReport)
        ->std::result::Result<(),ManuallyDrop<Self>> {
        // A failed current check effects no closes. The caller retains its
        // canonical owner and exact already allocated native close report.
        if self.recheck().is_err(){return Err(ManuallyDrop::new(self));}
        let Some(expected)=self.retained_file_count() else{return Err(ManuallyDrop::new(self));};
        let attempted=report.attempted();let uncertain=report.uncertain_count();
        self.state.frozen=true;
        while let Some(file)=self.state.documents.pop(){ManuallyDrop::into_inner(file).close_retained_into(report);}
        while let Some((_,object))=self.state.objects.pop_first(){ManuallyDrop::into_inner(object.file).close_retained_into(report);}
        if report.attempted().checked_sub(attempted)!=Some(expected)||report.uncertain_count()!=uncertain {
            return Err(ManuallyDrop::new(self));
        }
        // Successful principal capture owns numerical facts only. All token
        // closes were settled at capture/recheck, not deferred to this Drop.
        unsafe{ManuallyDrop::drop(&mut self.state)};Ok(())
    }
    fn current(&mut self)->Result<()> {
        self.check_principal()?;require_own_process_boundary().map_err(|_|bad())?;
        let before=image_roster()?;
        if self.state.documents.len()!=3{return Err(bad());}
        let pins=[self.state.release_pin,self.state.source_pin,self.state.loaded_pin];
        for(file,pin)in self.state.documents.iter_mut().zip(pins){
            if Hash::from(Sha256::digest(file.bounded_bytes(65536).map_err(|_|bad())?))!=pin{return Err(bad());}
        }
        if before.len()!=self.state.objects.len(){return Err(bad());}
        for(path,object)in &mut self.state.objects {
            let image=before.get(path).ok_or_else(bad)?;
            if image.regions!=object.regions||object.file.hash_exact(object.size).map_err(|_|bad())?!=object.pin{return Err(bad());}
            require_original_backing(object,image)?;
        }
        let handle=unsafe{GetModuleHandleW(std::ptr::null())};
        if handle.is_null()||module_path(handle)?!=self.state.executable||image_roster()?!=before{return Err(bad());}
        require_own_process_boundary().map_err(|_|bad())?;self.check_principal()?;Ok(())
    }
}
fn descriptor_objects(value:&Value)->Result<()> {
    let rows=value.as_array().ok_or_else(bad)?;
    if rows.is_empty()||rows.len()>256{return Err(Error::Bound);}
    let mut paths=BTreeSet::new();let mut identities=BTreeSet::new();
    for row in rows {
        let o=exact(row,&["path","class","bytes","sha256","volume","file_id","links","regions"])?;
        let path=o["path"].as_str().ok_or_else(bad)?;
        if !path.starts_with("C:\\")||path.encode_utf16().count()>32768||path.contains('/')||path.contains('\0')
            ||path.contains("\\\\")||path.split('\\').any(|part|part=="."||part=="..")
            ||!paths.insert(path.to_ascii_lowercase()){return Err(bad());}
        let links=o["links"].as_u64().ok_or_else(bad)?;
        match o["class"].as_str(){
            Some("OS_SYSTEM32_DLL_EXACT_LINKS") if path.to_ascii_lowercase().starts_with(r"c:\windows\system32\")
                &&links>0&&links<=u64::from(u32::MAX)=>{},
            Some("ADMIN_SELECTED_CURRENT_IMAGE") if links==1=>{},_=>return Err(bad()),
        }
        if o["bytes"].as_u64().is_none_or(|bytes|bytes==0){return Err(bad());}
        digest(&o["sha256"])?;
        let volume=o["volume"].as_u64().ok_or_else(bad)?;
        let text=o["file_id"].as_str().ok_or_else(bad)?;let mut id=[0u8;16];
        if text.len()!=32||!text.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
            ||hex::decode_to_slice(text,&mut id).is_err()||!identities.insert((volume,id)) {
            return Err(bad());
        }
        selected_regions(&o["regions"])?;
    }Ok(())
}
fn selected_release(value:&Value,path:&str,pin:Hash)->Result<()> {
    descriptor_objects(value)?;
    let key=path.to_ascii_lowercase();
    let rows=value.as_array().ok_or_else(bad)?;
    let item=rows.iter().find(|row|row["path"].as_str().is_some_and(|actual|actual.to_ascii_lowercase()==key))
        .ok_or_else(bad)?;
    if digest(&item["sha256"])?!=pin{return Err(bad());}Ok(())
}

#[cfg(test)]
mod descriptor_controls {
    use super::*;
    fn row()->Value {serde_json::json!({"path":r"C:\Program Files\Mutiny\provider.exe",
        "class":"ADMIN_SELECTED_CURRENT_IMAGE","bytes":8192,"sha256":hex::encode([1u8;32]),
        "volume":1,"file_id":hex::encode([2u8;16]),"links":1,
        "regions":[{"offset":0,"bytes":4096,"state":4096,"protection":32}]})}
    #[test]
    fn modeled_provider_descriptor_roster_refuses_alias_identity_unknown_fields_and_executable_write(){
        let item=row();assert!(descriptor_objects(&serde_json::json!([item.clone()])).is_ok());
        let roster=serde_json::json!([item.clone()]);
        assert!(selected_release(&roster,r"C:\Program Files\Mutiny\provider.exe",[1u8;32]).is_ok());
        assert!(selected_release(&roster,r"C:\Program Files\Mutiny\foreign.exe",[1u8;32]).is_err());
        assert!(selected_release(&roster,r"C:\Program Files\Mutiny\provider.exe",[3u8;32]).is_err());
        let mut alias=item.clone();alias["path"]=serde_json::json!(r"C:\Program Files\Mutiny\alias.exe");
        assert!(descriptor_objects(&serde_json::json!([item.clone(),alias])).is_err());
        let mut unknown=item.clone();unknown["caller_approved"]=serde_json::json!(true);
        assert!(descriptor_objects(&serde_json::json!([unknown])).is_err());
        let mut writable=item.clone();writable["regions"][0]["protection"]=serde_json::json!(64);
        assert!(descriptor_objects(&serde_json::json!([writable])).is_err());
        let mut foreign=item;foreign["class"]=serde_json::json!("OS_SYSTEM32_DLL_EXACT_LINKS");
        assert!(descriptor_objects(&serde_json::json!([foreign])).is_err());
    }
}
#[repr(C)]
struct Memory {base:*mut c_void,allocation:*mut c_void,allocation_protection:u32,
    partition:u16,size:usize,state:u32,protection:u32,kind:u32}
#[repr(C)]
struct System {architecture:u32,page:u32,minimum:*mut c_void,maximum:*mut c_void,
    mask:usize,processors:u32,processor_type:u32,granularity:u32,level:u16,revision:u16}
#[link(name="kernel32")]
unsafe extern "system" {
    fn VirtualQuery(address:*const c_void,information:*mut Memory,length:usize)->usize;
    fn GetNativeSystemInfo(information:*mut System);
    fn GetModuleFileNameW(module:*mut c_void,path:*mut u16,length:u32)->u32;
    fn GetModuleHandleW(name:*const u16)->*mut c_void;
    fn GetModuleHandleExW(flags:u32,name_or_address:*const u16,module:*mut *mut c_void)->i32;
    fn FreeLibrary(module:*mut c_void)->i32;
    fn GetLastError()->u32;
}
#[derive(Clone,PartialEq,Eq)]
struct Region {offset:u64,size:u64,state:u32,protection:u32}
#[derive(PartialEq,Eq)]
struct Image {base:usize,regions:Vec<Region>}
// Original loader reference custody is preallocated before acquiring it.
// No Drop/retry; failed FreeLibrary retains the whole identity/error record.
struct ModuleCustody {base:usize,handle:*mut c_void,close_error:Option<u32>}
struct ModuleReference {custody:Option<Box<ModuleCustody>>}
impl Drop for ModuleReference {
    fn drop(&mut self) {
        if let Some(custody)=self.custody.take() {
            if !custody.handle.is_null() {
                // Abandonment/unwind must not release an unresolved loader
                // lifetime or lose its preallocated custody. Never auto-retry.
                let _retained=Box::into_raw(custody);
            }
        }
    }
}
fn module_path(module:*mut c_void)->Result<String> {
    let mut text=[0u16;32768];
    let count=unsafe{GetModuleFileNameW(module,text.as_mut_ptr(),text.len() as u32)} as usize;
    if count==0 || count>=text.len() {return Err(bad());}
    let path=String::from_utf16(&text[..count]).map_err(|_|bad())?;
    if !path.starts_with("C:\\") || path.contains('/') || path.contains("\\\\") {return Err(bad());}
    Ok(path.to_ascii_lowercase())
}
fn selected_regions(value:&Value)->Result<Vec<Region>> {
    let rows=value.as_array().ok_or_else(bad)?;
    if rows.is_empty() || rows.len()>1024 {return Err(bad());}
    let mut result=Vec::new();result.try_reserve_exact(rows.len()).map_err(|_|Error::Bound)?;
    let mut previous=0;
    for row in rows {
        let r=exact(row,&["offset","bytes","state","protection"])?;
        let offset=r["offset"].as_u64().ok_or_else(bad)?;
        let size=r["bytes"].as_u64().ok_or_else(bad)?;
        let state=u32::try_from(r["state"].as_u64().ok_or_else(bad)?).map_err(|_|bad())?;
        let protection=u32::try_from(r["protection"].as_u64().ok_or_else(bad)?).map_err(|_|bad())?;
        if size==0 || offset<previous || !matches!(state,0x1000|0x2000)
            || matches!(protection&0xff,0x40|0x80) {return Err(bad());}
        previous=offset.checked_add(size).ok_or(Error::Bound)?;
        result.push(Region{offset,size,state,protection});
    }
    Ok(result)
}
/// Inspect the current process, never a peer PID or its /proc files. The whole
/// image roster is read twice; racing loader/protection changes refuse.
fn image_roster()->Result<BTreeMap<String,Image>> {
    if std::mem::size_of::<usize>()!=8 || std::mem::size_of::<Memory>()!=48 {return Err(bad());}
    let mut system=std::mem::MaybeUninit::<System>::zeroed();
    unsafe{GetNativeSystemInfo(system.as_mut_ptr())};let system=unsafe{system.assume_init()};
    if system.architecture&0xffff!=9 || system.page==0 {return Err(bad());}
    let maximum=system.maximum as usize;let mut address=0usize;let mut count=0usize;
    let mut result:BTreeMap<String,Image>=BTreeMap::new();
    let mut allocations=BTreeMap::new();
    while address<=maximum {
        count=count.checked_add(1).ok_or(Error::Bound)?;if count>131072 {return Err(Error::Bound);}
        let mut memory=std::mem::MaybeUninit::<Memory>::uninit();
        if unsafe{VirtualQuery(address as *const c_void,memory.as_mut_ptr(),std::mem::size_of::<Memory>())}
            !=std::mem::size_of::<Memory>() {return Err(bad());}
        let memory=unsafe{memory.assume_init()};
        if memory.base as usize!=address || memory.size==0 {return Err(bad());}
        let end=address.checked_add(memory.size).ok_or(Error::Bound)?;
        if end<=address {return Err(bad());}
        let execute=matches!(memory.protection&0xff,0x10|0x20|0x40|0x80);
        if execute && (memory.kind!=0x1000000 || matches!(memory.protection&0xff,0x40|0x80)
            || memory.protection&0x100!=0) {return Err(bad());}
        if memory.kind==0x1000000 {
            let allocation=memory.allocation as usize;
            if allocation==0 || address<allocation || !matches!(memory.state,0x1000|0x2000) {return Err(bad());}
            let path=module_path(memory.allocation)?;
            if let Some(before)=allocations.insert(path.clone(),allocation) {if before!=allocation {return Err(bad());}}
            if result.len()>=256 && !result.contains_key(&path) {return Err(Error::Bound);}
            let image=result.entry(path).or_insert_with(||Image{base:allocation,regions:Vec::new()});
            if image.base!=allocation {return Err(bad());}
            let rows=&mut image.regions;if rows.len()>=1024 {return Err(Error::Bound);}
            rows.try_reserve(1).map_err(|_|Error::Bound)?;
            rows.push(Region{offset:(address-allocation) as u64,size:memory.size as u64,
                state:memory.state,protection:memory.protection});
        }
        address=end;
    }
    if result.is_empty(){return Err(bad());}Ok(result)
}
fn require_original_backing(object:&mut Object,image:&Image)->Result<()> {
    let mut reference=ModuleReference{custody:Some(Box::new(ModuleCustody{base:image.base,
        handle:std::ptr::null_mut(),close_error:None}))};
    let custody=reference.custody.as_mut().ok_or_else(bad)?;
    // FROM_ADDRESS increments the real loader reference; no PIN flag and no
    // unchanged-refcount shortcut. This protects lifetime, not module content.
    if unsafe{GetModuleHandleExW(0x04,image.base as *const u16,&mut custody.handle)}==0 {
        return Err(bad());
    }
    let result=(|| {
        if custody.handle as usize!=image.base {return Err(bad());}
        let mut memory=std::mem::MaybeUninit::<Memory>::uninit();
        if unsafe{VirtualQuery(image.base as *const c_void,memory.as_mut_ptr(),std::mem::size_of::<Memory>())}
            !=std::mem::size_of::<Memory>() {return Err(bad());}
        let memory=unsafe{memory.assume_init()};
        if memory.base as usize!=image.base || memory.allocation as usize!=image.base
            || memory.kind!=0x1000000 || memory.state!=0x1000 {return Err(bad());}
        // SAFETY: original loader reference is held, native SEC_IMAGE base
        // matches, original protected File is borrowed, selected v2 backing
        // profile is required by caller. No peer/caller address reaches here.
        unsafe{object.file.require_image_backing(image.base)}.map_err(|_|bad())
    })();
    if unsafe{FreeLibrary(custody.handle)}==0 {
        custody.close_error=Some(unsafe{GetLastError()});
        return Err(bad());
    }
    custody.handle=std::ptr::null_mut();
    result
}
