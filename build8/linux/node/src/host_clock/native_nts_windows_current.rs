//! Actual own-process mapped-file provenance only. Private relocated memory,
//! source-build correctness and physical time qualification are separate.
//! All selected documents/objects remain protected, existing and held. This
//! module cannot issue a deployment selection or relax its qualification gate.
use super::native_nts_deployment_record::{canonical_value,DecodedRecord,Error};
use super::native_nts_qualification::CurrentContract;
use super::state_dir::WindowsCurrentObject;
use serde_json::{Map,Value};
use sha2::{Digest,Sha256};
use std::{collections::{BTreeMap,BTreeSet},ffi::c_void,path::Path};
type Result<T>=std::result::Result<T,Error>;
const ROOT:&str=r"C:\ProgramData\Mutiny\NativeClock";
const MAX:u64=64*1024;
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
struct Object {file:WindowsCurrentObject,size:u64,pin:[u8;32],regions:Vec<Region>}
pub(super) struct WindowsBoundary {
    record:Vec<u8>,contract:CurrentContract,release:WindowsCurrentObject,
    source:WindowsCurrentObject,loaded:WindowsCurrentObject,release_pin:[u8;32],
    source_pin:[u8;32],loaded_pin:[u8;32],objects:BTreeMap<String,Object>,
    executable:String,section_profile:bool,last:super::native_nts_current::NativeSoftwareCapture,
}
impl WindowsBoundary {
    pub(super) fn close_retained(self)->std::result::Result<super::native_retained_close::RetainedCloseReport,Self> {
        let mut count=match self.release.retained_file_count().checked_add(self.source.retained_file_count())
            .and_then(|n|n.checked_add(self.loaded.retained_file_count())){Some(n)=>n,None=>return Err(self)};
        for object in self.objects.values(){count=match count.checked_add(object.file.retained_file_count()){Some(n)=>n,None=>return Err(self)};}
        let mut report=match super::native_retained_close::RetainedCloseReport::prepare(count){Ok(r)=>r,Err(_)=>return Err(self)};
        let Self{release,source,loaded,objects,..}=self;
        release.close_retained_into(&mut report);source.close_retained_into(&mut report);loaded.close_retained_into(&mut report);
        for (_,object) in objects{object.file.close_retained_into(&mut report);}
        Ok(report)
    }
}
fn bad()->Error {Error::UnsupportedCurrentFacts}
fn exact<'a>(value:&'a Value,keys:&[&str])->Result<&'a Map<String,Value>> {
    let map=value.as_object().ok_or_else(bad)?;
    if map.len()!=keys.len() || map.keys().any(|k|!keys.contains(&k.as_str())) {return Err(bad());}Ok(map)
}
fn digest(value:&Value)->Result<[u8;32]> {
    let text=value.as_str().ok_or_else(bad)?;let mut pin=[0;32];
    if text.len()!=64 || !text.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b))
        || hex::decode_to_slice(text,&mut pin).is_err() || pin==[0;32] {return Err(bad());}Ok(pin)
}
fn open_document(name:&str)->Result<WindowsCurrentObject> {
    WindowsCurrentObject::open(&Path::new(ROOT).join(name),false,1).map_err(|_|bad())
}
fn document(file:&mut WindowsCurrentObject)->Result<Vec<u8>> {file.bounded_bytes(MAX).map_err(|_|bad())}
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
impl WindowsBoundary {
    pub(super) fn open(record:&DecodedRecord,contract:&CurrentContract)->Result<Self> {
        let mut release=open_document("release.json")?;let raw=document(&mut release)?;
        let release_pin:[u8;32]=Sha256::digest(&raw).into();
        let deployment=canonical_value(record.canonical())?;
        if digest(&deployment["context"]["code_sha256"])?!=release_pin {return Err(bad());}
        let value=canonical_value(&raw)?;
        let r=exact(&value,&["format","target","executable_path","executable_sha256","source_receipt_sha256","loaded_sha256"])?;
        if r["format"].as_str()!=Some("build8/native-nts/windows-release-v1") || r["target"].as_str()!=Some("windows-x86_64") {return Err(bad());}
        let executable=r["executable_path"].as_str().ok_or_else(bad)?.to_ascii_lowercase();
        let handle=unsafe{GetModuleHandleW(std::ptr::null())};if handle.is_null() || module_path(handle)?!=executable {return Err(bad());}
        let mut source=open_document("release-source.json")?;let source_raw=document(&mut source)?;
        let source_pin=digest(&r["source_receipt_sha256"])?;
        if <[u8;32]>::from(Sha256::digest(&source_raw))!=source_pin {return Err(bad());}
        let source_value=canonical_value(&source_raw)?;
        let s=exact(&source_value,&["format","target","source_tree_sha256","build_recipe_sha256","toolchain_sha256","executable_sha256"])?;
        if s["format"].as_str()!=Some("build8/native-nts/release-source-v1") || s["target"]!=r["target"]
            || digest(&s["executable_sha256"])?!=digest(&r["executable_sha256"])? {return Err(bad());}
        for name in ["source_tree_sha256","build_recipe_sha256","toolchain_sha256"] {digest(&s[name])?;}
        let mut loaded=open_document("release-loaded.json")?;let loaded_raw=document(&mut loaded)?;
        let loaded_pin=digest(&r["loaded_sha256"])?;
        if <[u8;32]>::from(Sha256::digest(&loaded_raw))!=loaded_pin {return Err(bad());}
        let loaded_value=canonical_value(&loaded_raw)?;
        let section_profile=loaded_value["format"].as_str()==Some("build8/native-nts/windows-loaded-v2");
        let keys=if section_profile {vec!["format","target","source_receipt_sha256","objects","backing_identity"]}
            else{vec!["format","target","source_receipt_sha256","objects"]};
        let l=exact(&loaded_value,&keys)?;
        if (!section_profile && l["format"].as_str()!=Some("build8/native-nts/windows-loaded-v1"))
            || (section_profile && l["backing_identity"].as_str()!=Some("nt-are-mapped-files-the-same-v1")) || l["target"]!=r["target"]
            || digest(&l["source_receipt_sha256"])?!=source_pin {return Err(bad());}
        let selected=l["objects"].as_array().ok_or_else(bad)?;
        if selected.is_empty() || selected.len()>256 {return Err(bad());}
        let mut objects=BTreeMap::new();let mut identities=BTreeSet::new();
        for value in selected {
            let o=exact(value,&["path","class","bytes","sha256","volume","file_id","links","regions"])?;
            let path=o["path"].as_str().ok_or_else(bad)?;let key=path.to_ascii_lowercase();
            let os_dll=match o["class"].as_str(){Some("OS_SYSTEM32_DLL_EXACT_LINKS")=>true,Some("ADMIN_SELECTED_CURRENT_IMAGE")=>false,_=>return Err(bad())};
            let links=u32::try_from(o["links"].as_u64().ok_or_else(bad)?).map_err(|_|bad())?;
            let mut file=WindowsCurrentObject::open(Path::new(path),os_dll,links).map_err(|_|bad())?;
            let(volume,id,_)=file.file_identity();
            if o["volume"].as_u64()!=Some(volume) || o["file_id"].as_str()!=Some(hex::encode(id).as_str())
                || !identities.insert((volume,id)) {return Err(bad());}
            let size=o["bytes"].as_u64().ok_or_else(bad)?;let pin=digest(&o["sha256"])?;
            if file.hash_exact(size).map_err(|_|bad())?!=pin {return Err(bad());}
            let regions=selected_regions(&o["regions"])?;
            if objects.insert(key,Object{file,size,pin,regions}).is_some(){return Err(bad());}
        }
        let executable_pin=digest(&r["executable_sha256"])?;
        if objects.get(&executable).is_none_or(|o|o.pin!=executable_pin) {return Err(bad());}
        let last=super::native_nts_current::capture_bound(record,contract).map_err(|_|bad())?;
        let mut value=Self{record:record.canonical().to_vec(),contract:contract.clone(),release,source,loaded,
            release_pin,source_pin,loaded_pin,objects,executable,section_profile,last};
        value.require_loaded(record)?;Ok(value)
    }
    pub(super) fn require_loaded(&mut self,record:&DecodedRecord)->Result<()> {
        if self.record!=record.canonical() {return Err(bad());}
        // This supported successor selects an exact whole image/backing-object
        // profile. v1 retains its documentary observations but cannot issue
        // normal current authority from loader names alone.
        if !self.section_profile {return Err(bad());}
        super::protected_clock_windows_channel::require_own_process_boundary().map_err(|_|bad())?;
        let fresh=super::native_nts_current::capture_bound(record,&self.contract).map_err(|_|bad())?;
        self.last.check_successor(&fresh).map_err(|_|bad())?;
        let before=image_roster()?;
        for(file,pin) in [(&mut self.release,self.release_pin),(&mut self.source,self.source_pin),(&mut self.loaded,self.loaded_pin)] {
            if <[u8;32]>::from(Sha256::digest(document(file)?))!=pin {return Err(bad());}
        }
        if before.len()!=self.objects.len() {return Err(bad());}
        for(path,object) in &mut self.objects {
            let image=before.get(path).ok_or_else(bad)?;
            if image.regions!=object.regions || object.file.hash_exact(object.size).map_err(|_|bad())?!=object.pin {return Err(bad());}
            if self.section_profile {require_original_backing(object,image)?;}
        }
        let handle=unsafe{GetModuleHandleW(std::ptr::null())};
        if handle.is_null() || module_path(handle)?!=self.executable || image_roster()?!=before {return Err(bad());}
        let after=super::native_nts_current::capture_bound(record,&self.contract).map_err(|_|bad())?;
        fresh.check_successor(&after).map_err(|_|bad())?;
        super::protected_clock_windows_channel::require_own_process_boundary().map_err(|_|bad())?;
        self.last=after;
        // Same scope as the accepted Linux counterpart: complete selected
        // mapped-file provenance plus actual installation/security/config/boot
        // observations. This does not attest private relocated/COW memory or
        // imported dispatch, qualify the kernel ABI/hardware, or authenticate
        // evidence. Mandatory installed qualification still precedes this route;
        // exact selected Windows ABI native controls are a separate software gate.
        Ok(())
    }
}
