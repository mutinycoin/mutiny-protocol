//! Private NONSHIPPING own-process module lifetime/backing mechanics.
//! This is not a source/role/token/ABI qualification capability. The application
//! owner must bind its actual original process/token and approved input objects.
//! No foreign PID, manual LoadLibrary, fallback path, or target invocation.
#![cfg(all(windows,target_arch="x86_64"))]
use std::{collections::BTreeSet,ffi::c_void,fs::File,mem::{size_of,size_of_val,zeroed},
    path::{Path,PathBuf},ptr::{null_mut},sync::atomic::{AtomicBool,AtomicPtr,Ordering}};
#[path="continuous_own_native_section.rs"] mod section;
#[path="continuous_own_native_bindings.rs"] mod bindings;
#[path="continuous_own_native_slot_observer.rs"] mod slot_observer;
pub(super) use slot_observer::{CompleteSlot,ParsedDirectExport,RequestedSymbol,OwnSlotEvidence};
#[cfg(test)] #[path="continuous_own_native_abi_controls.rs"] mod abi_controls;
pub(super) use bindings::{DeclaredImport,Symbol};
#[path="continuous_own_native_api_set_context.rs"] mod api_set_context;
#[path="continuous_own_native_requested_bindings.rs"] mod requested_bindings;
pub(super) use requested_bindings::ParsedRequestedExport;
type Handle=*mut c_void;
type Result<T>=std::result::Result<T,String>;
#[repr(C)] struct ModuleInfo{base:Handle,size:u32,entry:Handle}
#[repr(C)] struct Region{base:Handle,allocation_base:Handle,allocation_protect:u32,
    partition:u16,region_size:usize,state:u32,protect:u32,kind:u32}
#[link(name="kernel32")]
unsafe extern "system"{
    fn GetCurrentProcess()->Handle;
    fn GetCurrentProcessId()->u32;
    fn K32EnumProcessModules(process:Handle,modules:*mut Handle,bytes:u32,needed:*mut u32)->i32;
    fn K32GetModuleInformation(process:Handle,module:Handle,info:*mut ModuleInfo,bytes:u32)->i32;
    fn GetModuleFileNameW(module:Handle,name:*mut u16,length:u32)->u32;
    fn GetModuleHandleExW(flags:u32,address:*const u16,module:*mut Handle)->i32;
    fn GetModuleHandleW(name:*const u16)->Handle;
    fn GetProcAddress(module:Handle,name:*const u8)->*mut c_void;
    fn VirtualQuery(address:*const c_void,region:*mut Region,bytes:usize)->usize;
    fn FreeLibrary(module:Handle)->i32;
    fn GetLastError()->u32;
}
const CAP:usize=512;
static UNKNOWN:AtomicBool=AtomicBool::new(false);
static RETAINED:AtomicPtr<Reference>=AtomicPtr::new(null_mut());
struct Reference{next:usize,original_pid:u32,requested_base:usize,base:usize,path:PathBuf,extent:u32,
    own_executable:bool,acquired:bool,uncertain:bool,attempted:bool,outcome:Option<bool>,error:u32}
fn retain(record:Box<Reference>){let raw=Box::into_raw(record);let mut head=RETAINED.load(Ordering::Acquire);
    loop{unsafe{(*raw).next=head as usize;}
        match RETAINED.compare_exchange_weak(head,raw,Ordering::AcqRel,Ordering::Acquire){
            Ok(_)=>break,Err(now)=>head=now}}}
fn unknown()->Result<()>{if UNKNOWN.load(Ordering::Acquire){Err("Own module custody UNKNOWN; no qualification".into())}else{Ok(())}}
fn fail(s:&str)->String{format!("{s}: {}",unsafe{GetLastError()})}
fn spelling(path:&Path)->Result<String>{let s=path.to_str().ok_or("Own module ASCII path required")?;
    if !path.is_absolute()||!s.is_ascii()||s.len()>4096||s.bytes().any(|b|b<32)||s.contains('\0'){
        return Err("Bounded absolute own module path required".into());}
    Ok(s.replace('/',"\\").to_ascii_lowercase())}
#[derive(Clone,Debug,PartialEq,Eq)]
pub(super) struct ModuleObservation{pub(super) path:PathBuf,pub(super) image_bytes:u32,
    base:usize}
pub(super) fn selected_index(observations:&[ModuleObservation],path:&Path)->Result<usize>{
    let wanted=spelling(path)?;let mut selected=None;
    for(index,module)in observations.iter().enumerate(){
        if spelling(&module.path)?==wanted{
            if selected.replace(index).is_some(){return Err("Selected original module canonical path ambiguous".into());}
        }
    }
    selected.ok_or_else(||"Selected original module canonical path absent".into())
}
fn metadata(module:Handle)->Result<ModuleObservation>{
    let mut name=[0u16;4097];let n=unsafe{GetModuleFileNameW(module,name.as_mut_ptr(),name.len() as u32)} as usize;
    if n==0||n>=name.len(){return Err(fail("Own module filename bound"));}
    let path=PathBuf::from(String::from_utf16(&name[..n]).map_err(|_|"Own module UTF16")?);spelling(&path)?;
    let mut info:ModuleInfo=unsafe{zeroed()};
    if unsafe{K32GetModuleInformation(GetCurrentProcess(),module,&mut info,size_of::<ModuleInfo>() as u32)}==0{
        return Err(fail("Own module extent"));}
    if info.base!=module||!(4096..=512*1024*1024).contains(&info.size){return Err("Own module base/extent mismatch".into());}
    let mut region:Region=unsafe{zeroed()};
    if unsafe{VirtualQuery(module.cast(),&mut region,size_of::<Region>())}!=size_of::<Region>()
        ||region.allocation_base!=module||region.kind!=0x1000000||region.state!=0x1000{
        return Err("Own module is not a current committed SEC_IMAGE allocation base".into());}
    Ok(ModuleObservation{path,image_bytes:info.size,base:module as usize})
}
fn snapshot()->Result<Vec<ModuleObservation>>{
    let mut handles=[null_mut();CAP+1];let mut needed=0u32;
    if unsafe{K32EnumProcessModules(GetCurrentProcess(),handles.as_mut_ptr(),size_of_val(&handles) as u32,&mut needed)}==0{
        return Err(fail("Own module enumeration"));}
    if needed==0||needed as usize%size_of::<Handle>()!=0||needed as usize>CAP*size_of::<Handle>(){
        return Err("Own module enumeration cap/width".into());}
    let count=needed as usize/size_of::<Handle>();let mut seen=BTreeSet::new();let mut bases=BTreeSet::new();
    let mut result=Vec::with_capacity(count);let mut bytes=0usize;
    for module in &handles[..count]{let observation=metadata(*module)?;
        bytes=bytes.checked_add(observation.path.to_str().unwrap().len()).ok_or("Own module text overflow")?;
        if bytes>262144||!seen.insert(spelling(&observation.path)?)||!bases.insert(observation.base){
            return Err("Own module duplicate/path/text bound".into());}result.push(observation);}
    result.sort_by_key(|m|m.base);Ok(result)
}
fn release(record:&mut Reference)->Result<()>{
    if record.uncertain{UNKNOWN.store(true,Ordering::Release);return Err("Own DLL reference acquisition UNKNOWN; no release/retry".into());}
    if !record.acquired{return Ok(());}
    if record.attempted{return Err("Own module reference release already attempted; no retry".into());}
    record.attempted=true;
    // The original executable's lifetime is the lifetime of this process.
    // It is not a DLL reference and is never passed to FreeLibrary.
    if record.own_executable{record.outcome=Some(true);record.acquired=false;return Ok(());}
    let observed=unsafe{FreeLibrary(record.base as Handle)}!=0;
    record.outcome=Some(observed);record.error=if observed{0}else{unsafe{GetLastError()}};
    if observed{record.acquired=false;Ok(())}else{UNKNOWN.store(true,Ordering::Release);
        Err(format!("Own original DLL reference release UNKNOWN {}",record.error))}
}
pub(super) struct OwnLoadedModules{pid:u32,records:Vec<Option<Box<Reference>>>,observations:Vec<ModuleObservation>,closed:bool}
impl OwnLoadedModules{
    // Metadata preflight only: no original file or DLL reference acquisition.
    // This is not the authoritative module owner or a qualification capability.
    fn declared_metadata(approved:&[PathBuf],own_image:&Path)->Result<(u32,usize,Vec<ModuleObservation>)>{
        unknown()?;if approved.is_empty()||approved.len()>CAP{return Err("Own declared module cap".into());}
        let mut allowed=BTreeSet::new();for path in approved{if !allowed.insert(spelling(path)?){return Err("Duplicate own module declarations".into());}}
        let own=spelling(own_image)?;if !allowed.contains(&own){return Err("Own image must be explicitly declared".into());}
        let observations=snapshot()?;let missing:Vec<_>=observations.iter().filter(|m|!allowed.contains(&spelling(&m.path).unwrap())).map(|m|m.path.clone()).collect();
        if !missing.is_empty(){return Err(format!("Own unknown module metadata; no unknown file opened: {missing:?}"));}
        let pid=unsafe{GetCurrentProcessId()};if pid==0{return Err("Own process PID absent".into());}
        let executable=unsafe{GetModuleHandleW(std::ptr::null())} as usize;
        if observations.iter().filter(|m|m.base==executable&&spelling(&m.path).unwrap()==own).count()!=1{
            return Err("Own executable module/path mismatch".into());}
        Ok((pid,executable,observations))
    }
    pub(super) fn preflight_declared_metadata(approved:&[PathBuf],own_image:&Path)->Result<()>{
        Self::declared_metadata(approved,own_image).map(|_|())
    }
    /// All selected names are checked against the complete metadata snapshot
    /// before any corresponding unknown file is opened. This method opens no files.
    /// Approved paths are declarations supplied by an already validated caller,
    /// not a self-authenticating public receipt or basename search authority.
    pub(super) fn observe_declared(approved:&[PathBuf],own_image:&Path)->Result<Self>{
        let (pid,executable,observations)=Self::declared_metadata(approved,own_image)?;
        // Preallocate every record/path before acquiring any owned DLL reference.
        let records=observations.iter().map(|m|Some(Box::new(Reference{next:0,original_pid:pid,
            requested_base:m.base,base:m.base,path:m.path.clone(),extent:m.image_bytes,own_executable:m.base==executable,
            acquired:false,uncertain:false,attempted:false,outcome:None,error:0}))).collect();
        let mut owner=Self{pid,records,observations,closed:false};
        let operation=(||{for slot in &mut owner.records{let record=slot.as_mut().unwrap();
            if record.own_executable{record.acquired=true;continue;}
            let mut module=null_mut();
            let acquired=unsafe{GetModuleHandleExW(4,record.base as *const u16,&mut module)}!=0;
            let native_error=if acquired{0}else{unsafe{GetLastError()}};
            if !acquired{
                if !module.is_null(){record.base=module as usize;record.uncertain=true;
                    record.error=native_error;UNKNOWN.store(true,Ordering::Release);}
                return Err(format!("Own FROM_ADDRESS reference refused {native_error}; uncertain={}",record.uncertain));
            }
            // Record the actual returned original reference before validation.
            let expected=record.requested_base;record.base=module as usize;record.acquired=!module.is_null();
            if module.is_null()||record.base!=expected{return Err("Own loader-reference base changed".into());}
            let observed=metadata(module)?;if observed.path!=record.path||observed.image_bytes!=record.extent{
                return Err("Own loader-reference metadata changed".into());}}
            owner.recheck()})();
        if let Err(primary)=operation{let cleanup=owner.close_checked();return Err(format!("Own reference acquisition={primary}; closure={cleanup:?}"));}
        Ok(owner)
    }
    pub(super) fn observations(&self)->&[ModuleObservation]{&self.observations}
    /// Only a Root-authenticated original DIRECT export RVA may enter here.
    /// This checks the current pointer; genuine selected Rust ABI qualification
    /// and completeness of the original PE context are separate prerequisites.
    pub(super) fn require_selected_comparator(&self,direct_rva:u32)->Result<()>{
        self.recheck()?;
        let path=PathBuf::from(r"C:\Windows\System32\ntdll.dll");
        let index=selected_index(&self.observations,&path)?;
        let original=&self.observations[index];
        if direct_rva<4096||direct_rva>=original.image_bytes{return Err("Selected comparator direct export RVA bound".into());}
        let address=unsafe{GetProcAddress(original.base as Handle,c"NtAreMappedFilesTheSame".as_ptr().cast())} as usize;
        if address==0||address!=original.base.checked_add(direct_rva as usize).ok_or("Selected comparator address overflow")?{
            return Err("Actual selected native comparator differs from authenticated direct export".into());
        }
        self.recheck()
    }
    fn require_exact_observed_roster(&self,current:Vec<ModuleObservation>)->Result<()>{
        if current!=self.observations{
            // Diagnostic metadata only; full raw roster equality still refuses.
            // Both snapshots retain the existing CAP and aggregate path-text bound.
            let before_names=self.observations.iter().map(|m|spelling(&m.path)).collect::<Result<BTreeSet<_>>>()?;
            let after_names=current.iter().map(|m|spelling(&m.path)).collect::<Result<BTreeSet<_>>>()?;
            let missing=before_names.difference(&after_names).collect::<Vec<_>>();
            let added=after_names.difference(&before_names).collect::<Vec<_>>();
            return Err(format!("Own complete module roster changed; before_count={} after_count={} missing_count={} added_count={} missing={missing:?} added={added:?}",
                self.observations.len(),current.len(),missing.len(),added.len()));
        }
        Ok(())
    }
    pub(super) fn recheck(&self)->Result<()>{
        unknown()?;if self.closed||unsafe{GetCurrentProcessId()}!=self.pid{return Err("Own module owner revoked/wrong process".into());}
        let current=snapshot()?;
        self.require_exact_observed_roster(current)?;
        for slot in &self.records{let record=slot.as_ref().ok_or("Own original reference absent")?;
            if !record.acquired||record.attempted||record.original_pid!=self.pid{return Err("Own original module reference unavailable".into());}
            let m=metadata(record.base as Handle)?;if m.path!=record.path||m.image_bytes!=record.extent{return Err("Own original module observation changed".into());}}
        Ok(())
    }
    /// # Safety
    /// Caller must have independently established the exactly selected Windows
    /// x64 ntdll ABI profile and that `file` is its original retained approved
    /// input object, with exact source/role/hash/native/security/current checks.
    /// This sealed owner supplies the live OWN SEC_IMAGE base and original DLL
    /// reference. No public or peer-supplied numeric base reaches the comparator.
    /// This says nothing about COW pages, mutable dispatch, or role authority.
    pub(super) unsafe fn require_original_file_backing(&mut self,index:usize,file:&File)->Result<()>{
        self.recheck()?;let record=self.records.get(index).and_then(Option::as_ref).ok_or("Own selected module index")?;
        let outcome=unsafe{section::compare_original(file,record.base)};
        if let Err(error)=outcome{UNKNOWN.store(true,Ordering::Release);return Err(format!("Own original-file backing refused: {error:?}"));}
        self.recheck()
    }
    pub(super) fn close_checked(&mut self)->Result<()>{
        if self.closed{return Err("Own module closure already consumed; no retry".into());}self.closed=true;
        let mut failures=Vec::new();
        for slot in self.records.iter_mut().rev(){if let Some(mut record)=slot.take(){
            if let Err(error)=release(&mut record){failures.push(error);retain(record);}}}
        if failures.is_empty(){Ok(())}else{Err(format!("Independent own reference closures: {failures:?}"))}
    }
}
impl Drop for OwnLoadedModules{fn drop(&mut self){
    if !self.closed{UNKNOWN.store(true,Ordering::Release);for slot in &mut self.records{
        if let Some(record)=slot.take(){retain(record);}}}
}}

// SOURCE ONLY proposal: these controls call the real selected_index helper.
// No module enumeration, loader reference, file open or native call is made.
#[cfg(test)]
mod canonical_selected_index_controls {
    use super::{selected_index, ModuleObservation};
    use std::path::{Path, PathBuf};

    fn observation(path: &str, base: usize) -> ModuleObservation {
        ModuleObservation { path: PathBuf::from(path), image_bytes: 4096, base }
    }

    #[test]
    fn windows_case_and_separator_variants_select_same_retained_observation() {
        let observations = vec![
            observation(r"C:\WINDOWS\SYSTEM32\apphelp.dll", 0x1000),
            observation(r"C:\WINDOWS\SYSTEM32\ntdll.dll", 0x2000),
        ];
        for path in [r"C:\Windows\System32\apphelp.dll",
                     r"C:\WINDOWS\SYSTEM32\APPHELP.DLL",
                     "C:/Windows/System32/apphelp.dll"] {
            let index = selected_index(&observations, Path::new(path)).unwrap();
            assert_eq!(index, 0);
            assert_eq!(observations[index].base, 0x1000);
            assert_eq!(observations[index].path, PathBuf::from(r"C:\WINDOWS\SYSTEM32\apphelp.dll"));
        }
    }

    #[test]
    fn absent_or_foreign_path_is_not_selected_by_basename() {
        let observations = vec![observation(r"C:\WINDOWS\SYSTEM32\apphelp.dll", 0x1000)];
        for path in [r"C:\Windows\System32\absent.dll",
                     r"C:\Elsewhere\apphelp.dll",
                     r"D:\Windows\System32\apphelp.dll"] {
            assert_eq!(selected_index(&observations, Path::new(path)).unwrap_err(),
                       "Selected original module canonical path absent");
        }
    }

    #[test]
    fn duplicate_normalized_paths_refuse_instead_of_selecting_first() {
        let observations = vec![
            observation(r"C:\WINDOWS\SYSTEM32\apphelp.dll", 0x1000),
            observation(r"C:\Windows\System32\APPHELP.DLL", 0x2000),
        ];
        assert_eq!(selected_index(&observations, Path::new(r"C:\Windows\System32\apphelp.dll")).unwrap_err(),
                   "Selected original module canonical path ambiguous");
    }
}
