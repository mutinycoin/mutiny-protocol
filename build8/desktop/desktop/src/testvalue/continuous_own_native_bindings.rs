//! Private own-child exact import bindings, consumed from an independently
//! admitted complete declaration plan. No PE/schema discovery or API-set rewrite.
//! Every target is an already-owned live module with an independently verified
//! direct export RVA. No manual library load or exported target invocation.
use super::{metadata,ModuleObservation,OwnLoadedModules,Handle,Result};
use std::{ffi::{c_void,CString},path::PathBuf};
#[link(name="kernel32")]
unsafe extern "system"{
    fn GetCurrentProcess()->Handle;
    fn ReadProcessMemory(process:Handle,address:*const c_void,buffer:*mut c_void,
        bytes:usize,read:*mut usize)->i32;
    fn GetProcAddress(module:Handle,name:*const u8)->*mut c_void;
    fn GetLastError()->u32;
}
#[derive(Clone,Debug,PartialEq,Eq)]
pub(in super::super) enum Symbol{Named(String),Ordinal(u16)}
#[derive(Clone,Debug)]
pub(in super::super) struct DeclaredImport{
    pub(in super::super) importer:PathBuf,pub(in super::super) target:PathBuf,pub(in super::super) symbol:Symbol,
    pub(in super::super) iat_rva:u32,pub(in super::super) direct_export_rva:u32,
}
fn selected<'a>(modules:&'a [ModuleObservation],path:&PathBuf)->Result<&'a ModuleObservation>{
    let name=super::spelling(path)?;let mut found=modules.iter().filter(|m|super::spelling(&m.path).ok().as_ref()==Some(&name));
    let item=found.next().ok_or("Own import binding references a module outside the held complete roster")?;
    if found.next().is_some(){return Err("Own import binding module ambiguity".into());}Ok(item)
}
impl OwnLoadedModules{
    /// Caller must independently verify the complete PE declarations against
    /// the original file bytes and selected platform/import-resolution context.
    /// This method verifies the finite supplied bindings in this process only.
    /// It cannot turn an omitted declaration or guessed API alias into authority.
    pub(in super::super) fn require_declared_bindings(&self,bindings:&[DeclaredImport])->Result<()>{
        self.recheck()?;if bindings.len()>131072{return Err("Own import binding count bound".into());}
        let mut keys=std::collections::BTreeSet::new();let mut text=0usize;
        // Validate every declaration before any native export lookup. In
        // particular, GetProcAddress never receives an arbitrary forwarder target.
        for binding in bindings{
            let importer=selected(&self.observations,&binding.importer)?;
            let target=selected(&self.observations,&binding.target)?;
            if binding.iat_rva%8!=0||binding.iat_rva<4096
                ||binding.iat_rva.checked_add(8).is_none_or(|end|end>importer.image_bytes)
                ||binding.direct_export_rva<4096||binding.direct_export_rva>=target.image_bytes{
                return Err("Own declared import/export image range refused".into());}
            if !keys.insert((importer.base,binding.iat_rva)){return Err("Own duplicate IAT declaration".into());}
            if let Symbol::Named(name)=&binding.symbol{
                if name.is_empty()||name.len()>4096||!name.is_ascii()||name.bytes().any(|b|b<32||b==127){
                    return Err("Own import symbol bounded printable ASCII required".into());}
                text=text.checked_add(name.len()).ok_or("Own binding text overflow")?;
                if text>16*1024*1024{return Err("Own binding text bound".into());}}
            if matches!(binding.symbol,Symbol::Ordinal(0)){return Err("Own import ordinal zero refused".into());}}
        for binding in bindings{
            let importer=selected(&self.observations,&binding.importer)?;
            let target=selected(&self.observations,&binding.target)?;
            let expected=target.base.checked_add(binding.direct_export_rva as usize).ok_or("Own direct export pointer overflow")?;
            let named=match &binding.symbol{Symbol::Named(name)=>Some(CString::new(name.as_str()).map_err(|_|"Own import symbol NUL")?),_=>None};
            let symbol=match &binding.symbol{Symbol::Named(_)=>named.as_ref().unwrap().as_ptr().cast(),Symbol::Ordinal(n)=>(*n as usize) as *const u8};
            // The complete held target was independently parsed as a DIRECT
            // export, not a forwarder. The returned pointer must be that exact RVA.
            let actual=unsafe{GetProcAddress(target.base as Handle,symbol)} as usize;
            if actual!=expected{return Err(format!("Own actual direct export differs from declaration: {}",unsafe{GetLastError()}));}
            if metadata(target.base as Handle)?!=*target{return Err("Own target lifetime/base changed during binding".into());}
            let address=importer.base.checked_add(binding.iat_rva as usize).ok_or("Own IAT pointer overflow")?;
            let mut pointer=[0u8;8];let mut copied=0usize;
            if unsafe{ReadProcessMemory(GetCurrentProcess(),address as *const c_void,pointer.as_mut_ptr().cast(),8,&mut copied)}==0
                ||copied!=8||u64::from_le_bytes(pointer)!=expected as u64{
                return Err("Own current IAT does not contain the exact declared direct export".into());}
            self.recheck()?;
        }
        self.recheck()
    }
}
