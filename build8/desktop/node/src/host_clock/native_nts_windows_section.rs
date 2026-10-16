//! Backing-object comparison candidate for an exactly selected Windows x64
//! installation. NtAreMappedFilesTheSame is an exported but undocumented ABI:
//! absence, nonzero status or an unqualified platform profile refuses. This
//! primitive supplies no installation/current-software/qualification token.
//! A same-file result says nothing about private COW pages or imported dispatch.
use std::{ffi::c_void,fs::File,os::windows::io::AsRawHandle,ptr::{null,null_mut}};

type Handle=*mut c_void;
type Compare=unsafe extern "system" fn(*mut c_void,*mut c_void)->i32;
#[link(name="kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(name:*const u16)->Handle;
    fn GetProcAddress(module:Handle,name:*const u8)->*mut c_void;
    fn CreateFileMappingW(file:Handle,security:*const c_void,protection:u32,
        maximum_high:u32,maximum_low:u32,name:*const u16)->Handle;
    fn MapViewOfFile(mapping:Handle,access:u32,offset_high:u32,offset_low:u32,bytes:usize)->Handle;
    fn UnmapViewOfFile(view:*const c_void)->i32;
    fn CloseHandle(handle:Handle)->i32;
    fn GetLastError()->u32;
}

/// No Drop implementation and no retry. If native cleanup is uncertain, a
/// preallocated whole record is retained for process lifetime. The mapping/view
/// themselves retain the kernel backing object even if the caller later drops
/// its borrowed File. This does not claim closure of that caller's file owner.
struct Custody {
    mapping:Handle,view:Handle,image:usize,original_file:usize,
    compare_status:Option<i32>,unmap_error:Option<u32>,close_error:Option<u32>,
}
#[derive(Debug,Clone,Copy)]
pub(super) struct Failure {
    pub(super) stage:&'static str,
    pub(super) code:i64,
    pub(super) quarantined:bool,
}
fn failure(stage:&'static str,code:i64)->Failure {Failure{stage,code,quarantined:false}}

/// Only the original held file is mapped; this function never reopens a name,
/// uses a peer PID, changes protection, or maps a writable/executable view.
/// The caller must separately establish that `image` is its live SEC_IMAGE
/// allocation base and retain/recheck its selected original file and roster.
///
/// # Safety
/// `image` must be the allocation base of a genuine current-process SEC_IMAGE
/// module, with an original loader reference retained throughout this call.
/// The caller must use only the exactly selected Windows x64 ntdll ABI profile;
/// unsupported or unqualified exports cannot establish normal authority.
pub(super) unsafe fn compare_original(file:&File,image:usize)->Result<(),Failure> {
    if std::mem::size_of::<usize>()!=8 || image==0 {
        return Err(failure("unsupported section comparison platform/base",0));
    }
    let ntdll:Vec<u16>="ntdll.dll\0".encode_utf16().collect();
    let module=unsafe{GetModuleHandleW(ntdll.as_ptr())};
    if module.is_null(){return Err(failure("loaded ntdll absent",unsafe{GetLastError()} as i64));}
    let address=unsafe{GetProcAddress(module,c"NtAreMappedFilesTheSame".as_ptr().cast())};
    if address.is_null(){return Err(failure("section comparison export unavailable",unsafe{GetLastError()} as i64));}
    // Exact exported function type only: no syscall-number fallback or scanning.
    let compare:Compare=unsafe{std::mem::transmute(address)};
    let original=file.as_raw_handle();
    let mut custody=Box::new(Custody{mapping:null_mut(),view:null_mut(),image,
        original_file:original as usize,compare_status:None,unmap_error:None,close_error:None});
    custody.mapping=unsafe{CreateFileMappingW(original,null(),0x02,0,0,null())};
    if custody.mapping.is_null(){return Err(failure("readonly original-file mapping",unsafe{GetLastError()} as i64));}
    custody.view=unsafe{MapViewOfFile(custody.mapping,0x04,0,0,1)};
    let mut outcome=if custody.view.is_null() {
        Err(failure("readonly original-file view",unsafe{GetLastError()} as i64))
    } else {
        let status=unsafe{compare(image as Handle,custody.view)};
        custody.compare_status=Some(status);
        if status==0 {Ok(())}else{Err(failure("mapped backing object differs or unsupported",status as i64))}
    };
    // Attempt both independently, exactly once. Never allow one refusal to
    // skip the other cleanup, and never retry an uncertain native identity.
    if !custody.view.is_null() {
        if unsafe{UnmapViewOfFile(custody.view)}==0 {
            custody.unmap_error=Some(unsafe{GetLastError()});
        } else {custody.view=null_mut();}
    }
    if unsafe{CloseHandle(custody.mapping)}==0 {
        custody.close_error=Some(unsafe{GetLastError()});
    } else {custody.mapping=null_mut();}
    if custody.unmap_error.is_some() || custody.close_error.is_some() {
        let code=custody.unmap_error.or(custody.close_error).unwrap_or(0) as i64;
        // Keep the original successful/different status plus BOTH errors and
        // all unresolved identities. No allocation occurs after native effects.
        let _retained=Box::into_raw(custody);
        outcome=Err(Failure{stage:"section mapping cleanup uncertain",code,quarantined:true});
    }
    outcome
}
