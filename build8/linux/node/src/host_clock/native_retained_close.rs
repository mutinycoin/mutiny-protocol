//! Explicit once-only closure of OWNED retained read descriptors. No retry,
//! reopening, path selection, privilege, authority issuer or replacement token.
//! Capacity exists before the first close; failures retain native identities.
use std::fs::File;
pub(super) struct UncertainNativeClose {
    index:usize,raw:usize,original_identity:[u8;24],expected_identity:[u8;24],observed_identity:Option<[u8;24]>,identity_error:Option<i32>,close_error:Option<i32>,
}
/// Capture at ORIGINAL retention, before this holder is published. Close-time
/// failure can never erase this pin. No caller path/native number is accepted.
pub(crate) fn retained_identity(file:&File)->Result<[u8;24],i32> {
    #[cfg(target_os="linux")]
    {
        use std::os::unix::fs::MetadataExt;
        let m=file.metadata().map_err(|e|e.raw_os_error().unwrap_or(-1))?;
        let mut bytes=[0;24];bytes[..8].copy_from_slice(&m.dev().to_le_bytes());
        bytes[8..16].copy_from_slice(&m.ino().to_le_bytes());bytes[16..24].copy_from_slice(&m.nlink().to_le_bytes());Ok(bytes)
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        let mut bytes=[0;24];
        if unsafe{GetFileInformationByHandleEx(file.as_raw_handle(),18,bytes.as_mut_ptr().cast(),24)}==0 {
            Err(unsafe{GetLastError()} as i32)
        }else{Ok(bytes)}
    }
    #[cfg(not(any(target_os="linux",windows)))]
    {let _=file;Err(-1)}
}
pub(crate) struct RetainedCloseReport {maximum:usize,attempted:usize,uncertain:Vec<UncertainNativeClose>}
impl RetainedCloseReport {
    pub(crate) fn prepare(maximum:usize)->Result<Self,String> {
        if !cfg!(any(target_os="linux",windows)){return Err("retained native close platform unavailable".into());}
        if maximum==0{return Err("retained close roster is empty".into());}
        let mut uncertain=Vec::new();uncertain.try_reserve_exact(maximum)
            .map_err(|_|"retained close custody allocation refused")?;
        Ok(Self{maximum,attempted:0,uncertain})
    }
    /// Every caller computes its EXACT owned roster before transferring files.
    /// Report cannot be constructed from a raw external/native handle.
    pub(crate) fn file(&mut self,file:File,original_identity:[u8;24]) {
        self.file_checked(file,original_identity,original_identity)
    }
    /// ONLY the private same-owner joined-controller socket capability can
    /// authorize this exact dev/inode-preserving one-link to zero-link change.
    #[cfg(target_os="linux")]
    pub(super) fn file_after_owned_socket_unlink(&mut self,file:File,
        transition:super::protected_clock_unix_channel::UnlinkedSocketClose) {
        let(original_identity,expected_identity)=transition.identities();
        self.file_checked(file,original_identity,expected_identity)
    }
    fn file_checked(&mut self,file:File,original_identity:[u8;24],expected_identity:[u8;24]) {
        let file=std::mem::ManuallyDrop::new(file);
        assert!(self.attempted<self.maximum,"exact preallocated close roster");
        let file=std::mem::ManuallyDrop::into_inner(file);
        let index=self.attempted;self.attempted+=1;
        let (observed_identity,mut identity_error)=match retained_identity(&file){
            Ok(identity)=>(Some(identity),None),Err(error)=>(None,Some(error)),
        };
        if observed_identity.is_some_and(|identity|identity!=expected_identity){identity_error=Some(-2);}
        #[cfg(target_os="linux")]
        {
            use std::os::fd::IntoRawFd;
            let raw=file.into_raw_fd();let result=unsafe{libc::close(raw)};
            let close_error=if result==0{None}else{Some(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1))};
            if identity_error.is_some()||close_error.is_some(){self.uncertain.push(UncertainNativeClose{
                index,raw:raw as usize,original_identity,expected_identity,observed_identity,identity_error,close_error});}
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::IntoRawHandle;
            let raw=file.into_raw_handle();let result=unsafe{CloseHandle(raw)};
            let close_error=if result!=0{None}else{Some(unsafe{GetLastError()} as i32)};
            if identity_error.is_some()||close_error.is_some(){self.uncertain.push(UncertainNativeClose{
                index,raw:raw as usize,original_identity,expected_identity,observed_identity,identity_error,close_error});}
        }
        #[cfg(not(any(target_os="linux",windows)))]
        {
            // prepare refuses this platform before ANY effects. Defensive
            // abandonment retains the File without late custody allocation.
            std::mem::forget(file);
            self.uncertain.push(UncertainNativeClose{index,raw:0,original_identity,expected_identity,observed_identity,identity_error:Some(-1),close_error:Some(-1)});
        }
    }
    pub(crate) fn retained_handles_closed(&self)->bool {self.attempted==self.maximum&&self.uncertain.is_empty()}
    pub(crate) fn attempted(&self)->usize {self.attempted}
    pub(crate) fn uncertain_count(&self)->usize {self.uncertain.len()}
    // No Drop/close accessor retries any raw identity: even EINTR may already
    // have released the Linux FD. This is exact uncertainty custody, not a
    // claim that a failed raw number still identifies a live object.
}
impl Drop for RetainedCloseReport {
    fn drop(&mut self){
        if !self.uncertain.is_empty(){
            // The already allocated exact raw identity/error records survive
            // abandoned failure reports; no late allocation or native retry.
            std::mem::forget(std::mem::take(&mut self.uncertain));
        }
    }
}
#[cfg(windows)]
#[link(name="kernel32")]
unsafe extern "system" {
    fn GetFileInformationByHandleEx(file:*mut std::ffi::c_void,kind:i32,out:*mut std::ffi::c_void,length:u32)->i32;
    fn CloseHandle(file:*mut std::ffi::c_void)->i32;
    fn GetLastError()->u32;
}
