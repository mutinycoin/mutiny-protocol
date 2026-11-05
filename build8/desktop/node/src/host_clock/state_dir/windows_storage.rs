//! Windows C8 storage. All checks use the opened object, never a configured ACL label.
//! The directory chain is pinned without DELETE sharing for this object's lifetime.
//! This is account isolation and process-crash lineage, NOT account/admin rollback protection
//! or Windows elapsed/calibration qualification. Native qualification tests remain required.
use super::{StorageError, io};
use super::super::windows_native_query::{CurrentWindowsPrincipal,file_security_snapshot,require_no_thread_token,WindowsMechanicalFailure};
use super::super::windows_public_object::{FileId,wide,api_path,last,access,inspect,check_volume};
pub(super) use super::super::windows_public_object::strict;
use std::{
    ffi::c_void,
    fs::File,
    io::{Read, Write, Seek, SeekFrom},
    mem::{offset_of, size_of},
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, IntoRawHandle},
    },
    path::{Component, Path, PathBuf, Prefix},
    ptr::{null, null_mut},
};

type Ptr = *mut c_void;
const READ_CONTROL: u32 = 0x20000;
const READ: u32 = 0x80000000;
const WRITE: u32 = 0x40000000;
const DELETE: u32 = 0x10000;
const OPEN: u32 = 3;
const NEW: u32 = 1;
const NO_FOLLOW: u32 = 0x00200000;
const BACKUP: u32 = 0x02000000;
const WRITE_THROUGH: u32 = 0x80000000;

#[repr(C)]
struct SecurityAttributes {
    length: u32,
    descriptor: Ptr,
    inherit: i32,
}
#[repr(C)]
struct Acl {
    revision: u8,
    reserved: u8,
    size: u16,
    count: u16,
    reserved2: u16,
}
#[repr(C)]
struct Ace {
    kind: u8,
    flags: u8,
    size: u16,
    mask: u32,
    sid: u32,
}
#[repr(C)]
struct Rename {
    replace: u32,
    root: Ptr,
    length: u32,
    name: [u16; 1],
}
#[link(name = "kernel32")]
unsafe extern "system" {
    fn CreateFileW(
        name: *const u16,
        access: u32,
        share: u32,
        security: *const SecurityAttributes,
        disposition: u32,
        flags: u32,
        template: Ptr,
    ) -> Ptr;
    fn CreateDirectoryW(name: *const u16, security: *const SecurityAttributes) -> i32;
    fn GetCurrentProcess() -> Ptr;
    fn GetCurrentThread() -> Ptr;
    fn GetDriveTypeW(root: *const u16) -> u32;
    fn CloseHandle(handle: Ptr) -> i32;
    fn GetLastError() -> u32;
    fn LocalFree(allocation: Ptr) -> Ptr;
    fn GetFileInformationByHandle(handle: Ptr, information: *mut u32) -> i32;
    fn GetFileInformationByHandleEx(handle: Ptr, kind: u32, information: Ptr, length: u32) -> i32;
    fn GetVolumeInformationByHandleW(
        handle: Ptr,
        name: *mut u16,
        length: u32,
        serial: *mut u32,
        component: *mut u32,
        flags: *mut u32,
        fs: *mut u16,
        fs_length: u32,
    ) -> i32;
    fn SetFileInformationByHandle(handle: Ptr, kind: u32, information: Ptr, length: u32) -> i32;
    fn GetHandleInformation(handle: Ptr, flags: *mut u32) -> i32;
    #[cfg(test)]
    fn DeviceIoControl(
        handle: Ptr,
        code: u32,
        input: Ptr,
        input_length: u32,
        output: Ptr,
        output_length: u32,
        returned: *mut u32,
        overlapped: Ptr,
    ) -> i32;
}
#[link(name = "advapi32")]
unsafe extern "system" {
    fn OpenProcessToken(process: Ptr, access: u32, token: *mut Ptr) -> i32;
    fn OpenThreadToken(thread: Ptr, access: u32, open_as_self: i32, token: *mut Ptr) -> i32;
    fn GetTokenInformation(token: Ptr, kind: u32, data: Ptr, length: u32, needed: *mut u32) -> i32;
    fn ConvertSidToStringSidW(sid: Ptr, text: *mut *mut u16) -> i32;
    fn ConvertStringSidToSidW(text: *const u16, sid: *mut Ptr) -> i32;
    fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
        text: *const u16,
        revision: u32,
        sd: *mut Ptr,
        length: *mut u32,
    ) -> i32;
    fn GetSecurityInfo(
        handle: Ptr,
        kind: u32,
        info: u32,
        owner: *mut Ptr,
        group: *mut Ptr,
        dacl: *mut *mut Acl,
        sacl: *mut Ptr,
        sd: *mut Ptr,
    ) -> u32;
    fn GetSecurityDescriptorControl(sd: Ptr, control: *mut u16, revision: *mut u32) -> i32;
    fn GetAce(acl: *mut Acl, index: u32, ace: *mut Ptr) -> i32;
    fn EqualSid(a: Ptr, b: Ptr) -> i32;
    fn IsValidSid(sid: Ptr) -> i32;
    fn GetLengthSid(sid: Ptr) -> u32;
}
// Original allocation/conversion/use/release outcomes precede one LocalFree.
// Drop quarantines the preallocated record; it never retries native release.
struct LocalCore {
 path:PathBuf,input:Vec<u16>,allocation:usize,conversion_result:Option<i32>,
 conversion_error:Option<u32>,allocation_size:Option<u32>,
 directory_result:Option<i32>,directory_error:Option<u32>,
 body_result:Option<bool>,body_problem:Option<String>,
 release_attempted:bool,release_result:Option<usize>,release_error:Option<u32>,
}
struct Local {core:Option<Box<LocalCore>>}
impl Local {
 fn prepare(path:&Path,input:Vec<u16>)->Self {Self{core:Some(Box::new(LocalCore{
  path:path.to_path_buf(),input,allocation:0,conversion_result:None,conversion_error:None,
  allocation_size:None,directory_result:None,directory_error:None,body_result:None,
  body_problem:None,release_attempted:false,release_result:None,release_error:None}))}}
 fn descriptor(path:&Path,input:Vec<u16>)->Result<Self,StorageError>{
  let mut local=Self::prepare(path,input);let core=local.core.as_mut().expect("preallocated descriptor custody");
  let(mut original,mut size)=(null_mut(),0);
  let observed=unsafe{ConvertStringSecurityDescriptorToSecurityDescriptorW(core.input.as_ptr(),1,&mut original,&mut size)};
  let error=if observed==0{Some(unsafe{GetLastError()})}else{None};
  core.allocation=original as usize;core.allocation_size=Some(size);
  core.conversion_result=Some(observed);core.conversion_error=error;
  if observed==0||original.is_null(){return Err(StorageError::Io(path.to_path_buf(),format!("original descriptor conversion refused: {error:?}")));}
  Ok(local)
 }
 #[cfg(test)]
 fn sid(path:&Path,input:Vec<u16>)->Result<Self,StorageError>{
  let mut local=Self::prepare(path,input);let core=local.core.as_mut().expect("preallocated TEST SID custody");
  let mut original=null_mut();let observed=unsafe{ConvertStringSidToSidW(core.input.as_ptr(),&mut original)};
  let error=if observed==0{Some(unsafe{GetLastError()})}else{None};
  core.allocation=original as usize;core.conversion_result=Some(observed);core.conversion_error=error;
  if observed==0||original.is_null(){return Err(StorageError::Io(path.to_path_buf(),format!("original TEST SID conversion refused: {error:?}")));}
  Ok(local)
 }
 fn pointer(&self)->Ptr{let core=self.core.as_ref().expect("original allocation custody");
  assert!(core.conversion_result.is_some_and(|v|v!=0)&&core.allocation!=0&&!core.release_attempted,"valid live original allocation");core.allocation as Ptr}
 fn directory_create(&mut self,path:&Path,allow_exists:bool)->Result<(),StorageError>{
  let name=api_path(path);let attributes=SecurityAttributes{length:size_of::<SecurityAttributes>()as u32,descriptor:self.pointer(),inherit:0};
  let observed=unsafe{CreateDirectoryW(name.as_ptr(),&attributes)};
  let error=if observed==0{Some(unsafe{GetLastError()})}else{None};
  let core=self.core.as_mut().expect("original creation custody");core.directory_result=Some(observed);core.directory_error=error;
  if let Some(error)=error{if !allow_exists||error!=183{return Err(io(path,std::io::Error::from_raw_os_error(error as i32)));}}
  Ok(())
 }
 fn perform<T>(mut self,operation:impl FnOnce(&mut Self)->Result<T,StorageError>)->Result<T,StorageError>{
  // Preallocate result custody before any File/owner operation, then retain a
  // successful original result before the allocation release can fail.
  let mut output=ConstructingOwner::prepare();let result=operation(&mut self);
  let core=self.core.as_mut().expect("original allocation release custody");
  core.body_result=Some(result.is_ok());if let Err(error)=&result{core.body_problem=Some(error.to_string());}
  let body_error=match result{Ok(value)=>{output.capture(value);None},Err(error)=>Some(error)};
  assert!(!core.release_attempted&&core.allocation!=0&&core.conversion_result.is_some_and(|v|v!=0),"one valid original allocation release");
  core.release_attempted=true;let returned=unsafe{LocalFree(core.allocation as Ptr)};
  let error=if returned.is_null(){None}else{Some(unsafe{GetLastError()})};
  core.release_result=Some(returned as usize);core.release_error=error;
  if let Some(error)=error{return Err(StorageError::Io(core.path.clone(),format!("original LocalFree release unknown {error}; body={:?}",core.body_problem)));}
  if let Some(error)=body_error{return Err(error);}
  drop(self.core.take());Ok(output.publish())
 }
 fn close_checked(self)->Result<(),StorageError>{self.perform(|_|Ok(()))}
 #[cfg(test)]
 fn external_result(&mut self,allocation:Ptr,code:u32){let core=self.core.as_mut().expect("preallocated TEST query custody");
  core.allocation=allocation as usize;core.conversion_result=Some(i32::from(code==0));core.conversion_error=if code==0{None}else{Some(code)};}
}
impl Drop for Local {fn drop(&mut self){if let Some(core)=self.core.take(){
 if core.conversion_result.is_some()||core.allocation!=0{let _=Box::into_raw(core);}
}}}
fn text(value: &str) -> Vec<u16> {
    value.encode_utf16().chain([0]).collect()
}
// Original SID bytes stay usize-aligned, with no native allocation obligation.
struct PinnedSid(Ptr, Vec<usize>);
impl PinnedSid {
    fn from_bytes(bytes:&[u8])->Self {
        let mut words=vec![0usize;bytes.len().div_ceil(size_of::<usize>())];
        unsafe {std::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(),bytes.len())}
            .copy_from_slice(bytes);
        Self(words.as_mut_ptr().cast(),words)
    }
}
const SYSTEM_SID:&[u8]=&[1,1,0,0,0,0,0,5,18,0,0,0];
const ADMIN_SID:&[u8]=&[1,2,0,0,0,0,0,5,32,0,0,0,32,2,0,0];
const INSTALLER_SID:&[u8]=&[1,6,0,0,0,0,0,5,80,0,0,0,181,137,251,56,25,132,194,203,92,108,35,109,87,0,119,110,192,2,100,135];
fn mechanical(path:&Path, failure:WindowsMechanicalFailure)->StorageError {
    // The typed failure retains original native observations even after mapping.
    io(path,std::io::Error::other(failure.description().to_owned()))
}
struct Identity {
    token_data: Vec<usize>,
    user_text: String,
    principal: CurrentWindowsPrincipal,
    system: PinnedSid,
    admins: PinnedSid,
    installer: PinnedSid,
}
impl Identity {
    fn new(path: &Path) -> Result<Self, StorageError> {
        let principal=CurrentWindowsPrincipal::capture_own().map_err(|error|mechanical(path,error))?;
        let user_text=principal.user_sid_text().map_err(|error|mechanical(path,error))?;
        let user= PinnedSid::from_bytes(principal.user_sid());
        principal.recheck().map_err(|error|mechanical(path,error))?;
        Ok(Self {token_data:user.1,user_text,principal,
            system:PinnedSid::from_bytes(SYSTEM_SID),
            admins:PinnedSid::from_bytes(ADMIN_SID),
            installer:PinnedSid::from_bytes(INSTALLER_SID)})
    }
    fn user(&self) -> Ptr {
        self.token_data.as_ptr() as Ptr
    }
    fn trusted(&self, sid: Ptr) -> bool {
        unsafe {
            EqualSid(sid, self.user()) != 0
                || [self.system.0, self.admins.0, self.installer.0]
                    .iter()
                    .any(|s| EqualSid(sid, *s) != 0)
        }
    }
    fn descriptor(&self, path: &Path, directory: bool) -> Result<Local, StorageError> {
        // Explicit current-user owner, not the elevated token's default Administrators owner.
        let flags = if directory { "OICI" } else { "" };
        let value = text(&format!(
            "O:{}D:P(A;{flags};FA;;;SY)(A;{flags};FA;;;{})",
            self.user_text, self.user_text
        ));
        Local::descriptor(path,value)
    }
    fn check(&self, file: &File, path: &Path, private: bool) -> Result<(), StorageError> {
        self.check_inner(file,path,private,None)
    }
    fn check_inner(&self, file: &File, path: &Path, private: bool,
        test_installer: Option<Ptr>) -> Result<(), StorageError> {
        let snapshot=file_security_snapshot(file).map_err(|error|mechanical(path,error))?;
        // Byte comparison is exact for the fully bounded, native-valid SID bytes.
        let own=self.principal.user_sid();
        let test_sid=if let Some(sid)=test_installer {
            if unsafe{IsValidSid(sid)}==0{return Err(access(path));}
            let length=unsafe{GetLengthSid(sid)} as usize;
            if !(8..=68).contains(&length){return Err(access(path));}
            Some(unsafe{std::slice::from_raw_parts(sid.cast::<u8>(),length)})
        } else {None};
        let trusted_ancestor=|sid:&[u8]|sid==own||sid==SYSTEM_SID||sid==ADMIN_SID
            ||sid==INSTALLER_SID||test_sid.is_some_and(|installer|sid==installer);
        if (private&&snapshot.owner_sid()!=own)||(!private&&!trusted_ancestor(snapshot.owner_sid())) {
            return Err(if private{StorageError::NotOwner(path.into())}
                else{StorageError::ReplaceableAncestor(path.into())});
        }
        if private&&(snapshot.control()&0x1000==0||snapshot.ace_count()!=2){return Err(access(path));}
        let(mut user,mut system)=(false,false);
        for(kind,flags,mask,sid)in snapshot.aces(){
            if !private&&flags&8!=0{continue;}
            if !private&&kind==1{continue;}
            if kind!=0{return Err(access(path));}
            if private {
                if flags&(8|16)!=0||mask!=0x1f01ff{return Err(access(path));}
                if sid==own&&!user{user=true;}
                else if sid==SYSTEM_SID&&!system{system=true;}
                else{return Err(access(path));}
            }else if !trusted_ancestor(sid)
                &&mask&(0x2|0x10|0x100|0x40|DELETE|0x40000|0x80000|0x10000000|WRITE)!=0 {
                return Err(StorageError::ReplaceableAncestor(path.into()));
            }
        }
        if private&&(!user||!system){return Err(access(path));}
        self.principal.recheck().map_err(|error|mechanical(path,error))?;
        Ok(())
    }
}

// Whole original native File custody exists before CreateFile/validation.
// A failed validation or unwind retains the same holder; no RAII native close.
struct FileConstructionCore {
    file:Option<std::mem::ManuallyDrop<File>>,raw:usize,path:PathBuf,
    original:Option<[u8;24]>,expected:Option<[u8;24]>,identity_error:Option<i32>,
    flags_result:Option<i32>,flags_error:Option<u32>,flags:u32,
    open_error:Option<i32>,validation_result:Option<bool>,validation_problem:Option<String>,close:crate::host_clock::native_retained_close::RetainedCloseReport,
}
struct ConstructingFile {core:Option<Box<FileConstructionCore>>}
impl ConstructingFile {
    fn prepare(path:&Path)->std::io::Result<Self> {
        let close=crate::host_clock::native_retained_close::RetainedCloseReport::prepare(1)
            .map_err(std::io::Error::other)?;
        Ok(Self{core:Some(Box::new(FileConstructionCore{file:None,raw:0,path:path.into(),
            original:None,expected:None,identity_error:None,flags_result:None,flags_error:None,flags:0,open_error:None,validation_result:None,validation_problem:None,close}))})
    }
    fn original(&self)->&File {self.core.as_ref().expect("original File custody").file.as_ref().expect("original File held")}
    fn original_mut(&mut self)->&mut File {self.core.as_mut().expect("original File custody").file.as_mut().expect("original File held")}
    fn capture(&mut self,file:File)->std::io::Result<()> {
        // First step transfers the original File into preallocated ManuallyDrop.
        let file=std::mem::ManuallyDrop::new(file);
        let core=self.core.as_mut().expect("preallocated original File custody");
        assert!(core.file.is_none(),"one original File per constructor");
        core.raw=file.as_raw_handle() as usize;core.file=Some(file);
        match crate::host_clock::native_retained_close::retained_identity(core.file.as_ref().expect("original File")) {
            Ok(identity)=>{core.original=Some(identity);Ok(())},
            Err(error)=>{core.identity_error=Some(error);Err(std::io::Error::other(format!("opened original File identity query refused: {error}")))}
        }
    }
    fn validate<T>(&mut self,check:impl FnOnce(&mut File)->Result<T,StorageError>)->Result<T,StorageError>{
        if self.core.as_ref().expect("original validation custody").validation_result==Some(false){return Err(access(&self.core.as_ref().expect("original path").path));}
        let result=check(self.original_mut());let core=self.core.as_mut().expect("original validation custody");
        core.validation_result=Some(result.is_ok());
        if let Err(error)=&result{core.validation_problem=Some(error.to_string());}result
    }
    fn expect_same(&mut self,expected:&FileId,path:&Path,directory:bool)->Result<(),StorageError>{
        self.core.as_mut().expect("original comparison custody").expected=Some(expected.close_pin());
        self.validate(|file|{if inspect(file,path,directory)?!=*expected{return Err(StorageError::Substituted(path.into()));}Ok(())})
    }
    fn pin(&self)->[u8;24]{self.core.as_ref().expect("original File custody").original.expect("original identity captured")}
    fn publish(mut self)->File {
        let check=self.core.as_ref().expect("original File custody");
        assert!(check.original.is_some()&&check.file.is_some()&&check.validation_result!=Some(false),"no publication after failed validation");
        let mut core=self.core.take().expect("original File custody");
        std::mem::ManuallyDrop::into_inner(core.file.take().expect("one successful File transfer"))
    }
    fn close_checked(mut self)->Result<(),StorageError> {
        let core=self.core.as_mut().expect("preallocated File close custody");
        if core.validation_result==Some(false){return Err(access(&core.path));}
        let pin=core.original.ok_or_else(||access(&core.path))?;
        let file=core.file.take().ok_or_else(||access(&core.path))?;
        core.close.file(std::mem::ManuallyDrop::into_inner(file),pin);
        if !core.close.retained_handles_closed(){return Err(StorageError::Io(core.path.clone(),
            "original temporary File close/identity unknown; whole outcome retained".into()));}
        drop(self.core.take());Ok(())
    }
    fn absent(mut self,error:std::io::Error)->std::io::Error {
        let core=self.core.as_mut().expect("preallocated File open custody");
        core.open_error=error.raw_os_error();
        assert!(core.file.is_none(),"known absent open has no File obligation");
        drop(self.core.take());error
    }
}
impl std::ops::Deref for ConstructingFile{type Target=File;fn deref(&self)->&File{self.original()}}
impl std::ops::DerefMut for ConstructingFile{fn deref_mut(&mut self)->&mut File{self.original_mut()}}
impl Drop for ConstructingFile{fn drop(&mut self){if let Some(core)=self.core.take(){
    if core.file.is_some()||core.close.attempted()!=0{let _=Box::into_raw(core);}
}}}
// Original constructed aggregates remain protected before any fallible query.
struct ConstructingOwner<T>{value:Option<Box<Option<std::mem::ManuallyDrop<T>>>>}
impl<T> ConstructingOwner<T>{
    fn prepare()->Self{Self{value:Some(Box::new(None))}}
    fn capture(&mut self,value:T){let value=std::mem::ManuallyDrop::new(value);
        let slot=self.value.as_mut().expect("preallocated aggregate custody");assert!(slot.is_none(),"one aggregate");**slot=Some(value);}
    fn get(&self)->&T{self.value.as_ref().expect("aggregate slot").as_ref().as_ref().expect("aggregate original")}
    fn get_mut(&mut self)->&mut T{self.value.as_mut().expect("aggregate slot").as_mut().as_mut().expect("aggregate original")}
    fn publish(mut self)->T{let mut slot=self.value.take().expect("aggregate custody");
        std::mem::ManuallyDrop::into_inner(slot.take().expect("one aggregate transfer"))}
}
impl<T> Drop for ConstructingOwner<T>{fn drop(&mut self){if let Some(slot)=self.value.take(){if slot.is_some(){let _=Box::into_raw(slot);}}}}
fn open(
    path: &Path,
    access: u32,
    disposition: u32,
    security: Option<&Local>,
    directory: bool,
) -> Result<ConstructingFile, StorageError> {
    open_raw(path, access, disposition, security, directory).map_err(|e| io(path, e))
}
fn open_raw(
    path: &Path,
    access: u32,
    disposition: u32,
    security: Option<&Local>,
    directory: bool,
) -> std::io::Result<ConstructingFile> {
    let mut retained=ConstructingFile::prepare(path)?;
    let attributes = SecurityAttributes {
        length: size_of::<SecurityAttributes>() as u32,
        descriptor: security.map_or(null_mut(), Local::pointer),
        inherit: 0,
    };
    let flags = NO_FOLLOW
        | if directory {
            BACKUP
        } else {
            0x80 | WRITE_THROUGH
        };
    let handle = unsafe {
        CreateFileW(
            api_path(path).as_ptr(),
            access | if directory { 0x100080 } else { 0 },
            1 | 2,
            &attributes,
            disposition,
            flags,
            null_mut(),
        )
    };
    if handle == (-1isize) as Ptr {
        let error=std::io::Error::last_os_error();return Err(retained.absent(error));
    }
    // Original handle goes immediately into preallocated whole custody.
    retained.capture(unsafe { File::from_raw_handle(handle) })?;
    let mut inherited=0;let observed=unsafe{GetHandleInformation(handle,&mut inherited)};
    let error=if observed==0{Some(unsafe{GetLastError()})}else{None};
    let core=retained.core.as_mut().expect("original native flags custody");
    core.flags_result=Some(observed);core.flags_error=error;core.flags=inherited;
    if observed==0||inherited&1!=0{return Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,"inheritable or unreadable Windows handle"));}
    Ok(retained)
}
#[derive(Debug)]
pub(super) struct WindowsStateDir {
    _handles: Vec<File>,
    _originals: Vec<[u8;24]>,
    path: PathBuf,
    #[cfg(test)]
    test_installer: Option<TestPlacementAdministrator>,
}
impl WindowsStateDir {
    pub(super) fn secure(dir: &Path) -> Result<Self, StorageError> {
        Self::secure_inner(dir,true)
    }
    fn secure_inner(dir: &Path, create_leaf: bool) -> Result<Self, StorageError> {
        Self::secure_ancestor(dir,create_leaf,None)
    }
    fn secure_ancestor(dir: &Path, create_leaf: bool,
        test_installer:Option<Ptr>) -> Result<Self, StorageError> {
        strict(dir)?;
        let root = dir.components().take(2).collect::<PathBuf>();
        if unsafe { GetDriveTypeW(wide(root.as_os_str()).as_ptr()) } != 3 {
            return Err(StorageError::Unsupported(
                "clock storage requires a local fixed NTFS drive",
            ));
        }
        let identity = Identity::new(dir)?;
        let count=dir.components().filter(|c|!matches!(c,Component::Prefix(_))).count();
        let mut handles=Vec::new();handles.try_reserve_exact(count).map_err(|_|access(dir))?;
        let mut published=Vec::new();published.try_reserve_exact(count).map_err(|_|access(dir))?;
        let mut originals=Vec::new();originals.try_reserve_exact(count).map_err(|_|access(dir))?;
        let owned_path=dir.to_path_buf();
        let mut prefix = PathBuf::new();
        for component in dir.components() {
            prefix.push(component.as_os_str());
            if matches!(component, Component::Prefix(_)) {
                continue;
            }
            let leaf = prefix == dir;
            if leaf && create_leaf {
                let sd = identity.descriptor(dir, true)?;
                sd.perform(|allocation|allocation.directory_create(dir,true))?;
            }
            let mut handle = open(&prefix, READ_CONTROL, OPEN, None, true)?;
            let id = handle.validate(|file|inspect(file,&prefix,true))?;
            if leaf {
                #[cfg(test)]
                BETWEEN_DIRECTORY_PIN_AND_REOPEN.with(|hook| {
                    if let Some(hook) = hook.take() {
                        hook(&prefix);
                    }
                });
                let mut named = open(&prefix, READ_CONTROL, OPEN, None, true)?;
                named.expect_same(&id,&prefix,true)?;
                named.close_checked()?;

            }
            handle.validate(|file|{check_volume(file,&prefix)?;identity.check_inner(file,&prefix,leaf,test_installer)})?;
            // No DELETE sharing: retained chain cannot be renamed/replaced by another handle.
            handles.push(handle);
        }
        for handle in handles{originals.push(handle.pin());published.push(handle.publish());}
        Ok(Self {
            _handles: published,
            _originals: originals,
            path: owned_path,
            #[cfg(test)]
            test_installer:None,
        })
    }
    fn file(&self,path:&Path,access:u32,create:bool)->Result<Option<File>,StorageError>{
        Ok(self.file_guarded(path,access,create)?.map(ConstructingFile::publish))
    }
    fn file_guarded(&self, path: &Path, access: u32, create: bool) -> Result<Option<ConstructingFile>, StorageError> {
        strict(path)?;
        if path.parent() != Some(self.path.as_path()) {
            return Err(StorageError::Path(path.into()));
        }
        let identity = Identity::new(path)?;
        // DELETE access is incompatible with our no-delete-sharing probe. Retain ordinary
        // read handles; for a mutation compare a prior pinned identity after reopening DELETE.
        let prior = if access & DELETE != 0 {
            match open_raw(path, READ_CONTROL, OPEN, None, false) {
                Ok(mut probe) => {let id=probe.validate(|file|inspect(file,path,false))?;probe.close_checked()?;Some(id)},
                Err(e) if e.raw_os_error() == Some(2) => None,
                Err(e) => return Err(io(path, e)),
            }
        } else {
            None
        };
        #[cfg(test)]
        BETWEEN_MUTATION_OPEN.with(|hook| {
            if let Some(hook) = hook.take() {
                hook(path);
            }
        });
        let mut file = match open_raw(path, access | READ_CONTROL, OPEN, None, false) {
            Ok(file) => file,
            Err(e) if !create && e.raw_os_error() == Some(2) => return Ok(None),
            Err(e) => {
                // Only actual FILE_NOT_FOUND permits creation. Never truncate/repair an existing file.
                if e.raw_os_error() != Some(2) {
                    return Err(io(path, e));
                }
                let sd = identity.descriptor(path, false)?;
                sd.perform(|allocation|match open_raw(path, access | READ_CONTROL, NEW, Some(allocation), false) {
                    Ok(file) => Ok(file),
                    Err(e) if e.raw_os_error() == Some(80) || e.raw_os_error() == Some(183) => {
                        open(path, access | READ_CONTROL, OPEN, None, false)
                    }
                    Err(e) => Err(io(path, e)),
                })?
            }
        };
        let id=file.validate(|file|{let id=inspect(file,path,false)?;identity.check(file,path,true)?;Ok(id)})?;
        if access & DELETE != 0 {
            if prior.as_ref().is_some_and(|prior| *prior != id) {
                return Err(StorageError::Substituted(path.into()));
            }
        } else {
            let mut named = open(path, READ_CONTROL, OPEN, None, false)?;
            named.expect_same(&id,path,false)?;
            named.close_checked()?;

        }
        Ok(Some(file))
    }
    pub(super) fn lock(&self, path: &Path) -> Result<File, StorageError> {
        let file = self
            .file_guarded(path, READ | WRITE, true)?
            .ok_or_else(|| access(path))?;
        match file.try_lock() {
            Ok(()) => Ok(file.publish()),
            Err(std::fs::TryLockError::WouldBlock) => Err(StorageError::Locked(path.into())),
            Err(std::fs::TryLockError::Error(e)) => Err(io(path, e)),
        }
    }
    pub(super) fn check_entries(&self, entries: &[PathBuf]) -> Result<(), StorageError> {
        for path in entries {
            if let Some(file)=self.file_guarded(path,READ,false)?{file.close_checked()?;}
        }
        Ok(())
    }
    pub(super) fn read(&self, path: &Path, limit: usize) -> Result<Option<Vec<u8>>, StorageError> {
        let limit=(limit as u64).checked_add(1).ok_or_else(||access(path))?;
        let Some(mut file)=self.file_guarded(path,READ,false)? else{return Ok(None)};
        let mut raw=Vec::new();
        file.validate(|original|original.take(limit).read_to_end(&mut raw).map_err(|error|io(path,error)).map(|_|()))?;
        file.close_checked()?;Ok(Some(raw))
    }
    fn rename(&self, file: &File, target: &Path, replace: bool) -> Result<(), StorageError> {
        strict(target)?;
        if target.parent() != Some(self.path.as_path()) {
            return Err(StorageError::Path(target.into()));
        }
        // Win32 SetFileInformationByHandle rejected the relative root-handle form with native
        // ERROR_INVALID_PARAMETER in the retained positive attempt. Use its documented absolute
        // target form while every ancestor and the final directory remain pinned without DELETE
        // sharing; this is not a name-preflight/reopen-only substitution barrier.
        let name = api_path(target);
        let offset = offset_of!(Rename, name);
        // Win32's absolute-name conversion also consumes the terminating NUL. Preserve it in
        // the allocation and native buffer size although FileNameLength itself excludes NUL.
        let length = offset + name.len() * 2;
        // Native structure pointer alignment; FileNameLength excludes terminating NUL.
        let mut buffer = vec![0usize; length.div_ceil(size_of::<usize>())];
        let raw = buffer.as_mut_ptr() as *mut Rename;
        unsafe {
            (*raw).replace = u32::from(replace);
            (*raw).root = null_mut();
            (*raw).length = ((name.len() - 1) * 2) as u32;
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                std::ptr::addr_of_mut!((*raw).name).cast(),
                name.len(),
            );
            if SetFileInformationByHandle(file.as_raw_handle(), 3, raw.cast(), length as u32) == 0 {
                return Err(last(target));
            }
        }
        Ok(())
    }
    pub(super) fn write(&self, path: &Path, bytes: &[u8]) -> Result<(), StorageError> {
        // Validate the old target through its handle before it can be replaced.
        if let Some(file)=self.file_guarded(path,READ,false)?{file.close_checked()?;}
        let tmp = super::sibling(path, ".tmp");
        // Preserve crash leftovers instead of deleting partial evidence.
        if let Some(mut old) = self.file_guarded(&tmp, READ | DELETE, false)? {
            let mut salt = [0u8; 16];
            getrandom::getrandom(&mut salt)
                .map_err(|e| StorageError::Io(tmp.clone(), e.to_string()))?;
            old.validate(|original|self.rename(original,
                &super::sibling(&tmp,&format!(".evidence-{}",hex::encode(salt))),false))?;
            old.close_checked()?;
        }
        let identity = Identity::new(&tmp)?;
        let sd = identity.descriptor(&tmp, false)?;
        let mut file=sd.perform(|allocation|open(&tmp,READ_CONTROL|READ|WRITE|DELETE,NEW,Some(allocation),false))?;
        file.validate(|original|{inspect(original,&tmp,false)?;identity.check(original,&tmp,true)})?;
        #[cfg(test)]
        crash(1);
        file.validate(|original|original.write_all(bytes).map_err(|error|io(&tmp,error)))?;
        file.validate(|original|original.sync_all().map_err(|error|io(&tmp,error)))?;
        #[cfg(test)]
        crash(2);
        file.validate(|original|self.rename(original,path,true))?;
        #[cfg(test)]
        crash(3);
        file.validate(|original|original.sync_all().map_err(|error|io(path,error)))?;
        // Same durable ordering; no directory/volume power-loss flush claim.
        file.close_checked()
    }
    pub(super) fn remove(&self, path: &Path) -> Result<(), StorageError> {
        let Some(mut file)=self.file_guarded(path,READ|DELETE,false)? else{return Ok(())};
        file.validate(|original|{let mut delete=1u8;
            if unsafe{SetFileInformationByHandle(original.as_raw_handle(),4,(&mut delete as *mut u8).cast(),1)}==0{return Err(last(path));}
            Ok(())
        })?;
        file.close_checked()
    }
}
// Explicit Architect-authorized TEST installation domain. No string allowlist,
// environment-derived administrator, production factory or global policy change.
// The administrator's whole installation-domain rollback remains outside scope.
#[cfg(test)]
#[derive(Debug)]
struct TestPlacementAdministrator;
#[cfg(test)]
impl TestPlacementAdministrator {
    fn exact(directory:&Path,owner_sid:&str,node_sid:&str)->Result<Self,StorageError> {
        const ADMIN:&str="S-1-5-21-2588165551-1705744427-3256592067-1001";
        if directory!=Path::new(r"C:\Users\admin\MutinyClockQualification\owner-state")
            || owner_sid==ADMIN || node_sid==ADMIN {
            return Err(access(directory));
        }
        Ok(Self)
    }
    fn native_sid(&self,directory:&Path)->Result<Local,StorageError> {
        const ADMIN:&str="S-1-5-21-2588165551-1705744427-3256592067-1001";
        Local::sid(directory,text(ADMIN))
    }
}
// Local clock installation custody, separate from the current-user anchor
// writer. No directory creation, ACL repair or caller path is supplied here.
const INSTALL_DIR: &str = "C:/ProgramData/Mutiny/NativeClock";
const INSTALL_NAMES: [&str; 3] = ["accepted.json", "deployment.json", "qualification.json"];
fn installation_chain() -> Vec<PathBuf> {
    let mut prefix=PathBuf::new();let mut paths=Vec::new();
    for c in Path::new(INSTALL_DIR).components() {
        prefix.push(c.as_os_str());
        if !matches!(c,Component::Prefix(_)) {paths.push(prefix.clone());}
    }
    paths
}
fn installation_no_impersonation(path:&Path)->Result<(),StorageError> {
    require_no_thread_token().map_err(|error|mechanical(path,error))
}
fn installation_identity() -> Result<Identity,StorageError> {
    let path=Path::new(INSTALL_DIR);installation_no_impersonation(path)?;
    let identity=Identity::new(path)?;
    // Actual captured elevation; inherited SYSTEM/installer exclusions unchanged.
    if identity.principal.elevated()||identity.principal.user_sid()==SYSTEM_SID
        ||identity.principal.user_sid()==INSTALLER_SID{return Err(access(path));}
    identity.principal.recheck().map_err(|error|mechanical(path,error))?;
    installation_no_impersonation(path)?;
    Ok(identity)
}
fn installation_security(identity:&Identity,file:&File,path:&Path,leaf:bool)
    ->Result<(),StorageError> {
    let snapshot=file_security_snapshot(file).map_err(|error|mechanical(path,error))?;
    let administrator=|sid:&[u8]|sid==SYSTEM_SID||sid==ADMIN_SID||sid==INSTALLER_SID;
    if !administrator(snapshot.owner_sid())||(leaf&&snapshot.control()&0x1000==0){return Err(access(path));}
    for(kind,flags,mask,sid)in snapshot.aces(){
        if flags&8!=0{continue;}
        if kind==1{continue;}
        if kind!=0{return Err(access(path));}
        // Current user deliberately remains outside administrator writers.
        if !administrator(sid)
            &&mask&(0x2|0x4|0x10|0x100|0x40|DELETE|0x40000|0x80000|0x10000000|WRITE)!=0 {
            return Err(StorageError::ReplaceableAncestor(path.into()));
        }
    }
    identity.principal.recheck().map_err(|error|mechanical(path,error))?;
    Ok(())
}
fn installation_file(path:&Path)->Result<ConstructingFile,StorageError> {
    let mut retained=ConstructingFile::prepare(path).map_err(|e|io(path,e))?;
    let h=unsafe{CreateFileW(api_path(path).as_ptr(),READ|READ_CONTROL,1,null(),
        OPEN,NO_FOLLOW,null_mut())};
    if h==(-1isize) as Ptr {let error=std::io::Error::last_os_error();return Err(io(path,retained.absent(error)));}
    retained.capture(unsafe{File::from_raw_handle(h)}).map_err(|e|io(path,e))?;
    let mut flags=0;let result=unsafe{GetHandleInformation(h,&mut flags)};
    let error=if result==0{Some(unsafe{GetLastError()})}else{None};
    let core=retained.core.as_mut().expect("original installation File flags");
    core.flags_result=Some(result);core.flags_error=error;core.flags=flags;
    if result==0||flags&1!=0{return Err(access(path));}
    retained.validate(|file|{inspect(file,path,false)?;check_volume(file,path)?;Ok(())})?;Ok(retained)
}
pub(super) fn read_admin_installation()
    ->Result<(Vec<File>,Vec<(File,Vec<u8>)>),StorageError> {
    strict(Path::new(INSTALL_DIR))?;let identity=installation_identity()?;
    let root=Path::new(INSTALL_DIR).components().take(2).collect::<PathBuf>();
    if unsafe{GetDriveTypeW(wide(root.as_os_str()).as_ptr())}!=3 {
        return Err(StorageError::Unsupported("installation requires local fixed NTFS"));
    }
    let paths=installation_chain();let mut ancestors=Vec::new();
    ancestors.try_reserve_exact(paths.len()).map_err(|_|access(Path::new(INSTALL_DIR)))?;
    let mut published_ancestors=Vec::new();published_ancestors.try_reserve_exact(paths.len()).map_err(|_|access(Path::new(INSTALL_DIR)))?;
    let mut published_objects=Vec::new();published_objects.try_reserve_exact(INSTALL_NAMES.len()).map_err(|_|access(Path::new(INSTALL_DIR)))?;
    for path in &paths {
        let mut file=open(path,READ_CONTROL,OPEN,None,true)?;
        file.validate(|file|{inspect(file,path,true)?;check_volume(file,path)?;installation_security(&identity,file,path,path==Path::new(INSTALL_DIR))})?;
        ancestors.push(file);
    }
    let mut objects=Vec::new();objects.try_reserve_exact(INSTALL_NAMES.len()).map_err(|_|access(Path::new(INSTALL_DIR)))?;
    for name in INSTALL_NAMES {
        let path=Path::new(INSTALL_DIR).join(name);let mut file=installation_file(&path)?;
        let length=file.validate(|file|{installation_security(&identity,file,&path,true)?;file.metadata().map_err(|e|io(&path,e)).map(|m|m.len())})?;
        if length==0 || length>64*1024 {return Err(access(&path));}
        let mut bytes=Vec::new();
        file.original_mut().take(64*1024+1).read_to_end(&mut bytes).map_err(|e|io(&path,e))?;
        if bytes.len() as u64!=length || file.metadata().map_err(|e|io(&path,e))?.len()!=length {
            return Err(StorageError::Substituted(path));
        }
        inspect(&file,&path,false)?;installation_security(&identity,&file,&path,true)?;
        objects.push((file,bytes));
    }
    for file in ancestors{published_ancestors.push(file.publish());}
    for(file,bytes)in objects{published_objects.push((file.publish(),bytes));}
    Ok((published_ancestors,published_objects))
}
pub(super) fn recheck_admin_installation(ancestors:&[File],objects:&[&File])
    ->Result<(),StorageError> {
    let identity=installation_identity()?;let paths=installation_chain();
    if ancestors.len()!=paths.len() || objects.len()!=INSTALL_NAMES.len() {
        return Err(access(Path::new(INSTALL_DIR)));
    }
    for (file,path) in ancestors.iter().zip(paths.iter()) {
        inspect(file,path,true)?;check_volume(file,path)?;
        installation_security(&identity,file,path,path==Path::new(INSTALL_DIR))?;
    }
    for (file,name) in objects.iter().zip(INSTALL_NAMES) {
        let path=Path::new(INSTALL_DIR).join(name);
        inspect(file,&path,false)?;check_volume(file,&path)?;
        installation_security(&identity,file,&path,true)?;
    }
    Ok(())
}
fn artifact_name(name:&str)->bool {
    name.len()==69 && name.ends_with(".json") && name.as_bytes()[..64].iter()
        .all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(b))
        && name.as_bytes()[..64].iter().any(|b|*b!=b'0')
}
#[cfg(test)] mod artifact_leaf_tests {
    #[test] fn modeled_windows_digest_leaf_rejects_unicode_alias_device_stream_and_foreign_names() {
        let leaf=format!("{}.json","12".repeat(32));assert!(super::artifact_name(&leaf));
        for name in [format!("../{leaf}"),format!("{leaf}:stream"),leaf.to_uppercase(),
            format!("{}.json","00".repeat(32)),format!("{}.json","é".repeat(32)),
            "C:/foreign.json".into(),"NUL.json".into(),format!("{leaf}."),format!("{leaf} ")] {
            assert!(!super::artifact_name(&name));
        }
    }
}
fn named_installation_chain(ancestors:&[File],identity:&Identity)->Result<(),StorageError> {
    let paths=installation_chain();
    if ancestors.len()!=paths.len() {return Err(access(Path::new(INSTALL_DIR)));}
    for (held,path) in ancestors.iter().zip(paths.iter()) {
        let mut named=open(path,READ_CONTROL,OPEN,None,true)?;
        let expected=named.validate(|named|{for f in [held,named]{check_volume(f,path)?;
            installation_security(identity,f,path,path==Path::new(INSTALL_DIR))?;}inspect(held,path,true)})?;
        named.expect_same(&expected,path,true)?;named.close_checked()?;

    }
    Ok(())
}
pub(super) fn read_admin_artifacts(ancestors:&[File],names:&[String])->Result<Vec<File>,StorageError> {
    read_admin_artifacts_bounded(ancestors,names,32)
}
pub(super) fn read_admin_artifacts_extended(ancestors:&[File],names:&[String])->Result<Vec<File>,StorageError> {
    read_admin_artifacts_bounded(ancestors,names,4096)
}
fn read_admin_artifacts_bounded(ancestors:&[File],names:&[String],maximum:usize)->Result<Vec<File>,StorageError> {
    if names.is_empty() || names.len()>maximum || names.iter().any(|n|!artifact_name(n)) {
        return Err(access(Path::new(INSTALL_DIR)));
    }
    let identity=installation_identity()?;named_installation_chain(ancestors,&identity)?;
    let mut objects=Vec::new();objects.try_reserve_exact(names.len()).map_err(|_|access(Path::new(INSTALL_DIR)))?;
    let mut published=Vec::new();published.try_reserve_exact(names.len()).map_err(|_|access(Path::new(INSTALL_DIR)))?;
    for name in names {
        let path=Path::new(INSTALL_DIR).join(name);let mut file=installation_file(&path)?;
        let length=file.validate(|file|{installation_security(&identity,file,&path,true)?;file.metadata().map_err(|e|io(&path,e)).map(|m|m.len())})?;
        if length==0 || length>64*1024 {return Err(access(&path));}
        objects.push(file);
    }
    let refs:Vec<_>=names.iter().zip(objects.iter()).map(|(n,f)|(n.as_str(),f.original())).collect();
    recheck_admin_artifacts(ancestors,&refs)?;
    for file in objects{published.push(file.publish());}Ok(published)
}
pub(super) fn recheck_admin_artifacts(ancestors:&[File],objects:&[(&str,&File)])
    ->Result<(),StorageError> {
    if objects.len()>4096 || objects.iter().any(|(n,_)|!artifact_name(n)) {
        return Err(access(Path::new(INSTALL_DIR)));
    }
    let identity=installation_identity()?;named_installation_chain(ancestors,&identity)?;
    for (name,held) in objects {
        let path=Path::new(INSTALL_DIR).join(name);let mut named=installation_file(&path)?;
        let expected=named.validate(|named|{for file in [*held,named]{check_volume(file,&path)?;installation_security(&identity,file,&path,true)?;}inspect(held,&path,false)})?;
        named.expect_same(&expected,&path,false)?;named.close_checked()?;

    }
    named_installation_chain(ancestors,&identity)?;Ok(())
}

/// Existing-only head held by the dedicated process user. Does not authenticate
/// installed selection/process code or qualify a clock. The separate principal
/// gate is additional to the reused native owner/DACL/NTFS/no-reparse checks.
pub(in crate::host_clock) struct WindowsProtectedHead {
    owner: WindowsStateDir,
    head: Option<File>,
    identity: FileId,
    owner_sid: String,
    path: PathBuf,
    frozen: bool,
    journal:Option<File>,journal_identity:Option<FileId>,
    journal_scope:Option<crate::host_clock::protected_clock_lineage_v1::Scope>,
    original_head:[u8;24],original_journal:Option<[u8;24]>,original_ancestors:Vec<[u8;24]>,
}
/// Borrowed documentary revocation armed before a SAME-writer transition.
/// The writer flag is set before preflight; retaining only the engine borrow
/// lets the private transition borrow the original whole writer without aliases.
/// This in-memory barrier does not establish process-abort/power-loss durability.
struct WindowsLineageTransition<'a> {
    engine:&'a mut crate::host_clock::protected_clock_lineage_v1::DocumentaryEngine,
    completed:bool,
}
impl<'a> WindowsLineageTransition<'a> {
    fn begin(frozen:&mut bool,
        engine:&'a mut crate::host_clock::protected_clock_lineage_v1::DocumentaryEngine)->Self {
        *frozen=true;
        Self{engine,completed:false}
    }
    fn finish(mut self,result:Result<Vec<u8>,StorageError>)->Result<Vec<u8>,StorageError> {
        self.completed=result.is_ok();
        result
    }
}
impl Drop for WindowsLineageTransition<'_> {
    fn drop(&mut self) {
        // unknown() only assigns existing bookkeeping flags: no allocation,
        // native call, close, retry or panic while an unwind is already active.
        if !self.completed {self.engine.unknown();}
    }
}
/// Quarantine after failed explicit CloseHandle. It deliberately supplies no
/// Drop/retry/reopen method: an uncertain native handle must not be silently
/// relinquished or closed again after possible kernel reuse. The caller retains
/// this owner in the stopped lifecycle until exact OS reconciliation/process end.
pub(in crate::host_clock) struct WindowsCloseFailure {
    native:Option<crate::host_clock::native_retained_close::RetainedCloseReport>,
    unclosed:Option<std::mem::ManuallyDrop<WindowsProtectedHead>>,
}
impl WindowsCloseFailure {
    pub(in crate::host_clock) fn description(&self)->String {
        match &self.native {Some(report)=>format!("{} original Windows lineage close outcomes remain uncertain",report.uncertain_count()),
            None=>"original Windows lineage close refused before effects; whole writer retained".into()}
    }
}
impl WindowsProtectedHead {
    #[cfg(test)]
    pub(in crate::host_clock) fn open_existing_test_placement(directory:&Path,
        owner_sid:&str,node_sid:&str)->Result<Self,StorageError> {
        installation_no_impersonation(directory)?;
        let token=Identity::new(directory)?;
        if owner_sid.is_empty() || owner_sid==node_sid || token.user_text!=owner_sid
            || owner_sid=="S-1-5-18" || owner_sid=="S-1-5-32-544" {return Err(access(directory));}
        let installer=TestPlacementAdministrator::exact(directory,owner_sid,node_sid)?;
        let native_sid=installer.native_sid(directory)?;
        let mut owner=native_sid.perform(|sid|WindowsStateDir::secure_ancestor(directory,false,Some(sid.pointer())))?;
        owner.test_installer=Some(installer);
        Self::from_owner(owner,owner_sid)
    }
    pub(in crate::host_clock) fn open_existing(directory:&Path,owner_sid:&str,node_sid:&str)
        ->Result<Self,StorageError> {
        installation_no_impersonation(directory)?;
        let token=Identity::new(directory)?;
        if owner_sid.is_empty() || owner_sid==node_sid || token.user_text!=owner_sid
            || owner_sid=="S-1-5-18" || owner_sid=="S-1-5-32-544" {
            return Err(access(directory));
        }
        // No create/ACL repair/fixture fallback/selection from environment.
        let owner=WindowsStateDir::secure_inner(directory,false)?;
        Self::from_owner(owner,owner_sid)
    }
    fn from_owner(owner:WindowsStateDir,owner_sid:&str)->Result<Self,StorageError> {
        let mut owner_custody=ConstructingOwner::prepare();owner_custody.capture(owner);
        let mut head_custody=ConstructingOwner::prepare();
        let path=owner_custody.get().path.join("clock-lineage.head");
        let owned_sid=owner_sid.to_owned();
        let mut head=owner_custody.get().file_guarded(&path,READ|WRITE,false)?.ok_or_else(||access(&path))?;
        let identity=head.validate(|file|{file.try_lock().map_err(|e|StorageError::Io(path.clone(),format!("protected lineage lock: {e}")))?;inspect(file,&path,false)})?;let original_head=head.pin();
        let mut original_ancestors=Vec::new();original_ancestors.try_reserve_exact(owner_custody.get()._handles.len())
            .map_err(|_|StorageError::Io(path.clone(),"original lineage ancestor pin allocation refused".into()))?;
        if owner_custody.get()._originals.len()!=owner_custody.get()._handles.len(){return Err(access(&path));}
        original_ancestors.extend_from_slice(&owner_custody.get()._originals);
        // No allocation/query occurs between these linear transfers and capture.
        head_custody.capture(Self{owner:owner_custody.publish(),head:Some(head.publish()),identity,
            owner_sid:owned_sid,path,frozen:false,journal:None,journal_identity:None,journal_scope:None,
            original_head,original_journal:None,original_ancestors});
        head_custody.get_mut().read_current()?;Ok(head_custody.publish())
    }    fn recheck(&self)->Result<(),StorageError> {
        installation_no_impersonation(&self.path)?;
        let identity=Identity::new(&self.path)?;
        if identity.user_text!=self.owner_sid {return Err(access(&self.path));}
        #[cfg(test)]
        let native_sid=self.owner.test_installer.as_ref()
            .map(|v|v.native_sid(&self.owner.path)).transpose()?;
        let mut prefix=PathBuf::new();let mut index=0;
        for component in self.owner.path.components() {
            prefix.push(component.as_os_str());
            if matches!(component,Component::Prefix(_)) {continue;}
            let held=self.owner._handles.get(index).ok_or_else(||access(&self.path))?;
            index+=1;
            let mut named=open(&prefix,READ_CONTROL,OPEN,None,true)?;
            let expected=named.validate(|named|{for object in [held,named]{
                check_volume(object,&prefix)?;
                #[cfg(test)] let installer=native_sid.as_ref().map(Local::pointer);
                #[cfg(not(test))] let installer=None;
                identity.check_inner(object,&prefix,prefix==self.owner.path,installer)?;
            }inspect(held,&prefix,true)})?;
            named.expect_same(&expected,&prefix,true)?;named.close_checked()?;

        }
        if index!=self.owner._handles.len() {return Err(access(&self.path));}
        let head=self.head.as_ref().ok_or_else(||access(&self.path))?;
        check_volume(head,&self.path)?;identity.check(head,&self.path,true)?;
        if inspect(head,&self.path,false)?!=self.identity {return Err(StorageError::Substituted(self.path.clone()));}
        let mut named=self.owner.file_guarded(&self.path,READ,false)?.ok_or_else(||access(&self.path))?;
        named.expect_same(&self.identity,&self.path,false)?;named.close_checked()?;
        if let Some(journal)=&self.journal {
            let path=self.owner.path.join("clock-operations.journal");
            check_volume(journal,&path)?;identity.check(journal,&path,true)?;
            let held=inspect(journal,&path,false)?;
            if self.journal_identity.as_ref()!=Some(&held) || held==self.identity {return Err(StorageError::Substituted(path));}
            let mut named=self.owner.file_guarded(&path,READ,false)?.ok_or_else(||access(&path))?;
            named.expect_same(&held,&path,false)?;named.close_checked()?;
        }
        #[cfg(test)]
        if let Some(sid)=native_sid{sid.close_checked()?;}
        Ok(())
    }
    /// Separate existing-only one-link held NTFS journal and lifetime writer
    /// lock. Missing history is never created, reset, truncated or imported.
    pub(in crate::host_clock) fn attach_existing_journal(&mut self,
        scope:&crate::host_clock::protected_clock_lineage_v1::Scope)->Result<(),StorageError> {
        self.attach_journal_inner(scope,false)
    }
    pub(in crate::host_clock) fn attach_for_exact_reconciliation(&mut self,
        scope:&crate::host_clock::protected_clock_lineage_v1::Scope)->Result<(),StorageError> {
        self.attach_journal_inner(scope,true)
    }
    fn attach_journal_inner(&mut self,
        scope:&crate::host_clock::protected_clock_lineage_v1::Scope,reconciliation:bool)->Result<(),StorageError> {
        self.recheck()?;
        let path=self.owner.path.join("clock-operations.journal");
        if self.journal.is_some() {return Err(access(&path));}
        let mut file=self.owner.file_guarded(&path,READ|WRITE,false)?.ok_or_else(||access(&path))?;
        let identity=file.validate(|file|{let identity=inspect(file,&path,false)?;
            if identity==self.identity{return Err(StorageError::Substituted(path.clone()));}
            file.try_lock().map_err(|e|StorageError::Io(path.clone(),format!("protected journal lock: {e}")))?;Ok(identity)})?;
        let original_journal=file.pin();let selected_scope=scope.clone();
        self.journal=Some(file.publish());self.journal_identity=Some(identity);self.original_journal=Some(original_journal);self.journal_scope=Some(selected_scope);
        let result=self.journal_status();
        match result {
            Ok(status) if status.pending.is_none()=>Ok(()),
            Ok(_)=>{self.frozen=true;
                if reconciliation {Ok(())} else {Err(StorageError::Io(path,"unresolved exact operation; startup frozen".into()))}},
            Err(error)=>{self.frozen=true;Err(error)},
        }
    }
    /// Existing protected record recovery, without qualification or a new
    /// logical reservation. Before/partial/foreign heads retain sticky freeze.
    /// Genuine installed/current selection checks must bracket this primitive.
    pub(in crate::host_clock) fn reconcile_pending_operation(&mut self,
        operation:&crate::host_clock::protected_clock_lineage_v1::Operation)->Result<Vec<u8>,StorageError> {
        use crate::host_clock::protected_clock_lineage_v1::DocumentaryEngine;
        self.frozen=true;
        let result=(|| {
            self.recheck()?;
            let status=self.journal_status()?;
            let plan=status.pending.ok_or_else(||access(&self.path))?;
            if plan.operation()!=operation {return Err(access(&self.path));}
            let observed=self.read_current()?;let completion=plan.completion_head();
            if observed==plan.intent_head() {
                self.durable_write_readback(&plan.intent_head())?;
                self.durable_write_readback(&completion)?;
            } else if observed==completion {
                self.durable_write_readback(&completion)?;
            } else {return Err(StorageError::Io(self.path.clone(),"before/partial/foreign head remains frozen".into()));}
            self.append_journal_frame(&plan.completion_frame())?;
            let status=self.journal_status()?;
            let reply=status.lookup(operation).map_err(|e|StorageError::Io(self.path.clone(),e))?
                .ok_or_else(||access(&self.path))?;
            let scope=self.journal_scope.as_ref().ok_or_else(||access(&self.path))?;
            let document=DocumentaryEngine::from_document(scope,&completion).map_err(|_|access(&self.path))?;
            if reply.sequence!=document.sequence() || reply.floor!=document.floor()
                || document.frozen() || self.read_current()?!=completion {return Err(access(&self.path));}
            self.recheck()?;Ok(completion)
        })();
        if result.is_ok(){self.frozen=false;}result
    }
    fn journal_status(&mut self)->Result<crate::host_clock::protected_clock_operation_journal::JournalStatus,StorageError> {
        self.recheck()?;
        let path=self.owner.path.join("clock-operations.journal");
        let scope=self.journal_scope.as_ref().ok_or_else(||access(&path))?.clone();
        let file=self.journal.as_mut().ok_or_else(||access(&path))?;
        let length=file.metadata().map_err(|e|io(&path,e))?.len();
        file.seek(SeekFrom::Start(0)).map_err(|e|io(&path,e))?;
        let status=crate::host_clock::protected_clock_operation_journal::scan(&scope,file,length)
            .map_err(|e|StorageError::Io(path.clone(),e))?;
        if file.metadata().map_err(|e|io(&path,e))?.len()!=length {return Err(StorageError::Substituted(path));}
        self.recheck()?;Ok(status)
    }
    pub(in crate::host_clock) fn operation_reply(&mut self,
        operation:&crate::host_clock::protected_clock_lineage_v1::Operation)
        ->Result<Option<crate::host_clock::protected_clock_operation_journal::JournalReply>,StorageError> {
        if self.frozen {return Err(access(&self.path));}
        self.journal_status()?.lookup(operation).map_err(|e|StorageError::Io(self.path.clone(),e))
    }
    pub(in crate::host_clock) fn operation_bounds(&mut self)->Result<(u64,u64),StorageError> {
        if self.frozen {return Err(access(&self.path));}
        let status=self.journal_status()?;
        if status.pending.is_some() {return Err(access(&self.path));}
        Ok((status.sequence,status.floor))
    }
    fn append_journal_frame(&mut self,raw:&[u8])->Result<(),StorageError> {
        let path=self.owner.path.join("clock-operations.journal");
        if raw.is_empty() || raw.len()>2*crate::host_clock::protected_clock_lineage_v1::SNAPSHOT_MAX+128 {
            return Err(access(&path));
        }
        self.recheck()?;
        let file=self.journal.as_mut().ok_or_else(||access(&path))?;
        let before=file.metadata().map_err(|e|io(&path,e))?.len();
        let after=before.checked_add(raw.len() as u64).ok_or_else(||access(&path))?;
        file.seek(SeekFrom::Start(before)).map_err(|e|io(&path,e))?;
        // Existing entries are never renamed. Held WRITE_THROUGH file plus
        // successful sync_all precedes exact same-handle length/data readback.
        // This supplies no physical power-loss or filesystem qualification.
        file.write_all(raw).map_err(|e|io(&path,e))?;
        file.sync_all().map_err(|e|io(&path,e))?;
        if file.metadata().map_err(|e|io(&path,e))?.len()!=after {return Err(StorageError::Substituted(path));}
        file.seek(SeekFrom::Start(before)).map_err(|e|io(&path,e))?;
        let mut observed=vec![0;raw.len()];file.read_exact(&mut observed).map_err(|e|io(&path,e))?;
        if observed!=raw {return Err(StorageError::Substituted(path));}
        let mut extra=[0];if file.read(&mut extra).map_err(|e|io(&path,e))?!=0 {return Err(StorageError::Substituted(path));}
        self.recheck()
    }
    pub(in crate::host_clock) fn execute_operation(&mut self,
        engine:&mut crate::host_clock::protected_clock_lineage_v1::DocumentaryEngine,
        request:crate::host_clock::protected_clock_lineage_v1::Request)->Result<Vec<u8>,StorageError> {
        if self.frozen {return Err(access(&self.path));}
        let transition=WindowsLineageTransition::begin(&mut self.frozen,engine);
        let result=self.execute_operation_inner(&mut *transition.engine,request);
        let result=transition.finish(result);
        if result.is_ok() {self.frozen=false;}
        result
    }
    // Only the guarded public wrapper enters this transition. The private
    // head helper stays under this SAME journal transition's frozen barrier.
    fn execute_operation_inner(&mut self,
        engine:&mut crate::host_clock::protected_clock_lineage_v1::DocumentaryEngine,
        request:crate::host_clock::protected_clock_lineage_v1::Request)->Result<Vec<u8>,StorageError> {
        use crate::host_clock::protected_clock_operation_journal::JournalPlan;
        let result=(|| {
            let operation=request.operation().ok_or_else(||access(&self.path))?;
            if self.journal_status()?.lookup(operation).map_err(|e|StorageError::Io(self.path.clone(),e))?
                .is_some() {return Err(access(&self.path));}
            let current=self.read_current()?;
            if current!=engine.current_document() {return Err(StorageError::Substituted(self.path.clone()));}
            let status=self.journal_status()?;
            if engine.sequence()<status.sequence || engine.floor()<status.floor {return Err(access(&self.path));}
            let scope=self.journal_scope.as_ref().ok_or_else(||access(&self.path))?;
            let plan=JournalPlan::from_current(scope,&current,request.clone()).map_err(|e|StorageError::Io(self.path.clone(),e))?;
            // Durable identity+content intent BEFORE local head transition;
            // durable matching completion BEFORE exposing a logical outcome.
            self.append_journal_frame(&plan.intent_frame())?;
            let observed=self.execute_inner(engine,request)?;
            if observed!=plan.completion_head() {return Err(access(&self.path));}
            self.append_journal_frame(&plan.completion_frame())?;
            let status=self.journal_status()?;
            let reply=status.lookup(plan.operation()).map_err(|e|StorageError::Io(self.path.clone(),e))?
                .ok_or_else(||access(&self.path))?;
            if reply.sequence!=engine.sequence() || reply.floor!=engine.floor() {return Err(access(&self.path));}
            self.recheck()?;Ok(observed)
        })();
        result
    }
    pub(in crate::host_clock) fn replacement_observation(&mut self)
        ->Result<crate::host_clock::protected_clock_owner::NativeLineageObservation,String> {
        self.recheck().map_err(|e|e.to_string())?;
        let head=self.read_current().map_err(|e|e.to_string())?;
        let mut ancestors=Vec::new();ancestors.try_reserve_exact(self.original_ancestors.len())
            .map_err(|_|"replacement ancestry allocation")?;
        ancestors.extend_from_slice(&self.original_ancestors);
        let observation=crate::host_clock::protected_clock_owner::NativeLineageObservation::observed(self.original_head,
            self.original_journal.ok_or("replacement journal original pin absent")?,ancestors,
            self.journal.as_mut().ok_or("replacement journal absent")?,head)?;
        self.recheck().map_err(|e|e.to_string())?;Ok(observation)
    }
    pub(in crate::host_clock) fn read_current(&mut self)->Result<Vec<u8>,StorageError> {
        self.recheck()?;
        let head=self.head.as_mut().ok_or_else(||access(&self.path))?;
        let length=head.metadata().map_err(|e|io(&self.path,e))?.len();
        let bound=crate::host_clock::protected_clock_lineage_v1::SNAPSHOT_MAX;
        if length==0 || length>bound as u64 {return Err(access(&self.path));}
        head.seek(SeekFrom::Start(0)).map_err(|e|io(&self.path,e))?;
        let mut raw=vec![0;length as usize];head.read_exact(&mut raw).map_err(|e|io(&self.path,e))?;
        let mut extra=[0];if head.read(&mut extra).map_err(|e|io(&self.path,e))?!=0 {return Err(access(&self.path));}
        self.recheck()?;Ok(raw)
    }
    fn durable_write_readback(&mut self,raw:&[u8])->Result<Vec<u8>,StorageError> {
        if raw.is_empty() || raw.len()>crate::host_clock::protected_clock_lineage_v1::SNAPSHOT_MAX {
            return Err(access(&self.path));
        }
        self.recheck()?;
        let head=self.head.as_mut().ok_or_else(||access(&self.path))?;
        // Installed directory entries and head file identity are retained
        // without DELETE sharing. This route never creates or renames a name.
        // Writes use the held FILE_FLAG_WRITE_THROUGH object and file flush;
        // no directory-entry durability claim transfers from a rename backend.
        head.seek(SeekFrom::Start(0)).map_err(|e|io(&self.path,e))?;
        head.write_all(raw).map_err(|e|io(&self.path,e))?;
        head.set_len(raw.len() as u64).map_err(|e|io(&self.path,e))?;
        head.sync_all().map_err(|e|io(&self.path,e))?;
        let observed=self.read_current()?;
        if observed!=raw {return Err(StorageError::Substituted(self.path.clone()));}
        Ok(observed)
    }
    pub(in crate::host_clock) fn execute(&mut self,
        engine:&mut crate::host_clock::protected_clock_lineage_v1::DocumentaryEngine,
        request:crate::host_clock::protected_clock_lineage_v1::Request)->Result<Vec<u8>,StorageError> {
        if self.frozen {return Err(access(&self.path));}
        let transition=WindowsLineageTransition::begin(&mut self.frozen,engine);
        let result=self.execute_inner(&mut *transition.engine,request);
        let result=transition.finish(result);
        if result.is_ok() {self.frozen=false;}
        result
    }
    // Private helper: public entry points arm revocation before any read/write.
    fn execute_inner(&mut self,
        engine:&mut crate::host_clock::protected_clock_lineage_v1::DocumentaryEngine,
        request:crate::host_clock::protected_clock_lineage_v1::Request)->Result<Vec<u8>,StorageError> {
        use crate::host_clock::protected_clock_lineage_v1::Begin;
        let result=(|| {
            if self.read_current()?!=engine.current_document() {return Err(access(&self.path));}
            match engine.begin(request).map_err(|_|access(&self.path))? {
                Begin::ExactLastRetry(snapshot)=>{
                    if self.read_current()?!=snapshot.encode() {return Err(access(&self.path));}
                    Ok(snapshot.encode())
                },
                Begin::Plan(plan)=>{
                    let intent=self.durable_write_readback(&plan.intent())?;
                    engine.intent_readback(&intent).map_err(|_|access(&self.path))?;
                    let completion=self.durable_write_readback(&plan.completion())?;
                    engine.completion_readback(&completion).map_err(|_|access(&self.path))?;
                    self.recheck()?;Ok(completion)
                },
            }
        })();
        result
    }
    pub(in crate::host_clock) fn close(mut self)->Result<(),WindowsCloseFailure> {
        if self.head.is_none() || self.journal.is_some()!=self.original_journal.is_some()
            || self.owner._handles.len()!=self.original_ancestors.len() {
            return Err(WindowsCloseFailure{native:None,unclosed:Some(std::mem::ManuallyDrop::new(self))});
        }
        let count=match self.owner._handles.len().checked_add(1+usize::from(self.journal.is_some())) {
            Some(count)=>count,None=>return Err(WindowsCloseFailure{native:None,unclosed:Some(std::mem::ManuallyDrop::new(self))})};
        let mut report=match crate::host_clock::native_retained_close::RetainedCloseReport::prepare(count) {
            Ok(report)=>report,Err(_)=>return Err(WindowsCloseFailure{native:None,unclosed:Some(std::mem::ManuallyDrop::new(self))})};
        if let Some(journal)=self.journal.take(){report.file(journal,self.original_journal.expect("original journal pin"));}
        report.file(self.head.take().expect("original live head"),self.original_head);
        for (file,pin) in self.owner._handles.drain(..).zip(self.original_ancestors.drain(..)).rev(){report.file(file,pin);}
        if report.retained_handles_closed(){Ok(())}else{Err(WindowsCloseFailure{native:Some(report),unclosed:None})}
    }
}

// Only the exact native TEST child can request abrupt exit; no production environment hook.
#[cfg(test)]
mod lineage_transition_tests {
    use super::*;
    use crate::host_clock::protected_clock_lineage_v1::{Begin,DocumentaryEngine,Error,Request,Scope};
    // Pure canonical documentary fixture. No native writer/object/issuer is
    // fabricated, and these controls grant no storage/Clock qualification.
    fn modeled_engine()->DocumentaryEngine {
        let scope=Scope::selected_document([1;32],[2;32],[3;32],[4;32]);
        let mut raw=b"MCLC4D01".to_vec();
        for byte in [1u8,2,3,4] {raw.extend_from_slice(&[byte;32]);}
        raw.extend_from_slice(&0u64.to_be_bytes());
        raw.extend_from_slice(&0u64.to_be_bytes());
        raw.push(0);raw.extend_from_slice(&0u16.to_be_bytes());
        DocumentaryEngine::from_document(&scope,&raw).unwrap()
    }
    #[test]
    fn documentary_refusal_before_effects_revokes_same_engine() {
        let mut engine=modeled_engine();let mut frozen=false;
        let transition=WindowsLineageTransition::begin(&mut frozen,&mut engine);
        assert!(frozen);
        let result=transition.finish(Err(access(Path::new("PUBLIC modeled refusal"))));
        assert!(result.is_err() && frozen && engine.frozen());
        assert!(matches!(engine.begin(Request::invalidate_engine_floor(0,9)),Err(Error::Frozen)));
    }
    #[test]
    fn documentary_unwind_after_intent_revokes_readback_and_preserves_plan() {
        let mut engine=modeled_engine();let mut frozen=false;
        let mut completion=None;
        let failed=std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let transition=WindowsLineageTransition::begin(&mut frozen,&mut engine);
            let plan=match transition.engine.begin(Request::invalidate_engine_floor(0,9)).unwrap() {
                Begin::Plan(plan)=>plan,_=>panic!("new modeled plan required"),
            };
            transition.engine.intent_readback(&plan.intent()).unwrap();
            completion=Some(plan.completion());
            panic!("PUBLIC modeled transition unwind");
        }));
        assert!(failed.is_err() && frozen && engine.frozen());
        assert!(matches!(engine.completion_readback(&completion.unwrap()),Err(Error::IntentNotReadBack)));
        assert!(matches!(engine.begin(Request::invalidate_engine_floor(0,9)),Err(Error::Frozen)));
    }
    #[test]
    fn documentary_verified_completion_does_not_revoke_same_engine() {
        let mut engine=modeled_engine();let mut frozen=false;
        let transition=WindowsLineageTransition::begin(&mut frozen,&mut engine);
        let plan=match transition.engine.begin(Request::invalidate_engine_floor(0,9)).unwrap() {
            Begin::Plan(plan)=>plan,_=>panic!("new modeled plan required"),
        };
        transition.engine.intent_readback(&plan.intent()).unwrap();
        transition.engine.completion_readback(&plan.completion()).unwrap();
        let expected=plan.completion();
        let result=transition.finish(Ok(expected.clone()));
        // The actual wrapper performs this assignment only after finish Ok.
        if result.is_ok() {frozen=false;}
        assert_eq!(result.unwrap(),expected);
        assert!(!frozen && !engine.frozen());
        assert_eq!(engine.sequence(),1);assert_eq!(engine.floor(),9);
    }
}
#[cfg(test)]
fn crash(point: u8) {
    if std::env::var("MUTINY_CLOCK_STORAGE_TEST_CHILD").as_deref() == Ok("crash")
        && std::env::var("MUTINY_CLOCK_STORAGE_TEST_POINT")
            .ok()
            .and_then(|s| s.parse().ok())
            == Some(point)
    {
        std::process::exit(75);
    }
}
#[cfg(test)]
std::thread_local! { static BETWEEN_MUTATION_OPEN: std::cell::Cell<Option<fn(&Path)>> = const { std::cell::Cell::new(None) }; }
#[cfg(test)]
std::thread_local! { static BETWEEN_DIRECTORY_PIN_AND_REOPEN: std::cell::Cell<Option<fn(&Path)>> = const { std::cell::Cell::new(None) }; }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host_clock::{
        anchor_store::{AnchorStore, LoadOutcome, Refusal},
        state_dir::ClockStateDir,
    };
    use std::{
        process::{Child, Command},
        time::{Duration, Instant},
    };
    const CHILD: &str = "host_clock::state_dir::windows_storage::tests::native_child";
    struct OwnedChild(Child);
    impl std::ops::Deref for OwnedChild {
        type Target = Child;
        fn deref(&self) -> &Child {
            &self.0
        }
    }
    impl std::ops::DerefMut for OwnedChild {
        fn deref_mut(&mut self) -> &mut Child {
            &mut self.0
        }
    }
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if self.0.try_wait().ok().flatten().is_none() {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
    }
    fn base(tag: &str) -> PathBuf {
        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt).unwrap();
        let dir = std::env::temp_dir().join(format!(
            "build8-clock-windows-{tag}-{}-{}",
            std::process::id(),
            hex::encode(salt)
        ));
        assert!(!dir.exists());
        drop(WindowsStateDir::secure(&dir).unwrap());
        eprintln!(
            "retained native Windows clock TEST fixture {}",
            dir.display()
        );
        dir
    }
    fn child(path: &Path, mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([CHILD, "--exact", "--nocapture"])
            .env("MUTINY_CLOCK_STORAGE_TEST_CHILD", mode)
            .env("MUTINY_CLOCK_STORAGE_TEST_PATH", path);
        command
    }
    fn ready(child: &mut Child, path: &Path) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !path.exists() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "child exited before native storage readiness"
            );
            assert!(Instant::now() < deadline, "native child timed out");
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    #[test]
    fn native_child() {
        let Ok(mode) = std::env::var("MUTINY_CLOCK_STORAGE_TEST_CHILD") else {
            return;
        };
        let path = PathBuf::from(std::env::var_os("MUTINY_CLOCK_STORAGE_TEST_PATH").unwrap());
        match mode.as_str() {
            "locked" => assert!(matches!(
                ClockStateDir::open(&path),
                Err(StorageError::Locked(_))
            )),
            "holder" => {
                let _state = ClockStateDir::open(&path).unwrap();
                std::fs::write(
                    path.with_extension("ready"),
                    b"PUBLIC TEST native lock held",
                )
                .unwrap();
                loop {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            "idle" => {
                std::fs::write(
                    path.with_extension("ready"),
                    b"PUBLIC TEST child without opener",
                )
                .unwrap();
                loop {
                    std::thread::sleep(Duration::from_millis(100));
                }
            }
            "contend" => {
                let index = std::env::var("MUTINY_CLOCK_STORAGE_TEST_INDEX").unwrap();
                let root = path.parent().unwrap().parent().unwrap();
                std::fs::write(root.join(format!("ready-{index}")), b"PUBLIC TEST ready").unwrap();
                let deadline = Instant::now() + Duration::from_secs(10);
                while !root.join("gate").exists() {
                    assert!(Instant::now() < deadline);
                    std::thread::sleep(Duration::from_millis(2));
                }
                let opened = ClockStateDir::open(&path);
                let result = match &opened {
                    Ok(_) => "winner",
                    Err(StorageError::Locked(_)) => "locked",
                    Err(e) => panic!("unexpected checked storage race refusal: {e}"),
                };
                std::fs::write(root.join(format!("result-{index}")), result).unwrap();
                while !root.join("release").exists() {
                    assert!(Instant::now() < deadline);
                    std::thread::sleep(Duration::from_millis(2));
                }
                drop(opened);
            }
            "crash" => {
                let state = ClockStateDir::open(&path).unwrap();
                state
                    .windows
                    .as_ref()
                    .unwrap()
                    .write(&path, b"complete PUBLIC TEST replacement")
                    .unwrap();
                panic!("requested native crash point was not reached");
            }
            _ => panic!("unknown native TEST child mode"),
        }
    }
    #[test]
    fn c8_windows_safe_creation_handle_identity_and_native_store_bytes() {
        let root = base("positive");
        let path = root.join("state").join("clock.anchor");
        let state = ClockStateDir::open(&path).unwrap();
        let backend = state.windows.as_ref().unwrap();
        backend
            .write(&path, b"first complete PUBLIC TEST record")
            .unwrap();
        backend
            .write(&path, b"second complete PUBLIC TEST record")
            .unwrap();
        assert_eq!(
            backend.read(&path, 4096).unwrap().unwrap(),
            b"second complete PUBLIC TEST record"
        );
        assert!(
            std::fs::rename(path.parent().unwrap(), root.join("moved-state")).is_err(),
            "verified directory pinned"
        );
        assert!(child(&path, "locked").status().unwrap().success());
        let slash = PathBuf::from(path.to_string_lossy().replace('\\', "/"));
        assert!(
            child(&slash, "locked").status().unwrap().success(),
            "ordinary absolute slash spelling resolves the same protected native lock"
        );
        let identity = Identity::new(&path).unwrap();
        identity
            .check(
                &backend.file(&path, READ, false).unwrap().unwrap(),
                &path,
                true,
            )
            .unwrap();
        drop(state);
        let (_store, loaded) = AnchorStore::open(ClockStateDir::open(&path).unwrap());
        assert!(matches!(
            loaded.outcome,
            LoadOutcome::Refused(Refusal::Format(_))
        ));
        assert!(!AnchorStore::GRANTS_RESTART_QUALIFICATION);
    }
    #[test]
    fn c8_windows_existing_unsafe_leaf_unchanged_and_no_lock_created() {
        let root = base("unsafe-leaf");
        let dir = root.join("unsafe");
        std::fs::create_dir(&dir).unwrap();
        // Default inherited grants intentionally differ from the protected explicit policy.
        let handle = open(&dir, READ_CONTROL, OPEN, None, true).unwrap();
        let before = security_snapshot(&handle);
        let path = dir.join("clock.anchor");
        assert!(ClockStateDir::open(&path).is_err());
        assert_eq!(security_snapshot(&handle), before);
        assert!(!super::super::sibling(&path, ".lock").exists());
    }
    fn security_snapshot(file: &File) -> Vec<u8> {
        unsafe {
            let mut allocation=Local::prepare(Path::new("TEST security snapshot"),Vec::new()); let mut sd = null_mut();
            let mut owner = null_mut();
            let mut acl = null_mut();
            let observed=GetSecurityInfo(file.as_raw_handle(),1,1|4,&mut owner,null_mut(),&mut acl,null_mut(),&mut sd);
            allocation.external_result(sd,observed);assert_eq!(observed,0);
            let mut bytes =
                std::slice::from_raw_parts(owner.cast::<u8>(), GetLengthSid(owner) as usize)
                    .to_vec();
            if !acl.is_null() {
                bytes.extend_from_slice(std::slice::from_raw_parts(
                    acl.cast::<u8>(),
                    usize::from((*acl).size),
                ));
            }
            let mut control = 0;
            let mut revision = 0;
            assert_ne!(
                GetSecurityDescriptorControl(sd, &mut control, &mut revision),
                0
            );
            bytes.extend_from_slice(&control.to_le_bytes());
            allocation.perform(|_|Ok(bytes)).unwrap()
        }
    }
    fn directory_descriptor(path: &Path, descriptor: &str) {
        assert!(!path.exists());
        let allocation=Local::descriptor(path,text(descriptor)).unwrap();
        allocation.perform(|allocation|allocation.directory_create(path,false)).unwrap();
    }
    #[test]
    fn c8_windows_delete_child_null_dacl_foreign_grants_and_owner_refuse_unchanged() {
        let root = base("acl-negatives");
        let identity = Identity::new(&root).unwrap();
        for (tag, descriptor, ancestor) in [
            (
                "delete-child",
                format!(
                    "O:{}D:P(A;;FA;;;SY)(A;;FA;;;{})(A;;0x40;;;AU)",
                    identity.user_text, identity.user_text
                ),
                true,
            ),
            (
                "null-dacl",
                format!("O:{}D:NO_ACCESS_CONTROL", identity.user_text),
                false,
            ),
            (
                "foreign-read",
                format!(
                    "O:{}D:P(A;;FA;;;SY)(A;;FA;;;{})(A;;FR;;;AU)",
                    identity.user_text, identity.user_text
                ),
                false,
            ),
        ] {
            let dir = root.join(tag);
            directory_descriptor(&dir, &descriptor);
            let handle = open(&dir, READ_CONTROL, OPEN, None, true).unwrap();
            let before = security_snapshot(&handle);
            let leaf = if ancestor {
                dir.join("must-not-be-created")
            } else {
                dir.clone()
            };
            assert!(
                ClockStateDir::open(&leaf.join("clock.anchor")).is_err(),
                "{tag}"
            );
            assert_eq!(
                security_snapshot(&handle),
                before,
                "unsafe ACL/owner was not repaired: {tag}"
            );
            if ancestor {
                assert!(!leaf.exists());
            }
            assert!(!leaf.join("clock.anchor.lock").exists());
        }
        // No restore/elevation privilege is requested to manufacture a foreign owner. Verify
        // the actual SYSTEM-owned Users directory read-only; refusal precedes any lock creation
        // or entry read. No ACL, ownership or contents are modified on this existing path.
        let users = std::env::var_os("SystemDrive")
            .map(PathBuf::from)
            .unwrap()
            .join("\\Users");
        let handle = open(&users, READ_CONTROL, OPEN, None, true).unwrap();
        let before = security_snapshot(&handle);
        // Keep the owner mutation probe read-only: it must fail here before production open
        // could attempt any lock creation under this existing foreign-owned directory.
        assert_eq!(
            identity.check(&handle, &users, true).unwrap_err(),
            StorageError::NotOwner(users.clone())
        );
        let anchor = users.join(format!(
            "build8-must-not-create-clock-{}.anchor",
            std::process::id()
        ));
        assert!(!anchor.exists() && !super::super::sibling(&anchor, ".lock").exists());
        assert_eq!(
            ClockStateDir::open(&anchor).unwrap_err(),
            StorageError::NotOwner(users.clone())
        );
        assert_eq!(security_snapshot(&handle), before);
        assert!(!anchor.exists() && !super::super::sibling(&anchor, ".lock").exists());
    }
    #[test]
    fn c8_windows_actual_file_id_detects_mutation_open_substitution() {
        fn substitute(path: &Path) {
            std::fs::rename(path, path.with_extension("swapped-evidence")).unwrap();
            let identity = Identity::new(path).unwrap();
            let sd = identity.descriptor(path, false).unwrap();
            let mut file=sd.perform(|allocation|open(path,READ_CONTROL|READ|WRITE,NEW,Some(allocation),false)).unwrap();
            file.write_all(b"other complete PUBLIC TEST candidate")
                .unwrap();
            file.sync_all().unwrap(); file.close_checked().unwrap();
        }
        let root = base("file-swap");
        let path = root.join("state").join("clock.anchor");
        let state = ClockStateDir::open(&path).unwrap();
        let backend = state.windows.as_ref().unwrap();
        backend
            .write(&path, b"original complete PUBLIC TEST candidate")
            .unwrap();
        BETWEEN_MUTATION_OPEN.with(|hook| hook.set(Some(substitute)));
        assert_eq!(
            backend.remove(&path).unwrap_err(),
            StorageError::Substituted(path.clone())
        );
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"other complete PUBLIC TEST candidate"
        );
        assert_eq!(
            std::fs::read(path.with_extension("swapped-evidence")).unwrap(),
            b"original complete PUBLIC TEST candidate"
        );
    }
    #[test]
    fn c8_windows_directory_identity_boundary_pins_before_named_reopen() {
        fn attempt(dir: &Path) {
            assert!(
                std::fs::rename(dir, dir.with_extension("swap-evidence")).is_err(),
                "checked native directory handle denies DELETE sharing before reopen"
            );
        }
        let root = base("directory-boundary");
        let dir = root.join("state");
        drop(WindowsStateDir::secure(&dir).unwrap());
        BETWEEN_DIRECTORY_PIN_AND_REOPEN.with(|hook| hook.set(Some(attempt)));
        let opened = ClockStateDir::open(&dir.join("clock.anchor")).unwrap();
        assert!(opened.windows.is_some());
        assert!(!dir.with_extension("swap-evidence").exists());
    }
    #[test]
    fn c8_windows_directory_chain_remains_pinned_without_an_open_lock_file() {
        let root = base("directory-lifetime");
        let dir = root.join("state");
        let moved = root.join("retained-moved-state");
        let backend = WindowsStateDir::secure(&dir).unwrap();
        assert!(
            std::fs::rename(&dir, &moved).is_err(),
            "native directory lifetime pin must hold even when no child lock file exists"
        );
        assert!(dir.exists() && !moved.exists());
        drop(backend);
        std::fs::rename(&dir, &moved).unwrap();
        assert!(!dir.exists() && moved.exists());
        eprintln!(
            "retained native directory lifetime PUBLIC TEST fixture {}",
            root.display()
        );
    }
    #[test]
    fn c12_windows_concurrent_process_creation_and_actual_case_alias_share_one_lock() {
        let root = base("process-race");
        let path = root.join("state").join("clock.anchor");
        let mut children: Vec<_> = (0..4)
            .map(|index| {
                OwnedChild(
                    child(&path, "contend")
                        .env("MUTINY_CLOCK_STORAGE_TEST_INDEX", index.to_string())
                        .spawn()
                        .unwrap(),
                )
            })
            .collect();
        for (index, process) in children.iter_mut().enumerate() {
            ready(process, &root.join(format!("ready-{index}")));
        }
        std::fs::write(root.join("gate"), b"PUBLIC TEST simultaneous native opens").unwrap();
        for (index, process) in children.iter_mut().enumerate() {
            ready(process, &root.join(format!("result-{index}")));
        }
        let winners = (0..4)
            .filter(|index| {
                std::fs::read(root.join(format!("result-{index}"))).unwrap() == b"winner"
            })
            .count();
        assert_eq!(winners, 1);
        assert!(
            child(&path.with_file_name("CLOCK.ANCHOR"), "locked")
                .status()
                .unwrap()
                .success(),
            "actual native case alias cannot get a second lock"
        );
        std::fs::write(root.join("release"), b"PUBLIC TEST release owned processes").unwrap();
        for process in &mut children {
            assert!(process.wait().unwrap().success());
        }
        assert!(ClockStateDir::open(&path).is_ok());
    }
    fn record(sequence: u64) -> mutiny_consensus_v8::holdover_clock_v1::PersistedAnchor {
        use mutiny_consensus_v8::holdover_clock_v1::{
            ClockProfile, ControlledElapsed, HoldoverClock, LeapView, SourceSample,
        };
        let profile = ClockProfile {
            max_source_uncertainty_ms: 248,
            max_calibration_half_width_ms: 250,
            min_sources: 1,
            max_faulty_sources: 0,
            drift_bound_ppb: 8680,
            max_holdover_ms: 86_400_000,
            max_interval_half_width_ms: 1000,
            max_suspend_gap_ms: 50,
            confirm_calibrations: 1,
        };
        let elapsed = ControlledElapsed::start(5);
        let clock = HoldoverClock::new(profile, elapsed.clone()).unwrap();
        clock.set_leap_view(LeapView::Clear {
            valid_until_ms: u64::MAX,
        });
        clock
            .calibrate(&[SourceSample {
                source: "PUBLIC TEST controlled source".into(),
                authenticated: true,
                utc_ms: 1_790_899_300_000,
                uncertainty_ms: 13,
                at: elapsed.now(),
            }])
            .unwrap();
        clock.persisted(sequence, 1).unwrap()
    }
    #[test]
    fn c5_windows_native_store_commit_failed_unlink_and_same_boot_restart_never_qualify() {
        use crate::host_clock::anchor_store::StoreCondition;
        let root = base("store-lifecycle");
        let path = root.join("state").join("clock.anchor");
        let (mut store, loaded) = AnchorStore::open(ClockStateDir::open(&path).unwrap());
        assert_eq!(loaded.outcome, LoadOutcome::Empty);
        store.commit(&record(1)).unwrap();
        let backend = WindowsStateDir::secure(path.parent().unwrap()).unwrap();
        let mark = super::super::sibling(&path, ".seq");
        let held_mark = backend.file(&mark, READ, false).unwrap().unwrap();
        assert!(
            store.commit(&record(2)).is_err(),
            "native target sharing refuses mark replacement"
        );
        assert_eq!(store.condition(), StoreCondition::NoLiveRecord);
        assert!(
            !path.exists(),
            "failed mark publication invalidates the possibly stale record"
        );
        drop(held_mark);
        store.commit(&record(3)).unwrap();
        let held = backend.file(&path, READ, false).unwrap().unwrap(); // native no DELETE sharing
        assert!(store.invalidate(42).is_err());
        assert_eq!(store.condition(), StoreCondition::StaleNotInvalidated);
        assert_eq!(std::fs::read(&path).unwrap(), record(3).encode());
        drop(held);
        store.fail_closed();
        assert_eq!(store.condition(), StoreCondition::NoLiveRecord);
        assert!(!path.exists());
        store.commit(&record(store.next_sequence())).unwrap();
        drop(store);
        let (store, loaded) = AnchorStore::open(ClockStateDir::open(&path).unwrap());
        assert!(matches!(loaded.outcome, LoadOutcome::Record(_)));
        assert!(!AnchorStore::GRANTS_RESTART_QUALIFICATION);
        drop(store);
        let state = ClockStateDir::open(&path).unwrap();
        state
            .windows
            .as_ref()
            .unwrap()
            .write(
                &path,
                &crate::host_clock::anchor_store::legacy_v1_bytes([1; 32], 10, 20, 30),
            )
            .unwrap();
        let (_store, loaded) = AnchorStore::open(state);
        assert!(matches!(
            loaded.outcome,
            LoadOutcome::Refused(Refusal::Legacy(_))
        ));
    }
    #[test]
    fn c8_windows_hardlinks_and_reparse_leaf_are_refused_without_reading() {
        let root = base("aliases");
        let path = root.join("state").join("clock.anchor");
        let state = ClockStateDir::open(&path).unwrap();
        state
            .windows
            .as_ref()
            .unwrap()
            .write(&path, b"PUBLIC TEST alias candidate")
            .unwrap();
        drop(state);
        let alias = root.join("hardlink-evidence");
        std::fs::hard_link(&path, &alias).unwrap();
        assert!(ClockStateDir::open(&path).is_err());
        assert_eq!(
            std::fs::read(&alias).unwrap(),
            b"PUBLIC TEST alias candidate"
        );
        // Reparse creation is a required platform test input, never silently skipped.
        let link = root.join("linked-state");
        // The current token cannot create symbolic links (retained native error1314). Seed a
        // Microsoft mount-point reparse in a NEW owned directory, with no privilege changes.
        std::fs::create_dir(&link).unwrap();
        let handle = open(&link, READ_CONTROL | WRITE, OPEN, None, true).unwrap();
        let mut substitute = std::ffi::OsString::from("\\??\\");
        substitute.push(path.parent().unwrap());
        let substitute = wide(&substitute);
        let print = wide(path.parent().unwrap().as_os_str());
        let bytes = (substitute.len() + print.len()) * 2;
        let mut buffer = vec![0u32; (16 + bytes).div_ceil(4)];
        let raw = buffer.as_mut_ptr().cast::<u8>();
        unsafe {
            raw.cast::<u32>().write(0xa0000003);
            raw.add(4).cast::<u16>().write((8 + bytes) as u16);
            raw.add(8).cast::<u16>().write(0);
            raw.add(10)
                .cast::<u16>()
                .write(((substitute.len() - 1) * 2) as u16);
            raw.add(12)
                .cast::<u16>()
                .write((substitute.len() * 2) as u16);
            raw.add(14)
                .cast::<u16>()
                .write(((print.len() - 1) * 2) as u16);
            std::ptr::copy_nonoverlapping(
                substitute.as_ptr(),
                raw.add(16).cast::<u16>(),
                substitute.len(),
            );
            std::ptr::copy_nonoverlapping(
                print.as_ptr(),
                raw.add(16 + substitute.len() * 2).cast::<u16>(),
                print.len(),
            );
            let mut returned = 0;
            assert_ne!(
                DeviceIoControl(
                    handle.as_raw_handle(),
                    0x900a4,
                    raw.cast(),
                    (16 + bytes) as u32,
                    null_mut(),
                    0,
                    &mut returned,
                    null_mut()
                ),
                0,
                "actual new mount-point reparse seed: {:?}",
                std::io::Error::last_os_error()
            );
        }
        drop(handle);
        assert!(ClockStateDir::open(&link.join("clock.anchor")).is_err());
    }
    #[test]
    fn c12_windows_abrupt_holder_exit_releases_lock_and_child_does_not_inherit_chain() {
        let root = base("process");
        let path = root.join("state").join("clock.anchor");
        let mut holder = OwnedChild(child(&path, "holder").spawn().unwrap());
        ready(&mut holder, &path.with_extension("ready"));
        let competing = ClockStateDir::open(&path);
        let actual = match &competing {
            Ok(_) => "Ok(ACCEPTED)".to_owned(),
            Err(error) => format!("Err({error:?})"),
        };
        eprintln!("normal Windows lifetime lock competing open: {actual}");
        assert!(
            matches!(&competing, Err(StorageError::Locked(_))),
            "normal backend lock must refuse concurrent open; actual {actual}"
        );
        holder.kill().unwrap();
        holder.wait().unwrap();
        let state = ClockStateDir::open(&path).unwrap();
        let idle_path = root.join("idle.anchor");
        let mut idle = OwnedChild(child(&idle_path, "idle").spawn().unwrap());
        ready(&mut idle, &idle_path.with_extension("ready"));
        drop(state);
        assert!(
            ClockStateDir::open(&path).is_ok(),
            "idle child did not inherit lock"
        );
        assert!(
            std::fs::rename(path.parent().unwrap(), root.join("moved-state")).is_ok(),
            "idle child did not inherit directory pin"
        );
        idle.kill().unwrap();
        idle.wait().unwrap();
    }
    #[test]
    fn c5_windows_native_crash_boundaries_retain_partial_temp_and_fail_closed_records() {
        for point in [1, 2, 3] {
            let root = base(&format!("crash-{point}"));
            let path = root.join("state").join("clock.anchor");
            let state = ClockStateDir::open(&path).unwrap();
            state
                .windows
                .as_ref()
                .unwrap()
                .write(&path, b"old complete PUBLIC TEST record")
                .unwrap();
            drop(state);
            let status = child(&path, "crash")
                .env("MUTINY_CLOCK_STORAGE_TEST_POINT", point.to_string())
                .status()
                .unwrap();
            assert_eq!(status.code(), Some(75), "actual abrupt native child exit");
            let state = ClockStateDir::open(&path).unwrap();
            let expected = if point < 3 {
                b"old complete PUBLIC TEST record".as_slice()
            } else {
                b"complete PUBLIC TEST replacement".as_slice()
            };
            assert_eq!(
                state
                    .windows
                    .as_ref()
                    .unwrap()
                    .read(&path, 4096)
                    .unwrap()
                    .unwrap(),
                expected
            );
            if point < 3 {
                let tmp = super::super::sibling(&path, ".tmp");
                let partial = std::fs::read(&tmp).unwrap();
                state
                    .windows
                    .as_ref()
                    .unwrap()
                    .write(&path, b"retry complete PUBLIC TEST record")
                    .unwrap();
                let retained: Vec<_> = std::fs::read_dir(path.parent().unwrap())
                    .unwrap()
                    .map(|e| e.unwrap().path())
                    .filter(|p| {
                        p.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .contains(".tmp.evidence-")
                    })
                    .collect();
                assert_eq!(retained.len(), 1);
                assert_eq!(std::fs::read(&retained[0]).unwrap(), partial);
            }
            let (_store, loaded) = AnchorStore::open(state);
            assert!(matches!(loaded.outcome, LoadOutcome::Refused(_)));
            assert!(!AnchorStore::GRANTS_RESTART_QUALIFICATION);
        }
    }
}
