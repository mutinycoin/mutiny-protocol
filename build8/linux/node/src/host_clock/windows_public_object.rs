//! Shared existing-only Windows public-object mechanics, without role authority.
//! Original native reader/validators and custody are moved from reviewed Clock117.
//! Clock and distinct counter issuers retain their own selection/canonical scopes.
#![cfg(windows)]
use super::storage_error::{StorageError,io};
use std::{ffi::c_void,fs::File,io::{Read,Seek,SeekFrom},mem::size_of,
    os::windows::{ffi::OsStrExt,io::{AsRawHandle,FromRawHandle}},
    path::{Component,Path,PathBuf,Prefix},ptr::{null,null_mut}};
type Ptr=*mut c_void;
const READ_CONTROL:u32=0x20000;
const READ:u32=0x80000000;
const OPEN:u32=3;
const NO_FOLLOW:u32=0x00200000;
const BACKUP:u32=0x02000000;
#[repr(C)]
struct SecurityAttributes{length:u32,descriptor:Ptr,inherit:i32}
#[link(name="kernel32")]
unsafe extern "system" {
    fn CreateFileW(name:*const u16,access:u32,share:u32,security:*const SecurityAttributes,
        disposition:u32,flags:u32,template:Ptr)->Ptr;
    fn GetHandleInformation(handle:Ptr,flags:*mut u32)->i32;
    fn GetFileInformationByHandle(handle:Ptr,information:*mut u32)->i32;
    fn GetFileInformationByHandleEx(handle:Ptr,kind:u32,information:Ptr,length:u32)->i32;
    fn GetVolumeInformationByHandleW(handle:Ptr,name:*mut u16,length:u32,serial:*mut u32,
        component:*mut u32,flags:*mut u32,fs:*mut u16,fs_length:u32)->i32;
}

#[derive(Default, Debug, PartialEq, Eq)]
#[repr(C)]
pub(in crate::host_clock) struct FileId {
    pub(in crate::host_clock) volume: u64,
    pub(in crate::host_clock) id: [u8; 16],
}
impl FileId {pub(in crate::host_clock) fn close_pin(&self)->[u8;24] {let mut pin=[0;24];
    pin[..8].copy_from_slice(&self.volume.to_le_bytes());pin[8..].copy_from_slice(&self.id);pin}}

pub(in crate::host_clock) fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
    value.encode_wide().chain([0]).collect()
}
pub(in crate::host_clock) fn api_path(path: &Path) -> Vec<u16> {
    // Extended Win32 namespace disables ordinary slash normalization. Preserve arbitrary
    // UTF16 components while converting the separators accepted by the public drive path.
    "\\\\?\\"
        .encode_utf16()
        .chain(path.as_os_str().encode_wide().map(|c| {
            if c == u16::from(b'/') {
                u16::from(b'\\')
            } else {
                c
            }
        }))
        .chain([0])
        .collect()
}
pub(in crate::host_clock) fn last(path: &Path) -> StorageError {
    io(path, std::io::Error::last_os_error())
}
pub(in crate::host_clock) fn access(path: &Path) -> StorageError {
    StorageError::Accessible(path.into())
}

pub(in crate::host_clock) fn inspect(file: &File, path: &Path, directory: bool) -> Result<FileId, StorageError> {
    let mut old = [0u32; 13];
    let mut id = FileId::default();
    unsafe {
        if GetFileInformationByHandle(file.as_raw_handle(), old.as_mut_ptr()) == 0
            || GetFileInformationByHandleEx(
                file.as_raw_handle(),
                18,
                (&mut id as *mut FileId).cast(),
                size_of::<FileId>() as u32,
            ) == 0
        {
            return Err(last(path));
        }
    }
    if old[0] & 0x400 != 0 {
        return Err(StorageError::Symlink(path.into()));
    }
    if (old[0] & 0x10 != 0) != directory {
        return Err(StorageError::Path(path.into()));
    }
    if !directory && old[10] != 1 {
        return Err(access(path));
    }
    Ok(id)
}
pub(in crate::host_clock) fn check_volume(file: &File, path: &Path) -> Result<(), StorageError> {
    let mut flags = 0;
    let mut fs = [0u16; 32];
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &mut flags,
            fs.as_mut_ptr(),
            fs.len() as u32,
        )
    } == 0
    {
        return Err(last(path));
    }
    // Narrow first supported backend. ReFS/network/device semantics are not inferred from NTFS.
    if flags & 8 == 0
        || String::from_utf16_lossy(&fs[..fs.iter().position(|c| *c == 0).unwrap_or(fs.len())])
            != "NTFS"
    {
        return Err(StorageError::Unsupported(
            "clock storage requires local NTFS persistent ACLs",
        ));
    }
    Ok(())
}
pub(in crate::host_clock) fn strict(path: &Path) -> Result<(), StorageError> {
    if !matches!(path.components().next(),Some(Component::Prefix(p)) if matches!(p.kind(),Prefix::Disk(_)))
    {
        return Err(StorageError::Path(path.into()));
    }
    // Reject Win32 alias syntax (streams, device names, trailing dots/spaces) and explicit dots.
    let spelling = path.as_os_str().to_string_lossy().replace('/', "\\");
    if spelling.split('\\').any(|v| v == "." || v == "..") {
        return Err(StorageError::Path(path.into()));
    }
    for c in path.components() {
        if let Component::Normal(n) = c {
            let n = n.to_string_lossy();
            let stem = n.split('.').next().unwrap_or("").to_ascii_uppercase();
            if n.ends_with(['.', ' '])
                || n.contains([':', '\0'])
                || [
                    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6",
                    "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7",
                    "LPT8", "LPT9",
                ]
                .contains(&stem.as_str())
            {
                return Err(StorageError::Path(path.into()));
            }
        }
    }
    Ok(())
}

/// Actual mapped-file custody. This never selects a deployment, changes ACLs,
/// grants a writer, or authenticates relocated executable pages. TI belongs
/// only to the existing exact System32 OS DLL role; arbitrary provider paths
/// retain the narrower SYSTEM/Administrators public installation boundary.
pub(crate) struct WindowsCurrentObject{core:Option<Box<CurrentPublicCore>>}
struct CurrentPublicCore{
    path:PathBuf,dir_paths:Vec<PathBuf>,dirs:Vec<Option<File>>,dir_ids:Vec<Option<FileId>>,
    file:Option<File>,id:Option<FileId>,os_dll:bool,links:u32,
    section_refused:bool,frozen:std::sync::atomic::AtomicBool,
    last_read_error:Option<i32>,construction_error:Option<i32>,problem:Option<String>,
    query_failure:Option<super::windows_native_query::WindowsMechanicalFailure>,
}
struct TemporaryPublicFile{
    path:PathBuf,file:Option<File>,original_id:Option<FileId>,identity_error:Option<i32>,
    open_error:Option<i32>,query_failure:Option<super::windows_native_query::WindowsMechanicalFailure>,
    close:super::native_retained_close::RetainedCloseReport,problem:Option<String>,
}
pub(crate) struct WindowsPublicObjectFailure{
    description:String,original:Option<std::mem::ManuallyDrop<Box<CurrentPublicCore>>>,
    temporary:Option<std::mem::ManuallyDrop<Box<TemporaryPublicFile>>>,
    mechanical:Option<std::mem::ManuallyDrop<super::windows_native_query::WindowsMechanicalFailure>>,
}
impl WindowsPublicObjectFailure{pub(crate) fn description(&self)->&str{&self.description}}
impl std::fmt::Debug for WindowsPublicObjectFailure{fn fmt(&self,f:&mut std::fmt::Formatter<'_>)->std::fmt::Result{
    f.debug_tuple("WindowsPublicObjectFailure").field(&self.description).finish()}}
struct ConstructionOwner{core:Option<Box<CurrentPublicCore>>}
impl Drop for ConstructionOwner{fn drop(&mut self){if let Some(core)=self.core.take(){let _=Box::into_raw(core);}}}
struct TemporaryOwner{core:Option<Box<TemporaryPublicFile>>}
impl Drop for TemporaryOwner{fn drop(&mut self){if let Some(core)=self.core.take(){let _=Box::into_raw(core);}}}
struct CurrentUnwind<'a>{frozen:&'a std::sync::atomic::AtomicBool,armed:bool}
impl Drop for CurrentUnwind<'_>{fn drop(&mut self){if self.armed{self.frozen.store(true,std::sync::atomic::Ordering::SeqCst);}}}
impl Drop for WindowsCurrentObject{fn drop(&mut self){if let Some(core)=self.core.take(){let _=Box::into_raw(core);}}}
fn public_failure(description:String)->WindowsPublicObjectFailure{WindowsPublicObjectFailure{description,original:None,temporary:None,mechanical:None}}
fn mechanical_failure(error:super::windows_native_query::WindowsMechanicalFailure)->WindowsPublicObjectFailure{
    WindowsPublicObjectFailure{description:error.description().to_owned(),original:None,temporary:None,mechanical:Some(std::mem::ManuallyDrop::new(error))}}
fn original_id(file:&File)->Result<FileId,i32>{
    let pin=super::native_retained_close::retained_identity(file)?;
    Ok(FileId{volume:u64::from_le_bytes(pin[..8].try_into().expect("fixed original volume")),id:pin[8..].try_into().expect("fixed original ID")})
}
// Return the newly created ORIGINAL File immediately. Validation belongs to the
// already allocated owner slot; no nested constructor can RAII-drop it on error.
fn public_raw_file(path:&Path,directory:bool)->std::io::Result<File>{
    let handle=unsafe{CreateFileW(api_path(path).as_ptr(),if directory{0x120080}else{READ|READ_CONTROL},
        if directory{1|2}else{1},null(),OPEN,NO_FOLLOW|if directory{BACKUP}else{0},null_mut())};
    if handle==(-1isize)as Ptr{return Err(std::io::Error::last_os_error());}
    Ok(unsafe{File::from_raw_handle(handle)})
}
fn public_noninherit(file:&File)->Result<(),i32>{let mut flags=0;
    if unsafe{GetHandleInformation(file.as_raw_handle(),&mut flags)}==0{
        return Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1));}
    if flags&1!=0{return Err(-2);}Ok(())}
fn current_temporary(path:&Path,directory:bool,os_dll:bool,links:u32,expected:&FileId)
    ->Result<(),WindowsPublicObjectFailure>{
    let close=super::native_retained_close::RetainedCloseReport::prepare(1).map_err(public_failure)?;
    let mut owner=TemporaryOwner{core:Some(Box::new(TemporaryPublicFile{path:path.to_owned(),file:None,original_id:None,
        identity_error:None,open_error:None,query_failure:None,close,problem:None}))};
    let result=(||{
        let core=owner.core.as_mut().expect("preallocated temporary object");
        match public_raw_file(&core.path,directory){Ok(file)=>core.file=Some(file),Err(error)=>{
            core.open_error=error.raw_os_error();
            return Err(format!("temporary original open: {error:?}"));}}
        let file=core.file.as_ref().expect("original temporary file");
        match original_id(file){Ok(id)=>core.original_id=Some(id),Err(error)=>{core.identity_error=Some(error);return Err(format!("temporary original identity: {error}"));}}
        public_noninherit(file).map_err(|e|{core.identity_error=Some(e);format!("temporary inheritance: {e}")})?;
        check_volume(file,&core.path).map_err(|e|format!("temporary volume: {e:?}"))?;
        if let Err(error)=super::windows_native_query::public_object_security(file,os_dll){
            let description=error.description().to_owned();core.query_failure=Some(error);return Err(description);}
        let actual=if directory{inspect(file,&core.path,true)}else{current_object_identity(file,&core.path,links)}
            .map_err(|e|format!("temporary object properties: {e:?}"))?;
        if &actual!=expected||core.original_id.as_ref()!=Some(expected){return Err("temporary original/name identity differs".into());}
        // Both observations were made before the one close; later query failure
        // cannot replace or erase this original ID.
        let original=core.original_id.as_ref().expect("learned original ID").close_pin();
        core.close.file(core.file.take().expect("original temporary owner"),original);
        if !core.close.retained_handles_closed(){return Err("temporary once-close outcome unknown".into());}Ok(())
    })();
    match result{Ok(())=>{drop(owner.core.take());Ok(())},Err(description)=>{
        owner.core.as_mut().expect("temporary custody").problem=Some(description.clone());
        Err(WindowsPublicObjectFailure{description,original:None,temporary:Some(std::mem::ManuallyDrop::new(owner.core.take().expect("temporary custody"))),mechanical:None})}}
}
impl WindowsCurrentObject{
    pub(crate) fn retained_file_count(&self)->usize{1+self.core.as_ref().expect("retained object").dirs.len()}
    pub(crate) fn close_retained_into(mut self,report:&mut super::native_retained_close::RetainedCloseReport){
        // An actual CURRENT/query/temporary-close refusal keeps the original
        // owner. The external EXACT report roster remains incomplete, so it
        // cannot report all-success or release a parent writer/selection lease.
        if self.recheck().is_err(){return;}
        let mut core=std::mem::ManuallyDrop::new(self.core.take().expect("retained original object"));
        let pin=core.id.as_ref().expect("original file ID").close_pin();
        report.file(core.file.take().expect("original retained file"),pin);
        for index in (0..core.dirs.len()).rev(){let pin=core.dir_ids[index].as_ref().expect("original directory ID").close_pin();
            report.file(core.dirs[index].take().expect("original retained directory"),pin);}
        // Every actual obligation has transferred to the already allocated
        // once-close report; uncertainty remains inside that report, not Drop.
        drop(std::mem::ManuallyDrop::into_inner(core));
    }
    /// SAFETY: live original module reference plus native-validated own SEC_IMAGE
    /// allocation base retained through this call. No peer/document numeric base.
    #[cfg(target_arch="x86_64")]
    pub(crate) unsafe fn require_image_backing(&mut self,image:usize)->Result<(),WindowsPublicObjectFailure>{
        self.recheck()?;let core=self.core.as_mut().expect("retained object");
        let mut guard=CurrentUnwind{frozen:&core.frozen,armed:true};
        let result=unsafe{super::native_nts_windows_section::compare_original(core.file.as_ref().expect("original image file"),image)};
        if result.is_err(){core.section_refused=true;return Err(public_failure("original image backing refused/unknown".into()));}
        guard.armed=false;drop(guard);self.recheck()
    }
    pub(crate) fn file_identity(&self)->(u64,[u8;16],u32){let core=self.core.as_ref().expect("retained object");
        let id=core.id.as_ref().expect("published original ID");(id.volume,id.id,core.links)}
    pub(crate) fn bounded_bytes(&mut self,maximum:u64)->Result<Vec<u8>,WindowsPublicObjectFailure>{
        self.recheck()?;let core=self.core.as_mut().expect("retained object");
        let CurrentPublicCore{file,frozen,last_read_error,..}=&mut **core;
        let mut guard=CurrentUnwind{frozen,armed:true};
        let result=(||{let file=file.as_mut().expect("retained original file");
            let size=file.metadata().map_err(|e|{*last_read_error=e.raw_os_error();public_failure(format!("public length: {e}"))})?.len();
            if size==0||maximum>64*1024||size>maximum{return Err(public_failure("public bounded bytes refused".into()));}
            let mut raw=Vec::new();raw.try_reserve_exact((maximum+1)as usize).map_err(|_|public_failure("bounded public allocation refused".into()))?;
            file.seek(SeekFrom::Start(0)).map_err(|e|{*last_read_error=e.raw_os_error();public_failure(format!("public seek: {e}"))})?;
            Read::by_ref(file).take(maximum+1).read_to_end(&mut raw).map_err(|e|{*last_read_error=e.raw_os_error();public_failure(format!("public read: {e}"))})?;
            if raw.len()as u64!=size||file.metadata().map_err(|e|{*last_read_error=e.raw_os_error();public_failure(format!("public reread length: {e}"))})?.len()!=size{
                return Err(public_failure("public original byte length changed".into()));}Ok(raw)})();
        if result.is_ok(){guard.armed=false;}drop(guard);let raw=result?;self.recheck()?;Ok(raw)
    }
    pub(crate) fn open(path:&Path,os_dll:bool,links:u32)->Result<Self,WindowsPublicObjectFailure>{
        strict(path).map_err(|e|public_failure(format!("public path: {e:?}")))?;
        let spelling=path.to_str().ok_or_else(||public_failure("public path encoding".into()))?;
        if spelling.contains('/')||spelling.contains("\\\\")||spelling.ends_with('\\')||!spelling.starts_with("C:\\"){
            return Err(public_failure("public exact Windows path spelling".into()));}
        let leaf=spelling.strip_prefix("C:\\Windows\\System32\\");
        if links==0||(!os_dll&&links!=1)||(os_dll&&leaf.is_none_or(|s|s.contains('\\')||s.len()<5||!s.to_ascii_lowercase().ends_with(".dll"))){
            return Err(public_failure("public selected link/OS class refused".into()));}
        let parent=path.parent().ok_or_else(||public_failure("public parent".into()))?;
        // All path strings, File slots and identity slots exist before any open.
        let mut prefix=PathBuf::new();let mut paths=Vec::new();
        paths.try_reserve_exact(parent.components().count()).map_err(|_|public_failure("public ancestor roster allocation".into()))?;
        for part in parent.components(){prefix.push(part.as_os_str());if matches!(part,Component::Prefix(_)){continue;}paths.push(prefix.clone());}
        let mut dirs=Vec::new();let mut ids=Vec::new();dirs.try_reserve_exact(paths.len()).map_err(|_|public_failure("public holder slots".into()))?;
        ids.try_reserve_exact(paths.len()).map_err(|_|public_failure("public identity slots".into()))?;
        dirs.resize_with(paths.len(),||None);ids.resize_with(paths.len(),||None);
        let mut owner=ConstructionOwner{core:Some(Box::new(CurrentPublicCore{path:path.to_owned(),dir_paths:paths,dirs,dir_ids:ids,file:None,id:None,
            os_dll,links,section_refused:false,frozen:std::sync::atomic::AtomicBool::new(false),last_read_error:None,construction_error:None,problem:None,query_failure:None}))};
        let result=(||{let core=owner.core.as_mut().expect("unpublished public core");
            for index in 0..core.dir_paths.len(){let path=&core.dir_paths[index];
                core.dirs[index]=Some(public_raw_file(path,true).map_err(|e|{core.construction_error=e.raw_os_error();format!("public original directory open: {e:?}")})?);
                let file=core.dirs[index].as_ref().expect("retained original ancestor");
                core.dir_ids[index]=Some(original_id(file).map_err(|e|{core.construction_error=Some(e);format!("public original ancestor ID: {e}")})?);
                public_noninherit(file).map_err(|e|{core.construction_error=Some(e);format!("public original inheritance: {e}")})?;
                check_volume(file,path).map_err(|e|format!("public original volume: {e:?}"))?;
                if let Err(error)=super::windows_native_query::public_object_security(file,os_dll){let problem=error.description().to_owned();core.query_failure=Some(error);return Err(problem);}
                if Some(inspect(file,path,true).map_err(|e|format!("public ancestor properties: {e:?}"))?)!=core.dir_ids[index]{return Err("public original ancestor identity changed".into());}}
            core.file=Some(public_raw_file(&core.path,false).map_err(|e|{core.construction_error=e.raw_os_error();format!("public original file open: {e:?}")})?);
            let file=core.file.as_ref().expect("original selected file");core.id=Some(original_id(file).map_err(|e|{core.construction_error=Some(e);format!("public original file ID: {e}")})?);
            public_noninherit(file).map_err(|e|{core.construction_error=Some(e);format!("public file inheritance: {e}")})?;
            check_volume(file,&core.path).map_err(|e|format!("public file volume: {e:?}"))?;
            if let Err(error)=super::windows_native_query::public_object_security(file,os_dll){let problem=error.description().to_owned();core.query_failure=Some(error);return Err(problem);}
            if Some(current_object_identity(file,&core.path,links).map_err(|e|format!("public original file properties: {e:?}"))?)!=core.id{return Err("public original file identity changed".into());}Ok(())})();
        if let Err(description)=result{owner.core.as_mut().expect("whole unpublished owner").problem=Some(description.clone());
            return Err(WindowsPublicObjectFailure{description,original:Some(std::mem::ManuallyDrop::new(owner.core.take().expect("whole unpublished owner"))),temporary:None,mechanical:None});}
        let value=Self{core:owner.core.take()};value.recheck()?;Ok(value)
    }
    pub(crate) fn recheck(&self)->Result<(),WindowsPublicObjectFailure>{let core=self.core.as_ref().expect("retained public object");
        if core.section_refused||core.frozen.load(std::sync::atomic::Ordering::SeqCst){return Err(public_failure("retained public object frozen".into()));}
        let mut guard=CurrentUnwind{frozen:&core.frozen,armed:true};
        for index in 0..core.dirs.len(){let file=core.dirs[index].as_ref().expect("retained ancestor");let path=&core.dir_paths[index];
            check_volume(file,path).map_err(|e|public_failure(format!("held ancestor volume: {e:?}")))?;
            super::windows_native_query::public_object_security(file,core.os_dll).map_err(mechanical_failure)?;
            let actual=inspect(file,path,true).map_err(|e|public_failure(format!("held ancestor properties: {e:?}")))?;
            if Some(&actual)!=core.dir_ids[index].as_ref(){return Err(public_failure("held ancestor differs from ORIGINAL pin".into()));}
            current_temporary(path,true,core.os_dll,core.links,core.dir_ids[index].as_ref().expect("original ancestor ID"))?;}
        let file=core.file.as_ref().expect("original file");check_volume(file,&core.path).map_err(|e|public_failure(format!("held file volume: {e:?}")))?;
        super::windows_native_query::public_object_security(file,core.os_dll).map_err(mechanical_failure)?;
        let actual=current_object_identity(file,&core.path,core.links).map_err(|e|public_failure(format!("held file properties: {e:?}")))?;
        if Some(&actual)!=core.id.as_ref(){return Err(public_failure("held file differs from ORIGINAL pin".into()));}
        current_temporary(&core.path,false,core.os_dll,core.links,core.id.as_ref().expect("original file ID"))?;
        guard.armed=false;Ok(())
    }
    pub(crate) fn hash_exact(&mut self,size:u64)->Result<[u8;32],WindowsPublicObjectFailure>{
        use sha2::{Digest,Sha256};self.recheck()?;let core=self.core.as_mut().expect("retained object");
        let CurrentPublicCore{file,frozen,last_read_error,..}=&mut **core;
        let mut guard=CurrentUnwind{frozen,armed:true};
        let result=(||{let file=file.as_mut().expect("original file");
            if size==0||file.metadata().map_err(|e|{*last_read_error=e.raw_os_error();public_failure(format!("hash length: {e}"))})?.len()!=size{return Err(public_failure("exact original hash length".into()));}
            file.seek(SeekFrom::Start(0)).map_err(|e|{*last_read_error=e.raw_os_error();public_failure(format!("hash seek: {e}"))})?;
            let mut remaining=size;let mut hash=Sha256::new();let mut buffer=[0;65536];
            while remaining!=0{let limit=remaining.min(buffer.len()as u64)as usize;let n=file.read(&mut buffer[..limit]).map_err(|e|{*last_read_error=e.raw_os_error();public_failure(format!("hash read: {e}"))})?;
                if n==0{return Err(public_failure("exact hash truncated".into()));}hash.update(&buffer[..n]);remaining-=n as u64;}
            let mut extra=[0];if file.read(&mut extra).map_err(|e|{*last_read_error=e.raw_os_error();public_failure(format!("hash tail: {e}"))})?!=0
                ||file.metadata().map_err(|e|{*last_read_error=e.raw_os_error();public_failure(format!("hash final length: {e}"))})?.len()!=size{return Err(public_failure("exact hash changed".into()));}
            Ok(hash.finalize().into())})();
        if result.is_ok(){guard.armed=false;}drop(guard);let pin=result?;self.recheck()?;Ok(pin)
    }
}

fn current_object_identity(file:&File,path:&Path,links:u32)->Result<FileId,StorageError> {
    let mut old=[0u32;13];let mut id=FileId::default();
    if unsafe{GetFileInformationByHandle(file.as_raw_handle(),old.as_mut_ptr())}==0
        || unsafe{GetFileInformationByHandleEx(file.as_raw_handle(),18,(&mut id as *mut FileId).cast(),size_of::<FileId>() as u32)}==0 {
        return Err(last(path));
    }
    if old[0]&(0x400|0x10)!=0 || old[10]!=links || id.id==[0;16] {return Err(access(path));}
    Ok(id)
}
pub(crate) fn require_own_process_boundary()->std::result::Result<(),String> {
    super::windows_native_query::require_own_process_boundary().map_err(|error|error.description().to_owned())
}
