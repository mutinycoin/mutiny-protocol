//! Private NONSHIPPING own-child original public-file leases.
//! Selected object witnesses and TEST token/source/role admission are supplied by
//! the caller. These leases alone confer no loader, EA, ABI or signing authority.
#![cfg(all(windows,target_arch="x86_64"))]
use super::image_pin::native_handle_owner::{self,NativeFile};
use sha2::{Digest,Sha256};
use std::{cell::Cell,ffi::c_void,fs::File,io::{Read,Seek,SeekFrom},mem::{size_of,zeroed},
    os::windows::{ffi::OsStrExt,io::AsRawHandle},path::{Component,Path,PathBuf,Prefix},ptr,
    sync::atomic::{AtomicBool,AtomicPtr,Ordering}};
use windows_sys::Win32::{Foundation::LocalFree,
    Security::{Authorization::{GetSecurityInfo,SE_FILE_OBJECT},DACL_SECURITY_INFORMATION,
        OWNER_SECURITY_INFORMATION,GetAce,IsValidSid,GetLengthSid},
    Storage::FileSystem::{GetFileInformationByHandle,GetFileInformationByHandleEx,
        GetFinalPathNameByHandleW,GetVolumeInformationByHandleW,GetDriveTypeW,
        BY_HANDLE_FILE_INFORMATION,FILE_ID_INFO,FileIdInfo,FILE_LIST_DIRECTORY,
        FILE_READ_ATTRIBUTES,FILE_SHARE_READ,FILE_SHARE_WRITE,FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_FLAG_BACKUP_SEMANTICS,READ_CONTROL}};
type Result<T>=std::result::Result<T,String>;
const CAP:u64=128*1024*1024;
const MUTATION:u32=0x2|0x4|0x10|0x40|0x100|0x10000|0x40000|0x80000|0x10000000|0x40000000;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(super) enum PublicClass{OwnTestImage,System32Dll}
#[derive(Clone,Debug)]
pub(super) struct PublicObjectSpec{
    pub(super) path:PathBuf,pub(super) class:PublicClass,pub(super) bytes:u64,
    pub(super) sha256:[u8;32],pub(super) volume:u64,pub(super) file_id:[u8;16],
    pub(super) links:u32,pub(super) owner_sid:Vec<u8>,pub(super) dacl_sha256:[u8;32],
}
#[derive(Clone,Debug,PartialEq,Eq)]
struct Observation{volume:u64,id:[u8;16],links:u32,bytes:u64,attributes:u32,
    owner:Vec<u8>,dacl:[u8;32]}
struct Entry{path:PathBuf,file:NativeFile,observed:Option<Observation>,directory:bool,root:bool}
struct SecurityRecord{next:usize,raw:usize,attempted:bool,outcome:Option<bool>}
static RETAINED:AtomicPtr<SecurityRecord>=AtomicPtr::new(ptr::null_mut());
static UNKNOWN:AtomicBool=AtomicBool::new(false);
fn retain(record:Box<SecurityRecord>){let raw=Box::into_raw(record);let mut head=RETAINED.load(Ordering::Acquire);
    loop{unsafe{(*raw).next=head as usize;}match RETAINED.compare_exchange_weak(head,raw,Ordering::AcqRel,Ordering::Acquire){
        Ok(_)=>break,Err(now)=>head=now}}}
struct SecurityOwner{record:Option<Box<SecurityRecord>>}
impl Drop for SecurityOwner{fn drop(&mut self){if let Some(record)=self.record.take(){if record.raw!=0{
    UNKNOWN.store(true,Ordering::Release);retain(record);}}}}
fn known()->Result<()>{native_handle_owner::require_known()?;
    if UNKNOWN.load(Ordering::Acquire){Err("Own public native security custody UNKNOWN".into())}else{Ok(())}}
fn close_security(owner:&mut SecurityOwner)->Result<()>{let record=owner.record.as_mut().ok_or("Own security record absent")?;
    if record.attempted{return Err("Own security close consumed; no retry".into());}record.attempted=true;
    let released=record.raw==0||unsafe{LocalFree(record.raw as *mut c_void)}.is_null();record.outcome=Some(released);
    if released{owner.record.take();Ok(())}else{UNKNOWN.store(true,Ordering::Release);
        retain(owner.record.take().unwrap());Err("Own original security allocation close UNKNOWN".into())}}
fn fixed_sid(authority:u64,sub:&[u32])->Vec<u8>{let mut sid=vec![1,sub.len() as u8];
    sid.extend_from_slice(&authority.to_be_bytes()[2..]);for n in sub{sid.extend_from_slice(&n.to_le_bytes());}sid}
fn trusted_sids(user:&[u8])->Vec<Vec<u8>>{vec![user.to_vec(),fixed_sid(5,&[18]),fixed_sid(5,&[32,544]),
    fixed_sid(5,&[80,956008885,3418522649,1831038044,1853292631,2271478464])]}
fn sid(pointer:*mut c_void)->Result<Vec<u8>>{if pointer.is_null()||unsafe{IsValidSid(pointer)}==0{
    return Err("Own public native SID invalid".into());}let length=unsafe{GetLengthSid(pointer)} as usize;
    if !(8..=68).contains(&length){return Err("Own public native SID bound".into());}
    Ok(unsafe{std::slice::from_raw_parts(pointer.cast::<u8>(),length)}.to_vec())}
fn validate_original_security(status:u32,owner:*mut c_void,dacl:*mut windows_sys::Win32::Security::ACL,
    allocation:*mut c_void,user:&[u8],leaf:Option<PublicClass>,root:bool)->Result<(Vec<u8>,[u8;32])>{if status!=0||allocation.is_null()||dacl.is_null(){
        return Err(format!("Own public original security read refused {status}"));}
        let owner=sid(owner)?;let trusted=trusted_sids(user);
        let allowed=|s:&[u8]|trusted.iter().any(|t|t==s);
        match leaf{Some(PublicClass::OwnTestImage) if owner!=user=>return Err("Own TEST image owner differs from selected child account".into()),
            Some(PublicClass::System32Dll) if owner!=trusted[3]=>return Err("Own System32 DLL owner is not exact TrustedInstaller".into()),
            None if !allowed(&owner)=>return Err("Own public ancestor owner refused".into()),_=>{}}
        let acl=dacl.cast::<u8>();let acl_size=unsafe{u16::from_le_bytes([*acl.add(2),*acl.add(3)])} as usize;
        let count=unsafe{u16::from_le_bytes([*acl.add(4),*acl.add(5)])} as usize;
        if !(8..=65535).contains(&acl_size)||count>256||count>(acl_size-8)/4{return Err("Own public native ACL bound".into());}
        let raw=unsafe{std::slice::from_raw_parts(acl,acl_size)};
        for index in 0..count{let mut ace=ptr::null_mut();if unsafe{GetAce(dacl,index as u32,&mut ace)}==0||ace.is_null(){
            return Err("Own public ACE absent".into());}
            let start=(ace as usize).checked_sub(acl as usize).ok_or("Own public ACE outside original ACL")?;
            if start<8||start.checked_add(8).ok_or("Own ACE range")?>acl_size{return Err("Own ACE header bound".into());}
            let length=u16::from_le_bytes([raw[start+2],raw[start+3]]) as usize;
            if length<8||start.checked_add(length).ok_or("Own ACE extent")?>acl_size{return Err("Own ACE extent outside original ACL".into());}
            let kind=raw[start];let flags=raw[start+1];if flags&8!=0||kind==1{continue;}
            if kind!=0||!(16..=76).contains(&length){return Err("Own public conditional or unsupported effective ACE".into());}
            let width=8+4*(raw[start+9] as usize);if raw[start+9]>15||width+8>length{return Err("Own effective ACE SID bound".into());}
            let principal=sid(unsafe{ace.cast::<u8>().add(8)}.cast())?;if principal.len()!=width{return Err("Own ACE SID extent mismatch".into());}
            let mask=u32::from_le_bytes(raw[start+4..start+8].try_into().unwrap());
            if !allowed(&principal)&&mask&(if root{MUTATION&!0x4}else{MUTATION})!=0{
                return Err("Own public foreign mutation/delete/security authority refused".into());}}
        Ok((owner,Sha256::digest(raw).into()))
}
fn security(file:&File,user:&[u8],leaf:Option<PublicClass>,root:bool)->Result<(Vec<u8>,[u8;32])>{
    known()?;let mut custody=SecurityOwner{record:Some(Box::new(SecurityRecord{next:0,raw:0,attempted:false,outcome:None}))};
    let(mut owner,mut dacl,mut allocation)=(ptr::null_mut(),ptr::null_mut(),ptr::null_mut());
    let status=unsafe{GetSecurityInfo(file.as_raw_handle(),SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,
        &mut owner,ptr::null_mut(),&mut dacl,ptr::null_mut(),&mut allocation)};
    custody.record.as_mut().unwrap().raw=allocation as usize;
    let observed:Result<(Vec<u8>,[u8;32])>=validate_original_security(status,owner,dacl,allocation,user,leaf,root);;
    let closed=close_security(&mut custody);match(observed,closed){(Ok(value),Ok(()))=>Ok(value),
        (primary,cleanup)=>Err(format!("Own original security={primary:?}; once close={cleanup:?}"))}
}
fn strict(path:&Path)->Result<()>{if !path.is_absolute()||!matches!(path.components().next(),Some(Component::Prefix(p)) if matches!(p.kind(),Prefix::Disk(_))){
    return Err("Own public object local absolute drive path required".into());}
    let text=path.to_str().ok_or("Own public ASCII path required")?;if !text.is_ascii()||text.len()>4096||text.contains('\0')||text.bytes().any(|b|b<32){
        return Err("Own public bounded path refused".into());}
    for n in text.replace('/',"\\").split('\\').skip(1){let stem=n.split('.').next().unwrap_or("").to_ascii_uppercase();
        if n.is_empty()||n=="."||n==".."||n.ends_with(['.',' '])||n.contains(':')
            ||["CON","PRN","AUX","NUL","COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9",
               "LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9"].contains(&stem.as_str()){
            return Err("Own public Win32 alias/path component refused".into());}}Ok(())}
fn inspect(entry:&Entry,user:&[u8],class:PublicClass)->Result<Observation>{let file=entry.file.file()?;
    let mut old:BY_HANDLE_FILE_INFORMATION=unsafe{zeroed()};let mut id:FILE_ID_INFO=unsafe{zeroed()};
    if unsafe{GetFileInformationByHandle(file.as_raw_handle(),&mut old)}==0
        ||unsafe{GetFileInformationByHandleEx(file.as_raw_handle(),FileIdInfo,(&mut id as *mut FILE_ID_INFO).cast(),size_of::<FILE_ID_INFO>() as u32)}==0{
        return Err("Own public original native object metadata refused".into());}
    if old.dwFileAttributes&0x400!=0||(old.dwFileAttributes&0x10!=0)!=entry.directory{return Err("Own public reparse/type refused".into());}
    let mut fs=[0u16;32];let mut flags=0;
    if unsafe{GetVolumeInformationByHandleW(file.as_raw_handle(),ptr::null_mut(),0,ptr::null_mut(),ptr::null_mut(),&mut flags,fs.as_mut_ptr(),32)}==0
        ||flags&8==0||String::from_utf16(&fs[..fs.iter().position(|v|*v==0).ok_or("Own filesystem text bound")?]).map_err(|_|"Own filesystem UTF16")?!="NTFS"{
        return Err("Own public original object requires NTFS persistent ACLs".into());}
    let mut name=[0u16;4097];let length=unsafe{GetFinalPathNameByHandleW(file.as_raw_handle(),name.as_mut_ptr(),name.len() as u32,0)} as usize;
    if length==0||length>=name.len(){return Err("Own public final path bound".into());}
    let actual=String::from_utf16(&name[..length]).map_err(|_|"Own public final path UTF16")?;
    let expected=format!("\\\\?\\{}",entry.path.to_str().unwrap().replace('/',"\\"));
    if !actual.eq_ignore_ascii_case(&expected){return Err("Own original public final pathname mismatch".into());}
    let(owner,dacl)=security(file,user,(!entry.directory).then_some(class),entry.root)?;
    Ok(Observation{volume:id.VolumeSerialNumber,id:id.FileId.Identifier,links:old.nNumberOfLinks,
        bytes:(u64::from(old.nFileSizeHigh)<<32)|u64::from(old.nFileSizeLow),attributes:old.dwFileAttributes,owner,dacl})}
fn open(path:&Path,directory:bool,metadata_only:bool)->Result<NativeFile>{NativeFile::open(path,
    READ_CONTROL|FILE_READ_ATTRIBUTES|if directory{FILE_LIST_DIRECTORY}else if metadata_only{0}else{0x80000000},
    FILE_SHARE_READ|if directory{FILE_SHARE_WRITE}else{0},FILE_FLAG_OPEN_REPARSE_POINT|if directory{FILE_FLAG_BACKUP_SEMANTICS}else{0})}
pub(super) struct OriginalPublicFile{entries:Vec<Entry>,spec:PublicObjectSpec,user:Vec<u8>,revoked:Cell<bool>,closed:bool}
impl OriginalPublicFile{
    pub(super) fn open_declared(spec:PublicObjectSpec,user:&[u8])->Result<Self>{known()?;strict(&spec.path)?;
        if !(8..=68).contains(&user.len())||!(64..=CAP).contains(&spec.bytes)||spec.links==0||spec.links>64
            ||(spec.class==PublicClass::OwnTestImage&&spec.links!=1){return Err("Own public selected witness bound/class refused".into());}
        if spec.class==PublicClass::System32Dll{let parent=spec.path.parent().ok_or("Own System32 parent")?;
            if !parent.to_str().unwrap().replace('/',"\\").eq_ignore_ascii_case("C:\\Windows\\System32")
                ||!spec.path.extension().and_then(|n|n.to_str()).is_some_and(|n|n.eq_ignore_ascii_case("dll")){return Err("Own selected OS DLL exact flat System32 class required".into());}}
        let root=spec.path.components().take(2).collect::<PathBuf>();let wide:Vec<u16>=root.as_os_str().encode_wide().chain(Some(0)).collect();
        if unsafe{GetDriveTypeW(wide.as_ptr())}!=3{return Err("Own public local fixed volume required".into());}
        let mut owner=Self{entries:Vec::with_capacity(64),spec,user:user.to_vec(),revoked:Cell::new(false),closed:false};
        let operation:Result<()>=(||{let mut prefix=PathBuf::new();let path=owner.spec.path.clone();
            for component in path.components(){prefix.push(component.as_os_str());if matches!(component,Component::Prefix(_)){continue;}
                if owner.entries.len()>=64{return Err("Own public ancestor count bound".into());}
                let directory=prefix!=path;let native=open(&prefix,directory,false)?;
                owner.entries.push(Entry{path:prefix.clone(),file:native,observed:None,directory,root:directory&&prefix==root});
                let entry=owner.entries.last_mut().unwrap();entry.observed=Some(inspect(entry,&owner.user,owner.spec.class)?);}
            let held=owner.entries.last().unwrap().observed.as_ref().unwrap();
            if held.volume!=owner.spec.volume||held.id!=owner.spec.file_id||held.bytes!=owner.spec.bytes||held.links!=owner.spec.links
                ||held.owner!=owner.spec.owner_sid||held.dacl!=owner.spec.dacl_sha256{return Err("Own public exact original witness differs".into());}
            let mut reader=owner.entries.last().unwrap().file.file()?;reader.seek(SeekFrom::Start(0)).map_err(|_|"Own public original seek")?;
            let mut digest=Sha256::new();let mut buffer=[0u8;65536];let mut count=0u64;
            loop{let n=reader.read(&mut buffer).map_err(|_|"Own public original read")?;if n==0{break;}
                count=count.checked_add(n as u64).ok_or("Own public original count")?;
                if count>owner.spec.bytes{return Err("Own public original growth/size refusal".into());}digest.update(&buffer[..n]);}
            if count!=owner.spec.bytes||<[u8;32]>::from(digest.finalize())!=owner.spec.sha256{return Err("Own public original full SHA/EOF refusal".into());}
            owner.recheck()})();
        if let Err(primary)=operation{let cleanup=owner.close_checked();return Err(format!("Own public original={primary}; closure={cleanup:?}"));}Ok(owner)
    }
    pub(super) fn original_file(&self)->Result<&File>{self.recheck()?;self.entries.last().ok_or("Own original leaf absent")?.file.file()}
    pub(super) fn recheck(&self)->Result<()>{known()?;if self.closed||self.revoked.get(){return Err("Own public original owner revoked".into());}
        let result:Result<()>=(||{for entry in &self.entries{let expected=entry.observed.as_ref().ok_or("Own original observation absent")?;
            if &inspect(entry,&self.user,self.spec.class)?!=expected{return Err("Own held original identity/security drift".into());}
            let mut named=Entry{path:entry.path.clone(),file:open(&entry.path,entry.directory,true)?,observed:None,directory:entry.directory,root:entry.root};
            let observation=inspect(&named,&self.user,self.spec.class);let closure=named.file.close_checked();
            if observation.as_ref()!=Ok(expected)||closure.is_err(){return Err(format!("Own named original drift/release={observation:?}/{closure:?}"));}}
            Ok(())})();if result.is_err(){self.revoked.set(true);}result
    }
    pub(super) fn close_checked(&mut self)->Result<()>{if self.closed{return Err("Own public original close already consumed".into());}
        self.closed=true;self.revoked.set(true);let mut errors=Vec::new();for entry in self.entries.iter_mut().rev(){
            if let Err(error)=entry.file.close_checked(){errors.push(error);}}
        if errors.is_empty(){Ok(())}else{Err(format!("Independent own public original closures={errors:?}"))}}
}
impl Drop for OriginalPublicFile{fn drop(&mut self){if !self.closed{let _=self.close_checked();}}}
#[cfg(all(test,feature="testvalue-window"))]
#[path="continuous_own_native_security_value_controls.rs"] pub(crate) mod security_value_controls;
