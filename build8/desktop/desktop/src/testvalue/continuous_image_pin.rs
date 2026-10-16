// EXTERNAL SOURCE ONLY. Narrow read-only C8-style opened-object port for public TEST executables.
// Provenance: node/src/host_clock/state_dir/windows_storage.rs, reviewed69a66192 source.
// Retains every no-follow ancestor handle without DELETE sharing and image without WRITE sharing.
// This is account/OS isolation, not hostile administrator or same-account memory protection.
#![cfg(windows)]
use std::{fs::File,io::{Read,Seek,SeekFrom},mem::{size_of,zeroed},os::windows::{ffi::OsStrExt,io::{AsRawHandle,FromRawHandle}},path::{Component,Path,PathBuf,Prefix},ptr};
use sha2::{Digest,Sha256};
#[path="continuous_native_handle_owner.rs"] pub(crate) mod native_handle_owner;
use native_handle_owner::NativeFile;
use windows_sys::Win32::{Foundation::{GetLastError,HANDLE,INVALID_HANDLE_VALUE,LocalFree},
    Security::{Authorization::{ConvertStringSidToSidW,GetSecurityInfo,SE_FILE_OBJECT},ACL_SIZE_INFORMATION,AclSizeInformation,GetAce,GetAclInformation,GetLengthSid,IsValidSid,DACL_SECURITY_INFORMATION,OWNER_SECURITY_INFORMATION,ACCESS_ALLOWED_ACE},
    Storage::FileSystem::{CreateFileW,GetDriveTypeW,GetFileInformationByHandle,GetFileInformationByHandleEx,GetFinalPathNameByHandleW,GetVolumeInformationByHandleW,BY_HANDLE_FILE_INFORMATION,FILE_ID_INFO,FileIdInfo,FILE_FLAG_OPEN_REPARSE_POINT,FILE_FLAG_BACKUP_SEMANTICS,FILE_READ_ATTRIBUTES,FILE_READ_DATA,FILE_LIST_DIRECTORY,FILE_SHARE_READ,FILE_SHARE_WRITE,OPEN_EXISTING,READ_CONTROL}};
type Result<T>=std::result::Result<T,String>;
const MAX_IMAGE_BYTES:u64=256*1024*1024;
const GENERIC_READ:u32=0x80000000;
const FOREIGN_MUTATION:u32=0x2|0x4|0x10|0x40|0x100|0x10000|0x40000|0x80000|0x10000000|0x40000000;
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct Id {pub volume:u64,pub file:[u8;16]}
struct Entry {path:PathBuf,file:File,id:Id,directory:bool,volume_root:bool}
pub struct ImagePin {entries:Vec<Entry>,leaf_metadata:Entry,hash:[u8;32],owner:Vec<u8>}
struct Local(*mut core::ffi::c_void);
impl Drop for Local {fn drop(&mut self){unsafe{LocalFree(self.0);}}}
fn wide(s:&std::ffi::OsStr)->Vec<u16>{s.encode_wide().chain(Some(0)).collect()}
fn strict(path:&Path)->Result<()> {
    if !path.is_absolute() || !matches!(path.components().next(),Some(Component::Prefix(p)) if matches!(p.kind(),Prefix::Disk(_))) {
        return Err("Public image requires local drive absolute path".into());
    }
    let Some(text)=path.to_str() else{return Err("Public image path Unicode outside supported TEST scope".into());};
    if !text.is_ascii() || text.replace('/',"\\").split('\\').any(|n|n=="."||n=="..") {return Err("Public image alias/ASCII path refused".into());}
    for c in path.components(){if let Component::Normal(n)=c{
        let n=n.to_string_lossy();let stem=n.split('.').next().unwrap_or("").to_ascii_uppercase();
        if n.ends_with(['.',' '])||n.contains([':', '\0'])||["CON","PRN","AUX","NUL","COM1","COM2","COM3","COM4","COM5","COM6","COM7","COM8","COM9","LPT1","LPT2","LPT3","LPT4","LPT5","LPT6","LPT7","LPT8","LPT9"].contains(&stem.as_str()) {return Err("Public image Win32 alias refused".into());}
    }}Ok(())
}
fn open(path:&Path,directory:bool)->Result<File> {
    let text=format!("\\\\?\\{}",path.to_str().ok_or("Public image path")?.replace('/',"\\"));
    let name:Vec<u16>=text.encode_utf16().chain(Some(0)).collect();
    // FILE_LIST_DIRECTORY activates the retained no-DELETE-sharing directory lease.
    // Attribute-only directory handles do not prevent an empty directory rename.
    let handle=unsafe{CreateFileW(name.as_ptr(),READ_CONTROL|FILE_READ_ATTRIBUTES|if directory{FILE_LIST_DIRECTORY}else{GENERIC_READ},
        FILE_SHARE_READ|if directory{FILE_SHARE_WRITE}else{0},ptr::null(),OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT|if directory{FILE_FLAG_BACKUP_SEMANTICS}else{0},ptr::null_mut())};
    if handle==INVALID_HANDLE_VALUE||handle.is_null(){let native_error=unsafe{GetLastError()};return Err(format!("Public image no-follow open refused: {} (native error {native_error})",path.display()));}
    Ok(unsafe{File::from_raw_handle(handle)})
}
// Metadata-only leaf open can inspect an actual directory junction without
// following it. It grants no data read, WRITE/DELETE share, privilege or fallback.
fn open_leaf_metadata(path:&Path)->Result<File>{
    let text=format!("\\\\?\\{}",path.to_str().ok_or("Public metadata path")?.replace('/',"\\"));
    let name:Vec<u16>=text.encode_utf16().chain(Some(0)).collect();
    let handle=unsafe{CreateFileW(name.as_ptr(),READ_CONTROL|FILE_READ_ATTRIBUTES,
        FILE_SHARE_READ,ptr::null(),OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,ptr::null_mut())};
    if handle==INVALID_HANDLE_VALUE||handle.is_null(){let native_error=unsafe{GetLastError()};return Err(format!("Public image metadata no-follow open refused: {} (native error {native_error})",path.display()));}
    Ok(unsafe{File::from_raw_handle(handle)})
}
fn inspect(file:&File,directory:bool)->Result<Id>{
    let mut info:BY_HANDLE_FILE_INFORMATION=unsafe{zeroed()};let mut id:FILE_ID_INFO=unsafe{zeroed()};
    if unsafe{GetFileInformationByHandle(file.as_raw_handle(),&mut info)}==0 || unsafe{GetFileInformationByHandleEx(file.as_raw_handle(),FileIdInfo,(&mut id as *mut FILE_ID_INFO).cast(),size_of::<FILE_ID_INFO>() as u32)}==0 {return Err("Public image opened native identity refused".into());}
    if info.dwFileAttributes&0x400!=0 || (info.dwFileAttributes&0x10!=0)!=directory || (!directory&&info.nNumberOfLinks!=1) {return Err("Public image opened reparse/type/hardlink refused".into());}
    Ok(Id{volume:id.VolumeSerialNumber,file:id.FileId.Identifier})
}
fn volume(file:&File)->Result<()> {
    let mut flags=0;let mut fs=[0u16;32];
    if unsafe{GetVolumeInformationByHandleW(file.as_raw_handle(),ptr::null_mut(),0,ptr::null_mut(),ptr::null_mut(),&mut flags,fs.as_mut_ptr(),32)}==0 {return Err("Public image volume readback refused".into());}
    let name=String::from_utf16(&fs[..fs.iter().position(|n|*n==0).ok_or("Public image filesystem bound")?]).map_err(|_|"Public image filesystem UTF16")?;
    if flags&8==0||name!="NTFS" {return Err("Public image requires local NTFS persistent ACLs".into());}Ok(())
}
fn sid_bytes(sid:*mut core::ffi::c_void)->Result<Vec<u8>>{
    if sid.is_null()||unsafe{IsValidSid(sid)}==0{return Err("Public image ACL SID refused".into());}
    let n=unsafe{GetLengthSid(sid)} as usize;if !(8..=68).contains(&n){return Err("Public image SID bound".into());}
    Ok(unsafe{std::slice::from_raw_parts(sid.cast::<u8>(),n)}.to_vec())
}
fn system_sids()->Result<Vec<Vec<u8>>>{
    let mut result=Vec::new();
    for sid in ["S-1-5-18","S-1-5-32-544","S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"]{
        let w:Vec<u16>=sid.encode_utf16().chain(Some(0)).collect();let mut raw=ptr::null_mut();
        if unsafe{ConvertStringSidToSidW(w.as_ptr(),&mut raw)}==0{return Err("Public image trusted OS SID decode".into());}
        let _allocation=Local(raw);result.push(sid_bytes(raw)?);
    }Ok(result)
}
// Only the exact retained volume-root ancestor may grant creation of unrelated
// subdirectories. Descendant and leaf policy stays stricter. DELETE and all
// replacement/security-descriptor rights remain checked, as in reviewed C8.
fn mutation_mask(volume_root:bool)->u32 { if volume_root {FOREIGN_MUTATION & !0x4} else {FOREIGN_MUTATION} }
fn permissions(file:&File,user:&[u8],leaf:bool,volume_root:bool)->Result<()> {
    let(mut owner,mut dacl,mut sd)=(ptr::null_mut(),ptr::null_mut(),ptr::null_mut());
    if unsafe{GetSecurityInfo(file.as_raw_handle(),SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION,&mut owner,ptr::null_mut(),&mut dacl,ptr::null_mut(),&mut sd)}!=0 {
        if !sd.is_null(){unsafe{LocalFree(sd);}}return Err("Public image native ACL readback refused".into());
    }
    let _allocation=Local(sd);if sd.is_null()||dacl.is_null(){return Err("Public image null security/DACL refused".into());}
    let os=system_sids()?;let trusted=|sid:&[u8]|sid==user||os.iter().any(|x|x==sid);
    let owner=sid_bytes(owner)?;
    if (leaf&&owner!=user)||(!leaf&&!trusted(&owner)){return Err("Public image owner mismatch".into());}
    let mut size:ACL_SIZE_INFORMATION=unsafe{zeroed()};
    if unsafe{GetAclInformation(dacl,(&mut size as *mut ACL_SIZE_INFORMATION).cast(),size_of::<ACL_SIZE_INFORMATION>() as u32,AclSizeInformation)}==0 || size.AceCount>256 || size.AclBytesInUse>65536 {return Err("Public image ACL bound".into());}
    for i in 0..size.AceCount{
        let mut raw=ptr::null_mut();if unsafe{GetAce(dacl,i,&mut raw)}==0||raw.is_null(){return Err("Public image ACE missing".into());}
        let ace=unsafe{&*raw.cast::<ACCESS_ALLOWED_ACE>()};
        if ace.Header.AceFlags&8!=0 || ace.Header.AceType==1 {continue;}
        if ace.Header.AceType!=0||ace.Header.AceSize<16||ace.Header.AceSize>76{return Err("Public image conditional/unknown ACE refused".into());}
        // SID count/extent is bounded inside this ACE before IsValidSid reads it.
        let sid_raw=unsafe{raw.cast::<u8>().add(8)};
        let subauthorities=unsafe{*sid_raw.add(1)} as usize;
        let sid_width=8usize.checked_add(4usize.checked_mul(subauthorities).ok_or("Public image SID width overflow")?).ok_or("Public image SID width overflow")?;
        if subauthorities>15||sid_width+8>ace.Header.AceSize as usize{return Err("Public image ACE SID width".into());}
        let sid=sid_bytes(sid_raw.cast())?;
        if sid.len()!=sid_width {return Err("Public image ACE SID native width differs".into());}
        if !trusted(&sid)&&ace.Mask&mutation_mask(volume_root)!=0 {return Err("Public image foreign-write/replace principal refused".into());}
    }Ok(())
}
fn final_path(file:&File,path:&Path)->Result<()> {
    let mut text=vec![0u16;32768];let n=unsafe{GetFinalPathNameByHandleW(file.as_raw_handle(),text.as_mut_ptr(),text.len() as u32,0)} as usize;
    if n==0||n>=text.len(){return Err("Public image opened final path bound".into());}
    let actual=String::from_utf16(&text[..n]).map_err(|_|"Public image final path UTF16")?;
    let expected=format!("\\\\?\\{}",path.to_str().ok_or("Public image path")?.replace('/',"\\"));
    if !actual.eq_ignore_ascii_case(&expected){return Err("Public image opened final path mismatch".into());}Ok(())
}
impl ImagePin {
    pub fn open(path:&Path,user:&[u8])->Result<Self>{
        strict(path)?;if !(8..=68).contains(&user.len()){return Err("Public image user SID bound".into());}
        let root=path.components().take(2).collect::<PathBuf>();if unsafe{GetDriveTypeW(wide(root.as_os_str()).as_ptr())}!=3{return Err("Public image nonlocal drive refused".into());}
        let mut entries=Vec::new();let mut prefix=PathBuf::new();let mut leaf_metadata=None;
        for component in path.components(){
            prefix.push(component.as_os_str());if matches!(component,Component::Prefix(_)){continue;}
            let directory=prefix!=path;
            if !directory{
                let metadata=open_leaf_metadata(&prefix)?;let id=inspect(&metadata,false)?;
                volume(&metadata)?;permissions(&metadata,user,true,false)?;final_path(&metadata,&prefix)?;
                leaf_metadata=Some(Entry{path:prefix.clone(),file:metadata,id,directory:false,volume_root:false});
            }
            let file=open(&prefix,directory)?;let id=inspect(&file,directory)?;
            if !directory&&leaf_metadata.as_ref().ok_or("Public metadata leaf absent")?.id!=id{return Err("Public image metadata/data native identity mismatch".into());}
            let volume_root=directory&&prefix==root;
            volume(&file)?;permissions(&file,user,!directory,volume_root)?;final_path(&file,&prefix)?;
            let again=open(&prefix,directory)?;if inspect(&again,directory)?!=id{return Err("Public image path substitution refused".into());}
            entries.push(Entry{path:prefix.clone(),file,id,directory,volume_root});
        }
        let image=&mut entries.last_mut().ok_or("Public image leaf absent")?.file;
        let length=image.metadata().map_err(|_|"Public image metadata")?.len();if length==0||length>MAX_IMAGE_BYTES{return Err("Public image size bound".into());}
        let mut h=Sha256::new();let mut count=0u64;let mut buf=[0u8;65536];
        loop{let n=image.read(&mut buf).map_err(|_|"Public image read")?;if n==0{break;}count+=n as u64;if count>length{return Err("Public image changed while hashing".into());}h.update(&buf[..n]);}
        if count!=length{return Err("Public image short hash read".into());}image.seek(SeekFrom::Start(0)).map_err(|_|"Public image seek")?;
        let result=Self{entries,leaf_metadata:leaf_metadata.ok_or("Public metadata leaf absent")?,hash:h.finalize().into(),owner:user.to_vec()};result.recheck()?;Ok(result)
    }
    /// Read the already-opened pinned leaf; no second path open is needed.
    /// Callers serialize use of this public metadata handle. Validate the bytes
    /// against the initial held hash and identities before returning them.
    pub fn read_bounded(&self,limit:u64)->Result<Vec<u8>>{
        let mut file=self.entries.last().ok_or("Public held leaf absent")?.file.try_clone().map_err(|_|"Public held leaf clone")?;
        let length=file.metadata().map_err(|_|"Public held length")?.len();
        if length>limit||limit>MAX_IMAGE_BYTES{return Err("Public held read allocation bound".into());}
        file.seek(SeekFrom::Start(0)).map_err(|_|"Public held read seek")?;
        let mut raw=Vec::new();file.take(limit+1).read_to_end(&mut raw).map_err(|_|"Public held read")?;
        let actual:[u8;32]=Sha256::digest(&raw).into();
        if raw.len() as u64!=length||actual!=self.hash{return Err("Public held bytes differ from pinned leaf".into());}
        self.recheck()?;Ok(raw)
    }
    pub fn hash(&self)->[u8;32]{self.hash}
    pub fn leaf_id(&self)->&Id{&self.entries.last().expect("initialized nonempty entries").id}
    #[cfg(test)]
    pub(crate) fn native_control_metadata_leaf_id(&self)->&Id{&self.leaf_metadata.id}
    pub fn recheck(&self)->Result<()>{
        let metadata=&self.leaf_metadata;
        if inspect(&metadata.file,false)?!=metadata.id{return Err("Held public metadata identity changed".into());}
        permissions(&metadata.file,&self.owner,true,false)?;final_path(&metadata.file,&metadata.path)?;
        let named_metadata=open_leaf_metadata(&metadata.path)?;
        if inspect(&named_metadata,false)?!=metadata.id||self.leaf_id()!=&metadata.id{return Err("Public image metadata named/data identity mismatch".into());}
        for e in &self.entries{
            if inspect(&e.file,e.directory)?!=e.id{return Err("Held public image identity changed".into());}
            permissions(&e.file,&self.owner,!e.directory,e.volume_root)?;final_path(&e.file,&e.path)?;
            let named=open(&e.path,e.directory)?;if inspect(&named,e.directory)?!=e.id{return Err("Public image named object substituted".into());}
        }Ok(())
    }
}

#[cfg(test)]
pub(crate) fn native_control_mutation_mask(volume_root:bool)->u32 {mutation_mask(volume_root)}

/// Held existing database identity. This lease permits the same user's actual
/// SQLite opens/writes with a read-data leaf hold but never DELETE sharing, aliases, links, reparses or
/// foreign mutation. It does not hash changing database contents or create files.
/// Only the passive NONSHIPPING module imports it. Ordinary image pins keep
/// their original read-only/no-WRITE-sharing policy unchanged.
struct DatabaseEntry {path:PathBuf,file:NativeFile,id:Id,directory:bool,volume_root:bool}
pub struct DatabasePin {entries:Vec<DatabaseEntry>,owner:Vec<u8>,revoked:std::cell::Cell<bool>}
fn open_database_lease(path:&Path,directory:bool)->Result<NativeFile>{
    strict(path)?;
    NativeFile::open(path,READ_CONTROL|FILE_READ_ATTRIBUTES|if directory{FILE_LIST_DIRECTORY}else{FILE_READ_DATA},
        FILE_SHARE_READ|FILE_SHARE_WRITE,FILE_FLAG_OPEN_REPARSE_POINT|if directory{FILE_FLAG_BACKUP_SEMANTICS}else{0})
}
fn database_named_identity(path:&Path,directory:bool,expected:&Id)->Result<()>{
    let mut named=open_database_lease(path,directory)?;
    let observed:Result<()>=(||{if inspect(named.file()?,directory)?!=*expected{return Err("Held DB pathname substituted".into());}Ok(())})();
    let closed=named.close_checked();
    match (observed,closed){(Ok(()),Ok(()))=>Ok(()),(primary,cleanup)=>Err(format!("Existing DB named check={primary:?}; once native close={cleanup:?}"))}
}
impl DatabasePin {
    /// Private scoped SQLite journal only. The actual owned handle, original
    /// ancestor leases, one-link/no-reparse NTFS identity, ACL and final path
    /// must all agree. This does not register another trusted filesystem root.
    pub(super) fn check_sqlite_journal(&self,file:&File,path:&Path)->Result<[u8;32]> {
        self.recheck()?;
        let main=self.entries.last().ok_or("Existing DB pin absent")?;
        let expected=PathBuf::from(format!("{}-journal",main.path.to_str().ok_or("Existing DB journal path")?));
        if path!=expected{return Err("Existing DB exact rollback journal namespace required".into());}
        strict(path)?;volume(file)?;let id=inspect(file,false)?;
        if id.volume!=main.id.volume{return Err("Existing DB journal volume differs".into());}
        permissions(file,&self.owner,true,false)?;final_path(file,path)?;
        let mut hash=Sha256::new();hash.update(b"MUTINY-W15-SQLITE-OPENED-JOURNAL-ID-V1");
        hash.update(id.volume.to_be_bytes());hash.update(id.file);Ok(hash.finalize().into())
    }
    // Private nonshipping future provider only. Same strict native identity/ACL
    // checks; these methods neither create a leaf nor broaden permissions/sharing.
    pub(super) fn check_opened(&self,file:&File)->Result<()> {
        self.recheck()?;let leaf=self.entries.last().ok_or("Existing DB pin absent")?;
        if inspect(file,false)?!=leaf.id{return Err("Existing DB additional handle is not retained native identity".into());}
        permissions(file,&self.owner,true,false)?;final_path(file,&leaf.path)?;Ok(())
    }
    pub(super) fn native_id_hash(&self)->[u8;32] {
        let leaf=&self.entries.last().expect("initialized DB pin").id;
        let mut h=Sha256::new();h.update(b"MUTINY-W15-SYNTHETIC-SIGNER-NATIVE-ID-V1");h.update(leaf.volume.to_be_bytes());h.update(leaf.file);h.finalize().into()
    }
    pub fn open(path:&Path,user:&[u8])->Result<Self>{
        native_handle_owner::require_known()?;strict(path)?;if !(8..=68).contains(&user.len()){return Err("Existing DB SID bound".into());}
        let root=path.components().take(2).collect::<PathBuf>();
        if unsafe{GetDriveTypeW(wide(root.as_os_str()).as_ptr())}!=3{return Err("Existing DB nonlocal drive refused".into());}
        let mut entries=Vec::new();let mut prefix=PathBuf::new();
        for component in path.components(){prefix.push(component.as_os_str());if matches!(component,Component::Prefix(_)){continue;}
            let directory=prefix!=path;let file=open_database_lease(&prefix,directory)?;
            let id=inspect(file.file()?,directory)?;let volume_root=directory&&prefix==root;
            volume(file.file()?)?;permissions(file.file()?,user,!directory,volume_root)?;final_path(file.file()?,&prefix)?;
            database_named_identity(&prefix,directory,&id)?;
            entries.push(DatabaseEntry{path:prefix.clone(),file,id,directory,volume_root});
        }
        if entries.last().is_none_or(|e|e.directory){return Err("Existing DB leaf absent".into());}
        let out=Self{entries,owner:user.to_vec(),revoked:std::cell::Cell::new(false)};out.recheck()?;Ok(out)
    }
    pub fn recheck(&self)->Result<()>{
        native_handle_owner::require_known()?;
        if self.revoked.get(){return Err("Existing DB pin revoked before native cleanup".into());}
        for e in &self.entries{
            if inspect(e.file.file()?,e.directory)?!=e.id{return Err("Held existing DB native identity changed".into());}
            permissions(e.file.file()?,&self.owner,!e.directory,e.volume_root)?;final_path(e.file.file()?,&e.path)?;
            database_named_identity(&e.path,e.directory,&e.id)?;
        }Ok(())
    }
    pub(super) fn close_checked(&mut self)->Result<()>{
        if self.revoked.replace(true){return Err("Existing DB pin cleanup already attempted; no retry".into());}
        let mut errors=Vec::new();
        for e in self.entries.iter_mut().rev(){if let Err(error)=e.file.close_checked(){errors.push(format!("{}: {error}",e.path.display()));}}
        if errors.is_empty(){Ok(())}else{Err(format!("Existing DB independent once-close refusals: {errors:?}"))}
    }
    #[cfg(test)] pub(super) fn native_close_traces(&self)->Vec<native_handle_owner::CloseTrace>{self.entries.iter().map(|e|e.file.trace()).collect()}
    #[cfg(test)] pub(super) fn model_lost_leaf_close_ack(&mut self){self.entries.last_mut().unwrap().file.model_lost_ack();}
}
impl Drop for DatabasePin{fn drop(&mut self){if !self.revoked.get(){let _=self.close_checked();}}}

/// Existing PUBLIC archive-directory lease. All ancestors plus the empty leaf
/// retain FILE_LIST_DIRECTORY/no DELETE sharing; no child sentinel is required.
/// This owner neither creates a path nor mutates owner/DACL or directory members.
pub(super) struct DirectoryPin {entries:Vec<Entry>,owner:Vec<u8>}
impl DirectoryPin {
 pub(super) fn open(path:&Path,user:&[u8])->Result<Self>{
  strict(path)?;if !(8..=68).contains(&user.len()){return Err("Existing directory SID bound".into());}
  let root=path.components().take(2).collect::<PathBuf>();
  if unsafe{GetDriveTypeW(wide(root.as_os_str()).as_ptr())}!=3{return Err("Existing directory nonlocal drive refused".into());}
  let mut entries=Vec::new();let mut prefix=PathBuf::new();
  for component in path.components(){prefix.push(component.as_os_str());if matches!(component,Component::Prefix(_)){continue;}
   let file=open(&prefix,true)?;let id=inspect(&file,true)?;let volume_root=prefix==root;
   volume(&file)?;permissions(&file,user,false,volume_root)?;final_path(&file,&prefix)?;
   let named=open(&prefix,true)?;if inspect(&named,true)?!=id{return Err("Original directory substitution refused".into());}
   entries.push(Entry{path:prefix.clone(),file,id,directory:true,volume_root});
  }
  if entries.is_empty(){return Err("Existing directory absent".into());}
  let out=Self{entries,owner:user.to_vec()};out.recheck()?;Ok(out)
 }
 pub(super) fn native_id_hash(&self)->[u8;32]{let id=&self.entries.last().expect("held directory").id;
  let mut h=Sha256::new();h.update(b"MUTINY-W15-ORIGINAL-ARCHIVE-DIRECTORY-ID-V1");h.update(id.volume.to_be_bytes());h.update(id.file);h.finalize().into()}
 pub(super) fn recheck(&self)->Result<()>{for e in &self.entries{
  if inspect(&e.file,true)?!=e.id{return Err("Original held directory identity changed".into());}
  permissions(&e.file,&self.owner,false,e.volume_root)?;final_path(&e.file,&e.path)?;
  if inspect(&open(&e.path,true)?,true)?!=e.id{return Err("Original named directory substituted".into());}
 }Ok(())}
}

#[cfg(test)]
mod passive_database_pin_tests {
    use super::*;
    fn assert_actual_missing(path:&Path){
        let error=std::fs::symlink_metadata(path).expect_err("Actual TEST path must be absent");
        assert_eq!(error.kind(),std::io::ErrorKind::NotFound,"Absence cannot be inferred from permissions/other IO refusal");
    }

    #[test]
    fn actual_existing_database_lease_allows_own_sqlite_and_refuses_rename_delete_or_missing_leaf(){
        let id=super::super::process_auth::VerifiedProcess::observe_created_process(std::process::id()).unwrap();
        let nonce=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let root=std::env::temp_dir().join(format!("w15-existing-db-pin-{}-{nonce}",std::process::id()));
        assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&root).unwrap());
        let path=root.join("existing-public.sqlite");
        let db=rusqlite::Connection::open(&path).unwrap();db.execute_batch("CREATE TABLE retained(value INTEGER);INSERT INTO retained VALUES(1);").unwrap();drop(db);
        let before=std::fs::read(&path).unwrap();
        let held=DatabasePin::open(&path,&id.user_sid).unwrap();
        let replaced=root.join("replaced.sqlite");
        let rename_error=std::fs::rename(&path,&replaced).expect_err("Held DB must refuse actual rename");
        let delete_error=std::fs::remove_file(&path).expect_err("Held DB must refuse actual delete");
        println!("Actual held database rename/delete errors {:?}/{:?}",rename_error.raw_os_error(),delete_error.raw_os_error());
        assert_eq!(rename_error.raw_os_error(),Some(32)); // ERROR_SHARING_VIOLATION, not a missing/ACL false positive.
        assert_eq!(delete_error.raw_os_error(),Some(32));
        assert!(std::fs::symlink_metadata(&path).unwrap().is_file());assert_actual_missing(&replaced);held.recheck().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(),before);
        let own=rusqlite::Connection::open(&path).unwrap();own.execute("UPDATE retained SET value=2",[]).unwrap();drop(own);
        held.recheck().unwrap();assert_ne!(std::fs::read(&path).unwrap(),before);
        assert!(DatabasePin::open(&root.join("missing.sqlite"),&id.user_sid).is_err());
        assert_actual_missing(&root.join("missing.sqlite"));
        drop(held);
        // A positive after-release control proves permissions permit the exact
        // rename/delete; no existing ACL or original campaign DB is changed.
        std::fs::rename(&path,&replaced).unwrap();assert_actual_missing(&path);assert!(std::fs::symlink_metadata(&replaced).unwrap().is_file());
        std::fs::rename(&replaced,&path).unwrap();
        let disposable=root.join("delete-positive-public.txt");
        std::fs::write(&disposable,b"public after-release delete control").unwrap();
        std::fs::remove_file(&disposable).unwrap();assert_actual_missing(&disposable);
        assert!(std::fs::symlink_metadata(&path).unwrap().is_file());
        // New public test-owned evidence stays retained on both success/failure.
        // This proves only native existing-file continuity/own write sharing;
        // canonical finality/custody/reparse/foreign ACL tests are separate.
    }
}

#[cfg(test)]
mod directory_pin_tests {
    use super::*;
    fn missing(path:&Path){
        assert_eq!(std::fs::symlink_metadata(path).expect_err("Exact target absent").kind(),std::io::ErrorKind::NotFound);
    }
    #[test]
    fn actual_empty_directory_read_data_lease_refuses_rename_without_child_sentinel(){
        let id=super::super::process_auth::VerifiedProcess::observe_created_process(std::process::id()).unwrap();
        let nonce=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let root=std::env::temp_dir().join(format!("w15-empty-directory-lease-{}-{nonce}",std::process::id()));
        assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&root).unwrap());
        let original=root.join("empty-original");let renamed=root.join("empty-renamed");
        assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&original).unwrap());
        assert_eq!(std::fs::read_dir(&original).unwrap().count(),0,"No leaf or child sentinel may prevent this rename");missing(&renamed);
        let lease=open(&original,true).unwrap();let native=inspect(&lease,true).unwrap();
        volume(&lease).unwrap();permissions(&lease,&id.user_sid,false,false).unwrap();final_path(&lease,&original).unwrap();
        let error=std::fs::rename(&original,&renamed).expect_err("A genuine held empty directory must refuse rename");
        println!("Actual independent empty-directory rename native error {:?}",error.raw_os_error());
        assert_eq!(error.raw_os_error(),Some(32),"ERROR_SHARING_VIOLATION, not ACL/type/absence");
        assert_eq!(inspect(&lease,true).unwrap(),native);missing(&renamed);
        assert_eq!(std::fs::read_dir(&original).unwrap().count(),0);
        let named=open(&original,true).unwrap();assert_eq!(inspect(&named,true).unwrap(),native);drop(named);drop(lease);
        std::fs::rename(&original,&renamed).expect("Release control proves exact original permissions permit rename");
        missing(&original);assert_eq!(std::fs::read_dir(&renamed).unwrap().count(),0);
        std::fs::rename(&renamed,&original).unwrap();missing(&renamed);
        // Both empty directories/public evidence are retained; no ACL mutation,
        // deletion, original campaign DB or private credential is involved.
    }
}
