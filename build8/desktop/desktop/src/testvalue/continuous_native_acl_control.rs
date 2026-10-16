//! SOURCE ONLY. Native TEST creation with a fixed foreign grant on ONE NEW directory.
//! Never changes an existing ACL, requests privileges or deletes evidence.
#![cfg(test)]
use std::{path::Path,ptr};
use windows_sys::Win32::{Foundation::LocalFree,Security::{SECURITY_ATTRIBUTES,
    Authorization::{ConvertSidToStringSidW,ConvertStringSecurityDescriptorToSecurityDescriptorW,
        ConvertSecurityDescriptorToStringSecurityDescriptorW,GetSecurityInfo,SE_FILE_OBJECT},
    OWNER_SECURITY_INFORMATION,DACL_SECURITY_INFORMATION},Storage::FileSystem::CreateDirectoryW};
type Result<T>=std::result::Result<T,String>;
struct Local(*mut core::ffi::c_void);
impl Drop for Local{fn drop(&mut self){unsafe{LocalFree(self.0);}}}
unsafe fn bounded_string(p:*const u16)->Result<String>{
    if p.is_null(){return Err("Native TEST security string missing".into());}
    let mut n=0;while n<65536&&unsafe{*p.add(n)}!=0{n+=1;}
    if n==65536{return Err("Native TEST security string bound".into());}
    String::from_utf16(unsafe{std::slice::from_raw_parts(p,n)}).map_err(|_|"Native TEST security UTF16".into())
}
pub fn create_new_foreign_directory(path:&Path,user:&[u8],mask:u32)->Result<()> {
    let allowed=[0x2,0x4,0x10,0x40,0x100,0x10000,0x40000,0x80000,0x10000000,0x40000000];
    if !allowed.contains(&mask)||!path.is_absolute()||path.exists()||!(8..=68).contains(&user.len()) {return Err("One exact NEW native foreign-grant TEST directory required".into());}
    let parent=path.parent().ok_or("TEST parent missing")?;
    if !parent.is_dir()||mutiny_consensus_v8::submission_pool_v1::private_directory(parent).map_err(|e|format!("{e:?}"))?{return Err("Existing protected task-owned TEST parent required unchanged".into());}
    let mut sid=ptr::null_mut();
    if unsafe{ConvertSidToStringSidW(user.as_ptr().cast_mut().cast(),&mut sid)}==0{return Err("Native TEST current SID stringify".into());}
    let _sid=Local(sid.cast());let sid=unsafe{bounded_string(sid)}?;
    let text=format!("O:{sid}D:P(A;;FA;;;SY)(A;;FA;;;{sid})(A;;0x{mask:x};;;AU)");
    let descriptor=text.encode_utf16().chain(Some(0)).collect::<Vec<_>>();let mut sd=ptr::null_mut();
    if unsafe{ConvertStringSecurityDescriptorToSecurityDescriptorW(descriptor.as_ptr(),1,&mut sd,ptr::null_mut())}==0{return Err("Native TEST fixed descriptor parse".into());}
    let _sd=Local(sd);let attrs=SECURITY_ATTRIBUTES{nLength:std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,lpSecurityDescriptor:sd,bInheritHandle:0};
    let path=path.to_str().ok_or("TEST path Unicode")?.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    if unsafe{CreateDirectoryW(path.as_ptr(),&attrs)}==0{return Err("Native NEW foreign-grant TEST directory creation".into());}Ok(())
}
pub fn security_snapshot(path:&Path)->Result<String>{
    use std::os::windows::io::{AsRawHandle,FromRawHandle};
    use windows_sys::Win32::{Foundation::INVALID_HANDLE_VALUE,Storage::FileSystem::{CreateFileW,READ_CONTROL,FILE_FLAG_OPEN_REPARSE_POINT,FILE_FLAG_BACKUP_SEMANTICS,FILE_SHARE_READ,FILE_SHARE_WRITE,OPEN_EXISTING}};
    let raw=path.to_str().ok_or("TEST path Unicode")?.encode_utf16().chain(Some(0)).collect::<Vec<_>>();
    let handle=unsafe{CreateFileW(raw.as_ptr(),READ_CONTROL,FILE_SHARE_READ|FILE_SHARE_WRITE,ptr::null(),OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,ptr::null_mut())};
    if handle==INVALID_HANDLE_VALUE||handle.is_null(){return Err("Native TEST security snapshot open".into());}
    let file=unsafe{std::fs::File::from_raw_handle(handle)};let flags=OWNER_SECURITY_INFORMATION|DACL_SECURITY_INFORMATION;let mut sd=ptr::null_mut();
    if unsafe{GetSecurityInfo(file.as_raw_handle(),SE_FILE_OBJECT,flags,ptr::null_mut(),ptr::null_mut(),ptr::null_mut(),ptr::null_mut(),&mut sd)}!=0{return Err("Native TEST security snapshot read".into());}
    let _sd=Local(sd);let mut text=ptr::null_mut();
    if unsafe{ConvertSecurityDescriptorToStringSecurityDescriptorW(sd,1,flags,&mut text,ptr::null_mut())}==0{return Err("Native TEST security snapshot string".into());}
    let _text=Local(text.cast());unsafe{bounded_string(text)}
}
