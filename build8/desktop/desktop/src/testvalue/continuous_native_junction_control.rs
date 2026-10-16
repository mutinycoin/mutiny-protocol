//! EXTERNAL SOURCE ONLY. New TEST-owned junction; no existing path/ACL mutation.
//! Included ONLY by the NONSHIPPING native control test module.
#![cfg(test)]
use std::{os::windows::{ffi::OsStrExt,io::{FromRawHandle,AsRawHandle}},path::Path,ptr};
use windows_sys::Win32::{Storage::FileSystem::{CreateFileW,FILE_FLAG_OPEN_REPARSE_POINT,FILE_FLAG_BACKUP_SEMANTICS,FILE_SHARE_READ,FILE_SHARE_WRITE,OPEN_EXISTING},Foundation::INVALID_HANDLE_VALUE,System::IO::DeviceIoControl};
pub fn create_new_junction(leaf:&Path,target:&Path)->Result<(),String>{
    if leaf.exists()||!leaf.is_absolute()||!target.is_absolute()||!target.is_dir(){return Err("Only one new absolute TEST junction to existing task-owned target".into());}
    if !mutiny_consensus_v8::submission_pool_v1::private_directory(leaf).map_err(|e|format!("{e:?}"))?{return Err("New junction leaf not owned by this invocation".into());}
    let text=target.to_str().ok_or("Native TEST junction target UTF16 scope")?;
    if !text.is_ascii()||text.len()>4096{return Err("Native TEST junction target bound".into());}
    let target=text.replace('/',"\\");let sub=format!("\\??\\{target}");
    let sub=sub.encode_utf16().collect::<Vec<_>>();let print=target.encode_utf16().collect::<Vec<_>>();
    let sub_bytes:u16=(2*sub.len()).try_into().map_err(|_|"Junction substitute bound")?;
    let print_bytes:u16=(2*print.len()).try_into().map_err(|_|"Junction print bound")?;
    let mut data=Vec::new();data.extend_from_slice(&0xA0000003u32.to_le_bytes());
    let payload:u16=(8+2*(sub.len()+1+print.len()+1)).try_into().map_err(|_|"Junction data bound")?;
    data.extend_from_slice(&payload.to_le_bytes());data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());data.extend_from_slice(&sub_bytes.to_le_bytes());
    data.extend_from_slice(&(sub_bytes+2).to_le_bytes());data.extend_from_slice(&print_bytes.to_le_bytes());
    for c in sub.into_iter().chain(Some(0)).chain(print).chain(Some(0)){data.extend_from_slice(&c.to_le_bytes());}
    if data.len()>16384{return Err("Junction reparse bound".into());}
    let path:Vec<u16>=leaf.as_os_str().encode_wide().chain(Some(0)).collect();
    let h=unsafe{CreateFileW(path.as_ptr(),0x40000000,FILE_SHARE_READ|FILE_SHARE_WRITE,ptr::null(),OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_BACKUP_SEMANTICS,ptr::null_mut())};
    if h==INVALID_HANDLE_VALUE||h.is_null(){return Err("New TEST junction native open failed".into());}
    let file=unsafe{std::fs::File::from_raw_handle(h)};let mut returned=0;
    if unsafe{DeviceIoControl(file.as_raw_handle(),0x000900A4,data.as_ptr().cast(),data.len() as u32,ptr::null_mut(),0,&mut returned,ptr::null_mut())}==0{return Err("New TEST junction native reparse creation refused".into());}
    Ok(()) // No cleanup/delete. Both parent, junction and target are preserved.
}
