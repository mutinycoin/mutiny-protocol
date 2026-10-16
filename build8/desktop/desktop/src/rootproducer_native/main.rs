//! Isolated monolithic native TEST Root A. No production issuer or signer.
#![cfg(all(windows,target_arch="x86_64",feature="native-owner-test",feature="testvalue-window"))]
#[path="continuous_native_handle_owner.rs"]pub(crate) mod native_handle_owner;
mod image_pin{pub(crate) use crate::native_handle_owner;}
#[path="continuous_own_native_files.rs"]mod own_native_files;
#[path="continuous_own_native_modules.rs"]mod own_native_modules;
#[path="continuous_own_native_token.rs"]mod own_native_token;
#[path="continuous_own_native_facade.rs"]mod own_native_facade;
mod owned;mod job;mod pe;mod pipe;mod policy;mod launch;mod bootstrap;mod installed_vcruntime;
use sha2::{Digest,Sha256};use serde_json::{Value,json};use owned::{Handle,Owned,Kind};
use std::{ffi::c_void,ptr::null_mut,panic::{catch_unwind,AssertUnwindSafe}};
type Result<T>=std::result::Result<T,String>;
fn need(ok:bool,why:&str)->Result<()>{if ok{Ok(())}else{Err(why.into())}}
fn hash(bytes:&[u8])->[u8;32]{Sha256::digest(bytes).into()}
fn sha(bytes:&[u8])->String{hex::encode(hash(bytes))}
struct BoundedOutput{bytes:Vec<u8>,cap:usize}
impl std::io::Write for BoundedOutput{
 fn write(&mut self,part:&[u8])->std::io::Result<usize>{if part.len()>self.cap.saturating_sub(self.bytes.len()){return Err(std::io::Error::other("whole JSON bound before allocation"))}self.bytes.extend_from_slice(part);Ok(part.len())}
 fn flush(&mut self)->std::io::Result<()>{Ok(())}
}
fn json_bytes(value:&Value,cap:usize)->Result<Vec<u8>>{let mut output=BoundedOutput{bytes:Vec::new(),cap};serde_json::to_writer(&mut output,value).map_err(|e|e.to_string())?;Ok(output.bytes)}
fn token_json(t:&own_native_token::OwnTokenFacts)->Value{json!({"pid":t.pid,"process_start_filetime":t.process_start_filetime,"user_sid_hex":hex::encode(&t.user_sid),"token_id_low":t.token_id.low,"token_id_high":t.token_id.high,"authentication_id_low":t.authentication_id.low,"authentication_id_high":t.authentication_id.high,"modified_id_low":t.modified_id.low,"modified_id_high":t.modified_id.high,"session":t.session,"elevation_type":t.elevation_type,"elevated":t.elevated,"integrity_sid_hex":hex::encode(&t.integrity_sid),"restricted":t.restricted,"app_container":t.app_container})}
fn same_role(a:&own_native_token::OwnTokenFacts,b:&own_native_token::OwnTokenFacts)->Result<()>{need(a.user_sid==policy::SID&&b.user_sid==a.user_sid&&a.authentication_id==b.authentication_id&&a.session==b.session&&a.elevation_type==b.elevation_type&&a.elevated==b.elevated&&a.integrity_sid==b.integrity_sid&&!a.restricted&&!b.restricted&&!a.app_container&&!b.app_container,"actual selected same TEST principal/logon/session/profile")}
#[link(name="bcrypt")]unsafe extern "system"{fn BCryptGenRandom(algorithm:Handle,bytes:*mut u8,count:u32,flags:u32)->i32;}
fn instance()->Result<String>{let mut public_instance=[0u8;16];need(unsafe{BCryptGenRandom(null_mut(),public_instance.as_mut_ptr(),16,2)}==0,"actual fresh public pipe instance")?;Ok(hex::encode(public_instance))}
#[link(name="kernel32")]unsafe extern "system"{
 fn CreateFileW(path:*const u16,access:u32,share:u32,attributes:Handle,creation:u32,flags:u32,template:Handle)->Handle;
 fn WriteFile(h:Handle,bytes:*const c_void,count:u32,written:*mut u32,overlap:Handle)->i32;
 fn FlushFileBuffers(h:Handle)->i32;
}
fn write_new(path:&str,bytes:&[u8])->Result<()>{
 policy::strict(path)?;need(!bytes.is_empty()&&bytes.len()<=67108864,"finite CreateNew public output")?;owned::known()?;
 let wide:Vec<u16>=path.encode_utf16().chain(Some(0)).collect();let mut file=Owned::empty(Kind::Capture);
 file.attach(unsafe{CreateFileW(wide.as_ptr(),0x40000000,1,null_mut(),1,0x80,null_mut())})?;
 let operation:Result<()>=(||{for chunk in bytes.chunks(65536){let mut n=0;need(unsafe{WriteFile(file.raw()?,chunk.as_ptr().cast(),chunk.len() as u32,&mut n,null_mut())}!=0&&n as usize==chunk.len(),"original public output complete write")?}need(unsafe{FlushFileBuffers(file.raw()?)}!=0,"original public output flush")})();
 let close=file.close_checked();need(operation.is_ok()&&close.is_ok(),&format!("original CreateNew output operation={operation:?}; once close={close:?}"))
}
fn dispatch()->Result<()>{let args:Vec<_>=std::env::args().collect();match args.as_slice(){[_]=>bootstrap::outer(),[_,inner] if inner=="--native-root-inner"=>bootstrap::inner(),_=>Err("source-owned native Root admits only fixed recipe or exact original inner entry".into())}}
fn main(){let outcome=catch_unwind(AssertUnwindSafe(dispatch));let result=match outcome{Ok(r)=>r,Err(_)=>{owned::mark_unknown();Err("native Root unwind; originals UNKNOWN, no retry/reset".into())}};if let Err(error)=result{eprintln!("NATIVE_ROOT_TEST_REFUSED {error}");std::process::exit(1)}}
