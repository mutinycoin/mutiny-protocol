//! TEST-VALUE descriptors exercise the actual shared validator and new exact
//! permissions predicate. They do not authenticate package or filesystem state.
use super::{close_security,fixed_sid,known,validate_original_security,PublicClass,SecurityOwner,SecurityRecord};
use std::{ffi::c_void,ptr};
type Result<T>=std::result::Result<T,String>;
#[link(name="kernel32")]
unsafe extern "system"{fn LocalAlloc(flags:u32,bytes:usize)->*mut c_void;}
fn exercise(wrong_owner:bool,wrong_permissions:bool)->Result<Result<()>>{
 known()?;let user=crate::policy::SID.to_vec();
 let owner=if wrong_owner{user.clone()}else{fixed_sid(5,&[18])};
 let rows=[(fixed_sid(5,&[18]),0x1f01ffu32),(fixed_sid(5,&[32,544]),0x1f01ff),
  (fixed_sid(5,&[32,545]),if wrong_permissions{0x120089}else{0x1200a9}),
  (fixed_sid(15,&[2,1]),0x1200a9),(fixed_sid(15,&[2,2]),0x1200a9)];
 let mut acl=vec![2,0,0,0,5,0,0,0];
 for(sid,mask)in rows{acl.extend_from_slice(&[0,16]);acl.extend_from_slice(&((8+sid.len()) as u16).to_le_bytes());
  acl.extend_from_slice(&mask.to_le_bytes());acl.extend_from_slice(&sid);}
 let length=acl.len() as u16;acl[2..4].copy_from_slice(&length.to_le_bytes());
 let mut custody=SecurityOwner{record:Some(Box::new(SecurityRecord{next:0,raw:0,attempted:false,outcome:None}))};
 let allocation=unsafe{LocalAlloc(0x40,1024)};custody.record.as_mut().unwrap().raw=allocation as usize;
 if allocation.is_null(){return Err("CRT TEST bounded LocalAlloc failed".into());}
 let owner_pointer=unsafe{allocation.cast::<u8>().add(64)};let acl_pointer=unsafe{allocation.cast::<u8>().add(256)};
 unsafe{ptr::copy_nonoverlapping(owner.as_ptr(),owner_pointer,owner.len());ptr::copy_nonoverlapping(acl.as_ptr(),acl_pointer,acl.len());}
 let primary=validate_original_security(0,owner_pointer.cast(),acl_pointer.cast(),allocation,&user,
  Some(PublicClass::InstalledSystem32Vcruntime),false).map(|_|());
 let close=close_security(&mut custody);if let Err(error)=close{return Err(format!("CRT TEST descriptor once-close={error}; primary={primary:?}"));}
 known()?;Ok(primary)
}
#[test]fn approved_system_owner_permissions_value_positive(){exercise(false,false).unwrap().unwrap();}
#[test]fn wrong_observed_crt_owner_value_refused(){assert_eq!(exercise(true,false).unwrap(),Err("Installed CRT owner is not exact SYSTEM".into()));}
#[test]fn wrong_observed_crt_permissions_value_refused(){assert_eq!(exercise(false,true).unwrap(),Err("Installed CRT observed permissions differ from approved SYSTEM/admin FULL and users/apps READ".into()));}
