//! Isolated TEST-VALUE memory inputs to the production security validator.
//! No public-file open, filesystem ACL mutation, DLL load or protected activation.
//! These are security-value tests, not original-descriptor/native-read evidence.
use super::{close_security,fixed_sid,known,validate_original_security,PublicClass,SecurityOwner,SecurityRecord};
use std::{ffi::c_void,ptr};
type Result<T>=std::result::Result<T,String>;
#[link(name="kernel32")]
unsafe extern "system"{fn LocalAlloc(flags:u32,bytes:usize)->*mut c_void;}
#[derive(Clone,Copy,Debug)]
pub(crate) enum Case{Valid,SecurityStatus,MissingDacl,InvalidOwnerSid,AclBound,
 UnsupportedEffectiveAce,ForeignMutation,OwnOwner,SystemOwner,ForeignRead}
fn child_user()->Vec<u8>{fixed_sid(5,&[21,2588165551,1705744427,3256592067,1001])}
fn ace(kind:u8,flags:u8,mask:u32,sid:&[u8])->Vec<u8>{
 let length=8+sid.len();assert!((16..=76).contains(&length));
 let mut bytes=vec![kind,flags];bytes.extend_from_slice(&(length as u16).to_le_bytes());
 bytes.extend_from_slice(&mask.to_le_bytes());bytes.extend_from_slice(sid);bytes
}
/// Returns the exact validator result only after independent once-only native
/// LocalFree succeeds. A setup/cleanup error cannot earn a negative-control pass.
pub(crate) fn exercise(case:Case)->Result<Result<()>>{
 known()?;let user=child_user();let system=fixed_sid(5,&[18]);let everyone=fixed_sid(1,&[0]);
 let mut owner=match case{Case::OwnOwner|Case::SystemOwner=>system.clone(),_=>user.clone()};
 if matches!(case,Case::InvalidOwnerSid){owner[0]=0;}
 let mut aces=vec![ace(0,0,0x1f01ff,&system),ace(0,0,0x1f01ff,&user)];
 if matches!(case,Case::UnsupportedEffectiveAce){aces[0][0]=2;}
 if matches!(case,Case::ForeignMutation){aces.push(ace(0,0,2,&everyone));}
 if matches!(case,Case::ForeignRead){aces.push(ace(0,0,0x1200a9,&everyone));}
 let length=8+aces.iter().map(Vec::len).sum::<usize>();assert!(length<=768&&owner.len()<=68);
 let count=if matches!(case,Case::AclBound){257u16}else{aces.len() as u16};
 let mut acl=vec![2,0];acl.extend_from_slice(&(length as u16).to_le_bytes());
 acl.extend_from_slice(&count.to_le_bytes());acl.extend_from_slice(&[0,0]);for item in aces{acl.extend(item);}
 let mut custody=SecurityOwner{record:Some(Box::new(SecurityRecord{next:0,raw:0,attempted:false,outcome:None}))};
 let allocation=unsafe{LocalAlloc(0x40,1024)};
 custody.record.as_mut().unwrap().raw=allocation as usize;
 if allocation.is_null(){return Err("TEST-only bounded original LocalAlloc failed".into());}
 let owner_ptr=unsafe{allocation.cast::<u8>().add(64)};
 let acl_ptr=unsafe{allocation.cast::<u8>().add(256)};
 unsafe{ptr::copy_nonoverlapping(owner.as_ptr(),owner_ptr,owner.len());ptr::copy_nonoverlapping(acl.as_ptr(),acl_ptr,acl.len());}
 let dacl=if matches!(case,Case::MissingDacl){ptr::null_mut()}else{acl_ptr.cast::<windows_sys::Win32::Security::ACL>()};
 let status=if matches!(case,Case::SecurityStatus){5}else{0};
 let leaf=if matches!(case,Case::SystemOwner){PublicClass::System32Dll}else{PublicClass::OwnTestImage};
 let primary=validate_original_security(status,owner_ptr.cast(),dacl,allocation,&user,Some(leaf),false).map(|_|());
 let close=close_security(&mut custody);
 if let Err(cleanup)=close{return Err(format!("TEST descriptor closure failed independently: {cleanup}; primary={primary:?}"));}
 known()?;Ok(primary)
}
fn refused(case:Case,reason:&str){
 let actual=exercise(case).expect("native fixture setup and once-only descriptor close");
 assert_eq!(actual.expect_err("existing security check must refuse"),reason);
}
#[test]fn security_value_valid_owner_and_acl_accepted(){exercise(Case::Valid).unwrap().unwrap();}
#[test]fn security_value_failed_native_status_refused(){refused(Case::SecurityStatus,"Own public original security read refused 5");}
#[test]fn security_value_missing_dacl_refused(){refused(Case::MissingDacl,"Own public original security read refused 0");}
#[test]fn security_value_invalid_owner_sid_refused(){refused(Case::InvalidOwnerSid,"Own public native SID invalid");}
#[test]fn security_value_acl_count_bound_refused(){refused(Case::AclBound,"Own public native ACL bound");}
#[test]fn security_value_unsupported_effective_ace_refused(){refused(Case::UnsupportedEffectiveAce,"Own public conditional or unsupported effective ACE");}
#[test]fn security_value_foreign_effective_mutation_refused(){refused(Case::ForeignMutation,"Own public foreign mutation/delete/security authority refused");}
#[test]fn security_value_foreign_read_keeps_existing_policy(){exercise(Case::ForeignRead).unwrap().unwrap();}
#[test]fn security_value_wrong_own_image_owner_refused(){refused(Case::OwnOwner,"Own TEST image owner differs from selected child account");}
#[test]fn security_value_system_owner_not_trustedinstaller_refused(){refused(Case::SystemOwner,"Own System32 DLL owner is not exact TrustedInstaller");}
