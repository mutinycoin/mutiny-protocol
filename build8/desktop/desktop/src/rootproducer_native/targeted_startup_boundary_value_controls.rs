//! TEST-only shared startup acquisition-barrier controls.
//! Memory continuation entry is not protected functionality or end-to-end startup.
//! No channel, Job, child, anchor, signer, provider or activation operation is run.
use super::after_original_acquisition;
use crate::own_native_files::security_value_controls::{exercise,Case};
use std::cell::Cell;
#[test]
fn refused_actual_security_values_never_enter_shared_startup_continuation(){
 for (case,reason) in [
  (Case::MissingDacl,"Own public original security read refused 0"),
  (Case::InvalidOwnerSid,"Own public native SID invalid"),
  (Case::ForeignMutation,"Own public foreign mutation/delete/security authority refused"),
 ]{
  let entered=Cell::new(0u32);
  let outcome=after_original_acquisition(||exercise(case)?,|()|{entered.set(entered.get()+1);Ok(())});
  assert_eq!(outcome.unwrap_err(),reason);
  assert_eq!(entered.get(),0,"failed acquisition must never enter the real shared continuation boundary");
 }
}
#[test]
fn valid_security_value_enters_shared_startup_continuation_once(){
 let entered=Cell::new(0u32);
 after_original_acquisition(||exercise(Case::Valid)?,|()|{entered.set(entered.get()+1);Ok(())}).unwrap();
 assert_eq!(entered.get(),1,"positive control proves the same continuation can be observed");
}
