//! NativeOwnerTest process receiver and provider lifetime. No NORMAL issuer.
//! Selection is a private trusted-launcher seam, not a peer/GUI/serde DTO.
//! It must be formed from Root-admitted actual evidence before this receiver
//! is called. A plan hash or a caller-provided eligibility bool is insufficient.
#![cfg(all(windows,target_arch="x86_64",feature="native-owner-test"))]
use super::own_native_facade::{AdmittedTestInputs,OwnExecutionLease};
use std::{rc::Rc,path::Path};
type Result<T>=std::result::Result<T,String>;
struct UnjoinedRecord{owner:Option<Rc<OwnExecutionLease>>}
/// Private installation/launcher-selected input. There is deliberately no
/// deserialize, public constructor, process-global setter or ambient fallback.
pub(super) struct RootSelectedDriverInput{inputs:AdmittedTestInputs}
impl RootSelectedDriverInput{
 /// # Safety
 /// The trusted launcher factory must authenticate the complete original PE
 /// projection and independently admitted genuine Rust ABI evidence described
 /// by AdmittedTestInputs/open_admitted_test. It must bind THIS own process's
 /// primary token, exact artifact/source and campaign. Neither raw declaration
 /// records nor receipt hashes establish this. Missing evidence must refuse;
 /// this constructor must never be called from GUI/peer request decoding.
 pub(super) unsafe fn from_authenticated_launch(inputs:AdmittedTestInputs)->Self{Self{inputs}}
}
/// Cloneable internal custody guard, tied to the same retained native owner.
/// Rc intentionally prevents transfer to another thread/process. The current
/// native driver has a synchronous backend; a future worker needs an explicitly
/// reviewed ownership/join adaptation, never a Send/Sync assertion.
#[derive(Clone)]
pub(super) struct ProviderExecution{owner:Rc<OwnExecutionLease>,source:[u8;32],campaign:[u8;32]}
impl ProviderExecution{
 pub(super) fn require(&self,source:&[u8;32],campaign:&[u8;32])->Result<()>{
  if source!=&self.source||campaign!=&self.campaign{return Err("Native provider differs from selected source/campaign".into());}
  self.owner.require_custody_context(source,campaign)
 }
}
/// Owns the receiver through the complete synchronous prepare/run dispatch.
/// All provider clones must drop before checked native closure is attempted.
pub(super) struct NativeRunOwner{owner:Option<Rc<OwnExecutionLease>>,source:[u8;32],campaign:[u8;32],quarantine:Option<Box<UnjoinedRecord>>}
impl NativeRunOwner{
 pub(super) fn receive(selected:RootSelectedDriverInput)->Result<Self>{
  let source=selected.inputs.source_sha256;let campaign=selected.inputs.immutable_campaign;
  let quarantine=Some(Box::new(UnjoinedRecord{owner:None}));
  // The opaque selection can only originate at the unsafe trusted factory.
  // Actual token/files/IAT/backing observations are checked afresh here before
  // any provider creation, fixture private-key generation or existing reopen.
  let owner=unsafe{OwnExecutionLease::open_admitted_test(selected.inputs)}?;
  Ok(Self{owner:Some(Rc::new(owner)),source,campaign,quarantine})
 }
 pub(super) fn provider(&self)->Result<ProviderExecution>{
  let owner=self.owner.as_ref().ok_or("Native receiver already closed")?;
  owner.require_custody_context(&self.source,&self.campaign)?;
  Ok(ProviderExecution{owner:owner.clone(),source:self.source,campaign:self.campaign})
 }
 pub(super) fn require(&self,source:&[u8;32],campaign:&[u8;32])->Result<()>{self.provider()?.require(source,campaign)}
 /// The driver's result owns no backend/provider. Its synchronous stack has
 /// unwound before this consuming close on BOTH success and error.
 pub(super) fn close_after_driver(mut self)->Result<()>{self.close_inner()}
 fn close_inner(&mut self)->Result<()>{
  let original=self.owner.take().ok_or("Native receiver close already consumed")?;
  match Rc::try_unwrap(original){
   Ok(mut owner)=>owner.close_checked(),
   Err(owner)=>{
    // Do not close files/module references underneath a surviving provider.
    // Keep the whole original owner rooted; never retry close after unknown
    // worker/provider lifetime. The process remains unavailable for admission.
    owner.revoke();
    let mut record=self.quarantine.take().expect("preallocated whole-owner quarantine");
    record.owner=Some(owner);let _retained=Box::leak(record);
    Err("Native providers not joined/dropped; whole execution owner quarantined".into())
   }
  }
 }
}
impl Drop for NativeRunOwner{fn drop(&mut self){if self.owner.is_some(){let _=self.close_inner();}}}
/// Concrete application receiver. No provider/private driver entry is called
/// until the selected owner has opened successfully. The owner remains live
/// through bootstrap or existing-only reopen, H0 and every backend operation.
/// This is NOT an ordinary CLI input decoder or authority to admit a plan.
pub(super) fn dispatch_selected(selected:RootSelectedDriverInput)->Result<()>{
 let owner=NativeRunOwner::receive(selected)?;
 dispatch_received(owner)
}
/// Used only after the authenticated Root factory has received the owner and
/// checked independent channel/preflight closure. It cannot construct a lease.
pub(super) fn dispatch_received(owner:NativeRunOwner)->Result<()>{
 let operation=super::native_owner_driver::run_with_receiver(&owner);
 let closure=owner.close_after_driver();
 match(operation,closure){(Ok(()),Ok(()))=>Ok(()),(a,b)=>Err(format!("Native driver/owned closure: operation={a:?}, closure={b:?}"))}
}
/// Used by existing-only Driver before it opens any provider. Receipt content
/// cannot select another process owner; its source/campaign must match the
/// independently selected immutable receiver context.
pub(super) fn require_prepared_context(owner:&NativeRunOwner,source:&[u8;32],campaign:&[u8;32],base:&Path)->Result<()>{
 if !base.is_absolute(){return Err("Native prepared workspace must be absolute".into());}
 owner.require(source,campaign)
}
