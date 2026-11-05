//! Existing administrator-selected encrypted role inputs. No passwords or key
//! material are generated. The opaque issuer derives both paths and digests
//! from its held installed selection and current own canonical context.
use super::hybrid_installed_counter_v2::{HeldPublic,InstalledCounterAuthority};
use mutiny_consensus_v8::{Hash,canonical_store_v2::CanonicalStore};
use sha2::{Digest,Sha256};
use std::mem::ManuallyDrop;
type Result<T>=std::result::Result<T,String>;
struct Inputs {node:Option<HeldPublic>,continuity:Option<HeldPublic>,context:Hash,pins:(Hash,Hash),frozen:bool,close_unknown:Vec<super::hybrid_installed_counter_v2::HeldPublicClose>}
pub(crate) struct InstalledRoleInputs {inputs:ManuallyDrop<Box<Inputs>>}
pub(crate) enum RoleInputsClose {Retained(ManuallyDrop<InstalledRoleInputs>)}
impl InstalledRoleInputs {
    pub(crate) fn open_existing(authority:&mut InstalledCounterAuthority,chain:&CanonicalStore)->Result<Self>{
        let directory=authority.role_directory();let pins=authority.role_ciphertext_pins();
        let mut result=Self{inputs:ManuallyDrop::new(Box::new(Inputs{node:None,continuity:None,
            context:authority.context(),pins,frozen:true,close_unknown:Vec::with_capacity(2)}))};
        authority.recheck(chain)?;
        result.inputs.node=Some(HeldPublic::open(directory.join("node.custody"),8192)?);
        result.inputs.continuity=Some(HeldPublic::open(directory.join("continuity.custody"),8192)?);
        result.inputs.frozen=false;result.commitments_checked(authority,chain)?;Ok(result)
    }
    /// Repeated at unlock exchange, decryption and every factory custody entry.
    /// Digest equality only binds selected encrypted input, not qualification.
    pub(crate) fn commitments_checked(&mut self,authority:&mut InstalledCounterAuthority,chain:&CanonicalStore)->Result<(Hash,Hash)>{
        let inputs=&mut **self.inputs;
        if inputs.frozen{return Err("installed role input custody frozen".into());}
        inputs.frozen=true;authority.recheck(chain)?;
        if inputs.context!=authority.context()||inputs.pins!=authority.role_ciphertext_pins(){
            return Err("installed role input selection changed".into());}
        inputs.node.as_mut().ok_or("original Node ciphertext absent")?.recheck()?;inputs.continuity.as_mut().ok_or("original Continuity ciphertext absent")?.recheck()?;
        if <Hash>::from(Sha256::digest(inputs.node.as_ref().ok_or("original Node ciphertext absent")?.bytes()))!=inputs.pins.0
            ||<Hash>::from(Sha256::digest(inputs.continuity.as_ref().ok_or("original Continuity ciphertext absent")?.bytes()))!=inputs.pins.1 {
            return Err("installed role ciphertext commitment differs".into());}
        authority.recheck(chain)?;inputs.frozen=false;Ok(inputs.pins)
    }
    /// Borrow only after actual held-object/current checks. The caller cannot
    /// select a ciphertext, path, identity or generation through this method.
    pub(crate) fn borrow_checked<'a>(&'a mut self,authority:&mut InstalledCounterAuthority,
        chain:&CanonicalStore)->Result<(&'a[u8],&'a[u8])>{
        self.commitments_checked(authority,chain)?;
        let inputs=&**self.inputs;Ok((inputs.node.as_ref().ok_or("original Node ciphertext absent")?.bytes(),inputs.continuity.as_ref().ok_or("original Continuity ciphertext absent")?.bytes()))
    }
    pub(crate) fn close(mut self,authority:&mut InstalledCounterAuthority,chain:&CanonicalStore)
        ->std::result::Result<(),RoleInputsClose>{
        if self.commitments_checked(authority,chain).is_err(){return Err(RoleInputsClose::Retained(ManuallyDrop::new(self)));}
        let inputs=&mut **self.inputs;inputs.frozen=true;
        for object in [inputs.node.take(),inputs.continuity.take()].into_iter().flatten(){
            if let Err(unknown)=object.close(){inputs.close_unknown.push(unknown);}
        }
        if !inputs.close_unknown.is_empty(){return Err(RoleInputsClose::Retained(ManuallyDrop::new(self)));}
        unsafe{ManuallyDrop::drop(&mut self.inputs)};Ok(())
    }
}
