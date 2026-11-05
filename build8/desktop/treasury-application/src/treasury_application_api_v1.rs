//! Ordinary application capabilities. No caller-supplied provider, path, policy,
//! key, head or configuration can replace the independently installed selection.
use crate::{treasury_application_enrollment_v1 as enrollment,
    treasury_native_application_entry_v1 as entry,
    treasury_continuity_owner_v1::canonical_startup::CanonicalOwner,
    treasury_continuity_provider_v1::authenticated_wire::AuthenticatedProvider,
    treasury_native_service_v1::tcp::{NativeWire,SerializedEndpoint}};
use mutiny_consensus_v8::canonical_store_v2::CanonicalStore;
use mutiny_crypto_v2::{HybridSignature,treasury_proof_v1::Challenge};
use zeroize::Zeroizing;
use std::time::{Duration,Instant};
pub use crate::treasury_rehearsal_v3::{Denylist,VerifiedProof};
pub use crate::treasury_continuity_owner_v1::Error as ClientError;
pub use crate::treasury_native_service_v1::tcp::Error as ServiceError;
type NativeClient<'a>=CanonicalOwner<'a,AuthenticatedProvider<NativeWire>>;
#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub enum OpenError{MissingAuthenticEnrollment,InvalidEnrollment}
fn selected(error:enrollment::Error)->OpenError{
    match error{enrollment::Error::MissingEnrollment=>OpenError::MissingAuthenticEnrollment,
        _=>OpenError::InvalidEnrollment}
}
fn entry_error(error:entry::Error)->OpenError{
    match error{entry::Error::Enrollment(error)=>selected(error),_=>OpenError::InvalidEnrollment}
}
/// The supplied canonical store is already authenticated/replayed by its own
/// constructor. Current and historical Treasury expectations are derived there.
/// This handle owns transport custody and native storage; neither is exported.
pub struct Client<'a>{inner:Option<NativeClient<'a>>}
impl<'a> Client<'a>{
    pub fn open(public_record:&[u8],sealed_custody:Zeroizing<Vec<u8>>,
        password:Zeroizing<String>,chain:&'a CanonicalStore,denylist:Denylist)->Result<Self,OpenError>{
        let(config,policy)=enrollment::configured_client_inputs(public_record).map_err(selected)?;
        let inner=entry::open_current(public_record,&sealed_custody,&password,chain,config,policy,denylist)
            .map_err(entry_error)?;
        Ok(Self{inner:Some(inner)})
    }
    pub fn frozen(&self)->bool{self.inner.as_ref().is_none_or(|inner|inner.frozen())}
    pub fn sequence(&self)->u64{self.inner.as_ref().map_or(0,|inner|inner.sequence())}
    pub fn issue(&mut self,descriptor:&[u8])->Result<Challenge,ClientError>{
        self.inner.as_mut().ok_or(ClientError::Frozen)?.issue(descriptor)
    }
    pub fn admit(&mut self,descriptor:&[u8],challenge:&[u8],signature:&HybridSignature)
        ->Result<VerifiedProof,ClientError>{
        self.inner.as_mut().ok_or(ClientError::Frozen)?.admit(descriptor,challenge,signature)
    }
    /// Explicit authenticated exact-history reconstruction; never an automatic
    /// retry, reset, resubmission or deletion of external consumption.
    pub fn reconcile(&mut self)->Result<(),ClientError>{
        self.inner.as_mut().ok_or(ClientError::Frozen)?.reconcile()
    }
    pub fn close(mut self)->Result<(),ClientError>{
        self.inner.take().ok_or(ClientError::Frozen)?.close_final()
    }
}
impl Drop for Client<'_>{fn drop(&mut self){
    // One close attempt only. The native public storage owner is quarantined on
    // an uncertain close; transport custody is still dropped and erased.
    if let Some(inner)=self.inner.take(){let _=inner.close_final();}
}}
/// Separate service capability; it holds transport authentication custody only.
/// Ordinary consensus/replay never calls this application API.
pub struct Service{inner:Option<SerializedEndpoint>,io_budget:Duration}
impl Service{
    pub fn open(public_record:&[u8],sealed_custody:Zeroizing<Vec<u8>>,password:Zeroizing<String>)
        ->Result<Self,OpenError>{
        let(config,policy)=enrollment::configured_service_inputs(public_record).map_err(selected)?;
        let io_budget=enrollment::configured_io_budget(public_record).map_err(selected)?;
        let inner=entry::reopen_service(public_record,&sealed_custody,&password,&config,policy).map_err(entry_error)?;
        Ok(Self{inner:Some(inner),io_budget})
    }
    pub fn open_reconciling(public_record:&[u8],sealed_custody:Zeroizing<Vec<u8>>,password:Zeroizing<String>)
        ->Result<Self,OpenError>{
        let(config,policy)=enrollment::configured_service_inputs(public_record).map_err(selected)?;
        let io_budget=enrollment::configured_io_budget(public_record).map_err(selected)?;
        let inner=entry::reconcile_service(public_record,&sealed_custody,&password,&config,policy).map_err(entry_error)?;
        Ok(Self{inner:Some(inner),io_budget})
    }
    /// Drives exactly one ready request with the existing selected I/O budget.
    /// Idle and unknown outcomes remain explicit; no new loop or retry is added.
    pub fn serve_ready(&mut self)->Result<(),ServiceError>{
        self.inner.as_mut().ok_or(ServiceError::Unknown)?.serve_ready()
    }
    /// Finite ordinary executable operation: wait and exchange share the exact
    /// installed I/O budget. At most one request is accepted, never resubmitted.
    pub fn serve_once(&mut self)->Result<(),ServiceError>{
        let end=Instant::now().checked_add(self.io_budget).ok_or(ServiceError::Configuration)?;
        loop{
            match self.inner.as_mut().ok_or(ServiceError::Unknown)?.serve_ready_until(end){
                Err(ServiceError::Idle)=>std::thread::yield_now(),
                outcome=>return outcome,
            }
        }
    }
    pub fn close(mut self)->Result<(),ServiceError>{
        self.inner.take().ok_or(ServiceError::Unknown)?.close()
    }
}
impl Drop for Service{fn drop(&mut self){if let Some(inner)=self.inner.take(){let _=inner.close();}}}
