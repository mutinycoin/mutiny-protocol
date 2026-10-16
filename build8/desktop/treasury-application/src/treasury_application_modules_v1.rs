#[cfg(not(target_os="linux"))] compile_error!("reviewed application projection is Linux-only");
use mutiny_consensus_v8::*;
#[path="../native/protected_owner.rs"] mod protected_owner;
#[path="../native/treasury_storage_owner.rs"] mod treasury_storage_owner;
#[path="../native/treasury_bounded_readers.rs"] mod treasury_bounded_readers;
#[path="../native/treasury_rehearsal_v3.rs"] mod treasury_rehearsal_v3;
#[path="../native/treasury_continuity_v1.rs"] mod treasury_continuity_v1;
#[path="../native/treasury_continuity_provider_v1.rs"] mod treasury_continuity_provider_v1;
#[path="../native/treasury_admission_v3.rs"] mod treasury_admission_v3;
#[path="../native/treasury_continuity_owner_v1.rs"] mod treasury_continuity_owner_v1;
#[path="../native/treasury_native_service_v1.rs"] mod treasury_native_service_v1;
mod treasury_application_enrollment_v1;
mod treasury_native_application_entry_v1;
mod treasury_application_main_v1;
mod treasury_application_api_v1;
pub use treasury_application_main_v1::application_main;
pub use treasury_application_api_v1::{Client,Service,OpenError,ClientError,ServiceError,Denylist,VerifiedProof};
#[derive(Debug,Clone,Copy,PartialEq,Eq)] pub enum StartupRefusal{MissingAuthenticEnrollment,InvalidEnrollment}
/// No implicit file/network/custody selection; the reviewed immutable input is absent.
pub fn deployment_status()->std::result::Result<(),StartupRefusal>{
    match treasury_application_enrollment_v1::configured_approval(&[]){
        Err(treasury_application_enrollment_v1::Error::MissingEnrollment)=>Err(StartupRefusal::MissingAuthenticEnrollment),
        _=>Err(StartupRefusal::InvalidEnrollment),
    }
}
