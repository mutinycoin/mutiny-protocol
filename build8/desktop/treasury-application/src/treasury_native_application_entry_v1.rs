//! SOURCE ONLY / UNCOMPILED application-private native entry.
//! Separate ordinary application projection, NOT the shipping consensus API or
//! a re-labelled TEST host. Missing compiled enrollment fails before all IO.
use crate::{treasury_application_enrollment_v1 as enrollment,
    treasury_native_service_v1::{Policy,tcp::{SerializedEndpoint,NativeWire,TcpExchange,IoLimits}},
    treasury_continuity_owner_v1::{canonical_startup::CanonicalOwner,Error as OwnerError},
    treasury_rehearsal_v3::{CeremonyConfig,Denylist},
    treasury_admission_v3::{StoreIdentity,LocalStoragePolicy},
    canonical_store_v2::CanonicalStore};
type Provider=crate::treasury_continuity_provider_v1::authenticated_wire::AuthenticatedProvider<NativeWire>;
pub(crate) enum Error{Enrollment(enrollment::Error),Owner(OwnerError),Service}
pub(crate) fn open_current<'a>(public_record:&[u8],client_custody:&[u8],password:&str,
    chain:&'a CanonicalStore,config:CeremonyConfig,policy:LocalStoragePolicy,denylist:Denylist)
    ->Result<CanonicalOwner<'a,Provider>,Error>{
    let approved=enrollment::configured_approval(public_record).map_err(Error::Enrollment)?;
    let wire=NativeWire::for_approved_application(&approved).map_err(|_|Error::Service)?;
    let provider=approved.client_provider(client_custody,password,wire).map_err(Error::Enrollment)?;
    let identity=StoreIdentity::from_trusted_id(approved.store_identity()).map_err(|_|Error::Service)?;
    CanonicalOwner::open_native(approved.admission_path(),identity,policy,chain,config,
        provider,approved.pins().scope().clone(),denylist).map_err(Error::Owner)
}
pub(crate) fn reopen_service(public_record:&[u8],service_custody:&[u8],password:&str,
    config:&CeremonyConfig,policy:Policy)->Result<SerializedEndpoint,Error>{
    let(approved,head)=enrollment::configured_service_approval(public_record).map_err(Error::Enrollment)?;
    let opened=approved.service_custody(service_custody,password).map_err(Error::Enrollment)?;
    // Existing-only native read-only replay/exact independently selected head/
    // same held Owner promotion. Native phase/class/identity guards unchanged.
    SerializedEndpoint::reopen_approved_application(&approved,head,opened,config,policy)
        .map_err(|_|Error::Service)
}

/// Explicit exact intent reconciliation, not an automatic replay/resubmission.
pub(crate) fn reconcile_service(public_record:&[u8],service_custody:&[u8],password:&str,
    config:&CeremonyConfig,policy:Policy)->Result<SerializedEndpoint,Error>{
    let(approved,head,target)=enrollment::configured_reconciliation(public_record).map_err(Error::Enrollment)?;
    let opened=approved.service_custody(service_custody,password).map_err(Error::Enrollment)?;
    let key=opened.into_verified_key(&approved).map_err(Error::Enrollment)?;
    let service=crate::treasury_native_service_v1::Service::open_reconciling_native(
        approved.service_path(),config,approved.pins().scope().clone(),policy,&target).map_err(|_|Error::Service)?;
    let(approved,head)=enrollment::finish_reconciled(approved,head,&service).map_err(Error::Enrollment)?;
    let endpoint=crate::treasury_native_service_v1::Endpoint::with_head(service,approved.pins().clone(),key,head).map_err(|_|Error::Service)?;
    SerializedEndpoint::bind(approved.address(),endpoint,IoLimits::new(approved.io_budget()).map_err(|_|Error::Service)?).map_err(|_|Error::Service)
}
