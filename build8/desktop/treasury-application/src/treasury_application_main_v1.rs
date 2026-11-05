//! Finite ordinary executable dispatch. Selection precedes custody I/O.
//! TEST selection is compiled only into the --bin TEST harness; no NORMAL fallback.
use crate::{StartupRefusal,treasury_application_enrollment_v1 as enrollment,
    treasury_application_api_v1::{Service,OpenError}};
use std::io::Read;
use zeroize::Zeroizing;
fn frame(input:&mut impl Read,cap:usize)->Result<Zeroizing<Vec<u8>>,StartupRefusal>{
    let mut prefix=[0;4];input.read_exact(&mut prefix).map_err(|_|StartupRefusal::InvalidEnrollment)?;
    let n=u32::from_be_bytes(prefix) as usize;
    if n==0||n>cap{return Err(StartupRefusal::InvalidEnrollment);}
    let mut raw=Zeroizing::new(vec![0;n]);input.read_exact(&mut raw).map_err(|_|StartupRefusal::InvalidEnrollment)?;Ok(raw)
}
fn selected(error:enrollment::Error)->StartupRefusal{
    match error{enrollment::Error::MissingEnrollment=>StartupRefusal::MissingAuthenticEnrollment,
        _=>StartupRefusal::InvalidEnrollment}
}
pub fn application_main(args:&[String],input:&mut impl Read)->Result<(),StartupRefusal>{
    enrollment::installed_selection_present().map_err(selected)?;
    if args.len()!=1||!matches!(args[0].as_str(),"service-check"|"reconcile-service"|"serve-ready"){
        return Err(StartupRefusal::InvalidEnrollment);
    }
    // Public record must match the independently compiled selection BEFORE
    // reading custody/password. Authentication does not grant monotonicity.
    let document=frame(input,enrollment::MAX_DOCUMENT)?;
    enrollment::configured_service_inputs(&document).map_err(selected)?;
    let custody=frame(input,65536)?;let password=frame(input,4096)?;
    let password=std::str::from_utf8(&password).map_err(|_|StartupRefusal::InvalidEnrollment)?;
    let mut extra=Zeroizing::new([0;1]);if input.read(&mut extra[..]).map_err(|_|StartupRefusal::InvalidEnrollment)?!=0{
        return Err(StartupRefusal::InvalidEnrollment);
    }
    let password=Zeroizing::new(password.to_owned());
    let mut endpoint=match args[0].as_str(){
        "service-check"|"serve-ready"=>Service::open(&document,custody,password),
        "reconcile-service"=>Service::open_reconciling(&document,custody,password),
        _=>unreachable!(),
    }.map_err(|error|match error{OpenError::MissingAuthenticEnrollment=>StartupRefusal::MissingAuthenticEnrollment,
        OpenError::InvalidEnrollment=>StartupRefusal::InvalidEnrollment})?;
    let served=if args[0]=="serve-ready"{endpoint.serve_once().map_err(|_|StartupRefusal::InvalidEnrollment)}else{Ok(())};
    let closed=endpoint.close().map_err(|_|StartupRefusal::InvalidEnrollment);
    served.and(closed)
}
