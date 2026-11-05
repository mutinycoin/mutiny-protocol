//! SOURCE ONLY / UNCOMPILED ordinary application construction.
//! Untrusted public record parsing never enrolls an identity. Normal application
//! selection is immutable and EMPTY until authentic pre-enrolled inputs exist.
use crate::{Hash,treasury_continuity_v1::Scope,
    treasury_continuity_provider_v1::{PublicSnapshot,ProviderError,MAX_SNAPSHOT_BYTES,
        authenticated_wire::{PublicPins,AuthenticatedProvider,WireTransport}}};
use mutiny_crypto_v2::{HybridKey,PublicKey,Role};
use std::{path::{PathBuf,Component},ffi::OsString,time::Duration,
    net::SocketAddr,os::unix::ffi::{OsStringExt,OsStrExt}};
use minicbor::{Decoder,Encoder};
pub(crate) const MAX_DOCUMENT:usize=MAX_SNAPSHOT_BYTES+32768;
const MAX_DESCRIPTOR:usize=4096;
const MAX_PATH:usize=4096;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(crate) enum Error{MissingEnrollment,UntrustedSelection,Invalid,Full,Custody,Unavailable}
fn c<T,E>(r:Result<T,E>)->Result<T,Error>{r.map_err(|_|Error::Invalid)}
fn digest(raw:&[u8])->Hash{use sha2::{Digest,Sha256};Sha256::digest(raw).into()}
fn hash(d:&mut Decoder<'_>)->Result<Hash,Error>{c(c(d.bytes())?.try_into())}
fn optional(d:&mut Decoder<'_>)->Result<Option<Hash>,Error>{
    if c(d.datatype())?==minicbor::data::Type::Null{c(d.null())?;Ok(None)}else{Ok(Some(hash(d)?))}
}
fn bounded<'a>(d:&mut Decoder<'a>,limit:usize)->Result<&'a[u8],Error>{
    let raw=c(d.bytes())?;if raw.is_empty()||raw.len()>limit{return Err(Error::Full);}Ok(raw)
}
fn path(d:&mut Decoder<'_>)->Result<PathBuf,Error>{
    let raw=bounded(d,MAX_PATH)?;if raw.contains(&0)||raw.split(|b|*b==b'/').any(|part|part==b"."||part==b".."){return Err(Error::Invalid);}
    let value=PathBuf::from(OsString::from_vec(raw.to_vec()));
    if !value.is_absolute()||value.components().any(|x|matches!(x,Component::CurDir|Component::ParentDir|Component::Prefix(_))){return Err(Error::Invalid);}
    Ok(value)
}
// No Deserialize/authority conversion. Every field is still public information.
pub(crate) struct ParsedRecord{
    administrator:Hash,pins:PublicPins,client_context:Hash,service_context:Hash,
    store:Hash,address:SocketAddr,admission:PathBuf,service:PathBuf,
    io_budget:Duration,checkpoint:PublicSnapshot,
}
impl ParsedRecord{
    pub(crate) fn decode(raw:&[u8])->Result<Self,Error>{
        if raw.is_empty()||raw.len()>MAX_DOCUMENT{return Err(Error::Full);}
        let mut d=Decoder::new(raw);if c(d.array())?!=Some(14)||c(d.u8())?!=1{return Err(Error::Invalid);}
        let administrator=hash(&mut d)?;
        if c(d.array())?!=Some(7){return Err(Error::Invalid);}
        let scope=Scope{network:c(d.u32())?,genesis:optional(&mut d)?,ceremony_context:hash(&mut d)?,
            treasury_record:hash(&mut d)?,verifier:hash(&mut d)?,store:hash(&mut d)?,service:hash(&mut d)?};
        let wire_context=hash(&mut d)?;
        let client=bounded(&mut d,MAX_DESCRIPTOR)?.to_vec();
        let service_key=bounded(&mut d,MAX_DESCRIPTOR)?.to_vec();
        let pins=PublicPins::new(scope,wire_context,client,service_key).map_err(|_|Error::Invalid)?;
        let client_context=hash(&mut d)?;let service_context=hash(&mut d)?;let store=hash(&mut d)?;
        let endpoint=c(d.str())?;if endpoint.len()>128{return Err(Error::Full);}
        let address:SocketAddr=endpoint.parse().map_err(|_|Error::Invalid)?;
        let admission=path(&mut d)?;let service=path(&mut d)?;
        let io_budget=Duration::from_nanos(c(d.u64())?);
        let checkpoint=PublicSnapshot::decode(bounded(&mut d,MAX_SNAPSHOT_BYTES)?).map_err(|_|Error::Invalid)?;
        let value=Self{administrator,pins,client_context,service_context,store,address,admission,service,io_budget,checkpoint};
        if d.position()!=raw.len(){return Err(Error::Invalid);}value.validate()?;
        if value.encode()?.as_slice()!=raw{return Err(Error::Invalid);}Ok(value)
    }
    fn validate(&self)->Result<(),Error>{
        if [self.administrator,self.client_context,self.service_context,self.store].contains(&[0;32])
            || self.client_context==self.service_context||self.store!=self.pins.scope().store
            || self.admission==self.service||self.address.port()==0||self.address.ip().is_unspecified()
            || self.io_budget.is_zero()||std::time::Instant::now().checked_add(self.io_budget).is_none()
            || self.checkpoint.scope()!=self.pins.scope(){return Err(Error::Invalid);}
        for p in [&self.admission,&self.service]{
            let raw=p.as_os_str().as_bytes();
            if raw.is_empty()||raw.len()>MAX_PATH||raw.contains(&0)||!p.is_absolute()
                ||raw.split(|b|*b==b'/').any(|part|part==b"."||part==b".."){return Err(Error::Invalid);}
        }
        self.checkpoint.validate().map_err(|_|Error::Invalid)?;Ok(())
    }
    fn encode(&self)->Result<Vec<u8>,Error>{
        self.validate()?;let mut e=Encoder::new(Vec::new());c(e.array(14))?;c(e.u8(1))?;c(e.bytes(&self.administrator))?;
        let s=self.pins.scope();c(e.array(7))?;c(e.u32(s.network))?;
        match s.genesis{Some(h)=>{c(e.bytes(&h))?;},None=>{c(e.null())?;}}
        for h in [s.ceremony_context,s.treasury_record,s.verifier,s.store,s.service]{c(e.bytes(&h))?;}
        c(e.bytes(&self.pins.context()))?;c(e.bytes(self.pins.client_descriptor()))?;c(e.bytes(self.pins.service_descriptor()))?;
        for h in [self.client_context,self.service_context,self.store]{c(e.bytes(&h))?;}
        c(e.str(&self.address.to_string()))?;
        for p in [&self.admission,&self.service]{let raw=p.as_os_str().as_bytes();if raw.len()>MAX_PATH{return Err(Error::Full);}c(e.bytes(raw))?;}
        let nanos:u64=self.io_budget.as_nanos().try_into().map_err(|_|Error::Full)?;c(e.u64(nanos))?;
        c(e.bytes(&self.checkpoint.encode().map_err(|_|Error::Invalid)?))?;
        let raw=e.into_writer();if raw.len()>MAX_DOCUMENT{return Err(Error::Full);}Ok(raw)
    }
}

// No public constructor, caller digest, bool, Deserialize or pin->approval path.
// This is obtained ONLY through exact source-controlled independent selection.
pub(crate) struct VerifiedApproval{record:ParsedRecord,document:Vec<u8>,selection:Hash,current:PublicSnapshot}
#[path="treasury_application_protected_head_v1.rs"] pub(crate) mod protected_head;
impl VerifiedApproval{
    pub(crate) fn pins(&self)->&PublicPins{&self.record.pins}
    pub(crate) fn checkpoint(&self)->&PublicSnapshot{&self.current}
    pub(crate) fn provider_matches(&self,pins:&PublicPins,checkpoint:&PublicSnapshot)->bool{
        // Equality is only checking an already opaque approved capability; it
        // cannot construct one. No bool is accepted from an applicant/transport.
        self.record.pins.scope()==pins.scope()&&self.record.pins.context()==pins.context()
            &&self.record.pins.client_descriptor()==pins.client_descriptor()
            &&self.record.pins.service_descriptor()==pins.service_descriptor()
            &&self.current==*checkpoint&&digest(&self.document)==self.selection
    }
}
mod application_selection{
    use super::*;
    struct InstalledSelection{administrator:Hash,document_sha256:Hash,checkpoint_sha256:Hash,
        head_directory:&'static str,head_file_cap:i64,head_steps:u64}
    pub(super) fn head_location()->Result<protected_head::Location,Error>{
        #[cfg(test)] if let Some(location)=test_selection::location(){return Ok(location);}
        let expected=INSTALLED.as_ref().ok_or(Error::MissingEnrollment)?;
        Ok(protected_head::Location{path:expected.head_directory.into(),file_cap:expected.head_file_cap,
            steps:std::num::NonZeroU64::new(expected.head_steps).ok_or(Error::Invalid)?})
    }
    // Authentic independent public inputs have NOT been supplied. Changing this
    // requires a reviewed immutable application enrollment input tranche.
    // It is not filled from argv/env/network/admission DB/service response.
    static INSTALLED:Option<InstalledSelection>=None;
    pub(super) fn verify(raw:&[u8])->Result<VerifiedApproval,Error>{
        #[cfg(test)] if let Some(result)=test_selection::verify(raw){return result;}
        let expected=INSTALLED.as_ref().ok_or(Error::MissingEnrollment)?;
        verified_against(expected,raw)
    }
    fn verified_against(expected:&InstalledSelection,raw:&[u8])->Result<VerifiedApproval,Error>{
        if raw.is_empty()||raw.len()>MAX_DOCUMENT{return Err(Error::Full);}
        if digest(raw)!=expected.document_sha256{return Err(Error::UntrustedSelection);}
        let record=ParsedRecord::decode(raw)?;
        if record.administrator!=expected.administrator
            ||digest(&record.checkpoint.encode().map_err(|_|Error::Invalid)?)!=expected.checkpoint_sha256{
            return Err(Error::UntrustedSelection);
        }
        let current=record.checkpoint.clone();Ok(VerifiedApproval{record,document:raw.to_vec(),selection:expected.document_sha256,current})
    }


    // A scope exists only in this TEST binary and on its creating thread.
    // It supplies fixed independent TEST selection inputs to the same verifier;
    // no normal constructor, environment/argv selection or service fallback.
    #[cfg(test)] pub(super) mod test_selection{
        use super::*;
        use std::{cell::RefCell,num::NonZeroU64,marker::PhantomData,rc::Rc};
        struct Fixed{administrator:Hash,document:Hash,checkpoint:Hash,head:PathBuf,cap:i64,steps:NonZeroU64,
            config:crate::treasury_rehearsal_v3::CeremonyConfig}
        std::thread_local!{static INSTALLED_TEST:RefCell<Option<Fixed>>=const{RefCell::new(None)};}
        pub(in crate::treasury_application_enrollment_v1) struct ScopeGuard{document:Hash,_thread:PhantomData<Rc<()>>}
        pub(in crate::treasury_application_enrollment_v1) fn install(a:&VerifiedApproval,head:PathBuf,cap:i64,steps:NonZeroU64,
            config:crate::treasury_rehearsal_v3::CeremonyConfig)->ScopeGuard{
            assert_eq!(a.record.pins.scope().network,mutiny_crypto_v2::NETWORK);
            assert_eq!(config.class(),crate::treasury_v1::Class::TestValue);
            assert_eq!(config.network(),a.pins().scope().network);
            assert_eq!(config.context().value(),a.pins().scope().ceremony_context);
            assert_eq!(crate::treasury_rehearsal_v3::record_sha256(config.treasury()).unwrap(),a.pins().scope().treasury_record);
            let value=Fixed{administrator:a.record.administrator,document:digest(&a.document),
                checkpoint:digest(&a.record.checkpoint.encode().unwrap()),head,cap,steps,config};
            let document=value.document;
            INSTALLED_TEST.with(|slot|{let mut slot=slot.borrow_mut();assert!(slot.is_none(),"nested TEST selection refuses");*slot=Some(value);});
            ScopeGuard{document,_thread:PhantomData}
        }
        pub(super) fn verify(raw:&[u8])->Option<Result<VerifiedApproval,Error>>{
            INSTALLED_TEST.with(|slot|slot.borrow().as_ref().map(|fixed|{
                let expected=InstalledSelection{administrator:fixed.administrator,document_sha256:fixed.document,
                    checkpoint_sha256:fixed.checkpoint,head_directory:"PUBLIC TREASURY SHARED ENTRY TEST ONLY",
                    head_file_cap:fixed.cap,head_steps:fixed.steps.get()};
                verified_against(&expected,raw)
            }))
        }
        pub(super) fn location()->Option<protected_head::Location>{
            INSTALLED_TEST.with(|slot|slot.borrow().as_ref().map(|fixed|protected_head::Location{
                path:fixed.head.clone(),file_cap:fixed.cap,steps:fixed.steps}))
        }
        pub(in crate::treasury_application_enrollment_v1) fn service_inputs()->Option<(crate::treasury_rehearsal_v3::CeremonyConfig,crate::treasury_native_service_v1::Policy)>{
            INSTALLED_TEST.with(|slot|slot.borrow().as_ref().map(|fixed|(fixed.config.clone(),
                crate::treasury_native_service_v1::Policy::new(fixed.cap,fixed.steps).unwrap())))
        }
        pub(in crate::treasury_application_enrollment_v1) fn client_inputs()->Option<(crate::treasury_rehearsal_v3::CeremonyConfig,crate::treasury_admission_v3::LocalStoragePolicy)>{
            INSTALLED_TEST.with(|slot|slot.borrow().as_ref().map(|fixed|(fixed.config.clone(),
                crate::treasury_admission_v3::LocalStoragePolicy::new(fixed.cap,fixed.steps).unwrap())))
        }
        impl Drop for ScopeGuard{fn drop(&mut self){INSTALLED_TEST.with(|slot|{
            let fixed=slot.borrow_mut().take().expect("owned TEST selection must remain present");
            assert_eq!(fixed.document,self.document,"owned TEST selection changed");
        });}}
    }

    #[cfg(test)] mod tests{
        use super::*;
        #[test] fn fixed_test_selection_refuses_changed_administrator_document_or_checkpoint(){
            let(r,_,_)=super::super::tests::fixture();let raw=r.encode().unwrap();
            let expected=InstalledSelection{administrator:r.administrator,document_sha256:digest(&raw),
                checkpoint_sha256:digest(&r.checkpoint.encode().unwrap()),head_directory:"/PRIVATE-TEST-only/head",head_file_cap:32*1024*1024,head_steps:4_000_000};
            let a=verified_against(&expected,&raw).unwrap();assert!(a.provider_matches(&r.pins,&r.checkpoint));
            let wrong=InstalledSelection{administrator:[230;32],..expected};
            assert_eq!(verified_against(&wrong,&raw).err(),Some(Error::UntrustedSelection));
            let wrong=InstalledSelection{administrator:r.administrator,document_sha256:digest(&raw),checkpoint_sha256:[231;32],head_directory:"/PRIVATE-TEST-only/head",head_file_cap:32*1024*1024,head_steps:4_000_000};
            assert_eq!(verified_against(&wrong,&raw).err(),Some(Error::UntrustedSelection));
            let mut fork=raw.clone();fork.push(0);
            assert_eq!(verified_against(&expected,&fork).err(),Some(Error::UntrustedSelection));
        }
    }
}
pub(crate) fn installed_selection_present()->Result<(),Error>{
    application_selection::head_location().map(|_|())
}
pub(crate) fn configured_service_inputs(raw:&[u8])->Result<(crate::treasury_rehearsal_v3::CeremonyConfig,crate::treasury_native_service_v1::Policy),Error>{
    // Authenticate exact compiled selection before custody I/O. No head thaw or
    // parsed-record conversion grants config or storage authority.
    let _approved=application_selection::verify(raw)?;
    #[cfg(test)] if let Some(inputs)=application_selection::test_selection::service_inputs(){return Ok(inputs);}
    // Authentic production ceremony/config pins have not been supplied.
    // Ordinary INSTALLED is None and reaches MissingEnrollment before this point.
    Err(Error::UntrustedSelection)
}
pub(crate) fn configured_io_budget(raw:&[u8])->Result<Duration,Error>{
    Ok(application_selection::verify(raw)?.io_budget())
}
pub(crate) struct OpenedClient{key:HybridKey,generation:u64}
pub(crate) fn configured_client_inputs(raw:&[u8])->Result<(crate::treasury_rehearsal_v3::CeremonyConfig,crate::treasury_admission_v3::LocalStoragePolicy),Error>{
    let _approved=application_selection::verify(raw)?;
    #[cfg(test)] if let Some(inputs)=application_selection::test_selection::client_inputs(){return Ok(inputs);}
    // No NORMAL configuration or selection fallback is synthesized.
    Err(Error::UntrustedSelection)
}
pub(crate) struct OpenedService{key:HybridKey,generation:u64}
impl OpenedService{
    pub(crate) fn into_verified_key(self,a:&VerifiedApproval)->Result<HybridKey,Error>{
        let(public,generation)=PublicKey::decode_descriptor(a.pins().service_descriptor()).map_err(|_|Error::Custody)?;
        if public!=*self.key.public()||self.generation!=generation
            ||self.key.public().descriptor(self.generation).map_err(|_|Error::Custody)?!=a.pins().service_descriptor(){return Err(Error::Custody);}
        Ok(self.key)
    }
}
fn open_client(a:&VerifiedApproval,raw:&[u8],password:&str)->Result<OpenedClient,Error>{
    if raw.is_empty()||raw.len()>65536{return Err(Error::Full);}
    let(key,generation)=HybridKey::open_for(Role::Transport,password,&a.record.client_context,raw).map_err(|_|Error::Custody)?;
    let(public,expected)=PublicKey::decode_descriptor(a.record.pins.client_descriptor()).map_err(|_|Error::Custody)?;
    if public.role!=Role::Transport||public!=*key.public()||generation!=expected
        ||key.public().descriptor(generation).map_err(|_|Error::Custody)?!=a.record.pins.client_descriptor(){return Err(Error::Custody);}
    Ok(OpenedClient{key,generation})
}
// Ordinary software constructor implemented, but authentic selection missing
// means it returns MissingEnrollment BEFORE custody/network/database effects.
pub(crate) fn configured_provider<T:WireTransport>(public_record:&[u8],sealed_custody:&[u8],
    password:&str,transport:T)->Result<AuthenticatedProvider<T>,Error>{
    let approved=configured_approval(public_record)?;
    let opened=open_client(&approved,sealed_custody,password)?;
    AuthenticatedProvider::from_verified_application(&approved,opened.key,opened.generation,transport)
        .map_err(|_|Error::Unavailable)
}

// Application/native backend ports consume ONLY this opaque configured result.
// Publishing immutable selected paths does not grant write/storage authority.
pub(crate) fn configured_approval(raw:&[u8])->Result<VerifiedApproval,Error>{
    let a=application_selection::verify(raw)?;
    let location=application_selection::head_location()?;
    let head=protected_head::HeadOwner::open(&a,&location,false).map_err(|_|Error::Unavailable)?;
    let current=head.approved_current(a).map_err(|_|Error::Unavailable);
    head.close_final().map_err(|_|Error::Unavailable)?;current
}
pub(crate) fn configured_service_approval(raw:&[u8])->Result<(VerifiedApproval,protected_head::HeadOwner),Error>{
    let a=application_selection::verify(raw)?;let location=application_selection::head_location()?;
    let head=protected_head::HeadOwner::open(&a,&location,true).map_err(|_|Error::Unavailable)?;
    let a=head.approved_current(a).map_err(|_|Error::Unavailable)?;Ok((a,head))
}
pub(crate) fn configured_reconciliation(raw:&[u8])->Result<(VerifiedApproval,protected_head::HeadOwner,protected_head::RecoveryTarget),Error>{
    let a=application_selection::verify(raw)?;let location=application_selection::head_location()?;
    let head=protected_head::HeadOwner::open(&a,&location,true).map_err(|_|Error::Unavailable)?;
    let target=head.recovery_target().map_err(|_|Error::Unavailable)?;Ok((a,head,target))
}
pub(crate) fn finish_reconciled(a:VerifiedApproval,head:protected_head::HeadOwner,
    service:&crate::treasury_native_service_v1::Service)->Result<(VerifiedApproval,protected_head::HeadOwner),Error>{
    let mut head=head;head.reconcile(service).map_err(|_|Error::Unavailable)?;
    let a=head.approved_current(a).map_err(|_|Error::Unavailable)?;Ok((a,head))
}
impl VerifiedApproval{
    pub(crate) fn admission_path(&self)->&std::path::Path{&self.record.admission}
    pub(crate) fn service_path(&self)->&std::path::Path{&self.record.service}
    pub(crate) fn store_identity(&self)->Hash{self.record.store}
    pub(crate) fn address(&self)->SocketAddr{self.record.address}
    pub(crate) fn io_budget(&self)->Duration{self.record.io_budget}
    pub(crate) fn client_provider<T:WireTransport>(&self,raw:&[u8],password:&str,transport:T)
        ->Result<AuthenticatedProvider<T>,Error>{
        let opened=open_client(self,raw,password)?;
        AuthenticatedProvider::from_verified_application(self,opened.key,opened.generation,transport)
            .map_err(|_|Error::Unavailable)
    }
    pub(crate) fn service_custody(&self,raw:&[u8],password:&str)->Result<OpenedService,Error>{
        if raw.is_empty()||raw.len()>65536{return Err(Error::Full);}
        let(key,generation)=HybridKey::open_for(Role::Transport,password,&self.record.service_context,raw).map_err(|_|Error::Custody)?;
        let(public,expected)=PublicKey::decode_descriptor(self.record.pins.service_descriptor()).map_err(|_|Error::Custody)?;
        if public.role!=Role::Transport||public!=*key.public()||generation!=expected
            ||key.public().descriptor(generation).map_err(|_|Error::Custody)?!=self.record.pins.service_descriptor(){return Err(Error::Custody);}
        Ok(OpenedService{key,generation})
    }
}


#[cfg(test)] mod tests{
    use super::*;
    const VALUE:&str="PUBLIC TREASURY ORDINARY CONSTRUCTION TEST ONLY";
    pub(super) fn fixture()->(ParsedRecord,HybridKey,HybridKey){
        let client=HybridKey::generate(Role::Transport).unwrap();let service=HybridKey::generate(Role::Transport).unwrap();
        let scope=Scope{network:mutiny_crypto_v2::NETWORK,genesis:None,ceremony_context:[211;32],
            treasury_record:[212;32],verifier:[213;32],store:[214;32],service:[215;32]};
        let pins=PublicPins::new(scope.clone(),[216;32],client.public().descriptor(1).unwrap(),service.public().descriptor(1).unwrap()).unwrap();
        let checkpoint=PublicSnapshot::new(scope,[217;32],0,None,vec![]).unwrap();
        (ParsedRecord{administrator:[218;32],pins,client_context:[219;32],service_context:[220;32],
            store:[214;32],address:"127.0.0.1:34972".parse().unwrap(),admission:"/PRIVATE-TEST-only/admission".into(),
            service:"/PRIVATE-TEST-only/service".into(),io_budget:Duration::from_secs(10),checkpoint},client,service)
    }
    // Only private TEST fixture administration; normal INSTALLED remains None.
    fn approved(r:ParsedRecord)->VerifiedApproval{
        let document=r.encode().unwrap();let current=r.checkpoint.clone();VerifiedApproval{selection:digest(&document),record:r,document,current}
    }
    #[test] fn canonical_enrollment_document_roundtrip_retains_exact_public_context(){
        let(r,_,_)=fixture();let raw=r.encode().unwrap();let d=ParsedRecord::decode(&raw).unwrap();
        assert_eq!(d.encode().unwrap(),raw);assert_eq!(d.administrator,r.administrator);
        assert_eq!(d.pins.client_descriptor(),r.pins.client_descriptor());assert_eq!(d.pins.service_descriptor(),r.pins.service_descriptor());
        assert_eq!(d.checkpoint,r.checkpoint);assert_eq!(d.admission,r.admission);assert_eq!(d.service,r.service);
    }
    #[test] fn internal_dot_parent_relative_and_nul_paths_refuse_raw_spellings(){
        for raw in [b"/a/./b".as_slice(),b"/a/../b",b"a/b",b"/a\0b"]{
            let mut e=Encoder::new(Vec::new());e.bytes(raw).unwrap();let encoded=e.into_writer();
            assert_eq!(path(&mut Decoder::new(&encoded)),Err(Error::Invalid));
        }
        let mut e=Encoder::new(Vec::new());e.bytes(b"/a/b").unwrap();let encoded=e.into_writer();
        assert_eq!(path(&mut Decoder::new(&encoded)).unwrap(),PathBuf::from("/a/b"));
    }
    #[test] fn enrollment_noncanonical_trailing_version_and_bounds_refuse(){
        let(r,_,_)=fixture();let raw=r.encode().unwrap();let mut trailing=raw.clone();trailing.push(0);
        assert_eq!(ParsedRecord::decode(&trailing).err(),Some(Error::Invalid));
        let mut version=raw.clone();assert_eq!(version[0],0x8e);assert_eq!(version[1],1);version[1]=2;
        assert_eq!(ParsedRecord::decode(&version).err(),Some(Error::Invalid));
        let alternate=[vec![0x98,14],raw[1..].to_vec()].concat();
        assert_eq!(ParsedRecord::decode(&alternate).err(),Some(Error::Invalid));
        assert_eq!(ParsedRecord::decode(&vec![0;MAX_DOCUMENT+1]).err(),Some(Error::Full));
        let mut e=Encoder::new(Vec::new());e.bytes(&vec![b'a';MAX_PATH+1]).unwrap();let encoded=e.into_writer();
        assert_eq!(path(&mut Decoder::new(&encoded)),Err(Error::Full));
    }
    #[test] fn enrollment_context_store_endpoint_and_distinct_paths_are_checked(){
        let(mut r,_,_)=fixture();r.store=[221;32];assert_eq!(r.validate(),Err(Error::Invalid));r.store=[214;32];
        r.address="127.0.0.1:0".parse().unwrap();assert_eq!(r.validate(),Err(Error::Invalid));r.address="127.0.0.1:34972".parse().unwrap();
        r.service=r.admission.clone();assert_eq!(r.validate(),Err(Error::Invalid));r.service="/PRIVATE-TEST-only/service".into();
        r.client_context=r.service_context;assert_eq!(r.validate(),Err(Error::Invalid));r.client_context=[219;32];
        r.administrator=[0;32];assert_eq!(r.validate(),Err(Error::Invalid));
    }
    struct NeverExchange;
    impl WireTransport for NeverExchange{fn exchange(&mut self,_:&[u8])->Result<Box<dyn std::io::Read>,ProviderError>{panic!("missing enrollment must precede IO")}}
    #[test] fn missing_installed_enrollment_refuses_before_custody_or_transport(){
        assert_eq!(configured_approval(b"invalid").err(),Some(Error::MissingEnrollment));
        assert_eq!(configured_provider(b"invalid",b"not-custody","",NeverExchange).err(),Some(Error::MissingEnrollment));
        assert_eq!(crate::deployment_status(),Err(crate::StartupRefusal::MissingAuthenticEnrollment));
    }
    #[test] fn opened_client_role_context_key_and_actual_generation_refuse(){
        let(r,client,service)=fixture();let a=approved(r);
        let raw=client.seal_for(VALUE,1,&a.record.client_context).unwrap();open_client(&a,&raw,VALUE).unwrap();
        let raw=client.seal_for(VALUE,2,&a.record.client_context).unwrap();assert_eq!(open_client(&a,&raw,VALUE).err(),Some(Error::Custody));
        let raw=client.seal_for(VALUE,1,&a.record.service_context).unwrap();assert_eq!(open_client(&a,&raw,VALUE).err(),Some(Error::Custody));
        let raw=service.seal_for(VALUE,1,&a.record.client_context).unwrap();assert_eq!(open_client(&a,&raw,VALUE).err(),Some(Error::Custody));
        let other=HybridKey::generate(Role::Node).unwrap();let raw=other.seal_for(VALUE,1,&a.record.client_context).unwrap();
        assert_eq!(open_client(&a,&raw,VALUE).err(),Some(Error::Custody));
    }
    #[test] fn opened_service_generation_and_role_are_rechecked_before_publication(){
        let(r,client,service)=fixture();let a=approved(r);
        let raw=service.seal_for(VALUE,1,&a.record.service_context).unwrap();a.service_custody(&raw,VALUE).unwrap().into_verified_key(&a).unwrap();
        let raw=service.seal_for(VALUE,2,&a.record.service_context).unwrap();assert_eq!(a.service_custody(&raw,VALUE).err(),Some(Error::Custody));
        let raw=client.seal_for(VALUE,1,&a.record.service_context).unwrap();assert_eq!(a.service_custody(&raw,VALUE).err(),Some(Error::Custody));
    }
}

#[cfg(test)] #[path="treasury_application_entry_controls_v1.rs"] mod entry_controls;
