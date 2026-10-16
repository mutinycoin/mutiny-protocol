//! SOURCE ONLY / UNRUN. Private Linux TEST host native Endpoint-over-TCP.
//! Length prefixes/local IO budget copied from the reviewed TCP3 adapter;
//! no normal Provider/enrollment factory, proof/domain/TTL or Production enable.
//! The native Service stays on its creating thread and owns its held VFS.
//! PublicPins/verified signatures do not enroll a protected service. This module
//! cannot construct Provider, Snapshot or AuthenticatedReceipt; Production stays off.
use super::{Endpoint, Service, Policy, Error as ServiceError};
use crate::{Hash,
    treasury_continuity_v1::{HistoryEntry, Receipt, Request, Scope},
    treasury_continuity_provider_v1::{ProviderError, PublicSnapshot,
        authenticated_wire::{ClientAction, ClientSession, PublicPins,
            MAX_REQUEST_BYTES, MAX_TRANSCRIPT_BYTES, MAX_WIRE_BYTES}},
};
use mutiny_crypto_v2::{HybridKey, PublicKey};
use std::{io::{Read, Write}, net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    time::{Duration, Instant}};

// The unchanged envelope contains transcript, payload and hybrid signature.
// These are conservative local framing bounds; native wire validation follows.
pub const MAX_REQUEST_FRAME: usize = MAX_REQUEST_BYTES + MAX_TRANSCRIPT_BYTES + 2048;
pub const MAX_RESPONSE_FRAME: usize = MAX_WIRE_BYTES;
const _: () = assert!(MAX_RESPONSE_FRAME <= u32::MAX as usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error { Configuration, Idle, Unknown, Invalid, Authentication(ProviderError),
    Endpoint }
impl From<ProviderError> for Error {
    fn from(value: ProviderError) -> Self { Self::Authentication(value) }
}
impl From<ServiceError> for Error {
    fn from(value: ServiceError) -> Self {
        match value { ServiceError::Unknown => Self::Unknown, _ => Self::Endpoint }
    }
}

/// Explicit local availability input. No default, proof expiry, consensus TTL,
/// clock qualification, wall clock or automatic retry is attached to it.
#[derive(Clone, Copy)]
pub struct IoLimits { exchange: Duration }
impl IoLimits {
    pub fn new(exchange: Duration) -> Result<Self, Error> {
        if exchange.is_zero() || Instant::now().checked_add(exchange).is_none() {
            return Err(Error::Configuration);
        }
        Ok(Self { exchange })
    }
}
struct Deadline { end: Instant }
impl Deadline {
    fn start(limits: IoLimits) -> Result<Self, Error> {
        Ok(Self { end: Instant::now().checked_add(limits.exchange)
            .ok_or(Error::Configuration)? })
    }
    fn remaining_at(&self, now: Instant) -> Result<Duration, Error> {
        self.end.checked_duration_since(now).filter(|left| !left.is_zero())
            .ok_or(Error::Unknown)
    }
    fn remaining(&self) -> Result<Duration, Error> { self.remaining_at(Instant::now()) }
}
fn read_all(stream: &mut TcpStream, deadline: &Deadline, mut out: &mut [u8]) -> Result<(), Error> {
    while !out.is_empty() {
        stream.set_read_timeout(Some(deadline.remaining()?)).map_err(|_| Error::Unknown)?;
        match stream.read(out) {
            Ok(0) => return Err(Error::Unknown),
            Ok(n) => { deadline.remaining()?; out = &mut out[n..]; }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => { deadline.remaining()?; }
            Err(_) => return Err(Error::Unknown),
        }
    }
    Ok(())
}
fn write_all(stream: &mut TcpStream, deadline: &Deadline, mut bytes: &[u8]) -> Result<(), Error> {
    while !bytes.is_empty() {
        stream.set_write_timeout(Some(deadline.remaining()?)).map_err(|_| Error::Unknown)?;
        match stream.write(bytes) {
            Ok(0) => return Err(Error::Unknown),
            Ok(n) => { deadline.remaining()?; bytes = &bytes[n..]; }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => { deadline.remaining()?; }
            Err(_) => return Err(Error::Unknown),
        }
    }
    Ok(())
}
fn frame(stream: &mut TcpStream, deadline: &Deadline, raw: &[u8], cap: usize) -> Result<(), Error> {
    if raw.is_empty() || raw.len() > cap { return Err(Error::Invalid); }
    let count: u32 = raw.len().try_into().map_err(|_| Error::Invalid)?;
    write_all(stream, deadline, &count.to_be_bytes())?;
    write_all(stream, deadline, raw)
}
fn read_frame(stream: &mut TcpStream, deadline: &Deadline, cap: usize) -> Result<Vec<u8>, Error> {
    let mut prefix = [0; 4]; read_all(stream, deadline, &mut prefix)?;
    let count = u32::from_be_bytes(prefix) as usize;
    if count == 0 || count > cap { return Err(Error::Invalid); }
    let mut raw = vec![0; count]; // Only after the public length bound.
    read_all(stream, deadline, &mut raw)?;
    Ok(raw)
}
fn exact_eof(stream: &mut TcpStream, deadline: &Deadline) -> Result<(), Error> {
    let mut trailing = [0; 1];
    loop {
        stream.set_read_timeout(Some(deadline.remaining()?)).map_err(|_| Error::Unknown)?;
        match stream.read(&mut trailing) {
            Ok(0) => { deadline.remaining()?; return Ok(()); }
            Ok(_) => return Err(Error::Invalid),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => { deadline.remaining()?; }
            Err(_) => return Err(Error::Unknown),
        }
    }
}

/// One connection per session, numeric address only. No DNS fallback, reuse,
/// pipelining, implicit retry, app queue or private message logging.
pub struct TcpExchange { endpoint: SocketAddr, limits: IoLimits }
impl TcpExchange {
    pub fn new(endpoint: SocketAddr, limits: IoLimits) -> Result<Self, Error> {
        if endpoint.port() == 0 || endpoint.ip().is_unspecified() { return Err(Error::Configuration); }
        Ok(Self { endpoint, limits })
    }
    pub fn exchange(&mut self, request: &[u8]) -> Result<Vec<u8>, Error> {
        if request.is_empty() || request.len() > MAX_REQUEST_FRAME { return Err(Error::Invalid); }
        let deadline = Deadline::start(self.limits)?;
        let mut stream = TcpStream::connect_timeout(&self.endpoint, deadline.remaining()?)
            .map_err(|_| Error::Unknown)?;
        deadline.remaining()?;
        frame(&mut stream, &deadline, request, MAX_REQUEST_FRAME)?;
        stream.shutdown(Shutdown::Write).map_err(|_| Error::Unknown)?;
        let reply = read_frame(&mut stream, &deadline, MAX_RESPONSE_FRAME)?;
        exact_eof(&mut stream, &deadline)?;
        Ok(reply)
    }
}

/// Mutable endpoint owner serializes service execution. At most one accepted
/// connection/request/response exists in this application; no worker queue.
/// Kernel listen backlog is OS-bounded, not a new app reservation or priority.
/// The caller drives idle polling; this API adds no sleep, daemon or automatic loop.
pub struct SerializedEndpoint { listener: TcpListener, endpoint: Endpoint, limits: IoLimits }
impl SerializedEndpoint {
    pub fn bind(address: SocketAddr, endpoint: Endpoint, limits: IoLimits) -> Result<Self, Error> {
        let listener = TcpListener::bind(address).map_err(|_| Error::Unknown)?;
        listener.set_nonblocking(true).map_err(|_| Error::Unknown)?;
        Ok(Self { listener, endpoint, limits })
    }
    pub fn local_addr(&self) -> Result<SocketAddr, Error> { self.listener.local_addr().map_err(|_| Error::Unknown) }
    pub fn serve_ready(&mut self) -> Result<(), Error> {
        match self.listener.accept() {
            Ok((stream, _)) => serve_stream(&mut self.endpoint, stream, self.limits),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Err(Error::Idle),
            Err(_) => Err(Error::Unknown),
        }
    }
    pub(crate) fn serve_ready_until(&mut self,end:Instant)->Result<(),Error>{
        let deadline=Deadline{end};deadline.remaining()?;
        match self.listener.accept(){
            Ok((stream,_))=>serve_stream_deadline(&mut self.endpoint,stream,deadline),
            Err(error) if error.kind()==std::io::ErrorKind::WouldBlock=>Err(Error::Idle),
            Err(_)=>Err(Error::Unknown),
        }
    }
}
fn serve_stream(endpoint: &mut Endpoint, stream: TcpStream, limits: IoLimits) -> Result<(), Error> {
    serve_stream_deadline(endpoint,stream,Deadline::start(limits)?)
}
fn serve_stream_deadline(endpoint:&mut Endpoint,mut stream:TcpStream,deadline:Deadline)->Result<(),Error>{
    // Accepted sockets are explicitly blocking for bounded timeout IO on every OS.
    stream.set_nonblocking(false).map_err(|_| Error::Unknown)?;
    let request = read_frame(&mut stream, &deadline, MAX_REQUEST_FRAME)?;
    exact_eof(&mut stream, &deadline)?; // Trailing/second request refuses before DB action.
    deadline.remaining()?;
    let reply = endpoint.handle(&request)?;
    // The commit/signature may finish after the local budget. No ACK is sent;
    // remote result is UNKNOWN, never rolled back or automatically resubmitted.
    deadline.remaining()?;
    frame(&mut stream, &deadline, &reply, MAX_RESPONSE_FRAME)?;
    stream.shutdown(Shutdown::Write).map_err(|_| Error::Unknown)?;
    deadline.remaining()?;
    Ok(())
}


/// Ordinary approved transport and private TEST paths use the existing authenticated wire client.
/// It returns bytes only; signatures/context/history are checked by Provider.
pub(crate) struct NativeWire { transport: TcpExchange }
impl crate::treasury_continuity_provider_v1::authenticated_wire::WireTransport for NativeWire {
    fn exchange(&mut self,request:&[u8])->Result<Box<dyn Read>,ProviderError>{
        let raw=self.transport.exchange(request).map_err(|e|match e {
            Error::Invalid|Error::Configuration=>ProviderError::Invalid,
            _=>ProviderError::Unknown,
        })?;
        Ok(Box::new(std::io::Cursor::new(raw)))
    }
}
#[cfg(test)]
type TestProvider=crate::treasury_continuity_provider_v1::authenticated_wire::AuthenticatedProvider<NativeWire>;

/// This capability constructor is absent from the normal library graph.
/// Selected pins/keys are synthetic TEST premises, not administrator enrollment.
#[cfg(test)]
fn test_provider(pins:PublicPins,key:HybridKey,address:SocketAddr,limits:IoLimits)
    ->Result<TestProvider,ProviderError>{
    let transport=TcpExchange::new(address,limits).map_err(|_|ProviderError::Invalid)?;
    crate::treasury_continuity_provider_v1::authenticated_wire::AuthenticatedProvider::modeled(
        pins,key,NativeWire{transport})
}

/// Concrete nonshipping existing-only startup funnel. CanonicalOwner performs
/// authenticated latest/history audit and derives all current/retired keys from
/// the real canonical store. Public pins are not promoted into normal authority.
#[cfg(test)]
fn open_current_testvalue<'a>(directory:&std::path::Path,
    identity:crate::treasury_admission_v3::StoreIdentity,
    storage:crate::treasury_admission_v3::LocalStoragePolicy,
    chain:&'a crate::canonical_store_v2::CanonicalStore,
    config:crate::treasury_rehearsal_v3::CeremonyConfig,
    pins:PublicPins,client:HybridKey,address:SocketAddr,limits:IoLimits,
    denylist:crate::treasury_rehearsal_v3::Denylist)
    ->Result<crate::treasury_continuity_owner_v1::canonical_startup::CanonicalOwner<'a,TestProvider>,
        crate::treasury_continuity_owner_v1::Error>{
    if config.phase()!=mutiny_crypto_v2::treasury_proof_v1::Phase::Rehearsal
        || config.class()!=crate::treasury_v1::Class::TestValue {
        return Err(crate::treasury_continuity_owner_v1::Error::Context);
    }
    let scope=pins.scope().clone();
    let provider=test_provider(pins,client,address,limits)
        .map_err(crate::treasury_continuity_owner_v1::Error::Provider)?;
    crate::treasury_continuity_owner_v1::canonical_startup::CanonicalOwner::open_native(
        directory,identity,storage,chain,config,provider,scope,denylist)
}

/// Native held-owner service creation/reopen. Existing data requires an exact
/// independently trusted head before read-only replay/writable promotion.
impl SerializedEndpoint {
    #[cfg(test)]
    fn create_testvalue(address:SocketAddr,config:&crate::treasury_rehearsal_v3::CeremonyConfig,
        directory:&std::path::Path,pins:PublicPins,key:HybridKey,policy:Policy,limits:IoLimits)
        ->Result<Self,Error>{
        let service=Service::create_native(directory,config,pins.scope().clone(),policy)?;
        Self::bind(address,Endpoint::new(service,pins,key)?,limits)
    }
    #[cfg(test)]
    fn reopen_testvalue(address:SocketAddr,config:&crate::treasury_rehearsal_v3::CeremonyConfig,
        directory:&std::path::Path,pins:PublicPins,key:HybridKey,policy:Policy,
        pinned:&PublicSnapshot,limits:IoLimits)->Result<Self,Error>{
        let service=Service::open_native(directory,config,pins.scope().clone(),policy,pinned,true)?;
        Self::bind(address,Endpoint::new(service,pins,key)?,limits)
    }
    pub(crate) fn close(self)->Result<(),Error>{
        let Self{listener,endpoint,limits:_}=self;drop(listener);
        // Close outcomes are final for this application owner. A failed public
        // storage owner stays quarantined instead of silently retrying in Drop.
        // Endpoint transport key still drops normally and erases its custody.
        let service_result=endpoint.service.close().map_err(|(retained,e)|{std::mem::forget(retained);Error::from(e)});
        let head_result=if let Some(head)=endpoint.head{head.close_final().map_err(|_|Error::Unknown)}else{Ok(())};
        service_result.and(head_result)
    }
}

#[cfg(test)] #[path="../controls/native_service_tcp_controls.rs"] mod tests;


// Application projection ONLY. Not registered in Source3 TEST-host graph or
// consensus shipping graph; exact normal native dependency review required.
impl NativeWire{
    pub(crate) fn for_approved_application(
        a:&crate::treasury_application_enrollment_v1::VerifiedApproval)->Result<Self,Error>{
        let limits=IoLimits::new(a.io_budget())?;
        Ok(Self{transport:TcpExchange::new(a.address(),limits)?})
    }
}
impl SerializedEndpoint{
    pub(crate) fn reopen_approved_application(
        a:&crate::treasury_application_enrollment_v1::VerifiedApproval,
        head:crate::treasury_application_enrollment_v1::protected_head::HeadOwner,
        custody:crate::treasury_application_enrollment_v1::OpenedService,
        config:&crate::treasury_rehearsal_v3::CeremonyConfig,policy:Policy)->Result<Self,Error>{
        let key=custody.into_verified_key(a).map_err(|_|Error::Authentication(ProviderError::Authentication))?;
        let limits=IoLimits::new(a.io_budget())?;
        let service=Service::open_native(a.service_path(),config,a.pins().scope().clone(),
            policy,a.checkpoint(),true)?;
        Self::bind(a.address(),Endpoint::with_head(service,a.pins().clone(),key,head)?,limits)
    }
}
