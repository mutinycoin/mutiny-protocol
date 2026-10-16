//! Local external-service artifacts; no consensus proof, rule or spending role.
//! Public pins verify a selected signature, not enrollment/admin separation.
//! Approved ordinary application construction exists; authentic installed inputs
//! remain missing, and no shipping production route is registered.
use super::{protocol,AuthenticatedReceipt,Provider,ProviderError,PublicSnapshot,Snapshot,
    MAX_HISTORY,MAX_SNAPSHOT_BYTES,encode_receipt,decode_receipt};
use crate::{Hash,domain_hash};
use protocol::{HistoryEntry,Receipt,Request,Scope};
use mutiny_crypto_v2::{Domain,HybridKey,HybridSignature,PublicKey,Role};
use minicbor::{Decoder,Encoder};
use std::io::Read;
pub const MAX_REQUEST_BYTES:usize=8192;
pub const MAX_TRANSCRIPT_BYTES:usize=8192;
pub const MAX_RESPONSE_PAYLOAD_BYTES:usize=MAX_SNAPSHOT_BYTES+2048;
pub const MAX_WIRE_BYTES:usize=MAX_RESPONSE_PAYLOAD_BYTES+MAX_TRANSCRIPT_BYTES+2048;
pub const PAYLOAD_DOMAIN:&[u8]=b"MUTINY-BUILD8-LOCAL-TREASURY-CONTINUITY-PAYLOAD-V1";
pub const REQUEST_DOMAIN:&[u8]=b"MUTINY-BUILD8-LOCAL-TREASURY-CONTINUITY-REQUEST-V1";
fn fail<T,E>(r:Result<T,E>)->Result<T,ProviderError>{r.map_err(|_|ProviderError::Invalid)}
fn array(d:&mut Decoder<'_>,n:u64)->Result<(),ProviderError>{
    if fail(d.array())?!=Some(n){return Err(ProviderError::Invalid);}Ok(())
}
fn hash(d:&mut Decoder<'_>)->Result<Hash,ProviderError>{fail(fail(d.bytes())?.try_into())}
/// Immutable selected public pins, explicitly not a trusted enrollment token.
#[derive(Clone)]
pub struct PublicPins {scope:Scope,context:Hash,client:Vec<u8>,service:Vec<u8>,client_key:PublicKey,service_key:PublicKey}
impl PublicPins {
    pub fn new(scope:Scope,context:Hash,client:Vec<u8>,service:Vec<u8>)->Result<Self,ProviderError>{
        if context==[0;32]||scope.network!=mutiny_crypto_v2::NETWORK{return Err(ProviderError::Context);}
        fail(protocol::Engine::new(scope.clone()))?;
        let (client_key,_)=PublicKey::decode_descriptor(&client).map_err(|_|ProviderError::Authentication)?;
        let (service_key,_)=PublicKey::decode_descriptor(&service).map_err(|_|ProviderError::Authentication)?;
        if client_key.role!=Role::Transport||service_key.role!=Role::Transport||client_key==service_key{
            return Err(ProviderError::Authentication);
        }
        Ok(Self{scope,context,client,service,client_key,service_key})
    }
    pub fn scope(&self)->&Scope{&self.scope}
    pub fn context(&self)->Hash{self.context}
    pub fn client_descriptor(&self)->&[u8]{&self.client}
    pub fn service_descriptor(&self)->&[u8]{&self.service}
}
#[derive(Clone,Debug,PartialEq,Eq)]
pub enum ClientAction { Current{request_nonce:Hash,minimum_sequence:u64},Transition(Request) }
impl ClientAction {
    fn mode(&self)->u8{match self{Self::Current{..}=>0,Self::Transition(_)=>1}}
    pub fn request_nonce(&self)->Hash{match self{Self::Current{request_nonce,..}=>*request_nonce,Self::Transition(r)=>r.request_nonce}}
    pub fn minimum_sequence(&self)->u64{match self{Self::Current{minimum_sequence,..}=>*minimum_sequence,Self::Transition(r)=>r.expected_sequence}}
    fn encode(&self,pins:&PublicPins)->Result<Vec<u8>,ProviderError>{
        if self.request_nonce()==[0;32]||self.minimum_sequence()>MAX_HISTORY as u64{return Err(ProviderError::Invalid);}
        let mut e=Encoder::new(Vec::new());
        match self {
            Self::Current{request_nonce,minimum_sequence}=>{
                fail(e.array(3))?;fail(e.u8(0))?;fail(e.bytes(request_nonce))?;fail(e.u64(*minimum_sequence))?;
            },
            Self::Transition(r)=>{
                if r.scope!=pins.scope{return Err(ProviderError::Context);}
                fail(e.array(2))?;fail(e.u8(1))?;fail(e.bytes(&fail(r.encode())?))?;
            }
        }
        let raw=e.into_writer();if raw.len()>MAX_REQUEST_BYTES{return Err(ProviderError::Full);}Ok(raw)
    }
    fn decode(raw:&[u8],pins:&PublicPins)->Result<Self,ProviderError>{
        if raw.len()>MAX_REQUEST_BYTES{return Err(ProviderError::Full);}
        let mut d=Decoder::new(raw);let count=fail(d.array())?;let mode=fail(d.u8())?;
        let value=match(count,mode){
            (Some(3),0)=>Self::Current{request_nonce:hash(&mut d)?,minimum_sequence:fail(d.u64())?},
            (Some(2),1)=>Self::Transition(fail(Request::decode(fail(d.bytes())?))?),
            _=>return Err(ProviderError::Invalid),
        };
        if d.position()!=raw.len()||value.encode(pins)?.as_slice()!=raw{return Err(ProviderError::Invalid);}Ok(value)
    }
}
fn transcript(pins:&PublicPins,direction:u8,mode:u8,session:Hash,request:Hash,payload:&[u8])->Result<Vec<u8>,ProviderError>{
    if session==[0;32]||direction>1||mode>1{return Err(ProviderError::Invalid);}
    let mut e=Encoder::new(Vec::new());fail(e.array(11))?;fail(e.u8(1))?;fail(e.u8(direction))?;fail(e.u8(mode))?;
    fail(e.bytes(&pins.context))?;
    super::encode_scope(&mut e,&pins.scope).map_err(|_|ProviderError::Invalid)?;
    fail(e.bytes(&pins.client))?;fail(e.bytes(&pins.service))?;fail(e.bytes(&session))?;fail(e.bytes(&request))?;
    fail(e.u64(payload.len() as u64))?;fail(e.bytes(&domain_hash(PAYLOAD_DOMAIN,payload)))?;
    let raw=e.into_writer();if raw.len()>MAX_TRANSCRIPT_BYTES{return Err(ProviderError::Full);}Ok(raw)
}
fn sign_wire(pins:&PublicPins,key:&HybridKey,direction:u8,mode:u8,session:Hash,request:Hash,payload:&[u8])->Result<Vec<u8>,ProviderError>{
    if payload.len()>MAX_RESPONSE_PAYLOAD_BYTES{return Err(ProviderError::Full);}
    let public=if direction==0{&pins.client_key}else{&pins.service_key};
    if key.public()!=public{return Err(ProviderError::Authentication);}
    let body=transcript(pins,direction,mode,session,request,payload)?;
    let domain=if direction==0{Domain::TreasuryContinuityClientV1}else{Domain::TreasuryContinuityServiceV1};
    let signature=key.sign(domain,&body).map_err(|_|ProviderError::Authentication)?;
    let mut sig=Vec::with_capacity(1394);sig.extend(signature.ed448);sig.extend(signature.fndsa);
    envelope(&body,payload,&sig)
}
fn envelope(body:&[u8],payload:&[u8],sig:&[u8])->Result<Vec<u8>,ProviderError>{
    let mut e=Encoder::new(Vec::new());fail(e.array(4))?;fail(e.u8(1))?;fail(e.bytes(body))?;fail(e.bytes(payload))?;fail(e.bytes(sig))?;
    let raw=e.into_writer();if raw.len()>MAX_WIRE_BYTES{return Err(ProviderError::Full);}Ok(raw)
}
fn verify_wire<'a>(pins:&PublicPins,raw:&'a[u8],direction:u8,expected:Option<(u8,Hash,Hash)>)->Result<(u8,Hash,&'a[u8]),ProviderError>{
    if raw.is_empty()||raw.len()>MAX_WIRE_BYTES{return Err(ProviderError::Full);}
    let mut d=Decoder::new(raw);array(&mut d,4)?;if fail(d.u8())?!=1{return Err(ProviderError::Invalid);}
    let body=fail(d.bytes())?;let payload=fail(d.bytes())?;let sig=fail(d.bytes())?;
    if body.len()>MAX_TRANSCRIPT_BYTES||payload.len()>MAX_RESPONSE_PAYLOAD_BYTES||sig.len()!=1394{return Err(ProviderError::Full);}
    if d.position()!=raw.len()||envelope(body,payload,sig)?.as_slice()!=raw{return Err(ProviderError::Invalid);}
    // Select only routing/session scalars from bounded untrusted header. Every
    // header field is then compared to a canonical own-pins reconstruction.
    let mut h=Decoder::new(body);array(&mut h,11)?;
    if fail(h.u8())?!=1||fail(h.u8())?!=direction{return Err(ProviderError::Context);}
    let mode=fail(h.u8())?;let _context=hash(&mut h)?;super::decode_scope(&mut h).map_err(|_|ProviderError::Invalid)?;
    let _client=fail(h.bytes())?;let _service=fail(h.bytes())?;let session=hash(&mut h)?;let request=hash(&mut h)?;
    let _length=fail(h.u64())?;let _digest=hash(&mut h)?;
    if h.position()!=body.len()||body!=transcript(pins,direction,mode,session,request,payload)?{
        return Err(ProviderError::Context);
    }
    if let Some(want)=expected {if want!=(mode,session,request){return Err(ProviderError::Context);}}
    else if request!=[0;32]{return Err(ProviderError::Context);}
    let signature=HybridSignature{ed448:fail(sig[..114].try_into())?,fndsa:fail(sig[114..].try_into())?};
    let public=if direction==0{&pins.client_key}else{&pins.service_key};
    let domain=if direction==0{Domain::TreasuryContinuityClientV1}else{Domain::TreasuryContinuityServiceV1};
    public.verify(domain,body,&signature).map_err(|_|ProviderError::Authentication)?;
    Ok((mode,session,payload))
}
/// Own fresh session, consumed on one response. No stored/restart authority.
pub struct ClientSession {action:ClientAction,session:Hash,request:Vec<u8>}
impl ClientSession {
    pub fn prepare(pins:&PublicPins,key:&HybridKey,action:ClientAction)->Result<Self,ProviderError>{
        let payload=action.encode(pins)?;let mut session=[0;32];
        mutiny_crypto_v2::fill_os_random(&mut session).map_err(|_|ProviderError::Unavailable)?;
        if session==[0;32]{return Err(ProviderError::Unavailable);}
        let request=sign_wire(pins,key,0,action.mode(),session,[0;32],&payload)?;
        Ok(Self{action,session,request})
    }
    pub fn wire(&self)->&[u8]{&self.request}
    /// Public signature/history inspection under caller-selected pins. This
    /// returns only public data, never Snapshot/AuthenticatedReceipt authority.
    pub fn inspect_response(self,pins:&PublicPins,wire:&[u8],own_history:&[HistoryEntry])
        ->Result<(PublicSnapshot,Option<Receipt>),ProviderError>{self.accept(pins,wire,own_history)}
    fn accept(self,pins:&PublicPins,wire:&[u8],history:&[HistoryEntry])->Result<(PublicSnapshot,Option<Receipt>),ProviderError>{
        let (_,_,payload)=verify_wire(pins,wire,1,Some((self.action.mode(),self.session,domain_hash(REQUEST_DOMAIN,&self.request))))?;
        let mut d=Decoder::new(payload);let count=fail(d.array())?;let mode=fail(d.u8())?;
        let (receipt,snapshot)=match (count,mode){
            (Some(2),0)=>(None,fail(PublicSnapshot::decode(fail(d.bytes())?))?),
            (Some(3),1)=>(Some(fail(decode_receipt(fail(d.bytes())?))?),fail(PublicSnapshot::decode(fail(d.bytes())?))?),
            _=>return Err(ProviderError::Invalid),
        };
        if d.position()!=payload.len()||response_payload(receipt.as_ref(),&snapshot)?.as_slice()!=payload{return Err(ProviderError::Invalid);}
        validate_response(pins,&self.action,&snapshot,receipt.as_ref())?;
        if snapshot.operations().len()<history.len()||&snapshot.operations()[..history.len()]!=history{
            return Err(ProviderError::Conflict);
        }
        Ok((snapshot,receipt))
    }
}
/// Authenticated under the selected public client pin, not production enrollment.
pub struct VerifiedClientRequest {action:ClientAction,session:Hash,request_hash:Hash}
impl VerifiedClientRequest {
    pub fn verify(pins:&PublicPins,raw:&[u8])->Result<Self,ProviderError>{
        if raw.len()>MAX_REQUEST_BYTES+MAX_TRANSCRIPT_BYTES+2048{return Err(ProviderError::Full);}
        let(mode,session,payload)=verify_wire(pins,raw,0,None)?;let action=ClientAction::decode(payload,pins)?;
        if mode!=action.mode(){return Err(ProviderError::Context);}
        Ok(Self{action,session,request_hash:domain_hash(REQUEST_DOMAIN,raw)})
    }
    pub fn action(&self)->&ClientAction{&self.action}
    /// Caller supplies the actual one-transaction committed state. Signature
    /// cannot establish administrator separation or make copied DB current.
    pub fn sign_committed(self,pins:&PublicPins,key:&HybridKey,snapshot:&PublicSnapshot,receipt:Option<&Receipt>)->Result<Vec<u8>,ProviderError>{
        validate_response(pins,&self.action,snapshot,receipt)?;
        sign_wire(pins,key,1,self.action.mode(),self.session,self.request_hash,&response_payload(receipt,snapshot)?)
    }
}
fn response_payload(receipt:Option<&Receipt>,snapshot:&PublicSnapshot)->Result<Vec<u8>,ProviderError>{
    let mut e=Encoder::new(Vec::new());fail(e.array(if receipt.is_some(){3}else{2}))?;fail(e.u8(u8::from(receipt.is_some())))?;
    if let Some(receipt)=receipt{fail(e.bytes(&fail(encode_receipt(receipt))?))?;}
    fail(e.bytes(&fail(snapshot.encode())?))?;let raw=e.into_writer();
    if raw.len()>MAX_RESPONSE_PAYLOAD_BYTES{return Err(ProviderError::Full);}Ok(raw)
}
fn validate_response(pins:&PublicPins,action:&ClientAction,snapshot:&PublicSnapshot,receipt:Option<&Receipt>)->Result<(),ProviderError>{
    fail(snapshot.validate())?;
    if snapshot.scope()!=pins.scope()||snapshot.request_nonce()!=action.request_nonce()
        ||snapshot.sequence()<action.minimum_sequence(){return Err(ProviderError::Context);}
    match(action,receipt){
        (ClientAction::Current{..},None)=>Ok(()),
        (ClientAction::Transition(request),Some(receipt))=>{
            protocol::check_receipt(request,receipt).map_err(|_|ProviderError::Conflict)?;
            if snapshot.sequence()!=receipt.sequence{return Err(ProviderError::Conflict);}
            let item=snapshot.operations().get(receipt.operation_sequence.checked_sub(1).ok_or(ProviderError::Invalid)? as usize)
                .ok_or(ProviderError::Conflict)?;
            if item.operation!=request.operation||item.action!=request.action||item.outcome!=receipt.outcome{
                return Err(ProviderError::Conflict);
            }Ok(())
        },_=>Err(ProviderError::Context),
    }
}
/// Raw untrusted response stream. A provider bounds reads itself; transport
/// cannot mint opaque authority or ask this API to trust a public completion bit.
pub trait WireTransport {fn exchange(&mut self,request:&[u8])->Result<Box<dyn Read>,ProviderError>;}
pub struct AuthenticatedProvider<T> {pins:PublicPins,key:HybridKey,transport:T,history:Vec<HistoryEntry>}
impl<T:WireTransport> AuthenticatedProvider<T> {
    // Ordinary application-only construction; no modeled/public pin factory.
    // The immutable configured approval must exist before this can be called.
    pub(crate) fn from_verified_application(
        approved:&crate::treasury_application_enrollment_v1::VerifiedApproval,
        key:HybridKey,opened_generation:u64,transport:T)->Result<Self,ProviderError>{
        let pins=approved.pins().clone();let checkpoint=approved.checkpoint();
        if !approved.provider_matches(&pins,checkpoint){return Err(ProviderError::Authentication);}
        checkpoint.validate().map_err(|_|ProviderError::Invalid)?;
        let(public,generation)=PublicKey::decode_descriptor(pins.client_descriptor())
            .map_err(|_|ProviderError::Authentication)?;
        if public.role!=mutiny_crypto_v2::Role::Transport||public!=*key.public()
            ||generation!=opened_generation||key.public().descriptor(opened_generation)
                .map_err(|_|ProviderError::Authentication)?!=pins.client_descriptor(){
            return Err(ProviderError::Authentication);
        }
        Ok(Self{pins,key,transport,history:checkpoint.operations().to_vec()})
    }

    // The approved ordinary factory above is separate from this TEST-only model.
    // Actual enrolled identity/custody/admin-separated service
    // and native VFS qualification remain mandatory production inputs.
    #[cfg(test)]
    pub(crate) fn modeled(pins:PublicPins,key:HybridKey,transport:T)->Result<Self,ProviderError>{
        if key.public()!=&pins.client_key{return Err(ProviderError::Authentication);}
        Ok(Self{pins,key,transport,history:Vec::new()})
    }
    /// Private TEST application enrollment only. Its caller owns the separately
    /// modeled approval; a decoded snapshot/public signature is not enrollment.
    /// Full retained prefix protects startup against stale/forked service state.
    #[cfg(test)]
    pub(crate) fn modeled_pinned_history(pins:PublicPins,key:HybridKey,transport:T,
        checkpoint:&PublicSnapshot)->Result<Self,ProviderError>{
        checkpoint.validate().map_err(|_|ProviderError::Invalid)?;
        if checkpoint.scope()!=pins.scope(){return Err(ProviderError::Context);}
        let mut provider=Self::modeled(pins,key,transport)?;
        // validate enforces sequence==history length. Existing prepare/accept
        // uses that length as sequence floor and requires exact entire prefix.
        provider.history=checkpoint.operations().to_vec();
        Ok(provider)
    }
    fn exchange(&mut self,action:ClientAction)->Result<(PublicSnapshot,Option<Receipt>),ProviderError>{
        let session=ClientSession::prepare(&self.pins,&self.key,action)?;
        let stream=self.transport.exchange(session.wire())?;let mut raw=Vec::new();
        stream.take((MAX_WIRE_BYTES+1) as u64).read_to_end(&mut raw).map_err(|_|ProviderError::Unknown)?;
        if raw.len()>MAX_WIRE_BYTES{return Err(ProviderError::Full);}
        let(snapshot,receipt)=session.accept(&self.pins,&raw,&self.history)?;
        self.history=snapshot.operations().to_vec();Ok((snapshot,receipt))
    }
}
impl<T:WireTransport> Provider for AuthenticatedProvider<T> {
    fn scope(&self)->&Scope{self.pins.scope()}
    fn current(&mut self,nonce:Hash)->Result<Snapshot,ProviderError>{
        let(snapshot,receipt)=self.exchange(ClientAction::Current{request_nonce:nonce,minimum_sequence:self.history.len() as u64})?;
        if receipt.is_some(){return Err(ProviderError::Context);}Ok(Snapshot{public:snapshot})
    }
    fn transition(&mut self,request:&Request)->Result<AuthenticatedReceipt,ProviderError>{
        let(_,receipt)=self.exchange(ClientAction::Transition(request.clone()))?;
        Ok(AuthenticatedReceipt{receipt:receipt.ok_or(ProviderError::Context)?})
    }
}
