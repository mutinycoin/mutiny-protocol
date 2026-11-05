//! Local external-service artifacts; no consensus proof, rule or spending role.
//! Public pins verify a selected signature, not enrollment/admin separation.
//! No normal AuthenticatedProvider constructor or shipping route is registered.
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
    // No normal factory. Actual enrolled identity/custody/admin-separated service
    // and native VFS qualification remain mandatory production inputs.
    #[cfg(test)]
    pub(crate) fn modeled(pins:PublicPins,key:HybridKey,transport:T)->Result<Self,ProviderError>{
        if key.public()!=&pins.client_key{return Err(ProviderError::Authentication);}
        Ok(Self{pins,key,transport,history:Vec::new()})
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
#[cfg(test)]
mod tests {
    use super::*;
    use protocol::{Action,Engine,PublicRecord};
    use std::io::Cursor;
    fn scope()->Scope{Scope{network:mutiny_crypto_v2::NETWORK,genesis:Some([1;32]),ceremony_context:[2;32],
        treasury_record:[3;32],verifier:[4;32],store:[5;32],service:[6;32]}}
    fn setup()->(PublicPins,HybridKey,HybridKey){
        let client=HybridKey::generate(Role::Transport).unwrap();let service=HybridKey::generate(Role::Transport).unwrap();
        let pins=PublicPins::new(scope(),[7;32],client.public().descriptor(1).unwrap(),service.public().descriptor(2).unwrap()).unwrap();
        (pins,client,service)
    }
    // Public model values are NOT genuine native Treasury proof/authority.
    // They exercise the real wire/signature/history gates with simulated service.
    fn record(nonce:u8)->PublicRecord{PublicRecord{generation:1,nonce:[nonce;32],challenge:vec![8;300],descriptor:vec![9;1900],signature:None}}
    fn request(id:u8,sequence:u64,action:Action)->Request{Request{scope:scope(),operation:[id;32],request_nonce:[id+1;32],expected_sequence:sequence,action}}
    fn snapshot(engine:&Engine,nonce:Hash)->PublicSnapshot{
        PublicSnapshot::new(engine.scope().clone(),nonce,engine.sequence(),engine.pending_operation(),engine.history()).unwrap()
    }
    #[test]
    fn authentic_wire_exact_context_role_generation_mode_nonce_and_both_halves(){
        let(pins,client,service)=setup();let action=ClientAction::Current{request_nonce:[10;32],minimum_sequence:0};
        let own=ClientSession::prepare(&pins,&client,action.clone()).unwrap();
        let response=VerifiedClientRequest::verify(&pins,own.wire()).unwrap()
            .sign_committed(&pins,&service,&snapshot(&Engine::new(scope()).unwrap(),[10;32]),None).unwrap();
        let duplicate=ClientSession::prepare(&pins,&client,action.clone()).unwrap();
        assert!(duplicate.accept(&pins,&response,&[]).is_err());
        assert_eq!(own.accept(&pins,&response,&[]).unwrap().0.sequence(),0);
        let wrong=HybridKey::generate(Role::Transport).unwrap();
        assert!(ClientSession::prepare(&pins,&wrong,action.clone()).is_err());
        let wrong_signer=ClientSession::prepare(&pins,&client,action.clone()).unwrap();
        let payload=response_payload(None,&snapshot(&Engine::new(scope()).unwrap(),[10;32])).unwrap();
        let body=transcript(&pins,1,0,wrong_signer.session,domain_hash(REQUEST_DOMAIN,wrong_signer.wire()),&payload).unwrap();
        let forged=wrong.sign(Domain::TreasuryContinuityServiceV1,&body).unwrap();
        let mut bytes=forged.ed448.to_vec();bytes.extend(forged.fndsa);
        assert!(wrong_signer.accept(&pins,&envelope(&body,&payload,&bytes).unwrap(),&[]).is_err());
        let wrong_request=ClientSession::prepare(&pins,&client,action.clone()).unwrap();
        let reply=sign_wire(&pins,&service,1,0,wrong_request.session,[99;32],&payload).unwrap();
        assert!(wrong_request.accept(&pins,&reply,&[]).is_err());
        let node=HybridKey::generate(Role::Node).unwrap();
        assert!(PublicPins::new(scope(),[7;32],node.public().descriptor(1).unwrap(),pins.service.clone()).is_err());
        let original=ClientSession::prepare(&pins,&client,action.clone()).unwrap();
        let changed=PublicPins::new(scope(),[7;32],client.public().descriptor(2).unwrap(),pins.service.clone()).unwrap();
        assert!(VerifiedClientRequest::verify(&changed,original.wire()).is_err());
        let changed=PublicPins::new(scope(),[7;32],pins.client.clone(),service.public().descriptor(3).unwrap()).unwrap();
        assert!(VerifiedClientRequest::verify(&changed,original.wire()).is_err());
        let changed=PublicPins::new(scope(),[11;32],pins.client.clone(),pins.service.clone()).unwrap();
        assert!(VerifiedClientRequest::verify(&changed,original.wire()).is_err());
        let mut other_scope=scope();other_scope.genesis=Some([12;32]);
        let changed=PublicPins::new(other_scope,[7;32],pins.client.clone(),pins.service.clone()).unwrap();
        assert!(VerifiedClientRequest::verify(&changed,original.wire()).is_err());
        // Coherent body/header/signature repacks isolate the individual binding.
        let payload=action.encode(&pins).unwrap();
        let wrong_mode=sign_wire(&pins,&client,0,1,original.session,[0;32],&payload).unwrap();
        assert!(VerifiedClientRequest::verify(&pins,&wrong_mode).is_err());
        let good=original.wire();let mut d=Decoder::new(good);d.array().unwrap();d.u8().unwrap();
        let body=d.bytes().unwrap();let payload=d.bytes().unwrap();let sig=d.bytes().unwrap();
        for offset in [0,124]{let mut invalid=sig.to_vec();invalid[offset]^=1;
            assert!(VerifiedClientRequest::verify(&pins,&envelope(body,payload,&invalid).unwrap()).is_err());}
        let mut changed=payload.to_vec();let last=changed.len()-1;changed[last]^=1;
        assert!(VerifiedClientRequest::verify(&pins,&envelope(body,&changed,sig).unwrap()).is_err());
        let mut trailing=good.to_vec();trailing.push(0);assert!(VerifiedClientRequest::verify(&pins,&trailing).is_err());
    }
    #[test]
    fn signed_stale_heads_and_forks_fail_against_own_authenticated_prefix(){
        let(pins,client,service)=setup();let mut engine=Engine::new(scope()).unwrap();
        let reserve=request(20,0,Action::Reserve(record(21)));engine.apply(&reserve).unwrap();
        let prefix=engine.history();
        for fork in [false,true]{
            let session=ClientSession::prepare(&pins,&client,ClientAction::Current{request_nonce:[22;32],minimum_sequence:1}).unwrap();
            let mut other=Engine::new(scope()).unwrap();
            if fork{let mut different=reserve.clone();different.action=Action::Reserve(record(23));other.apply(&different).unwrap();}
            let snap=snapshot(&other,[22;32]);
            // Deliberately bypass modeled endpoint's min-head check ONLY within
            // this private TEST to produce an authentically signed bad server.
            let raw=sign_wire(&pins,&service,1,0,session.session,domain_hash(REQUEST_DOMAIN,session.wire()),&response_payload(None,&snap).unwrap()).unwrap();
            assert!(session.accept(&pins,&raw,&prefix).is_err());
        }
        let session=ClientSession::prepare(&pins,&client,ClientAction::Current{request_nonce:[22;32],minimum_sequence:1}).unwrap();
        let response=VerifiedClientRequest::verify(&pins,session.wire()).unwrap().sign_committed(&pins,&service,&snapshot(&engine,[22;32]),None).unwrap();
        assert_eq!(session.accept(&pins,&response,&prefix).unwrap().0.operations(),prefix);
    }
    #[test]
    fn exact_retry_identity_survives_fresh_auth_sessions_and_receipt_requires_same_history(){
        let(pins,client,service)=setup();let mut engine=Engine::new(scope()).unwrap();
        let first=request(30,0,Action::Reserve(record(31)));let session=ClientSession::prepare(&pins,&client,ClientAction::Transition(first.clone())).unwrap();
        let receipt=engine.apply(&first).unwrap();let verified=VerifiedClientRequest::verify(&pins,session.wire()).unwrap();
        let response=verified.sign_committed(&pins,&service,&snapshot(&engine,first.request_nonce),Some(&receipt)).unwrap();
        let(prefix,verified_receipt)=session.accept(&pins,&response,&[]).unwrap();assert!(!verified_receipt.unwrap().repeated);
        let mut retry=first.clone();retry.request_nonce=[33;32];retry.expected_sequence=1;
        assert_eq!(first.content_commitment().unwrap(),retry.content_commitment().unwrap());
        let repeated=engine.apply(&retry).unwrap();assert!(repeated.repeated);assert_eq!(repeated.operation_sequence,1);
        let next=ClientSession::prepare(&pins,&client,ClientAction::Transition(retry.clone())).unwrap();
        let response=VerifiedClientRequest::verify(&pins,next.wire()).unwrap().sign_committed(&pins,&service,&snapshot(&engine,retry.request_nonce),Some(&repeated)).unwrap();
        assert!(next.accept(&pins,&response,prefix.operations()).unwrap().1.unwrap().repeated);
        let mut conflict=retry.clone();conflict.action=Action::Reserve(record(34));assert!(engine.apply(&conflict).is_err());
        let next=ClientSession::prepare(&pins,&client,ClientAction::Transition(retry.clone())).unwrap();
        let mut forged=repeated;forged.content_commitment[0]^=1;
        let response=sign_wire(&pins,&service,1,1,next.session,domain_hash(REQUEST_DOMAIN,next.wire()),&response_payload(Some(&forged),&snapshot(&engine,retry.request_nonce)).unwrap()).unwrap();
        assert!(next.accept(&pins,&response,prefix.operations()).is_err());
    }
    struct ModeledTransport {pins:PublicPins,key:HybridKey,engine:Engine,lose_ack:bool}
    impl WireTransport for ModeledTransport {
        fn exchange(&mut self,wire:&[u8])->Result<Box<dyn Read>,ProviderError>{
            let verified=VerifiedClientRequest::verify(&self.pins,wire)?;
            let receipt=match verified.action(){ClientAction::Current{..}=>None,ClientAction::Transition(request)=>Some(self.engine.apply(request).map_err(|_|ProviderError::Conflict)?)};
            let snap=snapshot(&self.engine,verified.action().request_nonce());
            let raw=verified.sign_committed(&self.pins,&self.key,&snap,receipt.as_ref())?;
            if self.lose_ack{self.lose_ack=false;return Err(ProviderError::Unknown);}
            Ok(Box::new(Cursor::new(raw)))
        }
    }
    #[test]
    fn opaque_test_provider_uses_real_crypto_and_lost_ack_never_creates_second_operation(){
        let(pins,client,service)=setup();let transport=ModeledTransport{pins:pins.clone(),key:service,engine:Engine::new(scope()).unwrap(),lose_ack:true};
        let mut provider=AuthenticatedProvider::modeled(pins,client,transport).unwrap();let first=request(40,0,Action::Reserve(record(41)));
        assert!(matches!(provider.transition(&first),Err(ProviderError::Unknown)));assert!(provider.history.is_empty());
        let mut retry=first;retry.request_nonce=[42;32];let receipt=provider.transition(&retry).unwrap();
        assert!(receipt.receipt().repeated);assert_eq!(receipt.receipt().operation_sequence,1);
        let current=provider.current([43;32]).unwrap();assert_eq!(current.sequence(),1);assert_eq!(current.operations().len(),1);
    }
}
