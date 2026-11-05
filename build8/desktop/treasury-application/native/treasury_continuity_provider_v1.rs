//! Local external-service contract. Public codecs provide no authentication.
//! Ordinary application-private approved construction is registered here;
//! authentic inputs and qualified deployment remain absent, so Production is off.
use crate::{Hash,treasury_continuity_v1::{self as protocol,Action,Engine,Error,HistoryEntry,Outcome,Receipt,Request,Scope}};
use minicbor::{Decoder,Encoder};
pub const MAX_HISTORY:usize=4096;
pub const MAX_RECEIPT_BYTES:usize=1024;
// Complete bounded history; this is an implementation transport bound, not a
// changed Treasury proof, consensus carrier or expiry. Full replay is O(history).
pub const MAX_SNAPSHOT_BYTES:usize=MAX_HISTORY*8192+65536;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub enum ProviderError { Unavailable,Unknown,Authentication,Context,Invalid,Conflict,Full }
// Artifact-only authenticated wire codec. Its public pin/codec constructors do
// not enroll an identity or mint provider authority. The private application
// factory requires exact installed approval and current protected-head replay;
// deployment/custody/restore separation remains unqualified.
#[path = "treasury_continuity_authenticated_wire_v1.rs"]
pub mod authenticated_wire;
/// Trusted adapter boundary, not an implementable caller assertion of trust:
/// opaque return values have no normal public constructors. Current production
/// backend is unavailable. Implementations must authenticate a fresh session and
/// linearizable latest state under independently enrolled immutable scope.
pub trait Provider {
    fn scope(&self)->&Scope;
    fn current(&mut self,fresh_nonce:Hash)->Result<Snapshot,ProviderError>;
    fn transition(&mut self,request:&Request)->Result<AuthenticatedReceipt,ProviderError>;
}
/// Authenticated current-state authority. No public constructor/decoder/Clone.
pub struct Snapshot { public:PublicSnapshot }
impl Snapshot {
    pub fn scope(&self)->&Scope{self.public.scope()}
    pub fn sequence(&self)->u64{self.public.sequence()}
    pub fn pending_operation(&self)->Option<Hash>{self.public.pending_operation()}
    pub fn operations(&self)->&[HistoryEntry]{self.public.operations()}
    pub fn request_nonce(&self)->Hash{self.public.request_nonce()}
    #[cfg(test)]
    pub(crate) fn modeled(public:PublicSnapshot)->Self{Self{public}}
}
/// Exact authenticated transition result. A decoded public Receipt is not this.
pub struct AuthenticatedReceipt { receipt:Receipt }
impl AuthenticatedReceipt {
    pub fn receipt(&self)->&Receipt{&self.receipt}
    #[cfg(test)]
    pub(crate) fn modeled(receipt:Receipt)->Self{Self{receipt}}
}
/// Unauthenticated, bounded public state useful for transport and audits.
/// Validation/replay proves internal consistency only, never current authority.
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct PublicSnapshot {
    scope:Scope,request_nonce:Hash,sequence:u64,pending:Option<Hash>,history:Vec<HistoryEntry>,
}
impl PublicSnapshot {
    pub fn new(scope:Scope,request_nonce:Hash,sequence:u64,pending:Option<Hash>,history:Vec<HistoryEntry>)
        ->Result<Self,Error>{
        let value=Self{scope,request_nonce,sequence,pending,history};value.validate()?;Ok(value)
    }
    pub fn scope(&self)->&Scope{&self.scope}
    pub fn request_nonce(&self)->Hash{self.request_nonce}
    pub fn sequence(&self)->u64{self.sequence}
    pub fn pending_operation(&self)->Option<Hash>{self.pending}
    pub fn operations(&self)->&[HistoryEntry]{&self.history}
    pub fn validate(&self)->Result<(),Error>{
        if self.request_nonce==[0;32] || self.pending==Some([0;32]) || self.history.len()>MAX_HISTORY
            || self.sequence!=self.history.len() as u64{return Err(Error::Invalid);}
        let mut engine=Engine::new(self.scope.clone())?;
        for (index,item) in self.history.iter().enumerate(){
            if item.sequence!=index as u64+1{return Err(Error::Stale);}
            let request=replay_request(&self.scope,item)?;
            let receipt=engine.apply(&request)?;
            if receipt.repeated || receipt.operation_sequence!=item.sequence || receipt.outcome!=item.outcome{
                return Err(Error::Conflict);
            }
        }
        if engine.sequence()!=self.sequence || engine.pending_operation()!=self.pending{return Err(Error::Conflict);}
        Ok(())
    }
    pub fn encode(&self)->Result<Vec<u8>,Error>{
        self.validate()?;
        let mut e=Encoder::new(Vec::new());c(e.array(6))?;c(e.u8(1))?;
        encode_scope(&mut e,&self.scope)?;c(e.bytes(&self.request_nonce))?;c(e.u64(self.sequence))?;
        match self.pending {Some(hash)=>{c(e.bytes(&hash))?;},None=>{c(e.null())?;}}
        c(e.array(self.history.len() as u64))?;
        for item in &self.history {
            c(e.array(3))?;c(e.u64(item.sequence))?;c(e.u8(outcome_tag(item.outcome)))?;
            // These are replay records, not original request session nonces.
            // Exact action/scope/operation content is preserved canonically.
            c(e.bytes(&replay_request(&self.scope,item)?.encode()?))?;
        }
        let raw=e.into_writer();if raw.len()>MAX_SNAPSHOT_BYTES{return Err(Error::Full);}Ok(raw)
    }
    pub fn decode(raw:&[u8])->Result<Self,Error>{
        if raw.is_empty()||raw.len()>MAX_SNAPSHOT_BYTES{return Err(Error::Invalid);}
        let mut d=Decoder::new(raw);array(&mut d,6)?;if c(d.u8())?!=1{return Err(Error::Invalid);}
        let scope=decode_scope(&mut d)?;let request_nonce=hash(&mut d)?;let sequence=c(d.u64())?;
        let pending=optional_hash(&mut d)?;let count=c(d.array())?.ok_or(Error::Invalid)?;
        if count>MAX_HISTORY as u64{return Err(Error::Full);}
        let mut history=Vec::with_capacity(count as usize);
        for _ in 0..count{
            array(&mut d,3)?;let sequence=c(d.u64())?;let outcome=decode_outcome(c(d.u8())?)?;
            let wire=c(d.bytes())?;let request=Request::decode(wire)?;
            if request.scope!=scope || request.request_nonce!=request.operation
                || request.expected_sequence!=sequence.checked_sub(1).ok_or(Error::Invalid)?{return Err(Error::Conflict);}
            history.push(HistoryEntry{operation:request.operation,sequence,action:request.action,outcome});
        }
        let value=Self::new(scope,request_nonce,sequence,pending,history)?;
        if d.position()!=raw.len()||value.encode()?.as_slice()!=raw{return Err(Error::Invalid);}Ok(value)
    }
}
fn replay_request(scope:&Scope,item:&HistoryEntry)->Result<Request,Error>{
    Ok(Request{scope:scope.clone(),operation:item.operation,request_nonce:item.operation,
        expected_sequence:item.sequence.checked_sub(1).ok_or(Error::Invalid)?,action:item.action.clone()})
}
fn c<T,E>(value:Result<T,E>)->Result<T,Error>{value.map_err(|_|Error::Invalid)}
fn array(d:&mut Decoder<'_>,count:u64)->Result<(),Error>{if c(d.array())?!=Some(count){return Err(Error::Invalid);}Ok(())}
fn hash(d:&mut Decoder<'_>)->Result<Hash,Error>{c(c(d.bytes())?.try_into())}
fn optional_hash(d:&mut Decoder<'_>)->Result<Option<Hash>,Error>{
    if c(d.datatype())?==minicbor::data::Type::Null{c(d.null())?;Ok(None)}else{Ok(Some(hash(d)?))}
}
fn encode_scope(e:&mut Encoder<Vec<u8>>,scope:&Scope)->Result<(),Error>{
    Engine::new(scope.clone())?;c(e.array(7))?;c(e.u32(scope.network))?;
    match scope.genesis{Some(h)=>{c(e.bytes(&h))?;},None=>{c(e.null())?;}}
    for hash in [scope.ceremony_context,scope.treasury_record,scope.verifier,scope.store,scope.service]{c(e.bytes(&hash))?;}Ok(())
}
fn decode_scope(d:&mut Decoder<'_>)->Result<Scope,Error>{
    array(d,7)?;let scope=Scope{network:c(d.u32())?,genesis:optional_hash(d)?,ceremony_context:hash(d)?,
        treasury_record:hash(d)?,verifier:hash(d)?,store:hash(d)?,service:hash(d)?};Engine::new(scope.clone())?;Ok(scope)
}
fn outcome_tag(value:Outcome)->u8{match value{Outcome::Reserved=>0,Outcome::Consumed=>1,Outcome::LocalConfirmed=>2}}
fn decode_outcome(value:u8)->Result<Outcome,Error>{match value{0=>Ok(Outcome::Reserved),1=>Ok(Outcome::Consumed),2=>Ok(Outcome::LocalConfirmed),_=>Err(Error::Invalid)}}
fn validate_receipt(receipt:&Receipt)->Result<(),Error>{
    Engine::new(receipt.scope.clone())?;
    if [receipt.operation,receipt.content_commitment,receipt.request_nonce].contains(&[0;32])
        || receipt.operation_sequence==0 || receipt.operation_sequence>receipt.sequence || receipt.sequence>MAX_HISTORY as u64
        || (!receipt.repeated && receipt.operation_sequence!=receipt.sequence){return Err(Error::Invalid);}Ok(())
}
pub fn encode_receipt(receipt:&Receipt)->Result<Vec<u8>,Error>{
    validate_receipt(receipt)?;let mut e=Encoder::new(Vec::new());c(e.array(9))?;c(e.u8(1))?;
    encode_scope(&mut e,&receipt.scope)?;
    for hash in [receipt.operation,receipt.content_commitment,receipt.request_nonce]{c(e.bytes(&hash))?;}
    c(e.u64(receipt.sequence))?;c(e.u64(receipt.operation_sequence))?;c(e.u8(outcome_tag(receipt.outcome)))?;c(e.bool(receipt.repeated))?;
    let raw=e.into_writer();if raw.len()>MAX_RECEIPT_BYTES{return Err(Error::Full);}Ok(raw)
}
pub fn decode_receipt(raw:&[u8])->Result<Receipt,Error>{
    if raw.is_empty()||raw.len()>MAX_RECEIPT_BYTES{return Err(Error::Invalid);}
    let mut d=Decoder::new(raw);array(&mut d,9)?;if c(d.u8())?!=1{return Err(Error::Invalid);}
    let receipt=Receipt{scope:decode_scope(&mut d)?,operation:hash(&mut d)?,content_commitment:hash(&mut d)?,
        request_nonce:hash(&mut d)?,sequence:c(d.u64())?,operation_sequence:c(d.u64())?,outcome:decode_outcome(c(d.u8())?)?,repeated:c(d.bool())?};
    validate_receipt(&receipt)?;if d.position()!=raw.len()||encode_receipt(&receipt)?.as_slice()!=raw{return Err(Error::Invalid);}Ok(receipt)
}
/// Private TEST host only: simulates service authentication/admin separation.
/// It exercises normal complete replay/owner flow, not a qualified actual service.
#[cfg(test)]
pub(crate) struct ModeledProvider { pub(crate) engine:Engine }
#[cfg(test)]
impl ModeledProvider {pub(crate) fn new(scope:Scope)->Result<Self,Error>{Ok(Self{engine:Engine::new(scope)?})}}
#[cfg(test)]
impl Provider for ModeledProvider {
    fn scope(&self)->&Scope{self.engine.scope()}
    fn current(&mut self,nonce:Hash)->Result<Snapshot,ProviderError>{
        let public=PublicSnapshot::new(self.engine.scope().clone(),nonce,self.engine.sequence(),self.engine.pending_operation(),self.engine.history())
            .map_err(|_|ProviderError::Invalid)?;Ok(Snapshot::modeled(public))
    }
    fn transition(&mut self,request:&Request)->Result<AuthenticatedReceipt,ProviderError>{
        let receipt=self.engine.apply(request).map_err(|error|match error{Error::Full=>ProviderError::Full,Error::WrongScope=>ProviderError::Context,
            Error::Conflict|Error::Replay=>ProviderError::Conflict,_=>ProviderError::Invalid})?;
        protocol::check_receipt(request,&receipt).map_err(|_|ProviderError::Invalid)?;Ok(AuthenticatedReceipt::modeled(receipt))
    }
}
