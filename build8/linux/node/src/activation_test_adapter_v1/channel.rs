//! Memory-only private records carried by an EXISTING completed hybrid-auth
//! transport Session. No plaintext response goes into public object/pool storage.
//! The caller independently provisions exact transport keys/roles and Context;
//! session/peer matches are an encrypted channel boundary, never an admission
//! or physical-TPM capability. No new handshake/domain/signing key is introduced.
use super::{exchange::{ChallengeFrame,ResponseFrame,MAX_FRAME},Error,Result};
use mutiny_consensus_v8::Hash;
use mutiny_transport_v2::{Context,Metadata,Session,MAX_PAYLOAD};
use zeroize::Zeroizing;
const PRIVATE_RECORD_DOMAIN:&[u8]=b"BUILD8-PRIVATE-ACTIVATION-TEST-RECORD-V1";
const MAX_ENCRYPTED_FRAGMENT:usize=255;
const MAX_RESPONSE:usize=512;
pub struct PrivateChannel {session:Session}
#[derive(Clone,Copy)]
enum Direction {Challenge=1,Response=2}
fn object(expected:&ChallengeFrame,direction:Direction)->Result<Hash>{
    let public=expected.encode()?;
    // Encrypted credential bytes are public to this enrollment exchange. A raw
    // recovered secret is NEVER hashed into public object metadata.
    let mut bound=Vec::with_capacity(public.len()+1);bound.push(direction as u8);bound.extend(public);
    Ok(mutiny_consensus_v8::domain_hash(PRIVATE_RECORD_DOMAIN,&bound))
}
impl PrivateChannel {
    pub fn matches_network(&self,genesis:Hash,fingerprint:Hash)->bool{
        self.session.matches_network(genesis,fingerprint)
    }
    pub fn from_authenticated(session:Session,expected:&Context,peer:Hash)->Result<Self>{
        if peer==[0;32]||!session.matches_context(expected)||session.peer_id()!=peer{return Err(Error::Endpoint);}
        Ok(Self{session})
    }
    fn seal(&mut self,expected:&ChallengeFrame,direction:Direction,raw:&[u8])->Result<Vec<Vec<u8>>>{
        let limit=match direction {Direction::Challenge=>MAX_FRAME,Direction::Response=>MAX_RESPONSE};
        if raw.is_empty()||raw.len()>limit{return Err(Error::Bounds);}
        let id=object(expected,direction)?;let count=raw.len().div_ceil(MAX_PAYLOAD);
        let mut frames=Vec::with_capacity(count);
        for (i,bytes) in raw.chunks(MAX_PAYLOAD).enumerate(){
            let meta=Metadata{kind:3,object:id,fragment:i as u16,count:count as u16,hops:0};
            frames.push(self.session.seal(&meta,bytes).map_err(|_|Error::Endpoint)?);
        }Ok(frames)
    }
    fn open(&mut self,expected:&ChallengeFrame,direction:Direction,frames:&[Vec<u8>])->Result<Zeroizing<Vec<u8>>>{
        let limit=match direction {Direction::Challenge=>MAX_FRAME,Direction::Response=>MAX_RESPONSE};
        if frames.is_empty()||frames.len()>limit.div_ceil(MAX_PAYLOAD){return Err(Error::Bounds);}
        let id=object(expected,direction)?;
        let mut plaintext=Zeroizing::new(Vec::with_capacity(limit));
        for (index,frame) in frames.iter().enumerate(){
            if frame.len()>MAX_ENCRYPTED_FRAGMENT{return Err(Error::Bounds);}
            let (meta,value)=self.session.open(frame).map_err(|_|Error::Endpoint)?;
            let value=Zeroizing::new(value);
            if meta.kind!=3||meta.object!=id||meta.hops!=0||meta.fragment as usize!=index
                ||meta.count as usize!=frames.len()||value.is_empty()
                ||(index+1<frames.len() && value.len()!=MAX_PAYLOAD)
                ||plaintext.len().checked_add(value.len()).is_none_or(|n|n>limit){return Err(Error::Context);}
            plaintext.extend_from_slice(&value);
        }Ok(plaintext)
    }
    pub fn seal_challenge(&mut self,expected:&ChallengeFrame)->Result<Vec<Vec<u8>>>{
        self.seal(expected,Direction::Challenge,&expected.encode()?)
    }
    pub fn open_challenge(&mut self,expected:&ChallengeFrame,frames:&[Vec<u8>])->Result<ChallengeFrame>{
        let raw=self.open(expected,Direction::Challenge,frames)?;
        let actual=ChallengeFrame::decode(&raw)?;
        if actual.encode()?!=expected.encode()?{return Err(Error::Context);}Ok(actual)
    }
    /// The endpoint owns this native request independently. Random credential
    /// bytes/session arrive over the pinned channel; they grant no authority.
    /// Decode only after bounded authenticated ordered fragments, then bind all
    /// fields and the metadata object to this exact admission/class endpoint.
    pub fn open_requested_challenge(&mut self,request:&mutiny_consensus_v8::activation_attestation_v1::Request,
        admission:u32,class:u8,frames:&[Vec<u8>])->Result<ChallengeFrame>{
        let parent=request.scope().parent();
        if !self.matches_network(parent.genesis,parent.fingerprint)
            ||frames.is_empty()||frames.len()>MAX_FRAME.div_ceil(MAX_PAYLOAD){return Err(Error::Context);}
        let selected=request.scope().admissions().get(admission as usize).ok_or(Error::Context)?;
        let identity=selected.endorsements().get(class as usize).ok_or(Error::Context)?;
        let mut plaintext=Zeroizing::new(Vec::with_capacity(MAX_FRAME));let mut expected_object=None;
        for (index,frame) in frames.iter().enumerate(){
            if !(116..=MAX_ENCRYPTED_FRAGMENT).contains(&frame.len()){return Err(Error::Bounds);}
            let(meta,value)=self.session.open(frame).map_err(|_|Error::Endpoint)?;
            let value=Zeroizing::new(value);
            if meta.kind!=3||meta.hops!=0||meta.fragment as usize!=index
                ||meta.count as usize!=frames.len()||value.is_empty()
                ||(index+1<frames.len()&&value.len()!=MAX_PAYLOAD)
                ||plaintext.len().checked_add(value.len()).is_none_or(|n|n>MAX_FRAME)
                ||expected_object.is_some_and(|id|id!=meta.object){return Err(Error::Context);}
            expected_object=Some(meta.object);plaintext.extend_from_slice(&value);
        }
        let actual=ChallengeFrame::decode(&plaintext)?;
        if actual.scope!=request.scope().commitment()||actual.signer!=request.signer()
            ||actual.round!=request.round()||actual.step!=request.step()||actual.items.len()!=1
            ||expected_object!=Some(object(&actual,Direction::Challenge)?){return Err(Error::Context);}
        let item=&actual.items[0];
        if item.admission!=admission||item.class!=class||&item.identity!=identity
            ||&item.ak_name!=selected.ak_name(){return Err(Error::Context);}
        Ok(actual)
    }
    pub fn seal_response(&mut self,expected:&ChallengeFrame,response:&ResponseFrame)->Result<Vec<Vec<u8>>>{
        let raw=response.encode_private()?;
        // Refuse a response created against a different request before sending.
        ResponseFrame::decode_private(Zeroizing::new(raw.to_vec()),expected)?;
        self.seal(expected,Direction::Response,&raw)
    }
    pub fn open_response(&mut self,expected:&ChallengeFrame,frames:&[Vec<u8>])->Result<ResponseFrame>{
        let raw=self.open(expected,Direction::Response,frames)?;
        ResponseFrame::decode_private(raw,expected)
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use mutiny_crypto_v2::{HybridKey,Role};
    use mutiny_transport_v2::{Endpoint,InitiatorPending,ResponderPending};
    pub(crate) fn pair()->(PrivateChannel,PrivateChannel){
        let a=HybridKey::generate(Role::Transport).unwrap();let b=HybridKey::generate(Role::Transport).unwrap();
        let ae=Endpoint::pinned(a.public().clone(),1).unwrap();let be=Endpoint::pinned(b.public().clone(),1).unwrap();
        let aid=ae.id();let bid=be.id();let ctx=Context::pinned([1;32],[2;32],ae,be).unwrap();
        let (ip,hello)=InitiatorPending::start(ctx.clone(),&a).unwrap();
        let (rp,response)=ResponderPending::accept(ctx.clone(),&b,&hello).unwrap();
        let (confirm,finish)=ip.accept(&a,&response).unwrap();let (bs,tag)=rp.finish(&finish).unwrap();
        let asession=confirm.finish(&tag).unwrap();
        (PrivateChannel::from_authenticated(asession,&ctx,bid).unwrap(),PrivateChannel::from_authenticated(bs,&ctx,aid).unwrap())
    }
    #[test]
    fn genuine_handshake_private_exchange_then_replay_refusal(){
        let (mut a,mut b)=pair();let f=super::super::exchange::tests::frame();
        let encrypted=a.seal_challenge(&f).unwrap();b.open_challenge(&f,&encrypted).unwrap();
        assert!(b.open_challenge(&f,&encrypted).is_err());
        let r=ResponseFrame::new(&f,vec![Zeroizing::new([10;32]),Zeroizing::new([11;32])]).unwrap();
        let encrypted=b.seal_response(&f,&r).unwrap();
        let actual=a.open_response(&f,&encrypted).unwrap();
        assert_eq!(actual.encode_private().unwrap().as_slice(),r.encode_private().unwrap().as_slice());
        assert!(a.open_response(&f,&encrypted).is_err());
    }
    #[test]
    fn genuine_authenticated_fragments_changed_ciphertext_context_and_order_refuse(){
        let (mut a,mut b)=pair();let f=super::super::exchange::tests::frame();
        let mut encrypted=a.seal_challenge(&f).unwrap();
        *encrypted[0].last_mut().unwrap()^=1;assert!(b.open_challenge(&f,&encrypted).is_err());
        *encrypted[0].last_mut().unwrap()^=1;b.open_challenge(&f,&encrypted).unwrap();
        let encrypted=a.seal_challenge(&f).unwrap();let mut other=super::super::exchange::tests::frame();other.round+=1;
        assert!(b.open_challenge(&other,&encrypted).is_err());
        let mut encrypted=a.seal_challenge(&f).unwrap();encrypted.swap(0,1);
        assert!(b.open_challenge(&f,&encrypted).is_err());
    }
}
