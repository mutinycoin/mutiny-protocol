//! Proposed private off-chain schema only. Authentication/confidentiality must
//! be supplied by an independently pinned enrollment channel. A decoded frame
//! is never a signing grant, physical qualification, or canonical evidence.
use super::{Error, Result};
use minicbor::{Decoder, Encoder};
use mutiny_consensus_v8::{Hash, NETWORK_ID, activation_attestation_v1::{Exchange, RecoveryResponse}};
use zeroize::{Zeroize,Zeroizing};
pub const SCHEMA: &[u8] = b"BUILD8-PRIVATE-ACTIVATION-TEST-V1";
// Private transport chunk only, not a new consensus/body capacity.
// Larger native scopes are exchanged in ordered chunks under the same session.
pub const MAX_CHALLENGES: usize = 4;
pub const MAX_FRAME: usize = 65536;
pub struct EncryptedItem {pub admission:u32,pub class:u8,pub identity:Hash,
    pub ak_name:[u8;34],pub credential:Vec<u8>,pub seed:Vec<u8>}
pub struct ChallengeFrame {pub session:Hash,pub scope:Hash,pub signer:Hash,
    pub round:u64,pub step:u8,pub items:Vec<EncryptedItem>}
fn array(d:&mut Decoder<'_>,n:u64)->Result<()> {
    if d.array().map_err(|_|Error::Codec)?!=Some(n){return Err(Error::Codec);} Ok(())
}
fn fixed<const N:usize>(d:&mut Decoder<'_>)->Result<[u8;N]>{
    d.bytes().map_err(|_|Error::Codec)?.try_into().map_err(|_|Error::Codec)
}
impl ChallengeFrame {
    pub fn from_exchange(e:&Exchange)->Result<Self>{
        Self::from_exchange_range(e,0..e.challenges.len())
    }
    pub fn from_exchange_range(e:&Exchange,range:std::ops::Range<usize>)->Result<Self>{
        let selected=e.challenges.get(range).ok_or(Error::Bounds)?;
        if selected.is_empty() || selected.len()>MAX_CHALLENGES{return Err(Error::Bounds);}
        let mut items=Vec::new();
        for c in selected {
            let a=e.request.scope().admissions().get(c.admission_index as usize).ok_or(Error::Context)?;
            if a.endorsements().get(c.class_index as usize)!=Some(&c.identity){return Err(Error::Context);}
            items.push(EncryptedItem{admission:c.admission_index,class:c.class_index,identity:c.identity,
                ak_name:*a.ak_name(),credential:c.encrypted.credential().to_vec(),seed:c.encrypted.encrypted_seed().to_vec()});
        }
        let value=Self{session:e.session,scope:e.request.scope().commitment(),signer:e.request.signer(),
            round:e.request.round(),step:e.request.step(),items}; value.encode()?; Ok(value)
    }
    fn check(&self)->Result<()> {
        if [self.session,self.scope,self.signer].contains(&[0;32]) || ![2,3].contains(&self.step)
            || self.items.is_empty() || self.items.len()>MAX_CHALLENGES{return Err(Error::Bounds);}
        let mut previous=None;
        for c in &self.items {
            // Scope may append one separately prepared recovery to 4096 items.
            if c.admission>4096 || c.class>=4 || c.identity==[0;32] || c.ak_name[..2]!=[0,11]
                || c.credential.is_empty() || c.seed.is_empty() || c.credential.len()>4096 || c.seed.len()>4096 {
                return Err(Error::Bounds);
            }
            if previous.is_some_and(|p|p>=(c.admission,c.class)){return Err(Error::Context);}
            previous=Some((c.admission,c.class));
        } Ok(())
    }
    pub fn encode(&self)->Result<Vec<u8>>{
        self.check()?; let mut e=Encoder::new(Vec::new());
        e.array(9).unwrap().bytes(SCHEMA).unwrap().u8(1).unwrap().u32(NETWORK_ID).unwrap()
            .bytes(&self.session).unwrap().bytes(&self.scope).unwrap().bytes(&self.signer).unwrap()
            .u64(self.round).unwrap().u8(self.step).unwrap().array(self.items.len() as u64).unwrap();
        for c in &self.items {e.array(6).unwrap().u32(c.admission).unwrap().u8(c.class).unwrap()
            .bytes(&c.identity).unwrap().bytes(&c.ak_name).unwrap().bytes(&c.credential).unwrap().bytes(&c.seed).unwrap();}
        let raw=e.into_writer(); if raw.len()>MAX_FRAME{return Err(Error::Bounds);} Ok(raw)
    }
    pub fn decode(raw:&[u8])->Result<Self>{
        if raw.len()>MAX_FRAME{return Err(Error::Bounds);} let mut d=Decoder::new(raw);array(&mut d,9)?;
        if d.bytes().map_err(|_|Error::Codec)?!=SCHEMA || d.u8().map_err(|_|Error::Codec)?!=1
            || d.u32().map_err(|_|Error::Codec)?!=NETWORK_ID{return Err(Error::Context);}
        let session=fixed(&mut d)?;let scope=fixed(&mut d)?;let signer=fixed(&mut d)?;
        let round=d.u64().map_err(|_|Error::Codec)?;let step=d.u8().map_err(|_|Error::Codec)?;
        let n=d.array().map_err(|_|Error::Codec)?.ok_or(Error::Codec)?;
        if n==0 || n>MAX_CHALLENGES as u64{return Err(Error::Bounds);}
        let mut items=Vec::with_capacity(n as usize);
        for _ in 0..n {array(&mut d,6)?;
            let admission=d.u32().map_err(|_|Error::Codec)?;let class=d.u8().map_err(|_|Error::Codec)?;
            let identity=fixed(&mut d)?;let ak_name=fixed(&mut d)?;
            let credential=d.bytes().map_err(|_|Error::Codec)?; if credential.is_empty()||credential.len()>4096{return Err(Error::Bounds);}
            let seed=d.bytes().map_err(|_|Error::Codec)?; if seed.is_empty()||seed.len()>4096{return Err(Error::Bounds);}
            items.push(EncryptedItem{admission,class,identity,ak_name,credential:credential.to_vec(),seed:seed.to_vec()});
        }
        let value=Self{session,scope,signer,round,step,items};
        if d.position()!=raw.len() || value.encode()?!=raw{return Err(Error::Codec);} Ok(value)
    }
}
/// Response bytes never implement Debug/Clone and are always erased on drop.
pub struct ResponseFrame {session:Hash,scope:Hash,signer:Hash,round:u64,step:u8,
    values:Vec<(u32,u8,Zeroizing<[u8;32]>)>}
struct PrivateBuffer(Zeroizing<Vec<u8>>);
impl minicbor::encode::Write for PrivateBuffer {
    type Error=std::convert::Infallible;
    fn write_all(&mut self,raw:&[u8])->std::result::Result<(),Self::Error>{
        self.0.extend_from_slice(raw); Ok(())
    }
}
impl ResponseFrame {
    pub fn new(expected:&ChallengeFrame,mut values:Vec<Zeroizing<[u8;32]>>)->Result<Self>{
        expected.check()?; if values.len()!=expected.items.len(){return Err(Error::Response);}
        let bound=Self::bind_values(expected,&mut values);
        Ok(Self{session:expected.session,scope:expected.scope,signer:expected.signer,round:expected.round,
            step:expected.step,values:bound})
    }
    fn bind_values(expected:&ChallengeFrame,values:&mut [Zeroizing<[u8;32]>])
        ->Vec<(u32,u8,Zeroizing<[u8;32]>)>{
        let mut bound=Vec::with_capacity(values.len());
        for (c,s) in expected.items.iter().zip(values.iter_mut()) {
            let owned=Zeroizing::new(**s);s.zeroize();
            bound.push((c.admission,c.class,owned));
        }bound
    }
    pub fn encode_private(&self)->Result<Zeroizing<Vec<u8>>>{
        // Capacity is reserved BEFORE copying private data, so growth cannot
        // leave earlier response bytes in an abandoned allocation.
        let mut e=Encoder::new(PrivateBuffer(Zeroizing::new(Vec::with_capacity(512))));
        e.array(9).map_err(|_|Error::Codec)?.bytes(SCHEMA).map_err(|_|Error::Codec)?.u8(2).map_err(|_|Error::Codec)?
            .u32(NETWORK_ID).map_err(|_|Error::Codec)?.bytes(&self.session).map_err(|_|Error::Codec)?
            .bytes(&self.scope).map_err(|_|Error::Codec)?.bytes(&self.signer).map_err(|_|Error::Codec)?
            .u64(self.round).map_err(|_|Error::Codec)?.u8(self.step).map_err(|_|Error::Codec)?
            .array(self.values.len() as u64).map_err(|_|Error::Codec)?;
        for (i,j,s) in &self.values {e.array(3).map_err(|_|Error::Codec)?.u32(*i).map_err(|_|Error::Codec)?
            .u8(*j).map_err(|_|Error::Codec)?.bytes(s.as_ref()).map_err(|_|Error::Codec)?;}
        Ok(e.into_writer().0)
    }
    pub fn decode_private(raw:Zeroizing<Vec<u8>>,expected:&ChallengeFrame)->Result<Self>{
        expected.check()?;
        if raw.len()>64+MAX_CHALLENGES*48+256{return Err(Error::Bounds);}
        let mut d=Decoder::new(&raw); array(&mut d,9)?;
        if d.bytes().map_err(|_|Error::Codec)?!=SCHEMA || d.u8().map_err(|_|Error::Codec)?!=2
            || d.u32().map_err(|_|Error::Codec)?!=NETWORK_ID{return Err(Error::Context);}
        let session=fixed(&mut d)?;let scope=fixed(&mut d)?;let signer=fixed(&mut d)?;
        let round=d.u64().map_err(|_|Error::Codec)?;let step=d.u8().map_err(|_|Error::Codec)?;
        if (session,scope,signer,round,step)!=(expected.session,expected.scope,expected.signer,expected.round,expected.step){return Err(Error::Context);}
        if d.array().map_err(|_|Error::Codec)?!=Some(expected.items.len() as u64){return Err(Error::Response);}
        let mut values=Vec::with_capacity(expected.items.len());
        for c in &expected.items {array(&mut d,3)?;
            let i=d.u32().map_err(|_|Error::Codec)?;let j=d.u8().map_err(|_|Error::Codec)?;
            if (i,j)!=(c.admission,c.class){return Err(Error::Response);}
            let s=d.bytes().map_err(|_|Error::Codec)?; if s.len()!=32{return Err(Error::Response);}
            let mut owned=Zeroizing::new([0;32]); owned.copy_from_slice(s);values.push((i,j,owned));
        }
        let value=Self{session,scope,signer,round,step,values};
        if d.position()!=raw.len() || value.encode_private()?.as_slice()!=raw.as_slice(){return Err(Error::Codec);} Ok(value)
    }
    pub fn into_responses(mut self)->Vec<RecoveryResponse>{self.take_responses()}
    fn take_responses(&mut self)->Vec<RecoveryResponse>{
        let mut responses=Vec::with_capacity(self.values.len());
        for (i,j,s) in &mut self.values {
            // A consuming Vec iterator does not drop/wipe its moved slots.
            // Keep every source slot alive and explicitly erase it instead.
            let owned=Zeroizing::new(**s);s.zeroize();
            responses.push(RecoveryResponse::new(*i,*j,owned));
        }responses
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    #[test]
    fn private_transfer_erases_retained_source_slots_before_heap_release(){
        let f=frame();let mut values=vec![Zeroizing::new([10;32]),Zeroizing::new([11;32])];
        let bound=ResponseFrame::bind_values(&f,&mut values);
        assert!(values.iter().all(|s|**s==[0;32]));
        let mut response=ResponseFrame{session:f.session,scope:f.scope,signer:f.signer,
            round:f.round,step:f.step,values:bound};
        let raw=response.encode_private().unwrap();
        let decoded=ResponseFrame::decode_private(raw,&f).unwrap();
        assert_eq!(*decoded.values[0].2,[10;32]);assert_eq!(*decoded.values[1].2,[11;32]);
        let returned=response.take_responses();assert_eq!(returned.len(),2);
        assert!(response.values.iter().all(|(_,_,s)|**s==[0;32]));
    }
    pub(crate) fn frame()->ChallengeFrame {
        let mut name=[5;34];name[..2].copy_from_slice(&[0,11]);
        ChallengeFrame{session:[1;32],scope:[2;32],signer:[3;32],round:7,step:2,
            items:(0..2).map(|class|EncryptedItem{admission:4,class,identity:[class+6;32],
                ak_name:name,credential:vec![8;64],seed:vec![9;256]}).collect()}
    }
    #[test]
    fn challenge_every_truncation_extension_order_and_bounds(){
        let f=frame();let raw=f.encode().unwrap();
        assert_eq!(ChallengeFrame::decode(&raw).unwrap().encode().unwrap(),raw);
        for end in 0..raw.len(){assert!(ChallengeFrame::decode(&raw[..end]).is_err());}
        let mut bad=raw;bad.push(0);assert!(ChallengeFrame::decode(&bad).is_err());
        let mut f=frame();f.items.swap(0,1);assert!(f.encode().is_err());
        f=frame();f.items[1].class=0;assert!(f.encode().is_err());
        f=frame();f.items[0].credential.resize(4097,0);assert!(f.encode().is_err());
        f=frame();f.items[0].ak_name[1]=12;assert!(f.encode().is_err());
    }
    #[test]
    fn private_response_exact_context_tuple_and_every_truncation(){
        let f=frame();let value=ResponseFrame::new(&f,vec![Zeroizing::new([10;32]),Zeroizing::new([11;32])]).unwrap();
        let raw=value.encode_private().unwrap();
        let decoded=ResponseFrame::decode_private(Zeroizing::new(raw.to_vec()),&f).unwrap();
        assert_eq!(decoded.encode_private().unwrap().as_slice(),raw.as_slice());
        for end in 0..raw.len(){assert!(ResponseFrame::decode_private(Zeroizing::new(raw[..end].to_vec()),&f).is_err());}
        let mut extra=Zeroizing::new(raw.to_vec());extra.push(0);
        assert!(ResponseFrame::decode_private(extra,&f).is_err());
        for which in 0..5 {let mut other=frame();match which {0=>other.session[0]^=1,1=>other.scope[0]^=1,
            2=>other.signer[0]^=1,3=>other.round+=1,_=>other.step=3};
            assert!(ResponseFrame::decode_private(Zeroizing::new(raw.to_vec()),&other).is_err());}
        assert!(ResponseFrame::new(&f,vec![Zeroizing::new([10;32])]).is_err());
    }
}
