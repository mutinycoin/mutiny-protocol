//! Explicitly provisional SAME-BYTES firmware qualification receipt, no protocol
//! allocation. This module does not grant canonical authority or settlement.
//! The caller must independently establish durable, historically valid licensed
//! PoW. Only a fixed positive-observation intent can be constructed here.
use crate::{Domain, Error, HybridKey, HybridSignature, PublicKey, Result, NETWORK};
use sha2::{Digest, Sha256, Sha512};
pub const RESULT_BYTES:usize=590;
pub const BODY_BYTES:usize=317;
pub const RECEIPT_BYTES:usize=1711;
const RESULT_DOMAIN:&[u8]=b"MUTINY-BUILD8-QUAL-RESULT-ADAPTER-V1\0";
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Intent { body:[u8;BODY_BYTES] }
fn hash256(domain:&[u8],raw:&[u8])->[u8;32]{let mut h=Sha256::new();h.update(domain);h.update(raw);h.finalize().into()}
fn u64_at(raw:&[u8],at:usize)->u64{u64::from_be_bytes(raw[at..at+8].try_into().unwrap())}
impl Intent {
    /// Shape/signature validation is necessary but insufficient authority. No
    /// arbitrary body constructor exists, and Domain signing checks exact body.
    pub fn accepted(result:&[u8],worker:&[u8;57])->Result<Self>{
        if result.len()!=RESULT_BYTES || &result[..8]!=b"B8QRSLT1"
            || result[8..12]!=NETWORK.to_be_bytes(){return Err(Error::Encoding);}
        let seq=u64_at(result,428);let prior=u64_at(result,436);let total=prior.checked_add(1).ok_or(Error::Encoding)?;
        if seq==0 || prior>=seq || ((seq==1)!=(result[444..476]==[0;32]))
            || u64_at(result,388)<u64_at(result,332) || u64_at(result,388)>u64_at(result,340)
            || result[356..388]==[0;32]{return Err(Error::Encoding);}
        let mut h=Sha512::new();h.update(RESULT_DOMAIN);h.update(&result[..476]);let message:[u8;64]=h.finalize().into();
        if unsafe{crate::build8_qual_ed448_verify(worker.as_ptr(),57,result[476..].as_ptr(),114,message.as_ptr(),64)}!=1{return Err(Error::Signature);}
        let id=hash256(b"MUTINY-BUILD8-QUAL-RESULT-ID-V1\0",result);
        let mut preimage=[0;81];preimage[..8].copy_from_slice(&seq.to_be_bytes());preimage[8..40].copy_from_slice(&result[444..476]);
        preimage[40..72].copy_from_slice(&id);preimage[72]=1;preimage[73..].copy_from_slice(&total.to_be_bytes());
        let chain=hash256(b"MUTINY-BUILD8-QUAL-ACCOUNT-CHAIN-V1\0",&preimage);
        let mut body=[0;BODY_BYTES];body[..8].copy_from_slice(b"B8QRCPT1");body[8..76].copy_from_slice(&result[8..76]);
        body[76..140].copy_from_slice(&result[188..252]);body[140..172].copy_from_slice(&result[268..300]);
        body[172..204].copy_from_slice(&result[356..388]);body[204..236].copy_from_slice(&id);
        body[236..244].copy_from_slice(&seq.to_be_bytes());body[244]=1;body[245..253].copy_from_slice(&total.to_be_bytes());
        body[253..285].copy_from_slice(&result[444..476]);body[285..].copy_from_slice(&chain);
        Ok(Self{body})
    }
    pub fn body(&self)->&[u8;BODY_BYTES]{&self.body}
    pub fn sequence(&self)->u64{u64_at(&self.body,236)}
    pub fn total(&self)->u64{u64_at(&self.body,245)}
    pub fn chain(&self)->[u8;32]{self.body[285..].try_into().unwrap()}
}
pub fn sign(key:&HybridKey,intent:&Intent)->Result<Vec<u8>>{
    let signature=key.sign(Domain::QualificationReceipt(*intent),intent.body())?;
    let mut raw=intent.body().to_vec();raw.extend(signature.ed448);raw.extend(signature.fndsa);
    verify(key.public(),intent,&raw)?;Ok(raw)
}
pub fn verify(public:&PublicKey,intent:&Intent,raw:&[u8])->Result<()> {
    if raw.len()!=RECEIPT_BYTES || &raw[..BODY_BYTES]!=intent.body(){return Err(Error::Encoding);}
    let signature=HybridSignature{ed448:raw[BODY_BYTES..BODY_BYTES+114].try_into().unwrap(),fndsa:raw[BODY_BYTES+114..].try_into().unwrap()};
    public.verify(Domain::QualificationReceipt(*intent),intent.body(),&signature)
}
