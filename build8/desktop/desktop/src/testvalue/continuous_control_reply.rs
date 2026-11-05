// EXTERNAL SOURCE-ONLY. Local TEST observations only: no Confirmed/Applied or authority proof.
use super::control_codec::{Error, Hash, Head, HEADER_BYTES as REQUEST_HEADER_BYTES};
pub const MAGIC: [u8;16] = *b"MW15LOCALREPLY1\0";
pub const HEADER_BYTES: usize = 168;
pub const MAX_REPLY_BYTES: usize = 1024;
type Result<T> = std::result::Result<T,Error>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Code { Observed=1, ExactDurableAdmission=2, ActualHistoryAdvertised=3, Refused=4 }
impl Code {
    fn decode(x:u8)->Result<Self> {
        match x {1=>Ok(Self::Observed),2=>Ok(Self::ExactDurableAdmission),3=>Ok(Self::ActualHistoryAdvertised),4=>Ok(Self::Refused),_=>Err(Error::Tag)}
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    None=0, NativeAdmission=1, ExactQueue=2, ParentChanged=3, Budget=4, Deadline=5,
    NativeAssembly=6, NativeCommit=7, HistoryInstall=8, Unsupported=9,
}
impl Refusal {
    fn decode(x:u8)->Result<Self> {
        match x {0=>Ok(Self::None),1=>Ok(Self::NativeAdmission),2=>Ok(Self::ExactQueue),3=>Ok(Self::ParentChanged),4=>Ok(Self::Budget),5=>Ok(Self::Deadline),6=>Ok(Self::NativeAssembly),7=>Ok(Self::NativeCommit),8=>Ok(Self::HistoryInstall),9=>Ok(Self::Unsupported),_=>Err(Error::Payload)}
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reply {
    pub code:Code, pub refusal:Refusal, pub sequence:u64, pub campaign:Hash,
    pub exact_request_sha256:Hash, pub observed_head:Head,
}
pub fn decode(bytes:&[u8])->Result<Reply> {
    // Version1 response has no payload, strings, receipt or alternate encoding.
    if bytes.len()!=HEADER_BYTES {return Err(Error::Bounds);}
    if bytes[..16]!=MAGIC {return Err(Error::Magic);}
    if bytes[16..18]!=1u16.to_be_bytes() {return Err(Error::Version);}
    let code=Code::decode(bytes[18])?; let refusal=Refusal::decode(bytes[19])?;
    if (code==Code::Refused)==(refusal==Refusal::None) {return Err(Error::Payload);}
    let sequence=u64::from_be_bytes(bytes[20..28].try_into().unwrap());
    if sequence==0 {return Err(Error::Sequence);}
    let campaign:Hash=bytes[28..60].try_into().unwrap();
    let exact_request_sha256:Hash=bytes[60..92].try_into().unwrap();
    if campaign==[0;32] || exact_request_sha256==[0;32] {return Err(Error::Context);}
    if bytes[164..168]!=[0;4] {return Err(Error::Payload);}
    Ok(Reply{code,refusal,sequence,campaign,exact_request_sha256,
        observed_head:Head{height:u64::from_be_bytes(bytes[92..100].try_into().unwrap()),block:bytes[100..132].try_into().unwrap(),root:bytes[132..164].try_into().unwrap()}})
}
pub fn encode(r:Reply)->Result<[u8;HEADER_BYTES]> {
    let mut b=[0;HEADER_BYTES];b[..16].copy_from_slice(&MAGIC);b[16..18].copy_from_slice(&1u16.to_be_bytes());
    b[18]=r.code as u8;b[19]=r.refusal as u8;b[20..28].copy_from_slice(&r.sequence.to_be_bytes());
    b[28..60].copy_from_slice(&r.campaign);b[60..92].copy_from_slice(&r.exact_request_sha256);
    b[92..100].copy_from_slice(&r.observed_head.height.to_be_bytes());b[100..132].copy_from_slice(&r.observed_head.block);b[132..164].copy_from_slice(&r.observed_head.root);
    if decode(&b)?!=r {return Err(Error::Payload);} Ok(b)
}
// Echo binding prevents mixing concurrent/stale responses. It supplies NO finality.
pub fn match_request(r:Reply,sequence:u64,campaign:Hash,raw_request:&[u8])->Result<()> {
    use sha2::{Digest,Sha256};
    if raw_request.len()<REQUEST_HEADER_BYTES || raw_request.len()>1024 {return Err(Error::Bounds);}
    if r.sequence!=sequence {return Err(Error::Sequence);}
    if r.campaign!=campaign {return Err(Error::Context);}
    if r.exact_request_sha256!=Hash::from(Sha256::digest(raw_request)) {return Err(Error::Context);}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reply()->Reply {Reply{code:Code::Observed,refusal:Refusal::None,sequence:1,campaign:[1;32],exact_request_sha256:[2;32],observed_head:Head{height:0,block:[3;32],root:[4;32]}}}
    #[test] fn every_reply_code_and_refusal_roundtrip_and_strict_bounds() {
        for code in [Code::Observed,Code::ExactDurableAdmission,Code::ActualHistoryAdvertised,Code::Refused] {
            let mut r=reply();r.code=code;
            if code==Code::Refused {r.refusal=Refusal::NativeCommit;}
            let b=encode(r).unwrap();assert_eq!(decode(&b).unwrap(),r);
            for n in 0..HEADER_BYTES {assert!(decode(&b[..n]).is_err());}
            let mut extra=b.to_vec();extra.push(0);assert!(decode(&extra).is_err());
        }
    }
    #[test] fn no_receipt_payload_or_reserved_code_or_inconsistent_refusal() {
        let b=encode(reply()).unwrap();
        for (offset,value) in [(18,0),(18,5),(19,1),(19,10),(164,1),(167,1)] {let mut x=b;x[offset]=value;assert!(decode(&x).is_err());}
        let mut bad=reply();bad.code=Code::Refused;assert!(encode(bad).is_err());
    }
    #[test] fn exact_echo_hash_sequence_campaign_binding() {
        use sha2::{Digest,Sha256};
        let raw=[5;264];let mut r=reply();r.exact_request_sha256=Sha256::digest(raw).into();
        match_request(r,1,[1;32],&raw).unwrap();
        for n in 0..raw.len() {let mut wrong=raw;wrong[n]^=1;assert!(match_request(r,1,[1;32],&wrong).is_err());}
        assert!(match_request(r,2,[1;32],&raw).is_err());assert!(match_request(r,1,[2;32],&raw).is_err());
    }
}
