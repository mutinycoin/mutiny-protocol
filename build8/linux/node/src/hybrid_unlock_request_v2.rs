//! Public fixed local unlock request. Parsing binds selected ciphertexts and
//! fresh request identity; it cannot issue a principal or custody capability.
use mutiny_consensus_v8::Hash;
use sha2::{Digest,Sha256};
use crate::hybrid_owned_unlock_input_v2::UnlockBinding;
type Result<T>=std::result::Result<T,String>;
const MAGIC:&[u8;16]=b"B8-UNLOCK-REQ-V1";
pub(super) struct UnlockRequest {context:Hash,node_ciphertext:Hash,continuity_ciphertext:Hash,nonce:Hash}
impl UnlockRequest {
    pub(super) fn new(context:Hash,node_ciphertext:Hash,continuity_ciphertext:Hash)->Result<Self>{
        if [context,node_ciphertext,continuity_ciphertext].contains(&[0;32]){
            return Err("unlock selected context/ciphertext commitment missing".into());}
        let mut nonce=[0;32];getrandom::getrandom(&mut nonce).map_err(|_|"unlock challenge entropy unavailable")?;
        if nonce==[0;32]{return Err("unlock challenge entropy invalid".into());}
        Ok(Self{context,node_ciphertext,continuity_ciphertext,nonce})
    }
    pub(super) fn encode(&self)->[u8;144]{let mut frame=[0;144];frame[..16].copy_from_slice(MAGIC);
        for(at,value)in [self.context,self.node_ciphertext,self.continuity_ciphertext,self.nonce].iter().enumerate(){
            frame[16+at*32..48+at*32].copy_from_slice(value);}frame}
    pub(super) fn decode(frame:&[u8;144],context:Hash,node_ciphertext:Hash,continuity_ciphertext:Hash)->Result<Self>{
        if &frame[..16]!=MAGIC||[context,node_ciphertext,continuity_ciphertext].contains(&[0;32])
            || frame[16..48]!=context||frame[48..80]!=node_ciphertext||frame[80..112]!=continuity_ciphertext {
            return Err("unlock request differs from own selected role/ciphertexts".into());}
        let nonce:Hash=frame[112..144].try_into().map_err(|_|"unlock nonce length")?;
        if nonce==[0;32]{return Err("unlock zero request identity".into());}
        Ok(Self{context,node_ciphertext,continuity_ciphertext,nonce})
    }
    pub(super) fn binding(&self)->UnlockBinding {let mut hash=Sha256::new();
        hash.update(b"BUILD8-OWNED-ROLE-UNLOCK-REQUEST-V1\0");hash.update(self.encode());
        UnlockBinding(hash.finalize().into())}
    pub(super) fn acknowledgment(&self)->[u8;48]{let mut frame=[0;48];
        frame[..16].copy_from_slice(b"B8-UNLOCK-ACK-V1");frame[16..].copy_from_slice(&self.binding().0);frame}
}
#[cfg(test)]
mod modeled_controls {
    use super::*;
    #[test]
    fn request_binds_both_role_ciphertexts_context_and_fresh_identity(){
        let request=UnlockRequest{context:[1;32],node_ciphertext:[2;32],continuity_ciphertext:[3;32],nonce:[4;32]};
        let frame=request.encode();let parsed=UnlockRequest::decode(&frame,[1;32],[2;32],[3;32]).unwrap();
        assert_eq!(parsed.binding().0,request.binding().0);
        assert!(UnlockRequest::decode(&frame,[1;32],[2;32],[5;32]).is_err());
        assert!(UnlockRequest::decode(&frame,[6;32],[2;32],[3;32]).is_err());
        let mut zero=frame;zero[112..].fill(0);assert!(UnlockRequest::decode(&zero,[1;32],[2;32],[3;32]).is_err());
        let changed=UnlockRequest{nonce:[5;32],..request};assert_ne!(changed.binding().0,parsed.binding().0);
    }
}
