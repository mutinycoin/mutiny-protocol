//! Internal exact-operation NV proof client, not an installed provider issuer.
//! The native issuer must own exclusive lifetime/lineage and persist uncertain
//! operation custody across restart. A generic endpoint cannot supply those.
use mutiny_consensus_v8::{Hash,counter_store::MonotonicCounter,
    tpm::{TpmProfile,nv_counter::{self,Observation}}};
use sha2::{Digest,Sha256};
use zeroize::{Zeroize,Zeroizing};
type Result<T>=std::result::Result<T,String>;
const MAX_RESPONSE:usize=6+80+256+128;

/// Public local implementation request. The attestation nonce commits to this
/// complete exact action/context/sequence/expected counter plus fresh entropy.
/// It is not a protocol proof and contains no authorization secret.
pub(crate) struct Request {context:Hash,sequence:u64,increment:bool,
    expected:Option<u64>,challenge:Hash}
// Local challenge/proof staging is cleared on success, refusal and unwind.
// Native pending frames/OVERLAPPED storage have separate retained custody;
// their memory is never erased while an original operation remains unknown.
impl Drop for Request {fn drop(&mut self){self.challenge.zeroize();}}
impl Request {
    pub(crate) fn context(&self)->Hash{self.context}
    pub(crate) fn sequence(&self)->u64{self.sequence}
    pub(crate) fn is_increment(&self)->bool{self.increment}
    pub(crate) fn expected(&self)->Option<u64>{self.expected}
    pub(crate) fn challenge(&self)->Hash{self.challenge}
    /// Fixed local implementation frame; not a protocol/public-proof format.
    pub(crate) fn encode_native(&self)->[u8;98]{
        let mut out=[0;98];out[..16].copy_from_slice(b"BUILD8-NV-REQ-V1");
        out[16..48].copy_from_slice(&self.context);out[48..56].copy_from_slice(&self.sequence.to_be_bytes());
        out[56]=u8::from(self.increment);out[57]=u8::from(self.expected.is_some());
        out[58..66].copy_from_slice(&self.expected.unwrap_or(0).to_be_bytes());
        out[66..].copy_from_slice(&self.challenge);out
    }
    /// Only an authenticated native provider receiver calls this after its own
    /// installed context/current/peer checks. Parsing is not an authority issuer.
    pub(crate) fn decode_native(raw:&[u8;98],installed_context:Hash)->Result<Self>{
        if &raw[..16]!=b"BUILD8-NV-REQ-V1" || installed_context==[0;32]
            || raw[16..48]!=installed_context || raw[56]>1 || raw[57]>1 {
            return Err("NV native request exact framing/context".into());
        }
        let sequence=u64::from_be_bytes(raw[48..56].try_into().map_err(|_|"NV sequence")?);
        let value=u64::from_be_bytes(raw[58..66].try_into().map_err(|_|"NV before")?);
        let expected=if raw[57]==1{Some(value)}else{if value!=0{return Err("NV absent before encoding".into());}None};
        let challenge:Hash=raw[66..].try_into().map_err(|_|"NV challenge")?;
        if sequence==0 || challenge==[0;32] || (raw[56]==1 && expected.is_none()) {
            return Err("NV native request missing identity/before".into());
        }
        Ok(Self{context:installed_context,sequence,increment:raw[56]==1,expected,challenge})
    }
}
#[cfg(test)]
mod native_codec_controls {
    use super::*;
    #[test]
    fn fixed_request_refuses_changed_context_absent_before_and_invalid_opcode_flags(){
        let request=Request{context:[1;32],sequence:1,increment:true,expected:Some(7),challenge:[2;32]};
        let frame=request.encode_native();let parsed=Request::decode_native(&frame,[1;32]).unwrap();
        assert_eq!(parsed.context(),[1;32]);assert_eq!(parsed.expected(),Some(7));assert!(parsed.is_increment());
        assert!(Request::decode_native(&frame,[3;32]).is_err());
        let mut missing=frame;missing[57]=0;assert!(Request::decode_native(&missing,[1;32]).is_err());
        let mut flags=frame;flags[56]=2;assert!(Request::decode_native(&flags,[1;32]).is_err());
        let mut zero=frame;zero[66..].fill(0);assert!(Request::decode_native(&zero,[1;32]).is_err());
    }
}
/// Already authenticated native endpoint, used exclusively on the owned private
/// worker. The caller supplies a fixed bounded response destination. No raw
/// reader, pass Boolean, arbitrary allocated response or qualification callback.
/// An error is an UNKNOWN outcome, including before an acknowledgment arrives.
pub(crate) trait NvExchange {
    fn exchange(&mut self,request:&Request,response:&mut [u8;MAX_RESPONSE])->Result<usize>;
}
pub(crate) struct ExactCounter<E:NvExchange> {endpoint:E,profile:TpmProfile,
    public_sha256:Hash,context:Hash,sequence:u64,last:Option<Observation>,frozen:bool}
pub(crate) struct ExistingExactCounterRefusal<E:NvExchange>{cause:String,endpoint:std::mem::ManuallyDrop<E>}
impl<E:NvExchange> ExistingExactCounterRefusal<E>{
    pub(crate) fn cause(&self)->&str{&self.cause}
    pub(crate) fn into_retained(self)->(String,std::mem::ManuallyDrop<E>){(self.cause,self.endpoint)}
}
impl<E:NvExchange> ExactCounter<E> {
    /// Native factory entry; original authenticated endpoint stays owned on
    /// profile/current input failure and unwind, rather than generic RAII Drop.
    pub(crate) fn from_retained_endpoint(endpoint:std::mem::ManuallyDrop<E>,profile:TpmProfile,
        public_sha256:Hash,context:Hash)->std::result::Result<Self,ExistingExactCounterRefusal<E>>{
        let checked=(||->Result<()>{
            if public_sha256==[0;32]||context==[0;32]{return Err("NV exact selection missing".into());}
            profile.verify_certified_key().map_err(|_|"NV selected AK invalid")?;Ok(())
        })();
        match checked{Ok(())=>Ok(Self{endpoint:std::mem::ManuallyDrop::into_inner(endpoint),
            profile,public_sha256,context,sequence:0,last:None,frozen:false}),
            Err(cause)=>Err(ExistingExactCounterRefusal{cause,endpoint})}
    }
    /// Private stopped-worker transfer. Unknown/unwind outcome remains whole;
    /// no numeric fd retry, counter read/increment or new endpoint is created.
    pub(crate) fn into_existing_endpoint(self)
        ->std::result::Result<std::mem::ManuallyDrop<E>,std::mem::ManuallyDrop<Self>>{
        if self.frozen{return Err(std::mem::ManuallyDrop::new(self));}
        let Self{endpoint,..}=self;Ok(std::mem::ManuallyDrop::new(endpoint))
    }
    /// Internal composition only. Selection must come from the factory's own
    /// held current profile/NV-public/provider artifacts. Authentication of AK
    /// bytes does not establish physical lineage, deletion policy or exclusivity.
    pub(crate) fn from_existing_endpoint(endpoint:E,profile:TpmProfile,
        public_sha256:Hash,context:Hash)->Result<Self>{
        if public_sha256==[0;32]||context==[0;32]{return Err("NV exact selection missing".into());}
        profile.verify_certified_key().map_err(|_|"NV selected AK invalid")?;
        Ok(Self{endpoint,profile,public_sha256,context,sequence:0,last:None,frozen:false})
    }
    fn operation(&mut self,increment:bool)->Result<Observation>{
        if self.frozen{return Err("NV exact owner frozen".into());}
        let result=(||{
            let sequence=self.sequence.checked_add(1).ok_or("NV request sequence overflow")?;
            let expected=self.last.map(|o|o.counter);
            if increment&&expected.is_none(){return Err("NV increment lacks authenticated before value".into());}
            let intended=if increment{Some(expected.ok_or("NV before value absent")?
                .checked_add(1).ok_or("NV counter overflow")?)}else{expected};
            let mut entropy=Zeroizing::new([0u8;32]);getrandom::getrandom(&mut *entropy)
                .map_err(|_|"NV challenge entropy unavailable")?;
            if *entropy==[0;32]{return Err("NV challenge entropy invalid".into());}
            let mut hash=Sha256::new();hash.update(b"BUILD8-EXACT-NV-OPERATION-V1\0");
            hash.update(self.context);hash.update(sequence.to_be_bytes());hash.update([u8::from(increment)]);
            hash.update([u8::from(expected.is_some())]);hash.update(expected.unwrap_or(0).to_be_bytes());
            hash.update(self.public_sha256);hash.update(&*entropy);
            let request=Request{context:self.context,sequence,increment,expected,challenge:hash.finalize().into()};
            // Reserve local identity BEFORE any external action. No automatic
            // identical or conflicting retransmission follows an unknown result.
            self.sequence=sequence;
            // Arm the freeze BEFORE the external action. A native endpoint can
            // unwind after irreversible mutation; catching that unwind above
            // this owner must never leave a usable stale before-counter.
            self.frozen=true;
            let mut response=Zeroizing::new([0u8;MAX_RESPONSE]);
            let used=self.endpoint.exchange(&request,&mut *response)?;
            if !(6..=MAX_RESPONSE).contains(&used){return Err("NV response bounds".into());}
            let lengths=[u16::from_be_bytes([response[0],response[1]]) as usize,
                u16::from_be_bytes([response[2],response[3]]) as usize,
                u16::from_be_bytes([response[4],response[5]]) as usize];
            if lengths[0]>80||lengths[1]>256||lengths[2]>128
                || lengths.iter().try_fold(6usize,|a,b|a.checked_add(*b))!=Some(used){
                return Err("NV response exact framing".into());
            }
            let p=6+lengths[0];let m=p+lengths[1];
            let observation=nv_counter::verify(&self.profile,self.public_sha256,&response[6..p],
                request.challenge,&response[p..m],&response[m..used]).map_err(|_|"NV exact proof refusal")?;
            // CounterStore's existing contract requires NON-orderly counters.
            // The general public verifier authenticates numbers only; this
            // client separately enforces the existing custody constraint.
            if observation.attributes&0x04000000!=0||observation.attributes&0x20000000==0 {
                return Err("NV orderly or unwritten counter refused for custody".into());
            }
            if let Some(before)=self.last {
                if observation.index!=before.index||observation.attributes!=before.attributes
                    || observation.reset_count!=before.reset_count||observation.restart_count!=before.restart_count
                    || observation.firmware_version!=before.firmware_version
                    || observation.clock<before.clock{
                    return Err("NV selected lineage changed".into());
                }
                let value=intended.ok_or("NV intended value absent")?;
                if observation.counter!=value{return Err("NV conflicting or stale exact operation".into());}
            }
            Ok(observation)
        })();
        match result {Ok(observation)=>{self.last=Some(observation);self.frozen=false;Ok(observation)},
            Err(error)=>{self.frozen=true;Err(error)}}
    }
}
impl<E:NvExchange> MonotonicCounter for ExactCounter<E> {
    fn read(&mut self)->Result<u64>{Ok(self.operation(false)?.counter)}
    fn increment(&mut self)->Result<()>{
        if self.last.is_none(){self.operation(false)?;}
        self.operation(true)?;Ok(())
    }
}

#[cfg(test)]
mod modeled_controls {
    use super::*;
    struct Unknown {calls:usize}
    impl NvExchange for Unknown {
        fn exchange(&mut self,request:&Request,_:&mut [u8;MAX_RESPONSE])->Result<usize>{
            self.calls+=1;
            assert_eq!(request.sequence(),1);assert_eq!(request.context(),[7;32]);
            assert_eq!(request.expected(),Some(45));assert!(!request.is_increment());
            assert_ne!(request.challenge(),[0;32]);
            Err("MODELED lost acknowledgment; outcome unknown".into())
        }
    }
    fn rig_with<E:NvExchange>(endpoint:E,value:u64)->ExactCounter<E>{
        // A deliberately INVALID public profile is sufficient for these two
        // pre-proof/unknown-outcome tests. This private TEST constructor is not
        // the normal constructor and creates no authenticated observation.
        let profile=TpmProfile{hardware:[0;32],ak_public:vec![],voting_public:vec![],
            qualified_signer:vec![],pcr_bitmap:[0;3],pcr_digest:[0;32],
            certify_message:vec![],certify_signature:vec![],admission_trust_manifest:[0;32],provenance:None};
        let last=Observation{counter:value,index:0x01500020,attributes:0x20060010,
            clock:1,reset_count:0,restart_count:0,safe:true,firmware_version:1};
        ExactCounter{endpoint,profile,public_sha256:[8;32],
            context:[7;32],sequence:0,last:Some(last),frozen:false}
    }
    fn rig(value:u64)->ExactCounter<Unknown>{rig_with(Unknown{calls:0},value)}
    #[test]
    fn modeled_unknown_outcome_freezes_read_and_increment_without_retry(){
        let mut counter=rig(45);
        assert!(counter.read().is_err());assert_eq!(counter.endpoint.calls,1);
        assert!(counter.read().is_err());assert!(counter.increment().is_err());
        assert_eq!(counter.endpoint.calls,1);assert!(counter.frozen);
        assert_eq!(counter.sequence,1);assert_eq!(counter.last.unwrap().counter,45);
    }
    #[test]
    fn modeled_counter_overflow_refuses_before_external_action(){
        let mut counter=rig(u64::MAX);
        assert!(counter.increment().is_err());assert_eq!(counter.endpoint.calls,0);
        assert_eq!(counter.sequence,0);assert!(counter.frozen);
    }
    #[test]
    fn modeled_caught_endpoint_unwind_cannot_repeat_increment(){
        struct PanicAfterMutation{increments:usize}
        impl NvExchange for PanicAfterMutation{
            fn exchange(&mut self,request:&Request,_:&mut [u8;MAX_RESPONSE])->Result<usize>{
                assert!(request.is_increment());assert_eq!(request.expected(),Some(45));
                self.increments+=1;panic!("MODELED mutation succeeded then endpoint unwound");
            }
        }
        let mut counter=rig_with(PanicAfterMutation{increments:0},45);
        let caught=std::panic::catch_unwind(std::panic::AssertUnwindSafe(||counter.increment()));
        assert!(caught.is_err());assert!(counter.frozen);assert_eq!(counter.sequence,1);
        assert_eq!(counter.last.unwrap().counter,45);assert_eq!(counter.endpoint.increments,1);
        assert!(counter.increment().is_err());assert!(counter.read().is_err());
        assert_eq!(counter.endpoint.increments,1);
    }
}
