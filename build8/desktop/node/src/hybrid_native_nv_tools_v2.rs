//! Actual existing-index Linux TPM command producer. No provisioning, reset,
//! simulator bootstrap, authority issuer or automatic unknown-outcome retry.
//! The installed factory must supply its own qualified profile, exact held
//! device/tool/NV selection and authenticated owned authorization input.
use crate::{hybrid_authenticated_counter_v2::{NvExchange,Request},
    activation_private_owner_v1::linux_tools::{ToolPin,ToolClose,Memory,MemoryFailure,InvokeFailure,invoke_owned}};
use crate::host_clock::{retained_identity,RetainedCloseReport};
use mutiny_consensus_v8::{Hash,tpm::{TpmProfile,nv_counter::{self,Observation}}};
use sha2::{Digest,Sha256};
use std::{fs::File,os::unix::fs::{FileTypeExt,MetadataExt}};
use zeroize::Zeroizing;
type Result<T>=std::result::Result<T,String>;
const MAX_RESPONSE:usize=6+80+256+128;

/// Already owned native device and administrator-selected device identity.
/// Character-device identity is not proof of physical TPM lineage or locality.
pub(crate) struct DeviceState{file:std::mem::ManuallyDrop<File>,device:u64,inode:u64,rdev:u64,original:[u8;24]}
pub(crate) struct HeldDevice {state:std::mem::ManuallyDrop<Box<DeviceState>>}
impl std::ops::Deref for HeldDevice{type Target=DeviceState;fn deref(&self)->&DeviceState{&self.state}}
impl HeldDevice {
    pub(crate) fn from_existing(file:File,expected_rdev:u64)->Result<Self>{
        // Root the ORIGINAL incoming native File before allocation, metadata,
        // security or identity queries. Any early refusal/unwind preserves the
        // exact unpublished holder; no implicit File Drop or guessed FD close.
        let file=std::mem::ManuallyDrop::new(file);
        let mut owner=Self{state:std::mem::ManuallyDrop::new(Box::new(DeviceState{
            file,device:0,inode:0,rdev:0,original:[0;24]}))};
        let m=owner.file.metadata().map_err(|_|"NV device metadata unavailable")?;
        if !m.file_type().is_char_device() || m.uid()!=0 || m.rdev()!=expected_rdev
            || m.nlink()!=1 || m.mode()&0o002!=0 {
            return Err("NV selected device type/identity/owner refused".into());
        }
        let original=retained_identity(&owner.file).map_err(|_|"NV original device identity unavailable")?;
        let s=&mut **owner.state;s.device=m.dev();s.inode=m.ino();s.rdev=m.rdev();s.original=original;
        Ok(owner)
    }
    fn recheck(&self)->Result<()> {
        let m=self.file.metadata().map_err(|_|"NV device current metadata unavailable")?;
        if !m.file_type().is_char_device() || m.uid()!=0 || m.nlink()!=1 || m.mode()&0o002!=0
            || (m.dev(),m.ino(),m.rdev())!=(self.device,self.inode,self.rdev) {
            return Err("NV selected original device changed".into());
        }Ok(())
    }
}
/// Values are copied into zeroizing destinations before any command. The native
/// factory must obtain them through its separately authenticated secret channel;
/// this internal constructor cannot authenticate a caller or mint qualification.
pub(crate) struct OwnedNvAuth {ak:Zeroizing<Vec<u8>>,nv:Zeroizing<Vec<u8>>}
impl OwnedNvAuth {
    pub(crate) fn from_owned(ak:Zeroizing<Vec<u8>>,nv:Zeroizing<Vec<u8>>)->Result<Self>{
        // TPM2B_AUTH upper bound in the selected SHA-256/SHA-384 profiles.
        if ak.len()>64 || nv.len()>64{return Err("NV authorization bound".into());}
        Ok(Self{ak,nv})
    }
}
pub(crate) struct NativeNvTools {
    tool:ToolPin,device:HeldDevice,auth:OwnedNvAuth,profile:TpmProfile,
    public:Vec<u8>,public_sha256:Hash,context:Hash,index:u32,ak:u32,
    sequence:u64,last:Option<Observation>,frozen:bool,memory_failures:Vec<MemoryFailure>,
    invocation_failures:Vec<InvokeFailure>,device_close:Option<RetainedCloseReport>,
}
pub(crate) enum NativeProducerClose {
    Retained(std::mem::ManuallyDrop<NativeNvTools>),
    Unknown{device:RetainedCloseReport,tool:Option<ToolClose>},
}
impl NativeNvTools {
    pub(crate) fn selected_bindings(&self)->Result<(Hash,Hash,Hash)>{
        Ok((self.context,self.profile.commitment().map_err(|_|"NV selected profile commitment")?,self.public_sha256))
    }
    /// Called only after the original owning worker has settled known commands.
    /// Unknown mutation retains the entire producer and owned authorizations.
    pub(crate) fn close_retained(mut self)->std::result::Result<(),NativeProducerClose> {
        if self.frozen||!self.memory_failures.is_empty()||!self.invocation_failures.is_empty()
            ||self.device.recheck().is_err()||self.tool.recheck_installed().is_err() {
            return Err(NativeProducerClose::Retained(std::mem::ManuallyDrop::new(self)));
        }
        let mut device=self.device_close.take().expect("preallocated original device close");
        let original=*std::mem::ManuallyDrop::into_inner(self.device.state);
        device.file(std::mem::ManuallyDrop::into_inner(original.file),original.original);
        let tool=self.tool.close_retained().err();drop(self.auth);
        if !device.retained_handles_closed()||tool.is_some() {
            // Both independent closes were attempted; their outcome remains
            // UNKNOWN. No reused numeric handle is retried or reopened.
            return Err(NativeProducerClose::Unknown{device,tool});
        }
        Ok(())
    }
    /// Existing objects only. Generic inputs confer no admission or physical
    /// qualification. The protected normal issuer and own canonical authority
    /// must be verified before this producer can enter the signing factory.
    pub(crate) fn from_existing(tool:ToolPin,device:HeldDevice,auth:OwnedNvAuth,
        profile:TpmProfile,public:&[u8],public_sha256:Hash,context:Hash,ak:u32)->Result<Self>{
        if !(6..=80).contains(&public.len()) || public_sha256==[0;32] || context==[0;32]
            || <Hash>::from(Sha256::digest(public))!=public_sha256
            || !(0x81000000..=0x81ffffff).contains(&ak) {
            return Err("NV exact public/context/AK selection refused".into());
        }
        let index=u32::from_be_bytes(public[2..6].try_into().map_err(|_|"NV index framing")?);
        if !(0x01000000..=0x01ffffff).contains(&index) {
            return Err("NV existing index range refused".into());
        }
        profile.verify_certified_key().map_err(|_|"NV selected AK certification refused")?;
        tool.recheck_installed().map_err(|_|"NV selected installed tool unavailable")?;device.recheck()?;
        // At most two four-object certifications plus one increment auth exist
        // in an exchange. Failure permanently freezes this producer, so this
        // exact capacity is never reused for another operation or grown later.
        let mut memory_failures=Vec::new();memory_failures.try_reserve_exact(9)
            .map_err(|_|"NV original memory-failure custody allocation refused")?;
        let mut invocation_failures=Vec::new();invocation_failures.try_reserve_exact(3)
            .map_err(|_|"NV original invocation-failure custody allocation refused")?;
        let device_close=RetainedCloseReport::prepare(1).map_err(|_|"NV original device-close custody allocation refused")?;
        Ok(Self{tool,device,auth,profile,public:public.to_vec(),public_sha256,context,index,ak,
            sequence:0,last:None,frozen:false,memory_failures,invocation_failures,device_close:Some(device_close)})
    }
    fn certify(&mut self,challenge:Hash)->Result<(Observation,Zeroizing<Vec<u8>>,Zeroizing<Vec<u8>>)>{
        self.device.recheck()?;self.tool.recheck_installed().map_err(|_|"NV selected tool current")?;
        let mut owned=Vec::with_capacity(4);
        for bytes in [&self.auth.ak[..],&self.auth.nv[..],&[][..],&[][..]] {
            match Memory::new(bytes) {
                Ok(file)=>owned.push(file),
                Err(error)=>{self.memory_failures.push(error);
                    for file in owned {if let Err(error)=file.finish(){self.memory_failures.push(error);}}
                    return Err("NV owned input preparation refused".into());}
            }
        }
        let result=(||{
            let args=vec!["-Q".into(),"-T".into(),"device:/proc/self/fd/7".into(),
                "-C".into(),format!("0x{:08x}",self.ak),"-P".into(),"file:/proc/self/fd/3".into(),
                "-c".into(),format!("0x{:08x}",self.index),"-p".into(),"file:/proc/self/fd/4".into(),
                "-g".into(),"sha256".into(),"-s".into(),"ecdsa".into(),"-f".into(),"tss".into(),
                "-o".into(),"/proc/self/fd/6".into(),"--attestation".into(),"/proc/self/fd/5".into(),
                "--size".into(),"8".into(),"--offset".into(),"0".into(),"-q".into(),hex::encode(challenge),
                format!("0x{:08x}",self.index)];
            if let Err(error)=invoke_owned(&self.tool,"nvcertify",&args,
                &[owned[0].file(),owned[1].file(),owned[2].file(),owned[3].file(),&self.device.file],None) {
                self.invocation_failures.push(error);return Err("NV certified-read outcome unavailable".into());
            }
            let message=owned[2].bounded(256).map_err(|_|"NV attestation bound")?;
            let signature=owned[3].bounded(128).map_err(|_|"NV signature bound")?;
            let value=nv_counter::verify(&self.profile,self.public_sha256,&self.public,
                challenge,&message,&signature).map_err(|_|"NV native certified-read refused")?;
            if value.index!=self.index || value.attributes&0x04000000!=0 || value.attributes&0x20000000==0 {
                return Err("NV native non-orderly written index required".into());
            }
            self.device.recheck()?;Ok((value,message,signature))
        })();
        let mut errors=false;
        for file in owned {if let Err(error)=file.finish(){self.memory_failures.push(error);errors=true;}}
        if errors{return Err("NV independent owned input/output closure unknown".into());}result
    }
    fn increment(&mut self)->Result<()> {
        self.device.recheck()?;
        let auth=match Memory::new(&self.auth.nv){Ok(auth)=>auth,Err(error)=>{
            self.memory_failures.push(error);return Err("NV owned increment auth unavailable".into());
        }};
        let args=vec!["-Q".into(),"-T".into(),"device:/proc/self/fd/4".into(),"-C".into(),
            format!("0x{:08x}",self.index),"-P".into(),"file:/proc/self/fd/3".into(),format!("0x{:08x}",self.index)];
        let result=match invoke_owned(&self.tool,"nvincrement",&args,&[auth.file(),&self.device.file],None) {
            Ok(())=>Ok(()),Err(error)=>{self.invocation_failures.push(error);Err("NV native increment outcome UNKNOWN".to_owned())}
        };
        if let Err(error)=auth.finish(){self.memory_failures.push(error);
            return Err("NV increment auth closure unknown".into());}
        result?;self.device.recheck()
    }
    fn same_lineage(before:Observation,after:Observation)->bool {
        before.index==after.index && before.attributes==after.attributes
            && before.reset_count==after.reset_count && before.restart_count==after.restart_count
            && before.firmware_version==after.firmware_version && after.clock>=before.clock
    }
}
impl NvExchange for NativeNvTools {
    fn exchange(&mut self,request:&Request,response:&mut [u8;MAX_RESPONSE])->Result<usize>{
        if self.frozen{return Err("NV native producer frozen".into());}
        if request.context()!=self.context || request.challenge()==[0;32]
            || request.sequence()!=self.sequence.checked_add(1).ok_or("NV native sequence overflow")?
            || request.expected()!=self.last.map(|v|v.counter)
            || (request.is_increment() && request.expected().is_none()) {
            return Err("NV native exact request refused before command".into());
        }
        let intended=if request.is_increment(){Some(request.expected().ok_or("NV before absent")?
            .checked_add(1).ok_or("NV overflow before command")?)}else{request.expected()};
        // Armed before every real command, including read/auth errors or unwind.
        // An interrupted mutation never becomes a usable producer by catching a
        // panic. Restart requires the existing exact CounterStore/NV recovery.
        self.frozen=true;self.sequence=request.sequence();
        let result=(||{
            let(before,mut message,mut signature)=self.certify(request.challenge())?;
            if request.expected().is_some_and(|v|v!=before.counter)
                || self.last.is_some_and(|v|!Self::same_lineage(v,before)) {
                return Err("NV native before value/lineage changed".into());
            }
            let outcome=if request.is_increment(){
                self.increment()?;
                let(after,new_message,new_signature)=self.certify(request.challenge())?;
                if Some(after.counter)!=intended || !Self::same_lineage(before,after) {
                    return Err("NV native after value/lineage ambiguous".into());
                }
                message=new_message;signature=new_signature;after
            }else{before};
            let used=6usize.checked_add(self.public.len()).and_then(|n|n.checked_add(message.len()))
                .and_then(|n|n.checked_add(signature.len())).ok_or("NV response size overflow")?;
            if used>MAX_RESPONSE{return Err("NV native response bound".into());}
            response[..2].copy_from_slice(&(self.public.len() as u16).to_be_bytes());
            response[2..4].copy_from_slice(&(message.len() as u16).to_be_bytes());
            response[4..6].copy_from_slice(&(signature.len() as u16).to_be_bytes());
            let p=6+self.public.len();let m=p+message.len();
            response[6..p].copy_from_slice(&self.public);response[p..m].copy_from_slice(&message);
            response[m..used].copy_from_slice(&signature);Ok((outcome,used))
        })();
        match result {Ok((last,used))=>{self.last=Some(last);self.frozen=false;Ok(used)},Err(e)=>Err(e)}
    }
}
