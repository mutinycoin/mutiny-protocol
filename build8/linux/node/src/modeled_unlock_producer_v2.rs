//! Explicit TEST-VALUE producer. No installed/normal constructor or secret
//! source authority is exported; this entire module is absent outside tests.
#![cfg(test)]
use crate::hybrid_owned_unlock_input_v2::UnlockBinding;
use crate::hybrid_unlock_request_v2::UnlockRequest;
use mutiny_consensus_v8::Hash;
use std::io::Write;
use zeroize::Zeroizing;
type Result<T>=std::result::Result<T,String>;
struct ModeledUnlockProducer{context:Hash,node_pin:Hash,continuity_pin:Hash,
    node:Zeroizing<String>,continuity:Zeroizing<String>,used:bool,delivered:bool}
impl ModeledUnlockProducer{
    fn from_public_test_values(context:Hash,node_pin:Hash,continuity_pin:Hash,
        node:Zeroizing<String>,continuity:Zeroizing<String>)->Result<Self>{
        if [context,node_pin,continuity_pin].contains(&[0;32])||node.len()>4096||continuity.len()>4096{
            return Err("modeled source bounds/context".into());}
        Ok(Self{context,node_pin,continuity_pin,node,continuity,used:false,delivered:false})
    }
    fn issue_once(&mut self,request:&[u8;144],writer:&mut impl Write)->Result<[u8;48]>{
        if self.used{return Err("modeled source cannot retry an issued or unknown delivery".into());}
        let request=UnlockRequest::decode(request,self.context,self.node_pin,self.continuity_pin)?;
        let UnlockBinding(binding)=request.binding();
        // Arm BEFORE external Write. A caught panic, partial write or lost
        // acknowledgment cannot offer the source secrets a second time.
        self.used=true;
        let mut header=[0;52];header[..16].copy_from_slice(b"BUILD8-UNLOCK-V1");header[16..48].copy_from_slice(&binding);
        header[48..50].copy_from_slice(&(self.node.len() as u16).to_be_bytes());
        header[50..52].copy_from_slice(&(self.continuity.len() as u16).to_be_bytes());
        writer.write_all(&header).map_err(|_|"modeled secret header write unknown")?;
        writer.write_all(self.node.as_bytes()).map_err(|_|"modeled Node secret write unknown")?;
        writer.write_all(self.continuity.as_bytes()).map_err(|_|"modeled Continuity secret write unknown")?;
        writer.flush().map_err(|_|"modeled secret flush unknown")?;self.delivered=true;Ok(request.acknowledgment())
    }
    fn accept_exact_ack(&mut self,ack:&[u8;48],expected:&[u8;48])->Result<()>{
        let delivered=self.delivered;self.delivered=false;
        if !self.used||!delivered||ack!=expected{return Err("modeled exact secret acknowledgment refused".into());}
        Ok(())
    }
}
fn request()->[u8;144]{let mut frame=[0;144];frame[..16].copy_from_slice(b"B8-UNLOCK-REQ-V1");
    for(i,pin)in [[1;32],[2;32],[3;32],[4;32]].iter().enumerate(){frame[16+i*32..48+i*32].copy_from_slice(pin);}frame}
fn producer()->ModeledUnlockProducer{ModeledUnlockProducer::from_public_test_values([1;32],[2;32],[3;32],
    Zeroizing::new("PUBLIC TEST Node".into()),Zeroizing::new("PUBLIC TEST Continuity".into())).unwrap()}
#[test]
fn modeled_one_shot_producer_reaches_exact_zeroizing_consumer_and_ack(){
    let raw=request();let mut producer=producer();let mut frame=Zeroizing::new(Vec::new());
    let ack=producer.issue_once(&raw,&mut *frame).unwrap();
    let request=UnlockRequest::decode(&raw,[1;32],[2;32],[3;32]).unwrap();
    let value=crate::hybrid_owned_unlock_input_v2::OwnedPasswords::read_existing(
        &mut std::io::Cursor::new(&frame[..]),&request.binding()).unwrap();
    assert_eq!(value.node(),"PUBLIC TEST Node");assert_eq!(value.continuity(),"PUBLIC TEST Continuity");
    producer.accept_exact_ack(&ack,&ack).unwrap();assert!(producer.issue_once(&raw,&mut *frame).is_err());
}
#[test]
fn modeled_producer_wrong_role_partial_write_and_caught_unwind_cannot_reissue(){
    let mut wrong=request();wrong[48]=9;let mut producer=producer();let mut frame=Zeroizing::new(Vec::new());
    assert!(producer.issue_once(&wrong,&mut *frame).is_err());assert!(!producer.used);assert!(frame.is_empty());
    struct Fail;impl Write for Fail{fn write(&mut self,_:&[u8])->std::io::Result<usize>{Err(std::io::ErrorKind::BrokenPipe.into())}
        fn flush(&mut self)->std::io::Result<()>{Ok(())}}
    assert!(producer.issue_once(&request(),&mut Fail).is_err());assert!(producer.issue_once(&request(),&mut *frame).is_err());
    struct Panic;impl Write for Panic{fn write(&mut self,_:&[u8])->std::io::Result<usize>{panic!("PUBLIC modeled writer failure")}
        fn flush(&mut self)->std::io::Result<()>{Ok(())}}
    let mut other=super::modeled_unlock_producer_v2::producer();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(||other.issue_once(&request(),&mut Panic))).is_err());
    assert!(other.issue_once(&request(),&mut *frame).is_err());
}

/// This TEST owns a genuine kernel socket pair and original private producer
/// thread. Its peer is the same TEST process, not an installed secret issuer or
/// hardware/provider authority. No path, account, production secret or service
/// is selected here; only explicitly PUBLIC TEST values enter the old codec.
#[cfg(target_os="linux")]
mod native_owned_pair_controls{
    use super::*;
    use crate::{hybrid_native_retained_input_v2::{NativeInputSlot,RetainedNativeFile},
        host_clock::RetainedCloseReport};
    use std::{fs::File,io::{Read,Write},mem::{ManuallyDrop as MD,size_of,zeroed},
        os::{fd::{AsRawFd,OwnedFd},unix::net::UnixStream}};

    struct Pair{
        producer:Option<RetainedNativeFile>,consumer:Option<RetainedNativeFile>,
    }
    fn original_pair()->std::result::Result<MD<Box<Pair>>,String>{
        // Both original custody/once-close slots precede socket acquisition.
        let left_slot=NativeInputSlot::prepare()?;let right_slot=NativeInputSlot::prepare()?;
        let mut pair=MD::new(Box::new(Pair{producer:None,consumer:None}));
        let(left,right)=UnixStream::pair().map_err(|_|"TEST original socket pair unavailable")?;
        let right=MD::new(right);
        pair.producer=Some(left_slot.retain(File::from(OwnedFd::from(left)))
            .map_err(|failure|failure.cause)?);
        pair.consumer=Some(right_slot.retain(File::from(OwnedFd::from(MD::into_inner(right))))
            .map_err(|failure|failure.cause)?);
        Ok(pair)
    }
    fn same_test_peer(socket:&RetainedNativeFile)->Result<()>{
        socket.recheck_identity()?;
        let mut observed:libc::ucred=unsafe{zeroed()};let mut length=size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe{libc::getsockopt(socket.file()?.as_raw_fd(),libc::SOL_SOCKET,libc::SO_PEERCRED,
            (&mut observed as *mut libc::ucred).cast(),&mut length)}!=0
            ||length as usize!=size_of::<libc::ucred>()
            ||(observed.pid,observed.uid,observed.gid)!=unsafe{(libc::getpid(),libc::geteuid(),libc::getegid())}{
            return Err("TEST pair exact own kernel peer differs".into());
        }Ok(())
    }
    fn end_original_write(socket:&RetainedNativeFile)->Result<()>{
        if unsafe{libc::shutdown(socket.file()?.as_raw_fd(),libc::SHUT_WR)}!=0{
            return Err("TEST original socket write settlement unavailable".into());
        }Ok(())
    }
    struct ProducerState{socket:Option<RetainedNativeFile>,source:ModeledUnlockProducer,
        failure:Option<String>,terminal_wake:Option<std::result::Result<(),i32>>}
    struct ProducerOutcome{state:MD<Box<ProducerState>>,close:Option<RetainedCloseReport>,completed:bool}
    fn run_producer(mut state:MD<Box<ProducerState>>)->ProducerOutcome{
        let s=&mut **state;
        let result=(||->Result<()>{
            let socket=s.socket.as_ref().ok_or("TEST original producer absent")?;
            same_test_peer(socket)?;
            let mut request=[0;144];let mut input=socket.file()?;
            input.read_exact(&mut request).map_err(|_|"TEST request exact read")?;
            same_test_peer(socket)?;
            let mut output=socket.file()?;
            let ack=s.source.issue_once(&request,&mut output)?;
            end_original_write(socket)?;
            let mut received=[0;48];input.read_exact(&mut received).map_err(|_|"TEST exact ack read")?;
            let mut extra=[0];if input.read(&mut extra).map_err(|_|"TEST ack EOF")?!=0{
                return Err("TEST ack trailing data".into());
            }
            same_test_peer(socket)?;s.source.accept_exact_ack(&received,&ack)?;Ok(())
        })();
        if let Err(error)=result{state.failure=Some(error);
            // A refused producer must not leave its counterpart blocked on the
            // same socket's secret EOF. Signal ONLY this original owned TEST
            // socket, once, and retain the exact outcome before returning its
            // frozen custody. Shutdown is not a close or a successful join.
            if let Some(socket)=state.socket.as_ref(){
                if let Ok(original)=socket.file(){
                    let value=unsafe{libc::shutdown(original.as_raw_fd(),libc::SHUT_RDWR)};
                    let outcome=if value==0{Ok(())}else{
                        Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(-1))};
                    state.terminal_wake=Some(outcome);
                }
            }
            return ProducerOutcome{state,close:None,completed:false};}
        let close=match state.socket.take().expect("original TEST producer socket").close_once(){
            Ok(report)=>report,Err(original)=>{state.socket=Some(MD::into_inner(original));
                return ProducerOutcome{state,close:None,completed:false};}
        };
        let completed=close.retained_handles_closed();ProducerOutcome{state,close:Some(close),completed}
    }
    #[test]
    fn test_owned_kernel_pair_exact_secret_delivery_original_thread_join_and_both_once_closes(){
        let mut pair=match original_pair(){Ok(value)=>value,Err(_)=>panic!("TEST pair preparation refused")};
        same_test_peer(pair.producer.as_ref().expect("producer original")).expect("TEST producer peer");
        same_test_peer(pair.consumer.as_ref().expect("consumer original")).expect("TEST consumer peer");
        let producer=MD::new(Box::new(ProducerState{socket:pair.producer.take(),source:producer(),failure:None,terminal_wake:None}));
        let original=MD::new(match std::thread::Builder::new().name("test-public-unlock-source".into())
            .spawn(move||run_producer(producer)){Ok(value)=>value,Err(_)=>panic!("TEST original producer spawn refused")});
        let socket=pair.consumer.as_ref().expect("consumer original");
        let raw=request();let binding=UnlockRequest::decode(&raw,[1;32],[2;32],[3;32]).expect("TEST request");
        let mut io=socket.file().expect("consumer original file");
        io.write_all(&raw).expect("TEST exact request write");io.flush().expect("TEST request flush");
        let passwords=crate::hybrid_owned_unlock_input_v2::OwnedPasswords::read_existing(&mut io,&binding.binding())
            .expect("TEST zeroizing consumer");
        assert_eq!(passwords.node(),"PUBLIC TEST Node");assert_eq!(passwords.continuity(),"PUBLIC TEST Continuity");
        same_test_peer(socket).expect("TEST current consumer peer");
        io.write_all(&binding.acknowledgment()).expect("TEST exact ack write");io.flush().expect("TEST ack flush");
        end_original_write(socket).expect("TEST original consumer write settlement");
        // Preserve the exact ORIGINAL thread outcome before inspecting it.
        let mut joined=MD::new(MD::into_inner(original).join());
        let outcome=match &mut *joined{Ok(value)=>value,Err(_)=>panic!("TEST original producer panic retained")};
        assert!(outcome.completed);assert!(outcome.close.as_ref().is_some_and(RetainedCloseReport::retained_handles_closed));
        let close=match pair.consumer.take().expect("consumer original").close_once(){
            Ok(value)=>value,Err(_original)=>panic!("TEST consumer original close retained")};
        assert!(close.retained_handles_closed());assert_eq!(close.attempted(),1);
        drop(passwords);
        // Both native observations are known, so the completed owner allocations
        // can be released. No numeric FD is retried or fabricated from a path.
        let mut outcome=MD::into_inner(joined).expect("known TEST original thread outcome");
        unsafe{MD::drop(&mut outcome.state)};
        unsafe{MD::drop(&mut pair)};
    }
}
