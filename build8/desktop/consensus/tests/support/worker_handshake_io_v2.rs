fn qualify_worker_handshake_io(
    key: crate::worker_handshake_io_v2::Custody<'_>,
    context: mutiny_transport_v2::worker_context_v2::Context,
    binding: &mutiny_crypto_v2::enrollment::Binding,
    chain: &crate::canonical_store_v2::CanonicalStore,
    parent: &FinalizedAnchor,
    descriptor: &[u8],
) {
    use crate::{worker_handshake_io_v2::Handshake,worker_carrier_v2::NonblockingIo,
        hybrid_coordinator_v2::{Clock,Sample}};
    use mutiny_transport_v2::worker_handshake_v2::{WorkerSigner,WorkerPending,Authority,RESPONSE_LEN};
    use std::{io::{self,Read,Write,ErrorKind},cell::RefCell,rc::Rc,time::{Instant,Duration}};
    struct Device(u8);
    impl WorkerSigner for Device {
        fn public(&self)->[u8;57] {license_fixture::worker(self.0)}
        fn sign_session(&mut self,t:&[u8;64])->mutiny_transport_v2::Result<[u8;114]> {
            use std::ffi::{c_void,c_char};
            unsafe extern "C" {
                fn ossl_ed448_sign(c:*mut c_void,s:*mut u8,m:*const u8,n:usize,p:*const u8,
                    k:*const u8,d:*const u8,dn:usize,ph:u8,prop:*const c_char)->i32;
            }
            let m=mutiny_crypto_v2::worker_session_auth::intent(t);let mut s=[0;114];
            assert_eq!(unsafe {ossl_ed448_sign(std::ptr::null_mut(),s.as_mut_ptr(),m.as_ptr(),64,
                self.public().as_ptr(),[self.0;57].as_ptr(),std::ptr::null(),0,0,std::ptr::null())},1);
            Ok(s)
        }
    }
    struct TestClock {calls:u64,bad_at:u64,value:Sample}
    impl Clock for TestClock {
        fn sample(&mut self)->std::result::Result<Sample,String> {
            self.calls+=1;let mut v=self.value;
            if self.calls==self.bad_at {v.monotonic_ms-=1;}
            Ok(v)
        }
    }
    #[derive(Default)]
    struct State {input:Vec<u8>,offset:usize,output:Vec<u8>,blocked:bool,closed:bool,mode:u8,calls:usize}
    struct Io(Rc<RefCell<State>>);
    impl Read for Io {
        fn read(&mut self,b:&mut[u8])->io::Result<usize> {
            assert!(b.len()<=4096);let mut s=self.0.borrow_mut();s.calls+=1;
            if s.mode==3 {return Ok(0);}
            if s.mode==10 {return Ok(b.len()+1);}
            let n=b.len().min(256).min(s.input.len()-s.offset);
            if n==0 {return Err(ErrorKind::WouldBlock.into());}
            b[..n].copy_from_slice(&s.input[s.offset..s.offset+n]);s.offset+=n;Ok(n)
        }
    }
    impl Write for Io {
        fn write(&mut self,b:&[u8])->io::Result<usize> {
            assert!(b.len()<=4096);let mut s=self.0.borrow_mut();s.calls+=1;
            if s.blocked {return Err(ErrorKind::WouldBlock.into());}
            let n=b.len().min(512);s.output.extend_from_slice(&b[..n]);Ok(n)
        }
        fn flush(&mut self)->io::Result<()> {Ok(())}
    }
    impl NonblockingIo for Io {fn close(&mut self){self.0.borrow_mut().closed=true;}}
    let seed=(1..=12).find(|s|license_fixture::worker(*s)==binding.worker_public).unwrap();
    let (public,generation)=mutiny_crypto_v2::PublicKey::decode_descriptor(descriptor).unwrap();
    let authority=Authority {binding,node:&public,node_generation:generation,height:1,epoch:1};
    use crate::worker_pending_budget_v2::{Budget,Limits};
    let budget=Budget::new(Limits {pending:1,attempts_per_minute:100,attempts_per_worker_per_minute:100}).unwrap();
    for claim in [None,Some([0;32])] {
        let permit=budget.reserve().unwrap();
        if let Some(worker)=claim {permit.claim(worker).unwrap();}
        let shared=Rc::new(RefCell::new(State::default()));
        let mut clock=TestClock {calls:0,bad_at:u64::MAX,value:Sample {monotonic_ms:100,unix_ms:1_100_000}};
        assert!(Handshake::begin_admitted(Io(shared.clone()),permit,key,chain,parent,binding.license,binding.worker_id,&mut clock).is_err());
        assert!(shared.borrow().closed);assert_eq!(shared.borrow().calls,0);assert_eq!(clock.calls,0);
    }
    for mode in [0,1,2,3,4,5,6,7,8,9,10] {
        let mut device=Device(seed);
        let (worker,mut hello)=WorkerPending::start(context.clone(),&device).unwrap();
        if mode==1 {hello[0]^=1;}
        let shared=Rc::new(RefCell::new(State {input:hello,mode,..State::default()}));
        let mut clock=TestClock {calls:0,bad_at:u64::MAX,value:Sample {monotonic_ms:100,unix_ms:1_100_000}};
        let mut hs=if mode==0 {
            use crate::worker_context_router_v2::{Prefix,Routes,Route};
            let routes=Routes::new([(context.id(),Route {license:binding.license,worker:binding.worker_id})],1).unwrap();
            let mut prefix=Prefix::begin(Io(shared.clone()),&budget).unwrap();
            let routed=prefix.step(&routes).unwrap().unwrap();
            assert_eq!(shared.borrow().offset,66);drop(prefix);assert!(!shared.borrow().closed);
            Handshake::begin_routed(routed,key,chain,parent,&mut clock).unwrap()
        } else {
            let permit=budget.reserve().unwrap();permit.claim(binding.worker_id).unwrap();
            Handshake::begin_admitted(Io(shared.clone()),permit,key,chain,parent,binding.license,binding.worker_id,&mut clock).unwrap()
        };
        assert!(budget.reserve().is_err());
        let mut expected=parent.clone();if mode==6 {expected.block[0]^=1;}
        if mode==4 {clock.value.monotonic_ms=99;}
        if mode==5 {clock.value.monotonic_ms=60_100;}
        let mut failed=false;
        for _ in 0..40 {
            let before=shared.borrow().calls;
            match hs.step(key,chain,&expected,&mut clock) {Ok(None)=>{},Ok(Some(_))=>panic!("premature carrier"),Err(_)=>{failed=true;}}
            assert!(shared.borrow().calls-before<=1);
            if failed {break;}
            if mode==7 && shared.borrow().offset==shared.borrow().input.len() {
                shared.borrow_mut().blocked=true;
                for _ in 0..3 {assert!(hs.step(key,chain,parent,&mut clock).unwrap().is_none());}
                clock.value.monotonic_ms=60_100;
                assert!(matches!(hs.step(key,chain,parent,&mut clock),Err(mutiny_transport_v2::Error::Expired)));
                failed=true;break;
            }
            if shared.borrow().output.len()==RESPONSE_LEN {break;}
        }
        if matches!(mode,1|3|4|5|6|7|10) {
            assert!(failed,"mode {mode}");assert!(shared.borrow().closed);assert!(shared.borrow().output.is_empty());continue;
        }
        assert!(!failed);assert_eq!(shared.borrow().output.len(),RESPONSE_LEN);
        let (worker,mut finish)=worker.accept(&mut device,&shared.borrow().output).unwrap();
        if mode==2 {finish[114]^=1;}
        {let mut s=shared.borrow_mut();s.output.clear();s.input=finish;s.offset=0;}
        if mode==8 {clock.bad_at=clock.calls+3;} // first nested activation sample
        let result=hs.step(key,chain,parent,&mut clock);
        if matches!(mode,2|8) {
            assert!(result.is_err(),"mode {mode}");assert!(shared.borrow().closed);assert!(shared.borrow().output.is_empty());continue;
        }
        assert!(result.unwrap().is_none());assert!(shared.borrow().output.is_empty());
        if mode==9 {clock.bad_at=clock.calls+2;} // nested pre-write channel check
        let result=hs.step(key,chain,parent,&mut clock);
        if mode==9 {
            assert!(result.is_err());assert!(shared.borrow().closed);assert!(shared.borrow().output.is_empty());continue;
        }
        let carrier=result.unwrap().expect("complete Finished handoff");
        let active=crate::worker_active_connections_v2::Registry::new(1).unwrap();
        let mut carrier=active.admit(carrier,chain,parent,&mut clock).unwrap();
        assert_eq!(shared.borrow().output.len(),16);
        let mut worker=worker.finish(&shared.borrow().output).unwrap().into_channel(&authority).unwrap();
        drop(hs);assert!(!shared.borrow().closed,"handoff closed owned socket");
        shared.borrow_mut().output.clear();
        assert!(carrier.queue(chain,parent,&mut clock,b"ready",Instant::now()+Duration::from_secs(5)).unwrap());
        for _ in 0..4 {carrier.step(chain,parent,&mut clock).unwrap();if shared.borrow().output.len()==65 {break;}}
        assert_eq!(worker.open(&authority,&shared.borrow().output).unwrap(),b"ready");
        let mut request=vec![5];request.extend([0x61;32]);request.extend([0;40]);
        {let mut s=shared.borrow_mut();s.input=worker.seal(&authority,&request).unwrap();s.offset=0;}
        let received=loop {if let Some(event)=carrier.step(chain,parent,&mut clock).unwrap(){break event;}};
        let io_calls=shared.borrow().calls;
        assert!(carrier.step(chain,parent,&mut clock).unwrap().is_none());
        assert_eq!(shared.borrow().calls,io_calls,"outstanding dispatch must bound additional receive");
        let mut dispatched=false;
        carrier.dispatch_typed(received,chain,parent,&mut clock,|message|{
            assert_eq!(message,crate::worker_protocol_v2::Incoming::Request {nonce:[0x61;32],sequence:0,chain:[0;32]});
            dispatched=true;Ok(())
        }).unwrap();
        assert!(dispatched);
        carrier.close();assert!(shared.borrow().closed);
    }
}
