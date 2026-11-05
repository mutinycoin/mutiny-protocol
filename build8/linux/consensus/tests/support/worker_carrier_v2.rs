fn qualify_worker_carrier(
    context: mutiny_transport_v2::worker_context_v2::Context,
    signer: &impl mutiny_transport_v2::worker_handshake_v2::NodeSessionSigner,
    binding: &mutiny_crypto_v2::enrollment::Binding,
    chain: &crate::canonical_store_v2::CanonicalStore,
    parent: &FinalizedAnchor,
    descriptor: &[u8],
) {
    use std::{cell::RefCell, rc::Rc, io::{self, Read, Write, ErrorKind}, time::{Instant, Duration}};
    use crate::{worker_carrier_v2::{Carrier, NonblockingIo}, worker_current_channel_v2::CanonicalWorkerChannel};
    use mutiny_transport_v2::worker_handshake_v2::Authority;
    #[derive(Default)]
    struct State {input: Vec<u8>, offset: usize, output: Vec<u8>, blocked: bool, closed: bool,
        reads: usize, writes: usize, mode: u8}
    struct Io(Rc<RefCell<State>>, std::sync::Arc<std::sync::Mutex<Instant>>);
    impl Read for Io {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            assert!(buf.len()<=4096);
            let mut s=self.0.borrow_mut();s.reads+=1;
            if s.mode==1 {return Ok(buf.len()+1);}
            if s.mode==2 {return Ok(0);}
            if s.mode==6 { *self.1.lock().unwrap() += Duration::from_millis(5010); }
            // Positive partial-I/O case makes the first transfer short, then
            // permits normal host batching. Arbitrarily slow repeated prefixes
            // may correctly exhaust the production five-second deadline.
            let chunk=if s.mode==8 || (s.mode==7 && s.reads>1) {4096} else {31};
            let n=buf.len().min(chunk).min(s.input.len()-s.offset);
            if n==0 {return Err(ErrorKind::WouldBlock.into());}
            buf[..n].copy_from_slice(&s.input[s.offset..s.offset+n]);s.offset+=n;Ok(n)
        }
    }
    impl Write for Io {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            assert!(buf.len()<=4096);
            let mut s=self.0.borrow_mut();s.writes+=1;
            if s.mode==3 {return Ok(buf.len()+1);}
            if s.blocked {return Err(ErrorKind::WouldBlock.into());}
            let chunk=if s.mode==7 && s.writes>1 {4096} else {31};
            let n=buf.len().min(chunk);s.output.extend_from_slice(&buf[..n]);Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {Ok(())}
    }
    impl NonblockingIo for Io {fn close(&mut self) {self.0.borrow_mut().closed=true;}}
    let (public,generation)=mutiny_crypto_v2::PublicKey::decode_descriptor(descriptor).unwrap();
    let authority=Authority {binding,node:&public,node_generation:generation,height:1,epoch:1};
    for mode in [0,1,2,3,4,5,6,7,8] {
        let (worker,pending,finish)=begin_worker_custody_handshake(context.clone(),signer,binding);
        let mut clock=FixedWorkerClock(crate::hybrid_coordinator_v2::Sample {monotonic_ms:100,unix_ms:1_100_000});
        let (node,tag)=CanonicalWorkerChannel::finish(pending,&finish,chain,parent,binding.license,binding.worker_id,&mut clock).unwrap();
        let mut worker=worker.finish(&tag).unwrap().into_channel(&authority).unwrap();
        let time=std::sync::Arc::new(std::sync::Mutex::new(Instant::now()));
        let shared=Rc::new(RefCell::new(State {mode,blocked:mode==0,..State::default()}));
        if mode==8 {
            let payload=vec![0x55;mutiny_transport_v2::worker_handshake_v2::MAX_PAYLOAD];
            shared.borrow_mut().input.extend(worker.seal(&authority,&payload).unwrap());
            let mut carrier=Carrier::new_with_test_clock(Io(shared.clone(),time.clone()),node,time.clone());
            let began=Instant::now();let mut found=None;
            for _ in 0..25 {
                match carrier.step(chain,parent,&mut clock) {
                    Ok(Some(p))=>{found=Some(p);break;},Ok(None)=>{},
                    Err(e)=>panic!("maximum frame {e:?}; elapsed_ms={} reads={}",began.elapsed().as_millis(),shared.borrow().reads),
                }
            }
            assert_eq!(found.unwrap(),payload);
            println!("WORKER_CARRIER_MAX_FRAME_PASS elapsed_ms={} reads={}",began.elapsed().as_millis(),shared.borrow().reads);
            continue;
        }
        shared.borrow_mut().input.extend(worker.seal(&authority,b"first").unwrap());
        shared.borrow_mut().input.extend(worker.seal(&authority,b"second").unwrap());
        let mut carrier=Carrier::new_with_test_clock(Io(shared.clone(),time.clone()),node,time.clone());
        let until=if mode==4 {*time.lock().unwrap()-Duration::from_millis(1)} else {*time.lock().unwrap()+Duration::from_secs(5)};
        let began=Instant::now();
        let queued=carrier.queue(chain,parent,&mut clock,b"outgoing",until);
        if mode==4 {
            assert!(queued.is_err());assert!(shared.borrow().closed);assert_eq!(shared.borrow().reads+shared.borrow().writes,0);continue;
        }
        assert!(queued.unwrap());
        assert!(!carrier.queue(chain,parent,&mut clock,b"must not replace",until).unwrap());
        let mut received=Vec::new();let mut failed=false;let mut failure=None;
        let mut expected=parent.clone();if mode==5 {expected.block[0]^=1;}
        for _ in 0..200 {
            let before={let s=shared.borrow();s.reads+s.writes};
            let result=carrier.step(chain,&expected,&mut clock);
            let after={let s=shared.borrow();s.reads+s.writes};assert!(after-before<=1);
            match result {Ok(Some(p))=>received.push(p),Ok(None)=>{},Err(e)=>{failure=Some(e);failed=true;break;}}
            if received.len()==if mode==0 {1} else {2} {break;}
        }
        if mode==0 {
            assert!(!failed,"carrier {failure:?}; elapsed_ms={} reads={} writes={} received={}",
                began.elapsed().as_millis(),shared.borrow().reads,shared.borrow().writes,received.len());
            assert_eq!(received,vec![b"first".to_vec()]);
            assert!(shared.borrow().output.is_empty(),"blocked output was written");
            *time.lock().unwrap()=until;
            let before={let s=shared.borrow();s.reads+s.writes};
            assert!(matches!(carrier.step(chain,parent,&mut clock),Err(mutiny_transport_v2::Error::Expired)));
            assert_eq!(before,{let s=shared.borrow();s.reads+s.writes});
        } else if mode==7 {
            assert!(!failed,"short I/O {failure:?}; elapsed_ms={}",began.elapsed().as_millis());
            assert_eq!(received,vec![b"first".to_vec(),b"second".to_vec()]);
            for _ in 0..200 {if shared.borrow().output.len()==68 {break;}carrier.step(chain,parent,&mut clock).unwrap();}
            assert_eq!(worker.open(&authority,&shared.borrow().output).unwrap(),b"outgoing");
            let next_until=*time.lock().unwrap()+Duration::from_secs(5);
            assert!(carrier.queue(chain,parent,&mut clock,b"next",next_until).unwrap());
            carrier.close();
        } else {assert!(failed,"fault mode {mode}");assert!(received.is_empty());}
        assert!(shared.borrow().closed);
        assert!(carrier.step(chain,parent,&mut clock).is_err());
    }
}
