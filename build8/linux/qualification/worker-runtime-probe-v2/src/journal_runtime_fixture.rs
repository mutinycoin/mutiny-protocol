//! PUBLIC native route through actual C controller/stream/runtime guards.
//! Callback I/O is a software model; canonical policy supplied separately.
use super::*;
use mutiny_consensus_v8::pow::WorkContext;
#[repr(C)]
struct PinnedWork {
    genesis: [u8;32], fingerprint: [u8;32], parent: [u8;32], license: [u8;32], worker: [u8;32], coordinator: [u8;32], target: [u8;32],
    height: u64, genesis_timestamp: u64, assignment: u64, last_ticket: u64,
}
unsafe extern "C" {
    fn build8_qual_journal_owner_size()->usize;
    fn build8_qual_journal_owner_alignment()->usize;
    fn build8_qual_journal_owner_init(s:*mut c_void,a:*const JournalLocal,p:*mut c_void,pn:usize,w:*const PinnedWork,id:*const u8,h:u64,e:u64)->i32;
    fn build8_qual_journal_owner_input(s:*mut c_void,raw:*const u8,n:usize);
    fn build8_qual_journal_owner_output(s:*mut c_void,out:*mut u8,n:usize)->usize;
    fn build8_qual_journal_owner_step(s:*mut c_void,plain:*mut u8,n:usize,written:*mut usize)->i32;
    fn build8_qual_journal_owner_confirm(s:*mut c_void)->i32;
    fn build8_qual_journal_owner_send(s:*mut c_void,raw:*const u8,n:usize)->i32;
    fn build8_qual_journal_owner_request(s:*mut c_void,nonce:*const u8)->i32;
    fn build8_qual_journal_owner_offer(s:*mut c_void,raw:*const u8,n:usize)->i32;
    fn build8_qual_journal_owner_nonce(s:*mut c_void,out:*mut u64)->i32;
    fn build8_qual_journal_owner_found(s:*mut c_void,id:*const u8,nonce:u64)->i32;
    fn build8_qual_journal_owner_fault(s:*mut c_void,fault:u32);
    fn build8_qual_journal_owner_maintenance(s:*mut c_void);
    fn build8_qual_journal_owner_accounting(s:*mut c_void);
    fn build8_qual_journal_owner_flags(s:*mut c_void)->u32;
    fn build8_qual_journal_owner_ticket(s:*mut c_void)->u64;
    fn build8_qual_journal_owner_close(s:*mut c_void);
    fn build8_qual_journal_owner_cleared(s:*mut c_void)->i32;
    fn build8_qual_journal_owner_legacy_bypass(s:*mut c_void)->i32;
}
#[cfg(target_os="linux")]
unsafe extern "C" {
    fn build8_qual_journal_owner_socket(s:*mut c_void,fd:i32)->i32;
    fn build8_qual_journal_owner_socket_closed(s:*mut c_void)->i32;
}
struct Owner { words: Vec<u64>, #[cfg(target_os="linux")] peer:Option<std::os::unix::net::UnixStream> }
impl Owner {
    fn new()->Self {assert!(unsafe{build8_qual_journal_owner_alignment()}<=8);Self{words:vec![0;unsafe{build8_qual_journal_owner_size()}.div_ceil(8)],#[cfg(target_os="linux")] peer:None}}
    fn ptr(&mut self)->*mut c_void{self.words.as_mut_ptr().cast()}
    #[cfg(target_os="linux")]
    fn attach_socket(&mut self){
        use std::os::fd::{IntoRawFd,FromRawFd,OwnedFd};
        let(worker,peer)=std::os::unix::net::UnixStream::pair().unwrap();
        worker.set_nonblocking(true).unwrap();
        peer.set_read_timeout(Some(std::time::Duration::from_millis(2))).unwrap();
        peer.set_write_timeout(Some(std::time::Duration::from_secs(1))).unwrap();
        let fd=worker.into_raw_fd();
        if unsafe{build8_qual_journal_owner_socket(self.ptr(),fd)}!=1{
            drop(unsafe{OwnedFd::from_raw_fd(fd)});panic!("native socket ownership refused");
        }
        self.peer=Some(peer);
    }
    #[cfg(target_os="linux")]
    fn socket_retirement(&mut self){
        use std::io::Read;
        unsafe{build8_qual_journal_owner_close(self.ptr())};self.closed();
        assert_eq!(unsafe{build8_qual_journal_owner_socket_closed(self.ptr())},1);
        let mut byte=[0;1];assert_eq!(self.peer.as_mut().unwrap().read(&mut byte).unwrap(),0,"peer observes actual EOF");
        // Idempotent retirement must not close a recycled descriptor or reopen authority.
        unsafe{build8_qual_journal_owner_close(self.ptr())};
        assert_eq!(unsafe{build8_qual_journal_owner_socket_closed(self.ptr())},1);
    }
    fn step(&mut self)->(i32,Vec<u8>){
        let mut raw=vec![7;16384];let mut n=7;
        let event=unsafe{build8_qual_journal_owner_step(self.ptr(),raw.as_mut_ptr(),raw.len(),&mut n)};
        if event!=4 {assert_eq!(n,0);assert!(raw.iter().all(|b|*b==0));raw.clear();}else{raw.truncate(n);}
        (event,raw)
    }
    fn input(&mut self,raw:&[u8]){
        #[cfg(target_os="linux")]
        if let Some(peer)=self.peer.as_mut(){use std::io::Write;peer.write_all(raw).unwrap();return;}
        unsafe{build8_qual_journal_owner_input(self.ptr(),raw.as_ptr(),raw.len())};
    }
    fn output(&mut self)->Vec<u8>{
        #[cfg(target_os="linux")]
        if let Some(peer)=self.peer.as_mut(){
            use std::io::{Read,ErrorKind};let mut out=Vec::new();let mut chunk=[0;4096];
            for _ in 0..16{match peer.read(&mut chunk){
                Ok(0)=>return out,Ok(n)=>out.extend_from_slice(&chunk[..n]),
                Err(e) if matches!(e.kind(),ErrorKind::WouldBlock|ErrorKind::TimedOut)=>return out,
                Err(e)=>panic!("native socket peer read failed: {e}"),
            }}panic!("native socket output exceeded bounded drain");
        }
        let mut out=vec![0;65536];let n=unsafe{build8_qual_journal_owner_output(self.ptr(),out.as_mut_ptr(),out.len())};out.truncate(n);out
    }
    fn flush(&mut self,n:usize)->Vec<u8>{
        let mut out=Vec::new();for _ in 0..40 {assert_ne!(self.step().0,0);out.extend(self.output());if out.len()==n{return out;}assert!(out.len()<n);}
        panic!("actual C stream did not finish bounded output of {n} bytes");
    }
    fn message(&mut self)->Vec<u8>{for _ in 0..40{let(e,raw)=self.step();assert_ne!(e,0);if e==4{return raw;}}panic!("actual C stream failed bounded incoming frame");}
    fn closed(&mut self){assert_eq!(unsafe{build8_qual_journal_owner_cleared(self.ptr())},1);}
}
impl Drop for Owner {fn drop(&mut self){unsafe{build8_qual_journal_owner_close(self.ptr())};}}

/// Actual C stream callbacks (partial write/read), independent real Rust Node
/// both-Finished crypto and ordinary mining guards. WorkContext must come from
/// caller's verified own chain for canonical tests; model controls label it.
pub(super) fn route(journal:&mut Journal,worker:&mut Ordinary,binding:&Binding,node:&HybridKey,
    work:&WorkContext,epoch:u64,signed_offer:Option<(&[u8],[u8;32],u64)>,fault:u32,mut change:Option<&mut dyn FnMut()>)
{
    route_transport(journal,worker,binding,node,work,epoch,signed_offer,fault,change,false);
}
#[cfg(target_os="linux")]
pub(super) fn route_socket(journal:&mut Journal,worker:&mut Ordinary,binding:&Binding,node:&HybridKey,
    work:&WorkContext,epoch:u64,signed_offer:Option<(&[u8],[u8;32],u64)>,fault:u32,change:Option<&mut dyn FnMut()>)
{route_transport(journal,worker,binding,node,work,epoch,signed_offer,fault,change,true);}
fn route_transport(journal:&mut Journal,worker:&mut Ordinary,binding:&Binding,node:&HybridKey,
    work:&WorkContext,epoch:u64,signed_offer:Option<(&[u8],[u8;32],u64)>,fault:u32,mut change:Option<&mut dyn FnMut()>,socket:bool)
{
    assert_eq!(work.license,binding.license);assert_eq!(work.worker,binding.worker_id);
    assert_eq!(work.assignment_sequence,binding.assignment_generation);
    let height=work.parent_height+1;assert!(height>binding.valid_until_height);
    eprintln!("PUBLIC runtime stage: begin fault={fault} height={height} epoch={epoch}");
    *worker.context=context(binding);worker.platform.now=0;worker.platform.step=0;
    let mut base=local(&worker.local);base.public=std::ptr::null();
    let a=Box::new(JournalLocal{base,journal:&*journal.backend,authority:&*journal.authority});
    let expected=HostContext::pinned(binding,node.public(),1).unwrap().id();
    let pinned=PinnedWork{genesis:work.genesis,fingerprint:work.fingerprint,parent:work.parent,license:work.license,
        worker:work.worker,coordinator:work.coordinator,target:work.target,height,genesis_timestamp:work.t0,
        assignment:work.assignment_sequence,last_ticket:work.last_accepted_ticket};
    let records=journal.records();let markers=journal.rows.markers.clone();
    // Owner closes the connection using pending: drop Owner before freeing Pending.
    let mut pending=Pending::new();let mut owner=Owner::new();
    assert_eq!(unsafe{build8_qual_journal_owner_init(owner.ptr(),&*a,pending.ptr(),build8_worker_pending_v2_size(),&pinned,expected.as_ptr(),height,epoch)},1);
    if socket{
        #[cfg(target_os="linux")] owner.attach_socket();
        #[cfg(not(target_os="linux"))] panic!("POSIX socket route is Linux-only");
    }
    eprintln!("PUBLIC runtime stage: native init passed; flushing hello");
    let hello=owner.flush(1722);
    eprintln!("PUBLIC runtime stage: hello complete; NodePending accept");
    let (peer,response)=NodePending::accept(HostContext::pinned(binding,node.public(),1).unwrap(),node,&hello).unwrap();
    eprintln!("PUBLIC runtime stage: Node response ready; C stream response/finish");
    owner.input(&response);
    let mut finish=Vec::new();for _ in 0..40 {assert_ne!(owner.step().0,0);finish.extend(owner.output());if finish.len()==130{break;}assert!(finish.len()<130);}
    assert_eq!(finish.len(),130);
    eprintln!("PUBLIC runtime stage: C finish complete; Node finish");
    let (peer,tag)=peer.finish(&finish).unwrap();
    eprintln!("PUBLIC runtime stage: Node finish passed");
    let authority=Authority{binding,node:node.public(),node_generation:1,height,epoch};
    let mut peer=peer.into_channel(&authority).unwrap();
    let frame=peer.seal(&authority,b"actual journal stream").unwrap();
    owner.input(&[tag.as_slice(),frame.as_slice()].concat());
    let mut confirmed=false;let mut received=false;
    for _ in 0..40 {
        let(e,plain)=owner.step();assert_ne!(e,0);
        if e==3 {eprintln!("PUBLIC runtime stage: both-Finished event; runtime confirm");assert!(!confirmed);assert_eq!(unsafe{build8_qual_journal_owner_confirm(owner.ptr())},1);confirmed=true;}
        if e==4 {assert!(confirmed);assert_eq!(plain,b"actual journal stream");received=true;break;}
    }
    assert!(confirmed&&received);assert!(pending.cleared());
    eprintln!("PUBLIC runtime stage: confirmed plus authenticated frame received");
    if fault==1 || fault==2 {
        if fault==1 {assert_eq!(unsafe{build8_qual_journal_owner_send(owner.ptr(),b"must not leave".as_ptr(),14)},2);}
        else {let frame=peer.seal(&authority,b"must not be exposed").unwrap();owner.input(&frame);}
        journal.policy.active_deny_at=Some(journal.policy.active_calls+1);
        assert_eq!(owner.step(),(0,Vec::new()));assert!(owner.output().is_empty());owner.closed();
        assert_eq!(unsafe{build8_qual_journal_owner_flags(owner.ptr())},1);
    } else if fault==3 {
        owner.input(&[255;64]);assert_eq!(owner.step().0,0);owner.closed();
    } else if fault==4 {
        unsafe{build8_qual_journal_owner_fault(owner.ptr(),3)};assert_eq!(owner.step().0,0);owner.closed();
    } else if fault==5 {
        assert_eq!(unsafe{build8_qual_journal_owner_legacy_bypass(owner.ptr())},0);
        assert_eq!(unsafe{build8_qual_journal_owner_request(owner.ptr(),[9;32].as_ptr())},0);owner.closed();
    } else if fault==6 {
        assert_eq!(unsafe{build8_qual_journal_owner_send(owner.ptr(),b"must not leave".as_ptr(),14)},2);
        eprintln!("PUBLIC runtime stage: queued frame; own-chain change starts");
        change.as_mut().expect("actual own-chain change callback")();
        eprintln!("PUBLIC runtime stage: own-chain change completed; refusal step");
        assert_eq!(owner.step(),(0,Vec::new()));assert!(owner.output().is_empty());owner.closed();
        assert_eq!(unsafe{build8_qual_journal_owner_flags(owner.ptr())},1);
    } else if fault==7 || fault==8 {
        let (offer,_,_)=signed_offer.expect("a representable genuinely signed work fixture");
        let mut decoded=mutiny_consensus_v8::work_authority_v2::Authority::decode(&offer[52..]).unwrap();
        if fault==7 {decoded.signature.ed448[0]^=1;}else{decoded.signature.fndsa[0]^=1;}
        let encoded=decoded.encode().unwrap();
        assert_eq!(mutiny_consensus_v8::work_authority_v2::Authority::decode(&encoded).unwrap(),decoded);
        let header=mutiny_consensus_v8::pow::WorkHeader{candidate:decoded.work.candidate.clone(),authority:decoded.id().unwrap(),nonce:7};
        assert!(decoded.verify(&header,work,&worker.descriptor).is_err());
        let mut bad=offer[..50].to_vec();bad.extend_from_slice(&(encoded.len() as u16).to_be_bytes());bad.extend_from_slice(&encoded);
        assert_eq!(unsafe{build8_qual_journal_owner_request(owner.ptr(),[9;32].as_ptr())},1);
        let frame=peer.seal(&authority,&bad).unwrap();owner.input(&frame);let plain=owner.message();assert_eq!(plain,bad);
        assert_eq!(unsafe{build8_qual_journal_owner_offer(owner.ptr(),plain.as_ptr(),plain.len())},0);
        assert_eq!(unsafe{build8_qual_journal_owner_ticket(owner.ptr())},work.last_accepted_ticket);owner.closed();
    } else if fault==9 {
        unsafe{build8_qual_journal_owner_maintenance(owner.ptr())};assert_eq!(owner.step().0,0);owner.closed();
    } else if fault==10 {
        unsafe{build8_qual_journal_owner_accounting(owner.ptr())};
        assert_eq!(unsafe{build8_qual_journal_owner_request(owner.ptr(),[9;32].as_ptr())},0);owner.closed();
        assert_eq!(unsafe{build8_qual_journal_owner_flags(owner.ptr())},3); // RUN + preserved pending accounting
    } else if fault==11 {
        worker.platform.now=1;assert_ne!(owner.step().0,0);
        worker.platform.now=0;assert_eq!(owner.step().0,0);owner.closed();
    } else {
        let public=b"guarded journal return";
        assert_eq!(unsafe{build8_qual_journal_owner_send(owner.ptr(),public.as_ptr(),public.len())},2);
        // Existing frame overhead is 60 bytes; this is the actual C stream's
        // byte output, not a direct b8_worker_seal bypass.
        eprintln!("PUBLIC runtime stage: C return frame queued; actual stream flush");
        let wire=owner.flush(public.len()+60);assert_eq!(peer.open(&authority,&wire).unwrap(),public);
        eprintln!("PUBLIC runtime stage: C return frame verified by Rust Node");
        if let Some((offer,id,ticket))=signed_offer {
            eprintln!("PUBLIC runtime stage: valid work request starts");
            assert_eq!(unsafe{build8_qual_journal_owner_request(owner.ptr(),[9;32].as_ptr())},1);
            eprintln!("PUBLIC runtime stage: work request accepted; Node seals work offer");
            let frame=peer.seal(&authority,offer).unwrap();owner.input(&frame);let plain=owner.message();assert_eq!(plain,offer);
            eprintln!("PUBLIC runtime stage: authenticated work offer plaintext returned; C offer verification");
            assert_eq!(unsafe{build8_qual_journal_owner_offer(owner.ptr(),plain.as_ptr(),plain.len())},1);
            eprintln!("PUBLIC runtime stage: C valid work offer accepted");
            assert_eq!(unsafe{build8_qual_journal_owner_ticket(owner.ptr())},ticket);
            eprintln!("PUBLIC runtime stage: first inclusive nonce");
            let mut nonce=99;assert_eq!(unsafe{build8_qual_journal_owner_nonce(owner.ptr(),&mut nonce)},1);assert_eq!(nonce,7);
            eprintln!("PUBLIC runtime stage: first nonce authorized; second inclusive nonce");
            assert_eq!(unsafe{build8_qual_journal_owner_nonce(owner.ptr(),&mut nonce)},1);assert_eq!(nonce,8);
            eprintln!("PUBLIC runtime stage: second nonce authorized; found handoff");
            assert_eq!(unsafe{build8_qual_journal_owner_found(owner.ptr(),id.as_ptr(),nonce)},1);
            eprintln!("PUBLIC runtime stage: found handoff authorized");
            assert_eq!(unsafe{build8_qual_journal_owner_flags(owner.ptr())},7);
        }
    }
    assert_eq!(journal.records(),records);assert_eq!(journal.rows.markers,markers);worker.assert_birth_unchanged();
    if socket{
        #[cfg(target_os="linux")] owner.socket_retirement();
    }
    eprintln!("PUBLIC runtime stage: journal rows/markers and birth unchanged; dropping native owner");
}

#[test]
fn actual_journal_stream_provider_frame_clock_and_mode_failures_retire_without_birth_writes(){
    for fault in [0,1,2,3,4,5,7,8,9,10,11] {
        let(mut worker,_,node,a)=component();let mut journal=Journal::model(&worker,2);
        assert_eq!(journal.put(&a).0,STORED);journal.policy.active_raw=Some(a.encode().unwrap());assert_eq!(journal.activate(&a,4,2),ACTIVE);
        let work=WorkContext{genesis:a.enrollment.binding.genesis,fingerprint:a.enrollment.binding.fingerprint,
            parent:[4;32],parent_height:3,t0:1000,target:[255;32],license:a.enrollment.binding.license,worker:a.enrollment.binding.worker_id,
            coordinator:a.enrollment.binding.coordinator,assignment_sequence:a.enrollment.binding.assignment_generation,
            last_accepted_ticket:0,ancestor_timestamps:vec![1000,1001,1002,1003]};
        let mut signed=mutiny_consensus_v8::work_authority_v2::Authority{
            work:mutiny_consensus_v8::pow::WorkAuthority{candidate:mutiny_consensus_v8::pow::Candidate{
                network:mutiny_consensus_v8::NETWORK_ID,genesis:work.genesis,fingerprint:work.fingerprint,parent:work.parent,
                height:work.parent_height+1,timestamp:1120,body_root:[5;32],state_root:[6;32],license:work.license,worker:work.worker,target:work.target},
                assignment_sequence:work.assignment_sequence,ticket_sequence:1,coordinator:work.coordinator,nonce_start:7,nonce_end:8,epoch:2},
            node_descriptor:worker.descriptor.clone(),signature:mutiny_crypto_v2::HybridSignature{ed448:[0;114],fndsa:[0;1280]}};
        signed.sign(&node).unwrap();let id=signed.id().unwrap();
        let header=mutiny_consensus_v8::pow::WorkHeader{candidate:signed.work.candidate.clone(),authority:id,nonce:7};
        signed.verify(&header,&work,&worker.descriptor).unwrap();let raw=signed.encode().unwrap();
        let mut offer=vec![5,2];offer.extend_from_slice(&[9;32]);offer.extend_from_slice(&2u64.to_be_bytes());
        offer.extend_from_slice(&1000u64.to_be_bytes());offer.extend_from_slice(&(raw.len() as u16).to_be_bytes());offer.extend_from_slice(&raw);
        route(&mut journal,&mut worker,&a.enrollment.binding,&node,&work,2,Some((&offer,id,1)),fault,None);
    }
}
