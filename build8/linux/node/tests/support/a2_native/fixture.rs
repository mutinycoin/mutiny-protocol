//! Genuine signed-Genesis TEST input consumed without enabling wallet custody
//! in the Node shipping graph. The separate fixture generator must establish
//! Genesis; this consumer never invents a membership or caller-Applied flag.
use mutiny_consensus_v8::{
    Hash, anchors::FinalizedAnchor, block_envelope_v2::BlockEnvelope,
    canonical_store_v2::CanonicalStore, execution::State, mempool_v2::Mempool,
    endorsement_revocation_v1::{self as withdrawal, Evidence, Operation, Target, TargetClass, TargetScope},
    pow::{WorkAuthority, WorkHeader}, work_authority_v2::Authority,
};
use mutiny_crypto_v2::{HybridKey, HybridSignature, Role};
use mutinyd_v8::{hybrid_runtime_v2::{HybridRuntime as NativeRuntime, WorkRequest}, node_custody_v2::EncryptedNodeKey};
use std::path::{Path, PathBuf};

/// Integration TEST ownership only. Both native store handles open the exact
/// same pinned SQLite file. No production Runtime field or API is exposed.
/// The independent public store drives full canonical commit/replay assertions;
/// ordinary pool, journal, prepare and transport calls still use NativeRuntime.
pub struct HybridRuntime {
    native: NativeRuntime,
    pub chain: CanonicalStore,
}
impl std::ops::Deref for HybridRuntime {
    type Target = NativeRuntime;
    fn deref(&self) -> &Self::Target { &self.native }
}
impl std::ops::DerefMut for HybridRuntime {
    fn deref_mut(&mut self) -> &mut Self::Target { &mut self.native }
}

pub const PASSWORD: &str = "PUBLIC TEST VALUE A2 ONLY";
pub const T_REF: u64 = 1_800_000_000;
pub fn public_clock() -> u64 { T_REF + 60 }
pub fn zero() -> HybridSignature { HybridSignature { ed448:[0;114], fndsa:[0;1280] } }
pub fn label(name: &str) -> Hash {
    mutiny_consensus_v8::domain_hash(b"MUTINY-BUILD8-PUBLIC-A2-NODE-LIFECYCLE-TEST-V1",name.as_bytes())
}
pub fn private_root(label: &str) -> PathBuf {
    let mut random=[0;16];mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
    let root=std::env::temp_dir().join(format!("build8-public-a2-{label}-{}",hex::encode(random)));
    assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&root).unwrap());
    eprintln!("RETAINED_PUBLIC_A2_SOFTWARE_TEST_EVIDENCE={}",root.display());
    root // No Drop cleanup: all positive, failed and partial artifacts remain.
}
pub struct Fixture {
    pub state:State, pub parent:FinalizedAnchor, pub root:Hash,
    pub node:Hash, pub license:Hash, pub worker:Hash,
    pub unused_roots:Vec<Vec<u8>>, pub node_encrypted:Vec<u8>,
    pub continuity:HybridKey, transport_a:Vec<u8>, transport_b:Vec<u8>,
    terminal_operation:Option<Vec<u8>>,
}
impl Fixture {
    pub fn load() -> Self {
        Self::load_env("BUILD8_A2_LOCAL_SOFTWARE_FIXTURE")
    }
    /// A separately generated, launch-frozen protected local TEST Genesis. This
    /// never creates or retags an anchor from the first fixture's state.
    pub fn load_foreign() -> Self {
        Self::load_env("BUILD8_A2_LOCAL_SOFTWARE_FOREIGN_FIXTURE")
    }
    /// Dedicated mandatory input: genuine signed five-cert/four-CRL fixture,
    /// separately generated before native Genesis freeze. No absent-input PASS.
    pub fn load_genuine_terminal() -> Self {
        Self::load_env("BUILD8_A2_LOCAL_SOFTWARE_GENUINE_FIXTURE")
    }
    fn load_env(name:&str) -> Self {
        let input=std::env::var_os(name)
            .expect("required protected local A2 software fixture input is missing; no runtime PASS");
        let input=PathBuf::from(input);
        assert!(input.is_absolute() && input.components().all(|c|!matches!(c,std::path::Component::ParentDir|std::path::Component::CurDir)));
        #[cfg(windows)] {
            let profile=PathBuf::from(std::env::var_os("USERPROFILE").expect("current user profile required"));
            assert!(matches!(input.components().next(),Some(std::path::Component::Prefix(p))
                if matches!(p.kind(),std::path::Prefix::Disk(b'C')|std::path::Prefix::Disk(b'c')|std::path::Prefix::VerbatimDisk(b'C')|std::path::Prefix::VerbatimDisk(b'c'))));
            assert_eq!(input.file_name(),Some(std::ffi::OsStr::new("fixture.json")));
            let directory=input.parent().unwrap();
            assert_eq!(std::fs::canonicalize(directory.parent().unwrap()).unwrap(),std::fs::canonicalize(profile).unwrap());
            assert!(directory.file_name().and_then(|p|p.to_str()).is_some_and(|p|p.starts_with("MutinyBuild8-A2-LocalSynthetic-")));
        }
        let metadata=std::fs::symlink_metadata(&input).unwrap();
        assert!(metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len()>0 && metadata.len()<=2*1024*1024);
        let canonical=std::fs::canonicalize(&input).unwrap();
        // Windows canonicalize adds the verbatim prefix. Compare the actual
        // parent identity instead of falsely requiring callers to spell it.
        assert_eq!(std::fs::canonicalize(input.parent().unwrap()).unwrap(),canonical.parent().unwrap());
        // Read-only validate the existing protected leaf/ancestors; do not chmod,
        // migrate or create a fixture file. Root's reviewed launch preflight also
        // checks this exact file's owner/DACL and no hardlink before the freeze.
        assert!(!mutiny_consensus_v8::submission_pool_v1::private_directory(input.parent().unwrap()).unwrap());
        let bytes=std::fs::read(&input).unwrap();assert!(bytes.len()<=2*1024*1024);
        let v:serde_json::Value=serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v["schema"],"MUTINY-BUILD8-PUBLIC-A2-NATIVE-LIFECYCLE-V1");
        assert_eq!(v["synthetic_only"],true);assert_eq!(v["production_authorized"],false);
        assert_eq!(v["t0"],T_REF);
        if name=="BUILD8_A2_LOCAL_SOFTWARE_GENUINE_FIXTURE" {
            assert_eq!(v["software_variant"],"GENUINE_TERMINAL_PKI_V1");
            assert!(v.get("terminal_operation").is_some());
        }
        let raw=|v:&serde_json::Value|hex::decode(v.as_str().unwrap()).unwrap();
        let root:Hash=raw(&v["root"]).try_into().unwrap();
        let rows:Vec<_>=v["records"].as_array().unwrap().iter()
            .map(|r|(raw(&r["key"]).try_into().unwrap(),raw(&r["record"]))).collect();
        let state=State::from_records(&rows,root).unwrap();
        let parent=FinalizedAnchor::decode(&raw(&v["genesis"])).unwrap();assert_eq!(parent.height,0);
        let node:Hash=raw(&v["node"]).try_into().unwrap();
        let license=state.licenses_v2.licenses().next().unwrap();
        let worker=license.active_worker.expect("required genuine active Genesis Worker");
        let assignment=state.licenses_v2.active(license.id,worker,0).unwrap().1.assignment.enrollment.binding.clone();
        let context=mutiny_consensus_v8::domain_hash(b"MUTINY-BUILD8-PUBLIC-A2-CONTINUITY-FIXTURE-V1",&parent.genesis);
        let (continuity,generation)=HybridKey::open_for(Role::Continuity,PASSWORD,&context,&raw(&v["continuity_encrypted"])).unwrap();
        assert_eq!(generation,1);
        let unused_roots=v["unused_root_certificates"].as_array().unwrap().iter().map(raw).collect::<Vec<_>>();
        assert_eq!(unused_roots.len(),2);
        Self {state,parent,root,node,license:assignment.license,worker:assignment.worker_id,
            unused_roots,node_encrypted:raw(&v["node_encrypted"]),continuity,
            transport_a:raw(&v["transport_a_encrypted"]),transport_b:raw(&v["transport_b_encrypted"]),
            terminal_operation:v.get("terminal_operation").map(raw)}
    }
    pub fn genuine_terminal_operation(&self) -> Vec<u8> {
        let raw=self.terminal_operation.as_ref().expect("required genuine public operation is missing");
        assert!((151201..=151785).contains(&raw.len()),"genuine fixture did not attain a second window");
        let op=Operation::decode(raw).unwrap();assert_eq!(op.encode().unwrap(),*raw);
        assert_eq!(op.context,withdrawal::Context {genesis:self.parent.genesis,fingerprint:self.parent.fingerprint,
            parent_height:0,parent_block:self.parent.block,parent_state:self.root,height:1,timestamp:T_REF+60});
        assert_eq!(self.parent.height,0);
        let Evidence::Crl {target_certificate,signer_chain,crls}=&op.evidence else {panic!("genuine CRL evidence required")};
        assert_eq!(signer_chain.len(),4);assert_eq!(crls.len(),4);
        assert!(std::iter::once(target_certificate).chain(signer_chain.iter()).all(|c|!c.is_empty() && c.len()<=4096));
        assert!(crls.iter().all(|c|(32700..=32768).contains(&c.len())));
        assert_eq!(op.target,Target {class:TargetClass::Ek,scope:TargetScope::Certificate,identity:sha(target_certificate)});
        // These are structural/context requirements. Native full execution in
        // each parent TEST authenticates every used issuer/signature/CRL policy.
        raw.clone()
    }
    pub fn runtime(&self,root:&Path) -> HybridRuntime {
        let chain=CanonicalStore::open_trusted_genesis(&root.join("canonical.sqlite"),&self.parent,&self.state,
            self.root,T_REF,[255;32]).unwrap();
        let pool=Mempool::open(&root.join("mempool.sqlite"),self.parent.genesis,self.parent.fingerprint,64*1024*1024).unwrap();
        let native=NativeRuntime::from_pinned_chain_with_clock(chain,pool,public_clock).unwrap();
        let chain=CanonicalStore::open_trusted_genesis(&root.join("canonical.sqlite"),&self.parent,&self.state,
            self.root,T_REF,[255;32]).unwrap();
        let runtime=HybridRuntime { native, chain };
        assert!(runtime.chain.body_capacity(&runtime.head().unwrap()).unwrap().allows_a2());
        runtime
    }
    pub fn node_key(&self,runtime:&HybridRuntime) -> HybridKey {
        let pins=runtime.chain.current_node_authority(&runtime.head().unwrap(),self.node).unwrap();
        let (key,generation)=HybridKey::open_for(Role::Node,PASSWORD,&pins.context(),&self.node_encrypted).unwrap();
        assert_eq!(key.public().descriptor(generation).unwrap(),pins.descriptor());key
    }
    pub fn install(&self,runtime:&mut HybridRuntime,envelope:&BlockEnvelope) {
        let capacity=runtime.chain.proposal_body_capacity(&envelope.header).unwrap();
        let bytes=envelope.encode_with_capacity(&capacity).unwrap();
        let installation=runtime.install(&bytes).unwrap();
        assert!(installation.inserted);
        assert!(matches!(installation.pending,mutinyd_v8::hybrid_runtime_v2::PendingCache::Reconciled));
        assert_eq!(runtime.head().unwrap(),installation.finalized);
    }
    pub fn custody(&self,runtime:&HybridRuntime) -> EncryptedNodeKey {
        EncryptedNodeKey::unlock(&runtime.chain,&runtime.head().unwrap(),self.node,&self.node_encrypted,PASSWORD).unwrap()
    }
    pub fn transport_keys(&self) -> (HybridKey,HybridKey) {
        let context=mutiny_consensus_v8::domain_hash(b"MUTINY-BUILD8-PUBLIC-A2-TRANSPORT-FIXTURE-V1",&self.parent.genesis);
        let open=|raw:&[u8]| { let (key,generation)=HybridKey::open_for(Role::Transport,PASSWORD,&context,raw).unwrap();assert_eq!(generation,1);key };
        (open(&self.transport_a),open(&self.transport_b))
    }
    pub fn judgment(&self,runtime:&HybridRuntime,unused:usize,timestamp:u64,large:bool) -> Vec<u8> {
        let parent=runtime.head().unwrap();let (_,state)=runtime.chain.load().unwrap();
        let certificate=self.unused_roots[unused].clone();
        let reason=if large {vec![b'P';withdrawal::MAX_REASON_BYTES]} else {b"PUBLIC software TEST unused frozen-root judgment".to_vec()};
        let mut evidence=vec![certificate.clone()];
        if large {
            evidence.push(vec![b'T';withdrawal::MAX_JUDGMENT_BYTES-certificate.len()]);
            assert_eq!(evidence.iter().map(Vec::len).sum::<usize>(),withdrawal::MAX_JUDGMENT_BYTES);
        }
        let op=Operation {context:withdrawal::Context {genesis:parent.genesis,fingerprint:parent.fingerprint,
            parent_height:parent.height,parent_block:parent.block,parent_state:state.root().unwrap(),height:parent.height+1,timestamp},
            target:Target {class:TargetClass::Root,scope:TargetScope::Certificate,identity:sha(&certificate)},
            evidence:Evidence::Judgment {reason,evidence}};
        let raw=op.encode().unwrap();assert_eq!(Operation::decode(&raw).unwrap(),op);
        assert!(raw.len()<=withdrawal::MAX_OPERATION_BYTES);
        if large {assert!(raw.len()>mutiny_consensus_v8::body_capacity_v3::MAX_LEGACY_BODY_BYTES);}
        raw
    }
    /// Complete native candidate preparation and both-required Node signature.
    /// Parent certificate remains separate; this creates no local finality.
    pub fn candidate(&self,runtime:&mut HybridRuntime,raw:&[u8],timestamp:u64,ticket:u64) -> mutinyd_v8::candidate_journal_v3::Record {
        let parent=runtime.head().unwrap();let operations=vec![raw.to_vec()];
        let context=runtime.chain.current_work_context(&parent,self.license,self.worker,timestamp).unwrap().0;
        let prepared=runtime.prepare(WorkRequest {expected_parent:&parent,license:self.license,worker:self.worker,timestamp,ticket,operations:&operations}).unwrap();
        assert_eq!(prepared.body.operations,operations);
        let key=self.node_key(runtime);
        let mut authority=Authority {work:WorkAuthority {candidate:prepared.candidate,assignment_sequence:context.assignment_sequence,
            ticket_sequence:ticket,coordinator:context.coordinator,nonce_start:0,nonce_end:100,
            epoch:mutiny_consensus_v8::pow::mining_epoch(timestamp,T_REF).unwrap()},node_descriptor:key.public().descriptor(1).unwrap(),signature:zero()};
        authority.sign(&key).unwrap();
        let header=WorkHeader {candidate:authority.work.candidate.clone(),authority:authority.id().unwrap(),nonce:1};
        runtime.chain.validate_observation_v2(&header,&authority,&prepared.body).unwrap();
        mutinyd_v8::candidate_journal_v3::Record {header,authority,body:prepared.body}
    }
    pub fn certify(&self,runtime:&HybridRuntime,record:&mutinyd_v8::candidate_journal_v3::Record) -> BlockEnvelope {
        let parent=runtime.head().unwrap();let authority=runtime.chain.current_authority(&parent).unwrap();
        let voter=&authority.voters[&self.node];assert!(!voter.weight().unwrap().is_zero());
        let decision=mutiny_consensus_v8::certificates::Decision {network:parent.network,genesis:parent.genesis,fingerprint:parent.fingerprint,
            purpose:2,height:parent.height+1,mining_epoch:record.authority.work.epoch,continuity_period:parent.height/60,round:0,step:3,
            previous_finalized_anchor:parent.id(),parent:parent.block,block:record.header.block_hash(),state:record.header.candidate.state_root,
            membership:authority.membership,reputation:authority.reputation,attestation:authority.attestation};
        let mut vote=mutiny_consensus_v8::continuity_v2::Vote {decision:decision.clone(),nil:false,node:self.node,
            hardware_generation:voter.hardware_generation,key_generation:voter.key_generation,sequence:parent.height+1,
            tpm_identity:voter.tpm_identity(),profile:voter.profile,signature:zero()};
        vote.sign(&self.continuity).unwrap();
        let certificate=mutiny_consensus_v8::continuity_v2::Certificate {decision:decision.clone(),votes:vec![vote]};
        certificate.verify_quorum(&decision,&parent,&authority.voters).unwrap();
        BlockEnvelope {header:record.header.clone(),body:record.body.clone(),authority:record.authority.clone(),certificate}
    }
}
pub fn sha(raw:&[u8]) -> Hash {use sha2::{Digest,Sha256};Sha256::digest(raw).into()}
pub fn exact_index(runtime:&HybridRuntime,raw:&[u8],envelope:&BlockEnvelope) {
    let cap=runtime.chain.proposal_body_capacity(&envelope.header).unwrap();
    let (kind,id)=cap.operation_id(raw).unwrap();assert_eq!(kind,25);
    let records=runtime.chain.verified_operation_records(id).unwrap();assert_eq!(records.len(),1);
    let record=&records[0];assert_eq!(record.kind,25);assert_eq!(record.list,1);assert_eq!(record.position,0);
    assert_eq!(record.height,envelope.body.height);assert_eq!(record.block,envelope.block_hash());
    assert_eq!(record.wire,mutiny_consensus_v8::domain_hash(mutiny_consensus_v8::operation_index_v2::WIRE_DOMAIN,raw));
    record.verify_in_block_with_capacity(&envelope.body,envelope.block_hash(),&cap).unwrap();
    let bytes=envelope.encode_with_capacity(&cap).unwrap();
    assert_eq!(runtime.chain.certified_envelope_bytes(record.height,record.block).unwrap(),Some(bytes.clone()));
    let decoded=BlockEnvelope::decode_with_capacity(&bytes,&cap).unwrap();assert_eq!(decoded.body.operations[0],raw);
    assert!(runtime.chain.certified_envelope_bytes(record.height,label("wrong-block")).is_err());
}

// Public integration TEST capture only. This grants no key/admission authority.
// Thread resources and both CreateNew output files precede child launch. Every
// owned stream is drained concurrently before natural wait, including log errors.
pub fn capture_handoff_child(root:&Path,name:&str,path_variable:&str,expected:i32,prefix:&str) {
    use std::{io::{Read,Write},process::{Command,Stdio},sync::{Arc,Mutex,Condvar},thread};
    #[cfg(target_os="linux")]
    use sha2::{Digest,Sha256};
    use super::process_output::drain;
    #[cfg(windows)]
    fn identity(child:&std::process::Child)->std::io::Result<serde_json::Value> {
        use std::os::windows::io::AsRawHandle;
        #[repr(C)] #[derive(Default)] struct FileTime {low:u32,high:u32}
        #[link(name="kernel32")]
        unsafe extern "system" {
            fn GetProcessId(handle:*mut std::ffi::c_void)->u32;
            fn GetProcessTimes(handle:*mut std::ffi::c_void,c:*mut FileTime,e:*mut FileTime,k:*mut FileTime,u:*mut FileTime)->i32;
            fn QueryFullProcessImageNameW(handle:*mut std::ffi::c_void,flags:u32,out:*mut u16,count:*mut u32)->i32;
        }
        let handle=child.as_raw_handle();let pid=unsafe{GetProcessId(handle)};
        if pid==0 || pid!=child.id(){return Err(std::io::Error::last_os_error());}
        let(mut c,mut e,mut k,mut u)=(FileTime::default(),FileTime::default(),FileTime::default(),FileTime::default());
        if unsafe{GetProcessTimes(handle,&mut c,&mut e,&mut k,&mut u)}==0{return Err(std::io::Error::last_os_error());}
        let mut image=[0u16;32768];let mut count=image.len() as u32;
        if unsafe{QueryFullProcessImageNameW(handle,0,image.as_mut_ptr(),&mut count)}==0 || count==0 || count>=image.len() as u32 {
            return Err(std::io::Error::last_os_error());
        }
        let image=String::from_utf16(&image[..count as usize]).map_err(|_|std::io::Error::other("invalid native image UTF16"))?;
        Ok(serde_json::json!({"pid":pid,"start_filetime":((c.high as u64)<<32)|c.low as u64,"image":image,
            "source":"retained owned Child handle, never PID lookup or fast-exit tuple"}))
    }
    #[cfg(target_os="linux")]
    fn identity(child: &std::process::Child)->std::io::Result<serde_json::Value> {
        use std::{io::Read,os::unix::fs::MetadataExt};
        fn refusal()->std::io::Error {std::io::Error::other("owned Linux child identity/context refused")}
        let pid=child.id();if pid==0 {return Err(refusal());}
        let proc=std::path::PathBuf::from(format!("/proc/{pid}"));
        let mut stat=std::fs::File::open(proc.join("stat"))?;
        if stat.metadata()?.uid()!=unsafe{libc::geteuid()} {return Err(refusal());}
        let mut raw=Vec::new();Read::by_ref(&mut stat).take(4097).read_to_end(&mut raw)?;
        if raw.is_empty() || raw.len()>4096 {return Err(refusal());}
        let raw=std::str::from_utf8(&raw).map_err(|_|refusal())?;
        let left=raw.find('(').ok_or_else(refusal)?;
        let right=raw.rfind(')').ok_or_else(refusal)?;
        if left>=right || raw[..left].trim().parse::<u32>().ok()!=Some(pid) {return Err(refusal());}
        // Fields following comm start at state(3); starttime is field22.
        let fields:Vec<_>=raw[right+1..].split_ascii_whitespace().collect();
        let ticks=fields.get(19).and_then(|s|s.parse::<u64>().ok()).filter(|n|*n>0).ok_or_else(refusal)?;
        let mut boot=String::new();
        std::fs::File::open("/proc/sys/kernel/random/boot_id")?.take(42).read_to_string(&mut boot)?;
        let boot=boot.trim();
        if boot.len()!=36 || !boot.bytes().all(|b|b.is_ascii_hexdigit()||b==b'-') {return Err(refusal());}
        let own=std::fs::File::open(std::env::current_exe()?)?;
        let mut image=std::fs::File::open(proc.join("exe"))?;
        let a=own.metadata()?;let b=image.metadata()?;
        if !a.is_file() || !b.is_file() || a.dev()!=b.dev() || a.ino()!=b.ino()
            || a.len()!=b.len() || a.len()==0 || a.len()>512*1024*1024 {return Err(refusal());}
        let name=std::fs::read_link(proc.join("exe"))?;
        if name!=std::fs::canonicalize(std::env::current_exe()?)? {return Err(refusal());}
        let mut bytes=Vec::new();Read::by_ref(&mut image).take(a.len()+1).read_to_end(&mut bytes)?;
        if bytes.len() as u64!=a.len() {return Err(refusal());}
        let after=image.metadata()?;
        if b.dev()!=after.dev()||b.ino()!=after.ino()||b.len()!=after.len()
            ||b.mtime()!=after.mtime()||b.mtime_nsec()!=after.mtime_nsec() {return Err(refusal());}
        Ok(serde_json::json!({"pid":pid,"start_ticks":ticks,"boot_id":boot,
            "image":name,"image_sha256":hex::encode(Sha256::digest(&bytes)),
            "source":"owned Child PID, bounded retained proc stat and matching held executable; no exited-PID fallback"}))
    }
    #[cfg(not(any(windows,target_os="linux")))]
    fn identity(_: &std::process::Child)->std::io::Result<serde_json::Value> {
        Err(std::io::Error::other("unsupported qualification child observer; no unsupported PASS"))
    }
    assert!(matches!(expected,93|94));assert!(prefix.chars().all(|c|c.is_ascii_alphanumeric()||c=='-'));
    assert!(root.is_absolute());let exe=std::env::current_exe().unwrap();let image_before=sha(&std::fs::read(&exe).unwrap());
    let output=std::fs::OpenOptions::new().create_new(true).write(true).open(root.join(format!("{prefix}.stdout"))).unwrap();
    let error=std::fs::OpenOptions::new().create_new(true).write(true).open(root.join(format!("{prefix}.stderr"))).unwrap();
    type Slot<T> = Arc<(Mutex<Option<Option<T>>>,Condvar)>;
    fn reader<T:Read+Send+'static>(slot:Slot<T>,file:std::fs::File,name:&str)->std::io::Result<thread::JoinHandle<serde_json::Value>> {
        thread::Builder::new().name(name.into()).spawn(move||{
            let (lock,wake)=&*slot;
            let mut value=lock.lock().unwrap_or_else(|p|p.into_inner());
            while value.is_none(){value=wake.wait(value).unwrap_or_else(|p|p.into_inner());}
            let pipe=value.take().unwrap();drop(value);
            pipe.map(|p|drain(p,file)).unwrap_or(serde_json::Value::Null)
        })
    }
    fn transfer<T>(slot:&Slot<T>,pipe:Option<T>){
        let (lock,wake)=&**slot;*lock.lock().unwrap_or_else(|p|p.into_inner())=Some(pipe);wake.notify_one();
    }
    // Both resources exist before launch; transfer has no channel/receiver error
    // path and no receipt operation intervenes between the two transfers.
    let out_slot:Slot<std::process::ChildStdout>=Arc::new((Mutex::new(None),Condvar::new()));
    let err_slot:Slot<std::process::ChildStderr>=Arc::new((Mutex::new(None),Condvar::new()));
    let out_thread=reader(out_slot.clone(),output,"public-a2-child-stdout").unwrap();
    let err_thread=match reader(err_slot.clone(),error,"public-a2-child-stderr") {
        Ok(t)=>t,Err(e)=>{transfer(&out_slot,None);let _=out_thread.join();panic!("prelaunch drain thread unavailable: {e}");}
    };
    let argv=["--exact",name,"--test-threads=1","--nocapture"];
    let started=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos().to_string();
    let mut child=match Command::new(&exe).args(argv).env(path_variable,root).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(c)=>c,Err(e)=>{transfer(&out_slot,None);transfer(&err_slot,None);let _=out_thread.join();let _=err_thread.join();panic!("child launch refused: {e}");}
    };
    let out=child.stdout.take();let err=child.stderr.take();let pipes_present=out.is_some() && err.is_some();
    transfer(&out_slot,out);transfer(&err_slot,err);
    let observed=identity(&child).map_err(|e|format!("native child identity refused: {e}"));
    let stdout=out_thread.join().ok();let stderr=err_thread.join().ok();
    let exit=loop{match child.wait(){Err(ref e) if e.kind()==std::io::ErrorKind::Interrupted=>continue,r=>break r}};
    let image_after=sha(&std::fs::read(&exe).unwrap());
    let exact_image=observed.as_ref().ok().and_then(|r|r["image"].as_str()).is_some_and(|p|{
        match(std::fs::canonicalize(p),std::fs::canonicalize(&exe)){
            (Ok(a),Ok(b))=>a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy()),_=>false
        }
    });
    let drained=|v:&Option<serde_json::Value>|v.as_ref().is_some_and(|r|r["eof"]==true && r["limit_exceeded"]==false && r["errors"].as_array().is_some_and(Vec::is_empty));
    let ok=pipes_present && observed.is_ok() && exact_image && image_before==image_after && drained(&stdout) && drained(&stderr)
        && exit.as_ref().ok().and_then(|s|s.code())==Some(expected);
    let receipt=serde_json::json!({"classification":"PUBLIC_TEST_CHILD_BOUNDARY_NOT_POWERLOSS_OR_AUTHORITY",
        "requested_argv":argv,"path_environment_name":path_variable,"start_unix_nanoseconds":started,
        "observed_identity":observed.as_ref().ok(),"identity_error":observed.as_ref().err(),
        "image_sha256_before":hex::encode(image_before),"image_sha256_after":hex::encode(image_after),"exact_image":exact_image,
        "stdout":stdout,"stderr":stderr,"both_pipes_present":pipes_present,
        "expected_exit":expected,"actual_exit":exit.as_ref().ok().and_then(|s|s.code()),
        "natural_wait":exit.is_ok(),"accepted_checkpoint":ok,"no_signals":true});
    let mut file=std::fs::OpenOptions::new().create_new(true).write(true).open(root.join(format!("{prefix}.child-closure.json"))).unwrap();
    file.write_all(&serde_json::to_vec(&receipt).unwrap()).unwrap();file.sync_all().unwrap();
    println!("\nPUBLIC_A2_CHILD_EVIDENCE={}",root.join(format!("{prefix}.child-closure.json")).display());
    assert!(ok,"child checkpoint refused: inspect preserved public child closure; no fast-exit promotion");
}
