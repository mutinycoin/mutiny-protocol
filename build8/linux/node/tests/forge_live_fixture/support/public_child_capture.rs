//! Nonshipping finite crash-child evidence only; no protocol/custody authority.
//! Reuses reviewed A2 native observation and unchanged complete stream drains.
#![allow(dead_code)]
#[path="../../../node/tests/support/a2_native/process_output.rs"]
mod process_output;
const ENTRY_TOKEN:&[u8]=b"MUTINY-PUBLIC-CHILD-ENTRY-V1\n";
pub fn enter_public_child() {
    use std::io::Read;
    assert_eq!(std::env::var("MUTINY_PUBLIC_CHILD_ENTRY_V1").unwrap(),"1");
    let mut token=vec![0u8;ENTRY_TOKEN.len()];let mut stdin=std::io::stdin().lock();
    stdin.read_exact(&mut token).unwrap();assert_eq!(token.as_slice(),ENTRY_TOKEN);
    let mut tail=[0u8;1];assert_eq!(stdin.read(&mut tail).unwrap(),0,"public entry requires owned EOF");
}
pub fn capture_public_child(mut command:std::process::Command,root:&std::path::Path,expected:i32,prefix:&str) {
    use std::{io::{Read,Write},process::{Command,Stdio},sync::{Arc,Mutex,Condvar},thread};
    #[cfg(target_os="linux")]
    use sha2::{Digest,Sha256};
    use process_output::drain;
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
        if (((c.high as u64)<<32)|c.low as u64)==0 {return Err(std::io::Error::other("zero native creation time"));}
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
        if stat.metadata()?.uid()!=std::fs::metadata("/proc/self/stat")?.uid() {return Err(refusal());}
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
    assert!(matches!(expected,31|32|75));assert!(prefix.chars().all(|c|c.is_ascii_alphanumeric()||c=='-'));
    assert!(root.is_absolute() && std::fs::symlink_metadata(root).unwrap().is_dir());
    assert!(!mutiny_consensus_v8::submission_pool_v1::private_directory(root).unwrap());
    let exe=std::env::current_exe().unwrap();assert_eq!(command.get_program(),exe.as_os_str());
    let argv:Vec<String>=command.get_args().map(|a|a.to_str().unwrap().to_owned()).collect();
    assert_eq!(argv.len(),3);assert_eq!(argv[0],"--exact");assert_eq!(argv[2],"--nocapture");
    assert!(matches!(argv[1].as_str(),"public_queue_fault_child"|"archive_crash_child"));
    assert!(!prefix.is_empty() && prefix.len()<=96);
    fn hash_image(path:&std::path::Path)->std::io::Result<[u8;32]> {
        use sha2::{Digest,Sha256};use std::io::Read;
        fn refused()->std::io::Error {std::io::Error::other("bounded current image read/hash refused")}
        let mut file=std::fs::File::open(path)?;let before=file.metadata()?;
        if !before.is_file() || before.len()==0 || before.len()>512*1024*1024 {return Err(refused());}
        let mut h=Sha256::new();let mut count=0u64;let mut buf=[0u8;65536];
        loop {let n=file.read(&mut buf)?;if n==0{break;}
            count=count.checked_add(n as u64).ok_or_else(refused)?;if count>before.len(){return Err(refused());}h.update(&buf[..n]);}
        let after=file.metadata()?;
        if count!=before.len() || after.len()!=before.len() || after.modified()?!=before.modified()? {return Err(refused());}
        Ok(h.finalize().into())
    }
    let image_before=hash_image(&exe).expect("prelaunch current image read refused");
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
    let started=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos().to_string();
    // Both resources exist before launch; transfer has no channel/receiver error
    // path and no receipt operation intervenes between the two transfers.
    let out_slot:Slot<std::process::ChildStdout>=Arc::new((Mutex::new(None),Condvar::new()));
    let err_slot:Slot<std::process::ChildStderr>=Arc::new((Mutex::new(None),Condvar::new()));
    let out_thread=reader(out_slot.clone(),output,"public-a2-child-stdout").unwrap();
    let err_thread=match reader(err_slot.clone(),error,"public-a2-child-stderr") {
        Ok(t)=>t,Err(e)=>{transfer(&out_slot,None);let _=out_thread.join();panic!("prelaunch drain thread unavailable: {e}");}
    };
    
    let mut child=match command.env("MUTINY_PUBLIC_CHILD_ENTRY_V1","1").stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(c)=>c,Err(e)=>{transfer(&out_slot,None);transfer(&err_slot,None);let _=out_thread.join();let _=err_thread.join();panic!("child launch refused: {e}");}
    };
    let out=child.stdout.take();let err=child.stderr.take();let pipes_present=out.is_some() && err.is_some();
    transfer(&out_slot,out);transfer(&err_slot,err);
    let observed=identity(&child).map_err(|e|format!("native child identity refused: {e}"));
    let mut stdin=child.stdin.take();let mut entry_errors=Vec::<String>::new();
    // On unknown identity, close EOF without granting entry; the child refuses.
    // The pipe is always closed before drain/join/wait; no signal or deadline.
    let entry_image=observed.as_ref().ok().and_then(|r|r["image"].as_str()).is_some_and(|p|{
        match(std::fs::canonicalize(p),std::fs::canonicalize(&exe)) {
            (Ok(a),Ok(b))=>a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy()),_=>false
        }
    });
    let entry_image_pin=hash_image(&exe).map_err(|e|format!("pre-entry image read refused: {e}"));
    if observed.is_ok() && entry_image && entry_image_pin.as_ref().ok()==Some(&image_before) {
        if let Some(pipe)=stdin.as_mut() {
            if pipe.write_all(ENTRY_TOKEN).and_then(|_|pipe.flush()).is_err(){entry_errors.push("public entry write/flush refused".into());}
    } else {entry_errors.push("owned child stdin unavailable".into());}
    }
    else {entry_errors.push("native entry identity/image pin refused; EOF only".into());}
    drop(stdin);
    let stdout=out_thread.join().ok();let stderr=err_thread.join().ok();
    let exit=loop{match child.wait(){Err(ref e) if e.kind()==std::io::ErrorKind::Interrupted=>continue,r=>break r}};
    let image_after=hash_image(&exe).map_err(|e|format!("post-wait image read refused: {e}"));
    let exact_image=observed.as_ref().ok().and_then(|r|r["image"].as_str()).is_some_and(|p|{
        match(std::fs::canonicalize(p),std::fs::canonicalize(&exe)){
            (Ok(a),Ok(b))=>a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy()),_=>false
        }
    });
    let drained=|v:&Option<serde_json::Value>|v.as_ref().is_some_and(|r|r["eof"]==true && r["limit_exceeded"]==false && r["errors"].as_array().is_some_and(Vec::is_empty));
    let ok=entry_errors.is_empty() && pipes_present && observed.is_ok() && exact_image && image_after.as_ref().ok()==Some(&image_before) && drained(&stdout) && drained(&stderr)
        && exit.as_ref().ok().and_then(|s|s.code())==Some(expected);
    let receipt=serde_json::json!({"classification":"PUBLIC_TEST_CHILD_BOUNDARY_NOT_POWERLOSS_OR_AUTHORITY",
        "requested_argv":argv,"entry_errors":entry_errors,"entry_barrier":"fixed public token and EOF after native identity","start_unix_nanoseconds":started,
        "observed_identity":observed.as_ref().ok(),"identity_error":observed.as_ref().err(),
        "image_sha256_before":hex::encode(image_before),"image_sha256_after":image_after.as_ref().ok().map(hex::encode),"image_hash_error_after":image_after.as_ref().err(),"entry_image_hash_error":entry_image_pin.as_ref().err(),"exact_image":exact_image,
        "stdout":stdout,"stderr":stderr,"both_pipes_present":pipes_present,
        "expected_exit":expected,"actual_exit":exit.as_ref().ok().and_then(|s|s.code()),
        "natural_wait":exit.is_ok(),"accepted_checkpoint":ok,"no_signals":true});
    let mut file=std::fs::OpenOptions::new().create_new(true).write(true).open(root.join(format!("{prefix}.child-closure.json"))).unwrap();
    file.write_all(&serde_json::to_vec(&receipt).unwrap()).unwrap();file.sync_all().unwrap();
    println!("\nPUBLIC_FINITE_CHILD_EVIDENCE={}",root.join(format!("{prefix}.child-closure.json")).display());
    assert!(ok,"child checkpoint refused: inspect preserved public child closure; no fast-exit promotion");
}
