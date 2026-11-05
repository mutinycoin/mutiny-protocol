//! EXTERNAL SOURCE ONLY. Native executable controls, not simulated IO outcomes.
//! Runner must supply the exact freshly built nonshipping peer executable/hash.
//! Failed/partial/successful public fixture trees and child stdout/stderr are retained.
#![cfg(test)]
use super::{control_codec::{self,Context,Head,Header,Request,Action,Role,Tag},control_reply::{Reply,Code,Refusal},
    control_budget::Budget,process_auth::{Identity,VerifiedProcess},image_pin::ImagePin,
    pipe_io::{RolePipe,Deadline,Availability},native_peer_probe::{Input,PROBE_MARKER}};
use sha2::{Digest,Sha256};
use std::{path::PathBuf,io::Write,time::{Instant,Duration},process::{Command,Child,Stdio}};
fn fresh(name:&str)->PathBuf{
    let unique=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    let base=std::env::temp_dir().join(format!("w15-continuous-{name}-{}-{unique}",std::process::id()));
    assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());base
}
fn write_new(path:&std::path::Path,raw:&[u8]){
    let mut f=std::fs::OpenOptions::new().write(true).create_new(true).open(path).unwrap();f.write_all(raw).unwrap();f.sync_all().unwrap();
}
fn own()->VerifiedProcess{VerifiedProcess::open(&VerifiedProcess::observe_created_process(std::process::id()).unwrap()).unwrap()}
fn request(role:Role,base:&std::path::Path)->Request{Request{header:Header{tag:Tag::Head,role,sequence:1,context:Context{campaign:Sha256::digest(base.to_string_lossy().as_bytes()).into(),source:[2;32],h0:[3;32],genesis:[4;32],fingerprint:[5;32]},expected_head:Head{height:0,block:[6;32],root:[7;32]},payload_bytes:0},action:Action::Head}}
fn child(input:Input,base:&std::path::Path,current:&VerifiedProcess)->(Child,ImagePin){
    let exe=PathBuf::from(std::env::var_os("BUILD8_W15_NATIVE_PEER_BINARY").expect("Reviewed runner MUST pin actual peer executable"));
    let expected=super::control_files::hash(&std::env::var("BUILD8_W15_NATIVE_PEER_SHA256").expect("Actual peer artifact SHA is required")).unwrap();
    let held=ImagePin::open(&exe,&current.identity().user_sid).unwrap();assert_eq!(held.hash(),expected);
    let raw=serde_json::to_vec_pretty(&input).unwrap();let file=base.join("native-peer-input.json");write_new(&file,&raw);
    let stdout=std::fs::OpenOptions::new().create_new(true).write(true).open(base.join("child.stdout")).unwrap();
    let stderr=std::fs::OpenOptions::new().create_new(true).write(true).open(base.join("child.stderr")).unwrap();
    let child=Command::new(&exe).args(["--continuous-native-peer","--input",file.to_str().unwrap(),"--input-sha",&hex::encode(Sha256::digest(&raw))]).stdin(Stdio::null()).stdout(stdout).stderr(stderr).spawn().unwrap();
    held.recheck().unwrap();(child,held)
}
fn native_child_pin(child:&Child)->VerifiedProcess{
    // Independently inspected actual Child PID/start/token/image, NOT fields
    // supplied by the IPC client request or its output receipt.
    let observed=VerifiedProcess::observe_created_process(child.id()).unwrap();
    assert_eq!(observed.pid,child.id());assert_ne!(observed.pid,std::process::id());
    VerifiedProcess::open(&observed).unwrap()
}
fn wait_connected(pipe:&RolePipe,peer:&VerifiedProcess){
    let deadline=Instant::now()+Duration::from_secs(30);
    while !pipe.poll_authenticated_connection(peer).unwrap(){assert!(Instant::now()<deadline,"Actual native connection deadline");std::thread::sleep(Duration::from_millis(5));}
}
fn wait_message(pipe:&RolePipe,peer:&VerifiedProcess){
    let deadline=Instant::now()+Duration::from_secs(30);
    loop{match pipe.request_ready(peer).unwrap(){Availability::Message=>return,Availability::Empty=>{},Availability::Disconnected=>panic!("Peer closed before exact request")};assert!(Instant::now()<deadline);std::thread::sleep(Duration::from_millis(5));}
}
fn wait_exit(child:&mut Child,base:&std::path::Path,expected_success:bool){
    let deadline=Instant::now()+Duration::from_secs(32);
    let exit=loop{if let Some(s)=child.try_wait().unwrap(){break s;}assert!(Instant::now()<deadline,"Control peer did not naturally close; preserve, do not kill");std::thread::sleep(Duration::from_millis(5));};
    assert_eq!(exit.success(),expected_success);
    let result=base.join(format!("native-peer-result-{}.json",child.id()));
    assert!(result.is_file());
    let v:serde_json::Value=serde_json::from_slice(&std::fs::read(result).unwrap()).unwrap();
    assert_eq!(v["format"],PROBE_MARKER);
    if expected_success{assert_eq!(v["finality_authority"],false);}else{assert!(v["refusal"].as_str().is_some_and(|s|!s.is_empty()));}
}
#[test]
fn actual_distinct_native_peers_all_three_fixed_roles_roundtrip_and_reconnect_sequence(){
    for role in [Role::WalletA,Role::WalletC,Role::Treasury]{
        let base=fresh(&format!("role{}",role as u8));let owner=own();let request=request(role,&base);
        let pipe=RolePipe::create(request.header.context.campaign,role,&owner).unwrap();
        let input=Input{format:PROBE_MARKER.into(),server:owner.identity().clone(),campaign:request.header.context.campaign,pipe_role:role as u8,raw_request_hex:hex::encode(control_codec::encode(&request).unwrap()),reconnect_once:true,malformed_control:false};
        let(mut child,_image)=child(input,&base,&owner);let peer=native_child_pin(&child);let mut budget=Budget::new();
        for sequence in [1,2]{
            wait_connected(&pipe,&peer);assert_eq!(budget.connect(role).unwrap(),sequence);wait_message(&pipe,&peer);
            let read=pipe.read_authenticated(&peer,request.header.context,request.header.expected_head,budget.next_sequence(role).unwrap(),&Deadline::new()).unwrap();
            assert_eq!(read.request.header.sequence,sequence);budget.begin(role,sequence).unwrap();
            assert!(matches!(read.request.action,Action::Head));
            let reply=Reply{code:Code::Observed,refusal:Refusal::None,sequence,campaign:request.header.context.campaign,exact_request_sha256:Sha256::digest(&read.exact_bytes).into(),observed_head:request.header.expected_head};
            budget.finish(role).unwrap();pipe.write_authenticated(&peer,reply,&Deadline::new()).unwrap();
            if sequence==1{
                let deadline=Instant::now()+Duration::from_secs(30);
                while pipe.request_ready(&peer).unwrap()!=Availability::Disconnected{assert!(Instant::now()<deadline);std::thread::sleep(Duration::from_millis(5));}
                budget.disconnect(role).unwrap();pipe.disconnect_completed(&peer).unwrap();
            }
        }
        wait_exit(&mut child,&base,true);assert!(peer.recheck().is_err());
        let old=peer.identity().clone();assert!(VerifiedProcess::open(&old).is_err()); // Held exited PID/start cannot be silently reused.
    }
}
#[test]
fn actual_different_connected_process_is_not_authorized_by_same_account_or_executable(){
    let base=fresh("wrong-process");let owner=own();let r=request(Role::WalletA,&base);let pipe=RolePipe::create(r.header.context.campaign,Role::WalletA,&owner).unwrap();
    let input=Input{format:PROBE_MARKER.into(),server:owner.identity().clone(),campaign:r.header.context.campaign,pipe_role:1,raw_request_hex:hex::encode(control_codec::encode(&r).unwrap()),reconnect_once:false,malformed_control:false};
    let(mut child,_image)=child(input,&base,&owner);let actual=native_child_pin(&child);
    let deadline=Instant::now()+Duration::from_secs(30);
    let failure=loop{match pipe.poll_authenticated_connection(&owner){Ok(false)=>{},Ok(true)=>panic!("Actual child accepted as parent PID"),Err(e)=>break e};assert!(Instant::now()<deadline);std::thread::sleep(Duration::from_millis(5));};
    assert!(failure.contains("client PID/session mismatch"));actual.recheck().unwrap();drop(pipe);wait_exit(&mut child,&base,false);
}
#[test]
fn actual_native_role_context_sequence_truncated_extended_and_oversize_messages_refuse(){
    let original=control_codec::encode(&request(Role::WalletA,std::path::Path::new("public-native-negative-placeholder"))).unwrap();
    let mut cases=Vec::new();
    for (name,offset,value,reason) in [("wrong-role",19,2,"Role"),("wrong-context",60,9,"Context"),("wrong-seq",27,2,"Sequence")]{let mut raw=original.clone();raw[offset]=value;cases.push((name,raw,reason));}
    cases.push(("truncated",original[..263].to_vec(),"short message"));
    let mut extended=original.clone();extended.push(0);cases.push(("extended",extended,"length/header mismatch"));
    cases.push(("oversize",vec![1;1025],"queued request bound"));
    for (name,mut raw,reason) in cases{
        let base=fresh(name);let owner=own();let r=request(Role::WalletA,&base);let pipe=RolePipe::create(r.header.context.campaign,Role::WalletA,&owner).unwrap();
        raw[28..60].copy_from_slice(&r.header.context.campaign);
        let input=Input{format:PROBE_MARKER.into(),server:owner.identity().clone(),campaign:r.header.context.campaign,pipe_role:1,raw_request_hex:hex::encode(raw),reconnect_once:false,malformed_control:true};
        let(mut child,_image)=child(input,&base,&owner);let peer=native_child_pin(&child);wait_connected(&pipe,&peer);
        let deadline=Instant::now()+Duration::from_secs(30);
        let result=loop{match pipe.request_ready(&peer){Ok(Availability::Message)=>break pipe.read_authenticated(&peer,r.header.context,r.header.expected_head,1,&Deadline::new()).map(|_|()),Ok(Availability::Empty)=>{},Ok(Availability::Disconnected)=>panic!("Negative peer exited before read"),Err(e)=>break Err(e)};assert!(Instant::now()<deadline);std::thread::sleep(Duration::from_millis(5));};
        assert!(result.unwrap_err().contains(reason),"Exact expected malformed native gate {name}");drop(pipe);wait_exit(&mut child,&base,false);
    }
}
#[test]
fn actual_created_child_wrong_start_image_role_bootstrap_pin_refuses_before_pipe_use(){
    let base=fresh("changed-pins");let owner=own();let r=request(Role::WalletA,&base);let pipe=RolePipe::create(r.header.context.campaign,Role::WalletA,&owner).unwrap();
    let input=Input{format:PROBE_MARKER.into(),server:owner.identity().clone(),campaign:r.header.context.campaign,pipe_role:1,raw_request_hex:hex::encode(control_codec::encode(&r).unwrap()),reconnect_once:false,malformed_control:false};
    let(mut child,_image)=child(input,&base,&owner);let actual=native_child_pin(&child);wait_connected(&pipe,&actual);
    for field in 0..5{
        let mut wrong=actual.identity().clone();match field{0=>wrong.start_filetime^=1,1=>wrong.image_sha256[0]^=1,2=>wrong.session^=1,3=>wrong.authentication_luid.0^=1,4=>wrong.image_path=wrong.image_path.with_file_name("not-the-created-process.exe"),_=>unreachable!()};
        assert!(VerifiedProcess::open(&wrong).is_err());
    }
    actual.recheck().unwrap();drop(pipe);wait_exit(&mut child,&base,false);
}
#[test]
fn actual_opened_image_and_ancestor_replacement_writes_and_hardlinks_are_refused(){
    let base=fresh("image-handles");let current=own();let image=base.join("public-native-image.bin");write_new(&image,b"PUBLIC non-executable image pin fixture");
    let pin=ImagePin::open(&image,&current.identity().user_sid).unwrap();assert_eq!(pin.hash(),<[u8;32]>::from(Sha256::digest(b"PUBLIC non-executable image pin fixture")));
    assert_eq!(pin.native_control_metadata_leaf_id(),pin.leaf_id());
    assert!(std::fs::rename(&image,base.join("replaced.bin")).is_err());
    assert!(std::fs::OpenOptions::new().write(true).open(&image).is_err());
    assert!(std::fs::rename(&base,base.with_extension("renamed")).is_err());
    pin.recheck().unwrap();
    let other=base.join("other-public.bin");write_new(&other,b"PUBLIC hardlink negative");std::fs::hard_link(&other,base.join("other-public-alias.bin")).unwrap();
    let error=match ImagePin::open(&other,&current.identity().user_sid){Err(e)=>e,Ok(_)=>panic!("Actual hardlinked image was accepted")};assert!(error.contains("hardlink"));
    // Metadata-only assumptions are not used; exact IDs refer to opened objects.
    let again=ImagePin::open(&image,&current.identity().user_sid).unwrap();assert_eq!(pin.leaf_id(),again.leaf_id());
    assert_eq!(again.native_control_metadata_leaf_id(),again.leaf_id());
}

#[test]
fn actual_native_junction_ancestor_and_leaf_are_refused_before_image_read(){
    let base=fresh("native-junction");let target=base.join("public-target");
    assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&target).unwrap());
    write_new(&target.join("public.bin"),b"PUBLIC reparse fixture");
    let current=own();
    ImagePin::open(&target.join("public.bin"),&current.identity().user_sid).unwrap().recheck().unwrap();
    let link=base.join("new-junction");super::native_junction_control::create_new_junction(&link,&target).unwrap();
    for (case,path) in [("leaf",link.clone()), ("ancestor",link.join("public.bin"))]{
        let error=match ImagePin::open(&path,&current.identity().user_sid){Err(e)=>e,Ok(_)=>panic!("Actual native reparse accepted")};
        let evidence=serde_json::json!({"scope":"PUBLIC TEST native observed refusal ONLY","case":case,"path":path,"observed_error":error,"no_reparse_acceptance":true});
        write_new(&base.join(format!("reparse-{case}-observed-refusal.json")),&serde_json::to_vec(&evidence).unwrap());
        println!("PUBLIC native junction diagnostic: {evidence}");
        assert!(error.contains("reparse"),"Exact opened native reparse gate, not unrelated IO masking; case={case}, path={}, observed_error={error}",path.display());
    }
    ImagePin::open(&target.join("public.bin"),&current.identity().user_sid).unwrap().recheck().unwrap();
}


#[test]
fn actual_native_zero_short_and_no_data_io_never_become_an_authenticated_action(){
    // These syscall controls use the SAME current process at both endpoints;
    // distinct-process role binding is independently exercised above. This test
    // makes no claim that same-process pipe use proves role authentication.
    use super::pipe_io::ClientPipe;
    let base=fresh("native-io-counts");let owner=own();let r=request(Role::WalletA,&base);
    let pipe=RolePipe::create(r.header.context.campaign,Role::WalletA,&owner).unwrap();
    assert!(!pipe.poll_authenticated_connection(&owner).unwrap());
    let client=ClientPipe::open(r.header.context.campaign,Role::WalletA,VerifiedProcess::open(owner.identity()).unwrap(),&owner,&Deadline::new()).unwrap();
    wait_connected(&pipe,&owner);let mut budget=Budget::new();budget.connect(Role::WalletA).unwrap();
    // A genuine zero-width native write reports zero. It is never routed to
    // Request::decode nor Budget::begin, even if Windows returns success.
    let zero=client.native_control_write_once(&[]).unwrap();assert_eq!(zero.1,0);
    write_new(&base.join("zero-native-write.json"),&serde_json::to_vec(&serde_json::json!({"ok":zero.0,"written":zero.1,"error":zero.2,"confirmed":false})).unwrap());
    let mut raw=[0u8;264];let count=pipe.native_control_read_once(&owner,&mut raw).unwrap();
    assert_eq!(count.1,0);assert!(count.0||count.2==windows_sys::Win32::Foundation::ERROR_NO_DATA);
    assert_eq!(budget.next_sequence(Role::WalletA).unwrap(),1);
    // Real short message is refused by the production bounded reader; no
    // buffering together multiple independently framed messages is permitted.
    let short=client.native_control_write_once(&[1]).unwrap();assert!(short.0);assert_eq!(short.1,1);
    let e=match pipe.read_authenticated(&owner,r.header.context,r.header.expected_head,1,&Deadline::new()){Err(e)=>e,Ok(_)=>panic!("Actual native short read accepted")};
    assert!(e.contains("short message"));assert_eq!(budget.next_sequence(Role::WalletA).unwrap(),1);
    // An actual empty pipe must reach the fixed deadline without a fabricated
    // completion. The native control timeout changes only this TEST wait.
    let e=match pipe.read_authenticated(&owner,r.header.context,r.header.expected_head,1,&Deadline::native_control_timeout(Duration::from_secs(2))){Err(e)=>e,Ok(_)=>panic!("Actual no-data pipe accepted as request")};
    assert!(e.contains("deadline"));assert_eq!(budget.next_sequence(Role::WalletA).unwrap(),1);
    // Exact genuine positive on the same still-live pipe excludes a dead or
    // permanently invalid fixture from masking those specific IO boundaries.
    let bytes=control_codec::encode(&r).unwrap();let written=client.native_control_write_once(&bytes).unwrap();assert!(written.0);assert_eq!(written.1,264);
    let read=pipe.read_authenticated(&owner,r.header.context,r.header.expected_head,1,&Deadline::new()).unwrap();assert_eq!(read.request,r);
    budget.begin(Role::WalletA,1).unwrap();budget.finish(Role::WalletA).unwrap();assert_eq!(budget.next_sequence(Role::WalletA).unwrap(),2);
}
#[test]
fn actual_lost_reply_has_no_sequence_reset_or_implicit_reexecution_and_cancel_waits_complete_boundary(){
    let base=fresh("lost-ack");let owner=own();let r=request(Role::WalletA,&base);
    let pipe=RolePipe::create(r.header.context.campaign,Role::WalletA,&owner).unwrap();
    let input=Input{format:PROBE_MARKER.into(),server:owner.identity().clone(),campaign:r.header.context.campaign,pipe_role:1,raw_request_hex:hex::encode(control_codec::encode(&r).unwrap()),reconnect_once:false,malformed_control:false};
    let(mut child,_image)=child(input,&base,&owner);let peer=native_child_pin(&child);wait_connected(&pipe,&peer);wait_message(&pipe,&peer);
    let mut budget=Budget::new();budget.connect(Role::WalletA).unwrap();
    let read=pipe.read_authenticated(&peer,r.header.context,r.header.expected_head,1,&Deadline::new()).unwrap();assert_eq!(read.request,r);
    budget.begin(Role::WalletA,1).unwrap();assert_eq!(budget.disconnect(Role::WalletA),Err(super::control_budget::Error::Busy));
    // Cancellation is not allowed to tear down an in-flight action. Complete the
    // real Head attempt, then deliberately lose its reply by normal owned drop.
    budget.finish(Role::WalletA).unwrap();budget.disconnect(Role::WalletA).unwrap();
    assert_eq!(budget.connect(Role::WalletA).unwrap(),2);
    assert_eq!(budget.begin(Role::WalletA,1),Err(super::control_budget::Error::Sequence));
    assert_eq!(budget.next_sequence(Role::WalletA).unwrap(),2);
    write_new(&base.join("actual-lost-ack-sequence.json"),&serde_json::to_vec(&serde_json::json!({"authenticated_head_attempt":true,"sequence_consumed":1,"reply_sent":false,"next_sequence":2,"lost_ack_recovery_supported":false,"confirmed":false})).unwrap());
    drop(pipe);wait_exit(&mut child,&base,false);
    let result:serde_json::Value=serde_json::from_slice(&std::fs::read(base.join(format!("native-peer-result-{}.json",child.id()))).unwrap()).unwrap();
    assert!(result["refusal"].as_str().unwrap().contains("pipe"));
    // This is a fail-closed lost-ack control, NOT a service restart or successful
    // economic-action retry. A key-owning service error preserves the gap.
}
#[test]
fn actual_loopback_remote_named_pipe_route_is_rejected_by_native_remote_flag(){
    let base=fresh("remote-route");let owner=own();let r=request(Role::WalletC,&base);
    let pipe=RolePipe::create(r.header.context.campaign,Role::WalletC,&owner).unwrap();
    assert!(!pipe.poll_authenticated_connection(&owner).unwrap());
    let error=pipe.native_control_remote_loopback_error().unwrap();
    write_new(&base.join("actual-remote-route.json"),&serde_json::to_vec(&serde_json::json!({"route":"localhost UNC named pipe","native_error":error,"expected_policy_error":windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED,"confirmed":false})).unwrap());
    // An absent SMB route, wrong endpoint or unrelated network error must FAIL
    // this test, not masquerade as PIPE_REJECT_REMOTE_CLIENTS qualification.
    assert_eq!(error,windows_sys::Win32::Foundation::ERROR_ACCESS_DENIED,"Native remote-route policy must actually be reached; missing SMB is a retained dependency failure");
    let client=super::pipe_io::ClientPipe::open(r.header.context.campaign,Role::WalletC,VerifiedProcess::open(owner.identity()).unwrap(),&owner,&Deadline::new()).unwrap();
    wait_connected(&pipe,&owner);let bytes=control_codec::encode(&r).unwrap();let sent=client.native_control_write_once(&bytes).unwrap();assert!(sent.0);assert_eq!(sent.1,264);
    assert_eq!(pipe.read_authenticated(&owner,r.header.context,r.header.expected_head,1,&Deadline::new()).unwrap().request,r);
}
#[test]
fn actual_volume_root_public_image_positive_retains_delete_and_security_right_restrictions(){
    let base=fresh("volume-root-policy");assert!(base.to_string_lossy().to_ascii_uppercase().starts_with("C:\\"));
    let owner=own();let image=base.join("public-volume-image.bin");let bytes=b"PUBLIC TEST volume-root image positive";write_new(&image,bytes);
    let before=super::native_acl_control::security_snapshot(std::path::Path::new("C:\\")).unwrap();
    let held=ImagePin::open(&image,&owner.identity().user_sid).unwrap();assert_eq!(held.read_bounded(1024).unwrap(),bytes);held.recheck().unwrap();
    assert_eq!(super::native_acl_control::security_snapshot(std::path::Path::new("C:\\")).unwrap(),before);
    let root=super::image_pin::native_control_mutation_mask(true);let other=super::image_pin::native_control_mutation_mask(false);
    assert_eq!(other^root,0x4);assert_eq!(root&0x4,0);
    for bit in [0x2,0x10,0x40,0x100,0x10000,0x40000,0x80000,0x10000000,0x40000000]{assert_ne!(root&bit,0);assert_ne!(other&bit,0);}
}
#[test]
fn actual_native_foreign_descendant_create_write_delete_child_delete_dacl_owner_and_generic_grants_refuse_unchanged(){
    let base=fresh("foreign-descendant-masks");let owner=own();let good=base.join("public-positive.bin");write_new(&good,b"PUBLIC TEST unchanged positive image");
    ImagePin::open(&good,&owner.identity().user_sid).unwrap().recheck().unwrap();
    for mask in [0x2,0x4,0x10,0x40,0x100,0x10000,0x40000,0x80000,0x10000000,0x40000000]{
        let dir=base.join(format!("new-foreign-mask-{mask:x}"));super::native_acl_control::create_new_foreign_directory(&dir,&owner.identity().user_sid,mask).unwrap();
        let image=dir.join("public-negative.bin");write_new(&image,b"PUBLIC TEST foreign descendant negative");
        let before=super::native_acl_control::security_snapshot(&dir).unwrap();let contents=std::fs::read(&image).unwrap();
        let refusal=ImagePin::open(&image,&owner.identity().user_sid).err().expect("Exact actual foreign descendant grant MUST refuse");
        assert!(refusal.contains("foreign-write/replace principal refused"),"{mask:x}: {refusal}");
        assert_eq!(super::native_acl_control::security_snapshot(&dir).unwrap(),before);assert_eq!(std::fs::read(&image).unwrap(),contents);
    }
    ImagePin::open(&good,&owner.identity().user_sid).unwrap().recheck().unwrap();
}
