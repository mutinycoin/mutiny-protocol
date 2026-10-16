//! EXTERNAL SOURCE ONLY. Explicit NONSHIPPING new-campaign startup.
//! The independent launcher observes all four real child processes and pins
//! their executable/source/transport/role mapping. Ready files are public
//! observations, not self-issued role capability or wallet authority.
use super::{bootstrap::{self,Bootstrap},control_codec::Role,
    process_auth::{Identity,VerifiedProcess},native_service::Service,
    service_worker::Worker,client_workers,continuous_ui,role_vault};
use crate::{wallet_controller_v2::{Controller,VaultRoot},wallet_controller_v2::host::WalletPeer,recorder::Recorder};
use std::{path::{Path,PathBuf},net::{TcpListener,TcpStream,SocketAddrV4},
    io::Write,time::{Instant,Duration},sync::{Arc,atomic::{AtomicBool,Ordering}}};
use sha2::{Sha256,Digest};
use mutiny_crypto_v2::{HybridKey,Role as KeyRole};
use mutiny_transport_v2::{Endpoint,objects::ObjectQueue};
use mutinyd_v8::hybrid_peer_admission_v2::Registry;
type Result<T>=std::result::Result<T,String>;
pub const LAUNCH_MARKER:&str="MUTINY-W15-NONSHIPPING-CONTINUOUS-NATIVE-STARTUP-V1";
fn error(e:impl std::fmt::Debug)->String{format!("{e:?}")}
fn create(path:&Path,raw:&[u8])->Result<()> {
    let mut f=std::fs::OpenOptions::new().create_new(true).write(true).open(path).map_err(error)?;
    f.write_all(raw).map_err(error)?;f.sync_all().map_err(error)
}
#[derive(serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ready {
    pub format:String,pub role:u8,pub source:[u8;32],pub campaign:[u8;32],
    pub observed_process:Identity,pub transport_descriptor_hex:String,
    pub listener:Option<SocketAddrV4>,pub h0_file:Option<PathBuf>,pub h0_sha256:Option<[u8;32]>,
    pub finality_authority:bool,
}
#[derive(serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LauncherPin {pub format:String,pub source:[u8;32],pub campaign:[u8;32],pub bootstrap_sha256:[u8;32]}
enum Mode {New(super::continuous_passive::PathPin),Prepared(super::continuous_passive::PathPin),Existing(super::continuous_passive::PathPin)}
struct Common {mode:Mode,root:PathBuf,source_git:String,manifest:PathBuf,source:[u8;32],campaign:[u8;32],bootstrap:PathBuf,launcher_pin:PathBuf}
fn common(values:&[std::ffi::OsString])->Result<Common> {
    let [root_flag,root,git_flag,git,manifest_flag,manifest,source_flag,source,campaign_flag,campaign,boot_flag,boot,pin_flag,pin,mode_flag,mode_path,mode_pin_flag,mode_sha]=values else{return Err("Exact continuous root/source/campaign/bootstrap/pin pairs required".into());};
    if root_flag!="--root"||git_flag!="--source-id"||manifest_flag!="--source-manifest"||source_flag!="--source-manifest-sha"||campaign_flag!="--campaign"||boot_flag!="--bootstrap"||pin_flag!="--launcher-pin"{return Err("Unexpected continuous startup selector".into());}
    let input=super::continuous_passive::PathPin{path:PathBuf::from(mode_path),sha256:super::control_files::hash(mode_sha.to_str().ok_or("Mode pin Unicode")?)?};
    if !input.path.is_absolute()||input.sha256==[0;32]{return Err("Exact externally pinned original root/restart input required".into());}
    let mode=match (mode_flag.to_str(),mode_pin_flag.to_str()){
        (Some("--initial-role-roots"),Some("--initial-role-roots-sha"))=>Mode::New(input),
        (Some("--prepared-reopen"),Some("--prepared-reopen-sha"))=>Mode::Prepared(input),
        (Some("--existing-restart"),Some("--existing-restart-sha"))=>Mode::Existing(input),
        _=>return Err("Explicit NEW originals versus existing-only restart selector required".into()),
    };
    let c=Common{mode,root:PathBuf::from(root),source_git:git.to_str().ok_or("Source Git Unicode")?.into(),manifest:PathBuf::from(manifest),
        source:super::control_files::hash(source.to_str().ok_or("Source SHA Unicode")?)?,
        campaign:super::control_files::hash(campaign.to_str().ok_or("Campaign SHA Unicode")?)?,bootstrap:PathBuf::from(boot),launcher_pin:PathBuf::from(pin)};
    if c.source_git.len()!=40||!c.source_git.bytes().all(|b|b.is_ascii_hexdigit())||c.source==[0;32]||c.campaign==[0;32]||
        [&c.root,&c.manifest,&c.bootstrap,&c.launcher_pin].iter().any(|p|!p.is_absolute())||c.bootstrap==c.launcher_pin||c.manifest.starts_with(&c.root)||c.bootstrap.starts_with(&c.root)||c.launcher_pin.starts_with(&c.root){return Err("Exact fresh root/separate public bootstrap/source pins required".into());}
    Ok(c)
}
fn verify_source(c:&Common,own:&VerifiedProcess)->Result<()> {
    let raw=bootstrap::bounded(&c.manifest,Some(c.source),16*1024*1024,own)?;
    let v:serde_json::Value=serde_json::from_slice(&raw).map_err(error)?;
    if v["head"]!=c.source_git||v["files"].as_array().is_none_or(|f|f.is_empty()||f.len()>4096){return Err("Complete exact source manifest/Git required".into());}
    Ok(())
}
fn wait_boot(c:&Common,own:&VerifiedProcess)->Result<Bootstrap> {
    // Startup wait is distinct from the strict 30-second authenticated action
    // deadline. At most120seconds to observe the supervisor's create-new pins.
    let end=Instant::now()+Duration::from_secs(120);
    loop{match std::fs::symlink_metadata(&c.launcher_pin){Ok(_)=>break,Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{},Err(e)=>return Err(error(e))}
        own.recheck()?;if Instant::now()>=end{return Err("Independent launcher bootstrap was not published; preserve ready files".into());}std::thread::sleep(Duration::from_millis(20));}
    let raw=bootstrap::bounded(&c.launcher_pin,None,2048,own)?;
    let pin:LauncherPin=serde_json::from_slice(&raw).map_err(error)?;
    if pin.format!=LAUNCH_MARKER||pin.source!=c.source||pin.campaign!=c.campaign||pin.bootstrap_sha256==[0;32]{return Err("Independent launcher pin context differs".into());}
    let boot=Bootstrap::read(&c.bootstrap,pin.bootstrap_sha256,own)?;
    if boot.context.source!=c.source||boot.context.campaign!=c.campaign||boot.source_git!=c.source_git||boot.source_manifest!=c.manifest||boot.source_manifest_sha256!=c.source{return Err("Pinned bootstrap differs from actual startup inputs".into());}
    Ok(boot)
}
fn own()->Result<(Identity,VerifiedProcess)>{let id=VerifiedProcess::observe_created_process(std::process::id())?;let held=VerifiedProcess::open(&id)?;Ok((id,held))}
fn descriptor(key:&HybridKey)->Result<String>{key.public().descriptor(1).map(hex::encode).map_err(error)}

fn restart(c:&Common,owner:&VerifiedProcess)->Result<super::restart_spec::HeldRestart>{
    let Mode::Existing(input)=&c.mode else{return Err("Existing-only mode required".into());};
    let raw=bootstrap::bounded(&input.path,Some(input.sha256),2*1024*1024,owner)?;
    let spec:super::restart_spec::RestartSpec=serde_json::from_slice(&raw).map_err(error)?;spec.validate()?;
    if spec.context.source!=c.source||spec.context.campaign!=c.campaign{return Err("Externally pinned original restart context/source differs".into());}
    super::restart_spec::HeldRestart::read(&input.path,input.sha256,owner,spec.context.context(),&c.source_git,&c.manifest)
}
fn ready_path(root:&Path,identity:&Identity)->PathBuf{root.join(format!("ready-public-{}-{}.json",identity.pid,identity.start_filetime))}
fn session_namespace(identity:&Identity)->String{format!("{}-{}",identity.pid,identity.start_filetime)}
fn service(c:Common)->Result<()> {
    if mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED||mutiny_crypto_v2::RELEASE_CUSTODY_ENABLED{return Err("Closed production gates required by public TEST service".into());}
    let (identity,owner)=own()?;verify_source(&c,&owner)?;
    let (mut service,original_restart,original_new_roots)=match &c.mode{
        Mode::New(_)=>return Err("Prepare originals in a separate process, observe its actual exit, then use prepared-reopen; no same-process H0".into()),
        Mode::Prepared(input)=>{let held=super::initial_bootstrap::HeldPrepared::read(input,&owner,c.source,c.campaign,&c.manifest,&c.source_git)?;
            if held.value.service_root!=c.root{return Err("Exact prepared service root differs; no replacement".into());}
            let service=Service::reopen_before_h0(&held,&owner)?;held.recheck()?;(service,None,Some(held))},
        Mode::Existing(_)=>{let held=restart(&c,&owner)?;if held.spec.service_root!=c.root{return Err("Existing service root differs; never provision replacement".into());}
            let held=held.open_original_service(&owner)?;(held.service,Some(held.restart),None)},
    };
    // Original provider/canonical/custody/native leases remain live through Worker
    // natural completion and monitor join. These options never enter request codec.
    let transport=HybridKey::generate(KeyRole::Transport).map_err(error)?;
    let own_endpoint=Endpoint::pinned(transport.public().clone(),1).map_err(error)?;
    let ready=Ready{format:LAUNCH_MARKER.into(),role:0,source:c.source,campaign:c.campaign,
        observed_process:identity.clone(),transport_descriptor_hex:descriptor(&transport)?,listener:None,
        h0_file:Some(c.root.join("continuous-h0-public.json")),h0_sha256:Some(service.context().h0),finality_authority:false};
    create(&ready_path(&c.root,&identity),&serde_json::to_vec_pretty(&ready).map_err(error)?)?;
    let boot=wait_boot(&c,&owner)?;
    if boot.service!=identity||boot.service_root!=c.root||boot.context.context()!=service.context()||boot.service_descriptor_hex!=ready.transport_descriptor_hex{return Err("Supervisor did not pin this exact service/context/transport".into());}
    let registry=Registry::new(service.context().genesis,service.context().fingerprint,own_endpoint,
        [Role::WalletA,Role::WalletC,Role::Treasury].into_iter().map(|r|boot.role_endpoint(r)).collect::<Result<Vec<_>>>()?,3,3)?;
    for role in [Role::WalletA,Role::WalletC,Role::Treasury]{
        let peer=boot.peer(role);let held=VerifiedProcess::open(&peer.process)?;held.recheck()?;
        let socket=TcpStream::connect_timeout(&peer.listener.into(),Duration::from_secs(30)).map_err(error)?;
        let endpoint=boot.role_endpoint(role)?;
        let connection=registry.begin()?.initiate(endpoint.id(),socket,&transport,Duration::from_secs(30))?;
        held.recheck()?;
        let queue=ObjectQueue::open(&c.root.join(format!("role{}-native-transport-{}.sqlite",role as u8,session_namespace(&identity))),connection.peer_id()).map_err(error)?;
        service.attach(role,connection.attach(queue)?)?;
    }
    drop(transport); // Session keys remain in actual admitted peers; no key serialization.
    let stop=Arc::new(AtomicBool::new(false));let cancel=c.root.join(format!("cancel-between-actions-{}.public",session_namespace(&identity)));
    let monitor_stop=stop.clone();let monitor_context=service.context();let monitor_identity=identity.clone();
    let monitor=std::thread::Builder::new().name("w15-original-service-cancellation".into()).spawn(move||->Result<()>{
        let (_,held)=own()?;
        let result=(||->Result<()>{while !monitor_stop.load(Ordering::SeqCst){
            match std::fs::symlink_metadata(&cancel){Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{},Err(e)=>return Err(error(e)),Ok(_)=>{let raw=bootstrap::bounded(&cancel,None,2048,&held)?;
                let v:serde_json::Value=serde_json::from_slice(&raw).map_err(error)?;
                if v["format"]!=LAUNCH_MARKER||v["campaign"]!=hex::encode(monitor_context.campaign)||v["source"]!=hex::encode(monitor_context.source)||v["pid"]!=monitor_identity.pid||v["start_filetime"]!=monitor_identity.start_filetime||v["cancel_between_actions"]!=true{return Err("Cancellation public context differs".into());}
                monitor_stop.store(true,Ordering::SeqCst);return Ok(());
            }}std::thread::sleep(Duration::from_millis(20));
        }Ok(())})();
        if result.is_err(){monitor_stop.store(true,Ordering::SeqCst);}result
    }).map_err(|e|format!("Original cancellation monitor was not spawned: {e}"))?;
    let peers=[Role::WalletA,Role::WalletC,Role::Treasury].map(|r|(r,boot.peer(r).process.clone()));
    let result=Worker::new(service,peers,&identity,stop.clone(),&c.root.join(format!("authenticated-actions-{}.jsonl",session_namespace(&identity)))).and_then(|worker|worker.run_with_shutdown(&c.root));
    stop.store(true,Ordering::SeqCst);let monitored=monitor.join().map_err(|_|"Cancellation monitor panicked")?;
    if let Some(held)=&original_restart{held.recheck()?;}if let Some(held)=&original_new_roots{held.recheck()?;}
    // Preserve primary AND monitor failures, after both actual owners naturally
    // finish. Snapshot complete=false cannot promote ambiguous/lost acknowledgments.
    match (result,monitored){(Ok(()),Ok(()))=>Ok(()),(a,b)=>Err(format!("Service refused: worker={:?}, monitor={:?}",a.err(),b.err()))}
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PublicH0 {format:String,classification:String,campaign:String,source:String,genesis:String,root:String,records:Vec<([u8;32],Vec<u8>)>}
fn initial(boot:&Bootstrap,owner:&VerifiedProcess)->Result<(mutiny_consensus_v8::anchors::FinalizedAnchor,mutiny_consensus_v8::execution::State)> {
    let raw=bootstrap::bounded(&boot.h0_file,Some(boot.context.h0),8*1024*1024,owner)?;
    let h:PublicH0=serde_json::from_slice(&raw).map_err(error)?;
    if h.format!=super::native_service::SERVICE_MARKER||h.classification.is_empty()||h.campaign!=hex::encode(boot.context.campaign)||h.source!=hex::encode(boot.context.source)||h.records.is_empty()||h.records.len()>4096||h.records.iter().map(|(_,v)|v.len()).sum::<usize>()>8*1024*1024{return Err("Exact bounded new public H0 records required".into());}
    let genesis=mutiny_consensus_v8::anchors::FinalizedAnchor::decode(&hex::decode(h.genesis).map_err(error)?).map_err(error)?;
    if genesis.genesis!=boot.context.genesis||genesis.fingerprint!=boot.context.fingerprint||genesis.height!=0{return Err("Pinned public H0 anchor differs".into());}
    let root=super::control_files::hash(&h.root)?;
    let state=mutiny_consensus_v8::execution::State::from_records(&h.records,root).map_err(error)?;
    if state.dividends.treasury().map(|t|t.class())!=Some(mutiny_consensus_v8::treasury_v1::Class::TestValue){return Err("Only coherent PUBLIC TEST-VALUE H0 permitted".into());}
    Ok((genesis,state))
}
struct ClientArgs {common:Common,role:Role,record:PathBuf,script:Option<(PathBuf,[u8;32])>,start:bool}
fn client_args(values:&[std::ffi::OsString])->Result<ClientArgs>{
    if values.len()<22{return Err("Explicit client role/record and common pairs required".into());}
    let c=common(&values[..18])?;if values[18]!="--role"||values[20]!="--record-root"{return Err("Client role/record selectors".into());}
    let role=bootstrap::parse_role(values[19].to_str().ok_or("Role Unicode")?.parse::<u8>().map_err(|_|"Role decimal")?)?;
    let record=PathBuf::from(&values[21]);if !record.is_absolute()||record.starts_with(&c.root)||c.root.starts_with(&record){return Err("New separate role record root required".into());}
    let (script,start)=match &values[22..]{[] => (None,false),[flag,path,pin_flag,pin] if flag=="--event-script"&&pin_flag=="--event-script-sha"=>(Some((PathBuf::from(path),super::control_files::hash(pin.to_str().ok_or("Script pin Unicode")?)?)),false),[flag,path,pin_flag,pin,start] if flag=="--event-script"&&pin_flag=="--event-script-sha"&&start=="--start-public-phase"=>(Some((PathBuf::from(path),super::control_files::hash(pin.to_str().ok_or("Script pin Unicode")?)?)),true),_=>return Err("Exact public event script selectors only".into())};
    Ok(ClientArgs{common:c,role,record,script,start})
}
/// Exact native inbox must be NEW and protected before any key/Controller worker
/// is started. No post-start early return can detach its two original owners.
fn with_new_inbox<T>(root:&Path,start:impl FnOnce()->Result<T>)->Result<T>{
    if !mutiny_consensus_v8::submission_pool_v1::private_directory(root).map_err(|e|format!("New public input inbox: {e:?}"))?{
        return Err("Public input inbox must be NEW for this process; preserve existing evidence".into());
    }
    start()
}
fn client(args:ClientArgs)->eframe::Result {
    let preflight=(||->Result<_>{
        if mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED||mutiny_crypto_v2::RELEASE_CUSTODY_ENABLED{return Err("Closed production gates required".into());}
        let c=&args.common;let (identity,owner)=own()?;verify_source(c,&owner)?;
        let (original_restart,original_new_roots)=match &c.mode{
            Mode::New(_)=>return Err("Originals must pass actual fresh-process provider reopen before any client or viewport".into()),
            Mode::Prepared(input)=>{let held=super::initial_bootstrap::HeldPrepared::read(input,&owner,c.source,c.campaign,&c.manifest,&c.source_git)?;
                if held.value.client_roots[args.role as usize-1]!=c.root{return Err("Prepared exact original client root differs".into());}
                // No waiting on a partially initialized provider/Ready claim.
                held.require_publication(&owner)?;(None,Some(held))},
            Mode::Existing(_)=>{let held=restart(c,&owner)?;if held.spec.roles[args.role as usize-1].saved.client_root!=c.root{return Err("Original initialized client path differs; never replace vault".into());}(Some(held),None)},
        };
        let transport=HybridKey::generate(KeyRole::Transport).map_err(error)?;
        let listener=TcpListener::bind("127.0.0.1:0").map_err(error)?;
        let std::net::SocketAddr::V4(address)=listener.local_addr().map_err(error)? else{return Err("Native IPv4 loopback listener required".into());};
        let ready=Ready{format:LAUNCH_MARKER.into(),role:args.role as u8,source:c.source,campaign:c.campaign,observed_process:identity.clone(),transport_descriptor_hex:descriptor(&transport)?,listener:Some(address),h0_file:None,h0_sha256:None,finality_authority:false};
        create(&ready_path(&c.root,&identity),&serde_json::to_vec_pretty(&ready).map_err(error)?)?;
        let boot=wait_boot(c,&owner)?;let role_pin=boot.peer(args.role);
        if role_pin.process!=identity||role_pin.listener!=address||role_pin.transport_descriptor_hex!=ready.transport_descriptor_hex{return Err("Independent supervisor did not pin this exact client/listener/transport/role".into());}
        let prepared_publication=if let Some(held)=&original_new_roots{let(proof,h0,service)=held.require_publication(&owner)?;
            if service!=boot.service||held.value.context.context()!=boot.context.context(){return Err("Fresh original service proof does not match independently pinned peer".into());}Some((proof,h0))}else{None};
        let registry=Registry::new(boot.context.genesis,boot.context.fingerprint,boot.role_endpoint(args.role)?,vec![boot.service_endpoint()?],1,1)?;
        listener.set_nonblocking(true).map_err(error)?;let end=Instant::now()+Duration::from_secs(30);
        let socket=loop{match listener.accept(){Ok((s,a)) if a.ip()==std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)=>break s,
            Ok(_)=>return Err("Nonlocal native connection refused".into()),Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>{owner.recheck()?;if Instant::now()>=end{return Err("Actual pinned service handshake deadline".into());}std::thread::sleep(Duration::from_millis(5));},Err(e)=>return Err(e.to_string())}};
        drop(listener);let service_pin=VerifiedProcess::open(&boot.service)?;service_pin.recheck()?;
        let connection=registry.begin()?.respond(boot.service_endpoint()?.id(),socket,&transport,Duration::from_secs(30))?;
        service_pin.recheck()?;drop(transport);
        let queue=ObjectQueue::open(&c.root.join(format!("native-transport-{}.sqlite",session_namespace(&identity))),connection.peer_id()).map_err(error)?;
        let peer=WalletPeer::new(connection.attach(queue)?);
        let (genesis,state)=initial(&boot,&owner)?;
        // Controller is created only in a nested new role-vault leaf. The outer
        // transport/ready root is never mistaken for initialized custody.
        let vault=VaultRoot::new(&c.root.join("role-vault")).map_err(error)?;
        let (controller,role_lifetime,role_pins)=if let Some(original)=&original_restart{
            if original.spec.context.context()!=boot.context.context(){return Err("Original restart and new authenticated bootstrap context differ".into());}
            let (controller,held,pins)=super::existing_role::ExistingRole::open(&vault,args.role,boot.context.context(),&genesis,&state,original.spec.role_pins(args.role),&owner)?.into_runtime()?;
            (controller,held,Some(pins))
        }else{let (controller,held)=super::existing_role::ExistingRole::open_bootstrapped(&vault,args.role,boot.context.context(),&genesis,&state,&owner)?;(controller,held,None)};
        let script=args.script.as_ref().map(|(p,h)|continuous_ui::Script::read(p,*h,&owner,args.role,c.source,c.campaign)).transpose()?;
        Ok((identity,boot,controller,peer,script,registry,role_lifetime,role_pins,original_restart,original_new_roots,prepared_publication))
    })().map_err(|e|eframe::Error::AppCreation(e.into()))?;
    let (identity,boot,controller,peer,script,_registry,role_lifetime,role_pins,original_restart,original_new_roots,prepared_publication)=preflight;
    let reader_boot=boot.clone();let reader_identity=identity.clone();let client_namespace=session_namespace(&identity);
    // All fallible inbox validation precedes either worker spawn. A refusal here
    // drops only unstarted Controller/peer state while original holders remain.
    let command_root=args.common.root.join(format!("public-event-inbox-{}",client_namespace));
    let (handle,workers)=with_new_inbox(&command_root,||client_workers::start(controller,peer,args.role,boot.context.context(),identity,boot.service.clone(),move||{
        let held=VerifiedProcess::open(&reader_identity)?;reader_boot.observed_head(&held)
    })).map_err(|e|eframe::Error::AppCreation(e.into()))?;
    let title=format!("MUTINY PUBLIC TEST-VALUE CONTINUOUS {:?} - NON-SHIPPING - pid {}",args.role,std::process::id());
    let observed_title=title.clone();let source=args.common.source_git.clone();let manifest=args.common.manifest.clone();
    let record=args.record;let role=args.role;let start=args.start;let context=boot.context.context();
    let result=eframe::run_native(&title,eframe::NativeOptions{viewport:eframe::egui::ViewportBuilder::default().with_inner_size([1150.,850.]),..Default::default()},Box::new(move|cc|{
        use raw_window_handle::{HasWindowHandle,RawWindowHandle};
        use windows_sys::Win32::UI::WindowsAndMessaging::{SetWindowDisplayAffinity,WDA_EXCLUDEFROMCAPTURE,GetWindowTextW};
        let RawWindowHandle::Win32(window)=cc.window_handle()?.as_raw()else{return Err("Actual native Windows viewport required".into());};
        if unsafe{SetWindowDisplayAffinity(window.hwnd.get() as *mut _,WDA_EXCLUDEFROMCAPTURE)}==0{return Err("Actual native capture protection failed".into());}
        let mut text=[0u16;256];let n=unsafe{GetWindowTextW(window.hwnd.get() as *mut _,text.as_mut_ptr(),256)};
        if n<=0||String::from_utf16(&text[..n as usize])?!=observed_title{return Err("Observed actual role window title differs".into());}
        let recorder=Recorder::new(&record,source,&manifest,window.hwnd.get() as usize,observed_title)?;
        let app=continuous_ui::App::new(handle,role,context,recorder,script,start,command_root);let app=if let Some(pins)=role_pins{app.with_original_role(pins)?}else{app};Ok(Box::new(app))
    }));
    // Worker joins occur AFTER the actual native viewport exits. A live UI never
    // blocks for pipe IO or destroys Controller while a transport turn uses it.
    let joined=workers.finish().map_err(|e|eframe::Error::AppCreation(e.into()));
    // Retained native originals outlive BOTH worker joins even on GUI failure.
    let held=(||->Result<()>{role_lifetime.recheck()?;if let Some((proof,h0))=&prepared_publication{proof.recheck()?;h0.recheck()?;}if let Some(h)=&original_restart{h.recheck()?;}if let Some(h)=&original_new_roots{h.recheck()?;}Ok(())})().map_err(|e|eframe::Error::AppCreation(e.into()));
    match (result,joined,held){(Ok(()),Ok(()),Ok(()))=>Ok(()),(a,b,c)=>Err(eframe::Error::AppCreation(format!("Client closure refusal: viewport={:?}, workers={:?}, original leases={:?}",a.err(),b.err(),c.err()).into()))}
}
fn prepare(values:&[std::ffi::OsString])->Result<()> {
    if values.len()!=20||values[18]!="--prepared-output"{return Err("Exact eighteen common arguments plus create-new public prepared-output required".into());}
    if mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED||mutiny_crypto_v2::RELEASE_CUSTODY_ENABLED{return Err("Closed production gates required by public preparation".into());}
    let c=common(&values[..18])?;let Mode::New(input)=&c.mode else{return Err("Preparation exclusively accepts new original root plan".into());};
    let output=PathBuf::from(&values[19]);let(_,owner)=own()?;verify_source(&c,&owner)?;
    let roots=super::launch_roots::HeldRoots::read(input,&owner,c.source,c.campaign)?;
    if roots.roots.service!=c.root||!output.is_absolute()||output==c.manifest||output==input.path||output==c.bootstrap||output==c.launcher_pin||std::iter::once(&roots.roots.service).chain(roots.roots.roles.iter()).any(|r|output.starts_with(r)){return Err("Separate explicit public preparation output and exact originals required".into());}
    super::initial_bootstrap::absent(&output)?;super::initial_bootstrap::absent(&c.bootstrap)?;super::initial_bootstrap::absent(&c.launcher_pin)?;
    let source_lease=super::image_pin::ImagePin::open(&c.manifest,&owner.identity().user_sid)?;if source_lease.hash()!=c.source{return Err("Preparation source changed before creating originals".into());}
    roots.all_absent_before_bootstrap()?;
    let saved=Service::prepare_before_h0(&c.root,c.campaign,c.source,&roots.roots.roles,&owner,&c.source_git,super::continuous_passive::PathPin{path:c.manifest.clone(),sha256:c.source},input.clone())?;
    roots.recheck()?;owner.recheck()?;saved.validate()?;
    let raw=serde_json::to_vec_pretty(&saved).map_err(error)?;super::initial_bootstrap::create_public(&output,&raw)?;
    let readback=super::image_pin::ImagePin::open(&output,&owner.identity().user_sid)?;
    if readback.read_bounded(2*1024*1024)?!=raw{return Err("Prepared public receipt readback differs; no H0".into());}
    super::initial_bootstrap::absent(&c.root.join("continuous-h0-public.json"))?;super::initial_bootstrap::absent(&c.root.join(super::initial_bootstrap::PROOF))?;
    readback.recheck()?;source_lease.recheck()?;roots.recheck()?;owner.recheck()?;Ok(())
    // main returns; external supervisor observes actual natural process exit.
}
pub fn run_if_requested(treasury_root:bool)->Option<eframe::Result>{
    let args=std::env::args_os().skip(1).collect::<Vec<_>>();
    match args.first().and_then(|v|v.to_str()){
        Some("--continuous-bootstrap-prepare") if !treasury_root=>Some(prepare(&args[1..]).map_err(|e|eframe::Error::AppCreation(e.into()))),
        Some("--continuous-service") if !treasury_root=>Some(common(&args[1..]).and_then(service).map_err(|e|eframe::Error::AppCreation(e.into()))),
        Some("--continuous-client")=>Some(client_args(&args[1..]).and_then(|a|if (a.role==Role::Treasury)==treasury_root{Ok(a)}else{Err("Separate exact ordinary/Treasury root role gate".into())}).map_err(|e|eframe::Error::AppCreation(e.into())).and_then(client)),
        _=>None,
    }
}

#[cfg(test)] mod inbox_before_workers_tests {
 use super::*;
 #[test] fn actual_existing_inbox_refuses_before_any_worker_spawn_and_fresh_inbox_naturally_joins(){
  use std::sync::atomic::{AtomicUsize,Ordering};
  let nonce=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
  let root=std::env::temp_dir().join(format!("w15-inbox-order-{}-{nonce}",std::process::id()));
  assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&root).unwrap());
  let existing=root.join("existing-public-inbox");assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&existing).unwrap());
  let marker=existing.join("preserved.public");create(&marker,b"PUBLIC retained inbox evidence").unwrap();
  let starts=AtomicUsize::new(0);
  let start=||->Result<()>{std::thread::scope(|s|{let a=s.spawn(||{starts.fetch_add(1,Ordering::SeqCst);});let b=s.spawn(||{starts.fetch_add(1,Ordering::SeqCst);});a.join().unwrap();b.join().unwrap();});Ok(())};
  assert!(with_new_inbox(&existing,start).is_err());assert_eq!(starts.load(Ordering::SeqCst),0,"Pre-viewport failure must occur before either actual worker starts");
  assert_eq!(std::fs::read(&marker).unwrap(),b"PUBLIC retained inbox evidence");assert_eq!(std::fs::read_dir(&existing).unwrap().count(),1);
  let fresh=root.join("new-public-inbox");with_new_inbox(&fresh,start).unwrap();assert_eq!(starts.load(Ordering::SeqCst),2,"Actual two scoped workers completed and joined");
  assert_eq!(std::fs::read_dir(&fresh).unwrap().count(),0);
  // Native public filesystem + actual spawned worker ordering only. This is
  // not GUI/HWND, original vault reopening, wallet authorization or finality.
 }
}