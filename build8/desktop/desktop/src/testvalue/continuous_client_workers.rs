//! EXTERNAL SOURCE ONLY. Two supervised NONSHIPPING workers per real GUI role.
//! GUI renders the actual WalletUi/Controller with try_lock; no pipe IO on egui main.
//! The transport worker invokes only existing advertise/peer_turn host capabilities.
//! The RPC worker has no Controller, vault password, Session or wallet-signing API.
use super::{control_codec::{Action,Context,Head,Header,Request,Role,Tag},control_reply::Reply,
    process_auth::{Identity,VerifiedProcess},pipe_io::{ClientPipe,Deadline}};
use crate::{wallet_controller_v2::Controller,wallet_controller_v2::host::WalletPeer};
use std::{sync::{Arc,Mutex,mpsc::{self,SyncSender,Receiver,TryRecvError},atomic::{AtomicBool,Ordering}},time::{Duration,Instant},thread::JoinHandle};
type Result<T>=std::result::Result<T,String>;
pub const CLIENT_MARKER:&str="MUTINY-W15-NONSHIPPING-CONTINUOUS-CLIENT-WORKERS-V1";
#[derive(Clone,Debug)]
pub struct Status{pub action:String,pub reply:Option<Reply>,pub failure:Option<String>,pub own_history_events:u64}
impl Default for Status{fn default()->Self{Self{action:"No authenticated action yet".into(),reply:None,failure:None,own_history_events:0}}}
enum TransportCommand{Deliver{native_id:[u8;32],payment:bool}}
enum RpcCommand{Action(Action),Reconnect}
#[derive(Clone)]
pub struct UiHandle {
    pub controller:Arc<Mutex<Controller>>,pub status:Arc<Mutex<Status>>,
    completion:Completion,transport:SyncSender<TransportCommand>,rpc:SyncSender<RpcCommand>,stop:Arc<AtomicBool>,gate:Arc<AtomicBool>,
}
#[derive(Clone)]
struct Completion {done:[Arc<AtomicBool>;2],fatal:Arc<Mutex<Option<String>>>}
impl Completion {
 fn new()->Self{Self{done:std::array::from_fn(|_|Arc::new(AtomicBool::new(false))),fatal:Arc::new(Mutex::new(None))}}
 fn completed(&self)->Result<bool>{if let Some(e)=&*self.fatal.lock().map_err(|_|"Native completion registry poisoned")?{return Err(e.clone());}Ok(self.done.iter().all(|d|d.load(Ordering::SeqCst)))}
 fn failure(&self,e:String){if let Ok(mut f)=self.fatal.lock(){*f=Some(e.chars().take(2048).collect());}}
}
struct CompletedLoop {completion:Completion,index:usize}
impl Drop for CompletedLoop {fn drop(&mut self){if std::thread::panicking(){self.completion.failure("Actual native client loop panicked".into());}self.completion.done[self.index].store(true,Ordering::SeqCst);}}
pub struct FrameLease(Arc<AtomicBool>);
impl Drop for FrameLease{fn drop(&mut self){self.0.store(false,Ordering::SeqCst);}}
fn acquire_frame(gate:&Arc<AtomicBool>)->Option<FrameLease>{gate.compare_exchange(false,true,Ordering::SeqCst,Ordering::SeqCst).ok().map(|_|FrameLease(gate.clone()))}
impl UiHandle{
    /// Actual loop completion only, not the stop request, timer, process exit,
    /// or action-refusal UI message. The original peer remains held until join.
    pub(super) fn completed_for_snapshot(&self)->Result<bool>{self.completion.completed()}
    /// The raw-input hook retains this token until the same real UI frame ends.
    /// Workers cannot acquire the Controller between click injection and rendering.
    /// If a real worker is busy, Player does not consume an action for that frame.
    pub fn begin_frame(&self)->Option<FrameLease>{acquire_frame(&self.gate)}

    /// Only enqueue a native ID from the actual existing protected queue. The
    /// worker calls Controller.advertise_* and independently derives exact bytes.
    pub fn deliver_existing(&self,id:[u8;32],payment:bool)->Result<()>{
        self.transport.try_send(TransportCommand::Deliver{native_id:id,payment}).map_err(|_|"One bounded pending delivery command per role".into())
    }
    /// Chain test controls have no economic authorization. IDs must equal the
    /// real native assembler set; wallet approval always stays in actual widgets.
    pub fn certify_exact(&self,ids:Vec<[u8;32]>,next_epoch:bool)->Result<()>{
        if ids.is_empty()||ids.len()>16||ids.windows(2).any(|p|p[0]>=p[1]){return Err("Canonical exact ID-set bound/order".into());}
        self.rpc.try_send(RpcCommand::Action(Action::Certify{next_epoch,ids})).map_err(|_|"One bounded pending pipe command per role".into())
    }
    pub fn advertise_actual(&self,height:u64,block:[u8;32])->Result<()>{
        self.rpc.try_send(RpcCommand::Action(Action::Advertise{height,block})).map_err(|_|"One bounded pending pipe command per role".into())
    }
    pub fn reconnect_after_reply(&self)->Result<()>{self.rpc.try_send(RpcCommand::Reconnect).map_err(|_|"Pending local action; reconnect refused".into())}
    pub fn cancel_between_actions(&self){self.stop.store(true,Ordering::SeqCst);}
}
/// The main caller retains these joins OUTSIDE the App and calls finish AFTER
/// run_native returns. App drop never blocks a live UI, detaches pending IO or
/// destroys its key/session mutex while a worker can still use it.
pub struct Workers{transport:JoinHandle<Result<WalletPeer>>,rpc:JoinHandle<Result<()>>,stop:Arc<AtomicBool>}
impl Workers{
    pub fn finish(self)->Result<()> {
        self.stop.store(true,Ordering::SeqCst);
        let a=self.transport.join().map_err(|_|"Native transport worker panicked");
        let b=self.rpc.join().map_err(|_|"Native pipe worker panicked");
        a??;b?
    }
}
fn set_failure(status:&Mutex<Status>,error:String){if let Ok(mut s)=status.lock(){s.failure=Some(error);}}
fn lock_controller<'a>(wallet:&'a Mutex<Controller>,gate:&Arc<AtomicBool>,deadline:Instant)->Result<(FrameLease,std::sync::MutexGuard<'a,Controller>)> {
    loop{if let Some(lease)=acquire_frame(gate){match wallet.try_lock(){Ok(v)=>return Ok((lease,v)),Err(std::sync::TryLockError::Poisoned(_))=>return Err("Actual Controller worker mutex poisoned".into()),Err(std::sync::TryLockError::WouldBlock)=>{}}drop(lease);}
        if Instant::now()>=deadline{return Err("Actual Controller remains busy; deadline preserves queue".into());}
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn exact_existing(wallet:&mut Controller,id:[u8;32],payment:bool)->Result<(u8,u8,Vec<u8>)> {
    let raw=if payment {
        wallet.pending_for_transport()?.into_iter().find(|raw|mutiny_consensus_v8::operation_index_v2::operation_id(0,raw).is_ok_and(|(_,actual)|actual==id)).ok_or("Exact payment is absent from own protected pending store")?
    }else{wallet.export(id)?};
    let list=if payment{0}else{
        // Actual wallet rotation tag25 is list0; all other native exported
        // operations are list1. The real advertise API remains capability gate.
        if mutiny_consensus_v8::hybrid_transaction_v2::Transaction::decode(&raw).is_ok(){0}else{1}
    };
    let(kind,actual)=mutiny_consensus_v8::operation_index_v2::operation_id(list,&raw).map_err(|e|format!("{e:?}"))?;
    if actual!=id||raw.is_empty()||raw.len()>16384{return Err("Exact existing submission ID/size differs".into());}Ok((list,kind,raw))
}
fn transport_loop(wallet:Arc<Mutex<Controller>>,mut peer:WalletPeer,commands:Receiver<TransportCommand>,rpc:SyncSender<RpcCommand>,stop:Arc<AtomicBool>,status:Arc<Mutex<Status>>,gate:Arc<AtomicBool>)->Result<WalletPeer> {
    let mut outgoing:Vec<([u8;32],[u8;32],bool)>=Vec::new();
    while !stop.load(Ordering::SeqCst){
        match commands.try_recv(){
            Ok(TransportCommand::Deliver{native_id,payment})=>{
                if outgoing.len()>=2{return Err("Two actual unreclaimed submission slots already occupied".into());}
                let deadline=Instant::now()+Duration::from_secs(30);
                let (lease,mut w)=lock_controller(&wallet,&gate,deadline)?;
                let(list,kind,raw)=exact_existing(&mut w,native_id,payment)?;
                // Gate checks exact queue completion/signatures/current context.
                let offer=if payment{w.advertise_payment(&mut peer,native_id,deadline)?}else{w.advertise_operation(&mut peer,native_id,deadline)?};
                if offer.length!=raw.len()||offer.kind!=if list==0{mutiny_transport_v2::objects::ObjectKind::SignedTransaction}else{mutiny_transport_v2::objects::ObjectKind::SignedOperation}{return Err("Real advertised carrier differs from exact protected export".into());}
                outgoing.push((offer.id,native_id,payment));
                drop(w);drop(lease);
                rpc.try_send(RpcCommand::Action(Action::Pump{list,kind,id:native_id,wire_commitment:mutiny_consensus_v8::domain_hash(b"MUTINY-BUILD8-OPERATION-WIRE-V1",&raw),raw_bytes:raw.len() as u32})).map_err(|_|"Bounded RPC already pending; HAVE retained, no pretend admission")?;
            }
            Err(TryRecvError::Empty)=>{},Err(TryRecvError::Disconnected)=>break,
        }
        let (lease,mut w)=lock_controller(&wallet,&gate,Instant::now()+Duration::from_secs(30))?;
        if let Some(progress)=w.peer_turn(&mut peer,Instant::now()+Duration::from_millis(100))?{
            if let crate::wallet_controller_v2::host::Progress::History{object,..}=progress{
                let mut s=status.lock().map_err(|_|"Status poisoned")?;
                s.own_history_events=s.own_history_events.checked_add(1).ok_or("History event count overflow")?;
                drop(s);
                w.reclaim_peer_history(&mut peer,object)?;
                let mut keep=Vec::new();
                for (object,id,payment) in outgoing.drain(..){
                    if matches!(w.delivery(id)?,crate::verified_sync_v2::Delivery::ConfirmedAt(_)){
                        if payment{w.reclaim_confirmed_payment(&mut peer,object)?;}else{w.reclaim_confirmed_operation(&mut peer,object)?;}
                    }else{keep.push((object,id,payment));}
                }
                outgoing=keep;
            }
        }
        drop(w);drop(lease);std::thread::sleep(Duration::from_millis(5));
    }Ok(peer)
}
/// HeadReader reads only a bounded pinned service-public observation (not own
/// wallet state/proof). The service checks it against its own current snapshot.
/// It MUST be pinned to the independently launched process/context/root; the
/// complete bootstrap module supplies this closure, never request data.
pub fn start(controller:Controller,peer:WalletPeer,role:Role,context:Context,owner:Identity,server:Identity,head_reader:impl Fn()->Result<Head>+Send+'static)->Result<(UiHandle,Workers)>{
    let controller=Arc::new(Mutex::new(controller));let status=Arc::new(Mutex::new(Status::default()));let stop=Arc::new(AtomicBool::new(false));
    let gate=Arc::new(AtomicBool::new(false));let completion=Completion::new();
    let(tx,rx)=mpsc::sync_channel(1);let(rt,rr)=mpsc::sync_channel(1);
    let ui=UiHandle{completion:completion.clone(),controller:controller.clone(),status:status.clone(),transport:tx,rpc:rt.clone(),stop:stop.clone(),gate:gate.clone()};
    let transport={let status=status.clone();let stop=stop.clone();let done=completion.clone();std::thread::Builder::new().name("w15-original-native-transport".into()).spawn(move||{
        let _completed=CompletedLoop{completion:done.clone(),index:0};let result=transport_loop(controller,peer,rx,rt,stop.clone(),status.clone(),gate);
        if let Err(ref e)=result{done.failure(e.clone());set_failure(&status,e.clone());stop.store(true,Ordering::SeqCst);}result
    }).map_err(|e|format!("Native transport worker was not spawned: {e}"))?};
    let rpc_spawn={let status=status.clone();let stop=stop.clone();let done=completion.clone();std::thread::Builder::new().name("w15-original-native-pipe".into()).spawn(move||->Result<()>{
        let _completed=CompletedLoop{completion:done.clone(),index:1};
        let result:Result<()>=(||{
            // Created INSIDE this worker; no raw HANDLE marked Send or moved unsafely.
            let own=VerifiedProcess::open(&owner)?;
            let mut pipe=Some(ClientPipe::open(context.campaign,role,VerifiedProcess::open(&server)?,&own,&Deadline::new())?);
            let mut sequence=1u64;
            while !stop.load(Ordering::SeqCst){
                let command=match rr.recv_timeout(Duration::from_millis(20)){Ok(c)=>c,Err(mpsc::RecvTimeoutError::Timeout)=>continue,Err(mpsc::RecvTimeoutError::Disconnected)=>break};
                match command{
                    RpcCommand::Reconnect=>{
                        // Only after the prior full reply, whose local sequence
                        // increments below. Never replay an ambiguously consumed action.
                        drop(pipe.take());
                        pipe=Some(ClientPipe::open(context.campaign,role,VerifiedProcess::open(&server)?,&own,&Deadline::new())?);
                    }
                    RpcCommand::Action(action)=>{
                        let(tag,n)=match &action{Action::Head=>(Tag::Head,0),Action::Pump{..}=>(Tag::Pump,70),Action::Certify{ids,..}=>(Tag::Certify,(2+32*ids.len()) as u32),Action::Advertise{..}=>(Tag::Advertise,40)};
                        let head=head_reader()?;
                        let request=Request{header:Header{tag,role,sequence,context,expected_head:head,payload_bytes:n},action};
                        let reply=pipe.as_ref().ok_or("Pinned role pipe absent")?.exchange(&request,&Deadline::new())?;
                        sequence=sequence.checked_add(1).ok_or("Local sequence overflow")?;
                        let mut s=status.lock().map_err(|_|"Status poisoned")?;
                        s.action=format!("Actual authenticated local observation {:?}; no finality claim",reply.code);s.reply=Some(reply);
                        if reply.code==super::control_reply::Code::Refused{s.failure=Some(format!("Native action refused: {:?}",reply.refusal));}
                    }
                }
            }drop(pipe);Ok(())
        })();
        if let Err(ref e)=result{done.failure(e.clone());set_failure(&status,e.clone());stop.store(true,Ordering::SeqCst);}result
    })};
    let rpc=match rpc_spawn{Ok(rpc)=>rpc,Err(error)=>{stop.store(true,Ordering::SeqCst);let drained=transport.join();return Err(format!("Native pipe worker was not spawned: {error}; original transport naturally joined: {}",matches!(drained,Ok(Ok(_)))));}};
    Ok((ui,Workers{transport,rpc,stop}))
}


#[cfg(test)]
mod real_frame_lease_tests {
    use super::*;
    #[test]
    fn native_raw_click_retains_frame_lease_until_actual_widget_callback_completes(){
        use crate::player::{Player,Action};
        use eframe::egui;
        let gate=Arc::new(AtomicBool::new(false));let ctx=egui::Context::default();
        let window=egui::Rect::from_min_size(egui::Pos2::ZERO,egui::vec2(600.,400.));
        let mut player=Player::default();let mut targets=Vec::new();let mut clicked=false;
        for frame in 0..5{
            if frame==2{player.queue([Action::Click("continuous:Actual callback".into())]).unwrap();}
            let mut raw=egui::RawInput{screen_rect:Some(window),time:Some(frame as f64*0.1),..Default::default()};
            let lease=acquire_frame(&gate).unwrap();
            player.inject(&mut raw,&targets,window,window);
            std::thread::scope(|s|{let g=gate.clone();s.spawn(move||assert!(acquire_frame(&g).is_none())).join().unwrap();});
            targets.clear();let output=ctx.run_ui(raw,|ui|{
                let r=ui.button("Actual native callback");targets.push(("continuous:Actual callback".into(),r.rect));
                if r.clicked(){assert!(gate.load(Ordering::SeqCst));clicked=true;}
            });output.drop_without_applying_deltas();
            drop(lease);let after=acquire_frame(&gate).unwrap();drop(after);
        }
        assert!(clicked);assert!(player.done());assert!(player.failure.is_none());
        // This proves the real egui/raw event + shared lease primitive, not
        // canonical finality, economic authorization or a mounted HWND result.
    }
}
#[cfg(test)]
mod completed_peer_lifetime_tests {
    use std::{net::{TcpListener,TcpStream},io::Read};
    // Actual native TCP socket lifetime, not a CanonicalStore/finality model.
    // The transport JoinHandle keeps its successful peer return value until
    // the main owner joins AFTER the viewport and service shutdown are observed.
    #[test]
    fn completed_native_transport_peer_stays_open_until_actual_main_join(){
        let listener=TcpListener::bind("127.0.0.1:0").unwrap();
        let client=TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server,_)=listener.accept().unwrap();server.set_nonblocking(true).unwrap();
        let (ready_rx,ready_tx)=std::sync::mpsc::sync_channel::<()>(1);
        let worker=std::thread::spawn(move||{ready_rx.send(()).unwrap();Ok::<TcpStream,String>(client)});
        ready_tx.recv().unwrap();while !worker.is_finished(){std::thread::yield_now();}
        let mut byte=[0u8;1];assert_eq!(server.read(&mut byte).unwrap_err().kind(),std::io::ErrorKind::WouldBlock,"Completed worker must not close native peer before owner joins");
        let peer=worker.join().unwrap().unwrap();assert_eq!(server.read(&mut byte).unwrap_err().kind(),std::io::ErrorKind::WouldBlock);drop(peer);
        server.set_nonblocking(false).unwrap();server.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();assert_eq!(server.read(&mut byte).unwrap(),0,"Actual peer drop produces EOF");
    }
}
#[cfg(test)]
mod actual_completion_tests {
    use super::*;
    #[test]
    fn snapshot_completion_waits_for_both_actual_worker_exits_and_retains_fatal_refusal(){
        let completion=Completion::new();let stop=Arc::new(AtomicBool::new(false));
        let (release_tx,release_rx)=mpsc::sync_channel::<()>(1);
        let first={let done=completion.clone();std::thread::Builder::new().spawn(move||{let _completed=CompletedLoop{completion:done,index:0};}).unwrap()};
        let second={let done=completion.clone();std::thread::Builder::new().spawn(move||{let _completed=CompletedLoop{completion:done,index:1};release_rx.recv().unwrap();}).unwrap()};
        first.join().unwrap();stop.store(true,Ordering::SeqCst);
        assert!(!completion.completed().unwrap(),"Stop request and one completed real worker cannot become a checkpoint");
        release_tx.send(()).unwrap();second.join().unwrap();assert!(completion.completed().unwrap());
        completion.failure("Actual IO failure retained".into());assert_eq!(completion.completed().unwrap_err(),"Actual IO failure retained");
    }
    #[test]
    fn actual_worker_panic_or_poisoned_completion_registry_never_becomes_success(){
        let completion=Completion::new();let done=completion.clone();
        assert!(std::thread::spawn(move||{let _completed=CompletedLoop{completion:done,index:0};panic!("PUBLIC TEST worker panic");}).join().is_err());
        {let _completed=CompletedLoop{completion:completion.clone(),index:1};}
        assert!(completion.completed().is_err());
        let poisoned=Completion::new();let registry=poisoned.fatal.clone();
        assert!(std::thread::spawn(move||{let _guard=registry.lock().unwrap();panic!("PUBLIC TEST completion poison");}).join().is_err());
        for index in 0..2{let _completed=CompletedLoop{completion:poisoned.clone(),index};}
        assert_eq!(poisoned.completed().unwrap_err(),"Native completion registry poisoned");
    }
}