//! EXTERNAL SOURCE ONLY. Real egui widgets over the actual role Controller.
//! The input player emits RawInput only. Neither it nor the local RPC worker
//! may request, approve, authorize, unlock or synthesize finality directly.
use super::{control_codec::{Role,Context},client_workers::{UiHandle,FrameLease},
    public_roles::PublicRole,process_auth::VerifiedProcess,image_pin::ImagePin};
use crate::{operation_screens::WalletUi,wallet_controller_v2::Controller,
    player::{Player,Action},recorder::Recorder};
use eframe::egui;
use sha2::Digest;
use std::{path::{Path,PathBuf},sync::Arc,time::{Instant,Duration},io::Write};
pub const UI_MARKER:&str="MUTINY-W15-NONSHIPPING-CONTINUOUS-ROLE-WINDOW-V1";
type Result<T>=std::result::Result<T,String>;

// A reviewed, externally hash-pinned PUBLIC event script can automate widgets.
// It has no OperationRequest, ReviewInput, Controller or private key value.
#[derive(Clone,serde::Serialize,serde::Deserialize)]
#[serde(tag="event",deny_unknown_fields)]
pub enum InputEvent {
    Click{target:String}, Text{target:String,value:String}, Wait{frames:u16},
}
#[derive(Clone,serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Phase {pub label:String,pub events:Vec<InputEvent>}
#[derive(Clone,serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Script {pub format:String,pub role:u8,pub source:[u8;32],pub campaign:[u8;32],pub phases:Vec<Phase>}
impl Script {
    pub fn read(path:&Path,pin:[u8;32],owner:&VerifiedProcess,role:Role,source:[u8;32],campaign:[u8;32])->Result<Self>{
        let held=ImagePin::open(path,&owner.identity().user_sid)?;
        if held.hash()!=pin{return Err("Externally reviewed public event script differs".into());}
        let raw=held.read_bounded(64*1024)?;
        let s:Self=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
        if s.format!=UI_MARKER||s.role!=role as u8||s.source!=source||s.campaign!=campaign||s.phases.is_empty()||s.phases.len()>32{return Err("Exact public event script role/context/phase bounds".into());}
        for p in &s.phases {
            if p.label.is_empty()||p.label.len()>96||p.events.is_empty()||p.events.len()>64{return Err("Public phase name/event bounds".into());}
            for e in &p.events {match e {
                InputEvent::Click{target} if !target.is_empty()&&target.len()<=160=>{},
                InputEvent::Text{target,value} if !target.is_empty()&&target.len()<=160&&value.len()<=32768=>{},
                InputEvent::Wait{frames} if *frames<=300=>{},
                _=>return Err("Public raw input width/frame bound".into()),
            }}
        }Ok(s)
    }
}
// Local public rehearsal input only. This is not a peer role/custody/finality proof.
// Each command is create-new and externally reviewed by the launcher; the actual
// next script still passes Script::read, then all Reload/Next phase widget gates.
#[derive(serde::Serialize,serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicCommand {
    pub format:String,pub source:[u8;32],pub campaign:[u8;32],pub role:u8,
    pub sequence:u16,pub expected_phase:usize,pub script:PathBuf,pub script_sha256:[u8;32],
}
impl PublicCommand {
    fn validate(&self,role:Role,context:Context,sequence:u16,phase:usize)->Result<()> {
        if self.format!=UI_MARKER||self.source!=context.source||self.campaign!=context.campaign||self.role!=role as u8||
            self.sequence!=sequence||!(1..=128).contains(&sequence)||self.expected_phase!=phase||
            !self.script.is_absolute()||self.script.to_str().is_none_or(|p|p.is_empty()||p.len()>4096)||self.script_sha256==[0;32]{
            return Err("Exact local public input command context/sequence/phase/script bounds".into());
        }Ok(())
    }
    fn raw_actions(&self)->Result<Vec<Action>> {
        let path=self.script.to_str().ok_or("Public script path Unicode")?;
        Ok(vec![Action::Text{target:"continuous:Script path".into(),value:path.into()},
            Action::Text{target:"continuous:Script SHA256".into(),value:hex::encode(self.script_sha256)},
            Action::Click("continuous:Reload script".into())])
    }
}
pub struct App {
    handle:UiHandle,role:Role,context:Context,public:PublicRole,screens:WalletUi,recorder:Recorder,
    player:Player,targets:Vec<(String,egui::Rect)>,scroll:egui::Rect,
    lease:Option<FrameLease>,focused:bool,input_time:Option<f64>,focus_requested:bool,
    message:Option<String>,last_visual:String,rehearsal:serde_json::Value,public_native_export:serde_json::Value,
    id_text:String,certify_text:String,adopt_text:String,export_text:String,
    script_path:String,script_pin:String,kind_text:String,trade_text:String,contract_text:String,
    next_epoch:bool,script:Option<Script>,phase:usize,start_pending:bool,continuity:Option<super::existing_role::RolePins>,continuity_verified:bool,continuity_result:serde_json::Value,
    start_at:Instant,command_root:PathBuf,command_next:u16,command_failure:bool,command_reload_pending:bool,
}
impl App {
    pub fn new(handle:UiHandle,role:Role,context:Context,recorder:Recorder,script:Option<Script>,start_pending:bool,command_root:PathBuf)->Self{
        Self{handle,role,context,public:super::role_vault::public(role),screens:WalletUi::default(),recorder,
            player:Player::default(),targets:Vec::new(),scroll:egui::Rect::NOTHING,lease:None,
            focused:false,input_time:None,focus_requested:false,message:None,last_visual:String::new(),
            rehearsal:serde_json::Value::Null,public_native_export:serde_json::Value::Null,id_text:String::new(),certify_text:String::new(),
            adopt_text:String::new(),export_text:String::new(),script_path:String::new(),script_pin:String::new(),kind_text:String::new(),trade_text:String::new(),contract_text:String::new(),next_epoch:false,script,phase:0,
            start_pending,start_at:Instant::now(),command_root,command_next:1,command_failure:false,command_reload_pending:false,continuity:None,continuity_verified:false,continuity_result:serde_json::Value::Null}
    }
    /// Immutable existing-only native comparison pins; never wallet authority.
    pub(super) fn with_original_role(mut self,pins:super::existing_role::RolePins)->Result<Self>{
        if pins.saved.role!=self.role as u8||pins.saved.client_root!=self.command_root.parent().ok_or("Original client parent")?
            ||pins.saved.queued.is_empty()||pins.saved.preimage_conditions.is_empty(){return Err("Exact original role/nonempty continuity pins required".into());}
        self.continuity=Some(pins);Ok(self)
    }
    fn reverify_original_or_current(&mut self,w:&mut Controller)->Result<()> {
        if let Some(pins)=&self.continuity{
            self.continuity_verified=false;self.continuity_result=serde_json::Value::Null;
            let actual=super::existing_role::verify_after_actual_unlock(w,pins)?;
            self.continuity_result=actual;self.continuity_verified=true;Ok(())
        }else{w.with_view(|v|->Result<()>{v.state().root().map_err(|e|format!("{e:?}"))?;Ok(())})??;Ok(())}
    }
    fn continuity_ready(&self)->bool{self.continuity.is_none()||self.continuity_verified}
    fn button(&mut self,ui:&mut egui::Ui,name:&str,label:&str)->bool{
        let r=ui.button(label);self.targets.push((name.into(),r.rect));r.clicked()
    }
    fn phase(&mut self)->Result<()> {
        if !self.continuity_ready(){return Err("Actual original Unlock/Reverify callback must close before workflow phase".into());} if !self.player.sequence_consumed(){return Err("Previous real raw-input phase incomplete/refused".into());}
        let p=self.script.as_ref().and_then(|s|s.phases.get(self.phase)).ok_or("No next reviewed public phase")?;
        let actions=p.events.iter().map(|e|match e {
            InputEvent::Click{target}=>Action::Click(target.clone()),
            InputEvent::Text{target,value}=>Action::Text{target:target.clone(),value:value.clone()},
            InputEvent::Wait{frames}=>Action::Wait(*frames),
        }).collect::<Vec<_>>();
        self.player.queue(actions)?;self.phase+=1;Ok(())
    }
    fn reload_script(&mut self)->Result<()> {
        if !self.player.sequence_consumed(){return Err("Previous actual phase must finish without refusal before script reload".into());}
        if self.script_path.is_empty()||self.script_path.len()>4096{return Err("Exact public script path bound".into());}
        let actual=VerifiedProcess::observe_created_process(std::process::id())?;
        let owner=VerifiedProcess::open(&actual)?;
        let script=Script::read(Path::new(&self.script_path),super::control_files::hash(&self.script_pin)?,&owner,self.role,self.context.source,self.context.campaign)?;
        self.script=Some(script);self.phase=0;
        if self.command_reload_pending{
            // Only this successful genuine Reload callback schedules Next phase.
            // Player.queue retains the real native settling frame after the click.
            self.player.queue([Action::Click("continuous:Next phase".into())])?;
            self.command_reload_pending=false;
        }Ok(())
    }
    fn observe_public_command(&mut self,ctx:&egui::Context)->Result<()> {
        if self.command_failure||self.command_reload_pending||self.command_next>128||self.player.failure.is_some()||!self.player.done(){return Ok(());}
        let input=self.command_root.join(format!("command-{:04}.json",self.command_next));
        if !input.exists(){return Ok(());}
        let owner=VerifiedProcess::open(&VerifiedProcess::observe_created_process(std::process::id())?)?;
        let held=ImagePin::open(&input,&owner.identity().user_sid)?;
        let raw=held.read_bounded(8192)?;
        let command:PublicCommand=serde_json::from_slice(&raw).map_err(|e|e.to_string())?;
        command.validate(self.role,self.context,self.command_next,self.phase)?;
        // Preflight verifies this exact public script and shape; it does not execute
        // it or touch Controller. The Reload widget independently verifies it again.
        Script::read(&command.script,command.script_sha256,&owner,self.role,self.context.source,self.context.campaign)?;
        let actions=command.raw_actions()?;
        let intent=serde_json::to_vec_pretty(&serde_json::json!({"format":UI_MARKER,"classification":"PUBLIC raw-input command intent; not approval/execution/finality", "command_sha256":hex::encode(sha2::Sha256::digest(&raw)),"sequence":self.command_next,"expected_phase":self.phase,"source":hex::encode(self.context.source),"campaign":hex::encode(self.context.campaign),"role":self.role as u8,"script_sha256":hex::encode(command.script_sha256)})).map_err(|e|e.to_string())?;
        let mut file=std::fs::OpenOptions::new().create_new(true).write(true).open(self.command_root.join(format!("intent-{:04}.json",self.command_next))).map_err(|e|e.to_string())?;
        file.write_all(&intent).map_err(|e|e.to_string())?;file.sync_all().map_err(|e|e.to_string())?;
        self.player.queue(actions)?;self.command_next+=1;self.command_reload_pending=true;
        if !self.focused{ctx.send_viewport_cmd(egui::ViewportCommand::Focus);self.focus_requested=true;}
        Ok(())
    }
    fn note_public_export(&mut self,w:&mut Controller,queued_id:[u8;32],raw:&[u8])->Result<()> {
        if raw.is_empty()||raw.len()>16384{return Err("Actual public export byte bound".into());}
        let candidates=[0u8,1u8].into_iter().filter_map(|list|
            mutiny_consensus_v8::operation_index_v2::operation_id(list,raw).ok().map(|(kind,id)|(list,kind,id))).collect::<Vec<_>>();
        self.public_native_export=if let [(list,kind,id)]=candidates.as_slice(){
            let matches_queue=*id==queued_id;
            let delivery=if matches_queue{Some(w.delivery(*id)?)}else{None};
            let confirmed=match delivery{Some(crate::verified_sync_v2::Delivery::ConfirmedAt(h))=>Some(h),_=>None};
            serde_json::json!({"classification":"Actual exported public wire metadata; own ID confirmation does not attest this exact alternate signature encoding. Canonical wire equality requires native replay records.",
                "source":hex::encode(self.context.source),"campaign":hex::encode(self.context.campaign),
                "queued_id":hex::encode(queued_id),"list":list,"kind":kind,"native_id":hex::encode(id),"queued_id_matches_native":matches_queue,
                "raw_sha256":hex::encode(sha2::Sha256::digest(raw)),"raw_bytes":raw.len(),
                "wire_domain":"MUTINY-BUILD8-OPERATION-WIRE-V1",
                "export_wire_commitment":hex::encode(mutiny_consensus_v8::domain_hash(mutiny_consensus_v8::operation_index_v2::WIRE_DOMAIN,raw)),
                "id_confirmed_by_own_replay_height":confirmed})
        }else{
            serde_json::json!({"classification":"Actual owned above-consensus witness or incomplete partial export; no canonical carrier/finality claim",
                "queued_id":hex::encode(queued_id),"raw_sha256":hex::encode(sha2::Sha256::digest(raw)),"raw_bytes":raw.len(),"id_confirmed_by_own_replay_height":serde_json::Value::Null})
        };
        Ok(())
    }
    fn export_pending_payment(&mut self,w:&mut Controller)->Result<()> {
        let selected=super::control_files::hash(&self.id_text)?;
        let mut matches=Vec::new();
        for raw in w.pending_for_transport()?{
            let(kind,id)=mutiny_consensus_v8::operation_index_v2::operation_id(0,&raw).map_err(|e|format!("{e:?}"))?;
            if kind!=1{return Err("Protected payment queue contains another native kind".into());}
            if id==selected{matches.push(raw);}
        }
        if matches.len()!=1{return Err("Exactly one matching own protected pending payment required; no operation-outbox fallback or signed-body fabrication".into());}
        let raw=matches.pop().ok_or("Matching protected payment absent")?;
        self.note_public_export(w,selected,&raw)?;self.export_text=hex::encode(raw);Ok(())
    }
    fn select_pending_payment(&mut self,w:&mut Controller)->Result<()> {
        let mut ids=w.pending_for_transport()?.into_iter().map(|raw|mutiny_consensus_v8::operation_index_v2::operation_id(0,&raw).map(|(_,id)|id).map_err(|e|format!("{e:?}"))).collect::<Result<Vec<_>>>()?;
        ids.sort();ids.dedup();if ids.len()!=1{return Err("Select payment requires exactly one actual protected pending ID".into());}
        self.id_text=hex::encode(ids[0]);self.certify_text=self.id_text.clone();Ok(())
    }
    fn select_pending_operation(&mut self,w:&mut Controller)->Result<()> {
        if self.kind_text.is_empty()||self.kind_text.len()>96{return Err("Exact existing operation title required".into());}
        let mut ids=w.queued_operations()?.into_iter().filter(|(item,status)|item.kind.title()==self.kind_text&&status=="Queued").map(|(item,_)|item.id).collect::<Vec<_>>();
        ids.sort();ids.dedup();if ids.len()!=1{return Err("Select operation requires one actual pending ID of this exact title; witnesses remain above consensus".into());}
        self.id_text=hex::encode(ids[0]);self.certify_text=self.id_text.clone();Ok(())
    }
    fn complete_own_partial(&mut self,w:&mut Controller)->Result<()> {
        let id=super::control_files::hash(&self.id_text)?;
        let item=w.queued_operations()?.into_iter().find(|(item,_)|item.id==id).ok_or("Exact own partial is absent")?.0;
        if item.complete{return Err("Selected own operation is already complete; preserve record".into());}
        if self.adopt_text.is_empty()||self.adopt_text.len()>32768{return Err("Exact public counterparty part byte bound".into());}
        let other=hex::decode(&self.adopt_text).map_err(|_|"Public counterparty part hex")?;
        let parts=vec![w.export(id)?,other];
        use mutiny_wallet_core_v8::OperationKind as K;
        let (complete_id,raw)=match item.kind {
            K::HashLock|K::ConditionalClaim|K::ConditionalRefund=>{let done=w.complete_conditional(id,&parts,None)?;(done.id,w.export(done.id)?)},
            K::LicenseDvp|K::FiatLock|K::FiatRelease=>{let done=w.complete_trade(&parts,None)?;if !done.queued{return Err("Verified trade did not replace the exact own open partial".into());}(done.id,done.bytes)},
            K::WalletRotation=>{let done=w.complete_rotation(id,&parts)?;(done.id,w.export(done.id)?)},
            _=>return Err("This current Controller has no completion capability for that exact kind".into()),
        };
        if raw.len()>16384{return Err("Complete public native export byte bound".into());}
        self.id_text=hex::encode(complete_id);self.certify_text=self.id_text.clone();self.export_text=hex::encode(raw);Ok(())
    }
    fn rotation(&mut self,w:&mut Controller)->Result<()> {
        let generation=w.identity().ok_or("Unlock the exact public identity")?.generation;
        if generation!=1{return Err("Only the exact public first rotation is defined in this campaign".into());}
        let restored=crate::wallet_v2::RestoredKey::restore(self.public.rotation_phrase(),2,None).map_err(str::to_owned)?;
        let descriptor=restored.descriptor().to_vec();
        let repeated=crate::wallet_v2::RestoredKey::restore(self.public.rotation_phrase(),2,Some(&descriptor)).map_err(str::to_owned)?;
        self.rehearsal=serde_json::json!({"role":self.role as u8,"generation":2,"descriptor":hex::encode(&descriptor),"fingerprint":hex::encode(repeated.fingerprint()),"result":"exact PUBLIC descriptor reproduced before review","backup_media":"not exercised"});
        w.begin_rotation(super::chain::PASSWORD,self.public.rotation_phrase(),&descriptor,16)?;
        self.screens.present_current(w);Ok(())
    }
    fn destination(&mut self,w:&mut Controller)->Result<()> {
        if self.role!=Role::Treasury{return Err("Separate exact Treasury host required".into());}
        let me=w.signer_identity().ok_or("Unlock current Treasury authority")?;
        if me.generation()!=2{return Err("R2 requires actual own canonical R1 and exact current key".into());}
        let restored=crate::wallet_v2::RestoredKey::restore(self.public.rotation_phrase(),2,Some(me.descriptor())).map_err(str::to_owned)?;
        let authority=w.with_view(|v|v.treasury().map(|t|t.authority()).ok_or("Treasury missing"))?.map_err(str::to_owned)?;
        self.rehearsal=serde_json::json!({"role":3,"generation":2,"authority":hex::encode(authority),"descriptor":hex::encode(restored.descriptor()),"fingerprint":hex::encode(restored.fingerprint()),"result":"exact PUBLIC current authority descriptor reproduced before R2 review","backup_media":"not exercised"});
        w.request(mutiny_wallet_core_v8::OperationRequest::TreasuryRotate(
            mutiny_wallet_core_v8::TreasuryRotateRequest::new(mutiny_wallet_core_v8::Blob::new(restored.descriptor().to_vec()))
                .with_verified_restore(authority,restored.fingerprint()).with_treasury(authority).with_validity_blocks(16)))?;
        self.screens.present_current(w);Ok(())
    }
    fn freeze(&mut self,w:&mut Controller)->Result<()> {
        if self.role!=Role::Treasury{return Err("Separate exact Treasury host required for freeze review".into());}
        if self.adopt_text.is_empty()||self.adopt_text.len()>32768{return Err("Canonical current maker offer byte bound".into());}
        let offer=mutiny_consensus_v8::trading_offer_v2::SignedOffer::decode(&hex::decode(&self.adopt_text).map_err(|_|"Maker offer hex")?).map_err(|e|format!("{e:?}"))?;
        let trade=super::control_files::hash(&self.trade_text)?;let contract=super::control_files::hash(&self.contract_text)?;
        let me=w.signer_identity().ok_or("Unlock exact current Treasury destination authority")?;
        let proposal=w.with_view(|v|->Result<Vec<u8>>{
            use mutiny_consensus_v8::trading_v1::{self,Context,TreasuryOfferRequest,CandidatePolicy};
            let treasury=v.treasury().ok_or("Canonical Genesis Treasury missing")?.authority();
            let context=Context{network:v.anchor().network,genesis:v.anchor().genesis,fingerprint:v.anchor().fingerprint};
            let current=trading_v1::treasury_current(v.state(),&context,treasury).map_err(|e|format!("{e:?}"))?;
            let payload=trading_v1::prepare_treasury_offer(v.state(),v.anchor(),v.state_root(),TreasuryOfferRequest{treasury,generation:current.generation,address:current.address,trade,contract,offer:offer.clone(),wallet_descriptor:me.descriptor().to_vec()},&CandidatePolicy::native_denomination_locked()).map_err(|e|format!("{e:?}"))?.signing_payload().map_err(|e|format!("{e:?}"))?;
            mutiny_wallet_core_v8::ops::treasury::freeze_proposal(&payload,&offer.encode().map_err(|e|format!("{e:?}"))?).map_err(|e|format!("{e:?}"))
        })??;
        w.request(mutiny_wallet_core_v8::OperationRequest::TreasuryFreezeOffer(mutiny_wallet_core_v8::TreasuryFreezeOfferRequest::new(mutiny_wallet_core_v8::Blob::new(proposal))))?;
        self.screens.present_current(w);Ok(())
    }
    // Public metadata captured by one actual widget callback while this frame
    // owns Controller. No key, ciphertext or preimage plaintext is exported;
    // existing custody APIs internally validate sealed records.
    // The later native passive opener independently verifies every snapshot
    // field against initialized stores and its own six canonical replays.
    fn snapshot_initialized(&mut self,w:&mut Controller)->Result<()> {
        if !self.handle.completed_for_snapshot()?{return Err("Actual completed client workers required before immutable shutdown snapshot; use the real Cancel controls widget and wait for actual completion".into());}
        use super::continuous_passive::{VaultPin,QueuedPin,PointPin};
        let status=w.vault_status()?.ok_or("Existing initialized vault status absent")?;
        if w.identity()!=Some(&status.active){return Err("Exact actual unlocked current vault identity required before continuity snapshot".into());}
        let client_root=self.command_root.parent().ok_or("Existing exact client inbox parent")?.to_path_buf();
        let mut queued=w.queued_operations()?.into_iter().map(|(q,state)|QueuedPin{id:q.id,kind:q.kind.title().into(),complete:q.complete,status:state}).collect::<Vec<_>>();
        let mut preimage_conditions=w.preimage_conditions()?;
        let payments=w.pending_for_transport()?;
        let mut payment_wire_commitments=payments.iter().map(|raw|mutiny_consensus_v8::domain_hash(mutiny_consensus_v8::operation_index_v2::WIRE_DOMAIN,raw)).collect::<Vec<_>>();
        let (head,mut reserved_inputs)=w.with_view(|v|->Result<_>{
            let authority=super::control_files::hash(&status.active.authority_id)?;
            let descriptor=hex::decode(&status.active.owner_descriptor).map_err(|_|"Public active descriptor hex")?;
            if v.state().wallets.current(authority)!=Some(descriptor.as_slice()){return Err("Current own canonical authority differs from initialized vault".into());}
            Ok((super::continuous_passive::HeadPin{height:v.anchor().height,block:v.anchor().block,root:v.state_root()},
                v.reserved().iter().map(|p|PointPin{transaction:p.transaction,index:p.index}).collect::<Vec<_>>()))
        })??;
        if queued.len()>4096||preimage_conditions.len()>4096||payment_wire_commitments.len()>64||reserved_inputs.len()>4096{return Err("Bounded initialized public continuity snapshot rows required".into());}
        queued.sort_by_key(|q|q.id);preimage_conditions.sort();payment_wire_commitments.sort();reserved_inputs.sort();
        let snapshot=VaultPin{role:self.role as u8,client_root,revision:status.revision,active:status.active,staged:status.staged,superseded:status.superseded,
            queued,preimage_conditions,payment_wire_commitments,reserved_inputs};
        let process=VerifiedProcess::observe_created_process(std::process::id())?;let owner=VerifiedProcess::open(&process)?;
        let vault=crate::wallet_controller_v2::VaultRoot::new(&snapshot.client_root.join("role-vault")).map_err(|e|format!("{e:?}"))?;
        let marker=ImagePin::open(&vault.path().join("NEW-CONTINUOUS-TEST-ROLE.marker"),&process.user_sid)?;
        let sides=super::continuous_passive::preflight_side(&vault,self.context,mutiny_consensus_v8::NETWORK_ID,&owner)?;
        if sides.len()!=4{return Err("Four actual initialized original role side files required".into());}
        let side_native:[mutiny_consensus_v8::Hash;4]=sides.iter().map(|p|p.native_id_hash()).collect::<Vec<_>>().try_into().map_err(|_|"Four original side-native pins")?;
        let canonical=super::image_pin::DatabasePin::open(&vault.path().join("public-chain.sqlite"),&process.user_sid)?;
        let path=snapshot.client_root.join(format!("native-transport-{}-{}.sqlite",process.pid,process.start_filetime));
        let (transport,transport_hold)=super::cache_snapshot::Object::observe_transport(&path,&process.user_sid)?;transport_hold.recheck()?;
        let current=super::shutdown::RoleSnapshot{format:super::shutdown::MARKER.into(),context:super::shutdown::pin_context(self.context),actual_process:process,
            transport,observed_head:head.clone(),vault:snapshot.clone(),marker_sha256:marker.hash(),canonical_native:canonical.native_id_hash(),side_native};
        for p in &sides{p.recheck()?;}marker.recheck()?;canonical.recheck()?;owner.recheck()?;
        let checkpoint=super::shutdown::publish(&snapshot.client_root,&format!("role{}",self.role as u8),&current)?;
        self.rehearsal=serde_json::json!({"format":"MUTINY-W15-NONSHIPPING-INITIALIZED-CONTINUITY-SNAPSHOT-V1",
            "classification":"Actual current Controller public metadata only; no restart/finality/backup qualification",
            "source":hex::encode(self.context.source),"campaign":hex::encode(self.context.campaign),
            "actual_pid":std::process::id(),"own_head":head,"vault":snapshot,"public_checkpoint":checkpoint,
            "private_key_export":false,"preimage_plaintext_export":false,"new_key":false,"new_genesis":false});
        Ok(())
    }
    fn host_widgets(&mut self,ui:&mut egui::Ui,w:&mut Controller){
        if let Some(e)=&self.message{ui.colored_label(egui::Color32::RED,e);}
        ui.horizontal_wrapped(|ui|{
            if self.button(ui,"continuous:Lock","Lock"){w.lock();self.continuity_verified=false;self.continuity_result=serde_json::Value::Null;self.message=Some("Locked; actual review authority withdrawn".into());}
            if self.button(ui,"continuous:Unlock","Unlock fixed PUBLIC test identity"){self.message=w.unlock(super::chain::PASSWORD).err();}
            if self.button(ui,"continuous:Reverify","Own replay and current delivery"){self.message=self.reverify_original_or_current(w).err();}
            if self.continuity_ready()&&self.button(ui,"continuous:Snapshot initialized continuity","Snapshot existing public continuity metadata"){self.message=self.snapshot_initialized(w).err();}
            if self.continuity_ready()&&self.button(ui,"continuous:Next phase","Run next reviewed raw-input phase"){self.message=self.phase().err();}
            if self.button(ui,"continuous:Reconnect","Reconnect after complete local reply"){self.message=self.handle.reconnect_after_reply().err();}
            if self.button(ui,"continuous:Cancel service controls","Cancel client workers between actions"){self.handle.cancel_between_actions();}
        });
        if !self.continuity_ready(){ui.label("Existing original vault is LOCKED or continuity unverified. Actual Unlock and Reverify are required; workflows unavailable.");return;} ui.label("Externally hash-pinned PUBLIC next event script (reload does not run it)");
        let path=ui.text_edit_singleline(&mut self.script_path);self.targets.push(("continuous:Script path".into(),path.rect));
        let pin=ui.text_edit_singleline(&mut self.script_pin);self.targets.push(("continuous:Script SHA256".into(),pin.rect));
        if self.button(ui,"continuous:Reload script","Verify exact public script and reset phases"){self.message=self.reload_script().err();}
        ui.horizontal_wrapped(|ui|{
            if self.button(ui,"continuous:Review R1","Clean public restore and review R1"){self.message=self.rotation(w).err();}
            if self.button(ui,"continuous:Replace vault","Replace vault after own verified R1"){self.message=w.replace_vault(super::chain::PASSWORD,self.public.rotation_phrase()).err();}
            if self.role==Role::Treasury&&self.button(ui,"continuous:Review R2","Clean current restore and review R2"){self.message=self.destination(w).err();}
        });
        ui.label("Select only an unambiguous existing pending public ID; selection does not authorize, deliver or confirm");
        let kind=ui.text_edit_singleline(&mut self.kind_text);self.targets.push(("continuous:Operation title".into(),kind.rect));
        ui.horizontal_wrapped(|ui|{
            if self.button(ui,"continuous:Select pending payment","Select sole protected pending payment"){self.message=self.select_pending_payment(w).err();}
            if self.button(ui,"continuous:Select pending operation","Select sole pending operation by exact title"){self.message=self.select_pending_operation(w).err();}
        });
        ui.label("Exact own queued native ID (maker/freeze offers remain above consensus)");
        let r=ui.text_edit_singleline(&mut self.id_text);self.targets.push(("continuous:Native ID".into(),r.rect));
        ui.horizontal_wrapped(|ui|{
            if self.button(ui,"continuous:Deliver payment","Advertise exact protected payment"){
                self.message=super::control_files::hash(&self.id_text).and_then(|id|self.handle.deliver_existing(id,true)).err();
            }
            if self.button(ui,"continuous:Deliver operation","Advertise exact complete native operation"){
                self.message=super::control_files::hash(&self.id_text).and_then(|id|self.handle.deliver_existing(id,false)).err();
            }
            if self.button(ui,"continuous:Export pending payment","Export exact own protected pending payment"){
                self.message=self.export_pending_payment(w).err();
            }
            if self.button(ui,"continuous:Export","Export actual own queued bytes"){
                self.message=(||->Result<()>{let id=super::control_files::hash(&self.id_text)?;let raw=w.export(id)?;
                    self.note_public_export(w,id,&raw)?;self.export_text=hex::encode(raw);Ok(())})().err();
            }
            if self.button(ui,"continuous:Check confirmed ID","Check exact ID through own replay"){
                self.message=(||->Result<()>{let id=super::control_files::hash(&self.id_text)?;
                    match w.delivery(id)?{crate::verified_sync_v2::Delivery::ConfirmedAt(h)=>{self.export_text=format!("Own replay confirms exact operation at {h}");Ok(())},other=>Err(format!("Exact operation lacks own replay confirmation: {other:?}"))}})().err();
            }
        });
        ui.label("Public exported bytes (read-only; exchanged only between these TEST role hosts)");
        ui.add(egui::TextEdit::multiline(&mut self.export_text).desired_rows(2).interactive(false));
        ui.label("Exact public counterparty partial bytes (bounded hex)");
        let r=ui.add(egui::TextEdit::multiline(&mut self.adopt_text).desired_rows(2));self.targets.push(("continuous:Adopt bytes".into(),r.rect));
        if self.button(ui,"continuous:Adopt","Review actual counterparty partial"){
            self.message=(||->Result<()>{if self.adopt_text.len()>32768{return Err("Public imported body bound".into());}
                let raw=hex::decode(&self.adopt_text).map_err(|_|"Public import hex")?;w.adopt_partial(&raw)?;
                self.screens.present_current(w);Ok(())})().err();
        }
        ui.horizontal_wrapped(|ui|{
            if self.button(ui,"continuous:Complete own partial","Verify parts and atomically complete exact own partial"){
                self.message=self.complete_own_partial(w).err();
            }
            if self.button(ui,"continuous:Create condition","Create sealed preimage; disclose only its condition"){
                self.message=w.create_preimage().map(|condition|{self.export_text=hex::encode(condition);}).err();
            }
        });
        if self.role==Role::Treasury{
            ui.label("Public Treasury freeze witness terms; no canonical listing or fee is created");
            let r=ui.text_edit_singleline(&mut self.trade_text);self.targets.push(("continuous:Trade commitment".into(),r.rect));
            let r=ui.text_edit_singleline(&mut self.contract_text);self.targets.push(("continuous:Contract commitment".into(),r.rect));
            if self.button(ui,"continuous:Review freeze","Prepare and review exact current Treasury offer witness"){self.message=self.freeze(w).err();}
        }
        ui.label("Exact sorted native ID set for genuine next block (comma-separated)");
        let r=ui.text_edit_singleline(&mut self.certify_text);self.targets.push(("continuous:Certify IDs".into(),r.rect));
        let next=ui.checkbox(&mut self.next_epoch,"Explicit next epoch (actual due activation)");self.targets.push(("continuous:Next epoch".into(),next.rect));
        ui.horizontal_wrapped(|ui|{
            if self.button(ui,"continuous:Certify","Assemble exact set and certify actual block"){
                self.message=(||->Result<()>{if self.certify_text.len()>16*65{return Err("Exact ID-set text bound".into());}
                    let ids=self.certify_text.split(',').map(|s|super::control_files::hash(s.trim())).collect::<Result<Vec<_>>>()?;
                    self.handle.certify_exact(ids,self.next_epoch)})().err();
            }
            if self.button(ui,"continuous:Advertise history","Advertise last actual certified history"){
                self.message=(||->Result<()>{let status=self.handle.status.lock().map_err(|_|"Client status poisoned")?;
                    let h=status.reply.ok_or("No actual local reply")?.observed_head;drop(status);
                    self.handle.advertise_actual(h.height,h.block)})().err();
            }
        });
        ui.label("Host observations/ACKs are not finality. Only this Controller's own pinned Genesis replay confirms an ID.");
    }
}
impl eframe::App for App {
    fn raw_input_hook(&mut self,ctx:&egui::Context,raw:&mut egui::RawInput){
        self.focused=raw.focused;self.input_time=raw.time;
        self.lease=self.handle.begin_frame();
        // A live transport turn cannot race the target layout. No player event
        // is consumed until this exact frame owns Controller and viewport state.
        if self.lease.is_some()&&raw.focused{self.player.inject(raw,&self.targets,ctx.content_rect(),self.scroll);}
    }
    fn ui(&mut self,ui:&mut egui::Ui,_frame:&mut eframe::Frame){
        let ctx=ui.ctx().clone();let events=ctx.input(|i|i.events.clone());
        let mut screenshot=None;for e in &events{if let egui::Event::Screenshot{image,..}=e{
            match self.recorder.screenshot(image){Ok(h)=>screenshot=Some(h),Err(e)=>self.message=Some(e)}
        }}
        let mut state=serde_json::json!({"marker":UI_MARKER,"role":self.role as u8,"native_focused":self.focused,
            "native_input_time":self.input_time,"frame_controller_lease":self.lease.is_some(),"host_message":self.message,
            "phase":self.phase,"raw_player_done":self.player.done(),"raw_player_failure":self.player.failure,"raw_player_last":self.player.last});
        egui::Panel::top("continuous-test-banner").show(ui,|ui|{
            ui.visuals_mut().override_text_color=Some(egui::Color32::YELLOW);
            ui.visuals_mut().panel_fill=egui::Color32::from_rgb(145,0,120);
            ui.heading("PUBLIC TEST-VALUE. NOT A REAL WALLET. NON-SHIPPING. NO REAL FUNDS.");
            ui.label(format!("Distinct continuous campaign; role {:?}; actual process {}",self.role,std::process::id()));ui.label(UI_MARKER);
        });
        let controller=Arc::clone(&self.handle.controller);
        if self.lease.is_some(){match controller.try_lock(){
            Ok(mut w)=>{
                if events.iter().any(|e|matches!(e,egui::Event::Key{..}|egui::Event::Text(_)|egui::Event::PointerButton{..})){w.user_activity();}
                self.targets.clear();
                egui::CentralPanel::default().show(ui,|ui|{
                    // All host widgets and review rows share one genuine scroll
                    // viewport. Raw host targets must fit this clip too; see below.
                    self.scroll=egui::ScrollArea::vertical().show(ui,|ui|{
                        ui.add_space(4.0);self.host_widgets(ui,&mut w);
                        ui.separator();if self.continuity_ready(){self.screens.show_branded(ui,&mut w);}ui.add_space(4.0);
                    }).inner_rect;
                });
                if self.continuity_ready(){self.targets.extend(self.screens.native_targets());}
                state["review"]=match w.screen(){Ok(Some(s))=>serde_json::json!({"text":s.review.render_text(),"gate":format!("{:?}",s.status),"kind":s.review.kind().title(),"binding":format!("{:?}",s.review.binding()),"destination_reentry":s.review.destinations_needing_check().into_iter().map(|index|serde_json::json!({"index":index,"text":s.review.destination_check_text(index)})).collect::<Vec<_>>(),"acknowledgements":s.review.acknowledgements().iter().map(|a|format!("{a:?}")).collect::<Vec<_>>(),"confirmation_phrase":s.review.confirmation_phrase()}),Ok(None)=>serde_json::Value::Null,Err(e)=>serde_json::json!({"refusal":e})};
                state["identity"]=serde_json::json!(w.identity());
                state["public_role_state"]=if let Some(me)=w.signer_identity(){
                    match w.with_view(|v|serde_json::json!({"address":mutiny_wallet_core_v8::address_format::encode_for(&me.address(),v),"controlled_licenses":mutiny_wallet_core_v8::discovery::licenses::controlled(v.state(),me.descriptor()).into_iter().take(64).map(|l|serde_json::json!({"id":hex::encode(l.id),"owner":hex::encode(l.owner),"generation":l.generation,"index":l.index,"mining":l.mining,"pending_assignment":l.pending_assignment})).collect::<Vec<_>>(),"license_display_limit":64})){Ok(value)=>value,Err(e)=>serde_json::json!({"refusal":e})}
                }else{serde_json::Value::Null};

                state["own_head"]=match w.with_view(|v|(v.anchor().height,v.anchor().block,v.state().root())){
                    Ok((h,b,Ok(r)))=>serde_json::json!({"height":h,"block":hex::encode(b),"root":hex::encode(r)}),other=>serde_json::json!({"refusal":format!("{other:?}")})};
                state["own_queued"]=serde_json::json!(w.queued_operations().ok().map(|rows|rows.into_iter().take(64).map(|(item,status)|serde_json::json!({"id":hex::encode(item.id),"kind":item.kind.title(),"complete":item.complete,"status":status})).collect::<Vec<_>>()));
                state["own_selected_delivery"]=match super::control_files::hash(&self.id_text){
                    Ok(id)=>match w.delivery(id){Ok(crate::verified_sync_v2::Delivery::ConfirmedAt(h))=>serde_json::json!({"id":hex::encode(id),"own_confirmed_height":h}),other=>serde_json::json!({"id":hex::encode(id),"status":format!("{other:?}"),"confirmed":false})},Err(_)=>serde_json::Value::Null};
                if self.start_pending&&self.targets.iter().any(|(n,_)|n=="continuous:Next phase"){
                    if !self.focused{ctx.send_viewport_cmd(egui::ViewportCommand::Focus);self.focus_requested=true;}
                    self.message=self.player.queue([Action::Click("continuous:Next phase".into())]).err();self.start_pending=false;
                }
                if let Err(e)=self.observe_public_command(&ctx){self.command_failure=true;self.message=Some(e);self.handle.cancel_between_actions();}
                if let Err(e)=self.recorder.append(true,&format!("{events:?}"),self.complete_state(state.clone()),screenshot.clone()){
                    self.message=Some(e);w.lock();self.handle.cancel_between_actions();
                }
            },
            Err(e)=>{self.message=Some(format!("Leased actual Controller unavailable: {e}"));self.handle.cancel_between_actions();}
        }}else{
            egui::CentralPanel::default().show(ui,|ui|{ui.label("Actual transport worker owns Controller; input waits without consuming a raw action.");});
            if let Err(e)=self.recorder.append(true,&format!("{events:?}"),self.complete_state(state.clone()),screenshot){self.message=Some(e);self.handle.cancel_between_actions();}
        }
        let mut visual=self.complete_state(state);visual.as_object_mut().unwrap().remove("native_input_time");
        let text=visual.to_string();if text!=self.last_visual||self.recorder.frame==0{ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(Default::default()));self.last_visual=text;}
        // Release before the next actual worker turn, never between raw_input_hook
        // and this real frame's handlers/review. Closing main joins workers later.
        drop(self.lease.take());ctx.request_repaint_after(Duration::from_millis(100));
        if self.start_at.elapsed()>Duration::from_secs(3600){self.handle.cancel_between_actions();self.message=Some("Bounded one-hour public campaign UI limit; preserve evidence".into());}
    }
}
impl App {
    fn complete_state(&self,mut v:serde_json::Value)->serde_json::Value{
        // Only fixed PUBLIC TEST UI data; never Session/private key/password or an
        // inferred receipt. The wire export is from the actual protected queue.
        v["original_continuity_required"]=serde_json::json!(self.continuity.is_some());v["original_continuity_verified"]=serde_json::json!(self.continuity_verified);v["original_continuity_result"]=self.continuity_result.clone();v["public_export_display"]=serde_json::json!(self.export_text);
        v["selected_native_id_text"]=serde_json::json!(self.id_text);
        v["selected_operation_title"]=serde_json::json!(self.kind_text);
        v["requested_exact_certify_ids"]=serde_json::json!(self.certify_text);
        v["requested_next_epoch"]=serde_json::json!(self.next_epoch);
        v["public_command_next"]=serde_json::json!(self.command_next);
        v["public_command_failure"]=serde_json::json!(self.command_failure);v["public_command_reload_pending"]=serde_json::json!(self.command_reload_pending);
        v["public_native_export"]=self.public_native_export.clone();
        v["restore_rehearsal"]=self.rehearsal.clone();v["native_focus_requested"]=serde_json::json!(self.focus_requested);
        v["host_message"]=serde_json::json!(self.message);v["phase"]=serde_json::json!(self.phase);
        v["scroll_viewport"]=serde_json::json!([self.scroll.min.x,self.scroll.min.y,self.scroll.max.x,self.scroll.max.y]);
        v["visible_targets"]=serde_json::json!(self.targets.iter().map(|(n,r)|serde_json::json!({"name":n,"rect":[r.min.x,r.min.y,r.max.x,r.max.y]})).collect::<Vec<_>>());
        if let Ok(s)=self.handle.status.try_lock(){v["local_control"]=serde_json::json!({"action":s.action,"failure":s.failure,"own_history_events":s.own_history_events,"confirmation_authority":false});}
        v
    }
}

#[cfg(test)]
mod public_command_tests {
    use super::*;
    fn context()->Context{Context{campaign:[1;32],source:[2;32],h0:[3;32],genesis:[4;32],fingerprint:[5;32]}}
    fn command()->PublicCommand{PublicCommand{format:UI_MARKER.into(),source:[2;32],campaign:[1;32],role:1,sequence:1,expected_phase:0,script:PathBuf::from(r"C:\PUBLIC-TEST\phase.json"),script_sha256:[7;32]}}
    #[test]
    fn public_command_exact_role_context_sequence_phase_and_path_bounds(){
        let c=context();command().validate(Role::WalletA,c,1,0).unwrap();
        for fault in 0..9{let mut x=command();match fault{0=>x.role=2,1=>x.source=[8;32],2=>x.campaign=[8;32],3=>x.sequence=2,4=>x.expected_phase=1,5=>x.script=PathBuf::from("relative.json"),6=>x.script_sha256=[0;32],7=>x.format="wrong".into(),_=>x.script=PathBuf::from(format!(r"C:\{}", "x".repeat(4096)))}assert!(x.validate(Role::WalletA,c,1,0).is_err());}
        assert!(command().validate(Role::WalletA,c,0,0).is_err());assert!(command().validate(Role::WalletA,c,129,0).is_err());
    }
    #[test]
    fn public_command_has_only_actual_script_text_and_reload_raw_widgets(){
        let actions=command().raw_actions().unwrap();assert_eq!(actions.len(),3);
        assert!(matches!(&actions[0],Action::Text{target,..} if target=="continuous:Script path"));
        assert!(matches!(&actions[1],Action::Text{target,value} if target=="continuous:Script SHA256"&&value==&hex::encode([7u8;32])));
        assert!(matches!(&actions[2],Action::Click(target) if target=="continuous:Reload script"));
        // No Controller/approval/signing call; genuine Reload callback separately schedules Next phase.
    }
}
