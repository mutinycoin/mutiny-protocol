//! NON-SHIPPING passive restart of the exact original public TEST-VALUE wallet.
//! Opens initialized originals only. No fixture, new wallet, delivery or certifier.
use crate::{chain, original_replay::{OriginalReplay, hash, plain_original, read_bounded, pinned_file},
    player::{Action, Player}, recorder::Recorder, store_v2::Store,
    verified_sync_v2::{Delivery, Replica}, wallet_controller_v2::{Controller, VaultRoot}};
use eframe::egui;
use mutiny_consensus_v8::{Hash, canonical_store_v2::CanonicalStore, mempool_v2::Mempool};
use mutiny_crypto_v2::{PublicKey, Role};
use sha2::{Digest, Sha256};
use std::{ffi::OsString, path::{Component, Path, PathBuf}};
type Result<T> = std::result::Result<T, String>;
pub const PASSIVE_MARKER: &str = "MUTINY-W15-PASSIVE-ORIGINAL-RESTART-V1";
struct Args {
    h0: PathBuf, h0_sha: Hash, driver: PathBuf, vault: VaultRoot,
    operation: Hash, wire: PathBuf, record: PathBuf, source: String,
    manifest: PathBuf, manifest_sha: Hash,
}
fn parse(values: &[OsString]) -> Result<Args> {
    let flags = ["--passive-original-restart", "--h0-sha256", "--driver-root", "--vault-root",
        "--operation-id", "--wire-path", "--record-root", "--source-id",
        "--source-manifest", "--source-manifest-sha256", "--scenario"];
    if values.len() != 22 { return Err("Passive restart requires eleven exact argument pairs".into()); }
    for (i, flag) in flags.iter().enumerate() {
        if values[i*2] != *flag { return Err("Unexpected passive restart arguments".into()); }
    }
    let text = |i:usize| values[i].to_str().ok_or("Passive argument Unicode");
    if text(21)? != "passive-reopen" { return Err("Only passive-reopen is defined".into()); }
    let args = Args {h0:PathBuf::from(&values[1]), h0_sha:hash(text(3)?)?,
        driver:PathBuf::from(&values[5]), vault:VaultRoot::new(Path::new(&values[7])).map_err(|e|e.to_string())?,
        operation:hash(text(9)?)?, wire:PathBuf::from(&values[11]), record:PathBuf::from(&values[13]),
        source:text(15)?.into(), manifest:PathBuf::from(&values[17]), manifest_sha:hash(text(19)?)?};
    if args.source.len()!=40 || !args.source.bytes().all(|b|b.is_ascii_hexdigit())
        || !args.record.is_absolute() || args.record.exists()
        || args.record.components().any(|c|matches!(c,Component::ParentDir|Component::CurDir))
        || args.record.starts_with(&args.driver) || args.driver.starts_with(&args.record)
        || args.record.starts_with(args.vault.path()) || args.vault.path().starts_with(&args.record)
        || args.driver.starts_with(args.vault.path()) || args.vault.path().starts_with(&args.driver) {
        return Err("Passive original roots and new recording must be distinct absolute paths".into());
    }
    plain_original(args.record.parent().ok_or("Passive record parent")?,true)?;
    pinned_file(&args.manifest,args.manifest_sha,16*1024*1024)?;
    Ok(args)
}
/// Read only initialized schema/context/count metadata, never vault ciphertext or preimages.
/// Ordinary storage open validates full schema and sealed integrity afterwards.
fn initialized(path:&Path, app:i64, version:i64, tables:&[&str]) -> Result<rusqlite::Connection> {
    plain_original(path,false)?;
    let size=std::fs::metadata(path).map_err(|e|e.to_string())?.len();
    if size==0 || size>128*1024*1024 {return Err("Passive existing store size bound".into());}
    let db=rusqlite::Connection::open_with_flags(path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e|format!("Passive existing store: {e}"))?;
    db.execute_batch("PRAGMA trusted_schema=OFF; PRAGMA query_only=ON; BEGIN;").map_err(|e|e.to_string())?;
    let a:i64=db.pragma_query_value(None,"application_id",|r|r.get(0)).map_err(|e|e.to_string())?;
    let v:i64=db.pragma_query_value(None,"user_version",|r|r.get(0)).map_err(|e|e.to_string())?;
    let object_count:i64=db.query_row("SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",[],|r|r.get(0)).map_err(|e|e.to_string())?;
    if object_count!=tables.len() as i64 {return Err("Passive initialized object count mismatch".into());}
    // Bound SQLite schema byte widths BEFORE query_map allocates Rust Strings.
    // BLOB byte lengths also reject oversized names containing embedded NULs.
    let oversized:i64=db.query_row("SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' AND (typeof(type)!='text' OR typeof(name)!='text' OR length(CAST(type AS BLOB)) NOT BETWEEN 1 AND 16 OR length(CAST(name AS BLOB)) NOT BETWEEN 1 AND 128)",[],|r|r.get(0)).map_err(|e|e.to_string())?;
    if oversized!=0 {return Err("Passive initialized schema type/name byte bound".into());}
    let mut q=db.prepare("SELECT type,name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
        .map_err(|e|e.to_string())?;
    let objects=q.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,String>(1)?)))
        .map_err(|e|e.to_string())?.collect::<std::result::Result<Vec<_>,_>>().map_err(|e|e.to_string())?;
    if a!=app || v!=version || objects.len()!=tables.len()
        || objects.iter().any(|(kind,name)|kind!="table"||!tables.contains(&name.as_str())) {
        return Err("Passive store must already have its exact initialized application/version/table set".into());
    }
    drop(q); Ok(db)
}
fn scalar(db:&rusqlite::Connection, sql:&str) -> Result<i64> {
    db.query_row(sql,[],|r|r.get(0)).map_err(|e|format!("Passive context/count: {e}"))
}
fn existing_side_stores(args:&Args, genesis:Hash, fingerprint:Hash, network:u32) -> Result<serde_json::Value> {
    // All four preflights complete before ANY custody/cache mutable opener.
    plain_original(&args.vault.custody(),true)?;
    plain_original(&args.vault.path().join("TEST-VALUE-VAULT-ROOT.marker"),false)?;
    let vault=initialized(&args.vault.vault(),crate::store_v2::APP_ID,crate::store_v2::VERSION,
        &["vault_records","vault_pointer"])?;
    if scalar(&vault,"SELECT count(*) FROM vault_pointer WHERE id=1 AND revision>=1 AND active IN (1,2)")?!=1
        || scalar(&vault,"SELECT count(*) FROM vault_records WHERE state=1")?!=1
        || !(1..=2).contains(&scalar(&vault,"SELECT count(*) FROM vault_records")?) {
        return Err("Passive existing vault requires its committed active pointer and record".into());
    }
    let operations=initialized(&args.vault.operation_outbox(),crate::operation_outbox::APPLICATION_ID,
        crate::operation_outbox::SCHEMA_VERSION,&["operation_outbox_context_v1","operation_outbox_records_v1"])?;
    let context:(i64,Vec<u8>,Vec<u8>)=operations.query_row(
        "SELECT network,genesis,fingerprint FROM operation_outbox_context_v1 WHERE id=1",[],
        |r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(|e|e.to_string())?;
    if scalar(&operations,"SELECT count(*) FROM operation_outbox_context_v1")?!=1
        || context.0!=i64::from(network)||context.1!=genesis||context.2!=fingerprint {
        return Err("Passive original operation outbox context mismatch".into());
    }
    let preimages=initialized(&args.vault.preimages(),crate::preimage_store::APPLICATION_ID,
        crate::preimage_store::SCHEMA_VERSION,&["preimage_store_context_v1","preimage_store_records_v1"])?;
    if scalar(&preimages,"SELECT count(*) FROM preimage_store_context_v1 WHERE id=1")?!=1
        || scalar(&preimages,"SELECT count(*) FROM preimage_store_context_v1")?!=1 {
        return Err("Passive original preimage store is not initialized".into());
    }
    let pool=initialized(&args.vault.path().join("public-payment-pool.sqlite"),0x4d554d32,2,
        &["context_v2","basis_v2","lifecycle_v2","inputs_v2","rotations_v2"])?;
    let c:(Vec<u8>,Vec<u8>)=pool.query_row("SELECT genesis,fingerprint FROM context_v2 WHERE id=1",[],
        |r|Ok((r.get(0)?,r.get(1)?))).map_err(|e|e.to_string())?;
    if scalar(&pool,"SELECT count(*) FROM context_v2")?!=1 || c.0!=genesis || c.1!=fingerprint {
        return Err("Passive original payment cache context mismatch".into());
    }
    let count=scalar(&pool,"SELECT count(*) FROM lifecycle_v2")?;
    let outbox_count=scalar(&operations,"SELECT count(*) FROM operation_outbox_records_v1")?;
    let preimage_count=scalar(&preimages,"SELECT count(*) FROM preimage_store_records_v1")?;
    let pool_bytes=scalar(&pool,"SELECT coalesce(sum(length(raw)),0) FROM lifecycle_v2")?;
    let operation_bytes=scalar(&operations,"SELECT coalesce(sum(length(meta)+length(raw)),0) FROM operation_outbox_records_v1")?;
    let preimage_bytes=scalar(&preimages,"SELECT coalesce(sum(length(sealed)),0) FROM preimage_store_records_v1")?;
    if !(0..=65536).contains(&count)||!(0..=4096).contains(&outbox_count)||!(0..=4096).contains(&preimage_count)
        || !(0..=8*1024*1024).contains(&pool_bytes)||!(0..=8*1024*1024).contains(&operation_bytes)
        || !(0..=8*1024*1024).contains(&preimage_bytes) {
        return Err("Passive existing record count bound".into());
    }
    Ok(serde_json::json!({"existing_initialized_stores":4,"payment_cache_rows":count,
        "sealed_operation_rows":outbox_count,"sealed_preimage_rows":preimage_count,
        "scope":"read-only initialized metadata preflight; ordinary opens verify sealed integrity"}))
}
struct PassiveOriginalRestart {
    original:OriginalReplay, wallet:Controller, id:Hash, wire:Vec<u8>,
    descriptor:Vec<u8>, authority:Hash, active:crate::wallet_v2::Identity,
    revision:i64, preflight:serde_json::Value,
}
impl PassiveOriginalRestart {
    fn open(args:&Args) -> Result<Self> {
        if args.wire!=args.driver.join(format!("wire-{}.bin",hex::encode(args.operation))) {
            return Err("Passive wire must be the exact retained original ID path".into());
        }
        // The pinned H0 loader also validates the original start/exe/source/driver
        // associations and every original canonical file before mutable store open.
        // Preflight side stores first using the exact independently pinned H0 context.
        let h0=pinned_file(&args.h0,args.h0_sha,16*1024*1024)?;
        let value:serde_json::Value=serde_json::from_slice(&h0).map_err(|e|e.to_string())?;
        let genesis_text=value["genesis"].as_str().ok_or("Passive H0 Genesis")?;
        if genesis_text.len()>8192||genesis_text.len()%2!=0 {return Err("Passive H0 Genesis bound".into());}
        let genesis_bytes=hex::decode(genesis_text).map_err(|_|"Passive H0 Genesis hex")?;
        let anchor=mutiny_consensus_v8::anchors::FinalizedAnchor::decode(&genesis_bytes)
            .map_err(|e|format!("Passive H0 anchor: {e:?}"))?;
        let preflight=existing_side_stores(args,anchor.genesis,anchor.fingerprint,anchor.network)?;
        chain::marker(args.vault.path(),false)?; // existing root mandatory above; no provisioning branch.
        let wire=read_bounded(&args.wire,2*1024*1024)?;
        let original=OriginalReplay::open(&args.h0,args.h0_sha,&args.driver,&args.vault)?;
        if original.head.height==0 {return Err("Passive original restart requires retained nonzero history".into());}
        original.verify_exact_payment(args.operation,&wire)?;
        let payment=mutiny_consensus_v8::transactions_v2::Transfer::decode(&wire)
            .map_err(|e|format!("Passive original payment descriptor: {e:?}"))?;
        let descriptor=payment.inputs.first().ok_or("Passive original payment has no input")?.descriptor.clone();
        if payment.inputs.iter().any(|i|i.descriptor!=descriptor) {
            return Err("Passive Launch16 mode requires one exact original wallet descriptor".into());
        }
        let (public,generation)=PublicKey::decode_descriptor(&descriptor).map_err(|e|format!("{e:?}"))?;
        if public.role!=Role::WalletOwner||generation!=1 {return Err("Passive Launch16 expected original generation-one owner".into());}
        let authority=public.address_id(generation).map_err(|e|format!("{e:?}"))?;
        if original.initial.wallets.current(authority)!=Some(descriptor.as_slice())
            || payment.inputs.iter().any(|input|original.initial.coins.get(&input.point)
                .is_none_or(|coin|coin.output.owner!=authority)) {
            return Err("Passive exact signed payment does not name its pinned original owner".into());
        }
        let store=Store::open(&args.vault.vault()).map_err(|e|e.to_string())?;
        let status=store.status().map_err(str::to_owned)?.ok_or("Passive existing active vault absent")?;
        if status.active.generation!=generation||status.active.authority_id!=hex::encode(authority)
            || status.active.owner_descriptor!=hex::encode(&descriptor)||status.staged.is_some()||status.superseded.is_some() {
            return Err("Passive Launch16 original active vault identity/pointer mismatch".into());
        }
        let revision=status.revision; let active=status.active; drop(store);
        let chain=CanonicalStore::open_trusted_genesis(&args.vault.path().join("public-chain.sqlite"),
            &original.genesis,&original.initial,original.initial_root,1000,[255;32]).map_err(|e|format!("{e:?}"))?;
        let replica=Replica::from_pinned_chain(chain)?;
        let pool=Mempool::open(&args.vault.path().join("public-payment-pool.sqlite"),
            original.genesis.genesis,original.genesis.fingerprint,65536).map_err(|e|format!("{e:?}"))?;
        let mut wallet=Controller::open(&args.vault,replica,pool,None)?;
        if wallet.identity().is_some() {return Err("Passive controller must initially be locked".into());}
        Ok(Self {original,wallet,id:args.operation,wire,descriptor,authority,active,revision,preflight})
    }
    fn snapshot(&mut self) -> Result<serde_json::Value> {
        if self.wallet.identity()!=Some(&self.active)||self.wallet.profile()!=mutiny_wallet_core_v8::WalletProfile::Ordinary {
            return Err("Passive reverify requires actual unlock of the exact original ordinary identity".into());
        }
        let status=self.wallet.vault_status()?.ok_or("Passive vault disappeared")?;
        if status.revision!=self.revision||status.active!=self.active||status.staged.is_some()||status.superseded.is_some() {
            return Err("Passive original vault pointer changed".into());
        }
        let canonical=self.original.verify_exact_payment(self.id,&self.wire)?;
        let facts=self.wallet.with_view(|v| -> Result<serde_json::Value> {
            if v.anchor().height!=self.original.head.height||v.anchor().block!=self.original.head.block
                || v.state_root()!=self.original.head.root||v.state().wallets.current(self.authority)!=Some(self.descriptor.as_slice()) {
                return Err("Passive controller current authority/head differs from four original replays".into());
            }
            let total=v.state().coins.values().filter(|coin|v.state().wallets.authorize(coin.output.owner,&self.descriptor).is_ok())
                .try_fold(0u64,|sum,coin|sum.checked_add(coin.output.atoms).ok_or("Passive balance overflow"))?;
            Ok(serde_json::json!({"height":v.anchor().height,"block":hex::encode(v.anchor().block),
                "root":hex::encode(v.state_root()),"owned_atoms":total,"owned_atoms_scope":"verified owned coins, not a spendability claim",
                "reserved_inputs":v.reserved().len(),"authority":hex::encode(self.authority),"generation":self.active.generation,
                "current_descriptor_sha256":hex::encode(Sha256::digest(&self.descriptor)),"vault_revision":status.revision}))
        })??;
        let delivery=match self.wallet.delivery(self.id)? {
            Delivery::ConfirmedAt(h) if canonical["own_confirmations"][0]["own_confirmed_height"]==h=>h,
            _=>return Err("Passive actual Controller delivery lacks exact own replay confirmation".into()),
        };
        let queued=self.wallet.queued_operations()?.into_iter().map(|(item,state)|
            serde_json::json!({"id":hex::encode(item.id),"kind":item.kind.title(),"complete":item.complete,"status":state})).collect::<Vec<_>>();
        let pending=self.wallet.pending_for_transport()?.len();
        Ok(serde_json::json!({"canonical":canonical,"controller":facts,"actual_controller_confirmed_at":delivery,
            "reopened_protected_outbox":queued,"pending_payment_count":pending,"existing_preflight":self.preflight,
            "scope":"original-context Controller/custody/outbox reopen with own canonical replay; software public TEST-VALUE only",
            "previous_mounted_partial_reclassified":false,"new_block_capability":false,"physical_backup_qualification":false}))
    }
}
struct PassiveApp {
    backend:PassiveOriginalRestart, recorder:Recorder, player:Player,
    targets:Vec<(String,egui::Rect)>, focused:bool, input_time:Option<f64>, focus_requested:bool,
    start_pending:bool, unlocks:u8, locks:u8, reverifies:u8, started:bool,
    observation:serde_json::Value, error:Option<String>, visual:String,
}
impl eframe::App for PassiveApp {
    fn raw_input_hook(&mut self,ctx:&egui::Context,raw:&mut egui::RawInput) {
        self.focused=raw.focused; self.input_time=raw.time;
        if raw.focused {self.player.inject(raw,&self.targets,ctx.content_rect(),ctx.content_rect());}
    }
    fn ui(&mut self,ui:&mut egui::Ui,_:&mut eframe::Frame) {
        let ctx=ui.ctx().clone(); self.targets.clear();
        let events=ctx.input(|i|i.events.clone());
        if events.iter().any(|e|matches!(e,egui::Event::Key{..}|egui::Event::Text(_)|egui::Event::PointerButton{..})) {
            self.backend.wallet.user_activity();
        }
        if !self.focused&&!self.focus_requested {
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus); self.focus_requested=true;
        }
        let mut image=None;
        for event in &events {if let egui::Event::Screenshot{image:frame,..}=event {
            match self.recorder.screenshot(frame) {Ok(hash)=>image=Some(hash),Err(e)=>self.error=Some(e)}
        }}
        let mut banner=false;
        egui::Panel::top("passive-permanent-testvalue-banner").show(ui,|ui| {
            ui.visuals_mut().override_text_color=Some(egui::Color32::YELLOW);
            ui.visuals_mut().panel_fill=egui::Color32::from_rgb(145,0,120);
            ui.heading("PUBLIC TEST-VALUE. NON-SHIPPING. NOT A REAL WALLET. NO REAL FUNDS.");
            ui.label("Passive restart of original Launch16; no new Genesis or block-signing capability");
            ui.label(PASSIVE_MARKER); banner=true;
        });
        egui::CentralPanel::default().show(ui,|ui| {
            if let Some(error)=&self.error {ui.colored_label(egui::Color32::RED,error);}
            ui.horizontal(|ui| {
                let lock=ui.button("Lock original test identity"); self.targets.push(("host:Passive lock".into(),lock.rect));
                if lock.clicked() {self.backend.wallet.lock();if self.backend.wallet.identity().is_none(){self.locks=self.locks.saturating_add(1);}else{self.error=Some("Passive lock did not erase session".into());}}
                let unlock=ui.button("Unlock existing public test vault");self.targets.push(("host:Passive unlock".into(),unlock.rect));
                if unlock.clicked() {match self.backend.wallet.unlock(chain::PASSWORD) {
                    Ok(()) if self.backend.wallet.identity()==Some(&self.backend.active)=>self.unlocks=self.unlocks.saturating_add(1),
                    Ok(())=>{self.backend.wallet.lock();self.error=Some("Passive actual unlock identity mismatch".into());},
                    Err(e)=>self.error=Some(e),
                }}
                let verify=ui.button("Reverify original own history and outboxes");self.targets.push(("host:Passive reverify".into(),verify.rect));
                if verify.clicked() {match self.backend.snapshot(){Ok(value)=>{self.observation=value;self.reverifies=self.reverifies.saturating_add(1);},Err(e)=>{self.backend.wallet.lock();self.error=Some(e);}}}
            });
            let start=ui.add_enabled(!self.started,egui::Button::new("Run passive reopen controls through native events"));
            self.targets.push(("host:Passive start".into(),start.rect));
            if start.clicked() {match self.player.queue([
                Action::Click("host:Passive unlock".into()),Action::Wait(2),Action::Click("host:Passive reverify".into()),Action::Wait(2),
                Action::Click("host:Passive lock".into()),Action::Wait(2),Action::Click("host:Passive unlock".into()),Action::Wait(2),
                Action::Click("host:Passive reverify".into()),Action::Wait(2)]) {Ok(())=>self.started=true,Err(e)=>self.error=Some(e)}}
            ui.label(format!("Actual controller {}",if self.backend.wallet.identity().is_some(){"unlocked"}else{"locked"}));
            ui.label(format!("Original H{} / block {} / root {}",self.backend.original.head.height,
                hex::encode(self.backend.original.head.block),hex::encode(self.backend.original.head.root)));
            ui.label(format!("Exact original payment {}",hex::encode(self.backend.id)));
            ui.label(format!("Existing wallet checksummed address {}",mutiny_wallet_core_v8::address_format::encode(
                &self.backend.authority,mutiny_wallet_core_v8::ChainClass::TestValue)));
            ui.label(format!("Unlocks {} / locks {} / own-history reverifications {}",self.unlocks,self.locks,self.reverifies));
            if let Some(facts)=self.observation.get("controller") {
                ui.label(format!("Current authority {} / generation {}",facts["authority"],facts["generation"]));
                ui.label(format!("Verified owned coin total {} atoms; {} reserved inputs",facts["owned_atoms"],facts["reserved_inputs"]));
                ui.label(format!("Existing vault revision {} / exact own confirmed height {}",facts["vault_revision"],self.observation["actual_controller_confirmed_at"]));
                ui.label(format!("Reopened operation outbox {} / pending payment count {}",self.observation["reopened_protected_outbox"],self.observation["pending_payment_count"]));
            }
            ui.label("Previous Launch16 mounted attempt remains partial. This mode cannot advance its closed ephemeral certifier.");
        });
        if self.start_pending&&!self.targets.is_empty()&&self.error.is_none() {
            match self.player.queue([Action::Click("host:Passive start".into())]){Ok(())=>self.start_pending=false,Err(e)=>self.error=Some(e)}
        }
        let unlocked=self.backend.wallet.identity().is_some();
        let state=serde_json::json!({"mode":PASSIVE_MARKER,"actual_native_focus":self.focused,
            "native_input_time":self.input_time,"normal_focus_request_sent":self.focus_requested,
            "original_context":self.observation,"original_operation_id":hex::encode(self.backend.id),
            "actual_unlock":unlocked,"unlock_count":self.unlocks,"lock_count":self.locks,"reverify_count":self.reverifies,
            "native_player":{"last_event":self.player.last,"failure":self.player.failure,"done":self.player.done()},
            "passive_widget_controls_complete":self.started&&self.player.done()&&self.player.failure.is_none()
                &&self.error.is_none()&&self.unlocks==2&&self.locks==1&&self.reverifies==2&&unlocked,
            "refusal":self.error,"visible_targets":self.targets.iter().map(|(name,r)|serde_json::json!({"name":name,
                "rect":[r.min.x,r.min.y,r.max.x,r.max.y]})).collect::<Vec<_>>()});
        let mut visual=state.clone();visual.as_object_mut().unwrap().remove("native_input_time");
        let text=visual.to_string();
        if text!=self.visual||self.recorder.frame==0 {ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(Default::default()));self.visual=text;}
        if let Err(e)=self.recorder.append(banner,&format!("{events:?}"),state,image){self.backend.wallet.lock();self.error=Some(e);}
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}
pub fn run_if_requested() -> Option<eframe::Result> {
    let values=std::env::args_os().skip(1).collect::<Vec<_>>();
    if values.first().is_none_or(|v|v!="--passive-original-restart"){return None;}
    Some((|| -> Result<()> {
        if mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED||mutiny_crypto_v2::RELEASE_CUSTODY_ENABLED {
            return Err("Passive public TEST-VALUE requires closed production gates".into());
        }
        let args=parse(&values)?; let backend=PassiveOriginalRestart::open(&args)?;
        let title=format!("MUTINY PUBLIC TEST-VALUE PASSIVE ORIGINAL RESTART - NON-SHIPPING - pid {}",std::process::id());
        let returned=title.clone();
        eframe::run_native(&title,eframe::NativeOptions{viewport:egui::ViewportBuilder::default().with_inner_size([1150.,850.]),..Default::default()},
            Box::new(move|cc|{
                use raw_window_handle::{HasWindowHandle,RawWindowHandle};
                use windows_sys::Win32::UI::WindowsAndMessaging::{GetWindowTextW,SetWindowDisplayAffinity,WDA_EXCLUDEFROMCAPTURE};
                let RawWindowHandle::Win32(handle)=cc.window_handle()?.as_raw() else{return Err("Native Windows passive viewport required".into());};
                if unsafe{SetWindowDisplayAffinity(handle.hwnd.get() as *mut _,WDA_EXCLUDEFROMCAPTURE)}==0{return Err("Cannot protect passive viewport affinity".into());}
                let mut observed=[0u16;256];let n=unsafe{GetWindowTextW(handle.hwnd.get() as *mut _,observed.as_mut_ptr(),256)};
                if n<=0||String::from_utf16(&observed[..n as usize])?!=returned{return Err("Passive actual HWND/title mismatch".into());}
                let recorder=Recorder::new(&args.record,args.source,&args.manifest,handle.hwnd.get() as usize,returned)?;
                Ok(Box::new(PassiveApp{backend,recorder,player:Player::default(),targets:Vec::new(),focused:false,
                    input_time:None,focus_requested:false,start_pending:true,unlocks:0,locks:0,reverifies:0,started:false,
                    observation:serde_json::Value::Null,error:None,visual:String::new()}))
            })).map_err(|e|e.to_string())?;
        Ok(())
    })().map_err(|e|eframe::Error::AppCreation(e.into())))
}

#[cfg(test)]
mod passive_metadata_preflight_tests {
    use super::*;
    #[test]
    fn initialized_metadata_is_read_only_and_refuses_missing_empty_uninitialized_or_oversized_names() {
        let unique=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let base=std::env::temp_dir().join(format!("w15-passive-metadata-{}-{unique}",std::process::id()));
        assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
        let positive=base.join("positive.sqlite");
        let db=rusqlite::Connection::open(&positive).unwrap();
        db.execute_batch("CREATE TABLE fixture_table(value INTEGER); PRAGMA application_id=12345; PRAGMA user_version=1;").unwrap();
        drop(db);
        let original=std::fs::read(&positive).unwrap();
        let checked=initialized(&positive,12345,1,&["fixture_table"]).unwrap();
        assert!(checked.execute("INSERT INTO fixture_table VALUES(1)",[]).is_err());
        drop(checked);assert_eq!(std::fs::read(&positive).unwrap(),original);
        let missing=base.join("missing.sqlite");
        assert!(initialized(&missing,12345,1,&["fixture_table"]).is_err());assert!(!missing.exists());
        let empty=base.join("empty.sqlite");std::fs::write(&empty,[]).unwrap();
        assert!(initialized(&empty,12345,1,&["fixture_table"]).is_err());assert_eq!(std::fs::metadata(&empty).unwrap().len(),0);
        let uninitialized=base.join("uninitialized.sqlite");
        let db=rusqlite::Connection::open(&uninitialized).unwrap();db.execute_batch("CREATE TABLE fixture_table(value INTEGER);").unwrap();drop(db);
        let original=std::fs::read(&uninitialized).unwrap();
        assert!(initialized(&uninitialized,12345,1,&["fixture_table"]).is_err());assert_eq!(std::fs::read(&uninitialized).unwrap(),original);
        let oversized=base.join("oversized-schema-name.sqlite");
        let db=rusqlite::Connection::open(&oversized).unwrap();
        db.execute_batch(&format!("CREATE TABLE {}(value INTEGER); PRAGMA application_id=12345; PRAGMA user_version=1;","n".repeat(129))).unwrap();drop(db);
        let original=std::fs::read(&oversized).unwrap();
        assert!(initialized(&oversized,12345,1,&["fixture_table"]).err().unwrap().contains("schema type/name byte bound"));
        assert_eq!(std::fs::read(&oversized).unwrap(),original);
        // All TEST-owned evidence survives; no removal/ACL repair of originals.
    }


    // PUBLIC TEST metadata models only. They are deliberately not sealed custody
    // stores and are never passed to Controller or qualified as canonical history.
    fn metadata_model(base:&Path, fault:Option<(usize,u8)>) -> Args {
        use mutiny_consensus_v8::submission_pool_v1::private_directory;
        assert!(private_directory(base).unwrap());
        let root=VaultRoot::new(base).unwrap();
        assert!(private_directory(&root.custody()).unwrap());
        std::fs::write(base.join("TEST-VALUE-VAULT-ROOT.marker"),b"PUBLIC TEST METADATA ONLY").unwrap();
        let args=Args{h0:base.join("unused-h0"),h0_sha:[0;32],driver:base.join("unused-driver"),
            vault:root,operation:[0;32],wire:base.join("unused-wire"),record:base.join("unused-record"),
            source:String::new(),manifest:base.join("unused-manifest"),manifest_sha:[0;32]};
        let specs=[
            (args.vault.vault(),crate::store_v2::APP_ID,crate::store_v2::VERSION,
             "CREATE TABLE vault_records(state INTEGER); INSERT INTO vault_records VALUES(1); CREATE TABLE vault_pointer(id INTEGER, revision INTEGER, active INTEGER); INSERT INTO vault_pointer VALUES(1,1,1);"),
            (args.vault.operation_outbox(),crate::operation_outbox::APPLICATION_ID,crate::operation_outbox::SCHEMA_VERSION,
             "CREATE TABLE operation_outbox_context_v1(id INTEGER,network INTEGER,genesis BLOB,fingerprint BLOB); CREATE TABLE operation_outbox_records_v1(meta BLOB,raw BLOB);"),
            (args.vault.preimages(),crate::preimage_store::APPLICATION_ID,crate::preimage_store::SCHEMA_VERSION,
             "CREATE TABLE preimage_store_context_v1(id INTEGER); INSERT INTO preimage_store_context_v1 VALUES(1); CREATE TABLE preimage_store_records_v1(sealed BLOB);"),
            (args.vault.path().join("public-payment-pool.sqlite"),0x4d554d32,2,
             "CREATE TABLE context_v2(id INTEGER,genesis BLOB,fingerprint BLOB); CREATE TABLE basis_v2(value INTEGER); CREATE TABLE lifecycle_v2(raw BLOB); CREATE TABLE inputs_v2(value INTEGER); CREATE TABLE rotations_v2(value INTEGER);")];
        for (i,(path,app,version,sql)) in specs.iter().enumerate() {
            if fault==Some((i,0)) {continue;} // Missing NEW TEST file remains absent.
            if fault==Some((i,1)) {std::fs::write(path,[]).unwrap();continue;}
            let db=rusqlite::Connection::open(path).unwrap();db.execute_batch(sql).unwrap();
            if i==1 {db.execute("INSERT INTO operation_outbox_context_v1 VALUES(1,7,?1,?2)",
                rusqlite::params![[8u8;32].as_slice(),[9u8;32].as_slice()]).unwrap();}
            if i==3 {db.execute("INSERT INTO context_v2 VALUES(1,?1,?2)",
                rusqlite::params![[8u8;32].as_slice(),[9u8;32].as_slice()]).unwrap();}
            if fault!=Some((i,2)) {
                db.pragma_update(None,"application_id",app).unwrap();
                db.pragma_update(None,"user_version",version).unwrap();
            }
        }
        args
    }
    fn metadata_bytes(args:&Args) -> Vec<(PathBuf,Option<Vec<u8>>)> {
        [args.vault.vault(),args.vault.operation_outbox(),args.vault.preimages(),
            args.vault.path().join("public-payment-pool.sqlite")].into_iter()
            .map(|p|{let bytes=if p.exists(){Some(std::fs::read(&p).unwrap())}else{None};(p,bytes)}).collect()
    }
    fn assert_metadata_unchanged(before:&[(PathBuf,Option<Vec<u8>>)]) {
        for (p,bytes) in before {match bytes {
            Some(expected)=>assert_eq!(&std::fs::read(p).unwrap(),expected,"{}",p.display()),
            None=>assert!(!p.exists(),"{} was initialized",p.display()),
        }}
    }
    #[test]
    fn all_four_side_stores_refuse_each_missing_empty_or_uninitialized_model_without_initializing() {
        let stamp=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let base=std::env::temp_dir().join(format!("w15-passive-four-stores-{}-{stamp}",std::process::id()));
        assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
        for index in 0..4 {for fault in 0..3 {
            let positive=metadata_model(&base.join(format!("positive-{index}-{fault}")),None);
            let before=metadata_bytes(&positive);
            let ok=existing_side_stores(&positive,[8;32],[9;32],7).unwrap();
            assert_eq!(ok["existing_initialized_stores"],4);assert_metadata_unchanged(&before);
            let negative=metadata_model(&base.join(format!("negative-{index}-{fault}")),Some((index,fault)));
            let before=metadata_bytes(&negative);
            let err=existing_side_stores(&negative,[8;32],[9;32],7).unwrap_err();
            if fault==1 {assert!(err.contains("store size bound"),"{err}");}
            if fault==2 {assert!(err.contains("initialized application/version/table set"),"{err}");}
            assert_metadata_unchanged(&before);
        }}
    }
    #[test]
    fn initialized_side_stores_refuse_wrong_context_and_non_singleton_pointer_read_only() {
        let stamp=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
        let base=std::env::temp_dir().join(format!("w15-passive-context-{}-{stamp}",std::process::id()));
        assert!(mutiny_consensus_v8::submission_pool_v1::private_directory(&base).unwrap());
        let model=metadata_model(&base.join("positive"),None);
        let before=metadata_bytes(&model);
        existing_side_stores(&model,[8;32],[9;32],7).unwrap();
        for (genesis,fingerprint,network) in [([0;32],[9;32],7),([8;32],[0;32],7),([8;32],[9;32],8)] {
            assert!(existing_side_stores(&model,genesis,fingerprint,network).unwrap_err()
                .contains("operation outbox context mismatch"));
        }
        assert_metadata_unchanged(&before);
        // Isolate the payment context after a good outbox context.
        let payment=metadata_model(&base.join("payment-context"),None);
        let db=rusqlite::Connection::open(payment.vault.path().join("public-payment-pool.sqlite")).unwrap();
        db.execute("UPDATE context_v2 SET fingerprint=?1",rusqlite::params![[0u8;32].as_slice()]).unwrap();drop(db);
        let before=metadata_bytes(&payment);
        assert!(existing_side_stores(&payment,[8;32],[9;32],7).unwrap_err().contains("payment cache context mismatch"));
        assert_metadata_unchanged(&before);
        let pointer=metadata_model(&base.join("vault-pointer"),None);
        let db=rusqlite::Connection::open(pointer.vault.vault()).unwrap();
        db.execute("INSERT INTO vault_pointer VALUES(1,2,2)",[]).unwrap();drop(db);
        let before=metadata_bytes(&pointer);
        assert!(existing_side_stores(&pointer,[8;32],[9;32],7).unwrap_err().contains("committed active pointer"));
        assert_metadata_unchanged(&before);
    }

}
