//! Actual native window over the real controller; screenshots come from the rendered viewport.
use crate::{
    chain,
    native_driver::NativeDriver,
    operation_screens::WalletUi,
    player::{Action, Player},
    recorder::Recorder,
    wallet_controller_v2::{Controller, VaultRoot},
};
use eframe::egui;
use sha2::Digest;
use std::{ffi::OsString, path::PathBuf};
pub const MARKER: &str = "MUTINY-WALLET-V8-TESTVALUE-WINDOW-V1";
struct Args {
    vault: VaultRoot,
    record: PathBuf,
    source: String,
    manifest: PathBuf,
    driver: PathBuf,
    payment_scenario: bool,
}
fn args() -> Result<Args, String> {
    let values = std::env::args_os().skip(1).collect::<Vec<_>>();
    let (required, payment_scenario) = match values.as_slice() {
        required if required.len() == 10 => (required, false),
        all if all.len() == 12 && all[10] == "--scenario" && all[11] == "payment" =>
            (&all[..10], true),
        _ => return Err("Only the five explicit roots/identity pairs and optional --scenario payment are accepted".into()),
    };
    let [
        vault_flag,
        vault,
        record_flag,
        record,
        source_flag,
        source,
        manifest_flag,
        manifest,
        driver_flag,
        driver,
    ] = required
    else {
        return Err("Explicit --vault-root, --record-root, --source-id, --source-manifest and --driver-root are required".into());
    };
    if vault_flag != "--vault-root"
        || record_flag != "--record-root"
        || source_flag != "--source-id"
        || manifest_flag != "--source-manifest"
        || driver_flag != "--driver-root"
    {
        return Err("Unexpected TEST-VALUE arguments".into());
    }
    let vault = VaultRoot::from_args(&[OsString::from("--vault-root"), vault.clone()])
        .map_err(|e| e.to_string())?;
    let record = PathBuf::from(record);
    if !record.is_absolute()
        || record.starts_with(vault.path())
        || vault.path().starts_with(&record)
    {
        return Err("Record root and vault root must be separate absolute folders".into());
    }
    let driver = PathBuf::from(driver);
    let manifest = PathBuf::from(manifest);
    if !driver.is_absolute()
        || !manifest.is_absolute()
        || driver.starts_with(vault.path())
        || vault.path().starts_with(&driver)
        || driver.starts_with(&record)
        || record.starts_with(&driver)
    {
        return Err("Driver, vault and record directories must be separate absolute paths".into());
    }
    Ok(Args {
        vault,
        record,
        source: source.to_str().ok_or("Source identity Unicode")?.into(),
        manifest,
        driver,
        payment_scenario,
    })
}
// Nonshipping native viewport layout. Keep the first and final widgets completely
// inside the actual ScrollArea clip rectangle, including fractional DPI rounding.
// The player still requires the entire actual widget rectangle to be visible.
fn show_native_screens(ui: &mut egui::Ui, content: impl FnOnce(&mut egui::Ui)) -> egui::Rect {
    egui::ScrollArea::vertical()
        .show(ui, |ui| {
            ui.add_space(4.0);
            content(ui);
            ui.add_space(4.0);
        })
        .inner_rect
}

struct App {
    wallet: Controller,
    screens: WalletUi,
    recorder: Recorder,
    treasury: bool,
    message: Option<String>,
    last_state: String,
    rehearsal: serde_json::Value,
    driver: NativeDriver,
    player: Player,
    targets: Vec<(String, egui::Rect)>,
    payment_stage: u8,
    payment_operation: Option<String>,
    payment_start_pending: bool,
    native_focused: bool,
    native_focus_requested: bool,
    native_input_time: Option<f64>,
    scroll_rect: egui::Rect,
    /// The window has been fitted to the actual monitor once.
    fitted_to_monitor: bool,
}
/// The size this window asks for, and what it may keep on a monitor of `monitor` points:
/// never wider or taller than the monitor less room for the title bar and the taskbar.
const WANTED_INNER_SIZE: [f32; 2] = [1150., 850.];
fn inner_size_for_monitor(monitor: egui::Vec2) -> egui::Vec2 {
    egui::vec2(
        WANTED_INNER_SIZE[0].min((monitor.x - 40.).max(480.)),
        WANTED_INNER_SIZE[1].min((monitor.y - 120.).max(360.)),
    )
}
impl App {
    fn rotation_review(&mut self) -> Result<(), String> {
        let generation = self
            .wallet
            .identity()
            .ok_or("Unlock the public identity")?
            .generation;
        let next = generation.checked_add(1).ok_or("Generation overflow")?;
        if next != 2 {
            return Err("This public rehearsal defines only the first rotation".into());
        }
        let restored = crate::wallet_v2::RestoredKey::restore(chain::rotation_phrase(), next, None)
            .map_err(str::to_owned)?;
        let descriptor = restored.descriptor().to_vec();
        let repeated = crate::wallet_v2::RestoredKey::restore(
            chain::rotation_phrase(),
            next,
            Some(&descriptor),
        )
        .map_err(str::to_owned)?;
        self.rehearsal = serde_json::json!({"flow":"public TEST-VALUE clean phrase restore before R1","generation":next,"descriptor":hex::encode(&descriptor),"fingerprint":hex::encode(repeated.fingerprint()),"result":"exact descriptor reproduced","backup_media":"not exercised"});
        self.wallet
            .begin_rotation(chain::PASSWORD, chain::rotation_phrase(), &descriptor, 16)?;
        self.screens.present_current(&mut self.wallet);
        Ok(())
    }
    fn destination_review(&mut self) -> Result<(), String> {
        if !self.treasury {
            return Err("Separate Treasury host required".into());
        }
        let me = self
            .wallet
            .signer_identity()
            .ok_or("Unlock current Treasury authority")?;
        if me.generation() != 2 {
            return Err("R2 requires the canonical R1 and exact new public key first".into());
        }
        let restored = crate::wallet_v2::RestoredKey::restore(
            chain::rotation_phrase(),
            2,
            Some(me.descriptor()),
        )
        .map_err(str::to_owned)?;
        let authority = self
            .wallet
            .with_view(|v| {
                v.treasury()
                    .map(|t| t.authority())
                    .ok_or("Treasury missing")
            })?
            .map_err(str::to_owned)?;
        self.rehearsal = serde_json::json!({"flow":"public TEST-VALUE exact new Treasury authority restore before R2","authority":hex::encode(authority),"descriptor":hex::encode(restored.descriptor()),"fingerprint":hex::encode(restored.fingerprint()),"result":"exact current descriptor reproduced","backup_media":"not exercised"});
        self.wallet
            .request(mutiny_wallet_core_v8::OperationRequest::TreasuryRotate(
                mutiny_wallet_core_v8::TreasuryRotateRequest::new(
                    mutiny_wallet_core_v8::Blob::new(restored.descriptor().to_vec()),
                )
                .with_verified_restore(authority, restored.fingerprint())
                .with_treasury(authority)
                .with_validity_blocks(16),
            ))?;
        self.screens.present_current(&mut self.wallet);
        Ok(())
    }
}
impl eframe::App for App {
    fn raw_input_hook(&mut self, ctx: &egui::Context, raw: &mut egui::RawInput) {
        // This is the native integration's observed focus, never a fabricated event.
        // Keep queued test events pending until this actual window can receive input.
        self.native_focused = raw.focused;
        self.native_input_time = raw.time;
        if !raw.focused {
            return;
        }
        self.player
            .inject(raw, &self.targets, ctx.content_rect(), self.scroll_rect);
    }
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // On a high-DPI display the requested size can exceed the screen. Fit the window to the
        // monitor the system actually reports, once, and place it at the top-left corner.
        if !self.fitted_to_monitor {
            if let Some(monitor) = ctx.input(|i| i.viewport().monitor_size) {
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(inner_size_for_monitor(
                    monitor,
                )));
                ctx.send_viewport_cmd(egui::ViewportCommand::OuterPosition(egui::pos2(8., 8.)));
                self.fitted_to_monitor = true;
            }
        }
        self.targets.clear();
        let events = ctx.input(|i| i.events.clone());
        if events.iter().any(|event| {
            matches!(
                event,
                egui::Event::Key { .. } | egui::Event::Text(_) | egui::Event::PointerButton { .. }
            )
        }) {
            self.wallet.user_activity();
        }
        let mut screenshot = None;
        for event in &events {
            if let egui::Event::Screenshot { image, .. } = event {
                match self.recorder.screenshot(image) {
                    Ok(hash) => screenshot = Some(hash),
                    Err(e) => self.message = Some(e),
                }
            }
        }
        let mut banner = false;
        egui::Panel::top("permanent-testvalue-banner").show(ui, |ui| {
            ui.visuals_mut().override_text_color = Some(egui::Color32::YELLOW);
            ui.visuals_mut().panel_fill = egui::Color32::from_rgb(145, 0, 120);
            ui.heading(
                "TEST-VALUE. NOT A REAL WALLET. PUBLIC TEST KEYS. NO REAL FUNDS. NON-SHIPPING.",
            );
            ui.label(if self.treasury {
                "Separate Treasury rehearsal host â€” immutable TEST-VALUE authority"
            } else {
                "Mounted public TEST-VALUE wallet"
            });
            ui.label(MARKER);
            banner = true;
        });
        egui::CentralPanel::default().show(ui,|ui|{
   if let Some(message)=&self.message{ui.colored_label(egui::Color32::RED,message);}
   ui.horizontal(|ui|{
    let lock=ui.button("Lock");self.targets.push(("host:Lock".into(),lock.rect));
    if lock.clicked(){self.wallet.lock();self.message=Some("Vault locked; review authorization withdrawn".into());}
    let unlock=ui.button("Unlock public test identity");self.targets.push(("host:Unlock".into(),unlock.rect));
    if unlock.clicked(){self.message=self.wallet.unlock(chain::PASSWORD).err();}
    if ui.button("Record rendered screenshot").clicked(){ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(Default::default()));}
   });
   let start=ui.button("Run fixed public payment through native UI events");
   self.targets.push(("host:Start payment scenario".into(),start.rect));
   if start.clicked() {
       if self.treasury {self.message=Some("Payment scenario belongs to the separate ordinary TEST-VALUE wallet".into());}
       else {
           let actions=[Action::Click("form:MUT payment".into()),Action::Wait(3),
               Action::Text{target:"field:Recipient checksummed address".into(),value:self.driver.recipient_display()},
               Action::Text{target:"field:Amount (MUT)".into(),value:"0.01".into()},
               Action::Click("button:Review".into()),Action::Wait(3)];
           match self.player.queue(actions) {Ok(())=>self.payment_stage=1,Err(e)=>self.message=Some(e)}
       }
   }
   let deliver=ui.button("Deliver exact queued bytes through authenticated TCP");
   self.targets.push(("host:Deliver exact queue".into(),deliver.rect));
   if deliver.clicked() {
       let pending=self.wallet.pending_for_transport();
       let operations=self.wallet.queued_operations();
       self.message=(|| -> Result<(),String> {
           for raw in pending? {
               let (_,id)=mutiny_consensus_v8::operation_index_v2::operation_id(0,&raw).map_err(|e|format!("{e:?}"))?;
               self.driver.deliver(&mut self.wallet,id,true)?;
           }
           for (item,status) in operations? {
               // `queued_operations` reports wallet-core's `OutboxStatus` by its Debug name; the
               // open, deliverable state is `Queued` (there is no `Pending` variant).
               if item.complete && status=="Queued" && !matches!(item.kind,
                   mutiny_wallet_core_v8::OperationKind::MakerOffer|mutiny_wallet_core_v8::OperationKind::TreasuryFreezeOffer) {
                   self.driver.deliver(&mut self.wallet,item.id,false)?;
               }
           }
           Ok(())
       })().err();
   }
   let certify=ui.button("Certify and install actual next TEST-VALUE block");
   self.targets.push(("host:Certify actual block".into(),certify.rect));
   if certify.clicked() {self.message=self.driver.certify_next(&mut self.wallet).err();}
   ui.label(format!("Explicit test-chain action: {}",self.driver.last.get("action").and_then(serde_json::Value::as_str).unwrap_or("Public initial TEST-VALUE model opened; no delivery or certified block yet")));
   ui.label(format!("Native payment sequence stage {}; last event: {}", self.payment_stage, self.player.last.as_deref().unwrap_or("none")));
   if let Some(error)=&self.player.failure {ui.colored_label(egui::Color32::RED,error);}
   let public_status=self.wallet.with_view(|v|(v.anchor().height,v.class())).map(|(height,class)|format!("Verified height {height}; {}",class.label()));
   match public_status {Ok(text)=>{ui.label(text);},Err(e)=>{ui.colored_label(egui::Color32::RED,e);}}
   if ui.button(if self.treasury { "Review R1 public authority rotation" } else { "Review public wallet rotation" }).clicked() {
       self.message = self.rotation_review().err();
   }
   if self.treasury && ui.button("Restore exact current key and review R2 destination rotation").clicked() {
       self.message = self.destination_review().err();
   }
   if ui.button("Replace vault after own canonical rotation").clicked() {
       // Show the outcome either way: `.err()` alone discarded the success text.
       self.message = Some(match self.wallet.replace_vault(chain::PASSWORD, chain::rotation_phrase()) {
           Ok(_) => "Vault replaced after own canonical verification; old identity retained".to_owned(),
           Err(refusal) => refusal,
       });
   }
   if self.treasury {
       match self.wallet.with_view(|v| {
           let t = v.treasury().ok_or("Treasury missing")?;
           let c = mutiny_consensus_v8::trading_v1::Context {network:v.anchor().network,genesis:v.anchor().genesis,fingerprint:v.anchor().fingerprint};
           let d = mutiny_consensus_v8::trading_v1::treasury_current(v.state(),&c,t.authority()).map_err(|_| "Treasury destination invalid")?;
           Ok::<_, &'static str>(format!("Immutable T {} | destination generation {} | effective block {} | outstanding dividend reserve {} atoms",hex::encode(t.authority()), d.generation, d.effective_height, v.state().dividends.reserved()))
       }) {
           Ok(Ok(text)) => {ui.label(text);}, Ok(Err(e)) => {ui.colored_label(egui::Color32::RED,e);}, Err(e) => {ui.colored_label(egui::Color32::RED,e);}
       }
   }
   match self.wallet.queued_operations() {
       Ok(items) => {for (item,status) in items {ui.label(format!("Local outbox {} | {} | complete={} | {}",hex::encode(item.id),item.kind.title(),item.complete,status));}},
       Err(e) => {ui.colored_label(egui::Color32::RED,e);}
   }
   ui.label("Local queue/export, authenticated node admission and own certified replay confirmation are separately recorded. A peer ACK or pending entry cannot confirm an operation.");
   self.scroll_rect=show_native_screens(ui,|ui|self.screens.show_branded(ui,&mut self.wallet));
  });
        self.targets.extend(self.screens.native_targets());
        // Explicit nonshipping startup only queues a raw click at a widget rendered
        // by the previous frame. The existing button handler owns the same sequence.
        if self.payment_start_pending
            && self
                .targets
                .iter()
                .any(|(name, _)| name == "host:Start payment scenario")
        {
            if !self.native_focused {
                // Ordinary request to the real own viewport, not a fake focus event.
                // The raw-input guard still waits if the operating system refuses.
                ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                self.native_focus_requested = true;
            }
            self.message = self
                .player
                .queue([Action::Click("host:Start payment scenario".into())])
                .err();
            self.payment_start_pending = false;
        }
        if self.player.done() && self.player.failure.is_none() {
            if let Ok(Some(screen)) = self.wallet.screen() {
                if self.payment_stage == 1 {
                    if let Some(index) = screen.review.destinations_needing_check().first() {
                        self.message = self
                            .player
                            .queue([
                                Action::Text {
                                    target: format!("destination:{index}"),
                                    value: "BADTAIL!".into(),
                                },
                                Action::Wait(3),
                            ])
                            .err();
                        self.payment_stage = 2;
                    } else {
                        self.player.failure =
                            Some("Public payment expected an external destination check".into());
                    }
                } else if self.payment_stage == 2 {
                    if screen.status.ready || screen.status.refusal.is_none() {
                        self.player.failure = Some(
                            "Wrong typed address tail did not leave a refused/disabled gate".into(),
                        );
                    } else {
                        let mut actions = Vec::new();
                        for index in screen.review.destinations_needing_check() {
                            actions.push(Action::Text {
                                target: format!("destination:{index}"),
                                value: screen.review.destination_check_text(index),
                            });
                        }
                        for ack in screen.review.acknowledgements() {
                            actions.push(Action::Click(format!("ack:{ack:?}")));
                        }
                        if let Some(phrase) = screen.review.confirmation_phrase() {
                            actions.push(Action::Text {
                                target: "phrase".into(),
                                value: phrase.into(),
                            });
                        }
                        actions.push(Action::Click("button:Authorize".into()));
                        actions.push(Action::Wait(3));

                        self.message = self.player.queue(actions).err();
                        self.payment_stage = 3;
                    }
                }
            }
        }
        // Advance the rehearsal only after observing the previous real widget's
        // effect. A queued click or an empty certified block cannot qualify payment.
        if self.player.done() && self.player.failure.is_none() {
            match self.payment_stage {
                3 => match self.wallet.pending_for_transport() {
                    Ok(rows) if rows.len() == 1 => {
                        match mutiny_consensus_v8::operation_index_v2::operation_id(0, &rows[0]) {
                            Ok((_, id)) => {
                                self.payment_operation = Some(hex::encode(id));
                                self.message = self
                                    .player
                                    .queue([
                                        Action::Click("host:Deliver exact queue".into()),
                                        Action::Wait(3),
                                    ])
                                    .err();
                                self.payment_stage = 4;
                            }
                            Err(e) => {
                                self.player.failure = Some(format!(
                                    "Authorized payment has invalid native identity: {e:?}"
                                ))
                            }
                        }
                    }
                    Ok(rows) => {
                        self.player.failure = Some(format!(
                            "Native Authorize did not produce exactly one payment: {} queued",
                            rows.len()
                        ))
                    }
                    Err(e) => self.player.failure = Some(e),
                },
                4 => {
                    let accepted = self.driver.last["action"]
                        == "real authenticated TCP/durable admission"
                        && self.driver.last["id"].as_str() == self.payment_operation.as_deref()
                        && self.driver.last["confirmed"] == false
                        && self.driver.last["wallet_own_confirmation_height"].is_null();
                    if accepted {
                        self.message = self
                            .player
                            .queue([
                                Action::Click("host:Certify actual block".into()),
                                Action::Wait(3),
                            ])
                            .err();
                        self.payment_stage = 5;
                    } else {
                        self.player.failure = Some("Native delivery lacks the exact payment admission/absence-of-confirmation evidence".into());
                    }
                }
                5 => {
                    let confirmed = self.driver.last["own_confirmations"]
                        .as_array()
                        .is_some_and(|rows| {
                            rows.iter().any(|row| {
                                row["id"].as_str() == self.payment_operation.as_deref()
                                    && row["own_confirmed_height"].as_u64().is_some()
                                    && row["own_confirmed_height"] == self.driver.last["height"]
                            })
                        });
                    if confirmed
                        && self.driver.last["action"]
                            == "real certified history installed in four independent stores"
                    {
                        self.payment_stage = 6;
                    } else {
                        self.player.failure = Some("Native certification lacks the exact payment's own-replay confirmation".into());
                    }
                }
                _ => {}
            }
        }
        let screen = self.wallet.screen();
        let mut state = match screen {
            Ok(Some(s)) => {
                serde_json::json!({"review":s.review.render_text(),"gate":format!("{:?}",s.status)})
            }
            Ok(None) => serde_json::json!({"review":null}),
            Err(e) => serde_json::json!({"refusal":e}),
        };
        state["native_focused"] = serde_json::json!(self.native_focused);
        state["native_focus_requested"] = serde_json::json!(self.native_focus_requested);
        state["native_input_time"] = serde_json::json!(self.native_input_time);
        state["host_message"] = serde_json::json!(self.message);
        state["restore_rehearsal"] = self.rehearsal.clone();
        state["pixels_per_point"] = serde_json::json!(ctx.pixels_per_point());
        state["scroll_viewport"] = serde_json::json!([
            self.scroll_rect.min.x,
            self.scroll_rect.min.y,
            self.scroll_rect.max.x,
            self.scroll_rect.max.y
        ]);
        state["native_driver"] = self.driver.last.clone();
        state["native_player"] = serde_json::json!({"last_event":self.player.last,"failure":self.player.failure,"done":self.player.done(),"payment_stage":self.payment_stage,"payment_operation":self.payment_operation});
        state["visible_targets"] = serde_json::json!(self.targets.iter().map(|(name,r)|serde_json::json!({"name":name,"rect":[r.min.x,r.min.y,r.max.x,r.max.y]})).collect::<Vec<_>>());
        state["queued_operations"] = serde_json::json!(self.wallet.queued_operations().ok().map(|rows|rows.into_iter().map(|(item,status)|serde_json::json!({"id":hex::encode(item.id),"kind":item.kind.title(),"complete":item.complete,"status":status})).collect::<Vec<_>>()));
        state["pending_payments"] =
            serde_json::json!(self.wallet.pending_for_transport().ok().map(|rows| {
                rows.into_iter()
                    .map(|raw| hex::encode(sha2::Sha256::digest(raw)))
                    .collect::<Vec<_>>()
            }));
        // Raw native time remains in every transcript row. It is not a visual
        // change and must not cause an identical framebuffer capture every frame.
        let mut visual_state = state.clone();
        visual_state
            .as_object_mut()
            .unwrap()
            .remove("native_input_time");
        let state_text = visual_state.to_string();
        if state_text != self.last_state || self.recorder.frame == 0 {
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(Default::default()));
            self.last_state = state_text;
        }
        if let Err(error) = self
            .recorder
            .append(banner, &format!("{events:?}"), state, screenshot)
        {
            self.message = Some(error);
            self.wallet.lock();
        }
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}
pub fn run(treasury: bool) -> eframe::Result {
    if mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED {
        return Err(eframe::Error::AppCreation(
            "TEST-VALUE tool requires closed production qualification".into(),
        ));
    }
    let args = args().map_err(|e| eframe::Error::AppCreation(e.into()))?;
    if treasury && args.payment_scenario {
        return Err(eframe::Error::AppCreation(
            "--scenario payment belongs only to the separate ordinary TEST-VALUE wallet".into(),
        ));
    }
    chain::marker(args.vault.path(), treasury).map_err(|e| eframe::Error::AppCreation(e.into()))?;
    let driver =
        NativeDriver::new(&args.driver).map_err(|e| eframe::Error::AppCreation(e.into()))?;
    let (genesis, initial) = driver.initial();
    let wallet = chain::open(&args.vault, treasury, genesis, initial)
        .map_err(|e| eframe::Error::AppCreation(e.into()))?;
    let title = format!(
        "MUTINY TEST-VALUE {} - NOT A REAL WALLET - NON-SHIPPING - pid {}",
        if treasury { "TREASURY" } else { "WALLET" },
        std::process::id()
    );
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size(WANTED_INNER_SIZE),
        ..Default::default()
    };
    let returned_title = title.clone();
    eframe::run_native(
        &title,
        options,
        Box::new(move |cc| {
            use raw_window_handle::{HasWindowHandle, RawWindowHandle};
            use windows_sys::Win32::UI::WindowsAndMessaging::{
                GetWindowTextW, SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE,
            };
            let RawWindowHandle::Win32(handle) = cc.window_handle()?.as_raw() else {
                return Err("Native Windows test window required".into());
            };
            if unsafe {
                SetWindowDisplayAffinity(handle.hwnd.get() as *mut _, WDA_EXCLUDEFROMCAPTURE)
            } == 0
            {
                return Err("Cannot protect TEST-VALUE window capture affinity".into());
            }
            let mut observed_title = [0u16; 256];
            let observed_len = unsafe {
                GetWindowTextW(
                    handle.hwnd.get() as *mut _,
                    observed_title.as_mut_ptr(),
                    256,
                )
            };
            if observed_len <= 0 {
                return Err("Cannot observe actual native window title".into());
            }
            let actual_title = String::from_utf16(&observed_title[..observed_len as usize])?;
            if actual_title != returned_title {
                return Err("Actual native window title differs from rehearsal identity".into());
            }
            let recorder = Recorder::new(
                &args.record,
                args.source,
                &args.manifest,
                handle.hwnd.get() as usize,
                actual_title,
            )?;
            Ok(Box::new(App {
                wallet,
                screens: WalletUi::default(),
                recorder,
                treasury,
                message: None,
                last_state: String::new(),
                rehearsal: serde_json::Value::Null,
                driver,
                player: Player::default(),
                targets: Vec::new(),
                payment_stage: 0,
                payment_operation: None,
                payment_start_pending: args.payment_scenario,
                native_focused: false,
                native_focus_requested: false,
                native_input_time: None,
                scroll_rect: egui::Rect::NOTHING,
                fitted_to_monitor: false,
            }))
        }),
    )
}

#[cfg(test)]
mod native_scroll_tests {
    use super::*;

    #[test]
    fn fractional_dpi_first_form_is_fully_visible_and_accepts_actual_raw_click() {
        for scale in [1.0, 1.25, 1.5] {
            let ctx = egui::Context::default();
            ctx.set_pixels_per_point(scale);
            let window = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(600., 400.));
            let mut player = Player::default();
            let mut targets = Vec::new();
            let mut scroll = egui::Rect::NOTHING;
            let mut clicked = false;
            for frame in 0..5 {
                if frame == 2 {
                    player.queue([Action::Click("form:MUT payment".into())]).unwrap();
                }
                let mut raw = egui::RawInput {
                    screen_rect: Some(window),
                    time: Some(frame as f64 * 0.1),
                    ..Default::default()
                };
                player.inject(&mut raw, &targets, window, scroll);
                if frame == 2 {
                    assert!(raw.events.iter().any(|e| matches!(e,
                        egui::Event::PointerButton { pressed: true, .. })));
                    assert!(!raw.events.iter().any(|e| matches!(e,
                        egui::Event::MouseWheel { .. })));
                }
                targets.clear();
                let output = ctx.run_ui(raw, |ui| {
                    ui.add_space(40.9375);
                    scroll = show_native_screens(ui, |ui| {
                        let form = ui.button("MUT payment");
                        targets.push(("form:MUT payment".to_owned(), form.rect));
                        clicked |= form.clicked();
                    });
                    assert!(scroll.contains_rect(targets[0].1),
                        "actual first form clipped at DPI {scale}: {:?} in {scroll:?}", targets[0].1);
                });
                output.drop_without_applying_deltas();
            }
            assert!(clicked, "actual native input did not click the form at DPI {scale}");
            assert!(player.done());
            assert!(player.failure.is_none());
        }
    }
}

#[cfg(test)]
mod monitor_fit_tests {
    use super::*;
    #[test]
    fn window_never_exceeds_the_monitor_and_keeps_its_wanted_size_when_it_fits() {
        // A large monitor keeps the wanted size.
        assert_eq!(
            inner_size_for_monitor(egui::vec2(2560., 1440.)),
            egui::vec2(1150., 850.)
        );
        // 3840x2160 at 300% scaling is 1280x720 points: the height must shrink.
        assert_eq!(
            inner_size_for_monitor(egui::vec2(1280., 720.)),
            egui::vec2(1150., 600.)
        );
        // A small monitor reduces both axes.
        assert_eq!(
            inner_size_for_monitor(egui::vec2(1024., 600.)),
            egui::vec2(984., 480.)
        );
        // Never below a usable minimum, even for a nonsensical report.
        assert_eq!(
            inner_size_for_monitor(egui::vec2(300., 200.)),
            egui::vec2(480., 360.)
        );
    }
}
