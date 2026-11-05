//! Presentation-only routed native wallet. Every request/review stays in WalletUi/Controller.
#[path = "branded_theme.rs"]
mod theme;
use super::{FormKind, WalletUi};
use crate::wallet_controller_v2::Controller;
use eframe::egui;
use mutiny_wallet_core_v8::WalletProfile;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Page {
    #[default]
    Overview,
    Send,
    Receive,
    Activity,
    Management,
    Settings,
    Treasury,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_support::{TestDir, UiDriver},
        wallet_controller_v2::tests::{PASSWORD, fixture},
    };
    #[test]
    fn navigation_cancels_real_review_and_rendering_never_queues() {
        let base = TestDir::new("branded-native-navigation");
        let (mut wallet, _, _) = fixture(&base);
        wallet.unlock(PASSWORD).unwrap();
        let mut screens = WalletUi::default();
        let mut navigation = BrandedUi::default();
        navigation.navigate(&mut screens, &mut wallet, Page::Send);
        screens.forms.recipient = wallet
            .with_view(|v| mutiny_wallet_core_v8::address_format::encode_for(&[94; 32], v))
            .unwrap();
        screens.forms.amount = "0.0005".into();
        let mut driver = UiDriver::new();
        for _ in 0..3 {
            driver.frame(Vec::new(), |ui| {
                navigation.show(ui, &mut screens, &mut wallet)
            });
        }
        assert!(wallet.screen().unwrap().is_none());
        assert!(wallet.pending_for_transport().unwrap().is_empty());
        navigation.navigate(&mut screens, &mut wallet, Page::Management);
        driver.frame(Vec::new(), |ui| {
            navigation.show(ui, &mut screens, &mut wallet)
        });
        assert!(
            screens.forms.kind.is_none(),
            "Send draft cannot render in Offers group"
        );
        screens.forms.select(FormKind::BondCreate);
        navigation.group = Group::Trades;
        driver.frame(Vec::new(), |ui| {
            navigation.show(ui, &mut screens, &mut wallet)
        });
        assert!(
            screens.forms.kind.is_none(),
            "Bond draft cannot render in Trades group"
        );
        assert!(wallet.pending_for_transport().unwrap().is_empty());
        wallet.prepare([94; 32], 50_000).unwrap();
        screens.present_current(&mut wallet);
        assert!(screens.has_review());
        navigation.navigate(&mut screens, &mut wallet, Page::Activity);
        assert!(wallet.screen().unwrap().is_none());
        assert!(!screens.has_review());
        assert!(wallet.pending_for_transport().unwrap().is_empty());
        wallet.lock();
        assert!(wallet.signer_identity().is_none());
        navigation.navigate(&mut screens, &mut wallet, Page::Treasury);
        driver.frame(Vec::new(), |ui| {
            navigation.show(ui, &mut screens, &mut wallet)
        });
        assert!(
            navigation.page == Page::Overview,
            "ordinary/locked wallet cannot retain Treasury route"
        );
    }
}
impl Page {
    fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Send => "Send",
            Self::Receive => "Receive",
            Self::Activity => "Activity",
            Self::Management => "Management",
            Self::Settings => "Settings",
            Self::Treasury => "Treasury",
        }
    }
}
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Group {
    #[default]
    Offers,
    Trades,
    Licenses,
    Dividends,
    Bonds,
}
#[derive(Default)]
pub(super) struct BrandedUi {
    page: Page,
    group: Group,
    pub(super) targets: Vec<(String, egui::Rect)>,
    logo: Option<egui::TextureHandle>,
    fonts_ready: bool,
    light: bool,
    /// The service's last history line (B1): the wallet's own verified height and the node's report,
    /// as the history client described them. None while no history connection is attached.
    pub(super) sync: Option<String>,
}
impl BrandedUi {
    fn navigate(&mut self, screens: &mut WalletUi, wallet: &mut Controller, page: Page) {
        if page != self.page {
            // Back/navigation never authorizes. Leaving an active review cancels it explicitly.
            wallet.cancel_review();
            screens.discard_review();
            self.page = page;
        }
        if page == Page::Send {
            screens.forms.select(FormKind::Payment);
        }
    }
    fn nav(
        &mut self,
        ui: &mut egui::Ui,
        screens: &mut WalletUi,
        wallet: &mut Controller,
        treasury: bool,
    ) {
        for page in [
            Page::Overview,
            Page::Send,
            Page::Receive,
            Page::Activity,
            Page::Management,
            Page::Settings,
        ] {
            let r = ui
                .horizontal(|ui| {
                    theme::icon(ui, page.title());
                    ui.selectable_label(self.page == page, page.title())
                })
                .inner;
            if self.page == page {
                ui.painter().line_segment(
                    [r.rect.left_top(), r.rect.left_bottom()],
                    egui::Stroke::new(3.0, theme::accent(ui)),
                );
            }
            self.targets.push((format!("nav:{}", page.title()), r.rect));
            if page == Page::Send && self.page != Page::Send {
                self.targets.push(("form:MUT payment".into(), r.rect));
            }
            if r.clicked() {
                self.navigate(screens, wallet, page);
            }
        }
        if treasury {
            let r = ui.selectable_label(self.page == Page::Treasury, "Treasury · restricted");
            self.targets.push(("nav:Treasury".into(), r.rect));
            if r.clicked() {
                self.navigate(screens, wallet, Page::Treasury);
            }
        }
    }
    pub(super) fn show(
        &mut self,
        ui: &mut egui::Ui,
        screens: &mut WalletUi,
        wallet: &mut Controller,
    ) {
        if !self.fonts_ready {
            theme::install_fonts(ui.ctx());
            self.fonts_ready = true;
        }
        if self.logo.is_none() {
            self.logo = Some(theme::logo(ui.ctx()));
        }
        theme::apply(ui, self.light);
        self.targets.clear();
        wallet.tick();
        let treasury = wallet.profile() == WalletProfile::Treasury;
        if self.page == Page::Treasury && !treasury {
            self.navigate(screens, wallet, Page::Overview);
        }
        ui.horizontal_wrapped(|ui| {
            if let Some(logo) = &self.logo {
                ui.image((logo.id(), egui::vec2(64.0, 64.0)));
            }
            ui.heading("MUTINY");
            ui.label("DESKTOP");
            // The chain class comes from the verified view, never from the build or the host.
            match wallet.with_view(|v| v.class().label()) {
                Ok(class) => ui.label(class),
                Err(_) => ui.colored_label(ui.visuals().error_fg_color, "Chain unverified"),
            };
            ui.label(if wallet.signer_identity().is_some() {
                "Unlocked"
            } else {
                "Locked"
            });
            let lock = ui.button("Lock wallet");
            self.targets.push(("wallet:Lock".into(), lock.rect));
            if lock.clicked() {
                wallet.lock();
                screens.discard_review();
            }
        });
        ui.separator();
        if ui.ctx().input(|i| i.key_pressed(egui::Key::Escape)) {
            wallet.cancel_review();
            screens.discard_review();
        }
        if ui.available_width() < 960.0 {
            ui.horizontal_wrapped(|ui| self.nav(ui, screens, wallet, treasury));
            ui.separator();
            egui::Frame::default()
                .inner_margin(20)
                .show(ui, |ui| self.content(ui, screens, wallet));
        } else {
            let rail = if ui.available_width() < 1100.0 {
                190.0
            } else {
                theme::RAIL
            };
            ui.horizontal_top(|ui| {
                ui.vertical(|ui| {
                    ui.set_width(rail);
                    self.nav(ui, screens, wallet, treasury);
                });
                ui.separator();
                ui.vertical(|ui| {
                    ui.set_width(ui.available_width());
                    egui::Frame::default()
                        .inner_margin(32)
                        .show(ui, |ui| self.content(ui, screens, wallet));
                });
            });
        }
    }
    /// The branded shell while no wallet can be opened. `rows` are (subject, ready, detail), each a
    /// state the host actually observed; nothing here offers an action that needs the wallet.
    pub(super) fn show_unavailable(&mut self, ui: &mut egui::Ui, rows: &[(&str, bool, String)]) {
        if !self.fonts_ready {
            theme::install_fonts(ui.ctx());
            self.fonts_ready = true;
        }
        if self.logo.is_none() {
            self.logo = Some(theme::logo(ui.ctx()));
        }
        theme::apply(ui, self.light);
        self.targets.clear();
        ui.horizontal_wrapped(|ui| {
            if let Some(logo) = &self.logo {
                ui.image((logo.id(), egui::vec2(64.0, 64.0)));
            }
            ui.heading("MUTINY");
            ui.label("DESKTOP");
            ui.colored_label(ui.visuals().warn_fg_color, "Wallet unavailable");
        });
        ui.separator();
        egui::Frame::default().inner_margin(32).show(ui, |ui| {
            ui.heading("Wallet status");
            ui.add_space(12.0);
            for (subject, ready, detail) in rows {
                theme::card(ui, |ui| {
                    ui.horizontal(|ui| {
                        let (colour, state) = if *ready {
                            (theme::VERIFIED, "Ready")
                        } else {
                            (ui.visuals().error_fg_color, "Unavailable")
                        };
                        ui.strong(*subject);
                        ui.colored_label(colour, state);
                    });
                    ui.add(egui::Label::new(detail.as_str()).wrap());
                });
                ui.add_space(8.0);
            }
            ui.label("No wallet is created, restored, unlocked or signed while any of these is unavailable, and no balance is shown: an unavailable balance is not a zero balance.");
            ui.add_space(12.0);
            ui.horizontal(|ui| {
                ui.label("Appearance");
                ui.toggle_value(&mut self.light, "Light theme");
            });
            ui.label("No Masters. Only the Many.");
        });
    }
    fn content(&mut self, ui: &mut egui::Ui, screens: &mut WalletUi, wallet: &mut Controller) {
        if screens.has_review() {
            theme::card(ui, |ui| {
                screens.show_scoped(ui, wallet, &FormKind::offered())
            });
            return;
        }
        ui.heading(self.page.title());
        ui.add_space(12.0);
        match self.page {
            Page::Send => theme::card(ui, |ui| {
                screens.show_scoped(ui, wallet, &[FormKind::Payment])
            }),
            Page::Management => {
                ui.horizontal_wrapped(|ui| {
                    for (g, label) in [
                        (Group::Offers, "Offers"),
                        (Group::Trades, "Trades"),
                        (Group::Licenses, "Licenses / Workers"),
                        (Group::Dividends, "Dividends"),
                        (Group::Bonds, "Bonds"),
                    ] {
                        let response = ui.selectable_value(&mut self.group, g, label);
                        let key = match g {
                            Group::Offers => "Offers",
                            Group::Trades => "Trades",
                            Group::Licenses => "Licenses",
                            Group::Dividends => "Dividends",
                            Group::Bonds => "Bonds",
                        };
                        self.targets
                            .push((format!("management:{key}"), response.rect));
                        if response.changed() {
                            wallet.cancel_review();
                            screens.discard_review();
                            screens.forms.kind = None;
                        }
                    }
                });
                let kinds: &[FormKind] = match self.group {
                    Group::Offers => &[FormKind::MakerOffer],
                    Group::Trades => &[
                        FormKind::HashLock,
                        FormKind::ConditionalClaim,
                        FormKind::ConditionalRefund,
                        FormKind::FiatLock,
                        FormKind::FiatRelease,
                        FormKind::LicenseDvp,
                    ],
                    Group::Licenses => &[FormKind::WorkerAssignment, FormKind::LicenseDvp],
                    Group::Dividends => &[FormKind::DividendClaim],
                    Group::Bonds => &[
                        FormKind::BondCreate,
                        FormKind::BondUnbond,
                        FormKind::BondWithdraw,
                    ],
                };
                theme::card(ui, |ui| screens.show_scoped(ui, wallet, kinds));
            }
            Page::Overview => {
                theme::card(ui, |ui| {
                    ui.strong("Your wallet");
                    match wallet.with_view(|v| {
                        (v.anchor().height, v.head().state_root(), v.class().label())
                    }) {
                        Ok((height, root, class)) => {
                            ui.label(format!("Own verified chain · block {height}"));
                            ui.label(class);
                            // Sync progress never replaces the verified height above: it is shown beside it.
                            ui.label(self.sync.as_deref().unwrap_or("No node history connection."));
                            theme::exact(ui, format!("State root {}", hex::encode(root)));
                        }
                        Err(e) => {
                            ui.colored_label(
                                ui.visuals().error_fg_color,
                                format!("Verified context unavailable: {e}"),
                            );
                        }
                    }
                });
                theme::card(ui, |ui| {
                    ui.strong("Balances");
                    match wallet.balance() {
                        Ok(Some(balance)) => {
                            for (label, atoms) in [
                                ("Total", balance.total_atoms),
                                ("Available", balance.available_atoms),
                                ("Reserved", balance.reserved_atoms),
                            ] {
                                ui.label(label);
                                theme::exact(
                                    ui,
                                    mutiny_wallet_core_v8::units::format_amount(atoms),
                                );
                            }
                            ui.label(format!(
                                "Own verified balance at block {}",
                                balance.anchor.height
                            ));
                            theme::exact(
                                ui,
                                format!("Block hash {}", hex::encode(balance.anchor.block)),
                            );
                            ui.label("Protocol-locked breakdown is not supplied by this query.");
                        }
                        Ok(None) => {
                            ui.label("Balance unavailable: no wallet identity is mounted. This is not a zero balance.");
                        }
                        Err(error) => {
                            ui.colored_label(
                                ui.visuals().error_fg_color,
                                format!("Verified balance unavailable: {error}"),
                            );
                        }
                    }
                });
                ui.label("Connection status is provided by the native host. A verified local head does not imply a connected peer.");
                let send = ui.button("Send MUT");
                self.targets.push(("overview:Send".into(), send.rect));
                if send.clicked() {
                    self.navigate(screens, wallet, Page::Send);
                }
            }
            Page::Receive => {
                theme::card(ui, |ui| {
                    ui.strong("Your checksummed address");
                    if let Some(identity) = wallet.signer_identity() {
                        match wallet.with_view(|v| {
                            (
                                mutiny_wallet_core_v8::address_format::encode_for(
                                    &identity.address(),
                                    v,
                                ),
                                v.anchor().clone(),
                            )
                        }) {
                            Ok((address, shown_anchor)) => {
                                theme::exact(ui, address.clone());
                                if wallet.profile() == WalletProfile::Treasury {
                                    ui.label("Copy unavailable in the Treasury workspace; retain its offline policy.");
                                } else {
                                    let copy = ui.button("Copy address");
                                    self.targets
                                        .push(("receive:Copy address".into(), copy.rect));
                                    if copy.clicked() {
                                        // Re-read through the protected controller at the actual copy boundary.
                                        // The full signer identity and anchor must still match, including
                                        // generation, declared chain, verified block and rule fingerprint.
                                        let current = wallet.with_view(|v| {
                                            (
                                                mutiny_wallet_core_v8::address_format::encode_for(
                                                    &identity.address(),
                                                    v,
                                                ),
                                                v.anchor().clone(),
                                            )
                                        });
                                        let unchanged = current.is_ok_and(|(value, anchor)| {
                                            value == address && anchor == shown_anchor
                                        }) && wallet.signer_identity().as_ref()
                                            == Some(&identity)
                                            && wallet.profile() != WalletProfile::Treasury;
                                        if unchanged {
                                            ui.ctx().copy_text(address.clone());
                                        } else {
                                            ui.colored_label(ui.visuals().warn_fg_color,
                                                "Wallet context changed; refresh the address before copying.");
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                ui.label(e);
                            }
                        }
                    } else {
                        ui.label("Unlock through the approved protected provider to obtain the current wallet identity.");
                    }
                    ui.label("QR, payment URI and share are unavailable until their canonical formats are approved.");
                });
            }
            Page::Activity => {
                ui.strong("Open local payment queue");
                match wallet.pending_for_transport() {
                    Ok(records) => {
                        if records.is_empty() {
                            ui.label("No open local payment records.");
                        }
                        for bytes in records {
                            match mutiny_consensus_v8::operation_index_v2::operation_id(0, &bytes) {
                                Ok((_, id)) => {
                                    let delivery = wallet.delivery(id);
                                    theme::card(ui, |ui| {
                                        theme::exact(ui, hex::encode(id));
                                        match delivery {
                                            Ok(crate::verified_sync_v2::Delivery::ConfirmedAt(
                                                height,
                                            )) => {
                                                ui.label(format!("Verified by own canonical replay at block {height}"));
                                            }
                                            Ok(crate::verified_sync_v2::Delivery::Unconfirmed(
                                                status,
                                            )) => {
                                                ui.label("Signed and queued locally");
                                                ui.label(format!(
                                                    "Local verified admission status: {}",
                                                    status.map_or("unresolved", |s| s.text())
                                                ));
                                                ui.label("Delivery or peer admission requires its separate authenticated host record.");
                                                use mutiny_consensus_v8::mempool_v2::Status;
                                                ui.label(match status {
                                                    Some(Status::Pending) => "Awaiting own certified replay; unconfirmed.",
                                                    Some(Status::Expired) => "Expired without verified inclusion.",
                                                    Some(Status::InputSpent) => "Conflicted: an input was spent; no inclusion is established.",
                                                    Some(Status::Rejected) => "Refused by local verified admission.",
                                                    Some(Status::Superseded) => "Superseded; this operation remains unresolved.",
                                                    Some(Status::Confirmed) => "Local confirmed marker has no own replay height here; unresolved.",
                                                    None => "Unresolved: no local admission record; no confirmation is established.",
                                                });
                                            }
                                            Err(error) => {
                                                ui.colored_label(
                                                    ui.visuals().error_fg_color,
                                                    format!("Unresolved: {error}"),
                                                );
                                            }
                                        }
                                    });
                                }
                                Err(error) => {
                                    ui.colored_label(
                                        ui.visuals().error_fg_color,
                                        format!("Canonical payment identity refused: {error:?}"),
                                    );
                                }
                            }
                        }
                    }
                    Err(error) => {
                        ui.colored_label(
                            ui.visuals().error_fg_color,
                            format!("Local queue read refused: {error}"),
                        );
                    }
                }
                ui.label("Protected operation outbox · reconciled from own verified state");
                match wallet.queued_operations() {
                    Ok(records) if records.is_empty() => {
                        ui.label("No retained operation records.");
                    }
                    Ok(records) => {
                        for (record, status) in records {
                            theme::card(ui, |ui| {
                                ui.strong(record.kind.title());
                                theme::exact(ui, hex::encode(record.id));
                                ui.label(format!("Authoritative outbox status: {status}"));
                                if !record.complete {
                                    ui.label(format!(
                                        "Partial signature: {} required signature(s) missing",
                                        record.missing.len()
                                    ));
                                }
                                ui.label("A locally queued record does not establish delivery, admission or own certified replay.");
                            });
                        }
                    }
                    Err(e) => {
                        ui.colored_label(ui.visuals().error_fg_color, e);
                    }
                }
                theme::unavailable(
                    ui,
                    "Settled payment history query pending integration",
                    "This view shows only open local payments. Retained settled payment chronology needs a public accessor over the existing authenticated lifecycle records; no synthetic history is displayed.",
                );
            }
            Page::Settings => {
                ui.horizontal(|ui| {
                    ui.label("Appearance");
                    ui.toggle_value(&mut self.light, "Light theme");
                });
                theme::card(ui, |ui| {
                    ui.strong("Security / recovery");
                    ui.label("Unlock and recovery use the native host's approved protected provider. Secrets never enter this presentation state.");
                    ui.label("Lock and idle expiry withdraw signing authority and invalidate review consent.");
                });
                theme::card(ui, |ui| {
                    ui.strong("Connection / diagnostics");
                    let c = wallet.context();
                    theme::exact(ui, format!("Network {}", c.network));
                    theme::exact(ui, format!("Genesis {}", hex::encode(c.genesis)));
                    theme::exact(ui, format!("Rules {}", hex::encode(c.fingerprint)));
                });
                ui.label("No Masters. Only the Many.");
            }
            Page::Treasury => {
                // Controller still enforces each declared role on every request/use.
                if wallet.profile() != WalletProfile::Treasury {
                    ui.label("TREASURY_PROFILE_REQUIRED");
                    return;
                }
                theme::card(ui, |ui| {
                    ui.strong("Declared Treasury workspace");
                    ui.label("Authority and destination rotation remain separate protected host workflows. Reserve-aware operation review remains authoritative.");
                });
            }
        }
    }
}
