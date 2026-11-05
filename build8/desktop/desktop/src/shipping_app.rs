//! The shipping wallet shell (target B, approved by the Architect 2026-10-14). It replaces the fixed
//! closed notice: the branded screens over the real controller when a wallet can be opened, and
//! otherwise the branded shell with each missing dependency shown as the state actually observed.
//!
//! What this shell never does: open any default or installed folder (the vault root comes only from
//! `--vault-root`), read a TEST fixture, simulate a node or a certification, or bypass a gate. Custody
//! goes through `wallet_v2::ready()` FIRST, so while `PRODUCTION_SECURITY_QUALIFIED` is false a
//! shipping build refuses before any custody code can run, and that code stays dead-stripped from the
//! release executable (build/check-shipping-config.sh still checks its absence).
use crate::{operation_screens::WalletUi, wallet_controller_v2::{Controller, VaultRoot}};
use eframe::egui;
use std::ffi::OsString;

/// What the command line may say: nothing, or exactly `--vault-root <absolute folder>`.
pub(crate) fn parse_args(args: &[OsString]) -> Result<Option<VaultRoot>, String> {
    match args {
        [] => Ok(None),
        [flag, _] if flag == "--vault-root" => VaultRoot::from_args(args)
            .map(Some)
            .map_err(|e| e.to_string()),
        _ => Err("Only --vault-root <absolute folder> is accepted".into()),
    }
}

/// One dependency of the wallet and what the host observed about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Readiness {
    pub subject: &'static str,
    pub ready: bool,
    pub detail: String,
}

/// The dependencies in the order the shell checks them. Every row is observed, never assumed.
pub(crate) fn readiness(vault: Option<&VaultRoot>) -> Vec<Readiness> {
    let custody = crate::wallet_v2::ready();
    let mut rows = vec![Readiness {
        subject: "Custody",
        ready: custody.is_ok(),
        detail: match custody {
            Ok(()) => "Hybrid wallet custody is qualified for this build.".into(),
            Err(reason) => format!(
                "{reason}. Creating, restoring, unlocking and signing stay closed until the custody \
                 qualification is complete and released."
            ),
        },
    }];
    rows.push(Readiness {
        subject: "Wallet folder",
        ready: vault.is_some(),
        detail: match vault {
            Some(root) => format!("Explicit wallet folder {}", root.path().display()),
            None => "No wallet folder was given. Start the wallet with --vault-root <absolute folder>; \
                     there is no default location."
                .into(),
        },
    });
    // No sealed Build 8 Genesis exists yet, and this build carries no trust for one: no chain can be
    // verified, so no peer can be pinned and no balance or head can be shown.
    rows.push(Readiness {
        subject: "Chain",
        ready: false,
        detail: "No sealed Build 8 Genesis is installed. The Genesis Ceremony has not taken place, so \
                 this build cannot verify any chain."
            .into(),
    });
    rows.push(Readiness {
        subject: "Node",
        ready: false,
        detail: "Disconnected. A node connection is authenticated against the verified Genesis; \
                 without one no peer is contacted."
            .into(),
    });
    rows
}

pub(crate) struct ShippingApp {
    wallet: Option<Controller>,
    screens: WalletUi,
    rows: Vec<Readiness>,
}

impl ShippingApp {
    /// The shell for this launch. A wallet opens only when every dependency is ready; none of the
    /// paths that would open one exists in this build yet (see `readiness`), so it shows the states.
    pub(crate) fn new(vault: Option<VaultRoot>) -> Self {
        Self {
            wallet: None,
            screens: WalletUi::default(),
            rows: readiness(vault.as_ref()),
        }
    }
    /// The shell over an already opened controller.
    #[cfg(test)]
    pub(crate) fn with_wallet(wallet: Controller) -> Self {
        Self {
            wallet: Some(wallet),
            screens: WalletUi::default(),
            rows: Vec::new(),
        }
    }
    pub(crate) fn show(&mut self, ui: &mut egui::Ui) {
        let input = ui.ctx().input(|i| {
            i.events.iter().any(|event| {
                matches!(
                    event,
                    egui::Event::Key { .. } | egui::Event::Text(_) | egui::Event::PointerButton { .. }
                )
            })
        });
        egui::CentralPanel::default().show(ui, |ui| {
            egui::ScrollArea::vertical().show(ui, |ui| match &mut self.wallet {
                Some(wallet) => {
                    if input {
                        wallet.user_activity();
                    }
                    self.screens.show_branded(ui, wallet);
                }
                None => {
                    let rows: Vec<_> = self
                        .rows
                        .iter()
                        .map(|r| (r.subject, r.ready, r.detail.clone()))
                        .collect();
                    self.screens.show_branded_unavailable(ui, &rows);
                }
            });
        });
        // Idle expiry is serviced without input.
        if self.wallet.is_some() {
            ui.ctx()
                .request_repaint_after(std::time::Duration::from_millis(500));
        }
    }
}

impl Drop for ShippingApp {
    fn drop(&mut self) {
        if let Some(wallet) = self.wallet.as_mut() {
            wallet.lock();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_support::TestDir,
        wallet_controller_v2::tests::{PASSWORD, fixture},
    };

    #[test]
    fn arguments_are_nothing_or_exactly_an_explicit_vault_root() {
        assert_eq!(parse_args(&[]).unwrap(), None);
        let base = TestDir::new("shipping-args");
        let root = base.path().join("vault");
        let parsed = parse_args(&["--vault-root".into(), root.clone().into()])
            .unwrap()
            .unwrap();
        assert_eq!(parsed.path(), root);
        for refused in [
            vec![OsString::from("--vault-root")],
            vec!["--vault-root".into(), "relative".into()],
            vec!["--vault".into(), root.clone().into()],
            vec!["--vault-root".into(), root.clone().into(), "--scenario".into()],
        ] {
            assert!(parse_args(&refused).is_err(), "{refused:?}");
        }
    }

    #[test]
    fn missing_dependencies_are_shown_as_observed() {
        let rows = readiness(None);
        let subjects: Vec<_> = rows.iter().map(|r| r.subject).collect();
        assert_eq!(subjects, ["Custody", "Wallet folder", "Chain", "Node"]);
        // A test build opens custody through the test gate; every other row is genuinely missing.
        assert!(rows[0].ready);
        assert!(rows[1..].iter().all(|r| !r.ready));
        let mut app = ShippingApp::new(None);
        let context = egui::Context::default();
        let output = context.run_ui(Default::default(), |ui| app.show(ui));
        assert!(!output.shapes.is_empty());
        output.drop_without_applying_deltas();
    }

    #[test]
    fn the_shell_renders_the_branded_screens_over_an_open_wallet() {
        let base = TestDir::new("shipping-wallet");
        let (mut wallet, _, _) = fixture(&base);
        wallet.unlock(PASSWORD).unwrap();
        let mut app = ShippingApp::with_wallet(wallet);
        let context = egui::Context::default();
        for _ in 0..2 {
            let output = context.run_ui(Default::default(), |ui| app.show(ui));
            assert!(!output.shapes.is_empty());
            output.drop_without_applying_deltas();
        }
        let wallet = app.wallet.as_mut().unwrap();
        assert!(wallet.pending_for_transport().unwrap().is_empty());
        drop(app);
    }
}
