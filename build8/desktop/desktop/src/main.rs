#![windows_subsystem = "windows"]
const TEST_VALUE_WINDOW: bool = cfg!(feature = "testvalue-window");
const NATIVE_OWNER_TEST: bool = cfg!(feature = "native-owner-test");
const _: () = assert!(
    !NATIVE_OWNER_TEST,
    "Shipping wallet refuses the native-owner TEST feature in every profile"
);
const _: () = assert!(
    !TEST_VALUE_WINDOW,
    "Shipping wallet refuses the TEST-VALUE window feature in every profile"
);
const _: () = assert!(
    !mutiny_crypto_v2::RELEASE_CUSTODY_ENABLED,
    "Desktop wallet must not include private firmware-release custody"
);
// Phase 7: wallet-core's TEST-VALUE signing gate must never be in a shipping build. Tests get it
// through the desktop's DEV-dependency only: `cargo build --release` never unifies a dev-dependency
// feature into the shipping binary, and this assert holds in EVERY build with the shipping profile
// (`debug-assertions = false`, pinned by build/check-shipping-config.sh). It is not evaluated in a
// dev-profile build: `cargo clippy --all-targets` checks the non-test binary in the same invocation
// as the tests, so Cargo unifies the dev-dependency feature into that (never shipped) binary too.
// A release build that unified it (`cargo build --release --all-targets`) is refused here, as it
// must be. Second, independent check: the gate's marker string must be absent from the release exe
// and its pdb (build/check-shipping-config.sh).
#[cfg(all(not(test), not(debug_assertions)))]
const _: () = assert!(
    !mutiny_wallet_core_v8::TEST_VALUE_SIGNING_ENABLED,
    "Desktop wallet must not include the wallet-core TEST-VALUE signing gate"
);
// Phase 0C: the V1 Ed25519/BIP32 ceremony wallet (identity, SQLite store, payment, replica,
// Genesis bindings, physical admission, firmware) is retired from this tree; the record is
// build/imports/EDITED-AFTER-IMPORT-DESKTOP-V1.md. Nothing below depends on it.
// Phase 7: the desktop is a thin shell over wallet-core (plan, review, approval, authorization);
// its own payment pipeline (payment_v2, payment_review_v2) is retired. Target B (2026-10-14): the
// shipping shell (`shipping_app`) replaces the fixed closed notice. Every custody path still starts
// with `wallet_v2::ready()`, which refuses in every shipping build while production qualification is
// incomplete, so much of the wallet code remains dead there: hence `allow(dead_code)`.
mod custody_acl_v2;
// Order W7: what a custody file is, decided before anything touches it; typed, readable refusals.
#[allow(dead_code)]
mod custody_format;
// DPAPI sealing of the stores beside the vault (operation outbox, preimage store).
mod custody_seal;
// Windows DPAPI outer layer of the V2 vault (formerly inside the V1 wallet module).
mod dpapi_v2;
// The protected (DPAPI-sealed) durable outbox of signed operations other than payments.
#[allow(dead_code)]
mod operation_outbox;
// One request form per operation kind: each produces an OperationRequest.
#[allow(dead_code)]
mod operation_screens;
// Exact-decimal MUT amount entry (wallet-core's parser).
#[allow(dead_code)]
mod payment;
// The review screen: a thin egui widget over wallet-core's Review.
#[allow(dead_code)]
mod plan_review;
// Hash-lock preimages in their own sealed record (Q13).
#[allow(dead_code)]
mod preimage_store;
// The wallet's authenticated node connection; opened only once a verified Genesis exists.
#[allow(dead_code)]
mod node_link;
// Automatic history catch-up schedule over the node connection (G1/B1); canonical state stays the verifier's.
#[allow(dead_code)]
mod history_sync;
// NON-SHIPPING B1 acceptance flow through the wallet Service; compiled for tests only in this crate root.
#[cfg(test)]
mod service_acceptance;
pub mod proofs;
// The shipping shell: branded screens over the real controller, or the observed unavailable states.
mod shipping_app;
#[allow(dead_code)]
mod store_v2;
#[cfg(test)]
mod test_support;
#[allow(dead_code)]
mod verified_sync_v2;
#[allow(dead_code)]
mod wallet_controller_v2;
// Candidate V2 custody is compiled/tested but remains closed by the shared
// production qualification gate until the complete migration is qualified.
#[allow(dead_code)]
mod wallet_v2;
use eframe::egui;

/// The GUI shell (target B): `shipping_app::ShippingApp`. The fixed closed notice and its
/// `shell_closed` startup gate are retired; the custody gate (`wallet_v2::ready()`) is unchanged and
/// is now the only gate, checked before any custody code runs.
struct App(shipping_app::ShippingApp);
impl App {
    fn new(args: &[std::ffi::OsString]) -> Result<Self, String> {
        let vault = shipping_app::parse_args(args)?;
        Ok(Self(shipping_app::ShippingApp::new(vault)))
    }
}
impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.0.show(ui);
    }
}
fn main() -> eframe::Result {
    std::panic::set_hook(Box::new(|_| {}));
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let app = App::new(&args).map_err(|e| eframe::Error::AppCreation(e.into()))?;
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1150., 820.]),
        ..Default::default()
    };
    eframe::run_native(
        "Mutiny Desktop Wallet V8",
        options,
        Box::new(move |cc| {
            use raw_window_handle::{HasWindowHandle, RawWindowHandle};
            use windows_sys::Win32::UI::WindowsAndMessaging::{
                SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE,
            };
            let RawWindowHandle::Win32(handle) = cc.window_handle()?.as_raw() else {
                return Err("Windows wallet requires a native Windows window".into());
            };
            // Defense in depth; never use screen-capture automation on a real seed screen.
            if unsafe {
                SetWindowDisplayAffinity(handle.hwnd.get() as *mut _, WDA_EXCLUDEFROMCAPTURE)
            } == 0
            {
                return Err("Cannot enable wallet screen capture protection".into());
            }
            Ok(Box::new(app))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    const SOURCE: &str = include_str!("main.rs");
    #[test]
    fn shell_starts_without_a_wallet_and_refuses_unexpected_arguments() {
        let context = egui::Context::default();
        let mut app = App::new(&[]).unwrap();
        let output = context.run_ui(Default::default(), |ui| app.0.show(ui));
        assert!(!output.shapes.is_empty());
        output.drop_without_applying_deltas();
        assert!(App::new(&["--scenario".into(), "payment".into()]).is_err());
    }
    // End-to-end check of the shipped artifact: unexpected arguments are refused at startup (exit 1)
    // before any window or folder is opened. Ignored by default because it needs the built
    // executable; a runner sets the path explicitly:
    //   MUTINY_DESKTOP_RELEASE_EXE=<path to the built exe> cargo test -- --ignored refuses
    #[test]
    #[ignore = "needs the built non-test executable: set MUTINY_DESKTOP_RELEASE_EXE"]
    fn non_test_binary_refuses_unexpected_arguments() {
        use std::{io::Read, process::Stdio, time::Duration, time::Instant};
        let exe = std::env::var_os("MUTINY_DESKTOP_RELEASE_EXE")
            .expect("set MUTINY_DESKTOP_RELEASE_EXE to the built non-test executable");
        let mut child = std::process::Command::new(exe)
            .args(["--scenario", "payment"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                panic!("the executable did not refuse at startup within 20 s");
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let mut stderr = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert_eq!(status.code(), Some(1), "{stderr}");
        assert!(stderr.contains("Only --vault-root"), "{stderr}");
    }
    #[test]
    fn binary_guards_stay_in_place() {
        let source = SOURCE.replace("\r\n", "\n");
        // Needles are split so that this test cannot satisfy itself.
        assert!(source.starts_with(&["#![windows_subsystem", " = \"windows\"]\n"].concat()));
        for needle in [
            ["!mutiny_crypto_v2::RELEASE_CUSTODY", "_ENABLED,\n"].concat(),
            // Phase 7: the shipping binary refuses wallet-core's TEST-VALUE gate.
            [
                "#[cfg(all(not(test), not(debug_as",
                "sertions)))]\nconst _: () = assert!(\n    !mutiny_wallet_core_v8::TEST_VALUE_SIGNING",
                "_ENABLED,\n",
            ]
            .concat(),
            ["let vault = shipping_app::parse", "_args(args)?;\n"].concat(),
            ["std::panic::set_hook(Box::new(|", "_| {}));\n"].concat(),
            [
                "SetWindowDisplayAffinity(handle.hwnd.get() as *mut _, ",
                "WDA_EXCLUDEFROMCAPTURE)\n",
            ]
            .concat(),
            [
                "return Err(\"Cannot enable wallet screen",
                " capture protection\".into());\n",
            ]
            .concat(),
        ] {
            assert_eq!(
                source.matches(&needle).count(),
                1,
                "guard missing: {needle}"
            );
        }
    }
    // Target B: the shipping shell checks the custody gate itself and reaches no TEST host, fixture,
    // simulated driver or test gate outside its own `cfg(test)` module. Needles are split so that this
    // test cannot satisfy itself.
    #[test]
    fn shipping_shell_checks_custody_first_and_reaches_no_test_path() {
        let source = include_str!("shipping_app.rs").replace("\r\n", "\n");
        let (shipping, tests) = source
            .split_once(&["#[cfg(te", "st)]\nmod tests {\n"].concat())
            .unwrap();
        assert!(!tests.contains(&["#[cfg(te", "st)]\nmod tests {\n"].concat()));
        assert_eq!(
            shipping
                .matches(&["let custody = crate::wallet_v2::rea", "dy();\n"].concat())
                .count(),
            1
        );
        for needle in [
            ["test", "value"].concat(),
            ["native", "_driver"].concat(),
            ["chain::", "open"].concat(),
            ["test", "_support"].concat(),
            ["test", "_gate"].concat(),
            ["Signing", "Gate::"].concat(),
            ["PRODUCTION_SECURITY", "_QUALIFIED ="].concat(),
            ["std::", "env"].concat(),
        ] {
            assert!(
                !shipping.to_ascii_lowercase().contains(&needle.to_ascii_lowercase()),
                "shipping shell names {needle}"
            );
        }
        // The only non-test constructor of a wallet-bearing shell is the test hook.
        assert_eq!(
            shipping
                .matches(&["#[cfg(te", "st)]\n    pub(crate) fn with_wallet("].concat())
                .count(),
            1
        );
    }
    // Phase 7: wallet-core's TEST-VALUE signing gate reaches TEST builds only, through the
    // dev-dependency; the normal dependency enables no feature, and the shipping profile keeps
    // debug assertions off, so the compile-time guard above is evaluated in every release build.
    #[allow(clippy::assertions_on_constants)]
    #[test]
    fn the_wallet_core_test_value_gate_reaches_test_builds_only() {
        assert!(mutiny_wallet_core_v8::TEST_VALUE_SIGNING_ENABLED);
        let manifest = include_str!("../Cargo.toml").replace("\r\n", "\n");
        let (normal, dev) = manifest.split_once("\n[dev-dependencies]\n").unwrap();
        let lines = |section: &str, name: &str| -> Vec<String> {
            section
                .lines()
                .filter(|line| line.starts_with(name))
                .map(str::to_owned)
                .collect()
        };
        assert_eq!(
            lines(normal, "mutiny-wallet-core-v8"),
            ["mutiny-wallet-core-v8 = { path = \"../wallet-core\" }"]
        );
        let dev = dev.split("\n[").next().unwrap();
        assert_eq!(
            lines(dev, "mutiny-wallet-core-v8"),
            [
                "mutiny-wallet-core-v8 = { path = \"../wallet-core\", features = [\"test-value-signing\"] }"
            ]
        );
        let release = manifest.split("\n[profile.release]\n").nth(1).unwrap();
        assert!(
            release
                .lines()
                .any(|line| line == "debug-assertions = false")
        );
        // Both explicit nonshipping feature sets are absent from an ordinary
        // build; native-owner-test also requires the existing TEST window.
        let features = manifest
            .split_once("\n[features]\n")
            .unwrap()
            .1
            .split("\n[")
            .next()
            .unwrap();
        let declarations: Vec<_> = features
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        assert_eq!(
            declarations,
            [
                "testvalue-window = [\"mutiny-wallet-core-v8/test-value-signing\", \"dep:p256\", \"windows-sys/Win32_System_Pipes\", \"windows-sys/Win32_System_IO\"]",
                "native-owner-test = [\"testvalue-window\", \"dep:p384\", \"dep:x509-cert\", \"dep:ed25519-dalek\", \"dep:minicbor\", \"dep:rsa\"]",
                // The isolated debug native TEST Root principal; it requires native-owner-test and
                // so the TEST window, which the shipping asserts above refuse.
                "asus-native-test-principal = [\"native-owner-test\"]",
            ]
        );
        for (name, declaration) in [
            ("p384", "p384 = { version = \"=0.13.1\", default-features = false, features = [\"ecdsa\", \"std\"], optional = true }"),
            ("x509-cert", "x509-cert = { version = \"=0.2.5\", default-features = false, features = [\"std\"], optional = true }"),
            ("ed25519-dalek", "ed25519-dalek = { version = \"=2.2.0\", optional = true }"),
            ("minicbor", "minicbor = { version = \"=2.3.0\", features = [\"std\"], optional = true }"),
            ("rsa", "rsa = { version = \"=0.9.10\", default-features = false, features = [\"std\", \"sha2\"], optional = true }"),
        ] {
            assert_eq!(lines(normal, name), [declaration]);
        }
        let test_root = include_str!("testvalue/main.rs").replace("\r\n", "\n");
        for gated_module in [
            "#[cfg(feature = \"native-owner-test\")]\n#[path = \"continuous_native_owner_fixture.rs\"] mod native_owner_fixture;",
            "#[cfg(feature = \"native-owner-test\")]\n#[path = \"continuous_native_owner_driver.rs\"] mod native_owner_driver;",
        ] {
            assert_eq!(test_root.matches(gated_module).count(), 1);
        }
        assert_eq!(
            manifest
                .matches("required-features = [\"testvalue-window\"]")
                .count(),
            2
        );
        let source = SOURCE.replace("\r\n", "\n");
        assert!(
            source
                .contains("const TEST_VALUE_WINDOW: bool = cfg!(feature = \"testvalue-window\");")
        );
        let condensed: String = source.chars().filter(|c| !c.is_whitespace()).collect();
        assert!(condensed.contains("const_:()=assert!(!TEST_VALUE_WINDOW,"));
        assert!(condensed.contains("constNATIVE_OWNER_TEST:bool=cfg!(feature=\"native-owner-test\");"));
        assert!(condensed.contains("const_:()=assert!(!NATIVE_OWNER_TEST,"));
    }
    // Hygiene: no original-checkout path, host/vendor name, private evidence file name or removed
    // consensus feature name may reappear in the desktop sources. Needles are split so that this
    // scan cannot flag itself.
    #[test]
    fn sources_name_no_checkout_path_host_private_evidence_or_removed_feature() {
        let sources = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let forbidden = [
            ["node", "-a-"].concat(),
            ["vul", "tr"].concat(),
            ["lap", "top"].concat(),
            ["work", "station"].concat(),
            ["mutiny", "\\"].concat(),
            ["mutiny", " build8"].concat(),
            ["users", "\\"].concat(),
            ["/us", "ers/"].concat(),
            ["trading", "-candidate"].concat(),
            ["trading", "-qualification"].concat(),
            ["trading", "-license-hook"].concat(),
            ["fea", "ture = \"trading"].concat(),
        ];
        let mut scanned = 0;
        for entry in std::fs::read_dir(&sources).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            let lower = text.to_ascii_lowercase();
            for needle in &forbidden {
                assert!(
                    !lower.contains(needle.as_str()),
                    "{} names {needle}",
                    path.display()
                );
            }
            // No Windows drive-letter path literal, whether written in a normal string (escaped
            // backslashes) or in a raw string.
            let bytes = text.as_bytes();
            assert!(
                !bytes.windows(4).any(|w| w[0].is_ascii_alphabetic()
                    && w[1] == b':'
                    && w[2] == b'\\'
                    && w[3] == b'\\')
                    && !bytes.windows(5).any(|w| w[0] == b'r'
                        && w[1] == b'"'
                        && w[2].is_ascii_alphabetic()
                        && w[3] == b':'
                        && w[4] == b'\\'),
                "{} contains a drive-letter path",
                path.display()
            );
            scanned += 1;
        }
        assert!(scanned >= 10, "the source scan found only {scanned} files");
    }
}
