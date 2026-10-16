//! Test-only support for the desktop's unit tests (compiled only under `cfg(test)`).
//!
//! wallet-core's public test fixtures are included READ-ONLY (their owner is wallet-core): the
//! synthetic chain world of the payment tests, the human review flow, the conditional kit (a maker
//! played by the test, Q7) and the per-test directory. Every key is a public TEST-VALUE key (the
//! BIP-39 test vectors) or a fresh random maker key that a test creates and discards; nothing here
//! reads an installed wallet, a private fixture or the network.
#![allow(dead_code)]

#[path = "../../wallet-core/tests/support/synthetic.rs"]
pub mod synthetic;

/// The human review flow (wallet-core's `support/flow.rs`), loaded ONCE: through the conditional
/// kit, which includes it itself (a second `#[path]` module of the same file is clippy's
/// `duplicate_mod`).
pub mod flow {
    pub use super::conditional_kit::approve;
}

#[path = "../../wallet-core/tests/support/conditional_kit.rs"]
pub mod conditional_kit;

/// Certified-chain TEST-only execution for Desktop rotation and retirement fixtures.
#[path = "../../wallet-core/tests/support/rig.rs"]
pub mod canonical_rig;

#[path = "../../wallet-core/tests/support/tempdir.rs"]
mod tempdir;

pub use tempdir::TempDir as TestDir;

use std::path::PathBuf;

/// The custody directory every desktop store lives in, under a test's own directory.
pub fn custody_dir(base: &TestDir) -> PathBuf {
    base.path().join("WalletCustodyV2")
}

/// One file of that custody directory (an allow-listed name).
pub fn custody_file(base: &TestDir, name: &str) -> PathBuf {
    custody_dir(base).join(name)
}

/// Re-run this very test binary on one exact test with `env` set (the crash-child pattern of the
/// store tests: the child ends with `std::process::exit`, skipping every destructor).
pub fn run_child(test: &str, env: &[(&str, &std::ffi::OsStr)]) -> std::process::Output {
    let mut command = std::process::Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", test, "--nocapture", "--test-threads=1"]);
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().unwrap()
}

/// Order W10: `bytes` must not carry `secret`, neither raw nor as lower- or upper-case hexadecimal.
pub fn assert_no_secret_in_bytes(bytes: &[u8], secret: &[u8], what: &str) {
    let lower = hex::encode(secret);
    let upper = lower.to_ascii_uppercase();
    for needle in [secret, lower.as_bytes(), upper.as_bytes()] {
        assert!(
            !bytes.windows(needle.len()).any(|window| window == needle),
            "{what} carries the secret in clear"
        );
    }
}

/// Order W10: no file under `dir` (recursively: stores, rollback journals, crash leftovers, anything
/// else) carries `secret`. Returns how many files were scanned (a caller asserts there were some).
pub fn assert_no_secret_in_files(dir: &std::path::Path, secret: &[u8], stage: &str) -> usize {
    let mut scanned = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(folder) = stack.pop() {
        for entry in std::fs::read_dir(&folder).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let bytes = std::fs::read(&path).unwrap();
            assert_no_secret_in_bytes(&bytes, secret, &format!("{stage}: {}", path.display()));
            scanned += 1;
        }
    }
    scanned
}

/// Order W10: `text` (a `Debug` or `Display` rendering, an error, a log line) must not carry `secret`:
/// not its hexadecimal (either case), not its first or last four bytes in hexadecimal (what an
/// abbreviated rendering shows), no five consecutive bytes of it in hexadecimal, and no five
/// consecutive bytes of it inside a decimal byte list (how a derived `Debug` shows `[u8; N]` and
/// `Vec<u8>`, also when the secret is part of a longer list).
pub fn assert_no_secret_in_text(text: &str, secret: &[u8; 32], what: &str) {
    let lower_text = text.to_ascii_lowercase();
    let hex = hex::encode(secret);
    let mut needles = vec![hex.clone(), hex[..8].to_string(), hex[56..].to_string()];
    for start in 0..=27 {
        needles.push(hex[start * 2..start * 2 + 10].to_string());
    }
    for needle in needles {
        assert!(
            !lower_text.contains(&needle),
            "{what} shows the secret ({needle})"
        );
    }
    // Decimal byte lists: every run of numbers 0-255 separated by commas and white space.
    let mut lists: Vec<Vec<u8>> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let mut number: Option<u32> = None;
    for c in text.chars().chain(Some('.')) {
        if let Some(digit) = c.to_digit(10) {
            number = Some(number.unwrap_or(0).saturating_mul(10).saturating_add(digit));
            continue;
        }
        if let Some(value) = number.take() {
            match u8::try_from(value) {
                Ok(byte) => current.push(byte),
                Err(_) => lists.push(std::mem::take(&mut current)),
            }
        }
        if !matches!(c, ',' | ' ' | '\n' | '\r' | '\t') {
            lists.push(std::mem::take(&mut current));
        }
    }
    for list in lists {
        assert!(
            !secret
                .windows(5)
                .any(|run| list.windows(5).any(|window| window == run)),
            "{what} shows the secret as a decimal byte list"
        );
    }
}

/// wallet-core's `BondWorld` (tests/support/bond_support.rs, whose other parts this crate cannot
/// compile), the part the desktop tests need: the public canonical-store fixture's state without
/// coins (its one registry member is physical, eligible, generation one and owned by the public
/// TEST-VALUE key A), at an arbitrary head height.
pub struct BondWorld {
    pub state: mutiny_consensus_v8::execution::State,
    pub anchor: mutiny_consensus_v8::anchors::FinalizedAnchor,
    pub reserved: std::collections::BTreeSet<mutiny_consensus_v8::transactions::OutPoint>,
    pub timestamp: u64,
}

impl BondWorld {
    pub fn new(height: u64) -> Self {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/hybrid-canonical-store-public-v1.json"
        ))
        .unwrap();
        assert_eq!(f["synthetic_only"], true);
        assert_eq!(f["production_authorized"], false);
        let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let records: Vec<_> = f["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
            .collect();
        let mut state = mutiny_consensus_v8::execution::State::from_records(
            &records,
            raw(&f["root"]).try_into().unwrap(),
        )
        .unwrap();
        let genesis =
            mutiny_consensus_v8::anchors::FinalizedAnchor::decode(&raw(&f["genesis"])).unwrap();
        state.coins.clear();
        Self {
            state,
            anchor: mutiny_consensus_v8::anchors::FinalizedAnchor { height, ..genesis },
            reserved: Default::default(),
            timestamp: 1000 + 60 * height + 5,
        }
    }
    /// The fixture's one registry member.
    pub fn node(&self) -> mutiny_consensus_v8::Hash {
        self.state.continuity.as_ref().unwrap().members[0].node
    }
    pub fn coin(&mut self, owner: mutiny_consensus_v8::Hash, atoms: u64, tag: u8) {
        self.state.coins.insert(
            mutiny_consensus_v8::transactions::OutPoint {
                transaction: [tag; 32],
                index: 0,
            },
            mutiny_consensus_v8::transactions::Coin {
                output: mutiny_consensus_v8::transactions::Output { owner, atoms },
                created_height: 1,
                coinbase: false,
            },
        );
    }
    /// An Active lot of the fixture node, created at `created`, owned by `owner`.
    pub fn active_lot(
        &mut self,
        tag: u8,
        owner: mutiny_consensus_v8::Hash,
        atoms: u64,
        created: u64,
    ) -> mutiny_consensus_v8::Hash {
        use mutiny_consensus_v8::{
            bonds::{BondLot, LotStatus},
            bonds_v2::Lot,
        };
        let id = [tag; 32];
        let continuity = self.state.continuity.as_ref().unwrap();
        let (node, lineage) = (continuity.members[0].node, continuity.members[0].lineage);
        self.state.bonds_v2.lots.insert(
            id,
            Lot(BondLot {
                id,
                node,
                lineage,
                owner,
                atoms,
                created_height: created,
                sequence: 0,
                unbond_height: None,
                settled_height: None,
                status: LotStatus::Active,
                evidence: [0; 32],
            }),
        );
        id
    }
    pub fn view(&self) -> mutiny_wallet_core_v8::ChainView<'_> {
        // A synthetic state need not hash; the core never recomputes the root itself.
        let root = self.state.root().unwrap_or([0x77; 32]);
        let head =
            mutiny_wallet_core_v8::HeadInfo::new(self.anchor.clone(), self.timestamp, 1000, root)
                .unwrap();
        mutiny_wallet_core_v8::ChainView::new(head, &self.state, &self.reserved)
    }
}

/// Drives egui headless (`Context::run_ui`, no window) with synthetic pointer and keyboard events,
/// as a person would: a click is a press and a release in two frames; typing focuses the field
/// first. Returns every text a frame drew.
pub struct UiDriver {
    ctx: eframe::egui::Context,
    time: f64,
}

impl Default for UiDriver {
    fn default() -> Self {
        Self::new()
    }
}

impl UiDriver {
    pub fn new() -> Self {
        Self {
            ctx: eframe::egui::Context::default(),
            time: 0.0,
        }
    }
    pub fn frame(
        &mut self,
        events: Vec<eframe::egui::Event>,
        mut show: impl FnMut(&mut eframe::egui::Ui),
    ) -> Vec<String> {
        use eframe::egui::{Pos2, Rect, vec2};
        let input = eframe::egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, vec2(1600.0, 6000.0))),
            events,
            time: Some(self.time),
            ..Default::default()
        };
        self.time += 0.25;
        let output = self.ctx.run_ui(input, |ui| show(ui));
        fn collect(shape: &eframe::egui::Shape, out: &mut Vec<String>) {
            match shape {
                eframe::egui::Shape::Text(text) => out.push(text.galley.text().to_string()),
                eframe::egui::Shape::Vec(shapes) => shapes.iter().for_each(|s| collect(s, out)),
                _ => {}
            }
        }
        let mut texts = Vec::new();
        for clipped in &output.shapes {
            collect(&clipped.shape, &mut texts);
        }
        output.drop_without_applying_deltas();
        texts
    }
    pub fn click(&mut self, pos: eframe::egui::Pos2, mut show: impl FnMut(&mut eframe::egui::Ui)) {
        use eframe::egui::{Event, Modifiers, PointerButton};
        self.frame(
            vec![
                Event::PointerMoved(pos),
                Event::PointerButton {
                    pos,
                    button: PointerButton::Primary,
                    pressed: true,
                    modifiers: Modifiers::NONE,
                },
            ],
            &mut show,
        );
        self.frame(
            vec![Event::PointerButton {
                pos,
                button: PointerButton::Primary,
                pressed: false,
                modifiers: Modifiers::NONE,
            }],
            &mut show,
        );
    }
    pub fn type_text(
        &mut self,
        pos: eframe::egui::Pos2,
        text: &str,
        mut show: impl FnMut(&mut eframe::egui::Ui),
    ) {
        self.click(pos, &mut show);
        self.frame(vec![eframe::egui::Event::Text(text.into())], &mut show);
    }
}
