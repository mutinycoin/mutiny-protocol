//! Build independence: the wallet core's manifest, lockfile, resolved graph and sources contain no
//! GUI, operating-system-binding, network or Bitcoin dependency; crypto-v2 is linked with exactly
//! `wallet-custody`; the only feature is the non-shipping `test-value-signing` and it is never
//! default and is switched on for tests only through the dev-dependency self reference; guard
//! constants are present; and no source path takes bytes to sign. Mirrors the style of
//! consensus/tests/rule_set_build_independence.rs.
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// `table name -> (entry name -> raw value)` for a simple one-entry-per-line manifest.
fn tables(manifest: &str) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut out: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut current = String::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            current = line.trim_matches(|c| c == '[' || c == ']').to_string();
            out.entry(current.clone()).or_default();
        } else if let Some((name, value)) = line.split_once('=') {
            out.entry(current.clone())
                .or_default()
                .insert(name.trim().to_string(), value.trim().to_string());
        }
    }
    out
}

fn dependency_names(manifest: &str, kinds: &[&str]) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for (table, entries) in tables(manifest) {
        let is_dependency_table = kinds
            .iter()
            .any(|kind| table == *kind || (table.starts_with("target.") && table.ends_with(&format!(".{kind}"))));
        if is_dependency_table {
            names.extend(entries.keys().map(|name| name.replace('_', "-")));
        }
    }
    names
}

#[test]
fn dependency_table_suffix_separates_target_normal_dev_and_build() {
    // DEV/build table names must not be treated as the normal dependency kind
    // merely because their last characters also spell "dependencies".
    let manifest=r#"
[dependencies]
root_normal = "1"
[dev-dependencies]
root_dev = "1"
[build-dependencies]
root_build = "1"
[target.'cfg(target_os = "linux")'.dependencies]
linux_normal = "1"
[target.'cfg(target_os = "linux")'.dev-dependencies]
libc = "=0.2.189"
[target.'cfg(target_os = "linux")'.build-dependencies]
linux_build = "1"
"#;
    let expected=|items:&[&str]|items.iter().map(|s|s.to_string()).collect::<BTreeSet<_>>();
    assert_eq!(dependency_names(manifest,&["dependencies"]),expected(&["root-normal","linux-normal"]));
    assert_eq!(dependency_names(manifest,&["dev-dependencies"]),expected(&["root-dev","libc"]));
    assert_eq!(dependency_names(manifest,&["build-dependencies"]),expected(&["root-build","linux-build"]));
    assert_eq!(dependency_names(manifest,&["dependencies","build-dependencies"]),
        expected(&["root-normal","linux-normal","root-build","linux-build"]));
}

/// Packages whose NAME starts with "bitcoin" that are nevertheless allowed: `bitcoin_hashes` is the
/// hash-function library (SHA-256, SHA-512, HMAC) that `bip39` uses for mnemonic checksums. It has no
/// key, script, transaction, wallet or network code. It reaches every root of this repository through
/// mutiny-crypto-v2 -> bip39, so any "no Bitcoin crate" exclusion check must allow exactly this name.
const ALLOWED_BITCOIN_NAMED_PACKAGES: &[&str] = &["bitcoin_hashes"];

/// Crate names that must never appear in the wallet core's graph.
const FORBIDDEN_PACKAGES: &[&str] = &[
    // GUI and window system
    "eframe",
    "egui",
    "egui-winit",
    "egui_glow",
    "winit",
    "glutin",
    "glow",
    "wgpu",
    "raw-window-handle",
    "sdl2",
    "gtk",
    // operating-system bindings
    "windows-sys",
    "windows",
    "windows-core",
    "winapi",
    "winreg",
    "windows-targets",
    // network and async runtimes
    "tokio",
    "async-std",
    "reqwest",
    "hyper",
    "ureq",
    "curl",
    "mio",
    "socket2",
    "h2",
    "tonic",
    // Bitcoin
    "bitcoin",
    "bitcoin-private",
    "bitcoin-io",
    "bitcoin-internals",
    "secp256k1",
    "secp256k1-sys",
    "bdk",
    "bdk_wallet",
    "bdk_chain",
    "miniscript",
    "bitcoincore-rpc",
    "bitcoincore-rpc-json",
    "psbt",
    "rust-bitcoin",
    "electrum-client",
    "esplora-client",
    // a second key scheme or a V1 BIP-32 tree
    "ed25519-dalek-bip32",
];

#[test]
fn the_manifest_allows_exactly_the_reviewed_dependencies() {
    let manifest = read(&root().join("Cargo.toml"));
    let normal = dependency_names(&manifest, &["dependencies"]);
    let expected: BTreeSet<String> = [
        "mutiny-consensus-v8",
        "mutiny-crypto-v2",
        "minicbor",
        "sha2",
        "hex",
        "zeroize",
        "rusqlite",
    ]
    .into_iter()
    .map(String::from)
    .collect();
    assert_eq!(
        normal, expected,
        "a new dependency is a deliberate change: update this allow-list in the same commit"
    );
    let dev = dependency_names(&manifest, &["dev-dependencies"]);
    let expected_dev: BTreeSet<String> = ["mutiny-wallet-core-v8", "serde-json", "p256", "mutinyd-v8", "mutiny-transport-v2", "x509-cert", "p384", "rsa", "libc"]
        .into_iter()
        .map(String::from)
        .collect();
    assert_eq!(dev, expected_dev);
    // Reviewed actual TCP/Q17 integration edges only: never promote them to normal/build.
    let manifest_tables = tables(&manifest);
    assert_eq!(manifest_tables["dev-dependencies"]["mutinyd-v8"],
        r#"{ path = "../node", default-features = false }"#);
    assert_eq!(manifest_tables["dev-dependencies"]["mutiny-transport-v2"],
        r#"{ path = "../transport-v2" }"#);
    // Explicit private native collector TEST model only, preserving exact pinned
    // normal/build edges and all existing forbidden packages below.
    assert_eq!(manifest_tables["dev-dependencies"]["x509-cert"], r#"{ version = "=0.2.5", default-features = false, features = ["std"] }"#);
    assert_eq!(manifest_tables["dev-dependencies"]["p384"], r#"{ version = "=0.13.1", default-features = false, features = ["ecdsa", "std"] }"#);
    assert_eq!(manifest_tables["dev-dependencies"]["rsa"], r#"{ version = "=0.9.10", default-features = false, features = ["std", "sha2"] }"#);
    assert_eq!(manifest_tables[r#"target.'cfg(target_os = "linux")'.dev-dependencies"#]["libc"], r#""=0.2.189""#);
    assert!(
        dependency_names(&manifest, &["build-dependencies"]).is_empty(),
        "no build script, no build dependencies"
    );
    for name in normal.iter().chain(dev.iter()) {
        assert!(
            !FORBIDDEN_PACKAGES.contains(&name.as_str()),
            "{name} is forbidden in wallet-core"
        );
    }
    assert!(!root().join("build.rs").exists());
}

#[test]
fn crypto_v2_is_linked_with_exactly_wallet_custody_and_consensus_with_default_features() {
    let manifest = read(&root().join("Cargo.toml"));
    let all = tables(&manifest);
    let deps = &all["dependencies"];
    assert_eq!(
        deps["mutiny-crypto-v2"],
        r#"{ path = "../crypto-v2", features = ["wallet-custody"] }"#
    );
    assert_eq!(
        deps["mutiny-consensus-v8"], r#"{ path = "../consensus" }"#,
        "no feature of consensus is enabled"
    );
    for forbidden in [
        "release-custody",
        "receipt-qualification",
        "qualification",
        "dividend-test-fixtures",
        "legacy-v0-test-fixtures",
    ] {
        for (table, entries) in &all {
            if table.contains("dependencies") {
                for (name, value) in entries {
                    assert!(
                        !value.contains(forbidden),
                        "{table}.{name} enables {forbidden}"
                    );
                }
            }
        }
    }
}

#[test]
fn the_only_feature_is_the_non_shipping_test_gate_and_it_is_never_default() {
    let manifest = read(&root().join("Cargo.toml"));
    let all = tables(&manifest);
    let features = &all["features"];
    assert_eq!(
        features.keys().map(String::as_str).collect::<Vec<_>>(),
        ["default", "test-value-signing"]
    );
    assert_eq!(features["default"], "[]");
    assert_eq!(features["test-value-signing"], "[]");
    // It reaches tests only through the dev-dependency self reference; no normal dependency table
    // mentions it.
    assert_eq!(
        all["dev-dependencies"]["mutiny-wallet-core-v8"],
        r#"{ path = ".", features = ["test-value-signing"] }"#
    );
    for (table, entries) in &all {
        if table == "dev-dependencies" || table == "features" {
            continue;
        }
        for (name, value) in entries {
            assert!(
                !value.contains("test-value-signing") && !name.contains("test-value-signing"),
                "{table} mentions the test gate: {name}"
            );
        }
    }
    // No `--all-features`-style default sneaks it in.
    assert!(!manifest.contains("default = [\"test-value-signing\"]"));
}

#[test]
fn profiles_and_patches_match_the_other_roots() {
    let manifest = read(&root().join("Cargo.toml"));
    let all = tables(&manifest);
    let release = &all["profile.release"];
    for (key, value) in [
        ("opt-level", "3"),
        ("overflow-checks", "true"),
        ("debug-assertions", "false"),
        ("codegen-units", "1"),
        ("strip", "\"none\""),
        ("lto", "false"),
        ("panic", "\"unwind\""),
    ] {
        assert_eq!(release[key], value, "[profile.release] {key}");
    }
    // The same release table text as the consensus root (the exclusion script greps these lines).
    let consensus = tables(&read(&root().join("../consensus/Cargo.toml")));
    assert_eq!(release, &consensus["profile.release"]);
    // Dependencies optimised in debug builds: FN-DSA and the KDFs are far too slow at opt-level 0.
    assert_eq!(all["profile.dev.package.\"*\""]["opt-level"], "3");
    assert_eq!(
        all["profile.dev.package.\"*\""],
        consensus["profile.dev.package.\"*\""]
    );
    // The qualified source overrides are identical to the node root's.
    let node = tables(&read(&root().join("../node/Cargo.toml")));
    assert_eq!(all["patch.crates-io"], node["patch.crates-io"]);
    assert_eq!(all["patch.crates-io"].len(), 7);
    // The release table is the last table, as in every other root, so the script's range grep works.
    let last_table = manifest
        .lines()
        .rev()
        .find(|l| l.trim().starts_with('['))
        .unwrap();
    assert_eq!(last_table.trim(), "[profile.release]");
}

#[test]
fn the_lockfile_pins_the_same_versions_as_the_other_roots() {
    let lock = read(&root().join("Cargo.lock"));
    let node = read(&root().join("../node/Cargo.lock"));
    let versions = |text: &str| {
        let mut map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut name = String::new();
        for line in text.lines() {
            if let Some(n) = line.strip_prefix("name = \"") {
                name = n.trim_end_matches('"').to_string();
            } else if let Some(v) = line.strip_prefix("version = \"") {
                map.entry(name.clone())
                    .or_default()
                    .insert(v.trim_end_matches('"').to_string());
            }
        }
        map
    };
    let (mine, theirs) = (versions(&lock), versions(&node));
    for (name, set) in &mine {
        if name == "mutiny-wallet-core-v8" {
            continue;
        }
        assert_eq!(
            Some(set),
            theirs.get(name),
            "{name} must be locked to the node root's versions"
        );
    }
    assert!(mine.contains_key("mutiny-wallet-core-v8"));
}

#[test]
fn guard_constants_and_unsafe_ban_are_in_the_library_root() {
    let lib = read(&root().join("src/lib.rs"));
    assert!(lib.contains("#![forbid(unsafe_code)]"));
    for (negated, constant) in [
        (true, "mutiny_crypto_v2::RECEIPT_QUALIFICATION_ENABLED"),
        (true, "mutiny_crypto_v2::RELEASE_CUSTODY_ENABLED"),
        (false, "mutiny_crypto_v2::WALLET_CUSTODY_ENABLED"),
        (true, "mutiny_consensus_v8::DIVIDEND_TEST_FIXTURES_ENABLED"),
        (true, "mutiny_consensus_v8::LEGACY_V0_TEST_FIXTURES_ENABLED"),
    ] {
        let mark = if negated { "!" } else { "" };
        let wanted = format!("const _: () = assert!(\n    {mark}{constant},");
        assert!(lib.contains(&wanted), "missing guard for {constant}");
    }
    let authorize = read(&root().join("src/authorize.rs"));
    assert!(authorize.contains("pub const TEST_VALUE_SIGNING_ENABLED: bool = cfg!(any(test, feature = \"test-value-signing\"));"));
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Source text with comments removed (string literals are kept: review text legitimately says
/// "Bitcoin custody"; the patterns below only match code-shaped uses).
fn code_without_comments(text: &str) -> String {
    let mut out = String::new();
    let mut in_block = false;
    for line in text.lines() {
        let mut rest = line;
        let mut kept = String::new();
        loop {
            if in_block {
                match rest.find("*/") {
                    Some(end) => {
                        rest = &rest[end + 2..];
                        in_block = false;
                    }
                    None => break,
                }
            } else {
                match (rest.find("//"), rest.find("/*")) {
                    (Some(a), Some(b)) if b < a => {
                        kept.push_str(&rest[..b]);
                        rest = &rest[b + 2..];
                        in_block = true;
                    }
                    (Some(a), _) => {
                        kept.push_str(&rest[..a]);
                        break;
                    }
                    (None, Some(b)) => {
                        kept.push_str(&rest[..b]);
                        rest = &rest[b + 2..];
                        in_block = true;
                    }
                    (None, None) => {
                        kept.push_str(rest);
                        break;
                    }
                }
            }
        }
        out.push_str(&kept);
        out.push('\n');
    }
    out
}

#[test]
fn sources_have_no_forbidden_apis_no_environment_reads_and_only_the_declared_feature_cfg() {
    let mut files = Vec::new();
    rust_files(&root().join("src"), &mut files);
    assert!(files.len() >= 12);
    let mut sign_callers = BTreeSet::new();
    let mut sqlite_users = BTreeSet::new();
    let mut key_holders = BTreeSet::new();
    for file in &files {
        let name = file
            .strip_prefix(root().join("src"))
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let code = code_without_comments(&read(file));
        for pattern in [
            "unsafe ",
            "std::env::var",
            "env::var(",
            "option_env!",
            "ed25519",
            "bitcoin::",
            "use bitcoin",
            "extern crate bitcoin",
            "secp256k1",
            "bdk::",
            "bdk_",
            "miniscript::",
            "psbt::",
            "bitcoincore",
            "winit",
            "egui",
            "windows_sys",
            "eframe",
            "tokio",
            "std::net",
            "TcpStream",
            "UdpSocket",
            "std::process::Command",
            "std::fs::",
        ] {
            // `forbid(unsafe_code)` is the only permitted mention of unsafe.
            if pattern == "unsafe " && !code.contains("unsafe ") {
                continue;
            }
            assert!(
                !code.contains(pattern),
                "{name} contains the forbidden pattern {pattern:?}"
            );
        }
        // Feature cfgs: only the declared non-shipping gate.
        for line in code.lines().filter(|l| l.contains("feature")) {
            if line.contains("cfg(") || line.contains("cfg!(") {
                assert!(
                    line.contains("\"test-value-signing\""),
                    "{name}: unexpected feature cfg: {line}"
                );
            }
        }
        // Storage code lives in exactly one module.
        if code.contains("rusqlite") {
            sqlite_users.insert(name.clone());
        }
        // Order W4: a raw `.sign(` call (on a key or on a consensus object) exists only in the typed
        // capabilities of capability.rs; authorize.rs only hands the plan to its handler
        // (`handler.sign(`), and every other file, every handler module included, has none: a
        // handler signs through `authorize_input`, `authorize_bond`, `authorize_claim`,
        // `approve_slot`, `authorize_rotation` or `authorize_freeze`. Whitespace is squeezed out so a
        // method chain split over lines is read like any other. (The structural boundary is the type
        // system and the compile-fail doctests of capability.rs; this is the additional tripwire.)
        let squeezed: String = code.chars().filter(|c| !c.is_whitespace()).collect();
        for (at, _) in squeezed.match_indices(".sign(") {
            let allowed = name == "capability.rs"
                || (name == "authorize.rs" && squeezed[..at].ends_with("handler"));
            assert!(
                allowed,
                "{name}: a signing call outside the typed capabilities of capability.rs"
            );
            sign_callers.insert(name.clone());
        }
        // No handler module holds a key: `HybridKey` appears in the non-test code of the files that
        // hold or seal one, and nowhere else.
        let production = &code[..code.find("\n#[cfg(test)]\nmod ").unwrap_or(code.len())];
        if production.contains("HybridKey") {
            key_holders.insert(name.clone());
        }
        // No public function takes raw bytes to sign, in any spelling (`pub`, `pub const`,
        // `pub async`, `pub unsafe`): the only way to a signature is authorize(). Trait methods are
        // covered too, because the check is on every `fn` item and not only on `pub fn` lines.
        for (index, _) in code.match_indices("fn ") {
            let before = &code[..index];
            if before
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_')
            {
                continue; // part of a longer word, such as `cfn `
            }
            let rest = &code[index + 3..];
            let function: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let signature = &rest[..rest.find(['{', ';']).unwrap_or(rest.len())];
            let prefix = before.rsplit('\n').next().unwrap_or("").trim_start();
            let public = prefix.starts_with("pub ") && !prefix.starts_with("pub(");
            if function == "sign" || function.starts_with("sign_") {
                assert!(
                    !public,
                    "{name}: public signing function: {prefix}fn {function}"
                );
                // Since W4 no signing function takes raw bytes anywhere (the last one,
                // `KindSigner::sign`, was removed).
                assert!(
                    !signature.contains("[u8]") && !signature.contains("Vec<u8>"),
                    "{name}: a signing function over raw bytes: fn {function}"
                );
            }
            if public && let Some(returns) = signature.split("->").nth(1) {
                assert!(
                    !returns.contains("HybridKey"),
                    "{name}: a public function returns a key: fn {function}"
                );
            }
        }
    }
    // The typed capabilities sign, and authorize.rs dispatches; nothing else.
    assert_eq!(
        sign_callers,
        BTreeSet::from(["authorize.rs".to_string(), "capability.rs".to_string()]),
        "the check must find exactly the real signing calls"
    );
    assert_eq!(
        key_holders,
        BTreeSet::from([
            "authorize.rs".to_string(),
            "capability.rs".to_string(),
            "rotation_signer.rs".to_string(),
        ]),
        "only the signers and the capability module hold or seal a key"
    );
    assert_eq!(
        sqlite_users,
        BTreeSet::from(["outbox_sqlite.rs".to_string()]),
        "only the durable outbox touches SQLite"
    );
}

/// Order W4: the key is sealed and handlers get typed capabilities only. The sealed key, the key
/// ring and every constructor are crate-private and the key field is private to capability.rs;
/// apart from those, NOTHING in capability.rs is crate-private, so everything a handler can reach
/// from the `&KindSigner` it is lent is either public (and so checked by the compile-fail doctests
/// from outside) or private to the module (and so out of every handler's reach as well).
#[test]
fn key_access_for_operations_is_sealed_and_typed() {
    let capability =
        code_without_comments(&read(&root().join("src/capability.rs")).replace('\r', ""));
    let production = &capability[..capability
        .find("\n#[cfg(test)]\nmod ")
        .unwrap_or(capability.len())];
    assert!(production.contains("pub(crate) struct SealedKey {\n    key: HybridKey,\n}"));
    let crate_private: Vec<&str> = production
        .lines()
        .map(str::trim)
        .filter(|line| line.contains("pub("))
        .collect();
    assert_eq!(
        crate_private,
        [
            "pub(crate) struct SealedKey {",
            "pub(crate) fn seal(key: HybridKey) -> Self {",
            "pub(crate) fn public(&self) -> &PublicKey {",
            "pub(crate) struct KeyRing<'k> {",
            "pub(crate) fn single(primary: &'k SealedKey) -> Self {",
            "pub(crate) fn pair(primary: &'k SealedKey, secondary: &'k SealedKey) -> Self {",
            "pub(crate) fn new(kind: OperationKind, ring: KeyRing<'k>) -> Self {",
        ],
        "the crate-private items of capability.rs"
    );
    // No public field anywhere in the module.
    for (index, line) in production.lines().enumerate() {
        let trimmed = line.trim_start();
        if line.starts_with("    pub ")
            && !trimmed.starts_with("pub fn ")
            && !trimmed.starts_with("pub const ")
        {
            panic!("capability.rs:{}: a public field: {trimmed}", index + 1);
        }
    }
    let authorize = read(&root().join("src/authorize.rs"));
    assert!(
        authorize.contains("pub(crate) fn run_authorization"),
        "run_authorization must stay crate-private"
    );
    let plan = read(&root().join("src/plan.rs"));
    assert!(
        plan.contains("pub(crate) trait OperationHandler"),
        "the handler registry stays closed"
    );
}

/// The type-level claim another crate (the desktop) relies on (fixes of the independent wallet
/// review, MAJOR-2): outside this crate an `Approval`, a `SigningGate`, a `KeySigner` or a
/// `RotationSigner` comes only from the public functions listed here. Every other public function
/// that returns one is behind the non-shipping cfg, the fields are private (no struct literal or
/// functional update can build one), no `Default`, `From`, `TryFrom` or `Clone` makes one, the
/// signers' constructors take a `SigningGate`, and the one gate a shipping build has refuses while
/// production qualification is incomplete. `SignedOperation` is deliberately not in the list: it is
/// public DATA (its variants are public, `SignedOperation::import` builds one from a counterparty's
/// bytes), not a capability, because every consumer derives its metadata from the bytes again.
/// A `SignerIdentity` is public data, but one that carries the Treasury profile comes only from
/// `profile::declare` (fixes of the independent wallet review, MINOR-3): the public constructors
/// build an ordinary identity with no role, and the labelling is crate-private.
#[test]
fn outside_this_crate_the_signing_types_come_only_from_the_gate() {
    const CFG: &str = "#[cfg(any(test, feature = \"test-value-signing\"))]";
    const TYPES: [&str; 12] = [
        "Approval",
        "SigningGate",
        "KeySigner",
        "RotationSigner",
        "SignerIdentity",
        // The signer a handler is lent and its typed capabilities (Order W4).
        "KindSigner",
        "TransferSpend",
        "BondAuthorization",
        "ClaimAuthorization",
        "TradeApproval",
        "RotationProofs",
        "TreasuryFreeze",
    ];
    let word = |text: &str, name: &str| {
        text.match_indices(name).any(|(at, _)| {
            let before = text[..at].chars().next_back();
            let after = text[at + name.len()..].chars().next();
            !before.is_some_and(|c| c.is_alphanumeric() || c == '_')
                && !after.is_some_and(|c| c.is_alphanumeric() || c == '_')
        })
    };
    let mut files = Vec::new();
    rust_files(&root().join("src"), &mut files);
    // (file, impl type, fn, gated, signature) of every public function that returns one of TYPES.
    let mut found = BTreeSet::new();
    let mut signatures = BTreeMap::new();
    for file in &files {
        let name = file
            .strip_prefix(root().join("src"))
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let code = code_without_comments(&read(file).replace('\r', ""));
        // Everything after the file's own unit-test module is test-only by construction.
        let code = &code[..code.find("\n#[cfg(test)]\nmod ").unwrap_or(code.len())];
        let lines: Vec<&str> = code.lines().collect();
        let mut current_impl = String::new();
        for (index, line) in lines.iter().enumerate() {
            if *line == "}" {
                current_impl.clear();
                continue;
            }
            if line.starts_with("impl") {
                let head = line.trim_end_matches('{').trim();
                let target = head.rsplit(" for ").next().unwrap_or(head);
                let target = target.trim_start_matches("impl").trim_start();
                let target = if target.starts_with('<') {
                    target[target.find('>').unwrap() + 1..].trim()
                } else {
                    target
                };
                current_impl = target
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect();
                continue;
            }
            let trimmed = line.trim_start();
            let Some(rest) = trimmed.strip_prefix("pub fn ") else {
                continue;
            };
            let function: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let mut signature = String::new();
            for next in &lines[index..] {
                signature.push_str(next.trim());
                signature.push(' ');
                if next.contains('{') || next.trim_end().ends_with(';') {
                    break;
                }
            }
            let signature = signature[..signature.find('{').unwrap_or(signature.len())].to_string();
            let returns = signature.rsplit("->").next().unwrap_or("");
            // A function that returns a reference hands out what exists already: not a way in.
            if !signature.contains("->") || returns.contains('&') {
                continue;
            }
            let produced = if word(returns, "Self") {
                current_impl.clone()
            } else {
                match TYPES.iter().find(|t| word(returns, t)) {
                    Some(t) => t.to_string(),
                    None => continue,
                }
            };
            if !TYPES.contains(&produced.as_str()) {
                continue;
            }
            let mut gated = false;
            for above in lines[..index].iter().rev() {
                let above = above.trim();
                if above == CFG {
                    gated = true;
                } else if !above.starts_with("#[") {
                    break;
                }
            }
            let key = format!("{name} {current_impl}::{function} -> {produced}");
            found.insert((key.clone(), gated));
            signatures.insert(key, signature);
        }
    }
    let expected: BTreeSet<(String, bool)> = [
        ("authorize.rs SigningGate::production -> SigningGate", false),
        ("authorize.rs SigningGate::test_value -> SigningGate", true),
        (
            "authorize.rs Approval::for_review_for_test -> Approval",
            true,
        ),
        ("authorize.rs ReviewGate::approve -> Approval", false),
        ("authorize.rs ReviewGate::approve_at -> Approval", true),
        ("authorize.rs KeySigner::new_initial -> KeySigner", false),
        ("authorize.rs KeySigner::new_rotated -> KeySigner", false),
        ("authorize.rs KeySigner::with_identity -> KeySigner", false),
        ("authorize.rs KeySigner::for_test -> KeySigner", true),
        ("plan.rs PlanSession::approve -> Approval", false),
        (
            "rotation_signer.rs RotationSigner::new -> RotationSigner",
            false,
        ),
        (
            "rotation_signer.rs RotationSigner::for_test -> RotationSigner",
            true,
        ),
        // A typed capability comes only from the `&KindSigner` a handler is lent (whose only
        // constructor is crate-private), after the kind's row of `capabilities` and `domain_for`.
        (
            "capability.rs KindSigner::transfer_spend -> TransferSpend",
            false,
        ),
        (
            "capability.rs KindSigner::bond_authorization -> BondAuthorization",
            false,
        ),
        (
            "capability.rs KindSigner::claim_authorization -> ClaimAuthorization",
            false,
        ),
        (
            "capability.rs KindSigner::trade_approval -> TradeApproval",
            false,
        ),
        (
            "capability.rs KindSigner::rotation_proofs -> RotationProofs",
            false,
        ),
        (
            "capability.rs KindSigner::treasury_freeze -> TreasuryFreeze",
            false,
        ),
        ("authorize.rs SignerIdentity::new -> SignerIdentity", false),
        (
            "authorize.rs SignerIdentity::from_public -> SignerIdentity",
            false,
        ),
        (
            "authorize.rs SignerIdentity::with_treasury_roles_for_test -> SignerIdentity",
            true,
        ),
        ("profile.rs ::declare -> SignerIdentity", false),
    ]
    .into_iter()
    .map(|(key, gated)| (key.to_string(), gated))
    .collect();
    assert_eq!(
        found, expected,
        "the public ways to an Approval, a SigningGate or a signer changed"
    );
    // An ungated signer constructor needs a gate; an ungated approval comes from the review gate.
    for (key, signature) in &signatures {
        if key.ends_with("-> KeySigner") || key.ends_with("-> RotationSigner") {
            assert!(
                key.contains("::for_test ") || signature.contains("gate: SigningGate"),
                "{key}: {signature}"
            );
        }
    }
    let authorize =
        code_without_comments(&read(&root().join("src/authorize.rs")).replace('\r', ""));
    assert!(
        authorize.contains(
            "pub fn production() -> Result<Self, Refusal> {\n        if !mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED {\n            return Err(Refusal::GateClosed);"
        ),
        "the production gate refuses while production qualification is incomplete"
    );
    const {
        assert!(
            !mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED,
            "the production gate stays closed"
        )
    };
    // The public constructors of an identity build an ORDINARY one with no Treasury role (`new`;
    // `from_public` goes through `new`), and the labelling is crate-private (`declare` uses it).
    assert_eq!(
        authorize
            .matches("            profile: WalletProfile::Ordinary,\n            roles: TreasuryRoles::default(),\n")
            .count(),
        1
    );
    assert!(authorize.contains("        Self::new(&descriptor, authority)\n"));
    assert!(authorize.contains("    pub(crate) fn with_treasury_roles("));
    assert!(!authorize.contains("pub fn with_profile("));
    assert!(!authorize.contains("pub fn with_treasury_roles("));
    // Private fields only, and nothing else that makes one.
    let rotation =
        code_without_comments(&read(&root().join("src/rotation_signer.rs")).replace('\r', ""));
    let capability =
        code_without_comments(&read(&root().join("src/capability.rs")).replace('\r', ""));
    for (code, name) in [
        (&authorize, "Approval"),
        (&authorize, "SigningGate"),
        (&authorize, "KeySigner"),
        (&rotation, "RotationSigner"),
        (&authorize, "SignerIdentity"),
        (&capability, "KindSigner<'k>"),
        (&capability, "TransferSpend<'k>"),
        (&capability, "BondAuthorization<'k>"),
        (&capability, "ClaimAuthorization<'k>"),
        (&capability, "TradeApproval<'k>"),
        (&capability, "RotationProofs<'k>"),
        (&capability, "TreasuryFreeze<'k>"),
    ] {
        let start = code
            .find(&format!("\npub struct {name} {{\n"))
            .unwrap_or_else(|| panic!("pub struct {name}"));
        let body = &code[start + 1..];
        let body = &body[..body.find("\n}\n").unwrap()];
        for field in body.lines().skip(1) {
            assert!(
                !field.trim_start().starts_with("pub"),
                "{name}: a public field: {field}"
            );
        }
        let attributes: Vec<&str> = code[..start]
            .lines()
            .rev()
            .take_while(|line| line.starts_with("#["))
            .collect();
        // An identity is public data and may be cloned; nothing else here may be.
        assert!(
            attributes.iter().all(|a| (name == "SignerIdentity"
                || !a.contains("Clone") && !a.contains("Copy"))
                && !a.contains("Default")),
            "{name}: {attributes:?}"
        );
    }
    for file in &files {
        let code = code_without_comments(&read(file).replace('\r', ""));
        for line in code.lines().filter(|line| line.starts_with("impl")) {
            for name in TYPES {
                if !line.contains(&format!(" for {name}")) {
                    continue;
                }
                assert!(
                    line.starts_with("impl fmt::Debug for ")
                        || line.starts_with("impl Signer for "),
                    "{}: {line}",
                    file.display()
                );
            }
        }
    }
}

fn cargo(args: &[&str]) -> String {
    let output = Command::new(option_env!("CARGO").unwrap_or("cargo"))
        .current_dir(root())
        .args(args)
        .output()
        .expect("cargo runs");
    assert!(
        output.status.success(),
        "cargo {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).replace('\r', "")
}

#[test]
fn the_resolved_graph_has_no_gui_os_network_or_bitcoin_crates_and_the_right_features() {
    // Normal and build edges only: dev-dependencies (and so the test gate) are not part of it.
    let tree = cargo(&[
        "tree",
        "--offline",
        "--locked",
        "-e",
        "normal,build",
        "--prefix",
        "none",
        "--no-dedupe",
        "-f",
        "{p}|{f}",
    ]);
    let mut features: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in tree.lines().filter(|l| !l.trim().is_empty()) {
        let line = line.trim_end_matches(" (*)");
        let (package, feature_list) = line.split_once('|').unwrap_or((line, ""));
        let name = package.split(' ').next().unwrap().to_string();
        let set: BTreeSet<String> = feature_list
            .split(',')
            .map(str::trim)
            .filter(|f| !f.is_empty())
            .map(String::from)
            .collect();
        features.entry(name).or_default().extend(set);
    }
    for name in features.keys() {
        assert!(
            !FORBIDDEN_PACKAGES.contains(&name.as_str()),
            "the graph contains {name}"
        );
        for banned in ["bitcoin", "secp256k1", "winit", "egui", "windows"] {
            if banned == "bitcoin" && ALLOWED_BITCOIN_NAMED_PACKAGES.contains(&name.as_str()) {
                continue;
            }
            assert!(!name.starts_with(banned), "the graph contains {name}");
        }
    }
    // The one allowed package with a Bitcoin-sounding name is a HASH FUNCTION library pulled in by
    // crypto-v2 's BIP-39 mnemonic code in every root of this repository. Pin exactly that.
    let parents = cargo(&[
        "tree",
        "--offline",
        "--locked",
        "-e",
        "normal,build",
        "--prefix",
        "none",
        "--no-dedupe",
        "-i",
        "bitcoin_hashes",
    ]);
    let parent_names: BTreeSet<String> = parents
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| l.split(' ').next().unwrap().to_string())
        .collect();
    assert_eq!(
        parent_names,
        BTreeSet::from(
            [
                "bitcoin_hashes",
                "bip39",
                "mutiny-crypto-v2",
                "mutiny-consensus-v8",
                "mutiny-wallet-core-v8"
            ]
            .map(String::from)
        ),
        "bitcoin_hashes may only enter through crypto-v2 and bip39"
    );
    // The root and the two sibling crates, with exactly the declared features.
    assert_eq!(
        features["mutiny-wallet-core-v8"],
        BTreeSet::from(["default".to_string()]),
        "only the (empty) default feature is on in a normal build"
    );
    // With dev-dependency edges the test gate appears: that is the self reference, and only there.
    let with_dev = cargo(&[
        "tree",
        "--offline",
        "--locked",
        "-e",
        "normal,build,dev",
        "--prefix",
        "none",
        "--no-dedupe",
        "-f",
        "{p}|{f}",
    ]);
    assert!(
        with_dev
            .lines()
            .any(|l| l.starts_with("mutiny-wallet-core-v8 ") && l.contains("test-value-signing"))
    );
    assert_eq!(
        features["mutiny-crypto-v2"],
        BTreeSet::from(["wallet-custody".to_string()])
    );
    assert_eq!(
        features["mutiny-consensus-v8"],
        BTreeSet::from(["default".to_string()])
    );
    assert!(
        !features.contains_key("mutinyd-v8"),
        "the node library is not a dependency of the wallet core"
    );
    assert!(
        !features.contains_key("mutiny-transport-v2"),
        "no transport dependency"
    );
    // The offline release signer's custody feature never appears.
    assert!(!tree.contains("release-custody") && !tree.contains("receipt-qualification"));
    assert!(!tree.contains("dividend-test-fixtures") && !tree.contains("legacy-v0-test-fixtures"));
    assert!(
        !tree.contains("test-value-signing"),
        "the test gate is not in a normal graph"
    );
}

#[test]
fn the_locked_offline_resolution_is_consistent() {
    let metadata = cargo(&[
        "metadata",
        "--offline",
        "--locked",
        "--format-version",
        "1",
        "--no-deps",
    ]);
    assert!(metadata.contains("\"name\":\"mutiny-wallet-core-v8\""));
    assert!(metadata.contains("\"test-value-signing\":[]"));
    assert!(metadata.contains("\"default\":[]"));
}

#[test]
fn the_other_roots_cannot_pull_the_test_gate_or_the_wrong_custody_into_the_wallet() {
    // Exact reviewed W15 opt-in window and DEV edge. These manifest assertions do not
    // replace normal/build graph and actual shipping-binary exclusion verification.
    let desktop_source = read(&root().join("../desktop/Cargo.toml"));
    let desktop = tables(&desktop_source);
    assert_eq!(desktop["features"].len(), 1, "no default or unreviewed signing feature");
    assert_eq!(desktop["features"]["testvalue-window"],
        r#"["mutiny-wallet-core-v8/test-value-signing"]"#);
    // The simple `tables` helper collapses repeated [[bin]] tables: inspect every one
    // separately so an ordinary binary cannot acquire the explicit TEST-VALUE feature.
    let mut bins = BTreeMap::<String, BTreeMap<String, String>>::new();
    let mut bin = None::<BTreeMap<String, String>>;
    for line in desktop_source.lines().chain(std::iter::once("[end]")) {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            if let Some(entries) = bin.take() {
                let name = entries.get("name").expect("named binary").clone();
                assert!(bins.insert(name, entries).is_none(), "duplicate binary");
            }
            if line == "[[bin]]" { bin = Some(BTreeMap::new()); }
        } else if !line.starts_with('#') && let Some(entries) = bin.as_mut()
            && let Some((key, value)) = line.split_once('=') {
            assert!(entries.insert(key.trim().into(), value.trim().into()).is_none(),
                "duplicate binary property");
        }
    }
    assert_eq!(bins.len(), 3, "exact ordinary and two TEST-VALUE binaries");
    for (name, path, test_value) in [
        ("mutiny-wallet-v8", "src/main.rs", false),
        ("mutiny-wallet-v8-testvalue", "src/testvalue/main.rs", true),
        ("mutiny-treasury-v8-testvalue", "src/testvalue/treasury_main.rs", true),
    ] {
        let entries = &bins[&format!("\"{name}\"")];
        assert_eq!(entries["path"], format!("\"{path}\""));
        assert_eq!(entries.len(), if test_value { 3 } else { 2 });
        assert_eq!(entries.get("required-features").map(String::as_str),
            if test_value { Some(r#"["testvalue-window"]"#) } else { None });
    }
    for (table, entries) in &desktop {
        for (name, value) in entries {
            if value.contains("test-value-signing") || name.contains("test-value-signing") {
                let exact_dev = table == "dev-dependencies" && name == "mutiny-wallet-core-v8"
                    && value == r#"{ path = "../wallet-core", features = ["test-value-signing"] }"#;
                let exact_window = table == "features" && name == "testvalue-window"
                    && value == r#"["mutiny-wallet-core-v8/test-value-signing"]"#;
                assert!(exact_dev || exact_window,
                    "signing gate outside the exact reviewed DEV or explicitly selected W15 feature");
            }
        }
    }
    assert_eq!(
        desktop["dependencies"]["mutiny-wallet-core-v8"], r#"{ path = "../wallet-core" }"#,
        "desktop must depend on wallet-core with default features"
    );
    assert!(
        desktop
            .iter()
            .filter(|(table, _)| table.contains("dependencies"))
            .all(
                |(table, entries)| !entries.contains_key("mutiny-wallet-core-v8")
                    || table == "dependencies"
                    || table == "dev-dependencies"
            ),
        "wallet-core in another dependencies table of the desktop"
    );
    let signer = read(&root().join("../release-signer/Cargo.toml"));
    for banned in [
        "wallet-custody",
        "mutiny-consensus-v8",
        "mutinyd-v8",
        "mutiny-transport-v2",
        "mutiny-wallet-core-v8",
        "rusqlite",
        "eframe",
    ] {
        assert!(
            !signer.contains(banned),
            "the offline release signer must not depend on {banned}"
        );
    }
    assert!(signer.contains("release-custody"));
}

#[test]
fn every_test_gate_item_is_behind_the_non_shipping_cfg() {
    const CFG: &str = "#[cfg(any(test, feature = \"test-value-signing\"))]";
    // Definitions and match arms that exist only because of the test gate.
    let needles = [
        "pub fn test_value(",
        "pub fn for_test(",
        "pub fn for_review_for_test(",
        "pub fn with_treasury_roles_for_test(",
        "pub fn corrupt_for_test(",
        "pub const TEST_VALUE_GATE_MARKER",
        "GateMode::TestValue =>",
        // Explicit clocks and limits: a shipping build reads the real monotonic clock and uses the
        // fixed age limits, so a host cannot move time or widen them.
        "pub fn present_at(",
        "pub fn approve_at(",
        "pub fn authorize_at(",
        "pub fn with_limits(max_review_age",
        // Store rewrites that model someone who can rewrite the outbox (W6 export tests).
        "pub fn rewrite_for_test(",
        "pub fn set_approval_for_test(",
        "pub(crate) fn rechecksum_for_test(",
    ];
    let mut files = Vec::new();
    rust_files(&root().join("src"), &mut files);
    let mut seen = 0;
    for file in files {
        let text = read(&file);
        let lines: Vec<&str> = text.lines().collect();
        // Everything after the file's own unit-test module is test-only by construction.
        let limit = lines
            .iter()
            .position(|line| *line == "#[cfg(test)]")
            .unwrap_or(lines.len());
        for (index, line) in lines[..limit].iter().enumerate() {
            if line.trim_start().starts_with("//")
                || !needles.iter().any(|needle| line.contains(needle))
            {
                continue;
            }
            seen += 1;
            let mut guarded = false;
            let mut up = index;
            while up > 0 {
                up -= 1;
                let above = lines[up].trim();
                if above == CFG {
                    guarded = true;
                    break;
                }
                if above.starts_with("//") || above.starts_with("#[") {
                    continue;
                }
                break;
            }
            assert!(
                guarded,
                "{}:{}: test-gate item without the non-shipping cfg: {}",
                file.display(),
                index + 1,
                line.trim()
            );
        }
    }
    assert!(
        seen >= 10,
        "the scan must actually find the gated items (found {seen})"
    );
}

#[test]
fn the_gate_marker_is_in_a_test_gate_binary_because_the_library_embeds_it() {
    use mutiny_wallet_core_v8::{GateMode, SigningGate};
    // This test binary links the library WITH the test gate (the dev-dependency self reference).
    // The marker is assembled from pieces here, so the only way it can be inside this executable
    // is that the library itself embeds it; the shipping exclusion check relies on the same string
    // being absent from a build without the feature.
    let gate = SigningGate::test_value().expect("a test build has the test gate");
    assert_eq!(gate.mode(), GateMode::TestValue);
    let marker = ["MUTINY", "WALLET", "CORE", "TEST", "VALUE", "GATE", "V1"].join("-");
    // (Read from the source, not from the constant: using the constant here would put the string
    // into this binary by itself and make the check below prove nothing.)
    assert!(
        read(&root().join("src/authorize.rs")).contains(&format!(
            "pub const TEST_VALUE_GATE_MARKER: &str = \"{marker}\";"
        )),
        "the marker this test looks for is the one the library defines"
    );
    let exe = fs::read(std::env::current_exe().unwrap()).unwrap();
    let needle = marker.as_bytes();
    assert!(
        exe.windows(needle.len()).any(|window| window == needle),
        "the marker must be present in a binary that contains the test gate"
    );
}
