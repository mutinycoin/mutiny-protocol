//! Guard: shipping and test source must never depend (at compile time) on private, gitignored
//! host evidence. A fresh clone has none of it. Physical evidence is read at RUNTIME from an
//! explicit path instead (see tests/tpm.rs).
#[path = "support/ignore_rules.rs"]
mod ignore_rules;
use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if p.is_dir() {
            if !matches!(name.as_str(), "target" | ".git" | "node_modules" | "crypto-v2-sources") {
                rust_files(&p, out);
            }
        } else if name.ends_with(".rs") {
            out.push(p);
        }
    }
}
fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}
const PRIVATE_MARKERS: [&str; 3] = ["node-a-", "live-tpm", "private-evidence"];

#[test]
fn no_source_mentions_private_host_evidence_files() {
    let mut files = Vec::new();
    rust_files(&root(), &mut files);
    assert!(files.len() > 50, "walk found too few sources: {}", files.len());
    for f in files {
        if f.file_name().unwrap() == "private_evidence_guard.rs" {
            continue;
        }
        let text = std::fs::read_to_string(&f).unwrap_or_default().to_lowercase();
        for m in PRIVATE_MARKERS {
            assert!(!text.contains(m), "{} references private evidence marker {m:?}", f.display());
        }
    }
}

/// No `include_str!`/`include_bytes!`/`include!` names a `qualification/` file that `.gitignore`
/// ignores on a case-sensitive OR a case-insensitive checkout (git's semantics, see
/// `support/ignore_rules.rs`: `*` never crosses `/`, a matched directory ignores its contents).
#[test]
fn no_compile_time_include_of_a_gitignored_qualification_file() {
    let patterns = ignore_rules::qualification_patterns(&root());
    assert!(patterns.len() >= 3);
    let mut files = Vec::new();
    rust_files(&root(), &mut files);
    for f in files {
        if f.file_name().unwrap() == "private_evidence_guard.rs" {
            continue;
        }
        let text = std::fs::read_to_string(&f).unwrap_or_default();
        for mac in ["include_str!", "include_bytes!", "include!"] {
            for (at, _) in text.match_indices(mac) {
                let arg: String = text[at..].chars().take(300).collect();
                let arg = arg.split(')').next().unwrap();
                if let Some(q) = arg.to_ascii_lowercase().find("qualification/") {
                    let file = arg[q + "qualification/".len()..].trim_end_matches(['"', ' ', '\n', '\r']);
                    assert!(
                        !ignore_rules::ignored(&patterns, file) && !ignore_rules::ignored_ignoring_case(&patterns, file),
                        "{} include!s gitignored {file:?}",
                        f.display()
                    );
                }
            }
        }
    }
}

/// Strings that identified one developer host and its helper (and the removed ambient profile
/// pin). They must not occur anywhere in the source of a shipped crate (tests included) or in the
/// shipping configuration record, so no build or configuration can depend on that host. The
/// release binaries are checked for the same strings by build/check-shipping-config.sh.
pub const HOST_SPECIFIC: [&str; 6] = [
    "mutiny-node2",
    "mutinyadmin",
    "tpm_signer.py",
    "linux_tpm_signing_helper",
    "serve-qualification",
    "MUTINYD_PHYSICAL_PROFILE_COMMITMENT",
];
#[test]
fn shipped_sources_and_config_name_no_developer_host_or_helper() {
    let mut files = Vec::new();
    for d in ["consensus/src", "node/src", "crypto-v2/src", "transport-v2/src"] {
        rust_files(&root().join(d), &mut files);
    }
    assert!(files.len() > 100, "walk found too few shipped sources: {}", files.len());
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap();
        for s in HOST_SPECIFIC {
            assert!(!text.contains(s), "{} contains {s:?}", f.display());
        }
        // The qualification-only external helper bridge is never reachable from shipped source.
        for s in ["examples/support", "external_helper_bridge", "tpm_bridge"] {
            assert!(!text.contains(s), "{} references qualification tooling {s:?}", f.display());
        }
    }
    let config = std::fs::read_to_string(root().join("build/shipping-configurations-v1.json")).unwrap();
    for s in HOST_SPECIFIC {
        assert!(!config.contains(s), "shipping configuration contains {s:?}");
    }
}

/// The private-evidence spellings are named explicitly, uppercase, lowercase and in any
/// capitalisation: a case-sensitive checkout (Linux) matches `.gitignore` patterns exactly and must
/// not depend on core.ignorecase.
#[test]
fn gitignore_names_private_evidence_explicitly_in_every_case() {
    let ignore = std::fs::read_to_string(root().join(".gitignore")).unwrap();
    for needed in [
        "qualification/NODE-A-*.json",
        "qualification/node-a-*",
        "qualification/[Nn][Oo][Dd][Ee]-[Aa]-*",
        "qualification/*LIVE-TPM*",
        "qualification/*live-tpm*",
        "qualification/*[Ll][Ii][Vv][Ee]-[Tt][Pp][Mm]*",
        "qualification/*private*",
        "qualification/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*",
        "qualification/JOIN-PHYSICAL-FIXTURE-V1.json",
        "qualification/RECOVERY-MATERIAL-PHYSICAL-FIXTURE-V1.json",
        "qualification/ROTATION-PHYSICAL-FIXTURE-V1.json",
    ] {
        assert!(ignore.lines().any(|l| l.trim() == needed), "{needed} missing from .gitignore");
    }
}

/// With git's semantics on a case-SENSITIVE checkout, representative private-evidence paths are
/// ignored (including everything inside a `qualification/node-a-linux/` directory, which the
/// former rules missed) and representative public fixtures are not. Paths only: no such file is
/// created or opened. The model of git's semantics is checked against git itself by
/// `git -c core.ignorecase=false check-ignore` in the review record, not here (no git in packages).
#[test]
fn gitignore_ignores_private_evidence_on_case_sensitive_checkouts() {
    use ignore_rules::{ignored, ignores};
    let patterns = ignore_rules::qualification_patterns(&root());
    for private in [
        "node-a-linux",
        "node-a-linux/quote.json",
        "node-a-linux/sub/report.json",
        "node-a-native.json",
        "NODE-A-LIVE-TPM-QUOTE-V1.json",
        "NODE-A-NATIVE-TPM-PUBLIC-FIXTURE.json",
        "Node-A-Mixed/evidence.json",
        "x-live-tpm.json",
        "X-Live-Tpm-Quote.json",
        "private-evidence.json",
        "PRIVATE-EVIDENCE/report.json",
        "Private-Evidence-Notes.txt",
        "JOIN-PHYSICAL-FIXTURE-V1.json",
        "RECOVERY-MATERIAL-PHYSICAL-FIXTURE-V1.json",
        "ROTATION-PHYSICAL-FIXTURE-V1.json",
    ] {
        assert!(ignored(&patterns, private), "qualification/{private} is NOT ignored on a case-sensitive checkout");
    }
    for public in [
        "TEST-VALUE-SOFTWARE-TPM-FIXTURE-V1.json",
        "JOIN-TEST-VALUE-FIXTURE-V1.json",
        "RECOVERY-MATERIAL-TEST-VALUE-FIXTURE-V1.json",
        "ROTATION-TEST-VALUE-FIXTURE-V1.json",
        "GENESIS-BINDING-VECTORS-STATE-V2.json",
        "node-admission-v2-public-v1.json",
        "read-node-a-tpm.ps1",
        "run-node-a-tpm-proof.ps1",
        "nonce-20261002/README.md",
    ] {
        assert!(!ignored(&patterns, public), "qualification/{public} would be ignored");
    }
    // The matcher itself: `*` never crosses `/`; a matched directory ignores everything below it;
    // an anchored pattern matches at the top of qualification/ only; classes are case exact.
    assert!(!ignores("node-a-*.json", "node-a-linux/quote.json"));
    assert!(ignores("node-a-*", "node-a-linux/quote.json"));
    assert!(!ignores("*LIVE-TPM*", "sub/x-LIVE-TPM.json"));
    assert!(ignores("[Nn][Oo][Dd][Ee]-[Aa]-*", "NoDe-a-x"));
    assert!(!ignores("node-a-*", "NODE-A-x"), "case-sensitive");
    assert!(!ignores("dir/", "dir") && ignores("dir/", "dir/x"), "a trailing slash matches directories only");
}
