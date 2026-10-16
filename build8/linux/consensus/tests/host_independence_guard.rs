//! Source guards: consensus acceptance and custody must not depend on the developer host.
//!
//! TRIPWIRES, NOT PROPERTIES. These guards match spellings in source text, so a spelling they do
//! not list, a computed path, a new dependency or a helper process can still reach the host. The
//! property itself (a validator-local physical map, verifier or pin cannot change what consensus
//! accepts) is tested separately by the pin-invariance tests (`recovery_native_store.rs` T8 and the
//! node's `physical_profile_pin_only_narrows_and_never_admits`).
//!
//! One rule set, `build/host-independence-rules.txt` (host identity, process environment, string
//! assembly, and the explicit allow-list), and one probe corpus, `build/host-independence-probes.txt`,
//! are shared with `build/check-host-independence.pl`, which `build/check-shipping-config.sh` runs:
//! the two guards apply the same rules with the same model of test code and must reach the expected
//! verdict on every probe. The model of test code:
//! * comments are removed; string, raw-string, byte-string and char literals are kept (they can
//!   name a host file) but never count as code structure;
//! * an item preceded by an attribute whose whitespace-free text starts with `#[cfg(test)]` or
//!   `#[cfg(all(test,` is test code up to its end: the first `;` or `,` at its own nesting level,
//!   the `}` that closes its body, or the point where an enclosing block or bracket closes. Code
//!   after that point, even on the same line, is shipped code. `#[cfg(any(test, ...))]` is shipped;
//! * a file included by a test-only `#[path] mod`, and transitively every file such a test file
//!   includes by `#[path]`, is a test file.
//! Known limits (both guards): macro_rules! bodies and generic angle brackets are not modelled (a
//! `,` inside `<..>` ends a test item early, so code is treated as SHIPPED: the safe direction).
//! Host-specific helper/alias strings and the reachability of the qualification-only helper bridge
//! are guarded in `private_evidence_guard.rs` and `build/check-shipping-config.sh`.
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_path_buf()
}
fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// One comment-free source character: its line and whether it lies inside a literal.
#[derive(Clone, Copy)]
struct Ch {
    line: usize,
    c: char,
    lit: bool,
}
/// Raw string opening at `i` (`r"`, `r#"`, `br"`, ...): (index of the opening quote, hash count).
fn raw_start(c: &[char], i: usize) -> Option<(usize, usize)> {
    let start = if c[i] == 'b' { i + 2 } else { i + 1 };
    let mut j = start;
    while j < c.len() && c[j] == '#' {
        j += 1;
    }
    (j < c.len() && c[j] == '"').then_some((j, j - start))
}
fn lex(text: &str) -> Vec<Ch> {
    #[derive(PartialEq)]
    enum S {
        Code,
        Line,
        Block(u32),
        Str,
        Raw(usize),
    }
    let c: Vec<char> = text.chars().collect();
    let n = c.len();
    let mut out = Vec::new();
    let (mut line, mut i, mut state) = (1usize, 0usize, S::Code);
    let emit = |out: &mut Vec<Ch>, line: usize, ch: char, lit: bool| out.push(Ch { line, c: ch, lit });
    while i < n {
        let x = c[i];
        let nx = if i + 1 < n { c[i + 1] } else { '\0' };
        if x == '\n' {
            if state == S::Line {
                state = S::Code;
            }
            line += 1;
            i += 1;
            continue;
        }
        match state {
            S::Line => i += 1,
            S::Block(depth) => {
                if x == '*' && nx == '/' {
                    state = if depth == 1 { S::Code } else { S::Block(depth - 1) };
                    i += 2;
                } else if x == '/' && nx == '*' {
                    state = S::Block(depth + 1);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            S::Str => {
                emit(&mut out, line, x, true);
                if x == '\\' {
                    if nx == '\n' {
                        line += 1;
                    } else if i + 1 < n {
                        emit(&mut out, line, nx, true);
                    }
                    i += 2;
                } else {
                    if x == '"' {
                        state = S::Code;
                    }
                    i += 1;
                }
            }
            S::Raw(hashes) => {
                emit(&mut out, line, x, true);
                if x == '"' && (1..=hashes).all(|k| i + k < n && c[i + k] == '#') {
                    for _ in 0..hashes {
                        emit(&mut out, line, '#', true);
                    }
                    i += hashes;
                    state = S::Code;
                }
                i += 1;
            }
            S::Code => {
                let after_word = i > 0 && (c[i - 1].is_ascii_alphanumeric() || c[i - 1] == '_');
                if x == '/' && nx == '/' {
                    state = S::Line;
                    i += 2;
                } else if x == '/' && nx == '*' {
                    state = S::Block(1);
                    i += 2;
                } else if x == '"' {
                    emit(&mut out, line, x, true);
                    state = S::Str;
                    i += 1;
                } else if (x == 'r' || (x == 'b' && nx == 'r')) && !after_word && raw_start(&c, i).is_some() {
                    let (j, hashes) = raw_start(&c, i).unwrap();
                    for &ch in &c[i..=j] {
                        emit(&mut out, line, ch, true);
                    }
                    state = S::Raw(hashes);
                    i = j + 1;
                } else if x == '\'' && nx == '\\' {
                    // Escaped char literal ('\n', '\'', '\u{..}'), never past the end of the line.
                    let mut j = i + 3;
                    while j < n && c[j] != '\'' && c[j] != '\n' {
                        j += 1;
                    }
                    let end = if j < n && c[j] == '\'' { j } else { j - 1 };
                    for &ch in &c[i..=end] {
                        emit(&mut out, line, ch, true);
                    }
                    i = end + 1;
                } else if x == '\'' && i + 2 < n && c[i + 2] == '\'' {
                    for &ch in &c[i..=i + 2] {
                        emit(&mut out, line, ch, true);
                    }
                    i += 3;
                } else {
                    // Code, including the quote of a lifetime ('a).
                    emit(&mut out, line, x, false);
                    i += 1;
                }
            }
        }
    }
    out
}

/// Outer attribute starting at `i`: (end index, whitespace-free text, its literal characters).
fn attribute_at(ch: &[Ch], i: usize) -> Option<(usize, String, String)> {
    let n = ch.len();
    if i >= n || ch[i].lit || ch[i].c != '#' {
        return None;
    }
    let mut j = i + 1;
    while j < n && !ch[j].lit && ch[j].c.is_whitespace() {
        j += 1;
    }
    if j >= n || ch[j].lit || ch[j].c != '[' {
        return None;
    }
    let (mut depth, mut compact, mut lit) = (0i64, String::from("#"), String::new());
    for (k, x) in ch.iter().enumerate().skip(j) {
        if x.lit {
            compact.push(x.c);
            lit.push(x.c);
            continue;
        }
        if !x.c.is_whitespace() {
            compact.push(x.c);
        }
        if x.c == '[' {
            depth += 1;
        } else if x.c == ']' {
            depth -= 1;
            if depth == 0 {
                return Some((k + 1, compact, lit));
            }
        }
    }
    Some((n, compact, lit))
}
fn test_only(compact: &str) -> bool {
    compact.starts_with("#[cfg(test)]") || compact.starts_with("#[cfg(all(test,")
}
/// First index after the item that starts at `start`.
fn item_end(ch: &[Ch], start: usize) -> usize {
    let (mut brace, mut paren) = (0i64, 0i64);
    for (k, x) in ch.iter().enumerate().skip(start) {
        if x.lit {
            continue;
        }
        match x.c {
            '(' | '[' => paren += 1,
            ')' | ']' => {
                if paren == 0 && brace == 0 {
                    return k; // an enclosing bracket closes
                }
                if paren > 0 {
                    paren -= 1;
                }
            }
            '{' => brace += 1,
            '}' => {
                if brace == 0 {
                    return k; // an enclosing block closes
                }
                brace -= 1;
                if brace == 0 && paren == 0 {
                    return k + 1; // the item's own body closes
                }
            }
            ';' | ',' if brace == 0 && paren == 0 => return k + 1,
            _ => {}
        }
    }
    ch.len()
}
fn path_of(compact: &str, lit: &str) -> Option<String> {
    if !compact.starts_with("#[path=") {
        return None;
    }
    let start = lit.find('"')? + 1;
    let end = start + lit[start..].find('"')?;
    Some(lit[start..end].to_string())
}
/// (test flag per character, `#[path]` values attached to test-only items).
fn regions(ch: &[Ch]) -> (Vec<bool>, Vec<String>) {
    let n = ch.len();
    let mut test = vec![false; n];
    let mut paths = Vec::new();
    let mut i = 0;
    while i < n {
        let Some((end, compact, _)) = attribute_at(ch, i) else {
            i += 1;
            continue;
        };
        if !test_only(&compact) {
            i = end;
            continue;
        }
        let mut j = end;
        loop {
            while j < n && !ch[j].lit && ch[j].c.is_whitespace() {
                j += 1;
            }
            let Some((e2, c2, l2)) = attribute_at(ch, j) else { break };
            if let Some(p) = path_of(&c2, &l2) {
                paths.push(p);
            }
            j = e2;
        }
        let e = item_end(ch, j);
        for t in &mut test[i..e] {
            *t = true;
        }
        i = if e > i { e } else { i + 1 };
    }
    (test, paths)
}
/// Every `#[path]` value in the characters, test-only or not (used inside test files only).
fn all_paths(ch: &[Ch]) -> Vec<String> {
    (0..ch.len())
        .filter_map(|i| attribute_at(ch, i))
        .filter_map(|(_, compact, lit)| path_of(&compact, &lit))
        .collect()
}
/// (line number, comment-free code) of every NON-test line, and the `#[path]` files that this
/// file includes only under `#[cfg(test)]`.
fn non_test_lines(text: &str) -> (Vec<(usize, String)>, Vec<String>) {
    let ch = lex(text);
    let (test, paths) = regions(&ch);
    let mut by: BTreeMap<usize, String> = BTreeMap::new();
    for (x, t) in ch.iter().zip(&test) {
        if !t {
            by.entry(x.line).or_default().push(x.c);
        }
    }
    let lines = by
        .into_iter()
        .filter_map(|(n, s)| {
            let s = s.trim();
            (!s.is_empty()).then(|| (n, s.to_string()))
        })
        .collect();
    (lines, paths)
}

/// (repository-relative path, text) of every non-test Rust file under consensus/src and node/src.
fn shipped_files() -> Vec<(String, String)> {
    let mut files = Vec::new();
    for d in ["consensus/src", "node/src"] {
        rust_files(&root().join(d), &mut files);
    }
    files.sort();
    let mut texts = BTreeMap::new();
    let (mut test_files, mut queue) = (BTreeSet::new(), Vec::new());
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        for p in non_test_lines(&text).1 {
            if let Ok(c) = f.parent().unwrap().join(p).canonicalize() {
                if test_files.insert(c.clone()) {
                    queue.push(c);
                }
            }
        }
        texts.insert(f, text);
    }
    // A file that a test file includes is a test file too (transitively).
    while let Some(t) = queue.pop() {
        let Ok(text) = std::fs::read_to_string(&t) else { continue };
        for p in all_paths(&lex(&text)) {
            if let Ok(c) = t.parent().unwrap().join(p).canonicalize() {
                if test_files.insert(c.clone()) {
                    queue.push(c);
                }
            }
        }
    }
    texts
        .into_iter()
        .filter(|(f, _)| !test_files.contains(&f.canonicalize().unwrap()))
        .map(|(f, t)| (f.strip_prefix(root()).unwrap().to_string_lossy().replace('\\', "/"), t))
        .collect()
}
/// All non-test lines of every shipped Rust file.
fn shipped_lines() -> Vec<(String, usize, String)> {
    let mut out = Vec::new();
    for (rel, text) in shipped_files() {
        for (n, code) in non_test_lines(&text).0 {
            out.push((rel.clone(), n, code));
        }
    }
    out
}

struct Rule {
    class: String,
    kind: String,
    text: String,
}
struct Allow {
    file: String,
    fragment: String,
}
/// The shared rule set (`build/host-independence-rules.txt`).
fn rule_set() -> (Vec<Rule>, Vec<Allow>) {
    let text = std::fs::read_to_string(root().join("build/host-independence-rules.txt")).unwrap();
    let (mut rules, mut allows) = (Vec::new(), Vec::new());
    let field = |s: &str| -> (String, String) {
        let s = s.trim_start();
        let (a, b) = s.split_once(char::is_whitespace).unwrap_or((s, ""));
        (a.to_string(), b.trim().to_string())
    };
    for raw in text.lines() {
        let l = raw.trim_end_matches('\r');
        let t = l.trim_start();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if let Some(r) = l.strip_prefix("rule").filter(|r| r.starts_with(char::is_whitespace)) {
            let (class, rest) = field(r);
            let (kind, text) = field(&rest);
            assert!(["sub", "word", "iword", "macro"].contains(&kind.as_str()) && !text.is_empty(), "rule: {l}");
            rules.push(Rule { class, kind, text });
        } else if let Some(r) = l.strip_prefix("allow").filter(|r| r.starts_with(char::is_whitespace)) {
            let (file, fragment) = field(r);
            assert!(!fragment.is_empty(), "allow: {l}");
            allows.push(Allow { file, fragment });
        } else {
            panic!("build/host-independence-rules.txt: malformed line: {l}");
        }
    }
    assert!(!rules.is_empty());
    (rules, allows)
}
fn hits(r: &Rule, code: &str) -> bool {
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    match r.kind.as_str() {
        "sub" => code.to_lowercase().contains(&r.text.to_lowercase()),
        "word" => code.split(|c: char| !word(c)).any(|w| w == r.text),
        "iword" => code.split(|c: char| !word(c)).any(|w| w.to_lowercase() == r.text.to_lowercase()),
        "macro" => {
            let mut from = 0;
            while let Some(off) = code[from..].find(r.text.as_str()) {
                let at = from + off;
                let clear_before = !code[..at].chars().next_back().is_some_and(word);
                if clear_before && code[at + r.text.len()..].trim_start().starts_with('!') {
                    return true;
                }
                from = at + r.text.len();
            }
            false
        }
        other => panic!("unknown rule kind {other}"),
    }
}
/// (class, message) findings for `text` scanned as the repository-relative path `rel`; records the
/// index of every allow entry a line actually needed in `used`.
fn findings(rel: &str, text: &str, rules: &[Rule], allows: &[Allow], used: &mut BTreeSet<usize>) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (n, code) in non_test_lines(text).0 {
        let mut rest = code.clone();
        for (i, a) in allows.iter().enumerate().filter(|(_, a)| a.file == rel) {
            if !code.contains(&a.fragment) {
                continue;
            }
            if rules.iter().any(|r| hits(r, &code)) {
                used.insert(i);
            }
            rest = rest.replace(&a.fragment, "");
        }
        for r in rules {
            if hits(r, &rest) {
                out.push((r.class.clone(), format!("{rel}:{n}: {} (rule {} '{}'): {code}", r.class, r.kind, r.text)));
            }
        }
    }
    out
}
/// (scanned non-test lines, findings of `class`) over every shipped file.
fn report(class: &str) -> (usize, Vec<String>) {
    let (rules, allows) = rule_set();
    let (mut lines, mut bad, mut used) = (0, Vec::new(), BTreeSet::new());
    for (rel, text) in shipped_files() {
        lines += non_test_lines(&text).0.len();
        for (c, m) in findings(&rel, &text, &rules, &allows, &mut used) {
            if c == class {
                bad.push(m);
            }
        }
    }
    (lines, bad)
}

#[test]
fn lexer_tracks_test_regions_comments_and_literals() {
    let src = "fn a() { let s = \"}{\"; let c = '{'; }\n\
               // std::env::var in a comment\n\
               #[cfg(test)]\n\
               mod tests {\n\
               fn t() { std::env::var(\"X\"); }\n\
               }\n\
               #[cfg(test)]\n\
               if std::env::var(\"Y\").is_ok() { () }\n\
               #[cfg(any(test, feature = \"f\"))]\n\
               fn shipped() { std::env::var(\"Z\"); }\n\
               #[cfg(test)]\n\
               #[path = \"x_tests.rs\"]\n\
               mod x_tests;\n\
               #[cfg(all(test, unix))]\n\
               fn multi(\n\
                   a: u8,\n\
               ) -> u8 { let _ = std::env::var(\"W\"); a }\n\
               fn after() -> &'static str { let _q = '\\''; r#\"{\"# }\n\
               #[cfg(test)]\n\
               fn t2() {} fn same_line() { std::env::var(\"S\"); }\n\
               #[cfg(test)]\n\
               mod m {\n\
               } fn after_module() {}\n";
    let (lines, paths) = non_test_lines(src);
    let text: Vec<_> = lines.iter().map(|(_, c)| c.as_str()).collect();
    assert!(text.iter().any(|l| l.starts_with("fn a()")));
    assert!(!text.iter().any(|l| l.contains("std::env::var(\"X\")") || l.contains("\"Y\"")));
    assert!(text.iter().any(|l| l.contains("std::env::var(\"Z\")")), "cfg(any(test, ..)) is shipped code");
    assert!(!text.iter().any(|l| l.contains("\"W\"") || l.contains("a: u8")), "multi-line test item");
    assert!(text.iter().any(|l| l.starts_with("fn after()")));
    assert!(!text.iter().any(|l| l.contains("comment")));
    assert!(text.iter().any(|l| l == &"fn same_line() { std::env::var(\"S\"); }"), "code after a test item on its line is shipped");
    assert!(!text.iter().any(|l| l.contains("fn t2")));
    assert!(text.iter().any(|l| l == &"fn after_module() {}"), "code after a test module's brace is shipped");
    assert_eq!(paths, ["x_tests.rs"]);
    // Line numbers survive a string line continuation.
    let (lines, _) = non_test_lines("const A: &str = \"a\\\nb\";\nfn z() {}\n");
    assert_eq!(lines.last().unwrap(), &(3, "fn z() {}".to_string()));
}

#[test]
fn no_host_name_lookup_in_consensus_or_node_code() {
    let (lines, bad) = report("host");
    assert!(lines > 10_000, "too few shipped lines scanned: {lines}");
    assert!(bad.is_empty(), "host-identity spellings in non-test code outside the allow-list:\n{}", bad.join("\n"));
}

#[test]
fn no_environment_read_in_consensus_or_node_code_outside_allow_list() {
    let (lines, bad) = report("env");
    assert!(lines > 10_000, "too few shipped lines scanned: {lines}");
    assert!(bad.is_empty(), "environment access in non-test code outside the allow-list:\n{}", bad.join("\n"));
}

#[test]
fn no_string_assembly_in_consensus_or_node_code_outside_allow_list() {
    let (lines, bad) = report("assembly");
    assert!(lines > 10_000, "too few shipped lines scanned: {lines}");
    assert!(bad.is_empty(), "string assembly (concat!) in non-test code outside the allow-list:\n{}", bad.join("\n"));
}

/// The allow-list stays explicit and minimal: every entry is still needed by a non-test line, and
/// every rule class has its own test above.
#[test]
fn every_allow_entry_is_needed_and_every_rule_class_is_checked() {
    let (rules, allows) = rule_set();
    let classes: BTreeSet<&str> = rules.iter().map(|r| r.class.as_str()).collect();
    assert_eq!(classes, BTreeSet::from(["assembly", "env", "host"]), "a rule class without its own test");
    let mut used = BTreeSet::new();
    for (rel, text) in shipped_files() {
        findings(&rel, &text, &rules, &allows, &mut used);
    }
    for (i, a) in allows.iter().enumerate() {
        assert!(used.contains(&i), "stale allow entry ({}): {}", a.file, a.fragment);
    }
}

/// Every probe of the shared corpus reaches its expected verdict (the Perl twin runs the same corpus
/// with `--selftest`; build/negative-controls.sh injects the FAIL probes into a scratch clone).
#[test]
fn shared_probes_reach_the_expected_verdict() {
    let (rules, allows) = rule_set();
    let text = std::fs::read_to_string(root().join("build/host-independence-probes.txt")).unwrap();
    let mut probes: Vec<(String, String, String, String)> = Vec::new();
    for raw in text.lines() {
        let l = raw.trim_end_matches('\r');
        if let Some(h) = l.strip_prefix("=== ") {
            let mut it = h.splitn(3, ' ');
            let (id, want, rest) = (it.next().unwrap(), it.next().unwrap(), it.next().unwrap_or(""));
            assert!(want == "PASS" || want == "FAIL", "{l}");
            let file = rest
                .strip_prefix('@')
                .map(|r| r.split(' ').next().unwrap().to_string())
                .unwrap_or_else(|| "node/src/guard_probe.rs".into());
            probes.push((id.into(), want.into(), file, String::new()));
        } else if let Some(p) = probes.last_mut() {
            p.3.push_str(l);
            p.3.push('\n');
        }
    }
    let ids: BTreeSet<&str> = probes.iter().map(|p| p.0.as_str()).collect();
    for id in ["G0", "G1", "G2", "G3", "G4", "G6", "G6b", "G7", "G8", "G9"] {
        assert!(ids.contains(id), "review probe {id} missing from the corpus");
    }
    for (id, want, file, body) in &probes {
        let found = findings(file, body, &rules, &allows, &mut BTreeSet::new());
        let got = if found.is_empty() { "PASS" } else { "FAIL" };
        assert_eq!(got, want, "probe {id} ({file}): {found:?}");
    }
}

/// T7: the evidence-class LABELS of the JSON fixtures are documentation only. No non-test
/// consensus or node code reads them, so relabeling a fixture (or stripping its labels) cannot
/// change any acceptance decision; the drift tests reject any edited committed fixture.
#[test]
fn no_shipped_code_reads_fixture_evidence_labels() {
    let labels = [
        "\"TEST_VALUE\"",
        "\"physical_tpm\"",
        "\"qualifies_hardware\"",
        "\"production_eligible\"",
        "\"bond_eligible\"",
        "\"real_host_evidence\"",
    ];
    let lines = shipped_lines();
    assert!(lines.len() > 10_000, "too few shipped lines scanned: {}", lines.len());
    for (file, n, code) in lines {
        for label in labels {
            assert!(!code.contains(label), "{file}:{n}: shipped code reads evidence label {label}");
        }
    }
}
