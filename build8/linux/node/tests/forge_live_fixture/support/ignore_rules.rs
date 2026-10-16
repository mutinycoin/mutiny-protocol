//! The `qualification/` rules of the repository `.gitignore`, matched with git's semantics on a
//! case-SENSITIVE checkout (Linux): a pattern containing a slash is anchored at the repository
//! root, `*`, `?` and `[..]` never match `/`, and a pattern that matches a leading directory
//! ignores everything below it (`qualification/dir-*` ignores `qualification/dir-x/y`).
//! Only the syntax the file uses is modelled; negation, `**`, escapes or a further `/` after the
//! `qualification/` prefix fail loudly instead of being guessed. Test support only (included by
//! `#[path]` from the guards that need it); it names no private file.
#![allow(dead_code)]
use std::path::Path;

/// The `qualification/...` patterns of `<root>/.gitignore`, without that prefix, in file order.
pub fn qualification_patterns(root: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(root.join(".gitignore")).unwrap();
    let mut out = Vec::new();
    for line in text.lines() {
        let l = line.trim_end_matches('\r').trim_end();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        assert!(!l.starts_with('!'), ".gitignore negation is not modelled: {l}");
        if let Some(p) = l.strip_prefix("qualification/") {
            let body = p.strip_suffix('/').unwrap_or(p);
            assert!(
                !body.is_empty() && !body.contains('/') && !body.contains("**") && !body.contains('\\'),
                ".gitignore pattern not modelled: {l}"
            );
            out.push(p.to_string());
        }
    }
    out
}

/// fnmatch of ONE path component (neither side contains `/`): `*` any run, `?` one character,
/// `[..]` a class with optional `!`/`^` negation and `a-z` ranges; anything else is literal.
pub fn component_matches(pattern: &str, name: &str) -> bool {
    fn class(p: &[char], c: char) -> Option<(bool, usize)> {
        // (matches, length of the class in p including both brackets); None: no closing bracket.
        let mut i = 1;
        let negate = matches!(p.get(i), Some('!') | Some('^'));
        if negate {
            i += 1;
        }
        let start = i;
        let mut hit = false;
        while i < p.len() && (p[i] != ']' || i == start) {
            if i + 2 < p.len() && p[i + 1] == '-' && p[i + 2] != ']' {
                hit |= p[i] <= c && c <= p[i + 2];
                i += 3;
            } else {
                hit |= p[i] == c;
                i += 1;
            }
        }
        (i < p.len()).then_some((hit != negate, i + 1))
    }
    fn go(p: &[char], n: &[char]) -> bool {
        match p.first() {
            None => n.is_empty(),
            Some('*') => (0..=n.len()).any(|k| go(&p[1..], &n[k..])),
            Some('?') => !n.is_empty() && go(&p[1..], &n[1..]),
            Some('[') => match (n.first(), class(p, n.first().copied().unwrap_or('\0'))) {
                (Some(_), Some((true, len))) => go(&p[len..], &n[1..]),
                (_, Some(_)) => false,
                (Some('['), None) => go(&p[1..], &n[1..]),
                _ => false,
            },
            Some(c) => n.first() == Some(c) && go(&p[1..], &n[1..]),
        }
    }
    let (p, n): (Vec<char>, Vec<char>) = (pattern.chars().collect(), name.chars().collect());
    go(&p, &n)
}

/// Whether one pattern ignores `path` (relative to `qualification/`, `/`-separated): the pattern
/// matches the path's FIRST component, which is the file itself or a directory holding it. A
/// pattern with a trailing `/` matches directories only.
pub fn ignores(pattern: &str, path: &str) -> bool {
    let (dir_only, pat) = match pattern.strip_suffix('/') {
        Some(p) => (true, p),
        None => (false, pattern),
    };
    let mut parts = path.split('/');
    let first = parts.next().unwrap_or("");
    let below = parts.next().is_some();
    component_matches(pat, first) && (below || !dir_only)
}
/// Git's verdict on a case-sensitive checkout (core.ignorecase=false).
pub fn ignored(patterns: &[String], path: &str) -> bool {
    patterns.iter().any(|p| ignores(p, path))
}
/// Git's verdict on a case-insensitive checkout (core.ignorecase=true, the Windows default).
pub fn ignored_ignoring_case(patterns: &[String], path: &str) -> bool {
    patterns.iter().any(|p| ignores(&p.to_lowercase(), &path.to_lowercase()))
}
/// Deliberately BROADER than git, for walks that must never open private evidence: any component
/// of `path`, at any depth, matched by any pattern in any capitalisation.
pub fn any_component_matches_ignoring_case(patterns: &[String], path: &str) -> bool {
    path.split('/').any(|c| {
        patterns
            .iter()
            .any(|p| component_matches(&p.trim_end_matches('/').to_lowercase(), &c.to_lowercase()))
    })
}
