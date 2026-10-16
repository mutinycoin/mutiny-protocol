//! D3 (Architect, 3 Oct 2026): the 7,200 s wall-clock holds on UNFINALIZED candidate/proposal
//! admission are replaced. Timestamps are consensus data; admission applies only the deterministic
//! rules in `mutiny_consensus_v8::pow::validate_timestamp`, and signing a fresh block vote is gated
//! by the qualified clock. These are source-text guards in the style of
//! `finalized_ingestion_clock_free_v1`: they keep a wall-clock hold from being reintroduced.
const MAIN: &str = include_str!("../src/main.rs");
const ACTOR: &str = include_str!("../src/integrated_actor.rs");
const DRIVER: &str = include_str!("../src/voter_driver.rs");
const WORKERS: &str = include_str!("../src/worker_coordinator.rs");
const POW: &str = include_str!("../../consensus/src/pow.rs");

/// Strip line comments so explanatory text cannot satisfy or trip a guard.
fn code(src: &str) -> String {
    src.lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn no_two_hour_wall_clock_constant_remains_on_unfinalized_admission_paths() {
    for (name, src) in [
        ("main.rs", MAIN),
        ("integrated_actor.rs", ACTOR),
        ("voter_driver.rs", DRIVER),
        ("worker_coordinator.rs", WORKERS),
        ("consensus pow.rs", POW),
    ] {
        let c = code(src);
        for needle in ["7200", "7_200", "2 * 3600", "2*3600", "local_future_hold"] {
            assert!(!c.contains(needle), "{name} still contains {needle}");
        }
        for needle in ["future proposal held", "Future object held"] {
            assert!(
                !c.contains(needle),
                "{name} still holds on a wall clock: {needle}"
            );
        }
    }
}

#[test]
fn admission_handlers_read_no_wall_clock() {
    // The unfinalized admission handlers must not consult the host's wall clock at all. (The
    // production clock is `host_clock`, installed behind the `VoteClock` trait for SIGNING only.)
    let actor = code(ACTOR);
    assert!(!actor.contains("fn check_timestamp"));
    // Operation admission and participation timing use the mandatory qualified basis only; the
    // OS-clock fallback they once had is gone (see `no_os_wall_clock_read_outside_the_allow_list`).
    assert!(!actor.contains("SystemTime") && !actor.contains("UNIX_EPOCH"));
    let at = actor
        .find("\"submit_candidate\" => {")
        .expect("actor submit_candidate");
    let end = actor[at..]
        .find("\"submit_vote\" =>")
        .expect("actor submit_vote");
    assert!(
        !actor[at..at + end].contains("SystemTime"),
        "integrated_actor submit_candidate reads the wall clock"
    );
    let main = code(MAIN);
    for handler in ["\"submit_candidate\" =>", "\"validate_proposal\" =>"] {
        let at = main
            .find(handler)
            .unwrap_or_else(|| panic!("missing {handler}"));
        let window = &main[at..(at + 2500).min(main.len())];
        let end = window.find("\"observe_vote\" =>").unwrap_or(window.len());
        assert!(
            !window[..end].contains("SystemTime::now"),
            "{handler} reads the wall clock"
        );
    }
}

/// Every NON-TEST source file in `node/src` that may read the OS wall clock, with the reason. A
/// file not listed here must contain no `SystemTime` / `UNIX_EPOCH` outside `#[cfg(test)]` code.
/// Each entry is a deliberate, documented read (docs/OS-CLOCK-CLASSIFICATION-V1.md):
///  * `host_clock.rs`: `OsWall` is the explicit qualification mechanism. Its reading is only the
///    CENTRE of an interval whose width is NTS-authenticated chrony uncertainty plus the read
///    window, consumed by the holdover clock; it is never used as a time on its own.
const ALLOW_LIST: &[(&str, &str)] = &[(
    "host_clock.rs",
    "OsWall: centre of an authenticated uncertainty interval (the qualification mechanism)",
)];

/// Remove every `#[cfg(test)]`-gated item (module or fn) so test-only fixtures do not count.
fn without_test_code(src: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim_start().starts_with("#[cfg(test)]") {
            // Skip the attribute(s) and the item that follows (brace matched, or one line for `;`).
            let mut j = i + 1;
            while j < lines.len() && lines[j].trim_start().starts_with("#[") {
                j += 1;
            }
            let mut depth = 0i64;
            let mut opened = false;
            while j < lines.len() {
                for ch in lines[j].chars() {
                    match ch {
                        '{' => {
                            depth += 1;
                            opened = true;
                        }
                        '}' => depth -= 1,
                        _ => (),
                    }
                }
                let ended =
                    (opened && depth <= 0) || (!opened && lines[j].trim_end().ends_with(';'));
                j += 1;
                if ended {
                    break;
                }
            }
            i = j;
        } else {
            out.push(lines[i]);
            i += 1;
        }
    }
    out.join(
        "
",
    )
}

fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn no_os_wall_clock_read_outside_the_allow_list() {
    // Replaces the earlier permissive guard that blessed an OS-clock fallback. Neither
    // `consensus/src` nor `node/src` may read `SystemTime` / `UNIX_EPOCH` in non-test code except
    // the explicitly allow-listed qualification mechanism, so no silent unqualified fallback can
    // return for votes, work, signing authorization or admission.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    rust_files(&root.join("../consensus/src"), &mut files);
    assert!(files.len() > 50, "source walk found too few files");
    let mut offenders = Vec::new();
    for path in files {
        let name = path.file_name().unwrap().to_string_lossy().to_string();
        // Separate test modules (`*_tests.rs`) are `#[cfg(test)]` modules of their parent.
        if name.ends_with("_tests.rs") {
            continue;
        }
        let src = std::fs::read_to_string(&path).unwrap();
        let live = code(&without_test_code(&src));
        let reads = live.contains("SystemTime") || live.contains("UNIX_EPOCH");
        let allowed = ALLOW_LIST.iter().any(|(f, why)| {
            assert!(!why.is_empty(), "allow-list entry needs a justification");
            *f == name
        });
        if reads && !allowed {
            offenders.push(path.display().to_string());
        }
    }
    assert!(
        offenders.is_empty(),
        "OS wall-clock reads outside the allow list: {offenders:?}"
    );
}

#[test]
fn the_time_basis_is_mandatory_and_has_no_system_clock_implementation() {
    let coordinator = code(WORKERS);
    assert!(!coordinator.contains("time: None"));
    assert!(!coordinator.contains("Option<std::sync::Arc<dyn"));
    let actor = code(ACTOR);
    assert!(!actor.contains("time: None"));
    assert!(!code(include_str!("../src/hybrid_coordinator_v2.rs")).contains("SystemClock"));
}

#[test]
fn pairwise_skew_budget_fits_inside_the_base_round_delay() {
    // D1 numbers only: maximum uncertainty to vote 1 s, so two honest nodes can differ by up to
    // U_a + U_b = 2 s. The driver's base round delay must leave headroom over that skew, or a
    // correct block would be nil-voted by a node whose clock is merely behind.
    const MAX_UNCERTAINTY_SECS: u64 = 1;
    let skew = 2 * MAX_UNCERTAINTY_SECS;
    let base = 3; // `voter_driver::BASE_ROUND_DELAY_SECS`, asserted in the unit test beside it
    assert!(DRIVER.contains("BASE_ROUND_DELAY_SECS: u64 = 3;"));
    assert!(base > skew);
    assert_eq!(base - skew, 1, "headroom is 1 s");
}
