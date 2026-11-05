//! Package P-E, Architect decision (6): "An unqualified clock must prevent selecting or constructing
//! a NEW block proposal." Two layers.
//!
//! 1. Structural, at compile time. A NEW signed `RoundProposal` can only come from
//!    `RoundProposal::signed`, which consumes a `local_proposer::Offer`. `RoundProposal::signature`,
//!    `sign`, `body` and `digest` are private to `round_proposal.rs` and the fields of `Offer` are
//!    private to `local_proposer.rs`, so no other module can write a proposal literal (functional
//!    update syntax included), compute its signing payload or build an offer: such code does not
//!    compile. The first test pins that the seal is still in place.
//! 2. Source-text guards in the style of `timestamp_admission_v1` for what the type system does not
//!    enforce. They PIN the set of places where this node can select a proposal, construct a
//!    candidate or a work authorization, prepare hybrid work or implement a clock, and the order in
//!    which each of them consults qualified time. Matching is on comment-free, non-test code with
//!    whitespace collapsed, so a line break cannot hide a site. A new construction path, or a
//!    reordering that lets one run before the time check, fails here and must be reviewed against
//!    docs/OS-CLOCK-CLASSIFICATION-V1.md section 9.
//!
//! The behaviour behind each pinned site is exercised end to end by
//! `worker_coordinator::os_clock_tests::unqualified_proposal`.

/// Strip line comments so explanatory text cannot satisfy or trip a guard.
fn code(src: &str) -> String {
    src.lines()
        .map(|l| l.split("//").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Remove every `#[cfg(test)]`-gated item (module or fn) so test-only fixtures do not count.
fn without_test_code(src: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].trim_start().starts_with("#[cfg(test)]") {
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
    out.join("\n")
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

/// Non-test source of every `node/src` file, as (file name, comment-free code).
fn live_sources() -> Vec<(String, String)> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    rust_files(&root.join("src"), &mut files);
    assert!(files.len() > 50, "source walk found too few files");
    files
        .into_iter()
        .filter_map(|path| {
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            // Separate test modules (`*_tests.rs`) are `#[cfg(test)]` modules of their parent.
            if name.ends_with("_tests.rs") {
                return None;
            }
            let src = std::fs::read_to_string(&path).unwrap();
            Some((name, code(&without_test_code(&src))))
        })
        .collect()
}
/// Whitespace-insensitive form of code: every run of whitespace becomes one space, and a space
/// before `(` or `.` is dropped, so line breaks or extra spaces cannot hide a pinned site.
fn flat(src: &str) -> String {
    src.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" (", "(")
        .replace(" .", ".")
}
fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}
fn owned(expected: &[(&str, usize)]) -> Vec<(String, usize)> {
    expected.iter().map(|(f, n)| (f.to_string(), *n)).collect()
}
/// Per file, the number of matches `count` finds in the flattened non-test code (files without a
/// match are omitted), sorted by file name.
fn sites_by(count: impl Fn(&str) -> usize) -> Vec<(String, usize)> {
    let mut found: Vec<_> = live_sources()
        .into_iter()
        .filter_map(|(name, live)| {
            let n = count(&flat(&live));
            (n > 0).then_some((name, n))
        })
        .collect();
    found.sort();
    found
}
/// The files whose non-test code contains `needle`, with the number of occurrences.
fn sites(needle: &str) -> Vec<(String, usize)> {
    sites_by(|text| text.matches(needle).count())
}
fn only(needle: &str, expected: &[(&str, usize)]) {
    assert_eq!(
        sites(needle),
        owned(expected),
        "the set of non-test sites containing `{needle}` changed: a new construction path must be \
         gated on qualified time and recorded in docs/OS-CLOCK-CLASSIFICATION-V1.md section 9"
    );
}
/// The occurrences of `word` as a whole identifier, per file.
fn word_sites(word: &str) -> Vec<(String, usize)> {
    sites_by(|text| {
        text.match_indices(word)
            .filter(|(i, _)| {
                !text[..*i].chars().next_back().is_some_and(is_ident)
                    && !text[i + word.len()..].chars().next().is_some_and(is_ident)
            })
            .count()
    })
}
/// Every `prepare(` that defines or calls a function or method named exactly `prepare`, in any
/// call syntax, except an SQL statement preparation (first argument a string literal or
/// `format!`), per file. `HybridRuntime::prepare` builds hybrid work at a CALLER-chosen timestamp,
/// so every path to it is one of these sites.
fn prepare_sites() -> Vec<(String, usize)> {
    sites_by(|text| {
        text.match_indices("prepare(")
            .filter(|(i, _)| {
                let after = text[i + "prepare(".len()..].trim_start();
                !text[..*i].chars().next_back().is_some_and(is_ident)
                    && !["\"", "r\"", "r#", "format!", "&format!"]
                        .iter()
                        .any(|sql| after.starts_with(sql))
            })
            .count()
    })
}
/// Every non-test `impl` header of a trait whose name ends in `Clock` (`... Clock for ...`, with
/// any path, generics or line breaks), as (file, header).
fn clock_impls() -> Vec<(String, String)> {
    let mut found = Vec::new();
    for (name, live) in live_sources() {
        let text = flat(&live);
        for (hit, _) in text.match_indices("Clock for ") {
            // The `impl` keyword that owns this header, with no item boundary in between.
            let Some(start) = text[..hit]
                .match_indices("impl")
                .map(|(i, _)| i)
                .filter(|i| {
                    !text[..*i].chars().next_back().is_some_and(is_ident)
                        && !text[i + 4..].chars().next().is_some_and(is_ident)
                })
                .last()
            else {
                continue;
            };
            if text[start..hit].contains(['{', '}', ';']) {
                continue;
            }
            let end = text[hit..].find('{').map_or(text.len(), |e| hit + e);
            found.push((name.clone(), text[start..end].trim().to_string()));
        }
    }
    found.sort();
    found
}
fn live(name: &str) -> String {
    live_sources()
        .into_iter()
        .find(|(n, _)| n == name)
        .unwrap_or_else(|| panic!("missing {name}"))
        .1
}
/// The text of `fn <signature>` up to the next function at the same indentation.
fn body_of(src: &str, signature: &str) -> String {
    let at = src
        .find(signature)
        .unwrap_or_else(|| panic!("missing `{signature}`"));
    let rest = &src[at..];
    let tail = &rest[signature.len()..];
    let end = ["\n    fn ", "\n    pub fn ", "\n    pub(crate) fn "]
        .iter()
        .filter_map(|next| tail.find(next))
        .min()
        .map(|e| e + signature.len())
        .unwrap_or(rest.len());
    rest[..end].to_string()
}
/// The text of the item (struct or impl) that starts at `header`, through its closing brace.
fn item_text(src: &str, header: &str) -> String {
    let at = src
        .find(header)
        .unwrap_or_else(|| panic!("missing `{header}`"));
    let mut depth = 0i64;
    for (i, ch) in src[at..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return src[at..at + i + 1].to_string();
                }
            }
            _ => (),
        }
    }
    panic!("unterminated `{header}`")
}
fn before(text: &str, first: &str, second: &str) {
    let a = text
        .find(first)
        .unwrap_or_else(|| panic!("missing `{first}`"));
    let b = text
        .find(second)
        .unwrap_or_else(|| panic!("missing `{second}`"));
    assert!(a < b, "`{first}` must come before `{second}`");
}

#[test]
fn a_new_round_proposal_can_only_be_built_and_signed_by_the_local_proposer() {
    // The seal. Outside round_proposal.rs a proposal literal or a new signature does not compile;
    // these assertions keep the seal from being relaxed without this test noticing.
    let proposal = live("round_proposal.rs");
    let fields = item_text(&proposal, "pub struct RoundProposal {");
    assert!(
        fields.contains("\n    signature: [u8; 64],"),
        "the signature field must stay private"
    );
    for private in [
        "fn sign(&mut self, key: &SigningKey) {",
        "fn body(&self) -> Vec<u8> {",
        "fn digest(&self) -> Hash {",
    ] {
        assert!(
            proposal.contains(&format!("\n    {private}")),
            "`{private}` must stay private to round_proposal.rs"
        );
    }
    // No literal anywhere: the type name is followed by `{` only in its own definition and impl
    // (the module's own constructors write `Self {`).
    only("RoundProposal {", &[("round_proposal.rs", 2)]);
    // ONE constructor of a new signed proposal; it needs an `Offer`; the proposer calls it once.
    let signed = body_of(&proposal, "pub(crate) fn signed(");
    assert!(signed.contains("offer: crate::local_proposer::Offer,"));
    assert!(signed.contains("proposal.sign(key);"));
    only("RoundProposal::signed(", &[("local_proposer.rs", 1)]);
    only(".sign(key)", &[("round_proposal.rs", 1)]);
    // The signing payload's domain tag exists once: nothing re-implements the payload to sign it.
    only(
        "MUTINY-BUILD8-ROUND-PROPOSAL-V1",
        &[("round_proposal.rs", 1)],
    );
    // The offer: private fields, built in one place, inside `propose`, after the selection.
    let proposer = live("local_proposer.rs");
    let header = "pub(crate) struct Offer {";
    assert!(
        !item_text(&proposer, header)[header.len()..].contains("pub"),
        "the fields of Offer must stay private to local_proposer.rs"
    );
    only("struct Offer {", &[("local_proposer.rs", 1)]);
    // `Offer {`: its definition, its impl, and the one literal.
    only("Offer {", &[("local_proposer.rs", 3)]);
    only("Offer { block, pol_round }", &[("local_proposer.rs", 1)]);
    // Selection is a function of the proposer's OWN qualified clock, held lock and PoLC first.
    let propose = body_of(&proposer, "pub fn propose<V: PhysicalAttestationVerifier>(");
    assert!(
        propose.contains("&|timestamp| actor.timestamp_status(timestamp).is_eligible(),"),
        "fresh choice must be filtered by exactly the voter's own qualified clock"
    );
    // A persisted proposal is returned before anything is selected, signed or written.
    before(&propose, "return Ok(Some(proposal));", "fallback_choice(");
    before(
        &propose,
        "fallback_choice(",
        "let offer = Offer { block, pol_round };",
    );
    before(
        &propose,
        "let offer = Offer { block, pol_round };",
        "RoundProposal::signed(",
    );
    let choice = body_of(&proposer, "pub(crate) fn fallback_choice(");
    before(
        &choice,
        "if let Some(block) = locked {",
        ".filter(|p| eligible(",
    );
    assert!(
        choice.contains("return Some((block, None));"),
        "a held lock is re-proposed unfiltered"
    );
    // The actor offers a proposal only through the proposer (never from the candidate journal).
    only("local.propose(", &[("integrated_actor.rs", 1)]);
}

#[test]
fn work_and_candidates_are_only_constructed_behind_the_qualified_clock() {
    only("MiningRequest {", &[("worker_coordinator.rs", 1)]);
    only(".issue(", &[("worker_coordinator.rs", 1)]);
    // Body assembly and operation admission: called only by the coordinator (work) and the actor
    // (admission), never from anywhere else.
    only(".assemble(", &[("body_assembler.rs", 1)]);
    only(
        "admit_current_operation(",
        &[
            ("body_assembler.rs", 1),
            ("integrated_actor.rs", 2),
            ("worker_coordinator.rs", 1),
        ],
    );
    let coordinator = live("worker_coordinator.rs");
    // Architect decision V2: a Worker session authenticates without qualified time, against the
    // binding finalized state already establishes (status, stop, exact stored-receipt
    // retransmission, a bounded result deferral). Binding the Worker to the CURRENT epoch, issuing
    // work and accepting a fresh result happen only after the qualified-time read.
    for signature in [
        "fn active(&mut self, worker: Hash) -> Result<BindWorker> {",
        "fn handle(&mut self, worker: Hash, message: WorkerMessage) -> Result<Vec<u8>> {",
    ] {
        let body = flat(&body_of(&coordinator, signature));
        before(
            &body,
            "self.qualified_unix_ms()",
            "self.binding(worker, unix / 1000)",
        );
        before(
            &body,
            "self.qualified_unix_ms()",
            "self.settled_binding(worker)",
        );
        assert_eq!(body.matches("self.binding(").count(), 1, "{signature}");
    }
    let handle = flat(&body_of(
        &coordinator,
        "fn handle(&mut self, worker: Hash, message: WorkerMessage) -> Result<Vec<u8>> {",
    ));
    // New work: the qualified read must have succeeded before assembly and issuance.
    before(&handle, "let unix = qualified?;", "self.hooks.body(");
    before(&handle, "self.hooks.body(", "self.coordinator.issue(");
    // A fresh result is accepted only on the qualified path. Unqualified, only the exact stored
    // receipt (`retransmission`: no acceptance, credit or signature) or a bounded hold.
    before(
        &handle,
        "let Ok(bound_unix) = qualified else {",
        "self.result_clock_still_current(bound_unix)?",
    );
    before(
        &handle,
        "if !self.result_clock_still_current(bound_unix)? {",
        "self.coordinator.result(",
    );
    let unqualified = flat(&body_of(&coordinator, "fn unqualified_result("));
    assert!(unqualified.contains("self.coordinator.retransmission("));
    for forbidden in [
        "self.coordinator.result(",
        ".issue(",
        "self.binding(",
        "qualified_unix_ms",
    ] {
        assert!(
            !unqualified.contains(forbidden),
            "unqualified_result must not reach `{forbidden}`"
        );
    }
    // The settled binding reads no clock.
    let settled = flat(&body_of(&coordinator, "fn settled_binding("));
    for clock in ["qualified_unix_ms", "now()", "lower_bound_ms", "Qualified("] {
        assert!(
            !settled.contains(clock),
            "settled_binding must not read `{clock}`"
        );
    }
    // Held results are processed only with qualified time, through the current-epoch binding.
    let process = flat(&body_of(&coordinator, "pub fn process_deferred_results("));
    before(&process, "self.qualified_unix_ms()", "self.process_held(");
    let held = flat(&body_of(&coordinator, "fn process_held("));
    before(
        &held,
        "self.binding(worker, unix / 1000)?",
        "self.result_clock_still_current(unix)?",
    );
    before(
        &held,
        "if !self.result_clock_still_current(unix)? {",
        "self.coordinator.result(",
    );
    let final_result = flat(&body_of(&coordinator, "fn result_clock_still_current("));
    before(&final_result, "self.result_time_origin()?", "self.qualified_unix_ms()");
    assert!(final_result.contains("Some(bound_epoch)"));
    // Request preparation and canonical reads must precede the mandatory final
    // qualified provider sample and lease clock. No cached fallback is accepted.
    before(&handle, "self.coordinator.issue(", "decision_basis.lower_bound_ms()");
    before(&handle, "decision_basis.lower_bound_ms()", "decision_started.elapsed()");
    let decision_sample = &handle[handle.find("decision_basis.lower_bound_ms()").unwrap()..
        handle.find("worker_protocol::offer(").unwrap()];
    assert!(decision_sample.contains("ok_or_else"));
    assert!(!decision_sample.contains("unwrap_or"));
    let consensus = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../consensus/src");
    let issuance = code(&std::fs::read_to_string(consensus.join("work_issuance.rs")).unwrap());
    let issue = flat(&body_of(&issuance, "pub fn issue("));
    assert!(issue.contains("final_clock: impl FnOnce() -> Result<(u64, u64)>"));
    before(&issue, "prepare(ticket, &candidate)?", "final_clock()?");
    before(&issue, "final_clock()?", "gate.work_lease(decision_now, &context)");
    before(&issue, "decision_elapsed / 60000 != epoch", "key.sign(");
    before(&issue, "key.sign(", "DELETE FROM issued_work");
    let runtime = code(&std::fs::read_to_string(consensus.join("coordinator.rs")).unwrap());
    let issue = flat(&body_of(&runtime, "pub fn issue<V: PhysicalAttestationVerifier>("));
    assert!(issue.contains("final_clock: impl FnOnce() -> Result<(u64, u64)>"));
    before(&issue, "Ok((prepared.root, request.body))", "let(current, _) = chain.load_effective()");
    before(&issue, "let(current, _) = chain.load_effective()", "final_clock()");
    // Fresh acceptance has exactly these two sites.
    only("self.coordinator.result(", &[("worker_coordinator.rs", 2)]);
    // The qualified read fails closed: no fallback value exists.
    let qualified = body_of(&coordinator, "fn qualified_unix_ms(&self) -> Result<u64> {");
    assert!(qualified.contains("lower_bound_ms()"));
    assert!(qualified.contains("ok_or_else"));
    assert!(!qualified.contains("unwrap_or") && !qualified.contains("unwrap_or_default"));
    // Operation admission and participation use the same mandatory basis.
    let actor = live("integrated_actor.rs");
    assert!(actor.contains("self.time.seconds()"));
    let submit = &actor[actor
        .find("\"submit_operation\" => {")
        .expect("submit_operation")..];
    before(submit, ".admission_seconds()", "admit_current_operation(");
}

#[test]
fn the_hybrid_coordinator_samples_qualified_time_before_it_reserves_or_signs_anything() {
    // Every `impl` of a clock trait (`... Clock for ...`, any path, generics or line breaks) in
    // non-test node code: the OS wall clock read only by the qualification engine, the qualified
    // basis, and the wrapper that continues another clock inside the handshake (it forwards its
    // inner clock's sample and only adds regression and deadline refusals). No OS-clock `Clock`
    // exists, no new time source may appear unreviewed, and no clock trait is renamed on import.
    assert_eq!(
        clock_impls(),
        [
            ("host_clock.rs", "impl WallClock for OsWall"),
            ("hybrid_coordinator_v2.rs", "impl Clock for QualifiedClock"),
            (
                "worker_handshake_io_v2.rs",
                "impl<C: Clock> Clock for ContinuingClock<'_, C>",
            ),
        ]
        .map(|(f, h)| (f.to_string(), h.to_string()))
        .to_vec(),
        "the set of clock implementations changed: a new time source must be reviewed against \
         docs/OS-CLOCK-CLASSIFICATION-V1.md section 9"
    );
    only("Clock as", &[]);
    only("TimeBasis for", &[]);
    let hybrid = live("hybrid_coordinator_v2.rs");
    assert!(hybrid.contains("impl Clock for QualifiedClock"));
    // Hybrid work: `HybridRuntime::prepare` takes a CALLER-chosen timestamp, so every path to it is
    // pinned: the one `WorkRequest` literal, every mention of the type, every non-SQL `prepare(`
    // (definitions and calls, any call syntax) and every `authorize_work(`.
    only("WorkRequest {", &[("hybrid_coordinator_v2.rs", 1)]);
    assert_eq!(
        word_sites("WorkRequest"),
        owned(&[("hybrid_coordinator_v2.rs", 2), ("hybrid_runtime_v2.rs", 2)]),
        "a new path that handles a WorkRequest must be reviewed"
    );
    assert_eq!(
        prepare_sites(),
        owned(&[
            ("hybrid_coordinator_v2.rs", 3),
            ("hybrid_peer_worker_v2.rs", 1),
            ("hybrid_runtime_v2.rs", 1),
            ("submission_relay_v1.rs", 1),
            ("trading_service_v1.rs", 2),
            ("trading_storage_v1.rs", 2),
        ]),
        "a new non-SQL `prepare(` site must be reviewed: it may reach HybridRuntime::prepare"
    );
    // The two additional sites prepare bounded relay advertisements of existing
    // authenticated submissions, not HybridRuntime WorkRequest candidates.
    // Pin their exact typed path, current peer/network context and revalidation.
    let relay = live("submission_relay_v1.rs");
    let relay_prepare = flat(&body_of(&relay, "pub fn prepare("));
    assert!(relay_prepare.contains("runtime: &mut HybridRuntime"));
    before(&relay_prepare, "link.peer_id() != self.peer", ".relay_pending()");
    before(&relay_prepare, "!link.matches_network(genesis, fingerprint)", ".relay_pending()");
    before(&relay_prepare, ".verify_signatures()", "link.enqueue(");
    for work in ["WorkRequest", "authorize_work(", "runtime.prepare("] {
        assert!(!relay.contains(work), "relay must not construct or authorize fresh work: {work}");
    }
    let peer_worker = flat(&live("hybrid_peer_worker_v2.rs"));
    assert!(peer_worker.contains("relay: &mut crate::submission_relay_v1::Relay"));
    assert!(peer_worker.contains("peer.with_current(|link| relay.prepare(actor, link))"));
    let hybrid_runtime = live("hybrid_runtime_v2.rs");
    let pending = flat(&body_of(&hybrid_runtime, "pub fn relay_pending("));
    before(&pending, "self.reconcile()?", "self.submissions.pending_at(");
    before(&pending, "self.chain.load()?", "self.submissions.pending_at(");
    only(
        "authorize_work(",
        &[
            ("hybrid_coordinator_v2.rs", 2),
            ("node_custody_v2.rs", 1),
            ("software_coordinator_custody_v2.rs", 1),
        ],
    );
    let prepare = body_of(&hybrid, "fn prepare_with_signer(");
    before(&prepare, "self.sample(clock)?", "journal.reserve(");
    before(&prepare, "self.sample(clock)?", ".prepare(WorkRequest {");
    before(&prepare, "journal.reserve(", ".authorize_work(");
    // The qualified clock has no value to return while unqualified.
    assert!(hybrid.contains("ok_or(\"Qualified clock unavailable\")?"));
}

#[test]
fn the_actors_never_clear_the_halting_latch_on_account_of_a_time_deferral() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../consensus/src");
    for name in ["voter_actor.rs", "voter_actor_v2.rs"] {
        let src = std::fs::read_to_string(root.join(name)).unwrap();
        let live = code(&without_test_code(&src));
        // The old pattern branched on `is_time_deferral()` and reset the latch. The deferral is now
        // an explicit result produced only by `refusal`, before the latch is set.
        assert!(
            !live.contains(".is_time_deferral()"),
            "{name}: no branch may consult a time deferral to touch `halted`"
        );
        assert_eq!(
            live.matches("ActorError::TimeDeferred(").count(),
            2,
            "{name}: the deferral is produced only for FutureTimestamp and ClockUnqualified"
        );
        let refusal = body_of(
            &live,
            "fn refusal(&mut self, e: CounterVoterError) -> ActorError {",
        );
        assert!(refusal.contains("ActorError::TimeDeferred(TimeStatus::Future"));
        assert!(refusal.contains("ActorError::TimeDeferred(TimeStatus::Unqualified)"));
        // sign and replay: the pure pre-check precedes the latch, and the voter reuses one reading.
        for (signature, gate, mutation) in [
            (
                "pub fn sign(",
                "time_gate_with(&reading",
                "sign_at(&reading",
            ),
            (
                "pub fn replay(",
                "replay_gate_at(&reading",
                "replay_at(&reading",
            ),
        ] {
            let body = body_of(&live, signature);
            before(&body, "self.check_backend(", "clock_reading()");
            before(&body, gate, "self.halted = true;");
            before(&body, "self.halted = true;", mutation);
            assert_eq!(
                body.matches("clock_reading()").count(),
                1,
                "{name}: {signature} takes exactly one clock reading"
            );
        }
    }
    // The driver treats ONLY the explicit result as a deferral.
    let driver = code(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/voter_driver.rs"),
        )
        .unwrap(),
    );
    let defer = body_of(
        &driver,
        "fn defer_status(e: &ActorError) -> Option<TimeStatus> {",
    );
    assert!(defer.contains("e.time_deferral()"));
}
