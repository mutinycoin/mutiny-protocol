//! F4 (Architect, 2 Oct 2026 19:22 ET): authenticated finalized-history ingestion consults no
//! receiver clock. STRUCTURAL guard for the two node ingestion entry points: the behavioral
//! evidence (deterministic validation, conflicting finality retained and halted, forged or
//! insufficient certificates rejected) is the consensus `integrated_chain` release gate, whose
//! `commit_integrated` path reads no clock (no SystemTime/Instant exists in the consensus
//! validation code). This test fails if a wall-clock predicate, including a "zero allowance"
//! replacement, is reintroduced in front of `commit_integrated`.
const MAIN: &str = include_str!("../src/main.rs");
const ACTOR: &str = include_str!("../src/integrated_actor.rs");

fn arm<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let a = source
        .find(start)
        .unwrap_or_else(|| panic!("arm {start} not found"));
    let b = source[a..]
        .find(end)
        .unwrap_or_else(|| panic!("end {end} not found"));
    &source[a..a + b]
}
fn assert_clock_free(label: &str, body: &str) {
    for token in [
        "SystemTime",
        "Instant",
        "UNIX_EPOCH",
        "7200",
        "saturating_add",
        "check_timestamp",
        "HELD_FUTURE",
        "now",
        "clock",
    ] {
        assert!(
            !body.contains(token),
            "{label}: finalized ingestion must not consult a receiver clock ({token})"
        );
    }
    assert!(
        body.contains("commit_integrated") || body.contains("self.commit("),
        "{label}: the arm must still reach authenticated integrated commit"
    );
}

#[test]
fn finalized_block_ingestion_has_no_receiver_clock_predicate() {
    assert_clock_free(
        "main.rs submit_block",
        arm(MAIN, "\"submit_block\" => {", "\"get_block\" =>"),
    );
    assert_clock_free(
        "integrated_actor submit_block",
        arm(ACTOR, "\"submit_block\" => {", "\"submit_transaction\" =>"),
    );
}

#[test]
fn unfinalized_candidate_admission_has_no_wall_clock_hold() {
    // D3 (Architect, 3 Oct 2026) replaced the historical 7,200 s OS-time hold on UNFINALIZED
    // candidate/proposal admission (this test previously pinned its existence). Admission now
    // applies only the deterministic consensus timestamp rules; the qualified-clock guard at
    // signing is the sole time authority for new block votes. See `timestamp_admission_v1`.
    let arm = arm(ACTOR, "\"submit_candidate\" => {", "\"submit_vote\" =>");
    for token in ["check_timestamp", "7200", "SystemTime", "UNIX_EPOCH", "saturating_add"] {
        assert!(!arm.contains(token), "candidate admission reads a wall clock ({token})");
    }
    assert!(arm.contains("self.candidate("), "the arm must still reach candidate admission");
}
