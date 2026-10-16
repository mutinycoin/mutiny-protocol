use mutiny_consensus_v8::journal::{JournalError, Reservation, Step, VoteJournal};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "build8-journal-test-{}-{}.sqlite",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(!path.exists());
        Self(path)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
#[test]
fn crash_after_reservation_blocks_equivocation() {
    let f = Fixture::new();
    {
        let mut j = VoteJournal::open(&f.0, [1; 32]).unwrap();
        assert_eq!(
            j.reserve(1, 0, Step::Prevote, b"validated-A").unwrap(),
            Reservation::ReadyToSign
        );
    }
    let mut j = VoteJournal::open(&f.0, [1; 32]).unwrap();
    assert!(matches!(
        j.reserve(1, 0, Step::Prevote, b"validated-B"),
        Err(JournalError::ConflictingVote)
    ));
    assert_eq!(
        j.reserve(1, 0, Step::Prevote, b"validated-A").unwrap(),
        Reservation::ReadyToSign
    );
    j.record_signature(1, 0, Step::Prevote, b"validated-A", [8; 64])
        .unwrap();
    drop(j);
    let mut j = VoteJournal::open(&f.0, [1; 32]).unwrap();
    assert_eq!(
        j.reserve(1, 0, Step::Prevote, b"validated-A").unwrap(),
        Reservation::AlreadySigned([8; 64])
    );
}
#[test]
fn wrong_context_and_unreserved_signature_fail() {
    let f = Fixture::new();
    let mut j = VoteJournal::open(&f.0, [1; 32]).unwrap();
    assert!(matches!(
        j.record_signature(1, 0, Step::Precommit, b"A", [8; 64]),
        Err(JournalError::MissingReservation)
    ));
    assert!(matches!(
        VoteJournal::open(&f.0, [2; 32]),
        Err(JournalError::ContextMismatch)
    ));
}
#[test]
fn advancement_preserves_u64_high_water_and_bounds_history() {
    let f = Fixture::new();
    let mut j = VoteJournal::open(&f.0, [1; 32]).unwrap();
    for height in [1, 2, u64::MAX - 1, u64::MAX] {
        j.reserve(height, 0, Step::Prevote, b"A").unwrap();
    }
    drop(j);
    let mut j = VoteJournal::open(&f.0, [1; 32]).unwrap();
    assert!(matches!(
        j.reserve(u64::MAX - 1, 1, Step::Prevote, b"B"),
        Err(JournalError::StaleHeight)
    ));
    let db = rusqlite::Connection::open(&f.0).unwrap();
    let count: u64 = db
        .query_row("SELECT COUNT(*) FROM votes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
}
#[test]
fn independent_connections_cannot_reserve_conflicting_vote() {
    let f = Fixture::new();
    let mut a = VoteJournal::open(&f.0, [1; 32]).unwrap();
    let mut b = VoteJournal::open(&f.0, [1; 32]).unwrap();
    a.reserve(1, 0, Step::Precommit, b"A").unwrap();
    assert!(matches!(
        b.reserve(1, 0, Step::Precommit, b"B"),
        Err(JournalError::ConflictingVote)
    ));
    assert!(matches!(
        b.record_signature(1, 0, Step::Precommit, b"B", [9; 64]),
        Err(JournalError::ConflictingVote)
    ));
    a.record_signature(1, 0, Step::Precommit, b"A", [8; 64])
        .unwrap();
    assert!(matches!(
        b.record_signature(1, 0, Step::Precommit, b"A", [9; 64]),
        Err(JournalError::ConflictingSignature)
    ));
}
