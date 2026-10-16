//! The wallet's automatic history catch-up over one admitted node connection (G1, approved B1 with
//! clarification 1). This is the Desktop owner of the schedule only: when to ask, which request is
//! active, and what the shell may say about it. It never decides what is canonical. A page from the
//! node is a fetch plan; every block it names is installed by the wallet's own full verifier, and the
//! saved finalized anchor moves only when that verifier commits. The node's observed tip is a hint.
//!
//! Approved policy, enforced here:
//! - one active logical request per connection, sequences 1..=u32::MAX, never reused or wrapped;
//! - an exact retransmission keeps the active sequence and frozen bytes; a new request (including a
//!   same-checkpoint refresh) takes the next sequence;
//! - after a completed nonempty page, ask again at once; at the snapshot tip, refresh every 10 s
//!   while connected and idle;
//! - Busy, EvidenceUnavailable and NodeUnavailable keep verified state and retry no sooner than
//!   10 s later on the same connection; CheckpointRejected and BoundsRejected stop automatic history
//!   for this connection;
//! - a missing reply never means caught up; there is no logical request timeout here (the transport's
//!   own session and I/O bounds close the link) and no automatic reconnect;
//! - closing, expiry or revocation drops the plan and the sequence space, never canonical state.
use std::time::{Duration, Instant};

/// Idle refresh and the earliest retry after a temporary refusal (approved, clarification 1).
pub(crate) const REFRESH: Duration = Duration::from_secs(10);

/// The node's answer to one request (R3 status values 0..=7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PageStatus {
    More,
    AtSnapshotTip,
    Busy,
    CheckpointRejected,
    EvidenceUnavailable,
    NodeUnavailable,
    BoundsRejected,
    Page,
}
impl PageStatus {
    pub(crate) fn from_wire(value: u8) -> Option<Self> {
        Some(match value {
            0 => Self::More,
            1 => Self::AtSnapshotTip,
            2 => Self::Busy,
            3 => Self::CheckpointRejected,
            4 => Self::EvidenceUnavailable,
            5 => Self::NodeUnavailable,
            6 => Self::BoundsRejected,
            7 => Self::Page,
            _ => return None,
        })
    }
}

/// A page already validated against its request by the shared codec (`validate_for`). Heights are
/// the decoded anchors' heights; `through` and `tip` exist only for the success statuses.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PageSummary {
    pub sequence: u32,
    pub status: PageStatus,
    pub through: Option<u64>,
    pub tip: Option<u64>,
    pub entries: usize,
}

/// What the service must do now. The scheduler holds no transport; the service performs the action
/// through the admitted history session and reports back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Action {
    /// Build and send a new request from the actual saved anchor with this sequence.
    Request { sequence: u32 },
}

/// Why automatic history stopped on this connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    CheckpointRejected,
    BoundsRejected,
    SequenceExhausted,
    /// The node does not offer the history profile; nothing falls back to another mechanism.
    Unsupported,
    /// A reply or install failed verification; the link is closed by the service.
    Refused,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum State {
    /// No admitted connection.
    Disconnected,
    /// A request is outstanding; nothing about the chain is known from it yet.
    Requested { sequence: u32, at: Instant },
    /// A valid page is being installed in order by the verifier.
    Applying { sequence: u32, status: PageStatus, through: u64 },
    /// At the node's snapshot tip as of `at`; refresh at `next`.
    Current { at: Instant, next: Instant },
    /// A temporary refusal; verified state kept, retry no sooner than `next`.
    Waiting { status: PageStatus, next: Instant },
    Stopped(Stop),
}

pub(crate) struct HistorySync {
    state: State,
    /// The next unused sequence on this connection; `None` once u32::MAX has been used.
    next_sequence: Option<u32>,
    /// The wallet's own saved finalized height (from its committed replica, never from a page).
    saved: u64,
    /// The node's last observed snapshot tip: a hint for progress only.
    observed_tip: Option<u64>,
}

impl HistorySync {
    pub(crate) fn new(saved: u64) -> Self {
        Self { state: State::Disconnected, next_sequence: None, saved, observed_tip: None }
    }
    pub(crate) fn state(&self) -> &State {
        &self.state
    }
    pub(crate) fn saved(&self) -> u64 {
        self.saved
    }
    pub(crate) fn observed_tip(&self) -> Option<u64> {
        self.observed_tip
    }
    /// The active request's sequence, for exact retransmission and reply correlation.
    pub(crate) fn active(&self) -> Option<u32> {
        match self.state {
            State::Requested { sequence, .. } | State::Applying { sequence, .. } => Some(sequence),
            _ => None,
        }
    }

    /// A fresh admitted connection (the person asked to connect). The sequence space restarts with
    /// the connection, and catch-up starts at once from the saved anchor.
    pub(crate) fn connected(&mut self, now: Instant, history_profile: bool) -> Option<Action> {
        self.next_sequence = Some(1);
        self.observed_tip = None;
        if !history_profile {
            self.state = State::Stopped(Stop::Unsupported);
            return None;
        }
        self.request(now)
    }

    /// The connection closed, expired or was revoked: the plan and its authority go; canonical state
    /// and the saved height stay exactly as committed.
    pub(crate) fn disconnected(&mut self) {
        self.state = State::Disconnected;
        self.next_sequence = None;
    }

    /// Called on every service tick. Only an idle refresh or an elapsed retry starts a request; an
    /// outstanding request is never replaced by time alone.
    pub(crate) fn tick(&mut self, now: Instant) -> Option<Action> {
        match self.state {
            State::Current { next, .. } | State::Waiting { next, .. } if now >= next => self.request(now),
            _ => None,
        }
    }

    /// A validated reply. A reply that does not answer the active request is refused.
    pub(crate) fn page(&mut self, now: Instant, page: &PageSummary) -> Result<(), Stop> {
        let State::Requested { sequence, .. } = self.state else { return Err(self.refuse()) };
        if page.sequence != sequence {
            return Err(self.refuse());
        }
        match page.status {
            PageStatus::More | PageStatus::Page => {
                let (Some(through), Some(tip)) = (page.through, page.tip) else { return Err(self.refuse()) };
                if page.entries == 0 || through <= self.saved || through > tip
                    || (page.status == PageStatus::Page) != (through == tip)
                {
                    return Err(self.refuse());
                }
                self.observed_tip = Some(tip);
                self.state = State::Applying { sequence, status: page.status, through };
            }
            PageStatus::AtSnapshotTip => {
                if page.entries != 0 || page.through != Some(self.saved) || page.tip != Some(self.saved) {
                    return Err(self.refuse());
                }
                self.observed_tip = Some(self.saved);
                self.state = State::Current { at: now, next: now + REFRESH };
            }
            PageStatus::Busy | PageStatus::EvidenceUnavailable | PageStatus::NodeUnavailable => {
                if page.entries != 0 || page.through.is_some() || page.tip.is_some() {
                    return Err(self.refuse());
                }
                self.state = State::Waiting { status: page.status, next: now + REFRESH };
            }
            PageStatus::CheckpointRejected => self.state = State::Stopped(Stop::CheckpointRejected),
            PageStatus::BoundsRejected => self.state = State::Stopped(Stop::BoundsRejected),
        }
        Ok(())
    }

    /// The verifier committed a block: the wallet's own saved height, read back from its replica.
    pub(crate) fn committed(&mut self, saved: u64) {
        if saved > self.saved {
            self.saved = saved;
        }
    }

    /// Every member of the active page was installed. Only now does the plan finish; MORE asks again
    /// at once, PAGE returns to idle refresh.
    pub(crate) fn page_installed(&mut self, now: Instant) -> Result<Option<Action>, Stop> {
        let State::Applying { status, through, .. } = self.state else { return Err(self.refuse()) };
        if self.saved != through {
            return Err(self.refuse());
        }
        match status {
            PageStatus::More => Ok(self.request(now)),
            _ => {
                self.state = State::Current { at: now, next: now + REFRESH };
                Ok(None)
            }
        }
    }

    /// The request just scheduled could not be built because the local queue has no room for a page
    /// and one candidate: nothing was sent, verified state is kept, and the next try waits the same
    /// 10 s as a refusal (the sequence stays consumed; it is never reused).
    pub(crate) fn local_wait(&mut self, now: Instant) {
        if let State::Requested { .. } = self.state {
            self.state = State::Waiting { status: PageStatus::Busy, next: now + REFRESH };
        }
    }

    /// The verifier refused a member, or a reply was malformed: the service closes the link.
    pub(crate) fn refuse(&mut self) -> Stop {
        self.state = State::Stopped(Stop::Refused);
        Stop::Refused
    }

    fn request(&mut self, now: Instant) -> Option<Action> {
        let Some(sequence) = self.next_sequence else {
            self.state = State::Stopped(Stop::SequenceExhausted);
            return None;
        };
        self.next_sequence = sequence.checked_add(1);
        self.state = State::Requested { sequence, at: now };
        Some(Action::Request { sequence })
    }

    /// One line for the shell. Saved height is the wallet's own; the node's tip is labelled a target.
    pub(crate) fn describe(&self) -> String {
        let saved = self.saved;
        let target = match self.observed_tip {
            Some(tip) if tip > saved => format!(", node reports {tip}"),
            _ => String::new(),
        };
        match &self.state {
            State::Disconnected => format!("Verified to height {saved}. Not connected."),
            State::Requested { .. } => format!("Verified to height {saved}. Asking the node for history{target}."),
            State::Applying { .. } => format!("Verified to height {saved}. Verifying history{target}."),
            State::Current { .. } => format!("Verified to height {saved}. Up to date with the node."),
            State::Waiting { .. } => {
                format!("Verified to height {saved}. History is not available from the node right now; will retry.")
            }
            State::Stopped(Stop::CheckpointRejected) => {
                format!("Verified to height {saved}. The node does not recognise this wallet's chain position.")
            }
            State::Stopped(Stop::Unsupported) => {
                format!("Verified to height {saved}. This node does not offer wallet history.")
            }
            State::Stopped(_) => format!("Verified to height {saved}. History stopped on this connection."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page(sequence: u32, status: PageStatus, through: Option<u64>, tip: Option<u64>, entries: usize) -> PageSummary {
        PageSummary { sequence, status, through, tip, entries }
    }

    #[test]
    fn connecting_asks_at_once_and_a_more_page_asks_again_only_after_it_is_installed() {
        let t = Instant::now();
        let mut sync = HistorySync::new(4);
        assert_eq!(sync.connected(t, true), Some(Action::Request { sequence: 1 }));
        sync.page(t, &page(1, PageStatus::More, Some(10), Some(30), 6)).unwrap();
        assert_eq!(sync.observed_tip(), Some(30));
        assert_eq!(sync.saved(), 4, "a page is a plan; nothing is saved from it");
        assert_eq!(sync.tick(t + REFRESH * 5), None, "time never replaces an active plan");
        sync.committed(7);
        assert!(sync.page_installed(t).is_err(), "a partly installed page does not finish");
        let mut sync = HistorySync::new(4);
        sync.connected(t, true);
        sync.page(t, &page(1, PageStatus::More, Some(10), Some(30), 6)).unwrap();
        sync.committed(10);
        assert_eq!(sync.page_installed(t).unwrap(), Some(Action::Request { sequence: 2 }));
        sync.page(t, &page(2, PageStatus::Page, Some(30), Some(30), 6)).unwrap();
        sync.committed(30);
        assert_eq!(sync.page_installed(t).unwrap(), None);
        assert!(matches!(sync.state(), State::Current { .. }));
    }

    #[test]
    fn idle_refresh_and_temporary_refusals_wait_ten_seconds_with_a_new_sequence() {
        let t = Instant::now();
        let mut sync = HistorySync::new(5);
        sync.connected(t, true);
        sync.page(t, &page(1, PageStatus::AtSnapshotTip, Some(5), Some(5), 0)).unwrap();
        assert_eq!(sync.tick(t + REFRESH - Duration::from_millis(1)), None);
        assert_eq!(sync.tick(t + REFRESH), Some(Action::Request { sequence: 2 }));
        for (sequence, status) in
            [(2, PageStatus::Busy), (3, PageStatus::EvidenceUnavailable), (4, PageStatus::NodeUnavailable)]
        {
            let at = t + REFRESH * sequence;
            sync.page(at, &page(sequence, status, None, None, 0)).unwrap();
            assert_eq!(sync.saved(), 5);
            assert_eq!(sync.tick(at + REFRESH - Duration::from_millis(1)), None, "no retry burst");
            assert_eq!(sync.tick(at + REFRESH), Some(Action::Request { sequence: sequence + 1 }));
        }
    }

    #[test]
    fn checkpoint_or_bounds_rejection_stops_this_connection_until_a_fresh_connect() {
        let t = Instant::now();
        for (status, stop) in
            [(PageStatus::CheckpointRejected, Stop::CheckpointRejected), (PageStatus::BoundsRejected, Stop::BoundsRejected)]
        {
            let mut sync = HistorySync::new(3);
            sync.connected(t, true);
            sync.page(t, &page(1, status, None, None, 0)).unwrap();
            assert_eq!(sync.state(), &State::Stopped(stop));
            assert_eq!(sync.tick(t + REFRESH * 100), None);
            assert_eq!(sync.saved(), 3, "no rollback");
            sync.disconnected();
            assert_eq!(sync.connected(t, true), Some(Action::Request { sequence: 1 }));
        }
    }

    #[test]
    fn replies_that_do_not_answer_the_active_request_or_contradict_it_are_refused() {
        let t = Instant::now();
        let bad = [
            page(2, PageStatus::Page, Some(9), Some(9), 1),        // wrong sequence
            page(1, PageStatus::More, Some(9), Some(9), 1),        // MORE at the tip
            page(1, PageStatus::Page, Some(8), Some(9), 1),        // PAGE short of the tip
            page(1, PageStatus::More, Some(5), Some(9), 1),        // does not advance
            page(1, PageStatus::Page, Some(9), Some(9), 0),        // empty success
            page(1, PageStatus::More, None, Some(9), 1),           // missing anchor
            page(1, PageStatus::AtSnapshotTip, Some(6), Some(6), 0), // not the saved anchor
            page(1, PageStatus::Busy, None, None, 1),              // refusal with entries
            page(1, PageStatus::NodeUnavailable, Some(5), None, 0), // refusal with an anchor
        ];
        for reply in bad {
            let mut sync = HistorySync::new(5);
            sync.connected(t, true);
            assert_eq!(sync.page(t, &reply), Err(Stop::Refused), "{reply:?}");
            assert_eq!(sync.saved(), 5);
        }
        let mut sync = HistorySync::new(5);
        assert!(sync.page(t, &page(1, PageStatus::AtSnapshotTip, Some(5), Some(5), 0)).is_err(), "unsolicited");
        assert_eq!(PageStatus::from_wire(8), None);
        assert_eq!(PageStatus::from_wire(7), Some(PageStatus::Page));
    }

    #[test]
    fn sequences_never_wrap_and_restart_only_with_a_new_connection() {
        let t = Instant::now();
        let mut sync = HistorySync::new(1);
        sync.connected(t, true);
        sync.next_sequence = Some(u32::MAX);
        sync.page(t, &page(1, PageStatus::AtSnapshotTip, Some(1), Some(1), 0)).unwrap();
        assert_eq!(sync.tick(t + REFRESH), Some(Action::Request { sequence: u32::MAX }));
        sync.page(t, &page(u32::MAX, PageStatus::AtSnapshotTip, Some(1), Some(1), 0)).unwrap();
        assert_eq!(sync.tick(t + REFRESH * 2), None);
        assert_eq!(sync.state(), &State::Stopped(Stop::SequenceExhausted));
        sync.disconnected();
        assert_eq!(sync.connected(t, true), Some(Action::Request { sequence: 1 }));
    }

    #[test]
    fn a_missing_reply_is_never_caught_up_and_closing_keeps_verified_state() {
        let t = Instant::now();
        let mut sync = HistorySync::new(12);
        sync.connected(t, true);
        assert_eq!(sync.active(), Some(1));
        assert_eq!(sync.tick(t + Duration::from_secs(3600)), None);
        assert!(!matches!(sync.state(), State::Current { .. }));
        sync.page(t, &page(1, PageStatus::More, Some(20), Some(40), 2)).unwrap();
        sync.committed(15);
        sync.disconnected();
        assert_eq!(sync.state(), &State::Disconnected);
        assert_eq!(sync.saved(), 15, "committed blocks stay; the plan does not");
        assert_eq!(sync.active(), None);
        assert_eq!(sync.tick(t + REFRESH * 10), None, "no automatic reconnect or request");
        assert_eq!(sync.connected(t, false), None);
        assert_eq!(sync.state(), &State::Stopped(Stop::Unsupported));
    }

    #[test]
    fn the_shell_line_separates_own_height_from_the_node_target() {
        let t = Instant::now();
        let mut sync = HistorySync::new(4);
        assert_eq!(sync.describe(), "Verified to height 4. Not connected.");
        sync.connected(t, true);
        sync.page(t, &page(1, PageStatus::More, Some(10), Some(30), 6)).unwrap();
        assert_eq!(sync.describe(), "Verified to height 4. Verifying history, node reports 30.");
        sync.committed(10);
        sync.page_installed(t).unwrap();
        sync.page(t, &page(2, PageStatus::Page, Some(30), Some(30), 4)).unwrap();
        sync.committed(30);
        sync.page_installed(t).unwrap();
        assert_eq!(sync.describe(), "Verified to height 30. Up to date with the node.");
    }
}
