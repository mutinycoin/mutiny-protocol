//! Exact existing restore report, extracted for the private same-source NTS tests.
use super::{anchor_store::Refusal, leap_policy::ClaimDisposition};
use mutiny_consensus_v8::holdover_clock_v1::RestartEvidence;
/// What happened to the stored anchor at start-up (for the start-up log and for tests). Since
/// Order C4 NO outcome qualifies the clock: every start is unqualified until the first
/// authenticated calibration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RestoreReport {
    /// No stored anchor: cold start, unqualified until the first authenticated calibration.
    Cold,
    /// A record of this lineage and boot was verified as EVIDENCE (Order C4): it would still be
    /// within its budget, but the unkeyed file grants no qualification after a restart, so the clock
    /// is unqualified until the first authenticated calibration. `leap` says what its leap claim
    /// still contributes (at most a shorten-only hint, Order C11).
    NotGranted {
        evidence: RestartEvidence,
        leap: ClaimDisposition,
    },
    /// A stored anchor could not even serve as evidence (reboot, power loss, suspend, rollback,
    /// corruption, old or unknown format...); unqualified until an authenticated recalibration.
    Refused(Refusal),
}
impl RestoreReport {
    /// One line for the start-up log. No secrets: only formats, reasons and clock readings.
    pub fn describe(&self) -> String {
        match self {
            RestoreReport::Cold => "no stored anchor; unqualified until the first authenticated calibration".into(),
            RestoreReport::NotGranted { evidence, leap } => format!(
                "anchor record {} verified as evidence only (it would show lower {} ms, half-width {} ms, {} ms of holdover left); a restart never resumes qualification from the unkeyed record (Order C4): unqualified until the first authenticated calibration (leap claim: {leap:?})",
                evidence.sequence,
                evidence.would_be_lower_ms,
                evidence.would_be_half_width_ms,
                evidence.would_be_remaining_ms
            ),
            RestoreReport::Refused(Refusal::Legacy(Some(s))) => format!(
                "legacy v1 anchor refused, never adopted (profile {}, lower {} ms, upper {} ms, high-water {} ms); unqualified until the first authenticated calibration",
                hex::encode(s.profile),
                s.lower_ms,
                s.upper_ms,
                s.high_water_ms
            ),
            RestoreReport::Refused(r) => {
                format!("stored anchor refused ({r:?}); unqualified until the first authenticated calibration")
            }
        }
    }
}
