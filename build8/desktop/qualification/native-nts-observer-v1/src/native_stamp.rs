//! Bounded native counter sandwich shared by live observation and offline controls.
//! Explicit diagnostic assumptions never become a measured class or voting authority.
#[cfg(target_os = "linux")]
use super::native_linux_elapsed::LinuxElapsed as NativeElapsed;
#[cfg(windows)]
use super::native_windows_elapsed::WindowsElapsed as NativeElapsed;
use super::{
    integer_interval::{ElapsedPair, EraWindow, Limits},
    observer::ReadOnlyClock,
};
use ntp_proto::{NtpClock, NtpTimestamp};
use serde::{Deserialize, Serialize};
use std::{io, time::Duration};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiagnosticBounds {
    pub era_lower_posix_ns: u64,
    pub era_upper_posix_ns: u64,
    /// Public reference only: this diagnostic does not authenticate its contents.
    pub era_context_sha256: String,
    pub maximum_sampling_span_ns: u64,
    pub wall_timestamp_uncertainty_ns: u64,
    pub elapsed_drift_ppb: u64,
    pub maximum_round_trip_ns: u64,
    pub maximum_interval_uncertainty_ns: u64,
}
impl DiagnosticBounds {
    pub(crate) fn validate(&self) -> io::Result<()> {
        if self.era().is_none()
            || self.era_context_sha256.len() != 64
            || !self
                .era_context_sha256
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
            || self.era_context_sha256.bytes().all(|b| b == b'0')
            || !(1..=1_000_000_000).contains(&self.maximum_sampling_span_ns)
            || !(1..=1_000_000_000).contains(&self.wall_timestamp_uncertainty_ns)
            || !(1..1_000_000_000).contains(&self.elapsed_drift_ppb)
            || !(1..=60_000_000_000).contains(&self.maximum_round_trip_ns)
            || !(1..=250_000_000).contains(&self.maximum_interval_uncertainty_ns)
        {
            return Err(io::Error::other(
                "invalid explicit diagnostic era/error bounds",
            ));
        }
        Ok(())
    }
    pub(crate) fn era(&self) -> Option<EraWindow> {
        EraWindow::new(self.era_lower_posix_ns, self.era_upper_posix_ns)
    }
    pub(crate) fn limits(&self) -> Limits {
        Limits {
            max_round_trip_ns: self.maximum_round_trip_ns,
            elapsed_drift_ppb: self.elapsed_drift_ppb,
            max_uncertainty_ns: self.maximum_interval_uncertainty_ns,
        }
    }
}
pub(crate) struct NativeStamp {
    elapsed: NativeElapsed,
    bounds: DiagnosticBounds,
}
impl NativeStamp {
    pub(crate) fn new(bounds: DiagnosticBounds) -> io::Result<Self> {
        bounds.validate()?;
        let elapsed = NativeElapsed::new(Duration::from_nanos(bounds.maximum_sampling_span_ns))
            .map_err(io::Error::other)?;
        Ok(Self { elapsed, bounds })
    }
    pub(crate) fn read(&self, clock: &ReadOnlyClock) -> io::Result<(NtpTimestamp, ElapsedPair)> {
        let a = self
            .elapsed
            .capture()
            .ok_or_else(|| io::Error::other("native pre-timestamp capture refused"))?;
        let timestamp = clock.now()?;
        let b = self
            .elapsed
            .capture()
            .ok_or_else(|| io::Error::other("native post-timestamp capture refused"))?;
        let pair = checked_pair(
            a.elapsed.monotonic_ns,
            a.elapsed.boottime_ns,
            a.elapsed.boot_id,
            a.pairing_uncertainty_ns,
            b.elapsed.monotonic_ns,
            b.elapsed.boottime_ns,
            b.elapsed.boot_id,
            b.pairing_uncertainty_ns,
            &self.bounds,
        )
        .ok_or_else(|| io::Error::other("timestamp sandwich identity/span/overflow refused"))?;
        Ok((timestamp, pair))
    }
}
fn checked_pair(
    a: u64,
    ai: u64,
    ab: u128,
    ap: u64,
    b: u64,
    bi: u64,
    bb: u128,
    bp: u64,
    bounds: &DiagnosticBounds,
) -> Option<ElapsedPair> {
    if ab == 0 || ab != bb {
        return None;
    }
    let active = b.checked_sub(a)?;
    let inclusive = bi.checked_sub(ai)?;
    if active > bounds.maximum_sampling_span_ns || inclusive > bounds.maximum_sampling_span_ns {
        return None;
    }
    Some(ElapsedPair {
        active_ns: a.checked_add(active / 2)?,
        inclusive_ns: ai.checked_add(inclusive / 2)?,
        boot_id: ab,
        uncertainty_ns: ap
            .checked_add(bp)?
            .checked_add(inclusive)?
            .checked_add(bounds.wall_timestamp_uncertainty_ns)?,
    })
}
#[cfg(test)]
pub(crate) fn test_bounds() -> DiagnosticBounds {
    DiagnosticBounds {
        era_lower_posix_ns: 1_577_836_800_000_000_000,
        era_upper_posix_ns: 2_208_988_800_000_000_000,
        era_context_sha256: "a".repeat(64),
        maximum_sampling_span_ns: 250_000_000,
        wall_timestamp_uncertainty_ns: 1_000_000,
        elapsed_drift_ppb: 100_000,
        maximum_round_trip_ns: 1_000_000_000,
        maximum_interval_uncertainty_ns: 250_000_000,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn required_diagnostic_bounds_and_whole_timestamp_sandwich_refuse_unsafe_inputs() {
        let bounds = test_bounds();
        bounds.validate().unwrap();
        let pair = checked_pair(100, 200, 7, 3, 105, 207, 7, 4, &bounds).unwrap();
        assert_eq!(pair.active_ns, 102);
        assert_eq!(pair.inclusive_ns, 203);
        assert_eq!(pair.uncertainty_ns, 1_000_014);
        for (b, bi, boot) in [
            (99, 207, 7),
            (105, 199, 7),
            (105, 207, 8),
            (105, 207, 0),
            (250_000_101, 207, 7),
            (105, 250_000_201, 7),
        ] {
            assert!(checked_pair(100, 200, 7, 3, b, bi, boot, 4, &bounds).is_none());
        }
        assert!(checked_pair(100, 200, 7, u64::MAX, 105, 207, 7, 4, &bounds).is_none());
        let mut invalid = bounds.clone();
        invalid.elapsed_drift_ppb = 0;
        assert!(invalid.validate().is_err());
        invalid = bounds.clone();
        invalid.era_context_sha256 = "0".repeat(64);
        assert!(invalid.validate().is_err());
        invalid = bounds.clone();
        invalid.maximum_interval_uncertainty_ns = 250_000_001;
        assert!(invalid.validate().is_err());
        invalid = bounds.clone();
        invalid.era_upper_posix_ns = invalid.era_lower_posix_ns;
        assert!(invalid.validate().is_err());
        assert!(serde_json::from_str::<DiagnosticBounds>("{}").is_err());
    }
}
