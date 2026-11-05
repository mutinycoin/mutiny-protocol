//! Legacy chrony HostClock adapter and private installed native clock implementation.
//! The chrony adapter supplies Linux elapsed samples and authenticated NTS calibration
//! to the consensus interval engine; its legacy anchor grants no restart qualification.
//! The private installed path adds protected owner/storage/channel, native acquisition,
//! conditional artifact qualification, same-boot restoration and explicit lifecycle handling.
//! Protected owner/backend/channel paths remain uncompiled and native-unrun. Shared Windows
//! mechanics alone passed an ordinary component check. Actual accepted artifact/evidence
//! inputs and integrated application qualification remain required.
//! The chrony fault model below describes the legacy adapter.
//!
//! Source authentication and fault model (declared):
//! * A fresh calibration requires at least three independently operated declared sources,
//!   with selected usable numeric source reports, NTS association mode, accepted authenticated
//!   responses and bounded sample freshness. Repeated reports must remain coherent throughout
//!   the measured capture. chrony is the trusted local authenticator and source selector;
//!   this adapter does not independently verify network packets or daemon configuration.
//!   Association setup alone, plain NTP and OS wall time never qualify a calibration.
//! * The sample is OS wall time widened by `|system offset| + root dispersion + root delay / 2`,
//!   the measurement window and one granularity millisecond. NOTHING is added for a pending leap
//!   second: a sample is judged by the engine on its whole possible interval against the ambiguous
//!   zone derived from the POSIX step mapping (refused if it reaches it, unchanged otherwise;
//!   Architect ruling 4). Wall time is only the CENTER of an authenticated interval; the engine
//!   never reads it between calibrations.
//! * Leap seconds: POSIX-step semantics (chrony `leapsecmode system`, a declared host
//!   precondition); smearing is unsupported. Every poll pushes a `LeapView` into the engine (see
//!   `leap_policy`), even when chronyc fails, so new information reassesses existing holdover and a
//!   failed poll can never extend a horizon. A clear never crosses a month end that nothing
//!   authenticated excluded (Order C9). An unauthenticated poll can only shorten: its leap
//!   announcement is a bounded, shorten-only hint and its Normal is ignored (Order C11); only a
//!   qualified authenticated reading releases an event (Order C1). There is no unauthenticated
//!   fallback: OS wall time is only ever the centre of a sample the engine authenticates.
//! * Restart (Order C4): the unkeyed V2 record is NOT integrity or rollback protection, so it never
//!   grants qualification after a restart. A record of this lineage and boot is verified as
//!   EVIDENCE (`HoldoverClock::assess_restart`) for the start-up log; the restarted engine is
//!   unqualified until a fresh authenticated calibration, whatever the record says. Fresh voting
//!   after a process restart during a total external-time blackout is therefore unavailable until a
//!   qualified protected backend supplies it. The private native backend and owner below are
//!   implemented source paths, but remain uncompiled and native-unrun. This legacy adapter takes only the
//!   high-water ratchet (it can only refuse) and a stored announcement as a shorten-only hint.
//!   After a reboot, power loss or suspend nothing changes: unqualified until an authenticated
//!   recalibration. Every change of the live anchor or of the leap view is still written back (or
//!   the stored record invalidated), for lineage and diagnostics.
//! * No numeric qualification bound lives in this file. The deployment profile is frozen outside
//!   the code and supplied through runtime configuration and must pass
//!   `ClockProfile::validate_qualification`.
//!
//! The chrony CSV layouts below follow the documented `chronyc -c` output of chrony 4.x
//! (tracking: 14 fields; sources: mode,state,name,...; authdata: name,mode,...). They are verified
//! against documented samples only: live qualification against the target chrony is a named gate.
use mutiny_consensus_v8::holdover_clock_v1::{
    ADAPTER_GRANULARITY_MS, ClockProfile, Elapsed, ElapsedSource, HoldoverClock, LeapView,
    RestartEvidence, SourceSample, Status, TimeBasis,
};
use mutiny_consensus_v8::vote_clock_v1::VoteClock;
use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

#[path = "host_clock/anchor_store.rs"]
pub mod anchor_store;
// Private protected lineage, installed owner/session, native storage/channel, and
// conditional qualification/engine/restart/closure/replacement implementation.
// Reviewed source is uncompiled and native-unrun; actual selected authenticated
// qualification inputs and integrated application qualification remain required.
#[path = "host_clock/protected_clock_lineage_v1.rs"]
mod protected_clock_lineage_v1;
#[path = "host_clock/protected_clock_operation_journal.rs"]
mod protected_clock_operation_journal;
#[path = "host_clock/protected_clock_node_query.rs"]
mod protected_clock_node_query;
pub(crate) use protected_clock_node_query::{InstalledNodeClockQuery,PreparedNodeClockAttempt,NodeClockQueryFailure};
#[cfg(any(target_os="linux",windows))]
#[path = "host_clock/protected_clock_private_session.rs"]
mod protected_clock_private_session;
#[cfg(any(target_os="linux",windows))]
pub(crate) use protected_clock_private_session::{InstalledPrivateClockSession,PrivateClockSessionStart,PrivateClockSessionStop,JoinedPrivateClockSession,PrivateClockSessionStartFailure};
#[cfg(any(target_os="linux",windows))]
#[path = "host_clock/protected_clock_owner.rs"]
mod protected_clock_owner;
#[cfg(any(target_os="linux",windows))]
#[path = "host_clock/protected_clock_application.rs"]
mod protected_clock_application;
#[cfg(any(target_os="linux",windows))]
#[path = "host_clock/protected_clock_controller.rs"]
mod protected_clock_controller;
#[cfg(any(target_os="linux",windows))]
pub use protected_clock_controller::{ProtectedClockController,ProtectedClockControllerFailure,ClosedProtectedClockController};
#[cfg(target_os="linux")]
pub(crate) use protected_clock_controller::{OrdinaryNodeClockController,OrdinaryNodeClockFailure,ClosedOrdinaryNodeClock};
#[cfg(any(target_os="linux",windows))]
pub(crate) use protected_clock_application::{OwnedProtectedClockApplication,ProtectedClockApplicationStop,JoinedProtectedClockApplication};
#[cfg(target_os="linux")]
#[path = "host_clock/protected_clock_linux_io.rs"]
mod protected_clock_linux_io;
#[cfg(target_os="linux")]
#[path = "host_clock/protected_clock_unix_channel.rs"]
mod protected_clock_unix_channel;
#[cfg(windows)]
#[path = "host_clock/protected_clock_windows_channel.rs"]
mod protected_clock_windows_channel;
// Mechanical own-process/public-file checks only. Distinct counter issuers
// must supply their own retained selection/canonical role; no Clock authority
// or endpoint permission is exported. Original temporary native obligations
// have checked release/unknown custody; native qualification remains separate.
#[cfg(windows)]
#[path = "host_clock/windows_public_object.rs"]
mod windows_public_object;
#[cfg(windows)]
pub(crate) use windows_public_object::WindowsCurrentObject as RetainedWindowsPublicObject;
#[cfg(windows)]
pub(crate) use windows_public_object::require_own_process_boundary;
#[cfg(windows)]
#[path = "host_clock/windows_native_query.rs"]
mod windows_native_query;
#[cfg(windows)]
pub(crate) use windows_native_query::{CurrentWindowsPrincipal,WindowsMechanicalFailure};
#[path = "host_clock/chrony_exec.rs"]
pub mod chrony_exec;
#[path = "host_clock/leap_policy.rs"]
pub mod leap_policy;
#[path = "host_clock/live_nts.rs"]
pub mod live_nts;
// Typed native NTS acquisition/engine bridge. Production startup remains disabled.
#[path = "host_clock/native_nts_backend.rs"]
mod native_nts_backend;
#[path = "host_clock/native_nts_service.rs"]
mod native_nts_service;
// Private same-source test-host forwarding only; absent from ordinary builds.
#[cfg(test)]
#[path = "host_clock/native_nts_test_harness.rs"]
pub(crate) mod native_nts_test_harness;
#[path = "host_clock/native_nts_deployment_record.rs"]
mod native_nts_deployment_record;
#[path = "host_clock/native_nts_qualification.rs"]
mod native_nts_qualification;
#[path = "host_clock/native_nts_measurement_verifier.rs"]
mod native_nts_measurement_verifier;
#[path = "host_clock/native_nts_measurement_checks.rs"]
mod native_nts_measurement_checks;
#[path = "host_clock/native_nts_raw_measurements.rs"]
mod native_nts_raw_measurements;
#[path = "host_clock/native_nts_calibration_record.rs"]
mod native_nts_calibration_record;
#[path = "host_clock/native_nts_documentary_publication.rs"]
mod native_nts_documentary_publication;
#[cfg(all(target_os="linux",target_arch="x86_64"))]
#[path = "host_clock/native_nts_linux_current.rs"]
mod native_nts_linux_current;
#[cfg(all(windows,target_arch="x86_64"))]
#[path = "host_clock/native_nts_windows_current.rs"]
mod native_nts_windows_current;
#[cfg(all(windows,target_arch="x86_64"))]
#[path = "host_clock/native_nts_windows_section.rs"]
mod native_nts_windows_section;
#[path = "host_clock/native_nts_startup.rs"]
mod native_nts_startup;
#[path = "host_clock/native_nts_current.rs"]
mod native_nts_current;
#[path = "host_clock/native_nts_installation.rs"]
mod native_nts_installation;
#[path = "host_clock/installation_directory.rs"]
mod installation_directory;
#[path = "host_clock/native_retained_close.rs"]
mod native_retained_close;
pub(crate) use native_retained_close::{RetainedCloseReport,retained_identity};
#[path = "host_clock/selected_clock.rs"]
mod selected_clock;
#[path = "host_clock/chrony_task.rs"]
mod chrony_task;
pub use chrony_task::ChronyClock;
pub use selected_clock::SelectedClock;
pub(crate) use native_nts_startup::{NativeClock, NativeClockStop};
#[path = "host_clock/nts_sources.rs"]
pub mod nts_sources;
#[path = "host_clock/storage_error.rs"]
mod storage_error;
#[path = "host_clock/state_dir.rs"]
pub mod state_dir;
// Version-pinned native diagnostics remain separate from qualified Windows startup.
#[path = "host_clock/windows_boot.rs"]
mod windows_boot;
#[path = "host_clock/windows_elapsed.rs"]
pub mod windows_elapsed;
use anchor_store::{AnchorStore, LoadOutcome, Refusal, StoreCondition};
use leap_policy::{ClaimDisposition, LeapMemory, LeapObservation};
use state_dir::ClockStateDir;

type Result<T> = std::result::Result<T, String>;

// ---------------------------------------------------------------------------------------------
// Elapsed source
// ---------------------------------------------------------------------------------------------
#[cfg(target_os = "linux")]
mod sys {
    #[repr(C)]
    pub struct Timespec {
        pub tv_sec: i64,
        pub tv_nsec: i64,
    }
    unsafe extern "C" {
        pub fn clock_gettime(clk: i32, ts: *mut Timespec) -> i32;
    }
    pub const CLOCK_MONOTONIC: i32 = 1;
    pub const CLOCK_BOOTTIME: i32 = 7;
    pub fn read(clk: i32) -> Option<u64> {
        let mut ts = Timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: `ts` is a valid, exclusively borrowed timespec for the duration of the call.
        if unsafe { clock_gettime(clk, &mut ts) } != 0 || ts.tv_sec < 0 || ts.tv_nsec < 0 {
            return None;
        }
        (ts.tv_sec as u64)
            .checked_mul(1_000_000_000)?
            .checked_add(ts.tv_nsec as u64)
    }
}

/// `/proc/sys/kernel/random/boot_id` (a UUID) as 128 bits. That the kernel generates it at random
/// once per boot and shows the same value to every reader is general kernel knowledge, UNVERIFIED
/// on the target kernel (docs/CLOCK-PROFILE-V1.md, 5.7).
pub fn parse_boot_id(text: &str) -> Option<u128> {
    let hex: String = text.trim().chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 {
        return None;
    }
    u128::from_str_radix(&hex, 16).ok()
}

/// The monotonic value paired with a boottime sample taken between two monotonic samples
/// (`first`, then `second`): their midpoint. `None` when the monotonic clock went backwards between
/// them (impossible for a sane kernel; the reading is refused).
pub fn sandwich_midpoint(first_ns: u64, second_ns: u64) -> Option<u64> {
    first_ns.checked_add(second_ns.checked_sub(first_ns)? / 2)
}

/// CLOCK_MONOTONIC + CLOCK_BOOTTIME + boot identity. Unavailable off Linux (then the live node
/// cannot qualify a clock and abstains).
pub struct LinuxElapsed;
impl ElapsedSource for LinuxElapsed {
    fn read(&self) -> Option<Elapsed> {
        #[cfg(target_os = "linux")]
        {
            // The boot identity first: a /proc read takes microseconds and must not sit between
            // the clock samples below.
            let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
            // Two clocks cannot be read atomically, so each reading's gap `boottime - monotonic`
            // carries the time between its samples (independent review, MAJOR-2). They are read
            // as MONOTONIC, BOOTTIME, MONOTONIC back to back (vDSO calls, tens of nanoseconds each)
            // and the boottime sample is paired with the MIDPOINT of the two monotonic samples: the
            // pairing error is then half the difference of the two half-windows, centred on zero,
            // and a preemption between any two of the calls moves the gap by half its length.
            // Reading MONOTONIC then BOOTTIME (the previous order) put the whole delay into the
            // gap, always with the same sign; BOOTTIME then MONOTONIC would do the same with the
            // other sign. The engine tolerates the remaining jitter in both directions
            // (`max_suspend_gap_ms`); the elapsed time it uses is the difference of two BOOTTIME
            // samples, which this pairing does not touch.
            let first = sys::read(sys::CLOCK_MONOTONIC)?;
            let boottime_ns = sys::read(sys::CLOCK_BOOTTIME)?;
            let second = sys::read(sys::CLOCK_MONOTONIC)?;
            Some(Elapsed {
                monotonic_ns: sandwich_midpoint(first, second)?,
                boottime_ns,
                boot_id: parse_boot_id(&boot)?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
}

// ---------------------------------------------------------------------------------------------
// chrony
// ---------------------------------------------------------------------------------------------
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Leap {
    Normal,
    /// chrony announces a leap second to be inserted.
    Insert,
    /// chrony announces a leap second to be deleted.
    Delete,
}
impl Leap {
    /// A leap second is announced (an announcement may shorten holdover even when unauthenticated).
    pub fn is_pending(self) -> bool {
        !matches!(self, Leap::Normal)
    }
    fn observation(self) -> LeapObservation {
        match self {
            Leap::Normal => LeapObservation::Normal,
            Leap::Insert => LeapObservation::Insert,
            Leap::Delete => LeapObservation::Delete,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Tracking {
    pub stratum: u32,
    /// Absolute value only: the sign convention never matters for the bound.
    pub system_offset_s: f64,
    pub root_delay_s: f64,
    pub root_dispersion_s: f64,
    pub leap: Leap,
}
/// A finite chrony number of plausible magnitude, either sign.
fn finite(v: &str) -> Result<f64> {
    let x: f64 = v.trim().parse().map_err(|_| "chrony number")?;
    if !x.is_finite() || x.abs() > 1.0e6 {
        return Err("chrony number range".into());
    }
    Ok(x)
}
/// A chrony quantity that cannot be negative (root delay, root dispersion). A negative value
/// would SHRINK the error bound it is added to, so the reading is refused, never taken by magnitude.
fn finite_nonneg(v: &str) -> Result<f64> {
    let x = finite(v)?;
    if x < 0.0 {
        return Err("chrony negative root delay or dispersion".into());
    }
    Ok(x)
}
/// The 14 fields of the first non-empty line of `chronyc -c tracking`.
fn tracking_fields(csv: &str) -> Result<Vec<&str>> {
    let line = csv.lines().find(|l| !l.trim().is_empty()).ok_or("chrony tracking empty")?;
    let f: Vec<&str> = line.split(',').collect();
    if f.len() != 14 {
        return Err("chrony tracking layout".into());
    }
    Ok(f)
}
/// `chronyc -c tracking`: ref id, name, stratum, ref time, system offset, last offset, rms offset,
/// frequency, residual frequency, skew, root delay, root dispersion, update interval, leap status.
pub fn parse_tracking(csv: &str) -> Result<Tracking> {
    let f = tracking_fields(csv)?;
    let leap = match f[13].trim() {
        "Normal" => Leap::Normal,
        "Insert second" => Leap::Insert,
        "Delete second" => Leap::Delete,
        _ => return Err("chrony not synchronised".into()),
    };
    let stratum: u32 = f[2].trim().parse().map_err(|_| "chrony stratum")?;
    if stratum == 0 || stratum >= 16 {
        return Err("chrony stratum".into());
    }
    Ok(Tracking {
        stratum,
        // The offset's sign is a convention: its magnitude enters the bound.
        system_offset_s: finite(f[4])?.abs(),
        root_delay_s: finite_nonneg(f[10])?,
        root_dispersion_s: finite_nonneg(f[11])?,
        leap,
    })
}
/// Order C3, coherent capture: `tracking` is read before AND after the source lists of one poll.
/// Both readings must describe the same chrony clock update (reference id and name, stratum, the
/// reference time of the last update, leap status); a set that straddles an update is DISCARDED,
/// never mixed. Of the two readings the larger error terms are kept (conservative: the root
/// dispersion grows between them).
pub fn coherent_tracking(before: &str, after: &str) -> Result<Tracking> {
    let (a, b) = (tracking_fields(before)?, tracking_fields(after)?);
    let first = parse_tracking(before)?;
    let second = parse_tracking(after)?;
    let identity = |f: &[&str]| [0, 1, 2, 3, 13].map(|i| f[i].trim().to_string());
    if identity(&a) != identity(&b) {
        return Err("chrony state changed during the capture: reading set discarded".into());
    }
    Ok(Tracking {
        stratum: first.stratum,
        system_offset_s: first.system_offset_s.max(second.system_offset_s),
        root_delay_s: first.root_delay_s.max(second.root_delay_s),
        root_dispersion_s: first.root_dispersion_s.max(second.root_dispersion_s),
        leap: first.leap,
    })
}
/// `chronyc -n -c sources`: names (addresses) whose state is `*` (selected) or `+` (combined).
pub fn parse_selected(csv: &str) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for line in csv.lines().filter(|l| !l.trim().is_empty()) {
        let f: Vec<&str> = line.split(',').collect();
        if f.len() < 3 {
            return Err("chrony sources layout".into());
        }
        if matches!(f[1].trim(), "*" | "+") {
            out.insert(f[2].trim().to_string());
        }
    }
    Ok(out)
}
/// `chronyc -n -c authdata`: names (addresses) whose association mode is NTS.
pub fn parse_nts(csv: &str) -> Result<BTreeSet<String>> {
    let mut out = BTreeSet::new();
    for line in csv.lines().filter(|l| !l.trim().is_empty()) {
        let f: Vec<&str> = line.split(',').collect();
        if f.len() < 2 {
            return Err("chrony authdata layout".into());
        }
        if f[1].trim() == "NTS" {
            out.insert(f[0].trim().to_string());
        }
    }
    Ok(out)
}
pub trait ChronyClient: Send + Sync {
    /// Run `chronyc` with the given arguments and return stdout.
    fn run(&self, args: &[&str]) -> Result<String>;
}
pub struct ChronyCommand {
    pub path: PathBuf,
}
impl ChronyClient for ChronyCommand {
    /// Order C3: no shell, an empty inherited environment, a hard deadline with kill and reap, a
    /// bounded stdout and no unbounded wait (`chrony_exec`).
    fn run(&self, args: &[&str]) -> Result<String> {
        let stdout = chrony_exec::run_bounded(
            chrony_exec::chronyc_command(&self.path, args),
            chrony_exec::CHRONYC_DEADLINE,
            chrony_exec::CHRONYC_MAX_STDOUT,
        )
        .map_err(|e| format!("chronyc: {e}"))?;
        String::from_utf8(stdout).map_err(|_| "chronyc output".into())
    }
}
pub trait WallClock: Send + Sync {
    fn unix_ms(&self) -> Option<u64>;
}
pub struct OsWall;
impl WallClock for OsWall {
    fn unix_ms(&self) -> Option<u64> {
        u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_millis(),
        )
        .ok()
    }
}
/// How often the background thread looks at the clock status, and the poll cadence while the clock
/// is unqualified for ANY reason (a leap expiry, a regression catch-up, a discontinuity, a restart
/// or reboot, an expired holdover): an unqualified node must requalify as soon as an authenticated
/// sample is available, not after `calibrate_every_s` (at most one hour). Order C3: a LOCAL
/// IMPLEMENTATION SETTING (not a protocol or profile parameter, not covered by the profile identity).
/// No signing decision depends on it: every reading of the clock recomputes age and uncertainty from
/// the elapsed source (`HoldoverClock::status`), whenever the last poll was.
pub const RETRY_AFTER_EVENT: Duration = Duration::from_secs(5);

/// How long the background thread sleeps between two looks at the status. It never sleeps longer
/// than `RETRY_AFTER_EVENT`: the status is judged AFTER the sleep, so a clock that loses
/// qualification BETWEEN two polls (the anchor dies at a leap event, a holdover runs out) is noticed
/// and re-polled within that time instead of after a full `base`.
pub fn wake_interval(base: Duration) -> Duration {
    base.min(RETRY_AFTER_EVENT)
}
/// Whether a poll is due at a wake-up: the regular cadence `base` has elapsed since the last poll,
/// or the clock is not qualified (for any reason).
pub fn poll_due(base: Duration, since_last_poll: Duration, status: Status) -> bool {
    since_last_poll >= base || !matches!(status, Status::Qualified { .. })
}
/// The line to print when a poll reported a failure to maintain the anchor store (or `None`): once
/// per distinct message, so a full disk does not flood the log and a recovery is silent.
fn store_failure_to_report(result: &Result<bool>, reported: &mut Option<String>) -> Option<String> {
    match result {
        Err(e) if e.contains("anchor") => {
            if reported.as_deref() == Some(e.as_str()) {
                None
            } else {
                *reported = Some(e.clone());
                Some(format!("host clock: {e}"))
            }
        }
        Ok(_) => {
            *reported = None;
            None
        }
        Err(_) => None,
    }
}

pub struct ChronySource {
    pub client: Arc<dyn ChronyClient>,
    pub wall: Arc<dyn WallClock>,
    pub elapsed: Arc<dyn ElapsedSource>,
    pub min_nts_selected: usize,
    /// Configured deployment identities, joined to the live daemon's original
    /// source names; several endpoints of one operator count once.
    pub nts_sources: Vec<String>,
}
/// One poll of chrony: the sample it yields, whether it passed the NTS-selection check, the leap
/// status it reported and the UTC interval of the reading itself (dating for the leap policy).
#[derive(Clone, Debug)]
pub struct Observation {
    /// `authenticated` is false when fewer than `min_nts_selected` selected sources are NTS.
    pub sample: SourceSample,
    pub leap: Leap,
    /// `[wall - U, wall + U]`: the sample's possible UTC interval before the engine's roll.
    pub interval_ms: (u64, u64),
}
impl ChronySource {
    /// One authenticated sample, or an error that leaves the clock to abstain.
    pub fn sample(&self) -> Result<SourceSample> {
        let o = self.observe()?;
        if !o.sample.authenticated {
            return Err("too few NTS-authenticated selected sources".into());
        }
        Ok(o.sample)
    }
    /// Poll chrony once. An unauthenticated observation is returned (flagged) so that a leap
    /// ANNOUNCEMENT can still shorten holdover; it can never become an anchor or extend a horizon.
    /// Order C3: one coherent capture: `tracking` before and after the source lists must describe
    /// the same chrony update (`coherent_tracking`), and every reading lies inside the measured
    /// window `W` that is part of the sample's uncertainty.
    pub fn observe(&self) -> Result<Observation> {
        let before = self.elapsed.read().ok_or("elapsed source unavailable")?;
        let first = self.client.run(&["-h", "127.0.0.1", "-c", "tracking"])?;
        // Source refusal cannot discard a coherent pending leap announcement. It grants
        // no calibration: the unauthenticated observation reaches only shorten-only handling.
        let authenticated = tracking_fields(&first)?[1].trim().parse().ok()
            .and_then(|reference| live_nts::authenticated_operators(
                self.client.as_ref(), &self.nts_sources, self.min_nts_selected, reference,
            ).ok()).unwrap_or(false);
        let tracking = coherent_tracking(
            &first, &self.client.run(&["-h", "127.0.0.1", "-c", "tracking"])?,
        )?;
        let wall = self.wall.unix_ms().ok_or("wall clock unavailable")?;
        let after = self.elapsed.read().ok_or("elapsed source unavailable")?;
        if after.boot_id != before.boot_id || after.boottime_ns < before.boottime_ns {
            return Err("elapsed source discontinuity during sample".into());
        }
        let window_ms = (after.boottime_ns - before.boottime_ns).div_ceil(1_000_000);
        let seconds = tracking.system_offset_s + tracking.root_dispersion_s + tracking.root_delay_s / 2.0;
        let ceiling = (seconds * 1000.0).ceil();
        if !ceiling.is_finite() || !(0.0..=1.0e12).contains(&ceiling) {
            return Err("chrony uncertainty range".into());
        }
        // U = ceil(E) + W + ADAPTER_GRANULARITY_MS (the engine adds its own rounding and the
        // capture-age drift; see ClockProfile::validate_qualification).
        let base = (ceiling as u64)
            .checked_add(window_ms)
            .and_then(|v| v.checked_add(ADAPTER_GRANULARITY_MS))
            .ok_or("uncertainty overflow")?;
        // No allowance is added for a pending leap second. The engine judges the sample's WHOLE
        // possible interval (rolled over the capture age) against the ambiguous zone derived from
        // the POSIX step mapping: outside it the sample is unambiguous and unchanged, inside it
        // the sample is refused (an extra second would exceed the 1 s fresh-vote limit anyway).
        let interval_ms = (
            wall.checked_sub(base).ok_or("wall clock below its uncertainty")?,
            wall.checked_add(base).ok_or("uncertainty overflow")?,
        );
        Ok(Observation {
            sample: SourceSample {
                source: "chrony-nts".into(),
                authenticated,
                utc_ms: wall,
                uncertainty_ms: base,
                // The wall read happened between `before` and `after`; the window is in the bound.
                at: before,
            },
            leap: tracking.leap,
            interval_ms,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Host clock
// ---------------------------------------------------------------------------------------------
#[derive(Debug)]
pub struct HostClockConfig {
    pub profile: ClockProfile,
    pub chrony_path: PathBuf,
    pub min_nts_selected: usize,
    /// The V2 anchor record. `<anchor_file>.seq` (the write-ahead lineage mark), `<anchor_file>.lock`
    /// (the single-writer lock) and short-lived `.tmp` files live beside it. At start-up the
    /// directory is created owner-only if missing and must be owned by the node account, mode
    /// 0700, with no symbolic link and no ancestor another user could replace (Order C8,
    /// `state_dir`); one process per anchor holds the exclusive lock (Order C12).
    pub anchor_file: PathBuf,
    pub calibrate_every: Duration,
    /// Declared NTS source hostnames of the chrony configuration (validated: >= 3 operators).
    pub nts_sources: Vec<String>,
}
#[path = "host_clock/restore_report.rs"]
mod restore_report;
pub use restore_report::RestoreReport;
pub struct HostClock {
    clock: Arc<HoldoverClock>,
    source: ChronySource,
    store: Mutex<AnchorStore>,
    leap: Mutex<LeapMemory>,
    restore: RestoreReport,
}
impl HostClock {
    /// Build over explicit sources and an anchor directory that was verified and locked
    /// (`ClockStateDir::open`, Order C8 and C12; nothing of the store can be read without it).
    /// Production uses `start`; tests inject controlled sources.
    pub fn with_sources(
        profile: ClockProfile,
        source: ChronySource,
        state: ClockStateDir,
    ) -> Result<Arc<Self>> {
        let clock = HoldoverClock::new(profile, source.elapsed.clone())
            .map_err(|e| format!("clock profile: {e:?}"))?;
        // Start-up (Order C4). The engine starts unqualified and NOTHING read below can change
        // that: a stored record is verified as evidence for the log, never installed. The
        // high-water mark is a ratchet honoured from any VERIFIED stored bytes (it can only refuse
        // calibrations), and a stored announcement may become a shorten-only hint (Order C11).
        let (mut store, loaded) = AnchorStore::open(state);
        clock.ratchet_high_water(loaded.high_water_ms);
        let mut memory = LeapMemory::default();
        let restore = match loaded.outcome {
            LoadOutcome::Empty => RestoreReport::Cold,
            LoadOutcome::Refused(refusal) => RestoreReport::Refused(refusal),
            LoadOutcome::Record(record) => {
                // The record on disk does not belong to this process's (absent) live anchor.
                store.note_refused();
                match clock.assess_restart(&record) {
                    Ok(evidence) => RestoreReport::NotGranted {
                        leap: memory.restore_claim(evidence.leap),
                        evidence,
                    },
                    Err(e) => RestoreReport::Refused(Refusal::Verification(e)),
                }
            }
        };
        let host = Arc::new(Self {
            clock,
            source,
            store: Mutex::new(store),
            leap: Mutex::new(memory),
            restore,
        });
        // Push the view before any reading. Without an anchor and without an authenticated reading
        // the engine stays `Unassessed` (a hint alone assesses nothing).
        host.push_view();
        Ok(host)
    }
    /// How the stored anchor was treated at start-up.
    pub fn restore_report(&self) -> &RestoreReport {
        &self.restore
    }
    /// Push the adapter's current leap view into the engine (reassesses existing holdover).
    /// Returns whether the engine installed it: when the elapsed source cannot be read it installs
    /// only a view that vouches for no more than the one it holds (`HoldoverClock::set_leap_view`).
    fn push_view(&self) -> bool {
        let anchor_lower = self.clock.anchor_interval_ms().map(|(lo, _)| lo);
        let view = match self.leap.lock() {
            Ok(memory) => memory.view(anchor_lower),
            Err(_) => LeapView::Unassessed,
        };
        self.clock.set_leap_view(view)
    }
    /// Bring the stored record in line with the live engine: write it when the calibration evidence
    /// or the leap claim changed (or `force`), and INVALIDATE it when the live anchor is gone, so a
    /// restart can never resurrect holdover that newer information already ended.
    fn sync_store(&self, force: bool) -> Result<()> {
        let mut store = match self.store.lock() {
            Ok(store) => store,
            Err(poisoned) => {
                // A panic while the store was held may have left the disk in any state relative to
                // the live engine (a mark without its record, an older claim). Remove the record
                // (fail closed) rather than leave it restorable, and report. The lock stays
                // poisoned, so every later sync does the same and a restart is a cold start.
                poisoned.into_inner().fail_closed();
                return Err("anchor store poisoned: stored record removed (fail closed)".into());
            }
        };
        let synced = match self
            .clock
            .persisted(store.next_sequence(), leap_policy::POLICY_VERSION)
        {
            Some(record) => {
                if force || store.needs_write(&record) {
                    store.commit(&record)
                } else {
                    // Only the high-water mark may have advanced: keep the durable ratchet in step.
                    store.refresh_high_water(record.high_water_ms)
                }
            }
            // The elapsed source could not be read just now (a transient failure): the anchor is
            // still there, so nothing is invalidated on that account.
            None if self.clock.anchor_interval_ms().is_some() => Ok(()),
            None if store.live_record() => store.invalidate(self.clock.persisted_high_water()),
            None => Ok(()),
        };
        // Order C5. The live clock keeps its qualification after a failed write ONLY because stale
        // restart state cannot grant qualification here: the unkeyed store never does (Order C4,
        // `AnchorStore::GRANTS_RESTART_QUALIFICATION`), so a stale record fails closed on restore
        // whatever its content. A record that could not even be removed is still named explicitly.
        // Checked at COMPILE time for the worst condition (independent review, NIT-1): a backend
        // that could grant restart qualification would not build until this path is redesigned.
        const {
            assert!(anchor_store::live_qualification_may_continue(
                AnchorStore::GRANTS_RESTART_QUALIFICATION,
                StoreCondition::StaleNotInvalidated
            ))
        };
        match synced {
            Err(e) if store.condition() == StoreCondition::StaleNotInvalidated => Err(format!(
                "{e}; stale anchor record could not be invalidated (it grants nothing on a restart, Order C4)"
            )),
            other => other,
        }
    }
    /// The condition of the stored record (Order C5; diagnostics and tests).
    pub fn store_condition(&self) -> StoreCondition {
        match self.store.lock() {
            Ok(store) => store.condition(),
            Err(poisoned) => poisoned.into_inner().condition(),
        }
    }
    /// One wake-up of the background thread: poll when due (`poll_due`). `None` when no poll was due.
    pub fn background_step(&self, base: Duration, since_last_poll: Duration) -> Option<Result<bool>> {
        if poll_due(base, since_last_poll, self.clock.status()) {
            Some(self.calibrate_once())
        } else {
            None
        }
    }
    /// Native ordinary source adapter. Actual immutable accepted deployment and
    /// independently verified current-context inputs are absent in this candidate,
    /// so it cannot grant Windows voting/admission authority. This moves the same
    /// held storage owner, with no pathname reopen or caller-authored profile pin.
    pub(crate) fn start_native(record: &[u8], own_genesis: &[u8], state: ClockStateDir)
        -> Result<NativeClock> {
        native_nts_startup::start(record,own_genesis,state)
    }
    /// Production constructor: real elapsed source, chrony, OS wall time as sample CENTER only.
    pub fn start(config: HostClockConfig) -> Result<ChronyClock> {
        // Typed callers must satisfy the same settled budget gate as JSON input.
        config.profile.validate_qualification()
            .map_err(|e| format!("clock profile budget: {e:?}"))?;
        if !cfg!(target_os = "linux") {
            return Err("host clock requires Linux".into());
        }
        // Order C8 and C12, before anything of the store is read: owner-only storage, and the
        // exclusive lock this process keeps for its lifetime (a second instance fails here).
        let state = ClockStateDir::open(&config.anchor_file)
            .map_err(|e| format!("clock anchor storage refused: {e}"))?;
        let elapsed: Arc<dyn ElapsedSource> = Arc::new(LinuxElapsed);
        let host = Self::with_sources(
            config.profile,
            ChronySource {
                client: Arc::new(ChronyCommand {
                    path: config.chrony_path,
                }),
                wall: Arc::new(OsWall),
                elapsed,
                min_nts_selected: config.min_nts_selected,
                nts_sources: config.nts_sources,
            },
            state,
        )?;
        eprintln!("host clock: {}", host.restore_report().describe());
        ChronyClock::start(host, config.calibrate_every)
    }
    /// One calibration attempt. Failure leaves the clock on its holdover (or abstaining).
    /// The leap view is pushed FIRST (also when chronyc fails, then without new evidence), so new
    /// information reassesses existing holdover before anything else; a failed or unauthenticated
    /// poll can only keep or shorten the horizon. The wall clock is never read except as the centre
    /// of a sample. If the engine could not install the view of this poll (the elapsed source
    /// failed inside the push) no sample is offered at all in this poll. The stored record is
    /// brought in line twice per attempt (written when the evidence or the leap claim changed,
    /// invalidated when the anchor is gone): right after the new leap information is pushed, so it
    /// reaches the disk before the sample is processed (a crash in between cannot resurrect
    /// holdover the new information already ended), and at the end.
    pub fn calibrate_once(&self) -> Result<bool> {
        let observed = self.source.observe();
        let anchor_lower = self.clock.anchor_interval_ms().map(|(lo, _)| lo);
        if let Ok(mut memory) = self.leap.lock() {
            match &observed {
                // Authenticated: what chrony reports is evidence (it may announce or clear). Only a
                // reading within the profile's sample ceiling may release an announced event or
                // establish a clear (Order C1, C9); an announcement is folded either way.
                Ok(o) if o.sample.authenticated => {
                    let qualified =
                        o.sample.uncertainty_ms <= self.clock.profile().max_source_uncertainty_ms;
                    memory.observe(o.leap.observation(), Some(o.interval_ms), qualified)
                }
                // Unauthenticated ANNOUNCEMENT: a bounded, shorten-only hint (Order C11). Its kind
                // is not trusted (folded as the earliest possible step at that month end) and it is
                // applied only where it shortens the view.
                Ok(o) if o.leap.is_pending() => {
                    memory.observe_unverified(o.interval_ms, anchor_lower)
                }
                // Unauthenticated Normal, or no reading at all: no evidence, nothing to fold.
                Ok(_) | Err(_) => memory.observe(LeapObservation::Unavailable, None, false),
            }
        }
        let installed = self.push_view();
        // Write-ahead of new leap information. A failure here is handled inside the store (the
        // record that may now be stale is removed) and retried by the final sync below; it is still
        // reported if the final sync has nothing left to do.
        let early = self.sync_store(false);
        let result = (|| {
            let observed = observed?;
            // The view of THIS poll is not installed: the engine still holds an older view (or
            // none), which may not reflect what this poll learned. Offer nothing; the engine would
            // refuse a sample without a view anyway, but that must not be the only protection.
            if !installed {
                return Err(
                    "leap view not installed (elapsed source unavailable): calibration skipped"
                        .to_string(),
                );
            }
            if !observed.sample.authenticated {
                return Err("too few NTS-authenticated selected sources".to_string());
            }
            let anchored = self
                .clock
                .calibrate(&[observed.sample])
                .map_err(|e| format!("calibration rejected: {e:?}"));
            // A new anchor needs its own (calendar-only) view if no clear covers it.
            self.push_view();
            anchored
        })();
        let stored = match self.sync_store(false) {
            Ok(()) => early,
            failed => failed,
        };
        match (result, stored) {
            (Ok(anchored), Ok(())) => Ok(anchored),
            (Ok(_), Err(store)) => Err(store),
            (Err(calibration), Ok(())) => Err(calibration),
            // Both failed: report both (the store failure is what the operator can fix).
            (Err(calibration), Err(store)) => Err(format!("{calibration}; {store}")),
        }
    }
    /// Current leap view of the engine (diagnostics and tests).
    pub fn leap_view(&self) -> LeapView {
        self.clock.leap_view()
    }
    /// Write the current anchor and leap claim to the store unconditionally (a new lineage record).
    pub fn persist(&self) -> Result<()> {
        self.sync_store(true)
    }
    pub fn clock(&self) -> &Arc<HoldoverClock> {
        &self.clock
    }
    /// The same conservative basis for voter, proposer and operation admission.
    pub fn basis(&self) -> Arc<dyn TimeBasis> {
        self.clock.clone()
    }
    pub fn vote_clock(&self) -> Arc<dyn VoteClock> {
        self.clock.clone()
    }
}

/// Runtime configuration block `"clock"` of the node configuration (frozen deployment profile).
/// Strict parse of the nine identity-covered profile fields (no defaults, no unknown keys).
pub fn profile_from_json(p: &serde_json::Value) -> Result<ClockProfile> {
    let p = p.as_object().ok_or("clock profile object")?;
    const PROFILE: [&str; 9] = [
        "max_source_uncertainty_ms",
        "max_calibration_half_width_ms",
        "min_sources",
        "max_faulty_sources",
        "drift_bound_ppb",
        "max_holdover_ms",
        "max_interval_half_width_ms",
        "max_suspend_gap_ms",
        "confirm_calibrations",
    ];
    if p.len() != PROFILE.len() || p.keys().any(|k| !PROFILE.contains(&k.as_str())) {
        return Err("clock profile fields".into());
    }
    let n = |name: &str| -> Result<u64> {
        p[name].as_u64().ok_or_else(|| format!("clock profile {name}"))
    };
    Ok(ClockProfile {
        max_source_uncertainty_ms: n("max_source_uncertainty_ms")?,
        max_calibration_half_width_ms: n("max_calibration_half_width_ms")?,
        min_sources: u32::try_from(n("min_sources")?).map_err(|_| "min_sources")?,
        max_faulty_sources: u32::try_from(n("max_faulty_sources")?).map_err(|_| "max_faulty")?,
        drift_bound_ppb: n("drift_bound_ppb")?,
        max_holdover_ms: n("max_holdover_ms")?,
        max_interval_half_width_ms: n("max_interval_half_width_ms")?,
        max_suspend_gap_ms: n("max_suspend_gap_ms")?,
        confirm_calibrations: u32::try_from(n("confirm_calibrations")?)
            .map_err(|_| "confirm_calibrations")?,
    })
}

pub fn config_from_json(value: &serde_json::Value) -> Result<HostClockConfig> {
    let object = value.as_object().ok_or("clock configuration object")?;
    const FIELDS: [&str; 8] = [
        "profile",
        "chrony",
        "min_nts_selected",
        "anchor_file",
        "calibrate_every_s",
        "schema",
        "profile_sha256",
        "nts_sources",
    ];
    if object.len() != FIELDS.len() || object.keys().any(|k| !FIELDS.contains(&k.as_str())) {
        return Err("clock configuration fields".into());
    }
    if value["schema"] != "BUILD8-CLOCK-V1" {
        return Err("clock configuration schema".into());
    }
    let profile = profile_from_json(&value["profile"])?;
    profile.validate().map_err(|e| format!("clock profile: {e:?}"))?;
    // Budget rules: total initial uncertainty, 24 h-class drift budget, fresh-vote maximum.
    profile
        .validate_qualification()
        .map_err(|e| format!("clock profile budget: {e:?}"))?;
    // Declared NTS source hostnames: at least three independent OPERATORS.
    let hosts: Vec<String> = value["nts_sources"]
        .as_array()
        .ok_or("nts_sources")?
        .iter()
        .map(|h| h.as_str().map(str::to_string).ok_or("nts_sources entry"))
        .collect::<std::result::Result<_, _>>()?;
    nts_sources::validate_source_set(&hosts)?;
    // The frozen profile is pinned by its identity: editing a bound without re-freezing fails.
    let pinned = value["profile_sha256"].as_str().ok_or("profile_sha256")?;
    if pinned != hex::encode(profile.id()) {
        return Err("clock profile identity mismatch (profile is not the frozen one)".into());
    }
    let path = |field: &str| -> Result<PathBuf> {
        let p = PathBuf::from(value[field].as_str().ok_or_else(|| format!("clock {field}"))?);
        if !p.is_absolute() {
            return Err("clock paths must be absolute".into());
        }
        Ok(p)
    };
    let every = value["calibrate_every_s"].as_u64().ok_or("calibrate_every_s")?;
    if !(1..=3600).contains(&every) {
        return Err("calibrate_every_s range".into());
    }
    Ok(HostClockConfig {
        profile,
        chrony_path: path("chrony")?,
        min_nts_selected: usize::try_from(value["min_nts_selected"].as_u64().ok_or("min_nts_selected")?)
            .map_err(|_| "min_nts_selected")?,
        anchor_file: path("anchor_file")?,
        calibrate_every: Duration::from_secs(every),
        nts_sources: hosts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use mutiny_consensus_v8::holdover_clock_v1::{
        AnchorError, ControlledElapsed, LEAP_STEP_MS, LeapClaim, LeapKind, LineageMark,
        PersistedAnchor, Status, Unqualified,
    };
    use mutiny_consensus_v8::vote_clock_v1::ClockReading;
    use std::sync::Mutex;

    // Documented-format samples (chrony 4.x `-c`), TEST VALUES.
    const TRACKING: &str = "A29FC801,162.159.200.1,3,1790899200.123,-0.000012345,-0.000010,0.000020,12.345,0.012,0.045,0.020000000,0.001500000,64.2,Normal\n";
    const SOURCES: &str = "^,*,162.159.200.1,3,6,377,12,-0.000012,-0.000013,0.000200\n^,+,129.6.15.28,2,6,377,13,-0.000020,-0.000021,0.000300\n^,+,203.0.113.9,2,6,377,13,0.000050,0.000049,0.000300\n^,x,198.51.100.7,1,6,377,13,5.000000,5.000000,0.000300\n";
    const AUTHDATA: &str = "162.159.200.1,NTS,1,15,256,2880,0,0,8,100\n129.6.15.28,NTS,1,15,256,2880,0,0,8,100\n203.0.113.9,NTS,1,15,256,2880,0,0,8,100\n198.51.100.7,NTS,1,15,256,2880,0,0,8,100\n";

    struct Fake {
        tracking: Mutex<String>,
        sources: Mutex<String>,
        authdata: Mutex<String>,
    }
    impl ChronyClient for Fake {
        fn run(&self, args: &[&str]) -> Result<String> {
            Ok(match args.last().copied() {
                Some("tracking") => self.tracking.lock().unwrap().clone(),
                Some("sources") => self.sources.lock().unwrap().clone(),
                Some("authdata") => self.authdata.lock().unwrap().clone(),
                Some("-v") => "chronyc version 4.8 (+READLINE)\n".into(),
                Some(ip) if args.contains(&"sourcename") => match ip {
                    "162.159.200.1" => "time.cloudflare.com\n".into(),
                    "129.6.15.28" => "nts.netnod.se\n".into(),
                    "203.0.113.9" => "ptbtime1.ptb.de\n".into(),
                    _ => return Err("unknown TEST source".into()),
                },
                Some(ip) if args.contains(&"ntpdata") => live_nts::test_response(ip),
                _ => return Err("unexpected chronyc command".into()),
            })
        }
    }
    struct Wall(Mutex<u64>);
    impl WallClock for Wall {
        fn unix_ms(&self) -> Option<u64> {
            Some(*self.0.lock().unwrap())
        }
    }
    fn profile() -> ClockProfile {
        // Explicitly controlled TEST profile: not a device profile.
        ClockProfile {
            max_source_uncertainty_ms: 5_000,
            max_calibration_half_width_ms: 4_000,
            min_sources: 1,
            max_faulty_sources: 0,
            drift_bound_ppb: 100_000,
            max_holdover_ms: 3_600_000,
            max_interval_half_width_ms: 10_000,
            max_suspend_gap_ms: 50,
            confirm_calibrations: 1,
        }
    }
    fn qprofile() -> ClockProfile {
        // REQUIREMENT profile at the Architect budget (test use); NOT a hardware qualification.
        ClockProfile {
            max_source_uncertainty_ms: 248,
            max_calibration_half_width_ms: 250,
            min_sources: 1,
            max_faulty_sources: 0,
            drift_bound_ppb: 8680,
            max_holdover_ms: 86_400_000,
            max_interval_half_width_ms: 1000,
            max_suspend_gap_ms: 50,
            confirm_calibrations: 1,
        }
    }
    /// The anchor directory for a test process: the production lock (Order C12) without the unix
    /// ownership checks (Order C8, tested in `state_dir`); a second live process fails to open it.
    fn state(anchor: &PathBuf) -> ClockStateDir {
        ClockStateDir::open_unchecked_for_test(anchor).expect("anchor directory locked by another test process")
    }
    fn rig(
        min_nts: usize,
    ) -> (Arc<HostClock>, Arc<Fake>, Arc<Wall>, Arc<ControlledElapsed>, PathBuf) {
        rig_with(profile(), min_nts)
    }
    fn rig_with(
        profile: ClockProfile,
        min_nts: usize,
    ) -> (Arc<HostClock>, Arc<Fake>, Arc<Wall>, Arc<ControlledElapsed>, PathBuf) {
        let fake = Arc::new(Fake {
            tracking: Mutex::new(TRACKING.into()),
            sources: Mutex::new(SOURCES.into()),
            authdata: Mutex::new(AUTHDATA.into()),
        });
        let wall = Arc::new(Wall(Mutex::new(1_790_899_300_000)));
        let elapsed = ControlledElapsed::start(11);
        // Unique per test even when the platform clock is coarse (Windows) and tests run in parallel.
        static UNIQUE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "build8-host-clock-{}-{}-{}",
            std::process::id(),
            UNIQUE.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&dir).unwrap();
        let anchor = dir.join("anchor.bin");
        let host = HostClock::with_sources(
            profile,
            ChronySource {
                client: fake.clone(),
                wall: wall.clone(),
                elapsed: elapsed.clone(),
                min_nts_selected: min_nts,
                nts_sources: HOSTS.iter().map(|h| (*h).to_owned()).collect(),
            },
            state(&anchor),
        )
        .unwrap();
        (host, fake, wall, elapsed, anchor)
    }

    #[test]
    fn parses_documented_chrony_layouts_and_rejects_everything_else() {
        let t = parse_tracking(TRACKING).unwrap();
        assert_eq!(t.stratum, 3);
        assert_eq!(t.leap, Leap::Normal);
        assert!((t.system_offset_s - 0.000012345).abs() < 1e-12, "sign never matters");
        assert_eq!(
            parse_selected(SOURCES).unwrap().into_iter().collect::<Vec<_>>(),
            ["129.6.15.28", "162.159.200.1", "203.0.113.9"]
        );
        assert_eq!(parse_nts(AUTHDATA).unwrap().len(), 4);
        assert_eq!(parse_tracking(&TRACKING.replace("Normal", "Insert second")).unwrap().leap, Leap::Insert);
        assert_eq!(parse_tracking(&TRACKING.replace("Normal", "Delete second")).unwrap().leap, Leap::Delete);
        assert!(Leap::Insert.is_pending() && Leap::Delete.is_pending() && !Leap::Normal.is_pending());
        assert!(parse_tracking("").is_err());
        assert!(parse_tracking("a,b,c").is_err());
        assert!(parse_tracking(&TRACKING.replace("Normal", "Not synchronised")).is_err());
        assert!(parse_tracking(&TRACKING.replace(",3,", ",0,")).is_err());
        assert!(parse_tracking(&TRACKING.replace("0.001500000", "nan")).is_err());
        // Root delay and root dispersion cannot be negative: a negative value would shrink the
        // error bound, so the line is refused (only the system offset's sign is a convention).
        let delay_dispersion = "0.020000000,0.001500000";
        for bad in ["-0.020000000,0.001500000", "0.020000000,-0.001500000", "-0.02,-0.0015"] {
            let e = parse_tracking(&TRACKING.replace(delay_dispersion, bad)).unwrap_err();
            assert!(e.contains("negative"), "{bad}: {e}");
        }
        assert!(parse_tracking(&TRACKING.replace(delay_dispersion, "0.000000000,0.000000000")).is_ok());
        let positive = parse_tracking(&TRACKING.replace("-0.000012345", "0.000012345")).unwrap();
        assert_eq!(positive.system_offset_s, t.system_offset_s);
        assert!(parse_selected("garbage").is_err());
        assert!(parse_nts("x").is_err());
        assert_eq!(parse_boot_id("0123456789ab-cdef-0123-4567-89abcdef0123"), None);
        assert!(parse_boot_id("01234567-89ab-cdef-0123-456789abcdef").is_some());
        assert_eq!(parse_boot_id("zzzz"), None);
    }
    #[test]
    fn nts_selected_sources_qualify_a_conservative_floor_and_unauthenticated_do_not() {
        let (host, fake, wall, _e, _p) = rig(2);
        assert_eq!(host.vote_clock().reading(), ClockReading::Unqualified);
        assert_eq!(host.calibrate_once(), Ok(true));
        let ClockReading::Qualified { utc_seconds } = host.vote_clock().reading() else {
            panic!("qualified")
        };
        // wall center 1_790_899_300_000 ms; uncertainty ~ 12.3 + 1.5 + 10 ms + window + 1 ms.
        assert_eq!(utc_seconds, 1_790_899_299, "floor of the lower bound, never above wall time");
        assert!(host.basis().lower_bound_ms().unwrap() <= *wall.0.lock().unwrap());
        // Only two independent authenticated selected operators: below the required three. No new sample.
        *fake.authdata.lock().unwrap() = AUTHDATA.replace("129.6.15.28,NTS", "129.6.15.28,-");
        assert!(host.calibrate_once().is_err());
        // Not synchronised: no sample either.
        *fake.authdata.lock().unwrap() = AUTHDATA.into();
        *fake.tracking.lock().unwrap() = TRACKING.replace("Normal", "Not synchronised");
        assert!(host.calibrate_once().is_err());
    }
    #[test]
    fn os_wall_clock_steps_cannot_move_voting_authority_between_calibrations() {
        let (host, _f, wall, elapsed, _p) = rig(1);
        host.calibrate_once().unwrap();
        let before = host.basis().lower_bound_ms().unwrap();
        // The OS wall clock jumps a year forward and a year back: the engine never reads it.
        *wall.0.lock().unwrap() += 365 * 86_400_000;
        elapsed.run(5_000);
        let after = host.basis().lower_bound_ms().unwrap();
        assert!(after > before && after <= before + 5_000);
        *wall.0.lock().unwrap() -= 2 * 365 * 86_400_000;
        elapsed.run(5_000);
        let later = host.basis().lower_bound_ms().unwrap();
        assert!(later > after && later <= before + 10_000);
        // A calibration that follows the stepped wall time is NOT adopted as a forward jump
        // (discontinuity) nor accepted as a rollback (regression).
        assert!(host.calibrate_once().is_err() || host.basis().lower_bound_ms().is_none());
    }
    #[test]
    fn offline_holdover_then_expiry_and_a_restart_needs_a_fresh_authenticated_calibration() {
        let (host, fake, _w, elapsed, anchor) = rig(1);
        host.calibrate_once().unwrap();
        assert!(anchor.exists());
        // Internet gone: chrony fails. Holdover continues without any source.
        *fake.tracking.lock().unwrap() = String::new();
        assert!(host.calibrate_once().is_err());
        elapsed.run(30 * 60_000);
        assert!(host.basis().lower_bound_ms().is_some());
        // Past the permitted holdover the clock abstains: finite holdover != indefinite voting.
        elapsed.run(40 * 60_000);
        assert_eq!(
            host.clock().status(),
            Status::Unqualified(Unqualified::HoldoverExpired)
        );
        assert!(host.vote_clock().reading() == ClockReading::Unqualified);
        // A process restart within the same boot and holdover (Order C4): the stored record is
        // verified as evidence only; the restarted node is unqualified, and with chrony down it stays
        // so. Fresh voting after a restart during a total external-time blackout is unavailable.
        let (host, fake, _w, elapsed, anchor) = rig(1);
        host.calibrate_once().unwrap();
        *fake.tracking.lock().unwrap() = String::new();
        drop(host);
        elapsed.run(30 * 60_000);
        let restarted = restart(&fake, &elapsed, &anchor, profile());
        assert!(matches!(restarted.restore_report(), RestoreReport::NotGranted { .. }));
        assert!(restarted.basis().lower_bound_ms().is_none());
        assert!(restarted.calibrate_once().is_err());
        assert!(restarted.basis().lower_bound_ms().is_none(), "no source, no qualification");
        // A reboot between save and restart: powered-off time is unknown, the record is refused.
        let (host, fake, _w, elapsed, anchor) = rig(1);
        host.calibrate_once().unwrap();
        drop(host);
        elapsed.reboot(12);
        let rebooted = restart(&fake, &elapsed, &anchor, profile());
        assert!(matches!(rebooted.restore_report(), RestoreReport::Refused(_)));
        assert!(rebooted.basis().lower_bound_ms().is_none());
    }
    const HOSTS: [&str; 4] = [
        "time.cloudflare.com",
        "nts.netnod.se",
        "ptbtime1.ptb.de",
        "ntppool1.time.nl",
    ];
    fn config_json(p: &ClockProfile) -> serde_json::Value {
        // Platform-appropriate absolute paths (the check is `Path::is_absolute`).
        let abs = |n: &str| std::env::temp_dir().join(n).to_string_lossy().into_owned();
        serde_json::json!({
            "schema": "BUILD8-CLOCK-V1",
            "profile": {
                "max_source_uncertainty_ms": p.max_source_uncertainty_ms,
                "max_calibration_half_width_ms": p.max_calibration_half_width_ms,
                "min_sources": p.min_sources,
                "max_faulty_sources": p.max_faulty_sources,
                "drift_bound_ppb": p.drift_bound_ppb,
                "max_holdover_ms": p.max_holdover_ms,
                "max_interval_half_width_ms": p.max_interval_half_width_ms,
                "max_suspend_gap_ms": p.max_suspend_gap_ms,
                "confirm_calibrations": p.confirm_calibrations,
            },
            "profile_sha256": hex::encode(p.id()),
            "chrony": abs("chronyc"),
            "min_nts_selected": 3,
            "anchor_file": abs("clock.anchor"),
            "calibrate_every_s": 64,
            "nts_sources": HOSTS,
        })
    }

    #[test]
    fn refrozen_initial_251ms_profile_refuses_even_with_short_holdover() {
        let mut p = qprofile();
        p.max_holdover_ms = 1;
        assert_eq!(config_from_json(&config_json(&p)).unwrap().profile, p);
        p.max_calibration_half_width_ms = 251;
        p.max_source_uncertainty_ms = 249;
        assert_eq!(p.validate(), Ok(()));
        let error = config_from_json(&config_json(&p)).unwrap_err();
        assert!(error.contains("clock profile budget: ProfileBudget"), "{error}");
        p.max_calibration_half_width_ms = 249;
        p.max_source_uncertainty_ms = 247;
        assert_eq!(config_from_json(&config_json(&p)).unwrap().profile, p);
    }

    #[test]
    fn typed_start_refuses_initial_251ms_before_any_anchor_path_side_effect() {
        // A new public TEST directory inherits the campaign's protected TEMP.
        // Its sentinel and all failed/partial path evidence remain available.
        let mut random = [0u8; 16];
        mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
        let dir = std::env::temp_dir().join(format!("build8-initial-budget-{}", hex::encode(random)));
        std::fs::create_dir(&dir).unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let sentinel = dir.join("public-sentinel.bin");
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&sentinel).unwrap();
        file.write_all(b"PUBLIC TEST unchanged initial-budget sentinel").unwrap();
        file.sync_all().unwrap(); drop(file);
        let mut p = qprofile(); p.max_holdover_ms = 1;
        p.max_calibration_half_width_ms = 251; p.max_source_uncertainty_ms = 249;
        assert_eq!(p.validate(), Ok(()));
        let config = HostClockConfig {
            profile: p, chrony_path: dir.join("absent-chronyc"), min_nts_selected: 3,
            anchor_file: dir.join("must-remain-absent").join("anchor.bin"),
            calibrate_every: Duration::from_secs(64),
            nts_sources: HOSTS.iter().map(|s| (*s).to_owned()).collect(),
        };
        let error = match HostClock::start(config) {
            Err(error) => error,
            Ok(_) => panic!("invalid initial-budget typed startup unexpectedly succeeded"),
        };
        assert_eq!(error, "clock profile budget: ProfileBudget");
        assert!(!dir.join("must-remain-absent").exists());
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"PUBLIC TEST unchanged initial-budget sentinel");
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
    }

    #[test]
    fn frozen_profile_identity_is_enforced_in_configuration() {
        let p = qprofile();
        let mut config = config_json(&p);
        let anchor_path = config["anchor_file"].as_str().unwrap().to_string();
        let parsed = config_from_json(&config).unwrap();
        assert_eq!(parsed.profile, p);
        assert_eq!(parsed.min_nts_selected, 3);
        assert_eq!(parsed.nts_sources, HOSTS);
        // Editing any bound without re-freezing (new identity) is refused.
        config["profile"]["max_suspend_gap_ms"] = 51.into();
        assert!(config_from_json(&config).unwrap_err().contains("identity"));
        config["profile"]["max_suspend_gap_ms"] = 50.into();
        config["anchor_file"] = "relative.anchor".into();
        assert!(config_from_json(&config).is_err());
        config["anchor_file"] = anchor_path.clone().into();
        config["unknown"] = 1.into();
        assert!(config_from_json(&config).is_err());
    }
    #[test]
    fn config_budget_and_source_set_are_enforced() {
        // A profile that violates the budget is refused even with a RE-FROZEN identity.
        let edits: [&dyn Fn(&mut ClockProfile); 4] = [
            &|p| p.max_source_uncertainty_ms = 249,
            &|p| p.max_interval_half_width_ms = 1001,
            &|p| p.drift_bound_ppb = 8681,
            &|p| {
                p.min_sources = 3;
                p.max_faulty_sources = 1;
            },
        ];
        for edit in edits {
            let mut p = qprofile();
            edit(&mut p);
            let e = config_from_json(&config_json(&p)).unwrap_err();
            assert!(e.contains("clock profile budget"), "{e}");
        }
        // The old lenient TEST profile is no longer a deployable configuration.
        assert!(config_from_json(&config_json(&profile())).unwrap_err().contains("budget"));
        // Structural errors keep their own message.
        let mut p = qprofile();
        p.confirm_calibrations = 0;
        assert!(config_from_json(&config_json(&p)).unwrap_err().contains("clock profile:"));
        // Fewer than three independent OPERATORS, many hostnames of one operator, a missing key.
        let mut c = config_json(&qprofile());
        c["nts_sources"] = serde_json::json!(["time.cloudflare.com", "nts.netnod.se"]);
        assert!(config_from_json(&c).unwrap_err().contains("independent operator"));
        c["nts_sources"] = serde_json::json!([
            "gbg1.nts.netnod.se",
            "gbg2.nts.netnod.se",
            "sth1.nts.netnod.se",
            "nts.netnod.se"
        ]);
        assert!(config_from_json(&c).unwrap_err().contains("independent operator"));
        c["nts_sources"] = serde_json::json!(["time.cloudflare.com", "nts.netnod.se", "pool.ntp.org"]);
        assert!(config_from_json(&c).is_err());
        c.as_object_mut().unwrap().remove("nts_sources");
        assert!(config_from_json(&c).is_err());
        // The identity tool entry point agrees with config parsing.
        let p = profile_from_json(&config_json(&qprofile())["profile"]).unwrap();
        assert_eq!(p, qprofile());
        assert!(profile_from_json(&serde_json::json!({"min_sources": 1})).is_err());
    }

    fn at(y: i64, m: i64, d: i64, h: u64, mi: u64, s: u64) -> u64 {
        leap_policy::month_start_ms(y * 12 + m - 1).unwrap()
            + (d as u64 - 1) * 86_400_000
            + h * 3_600_000
            + mi * 60_000
            + s * 1_000
    }
    fn set_wall(w: &Wall, v: u64) {
        *w.0.lock().unwrap() = v;
    }
    fn insert_tracking() -> String {
        TRACKING.replace("Normal", "Insert second")
    }
    fn delete_tracking() -> String {
        TRACKING.replace("Normal", "Delete second")
    }
    /// A new process of the node over the same anchor files, same boot (or whatever the controlled
    /// elapsed source says), with its own wall clock.
    fn restart_at(
        fake: &Arc<Fake>,
        elapsed: &Arc<ControlledElapsed>,
        anchor: &PathBuf,
        profile: ClockProfile,
        wall_ms: u64,
    ) -> Arc<HostClock> {
        HostClock::with_sources(
            profile,
            ChronySource {
                client: fake.clone(),
                wall: Arc::new(Wall(Mutex::new(wall_ms))),
                elapsed: elapsed.clone(),
                min_nts_selected: 1,
                nts_sources: HOSTS.iter().map(|h| (*h).to_owned()).collect(),
            },
            state(&anchor),
        )
        .unwrap()
    }
    fn restart(
        fake: &Arc<Fake>,
        elapsed: &Arc<ControlledElapsed>,
        anchor: &PathBuf,
        profile: ClockProfile,
    ) -> Arc<HostClock> {
        restart_at(fake, elapsed, anchor, profile, 0)
    }
    fn stored(anchor: &PathBuf) -> PersistedAnchor {
        PersistedAnchor::decode(&std::fs::read(anchor).unwrap()).unwrap()
    }
    fn rewrite_record(anchor: &PathBuf, edit: impl FnOnce(&mut PersistedAnchor)) {
        let mut record = stored(anchor);
        edit(&mut record);
        // Same sequence, so the lineage mark still matches: only the evidence under test changes.
        std::fs::write(anchor, record.encode()).unwrap();
    }

    // ------------------------------------------------------------------------------------------
    // Ruling 4: no blanket second; samples are judged against the derived ambiguous zone.
    // ------------------------------------------------------------------------------------------
    #[test]
    fn an_announcement_adds_no_blanket_second_to_a_sample() {
        // The sample's uncertainty is exactly the plain formula whatever chrony says about leaps.
        for tracking in [TRACKING.to_string(), insert_tracking(), delete_tracking()] {
            let (host, fake, ..) = rig_with(qprofile(), 1);
            *fake.tracking.lock().unwrap() = tracking;
            let o = host.source.observe().unwrap();
            assert_eq!(o.sample.uncertainty_ms, 13, "E = 11.512 ms -> 12, W = 0, +1");
            assert_eq!(o.interval_ms, (o.sample.utc_ms - 13, o.sample.utc_ms + 13));
        }
        // Far from the event the qualified time is identical with and without the announcement.
        let (a, ..) = rig(1);
        a.calibrate_once().unwrap();
        let (b, fake, ..) = rig(1);
        *fake.tracking.lock().unwrap() = insert_tracking();
        assert_eq!(b.calibrate_once(), Ok(true), "accepted during an announcement");
        assert_eq!(a.basis().lower_bound_ms(), b.basis().lower_bound_ms());
        assert!(matches!(
            b.leap_view(),
            LeapView::Pending { kind: LeapKind::Insert, .. }
        ));
    }

    #[test]
    fn samples_are_judged_on_their_whole_interval_against_the_derived_zone() {
        let t = at(2027, 1, 1, 0, 0, 0);
        let zone = t - LEAP_STEP_MS; // the zone is [T - S, T)
        // U = 13 at capture age 0 and the engine's roll adds 1 ms to the upper bound: the rolled
        // interval of a reading at `wall` is [wall - 13, wall + 14].
        for kind in [LeapKind::Insert, LeapKind::Delete] {
            let announce = match kind {
                LeapKind::Insert => insert_tracking(),
                LeapKind::Delete => delete_tracking(),
            };
            let try_wall = |wall_ms: u64| {
                let (host, fake, wall, ..) = rig_with(qprofile(), 1);
                *fake.tracking.lock().unwrap() = announce.clone();
                set_wall(&wall, wall_ms);
                let r = host.calibrate_once();
                (r, host)
            };
            // One millisecond below the zone: unambiguous, accepted, nothing added.
            let (r, host) = try_wall(zone - 15);
            assert_eq!(r, Ok(true), "{kind:?}");
            match kind {
                LeapKind::Insert => {
                    assert_eq!(host.clock().anchor_interval_ms().unwrap().1, zone - 1);
                    assert!(host.basis().lower_bound_ms().is_some());
                }
                // A deletion steps at the zone start: the calibration is adopted (it is
                // unambiguous) but the holdover it starts is already over.
                LeapKind::Delete => assert_eq!(
                    host.clock().status(),
                    Status::Unqualified(Unqualified::LeapTransition)
                ),
            }
            // The interval ends exactly on the first zone label, one ms into it, and well into it.
            for wall_ms in [zone - 14, zone - 13, zone - 1] {
                let e = try_wall(wall_ms).0.unwrap_err();
                assert!(e.contains("SourceLeapAmbiguity"), "{kind:?} {wall_ms}: {e}");
            }
            // The MIDPOINT (the wall reading) is outside the zone but the interval reaches into it.
            let (r, host) = try_wall(zone - 5);
            assert!(r.unwrap_err().contains("SourceLeapAmbiguity"), "{kind:?}");
            assert!(host.basis().lower_bound_ms().is_none(), "nothing was adopted");
            // Midpoint inside the zone.
            assert!(try_wall(zone + 500).0.unwrap_err().contains("SourceLeapAmbiguity"));
            // A day before the event: accepted, the qualified time equals the unannounced one.
            let early = t - 86_400_000;
            let (r, host) = try_wall(early);
            assert_eq!(r, Ok(true));
            let (plain, _f, w, ..) = rig_with(qprofile(), 1);
            set_wall(&w, early);
            plain.calibrate_once().unwrap();
            assert_eq!(host.basis().lower_bound_ms(), plain.basis().lower_bound_ms());
        }
    }

    #[test]
    fn announced_leap_keeps_recalibrating_until_the_zone_expires_at_the_step_and_requalifies_after() {
        let (host, fake, wall, elapsed, _p) = rig_with(qprofile(), 1);
        let t = at(2027, 1, 1, 0, 0, 0);
        set_wall(&wall, at(2026, 12, 31, 22, 50, 0));
        assert_eq!(host.calibrate_once(), Ok(true));
        // 22:55: chrony announces an insertion. The sample is far from the zone, so it is accepted
        // with NO blanket second: the node keeps recalibrating during the announcement.
        elapsed.run(5 * 60_000);
        set_wall(&wall, at(2026, 12, 31, 22, 55, 0));
        *fake.tracking.lock().unwrap() = insert_tracking();
        assert_eq!(host.calibrate_once(), Ok(true));
        assert_eq!(
            host.leap_view(),
            LeapView::Pending { kind: LeapKind::Insert, boundary_ms: t }
        );
        // The last sample whose interval still ends below the zone: wall = T - 1015.
        let sample_at = t - 1_015;
        elapsed.run(sample_at - at(2026, 12, 31, 22, 55, 0));
        set_wall(&wall, sample_at);
        assert_eq!(host.calibrate_once(), Ok(true), "interval ends 1 ms below the zone");
        // One millisecond later the interval ends on the first zone label: refused, and the
        // holdover of the previous sample continues untouched.
        elapsed.run(1);
        set_wall(&wall, sample_at + 1);
        let e = host.calibrate_once().unwrap_err();
        assert!(e.contains("SourceLeapAmbiguity"), "{e}");
        assert!(host.basis().lower_bound_ms().is_some());
        // Qualified operation continues until the rolled upper bound reaches the step (T): 998 ms
        // after the last accepted sample, and not one millisecond longer.
        elapsed.run(997);
        assert!(host.basis().lower_bound_ms().is_some(), "qualified up to the step");
        let hour = Duration::from_secs(3600);
        assert!(!poll_due(hour, Duration::ZERO, host.clock().status()), "qualified: regular cadence");
        elapsed.run(1);
        assert_eq!(
            host.clock().status(),
            Status::Unqualified(Unqualified::LeapTransition)
        );
        assert!(host.basis().lower_bound_ms().is_none());
        // The thread looks at the status every `wake_interval` (not every hour), sees the loss of
        // qualification BETWEEN two polls and polls at once instead of after the regular cadence.
        assert_eq!(wake_interval(hour), RETRY_AFTER_EVENT);
        assert!(poll_due(hour, Duration::ZERO, host.clock().status()));
        // The OS clock repeats a second: x ms after the last accepted wall read it shows
        // `label(x)`; the step is at x = 1015, after which the label is 1000 ms lower.
        let label = |x: u64| {
            if x < 1_015 {
                sample_at + x
            } else {
                sample_at + x - LEAP_STEP_MS
            }
        };
        // chrony reports Normal again. Inside the repeated second the reading is in the zone:
        // refused, and the sticky announcement is not withdrawn.
        *fake.tracking.lock().unwrap() = TRACKING.into();
        elapsed.run(1_500 - 999);
        set_wall(&wall, label(1_500));
        assert!(label(1_500) < t);
        let e = host.calibrate_once().unwrap_err();
        assert!(e.contains("SourceLeapAmbiguity"), "inside the zone: still abstaining: {e}");
        assert!(matches!(host.leap_view(), LeapView::Pending { .. }));
        // The label reaches T: the zone has been left but the event is not yet resolved.
        elapsed.run(2_015 - 1_500);
        set_wall(&wall, label(2_015));
        assert_eq!(label(2_015), t);
        assert!(host.calibrate_once().is_err());
        assert!(matches!(host.leap_view(), LeapView::Pending { .. }));
        // The event is resolved exactly when the reading's LOWEST possible time is one step past T.
        let release = t + leap_policy::RELEASE_AFTER_BOUNDARY_MS + 13;
        elapsed.run((release - 1) - t);
        set_wall(&wall, release - 1);
        assert!(host.calibrate_once().is_err());
        assert!(matches!(host.leap_view(), LeapView::Pending { .. }), "one ms short");
        elapsed.run(1);
        set_wall(&wall, release);
        assert_eq!(host.calibrate_once(), Ok(true));
        assert!(host.basis().lower_bound_ms().is_some());
        let LeapView::Clear { valid_until_ms } = host.leap_view() else {
            panic!("clear")
        };
        // Order C9: the January reading clears the end of January only.
        assert_eq!(valid_until_ms, at(2027, 2, 1, 0, 0, 0) - LEAP_STEP_MS);
    }

    #[test]
    fn c1_only_a_qualified_reading_past_the_cushion_releases_an_announced_event() {
        // Order C1 at host level. The cushion is policy; the release ALSO needs a qualified,
        // unambiguous interval: after an announced insertion, an authenticated reading wholly past
        // T + S but with an uncertainty over the profile's sample ceiling releases nothing (and is
        // no sample); a qualified reading a second later does.
        let (host, fake, wall, elapsed, _anchor) = rig_with(qprofile(), 1);
        let t = at(2027, 1, 1, 0, 0, 0);
        set_wall(&wall, at(2026, 12, 31, 23, 0, 0));
        *fake.tracking.lock().unwrap() = insert_tracking();
        assert_eq!(host.calibrate_once(), Ok(true));
        let announced = LeapView::Pending { kind: LeapKind::Insert, boundary_ms: t };
        assert_eq!(host.leap_view(), announced);
        // Five seconds after the event chrony reports Normal with 300 ms of root dispersion:
        // U = 312 ms > 248.
        elapsed.run(3_600_000 + 5_000);
        set_wall(&wall, t + 5_000);
        *fake.tracking.lock().unwrap() = TRACKING.replace("0.001500000", "0.300000000");
        assert_eq!(host.source.observe().unwrap().sample.uncertainty_ms, 312);
        let e = host.calibrate_once().unwrap_err();
        assert!(e.contains("SourceUncertainty"), "{e}");
        assert_eq!(host.leap_view(), announced, "an unqualified reading released the event");
        assert!(host.basis().lower_bound_ms().is_none());
        // The same instant with a qualified reading releases it and requalifies.
        *fake.tracking.lock().unwrap() = TRACKING.into();
        elapsed.run(1_000);
        set_wall(&wall, t + 6_000);
        assert_eq!(host.calibrate_once(), Ok(true));
        assert!(matches!(host.leap_view(), LeapView::Clear { .. }));
        assert!(host.basis().lower_bound_ms().is_some());
    }
    #[test]
    fn a_deleted_second_is_handled_with_the_same_zone() {
        let (host, fake, wall, elapsed, _p) = rig_with(qprofile(), 1);
        let t = at(2026, 7, 1, 0, 0, 0); // end of June
        set_wall(&wall, at(2026, 6, 30, 22, 0, 0));
        *fake.tracking.lock().unwrap() = delete_tracking();
        assert_eq!(host.calibrate_once(), Ok(true));
        assert_eq!(
            host.leap_view(),
            LeapView::Pending { kind: LeapKind::Delete, boundary_ms: t }
        );
        // 5 minutes before the end of June the anchor of 22:00 is still valid and a fresh sample
        // is accepted: a deletion steps at T - 1 s, far away.
        elapsed.run(115 * 60_000);
        set_wall(&wall, at(2026, 6, 30, 23, 55, 0));
        assert_eq!(host.calibrate_once(), Ok(true));
        // The clock steps FORWARD at T - S: the holdover must be over before that instant.
        let sample_at = t - LEAP_STEP_MS - 15;
        elapsed.run(sample_at - at(2026, 6, 30, 23, 55, 0));
        set_wall(&wall, sample_at);
        assert_eq!(host.calibrate_once(), Ok(true), "ends 1 ms below the zone start T - S");
        assert_eq!(
            host.clock().status(),
            Status::Unqualified(Unqualified::LeapTransition),
            "the step of a deletion is at the zone start itself"
        );
        // The skipped labels: after the step the reading jumps from T - S - 1 to T, so x ms after
        // the last wall read (at label zone - 15) it shows zone - 15 + x + S once x >= 15. Chrony
        // reports Normal. At x = 1000 the label is T + 985: past the zone, but the event is
        // unresolved until the reading's lowest possible time is one step beyond T.
        *fake.tracking.lock().unwrap() = TRACKING.into();
        elapsed.run(1_000);
        set_wall(&wall, t + 985);
        let e = host.calibrate_once().unwrap_err();
        assert!(e.contains("SourceLeapAmbiguity"), "{e}");
        assert!(matches!(host.leap_view(), LeapView::Pending { .. }));
        elapsed.run(28);
        set_wall(&wall, t + LEAP_STEP_MS + 13); // lowest possible time T + S: resolved
        assert_eq!(host.calibrate_once(), Ok(true));
        assert!(host.basis().lower_bound_ms().is_some());
    }

    #[test]
    fn no_unauthenticated_fallback_after_leap_rejection_or_chrony_failure() {
        let (host, fake, wall, elapsed, anchor) = rig_with(qprofile(), 2);
        assert_eq!(host.calibrate_once(), Ok(true));
        let first = host.basis().lower_bound_ms().unwrap();
        let evidence = {
            let r = stored(&anchor);
            (r.lower_ms, r.upper_ms, r.at)
        };
        // Order C9: the authenticated Normal reading of 2 October clears only up to the earliest
        // possible step at the end of October.
        let view = host.leap_view();
        assert_eq!(view, LeapView::Clear { valid_until_ms: at(2026, 11, 1, 0, 0, 0) - LEAP_STEP_MS });
        // chrony reports a leap but the NTS quorum is gone: no sample, and the view never extends.
        // The announcement is held as a shorten-only hint (Order C11); here the calendar bound
        // already ends at the earliest step of this month end, so there is nothing left to shorten.
        *fake.tracking.lock().unwrap() = insert_tracking();
        *fake.authdata.lock().unwrap() = AUTHDATA.replace("129.6.15.28,NTS", "129.6.15.28,-");
        assert!(host.calibrate_once().is_err());
        assert_eq!(host.leap_view(), view, "an unauthenticated announcement never extends");
        // A Normal but unauthenticated poll cannot clear or extend anything either.
        *fake.tracking.lock().unwrap() = TRACKING.into();
        assert!(host.calibrate_once().is_err());
        assert_eq!(host.leap_view(), view);
        // chronyc down, and a hostile wall clock: wall only ever centres a sample, so it cannot
        // move voting authority beyond elapsed time.
        *fake.tracking.lock().unwrap() = String::new();
        let now = *wall.0.lock().unwrap();
        set_wall(&wall, now + 10 * 86_400_000);
        elapsed.run(5_000);
        assert!(host.calibrate_once().is_err());
        let later = host.basis().lower_bound_ms().unwrap();
        assert!(later > first && later <= first + 5_000, "{first} {later}");
        // No new calibration was stored, and the stored claim is unchanged (the view never moved).
        let r = stored(&anchor);
        assert_eq!((r.lower_ms, r.upper_ms, r.at), evidence, "no new anchor was stored");
        assert_eq!(r.leap.view, view);
    }

    // ------------------------------------------------------------------------------------------
    // Ruling 5: the persistent anchor across restarts.
    // ------------------------------------------------------------------------------------------
    /// 23:30 on 31 Oct 2026, a Normal reading: the clear (end of November) is persisted.
    fn month_end_rig() -> (Arc<HostClock>, Arc<Fake>, Arc<Wall>, Arc<ControlledElapsed>, PathBuf) {
        let (host, fake, wall, elapsed, anchor) = rig_with(qprofile(), 1);
        set_wall(&wall, at(2026, 10, 31, 23, 30, 0));
        assert_eq!(host.calibrate_once(), Ok(true));
        (host, fake, wall, elapsed, anchor)
    }
    #[test]
    fn c9_a_blackout_across_a_month_end_ends_holdover_and_a_restart_resumes_nothing() {
        let (host, fake, _wall, elapsed, anchor) = month_end_rig();
        let october_end = at(2026, 11, 1, 0, 0, 0) - LEAP_STEP_MS;
        // Order C9: the authenticated Normal reading at 23:30 on 31 October clears ONLY up to the
        // earliest possible step at the end of October (no announcement lead time is qualified, so
        // the reading excludes no future month end; the previous policy cleared until the end of
        // November on the unmeasured "24 h + 1 s" assumption).
        assert_eq!(host.leap_view(), LeapView::Clear { valid_until_ms: october_end });
        // chronyc fails: the view is re-pushed (unchanged, never extended) and nothing is rewritten.
        *fake.tracking.lock().unwrap() = String::new();
        assert!(host.calibrate_once().is_err());
        assert_eq!(host.leap_view(), LeapView::Clear { valid_until_ms: october_end });
        assert_eq!(stored(&anchor).sequence, 1);
        // The blackout spans the month end: holdover ends one millisecond before its earliest
        // possible step, not after 24 h.
        elapsed.run(29 * 60_000); // 23:59
        assert!(host.basis().lower_bound_ms().is_some());
        elapsed.run(2 * 60_000); // 00:01 on 1 November
        assert_eq!(host.clock().status(), Status::Unqualified(Unqualified::LeapTransition));
        // A restart inside the same boot resumes nothing (Order C4): the record is evidence only,
        // and its clear is not restored (Order C9).
        drop(host);
        let restarted = restart_at(&fake, &elapsed, &anchor, qprofile(), at(2026, 11, 1, 0, 1, 0));
        let RestoreReport::NotGranted { leap, .. } = restarted.restore_report() else {
            panic!("{:?}", restarted.restore_report())
        };
        assert_eq!(*leap, ClaimDisposition::Discarded(leap_policy::DiscardReason::ClearNotRestored));
        assert_eq!(restarted.leap_view(), LeapView::Unassessed);
        assert!(restarted.basis().lower_bound_ms().is_none());
        // Only a fresh authenticated calibration requalifies it (a November reading clears November).
        *fake.tracking.lock().unwrap() = TRACKING.into();
        assert_eq!(restarted.calibrate_once(), Ok(true));
        assert!(restarted.basis().lower_bound_ms().is_some());
        assert_eq!(
            restarted.leap_view(),
            LeapView::Clear { valid_until_ms: at(2026, 12, 1, 0, 0, 0) - LEAP_STEP_MS }
        );
    }
    #[test]
    fn c1_a_node_that_missed_any_announcement_still_gets_the_cushion_after_a_month_end() {
        // Independent review, MINOR-2: a node that never saw an announcement (a blackout over the
        // month end, or an announcement window between two polls) must not adopt the first
        // authenticated Normal reading just past T. Order C1's cushion applies after EVERY month
        // end: within it nothing is cleared and no sample is admitted; one step after T it is.
        let t = at(2027, 1, 1, 0, 0, 0);
        let (host, fake, wall, elapsed, _anchor) = rig_with(qprofile(), 1);
        *fake.tracking.lock().unwrap() = TRACKING.into();
        set_wall(&wall, t + 500);
        let err = host.calibrate_once().unwrap_err();
        assert!(err.contains("LeapUnassessed"), "{err}");
        assert!(host.basis().lower_bound_ms().is_none());
        assert_eq!(host.leap_view(), LeapView::Unassessed);
        elapsed.run(1_000);
        set_wall(&wall, t + LEAP_STEP_MS + 500);
        assert_eq!(host.calibrate_once(), Ok(true));
        assert!(host.basis().lower_bound_ms().is_some());
        assert_eq!(
            host.leap_view(),
            LeapView::Clear { valid_until_ms: at(2027, 2, 1, 0, 0, 0) - LEAP_STEP_MS }
        );
    }
    #[test]
    fn c7_c11_a_restored_leap_claim_is_at_most_a_shorten_only_hint() {
        let nov_1 = at(2026, 11, 1, 0, 0, 0);
        let restarted_with = |edit: &dyn Fn(&mut PersistedAnchor)| {
            let (host, fake, _w, elapsed, anchor) = month_end_rig();
            drop(host);
            rewrite_record(&anchor, |r| edit(r));
            let r = restart_at(&fake, &elapsed, &anchor, qprofile(), at(2026, 10, 31, 23, 30, 0));
            (r, fake)
        };
        let disposition = |r: &HostClock| match r.restore_report() {
            RestoreReport::NotGranted { leap, .. } => *leap,
            other => panic!("{other:?}"),
        };
        // C7: a claim of another policy version (older or newer) gains no authority at all.
        for policy in [1, leap_policy::POLICY_VERSION + 1] {
            let (r, _) = restarted_with(&|rec| {
                rec.leap = LeapClaim {
                    policy,
                    view: LeapView::Pending { kind: LeapKind::Insert, boundary_ms: nov_1 },
                }
            });
            assert_eq!(
                disposition(&r),
                ClaimDisposition::Discarded(leap_policy::DiscardReason::PolicyVersion)
            );
            assert_eq!(r.leap_view(), LeapView::Unassessed);
        }
        // C9: a stored clear, even one far beyond any evidence, is never restored.
        let (r, _) = restarted_with(&|rec| {
            rec.leap.view = LeapView::Clear { valid_until_ms: at(2027, 3, 1, 0, 0, 0) - LEAP_STEP_MS }
        });
        assert_eq!(
            disposition(&r),
            ClaimDisposition::Discarded(leap_policy::DiscardReason::ClearNotRestored)
        );
        // A value the policy cannot produce: dropped.
        let (r, _) = restarted_with(&|rec| {
            rec.leap.view = LeapView::Pending { kind: LeapKind::Insert, boundary_ms: nov_1 + 1 }
        });
        assert_eq!(disposition(&r), ClaimDisposition::Discarded(leap_policy::DiscardReason::Malformed));
        // C11: a stored ANNOUNCEMENT for this month end becomes a hint. It qualifies nothing and
        // assesses nothing by itself; once a fresh AUTHENTICATED poll reports the insertion again,
        // the hint shortens it to the earliest step (T - S instead of T), never the other way.
        let (r, fake) = restarted_with(&|rec| {
            rec.leap.view = LeapView::Pending { kind: LeapKind::Insert, boundary_ms: nov_1 }
        });
        assert_eq!(disposition(&r), ClaimDisposition::Hinted);
        assert_eq!(r.leap_view(), LeapView::Unassessed);
        assert!(r.basis().lower_bound_ms().is_none());
        *fake.tracking.lock().unwrap() = insert_tracking();
        assert_eq!(r.calibrate_once(), Ok(true));
        assert_eq!(r.leap_view(), LeapView::Pending { kind: LeapKind::Delete, boundary_ms: nov_1 });
        // The same poll without the stored hint keeps the authenticated insertion's step T.
        let (plain, fake) = restarted_with(&|rec| rec.leap.view = LeapView::Unassessed);
        assert_eq!(disposition(&plain), ClaimDisposition::NoClaim);
        *fake.tracking.lock().unwrap() = insert_tracking();
        assert_eq!(plain.calibrate_once(), Ok(true));
        assert_eq!(plain.leap_view(), LeapView::Pending { kind: LeapKind::Insert, boundary_ms: nov_1 });
    }
    #[test]
    fn live_source_refusals_preserve_coherent_shorten_only_leap_information() {
        for fault in 0..3 {
            let (host, fake, wall, elapsed, anchor) = month_end_rig();
            *fake.tracking.lock().unwrap() = insert_tracking();
            assert_eq!(host.calibrate_once(), Ok(true));
            let old_interval = host.clock().anchor_interval_ms();
            let old_sequence = stored(&anchor).sequence;
            elapsed.run(5 * 60_000);
            set_wall(&wall, at(2026, 10, 31, 23, 35, 0));
            *fake.tracking.lock().unwrap() = delete_tracking();
            match fault {
                0 => *fake.sources.lock().unwrap() = SOURCES.replace(",12,", ",129,"),
                1 => *fake.authdata.lock().unwrap() = "truncated,NTS".into(),
                _ => *fake.sources.lock().unwrap() = SOURCES.replace(",*,", ",-,"),
            }
            assert!(host.calibrate_once().unwrap_err().contains("NTS"));
            let pending = LeapView::Pending { kind: LeapKind::Delete,
                boundary_ms: at(2026, 11, 1, 0, 0, 0) };
            assert_eq!(host.leap_view(), pending);
            assert_eq!(stored(&anchor).leap.view, pending);
            assert!(stored(&anchor).sequence > old_sequence);
            assert_eq!(host.clock().anchor_interval_ms(), old_interval,
                "source refusal must never replace the calibrated anchor");
        }
    }
    #[test]
    fn new_leap_information_reaches_the_stored_record_and_a_restart_takes_it_as_a_hint_only() {
        let (host, fake, wall, elapsed, anchor) = month_end_rig();
        let nov_1 = at(2026, 11, 1, 0, 0, 0);
        assert!(matches!(stored(&anchor).leap.view, LeapView::Clear { .. }));
        // Five minutes later chrony announces an insertion for the end of October. The sample is far
        // from the zone, so it is accepted; the announcement replaces the clear and the STORED
        // record carries it: two writes in this poll, the announcement first (old anchor, new
        // claim), then the new calibration with the same claim.
        elapsed.run(5 * 60_000);
        set_wall(&wall, at(2026, 10, 31, 23, 35, 0));
        *fake.tracking.lock().unwrap() = insert_tracking();
        assert_eq!(host.calibrate_once(), Ok(true));
        let pending = LeapView::Pending { kind: LeapKind::Insert, boundary_ms: nov_1 };
        assert_eq!(host.leap_view(), pending);
        assert_eq!(stored(&anchor).sequence, 3);
        assert_eq!(stored(&anchor).leap.view, pending);
        // A later restart (Order C4) is unqualified and takes the stored announcement as an
        // unauthenticated hint only (Order C11): it assesses nothing by itself ...
        drop(host);
        *fake.tracking.lock().unwrap() = String::new();
        let r3 = restart_at(&fake, &elapsed, &anchor, qprofile(), at(2026, 10, 31, 23, 36, 0));
        assert!(matches!(
            r3.restore_report(),
            RestoreReport::NotGranted { leap: ClaimDisposition::Hinted, .. }
        ));
        assert_eq!(r3.leap_view(), LeapView::Unassessed);
        assert!(r3.calibrate_once().is_err());
        assert!(r3.basis().lower_bound_ms().is_none());
        // ... and once chrony is back and AUTHENTICATED, the requalified clock ends at the earliest
        // step of that month end (the hint shortens the authenticated insertion by one step).
        drop(r3);
        elapsed.run(60_000);
        *fake.tracking.lock().unwrap() = insert_tracking();
        let r4 = restart_at(&fake, &elapsed, &anchor, qprofile(), at(2026, 10, 31, 23, 37, 0));
        assert_eq!(r4.calibrate_once(), Ok(true));
        assert_eq!(r4.leap_view(), LeapView::Pending { kind: LeapKind::Delete, boundary_ms: nov_1 });
        elapsed.run(22 * 60_000); // 23:59
        assert!(r4.basis().lower_bound_ms().is_some());
        elapsed.run(2 * 60_000); // 00:01: past the earliest step of the October month end
        assert_eq!(r4.clock().status(), Status::Unqualified(Unqualified::LeapTransition));
    }
    #[test]
    fn an_anchor_that_new_leap_information_ended_is_invalidated_on_disk_and_a_rollback_is_refused() {
        let (host, fake, wall, elapsed, anchor) = rig_with(qprofile(), 1);
        let t = at(2027, 1, 1, 0, 0, 0);
        set_wall(&wall, at(2026, 12, 31, 22, 50, 0));
        assert_eq!(host.calibrate_once(), Ok(true));
        assert!(matches!(stored(&anchor).leap.view, LeapView::Clear { .. }));
        // The announcement arrives: it is written to the record immediately.
        elapsed.run(5 * 60_000);
        set_wall(&wall, at(2026, 12, 31, 22, 55, 0));
        *fake.tracking.lock().unwrap() = insert_tracking();
        assert_eq!(host.calibrate_once(), Ok(true));
        let announced = std::fs::read(&anchor).unwrap();
        assert_eq!(
            stored(&anchor).leap.view,
            LeapView::Pending { kind: LeapKind::Insert, boundary_ms: t }
        );
        // Blackout through the event: the live anchor ends at the step ...
        *fake.tracking.lock().unwrap() = String::new();
        elapsed.run(70 * 60_000);
        assert!(host.basis().lower_bound_ms().is_none());
        // ... and the next poll INVALIDATES the stored record (lineage and diagnostics: since
        // Order C4 no record could have resumed qualification anyway).
        assert!(host.calibrate_once().is_err());
        assert!(!anchor.exists(), "the dead anchor's record is removed");
        drop(host);
        let late = restart(&fake, &elapsed, &anchor, qprofile());
        assert_eq!(late.restore_report(), &RestoreReport::Cold);
        assert!(late.basis().lower_bound_ms().is_none());
        drop(late);
        // Putting the old record back (same boot) is a rollback and is refused outright: it is not
        // even evidence.
        std::fs::write(&anchor, &announced).unwrap();
        let again = restart(&fake, &elapsed, &anchor, qprofile());
        assert!(matches!(
            again.restore_report(),
            RestoreReport::Refused(Refusal::Lineage(AnchorError::Rollback))
        ));
        assert!(again.basis().lower_bound_ms().is_none());
        assert_eq!(again.vote_clock().reading(), ClockReading::Unqualified);
    }
    #[test]
    fn restarting_the_process_in_a_loop_never_qualifies_and_never_rewrites_the_record() {
        let (control, fake, _w, elapsed, anchor) = rig_with(qprofile(), 1);
        assert_eq!(control.calibrate_once(), Ok(true));
        let first = std::fs::read(&anchor).unwrap();
        // An engine that never stops, holding the very same calibration (the same sample at the
        // same elapsed reading), for comparison. In memory only: it never touches the files.
        let uninterrupted = HoldoverClock::new(qprofile(), elapsed.clone()).unwrap();
        assert!(uninterrupted.set_leap_view(LeapView::Clear { valid_until_ms: u64::MAX }));
        let sample = control.source.observe().unwrap().sample;
        assert_eq!(uninterrupted.calibrate(&[sample]), Ok(true));
        assert_eq!(uninterrupted.anchor_interval_ms(), control.clock().anchor_interval_ms());
        drop(control);
        // Blackout: no source at all. Restart 50 times across 24 h; each restarted process polls
        // the dead source too.
        *fake.tracking.lock().unwrap() = String::new();
        let step = 86_400_000 / 50;
        for i in 1..=50u64 {
            elapsed.run(step);
            let restarted = restart(&fake, &elapsed, &anchor, qprofile());
            let RestoreReport::NotGranted { evidence, .. } = restarted.restore_report().clone() else {
                panic!("restart {i}: {:?}", restarted.restore_report())
            };
            // Order C4: unqualified whatever the record says. Fresh voting after a restart during
            // a total external-time blackout is unavailable; the record is evidence only, and that
            // evidence is exactly the uninterrupted engine's status.
            assert!(restarted.basis().lower_bound_ms().is_none(), "restart {i}");
            assert_eq!(evidence.sequence, 1);
            assert_eq!(
                Status::Qualified {
                    lower_ms: evidence.would_be_lower_ms,
                    half_width_ms: evidence.would_be_half_width_ms,
                    holdover_remaining_ms: evidence.would_be_remaining_ms,
                },
                uninterrupted.status(),
                "restart {i}"
            );
            assert!(restarted.calibrate_once().is_err());
            assert!(restarted.basis().lower_bound_ms().is_none());
            assert_eq!(std::fs::read(&anchor).unwrap(), first, "nothing re-baselines the record ({i})");
        }
        // Exactly 24 h after the ORIGINAL calibration the budget is spent; one ms later the record
        // is not even evidence.
        elapsed.run(1);
        assert_eq!(
            uninterrupted.status(),
            Status::Unqualified(Unqualified::HoldoverExpired)
        );
        let late = restart(&fake, &elapsed, &anchor, qprofile());
        assert_eq!(
            late.restore_report(),
            &RestoreReport::Refused(Refusal::Verification(AnchorError::Unqualified(
                Unqualified::HoldoverExpired
            )))
        );
        assert!(late.basis().lower_bound_ms().is_none());
    }
    #[test]
    fn reboot_power_loss_suspend_and_rollback_stay_unqualified_until_an_authenticated_recalibration() {
        let wall0 = 1_790_899_300_000u64;
        // Reboot or power loss: the elapsed time is unproven; the record is not even evidence.
        let (host, fake, _w, elapsed, anchor) = rig_with(qprofile(), 1);
        host.calibrate_once().unwrap();
        drop(host);
        elapsed.reboot(12);
        let r = restart_at(&fake, &elapsed, &anchor, qprofile(), wall0 + 3_600_000);
        assert_eq!(
            r.restore_report(),
            &RestoreReport::Refused(Refusal::Verification(AnchorError::Unqualified(
                Unqualified::BootChanged
            )))
        );
        assert_eq!(r.clock().status(), Status::Unqualified(Unqualified::NeverCalibrated));
        // No unauthenticated fallback: with chrony down the node stays unqualified however the
        // wall clock reads.
        let saved = fake.tracking.lock().unwrap().clone();
        *fake.tracking.lock().unwrap() = String::new();
        assert!(r.calibrate_once().is_err());
        assert!(r.basis().lower_bound_ms().is_none());
        // An authenticated recalibration qualifies it again.
        *fake.tracking.lock().unwrap() = saved;
        assert_eq!(r.calibrate_once(), Ok(true));
        assert!(r.basis().lower_bound_ms().is_some());
        // Suspend: boottime outgrew monotonic. The live node drops its anchor and requalifies only
        // through a new calibration ...
        let (host, _fake, wall, elapsed, _anchor) = rig_with(qprofile(), 1);
        host.calibrate_once().unwrap();
        elapsed.suspend(10_000);
        assert_eq!(host.clock().status(), Status::Unqualified(Unqualified::SuspendDetected));
        set_wall(&wall, wall0 + 10_000);
        assert_eq!(host.calibrate_once(), Ok(true));
        assert!(host.basis().lower_bound_ms().is_some());
        // ... and a node restarted across a suspend refuses the record.
        let (host, fake, _w, elapsed, anchor) = rig_with(qprofile(), 1);
        host.calibrate_once().unwrap();
        drop(host);
        elapsed.suspend(10_000);
        let r = restart_at(&fake, &elapsed, &anchor, qprofile(), wall0 + 10_000);
        assert_eq!(
            r.restore_report(),
            &RestoreReport::Refused(Refusal::Verification(AnchorError::Unqualified(
                Unqualified::SuspendDetected
            )))
        );
        assert!(r.basis().lower_bound_ms().is_none());
        // Rollback inside a boot: an older valid record is put back after a newer one was written.
        let (host, fake, wall, elapsed, anchor) = rig_with(qprofile(), 1);
        host.calibrate_once().unwrap();
        let old = std::fs::read(&anchor).unwrap();
        elapsed.run(1_000);
        set_wall(&wall, wall0 + 1_000);
        host.calibrate_once().unwrap();
        let newest = stored(&anchor);
        assert_eq!(newest.sequence, 2);
        drop(host);
        std::fs::write(&anchor, &old).unwrap();
        let r = restart_at(&fake, &elapsed, &anchor, qprofile(), wall0 + 1_000);
        assert_eq!(
            r.restore_report(),
            &RestoreReport::Refused(Refusal::Lineage(AnchorError::Rollback))
        );
        assert!(r.basis().lower_bound_ms().is_none());
        // The high-water mark of the lineage is still honoured: a calibration BELOW what the
        // previous process reported is a regression, not a way back in.
        assert!(r.clock().persisted_high_water() >= newest.high_water_ms);
        drop(r);
        let behind = restart_at(&fake, &elapsed, &anchor, qprofile(), wall0 - 5_000);
        assert!(behind.calibrate_once().unwrap_err().contains("Regression"));
        assert!(behind.basis().lower_bound_ms().is_none());
    }
    #[test]
    fn old_unknown_corrupt_and_foreign_anchors_never_qualify_the_host() {
        let (host, fake, _w, elapsed, anchor) = rig_with(qprofile(), 1);
        host.calibrate_once().unwrap();
        drop(host);
        let good = std::fs::read(&anchor).unwrap();
        let rec = stored(&anchor);
        let legacy = anchor_store::legacy_v1_bytes(qprofile().id(), rec.lower_ms, rec.upper_ms, rec.high_water_ms);
        let mut unknown = good.clone();
        unknown[7] = b'3';
        let mut flipped = good.clone();
        flipped[150] ^= 1;
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("legacy v1", legacy),
            ("unknown version", unknown),
            ("bit flip", flipped),
            ("truncated", good[..good.len() - 1].to_vec()),
            ("oversized", [good.clone(), vec![0; 100]].concat()),
            ("empty", Vec::new()),
        ];
        for (name, bytes) in cases {
            std::fs::write(&anchor, &bytes).unwrap();
            let r = restart(&fake, &elapsed, &anchor, qprofile());
            assert!(matches!(r.restore_report(), RestoreReport::Refused(_)), "{name}");
            assert!(r.basis().lower_bound_ms().is_none(), "{name} must not qualify");
            assert_eq!(r.vote_clock().reading(), ClockReading::Unqualified, "{name}");
            assert_eq!(r.clock().status(), Status::Unqualified(Unqualified::NeverCalibrated));
        }
        // A legacy file is read for the log line only (Order C6: nothing is imported or ratcheted).
        std::fs::write(&anchor, anchor_store::legacy_v1_bytes(qprofile().id(), 1, 2, u64::MAX / 2)).unwrap();
        let r = restart(&fake, &elapsed, &anchor, qprofile());
        let line = r.restore_report().describe();
        assert!(line.contains("legacy v1") && line.contains("never adopted"), "{line}");
        assert!(r.clock().persisted_high_water() < u64::MAX / 2, "the v1 high-water mark is not ratcheted");
        drop(r);
        // Wrong profile: another profile takes nothing from a record written under this one.
        std::fs::write(&anchor, &good).unwrap();
        let mut other = qprofile();
        other.drift_bound_ppb = 8000;
        let r = restart(&fake, &elapsed, &anchor, other.clone());
        assert_eq!(
            r.restore_report(),
            &RestoreReport::Refused(Refusal::Verification(AnchorError::Profile))
        );
        assert!(r.basis().lower_bound_ms().is_none());
        drop(r);
        // It requalifies only through its own authenticated calibration and then owns the lineage:
        // the first profile cannot even read it as evidence.
        let r = restart_at(&fake, &elapsed, &anchor, other, 1_790_899_300_000 + 1_000);
        elapsed.run(1_000);
        assert_eq!(r.calibrate_once(), Ok(true));
        drop(r);
        let back = restart(&fake, &elapsed, &anchor, qprofile());
        assert_eq!(
            back.restore_report(),
            &RestoreReport::Refused(Refusal::Verification(AnchorError::Profile))
        );
    }
    #[test]
    fn a_failed_write_never_disturbs_the_clock_and_is_retried_and_persist_forces_a_new_record() {
        // Every write fails (the mark's temp name is blocked by a directory): the clock does not
        // care, and the next poll after the obstacle is gone writes the record.
        let (host, fake, wall, elapsed, anchor) = rig_with(qprofile(), 1);
        let blocked = PathBuf::from(format!("{}.tmp", seq_path(&anchor).display()));
        std::fs::create_dir(&blocked).unwrap();
        let e = host.calibrate_once().unwrap_err();
        assert!(e.contains("anchor"), "{e}");
        assert!(host.basis().lower_bound_ms().is_some(), "the clock is qualified in memory");
        assert_eq!(host.restore_report(), &RestoreReport::Cold);
        assert!(!anchor.exists());
        std::fs::remove_dir(&blocked).unwrap();
        elapsed.run(1_000);
        let now = *wall.0.lock().unwrap();
        set_wall(&wall, now + 1_000);
        assert_eq!(host.calibrate_once(), Ok(true), "retried and written");
        let first = stored(&anchor);
        assert!(first.sequence >= 2, "the spent number of the failed attempt is not reused");
        // `persist` forces a new record even though nothing changed; the evidence is identical.
        host.persist().unwrap();
        let second = stored(&anchor);
        assert_eq!(second.sequence, first.sequence + 1);
        assert!(first.same_evidence(&second));
        // A restart over the repaired store finds the record as evidence; it resumes nothing
        // (Order C4).
        drop(host);
        let r = restart(&fake, &elapsed, &anchor, qprofile());
        assert!(matches!(r.restore_report(), RestoreReport::NotGranted { .. }));
        assert!(r.basis().lower_bound_ms().is_none());
    }
    /// An elapsed source that "crashes the process" (panics) at the N-th read after being armed.
    struct CrashingElapsed {
        inner: Arc<ControlledElapsed>,
        reads: std::sync::atomic::AtomicU32,
        crash_at: std::sync::atomic::AtomicU32,
    }
    impl ElapsedSource for CrashingElapsed {
        fn read(&self) -> Option<Elapsed> {
            use std::sync::atomic::Ordering::SeqCst;
            let n = self.reads.fetch_add(1, SeqCst) + 1;
            if n == self.crash_at.load(SeqCst) {
                panic!("simulated crash");
            }
            self.inner.read()
        }
    }
    #[test]
    fn new_leap_information_is_stored_before_the_sample_is_processed() {
        use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
        let (_h, fake, wall, controlled, anchor) = rig_with(qprofile(), 1);
        let crashing = Arc::new(CrashingElapsed {
            inner: controlled.clone(),
            reads: AtomicU32::new(0),
            crash_at: AtomicU32::new(0),
        });
        let missing_dir = anchor.parent().unwrap().join("crash");
        std::fs::create_dir_all(&missing_dir).unwrap();
        let file = missing_dir.join("clock.anchor");
        let host = HostClock::with_sources(
            qprofile(),
            ChronySource {
                client: fake.clone(),
                wall: wall.clone(),
                elapsed: crashing.clone(),
                min_nts_selected: 1,
                nts_sources: HOSTS.iter().map(|h| (*h).to_owned()).collect(),
            },
            state(&file),
        )
        .unwrap();
        set_wall(&wall, at(2026, 12, 31, 22, 50, 0));
        assert_eq!(host.calibrate_once(), Ok(true));
        assert!(matches!(stored(&file).leap.view, LeapView::Clear { .. }));
        // Five minutes later chrony announces an insertion. The process "crashes" at the engine's
        // first read while it processes the new sample: observe() reads the elapsed source twice,
        // pushing the view once, the early store sync once, and calibrate() is the fifth read.
        controlled.run(5 * 60_000);
        set_wall(&wall, at(2026, 12, 31, 22, 55, 0));
        *fake.tracking.lock().unwrap() = insert_tracking();
        // The offset counts the elapsed reads of ONE announcement poll up to the engine's first read:
        // observe() 2, set_leap_view 1, the early persisted() 1, then calibrate(). If a read is added
        // BEFORE the early sync the crash happens earlier and the assertions below fail loudly
        // (the record would still carry the old claim); that is the intended coupling.
        crashing.crash_at.store(crashing.reads.load(SeqCst) + 5, SeqCst);
        let crashed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| host.calibrate_once()));
        assert!(crashed.is_err(), "the simulated crash happened");
        // The announcement is already on disk: a restart cannot resurrect the old clear.
        assert_eq!(
            stored(&file).leap.view,
            LeapView::Pending { kind: LeapKind::Insert, boundary_ms: at(2027, 1, 1, 0, 0, 0) }
        );
        // A restart (Order C4) resumes nothing and takes the stored announcement as a hint only.
        drop(host);
        let r = restart(&fake, &controlled, &file, qprofile());
        assert!(matches!(
            r.restore_report(),
            RestoreReport::NotGranted { leap: ClaimDisposition::Hinted, .. }
        ));
        assert!(r.basis().lower_bound_ms().is_none());
    }
    /// An elapsed source that can be switched off and on (a transient /proc read failure).
    struct ToggleElapsed {
        inner: Arc<ControlledElapsed>,
        down: std::sync::atomic::AtomicBool,
    }
    impl ElapsedSource for ToggleElapsed {
        fn read(&self) -> Option<Elapsed> {
            if self.down.load(std::sync::atomic::Ordering::SeqCst) {
                None
            } else {
                self.inner.read()
            }
        }
    }
    fn seq_path(anchor: &PathBuf) -> PathBuf {
        PathBuf::from(format!("{}.seq", anchor.display()))
    }
    #[test]
    fn a_failed_store_update_removes_the_stale_record_is_reported_and_the_clock_keeps_running() {
        let (host, fake, wall, elapsed, anchor) = month_end_rig();
        assert!(matches!(stored(&anchor).leap.view, LeapView::Clear { .. }));
        // Every store update now fails (the mark's temp name is blocked).
        let blocked = PathBuf::from(format!("{}.tmp", seq_path(&anchor).display()));
        std::fs::create_dir(&blocked).unwrap();
        // chrony announces an insertion; the view changes but the new claim cannot be written.
        *fake.tracking.lock().unwrap() = insert_tracking();
        elapsed.run(60_000);
        set_wall(&wall, at(2026, 10, 31, 23, 31, 0));
        let e = host.calibrate_once().unwrap_err();
        assert!(e.contains("anchor"), "the poll reports the store failure: {e}");
        // The record that still carried the OLD Clear claim is gone (lineage and diagnostics; since
        // Order C4 it could not have resumed qualification anyway), and no second instance can even
        // open the store while this one runs (Order C12).
        assert!(!anchor.exists());
        assert!(matches!(
            ClockStateDir::open_unchecked_for_test(&anchor),
            Err(state_dir::StorageError::Locked(_))
        ));
        // The live clock is unaffected: it took the sample and holds the announcement in memory.
        assert!(host.basis().lower_bound_ms().is_some());
        assert!(matches!(host.leap_view(), LeapView::Pending { .. }));
        // Once writes work again the next poll writes the current record, announcement included.
        std::fs::remove_dir(&blocked).unwrap();
        elapsed.run(1_000);
        set_wall(&wall, at(2026, 10, 31, 23, 31, 1));
        assert_eq!(host.calibrate_once(), Ok(true));
        assert!(matches!(stored(&anchor).leap.view, LeapView::Pending { .. }));
        // A death of the anchor while the store cannot be written: the file is removed anyway.
        std::fs::create_dir(&blocked).unwrap();
        *fake.tracking.lock().unwrap() = String::new();
        elapsed.run(40 * 60_000);
        assert!(host.basis().lower_bound_ms().is_none(), "ended at the announced event");
        assert!(host.calibrate_once().unwrap_err().contains("anchor"));
        assert!(!anchor.exists());
    }
    #[test]
    fn a_transient_elapsed_source_failure_does_not_invalidate_the_stored_record() {
        use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
        let (_h, fake, wall, controlled, anchor) = rig_with(qprofile(), 1);
        let toggle = Arc::new(ToggleElapsed {
            inner: controlled.clone(),
            down: AtomicBool::new(false),
        });
        let file = anchor.parent().unwrap().join("toggle.anchor");
        let host = HostClock::with_sources(
            qprofile(),
            ChronySource {
                client: fake.clone(),
                wall: wall.clone(),
                elapsed: toggle.clone(),
                min_nts_selected: 1,
                nts_sources: HOSTS.iter().map(|h| (*h).to_owned()).collect(),
            },
            state(&file),
        )
        .unwrap();
        assert_eq!(host.calibrate_once(), Ok(true));
        let before = std::fs::read(&file).unwrap();
        toggle.down.store(true, SeqCst);
        let e = host.calibrate_once().unwrap_err();
        assert!(e.contains("elapsed"), "{e}");
        assert_eq!(std::fs::read(&file).unwrap(), before, "the live anchor's record is untouched");
        toggle.down.store(false, SeqCst);
        drop(host);
        let r = restart(&fake, &controlled, &file, qprofile());
        assert!(
            matches!(r.restore_report(), RestoreReport::NotGranted { .. }),
            "the record is intact evidence (and, Order C4, no more)"
        );
    }
    #[test]
    fn the_durable_high_water_follows_a_blackout_so_a_reboot_cannot_be_walked_backwards() {
        let wall0 = 1_790_899_300_000u64;
        let (host, fake, _w, elapsed, anchor) = rig_with(qprofile(), 1);
        host.calibrate_once().unwrap();
        let first = stored(&anchor);
        // Ten minutes of blackout: every failing poll refreshes the durable mark (same lineage entry).
        *fake.tracking.lock().unwrap() = String::new();
        elapsed.run(600_000);
        assert!(host.calibrate_once().is_err());
        let reported = host.clock().persisted_high_water();
        assert!(reported > first.high_water_ms + 500_000, "{reported} {}", first.high_water_ms);
        let mark = LineageMark::decode(&std::fs::read(seq_path(&anchor)).unwrap()).unwrap();
        assert_eq!((mark.sequence, mark.high_water_ms), (first.sequence, reported));
        assert_eq!(stored(&anchor).sequence, first.sequence, "the record itself was not rewritten");
        // Power loss. The record is refused (new boot) but the ratchet is honoured: an authenticated
        // sample that goes BACK in time (5 minutes after the calibration, 5 minutes behind what was
        // already reported) is a Regression, not a way back in.
        drop(host);
        elapsed.reboot(12);
        *fake.tracking.lock().unwrap() = TRACKING.into();
        let behind = restart_at(&fake, &elapsed, &anchor, qprofile(), wall0 + 300_000);
        assert!(behind.clock().persisted_high_water() >= reported);
        assert!(behind.calibrate_once().unwrap_err().contains("Regression"));
        assert!(behind.basis().lower_bound_ms().is_none());
        drop(behind);
        // A sample past what was reported is accepted.
        let late = restart_at(&fake, &elapsed, &anchor, qprofile(), wall0 + 700_000);
        assert_eq!(late.calibrate_once(), Ok(true));
    }
    #[test]
    fn c11_a_restored_announcement_far_or_near_is_only_a_hint_released_after_the_event_by_c1() {
        let nov_1 = at(2026, 11, 1, 0, 0, 0);
        let restarted_with = |boundary_ms: u64, wall_ms: u64| {
            let (host, fake, _w, elapsed, anchor) = month_end_rig();
            drop(host);
            rewrite_record(&anchor, |r| {
                r.leap.view = LeapView::Pending { kind: LeapKind::Insert, boundary_ms }
            });
            let wall = Arc::new(Wall(Mutex::new(wall_ms)));
            let r = HostClock::with_sources(
                qprofile(),
                ChronySource {
                    client: fake.clone(),
                    wall: wall.clone(),
                    elapsed: elapsed.clone(),
                    min_nts_selected: 1,
                    nts_sources: HOSTS.iter().map(|h| (*h).to_owned()).collect(),
                },
                state(&anchor),
            )
            .unwrap();
            assert!(matches!(
                r.restore_report(),
                RestoreReport::NotGranted { leap: ClaimDisposition::Hinted, .. }
            ));
            (r, wall, elapsed)
        };
        // A forged-but-consistent record naming an event in 2030: a hint that shortens nothing
        // before its month, so the calendar bound alone ends holdover at the October month end.
        let (r, _wall, elapsed) = restarted_with(at(2030, 1, 1, 0, 0, 0), at(2026, 10, 31, 23, 30, 0));
        assert_eq!(r.calibrate_once(), Ok(true));
        assert_eq!(r.leap_view(), LeapView::Clear { valid_until_ms: nov_1 - LEAP_STEP_MS });
        elapsed.run(29 * 60_000);
        assert!(r.basis().lower_bound_ms().is_some());
        elapsed.run(2 * 60_000);
        assert_eq!(
            r.clock().status(),
            Status::Unqualified(Unqualified::LeapTransition),
            "the calendar bound still ends holdover at the month end"
        );
        // A stored announcement for THIS month end: after the event, the hint is released only by a
        // QUALIFIED authenticated reading whose lowest possible time is one step past T (Order C1);
        // one millisecond short of that, the sample is refused as lying past an unresolved event.
        let (r, wall, elapsed) = restarted_with(nov_1, at(2026, 10, 31, 23, 30, 0));
        assert_eq!(r.calibrate_once(), Ok(true));
        elapsed.run(30 * 60_000 + 2_012);
        assert_eq!(r.clock().status(), Status::Unqualified(Unqualified::LeapTransition));
        set_wall(&wall, nov_1 + 1_012);
        let e = r.calibrate_once().unwrap_err();
        assert!(e.contains("SourceLeapAmbiguity"), "{e}");
        elapsed.run(1);
        set_wall(&wall, nov_1 + 1_013);
        assert_eq!(r.calibrate_once(), Ok(true), "released by the qualified authenticated reading");
        assert_eq!(r.leap_view(), LeapView::Clear { valid_until_ms: at(2026, 12, 1, 0, 0, 0) - LEAP_STEP_MS });
        assert!(r.basis().lower_bound_ms().is_some());
    }
    /// An elapsed source that fails exactly the N-th read after being armed (one transient /proc
    /// read failure); every other read is the controlled source.
    struct FailNth {
        inner: Arc<ControlledElapsed>,
        reads: std::sync::atomic::AtomicU32,
        fail_at: std::sync::atomic::AtomicU32,
    }
    impl ElapsedSource for FailNth {
        fn read(&self) -> Option<Elapsed> {
            use std::sync::atomic::Ordering::SeqCst;
            let n = self.reads.fetch_add(1, SeqCst) + 1;
            if n == self.fail_at.load(SeqCst) {
                None
            } else {
                self.inner.read()
            }
        }
    }
    #[test]
    fn review_r2_a_view_that_could_not_be_installed_stops_the_poll_before_any_calibration() {
        // Reviewer R2, reproduced before the fix: cold start, chrony announces an insertion, the
        // wall reading lies INSIDE the zone [T - S, T), and the one elapsed read inside the FIRST
        // view push fails, so the announcement is not installed. `calibrate` then ran with no guard,
        // adopted the zone sample and stored it, and a restart resumed it qualified.
        use std::sync::atomic::{AtomicU32, Ordering::SeqCst};
        let t = at(2027, 1, 1, 0, 0, 0);
        // Control: the same poll without the failure is refused as ambiguous.
        let (control, cfake, cwall, ..) = rig_with(qprofile(), 1);
        *cfake.tracking.lock().unwrap() = insert_tracking();
        set_wall(&cwall, t - 500);
        assert!(control.calibrate_once().unwrap_err().contains("SourceLeapAmbiguity"));
        let (_rig, fake, wall, controlled, anchor) = rig_with(qprofile(), 1);
        *fake.tracking.lock().unwrap() = insert_tracking();
        set_wall(&wall, t - 500);
        let src = Arc::new(FailNth {
            inner: controlled.clone(),
            reads: AtomicU32::new(0),
            fail_at: AtomicU32::new(0),
        });
        let file = anchor.parent().unwrap().join("r2.anchor");
        let host = HostClock::with_sources(
            qprofile(),
            ChronySource {
                client: fake.clone(),
                wall: wall.clone(),
                elapsed: src.clone(),
                min_nts_selected: 1,
                nts_sources: HOSTS.iter().map(|h| (*h).to_owned()).collect(),
            },
            state(&file),
        )
        .unwrap();
        // observe() reads the elapsed source twice; the third read is the one inside the first push.
        src.fail_at.store(src.reads.load(SeqCst) + 3, SeqCst);
        let e = host.calibrate_once().unwrap_err();
        assert!(e.contains("leap view not installed"), "{e}");
        assert!(!e.contains("calibration rejected"), "no sample was offered at all: {e}");
        assert_eq!(host.leap_view(), LeapView::Unassessed);
        assert_eq!((host.clock().anchor_interval_ms(), host.clock().fault_count()), (None, 0));
        assert!(!file.exists(), "nothing was stored");
        // The next poll installs the announcement and refuses the zone sample as ambiguous.
        let e = host.calibrate_once().unwrap_err();
        assert!(e.contains("SourceLeapAmbiguity"), "{e}");
        assert_eq!(host.leap_view(), LeapView::Pending { kind: LeapKind::Insert, boundary_ms: t });
        assert!(host.basis().lower_bound_ms().is_none());
        // Nothing was stored by either poll: a restart (after this process is gone) is cold.
        drop(host);
        let r = restart(&fake, &controlled, &file, qprofile());
        assert_eq!(r.restore_report(), &RestoreReport::Cold);
        assert!(r.basis().lower_bound_ms().is_none());
    }
    #[test]
    fn a_stored_anchor_inside_an_announced_zone_resumes_nothing_on_restart() {
        // The record review R2 left behind before its fix: an anchor adopted INSIDE the zone of an
        // insertion at T, stored with the announcement as its claim and a current lineage mark.
        // Before Order C4 the zone predicate had to drop it after the restart; now nothing is
        // installed from any record, so the restarted node is unqualified before and after its
        // claim (a hint) is applied, and only a fresh authenticated sample outside the zone counts.
        let t = at(2027, 1, 1, 0, 0, 0);
        let (rig_host, fake, _w, elapsed, anchor) = rig_with(qprofile(), 1);
        drop(rig_host);
        let writer = HoldoverClock::new(qprofile(), elapsed.clone()).unwrap();
        writer.set_leap_view(LeapView::Clear { valid_until_ms: u64::MAX });
        let sample = SourceSample {
            source: "chrony-nts".into(),
            authenticated: true,
            utc_ms: t - 500,
            uncertainty_ms: 13,
            at: elapsed.now(),
        };
        assert_eq!(writer.calibrate(&[sample]), Ok(true));
        let mut record = writer.persisted(1, leap_policy::POLICY_VERSION).unwrap();
        record.leap.view = LeapView::Pending { kind: LeapKind::Insert, boundary_ms: t };
        // Stored the way the store writes (mark first, then the record): the lineage is current.
        let (mut store, _) = AnchorStore::open(state(&anchor));
        store.commit(&record).unwrap();
        drop(store);
        elapsed.run(100);
        let r = restart_at(&fake, &elapsed, &anchor, qprofile(), t - 400);
        assert!(matches!(
            r.restore_report(),
            RestoreReport::NotGranted { leap: ClaimDisposition::Hinted, .. }
        ));
        assert_eq!(r.leap_view(), LeapView::Unassessed);
        assert!(r.basis().lower_bound_ms().is_none());
        // The authenticated poll inside the zone is refused (the hint and the announcement agree).
        *fake.tracking.lock().unwrap() = insert_tracking();
        let e = r.calibrate_once().unwrap_err();
        assert!(e.contains("SourceLeapAmbiguity"), "{e}");
        assert!(r.basis().lower_bound_ms().is_none());
        assert_eq!(r.clock().anchor_interval_ms(), None);
    }
    #[test]
    fn review_r3_an_unauthenticated_announcement_never_extends_the_horizon() {
        // Reviewer R3, reproduced before its fix: an anchor under the bound Clear{T - S} (the
        // earliest possible step at the month end); an UNAUTHENTICATED poll reporting an insertion
        // turned it into Pending{Insert, T}, whose horizon T is one step LATER. Since Order C11 such
        // an announcement is a shorten-only hint: the anchor still ends at T - S, not at T.
        let t = at(2027, 1, 1, 0, 0, 0);
        // Two NTS-authenticated selected sources in the rig and two required: authenticated until
        // one association is downgraded below.
        let (b, fake, wall, elapsed, _anchor) = rig_with(qprofile(), 2);
        set_wall(&wall, t - 10 * 3_600_000);
        assert_eq!(b.calibrate_once(), Ok(true));
        let calendar = LeapView::Clear { valid_until_ms: t - LEAP_STEP_MS };
        assert_eq!(b.leap_view(), calendar);
        // A control process with no unauthenticated announcement at all.
        let (control, _cf, cwall, celapsed, _ca) = rig_with(qprofile(), 2);
        set_wall(&cwall, t - 10 * 3_600_000);
        assert_eq!(control.calibrate_once(), Ok(true));
        *fake.authdata.lock().unwrap() = AUTHDATA.replace("129.6.15.28,NTS", "129.6.15.28,-");
        *fake.tracking.lock().unwrap() = insert_tracking();
        assert!(b.calibrate_once().unwrap_err().contains("NTS"), "an unauthenticated poll");
        assert_eq!(b.leap_view(), calendar, "no later horizon than before");
        // Run until the rolled upper bound reaches T - S: both clocks end there, the step of a
        // deletion, not at T.
        let mut hi = b.clock().interval_ms().unwrap().1;
        while hi < t - LEAP_STEP_MS {
            let step = 100.max((t - LEAP_STEP_MS - hi) / 2);
            elapsed.run(step);
            celapsed.run(step);
            hi = b.clock().interval_ms().unwrap().1;
        }
        assert!(hi < t, "{hi}");
        assert_eq!(control.clock().status(), Status::Unqualified(Unqualified::LeapTransition));
        assert_eq!(
            b.clock().status(),
            Status::Unqualified(Unqualified::LeapTransition),
            "an unauthenticated announcement extended holdover past T - S"
        );
    }
    #[test]
    fn review_r4_an_unauthenticated_normal_reading_never_clears_or_extends_the_view() {
        // The reviewer's missing test (mutant M35 survived at 0fb149d): a fold that treats every
        // observation, an UNAUTHENTICATED Normal included, as evidence must fail. A cold node (no
        // anchor, no view) and a node holding an anchor, no announcement in play.
        let t = at(2027, 1, 1, 0, 0, 0);
        let (cold, fake, wall, ..) = rig_with(qprofile(), 4);
        set_wall(&wall, t - 9 * 3_600_000);
        // Two NTS-authenticated selected sources in the rig, three required: UNAUTHENTICATED.
        assert!(cold.calibrate_once().unwrap_err().contains("NTS"), "an unauthenticated poll");
        assert_eq!(cold.leap_view(), LeapView::Unassessed, "an unauthenticated Normal assesses nothing");
        let (b, fake_b, wall_b, _e, anchor) = rig_with(qprofile(), 2);
        set_wall(&wall_b, t - 10 * 3_600_000);
        assert_eq!(b.calibrate_once(), Ok(true));
        let calendar = LeapView::Clear { valid_until_ms: t - LEAP_STEP_MS };
        assert_eq!(b.leap_view(), calendar);
        *fake_b.authdata.lock().unwrap() = AUTHDATA.replace("129.6.15.28,NTS", "129.6.15.28,-");
        set_wall(&wall_b, t + 20 * 86_400_000);
        assert!(b.calibrate_once().unwrap_err().contains("NTS"));
        assert_eq!(b.leap_view(), calendar, "an unauthenticated Normal must not extend the view");
        assert_eq!(stored(&anchor).leap.view, calendar, "nor does it reach the stored claim");
        // The same reading AUTHENTICATED does clear, and (Order C9) only the end of ITS month.
        let (c, _f, cwall, ..) = rig_with(qprofile(), 1);
        set_wall(&cwall, t - 9 * 3_600_000);
        assert_eq!(c.calibrate_once(), Ok(true));
        assert_eq!(c.leap_view(), LeapView::Clear { valid_until_ms: t - LEAP_STEP_MS });
        drop(fake);
    }
    #[test]
    fn a_negative_root_delay_or_dispersion_never_shrinks_the_sample_bound() {
        // Before the fix a negative dispersion was SUBTRACTED from chrony's error: 0.012 - 5 + 10 ms
        // made a 7 ms sample out of a reading whose plain bound is 13 ms. Now the reading is refused.
        let (host, fake, ..) = rig_with(qprofile(), 1);
        assert_eq!(host.source.observe().unwrap().sample.uncertainty_ms, 13);
        *fake.tracking.lock().unwrap() = TRACKING.replace("0.001500000", "-0.005000000");
        assert!(host.source.observe().unwrap_err().contains("negative"));
        assert!(host.calibrate_once().is_err());
        assert!(host.basis().lower_bound_ms().is_none());
    }
    #[test]
    fn a_poisoned_store_lock_removes_the_stored_record_instead_of_leaving_it_restorable() {
        let (host, fake, wall, elapsed, anchor) = month_end_rig();
        assert!(anchor.exists());
        // Poison the store lock the way a panic inside a locked section would.
        let shared = host.clone();
        let _ = std::thread::spawn(move || {
            let _guard = shared.store.lock().unwrap();
            panic!("poison the anchor store lock");
        })
        .join();
        assert!(host.store.is_poisoned());
        // The next poll removes the record (it may be older than the live state) and reports it;
        // the clock keeps running from memory.
        elapsed.run(1_000);
        set_wall(&wall, at(2026, 10, 31, 23, 30, 1));
        let e = host.calibrate_once().unwrap_err();
        assert!(e.contains("anchor store poisoned"), "{e}");
        assert!(!anchor.exists(), "the record is not left");
        assert!(host.basis().lower_bound_ms().is_some());
        // Every later sync fails closed the same way (a forced persist included). The poisoned
        // store still holds the exclusive lock (Order C12): no second instance can open it.
        assert!(host.persist().unwrap_err().contains("anchor store poisoned"));
        assert!(!anchor.exists());
        assert!(matches!(
            ClockStateDir::open_unchecked_for_test(&anchor),
            Err(state_dir::StorageError::Locked(_))
        ));
        drop(host);
        let r = restart(&fake, &elapsed, &anchor, qprofile());
        assert_eq!(r.restore_report(), &RestoreReport::Cold);
    }
    #[test]
    fn the_start_up_report_names_the_outcome_without_exposing_stored_bytes() {
        assert!(RestoreReport::Cold.describe().contains("no stored anchor"));
        let evidence = RestartEvidence {
            sequence: 4,
            leap: LeapClaim { policy: 2, view: LeapView::Unassessed },
            would_be_lower_ms: 1,
            would_be_half_width_ms: 2,
            would_be_remaining_ms: 3,
        };
        let line = RestoreReport::NotGranted { evidence, leap: ClaimDisposition::NoClaim }.describe();
        for needle in ["record 4", "evidence only", "Order C4", "unqualified"] {
            assert!(line.contains(needle), "{needle}: {line}");
        }
        let refused = RestoreReport::Refused(Refusal::Lineage(AnchorError::Rollback));
        assert!(refused.describe().contains("Rollback") && refused.describe().contains("unqualified"));
        let (host, ..) = rig_with(qprofile(), 1);
        assert_eq!(host.restore_report(), &RestoreReport::Cold);
    }
    #[test]
    fn a_stored_record_installs_nothing_in_a_bare_engine_whatever_view_follows() {
        let (h2, _f, _w, e2, a2) = rig_with(qprofile(), 1);
        h2.calibrate_once().unwrap();
        let bare = HoldoverClock::new(qprofile(), e2.clone()).unwrap();
        assert!(bare.assess_restart(&stored(&a2)).is_ok(), "valid evidence");
        assert_eq!(bare.status(), Status::Unqualified(Unqualified::NeverCalibrated));
        assert!(bare.set_leap_view(LeapView::Clear { valid_until_ms: u64::MAX }));
        assert_eq!(bare.status(), Status::Unqualified(Unqualified::NeverCalibrated));
    }
    #[test]
    fn poll_cadence_decision_functions() {
        let hour = Duration::from_secs(3600);
        assert_eq!(wake_interval(hour), RETRY_AFTER_EVENT);
        assert_eq!(wake_interval(Duration::from_secs(2)), Duration::from_secs(2));
        let ok = Status::Qualified {
            lower_ms: 1,
            half_width_ms: 1,
            holdover_remaining_ms: 1,
        };
        // Qualified: the regular cadence, to the nanosecond.
        assert!(!poll_due(hour, Duration::ZERO, ok));
        assert!(!poll_due(hour, hour - Duration::from_nanos(1), ok));
        assert!(poll_due(hour, hour, ok));
        // Unqualified for ANY reason: poll at every wake-up, whatever the regular cadence.
        for u in [
            Unqualified::NeverCalibrated,
            Unqualified::ElapsedSourceUnavailable,
            Unqualified::ElapsedRegressed,
            Unqualified::BootChanged,
            Unqualified::SuspendDetected,
            Unqualified::HoldoverExpired,
            Unqualified::IntervalTooWide,
            Unqualified::Arithmetic,
            Unqualified::Regression,
            Unqualified::Discontinuity,
            Unqualified::LeapUnassessed,
            Unqualified::LeapTransition,
        ] {
            assert!(poll_due(hour, Duration::ZERO, Status::Unqualified(u)), "{u:?}");
        }
        // Store failures are reported once per distinct message; a success re-arms the report.
        let mut reported = None;
        let e: Result<bool> = Err("anchor: disk full".into());
        assert_eq!(
            store_failure_to_report(&e, &mut reported),
            Some("host clock: anchor: disk full".to_string())
        );
        assert_eq!(store_failure_to_report(&e, &mut reported), None, "same message: silent");
        let both: Result<bool> = Err("chrony failed; anchor: disk full".into());
        assert!(store_failure_to_report(&both, &mut reported).is_some(), "a different message");
        let chrony: Result<bool> = Err("chronyc failed".into());
        assert_eq!(store_failure_to_report(&chrony, &mut reported), None, "not a store failure");
        assert_eq!(store_failure_to_report(&Ok(true), &mut reported), None);
        assert!(store_failure_to_report(&e, &mut reported).is_some(), "re-armed after a success");
    }
    #[test]
    fn the_background_step_polls_when_qualification_is_lost_between_polls() {
        let (host, _fake, wall, elapsed, _p) = rig_with(qprofile(), 1);
        let hour = Duration::from_secs(3600);
        assert!(host.background_step(hour, hour).is_some(), "cold start: unqualified, polls at once");
        assert!(host.basis().lower_bound_ms().is_some());
        // Qualified and the cadence has not elapsed: the step does nothing.
        assert!(host.background_step(hour, Duration::from_secs(1)).is_none());
        // The holdover runs out BETWEEN two polls (no poll happened for 25 h): at the next wake-up
        // the status is checked, found unqualified and a poll runs at once (the regular cadence
        // has NOT elapsed in terms of `since_last_poll`).
        elapsed.run(25 * 3_600_000);
        let now = *wall.0.lock().unwrap();
        set_wall(&wall, now + 25 * 3_600_000);
        assert_eq!(
            host.clock().status(),
            Status::Unqualified(Unqualified::HoldoverExpired)
        );
        assert_eq!(host.background_step(hour, Duration::from_secs(5)), Some(Ok(true)));
        assert!(host.basis().lower_bound_ms().is_some(), "requalified by that poll");
        assert!(host.background_step(hour, Duration::from_secs(5)).is_none());
    }
    #[test]
    fn qualified_sample_overhead_matches_the_documented_formula() {
        // E = 0.012345 + 1.5 + 10 ms = 11.512 -> ceil 12; W = 0 (frozen elapsed); U = 12 + 0 + 1.
        let (host, fake, ..) = rig_with(qprofile(), 1);
        let o = host.source.observe().unwrap();
        assert!(o.sample.authenticated);
        assert_eq!(o.sample.uncertainty_ms, 13);
        assert_eq!(o.interval_ms, (o.sample.utc_ms - 13, o.sample.utc_ms + 13));
        // The largest E allowed by the 250 ms profile at W = 0 is 247 ms: ceil(E) + W + 1 = 248.
        assert_eq!(qprofile().max_chrony_error_ms(0), Some(247));
        // 0.012 + 13 + 233 = 246.012 ms -> 247 -> U = 248: accepted, total initial 249 <= 250.
        *fake.tracking.lock().unwrap() =
            TRACKING.replace("0.020000000,0.001500000", "0.466000000,0.013000000");
        assert_eq!(host.source.observe().unwrap().sample.uncertainty_ms, 248);
        assert_eq!(host.calibrate_once(), Ok(true));
        let (host, fake, ..) = rig_with(qprofile(), 1);
        *fake.tracking.lock().unwrap() =
            TRACKING.replace("0.020000000,0.001500000", "0.468000000,0.013000000");
        // 0.012 + 13 + 234 = 247.012 ms -> 248 -> U = 249 > 248: refused by the engine.
        let e = host.calibrate_once().unwrap_err();
        assert!(e.contains("SourceUncertainty"), "{e}");
    }
    #[test]
    fn a_reading_pairs_boottime_with_the_midpoint_of_the_monotonic_sandwich() {
        assert_eq!(sandwich_midpoint(100, 110), Some(105));
        assert_eq!(sandwich_midpoint(100, 101), Some(100), "floored to the nanosecond");
        assert_eq!(sandwich_midpoint(7, 7), Some(7));
        assert_eq!(sandwich_midpoint(u64::MAX - 2, u64::MAX), Some(u64::MAX - 1));
        assert_eq!(sandwich_midpoint(110, 100), None, "a monotonic clock that went backwards");
        // Wherever the boottime sample falls inside the sandwich, the pairing error is at most
        // half the sandwich.
        for at in 100u64..=110 {
            let error = at.abs_diff(sandwich_midpoint(100, 110).unwrap());
            assert!(error <= 5, "{at}");
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn real_linux_readings_never_trip_the_continuity_rule_and_keep_the_clock_qualified() {
        // Independent review, MAJOR-2; for the Linux campaign (it cannot run on the development
        // host). A few thousand REAL readings through `LinuxElapsed::read`, each through the
        // engine's continuity/roll path: live status reads against the anchor's reading,
        // calibrations whose sample was read one iteration earlier, and persist/restore round
        // trips (calibration -> persist -> now). Under the previous zero-tolerance rule about half
        // of all reading pairs failed. The host must not suspend during the test (well under 1 s).
        let source: Arc<dyn ElapsedSource> = Arc::new(LinuxElapsed);
        let open = LeapView::Clear { valid_until_ms: u64::MAX };
        let sample = |at: Elapsed| SourceSample {
            source: "chrony-nts".into(),
            authenticated: true,
            // TEST centre; leap handling is not under test (the view vouches for everything).
            utc_ms: 1_790_899_300_000,
            uncertainty_ms: 13,
            at,
        };
        let clock = HoldoverClock::new(qprofile(), source.clone()).unwrap();
        assert!(clock.set_leap_view(open));
        let first = source.read().expect("CLOCK_MONOTONIC, CLOCK_BOOTTIME and boot_id readable");
        assert_eq!(clock.calibrate(&[sample(first)]), Ok(true));
        let mut previous = first;
        for i in 0..4_000u64 {
            let status = clock.status();
            assert!(matches!(status, Status::Qualified { .. }), "reading {i}: {status:?}");
            let reading = source.read().unwrap();
            assert_eq!(reading.boot_id, first.boot_id);
            if i % 50 == 0 {
                let fresh = HoldoverClock::new(qprofile(), source.clone()).unwrap();
                assert!(fresh.set_leap_view(open));
                assert_eq!(fresh.calibrate(&[sample(previous)]), Ok(true), "reading {i}");
                let record = clock.persisted(i + 1, leap_policy::POLICY_VERSION).unwrap();
                let restarted = HoldoverClock::new(qprofile(), source.clone()).unwrap();
                // Order C4: real readings make the record valid EVIDENCE, never qualification.
                let evidence = restarted.assess_restart(&record).map(|r| r.sequence);
                assert_eq!(evidence, Ok(i + 1), "reading {i}");
                assert!(restarted.set_leap_view(open));
                assert_eq!(
                    restarted.status(),
                    Status::Unqualified(Unqualified::NeverCalibrated),
                    "reading {i}"
                );
            }
            previous = reading;
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_elapsed_source_is_monotonic_and_has_a_boot_identity() {
        let a = LinuxElapsed.read().unwrap();
        std::thread::sleep(Duration::from_millis(5));
        let b = LinuxElapsed.read().unwrap();
        assert_eq!(a.boot_id, b.boot_id);
        assert!(b.monotonic_ns > a.monotonic_ns && b.boottime_ns >= b.monotonic_ns.min(a.boottime_ns));
    }

    // ------------------------------------------------------------------------------------------
    // Order of 4 Oct 2026, decisions C8 and C12 at host level (software, Windows host unless
    // marked unix; Implemented, not Qualified).
    // ------------------------------------------------------------------------------------------
    /// Every file of the anchor directory, name -> bytes (the lock file only by name: on Windows a
    /// locked range cannot be read by another handle, and it holds no data).
    fn snapshot(anchor: &PathBuf) -> std::collections::BTreeMap<String, Vec<u8>> {
        std::fs::read_dir(anchor.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap())
            .filter(|e| e.file_type().unwrap().is_file())
            .map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let bytes = if name.ends_with(".lock") { Vec::new() } else { std::fs::read(e.path()).unwrap() };
                (name, bytes)
            })
            .collect()
    }
    #[test]
    fn c12_a_second_node_instance_fails_closed_before_reading_or_writing_anything() {
        let (host, fake, _w, elapsed, anchor) = rig_with(qprofile(), 1);
        assert_eq!(host.calibrate_once(), Ok(true));
        let before = snapshot(&anchor);
        assert!(before.contains_key("anchor.bin") && before.contains_key("anchor.bin.lock"));
        // (Two HostClock instances in ONE test process with the test-only opener; the OS lock is
        // per open file description, so it conflicts within one process too. No multi-process run
        // exists: independent review, DOC-2.) While the first instance runs, a second one cannot
        // even open the store: an explicit error, no waiting, no lock stealing, no read, no restore
        // race. Repeatedly.
        for _ in 0..5 {
            let refused = ClockStateDir::open_unchecked_for_test(&anchor).unwrap_err();
            assert_eq!(refused, state_dir::StorageError::Locked(PathBuf::from(format!("{}.lock", anchor.display()))));
        }
        assert_eq!(snapshot(&anchor), before, "the refused instance touched nothing");
        // The first process keeps working and writing.
        elapsed.run(1_000);
        assert!(host.persist().is_ok());
        // Only after it is gone does the next process get the store (and, Order C4, no qualification).
        drop(host);
        let next = restart(&fake, &elapsed, &anchor, qprofile());
        assert!(matches!(next.restore_report(), RestoreReport::NotGranted { .. }));
    }
    #[test]
    fn c12_racing_node_instances_get_exactly_one_store() {
        let (host, fake, wall, elapsed, anchor) = rig_with(qprofile(), 1);
        assert_eq!(host.calibrate_once(), Ok(true));
        drop(host);
        for round in 0..10 {
            let barrier = Arc::new(std::sync::Barrier::new(6));
            let started: Vec<_> = (0..6)
                .map(|_| {
                    let (barrier, anchor) = (barrier.clone(), anchor.clone());
                    let source = ChronySource {
                        client: fake.clone(),
                        wall: wall.clone(),
                        elapsed: elapsed.clone(),
                        min_nts_selected: 1,
                        nts_sources: HOSTS.iter().map(|h| (*h).to_owned()).collect(),
                    };
                    std::thread::spawn(move || {
                        barrier.wait();
                        ClockStateDir::open_unchecked_for_test(&anchor)
                            .map(|state| HostClock::with_sources(qprofile(), source, state).unwrap())
                    })
                })
                .collect();
            let results: Vec<_> = started.into_iter().map(|t| t.join().unwrap()).collect();
            assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1, "round {round}");
            assert!(results.iter().all(|r| match r {
                Ok(h) => matches!(h.restore_report(), RestoreReport::NotGranted { .. }),
                Err(e) => matches!(e, state_dir::StorageError::Locked(_)),
            }));
        }
    }
    #[cfg(unix)]
    #[test]
    fn c8_the_production_opener_refuses_unsafe_storage_at_start_up_and_accepts_owner_only() {
        // Unix only: runs in the Linux campaign, not on the Windows development host.
        use std::os::unix::fs::PermissionsExt;
        let (_h, fake, wall, elapsed, anchor) = rig_with(qprofile(), 1);
        let base = anchor.parent().unwrap().join("prod");
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let source = || ChronySource {
            client: fake.clone(),
            wall: wall.clone(),
            elapsed: elapsed.clone(),
            min_nts_selected: 1,
            nts_sources: HOSTS.iter().map(|h| (*h).to_owned()).collect(),
        };
        // A group-readable state directory is refused before anything is locked or read.
        let open_dir = base.join("open");
        std::fs::create_dir(&open_dir).unwrap();
        std::fs::set_permissions(&open_dir, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert_eq!(
            ClockStateDir::open(&open_dir.join("clock.anchor")).err(),
            Some(state_dir::StorageError::Accessible(open_dir.clone()))
        );
        // A missing one is created owner-only, locked, and the node starts (unqualified).
        let fresh = base.join("state").join("clock.anchor");
        let host = HostClock::with_sources(qprofile(), source(), ClockStateDir::open(&fresh).unwrap()).unwrap();
        assert_eq!(host.restore_report(), &RestoreReport::Cold);
        assert_eq!(host.calibrate_once(), Ok(true));
        assert!(matches!(ClockStateDir::open(&fresh), Err(state_dir::StorageError::Locked(_))));
    }

    // ------------------------------------------------------------------------------------------
    // Order of 4 Oct 2026, decision C3 at host level (software, Windows host; Implemented, not
    // Qualified; the real `chronyc` was never run here).
    // ------------------------------------------------------------------------------------------
    /// A chrony whose `tracking` output changes between consecutive reads: `change` is applied to
    /// every SECOND tracking read (the read that closes a capture).
    struct Changing {
        inner: Arc<Fake>,
        reads: std::sync::atomic::AtomicU32,
        change: fn(&str) -> String,
    }
    impl ChronyClient for Changing {
        fn run(&self, args: &[&str]) -> Result<String> {
            let out = self.inner.run(args)?;
            if args.last() == Some(&"tracking")
                && self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst) % 2 == 1
            {
                return Ok((self.change)(&out));
            }
            Ok(out)
        }
    }
    #[test]
    fn c3_tracking_readings_of_one_capture_must_describe_one_chrony_update() {
        let t = parse_tracking(TRACKING).unwrap();
        assert_eq!(coherent_tracking(TRACKING, TRACKING).unwrap(), t);
        // Another reference, stratum, last-update time or leap status between the two reads: the
        // set straddles a chrony update and is discarded.
        for (field, changed) in [
            ("ref id", TRACKING.replace("A29FC801", "A29FC802")),
            ("name", TRACKING.replace(",162.159.200.1,", ",129.6.15.28,")),
            ("stratum", TRACKING.replace(",3,1790899200.123", ",2,1790899200.123")),
            ("update time", TRACKING.replace("1790899200.123", "1790899264.502")),
            ("leap status", insert_tracking()),
        ] {
            let e = coherent_tracking(TRACKING, &changed).unwrap_err();
            assert!(e.contains("changed during the capture"), "{field}: {e}");
        }
        // The same update read twice: the larger error terms are kept (the dispersion grew).
        let later = TRACKING.replace("0.001500000", "0.001700000").replace("-0.000012345", "-0.000002345");
        let merged = coherent_tracking(TRACKING, &later).unwrap();
        assert_eq!(merged.root_dispersion_s, 0.0017);
        assert_eq!(merged.system_offset_s, t.system_offset_s);
        assert!(coherent_tracking("", TRACKING).is_err() && coherent_tracking(TRACKING, "a,b").is_err());
    }
    #[test]
    fn c3_a_poll_that_straddles_a_chrony_update_offers_nothing() {
        let (_rig, fake, wall, elapsed, anchor) = rig_with(qprofile(), 1);
        let file = anchor.parent().unwrap().join("straddle.anchor");
        let changing = Arc::new(Changing {
            inner: fake.clone(),
            reads: std::sync::atomic::AtomicU32::new(0),
            change: |s: &str| s.replace("1790899200.123", "1790899264.502"),
        });
        let host = HostClock::with_sources(
            qprofile(),
            ChronySource {
                client: changing.clone(),
                wall: wall.clone(),
                elapsed: elapsed.clone(),
                min_nts_selected: 1,
                nts_sources: HOSTS.iter().map(|h| (*h).to_owned()).collect(),
            },
            state(&file),
        )
        .unwrap();
        let e = host.calibrate_once().unwrap_err();
        assert!(e.contains("changed during the capture"), "{e}");
        assert_eq!((host.clock().anchor_interval_ms(), host.leap_view()), (None, LeapView::Unassessed));
        assert!(!file.exists(), "nothing was stored");
        // An announcement that arrives in the middle of a capture is not folded either: the next
        // coherent poll reads it whole.
        let announcing = Arc::new(Changing {
            inner: fake.clone(),
            reads: std::sync::atomic::AtomicU32::new(0),
            change: |s: &str| s.replace("Normal", "Insert second"),
        });
        let file2 = anchor.parent().unwrap().join("announce.anchor");
        let host2 = HostClock::with_sources(
            qprofile(),
            ChronySource { client: announcing, wall, elapsed, min_nts_selected: 1, nts_sources: HOSTS.iter().map(|h| (*h).to_owned()).collect() },
            state(&file2),
        )
        .unwrap();
        assert!(host2.calibrate_once().unwrap_err().contains("changed during the capture"));
        assert_eq!(host2.leap_view(), LeapView::Unassessed);
    }
    #[test]
    fn c3_a_signing_decision_between_polls_is_judged_at_its_own_instant() {
        // The node hands the ENGINE itself to the voter (no cached verdict): a decision 4.9 s after
        // the last poll sees the lower bound, drift and holdover of that instant.
        use mutiny_consensus_v8::vote_clock_v1::{TimeStatus, evaluate};
        let (host, _fake, _wall, elapsed, _anchor) = rig_with(qprofile(), 1);
        assert_eq!(host.calibrate_once(), Ok(true));
        let clock = host.vote_clock();
        let at_poll = host.basis().lower_bound_ms().unwrap();
        let later = (at_poll + 4_900 - 1) / 1000;
        assert!(matches!(evaluate(&*clock, later), TimeStatus::Future { .. }), "not yet at the poll");
        elapsed.run(4_900);
        assert_eq!(evaluate(&*clock, later), TimeStatus::Eligible, "eligible 4.9 s later, no poll");
        // A horizon that ends BETWEEN two polls ends the next decision, without any poll: the
        // engine's view is pushed by the poll, but its expiry is evaluated at every reading.
        let (_, hi) = host.clock().interval_ms().unwrap();
        host.clock().set_leap_view(LeapView::Clear { valid_until_ms: hi + 4_800 });
        assert_eq!(evaluate(&*clock, 0), TimeStatus::Eligible);
        elapsed.run(4_900);
        assert_eq!(evaluate(&*clock, 0), TimeStatus::Unqualified);
        assert!(poll_due(Duration::from_secs(3600), Duration::ZERO, host.clock().status()));
    }

    // ------------------------------------------------------------------------------------------
    // Order of 4 Oct 2026, decision C5 (software; Windows host, the unix variant runs only in the
    // Linux campaign; Implemented, not Qualified).
    // ------------------------------------------------------------------------------------------
    /// Makes the stored record impossible to remove until dropped. Windows: a handle that shares
    /// nothing (Rust removes read-only files, so that is not enough). Unix: a read-only directory,
    /// which also makes every write fail (the Linux campaign runs unprivileged).
    struct Undeletable {
        #[cfg(windows)]
        _handle: std::fs::File,
        #[cfg(unix)]
        dir: PathBuf,
    }
    impl Undeletable {
        fn hold(anchor: &PathBuf) -> Self {
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                let handle = std::fs::OpenOptions::new().read(true).share_mode(0).open(anchor).unwrap();
                Self { _handle: handle }
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let dir = anchor.parent().unwrap().to_path_buf();
                std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();
                Self { dir }
            }
        }
    }
    #[cfg(unix)]
    impl Drop for Undeletable {
        fn drop(&mut self) {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    #[test]
    fn c5_a_failed_write_keeps_live_qualification_only_because_no_stale_record_can_qualify_a_restart() {
        let (host, fake, wall, elapsed, anchor) = month_end_rig();
        let stale = std::fs::read(&anchor).unwrap();
        assert!(matches!(stored(&anchor).leap.view, LeapView::Clear { .. }));
        assert_eq!(host.store_condition(), StoreCondition::Current);
        // The next write fails (the mark's temp name is blocked) AND the record that would then be
        // stale cannot be removed.
        let blocked = PathBuf::from(format!("{}.tmp", seq_path(&anchor).display()));
        std::fs::create_dir(&blocked).unwrap();
        let held = Undeletable::hold(&anchor);
        *fake.tracking.lock().unwrap() = insert_tracking();
        elapsed.run(60_000);
        set_wall(&wall, at(2026, 10, 31, 23, 31, 0));
        let e = host.calibrate_once().unwrap_err();
        // The explicit condition is recorded and reported ...
        assert!(e.contains("stale anchor record could not be invalidated"), "{e}");
        assert_eq!(host.store_condition(), StoreCondition::StaleNotInvalidated);
        // ... and live qualification continues: the stale record cannot qualify any restart.
        assert!(host.basis().lower_bound_ms().is_some());
        assert!(matches!(host.leap_view(), LeapView::Pending { .. }));
        drop(held);
        assert_eq!(std::fs::read(&anchor).unwrap(), stale, "the stale record (old Clear claim) remains");
        // It fails closed on restore: evidence at most, its clear is not restored, unqualified.
        drop(host);
        let r = restart_at(&fake, &elapsed, &anchor, qprofile(), at(2026, 10, 31, 23, 31, 0));
        assert!(
            matches!(
                r.restore_report(),
                RestoreReport::NotGranted {
                    leap: ClaimDisposition::Discarded(leap_policy::DiscardReason::ClearNotRestored),
                    ..
                }
            ),
            "{:?}",
            r.restore_report()
        );
        assert!(r.basis().lower_bound_ms().is_none());
        assert_eq!(r.leap_view(), LeapView::Unassessed);
        // Once writes work again, a fresh authenticated calibration qualifies and is stored.
        std::fs::remove_dir(&blocked).unwrap();
        *fake.tracking.lock().unwrap() = insert_tracking();
        assert_eq!(r.calibrate_once(), Ok(true));
        assert_eq!(r.store_condition(), StoreCondition::Current);
        assert!(matches!(stored(&anchor).leap.view, LeapView::Pending { .. }));
    }
    #[test]
    fn c5_failed_and_retried_writes_never_reset_the_original_calibration_age() {
        let (host, fake, _w, elapsed, anchor) = rig_with(qprofile(), 1);
        assert_eq!(host.calibrate_once(), Ok(true));
        let first = stored(&anchor);
        // An engine that never stops, holding the same calibration (in memory only).
        let uninterrupted = HoldoverClock::new(qprofile(), elapsed.clone()).unwrap();
        assert!(uninterrupted.set_leap_view(LeapView::Clear { valid_until_ms: u64::MAX }));
        assert_eq!(uninterrupted.calibrate(&[host.source.observe().unwrap().sample]), Ok(true));
        // Blackout, and every write fails for an hour (each failed attempt spends a sequence and
        // removes the possibly stale record).
        *fake.tracking.lock().unwrap() = String::new();
        let blocked = PathBuf::from(format!("{}.tmp", seq_path(&anchor).display()));
        std::fs::create_dir(&blocked).unwrap();
        for _ in 0..12 {
            elapsed.run(300_000);
            assert!(host.persist().unwrap_err().contains("anchor"));
            assert!(host.calibrate_once().is_err());
        }
        assert!(!anchor.exists());
        // Writes work again: the rewritten record carries the ORIGINAL calibration (no
        // re-baselining) and the live uncertainty is the uninterrupted engine's, an hour of drift
        // from the original calibration included.
        std::fs::remove_dir(&blocked).unwrap();
        host.persist().unwrap();
        let rewritten = stored(&anchor);
        assert!(rewritten.sequence > first.sequence + 12);
        assert_eq!(
            (rewritten.lower_ms, rewritten.upper_ms, rewritten.at, rewritten.validity_horizon_ms),
            (first.lower_ms, first.upper_ms, first.at, first.validity_horizon_ms)
        );
        assert_eq!(host.clock().status(), uninterrupted.status());
        let Status::Qualified { holdover_remaining_ms, .. } = host.clock().status() else {
            panic!("qualified")
        };
        assert_eq!(holdover_remaining_ms, 86_400_000 - 3_600_000);
    }
}
