//! Native Windows elapsed observations; no UTC, clock steering or restart grant.
//! QueryUnbiasedInterruptTimePrecise excludes sleep/hibernate; QueryInterruptTimePrecise
//! includes the Windows sleep compensation. Both have 100ns units. The deployment
//! must separately qualify their error envelope and actual suspend behavior.
//! https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryunbiasedinterrupttimeprecise
//! https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryinterrupttimeprecise
//! No default sampling bound or drift profile is invented. The existing HostClock
//! Windows startup path remains disabled pending the authenticated sample adapter.
use mutiny_consensus_v8::holdover_clock_v1::{Elapsed, ElapsedSource};
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capture {
    pub elapsed: Elapsed,
    /// Exact active-clock sandwich span; UTC adapter must account for this.
    pub sampling_span_ns: u64,
    /// Ceiled midpoint pairing error plus one 100ns counter quantum.
    pub pairing_uncertainty_ns: u64,
}
pub struct WindowsElapsed {
    max_sampling_span_ns: u64,
}
impl WindowsElapsed {
    pub fn new(max_sampling_span: Duration) -> Result<Self, &'static str> {
        let ns = u64::try_from(max_sampling_span.as_nanos())
            .map_err(|_| "elapsed sampling bound overflow")?;
        if ns == 0 { return Err("elapsed sampling bound must be positive"); }
        Ok(Self { max_sampling_span_ns: ns })
    }
    pub fn capture(&self) -> Option<Capture> {
        let before = super::windows_boot::read().ok()?;
        let (first, biased, second) = native::counters()?;
        let after = super::windows_boot::read().ok()?;
        if before != after { return None; }
        checked_capture(before.identifier_bytes, first, biased, second, self.max_sampling_span_ns)
    }
}
impl ElapsedSource for WindowsElapsed {
    fn read(&self) -> Option<Elapsed> { self.capture().map(|c| c.elapsed) }
}
fn checked_capture(boot: [u8; 16], first: u64, biased: u64, second: u64,
    bound_ns: u64) -> Option<Capture> {
    if boot == [0; 16] || first == 0 || biased == 0 || second == 0 || bound_ns == 0 {
        return None;
    }
    let first_ns = first.checked_mul(100)?;
    let boottime_ns = biased.checked_mul(100)?;
    let second_ns = second.checked_mul(100)?;
    let span = second_ns.checked_sub(first_ns)?;
    if span > bound_ns { return None; }
    let midpoint = first_ns.checked_add(span / 2)?;
    // Biased time was read between the active samples. It can legitimately be
    // below the active midpoint within the pairing interval, so do not invent
    // a zero-gap equality requirement or subtract a wall-time-derived bias.
    if boottime_ns < first_ns { return None; }
    Some(Capture {
        elapsed: Elapsed { monotonic_ns: midpoint, boottime_ns,
            boot_id: u128::from_le_bytes(boot) },
        sampling_span_ns: span,
        pairing_uncertainty_ns: span.checked_add(1)?.checked_div(2)?.checked_add(100)?,
    })
}
#[cfg(all(windows, target_arch = "x86_64"))]
mod native {
    // Use Microsoft's documented SDK import library for these API-set
    // contracts. The pinned Windows build does not export them from
    // kernel32.dll by name; probing an implementation DLL is not the contract.
    #[link(name = "mincore")]
    unsafe extern "system" {
        fn QueryUnbiasedInterruptTimePrecise(value: *mut u64);
        fn QueryInterruptTimePrecise(value: *mut u64);
    }
    pub(super) fn counters() -> Option<(u64, u64, u64)> {
        let (mut first, mut middle, mut second) = (0u64, 0u64, 0u64);
        // SAFETY: documented VOID(PULONGLONG) ABI, three exclusive initialized
        // u64 outputs. Windows >=10 is required by the SDK contract; capture
        // first checks the exact reviewed Windows build. No private DLL lookup.
        unsafe {
            QueryUnbiasedInterruptTimePrecise(&mut first);
            QueryInterruptTimePrecise(&mut middle);
            QueryUnbiasedInterruptTimePrecise(&mut second);
        }
        Some((first, middle, second))
    }
}
#[cfg(not(all(windows, target_arch = "x86_64")))]
mod native {
    pub(super) fn counters() -> Option<(u64, u64, u64)> { None }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checked_capture_accounts_for_pairing_and_never_uses_wall_time() {
        let c = checked_capture([1; 16], 100, 103, 105, 500).unwrap();
        assert_eq!(c.elapsed.monotonic_ns, 10_250);
        assert_eq!(c.elapsed.boottime_ns, 10_300);
        assert_eq!(c.sampling_span_ns, 500);
        assert_eq!(c.pairing_uncertainty_ns, 350);
        // A sleep compensation is retained in biased time, never erased.
        let suspended = checked_capture([1; 16], 100, 100_103, 105, 500).unwrap();
        assert_eq!(suspended.elapsed.boottime_ns, 10_010_300);
    }
    #[test]
    fn unsupported_zero_overflow_regression_and_excess_span_refuse() {
        for (boot, a, b, c, limit) in [([0;16],1,1,1,100),([1;16],0,1,1,100),
            ([1;16],2,2,1,100),([1;16],1,1,3,199),
            ([1;16],u64::MAX,u64::MAX,u64::MAX,100),([1;16],2,1,2,100)] {
            assert!(checked_capture(boot,a,b,c,limit).is_none());
        }
        assert!(WindowsElapsed::new(Duration::ZERO).is_err());
        assert!(WindowsElapsed::new(Duration::MAX).is_err());
    }
    #[test]
    #[cfg(all(windows, target_arch = "x86_64"))]
    fn actual_pinned_windows_counters_are_nonzero_and_monotone_within_process() {
        // A PUBLIC TEST capture bound, not a measured hardware/profile ceiling.
        let source = WindowsElapsed::new(Duration::from_millis(250)).unwrap();
        let mut previous = source.capture().expect("actual native Windows capture");
        for _ in 0..32 {
            let current = source.capture().unwrap();
            assert_eq!(current.elapsed.boot_id, previous.elapsed.boot_id);
            assert!(current.elapsed.monotonic_ns >= previous.elapsed.monotonic_ns);
            assert!(current.elapsed.boottime_ns >= previous.elapsed.boottime_ns);
            assert!(current.sampling_span_ns <= 250_000_000);
            previous = current;
        }
        // No cross-process/reboot/hibernate/drift or blackout qualification inferred.
    }
    #[test]
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    fn unsupported_platform_refuses_without_any_fallback() {
        assert!(WindowsElapsed::new(Duration::from_millis(250)).unwrap().read().is_none());
    }
}
