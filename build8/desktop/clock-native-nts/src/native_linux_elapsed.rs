//! Native Linux software observations, not a measured drift/continuity profile.
//! Mirrors the existing Node CLOCK_MONOTONIC/CLOCK_BOOTTIME sandwich.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod native {
    #[repr(C)]
    struct Timespec {
        seconds: i64,
        nanos: i64,
    }
    unsafe extern "C" {
        fn clock_gettime(clock: i32, out: *mut Timespec) -> i32;
    }
    fn counter(clock: i32) -> Option<u64> {
        let mut t = Timespec {
            seconds: 0,
            nanos: 0,
        };
        if unsafe { clock_gettime(clock, &mut t) } != 0
            || t.seconds < 0
            || !(0..1_000_000_000).contains(&t.nanos)
        {
            return None;
        }
        (t.seconds as u64)
            .checked_mul(1_000_000_000)?
            .checked_add(t.nanos as u64)
    }
    pub(super) fn counters() -> Option<(u64, u64, u64)> {
        Some((counter(1)?, counter(7)?, counter(1)?))
    }
    pub(super) fn boot() -> Option<u128> {
        use std::io::Read;
        let mut input = std::fs::File::open("/proc/sys/kernel/random/boot_id").ok()?;
        let mut raw = [0u8; 38];
        let count = input.read(&mut raw).ok()?;
        if count != 37 || raw[36] != b'\n' || [8, 13, 18, 23].into_iter().any(|n| raw[n] != b'-') {
            return None;
        }
        let mut id = 0u128;
        for (n, b) in raw[..36].iter().copied().enumerate() {
            if [8, 13, 18, 23].contains(&n) {
                continue;
            }
            let v = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => return None,
            };
            id = id.checked_mul(16)?.checked_add(u128::from(v))?;
        }
        if id == 0 { None } else { Some(id) }
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Elapsed {
    pub monotonic_ns: u64,
    pub boottime_ns: u64,
    pub boot_id: u128,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Capture {
    pub elapsed: Elapsed,
    pub pairing_uncertainty_ns: u64,
    // Captured at the actual syscall boundary, never reconstructed from midpoint.
    pub active_before_ns: u64,
    pub active_after_ns: u64,
}
pub(crate) struct LinuxElapsed {
    maximum_ns: u64,
}
impl LinuxElapsed {
    pub(crate) fn new(span: std::time::Duration) -> Result<Self, &'static str> {
        let maximum_ns =
            u64::try_from(span.as_nanos()).map_err(|_| "Linux capture bound overflow")?;
        if maximum_ns == 0 {
            return Err("Linux capture bound zero");
        }
        Ok(Self { maximum_ns })
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn capture(&self) -> Option<Capture> {
        let boot = native::boot()?;
        let (first, inclusive, second) = native::counters()?;
        if native::boot()? != boot || first == 0 || inclusive < first {
            return None;
        }
        let span = second.checked_sub(first)?;
        if span > self.maximum_ns {
            return None;
        }
        Some(Capture {
            active_before_ns: first,
            active_after_ns: second,
            elapsed: Elapsed {
                monotonic_ns: first.checked_add(span / 2)?,
                boottime_ns: inclusive,
                boot_id: boot,
            },
            pairing_uncertainty_ns: span.checked_add(1)?.checked_div(2)?.checked_add(1)?,
        })
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    pub(crate) fn capture(&self) -> Option<Capture> { None }
}
