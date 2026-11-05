//! Actual elapsed counter sandwich, with uncertainty retained. These private
//! producer fields are numerical observations, never installation authority,
//! clock qualification, an authenticated reply or a restart grant.
use std::time::Duration;

/// No raw constructor, deserialization or caller assertion constructor.
/// Inclusive bounds describe the sampled inclusive-counter instant, expanded
/// by observed active-clock pairing span and quantum. That active span cannot
/// bound a suspend interval between syscalls; current owner/OS qualification
/// checks remain mandatory. A lifetime comparison must additionally apply
/// the selected oscillator drift bound and require the same selected context.
pub struct NativeElapsedInterval {
    active_lower_ns:u64,active_upper_ns:u64,
    inclusive_lower_ns:u64,inclusive_upper_ns:u64,boot_id:u128,
}
impl NativeElapsedInterval {
    pub fn active_lower_ns(&self)->u64 {self.active_lower_ns}
    pub fn active_upper_ns(&self)->u64 {self.active_upper_ns}
    pub fn inclusive_lower_ns(&self)->u64 {self.inclusive_lower_ns}
    pub fn inclusive_upper_ns(&self)->u64 {self.inclusive_upper_ns}
    pub fn boot_id(&self)->u128 {self.boot_id}
}
pub fn capture_elapsed_interval(maximum_sampling_span_ns:u64)->Option<NativeElapsedInterval> {
    if !(1..=1_000_000_000).contains(&maximum_sampling_span_ns) {return None;}
    #[cfg(windows)]
    let (capture,quantum)=
        (super::native_windows_elapsed::WindowsElapsed::new(Duration::from_nanos(maximum_sampling_span_ns)).ok()?.capture()?,100u64);
    #[cfg(target_os="linux")]
    let (capture,quantum)=
        (super::native_linux_elapsed::LinuxElapsed::new(Duration::from_nanos(maximum_sampling_span_ns)).ok()?.capture()?,1u64);
    #[cfg(any(windows,target_os="linux"))]
    {
        let first=capture.active_before_ns;let last=capture.active_after_ns;
        let inclusive=capture.elapsed.boottime_ns;let boot_id=capture.elapsed.boot_id;
        if first==0 || boot_id==0 || inclusive<first {return None;}
        let span=last.checked_sub(first)?;
        if span>maximum_sampling_span_ns {return None;}
        let radius=span.checked_add(quantum)?;
        Some(NativeElapsedInterval {
            active_lower_ns:first.checked_sub(quantum)?,active_upper_ns:last.checked_add(quantum)?,
            inclusive_lower_ns:inclusive.checked_sub(radius)?,inclusive_upper_ns:inclusive.checked_add(radius)?,boot_id,
        })
    }
    #[cfg(not(any(windows,target_os="linux")))]
    None
}
