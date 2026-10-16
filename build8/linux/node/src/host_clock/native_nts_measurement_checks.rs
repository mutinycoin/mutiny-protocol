//! Necessary integer constraints ONLY; never an experiment/qualification issuer.
//! Inputs must eventually be reconstructed by a genuine report/raw-data verifier.
//! These functions cannot authenticate a sensor, confidence method or margin.
use mutiny_consensus_v8::holdover_clock_v1::{ClockProfile,INITIAL_CALIBRATION_MAX_UNCERTAINTY_MS};
use super::native_nts_deployment_record::Error;
type Result<T>=std::result::Result<T,Error>;

/// Conservative frequency constraint for a reconstructed external duration
/// interval. Check both endpoints with integer cross-products; no float,
/// synthetic confidence level/margin or declared upper-bound trust.
pub(super) fn frequency_interval(profile:&ClockProfile,elapsed_ns:u64,
    reference_lower_ns:u64,reference_upper_ns:u64)->Result<()> {
    profile.validate().map_err(|_|Error::QualificationProvenance)?;
    let minimum=profile.max_holdover_ms.checked_mul(1_000_000).ok_or(Error::QualificationProvenance)?;
    if elapsed_ns==0 || reference_lower_ns==0 || reference_lower_ns>reference_upper_ns
        || reference_lower_ns<minimum || profile.drift_bound_ppb==0 {return Err(Error::QualificationProvenance);}
    for reference in [reference_lower_ns,reference_upper_ns] {
        let error=u128::from(elapsed_ns.abs_diff(reference));
        if error*1_000_000_000>u128::from(profile.drift_bound_ppb)*u128::from(reference) {
            return Err(Error::QualificationProvenance);
        }
    }
    Ok(()) // only the represented interval passes, not an entire hardware class.
}
/// Existing engine's TOTAL initial half-width, inclusive, after all source/
/// capture/drift/rounding contributions. Does not accept an isolated source E.
pub(super) fn initial_interval(profile:&ClockProfile,lower_ms:u64,upper_ms:u64)->Result<()> {
    profile.validate().map_err(|_|Error::QualificationProvenance)?;
    let width=upper_ms.checked_sub(lower_ms).ok_or(Error::QualificationProvenance)?;
    let half=width.div_ceil(2);
    if half>profile.max_calibration_half_width_ms || half>INITIAL_CALIBRATION_MAX_UNCERTAINTY_MS {
        return Err(Error::QualificationProvenance);
    }
    Ok(())
}
/// Existing configured sample pairing/span and timestamp precision bounds.
/// Measured precision is supplied by the later genuine parser; never guessed.
pub(super) fn capture_bounds(config:&mutiny_clock_native_nts_v1::Config,
    span_ns:u64,measured_precision_ns:u64)->Result<()> {
    config.validate().map_err(|_|Error::QualificationProvenance)?;
    if config.bounds.maximum_sampling_span_ns==0 || span_ns>config.bounds.maximum_sampling_span_ns
        || measured_precision_ns==0 || measured_precision_ns>config.bounds.wall_timestamp_uncertainty_ns {
        return Err(Error::QualificationProvenance);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn profile()->ClockProfile {ClockProfile {max_source_uncertainty_ms:240,max_calibration_half_width_ms:250,
        min_sources:3,max_faulty_sources:1,drift_bound_ppb:1000,max_holdover_ms:1000,
        max_interval_half_width_ms:1000,max_suspend_gap_ms:1,confirm_calibrations:1}}
    #[test] fn modeled_frequency_checks_both_interval_ends_and_existing_duration() {
        let p=profile();assert_eq!(frequency_interval(&p,1_000_000_000,1_000_000_000,1_000_000_000),Ok(()));
        assert_eq!(frequency_interval(&p,1_000_001_000,1_000_000_000,1_000_000_000),Ok(()));
        assert!(frequency_interval(&p,1_000_001_001,1_000_000_000,1_000_000_000).is_err());
        assert!(frequency_interval(&p,1_000_000_000,1_000_000_000,1_000_002_000).is_err());
        assert!(frequency_interval(&p,999_999_999,999_999_999,999_999_999).is_err());
        assert!(frequency_interval(&p,1,2,1).is_err());assert!(frequency_interval(&p,1,0,1).is_err());
    }
    #[test] fn modeled_frequency_u64_extremes_do_not_overflow_cross_products() {
        let p=profile();assert_eq!(frequency_interval(&p,u64::MAX,u64::MAX,u64::MAX),Ok(()));
        assert!(frequency_interval(&p,u64::MAX,1_000_000_000,1_000_000_000).is_err());
        let mut overflow=p;overflow.max_holdover_ms=u64::MAX;
        assert!(frequency_interval(&overflow,u64::MAX,u64::MAX,u64::MAX).is_err());
    }
    #[test] fn modeled_total_initial_width_enforces_existing_inclusive_ceiling() {
        let p=profile();assert_eq!(initial_interval(&p,1000,1500),Ok(()));
        assert!(initial_interval(&p,1000,1501).is_err());assert!(initial_interval(&p,2,1).is_err());
        let mut tighter=p;tighter.max_calibration_half_width_ms=249;
        assert!(initial_interval(&tighter,1000,1500).is_err());
    }
}
