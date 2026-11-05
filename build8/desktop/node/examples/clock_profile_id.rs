//! Compute the clock PROFILE IDENTIFIER from a profile JSON, and report the qualification budget
//! rules. Prints no secrets and reads no node configuration beyond the JSON file it is given.
//!
//! Usage:
//!   cargo run --offline --locked --example clock_profile_id -- <profile.json>
//!
//! `<profile.json>` is either the nine-field profile object itself or a node `clock`
//! configuration block (its `profile` member is used). The identifier is
//! `domain_hash("MUTINY-CLOCK-PROFILE-V1", nine u64 big-endian values)` computed by
//! `ClockProfile::id()`; it is computed from the FINALIZED canonical profile, nothing is invented.
//! The identity covers only those nine numbers; it does not cover the NTS source set, the chrony
//! settings, `calibrate_every_s`, `min_nts_selected` or the leap policy constants.
use mutinyd_v8::host_clock::profile_from_json;
use mutiny_consensus_v8::holdover_clock_v1::{FRESH_VOTE_MAX_UNCERTAINTY_MS, drift_budget_ppb};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [path] = args.as_slice() else {
        eprintln!("usage: clock_profile_id <profile.json>");
        std::process::exit(2);
    };
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("cannot read {path}: {e}");
            std::process::exit(2);
        }
    };
    let value: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("not JSON: {e}");
            std::process::exit(2);
        }
    };
    let object = value.get("profile").unwrap_or(&value);
    let profile = match profile_from_json(object) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("profile: {e}");
            std::process::exit(2);
        }
    };
    println!("profile_id_v1 {}", hex::encode(profile.id()));
    println!("max_source_uncertainty_ms {}", profile.max_source_uncertainty_ms);
    println!("max_calibration_half_width_ms {}", profile.max_calibration_half_width_ms);
    println!("min_sources {}", profile.min_sources);
    println!("max_faulty_sources {}", profile.max_faulty_sources);
    println!("drift_bound_ppb {}", profile.drift_bound_ppb);
    println!("max_holdover_ms {}", profile.max_holdover_ms);
    println!("max_interval_half_width_ms {}", profile.max_interval_half_width_ms);
    println!("max_suspend_gap_ms {}", profile.max_suspend_gap_ms);
    println!("confirm_calibrations {}", profile.confirm_calibrations);
    println!("fresh_vote_max_uncertainty_ms {FRESH_VOTE_MAX_UNCERTAINTY_MS}");
    println!(
        "structural_validate {}",
        match profile.validate() {
            Ok(()) => "ok".to_string(),
            Err(e) => format!("{e:?}"),
        }
    );
    println!(
        "qualification_budget {}",
        match profile.validate_qualification() {
            Ok(()) => "ok".to_string(),
            Err(e) => format!("{e:?}"),
        }
    );
    if let Some(ppb) = drift_budget_ppb(
        profile.max_holdover_ms,
        profile.max_calibration_half_width_ms,
        profile.max_interval_half_width_ms,
    ) {
        println!("max_drift_ppb_closing_this_budget (floored) {ppb}");
    }
    println!(
        "max_chrony_error_ms_at_window_0 {}",
        profile
            .max_chrony_error_ms(0)
            .map_or("none".to_string(), |v| v.to_string())
    );
    println!("note: a passing budget is a requirement check, NOT a hardware qualification");
}
