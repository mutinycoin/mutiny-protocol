//! Nonshipping NTS interval conversion. No authority, wall-time era fallback or profile default.
//! Only the genuine authenticated source callback constructs MeasurementFacts.
use ntp_proto::{Measurement, NtpDuration, NtpLeapIndicator, NtpTimestamp};

const NS: i128 = 1_000_000_000;
const NTP_UNIX_SECONDS: i128 = 2_208_988_800;
const ERA_SECONDS: i128 = 1i128 << 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EraWindow {
    lower_ns: u64,
    upper_ns: u64,
}
impl EraWindow {
    /// Must originate in an independently justified deployment time window.
    /// A packet, local current wall clock or unsigned cache cannot justify it.
    pub(crate) fn new(lower_ns: u64, upper_ns: u64) -> Option<Self> {
        if upper_ns.checked_sub(lower_ns)? as i128 >= ERA_SECONDS * NS {
            return None;
        }
        if lower_ns >= upper_ns {
            return None;
        }
        Some(Self { lower_ns, upper_ns })
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    pub max_round_trip_ns: u64,
    pub elapsed_drift_ppb: u64,
    pub max_uncertainty_ns: u64,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct ElapsedPair {
    pub active_ns: u64,
    pub inclusive_ns: u64,
    pub boot_id: u128,
    /// Full bound covering the wall timestamp's position and counter pairing.
    pub uncertainty_ns: u64,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Exchange {
    pub sent: NtpTimestamp,
    pub received: NtpTimestamp,
    pub before: ElapsedPair,
    pub after: ElapsedPair,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Interval {
    pub lower_posix_ns: u64,
    pub upper_posix_ns: u64,
    pub midpoint_active_ns: u64,
    pub midpoint_inclusive_ns: u64,
    pub boot_id: u128,
    pub round_trip_ns: u64,
    pub uncertainty_ns: u64,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct MeasurementFacts {
    remote_midpoint: NtpTimestamp,
    local_midpoint: NtpTimestamp,
    delay: NtpDuration,
    root_delay: NtpDuration,
    root_dispersion: NtpDuration,
    precision: i8,
}
fn nanos_floor(d: NtpDuration) -> i128 {
    let (seconds, nanos) = d.as_seconds_nanos();
    i128::from(seconds) * NS + i128::from(nanos)
}
fn ceil_div(n: i128, d: i128) -> Option<i128> {
    if n < 0 || d <= 0 {
        return None;
    }
    Some(n.checked_add(d - 1)? / d)
}
fn precision_ns(exponent: i8) -> Option<i128> {
    // NTP precision is 2^exponent seconds. Round outward even below one ns.
    if exponent >= 0 {
        NS.checked_mul(1i128.checked_shl(exponent as u32)?)
    } else {
        let shift = -i16::from(exponent);
        if shift >= 127 {
            Some(1)
        } else {
            ceil_div(NS, 1i128.checked_shl(shift as u32)?)
        }
    }
}
fn posix_midpoint(t: NtpTimestamp, w: EraWindow) -> Option<i128> {
    // Public integer API recovers modulo seconds; its fractional conversion
    // floors <1ns. Explicit uncertainty below includes this loss.
    let zero = NtpTimestamp::from_seconds_nanos_since_ntp_era(0, 0);
    let (signed_seconds, fraction_ns) = (t - zero).as_seconds_nanos();
    let seconds = i128::from(signed_seconds as u32);
    let first = (i128::from(w.lower_ns) / NS + NTP_UNIX_SECONDS) / ERA_SECONDS;
    let last = (i128::from(w.upper_ns) / NS + NTP_UNIX_SECONDS) / ERA_SECONDS;
    if last.checked_sub(first)? > 1 {
        return None;
    }
    let mut selected = None;
    for era in first..=last {
        let value = era
            .checked_mul(ERA_SECONDS)?
            .checked_add(seconds)?
            .checked_sub(NTP_UNIX_SECONDS)?
            .checked_mul(NS)?
            .checked_add(i128::from(fraction_ns))?;
        if value >= i128::from(w.lower_ns) && value <= i128::from(w.upper_ns) {
            if selected.replace(value).is_some() {
                return None;
            }
        }
    }
    selected
}
impl MeasurementFacts {
    /// Exact nonsecret arithmetic inputs only. Pinned NtpTimestamp serde exposes
    /// unsigned 32.32 fixed-point bits as `timestamp`; durations use the same
    /// representation modulo 2^64, interpreted as signed two's complement.
    /// Do not use upstream NtpDuration serde: it converts through f64.
    pub(crate) fn public_inputs(&self, x: Exchange) -> serde_json::Value {
        let zero = NtpTimestamp::from_seconds_nanos_since_ntp_era(0, 0);
        fn pair(p: ElapsedPair) -> serde_json::Value {
            serde_json::json!({"active_ns":p.active_ns,"inclusive_ns":p.inclusive_ns,
                "boot_id_hex":format!("{:032x}",p.boot_id),"uncertainty_ns":p.uncertainty_ns})
        }
        serde_json::json!({"format":"MUTINY-NTS-INTEGER-INPUTS-V1",
            "encoding":"Pinned ntp-proto NtpTimestamp timestamp u64 is exact unsigned NTP 32.32; duration fields wrap signed 32.32 bits modulo 2^64",
            "sent_ntp_fixed32":x.sent,"received_ntp_fixed32":x.received,
            "before":pair(x.before),"after":pair(x.after),
            "remote_midpoint_ntp_fixed32":self.remote_midpoint,
            "local_midpoint_ntp_fixed32":self.local_midpoint,
            "delay_signed_fixed32":zero+self.delay,
            "root_delay_signed_fixed32":zero+self.root_delay,
            "root_dispersion_signed_fixed32":zero+self.root_dispersion,
            "precision_exponent":self.precision,
            "classification":"Public diagnostic arithmetic inputs; no independent proof of NTS authentication or measured profile authority"})
    }
    pub(super) fn authenticated_callback(m: &Measurement<NtpDuration>) -> Option<Self> {
        if !(1..=15).contains(&m.stratum)
            || m.leap == NtpLeapIndicator::Unknown
            || m.delay < NtpDuration::ZERO
            || m.root_delay < NtpDuration::ZERO
            || m.root_dispersion < NtpDuration::ZERO
        {
            return None;
        }
        Some(Self {
            remote_midpoint: m.localtime + m.offset,
            local_midpoint: m.localtime,
            delay: m.delay,
            root_delay: m.root_delay,
            root_dispersion: m.root_dispersion,
            precision: m.precision,
        })
    }
    pub(crate) fn interval(&self, x: Exchange, w: EraWindow, limits: Limits) -> Option<Interval> {
        if x.before.boot_id == 0
            || x.before.boot_id != x.after.boot_id
            || limits.max_round_trip_ns == 0
            || limits.max_uncertainty_ns == 0
            || limits.elapsed_drift_ppb == 0
            || limits.elapsed_drift_ppb >= 1_000_000_000
        {
            return None;
        }
        let active = x.after.active_ns.checked_sub(x.before.active_ns)?;
        let inclusive = x.after.inclusive_ns.checked_sub(x.before.inclusive_ns)?;
        if inclusive > limits.max_round_trip_ns {
            return None;
        }
        let wall_ns = nanos_floor(x.received - x.sent);
        let pairs =
            i128::from(x.before.uncertainty_ns).checked_add(i128::from(x.after.uncertainty_ns))?;
        let drift = ceil_div(
            i128::from(inclusive).checked_mul(i128::from(limits.elapsed_drift_ppb))?,
            NS,
        )?;
        let local_budget = pairs.checked_add(drift)?.checked_add(3)?;
        // Local wall labels cancel from the remote midpoint. Still refuse any
        // wall step/rate change not supported by elapsed/profile evidence.
        if wall_ns < 0 || (wall_ns - i128::from(inclusive)).abs() > local_budget {
            return None;
        }
        let wall_midpoint = x.sent + (x.received - x.sent) / 2;
        if nanos_floor(self.local_midpoint - wall_midpoint).abs() > 3 {
            return None;
        }
        let gap = (i128::from(inclusive) - i128::from(active)).abs();
        if gap > local_budget {
            return None;
        } // includes suspend and regressing pairing evidence
        // The source's NTP delay excludes server processing. It cannot exceed
        // the complete elapsed exchange outside the same conservative budget.
        if nanos_floor(self.delay) > i128::from(inclusive).checked_add(local_budget)? {
            return None;
        }
        let root_delay = nanos_floor(self.root_delay).checked_add(1)?;
        let root_dispersion = nanos_floor(self.root_dispersion).checked_add(1)?;
        let uncertainty = ceil_div(i128::from(inclusive), 2)?
            .checked_add(ceil_div(root_delay, 2)?)?
            .checked_add(root_dispersion)?
            .checked_add(precision_ns(self.precision)?)?
            .checked_add(pairs)?
            .checked_add(drift)?
            .checked_add(gap)?
            .checked_add(3)?;
        if uncertainty > i128::from(limits.max_uncertainty_ns) {
            return None;
        }
        let center = posix_midpoint(self.remote_midpoint, w)?;
        let lower = center.checked_sub(uncertainty)?;
        let upper = center.checked_add(uncertainty)?;
        if lower < i128::from(w.lower_ns) || upper > i128::from(w.upper_ns) {
            return None;
        }
        Some(Interval {
            lower_posix_ns: u64::try_from(lower).ok()?,
            upper_posix_ns: u64::try_from(upper).ok()?,
            midpoint_active_ns: x.before.active_ns.checked_add(active / 2)?,
            midpoint_inclusive_ns: x.before.inclusive_ns.checked_add(inclusive / 2)?,
            boot_id: x.before.boot_id,
            round_trip_ns: inclusive,
            uncertainty_ns: u64::try_from(uncertainty).ok()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn t(posix_seconds: u64, nanos: u32) -> NtpTimestamp {
        NtpTimestamp::from_seconds_nanos_since_ntp_era(
            (posix_seconds + 2_208_988_800) as u32,
            nanos,
        )
    }
    fn fixture() -> (MeasurementFacts, Exchange, EraWindow, Limits) {
        let sent = t(1_800_000_000, 0);
        let received = t(1_800_000_000, 100_000_000);
        let midpoint = sent + (received - sent) / 2;
        let facts = MeasurementFacts {
            local_midpoint: midpoint,
            remote_midpoint: midpoint + NtpDuration::from_seconds(0.2),
            delay: NtpDuration::from_seconds(0.09),
            root_delay: NtpDuration::from_seconds(0.002),
            root_dispersion: NtpDuration::from_seconds(0.001),
            precision: -20,
        };
        let before = ElapsedPair {
            active_ns: 1_000_000_000,
            inclusive_ns: 2_000_000_000,
            boot_id: 7,
            uncertainty_ns: 10_000,
        };
        let after = ElapsedPair {
            active_ns: 1_100_000_000,
            inclusive_ns: 2_100_000_000,
            ..before
        };
        (
            facts,
            Exchange {
                sent,
                received,
                before,
                after,
            },
            EraWindow::new(1_799_000_000_000_000_000, 1_801_000_000_000_000_000).unwrap(),
            Limits {
                max_round_trip_ns: 1_000_000_000,
                elapsed_drift_ppb: 100_000,
                max_uncertainty_ns: 250_000_000,
            },
        )
    }
    #[test]
    fn interval_contains_asymmetric_paths_and_every_explicit_uncertainty_term() {
        let (f, x, w, l) = fixture();
        let interval = f.interval(x, w, l).unwrap();
        // Independent worst-case server receive/transmit path placement: full
        // RTT/2 already dominates either extreme. Root/precision/pair/drift add room.
        let earliest = 1_800_000_000_200_000_000u64;
        let latest = 1_800_000_000_300_000_000u64;
        assert!(interval.lower_posix_ns < earliest && interval.upper_posix_ns > latest);
        assert!(interval.uncertainty_ns > 52_000_000);
        assert_eq!(interval.midpoint_active_ns, 1_050_000_000);
        let mut larger = f;
        larger.root_dispersion = NtpDuration::from_seconds(0.2);
        assert!(larger.interval(x, w, l).is_none());
    }
    #[test]
    fn wall_step_suspend_boot_change_and_counter_regression_refuse() {
        let (f, x, w, l) = fixture();
        let mut bad = x;
        bad.received = bad.received + NtpDuration::from_seconds(1.0);
        assert!(f.interval(bad, w, l).is_none());
        bad = x;
        bad.after.inclusive_ns += 100_000_000;
        assert!(f.interval(bad, w, l).is_none());
        bad = x;
        bad.after.boot_id = 8;
        assert!(f.interval(bad, w, l).is_none());
        bad = x;
        bad.after.active_ns = 0;
        assert!(f.interval(bad, w, l).is_none());
        bad = x;
        bad.after.inclusive_ns = 0;
        assert!(f.interval(bad, w, l).is_none());
        bad = x;
        bad.sent = bad.received;
        assert!(f.interval(bad, w, l).is_none());
    }
    #[test]
    fn era_rollover_never_uses_local_wall_time_or_accepts_ambiguous_window() {
        let rollover = ((1u64 << 32) - 2_208_988_800) * 1_000_000_000;
        let w = EraWindow::new(rollover - 2_000_000_000, rollover + 2_000_000_000).unwrap();
        assert_eq!(
            posix_midpoint(t(rollover / 1_000_000_000 - 1, 0), w),
            Some(i128::from(rollover) - NS)
        );
        assert_eq!(
            posix_midpoint(t(rollover / 1_000_000_000 + 1, 0), w),
            Some(i128::from(rollover) + NS)
        );
        assert!(EraWindow::new(0, (1u64 << 32) * 1_000_000_000).is_none());
        assert!(EraWindow::new(2, 1).is_none());
        let (f, x, _, l) = fixture();
        assert!(f.interval(x, w, l).is_none());
    }
    #[test]
    fn outward_rounding_precision_and_exact_budget_boundary() {
        assert_eq!(precision_ns(-128), Some(1));
        assert_eq!(precision_ns(-20), Some(954));
        assert_eq!(precision_ns(1), Some(2_000_000_000));
        assert!(precision_ns(127).is_none());
        let (f, x, w, mut l) = fixture();
        let public = f.public_inputs(x);
        assert!(serde_json::to_vec(&public).unwrap().len() <= 4096);
        let read =
            |name: &str| -> NtpTimestamp { serde_json::from_value(public[name].clone()).unwrap() };
        let zero = NtpTimestamp::from_seconds_nanos_since_ntp_era(0, 0);
        assert_eq!(read("sent_ntp_fixed32"), x.sent);
        assert_eq!(read("received_ntp_fixed32"), x.received);
        let restored = MeasurementFacts {
            remote_midpoint: read("remote_midpoint_ntp_fixed32"),
            local_midpoint: read("local_midpoint_ntp_fixed32"),
            delay: read("delay_signed_fixed32") - zero,
            root_delay: read("root_delay_signed_fixed32") - zero,
            root_dispersion: read("root_dispersion_signed_fixed32") - zero,
            precision: public["precision_exponent"].as_i64().unwrap() as i8,
        };
        let read_pair = |name: &str| -> ElapsedPair {
            let value = &public[name];
            ElapsedPair {
                active_ns: value["active_ns"].as_u64().unwrap(),
                inclusive_ns: value["inclusive_ns"].as_u64().unwrap(),
                boot_id: u128::from_str_radix(value["boot_id_hex"].as_str().unwrap(), 16).unwrap(),
                uncertainty_ns: value["uncertainty_ns"].as_u64().unwrap(),
            }
        };
        let restored_exchange = Exchange {
            sent: read("sent_ntp_fixed32"),
            received: read("received_ntp_fixed32"),
            before: read_pair("before"),
            after: read_pair("after"),
        };
        assert_eq!(
            restored.interval(restored_exchange, w, l),
            f.interval(x, w, l)
        );
        let exact = f.interval(x, w, l).unwrap().uncertainty_ns;
        l.max_uncertainty_ns = exact;
        assert!(f.interval(x, w, l).is_some());
        l.max_uncertainty_ns = exact - 1;
        assert!(f.interval(x, w, l).is_none());
        l.max_uncertainty_ns = 250_000_000;
        l.elapsed_drift_ppb = 1_000_000_000;
        assert!(f.interval(x, w, l).is_none());
        let mut bad = f;
        bad.precision = 127;
        assert!(bad.interval(x, w, l).is_none());
    }
}
