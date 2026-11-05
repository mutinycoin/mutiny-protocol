//! Read-only NTS observer. No steering, service installation or voting authority.
//! ntp-proto is pinned because its internal API explicitly has no stability guarantee.
use ntp_proto::{
    Measurement, NtpClock, NtpDuration, NtpLeapIndicator, NtpTimestamp, ObservableSourceTimedata,
    PollInterval, SourceConfig, SourceController, StateUpdate, SynchronizationConfig,
    TimeSyncController,
};
use std::{
    io,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Default)]
pub struct ReadOnlyClock {
    pub samples: Arc<Mutex<Vec<Sample>>>,
}
fn forbidden<T>() -> io::Result<T> {
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "clock steering is forbidden",
    ))
}
impl NtpClock for ReadOnlyClock {
    type Error = io::Error;
    fn now(&self) -> io::Result<NtpTimestamp> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?;
        let seconds = now
            .as_secs()
            .checked_add(2_208_988_800)
            .ok_or_else(|| io::Error::other("NTP epoch overflow"))?;
        // Era modulo is defined by NTP; OS time is only a packet timestamp, not calibration.
        Ok(NtpTimestamp::from_seconds_nanos_since_ntp_era(
            seconds as u32,
            now.subsec_nanos(),
        ))
    }
    fn set_frequency(&self, _: f64) -> io::Result<NtpTimestamp> {
        forbidden()
    }
    fn get_frequency(&self) -> io::Result<f64> {
        forbidden()
    }
    fn step_clock(&self, _: NtpDuration) -> io::Result<NtpTimestamp> {
        forbidden()
    }
    fn disable_ntp_algorithm(&self) -> io::Result<()> {
        forbidden()
    }
    fn error_estimate_update(&self, _: NtpDuration, _: NtpDuration) -> io::Result<()> {
        forbidden()
    }
    fn status_update(&self, _: NtpLeapIndicator) -> io::Result<()> {
        forbidden()
    }
}

#[derive(Clone, Debug)]
pub struct Sample {
    pub(crate) integer: super::integer_interval::MeasurementFacts,
    pub delay_seconds: f64,
    pub offset_seconds: f64,
    pub root_delay_seconds: f64,
    pub root_dispersion_seconds: f64,
    pub precision: i8,
    pub leap: NtpLeapIndicator,
    pub stratum: u8,
}
pub struct Observer<D: std::fmt::Debug + Copy + Clone> {
    samples: Arc<Mutex<Vec<Sample>>>,
    _delay: std::marker::PhantomData<D>,
}
impl<D: std::fmt::Debug + Copy + Clone + Send + 'static> SourceController for Observer<D> {
    type ControllerMessage = ();
    type SourceMessage = ();
    type MeasurementDelay = D;
    fn handle_message(&mut self, _: ()) {}
    fn handle_measurement(&mut self, _: Measurement<D>) -> Option<()> {
        None
    }
    fn desired_poll_interval(&self) -> PollInterval {
        PollInterval::from_byte(4)
    }
    fn observe(&self) -> ObservableSourceTimedata {
        ObservableSourceTimedata::default()
    }
}
// Only authenticated NTP source processing calls this implementation. No external sample input.
pub struct TwoWayObserver {
    samples: Arc<Mutex<Vec<Sample>>>,
}
impl SourceController for TwoWayObserver {
    type ControllerMessage = ();
    type SourceMessage = ();
    type MeasurementDelay = NtpDuration;
    fn handle_message(&mut self, _: ()) {}
    fn handle_measurement(&mut self, m: Measurement<NtpDuration>) -> Option<()> {
        let integer = super::integer_interval::MeasurementFacts::authenticated_callback(&m)?;
        let sample = Sample {
            integer,
            delay_seconds: m.delay.to_seconds(),
            offset_seconds: m.offset.to_seconds(),
            root_delay_seconds: m.root_delay.to_seconds(),
            root_dispersion_seconds: m.root_dispersion.to_seconds(),
            precision: m.precision,
            leap: m.leap,
            stratum: m.stratum,
        };
        // Fail closed on nonsensical/unsynchronized measurements. The diagnostic bound
        // is NOT a qualification profile or a replacement for holdover uncertainty rules.
        if [
            sample.delay_seconds,
            sample.offset_seconds,
            sample.root_delay_seconds,
            sample.root_dispersion_seconds,
        ]
        .iter()
        .any(|x| !x.is_finite() || x.abs() > 1_000_000.0)
            || sample.delay_seconds < 0.0
            || sample.root_delay_seconds < 0.0
            || sample.root_dispersion_seconds < 0.0
            || !(1..=15).contains(&sample.stratum)
            || matches!(sample.leap,NtpLeapIndicator::Unknown|NtpLeapIndicator::Unsynchronized)
        {
            return None;
        }
        let Ok(mut rows) = self.samples.lock() else {
            return None;
        };
        if rows.len() < 4 {
            rows.push(sample);
        }
        None
    }
    fn desired_poll_interval(&self) -> PollInterval {
        PollInterval::from_byte(4)
    }
    fn observe(&self) -> ObservableSourceTimedata {
        ObservableSourceTimedata::default()
    }
}

pub struct ObserverController {
    pub samples: Arc<Mutex<Vec<Sample>>>,
}
impl TimeSyncController for ObserverController {
    type Clock = ReadOnlyClock;
    type SourceId = u8;
    type AlgorithmConfig = ();
    type ControllerMessage = ();
    type SourceMessage = ();
    type NtpSourceController = TwoWayObserver;
    type OneWaySourceController = Observer<()>;
    fn new(clock: ReadOnlyClock, _: SynchronizationConfig, _: ()) -> io::Result<Self> {
        Ok(Self {
            samples: clock.samples,
        })
    }
    // This controller deliberately never takes control of the OS clock.
    fn take_control(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn add_source(&mut self, _: u8, _: SourceConfig) -> TwoWayObserver {
        TwoWayObserver {
            samples: self.samples.clone(),
        }
    }
    fn add_one_way_source(
        &mut self,
        _: u8,
        _: SourceConfig,
        _: f64,
        _: f64,
        _: Option<f64>,
    ) -> Observer<()> {
        Observer {
            samples: self.samples.clone(),
            _delay: std::marker::PhantomData,
        }
    }
    fn remove_source(&mut self, _: u8) {}
    fn source_update(&mut self, _: u8, _: bool) {}
    fn source_message(&mut self, _: u8, _: ()) -> StateUpdate<u8, ()> {
        StateUpdate::default()
    }
    fn time_update(&mut self) -> StateUpdate<u8, ()> {
        StateUpdate::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn all_clock_mutation_methods_refuse() {
        let c = ReadOnlyClock::default();
        assert!(c.now().is_ok());
        assert!(c.set_frequency(0.0).is_err());
        assert!(c.get_frequency().is_err());
        assert!(c.step_clock(NtpDuration::ZERO).is_err());
        assert!(c.disable_ntp_algorithm().is_err());
        assert!(
            c.error_estimate_update(NtpDuration::ZERO, NtpDuration::ZERO)
                .is_err()
        );
        assert!(c.status_update(NtpLeapIndicator::NoWarning).is_err());
    }
}
