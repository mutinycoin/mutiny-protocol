//! Private TEST host forwarding over the actual Node service implementation.
//! This entire module is cfg(test); it issues no ordinary deployment authority.
//! Genuine typed reports are produced by the NTS crate's private TLS/NTS fixture.
#![cfg(test)]
use super::{
    RestoreReport,
    native_nts_service::{AuthorizedNativeDeployment, NativeNtsService, StopHandle},
};
use mutiny_clock_native_nts_v1::{AcquisitionReport, Config};
use mutiny_consensus_v8::{
    holdover_clock_v1::{ClockProfile, ElapsedSource, PersistedAnchor, TimeBasis},
    vote_clock_v1::VoteClock,
};
use std::{future::Future, io, path::PathBuf, sync::Arc, time::Duration};

type Result<T> = std::result::Result<T, String>;

/// Checks the existing modeled declaration only; does not open storage.
pub(crate) fn validate_modeled_deployment(
    profile: ClockProfile, config: Config, anchor: PathBuf, cadence: Duration,
) -> Result<()> {
    AuthorizedNativeDeployment::modeled_test_value(profile, config, anchor, cadence)
        .map(|_| ())
}

pub(crate) struct ServiceHarness { service: NativeNtsService }
pub(crate) struct StopHarness { inner: StopHandle }
impl StopHarness {
    pub(crate) fn stop(&self) { self.inner.stop(); }
}
impl ServiceHarness {
    /// Modeled approval only. Actual C8 storage, backend and shared State gate
    /// are reached through their real constructors; no service copy or stubs.
    pub(crate) fn modeled_test_value(
        profile: ClockProfile, config: Config, anchor: PathBuf, cadence: Duration,
    ) -> Result<Self> {
        let deployment=AuthorizedNativeDeployment::modeled_test_value(
            profile,config,anchor,cadence)?;
        Ok(Self { service: NativeNtsService::start(deployment)? })
    }
    pub(crate) fn basis(&self) -> Arc<dyn TimeBasis> { self.service.basis() }
    pub(crate) fn vote_clock(&self) -> Arc<dyn VoteClock> { self.service.vote_clock() }
    pub(crate) fn stop_handle(&self) -> StopHarness {
        StopHarness { inner:self.service.stop_handle() }
    }
    pub(crate) fn restore_report(&self) -> Option<&RestoreReport> {
        self.service.restore_report()
    }
    pub(crate) fn due(&self) -> bool { self.service.due() }
    pub(crate) fn replace_elapsed_private_test(&mut self, elapsed: Arc<dyn ElapsedSource>)
        -> Result<()> {
        self.service.replace_elapsed_private_test(elapsed)
    }
    pub(crate) fn diagnostic_anchor_private_test(&self) -> Option<PersistedAnchor> {
        self.service.diagnostic_anchor_private_test()
    }
    pub(crate) async fn poll_private_test_acquisition(&mut self,
        future: impl Future<Output=io::Result<AcquisitionReport>>) -> Result<bool> {
        self.service.poll_private_test_acquisition(future).await
    }
    pub(crate) async fn run_private_test<F: Future<Output=io::Result<AcquisitionReport>>>(self,
        acquire: impl FnMut(Config)->F) -> Result<()> {
        self.service.run_private_test(acquire).await
    }
}
