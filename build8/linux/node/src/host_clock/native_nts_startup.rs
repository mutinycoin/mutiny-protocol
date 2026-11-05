//! Concrete ordinary native NTS startup composition. No accepted-input issuer,
//! platform qualification, production registration, or default profile is minted.
use super::{native_nts_deployment_record::select_supported_native,
    native_nts_service::{AuthorizedNativeDeployment, NativeNtsService, StopHandle},
    state_dir::ClockStateDir};
use mutiny_consensus_v8::{holdover_clock_v1::TimeBasis, vote_clock_v1::VoteClock};
use std::sync::Arc;

/// Owns the service/backend/AnchorStore and the same held C8/C12 owner. Consumer
/// Arcs are revocable clocks, not owners; run future cancellation poisons them.
pub(crate) struct NativeClock { service: NativeNtsService }
impl NativeClock {
    pub(crate) fn basis(&self) -> Arc<dyn TimeBasis> { self.service.basis() }
    pub(crate) fn vote_clock(&self) -> Arc<dyn VoteClock> { self.service.vote_clock() }
    pub(crate) fn stop_handle(&self) -> NativeClockStop {
        NativeClockStop {inner:self.service.stop_handle()}
    }
    pub(crate) fn restore_report(&self) -> Option<&super::RestoreReport> {
        self.service.restore_report()
    }
    pub(crate) async fn run(self) -> Result<(),String> { self.service.run().await }
}
pub(crate) struct NativeClockStop { inner: StopHandle }
impl NativeClockStop {
    pub(crate) fn stop(&self) { self.inner.stop(); }
    pub(super) fn freeze_for_replacement(&self)
        ->Result<super::anchor_store::ReplacementContinuity,String> {
        self.inner.freeze_for_replacement()
    }
}

/// Already-held owner only: no pathname reopening or generation of caller
/// approval pins. Select before NativeNtsBackend performs anchor restore. Actual
/// accepted inputs/current receipt are absent, so this candidate always refuses.
pub(super) fn start(record: &[u8], genesis: &[u8], state: ClockStateDir)
    -> Result<NativeClock,String> {
    let (record,placement)=select_supported_native(record,genesis,state)
        .map_err(|e|format!("native startup inputs refused: {e:?}"))?;
    let deployment=AuthorizedNativeDeployment::from_validated(record,placement)?;
    Ok(NativeClock {service:NativeNtsService::start(deployment)?})
}

/// Public application composition reaches this private selected-input route.
/// Missing accepted/current receipts fail before anchor open or task creation.
pub(super) fn start_installed(record:&[u8],genesis:&[u8])->Result<NativeClock,String> {
    let (record,placement)=super::native_nts_deployment_record::select_installed_native(record,genesis)
        .map_err(|e|format!("native startup inputs refused: {e:?}"))?;
    let deployment=AuthorizedNativeDeployment::from_validated(record,placement)?;
    Ok(NativeClock {service:NativeNtsService::start(deployment)?})
}

/// Existing installed authority and genuine/current validation remain required.
/// A one-use predecessor lineage token can only preserve/refuse a floor; it
/// cannot approve a record, restore qualification or replace accepted inputs.
pub(super) fn start_installed_replacement(record:&[u8],genesis:&[u8],
    continuity:super::anchor_store::ReplacementContinuity)->Result<NativeClock,String> {
    let (record,placement)=super::native_nts_deployment_record::select_installed_native_replacement(
        record,genesis,&continuity)
        .map_err(|e|format!("native replacement startup inputs refused: {e:?}"))?;
    let deployment=AuthorizedNativeDeployment::from_validated_replacement(record,placement,continuity)?;
    Ok(NativeClock {service:NativeNtsService::start(deployment)?})
}
