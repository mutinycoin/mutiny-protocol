//! Private TEST controls over the real whole Node clock module graph. No runner,
//! normal dependency, public fixture feature, credential export or OS root edit.
//! Genuine TLS/NTS authentication differs from modeled deployment approval and
//! controlled elapsed fault cases; none proves physical operator independence.
use crate::host_clock::{state_dir, RestoreReport, RETRY_AFTER_EVENT, wake_interval};
use crate::host_clock::native_nts_test_harness::{
    ServiceHarness as NativeNtsService, validate_modeled_deployment,
};
use mutiny_consensus_v8::holdover_clock_v1::{ClockProfile, Elapsed, ElapsedSource};
use std::{sync::{Arc,Mutex}, time::Duration, path::PathBuf};
fn config()->crate::Config {
    crate::Config { providers:(1..=3).map(|n| crate::Provider {
        hostname:format!("source{n}.invalid"),operator:format!("Operator{n}"),
        key_establishment_port:4460,no_smear_profile_evidence_sha256:[n;32],
    }).collect(),timeout_seconds:10,bounds:crate::native_stamp::test_bounds() }
}
fn profile()->ClockProfile {
    // Existing small DEVELOPMENT fixture only. No 24h or hardware qualification.
    ClockProfile { max_source_uncertainty_ms:250,max_calibration_half_width_ms:250,
        min_sources:3,max_faulty_sources:1,drift_bound_ppb:100_000,max_holdover_ms:10_000,
        max_interval_half_width_ms:1000,max_suspend_gap_ms:50,confirm_calibrations:1 }
}
fn checked_profile()->ClockProfile {
    // Match the existing Node development fixture and leave outward/engine room.
    let mut p=profile();p.max_source_uncertainty_ms=248;p
}
fn checked_config()->crate::Config {
    let mut c=config();c.bounds.maximum_interval_uncertainty_ns=200_000_000;c
}
fn anchor(name:&str)->PathBuf {
    static NEXT:std::sync::atomic::AtomicU64=std::sync::atomic::AtomicU64::new(1);
    let root=PathBuf::from(std::env::var_os("BUILD8_NATIVE_NTS_TEST_ROOT")
        .expect("mandatory protected local PUBLIC TEST root; missing input is failure"));
    assert!(root.is_absolute() && root.is_dir());
    assert!(!std::fs::symlink_metadata(&root).unwrap().file_type().is_symlink());
    let leaf=root.join(format!("service-{name}-{}-{}",std::process::id(),
        NEXT.fetch_add(1,std::sync::atomic::Ordering::SeqCst)));
    assert!(!leaf.exists());
    eprintln!("PUBLIC native NTS TEST storage retained: {}",leaf.display());
    leaf.join("clock.anchor")
}
fn service(path:PathBuf)->NativeNtsService {
    NativeNtsService::modeled_test_value(
        checked_profile(),checked_config(),path,Duration::from_secs(1)).unwrap()
}

#[tokio::test(flavor="current_thread")]
async fn genuine_three_operator_reports_calibrate_persist_stop_and_cold_restart() {
    let path=anchor("three-restart");let mut host=service(path.clone());
    let basis=host.basis();let voting=host.vote_clock();
    assert!(basis.lower_bound_ms().is_none());assert!(host.due());
    let report=crate::offline_auth::genuine_test_report(checked_config(),
        ntp_proto::NtpLeapIndicator::NoWarning).await.unwrap();
    assert_eq!(report.usable_operator_count(),3);
    assert_eq!(host.poll_private_test_acquisition(std::future::ready(Ok(report))).await,Ok(true));
    assert!(basis.lower_bound_ms().is_some());assert!(path.is_file());
    assert!(state_dir::ClockStateDir::open(&path).is_err());
    host.stop_handle().stop();
    assert!(basis.lower_bound_ms().is_none());
    assert_eq!(voting.reading(),mutiny_consensus_v8::vote_clock_v1::ClockReading::Unqualified);
    let before=std::fs::read(&path).unwrap();drop(host);
    let reopened=service(path.clone());
    assert!(matches!(reopened.restore_report(),Some(RestoreReport::NotGranted {..})));
    assert!(reopened.basis().lower_bound_ms().is_none());
    assert_eq!(std::fs::read(path).unwrap(),before);
}
#[tokio::test(flavor="current_thread")]
async fn genuine_authenticated_result_from_different_era_context_cannot_change_node_anchor() {
    let path=anchor("context");let mut host=service(path.clone());
    let mut changed=checked_config();changed.bounds.era_context_sha256="b".repeat(64);
    let report=crate::offline_auth::genuine_test_report(changed,
        ntp_proto::NtpLeapIndicator::NoWarning).await.unwrap();
    assert!(host.poll_private_test_acquisition(std::future::ready(Ok(report))).await
        .unwrap_err().contains("different fixed configuration"));
    assert!(host.basis().lower_bound_ms().is_none());assert!(!path.exists());
}
#[tokio::test(flavor="current_thread")]
async fn explicit_stop_cancels_pending_acquisition_without_anchor_or_retained_time_authority() {
    use std::future::Future;
    let path=anchor("cancel");let mut host=service(path.clone());
    let stop=host.stop_handle();let basis=host.basis();
    let future=host.poll_private_test_acquisition(std::future::pending());tokio::pin!(future);
    let waker=std::task::Waker::noop();let mut cx=std::task::Context::from_waker(waker);
    assert!(future.as_mut().poll(&mut cx).is_pending());
    stop.stop();assert!(future.await.unwrap_err().contains("stopped"));
    assert!(!path.exists());assert!(basis.lower_bound_ms().is_none());
}
struct Controlled(Mutex<Elapsed>);
impl ElapsedSource for Controlled { fn read(&self)->Option<Elapsed> {Some(self.0.lock().ok()?.clone())} }
#[tokio::test(flavor="current_thread")]
async fn genuine_anchor_failure_keeps_age_and_controlled_holdover_expiry_refuses_all_consumers() {
    let path=anchor("holdover");let mut host=service(path.clone());
    // Authentication/certificate processing are genuine. Elapsed aging below is
    // explicitly controlled software input; it is not a measured native blackout.
    let report=crate::offline_auth::genuine_test_report(checked_config(),
        ntp_proto::NtpLeapIndicator::NoWarning).await.unwrap();
    let (active,inclusive,boot)=crate::read_elapsed(checked_config().bounds.maximum_sampling_span_ns).unwrap();
    let elapsed=Arc::new(Controlled(Mutex::new(Elapsed {monotonic_ns:active,boottime_ns:inclusive,boot_id:boot})));
    host.replace_elapsed_private_test(elapsed.clone()).unwrap();
    assert_eq!(host.poll_private_test_acquisition(std::future::ready(Ok(report))).await,Ok(true));
    let before=host.diagnostic_anchor_private_test().unwrap();
    let error=host.poll_private_test_acquisition(std::future::ready(Err(std::io::Error::other("PUBLIC TEST source outage")))).await.unwrap_err();
    assert!(error.contains("source outage"));
    let after=host.diagnostic_anchor_private_test().unwrap();
    assert_eq!((before.at,before.lower_ms,before.upper_ms),(after.at,after.lower_ms,after.upper_ms));
    {let mut at=elapsed.0.lock().unwrap();at.monotonic_ns+=10_001_000_000;at.boottime_ns+=10_001_000_000;}
    assert!(host.basis().lower_bound_ms().is_none());
    assert_eq!(host.vote_clock().reading(),mutiny_consensus_v8::vote_clock_v1::ClockReading::Unqualified);
}
#[tokio::test(flavor="current_thread")]
async fn owned_loop_stop_cancels_pending_real_report_slot_and_releases_native_storage() {
    use std::future::Future;
    let path=anchor("owned-loop-cancel");let host=service(path.clone());
    let stop=host.stop_handle();let basis=host.basis();let voting=host.vote_clock();
    let future=host.run_private_test(|_| std::future::pending());tokio::pin!(future);
    let waker=std::task::Waker::noop();let mut cx=std::task::Context::from_waker(waker);
    assert!(future.as_mut().poll(&mut cx).is_pending());
    assert!(state_dir::ClockStateDir::open(&path).is_err());
    stop.stop();assert_eq!(future.await,Ok(()));
    assert!(!path.exists());assert!(basis.lower_bound_ms().is_none());
    assert_eq!(voting.reading(),mutiny_consensus_v8::vote_clock_v1::ClockReading::Unqualified);
    let reopen=service(path);assert!(reopen.basis().lower_bound_ms().is_none());
}
#[tokio::test(flavor="current_thread")]
async fn owning_future_drop_after_genuine_three_source_calibration_poisons_consumer_arcs() {
    use std::future::Future;
    let path=anchor("owned-loop-drop");let host=service(path.clone());
    let basis=host.basis();let voting=host.vote_clock();
    let report=crate::offline_auth::genuine_test_report(checked_config(),
        ntp_proto::NtpLeapIndicator::NoWarning).await.unwrap();
    let mut next=Some(report);
    let mut future=Box::pin(host.run_private_test(move |_| std::future::ready(
        next.take().ok_or_else(|| std::io::Error::other("PUBLIC TEST source outage")))));
    let waker=std::task::Waker::noop();let mut cx=std::task::Context::from_waker(waker);
    assert!(future.as_mut().poll(&mut cx).is_pending());
    assert!(basis.lower_bound_ms().is_some());assert!(path.is_file());
    let bytes=std::fs::read(&path).unwrap();drop(future);
    assert!(basis.lower_bound_ms().is_none());
    assert_eq!(voting.reading(),mutiny_consensus_v8::vote_clock_v1::ClockReading::Unqualified);
    let reopen=service(path.clone());assert!(reopen.basis().lower_bound_ms().is_none());
    assert_eq!(std::fs::read(path).unwrap(),bytes);
}
#[test]
fn owned_loop_uses_existing_local_wake_policy_without_new_clock_numeric_rules() {
    assert_eq!(wake_interval(Duration::from_secs(3600)),RETRY_AFTER_EVENT);
    assert_eq!(wake_interval(Duration::from_secs(1)),Duration::from_secs(1));
    assert_eq!(RETRY_AFTER_EVENT,Duration::from_secs(5));
}

#[test]
fn no_reference_hash_or_small_profile_can_construct_production_deployment_approval() {
    // This is structural modeled validation ONLY; ordinary code has no modeled
    // constructor or deployment issuer. Compile/artifact exclusion remains unrun.
    let mut c=checked_config();c.bounds.era_context_sha256="0".repeat(64);
    assert!(validate_modeled_deployment(checked_profile(),c,
        PathBuf::from("relative.anchor"),Duration::from_secs(1)).is_err());
    assert!(validate_modeled_deployment(checked_profile(),checked_config(),
        std::env::current_dir().unwrap().join("not-opened.anchor"),Duration::ZERO).is_err());
}
