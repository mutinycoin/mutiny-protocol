//! NON-SHIPPING mounted public TEST-VALUE host; shipping crate root never reaches this code.
#![windows_subsystem = "windows"]
#![allow(dead_code)]
const _: () = assert!(cfg!(feature = "testvalue-window"));
const _: () = assert!(!mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED);
const _: () = assert!(!mutiny_crypto_v2::RELEASE_CUSTODY_ENABLED);
mod app;
mod chain;
mod native_driver;
mod original_replay;
mod passive_restart;
mod player;
// Joint Desktop/Linux TEST host: real node, real Genesis bundle, no simulated certification.
mod joint_host;
// Forge's joint run forge-joint-h01-20261015-r1 (wallet side).
mod joint_h01;
// Desktop side of the live B1 acceptance run against Forge's TEST live node (Service-based).
mod service_live;
#[path = "../node_link.rs"]
mod node_link;
#[path = "../history_sync.rs"]
mod history_sync;
#[path = "../service_acceptance.rs"]
mod service_acceptance;
// Distinct NONSHIPPING local public campaign; ordinary crate root never imports these.
#[path = "continuous_control_codec.rs"] mod control_codec;
#[path = "continuous_control_reply.rs"] mod control_reply;
#[path = "continuous_control_budget.rs"] mod control_budget;
#[path = "continuous_control_files.rs"] mod control_files;
#[path = "continuous_image_pin.rs"] mod image_pin;
// TEST1001 mechanics shared by isolated ABI controls and the scoped native receiver.
#[cfg(all(windows, target_arch = "x86_64", feature = "native-owner-test"))]
#[path = "continuous_own_native_token.rs"] mod own_native_token;
#[cfg(all(windows, target_arch = "x86_64", feature = "native-owner-test"))]
#[path = "continuous_own_native_files.rs"] mod own_native_files;
#[cfg(all(windows, target_arch = "x86_64", feature = "native-owner-test"))]
#[path = "continuous_own_native_modules.rs"] mod own_native_modules;
#[cfg(all(windows,target_arch="x86_64",feature="native-owner-test"))]
#[path="continuous_own_native_facade.rs"] mod own_native_facade;
#[cfg(all(windows,target_arch="x86_64",feature="native-owner-test"))]
#[path="continuous_own_native_receiver.rs"] mod own_native_receiver;
#[cfg(all(windows,target_arch="x86_64",feature="native-owner-test"))]
#[path="continuous_root_launch_factory.rs"] mod root_launch_factory;
#[path = "continuous_process_auth.rs"] mod process_auth;
#[path = "continuous_pipe_io.rs"] mod pipe_io;
#[path = "continuous_native_service.rs"] mod native_service;
#[path = "continuous_service_worker.rs"] mod service_worker;
#[path = "continuous_client_workers.rs"] mod client_workers;
#[path = "continuous_bootstrap.rs"] mod bootstrap;
#[path = "continuous_public_roles.rs"] mod public_roles;
#[path = "continuous_role_vault.rs"] mod role_vault;
#[path = "continuous_native_peer_probe.rs"] mod native_peer_probe;
#[path = "continuous_ui.rs"] mod continuous_ui;
#[path = "continuous_launch.rs"] mod continuous_launch;
#[path = "continuous_passive.rs"] mod continuous_passive;
#[path = "continuous_supervisor.rs"] mod continuous_supervisor;
#[path = "continuous_worker_fixture.rs"] mod worker_fixture;
// Private synthetic-only retained-original provider/reopen/shutdown graph.
// No ordinary executable imports or normal dependency/feature edge is added.
#[path = "continuous_test_signer_store.rs"] mod test_signer_store;
#[path = "continuous_existing_six.rs"] mod existing_six;
#[path = "continuous_existing_cache.rs"] mod existing_cache;
#[path = "continuous_certifier_provider.rs"] mod certifier_provider;
#[path = "continuous_existing_role.rs"] mod existing_role;
#[path = "continuous_restart_spec.rs"] mod restart_spec;
#[path = "continuous_cache_snapshot.rs"] mod cache_snapshot;
#[path = "continuous_shutdown.rs"] mod shutdown;
#[path = "continuous_launch_roots.rs"] mod launch_roots;
#[path = "continuous_initial_bootstrap.rs"] mod initial_bootstrap;
// Distinct immutable NativeOwnerTest campaign; fixed wallet mode is unchanged.
#[cfg(feature = "native-owner-test")]
use mutiny_consensus_v8::x509_syntax;
#[cfg(feature = "native-owner-test")]
#[path = "continuous_native_owner_fixture.rs"] mod native_owner_fixture;
#[cfg(feature = "native-owner-test")]
#[path = "continuous_native_owner_driver.rs"] mod native_owner_driver;

#[cfg(test)]
#[path = "continuous_native_controls.rs"] mod native_controls;
#[cfg(test)]
#[path = "continuous_native_junction_control.rs"] mod native_junction_control;
#[cfg(test)]
#[path = "continuous_native_acl_control.rs"] mod native_acl_control;

#[path = "../custody_acl_v2.rs"]
mod custody_acl_v2;
#[path = "../custody_format.rs"]
mod custody_format;
#[path = "../custody_seal.rs"]
mod custody_seal;
#[path = "../dpapi_v2.rs"]
mod dpapi_v2;
#[path = "../operation_outbox.rs"]
mod operation_outbox;
#[path = "../operation_screens.rs"]
mod operation_screens;
#[path = "../payment.rs"]
mod payment;
#[path = "../plan_review.rs"]
mod plan_review;
#[path = "../preimage_store.rs"]
mod preimage_store;
#[path = "../proofs.rs"]
mod proofs;
mod recorder;
#[path = "../store_v2.rs"]
mod store_v2;
#[cfg(test)]
#[path = "../test_support.rs"]
mod test_support;
#[path = "../verified_sync_v2.rs"]
mod verified_sync_v2;
#[path = "../wallet_controller_v2.rs"]
mod wallet_controller_v2;
#[path = "../wallet_v2.rs"]
mod wallet_v2;
fn main() -> eframe::Result {
    test_signer_store::install_sqlite_close_boundary_at_process_entry().map_err(|e| eframe::Error::AppCreation(e.into()))?;
    #[cfg(all(windows,target_arch="x86_64",feature="native-owner-test"))]
    if let Some(result) = root_launch_factory::run_if_requested() { return result.map_err(|e| eframe::Error::AppCreation(e.into())); }
    #[cfg(feature = "native-owner-test")]
    if let Some(result) = native_owner_driver::run_if_requested() { return result.map_err(|e| eframe::Error::AppCreation(e.into())); }
    if let Some(result) = joint_h01::run_if_requested() { return result; }
    if let Some(result) = joint_host::run_if_requested() { return result; }
    if let Some(result) = service_live::run_if_requested() { return result; }
    if let Some(result) = shutdown::assembly_if_requested() { return result.map_err(|e| eframe::Error::AppCreation(e.into())); }
    if let Some(result) = native_peer_probe::run_if_requested() { return result.map_err(|e| eframe::Error::AppCreation(e.into())); }
    if let Some(result) = continuous_supervisor::run_if_requested() { return result.map_err(|e| eframe::Error::AppCreation(e.into())); }
    if let Some(result) = continuous_passive::run_if_requested(false) { return result; }
    if let Some(result) = continuous_launch::run_if_requested(false) { return result; }
    if let Some(result) = passive_restart::run_if_requested() { return result; }
    if let Some(result) = original_replay::run_if_requested() {
        return result.map_err(|e| eframe::Error::AppCreation(e.into()));
    }
    app::run(false)
}
