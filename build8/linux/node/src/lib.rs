//! Reusable bounded services for the Build8 node runtime.
// Production exclusion guard for the node LIBRARY (the node bin repeats the custody guards in
// main.rs). Test-fixture and qualification-only features must never be compiled into any
// binary that links this library. Wallet/release custody is NOT asserted here: the wallet
// executable links this library with crypto-v2 `wallet-custody` on by design; the validator
// binary asserts their absence in main.rs.
const _: () = assert!(!mutiny_crypto_v2::RECEIPT_QUALIFICATION_ENABLED,
    "receipt qualification must not be compiled into node-library consumers");
const _: () = assert!(!mutiny_consensus_v8::DIVIDEND_TEST_FIXTURES_ENABLED,
    "dividend test fixtures must not be compiled into node-library consumers");
const _: () = assert!(!mutiny_consensus_v8::LEGACY_V0_TEST_FIXTURES_ENABLED,
    "legacy v0 test fixtures must not be compiled into node-library consumers");

pub mod candidate_journal;
pub mod worker_coordinator;
pub mod worker_protocol;
pub mod worker_server;
pub mod worker_transport;

pub mod state_proof_service;

pub mod deadline_io;

pub mod actor_service;
pub mod body_assembler;
pub mod certificate_assembly;
pub mod genesis_artifact;
pub mod genesis_ceremony;
pub mod integrated_actor;
pub mod local_proposer;
pub mod operation_pool;
pub mod participation_producer;
pub mod peer;
pub mod peer_client;
pub mod peer_gossip;
pub mod peer_server;
pub mod peer_supervisor;
pub mod peer_sync;
pub mod proposer_cursor;
pub mod round_proposal;
pub mod runtime_service;
pub mod tpm_backend;
pub mod vote_journal;
pub mod voter_driver;
pub mod work_probes;

pub mod daemon_shutdown;

pub mod custody_initialization;

pub mod disk_guard;
pub mod production_gate;
pub mod continuity_custody_v2;
pub mod node_custody_v2;
#[cfg(target_os = "linux")]
mod continuity_generation_store_v2;

#[cfg(target_os = "linux")]
mod cancellable_pipe;
pub mod hybrid_runtime_v2;
pub mod history_protocol_v1;
pub mod history_service_v1;
pub mod history_node_host_v1;
pub mod hybrid_sync_v2;
pub mod hybrid_dispatch_v2;
pub mod hybrid_voter_v2;

pub mod work_journal_v2;
pub mod node_generation_preparation_v2;
pub mod hybrid_coordinator_v2;
pub mod host_clock;
pub mod hybrid_work_probes_v2;
pub mod hybrid_probe_dispatch_v2;
pub mod software_coordinator_custody_v2;
pub mod worker_session_custody_v2;
pub mod worker_current_channel_v2;
pub mod worker_carrier_v2;
pub mod worker_handshake_io_v2;
pub mod worker_pending_budget_v2;
pub mod worker_context_router_v2;
pub mod worker_active_connections_v2;
pub mod worker_protocol_v2;
pub mod observation_custody_v2;
pub mod observation_journal_v2;
pub mod candidate_journal_v2;
pub mod candidate_journal_v3;
pub mod a2_operation_pool_v1;
pub mod a2_operation_relay_v1;
pub mod hybrid_a2_dispatch_v1;
mod journal_body_codec_v1;
pub mod hybrid_proposal_dispatch_v3;
pub mod hybrid_proposal_dispatch_v2;
pub mod hybrid_peer_admission_v2;
pub mod hybrid_peer_error_v2;
pub mod hybrid_peer_listener_v2;
pub mod hybrid_peer_worker_v2;
pub mod submission_relay_v1;

#[cfg(feature = "trading-service")]
pub mod trading_service_v1;
pub mod genesis_artifact_v2;
pub mod genesis_ceremony_v2;

pub mod activation_private_owner_v1;

pub mod hybrid_application_v2;
pub mod hybrid_application_stdio_v2;

// Real distinct installed counter client; no Clock qualification role is issued.
mod hybrid_authenticated_counter_v2;
#[cfg(windows)]
mod hybrid_counter_windows_transport_v2;
#[cfg(windows)]
mod hybrid_installed_counter_windows_v2;
#[cfg(windows)]
mod hybrid_counter_windows_current_v2;
// Distinct installed V2 private factory: no caller secret/default issuer.
mod hybrid_existing_custody_v2;
#[cfg(target_os="linux")]
mod hybrid_counter_linux_current_v2;
#[cfg(target_os="linux")]
mod hybrid_installed_counter_v2;
#[cfg(target_os="linux")]
mod hybrid_counter_unix_v2;
#[cfg(target_os="linux")]
mod hybrid_native_retained_input_v2;
#[cfg(target_os="linux")]
mod hybrid_installed_role_inputs_v2;
#[cfg(target_os="linux")]
mod hybrid_native_nv_tools_v2;
#[cfg(target_os="linux")]
mod hybrid_owned_unlock_input_v2;
#[cfg(target_os="linux")]
mod hybrid_unlock_request_v2;
#[cfg(target_os="linux")]
mod hybrid_native_sqlite_linux_v2;
#[cfg(target_os="linux")]
mod hybrid_installed_databases_v2;
#[cfg(target_os="linux")]
mod hybrid_installed_signer_inputs_v2;
#[cfg(target_os="linux")]
mod hybrid_normal_factory_v2;
#[cfg(target_os="linux")]
mod hybrid_installed_secret_source_v2;
#[cfg(target_os="linux")]
mod hybrid_installed_private_worker_v2;
#[cfg(target_os="linux")]
pub mod hybrid_installed_actor_v2;
#[cfg(all(test,target_os="linux"))]
mod modeled_unlock_producer_v2;

#[cfg(target_os="linux")]
mod hybrid_installed_worker_join_v2;

#[cfg(target_os="linux")]
mod hybrid_installed_daemon_v2;

#[cfg(windows)]
mod hybrid_installed_counter_windows_consumer_v2;
