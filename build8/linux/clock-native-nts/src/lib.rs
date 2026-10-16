//! Native NTS acquisition shared with the node, without a diagnostic JSON bridge.
//! Public configuration supplies deployment assumptions, never authenticates them.
//! Results have private fields and no Deserialize or caller assertion constructor.
//! This library neither steers the OS clock nor grants restart/production authority.
mod bounded_io;
mod integer_interval;
mod diagnostic_reconstruction;
mod acquisition_export;
pub use acquisition_export::{RetainedAcquisition,LiveVerifiedExport,retain_acquisition,try_retain_acquisition};
pub use diagnostic_reconstruction::{DiagnosticInterval, reconstruct_diagnostic_interval};
#[cfg(target_os = "linux")]
mod native_linux_elapsed;
mod native_stamp;
mod native_elapsed_interval;
pub use native_elapsed_interval::{NativeElapsedInterval,capture_elapsed_interval};
mod native_windows_elapsed;
mod observer;
#[cfg(test)]
mod offline_auth;
// Private same-source software adapter tests only; no public fixture feature.
#[cfg(test)]
extern crate self as mutiny_clock_native_nts_v1;
#[cfg(test)]
#[path = "../../node/src/host_clock.rs"]
mod host_clock;
#[cfg(test)]
#[path = "../../node/src/genesis_artifact.rs"]
mod genesis_artifact;
#[cfg(test)]
#[path = "../../node/src/genesis_artifact_v2.rs"]
mod genesis_artifact_v2;
#[cfg(test)]
mod node_service_tests;
// Private Linux same-source closure for the already included real Node owner.
// Reuse existing modules and every nested TEST module; no shipping edge.
#[cfg(all(test, target_os = "linux"))]
#[path = "../../node/src/candidate_journal_v2.rs"]
mod candidate_journal_v2;
#[cfg(all(test, target_os = "linux"))]
#[path = "../../node/src/candidate_journal_v3.rs"]
mod candidate_journal_v3;
#[cfg(all(test, target_os = "linux"))]
#[path = "../../node/src/continuity_custody_v2.rs"]
mod continuity_custody_v2;
#[cfg(all(test, target_os = "linux"))]
#[path = "../../node/src/continuity_generation_store_v2.rs"]
mod continuity_generation_store_v2;
#[cfg(all(test, target_os = "linux"))]
#[path = "../../node/src/custody_initialization.rs"]
mod custody_initialization;
#[cfg(all(test, target_os = "linux"))]
#[path = "../../node/src/hybrid_counter_linux_current_v2.rs"]
mod hybrid_counter_linux_current_v2;
#[cfg(all(test, target_os = "linux"))]
#[path = "../../node/src/hybrid_installed_counter_v2.rs"]
mod hybrid_installed_counter_v2;
#[cfg(all(test, target_os = "linux"))]
#[path = "../../node/src/hybrid_installed_databases_v2.rs"]
mod hybrid_installed_databases_v2;
#[cfg(all(test, target_os = "linux"))]
#[path = "../../node/src/hybrid_installed_secret_source_v2.rs"]
mod hybrid_installed_secret_source_v2;
#[cfg(all(test, target_os = "linux"))]
#[path = "../../node/src/hybrid_installed_signer_inputs_v2.rs"]
mod hybrid_installed_signer_inputs_v2;
#[cfg(all(test, target_os = "linux"))]
#[path = "../../node/src/hybrid_native_retained_input_v2.rs"]
mod hybrid_native_retained_input_v2;
#[cfg(all(test, target_os = "linux"))]
#[path = "../../node/src/hybrid_probe_dispatch_v2.rs"]
mod hybrid_probe_dispatch_v2;
#[cfg(all(test, target_os = "linux"))]
#[path = "../../node/src/hybrid_runtime_v2.rs"]
mod hybrid_runtime_v2;
#[cfg(all(test, target_os = "linux"))]
#[path = "../../node/src/hybrid_voter_v2.rs"]
mod hybrid_voter_v2;
#[cfg(all(test, target_os = "linux"))]
#[path = "../../node/src/hybrid_work_probes_v2.rs"]
mod hybrid_work_probes_v2;
#[cfg(all(test, target_os = "linux"))]
#[path = "../../node/src/state_proof_service.rs"]
mod state_proof_service;
mod windows_boot;
pub use native_stamp::AcquisitionBounds;
use ntp_proto::{
    KeyExchangeClient, NtpClock, NtpInstant, NtpLeapIndicator, NtpSourceAction, NtsClientConfig,
    ProtocolVersion, SourceConfig, SynchronizationConfig, System,
};
use observer::{ObserverController, ReadOnlyClock};
use std::{collections::BTreeSet, io, sync::Arc, time::Duration};
use tokio::net::{TcpStream, UdpSocket};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provider {
    pub hostname: String,
    /// Configured public profile's operator identity. A label is not proof of independence.
    pub operator: String,
    pub key_establishment_port: u16,
    /// Exact retained public evidence reference; verification belongs to deployment admission.
    pub no_smear_profile_evidence_sha256: [u8; 32],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub providers: Vec<Provider>,
    pub timeout_seconds: u64,
    pub bounds: AcquisitionBounds,
}
impl Config {
    pub fn validate(&self) -> io::Result<()> {
        self.bounds.validate()?;
        if !(3..=8).contains(&self.providers.len()) || !(1..=60).contains(&self.timeout_seconds) {
            return Err(fail("source count or I/O bound"));
        }
        let mut hosts = BTreeSet::new();
        let mut operators = BTreeSet::new();
        for p in &self.providers {
            if p.hostname.is_empty()
                || p.hostname.len() > 253
                || p.hostname.starts_with('.')
                || p.hostname.ends_with('.')
                || p.hostname.contains("..")
                || !p
                    .hostname
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
                || p.operator.is_empty()
                || p.operator.len() > 64
                || !p
                    .operator
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
                || p.key_establishment_port == 0
                || p.no_smear_profile_evidence_sha256 == [0; 32]
                || !hosts.insert(&p.hostname)
            {
                return Err(fail("invalid/duplicate exact source profile"));
            }
            operators.insert(&p.operator);
        }
        if operators.len() < 3 {
            return Err(fail("fewer than three declared independent operators"));
        }
        Ok(())
    }
}
fn fail(s: &str) -> io::Error {
    io::Error::other(s)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Leap {
    Clear,
    Insert,
    Delete,
}
/// Immutable view only. Possessing these numbers is not an authenticated observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntervalView {
    pub lower_posix_ns: u64,
    pub upper_posix_ns: u64,
    pub active_ns: u64,
    pub inclusive_ns: u64,
    pub boot_id: u128,
    pub round_trip_ns: u64,
    pub uncertainty_ns: u64,
}
/// Native elapsed reading only. This conveys neither UTC nor restart authority.
pub fn read_elapsed(maximum_sampling_span_ns: u64) -> Option<(u64, u64, u128)> {
    if !(1..=1_000_000_000).contains(&maximum_sampling_span_ns) {
        return None;
    }
    #[cfg(windows)]
    let elapsed =
        native_windows_elapsed::WindowsElapsed::new(Duration::from_nanos(maximum_sampling_span_ns))
            .ok()?
            .capture()?
            .elapsed;
    #[cfg(target_os = "linux")]
    let elapsed =
        native_linux_elapsed::LinuxElapsed::new(Duration::from_nanos(maximum_sampling_span_ns))
            .ok()?
            .capture()?
            .elapsed;
    #[cfg(any(windows, target_os = "linux"))]
    return Some((elapsed.monotonic_ns, elapsed.boottime_ns, elapsed.boot_id));
    #[cfg(not(any(windows, target_os = "linux")))]
    None
}
/// Actual counter triple retention, diagnostic only. No caller raw constructor,
/// authentication, accepted experimental reference, qualification or disk writer.
pub struct DiagnosticElapsedCapture {raw:Vec<u8>,active:u64,inclusive:u64,boot:u128}
impl DiagnosticElapsedCapture {
    pub fn raw(&self)->&[u8] {&self.raw}
    pub fn reading(&self)->(u64,u64,u128) {(self.active,self.inclusive,self.boot)}
}
pub fn read_elapsed_diagnostic(maximum_sampling_span_ns:u64)->Option<DiagnosticElapsedCapture> {
    if !(1..=1_000_000_000).contains(&maximum_sampling_span_ns) {return None;}
    #[cfg(windows)]
    let capture=native_windows_elapsed::WindowsElapsed::new(Duration::from_nanos(maximum_sampling_span_ns)).ok()?.capture()?;
    #[cfg(target_os="linux")]
    let capture=native_linux_elapsed::LinuxElapsed::new(Duration::from_nanos(maximum_sampling_span_ns)).ok()?.capture()?;
    #[cfg(any(windows,target_os="linux"))]
    {
        let raw=diagnostic_reconstruction::encode(&serde_json::json!({
            "active_before_ns":capture.active_before_ns,"active_after_ns":capture.active_after_ns,
            "inclusive_ns":capture.elapsed.boottime_ns,"boot_id_hex":format!("{:032x}",capture.elapsed.boot_id)})).ok()?;
        Some(DiagnosticElapsedCapture {raw,active:capture.elapsed.monotonic_ns,
            inclusive:capture.elapsed.boottime_ns,boot:capture.elapsed.boot_id})
    }
    #[cfg(not(any(windows,target_os="linux")))]
    None
}
/// Constructed only after real NTS key establishment and usable authenticated response.
/// No public constructor, Deserialize, boolean authenticity field or replay import exists.
pub struct AuthenticatedObservation {
    hostname: String,
    operator: String,
    profile: [u8; 32],
    interval: IntervalView,
    leap: Leap,
    diagnostic:DiagnosticTranscript,
}
/// Public numerical retention only. No keys, cookies, packet/TLS transcript,
/// exporter material, authentication proof, replay constructor or disk writer.
pub struct DiagnosticTranscript {
    arithmetic:Vec<u8>, response_bytes:usize, stratum:u8,
    provider:Provider,bounds:AcquisitionBounds,destination:std::net::SocketAddr,
}
impl DiagnosticTranscript {
    pub fn arithmetic(&self)->&[u8] {&self.arithmetic}
    pub fn response_bytes(&self)->usize {self.response_bytes}
    pub fn stratum(&self)->u8 {self.stratum}
    pub fn provider(&self)->&Provider {&self.provider}
    pub fn bounds(&self)->&AcquisitionBounds {&self.bounds}
    pub fn destination(&self)->std::net::SocketAddr {self.destination}
}
impl AuthenticatedObservation {
    /// Caller must retain provider/config scope separately. Exporting these
    /// bytes strips live callback provenance; numeric replay is untrusted.
    pub fn diagnostic_transcript(&self)->&DiagnosticTranscript {&self.diagnostic}
    pub fn hostname(&self) -> &str {
        &self.hostname
    }
    pub fn operator(&self) -> &str {
        &self.operator
    }
    pub fn profile_reference(&self) -> [u8; 32] {
        self.profile
    }
    pub fn interval(&self) -> IntervalView {
        self.interval
    }
    pub fn leap(&self) -> Leap {
        self.leap
    }
}
pub struct AcquisitionReport {
    // Exact immutable inputs used by this acquisition, not deployment approval.
    // Prevent a genuine result from a different Era/error/source context being
    // fed into a backend's independently fixed configuration.
    config: Config,
    accepted: Vec<AuthenticatedObservation>,
    /// Bounded public source identity and error class only; never key/cookie/transcript bytes.
    failures: Vec<(String, io::ErrorKind)>,
}
impl AcquisitionReport {
    pub fn matches_config(&self, expected: &Config) -> bool {
        &self.config == expected
    }
    pub fn accepted(&self) -> &[AuthenticatedObservation] {
        &self.accepted
    }
    pub fn failures(&self) -> &[(String, io::ErrorKind)] {
        &self.failures
    }
    pub fn usable_operator_count(&self) -> usize {
        self.accepted
            .iter()
            .map(|o| o.operator())
            .collect::<BTreeSet<_>>()
            .len()
    }
}
/// Poll sources concurrently, retain deterministic configured order, count one usable
/// response per configured operator. Losing sources does not invalidate an existing holdover.
pub async fn acquire(config: Config) -> io::Result<AcquisitionReport> {
    acquire_cancellable(config,std::future::pending()).await?
        .ok_or_else(||fail("uncancelled acquisition unexpectedly cancelled"))
}
/// Owner cancellation is a lifecycle signal, never a calibration or report.
/// Every spawned source task is aborted and then joined before a cancellation
/// result returns. Dropping/aborting this entire future is not closure evidence.
pub async fn acquire_cancellable(config: Config,
    cancelled:impl std::future::Future<Output=()>) -> io::Result<Option<AcquisitionReport>> {
    config.validate()?;
    let exact_config = config.clone();
    let mut jobs = tokio::task::JoinSet::new();
    for (index, p) in config.providers.into_iter().enumerate() {
        let bounds = config.bounds.clone();
        let timeout = Duration::from_secs(config.timeout_seconds);
        jobs.spawn(async move {
            let host = p.hostname.clone();
            let result = match tokio::time::timeout(timeout, observe(&p, &bounds)).await {
                Ok(r) => r.map_err(|e| e.kind()),
                Err(_) => Err(io::ErrorKind::TimedOut),
            };
            (index, host, result)
        });
    }
    let mut rows = Vec::new();
    let mut cancelled=std::pin::pin!(cancelled);
    loop {
        // Cancellation wins an already-ready acquisition. Join cancellation
        // outcomes before revocation/selection cleanup may report closure.
        let row=tokio::select! {biased;
            _=cancelled.as_mut()=>{
                jobs.abort_all();
                while jobs.join_next().await.is_some() {}
                return Ok(None);
            },
            row=jobs.join_next()=>row,
        };
        match row {
            None=>break,
            Some(Ok(row))=>rows.push(row),
            Some(Err(_))=>{
                jobs.abort_all();
                while jobs.join_next().await.is_some() {}
                return Err(fail("source task failed; no calibration authority"));
            },
        }
    }
    rows.sort_by_key(|r| r.0);
    let mut operators = BTreeSet::new();
    let mut report = AcquisitionReport {
        config: exact_config,
        accepted: Vec::new(),
        failures: Vec::new(),
    };
    for (_, host, result) in rows {
        match result {
            Ok(o) if operators.insert(o.operator.clone()) => report.accepted.push(o),
            Ok(_) => {}
            Err(kind) => report.failures.push((host, kind)),
        }
    }
    Ok(Some(report))
}

async fn observe(p: &Provider, bounds: &AcquisitionBounds) -> io::Result<AuthenticatedObservation> {
    let clock = ReadOnlyClock::default();
    let stamp = native_stamp::NativeStamp::new(bounds.clone())?;
    let tls = KeyExchangeClient::new(&NtsClientConfig::default()).map_err(io::Error::other)?;
    let tcp = TcpStream::connect((p.hostname.as_str(), p.key_establishment_port)).await?;
    // TLS hostname/certificate/OS-root validation is unchanged; no test roots here.
    let keys = tls
        .exchange_keys(
            bounded_io::BoundedIo::new(tcp),
            p.hostname.clone(),
            std::iter::empty(),
        )
        .await
        .map_err(io::Error::other)?;
    let destination = tokio::net::lookup_host((keys.remote.as_str(), keys.port))
        .await?
        .next()
        .ok_or_else(|| fail("no negotiated NTS destination"))?;
    let socket = UdpSocket::bind(if destination.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await?;
    socket.connect(destination).await?;
    let mut system = System::<u8, ObserverController>::new(
        clock.clone(),
        SynchronizationConfig::default(),
        (),
        Arc::new([]),
    )?;
    let (mut source, _) = system.create_ntp_source(
        0,
        SourceConfig::default(),
        destination,
        ProtocolVersion::V4,
        Some(keys.nts),
    )?;
    let mut sent = None;
    for action in source.handle_timer() {
        if let NtpSourceAction::Send(bytes) = action {
            if sent.is_some() {
                return Err(fail("multiple poll packets"));
            }
            let pair = stamp.read_recorded(&clock)?;
            if socket.send(&bytes).await? != bytes.len() {
                return Err(fail("partial UDP send"));
            }
            sent = Some(pair);
        }
    }
    let sent_record = sent.ok_or_else(|| fail("authenticated poll unavailable"))?;
    let sent=sent_record.timestamp;let before=sent_record.pair;
    let mut bytes = [0u8; 1025];
    let length = socket.recv(&mut bytes).await?;
    let received_record = stamp.read_recorded(&clock)?;
    let received=received_record.timestamp;let after=received_record.pair;
    if !(48..=1024).contains(&length) {
        return Err(fail("response size"));
    }
    let _: Vec<_> = source
        .handle_incoming(&bytes[..length], NtpInstant::now(), sent, received)
        .collect();
    let sample = {
        let rows = clock
            .samples
            .lock()
            .map_err(|_| fail("observer poisoned"))?;
        if rows.len() != 1 {
            return Err(fail("no current authenticated usable response"));
        }
        rows[0].clone()
    };
    let interval = sample
        .integer
        .interval(
            integer_interval::Exchange {
                sent,
                received,
                before,
                after,
            },
            bounds
                .era()
                .ok_or_else(|| fail("explicit Era window refused"))?,
            bounds.limits(),
        )
        .ok_or_else(|| fail("integer interval refused"))?;
    let leap = match sample.leap {
        NtpLeapIndicator::NoWarning => Leap::Clear,
        NtpLeapIndicator::Leap61 => Leap::Insert,
        NtpLeapIndicator::Leap59 => Leap::Delete,
        _ => return Err(fail("unusable leap indication")),
    };
    let arithmetic=sample.integer.retained_raw(&sent_record,&received_record)?;
    // An absent/partial capture refuses. This is same-producer arithmetic
    // equality, not independent authentication or method qualification.
    let reconstructed=reconstruct_diagnostic_interval(&arithmetic,bounds)?.view();
    let expected=IntervalView {lower_posix_ns:interval.lower_posix_ns,upper_posix_ns:interval.upper_posix_ns,
        active_ns:interval.midpoint_active_ns,inclusive_ns:interval.midpoint_inclusive_ns,
        boot_id:interval.boot_id,round_trip_ns:interval.round_trip_ns,uncertainty_ns:interval.uncertainty_ns};
    if reconstructed!=expected {return Err(fail("actual retained arithmetic differs from live interval"));}
    Ok(AuthenticatedObservation {
        hostname: p.hostname.clone(),
        operator: p.operator.clone(),
        profile: p.no_smear_profile_evidence_sha256,
        interval: IntervalView {
            lower_posix_ns: interval.lower_posix_ns,
            upper_posix_ns: interval.upper_posix_ns,
            active_ns: interval.midpoint_active_ns,
            inclusive_ns: interval.midpoint_inclusive_ns,
            boot_id: interval.boot_id,
            round_trip_ns: interval.round_trip_ns,
            uncertainty_ns: interval.uncertainty_ns,
        },
        leap,
        diagnostic:DiagnosticTranscript {arithmetic,response_bytes:length,stratum:sample.stratum,
            provider:p.clone(),bounds:bounds.clone(),destination},
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> Config {
        Config {
            providers: (1..=3)
                .map(|n| Provider {
                    hostname: format!("source{n}.invalid"),
                    operator: format!("Operator{n}"),
                    key_establishment_port: 4460,
                    no_smear_profile_evidence_sha256: [n; 32],
                })
                .collect(),
            timeout_seconds: 10,
            bounds: native_stamp::test_bounds(),
        }
    }
    #[test]
    fn explicit_profile_and_operator_requirements_refuse_missing_or_duplicate_inputs() {
        let c = config();
        assert!(c.validate().is_ok());
        let mut bad = c.clone();
        bad.providers[0].no_smear_profile_evidence_sha256 = [0; 32];
        assert!(bad.validate().is_err());
        let mut bad = c.clone();
        bad.providers[2].operator = bad.providers[1].operator.clone();
        assert!(bad.validate().is_err());
        let mut bad = c;
        bad.providers[2].hostname = bad.providers[1].hostname.clone();
        assert!(bad.validate().is_err());
    }
}
