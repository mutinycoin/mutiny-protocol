//! Native NTS qualification observer. Its output cannot enable the voting clock.
mod bounded_io;
mod integer_interval;
#[cfg(target_os = "linux")]
mod native_linux_elapsed;
mod native_stamp;
mod native_windows_elapsed;
mod observer;
#[cfg(test)]
mod offline_auth;
mod windows_boot;
use ntp_proto::{
    KeyExchangeClient, NtpClock, NtpInstant, NtpSourceAction, NtsClientConfig, ProtocolVersion,
    SourceConfig, SynchronizationConfig, System,
};
use observer::{ObserverController, ReadOnlyClock};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    io,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::net::{TcpStream, UdpSocket};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Provider {
    hostname: String,
    operator: String,
    key_establishment_port: u16,
    // Missing public profile is recorded honestly in a diagnostic. It can never
    // enable calibration or qualify this provider's leap policy.
    no_smear_profile_evidence_sha256: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    providers: Vec<Provider>,
    timeout_seconds: u64,
    diagnostic_bounds: native_stamp::DiagnosticBounds,
}
#[derive(Serialize)]
struct Receipt {
    hostname: String,
    operator: String,
    negotiated_server: String,
    negotiated_port: u16,
    no_smear_profile_evidence_sha256: Option<String>,
    current_authenticated_response: bool,
    corrupted_packet_refused: bool,
    exact_response_replay_refused: bool,
    elapsed_capture_ns: u128,
    delay_seconds: f64,
    offset_seconds: f64,
    root_delay_seconds: f64,
    root_dispersion_seconds: f64,
    precision: i8,
    leap: String,
    stratum: u8,
    integer_interval: serde_json::Value,
    integer_inputs: serde_json::Value,
}
fn fail(message: &str) -> io::Error {
    io::Error::other(message)
}
fn validate(c: &Config) -> io::Result<()> {
    c.diagnostic_bounds.validate()?;
    if !(3..=8).contains(&c.providers.len()) || !(1..=60).contains(&c.timeout_seconds) {
        return Err(fail(
            "qualification provider count or deployment I/O timeout bound",
        ));
    }
    let mut hosts = BTreeSet::new();
    let mut operators = BTreeSet::new();
    for p in &c.providers {
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
            || p.no_smear_profile_evidence_sha256
                .as_ref()
                .is_some_and(|s| {
                    s.len() != 64
                        || !s.bytes().all(|b| b.is_ascii_hexdigit())
                        || s.bytes().all(|b| b == b'0')
                })
            || !hosts.insert(&p.hostname)
        {
            return Err(fail(
                "invalid or duplicate public deployment provider profile",
            ));
        }
        operators.insert(&p.operator);
    }
    if operators.len() < 3 {
        return Err(fail("fewer than three declared independent operators"));
    }
    Ok(())
}

async fn observe(p: &Provider, bounds: &native_stamp::DiagnosticBounds) -> io::Result<Receipt> {
    let clock = ReadOnlyClock::default();
    let native_stamp = native_stamp::NativeStamp::new(bounds.clone())?;
    let start = Instant::now();
    let tls = KeyExchangeClient::new(&NtsClientConfig::default()).map_err(io::Error::other)?;
    let tcp = TcpStream::connect((p.hostname.as_str(), p.key_establishment_port)).await?;
    // TLS 1.3, ntske/1, hostname/certificate verification, OS trust store; no extra test roots.
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
                return Err(fail("unexpected multiple poll packets"));
            }
            let timestamp = native_stamp.read(&clock)?;
            let written = socket.send(&bytes).await?;
            if written != bytes.len() {
                return Err(fail("partial UDP send"));
            }
            sent = Some(timestamp);
        }
    }
    let (sent, before) = sent.ok_or_else(|| fail("authenticated poll unavailable"))?;
    let mut bytes = [0u8; 1025];
    let length = socket.recv(&mut bytes).await?;
    let (received, after) = native_stamp.read(&clock)?;
    if length > 1024 {
        return Err(fail("oversized NTP packet"));
    }
    // Alter an authenticated NTP header timestamp byte before submitting the intact response.
    // This preserves parseable header structure and requires actual AEAD authentication refusal.
    let mut damaged = bytes[..length].to_vec();
    if damaged.len() < 48 {
        return Err(fail("truncated response"));
    }
    damaged[40] ^= 1;
    let _: Vec<_> = source
        .handle_incoming(&damaged, NtpInstant::now(), sent, received)
        .collect();
    if !clock
        .samples
        .lock()
        .map_err(|_| fail("observer poisoned"))?
        .is_empty()
    {
        return Err(fail("corrupted response accepted"));
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
            return Err(fail("no current authenticated usable NTS response"));
        }
        rows[0].clone()
    };
    let _: Vec<_> = source
        .handle_incoming(&bytes[..length], NtpInstant::now(), sent, received)
        .collect();
    let replay_refused = clock
        .samples
        .lock()
        .map_err(|_| fail("observer poisoned"))?
        .len()
        == 1;
    if !replay_refused {
        return Err(fail("exact NTS response replay accepted"));
    }
    let exchange = integer_interval::Exchange {
        sent,
        received,
        before,
        after,
    };
    let interval = sample
        .integer
        .interval(
            exchange,
            bounds
                .era()
                .ok_or_else(|| fail("explicit era context refused"))?,
            bounds.limits(),
        )
        .ok_or_else(|| {
            fail("authenticated integer interval refused under explicit diagnostic bounds")
        })?;
    Ok(Receipt {
        hostname: p.hostname.clone(),
        operator: p.operator.clone(),
        negotiated_server: keys.remote,
        negotiated_port: keys.port,
        no_smear_profile_evidence_sha256: p.no_smear_profile_evidence_sha256.clone(),
        current_authenticated_response: true,
        corrupted_packet_refused: true,
        exact_response_replay_refused: replay_refused,
        elapsed_capture_ns: start.elapsed().as_nanos(),
        delay_seconds: sample.delay_seconds,
        offset_seconds: sample.offset_seconds,
        root_delay_seconds: sample.root_delay_seconds,
        root_dispersion_seconds: sample.root_dispersion_seconds,
        precision: sample.precision,
        leap: format!("{:?}", sample.leap),
        stratum: sample.stratum,
        integer_inputs: sample.integer.public_inputs(exchange),
        integer_interval: serde_json::json!({
            "lower_posix_ns":interval.lower_posix_ns,"upper_posix_ns":interval.upper_posix_ns,
            "midpoint_active_ns":interval.midpoint_active_ns,
            "midpoint_inclusive_ns":interval.midpoint_inclusive_ns,
            "boot_id_hex":format!("{:032x}",interval.boot_id),
            "round_trip_ns":interval.round_trip_ns,"uncertainty_ns":interval.uncertainty_ns,
            "classification":"Diagnostic assumptions only; not an authenticated measured class profile"
        }),
    })
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.len() == 2 && args[0] == "--boot-diagnostic" {
        let output = PathBuf::from(&args[1]);
        if !output.is_absolute() || output.exists() {
            return Err(fail("create-new absolute diagnostic receipt required").into());
        }
        let b = windows_boot::read()?;
        let payload = serde_json::to_vec_pretty(&serde_json::json!({
            "format": "MUTINY-WINDOWS-KERNEL-BOOT-DIAGNOSTIC-V1",
            "identifier_raw_bytes": b.identifier_bytes, "firmware_type": b.firmware_type,
            "boot_flags": b.boot_flags, "os_build": b.os_build,
            "classification": "Unqualified internal ABI diagnostic only; no voting or restart authority",
            "production_clock_enabled": false
        }))?;
        use std::io::Write;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output)?
            .write_all(&payload)?;
        return Ok(());
    }
    if args.len() != 2 {
        return Err(fail("usage: observer PUBLIC_CONFIG.json NEW_RECEIPT.json").into());
    }
    let config_path = PathBuf::from(&args[0]);
    let output = PathBuf::from(&args[1]);
    if !config_path.is_absolute() || !output.is_absolute() || output.exists() {
        return Err(fail("absolute public inputs and create-new receipt required").into());
    }
    if std::fs::metadata(&config_path)?.len() > 16_384 {
        return Err(fail("config size bound").into());
    }
    let config: Config = serde_json::from_slice(&std::fs::read(&config_path)?)?;
    validate(&config)?;
    let mut responses = Vec::new();
    let mut errors = Vec::new();
    for provider in &config.providers {
        match tokio::time::timeout(Duration::from_secs(config.timeout_seconds), observe(provider, &config.diagnostic_bounds)).await {
            Ok(Ok(row)) => responses.push(row),
            Ok(Err(e)) => errors.push(serde_json::json!({"hostname": provider.hostname, "error": e.to_string()})),
            Err(_) => errors.push(serde_json::json!({"hostname": provider.hostname, "error": "bounded observation timeout"})),
        }
    }
    let operators = responses
        .iter()
        .map(|r| &r.operator)
        .collect::<BTreeSet<_>>();
    let enough = operators.len() >= 3;
    let payload = serde_json::to_vec_pretty(&serde_json::json!({
        "format": "MUTINY-NATIVE-NTS-DIAGNOSTIC-V1", "responses": responses, "errors": errors,
        "at_least_three_declared_authenticated_operators": enough,
        "classification": "Live transport diagnostic; not offline campaign, protected clock, physical drift or voting qualification",
        "production_clock_enabled": false, "system_clock_mutated": false,
        "profile_evidence_references_independently_verified": false,
        "diagnostic_bounds":config.diagnostic_bounds,
        "era_context_reference_independently_authenticated":false,
        "trust": "Pinned ntp-proto transport authentication plus local OS certificate trust store; declared operator/profile mappings need independent verification"
    }))?;
    if payload.len() > 131_072 {
        return Err(
            fail("bounded public diagnostic receipt exceeded; no authority granted").into(),
        );
    }
    use std::io::Write;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)?
        .write_all(&payload)?;
    if !enough {
        return Err(
            fail("fewer than three current authenticated operators; diagnostic retained").into(),
        );
    }
    Ok(())
}
