//! Offline real TLS/NTS cryptography controls; all keys generated only in memory.
//! No host networking, TPM, time steering, trust-store changes or voting authority.
use super::*;
use ntp_proto::{
    FilterAction, FilterList, KeyExchangeResult, KeyExchangeServer, KeySet, KeySetProvider,
    NtpLeapIndicator, NtpVersion, NtsServerConfig, Server, ServerAction, ServerConfig,
    ServerReason, ServerResponse, ServerStatHandler, SystemSnapshot,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn exchange(host: &str, wrong_root: bool) -> Result<(KeyExchangeResult, Arc<KeySet>), ()> {
    exchange_named(host, "nts-fixture.invalid", wrong_root).await
}
async fn exchange_named(host: &str, certificate_host: &str, wrong_root: bool) -> Result<(KeyExchangeResult, Arc<KeySet>), ()> {
    // A genuine CA and server-auth leaf, not a self-signed end entity accepted
    // by relaxing the platform verifier. All TEST signing keys stay in RAM.
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
        KeyPair, KeyUsagePurpose,
    };
    let root_key = KeyPair::generate().unwrap();
    let mut ca = CertificateParams::default();
    ca.distinguished_name
        .push(DnType::CommonName, "PUBLIC TEST NTS fixture CA");
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root_cert = ca.self_signed(&root_key).unwrap();
    let signing_key = KeyPair::generate().unwrap();
    let mut leaf = CertificateParams::new(vec![certificate_host.into()]).unwrap();
    leaf.distinguished_name
        .push(DnType::CommonName, "nts-fixture.invalid");
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.use_authority_key_identifier_extension = true;
    let cert = leaf
        .signed_by(&signing_key, &Issuer::from_params(&ca, &root_key))
        .unwrap();
    let root = if wrong_root {
        rcgen::generate_simple_self_signed(vec!["other-fixture.invalid".into()])
            .unwrap()
            .cert
            .der()
            .to_vec()
    } else {
        root_cert.der().to_vec()
    };
    let client = KeyExchangeClient::new(&NtsClientConfig {
        certificates: Arc::from([CertificateDer::from(root)]),
        protocol_version: ProtocolVersion::V4,
    })
    .unwrap();
    let server = KeyExchangeServer::new(NtsServerConfig {
        // The trust anchor is configured locally, not transmitted as a peer intermediate.
        certificate_chain: vec![CertificateDer::from(cert.der().to_vec())],
        private_key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der())),
        accepted_versions: vec![NtpVersion::V4],
        server: Some("negotiated-fixture.invalid".into()),
        port: Some(4123),
        pool_authentication_tokens: vec![],
    })
    .unwrap();
    let keyset = KeySetProvider::new(0).get();
    let (a, b) = tokio::io::duplex(65_536);
    let both = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            client.exchange_keys(
                bounded_io::BoundedIo::new(a),
                host.to_owned(),
                std::iter::empty()
            ),
            server.handle_connection(
                bounded_io::BoundedIo::new(b),
                keyset.as_ref(),
                || None::<()>
            )
        )
    })
    .await
    .map_err(|_| ())?;
    match both {
        (Ok(result), Ok(_)) => Ok((result, keyset)),
        // NtsError contains protocol/IO/TLS classifications, no credential or
        // exported key bytes. Log only a coarse variant; never Debug either Ok.
        (client, server) => {
            let classify = |error: ntp_proto::NtsError| match error {
                ntp_proto::NtsError::IO(ref e) => {
                    eprintln!(
                        "PUBLIC offline IO diagnostic: kind={:?}, detail={}",
                        e.kind(),
                        e
                    );
                    "IO"
                }
                ntp_proto::NtsError::Tls(_) => "TLS",
                ntp_proto::NtsError::Dns(_) => "DNS",
                _ => "NTS protocol",
            };
            if let Err(e) = client {
                eprintln!("PUBLIC offline client failure class: {}", classify(e));
            }
            if let Err(e) = server {
                eprintln!("PUBLIC offline server failure class: {}", classify(e));
            }
            Err(())
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn real_tls_hostname_and_trust_roots_refuse_substitution() {
    let (result, _) = exchange("nts-fixture.invalid", false).await.unwrap();
    assert_eq!(result.remote, "negotiated-fixture.invalid");
    assert_eq!(result.port, 4123);
    assert!(exchange("wrong-fixture.invalid", false).await.is_err());
    assert!(exchange("nts-fixture.invalid", true).await.is_err());
}

#[derive(Default)]
struct Stats(Vec<(bool, ServerResponse)>);
impl ServerStatHandler for Stats {
    fn register(&mut self, _: u8, nts: bool, _: ServerReason, response: ServerResponse) {
        self.0.push((nts, response));
    }
}
/// Private genuine in-memory TLS/NTS acquisition for same-source Node service
/// tests. Explicit TEST roots/keys stay in RAM and never enter ordinary acquire.
/// No network listener, caller authenticity bit or serialized result is used.
pub(crate) async fn genuine_test_report(config: Config, leap: NtpLeapIndicator)
    -> io::Result<AcquisitionReport> {
    config.validate()?;
    let mut report = AcquisitionReport { config:config.clone(), accepted:Vec::new(), failures:Vec::new() };
    let mut operators = std::collections::BTreeSet::new();
    for p in &config.providers {
        let (keys, keyset) = exchange_named(&p.hostname, &p.hostname, false).await
            .map_err(|_| io::Error::other("private TEST TLS exchange refused"))?;
        let clock = ReadOnlyClock::default();
        let mut system = System::<u8, ObserverController>::new(clock.clone(),
            SynchronizationConfig::default(), (), Arc::new([]))?;
        let (mut source, _) = system.create_ntp_source(0, SourceConfig::default(),
            "127.0.0.1:4123".parse().unwrap(), ProtocolVersion::V4, Some(keys.nts))?;
        let polls:Vec<_> = source.handle_timer().filter_map(|a| match a {
            NtpSourceAction::Send(bytes) => Some(bytes), _ => None }).collect();
        if polls.len()!=1 { return Err(io::Error::other("private TEST poll count")); }
        let stamp = native_stamp::NativeStamp::new(config.bounds.clone())?;
        let sent_record=stamp.read_recorded(&clock)?;
        let sent=sent_record.timestamp;let before=sent_record.pair;
        let mut snapshot=SystemSnapshot::default();
        snapshot.stratum=1; snapshot.time_snapshot.leap_indicator=leap;
        let mut server = Server::new(ServerConfig {
            denylist:FilterList { filter:vec![], action:FilterAction::Ignore },
            allowlist:FilterList { filter:vec!["0.0.0.0/0".parse().unwrap()], action:FilterAction::Ignore },
            rate_limiting_cache_size:0, rate_limiting_cutoff:Duration::ZERO,
            require_nts:Some(FilterAction::Ignore), accepted_versions:vec![NtpVersion::V4],
        }, clock.clone(), snapshot, keyset);
        let mut stats=Stats::default(); let mut buffer=[0u8;1024];
        let ServerAction::Respond { message } = server.handle("127.0.0.1".parse().unwrap(),
            clock.now()?, &polls[0], &mut buffer, &mut stats) else {
            return Err(io::Error::other("private TEST authenticated server refusal"));
        };
        let response=message.to_vec();
        if stats.0 != vec![(true,ServerResponse::ProvideTime)] || !(48..=1024).contains(&response.len()) {
            return Err(io::Error::other("private TEST response profile"));
        }
        let received_record=stamp.read_recorded(&clock)?;
        let received=received_record.timestamp;let after=received_record.pair;
        let _:Vec<_>=source.handle_incoming(&response,NtpInstant::now(),sent,received).collect();
        let rows=clock.samples.lock().map_err(|_| io::Error::other("private TEST observer poison"))?;
        if rows.len()!=1 { return Err(io::Error::other("no private TEST authenticated usable response")); }
        let sample=&rows[0];
        let interval=sample.integer.interval(integer_interval::Exchange {sent,received,before,after},
            config.bounds.era().ok_or_else(|| io::Error::other("private TEST era"))?,config.bounds.limits())
            .ok_or_else(|| io::Error::other("private TEST integer interval refused"))?;
        let leap=match sample.leap { NtpLeapIndicator::NoWarning=>Leap::Clear,
            NtpLeapIndicator::Leap61=>Leap::Insert,NtpLeapIndicator::Leap59=>Leap::Delete,
            _=>return Err(io::Error::other("private TEST leap refused")) };
        if operators.insert(p.operator.clone()) {
            report.accepted.push(AuthenticatedObservation { hostname:p.hostname.clone(),
                operator:p.operator.clone(),profile:p.no_smear_profile_evidence_sha256,
                interval:IntervalView { lower_posix_ns:interval.lower_posix_ns,
                    upper_posix_ns:interval.upper_posix_ns,active_ns:interval.midpoint_active_ns,
                    inclusive_ns:interval.midpoint_inclusive_ns,boot_id:interval.boot_id,
                    round_trip_ns:interval.round_trip_ns,uncertainty_ns:interval.uncertainty_ns },leap,
                diagnostic:DiagnosticTranscript {arithmetic:sample.integer.retained_raw(&sent_record,&received_record)?,
                    response_bytes:response.len(),stratum:sample.stratum,provider:p.clone(),
                    bounds:config.bounds.clone(),destination:"127.0.0.1:4123".parse().unwrap()} });
        }
    }
    Ok(report)
}
#[tokio::test(flavor="current_thread")]
async fn real_private_offline_nts_producer_retains_actual_capture_transcripts_without_secret_packet_export() {
    // Existing genuine private TLS/NTS fixture; no remote/network deployment,
    // physical qualification or imported replay authority. All newly added
    // native-counter/crypto assertions are authored but not executed here.
    let config=Config {providers:(1..=3).map(|n|Provider {hostname:format!("source{n}.invalid"),
        operator:format!("Operator{n}"),key_establishment_port:4460,
        no_smear_profile_evidence_sha256:[n;32]}).collect(),timeout_seconds:10,bounds:native_stamp::test_bounds()};
    let report=genuine_test_report(config.clone(),NtpLeapIndicator::NoWarning).await.unwrap();
    assert!(report.matches_config(&config));assert_eq!(report.usable_operator_count(),3);
    for (observation,provider) in report.accepted().iter().zip(&config.providers) {
        let transcript=observation.diagnostic_transcript();
        assert_eq!(transcript.provider(),provider);assert_eq!(transcript.bounds(),&config.bounds);
        assert_eq!(transcript.destination(),"127.0.0.1:4123".parse().unwrap());
        assert!((48..=1024).contains(&transcript.response_bytes()));assert_eq!(transcript.stratum(),1);
        let raw=transcript.arithmetic();assert!(raw.len()<=64*1024);
        assert_eq!(reconstruct_diagnostic_interval(raw,&config.bounds).unwrap().view(),observation.interval());
        let value:serde_json::Value=serde_json::from_slice(raw).unwrap();
        for name in ["before","after"] {for side in ["pre","post"] {
            assert!(value[name][side]["active_before_ns"].as_u64().unwrap()>0);
            assert!(value[name][side]["active_after_ns"].as_u64().unwrap()>=
                value[name][side]["active_before_ns"].as_u64().unwrap());
        }}
        assert!(value.as_object().unwrap().keys().all(|k|!["keys","cookies","packet","TLS","authenticated"].contains(&k.as_str())));
    }
}
#[tokio::test(flavor = "current_thread")]
async fn real_nts_response_rejects_plaintext_damage_and_replay() {
    let (keys, keyset) = exchange("nts-fixture.invalid", false).await.unwrap();
    let clock = ReadOnlyClock::default();
    let mut system = System::<u8, ObserverController>::new(
        clock.clone(),
        SynchronizationConfig::default(),
        (),
        Arc::new([]),
    )
    .unwrap();
    let (mut source, _) = system
        .create_ntp_source(
            0,
            SourceConfig::default(),
            "127.0.0.1:4123".parse().unwrap(),
            ProtocolVersion::V4,
            Some(keys.nts),
        )
        .unwrap();
    let polls: Vec<_> = source
        .handle_timer()
        .filter_map(|a| {
            if let NtpSourceAction::Send(b) = a {
                Some(b)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(polls.len(), 1);
    // These bounds are PUBLIC TEST values only, not physical qualification.
    // Measure the actual native counter sandwich around each wall timestamp.
    let elapsed = native_stamp::NativeStamp::new(native_stamp::test_bounds()).unwrap();
    let (sent, before) = elapsed.read(&clock).unwrap();
    let mut snapshot = SystemSnapshot::default();
    snapshot.stratum = 1;
    snapshot.time_snapshot.leap_indicator = NtpLeapIndicator::NoWarning;
    let mut server = Server::new(
        ServerConfig {
            denylist: FilterList {
                filter: vec![],
                action: FilterAction::Ignore,
            },
            allowlist: FilterList {
                filter: vec!["0.0.0.0/0".parse().unwrap()],
                action: FilterAction::Ignore,
            },
            rate_limiting_cache_size: 0,
            rate_limiting_cutoff: Duration::ZERO,
            require_nts: Some(FilterAction::Ignore),
            accepted_versions: vec![NtpVersion::V4],
        },
        clock.clone(),
        snapshot,
        keyset,
    );
    let mut stats = Stats::default();
    let mut buffer = [0u8; 1024];
    let ServerAction::Respond { message } = server.handle(
        "127.0.0.1".parse().unwrap(),
        clock.now().unwrap(),
        &polls[0],
        &mut buffer,
        &mut stats,
    ) else {
        panic!("genuine authenticated poll refused")
    };
    let response = message.to_vec();
    assert!(response.len() > 48 && response.len() <= 1024);
    assert_eq!(stats.0, vec![(true, ServerResponse::ProvideTime)]);
    let (received, after) = elapsed.read(&clock).unwrap();
    // Exact genuine response header without any authentication extensions.
    let _: Vec<_> = source
        .handle_incoming(&response[..48], NtpInstant::now(), sent, received)
        .collect();
    assert!(clock.samples.lock().unwrap().is_empty());
    let mut damaged = response.clone();
    damaged[40] ^= 1;
    let _: Vec<_> = source
        .handle_incoming(&damaged, NtpInstant::now(), sent, received)
        .collect();
    assert!(clock.samples.lock().unwrap().is_empty());
    let _: Vec<_> = source
        .handle_incoming(&response, NtpInstant::now(), sent, received)
        .collect();
    assert_eq!(clock.samples.lock().unwrap().len(), 1);
    let integer = clock.samples.lock().unwrap()[0].integer;
    // Explicit PUBLIC TEST 2020..2040 era context, never inferred from wall time.
    let era =
        integer_interval::EraWindow::new(1_577_836_800_000_000_000, 2_208_988_800_000_000_000)
            .unwrap();
    let limits = integer_interval::Limits {
        max_round_trip_ns: 1_000_000_000,
        elapsed_drift_ppb: 100_000,
        max_uncertainty_ns: 250_000_000,
    };
    let exchange = integer_interval::Exchange {
        sent,
        received,
        before,
        after,
    };
    let interval = integer
        .interval(exchange, era, limits)
        .expect("genuine NTS with actual native elapsed sampling");
    assert!(interval.lower_posix_ns < interval.upper_posix_ns);
    assert_eq!(interval.boot_id, before.boot_id);
    let mut changed = exchange;
    changed.received = changed.received + ntp_proto::NtpDuration::from_seconds(1.0);
    assert!(integer.interval(changed, era, limits).is_none());
    changed = exchange;
    changed.after.boot_id ^= 1;
    assert!(integer.interval(changed, era, limits).is_none());
    let _: Vec<_> = source
        .handle_incoming(&response, NtpInstant::now(), sent, received)
        .collect();
    assert_eq!(clock.samples.lock().unwrap().len(), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn encrypted_io_exact_boundary_preserves_budget_and_refuses_next_byte() {
    let (a, mut b) = tokio::io::duplex(65_537);
    let mut io = bounded_io::BoundedIo::new(a);
    b.write_all(&vec![7; 65_537]).await.unwrap();
    let mut raw = vec![0; 65_536];
    io.read_exact(&mut raw).await.unwrap();
    assert!(raw.iter().all(|b| *b == 7));
    assert!(io.read_u8().await.is_err());
    io.write_all(&vec![8; 65_536]).await.unwrap();
    assert!(io.write_all(&[8]).await.is_err());
    let mut exact = vec![0; 65_536];
    b.read_exact(&mut exact).await.unwrap();
    assert!(exact.iter().all(|b| *b == 8));
}

#[tokio::test(flavor = "current_thread")]
async fn real_nts_authenticated_unsynchronized_leap_refuses_with_synchronized_positive() {
    for leap in [
        NtpLeapIndicator::NoWarning,
        NtpLeapIndicator::Unsynchronized,
    ] {
        // Each case establishes genuine TLS/NTS keys and receives a freshly
        // authenticated server response; no caller-authenticated sample input.
        let (keys, keyset) = exchange("nts-fixture.invalid", false).await.unwrap();
        let clock = ReadOnlyClock::default();
        let mut system = System::<u8, ObserverController>::new(
            clock.clone(),
            SynchronizationConfig::default(),
            (),
            Arc::new([]),
        )
        .unwrap();
        let (mut source, _) = system
            .create_ntp_source(
                0,
                SourceConfig::default(),
                "127.0.0.1:4123".parse().unwrap(),
                ProtocolVersion::V4,
                Some(keys.nts),
            )
            .unwrap();
        let polls: Vec<_> = source
            .handle_timer()
            .filter_map(|a| {
                if let NtpSourceAction::Send(b) = a {
                    Some(b)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(polls.len(), 1);
        let elapsed = native_stamp::NativeStamp::new(native_stamp::test_bounds()).unwrap();
        let (sent, _) = elapsed.read(&clock).unwrap();
        let mut snapshot = SystemSnapshot::default();
        snapshot.stratum = 1;
        snapshot.time_snapshot.leap_indicator = leap;
        let mut server = Server::new(
            ServerConfig {
                denylist: FilterList {
                    filter: vec![],
                    action: FilterAction::Ignore,
                },
                allowlist: FilterList {
                    filter: vec!["0.0.0.0/0".parse().unwrap()],
                    action: FilterAction::Ignore,
                },
                rate_limiting_cache_size: 0,
                rate_limiting_cutoff: Duration::ZERO,
                require_nts: Some(FilterAction::Ignore),
                accepted_versions: vec![NtpVersion::V4],
            },
            clock.clone(),
            snapshot,
            keyset,
        );
        let mut stats = Stats::default();
        let mut buffer = [0u8; 1024];
        let ServerAction::Respond { message } = server.handle(
            "127.0.0.1".parse().unwrap(),
            clock.now().unwrap(),
            &polls[0],
            &mut buffer,
            &mut stats,
        ) else {
            panic!("genuine authenticated leap poll refused")
        };
        let response = message.to_vec();
        assert!(response.len() > 48 && response.len() <= 1024);
        assert_eq!(stats.0, vec![(true, ServerResponse::ProvideTime)]);
        assert_eq!(
            response[0] >> 6,
            if leap == NtpLeapIndicator::NoWarning {
                0
            } else {
                3
            }
        );
        let (received, _) = elapsed.read(&clock).unwrap();
        let _: Vec<_> = source
            .handle_incoming(&response, NtpInstant::now(), sent, received)
            .collect();
        let count = if leap == NtpLeapIndicator::NoWarning {
            1
        } else {
            0
        };
        assert_eq!(
            clock.samples.lock().unwrap().len(),
            count,
            "authenticated NTPv4 LI=3 must remain unusable"
        );
        let _: Vec<_> = source
            .handle_incoming(&response, NtpInstant::now(), sent, received)
            .collect();
        assert_eq!(clock.samples.lock().unwrap().len(), count);
    }
}
