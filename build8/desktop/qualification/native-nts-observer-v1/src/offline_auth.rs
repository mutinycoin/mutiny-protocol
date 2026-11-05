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

#[test]
fn deployment_diversity_and_missing_profiles_remain_diagnostic_only() {
    fn provider(host: &str, operator: &str) -> Provider {
        Provider {
            hostname: host.into(),
            operator: operator.into(),
            key_establishment_port: 4460,
            no_smear_profile_evidence_sha256: None,
        }
    }
    let mut config = Config {
        timeout_seconds: 10,
        diagnostic_bounds: native_stamp::test_bounds(),
        providers: vec![
            provider("one-fixture.invalid", "One"),
            provider("two-fixture.invalid", "Two"),
            provider("three-fixture.invalid", "Three"),
        ],
    };
    validate(&config).unwrap();
    assert!(
        config
            .providers
            .iter()
            .all(|p| p.no_smear_profile_evidence_sha256.is_none())
    );
    config.providers[2].operator = "One".into();
    assert!(validate(&config).is_err());
    config.providers[2].operator = "Three".into();
    config.providers[2].hostname = config.providers[0].hostname.clone();
    assert!(validate(&config).is_err());
    config.providers[2].hostname = "three-fixture.invalid".into();
    config.providers[0].key_establishment_port = 0;
    assert!(validate(&config).is_err());
    config.providers[0].key_establishment_port = 4460;
    for invalid in ["0".repeat(64), "f".repeat(63), "z".repeat(64)] {
        config.providers[0].no_smear_profile_evidence_sha256 = Some(invalid);
        assert!(validate(&config).is_err());
    }
}

async fn exchange(host: &str, wrong_root: bool) -> Result<(KeyExchangeResult, Arc<KeySet>), ()> {
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
    let mut leaf = CertificateParams::new(vec!["nts-fixture.invalid".into()]).unwrap();
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
