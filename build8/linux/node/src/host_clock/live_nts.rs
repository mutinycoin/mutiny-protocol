//! Ordinary-user, bounded chrony evidence for a fresh calibration.
//! Provider names are deployment inputs; this is not a consensus source list or
//! a measured clock profile. Unknown report layouts fail closed. Local monitoring
//! requires administrator-prepared chrony >= 4.7; it never changes the daemon.
use super::{ChronyClient, Result, nts_sources};
use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

/// Local adapter refusal limits, not measured drift or consensus parameters.
pub const MAX_SELECTED_SOURCES: usize = 16;
pub const MAX_ACCEPTED_SAMPLE_AGE_SECONDS: u64 = 128;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Selected {
    state: String,
    stratum: u32,
    poll: i32,
    age: u64,
}

fn selected(csv: &str) -> Result<BTreeMap<IpAddr, Selected>> {
    let mut out = BTreeMap::new();
    let mut best = 0;
    for line in csv.lines().filter(|l| !l.trim().is_empty()) {
        let f: Vec<_> = line.split(',').map(str::trim).collect();
        if f.len() != 10 {
            return Err("chrony sources layout".into());
        }
        if !matches!(f[1], "*" | "+") {
            continue;
        }
        if f[0] != "^" {
            return Err("selected chrony source is not an NTP server".into());
        }
        let address: IpAddr = f[2].parse().map_err(|_| "chrony numeric source address")?;
        let stratum = f[3].parse().map_err(|_| "chrony source stratum")?;
        let poll = f[4].parse().map_err(|_| "chrony source poll")?;
        let reach = u16::from_str_radix(f[5], 8).map_err(|_| "chrony source reach")?;
        let age = f[6].parse().map_err(|_| "chrony source sample age")?;
        if !(1..16).contains(&stratum)
            || !(-7..=24).contains(&poll)
            || reach == 0
            || reach > 255
            || age > MAX_ACCEPTED_SAMPLE_AGE_SECONDS
        {
            return Err("chrony selected source unusable or stale".into());
        }
        if f[1] == "*" {
            best += 1;
        }
        if out
            .insert(
                address,
                Selected {
                    state: f[1].into(),
                    stratum,
                    poll,
                    age,
                },
            )
            .is_some()
            || out.len() > MAX_SELECTED_SOURCES
        {
            return Err("chrony duplicate or excessive selected sources".into());
        }
    }
    if best != 1 {
        return Err("chrony must have one selected reference".into());
    }
    Ok(out)
}

/// Documented chrony 4.7/4.8 named report; no order-dependent CSV guess.
fn response(text: &str, address: IpAddr) -> Result<BTreeMap<String, String>> {
    if text.len() > 8192 {
        return Err("chrony ntpdata oversized".into());
    }
    let mut fields = BTreeMap::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let (key, value) = line.split_once(':').ok_or("chrony ntpdata layout")?;
        if fields
            .insert(key.trim().to_owned(), value.trim().to_owned())
            .is_some()
        {
            return Err("chrony duplicate ntpdata field".into());
        }
    }
    let expected: BTreeSet<_> = [
        "Remote address",
        "Remote port",
        "Local address",
        "Leap status",
        "Version",
        "Mode",
        "Stratum",
        "Poll interval",
        "Precision",
        "Root delay",
        "Root dispersion",
        "Reference ID",
        "Reference time",
        "Offset",
        "Peer delay",
        "Peer dispersion",
        "Response time",
        "Jitter asymmetry",
        "NTP tests",
        "Interleaved",
        "Authenticated",
        "TX timestamping",
        "RX timestamping",
        "Total TX",
        "Total RX",
        "Total valid RX",
        "Total good RX",
        "Total kernel TX",
        "Total kernel RX",
        "Total HW TX",
        "Total HW RX",
    ]
    .into_iter()
    .collect();
    if fields.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err("chrony ntpdata unsupported field schema".into());
    }
    let value = |key: &str| -> Result<&str> {
        fields
            .get(key)
            .map(String::as_str)
            .ok_or_else(|| format!("chrony ntpdata missing {key}"))
    };
    let remote: IpAddr = value("Remote address")?
        .split_whitespace()
        .next()
        .ok_or("chrony ntpdata remote")?
        .parse()
        .map_err(|_| "chrony ntpdata remote")?;
    let port: u16 = value("Remote port")?
        .parse()
        .map_err(|_| "chrony ntpdata port")?;
    let good: u64 = value("Total good RX")?
        .parse()
        .map_err(|_| "chrony ntpdata good RX")?;
    let valid: u64 = value("Total valid RX")?
        .parse()
        .map_err(|_| "chrony ntpdata valid RX")?;
    let received: u64 = value("Total RX")?
        .parse()
        .map_err(|_| "chrony ntpdata RX")?;
    let stratum: u32 = value("Stratum")?
        .parse()
        .map_err(|_| "chrony ntpdata stratum")?;
    if remote != address
        || port == 0
        || good == 0
        || good > valid
        || valid > received
        || !(1..16).contains(&stratum)
        || value("Version")? != "4"
        || value("Mode")? != "Server"
        || value("Authenticated")? != "Yes"
        || value("NTP tests")? != "111 111 1111"
        || !matches!(
            value("Leap status")?,
            "Normal" | "Insert second" | "Delete second"
        )
    {
        return Err("chrony last response is not authenticated and usable".into());
    }
    // Pin the last response and counters across the capture. A daemon update is
    // retried later, never joined with another source-selection snapshot.
    Ok(fields)
}

fn source_name(text: &str) -> Result<String> {
    if text.len() > 256 || text.lines().count() != 1 {
        return Err("chrony sourcename layout".into());
    }
    nts_sources::normalize_host(text.trim()).map_err(Into::into)
}

// chrony 4.7/4.8 numeric CSV authdata schema. Association state is necessary,
// but accepted authenticated packet evidence is checked separately in ntpdata.
fn associations(csv: &str) -> Result<BTreeSet<String>> {
    if csv.len() > 65536 {
        return Err("chrony authdata size".into());
    }
    let mut seen = BTreeSet::new();
    let mut nts = BTreeSet::new();
    for line in csv.lines().filter(|line| !line.trim().is_empty()) {
        let f: Vec<_> = line.split(',').map(str::trim).collect();
        if f.len() != 10 || seen.len() >= 256 {
            return Err("chrony authdata schema".into());
        }
        let ip: IpAddr = f[0]
            .parse()
            .map_err(|_| "chrony authdata numeric address")?;
        if !seen.insert(ip) {
            return Err("chrony duplicate authentication association".into());
        }
        if !matches!(f[1], "NTS" | "SK" | "-") {
            return Err("chrony authentication mode".into());
        }
        let numbers = [2, 3, 4, 6, 7, 8, 9].map(|i| f[i].parse::<u64>());
        if numbers.iter().any(|v| v.is_err()) || (f[5] != "-" && f[5].parse::<u64>().is_err()) {
            return Err("chrony authentication numeric field".into());
        }
        if f[1] == "NTS" {
            if !matches!((f[3], f[4]), ("15", "256") | ("30", "128")) {
                return Err("chrony unsupported NTS algorithm".into());
            }
            nts.insert(ip.to_string());
        }
    }
    Ok(nts)
}

pub fn authenticated_operators(
    client: &dyn ChronyClient,
    declared: &[String],
    minimum: usize,
    reference: IpAddr,
) -> Result<bool> {
    let started = std::time::Instant::now();
    // Bound the complete report collection as well as each child. The existing
    // command deadline can overrun this by at most one bounded child duration.
    let run = |args: &[&str]| -> Result<String> {
        if started.elapsed() >= std::time::Duration::from_secs(1) {
            return Err("chrony live evidence capture deadline".into());
        }
        let result = client.run(args)?;
        if started.elapsed() >= std::time::Duration::from_secs(1) {
            return Err("chrony live evidence capture deadline".into());
        }
        Ok(result)
    };
    nts_sources::validate_source_set(declared)?;
    let declared: BTreeSet<_> = declared
        .iter()
        .map(|h| nts_sources::normalize_host(h))
        .collect::<std::result::Result<_, _>>()?;
    let version = run(&["-v"])?;
    let words: Vec<_> = version.split_whitespace().collect();
    if words.first() != Some(&"chronyc")
        || !words
            .windows(2)
            .any(|v| v[0] == "version" && matches!(v[1], "4.7" | "4.8"))
    {
        return Err("chronyc report schema requires qualified 4.7 or 4.8".into());
    }
    let before = selected(&run(&["-h", "127.0.0.1", "-n", "-c", "sources"])?)?;
    if !before
        .get(&reference)
        .is_some_and(|source| source.state == "*")
    {
        return Err("chrony tracking reference is not the selected source".into());
    }
    let nts = associations(&run(&["-h", "127.0.0.1", "-n", "-c", "authdata"])?)?;
    let mut evidence = Vec::new();
    let mut operators = BTreeSet::new();
    for address in before.keys() {
        let ip = address.to_string();
        if !nts.contains(&ip) {
            return Ok(false);
        }
        let name = source_name(&run(&["-h", "127.0.0.1", "-n", "sourcename", &ip])?)?;
        if !declared.contains(&name) {
            return Err("selected chrony source is not declared".into());
        }
        operators.insert(nts_sources::operator_of(&name)?);
        let data = response(&run(&["-h", "127.0.0.1", "-n", "ntpdata", &ip])?, *address)?;
        evidence.push((*address, name, data));
    }
    for (address, name, data) in evidence {
        let ip = address.to_string();
        if name != source_name(&run(&["-h", "127.0.0.1", "-n", "sourcename", &ip])?)?
            || data != response(&run(&["-h", "127.0.0.1", "-n", "ntpdata", &ip])?, address)?
        {
            return Err("chrony source evidence changed during capture".into());
        }
    }
    let after = selected(&run(&["-h", "127.0.0.1", "-n", "-c", "sources"])?)?;
    if before.len() != after.len()
        || before.iter().any(|(ip, a)| match after.get(ip) {
            Some(b) => {
                a.state != b.state || a.stratum != b.stratum || a.poll != b.poll || b.age < a.age
            }
            None => true,
        })
    {
        return Err("chrony selected source set changed during capture".into());
    }
    let after_nts = associations(&run(&["-h", "127.0.0.1", "-n", "-c", "authdata"])?)?;
    if nts != after_nts {
        return Err("chrony authenticated associations changed during capture".into());
    }
    Ok(operators.len() >= minimum.max(nts_sources::MIN_INDEPENDENT_OPERATORS))
}

#[cfg(test)]
pub(super) fn test_response(ip: &str) -> String {
    format!(
        "Remote address : {ip} (CB00710F)\nRemote port : 4123\nLocal address : 127.0.0.1 (7F000001)\nLeap status : Normal\nVersion : 4\nMode : Server\nStratum : 2\nPoll interval : 6 (64 seconds)\nPrecision : -24 (0.000000060 seconds)\nRoot delay : 0.000015 seconds\nRoot dispersion : 0.000015 seconds\nReference ID : 47505300 (GPS)\nReference time : Mon Oct 05 00:00:00 2026\nOffset : -0.000060878 seconds\nPeer delay : 0.000175634 seconds\nPeer dispersion : 0.000000681 seconds\nResponse time : 0.000053050 seconds\nJitter asymmetry : +0.00\nNTP tests : 111 111 1111\nInterleaved : No\nAuthenticated : Yes\nTX timestamping : Kernel\nRX timestamping : Kernel\nTotal TX : 24\nTotal RX : 24\nTotal valid RX : 24\nTotal good RX : 22\nTotal kernel TX : 24\nTotal kernel RX : 24\nTotal HW TX : 0\nTotal HW RX : 0\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    const HOSTS: [&str; 4] = [
        "time.cloudflare.com",
        "nts.netnod.se",
        "ptbtime1.ptb.de",
        "ntppool1.time.nl",
    ];
    const SOURCES: &str = "^,*,192.0.2.1,2,6,377,12,0,0,0\n^,+,192.0.2.2,2,6,377,12,0,0,0\n^,+,192.0.2.3,2,6,377,12,0,0,0\n";
    struct Client {
        mode: u8,
        sources_reads: AtomicUsize,
        data_reads: AtomicUsize,
    }
    impl Client {
        fn new(mode: u8) -> Self {
            Self {
                mode,
                sources_reads: AtomicUsize::new(0),
                data_reads: AtomicUsize::new(0),
            }
        }
    }
    #[test]
    fn authentication_association_schema_does_not_accept_truncated_or_duplicate_claims() {
        let valid = "192.0.2.1,NTS,1,15,256,10,0,0,8,100\n";
        assert_eq!(associations(valid).unwrap().len(), 1);
        for bad in [
            "192.0.2.1,NTS\n".to_owned(),
            valid.repeat(2),
            valid.replace(",15,256,", ",99,256,"),
            valid.replace(",10,", ",48m,"),
            valid.replace("192.0.2.1", "source.example"),
        ] {
            assert!(associations(&bad).is_err(), "{bad}");
        }
        assert!(
            associations(&valid.replace("NTS,1,15,256,10", "-,0,0,0,-"))
                .unwrap()
                .is_empty()
        );
    }
    impl ChronyClient for Client {
        fn run(&self, args: &[&str]) -> Result<String> {
            if args == ["-v"] {
                return Ok("chronyc version 4.8 (+READLINE)\n".into());
            }
            assert_eq!(&args[..2], &["-h", "127.0.0.1"]);
            if args.contains(&"sources") {
                let n = self.sources_reads.fetch_add(1, Ordering::SeqCst);
                return Ok(match self.mode {
                    3 => SOURCES.replace(",12,", ",129,"),
                    4 if n > 0 => SOURCES.replace(",+,192.0.2.3", ",-,192.0.2.3"),
                    _ => SOURCES.into(),
                });
            }
            if args.contains(&"authdata") {
                return Ok([1, 2, 3]
                    .iter()
                    .map(|n| format!("192.0.2.{n},NTS,1,15,256,10,0,0,8,100\n"))
                    .collect());
            }
            let ip = args.last().unwrap();
            if args.contains(&"sourcename") {
                let index = ip.as_bytes().last().unwrap() - b'1';
                return Ok(if self.mode == 1 && index > 0 {
                    format!("ptbtime{}.ptb.de\n", index)
                } else if self.mode == 2 {
                    "unapproved.example\n".into()
                } else {
                    format!("{}\n", HOSTS[index as usize])
                });
            }
            if args.contains(&"ntpdata") {
                let n = self.data_reads.fetch_add(1, Ordering::SeqCst);
                return Ok(if self.mode == 5 && n >= 3 {
                    test_response(ip).replace("Total good RX : 22", "Total good RX : 23")
                } else {
                    test_response(ip)
                });
            }
            Err("unexpected TEST command".into())
        }
    }
    fn declared() -> Vec<String> {
        HOSTS
            .into_iter()
            .chain(["ptbtime2.ptb.de"])
            .map(str::to_owned)
            .collect()
    }
    #[test]
    fn genuine_three_operator_live_join_and_all_authenticated_response_fields_pass() {
        assert_eq!(
            authenticated_operators(
                &Client::new(0),
                &declared(),
                1,
                "192.0.2.1".parse().unwrap()
            )
            .unwrap(),
            true
        );
        assert_eq!(
            authenticated_operators(
                &Client::new(0),
                &declared(),
                4,
                "192.0.2.1".parse().unwrap()
            )
            .unwrap(),
            false
        );
        assert!(
            authenticated_operators(
                &Client::new(0),
                &declared(),
                3,
                "192.0.2.2".parse().unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn multiple_addresses_of_one_operator_never_satisfy_diversity() {
        assert_eq!(
            authenticated_operators(
                &Client::new(1),
                &declared(),
                1,
                "192.0.2.1".parse().unwrap()
            )
            .unwrap(),
            false
        );
    }
    #[test]
    fn undeclared_stale_and_changed_evidence_each_refuse() {
        for mode in [2, 3, 4, 5] {
            assert!(
                authenticated_operators(
                    &Client::new(mode),
                    &declared(),
                    3,
                    "192.0.2.1".parse().unwrap()
                )
                .is_err(),
                "mode {mode}"
            );
        }
    }
    #[test]
    fn kex_only_forged_unusable_duplicate_and_unknown_response_reports_refuse() {
        let ip = "192.0.2.1".parse().unwrap();
        let good = test_response("192.0.2.1");
        assert!(response(&good, ip).is_ok());
        for bad in [
            good.replace("Authenticated : Yes", "Authenticated : No"),
            good.replace("111 111 1111", "111 111 0111"),
            good.replace("Total good RX : 22", "Total good RX : 0"),
            good.replace("Total good RX : 22", "Total good RX : 25"),
            good.replace("192.0.2.1 (", "192.0.2.2 ("),
            good.replace("Remote port : 4123", "Remote port : 0"),
            good.replace("Mode : Server", "Mode : Client"),
            good.replace("Leap status : Normal", "Leap status : Not synchronised"),
            format!("{good}Authenticated : Yes\n"),
            format!("{good}Unknown field : yes\n"),
            good.replace("Authenticated : Yes\n", ""),
        ] {
            assert!(response(&bad, ip).is_err(), "{bad}");
        }
    }
    #[test]
    fn selected_source_identity_cardinality_mode_reach_and_freshness_are_checked() {
        assert!(selected(SOURCES).is_ok());
        for bad in [
            SOURCES.replace(",12,", ",129,"),
            SOURCES.replace(",377,", ",0,"),
            SOURCES.replace("^,*", "=,*"),
            format!("{SOURCES}{SOURCES}"),
            SOURCES.replace(",*,", ",+,"),
            SOURCES.replace("192.0.2.1", "bad-address"),
        ] {
            assert!(selected(&bad).is_err(), "{bad}");
        }
    }
}
