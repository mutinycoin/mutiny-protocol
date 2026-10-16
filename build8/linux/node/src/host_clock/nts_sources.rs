//! NTS source-set validation (Build 8 clock profile). Maps each configured source host to an
//! OPERATOR and requires at least [`MIN_INDEPENDENT_OPERATORS`] independent operators: several
//! hostnames or addresses of one operator count ONCE. Approved initial set (Architect, 3 Oct 2026):
//! Cloudflare, Netnod, PTB, SIDN (time.nl). Hostnames are as read on the operators' own pages on
//! 2026-10-03 (see docs/CLOCK-PROFILE-V1.md); ports, AEAD and leap behaviour are recorded in the
//! chrony template and the profile document, with UNVERIFIED items marked.
//!
//! This validates a DECLARATION (configuration), not live behaviour: it cannot prove which
//! addresses chrony actually selected, that the operators are operationally independent below the
//! legal/jurisdictional level, or that their time is correct. Authentication and agreement do not
//! prove the uncertainty bound; the bound comes from the profile and qualification measurements.
use std::collections::BTreeMap;

/// Independence floor: three distinct OPERATORS (so one may fail or be excluded: n >= 2f+1, f = 1).
pub const MIN_INDEPENDENT_OPERATORS: usize = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Operator {
    Cloudflare,
    Netnod,
    Ptb,
    Sidn,
}
impl Operator {
    pub fn id(self) -> &'static str {
        match self {
            Operator::Cloudflare => "cloudflare",
            Operator::Netnod => "netnod",
            Operator::Ptb => "ptb",
            Operator::Sidn => "sidn",
        }
    }
}

fn label_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}
/// Lower-case, strip one trailing dot, and require a plain DNS name (no scheme, port or address).
pub fn normalize_host(host: &str) -> Result<String, String> {
    let h = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() || h.len() > 253 || !h.split('.').all(label_ok) || !h.contains('.') {
        return Err(format!("nts source {host:?} is not a plain hostname"));
    }
    if h.split('.').all(|l| l.bytes().all(|b| b.is_ascii_digit())) {
        return Err(format!("nts source {host:?} is an address, not an operator hostname"));
    }
    Ok(h)
}

/// Operator of one hostname, or an error when it is unknown or explicitly excluded.
pub fn operator_of(host: &str) -> Result<Operator, String> {
    let h = normalize_host(host)?;
    let s = h.as_str();
    if s == "time.cloudflare.com" {
        return Ok(Operator::Cloudflare);
    }
    if s == "nts.netnod.se" {
        return Ok(Operator::Netnod);
    }
    if let Some(site) = s.strip_suffix(".nts.netnod.se") {
        // gbg1/gbg2/lul1/lul2/mmo1/mmo2/sth1/sth2/svl1/svl2: one label, letters then a digit.
        if site.len() == 4 && !site.contains('.') && label_ok(site) {
            return Ok(Operator::Netnod);
        }
    }
    if let Some(n) = s.strip_prefix("ptbtime").and_then(|r| r.strip_suffix(".ptb.de")) {
        if matches!(n, "1" | "2" | "3" | "4") {
            return Ok(Operator::Ptb);
        }
    }
    // SIDN: production names only. Pool / pilot / anycast / pre-production names are excluded.
    if matches!(s, "ntppool1.time.nl" | "ntppool2.time.nl") {
        return Ok(Operator::Sidn);
    }
    if matches!(
        s,
        "ntspool.time.nl" | "nts1.time.nl" | "any.time.nl" | "ntppool3.time.nl" | "ntppool4.time.nl"
    ) {
        return Err(format!(
            "nts source {host:?} is excluded (pool, pilot, anycast or pre-production name)"
        ));
    }
    Err(format!("nts source {host:?} maps to no approved operator"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceSetReport {
    /// Operator -> hostnames configured for it (normalised).
    pub operators: BTreeMap<Operator, Vec<String>>,
}
impl SourceSetReport {
    pub fn independent_operators(&self) -> usize {
        self.operators.len()
    }
}

/// Validate a declared set of NTS source hostnames: every host must map to an approved operator,
/// duplicates are refused, and the number of DISTINCT operators must be at least
/// [`MIN_INDEPENDENT_OPERATORS`].
pub fn validate_source_set<S: AsRef<str>>(hosts: &[S]) -> Result<SourceSetReport, String> {
    let mut operators: BTreeMap<Operator, Vec<String>> = BTreeMap::new();
    let mut seen = std::collections::BTreeSet::new();
    for host in hosts {
        let normal = normalize_host(host.as_ref())?;
        let op = operator_of(&normal)?;
        if !seen.insert(normal.clone()) {
            return Err(format!("nts source {normal:?} is listed twice"));
        }
        operators.entry(op).or_default().push(normal);
    }
    if operators.len() < MIN_INDEPENDENT_OPERATORS {
        let found: Vec<&str> = operators.keys().map(|o| o.id()).collect();
        return Err(format!(
            "nts source set has {} independent operator(s) {found:?}; at least {MIN_INDEPENDENT_OPERATORS} required (hostnames of one operator count once)",
            operators.len()
        ));
    }
    Ok(SourceSetReport { operators })
}

/// Validate the text of a chrony configuration against the profile's preconditions: every
/// `server` line is NTS, no `pool`/`peer` lines (a pool can span operators and is unauthenticated
/// without `nts`), `leapsecmode system` is set (POSIX step), no `smoothtime` and no `leapsectz`
/// (smearing / locally scheduled leap are unsupported), and the NTS server hosts form a valid
/// source set.
pub fn validate_chrony_conf(text: &str) -> Result<SourceSetReport, String> {
    let mut hosts = Vec::new();
    let mut leapsecmode_system = false;
    let mut authentication_required = false;
    let mut source_floor = false;
    let mut loopback_v4 = false;
    let mut loopback_v6 = false;
    let mut monitoring_port = false;
    let mut monitoring = false;
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        let mut words = line.split_whitespace();
        let Some(key) = words.next() else { continue };
        let rest: Vec<&str> = words.collect();
        match key.to_ascii_lowercase().as_str() {
            "server" => {
                let Some(host) = rest.first() else {
                    return Err("chrony server line without a host".into());
                };
                if !rest[1..].iter().any(|w| w.eq_ignore_ascii_case("nts")) {
                    return Err(format!("chrony server {host:?} is not NTS-authenticated"));
                }
                hosts.push((*host).to_string());
            }
            "pool" | "peer" => return Err(format!("chrony `{key}` lines are not allowed")),
            "smoothtime" | "leapsectz" | "leapseclist" => {
                return Err(format!("chrony `{key}` is not supported (POSIX step required)"));
            }
            "leapsecmode" => {
                leapsecmode_system = rest.first().is_some_and(|w| w.eq_ignore_ascii_case("system"));
                if !leapsecmode_system {
                    return Err("chrony leapsecmode must be `system`".into());
                }
            }
            "authselectmode" => {
                if authentication_required || rest != ["require"] {
                    return Err("chrony must declare authselectmode require exactly once".into());
                }
                authentication_required = true;
            }
            "minsources" => {
                if source_floor || rest.len() != 1 || rest[0].parse::<usize>().ok()
                    .is_none_or(|n| n < MIN_INDEPENDENT_OPERATORS) {
                    return Err("chrony minsources must be at least three exactly once".into());
                }
                source_floor = true;
            }
            "bindcmdaddress" => match rest.as_slice() {
                ["127.0.0.1"] if !loopback_v4 => loopback_v4 = true,
                ["::1"] if !loopback_v6 => loopback_v6 = true,
                _ => return Err("chrony monitoring binds must be unique IPv4/IPv6 loopback".into()),
            },
            "cmdport" => {
                if monitoring_port || rest != ["323"] {
                    return Err("chrony monitoring port must be 323 exactly once".into());
                }
                monitoring_port = true;
            }
            "opencommands" => {
                let expected: std::collections::BTreeSet<_> = ["tracking", "sources", "sourcestats", "authdata",
                    "ntpdata", "selectdata", "sourcename"].into_iter().collect();
                if monitoring || rest.len() != expected.len() || rest.into_iter().collect::<std::collections::BTreeSet<_>>() != expected {
                    return Err("chrony read-only monitoring command declaration differs".into());
                }
                monitoring = true;
            }
            // This validator consumes one fully reconciled declaration. It cannot
            // recursively establish an effective daemon configuration, and does
            // not approve hidden/runtime sources or certificate-time bypasses.
            "include" | "confdir" | "sourcedir" | "nocerttimecheck" | "local" | "refclock" | "manual" => {
                return Err(format!("chrony `{key}` requires a separate effective-configuration review"));
            }
            _ => {}
        }
    }
    if !leapsecmode_system {
        return Err("chrony configuration must set `leapsecmode system`".into());
    }
    if !(authentication_required && source_floor && loopback_v4 && loopback_v6 && monitoring_port && monitoring) {
        return Err("chrony authenticated selection and loopback read-only monitoring declaration required".into());
    }
    validate_source_set(&hosts)
}

#[cfg(test)]
mod tests {
    use super::*;

    const APPROVED: [&str; 4] = [
        "time.cloudflare.com",
        "nts.netnod.se",
        "ptbtime1.ptb.de",
        "ntppool1.time.nl",
    ];

    #[test]
    fn hosts_map_to_operators() {
        for (h, op) in [
            ("time.cloudflare.com", Operator::Cloudflare),
            ("TIME.Cloudflare.com.", Operator::Cloudflare),
            ("nts.netnod.se", Operator::Netnod),
            ("sth1.nts.netnod.se", Operator::Netnod),
            ("svl2.nts.netnod.se", Operator::Netnod),
            ("ptbtime1.ptb.de", Operator::Ptb),
            ("ptbtime4.ptb.de", Operator::Ptb),
            ("ntppool1.time.nl", Operator::Sidn),
            ("ntppool2.time.nl", Operator::Sidn),
        ] {
            assert_eq!(operator_of(h), Ok(op), "{h}");
        }
        for h in [
            "ntspool.time.nl",
            "nts1.time.nl",
            "any.time.nl",
            "ntppool3.time.nl",
            "ptbtime5.ptb.de",
            "evil.nts.netnod.se.example.com",
            "a.b.nts.netnod.se",
            "time.cloudflare.com:1234",
            "162.159.200.1",
            "https://time.cloudflare.com",
            "",
            "pool.ntp.org",
        ] {
            assert!(operator_of(h).is_err(), "{h}");
        }
    }

    #[test]
    fn fewer_than_three_independent_operators_is_rejected() {
        let report = validate_source_set(&APPROVED).unwrap();
        assert_eq!(report.independent_operators(), 4);
        // Exactly three operators is the floor and passes.
        assert_eq!(validate_source_set(&APPROVED[..3]).unwrap().independent_operators(), 3);
        // Two operators fail.
        let two = validate_source_set(&APPROVED[..2]).unwrap_err();
        assert!(two.contains("independent operator"), "{two}");
        assert!(validate_source_set::<&str>(&[]).is_err());
        // MANY hostnames of ONE operator (and of two) never reach three.
        let netnod: Vec<String> = ["gbg1", "gbg2", "lul1", "lul2", "mmo1", "mmo2", "sth1", "sth2", "svl1", "svl2"]
            .iter()
            .map(|s| format!("{s}.nts.netnod.se"))
            .collect();
        assert!(validate_source_set(&netnod).is_err());
        let mut mix = netnod.clone();
        mix.extend(["ptbtime1.ptb.de".into(), "ptbtime2.ptb.de".into(), "ptbtime3.ptb.de".into(), "ptbtime4.ptb.de".into()]);
        let e = validate_source_set(&mix).unwrap_err();
        assert!(e.contains("2 independent"), "{e}");
        // Extra hostnames of an operator already present do not change the count.
        let mut more = APPROVED[..3].to_vec();
        more.extend(["ptbtime2.ptb.de", "gbg1.nts.netnod.se"]);
        assert_eq!(validate_source_set(&more).unwrap().independent_operators(), 3);
        let mut with_two_of_one = APPROVED[..2].to_vec();
        with_two_of_one.extend(["ptbtime1.ptb.de", "ptbtime2.ptb.de"]);
        assert_eq!(validate_source_set(&with_two_of_one).unwrap().operators[&Operator::Ptb].len(), 2);
        // Duplicates and unknown hosts are configuration errors, not silently counted.
        assert!(validate_source_set(&["time.cloudflare.com", "TIME.cloudflare.com", "nts.netnod.se", "ptbtime1.ptb.de"]).is_err());
        assert!(validate_source_set(&["time.cloudflare.com", "nts.netnod.se", "ptbtime1.ptb.de", "pool.ntp.org"]).is_err());
    }

    #[test]
    fn shipped_chrony_template_is_valid_and_bad_variants_are_not() {
        let template = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../deploy/chrony/mutiny-nts-sources.conf"
        ));
        let report = validate_chrony_conf(template).unwrap();
        assert_eq!(report.independent_operators(), 4);
        let without = |needle: &str| -> String {
            template
                .lines()
                .filter(|l| !l.contains(needle) || l.trim_start().starts_with('#'))
                .collect::<Vec<_>>()
                .join("\n")
        };
        // Dropping two operators leaves two: rejected.
        assert!(validate_chrony_conf(&without("ptbtime").replace("ntppool1.time.nl", "ptbtime9.invalid")).is_err());
        let two = without("ptbtime");
        assert_eq!(validate_chrony_conf(&two).unwrap().independent_operators(), 3);
        assert!(validate_chrony_conf(&without("nts.netnod.se").replace("ptbtime1.ptb.de", "x")).is_err());
        assert!(validate_chrony_conf(&without("leapsecmode")).is_err());
        assert!(validate_chrony_conf(&format!("{template}\nsmoothtime 400 0.001\n")).is_err());
        assert!(validate_chrony_conf(&format!("{template}\npool pool.ntp.org iburst\n")).is_err());
        assert!(validate_chrony_conf(&format!("{template}\nserver ntp.example.net iburst\n")).is_err());
        assert!(validate_chrony_conf(&template.replace("leapsecmode system", "leapsecmode slew")).is_err());
        for directive in ["authselectmode", "minsources", "bindcmdaddress", "cmdport", "opencommands"] {
            assert!(validate_chrony_conf(&without(directive)).is_err(), "{directive}");
        }
        for extra in ["authselectmode ignore", "minsources 2", "bindcmdaddress 0.0.0.0", "cmdport 0",
            "opencommands tracking", "nocerttimecheck 1", "include /other.conf", "leapseclist /leaps"] {
            assert!(validate_chrony_conf(&format!("{template}\n{extra}\n")).is_err(), "{extra}");
        }
    }
}
