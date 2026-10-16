//! Exact public export equality against STILL-OWNED live source callback state.
//! No secret transcript export, public import, new signer, historical replay
//! authentication, deployment/method qualification or production clock issuer.
use super::{AcquisitionReport,Config,DiagnosticElapsedCapture,diagnostic_reconstruction,
    read_elapsed_diagnostic,reconstruct_diagnostic_interval};
use serde_json::Value;
use std::io;
fn refusal()->io::Error {io::Error::other("retained live acquisition export refused")}
pub struct RetainedAcquisition {report:AcquisitionReport,now:DiagnosticElapsedCapture,canonical:Vec<u8>}
/// Borrowed lifetime proof of exact same live result ownership, NOT a portable
/// receipt or trusted historical source proof. No raw constructor/Deserialize.
pub struct LiveVerifiedExport<'a> {owner:&'a RetainedAcquisition}
impl LiveVerifiedExport<'_> {
    pub fn canonical(&self)->&[u8] {&self.owner.canonical}
}
fn provider(p:&super::Provider)->Value {
    // Existing hex crate is DEV-only here; canonical lowerhex without a new edge.
    let digest=p.no_smear_profile_evidence_sha256.iter().map(|b|format!("{b:02x}")).collect::<String>();
    serde_json::json!({"hostname":p.hostname,"operator":p.operator,
        "key_establishment_port":p.key_establishment_port,"no_smear_profile_evidence_sha256":digest})
}
fn reconstruct(report:&AcquisitionReport,now:&DiagnosticElapsedCapture)->io::Result<Vec<u8>> {
    report.config.validate()?;
    if report.accepted.is_empty() || report.accepted.len()>report.config.providers.len()
        || report.failures.len()>report.config.providers.len()
        || report.accepted.len().checked_add(report.failures.len()).ok_or_else(refusal)?>report.config.providers.len() {return Err(refusal());}
    let current=now.reading();let mut accepted=Vec::new();let mut operators=std::collections::BTreeSet::new();
    let mut positions=std::collections::BTreeSet::new();let mut last=None;let mut abi=None;
    for observation in &report.accepted {
        let transcript=observation.diagnostic_transcript();
        let position=report.config.providers.iter().position(|p|p==transcript.provider()).ok_or_else(refusal)?;
        if last.is_some_and(|p|position<=p) || !positions.insert(position)
            || !operators.insert(observation.operator()) || transcript.bounds()!=&report.config.bounds
            || observation.hostname()!=transcript.provider().hostname
            || observation.operator()!=transcript.provider().operator
            || observation.profile_reference()!=transcript.provider().no_smear_profile_evidence_sha256
            || !(48..=1024).contains(&transcript.response_bytes()) || !(1..=15).contains(&transcript.stratum()) {
            return Err(refusal());
        }
        last=Some(position);
        let interval=reconstruct_diagnostic_interval(transcript.arithmetic(),&report.config.bounds)?.view();
        if interval!=observation.interval() || interval.boot_id!=current.2
            || current.0<interval.active_ns || current.1<interval.inclusive_ns {return Err(refusal());}
        let raw:Value=serde_json::from_slice(transcript.arithmetic()).map_err(|_|refusal())?;
        let this_abi=raw["elapsed_abi"].as_str().ok_or_else(refusal)?.to_owned();
        if abi.as_ref().is_some_and(|a|a!=&this_abi) {return Err(refusal());}abi=Some(this_abi);
        accepted.push(serde_json::json!({"provider":provider(transcript.provider()),"arithmetic":raw,
            "destination":transcript.destination().to_string(),"response_bytes":transcript.response_bytes(),
            "stratum":transcript.stratum(),"leap":match observation.leap(){super::Leap::Clear=>"clear",
                super::Leap::Insert=>"insert",super::Leap::Delete=>"delete"}}));
    }
    let mut failed_positions=std::collections::BTreeSet::new();let mut last_failure=None;
    let failures=report.failures.iter().map(|(hostname,kind)| {
        let position=report.config.providers.iter().position(|p|p.hostname==*hostname).ok_or_else(refusal)?;
        if positions.contains(&position) || !failed_positions.insert(position)
            || last_failure.is_some_and(|p|position<=p) {return Err(refusal());}
        last_failure=Some(position);
        Ok(serde_json::json!({"hostname":hostname,"error_kind":format!("{kind:?}")}))
    }).collect::<io::Result<Vec<_>>>()?;
    let raw_now:Value=serde_json::from_slice(now.raw()).map_err(|_|refusal())?;
    diagnostic_reconstruction::encode(&serde_json::json!({
        "format":"build8/native-nts/live-acquisition-export-v1",
        "classification":"PUBLIC_NUMERICAL_EXPORT_NOT_HISTORICAL_AUTHENTICATION_OR_QUALIFICATION",
        "stage":"INPUT_RETENTION_NOT_ENGINE_ANCHOR_COMMIT","elapsed_abi":abi.ok_or_else(refusal)?,
        "config":{"providers":report.config.providers.iter().map(provider).collect::<Vec<_>>(),
            "timeout_seconds":report.config.timeout_seconds,"bounds":report.config.bounds},
        "now":raw_now,"accepted":accepted,"failures":failures}))
}
/// Consume the actual report from acquire(), not bytes or caller authenticity.
/// This extra capture is explicitly the INPUT-RETENTION point. It does not
/// pretend to be the holdover engine's calibration/anchor-commit read.
pub fn retain_acquisition(report:AcquisitionReport,expected:&Config)->io::Result<RetainedAcquisition> {
    try_retain_acquisition(report,expected).map_err(|(_,error)|error)
}
/// Ownership-preserving diagnostic retention. A failure returns the ORIGINAL
/// opaque live report rather than discarding it or manufacturing an export.
pub fn try_retain_acquisition(report:AcquisitionReport,expected:&Config)
    ->std::result::Result<RetainedAcquisition,(AcquisitionReport,io::Error)> {
    let captured=(|| {
        expected.validate()?;
        if !report.matches_config(expected) {return Err(refusal());}
        let now=read_elapsed_diagnostic(expected.bounds.maximum_sampling_span_ns).ok_or_else(refusal)?;
        let canonical=reconstruct(&report,&now)?;Ok((now,canonical))
    })();
    match captured {
        Ok((now,canonical))=>Ok(RetainedAcquisition{report,now,canonical}),
        Err(error)=>Err((report,error)),
    }
}
impl RetainedAcquisition {
    pub fn report(&self)->&AcquisitionReport {&self.report}
    pub fn public_export(&self)->&[u8] {&self.canonical}
    pub fn input_capture(&self)->&DiagnosticElapsedCapture {&self.now}
    pub fn verify_export<'a>(&'a self,raw:&[u8],expected:&Config)->io::Result<LiveVerifiedExport<'a>> {
        if raw.is_empty() || raw.len()>64*1024 || !self.report.matches_config(expected)
            || raw!=self.canonical || reconstruct(&self.report,&self.now)?!=self.canonical {return Err(refusal());}
        Ok(LiveVerifiedExport{owner:self})
    }
}
#[cfg(test)] mod tests {
    use super::*;
    fn config()->Config {
        Config{providers:(1..=3).map(|n|super::super::Provider {hostname:format!("source{n}.invalid"),
            operator:format!("Operator{n}"),key_establishment_port:4460,
            no_smear_profile_evidence_sha256:[n;32]}).collect(),timeout_seconds:10,
            bounds:super::super::native_stamp::test_bounds()}
    }
    #[tokio::test(flavor="current_thread")]
    async fn genuine_private_live_export_ownership_refuses_partial_foreign_context_and_public_auth_flags() {
        // Authored only. Existing private software TLS/NTS fixture plus actual
        // native input capture; no public replay authenticity or qualification.
        let config=config();let report=super::super::offline_auth::genuine_test_report(config.clone(),
            ntp_proto::NtpLeapIndicator::NoWarning).await.unwrap();
        let retained=retain_acquisition(report,&config).unwrap();let raw=retained.public_export();
        assert_eq!(retained.verify_export(raw,&config).unwrap().canonical(),raw);
        assert!(retained.verify_export(&raw[..raw.len()-1],&config).is_err());
        let mut whitespace=raw.to_vec();whitespace.push(b' ');
        assert!(retained.verify_export(&whitespace,&config).is_err());
        let mut different=config.clone();different.bounds.era_context_sha256="b".repeat(64);
        assert!(retained.verify_export(raw,&different).is_err());
        for field in ["authenticated","PASS","qualification","signature","cookies"] {
            let mut v:Value=serde_json::from_slice(raw).unwrap();v[field]=true.into();
            assert!(retained.verify_export(&serde_json::to_vec(&v).unwrap(),&config).is_err());
        }
        let v:Value=serde_json::from_slice(raw).unwrap();assert_eq!(v["accepted"].as_array().unwrap().len(),3);
        assert_eq!(v["stage"],"INPUT_RETENTION_NOT_ENGINE_ANCHOR_COMMIT");
    }
    #[tokio::test(flavor="current_thread")]
    async fn genuine_private_retained_callback_reconstruction_refuses_changed_internal_documentary_input() {
        let config=config();let report=super::super::offline_auth::genuine_test_report(config.clone(),
            ntp_proto::NtpLeapIndicator::NoWarning).await.unwrap();
        let mut retained=retain_acquisition(report,&config).unwrap();let old=retained.public_export().to_vec();
        // TEST-only module access. No ordinary raw or authentication constructor.
        retained.report.accepted[0].diagnostic.arithmetic=b"{}".to_vec();
        assert!(retained.verify_export(&old,&config).is_err());
    }
    #[tokio::test(flavor="current_thread")]
    async fn genuine_private_live_report_reconstruction_refuses_overlapping_failure_and_callback_scopes() {
        let config=config();let mut report=super::super::offline_auth::genuine_test_report(config.clone(),
            ntp_proto::NtpLeapIndicator::NoWarning).await.unwrap();
        // Private TEST corruption of an otherwise actual software-authenticated
        // report; no ordinary failure/result import exists.
        report.failures.push((config.providers[0].hostname.clone(),io::ErrorKind::TimedOut));
        assert!(retain_acquisition(report,&config).is_err());
    }
    #[tokio::test(flavor="current_thread")]
    async fn genuine_private_failed_retention_returns_original_report_without_public_import() {
        let config=config();let report=super::super::offline_auth::genuine_test_report(config.clone(),
            ntp_proto::NtpLeapIndicator::NoWarning).await.unwrap();
        let original_interval=report.accepted()[0].interval();
        let mut foreign=config.clone();foreign.bounds.era_context_sha256="b".repeat(64);
        let (original,_)=match try_retain_acquisition(report,&foreign) {
            Err(refused)=>refused,Ok(_)=>panic!("foreign retention accepted"),
        };
        assert!(original.matches_config(&config));assert_eq!(original.accepted().len(),3);
        assert_eq!(original.accepted()[0].interval(),original_interval);
    }
}
