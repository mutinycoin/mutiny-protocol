//! Executable necessary arithmetic for TWO obligations from bound raw records.
//! Documentary provenance, decoded bytes and successful arithmetic NEVER grant
//! accepted method/physical qualification, source authentication or clock input.
//! Protected normal resolver is separate; method verification remains absent;
//! six other obligations and
//! complete current loaded-code binding remain independent fail-closed gates.
use super::native_nts_deployment_record::{canonical_value,canonical_tree,Error};
use super::native_nts_measurement_checks::{frequency_interval,initial_interval};
use mutiny_clock_native_nts_v1::{Config,IntervalView,reconstruct_diagnostic_interval};
use mutiny_consensus_v8::holdover_clock_v1::ClockProfile;
use serde_json::{Map,Value};
use sha2::{Digest,Sha256};
use std::collections::BTreeSet;
type Result<T>=std::result::Result<T,Error>;
pub(super) struct RawRecords<'a> {pub(super) report:&'a [u8],pub(super) method:&'a [u8],
    pub(super) raw:&'a [u8],pub(super) environment:&'a [u8]}
/// Arithmetic findings only. Private fields; no capability conversion/issuer.
pub(super) struct NecessaryReport {frequency:(u64,u64,u64),initial:(u64,u64),
    frequency_raw:[u8;32],initial_raw:[u8;32]}
impl NecessaryReport {
    pub(super) fn frequency(&self)->(u64,u64,u64) {self.frequency}
    pub(super) fn initial(&self)->(u64,u64) {self.initial}
    /// Exact bytes actually checked by the arithmetic constructors. These are
    /// coverage inputs, never a successful qualification or caller pin.
    pub(super) fn documentary_inputs(&self)->([u8;32],[u8;32]) { (self.frequency_raw,self.initial_raw) }
    pub(super) fn qualification(&self)->Result<()> {Err(Error::MissingQualification)}
}
/// All eight exact documentary inputs, NOT verified experiment methods.
/// Private construction prevents a caller from omitting an obligation or
/// substituting a success flag. No conversion to a qualification capability.
pub(super) struct MeasurementInputs {necessary:NecessaryReport,methods:Vec<MethodInput>}
struct MethodInput {obligation:&'static str,algorithm:String,method_sha256:[u8;32],raw:Value}
impl MeasurementInputs {
    pub(super) fn necessary(&self)->&NecessaryReport {&self.necessary}
    pub(super) fn methods(&self)->impl Iterator<Item=(&'static str,&str,[u8;32])> {
        self.methods.iter().map(|m|(m.obligation,m.algorithm.as_str(),m.method_sha256))
    }
    pub(super) fn raw_for(&self,obligation:&str)->Option<&Value> {
        self.methods.iter().find(|m|m.obligation==obligation).map(|m|&m.raw)
    }
}
/// Exhaustive held-data dispatch before any future accepted-method verifier.
/// The old arithmetic-v1 method format contains no confidence protocol,
/// margin, authenticated instrument verifier or six experiment algorithms.
/// Retaining it supplies exact inputs; it does not invent any of those inputs.
pub(super) fn resolve_inputs(subject:&Value,measurements:&Value,profile:&ClockProfile,
    config:&Config,records:[RawRecords<'_>;8])->Result<MeasurementInputs> {
    use super::native_nts_qualification::OBLIGATIONS;
    super::native_nts_backend::validate_profile(profile,config).map_err(|_|Error::QualificationProvenance)?;
    exact(measurements,&OBLIGATIONS)?;
    let frequency_raw_pin=hash(records[0].raw);let initial_raw_pin=hash(records[1].raw);
    let mut methods=Vec::with_capacity(OBLIGATIONS.len());
    for (obligation,records) in OBLIGATIONS.into_iter().zip(records) {
        // Bounds precede parsing/allocation, including the method inspected
        // to select dispatch. objects() independently verifies all four pins.
        if records.method.is_empty() || records.method.len()>64*1024 {return Err(Error::Bound);}
        let method=canonical_value(records.method)?;
        let algorithm=method["algorithm"].as_str().filter(|s|!s.is_empty())
            .ok_or(Error::QualificationEncoding)?.to_owned();
        let method_sha256=digest(&measurements[obligation]["method_sha256"])?;
        let raw=objects(subject,&measurements[obligation],obligation,&algorithm,records)?;
        methods.push(MethodInput {obligation,algorithm,method_sha256,raw});
    }
    // ONLY the two existing reviewed arithmetic algorithms are executed.
    // Other records remain typed documentary inputs until their genuine
    // selected method and authenticated raw-trace mechanisms are implemented.
    if methods[0].algorithm!="elapsed-reference-interval-v1"
        || methods[1].algorithm!="native-nts-total-initial-v1" {return Err(Error::MissingQualification);}
    let necessary=NecessaryReport {frequency:frequency(&methods[0].raw,subject,profile)?,
        initial:initial(&methods[1].raw,subject,profile,config)?,
        frequency_raw:frequency_raw_pin,initial_raw:initial_raw_pin};
    Ok(MeasurementInputs {necessary,methods})
}
fn exact<'a>(v:&'a Value,keys:&[&str])->Result<&'a Map<String,Value>> {
    let m=v.as_object().ok_or(Error::QualificationEncoding)?;
    if m.len()!=keys.len() || m.keys().any(|k|!keys.contains(&k.as_str())) {return Err(Error::QualificationEncoding);}Ok(m)
}
fn number(v:&Value)->Result<u64> {v.as_u64().ok_or(Error::QualificationEncoding)}
fn digest(v:&Value)->Result<[u8;32]> {
    let s=v.as_str().ok_or(Error::QualificationEncoding)?;let mut out=[0;32];
    if s.len()!=64 || !s.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || hex::decode_to_slice(s,&mut out).is_err() || out==[0;32] {return Err(Error::QualificationProvenance);}Ok(out)
}
fn boot(v:&Value)->Result<u128> {
    let s=v.as_str().ok_or(Error::QualificationEncoding)?;
    if s.len()!=32 || !s.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {return Err(Error::QualificationEncoding);}
    let id=u128::from_str_radix(s,16).map_err(|_|Error::QualificationEncoding)?;
    if id==0 {return Err(Error::QualificationProvenance);}Ok(id)
}
fn hash(raw:&[u8])->[u8;32] {Sha256::digest(raw).into()}
fn objects(subject:&Value,refs:&Value,obligation:&str,algorithm:&str,records:RawRecords<'_>)->Result<Value> {
    let refs=exact(refs,&["report_sha256","method_sha256","raw_data_sha256","environment_sha256"])?;
    // All four objects are independently bounded to the existing64KiB canonical
    // record budget before parsing. No unbounded allocation or partial objects.
    let mut objects=Vec::new();
    for (key,raw) in [("report_sha256",records.report),("method_sha256",records.method),
        ("raw_data_sha256",records.raw),("environment_sha256",records.environment)] {
        if raw.is_empty() || raw.len()>64*1024 {return Err(Error::Bound);}
        if hash(raw)!=digest(&refs[key])? {return Err(Error::QualificationProvenance);}
        objects.push(canonical_value(raw)?);
    }
    let report=exact(&objects[0],&["format","obligation","method_sha256","raw_data_sha256","environment_sha256"])?;
    if report["format"].as_str()!=Some("build8/native-nts/measurement-report-v1")
        || report["obligation"].as_str()!=Some(obligation) {return Err(Error::QualificationEncoding);}
    for key in ["method_sha256","raw_data_sha256","environment_sha256"] {
        if report[key]!=refs[key] {return Err(Error::QualificationProvenance);}
    }
    let method=exact(&objects[1],&["format","obligation","algorithm","subject"])?;
    if method["format"].as_str()!=Some("build8/native-nts/arithmetic-method-v1")
        || method["obligation"].as_str()!=Some(obligation) || method["algorithm"].as_str()!=Some(algorithm)
        || &method["subject"]!=subject {return Err(Error::QualificationScope);}
    let environment=exact(&objects[3],&["format","obligation","subject","instrument_provenance_sha256"])?;
    if environment["format"].as_str()!=Some("build8/native-nts/measurement-environment-v1")
        || environment["obligation"].as_str()!=Some(obligation) || &environment["subject"]!=subject {
        return Err(Error::QualificationScope);
    }
    digest(&environment["instrument_provenance_sha256"])?;
    // Instrument digest is a reference, NOT evidence that a sensor was genuine,
    // conservative, traceably calibrated or met any confidence/margin protocol.
    Ok(objects.remove(2))
}
fn abi(raw:&Value,subject:&Value)->Result<u64> {
    let name=raw["elapsed_abi"].as_str().ok_or(Error::QualificationEncoding)?;
    let quantum=match name {
        "clock_gettime:CLOCK_MONOTONIC/CLOCK_BOOTTIME/CLOCK_MONOTONIC:ns:v1"=>1,
        "QueryUnbiasedInterruptTimePrecise/QueryInterruptTimePrecise:100ns:v1"=>100,_=>return Err(Error::UnsupportedCurrentFacts),
    };
    let canonical=serde_json::to_vec(&canonical_tree(&serde_json::json!({"implementation":name}))?).map_err(|_|Error::QualificationEncoding)?;
    if hash(&canonical)!=digest(&subject["elapsed_abi_sha256"])? {return Err(Error::QualificationScope);}Ok(quantum)
}
fn frequency(raw:&Value,subject:&Value,profile:&ClockProfile)->Result<(u64,u64,u64)> {
    let r=exact(raw,&["format","obligation","elapsed_abi","boot_id_hex","active_start_ns","active_end_ns","reference_start","reference_end"])?;
    if r["format"].as_str()!=Some("build8/native-nts/raw-frequency-v1")
        || r["obligation"].as_str()!=Some("frequency_error") {return Err(Error::QualificationEncoding);}
    boot(&r["boot_id_hex"])?;
    let q=abi(raw,subject)?;let start=number(&r["active_start_ns"])?;let end=number(&r["active_end_ns"])?;
    if start==0 || start%q!=0 || end%q!=0 {return Err(Error::QualificationProvenance);}
    let elapsed=end.checked_sub(start).ok_or(Error::QualificationProvenance)?;
    let range=|v:&Value|->Result<(u64,u64)> {
        let v=exact(v,&["lower_ns","upper_ns"])?;let lo=number(&v["lower_ns"])?;let hi=number(&v["upper_ns"])?;
        if hi<lo {return Err(Error::QualificationProvenance);}Ok((lo,hi))
    };
    let first=range(&r["reference_start"])?;let last=range(&r["reference_end"])?;
    let lower=last.0.checked_sub(first.1).ok_or(Error::QualificationProvenance)?;
    let upper=last.1.checked_sub(first.0).ok_or(Error::QualificationProvenance)?;
    frequency_interval(profile,elapsed,lower,upper)?;Ok((elapsed,lower,upper))
}
fn now(v:&Value,config:&Config,quantum:u64)->Result<(u64,u64,u128)> {
    let v=exact(v,&["active_before_ns","inclusive_ns","active_after_ns","boot_id_hex"])?;
    let a=number(&v["active_before_ns"])?;let c=number(&v["active_after_ns"])?;let b=number(&v["inclusive_ns"])?;
    let span=c.checked_sub(a).ok_or(Error::QualificationProvenance)?;
    if a==0 || b<a || span>config.bounds.maximum_sampling_span_ns
        || [a,b,c].iter().any(|n|n%quantum!=0) {return Err(Error::QualificationProvenance);}
    Ok((a.checked_add(span/2).ok_or(Error::QualificationProvenance)?,b,boot(&v["boot_id_hex"])?))
}
fn roll(i:IntervalView,at:(u64,u64,u128),profile:&ClockProfile)->Result<(u64,u64)> {
    // Exact native_backend::outward_ms and engine roll/continuity/gap ledger.
    let lo=i.lower_posix_ns/1_000_000;
    let hi=i.upper_posix_ns.checked_add(999_999).ok_or(Error::QualificationProvenance)?/1_000_000;
    let width=hi.checked_sub(lo).ok_or(Error::QualificationProvenance)?;
    let midpoint=lo.checked_add(width/2).ok_or(Error::QualificationProvenance)?;
    let half=width.checked_add(1).ok_or(Error::QualificationProvenance)?/2;
    if half>profile.max_source_uncertainty_ms || i.boot_id!=at.2 {return Err(Error::QualificationProvenance);}
    let boot=at.1.checked_sub(i.inclusive_ns).ok_or(Error::QualificationProvenance)?;
    let mono=at.0.checked_sub(i.active_ns).ok_or(Error::QualificationProvenance)?;
    if boot.abs_diff(mono)/1_000_000>profile.max_suspend_gap_ms {return Err(Error::QualificationProvenance);}
    let age=boot/1_000_000;if age>profile.max_holdover_ms {return Err(Error::QualificationProvenance);}
    let drift=u64::try_from((u128::from(age)*u128::from(profile.drift_bound_ppb)).div_ceil(1_000_000_000))
        .map_err(|_|Error::QualificationProvenance)?;
    let old_gap=i128::from(i.inclusive_ns)-i128::from(i.active_ns);
    let new_gap=i128::from(at.1)-i128::from(at.0);
    let gap=u64::try_from((new_gap-old_gap).unsigned_abs()).map_err(|_|Error::QualificationProvenance)?;
    let widen=gap.div_ceil(1_000_000);
    let below=drift.checked_add(widen).ok_or(Error::QualificationProvenance)?;
    let above=age.checked_add(1).and_then(|n|n.checked_add(drift)).and_then(|n|n.checked_add(widen)).ok_or(Error::QualificationProvenance)?;
    let lower=midpoint.checked_sub(half).and_then(|n|n.checked_add(age)).and_then(|n|n.checked_sub(below)).ok_or(Error::QualificationProvenance)?;
    let upper=midpoint.checked_add(half).and_then(|n|n.checked_add(above)).ok_or(Error::QualificationProvenance)?;
    Ok((lower,upper))
}
fn hull(ranges:&[(u64,u64)],faults:u32)->Result<(u64,u64)> {
    if ranges.is_empty(){return Err(Error::QualificationProvenance);}
    let need=ranges.len()-(faults as usize).min(ranges.len()-1);
    let mut events=Vec::with_capacity(2*ranges.len());
    for (lo,hi) in ranges {if hi<lo{return Err(Error::QualificationProvenance);}events.push((*lo,1i32));events.push((*hi,-1));}
    events.sort_unstable_by(|a,b|a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
    let (mut count,mut first,mut last)=(0i64,None,None);
    for (point,delta) in events {
        if delta<0 && count>=need as i64 {last=Some(point);}count+=i64::from(delta);
        if delta>0 && count>=need as i64 && first.is_none(){first=Some(point);}
    }
    match (first,last){(Some(lo),Some(hi)) if lo<=hi=>Ok((lo,hi)),_=>Err(Error::QualificationProvenance)}
}
pub(super) fn initial(raw:&Value,subject:&Value,profile:&ClockProfile,config:&Config)->Result<(u64,u64)> {
    let r=exact(raw,&["format","obligation","elapsed_abi","now","samples"])?;
    if r["format"].as_str()!=Some("build8/native-nts/raw-initial-v1")
        || r["obligation"].as_str()!=Some("capture_uncertainty") {return Err(Error::QualificationEncoding);}
    let at=now(&r["now"],config,abi(raw,subject)?)?;let samples=r["samples"].as_array().ok_or(Error::QualificationEncoding)?;
    if samples.len()<profile.min_sources as usize || samples.len()>config.providers.len() {return Err(Error::QualificationProvenance);}
    let mut operators=BTreeSet::new();let mut ranges=Vec::new();
    for sample in samples {
        let sample=exact(sample,&["provider","arithmetic"])?;let provider=&sample["provider"];
        let mut selected=None;
        for p in &config.providers {
            let value=serde_json::json!({"hostname":p.hostname,"operator":p.operator,"key_establishment_port":p.key_establishment_port,
                "no_smear_profile_evidence_sha256":hex::encode(p.no_smear_profile_evidence_sha256)});
            if provider==&value {selected=Some(p);break;}
        }
        let p=selected.ok_or(Error::QualificationScope)?;
        if !operators.insert(p.operator.as_str()) {return Err(Error::QualificationProvenance);}
        if sample["arithmetic"]["elapsed_abi"]!=r["elapsed_abi"] {return Err(Error::QualificationScope);}
        let raw=serde_json::to_vec(&canonical_tree(&sample["arithmetic"])?).map_err(|_|Error::QualificationEncoding)?;
        let i=reconstruct_diagnostic_interval(&raw,&config.bounds).map_err(|_|Error::QualificationProvenance)?.view();
        ranges.push(roll(i,at,profile)?);
    }
    let interval=hull(&ranges,profile.max_faulty_sources)?;
    initial_interval(profile,interval.0,interval.1)?;Ok(interval)
}
pub(super) fn verify(subject:&Value,measurements:&Value,profile:&ClockProfile,config:&Config,
    frequency_records:RawRecords<'_>,initial_records:RawRecords<'_>)->Result<NecessaryReport> {
    let frequency_raw_pin=hash(frequency_records.raw);let initial_raw_pin=hash(initial_records.raw);
    super::native_nts_backend::validate_profile(profile,config).map_err(|_|Error::QualificationProvenance)?;
    let frequency_raw=objects(subject,&measurements["frequency_error"],"frequency_error","elapsed-reference-interval-v1",frequency_records)?;
    let initial_raw=objects(subject,&measurements["capture_uncertainty"],"capture_uncertainty","native-nts-total-initial-v1",initial_records)?;
    Ok(NecessaryReport{frequency:frequency(&frequency_raw,subject,profile)?,initial:initial(&initial_raw,subject,profile,config)?,
        frequency_raw:frequency_raw_pin,initial_raw:initial_raw_pin})
}
#[cfg(test)]
mod tests {
    use super::*;
    const ABI:&str="clock_gettime:CLOCK_MONOTONIC/CLOCK_BOOTTIME/CLOCK_MONOTONIC:ns:v1";
    fn bytes(v:&Value)->Vec<u8> {serde_json::to_vec(&canonical_tree(v).unwrap()).unwrap()}
    fn profile()->ClockProfile {ClockProfile {max_source_uncertainty_ms:200,max_calibration_half_width_ms:250,
        min_sources:3,max_faulty_sources:1,drift_bound_ppb:100_000,max_holdover_ms:10_000,
        max_interval_half_width_ms:1000,max_suspend_gap_ms:50,confirm_calibrations:1}}
    fn config()->Config {Config {providers:(1..=3).map(|n|mutiny_clock_native_nts_v1::Provider {
        hostname:format!("source{n}.invalid"),operator:format!("Operator{n}"),key_establishment_port:4460,
        no_smear_profile_evidence_sha256:[n;32]}).collect(),timeout_seconds:10,
        bounds:mutiny_clock_native_nts_v1::AcquisitionBounds {era_lower_posix_ns:1_799_000_000_000_000_000,
            era_upper_posix_ns:1_801_000_000_000_000_000,era_context_sha256:"a".repeat(64),
            maximum_sampling_span_ns:250_000_000,wall_timestamp_uncertainty_ns:1_000_000,
            elapsed_drift_ppb:100_000,maximum_round_trip_ns:1_000_000_000,maximum_interval_uncertainty_ns:200_000_000}}}
    fn subject()->Value {serde_json::json!({"MODELED_ONLY":"no deployment or sensor authority",
        "elapsed_abi_sha256":hex::encode(hash(&bytes(&serde_json::json!({"implementation":ABI}))))})}
    fn timestamp(ns:u64)->u64 {((1_800_000_000u64+2_208_988_800)<<32)
        +u64::try_from(u128::from(ns)*(1u128<<32)/1_000_000_000).unwrap()}
    fn capture(active:u64,inclusive:u64)->Value {serde_json::json!({"active_before_ns":active,
        "active_after_ns":active+10_000,"inclusive_ns":inclusive,"boot_id_hex":format!("{:032x}",7)})}
    fn arithmetic()->Value {
        let sent=timestamp(0);let received=timestamp(100_000_000);let mid=sent+(received-sent)/2;
        let pair=|active:u64,inclusive:u64|serde_json::json!({"pre":capture(active,inclusive),
            "post":capture(active+20_000,inclusive+20_000)});
        serde_json::json!({"format":"build8/native-nts/raw-arithmetic-v1","elapsed_abi":ABI,
            "sent_ntp_fixed32":sent,"received_ntp_fixed32":received,
            "before":pair(1_000_000_000,2_000_000_000),"after":pair(1_100_000_000,2_100_000_000),
            "remote_midpoint_ntp_fixed32":mid,"local_midpoint_ntp_fixed32":mid,
            "delay_signed_fixed32":(1u64<<32)/10,"root_delay_signed_fixed32":0,
            "root_dispersion_signed_fixed32":0,"precision_sign":"negative","precision_magnitude":20})
    }
    fn raw_frequency()->Value {serde_json::json!({"format":"build8/native-nts/raw-frequency-v1",
        "obligation":"frequency_error","elapsed_abi":ABI,"boot_id_hex":format!("{:032x}",7),
        "active_start_ns":1,"active_end_ns":10_000_000_001u64,
        "reference_start":{"lower_ns":1_000_000_000u64,"upper_ns":1_000_000_000u64},
        "reference_end":{"lower_ns":11_000_000_000u64,"upper_ns":11_000_000_000u64}})}
    fn raw_initial(config:&Config)->Value {serde_json::json!({"format":"build8/native-nts/raw-initial-v1",
        "obligation":"capture_uncertainty","elapsed_abi":ABI,"now":capture(1_101_000_000,2_101_000_000),
        "samples":config.providers.iter().map(|p|serde_json::json!({"provider":{"hostname":p.hostname,
            "operator":p.operator,"key_establishment_port":p.key_establishment_port,
            "no_smear_profile_evidence_sha256":hex::encode(p.no_smear_profile_evidence_sha256)},"arithmetic":arithmetic()})).collect::<Vec<_>>()})}
    struct Bundle {report:Vec<u8>,method:Vec<u8>,raw:Vec<u8>,environment:Vec<u8>,refs:Value}
    impl Bundle {
        fn records(&self)->RawRecords<'_> {RawRecords {report:&self.report,method:&self.method,raw:&self.raw,environment:&self.environment}}
    }
    fn bundle(subject:&Value,obligation:&str,algorithm:&str,raw:&Value)->Bundle {
        let method=bytes(&serde_json::json!({"format":"build8/native-nts/arithmetic-method-v1","obligation":obligation,
            "algorithm":algorithm,"subject":subject}));let raw=bytes(raw);
        let environment=bytes(&serde_json::json!({"format":"build8/native-nts/measurement-environment-v1",
            "obligation":obligation,"subject":subject,"instrument_provenance_sha256":"7".repeat(64)}));
        let report=bytes(&serde_json::json!({"format":"build8/native-nts/measurement-report-v1","obligation":obligation,
            "method_sha256":hex::encode(hash(&method)),"raw_data_sha256":hex::encode(hash(&raw)),"environment_sha256":hex::encode(hash(&environment))}));
        let refs=serde_json::json!({"report_sha256":hex::encode(hash(&report)),"method_sha256":hex::encode(hash(&method)),
            "raw_data_sha256":hex::encode(hash(&raw)),"environment_sha256":hex::encode(hash(&environment))});
        Bundle {report,method,raw,environment,refs}
    }
    fn all_modeled_inputs(s:&Value,c:&Config)->(Vec<Bundle>,Value) {
        let mut refs=Map::new();
        let bundles=super::super::native_nts_qualification::OBLIGATIONS.iter().enumerate().map(|(at,name)| {
            let (algorithm,raw)=match at {0=>("elapsed-reference-interval-v1",raw_frequency()),
                1=>("native-nts-total-initial-v1",raw_initial(c)),
                _=>("UNIMPLEMENTED-MODELED-METHOD",serde_json::json!({"not_an_experiment":true}))};
            let b=bundle(s,name,algorithm,&raw);refs.insert((*name).into(),b.refs.clone());b
        }).collect();
        (bundles,Value::Object(refs))
    }
    #[test] fn modeled_all_eight_inputs_are_bound_without_granting_method_or_physical_qualification() {
        let s=subject();let p=profile();let c=config();let (bundles,refs)=all_modeled_inputs(&s,&c);
        let inputs=resolve_inputs(&s,&refs,&p,&c,std::array::from_fn(|at|bundles[at].records())).unwrap();
        assert_eq!(inputs.methods().count(),8);
        assert_eq!(inputs.necessary().frequency(),(10_000_000_000,10_000_000_000,10_000_000_000));
        assert_eq!(inputs.necessary().qualification(),Err(Error::MissingQualification));
        for name in super::super::native_nts_qualification::OBLIGATIONS {assert!(inputs.raw_for(name).is_some());}
        assert!(inputs.raw_for("foreign").is_none());
    }
    #[test] fn modeled_all_eight_dispatch_refuses_missing_or_replaced_nonarithmetic_artifacts() {
        let s=subject();let p=profile();let c=config();let (bundles,refs)=all_modeled_inputs(&s,&c);
        for fault in 0..8 {
            let records=std::array::from_fn(|at| {let mut r=bundles[at].records();
                if at==fault {r.raw=b"{}";}r});
            assert!(resolve_inputs(&s,&refs,&p,&c,records).is_err());
        }
        let mut incomplete=refs.clone();incomplete.as_object_mut().unwrap().remove("leap_behavior");
        assert!(resolve_inputs(&s,&incomplete,&p,&c,std::array::from_fn(|at|bundles[at].records())).is_err());
    }
    #[test] fn modeled_two_raw_obligations_reconstruct_but_never_qualify() {
        let s=subject();let p=profile();let c=config();let f=bundle(&s,"frequency_error","elapsed-reference-interval-v1",&raw_frequency());
        let i=bundle(&s,"capture_uncertainty","native-nts-total-initial-v1",&raw_initial(&c));
        let refs=serde_json::json!({"frequency_error":f.refs,"capture_uncertainty":i.refs});
        let result=verify(&s,&refs,&p,&c,f.records(),i.records()).unwrap();
        assert_eq!(result.frequency(),(10_000_000_000,10_000_000_000,10_000_000_000));
        assert!(result.initial().1>result.initial().0);assert_eq!(result.qualification(),Err(Error::MissingQualification));
    }
    #[test] fn modeled_frequency_reconstructs_both_endpoints_and_refuses_short_or_inconsistent_records() {
        let s=subject();let p=profile();assert!(frequency(&raw_frequency(),&s,&p).is_ok());
        for fault in 0..5 {
            let mut r=raw_frequency();match fault {0=>r["active_end_ns"]=10_001_000_002u64.into(),
                1=>r["reference_end"]["upper_ns"]=12_000_000_000u64.into(),
                2=>r["reference_end"]["lower_ns"]=0.into(),3=>r["active_end_ns"]=0.into(),
                _=>r["reference_start"]["upper_ns"]=2_000_000_000u64.into()};
            assert!(frequency(&r,&s,&p).is_err());
        }
    }
    #[test] fn modeled_method_context_digest_and_report_substitution_refuse() {
        let s=subject();let f=bundle(&s,"frequency_error","elapsed-reference-interval-v1",&raw_frequency());
        assert!(objects(&s,&f.refs,"frequency_error","elapsed-reference-interval-v1",f.records()).is_ok());
        let foreign=serde_json::json!({"different":"MODELED"});
        assert!(objects(&foreign,&f.refs,"frequency_error","elapsed-reference-interval-v1",f.records()).is_err());
        assert!(objects(&s,&f.refs,"frequency_error","different-method",f.records()).is_err());
        for which in 0..4 {
            let mut r=f.records();let wrong=b"{}";match which {0=>r.report=wrong,1=>r.method=wrong,2=>r.raw=wrong,_=>r.environment=wrong};
            assert!(objects(&s,&f.refs,"frequency_error","elapsed-reference-interval-v1",r).is_err());
        }
    }
    #[test] fn modeled_raw_canonical_partial_flag_and_oversize_refuse() {
        let s=subject();let f=bundle(&s,"frequency_error","elapsed-reference-interval-v1",&raw_frequency());
        assert!(objects(&s,&f.refs,"frequency_error","elapsed-reference-interval-v1",RawRecords {raw:&f.raw[..f.raw.len()-1],..f.records()}).is_err());
        let huge=vec![b' ';64*1024+1];assert!(objects(&s,&f.refs,"frequency_error","elapsed-reference-interval-v1",RawRecords {raw:&huge,..f.records()}).is_err());
        for field in ["PASS","UCB","confidence"] {let mut r=raw_frequency();r[field]=true.into();assert!(frequency(&r,&s,&profile()).is_err());}
        let spaced=[b" ".as_slice(),f.raw.as_slice()].concat();assert!(canonical_value(&spaced).is_err());
    }
    #[test] fn modeled_initial_refuses_foreign_duplicate_partial_and_changed_abi_inputs() {
        let s=subject();let p=profile();let c=config();assert!(initial(&raw_initial(&c),&s,&p,&c).is_ok());
        for fault in 0..6 {
            let mut r=raw_initial(&c);match fault {0=>r["samples"][0]["provider"]["hostname"]="foreign.invalid".into(),
                1=>r["samples"][1]=r["samples"][0].clone(),2=>{r["samples"].as_array_mut().unwrap().pop();},
                3=>r["samples"][0]["arithmetic"]["after"]["pre"]["boot_id_hex"]=format!("{:032x}",8).into(),
                4=>r["samples"][0]["arithmetic"]["after"].as_object_mut().unwrap().clear(),
                _=>r["elapsed_abi"]="foreign".into()};
            assert!(initial(&r,&s,&p,&c).is_err());
        }
    }
    #[test] fn modeled_total_250_includes_rounding_age_drift_and_capture_gap() {
        let mut p=profile();p.max_source_uncertainty_ms=248;
        let i=IntervalView {lower_posix_ns:1_800_000_000_000_000_000-248_000_000,
            upper_posix_ns:1_800_000_000_000_000_000+248_000_000,active_ns:1_000_000_000,
            inclusive_ns:1_000_000_000,boot_id:7,round_trip_ns:1,uncertainty_ns:248_000_000};
        let exact=roll(i,(1_010_000_000,1_010_000_000,7),&p).unwrap();
        assert_eq!((exact.1-exact.0).div_ceil(2),250);assert!(initial_interval(&p,exact.0,exact.1).is_ok());
        let wider=roll(i,(1_010_000_000,1_010_000_001,7),&p).unwrap();
        assert_eq!((wider.1-wider.0).div_ceil(2),251);assert!(initial_interval(&p,wider.0,wider.1).is_err());
    }
    #[test] fn modeled_initial_roll_overflow_boot_age_and_regression_refuse() {
        let p=profile();let i=IntervalView {lower_posix_ns:1_800_000_000_000_000_000,
            upper_posix_ns:1_800_000_000_002_000_000,active_ns:1_000_000_000,
            inclusive_ns:2_000_000_000,boot_id:7,round_trip_ns:1,uncertainty_ns:1_000_000};
        for at in [(1_001_000_000,2_001_000_000,8),(999_999_999,2_001_000_000,7),
            (1_001_000_000,1_999_999_999,7),(20_000_000_000,21_000_000_000,7),
            (1_001_000_000,2_100_000_000,7)] {assert!(roll(i,at,&p).is_err());}
        let mut overflow=i;overflow.upper_posix_ns=u64::MAX;assert!(roll(overflow,(1_001_000_000,2_001_000_000,7),&p).is_err());
    }
    #[test] fn modeled_closed_nf_hull_matches_endpoints_and_refuses_disagreement() {
        assert_eq!(hull(&[(100,200),(150,250),(175,225)],1),Ok((150,225)));
        assert_eq!(hull(&[(100,150),(150,200),(300,400)],1),Ok((150,150)));
        assert!(hull(&[(100,150),(200,250),(300,350)],1).is_err());
        assert!(hull(&[],1).is_err());assert!(hull(&[(2,1)],0).is_err());
    }
}
