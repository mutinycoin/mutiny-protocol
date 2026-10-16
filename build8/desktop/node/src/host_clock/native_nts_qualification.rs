//! Local evidence-envelope codec, NOT a physical qualification issuer.
//! New engineering encoding of the adopted installation contract. The eight
//! documentary obligations come from CLOCK-PROFILE-V1 section 7. Identified
//! reports/methods/raw data must still be independently verified; no hash, admin
//! number, Boolean or canonical JSON grants a qualified clock capability.
use super::native_nts_deployment_record::{canonical_value, DecodedRecord, Error};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};

type Result<T> = std::result::Result<T,Error>;
fn six_views(values:&[Vec<u8>])->Result<[&[u8];6]> {
    if values.len()!=6{return Err(Error::QualificationEncoding);}
    Ok([&values[0],&values[1],&values[2],&values[3],&values[4],&values[5]])
}
const FORMAT:&str="build8/native-nts/qualification-evidence-v1";
const FORMAT_V2:&str="build8/native-nts/qualification-evidence-v2";
pub(super) const OBLIGATIONS:[&str;8]=["frequency_error","capture_uncertainty","source_precision",
    "suspend_boot_virtualization","source_authentication","external_time_loss",
    "leap_behavior","storage_owner_lock"];

/// Structure/provenance match only. Fields are private; not a startup receipt.
pub(super) struct DecodedEvidence { current: CurrentContract,subject:Value,measurements:Value }
impl DecodedEvidence {
    pub(super) fn verify_installed_methods(&self,record:&DecodedRecord,
        owner:&mut super::installation_directory::InstallationDirectory)
        ->Result<super::native_nts_measurement_verifier::VerifiedExperiments> {
        let selected=super::native_nts_measurement_verifier::SelectedMethods::from_installed(owner,record)
            .map_err(|_|Error::QualificationProvenance)?;
        let finding=self.verify_selected_methods(record,owner,&selected)?;
        finding.normal_qualification().map_err(|_|Error::MissingQualification)?;
        owner.recheck().map_err(|_|Error::QualificationProvenance)?;Ok(finding)
    }
    /// Exact held installation composition for the six finite experiment
    /// reducers. This returns opaque software findings; ModeledTest cannot
    /// become a normal clock capability. Current platform/loaded-code checks
    /// and accepted policy/issuer construction remain the deployment's gates.
    pub(super) fn verify_selected_methods(&self,record:&DecodedRecord,
        owner:&mut super::installation_directory::InstallationDirectory,
        selection:&super::native_nts_measurement_verifier::SelectedMethods)
        ->Result<super::native_nts_measurement_verifier::VerifiedExperiments> {
        use super::native_nts_measurement_verifier as verifier;
        let lift=|_:verifier::Error|Error::QualificationProvenance;
        if measurement_subject(record)?!=self.subject {return Err(Error::QualificationScope);}
        let subject=serde_json::to_vec(&super::native_nts_deployment_record::canonical_tree(&self.subject)?)
            .map_err(|_|Error::QualificationEncoding)?;
        if verifier::hash(&subject)!=verifier::subject_pin(selection){return Err(Error::QualificationScope);}
        owner.recheck().map_err(|_|Error::QualificationProvenance)?;
        let necessary=self.verify_retained_subset(record,owner)?;
        let top=self.artifact_pins()?;
        let mut indices=Vec::with_capacity(6);
        for (index,name)in OBLIGATIONS[2..].iter().enumerate() {
            let refs=&self.measurements[*name];
            let get=|key:&str|->Result<&[u8]> {owner.artifact(&digest(&refs[key])?).map_err(|_|Error::QualificationProvenance)};
            verifier::group_bindings(selection,index,&self.subject,refs,
                super::native_nts_raw_measurements::RawRecords{report:get("report_sha256")?,method:get("method_sha256")?,
                    raw:get("raw_data_sha256")?,environment:get("environment_sha256")?}).map_err(lift)?;
            let pin=digest(&refs["raw_data_sha256"])?;
            let raw=owner.artifact(&pin).map_err(|_|Error::QualificationProvenance)?;
            if raw.is_empty() || raw.len()>64*1024{return Err(Error::Bound);}indices.push(raw.to_vec());
        }
        let plan=verifier::family_index_plan(selection,six_views(&indices)?,&top).map_err(lift)?;
        owner.extend_retained(&plan).map_err(|_|Error::QualificationProvenance)?;
        let retained=verifier::RetainedArtifacts::collect_from_installation(owner,&plan).map_err(lift)?;
        let plan=verifier::family_records_plan(selection,six_views(&indices)?,&top,&retained).map_err(lift)?;
        owner.extend_retained(&plan).map_err(|_|Error::QualificationProvenance)?;
        let retained=verifier::RetainedArtifacts::collect_from_installation(owner,&plan).map_err(lift)?;
        let plan=verifier::family_support_plan(selection,six_views(&indices)?,&top,&retained).map_err(lift)?;
        owner.extend_retained(&plan).map_err(|_|Error::QualificationProvenance)?;
        let retained=verifier::RetainedArtifacts::collect_from_installation(owner,&plan).map_err(lift)?;
        let frequency=owner.artifact(&verifier::frequency_pin(selection)).map_err(|_|Error::QualificationProvenance)?;
        let finding=verifier::verify_selected(selection,six_views(&indices)?,&retained,frequency,&necessary).map_err(lift)?;
        owner.recheck().map_err(|_|Error::QualificationProvenance)?;Ok(finding)
    }
    pub(super) fn current_contract(&self)->&CurrentContract {&self.current}
    pub(super) fn artifact_pins(&self)->Result<Vec<[u8;32]>> {
        let groups=exact(&self.measurements,&OBLIGATIONS)?;let mut pins=Vec::with_capacity(32);
        for name in OBLIGATIONS {
            let refs=exact(&groups[name],&["report_sha256","method_sha256","raw_data_sha256","environment_sha256"])?;
            for key in ["report_sha256","method_sha256","raw_data_sha256","environment_sha256"] {
                pins.push(digest(&refs[key])?);
            }
        }
        Ok(pins)
    }
    pub(super) fn verify_retained_subset(&self,record:&DecodedRecord,
        owner:&super::installation_directory::InstallationDirectory)
        ->Result<super::native_nts_raw_measurements::NecessaryReport> {
        let records=|obligation:&str|->Result<super::native_nts_raw_measurements::RawRecords<'_>> {
            let refs=exact(&self.measurements[obligation],&["report_sha256","method_sha256","raw_data_sha256","environment_sha256"])?;
            let get=|key:&str|->Result<&[u8]> {
                owner.artifact(&digest(&refs[key])?).map_err(|_|Error::QualificationProvenance)
            };
            Ok(super::native_nts_raw_measurements::RawRecords {report:get("report_sha256")?,
                method:get("method_sha256")?,raw:get("raw_data_sha256")?,environment:get("environment_sha256")?})
        };
        self.verify_raw_subset(record,records("frequency_error")?,records("capture_uncertainty")?)
    }
    pub(super) fn verify_raw_subset(&self,record:&DecodedRecord,
        frequency:super::native_nts_raw_measurements::RawRecords<'_>,
        initial:super::native_nts_raw_measurements::RawRecords<'_>)
        ->Result<super::native_nts_raw_measurements::NecessaryReport> {
        if measurement_subject(record)?!=self.subject {return Err(Error::QualificationScope);}
        super::native_nts_raw_measurements::verify(&self.subject,&self.measurements,
            record.profile(),record.acquisition(),frequency,initial)
    }
    /// Resolve EVERY obligatory report from the same already-held installation.
    /// The result identifies exact method inputs and reconstructs the two
    /// implemented arithmetic methods. It grants no accepted-method or physical
    /// qualification. Missing algorithms/authentication remain software gaps.
    pub(super) fn resolve_measurement_inputs(&self,record:&DecodedRecord,
        owner:&super::installation_directory::InstallationDirectory)
        ->Result<super::native_nts_raw_measurements::MeasurementInputs> {
        if measurement_subject(record)?!=self.subject {return Err(Error::QualificationScope);}
        let records=|obligation:&str|->Result<super::native_nts_raw_measurements::RawRecords<'_>> {
            let refs=exact(&self.measurements[obligation],&["report_sha256","method_sha256","raw_data_sha256","environment_sha256"])?;
            let get=|key:&str|->Result<&[u8]> {
                owner.artifact(&digest(&refs[key])?).map_err(|_|Error::QualificationProvenance)
            };
            Ok(super::native_nts_raw_measurements::RawRecords {report:get("report_sha256")?,
                method:get("method_sha256")?,raw:get("raw_data_sha256")?,environment:get("environment_sha256")?})
        };
        super::native_nts_raw_measurements::resolve_inputs(&self.subject,&self.measurements,
            record.profile(),record.acquisition(),[
                records(OBLIGATIONS[0])?,records(OBLIGATIONS[1])?,records(OBLIGATIONS[2])?,records(OBLIGATIONS[3])?,
                records(OBLIGATIONS[4])?,records(OBLIGATIONS[5])?,records(OBLIGATIONS[6])?,records(OBLIGATIONS[7])?])
    }
    pub(super) fn verify_measurements(&self)->Result<()> {
        // Missing SOFTWARE mechanism, separately from absent measured inputs:
        // Raw documentary objects and necessary arithmetic now have a normal
        // held-owner resolver; accepted confidence methodology/margin and
        // experiment/physical/raw authentication verification remain absent.
        // Canonical references cannot substitute for any of those operations.
        Err(Error::MissingQualification)
    }
}
/// No evidence self-reference: the full existing envelope scope binds all other
/// deployment bytes. Method/raw subjects bind the exact immutable experimental
/// profile/acquisition/hardware/code inputs without report->scope hash cycles.
pub(super) fn measurement_subject(record:&DecodedRecord)->Result<Value> {
    let v=canonical_value(record.canonical())?;
    super::native_nts_deployment_record::canonical_tree(&serde_json::json!({
        "binding":v["binding"],"profile":v["profile"],"profile_id":v["profile_id"],
        "acquisition":v["acquisition"],"code_sha256":v["context"]["code_sha256"],
        "os_build_sha256":v["context"]["os_build_sha256"],
        "elapsed_abi_sha256":v["context"]["elapsed_abi_sha256"],"boot_abi_sha256":v["context"]["boot_abi_sha256"]}))
}

/// Accepted-data candidate for comparison with independent native observations.
/// No public constructor and no conversion into CurrentNativeInputs.
#[derive(Clone)]
pub(super) struct CurrentContract {
    target: String, build:u32, firmware:u32, flags:u64,
    elapsed:String, boot:String,
    linux_os:Option<Value>,
}
impl CurrentContract {
    pub(super) fn is_linux(&self)->bool {self.linux_os.is_some()}
    pub(super) fn compare_linux(&self,observed:&Value)->Result<()> {
        if self.target!="linux-x86_64" || self.linux_os.as_ref()!=Some(observed)
            || self.elapsed!="clock_gettime:CLOCK_MONOTONIC/CLOCK_BOOTTIME/CLOCK_MONOTONIC:ns:v1"
            || self.boot!="procfs:/proc/sys/kernel/random/boot_id:uuid:v1" {
            return Err(Error::UnsupportedCurrentFacts);
        }
        Ok(())
    }
    pub(super) fn compare_windows_diagnostic(&self,
        observed:&super::windows_boot::BootEnvironment)->Result<()> {
        // Exact CURRENT implementation, not a generic Windows ABI guarantee.
        // Class90 remains diagnostic and unqualified even when this matches.
        if self.target!="windows-x86_64" || observed.identifier_bytes==[0;16]
            || self.build!=observed.os_build
            || self.firmware!=observed.firmware_type || self.flags!=observed.boot_flags
            || self.elapsed!="QueryUnbiasedInterruptTimePrecise/QueryInterruptTimePrecise:100ns:v1"
            || self.boot!="NtQuerySystemInformation:90:32:v1" {
            return Err(Error::UnsupportedCurrentFacts);
        }
        Ok(())
    }
}
fn hash(value:&Value)->Result<[u8;32]> {
    let value=super::native_nts_deployment_record::canonical_tree(value)?;
    Ok(Sha256::digest(serde_json::to_vec(&value).map_err(|_|Error::QualificationEncoding)?).into())
}
fn exact<'a>(value:&'a Value,keys:&[&str])->Result<&'a Map<String,Value>> {
    let map=value.as_object().ok_or(Error::QualificationEncoding)?;
    if map.len()!=keys.len() || map.keys().any(|key|!keys.contains(&key.as_str())) {
        return Err(Error::QualificationEncoding);
    }
    Ok(map)
}
fn digest(value:&Value)->Result<[u8;32]> {
    let text=value.as_str().ok_or(Error::QualificationEncoding)?;
    if text.len()!=64 || !text.bytes().all(|c|c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return Err(Error::QualificationEncoding);
    }
    let mut result=[0;32];
    hex::decode_to_slice(text,&mut result).map_err(|_|Error::QualificationEncoding)?;
    if result==[0;32] {return Err(Error::QualificationProvenance);}
    Ok(result)
}
fn provenance(value:&Value)->Result<()> {
    let map=exact(value,&["report_sha256","method_sha256","raw_data_sha256","environment_sha256"])?;
    for key in map.keys() {digest(&map[key])?;}
    Ok(())
}

/// Exact local scope projection. Remove ONLY the two evidence self-reference
/// digests, avoiding deployment<->evidence hash cycles. All other deployment
/// bytes, including source/config/code/measurement, protocol and predecessor,
/// plus exact selected anchor/cadence remain bound. No consensus domain changes.
fn scope(record:&DecodedRecord,anchor:&Path,cadence:Duration)->Result<Value> {
    let mut deployment=canonical_value(record.canonical())?;
    let context=deployment["context"].as_object_mut().ok_or(Error::QualificationEncoding)?;
    context.remove("qualification_sha256").ok_or(Error::QualificationEncoding)?;
    context.remove("qualification_scope_sha256").ok_or(Error::QualificationEncoding)?;
    let path=anchor.to_str().ok_or(Error::QualificationScope)?;
    if !anchor.is_absolute() || anchor.components().any(|part|matches!(part,
        std::path::Component::CurDir|std::path::Component::ParentDir))
        || super::native_nts_service::validate_cadence(cadence).is_err() {
        return Err(Error::QualificationScope);
    }
    // Serialization passes through the SAME bounded canonical tree, including
    // lexical key insertion under preserve_order. No ambient map ordering.
    let value=serde_json::json!({"deployment":deployment,"anchor":path,
        "cadence_seconds":cadence.as_secs()});
    super::native_nts_deployment_record::canonical_tree(&value)
}
fn contract(value:&Value,context:&Value,format:&str)->Result<CurrentContract> {
    let facts=exact(value,&["os","elapsed_abi","boot_abi"])?;
    let target=facts["os"]["target"].as_str().ok_or(Error::QualificationEncoding)?;
    if target=="linux-x86_64" {
        // A NEW local v2 grammar; never reinterpret old v1 numeric Windows-shaped
        // fields as an observed Linux OS/kernel receipt.
        if format!=FORMAT_V2 {return Err(Error::UnsupportedCurrentFacts);}
        let os=exact(&facts["os"],&["target","sysname","release","version","machine"])?;
        for name in ["target","sysname","release","version","machine"] {
            if os[name].as_str().is_none_or(|s|s.is_empty()) {return Err(Error::QualificationEncoding);}
        }
        if os["sysname"].as_str()!=Some("Linux") || os["machine"].as_str()!=Some("x86_64") {return Err(Error::UnsupportedCurrentFacts);}
        let elapsed=exact(&facts["elapsed_abi"],&["implementation"])?;
        let boot=exact(&facts["boot_abi"],&["implementation"])?;
        let elapsed=elapsed["implementation"].as_str().ok_or(Error::QualificationEncoding)?;
        let boot=boot["implementation"].as_str().ok_or(Error::QualificationEncoding)?;
        for (field,part) in [("os_build_sha256","os"),("elapsed_abi_sha256","elapsed_abi"),("boot_abi_sha256","boot_abi")] {
            if hash(&facts[part])?!=digest(&context[field])? {return Err(Error::QualificationScope);}
        }
        let result=CurrentContract {target:target.into(),build:0,firmware:0,flags:0,
            elapsed:elapsed.into(),boot:boot.into(),linux_os:Some(facts["os"].clone())};
        result.compare_linux(&facts["os"])?;return Ok(result);
    }
    let os=exact(&facts["os"],&["target","major","minor","build"])?;
    let target=os["target"].as_str().ok_or(Error::QualificationEncoding)?;
    if !["windows-x86_64","linux-x86_64"].contains(&target) {
        return Err(Error::UnsupportedCurrentFacts);
    }
    let number=|v:&Value|->Result<u32> {
        u32::try_from(v.as_u64().ok_or(Error::QualificationEncoding)?)
            .map_err(|_|Error::QualificationEncoding)
    };
    let major=number(&os["major"])?;let minor=number(&os["minor"])?;
    let build=number(&os["build"])?;
    let elapsed=exact(&facts["elapsed_abi"],&["implementation"])?;
    let boot=exact(&facts["boot_abi"],&["implementation","firmware_type","boot_flags"])?;
    let text=|v:&Value|->Result<String> {
        let s=v.as_str().ok_or(Error::QualificationEncoding)?;
        if s.is_empty() {return Err(Error::QualificationEncoding);} Ok(s.to_owned())
    };
    let elapsed=text(&elapsed["implementation"])?;
    let boot_name=text(&boot["implementation"])?;
    let firmware=number(&boot["firmware_type"])?;
    let flags=boot["boot_flags"].as_u64().ok_or(Error::QualificationEncoding)?;
    for (field,part) in [("os_build_sha256","os"),("elapsed_abi_sha256","elapsed_abi"),
        ("boot_abi_sha256","boot_abi")] {
        if hash(&facts[part])?!=digest(&context[field])? {return Err(Error::QualificationScope);}
    }
    // This branch retains the earlier version-pinned Windows diagnostic ABI.
    // Linux has its separate exact v2 grammar above, never this numeric shape.
    if target=="windows-x86_64" && (major!=10 || minor!=0 || build!=26200) {
        return Err(Error::UnsupportedCurrentFacts);
    }
    Ok(CurrentContract {target:target.to_owned(),build,firmware,flags,elapsed,boot:boot_name,linux_os:None})
}

pub(super) fn decode_and_bind(bytes:&[u8],record:&DecodedRecord,anchor:&Path,
    cadence:Duration)->Result<DecodedEvidence> {
    let value=canonical_value(bytes)?;
    let root=exact(&value,&["format","scope","measurements","provider_records","current_facts"])?;
    let format=root["format"].as_str().ok_or(Error::QualificationEncoding)?;
    if ![FORMAT,FORMAT_V2].contains(&format) {return Err(Error::QualificationEncoding);}
    let deployment=canonical_value(record.canonical())?;
    let context=&deployment["context"];
    let expected=scope(record,anchor,cadence)?;
    if root["scope"]!=expected || hash(&root["scope"])?!=digest(&context["qualification_scope_sha256"])?
        || <[u8;32]>::from(Sha256::digest(bytes))!=digest(&context["qualification_sha256"])? {
        return Err(Error::QualificationScope);
    }
    let measurements=exact(&root["measurements"],&OBLIGATIONS)?;
    for obligation in OBLIGATIONS {provenance(&measurements[obligation])?;}
    if hash(&root["measurements"])?!=digest(&context["measurement_sha256"])? {
        return Err(Error::QualificationProvenance);
    }
    let records=root["provider_records"].as_array().ok_or(Error::QualificationEncoding)?;
    let providers=deployment["acquisition"]["providers"].as_array().ok_or(Error::QualificationEncoding)?;
    if records.len()!=providers.len() {return Err(Error::QualificationProvenance);}
    for (record,provider) in records.iter().zip(providers) {
        let record=exact(record,&["provider","record"])?;
        if &record["provider"]!=provider {return Err(Error::QualificationScope);}
        provenance(&record["record"])?;
    }
    let current=contract(&root["current_facts"],context,format)?;
    Ok(DecodedEvidence {current,subject:measurement_subject(record)?,measurements:root["measurements"].clone()})
}

#[cfg(test)]
pub(super) fn modeled_envelope(deployment:&mut Value,anchor:&Path,cadence:Duration)->Vec<u8> {
    // Synthetic documentary references only: never a measurement verifier.
    let reference=serde_json::json!({"report_sha256":"11".repeat(32),
        "method_sha256":"22".repeat(32),"raw_data_sha256":"33".repeat(32),
        "environment_sha256":"44".repeat(32)});
    let mut measurements=Map::new();
    for key in OBLIGATIONS {measurements.insert(key.into(),reference.clone());}
    let measurements=Value::Object(measurements);
    let facts=serde_json::json!({"os":{"target":"windows-x86_64","major":10,"minor":0,"build":26200},
        "elapsed_abi":{"implementation":"QueryUnbiasedInterruptTimePrecise/QueryInterruptTimePrecise:100ns:v1"},
        "boot_abi":{"implementation":"NtQuerySystemInformation:90:32:v1","firmware_type":2,"boot_flags":0}});
    deployment["context"]["measurement_sha256"]=hex::encode(hash(&measurements).unwrap()).into();
    for (name,part) in [("os_build_sha256","os"),("elapsed_abi_sha256","elapsed_abi"),("boot_abi_sha256","boot_abi")] {
        deployment["context"][name]=hex::encode(hash(&facts[part]).unwrap()).into();
    }
    let canonical=super::native_nts_deployment_record::canonical_tree(deployment).unwrap();
    let decoded=super::native_nts_deployment_record::decode(&serde_json::to_vec(&canonical).unwrap()).unwrap();
    let projected=scope(&decoded,anchor,cadence).unwrap();
    deployment["context"]["qualification_scope_sha256"]=hex::encode(hash(&projected).unwrap()).into();
    let providers=deployment["acquisition"]["providers"].as_array().unwrap().iter()
        .map(|p|serde_json::json!({"provider":p,"record":reference})).collect::<Vec<_>>();
    let value=serde_json::json!({"format":FORMAT,"scope":projected,"measurements":measurements,
        "provider_records":providers,"current_facts":facts});
    let raw=serde_json::to_vec(&super::native_nts_deployment_record::canonical_tree(&value).unwrap()).unwrap();
    deployment["context"]["qualification_sha256"]=hex::encode(Sha256::digest(&raw)).into();
    raw
}
#[cfg(test)]
mod linux_contract_tests {
    use super::*;
    fn model()->(Value,Value) {
        let facts=serde_json::json!({"os":{"target":"linux-x86_64","sysname":"Linux",
            "release":"MODELED-KERNEL-NOT-OBSERVED","version":"MODELED-BUILD-NOT-OBSERVED","machine":"x86_64"},
            "elapsed_abi":{"implementation":"clock_gettime:CLOCK_MONOTONIC/CLOCK_BOOTTIME/CLOCK_MONOTONIC:ns:v1"},
            "boot_abi":{"implementation":"procfs:/proc/sys/kernel/random/boot_id:uuid:v1"}});
        let mut context=Map::new();
        for (key,part) in [("os_build_sha256","os"),("elapsed_abi_sha256","elapsed_abi"),("boot_abi_sha256","boot_abi")] {
            context.insert(key.into(),hex::encode(hash(&facts[part]).unwrap()).into());
        }
        (facts,Value::Object(context))
    }
    #[test] fn modeled_linux_contract_requires_v2_exact_os_and_abi_without_qualification() {
        let (facts,context)=model();let parsed=contract(&facts,&context,FORMAT_V2).unwrap();
        assert!(parsed.is_linux());assert_eq!(parsed.compare_linux(&facts["os"]),Ok(()));
        assert!(matches!(contract(&facts,&context,FORMAT),Err(Error::UnsupportedCurrentFacts)));
        let mut changed=facts["os"].clone();changed["release"]="foreign".into();
        assert_eq!(parsed.compare_linux(&changed),Err(Error::UnsupportedCurrentFacts));
        let envelope=DecodedEvidence{current:parsed,subject:Value::Null,measurements:Value::Null};
        assert_eq!(envelope.verify_measurements(),Err(Error::MissingQualification));
    }
    #[test] fn modeled_linux_contract_rejects_foreign_hashes_unknown_fields_and_impls() {
        let (facts,context)=model();
        for fault in 0..3 {
            let mut changed=facts.clone();match fault {0=>changed["os"]["version"]="foreign".into(),
                1=>changed["os"]["unknown"]=1.into(),_=>changed["elapsed_abi"]["implementation"]="foreign".into()};
            assert!(contract(&changed,&context,FORMAT_V2).is_err());
        }
        let mut foreign=facts.clone();foreign["elapsed_abi"]["implementation"]="foreign".into();
        let mut matched=context.clone();matched["elapsed_abi_sha256"]=hex::encode(hash(&foreign["elapsed_abi"]).unwrap()).into();
        assert!(matches!(contract(&foreign,&matched,FORMAT_V2),Err(Error::UnsupportedCurrentFacts)));
    }
}
