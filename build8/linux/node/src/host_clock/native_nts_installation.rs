//! Local administrator-installed selection. These are public configuration
//! bytes, not consensus authority or physical qualification. Reading them must
//! retain the independently protected installation owner for the service's
//! lifetime. Structural decoding alone never constructs InstalledNativeInputs.
use super::native_nts_deployment_record::{decode, DecodedRecord};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{path::PathBuf, time::Duration};

const FORMAT: &str = "build8/native-nts/installation-v1";
const OWNER_FORMAT:&str="build8/native-nts/installation-v2";
const MEASUREMENT_FORMAT:&str="build8/native-nts/installation-v3";
const MAX: usize = 64 * 1024;
type Result<T> = std::result::Result<T, &'static str>;

pub(super) struct InstallationDescriptor {
    pub(super) record: DecodedRecord,
    pub(super) qualification: [u8; 32],
    pub(super) genesis_artifact: [u8; 32],
    pub(super) genesis_block: [u8; 32],
    pub(super) anchor: PathBuf,
    pub(super) cadence: Duration,
    pub(super) protected_owner:Option<OwnerPlacementDocument>,
    pub(super) measurement_selection:Option<MeasurementSelectionDocument>,
}
/// Exact public administrator selection only. This cannot authenticate a
/// measurement, mint AcceptedPhysical, or issue normal clock authority.
pub(super) struct MeasurementSelectionDocument {
    selection:[u8;32],issuer_artifacts:Vec<[u8;32]>,
}
impl MeasurementSelectionDocument {
    pub(super) fn selection(&self)->[u8;32] {self.selection}
    pub(super) fn issuer_artifacts(&self)->&[[u8;32]] {&self.issuer_artifacts}
}
/// Documentary only until moved through the genuine held installation,
/// qualification and current-code pipeline. No public/raw authority constructor.
#[derive(Clone,PartialEq,Eq)]
pub(super) struct OwnerPlacementDocument {
    state:PathBuf,endpoint:PathBuf,lineage:[u8;32],principals:OwnerPrincipals,
}
#[derive(Clone,PartialEq,Eq)]
enum OwnerPrincipals {
    Linux {owner_uid:u32,node_uid:u32,owner_gid:u32,node_gid:u32,ipc_gid:u32},
    #[cfg(windows)]
    Windows {owner_sid:String,node_sid:String,async_message:bool},
}
impl OwnerPlacementDocument {
    pub(super) fn lineage(&self)->[u8;32] {self.lineage}
    pub(super) fn endpoint(&self)->&std::path::Path {&self.endpoint}
    #[cfg(windows)]
    pub(super) fn windows_principals(&self)->Result<(&str,&str)> {
        match &self.principals {OwnerPrincipals::Windows{owner_sid,node_sid,..}=>Ok((owner_sid,node_sid)),
            _=>Err("selected owner platform differs from Windows")}
    }
    #[cfg(windows)]
    pub(super) fn windows_async_message(&self)->bool {
        matches!(&self.principals,OwnerPrincipals::Windows{async_message:true,..})
    }
    #[cfg(target_os="linux")]
    pub(super) fn channel_principals(&self)->(u32,u32,u32,u32) {
        let OwnerPrincipals::Linux{owner_uid,node_uid,owner_gid,node_gid,..}=&self.principals;
        (*owner_uid,*node_uid,*owner_gid,*node_gid)
    }
    #[cfg(target_os="linux")]
    pub(super) fn channel_group(&self)->u32 {
        let OwnerPrincipals::Linux{ipc_gid,..}=&self.principals;*ipc_gid
    }
    /// Existing-only; this never prepares accounts/state or impersonates the
    /// selected owner. The normal issuer must retain its installation guard.
    pub(super) fn open_lineage(&self)->std::result::Result<super::protected_clock_owner::NativeLineage,String> {
        match &self.principals {
            #[cfg(windows)]
            OwnerPrincipals::Windows{owner_sid,node_sid,..}=>
                super::state_dir::WindowsProtectedHead::open_existing(&self.state,owner_sid,node_sid)
                    .map(super::protected_clock_owner::NativeLineage::Windows).map_err(|e|e.to_string()),
            #[cfg(target_os="linux")]
            OwnerPrincipals::Linux{owner_uid,node_uid,owner_gid,..}=>{
                if unsafe{libc::getgid()}!=*owner_gid || unsafe{libc::getegid()}!=*owner_gid {
                    return Err("selected dedicated owner primary group differs".into());
                }
                super::protected_clock_linux_io::LinuxLineageIo::open_existing(&self.state,*owner_uid,*node_uid)
                    .map(super::protected_clock_owner::NativeLineage::Linux)
            },
            _=>Err("selected protected owner platform differs".into()),
        }
    }
}

/// Owns all three exact bounded public objects in their original held
/// installation. Encoding/custody alone is not a qualification capability.
/// No raw-byte constructor, Clone, caller root or optional ordinary owner.
pub(super) struct InstalledSelection {
    descriptor: InstallationDescriptor,
    owner: super::installation_directory::InstallationDirectory,
}
impl InstalledSelection {
    pub(super) fn read() -> std::result::Result<Self,String> {
        let mut owner=super::installation_directory::InstallationDirectory::open()?;
        let (raw,deployment,qualification)=owner.objects();
        let descriptor=decode_descriptor(raw,deployment,qualification).map_err(str::to_owned)?;
        owner.recheck()?;
        Ok(Self {descriptor,owner})
    }
    pub(super) fn descriptor(&self)->&InstallationDescriptor { &self.descriptor }
    pub(super) fn exact_objects(&self)->(&[u8],&[u8],&[u8]) { self.owner.objects() }
    pub(super) fn require_requested_record(&self,requested:&[u8])->Result<()> {
        if requested.is_empty() || requested.len()>MAX {
            return Err("installation requested deployment bound");
        }
        if requested!=self.exact_objects().1
            || requested!=self.descriptor.record.canonical() {
            return Err("installation requested deployment differs from exact held selection");
        }
        Ok(())
    }
    pub(super) fn recheck(&mut self)->std::result::Result<(),String> { self.owner.recheck() }
    /// Normal qualification is issued only by the complete verifier over this
    /// same held installation, its exact descriptor and accepted public pins.
    /// Always close the currentness bracket, including a refused verification.
    pub(super) fn verify_installed_methods(&mut self,
        evidence:&super::native_nts_qualification::DecodedEvidence)
        ->std::result::Result<super::native_nts_measurement_verifier::VerifiedExperiments,
            super::native_nts_deployment_record::Error> {
        use super::native_nts_deployment_record::Error;
        self.owner.recheck().map_err(|_|Error::Installation)?;
        let outcome=(|| {
            self.owner.retain_artifacts(&evidence.artifact_pins()?).map_err(|_|Error::Installation)?;
            evidence.verify_installed_methods(&self.descriptor.record,&mut self.owner)
        })();
        self.owner.recheck().map_err(|_|Error::Installation)?;
        outcome
    }
    pub(super) fn verify_documentary_subset(&mut self,
        evidence:&super::native_nts_qualification::DecodedEvidence)
        ->std::result::Result<super::native_nts_raw_measurements::NecessaryReport,
            super::native_nts_deployment_record::Error> {
        use super::native_nts_deployment_record::Error;
        let outcome=(|| {
            self.owner.retain_artifacts(&evidence.artifact_pins()?).map_err(|_|Error::Installation)?;
            evidence.verify_retained_subset(&self.descriptor.record,&self.owner)
        })();
        // Always attempt the held/named/content/selection closure even if
        // arithmetic refuses; success cannot outlive a stale owner check.
        self.owner.recheck().map_err(|_|Error::Installation)?;
        outcome
    }
    pub(super) fn into_parts(self)->(InstallationDescriptor,
        super::installation_directory::InstallationDirectory) {
        (self.descriptor,self.owner)
    }
}
fn hash(bytes: &[u8]) -> [u8; 32] { Sha256::digest(bytes).into() }
fn digest(value: &Value) -> Result<[u8; 32]> {
    let text=value.as_str().ok_or("installation digest type")?;
    if text.len()!=64 || !text.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return Err("installation digest encoding");
    }
    let mut out=[0;32];hex::decode_to_slice(text,&mut out).map_err(|_|"installation digest encoding")?;
    if out==[0;32] { return Err("installation zero digest"); }
    Ok(out)
}
fn canonical(value:&Value,depth:usize)->Result<Value> {
    if depth>8 {return Err("installation depth");}
    match value {
        Value::Object(map)=>{
            if map.len()>16 {return Err("installation field bound");}
            let mut keys:Vec<_>=map.keys().collect();keys.sort();
            let mut sorted=serde_json::Map::new();
            for key in keys {
                if key.len()>128 {return Err("installation key bound");}
                sorted.insert(key.clone(),canonical(&map[key],depth+1)?);
            }
            Ok(Value::Object(sorted))
        }
        Value::Array(_)=>Err("installation arrays refused"),
        Value::String(s) if s.len()>1024=>Err("installation string bound"),
        Value::Number(n) if !n.is_u64()=>Err("installation integer encoding"),
        _=>Ok(value.clone()),
    }
}
/// Arrays remain forbidden throughout inherited v1/v2 documents. Only the
/// exact v3 measurement field may contain this finite, strictly sorted roster.
fn canonical_descriptor(parsed:&Value)->Result<(Value,Option<MeasurementSelectionDocument>)> {
    if parsed["format"].as_str()!=Some(MEASUREMENT_FORMAT) {
        return Ok((canonical(parsed,0)?,None));
    }
    let map=parsed.as_object().ok_or("installation object")?;
    let field=map.get("measurement_selection").ok_or("installation measurement selection absent")?;
    let selection=field.as_object().ok_or("installation measurement selection object")?;
    if selection.len()!=2 || !selection.contains_key("selection_sha256")
        || !selection.contains_key("accepted_issuer_pins") {
        return Err("installation measurement selection exact schema");
    }
    let selected=digest(&selection["selection_sha256"])?;
    let pins=selection["accepted_issuer_pins"].as_array().ok_or("installation issuer artifact roster")?;
    // Local implementation artifact limit; no committee or quorum semantics.
    if pins.is_empty() || pins.len()>32 {return Err("installation issuer artifact bound");}
    let mut issuer_artifacts=Vec::new();
    issuer_artifacts.try_reserve_exact(pins.len()).map_err(|_|"installation issuer allocation")?;
    for pin in pins {
        let pin=digest(pin)?;
        if issuer_artifacts.last().is_some_and(|previous|*previous>=pin) {
            return Err("installation issuer artifact order/duplicate");
        }
        issuer_artifacts.push(pin);
    }
    let mut without=map.clone();without.remove("measurement_selection");
    let mut canonical=canonical(&Value::Object(without),0)?;
    let mut selected_field=serde_json::Map::new();
    selected_field.insert("accepted_issuer_pins".into(),Value::Array(pins.clone()));
    selected_field.insert("selection_sha256".into(),selection["selection_sha256"].clone());
    canonical.as_object_mut().ok_or("installation object")?
        .insert("measurement_selection".into(),Value::Object(selected_field));
    // Preserve canonical key order even if another crate enables serde_json's
    // preserve_order feature through Cargo feature unification.
    let complete=canonical.as_object().ok_or("installation object")?;
    let mut keys:Vec<_>=complete.keys().collect();keys.sort();
    let mut sorted=serde_json::Map::new();
    for key in keys {sorted.insert(key.clone(),complete[key].clone());}
    Ok((Value::Object(sorted),Some(MeasurementSelectionDocument{selection:selected,issuer_artifacts})))
}
/// Three separately read exact public byte strings. Their digests are checked
/// against the installed descriptor AND the deployment's committed context.
/// A measurement digest does not prove a drift envelope; the qualification
/// verifier remains a separate mandatory gate, not a caller-supplied boolean.
pub(super) fn decode_descriptor(raw:&[u8],deployment:&[u8],qualification:&[u8])
    ->Result<InstallationDescriptor> {
    if raw.is_empty() || raw.len()>MAX || deployment.is_empty() || deployment.len()>MAX
        || qualification.is_empty() || qualification.len()>MAX {
        return Err("installation exact public object bound");
    }
    let parsed:Value=serde_json::from_slice(raw).map_err(|_|"installation JSON")?;
    let (value,measurement_selection)=canonical_descriptor(&parsed)?;
    if serde_json::to_vec(&value).map_err(|_|"installation JSON")?!=raw {
        return Err("installation canonical equality");
    }
    let map=value.as_object().ok_or("installation object")?;
    let v3=value["format"].as_str()==Some(MEASUREMENT_FORMAT);
    let v2=value["format"].as_str()==Some(OWNER_FORMAT) || v3;
    let fields=if v3 {vec!["format","record_sha256","qualification_sha256","genesis_artifact_sha256",
        "genesis_block_sha256","anchor","cadence_seconds","protected_owner","measurement_selection"]}
        else if v2 {vec!["format","record_sha256","qualification_sha256","genesis_artifact_sha256",
        "genesis_block_sha256","anchor","cadence_seconds","protected_owner"]}
        else {vec!["format","record_sha256","qualification_sha256","genesis_artifact_sha256",
        "genesis_block_sha256","anchor","cadence_seconds"]};
    if map.len()!=fields.len() || map.keys().any(|k|!fields.contains(&k.as_str()))
        || (!v2 && value["format"].as_str()!=Some(FORMAT)) {return Err("installation exact schema");}
    if digest(&value["record_sha256"])?!=hash(deployment) {
        return Err("installation substituted deployment");
    }
    let qualification_pin=digest(&value["qualification_sha256"])?;
    if qualification_pin!=hash(qualification) {return Err("installation substituted qualification");}
    let record=decode(deployment).map_err(|_|"installation deployment validation")?;
    let context:Value=serde_json::from_slice(record.canonical()).map_err(|_|"installation deployment JSON")?;
    if digest(&context["context"]["qualification_sha256"])?!=qualification_pin {
        return Err("installation qualification/deployment context");
    }
    let anchor=PathBuf::from(value["anchor"].as_str().ok_or("installation anchor type")?);
    if !anchor.is_absolute() || anchor.file_name().is_none()
        || anchor.components().any(|c|matches!(c,std::path::Component::ParentDir|std::path::Component::CurDir)) {
        return Err("installation absolute anchor");
    }
    let cadence=Duration::from_secs(value["cadence_seconds"].as_u64().ok_or("installation cadence integer")?);
    super::native_nts_service::validate_cadence(cadence).map_err(|_|"installation cadence contract")?;
    let protected_owner=if v2 {Some(decode_owner(&value["protected_owner"],&anchor)?)}else{None};
    Ok(InstallationDescriptor {record,qualification:qualification_pin,
        genesis_artifact:digest(&value["genesis_artifact_sha256"])?,
        genesis_block:digest(&value["genesis_block_sha256"])?,anchor,cadence,protected_owner,measurement_selection})
}
fn absolute(value:&Value)->Result<PathBuf> {
    let text=value.as_str().ok_or("owner path type")?;
    // This new owner document selects Linux only. Preserve literal spelling;
    // Path::components would otherwise normalize internal './' or '//'.
    if !text.starts_with('/') || text.ends_with('/') || text.contains("//") || text.contains('\0')
        || text.split('/').any(|v|matches!(v,"."|"..")) {return Err("owner Linux path spelling");}
    let path=PathBuf::from(text);
    if !path.is_absolute() || path.components().any(|c|matches!(c,std::path::Component::CurDir|std::path::Component::ParentDir))
        || path.file_name().is_none() {return Err("owner absolute canonical path");}Ok(path)
}
fn principal_number(value:&Value)->Result<u32> {
    let number=u32::try_from(value.as_u64().ok_or("owner principal integer")?).map_err(|_|"owner principal bound")?;
    if number==0 || number==u32::MAX {return Err("owner ordinary principal required");}Ok(number)
}
fn decode_owner(value:&Value,anchor:&std::path::Path)->Result<OwnerPlacementDocument> {
    let object=value.as_object().ok_or("protected owner object")?;
    let platform=value["platform"].as_str().ok_or("owner platform")?;
    #[cfg(windows)]
    if platform=="windows-x86_64" {return decode_windows_owner(value,anchor);}
    let fields=match platform {
        "linux-x86_64"=>vec!["platform","state","endpoint","lineage_sha256","owner_uid","node_uid","owner_gid","node_gid","ipc_gid"],
        // Windows protected placement/current/journal/channel integration is
        // unfinished. The approved TEST owner-state must not be silently
        // renamed or reinterpreted as this Linux state/ipc layout.
        _=>return Err("protected owner v2 currently supports Linux only"),
    };
    if object.len()!=fields.len() || object.keys().any(|k|!fields.contains(&k.as_str())) {return Err("owner exact schema");}
    let state=absolute(&value["state"])?;let endpoint=absolute(&value["endpoint"])?;
    if anchor!=state.join("clock-lineage.head") {return Err("owner descriptor/head placement differs");}
    let parent=state.parent().ok_or("owner state parent")?;
    if endpoint!=parent.join("ipc").join("clock.sock") || state.file_name()!=Some(std::ffi::OsStr::new("state")) {
        return Err("owner endpoint namespace differs");
    }
    let principals={
            let owner_uid=principal_number(&value["owner_uid"])?;let node_uid=principal_number(&value["node_uid"])?;
            let owner_gid=principal_number(&value["owner_gid"])?;let node_gid=principal_number(&value["node_gid"])?;
            let ipc_gid=principal_number(&value["ipc_gid"])?;
            if owner_uid==node_uid || owner_gid==node_gid || ipc_gid==owner_gid || ipc_gid==node_gid {
                return Err("owner/node/IPC principal separation required");
            }
            OwnerPrincipals::Linux{owner_uid,node_uid,owner_gid,node_gid,ipc_gid}
    };
    Ok(OwnerPlacementDocument{state,endpoint,lineage:digest(&value["lineage_sha256"])?,principals})
}

/// Existing prepared TEST-VALUE Windows installation profile only. These are
/// the Architect-approved identities/layout, not production roots or generic
/// caller-selected SID authority. Structural decoding remains documentary;
/// the installed factory still requires held admin selection, exact Genesis,
/// mandatory qualification and actual loaded/current software verification.
#[cfg(windows)]
fn decode_windows_owner(value:&Value,anchor:&std::path::Path)->Result<OwnerPlacementDocument> {
    let object=value.as_object().ok_or("Windows owner object")?;
    let async_message=value["channel_profile"].as_str()==Some("overlapped-message-v1");
    let mut fields=vec!["platform","state","endpoint","lineage_sha256","owner_sid","node_sid"];
    if async_message {fields.push("channel_profile");}
    if object.len()!=fields.len() || object.keys().any(|k|!fields.contains(&k.as_str())) {return Err("Windows owner exact schema");}
    let state=value["state"].as_str().ok_or("Windows owner state type")?;
    if state!=r"C:\Users\admin\MutinyClockQualification\owner-state" {return Err("Windows prepared owner state differs");}
    let owner_sid=value["owner_sid"].as_str().ok_or("Windows owner SID type")?;
    let node_sid=value["node_sid"].as_str().ok_or("Windows node SID type")?;
    if owner_sid!="S-1-5-21-2588165551-1705744427-3256592067-1005"
        || node_sid!="S-1-5-21-2588165551-1705744427-3256592067-1006" {return Err("Windows prepared principals differ");}
    let lineage=digest(&value["lineage_sha256"])?;
    let endpoint=if async_message {format!(r"\\.\pipe\MutinyClockQualification.AsyncMessage.{}",hex::encode(lineage))}
        else {format!(r"\\.\pipe\MutinyClockQualification.{}",hex::encode(lineage))};
    if value["endpoint"].as_str()!=Some(endpoint.as_str()) {return Err("Windows lineage-bound local endpoint differs");}
    let state=PathBuf::from(state);
    if anchor!=state.join("clock-lineage.head") {return Err("Windows owner anchor differs");}
    Ok(OwnerPlacementDocument{state,endpoint:PathBuf::from(endpoint),lineage,
        principals:OwnerPrincipals::Windows{owner_sid:owner_sid.into(),node_sid:node_sid.into(),async_message}})
}

/// Read all objects through the same retained administrator-owned directory
/// handles. This is a custody/encoding result, not a qualified deployment.
/// The caller must retain and recheck `owner`; it cannot turn this result into
/// InstalledNativeInputs without the separate qualification/current-fact gates.
pub(super) fn read_accepted_descriptor()->std::result::Result<
    (InstallationDescriptor,super::installation_directory::InstallationDirectory),String> {
    Ok(InstalledSelection::read()?.into_parts())
}

// This module deliberately has no public/feature-based fixture authority and
// no constructor for InstalledNativeInputs or CurrentNativeInputs. Native
// held-directory ownership and genuine qualification verification must be
// composed before ordinary selection can use the decoded descriptor.
