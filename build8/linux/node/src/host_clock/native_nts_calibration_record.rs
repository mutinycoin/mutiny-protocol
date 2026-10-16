//! Genuine live opaque ownership + input-retention arithmetic aggregation.
//! No historic export authentication, qualified method, engine-commit claim,
//! production clock issuer, disk writer, packet/key/cookie export or import.
use super::native_nts_deployment_record::{canonical_tree,DecodedRecord,Error};
use mutiny_clock_native_nts_v1::{AcquisitionReport,RetainedAcquisition,retain_acquisition};
use serde_json::Value;
use sha2::{Digest,Sha256};
type Result<T>=std::result::Result<T,Error>;
pub(super) struct LiveCalibrationRecord {record:DecodedRecord,live:RetainedAcquisition,
    initial:Vec<u8>,provenance:Vec<u8>,interval:(u64,u64)}
fn bytes(v:&Value)->Result<Vec<u8>> {
    let raw=serde_json::to_vec(&canonical_tree(v)?).map_err(|_|Error::QualificationEncoding)?;
    if raw.is_empty() || raw.len()>64*1024 {return Err(Error::Bound);}Ok(raw)
}
fn build_initial(live:&RetainedAcquisition)->Result<Vec<u8>> {
    let export:Value=serde_json::from_slice(live.public_export()).map_err(|_|Error::QualificationEncoding)?;
    let samples=export["accepted"].as_array().ok_or(Error::QualificationEncoding)?.iter()
        .map(|row|serde_json::json!({"provider":row["provider"],"arithmetic":row["arithmetic"]})).collect::<Vec<_>>();
    bytes(&serde_json::json!({"format":"build8/native-nts/raw-initial-v1","obligation":"capture_uncertainty",
        "elapsed_abi":export["elapsed_abi"],"now":export["now"],"samples":samples}))
}
pub(super) fn retain_live(record:&DecodedRecord,report:AcquisitionReport)->Result<LiveCalibrationRecord> {
    super::native_nts_backend::validate_profile(record.profile(),record.acquisition())
        .map_err(|_|Error::QualificationProvenance)?;
    let live=retain_acquisition(report,record.acquisition()).map_err(|_|Error::QualificationProvenance)?;
    live.verify_export(live.public_export(),record.acquisition()).map_err(|_|Error::QualificationProvenance)?;
    let initial=build_initial(&live)?;let raw:Value=serde_json::from_slice(&initial).map_err(|_|Error::QualificationEncoding)?;
    let subject=super::native_nts_qualification::measurement_subject(record)?;
    let interval=super::native_nts_raw_measurements::initial(&raw,&subject,record.profile(),record.acquisition())?;
    let provenance=bytes(&serde_json::json!({"format":"build8/native-nts/retained-live-provenance-v1",
        "classification":"PUBLIC_DOCUMENTATION_REQUIRES_STILL_OWNED_LIVE_REPORT_NOT_HISTORICAL_PROOF",
        "stage":"INPUT_RETENTION_NOT_ENGINE_ANCHOR_COMMIT","subject":subject,
        // Do not create qualification->deployment->report self-hash cycles.
        // Full record equality is required privately; existing envelope scope
        // binds its other fields separately. Public subject uses Source22's
        // exact experimental projection excluding only evidence self-pins.
        "subject_sha256":hex::encode(Sha256::digest(bytes(&subject)?)),
        "initial_sha256":hex::encode(Sha256::digest(&initial)),
        "live_export_sha256":hex::encode(Sha256::digest(live.public_export()))}))?;
    Ok(LiveCalibrationRecord{record:record.clone(),live,initial,provenance,interval})
}
impl LiveCalibrationRecord {
    pub(super) fn verify_live(&self,record:&DecodedRecord)->Result<()> {
        if record!=&self.record || build_initial(&self.live)?!=self.initial {return Err(Error::QualificationScope);}
        self.live.verify_export(self.live.public_export(),record.acquisition()).map_err(|_|Error::QualificationProvenance)?;
        Ok(())
    }
    pub(super) fn initial_interval(&self)->(u64,u64) {self.interval}
    pub(super) fn documentary_objects(&self)->[&[u8];3] {
        [&self.initial,&self.provenance,self.live.public_export()]
    }
    pub(super) fn qualification(&self)->Result<()> {Err(Error::MissingQualification)}
}
