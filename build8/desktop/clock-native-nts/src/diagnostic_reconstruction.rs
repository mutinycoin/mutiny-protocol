//! Bounded canonical UNTRUSTED raw integer inputs. No network, producer result,
//! signing, profile approval or qualification. This type has no conversion to
//! AuthenticatedObservation or AcquisitionReport; its numbers are diagnostics.
use super::{AcquisitionBounds,IntervalView,integer_interval::MeasurementFacts};
use serde_json::{Map,Value};
use std::io;
const LIMIT:usize=64*1024;
fn error()->io::Error {io::Error::other("untrusted diagnostic arithmetic input refused")}
fn tree(v:&Value,depth:usize)->io::Result<Value> {
    if depth>8 {return Err(error());}
    Ok(match v {
        Value::Object(m)=>{
            if m.len()>64 || m.keys().any(|k|k.len()>128){return Err(error());}
            let mut keys=m.keys().collect::<Vec<_>>();keys.sort();let mut out=Map::new();
            for k in keys {out.insert(k.clone(),tree(&m[k],depth+1)?);}Value::Object(out)
        },
        Value::Array(a)=>{if a.len()>8{return Err(error());}Value::Array(a.iter().map(|v|tree(v,depth+1)).collect::<io::Result<_>>()?)},
        Value::String(s)=>{if s.len()>1024{return Err(error());}v.clone()},
        Value::Number(n) if n.is_u64()=>v.clone(),_=>return Err(error()),
    })
}
/// Same bounded canonical grammar for producer retention, not a replay issuer.
pub(crate) fn encode(v:&Value)->io::Result<Vec<u8>> {
    let bytes=serde_json::to_vec(&tree(v,0)?).map_err(|_|error())?;
    if bytes.is_empty() || bytes.len()>LIMIT {return Err(error());}Ok(bytes)
}
fn exact(v:&Value,keys:&[&str])->io::Result<()> {
    let m=v.as_object().ok_or_else(error)?;
    if m.len()!=keys.len() || m.keys().any(|k|!keys.contains(&k.as_str())) {return Err(error());}Ok(())
}
/// Diagnostic-only opaque result. Read-only view cannot authenticate a source.
pub struct DiagnosticInterval {view:IntervalView}
impl DiagnosticInterval {pub fn view(&self)->IntervalView {self.view}}
pub fn reconstruct_diagnostic_interval(raw:&[u8],bounds:&AcquisitionBounds)->io::Result<DiagnosticInterval> {
    bounds.validate()?;
    if raw.is_empty() || raw.len()>LIMIT {return Err(error());}
    let parsed:Value=serde_json::from_slice(raw).map_err(|_|error())?;
    let v=tree(&parsed,0)?;
    if serde_json::to_vec(&v).map_err(|_|error())?!=raw {return Err(error());}
    exact(&v,&["format","elapsed_abi","sent_ntp_fixed32","received_ntp_fixed32","before","after",
        "remote_midpoint_ntp_fixed32","local_midpoint_ntp_fixed32","delay_signed_fixed32",
        "root_delay_signed_fixed32","root_dispersion_signed_fixed32","precision_sign","precision_magnitude"])?;
    if v["format"].as_str()!=Some("build8/native-nts/raw-arithmetic-v1") {return Err(error());}
    for name in ["before","after"] {
        exact(&v[name],&["pre","post"])?;
        for capture in ["pre","post"] {
            let p=&v[name][capture];exact(p,&["active_before_ns","inclusive_ns","active_after_ns","boot_id_hex"])?;
            let boot=p["boot_id_hex"].as_str().ok_or_else(error)?;
            if boot.len()!=32 || !boot.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {return Err(error());}
        }
    }
    let i=MeasurementFacts::diagnostic(&v,bounds).ok_or_else(error)?;
    Ok(DiagnosticInterval {view:IntervalView {lower_posix_ns:i.lower_posix_ns,upper_posix_ns:i.upper_posix_ns,
        active_ns:i.midpoint_active_ns,inclusive_ns:i.midpoint_inclusive_ns,boot_id:i.boot_id,
        round_trip_ns:i.round_trip_ns,uncertainty_ns:i.uncertainty_ns}})
}
#[cfg(test)]
mod tests {
    use super::*;
    fn canonical(v:&Value)->Vec<u8> {serde_json::to_vec(&tree(v,0).unwrap()).unwrap()}
    fn fixture()->Value {
        let sent=(1_800_000_000u64+2_208_988_800)<<32;let received=sent+(1u64<<32)/10;let mid=sent+(received-sent)/2;
        let capture=|a:u64,b:u64|serde_json::json!({"active_before_ns":a,"active_after_ns":a+1000,
            "inclusive_ns":b,"boot_id_hex":format!("{:032x}",7)});
        let pair=|a:u64,b:u64|serde_json::json!({"pre":capture(a,b),"post":capture(a+2000,b+2000)});
        serde_json::json!({"format":"build8/native-nts/raw-arithmetic-v1",
            "elapsed_abi":"clock_gettime:CLOCK_MONOTONIC/CLOCK_BOOTTIME/CLOCK_MONOTONIC:ns:v1",
            "sent_ntp_fixed32":sent,"received_ntp_fixed32":received,"before":pair(1_000_000_000,2_000_000_000),
            "after":pair(1_100_000_000,2_100_000_000),"remote_midpoint_ntp_fixed32":mid,"local_midpoint_ntp_fixed32":mid,
            "delay_signed_fixed32":(1u64<<32)/10,"root_delay_signed_fixed32":0,"root_dispersion_signed_fixed32":0,
            "precision_sign":"negative","precision_magnitude":20})
    }
    #[test] fn modeled_raw_diagnostic_reconstruction_keeps_all_integer_error_contributions() {
        let v=fixture();let bounds=super::super::native_stamp::test_bounds();
        let d=reconstruct_diagnostic_interval(&canonical(&v),&bounds).unwrap().view();
        assert_eq!(d.boot_id,7);assert_eq!(d.round_trip_ns,100_000_000);
        assert!(d.uncertainty_ns>52_000_000);assert!(d.upper_posix_ns>d.lower_posix_ns);
        let mut windows=v;windows["elapsed_abi"]="QueryUnbiasedInterruptTimePrecise/QueryInterruptTimePrecise:100ns:v1".into();
        let w=reconstruct_diagnostic_interval(&canonical(&windows),&bounds).unwrap().view();
        assert!(w.uncertainty_ns>d.uncertainty_ns); // existing100ns pairing quantum, not a measured class.
    }
    #[test] fn modeled_diagnostic_schema_canonical_duplicates_and_partial_inputs_refuse() {
        let v=fixture();let b=super::super::native_stamp::test_bounds();let raw=canonical(&v);
        let mut duplicate=b"{\"format\":\"build8/native-nts/raw-arithmetic-v1\",".to_vec();duplicate.extend_from_slice(&raw[1..]);
        assert!(reconstruct_diagnostic_interval(&duplicate,&b).is_err());
        assert!(reconstruct_diagnostic_interval(&raw[..raw.len()-1],&b).is_err());
        let mut spaced=vec![b' '];spaced.extend_from_slice(&raw);assert!(reconstruct_diagnostic_interval(&spaced,&b).is_err());
        for field in ["PASS","UCB","authenticated"] {let mut unknown=v.clone();unknown[field]=true.into();
            assert!(reconstruct_diagnostic_interval(&serde_json::to_vec(&unknown).unwrap(),&b).is_err());}
        assert!(reconstruct_diagnostic_interval(&vec![b' ';LIMIT+1],&b).is_err());
    }
    #[test] fn modeled_diagnostic_raw_boot_span_overflow_precision_and_foreign_abi_refuse() {
        let v=fixture();let b=super::super::native_stamp::test_bounds();
        for fault in 0..7 {
            let mut bad=v.clone();match fault {
                0=>bad["after"]["pre"]["boot_id_hex"]=format!("{:032x}",8).into(),
                1=>bad["after"]["pre"]["active_after_ns"]=u64::MAX.into(),
                2=>bad["before"]["post"]["active_before_ns"]=0.into(),
                3=>bad["precision_magnitude"]=u64::MAX.into(),
                4=>bad["elapsed_abi"]="foreign".into(),5=>bad["root_delay_signed_fixed32"]=(1u64<<63).into(),
                _=>bad["local_midpoint_ntp_fixed32"]=0.into(),
            }
            assert!(reconstruct_diagnostic_interval(&canonical(&bad),&b).is_err());
        }
    }
}
