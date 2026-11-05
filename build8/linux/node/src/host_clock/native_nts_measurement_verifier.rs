//! Finite local measurement verifier. No default accepted policy/issuer exists.
//! Modeled success is not a physical measurement or a normal clock capability.
#![allow(dead_code)]
use serde_json::{Map,Value};
use sha2::{Digest,Sha256};
use std::collections::{BTreeMap,BTreeSet};
#[path="measurement_math.rs"] mod math;
#[path="measurement_trace.rs"] mod trace;
#[path="measurement_provenance.rs"] mod provenance;
#[path="measurement_reducers.rs"] mod reducers;
#[cfg(test)] #[path="measurement_modeled_controls.rs"] mod modeled_controls;
pub(super) type Hash=[u8;32];
pub(super) type Result<T>=std::result::Result<T,Error>;
pub(super) const MAX_OBJECT:usize=64*1024;
pub(super) const MAX_OBJECTS:usize=4096;
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(super) enum Error {Bound,Encoding,Canonical,Digest,Scope,Sequence,ReferenceCycle,
    MissingArtifact,MissingAcceptedPolicy,MissingIssuer,Signature,Arithmetic,
    Frequency,Precision,Lifecycle,Authentication,Loss,Leap,Storage,Coverage,Experiment}
pub(super) fn hash(bytes:&[u8])->Hash {Sha256::digest(bytes).into()}
pub(super) fn exact<'a>(v:&'a Value,keys:&[&str])->Result<&'a Map<String,Value>> {
    let m=v.as_object().ok_or(Error::Encoding)?;
    if m.len()!=keys.len() || m.keys().any(|k|!keys.contains(&k.as_str())) {return Err(Error::Encoding);}Ok(m)
}
pub(super) fn text(v:&Value)->Result<&str>{v.as_str().ok_or(Error::Encoding)}
pub(super) fn number(v:&Value)->Result<u64>{v.as_u64().ok_or(Error::Encoding)}
pub(super) fn u32n(v:&Value)->Result<u32>{u32::try_from(number(v)?).map_err(|_|Error::Bound)}
pub(super) fn digest(v:&Value)->Result<Hash> {
    let s=text(v)?;let mut h=[0;32];
    if s.len()!=64 || !s.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || hex::decode_to_slice(s,&mut h).is_err() || h==[0;32] {return Err(Error::Digest);}Ok(h)
}
pub(super) fn bytes(v:&Value,maximum:usize)->Result<Vec<u8>> {
    let s=text(v)?;let limit=maximum.checked_mul(2).ok_or(Error::Bound)?;
    if s.len()>limit || s.len()%2!=0 || !s.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(Error::Bound);
    }hex::decode(s).map_err(|_|Error::Encoding)
}
pub(super) fn canonical(v:&Value)->Result<Vec<u8>> {
    fn tree(v:&Value,depth:usize)->Result<Value> {
        if depth>128{return Err(Error::Bound);}
        match v {
            Value::Number(n) if !n.is_u64()&&!n.is_i64()=>Err(Error::Encoding),
            Value::Array(a)=>{
                let mut out=Vec::with_capacity(a.len());for value in a{out.push(tree(value,depth+1)?);}Ok(Value::Array(out))
            }
            Value::Object(m)=>{
                let mut keys:Vec<&String>=m.keys().collect();keys.sort_unstable();let mut out=Map::new();
                for key in keys {out.insert(key.clone(),tree(&m[key],depth+1)?);}Ok(Value::Object(out))
            }
            _=>Ok(v.clone())
        }
    }
    serde_json::to_vec(&tree(v,0)?).map_err(|_|Error::Encoding)
}
pub(super) fn parse(raw:&[u8])->Result<Value> {
    if raw.is_empty() || raw.len()>MAX_OBJECT{return Err(Error::Bound);}
    let v:Value=serde_json::from_slice(raw).map_err(|_|Error::Encoding)?;
    // Re-encoding rejects duplicate keys, whitespace, key disorder, alternate
    // number spellings and floats, instead of silently normalizing an input.
    if canonical(&v)?!=raw{return Err(Error::Canonical);}Ok(v)
}
pub(super) fn ratio(v:&Value)->Result<math::Ratio> {
    let r=exact(v,&["numerator","denominator"])?;
    math::Ratio::new(number(&r["numerator"])? ,number(&r["denominator"])?)
}
/// Native reader consumes only digest names selected by this bounded parser.
/// Construction is private: neither a path nor a successful caller flag enters.
pub(super) struct RetentionPlan {digests:BTreeSet<Hash>,limit:usize}
impl RetentionPlan {
    fn empty(limit:usize)->Result<Self> {
        if limit==0 || limit>MAX_OBJECTS{return Err(Error::Bound);}Ok(Self{digests:BTreeSet::new(),limit})
    }
    fn add(&mut self,pin:Hash)->Result<()> {
        if pin==[0;32]{return Err(Error::Digest);}
        if !self.digests.contains(&pin) && self.digests.len()>=self.limit{return Err(Error::Bound);}
        self.digests.insert(pin);Ok(())
    }
    pub(super) fn digests(&self)->impl Iterator<Item=&Hash>{self.digests.iter()}
    pub(super) fn object_count(&self)->usize{self.digests.len()}
    pub(super) fn maximum_objects(&self)->usize{self.limit}
    pub(super) fn maximum_total_bytes(&self)->Result<u64> {
        u64::try_from(self.limit.checked_mul(MAX_OBJECT).ok_or(Error::Bound)?).map_err(|_|Error::Bound)
    }
}
/// Exact bytes supplied only by the installation's native-held reader in normal
/// composition. Test constructors are cfg(test), not a resolver callback.
pub(super) struct RetainedArtifacts {objects:BTreeMap<Hash,Vec<u8>>,total:usize}
impl RetainedArtifacts {
    pub(super) fn collect_from_installation(owner:&super::installation_directory::InstallationDirectory,
        plan:&RetentionPlan)->Result<Self> {
        let mut out=Self{objects:BTreeMap::new(),total:0};
        for pin in plan.digests() {
            let raw=owner.artifact(pin).map_err(|_|Error::MissingArtifact)?;
            out.insert(*pin,raw,plan.maximum_objects())?;
        }Ok(out)
    }
    fn insert(&mut self,pin:Hash,raw:&[u8],maximum:usize)->Result<()> {
        if raw.is_empty() || raw.len()>MAX_OBJECT || hash(raw)!=pin{return Err(Error::Digest);}
        if let Some(old)=self.objects.get(&pin) {if old!=raw{return Err(Error::Digest);}return Ok(());}
        if self.objects.len()>=maximum || maximum>MAX_OBJECTS{return Err(Error::Bound);}
        self.total=self.total.checked_add(raw.len()).ok_or(Error::Bound)?;
        if self.total>maximum.checked_mul(MAX_OBJECT).ok_or(Error::Bound)? {return Err(Error::Bound);}
        self.objects.insert(pin,raw.to_vec());Ok(())
    }
    fn raw(&self,pin:&Hash)->Result<&[u8]>{self.objects.get(pin).map(Vec::as_slice).ok_or(Error::MissingArtifact)}
    fn object(&self,pin:&Hash)->Result<Value>{parse(self.raw(pin)?)}
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum Class {ModeledTest,AcceptedPhysical}
/// Ordinary construction requires the SAME native-held installation's exact
/// administrator-selected artifacts and issuer pins. Parsed records alone,
/// caller flags and modeled findings cannot construct accepted qualification.
pub(super) struct SelectedMethods {
    scope:super::protected_clock_lineage_v1::Scope,
    class:Class,subject:Hash,confidence:math::Ratio,margin:math::Ratio,
    selected_drift_ppb:u64,quantum_ns:u64,maximum_span_ns:u64,
    precision_ns:u64,minimum_holdover_ns:u64,maximum_gap_ns:u64,
    provider_roots:Vec<Hash>,producer:Hash,issuers:Vec<provenance::Issuer>,
    methods:Vec<trace::Method>,instruments:BTreeMap<Hash,provenance::Instrument>,
    envelope:provenance::Envelope,coverage_pins:Vec<Hash>,
    profile:mutiny_consensus_v8::holdover_clock_v1::ClockProfile,
    acquisition:mutiny_clock_native_nts_v1::Config,
    lifecycle_cases:BTreeSet<(trace::LifecycleCase,Hash)>,
    authentication_cases:BTreeSet<(u32,trace::AuthCase)>,
    authentication_results:BTreeMap<trace::AuthCase,u32>,success_result:u32,
    tls_codes:BTreeSet<u16>,aead_codes:BTreeSet<u16>,leap_codes:BTreeMap<String,u32>,
    storage_cases:BTreeSet<trace::StorageCase>,
    frequency_raw_pin:Hash,
}
pub(super) struct VerifiedExperiments {class:Class,subject:Hash,methods:[Hash;6],
    frequency_upper_ppb:u64,margin_ppb:u64,trace_roots:[Hash;6]}
impl VerifiedExperiments {
    pub(super) fn normal_qualification(&self)->Result<()> {
        if self.class!=Class::AcceptedPhysical{return Err(Error::MissingAcceptedPolicy);}Ok(())
    }
    pub(super) fn frequency_upper_ppb(&self)->u64{self.frequency_upper_ppb}
    pub(super) fn trace_roots(&self)->&[Hash;6]{&self.trace_roots}
}
/// Explicit refusal is the normal default, not an administrator Boolean gate.
pub(super) fn normal_default_selection()->Result<SelectedMethods>{Err(Error::MissingAcceptedPolicy)}
impl SelectedMethods {
    /// Common mandatory input validation for separately typed TEST/installed
    /// selection. All policy/result/coverage inputs are explicit; no confidence, margin,
    /// experiment schedule, result code or timing default is synthesized.
    fn parse_inputs(raw:&[u8],subject:Hash,scope:super::protected_clock_lineage_v1::Scope,class:Class,
        profile:mutiny_consensus_v8::holdover_clock_v1::ClockProfile,
        acquisition:mutiny_clock_native_nts_v1::Config,held:&RetainedArtifacts)->Result<Self> {
        let v=parse(raw)?;
        let m=exact(&v,&["format","subject_sha256","confidence","margin","producer_execution_sha256","issuer_pins",
            "instrument_pins","envelope_pin","coverage_certificate_pins","method_pins","frequency_raw_pin","provider_root_pins","lifecycle_cases",
            "authentication_results","success_result_code","tls_codes","aead_codes","leap_codes","storage_cases"])?;
        let format=match class{Class::ModeledTest=>"b8-clock-modeled-method-selection-v1",Class::AcceptedPhysical=>"b8-clock-method-selection-v1"};
        if text(&m["format"])?!=format || digest(&m["subject_sha256"])?!=subject{return Err(Error::Scope);}
        super::native_nts_backend::validate_profile(&profile,&acquisition).map_err(|_|Error::Scope)?;
        let list=|name:&str|->Result<Vec<Hash>> {
            let a=m[name].as_array().ok_or(Error::Encoding)?;
            if a.is_empty() || a.len()>MAX_OBJECTS{return Err(Error::Bound);}
            let mut seen=BTreeSet::new();let mut out=Vec::with_capacity(a.len());
            for pin in a {let pin=digest(pin)?;if !seen.insert(pin){return Err(Error::Scope);}out.push(pin);}Ok(out)
        };
          let producer=digest(&m["producer_execution_sha256"])?;
          let confidence=ratio(&m["confidence"])?;let margin=ratio(&m["margin"])?;
          if !math::Ratio::new(999,1000)?.at_most(confidence) || margin!=math::Ratio::new(1,5)? {return Err(Error::Coverage);}
        let mut issuers=Vec::new();for pin in list("issuer_pins")? {
            issuers.push(provenance::Issuer::parse_selected(held.raw(&pin)?,pin,subject,producer)?);
        }
        let mut instruments=BTreeMap::new();for pin in list("instrument_pins")? {
            instruments.insert(pin,provenance::Instrument::parse_selected(held.raw(&pin)?,pin)?);
        }
        let envelope_pin=digest(&m["envelope_pin"])?;
        let envelope=provenance::Envelope::parse_selected(held.raw(&envelope_pin)?,envelope_pin)?;
        let method_pins=list("method_pins")?;
        if method_pins.len()!=6{return Err(Error::Scope);}
        let mut methods=Vec::with_capacity(6);
        for (i,pin)in method_pins.iter().enumerate() {
            let method=trace::Method::parse(held.raw(pin)?)?;
            if method.kind.index()!=i || method.subject!=subject || method.pin!=*pin{return Err(Error::Scope);}methods.push(method);
        }
        let provider_roots=list("provider_root_pins")?;
        if provider_roots.len()!=acquisition.providers.len(){return Err(Error::Scope);}
        let cases=m["lifecycle_cases"].as_array().ok_or(Error::Encoding)?;
        if cases.is_empty() || cases.len()>MAX_OBJECTS{return Err(Error::Bound);}
        let mut lifecycle_cases=BTreeSet::new();for case in cases {
            let c=exact(case,&["case","environment_cell"])?;
            let pair=(trace::LifecycleCase::parse(&c["case"])? ,digest(&c["environment_cell"]) ?);
            if !envelope.environment_cells.contains(&pair.1) || !lifecycle_cases.insert(pair){return Err(Error::Scope);}
        }
        let results=exact(&m["authentication_results"],&["valid","wrong-host","wrong-root","tampered-response","replayed-response","unavailable-source"])?;
        let mut authentication_results=BTreeMap::new();let mut authentication_cases=BTreeSet::new();
        for(name,value)in results {
            let case=trace::AuthCase::parse(&Value::from(name.as_str()))?;
            authentication_results.insert(case,u32n(value)?);
            for index in 0..provider_roots.len(){authentication_cases.insert((index as u32,case));}
        }
        let success_result=u32n(&m["success_result_code"])?;
        if authentication_results.get(&trace::AuthCase::Valid)!=Some(&success_result)
            || authentication_results.iter().any(|(case,result)|*case!=trace::AuthCase::Valid && *result==success_result) {return Err(Error::Scope);}
        let codes=|name:&str|->Result<BTreeSet<u16>> {
            let a=m[name].as_array().ok_or(Error::Encoding)?;
            if a.is_empty() || a.len()>MAX_OBJECTS{return Err(Error::Bound);}
            let mut out=BTreeSet::new();for code in a {
                if !out.insert(u16::try_from(u32n(code)?).map_err(|_|Error::Bound)?){return Err(Error::Scope);}
            }Ok(out)
        };
        let leap=exact(&m["leap_codes"],&["insert","delete"])?;
        let leap_codes=BTreeMap::from([("insert".to_owned(),u32n(&leap["insert"])?),("delete".to_owned(),u32n(&leap["delete"]) ?)]);
        let storage=m["storage_cases"].as_array().ok_or(Error::Encoding)?;
        if storage.is_empty() || storage.len()>6{return Err(Error::Bound);}
        let mut storage_cases=BTreeSet::new();for case in storage {
            if !storage_cases.insert(trace::StorageCase::parse(case)?){return Err(Error::Scope);}
        }
        let quantum_ns=if profile.id()==[0;32]{return Err(Error::Scope);} else {
            // ABI comes from the selected frequency raw record; unsupported ABI
            // refuses rather than assuming platform/local diagnostic output.
            let raw=held.object(&digest(&m["frequency_raw_pin"])?)?;
            match text(&raw["capture_start"]["boot"]["format"])? {
                "linux-boot-uuid-v1"=>1,"windows-class90-v1"=>100,_=>return Err(Error::Scope)
            }
        };
        if class==Class::AcceptedPhysical && methods.iter().any(|m|m.required_class==trace::ExperimentClass::Simulated)
            {return Err(Error::Experiment);}
        Ok(Self{scope,class,subject,confidence,margin,producer,issuers,instruments,envelope,methods,
            selected_drift_ppb:profile.drift_bound_ppb,quantum_ns,maximum_span_ns:acquisition.bounds.maximum_sampling_span_ns,
            precision_ns:acquisition.bounds.wall_timestamp_uncertainty_ns,
            minimum_holdover_ns:profile.max_holdover_ms.checked_mul(1_000_000).ok_or(Error::Arithmetic)?,
            maximum_gap_ns:profile.max_suspend_gap_ms.checked_mul(1_000_000).ok_or(Error::Arithmetic)?,
              provider_roots,lifecycle_cases,authentication_cases,authentication_results,success_result,
              coverage_pins:list("coverage_certificate_pins")?,
            tls_codes:codes("tls_codes")?,aead_codes:codes("aead_codes")?,leap_codes,storage_cases,
            frequency_raw_pin:digest(&m["frequency_raw_pin"])? ,profile,acquisition})
    }
    #[cfg(test)]
    fn from_modeled_inputs(raw:&[u8],subject:Hash,scope:super::protected_clock_lineage_v1::Scope,
        profile:mutiny_consensus_v8::holdover_clock_v1::ClockProfile,
        acquisition:mutiny_clock_native_nts_v1::Config,held:&RetainedArtifacts)->Result<Self> {
        Self::parse_inputs(raw,subject,scope,Class::ModeledTest,profile,acquisition,held)
    }
    /// Only SAME native-held administrator selection and exact own deployment
    /// supply accepted issuer artifacts. A raw descriptor/receipt/caller Boolean
    /// cannot construct this type. No accepted data is synthesized when absent.
    pub(super) fn from_installed(owner:&mut super::installation_directory::InstallationDirectory,
        record:&super::native_nts_deployment_record::DecodedRecord)->Result<Self> {
        owner.recheck().map_err(|_|Error::MissingAcceptedPolicy)?;
        let (descriptor,deployment,_)=owner.objects();
        if deployment!=record.canonical(){return Err(Error::Scope);}
        let v=parse(descriptor)?;let d=exact(&v,&["format","record_sha256","qualification_sha256","genesis_artifact_sha256",
            "genesis_block_sha256","anchor","cadence_seconds","protected_owner","measurement_selection"])?;
        if text(&d["format"])?!="build8/native-nts/installation-v3" || digest(&d["record_sha256"])?!=hash(deployment)
            {return Err(Error::MissingAcceptedPolicy);}
        let selected=exact(&d["measurement_selection"],&["selection_sha256","accepted_issuer_pins"])?;
        let selection_pin=digest(&selected["selection_sha256"])?;
        let a=selected["accepted_issuer_pins"].as_array().ok_or(Error::Encoding)?;
        if a.is_empty() || a.len()>32{return Err(Error::Bound);}
        let mut accepted=Vec::with_capacity(a.len());for pin in a {let pin=digest(pin)?;
            if accepted.last().is_some_and(|old|old>=&pin){return Err(Error::Canonical);}accepted.push(pin);}
        let deployment=parse(deployment)?;let binding=&deployment["binding"];
        let scope=super::protected_clock_lineage_v1::Scope::selected_document(digest(&binding["genesis_sha256"])? ,
            digest(&binding["network_sha256"])? ,digest(&binding["rule_sha256"])? ,digest(&d["protected_owner"]["lineage_sha256"])?);
        let subject=super::native_nts_qualification::measurement_subject(record).map_err(|_|Error::Scope)?;
        let subject=hash(&canonical(&subject)?);
        let mut plan=RetentionPlan::empty(MAX_OBJECTS)?;plan.add(selection_pin)?;
        for pin in &accepted{plan.add(*pin)?;}
        owner.extend_retained(&plan).map_err(|_|Error::MissingArtifact)?;
        let raw=owner.artifact(&selection_pin).map_err(|_|Error::MissingArtifact)?.to_vec();
        let selection=parse(&raw)?;
        for name in ["issuer_pins","instrument_pins","method_pins","provider_root_pins","coverage_certificate_pins"] {
            let a=selection[name].as_array().ok_or(Error::Encoding)?;
            if a.is_empty() || a.len()>MAX_OBJECTS{return Err(Error::Bound);}
            for pin in a{plan.add(digest(pin)?)?;}
        }
        for name in ["envelope_pin","frequency_raw_pin","producer_execution_sha256"]{plan.add(digest(&selection[name])?)?;}
        owner.extend_retained(&plan).map_err(|_|Error::MissingArtifact)?;
        let held=RetainedArtifacts::collect_from_installation(owner,&plan)?;
        let parsed=Self::parse_inputs(&raw,subject,scope,Class::AcceptedPhysical,record.profile().clone(),record.acquisition().clone(),&held)?;
        let actual:BTreeSet<Hash>=parsed.issuers.iter().map(provenance::Issuer::pin).collect();
        if actual!=accepted.into_iter().collect(){return Err(Error::MissingIssuer);}
        family_budget(&parsed)?;owner.recheck().map_err(|_|Error::MissingAcceptedPolicy)?;Ok(parsed)
    }
}
pub(super) fn index_plan(raw:&[u8],method:&trace::Method,subject:Hash)->Result<RetentionPlan> {
    trace::Index::parse(raw,method,subject)?.plan()
}
pub(super) fn records_plan(raw:&[u8],method:&trace::Method,selection:&SelectedMethods,
    retained:&RetainedArtifacts)->Result<RetentionPlan> {
    trace::Index::parse(raw,method,selection.subject)?.records_plan(retained,method,selection)
}
fn family_budget(selection:&SelectedMethods)->Result<usize> {
    if selection.methods.len()!=6{return Err(Error::Scope);}
    let budget=selection.methods[0].maximum_artifacts;
    if budget<32 || budget>MAX_OBJECTS || selection.methods.iter().any(|m|m.maximum_artifacts!=budget){return Err(Error::Bound);}Ok(budget)
}
pub(super) fn family_index_plan(selection:&SelectedMethods,indices:[&[u8];6],top:&[Hash])->Result<RetentionPlan> {
    let mut out=RetentionPlan::empty(family_budget(selection)?)?;
    if top.len()!=32{return Err(Error::Scope);}for pin in top{out.add(*pin)?;}
    out.add(selection.frequency_raw_pin)?;out.add(selection.envelope.pin)?;out.add(selection.producer)?;
    out.add(selection.envelope.calibration)?;out.add(selection.envelope.review)?;
    for pin in &selection.envelope.environment_cells{out.add(*pin)?;}
    for pin in &selection.coverage_pins{out.add(*pin)?;}
    for issuer in &selection.issuers{out.add(issuer.pin())?;}
    for instrument in selection.instruments.values(){out.add(instrument.pin)?;}
    for i in 0..6 {
        let method=&selection.methods[i];let index=trace::Index::parse(indices[i],method,selection.subject)?;
        for pin in index.plan()?.digests(){out.add(*pin)?;}
    }Ok(out)
}
pub(super) fn family_records_plan(selection:&SelectedMethods,indices:[&[u8];6],top:&[Hash],held:&RetainedArtifacts)->Result<RetentionPlan> {
    let mut out=family_index_plan(selection,indices,top)?;
    for i in 0..6 {
        let method=&selection.methods[i];let index=trace::Index::parse(indices[i],method,selection.subject)?;
        for pin in index.records_plan(held,method,selection)?.digests(){out.add(*pin)?;}
    }Ok(out)
}
pub(super) fn family_support_plan(selection:&SelectedMethods,indices:[&[u8];6],top:&[Hash],held:&RetainedArtifacts)->Result<RetentionPlan> {
    let mut out=family_records_plan(selection,indices,top,held)?;
    for pin in support_plan(selection,indices,held)?.digests(){out.add(*pin)?;}Ok(out)
}
pub(super) fn frequency_pin(selection:&SelectedMethods)->Hash{selection.frequency_raw_pin}
pub(super) fn subject_pin(selection:&SelectedMethods)->Hash{selection.subject}
pub(super) fn group_bindings(selection:&SelectedMethods,index:usize,subject:&Value,
    refs:&Value,records:super::native_nts_raw_measurements::RawRecords<'_>)->Result<()> {
    let r=exact(refs,&["report_sha256","method_sha256","raw_data_sha256","environment_sha256"])?;
    let raws=[records.report,records.method,records.raw,records.environment];
    let keys=["report_sha256","method_sha256","raw_data_sha256","environment_sha256"];
    for (name,raw)in keys.into_iter().zip(raws) {
        if raw.is_empty() || raw.len()>MAX_OBJECT || hash(raw)!=digest(&r[name])? {return Err(Error::Digest);}parse(raw)?;
    }
    let method=selection.methods.get(index).ok_or(Error::Scope)?;
    if method.kind.index()!=index || hash(records.method)!=method.pin || hash(records.environment)!=method.environment{return Err(Error::Scope);}
    let report=parse(records.report)?;
    let report=exact(&report,&["format","obligation","method_sha256","raw_data_sha256","environment_sha256"])?;
    if text(&report["format"])?!="build8/native-nts/measurement-report-v1" || text(&report["obligation"])?!=method.kind.obligation() {return Err(Error::Scope);}
    for key in ["method_sha256","raw_data_sha256","environment_sha256"]{if report[key]!=r[key]{return Err(Error::Digest);}}
    let environment=parse(records.environment)?;
    let environment=exact(&environment,&["format","obligation","subject","instrument_provenance_sha256"])?;
    if text(&environment["format"])?!="build8/native-nts/measurement-environment-v1"
        || text(&environment["obligation"])?!=method.kind.obligation() || &environment["subject"]!=subject
        || hash(&canonical(subject)?)!=selection.subject{return Err(Error::Scope);}
    let provenance=digest(&environment["instrument_provenance_sha256"])?;
    if provenance!=selection.envelope.instrument && !selection.instruments.values().any(|i|i.instrument==provenance||i.calibration==provenance) {return Err(Error::MissingIssuer);}
    Ok(())
}
/// Finite second-stage supporting objects; no recursive artifact discovery.
/// Newly retained objects are leaves in one explicit role graph. Unknown
/// producer/identity formats refuse before a reducer can use their bytes.
pub(super) fn support_plan(selection:&SelectedMethods,indices:[&[u8];6],held:&RetainedArtifacts)->Result<RetentionPlan> {
    let mut p=RetentionPlan::empty(MAX_OBJECTS)?;
    let mut graph:BTreeMap<Hash,BTreeSet<Hash>>=BTreeMap::new();
    let mut add=|from:Hash,to:Hash|->Result<()> {
        if from==to{return Err(Error::ReferenceCycle);}p.add(from)?;p.add(to)?;
        graph.entry(from).or_default().insert(to);graph.entry(to).or_default();Ok(())
    };
    for issuer in &selection.issuers {add(selection.subject,issuer.pin())?;}
    for instrument in selection.instruments.values() {
        for target in [instrument.instrument,instrument.calibration,instrument.environment,instrument.coverage_event] {
            add(instrument.pin,target)?;
        }
    }
    add(selection.envelope.pin,selection.envelope.instrument)?;
    add(selection.envelope.pin,selection.envelope.calibration)?;add(selection.envelope.pin,selection.envelope.review)?;
    for pin in &selection.coverage_pins {
        let v=held.object(pin)?;let c=exact(&v,&["format","subject_sha256","coverage_event_sha256","failure_probability","covered_events",
            "justification_sha256","producer_execution_sha256","issuer_sha256","algorithm","signature_der_hex"])?;
        if text(&c["format"])?!="b8-clock-joint-coverage-certificate-v1" {return Err(Error::Coverage);}
        add(*pin,digest(&c["justification_sha256"])?)?;
        add(*pin,digest(&c["coverage_event_sha256"])?)?;
    }
    for c in &selection.envelope.environment_cells {
        add(selection.envelope.pin,*c)?;
        let cell=held.object(c)?;let cell=exact(&cell,&["format","subject_sha256","hardware_sha256","firmware_sha256",
            "os_sha256","execution_environment_sha256","operating_conditions_sha256"])?;
        if text(&cell["format"])?!="b8-clock-supported-environment-cell-v1" || digest(&cell["subject_sha256"])?!=selection.subject
            {return Err(Error::Scope);}
        for name in ["hardware_sha256","firmware_sha256","os_sha256","execution_environment_sha256","operating_conditions_sha256"] {
            add(*c,digest(&cell[name])?)?;
        }
    }
    for i in 0..6 {
        let method=&selection.methods[i];let index=trace::Index::parse(indices[i],method,selection.subject)?;
        for pin in index.plan()?.digests(){add(selection.subject,*pin)?;}
        let events=index.events(held,method,selection)?;
        for event in events {
            for pin in event.refs(){add(index.pin,pin)?;}
            use trace::Record;
            match event.record {
                Record::Process{process,principal}=>{
                    let v=held.object(&process)?;
                    exact(&v,&["format","subject_sha256","principal_sha256","native_identity_sha256","execution_sha256"])?;
                    if text(&v["format"])?!="b8-clock-native-process-record-v1" || digest(&v["principal_sha256"])?!=principal{return Err(Error::Scope);}
                    add(process,digest(&v["native_identity_sha256"])?)?;add(process,principal)?;
                }
                Record::StorageAction{object,..}=>{
                    let v=held.object(&object)?;
                    exact(&v,&["format","subject_sha256","process_record_sha256","principal_record_sha256","retained_identity_sha256","filesystem_sha256","continuity"])?;
                    if text(&v["format"])?!="b8-clock-retained-native-object-v1" {return Err(Error::Scope);}
                    for name in ["process_record_sha256","principal_record_sha256","retained_identity_sha256","filesystem_sha256"]{add(object,digest(&v[name])?)?;}
                    let c=exact(&v["continuity"],&["format","scope","operation_identity_sha256","content_sha256",
                        "request_hex","before_state_sha256","intent_state_sha256","completion_state_sha256"])?;
                    if text(&c["format"])?!="b8-clock-storage-continuity-plan-v1" {return Err(Error::Scope);}
                    for name in ["before_state_sha256","intent_state_sha256","completion_state_sha256"]{add(object,digest(&c[name])?)?;}
                }
                _=>{}
            }
        }
    }
    drop(add);
    // Iterative bounded topological elimination detects every referenced cycle.
    // No recursive parser or callback may change roles/discover more objects.
    let mut indegrees:BTreeMap<Hash,usize>=graph.keys().map(|pin|(*pin,0)).collect();
    for targets in graph.values(){for to in targets{let count=indegrees.get_mut(to).ok_or(Error::ReferenceCycle)?;
        *count=count.checked_add(1).ok_or(Error::Bound)?;}}
    let mut ready:Vec<Hash>=indegrees.iter().filter_map(|(pin,n)|(*n==0).then_some(*pin)).collect();let mut visited=0usize;
    while let Some(pin)=ready.pop(){visited=visited.checked_add(1).ok_or(Error::Bound)?;
        for to in graph.get(&pin).ok_or(Error::ReferenceCycle)? {let n=indegrees.get_mut(to).ok_or(Error::ReferenceCycle)?;
            *n=n.checked_sub(1).ok_or(Error::ReferenceCycle)?;if *n==0{ready.push(*to);}}
    }
    if visited!=graph.len(){return Err(Error::ReferenceCycle);}Ok(p)
}
/// Entire finite dispatch has no pass field or executable sender callback.
pub(super) fn verify_selected(selection:&SelectedMethods,indices:[&[u8];6],
    retained:&RetainedArtifacts,frequency_raw:&[u8],
    necessary:&super::native_nts_raw_measurements::NecessaryReport)->Result<VerifiedExperiments> {
    if selection.methods.len()!=6 || selection.provider_roots.is_empty()
        || selection.producer==[0;32] || selection.quantum_ns==0 {return Err(Error::Scope);}
    let (frequency,reference,first,last)=frequency_run(selection,frequency_raw,retained)?;
    let mut reference_pins=BTreeSet::from([first,last]);
    selection.envelope.verify(selection,retained)?;
    let mut upper=math::frequency_upper(frequency,reference,selection.minimum_holdover_ns)?
        .max(selection.envelope.maximum_error_ppb);
    use provenance::CoverageKind as CK;
    let mut required=BTreeSet::from([(CK::Frequency,selection.frequency_raw_pin),(CK::Capture,selection.frequency_raw_pin),
        (CK::ClassModel,selection.envelope.pin),(CK::ClassModel,selection.envelope.instrument),
        (CK::Calibration,selection.envelope.calibration),(CK::Systematic,selection.envelope.review)]);
    let (arithmetic_frequency,arithmetic_initial)=necessary.documentary_inputs();
    for pin in [arithmetic_frequency,arithmetic_initial]{retained.raw(&pin)?;}
    required.insert((CK::Frequency,arithmetic_frequency));
    required.insert((CK::Capture,arithmetic_frequency));required.insert((CK::Capture,arithmetic_initial));
    let mut roots=[[0;32];6];let mut methods=[[0;32];6];
    for i in 0..6 {
        let method=&selection.methods[i];if method.kind.index()!=i {return Err(Error::Scope);}
        let index=trace::Index::parse(indices[i],method,selection.subject)?;
        let events=index.events(retained,method,selection)?;
        required.insert((CK::for_trace(method.kind),index.root));
        for event in &events {required.insert((CK::Capture,event.projection));
            for pin in event.external_refs(){reference_pins.insert(pin);}}
        provenance::trace_receipt(selection,&index,method,retained)?;
        upper=upper.max(reducers::reduce(selection,method,&index,&events,retained)?);
        roots[i]=index.root;methods[i]=method.pin;
    }
    let margin=math::check_margin(upper,selection.selected_drift_ppb,selection.margin)?;
    for pin in &reference_pins {
        let instrument=selection.instruments.get(pin).ok_or(Error::MissingIssuer)?;
        instrument.verify(selection,retained,*pin)?;
        required.insert((CK::Reference,*pin));required.insert((CK::Calibration,instrument.calibration));
        required.insert((CK::Systematic,instrument.instrument));
    }
    verify_joint_coverage(selection,&required,&reference_pins,retained)?;
    let initial=necessary.initial();
    if initial.1<initial.0 || (initial.1-initial.0).div_ceil(2)>selection.profile.max_calibration_half_width_ms {
        return Err(Error::Precision);
    }
    Ok(VerifiedExperiments{class:selection.class,subject:selection.subject,methods,
        frequency_upper_ppb:upper,margin_ppb:margin,trace_roots:roots})
}
fn verify_joint_coverage(selection:&SelectedMethods,required:&BTreeSet<provenance::CoveredEvent>,
    reference_pins:&BTreeSet<Hash>,retained:&RetainedArtifacts)->Result<()> {
    use provenance::CoverageKind as CK;
    let mut sum=math::Ratio::new(0,1)?;let mut covered=BTreeSet::new();let mut certificate_events=BTreeSet::new();
    for pin in &selection.coverage_pins {
        let certificate=provenance::CoverageCertificate::verify(selection,*pin,retained)?;
        if !certificate_events.insert(certificate.event){return Err(Error::Coverage);}
        if !certificate.covered.is_subset(required) || !certificate.covered.iter().any(|e|required.contains(e))
            {return Err(Error::Coverage);}
        for reference in reference_pins {let instrument=selection.instruments.get(reference).ok_or(Error::MissingIssuer)?;
            if instrument.coverage_event==certificate.event && (!certificate.covered.contains(&(CK::Reference,*reference))
                || !instrument.failure_probability.at_most(certificate.alpha)){return Err(Error::Coverage);}}
        covered.extend(certificate.covered);sum=sum.add(certificate.alpha)?;
    }
    for reference in reference_pins {let instrument=selection.instruments.get(reference).ok_or(Error::MissingIssuer)?;
        if !certificate_events.contains(&instrument.coverage_event){return Err(Error::Coverage);}}
    let allowed=math::Ratio::new(selection.confidence.denominator-selection.confidence.numerator,
        selection.confidence.denominator)?;
    if &covered!=required || !sum.at_most(allowed){return Err(Error::Coverage);}Ok(())
}
fn frequency_run(s:&SelectedMethods,raw:&[u8],held:&RetainedArtifacts)
    ->Result<(math::Interval,math::Interval,Hash,Hash)> {
    if hash(raw)!=s.frequency_raw_pin{return Err(Error::Digest);}let v=parse(raw)?;
    let m=exact(&v,&["format","subject_sha256","capture_start","capture_end","reference_start","reference_end"])?;
    if text(&m["format"])?!="b8-clock-frequency-trace-v1" || digest(&m["subject_sha256"])?!=s.subject{return Err(Error::Scope);}
    let start=trace::Capture::parse(&m["capture_start"],s)?;let end=trace::Capture::parse(&m["capture_end"],s)?;
    if start.boot!=end.boot{return Err(Error::Lifecycle);}
    let counter=math::Interval::duration(start.inclusive,end.inclusive)?;
    let first=trace::External::parse(&m["reference_start"])?;let last=trace::External::parse(&m["reference_end"])?;
    provenance::external(s,&first,held)?;provenance::external(s,&last,held)?;
    let reference=math::Interval::duration(first.time,last.time)?;
    Ok((counter,reference,first.instrument,last.instrument))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn modeled_canonical_parser_rejects_duplicates_unknown_number_spellings_and_bounds() {
        assert_eq!(parse(br#"{"a":1,"a":1}"#),Err(Error::Canonical));
        assert!(parse(br#"{"a":1.0}"#).is_err());assert!(parse(br#"{ "a":1}"#).is_err());
        assert!(parse(&vec![b' ';MAX_OBJECT+1]).is_err());
        let v=parse(br#"{"a":1}"#).unwrap();assert!(exact(&v,&["b"]).is_err());
    }
    #[test] fn modeled_private_plan_enforces_count_and_every_object_hash() {
        let mut p=RetentionPlan::empty(2).unwrap();p.add([1;32]).unwrap();p.add([1;32]).unwrap();
        p.add([2;32]).unwrap();assert!(p.add([3;32]).is_err());assert_eq!(p.maximum_total_bytes().unwrap(),131072);
        let mut held=RetainedArtifacts{objects:BTreeMap::new(),total:0};let raw=br#"{"a":1}"#;
        assert!(held.insert([1;32],raw,2).is_err());held.insert(hash(raw),raw,2).unwrap();
        assert_eq!(held.object(&hash(raw)).unwrap(),serde_json::json!({"a":1}));
    }
    #[test] fn modeled_success_has_no_normal_capability_or_default_issuer() {
        assert!(matches!(normal_default_selection(),Err(Error::MissingAcceptedPolicy)));
        let out=VerifiedExperiments{class:Class::ModeledTest,subject:[1;32],methods:[[2;32];6],
            frequency_upper_ppb:10,margin_ppb:20,trace_roots:[[3;32];6]};
        assert_eq!(out.normal_qualification(),Err(Error::MissingAcceptedPolicy));
    }
}
