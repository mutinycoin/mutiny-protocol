//! Bounded indexed stream and exhaustive event grammar, no recursive discovery.
use super::*;
use math::Interval;
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]
pub(super) enum Kind {Precision,Lifecycle,Authentication,Loss,Leap,Storage}
impl Kind {
    pub(super) fn index(self)->usize {self as usize}
    pub(super) fn obligation(self)->&'static str {match self {
        Self::Precision=>"source_precision",Self::Lifecycle=>"suspend_boot_virtualization",
        Self::Authentication=>"source_authentication",Self::Loss=>"external_time_loss",
        Self::Leap=>"leap_behavior",Self::Storage=>"storage_owner_lock"}}
    fn format(self)->&'static str {match self {
        Self::Precision=>"b8-clock-source-precision-trace-v1",Self::Lifecycle=>"b8-clock-lifecycle-trace-v1",
        Self::Authentication=>"b8-clock-nts-auth-trace-v1",Self::Loss=>"b8-clock-loss-trace-v1",
        Self::Leap=>"b8-clock-leap-trace-v1",Self::Storage=>"b8-clock-storage-trace-v1"}}
    fn algorithm(self)->&'static str {match self {
        Self::Precision=>"b8-clock-source-precision-check-v1",Self::Lifecycle=>"b8-clock-lifecycle-check-v1",
        Self::Authentication=>"b8-clock-nts-auth-check-v1",Self::Loss=>"b8-clock-loss-check-v1",
        Self::Leap=>"b8-clock-leap-check-v1",Self::Storage=>"b8-clock-storage-check-v1"}}
    fn parse(v:&Value)->Result<Self> {
        for k in [Self::Precision,Self::Lifecycle,Self::Authentication,Self::Loss,Self::Leap,Self::Storage] {
            if text(v)?==k.obligation(){return Ok(k);}
        }Err(Error::Encoding)
    }
}
#[derive(Clone,Debug,PartialEq,Eq)]
pub(super) enum Boot {Linux([u8;16]),Windows([u8;32])}
impl Boot {
    fn parse(v:&Value,quantum:u64)->Result<Self> {
        match text(&v["format"])? {
            "linux-boot-uuid-v1"=>{
                exact(v,&["format","uuid"])?;let s=text(&v["uuid"])?;
                if s.len()!=36 || [8,13,18,23].iter().any(|i|s.as_bytes()[*i]!=b'-')
                    || s.bytes().enumerate().any(|(i,b)| ![8,13,18,23].contains(&i)
                        && !(b.is_ascii_digit()||(b'a'..=b'f').contains(&b))) || quantum!=1 {return Err(Error::Encoding);}
                let mut id=[0;16];hex::decode_to_slice(s.replace('-',""),&mut id).map_err(|_|Error::Encoding)?;
                if id==[0;16]{return Err(Error::Scope);}Ok(Self::Linux(id))
            }
            "windows-class90-v1"=>{
                exact(v,&["format","record_hex"])?;let raw=bytes(&v["record_hex"],32)?;
                if raw.len()!=32 || quantum!=100{return Err(Error::Encoding);}
                let id:Hash=raw.try_into().map_err(|_|Error::Encoding)?;
                if id==[0;32]{return Err(Error::Scope);}Ok(Self::Windows(id))
            }
            _=>Err(Error::Encoding)
        }
    }
}
#[derive(Clone,Debug)]
pub(super) struct Capture {pub(super) boot:Boot,pub(super) active:Interval,
    pub(super) inclusive:Interval,pub(super) raw_span:u64}
impl Capture {
    pub(super) fn parse(v:&Value,s:&SelectedMethods)->Result<Self> {
        let m=exact(v,&["boot","active_before_ns","inclusive_ns","active_after_ns"])?;
        let a=number(&m["active_before_ns"])?;let b=number(&m["inclusive_ns"])?;let c=number(&m["active_after_ns"])?;
        let span=c.checked_sub(a).ok_or(Error::Arithmetic)?;
        if a==0 || b<a || span>s.maximum_span_ns || [a,b,c].iter().any(|n|n%s.quantum_ns!=0) {return Err(Error::Scope);}
        // Inclusive is read somewhere inside the active sandwich; its error
        // includes the ENTIRE sandwich span, not a synthesized exact midpoint.
        let inclusive=Interval::new(b.checked_sub(span).ok_or(Error::Arithmetic)?,
            b.checked_add(span).ok_or(Error::Arithmetic)?)?.widen(s.quantum_ns)?;
        Ok(Self{boot:Boot::parse(&m["boot"],s.quantum_ns)?,
            active:Interval::new(a,c)?.widen(s.quantum_ns)?,inclusive,raw_span:span})
    }
}
#[derive(Clone,Debug)]
pub(super) struct External {pub(super) time:Interval,pub(super) instrument:Hash}
impl External {
    pub(super) fn parse(v:&Value)->Result<Self> {
        let m=exact(v,&["lower_posix_ns","upper_posix_ns","uncertainty_event"])?;
        Ok(Self{time:Interval::new(number(&m["lower_posix_ns"])? ,number(&m["upper_posix_ns"])?)?,
            instrument:digest(&m["uncertainty_event"])?})
    }
}
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]
pub(super) enum LifecycleCase {Suspend,Hibernate,Pause,Restore,Migration,Jitter}
impl LifecycleCase {pub(super) fn parse(v:&Value)->Result<Self>{match text(v)? {
    "suspend"=>Ok(Self::Suspend),"hibernate"=>Ok(Self::Hibernate),"vm-pause"=>Ok(Self::Pause),
    "vm-snapshot-restore"=>Ok(Self::Restore),"vm-migration"=>Ok(Self::Migration),
    "loaded-read-jitter"=>Ok(Self::Jitter),_=>Err(Error::Encoding)}}}
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]
pub(super) enum AuthCase {Valid,WrongHost,WrongRoot,Tamper,Replay,Unavailable}
impl AuthCase {pub(super) fn parse(v:&Value)->Result<Self>{match text(v)? {
    "valid"=>Ok(Self::Valid),"wrong-host"=>Ok(Self::WrongHost),"wrong-root"=>Ok(Self::WrongRoot),
    "tampered-response"=>Ok(Self::Tamper),"replayed-response"=>Ok(Self::Replay),
    "unavailable-source"=>Ok(Self::Unavailable),_=>Err(Error::Encoding)}}}
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]
pub(super) enum StorageCase {Exclusive,Second,Ancestor,Journal,Restore,Reconcile}
impl StorageCase {pub(super) fn parse(v:&Value)->Result<Self>{match text(v)? {
    "exclusive-open"=>Ok(Self::Exclusive),"second-writer"=>Ok(Self::Second),
    "ancestor-substitution"=>Ok(Self::Ancestor),"journal-substitution"=>Ok(Self::Journal),
    "stale-restore"=>Ok(Self::Restore),"restart-reconcile"=>Ok(Self::Reconcile),_=>Err(Error::Encoding)}}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(super) enum Action {Open,Lock,Read,Write,Sync,Rename,Close,Reopen}
impl Action {fn parse(v:&Value)->Result<Self>{match text(v)? {
    "open"=>Ok(Self::Open),"lock"=>Ok(Self::Lock),"read"=>Ok(Self::Read),"write"=>Ok(Self::Write),
    "sync"=>Ok(Self::Sync),"rename"=>Ok(Self::Rename),"close"=>Ok(Self::Close),"reopen"=>Ok(Self::Reopen),_=>Err(Error::Encoding)}}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(super) enum StateRef {Present(Hash),Absent,Unknown}
impl StateRef {fn parse(v:&Value)->Result<Self>{match text(&v["kind"])? {
    "present"=>{exact(v,&["kind","sha256"])?;Ok(Self::Present(digest(&v["sha256"])?))},
    "absent"=>{exact(v,&["kind"])?;Ok(Self::Absent)},"unknown"=>{exact(v,&["kind"])?;Ok(Self::Unknown)},_=>Err(Error::Encoding)}}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(super) enum Outcome {Known(u32),Unknown}
impl Outcome {fn parse(v:&Value)->Result<Self>{match text(&v["kind"])? {
    "known"=>{exact(v,&["kind","native_result_code"])?;Ok(Self::Known(u32n(&v["native_result_code"])?))},
    "unknown"=>{exact(v,&["kind"])?;Ok(Self::Unknown)},_=>Err(Error::Encoding)}}}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub(super) enum Boundary {BeforeWrite,BeforeSync,BeforeAck,BeforeReopen}
impl Boundary {fn parse(v:&Value)->Result<Self>{match text(v)? {
    "before-write"=>Ok(Self::BeforeWrite),"after-write-before-sync"=>Ok(Self::BeforeSync),
    "after-sync-before-ack"=>Ok(Self::BeforeAck),"after-ack-before-reopen"=>Ok(Self::BeforeReopen),_=>Err(Error::Encoding)}}}
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]
pub(super) enum ExperimentClass {Simulated,Filesystem,PowerLoss}
impl ExperimentClass {fn parse(v:&Value)->Result<Self>{match text(v)? {
    "simulated"=>Ok(Self::Simulated),"native-filesystem"=>Ok(Self::Filesystem),
    "physical-power-loss"=>Ok(Self::PowerLoss),_=>Err(Error::Encoding)}}}
#[derive(Clone,Debug)]
pub(super) enum Record {
    Precision{provider:u32,update:Hash,printed:Vec<u8>,exponent:i64,delay:i64,dispersion:i64,
        before:Capture,after:Capture,external:External},
    Lifecycle{begin:bool,case:LifecycleCase,cell:Hash,capture:Capture,external:External,lineage:Hash},
    Ke{provider:u32,connection:Hash,tls:Hash,chain:Hash,root:Hash,tls_code:u16,aead:u16,records:Hash,capture:Capture},
    Exchange{provider:u32,connection:Hash,request:Hash,case:AuthCase,request_public:Hash,response_public:Hash,
        receipt:Hash,result:u32,capture:Capture},
    Loss{disconnect:bool,set:Hash,capture:Capture,external:External},
    LossSample{capture:Capture,external:External,protected:Hash},
    LeapReference{reference:Hash,external:External},
    LeapAnnouncement{provider:u32,reference:Hash,wire:u32,receipt:Hash,capture:Capture},
    LeapSample{reference:Hash,capture:Capture,external:External,update:Hash,protected:Hash},
    Process{process:Hash,principal:Hash},
    StorageAction{process:Hash,case:StorageCase,action:Action,object:Hash,before:StateRef,after:StateRef,outcome:Outcome},
    Fault{boundary:Boundary,class:ExperimentClass,external:External},
}
#[derive(Clone,Debug)]
pub(super) struct Event {pub(super) sequence:u64,pub(super) record:Record,pub(super) projection:Hash}
impl Event {
    fn parse(v:&Value,kind:Kind,s:&SelectedMethods)->Result<Self> {
        exact(v,&["sequence","record"])?;let r=&v["record"];
        let capture=|k:&str|Capture::parse(&r[k],s);let external=|k:&str|External::parse(&r[k]);
        let d=|k:&str|digest(&r[k]);let n=|k:&str|u32n(&r[k]);
        let record=match (kind,text(&r["kind"])?) {
            (Kind::Precision,"sample")=>{
                exact(r,&["kind","provider_index","update_sha256","printed_ascii_hex","precision_exponent",
                    "root_delay_fixed32","root_dispersion_fixed32","capture_before","capture_after","external"])?;
                Record::Precision{provider:n("provider_index")?,update:d("update_sha256")?,printed:bytes(&r["printed_ascii_hex"],8192)?,
                    exponent:r["precision_exponent"].as_i64().ok_or(Error::Encoding)?,delay:r["root_delay_fixed32"].as_i64().ok_or(Error::Encoding)?,
                    dispersion:r["root_dispersion_fixed32"].as_i64().ok_or(Error::Encoding)?,before:capture("capture_before")?,
                    after:capture("capture_after")?,external:external("external")?}
            }
            (Kind::Lifecycle,k @ ("begin"|"end"))=>{
                exact(r,&["kind","case","environment_cell","capture","external","lineage_record_sha256"])?;
                Record::Lifecycle{begin:k=="begin",case:LifecycleCase::parse(&r["case"])?,cell:d("environment_cell")?,
                    capture:capture("capture")?,external:external("external")?,lineage:d("lineage_record_sha256")?}
            }
            (Kind::Authentication,"ke")=>{
                exact(r,&["kind","provider_index","connection_id","tls_public_trace_sha256","certificate_chain_sha256",
                    "selected_root_sha256","negotiated_tls_wire","negotiated_aead_wire","ke_public_records_sha256","capture"])?;
                Record::Ke{provider:n("provider_index")?,connection:d("connection_id")?,tls:d("tls_public_trace_sha256")?,
                    chain:d("certificate_chain_sha256")?,root:d("selected_root_sha256")?,
                    tls_code:u16::try_from(n("negotiated_tls_wire")?).map_err(|_|Error::Encoding)?,
                    aead:u16::try_from(n("negotiated_aead_wire")?).map_err(|_|Error::Encoding)?,
                    records:d("ke_public_records_sha256")?,capture:capture("capture")?}
            }
            (Kind::Authentication,"exchange")=>{
                exact(r,&["kind","provider_index","connection_id","request_id","case","request_public_sha256",
                    "response_public_sha256","producer_receipt_sha256","native_result_code","capture"])?;
                Record::Exchange{provider:n("provider_index")?,connection:d("connection_id")?,request:d("request_id")?,
                    case:AuthCase::parse(&r["case"])?,request_public:d("request_public_sha256")?,response_public:d("response_public_sha256")?,
                    receipt:d("producer_receipt_sha256")?,result:n("native_result_code")?,capture:capture("capture")?}
            }
            (Kind::Loss,k @ ("disconnect"|"reconnect"))=>{
                exact(r,&["kind","source_set_sha256","capture","external"])?;
                Record::Loss{disconnect:k=="disconnect",set:d("source_set_sha256")?,capture:capture("capture")?,external:external("external")?}
            }
            (Kind::Loss,"sample")=>{
                exact(r,&["kind","capture","external","protected_record_sha256"])?;
                Record::LossSample{capture:capture("capture")?,external:external("external")?,protected:d("protected_record_sha256")?}
            }
            (Kind::Leap,"reference")=>{
                exact(r,&["kind","reference_event_sha256","external"])?;
                Record::LeapReference{reference:d("reference_event_sha256")?,external:external("external")?}
            }
            (Kind::Leap,"announcement")=>{
                exact(r,&["kind","provider_index","reference_event_sha256","announcement_wire","producer_receipt_sha256","capture"])?;
                Record::LeapAnnouncement{provider:n("provider_index")?,reference:d("reference_event_sha256")?,wire:n("announcement_wire")?,
                    receipt:d("producer_receipt_sha256")?,capture:capture("capture")?}
            }
            (Kind::Leap,"sample")=>{
                exact(r,&["kind","reference_event_sha256","capture","external","kernel_update_sha256","protected_record_sha256"])?;
                Record::LeapSample{reference:d("reference_event_sha256")?,capture:capture("capture")?,external:external("external")?,
                    update:d("kernel_update_sha256")?,protected:d("protected_record_sha256")?}
            }
            (Kind::Storage,"process")=>{
                exact(r,&["kind","process_record_sha256","principal_record_sha256"])?;
                Record::Process{process:d("process_record_sha256")?,principal:d("principal_record_sha256")?}
            }
            (Kind::Storage,k @ ("action"|"uncertain-action"))=>{
                let (before,after,outcome)=if k=="action" {
                    exact(r,&["kind","process_record_sha256","case","action","native_object_sha256","before_state_sha256","after_state_sha256","native_result_code"])?;
                    (StateRef::Present(d("before_state_sha256")?),StateRef::Present(d("after_state_sha256")?),Outcome::Known(n("native_result_code")?))
                } else {
                    exact(r,&["kind","process_record_sha256","case","action","native_object_sha256","before_state","after_state","outcome"])?;
                    (StateRef::parse(&r["before_state"])?,StateRef::parse(&r["after_state"])?,Outcome::parse(&r["outcome"])?)
                };
                Record::StorageAction{process:d("process_record_sha256")?,case:StorageCase::parse(&r["case"])?,
                    action:Action::parse(&r["action"])?,object:d("native_object_sha256")?,before,after,outcome}
            }
            (Kind::Storage,"fault")=>{
                exact(r,&["kind","boundary","experiment_class","external"])?;
                Record::Fault{boundary:Boundary::parse(&r["boundary"])?,class:ExperimentClass::parse(&r["experiment_class"])?,external:external("external")?}
            }
            _=>return Err(Error::Encoding)
        };
        let mut projected=v.clone();if let Some(m)=projected["record"].as_object_mut(){m.remove("producer_receipt_sha256");}
        Ok(Self{sequence:number(&v["sequence"])? ,record,projection:hash(&canonical(&projected)?)})
    }
    pub(super) fn refs(&self)->Vec<Hash> {
        use Record::*;
        match &self.record {
            Precision{update,external,..}=>vec![*update,external.instrument],
            Lifecycle{cell,external,lineage,..}=>vec![*cell,external.instrument,*lineage],
            Ke{tls,chain,root,records,..}=>vec![*tls,*chain,*root,*records],
            Exchange{request_public,response_public,receipt,..}=>vec![*request_public,*response_public,*receipt],
            Loss{set,external,..}=>vec![*set,external.instrument],LossSample{external,protected,..}=>vec![external.instrument,*protected],
            LeapReference{reference,external}=>vec![*reference,external.instrument],
            LeapAnnouncement{reference,receipt,..}=>vec![*reference,*receipt],
            LeapSample{reference,external,update,protected,..}=>vec![*reference,external.instrument,*update,*protected],
            Process{process,principal}=>vec![*process,*principal],
            StorageAction{process,object,before,after,..}=>{
                let mut pins=vec![*process,*object];for state in [before,after]{if let StateRef::Present(p)=state{pins.push(*p);}}pins
            }
            Fault{external,..}=>vec![external.instrument]
        }
    }
    pub(super) fn external_refs(&self)->Vec<Hash> {
        use Record::*;match &self.record {
            Precision{external,..}|Lifecycle{external,..}|Loss{external,..}|LossSample{external,..}
                |LeapReference{external,..}|LeapSample{external,..}|Fault{external,..}=>vec![external.instrument],_=>vec![]
        }
    }
}
pub(super) struct Method {pub(super) pin:Hash,pub(super) kind:Kind,pub(super) subject:Hash,
    pub(super) environment:Hash,pub(super) experiment:Hash,pub(super) expected_events:usize,
    pub(super) maximum_artifacts:usize,pub(super) maximum_sample_gap_ns:u64,
    pub(super) event_projections:Vec<Hash>,pub(super) required_class:ExperimentClass}
impl Method {
    /// Exact selected schedule is digest-bound, never a per-event pass flag.
    /// Count/cadence are explicit measured method inputs, not invented defaults.
    pub(super) fn parse(raw:&[u8])->Result<Self> {
        let v=super::parse(raw)?;
        let m=exact(&v,&["format","obligation","algorithm","subject_sha256","environment_sha256","experiment_id",
            "expected_events","maximum_artifacts","maximum_sample_gap_ns","event_projections","required_evidence_class"])?;
        if text(&m["format"])?!="b8-clock-selected-method-v1"{return Err(Error::Encoding);}
        let kind=Kind::parse(&m["obligation"])?;
        if text(&m["algorithm"])?!=kind.algorithm(){return Err(Error::Scope);}
        let expected_events=usize::try_from(number(&m["expected_events"])?).map_err(|_|Error::Bound)?;
        let maximum_artifacts=usize::try_from(number(&m["maximum_artifacts"])?).map_err(|_|Error::Bound)?;
        let schedule=m["event_projections"].as_array().ok_or(Error::Encoding)?;
        if expected_events==0 || expected_events!=schedule.len() || maximum_artifacts==0
            || maximum_artifacts>MAX_OBJECTS{return Err(Error::Bound);}
        let mut projections=Vec::with_capacity(schedule.len());for pin in schedule{projections.push(digest(pin)?);}
        Ok(Self{pin:hash(raw),kind,subject:digest(&m["subject_sha256"])? ,environment:digest(&m["environment_sha256"])? ,
            experiment:digest(&m["experiment_id"])? ,expected_events,maximum_artifacts,
            maximum_sample_gap_ns:number(&m["maximum_sample_gap_ns"])? ,event_projections:projections,
            required_class:ExperimentClass::parse(&m["required_evidence_class"]) ?})
    }
}
struct ChunkRef {sequence:u32,pin:Hash,first:u64,count:u32}
pub(super) struct Index {pub(super) root:Hash,pub(super) pin:Hash,pub(super) header:Hash,
    pub(super) subject:Hash,pub(super) method:Hash,pub(super) environment:Hash,
    pub(super) experiment:Hash,pub(super) receipt:Hash,chunks:Vec<ChunkRef>,count:usize}
impl Index {
    pub(super) fn parse(raw:&[u8],method:&Method,subject:Hash)->Result<Self> {
        let v=super::parse(raw)?;let m=exact(&v,&["format","header","event_count","chunks","producer_receipt_sha256"])?;
        if text(&m["format"])?!="b8-clock-trace-index-v1"{return Err(Error::Encoding);}
        let h=exact(&m["header"],&["format","obligation","subject_sha256","method_sha256","environment_sha256","experiment_id"])?;
        if text(&h["format"])?!=method.kind.format() || text(&h["obligation"])?!=method.kind.obligation()
            || digest(&h["subject_sha256"])?!=subject || method.subject!=subject || digest(&h["method_sha256"])?!=method.pin
            || digest(&h["environment_sha256"])?!=method.environment || digest(&h["experiment_id"])?!=method.experiment {return Err(Error::Scope);}
        let count=usize::try_from(number(&m["event_count"])?).map_err(|_|Error::Bound)?;
        let cs=m["chunks"].as_array().ok_or(Error::Encoding)?;
        if count!=method.expected_events || cs.is_empty() || cs.len()>method.maximum_artifacts {return Err(Error::Bound);}
        let mut chunks=Vec::with_capacity(cs.len());let mut next=0u64;let mut unique=BTreeSet::new();
        for (i,c) in cs.iter().enumerate() {
            let c=exact(c,&["sequence","sha256","first_event","event_count"])?;
            let pin=digest(&c["sha256"])?;let events=u32n(&c["event_count"])?;
            if u32n(&c["sequence"])?!=u32::try_from(i).map_err(|_|Error::Bound)?
                || number(&c["first_event"])?!=next || events==0 || !unique.insert(pin){return Err(Error::Sequence);}
            chunks.push(ChunkRef{sequence:i as u32,pin,first:next,count:events});
            next=next.checked_add(u64::from(events)).ok_or(Error::Bound)?;
        }
        if next!=u64::try_from(count).map_err(|_|Error::Bound)? {return Err(Error::Sequence);}
        let mut projected=v.clone();projected.as_object_mut().ok_or(Error::Encoding)?.remove("producer_receipt_sha256");
        Ok(Self{root:hash(&canonical(&projected)?),pin:hash(raw),header:hash(&canonical(&m["header"])?),
            subject,method:method.pin,environment:method.environment,experiment:method.experiment,
            receipt:digest(&m["producer_receipt_sha256"])? ,chunks,count})
    }
    pub(super) fn plan(&self)->Result<RetentionPlan> {
        let mut p=RetentionPlan::empty(MAX_OBJECTS)?;
        for h in [self.pin,self.receipt,self.method,self.environment]{p.add(h)?;}
        for c in &self.chunks{p.add(c.pin)?;}Ok(p)
    }
    /// Full method-bounded event allocation and digest chain before reduction.
    pub(super) fn events(&self,held:&RetainedArtifacts,m:&Method,s:&SelectedMethods)->Result<Vec<Event>> {
        if self.count!=m.expected_events{return Err(Error::Bound);}
        let mut out=Vec::with_capacity(self.count);let mut previous=None;
        for c in &self.chunks {
            let v=held.object(&c.pin)?;let v=exact(&v,&["format","header_sha256","sequence","previous","events"])?;
            if text(&v["format"])?!="b8-clock-trace-chunk-v1" || digest(&v["header_sha256"])?!=self.header
                || u32n(&v["sequence"])?!=c.sequence{return Err(Error::Scope);}
            match previous {None=>{if text(&v["previous"])?!="first"{return Err(Error::Sequence);}},
                Some(pin)=>{if digest(&v["previous"])?!=pin{return Err(Error::Sequence);}}}
            let es=v["events"].as_array().ok_or(Error::Encoding)?;
            if es.len()!=c.count as usize{return Err(Error::Sequence);}
            if out.len() as u64!=c.first{return Err(Error::Sequence);}
            for raw in es {
                if out.len()>=self.count{return Err(Error::Bound);}
                let event=Event::parse(raw,m.kind,s)?;
                if event.sequence!=out.len() as u64 || event.projection!=m.event_projections[out.len()] {return Err(Error::Sequence);}
                out.push(event);
            }previous=Some(c.pin);
        }
        if out.len()!=self.count{return Err(Error::Sequence);}Ok(out)
    }
    pub(super) fn records_plan(&self,held:&RetainedArtifacts,m:&Method,s:&SelectedMethods)->Result<RetentionPlan> {
        let events=self.events(held,m,s)?;let mut plan=RetentionPlan::empty(m.maximum_artifacts)?;
        for pin in self.plan()?.digests(){plan.add(*pin)?;}
        for event in &events {for pin in event.refs(){
            // Records have finite typed roles. Referencing an enclosing object
            // or top receipt from any lower-level event is always a cycle.
            if pin==self.pin || pin==self.root || pin==self.receipt
                || self.chunks.iter().any(|c|c.pin==pin){return Err(Error::ReferenceCycle);}plan.add(pin)?;
        }}Ok(plan)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn method()->Method {
        Method{pin:[2;32],kind:Kind::Storage,subject:[1;32],environment:[3;32],experiment:[4;32],
            expected_events:2,maximum_artifacts:32,maximum_sample_gap_ns:1_000_000,
            event_projections:vec![[5;32],[6;32]],required_class:ExperimentClass::Simulated}
    }
    fn index()->Value {serde_json::json!({"format":"b8-clock-trace-index-v1","header":{
        "format":"b8-clock-storage-trace-v1","obligation":"storage_owner_lock","subject_sha256":hex::encode([1;32]),
        "method_sha256":hex::encode([2;32]),"environment_sha256":hex::encode([3;32]),"experiment_id":hex::encode([4;32])},
        "event_count":2,"chunks":[{"sequence":0,"sha256":hex::encode([7;32]),"first_event":0,"event_count":2}],
        "producer_receipt_sha256":hex::encode([8;32])})}
    #[test] fn modeled_index_projection_and_exact_contiguous_chunk_accounting() {
        let v=index();let a=Index::parse(&canonical(&v).unwrap(),&method(),[1;32]).unwrap();
        let mut other=v.clone();other["producer_receipt_sha256"]=hex::encode([9;32]).into();
        let b=Index::parse(&canonical(&other).unwrap(),&method(),[1;32]).unwrap();
        assert_eq!(a.root,b.root);assert_ne!(a.pin,b.pin);
        other["chunks"][0]["first_event"]=1.into();assert!(Index::parse(&canonical(&other).unwrap(),&method(),[1;32]).is_err());
        other=v.clone();other["chunks"][0]["event_count"]=0.into();assert!(Index::parse(&canonical(&other).unwrap(),&method(),[1;32]).is_err());
        other=v;other["header"]["subject_sha256"]=hex::encode([9;32]).into();assert!(Index::parse(&canonical(&other).unwrap(),&method(),[1;32]).is_err());
    }
    #[test] fn modeled_unknown_crash_is_a_variant_not_guessed_success() {
        assert_eq!(StateRef::parse(&serde_json::json!({"kind":"unknown"})).unwrap(),StateRef::Unknown);
        assert!(StateRef::parse(&serde_json::json!({"kind":"unknown","sha256":hex::encode([1;32])})).is_err());
        assert_eq!(Outcome::parse(&serde_json::json!({"kind":"unknown"})).unwrap(),Outcome::Unknown);
        assert!(Outcome::parse(&serde_json::json!({"kind":"unknown","native_result_code":0})).is_err());
        assert!(ExperimentClass::parse(&Value::from("powerloss-like-simulation")).is_err());
    }
}
