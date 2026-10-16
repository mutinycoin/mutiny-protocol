//! Six fixed reducers. The signed finite trace is reduced, never a PASS report.
use super::*;
use trace::{Action,AuthCase,Boot,Capture,Event,ExperimentClass,Kind,LifecycleCase,Outcome,Record,StateRef,StorageCase};
use mutiny_consensus_v8::holdover_clock_v1::{Elapsed,ElapsedSource,HoldoverClock,ProtectedCheckpoint};
use std::sync::Arc;
use super::super::leap_policy::{LeapMemory,POLICY_VERSION};
use super::super::protected_clock_lineage_v1 as lineage;
fn provider(s:&SelectedMethods,index:u32)->Result<Hash> {
    s.provider_roots.get(index as usize).copied().ok_or(Error::Scope)
}
fn order(a:&Capture,b:&Capture)->Result<()> {
    if a.boot!=b.boot || b.active.lower<a.active.lower || b.active.upper<a.active.upper
        || b.inclusive.lower<a.inclusive.lower || b.inclusive.upper<a.inclusive.upper{return Err(Error::Lifecycle);}Ok(())
}
fn sample_gap(a:&Capture,b:&Capture,maximum:u64)->Result<()> {
    order(a,b)?;
    let gap=math::Interval::duration(a.inclusive,b.inclusive)?;
    if maximum==0 || gap.upper>maximum{return Err(Error::Coverage);}Ok(())
}
fn same_elapsed(a:&Capture,b:&Capture,maximum_gap:u64)->Result<()> {
    order(a,b)?;let active=math::Interval::duration(a.active,b.active)?;
    let inclusive=math::Interval::duration(a.inclusive,b.inclusive)?;
    let gap=active.lower.abs_diff(inclusive.upper).max(active.upper.abs_diff(inclusive.lower));
    if gap>maximum_gap{return Err(Error::Lifecycle);}Ok(())
}
struct RecordedElapsed(Elapsed);
impl ElapsedSource for RecordedElapsed {fn read(&self)->Option<Elapsed>{Some(self.0)}}
fn boot_id(boot:&Boot)->u128 {match boot {
    Boot::Linux(id)=>u128::from_be_bytes(*id),Boot::Windows(record)=>u128::from_le_bytes(record[..16].try_into().expect("fixed boot record"))}}
#[derive(Clone,Copy)]
enum Observation {Unavailable,Floor(u64)}
struct EngineDocument {checkpoint:ProtectedCheckpoint,leap:LeapMemory,observation:Observation}
impl EngineDocument {
    fn parse(s:&SelectedMethods,pin:Hash,held:&RetainedArtifacts)->Result<Self> {
        let v=held.object(&pin)?;
        let m=exact(&v,&["format","subject_sha256","checkpoint_hex","leap_memory_hex","observation"])?;
        if text(&m["format"])?!="b8-clock-protected-engine-document-v1" || digest(&m["subject_sha256"])?!=s.subject{return Err(Error::Scope);}
        let raw=bytes(&m["checkpoint_hex"],ProtectedCheckpoint::LEN)?;
        let checkpoint=ProtectedCheckpoint::decode(&raw).map_err(|_|Error::Loss)?;
        if checkpoint.anchor().params!=s.profile{return Err(Error::Scope);}
        let raw=bytes(&m["leap_memory_hex"],27)?;
        let leap=LeapMemory::from_protected_document(&raw).map_err(|_|Error::Leap)?;
        if checkpoint.anchor().leap.policy!=POLICY_VERSION
            || checkpoint.anchor().leap.view!=leap.view(Some(checkpoint.anchor().lower_ms)){return Err(Error::Leap);}
        let o=&m["observation"];let observation=match text(&o["kind"])? {
            "unavailable"=>{exact(o,&["kind"])?;Observation::Unavailable},
            "floor"=>{exact(o,&["kind","floor_ms"])?;Observation::Floor(number(&o["floor_ms"])?)},_=>return Err(Error::Encoding)
        };Ok(Self{checkpoint,leap,observation})
    }
    /// Four conservative capture corners use the ACTUAL inherited engine,
    /// original anchor, full gap ledger and complete leap memory. These temporary
    /// deterministic engines never enter a runtime factory or issue time.
    fn interval(&self,c:&Capture)->Result<Option<math::Interval>> {
        let mut lower=u64::MAX;let mut upper=0;
        for active in [c.active.lower,c.active.upper] {for inclusive in [c.inclusive.lower,c.inclusive.upper] {
            let clock=HoldoverClock::new(self.checkpoint.anchor().params.clone(),Arc::new(RecordedElapsed(
                Elapsed{monotonic_ns:active,boottime_ns:inclusive,boot_id:boot_id(&c.boot)}))).map_err(|_|Error::Loss)?;
            let view=self.leap.view(Some(self.checkpoint.anchor().lower_ms));
            if clock.restore_protected_same_boot(&self.checkpoint,POLICY_VERSION,view).is_err(){
                return match self.observation {Observation::Unavailable=>Ok(None),Observation::Floor(_)=>Err(Error::Loss)};
            }
            let Some((lo,hi))=clock.interval_ms() else{
                return match self.observation {Observation::Unavailable=>Ok(None),Observation::Floor(_)=>Err(Error::Loss)};
            };
            lower=lower.min(lo.checked_mul(1_000_000).ok_or(Error::Arithmetic)?);
            upper=upper.max(hi.checked_mul(1_000_000).ok_or(Error::Arithmetic)?);
        }}
        match self.observation {
            Observation::Unavailable=>Ok(None),
            Observation::Floor(floor)=>{
                if floor.checked_mul(1_000_000).ok_or(Error::Arithmetic)?>lower
                    || floor>self.checkpoint.anchor().high_water_ms{return Err(Error::Loss);}
                Ok(Some(math::Interval::new(lower,upper)?))
            }
        }
    }
    fn same_anchor(&self,other:&Self)->bool {
        let a=self.checkpoint.anchor();let b=other.checkpoint.anchor();
        a.params==b.params && a.at==b.at && a.lower_ms==b.lower_ms && a.upper_ms==b.upper_ms
    }
}
fn contains(outer:math::Interval,inner:math::Interval)->Result<()> {
    if outer.lower>inner.lower || outer.upper<inner.upper{return Err(Error::Coverage);}Ok(())
}
pub(super) fn reduce(s:&SelectedMethods,m:&trace::Method,index:&trace::Index,events:&[Event],held:&RetainedArtifacts)->Result<u64> {
    if events.len()!=m.expected_events || events.is_empty(){return Err(Error::Sequence);}
    match m.kind {
        Kind::Precision=>precision(s,events,held).map(|()|0),Kind::Lifecycle=>lifecycle(s,events,held),
        Kind::Authentication=>authentication(s,m,index,events,held).map(|()|0),Kind::Loss=>loss(s,m,events,held),
        Kind::Leap=>leap(s,m,index,events,held).map(|()|0),Kind::Storage=>storage(s,m,events,held).map(|()|0)
    }
}
fn precision(s:&SelectedMethods,events:&[Event],held:&RetainedArtifacts)->Result<()> {
    let mut seen=BTreeSet::new();
    for e in events {let Record::Precision{provider:index,update,printed,exponent,delay,dispersion,before,after,external}=&e.record else{return Err(Error::Precision);};
        provider(s,*index)?;seen.insert(*index);same_elapsed(before,after,s.maximum_gap_ns)?;
        provenance::external(s,external,held)?;
        let v=held.object(update)?;
        let r=exact(&v,&["format","subject_sha256","provider_index","precision_exponent","root_delay_fixed32","root_dispersion_fixed32","printed_ascii_hex","arithmetic"])?;
        if text(&r["format"])?!="b8-clock-source-update-v1" || digest(&r["subject_sha256"])?!=s.subject
            || u32n(&r["provider_index"])?!=*index || r["precision_exponent"].as_i64()!=Some(*exponent)
            || r["root_delay_fixed32"].as_i64()!=Some(*delay) || r["root_dispersion_fixed32"].as_i64()!=Some(*dispersion)
            || bytes(&r["printed_ascii_hex"],8192)?!=*printed{return Err(Error::Precision);}
        // A selected public producer prints this fixed local grammar, rather
        // than silently interpreting arbitrary chrony/different backend output.
        let expected=format!("precision_exponent={exponent}\nroot_delay_fixed32={delay}\nroot_dispersion_fixed32={dispersion}\n");
        if printed.as_slice()!=expected.as_bytes() || math::precision_ns(*exponent)?>s.precision_ns || *dispersion<0 {return Err(Error::Precision);}
        let raw=canonical(&r["arithmetic"])?;
        let sign=if *exponent<0 {"negative"} else {"nonnegative"};
        if r["arithmetic"]["precision_sign"].as_str()!=Some(sign)
            || r["arithmetic"]["precision_magnitude"].as_u64()!=Some(exponent.unsigned_abs())
            || r["arithmetic"]["root_delay_signed_fixed32"].as_u64()!=u64::try_from(*delay).ok()
            || r["arithmetic"]["root_dispersion_signed_fixed32"].as_u64()!=u64::try_from(*dispersion).ok(){return Err(Error::Precision);}
        let interval=mutiny_clock_native_nts_v1::reconstruct_diagnostic_interval(&raw,&s.acquisition.bounds)
            .map_err(|_|Error::Precision)?.view();
        if interval.upper_posix_ns<interval.lower_posix_ns || interval.upper_posix_ns-interval.lower_posix_ns
            >s.acquisition.bounds.maximum_interval_uncertainty_ns.checked_mul(2).ok_or(Error::Arithmetic)? {return Err(Error::Precision);}
        let represented=math::Interval::new(interval.lower_posix_ns,interval.upper_posix_ns)?;
        contains(represented,external.time)?;
    }
    if seen.len()!=s.provider_roots.len(){return Err(Error::Coverage);}Ok(())
}
fn lifecycle(s:&SelectedMethods,events:&[Event],held:&RetainedArtifacts)->Result<u64> {
    let mut pending:BTreeMap<(LifecycleCase,Hash),(Capture,math::Interval,Hash)>=BTreeMap::new();
    let mut covered=BTreeSet::new();let mut maximum_run=0;
    for e in events {let Record::Lifecycle{begin,case,cell,capture,external,lineage}=&e.record else{return Err(Error::Lifecycle);};
        if !s.envelope.environment_cells.contains(cell){return Err(Error::Scope);}provenance::external(s,external,held)?;
        let document=EngineDocument::parse(s,*lineage,held)?;
        if *begin {
            if pending.insert((*case,*cell),(capture.clone(),external.time,*lineage)).is_some(){return Err(Error::Sequence);}
        } else {
            let (start,reference,old)=pending.remove(&(*case,*cell)).ok_or(Error::Sequence)?;
            let old=EngineDocument::parse(s,old,held)?;
            let restarted=capture.boot!=start.boot || *case==LifecycleCase::Restore || *case==LifecycleCase::Migration;
            let current=document.interval(capture)?;
            if restarted {
                // Cross-boot/rollback/migration cannot preserve the old eligible
                // anchor. New calibration is a separately authenticated trace.
                if document.same_anchor(&old) && current.is_some(){return Err(Error::Lifecycle);}
            } else {
                order(&start,capture)?;
                let active=math::Interval::duration(start.active,capture.active)?;
                let inclusive=math::Interval::duration(start.inclusive,capture.inclusive)?;
                let reference=math::Interval::duration(reference,external.time)?;
                let bound=math::frequency_upper(inclusive,reference,1)?;
                maximum_run=maximum_run.max(bound);
                let gap=active.lower.abs_diff(inclusive.upper).max(active.upper.abs_diff(inclusive.lower));
                if gap>s.maximum_gap_ns && document.same_anchor(&old) && current.is_some(){return Err(Error::Lifecycle);}
                if let Some(range)=current {contains(range,external.time)?;}
            }
            covered.insert((*case,*cell));
        }
    }
    if !pending.is_empty() || covered!=s.lifecycle_cases{return Err(Error::Coverage);}Ok(maximum_run)
}
fn authentication(s:&SelectedMethods,m:&trace::Method,trace_index:&trace::Index,events:&[Event],held:&RetainedArtifacts)->Result<()> {
    let mut connections=BTreeMap::new();let mut requests=BTreeSet::new();let mut covered=BTreeSet::new();
    for e in events {match &e.record {
        Record::Ke{provider:index,connection,tls,chain,root,tls_code,aead,records,capture}=>{
            if provider(s,*index)?!=*root || !s.tls_codes.contains(tls_code) || !s.aead_codes.contains(aead)
                || connections.insert(*connection,(*index,capture.clone())).is_some(){return Err(Error::Authentication);}
            // Exact public artifacts of the selected acquisition producer; they
            // are committed by its authenticated top trace receipt, not raw codes.
            for pin in [tls,chain,root,records]{held.raw(pin)?;}
        }
        Record::Exchange{provider:index,connection,request,case,request_public,response_public,receipt,result,capture}=>{
            let (known,before)=connections.get(connection).ok_or(Error::Authentication)?;
            if known!=index{return Err(Error::Scope);}order(before,capture)?;
            // Replay TEST records may intentionally repeat the exact request
            // identity; only the refusal case may do so and it cannot succeed.
            let fresh=requests.insert((*index,*request));
            if !fresh && *case!=AuthCase::Replay{return Err(Error::Authentication);}
            let expected=s.authentication_results.get(case).ok_or(Error::Scope)?;
            if expected!=result || (*case!=AuthCase::Valid && *result==s.success_result){return Err(Error::Authentication);}
            held.raw(request_public)?;held.raw(response_public)?;
            provenance::event_receipt(s,e,*receipt,trace_index,m,held)?;covered.insert((*index,*case));
        }
        _=>return Err(Error::Authentication)
    }}
    if covered!=s.authentication_cases{return Err(Error::Coverage);}Ok(())
}
fn loss(s:&SelectedMethods,m:&trace::Method,events:&[Event],held:&RetainedArtifacts)->Result<u64> {
    let mut start:Option<(Hash,Capture,math::Interval)>=None;let mut last:Option<Capture>=None;
    let mut original:Option<EngineDocument>=None;let mut last_sequence=None;let mut finished=false;let mut samples=0usize;
    let mut healthy_samples=0usize;let mut maximum_run=0;
    for e in events {match &e.record {
        Record::Loss{disconnect:true,set,capture,external}=>{
            if start.is_some() || finished{return Err(Error::Sequence);}held.raw(set)?;provenance::external(s,external,held)?;
            start=Some((*set,capture.clone(),external.time));last=Some(capture.clone());
        }
        Record::LossSample{capture,external,protected}=>{
            if start.is_none() || finished{return Err(Error::Sequence);}provenance::external(s,external,held)?;
            let previous=last.as_ref().ok_or(Error::Sequence)?;
            sample_gap(previous,capture,m.maximum_sample_gap_ns)?;
            let record=EngineDocument::parse(s,*protected,held)?;
            if let Some(old)=&original {if !old.same_anchor(&record){return Err(Error::Loss);}} else {original=Some(EngineDocument::parse(s,*protected,held)?);}
            let seq=record.checkpoint.anchor().sequence;
            if last_sequence.is_some_and(|old|seq<=old){return Err(Error::Sequence);}last_sequence=Some(seq);
            if let Some(range)=record.interval(capture)? {contains(range,external.time)?;healthy_samples+=1;}
            else {
                let age=capture.inclusive.lower.checked_sub(record.checkpoint.anchor().at.boottime_ns).ok_or(Error::Loss)?;
                let horizon=record.checkpoint.anchor().validity_horizon_ms.checked_mul(1_000_000).ok_or(Error::Arithmetic)?;
                // Unavailability is acceptable only AFTER the inherited age
                // horizon. A never-qualified/early-refusing engine is no
                // positive holdover experiment, despite safe refusal.
                if age<=horizon{return Err(Error::Loss);}
            }
            // Expiration remains unavailable; the trace cannot create a fresh
            // calibration while external time is disconnected.
            last=Some(capture.clone());samples=samples.checked_add(1).ok_or(Error::Bound)?;
        }
        Record::Loss{disconnect:false,set,capture,external}=>{
            let (expected,begin,reference)=start.as_ref().ok_or(Error::Sequence)?;
            if finished || expected!=set || samples==0 || healthy_samples==0{return Err(Error::Loss);}provenance::external(s,external,held)?;
            sample_gap(last.as_ref().ok_or(Error::Sequence)?,capture,m.maximum_sample_gap_ns)?;
            let elapsed=math::Interval::duration(begin.inclusive,capture.inclusive)?;
            let actual=math::Interval::duration(*reference,external.time)?;
            if actual.lower<s.minimum_holdover_ns || elapsed.lower<s.minimum_holdover_ns{return Err(Error::Loss);}
            maximum_run=maximum_run.max(math::frequency_upper(elapsed,actual,s.minimum_holdover_ns)?);
            finished=true;
        }
        _=>return Err(Error::Loss)
    }}if !finished{return Err(Error::Coverage);}Ok(maximum_run)
}
fn leap(s:&SelectedMethods,m:&trace::Method,trace_index:&trace::Index,events:&[Event],held:&RetainedArtifacts)->Result<()> {
    let mut references=BTreeMap::new();let mut announcements=BTreeSet::new();let mut samples=BTreeSet::new();
    for e in events {match &e.record {
        Record::LeapReference{reference,external}=>{
            provenance::external(s,external,held)?;
            let v=held.object(reference)?;let r=exact(&v,&["format","subject_sha256","boundary_posix_ms","kind"])?;
            if text(&r["format"])?!="b8-clock-reference-leap-v1" || digest(&r["subject_sha256"])?!=s.subject{return Err(Error::Scope);}
            let boundary=number(&r["boundary_posix_ms"])?;
            if !super::super::leap_policy::is_month_start(boundary) || !matches!(text(&r["kind"])?,"insert"|"delete")
                || references.insert(*reference,(boundary,text(&r["kind"])?.to_owned())).is_some(){return Err(Error::Leap);}
        }
        Record::LeapAnnouncement{provider:index,reference,wire,receipt,..}=>{
            provider(s,*index)?;let(_,kind)=references.get(reference).ok_or(Error::Leap)?;
            if s.leap_codes.get(kind)!=Some(wire){return Err(Error::Leap);}
            provenance::event_receipt(s,e,*receipt,trace_index,m,held)?;announcements.insert((*reference,*index));
        }
        Record::LeapSample{reference,capture,external,update,protected}=>{
            let(boundary,_)=references.get(reference).ok_or(Error::Leap)?;held.raw(update)?;
            provenance::external(s,external,held)?;let record=EngineDocument::parse(s,*protected,held)?;
            if let Some(range)=record.interval(capture)? {
                contains(range,external.time)?;
                let zone=mutiny_consensus_v8::holdover_clock_v1::leap_ambiguity_zone_ms(*boundary);
                let lo=zone.0.checked_mul(1_000_000).ok_or(Error::Arithmetic)?;
                let hi=zone.1.checked_mul(1_000_000).ok_or(Error::Arithmetic)?;
                if range.lower<=hi && range.upper>=lo{return Err(Error::Leap);}
            }
            samples.insert(*reference);
        }
        _=>return Err(Error::Leap)
    }}
    if references.is_empty() || samples.len()!=references.len(){return Err(Error::Coverage);}
    for reference in references.keys(){for index in 0..s.provider_roots.len(){
        if !announcements.contains(&(*reference,index as u32)){return Err(Error::Coverage);}
    }}Ok(())
}
struct StorageContinuity {
    identity:Hash,principal:Hash,filesystem:Hash,plan_digest:Hash,
    engine:lineage::DocumentaryEngine,before:Hash,intent:Hash,completion:Hash,
    state:StateRef,ambiguous:bool,
}
impl StorageContinuity {
    fn parse(expected_scope:&lineage::Scope,native:&Map<String,Value>,held:&RetainedArtifacts)->Result<Self> {
        let c=exact(&native["continuity"],&["format","scope","operation_identity_sha256","content_sha256",
            "request_hex","before_state_sha256","intent_state_sha256","completion_state_sha256"])?;
        if text(&c["format"])?!="b8-clock-storage-continuity-plan-v1" {return Err(Error::Storage);}
        let sc=exact(&c["scope"],&["genesis_sha256","network_sha256","rule_sha256","lineage_sha256"])?;
        let scope=lineage::Scope::selected_document(digest(&sc["genesis_sha256"])? ,digest(&sc["network_sha256"])? ,
            digest(&sc["rule_sha256"])? ,digest(&sc["lineage_sha256"])?);
        if &scope!=expected_scope{return Err(Error::Scope);}
        let before=digest(&c["before_state_sha256"])?;let intent=digest(&c["intent_state_sha256"])?;
        let completion=digest(&c["completion_state_sha256"])?;
        if before==intent || before==completion || intent==completion{return Err(Error::Storage);}
        let mut engine=lineage::DocumentaryEngine::from_document(&scope,held.raw(&before)?).map_err(|_|Error::Storage)?;
        let request_raw=bytes(&c["request_hex"],lineage::SNAPSHOT_MAX)?;
        let request=lineage::Request::decode(&request_raw).map_err(|_|Error::Storage)?;
        let op=request.operation().ok_or(Error::Storage)?;
        if op.identity()!=digest(&c["operation_identity_sha256"])? || op.content()!=digest(&c["content_sha256"])?
            {return Err(Error::Storage);}
        let lineage::Begin::Plan(plan)=engine.begin(request).map_err(|_|Error::Storage)? else{return Err(Error::Storage);};
        // The existing canonical lineage reducer checks exact expected sequence,
        // monotonic floor and operation conflict BEFORE making this plan. No
        // checkpoint with merely a positive sequence can substitute for it.
        if plan.before()!=held.raw(&before)? || plan.intent()!=held.raw(&intent)?
            || plan.completion()!=held.raw(&completion)? {return Err(Error::Storage);}
        Ok(Self{identity:digest(&native["retained_identity_sha256"])? ,principal:digest(&native["principal_record_sha256"])? ,
            filesystem:digest(&native["filesystem_sha256"])? ,plan_digest:hash(&canonical(&native["continuity"])?),
            engine,before,intent,completion,state:StateRef::Present(before),ambiguous:false})
    }
    fn matches(&self,native:&Map<String,Value>)->Result<()> {
        if self.identity!=digest(&native["retained_identity_sha256"])? || self.principal!=digest(&native["principal_record_sha256"])?
            || self.filesystem!=digest(&native["filesystem_sha256"])? || self.plan_digest!=hash(&canonical(&native["continuity"])? )
            {return Err(Error::Storage);}Ok(())
    }
    fn check_state(&self,state:StateRef)->Result<()> {
        match state {StateRef::Present(pin) if [self.before,self.intent,self.completion].contains(&pin)=>Ok(()),
            _=>Err(Error::Storage)}
    }
    fn reconcile(&mut self,after:StateRef,held:&RetainedArtifacts)->Result<()> {
        if after!=StateRef::Present(self.completion){return Err(Error::Storage);}
        if self.engine.reconcile_document(held.raw(&self.completion)?).map_err(|_|Error::Storage)?
            !=lineage::Reconcile::CompletionObserved || self.engine.frozen(){return Err(Error::Storage);}
        self.state=after;self.ambiguous=false;Ok(())
    }
}
fn storage(s:&SelectedMethods,m:&trace::Method,events:&[Event],held:&RetainedArtifacts)->Result<()> {
    let mut processes=BTreeMap::new();let mut states:BTreeMap<Hash,StorageContinuity>=BTreeMap::new();
    let mut frozen=BTreeSet::new();let mut dirty=BTreeSet::new();let mut synced=BTreeSet::new();let mut covered=BTreeSet::new();
    let mut fault_classes=BTreeSet::new();
    for e in events {match &e.record {
        Record::Process{process,principal}=>{
            let p=held.object(process)?;
            let p=exact(&p,&["format","subject_sha256","principal_sha256","native_identity_sha256","execution_sha256"])?;
            if text(&p["format"])?!="b8-clock-native-process-record-v1" || digest(&p["subject_sha256"])?!=s.subject
                || digest(&p["principal_sha256"])?!=*principal || digest(&p["execution_sha256"])?!=s.producer {return Err(Error::Storage);}
            held.raw(principal)?;held.raw(&digest(&p["native_identity_sha256"])?)?;
            if processes.insert(*process,*principal).is_some(){return Err(Error::Sequence);}
        }
        Record::StorageAction{process,case,action,object,before,after,outcome}=>{
            let principal=processes.get(process).ok_or(Error::Storage)?;
            let native=held.object(object)?;
            let native=exact(&native,&["format","subject_sha256","process_record_sha256","principal_record_sha256","retained_identity_sha256","filesystem_sha256","continuity"])?;
            if text(&native["format"])?!="b8-clock-retained-native-object-v1" || digest(&native["subject_sha256"])?!=s.subject
                || digest(&native["process_record_sha256"])?!=*process || digest(&native["principal_record_sha256"])?!=*principal {return Err(Error::Storage);}
            for name in ["principal_record_sha256","retained_identity_sha256","filesystem_sha256"]{held.raw(&digest(&native[name])?)?;}
            let identity=digest(&native["retained_identity_sha256"])?;
            if !states.contains_key(&identity){states.insert(identity,StorageContinuity::parse(&s.scope,native,held)?);}
            let continuity=states.get_mut(&identity).ok_or(Error::Storage)?;continuity.matches(native)?;
            // A different object-record digest cannot fork the same retained
            // native identity. Ambiguity keeps its pre-unknown state and plan.
            if *before!=continuity.state && !(continuity.ambiguous && *before==StateRef::Unknown)
                {return Err(Error::Storage);}
            let unknown=*outcome==Outcome::Unknown || *before==StateRef::Unknown || *after==StateRef::Unknown;
            let reconciling=continuity.ambiguous && *case==StorageCase::Reconcile && *action==Action::Reopen
                && *outcome==Outcome::Known(s.success_result) && matches!(after,StateRef::Present(_));
            if unknown && !reconciling {
                continuity.engine.unknown();continuity.ambiguous=true;frozen.insert(identity);continue;
            }
            let Outcome::Known(code)=outcome else{return Err(Error::Storage);};
            let success=*code==s.success_result;
            if !success && before!=after{return Err(Error::Storage);}
            let adversarial=matches!(case,StorageCase::Second|StorageCase::Ancestor|StorageCase::Journal|StorageCase::Restore);
            if adversarial && (success || before!=after){return Err(Error::Storage);}
            if frozen.contains(&identity) {
                if *case!=StorageCase::Reconcile || *action!=Action::Reopen || !success
                    || !matches!(after,StateRef::Present(_)){return Err(Error::Storage);}
                continuity.reconcile(*after,held)?;frozen.remove(&identity);dirty.remove(&identity);synced.remove(&identity);
            } else if success {
                continuity.check_state(*before)?;continuity.check_state(*after)?;
                match action {
                    Action::Write=>{dirty.insert(identity);synced.remove(&identity);}
                    Action::Sync=>{if !dirty.remove(&identity){return Err(Error::Storage);}synced.insert(identity);
                        if *after==StateRef::Present(continuity.intent){continuity.engine.intent_readback(held.raw(&continuity.intent)?).map_err(|_|Error::Storage)?;}}
                    Action::Rename=>{if !synced.contains(&identity){return Err(Error::Storage);}
                        if *after==StateRef::Present(continuity.completion){continuity.engine.completion_readback(held.raw(&continuity.completion)?).map_err(|_|Error::Storage)?;}}
                    Action::Close|Action::Reopen if dirty.contains(&identity)=>return Err(Error::Storage),_=>{}
                }
            }
            for state in [before,after] {if let StateRef::Present(pin)=state{held.raw(pin)?;}}
            continuity.state=*after;covered.insert(*case);
        }
        Record::Fault{boundary,class,external}=>{
            provenance::external(s,external,held)?;
            if *class!=m.required_class || (s.class==Class::AcceptedPhysical && *class==ExperimentClass::Simulated){return Err(Error::Scope);}
            // Boundary is typed and remains part of the exact selected event
            // schedule; evidence labels can never be promoted by the reducer.
            let _=boundary;fault_classes.insert(*class);
        }
        _=>return Err(Error::Storage)
    }}
    if !frozen.is_empty() || !dirty.is_empty() || covered!=s.storage_cases
        || !fault_classes.contains(&m.required_class) || states.values().any(|s|s.engine.frozen()) {return Err(Error::Coverage);}Ok(())
}

#[cfg(test)]
mod continuity_controls {
    use super::*;
    fn capture(at:u64)->Capture {
        Capture{boot:Boot::Linux([7;16]),active:math::Interval::new(at,at+2).unwrap(),
            inclusive:math::Interval::new(at,at+2).unwrap(),raw_span:2}
    }
    #[test] fn modeled_loss_final_tail_uses_full_outward_gap() {
        assert!(sample_gap(&capture(10),&capture(20),12).is_ok());
        assert_eq!(sample_gap(&capture(10),&capture(21),12),Err(Error::Coverage));
        assert_eq!(sample_gap(&capture(10),&capture(1_000_000),12),Err(Error::Coverage));
    }
    fn prepared()->(Map<String,Value>,RetainedArtifacts) {
        let scope=lineage::Scope::selected_document([1;32],[2;32],[3;32],[4;32]);
        let mut raw=b"MCLC4D01".to_vec();for id in [1,2,3,4]{raw.extend_from_slice(&[id;32]);}
        raw.extend_from_slice(&0u64.to_be_bytes());raw.extend_from_slice(&0u64.to_be_bytes());
        raw.push(0);raw.extend_from_slice(&0u16.to_be_bytes());
        let mut engine=lineage::DocumentaryEngine::from_document(&scope,&raw).unwrap();
        let op=lineage::Operation::authenticated_document([5;32],[6;32]).unwrap();
        let request=lineage::Request::invalidate_operation_floor(0,10,op).unwrap();
        let lineage::Begin::Plan(plan)=engine.begin(request.clone()).unwrap() else{panic!("new plan")};
        let mut held=RetainedArtifacts{objects:BTreeMap::new(),total:0};
        for document in [plan.before(),plan.intent(),plan.completion()] {
            held.insert(hash(&document),&document,32).unwrap();
        }
        let v=serde_json::json!({"retained_identity_sha256":hex::encode([8;32]),
            "principal_record_sha256":hex::encode([9;32]),"filesystem_sha256":hex::encode([10;32]),
            "continuity":{"format":"b8-clock-storage-continuity-plan-v1","scope":{
                "genesis_sha256":hex::encode([1;32]),"network_sha256":hex::encode([2;32]),
                "rule_sha256":hex::encode([3;32]),"lineage_sha256":hex::encode([4;32])},
                "operation_identity_sha256":hex::encode([5;32]),"content_sha256":hex::encode([6;32]),
                "request_hex":hex::encode(request.encode()),"before_state_sha256":hex::encode(hash(&plan.before())),
                "intent_state_sha256":hex::encode(hash(&plan.intent())),"completion_state_sha256":hex::encode(hash(&plan.completion()))}});
        (v.as_object().unwrap().clone(),held)
    }
    #[test] fn modeled_unknown_reconciliation_preserves_exact_operation_and_prior_state() {
        let (native,held)=prepared();let scope=lineage::Scope::selected_document([1;32],[2;32],[3;32],[4;32]);
        let mut c=StorageContinuity::parse(&scope,&native,&held).unwrap();
        let foreign=lineage::Scope::selected_document([12;32],[2;32],[3;32],[4;32]);
        assert!(matches!(StorageContinuity::parse(&foreign,&native,&held),Err(Error::Scope)));
        let prior=c.state;c.engine.unknown();c.ambiguous=true;
        assert!(c.reconcile(StateRef::Present(c.before),&held).is_err());
        assert!(c.reconcile(StateRef::Present(c.intent),&held).is_err());
        assert_eq!(c.state,prior);assert!(c.engine.frozen());
        c.reconcile(StateRef::Present(c.completion),&held).unwrap();
        assert!(!c.engine.frozen());assert_eq!(c.engine.sequence(),1);assert_eq!(c.engine.floor(),10);
        let mut conflict=native.clone();conflict["continuity"]["content_sha256"]=hex::encode([11;32]).into();
        assert!(StorageContinuity::parse(&scope,&conflict,&held).is_err());
        let mut wrong=native.clone();wrong["continuity"]["completion_state_sha256"]=wrong["continuity"]["before_state_sha256"].clone();
        assert!(StorageContinuity::parse(&scope,&wrong,&held).is_err());
    }
}
