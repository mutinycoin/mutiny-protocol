//! Explicit TEST-only trace fixtures. Real canonical parsers/receipt signatures
//! and inherited clock reconstruction run over modeled acquisition/native data.
//! These fixtures never instantiate installation/current/physical authority.
use super::*;
use trace::{Kind,Method,Index};
use p256::ecdsa::signature::Signer;
use mutiny_consensus_v8::holdover_clock_v1::{ClockProfile,ControlledElapsed,HoldoverClock,SourceSample};
use super::super::leap_policy::{LeapMemory,LeapObservation,POLICY_VERSION};
use std::sync::Arc;
const UTC:u64=1_800_000_000_000;
fn h(pin:Hash)->Value {hex::encode(pin).into()}
const ABI:&str="clock_gettime:CLOCK_MONOTONIC/CLOCK_BOOTTIME/CLOCK_MONOTONIC:ns:v1";
fn modeled_subject()->Value {serde_json::json!({"MODELED_ONLY":"no deployment or sensor authority",
    "elapsed_abi_sha256":h(hash(&canonical(&serde_json::json!({"implementation":ABI})).unwrap()))})}
struct Fixture {s:SelectedMethods,held:RetainedArtifacts,key:p256::ecdsa::SigningKey,issuer:Hash,cell:Hash}
impl Fixture {
    fn raw(&mut self,raw:&[u8])->Hash {let pin=hash(raw);self.held.insert(pin,raw,512).unwrap();pin}
    fn object(&mut self,v:&Value)->Hash {self.raw(&canonical(v).unwrap())}
    fn sign(&mut self,mut v:Value,domain:&[u8])->Hash {
        v["subject_sha256"]=h(self.s.subject);v["producer_execution_sha256"]=h(self.s.producer);
        v["issuer_sha256"]=h(self.issuer);v["algorithm"]="p256-sha256-v1".into();
        let mut bytes=domain.to_vec();bytes.extend_from_slice(&canonical(&v).unwrap());
        let sig:p256::ecdsa::Signature=self.key.sign(&bytes);v["signature_der_hex"]=hex::encode(sig.to_der()).into();self.object(&v)
    }
    fn new()->Self {
        let mut held=RetainedArtifacts{objects:BTreeMap::new(),total:0};
        let leaf=|held:&mut RetainedArtifacts,raw:&[u8]|{let pin=hash(raw);held.insert(pin,raw,512).unwrap();pin};
        let producer=leaf(&mut held,b"MODELED selected public producer");
        let calibration=leaf(&mut held,b"MODELED calibration");let model=leaf(&mut held,b"MODELED class model");
        let review=leaf(&mut held,b"MODELED independent review");let cell=leaf(&mut held,b"MODELED supported cell");
        let key=p256::ecdsa::SigningKey::from_bytes((&[9u8;32]).into()).unwrap();
        let subject=leaf(&mut held,&canonical(&modeled_subject()).unwrap());
        let issuer_raw=canonical(&serde_json::json!({"format":"b8-clock-public-issuer-v1","subject_sha256":h(subject),
            "producer_execution_sha256":h(producer),"algorithm":"p256-sha256-v1",
            "sec1_public_key_hex":hex::encode(key.verifying_key().to_encoded_point(false))})).unwrap();
        let issuer=leaf(&mut held,&issuer_raw);
        let issuer_object=provenance::Issuer::parse_selected(&issuer_raw,issuer,subject,producer).unwrap();
        // Exact existing development profile: TEST inputs, never a production
        // selection/default. Option A's ratio is enforced against this selected P.
        let profile=ClockProfile{max_source_uncertainty_ms:200,max_calibration_half_width_ms:250,min_sources:3,
            max_faulty_sources:1,drift_bound_ppb:100_000,max_holdover_ms:10_000,max_interval_half_width_ms:1000,
            max_suspend_gap_ms:50,confirm_calibrations:1};
        let acquisition=mutiny_clock_native_nts_v1::Config{providers:(1..=3).map(|n|mutiny_clock_native_nts_v1::Provider{
            hostname:format!("source{n}.invalid"),operator:format!("Operator{n}"),key_establishment_port:4460,
            no_smear_profile_evidence_sha256:[n;32]}).collect(),timeout_seconds:10,
            bounds:mutiny_clock_native_nts_v1::AcquisitionBounds{era_lower_posix_ns:1_577_836_800_000_000_000,
                era_upper_posix_ns:2_208_988_800_000_000_000,era_context_sha256:"a".repeat(64),maximum_sampling_span_ns:250_000_000,
                wall_timestamp_uncertainty_ns:1_000_000,elapsed_drift_ppb:100_000,maximum_round_trip_ns:1_000_000_000,
                maximum_interval_uncertainty_ns:200_000_000}};
        let env=serde_json::json!({"format":"b8-clock-class-envelope-receipt-v1","subject_sha256":h(subject),
            "counter_model_sha256":h(model),"environment_cells":[h(cell)],"maximum_error_ppb":10,
            "calibration_provenance_sha256":h(calibration),"independent_model_review_sha256":h(review),
            "minimum_interval_ns":1,"maximum_interval_ns":10_000_000_000u64,"counter_nonlinearity_ppb":10,
            "producer_execution_sha256":h(producer),"issuer_sha256":h(issuer),"algorithm":"p256-sha256-v1","signature_der_hex":"00"});
        let env_raw=canonical(&env).unwrap();let env_pin=leaf(&mut held,&env_raw);
        let envelope=provenance::Envelope::parse_selected(&env_raw,env_pin).unwrap();
        let roots=(1..=3).map(|n|leaf(&mut held,format!("MODELED root{n}").as_bytes())).collect();
        let results=BTreeMap::from([(trace::AuthCase::Valid,0),(trace::AuthCase::WrongHost,1),(trace::AuthCase::WrongRoot,2),
            (trace::AuthCase::Tamper,3),(trace::AuthCase::Replay,4),(trace::AuthCase::Unavailable,5)]);
        let authentication_cases=results.keys().flat_map(|case|(0..3).map(move|provider|(provider,*case))).collect();
        let s=SelectedMethods{scope:super::super::protected_clock_lineage_v1::Scope::selected_document([1;32],[2;32],[3;32],[4;32]),
            class:Class::ModeledTest,subject,confidence:math::Ratio::new(999,1000).unwrap(),margin:math::Ratio::new(1,5).unwrap(),
            selected_drift_ppb:profile.drift_bound_ppb,quantum_ns:1,maximum_span_ns:250_000_000,precision_ns:1_000_000,
            minimum_holdover_ns:10_000_000_000,maximum_gap_ns:50_000_000,provider_roots:roots,producer,
            issuers:vec![issuer_object],methods:vec![],instruments:BTreeMap::new(),envelope,coverage_pins:vec![],profile,acquisition,
            lifecycle_cases:BTreeSet::from([(trace::LifecycleCase::Jitter,cell)]),authentication_cases,authentication_results:results,
            success_result:0,tls_codes:BTreeSet::from([0x304]),aead_codes:BTreeSet::from([15]),
            leap_codes:BTreeMap::from([("insert".into(),1),("delete".into(),2)]),storage_cases:BTreeSet::from([trace::StorageCase::Exclusive]),
            frequency_raw_pin:[2;32]};
        Self{s,held,key,issuer,cell}
    }
    fn capture(at:u64)->Value {serde_json::json!({"boot":{"format":"linux-boot-uuid-v1","uuid":"00000000-0000-0000-0000-000000000007"},
        "active_before_ns":at,"inclusive_ns":at,"active_after_ns":at})}
    fn reference(&mut self,at:u64)->Value {
        let calibration=self.s.envelope.calibration;let environment=self.cell;let instrument=self.s.envelope.instrument;
        let coverage=self.raw(b"MODELED reducer-only coverage; NOT full qualification");
        let pin=self.sign(serde_json::json!({"format":"b8-clock-reference-interval-receipt-v1",
            "instrument_sha256":h(instrument),"calibration_sha256":h(calibration),"environment_sha256":h(environment),
            "coverage_event_sha256":h(coverage),"failure_probability":{"numerator":1,"denominator":10000},
            "lower_posix_ns":at,"upper_posix_ns":at}),b"BUILD8-NATIVE-CLOCK-REFERENCE-INTERVAL-V1");
        let object=provenance::Instrument::parse_selected(self.held.raw(&pin).unwrap(),pin).unwrap();self.s.instruments.insert(pin,object);
        serde_json::json!({"lower_posix_ns":at,"upper_posix_ns":at,"uncertainty_event":h(pin)})
    }
    fn engine(&mut self,elapsed:&Arc<ControlledElapsed>,clock:&HoldoverClock,memory:&LeapMemory,seq:u64,available:bool)->Hash {
        let checkpoint=clock.protected_checkpoint(seq,POLICY_VERSION).unwrap();
        let observation=if available {serde_json::json!({"kind":"floor","floor_ms":clock.lower_bound_ms().unwrap()})}
            else{serde_json::json!({"kind":"unavailable"})};
        let _=elapsed;
        self.object(&serde_json::json!({"format":"b8-clock-protected-engine-document-v1","subject_sha256":h(self.s.subject),
            "checkpoint_hex":hex::encode(checkpoint.encode()),"leap_memory_hex":hex::encode(memory.protected_document()),"observation":observation}))
    }
    fn clock(&self)->(Arc<ControlledElapsed>,Arc<HoldoverClock>,LeapMemory) {
        let elapsed=ControlledElapsed::start(7);let clock=HoldoverClock::new(self.s.profile.clone(),elapsed.clone()).unwrap();
        let mut memory=LeapMemory::default();memory.observe(LeapObservation::Normal,Some((UTC-13,UTC+13)),true);
        clock.set_leap_view(memory.view(Some(UTC)));
        let samples=(0..3).map(|n|SourceSample{source:format!("TESTsource{n}"),authenticated:true,utc_ms:UTC,
            uncertainty_ms:13,at:elapsed.now()}).collect::<Vec<_>>();clock.calibrate(&samples).unwrap();
        (elapsed,clock,memory)
    }
    fn trace(&mut self,kind:Kind,records:Vec<Value>)->(Method,Index,Vec<trace::Event>) {
        let environment=self.object(&serde_json::json!({"format":"build8/native-nts/measurement-environment-v1",
            "obligation":kind.obligation(),"subject":modeled_subject(),"instrument_provenance_sha256":h(self.s.envelope.instrument)}));
        let mut events:Vec<Value>=records.into_iter().enumerate().map(|(i,record)|serde_json::json!({"sequence":i,"record":record})).collect();
        let projections=events.iter().map(|e|{let mut e=e.clone();e["record"].as_object_mut().unwrap().remove("producer_receipt_sha256");hash(&canonical(&e).unwrap())}).collect::<Vec<_>>();
        let obligation=kind.obligation();let formats=["b8-clock-source-precision-trace-v1","b8-clock-lifecycle-trace-v1","b8-clock-nts-auth-trace-v1",
            "b8-clock-loss-trace-v1","b8-clock-leap-trace-v1","b8-clock-storage-trace-v1"];
        let algorithms=["b8-clock-source-precision-check-v1","b8-clock-lifecycle-check-v1","b8-clock-nts-auth-check-v1",
            "b8-clock-loss-check-v1","b8-clock-leap-check-v1","b8-clock-storage-check-v1"];
        let method=self.object(&serde_json::json!({"format":"b8-clock-selected-method-v1","obligation":obligation,
            "algorithm":algorithms[kind.index()],"subject_sha256":h(self.s.subject),"environment_sha256":h(environment),"experiment_id":h([7;32]),
            "expected_events":events.len(),"maximum_artifacts":512,"maximum_sample_gap_ns":5_100_000_000u64,
            "event_projections":projections.iter().copied().map(h).collect::<Vec<_>>(),"required_evidence_class":"simulated"}));
        let method=Method::parse(self.held.raw(&method).unwrap()).unwrap();
        for (event,projection) in events.iter_mut().zip(projections) {
            if event["record"].get("producer_receipt_sha256").is_some(){let receipt=self.sign(serde_json::json!({
                "format":"b8-clock-event-receipt-v1","method_sha256":h(method.pin),"environment_sha256":h(environment),
                "experiment_id":h([7;32]),"event_projection_sha256":h(projection)}),b"BUILD8-NATIVE-CLOCK-MEASUREMENT-EVENT-RECEIPT-V1");
                event["record"]["producer_receipt_sha256"]=h(receipt);}
        }
        let header=serde_json::json!({"format":formats[kind.index()],"obligation":obligation,"subject_sha256":h(self.s.subject),
            "method_sha256":h(method.pin),"environment_sha256":h(environment),"experiment_id":h([7;32])});
        let chunk=self.object(&serde_json::json!({"format":"b8-clock-trace-chunk-v1","header_sha256":h(hash(&canonical(&header).unwrap())),
            "sequence":0,"previous":"first","events":events}));
        let mut index=serde_json::json!({"format":"b8-clock-trace-index-v1","header":header,"event_count":method.expected_events,
            "chunks":[{"sequence":0,"sha256":h(chunk),"first_event":0,"event_count":method.expected_events}],"producer_receipt_sha256":h([99;32])});
        let initial=Index::parse(&canonical(&index).unwrap(),&method,self.s.subject).unwrap();
        let receipt=self.sign(serde_json::json!({"format":"b8-clock-producer-receipt-v1","method_sha256":h(method.pin),
            "environment_sha256":h(environment),"trace_root_sha256":h(initial.root)}),b"BUILD8-NATIVE-CLOCK-MEASUREMENT-RECEIPT-V1");
        index["producer_receipt_sha256"]=h(receipt);let pin=self.object(&index);
        let index=Index::parse(self.held.raw(&pin).unwrap(),&method,self.s.subject).unwrap();
        provenance::trace_receipt(&self.s,&index,&method,&self.held).unwrap();
        let events=index.events(&self.held,&method,&self.s).unwrap();(method,index,events)
    }
}
fn precision_records(f:&mut Fixture)->Vec<Value> {
    let timestamp=|ns:u64|((1_800_000_000u64+2_208_988_800)<<32)
        +u64::try_from(u128::from(ns)*(1u128<<32)/1_000_000_000).unwrap();
    let raw_capture=|a:u64|serde_json::json!({"active_before_ns":a,"active_after_ns":a+10_000,
        "inclusive_ns":a,"boot_id_hex":format!("{:032x}",7)});
    let pair=|a:u64|serde_json::json!({"pre":raw_capture(a),"post":raw_capture(a+20_000)});
    let sent=timestamp(0);let received=timestamp(100_000_000);let midpoint=sent+(received-sent)/2;
    let arithmetic=serde_json::json!({"format":"build8/native-nts/raw-arithmetic-v1",
        "elapsed_abi":"clock_gettime:CLOCK_MONOTONIC/CLOCK_BOOTTIME/CLOCK_MONOTONIC:ns:v1",
        "sent_ntp_fixed32":sent,"received_ntp_fixed32":received,"before":pair(1_000_000_000),"after":pair(1_100_000_000),
        "remote_midpoint_ntp_fixed32":midpoint,"local_midpoint_ntp_fixed32":midpoint,"delay_signed_fixed32":(1u64<<32)/10,
        "root_delay_signed_fixed32":0,"root_dispersion_signed_fixed32":0,"precision_sign":"negative","precision_magnitude":20});
    let represented=mutiny_clock_native_nts_v1::reconstruct_diagnostic_interval(&canonical(&arithmetic).unwrap(),&f.s.acquisition.bounds).unwrap().view();
    let external=f.reference(represented.lower_posix_ns+(represented.upper_posix_ns-represented.lower_posix_ns)/2);
    let printed=b"precision_exponent=-20\nroot_delay_fixed32=0\nroot_dispersion_fixed32=0\n";
    let mut records=vec![];for provider in 0..3 {let update=f.object(&serde_json::json!({"format":"b8-clock-source-update-v1",
        "subject_sha256":h(f.s.subject),"provider_index":provider,"precision_exponent":-20,"root_delay_fixed32":0,
        "root_dispersion_fixed32":0,"printed_ascii_hex":hex::encode(printed),"arithmetic":arithmetic}));
        records.push(serde_json::json!({"kind":"sample","provider_index":provider,"update_sha256":h(update),
            "printed_ascii_hex":hex::encode(printed),"precision_exponent":-20,"root_delay_fixed32":0,"root_dispersion_fixed32":0,
            "capture_before":Fixture::capture(1_100_000_100),"capture_after":Fixture::capture(1_100_001_100),"external":external}));}
    records
}
fn lifecycle_records(f:&mut Fixture)->Vec<Value> {
    let (elapsed,clock,memory)=f.clock();
    let first=f.engine(&elapsed,&clock,&memory,1,true);elapsed.run(1000);let second=f.engine(&elapsed,&clock,&memory,2,true);
    let mut records=vec![];for (begin,at,pin)in [(true,1_000_001_000,first),(false,2_000_001_000,second)] {
        let external=f.reference(UTC*1_000_000+at-1_000_000_000);
        records.push(serde_json::json!({"kind":if begin{"begin"}else{"end"},"case":"loaded-read-jitter", "environment_cell":h(f.cell),
            "capture":Fixture::capture(at),"external":external,"lineage_record_sha256":h(pin)}));}
    records
}
fn authentication_records(f:&mut Fixture)->Vec<Value> {
    let public=f.raw(b"MODELED public TLS/NTS exchange");let mut records=vec![];
    for provider in 0..3 {let connection=[provider as u8+10;32];records.push(serde_json::json!({"kind":"ke","provider_index":provider,
        "connection_id":h(connection),"tls_public_trace_sha256":h(public),"certificate_chain_sha256":h(public),
        "selected_root_sha256":h(f.s.provider_roots[provider]),"negotiated_tls_wire":0x304,"negotiated_aead_wire":15,
        "ke_public_records_sha256":h(public),"capture":Fixture::capture(1_000_000_100)}));
        for (case,result) in [("valid",0),("wrong-host",1),("wrong-root",2),("tampered-response",3),("replayed-response",4),("unavailable-source",5)] {
            records.push(serde_json::json!({"kind":"exchange","provider_index":provider,"connection_id":h(connection),
                "request_id":h([provider as u8*10+result+30;32]),"case":case,"request_public_sha256":h(public),"response_public_sha256":h(public),
                "producer_receipt_sha256":h([99;32]),"native_result_code":result,"capture":Fixture::capture(1_000_001_100)}));}}
    records
}
fn loss_records(f:&mut Fixture)->Vec<Value> {
    let (elapsed,clock,memory)=f.clock();let set=f.raw(b"MODELED all sources disconnected");let mut records=vec![];
    let external=f.reference(UTC*1_000_000+1000);records.push(serde_json::json!({"kind":"disconnect","source_set_sha256":h(set),
        "capture":Fixture::capture(1_000_001_000),"external":external}));
    for (seq,delta)in [(1,1u64),(2,4000),(3,4000)] {elapsed.run(delta);let at=elapsed.now().boottime_ns+1000;
        let protected=f.engine(&elapsed,&clock,&memory,seq,true);let external=f.reference(UTC*1_000_000+at-1_000_000_000);
        records.push(serde_json::json!({"kind":"sample","capture":Fixture::capture(at),"external":external,"protected_record_sha256":h(protected)}));}
    let external=f.reference(UTC*1_000_000+10_001_001_000);records.push(serde_json::json!({"kind":"reconnect","source_set_sha256":h(set),
        "capture":Fixture::capture(11_001_001_000),"external":external}));
    records
}
fn leap_records(f:&mut Fixture)->Vec<Value> {
    let boundary=super::super::leap_policy::month_start_ms(super::super::leap_policy::month_index(UTC)+1).unwrap();
    let base=boundary-10_000;let elapsed=ControlledElapsed::start(7);let clock=HoldoverClock::new(f.s.profile.clone(),elapsed.clone()).unwrap();
    let mut memory=LeapMemory::default();memory.observe(LeapObservation::Insert,Some((base-13,base+13)),true);
    clock.set_leap_view(memory.view(Some(base)));
    clock.calibrate(&(0..3).map(|n|SourceSample{source:format!("TESTsource{n}"),authenticated:true,utc_ms:base,
        uncertainty_ms:13,at:elapsed.now()}).collect::<Vec<_>>()).unwrap();
    let reference=f.object(&serde_json::json!({"format":"b8-clock-reference-leap-v1","subject_sha256":h(f.s.subject),
        "boundary_posix_ms":boundary,"kind":"insert"}));let external=f.reference(base*1_000_000);
    let mut records=vec![serde_json::json!({"kind":"reference","reference_event_sha256":h(reference),"external":external})];
    for provider in 0..3 {records.push(serde_json::json!({"kind":"announcement","provider_index":provider,"reference_event_sha256":h(reference),
        "announcement_wire":1,"producer_receipt_sha256":h([99;32]),"capture":Fixture::capture(1_000_001_000)}));}
    let update=f.raw(b"MODELED kernel leap observation");elapsed.run(8000);
    let protected=f.engine(&elapsed,&clock,&memory,1,true);let external=f.reference((base+8000)*1_000_000+1000);
    records.push(serde_json::json!({"kind":"sample","reference_event_sha256":h(reference),"capture":Fixture::capture(9_000_001_000),
        "external":external,"kernel_update_sha256":h(update),"protected_record_sha256":h(protected)}));
    elapsed.run(1500);assert_eq!(clock.lower_bound_ms(),None);
    let protected=f.engine(&elapsed,&clock,&memory,2,false);let external=f.reference((base+9500)*1_000_000+1000);
    records.push(serde_json::json!({"kind":"sample","reference_event_sha256":h(reference),"capture":Fixture::capture(10_500_001_000),
        "external":external,"kernel_update_sha256":h(update),"protected_record_sha256":h(protected)}));
    records
}
fn storage_records(f:&mut Fixture)->Vec<Value> {
    use super::super::protected_clock_lineage_v1 as lineage;
    f.s.storage_cases=BTreeSet::from([trace::StorageCase::Exclusive,trace::StorageCase::Second,
        trace::StorageCase::Ancestor,trace::StorageCase::Journal,trace::StorageCase::Restore,trace::StorageCase::Reconcile]);
    let mut initial=b"MCLC4D01".to_vec();for id in [1,2,3,4]{initial.extend_from_slice(&[id;32]);}
    initial.extend_from_slice(&0u64.to_be_bytes());initial.extend_from_slice(&0u64.to_be_bytes());initial.push(0);initial.extend_from_slice(&0u16.to_be_bytes());
    let mut engine=lineage::DocumentaryEngine::from_document(&f.s.scope,&initial).unwrap();
    let op=lineage::Operation::authenticated_document([5;32],[6;32]).unwrap();
    let request=lineage::Request::invalidate_operation_floor(0,10,op).unwrap();
    let lineage::Begin::Plan(plan)=engine.begin(request.clone()).unwrap() else{panic!("new plan")};
    let before=f.raw(&plan.before());let intent=f.raw(&plan.intent());let completion=f.raw(&plan.completion());
    let principal=f.raw(b"MODELED observed principal");let identity=f.raw(b"MODELED retained native object identity");
    let process_identity=f.raw(b"MODELED native process identity");let filesystem=f.raw(b"MODELED native filesystem");
    let process=f.object(&serde_json::json!({"format":"b8-clock-native-process-record-v1","subject_sha256":h(f.s.subject),
        "principal_sha256":h(principal),"native_identity_sha256":h(process_identity),"execution_sha256":h(f.s.producer)}));
    let object=f.object(&serde_json::json!({"format":"b8-clock-retained-native-object-v1","subject_sha256":h(f.s.subject),
        "process_record_sha256":h(process),"principal_record_sha256":h(principal),"retained_identity_sha256":h(identity),"filesystem_sha256":h(filesystem),
        "continuity":{"format":"b8-clock-storage-continuity-plan-v1","scope":{"genesis_sha256":h([1;32]),"network_sha256":h([2;32]),
            "rule_sha256":h([3;32]),"lineage_sha256":h([4;32])},"operation_identity_sha256":h([5;32]),"content_sha256":h([6;32]),
            "request_hex":hex::encode(request.encode()),"before_state_sha256":h(before),"intent_state_sha256":h(intent),"completion_state_sha256":h(completion)}}));
    let action=|case:&str,action:&str,b:Hash,a:Hash,result:u32|serde_json::json!({"kind":"action","process_record_sha256":h(process),
        "case":case,"action":action,"native_object_sha256":h(object),"before_state_sha256":h(b),"after_state_sha256":h(a),"native_result_code":result});
    let mut records=vec![serde_json::json!({"kind":"process","process_record_sha256":h(process),"principal_record_sha256":h(principal)}),
        action("exclusive-open","open",before,before,0),serde_json::json!({"kind":"uncertain-action","process_record_sha256":h(process),
            "case":"exclusive-open","action":"write","native_object_sha256":h(object),"before_state":{"kind":"present","sha256":h(before)},
            "after_state":{"kind":"unknown"},"outcome":{"kind":"unknown"}}),
        serde_json::json!({"kind":"uncertain-action","process_record_sha256":h(process),"case":"restart-reconcile","action":"reopen",
            "native_object_sha256":h(object),"before_state":{"kind":"unknown"},"after_state":{"kind":"present","sha256":h(completion)},
            "outcome":{"kind":"known","native_result_code":0}})];
    for case in ["second-writer","ancestor-substitution","journal-substitution","stale-restore"]{records.push(action(case,"open",completion,completion,1));}
    let external=f.reference(UTC*1_000_000);records.push(serde_json::json!({"kind":"fault","boundary":"after-sync-before-ack",
        "experiment_class":"simulated","external":external}));
    records
}
#[test]
fn modeled_precision_full_trace_and_wrong_printed_value_refusal() {
    let mut f=Fixture::new();let mut records=precision_records(&mut f);
    let (method,index,events)=f.trace(Kind::Precision,records.clone());
    assert_eq!(reducers::reduce(&f.s,&method,&index,&events,&f.held),Ok(0));
    records[0]["printed_ascii_hex"]=hex::encode(b"precision_exponent=0\n").into();
    let (method,index,events)=f.trace(Kind::Precision,records);
    assert!(reducers::reduce(&f.s,&method,&index,&events,&f.held).is_err());
}
#[test]
fn modeled_lifecycle_full_trace_and_eligible_same_anchor_crossboot_refusal() {
    let mut f=Fixture::new();let mut records=lifecycle_records(&mut f);
    let (method,index,events)=f.trace(Kind::Lifecycle,records.clone());
    let bound=reducers::reduce(&f.s,&method,&index,&events,&f.held).unwrap();assert!(bound<=1000);
    // A future native profile retains the adopted reserve against every run,
    // rather than allowing a short-run result between P-M and P.
    assert!(math::check_margin(80_001,100_000,f.s.margin).is_err());
    records[1]["capture"]["boot"]["uuid"]="00000000-0000-0000-0000-000000000008".into();
    // Wrong boot with a claimed healthy old anchor fails actual engine restore.
    let (method,index,events)=f.trace(Kind::Lifecycle,records);
    assert!(reducers::reduce(&f.s,&method,&index,&events,&f.held).is_err());
}
#[test]
fn modeled_authentication_all_six_cases_all_providers_and_forged_success_refusal() {
    let mut f=Fixture::new();let mut records=authentication_records(&mut f);
    let (method,index,events)=f.trace(Kind::Authentication,records.clone());
    assert_eq!(reducers::reduce(&f.s,&method,&index,&events,&f.held),Ok(0));
    records[2]["native_result_code"]=0.into();let (method,index,events)=f.trace(Kind::Authentication,records);
    assert!(reducers::reduce(&f.s,&method,&index,&events,&f.held).is_err());
}
#[test]
fn modeled_loss_full_duration_trace_and_sparse_tail_refusal() {
    let mut f=Fixture::new();let mut records=loss_records(&mut f);
    let (method,index,events)=f.trace(Kind::Loss,records.clone());assert!(reducers::reduce(&f.s,&method,&index,&events,&f.held).is_ok());
    // Same valid signed records, but removing late samples leaves a long tail.
    let sparse=vec![records[0].clone(),records[1].clone(),records.last().unwrap().clone()];
    let (method,index,events)=f.trace(Kind::Loss,sparse);assert!(reducers::reduce(&f.s,&method,&index,&events,&f.held).is_err());
}
#[test]
fn modeled_leap_full_trace_current_engine_ambiguity_and_wrong_wire_refusal() {
    let mut f=Fixture::new();let mut records=leap_records(&mut f);
    let (method,index,events)=f.trace(Kind::Leap,records.clone());assert_eq!(reducers::reduce(&f.s,&method,&index,&events,&f.held),Ok(0));
    records[1]["announcement_wire"]=2.into();let (method,index,events)=f.trace(Kind::Leap,records);
    assert!(reducers::reduce(&f.s,&method,&index,&events,&f.held).is_err());
}
#[test]
fn modeled_storage_full_trace_unknown_exact_recovery_and_stale_repair_refusal() {
    let mut f=Fixture::new();let mut records=storage_records(&mut f);
    let before=digest(&records[1]["before_state_sha256"]).unwrap();
    let (method,index,events)=f.trace(Kind::Storage,records.clone());assert_eq!(reducers::reduce(&f.s,&method,&index,&events,&f.held),Ok(0));
    records[3]["after_state"]["sha256"]=h(before);let (method,index,events)=f.trace(Kind::Storage,records);
    assert!(reducers::reduce(&f.s,&method,&index,&events,&f.held).is_err());
}
#[test]
fn modeled_joint_certificate_exact_scope_systematic_coverage_and_global_budget() {
    use provenance::CoverageKind as CK;
    let mut f=Fixture::new();let first=f.reference(UTC*1_000_000);let second=f.reference(UTC*1_000_000+1);
    let reference_pins=BTreeSet::from([digest(&first["uncertainty_event"]).unwrap(),digest(&second["uncertainty_event"]).unwrap()]);
    let event=f.s.instruments.get(reference_pins.first().unwrap()).unwrap().coverage_event;
    let commitment=f.raw(b"MODELED full-run commitments");
    let mut required=BTreeSet::from([(CK::Systematic,f.s.envelope.instrument),(CK::Calibration,f.s.envelope.calibration),
        (CK::ClassModel,f.s.envelope.pin),(CK::Frequency,commitment),(CK::Capture,commitment)]);
    for kind in [CK::Precision,CK::Lifecycle,CK::Authentication,CK::Loss,CK::Leap,CK::Storage]{required.insert((kind,commitment));}
    for pin in &reference_pins{required.insert((CK::Reference,*pin));}
    let names=|kind:CK|match kind{CK::Reference=>"reference",CK::Frequency=>"frequency",CK::Capture=>"capture",CK::Precision=>"source-precision",
        CK::Lifecycle=>"lifecycle",CK::Authentication=>"authentication",CK::Loss=>"loss",CK::Leap=>"leap",CK::Storage=>"storage",
        CK::Calibration=>"calibration",CK::Systematic=>"systematic",CK::ClassModel=>"class-model"};
    let make=|f:&mut Fixture,scope:&BTreeSet<provenance::CoveredEvent>,event:Hash,numerator:u64| {
        let events=scope.iter().map(|(kind,pin)|serde_json::json!({"kind":names(*kind),"commitment_sha256":h(*pin)})).collect::<Vec<_>>();
        let alpha=serde_json::json!({"numerator":numerator,"denominator":10000});
        let justification=f.sign(serde_json::json!({"format":"b8-clock-uncertainty-bound-justification-v1","failure_probability":alpha,
            "covered_events":events,"calibration_provenance_sha256":h(f.s.envelope.calibration),"uncertainty_model_sha256":h(f.s.envelope.instrument)}),
            b"BUILD8-NATIVE-CLOCK-UNCERTAINTY-JUSTIFICATION-V1");
        f.sign(serde_json::json!({"format":"b8-clock-joint-coverage-certificate-v1","coverage_event_sha256":h(event),
            "failure_probability":alpha,"covered_events":events,"justification_sha256":h(justification)}),b"BUILD8-NATIVE-CLOCK-JOINT-COVERAGE-V1")
    };
    let joint=make(&mut f,&required,event,1);f.s.coverage_pins=vec![joint];
    assert_eq!(verify_joint_coverage(&f.s,&required,&reference_pins,&f.held),Ok(()));
    let mut missing=required.clone();missing.remove(&(CK::Systematic,f.s.envelope.instrument));
    let incomplete=make(&mut f,&missing,event,1);f.s.coverage_pins=vec![incomplete];
    assert_eq!(verify_joint_coverage(&f.s,&required,&reference_pins,&f.held),Err(Error::Coverage));
    let excessive=make(&mut f,&required,event,11);f.s.coverage_pins=vec![excessive];
    assert_eq!(verify_joint_coverage(&f.s,&required,&reference_pins,&f.held),Err(Error::Coverage));
    f.s.coverage_pins=vec![joint,incomplete];
    assert_eq!(verify_joint_coverage(&f.s,&required,&reference_pins,&f.held),Err(Error::Coverage));
    // A real signature on an incomplete/out-of-budget scope gives no permission.
    let modeled=VerifiedExperiments{class:Class::ModeledTest,subject:f.s.subject,methods:[[2;32];6],frequency_upper_ppb:10,
        margin_ppb:20_000,trace_roots:[[3;32];6]};assert_eq!(modeled.normal_qualification(),Err(Error::MissingAcceptedPolicy));
}
#[test]
fn modeled_authenticated_class_envelope_short_intervals_nonlinearity_and_horizon() {
    let mut f=Fixture::new();let hardware=f.raw(b"MODELED hardware");let firmware=f.raw(b"MODELED firmware");let os=f.raw(b"MODELED OS");
    let execution=f.raw(b"MODELED execution environment");let conditions=f.raw(b"MODELED supported conditions");
    let cell=f.object(&serde_json::json!({"format":"b8-clock-supported-environment-cell-v1","subject_sha256":h(f.s.subject),
        "hardware_sha256":h(hardware),"firmware_sha256":h(firmware),"os_sha256":h(os),
        "execution_environment_sha256":h(execution),"operating_conditions_sha256":h(conditions)}));
    let model=f.s.envelope.instrument;
    let evidence=|format:&str|serde_json::json!({"format":format,"counter_model_sha256":h(model),
        "environment_cells":[h(cell)],"minimum_interval_ns":1,"maximum_interval_ns":10_000_000_000u64,"maximum_error_ppb":10,"counter_nonlinearity_ppb":10});
    // Separately authenticated calibration provenance and independently reviewed
    // class specification support the declared interval/environment applicability.
    let calibration=f.sign(evidence("b8-clock-class-calibration-provenance-v1"),b"BUILD8-NATIVE-CLOCK-CLASS-JUSTIFICATION-V1");
    let review=f.sign(evidence("b8-clock-independent-class-review-v1"),b"BUILD8-NATIVE-CLOCK-CLASS-JUSTIFICATION-V1");
    let envelope=serde_json::json!({"format":"b8-clock-class-envelope-receipt-v1","counter_model_sha256":h(f.s.envelope.instrument),
        "environment_cells":[h(cell)],"calibration_provenance_sha256":h(calibration),"independent_model_review_sha256":h(review),
        "minimum_interval_ns":1,"maximum_interval_ns":10_000_000_000u64,"maximum_error_ppb":10,"counter_nonlinearity_ppb":10});
    let pin=f.sign(envelope.clone(),b"BUILD8-NATIVE-CLOCK-CLASS-ENVELOPE-V1");
    let checked=provenance::Envelope::parse_selected(f.held.raw(&pin).unwrap(),pin).unwrap();assert_eq!(checked.verify(&f.s,&f.held),Ok(()));
    for (field,value)in [("minimum_interval_ns",2u64),("maximum_interval_ns",9_999_999_999),("counter_nonlinearity_ppb",11)] {
        let mut wrong=envelope.clone();wrong[field]=value.into();let pin=f.sign(wrong,b"BUILD8-NATIVE-CLOCK-CLASS-ENVELOPE-V1");
        let checked=provenance::Envelope::parse_selected(f.held.raw(&pin).unwrap(),pin).unwrap();assert!(checked.verify(&f.s,&f.held).is_err());
    }
}

struct ArithmeticBundle {parts:[Vec<u8>;4],refs:Value}
impl ArithmeticBundle {
    fn records(&self)->super::super::native_nts_raw_measurements::RawRecords<'_> {
        super::super::native_nts_raw_measurements::RawRecords{report:&self.parts[0],method:&self.parts[1],raw:&self.parts[2],environment:&self.parts[3]}
    }
}
fn arithmetic_bundle(f:&mut Fixture,obligation:&str,algorithm:&str,raw:Value)->ArithmeticBundle {
    let method=canonical(&serde_json::json!({"format":"build8/native-nts/arithmetic-method-v1","obligation":obligation,
        "algorithm":algorithm,"subject":modeled_subject()})).unwrap();let raw=canonical(&raw).unwrap();
    let environment=canonical(&serde_json::json!({"format":"build8/native-nts/measurement-environment-v1","obligation":obligation,
        "subject":modeled_subject(),"instrument_provenance_sha256":h(f.s.envelope.instrument)})).unwrap();
    let report=canonical(&serde_json::json!({"format":"build8/native-nts/measurement-report-v1","obligation":obligation,
        "method_sha256":h(hash(&method)),"raw_data_sha256":h(hash(&raw)),"environment_sha256":h(hash(&environment))})).unwrap();
    let refs=serde_json::json!({"report_sha256":h(hash(&report)),"method_sha256":h(hash(&method)),
        "raw_data_sha256":h(hash(&raw)),"environment_sha256":h(hash(&environment))});
    let parts=[report,method,raw,environment];for raw in &parts{f.raw(raw);}ArithmeticBundle{parts,refs}
}
fn complete_class(f:&mut Fixture) {
    let leaves=[f.raw(b"MODELED hardware"),f.raw(b"MODELED firmware"),f.raw(b"MODELED OS"),
        f.raw(b"MODELED execution environment"),f.raw(b"MODELED supported conditions")];
    let cell=f.object(&serde_json::json!({"format":"b8-clock-supported-environment-cell-v1","subject_sha256":h(f.s.subject),
        "hardware_sha256":h(leaves[0]),"firmware_sha256":h(leaves[1]),"os_sha256":h(leaves[2]),
        "execution_environment_sha256":h(leaves[3]),"operating_conditions_sha256":h(leaves[4])}));
    let model=f.s.envelope.instrument;
    let evidence=|format:&str|serde_json::json!({"format":format,"counter_model_sha256":h(model),"environment_cells":[h(cell)],
        "minimum_interval_ns":1,"maximum_interval_ns":10_000_000_000u64,"maximum_error_ppb":10,"counter_nonlinearity_ppb":10});
    let calibration=f.sign(evidence("b8-clock-class-calibration-provenance-v1"),b"BUILD8-NATIVE-CLOCK-CLASS-JUSTIFICATION-V1");
    let review=f.sign(evidence("b8-clock-independent-class-review-v1"),b"BUILD8-NATIVE-CLOCK-CLASS-JUSTIFICATION-V1");
    let pin=f.sign(serde_json::json!({"format":"b8-clock-class-envelope-receipt-v1","counter_model_sha256":h(model),
        "environment_cells":[h(cell)],"minimum_interval_ns":1,"maximum_interval_ns":10_000_000_000u64,
        "maximum_error_ppb":10,"counter_nonlinearity_ppb":10,"calibration_provenance_sha256":h(calibration),
        "independent_model_review_sha256":h(review)}),b"BUILD8-NATIVE-CLOCK-CLASS-ENVELOPE-V1");
    f.s.envelope=provenance::Envelope::parse_selected(f.held.raw(&pin).unwrap(),pin).unwrap();
    f.cell=cell;f.s.lifecycle_cases=BTreeSet::from([(trace::LifecycleCase::Jitter,cell)]);
}
fn complete_certificate(f:&mut Fixture,required:&BTreeSet<provenance::CoveredEvent>,event:Hash)->Hash {
    use provenance::CoverageKind as CK;
    let name=|k:CK|match k{CK::Reference=>"reference",CK::Frequency=>"frequency",CK::Capture=>"capture",CK::Precision=>"source-precision",
        CK::Lifecycle=>"lifecycle",CK::Authentication=>"authentication",CK::Loss=>"loss",CK::Leap=>"leap",CK::Storage=>"storage",
        CK::Calibration=>"calibration",CK::Systematic=>"systematic",CK::ClassModel=>"class-model"};
    let events=required.iter().map(|(kind,pin)|serde_json::json!({"kind":name(*kind),"commitment_sha256":h(*pin)})).collect::<Vec<_>>();
    let alpha=serde_json::json!({"numerator":1,"denominator":10000});
    let justification=f.sign(serde_json::json!({"format":"b8-clock-uncertainty-bound-justification-v1","failure_probability":alpha,
        "covered_events":events,"calibration_provenance_sha256":h(f.s.envelope.calibration),"uncertainty_model_sha256":h(f.s.envelope.instrument)}),
        b"BUILD8-NATIVE-CLOCK-UNCERTAINTY-JUSTIFICATION-V1");
    f.sign(serde_json::json!({"format":"b8-clock-joint-coverage-certificate-v1","coverage_event_sha256":h(event),"failure_probability":alpha,
        "covered_events":events,"justification_sha256":h(justification)}),b"BUILD8-NATIVE-CLOCK-JOINT-COVERAGE-V1")
}
fn six_indices(raws:&[Vec<u8>])->[&[u8];6] {
    assert_eq!(raws.len(),6);[&raws[0],&raws[1],&raws[2],&raws[3],&raws[4],&raws[5]]
}
#[test]
fn modeled_complete_pipeline_six_traces_arithmetic_provenance_retention_and_missing_initial_coverage_refusal() {
    use provenance::CoverageKind as CK;
    use super::super::native_nts_raw_measurements as raw;
    let mut f=Fixture::new();complete_class(&mut f);
    let builders:[fn(&mut Fixture)->Vec<Value>;6]=[precision_records,lifecycle_records,authentication_records,loss_records,leap_records,storage_records];
    let kinds=[Kind::Precision,Kind::Lifecycle,Kind::Authentication,Kind::Loss,Kind::Leap,Kind::Storage];
    let mut indices=vec![];let mut events=vec![];let mut roots=vec![];let mut top=vec![];
    for (kind,build)in kinds.into_iter().zip(builders) {
        let records=build(&mut f);let (method,index,decoded)=f.trace(kind,records);
        let raw=f.held.raw(&index.pin).unwrap().to_vec();
        let report=f.object(&serde_json::json!({"format":"build8/native-nts/measurement-report-v1","obligation":kind.obligation(),
            "method_sha256":h(method.pin),"raw_data_sha256":h(index.pin),"environment_sha256":h(method.environment)}));
        let refs=serde_json::json!({"report_sha256":h(report),"method_sha256":h(method.pin),"raw_data_sha256":h(index.pin),"environment_sha256":h(method.environment)});
        f.s.methods.push(method);let m=f.s.methods.last().unwrap();
        group_bindings(&f.s,kind.index(),&modeled_subject(),&refs,raw::RawRecords{report:f.held.raw(&report).unwrap(),
            method:f.held.raw(&m.pin).unwrap(),raw:&raw,environment:f.held.raw(&m.environment).unwrap()}).unwrap();
        top.extend([report,m.pin,index.pin,m.environment]);roots.push(index.root);indices.push(raw);events.push(decoded);
    }
    let first=f.reference(UTC*1_000_000+1000);let last=f.reference(UTC*1_000_000+10_000_001_000);
    let freq=f.object(&serde_json::json!({"format":"b8-clock-frequency-trace-v1","subject_sha256":h(f.s.subject),
        "capture_start":Fixture::capture(1_000_001_000),"capture_end":Fixture::capture(11_000_001_000),"reference_start":first,"reference_end":last}));
    f.s.frequency_raw_pin=freq;
    let native_frequency=arithmetic_bundle(&mut f,"frequency_error","elapsed-reference-interval-v1",serde_json::json!({
        "format":"build8/native-nts/raw-frequency-v1","obligation":"frequency_error","elapsed_abi":ABI,"boot_id_hex":format!("{:032x}",7),
        "active_start_ns":1,"active_end_ns":10_000_000_001u64,"reference_start":{"lower_ns":1_000_000_000u64,"upper_ns":1_000_000_000u64},
        "reference_end":{"lower_ns":11_000_000_000u64,"upper_ns":11_000_000_000u64}}));
    let update=match &events[0][0].record{trace::Record::Precision{update,..}=>*update,_=>panic!("precision")};
    let arithmetic=f.held.object(&update).unwrap()["arithmetic"].clone();
    let samples=f.s.acquisition.providers.iter().map(|p|serde_json::json!({"provider":{"hostname":p.hostname,"operator":p.operator,
        "key_establishment_port":p.key_establishment_port,"no_smear_profile_evidence_sha256":h(p.no_smear_profile_evidence_sha256)},"arithmetic":arithmetic})).collect::<Vec<_>>();
    let native_initial=arithmetic_bundle(&mut f,"capture_uncertainty","native-nts-total-initial-v1",serde_json::json!({
        "format":"build8/native-nts/raw-initial-v1","obligation":"capture_uncertainty","elapsed_abi":ABI,
        "now":{"active_before_ns":1_101_000_000u64,"active_after_ns":1_101_010_000u64,"inclusive_ns":1_101_000_000u64,"boot_id_hex":format!("{:032x}",7)},"samples":samples}));
    let refs=serde_json::json!({"frequency_error":native_frequency.refs,"capture_uncertainty":native_initial.refs});
    let necessary=raw::verify(&modeled_subject(),&refs,&f.s.profile,&f.s.acquisition,native_frequency.records(),native_initial.records()).unwrap();
    assert_eq!(necessary.documentary_inputs(),(hash(&native_frequency.parts[2]),hash(&native_initial.parts[2])));
    for bundle in [&native_frequency,&native_initial]{for part in &bundle.parts{top.push(hash(part));}}
    assert_eq!(top.len(),32);
    let (af,ai)=necessary.documentary_inputs();let mut required=BTreeSet::from([(CK::Frequency,freq),(CK::Capture,freq),(CK::Frequency,af),
        (CK::Capture,af),(CK::Capture,ai),(CK::ClassModel,f.s.envelope.pin),(CK::ClassModel,f.s.envelope.instrument),
        (CK::Calibration,f.s.envelope.calibration),(CK::Systematic,f.s.envelope.review)]);
    let mut reference_pins=BTreeSet::from([digest(&first["uncertainty_event"]).unwrap(),digest(&last["uncertainty_event"]).unwrap()]);
    for i in 0..6 {required.insert((CK::for_trace(kinds[i]),roots[i]));for e in &events[i]{required.insert((CK::Capture,e.projection));
        for pin in e.external_refs(){reference_pins.insert(pin);}}}
    for pin in &reference_pins{let instrument=&f.s.instruments[pin];required.insert((CK::Reference,*pin));
        required.insert((CK::Calibration,instrument.calibration));required.insert((CK::Systematic,instrument.instrument));}
    let event=f.s.instruments[reference_pins.first().unwrap()].coverage_event;
    f.s.coverage_pins=vec![complete_certificate(&mut f,&required,event)];
    let plan=family_support_plan(&f.s,six_indices(&indices),&top,&f.held).unwrap();
    assert!(plan.object_count()<=plan.maximum_objects());assert!(plan.maximum_total_bytes().unwrap()<=256*1024*1024);
    for pin in plan.digests(){f.held.raw(pin).unwrap();}
    let finding=verify_selected(&f.s,six_indices(&indices),&f.held,f.held.raw(&freq).unwrap(),&necessary).unwrap();
    assert!(finding.frequency_upper_ppb()<=80_000);assert_eq!(finding.normal_qualification(),Err(Error::MissingAcceptedPolicy));
    let mut missing=required;assert!(missing.remove(&(CK::Capture,ai)));
    f.s.coverage_pins=vec![complete_certificate(&mut f,&missing,event)];
    assert!(matches!(verify_selected(&f.s,six_indices(&indices),&f.held,f.held.raw(&freq).unwrap(),&necessary),Err(Error::Coverage)));
    // Canonical truncation of any full trace cannot supply substitute coverage.
    let mut truncated=indices;truncated[5].pop();
    assert!(verify_selected(&f.s,six_indices(&truncated),&f.held,f.held.raw(&freq).unwrap(),&necessary).is_err());
}
