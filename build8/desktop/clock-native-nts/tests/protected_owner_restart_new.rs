//! New MODELED protected-checkpoint algorithms only. No native owner/store,
//! time qualification, old lib15/node_service selector or held coverage credit.
//! Consensus is an ordinary dev library; only this integration target executes.
#[path="../../node/src/host_clock/leap_policy.rs"] mod leap_policy;
#[path="../../node/src/host_clock/protected_clock_lineage_v1.rs"] mod protected_clock_lineage_v1;
#[path="../../node/src/host_clock/protected_clock_operation_journal.rs"] mod protected_clock_operation_journal;
use mutiny_consensus_v8::holdover_clock_v1::{ClockProfile,ControlledElapsed,ElapsedSource,
    HoldoverClock,LeapView,ProtectedCheckpoint,SourceSample,Status};
use protected_clock_lineage_v1::{Binding,Operation,Request,Scope};
use protected_clock_operation_journal::{installed_header_document,scan,JournalPlan};
use std::{sync::Arc,io::Cursor};
const UTC:u64=1_790_000_000_000;
fn profile()->ClockProfile {ClockProfile {max_source_uncertainty_ms:100,
    max_calibration_half_width_ms:250,min_sources:3,max_faulty_sources:0,drift_bound_ppb:1000,
    max_holdover_ms:60_000,max_interval_half_width_ms:1000,max_suspend_gap_ms:2,confirm_calibrations:1}}
fn setup()->(Arc<HoldoverClock>,Arc<ControlledElapsed>,LeapView,[u8;27]) {
    let elapsed=ControlledElapsed::start(7);let clock=HoldoverClock::new(profile(),elapsed.clone()).unwrap();
    let horizon=leap_policy::calendar_horizon_ms(UTC).unwrap();let leap=LeapView::Clear{valid_until_ms:horizon};
    assert!(clock.set_leap_view(leap));let at=elapsed.read().unwrap();
    let samples=(1..=3).map(|id|SourceSample{source:format!("EXPLICIT-NEW-MODELED-{id}"),
        authenticated:true,utc_ms:UTC,uncertainty_ms:100,at}).collect::<Vec<_>>();
    assert_eq!(clock.calibrate(&samples),Ok(true));
    let mut memory=[0u8;27];memory[0]=1;memory[1..9].copy_from_slice(&horizon.to_be_bytes());
    (clock,elapsed,leap,memory)
}
#[test]
fn protected_restart_new_preserves_full_gap_range_and_original_age() {
    let(clock,elapsed,leap,_)=setup();elapsed.run(1000);elapsed.suspend(1);
    assert!(clock.lower_bound_ms().is_some());elapsed.regress_boottime(1);elapsed.run(1000);
    let checkpoint=clock.protected_checkpoint(1,leap_policy::POLICY_VERSION).unwrap();
    let decoded=ProtectedCheckpoint::decode(&checkpoint.encode()).unwrap();assert_eq!(decoded,checkpoint);
    let legacy=clock.assess_restart(checkpoint.anchor()).unwrap();
    let restored=HoldoverClock::new(profile(),elapsed.clone()).unwrap();
    let evidence=restored.restore_protected_same_boot(&decoded,leap_policy::POLICY_VERSION,leap).unwrap();
    assert!(evidence.would_be_half_width_ms>legacy.would_be_half_width_ms);
    assert_eq!(restored.status(),clock.status());
    elapsed.run(60_000);assert!(restored.lower_bound_ms().is_none());
}
#[test]
fn protected_restart_new_refuses_changed_boot_floor_and_leap_without_install() {
    let(clock,elapsed,leap,_)=setup();let checkpoint=clock.protected_checkpoint(1,2).unwrap();
    for mode in 0..3 {
        let fresh=HoldoverClock::new(profile(),elapsed.clone()).unwrap();
        let view=if mode==0 {LeapView::Unassessed}else{leap};
        if mode==1 {fresh.ratchet_high_water(u64::MAX);}
        if mode==2 {elapsed.reboot(8);}
        assert!(fresh.restore_protected_same_boot(&checkpoint,2,view).is_err());
        assert!(fresh.anchor_interval_ms().is_none());assert!(fresh.lower_bound_ms().is_none());
    }
}
#[test]
fn protected_restart_new_complete_checkpoint_operation_journal_exact_retry_bound() {
    let(clock,_,_,leap)=setup();let checkpoint=clock.protected_checkpoint(1,2).unwrap();
    let binding=Binding::selected_document([1;32],[2;32],[3;32],[4;32],checkpoint.anchor().params.id());
    let operation=Operation::authenticated_document([5;32],[6;32]).unwrap();
    let scope=Scope::selected_document([7;32],[8;32],[9;32],[10;32]);
    let mut initial=b"MCLC4D01".to_vec();for byte in [7,8,9,10]{initial.extend_from_slice(&[byte;32]);}
    initial.extend_from_slice(&0u64.to_be_bytes());initial.extend_from_slice(&0u64.to_be_bytes());initial.push(0);
    initial.extend_from_slice(&0u16.to_be_bytes());
    let request=Request::from_protected_engine(0,&binding,checkpoint,leap,Some(operation.clone())).unwrap();
    assert_eq!(Request::decode(&request.encode()).unwrap(),request);
    let plan=JournalPlan::from_current(&scope,&initial,request).unwrap();
    assert!(plan.intent_head().len()<=protected_clock_lineage_v1::SNAPSHOT_MAX);
    assert!(plan.completion_head().len()<=protected_clock_lineage_v1::SNAPSHOT_MAX);
    let mut journal=installed_header_document(&scope);journal.extend_from_slice(&plan.intent_frame());journal.extend_from_slice(&plan.completion_frame());
    let history=scan(&scope,&mut Cursor::new(&journal),journal.len() as u64).unwrap();
    assert_eq!(history.lookup(&operation).unwrap().unwrap().sequence,1);
    assert!(history.lookup(&Operation::authenticated_document([5;32],[11;32]).unwrap()).is_err());
    let _label:Option<Status>=None; // Explicit algorithm result, never native qualification.
}
