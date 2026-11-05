//! Independent takeover probes: controlled public software time, no physical claim.
use mutiny_consensus_v8::holdover_clock_v1::{ClockProfile,Elapsed,ElapsedSource,HoldoverClock,LeapView,SourceSample,Status,Unqualified};
use std::sync::{Arc,Mutex};
const UTC:u64=1_790_899_300_000;
const NS:u64=1_000_000;
struct Trace(Mutex<Elapsed>);
impl ElapsedSource for Trace {fn read(&self)->Option<Elapsed>{Some(*self.0.lock().ok()?)}}
impl Trace {
    fn set(&self,real_ms:u64,suspend_ms:u64,pairing_ms:i64){
        assert!(real_ms>=suspend_ms);
        *self.0.lock().unwrap()=Elapsed{boottime_ns:(1000+real_ms)*NS,
            monotonic_ns:((1000+real_ms-suspend_ms)*NS).checked_add_signed(pairing_ms*NS as i64).unwrap(),boot_id:91};
    }
}
fn start()->(Arc<HoldoverClock>,Arc<Trace>){
    let source=Arc::new(Trace(Mutex::new(Elapsed{boottime_ns:1000*NS,monotonic_ns:1000*NS,boot_id:91})));
    let c=HoldoverClock::new(ClockProfile{max_source_uncertainty_ms:248,max_calibration_half_width_ms:250,min_sources:1,max_faulty_sources:0,drift_bound_ppb:8680,max_holdover_ms:86_400_000,max_interval_half_width_ms:1000,max_suspend_gap_ms:50,confirm_calibrations:1},source.clone()).unwrap();
    assert!(c.set_leap_view(LeapView::Clear{valid_until_ms:UTC+100_000_000}));
    assert_eq!(c.calibrate(&[SourceSample{source:"public-software-trace".into(),authenticated:true,utc_ms:UTC,uncertainty_ms:100,at:source.read().unwrap()}]),Ok(true));
    (c,source)
}
fn contains_truth(c:&HoldoverClock,real_ms:u64)->u64{
    let Status::Qualified{lower_ms,half_width_ms,..}=c.status() else{panic!("unexpected refusal at {real_ms}")};
    let (lo,hi)=c.interval_ms().unwrap();
    assert_eq!(lo,lower_ms);
    assert!(lo<=UTC+real_ms && UTC+real_ms<=hi,"truth={} interval={lo}..{hi}",UTC+real_ms);
    assert!(half_width_ms<=1000);
    half_width_ms
}
#[test]
fn sparse_sampling_can_miss_jitter_extrema_but_both_intervals_contain_independent_truth(){
    let (dense,d)=start(); let (sparse,s)=start();
    for step in 1..=600 {
        let real=step*100;
        let pairing=match step%10{3=>12,7=>-9,_=>0};
        d.set(real,0,pairing); contains_truth(&dense,real);
        if step%10==0 {s.set(real,0,pairing);contains_truth(&sparse,real);}
    }
    let dw=contains_truth(&dense,60_000);let sw=contains_truth(&sparse,60_000);
    // Same elapsed process, distinct observed extrema. Literal equality at any
    // sampling rate is not a valid claim; adding reads cannot shrink this range.
    assert_eq!(dw,sw+21);
}
#[test]
fn opposing_pairing_jitter_can_mask_short_suspends_until_its_amplitude_is_exhausted(){
    let (clock,source)=start();let (control,clean)=start();
    // One millisecond of real suspend per second; a simultaneous monotonic
    // pairing offset cancels the observable gap during the first25ms. Real UTC
    // advances through suspend and is computed independently of ledger fields.
    for k in 1..=25 {
        let real=k*1001;
        source.set(real,k,k as i64);clean.set(real,0,0);
        assert_eq!(contains_truth(&clock,real),contains_truth(&control,real));
    }
    for k in 26..=75 {
        let real=k*1001;
        source.set(real,k,25);clean.set(real,0,0);
        assert_eq!(contains_truth(&clock,real),contains_truth(&control,real)+k-25);
    }
    source.set(76*1001,76,25);
    assert_eq!(clock.status(),Status::Unqualified(Unqualified::SuspendDetected));
    source.set(77*1001,77,25);
    assert_eq!(clock.status(),Status::Unqualified(Unqualified::SuspendDetected));
}
