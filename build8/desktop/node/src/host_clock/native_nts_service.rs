//! Cancellable native NTS software lifecycle. No production deployment issuer
//! exists here; hashes and structural validation are not profile authorization.
//! The cfg(test) factory models only that missing local decision. It cannot be
//! enabled with a Cargo feature or construct an authenticated observation.
use super::{native_nts_backend::{NativeNtsBackend, validate_profile}, state_dir::ClockStateDir};
use super::native_nts_deployment_record::{ApprovedNativePlacement, ValidatedRecord, NativeSelectionGuard};
use super::anchor_store::{AnchorStore, ReplacementContinuity};
use mutiny_clock_native_nts_v1::{AcquisitionReport, Config};
use mutiny_consensus_v8::{holdover_clock_v1::{ClockProfile, HoldoverClock, TimeBasis},
    vote_clock_v1::{ClockReading, VoteClock}};
#[cfg(test)]
use std::path::PathBuf;
use std::{future::{Future, poll_fn}, io, pin::pin,
    sync::{Arc, Mutex, Weak}, task::{Poll, Waker}, time::{Duration, Instant}};

type Result<T> = std::result::Result<T, String>;

/// Nonconstructible in ordinary code. The future issuer must independently
/// authenticate the complete deployment contract, not just these numbers.
/// No issuer or registration is supplied by this software implementation.
pub(super) struct AuthorizedNativeDeployment {
    profile: ClockProfile,
    acquisition: Config,
    storage: NativeStateSelection,
    cadence: Duration,
    selection: NativeSelectionGuard,
    continuity: Option<ReplacementContinuity>,
}
enum NativeStateSelection {
    Prepared(ClockStateDir),
    #[cfg(test)]
    ModeledPath(PathBuf),
}
// Existing service declaration constraint, not a new profile/default or a
// consensus deadline. The future deployment issuer must select its exact value.
pub(super) fn validate_cadence(cadence: Duration) -> Result<()> {
    if !(1..=3600).contains(&cadence.as_secs()) || cadence.subsec_nanos()!=0 {
        return Err("native cadence declaration refused".into());
    }
    Ok(())
}
impl AuthorizedNativeDeployment {
    pub(super) fn from_validated(record: ValidatedRecord, placement: ApprovedNativePlacement)
        -> Result<Self> {
        let (profile,acquisition,state,cadence,selection)=placement.into_parts(record)
            .map_err(|e| format!("native selected placement refused: {e:?}"))?;
        Ok(Self {profile,acquisition,storage:NativeStateSelection::Prepared(state),cadence,selection,
            continuity:None})
    }
    pub(super) fn from_validated_replacement(record: ValidatedRecord,
        placement: ApprovedNativePlacement, continuity: ReplacementContinuity) -> Result<Self> {
        let mut deployment=Self::from_validated(record,placement)?;
        deployment.continuity=Some(continuity);
        Ok(deployment)
    }
    #[cfg(test)]
    pub(super) fn modeled_test_value(profile: ClockProfile, acquisition: Config,
        anchor: PathBuf, cadence: Duration) -> Result<Self> {
        validate_profile(&profile, &acquisition)?;
        if !anchor.is_absolute() || validate_cadence(cadence).is_err() {
            return Err("native anchor/cadence declaration refused".into());
        }
        Ok(Self { profile, acquisition, storage:NativeStateSelection::ModeledPath(anchor), cadence,
            selection:NativeSelectionGuard::modeled(),continuity:None })
    }
}

struct State {
    stopped: bool, waiting: Option<Waker>, last_failure: Option<String>,
    selection: Option<NativeSelectionGuard>,
}
impl State {
    // One lock order: State -> installation/current recheck -> engine -> anchor.
    // No await or caller callback under State. Wake only after releasing State.
    fn check(&mut self) -> Result<()> {
        if self.stopped {return Err("native service stopped".into());}
        let checked=match self.selection.as_mut() {
            Some(selection)=>selection.recheck(),
            None=>Err("native service selection owner absent".into()),
        };
        if let Err(error)=checked {
            self.stopped=true;
            // Fixed bounded diagnostic, no raw qualification evidence logged.
            self.last_failure=Some("native installation/current selection retired".into());
            return Err(error);
        }
        Ok(())
    }
}
#[derive(Clone)]
pub(super) struct StopHandle {
    state: Arc<Mutex<State>>, clock: Weak<HoldoverClock>,
    store: Option<Weak<Mutex<AnchorStore>>>,
}
impl StopHandle {
    /// No new reading or calibration can pass the barrier while the greatest
    /// consumed floor is durably retired. This can only refuse/shorten; it does
    /// not revive a retired installation or grant successor qualification.
    pub(super) fn freeze_for_replacement(&self) -> Result<ReplacementContinuity> {
        let mut state=match self.state.lock() {
            Ok(state)=>state,
            Err(poisoned)=>{
                let mut state=poisoned.into_inner();state.stopped=true;
                let wake=state.waiting.take();drop(state);
                if let Some(wake)=wake {wake.wake();}
                return Err("native replacement service barrier poisoned".into());
            },
        };
        state.stopped=true;
        let wake=state.waiting.take();
        let result=(|| {
            let clock=self.clock.upgrade().ok_or("native replacement engine owner absent")?;
            let floor=clock.persisted_high_water();
            let store=self.store.as_ref().and_then(Weak::upgrade)
                .ok_or("native replacement durable owner absent")?;
            let mut store=store.lock().map_err(|_| "native replacement store poisoned")?;
            store.freeze_replacement(floor)
        })();
        drop(state);
        if let Some(wake)=wake {wake.wake();}
        result
    }
    /// Linearizes against calibration and every basis/clock read. No later
    /// reading grants fresh-vote/admission time, even while another Arc survives.
    pub(super) fn stop(&self) {
        let wake = match self.state.lock() {
            Ok(mut s) => { s.stopped = true; s.waiting.take() }
            Err(poisoned) => { let mut s = poisoned.into_inner(); s.stopped=true; s.waiting.take() }
        };
        if let Some(w) = wake { w.wake(); }
    }
}
struct LiveBasis { clock: Arc<HoldoverClock>, state: Arc<Mutex<State>> }
impl TimeBasis for LiveBasis {
    fn lower_bound_ms(&self) -> Option<u64> {
        let mut s=match self.state.lock() {
            Ok(s)=>s,
            Err(poisoned)=>{
                let mut s=poisoned.into_inner();s.stopped=true;
                let wake=s.waiting.take();drop(s);
                if let Some(w)=wake {w.wake();}
                return None;
            },
        };
        if s.check().is_err() {
            let wake=s.waiting.take();drop(s);
            if let Some(w)=wake {w.wake();}
            return None;
        }
        self.clock.lower_bound_ms()
    }
}
impl VoteClock for LiveBasis {
    fn reading(&self) -> ClockReading {
        match self.lower_bound_ms() {
            Some(ms) => ClockReading::Qualified { utc_seconds: ms / 1000 },
            None => ClockReading::Unqualified,
        }
    }
}

pub(super) struct NativeNtsService {
    backend: NativeNtsBackend,
    state: Arc<Mutex<State>>,
    cadence: Duration,
    last_attempt: Option<Instant>,
}
impl NativeNtsService {
    pub(super) fn start(mut deployment: AuthorizedNativeDeployment) -> Result<Self> {
        // Revalidate typed inputs; the selected route moves the already-held
        // C8/C12 owner into AnchorStore BEFORE any anchor read. No reopen. There
        // is no ordinary issuer of `deployment` today.
        validate_profile(&deployment.profile, &deployment.acquisition)?;
        validate_cadence(deployment.cadence)?;
        deployment.selection.recheck()?;
        let state = match deployment.storage {
            NativeStateSelection::Prepared(state)=>state,
            #[cfg(test)]
            NativeStateSelection::ModeledPath(anchor)=>ClockStateDir::open(&anchor)
                .map_err(|e| format!("native anchor storage refused: {e}"))?,
        };
        let backend=match deployment.continuity {
            Some(continuity)=>NativeNtsBackend::with_state_replacement(deployment.profile,
                deployment.acquisition,state,continuity)?,
            None=>NativeNtsBackend::with_state(deployment.profile,deployment.acquisition,state)?,
        };
        Ok(Self { backend, state: Arc::new(Mutex::new(State {
                stopped:false,waiting:None,last_failure:None,selection:Some(deployment.selection) })),
            cadence: deployment.cadence, last_attempt: None })
    }
    pub(super) fn stop_handle(&self) -> StopHandle {
        let (clock,store)=self.backend.replacement_stop_inputs();
        StopHandle {state:self.state.clone(),clock,store}
    }
    pub(super) fn basis(&self) -> Arc<dyn TimeBasis> {
        Arc::new(LiveBasis { clock:self.backend.clock(), state:self.state.clone() })
    }
    pub(super) fn vote_clock(&self) -> Arc<dyn VoteClock> {
        Arc::new(LiveBasis { clock:self.backend.clock(), state:self.state.clone() })
    }
    pub(super) fn restore_report(&self) -> Option<&super::RestoreReport> {
        self.backend.restore_report()
    }
    #[cfg(test)]
    pub(super) fn replace_elapsed_private_test(&mut self,
        elapsed: Arc<dyn mutiny_consensus_v8::holdover_clock_v1::ElapsedSource>) -> Result<()> {
        self.backend.replace_elapsed_private_test(elapsed)
    }
    #[cfg(test)]
    pub(super) fn diagnostic_anchor_private_test(&self)
        -> Option<mutiny_consensus_v8::holdover_clock_v1::PersistedAnchor> {
        self.backend.clock().persisted(1, super::leap_policy::POLICY_VERSION)
    }
    /// Caller schedules using monotonic local wake-ups only. Due checks use the
    /// existing poll_due predicate; an owning run loop uses wake_interval.
    /// No cached `qualified` result or persisted anchor starts fresh authority.
    pub(super) fn due(&self) -> bool {
        let mut state=match self.state.lock() {Ok(s)=>s,Err(_)=>return false};
        if state.check().is_err() {
            let wake=state.waiting.take();drop(state);
            if let Some(w)=wake {w.wake();}
            return false;
        }
        self.last_attempt.is_none_or(|last| super::poll_due(self.cadence,
            last.elapsed(), self.backend.clock().status()))
    }
    /// Exclusive mutable borrow serializes attempts. Cancellation drops the
    /// acquisition/JoinSet before applying any result; already acquired reports
    /// are applied synchronously under the same stop/read gate (no await there).
    /// Owns the service until explicit stop or future drop. Uses exactly the
    /// existing local wake interval; failed acquisition never refreshes anchor age.
    /// Dropping this owning future drops the service and poisons held consumers.
    pub(super) async fn run(self) -> Result<()> {
        self.run_with(native_acquire).await
    }
    async fn run_with<F: Future<Output=io::Result<AcquisitionReport>>>(mut self,
        mut acquire: impl FnMut(Config) -> F) -> Result<()> {
        loop {
            if self.stopped()? { return Ok(()); }
            if self.due() {
                let config=self.backend.config().clone();
                let result=self.poll_acquisition(acquire(config)).await;
                if self.stopped()? { return Ok(()); }
                self.state.lock().map_err(|_| "native service state poisoned")?
                    .last_failure=result.err();
            }
            if !self.wait_for_wakeup().await? { return Ok(()); }
        }
    }
    fn stopped(&self) -> Result<bool> {
        self.state.lock().map(|s| s.stopped)
            .map_err(|_| "native service state poisoned".to_owned())
    }
    pub(super) fn last_failure(&self) -> Result<Option<String>> {
        self.state.lock().map(|s| s.last_failure.clone())
            .map_err(|_| "native service state poisoned".to_owned())
    }
    async fn wait_for_wakeup(&self) -> Result<bool> {
        let mut sleep=pin!(tokio::time::sleep(super::wake_interval(self.cadence)));
        let result=poll_fn(|cx| {
            {
                let mut s=match self.state.lock() {
                    Ok(s)=>s,Err(_)=>return Poll::Ready(Err("native service state poisoned".to_owned())),
                };
                if s.stopped { return Poll::Ready(Ok(false)); }
                s.waiting=Some(cx.waker().clone());
            }
            sleep.as_mut().poll(cx).map(|_| Ok(true))
        }).await;
        self.state.lock().map_err(|_| "native service state poisoned")?.waiting=None;
        result
    }
    #[cfg(test)]
    pub(super) async fn run_private_test<F: Future<Output=io::Result<AcquisitionReport>>>(self,
        acquire: impl FnMut(Config) -> F) -> Result<()> {
        self.run_with(acquire).await
    }
    pub(super) async fn poll_once(&mut self) -> Result<bool> {
        let config = self.backend.config().clone();
        self.poll_acquisition(native_acquire(config)).await
    }
    async fn poll_acquisition(&mut self, future: impl Future<Output=io::Result<AcquisitionReport>>) -> Result<bool> {
        let mut future = pin!(future);
        let acquired = poll_fn(|cx| {
            {
                let mut state = match self.state.lock() {
                    Ok(s) => s,
                    Err(_) => return Poll::Ready(Err("native service state poisoned".to_owned())),
                };
                if let Err(error)=state.check() {
                    let wake=state.waiting.take();drop(state);
                    if let Some(w)=wake {w.wake();}
                    return Poll::Ready(Err(error));
                }
                state.waiting = Some(cx.waker().clone());
            }
            future.as_mut().poll(cx).map(|r| r.map_err(|e| format!("native acquisition: {e}")))
        }).await;
        let mut state = self.state.lock().map_err(|_| "native service state poisoned")?;
        state.waiting = None;
        state.check()?;
        // Capture time only as a scheduling fact. It never changes anchor age.
        self.last_attempt = Some(Instant::now());
        // Recheck after acquisition and immediately before applying its result.
        // Network failures retain existing clock fault/holdover semantics.
        let finished=self.backend.finish_acquired(acquired);
        // Writes made before a failed post-check remain evidence, never authority.
        state.check()?;
        finished
    }
    #[cfg(test)]
    pub(super) async fn poll_private_test_acquisition(&mut self,
        future: impl Future<Output=io::Result<AcquisitionReport>>) -> Result<bool> {
        self.poll_acquisition(future).await
    }
}
async fn native_acquire(config: Config) -> io::Result<AcquisitionReport> {
    mutiny_clock_native_nts_v1::acquire(config).await
}
impl Drop for NativeNtsService {
    fn drop(&mut self) {
        self.stop_handle().stop();
        // Owning acquisition future has ended or been cancelled before service
        // destruction. Retained consumer/stop Arcs keep only the stopped gate,
        // never installation handles. Backend anchor owner drops with service.
        let owner=match self.state.lock() {
            Ok(mut state)=>state.selection.take(),
            Err(poisoned)=>poisoned.into_inner().selection.take(),
        };
        drop(owner);
    }
}

#[cfg(test)] mod selection_gate_tests {
    use super::*;
    use std::sync::atomic::Ordering;
    fn modeled_state()->(State,Arc<std::sync::atomic::AtomicBool>,Arc<std::sync::atomic::AtomicBool>) {
        let owner=NativeSelectionGuard::modeled();let (valid,released)=owner.modeled_controls();
        (State {stopped:false,waiting:None,last_failure:None,selection:Some(owner)},valid,released)
    }
    #[test] fn modeled_selection_failure_is_sticky_and_keeps_owner_until_close() {
        let (mut state,valid,released)=modeled_state();
        assert!(state.check().is_ok());valid.store(false,Ordering::SeqCst);
        assert!(state.check().is_err());assert!(state.stopped);
        assert!(!released.load(Ordering::SeqCst));
        valid.store(true,Ordering::SeqCst);assert!(state.check().is_err());
        drop(state.selection.take());assert!(released.load(Ordering::SeqCst));
    }
    #[test] fn modeled_retained_gate_cannot_keep_owner_after_explicit_close() {
        let (state,_,released)=modeled_state();let gate=Arc::new(Mutex::new(state));
        let retained=gate.clone();let stop=StopHandle {state:gate.clone(),clock:Weak::new(),store:None};
        stop.stop();assert!(!released.load(Ordering::SeqCst));
        drop(gate.lock().unwrap().selection.take());drop(gate);
        assert!(released.load(Ordering::SeqCst));
        assert!(retained.lock().unwrap().check().is_err());
    }
    #[test] fn missing_selection_owner_refuses_without_revival() {
        let mut state=State {stopped:false,waiting:None,last_failure:None,selection:None};
        assert!(state.check().is_err());assert!(state.stopped);
        state.selection=Some(NativeSelectionGuard::modeled());assert!(state.check().is_err());
    }
    #[test] fn replacement_missing_owner_stops_and_wakes_without_revival() {
        struct WakeCount(std::sync::atomic::AtomicUsize);
        impl std::task::Wake for WakeCount {
            fn wake(self:Arc<Self>) {self.0.fetch_add(1,Ordering::SeqCst);}
        }
        let (mut state,_,_)=modeled_state();
        let wakes=Arc::new(WakeCount(std::sync::atomic::AtomicUsize::new(0)));
        state.waiting=Some(Waker::from(wakes.clone()));
        let state=Arc::new(Mutex::new(state));
        let stop=StopHandle {state:state.clone(),clock:Weak::new(),store:None};
        assert!(stop.freeze_for_replacement().is_err());
        assert_eq!(wakes.0.load(Ordering::SeqCst),1);
        let mut state=state.lock().unwrap();
        assert!(state.stopped);assert!(state.waiting.is_none());
        assert!(state.check().is_err());
    }
    #[test] fn modeled_replacement_barrier_persists_consumed_floor_and_wakes_after_unlock() {
        // Existing anchor unit-test owner, no native C8/C12 qualification.
        // No authenticated observation or approved deployment is constructed.
        use mutiny_consensus_v8::holdover_clock_v1::ControlledElapsed;
        let profile=ClockProfile {max_source_uncertainty_ms:248,max_calibration_half_width_ms:250,
            min_sources:1,max_faulty_sources:0,drift_bound_ppb:8680,max_holdover_ms:86_400_000,
            max_interval_half_width_ms:1000,max_suspend_gap_ms:50,confirm_calibrations:1};
        let clock=HoldoverClock::new(profile,ControlledElapsed::start(5)).unwrap();
        clock.ratchet_high_water(12345);
        static NEXT:std::sync::atomic::AtomicU64=std::sync::atomic::AtomicU64::new(0);
        let leaf=std::env::temp_dir().join(format!("build8-modeled-replacement-barrier-{}-{}",
            std::process::id(),NEXT.fetch_add(1,Ordering::SeqCst)));
        std::fs::create_dir(&leaf).unwrap();let anchor=leaf.join("clock.anchor");
        let (store,_)=AnchorStore::open(ClockStateDir::unlocked_for_test(&anchor));
        let store=Arc::new(Mutex::new(store));
        let (state,_,_)=modeled_state();let state=Arc::new(Mutex::new(state));
        struct AfterUnlock {state:Weak<Mutex<State>>,observed:std::sync::atomic::AtomicBool}
        impl std::task::Wake for AfterUnlock {
            fn wake(self:Arc<Self>) {
                let state=self.state.upgrade().unwrap();
                assert!(state.try_lock().unwrap().stopped);
                self.observed.store(true,Ordering::SeqCst);
            }
        }
        let wake=Arc::new(AfterUnlock {state:Arc::downgrade(&state),
            observed:std::sync::atomic::AtomicBool::new(false)});
        state.lock().unwrap().waiting=Some(Waker::from(wake.clone()));
        let stop=StopHandle {state:state.clone(),clock:Arc::downgrade(&clock),
            store:Some(Arc::downgrade(&store))};
        let token=stop.freeze_for_replacement().unwrap();
        assert!(wake.observed.load(Ordering::SeqCst));
        assert!(state.lock().unwrap().check().is_err());
        drop(store);
        assert!(stop.store.as_ref().unwrap().upgrade().is_none());
        let (successor,loaded)=AnchorStore::open(ClockStateDir::unlocked_for_test(&anchor));
        assert_eq!(loaded.high_water_ms,12345);successor.accept_replacement(token).unwrap();
        assert!(stop.freeze_for_replacement().is_err());
    }
}
