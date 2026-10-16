//! SOURCE-ONLY native NTS -> existing holdover engine bridge.
//! No diagnostic JSON input, current-wall-clock Era guess, cached authenticity flag,
//! profile default, production startup factory or persisted qualification grant.
//! Authenticated deployment profile/Era/leap evidence and native restart qualification
//! remain explicit launch inputs; this is software implementation, not their proof.
use super::leap_policy::{LeapMemory, LeapObservation};
use super::{
    RestoreReport,
    anchor_store::{AnchorStore, LoadOutcome, Refusal, StoreCondition, ReplacementContinuity},
    state_dir::ClockStateDir,
};
use mutiny_clock_native_nts_v1::{self as nts, AuthenticatedObservation, Config, Leap};
use mutiny_consensus_v8::holdover_clock_v1::{
    ClockProfile, Elapsed, ElapsedSource, CalibrationResult, FRESH_VOTE_MAX_UNCERTAINTY_MS, HoldoverClock,
    INITIAL_CALIBRATION_MAX_UNCERTAINTY_MS, ROLL_ROUNDING_MS, SourceSample,
};
use std::sync::{Arc, Mutex, Weak};
type Result<T> = std::result::Result<T, String>;
struct NativeElapsed {
    span: u64,
}
impl ElapsedSource for NativeElapsed {
    fn read(&self) -> Option<Elapsed> {
        let (monotonic_ns, boottime_ns, boot_id) = nts::read_elapsed(self.span)?;
        Some(Elapsed {
            monotonic_ns,
            boottime_ns,
            boot_id,
        })
    }
}
// One latest COMPLETED attempt in RAM. No restart import, authority conversion,
// secret transcript logging or unbounded history. Failed export retains the
// genuine original report; a diagnostic error does not replace engine/storage
// errors or suppress the existing persistence call.
struct CompletedAcquisition {
    report:Option<std::result::Result<nts::RetainedAcquisition,(nts::AcquisitionReport,String)>>,
    engine:Option<CalibrationResult>, applied:Result<bool>, storage_action:PersistenceAction,
    storage:Result<()>,finished:Result<bool>,
}
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
enum PersistenceAction {Unavailable,StoreAbsent,CommitAttempt,RefreshHighWaterAttempt,
    LiveAnchorNoWrite,InvalidateAttempt,EmptyNoWrite}
pub(crate) struct NativeNtsBackend {
    config: Config,
    clock: Arc<HoldoverClock>,
    leap: Mutex<LeapMemory>,
    store: Option<Arc<Mutex<AnchorStore>>>,
    restore: Option<RestoreReport>,
    completed:Mutex<Option<CompletedAcquisition>>,
}
// Chrony's qualified profile remains exactly its existing one-aggregate/zero-fault
// contract. This separate adapter checks explicit N/f native source profile values.
pub(super) fn validate_profile(profile: &ClockProfile, config: &Config) -> Result<()> {
    profile
        .validate()
        .map_err(|e| format!("native NTS profile: {e:?}"))?;
    config
        .validate()
        .map_err(|e| format!("native NTS deployment: {e}"))?;
    let drift = |ms: u64| {
        ms.checked_mul(profile.drift_bound_ppb)?
            .checked_add(999_999_999)
            .map(|n| n / 1_000_000_000)
    };
    let operators = config
        .providers
        .iter()
        .map(|p| &p.operator)
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    if profile.min_sources < 3
        || profile.min_sources as usize > operators
        || profile.drift_bound_ppb == 0
        || profile.drift_bound_ppb != config.bounds.elapsed_drift_ppb
        || profile.max_calibration_half_width_ms > INITIAL_CALIBRATION_MAX_UNCERTAINTY_MS
        || profile.max_interval_half_width_ms > FRESH_VOTE_MAX_UNCERTAINTY_MS
        || config.bounds.maximum_interval_uncertainty_ns
            > profile
                .max_source_uncertainty_ms
                .checked_mul(1_000_000)
                .ok_or("native uncertainty overflow")?
        || profile
            .max_source_uncertainty_ms
            .checked_add(ROLL_ROUNDING_MS)
            .and_then(|n| n.checked_add(drift(1)?))
            .is_none_or(|n| n > profile.max_calibration_half_width_ms)
        || profile
            .max_calibration_half_width_ms
            .checked_add(drift(profile.max_holdover_ms).ok_or("native drift overflow")?)
            .is_none_or(|n| n > profile.max_interval_half_width_ms)
    {
        return Err("native NTS source/calibration/holdover budget refused".into());
    }
    Ok(())
}
// Only the module's TEST-VALUE harness constructs this backend at present.
// Real production startup still refuses Windows in HostClock::start. The private
// constructor cannot reinterpret an unverified public hash as profile authority.
impl NativeNtsBackend {
    /// Genuine engine without the ordinary-node AnchorStore. Protected owner
    /// persistence is performed by its serial lineage owner before publication.
    /// The opaque validated record is required; no public numeric/JSON issuer.
    pub(super) fn for_protected_owner(record:&super::native_nts_deployment_record::ValidatedRecord)
        ->Result<Self> {
        Self::initialize(record.record().profile().clone(),record.record().acquisition().clone())
    }
    fn initialize(profile: ClockProfile, config: Config) -> Result<Self> {
        validate_profile(&profile, &config)?;
        let clock = HoldoverClock::new(
            profile,
            Arc::new(NativeElapsed {
                span: config.bounds.maximum_sampling_span_ns,
            }),
        )
        .map_err(|e| format!("native engine: {e:?}"))?;
        Ok(Self {
            config,
            clock,
            leap: Mutex::new(LeapMemory::default()),
            store: None,
            restore: None,
            completed:Mutex::new(None),
        })
    }
    #[cfg(test)]
    fn new_test_value(profile: ClockProfile, config: Config) -> Result<Self> {
        Self::initialize(profile, config)
    }
    /// TEST-VALUE integration over the existing held native storage boundary.
    /// Stored bytes are diagnostic evidence and shorten-only ratchets, never
    /// authenticated source results or qualification after restart.
    #[cfg(test)]
    fn with_state_test_value(
        profile: ClockProfile,
        config: Config,
        state: ClockStateDir,
    ) -> Result<Self> {
        Self::with_state(profile, config, state)
    }
    // Private software initializer. No public production factory or deployment
    // approval is supplied by passing these numeric/configuration values.
    pub(super) fn with_state(
        profile: ClockProfile,
        config: Config,
        state: ClockStateDir,
    ) -> Result<Self> {
        Self::with_state_inner(profile, config, state, None)
    }
    pub(super) fn with_state_replacement(profile: ClockProfile, config: Config,
        state: ClockStateDir, continuity: ReplacementContinuity) -> Result<Self> {
        continuity.require_anchor(state.anchor_file())?;
        Self::with_state_inner(profile, config, state, Some(continuity))
    }
    fn with_state_inner(profile: ClockProfile, config: Config, state: ClockStateDir,
        continuity: Option<ReplacementContinuity>) -> Result<Self> {
        let mut backend = Self::initialize(profile, config)?;
        let (mut store, loaded) = AnchorStore::open(state);
        if let Some(continuity) = continuity {store.accept_replacement(continuity)?;}
        backend.clock.ratchet_high_water(loaded.high_water_ms);
        let report = match loaded.outcome {
            LoadOutcome::Empty => RestoreReport::Cold,
            LoadOutcome::Refused(refusal) => RestoreReport::Refused(refusal),
            LoadOutcome::Record(record) => {
                store.note_refused();
                match backend.clock.assess_restart(&record) {
                    Ok(evidence) => RestoreReport::NotGranted {
                        leap: backend
                            .leap
                            .lock()
                            .map_err(|_| "native leap state poisoned")?
                            .restore_claim(evidence.leap),
                        evidence,
                    },
                    Err(error) => RestoreReport::Refused(Refusal::Verification(error)),
                }
            }
        };
        backend.store = Some(Arc::new(Mutex::new(store)));
        backend.restore = Some(report);
        backend.push_leap()?;
        Ok(backend)
    }
    // Retained stop handles cannot keep the C8/C12 owner alive after the joined
    // service drops. Temporary upgrades occur only inside the service barrier.
    pub(super) fn replacement_stop_inputs(&self)
        -> (Weak<HoldoverClock>, Option<Weak<Mutex<AnchorStore>>>) {
        (Arc::downgrade(&self.clock), self.store.as_ref().map(Arc::downgrade))
    }
    /// Same C4/C5 storage contract as the existing host adapter: even an intact
    /// stale record cannot restore qualification. No protected-continuity claim.
    pub(super) fn persist(&self) -> Result<()> {
        self.persist_inner(&mut None)
    }
    fn persist_inner(&self,action:&mut Option<PersistenceAction>)->Result<()> {
        let Some(store) = &self.store else {
            *action=Some(PersistenceAction::StoreAbsent);
            return Ok(());
        };
        let mut store = match store.lock() {
            Ok(store) => store,
            Err(poisoned) => {
                poisoned.into_inner().fail_closed();
                return Err("native anchor store poisoned; failed closed".into());
            }
        };
        let result = match self
            .clock
            .persisted(store.next_sequence(), super::leap_policy::POLICY_VERSION)
        {
            Some(record) if store.needs_write(&record) => {
                *action=Some(PersistenceAction::CommitAttempt);store.commit(&record)
            },
            Some(record) => {
                *action=Some(PersistenceAction::RefreshHighWaterAttempt);store.refresh_high_water(record.high_water_ms)
            },
            None if self.clock.anchor_interval_ms().is_some() => {
                *action=Some(PersistenceAction::LiveAnchorNoWrite);Ok(())
            },
            None if store.live_record() => {
                *action=Some(PersistenceAction::InvalidateAttempt);store.invalidate(self.clock.persisted_high_water())
            },
            None => {*action=Some(PersistenceAction::EmptyNoWrite);Ok(())},
        };
        const { assert!(!AnchorStore::GRANTS_RESTART_QUALIFICATION) };
        if result.is_err() && store.condition() == StoreCondition::StaleNotInvalidated {
            return Err(
                "native stale anchor could not be invalidated; it grants no restart qualification"
                    .into(),
            );
        }
        result
    }
    fn push_leap(&self) -> Result<()> {
        let memory = self.leap.lock().map_err(|_| "native leap state poisoned")?;
        let view = memory.view(self.clock.anchor_interval_ms().map(|r| r.0));
        if !self.clock.set_leap_view(view) {
            return Err("native elapsed unavailable; leap view not installed".into());
        }
        Ok(())
    }
    async fn calibrate_once(&self) -> Result<bool> {
        let acquired=nts::acquire(self.config.clone()).await
            .map_err(|e|format!("native acquisition: {e}"));
        self.finish_acquired(acquired)
    }
    pub(super) fn finish_calibration(&self, result: Result<bool>) -> Result<bool> {
        // Acquisition, conversion and leap errors also reach the storage gate.
        // A failed update retains the original bounded anchor and its age; an
        // independently expired anchor is invalidated by persist's C4/C5 rule.
        Self::finish_results(result,self.persist())
    }
    fn finish_results(result:Result<bool>,storage:Result<()>)->Result<bool> {
        match (result, storage) {
            (result, Ok(())) => result,
            (Ok(_), Err(storage)) => Err(storage),
            (Err(acquisition), Err(storage)) => Err(format!(
                "{acquisition}; native storage persistence also refused: {storage}"
            )),
        }
    }
    /// Called only after the service's acquired-result selection/stop check,
    /// synchronously before its post-finish check. No await or caller callback.
    pub(super) fn finish_acquired(&self,acquired:Result<nts::AcquisitionReport>)->Result<bool> {
        let mut engine=None;
        let (report,applied)=match acquired {
            Ok(report)=>{let applied=self.apply_report_inner(&report,&mut engine,true);(Some(report),applied)},
            Err(error)=>(None,Err(error)),
        };
        // Exactly one existing persist call, even on acquisition/conversion/
        // engine/leap refusal. Preserve both errors through the original match.
        let mut storage_action=None;let storage=self.persist_inner(&mut storage_action);
        let finished=Self::finish_results(applied.clone(),storage.clone());
        // A distinct POST-FINISH retention capture, not engine/anchor timing.
        let report=report.map(|report|nts::try_retain_acquisition(report,&self.config)
            .map_err(|(report,error)|(report,error.to_string())));
        let completed=CompletedAcquisition{report,engine,applied,
            storage_action:storage_action.unwrap_or(PersistenceAction::Unavailable),storage,finished:finished.clone()};
        // Diagnostic retention cannot grant time or change the already chosen
        // outcome. Poisoned diagnostic memory is overwritten with this result.
        match self.completed.lock() {
            Ok(mut slot)=>*slot=Some(completed),
            Err(poisoned)=>*poisoned.into_inner()=Some(completed),
        }
        finished
    }
    pub(super) fn config(&self) -> &Config { &self.config }
    pub(super) fn clock(&self) -> Arc<HoldoverClock> { self.clock.clone() }
    /// Actual live engine and complete leap memory, under the serialized owner
    /// barrier. No serialized acquisition or IPC request can create this pair.
    pub(super) fn protected_checkpoint(&self,sequence:u64)
        ->Result<Option<(mutiny_consensus_v8::holdover_clock_v1::ProtectedCheckpoint,[u8;27])>> {
        let memory=self.leap.lock().map_err(|_|"protected leap state poisoned")?;
        let Some(checkpoint)=self.clock.protected_checkpoint(sequence,super::leap_policy::POLICY_VERSION)
            else{return Ok(None);};
        if memory.view(Some(checkpoint.anchor().lower_ms))!=checkpoint.anchor().leap.view {
            return Err("live protected leap memory differs from engine".into());
        }
        Ok(Some((checkpoint,memory.protected_document())))
    }
    /// Private dedicated-owner route ONLY after the same held native lineage,
    /// final journal dominance, binding and selected current qualification gates.
    /// Legacy anchor-store restoration never calls this method.
    pub(super) fn restore_protected_record(&self,record:&super::protected_clock_lineage_v1::ProtectedRecord)
        ->Result<()> {
        let memory=LeapMemory::from_protected_document(record.leap_memory()).map_err(str::to_owned)?;
        let checkpoint=record.checkpoint();
        let view=memory.view(Some(checkpoint.anchor().lower_ms));
        let mut leap=self.leap.lock().map_err(|_|"protected leap state poisoned")?;
        self.clock.restore_protected_same_boot(checkpoint,super::leap_policy::POLICY_VERSION,view)
            .map_err(|e|format!("protected same-boot engine restoration refused: {e:?}"))?;
        *leap=memory;Ok(())
    }
    /// Read-only remote-consumer reconstruction. The caller MUST first own the
    /// live authenticated installed-owner quote and its exact selected binding.
    /// This method authenticates nothing. Ordinary elapsed age/continuity loss
    /// is unavailability, rather than a storage/channel corruption claim.
    pub(super) fn assess_consumer_record(&self,record:&super::protected_clock_lineage_v1::ProtectedRecord)
        ->Result<bool> {
        let memory=LeapMemory::from_protected_document(record.leap_memory()).map_err(str::to_owned)?;
        let checkpoint=record.checkpoint();let view=memory.view(Some(checkpoint.anchor().lower_ms));
        let mut leap=self.leap.lock().map_err(|_|"consumer leap state poisoned")?;
        match self.clock.restore_protected_same_boot(checkpoint,super::leap_policy::POLICY_VERSION,view) {
            Ok(_)=>{*leap=memory;Ok(true)},
            Err(mutiny_consensus_v8::holdover_clock_v1::AnchorError::Unqualified(_))=>Ok(false),
            Err(error)=>Err(format!("consumer protected checkpoint invalid: {error:?}")),
        }
    }
    pub(super) fn restore_report(&self) -> Option<&RestoreReport> { self.restore.as_ref() }
    #[cfg(test)]
    pub(super) fn replace_elapsed_private_test(&mut self,
        elapsed: Arc<dyn ElapsedSource>) -> Result<()> {
        if self.clock.anchor_interval_ms().is_some() { return Err("TEST elapsed replacement after calibration refused".into()); }
        self.clock=HoldoverClock::new(self.clock.profile().clone(),elapsed)
            .map_err(|e| format!("TEST elapsed engine: {e:?}"))?;
        self.push_leap()
    }
    pub(super) fn apply_report(&self, report: &nts::AcquisitionReport) -> Result<bool> {
        self.apply_report_inner(report,&mut None,false)
    }
    fn apply_report_inner(&self,report:&nts::AcquisitionReport,engine:&mut Option<CalibrationResult>,
        recorded:bool)->Result<bool> {
        if !report.matches_config(&self.config) {
            return Err("native authenticated result belongs to a different fixed configuration".into());
        }
        // Every accepted input is the library's non-Deserialize private-result type.
        // Sample reconstruction never accepts serialized diagnostic receipt data.
        let samples = report
            .accepted()
            .iter()
            .map(sample)
            .collect::<Result<Vec<_>>>()?;
        let enough = report.usable_operator_count() >= self.clock.profile().min_sources as usize;
        let coherent = report
            .accepted()
            .first()
            .map(|o| o.leap())
            .filter(|leap| enough && report.accepted().iter().all(|o| o.leap() == *leap));
        {
            let mut memory = self.leap.lock().map_err(|_| "native leap state poisoned")?;
            if let Some(leap) = coherent {
                let lo = samples
                    .iter()
                    .map(|s| s.utc_ms.saturating_sub(s.uncertainty_ms))
                    .min()
                    .ok_or("empty native set")?;
                let hi = samples
                    .iter()
                    .map(|s| {
                        s.utc_ms
                            .checked_add(s.uncertainty_ms)
                            .ok_or_else(||String::from("native interval overflow"))
                    })
                    .collect::<Result<Vec<_>>>()?
                    .into_iter()
                    .max()
                    .ok_or("empty native set")?;
                let qualified = samples
                    .iter()
                    .all(|s| s.uncertainty_ms <= self.clock.profile().max_source_uncertainty_ms);
                let obs = match leap {
                    Leap::Clear => LeapObservation::Normal,
                    Leap::Insert => LeapObservation::Insert,
                    Leap::Delete => LeapObservation::Delete,
                };
                memory.observe(obs, Some((lo, hi)), qualified);
            } else {
                // Individual or conflicting leap flags may only shorten a horizon.
                // No single operator clears a leap event or qualifies a calibration.
                for (o, s) in report.accepted().iter().zip(&samples) {
                    if o.leap() != Leap::Clear {
                        memory.observe_unverified(
                            (
                                s.utc_ms
                                    .checked_sub(s.uncertainty_ms)
                                    .ok_or("native interval underflow")?,
                                s.utc_ms
                                    .checked_add(s.uncertainty_ms)
                                    .ok_or("native interval overflow")?,
                            ),
                            self.clock.anchor_interval_ms().map(|r| r.0),
                        );
                    }
                }
            }
        }
        self.push_leap()?;
        if !enough || coherent.is_none() {
            return Err("native NTS requires usable source diversity and coherent leap evidence; existing bounded holdover retained".into());
        }
        let result=if recorded {
            let captured=self.clock.calibrate_recorded(&samples);let outcome=captured.outcome();
            *engine=Some(captured);outcome
        }else {self.clock.calibrate(&samples)}
            .map_err(|e|format!("native calibration: {e:?}"));
        self.push_leap()?;
        result
    }
}
fn sample(o: &AuthenticatedObservation) -> Result<SourceSample> {
    let i = o.interval();
    let (utc_ms, uncertainty_ms) = outward_ms(i.lower_posix_ns, i.upper_posix_ns)?;
    Ok(SourceSample {
        source: o.operator().into(),
        authenticated: true,
        utc_ms,
        uncertainty_ms,
        at: Elapsed {
            monotonic_ns: i.active_ns,
            boottime_ns: i.inclusive_ns,
            boot_id: i.boot_id,
        },
    })
}
fn outward_ms(lower: u64, upper: u64) -> Result<(u64, u64)> {
    let lo = lower / 1_000_000;
    let hi = upper
        .checked_add(999_999)
        .ok_or("native upper rounding overflow")?
        / 1_000_000;
    let width = hi.checked_sub(lo).ok_or("native interval ordering")?;
    let mid = lo
        .checked_add(width / 2)
        .ok_or("native midpoint overflow")?;
    let half = width.checked_add(1).ok_or("native width overflow")? / 2;
    mid.checked_sub(half).ok_or("native interval underflow")?;
    mid.checked_add(half).ok_or("native interval overflow")?;
    Ok((mid, half))
}
#[cfg(test)]
mod tests {
    use super::*;
    use mutiny_consensus_v8::holdover_clock_v1::{ClockError, LeapView};
    use std::path::PathBuf;
    #[test]
    fn modeled_completed_acquisition_failure_retains_exact_error_storage_and_no_report_or_engine_claim() {
        let backend=NativeNtsBackend::new_test_value(development_profile(),development_config()).unwrap();
        let failure="PUBLIC MODELED acquisition refusal".to_owned();
        assert_eq!(backend.finish_acquired(Err(failure.clone())),Err(failure.clone()));
        let retained=backend.completed.lock().unwrap();let retained=retained.as_ref().unwrap();
        assert!(retained.report.is_none() && retained.engine.is_none());
        assert_eq!(retained.applied,Err(failure.clone()));assert_eq!(retained.storage,Ok(()));
        assert_eq!(retained.storage_action,PersistenceAction::StoreAbsent);
        assert_eq!(retained.finished,Err(failure));
        assert!(backend.clock.anchor_interval_ms().is_none());
    }

    #[derive(Clone)]
    struct FixedElapsed(Elapsed);
    impl ElapsedSource for FixedElapsed {
        fn read(&self) -> Option<Elapsed> {
            Some(self.0.clone())
        }
    }
    fn development_profile() -> ClockProfile {
        ClockProfile {
            max_source_uncertainty_ms: 200,
            max_calibration_half_width_ms: 250,
            min_sources: 3,
            max_faulty_sources: 1,
            drift_bound_ppb: 100_000,
            max_holdover_ms: 10_000,
            max_interval_half_width_ms: 1_000,
            max_suspend_gap_ms: 50,
            confirm_calibrations: 1,
        }
    }
    fn development_config() -> Config {
        Config {
            providers: (1..=3)
                .map(|n| nts::Provider {
                    hostname: format!("source{n}.invalid"),
                    operator: format!("Operator{n}"),
                    key_establishment_port: 4460,
                    no_smear_profile_evidence_sha256: [n; 32],
                })
                .collect(),
            timeout_seconds: 10,
            bounds: nts::AcquisitionBounds {
                era_lower_posix_ns: 1_577_836_800_000_000_000,
                era_upper_posix_ns: 2_208_988_800_000_000_000,
                era_context_sha256: "a".repeat(64),
                maximum_sampling_span_ns: 250_000_000,
                wall_timestamp_uncertainty_ns: 1_000_000,
                elapsed_drift_ppb: 100_000,
                maximum_round_trip_ns: 1_000_000_000,
                maximum_interval_uncertainty_ns: 200_000_000,
            },
        }
    }
    fn public_native_case(name: &str) -> PathBuf {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let root = PathBuf::from(
            std::env::var_os("BUILD8_NATIVE_NTS_TEST_ROOT")
                .expect("reviewed runner must provide an isolated protected public TEST root"),
        );
        assert!(root.is_absolute() && root.is_dir());
        assert!(
            !std::fs::symlink_metadata(&root)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let leaf = root.join(format!(
            "native-nts-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        ));
        assert!(!leaf.exists());
        println!(
            "PUBLIC native NTS storage evidence retained: {}",
            leaf.display()
        );
        leaf.join("clock.anchor")
    }
    // These controlled samples exercise the adapter's engine/storage boundary.
    // They do not construct AuthenticatedObservation or attest a real NTS exchange.
    fn seed_controlled_engine(backend: &mut NativeNtsBackend) {
        let at = NativeElapsed {
            span: backend.config.bounds.maximum_sampling_span_ns,
        }
        .read()
        .expect("actual native elapsed backend required");
        backend.clock =
            HoldoverClock::new(development_profile(), Arc::new(FixedElapsed(at.clone()))).unwrap();
        assert!(backend.clock.set_leap_view(LeapView::Clear {
            valid_until_ms: u64::MAX,
        }));
        let samples: Vec<_> = (1..=3)
            .map(|n| SourceSample {
                source: format!("controlled-{n}"),
                authenticated: true,
                utc_ms: 1_792_022_400_000,
                uncertainty_ms: 20,
                at: at.clone(),
            })
            .collect();
        assert_eq!(backend.clock.calibrate(&samples), Ok(true));
    }

    #[test]
    fn rounded_native_ceiling_refuses_in_actual_engine_without_replacing_existing_anchor() {
        let at = Elapsed {
            monotonic_ns: 1_000_000,
            boottime_ns: 1_000_000,
            boot_id: 1,
        };
        let engine =
            HoldoverClock::new(development_profile(), Arc::new(FixedElapsed(at.clone()))).unwrap();
        assert!(engine.set_leap_view(LeapView::Clear {
            valid_until_ms: u64::MAX
        }));
        let samples = |center, half| {
            (1..=3)
                .map(|n| SourceSample {
                    source: format!("controlled-{n}"),
                    authenticated: true,
                    utc_ms: center,
                    uncertainty_ms: half,
                    at: at.clone(),
                })
                .collect::<Vec<_>>()
        };
        let (center, half) = outward_ms(1_000_000_000, 1_400_000_000).unwrap();
        assert_eq!(half, 200);
        assert_eq!(engine.calibrate(&samples(center, half)), Ok(true));
        let before = engine
            .persisted(1, super::super::leap_policy::POLICY_VERSION)
            .unwrap();
        let (center, half) = outward_ms(1_000_000_001, 1_400_000_001).unwrap();
        assert_eq!(half, 201);
        assert_eq!(
            engine.calibrate(&samples(center, half)),
            Err(ClockError::SourceUncertainty)
        );
        assert_eq!(
            engine.persisted(1, super::super::leap_policy::POLICY_VERSION),
            Some(before)
        );
    }

    #[test]
    fn native_replacement_same_held_lineage_preserves_floor_and_releases_old_owner() {
        // Actual native C8/C12 I/O is exercised if this future control runs;
        // calibration samples remain MODELED, never genuine NTS evidence.
        let anchor=public_native_case("replacement-lineage");
        let mut prior=NativeNtsBackend::with_state_test_value(development_profile(),
            development_config(),ClockStateDir::open(&anchor).unwrap()).unwrap();
        seed_controlled_engine(&mut prior);
        let floor=prior.clock.lower_bound_ms().unwrap().checked_add(1000).unwrap();
        prior.persist().unwrap();
        let (_,retained)=prior.replacement_stop_inputs();
        let token=prior.store.as_ref().unwrap().lock().unwrap().freeze_replacement(floor).unwrap();
        assert!(ClockStateDir::open(&anchor).is_err());
        drop(prior);
        assert!(retained.unwrap().upgrade().is_none(),"weak stop inputs do not retain storage");
        let successor=NativeNtsBackend::with_state_replacement(development_profile(),
            development_config(),ClockStateDir::open(&anchor).unwrap(),token).unwrap();
        assert_eq!(successor.clock.persisted_high_water(),floor);
        assert!(successor.clock.anchor_interval_ms().is_none());
        assert!(successor.clock.lower_bound_ms().is_none());
        assert!(matches!(successor.restore,Some(RestoreReport::Cold)));
        assert!(ClockStateDir::open(&anchor).is_err());
        drop(successor);assert!(ClockStateDir::open(&anchor).is_ok());
    }

    #[test]
    fn native_replacement_wrong_new_anchor_refuses_before_loading_or_writing() {
        let anchor=public_native_case("replacement-original");
        let prior=NativeNtsBackend::with_state_test_value(development_profile(),
            development_config(),ClockStateDir::open(&anchor).unwrap()).unwrap();
        let token=prior.store.as_ref().unwrap().lock().unwrap().freeze_replacement(9000).unwrap();
        drop(prior);
        let other=public_native_case("replacement-other");
        // Opening the fresh TEST owner creates only its lock; backend refusal
        // never loads/writes an anchor or mark at this wrong selected location.
        let state=ClockStateDir::open(&other).unwrap();
        assert!(NativeNtsBackend::with_state_replacement(development_profile(),
            development_config(),state,token).is_err());
        let mut mark=other.as_os_str().to_owned();mark.push(".seq");let mark=PathBuf::from(mark);
        for path in [&other, &mark] {
            assert!(matches!(std::fs::symlink_metadata(path),Err(e)
                if e.kind()==std::io::ErrorKind::NotFound));
        }
        assert!(ClockStateDir::open(&other).is_ok());
    }

    #[test]
    fn native_adapter_stored_anchor_reopens_same_identity_but_grants_no_restart_qualification() {
        let anchor = public_native_case("restart");
        let mut backend = NativeNtsBackend::with_state_test_value(
            development_profile(),
            development_config(),
            ClockStateDir::open(&anchor).unwrap(),
        )
        .unwrap();
        assert!(matches!(backend.restore, Some(RestoreReport::Cold)));
        seed_controlled_engine(&mut backend);
        backend.persist().unwrap();
        assert!(anchor.is_file());
        let raw = std::fs::read(&anchor).unwrap();
        assert!(
            ClockStateDir::open(&anchor).is_err(),
            "original live owner keeps the native lock"
        );
        drop(backend);
        let restarted = NativeNtsBackend::with_state_test_value(
            development_profile(),
            development_config(),
            ClockStateDir::open(&anchor).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            restarted.restore,
            Some(RestoreReport::NotGranted { .. })
        ));
        assert!(restarted.clock.anchor_interval_ms().is_none());
        assert!(restarted.clock.lower_bound_ms().is_none());
        assert_eq!(
            std::fs::read(&anchor).unwrap(),
            raw,
            "restart does not rewrite retained evidence"
        );
        restarted.persist().unwrap();
        assert_eq!(
            std::fs::read(&anchor).unwrap(),
            raw,
            "note_refused keeps historical evidence without treating it as live authority"
        );
        assert!(restarted.clock.lower_bound_ms().is_none());
        assert!(ClockStateDir::open(&anchor).is_err());
    }

    #[test]
    fn native_adapter_poisoned_store_invalidates_record_and_retains_original_lock() {
        let anchor = public_native_case("poison");
        let mut backend = NativeNtsBackend::with_state_test_value(
            development_profile(),
            development_config(),
            ClockStateDir::open(&anchor).unwrap(),
        )
        .unwrap();
        seed_controlled_engine(&mut backend);
        backend.persist().unwrap();
        assert!(anchor.is_file());
        let store = backend.store.as_ref().unwrap();
        let fault = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _held = store.lock().unwrap();
            panic!("controlled TEST store poisoning");
        }));
        assert!(fault.is_err() && store.is_poisoned());
        assert!(backend.persist().unwrap_err().contains("poisoned"));
        assert!(!anchor.exists());
        assert!(
            ClockStateDir::open(&anchor).is_err(),
            "failure never releases the owner lock"
        );
        drop(backend);
        let restarted = NativeNtsBackend::with_state_test_value(
            development_profile(),
            development_config(),
            ClockStateDir::open(&anchor).unwrap(),
        )
        .unwrap();
        assert!(matches!(restarted.restore, Some(RestoreReport::Cold)));
        assert!(restarted.clock.lower_bound_ms().is_none());
    }

    #[test]
    fn native_adapter_acquisition_failure_preserves_age_and_reports_actual_write_failure() {
        let anchor = public_native_case("failed-acquisition");
        let mut backend = NativeNtsBackend::with_state_test_value(
            development_profile(),
            development_config(),
            ClockStateDir::open(&anchor).unwrap(),
        )
        .unwrap();
        seed_controlled_engine(&mut backend);
        backend.persist().unwrap();
        let before = backend
            .clock
            .persisted(1, super::super::leap_policy::POLICY_VERSION)
            .unwrap();
        assert!(
            backend
                .finish_calibration(Err("controlled acquisition refusal".into()))
                .unwrap_err()
                .contains("controlled acquisition refusal")
        );
        assert_eq!(
            backend
                .clock
                .persisted(1, super::super::leap_policy::POLICY_VERSION),
            Some(before.clone())
        );
        // A real create-new temporary-directory collision is retained as failed
        // public evidence; no permission change or synthetic I/O-success flag.
        let blocked = PathBuf::from(format!("{}.seq.tmp", anchor.display()));
        std::fs::create_dir(&blocked).unwrap();
        assert!(backend.clock.set_leap_view(LeapView::Clear {
            valid_until_ms: u64::MAX - 1
        }));
        let error = backend
            .finish_calibration(Err("controlled acquisition refusal".into()))
            .unwrap_err();
        assert!(
            error.contains("controlled acquisition refusal")
                && error.contains("storage persistence also refused")
        );
        assert!(
            !anchor.exists(),
            "failed write invokes actual fail-closed removal"
        );
        assert!(blocked.is_dir(), "failed fixture remains evidence");
        let after = backend
            .clock
            .persisted(1, super::super::leap_policy::POLICY_VERSION)
            .unwrap();
        assert_eq!(
            (after.lower_ms, after.upper_ms, after.at),
            (before.lower_ms, before.upper_ms, before.at),
            "failed acquisition never re-baselines the calibration"
        );
        assert!(
            ClockStateDir::open(&anchor).is_err(),
            "original owner remains pinned after failure"
        );
    }
    #[test]
    fn integer_native_to_engine_intervals_round_outward_and_refuse_overflow() {
        for (lo, hi) in [
            (2_000_001, 2_999_999),
            (1_000_000, 1_000_001),
            (3_000_000, 3_000_000),
        ] {
            let (m, h) = outward_ms(lo, hi).unwrap();
            assert!((m - h) * 1_000_000 <= lo && (m + h) * 1_000_000 >= hi);
        }
        assert!(outward_ms(u64::MAX, u64::MAX).is_err());
        assert!(outward_ms(3_000_000, 1_000_000).is_err());
        // Nanosecond input exactly at a configured 200ms source ceiling can
        // widen to 201ms at the integer engine boundary. Preserve that refusal.
        let (center, half) = outward_ms(1_000_000_001, 1_400_000_001).unwrap();
        assert_eq!(half, 201);
        assert!((center - half) * 1_000_000 <= 1_000_000_001);
        assert!((center + half) * 1_000_000 >= 1_400_000_001);
    }
    #[test]
    fn native_source_profile_preserves_initial_fresh_and_fault_bounds_without_chrony_relaxation() {
        let p = ClockProfile {
            max_source_uncertainty_ms: 200,
            max_calibration_half_width_ms: 250,
            min_sources: 3,
            max_faulty_sources: 1,
            drift_bound_ppb: 100_000,
            max_holdover_ms: 1_000,
            max_interval_half_width_ms: 1_000,
            max_suspend_gap_ms: 50,
            confirm_calibrations: 1,
        };
        // Explicit DEVELOPMENT constants, no hardware qualification claim.
        let c = Config {
            providers: (1..=3)
                .map(|n| nts::Provider {
                    hostname: format!("source{n}.invalid"),
                    operator: format!("Operator{n}"),
                    key_establishment_port: 4460,
                    no_smear_profile_evidence_sha256: [n; 32],
                })
                .collect(),
            timeout_seconds: 10,
            bounds: nts::AcquisitionBounds {
                era_lower_posix_ns: 1_577_836_800_000_000_000,
                era_upper_posix_ns: 2_208_988_800_000_000_000,
                era_context_sha256: "a".repeat(64),
                maximum_sampling_span_ns: 250_000_000,
                wall_timestamp_uncertainty_ns: 1_000_000,
                elapsed_drift_ppb: 100_000,
                maximum_round_trip_ns: 1_000_000_000,
                maximum_interval_uncertainty_ns: 200_000_000,
            },
        };
        assert!(validate_profile(&p, &c).is_ok());
        assert!(
            p.validate_qualification().is_err(),
            "Chrony aggregate policy stays unchanged"
        );
        let mut bad = p.clone();
        bad.max_calibration_half_width_ms = 251;
        assert!(validate_profile(&bad, &c).is_err());
        let mut bad = p.clone();
        bad.max_faulty_sources = 2;
        assert!(validate_profile(&bad, &c).is_err());
        let mut bad = p.clone();
        bad.max_interval_half_width_ms = 1_001;
        assert!(validate_profile(&bad, &c).is_err());
        let mut bad = c.clone();
        bad.bounds.elapsed_drift_ppb += 1;
        assert!(validate_profile(&p, &bad).is_err());
        let backend = NativeNtsBackend::new_test_value(p, c).unwrap();
        assert!(backend.clock.anchor_interval_ms().is_none());
    }
}
