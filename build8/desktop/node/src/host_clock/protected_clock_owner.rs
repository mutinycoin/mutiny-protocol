//! Dedicated owner engine and durable-result gate. No installed-owner issuer,
//! Node-facing raw Commit/calibration, qualified restart or account setup.
//! The owner keeps the genuine NTS backend and held native lineage together;
//! consumers retain only a revocable Weak proxy. No numeric clock rules change.
#![allow(dead_code)]

use super::{native_nts_backend::NativeNtsBackend,
    native_nts_deployment_record::{ValidatedRecord,NativeSelectionGuard,canonical_value},
    protected_clock_lineage_v1::{Scope,Binding,Request,Operation,DocumentaryEngine}};
use mutiny_consensus_v8::holdover_clock_v1::TimeBasis;
use mutiny_consensus_v8::vote_clock_v1::{ClockReading,VoteClock};
use sha2::{Digest,Sha256};
use std::{future::poll_fn,sync::{Arc,Mutex,Weak},task::{Poll,Waker}};

type Result<T>=std::result::Result<T,String>;
/// Original held writer identities and complete journal digest, observed under
/// the lifetime writer locks. No caller can construct replacement authority.
#[derive(PartialEq,Eq)]
pub(super) struct NativeLineageObservation {
    head_id:[u8;24],journal_id:[u8;24],ancestors:Vec<[u8;24]>,
    journal_bytes:u64,journal_sha256:[u8;32],head:Vec<u8>,
}
impl NativeLineageObservation {
    pub(super) fn observed(head_id:[u8;24],journal_id:[u8;24],ancestors:Vec<[u8;24]>,
        journal:&mut std::fs::File,head:Vec<u8>)->Result<Self> {
        use std::io::{Read,Seek,SeekFrom};
        let journal_bytes=journal.metadata().map_err(|e|e.to_string())?.len();
        journal.seek(SeekFrom::Start(0)).map_err(|e|e.to_string())?;
        let mut hash=Sha256::new();let mut buffer=[0u8;8192];let mut left=journal_bytes;
        while left!=0 {let take=left.min(buffer.len() as u64) as usize;
            journal.read_exact(&mut buffer[..take]).map_err(|e|e.to_string())?;
            hash.update(&buffer[..take]);left-=take as u64;}
        let mut extra=[0u8;1];
        if journal.read(&mut extra).map_err(|e|e.to_string())?!=0
            ||journal.metadata().map_err(|e|e.to_string())?.len()!=journal_bytes {
            return Err("replacement journal changed during complete digest".into());}
        Ok(Self{head_id,journal_id,ancestors,journal_bytes,journal_sha256:hash.finalize().into(),head})
    }
}
pub(super) struct ClosedLineageContinuity {
    predecessor:Vec<u8>,placement:super::native_nts_installation::OwnerPlacementDocument,
    observation:NativeLineageObservation,scope:Scope,sequence:u64,floor:u64,
}
impl ClosedLineageContinuity {
    pub(super) fn require_successor(&self,raw:&[u8],placement:&super::native_nts_installation::OwnerPlacementDocument)->Result<()> {
        super::native_nts_deployment_record::require_successor(&self.predecessor,raw)
            .map_err(|e|format!("replacement predecessor differs: {e:?}"))?;
        if placement!=&self.placement{return Err("replacement principal/state/lineage/endpoint differs".into());}Ok(())
    }
}
pub(super) enum NativeLineage {
    #[cfg(target_os="linux")]
    Linux(super::protected_clock_linux_io::LinuxLineageIo),
    #[cfg(windows)]
    Windows(super::state_dir::WindowsProtectedHead),
}
impl NativeLineage {
    fn observation(&mut self)->Result<NativeLineageObservation> {
        match self {
            #[cfg(target_os="linux")]Self::Linux(io)=>io.replacement_observation(),
            #[cfg(windows)]Self::Windows(io)=>io.replacement_observation(),
        }
    }
    fn close(self)->std::result::Result<(),NativeCloseFailure> {
        match self {
            #[cfg(target_os="linux")]
            Self::Linux(io)=>io.close().map_err(NativeCloseFailure::Linux),
            #[cfg(windows)]
            Self::Windows(io)=>io.close().map_err(NativeCloseFailure::Windows),
        }
    }
    fn attach_for_reconciliation(&mut self,scope:&Scope)->Result<()> {
        match self {
            #[cfg(target_os="linux")]
            Self::Linux(io)=>io.attach_for_exact_reconciliation(scope),
            #[cfg(windows)]
            Self::Windows(io)=>io.attach_for_exact_reconciliation(scope).map_err(|e|e.to_string()),
        }
    }
    fn reconcile_pending_operation(&mut self,operation:&Operation)->Result<Vec<u8>> {
        match self {
            #[cfg(target_os="linux")]
            Self::Linux(io)=>io.reconcile_pending_operation(operation),
            #[cfg(windows)]
            Self::Windows(io)=>io.reconcile_pending_operation(operation).map_err(|e|e.to_string()),
        }
    }
    fn attach_journal(&mut self,scope:&Scope)->Result<()> {
        match self {
            #[cfg(target_os="linux")]
            Self::Linux(io)=>io.attach_existing_journal(scope),
            #[cfg(windows)]
            Self::Windows(io)=>io.attach_existing_journal(scope).map_err(|e|e.to_string()),
        }
    }
    fn operation_bounds(&mut self)->Result<(u64,u64)> {
        match self {
            #[cfg(target_os="linux")]
            Self::Linux(io)=>io.operation_bounds(),
            #[cfg(windows)]
            Self::Windows(io)=>io.operation_bounds().map_err(|e|e.to_string()),
        }
    }
    fn operation_reply(&mut self,operation:&Operation)->Result<Option<super::protected_clock_operation_journal::JournalReply>> {
        match self {
            #[cfg(target_os="linux")]
            Self::Linux(io)=>io.operation_reply(operation),
            #[cfg(windows)]
            Self::Windows(io)=>io.operation_reply(operation).map_err(|e|e.to_string()),
        }
    }
    fn execute_operation(&mut self,document:&mut DocumentaryEngine,request:Request)->Result<Vec<u8>> {
        match self {
            #[cfg(target_os="linux")]
            Self::Linux(io)=>io.execute_operation(document,request),
            #[cfg(windows)]
            Self::Windows(io)=>io.execute_operation(document,request).map_err(|e|e.to_string()),
        }
    }
    fn read(&mut self)->Result<Vec<u8>> {
        match self {
            #[cfg(target_os="linux")]
            Self::Linux(io)=>io.read_current(),
            #[cfg(windows)]
            Self::Windows(io)=>io.read_current().map_err(|e|e.to_string()),
        }
    }
    fn execute(&mut self,doc:&mut DocumentaryEngine,request:Request)->Result<Vec<u8>> {
        match self {
            #[cfg(target_os="linux")]
            Self::Linux(io)=>io.execute(doc,request),
            #[cfg(windows)]
            Self::Windows(io)=>io.execute(doc,request).map_err(|e|e.to_string()),
        }
    }
}
struct Core {
    backend:NativeNtsBackend,selection:NativeSelectionGuard,io:NativeLineage,
    document:DocumentaryEngine,binding:Binding,elapsed_context:[u8;32],channel_context:[u8;32],predecessor:Vec<u8>,placement:super::native_nts_installation::OwnerPlacementDocument,
}
impl Core {
    fn persist_stop_invalidation(&mut self)->Result<()> {
        self.selection.recheck()?;
        let mut stopped=self.document.for_stop_invalidation()
            .map_err(|e|format!("stop retains unresolved lineage: {e:?}"))?;
        if self.io.read()?!=stopped.current_document(){return Err("stop native head differs; no reconstruction".into());}
        let(sequence,floor)=self.io.operation_bounds()?;
        if stopped.sequence()<sequence || stopped.floor()<floor {
            return Err("stop head predates recorded operations".into());
        }
        let request=Request::invalidate_engine_floor(stopped.sequence(),
            self.backend.clock().persisted_high_water().max(stopped.floor()));
        // Native execute refuses sticky storage uncertainty. Its intent and
        // completion are synchronized/read back; no journal record is erased.
        self.io.execute(&mut stopped,request)?;
        self.selection.recheck()?;
        if self.io.read()?!=stopped.current_document(){return Err("stop completion head differs".into());}
        let(sequence,floor)=self.io.operation_bounds()?;
        if stopped.sequence()<sequence || stopped.floor()<floor{return Err("stop journal dominance differs".into());}
        self.document=stopped;self.document.unknown();Ok(())
    }
    fn current(&mut self)->Result<()> {
        let result=(|| {
            self.selection.recheck()?;
            if self.document.frozen() || self.io.read()?!=self.document.current_document() {
                return Err("protected clock current lineage differs or is frozen".into());
            }
            let (sequence,floor)=self.io.operation_bounds()?;
            if self.document.sequence()<sequence || self.document.floor()<floor {
                return Err("local head predates durable operation journal".into());
            }
            self.selection.recheck()
        })();
        if result.is_err() {self.document.unknown();}
        result
    }
    fn persist_engine(&mut self)->Result<()> {
        let result=self.persist_engine_inner();
        // Exhaustion, conversion and preflight failures also revoke consumers;
        // an acquisition caller cannot preserve a previously exposed basis.
        if result.is_err() {self.document.unknown();}
        result
    }
    fn persist_engine_inner(&mut self)->Result<()> {
        self.current()?;
        let expected=self.document.sequence();
        let sequence=expected.checked_add(1).ok_or("protected clock sequence exhausted")?;
        let clock=self.backend.clock();
        let request=match self.backend.protected_checkpoint(sequence)? {
            Some((checkpoint,leap))=>Request::from_protected_engine(expected,&self.binding,checkpoint,leap,None)
                .map_err(|e|format!("protected live engine record refused: {e:?}"))?,
            None=>Request::invalidate_engine_floor(expected,
                clock.persisted_high_water().max(self.document.floor())),
        };
        self.io.execute(&mut self.document,request)?;
        self.current()
    }
    fn deliver(&mut self)->Result<Option<u64>> {
        self.current()?;
        let floor=self.backend.clock().lower_bound_ms();
        // Reserve every delivery, including a current unqualification. No
        // result is exposed before native durable intent/completion readback.
        self.persist_engine()?;
        let Some(observed)=floor else {return Ok(None);};
        let floor=self.document.floor();
        if floor<observed {return Err("protected result reservation below returned floor".into());}
        // Storage may have taken long enough to expire/suspend the engine.
        // This second number is only a current predicate; it is not delivered.
        if self.backend.clock().lower_bound_ms().is_none_or(|current|current<floor) {
            return Ok(None);
        }
        self.current()?;Ok(Some(floor))
    }
    /// Fresh private quote preserves the exact historical operation outcome
    /// separately from the current durable engine checkpoint. A retry never
    /// creates a new logical operation or refreshes calibration age.
    fn fresh_operation(&mut self,expected_sequence:u64,operation:Operation)->Result<FreshOwnerQuote> {
        let identity=operation.identity();
        let outcome=self.deliver_operation(expected_sequence,operation)?;
        self.current()?;
        let capture=mutiny_clock_native_nts_v1::capture_elapsed_interval(
            self.backend.config().bounds.maximum_sampling_span_ns)
            .ok_or("fresh owner native interval unavailable")?;
        // The quote's current head includes a NEW durable full checkpoint,
        // even for an identical retry. This advances only engine publication;
        // the all-history operation receipt remains exactly the same.
        self.persist_engine()?;
        self.current()?;
        if self.document.sequence()<outcome.sequence || self.document.floor()<outcome.floor {
            return Err("fresh quote predates reserved operation".into());
        }
        let clock=self.backend.clock();
        let record=self.document.protected_record(&self.binding)
            .map_err(|e|format!("fresh quote checkpoint binding: {e:?}"))?;
        let elapsed=match record {
            Some(record)=>{
                if capture.boot_id()!=record.checkpoint().anchor().at.boot_id {
                    return Err("fresh quote boot changed".into());
                }
                let drift_ppb=clock.profile().drift_bound_ppb;
                if drift_ppb>=1_000_000_000 {return Err("fresh quote selected drift invalid".into());}
                Some(OwnerElapsedInterval{capture,drift_ppb,context:self.elapsed_context})
            },
            None=>None,
        };
        // This flag is only documentary owner eligibility. A delayed remote
        // consumer MUST reconstruct current eligibility using its own selected
        // native capture and guard, and deliver only outcome.floor.
        let eligible=elapsed.is_some() && clock.lower_bound_ms().is_some_and(|floor|floor>=outcome.floor);
        self.current()?;
        let head=self.document.current_document();
        if head.len()>579 {return Err("fresh quote protected head exceeds existing bound".into());}
        Ok(FreshOwnerQuote{outcome,current_sequence:self.document.sequence(),head,
            elapsed,eligible,operation:identity,channel_context:self.channel_context})
    }
    /// Normal registered consumers do not read the owner's private head or
    /// supply its authoritative counter. For the no-counter request grammar,
    /// the live owner selects its current sequence, or the exact historical
    /// predecessor for a byte-identical operation. No reset/replace action.
    fn fresh_selected_operation(&mut self,operation:Operation)->Result<FreshOwnerQuote> {
        self.current()?;
        let expected=match self.io.operation_reply(&operation)? {
            Some(record)=>record.sequence.checked_sub(1).ok_or("operation history zero sequence")?,
            None=>self.document.sequence(),
        };
        self.fresh_operation(expected,operation)
    }
    fn elapsed_interval(&mut self)->Result<Option<OwnerElapsedInterval>> {
        // No raw OS read bypasses the live owner, selected current guard or
        // durable publication barrier. An old decoded anchor is insufficient.
        if self.deliver()?.is_none() {return Ok(None);}
        self.current()?;
        let clock=self.backend.clock();
        let Some(before)=clock.persisted(self.document.sequence(),super::leap_policy::POLICY_VERSION)
            else {return Ok(None);};
        let capture=mutiny_clock_native_nts_v1::capture_elapsed_interval(
            self.backend.config().bounds.maximum_sampling_span_ns)
            .ok_or("protected elapsed native interval unavailable")?;
        if capture.boot_id()!=before.at.boot_id {
            return Err("protected elapsed boot changed".into());
        }
        self.current()?;
        if clock.lower_bound_ms().is_none() {return Ok(None);}
        let drift_ppb=clock.profile().drift_bound_ppb;
        if drift_ppb>=1_000_000_000 {return Err("protected elapsed selected drift invalid".into());}
        Ok(Some(OwnerElapsedInterval {capture,drift_ppb,context:self.elapsed_context}))
    }
    /// A reservation outcome and current qualification are deliberately
    /// distinct: retransmission never refreshes acquisition age. This resolves
    /// every completed durable operation. Neither history decoding nor an old
    /// outcome refreshes qualification; installed endpoint authority is separate.
    fn deliver_operation(&mut self,expected_sequence:u64,operation:Operation)->Result<ReservedReply> {
        self.current()?;
        if let Some(record)=self.io.operation_reply(&operation)? {
            let sequence=record.sequence;let floor=record.floor;
            if expected_sequence.checked_add(1)!=Some(sequence) {
                return Err("exact retry expected sequence changed".into());
            }
            let qualified=self.backend.clock().lower_bound_ms().is_some_and(|value|value>=floor);
            self.current()?;
            return Ok(ReservedReply{sequence,floor,qualified});
        }
        if expected_sequence!=self.document.sequence() {
            return Err("operation expected sequence differs".into());
        }
        let sequence=expected_sequence.checked_add(1).ok_or("protected sequence exhausted")?;
        let clock=self.backend.clock();
        let request=match self.backend.protected_checkpoint(sequence)? {
            Some((checkpoint,leap))=>Request::from_protected_engine(expected_sequence,&self.binding,checkpoint,leap,Some(operation)),
            None=>Request::invalidate_operation_floor(expected_sequence,
                clock.persisted_high_water().max(self.document.floor()),operation),
        }.map_err(|e|format!("protected operation record: {e:?}"))?;
        self.io.execute_operation(&mut self.document,request)?;
        self.current()?;
        let floor=self.document.floor();
        let qualified=self.backend.clock().lower_bound_ms().is_some_and(|value|value>=floor);
        self.current()?;
        Ok(ReservedReply{sequence:self.document.sequence(),floor,qualified})
    }
}
/// No public proof or historical qualification claim is made by a reservation.
pub(super) struct ReservedReply {pub(super) sequence:u64,pub(super) floor:u64,pub(super) qualified:bool}
/// Constructible only by the live serialized dedicated owner after durable
/// operation/history and a fresh durable checkpoint. Serialized bytes alone
/// are not consumer authority, qualification, or a public proof.
pub(super) struct FreshOwnerQuote {
    outcome:ReservedReply,current_sequence:u64,head:Vec<u8>,
    elapsed:Option<OwnerElapsedInterval>,eligible:bool,operation:[u8;32],channel_context:[u8;32],
}
impl FreshOwnerQuote {
    /// Fixed bounded PRIVATE implementation frame. The old 89-byte endpoint
    /// remains unchanged and cannot acquire fresh-quote authority. Remaining
    /// unused head bytes are canonical zeroes; no unbounded allocation/length.
    pub(super) fn encode(&self,context:[u8;32])->Result<[u8;775]> {
        if self.operation==[0;32] || context!=self.channel_context || self.head.len()>579
            || self.current_sequence<self.outcome.sequence {return Err("fresh quote frame binding refused".into());}
        let mut frame=[0u8;775];frame[..8].copy_from_slice(b"MCLCFQR2");
        frame[8..40].copy_from_slice(&self.operation);frame[40..72].copy_from_slice(&context);
        frame[72..80].copy_from_slice(&self.outcome.sequence.to_be_bytes());
        frame[80..88].copy_from_slice(&self.outcome.floor.to_be_bytes());
        frame[88..96].copy_from_slice(&self.current_sequence.to_be_bytes());
        frame[96]=u8::from(self.eligible);frame[97]=u8::from(self.elapsed.is_some());
        if let Some(elapsed)=&self.elapsed {
            frame[98..106].copy_from_slice(&elapsed.lower_ns().to_be_bytes());
            frame[106..114].copy_from_slice(&elapsed.upper_ns().to_be_bytes());
            frame[114..122].copy_from_slice(&elapsed.active_lower_ns().to_be_bytes());
            frame[122..130].copy_from_slice(&elapsed.active_upper_ns().to_be_bytes());
            frame[130..146].copy_from_slice(&elapsed.boot_id().to_be_bytes());
            frame[146..154].copy_from_slice(&elapsed.drift_ppb().to_be_bytes());
            frame[154..186].copy_from_slice(&elapsed.context());
        }
        // Eight reserved bytes remain zero for exact version-2 canonical grammar.
        frame[194..196].copy_from_slice(&(self.head.len() as u16).to_be_bytes());
        frame[196..196+self.head.len()].copy_from_slice(&self.head);Ok(frame)
    }
}
/// Opaque, freshly owner-gated inclusive elapsed interval. This is not a UTC
/// proof or an installed consumer issuer. Sampling and oscillator uncertainty
/// cannot be discarded by converting this to a scalar midpoint.
pub(super) struct OwnerElapsedInterval {
    capture:mutiny_clock_native_nts_v1::NativeElapsedInterval,drift_ppb:u64,context:[u8;32],
}
impl OwnerElapsedInterval {
    pub(super) fn lower_ns(&self)->u64 {self.capture.inclusive_lower_ns()}
    pub(super) fn upper_ns(&self)->u64 {self.capture.inclusive_upper_ns()}
    pub(super) fn active_lower_ns(&self)->u64 {self.capture.active_lower_ns()}
    pub(super) fn active_upper_ns(&self)->u64 {self.capture.active_upper_ns()}
    pub(super) fn boot_id(&self)->u128 {self.capture.boot_id()}
    pub(super) fn drift_ppb(&self)->u64 {self.drift_ppb}
    pub(super) fn context(&self)->[u8;32] {self.context}
}
struct State {core:Option<Core>,stopped:bool,waiter:Option<Waker>,failure:Option<String>,acquisition_active:bool,
    durable_stop:Option<Result<()>>}
impl State {
    fn live(&mut self)->Result<&mut Core> {
        if self.stopped {return Err("protected owner stopped".into());}
        let result=self.core.as_mut().ok_or("protected owner closed")?.current();
        if let Err(error)=result {self.fail(&error);return Err(error);}
        self.core.as_mut().ok_or_else(||"protected owner closed".into())
    }
    fn fail(&mut self,error:&str) {
        self.stopped=true;self.failure=Some(error.to_owned());
        if let Some(core)=self.core.as_mut() {core.document.unknown();}
    }
}

pub(super) struct ProtectedClockOwner {state:Arc<Mutex<State>>}
/// Actual native acquisition result, never a string-selected cancellation.
pub(super) enum ProtectedAcquisitionOutcome {Applied(bool),DurablyStoppedAfterNativeJoin}
pub(super) struct ProtectedOwnerStop {state:Weak<Mutex<State>>}
/// Borrowed SAME-owner lifetime writer lease, issued only after checked durable
/// stop. It never releases head/journal locks, creates state or accepts a bool.
#[cfg(target_os="linux")]
pub(super) struct StoppedOwnerNamespaceLease<'a> {state:std::sync::MutexGuard<'a,State>}
#[cfg(target_os="linux")]
impl StoppedOwnerNamespaceLease<'_> {
    pub(super) fn recheck(&mut self,placement:&super::native_nts_installation::OwnerPlacementDocument,record:&[u8])->Result<()> {
        if !self.state.stopped||self.state.acquisition_active||self.state.failure.is_some()
            ||!matches!(self.state.durable_stop,Some(Ok(()))) {return Err("namespace cleanup lacks exact checked stopped owner".into());}
        let core=self.state.core.as_mut().ok_or("namespace owner already closed")?;
        if &core.placement!=placement||core.predecessor!=record{return Err("namespace owner selection differs".into());}
        core.selection.recheck()?;
        let stopped=core.document.for_stop_invalidation().map_err(|e|format!("namespace stopped head: {e:?}"))?;
        if !stopped.stopped_final()||core.io.read()?!=stopped.current_document(){return Err("namespace stopped native head differs".into());}
        let(sequence,floor)=core.io.operation_bounds()?;
        if sequence>stopped.sequence()||floor>stopped.floor(){return Err("namespace stopped journal dominance differs".into());}
        core.selection.recheck()
    }
}
/// Revocable dispatch reference for the installed OS channel. This cannot keep
/// the owner, its native stores or acquisition alive, create/reset a lineage,
/// perform calibration or authorize replacement. Dropping it does not stop
/// the unique owner. Every operation still serializes through that owner's
/// live/current durable core.
pub(super) struct ProtectedOwnerDispatcher {state:Weak<Mutex<State>>}
impl ProtectedOwnerDispatcher {
    /// Same weak owner, never a caller-selected stop or a new strong owner.
    pub(super) fn stop_handle(&self)->ProtectedOwnerStop {
        ProtectedOwnerStop{state:self.state.clone()}
    }
    fn with_live<T>(&self,operation:impl FnOnce(&mut Core)->Result<T>)->Result<T> {
        let state=self.state.upgrade().ok_or("protected dispatch owner gone")?;
        let mut state=match state.lock() {
            Ok(state)=>state,
            Err(poisoned)=>{let mut state=poisoned.into_inner();
                state.fail("protected owner state poisoned");
                let wake=state.waiter.take();drop(state);if let Some(wake)=wake {wake.wake();}
                return Err("protected owner state poisoned".into());},
        };
        let result=state.live().and_then(operation);
        if let Err(error)=&result {state.fail(error);}
        let wake=if result.is_err(){state.waiter.take()}else{None};
        drop(state);if let Some(wake)=wake {wake.wake();}result
    }
    pub(super) fn channel_context(&self)->Result<[u8;32]> {
        self.with_live(|core|Ok(core.channel_context))
    }
    pub(super) fn reserve_operation(&self,expected_sequence:u64,operation:Operation)->Result<ReservedReply> {
        self.with_live(|core|core.deliver_operation(expected_sequence,operation))
    }
    pub(super) fn fresh_operation(&self,expected_sequence:u64,operation:Operation)->Result<FreshOwnerQuote> {
        self.with_live(|core|core.fresh_operation(expected_sequence,operation))
    }
    pub(super) fn fresh_selected_operation(&self,operation:Operation)->Result<FreshOwnerQuote> {
        self.with_live(|core|core.fresh_selected_operation(operation))
    }
}
/// Native close uncertainty remains owned. Windows failure retains exact raw
/// handles and known identities; no automatic close retry is permitted.
pub(super) enum NativeCloseFailure {
    #[cfg(target_os="linux")]
    Linux(super::protected_clock_linux_io::LinuxCloseFailure),
    #[cfg(windows)]
    Windows(super::state_dir::WindowsCloseFailure),
}
/// This is explicit lineage closure only. Installation/loaded-image guard
/// Drop remains ordinary RAII and supplies no complete owner-lifecycle token.
pub(super) struct OwnerLineageCloseFailure {
    errors:Vec<String>,native:Option<NativeCloseFailure>,
    // The installed selection remains owned after any native close outcome;
    // no RAII release is promoted to complete installed-guard closure.
    selection:Option<std::mem::ManuallyDrop<NativeSelectionGuard>>,
    // A dropped acquisition future cannot prove its source tasks were joined.
    // Keep the associated native ownership until process termination rather
    // than silently closing/reopening it or claiming a replacement token.
    unjoined:Option<std::mem::ManuallyDrop<Core>>,
}
pub(super) struct ClosedOwnerLineage {
    selection:std::mem::ManuallyDrop<NativeSelectionGuard>,continuity:ClosedLineageContinuity,
}
impl ClosedOwnerLineage {
    /// Narrow native head/journal/ancestor closure only. The installed current
    /// guard remains retained; this is NOT a replacement/whole-lifecycle token.
    pub(super) fn native_lineage_handles_closed(&self)->bool {true}
    pub(super) fn close_for_successor(self)->(std::result::Result<super::native_nts_deployment_record::SelectionRetainedClose,
        std::mem::ManuallyDrop<NativeSelectionGuard>>,ClosedLineageContinuity) {
        (std::mem::ManuallyDrop::into_inner(self.selection).close_retained(),self.continuity)
    }
    /// Available only after SAME-owner checked durable stop and actual native
    /// writer close. Each selection/current holder is then explicitly consumed.
    pub(super) fn close_installed_retained(self)->std::result::Result<super::native_nts_deployment_record::SelectionRetainedClose,
        std::mem::ManuallyDrop<NativeSelectionGuard>> {
        std::mem::ManuallyDrop::into_inner(self.selection).close_retained()
    }
}
impl OwnerLineageCloseFailure {
    pub(super) fn description(&self)->String {
        let mut errors=self.errors.clone();
        if let Some(native)=&self.native {errors.push(match native {
            #[cfg(target_os="linux")]
            NativeCloseFailure::Linux(error)=>error.description(),
            #[cfg(windows)]
            NativeCloseFailure::Windows(error)=>error.description(),
        });}
        errors.join("; ")
    }
}
struct ProtectedBasis {state:Weak<Mutex<State>>}
struct AcquisitionLifetime {state:Weak<Mutex<State>>,armed:bool}
impl Drop for AcquisitionLifetime {
    fn drop(&mut self) {
        if !self.armed {return;}
        let Some(state)=self.state.upgrade() else {return;};
        let wake={let mut state=state.lock().unwrap_or_else(|p|p.into_inner());
            state.fail("acquisition future dropped before native task join confirmation");state.waiter.take()};
        if let Some(wake)=wake {wake.wake();}
    }
}
/// Retaining this proxy cannot keep an owner or native lineage alive.
pub(super) struct ProtectedElapsedProxy {state:Weak<Mutex<State>>}
impl ProtectedElapsedProxy {
    pub(super) fn capture(&self)->Result<Option<OwnerElapsedInterval>> {
        let state=self.state.upgrade().ok_or("protected elapsed owner gone")?;
        let mut state=match state.lock() {
            Ok(state)=>state,
            Err(poisoned)=>{let mut state=poisoned.into_inner();state.fail("protected owner state poisoned");
                let wake=state.waiter.take();drop(state);if let Some(wake)=wake {wake.wake();}
                return Err("protected owner state poisoned".into());},
        };
        let result=state.live().and_then(Core::elapsed_interval);
        if let Err(error)=&result {state.fail(error);}
        let wake=if result.is_err(){state.waiter.take()}else{None};
        drop(state);if let Some(wake)=wake {wake.wake();}result
    }
}
/// Concrete activation interface over the same revocable current owner. Every
/// capture retains both native endpoints and selected drift; there is no
/// scalar/midpoint, Instant, OS-wall or decoded-anchor fallback. Consensus's
/// opaque capture value alone is not an installed authority or public proof.
impl mutiny_consensus_v8::activation_attestation_v1::Elapsed for ProtectedElapsedProxy {
    fn elapsed(&self)->std::result::Result<std::time::Duration,
        mutiny_consensus_v8::activation_attestation_v1::Failure> {
        Err(mutiny_consensus_v8::activation_attestation_v1::Failure::Elapsed)
    }
    fn capture(&self)->std::result::Result<mutiny_consensus_v8::activation_attestation_v1::ElapsedCapture,
        mutiny_consensus_v8::activation_attestation_v1::Failure> {
        use mutiny_consensus_v8::activation_attestation_v1::{ElapsedCapture,Failure};
        // None is ordinary not-yet-qualified availability. The owner itself
        // remains available for genuine fresh acquisition; only the activation
        // caller receives refusal. Native/current/storage faults already freeze
        // at the owner boundary and revoke every Weak consumer.
        let current=ProtectedElapsedProxy::capture(self).map_err(|_|Failure::Elapsed)?
            .ok_or(Failure::Elapsed)?;
        ElapsedCapture::from_current_owner(std::time::Duration::from_nanos(current.lower_ns()),
            std::time::Duration::from_nanos(current.upper_ns()),current.boot_id(),
            current.context(),current.drift_ppb())
    }
}
impl TimeBasis for ProtectedBasis {
    fn lower_bound_ms(&self)->Option<u64> {
        let state=self.state.upgrade()?;
        let mut state=match state.lock() {
            Ok(state)=>state,
            Err(poisoned)=>{
                let mut state=poisoned.into_inner();state.fail("protected owner state poisoned");
                let wake=state.waiter.take();drop(state);if let Some(wake)=wake {wake.wake();}return None;
            },
        };
        let result=state.live().and_then(Core::deliver);
        if let Err(error)=&result {state.fail(error);}
        let wake=if result.is_err() {state.waiter.take()}else{None};
        drop(state);if let Some(wake)=wake {wake.wake();}
        result.ok().flatten()
    }
}
impl VoteClock for ProtectedBasis {
    fn reading(&self)->ClockReading {
        match self.lower_bound_ms() {
            Some(ms)=>ClockReading::Qualified{utc_seconds:ms/1000},
            None=>ClockReading::Unqualified,
        }
    }
}
impl ProtectedOwnerStop {
    /// The owned application and native acquisition use the SAME task waker.
    /// This observes revocation only; it neither exposes time nor writes state.
    pub(super) fn poll_stopped(&self,cx:&std::task::Context<'_>)->Poll<()> {
        let Some(state)=self.state.upgrade() else{return Poll::Ready(());};
        let mut state=match state.lock(){Ok(state)=>state,Err(poisoned)=>{
            let mut state=poisoned.into_inner();state.fail("owner application stop mutex poisoned");
            return Poll::Ready(());
        }};
        if state.stopped{return Poll::Ready(());}
        state.waiter=Some(cx.waker().clone());Poll::Pending
    }
    /// One explicit checked shutdown. A prior in-memory fault cannot supply
    /// durability credit; persist only an exact final-head invalidation, while
    /// pending/foreign/native uncertainty remains frozen. A failed checked
    /// attempt is recorded and never silently retried.
    pub(super) fn stop_checked(&self)->Result<()> {
        let state=self.state.upgrade().ok_or("protected owner gone before checked stop")?;
        let (result,wake)={
            let mut state=match state.lock(){Ok(state)=>state,Err(poisoned)=>{
                let mut state=poisoned.into_inner();state.fail("owner stop state poisoned");
                let wake=state.waiter.take();drop(state);if let Some(wake)=wake{wake.wake();}
                return Err("owner stop state poisoned; durability unknown".into());
            }};
            let result=if let Some(previous)=&state.durable_stop {
                previous.clone()
            }else{
                // Revoke in-memory consumers BEFORE any potentially blocking
                // native storage transition. This mutex serializes the actual
                // invalidation with acquisition and every channel operation.
                state.stopped=true;
                let result=state.core.as_mut().ok_or_else(||"owner core closed before checked stop".to_string())
                    .and_then(Core::persist_stop_invalidation);
                if let Err(error)=&result{state.fail(error);}
                state.durable_stop=Some(result.clone());result
            };
            (result,state.waiter.take())
        };
        if let Some(wake)=wake{wake.wake();}result
    }
    pub(super) fn stop(&self) {
        let Some(state)=self.state.upgrade() else {return;};
        let wake={let mut state=match state.lock(){Ok(state)=>state,Err(p)=>p.into_inner()};
            if !state.stopped {
                if let Some(core)=state.core.as_mut() {
                    let result=(|| {
                        core.current()?;
                        let request=Request::invalidate_engine_floor(core.document.sequence(),
                            core.backend.clock().persisted_high_water().max(core.document.floor()));
                        core.io.execute(&mut core.document,request)?;core.current()
                    })();
                    if let Err(error)=result {state.fail(&error);}
                }
            }
            state.stopped=true;state.waiter.take()};
        if let Some(wake)=wake {wake.wake();}
    }
}
// Constructor refusal/unwind must not release an installed selection or its
// native writer. Originals enter ManuallyDrop before the custody allocation;
// the allocation exists before validation/reconciliation/restoration effects.
// Only explicit successful publication removes the retained value.
pub(super) struct ConstructingProtectedOwner<T> {
    value:Option<Box<std::mem::ManuallyDrop<T>>>,
}
impl<T> ConstructingProtectedOwner<T> {
    pub(super) fn retain(value:T)->Self {
        let original=std::mem::ManuallyDrop::new(value);
        Self{value:Some(Box::new(original))}
    }
    pub(super) fn get_mut(&mut self)->&mut T {
        &mut **self.value.as_mut().expect("retained original owner construction")
    }
    pub(super) fn publish(mut self)->T {
        std::mem::ManuallyDrop::into_inner(*self.value.take().expect("one owner construction publication"))
    }
}
impl<T> Drop for ConstructingProtectedOwner<T> {
    fn drop(&mut self) {
        if let Some(original)=self.value.take(){let _=Box::into_raw(original);}
    }
}
impl ProtectedClockOwner {
    /// Private coupling over an already opaque validated selection and an
    /// existing dedicated-principal native store. The externally installed
    /// lineage pin must be supplied by the still-missing protected placement
    /// issuer; this initializer does not authenticate that pin or create it.
    pub(super) fn from_selected(record:ValidatedRecord,mut selection:NativeSelectionGuard,
        mut io:NativeLineage,placement:super::native_nts_installation::OwnerPlacementDocument)->Result<Self> {
        Self::from_selected_inner(record,selection,io,placement,None,None)
    }
    pub(super) fn from_selected_reconciled(record:ValidatedRecord,selection:NativeSelectionGuard,
        io:NativeLineage,placement:super::native_nts_installation::OwnerPlacementDocument,operation:Operation)->Result<Self> {
        Self::from_selected_inner(record,selection,io,placement,Some(operation),None)
    }
    pub(super) fn from_selected_successor(record:ValidatedRecord,selection:NativeSelectionGuard,
        io:NativeLineage,placement:super::native_nts_installation::OwnerPlacementDocument,
        continuity:ClosedLineageContinuity)->Result<Self> {
        Self::from_selected_inner(record,selection,io,placement,None,Some(continuity))
    }
    fn from_selected_inner(record:ValidatedRecord,mut selection:NativeSelectionGuard,
        mut io:NativeLineage,placement:super::native_nts_installation::OwnerPlacementDocument,reconciliation:Option<Operation>,continuity:Option<ClosedLineageContinuity>)->Result<Self> {
        let mut construction=ConstructingProtectedOwner::retain((selection,io));
        let (selection,io)=construction.get_mut();
        let installed_lineage=placement.lineage();
        if let Some(proof)=&continuity{proof.require_successor(record.record().canonical(),&placement)?;}
        if installed_lineage==[0;32] {return Err("installed protected lineage absent".into());}
        selection.recheck()?;
        let value=canonical_value(record.record().canonical()).map_err(|e|format!("selected owner context: {e:?}"))?;
        let digest=|v:&serde_json::Value|->Result<[u8;32]> {
            let text=v.as_str().ok_or("selected owner digest type")?;let mut out=[0;32];
            hex::decode_to_slice(text,&mut out).map_err(|_|"selected owner digest encoding")?;Ok(out)
        };
        let scope=Scope::selected_document(digest(&value["binding"]["genesis_sha256"])?,
            digest(&value["binding"]["network_sha256"])?,digest(&value["binding"]["rule_sha256"])?,installed_lineage);
        let mut code=Sha256::new();code.update(b"MCLC4-CODE-CONFIG-1");
        code.update(digest(&value["context"]["code_sha256"])?);code.update(digest(&value["context"]["config_sha256"])?);
        let binding=Binding::selected_document(Sha256::digest(record.record().canonical()).into(),
            digest(&value["context"]["qualification_sha256"])?,code.finalize().into(),
            Sha256::digest(serde_json::to_vec(&value["acquisition"]).map_err(|_|"selected provider encoding")?).into(),
            record.record().profile().id());
        let reconciled=reconciliation.is_some();
        if let Some(operation)=reconciliation {
            selection.recheck()?;
            io.attach_for_reconciliation(&scope)?;
            selection.recheck()?;
            // The native journal itself supplies the only authorized plan.
            // Caller bytes must match identity+content exactly, and cannot
            // request a new Commit, counter reset or an old authoritative head.
            io.reconcile_pending_operation(&operation)?;
            selection.recheck()?;
        }
        let document=DocumentaryEngine::from_document(&scope,&io.read()?)
            .map_err(|e|format!("protected owner startup head: {e:?}"))?;
        if document.frozen() {return Err("protected pending head requires exact recovery; no automatic thaw".into());}
        if !reconciled {io.attach_journal(&scope)?;}
        if let Some(proof)=continuity {
            let stopped=document.for_stop_invalidation().map_err(|e|format!("successor stopped head: {e:?}"))?;
            if !stopped.stopped_final()||stopped.retained_scope()!=proof.scope
                ||stopped.sequence()!=proof.sequence||stopped.floor()!=proof.floor
                ||io.observation()?!=proof.observation {
                return Err("successor original stopped head/journal/native identities differ".into());}
            let(sequence,floor)=io.operation_bounds()?;
            if sequence>stopped.sequence()||floor>stopped.floor(){return Err("successor journal dominance differs".into());}
            selection.recheck()?;
        }
        let predecessor=record.record().canonical().to_vec();
        let backend=NativeNtsBackend::for_protected_owner(&record)?;
        // Durable consumed floor can only make fresh calibration stricter.
        // Current decoded anchors do not install qualification after restart.
        backend.clock().ratchet_high_water(document.floor());
        selection.recheck()?;
        // Fresh capability incarnation is distinct from durable continuity.
        // Restart/replacement cannot reuse a previous permit's elapsed context.
        // Random bytes neither qualify the clock nor alter durable lineage.
        let mut incarnation=[0u8;32];
        getrandom::getrandom(&mut incarnation).map_err(|_|"protected elapsed incarnation unavailable")?;
        if incarnation==[0;32] {return Err("protected elapsed incarnation empty".into());}
        let mut context=Sha256::new();context.update(b"MCLC4-ELAPSED-INCARNATION-1");
        context.update(scope.journal_context());context.update(binding.deployment());context.update(incarnation);
        let elapsed_context=context.finalize().into();
        let mut context=Sha256::new();context.update(b"MCLC4-CHANNEL-CONTEXT-1");
        context.update(scope.journal_context());context.update(binding.deployment());
        let channel_context=context.finalize().into();
        let (selection,io)=construction.publish();
        let mut construction=ConstructingProtectedOwner::retain(Core{
            backend,selection,io,document,binding,elapsed_context,channel_context,predecessor,placement});
        let core=construction.get_mut();core.current()?;
        if let Some(record)=core.document.protected_record(&core.binding)
            .map_err(|e|format!("protected startup record binding: {e:?}"))?.cloned() {
            // Authentication comes from this still-held dedicated store/current
            // installation, exact final head/journal dominance and binding;
            // decoded checkpoints outside this private route remain evidence.
            let(_,_,boot)=mutiny_clock_native_nts_v1::read_elapsed(core.backend.config().bounds.maximum_sampling_span_ns)
                .ok_or("protected restart native elapsed unavailable")?;
            if boot==record.checkpoint().anchor().at.boot_id
                && !matches!(record.checkpoint().anchor().leap.view,
                    mutiny_consensus_v8::holdover_clock_v1::LeapView::Unassessed) {
                core.current()?;core.backend.restore_protected_record(&record)?;core.current()?;
                // Do not expose restored qualification before a NEW durable
                // exact full-ledger checkpoint includes the restart reading.
                core.persist_engine()?;
            }
            // Cross-boot state remains cold with its consumed floor preserved.
            // Fresh authenticated calibration is required; no boot substitution.
        }
        let core=construction.publish();
        Ok(Self{state:Arc::new(Mutex::new(State{core:Some(core),stopped:false,waiter:None,failure:None,acquisition_active:false,durable_stop:None}))})
    }
    #[cfg(target_os="linux")]
    pub(super) fn stopped_namespace_lease(&self)->Result<StoppedOwnerNamespaceLease<'_>> {
        let state=self.state.lock().map_err(|_|"namespace owner mutex poisoned")?;
        if !state.stopped||state.acquisition_active||state.failure.is_some()
            ||!matches!(state.durable_stop,Some(Ok(()))) {return Err("namespace owner stop/joins unresolved".into());}
        Ok(StoppedOwnerNamespaceLease{state})
    }
    pub(super) fn basis(&self)->Arc<dyn TimeBasis> {Arc::new(ProtectedBasis{state:Arc::downgrade(&self.state)})}
    pub(super) fn channel_context(&self)->Result<[u8;32]> {
        let mut state=self.state.lock().map_err(|_|"protected owner state poisoned")?;
        let result=state.live().map(|core|core.channel_context);
        if let Err(error)=&result {state.fail(error);}
        result
    }
    pub(super) fn vote_clock(&self)->Arc<dyn VoteClock> {Arc::new(ProtectedBasis{state:Arc::downgrade(&self.state)})}
    pub(super) fn stop_handle(&self)->ProtectedOwnerStop {ProtectedOwnerStop{state:Arc::downgrade(&self.state)}}
    pub(super) fn dispatcher(&self)->ProtectedOwnerDispatcher {
        ProtectedOwnerDispatcher{state:Arc::downgrade(&self.state)}
    }
    pub(super) fn elapsed_proxy(&self)->Arc<ProtectedElapsedProxy> {
        Arc::new(ProtectedElapsedProxy{state:Arc::downgrade(&self.state)})
    }
    pub(super) fn elapsed_interval(&self)->Result<Option<OwnerElapsedInterval>> {
        let mut state=match self.state.lock() {
            Ok(state)=>state,
            Err(poisoned)=>{let mut state=poisoned.into_inner();state.fail("protected owner state poisoned");
                let wake=state.waiter.take();drop(state);if let Some(wake)=wake {wake.wake();}
                return Err("protected owner state poisoned".into());},
        };
        let result=state.live().and_then(Core::elapsed_interval);
        if let Err(error)=&result {state.fail(error);}
        let wake=if result.is_err(){state.waiter.take()}else{None};
        drop(state);if let Some(wake)=wake {wake.wake();}result
    }
    /// Private owner dispatch target; the OS channel must authenticate every
    /// frame and retain peer/endpoint liveness across this synchronous commit.
    /// Missing installed issuer means this is not exposed as an ordinary endpoint.
    pub(super) fn reserve_operation(&self,expected_sequence:u64,operation:Operation)->Result<ReservedReply> {
        let mut state=match self.state.lock() {
            Ok(state)=>state,
            Err(poisoned)=>{let mut state=poisoned.into_inner();state.fail("protected owner state poisoned");
                let wake=state.waiter.take();drop(state);if let Some(wake)=wake {wake.wake();}
                return Err("protected owner state poisoned".into());},
        };
        let result=state.live().and_then(|core|core.deliver_operation(expected_sequence,operation));
        if let Err(error)=&result {state.fail(error);}
        let wake=if result.is_err(){state.waiter.take()}else{None};
        drop(state);if let Some(wake)=wake {wake.wake();}result
    }

    /// Private fresh-quote dispatch. OS-authenticated endpoint/current-lease
    /// checks still bracket this operation and the actual reply delivery.
    pub(super) fn fresh_operation(&self,expected_sequence:u64,operation:Operation)->Result<FreshOwnerQuote> {
        let mut state=match self.state.lock() {
            Ok(state)=>state,
            Err(poisoned)=>{let mut state=poisoned.into_inner();state.fail("protected owner state poisoned");
                let wake=state.waiter.take();drop(state);if let Some(wake)=wake {wake.wake();}
                return Err("protected owner state poisoned".into());},
        };
        let result=state.live().and_then(|core|core.fresh_operation(expected_sequence,operation));
        if let Err(error)=&result {state.fail(error);}
        let wake=if result.is_err(){state.waiter.take()}else{None};
        drop(state);if let Some(wake)=wake {wake.wake();}result
    }
    pub(super) fn fresh_selected_operation(&self,operation:Operation)->Result<FreshOwnerQuote> {
        let mut state=match self.state.lock() {
            Ok(state)=>state,
            Err(poisoned)=>{let mut state=poisoned.into_inner();state.fail("protected owner state poisoned");
                let wake=state.waiter.take();drop(state);if let Some(wake)=wake {wake.wake();}
                return Err("protected owner state poisoned".into());},
        };
        let result=state.live().and_then(|core|core.fresh_selected_operation(operation));
        if let Err(error)=&result {state.fail(error);}
        let wake=if result.is_err(){state.waiter.take()}else{None};
        drop(state);if let Some(wake)=wake {wake.wake();}result
    }

    /// Consuming ownership precludes a concurrent borrowed acquire_once.
    /// An earlier dropped acquisition future remains unknown and quarantined.
    /// Consumers are revoked before native locks/objects can be released.
    /// This does not authorize replacement or qualified restart.
    pub(super) fn close_lineage(self)->std::result::Result<ClosedOwnerLineage,OwnerLineageCloseFailure> {
        let durable_stop=self.stop_handle().stop_checked();
        let (core,active,mut errors)={
            let mut state=match self.state.lock() {
                Ok(state)=>state,
                Err(poisoned)=>{let mut state=poisoned.into_inner();state.fail("protected owner close mutex poisoned");state},
            };
            state.stopped=true;
            let errors=state.failure.iter().cloned().collect::<Vec<_>>();
            (state.core.take(),state.acquisition_active,errors)
        };
        let Some(mut core)=core else {
            errors.push("protected lineage was already unavailable".into());
            return Err(OwnerLineageCloseFailure{errors,native:None,selection:None,unjoined:None});
        };
        if let Err(error)=durable_stop {errors.push(format!("durable stop before close: {error}"));}
        if active {
            errors.push("acquisition task join outcome unknown; native ownership quarantined".into());
        }
        // Unknown or failed durable revocation cannot release the writer lock,
        // head, journal, engine or current-selection holders. Never reset the
        // plan or retry a cached failed stop in order to manufacture closure.
        if !errors.is_empty() {
            return Err(OwnerLineageCloseFailure{errors,native:None,selection:None,
                unjoined:Some(std::mem::ManuallyDrop::new(core))});
        }
        // Snapshot the exact stopped state BEFORE any native close. Failed
        // proof observation keeps every original writer/guard in custody.
        let continuity:Result<ClosedLineageContinuity>=(||{
            core.selection.recheck()?;
            let stopped=core.document.for_stop_invalidation().map_err(|e|format!("closed predecessor: {e:?}"))?;
            if !stopped.stopped_final(){return Err("closed predecessor is not a final invalidation".into());}
            let(sequence,floor)=core.io.operation_bounds()?;
            if sequence>stopped.sequence()||floor>stopped.floor(){return Err("closed predecessor journal dominance".into());}
            let observation=core.io.observation()?;
            if observation.head!=stopped.current_document(){return Err("closed predecessor head changed".into());}
            core.selection.recheck()?;
            Ok(ClosedLineageContinuity{predecessor:core.predecessor.clone(),placement:core.placement.clone(),
                observation,scope:stopped.retained_scope(),sequence:stopped.sequence(),floor:stopped.floor()})
        })();
        let continuity=match continuity{Ok(proof)=>proof,Err(error)=>{errors.push(error);
            return Err(OwnerLineageCloseFailure{errors,native:None,selection:None,unjoined:Some(std::mem::ManuallyDrop::new(core))});}};
        let Core{io,selection,..}=core;
        let selection=std::mem::ManuallyDrop::new(selection);
        let native=io.close().err();
        if native.is_none() {Ok(ClosedOwnerLineage{selection,continuity})}
        else {Err(OwnerLineageCloseFailure{errors,native,selection:Some(selection),unjoined:None})}
    }

    /// Only the owned native acquisition function produces reports. The caller
    /// cannot submit a calibration or raw Commit through this entry point.
    pub(super) async fn acquire_once(&mut self)->Result<bool> {
        match self.acquire_for_application().await? {
            ProtectedAcquisitionOutcome::Applied(applied)=>Ok(applied),
            ProtectedAcquisitionOutcome::DurablyStoppedAfterNativeJoin=>
                Err("protected acquisition durably stopped after native task join".into()),
        }
    }
    pub(super) async fn acquire_for_application(&mut self)->Result<ProtectedAcquisitionOutcome> {
        let config={let mut state=self.state.lock().map_err(|_|"protected owner state poisoned")?;
            if state.acquisition_active {state.fail("previous acquisition join outcome unknown");
                return Err("previous acquisition join outcome unknown".into());}
            let config=state.live()?.backend.config().clone();
            state.acquisition_active=true;config};
        let mut lifetime=AcquisitionLifetime{state:Arc::downgrade(&self.state),armed:true};
        let cancelled=poll_fn(|cx| {
            let mut state=match self.state.lock() {
                Ok(s)=>s,
                Err(poisoned)=>{
                    let mut state=poisoned.into_inner();state.fail("protected owner poisoned");
                    return Poll::Ready(());
                },
            };
            if state.live().is_err(){return Poll::Ready(());}
            state.waiter=Some(cx.waker().clone());Poll::Pending
        });
        let acquired=mutiny_clock_native_nts_v1::acquire_cancellable(config,cancelled).await
            .map_err(|e|format!("protected native acquisition: {e}"));
        // This line is reached only after the native function naturally
        // returns; that implementation joins all spawned tasks on every
        // report, cancellation and task-failure route. Whole-future Drop never
        // clears this marker and cannot produce explicit closure evidence.
        {let mut state=self.state.lock().unwrap_or_else(|p|p.into_inner());state.acquisition_active=false;}
        lifetime.armed=false;
        let acquired=match acquired {
            Ok(Some(report))=>Ok(report),
            Ok(None)=>{
                // Native source tasks have been joined. Stop/current loss may
                // not commit a stale acquired report or expose time afterward.
                let mut state=self.state.lock().unwrap_or_else(|p|p.into_inner());
                state.waiter=None;
                // Only this same owner's already confirmed durable stop plus
                // the actual natural native join makes cancellation settled.
                // It exposes no report or qualification. Current-loss, failed
                // stop and whole-future abandonment remain sticky unknown.
                if state.stopped && state.failure.is_none()
                    && matches!(&state.durable_stop,Some(Ok(()))) {
                    return Ok(ProtectedAcquisitionOutcome::DurablyStoppedAfterNativeJoin);
                }
                state.fail("protected acquisition cancelled after native task join");
                return Err("protected acquisition cancelled after native task join".into());
            },
            Err(error)=>Err(error),
        };
        let mut state=self.state.lock().map_err(|_|"protected owner state poisoned")?;state.waiter=None;
        let native_error=acquired.as_ref().err().cloned();
        let mut durable_fault=false;
        let result=(|| {
            // A source task/provider failure is retained even if stop or
            // current loss races its actual native return. Never replace it
            // with a generic stopped/current refusal or clean cancellation.
            let core=state.live().map_err(|current|match &native_error {
                Some(native)=>format!("{native}; protected current: {current}"),
                None=>current,
            })?;
            let applied=core.backend.finish_acquired(acquired);
            let stored=core.persist_engine();
            let checked=core.current();
            durable_fault=stored.is_err() || checked.is_err();
            let result=match (applied,stored) {
                (outcome,Ok(()))=>outcome,
                (Ok(_),Err(storage))=>Err(storage),
                (Err(acquisition),Err(storage))=>Err(format!("{acquisition}; protected persistence refused: {storage}")),
            };
            match (result,checked) {
                (Ok(outcome),Ok(()))=>Ok(outcome),
                (Err(error),Ok(()))=>Err(error),
                (Ok(_),Err(current))=>Err(current),
                (Err(error),Err(current))=>Err(format!("{error}; protected current: {current}")),
            }
        })();
        // Network/provider failure alone may preserve bounded holdover. A
        // failed storage/current check marks DocumentaryEngine unknown and
        // revokes every basis through the sticky owner barrier.
        if durable_fault || state.core.as_ref().is_some_and(|core|core.document.frozen()) {
            state.fail("protected owner durable outcome unknown");
        }
        result.map(ProtectedAcquisitionOutcome::Applied)
    }
}
impl Drop for ProtectedClockOwner {
    fn drop(&mut self) {
        // Keep the original State allocation before stop/wake can fail or
        // unwind. Arc cloning allocates no new custody. Weak consumers remain
        // revoked by stop; this retained strong reference supplies no reading.
        // Explicit close_lineage has already taken Core, so its empty State
        // needs no abandonment retention and cannot acquire a second close.
        let retains_core=match self.state.lock() {
            Ok(state)=>state.core.is_some(),
            Err(poisoned)=>poisoned.into_inner().core.is_some(),
        };
        if retains_core {let _=Arc::into_raw(Arc::clone(&self.state));}
        self.stop_handle().stop();
        // Abandonment retains writer/selection/backend plus original stopped,
        // failure and acquisition state. It grants no durable-stop outcome,
        // native closure, successor token or restart qualification.
    }
}
