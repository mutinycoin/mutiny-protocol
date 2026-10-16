//! Ordinary installed consumer facade. It issues neither a cached VoteClock
//! nor a caller-selected qualification capability. The Node coordinator owns
//! one connection and one opaque current-reconstructed attempt at a time.
type Result<T>=std::result::Result<T,NodeClockQueryFailure>;
pub(crate) enum NodeClockQueryFailure {
    Inputs(String),
    #[cfg(windows)]
    Windows(std::mem::ManuallyDrop<super::protected_clock_windows_channel::FreshRequestFailure>),
}
impl NodeClockQueryFailure {
    pub(crate) fn description(&self)->&str {
        match self {Self::Inputs(message)=>message,
            #[cfg(windows)] Self::Windows(_)=>"installed Windows query refused; exact native/operation custody retained"}
    }
}
enum Connection {
    #[cfg(target_os="linux")]
    Unix(super::protected_clock_unix_channel::InstalledUnixFreshConsumer),
    #[cfg(windows)]
    Windows(super::protected_clock_windows_channel::InstalledFreshConsumer),
}
enum Attempt {
    #[cfg(target_os="linux")]
    Unix(super::protected_clock_unix_channel::PreparedUnixFreshAttempt),
    #[cfg(windows)]
    Windows(super::protected_clock_windows_channel::PreparedFreshAttempt),
}
pub(crate) struct InstalledNodeClockQuery {inner:Connection}
pub(crate) struct PreparedNodeClockAttempt {inner:Attempt}
pub(crate) enum NodeClockRetainedClose {
    #[cfg(target_os="linux")]
    Unix(super::protected_clock_unix_channel::UnixPreparedRetainedClose),
    #[cfg(windows)]
    Windows(std::result::Result<super::protected_clock_windows_channel::PreparedConsumerRetainedClose,
        std::mem::ManuallyDrop<super::protected_clock_windows_channel::PreparedFreshAttempt>>),
    #[cfg(windows)]
    IdleWindows(super::protected_clock_windows_channel::IdleConsumerRetainedClose),
}
impl NodeClockRetainedClose {pub(crate) fn retained_handles_closed(&self)->bool {
    match self {#[cfg(target_os="linux")]Self::Unix(report)=>report.retained_handles_closed(),
        #[cfg(windows)]Self::Windows(report)=>report.as_ref().is_ok_and(|r|r.retained_handles_closed()),
        #[cfg(windows)]Self::IdleWindows(report)=>report.retained_handles_closed()}
}}
// Ordinary compilation must prove this bound. No unsafe Node-side assertion
// and no runtime/held test target is introduced by this check.
#[allow(dead_code)]
fn require_owned_attempt_send(){fn require_send<T:Send>(){} require_send::<PreparedNodeClockAttempt>();}
impl InstalledNodeClockQuery {
    /// Original executor shutdown after a consuming request returned. This
    /// idle value cannot contain a detached query worker or fresh receipt.
    pub(crate) fn close_idle_retained(self)->NodeClockRetainedClose {
        match self.inner {
            #[cfg(target_os="linux")]
            Connection::Unix(consumer)=>NodeClockRetainedClose::Unix(consumer.close_idle_retained()),
            #[cfg(windows)]
            Connection::Windows(consumer)=>NodeClockRetainedClose::IdleWindows(consumer.close_idle_retained()),
        }
    }
    /// The fixed held administrator selection, exact requested record, own
    /// authenticated Genesis, accepted measurements and current native image
    /// gates all precede connecting. No raw path/SID/profile/Boolean argument.
    pub(crate) async fn connect_installed(record:&[u8],own_genesis:&[u8])->Result<Self> {
        #[cfg(target_os="linux")]
        {
            let authority=super::native_nts_deployment_record::issue_installed_channel(record,own_genesis,
                super::protected_clock_unix_channel::ChannelRole::Consumer)
                .map_err(|e|NodeClockQueryFailure::Inputs(format!("installed consumer inputs: {e:?}")))?;
            let consumer=super::protected_clock_unix_channel::InstalledUnixFreshConsumer::connect(authority).await
                .map_err(NodeClockQueryFailure::Inputs)?;
            return Ok(Self{inner:Connection::Unix(consumer)});
        }
        #[cfg(windows)]
        {
            let authority=super::native_nts_deployment_record::issue_installed_windows_channel(record,own_genesis,
                super::protected_clock_windows_channel::ChannelRole::Consumer)
                .map_err(|e|NodeClockQueryFailure::Inputs(format!("installed consumer inputs: {e:?}")))?;
            let consumer=super::protected_clock_windows_channel::InstalledFreshConsumer::connect(authority)
                .map_err(|e|NodeClockQueryFailure::Windows(std::mem::ManuallyDrop::new(e)))?;
            return Ok(Self{inner:Connection::Windows(consumer)});
        }
        #[cfg(not(any(target_os="linux",windows)))]
        {let _=(record,own_genesis);Err(NodeClockQueryFailure::Inputs("installed native consumer unsupported".into()))}
    }
    /// Call only if the authoritative pure Node gate consulted its lazy clock.
    /// Every call creates one NEW exact authenticated operation; nil/guarded
    /// and durable signed replay paths need not call this at all.
    pub(crate) async fn prepare(self)->Result<PreparedNodeClockAttempt> {
        match self.inner {
            #[cfg(target_os="linux")]
            Connection::Unix(consumer)=>consumer.prepare_attempt().await
                .map(|inner|PreparedNodeClockAttempt{inner:Attempt::Unix(inner)})
                .map_err(NodeClockQueryFailure::Inputs),
            #[cfg(windows)]
            Connection::Windows(consumer)=>{
                let query=consumer.begin_request().map_err(|e|NodeClockQueryFailure::Windows(std::mem::ManuallyDrop::new(e)))?;
                let joined=query.await.map_err(NodeClockQueryFailure::Inputs)?;
                joined.prepare_attempt().map(|inner|PreparedNodeClockAttempt{inner:Attempt::Windows(inner)})
                    .map_err(|e|NodeClockQueryFailure::Windows(std::mem::ManuallyDrop::new(e)))
            },
        }
    }
}
impl PreparedNodeClockAttempt {
    /// Controller shutdown only after ORIGINAL worker join. No new operation,
    /// reconstructed UTC, key-entry approval or replacement capability.
    pub(crate) fn close_retained(self)->NodeClockRetainedClose {
        match self.inner {#[cfg(target_os="linux")]Attempt::Unix(attempt)=>NodeClockRetainedClose::Unix(attempt.close_retained()),
            #[cfg(windows)]Attempt::Windows(attempt)=>NodeClockRetainedClose::Windows(attempt.close_retained())}
    }
    pub(crate) fn recheck_installed_only(&mut self)->Result<()> {
        match &mut self.inner {
            #[cfg(target_os="linux")] Attempt::Unix(attempt)=>attempt.recheck_installed_only().map_err(NodeClockQueryFailure::Inputs),
            #[cfg(windows)] Attempt::Windows(attempt)=>attempt.recheck_installed_only().map_err(NodeClockQueryFailure::Inputs),
        }
    }
    /// Called only by the installed private custody worker after a NEW owner
    /// operation. A locally current reconstruction retains both endpoints,
    /// original age/gap/leap and incarnation; no UTC-floor conversion/cache.
    pub(crate) fn capture_current(&mut self)->Result<Option<mutiny_consensus_v8::activation_attestation_v1::ElapsedCapture>> {
        match &mut self.inner {
            #[cfg(target_os="linux")] Attempt::Unix(attempt)=>attempt.capture_current().map_err(NodeClockQueryFailure::Inputs),
            #[cfg(windows)] Attempt::Windows(attempt)=>attempt.capture_current().map_err(NodeClockQueryFailure::Inputs),
        }
    }
    /// Consume the previous receipt and issue a NEW authenticated operation on
    /// the SAME installed connection. An owned I/O worker must run this future;
    /// this method supplies neither a cached activation source nor a new socket.
    pub(crate) async fn refresh(self)->Result<Self>{self.finish()?.prepare().await}
    /// Serialize mutable use within this actor attempt. This rebuilds CURRENT
    /// native/boot/current-guard plus original age/gap/leap eligibility each
    /// time the signing gate asks, and returns ONLY its already durable floor.
    pub(crate) fn reading(&mut self)->Result<mutiny_consensus_v8::vote_clock_v1::ClockReading> {
        match &mut self.inner {
            #[cfg(target_os="linux")] Attempt::Unix(attempt)=>attempt.reading().map_err(NodeClockQueryFailure::Inputs),
            #[cfg(windows)] Attempt::Windows(attempt)=>attempt.reading().map_err(NodeClockQueryFailure::Inputs),
        }
    }
    /// Ending an attempt consumes its private receipt. No elapsed value is
    /// exposed here: a reusable activation source requires a NEW operation at
    /// EVERY custody entry. Abandonment retains underlying transport custody.
    pub(crate) fn finish(self)->Result<InstalledNodeClockQuery> {
        match self.inner {
            #[cfg(target_os="linux")]
            Attempt::Unix(attempt)=>{let(consumer,_one_attempt_capture)=attempt.into_parts().map_err(NodeClockQueryFailure::Inputs)?;
                Ok(InstalledNodeClockQuery{inner:Connection::Unix(consumer)})},
            #[cfg(windows)]
            Attempt::Windows(attempt)=>{let consumer=attempt.finish_connection()
                .map_err(|error|NodeClockQueryFailure::Windows(std::mem::ManuallyDrop::new(error)))?;
                Ok(InstalledNodeClockQuery{inner:Connection::Windows(consumer)})},
        }
    }
}
