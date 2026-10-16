//! Bounded host worker for an already authenticated, admission-owned peer.
//! No listener launch, private-key generation, discovery or automatic authority.
use crate::{
    hybrid_dispatch_v2::{self, DispatchEvent},
    hybrid_peer_admission_v2::{Connection, PeerLink},
    hybrid_runtime_v2::HybridRuntime,
};
use mutiny_consensus_v8::Hash;
use crate::hybrid_peer_error_v2::{PeerFailure, PeerResult};
use mutiny_transport_v2::{
    object_link::Event,
    objects::{GeneralCapacity, HistoryCapacity, ObjectKind, ObjectQueue, Offer},
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const TICK: Duration = Duration::from_millis(20);
const IO: Duration = Duration::from_secs(5);
const CHANNEL_CAPACITY: usize = 1;
type Result<T> = PeerResult<T>;
type LegacyResult<T> = std::result::Result<T, String>;
pub enum Command {
    HistoryCapacity { request: Option<Hash> },
    /// Local host supplies only its private, canonically prepared export.
    /// This queues the page atomically and sends its HAVE, never candidate HAVEs.
    PublishHistoryPage(crate::history_service_v1::PreparedHistoryPublication),
    HistoryAcknowledged { object: Hash, start: u16, count: u16 },
    /// Host has validated the decoded page and current request correlation.
    HistoryAcceptPlan { request: Hash, page: Hash, members: Vec<Offer> },
    HistoryReclaimAcknowledged { page: Hash, object: Hash },
    /// The local receiver has already canonically committed this exact member.
    HistoryReclaimVerified(crate::history_service_v1::VerifiedHistoryReclaim),
    HistoryRetireRequest { request: Hash },
    HistoryRetirePlan { page: Hash },
    /// Explicit local scheduling of fully validated complete pool objects.
    RelayPending,
    Enqueue {
        kind: ObjectKind,
        bytes: Vec<u8>,
    },
    Advertise {
        object: Hash,
    },
    RequestMissing {
        object: Hash,
    },
    QueryWindow {
        object: Hash,
        start: u16,
        count: u16,
    },
    RetryCompleted {
        object: Hash,
    },
    Receipt {
        object: Hash,
        start: u16,
        count: u16,
    },
}
pub struct RejectedCommand {
    pub command: Command,
    pub reason: &'static str,
}
pub enum Notification {
    HistoryCapacity { request: Option<Hash>, general: GeneralCapacity, candidates: HistoryCapacity },
    HistoryPageQueued { request: Hash, offers: Vec<Offer> },
    HistoryBusy { request: Hash },
    HistoryPlanAccepted { request: Hash, page: Hash, grant: crate::history_service_v1::HistoryPlanAdmission },
    HistoryAcknowledged { object: Hash, start: u16, count: u16, acknowledged: u16 },
    HistoryReclaimed { object: Hash },
    /// Public object queued and HAVE sent; no canonical acceptance is implied.
    Advertised(Offer),
    RelayAdvertised(Vec<Offer>),
    RequestWindow {
        object: Hash,
        start: u16,
        count: u16,
    },
    NoMissingFragments {
        object: Hash,
    },
    /// Durable transport progress, never canonical acceptance.
    WindowProgress {
        object: Hash,
        start: u16,
        count: u16,
        missing: u16,
    },
    Dispatched(DispatchEvent),
}
pub struct Worker {
    commands: SyncSender<Command>,
    notifications: Receiver<Notification>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<()>>>,
    history_node: bool,
    history_session: Option<crate::hybrid_peer_admission_v2::AdmittedHistorySession>,
    #[cfg(test)]
    exit: Arc<Mutex<Option<Result<()>>>>,
}
fn outgoing_policy_failure(message: &'static str, error: mutiny_transport_v2::Error) -> PeerFailure {
    match error {
        mutiny_transport_v2::Error::Expired => PeerFailure::SessionExpired,
        _ => PeerFailure::Other(message.into()),
    }
}
fn notify(tx: &SyncSender<Notification>, value: Notification) -> Result<()> {
    tx.try_send(value).map_err(|e| match e {
        TrySendError::Full(_) => "Peer event consumer backpressure".into(),
        TrySendError::Disconnected(_) => "Peer event consumer disconnected".into(),
    })
}
fn command(
    peer: &mut PeerLink,
    runtime: &Mutex<HybridRuntime>,
    cmd: Command,
    tx: &SyncSender<Notification>,
    relay: &mut crate::submission_relay_v1::Relay,
) -> Result<()> {
    match cmd {
        Command::HistoryCapacity { request } => {
            let general = peer.with_current(|link| link.history_general_capacity())?
                .map_err(|e| PeerFailure::transport("History capacity", e))?;
            let candidates = match request {
                Some(id) => peer.with_current(|link| link.history_capacity(&id))?
                    .map_err(|e| PeerFailure::transport("History request capacity", e))?,
                None => general.history_candidates(),
            };
            notify(tx, Notification::HistoryCapacity { request, general, candidates })
        }
        Command::PublishHistoryPage(publication) => {
            let proof = peer.history_session()?;
            let (request, page, candidates) = publication.into_parts(&proof)?;
            let queued = peer.with_current(|link| link.enqueue_history_page(&request, &page, &candidates))?
                .map_err(|e| PeerFailure::transport("History page queue", e))?;
            if let Some(offers) = queued {
                let frame = peer.with_current(|link| link.advertise(&offers[0].id, 0))?
                    .map_err(|e| PeerFailure::transport("History page advertise", e))?;
                peer.send_typed(&frame, Instant::now() + IO)?;
                notify(tx, Notification::HistoryPageQueued { request, offers })
            } else {
                notify(tx, Notification::HistoryBusy { request })
            }
        }
        Command::HistoryAcknowledged { object, start, count } => {
            let bits = peer.with_current(|link| link.history_acknowledged(&object, start, count))?
                .map_err(|e| PeerFailure::transport("History ACK window", e))?;
            notify(tx, Notification::HistoryAcknowledged { object, start, count,
                acknowledged: bits.bits.iter().filter(|bit| **bit).count() as u16 })
        }
        Command::HistoryAcceptPlan { request, page, members } => {
            peer.with_current(|link| link.history_accept_plan(&request, &page, &members))?
                .map_err(|e| PeerFailure::transport("History plan accept", e))?;
            let lease=peer.with_current(|link|link.history_plan_lease(&page))?
                .map_err(|e|PeerFailure::transport("History accepted plan lease",e))?;
            let grant=crate::history_service_v1::HistoryPlanAdmission::new(peer.history_session()?,request,page,members,lease)?;
            notify(tx, Notification::HistoryPlanAccepted { request, page, grant })
        }
        Command::HistoryReclaimAcknowledged { page, object } => {
            peer.with_current(|link| link.history_reclaim_acknowledged_export(&page, &object))?
                .map_err(|e| PeerFailure::transport("History ACK reclaim", e))?;
            notify(tx, Notification::HistoryReclaimed { object })
        }
        Command::HistoryReclaimVerified(verified) => {
            let object = peer.history_reclaim_verified_object(verified)?;
            notify(tx, Notification::HistoryReclaimed { object })
        }
        Command::HistoryRetireRequest { request } => {
            peer.with_current(|link| link.history_retire_consumed_request(&request))?
                .map_err(|e| PeerFailure::transport("History request retire", e))?;
            notify(tx, Notification::HistoryReclaimed { object: request })
        }
        Command::HistoryRetirePlan { page } => {
            peer.with_current(|link| link.history_retire_plan(&page))?
                .map_err(|e| PeerFailure::transport("History plan retire", e))?;
            notify(tx, Notification::HistoryReclaimed { object: page })
        }
        Command::RelayPending => {
            peer.with_current(|link| link.check_outgoing_kind(ObjectKind::SignedTransaction))?
                .map_err(|error| outgoing_policy_failure("Wallet-client service cannot relay node submissions", error))?;
            let frames = hybrid_dispatch_v2::with_actor(
                runtime,
                peer,
                Instant::now() + IO,
                |actor, peer| {
                    peer.with_current(|link| relay.prepare_typed(actor, link))
                        .map_err(hybrid_dispatch_v2::DispatchError::Admission)?
                        .map_err(hybrid_dispatch_v2::DispatchError::from)
                },
            )
            .map_err(|e| PeerFailure::dispatch("Peer relay", e))?;
            let mut offers = Vec::new();
            for (offer, frame) in frames {
                peer.send_typed(&frame, Instant::now() + IO)?;
                offers.push(offer);
            }
            notify(tx, Notification::RelayAdvertised(offers))
        }
        Command::QueryWindow {
            object,
            start,
            count,
        } => {
            let bitmap = peer
                .with_current(|link| link.missing_window(&object, start, count))?
                .map_err(|e| PeerFailure::transport("Peer progress window", e))?;
            let missing = bitmap.bits.iter().filter(|v| **v).count() as u16;
            notify(
                tx,
                Notification::WindowProgress {
                    object,
                    start,
                    count,
                    missing,
                },
            )
        }
        Command::RetryCompleted { object } => {
            let event = hybrid_dispatch_v2::retry_peer_completed(
                runtime,
                peer,
                object,
                Instant::now() + IO,
            )
            .map_err(|error| match error {
                hybrid_dispatch_v2::DispatchError::Transport(mutiny_transport_v2::Error::Expired) =>
                    PeerFailure::SessionExpired,
                _ => PeerFailure::Other("Peer completed-object validation rejected".into()),
            })?;
            if let DispatchEvent::OperationAccepted { offer, .. } = &event {
                release_received_submission(peer, runtime, offer)?;
            }
            notify(tx, Notification::Dispatched(event))
        }
        Command::Enqueue { kind, bytes } => {
            // Refuse a prohibited local command before even pool admission.
            peer.with_current(|link| link.check_outgoing_kind(kind))?
                .map_err(|error| outgoing_policy_failure("Wallet-client service outgoing operation refused", error))?;
            if matches!(
                kind,
                ObjectKind::SignedTransaction | ObjectKind::SignedOperation
            ) {
                hybrid_dispatch_v2::with_actor(
                    runtime,
                    peer,
                    Instant::now() + IO,
                    |actor, peer| {
                        peer.with_current(|link| {
                            let (genesis, fingerprint) = actor.network_context();
                            if !link.matches_network(genesis, fingerprint) {
                                return Err(hybrid_dispatch_v2::DispatchError::Admission(
                                    "Local submission network mismatch".into(),
                                ));
                            }
                            let (_, status) = actor
                                .admit_submission(
                                    if kind == ObjectKind::SignedTransaction {
                                        0
                                    } else {
                                        1
                                    },
                                    &bytes,
                                )
                                .map_err(hybrid_dispatch_v2::DispatchError::Runtime)?;
                            if !matches!(
                                status,
                                mutiny_consensus_v8::submission_v1::Status::Pending
                            ) {
                                return Err(hybrid_dispatch_v2::DispatchError::Admission(
                                    "Submission is not pending".into(),
                                ));
                            }
                            Ok(())
                        })
                        .map_err(hybrid_dispatch_v2::DispatchError::Admission)?
                    },
                )
                .map_err(|e| PeerFailure::dispatch("Peer local complete submission", e))?;
            }
            let (offer, frame) = peer
                .with_current(|link| link.enqueue(kind, &bytes, 0))?
                .map_err(|e| PeerFailure::transport("Peer enqueue", e))?;
            peer.send_typed(&frame, Instant::now() + IO)?;
            notify(tx, Notification::Advertised(offer))
        }
        Command::Advertise { object } => {
            check_submission_copy(peer, runtime, object, true)?;
            let frame = peer
                .with_current(|link| link.advertise(&object, 0))?
                .map_err(|e| PeerFailure::transport("Peer advertise", e))?;
            peer.send_typed(&frame, Instant::now() + IO)
        }
        Command::RequestMissing { object } => {
            let window = peer
                .with_current(|link| link.next_missing_request(&object, 0, false))?
                .map_err(|e| PeerFailure::transport("Peer request window", e))?;
            if let Some(window) = window {
                peer.send_typed(&window.frame, Instant::now() + IO)?;
                notify(
                    tx,
                    Notification::RequestWindow {
                        object,
                        start: window.start,
                        count: window.count,
                    },
                )
            } else {
                notify(tx, Notification::NoMissingFragments { object })
            }
        }
        Command::Receipt {
            object,
            start,
            count,
        } => {
            check_submission_copy(peer, runtime, object, false)?;
            let frame = peer
                .with_current(|link| link.receipt(&object, start, count, 0))?
                .map_err(|e| PeerFailure::transport("Peer receipt", e))?;
            peer.send_typed(&frame, Instant::now() + IO)?;
            let (offer, complete) = peer
                .with_current(|link| link.describe(&object))?
                .map_err(|e| PeerFailure::transport("Peer receipt identity", e))?;
            if complete
                && matches!(
                    offer.kind,
                    ObjectKind::SignedTransaction | ObjectKind::SignedOperation
                )
                && start == 0
                && usize::from(count) == offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD)
            {
                peer.with_current(|link| link.discard(&object))?
                    .map_err(|e| PeerFailure::transport("Peer retained submission release", e))?;
            }
            Ok(())
        }
    }
}
/// Complete submission copies require durable local admission before either
/// advertisement or ACK. Fragment receipt alone never authorizes an ACK.
fn check_submission_copy(
    peer: &mut PeerLink,
    runtime: &Mutex<HybridRuntime>,
    object: Hash,
    pending: bool,
) -> Result<()> {
    hybrid_dispatch_v2::with_actor(runtime, peer, Instant::now() + IO, |actor, peer| {
        let (genesis, fingerprint) = actor.network_context();
        let (header, _) = peer
            .with_current(|link| {
                if !link.matches_network(genesis, fingerprint) {
                    return Err(mutiny_transport_v2::Error::Context);
                }
                link.describe(&object)
            })
            .map_err(hybrid_dispatch_v2::DispatchError::Admission)?
            .map_err(hybrid_dispatch_v2::DispatchError::Transport)?;
        if !matches!(
            header.kind,
            ObjectKind::SignedTransaction | ObjectKind::SignedOperation
        ) {
            return Ok(());
        }
        let (offer, raw) = peer
            .with_current(|link| link.completed(&object))
            .map_err(hybrid_dispatch_v2::DispatchError::Admission)?
            .map_err(hybrid_dispatch_v2::DispatchError::Transport)?;
        if matches!(
            offer.kind,
            ObjectKind::SignedTransaction | ObjectKind::SignedOperation
        ) {
            let list = if offer.kind == ObjectKind::SignedTransaction {
                0
            } else {
                1
            };
            let op = mutiny_consensus_v8::submission_v1::Submission::decode(list, &raw).map_err(
                |e| {
                    hybrid_dispatch_v2::DispatchError::Admission(format!(
                        "Complete submission: {e:?}"
                    ))
                },
            )?;
            if actor
                .exact_submission_bytes(op.id)
                .map_err(hybrid_dispatch_v2::DispatchError::Runtime)?
                != Some((list, raw))
            {
                return Err(hybrid_dispatch_v2::DispatchError::Admission(
                    "Submission not durably admitted".into(),
                ));
            }
            if pending
                && !matches!(
                    actor
                        .submission_status(op.id)
                        .map_err(hybrid_dispatch_v2::DispatchError::Runtime)?,
                    mutiny_consensus_v8::submission_v1::Status::Pending
                )
            {
                return Err(hybrid_dispatch_v2::DispatchError::Admission(
                    "Submission no longer pending".into(),
                ));
            }
        }
        Ok(())
    })
    .map_err(|e| PeerFailure::dispatch("Submission transport copy", e))
}
fn release_received_submission(
    peer: &mut PeerLink,
    runtime: &Mutex<HybridRuntime>,
    offer: &Offer,
) -> Result<()> {
    check_submission_copy(peer, runtime, offer.id, false)?;
    let count = offer.length.div_ceil(mutiny_transport_v2::MAX_PAYLOAD) as u16;
    let ack = peer
        .with_current(|link| link.receipt(&offer.id, 0, count, 0))?
        .map_err(|e| PeerFailure::transport("Submission receipt", e))?;
    peer.send_typed(&ack, Instant::now() + IO)?;
    // The full exact object remains in the pool; only its redundant transport
    // copy is released after successful send. Failed/partial copies stay intact.
    peer.with_current(|link| link.discard(&offer.id))?
        .map_err(|e| PeerFailure::transport("Submission transport release", e))
}
/// Pull only fresh authenticated submission offers in the explicit node history
/// worker. Metadata is bounded independently; public bytes remain in ObjectQueue.
struct SubmissionPull {
    session: crate::hybrid_peer_admission_v2::AdmittedHistorySession,
    offers: std::collections::VecDeque<SubmissionOffer>,
}
struct SubmissionOffer {
    offer: Offer,
    window: Option<(u16, u16)>,
}
enum SubmissionTurn {
    Idle,
    Requested,
    Completed(DispatchEvent),
}
impl SubmissionPull {
    fn new(peer: &mut PeerLink) -> Result<Self> {
        let session = peer.history_session()?;
        if session.authorization() != mutiny_transport_v2::object_link::LocalAuthorization::WalletHistoryClientToNode {
            return Err("Submission pull requires node history purpose".into());
        }
        Ok(Self { session, offers: std::collections::VecDeque::with_capacity(mutiny_transport_v2::objects::MAX_OBJECTS) })
    }
    fn check_peer(&self, peer: &mut PeerLink) -> Result<()> {
        self.session.check_current()?;
        peer.with_current(|link| {
            if link.session_id() != self.session.session_id()
                || link.peer_id() != self.session.peer_id()
                || link.authorization() != self.session.authorization() {
                return Err(mutiny_transport_v2::Error::Context);
            }
            Ok(())
        })?.map_err(|e| PeerFailure::transport("Submission pull session", e))
    }
    fn described(&self, peer: &mut PeerLink, offer: &Offer) -> Result<bool> {
        self.check_peer(peer)?;
        peer.with_current(|link| {
            link.check_incoming_event(&Event::Offered(offer.clone()))?;
            let (queued, complete) = link.describe(&offer.id)?;
            if queued != *offer { return Err(mutiny_transport_v2::Error::Context); }
            Ok(complete)
        })?.map_err(|e| PeerFailure::transport("Submission pull offer", e))
    }
    /// Called only on this Worker's guarded receive/dispatch result. An exact
    /// duplicate HAVE neither replaces its FIFO slot nor resets its window.
    fn receive(&mut self, event: &DispatchEvent, peer: &mut PeerLink) -> Result<bool> {
        match event {
            DispatchEvent::Transport(Event::Offered(offer))
                if matches!(offer.kind, ObjectKind::SignedTransaction | ObjectKind::SignedOperation) => {
                self.described(peer, offer)?;
                if let Some(old) = self.offers.iter().find(|old| old.offer.id == offer.id) {
                    if old.offer != *offer { return Err("Submission pull offer changed".into()); }
                } else {
                    if self.offers.len() >= mutiny_transport_v2::objects::MAX_OBJECTS {
                        return Err("Submission pull metadata backpressure".into());
                    }
                    self.offers.push_back(SubmissionOffer { offer: offer.clone(), window: None });
                }
                Ok(true)
            }
            DispatchEvent::TransactionAccepted { offer, .. } | DispatchEvent::OperationAccepted { offer, .. } => {
                self.described(peer, offer)?;
                if let Some(index) = self.offers.iter().position(|old| old.offer.id == offer.id) {
                    if self.offers[index].offer != *offer { return Err("Submission pull completion changed".into()); }
                    self.offers.remove(index);
                }
                Ok(false) // Existing AutoResponse owns durable full ACK/release.
            }
            _ => Ok(false),
        }
    }
    // One in-flight FIFO window: an incomplete front retains later offers
    // until completion or this existing session ends. No cancellation timer.
    fn turn(&mut self, peer: &mut PeerLink, runtime: &Mutex<HybridRuntime>) -> Result<SubmissionTurn> {
        let Some(front) = self.offers.front() else { return Ok(SubmissionTurn::Idle); };
        let offer = front.offer.clone();
        let window = front.window;
        if self.described(peer, &offer)? {
            // Retained completion is rehashed and canonically dispatched under
            // the actual current pin/actor, exactly like a fresh completion.
            let event = hybrid_dispatch_v2::retry_peer_completed(runtime, peer, offer.id, Instant::now() + IO)
                .map_err(|e| PeerFailure::dispatch("Automatic retained submission", e))?;
            if !matches!(&event, DispatchEvent::TransactionAccepted { .. } | DispatchEvent::OperationAccepted { .. }) {
                return Err("Automatic retained submission kind".into());
            }
            self.receive(&event, peer)?;
            return Ok(SubmissionTurn::Completed(event));
        }
        if let Some((start, count)) = window {
            let missing = peer.with_current(|link| link.missing_window(&offer.id, start, count))?
                .map_err(|e| PeerFailure::transport("Submission pull window progress", e))?;
            if missing.bits.iter().any(|missing| *missing) { return Ok(SubmissionTurn::Idle); }
        }
        let window = peer.with_current(|link| link.next_missing_request(&offer.id, 0, false))?
            .map_err(|e| PeerFailure::transport("Submission pull next window", e))?
            .ok_or("Incomplete submission has no missing window")?;
        self.offers.front_mut().unwrap().window = Some((window.start, window.count));
        // IO bounds this one frame only. A paced fragment window has no new
        // five-second completion deadline and advances only on durable bits.
        peer.send_typed(&window.frame, Instant::now() + IO)?;
        Ok(SubmissionTurn::Requested)
    }
}

enum AutoResponse {
    Submission(DispatchEvent),
    Status {offer:Offer,reports:Vec<Vec<u8>>,next:usize},
}
impl AutoResponse {
    fn new(event:DispatchEvent)->Result<Self> {
        match event {
            event @ (DispatchEvent::OperationAccepted{..}|DispatchEvent::TransactionAccepted{..})=>Ok(Self::Submission(event)),
            DispatchEvent::StatusQueryAnswered{offer,reports}=>Ok(Self::Status{offer,reports,next:0}),
            _=>Err("Unsupported automatic node response".into()),
        }
    }
}
/// Ordinary wallet submission/status work uses the same single outbound turn
/// in auto-node mode. Existing explicit G2/client worker behavior is unchanged.
fn auto_response(peer:&mut PeerLink,runtime:&Mutex<HybridRuntime>,reply:AutoResponse,
    notifications:&SyncSender<Notification>,pending:&mut Option<AutoResponse>)->Result<()> {
    match reply {
        AutoResponse::Submission(event)=>{
            let offer=match &event {
                DispatchEvent::OperationAccepted{offer,..}|DispatchEvent::TransactionAccepted{offer,..}=>offer,
                _=>return Err("Invalid automatic submission response".into()),
            };
            release_received_submission(peer,runtime,offer)?;
            notify(notifications,Notification::Dispatched(event))
        },
        AutoResponse::Status{offer,reports,next}=>{
            if let Some(raw)=reports.get(next) {
                let (_,frame)=peer.with_current(|link|link.enqueue(ObjectKind::StatusReport,raw,0))?
                    .map_err(|e|PeerFailure::transport("Automatic status response",e))?;
                peer.send_typed(&frame,Instant::now()+IO)?;
            }
            if next+1<reports.len() {
                *pending=Some(AutoResponse::Status{offer,reports,next:next+1});Ok(())
            } else {notify(notifications,Notification::Dispatched(DispatchEvent::StatusQueryAnswered{offer,reports}))}
        },
    }
}
/// Choose the class before constructing a frame. Flip control priority only
/// after an action, independently of the existing fragment/control alternation.
fn automatic_control(
    host: &mut crate::history_node_host_v1::NodeHistoryHost,
    pull: &mut SubmissionPull,
    submission_first: &mut bool,
    peer: &mut PeerLink,
    runtime: &Mutex<HybridRuntime>,
    response: &mut Option<AutoResponse>,
) -> Result<bool> {
    fn pull_control(pull: &mut SubmissionPull, peer: &mut PeerLink,
        runtime: &Mutex<HybridRuntime>, response: &mut Option<AutoResponse>) -> Result<bool> {
        match pull.turn(peer, runtime)? {
            SubmissionTurn::Idle => Ok(false),
            SubmissionTurn::Requested => Ok(true),
            SubmissionTurn::Completed(event) => {
                *response = Some(AutoResponse::new(event)?);
                Ok(true)
            }
        }
    }
    let acted = if *submission_first {
        pull_control(pull, peer, runtime, response)? || host.turn(peer, runtime, Instant::now())?
    } else {
        host.turn(peer, runtime, Instant::now())? || pull_control(pull, peer, runtime, response)?
    };
    if acted { *submission_first = !*submission_first; }
    Ok(acted)
}

fn run(
    mut peer: PeerLink,
    runtime: Arc<Mutex<HybridRuntime>>,
    commands: Receiver<Command>,
    notifications: SyncSender<Notification>,
    stop: Arc<AtomicBool>,
    mut history: Option<crate::history_node_host_v1::NodeHistoryHost>,
) -> Result<()> {
    let result = (|| {
        let mut control_first = true;
        let mut relay = crate::submission_relay_v1::Relay::new(peer.peer_id())?;
        let mut response = None;
        let mut submission_first = false;
        let mut submission_pull = if history.is_some() { Some(SubmissionPull::new(&mut peer)?) } else { None };
        while !stop.load(Ordering::Acquire) {
            let tick = Instant::now();
            // At most one outbound action per tick, alternating priority when
            // both controls and fragments are queued. This avoids two writers
            // outpacing one reader and prevents a busy control producer from
            // starving requested fragments. No frame is sealed then discarded
            // merely because another action won scheduling priority.
            let mut serviced = false;
            if !control_first {
                serviced = send_next(&mut peer)?;
            }
            if !serviced {
                if let Some(host) = history.as_mut() {
                    serviced = if let Some(reply) = response.take() {
                        auto_response(&mut peer,&runtime,reply,&notifications,&mut response)?;
                        true
                    } else {
                        automatic_control(host, submission_pull.as_mut().unwrap(), &mut submission_first,
                            &mut peer, &runtime, &mut response)?
                    };
                } else { match commands.try_recv() {
                    Ok(cmd) => {
                        command(&mut peer, &runtime, cmd, &notifications, &mut relay)?;
                        serviced = true;
                    }
                    Err(TryRecvError::Disconnected) => break,
                    Err(TryRecvError::Empty) => {}
                } }
            }
            if !serviced && control_first {
                send_next(&mut peer)?;
            }
            control_first = !control_first;
            if stop.load(Ordering::Acquire) {
                break;
            }
            // Auto replies retain at most the already bounded single dispatch
            // result. Finish their paced frames before admitting another one.
            if history.is_some() && response.is_some() {
                if let Some(left)=TICK.checked_sub(tick.elapsed()) {thread::sleep(left);}
                continue;
            }
            // Short idle tick, then a separate complete-frame/actor wait bound.
            // The second readiness check inside poll_peer consumes no bytes.
            if peer.wait_for_frame_typed(Instant::now() + TICK)? {
                let event = hybrid_dispatch_v2::poll_peer(&runtime, &mut peer, Instant::now() + IO)
                    .map_err(|error| match error {
                        hybrid_dispatch_v2::DispatchError::Transport(mutiny_transport_v2::Error::Expired) =>
                            PeerFailure::SessionExpired,
                        error => {
                            #[cfg(test)]
                            { PeerFailure::Other(format!("Peer canonical dispatch rejected: {error:?}")) }
                            #[cfg(not(test))]
                            { let _ = error; PeerFailure::Other("Peer canonical dispatch rejected".into()) }
                        }
                    })?;
                if let Some(event) = event {
                    if let Some(host)=history.as_mut() {
                        if host.receive(&event,&mut peer)? {
                            if let Some(left)=TICK.checked_sub(tick.elapsed()) {thread::sleep(left);}
                            continue;
                        }
                        if submission_pull.as_mut().unwrap().receive(&event, &mut peer)? {
                            if let Some(left)=TICK.checked_sub(tick.elapsed()) {thread::sleep(left);}
                            continue;
                        }
                        if matches!(&event,DispatchEvent::OperationAccepted{..}
                            |DispatchEvent::TransactionAccepted{..}|DispatchEvent::StatusQueryAnswered{..}) {
                            response=Some(AutoResponse::new(event)?);
                            if let Some(left)=TICK.checked_sub(tick.elapsed()) {thread::sleep(left);}
                            continue;
                        }
                    }
                    match event {
                        DispatchEvent::OperationAccepted { offer, id, status } => {
                            release_received_submission(&mut peer, &runtime, &offer)?;
                            notify(
                                &notifications,
                                Notification::Dispatched(DispatchEvent::OperationAccepted {
                                    offer,
                                    id,
                                    status,
                                }),
                            )?;
                        }
                        DispatchEvent::TransactionAccepted { offer, id, status } => {
                            // Preserve the legacy caller's explicit Receipt flow.
                            // That command verifies durable admission then releases
                            // the transport copy after its successful full ACK.
                            notify(
                                &notifications,
                                Notification::Dispatched(DispatchEvent::TransactionAccepted {
                                    offer,
                                    id,
                                    status,
                                }),
                            )?;
                        }
                        DispatchEvent::StatusQueryAnswered { offer, reports } => {
                            // Bounded reports are hints and may become stale. Socket
                            // writes occur after releasing the canonical actor.
                            for raw in &reports {
                                let (_, frame) = peer
                                    .with_current(|link| {
                                        link.enqueue(ObjectKind::StatusReport, raw, 0)
                                    })?
                                    .map_err(|e| PeerFailure::transport("Status response", e))?;
                                peer.send_typed(&frame, Instant::now() + IO)?;
                            }
                            notify(
                                &notifications,
                                Notification::Dispatched(DispatchEvent::StatusQueryAnswered {
                                    offer,
                                    reports,
                                }),
                            )?;
                        }
                        // Progress is durable in ObjectQueue. Do not accumulate
                        // one unbounded application notification per fragment.
                        DispatchEvent::Transport(
                            Event::FragmentReceived | Event::Requested | Event::ReceiptRecorded,
                        ) => {}
                        event => notify(&notifications, Notification::Dispatched(event))?,
                    }
                }
            }
            if let Some(left) = TICK.checked_sub(tick.elapsed()) {
                thread::sleep(left);
            }
        }
        Ok(())
    })();
    peer.close();
    result
}
fn send_next(peer: &mut PeerLink) -> Result<bool> {
    let frame = peer
        .with_current(|link| link.send_one())?
        .map_err(|e| PeerFailure::transport("Peer paced fragment", e))?;
    if let Some(frame) = frame {
        peer.send_typed(&frame, Instant::now() + IO)?;
        Ok(true)
    } else {
        Ok(false)
    }
}
impl Worker {
    /// Admission leases bound the number of these threads across the registry.
    /// The queue must belong to the exact authenticated peer; attach checks it.
    pub fn start(
        connection: Connection,
        queue: ObjectQueue,
        runtime: Arc<Mutex<HybridRuntime>>,
    ) -> LegacyResult<Self> {
        Self::start_typed(connection, queue, runtime).map_err(String::from)
    }
    pub fn start_typed(
        connection: Connection,
        queue: ObjectQueue,
        runtime: Arc<Mutex<HybridRuntime>>,
    ) -> PeerResult<Self> {
        Self::start_inner(connection,queue,runtime,None)
    }
    /// Explicit autonomous node-side history owner. The caller supplies one
    /// shared node budget, retained outside every connection worker/reconnect.
    pub fn start_history_node(connection:Connection,queue:ObjectQueue,
        runtime:Arc<Mutex<HybridRuntime>>,budget:crate::history_service_v1::HistoryBudget)->LegacyResult<Self> {
        Self::start_history_node_typed(connection,queue,runtime,budget).map_err(String::from)
    }
    pub fn start_history_node_typed(connection:Connection,queue:ObjectQueue,
        runtime:Arc<Mutex<HybridRuntime>>,budget:crate::history_service_v1::HistoryBudget)->PeerResult<Self> {
        Self::start_inner(connection,queue,runtime,Some(budget))
    }
    fn start_inner(connection:Connection,queue:ObjectQueue,runtime:Arc<Mutex<HybridRuntime>>,
        budget:Option<crate::history_service_v1::HistoryBudget>)->PeerResult<Self> {
        let mut peer = connection.attach(queue)?;
        let authorization=peer.with_current(|link|link.authorization())?;
        let history_session=if matches!(authorization,
            mutiny_transport_v2::object_link::LocalAuthorization::WalletHistoryClientToNode
                |mutiny_transport_v2::object_link::LocalAuthorization::NodeToWalletHistoryClient) {
            Some(peer.history_session()?)
        } else {None};
        let history_node=budget.is_some();
        let history=budget.map(|budget|crate::history_node_host_v1::NodeHistoryHost::new(&mut peer,budget)).transpose()?;
        let (commands, rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let (tx, notifications) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        #[cfg(test)]
        let exit = Arc::new(Mutex::new(None));
        #[cfg(test)]
        let exiting = exit.clone();
        let thread = thread::Builder::new()
            .name("build8-hybrid-peer".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                #[cfg(test)]
                {
                    // Keep a sender alive until the exact exit reason is recorded.
                    // The fixture can then observe disconnect only after diagnostics
                    // are available, without sleeps or a changed queue/deadline.
                    let result = run(peer, runtime, rx, tx.clone(), stopping,history);
                    *exiting.lock().unwrap() = Some(result.clone());
                    drop(tx);
                    result
                }
                #[cfg(not(test))]
                { run(peer, runtime, rx, tx, stopping,history) }
            })
            .map_err(|e| format!("Peer worker start: {e}"))?;
        Ok(Self {
            commands,
            notifications,
            stop,
            thread: Some(thread),
            history_node,
            history_session,
            #[cfg(test)]
            exit,
        })
    }
    pub fn try_submit(&self, command: Command) -> std::result::Result<(), RejectedCommand> {
        if self.history_node {
            return Err(RejectedCommand { command,reason:"History node owns automatic peer scheduling" });
        }
        if matches!(&command, Command::HistoryAcceptPlan { members, .. }
            if members.len() > mutiny_transport_v2::objects::MAX_HISTORY_CANDIDATES) {
            return Err(RejectedCommand { command, reason: "History plan bounds" });
        }
        if matches!(&command,Command::Enqueue{kind,bytes} if bytes.is_empty() || bytes.len()>kind.max_bytes())
        {
            return Err(RejectedCommand {
                command,
                reason: "Peer object size",
            });
        }
        if self.stop.load(Ordering::Acquire) {
            return Err(RejectedCommand {
                command,
                reason: "Peer worker stopping",
            });
        }
        self.commands.try_send(command).map_err(|e| match e {
            TrySendError::Full(command) => RejectedCommand {
                command,
                reason: "Peer command backpressure",
            },
            TrySendError::Disconnected(command) => RejectedCommand {
                command,
                reason: "Peer worker disconnected",
            },
        })
    }
    pub fn try_notification(&self) -> std::result::Result<Notification, TryRecvError> {
        self.notifications.try_recv()
    }
    /// Read-only current-session evidence; it neither retains an admission slot
    /// nor grants a fresh offer, accepted plan or canonical installation.
    pub fn history_session(&self)->PeerResult<crate::hybrid_peer_admission_v2::AdmittedHistorySession> {
        let proof=self.history_session.as_ref().ok_or("Worker has no history purpose")?;
        proof.check_current()?;
        Ok(proof.clone())
    }
    #[cfg(test)]
    fn exit_result(&self) -> Option<LegacyResult<()>> {
        self.exit.lock().unwrap().clone().map(|result| result.map_err(String::from))
    }
    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(|t| t.is_finished())
    }
    pub fn shutdown(self) -> LegacyResult<()> {
        self.shutdown_typed().map_err(String::from)
    }
    pub fn shutdown_typed(mut self) -> PeerResult<()> {
        self.stop.store(true, Ordering::Release);
        self.thread
            .take()
            .ok_or("Peer worker already joined")?
            .join()
            .map_err(|_| "Peer worker panicked".to_string())?
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
#[cfg(test)]
#[path = "hybrid_peer_worker_v2_tests.rs"]
mod tests;

#[cfg(test)]
mod g3_typed_tests {
    use super::*;
    fn ended(outcome: PeerResult<()>) -> Worker {
        let (commands, _rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
        let (_tx, notifications) = mpsc::sync_channel(CHANNEL_CAPACITY);
        Worker {
            commands, notifications, stop: Arc::new(AtomicBool::new(false)),
            thread: Some(std::thread::spawn(move || outcome)),
            history_node:false,
            history_session:None,
            exit: Arc::new(Mutex::new(None)),
        }
    }
    #[test]
    fn g3_worker_outgoing_policy_shortcuts_preserve_expiry_without_changing_denials() {
        for message in ["Wallet-client service cannot relay node submissions",
            "Wallet-client service outgoing operation refused"] {
            assert_eq!(outgoing_policy_failure(message, mutiny_transport_v2::Error::Expired), PeerFailure::SessionExpired);
            for error in [mutiny_transport_v2::Error::Context, mutiny_transport_v2::Error::Limit] {
                assert_eq!(outgoing_policy_failure(message, error), PeerFailure::Other(message.into()));
            }
        }
    }
    #[test]
    fn g3_worker_typed_join_preserves_expiry_and_legacy_join_is_compatible() {
        assert_eq!(ended(Err(PeerFailure::SessionExpired)).shutdown_typed().unwrap_err(), PeerFailure::SessionExpired);
        assert_eq!(ended(Err(PeerFailure::SessionExpired)).shutdown().unwrap_err(), "Peer session expired");
        assert!(ended(Ok(())).shutdown_typed().is_ok());
    }
    #[test]
    fn g3_worker_diagnostic_text_cannot_become_expiry_and_panics_still_fail() {
        assert!(matches!(ended(Err(PeerFailure::Other("Expired".into()))).shutdown_typed(), Err(PeerFailure::Other(_))));
        let mut worker = ended(Ok(()));
        worker.thread.take().unwrap().join().unwrap().unwrap();
        worker.thread = Some(std::thread::spawn(|| panic!("synthetic G3 worker panic")));
        assert!(matches!(worker.shutdown_typed(), Err(PeerFailure::Other(message)) if message == "Peer worker panicked"));
    }
}

#[cfg(test)]
#[path = "hybrid_peer_worker_submission_pull_tests.rs"]
mod submission_pull_tests;
