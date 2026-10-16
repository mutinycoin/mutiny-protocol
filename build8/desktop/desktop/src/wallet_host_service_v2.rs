//! Single-owner wallet service. Public UI commands never gain access to custody
//! or arbitrary signing. Production startup remains behind the existing gates.
//! Phase 7: the commands are plan commands (request -> review inputs -> authorize, which approves,
//! signs and durably queues in one step inside the controller -> export). An approval never
//! crosses the command queue; the UI thread only ever holds public review data.
use super::{Controller, Progress, WalletPeer, history::{HistoryClient, HistoryProgress}};
use crate::{
    plan_review::{ReviewInput, ReviewScreen},
    wallet_controller_v2::{QueuedOperation, ReviewOutcome},
    verified_sync_v2::{Balance, Delivery},
    wallet_v2::Identity,
};
use mutiny_consensus_v8::{Hash, anchors::FinalizedAnchor};
use mutiny_transport_v2::objects::Offer;
use mutiny_wallet_core_v8::OperationRequest;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender, TryRecvError, TrySendError},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, String>;
const TICK: Duration = Duration::from_millis(20);
const IO: Duration = Duration::from_millis(100);
const COMMAND_CAPACITY: usize = 1;
const EVENT_CAPACITY: usize = 8;

pub enum Command {
    Unlock(Zeroizing<String>),
    Lock,
    /// Submit for actual local input only. Queue insertion captures its time.
    UserActivity,
    /// Plan an operation for this wallet and put its review on screen.
    Request(Box<OperationRequest>),
    /// What the person did on the review screen. `Authorize` approves (the gate must be ready at
    /// the current verified head), signs and durably queues, in one step.
    Review(ReviewInput),
    CancelReview,
    Snapshot {
        payment: Option<Hash>,
    },
    /// The public bytes of a queued operation, for export by file or QR (Q1, Q12).
    Export {
        id: Hash,
    },
    /// Drop a queued record and release its reservations (never revokes the signed bytes).
    Forget {
        id: Hash,
    },
    Attach(Box<WalletPeer>),
    Detach,
    /// Stop all further turns on the attached history link, keeping it attached and unread, so the
    /// node can retire the session as planned. Refused (QuiesceDeferred) while history work is in flight.
    Quiesce,
    Advertise {
        transaction: Hash,
    },
    AdvertiseOperation {id:Hash},
    QueryOperationStatus {ids:Vec<Hash>},
    ReclaimOperation {object:Hash},
    RetryHistory {
        object: Hash,
    },
    ReclaimHistory {
        object: Hash,
    },
    ReclaimPayment {
        object: Hash,
    },
}
struct Queued {
    command: Command,
    at: Instant,
}
pub struct RejectedCommand {
    pub command: Command,
    pub reason: &'static str,
}
#[derive(Debug)]
pub struct View {
    pub anchor: FinalizedAnchor,
    pub identity: Option<Identity>,
    pub balance: Option<Balance>,
    pub payment: Option<(Hash, Delivery)>,
}
/// What the service reports. Its `Debug` never shows exported bytes (Order W10, below).
pub enum Event {
    Unlocked(Identity),
    Locked,
    ActivityRecorded,
    /// The review on screen (new or updated), with what the gate says about it.
    Review(Box<ReviewScreen>),
    /// Approved, signed and durably queued: queued locally, never "delivered" or "settled".
    Queued(QueuedOperation),
    Cancelled,
    Exported {
        id: Hash,
        bytes: Vec<u8>,
    },
    Forgotten {
        id: Hash,
    },
    Snapshot(Box<View>),
    PeerAttached,
    PeerDetached,
    Advertised(Offer),
    History(Progress),
    Reclaimed,
    /// The failing operation has locked custody and detached the peer. A local
    /// retry can explicitly unlock or attach; no background retry signs again.
    Rejected(String),
    /// The node session reached the transport's own lifetime (G3). Custody is locked and the peer
    /// detached exactly as for any other link failure; a new session needs an explicit fresh attach.
    SessionExpired,
    /// Automatic history (B1) on a history-profile connection: the wallet's own verified height, the
    /// node's last reported tip (a hint only) and the shell line describing both.
    Sync { saved: u64, tip: Option<u64>, line: String },
    /// The history link is attached but no longer turned: no request, read or write happens on it until
    /// Detach. `anchor` is the wallet's own verified anchor at that moment.
    Quiesced { anchor: FinalizedAnchor },
    /// History work is in flight on the link; try Quiesce again after it settles.
    QuiesceDeferred,
}
/// The event a failed peer turn produces: the typed expiry, or the diagnostic text as before.
pub(crate) fn link_failure_event(failure: super::PeerFailure) -> Event {
    match failure {
        super::PeerFailure::SessionExpired => Event::SessionExpired,
        super::PeerFailure::Other(reason) => Event::Rejected(reason),
    }
}
/// Order W10: `Debug` is a diagnostic path, so it never shows an export's bytes (a complete hash-lock
/// claim carries its preimage, revealed only in that authorized settlement payload); every other
/// variant shows what it holds, as the derived `Debug` did.
impl std::fmt::Debug for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unlocked(identity) => f.debug_tuple("Unlocked").field(identity).finish(),
            Self::Locked => f.write_str("Locked"),
            Self::ActivityRecorded => f.write_str("ActivityRecorded"),
            Self::Review(screen) => f.debug_tuple("Review").field(screen).finish(),
            Self::Queued(queued) => f.debug_tuple("Queued").field(queued).finish(),
            Self::Cancelled => f.write_str("Cancelled"),
            Self::Exported { id, bytes } => f
                .debug_struct("Exported")
                .field("id", id)
                .field("bytes", &format_args!("<{} bytes, not shown>", bytes.len()))
                .finish(),
            Self::Forgotten { id } => f.debug_struct("Forgotten").field("id", id).finish(),
            Self::Snapshot(view) => f.debug_tuple("Snapshot").field(view).finish(),
            Self::PeerAttached => f.write_str("PeerAttached"),
            Self::PeerDetached => f.write_str("PeerDetached"),
            Self::Advertised(offer) => f.debug_tuple("Advertised").field(offer).finish(),
            Self::History(progress) => f.debug_tuple("History").field(progress).finish(),
            Self::Reclaimed => f.write_str("Reclaimed"),
            Self::Rejected(reason) => f.debug_tuple("Rejected").field(reason).finish(),
            Self::SessionExpired => f.write_str("SessionExpired"),
            Self::Quiesced { anchor } => f.debug_struct("Quiesced").field("anchor", anchor).finish(),
            Self::QuiesceDeferred => f.write_str("QuiesceDeferred"),
            Self::Sync { saved, tip, line } => {
                f.debug_struct("Sync").field("saved", saved).field("tip", tip).field("line", line).finish()
            }
        }
    }
}
pub struct Service {
    commands: SyncSender<Queued>,
    events: Receiver<Event>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<Result<()>>>,
}

fn detach(peer: &mut Option<WalletPeer>) {
    if let Some(mut old) = peer.take() {
        old.link.close();
    }
}
fn notify(events: &SyncSender<Event>, event: Event) -> Result<()> {
    events.try_send(event).map_err(|error| match error {
        TrySendError::Full(_) => "Wallet event consumer backpressure".into(),
        TrySendError::Disconnected(_) => "Wallet event consumer disconnected".into(),
    })
}
fn sync_event(history: &HistoryClient) -> Event {
    let sync = history.sync();
    Event::Sync { saved: sync.saved(), tip: sync.observed_tip(), line: sync.describe() }
}
fn command(
    wallet: &mut Controller,
    peer: &mut Option<WalletPeer>,
    history: &mut Option<HistoryClient>,
    quiesced: &mut bool,
    queued: Queued,
) -> super::PeerResult<Event> {
    wallet.tick();
    match queued.command {
        Command::Unlock(password) => {
            wallet.unlock(&password)?;
            Ok(Event::Unlocked(
                wallet.identity().ok_or("Wallet locked")?.clone(),
            ))
        }
        Command::Lock => {
            wallet.lock();
            Ok(Event::Locked)
        }
        Command::UserActivity => {
            // A delayed event must not refresh the private session to the time
            // it is processed, and cannot revive an already expired session.
            // The signer's own idle clock is refreshed too (it would otherwise
            // lock the key while the person is active); a signer that already
            // locked itself locks the session (wallet review fixes).
            if wallet.session.is_some()
                && wallet.last_activity.is_some_and(|last| queued.at >= last)
            {
                wallet.last_activity = Some(queued.at);
                wallet.tick();
                wallet.touch_signer();
            }
            Ok(Event::ActivityRecorded)
        }
        Command::Request(request) => wallet
            .request(*request)
            .map(|screen| Event::Review(Box::new(screen)))
            .map_err(super::PeerFailure::from),
        Command::Review(input) => match wallet.review_input(input)? {
            ReviewOutcome::Screen(screen) => Ok(Event::Review(screen)),
            ReviewOutcome::Queued(queued) => Ok(Event::Queued(queued)),
            ReviewOutcome::Cancelled => Ok(Event::Cancelled),
        },
        Command::CancelReview => {
            wallet.cancel_review();
            Ok(Event::Cancelled)
        }
        Command::Snapshot { payment } => {
            let anchor = wallet.replica.current_anchor()?;
            let identity = wallet.identity().cloned();
            let balance = if identity.is_some() {
                Some(wallet.verified_balance()?)
            } else {
                None
            };
            let payment = payment
                .map(|id| wallet.delivery(id).map(|status| (id, status)))
                .transpose()?;
            Ok(Event::Snapshot(Box::new(View {
                anchor,
                identity,
                balance,
                payment,
            })))
        }
        Command::Export { id } => wallet
            .export(id)
            .map(|bytes| Event::Exported { id, bytes })
            .map_err(super::PeerFailure::from),
        Command::Forget { id } => wallet.forget(id).map(|()| Event::Forgotten { id }).map_err(super::PeerFailure::from),
        Command::Attach(mut new) => {
            // The admission lease and queue are already bound to this exact
            // authenticated connection. Recheck its current pin before use.
            new.link.with_current(|_| ())?;
            detach(peer);
            *history = None;
            *quiesced = false;
            // A history-profile connection starts automatic catch-up at once from the saved anchor (B1);
            // any other connection keeps the existing history path and gets no history client.
            let profile = new.link.with_current(|l| {
                l.authorization() == mutiny_transport_v2::object_link::LocalAuthorization::NodeToWalletHistoryClient
            })?;
            if profile {
                *history = Some(wallet.history_open(&mut new, Instant::now())?);
            }
            *peer = Some(*new);
            Ok(Event::PeerAttached)
        }
        Command::Detach => {
            detach(peer);
            *history = None;
            *quiesced = false;
            Ok(Event::PeerDetached)
        }
        Command::Quiesce => {
            peer.as_ref().ok_or("No authenticated wallet peer")?;
            let client = history.as_ref().ok_or("Quiesce applies to a history-profile link only")?;
            if !client.idle() {
                return Ok(Event::QuiesceDeferred);
            }
            *quiesced = true;
            Ok(Event::Quiesced { anchor: wallet.replica.current_anchor()? })
        }
        Command::Advertise { transaction } => wallet
            .advertise_payment_typed(
                peer.as_mut().ok_or("No authenticated wallet peer")?,
                transaction,
                // Durable-outbox reconciliation verifies canonical signatures
                // before egress. The host adapter independently caps the actual
                // socket send at 100 ms after that local verification completes.
                Instant::now() + Duration::from_secs(30),
            )
            .map(Event::Advertised),
        Command::AdvertiseOperation {id} => wallet.advertise_operation_typed(
            peer.as_mut().ok_or("No authenticated wallet peer")?,id,Instant::now()+Duration::from_secs(30)).map(Event::Advertised),
        Command::QueryOperationStatus {ids} => wallet.query_operation_status_typed(
            peer.as_mut().ok_or("No authenticated wallet peer")?,&ids,Instant::now()+Duration::from_secs(30)).map(Event::Advertised),
        Command::ReclaimOperation {object} => wallet.reclaim_confirmed_operation_typed(
            peer.as_mut().ok_or("No authenticated wallet peer")?,object).map(|()|Event::Reclaimed),
        Command::RetryHistory { object } => wallet
            .retry_peer_history_typed(peer.as_mut().ok_or("No authenticated wallet peer")?, object)
            .map(Event::History),
        Command::ReclaimHistory { object } => {
            wallet.reclaim_peer_history_typed(
                peer.as_mut().ok_or("No authenticated wallet peer")?,
                object,
            )?;
            Ok(Event::Reclaimed)
        }
        Command::ReclaimPayment { object } => {
            wallet.reclaim_confirmed_payment_typed(
                peer.as_mut().ok_or("No authenticated wallet peer")?,
                object,
            )?;
            Ok(Event::Reclaimed)
        }
    }
}
fn run(
    mut wallet: Controller,
    commands: Receiver<Queued>,
    events: SyncSender<Event>,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let mut peer = None;
    let mut history: Option<HistoryClient> = None;
    let mut quiesced = false;
    let result = (|| {
        while !stop.load(Ordering::Acquire) {
            let started = Instant::now();
            // Expiry is serviced even when UI input and network traffic stop.
            wallet.tick();
            match commands.try_recv() {
                Ok(queued) => match command(&mut wallet, &mut peer, &mut history, &mut quiesced, queued) {
                    Ok(event) => {
                        let attached = matches!(event, Event::PeerAttached);
                        notify(&events, event)?;
                        if attached && let Some(history) = history.as_ref() {
                            notify(&events, sync_event(history))?;
                        }
                    }
                    Err(failure) => {
                        wallet.lock();
                        detach(&mut peer);
                        history = None;
                        quiesced = false;
                        notify(&events, link_failure_event(failure))?;
                    }
                },
                Err(TryRecvError::Disconnected) => break,
                Err(TryRecvError::Empty) => {}
            }
            if stop.load(Ordering::Acquire) {
                break;
            }
            if quiesced {
                // Planned retirement in progress: the link stays attached and is not touched at all.
            } else if let (Some(link), Some(client)) = (peer.as_mut(), history.as_mut()) {
                // History-profile connection: the B1 client owns every turn of this link.
                match wallet.history_turn(link, client, Instant::now()) {
                    Ok(HistoryProgress::Idle | HistoryProgress::Transport) => {}
                    Ok(_) => notify(&events, sync_event(client))?,
                    Err(failure) => {
                        wallet.lock();
                        detach(&mut peer);
                        history = None;
                        notify(&events, link_failure_event(failure))?;
                    }
                }
            } else if let Some(link) = peer.as_mut() {
                match wallet.peer_turn_typed(link, Instant::now() + IO) {
                    Ok(None | Some(Progress::Transport)) => {}
                    Ok(Some(history)) => notify(&events, Event::History(history))?,
                    Err(failure) => {
                        wallet.lock();
                        detach(&mut peer);
                        notify(&events, link_failure_event(failure))?;
                    }
                }
            }
            if let Some(left) = TICK.checked_sub(started.elapsed()) {
                thread::sleep(left);
            }
        }
        Ok(())
    })();
    // Also runs for event backpressure. Exact signed outbox bytes survive; no
    // approval or unlocked session survives a failed event consumer.
    wallet.lock();
    detach(&mut peer);
    drop(history);
    stop.store(true, Ordering::Release);
    result
}
impl Service {
    pub fn start(wallet: Controller) -> Result<Self> {
        crate::wallet_v2::ready().map_err(str::to_owned)?;
        let (commands, rx) = mpsc::sync_channel(COMMAND_CAPACITY);
        let (tx, events) = mpsc::sync_channel(EVENT_CAPACITY);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let thread = thread::Builder::new()
            .name("build8-wallet-service".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || run(wallet, rx, tx, stopping))
            .map_err(|e| format!("Wallet service start: {e}"))?;
        Ok(Self {
            commands,
            events,
            stop,
            thread: Some(thread),
        })
    }
    pub fn try_submit(&self, command: Command) -> std::result::Result<(), Box<RejectedCommand>> {
        if matches!(&command, Command::Unlock(password) if password.len() > 4096) {
            return Err(Box::new(RejectedCommand {
                command,
                reason: "Wallet password input exceeds service limit",
            }));
        }
        if self.stop.load(Ordering::Acquire) {
            return Err(Box::new(RejectedCommand {
                command,
                reason: "Wallet service stopping",
            }));
        }
        self.commands
            .try_send(Queued {
                command,
                at: Instant::now(),
            })
            .map_err(|error| {
                Box::new(match error {
                    TrySendError::Full(queued) => RejectedCommand {
                        command: queued.command,
                        reason: "Wallet command backpressure",
                    },
                    TrySendError::Disconnected(queued) => RejectedCommand {
                        command: queued.command,
                        reason: "Wallet service disconnected",
                    },
                })
            })
    }
    pub fn try_event(&self) -> std::result::Result<Event, TryRecvError> {
        self.events.try_recv()
    }
    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(|t| t.is_finished())
    }
    /// Joins after any in-flight validation/custody transaction finishes. This
    /// method belongs to application shutdown, never the UI repaint path.
    pub fn shutdown(mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        self.thread
            .take()
            .ok_or("Wallet service already joined")?
            .join()
            .map_err(|_| "Wallet service panicked".to_string())?
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
