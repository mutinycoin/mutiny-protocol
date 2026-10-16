//! NON-SHIPPING B1 acceptance flow through the wallet Service (TEST-VALUE only). One composed run:
//! Service start, unlock, explicit Attach of a fresh history-profile connection, Sync until the
//! wallet's OWN verified height reaches the target, Request/Review/Authorize one payment through the
//! service queue, Advertise it on the SAME history link, wait until the wallet's own replay reports it
//! confirmed, then for each session a planned retirement: Quiesce (the Service stops touching the
//! still-attached link once its history work is idle), the node's exact retirement acknowledgement,
//! and only then Detach and Service shutdown/join. The same wallet files then open in a NEW Service,
//! whose locked state, identity, full anchor and payment are compared, a fresh connection is attached,
//! the payment is shown again, and that second session is retired the same way.
//!
//! Witness level: the review inputs are entered by this flow through Service commands (a synthetic
//! Service witness), not by a person in the UI. Nothing here signs outside the controller's own
//! review gate, exports a key, password, vault or descriptor, provisions anything, or opens a second
//! payment connection. Every step is reported as one JSON record. Every wait checks the one original
//! deadline before accepting an event and after each callback; nothing extends it.
use crate::wallet_controller_v2::{
    Controller,
    host::{
        WalletPeer,
        service::{Command, Event, Service},
    },
};
use crate::{plan_review::ReviewInput, verified_sync_v2::Delivery};
use mutiny_consensus_v8::{Hash, anchors::FinalizedAnchor};
use mutiny_wallet_core_v8::{OperationRequest, PaymentRequest};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, String>;

/// What the run must achieve and its one overall bound.
pub(crate) struct Plan {
    /// The wallet's own verified height to reach before paying (100 for the live H101 sequence).
    pub target_height: u64,
    pub recipient: Hash,
    pub atoms: u64,
    pub deadline: Instant,
}

/// A fresh, authenticated history-profile connection to the node, made within `deadline`. Called once
/// per session (1 = first Service, 2 = after restart), only after the node side is ready to admit it.
pub(crate) trait HistoryConnector {
    fn connect(&mut self, session: u32, deadline: Instant) -> Result<WalletPeer>;
}

/// The node's explicit, successful retirement of exactly that session (native join Ok), returned as the
/// node's own public record. Any other outcome is an error; no counter, join count or error text stands
/// in for it. The live adapter belongs to the node owner's acknowledgement API.
pub(crate) trait RetirementBarrier {
    fn await_retired(&mut self, session: u32, deadline: Instant) -> Result<Value>;
}

/// The live seam until the node owner's acknowledgement API is bound: the flow stops here, honestly.
pub(crate) struct PendingRetirementApi;
impl RetirementBarrier for PendingRetirementApi {
    fn await_retired(&mut self, _: u32, _: Instant) -> Result<Value> {
        Err("node retirement acknowledgement API is pending (node owner R2); no detach or restart attempted".into())
    }
}

fn live(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline { Err("acceptance deadline reached".into()) } else { Ok(()) }
}
fn next(service: &Service, deadline: Instant) -> Result<Event> {
    loop {
        live(deadline)?;
        match service.try_event() {
            Ok(event) => return Ok(event),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => return Err("wallet service stopped".into()),
            Err(std::sync::mpsc::TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(5)),
        }
    }
}
fn submit(service: &Service, command: Command, deadline: Instant) -> Result<()> {
    live(deadline)?;
    service.try_submit(command).map_err(|rejected| rejected.reason.to_string())
}
/// The next event that is not a Sync report; Sync reports are recorded as they pass. A link failure
/// is always an error here (it is never read as a planned retirement).
fn reply(service: &Service, deadline: Instant, emit: &mut dyn FnMut(Value)) -> Result<Event> {
    loop {
        match next(service, deadline)? {
            Event::Sync { saved, tip, line } => emit(json!({"step":"sync","saved":saved,"tip":tip,"line":line})),
            Event::Rejected(reason) => return Err(format!("service rejected: {reason}")),
            Event::SessionExpired => return Err("node session expired".into()),
            other => return Ok(other),
        }
    }
}
struct Seen {
    anchor: FinalizedAnchor,
    payment: Option<Delivery>,
    locked: bool,
}
fn snapshot(service: &Service, id: Hash, deadline: Instant, emit: &mut dyn FnMut(Value)) -> Result<Seen> {
    submit(service, Command::Snapshot { payment: Some(id) }, deadline)?;
    match reply(service, deadline, emit)? {
        Event::Snapshot(view) => Ok(Seen {
            anchor: view.anchor,
            payment: view.payment.map(|(_, delivery)| delivery),
            locked: view.identity.is_none(),
        }),
        other => Err(format!("snapshot expected, got {other:?}")),
    }
}
fn unlock(service: &Service, password: &str, deadline: Instant, emit: &mut dyn FnMut(Value)) -> Result<String> {
    submit(service, Command::Unlock(Zeroizing::new(password.to_owned())), deadline)?;
    match reply(service, deadline, emit)? {
        // Only the public address id is reported; no descriptor or key material.
        Event::Unlocked(identity) => Ok(identity.address_id.clone()),
        other => Err(format!("unlock expected, got {other:?}")),
    }
}
fn attach(service: &Service, connector: &mut dyn HistoryConnector, session: u32, deadline: Instant,
    emit: &mut dyn FnMut(Value)) -> Result<()> {
    live(deadline)?;
    let peer = connector.connect(session, deadline)?;
    live(deadline)?;
    submit(service, Command::Attach(Box::new(peer)), deadline)?;
    match reply(service, deadline, emit)? {
        Event::PeerAttached => {
            emit(json!({"step":"attached","session":session,"profile":"history"}));
            Ok(())
        }
        other => Err(format!("attach expected, got {other:?}")),
    }
}
/// Planned retirement of the attached session: quiesce once history is idle, then the node's exact
/// acknowledgement, then Detach. Returns the wallet's verified anchor at quiesce.
fn retire(service: &Service, barrier: &mut dyn RetirementBarrier, session: u32, deadline: Instant,
    emit: &mut dyn FnMut(Value)) -> Result<FinalizedAnchor> {
    let anchor = loop {
        submit(service, Command::Quiesce, deadline)?;
        match reply(service, deadline, emit)? {
            Event::Quiesced { anchor } => break anchor,
            Event::QuiesceDeferred => std::thread::sleep(Duration::from_millis(100)),
            other => return Err(format!("quiesce expected, got {other:?}")),
        }
    };
    emit(json!({"step":"quiesced","session":session,"verified_height":anchor.height,"verified_block":hex::encode(anchor.block)}));
    let ack = barrier.await_retired(session, deadline)?;
    live(deadline)?;
    emit(json!({"step":"node_retired","session":session,"ack":ack}));
    submit(service, Command::Detach, deadline)?;
    match reply(service, deadline, emit)? {
        Event::PeerDetached => Ok(anchor),
        other => Err(format!("detach expected, got {other:?}")),
    }
}

/// Run the whole flow. `open` opens the same wallet files each time (first run and restart).
pub(crate) fn run(
    open: &mut dyn FnMut() -> Result<Controller>,
    password: &str,
    connector: &mut dyn HistoryConnector,
    barrier: &mut dyn RetirementBarrier,
    plan: &Plan,
    emit: &mut dyn FnMut(Value),
) -> Result<Hash> {
    let deadline = plan.deadline;
    live(deadline)?;
    // First Service.
    let service = Service::start(open()?)?;
    let address = unlock(&service, password, deadline, emit)?;
    emit(json!({"step":"unlocked","address_id":address}));
    attach(&service, connector, 1, deadline, emit)?;
    // Catch up: the wallet's own verified height, never the node's report.
    loop {
        match next(&service, deadline)? {
            Event::Sync { saved, tip, line } => {
                emit(json!({"step":"sync","saved":saved,"tip":tip,"line":line}));
                if saved >= plan.target_height && line.contains("Up to date") {
                    break;
                }
            }
            Event::Rejected(reason) => return Err(format!("service rejected during catch-up: {reason}")),
            Event::SessionExpired => return Err("node session expired during catch-up".into()),
            other => return Err(format!("unexpected event during catch-up: {other:?}")),
        }
    }
    // The wallet's own full verified anchor at the target, before paying.
    let head = {
        submit(&service, Command::Snapshot { payment: None }, deadline)?;
        match reply(&service, deadline, emit)? {
            Event::Snapshot(view) => view.anchor,
            other => return Err(format!("snapshot expected, got {other:?}")),
        }
    };
    emit(json!({"step":"caught_up","target":plan.target_height,"verified_height":head.height,
        "verified_block":hex::encode(head.block),"genesis":hex::encode(head.genesis)}));
    // One payment through the review gate (synthetic Service witness).
    submit(&service, Command::Request(Box::new(OperationRequest::Payment(PaymentRequest::new(plan.recipient, plan.atoms)))), deadline)?;
    let screen = match reply(&service, deadline, emit)? {
        Event::Review(screen) => *screen,
        other => return Err(format!("review expected, got {other:?}")),
    };
    // The coins the review selected (public outpoints only), for matching against replayed history.
    let inputs: Vec<String> = screen.review.inputs().iter().map(|point| format!("{point:?}")).collect();
    emit(json!({"step":"reviewed","inputs":inputs,"next_height":head.height + 1}));
    for index in screen.review.destinations_needing_check() {
        let typed = screen.review.destination_check_text(index);
        submit(&service, Command::Review(ReviewInput::ConfirmDestination { index, typed }), deadline)?;
        reply(&service, deadline, emit)?;
    }
    for ack in screen.review.acknowledgements() {
        submit(&service, Command::Review(ReviewInput::Acknowledge(*ack)), deadline)?;
        reply(&service, deadline, emit)?;
    }
    if let Some(phrase) = screen.review.confirmation_phrase() {
        submit(&service, Command::Review(ReviewInput::ConfirmPhrase(phrase.into())), deadline)?;
        reply(&service, deadline, emit)?;
    }
    submit(&service, Command::Review(ReviewInput::Authorize), deadline)?;
    let id = match reply(&service, deadline, emit)? {
        Event::Queued(queued) => queued.id,
        other => return Err(format!("queued payment expected, got {other:?}")),
    };
    emit(json!({"step":"queued","id":hex::encode(id),"witness":"synthetic Service review inputs"}));
    submit(&service, Command::Advertise { transaction: id }, deadline)?;
    match reply(&service, deadline, emit)? {
        Event::Advertised(offer) => emit(json!({"step":"advertised","id":hex::encode(id),"object_id":hex::encode(offer.id),
            "link":"same history session"})),
        other => return Err(format!("advertised expected, got {other:?}")),
    }
    // Confirmed only by the wallet's own replay of a later block.
    let confirmed = loop {
        let seen = snapshot(&service, id, deadline, emit)?;
        if let Some(Delivery::ConfirmedAt(at)) = seen.payment {
            emit(json!({"step":"confirmed","id":hex::encode(id),"own_replay_height":at,"verified_height":seen.anchor.height,
                "verified_block":hex::encode(seen.anchor.block)}));
            break at;
        }
        std::thread::sleep(Duration::from_millis(250));
    };
    if confirmed != plan.target_height + 1 {
        return Err(format!("confirmed at {confirmed}, expected the next block {}", plan.target_height + 1));
    }
    let before = retire(&service, barrier, 1, deadline, emit)?;
    live(deadline)?;
    service.shutdown()?;
    emit(json!({"step":"service_joined","session":1}));
    // Restart: the same wallet files in a NEW Service; compare locked state, full anchor and payment.
    live(deadline)?;
    let service = Service::start(open()?)?;
    let seen = snapshot(&service, id, deadline, emit)?;
    if !seen.locked || seen.anchor != before || seen.payment != Some(Delivery::ConfirmedAt(confirmed)) {
        return Err(format!("after restart: locked {}, anchor equal {}, payment {:?}", seen.locked, seen.anchor == before, seen.payment));
    }
    emit(json!({"step":"restart_state","custody_locked":true,"anchor_equal":true,"verified_height":seen.anchor.height,
        "verified_block":hex::encode(seen.anchor.block),"own_replay_height":confirmed}));
    let again = unlock(&service, password, deadline, emit)?;
    if again != address {
        return Err("a different wallet identity after restart".into());
    }
    emit(json!({"step":"restart_unlocked","same_address_id":true}));
    attach(&service, connector, 2, deadline, emit)?;
    let seen = snapshot(&service, id, deadline, emit)?;
    if seen.payment != Some(Delivery::ConfirmedAt(confirmed)) || seen.anchor.height < before.height {
        return Err(format!("after fresh attach: payment {:?}, height {}", seen.payment, seen.anchor.height));
    }
    emit(json!({"step":"restart_attached","verified_height":seen.anchor.height,"own_replay_height":confirmed}));
    retire(&service, barrier, 2, deadline, emit)?;
    live(deadline)?;
    service.shutdown()?;
    emit(json!({"step":"service_joined","session":2}));
    emit(json!({"step":"done","id":hex::encode(id)}));
    Ok(id)
}
