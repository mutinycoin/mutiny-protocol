//! The wallet side of automatic history catch-up (approved B1, R3 + clarification 1) over the
//! wallet's single direct `PeerLink`. The schedule is `history_sync::HistorySync`; this module only
//! moves its requests and pages over the admitted history session and installs each planned block
//! through the node's sealed canonical adapter borrowing the wallet's own store
//! (`Replica::with_history_verifier`). Nothing a page claims is believed: every member is verified
//! and committed by the same native path as `Replica::accept`, the terminal full anchor must match
//! before its commit, and the saved height is always re-read from the store afterwards.
//!
//! One active request, page, dependency and fragment window at a time. A failure closes the link;
//! there is no automatic reconnect and no fallback to another mechanism.
use super::{PeerFailure, PeerResult, WalletPeer, TURN_LIMIT, context, guarded};
use crate::history_sync::{Action, HistorySync, PageStatus, PageSummary};
use mutiny_transport_v2::{
    MAX_PAYLOAD,
    object_link::{Event, LocalAuthorization},
    objects::{MAX_BITMAP_BITS, ObjectKind, Offer},
};
use mutinyd_v8::{
    history_protocol_v1::{
        HistoryPage, HistoryRequest, MAX_BLOCKS, MAX_CANDIDATE_BYTES, MAX_CANDIDATE_ENTRIES, MAX_PAGE_BYTES,
        MAX_REQUEST_BYTES,
    },
    history_service_v1::ReceiverHistoryPlan,
};
use std::time::Instant;

/// Fragments requested at once for one object (the bound the node's own client tests use).
const WINDOW: u16 = 16;

struct Window {
    offer: Offer,
    start: u16,
    count: u16,
}

/// History state of one admitted connection. Dropped with the connection: a new connection starts
/// a new client (and a new sequence space) from the saved anchor.
pub struct HistoryClient {
    sync: HistorySync,
    request: Option<HistoryRequest>,
    window: Option<Window>,
    plan: Option<(ReceiverHistoryPlan, Offer)>,
    /// Most candidate entries this wallet offers to receive per page (<= MAX_CANDIDATE_ENTRIES).
    max_entries: u8,
}
impl HistoryClient {
    pub fn sync(&self) -> &HistorySync {
        &self.sync
    }
    /// No request, page, plan or fragment window is outstanding and the schedule is between requests
    /// (at the tip or waiting a refusal out). Only then may the link be quiesced for a planned retirement.
    pub fn idle(&self) -> bool {
        use crate::history_sync::State;
        self.request.is_none()
            && self.window.is_none()
            && self.plan.is_none()
            && matches!(self.sync.state(), State::Current { .. } | State::Waiting { .. })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum HistoryProgress {
    Idle,
    Transport,
    Requested { sequence: u32 },
    Page { status: PageStatus, entries: usize },
    Installed { kind: ObjectKind, height: u64 },
}

fn fragments(offer: &Offer) -> u16 {
    offer.length.div_ceil(MAX_PAYLOAD) as u16
}
fn deadline() -> Instant {
    Instant::now() + TURN_LIMIT
}
fn transport<T>(
    host: &mut WalletPeer,
    what: &'static str,
    f: impl FnOnce(&mut mutiny_transport_v2::object_link::ObjectLink) -> mutiny_transport_v2::Result<T>,
) -> PeerResult<T> {
    guarded(host.link.with_current(|link| f(link).map_err(|e| PeerFailure::transport(what, e))))
}
fn open_window(host: &mut WalletPeer, offer: Offer, start: u16) -> PeerResult<Window> {
    let count = (fragments(&offer) - start).min(WINDOW);
    let frame = transport(host, "Wallet history window", |l| l.request_missing(&offer.id, start, count, 0, false))?;
    host.link.send_typed(&frame, deadline())?;
    Ok(Window { offer, start, count })
}
/// Acknowledge every fragment of a complete object, after its semantic check.
fn full_ack(host: &mut WalletPeer, offer: &Offer) -> PeerResult<()> {
    let total = fragments(offer);
    for start in (0..total).step_by(MAX_BITMAP_BITS as usize) {
        let count = (total - start).min(MAX_BITMAP_BITS);
        let frame = transport(host, "Wallet history receipt", |l| l.receipt(&offer.id, start, count, 0))?;
        host.link.send_typed(&frame, deadline())?;
    }
    Ok(())
}

impl super::Controller {
    /// Start history on a freshly admitted connection. Without the explicit history profile on this
    /// link the client stays stopped as unsupported; nothing else is tried.
    pub fn history_open(&mut self, host: &mut WalletPeer, now: Instant) -> PeerResult<HistoryClient> {
        self.history_open_bounded(host, now, MAX_CANDIDATE_ENTRIES)
    }
    /// `history_open` offering at most `max_entries` candidates per page (a smaller receiver budget is
    /// always allowed; the node then pages whole groups within it). Zero is refused.
    pub fn history_open_bounded(&mut self, host: &mut WalletPeer, now: Instant, max_entries: u8)
        -> PeerResult<HistoryClient> {
        if max_entries == 0 || max_entries > MAX_CANDIDATE_ENTRIES {
            return Err("History receiver entry budget out of range".into());
        }
        let saved = self.replica.current_anchor()?.height;
        let profile = host
            .link
            .with_current(|l| l.authorization() == LocalAuthorization::NodeToWalletHistoryClient)?;
        let mut client =
            HistoryClient { sync: HistorySync::new(saved), request: None, window: None, plan: None, max_entries };
        if let Some(Action::Request { sequence }) = client.sync.connected(now, profile) {
            if let Err(failure) = self.history_request(host, &mut client, sequence, now) {
                host.link.close();
                return Err(failure);
            }
        }
        Ok(client)
    }

    /// One bounded service turn of history. Any failure closes the link and ends this client's
    /// connection state; committed blocks stay committed.
    pub fn history_turn(&mut self, host: &mut WalletPeer, client: &mut HistoryClient, now: Instant)
        -> PeerResult<HistoryProgress> {
        let result = self.history_turn_inner(host, client, now);
        if result.is_err() {
            host.link.close();
            client.sync.disconnected();
            client.request = None;
            client.window = None;
            client.plan = None;
        }
        result
    }

    fn history_request(&mut self, host: &mut WalletPeer, client: &mut HistoryClient, sequence: u32, now: Instant)
        -> PeerResult<()> {
        let saved_anchor = self.replica.current_anchor()?;
        let room = transport(host, "Wallet history capacity", |l| l.history_general_capacity())?;
        // Room for the outgoing request and the incoming page is reserved before any candidate.
        let entries = room.free_objects.saturating_sub(2).min(client.max_entries as usize);
        let bytes = room
            .free_bytes
            .saturating_sub(MAX_REQUEST_BYTES + MAX_PAGE_BYTES)
            .min(MAX_CANDIDATE_BYTES as usize);
        if entries == 0 || bytes == 0 {
            client.sync.local_wait(now);
            return Ok(());
        }
        let request = HistoryRequest {
            sequence,
            saved_anchor,
            max_blocks: MAX_BLOCKS,
            max_candidate_bytes: bytes as u32,
            max_candidate_entries: entries as u8,
        };
        let raw = request.encode().map_err(|e| format!("History request encoding: {e:?}"))?;
        if let Some(frame) = host.pending_control.take() {
            host.link.send_typed(&frame, deadline())?;
        }
        let (_, frame) = host
            .link
            .with_current_transport(|l| l.enqueue(ObjectKind::HistoryRequestV1, &raw, 0))
            .map_err(|e| context("Wallet history request queue", e))?;
        host.link.send_typed(&frame, deadline())?;
        client.request = Some(request);
        Ok(())
    }

    fn history_turn_inner(&mut self, host: &mut WalletPeer, client: &mut HistoryClient, now: Instant)
        -> PeerResult<HistoryProgress> {
        if let Some(Action::Request { sequence }) = client.sync.tick(now) {
            self.history_request(host, client, sequence, now)?;
            return Ok(HistoryProgress::Requested { sequence });
        }
        if let Some(frame) = host.pending_control.take() {
            host.link.send_typed(&frame, deadline())?;
        }
        if !host.link.wait_for_frame_typed(deadline())? {
            return Ok(HistoryProgress::Idle);
        }
        let received = host.link.receive_typed(deadline())?;
        let chain = self.context();
        let event = host.link.dispatch_received_typed(received, |link, event| -> PeerResult<Event> {
            if !link.matches_network(chain.genesis, chain.fingerprint) {
                return Err("Wallet history peer chain mismatch".into());
            }
            link.check_incoming_event(&event).map_err(|e| PeerFailure::transport("Wallet history event", e))?;
            Ok(event)
        })??;
        match event {
            Event::Requested => {
                while let Some(frame) =
                    host.link.with_current_transport(|l| l.send_one()).map_err(|e| context("Wallet fragment", e))?
                {
                    host.link.send_typed(&frame, deadline())?;
                }
                Ok(HistoryProgress::Transport)
            }
            Event::ReceiptRecorded => Ok(HistoryProgress::Transport),
            Event::Offered(offer) => {
                if client.window.is_some() {
                    return Err("History offer while another object is being fetched".into());
                }
                let planned = match &client.plan {
                    None => offer.kind == ObjectKind::HistoryPageV1 && client.request.is_some(),
                    Some((plan, _)) => plan.next_entry().is_some_and(|entry| entry.matches_offer(&offer)),
                };
                if !planned {
                    return Err("History offer is not the next planned object".into());
                }
                client.window = Some(open_window(host, offer, 0)?);
                Ok(HistoryProgress::Transport)
            }
            Event::FragmentReceived => {
                let window = client.window.as_ref().ok_or("History fragment outside a requested window")?;
                let (id, start, count) = (window.offer.id, window.start, window.count);
                let bits = transport(host, "Wallet history progress", |l| l.missing_window(&id, start, count))?;
                if bits.bits.iter().all(|missing| !*missing) && start + count < fragments(&window.offer) {
                    let offer = window.offer.clone();
                    client.window = Some(open_window(host, offer, start + count)?);
                }
                Ok(HistoryProgress::Transport)
            }
            Event::Completed { offer, bytes } => {
                let window = client.window.take().ok_or("History object completed without a request")?;
                if window.offer != offer {
                    return Err("History object differs from the requested one".into());
                }
                match offer.kind {
                    ObjectKind::HistoryPageV1 => self.history_page(host, client, offer, &bytes, now),
                    ObjectKind::CertifiedBlock | ObjectKind::RecoveryEvidence => {
                        self.history_candidate(host, client, offer, &bytes, now)
                    }
                    _ => Err("Unexpected object on the wallet history session".into()),
                }
            }
        }
    }

    fn history_page(&mut self, host: &mut WalletPeer, client: &mut HistoryClient, offer: Offer, bytes: &[u8],
        now: Instant) -> PeerResult<HistoryProgress> {
        let request = client.request.take().ok_or("History page without an active request")?;
        let page = HistoryPage::decode(bytes).map_err(|e| format!("History page: {e:?}"))?;
        page.validate_for(&request).map_err(|e| format!("History page correlation: {e:?}"))?;
        let status = PageStatus::from_wire(page.status as u8).ok_or("History page status")?;
        let entries = page.entries.len();
        let summary = PageSummary {
            sequence: request.sequence,
            status,
            through: page.offered_through_anchor.as_ref().map(|a| a.height),
            tip: page.observed_tip_anchor.as_ref().map(|a| a.height),
            entries,
        };
        client.sync.page(now, &summary).map_err(|_| "History page contradicts the wallet's request")?;
        let link = &mut host.link;
        let plan =
            self.replica.with_history_verifier(|verifier| ReceiverHistoryPlan::accept(link, &request, &offer, page, &*verifier))?;
        let request_id = request.object_id().map_err(|e| format!("History request identity: {e:?}"))?;
        transport(host, "Wallet history request retirement", |l| l.history_retire_consumed_request(&request_id))?;
        full_ack(host, &offer)?;
        if plan.complete() {
            transport(host, "Wallet history plan retirement", |l| l.history_retire_plan(&offer.id))?;
        } else {
            client.plan = Some((plan, offer));
        }
        Ok(HistoryProgress::Page { status, entries })
    }

    fn history_candidate(&mut self, host: &mut WalletPeer, client: &mut HistoryClient, offer: Offer, bytes: &[u8],
        now: Instant) -> PeerResult<HistoryProgress> {
        // Public history ingress never requests signing; an outstanding review is discarded.
        self.tick();
        self.cancel_review();
        let (plan, page) = client.plan.as_mut().ok_or("History candidate without a plan")?;
        let installed = self.replica.with_history_verifier(|verifier| plan.install(&offer, bytes, verifier));
        let complete = plan.complete();
        let page_id = page.id;
        // Whatever the outcome, read the actual saved anchor and reconcile outside the store borrow.
        let anchor = self.replica.current_anchor();
        let refreshed = self.refresh();
        if let Ok(anchor) = &anchor {
            client.sync.committed(anchor.height);
        }
        let proof = installed?;
        anchor?;
        refreshed?;
        // Order (R9): receipt while the copy exists, then consume the proof to reclaim that exact copy,
        // and only then retire the plan (retirement revokes the proof's lease). No raw-hash fallback.
        full_ack(host, &offer)?;
        host.link.history_reclaim_verified(proof)?;
        let height = client.sync.saved();
        if complete {
            transport(host, "Wallet history plan retirement", |l| l.history_retire_plan(&page_id))?;
            client.plan = None;
            if let Some(Action::Request { sequence }) =
                client.sync.page_installed(now).map_err(|_| "History page ended short of its offered anchor")?
            {
                self.history_request(host, client, sequence, now)?;
            }
        }
        Ok(HistoryProgress::Installed { kind: offer.kind, height })
    }
}
