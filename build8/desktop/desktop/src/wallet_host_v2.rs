//! Wallet-only host integration. The caller supplies an already pinned peer;
//! this module opens no listener and cannot change production launch gates.
//! Service turns must run on the controller's owning service thread, not the UI
//! repaint thread. Transport never receives the vault or private session.
use super::Controller;
use crate::verified_sync_v2::{Balance, Delivery};
use eframe::egui;
use mutiny_consensus_v8::Hash;
use mutiny_transport_v2::{
    object_link::Event,
    objects::{ObjectKind, Offer},
};
use mutinyd_v8::hybrid_peer_admission_v2::PeerLink;
pub use mutinyd_v8::hybrid_peer_error_v2::{PeerFailure, PeerResult};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

type Result<T> = std::result::Result<T, String>;
const TURN_LIMIT: Duration = Duration::from_millis(100);

/// The link operations a received history event uses, so their transport errors keep their type (G3).
/// `ObjectLink` is the only production implementation; tests substitute exact transport failures.
trait HistoryLink {
    fn next_missing_request(
        &mut self,
        id: &Hash,
        hops: u8,
        nack: bool,
    ) -> mutiny_transport_v2::Result<Option<mutiny_transport_v2::object_link::RequestWindow>>;
    fn missing_window(&self, id: &Hash, start: u16, count: u16) -> mutiny_transport_v2::Result<mutiny_transport_v2::objects::Bitmap>;
    fn completed(&self, id: &Hash) -> mutiny_transport_v2::Result<(Offer, Vec<u8>)>;
}
impl HistoryLink for mutiny_transport_v2::object_link::ObjectLink {
    fn next_missing_request(
        &mut self,
        id: &Hash,
        hops: u8,
        nack: bool,
    ) -> mutiny_transport_v2::Result<Option<mutiny_transport_v2::object_link::RequestWindow>> {
        mutiny_transport_v2::object_link::ObjectLink::next_missing_request(self, id, hops, nack)
    }
    fn missing_window(&self, id: &Hash, start: u16, count: u16) -> mutiny_transport_v2::Result<mutiny_transport_v2::objects::Bitmap> {
        mutiny_transport_v2::object_link::ObjectLink::missing_window(self, id, start, count)
    }
    fn completed(&self, id: &Hash) -> mutiny_transport_v2::Result<(Offer, Vec<u8>)> {
        mutiny_transport_v2::object_link::ObjectLink::completed(self, id)
    }
}
/// Flattens a `PeerLink::with_current` guard result around a typed action: a guard refusal (closed link,
/// retired pin) is `Other`; the action's own typed failure passes unchanged.
fn guarded<T>(result: Result<PeerResult<T>>) -> PeerResult<T> {
    result.map_err(PeerFailure::from)?
}
/// Adds a diagnostic prefix to an `Other` failure; the session-expiry discriminant passes unchanged.
fn context(prefix: &str, failure: PeerFailure) -> PeerFailure {
    match failure {
        PeerFailure::SessionExpired => PeerFailure::SessionExpired,
        PeerFailure::Other(message) => PeerFailure::Other(format!("{prefix}: {message}")),
    }
}

#[path = "wallet_host_service_v2.rs"]
pub mod service;
// Automatic history catch-up over the admitted history session (B1).
#[path = "wallet_history_client_v2.rs"]
pub mod history;

/// Owns progress for this exact admitted connection. Reconnect reconstructs
/// missing windows from the durable object queue, never from packet counts.
pub struct WalletPeer {
    link: PeerLink,
    windows: BTreeMap<Hash, (u16, u16)>,
    // One already encoded control frame, owned by this exact connection.
    // Flush it before allocating another outbound frame: channel sequence
    // numbers must keep their original order across service commands.
    pending_control: Option<Vec<u8>>,
    #[cfg(test)]
    after_dispatch_delay: Duration,
    #[cfg(test)]
    after_readiness_delay: Duration,
}
impl WalletPeer {
    /// Whether durable completed bytes of `object` may be used on THIS session, without using them and
    /// without closing the link. Under the restricted wallet-client admission a reconnect must see a
    /// fresh authenticated offer first, so this is `false` until the node offers the object again.
    pub fn completed_retry_authorized(&mut self, object: Hash) -> Result<bool> {
        self.link.with_current(|link| link.completed_incoming(&object).is_ok())
    }
    /// The admitted history session's public identity (session id, node peer id) for correlating the
    /// node's own retirement record with this exact connection. Fails if the link is not a current
    /// history-profile session.
    pub fn history_session_identity(&mut self) -> PeerResult<(Hash, Hash)> {
        let proof = self.link.history_session()?;
        Ok((proof.session_id(), proof.peer_id()))
    }
    /// Close this connection's carrier; the durable queue stays as it is for a later session.
    pub fn close(&mut self) {
        self.link.close();
    }
    pub fn new(link: PeerLink) -> Self {
        Self {
            link,
            windows: BTreeMap::new(),
            pending_control: None,
            #[cfg(test)]
            after_dispatch_delay: Duration::ZERO,
            #[cfg(test)]
            after_readiness_delay: Duration::ZERO,
        }
    }
}

#[derive(Debug)]
pub enum Progress {
    Transport,
    History { object: Hash, inserted: bool },
    Recovery { object: Hash, inserted: bool },
    /// Peer hints only. They neither install history nor settle a wallet outbox entry.
    StatusHints { object: Hash, count: usize },
}

impl Controller {
    pub fn reclaim_confirmed_operation(&mut self,host:&mut WalletPeer,object:Hash)->Result<()> {
        self.reclaim_confirmed_operation_typed(host,object).map_err(String::from)
    }
    /// `reclaim_confirmed_operation` keeping the transport's expiry discriminant (G3).
    pub fn reclaim_confirmed_operation_typed(&mut self,host:&mut WalletPeer,object:Hash)->PeerResult<()> {
        guarded(host.link.with_current(|link| -> PeerResult<()> {
            let (offer,bytes)=link.completed(&object).map_err(|e|PeerFailure::transport("Wallet completed operation",e))?;
            let list=match offer.kind {ObjectKind::SignedTransaction=>0,ObjectKind::SignedOperation=>1,
                _=>return Err("Not a canonical operation transport object".into())};
            let submission=mutiny_consensus_v8::submission_v1::Submission::decode(list,&bytes).map_err(|e|format!("Completed operation: {e:?}"))?;
            if !matches!(self.delivery(submission.id)?,Delivery::ConfirmedAt(_)){return Err("Operation has no own canonical replay confirmation".into())}
            link.discard(&object).map_err(|e|PeerFailure::transport("Wallet operation reclaim",e))
        }))
    }
    /// Advertise the exact durable COMPLETE canonical operation after local revalidation.
    /// Maker offers, freeze witnesses and partial exchange objects are export-only and refused.
    pub fn advertise_operation(&mut self, host:&mut WalletPeer,id:Hash,limit:Instant)->Result<Offer> {
        self.advertise_operation_typed(host,id,limit).map_err(String::from)
    }
    /// `advertise_operation` keeping the transport's expiry discriminant (G3); every local
    /// revalidation refusal stays `Other`.
    pub fn advertise_operation_typed(&mut self, host:&mut WalletPeer,id:Hash,limit:Instant)->PeerResult<Offer> {
        use mutiny_wallet_core_v8::Outbox;
        self.tick();self.refresh()?;
        let context=self.context();
        if !host.link.with_current(|link| link.matches_network(context.genesis,context.fingerprint))? {
            return Err("Wallet peer is not pinned to this chain context".into());
        }
        let record=self.operations.records().map_err(|e|e.to_string())?.into_iter()
            .find(|r|r.id==id&&r.complete&&r.status.is_open()).ok_or("Operation is not complete and pending at the verified head")?;
        let (list,kind)=match record.kind {
            mutiny_wallet_core_v8::OperationKind::WalletRotation=>(0,ObjectKind::SignedTransaction),
            mutiny_wallet_core_v8::OperationKind::MakerOffer|mutiny_wallet_core_v8::OperationKind::TreasuryFreezeOffer=>return Err("Above-consensus witnesses are export-only".into()),
            _=>(1,ObjectKind::SignedOperation),
        };
        let submission=mutiny_consensus_v8::submission_v1::Submission::decode(list,&record.bytes).map_err(|e|format!("Canonical submission: {e:?}"))?;
        if submission.id!=id {return Err("Canonical operation identity differs from protected outbox".into())}
        submission.verify_signatures().map_err(|e|format!("Canonical operation signature: {e:?}"))?;
        if let Some(frame)=host.pending_control.take() {host.link.send_typed(&frame,limit.min(Instant::now()+TURN_LIMIT))?;}
        let (offer,frame)=host.link.with_current_transport(|link|link.enqueue(kind,&record.bytes,0)).map_err(|e|self::context("Wallet operation queue",e))?;
        host.link.send_typed(&frame,limit.min(Instant::now()+TURN_LIMIT))?;
        Ok(offer)
    }

    /// Public exact-ID query. Reports remain hints until own canonical replay agrees.
    pub fn query_operation_status(&mut self,host:&mut WalletPeer,ids:&[Hash],limit:Instant)->Result<Offer> {
        self.query_operation_status_typed(host,ids,limit).map_err(String::from)
    }
    /// `query_operation_status` keeping the transport's expiry discriminant (G3).
    pub fn query_operation_status_typed(&mut self,host:&mut WalletPeer,ids:&[Hash],limit:Instant)->PeerResult<Offer> {
        let raw=mutiny_consensus_v8::submission_v1::encode_query(ids).map_err(|e|format!("Bounded status query: {e:?}"))?;
        let context=self.context();
        if !host.link.with_current(|link|link.matches_network(context.genesis,context.fingerprint))? {return Err("Wallet peer chain mismatch".into())}
        if let Some(frame)=host.pending_control.take(){host.link.send_typed(&frame,limit.min(Instant::now()+TURN_LIMIT))?;}
        let (offer,frame)=host.link.with_current_transport(|link|link.enqueue(ObjectKind::StatusQuery,&raw,0)).map_err(|e|self::context("Wallet status query queue",e))?;
        host.link.send_typed(&frame,limit.min(Instant::now()+TURN_LIMIT))?;Ok(offer)
    }
    /// Read balances from local canonical execution and reconcile reservations
    /// first. An unlocked identity is required; a failed read produces no balance.
    /// Reserved = the payment pool's reservations and the operation outbox's (phase 7).
    pub fn verified_balance(&mut self) -> Result<Balance> {
        self.tick();
        let descriptor = hex::decode(
            &self
                .session
                .as_ref()
                .ok_or("Unlock the wallet first")?
                .identity
                .owner_descriptor,
        )
        .map_err(|_| "Invalid wallet descriptor")?;
        self.replica.pending_for_transport(&mut self.outbox)?;
        let mut reserved = self
            .outbox
            .reserved_inputs()
            .map_err(|e| format!("Wallet outbox: {e:?}"))?;
        reserved.extend(
            mutiny_wallet_core_v8::Outbox::reserved(&self.operations)
                .map_err(|e| format!("Wallet operation outbox: {e} ({})", e.code()))?,
        );
        self.replica.balance(&descriptor, &reserved)
    }

    /// Retrieve only already committed public signed bytes. A HAVE or transport
    /// receipt never changes transaction status to confirmed.
    pub fn advertise_payment(
        &mut self,
        host: &mut WalletPeer,
        id: Hash,
        limit: Instant,
    ) -> Result<Offer> {
        self.advertise_payment_typed(host, id, limit).map_err(String::from)
    }
    /// `advertise_payment` keeping the transport's expiry discriminant (G3).
    pub fn advertise_payment_typed(&mut self, host: &mut WalletPeer, id: Hash, limit: Instant) -> PeerResult<Offer> {
        self.tick();
        if let Some(frame) = host.pending_control.take() {
            host.link
                .send_typed(&frame, limit.min(Instant::now() + TURN_LIMIT))
                .map_err(|e| context("Wallet queued history reply", e))?;
        }
        let peer = &mut host.link;
        let raw = self
            .pending_for_transport()?
            .into_iter()
            .find(|raw| {
                mutiny_consensus_v8::hybrid_transaction_v2::Transaction::decode(raw)
                    .and_then(|tx| tx.id())
                    .ok()
                    == Some(id)
            })
            .ok_or("Payment is not pending at the verified head")?;
        let (offer, frame) = peer
            .with_current_transport(|link| link.enqueue(ObjectKind::SignedTransaction, &raw, 0))
            .map_err(|e| context("Wallet transport queue", e))?;
        peer.send_typed(&frame, limit.min(Instant::now() + TURN_LIMIT))?;
        Ok(offer)
    }

    /// One received, authenticated history event (the receive callback of `peer_turn_typed`). The four
    /// link operations it performs keep the transport's own error, so an actual `Error::Expired` stays
    /// `SessionExpired` (G3); a semantic refusal or canonical-replay failure is `Other` with the same
    /// text as before. Behaviour is otherwise unchanged.
    fn history_event<L: HistoryLink>(
        &mut self,
        link: &mut L,
        windows: &mut BTreeMap<Hash, (u16, u16)>,
        event: Event,
    ) -> PeerResult<(Progress, Option<Vec<u8>>)> {
        match event {
            Event::Offered(offer) => {
                if !matches!(
                    offer.kind,
                    ObjectKind::CertifiedBlock | ObjectKind::RecoveryEvidence | ObjectKind::StatusReport
                ) {
                    return Err("Unexpected wallet history offer".into());
                }
                if !windows.contains_key(&offer.id)
                    && windows.len() >= mutiny_transport_v2::objects::MAX_OBJECTS
                {
                    return Err("Wallet history capacity".into());
                }
                match link
                    .next_missing_request(&offer.id, 0, false)
                    .map_err(|e| PeerFailure::transport("Wallet history request", e))?
                {
                    Some(request) => {
                        windows.insert(offer.id, (request.start, request.count));
                        Ok((Progress::Transport, Some(request.frame)))
                    }
                    None => {
                        let (offer, bytes) = link
                            .completed(&offer.id)
                            .map_err(|e| PeerFailure::transport("Wallet completed history", e))?;
                        windows.remove(&offer.id);
                        Ok((self.completed_history(offer, &bytes)?, None))
                    }
                }
            }
            Event::Completed { offer, bytes } => {
                windows.remove(&offer.id);
                let progress = self.completed_history(offer, &bytes)?;
                Ok((progress, None))
            }
            Event::FragmentReceived => {
                let mut reply = None;
                for (id, (start, count)) in windows.iter_mut() {
                    let bitmap = link
                        .missing_window(id, *start, *count)
                        .map_err(|e| PeerFailure::transport("Wallet history progress", e))?;
                    if bitmap.bits.iter().all(|missing| !missing)
                        && let Some(next) = link
                            .next_missing_request(id, 0, false)
                            .map_err(|e| PeerFailure::transport("Wallet next history window", e))?
                    {
                        *start = next.start;
                        *count = next.count;
                        reply = Some(next.frame);
                        break;
                    }
                }
                Ok((Progress::Transport, reply))
            }
            Event::Requested | Event::ReceiptRecorded => Ok((Progress::Transport, None)),
        }
    }

    fn completed_history(&mut self, offer: Offer, bytes: &[u8]) -> Result<Progress> {
        match offer.kind {
            ObjectKind::CertifiedBlock => Ok(Progress::History {
                object: offer.id,
                inserted: self.accept_history(bytes)?,
            }),
            ObjectKind::RecoveryEvidence => Ok(Progress::Recovery {
                object: offer.id,
                inserted: self.accept_recovery_history(bytes)?,
            }),
            ObjectKind::StatusReport => Ok(Progress::StatusHints {object:offer.id,
                count:mutiny_consensus_v8::submission_v1::StatusReport::decode(bytes).map_err(|e|format!("Peer status hint refused: {e:?}"))?.entries.len()}),
            _ => Err("Unexpected object on the wallet history channel".into()),
        }
    }

    /// Retry durable reassembly after interruption/reconnect. Pin validation,
    /// reassembly hash, and canonical execution all run again.
    pub fn retry_peer_history(&mut self, host: &mut WalletPeer, object: Hash) -> Result<Progress> {
        self.retry_peer_history_typed(host, object).map_err(String::from)
    }
    /// `retry_peer_history` keeping the transport's expiry discriminant (G3); a semantic refusal is `Other`.
    pub fn retry_peer_history_typed(&mut self, host: &mut WalletPeer, object: Hash) -> PeerResult<Progress> {
        let peer = &mut host.link;
        let result = guarded(peer.with_current(|link| -> PeerResult<Progress> {
            let (offer, bytes) = link
                .completed(&object)
                .map_err(|e| PeerFailure::transport("Wallet completed object", e))?;
            Ok(self.completed_history(offer, &bytes)?)
        }));
        if result.is_err() {
            peer.close();
        }
        result
    }

    /// Reclaim a public transport copy only after replay succeeds again. A crash
    /// before this call leaves a retryable complete object; canonical history is
    /// never pruned here. Call after consuming the History/Recovery notification.
    pub fn reclaim_peer_history(
        &mut self,
        host: &mut WalletPeer,
        object: Hash,
    ) -> Result<Progress> {
        self.reclaim_peer_history_typed(host, object).map_err(String::from)
    }
    /// `reclaim_peer_history` keeping the transport's expiry discriminant (G3).
    pub fn reclaim_peer_history_typed(&mut self, host: &mut WalletPeer, object: Hash) -> PeerResult<Progress> {
        let result = guarded(host.link.with_current(|link| -> PeerResult<Progress> {
            let (offer, bytes) = link
                .completed(&object)
                .map_err(|e| PeerFailure::transport("Wallet completed object", e))?;
            let progress = self.completed_history(offer, &bytes)?;
            link.discard(&object)
                .map_err(|e| PeerFailure::transport("Wallet transport reclaim", e))?;
            Ok(progress)
        }));
        if result.is_err() {
            host.link.close();
        }
        result
    }

    /// Reclaim an outgoing transport copy after local canonical confirmation.
    /// Receipt bits alone never authorize this transition.
    pub fn reclaim_confirmed_payment(&mut self, host: &mut WalletPeer, object: Hash) -> Result<()> {
        self.reclaim_confirmed_payment_typed(host, object).map_err(String::from)
    }
    /// `reclaim_confirmed_payment` keeping the transport's expiry discriminant (G3).
    pub fn reclaim_confirmed_payment_typed(&mut self, host: &mut WalletPeer, object: Hash) -> PeerResult<()> {
        guarded(host.link.with_current(|link| -> PeerResult<()> {
            let (offer, bytes) = link
                .completed(&object)
                .map_err(|e| PeerFailure::transport("Wallet completed payment", e))?;
            if offer.kind != ObjectKind::SignedTransaction {
                return Err("Not a payment object".into());
            }
            let tx = mutiny_consensus_v8::hybrid_transaction_v2::Transaction::decode(&bytes)
                .map_err(|e| format!("Wallet completed transaction: {e:?}"))?;
            let id = tx
                .id()
                .map_err(|e| format!("Wallet transaction identity: {e:?}"))?;
            if !matches!(self.delivery(id)?, Delivery::ConfirmedAt(_)) {
                return Err("Payment has no local canonical confirmation".into());
            }
            link.discard(&object)
                .map_err(|e| PeerFailure::transport("Wallet payment reclaim", e))
        }))
    }

    /// Bounded send/idle phase, then a separate bounded complete-frame receive.
    /// The caller limit bounds the first phase; reception gets at most100 ms
    /// after readiness. Partial frame reads never renew that deadline. Canonical
    /// execution is not interrupted midway when the I/O deadline expires.
    /// Inbound objects do not extend wallet unlock time or approve a payment.
    pub fn peer_turn(&mut self, host: &mut WalletPeer, limit: Instant) -> Result<Option<Progress>> {
        self.peer_turn_typed(host, limit).map_err(String::from)
    }
    /// `peer_turn` with the transport's own session-expiry discriminant kept (G3): the turn fails with
    /// `PeerFailure::SessionExpired` only for the transport's actual `Error::Expired`; every other failure
    /// is `Other` with the same diagnostic as before. The link is closed on any failure, as before; an
    /// expired session is never reconnected or reused here.
    pub fn peer_turn_typed(&mut self, host: &mut WalletPeer, limit: Instant) -> PeerResult<Option<Progress>> {
        let peer = &mut host.link;
        let windows = &mut host.windows;
        let pending_control = &mut host.pending_control;
        self.tick();
        let limit = limit.min(Instant::now() + TURN_LIMIT);
        let result = (|| -> PeerResult<Option<Progress>> {
            let (next, label) = match pending_control.take() {
                Some(frame) => (Some(frame), "queued history reply"),
                None => (
                    peer.with_current_transport(|link| link.send_one())
                        .map_err(|e| context("Wallet fragment", e))?,
                    "outgoing fragment",
                ),
            };
            if let Some(frame) = next {
                peer.send_typed(&frame, limit)
                    .map_err(|e| context(&format!("Wallet {label}"), e))?;
            }
            if !peer.wait_for_frame_typed(limit)? {
                return Ok(None);
            }
            #[cfg(test)]
            if !host.after_readiness_delay.is_zero() {
                std::thread::sleep(std::mem::take(&mut host.after_readiness_delay));
            }
            // Idle waiting must not consume the complete-frame receive budget.
            // One absolute deadline still bounds prefix and body together.
            let received = peer.receive_typed(Instant::now() + TURN_LIMIT)?;
            let (progress, reply) = peer
                .dispatch_received_typed(received, |link, event| self.history_event(link, windows, event))??;
            // Durable dispatch/validation may finish after the receive turn's
            // I/O budget. Keep its exact reply for a new bounded service turn;
            // never send using an expired deadline or extend the old one.
            #[cfg(test)]
            if !host.after_dispatch_delay.is_zero() {
                std::thread::sleep(std::mem::take(&mut host.after_dispatch_delay));
            }
            debug_assert!(pending_control.is_none());
            *pending_control = reply;
            Ok(Some(progress))
        })();
        if result.is_err() {
            peer.close();
        }
        result
    }

    /// UI reads canonical confirmation every time; it never caches a peer claim.
    pub fn show_payment_status(&mut self, ui: &mut egui::Ui, id: Hash) -> Result<()> {
        ui.label(format!("Transaction {}", hex::encode(id)));
        match self.delivery(id)? {
            Delivery::ConfirmedAt(height) => {
                ui.label(format!("Confirmed in verified block {height}"));
            }
            Delivery::Unconfirmed(status) => {
                use mutiny_consensus_v8::mempool_v2::Status;
                ui.label(match status {
                    Some(Status::Pending) => "Pending confirmation",
                    Some(Status::Expired) => "Expired before confirmation",
                    Some(Status::Superseded) => "Replaced before confirmation",
                    Some(Status::InputSpent) => "Input spent by another transaction",
                    Some(Status::Rejected) => "Rejected by local validation",
                    Some(Status::Confirmed) => return Err("Unverified confirmation status".into()),
                    None => "Not found in verified history or local queue",
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "wallet_host_v2_tests.rs"]
mod tests;
