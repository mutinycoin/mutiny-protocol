//! Host transport-to-runtime candidate. AEAD, replay and complete object hash
//! checks precede semantic dispatch. A transport receipt grants no authority.
use crate::hybrid_runtime_v2::{HybridRuntime, Installation, RuntimeError};
use mutiny_consensus_v8::{Hash, mempool_v2::Status};
use mutiny_transport_v2::{
    object_link::{Event, ObjectLink},
    objects::{ObjectKind, Offer},
};
#[derive(Debug)]
pub enum DispatchError {
    Admission(String),
    Transport(mutiny_transport_v2::Error),
    Runtime(RuntimeError),
    /// A bounded authenticated history control failed canonical decoding.
    History(crate::history_protocol_v1::HistoryError),
    ActorDeadline,
    ActorPoisoned,
}
/// One bounded peer-service turn. Idle waits and complete-frame reads occur
/// outside the canonical actor. Once an event exists, acquire the actor with a
/// bounded wait and only then recheck the originating connection's current pin.
/// The deadline bounds waits, not a canonical transition already in progress;
/// such a transition must run atomically to completion under its own bounds.
pub fn poll_peer(
    runtime: &std::sync::Mutex<HybridRuntime>,
    peer: &mut crate::hybrid_peer_admission_v2::PeerLink,
    limit: std::time::Instant,
) -> Result<Option<DispatchEvent>, DispatchError> {
    use std::time::{Duration, Instant};
    let limit = limit.min(Instant::now() + Duration::from_secs(5));
    if !peer
        .wait_for_frame_typed(limit)
        .map_err(DispatchError::from)?
    {
        return Ok(None);
    }
    let received = peer.receive_typed(limit).map_err(DispatchError::from)?;
    with_actor(runtime, peer, limit, |actor, peer| {
        dispatch_peer(actor, peer, received)
    })
    .map(Some)
}
pub(crate) fn with_actor<T>(
    runtime: &std::sync::Mutex<HybridRuntime>,
    peer: &mut crate::hybrid_peer_admission_v2::PeerLink,
    limit: std::time::Instant,
    action: impl FnOnce(
        &mut HybridRuntime,
        &mut crate::hybrid_peer_admission_v2::PeerLink,
    ) -> Result<T, DispatchError>,
) -> Result<T, DispatchError> {
    use std::{
        sync::TryLockError,
        time::{Duration, Instant},
    };
    let limit = limit.min(Instant::now() + Duration::from_secs(5));
    loop {
        let Some(remaining) = limit
            .checked_duration_since(Instant::now())
            .filter(|v| !v.is_zero())
        else {
            peer.close();
            return Err(DispatchError::ActorDeadline);
        };
        match runtime.try_lock() {
            Ok(mut actor) => {
                if Instant::now() >= limit {
                    peer.close();
                    return Err(DispatchError::ActorDeadline);
                }
                return action(&mut actor, peer);
            }
            Err(TryLockError::Poisoned(_)) => {
                peer.close();
                return Err(DispatchError::ActorPoisoned);
            }
            Err(TryLockError::WouldBlock) => {
                std::thread::sleep(remaining.min(Duration::from_millis(1)))
            }
        }
    }
}
/// Locally requested durable retry after reconnection or a lost notification.
/// Completion in the transport queue grants no authority: bytes are rehashed
/// and canonically validated again under the current peer pin and actor.
pub fn retry_peer_completed(
    runtime: &std::sync::Mutex<HybridRuntime>,
    peer: &mut crate::hybrid_peer_admission_v2::PeerLink,
    object: Hash,
    limit: std::time::Instant,
) -> Result<DispatchEvent, DispatchError> {
    let result = with_actor(runtime, peer, limit, |actor, peer| {
        peer.with_current(|link| retry_completed(actor, link, &object))
            .map_err(DispatchError::Admission)?
    });
    if result.is_err() {
        peer.close();
    }
    result
}
/// Socket receive happens first, outside the canonical actor. After acquiring
/// that actor, consume the opaque event under its originating peer's current-pin
/// guard. This prevents event swapping and revocation during semantic dispatch.
pub fn dispatch_peer(
    runtime: &mut HybridRuntime,
    peer: &mut crate::hybrid_peer_admission_v2::PeerLink,
    received: crate::hybrid_peer_admission_v2::Received,
) -> Result<DispatchEvent, DispatchError> {
    peer.dispatch_received_typed(received, |link, event| {
        check_network(runtime, link)?;
        link.check_incoming_event(&event).map_err(DispatchError::Transport)?;
        dispatch_admitted(runtime, link, event)
    })
    .map_err(DispatchError::from)?
}
pub enum DispatchEvent {
    /// An admitted B1 public history candidate. It has NOT been installed.
    /// Only the active ordered plan owner may invoke canonical verification.
    HistoryCandidate { offer: Offer, bytes: Vec<u8> },
    /// Authenticated, hash-checked B1 request for the bounded host exporter.
    /// This is a fetch request, never a canonical state transition or authority.
    HistoryRequest {
        offer: Offer,
        bytes: Vec<u8>,
        request: crate::history_protocol_v1::HistoryRequest,
    },
    /// Authenticated B1 fetch plan. The receiver must correlate the current
    /// request/session and verify each planned candidate independently in order.
    HistoryPage {
        offer: Offer,
        bytes: Vec<u8>,
        page: crate::history_protocol_v1::HistoryPage,
    },
    /// Includes opaque completed vote/settlement objects. Their dedicated
    /// semantic handlers remain mandatory; this path does not count votes.
    Transport(Event),
    TransactionAccepted {
        offer: Offer,
        id: Hash,
        status: Status,
    },
    BlockInstalled {
        offer: Offer,
        result: Installation,
    },
    RecoveryAccepted {
        offer: Offer,
        result: mutiny_consensus_v8::canonical_store_v2::RecoveryAcceptance,
    },
    OperationAccepted {
        offer: Offer,
        id: Hash,
        status: mutiny_consensus_v8::submission_v1::Status,
    },
    StatusQueryAnswered {
        offer: Offer,
        reports: Vec<Vec<u8>>,
    },
    /// Peer hints only. This event makes no local canonical/pool mutation.
    StatusHints {
        offer: Offer,
        report: mutiny_consensus_v8::submission_v1::StatusReport,
    },
}
pub fn receive(
    runtime: &mut HybridRuntime,
    link: &mut ObjectLink,
    frame: &[u8],
) -> Result<DispatchEvent, DispatchError> {
    check_network(runtime, link)?;
    let event = link.receive(frame).map_err(DispatchError::Transport)?;
    dispatch_admitted(runtime, link, event)
}
/// Local retry after durable reassembly, interrupted semantic dispatch, or a
/// transient canonical/cache failure. Bytes are reassembled/hash-checked and
/// fully validated against current canonical state; no delivery status is trusted.
pub fn retry_completed(
    runtime: &mut HybridRuntime,
    link: &ObjectLink,
    id: &Hash,
) -> Result<DispatchEvent, DispatchError> {
    check_network(runtime, link)?;
    let (offer, bytes) = link.completed_incoming(id).map_err(DispatchError::Transport)?;
    dispatch_admitted(runtime, link, Event::Completed { offer, bytes })
}
/// The locally provisioned history receiver never uses the generic canonical
/// auto-apply path. The same rule covers fresh receive and durable retry. The
/// caller already authenticated/current-pin checked this event before entry.
fn dispatch_admitted(
    runtime: &mut HybridRuntime,
    link: &ObjectLink,
    event: Event,
) -> Result<DispatchEvent, DispatchError> {
    if link.authorization() == mutiny_transport_v2::object_link::LocalAuthorization::NodeToWalletHistoryClient {
        if let Event::Completed { offer, bytes } = event {
            if matches!(offer.kind, ObjectKind::CertifiedBlock | ObjectKind::RecoveryEvidence) {
                return Ok(DispatchEvent::HistoryCandidate { offer, bytes });
            }
            return dispatch(runtime, Event::Completed { offer, bytes });
        }
    }
    dispatch(runtime, event)
}
fn check_network(runtime: &HybridRuntime, link: &ObjectLink) -> Result<(), DispatchError> {
    let (genesis, fingerprint) = runtime.network_context();
    if !link.matches_network(genesis, fingerprint) {
        return Err(DispatchError::Admission(
            "Canonical transport network mismatch".into(),
        ));
    }
    Ok(())
}
/// Event from an authenticated ObjectLink, including a TCP carrier's verified
/// receive_object. Invoke only after socket waits, under the canonical actor.
pub fn dispatch(runtime: &mut HybridRuntime, event: Event) -> Result<DispatchEvent, DispatchError> {
    match event {
        Event::Completed { offer, bytes } if offer.kind == ObjectKind::HistoryRequestV1 => {
            let request = crate::history_protocol_v1::HistoryRequest::decode(&bytes)
                .map_err(DispatchError::History)?;
            Ok(DispatchEvent::HistoryRequest { offer, bytes, request })
        }
        Event::Completed { offer, bytes } if offer.kind == ObjectKind::HistoryPageV1 => {
            let page = crate::history_protocol_v1::HistoryPage::decode(&bytes)
                .map_err(DispatchError::History)?;
            Ok(DispatchEvent::HistoryPage { offer, bytes, page })
        }
        Event::Completed { offer, bytes } if offer.kind == ObjectKind::SignedOperation => {
            let (id, status) = runtime
                .admit_submission(1, &bytes)
                .map_err(DispatchError::Runtime)?;
            Ok(DispatchEvent::OperationAccepted { offer, id, status })
        }
        Event::Completed { offer, bytes } if offer.kind == ObjectKind::StatusQuery => {
            let reports = runtime
                .status_reports(&bytes)
                .map_err(DispatchError::Runtime)?;
            Ok(DispatchEvent::StatusQueryAnswered { offer, reports })
        }
        Event::Completed { offer, bytes } if offer.kind == ObjectKind::StatusReport => {
            let report = mutiny_consensus_v8::submission_v1::StatusReport::decode(&bytes)
                .map_err(|e| DispatchError::Admission(format!("Status report: {e:?}")))?;
            Ok(DispatchEvent::StatusHints { offer, report })
        }
        Event::Completed { offer, bytes } if offer.kind == ObjectKind::SignedTransaction => {
            let (id, status) = runtime.admit(&bytes).map_err(DispatchError::Runtime)?;
            Ok(DispatchEvent::TransactionAccepted { offer, id, status })
        }
        Event::Completed { offer, bytes } if offer.kind == ObjectKind::CertifiedBlock => {
            let result = runtime.install(&bytes).map_err(DispatchError::Runtime)?;
            Ok(DispatchEvent::BlockInstalled { offer, result })
        }
        Event::Completed { offer, bytes } if offer.kind == ObjectKind::RecoveryEvidence => {
            let result = runtime
                .accept_recovery(&bytes)
                .map_err(DispatchError::Runtime)?;
            Ok(DispatchEvent::RecoveryAccepted { offer, result })
        }
        event => Ok(DispatchEvent::Transport(event)),
    }
}
#[cfg(test)]
#[path = "hybrid_dispatch_v2_tests.rs"]
mod tests;
