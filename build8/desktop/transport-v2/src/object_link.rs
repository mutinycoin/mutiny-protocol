//! Authenticated host dispatch. No socket, radio, wallet or consensus verifier.
//! Callers pace each returned frame; no remote control creates a send loop.
use crate::{
    Error, Result, Session,
    objects::{Bitmap, GeneralCapacity, HistoryCapacity, ObjectKind, ObjectQueue, Offer, MAX_HISTORY_CANDIDATES},
};
use std::{collections::{BTreeMap, BTreeSet},sync::{Arc,atomic::{AtomicBool,Ordering}}};
pub enum Event {
    Offered(Offer),
    Requested,
    FragmentReceived,
    /// Exact hash-checked opaque bytes. Endpoint semantic verification is mandatory.
    Completed {
        offer: Offer,
        bytes: Vec<u8>,
    },
    ReceiptRecorded,
}
/// One bounded locally selected missing-fragment window. The caller paces this
/// control frame and waits for progress; receiving an offer never starts a loop.
pub struct RequestWindow {
    pub start: u16,
    pub count: u16,
    pub frame: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Context, Endpoint, InitiatorPending, ResponderPending};
    use mutiny_crypto_v2::{HybridKey, Role};
    fn pair(a: &HybridKey, b: &HybridKey) -> (Session, Session) {
        let ctx = Context::pinned(
            [1; 32],
            [2; 32],
            Endpoint::pinned(a.public().clone(), 1).unwrap(),
            Endpoint::pinned(b.public().clone(), 1).unwrap(),
        )
        .unwrap();
        let (i, hello) = InitiatorPending::start(ctx.clone(), a).unwrap();
        let (r, response) = ResponderPending::accept(ctx, b, &hello).unwrap();
        let (i, finish) = i.accept(a, &response).unwrap();
        let (r, tag) = r.finish(&finish).unwrap();
        (i.finish(&tag).unwrap(), r)
    }
    #[test]
    fn bounded_windows_round_robin_and_persistent_retry_exhaustion() {
        let a = HybridKey::generate(Role::Transport).unwrap();
        let b = HybridKey::generate(Role::Transport).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "build8-link-bounds-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let (i, r) = pair(&a, &b);
        let qi = ObjectQueue::open(&directory.join("send.sqlite"), i.peer_id()).unwrap();
        let qr = ObjectQueue::open(&directory.join("recv.sqlite"), r.peer_id()).unwrap();
        let mut send = ObjectLink::new(i, qi).unwrap();
        let mut recv = ObjectLink::new(r, qr).unwrap();
        let mut offers = Vec::new();
        for n in 1..=8 {
            let (offer, have) = send
                .enqueue(ObjectKind::ContinuityVote, &[n; 281], 0)
                .unwrap();
            recv.receive(&have).unwrap();
            let request = recv.request_missing(&offer.id, 0, 3, 0, false).unwrap();
            send.receive(&request).unwrap();
            offers.push(offer);
        }
        assert_eq!(send.wanted.len(), 8);
        assert!(matches!(
            send.enqueue(ObjectKind::ContinuityVote, &[9; 281], 0),
            Err(Error::Limit)
        ));
        let mut round = std::collections::BTreeSet::new();
        for _ in 0..8 {
            let frame = send.send_one().unwrap().unwrap();
            let id: [u8; 32] = frame[60..92].try_into().unwrap();
            recv.receive(&frame).unwrap();
            assert!(round.insert(id));
        }
        assert_eq!(round.len(), 8);
        // Repeated authenticated NACKs cannot refund the persistent retry budget.
        let offer = &offers[0];
        send.wanted.clear();
        let (mut meta, _) = offer.have(0).unwrap();
        meta.kind = 5;
        let payload = Bitmap {
            start: 0,
            bits: vec![true],
        }
        .encode(3)
        .unwrap();
        for _ in 1..8 {
            let request = recv.session.seal(&meta, &payload).unwrap();
            send.receive(&request).unwrap();
            assert!(send.send_one().unwrap().is_some());
        }
        let request = recv.session.seal(&meta, &payload).unwrap();
        send.receive(&request).unwrap();
        assert!(send.send_one().unwrap().is_none());
        let qi = send.disconnect();
        let qr = recv.disconnect();
        let (i, r) = pair(&a, &b);
        let mut send = ObjectLink::new(i, qi).unwrap();
        let mut recv = ObjectLink::new(r, qr).unwrap();
        let request = recv.session.seal(&meta, &payload).unwrap();
        send.receive(&request).unwrap();
        assert!(send.send_one().unwrap().is_none());
        drop(send);
        drop(recv);
        for name in ["send.sqlite", "recv.sqlite"] {
            std::fs::remove_file(directory.join(name)).unwrap();
        }
        std::fs::remove_dir(directory).unwrap();
    }
    #[test]
    fn authenticated_dispatch_loss_retry_receipts_reconnect_and_peer_binding() {
        let a = HybridKey::generate(Role::Transport).unwrap();
        let b = HybridKey::generate(Role::Transport).unwrap();
        let directory = std::env::temp_dir().join(format!(
            "build8-object-link-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&directory).unwrap();
        let (i, _) = pair(&a, &b);
        let wrong = ObjectQueue::open(&directory.join("wrong.sqlite"), [9; 32]).unwrap();
        assert!(matches!(ObjectLink::new(i, wrong), Err(Error::Context)));
        let (i, r) = pair(&a, &b);
        let send_peer = i.peer_id();
        let recv_peer = r.peer_id();
        assert_ne!(send_peer, recv_peer);
        let send = ObjectQueue::open(&directory.join("send.sqlite"), send_peer).unwrap();
        let recv = ObjectQueue::open(&directory.join("recv.sqlite"), recv_peer).unwrap();
        let mut send = ObjectLink::new(i, send).unwrap();
        let mut recv = ObjectLink::new(r, recv).unwrap();
        let raw = vec![37; 7001];
        let (offer, have) = send
            .enqueue(ObjectKind::SignedTransaction, &raw, 1)
            .unwrap();
        let mut damaged = have.clone();
        *damaged.last_mut().unwrap() ^= 1;
        assert!(matches!(recv.receive(&damaged), Err(Error::Crypto)));
        assert!(recv.queue.describe(&offer.id).is_err());
        assert!(matches!(recv.receive(&have), Ok(Event::Offered(_))));
        assert!(matches!(recv.receive(&have), Err(Error::Replay)));
        for _ in 0..16 {
            let progress = recv.missing_window(&offer.id, 0, 51).unwrap();
            assert_eq!(progress.start, 0);
            assert_eq!(progress.bits, vec![true; 51]);
        }
        assert!(recv.missing_window(&offer.id, 0, 0).is_err());
        assert!(recv.missing_window(&offer.id, 50, 2).is_err());
        assert!(recv.missing_window(&[0; 32], 0, 1).is_err());
        let wanted = recv.request_missing(&offer.id, 0, 51, 1, false).unwrap();
        assert!(matches!(send.receive(&wanted), Ok(Event::Requested)));
        let mut frames = 0;
        let mut skipped = None;
        while let Some(frame) = send.send_one().unwrap() {
            frames += 1;
            if frames == 3 {
                skipped = Some(frame);
                continue;
            }
            assert!(matches!(recv.receive(&frame), Ok(Event::FragmentReceived)));
        }
        assert_eq!(frames, 51);
        assert!(recv.completed(&offer.id).is_err());
        let missing = recv.missing_window(&offer.id, 0, 51).unwrap();
        assert_eq!(missing.bits.iter().filter(|v| **v).count(), 1);
        assert!(missing.bits[2]);
        let receipt = recv.receipt(&offer.id, 0, 51, 1).unwrap();
        assert!(matches!(send.receive(&receipt), Ok(Event::ReceiptRecorded)));
        let ack = send.acknowledged(&offer.id, 0, 51).unwrap();
        assert_eq!(ack.bits.iter().filter(|x| **x).count(), 50);
        assert!(!ack.bits[2]);
        let request = recv.request_missing(&offer.id, 0, 51, 1, true).unwrap();
        send.receive(&request).unwrap();
        let frame = send.send_one().unwrap().unwrap();
        assert_ne!(frame, skipped.clone().unwrap());
        match recv.receive(&frame).unwrap() {
            Event::Completed { offer: got, bytes } => {
                assert_eq!(got, offer);
                assert_eq!(bytes, raw)
            }
            _ => panic!("missing completion"),
        }
        assert!(send.send_one().unwrap().is_none());
        // An old, previously unseen sequence can arrive harmlessly within the
        // replay window, but cannot redeliver an already complete object.
        assert!(matches!(
            recv.receive(&skipped.unwrap()),
            Ok(Event::FragmentReceived)
        ));
        let receipt = recv.receipt(&offer.id, 0, 51, 1).unwrap();
        send.receive(&receipt).unwrap();
        assert!(
            send.acknowledged(&offer.id, 0, 51)
                .unwrap()
                .bits
                .iter()
                .all(|b| *b)
        );
        let mut meta = offer.have(0).unwrap().0;
        meta.kind = 2;
        meta.count += 1;
        let malformed = recv
            .session
            .seal(
                &meta,
                &Bitmap {
                    start: 0,
                    bits: vec![true],
                }
                .encode(meta.count)
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(send.receive(&malformed), Err(Error::Context)));
        assert!(send.wanted.is_empty());
        let send_queue = send.disconnect();
        let recv_queue = recv.disconnect();
        let (i, r) = pair(&a, &b);
        let mut send = ObjectLink::new(i, send_queue).unwrap();
        let mut recv = ObjectLink::new(r, recv_queue).unwrap();
        assert!(recv.receive(&have).is_err());
        assert!(send.send_one().unwrap().is_none());
        assert_eq!(recv.completed(&offer.id).unwrap().1, raw);
        let repeat = send.advertise(&offer.id, 0).unwrap();
        assert!(matches!(recv.receive(&repeat), Ok(Event::Offered(_))));
        drop(send);
        drop(recv);
        let restored = ObjectQueue::open(&directory.join("send.sqlite"), send_peer).unwrap();
        assert!(
            restored
                .acknowledged(&offer.id, 0, 51)
                .unwrap()
                .bits
                .iter()
                .all(|b| *b)
        );
        drop(restored);
        for name in ["send.sqlite", "recv.sqlite", "wrong.sqlite"] {
            std::fs::remove_file(directory.join(name)).unwrap();
        }
        std::fs::remove_dir(directory).unwrap();
    }
}
#[cfg(test)]
mod window_tests {
    use super::*;
    use crate::{Context, Endpoint, InitiatorPending, ResponderPending};
    use mutiny_crypto_v2::{HybridKey, Role};
    fn pair(a: &HybridKey, b: &HybridKey) -> (Session, Session) {
        let context = Context::pinned(
            [1; 32],
            [2; 32],
            Endpoint::pinned(a.public().clone(), 1).unwrap(),
            Endpoint::pinned(b.public().clone(), 1).unwrap(),
        )
        .unwrap();
        let (i, hello) = InitiatorPending::start(context.clone(), a).unwrap();
        let (r, response) = ResponderPending::accept(context, b, &hello).unwrap();
        let (i, finish) = i.accept(a, &response).unwrap();
        let (r, tag) = r.finish(&finish).unwrap();
        (i.finish(&tag).unwrap(), r)
    }
    #[test]
    fn durable_missing_windows_do_not_advance_past_holes_and_resume_after_reconnect() {
        let a = HybridKey::generate(Role::Transport).unwrap();
        let b = HybridKey::generate(Role::Transport).unwrap();
        let mut random = [0; 16];
        mutiny_crypto_v2::fill_os_random(&mut random).unwrap();
        let base =
            std::env::temp_dir().join(format!("build8-missing-window-{}", hex::encode(random)));
        std::fs::create_dir(&base).unwrap();
        let (i, r) = pair(&a, &b);
        let qi = ObjectQueue::open(&base.join("send.sqlite"), i.peer_id()).unwrap();
        let qr = ObjectQueue::open(&base.join("recv.sqlite"), r.peer_id()).unwrap();
        let mut send = ObjectLink::new(i, qi).unwrap();
        let mut recv = ObjectLink::new(r, qr).unwrap();
        let raw = vec![79; crate::MAX_PAYLOAD * crate::objects::MAX_BITMAP_BITS as usize + 1];
        let (offer, have) = send.enqueue(ObjectKind::CertifiedBlock, &raw, 0).unwrap();
        recv.receive(&have).unwrap();
        let window = recv
            .next_missing_request(&offer.id, 0, false)
            .unwrap()
            .unwrap();
        assert_eq!((window.start, window.count), (0, 1080));
        send.receive(&window.frame).unwrap();
        let mut frames = 0;
        while let Some(frame) = send.send_one().unwrap() {
            frames += 1;
            if frames != 1 {
                assert!(matches!(recv.receive(&frame), Ok(Event::FragmentReceived)));
            }
        }
        assert_eq!(frames, 1080);
        let receipt = recv.receipt(&offer.id, 0, 1080, 0).unwrap();
        send.receive(&receipt).unwrap();
        assert_eq!(
            send.acknowledged(&offer.id, 0, 1080)
                .unwrap()
                .bits
                .iter()
                .filter(|v| **v)
                .count(),
            1079
        );
        // Persisted holes, not volatile packet counters, choose the next window.
        let qi = send.disconnect();
        let qr = recv.disconnect();
        let (i, r) = pair(&a, &b);
        let mut send = ObjectLink::new(i, qi).unwrap();
        let mut recv = ObjectLink::new(r, qr).unwrap();
        let retry = recv
            .next_missing_request(&offer.id, 0, true)
            .unwrap()
            .unwrap();
        assert_eq!((retry.start, retry.count), (0, 1080));
        send.receive(&retry.frame).unwrap();
        let frame = send.send_one().unwrap().unwrap();
        assert!(matches!(recv.receive(&frame), Ok(Event::FragmentReceived)));
        assert!(send.send_one().unwrap().is_none());
        let next = recv
            .next_missing_request(&offer.id, 0, false)
            .unwrap()
            .unwrap();
        assert_eq!((next.start, next.count), (1080, 1));
        send.receive(&next.frame).unwrap();
        let Event::Completed { bytes, .. } =
            recv.receive(&send.send_one().unwrap().unwrap()).unwrap()
        else {
            panic!("missing complete object")
        };
        assert_eq!(bytes, raw);
        assert!(
            recv.next_missing_request(&offer.id, 0, false)
                .unwrap()
                .is_none()
        );
        assert!(recv.next_missing_request(&[0; 32], 0, false).is_err());
        drop(send);
        drop(recv);
        for name in [
            "send.sqlite",
            "recv.sqlite",
            "send.sqlite-wal",
            "recv.sqlite-wal",
            "send.sqlite-shm",
            "recv.sqlite-shm",
        ] {
            let p = base.join(name);
            if p.exists() {
                std::fs::remove_file(p).unwrap();
            }
        }
        std::fs::remove_dir(base).unwrap();
    }
}
/// Trusted local service restriction, never a wire claim or consensus role.
/// The two wallet directions deliberately have disjoint object-kind sets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LocalAuthorization {
    Unrestricted,
    /// Local node serves an independently pinned wallet client.
    WalletClientToNode,
    /// Local wallet connects to its independently pinned node.
    NodeToWalletClient,
    WalletHistoryClientToNode,
    NodeToWalletHistoryClient,
}
impl LocalAuthorization {
    fn incoming(self, kind: ObjectKind) -> bool {
        match self {
            Self::Unrestricted => !matches!(kind, ObjectKind::HistoryRequestV1 | ObjectKind::HistoryPageV1),
            Self::WalletClientToNode => matches!(kind, ObjectKind::SignedTransaction | ObjectKind::SignedOperation | ObjectKind::StatusQuery),
            Self::NodeToWalletClient => matches!(kind, ObjectKind::CertifiedBlock | ObjectKind::RecoveryEvidence | ObjectKind::StatusReport),
            Self::WalletHistoryClientToNode => Self::WalletClientToNode.incoming(kind) || kind == ObjectKind::HistoryRequestV1,
            Self::NodeToWalletHistoryClient => Self::NodeToWalletClient.incoming(kind) || kind == ObjectKind::HistoryPageV1,
        }
    }
    fn outgoing(self, kind: ObjectKind) -> bool {
        match self {
            Self::Unrestricted => !matches!(kind, ObjectKind::HistoryRequestV1 | ObjectKind::HistoryPageV1),
            Self::WalletClientToNode => Self::NodeToWalletClient.incoming(kind),
            Self::NodeToWalletClient => Self::WalletClientToNode.incoming(kind),
            Self::WalletHistoryClientToNode => Self::NodeToWalletHistoryClient.incoming(kind),
            Self::NodeToWalletHistoryClient => Self::WalletHistoryClientToNode.incoming(kind),
        }
    }
}
/// Read-only evidence that the exact locally accepted transport plan remains
/// owned. No public constructor exists. Combine with current-session admission
/// evidence; this token alone grants no canonical installation authority.
#[derive(Clone)]
pub struct HistoryPlanLease {
    alive:Arc<AtomicBool>,
}
impl HistoryPlanLease {
    pub fn check_current(&self)->Result<()> {
        if self.alive.load(Ordering::Acquire) {Ok(())} else {Err(Error::Context)}
    }
}
struct HistoryPlan {
    request: [u8; 32],
    page: [u8; 32],
    members: Vec<Offer>,
    owned: BTreeSet<[u8; 32]>,
    page_advertised: bool,
    alive:Arc<AtomicBool>,
}
impl Drop for HistoryPlan {
    fn drop(&mut self) {self.alive.store(false,Ordering::Release);}
}
pub struct ObjectLink {
    session: Session,
    queue: ObjectQueue,
    wanted: BTreeMap<[u8; 32], (Bitmap, u8)>,
    last_served: Option<[u8; 32]>,
    authorization: LocalAuthorization,
    // These bounded grants belong ONLY to this exact memory-only Session.
    // Durable public queue bytes never carry authorization into a reconnect.
    incoming: BTreeSet<[u8; 32]>,
    outgoing: BTreeSet<[u8; 32]>,
    history_plan: Option<HistoryPlan>,
    history_request: Option<[u8; 32]>,
    history_response: Option<[u8; 32]>,
}
impl ObjectLink {
    /// Pinned identity authenticated by the live hybrid session, not an object field.
    pub fn peer_id(&self) -> [u8; 32] {
        self.session.peer_id()
    }
    pub fn matches_network(&self, genesis: [u8; 32], fingerprint: [u8; 32]) -> bool {
        self.session.matches_network(genesis, fingerprint)
    }
    /// Binds a socket carrier to this exact completed handshake, not only a peer.
    pub fn session_id(&self) -> [u8; 32] {
        self.session.id()
    }
    pub fn lifetime_deadline(&self) -> std::time::Instant { self.session.lifetime_deadline() }
    pub fn new(session: Session, queue: ObjectQueue) -> Result<Self> {
        Self::new_authorized(session, queue, LocalAuthorization::Unrestricted)
    }
    /// Call only from trusted local provisioning after the pinned handshake.
    /// There is no protocol field that selects or broadens this restriction.
    pub fn new_authorized(session: Session, queue: ObjectQueue, authorization: LocalAuthorization) -> Result<Self> {
        if session.peer_id() != queue.peer_id() {
            return Err(Error::Context);
        }
        if matches!(authorization, LocalAuthorization::WalletHistoryClientToNode | LocalAuthorization::NodeToWalletHistoryClient)
            && !queue.history_profile() { return Err(Error::Context); }
        Ok(Self {
            session,
            queue,
            wanted: BTreeMap::new(),
            last_served: None,
            authorization,
            incoming: BTreeSet::new(),
            outgoing: BTreeSet::new(),
            history_plan: None,
            history_request: None,
            history_response: None,
        })
    }
    pub fn authorization(&self) -> LocalAuthorization { self.authorization }
    pub fn check_outgoing_kind(&self, kind: ObjectKind) -> Result<()> {
        if self.authorization != LocalAuthorization::Unrestricted { self.session.live()?; }
        if self.authorization.outgoing(kind) { Ok(()) } else { Err(Error::Context) }
    }
    fn check_incoming_kind(&self, kind: ObjectKind) -> Result<()> {
        if self.authorization != LocalAuthorization::Unrestricted { self.session.live()?; }
        if self.authorization.incoming(kind) { Ok(()) } else { Err(Error::Context) }
    }
    fn incoming_object(&self, id: &[u8; 32]) -> Result<()> {
        if self.authorization == LocalAuthorization::Unrestricted { return Ok(()); }
        self.session.live()?;
        let (offer, _) = self.queue.describe(id)?;
        self.check_incoming_kind(offer.kind)?;
        if self.incoming.contains(id) { Ok(()) } else { Err(Error::Context) }
    }
    fn outgoing_object(&self, id: &[u8; 32]) -> Result<()> {
        if self.authorization == LocalAuthorization::Unrestricted { return Ok(()); }
        self.session.live()?;
        let (offer, _) = self.queue.describe(id)?;
        self.check_outgoing_kind(offer.kind)?;
        if self.outgoing.contains(id) { Ok(()) } else { Err(Error::Context) }
    }
    /// Recheck before semantic processing, including after a canonical actor wait.
    pub fn check_incoming_event(&self, event: &Event) -> Result<()> {
        if self.authorization != LocalAuthorization::Unrestricted { self.session.live()?; }
        match event {
            Event::Offered(offer) | Event::Completed { offer, .. } => self.incoming_object(&offer.id),
            _ => Ok(()),
        }
    }
    /// Durable bytes require a NEW authenticated offer in this exact session.
    pub fn completed_incoming(&self, id: &[u8; 32]) -> Result<(Offer, Vec<u8>)> {
        self.incoming_object(id)?;
        self.completed(id)
    }
    pub fn enqueue(
        &mut self,
        kind: ObjectKind,
        bytes: &[u8],
        hops: u8,
    ) -> Result<(Offer, Vec<u8>)> {
        if hops > 16 {
            return Err(Error::Encoding);
        }
        self.check_outgoing_kind(kind)?;
        if self.authorization == LocalAuthorization::WalletHistoryClientToNode
            && matches!(kind, ObjectKind::CertifiedBlock | ObjectKind::RecoveryEvidence | ObjectKind::HistoryPageV1) {
            return Err(Error::Context);
        }
        if kind == ObjectKind::HistoryRequestV1 {
            let id = crate::objects::object_id(kind, bytes)?;
            if self.history_plan.is_some() || self.history_request.is_some_and(|active| active != id) {
                return Err(Error::Context);
            }
        }
        let offer = self.queue.enqueue(kind, bytes)?;
        if kind == ObjectKind::HistoryRequestV1 { self.history_request = Some(offer.id); }
        let frame = self.advertise(&offer.id, hops)?;
        Ok((offer, frame))
    }
    pub fn advertise(&mut self, id: &[u8; 32], hops: u8) -> Result<Vec<u8>> {
        let (offer, complete) = self.queue.describe(id)?;
        if !complete {
            return Err(Error::Context);
        }
        self.check_outgoing_kind(offer.kind)?;
        if self.authorization == LocalAuthorization::WalletHistoryClientToNode
            && matches!(offer.kind, ObjectKind::CertifiedBlock | ObjectKind::RecoveryEvidence | ObjectKind::HistoryPageV1) {
            let plan = self.history_plan.as_ref().ok_or(Error::Context)?;
            if *id != plan.page && (!plan.page_advertised || !plan.members.iter().any(|member| member == &offer)) {
                return Err(Error::Context);
            }
        }
        let (meta, payload) = offer.have(hops)?;
        let frame = self.session.seal(&meta, &payload)?;
        if self.authorization != LocalAuthorization::Unrestricted { self.outgoing.insert(*id); }
        if let Some(plan) = self.history_plan.as_mut() {
            if plan.page == *id { plan.page_advertised = true; }
        }
        Ok(frame)
    }
    fn control(&mut self, id: &[u8; 32], bitmap: &Bitmap, hops: u8, kind: u8) -> Result<Vec<u8>> {
        self.incoming_object(id)?;
        let (offer, _) = self.queue.describe(id)?;
        let (mut meta, _) = offer.have(hops)?;
        meta.kind = kind;
        let payload = bitmap.encode(meta.count)?;
        self.session.seal(&meta, &payload)
    }
    /// Local scheduling chooses the next bounded window. No unbounded response
    /// amplification; the peer must call send_one at its own pacing boundary.
    pub fn request_missing(
        &mut self,
        id: &[u8; 32],
        start: u16,
        count: u16,
        hops: u8,
        nack: bool,
    ) -> Result<Vec<u8>> {
        self.incoming_object(id)?;
        let bitmap = self.queue.missing(id, start, count)?;
        self.control(id, &bitmap, hops, if nack { 5 } else { 2 })
    }
    /// Find the first missing durable window, including after reconnect. At most
    /// ceil(MAX_OBJECT_BYTES / MAX_PAYLOAD / MAX_BITMAP_BITS) bounded reads.
    /// Never infer progress from packet count (duplicates may arrive).
    pub fn next_missing_request(
        &mut self,
        id: &[u8; 32],
        hops: u8,
        nack: bool,
    ) -> Result<Option<RequestWindow>> {
        self.incoming_object(id)?;
        let (offer, complete) = self.queue.describe(id)?;
        if complete {
            return Ok(None);
        }
        let total: u16 = offer
            .length
            .div_ceil(crate::MAX_PAYLOAD)
            .try_into()
            .map_err(|_| Error::Limit)?;
        let mut start = 0u16;
        while start < total {
            let count = (total - start).min(crate::objects::MAX_BITMAP_BITS);
            self.incoming_object(id)?;
        let bitmap = self.queue.missing(id, start, count)?;
            if bitmap.bits.iter().any(|missing| *missing) {
                let frame = self.control(id, &bitmap, hops, if nack { 5 } else { 2 })?;
                return Ok(Some(RequestWindow {
                    start,
                    count,
                    frame,
                }));
            }
            start = start.checked_add(count).ok_or(Error::Limit)?;
        }
        // A complete fragment set without the durable hash-checked completion
        // marker is a storage inconsistency, not successful delivery.
        Err(Error::Storage)
    }
    /// Local durable progress only. No frame, send-attempt reservation or
    /// settlement authority is produced by this bounded read.
    pub fn missing_window(&self, id: &[u8; 32], start: u16, count: u16) -> Result<Bitmap> {
        self.incoming_object(id)?;
        self.queue.missing(id, start, count)
    }
    pub fn receipt(&mut self, id: &[u8; 32], start: u16, count: u16, hops: u8) -> Result<Vec<u8>> {
        self.incoming_object(id)?;
        let mut bitmap = self.queue.missing(id, start, count)?;
        for bit in &mut bitmap.bits {
            *bit = !*bit;
        }
        self.control(id, &bitmap, hops, 4)
    }
    pub fn receive(&mut self, frame: &[u8]) -> Result<Event> {
        // Authentication/replay checks precede all persistent object operations.
        let (meta, payload) = self.session.open(frame)?;
        match meta.kind {
            1 => {
                let offer = Offer::parse(&meta, &payload)?;
                self.check_incoming_kind(offer.kind)?;
                if offer.kind == ObjectKind::HistoryPageV1 {
                    if self.history_request.is_none() || self.history_response.is_some_and(|active| active != offer.id) {
                        return Err(Error::Context);
                    }
                }
                if self.authorization == LocalAuthorization::NodeToWalletHistoryClient
                    && matches!(offer.kind, ObjectKind::CertifiedBlock | ObjectKind::RecoveryEvidence) {
                    let plan = self.history_plan.as_ref().ok_or(Error::Context)?;
                    if !plan.members.contains(&offer) { return Err(Error::Context); }
                }
                self.queue.offer(&offer)?;
                if offer.kind == ObjectKind::HistoryPageV1 { self.history_response = Some(offer.id); }
                if self.authorization != LocalAuthorization::Unrestricted { self.incoming.insert(offer.id); }
                Ok(Event::Offered(offer))
            }
            3 => {
                self.incoming_object(&meta.object)?;
                match self.queue.receive(&meta, &payload)? {
                Some(bytes) => {
                    let (offer, _) = self.queue.describe(&meta.object)?;
                    Ok(Event::Completed { offer, bytes })
                }
                None => Ok(Event::FragmentReceived),
                }
            },
            2 | 4 | 5 => {
                self.outgoing_object(&meta.object)?;
                let (offer, complete) = self.queue.describe(&meta.object)?;
                let (expected, _) = offer.have(meta.hops)?;
                if !complete || meta.fragment != 0 || meta.count != expected.count {
                    return Err(Error::Context);
                }
                let bitmap = Bitmap::parse(&payload, meta.count)?;
                if meta.kind == 4 {
                    self.queue.acknowledge(&meta.object, &bitmap)?;
                    Ok(Event::ReceiptRecorded)
                } else {
                    if !self.wanted.contains_key(&meta.object)
                        && self.wanted.len() >= crate::objects::MAX_REQUESTS
                    {
                        return Err(Error::Limit);
                    }
                    self.wanted.insert(meta.object, (bitmap, meta.hops));
                    Ok(Event::Requested)
                }
            }
            _ => Err(Error::Encoding),
        }
    }
    /// At most one frame per call, with at most eight queued request windows.
    /// Storage commits retry consumption before encryption. A sealing failure
    /// may consume an attempt; it never resets retries or permits nonce reuse.
    pub fn send_one(&mut self) -> Result<Option<Vec<u8>>> {
        while let Some(id) = self
            .last_served
            .and_then(|last| {
                self.wanted
                    .range((std::ops::Bound::Excluded(last), std::ops::Bound::Unbounded))
                    .next()
                    .map(|(id, _)| *id)
            })
            .or_else(|| self.wanted.keys().next().copied())
        {
            self.outgoing_object(&id)?;
            let (wanted, hops) = self.wanted.get_mut(&id).ok_or(Error::Context)?;
            match self.queue.next_fragment(&id, wanted, *hops)? {
                Some((meta, payload)) => {
                    let frame = self.session.seal(&meta, &payload)?;
                    wanted.bits[(meta.fragment - wanted.start) as usize] = false;
                    self.last_served = Some(id);
                    return Ok(Some(frame));
                }
                None => {
                    self.wanted.remove(&id);
                }
            }
        }
        Ok(None)
    }
    pub fn acknowledged(&self, id: &[u8; 32], start: u16, count: u16) -> Result<Bitmap> {
        self.outgoing_object(id)?;
        self.queue.acknowledged(id, start, count)
    }
    fn history_live(&self) -> Result<()> {
        self.session.live()?;
        if !matches!(self.authorization, LocalAuthorization::WalletHistoryClientToNode | LocalAuthorization::NodeToWalletHistoryClient)
            || !self.queue.history_profile() { return Err(Error::Context); }
        Ok(())
    }
    pub fn history_general_capacity(&self) -> Result<GeneralCapacity> {
        self.history_live()?;
        self.queue.general_capacity()
    }
    pub fn history_capacity(&self, request: &[u8; 32]) -> Result<HistoryCapacity> {
        self.history_live()?;
        if self.authorization == LocalAuthorization::WalletHistoryClientToNode { self.incoming_object(request)?; }
        else { self.outgoing_object(request)?; }
        self.queue.history_capacity(request)
    }
    /// Only the local canonically verified exporter may call this. Raw public
    /// bytes remain transport copies, not evidence of canonical verification.
    /// Success does not advertise any candidate. The host advertises the page
    /// first, then paces each member using the existing command owner.
    pub fn enqueue_history_page(&mut self, request: &[u8; 32], page: &[u8],
        candidates: &[(ObjectKind, Vec<u8>)]) -> Result<Option<Vec<Offer>>> {
        self.history_live()?;
        if self.authorization != LocalAuthorization::WalletHistoryClientToNode { return Err(Error::Context); }
        if self.history_plan.is_some() { return Ok(None); }
        self.incoming_object(request)?;
        let Some(queued) = self.queue.enqueue_history_page(request, page, candidates)? else { return Ok(None); };
        self.history_plan = Some(HistoryPlan {
            request: *request, page: queued.offers[0].id,
            members: queued.offers[1..].to_vec(),
            owned: queued.offers.iter().zip(&queued.fresh).filter_map(|(offer, fresh)| fresh.then_some(offer.id)).collect(),
            page_advertised: false,
            alive:Arc::new(AtomicBool::new(true)),
        });
        Ok(Some(queued.offers))
    }
    /// Called ONLY after the host has canonically decoded/validated correlation,
    /// context, anchors, ordering and receiver budgets for a complete incoming
    /// page. This grants fetching only; it grants no canonical acceptance.
    pub fn history_accept_plan(&mut self, request: &[u8; 32], page: &[u8; 32], members: &[Offer]) -> Result<()> {
        self.history_live()?;
        if self.authorization != LocalAuthorization::NodeToWalletHistoryClient
            || self.history_plan.is_some() || self.history_request != Some(*request)
            || self.history_response != Some(*page) || members.len() > MAX_HISTORY_CANDIDATES { return Err(Error::Context); }
        self.outgoing_object(request)?;
        let (req, req_complete) = self.queue.describe(request)?;
        if req.kind != ObjectKind::HistoryRequestV1 || !req_complete { return Err(Error::Context); }
        self.incoming_object(page)?;
        let (response, complete) = self.queue.describe(page)?;
        if response.kind != ObjectKind::HistoryPageV1 || !complete { return Err(Error::Context); }
        let mut ids = BTreeSet::new();
        let mut recovery = false;
        for member in members {
            member.have(0)?;
            if !ids.insert(member.id) { return Err(Error::Context); }
            match member.kind {
                ObjectKind::RecoveryEvidence if !recovery => recovery = true,
                ObjectKind::CertifiedBlock => recovery = false,
                _ => return Err(Error::Context),
            }
        }
        if recovery { return Err(Error::Context); }
        self.queue.check_history_plan_capacity(request, page, members)?;
        self.history_plan = Some(HistoryPlan { request: *request, page: *page,
            members: members.to_vec(), owned: BTreeSet::new(), page_advertised: false,
            alive:Arc::new(AtomicBool::new(true)) });
        Ok(())
    }
    /// Mint only after actual acceptance under a fresh incoming page grant.
    /// Retirement, replacement and link disconnect/drop revoke every clone.
    pub fn history_plan_lease(&self,page:&[u8;32])->Result<HistoryPlanLease> {
        self.history_live()?;
        if self.authorization!=LocalAuthorization::NodeToWalletHistoryClient {return Err(Error::Context);}
        let plan=self.history_plan.as_ref().ok_or(Error::Context)?;
        if plan.page!=*page {return Err(Error::Context);}
        self.incoming_object(page)?;
        let lease=HistoryPlanLease{alive:plan.alive.clone()};
        lease.check_current()?;
        Ok(lease)
    }
    pub fn history_acknowledged(&self, object: &[u8; 32], start: u16, count: u16) -> Result<Bitmap> {
        self.history_live()?;
        let plan = self.history_plan.as_ref().ok_or(Error::Context)?;
        if *object != plan.page && !plan.members.iter().any(|offer| offer.id == *object) { return Err(Error::Context); }
        self.acknowledged(object, start, count)
    }
    /// Host proof prerequisite: page correlation/plan accepted (wallet), or
    /// request decoded/validated and export prepared (node). Complete current
    /// session grants and the exact active request are checked again here.
    pub fn history_retire_consumed_request(&mut self, request: &[u8; 32]) -> Result<()> {
        self.history_live()?;
        let plan = self.history_plan.as_ref().ok_or(Error::Context)?;
        if plan.request != *request { return Err(Error::Context); }
        if self.authorization == LocalAuthorization::WalletHistoryClientToNode { self.incoming_object(request)?; }
        else { self.outgoing_object(request)?; }
        let (offer, complete) = self.queue.describe(request)?;
        if offer.kind != ObjectKind::HistoryRequestV1 || !complete { return Err(Error::Context); }
        self.discard(request)
    }
    /// Receiver host MUST first commit/revalidate the exact member with its
    /// canonical verifier. This method verifies only current plan and transport
    /// provenance. A transport ACK or complete hash is never that host proof.
    pub fn history_reclaim_verified_candidate(&mut self, page: &[u8; 32], object: &[u8; 32]) -> Result<()> {
        self.history_live()?;
        if self.authorization != LocalAuthorization::NodeToWalletHistoryClient { return Err(Error::Context); }
        let plan = self.history_plan.as_ref().ok_or(Error::Context)?;
        if plan.page != *page { return Err(Error::Context); }
        let member = plan.members.iter().find(|offer| offer.id == *object).ok_or(Error::Context)?;
        self.incoming_object(object)?;
        let (offer, complete) = self.queue.describe(object)?;
        if &offer != member || !complete { return Err(Error::Context); }
        self.discard(object)?;
        if let Some(plan) = self.history_plan.as_mut() { plan.members.retain(|member| member.id != *object); }
        Ok(())
    }
    /// Node export copies are re-exportable from canonical storage. Release
    /// only a copy created by this page and only after every fragment is ACKed
    /// in this exact authenticated session. No remote acceptance is inferred.
    pub fn history_reclaim_acknowledged_export(&mut self, page: &[u8; 32], object: &[u8; 32]) -> Result<()> {
        self.history_live()?;
        if self.authorization != LocalAuthorization::WalletHistoryClientToNode { return Err(Error::Context); }
        let plan = self.history_plan.as_ref().ok_or(Error::Context)?;
        if plan.page != *page || *object == *page || !plan.owned.contains(object)
            || !plan.members.iter().any(|offer| offer.id == *object) { return Err(Error::Context); }
        self.outgoing_object(object)?;
        let (offer, _) = self.queue.describe(object)?;
        let fragments = offer.length.div_ceil(crate::MAX_PAYLOAD) as u16;
        for start in (0..fragments).step_by(crate::objects::MAX_BITMAP_BITS as usize) {
            let n = (fragments - start).min(crate::objects::MAX_BITMAP_BITS);
            if !self.queue.acknowledged(object, start, n)?.bits.iter().all(|bit| *bit) { return Err(Error::Context); }
        }
        self.discard(object)
    }
    /// Autonomous owner variant: preserved pre-existing copies are not evicted.
    /// The caller has already observed full ACK; fresh copies still pass the
    /// complete authenticated ACK check in the strict release operation.
    pub fn history_reclaim_acknowledged_export_if_owned(&mut self, page: &[u8; 32], object: &[u8; 32]) -> Result<bool> {
        self.history_live()?;
        if self.authorization != LocalAuthorization::WalletHistoryClientToNode { return Err(Error::Context); }
        let plan = self.history_plan.as_ref().ok_or(Error::Context)?;
        if plan.page != *page || !plan.members.iter().any(|offer| offer.id == *object) { return Err(Error::Context); }
        if !plan.owned.contains(object) { return Ok(false); }
        self.history_reclaim_acknowledged_export(page, object)?;
        Ok(true)
    }
    /// Host retires a consumed/redundant plan before accepting the next request.
    /// Only this exact public page copy is removed; member bytes remain unless
    /// separately reclaimed with the canonical/ACK checks above.
    pub fn history_retire_plan(&mut self, page: &[u8; 32]) -> Result<()> {
        self.history_live()?;
        let plan = self.history_plan.as_ref().ok_or(Error::Context)?;
        if plan.page != *page { return Err(Error::Context); }
        if self.authorization == LocalAuthorization::NodeToWalletHistoryClient {
            self.incoming_object(page)?;
            let (_, complete) = self.queue.describe(page)?;
            if !complete { return Err(Error::Context); }
            self.discard(page)?;
        } else {
            // Exact current-session page grant and active plan make even a
            // reoffered retained control copy redundant. Canonical candidate
            // copies retain their separate fresh-ownership/ACK requirement.
            self.outgoing_object(page)?;
            self.discard(page)?;
        }
        self.history_plan = None;
        self.history_request = None;
        self.history_response = None;
        Ok(())
    }
    /// Allows idempotent application delivery after restart. Object hash is
    /// checked again; the endpoint must independently validate canonical meaning.
    pub fn completed(&self, id: &[u8; 32]) -> Result<(Offer, Vec<u8>)> {
        if self.authorization != LocalAuthorization::Unrestricted {
            if self.incoming_object(id).is_err() { self.outgoing_object(id)?; }
        }
        let (offer, complete) = self.queue.describe(id)?;
        if !complete {
            return Err(Error::Context);
        }
        Ok((offer, self.queue.read_complete(id)?))
    }
    pub fn submission_offers(&self) -> Result<Vec<Offer>> {
        self.queue.submission_offers()
    }
    pub fn a2_evidence_offer(&self) -> Result<Option<Offer>> {
        self.queue.a2_evidence_offer()
    }
    pub fn has_a2_reservation(&self) -> Result<bool> {
        self.queue.has_a2_reservation()
    }
    pub fn describe(&self, id: &[u8; 32]) -> Result<(Offer, bool)> {
        self.queue.describe(id)
    }
    /// Local-only administration; no wire message dispatches object deletion.
    pub fn discard(&mut self, id: &[u8; 32]) -> Result<()> {
        self.queue.discard(id)?;
        self.wanted.remove(id);
        self.incoming.remove(id);
        self.outgoing.remove(id);
        Ok(())
    }
    /// Reconnection drops traffic keys and transient requests. Reattach the
    /// durable public queue only to a freshly authenticated same-peer session.
    pub fn disconnect(self) -> ObjectQueue {
        self.queue
    }
}

#[cfg(test)]
#[path = "wallet_client_authorization_tests.rs"]
mod wallet_client_authorization_tests;
#[cfg(test)]
#[path = "history_link_v1_tests.rs"]
mod history_link_v1_tests;
