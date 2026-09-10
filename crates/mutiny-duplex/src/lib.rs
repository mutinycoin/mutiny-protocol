use mutiny_p2p::{Frame, P2pError};
use std::{
    collections::HashMap,
    net::{Shutdown, TcpStream},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use thiserror::Error;

/// Build 4.5 transport direction. This is not a consensus value and is never serialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDirection {
    Inbound,
    Outbound,
}

/// Deterministic duplicate-connection rule.
///
/// The lexicographically smaller NodeID is the preferred TCP initiator. Therefore both
/// endpoints independently select the same physical connection when simultaneous A->B and
/// B->A handshakes occur:
/// - lower NodeID keeps its outbound connection;
/// - higher NodeID keeps its inbound connection.
pub fn preferred_direction(
    local_node_id: [u8; 32],
    remote_node_id: [u8; 32],
) -> ConnectionDirection {
    if local_node_id < remote_node_id {
        ConnectionDirection::Outbound
    } else {
        ConnectionDirection::Inbound
    }
}

pub fn candidate_should_replace(
    local_node_id: [u8; 32],
    remote_node_id: [u8; 32],
    current: ConnectionDirection,
    candidate: ConnectionDirection,
) -> bool {
    if current == candidate {
        return false;
    }
    candidate == preferred_direction(local_node_id, remote_node_id)
}

pub const DEFAULT_MAX_PENDING_REQUESTS: usize = 64;
pub const DEFAULT_MAX_UNSOLICITED_FRAMES: usize = 128;
pub const DEFAULT_MAX_FRAMES_PER_WINDOW: u64 = 512;
pub const DEFAULT_MAX_BYTES_PER_WINDOW: u64 = 16 * 1024 * 1024;
pub const DEFAULT_RATE_WINDOW: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplexLimits {
    pub max_pending_requests: usize,
    pub max_unsolicited_frames: usize,
    pub max_frames_per_window: u64,
    pub max_bytes_per_window: u64,
    pub rate_window: Duration,
}

impl Default for DuplexLimits {
    fn default() -> Self {
        Self {
            max_pending_requests: DEFAULT_MAX_PENDING_REQUESTS,
            max_unsolicited_frames: DEFAULT_MAX_UNSOLICITED_FRAMES,
            max_frames_per_window: DEFAULT_MAX_FRAMES_PER_WINDOW,
            max_bytes_per_window: DEFAULT_MAX_BYTES_PER_WINDOW,
            rate_window: DEFAULT_RATE_WINDOW,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DuplexMetrics {
    pub frames_sent: u64,
    pub frames_received: u64,
    pub requests_started: u64,
    pub responses_routed: u64,
    pub unsolicited_routed: u64,
    pub request_timeouts: u64,
    pub reader_exits: u64,
    pub pending_limit_rejections: u64,
    pub unsolicited_overflow_closes: u64,
    pub rate_limit_closes: u64,
}

#[derive(Debug, Error)]
pub enum DuplexError {
    #[error("duplex session is closed")]
    Closed,
    #[error("duplicate pending RequestID {0}")]
    DuplicateRequestId(u64),
    #[error("duplex request {0} timed out")]
    Timeout(u64),
    #[error("duplex reader stopped: {0}")]
    ReaderStopped(String),
    #[error("duplex protocol error: {0}")]
    Protocol(String),
    #[error("duplex resource limit: {0}")]
    ResourceLimit(String),
    #[error(transparent)]
    P2p(#[from] P2pError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

type PendingResult = Result<Frame, String>;

struct PendingRequest {
    expected_types: Vec<u16>,
    tx: mpsc::Sender<PendingResult>,
}

struct Inner {
    magic: u32,
    writer: Mutex<TcpStream>,
    pending: Mutex<HashMap<u64, PendingRequest>>,
    unsolicited_tx: mpsc::SyncSender<Frame>,
    unsolicited_rx: Mutex<mpsc::Receiver<Frame>>,
    limits: DuplexLimits,
    closed: AtomicBool,
    next_request_id: AtomicU64,
    lane_high_bit: bool,
    frames_sent: AtomicU64,
    frames_received: AtomicU64,
    requests_started: AtomicU64,
    responses_routed: AtomicU64,
    unsolicited_routed: AtomicU64,
    request_timeouts: AtomicU64,
    reader_exits: AtomicU64,
    pending_limit_rejections: AtomicU64,
    unsolicited_overflow_closes: AtomicU64,
    rate_limit_closes: AtomicU64,
}

/// One authenticated full-duplex transport.
///
/// Authentication happens before construction. Once created, exactly one reader loop owns
/// incoming bytes, responses are routed by RequestID + expected message type, and all writers
/// serialize through one mutex so concurrent callers cannot interleave frame bytes.
#[derive(Clone)]
pub struct DuplexSession {
    inner: Arc<Inner>,
}

impl DuplexSession {
    /// Wrap an already-authenticated TCP stream.
    ///
    /// `lane_high_bit` partitions locally allocated RequestIDs into disjoint halves. A live
    /// peer pair should derive opposite values from NodeID ordering, preventing simultaneous
    /// bidirectional requests from allocating the same RequestID.
    pub fn from_authenticated_stream(
        stream: TcpStream,
        magic: u32,
        lane_high_bit: bool,
    ) -> Result<Self, DuplexError> {
        Self::from_authenticated_stream_with_limits(
            stream,
            magic,
            lane_high_bit,
            DuplexLimits::default(),
        )
    }

    pub fn from_authenticated_stream_with_limits(
        stream: TcpStream,
        magic: u32,
        lane_high_bit: bool,
        limits: DuplexLimits,
    ) -> Result<Self, DuplexError> {
        if limits.max_pending_requests == 0
            || limits.max_unsolicited_frames == 0
            || limits.max_frames_per_window == 0
            || limits.max_bytes_per_window == 0
            || limits.rate_window.is_zero()
        {
            return Err(DuplexError::Protocol(
                "duplex limits must all be non-zero".into(),
            ));
        }
        stream.set_nodelay(true)?;
        let reader = stream.try_clone()?;
        let (unsolicited_tx, unsolicited_rx) = mpsc::sync_channel(limits.max_unsolicited_frames);
        let first = if lane_high_bit { 1u64 << 63 } else { 1 };
        let inner = Arc::new(Inner {
            magic,
            writer: Mutex::new(stream),
            pending: Mutex::new(HashMap::new()),
            unsolicited_tx,
            unsolicited_rx: Mutex::new(unsolicited_rx),
            limits,
            closed: AtomicBool::new(false),
            next_request_id: AtomicU64::new(first),
            lane_high_bit,
            frames_sent: AtomicU64::new(0),
            frames_received: AtomicU64::new(0),
            requests_started: AtomicU64::new(0),
            responses_routed: AtomicU64::new(0),
            unsolicited_routed: AtomicU64::new(0),
            request_timeouts: AtomicU64::new(0),
            reader_exits: AtomicU64::new(0),
            pending_limit_rejections: AtomicU64::new(0),
            unsolicited_overflow_closes: AtomicU64::new(0),
            rate_limit_closes: AtomicU64::new(0),
        });
        let session = Self { inner };
        session.spawn_reader(reader);
        Ok(session)
    }

    fn spawn_reader(&self, mut reader: TcpStream) {
        let inner = self.inner.clone();
        thread::spawn(move || {
            let mut window_started = Instant::now();
            let mut window_frames = 0u64;
            let mut window_bytes = 0u64;
            loop {
                let frame = match Frame::read_from(&mut reader, inner.magic) {
                    Ok(frame) => frame,
                    Err(e) => {
                        inner.closed.store(true, Ordering::SeqCst);
                        inner.reader_exits.fetch_add(1, Ordering::Relaxed);
                        let reason = e.to_string();
                        if let Ok(mut pending) = inner.pending.lock() {
                            for (_, waiter) in pending.drain() {
                                let _ = waiter.tx.send(Err(reason.clone()));
                            }
                        }
                        break;
                    }
                };
                inner.frames_received.fetch_add(1, Ordering::Relaxed);

                if window_started.elapsed() >= inner.limits.rate_window {
                    window_started = Instant::now();
                    window_frames = 0;
                    window_bytes = 0;
                }
                window_frames = window_frames.saturating_add(1);
                window_bytes = window_bytes.saturating_add(26 + frame.payload.len() as u64);
                if window_frames > inner.limits.max_frames_per_window
                    || window_bytes > inner.limits.max_bytes_per_window
                {
                    inner.rate_limit_closes.fetch_add(1, Ordering::Relaxed);
                    inner.closed.store(true, Ordering::SeqCst);
                    inner.reader_exits.fetch_add(1, Ordering::Relaxed);
                    if let Ok(mut pending) = inner.pending.lock() {
                        for (_, waiter) in pending.drain() {
                            let _ = waiter
                                .tx
                                .send(Err("peer exceeded duplex receive budget".into()));
                        }
                    }
                    let _ = reader.shutdown(Shutdown::Both);
                    break;
                }

                let waiter = {
                    let mut pending = match inner.pending.lock() {
                        Ok(v) => v,
                        Err(_) => {
                            inner.closed.store(true, Ordering::SeqCst);
                            inner.reader_exits.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                    };
                    let matches_pending = pending
                        .get(&frame.request_id)
                        .is_some_and(|p| p.expected_types.contains(&frame.message_type));
                    if matches_pending {
                        pending.remove(&frame.request_id)
                    } else {
                        None
                    }
                };

                if let Some(waiter) = waiter {
                    inner.responses_routed.fetch_add(1, Ordering::Relaxed);
                    let _ = waiter.tx.send(Ok(frame));
                } else {
                    match inner.unsolicited_tx.try_send(frame) {
                        Ok(()) => {
                            inner.unsolicited_routed.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(mpsc::TrySendError::Full(_)) => {
                            inner
                                .unsolicited_overflow_closes
                                .fetch_add(1, Ordering::Relaxed);
                            inner.closed.store(true, Ordering::SeqCst);
                            inner.reader_exits.fetch_add(1, Ordering::Relaxed);
                            if let Ok(mut pending) = inner.pending.lock() {
                                for (_, waiter) in pending.drain() {
                                    let _ = waiter.tx.send(Err(
                                        "peer overflowed bounded unsolicited queue".into(),
                                    ));
                                }
                            }
                            let _ = reader.shutdown(Shutdown::Both);
                            break;
                        }
                        Err(mpsc::TrySendError::Disconnected(_)) => {
                            inner.closed.store(true, Ordering::SeqCst);
                            inner.reader_exits.fetch_add(1, Ordering::Relaxed);
                            break;
                        }
                    }
                }
            }
        });
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    pub fn lane_high_bit(&self) -> bool {
        self.inner.lane_high_bit
    }

    pub fn allocate_request_id(&self) -> Result<u64, DuplexError> {
        if self.is_closed() {
            return Err(DuplexError::Closed);
        }
        loop {
            let id = self.inner.next_request_id.fetch_add(1, Ordering::Relaxed);
            let normalized = if self.inner.lane_high_bit {
                id | (1u64 << 63)
            } else {
                id & !(1u64 << 63)
            };
            if normalized != 0 {
                return Ok(normalized);
            }
        }
    }

    pub fn send_frame(&self, frame: Frame) -> Result<(), DuplexError> {
        if self.is_closed() {
            return Err(DuplexError::Closed);
        }
        let mut writer = self
            .inner
            .writer
            .lock()
            .map_err(|_| DuplexError::Protocol("writer mutex poisoned".into()))?;
        frame.write_to(&mut writer)?;
        self.inner.frames_sent.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    pub fn send_unsolicited(&self, message_type: u16, payload: Vec<u8>) -> Result<(), DuplexError> {
        self.send_frame(Frame::new(self.inner.magic, message_type, 0, payload)?)
    }

    pub fn request(
        &self,
        message_type: u16,
        payload: Vec<u8>,
        expected_types: &[u16],
        timeout: Duration,
    ) -> Result<Frame, DuplexError> {
        let request_id = self.allocate_request_id()?;
        self.request_with_id(request_id, message_type, payload, expected_types, timeout)
    }

    pub fn request_with_id(
        &self,
        request_id: u64,
        message_type: u16,
        payload: Vec<u8>,
        expected_types: &[u16],
        timeout: Duration,
    ) -> Result<Frame, DuplexError> {
        if expected_types.is_empty() {
            return Err(DuplexError::Protocol(
                "request must declare at least one expected response type".into(),
            ));
        }
        if self.is_closed() {
            return Err(DuplexError::Closed);
        }
        let (tx, rx) = mpsc::channel();
        {
            let mut pending = self
                .inner
                .pending
                .lock()
                .map_err(|_| DuplexError::Protocol("pending mutex poisoned".into()))?;
            if pending.contains_key(&request_id) {
                return Err(DuplexError::DuplicateRequestId(request_id));
            }
            if pending.len() >= self.inner.limits.max_pending_requests {
                self.inner
                    .pending_limit_rejections
                    .fetch_add(1, Ordering::Relaxed);
                return Err(DuplexError::ResourceLimit(format!(
                    "pending request cap {} reached",
                    self.inner.limits.max_pending_requests
                )));
            }
            pending.insert(
                request_id,
                PendingRequest {
                    expected_types: expected_types.to_vec(),
                    tx,
                },
            );
        }
        self.inner.requests_started.fetch_add(1, Ordering::Relaxed);

        let frame = Frame::new(self.inner.magic, message_type, request_id, payload)?;
        if let Err(e) = self.send_frame(frame) {
            if let Ok(mut pending) = self.inner.pending.lock() {
                pending.remove(&request_id);
            }
            return Err(e);
        }

        match rx.recv_timeout(timeout) {
            Ok(Ok(frame)) => Ok(frame),
            Ok(Err(reason)) => Err(DuplexError::ReaderStopped(reason)),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if let Ok(mut pending) = self.inner.pending.lock() {
                    pending.remove(&request_id);
                }
                self.inner.request_timeouts.fetch_add(1, Ordering::Relaxed);
                Err(DuplexError::Timeout(request_id))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(DuplexError::ReaderStopped(
                "response router disconnected".into(),
            )),
        }
    }

    /// Receive a frame that was not a matching response to a local pending request.
    /// Requests from the peer and unsolicited announcements both arrive here.
    pub fn recv_unsolicited(&self, timeout: Duration) -> Result<Option<Frame>, DuplexError> {
        let rx = self
            .inner
            .unsolicited_rx
            .lock()
            .map_err(|_| DuplexError::Protocol("unsolicited receiver mutex poisoned".into()))?;
        match rx.recv_timeout(timeout) {
            Ok(frame) => Ok(Some(frame)),
            Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if self.is_closed() {
                    Err(DuplexError::Closed)
                } else {
                    Err(DuplexError::ReaderStopped(
                        "unsolicited router disconnected".into(),
                    ))
                }
            }
        }
    }

    pub fn metrics(&self) -> DuplexMetrics {
        DuplexMetrics {
            frames_sent: self.inner.frames_sent.load(Ordering::Relaxed),
            frames_received: self.inner.frames_received.load(Ordering::Relaxed),
            requests_started: self.inner.requests_started.load(Ordering::Relaxed),
            responses_routed: self.inner.responses_routed.load(Ordering::Relaxed),
            unsolicited_routed: self.inner.unsolicited_routed.load(Ordering::Relaxed),
            request_timeouts: self.inner.request_timeouts.load(Ordering::Relaxed),
            reader_exits: self.inner.reader_exits.load(Ordering::Relaxed),
            pending_limit_rejections: self.inner.pending_limit_rejections.load(Ordering::Relaxed),
            unsolicited_overflow_closes: self
                .inner
                .unsolicited_overflow_closes
                .load(Ordering::Relaxed),
            rate_limit_closes: self.inner.rate_limit_closes.load(Ordering::Relaxed),
        }
    }

    pub fn close(&self) {
        if !self.inner.closed.swap(true, Ordering::SeqCst) {
            if let Ok(writer) = self.inner.writer.lock() {
                let _ = writer.shutdown(Shutdown::Both);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mutiny_p2p::{MSG_BLOCK_ANNOUNCE, MSG_GET_ADDR, MSG_PING, MSG_PONG, P2P_MAGIC_DEVNET};
    use std::{net::TcpListener, sync::Barrier};

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    #[test]
    fn duplicate_connection_election_is_symmetric() {
        let mut low = [0u8; 32];
        let mut high = [0u8; 32];
        low[31] = 1;
        high[31] = 2;
        assert_eq!(
            preferred_direction(low, high),
            ConnectionDirection::Outbound
        );
        assert_eq!(preferred_direction(high, low), ConnectionDirection::Inbound);
        assert!(candidate_should_replace(
            low,
            high,
            ConnectionDirection::Inbound,
            ConnectionDirection::Outbound
        ));
        assert!(candidate_should_replace(
            high,
            low,
            ConnectionDirection::Outbound,
            ConnectionDirection::Inbound
        ));
    }

    #[test]
    fn request_id_lanes_do_not_collide() {
        let (a_raw, b_raw) = pair();
        let a = DuplexSession::from_authenticated_stream(a_raw, P2P_MAGIC_DEVNET, false).unwrap();
        let b = DuplexSession::from_authenticated_stream(b_raw, P2P_MAGIC_DEVNET, true).unwrap();
        let a_id = a.allocate_request_id().unwrap();
        let b_id = b.allocate_request_id().unwrap();
        assert_eq!(a_id >> 63, 0);
        assert_eq!(b_id >> 63, 1);
        assert_ne!(a_id, b_id);
        a.close();
        b.close();
    }

    #[test]
    fn routes_out_of_order_responses_by_request_id() {
        let (a_raw, b_raw) = pair();
        let a = DuplexSession::from_authenticated_stream(a_raw, P2P_MAGIC_DEVNET, false).unwrap();
        let b = DuplexSession::from_authenticated_stream(b_raw, P2P_MAGIC_DEVNET, true).unwrap();

        let b_worker = {
            let b = b.clone();
            thread::spawn(move || {
                let first = b.recv_unsolicited(Duration::from_secs(2)).unwrap().unwrap();
                let second = b.recv_unsolicited(Duration::from_secs(2)).unwrap().unwrap();
                b.send_frame(
                    Frame::new(
                        P2P_MAGIC_DEVNET,
                        MSG_PONG,
                        second.request_id,
                        second.payload,
                    )
                    .unwrap(),
                )
                .unwrap();
                b.send_frame(
                    Frame::new(P2P_MAGIC_DEVNET, MSG_PONG, first.request_id, first.payload)
                        .unwrap(),
                )
                .unwrap();
            })
        };

        let barrier = Arc::new(Barrier::new(3));
        let a1 = a.clone();
        let c1 = barrier.clone();
        let t1 = thread::spawn(move || {
            c1.wait();
            a1.request_with_id(
                101,
                MSG_PING,
                b"one".to_vec(),
                &[MSG_PONG],
                Duration::from_secs(2),
            )
            .unwrap()
        });
        let a2 = a.clone();
        let c2 = barrier.clone();
        let t2 = thread::spawn(move || {
            c2.wait();
            a2.request_with_id(
                102,
                MSG_PING,
                b"two".to_vec(),
                &[MSG_PONG],
                Duration::from_secs(2),
            )
            .unwrap()
        });
        barrier.wait();
        let r1 = t1.join().unwrap();
        let r2 = t2.join().unwrap();
        assert_eq!(r1.request_id, 101);
        assert_eq!(r1.payload.as_slice(), b"one");
        assert_eq!(r2.request_id, 102);
        assert_eq!(r2.payload.as_slice(), b"two");
        b_worker.join().unwrap();
        let metrics = a.metrics();
        assert_eq!(metrics.requests_started, 2);
        assert_eq!(metrics.responses_routed, 2);
        a.close();
        b.close();
    }

    #[test]
    fn unsolicited_announcement_does_not_steal_pending_response() {
        let (a_raw, b_raw) = pair();
        let a = DuplexSession::from_authenticated_stream(a_raw, P2P_MAGIC_DEVNET, false).unwrap();
        let b = DuplexSession::from_authenticated_stream(b_raw, P2P_MAGIC_DEVNET, true).unwrap();

        let b_worker = {
            let b = b.clone();
            thread::spawn(move || {
                let request = b.recv_unsolicited(Duration::from_secs(2)).unwrap().unwrap();
                b.send_unsolicited(MSG_BLOCK_ANNOUNCE, vec![7u8; 32])
                    .unwrap();
                b.send_frame(
                    Frame::new(
                        P2P_MAGIC_DEVNET,
                        MSG_PONG,
                        request.request_id,
                        request.payload,
                    )
                    .unwrap(),
                )
                .unwrap();
            })
        };

        let response = a
            .request(
                MSG_PING,
                b"ping".to_vec(),
                &[MSG_PONG],
                Duration::from_secs(2),
            )
            .unwrap();
        assert_eq!(response.payload.as_slice(), b"ping");
        let announce = a.recv_unsolicited(Duration::from_secs(2)).unwrap().unwrap();
        assert_eq!(announce.message_type, MSG_BLOCK_ANNOUNCE);
        assert_eq!(announce.request_id, 0);
        b_worker.join().unwrap();
        let metrics = a.metrics();
        assert_eq!(metrics.responses_routed, 1);
        assert_eq!(metrics.unsolicited_routed, 1);
        a.close();
        b.close();
    }

    #[test]
    fn simultaneous_bidirectional_requests_share_one_duplex_socket() {
        let (a_raw, b_raw) = pair();
        let a = DuplexSession::from_authenticated_stream(a_raw, P2P_MAGIC_DEVNET, false).unwrap();
        let b = DuplexSession::from_authenticated_stream(b_raw, P2P_MAGIC_DEVNET, true).unwrap();

        let a_service = {
            let a = a.clone();
            thread::spawn(move || {
                let frame = a.recv_unsolicited(Duration::from_secs(2)).unwrap().unwrap();
                assert_eq!(frame.message_type, MSG_GET_ADDR);
                a.send_frame(
                    Frame::new(
                        P2P_MAGIC_DEVNET,
                        MSG_PONG,
                        frame.request_id,
                        b"from-a".to_vec(),
                    )
                    .unwrap(),
                )
                .unwrap();
            })
        };
        let b_service = {
            let b = b.clone();
            thread::spawn(move || {
                let frame = b.recv_unsolicited(Duration::from_secs(2)).unwrap().unwrap();
                assert_eq!(frame.message_type, MSG_PING);
                b.send_frame(
                    Frame::new(
                        P2P_MAGIC_DEVNET,
                        MSG_PONG,
                        frame.request_id,
                        b"from-b".to_vec(),
                    )
                    .unwrap(),
                )
                .unwrap();
            })
        };

        let a_req = {
            let a = a.clone();
            thread::spawn(move || {
                a.request(MSG_PING, Vec::new(), &[MSG_PONG], Duration::from_secs(2))
                    .unwrap()
            })
        };
        let b_req = {
            let b = b.clone();
            thread::spawn(move || {
                b.request(
                    MSG_GET_ADDR,
                    Vec::new(),
                    &[MSG_PONG],
                    Duration::from_secs(2),
                )
                .unwrap()
            })
        };
        assert_eq!(a_req.join().unwrap().payload.as_slice(), b"from-b");
        assert_eq!(b_req.join().unwrap().payload.as_slice(), b"from-a");
        a_service.join().unwrap();
        b_service.join().unwrap();
        assert_eq!(a.metrics().responses_routed, 1);
        assert_eq!(b.metrics().responses_routed, 1);
        a.close();
        b.close();
    }
    #[test]
    fn hardened_pending_request_cap_rejects_excess_without_sending() {
        let (a_raw, _b_raw) = pair();
        let limits = DuplexLimits {
            max_pending_requests: 1,
            ..DuplexLimits::default()
        };
        let a = DuplexSession::from_authenticated_stream_with_limits(
            a_raw,
            P2P_MAGIC_DEVNET,
            false,
            limits,
        )
        .unwrap();
        let (tx, _rx) = mpsc::channel();
        a.inner.pending.lock().unwrap().insert(
            7,
            PendingRequest {
                expected_types: vec![MSG_PONG],
                tx,
            },
        );
        let err = a
            .request_with_id(
                8,
                MSG_PING,
                Vec::new(),
                &[MSG_PONG],
                Duration::from_millis(10),
            )
            .unwrap_err();
        assert!(matches!(err, DuplexError::ResourceLimit(_)));
        assert_eq!(a.metrics().pending_limit_rejections, 1);
        a.close();
    }

    #[test]
    fn hardened_unsolicited_queue_overflow_closes_peer() {
        let (a_raw, b_raw) = pair();
        let limits = DuplexLimits {
            max_unsolicited_frames: 1,
            max_frames_per_window: 100,
            max_bytes_per_window: 1024 * 1024,
            ..DuplexLimits::default()
        };
        let a = DuplexSession::from_authenticated_stream_with_limits(
            a_raw,
            P2P_MAGIC_DEVNET,
            false,
            limits,
        )
        .unwrap();
        let b = DuplexSession::from_authenticated_stream(b_raw, P2P_MAGIC_DEVNET, true).unwrap();
        b.send_unsolicited(MSG_BLOCK_ANNOUNCE, vec![1u8; 32])
            .unwrap();
        b.send_unsolicited(MSG_BLOCK_ANNOUNCE, vec![2u8; 32])
            .unwrap();
        for _ in 0..50 {
            if a.is_closed() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(a.is_closed());
        assert_eq!(a.metrics().unsolicited_overflow_closes, 1);
        b.close();
    }

    #[test]
    fn hardened_receive_rate_budget_closes_flooding_peer() {
        let (a_raw, b_raw) = pair();
        let limits = DuplexLimits {
            max_unsolicited_frames: 8,
            max_frames_per_window: 1,
            max_bytes_per_window: 1024 * 1024,
            rate_window: Duration::from_secs(10),
            ..DuplexLimits::default()
        };
        let a = DuplexSession::from_authenticated_stream_with_limits(
            a_raw,
            P2P_MAGIC_DEVNET,
            false,
            limits,
        )
        .unwrap();
        let b = DuplexSession::from_authenticated_stream(b_raw, P2P_MAGIC_DEVNET, true).unwrap();
        b.send_unsolicited(MSG_BLOCK_ANNOUNCE, vec![1u8; 32])
            .unwrap();
        b.send_unsolicited(MSG_BLOCK_ANNOUNCE, vec![2u8; 32])
            .unwrap();
        for _ in 0..50 {
            if a.is_closed() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(a.is_closed());
        assert_eq!(a.metrics().rate_limit_closes, 1);
        b.close();
    }
}
