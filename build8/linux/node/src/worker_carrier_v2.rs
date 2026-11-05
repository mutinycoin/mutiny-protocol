//! Single-owner bounded carrier for an already confirmed canonical Worker channel.
//! No listener, handshake admission, reconnect, or mining authorization.
use crate::{hybrid_coordinator_v2::Clock, worker_current_channel_v2::CanonicalWorkerChannel};
use mutiny_consensus_v8::{anchors::FinalizedAnchor, canonical_store_v2::CanonicalStore};
use mutiny_transport_v2::{
    Error, Result,
    worker_handshake_v2::{MAX_FRAME_BYTES, MAX_PAYLOAD},
};
use std::{
    io::{ErrorKind, Read, Write},
    net::{Shutdown, TcpStream},
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

const HEADER: usize = 44;
// Node host batching: bounds one syscall while amortizing authenticated-state
// checks. The ESP32 peer keeps its independent smaller read/write chunk limit.
const IO_CHUNK: usize = 4096;
const IO_LIMIT: Duration = Duration::from_secs(5);

/// Trusted nonblocking local I/O adapter. A call may transfer at most its supplied
/// slice length. Implementations must not wait internally or change ownership.
pub trait NonblockingIo: Read + Write {
    fn close(&mut self);
}
pub struct Socket(TcpStream);
impl Socket {
    pub fn connected(stream: TcpStream) -> std::io::Result<Self> {
        stream.peer_addr()?;
        stream.set_nonblocking(true)?;
        Ok(Self(stream))
    }
}
impl Read for Socket {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(bytes)
    }
}
impl Write for Socket {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
impl NonblockingIo for Socket {
    fn close(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }
}

pub struct Carrier<I: NonblockingIo> {
    io: I,
    channel: CanonicalWorkerChannel,
    input: Vec<u8>,
    used: usize,
    expected: usize,
    receiving_since: Option<Instant>,
    output: Option<(Vec<u8>, usize, Instant)>,
    prefer_read: bool,
    closed: bool,
    #[cfg(test)]
    test_time: Option<std::sync::Arc<std::sync::Mutex<Instant>>>,
}
impl<I: NonblockingIo> Carrier<I> {
    pub(crate) fn scope(&self) -> Result<crate::worker_protocol_v2::Scope> {
        if self.closed {
            return Err(Error::Context);
        }
        self.channel.scope()
    }
    pub(crate) fn worker_identity(&self) -> Result<mutiny_consensus_v8::Hash> {
        if self.closed {
            return Err(Error::Context);
        }
        self.channel.worker_identity()
    }
    pub fn new(io: I, channel: CanonicalWorkerChannel) -> Self {
        Self {
            io,
            channel,
            input: vec![0; MAX_FRAME_BYTES],
            used: 0,
            expected: HEADER,
            receiving_since: None,
            output: None,
            prefer_read: true,
            closed: false,
            #[cfg(test)]
            test_time: None,
        }
    }
    // Deterministic test clock. Every shipping build uses Instant::now and the
    // unchanged IO_LIMIT; this seam is absent from non-test artifacts.
    #[cfg(test)]
    pub(crate) fn new_with_test_clock(io: I, channel: CanonicalWorkerChannel,
        time: std::sync::Arc<std::sync::Mutex<Instant>>) -> Self {
        let mut carrier = Self::new(io, channel);
        carrier.test_time = Some(time);
        carrier
    }
    fn instant(&self) -> Instant {
        #[cfg(test)]
        if let Some(time) = &self.test_time { return *time.lock().unwrap(); }
        Instant::now()
    }
    pub fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        self.channel.close();
        self.input.zeroize();
        self.output = None;
        self.used = 0;
        self.expected = HEADER;
        self.receiving_since = None;
        self.io.close();
    }
    fn deadlines(&self) -> Result<()> {
        let now = self.instant();
        if self.closed {
            return Err(Error::Context);
        }
        if self
            .receiving_since
            .is_some_and(|s| now.duration_since(s) >= IO_LIMIT)
            || self
                .output
                .as_ref()
                .is_some_and(|(_, _, deadline)| now >= *deadline)
        {
            return Err(Error::Expired);
        }
        Ok(())
    }
    pub(crate) fn check(
        &mut self,
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        clock: &mut impl Clock,
    ) -> Result<()> {
        self.deadlines()?;
        self.channel.check(chain, parent, clock)?;
        self.deadlines()
    }
    /// One queued frame. A full queue returns false without consuming a channel
    /// sequence. Caller retains its typed message and must revalidate before retry.
    /// `valid_until` is a trusted local application deadline, not packet data;
    /// mining work must use its original request/epoch/liveness deadline.
    pub fn queue(
        &mut self,
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        clock: &mut impl Clock,
        payload: &[u8],
        valid_until: Instant,
    ) -> Result<bool> {
        let result = (|| {
            self.check(chain, parent, clock)?;
            if self.output.is_some() {
                return Ok(false);
            }
            let deadline = valid_until.min(self.instant() + IO_LIMIT);
            if self.instant() >= deadline {
                return Err(Error::Expired);
            }
            let frame = self.channel.seal(chain, parent, clock, payload)?;
            self.output = Some((frame, 0, deadline));
            self.check(chain, parent, clock)?;
            Ok(true)
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
    /// At most one nonblocking read OR write of at most4096 bytes and one
    /// authenticated plaintext event. Short I/O never resets a frame deadline.
    /// The owner calls this while idle too, and processes returned bytes with
    /// the separate bounded application codec and current work authority.
    pub fn step(
        &mut self,
        chain: &CanonicalStore,
        parent: &FinalizedAnchor,
        clock: &mut impl Clock,
    ) -> Result<Option<Vec<u8>>> {
        let result = (|| {
            self.check(chain, parent, clock)?;
            if self.output.is_some() && !self.prefer_read {
                self.prefer_read = true;
                let (frame, offset, _) = self.output.as_mut().ok_or(Error::Context)?;
                let count = IO_CHUNK.min(frame.len() - *offset);
                match self.io.write(&frame[*offset..*offset + count]) {
                    Ok(n) if n > 0 && n <= count => {
                        *offset += n;
                    }
                    Err(e)
                        if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
                    _ => return Err(Error::Context),
                }
                self.check(chain, parent, clock)?;
                if self.output.as_ref().is_some_and(|(v, n, _)| *n == v.len()) {
                    self.output = None;
                }
                return Ok(None);
            }
            self.prefer_read = false;
            let count = IO_CHUNK.min(self.expected - self.used);
            let read_started = self.instant();
            match self.io.read(&mut self.input[self.used..self.used + count]) {
                Ok(n) if n > 0 && n <= count => {
                    if self.used == 0 {
                        self.receiving_since = Some(read_started);
                    }
                    self.used += n;
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {}
                _ => return Err(Error::Context),
            }
            self.check(chain, parent, clock)?;
            if self.used == HEADER && self.expected == HEADER {
                let n = u16::from_be_bytes([self.input[42], self.input[43]]) as usize;
                if n == 0 || n > MAX_PAYLOAD {
                    return Err(Error::Limit);
                }
                self.expected = HEADER + n + 16;
            }
            if self.used != self.expected {
                return Ok(None);
            }
            let mut plain = Zeroizing::new(self.channel.open(
                chain,
                parent,
                clock,
                &self.input[..self.used],
            )?);
            self.check(chain, parent, clock)?;
            self.input[..self.used].zeroize();
            self.used = 0;
            self.expected = HEADER;
            self.receiving_since = None;
            Ok(Some(std::mem::take(&mut *plain)))
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}
impl<I: NonblockingIo> Drop for Carrier<I> {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn connected_socket_is_nonblocking_and_observes_peer_eof() {
        let listener = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        drop(listener);
        let mut socket = Socket::connected(server).unwrap();
        let mut bytes = [0; 2];
        assert_eq!(
            socket.read(&mut bytes).unwrap_err().kind(),
            ErrorKind::WouldBlock
        );
        client.write_all(&[3, 4, 5]).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut got = Vec::new();
        while got.len() < 3 {
            assert!(Instant::now() < deadline);
            match socket.read(&mut bytes) {
                Ok(n) if n > 0 => got.extend_from_slice(&bytes[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => std::thread::yield_now(),
                r => panic!("socket read {r:?}"),
            }
        }
        assert_eq!(got, [3, 4, 5]);
        drop(client);
        loop {
            assert!(Instant::now() < deadline);
            match socket.read(&mut bytes) {
                Ok(0) => break,
                Err(e) if e.kind() == ErrorKind::WouldBlock => std::thread::yield_now(),
                r => panic!("peer EOF {r:?}"),
            }
        }
        socket.close();
    }
}
