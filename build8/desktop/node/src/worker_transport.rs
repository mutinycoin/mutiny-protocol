//! TCP carrier for Wi-Fi Workers. Binding lookup must use current canonical
//! state, checking activation, reassignment, and node coordinator authority.
use ed25519_dalek::SigningKey;
use mutiny_consensus_v8::{
    Hash,
    licenses::BindWorker,
    worker_session::{FRAME_HEADER_BYTES, FrameChannel, MAX_FRAME_PAYLOAD, PendingSession, Role},
};
use std::{
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, String>;
const IO_DEADLINE: Duration = Duration::from_secs(5);
pub const HELLO_BYTES: usize = 65;

// A total deadline, not five seconds per byte: slow fragmented messages cannot
// keep a connection slot occupied forever by resetting read_exact's timeout.
fn read_until(stream: &mut TcpStream, mut out: &mut [u8], deadline: Instant) -> Result<()> {
    while !out.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|x| !x.is_zero())
            .ok_or("Worker read deadline")?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|e| e.to_string())?;
        match stream.read(out) {
            Ok(0) => return Err("Worker disconnected".into()),
            Ok(n) => out = &mut out[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

fn write_until(stream: &mut TcpStream, mut raw: &[u8], deadline: Instant) -> Result<()> {
    while !raw.is_empty() {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|x| !x.is_zero())
            .ok_or("Worker write deadline")?;
        stream
            .set_write_timeout(Some(remaining))
            .map_err(|e| e.to_string())?;
        match stream.write(raw) {
            Ok(0) => return Err("Worker disconnected".into()),
            Ok(n) => raw = &raw[n..],
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}
pub struct CoordinatorConnection {
    stream: TcpStream,
    signer: SigningKey,
    worker: Hash,
    channel: FrameChannel,
    closed: bool,
}
impl CoordinatorConnection {
    /// The listener must bound concurrent connections before calling this.
    /// `active` must reject unknown/inactive/reassigned canonical Workers.
    pub fn accept(
        mut stream: TcpStream,
        signer: SigningKey,
        mut active: impl FnMut(Hash) -> Result<BindWorker>,
    ) -> Result<Self> {
        let deadline = Instant::now() + IO_DEADLINE;
        let mut hello = [0; HELLO_BYTES];
        read_until(&mut stream, &mut hello, deadline)?;
        if hello[0] != 1 {
            return Err("Worker Hello version".into());
        }
        let worker: Hash = hello[1..33].try_into().map_err(|_| "Worker identity")?;
        let nonce: Hash = hello[33..65].try_into().map_err(|_| "Worker nonce")?;
        let binding = active(worker)?;
        if binding.worker != worker {
            return Err("Worker lookup mismatch".into());
        }
        let mut server_nonce = [0; 32];
        getrandom::getrandom(&mut server_nonce).map_err(|e| e.to_string())?;
        let mut pending = PendingSession::issue(&binding, &signer, nonce, server_nonce)
            .map_err(|e| format!("Worker handshake: {e:?}"))?;
        let (raw, signature) = pending.challenge();
        let mut challenge = Vec::with_capacity(raw.len() + signature.len());
        challenge.extend(raw);
        challenge.extend(signature);
        write_until(&mut stream, &challenge, deadline)?;
        let mut possession = [0; 64];
        read_until(&mut stream, &mut possession, deadline)?;
        let current = active(worker)?;
        let session = pending
            .finish(&current, possession)
            .map_err(|e| format!("Worker possession: {e:?}"))?;
        Ok(Self {
            stream,
            signer,
            worker,
            channel: FrameChannel::new(session, Role::Coordinator),
            closed: false,
        })
    }
    pub fn worker(&self) -> Hash {
        self.worker
    }
    fn check(&mut self, current: &BindWorker) -> Result<()> {
        if self.closed || !self.channel.authorizes(current) {
            self.close();
            return Err("Worker session no longer authorized".into());
        }
        Ok(())
    }
    fn close(&mut self) {
        self.closed = true;
        let _ = self.stream.shutdown(Shutdown::Both);
    }
    pub fn send(&mut self, current: &BindWorker, payload: &[u8]) -> Result<()> {
        self.check(current)?;
        let result = self
            .channel
            .send(&self.signer, payload)
            .map_err(|e| format!("Worker frame: {e:?}"))
            .and_then(|raw| write_until(&mut self.stream, &raw, Instant::now() + IO_DEADLINE));
        if result.is_err() {
            self.close();
        }
        result
    }
    pub fn receive(
        &mut self,
        mut active: impl FnMut(Hash) -> Result<BindWorker>,
    ) -> Result<Vec<u8>> {
        let result = (|| {
            self.check(&active(self.worker)?)?;
            let deadline = Instant::now() + IO_DEADLINE;
            let mut header = [0; FRAME_HEADER_BYTES];
            read_until(&mut self.stream, &mut header, deadline)?;
            let n = u16::from_be_bytes([header[42], header[43]]) as usize;
            if n == 0 || n > MAX_FRAME_PAYLOAD {
                return Err("Worker frame bound".into());
            }
            let mut raw = vec![0; FRAME_HEADER_BYTES + n + 64];
            raw[..FRAME_HEADER_BYTES].copy_from_slice(&header);
            read_until(&mut self.stream, &mut raw[FRAME_HEADER_BYTES..], deadline)?;
            // A state change during socket I/O must invalidate this message.
            self.check(&active(self.worker)?)?;
            self.channel
                .receive(&raw)
                .map(|p| p.to_vec())
                .map_err(|e| format!("Worker frame: {e:?}"))
        })();
        if result.is_err() {
            self.close();
        }
        result
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Signer, VerifyingKey};
    use mutiny_consensus_v8::worker_session::{coordinator_digest, transcript, worker_digest};
    use std::net::TcpListener;

    pub(crate) fn binding() -> BindWorker {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/GENESIS-BINDING-VECTORS-STATE-V2.json"
        ))
        .unwrap();
        BindWorker::decode(
            &hex::decode(
                fixture["cases"][0]["bindings"][0]["binding_hex"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap(),
        )
        .unwrap()
    }
    pub(crate) fn connect(
        addr: std::net::SocketAddr,
        binding: &BindWorker,
    ) -> (TcpStream, FrameChannel) {
        let mut stream = TcpStream::connect(addr).unwrap();
        let worker = SigningKey::from_bytes(&[10; 32]);
        let coordinator = SigningKey::from_bytes(&[90; 32]);
        let nonce = [27; 32];
        let mut hello = vec![1];
        hello.extend(binding.worker);
        hello.extend(nonce);
        // Deliberately fragmented TCP delivery.
        for byte in hello {
            stream.write_all(&[byte]).unwrap();
        }
        let mut challenge = [0; 301];
        read_until(&mut stream, &mut challenge, Instant::now() + IO_DEADLINE).unwrap();
        let remote_nonce = challenge[205..237].try_into().unwrap();
        let raw = transcript(binding, nonce, remote_nonce).unwrap();
        assert_eq!(challenge[..237], raw);
        VerifyingKey::from_bytes(&binding.coordinator_public)
            .unwrap()
            .verify_strict(
                &coordinator_digest(&raw),
                &Signature::from_slice(&challenge[237..]).unwrap(),
            )
            .unwrap();
        let proof = worker.sign(&worker_digest(&raw)).to_bytes();
        stream.write_all(&proof).unwrap();
        // Fixture-only construction of a client channel after independently
        // validating the actual server challenge; no production key export.
        let mut pending =
            PendingSession::issue(binding, &coordinator, nonce, remote_nonce).unwrap();
        let session = pending.finish(binding, proof).unwrap();
        (stream, FrameChannel::new(session, Role::Worker))
    }
    pub(crate) fn receive(stream: &mut TcpStream, channel: &mut FrameChannel) -> Vec<u8> {
        let mut header = [0; 44];
        let deadline = Instant::now() + IO_DEADLINE;
        read_until(stream, &mut header, deadline).unwrap();
        let n = u16::from_be_bytes([header[42], header[43]]) as usize;
        assert!(n <= MAX_FRAME_PAYLOAD);
        let mut raw = vec![0; 44 + n + 64];
        raw[..44].copy_from_slice(&header);
        read_until(stream, &mut raw[44..], deadline).unwrap();
        channel.receive(&raw).unwrap().to_vec()
    }
    #[test]
    fn live_worker_session_fragmentation_replay_and_binding_change() {
        for change_binding in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = listener.local_addr().unwrap();
            let b = binding();
            let server_binding = b.clone();
            let server = std::thread::spawn(move || {
                let (stream, _) = listener.accept().unwrap();
                let mut c = CoordinatorConnection::accept(
                    stream,
                    SigningKey::from_bytes(&[90; 32]),
                    |_| Ok(server_binding.clone()),
                )
                .unwrap();
                assert_eq!(c.worker(), server_binding.worker);
                c.send(&server_binding, b"ready").unwrap();
                assert_eq!(
                    c.receive(|_| Ok(server_binding.clone())).unwrap(),
                    b"result"
                );
                c.send(&server_binding, b"receipt").unwrap();
                let mut updated = server_binding.clone();
                if change_binding {
                    updated.sequence += 1;
                }
                assert!(c.receive(|_| Ok(updated.clone())).is_err());
                assert!(c.closed);
                assert!(c.send(&server_binding, b"after failure").is_err());
            });
            let (mut stream, mut c) = connect(addr, &b);
            assert_eq!(receive(&mut stream, &mut c), b"ready");
            let result = c
                .send(&SigningKey::from_bytes(&[10; 32]), b"result")
                .unwrap();
            stream.write_all(&result).unwrap();
            assert_eq!(receive(&mut stream, &mut c), b"receipt");
            if !change_binding {
                stream.write_all(&result).unwrap();
            }
            server.join().unwrap();
        }
    }
    #[test]
    fn unknown_worker_and_total_io_deadline_fail_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            assert!(read_until(&mut stream, &mut [0; 1], Instant::now()).is_err());
            let called = std::cell::Cell::new(0);
            assert!(
                CoordinatorConnection::accept(stream, SigningKey::from_bytes(&[90; 32]), |_| {
                    called.set(called.get() + 1);
                    Err("not canonical".into())
                })
                .is_err()
            );
            assert_eq!(called.get(), 1);
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        let mut hello = [1; 65];
        hello[33..].fill(27);
        stream.write_all(&hello).unwrap();
        server.join().unwrap();
    }
}
