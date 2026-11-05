//! Bounded ordered Wi-Fi/TCP frames for a completed Worker handshake.
//! Application messages still require independent typed/work validation.
use super::*;
use mutiny_crypto_v2::{PublicKey, enrollment::Binding};
use zeroize::Zeroize;
#[cfg(test)]
#[path = "worker_frames_c_tests.rs"]
mod c_tests;
#[cfg(test)]
#[path = "../../qualification/worker_finished_c_test_v1.rs"]
mod finished_c_tests;
pub const MAX_PAYLOAD: usize = 16 * 1024;
const HEADER: usize = 44;
pub const MAX_FRAME_BYTES: usize = HEADER + MAX_PAYLOAD + 16;
const MAX_FRAMES: u64 = 1 << 20;
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const LIFETIME: Duration = Duration::from_secs(3600);

/// Trusted current canonical state, supplied by the application actor for each
/// operation. This is not a self-authenticating network object.
pub struct Authority<'a> {
    pub binding: &'a Binding,
    pub node: &'a PublicKey,
    pub node_generation: u64,
    pub height: u64,
    pub epoch: u64,
}
pub struct Channel {
    confirmed: Confirmed,
    send_next: u64,
    receive_next: u64,
    tx_bytes: u64,
    rx_bytes: u64,
    valid: bool,
}
impl Confirmed {
    pub fn into_channel(self, current: &Authority<'_>) -> Result<Channel> {
        live(self.confirmed_at)?;
        let mut out = Channel {
            confirmed: self,
            send_next: 1,
            receive_next: 1,
            tx_bytes: 0,
            rx_bytes: 0,
            valid: true,
        };
        out.check(current)?;
        Ok(out)
    }
}
impl Channel {
    /// Trusted owner idle/pre-delivery gate. No frame or sequence consumption.
    /// Failure closes the channel and erases its traffic keys.
    pub fn validate_current(&mut self, current: &Authority<'_>) -> Result<()> {
        self.check(current)
    }
    pub fn close(&mut self) {
        self.valid = false;
        self.confirmed.keys.tx.zeroize();
        self.confirmed.keys.rx.zeroize();
    }
    fn check(&mut self, current: &Authority<'_>) -> Result<()> {
        if !self.valid {
            return Err(Error::Context);
        }
        if self.confirmed.confirmed_at.elapsed() >= LIFETIME {
            self.close();
            return Err(Error::Expired);
        }
        if !self.confirmed.matches_current(
            current.binding,
            current.node,
            current.node_generation,
            current.height,
            current.epoch,
        ) {
            self.close();
            return Err(Error::Context);
        }
        Ok(())
    }
    pub fn seal(&mut self, current: &Authority<'_>, payload: &[u8]) -> Result<Vec<u8>> {
        self.check(current)?;
        if payload.is_empty()
            || payload.len() > MAX_PAYLOAD
            || self.send_next > MAX_FRAMES
            || self
                .tx_bytes
                .checked_add(payload.len() as u64)
                .is_none_or(|v| v > MAX_BYTES)
        {
            self.close();
            return Err(Error::Limit);
        }
        let mut header = [0; HEADER];
        header[0] = 2;
        header[1] = u8::from(!self.confirmed.worker);
        header[2..34].copy_from_slice(&self.confirmed.keys.id);
        header[34..42].copy_from_slice(&self.send_next.to_be_bytes());
        header[42..].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        let mut nonce = [0; 12];
        nonce[..4].copy_from_slice(&self.confirmed.keys.tx_prefix);
        nonce[4..].copy_from_slice(&self.send_next.to_be_bytes());
        let mut aad = Vec::from(b"MUTINY-BUILD8-WORKER-SESSION-FRAME-V2\0".as_slice());
        aad.extend(header);
        let encrypted = match ChaCha20Poly1305::new(self.confirmed.keys.tx.as_ref().into()).encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: payload,
                aad: &aad,
            },
        ) {
            Ok(v) => v,
            Err(_) => {
                self.close();
                return Err(Error::Crypto);
            }
        };
        self.send_next += 1;
        self.tx_bytes += payload.len() as u64;
        let mut out = header.to_vec();
        out.extend(encrypted);
        Ok(out)
    }
    pub fn open(&mut self, current: &Authority<'_>, frame: &[u8]) -> Result<Vec<u8>> {
        self.check(current)?;
        let result = self.open_inner(frame);
        if result.is_err() {
            self.close();
        }
        result
    }
    fn open_inner(&mut self, frame: &[u8]) -> Result<Vec<u8>> {
        if frame.len() < HEADER + 17 || frame.len() > MAX_FRAME_BYTES {
            return Err(Error::Encoding);
        }
        let seq = u64::from_be_bytes(frame[34..42].try_into().unwrap());
        let n = usize::from(u16::from_be_bytes(frame[42..44].try_into().unwrap()));
        if frame[0] != 2
            || frame[1] != u8::from(self.confirmed.worker)
            || frame[2..34] != self.confirmed.keys.id
            || seq != self.receive_next
            || seq > MAX_FRAMES
        {
            return Err(Error::Replay);
        }
        if n == 0
            || n > MAX_PAYLOAD
            || frame.len() != HEADER + n + 16
            || self
                .rx_bytes
                .checked_add(n as u64)
                .is_none_or(|v| v > MAX_BYTES)
        {
            return Err(Error::Limit);
        }
        let mut nonce = [0; 12];
        nonce[..4].copy_from_slice(&self.confirmed.keys.rx_prefix);
        nonce[4..].copy_from_slice(&seq.to_be_bytes());
        let mut aad = Vec::from(b"MUTINY-BUILD8-WORKER-SESSION-FRAME-V2\0".as_slice());
        aad.extend(&frame[..HEADER]);
        let plain = ChaCha20Poly1305::new(self.confirmed.keys.rx.as_ref().into())
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &frame[HEADER..],
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?;
        self.receive_next += 1;
        self.rx_bytes += n as u64;
        Ok(plain)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_constant_frame_vectors_cover_payload_bounds() {
        let (c, b, node, _) = super::super::tests::fixture();
        let current = authority(&b, node.public());
        // Public fixed schedule inputs only; not exported handshake secrets.
        let confirmed = Confirmed {
            context: c,
            keys: derive(&[1; 56], &[2; 32], &[3; 64], true).unwrap(),
            worker: true,
            confirmed_at: Instant::now(),
        };
        let mut channel = confirmed.into_channel(&current).unwrap();
        let mut cases = Vec::new();
        for n in [1, 255, 8192, MAX_PAYLOAD] {
            let plain: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            let frame = channel.seal(&current, &plain).unwrap();
            cases.push(
                serde_json::json!({"plaintext":hex::encode(plain),"frame":hex::encode(frame)}),
            );
        }
        if let Ok(path) = std::env::var("BUILD8_PUBLIC_WORKER_FRAME_VECTOR") {
            let vector = serde_json::json!({"synthetic_only":true,"public_constants_only":true,
                "production_authorized":false,"x":hex::encode([1;56]),"kem":hex::encode([2;32]),
                "transcript":hex::encode([3;64]),"cases":cases});
            use std::io::Write;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .unwrap()
                .write_all(serde_json::to_string_pretty(&vector).unwrap().as_bytes())
                .unwrap();
        }
    }
    fn pair() -> (Channel, Channel, Binding, PublicKey) {
        let (c, b, node, mut device) = super::super::tests::fixture();
        let (worker, hello) = WorkerPending::start(c.clone(), &device).unwrap();
        let (pending, response) = NodePending::accept(c, &node, &hello).unwrap();
        let (confirm, finish) = worker.accept(&mut device, &response).unwrap();
        let (node_confirm, tag) = pending.finish(&finish).unwrap();
        let worker_confirm = confirm.finish(&tag).unwrap();
        let p = node.public().clone();
        let current = authority(&b, &p);
        (
            worker_confirm.into_channel(&current).unwrap(),
            node_confirm.into_channel(&current).unwrap(),
            b,
            p,
        )
    }
    fn authority<'a>(b: &'a Binding, p: &'a PublicKey) -> Authority<'a> {
        Authority {
            binding: b,
            node: p,
            node_generation: 1,
            height: 1,
            epoch: 0,
        }
    }
    #[test]
    fn ordered_bidirectional_frames_and_replay_close_without_plaintext() {
        let (mut a, mut b, binding, node) = pair();
        let current = authority(&binding, &node);
        let frame = a.seal(&current, b"public work request").unwrap();
        assert_eq!(b.open(&current, &frame).unwrap(), b"public work request");
        let reply = b.seal(&current, &vec![5; MAX_PAYLOAD]).unwrap();
        assert_eq!(reply.len(), MAX_FRAME_BYTES);
        assert_eq!(a.open(&current, &reply).unwrap(), vec![5; MAX_PAYLOAD]);
        assert!(b.open(&current, &frame).is_err());
        assert!(!b.valid);
        assert!(
            b.confirmed.keys.tx.iter().all(|x| *x == 0)
                && b.confirmed.keys.rx.iter().all(|x| *x == 0)
        );
        assert!(b.seal(&current, b"after replay").is_err());
    }
    #[test]
    fn malformed_frames_wrong_context_and_changed_authority_fail_closed() {
        for index in [0, 1, 2, 34, 42, 44, 60] {
            let (mut a, mut b, binding, node) = pair();
            let current = authority(&binding, &node);
            let mut frame = a.seal(&current, b"public payload").unwrap();
            frame[index] ^= 1;
            assert!(b.open(&current, &frame).is_err());
            assert!(!b.valid);
            assert_eq!((b.receive_next, b.rx_bytes), (1, 0));
        }
        let (mut a, mut b, mut binding, node) = pair();
        let frame = a.seal(&authority(&binding, &node), b"public").unwrap();
        binding.assignment_generation += 1;
        assert!(b.open(&authority(&binding, &node), &frame).is_err());
        assert!(
            a.seal(&authority(&binding, &node), b"stale binding")
                .is_err()
        );
    }
    #[test]
    fn exact_rekey_limits_expiry_and_no_counter_wrap() {
        let (mut a, _, binding, node) = pair();
        a.confirmed.confirmed_at = Instant::now() - MAX_LIFETIME;
        assert!(
            a.confirmed
                .into_channel(&authority(&binding, &node))
                .is_err()
        );
        let (mut a, mut b, binding, node) = pair();
        let current = authority(&binding, &node);
        a.send_next = MAX_FRAMES;
        b.receive_next = MAX_FRAMES;
        let frame = a.seal(&current, b"last").unwrap();
        assert_eq!(b.open(&current, &frame).unwrap(), b"last");
        assert!(a.seal(&current, b"exhausted").is_err());
        let (mut a, mut b, binding, node) = pair();
        let current = authority(&binding, &node);
        a.tx_bytes = MAX_BYTES - 1;
        b.rx_bytes = MAX_BYTES - 1;
        let frame = a.seal(&current, b"x").unwrap();
        assert!(b.open(&current, &frame).is_ok());
        assert!(a.seal(&current, b"x").is_err());
        let (mut a, mut b, binding, node) = pair();
        let current = authority(&binding, &node);
        let frame = a.seal(&current, b"x").unwrap();
        b.confirmed.confirmed_at = Instant::now() - LIFETIME;
        assert!(matches!(b.open(&current, &frame), Err(Error::Expired)));
        a.send_next = u64::MAX;
        assert!(a.seal(&current, b"x").is_err());
    }
}
