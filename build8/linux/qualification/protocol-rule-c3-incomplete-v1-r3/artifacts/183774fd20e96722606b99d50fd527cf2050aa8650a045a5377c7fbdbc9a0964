//! Bounded mutually authenticated transport. This authenticates peer bytes only;
//! canonical execution and certificates still decide whether a block is valid.
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use minicbor::{Decoder, Encoder};
use mutiny_consensus_v8::{Hash, NETWORK_ID, domain_hash};
use std::io::{Read, Write};
pub const MAX_FRAME: usize = 1024 * 1024;
type Result<T> = std::result::Result<T, String>;
fn h(d: &mut Decoder<'_>) -> Result<Hash> {
    d.bytes()
        .map_err(|_| "bytes")?
        .try_into()
        .map_err(|_| "hash length".into())
}
fn frame_read(io: &mut impl Read) -> Result<Vec<u8>> {
    let mut n = [0; 4];
    io.read_exact(&mut n).map_err(|e| e.to_string())?;
    let n = u32::from_be_bytes(n) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err("peer frame bound".into());
    }
    let mut b = vec![0; n];
    io.read_exact(&mut b).map_err(|e| e.to_string())?;
    Ok(b)
}
fn frame_write(io: &mut impl Write, b: &[u8]) -> Result<()> {
    if b.is_empty() || b.len() > MAX_FRAME {
        return Err("peer frame bound".into());
    }
    io.write_all(&(b.len() as u32).to_be_bytes())
        .and_then(|_| io.write_all(b))
        .and_then(|_| io.flush())
        .map_err(|e| e.to_string())
}
#[derive(Clone)]
struct Hello {
    genesis: Hash,
    fingerprint: Hash,
    key: Hash,
    nonce: Hash,
}
impl Hello {
    fn encode(&self) -> Vec<u8> {
        let mut e = Encoder::new(Vec::new());
        e.array(6)
            .unwrap()
            .u8(1)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .bytes(&self.key)
            .unwrap()
            .bytes(&self.nonce)
            .unwrap();
        e.into_writer()
    }
    fn decode(raw: &[u8]) -> Result<Self> {
        if raw.len() > 256 {
            return Err("hello bound".into());
        }
        let mut d = Decoder::new(raw);
        if d.array().map_err(|_| "array")? != Some(6)
            || d.u8().map_err(|_| "version")? != 1
            || d.u32().map_err(|_| "network")? != NETWORK_ID
        {
            return Err("peer context".into());
        }
        let x = Self {
            genesis: h(&mut d)?,
            fingerprint: h(&mut d)?,
            key: h(&mut d)?,
            nonce: h(&mut d)?,
        };
        if x.nonce == [0; 32] || x.encode() != raw {
            return Err("noncanonical hello".into());
        }
        Ok(x)
    }
}
pub struct Session {
    context: Hash,
    key: SigningKey,
    remote: VerifyingKey,
    initiator: bool,
    send: u64,
    receive: u64,
    poisoned: bool,
}
impl Session {
    /// Exact peer key is configured independently; never trust a self-asserted
    /// key merely because its handshake signature verifies.
    pub fn handshake(
        io: &mut (impl Read + Write),
        key: SigningKey,
        remote: Hash,
        genesis: Hash,
        fingerprint: Hash,
        initiator: bool,
    ) -> Result<Self> {
        Self::handshake_pinned(io, key, &[remote], genesis, fingerprint, initiator)
            .map(|(session, _)| session)
    }
    /// The allowlist is local configuration, not data asserted by the peer.
    /// Returns the authenticated identity for duplicate-session accounting.
    pub fn handshake_pinned(
        io: &mut (impl Read + Write),
        key: SigningKey,
        allowed: &[Hash],
        genesis: Hash,
        fingerprint: Hash,
        initiator: bool,
    ) -> Result<(Self, Hash)> {
        if allowed.is_empty() || allowed.len() > 1024 {
            return Err("Peer allowlist bound".into());
        }
        let mut nonce = [0; 32];
        getrandom::getrandom(&mut nonce).map_err(|_| "OS entropy unavailable")?;
        let local = Hello {
            genesis,
            fingerprint,
            key: key.verifying_key().to_bytes(),
            nonce,
        };
        if allowed.contains(&local.key) {
            return Err("peer reflection".into());
        }
        let theirs = if initiator {
            frame_write(io, &local.encode())?;
            Hello::decode(&frame_read(io)?)?
        } else {
            let other = Hello::decode(&frame_read(io)?)?;
            frame_write(io, &local.encode())?;
            other
        };
        if theirs.genesis != genesis
            || theirs.fingerprint != fingerprint
            || !allowed.contains(&theirs.key)
            || theirs.nonce == local.nonce
        {
            return Err("pinned peer/context mismatch".into());
        }
        let remote_key = theirs.key;
        let (a, b) = if initiator {
            (&local, &theirs)
        } else {
            (&theirs, &local)
        };
        let mut e = Encoder::new(Vec::new());
        e.array(2)
            .unwrap()
            .bytes(&a.encode())
            .unwrap()
            .bytes(&b.encode())
            .unwrap();
        let context = domain_hash(b"MUTINY-BUILD8-PEER-HANDSHAKE-V1", &e.into_writer());
        let remote = VerifyingKey::from_bytes(&remote_key).map_err(|_| "peer key")?;
        let proof = |role: bool| {
            let mut bytes = context.to_vec();
            bytes.push(u8::from(role));
            domain_hash(b"MUTINY-BUILD8-PEER-POSSESSION-V1", &bytes)
        };
        let signature = key.sign(&proof(initiator)).to_bytes();
        let theirs = if initiator {
            frame_write(io, &signature)?;
            frame_read(io)?
        } else {
            let s = frame_read(io)?;
            frame_write(io, &signature)?;
            s
        };
        remote
            .verify_strict(
                &proof(!initiator),
                &Signature::from_slice(&theirs).map_err(|_| "signature length")?,
            )
            .map_err(|_| "peer possession")?;
        Ok((
            Self {
                context,
                key,
                remote,
                initiator,
                send: 0,
                receive: 0,
                poisoned: false,
            },
            remote_key,
        ))
    }
    fn digest(&self, role: bool, sequence: u64, payload: &[u8]) -> Hash {
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .bytes(&self.context)
            .unwrap()
            .bool(role)
            .unwrap()
            .u64(sequence)
            .unwrap()
            .bytes(payload)
            .unwrap();
        domain_hash(b"MUTINY-BUILD8-PEER-FRAME-V1", &e.into_writer())
    }
    pub fn send(&mut self, io: &mut impl Write, payload: &[u8]) -> Result<()> {
        if self.poisoned || payload.len() > MAX_FRAME - 128 {
            return Err("peer session unavailable/frame bound".into());
        }
        self.poisoned = true;
        let signature = self
            .key
            .sign(&self.digest(self.initiator, self.send, payload));
        let mut e = Encoder::new(Vec::new());
        e.array(3)
            .unwrap()
            .u64(self.send)
            .unwrap()
            .bytes(payload)
            .unwrap()
            .bytes(&signature.to_bytes())
            .unwrap();
        frame_write(io, &e.into_writer())?;
        self.send = self.send.checked_add(1).ok_or("sequence exhausted")?;
        self.poisoned = false;
        Ok(())
    }
    pub fn receive(&mut self, io: &mut impl Read) -> Result<Vec<u8>> {
        if self.poisoned {
            return Err("peer session unavailable".into());
        }
        self.poisoned = true;
        let raw = frame_read(io)?;
        let mut d = Decoder::new(&raw);
        if d.array().map_err(|_| "array")? != Some(3)
            || d.u64().map_err(|_| "sequence")? != self.receive
        {
            return Err("replayed/out-of-order frame".into());
        }
        let payload = d.bytes().map_err(|_| "payload")?;
        if payload.len() > MAX_FRAME - 128 {
            return Err("payload bound".into());
        }
        let signature = d.bytes().map_err(|_| "signature")?;
        let mut e = Encoder::new(Vec::new());
        e.array(3)
            .unwrap()
            .u64(self.receive)
            .unwrap()
            .bytes(payload)
            .unwrap()
            .bytes(signature)
            .unwrap();
        if e.into_writer() != raw {
            return Err("noncanonical frame".into());
        }
        self.remote
            .verify_strict(
                &self.digest(!self.initiator, self.receive, payload),
                &Signature::from_slice(signature).map_err(|_| "signature")?,
            )
            .map_err(|_| "frame authentication")?;
        self.receive = self.receive.checked_add(1).ok_or("sequence exhausted")?;
        self.poisoned = false;
        Ok(payload.to_vec())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};
    #[test]
    fn live_handshake_authenticated_frames_and_replay_poisoning() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let a = SigningKey::from_bytes(&[61; 32]);
        let b = SigningKey::from_bytes(&[62; 32]);
        let ap = a.verifying_key().to_bytes();
        let bp = b.verifying_key().to_bytes();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            let mut s = Session::handshake(&mut stream, b, ap, [1; 32], [2; 32], false).unwrap();
            assert_eq!(s.receive(&mut stream).unwrap(), b"canonical block");
            s.send(&mut stream, b"validated").unwrap();
            assert!(s.receive(&mut stream).is_err());
            assert!(s.poisoned);
        });
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut s = Session::handshake(&mut stream, a, bp, [1; 32], [2; 32], true).unwrap();
        let mut wire = Vec::new();
        s.send(&mut wire, b"canonical block").unwrap();
        stream.write_all(&wire).unwrap();
        assert_eq!(s.receive(&mut stream).unwrap(), b"validated");
        stream.write_all(&wire).unwrap();
        server.join().unwrap();
    }
    #[test]
    fn tamper_direction_cross_session_and_oversize_fail_closed() {
        let a = SigningKey::from_bytes(&[61; 32]);
        let b = SigningKey::from_bytes(&[62; 32]);
        let make = |context, initiator, key: SigningKey, remote| Session {
            context,
            key,
            remote,
            initiator,
            send: 0,
            receive: 0,
            poisoned: false,
        };
        let mut sender = make([3; 32], true, a.clone(), b.verifying_key());
        let mut wire = Vec::new();
        sender.send(&mut wire, b"block").unwrap();
        for (context, direction, mut frame) in [
            ([4; 32], false, wire.clone()),
            ([3; 32], true, wire.clone()),
            ([3; 32], false, wire.clone()),
        ] {
            if context == [3; 32] && !direction {
                *frame.last_mut().unwrap() ^= 1;
            }
            let mut receiver = make(context, direction, b.clone(), a.verifying_key());
            assert!(receiver.receive(&mut frame.as_slice()).is_err());
            assert!(receiver.poisoned);
        }
        assert!(frame_read(&mut ((MAX_FRAME + 1) as u32).to_be_bytes().as_slice()).is_err());
        let mut bad = Hello {
            genesis: [1; 32],
            fingerprint: [2; 32],
            key: [3; 32],
            nonce: [0; 32],
        }
        .encode();
        assert!(Hello::decode(&bad).is_err());
        bad.push(0);
        assert!(Hello::decode(&bad).is_err());
    }
}
