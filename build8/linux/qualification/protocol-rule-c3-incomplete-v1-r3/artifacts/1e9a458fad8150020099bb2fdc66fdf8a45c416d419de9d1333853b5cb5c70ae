use crate::{
    Error, Result,
    primitives::{Kem, X448, encapsulate, random},
};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, NETWORK, PublicKey, Role};
use sha2::{Digest, Sha256, Sha512};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const CONTEXT_LEN: usize = 166;
pub const HELLO_LEN: usize = CONTEXT_LEN + 32 + 56 + 1568;
pub const RESPONSE_LEN: usize = 32 + 56 + 1568 + 1394;
pub const CLIENT_FINISH_LEN: usize = 1394 + 16;
const HANDSHAKE_LIFETIME: Duration = Duration::from_secs(600);

#[derive(Clone)]
pub struct Endpoint {
    public: PublicKey,
    generation: u64,
    id: [u8; 32],
}
impl Endpoint {
    /// The caller must obtain this descriptor through independent trusted provisioning.
    /// A self-supplied peer descriptor is never a trust source.
    pub fn pinned(public: PublicKey, generation: u64) -> Result<Self> {
        if public.role != Role::Transport || generation == 0 {
            return Err(Error::Context);
        }
        let desc = public.descriptor(generation).map_err(|_| Error::Crypto)?;
        let mut h = Sha256::new();
        h.update(b"MUTINY-BUILD8-TRANSPORT-IDENTITY-V2\0");
        h.update(desc);
        Ok(Self {
            public,
            generation,
            id: h.finalize().into(),
        })
    }
    pub fn id(&self) -> [u8; 32] {
        self.id
    }
}
#[derive(Clone)]
pub struct Context {
    pub(crate) bytes: [u8; CONTEXT_LEN],
    initiator: Endpoint,
    responder: Endpoint,
    pub(crate) tag: [u8; 16],
}
impl Context {
    pub(crate) fn initiator_id(&self) -> [u8; 32] {
        self.initiator.id
    }
    pub(crate) fn responder_id(&self) -> [u8; 32] {
        self.responder.id
    }
    pub fn network_tag(&self) -> [u8; 16] {
        self.tag
    }
    /// Full network identity, never the truncated network tag.
    pub(crate) fn matches_network(&self, genesis: [u8; 32], fingerprint: [u8; 32]) -> bool {
        self.bytes[2..6] == NETWORK.to_be_bytes()
            && self.bytes[6..38] == genesis
            && self.bytes[38..70] == fingerprint
    }
    pub fn pinned(
        genesis: [u8; 32],
        fingerprint: [u8; 32],
        initiator: Endpoint,
        responder: Endpoint,
    ) -> Result<Self> {
        if genesis == [0; 32] || fingerprint == [0; 32] || initiator.id == responder.id {
            return Err(Error::Context);
        }
        let mut h = Sha256::new();
        h.update(b"MUTINY-BUILD8-NETWORK-TAG-V1\0");
        h.update(NETWORK.to_be_bytes());
        h.update(genesis);
        h.update(fingerprint);
        let tag: [u8; 16] = h.finalize()[..16].try_into().unwrap();
        let mut b = Vec::with_capacity(CONTEXT_LEN);
        b.extend_from_slice(&[2, 1]);
        b.extend_from_slice(&NETWORK.to_be_bytes());
        b.extend_from_slice(&genesis);
        b.extend_from_slice(&fingerprint);
        b.extend_from_slice(&tag);
        b.extend_from_slice(&initiator.id);
        b.extend_from_slice(&responder.id);
        b.extend_from_slice(&initiator.generation.to_be_bytes());
        b.extend_from_slice(&responder.generation.to_be_bytes());
        Ok(Self {
            bytes: b.try_into().unwrap(),
            initiator,
            responder,
            tag,
        })
    }
}
fn transcript(hello: &[u8], response_body: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(b"MUTINY-BUILD8-HYBRID-SESSION-TRANSCRIPT-V2\0");
    h.update(hello);
    h.update(response_body);
    h.finalize().into()
}
fn signature(bytes: &[u8]) -> Result<HybridSignature> {
    if bytes.len() != 1394 {
        return Err(Error::Encoding);
    }
    Ok(HybridSignature {
        ed448: bytes[..114].try_into().unwrap(),
        fndsa: bytes[114..].try_into().unwrap(),
    })
}
fn append_signature(out: &mut Vec<u8>, s: &HybridSignature) {
    out.extend_from_slice(&s.ed448);
    out.extend_from_slice(&s.fndsa);
}
fn matches_key(key: &HybridKey, endpoint: &Endpoint) -> Result<()> {
    if key.public() != &endpoint.public {
        return Err(Error::Context);
    }
    Ok(())
}
fn live(start: Instant) -> Result<()> {
    if start.elapsed() > HANDSHAKE_LIFETIME {
        Err(Error::Expired)
    } else {
        Ok(())
    }
}
pub(crate) struct Keys {
    pub tx: Zeroizing<[u8; 32]>,
    pub rx: Zeroizing<[u8; 32]>,
    pub tx_prefix: [u8; 4],
    pub rx_prefix: [u8; 4],
    pub id: [u8; 32],
}
fn keys(x: &[u8; 56], kem: &[u8; 32], th: &[u8; 64], initiator: bool) -> Result<Keys> {
    let mut ikm = Zeroizing::new([0u8; 88]);
    ikm[..56].copy_from_slice(x);
    ikm[56..].copy_from_slice(kem);
    let kdf = hkdf::Hkdf::<Sha512>::new(Some(th), ikm.as_ref());
    let mut out = Zeroizing::new([0u8; 104]);
    kdf.expand(b"MUTINY-BUILD8-HYBRID-SESSION-KEYS-V2\0", out.as_mut())
        .map_err(|_| Error::Crypto)?;
    let mut a = Zeroizing::new([0u8; 32]);
    a.copy_from_slice(&out[..32]);
    let mut b = Zeroizing::new([0u8; 32]);
    b.copy_from_slice(&out[32..64]);
    let ap = out[64..68].try_into().unwrap();
    let bp = out[68..72].try_into().unwrap();
    let id = out[72..104].try_into().unwrap();
    if initiator {
        Ok(Keys {
            tx: a,
            rx: b,
            tx_prefix: ap,
            rx_prefix: bp,
            id,
        })
    } else {
        Ok(Keys {
            tx: b,
            rx: a,
            tx_prefix: bp,
            rx_prefix: ap,
            id,
        })
    }
}
fn confirmation(key: &[u8; 32], prefix: [u8; 4], th: &[u8; 64], sender: u8) -> Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&prefix); // sequence zero reserved for this one Finished.
    let mut aad = Vec::from(b"MUTINY-BUILD8-SESSION-FINISHED-V2\0".as_slice());
    aad.push(sender);
    aad.extend_from_slice(th);
    ChaCha20Poly1305::new(key.into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &[],
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto)
}
fn verify_confirmation(
    key: &[u8; 32],
    prefix: [u8; 4],
    th: &[u8; 64],
    sender: u8,
    tag: &[u8],
) -> Result<()> {
    if tag.len() != 16 {
        return Err(Error::Encoding);
    }
    let mut nonce = [0u8; 12];
    nonce[..4].copy_from_slice(&prefix);
    let mut aad = Vec::from(b"MUTINY-BUILD8-SESSION-FINISHED-V2\0".as_slice());
    aad.push(sender);
    aad.extend_from_slice(th);
    let plain = ChaCha20Poly1305::new(key.into())
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: tag,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto)?;
    if !plain.is_empty() {
        return Err(Error::Crypto);
    }
    Ok(())
}
pub struct InitiatorPending {
    context: Context,
    x: X448,
    kem: Kem,
    hello: Vec<u8>,
    started: Instant,
}
pub struct ResponderPending {
    context: Context,
    keys: Keys,
    transcript: [u8; 64],
    started: Instant,
}
pub struct InitiatorConfirm {
    context: Context,
    keys: Keys,
    transcript: [u8; 64],
    started: Instant,
}
impl InitiatorPending {
    pub fn start(context: Context, key: &HybridKey) -> Result<(Self, Vec<u8>)> {
        matches_key(key, &context.initiator)?;
        let started = Instant::now();
        let x = X448::generate()?;
        let kem = Kem::generate()?;
        let nonce = random::<32>()?;
        let mut hello = context.bytes.to_vec();
        hello.extend_from_slice(nonce.as_ref());
        hello.extend_from_slice(&x.public);
        hello.extend_from_slice(&kem.public);
        Ok((
            Self {
                context,
                x,
                kem,
                hello: hello.clone(),
                started,
            },
            hello,
        ))
    }
    /// Consumes the ephemeral keys on success or any failure. No retry/resumption.
    pub fn accept(self, key: &HybridKey, response: &[u8]) -> Result<(InitiatorConfirm, Vec<u8>)> {
        live(self.started)?;
        matches_key(key, &self.context.initiator)?;
        if response.len() != RESPONSE_LEN {
            return Err(Error::Encoding);
        }
        if response[..32] == [0u8; 32]
            || response[..32] == self.hello[CONTEXT_LEN..CONTEXT_LEN + 32]
        {
            return Err(Error::Context);
        }
        let body = &response[..RESPONSE_LEN - 1394];
        let th = transcript(&self.hello, body);
        self.context
            .responder
            .public
            .verify(
                Domain::TransportResponder,
                &th,
                &signature(&response[body.len()..])?,
            )
            .map_err(|_| Error::Crypto)?;
        let x = self.x.agree(response[32..88].try_into().unwrap())?;
        let kem = self
            .kem
            .decapsulate(response[88..1656].try_into().unwrap())?;
        let k = keys(&x, &kem, &th, true)?;
        let mut finish = Vec::with_capacity(CLIENT_FINISH_LEN);
        append_signature(
            &mut finish,
            &key.sign(Domain::TransportInitiator, &th)
                .map_err(|_| Error::Crypto)?,
        );
        finish.extend_from_slice(&confirmation(&k.tx, k.tx_prefix, &th, 0)?);
        live(self.started)?;
        Ok((
            InitiatorConfirm {
                context: self.context,
                keys: k,
                transcript: th,
                started: self.started,
            },
            finish,
        ))
    }
}
impl ResponderPending {
    pub fn accept(context: Context, key: &HybridKey, hello: &[u8]) -> Result<(Self, Vec<u8>)> {
        matches_key(key, &context.responder)?;
        if hello.len() != HELLO_LEN {
            return Err(Error::Encoding);
        }
        if hello[..CONTEXT_LEN] != context.bytes {
            return Err(Error::Context);
        }
        if hello[CONTEXT_LEN..CONTEXT_LEN + 32] == [0u8; 32] {
            return Err(Error::Context);
        }
        let started = Instant::now();
        let x = X448::generate()?;
        let shared = x.agree(
            hello[CONTEXT_LEN + 32..CONTEXT_LEN + 88]
                .try_into()
                .unwrap(),
        )?;
        let (ct, kem) = encapsulate(hello[CONTEXT_LEN + 88..].try_into().unwrap())?;
        let nonce = random::<32>()?;
        if nonce.as_ref() == &hello[CONTEXT_LEN..CONTEXT_LEN + 32] {
            return Err(Error::Crypto);
        }
        let mut response = Vec::with_capacity(RESPONSE_LEN);
        response.extend_from_slice(nonce.as_ref());
        response.extend_from_slice(&x.public);
        response.extend_from_slice(&ct);
        let th = transcript(hello, &response);
        let k = keys(&shared, &kem, &th, false)?;
        append_signature(
            &mut response,
            &key.sign(Domain::TransportResponder, &th)
                .map_err(|_| Error::Crypto)?,
        );
        live(started)?;
        Ok((
            Self {
                context,
                keys: k,
                transcript: th,
                started,
            },
            response,
        ))
    }
    pub fn finish(self, finish: &[u8]) -> Result<(crate::Session, Vec<u8>)> {
        live(self.started)?;
        if finish.len() != CLIENT_FINISH_LEN {
            return Err(Error::Encoding);
        }
        self.context
            .initiator
            .public
            .verify(
                Domain::TransportInitiator,
                &self.transcript,
                &signature(&finish[..1394])?,
            )
            .map_err(|_| Error::Crypto)?;
        verify_confirmation(
            &self.keys.rx,
            self.keys.rx_prefix,
            &self.transcript,
            0,
            &finish[1394..],
        )?;
        let reply = confirmation(&self.keys.tx, self.keys.tx_prefix, &self.transcript, 1)?;
        Ok((crate::Session::new(self.context, self.keys, false), reply))
    }
}
impl InitiatorConfirm {
    pub fn finish(self, tag: &[u8]) -> Result<crate::Session> {
        live(self.started)?;
        verify_confirmation(&self.keys.rx, self.keys.rx_prefix, &self.transcript, 1, tag)?;
        Ok(crate::Session::new(self.context, self.keys, true))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_handshake_expiry_and_transcript_bound_schedule() {
        assert_eq!(
            live(Instant::now() - HANDSHAKE_LIFETIME - Duration::from_secs(1)),
            Err(Error::Expired)
        );
        let k = keys(&[1; 56], &[2; 32], &[3; 64], true).unwrap();
        let r = keys(&[1; 56], &[2; 32], &[3; 64], false).unwrap();
        assert_eq!(k.tx, r.rx);
        assert_eq!(k.rx, r.tx);
        assert_ne!(k.tx, k.rx);
        assert_eq!(k.id, r.id);
        for changed in [
            keys(&[4; 56], &[2; 32], &[3; 64], true).unwrap(),
            keys(&[1; 56], &[4; 32], &[3; 64], true).unwrap(),
            keys(&[1; 56], &[2; 32], &[4; 64], true).unwrap(),
        ] {
            assert_ne!(k.tx, changed.tx);
            assert_ne!(k.rx, changed.rx);
            assert_ne!(k.id, changed.id);
        }
        let tag = confirmation(&k.tx, k.tx_prefix, &[3; 64], 0).unwrap();
        assert!(verify_confirmation(&r.rx, r.rx_prefix, &[3; 64], 0, &tag).is_ok());
        assert!(verify_confirmation(&r.rx, r.rx_prefix, &[3; 64], 1, &tag).is_err());
        assert!(verify_confirmation(&r.rx, r.rx_prefix, &[4; 64], 0, &tag).is_err());
        // Expected values independently computed by qualification/session_schedule_reference_v1.py.
        assert_eq!(
            hex::encode(k.tx.as_ref()),
            "7aa4f4c6b8a84c81831438c907a532c18d928ccd1949e74edb514bb951f979f9"
        );
        assert_eq!(
            hex::encode(k.rx.as_ref()),
            "71efd92dd06df3876fe2d5b37fea3d491433085bee27f92b7d68ce7b9cc027c4"
        );
        assert_eq!(
            hex::encode(k.id),
            "ba019aaca589ffe7a76dc39e5865da18a0755beccc5f1e4fc4d93a17c4d42da0"
        );
        assert_eq!(hex::encode(tag), "2001560d7fdf0f001ad403a6fe9d161a");
    }
}
