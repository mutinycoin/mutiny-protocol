//! Worker handshake candidate. No listener, device provisioning or activation.
//! Uses the existing pinned X448/ML-KEM implementations and custody primitives.
//! Callers must recheck canonical binding authority before activating traffic.
use crate::{
    Error, Result,
    primitives::{Kem, X448, encapsulate, random},
    worker_context_v2::{Context, RESPONSE_BODY_LEN},
};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature};
use sha2::Sha512;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

pub const RESPONSE_LEN: usize = RESPONSE_BODY_LEN + 1394;
pub const WORKER_FINISH_LEN: usize = 114 + 16;
// Local qualification bound, not a final hardware latency qualification.
const MAX_LIFETIME: Duration = Duration::from_secs(60);
#[path = "worker_frames_v2.rs"]
mod traffic;
pub use traffic::{Authority, Channel, MAX_FRAME_BYTES, MAX_PAYLOAD};

/// A trusted device-local adapter. This API signs only the fixed Worker session
/// intent; no arbitrary domain, seed export, owner key or host provisioning API.
pub trait WorkerSigner {
    fn public(&self) -> [u8; 57];
    fn sign_session(&mut self, transcript: &[u8; 64]) -> Result<[u8; 114]>;
}
/// Node-local custody adapter for this handshake only. Implementations must
/// check their current canonical assignment and key generation in
/// `validate_context`; no private key export or generic signing callback is
/// required. The caller must also recheck authority before final activation.
pub trait NodeSessionSigner {
    fn validate_context(&self, context: &Context) -> Result<()>;
    fn sign_session(&self, context: &Context, hello: &[u8], body: &[u8])
    -> Result<HybridSignature>;
}
// Existing in-memory component path. It checks the pinned public identity;
// canonical runtime freshness remains the caller's responsibility. Encrypted
// node custody can instead implement the restricted adapter above.
impl NodeSessionSigner for HybridKey {
    fn validate_context(&self, context: &Context) -> Result<()> {
        if context.node_matches(self.public()) {
            Ok(())
        } else {
            Err(Error::Context)
        }
    }
    fn sign_session(
        &self,
        context: &Context,
        hello: &[u8],
        body: &[u8],
    ) -> Result<HybridSignature> {
        self.validate_context(context)?;
        let transcript = context.transcript(hello, body)?;
        self.sign(Domain::NodeWorkerSession, &transcript)
            .map_err(|_| Error::Crypto)
    }
}
struct Keys {
    tx: Zeroizing<[u8; 32]>,
    rx: Zeroizing<[u8; 32]>,
    tx_prefix: [u8; 4],
    rx_prefix: [u8; 4],
    id: [u8; 32],
}
fn derive(x: &[u8; 56], kem: &[u8; 32], th: &[u8; 64], worker: bool) -> Result<Keys> {
    let mut ikm = Zeroizing::new([0u8; 88]);
    ikm[..56].copy_from_slice(x);
    ikm[56..].copy_from_slice(kem);
    let hk = hkdf::Hkdf::<Sha512>::new(Some(th), ikm.as_ref());
    let mut out = Zeroizing::new([0u8; 104]);
    hk.expand(b"MUTINY-BUILD8-WORKER-SESSION-KEYS-V2\0", out.as_mut())
        .map_err(|_| Error::Crypto)?;
    let mut a = Zeroizing::new([0; 32]);
    a.copy_from_slice(&out[..32]);
    let mut b = Zeroizing::new([0; 32]);
    b.copy_from_slice(&out[32..64]);
    let ap = out[64..68].try_into().unwrap();
    let bp = out[68..72].try_into().unwrap();
    let id = out[72..].try_into().unwrap();
    Ok(if worker {
        Keys {
            tx: a,
            rx: b,
            tx_prefix: ap,
            rx_prefix: bp,
            id,
        }
    } else {
        Keys {
            tx: b,
            rx: a,
            tx_prefix: bp,
            rx_prefix: ap,
            id,
        }
    })
}
fn confirmation(key: &[u8; 32], prefix: [u8; 4], th: &[u8; 64], sender: u8) -> Result<[u8; 16]> {
    let mut nonce = [0; 12];
    nonce[..4].copy_from_slice(&prefix); // zero reserved for Finished
    let mut aad = Vec::from(b"MUTINY-BUILD8-WORKER-SESSION-FINISHED-V2\0".as_slice());
    aad.push(sender);
    aad.extend(th);
    ChaCha20Poly1305::new(key.into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &[],
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto)?
        .try_into()
        .map_err(|_| Error::Encoding)
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
    let mut nonce = [0; 12];
    nonce[..4].copy_from_slice(&prefix);
    let mut aad = Vec::from(b"MUTINY-BUILD8-WORKER-SESSION-FINISHED-V2\0".as_slice());
    aad.push(sender);
    aad.extend(th);
    let plain = ChaCha20Poly1305::new(key.into())
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: tag,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto)?;
    if plain.is_empty() {
        Ok(())
    } else {
        Err(Error::Encoding)
    }
}
fn live(start: Instant) -> Result<()> {
    if start.elapsed() >= MAX_LIFETIME {
        Err(Error::Expired)
    } else {
        Ok(())
    }
}
fn matches_worker(c: &Context, signer: &impl WorkerSigner) -> Result<()> {
    if c.worker_public() == signer.public() {
        Ok(())
    } else {
        Err(Error::Context)
    }
}

pub struct WorkerPending {
    context: Context,
    x: X448,
    kem: Kem,
    hello: Vec<u8>,
    started: Instant,
}
pub struct WorkerConfirm {
    context: Context,
    keys: Keys,
    transcript: [u8; 64],
    started: Instant,
}
pub struct NodePending {
    context: Context,
    keys: Keys,
    hello: Vec<u8>,
    body: Vec<u8>,
    transcript: [u8; 64],
    started: Instant,
}

/// Opaque confirmed material. No secret export/Clone/Debug/serialization API.
/// Conversion to bounded traffic rechecks the supplied current authority.
/// No listener or canonical runtime activation is provided here.
pub struct Confirmed {
    context: Context,
    keys: Keys,
    worker: bool,
    confirmed_at: Instant,
}
impl Confirmed {
    pub fn is_worker_endpoint(&self) -> bool {
        self.worker
    }
    pub fn id(&self) -> [u8; 32] {
        self.keys.id
    }
    pub fn matches_current(
        &self,
        binding: &mutiny_crypto_v2::enrollment::Binding,
        node: &mutiny_crypto_v2::PublicKey,
        generation: u64,
        height: u64,
        epoch: u64,
    ) -> bool {
        self.context
            .matches_current(binding, node, generation, height, epoch)
    }
}
impl WorkerPending {
    pub fn start(context: Context, signer: &impl WorkerSigner) -> Result<(Self, Vec<u8>)> {
        matches_worker(&context, signer)?;
        let started = Instant::now();
        let x = X448::generate()?;
        let kem = Kem::generate()?;
        let nonce = random::<32>()?;
        let hello = context.hello(&nonce, &x.public, &kem.public)?.to_vec();
        live(started)?;
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
    /// Consumes ephemeral keys even on failure. Authenticate Node before invoking
    /// the Worker signer or accepting any peer key as authority.
    pub fn accept(
        self,
        signer: &mut impl WorkerSigner,
        response: &[u8],
    ) -> Result<(WorkerConfirm, Vec<u8>)> {
        live(self.started)?;
        matches_worker(&self.context, signer)?;
        if response.len() != RESPONSE_LEN {
            return Err(Error::Encoding);
        }
        let body = &response[..RESPONSE_BODY_LEN];
        let signature = HybridSignature {
            ed448: response[RESPONSE_BODY_LEN..RESPONSE_BODY_LEN + 114]
                .try_into()
                .unwrap(),
            fndsa: response[RESPONSE_BODY_LEN + 114..].try_into().unwrap(),
        };
        let th = self
            .context
            .verify_coordinator(&self.hello, body, &signature)?;
        let x = self.x.agree(body[32..88].try_into().unwrap())?;
        let kem = self.kem.decapsulate(body[88..].try_into().unwrap())?;
        let keys = derive(&x, &kem, &th, true)?;
        live(self.started)?;
        let signature = signer.sign_session(&th)?;
        self.context.verify_worker(&self.hello, body, &signature)?; // detect signer/backend faults
        let mut finish = signature.to_vec();
        finish.extend(confirmation(&keys.tx, keys.tx_prefix, &th, 0)?);
        live(self.started)?;
        Ok((
            WorkerConfirm {
                context: self.context,
                keys,
                transcript: th,
                started: self.started,
            },
            finish,
        ))
    }
}
impl NodePending {
    pub fn accept(
        context: Context,
        node: &impl NodeSessionSigner,
        hello: &[u8],
    ) -> Result<(Self, Vec<u8>)> {
        let started = Instant::now();
        context.validate_hello(hello)?;
        node.validate_context(&context)?;
        live(started)?;
        let x = X448::generate()?;
        let shared = x.agree(hello[98..154].try_into().unwrap())?;
        let (ciphertext, kem) = encapsulate(hello[154..].try_into().unwrap())?;
        let nonce = random::<32>()?;
        let mut body = nonce.to_vec();
        body.extend(x.public);
        body.extend(ciphertext);
        let th = context.transcript(hello, &body)?;
        let keys = derive(&shared, &kem, &th, false)?;
        let signature = node.sign_session(&context, hello, &body)?;
        // A custody callback cannot substitute a partial/wrong-domain signature
        // or return authority that expired while private signing was in flight.
        context.verify_coordinator(hello, &body, &signature)?;
        node.validate_context(&context)?;
        let mut response = body.clone();
        response.extend(signature.ed448);
        response.extend(signature.fndsa);
        live(started)?;
        Ok((
            Self {
                context,
                keys,
                hello: hello.to_vec(),
                body,
                transcript: th,
                started,
            },
            response,
        ))
    }
    /// Consumed on every completion attempt; duplicate finish cannot be retried.
    pub fn finish(self, finish: &[u8]) -> Result<(Confirmed, [u8; 16])> {
        live(self.started)?;
        if finish.len() != WORKER_FINISH_LEN {
            return Err(Error::Encoding);
        }
        self.context
            .verify_worker(&self.hello, &self.body, finish[..114].try_into().unwrap())?;
        verify_confirmation(
            &self.keys.rx,
            self.keys.rx_prefix,
            &self.transcript,
            0,
            &finish[114..],
        )?;
        let reply = confirmation(&self.keys.tx, self.keys.tx_prefix, &self.transcript, 1)?;
        live(self.started)?;
        Ok((
            Confirmed {
                context: self.context,
                keys: self.keys,
                worker: false,
                confirmed_at: Instant::now(),
            },
            reply,
        ))
    }
}
impl WorkerConfirm {
    pub fn finish(self, tag: &[u8]) -> Result<Confirmed> {
        live(self.started)?;
        verify_confirmation(&self.keys.rx, self.keys.rx_prefix, &self.transcript, 1, tag)?;
        live(self.started)?;
        Ok(Confirmed {
            context: self.context,
            keys: self.keys,
            worker: true,
            confirmed_at: Instant::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mutiny_crypto_v2::{Role, enrollment::Binding};
    use sha2::{Digest, Sha256};
    use std::ffi::{c_char, c_void};
    #[test]
    fn public_constant_schedule_vector_and_finished_direction_separation() {
        // Deliberately public constants, not material from a live handshake.
        let a = derive(&[1; 56], &[2; 32], &[3; 64], true).unwrap();
        let b = derive(&[1; 56], &[2; 32], &[3; 64], false).unwrap();
        assert_eq!(a.tx.as_ref(), b.rx.as_ref());
        assert_eq!(a.rx.as_ref(), b.tx.as_ref());
        let tag = confirmation(&a.tx, a.tx_prefix, &[3; 64], 0).unwrap();
        verify_confirmation(&b.rx, b.rx_prefix, &[3; 64], 0, &tag).unwrap();
        assert!(verify_confirmation(&b.rx, b.rx_prefix, &[3; 64], 1, &tag).is_err());
        assert!(verify_confirmation(&b.rx, b.rx_prefix, &[4; 64], 0, &tag).is_err());
        assert!(verify_confirmation(&b.tx, b.tx_prefix, &[3; 64], 0, &tag).is_err());
        for n in [0, 1, 15] {
            assert!(verify_confirmation(&b.rx, b.rx_prefix, &[3; 64], 0, &tag[..n]).is_err());
        }
        if let Ok(path) = std::env::var("BUILD8_PUBLIC_WORKER_KDF_VECTOR") {
            let vector = serde_json::json!({"synthetic_only":true,"public_constants_only":true,
                "production_authorized":false,"x":hex::encode([1;56]),"kem":hex::encode([2;32]),
                "transcript":hex::encode([3;64]),"worker_tx":hex::encode(a.tx.as_ref()),
                "worker_rx":hex::encode(a.rx.as_ref()),"worker_prefix":hex::encode(a.tx_prefix),
                "node_prefix":hex::encode(a.rx_prefix),"id":hex::encode(a.id),"worker_finished":hex::encode(tag)});
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
    unsafe extern "C" {
        fn ossl_ed448_public_from_private(
            c: *mut c_void,
            p: *mut u8,
            s: *const u8,
            q: *const c_char,
        ) -> i32;
        fn ossl_ed448_sign(
            c: *mut c_void,
            o: *mut u8,
            m: *const u8,
            n: usize,
            p: *const u8,
            s: *const u8,
            x: *const u8,
            xn: usize,
            pre: u8,
            q: *const c_char,
        ) -> i32;
    }
    pub(super) struct Device {
        public: [u8; 57],
        calls: usize,
        fault: bool,
    }
    impl Device {
        fn synthetic() -> Self {
            let mut public = [0; 57];
            assert_eq!(
                unsafe {
                    ossl_ed448_public_from_private(
                        std::ptr::null_mut(),
                        public.as_mut_ptr(),
                        [42; 57].as_ptr(),
                        std::ptr::null(),
                    )
                },
                1
            );
            Self {
                public,
                calls: 0,
                fault: false,
            }
        }
    }
    impl WorkerSigner for Device {
        fn public(&self) -> [u8; 57] {
            self.public
        }
        fn sign_session(&mut self, t: &[u8; 64]) -> Result<[u8; 114]> {
            self.calls += 1;
            if self.fault {
                return Ok([0; 114]);
            }
            let mut s = [0; 114];
            let m = mutiny_crypto_v2::worker_session_auth::intent(t);
            if unsafe {
                ossl_ed448_sign(
                    std::ptr::null_mut(),
                    s.as_mut_ptr(),
                    m.as_ptr(),
                    64,
                    self.public.as_ptr(),
                    [42; 57].as_ptr(),
                    std::ptr::null(),
                    0,
                    0,
                    std::ptr::null(),
                )
            } != 1
            {
                return Err(Error::Crypto);
            }
            Ok(s)
        }
    }
    pub(super) fn fixture() -> (Context, Binding, HybridKey, Device) {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/enrollment-v2-public-fixture-v3.json"
        ))
        .unwrap();
        assert_eq!(f["synthetic"], true);
        let mut b =
            Binding::decode(&hex::decode(f["unsigned"].as_str().unwrap()).unwrap()).unwrap();
        let node = HybridKey::generate(Role::Node).unwrap();
        let device = Device::synthetic();
        b.worker_public = device.public;
        b.worker_id = b.derived_worker_id();
        let mut h = Sha256::new();
        h.update(b"MUTINY-BUILD8-NODE-AUTHORITY-IDENTITY-V2\0");
        h.update(node.public().descriptor(1).unwrap());
        b.coordinator = h.finalize().into();
        (
            Context::pinned(&b, node.public(), 1).unwrap(),
            b,
            node,
            device,
        )
    }
    #[test]
    fn actual_ephemeral_agreement_and_both_finished_messages_are_required() {
        let (c, b, node, mut device) = fixture();
        let (worker, hello) = WorkerPending::start(c.clone(), &device).unwrap();
        let (pending, response) = NodePending::accept(c, &node, &hello).unwrap();
        let (confirm, finish) = worker.accept(&mut device, &response).unwrap();
        let (node_session, tag) = pending.finish(&finish).unwrap();
        let worker_session = confirm.finish(&tag).unwrap();
        assert_eq!(device.calls, 1);
        assert_eq!(worker_session.id(), node_session.id());
        assert_eq!(
            worker_session.keys.tx.as_ref(),
            node_session.keys.rx.as_ref()
        );
        assert_eq!(
            worker_session.keys.rx.as_ref(),
            node_session.keys.tx.as_ref()
        );
        assert_ne!(
            worker_session.keys.tx.as_ref(),
            worker_session.keys.rx.as_ref()
        );
        assert!(worker_session.is_worker_endpoint());
        assert!(!node_session.is_worker_endpoint());
        assert!(worker_session.matches_current(&b, node.public(), 1, 1, 0));
        let mut changed = b;
        changed.assignment_generation += 1;
        assert!(!worker_session.matches_current(&changed, node.public(), 1, 1, 0));
    }
    #[test]
    fn node_custody_adapter_rechecks_authority_and_both_signature_halves() {
        use std::cell::Cell;
        struct Adapter<'a> {
            key: &'a HybridKey,
            mode: u8,
            calls: Cell<u32>,
            checks: Cell<u32>,
        }
        impl NodeSessionSigner for Adapter<'_> {
            fn validate_context(&self, c: &Context) -> Result<()> {
                self.checks.set(self.checks.get() + 1);
                if self.mode == 1 || (self.mode == 2 && self.calls.get() > 0) {
                    return Err(Error::Context);
                }
                self.key.validate_context(c)
            }
            fn sign_session(&self, c: &Context, h: &[u8], b: &[u8]) -> Result<HybridSignature> {
                self.calls.set(self.calls.get() + 1);
                let mut sig = self.key.sign_session(c, h, b)?;
                if self.mode == 3 {
                    sig.ed448[0] ^= 1;
                }
                if self.mode == 4 {
                    sig.fndsa[0] ^= 1;
                }
                Ok(sig)
            }
        }
        let (c, _, node, mut device) = fixture();
        for mode in 0..=4 {
            let (worker, hello) = WorkerPending::start(c.clone(), &device).unwrap();
            let adapter = Adapter {
                key: &node,
                mode,
                calls: Cell::new(0),
                checks: Cell::new(0),
            };
            let result = NodePending::accept(c.clone(), &adapter, &hello);
            assert_eq!(adapter.calls.get(), if mode == 1 { 0 } else { 1 });
            if mode == 0 {
                let (pending, response) = result.unwrap();
                let (confirm, finish) = worker.accept(&mut device, &response).unwrap();
                let (session, tag) = pending.finish(&finish).unwrap();
                assert_eq!(confirm.finish(&tag).unwrap().id(), session.id());
                assert_eq!(adapter.checks.get(), 2);
            } else {
                assert!(result.is_err());
            }
        }
    }
    #[test]
    fn hostile_response_cannot_reach_worker_signer_and_faults_cannot_finish() {
        let (c, _, node, mut device) = fixture();
        for index in [
            0,
            32,
            88,
            RESPONSE_BODY_LEN,
            RESPONSE_BODY_LEN + 114,
            RESPONSE_LEN - 1,
        ] {
            let (worker, hello) = WorkerPending::start(c.clone(), &device).unwrap();
            let (_, mut response) = NodePending::accept(c.clone(), &node, &hello).unwrap();
            response[index] ^= 1;
            let before = device.calls;
            assert!(worker.accept(&mut device, &response).is_err());
            assert_eq!(device.calls, before);
        }
        let (worker, hello) = WorkerPending::start(c.clone(), &device).unwrap();
        let (_, response) = NodePending::accept(c.clone(), &node, &hello).unwrap();
        device.fault = true;
        assert!(worker.accept(&mut device, &response).is_err());
        device.fault = false;
        let (worker, hello) = WorkerPending::start(c.clone(), &device).unwrap();
        let (pending, response) = NodePending::accept(c.clone(), &node, &hello).unwrap();
        let (_, mut finish) = worker.accept(&mut device, &response).unwrap();
        finish[114] ^= 1;
        assert!(pending.finish(&finish).is_err());
        let (worker, hello) = WorkerPending::start(c.clone(), &device).unwrap();
        let (pending, response) = NodePending::accept(c, &node, &hello).unwrap();
        let (confirm, finish) = worker.accept(&mut device, &response).unwrap();
        let (_, mut tag) = pending.finish(&finish).unwrap();
        tag[0] ^= 1;
        assert!(confirm.finish(&tag).is_err());
    }
    #[test]
    fn malformed_expired_and_cross_session_messages_fail_closed() {
        let (c, _, node, mut device) = fixture();
        let (mut worker, hello) = WorkerPending::start(c.clone(), &device).unwrap();
        for n in [0, 1, hello.len() - 1] {
            assert!(NodePending::accept(c.clone(), &node, &hello[..n]).is_err());
        }
        let mut bad = hello.clone();
        bad.push(0);
        assert!(NodePending::accept(c.clone(), &node, &bad).is_err());
        let (_, response) = NodePending::accept(c.clone(), &node, &hello).unwrap();
        worker.started = Instant::now() - MAX_LIFETIME;
        assert!(worker.accept(&mut device, &response).is_err());
        assert_eq!(device.calls, 0);
        let (worker, hello) = WorkerPending::start(c.clone(), &device).unwrap();
        let (mut pending, response) = NodePending::accept(c.clone(), &node, &hello).unwrap();
        let (mut confirm, finish) = worker.accept(&mut device, &response).unwrap();
        pending.started = Instant::now() - MAX_LIFETIME;
        assert!(pending.finish(&finish).is_err());
        confirm.started = Instant::now() - MAX_LIFETIME;
        assert!(confirm.finish(&[0; 16]).is_err());
        let (w1, h1) = WorkerPending::start(c.clone(), &device).unwrap();
        let (w2, h2) = WorkerPending::start(c.clone(), &device).unwrap();
        assert_ne!(h1, h2);
        let (n1, r1) = NodePending::accept(c.clone(), &node, &h1).unwrap();
        let (n2, r2) = NodePending::accept(c, &node, &h2).unwrap();
        let (f1, s1) = w1.accept(&mut device, &r1).unwrap();
        let (_, s2) = w2.accept(&mut device, &r2).unwrap();
        assert!(n1.finish(&s2).is_err());
        assert!(n2.finish(&s1).is_err());
        drop(f1);
    }
}
