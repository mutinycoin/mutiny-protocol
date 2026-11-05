// Synthetic fixture keys only. Exercises encrypted custody via the actual
// handshake, including Worker possession and both Finished directions.
struct FixedWorkerClock(crate::hybrid_coordinator_v2::Sample);
impl crate::hybrid_coordinator_v2::Clock for FixedWorkerClock {
    fn sample(&mut self) -> std::result::Result<crate::hybrid_coordinator_v2::Sample, String> {
        Ok(self.0)
    }
}
fn live_canonical_worker_channel(
    context: mutiny_transport_v2::worker_context_v2::Context,
    signer: &impl mutiny_transport_v2::worker_handshake_v2::NodeSessionSigner,
    binding: &mutiny_crypto_v2::enrollment::Binding,
    chain: &crate::canonical_store_v2::CanonicalStore,
    parent: &FinalizedAnchor,
) -> crate::worker_current_channel_v2::CanonicalWorkerChannel {
    let (worker, pending, finish) = begin_worker_custody_handshake(context, signer, binding);
    let mut clock = FixedWorkerClock(crate::hybrid_coordinator_v2::Sample {
        monotonic_ms: 100, unix_ms: 1_100_000,
    });
    let (node, tag) = crate::worker_current_channel_v2::CanonicalWorkerChannel::finish(
        pending, &finish, chain, parent, binding.license, binding.worker_id, &mut clock,
    ).unwrap();
    worker.finish(&tag).unwrap();
    node
}
fn begin_worker_custody_handshake(
    context: mutiny_transport_v2::worker_context_v2::Context,
    signer: &impl mutiny_transport_v2::worker_handshake_v2::NodeSessionSigner,
    binding: &mutiny_crypto_v2::enrollment::Binding,
) -> (mutiny_transport_v2::worker_handshake_v2::WorkerConfirm,
      mutiny_transport_v2::worker_handshake_v2::NodePending, Vec<u8>) {
    use mutiny_transport_v2::worker_handshake_v2::{NodePending, WorkerPending, WorkerSigner};
    struct Device(u8);
    impl WorkerSigner for Device {
        fn public(&self) -> [u8; 57] { license_fixture::worker(self.0) }
        fn sign_session(&mut self, t: &[u8; 64]) -> mutiny_transport_v2::Result<[u8; 114]> {
            use std::ffi::{c_char, c_void};
            unsafe extern "C" {
                fn ossl_ed448_sign(c: *mut c_void, s: *mut u8, m: *const u8, n: usize,
                    p: *const u8, k: *const u8, d: *const u8, dn: usize, ph: u8,
                    prop: *const c_char) -> i32;
            }
            let m = mutiny_crypto_v2::worker_session_auth::intent(t);
            let mut s = [0; 114];
            let rc = unsafe { ossl_ed448_sign(std::ptr::null_mut(), s.as_mut_ptr(), m.as_ptr(),
                m.len(), self.public().as_ptr(), [self.0; 57].as_ptr(), std::ptr::null(),
                0, 0, std::ptr::null()) };
            assert_eq!(rc, 1);
            Ok(s)
        }
    }
    let seed = (1..=12).find(|s| license_fixture::worker(*s) == binding.worker_public).unwrap();
    let mut device = Device(seed);
    signer.validate_context(&context).unwrap();
    let (worker, hello) = WorkerPending::start(context.clone(), &device).unwrap();
    let (node, response) = NodePending::accept(context, signer, &hello).unwrap();
    let (worker, finish) = worker.accept(&mut device, &response).unwrap();
    (worker, node, finish)
}

fn qualify_worker_custody_handshake(
    context: mutiny_transport_v2::worker_context_v2::Context,
    signer: &impl mutiny_transport_v2::worker_handshake_v2::NodeSessionSigner,
    binding: &mutiny_crypto_v2::enrollment::Binding,
) {
    let (worker, node, finish) = begin_worker_custody_handshake(context, signer, binding);
    let (node, tag) = node.finish(&finish).unwrap();
    assert_eq!(worker.finish(&tag).unwrap().id(), node.id());
}

fn qualify_current_worker_channel(
    context: mutiny_transport_v2::worker_context_v2::Context,
    signer: &impl mutiny_transport_v2::worker_handshake_v2::NodeSessionSigner,
    binding: &mutiny_crypto_v2::enrollment::Binding,
    chain: &crate::canonical_store_v2::CanonicalStore,
    parent: &FinalizedAnchor,
    descriptor: &[u8],
) {
    use crate::hybrid_coordinator_v2::{Clock, Sample};
    use crate::worker_current_channel_v2::CanonicalWorkerChannel;
    use mutiny_transport_v2::worker_handshake_v2::Authority;
    struct TestClock {calls: u64, fault_at: u64, mode: u8}
    impl Clock for TestClock {
        fn sample(&mut self) -> std::result::Result<Sample, String> {
            self.calls += 1;
            let mut v = Sample {monotonic_ms: 100, unix_ms: 1_100_000};
            if self.calls == self.fault_at {
                match self.mode {
                    2 => return Err("synthetic clock unavailable".into()),
                    3 => v.monotonic_ms -= 1,
                    4 => v.unix_ms -= 1,
                    _ => unreachable!(),
                }
            }
            Ok(v)
        }
    }
    let (public, generation) = mutiny_crypto_v2::PublicKey::decode_descriptor(descriptor).unwrap();
    let authority = Authority {binding, node: &public, node_generation: generation, height: 1, epoch: 1};
    for mode in 0..=5 {
        let (worker, pending, finish) = begin_worker_custody_handshake(context.clone(), signer, binding);
        let mut clock = TestClock {calls: 0, fault_at: u64::MAX, mode};
        let (mut node, tag) = CanonicalWorkerChannel::finish(pending, &finish, chain, parent,
            binding.license, binding.worker_id, &mut clock).unwrap();
        let mut worker = worker.finish(&tag).unwrap().into_channel(&authority).unwrap();
        let frame = node.seal(chain, parent, &mut clock, b"synthetic response").unwrap();
        assert_eq!(worker.open(&authority, &frame).unwrap(), b"synthetic response");
        let mut frame = worker.seal(&authority, b"synthetic request").unwrap();
        if (2..=4).contains(&mode) {clock.fault_at = clock.calls + 2;}
        let mut expected = parent.clone();
        if mode == 1 {expected.block[0] ^= 1;}
        if mode == 5 {*frame.last_mut().unwrap() ^= 1;}
        let result = node.open(chain, &expected, &mut clock, &frame);
        if mode == 0 {
            assert_eq!(result.unwrap(), b"synthetic request");
            node.check(chain, parent, &mut clock).unwrap();
            assert!(node.open(chain, parent, &mut clock, &frame).is_err(), "replay");
        } else {assert!(result.is_err(), "mode {mode} released plaintext");}
        clock.fault_at = u64::MAX;
        assert!(node.check(chain, parent, &mut clock).is_err(), "closed channel revived");
        assert!(node.seal(chain, parent, &mut clock, b"later").is_err());
    }
    // A stale parent cannot release the Node's Finished confirmation.
    let (_, pending, finish) = begin_worker_custody_handshake(context, signer, binding);
    let mut wrong = parent.clone();wrong.block[0] ^= 1;
    let mut clock = TestClock {calls:0, fault_at:u64::MAX, mode:0};
    assert!(CanonicalWorkerChannel::finish(pending, &finish, chain, &wrong,
        binding.license, binding.worker_id, &mut clock).is_err());
}

fn reject_worker_canonical_contexts(
    chain: &crate::canonical_store_v2::CanonicalStore,
    parent: &FinalizedAnchor,
    license: [u8; 32], worker: [u8; 32],
) {
    let mut wrong_parent = parent.clone();
    wrong_parent.block[0] ^= 1;
    assert!(chain.current_worker_session(&wrong_parent, license, worker, 1100).is_err());
    assert!(chain.current_worker_session(parent, [0; 32], worker, 1100).is_err());
    assert!(chain.current_worker_session(parent, license, [0; 32], 1100).is_err());
    assert!(chain.current_worker_session(parent, license, worker, 999).is_err());
}
