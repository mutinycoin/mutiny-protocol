//! Native PUBLIC TEST-VALUE RAM custody for explicit ordinary C entry points.
//! No hardware/storage/entropy claim. Canonical provenance is supplied separately.
use super::*;
unsafe extern "C" {
    fn build8_v2_assignment_candidate_public(
        b: *const PrivateBackend, h256: Hash, h512: Hash, out: *mut PublicCandidate,
    ) -> i32;
    fn build8_enrollment_v2_assignment_candidate_valid(
        raw: *const u8, n: usize, owner: *const u8, on: usize, worker: *const u8,
        proof: *const u8, h256: Hash, h512: Hash,
    ) -> i32;
    fn build8_v2_assignment_restore(
        s: *const Store, expected: *const u8, en: usize, owner: *const u8, on: usize,
        h256: Hash, h512: Hash, ws: *mut c_void, wn: usize,
    ) -> i32;
    fn build8_v2_candidate_public(
        b: *const PrivateBackend, h256: Hash, h512: Hash, out: *mut PublicCandidate,
    ) -> i32;
    fn build8_v2_assignment_candidate_prepare(
        b: *const PrivateBackend, c: *const Context, owner: *const u8, on: usize,
        h256: Hash, h512: Hash, out: *mut PublicCandidate,
    ) -> i32;
    fn build8_v2_assignment_activate(
        s: *const Store, raw: *const u8, n: usize, expected: *const u8, en: usize,
        owner: *const u8, on: usize, h256: Hash, h512: Hash, ws: *mut c_void, wn: usize,
    ) -> i32;
    fn build8_worker_assignment_pending_v2_begin(
        s: *mut c_void, a: *const Local, h: u64, e: u64, out: *mut u8,
    ) -> i32;
    fn build8_worker_assignment_pending_v2_accept(
        s: *mut c_void, a: *const Local, h: u64, e: u64, raw: *const u8, n: usize, out: *mut u8,
    ) -> i32;
    fn build8_worker_assignment_pending_v2_finish(
        s: *mut c_void, a: *const Local, h: u64, e: u64, raw: *const u8, n: usize, out: *mut c_void,
    ) -> i32;
}
pub(super) struct Ordinary {
    pub(super) private: Box<Private>,
    pub(super) public: Box<Public>,
    pub(super) backend: Box<PrivateBackend>,
    pub(super) store: Box<Store>,
    pub(super) context: Box<Context>,
    pub(super) descriptor: Vec<u8>,
    pub(super) owner_descriptor: Vec<u8>,
    pub(super) scratch: Vec<u64>,
    pub(super) platform: Box<Platform>,
    pub(super) local: Local,
    pub(super) binding: Binding,
    pub(super) possession: [u8; 114],
    birth: Vec<u8>,
}
impl Ordinary {
    pub(super) fn prepare(context: Context, owner: &HybridKey, node: &HybridKey) -> Self {
        let mut private = Box::<Private>::default();
        let public = Box::<Public>::default();
        let backend = Box::new(PrivateBackend {
            context: (&mut *private as *mut Private).cast(), read: private_read,
            write: private_write, entropy: private_entropy,
        });
        let mut public = public;
        let store = Box::new(Store {
            context: (&mut *public as *mut Public).cast(), read: public_read, write: public_write,
        });
        let context = Box::new(context);
        let descriptor = node.public().descriptor(1).unwrap();
        let owner_descriptor = owner.public().descriptor(context.owner_generation).unwrap();
        let mut candidate = PublicCandidate {
            unsigned: [0; 512], owner: [0; 2048], worker: [0; 57], proof: [0; 114], un: 0, on: 0,
        };
        assert_eq!(unsafe {
            build8_v2_assignment_candidate_prepare(&*backend, &*context,
                owner_descriptor.as_ptr(), owner_descriptor.len(), build8_v2_mbed_hash256,
                build8_release_mbed_hash512, &mut candidate)
        }, 1);
        let binding = Binding::decode(&candidate.unsigned[..candidate.un]).unwrap();
        binding.verify_worker_possession(&candidate.proof).unwrap();
        assert_eq!(binding.owner_descriptor, owner_descriptor_id(owner.public(), context.owner_generation).unwrap());
        assert_eq!(candidate.owner[..candidate.on], owner_descriptor);
        let birth = private.record.as_ref().unwrap().clone();
        assert_eq!(&birth[..8], b"B8V2KEY\x01");
        assert_eq!((private.writes, private.draws, public.writes), (1, 1, 0));
        let mut scratch = vec![0u64; 516];
        let mut platform = Box::<Platform>::default();
        let local = Local {
            private: &*backend, public: &*store, current: &*context,
            descriptor: descriptor.as_ptr(), dn: descriptor.len(),
            h256: build8_v2_mbed_hash256, h512: build8_release_mbed_hash512,
            workspace: scratch.as_mut_ptr().cast(), wn: 4127,
            platform: (&mut *platform as *mut Platform).cast(), entropy, clock,
        };
        Self { private, public, backend, store, context, descriptor, owner_descriptor,
               scratch, platform, local, binding, possession: candidate.proof, birth }
    }
    pub(super) fn assert_birth_unchanged(&self) {
        assert_eq!(self.private.record.as_ref().unwrap(), &self.birth);
        assert_eq!((self.private.writes, self.private.draws), (1, 1));
    }
    pub(super) fn assert_strict_genesis_refuses(&mut self, enrollment: &Enrollment) {
        let writes = self.public.writes;
        let public = self.public.keys.clone();
        let mut candidate = PublicCandidate {
            unsigned: [7; 512], owner: [7; 2048], worker: [7; 57], proof: [7; 114], un: 7, on: 7,
        };
        assert_eq!(unsafe { build8_v2_candidate_public(&*self.backend,
            build8_v2_mbed_hash256, build8_release_mbed_hash512, &mut candidate) }, 0);
        assert_eq!((candidate.un, candidate.on), (0, 0));
        assert!(candidate.unsigned.iter().chain(candidate.owner.iter()).chain(candidate.worker.iter())
            .chain(candidate.proof.iter()).all(|b| *b == 0));
        let raw = enrollment.bytes().unwrap();
        let unsigned = enrollment.binding.bytes().unwrap();
        assert_eq!(unsafe { build8_v2_activate(&*self.store, raw.as_ptr(), raw.len(),
            unsigned.as_ptr(), unsigned.len(), self.owner_descriptor.as_ptr(), self.owner_descriptor.len(),
            build8_v2_mbed_hash256, build8_release_mbed_hash512, self.scratch.as_mut_ptr().cast(), 4127) }, 0);
        let mut pending = Pending::new();
        let mut hello = vec![7; 1722];
        assert_eq!(unsafe { build8_worker_pending_v2_begin(pending.ptr(), &self.local, 4, 2,
            hello.as_mut_ptr()) }, 0);
        assert!(pending.cleared());
        assert!(hello.iter().all(|b| *b == 0));
        assert_eq!(self.public.writes, writes);
        assert_eq!(self.public.keys, public);
        self.assert_birth_unchanged();
    }
    pub(super) fn activate_current(&mut self, canonical: &Binding, descriptor: &[u8], enrollment: &Enrollment) {
        assert_eq!(canonical, &self.binding);
        assert_eq!(descriptor, self.descriptor);
        assert_eq!(&enrollment.binding, canonical);
        let raw = enrollment.bytes().unwrap();
        let unsigned = canonical.bytes().unwrap();
        assert_eq!(unsafe { build8_v2_assignment_activate(&*self.store, raw.as_ptr(), raw.len(),
            unsigned.as_ptr(), unsigned.len(), self.owner_descriptor.as_ptr(), self.owner_descriptor.len(),
            build8_v2_mbed_hash256, build8_release_mbed_hash512, self.scratch.as_mut_ptr().cast(), 4127) }, 1);
        self.assert_birth_unchanged();
    }
    pub(super) fn assert_bad_activation_refused(&mut self, enrollment: &Enrollment) {
        let unsigned = enrollment.binding.bytes().unwrap();
        for which in 0..4 {
            let mut bad = enrollment.clone();
            match which {
                0 => bad.owner_signature.ed448[0] ^= 1,
                1 => bad.owner_signature.fndsa[32] ^= 1,
                2 => bad.worker_signature[0] ^= 1,
                3 => bad.binding.valid_until_height += 1,
                _ => unreachable!(),
            }
            let raw = bad.bytes().unwrap();
            assert_eq!(unsafe { build8_v2_assignment_activate(&*self.store, raw.as_ptr(), raw.len(),
                unsigned.as_ptr(), unsigned.len(), self.owner_descriptor.as_ptr(), self.owner_descriptor.len(),
                build8_v2_mbed_hash256, build8_release_mbed_hash512,
                self.scratch.as_mut_ptr().cast(), 4127) }, 0, "bad activation variant {which}");
            assert_eq!(self.public.writes, 0);
            assert!(self.public.keys.iter().all(Option::is_none));
            self.assert_birth_unchanged();
        }
    }
    pub(super) fn assert_pending_cannot_begin(&self) {
        let mut pending = Pending::new();
        let mut hello = vec![7; 1722];
        let draws = self.platform.draws;
        assert_eq!(unsafe { build8_worker_assignment_pending_v2_begin(pending.ptr(), &self.local,
            4, self.binding.effective_epoch, hello.as_mut_ptr()) }, 0);
        assert!(pending.cleared());
        assert!(hello.iter().all(|b| *b == 0));
        assert_eq!(self.platform.draws, draws);
        assert_eq!(self.public.writes, 0);
        self.assert_birth_unchanged();
    }
    pub(super) fn assert_active_refusal_boundaries(&mut self) {
        for (height, epoch) in [(0, 2), (4, 1)] {
            self.assert_begin_refused(height, epoch);
        }
        self.private.fail = true;
        self.assert_begin_refused(4, 2);
        self.private.fail = false;
        self.public.fail = true;
        self.assert_begin_refused(4, 2);
        self.public.fail = false;
        // Context is externally canonical; a changed local expected binding
        // cannot be substituted for the immutable birth record or public proof.
        self.context.assignment_generation += 1;
        self.assert_begin_refused(4, 2);
        self.context.assignment_generation -= 1;
        let marker = self.public.keys[1].take().unwrap();
        self.assert_begin_refused(4, 2);
        self.public.keys[1] = Some(marker);
        self.public.keys[0].as_mut().unwrap()[10] ^= 1;
        self.assert_begin_refused(4, 2);
        self.public.keys[0].as_mut().unwrap()[10] ^= 1;
        self.public.keys[1].as_mut().unwrap()[8] ^= 1;
        self.assert_begin_refused(4, 2);
        self.public.keys[1].as_mut().unwrap()[8] ^= 1;
        self.assert_birth_unchanged();
    }
    pub(super) fn assert_mixed_flights_refused(&mut self, node: &HybridKey) {
        for at_finish in [false, true] {
            let mut pending = Pending::new();
            let mut hello = vec![0; 1722];
            assert_eq!(unsafe { build8_worker_assignment_pending_v2_begin(pending.ptr(), &self.local,
                4, 2, hello.as_mut_ptr()) }, 1);
            let (peer, response) = NodePending::accept(HostContext::pinned(&self.binding, node.public(), 1).unwrap(),
                node, &hello).unwrap();
            let mut finish = vec![7; 130];
            if at_finish {
                assert_eq!(unsafe { build8_worker_assignment_pending_v2_accept(pending.ptr(), &self.local,
                    4, 2, response.as_ptr(), response.len(), finish.as_mut_ptr()) }, 1);
                let (_, tag) = peer.finish(&finish).unwrap();
                let mut channel = Channel::new();
                channel.0.fill(7);
                assert_eq!(unsafe { build8_worker_pending_v2_finish(pending.ptr(), &self.local,
                    4, 2, tag.as_ptr(), tag.len(), channel.ptr()) }, 0);
                assert!(channel.0.iter().all(|b| *b == 0));
            } else {
                assert_eq!(unsafe { build8_worker_pending_v2_accept(pending.ptr(), &self.local,
                    4, 2, response.as_ptr(), response.len(), finish.as_mut_ptr()) }, 0);
                assert!(finish.iter().all(|b| *b == 0));
            }
            assert!(pending.cleared());
            self.assert_birth_unchanged();
        }
    }
    fn assert_begin_refused(&self, height: u64, epoch: u64) {
        let mut pending = Pending::new();
        let mut hello = vec![7; 1722];
        let draws = self.platform.draws;
        let writes = self.public.writes;
        assert_eq!(unsafe { build8_worker_assignment_pending_v2_begin(pending.ptr(), &self.local,
            height, epoch, hello.as_mut_ptr()) }, 0);
        assert!(pending.cleared());
        assert!(hello.iter().all(|b| *b == 0));
        assert_eq!(self.platform.draws, draws);
        assert_eq!(self.public.writes, writes);
    }
    pub(super) fn handshake(&mut self, node: &HybridKey, canonical: &Binding, height: u64, epoch: u64) {
        assert_eq!(canonical, &self.binding);
        assert!(height > canonical.valid_until_height, "real canonical work is past the inclusion deadline");
        let authority = Authority { binding: canonical, node: node.public(), node_generation: 1, height, epoch };
        let mut pending = Pending::new();
        let mut hello = vec![0; 1722];
        assert_eq!(unsafe { build8_worker_assignment_pending_v2_begin(pending.ptr(), &self.local,
            height, epoch, hello.as_mut_ptr()) }, 1);
        let (peer, response) = NodePending::accept(HostContext::pinned(canonical, node.public(), 1).unwrap(), node, &hello).unwrap();
        let mut finish = vec![0; 130];
        assert_eq!(unsafe { build8_worker_assignment_pending_v2_accept(pending.ptr(), &self.local,
            height, epoch, response.as_ptr(), response.len(), finish.as_mut_ptr()) }, 1);
        let (peer, tag) = peer.finish(&finish).unwrap();
        let mut channel = Channel::new();
        assert_eq!(unsafe { build8_worker_assignment_pending_v2_finish(pending.ptr(), &self.local,
            height, epoch, tag.as_ptr(), tag.len(), channel.ptr()) }, 1);
        assert!(pending.cleared());
        let mut peer = peer.into_channel(&authority).unwrap();
        let id = HostContext::pinned(canonical, node.public(), 1).unwrap().id();
        let mut wire = vec![0; 16444];
        let mut written = 0;
        assert_eq!(unsafe { b8_worker_seal(channel.ptr(), id.as_ptr(), height, epoch, 0,
            b"current assignment".as_ptr(), 18, wire.as_mut_ptr(), wire.len(), &mut written) }, 1);
        assert_eq!(peer.open(&authority, &wire[..written]).unwrap(), b"current assignment");
        let wire = peer.seal(&authority, b"confirmed return").unwrap();
        let mut plain = vec![0; 16384];
        assert_eq!(unsafe { b8_worker_open(channel.ptr(), id.as_ptr(), height, epoch, 0,
            wire.as_ptr(), wire.len(), plain.as_mut_ptr(), plain.len(), &mut written) }, 1);
        assert_eq!(&plain[..written], b"confirmed return");
        self.assert_birth_unchanged();
    }
}

/// Authentic real-signature Genesis-shaped private/public records remain valid
/// for the original strict path, but never become ordinary API evidence. This
/// is a local TEST component control, not a claim of canonical enrollment.
#[test]
fn ordinary_entry_points_refuse_authentic_genesis_records_and_mixed_flights() {
    let mut f = Fixture::new();
    let birth = f._private.record.clone();
    let public = f.public.keys.clone();
    let writes = f.public.writes;
    let draws = f._private.draws;
    let mut candidate = PublicCandidate {
        unsigned: [0; 512], owner: [0; 2048], worker: [0; 57], proof: [0; 114], un: 0, on: 0,
    };
    assert_eq!(unsafe { build8_v2_candidate_public(&*f._backend, build8_v2_mbed_hash256,
        build8_release_mbed_hash512, &mut candidate) }, 1);
    let unsigned = candidate.unsigned[..candidate.un].to_vec();
    let owner = candidate.owner[..candidate.on].to_vec();
    let mut encoded = minicbor::Encoder::new(Vec::new());
    encoded.array(4).unwrap().bytes(&unsigned).unwrap();
    let mut raw = encoded.into_writer();
    raw.extend_from_slice(&public[0].as_ref().unwrap()[8..]);
    let enrollment = Enrollment::decode(&raw).unwrap();
    let (owner_key, _) = mutiny_crypto_v2::PublicKey::decode_descriptor(&owner).unwrap();
    enrollment.verify_genesis(&f.binding, &owner_key).unwrap();
    assert_eq!(unsafe { build8_enrollment_v2_assignment_candidate_valid(unsigned.as_ptr(), unsigned.len(),
        owner.as_ptr(), owner.len(), candidate.worker.as_ptr(), candidate.proof.as_ptr(),
        build8_v2_mbed_hash256, build8_release_mbed_hash512) }, 0);
    assert_eq!(unsafe { build8_v2_assignment_candidate_public(&*f._backend, build8_v2_mbed_hash256,
        build8_release_mbed_hash512, &mut candidate) }, 0);
    assert_eq!((candidate.un, candidate.on), (0, 0));
    assert_eq!(unsafe { build8_v2_assignment_restore(&*f._store, unsigned.as_ptr(), unsigned.len(),
        owner.as_ptr(), owner.len(), build8_v2_mbed_hash256, build8_release_mbed_hash512,
        f._scratch.as_mut_ptr().cast(), 4127) }, -1);
    assert_eq!(unsafe { build8_v2_assignment_activate(&*f._store, raw.as_ptr(), raw.len(),
        unsigned.as_ptr(), unsigned.len(), owner.as_ptr(), owner.len(), build8_v2_mbed_hash256,
        build8_release_mbed_hash512, f._scratch.as_mut_ptr().cast(), 4127) }, 0);
    let mut pending = Pending::new();
    let hello = f.hello(&mut pending); // Strict Genesis path still works.
    let (_, response) = f.response(&hello);
    let mut finish = vec![7; 130];
    assert_eq!(unsafe { build8_worker_assignment_pending_v2_accept(pending.ptr(), &f.local,
        1, 0, response.as_ptr(), response.len(), finish.as_mut_ptr()) }, 0);
    assert!(pending.cleared());
    assert!(finish.iter().all(|b| *b == 0));
    // Drive a fresh strict path to its second phase, then refuse ordinary finish.
    let hello = f.hello(&mut pending);
    let (peer, response) = f.response(&hello);
    let (status, finish) = f.accept(&mut pending, &response);
    assert_eq!(status, 1);
    let (_, tag) = peer.finish(&finish).unwrap();
    let mut channel = Channel::new();
    channel.0.fill(7);
    assert_eq!(unsafe { build8_worker_assignment_pending_v2_finish(pending.ptr(), &f.local,
        1, 0, tag.as_ptr(), tag.len(), channel.ptr()) }, 0);
    assert!(pending.cleared());
    assert!(channel.0.iter().all(|b| *b == 0));
    assert_eq!(f._private.record, birth);
    assert_eq!(f.public.keys, public);
    assert_eq!((f.public.writes, f._private.draws), (writes, draws));
}
