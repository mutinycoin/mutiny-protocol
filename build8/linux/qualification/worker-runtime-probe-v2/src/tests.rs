use mutiny_crypto_v2::{
    Domain, HybridKey, Role,
    enrollment::{Binding, Enrollment, owner_descriptor_id},
};
use mutiny_transport_v2::{
    worker_context_v2::Context as HostContext,
    worker_handshake_v2::{Authority, NodePending},
};
use sha2::{Digest, Sha256, Sha512};
use std::ffi::{c_char, c_void};
type Hash = unsafe extern "C" fn(*const c_char, *const u8, usize, *mut u8) -> i32;
static NVS_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
#[path = "ordinary_fixture.rs"]
mod ordinary_fixture;
#[path = "canonical_assignment_fixture.rs"]
mod canonical_assignment_fixture;
#[path = "journal_fixture.rs"]
mod journal_fixture;
#[test]
fn actual_owner_maintenance_retires_and_parks_only_receipted_checkpoint() {
    let _lock = NVS_TEST_LOCK.lock().unwrap();
    unsafe extern "C" {
        fn build8_qual_maintenance_accounting(
            a: *const u8,
            an: usize,
            d: *const u8,
            dn: usize,
            r: *const u8,
            rn: usize,
            c: *const u8,
        ) -> i32;
    }
    let f: serde_json::Value =
        serde_json::from_str(include_str!("../../worker-runtime-candidate-v2/qualification/worker-accounting-public-v1.json")).unwrap();
    assert_eq!(f["synthetic_only"], true);
    assert_eq!(f["production_authorized"], false);
    let bytes = |name: &str| hex::decode(f[name].as_str().unwrap()).unwrap();
    let a = bytes("authority");
    let d = bytes("descriptor");
    let r = bytes("receipt");
    let c = bytes("coordinator");
    assert_eq!(
        unsafe {
            build8_qual_maintenance_accounting(
                a.as_ptr(),
                a.len(),
                d.as_ptr(),
                d.len(),
                r.as_ptr(),
                r.len(),
                c.as_ptr(),
            )
        },
        0,
        "C maintenance checkpoint line"
    );
}
#[repr(C)]
struct Context {
    genesis: [u8; 32],
    fingerprint: [u8; 32],
    license: [u8; 32],
    owner_descriptor: [u8; 32],
    owner_generation: u64,
    coordinator: [u8; 32],
    configuration_generation: u64,
    device_mac: [u8; 6],
    assignment_generation: u64,
    effective_epoch: u64,
    valid_until_height: u64,
}
#[repr(C)]
struct PrivateBackend {
    context: *mut c_void,
    read: unsafe extern "C" fn(*mut c_void, *mut u8, usize, *mut usize) -> i32,
    write: unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32,
    entropy: unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> i32,
}
#[repr(C)]
struct Store {
    context: *mut c_void,
    read: unsafe extern "C" fn(*mut c_void, u32, *mut u8, usize, *mut usize) -> i32,
    write: unsafe extern "C" fn(*mut c_void, u32, *const u8, usize) -> i32,
}
#[repr(C)]
struct PublicCandidate {
    unsigned: [u8; 512],
    owner: [u8; 2048],
    worker: [u8; 57],
    proof: [u8; 114],
    un: usize,
    on: usize,
}
#[repr(C)]
struct Local {
    private: *const PrivateBackend,
    public: *const Store,
    current: *const Context,
    descriptor: *const u8,
    dn: usize,
    h256: Hash,
    h512: Hash,
    workspace: *mut c_void,
    wn: usize,
    platform: *mut c_void,
    entropy: unsafe extern "C" fn(*mut c_void, *mut u8, usize) -> i32,
    clock: unsafe extern "C" fn(*mut c_void) -> u64,
}
#[repr(C)]
#[derive(Default)]
struct Receive {
    storage: *mut u8,
    capacity: usize,
    used: usize,
    target: usize,
    kind: u32,
    ready: u32,
}
unsafe extern "C" {
    fn build8_qual_runtime_request(value: u8);
    fn build8_qual_runtime_reject_signed_work(
        local: *const Local,
        wire: *const u8,
        n: usize,
    ) -> i32;
    fn build8_qual_runtime_signed_work(local: *const Local, wire: *const u8, n: usize) -> i32;
    fn build8_qual_runtime_binding(
        s: *mut c_void,
        local: *const Local,
        worker: *const u8,
        worker_id: *const u8,
        mutation: u32,
    ) -> i32;
    fn build8_enrollment_v2_worker_id(
        c: *const Context,
        worker: *const u8,
        hash: Hash,
        out: *mut u8,
    ) -> i32;
    fn build8_worker_connection_v2_close(s: *mut c_void);
    fn build8_qual_runtime_init();
    fn build8_qual_runtime_guard(
        s: *mut c_void,
        context: *const u8,
        h: u64,
        now: u64,
        maintenance: i32,
    ) -> i32;
    fn build8_qual_runtime_accounting();
    fn build8_qual_runtime_later_clock();
    fn build8_qual_runtime_flags() -> u32;
    fn build8_worker_connection_v2_size() -> usize;
    fn build8_worker_connection_v2_alignment() -> usize;
    fn build8_worker_connection_v2_start(
        s: *mut c_void,
        p: *mut c_void,
        pn: usize,
        rx: *mut u8,
        tx: *mut u8,
        a: *const Local,
        h: u64,
        e: u64,
    ) -> i32;
    fn build8_worker_connection_v2_out(s: *const c_void, n: *mut usize) -> *const u8;
    fn build8_worker_connection_v2_sent(s: *mut c_void, n: usize) -> i32;
    fn build8_worker_connection_v2_send(
        s: *mut c_void,
        context: *const u8,
        h: u64,
        e: u64,
        now: u64,
        p: *const u8,
        n: usize,
    ) -> i32;
    fn build8_worker_connection_v2_receive(
        s: *mut c_void,
        a: *const Local,
        context: *const u8,
        h: u64,
        e: u64,
        now: u64,
        wire: *const u8,
        n: usize,
        consumed: *mut usize,
        plain: *mut u8,
        capacity: usize,
        written: *mut usize,
    ) -> i32;
    fn build8_worker_receive_v2_init(
        s: *mut Receive,
        p: *mut u8,
        capacity: usize,
        kind: u32,
    ) -> i32;
    fn build8_worker_receive_v2_clear(s: *mut Receive);
    fn build8_worker_receive_v2_feed(
        s: *mut Receive,
        p: *const u8,
        n: usize,
        consumed: *mut usize,
    ) -> i32;
    fn build8_worker_receive_v2_message(s: *const Receive, n: *mut usize) -> *const u8;
    fn build8_qual_bind_nvs(p: *const PrivateBackend, s: *const Store) -> i32;
    fn build8_qual_unbind_nvs();
    fn build8_worker_v2_handshake_begin(
        p: *mut c_void,
        a: *const Local,
        h: u64,
        e: u64,
        out: *mut u8,
    ) -> i32;
    fn build8_worker_v2_handshake_accept(
        p: *mut c_void,
        a: *const Local,
        h: u64,
        e: u64,
        r: *const u8,
        n: usize,
        out: *mut u8,
    ) -> i32;
    fn build8_worker_v2_handshake_finish(
        p: *mut c_void,
        a: *const Local,
        h: u64,
        e: u64,
        t: *const u8,
        n: usize,
        out: *mut c_void,
    ) -> i32;
    fn build8_v2_mbed_hash256(d: *const c_char, p: *const u8, n: usize, o: *mut u8) -> i32;
    fn build8_release_mbed_hash512(d: *const c_char, p: *const u8, n: usize, o: *mut u8) -> i32;
    fn build8_v2_candidate_prepare(
        b: *const PrivateBackend,
        c: *const Context,
        owner: *const u8,
        n: usize,
        h: Hash,
        g: Hash,
        o: *mut PublicCandidate,
    ) -> i32;
    fn build8_v2_activate(
        s: *const Store,
        raw: *const u8,
        n: usize,
        u: *const u8,
        un: usize,
        owner: *const u8,
        on: usize,
        h: Hash,
        g: Hash,
        w: *mut c_void,
        wn: usize,
    ) -> i32;
    fn build8_worker_pending_v2_size() -> usize;
    fn build8_worker_pending_v2_alignment() -> usize;
    fn build8_worker_pending_v2_init(p: *mut c_void, n: usize) -> *mut c_void;
    fn build8_worker_pending_v2_clear(p: *mut c_void);
    fn build8_worker_pending_v2_expire(p: *mut c_void, now: u64) -> i32;
    fn build8_worker_pending_v2_begin(
        p: *mut c_void,
        a: *const Local,
        h: u64,
        e: u64,
        out: *mut u8,
    ) -> i32;
    fn build8_worker_pending_v2_accept(
        p: *mut c_void,
        a: *const Local,
        h: u64,
        e: u64,
        r: *const u8,
        n: usize,
        out: *mut u8,
    ) -> i32;
    fn build8_worker_pending_v2_finish(
        p: *mut c_void,
        a: *const Local,
        h: u64,
        e: u64,
        t: *const u8,
        n: usize,
        c: *mut c_void,
    ) -> i32;
    fn b8_worker_channel_size() -> usize;
    fn b8_worker_channel_clear(c: *mut c_void);
    fn b8_worker_seal(
        c: *mut c_void,
        context: *const u8,
        h: u64,
        e: u64,
        now: u64,
        p: *const u8,
        n: usize,
        o: *mut u8,
        cap: usize,
        w: *mut usize,
    ) -> i32;
    fn b8_worker_open(
        c: *mut c_void,
        context: *const u8,
        h: u64,
        e: u64,
        now: u64,
        p: *const u8,
        n: usize,
        o: *mut u8,
        cap: usize,
        w: *mut usize,
    ) -> i32;
}
#[derive(Default)]
struct Private {
    record: Option<Vec<u8>>,
    writes: usize,
    draws: usize,
    fail: bool,
}
#[derive(Default)]
struct Public {
    keys: [Option<Vec<u8>>; 2],
    writes: usize,
    fail: bool,
}
unsafe extern "C" fn private_read(p: *mut c_void, o: *mut u8, cap: usize, n: *mut usize) -> i32 {
    let d = unsafe { &mut *p.cast::<Private>() };
    if d.fail {
        return -1;
    }
    match &d.record {
        None => 0,
        Some(b) => {
            if b.len() > cap {
                return -1;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(b.as_ptr(), o, b.len());
                *n = b.len();
            }
            1
        }
    }
}
unsafe extern "C" fn private_write(p: *mut c_void, b: *const u8, n: usize) -> i32 {
    let d = unsafe { &mut *p.cast::<Private>() };
    d.writes += 1;
    d.record = Some(unsafe { std::slice::from_raw_parts(b, n) }.to_vec());
    1
}
unsafe extern "C" fn private_entropy(p: *mut c_void, o: *mut u8, n: usize) -> i32 {
    assert_eq!(n, 57);
    unsafe {
        (*p.cast::<Private>()).draws += 1;
        for i in 0..n {
            *o.add(i) = i as u8;
        }
    }
    1
}
unsafe extern "C" fn public_read(
    p: *mut c_void,
    k: u32,
    o: *mut u8,
    cap: usize,
    n: *mut usize,
) -> i32 {
    let d = unsafe { &mut *p.cast::<Public>() };
    if d.fail || k > 1 {
        return -1;
    }
    match &d.keys[k as usize] {
        None => 0,
        Some(b) => {
            if b.len() > cap {
                return -1;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(b.as_ptr(), o, b.len());
                *n = b.len();
            }
            1
        }
    }
}
unsafe extern "C" fn public_write(p: *mut c_void, k: u32, b: *const u8, n: usize) -> i32 {
    assert!(k < 2);
    let d = unsafe { &mut *p.cast::<Public>() };
    d.writes += 1;
    d.keys[k as usize] = Some(unsafe { std::slice::from_raw_parts(b, n) }.to_vec());
    1
}
#[derive(Default)]
struct Platform {
    now: u64,
    step: u64,
    draws: u64,
    fail: bool,
    zero: bool,
    pattern: u8,
}
unsafe extern "C" fn clock(p: *mut c_void) -> u64 {
    let d = unsafe { &mut *p.cast::<Platform>() };
    let now = d.now;
    d.now += d.step;
    now
}
unsafe extern "C" fn entropy(p: *mut c_void, o: *mut u8, n: usize) -> i32 {
    let d = unsafe { &mut *p.cast::<Platform>() };
    d.draws += 1;
    if d.fail {
        return 0;
    }
    assert_eq!(n, 152);
    // Explicit synthetic-only stream. Never used by any device adapter.
    for i in 0..n {
        let block = Sha512::digest([d.draws as u8, (i / 64) as u8]);
        unsafe {
            *o.add(i) = if d.zero {
                0
            } else if d.pattern == 1 {
                255
            } else if d.pattern == 2 {
                (i % 4) as u8
            } else {
                block[i % 64]
            };
        }
    }
    1
}
struct Pending(Vec<u64>);
impl Pending {
    fn new() -> Self {
        let size = unsafe { build8_worker_pending_v2_size() };
        assert!(size <= 5312);
        assert!(unsafe { build8_worker_pending_v2_alignment() } <= 8);
        let mut s = Self(vec![0; size.div_ceil(8)]);
        let p = s.ptr();
        assert_eq!(
            unsafe { build8_worker_pending_v2_init(p, s.0.len() * 8) },
            p
        );
        s
    }
    fn ptr(&mut self) -> *mut c_void {
        self.0.as_mut_ptr().cast()
    }
    fn cleared(&self) -> bool {
        self.0.iter().all(|&x| x == 0)
    }
}
impl Drop for Pending {
    fn drop(&mut self) {
        unsafe { build8_worker_pending_v2_clear(self.ptr()) };
    }
}
struct Channel(Vec<u64>);
impl Channel {
    fn new() -> Self {
        Self(vec![0; unsafe { b8_worker_channel_size() }.div_ceil(8)])
    }
    fn ptr(&mut self) -> *mut c_void {
        self.0.as_mut_ptr().cast()
    }
}
impl Drop for Channel {
    fn drop(&mut self) {
        unsafe { b8_worker_channel_clear(self.ptr()) };
    }
}
struct Fixture {
    _private: Box<Private>,
    public: Box<Public>,
    _backend: Box<PrivateBackend>,
    _store: Box<Store>,
    context: Box<Context>,
    _descriptor: Vec<u8>,
    _scratch: Vec<u64>,
    platform: Box<Platform>,
    local: Local,
    binding: Binding,
    node: HybridKey,
}
impl Fixture {
    fn new() -> Self {
        // Public synthetic entropy; phrase is transient and never exported.
        let phrase = zeroize::Zeroizing::new(
            bip39::Mnemonic::from_entropy(&[42; 32])
                .unwrap()
                .to_string(),
        );
        let owner = HybridKey::wallet_restore(&phrase, Role::WalletOwner).unwrap();
        let node = HybridKey::generate(Role::Node).unwrap();
        let descriptor = node.public().descriptor(1).unwrap();
        let mut h = Sha256::new();
        h.update(b"MUTINY-BUILD8-NODE-AUTHORITY-IDENTITY-V2\0");
        h.update(&descriptor);
        let context = Box::new(Context {
            genesis: [1; 32],
            fingerprint: [2; 32],
            license: [3; 32],
            owner_descriptor: owner_descriptor_id(owner.public(), 1).unwrap(),
            owner_generation: 1,
            coordinator: h.finalize().into(),
            configuration_generation: 1,
            device_mac: [1, 2, 3, 4, 5, 6],
            assignment_generation: 1,
            effective_epoch: 0,
            valid_until_height: 0,
        });
        let mut private = Box::<Private>::default();
        let mut public = Box::<Public>::default();
        let backend = Box::new(PrivateBackend {
            context: (&mut *private as *mut Private).cast(),
            read: private_read,
            write: private_write,
            entropy: private_entropy,
        });
        let store = Box::new(Store {
            context: (&mut *public as *mut Public).cast(),
            read: public_read,
            write: public_write,
        });
        let mut platform = Box::<Platform>::default();
        let mut scratch = vec![0u64; 516];
        let od = owner.public().descriptor(1).unwrap();
        let mut candidate = PublicCandidate {
            unsigned: [0; 512],
            owner: [0; 2048],
            worker: [0; 57],
            proof: [0; 114],
            un: 0,
            on: 0,
        };
        assert_eq!(
            unsafe {
                build8_v2_candidate_prepare(
                    &*backend,
                    &*context,
                    od.as_ptr(),
                    od.len(),
                    build8_v2_mbed_hash256,
                    build8_release_mbed_hash512,
                    &mut candidate,
                )
            },
            1
        );
        let binding = Binding::decode(&candidate.unsigned[..candidate.un]).unwrap();
        let enrollment = Enrollment {
            binding: binding.clone(),
            owner_signature: owner
                .sign(Domain::MinerEnrollment, &binding.bytes().unwrap())
                .unwrap(),
            worker_signature: candidate.proof,
        };
        enrollment.verify(&binding, owner.public()).unwrap();
        let raw = enrollment.bytes().unwrap();
        assert_eq!(
            unsafe {
                build8_v2_activate(
                    &*store,
                    raw.as_ptr(),
                    raw.len(),
                    candidate.unsigned.as_ptr(),
                    candidate.un,
                    od.as_ptr(),
                    od.len(),
                    build8_v2_mbed_hash256,
                    build8_release_mbed_hash512,
                    scratch.as_mut_ptr().cast(),
                    4127,
                )
            },
            1
        );
        let local = Local {
            private: &*backend,
            public: &*store,
            current: &*context,
            descriptor: descriptor.as_ptr(),
            dn: descriptor.len(),
            h256: build8_v2_mbed_hash256,
            h512: build8_release_mbed_hash512,
            workspace: scratch.as_mut_ptr().cast(),
            wn: 4127,
            platform: (&mut *platform as *mut Platform).cast(),
            entropy,
            clock,
        };
        Self {
            _private: private,
            public,
            _backend: backend,
            _store: store,
            context,
            _descriptor: descriptor,
            _scratch: scratch,
            platform,
            local,
            binding,
            node,
        }
    }
    fn hello(&self, s: &mut Pending) -> Vec<u8> {
        let mut hello = vec![0xa5; 1722];
        assert_eq!(
            unsafe {
                build8_worker_pending_v2_begin(s.ptr(), &self.local, 1, 0, hello.as_mut_ptr())
            },
            1
        );
        hello
    }
    fn response(&self, hello: &[u8]) -> (NodePending, Vec<u8>) {
        NodePending::accept(
            HostContext::pinned(&self.binding, self.node.public(), 1).unwrap(),
            &self.node,
            hello,
        )
        .unwrap()
    }
    fn accept(&self, s: &mut Pending, response: &[u8]) -> (i32, Vec<u8>) {
        let mut finish = vec![0xa5; 130];
        let result = unsafe {
            build8_worker_pending_v2_accept(
                s.ptr(),
                &self.local,
                1,
                0,
                response.as_ptr(),
                response.len(),
                finish.as_mut_ptr(),
            )
        };
        if result == 0 {
            assert!(finish.iter().all(|&x| x == 0));
            assert!(s.cleared());
        }
        (result, finish)
    }
}
#[test]
fn full_c_worker_and_rust_node_require_both_finished_then_exchange_frames() {
    let f = Fixture::new();
    let mut s = Pending::new();
    let hello = f.hello(&mut s);
    let (node, response) = f.response(&hello);
    let (status, finish) = f.accept(&mut s, &response);
    assert_eq!(status, 1);
    let (node, tag) = node.finish(&finish).unwrap();
    let mut channel = Channel::new();
    assert_eq!(
        unsafe {
            build8_worker_pending_v2_finish(
                s.ptr(),
                &f.local,
                1,
                0,
                tag.as_ptr(),
                tag.len(),
                channel.ptr(),
            )
        },
        1
    );
    assert!(s.cleared());
    let authority = Authority {
        binding: &f.binding,
        node: f.node.public(),
        node_generation: 1,
        height: 1,
        epoch: 0,
    };
    let mut peer = node.into_channel(&authority).unwrap();
    let context = HostContext::pinned(&f.binding, f.node.public(), 1)
        .unwrap()
        .id();
    let mut wire = vec![0; 16444];
    let mut written = 0;
    let payload = b"typed work remains separately verified";
    assert_eq!(
        unsafe {
            b8_worker_seal(
                channel.ptr(),
                context.as_ptr(),
                1,
                0,
                0,
                payload.as_ptr(),
                payload.len(),
                wire.as_mut_ptr(),
                wire.len(),
                &mut written,
            )
        },
        1
    );
    assert_eq!(peer.open(&authority, &wire[..written]).unwrap(), payload);
    let wire = peer.seal(&authority, b"return path").unwrap();
    let mut plain = vec![0; 16384];
    assert_eq!(
        unsafe {
            b8_worker_open(
                channel.ptr(),
                context.as_ptr(),
                1,
                0,
                0,
                wire.as_ptr(),
                wire.len(),
                plain.as_mut_ptr(),
                plain.len(),
                &mut written,
            )
        },
        1
    );
    assert_eq!(&plain[..written], b"return path");
    assert_eq!(f._private.draws, 1);
    assert_eq!(f._private.writes, 1);
    assert_eq!(f.public.writes, 2);
}
#[test]
fn c_worker_pending_failure_expiry_and_authority_change_erase_state() {
    let mut f = Fixture::new();
    for mode in 0..7 {
        let mut s = Pending::new();
        let hello = f.hello(&mut s);
        let (_, mut response) = f.response(&hello);
        match mode {
            0 => response[1656] ^= 1,
            1 => response[1770] ^= 1,
            2 => {
                response.pop();
            }
            3 => f.platform.now += 60000,
            4 => f.context.assignment_generation += 1,
            5 => f.public.fail = true,
            _ => f.platform.step = 60000,
        }
        assert_eq!(f.accept(&mut s, &response).0, 0);
        f.platform.step = 0;
        f.public.fail = false;
        if mode == 4 {
            f.context.assignment_generation -= 1;
        }
    }
    for mode in 0..5 {
        let mut s = Pending::new();
        let mut hello = [0xa5; 1722];
        match mode {
            0 => f.platform.fail = true,
            1 => f.platform.zero = true,
            2 => f.public.fail = true,
            3 => f.platform.pattern = 1,
            _ => f.platform.pattern = 2,
        }
        assert_eq!(
            unsafe { build8_worker_pending_v2_begin(s.ptr(), &f.local, 1, 0, hello.as_mut_ptr()) },
            0
        );
        assert!(s.cleared());
        assert!(hello.iter().all(|&x| x == 0));
        f.platform.fail = false;
        f.platform.zero = false;
        f.public.fail = false;
        f.platform.pattern = 0;
    }
    let mut s = Pending::new();
    let hello = f.hello(&mut s);
    let (node, response) = f.response(&hello);
    let (status, finish) = f.accept(&mut s, &response);
    assert_eq!(status, 1);
    let (_, mut tag) = node.finish(&finish).unwrap();
    tag[0] ^= 1;
    let mut channel = Channel::new();
    assert_eq!(
        unsafe {
            build8_worker_pending_v2_finish(
                s.ptr(),
                &f.local,
                1,
                0,
                tag.as_ptr(),
                tag.len(),
                channel.ptr(),
            )
        },
        0
    );
    assert!(s.cleared());
    assert!(channel.0.iter().all(|&x| x == 0));
}
#[test]
fn c_worker_final_boundary_replay_and_context_checks_consume_pending_secrets() {
    let mut f = Fixture::new();
    for mode in 0..5 {
        let mut s = Pending::new();
        let hello = f.hello(&mut s);
        let (node, response) = f.response(&hello);
        let (status, finish) = f.accept(&mut s, &response);
        assert_eq!(status, 1);
        let (_, tag) = node.finish(&finish).unwrap();
        let mut channel = Channel::new();
        match mode {
            0 => f.platform.now += 60000,
            1 => f.context.configuration_generation += 1,
            2 => f.public.fail = true,
            3 => f.platform.step = 60000,
            _ => {
                assert_eq!(f.accept(&mut s, &response).0, 0);
            }
        }
        assert_eq!(
            unsafe {
                build8_worker_pending_v2_finish(
                    s.ptr(),
                    &f.local,
                    1,
                    0,
                    tag.as_ptr(),
                    tag.len(),
                    channel.ptr(),
                )
            },
            0
        );
        assert!(s.cleared());
        assert!(channel.0.iter().all(|&x| x == 0));
        f.platform.step = 0;
        f.public.fail = false;
        if mode == 1 {
            f.context.configuration_generation -= 1;
        }
    }
    let mut s = Pending::new();
    let hello = f.hello(&mut s);
    let (_, response) = f.response(&hello);
    let mut other = Pending::new();
    let _ = f.hello(&mut other);
    assert_eq!(f.accept(&mut other, &response).0, 0);
    f.platform.now -= 1;
    assert_eq!(f.accept(&mut s, &response).0, 0);
}
#[test]
fn idle_timer_erases_pending_secrets_at_exact_deadline_and_clock_rollback() {
    let f = Fixture::new();
    for confirmed_phase in [false, true] {
        let mut s = Pending::new();
        let hello = f.hello(&mut s);
        if confirmed_phase {
            let (_, response) = f.response(&hello);
            assert_eq!(f.accept(&mut s, &response).0, 1);
        }
        assert_eq!(
            unsafe { build8_worker_pending_v2_expire(s.ptr(), 59999) },
            1
        );
        assert!(!s.cleared());
        assert_eq!(
            unsafe { build8_worker_pending_v2_expire(s.ptr(), 60000) },
            0
        );
        assert!(s.cleared());
        assert_eq!(
            unsafe { build8_worker_pending_v2_expire(s.ptr(), 60001) },
            0
        );
        assert!(s.cleared());
    }
    let mut s = Pending::new();
    let _ = f.hello(&mut s);
    assert_eq!(unsafe { build8_worker_pending_v2_expire(s.ptr(), 1) }, 1);
    assert_eq!(unsafe { build8_worker_pending_v2_expire(s.ptr(), 0) }, 0);
    assert!(s.cleared());
}

#[test]
fn real_nvs_adapters_complete_crypto_and_reject_storage_faults_without_writes() {
    let _serial = NVS_TEST_LOCK.lock().unwrap();
    let mut f = Fixture::new();
    assert_eq!(unsafe { build8_qual_bind_nvs(&*f._backend, &*f._store) }, 1);
    struct Unbind;
    impl Drop for Unbind {
        fn drop(&mut self) {
            unsafe { build8_qual_unbind_nvs() };
        }
    }
    let _unbind = Unbind;
    f.local.private = std::ptr::null();
    f.local.public = std::ptr::null();
    for mode in 0..4 {
        let mut pending = Pending::new();
        let mut hello = [0; 1722];
        assert_eq!(
            unsafe {
                build8_worker_v2_handshake_begin(pending.ptr(), &f.local, 1, 0, hello.as_mut_ptr())
            },
            1
        );
        let (node, response) = f.response(&hello);
        if mode == 1 {
            f.public.fail = true;
        }
        if mode == 2 {
            f._private.fail = true;
        }
        let mut finish = [0xa5; 130];
        let accepted = unsafe {
            build8_worker_v2_handshake_accept(
                pending.ptr(),
                &f.local,
                1,
                0,
                response.as_ptr(),
                response.len(),
                finish.as_mut_ptr(),
            )
        };
        f.public.fail = false;
        f._private.fail = false;
        if mode == 1 || mode == 2 {
            assert_eq!(accepted, 0);
            assert!(pending.cleared());
            assert_eq!(finish, [0; 130]);
            continue;
        }
        assert_eq!(accepted, 1);
        let (node, tag) = node.finish(&finish).unwrap();
        if mode == 3 {
            f.public.fail = true;
        }
        let mut channel = Channel::new();
        assert_eq!(
            unsafe {
                build8_worker_v2_handshake_finish(
                    pending.ptr(),
                    &f.local,
                    1,
                    0,
                    tag.as_ptr(),
                    tag.len(),
                    channel.ptr(),
                )
            },
            i32::from(mode == 0)
        );
        f.public.fail = false;
        assert!(pending.cleared());
        if mode == 3 {
            assert!(channel.0.iter().all(|&x| x == 0));
            continue;
        }
        let authority = Authority {
            binding: &f.binding,
            node: f.node.public(),
            node_generation: 1,
            height: 1,
            epoch: 0,
        };
        let mut peer = node.into_channel(&authority).unwrap();
        let wire = peer
            .seal(&authority, b"real wrappers, synthetic storage")
            .unwrap();
        let context = HostContext::pinned(&f.binding, f.node.public(), 1)
            .unwrap()
            .id();
        let mut plain = [0; 64];
        let mut written = 0;
        assert_eq!(
            unsafe {
                b8_worker_open(
                    channel.ptr(),
                    context.as_ptr(),
                    1,
                    0,
                    0,
                    wire.as_ptr(),
                    wire.len(),
                    plain.as_mut_ptr(),
                    plain.len(),
                    &mut written,
                )
            },
            1
        );
        assert_eq!(&plain[..written], b"real wrappers, synthetic storage");
    }
    assert_eq!(f._private.draws, 1);
    assert_eq!(f._private.writes, 1);
    assert_eq!(f.public.writes, 2);
}

#[test]
fn bounded_receive_assembles_real_flights_without_implicit_phase_change() {
    let f = Fixture::new();
    let mut pending = Pending::new();
    let hello = f.hello(&mut pending);
    let (node, response) = f.response(&hello);
    let mut buffer = vec![0xa5; 16444];
    let mut receiver = Receive::default();
    assert_eq!(
        unsafe {
            build8_worker_receive_v2_init(&mut receiver, buffer.as_mut_ptr(), buffer.len(), 1)
        },
        1
    );
    for (i, byte) in response.iter().enumerate() {
        let mut consumed = usize::MAX;
        assert_eq!(
            unsafe { build8_worker_receive_v2_feed(&mut receiver, byte, 1, &mut consumed) },
            1
        );
        assert_eq!(consumed, 1);
        assert_eq!(receiver.ready != 0, i + 1 == response.len());
    }
    let mut size = 0;
    let message = unsafe { build8_worker_receive_v2_message(&receiver, &mut size) };
    assert_eq!(
        unsafe { std::slice::from_raw_parts(message, size) },
        response
    );
    let (accepted, finish) = f.accept(&mut pending, &buffer[..size]);
    assert_eq!(accepted, 1);
    let (_, tag) = node.finish(&finish).unwrap();
    unsafe { build8_worker_receive_v2_clear(&mut receiver) };
    assert!(buffer.iter().all(|&x| x == 0));
    assert_eq!(
        unsafe {
            build8_worker_receive_v2_init(&mut receiver, buffer.as_mut_ptr(), buffer.len(), 2)
        },
        1
    );
    let coalesced = [tag.as_slice(), b"next record"].concat();
    let mut consumed = 0;
    assert_eq!(
        unsafe {
            build8_worker_receive_v2_feed(
                &mut receiver,
                coalesced.as_ptr(),
                coalesced.len(),
                &mut consumed,
            )
        },
        1
    );
    assert_eq!(consumed, 16);
    assert_eq!(receiver.kind, 2);
    assert_eq!(receiver.ready, 1);
    let mut channel = Channel::new();
    assert_eq!(
        unsafe {
            build8_worker_pending_v2_finish(
                pending.ptr(),
                &f.local,
                1,
                0,
                buffer.as_ptr(),
                consumed,
                channel.ptr(),
            )
        },
        1
    );
    unsafe { build8_worker_receive_v2_clear(&mut receiver) };
    assert!(buffer.iter().all(|&x| x == 0));
}

#[test]
fn bounded_receive_rejects_hostile_lengths_aliases_and_extra_unhandled_records() {
    let mut receiver = Receive::default();
    let mut buffer = vec![0xa5; 16444];
    for (version, sender, length) in [
        (1, 1, 1),
        (2, 0, 1),
        (2, 1, 0),
        (2, 1, 16385),
        (2, 1, 65535),
    ] {
        assert_eq!(
            unsafe {
                build8_worker_receive_v2_init(&mut receiver, buffer.as_mut_ptr(), buffer.len(), 3)
            },
            1
        );
        let mut header = [0; 44];
        header[0] = version;
        header[1] = sender;
        header[42..].copy_from_slice(&(length as u16).to_be_bytes());
        let mut consumed = 0;
        assert_eq!(
            unsafe {
                build8_worker_receive_v2_feed(
                    &mut receiver,
                    header.as_ptr(),
                    header.len(),
                    &mut consumed,
                )
            },
            0
        );
        assert!(buffer.iter().all(|&x| x == 0));
        assert_eq!(receiver.ready, 0);
        assert!(receiver.storage.is_null());
    }
    for length in [1usize, 255, 16384] {
        let mut frame = vec![0x55; 44 + length + 16];
        frame[0] = 2;
        frame[1] = 1;
        frame[42..44].copy_from_slice(&(length as u16).to_be_bytes());
        assert_eq!(
            unsafe {
                build8_worker_receive_v2_init(&mut receiver, buffer.as_mut_ptr(), buffer.len(), 3)
            },
            1
        );
        let mut consumed = 0;
        assert_eq!(
            unsafe {
                build8_worker_receive_v2_feed(&mut receiver, frame.as_ptr(), 43, &mut consumed)
            },
            1
        );
        assert_eq!(receiver.ready, 0);
        assert_eq!(
            unsafe {
                build8_worker_receive_v2_feed(
                    &mut receiver,
                    frame[43..].as_ptr(),
                    frame.len() - 43,
                    &mut consumed,
                )
            },
            1
        );
        assert_eq!(receiver.ready, 1);
        assert_eq!(&buffer[..frame.len()], frame);
        assert_eq!(
            unsafe {
                build8_worker_receive_v2_feed(&mut receiver, frame.as_ptr(), 1, &mut consumed)
            },
            0
        );
        assert!(buffer.iter().all(|&x| x == 0));
    }
    assert_eq!(
        unsafe {
            build8_worker_receive_v2_init(&mut receiver, buffer.as_mut_ptr(), buffer.len(), 1)
        },
        1
    );
    let mut consumed = 99;
    assert_eq!(
        unsafe { build8_worker_receive_v2_feed(&mut receiver, buffer.as_ptr(), 1, &mut consumed) },
        0
    );
    assert!(buffer.iter().all(|&x| x == 0));
    assert_eq!(consumed, 99);
    for (capacity, kind) in [(15, 2), (3049, 1), (16443, 3), (16444, 0), (16444, 4)] {
        assert_eq!(
            unsafe {
                build8_worker_receive_v2_init(&mut receiver, buffer.as_mut_ptr(), capacity, kind)
            },
            0
        );
    }
}

#[test]
fn owner_connection_handles_partial_io_confirmation_timeout_and_disconnect() {
    let _serial = NVS_TEST_LOCK.lock().unwrap();
    let mut f = Fixture::new();
    assert_eq!(unsafe { build8_qual_bind_nvs(&*f._backend, &*f._store) }, 1);
    struct Unbind;
    impl Drop for Unbind {
        fn drop(&mut self) {
            unsafe { build8_qual_unbind_nvs() };
        }
    }
    let _unbind = Unbind;
    f.local.private = std::ptr::null();
    f.local.public = std::ptr::null();
    let context = HostContext::pinned(&f.binding, f.node.public(), 1)
        .unwrap()
        .id();
    assert!(unsafe { build8_worker_connection_v2_alignment() } <= std::mem::align_of::<u64>());
    for mode in 0..5 {
        let mut owner = vec![0u64; unsafe { build8_worker_connection_v2_size() }.div_ceil(8)];
        let s = owner.as_mut_ptr().cast();
        let mut pending = Pending::new();
        let mut rx = vec![0xa5; 16444];
        let mut tx = vec![0xa5; 16444];
        assert_eq!(
            unsafe {
                build8_worker_connection_v2_start(
                    s,
                    pending.ptr(),
                    build8_worker_pending_v2_size(),
                    rx.as_mut_ptr(),
                    tx.as_mut_ptr(),
                    &f.local,
                    1,
                    0,
                )
            },
            1
        );
        unsafe { build8_qual_runtime_init() };
        assert_eq!(
            unsafe { build8_qual_runtime_guard(s, context.as_ptr(), 1, 0, 0) },
            0
        );
        assert_eq!(unsafe { build8_qual_runtime_flags() }, 1);
        let mut length = 0;
        let bytes = unsafe { build8_worker_connection_v2_out(s, &mut length) };
        assert_eq!(length, 1722);
        let hello = unsafe { std::slice::from_raw_parts(bytes, length) }.to_vec();
        assert_eq!(unsafe { build8_worker_connection_v2_sent(s, 1721) }, 1);
        assert!(!unsafe { build8_worker_connection_v2_out(s, &mut length) }.is_null());
        assert_eq!(length, 1);
        if mode == 1 {
            assert_eq!(
                unsafe { build8_qual_runtime_guard(s, context.as_ptr(), 2, 60000, 0) },
                0
            );
        } else {
            assert_eq!(unsafe { build8_worker_connection_v2_sent(s, 1) }, 1);
            assert!(tx.iter().all(|&x| x == 0));
            let (node, response) = f.response(&hello);
            let mut plain = vec![0xa5; 16384];
            let mut consumed = 0;
            let mut written = 0;
            if mode == 2 {
                assert_eq!(
                    unsafe {
                        build8_worker_connection_v2_receive(
                            s,
                            &f.local,
                            context.as_ptr(),
                            1,
                            0,
                            0,
                            response.as_ptr(),
                            17,
                            &mut consumed,
                            plain.as_mut_ptr(),
                            plain.len(),
                            &mut written,
                        )
                    },
                    1
                );
                assert_eq!(
                    unsafe { build8_qual_runtime_guard(s, context.as_ptr(), 1, 0, 1) },
                    0
                );
                assert_eq!(unsafe { build8_qual_runtime_flags() }, 33);
            } else {
                if mode == 3 {
                    f.public.fail = true;
                }
                let event = unsafe {
                    build8_worker_connection_v2_receive(
                        s,
                        &f.local,
                        context.as_ptr(),
                        1,
                        0,
                        0,
                        response.as_ptr(),
                        response.len(),
                        &mut consumed,
                        plain.as_mut_ptr(),
                        plain.len(),
                        &mut written,
                    )
                };
                f.public.fail = false;
                assert_eq!(event, if mode == 3 { 0 } else { 2 });
                assert_eq!(written, 0);
                assert!(plain.iter().all(|&x| x == 0));
                if mode == 0 || mode == 4 {
                    let bytes = unsafe { build8_worker_connection_v2_out(s, &mut length) };
                    assert_eq!(length, 130);
                    let (node, tag) = node
                        .finish(unsafe { std::slice::from_raw_parts(bytes, length) })
                        .unwrap();
                    assert_eq!(unsafe { build8_worker_connection_v2_sent(s, length) }, 1);
                    let authority = Authority {
                        binding: &f.binding,
                        node: f.node.public(),
                        node_generation: 1,
                        height: 1,
                        epoch: 0,
                    };
                    let mut peer = node.into_channel(&authority).unwrap();
                    let frame = peer
                        .seal(&authority, b"owner controller verified message")
                        .unwrap();
                    let coalesced = [tag.as_slice(), frame.as_slice()].concat();
                    assert_eq!(
                        unsafe {
                            build8_worker_connection_v2_receive(
                                s,
                                &f.local,
                                context.as_ptr(),
                                1,
                                0,
                                0,
                                coalesced.as_ptr(),
                                coalesced.len(),
                                &mut consumed,
                                plain.as_mut_ptr(),
                                plain.len(),
                                &mut written,
                            )
                        },
                        3
                    );
                    assert_eq!(consumed, 16);
                    assert_eq!(written, 0);
                    assert_eq!(
                        unsafe { build8_qual_runtime_guard(s, context.as_ptr(), 1, 0, 0) },
                        1
                    );
                    assert_eq!(unsafe { build8_qual_runtime_flags() }, 5);
                    unsafe { build8_qual_runtime_accounting() };
                    assert_eq!(unsafe { build8_qual_runtime_flags() }, 7);
                    assert_eq!(
                        unsafe { build8_qual_runtime_guard(s, context.as_ptr(), 2, 0, 0) },
                        0
                    );
                    assert_eq!(unsafe { build8_qual_runtime_flags() }, 3);
                    assert_eq!(
                        unsafe { build8_qual_runtime_guard(s, context.as_ptr(), 1, 0, 0) },
                        1
                    );
                    assert_eq!(unsafe { build8_qual_runtime_flags() }, 7);
                    assert_eq!(
                        unsafe {
                            build8_worker_connection_v2_receive(
                                s,
                                &f.local,
                                context.as_ptr(),
                                1,
                                0,
                                0,
                                coalesced[16..].as_ptr(),
                                coalesced.len() - 16,
                                &mut consumed,
                                plain.as_mut_ptr(),
                                plain.len(),
                                &mut written,
                            )
                        },
                        4
                    );
                    assert_eq!(&plain[..written], b"owner controller verified message");
                    let outbound = vec![0x3c; 16384];
                    assert_eq!(
                        unsafe {
                            build8_worker_connection_v2_send(
                                s,
                                context.as_ptr(),
                                1,
                                0,
                                0,
                                outbound.as_ptr(),
                                outbound.len(),
                            )
                        },
                        2
                    );
                    let bytes = unsafe { build8_worker_connection_v2_out(s, &mut length) };
                    let queued = unsafe { std::slice::from_raw_parts(bytes, length) }.to_vec();
                    assert_eq!(
                        unsafe {
                            build8_worker_connection_v2_send(
                                s,
                                context.as_ptr(),
                                1,
                                0,
                                0,
                                b"busy".as_ptr(),
                                4,
                            )
                        },
                        5
                    );
                    assert_eq!(peer.open(&authority, &queued).unwrap(), outbound);
                    assert_eq!(unsafe { build8_worker_connection_v2_sent(s, 1) }, 1);
                    let mut remaining = 0;
                    let bytes = unsafe { build8_worker_connection_v2_out(s, &mut remaining) };
                    assert_eq!(remaining, length - 1);
                    assert_eq!(
                        unsafe { std::slice::from_raw_parts(bytes, remaining) },
                        &queued[1..]
                    );
                    assert_eq!(unsafe { build8_worker_connection_v2_sent(s, remaining) }, 1);
                    assert!(tx.iter().all(|&x| x == 0));
                    assert_eq!(
                        unsafe {
                            build8_worker_connection_v2_send(
                                s,
                                context.as_ptr(),
                                1,
                                0,
                                0,
                                b"next".as_ptr(),
                                4,
                            )
                        },
                        2
                    );
                    let bytes = unsafe { build8_worker_connection_v2_out(s, &mut length) };
                    assert_eq!(
                        peer.open(&authority, unsafe {
                            std::slice::from_raw_parts(bytes, length)
                        })
                        .unwrap(),
                        b"next"
                    );
                    if mode == 0 {
                        assert_eq!(
                            unsafe {
                                build8_qual_runtime_guard(s, context.as_ptr(), 1, 3_600_000, 0)
                            },
                            0
                        );
                        assert_eq!(unsafe { build8_qual_runtime_flags() }, 3);
                    } else {
                        unsafe { build8_qual_runtime_later_clock() };
                        assert_eq!(
                            unsafe { build8_qual_runtime_guard(s, context.as_ptr(), 1, 50, 0) },
                            0
                        );
                        assert_eq!(unsafe { build8_qual_runtime_flags() }, 67);
                        assert_eq!(
                            unsafe { build8_qual_runtime_guard(s, context.as_ptr(), 1, 1000, 0) },
                            0
                        );
                        assert_eq!(unsafe { build8_qual_runtime_flags() }, 67);
                    }
                }
            }
        }
        assert!(pending.cleared());
        assert!(rx.iter().all(|&x| x == 0));
        assert!(tx.iter().all(|&x| x == 0));
        assert!(owner.iter().all(|&x| x == 0));
    }
    assert_eq!(f._private.draws, 1);
    assert_eq!(f._private.writes, 1);
    assert_eq!(f.public.writes, 2);
}

#[test]
fn runtime_binding_matches_independent_worker_identity_and_confirmed_enrollment() {
    let _serial = NVS_TEST_LOCK.lock().unwrap();
    let mut f = Fixture::new();
    assert_eq!(unsafe { build8_qual_bind_nvs(&*f._backend, &*f._store) }, 1);
    struct Unbind;
    impl Drop for Unbind {
        fn drop(&mut self) {
            unsafe { build8_qual_unbind_nvs() };
        }
    }
    let _unbind = Unbind;
    f.local.private = std::ptr::null();
    f.local.public = std::ptr::null();
    let context = HostContext::pinned(&f.binding, f.node.public(), 1)
        .unwrap()
        .id();
    let mut id = [0u8; 32];
    assert_eq!(
        unsafe {
            build8_enrollment_v2_worker_id(
                &*f.context,
                f.binding.worker_public.as_ptr(),
                build8_v2_mbed_hash256,
                id.as_mut_ptr(),
            )
        },
        1
    );
    assert_eq!(id, f.binding.derived_worker_id());
    // Every mutation starts with a fresh, genuinely confirmed session.
    // Parent/job expectations are trusted synthetic fixtures. The positive
    // case also carries genuinely dual-signed work through encrypted traffic.
    for mutation in 0..14 {
        let mut owner = vec![0u64; unsafe { build8_worker_connection_v2_size() }.div_ceil(8)];
        let s = owner.as_mut_ptr().cast();
        let mut pending = Pending::new();
        let mut rx = vec![0u8; 16444];
        let mut tx = vec![0u8; 16444];
        assert_eq!(
            unsafe {
                build8_worker_connection_v2_start(
                    s,
                    pending.ptr(),
                    build8_worker_pending_v2_size(),
                    rx.as_mut_ptr(),
                    tx.as_mut_ptr(),
                    &f.local,
                    1,
                    0,
                )
            },
            1
        );
        let mut n = 0;
        let bytes = unsafe { build8_worker_connection_v2_out(s, &mut n) };
        let hello = unsafe { std::slice::from_raw_parts(bytes, n) }.to_vec();
        assert_eq!(unsafe { build8_worker_connection_v2_sent(s, n) }, 1);
        let (node, response) = f.response(&hello);
        let mut plain = vec![0u8; 16384];
        let mut consumed = 0;
        let mut written = 0;
        assert_eq!(
            unsafe {
                build8_worker_connection_v2_receive(
                    s,
                    &f.local,
                    context.as_ptr(),
                    1,
                    0,
                    0,
                    response.as_ptr(),
                    response.len(),
                    &mut consumed,
                    plain.as_mut_ptr(),
                    plain.len(),
                    &mut written,
                )
            },
            2
        );
        let bytes = unsafe { build8_worker_connection_v2_out(s, &mut n) };
        let (node, tag) = node
            .finish(unsafe { std::slice::from_raw_parts(bytes, n) })
            .unwrap();
        assert_eq!(unsafe { build8_worker_connection_v2_sent(s, n) }, 1);
        assert_eq!(
            unsafe {
                build8_worker_connection_v2_receive(
                    s,
                    &f.local,
                    context.as_ptr(),
                    1,
                    0,
                    0,
                    tag.as_ptr(),
                    tag.len(),
                    &mut consumed,
                    plain.as_mut_ptr(),
                    plain.len(),
                    &mut written,
                )
            },
            3
        );
        assert_eq!(
            unsafe {
                build8_qual_runtime_binding(
                    s,
                    &f.local,
                    f.binding.worker_public.as_ptr(),
                    id.as_ptr(),
                    mutation,
                )
            },
            if mutation == 0 { 1 } else { 0 },
            "mutation {mutation}"
        );
        if mutation == 0 {
            let authority = Authority {
                binding: &f.binding,
                node: f.node.public(),
                node_generation: 1,
                height: 1,
                epoch: 0,
            };
            let mut peer = node.into_channel(&authority).unwrap();
            unsafe { build8_qual_runtime_request(9) };
            // Independent fixture encoder of the existing canonical work codec.
            // Parent, target and timestamp expectations are fixed separately in
            // the C bridge; no envelope initializes its own expected authority.
            let mut w = minicbor::Encoder::new(Vec::new());
            w.array(18)
                .unwrap()
                .u8(1)
                .unwrap()
                .u32(0x4d555401)
                .unwrap()
                .bytes(&f.binding.genesis)
                .unwrap()
                .bytes(&f.binding.fingerprint)
                .unwrap()
                .bytes(&[4; 32])
                .unwrap()
                .u64(1)
                .unwrap()
                .u64(1000)
                .unwrap()
                .bytes(&[5; 32])
                .unwrap()
                .bytes(&[6; 32])
                .unwrap()
                .bytes(&f.binding.license)
                .unwrap()
                .bytes(&id)
                .unwrap()
                .u64(1)
                .unwrap()
                .u64(78)
                .unwrap()
                .bytes(&f.context.coordinator)
                .unwrap()
                .bytes(&[255; 32])
                .unwrap()
                .bytes(&7u64.to_be_bytes())
                .unwrap()
                .bytes(&8u64.to_be_bytes())
                .unwrap()
                .u64(0)
                .unwrap();
            let mut u = minicbor::Encoder::new(Vec::new());
            u.array(3)
                .unwrap()
                .u8(2)
                .unwrap()
                .bytes(&w.into_writer())
                .unwrap()
                .bytes(&f.node.public().descriptor(1).unwrap())
                .unwrap();
            let unsigned = u.into_writer();
            let signature = f.node.sign(Domain::NodeWork, &unsigned).unwrap();
            let mut e = minicbor::Encoder::new(Vec::new());
            e.array(4)
                .unwrap()
                .u8(2)
                .unwrap()
                .bytes(&unsigned)
                .unwrap()
                .bytes(&signature.ed448)
                .unwrap()
                .bytes(&signature.fndsa)
                .unwrap();
            let work = e.into_writer();
            let mut bad = work.clone();
            *bad.last_mut().unwrap() ^= 1;
            let bad_frame = peer.seal(&authority, &bad).unwrap();
            assert_eq!(
                unsafe {
                    build8_worker_connection_v2_receive(
                        s,
                        &f.local,
                        context.as_ptr(),
                        1,
                        0,
                        0,
                        bad_frame.as_ptr(),
                        bad_frame.len(),
                        &mut consumed,
                        plain.as_mut_ptr(),
                        plain.len(),
                        &mut written,
                    )
                },
                4
            );
            assert_eq!(
                unsafe {
                    build8_qual_runtime_reject_signed_work(&f.local, plain.as_ptr(), written)
                },
                1
            );
            plain.fill(0);
            unsafe { build8_qual_runtime_request(10) };
            let frame = peer.seal(&authority, &work).unwrap();
            assert_eq!(
                unsafe {
                    build8_worker_connection_v2_receive(
                        s,
                        &f.local,
                        context.as_ptr(),
                        1,
                        0,
                        0,
                        frame.as_ptr(),
                        frame.len(),
                        &mut consumed,
                        plain.as_mut_ptr(),
                        plain.len(),
                        &mut written,
                    )
                },
                4
            );
            assert_eq!(consumed, frame.len());
            assert_eq!(&plain[..written], work);
            assert_eq!(
                unsafe { build8_qual_runtime_signed_work(&f.local, plain.as_ptr(), written) },
                1
            );
            plain.fill(0);
        } else {
            assert!(unsafe { build8_worker_connection_v2_out(s, &mut n) }.is_null());
            assert!(rx.iter().chain(tx.iter()).all(|&b| b == 0));
            assert!(pending.cleared());
        }
        unsafe { build8_worker_connection_v2_close(s) };
    }
}

#[test]
fn owner_connection_rejects_nested_authority_aliases_before_writing_buffers() {
    let mut f = Fixture::new();
    f.local.private = std::ptr::null();
    f.local.public = std::ptr::null();
    let original_context = f.local.current;
    let original_descriptor = f.local.descriptor;
    let original_workspace = f.local.workspace;
    let original_wn = f.local.wn;
    for mode in 0..3 {
        let mut owner = vec![0u64; unsafe { build8_worker_connection_v2_size() }.div_ceil(8)];
        let mut pending = Pending::new();
        let mut rx = vec![0xa5; 16444];
        let mut tx = vec![0xa5; 16444];
        match mode {
            0 => {
                f.local.workspace = rx.as_mut_ptr().cast();
                f.local.wn = rx.len();
            }
            1 => f.local.current = rx.as_ptr().cast(),
            _ => f.local.descriptor = tx.as_ptr(),
        }
        assert_eq!(
            unsafe {
                build8_worker_connection_v2_start(
                    owner.as_mut_ptr().cast(),
                    pending.ptr(),
                    build8_worker_pending_v2_size(),
                    rx.as_mut_ptr(),
                    tx.as_mut_ptr(),
                    &f.local,
                    1,
                    0,
                )
            },
            0
        );
        assert!(rx.iter().all(|&x| x == 0xa5));
        assert!(tx.iter().all(|&x| x == 0xa5));
        assert!(pending.cleared());
        f.local.current = original_context;
        f.local.descriptor = original_descriptor;
        f.local.workspace = original_workspace;
        f.local.wn = original_wn;
    }
}

#[test]
fn bounded_stream_preserves_coalesced_frames_and_retires_on_io_or_clock_fault() {
    unsafe extern "C" {
        fn build8_qual_stream_init();
        fn build8_qual_stream_input(input: *const u8, n: usize);
        fn build8_qual_stream_output(out: *mut u8, capacity: usize) -> usize;
        fn build8_qual_stream_fault(fault: u32, now: u64);
        fn build8_qual_stream_step(
            c: *mut std::ffi::c_void,
            local: *const Local,
            context: *const u8,
            plain: *mut u8,
            capacity: usize,
            written: *mut usize,
        ) -> i32;
    }
    let _serial = NVS_TEST_LOCK.lock().unwrap();
    let mut f = Fixture::new();
    assert_eq!(unsafe { build8_qual_bind_nvs(&*f._backend, &*f._store) }, 1);
    struct Unbind;
    impl Drop for Unbind {
        fn drop(&mut self) {
            unsafe { build8_qual_unbind_nvs() };
        }
    }
    let _unbind = Unbind;
    f.local.private = std::ptr::null();
    f.local.public = std::ptr::null();
    let context = HostContext::pinned(&f.binding, f.node.public(), 1)
        .unwrap()
        .id();
    // Separate fresh sessions: partial/coalesced success, receive faults,
    // expiry during I/O, clock failure/backstep, and send faults/backpressure.
    for fault in 0..=9 {
        unsafe {
            build8_qual_runtime_init();
            build8_qual_stream_init();
        }
        let mut owner = vec![0u64; unsafe { build8_worker_connection_v2_size() }.div_ceil(8)];
        let c = owner.as_mut_ptr().cast();
        let mut pending = Pending::new();
        let mut rx = vec![0u8; 16444];
        let mut tx = vec![0u8; 16444];
        assert_eq!(
            unsafe {
                build8_worker_connection_v2_start(
                    c,
                    pending.ptr(),
                    build8_worker_pending_v2_size(),
                    rx.as_mut_ptr(),
                    tx.as_mut_ptr(),
                    &f.local,
                    1,
                    0,
                )
            },
            1
        );
        let mut plain = vec![0u8; 16384];
        let mut written = 0;
        let step = |plain: &mut Vec<u8>, written: &mut usize| unsafe {
            build8_qual_stream_step(
                c,
                &f.local,
                context.as_ptr(),
                plain.as_mut_ptr(),
                plain.len(),
                written,
            )
        };
        if (6..=8).contains(&fault) {
            unsafe { build8_qual_stream_fault(fault, 0) };
            assert_eq!(
                step(&mut plain, &mut written),
                if fault == 8 { 1 } else { 0 }
            );
            let mut out = vec![0u8; 65536];
            assert_eq!(
                unsafe { build8_qual_stream_output(out.as_mut_ptr(), out.len()) },
                0
            );
            if fault != 8 {
                assert_eq!(unsafe { build8_qual_runtime_flags() }, 1);
                assert!(pending.cleared());
                continue;
            }
            unsafe { build8_qual_stream_fault(0, 0) };
        }
        let mut hello = Vec::new();
        let mut out = vec![0u8; 65536];
        for _ in 0..100 {
            assert_eq!(step(&mut plain, &mut written), 1);
            let n = unsafe { build8_qual_stream_output(out.as_mut_ptr(), out.len()) };
            hello.extend_from_slice(&out[..n]);
            if hello.len() == 1722 {
                break;
            }
        }
        assert_eq!(hello.len(), 1722);
        let (node, response) = f.response(&hello);
        unsafe {
            build8_qual_stream_input(response.as_ptr(), response.len());
            build8_qual_stream_fault(5, 0);
        }
        let mut event = 1;
        for _ in 0..1000 {
            event = step(&mut plain, &mut written);
            if event != 1 {
                break;
            }
        }
        assert_eq!(event, 2);
        assert_eq!(written, 0);
        let mut finish = Vec::new();
        for _ in 0..10 {
            assert_eq!(step(&mut plain, &mut written), 1);
            let n = unsafe { build8_qual_stream_output(out.as_mut_ptr(), out.len()) };
            finish.extend_from_slice(&out[..n]);
            if finish.len() == 130 {
                break;
            }
        }
        assert_eq!(finish.len(), 130);
        let (node, tag) = node.finish(&finish).unwrap();
        let authority = Authority {
            binding: &f.binding,
            node: f.node.public(),
            node_generation: 1,
            height: 1,
            epoch: 0,
        };
        let mut peer = node.into_channel(&authority).unwrap();
        let one = peer.seal(&authority, b"first exact message").unwrap();
        let two = peer.seal(&authority, b"second exact message").unwrap();
        let wire = [tag.as_slice(), one.as_slice(), two.as_slice()].concat();
        assert!(wire.len() < 1024);
        unsafe {
            build8_qual_stream_input(wire.as_ptr(), wire.len());
            build8_qual_stream_fault(0, 0);
        }
        assert_eq!(step(&mut plain, &mut written), 3);
        assert_eq!(written, 0);
        assert_eq!(
            unsafe { build8_qual_runtime_guard(c, context.as_ptr(), 1, 0, 0) },
            1
        );
        unsafe { build8_qual_runtime_accounting() };
        assert_eq!(step(&mut plain, &mut written), 4);
        assert_eq!(&plain[..written], b"first exact message");
        assert_eq!(step(&mut plain, &mut written), 4);
        assert_eq!(&plain[..written], b"second exact message");
        // No extra callback read was needed for either buffered frame.
        if fault == 0 {
            let outbound = b"outbound while peer sends control";
            assert_eq!(
                unsafe {
                    build8_worker_connection_v2_send(
                        c,
                        context.as_ptr(),
                        1,
                        0,
                        0,
                        outbound.as_ptr(),
                        outbound.len(),
                    )
                },
                2
            );
            let control = peer
                .seal(&authority, b"inbound despite blocked writes")
                .unwrap();
            unsafe {
                build8_qual_stream_input(control.as_ptr(), control.len());
                build8_qual_stream_fault(8, 0);
            }
            assert_eq!(step(&mut plain, &mut written), 1);
            assert_eq!(step(&mut plain, &mut written), 4);
            assert_eq!(&plain[..written], b"inbound despite blocked writes");
            unsafe { build8_qual_stream_fault(0, 0) };
            let mut queued = Vec::new();
            for _ in 0..20 {
                assert_eq!(step(&mut plain, &mut written), 1);
                let n = unsafe { build8_qual_stream_output(out.as_mut_ptr(), out.len()) };
                queued.extend_from_slice(&out[..n]);
                let mut left = 0;
                if unsafe { build8_worker_connection_v2_out(c, &mut left) }.is_null() {
                    break;
                }
            }
            assert_eq!(peer.open(&authority, &queued).unwrap(), outbound);
        }
        if fault == 9 {
            unsafe { build8_qual_stream_fault(0, 100) };
            assert_eq!(step(&mut plain, &mut written), 1);
            unsafe { build8_qual_stream_fault(0, 99) };
        } else {
            unsafe { build8_qual_stream_fault(if fault == 5 { 1 } else { fault }, 0) };
        }
        let result = step(&mut plain, &mut written);
        if [1, 2, 3, 4, 5, 9].contains(&fault) {
            assert_eq!(result, 0);
            assert_eq!(unsafe { build8_qual_runtime_flags() }, 3);
            assert!(rx.iter().chain(tx.iter()).all(|&v| v == 0));
            assert!(pending.cleared());
        } else {
            assert_eq!(result, 1);
        }
        assert_eq!(written, 0);
        assert!(plain.iter().all(|&v| v == 0));
        unsafe { build8_worker_connection_v2_close(c) };
    }
}

#[cfg(target_os = "linux")]
#[test]
fn owned_socket_maintenance_closes_before_parking_and_blocks_on_close_fault() {
    use std::io::Read;
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixStream;
    unsafe extern "C" {
        fn build8_qual_socket_maintenance(fd: i32, fault: u32) -> i32;
    }
    let _lock = NVS_TEST_LOCK.lock().unwrap();
    for fault in 0..3 {
        let (worker, mut peer) = UnixStream::pair().unwrap();
        worker.set_nonblocking(true).unwrap();
        assert_eq!(
            unsafe { build8_qual_socket_maintenance(worker.into_raw_fd(), fault) },
            0,
            "C socket maintenance line"
        );
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).unwrap();
        assert!(bytes.is_empty());
    }
}
#[cfg(target_os = "linux")]
#[test]
fn owned_local_socket_retirement_clears_buffers_and_never_retries_failed_close() {
    use std::io::Read;
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixStream;
    unsafe extern "C" {
        fn build8_qual_socket_owner_retirement(fd: i32, fault: u32) -> i32;
    }
    for fault in 0..2 {
        let (worker, mut peer) = UnixStream::pair().unwrap();
        worker.set_nonblocking(true).unwrap();
        // Sole descriptor ownership explicitly transfers to the actual C owner.
        assert_eq!(
            unsafe { build8_qual_socket_owner_retirement(worker.into_raw_fd(), fault) },
            1
        );
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, [0x42]);
    }
}
#[cfg(target_os = "linux")]
#[test]
fn real_local_socket_c_worker_to_rust_node_handshake_frames_and_eof() {
    use std::io::{Read, Write};
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixStream;
    unsafe extern "C" {
        fn build8_qual_stream_init();
        fn build8_qual_stream_socket_init(fd: i32) -> i32;
        fn build8_qual_stream_socket_step(
            c: *mut std::ffi::c_void,
            local: *const Local,
            context: *const u8,
            plain: *mut u8,
            capacity: usize,
            written: *mut usize,
        ) -> i32;
    }
    let _serial = NVS_TEST_LOCK.lock().unwrap();
    let mut f = Fixture::new();
    assert_eq!(unsafe { build8_qual_bind_nvs(&*f._backend, &*f._store) }, 1);
    struct Unbind;
    impl Drop for Unbind {
        fn drop(&mut self) {
            unsafe { build8_qual_unbind_nvs() };
        }
    }
    let _unbind = Unbind;
    f.local.private = std::ptr::null();
    f.local.public = std::ptr::null();
    let context = HostContext::pinned(&f.binding, f.node.public(), 1)
        .unwrap()
        .id();
    let (worker, mut peer_socket) = UnixStream::pair().unwrap();
    worker.set_nonblocking(true).unwrap();
    peer_socket.set_nonblocking(true).unwrap();
    unsafe {
        build8_qual_runtime_init();
        build8_qual_stream_init();
    }
    assert_eq!(
        unsafe { build8_qual_stream_socket_init(worker.into_raw_fd()) },
        1
    );
    let mut owner = vec![0u64; unsafe { build8_worker_connection_v2_size() }.div_ceil(8)];
    let c = owner.as_mut_ptr().cast();
    let mut pending = Pending::new();
    let mut rx = vec![0u8; 16444];
    let mut tx = vec![0u8; 16444];
    let mut plain = vec![0u8; 16384];
    let mut written = 0;
    assert_eq!(
        unsafe {
            build8_worker_connection_v2_start(
                c,
                pending.ptr(),
                build8_worker_pending_v2_size(),
                rx.as_mut_ptr(),
                tx.as_mut_ptr(),
                &f.local,
                1,
                0,
            )
        },
        1
    );
    let step = |plain: &mut Vec<u8>, written: &mut usize| unsafe {
        build8_qual_stream_socket_step(
            c,
            &f.local,
            context.as_ptr(),
            plain.as_mut_ptr(),
            plain.len(),
            written,
        )
    };
    let receive = |peer: &mut UnixStream, bytes: &mut Vec<u8>| {
        let mut buf = [0u8; 1024];
        match peer.read(&mut buf) {
            Ok(n) => {
                assert!(n > 0);
                bytes.extend_from_slice(&buf[..n]);
            }
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::WouldBlock),
        }
    };
    let mut hello = Vec::new();
    for _ in 0..20 {
        assert_eq!(step(&mut plain, &mut written), 1);
        receive(&mut peer_socket, &mut hello);
        if hello.len() == 1722 {
            break;
        }
    }
    assert_eq!(hello.len(), 1722);
    let (node, response) = f.response(&hello);
    peer_socket.write_all(&response).unwrap();
    let mut event = 1;
    for _ in 0..20 {
        event = step(&mut plain, &mut written);
        if event != 1 {
            break;
        }
    }
    assert_eq!(event, 2);
    let mut finish = Vec::new();
    for _ in 0..20 {
        assert_eq!(step(&mut plain, &mut written), 1);
        receive(&mut peer_socket, &mut finish);
        if finish.len() == 130 {
            break;
        }
    }
    let (node, tag) = node.finish(&finish).unwrap();
    let authority = Authority {
        binding: &f.binding,
        node: f.node.public(),
        node_generation: 1,
        height: 1,
        epoch: 0,
    };
    let mut peer = node.into_channel(&authority).unwrap();
    let frame = peer
        .seal(&authority, b"real socket authenticated bytes")
        .unwrap();
    peer_socket
        .write_all(&[tag.as_slice(), frame.as_slice()].concat())
        .unwrap();
    assert_eq!(step(&mut plain, &mut written), 3);
    assert_eq!(written, 0);
    assert_eq!(
        unsafe { build8_qual_runtime_guard(c, context.as_ptr(), 1, 0, 0) },
        1
    );
    unsafe { build8_qual_runtime_accounting() };
    assert_eq!(step(&mut plain, &mut written), 4);
    assert_eq!(&plain[..written], b"real socket authenticated bytes");
    let outbound = b"real socket return bytes";
    assert_eq!(
        unsafe {
            build8_worker_connection_v2_send(
                c,
                context.as_ptr(),
                1,
                0,
                0,
                outbound.as_ptr(),
                outbound.len(),
            )
        },
        2
    );
    assert_eq!(step(&mut plain, &mut written), 1);
    let mut wire = Vec::new();
    receive(&mut peer_socket, &mut wire);
    assert_eq!(peer.open(&authority, &wire).unwrap(), outbound);
    drop(peer_socket);
    assert_eq!(step(&mut plain, &mut written), 0);
    assert_eq!(written, 0);
    assert!(
        plain
            .iter()
            .chain(rx.iter())
            .chain(tx.iter())
            .all(|&v| v == 0)
    );
    assert!(pending.cleared());
    assert_eq!(unsafe { build8_qual_runtime_flags() }, 3);
}
