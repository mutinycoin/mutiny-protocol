//! PUBLIC RAM journal fault model only. Genuine canonical policy is installed
//! by the separate certified-block test; this model alone claims no finality.
use super::*;
use super::ordinary_fixture::Ordinary;
use mutiny_consensus_v8::license_assignment_v2::Assignment;
#[path="journal_runtime_fixture.rs"]
mod runtime;
const FAULT: i32 = -1;
const CONFLICT: i32 = -2;
const FULL: i32 = -3;
const DENIED: i32 = -4;
const STORED: i32 = 1;
const PENDING: i32 = 2;
const ACTIVE: i32 = 3;
#[repr(C)]
struct Backend {
    context: *mut c_void, slots: usize,
    read: unsafe extern "C" fn(*mut c_void, usize, *mut u8, usize, *mut usize) -> i32,
    append: unsafe extern "C" fn(*mut c_void, usize, *const u8, usize) -> i32,
    read_marker: unsafe extern "C" fn(*mut c_void, usize, *mut u8, usize, *mut usize) -> i32,
    append_marker: unsafe extern "C" fn(*mut c_void, usize, *const u8, usize) -> i32,
}
#[repr(C)]
struct Provider {
    context: *mut c_void,
    candidate: unsafe extern "C" fn(*mut c_void, *const u8, usize, *const u8, usize, *const u8, usize) -> i32,
    active: unsafe extern "C" fn(*mut c_void, *const u8, usize, u64, u64) -> i32,
}
#[repr(C)]
struct JournalLocal { base: Local, journal: *const Backend, authority: *const Provider }
unsafe extern "C" {
    fn build8_worker_assignment_pending_v2_accept(p: *mut c_void, a: *const Local, h: u64, e: u64,
        raw: *const u8, n: usize, out: *mut u8) -> i32;
    fn build8_worker_assignment_pending_v2_finish(p: *mut c_void, a: *const Local, h: u64, e: u64,
        raw: *const u8, n: usize, out: *mut c_void) -> i32;
    fn build8_v2_assignment_candidate_reprove(b: *const PrivateBackend, a: *const Provider, context: *const Context,
        owner: *const u8, on: usize, node: *const u8, nn: usize, h256: Hash, h512: Hash, out: *mut PublicCandidate) -> i32;
    fn build8_v2_assignment_journal_put(j: *const Backend, a: *const Provider, raw: *const u8, n: usize,
        h256: Hash, h512: Hash, workspace: *mut c_void, wn: usize, id: *mut u8) -> i32;
    fn build8_v2_assignment_journal_activate(j: *const Backend, a: *const Provider, id: *const u8,
        context: *const Context, height: u64, epoch: u64, h256: Hash, h512: Hash, ws: *mut c_void, wn: usize) -> i32;
    fn build8_v2_assignment_journal_restore(j: *const Backend, a: *const Provider, id: *const u8,
        context: *const Context, height: u64, epoch: u64, h256: Hash, h512: Hash, ws: *mut c_void, wn: usize,
        out: *mut u8, capacity: usize, length: *mut usize) -> i32;
    fn build8_v2_assignment_journal_current(b: *const PrivateBackend, j: *const Backend, a: *const Provider,
        current: *const Context, node: *const u8, nn: usize, h: u64, e: u64, h256: Hash, h512: Hash,
        workspace: *mut c_void, wn: usize, worker: *mut u8, session: *mut u8) -> i32;
    fn build8_worker_journal_pending_v2_begin(p: *mut c_void, a: *const JournalLocal, h: u64, e: u64, out: *mut u8) -> i32;
    fn build8_worker_journal_pending_v2_accept(p: *mut c_void, a: *const JournalLocal, h: u64, e: u64, raw: *const u8,
        n: usize, out: *mut u8) -> i32;
    fn build8_worker_journal_pending_v2_finish(p: *mut c_void, a: *const JournalLocal, h: u64, e: u64, raw: *const u8,
        n: usize, out: *mut c_void) -> i32;
}
#[derive(Default)]
struct Rows {
    records: Vec<Option<Vec<u8>>>, markers: Vec<Option<Vec<u8>>>, writes: usize,
    append_fault: u8, marker_fault: u8, read_fault: Option<usize>, corrupt_after_append: bool,
}
unsafe extern "C" fn read(p: *mut c_void, slot: usize, out: *mut u8, cap: usize, length: *mut usize) -> i32 {
    let rows = unsafe { &mut *p.cast::<Rows>() };
    if rows.read_fault == Some(slot) || slot >= rows.records.len() { return -1; }
    let Some(raw) = &rows.records[slot] else { return 0; };
    if raw.len() > cap { return -1; }
    unsafe { std::ptr::copy_nonoverlapping(raw.as_ptr(), out, raw.len()); *length = raw.len(); }
    1
}
unsafe extern "C" fn read_marker(p: *mut c_void, slot: usize, out: *mut u8, cap: usize, length: *mut usize) -> i32 {
    let rows = unsafe { &mut *p.cast::<Rows>() };
    if slot >= rows.markers.len() { return -1; }
    let Some(raw) = &rows.markers[slot] else { return 0; };
    if raw.len() > cap { return -1; }
    unsafe { std::ptr::copy_nonoverlapping(raw.as_ptr(), out, raw.len()); *length = raw.len(); }
    1
}
unsafe extern "C" fn append(p: *mut c_void, slot: usize, raw: *const u8, n: usize) -> i32 {
    let rows = unsafe { &mut *p.cast::<Rows>() };
    if slot >= rows.records.len() || rows.records[slot].is_some() || rows.append_fault == 1 { return 0; }
    let mut bytes = unsafe { std::slice::from_raw_parts(raw, n) }.to_vec();
    if rows.append_fault == 3 { bytes.truncate(n / 2); }
    if rows.corrupt_after_append { bytes[0] ^= 1; }
    rows.records[slot] = Some(bytes); rows.writes += 1;
    i32::from(rows.append_fault == 0)
}
unsafe extern "C" fn append_marker(p: *mut c_void, slot: usize, raw: *const u8, n: usize) -> i32 {
    let rows = unsafe { &mut *p.cast::<Rows>() };
    if slot >= rows.markers.len() || rows.markers[slot].is_some() || rows.marker_fault == 1 { return 0; }
    let mut bytes = unsafe { std::slice::from_raw_parts(raw, n) }.to_vec();
    if rows.marker_fault == 3 { bytes.truncate(n / 2); }
    rows.markers[slot] = Some(bytes); rows.writes += 1;
    i32::from(rows.marker_fault == 0)
}
pub(super) type CandidateRule = Box<dyn Fn(&[u8], &[u8], &[u8]) -> bool>;
pub(super) type ActiveRule = Box<dyn Fn(&[u8], u64, u64) -> bool>;
struct Policy {
    unsigned: Vec<u8>, owner: Vec<u8>, node: Vec<u8>, active_raw: Option<Vec<u8>>,
    candidate_calls: usize, active_calls: usize, candidate_deny_at: Option<usize>, active_deny_at: Option<usize>,
    candidate_rule: Option<CandidateRule>, active_rule: Option<ActiveRule>,
}
unsafe extern "C" fn candidate(p: *mut c_void, raw: *const u8, n: usize, owner: *const u8, on: usize,
    node: *const u8, nn: usize) -> i32 {
    if n == 0 || n > 512 || on == 0 || on > 2048 || nn == 0 || nn > 2048 { return 0; }
    let policy = unsafe { &mut *p.cast::<Policy>() };
    policy.candidate_calls += 1;
    if policy.candidate_deny_at.is_some_and(|at| policy.candidate_calls >= at) { return 0; }
    let (raw, owner, node) = unsafe { (std::slice::from_raw_parts(raw, n), std::slice::from_raw_parts(owner, on),
        std::slice::from_raw_parts(node, nn)) };
    i32::from(if let Some(rule) = &policy.candidate_rule { rule(raw, owner, node) }
        else { raw == policy.unsigned && owner == policy.owner && node == policy.node })
}
unsafe extern "C" fn active(p: *mut c_void, raw: *const u8, n: usize, height: u64, epoch: u64) -> i32 {
    if n == 0 || n > 8192 { return 0; }
    let policy = unsafe { &mut *p.cast::<Policy>() };
    policy.active_calls += 1;
    if policy.active_deny_at.is_some_and(|at| policy.active_calls >= at) { return 0; }
    let raw = unsafe { std::slice::from_raw_parts(raw, n) };
    i32::from(if let Some(rule) = &policy.active_rule { rule(raw, height, epoch) }
        else { policy.active_raw.as_deref() == Some(raw) && height > 0 && epoch >= 2 })
}
pub(super) fn context(b: &Binding) -> Context {
    Context { genesis: b.genesis, fingerprint: b.fingerprint, license: b.license, owner_descriptor: b.owner_descriptor,
        owner_generation: b.owner_generation, coordinator: b.coordinator, configuration_generation: b.configuration_generation,
        device_mac: b.device_mac, assignment_generation: b.assignment_generation, effective_epoch: b.effective_epoch,
        valid_until_height: b.valid_until_height }
}
fn local(a: &Local) -> Local {
    Local { private: a.private, public: a.public, current: a.current, descriptor: a.descriptor, dn: a.dn,
        h256: a.h256, h512: a.h512, workspace: a.workspace, wn: a.wn, platform: a.platform, entropy: a.entropy, clock: a.clock }
}
pub(super) struct Journal {
    rows: Box<Rows>, backend: Box<Backend>, policy: Box<Policy>, authority: Box<Provider>, scratch: Vec<u64>,
}
impl Journal {
    pub(super) fn runtime_route(&mut self,worker:&mut Ordinary,binding:&Binding,node:&HybridKey,
        work:&mutiny_consensus_v8::pow::WorkContext,epoch:u64,offer:Option<(&[u8],[u8;32],u64)>,fault:u32,change:Option<&mut dyn FnMut()>){
        runtime::route(self,worker,binding,node,work,epoch,offer,fault,change);
    }
    #[cfg(target_os="linux")]
    pub(super) fn runtime_socket_route(&mut self,worker:&mut Ordinary,binding:&Binding,node:&HybridKey,
        work:&mutiny_consensus_v8::pow::WorkContext,epoch:u64,offer:Option<(&[u8],[u8;32],u64)>,fault:u32,change:Option<&mut dyn FnMut()>){
        runtime::route_socket(self,worker,binding,node,work,epoch,offer,fault,change);
    }
    pub(super) fn model(worker: &Ordinary, slots: usize) -> Self {
        let mut rows = Box::new(Rows { records: vec![None; slots], markers: vec![None; slots], ..Default::default() });
        let backend = Box::new(Backend { context: (&mut *rows as *mut Rows).cast(), slots,
            read, append, read_marker, append_marker });
        let mut policy = Box::new(Policy { unsigned: worker.binding.bytes().unwrap(), owner: worker.owner_descriptor.clone(),
            node: worker.descriptor.clone(), active_raw: None, candidate_calls: 0, active_calls: 0,
            candidate_deny_at: None, active_deny_at: None, candidate_rule: None, active_rule: None });
        let authority = Box::new(Provider { context: (&mut *policy as *mut Policy).cast(), candidate, active });
        Self { rows, backend, policy, authority, scratch: vec![0; 516] }
    }
    pub(super) fn rules(&mut self, candidate: CandidateRule, active: ActiveRule) {
        self.policy.candidate_rule = Some(candidate); self.policy.active_rule = Some(active);
    }
    pub(super) fn set_model_candidate(&mut self, binding: &Binding, owner: &[u8]) {
        self.policy.unsigned = binding.bytes().unwrap(); self.policy.owner = owner.to_vec();
    }
    pub(super) fn reprove(&mut self, worker: &mut Ordinary, binding: &Binding, owner: &[u8]) -> (i32, PublicCandidate) {
        let current = context(binding);
        let mut out = PublicCandidate { unsigned: [7; 512], owner: [7; 2048], worker: [7; 57], proof: [7; 114], un: 7, on: 7 };
        let result = unsafe { build8_v2_assignment_candidate_reprove(&*worker.backend, &*self.authority, &current,
            owner.as_ptr(), owner.len(), worker.descriptor.as_ptr(), worker.descriptor.len(),
            build8_v2_mbed_hash256, build8_release_mbed_hash512, &mut out) };
        worker.assert_birth_unchanged();
        if result == 0 { assert_eq!((out.un, out.on), (0, 0)); assert!(out.unsigned.iter().chain(out.owner.iter())
            .chain(out.worker.iter()).chain(out.proof.iter()).all(|b| *b == 0)); }
        (result, out)
    }
    pub(super) fn put(&mut self, a: &Assignment) -> (i32, [u8; 32]) { self.put_raw(&a.encode().unwrap()) }
    fn put_raw(&mut self, raw: &[u8]) -> (i32, [u8; 32]) {
        let mut id = [7; 32];
        let result = unsafe { build8_v2_assignment_journal_put(&*self.backend, &*self.authority, raw.as_ptr(), raw.len(),
            build8_v2_mbed_hash256, build8_release_mbed_hash512, self.scratch.as_mut_ptr().cast(), 4127, id.as_mut_ptr()) };
        if result != STORED { assert_eq!(id, [0; 32]); }
        (result, id)
    }
    pub(super) fn activate(&mut self, a: &Assignment, height: u64, epoch: u64) -> i32 {
        let id = mutiny_consensus_v8::op_envelope_v1::assignment_id(a).unwrap();
        let current = context(&a.enrollment.binding);
        unsafe { build8_v2_assignment_journal_activate(&*self.backend, &*self.authority, id.as_ptr(), &current,
            height, epoch, build8_v2_mbed_hash256, build8_release_mbed_hash512, self.scratch.as_mut_ptr().cast(), 4127) }
    }
    pub(super) fn restore(&mut self, a: &Assignment, height: u64, epoch: u64) -> (i32, Vec<u8>) {
        let id = mutiny_consensus_v8::op_envelope_v1::assignment_id(a).unwrap();
        let current = context(&a.enrollment.binding);
        let mut raw = vec![7; 8192]; let mut length = 7;
        let status = unsafe { build8_v2_assignment_journal_restore(&*self.backend, &*self.authority, id.as_ptr(), &current,
            height, epoch, build8_v2_mbed_hash256, build8_release_mbed_hash512, self.scratch.as_mut_ptr().cast(), 4127,
            raw.as_mut_ptr(), raw.len(), &mut length) };
        if status == ACTIVE { raw.truncate(length); } else { assert_eq!(length, 0); assert!(raw.iter().all(|b| *b == 0)); raw.clear(); }
        (status, raw)
    }
    pub(super) fn records(&self) -> Vec<Option<Vec<u8>>> { self.rows.records.clone() }
    fn frame_gate(&mut self, worker: &mut Ordinary, binding: &Binding, height: u64, epoch: u64) {
        let mut public = [7; 57]; let mut session = [7; 64];
        assert_eq!(unsafe { build8_v2_assignment_journal_current(&*worker.backend, &*self.backend, &*self.authority,
            &*worker.context, worker.descriptor.as_ptr(), worker.descriptor.len(), height, epoch,
            build8_v2_mbed_hash256, build8_release_mbed_hash512, self.scratch.as_mut_ptr().cast(), 4127,
            public.as_mut_ptr(), session.as_mut_ptr()) }, 1);
        assert_eq!(public, binding.worker_public); assert_eq!(session,
            HostContext::pinned(binding, &mutiny_crypto_v2::PublicKey::decode_descriptor(&worker.descriptor).unwrap().0, 1).unwrap().id());
        worker.assert_birth_unchanged();
    }
    pub(super) fn coherent_public_edit_for_test(&mut self, slot: usize, a: &Assignment) {
        a.verify_signatures().unwrap();
        let enrollment = a.enrollment.bytes().unwrap(); let mut marker = b"B8V2ACT\x01".to_vec(); let mut digest = [0; 32];
        assert_eq!(unsafe { build8_v2_mbed_hash256(b"MUTINY-BUILD8-ENROLLMENT-ACTIVATION-V2\0".as_ptr().cast(),
            enrollment.as_ptr(), enrollment.len(), digest.as_mut_ptr()) }, 1);
        marker.extend_from_slice(&digest); self.rows.records[slot] = Some(a.encode().unwrap()); self.rows.markers[slot] = Some(marker);
    }
    pub(super) fn handshake(&mut self, worker: &mut Ordinary, binding: &Binding, node: &HybridKey, height: u64, epoch: u64) {
        assert!(height > binding.valid_until_height);
        *worker.context = context(binding);
        let local = JournalLocal { base: local(&worker.local), journal: &*self.backend, authority: &*self.authority };
        let mut pending = Pending::new(); let mut hello = vec![0; 1722];
        assert_eq!(unsafe { build8_worker_journal_pending_v2_begin(pending.ptr(), &local, height, epoch, hello.as_mut_ptr()) }, 1);
        let (peer, response) = NodePending::accept(HostContext::pinned(binding, node.public(), 1).unwrap(), node, &hello).unwrap();
        let mut finish = vec![0; 130];
        assert_eq!(unsafe { build8_worker_journal_pending_v2_accept(pending.ptr(), &local, height, epoch,
            response.as_ptr(), response.len(), finish.as_mut_ptr()) }, 1);
        let (peer, tag) = peer.finish(&finish).unwrap(); let mut channel = Channel::new();
        assert_eq!(unsafe { build8_worker_journal_pending_v2_finish(pending.ptr(), &local, height, epoch,
            tag.as_ptr(), tag.len(), channel.ptr()) }, 1); assert!(pending.cleared());
        let authority = Authority { binding, node: node.public(), node_generation: 1, height, epoch };
        let mut peer = peer.into_channel(&authority).unwrap();
        let id = HostContext::pinned(binding, node.public(), 1).unwrap().id();
        let mut wire = vec![0; 16444]; let mut length = 0;
        self.frame_gate(worker, binding, height, epoch);
        assert_eq!(unsafe { b8_worker_seal(channel.ptr(), id.as_ptr(), height, epoch, 0, b"journal assignment".as_ptr(),
            18, wire.as_mut_ptr(), wire.len(), &mut length) }, 1);
        assert_eq!(peer.open(&authority, &wire[..length]).unwrap(), b"journal assignment");
        let wire = peer.seal(&authority, b"journal return").unwrap(); let mut plain = vec![0; 16384];
        self.frame_gate(worker, binding, height, epoch);
        assert_eq!(unsafe { b8_worker_open(channel.ptr(), id.as_ptr(), height, epoch, 0, wire.as_ptr(), wire.len(),
            plain.as_mut_ptr(), plain.len(), &mut length) }, 1); assert_eq!(&plain[..length], b"journal return");
        worker.assert_birth_unchanged();
    }
}
fn component() -> (Ordinary, HybridKey, HybridKey, Assignment) {
    // Public qualified TEST mnemonic, using the real wallet-custody boundary.
    let owner = HybridKey::wallet_restore(&("zoo ".repeat(23) + "vote"), Role::WalletOwner).unwrap();
    let node = HybridKey::generate(Role::Node).unwrap();
    let descriptor = node.public().descriptor(1).unwrap();
    let current = Context { genesis: [1; 32], fingerprint: [2; 32], license: [3; 32], owner_descriptor: owner_descriptor_id(owner.public(), 1).unwrap(),
        owner_generation: 1, coordinator: mutiny_consensus_v8::work_authority_v2::node_identity(&descriptor).unwrap(),
        configuration_generation: 1, device_mac: [2, 0, 0, 0, 0, 13], assignment_generation: 3, effective_epoch: 2, valid_until_height: 2 };
    let worker = Ordinary::prepare(current, &owner, &node); let binding = worker.binding.clone();
    let a = Assignment { enrollment: Enrollment { owner_signature: owner.sign(Domain::MinerEnrollment, &binding.bytes().unwrap()).unwrap(),
        worker_signature: worker.possession, binding }, owner_descriptor: owner.public().descriptor(1).unwrap(), node_descriptor: descriptor };
    a.verify_signatures().unwrap(); (worker, owner, node, a)
}
#[test]
fn journal_exact_bytes_pending_active_reopen_and_stale_duplicates() {
    let (worker, _, _, a) = component(); let mut journal = Journal::model(&worker, 2);
    let expected = a.encode().unwrap(); let id = mutiny_consensus_v8::op_envelope_v1::assignment_id(&a).unwrap();
    assert_eq!(journal.put(&a), (STORED, id)); assert_eq!(journal.rows.writes, 1);
    assert_eq!(journal.activate(&a, 4, 2), DENIED); assert!(journal.rows.markers.iter().all(Option::is_none));
    journal.policy.active_raw = Some(expected.clone());
    assert_eq!(journal.restore(&a, 4, 2).0, PENDING); assert_eq!(journal.activate(&a, 4, 2), ACTIVE);
    assert_eq!(journal.restore(&a, 4, 2), (ACTIVE, expected.clone()));
    // No cache survives the simulated interface re-open; the exact same rows
    // are restored by fresh objects and all signatures/current policy checks.
    let records = journal.rows.records.clone(); let markers = journal.rows.markers.clone();
    let mut reopened = Journal::model(&worker, 2); reopened.rows.records = records; reopened.rows.markers = markers;
    reopened.policy.active_raw = Some(expected.clone()); assert_eq!(reopened.restore(&a, 4, 2), (ACTIVE, expected));
    reopened.policy.active_raw = None; reopened.policy.candidate_deny_at = Some(1);
    assert_eq!(reopened.restore(&a, 4, 2).0, DENIED); assert_eq!(reopened.put(&a), (STORED, id));
    assert_eq!(reopened.rows.writes, 0); worker.assert_birth_unchanged();
}
#[test]
fn journal_reproves_existing_identity_without_private_writes_or_entropy() {
    let (mut worker, owner, node, a) = component(); let mut journal = Journal::model(&worker, 2);
    assert_eq!(journal.put(&a).0, STORED); let old = journal.records();
    let mut binding = worker.binding.clone(); binding.effective_epoch = 3; binding.valid_until_height = 3;
    journal.set_model_candidate(&binding, &a.owner_descriptor);
    let (status, proof) = journal.reprove(&mut worker, &binding, &a.owner_descriptor); assert_eq!(status, 1);
    assert_eq!(Binding::decode(&proof.unsigned[..proof.un]).unwrap(), binding); binding.verify_worker_possession(&proof.proof).unwrap();
    let fresh = Assignment { enrollment: Enrollment { owner_signature: owner.sign(Domain::MinerEnrollment, &binding.bytes().unwrap()).unwrap(),
        worker_signature: proof.proof, binding: binding.clone() }, owner_descriptor: a.owner_descriptor, node_descriptor: a.node_descriptor };
    assert_eq!(journal.put(&fresh).0, STORED); assert_eq!(journal.rows.records[0], old[0]);
    journal.policy.active_raw = Some(fresh.encode().unwrap()); assert_eq!(journal.activate(&fresh, 5, 3), ACTIVE);
    journal.handshake(&mut worker, &binding, &node, 5, 3); worker.assert_birth_unchanged();
}
#[test]
fn journal_same_id_wire_conflicts_and_capacity_do_not_replace_records() {
    let (mut worker, owner, _, a) = component(); let mut journal = Journal::model(&worker, 1);
    assert_eq!(journal.put(&a).0, STORED); let records = journal.records();
    let alternate = (0..8).find_map(|_| {
        let mut alternate = a.clone();
        alternate.enrollment.owner_signature = owner.sign(Domain::MinerEnrollment, &a.enrollment.binding.bytes().unwrap()).unwrap();
        (alternate.encode().unwrap() != a.encode().unwrap()).then_some(alternate)
    }).expect("a genuinely different valid randomized signature within eight attempts");
    alternate.verify_signatures().unwrap(); assert_eq!(journal.put(&alternate).0, CONFLICT); assert_eq!(journal.records(), records);
    let mut binding = worker.binding.clone(); binding.effective_epoch = 3; binding.valid_until_height = 3;
    journal.set_model_candidate(&binding, &a.owner_descriptor); let (status, proof) = journal.reprove(&mut worker, &binding, &a.owner_descriptor);
    assert_eq!(status, 1); let fresh = Assignment { enrollment: Enrollment { owner_signature: owner.sign(Domain::MinerEnrollment,
        &binding.bytes().unwrap()).unwrap(), worker_signature: proof.proof, binding }, ..a };
    assert_eq!(journal.put(&fresh).0, FULL); assert_eq!(journal.records(), records); worker.assert_birth_unchanged();
}
#[test]
fn journal_partial_and_completed_failed_appends_are_preserved() {
    let (worker, _, _, a) = component();
    for fault in [1, 2, 3] {
        let mut journal = Journal::model(&worker, 2); journal.rows.append_fault = fault;
        assert_eq!(journal.put(&a).0, FAULT); let records = journal.records();
        assert_eq!(records[0].is_some(), fault != 1); journal.rows.append_fault = 0;
        assert_eq!(journal.put(&a).0, if fault == 3 { FAULT } else { STORED });
        if fault == 3 { assert_eq!(journal.records(), records); }
        assert!(journal.rows.markers.iter().all(Option::is_none));
    }
    let mut journal = Journal::model(&worker, 2); journal.rows.corrupt_after_append = true;
    assert_eq!(journal.put(&a).0, FAULT); assert!(journal.rows.records[0].is_some());
    let records = journal.records(); assert_eq!(journal.put(&a).0, FAULT); assert_eq!(journal.records(), records);
    let mut journal = Journal::model(&worker, 2); journal.policy.candidate_deny_at = Some(3);
    assert_eq!(journal.put(&a).0, DENIED); assert_eq!(journal.rows.records[0], Some(a.encode().unwrap()));
    let records = journal.records(); assert_eq!(journal.put(&a).0, STORED); assert_eq!(journal.records(), records);
    assert_eq!(journal.restore(&a, 4, 2).0, DENIED);
    worker.assert_birth_unchanged();
}
#[test]
fn journal_partial_activation_or_canonical_change_cannot_restore_active() {
    let (worker, _, _, a) = component();
    for fault in [1, 2, 3] {
        let mut journal = Journal::model(&worker, 2); assert_eq!(journal.put(&a).0, STORED);
        journal.policy.active_raw = Some(a.encode().unwrap()); journal.rows.marker_fault = fault;
        assert_eq!(journal.activate(&a, 4, 2), FAULT); let markers = journal.rows.markers.clone();
        journal.rows.marker_fault = 0;
        assert_eq!(journal.restore(&a, 4, 2).0, match fault { 1 => PENDING, 2 => ACTIVE, _ => FAULT });
        assert_eq!(journal.rows.markers, markers);
        journal.policy.active_raw = None; assert_ne!(journal.restore(&a, 4, 2).0, ACTIVE);
    }
    let mut journal = Journal::model(&worker, 2); assert_eq!(journal.put(&a).0, STORED);
    journal.policy.active_raw = Some(a.encode().unwrap()); journal.policy.active_deny_at = Some(2);
    assert_eq!(journal.activate(&a, 4, 2), DENIED); assert!(journal.rows.markers[0].is_some());
    assert_eq!(journal.restore(&a, 4, 2).0, DENIED); worker.assert_birth_unchanged();
}
#[test]
fn journal_scope_policy_signature_corruption_and_unknown_slots_refuse() {
    let (mut worker, _, _, a) = component(); let mut journal = Journal::model(&worker, 2);
    let mut binding = worker.binding.clone(); binding.effective_epoch = 3; binding.valid_until_height = 3;
    journal.set_model_candidate(&binding, &a.owner_descriptor);
    for which in 0..5 {
        let mut changed = binding.clone(); match which { 0 => changed.genesis[0] ^= 1, 1 => changed.fingerprint[0] ^= 1,
            2 => changed.license[0] ^= 1, 3 => changed.device_mac[5] ^= 1, _ => changed.assignment_generation = 2 }
        changed.worker_id = changed.derived_worker_id();
        assert_eq!(Binding::decode(&changed.bytes().unwrap()).unwrap(), changed, "representable scope variant {which}");
        journal.set_model_candidate(&changed, &a.owner_descriptor); assert_eq!(journal.reprove(&mut worker, &changed, &a.owner_descriptor).0, 0);
    }
    journal.set_model_candidate(&binding, &a.owner_descriptor); journal.policy.candidate_deny_at = Some(2);
    journal.policy.candidate_calls = 0; assert_eq!(journal.reprove(&mut worker, &binding, &a.owner_descriptor).0, 0);
    journal.policy.candidate_deny_at = None; journal.set_model_candidate(&worker.binding, &a.owner_descriptor);
    assert_eq!(journal.put(&a).0, STORED); let records = journal.records();
    journal.rows.records[1] = Some(vec![0]); assert_eq!(journal.put(&a).0, FAULT); assert_eq!(journal.rows.records[0], records[0]);
    journal.rows.records[1] = None;
    let mut bad = a.clone(); bad.enrollment.owner_signature.fndsa[32] ^= 1;
    journal.rows.records[0] = Some(bad.encode().unwrap()); assert_eq!(journal.put(&a).0, FAULT);
    assert_eq!(journal.rows.records[0], Some(bad.encode().unwrap())); worker.assert_birth_unchanged();
}

#[test]
fn journal_mixed_flight_modes_and_current_provider_changes_clear_pending() {
    let (mut worker, _, node, a) = component(); let mut journal = Journal::model(&worker, 2);
    assert_eq!(journal.put(&a).0, STORED); journal.policy.active_raw = Some(a.encode().unwrap());
    assert_eq!(journal.activate(&a, 4, 2), ACTIVE);
    let local = JournalLocal { base: local(&worker.local), journal: &*journal.backend, authority: &*journal.authority };
    for which in 0..6 {
        journal.policy.active_raw = Some(a.encode().unwrap()); journal.policy.active_deny_at = None;
        let mut pending = Pending::new(); let mut hello = vec![0; 1722];
        assert_eq!(unsafe { build8_worker_journal_pending_v2_begin(pending.ptr(), &local, 4, 2, hello.as_mut_ptr()) }, 1);
        let (peer, response) = NodePending::accept(HostContext::pinned(&a.enrollment.binding, node.public(), 1).unwrap(),
            &node, &hello).unwrap();
        let mut finish = vec![7; 130];
        if which < 3 {
            if which == 2 { journal.policy.active_raw = None; }
            let result = unsafe { match which {
                0 => build8_worker_pending_v2_accept(pending.ptr(), &worker.local, 4, 2,
                    response.as_ptr(), response.len(), finish.as_mut_ptr()),
                1 => build8_worker_assignment_pending_v2_accept(pending.ptr(), &worker.local, 4, 2,
                    response.as_ptr(), response.len(), finish.as_mut_ptr()),
                _ => build8_worker_journal_pending_v2_accept(pending.ptr(), &local, 4, 2,
                    response.as_ptr(), response.len(), finish.as_mut_ptr()),
            }};
            assert_eq!(result, 0); assert!(pending.cleared()); assert!(finish.iter().all(|b| *b == 0));
        } else {
            assert_eq!(unsafe { build8_worker_journal_pending_v2_accept(pending.ptr(), &local, 4, 2,
                response.as_ptr(), response.len(), finish.as_mut_ptr()) }, 1);
            let (_, tag) = peer.finish(&finish).unwrap(); let mut channel = Channel::new();
            if which == 5 { journal.policy.active_raw = None; }
            let result = unsafe { match which {
                3 => build8_worker_pending_v2_finish(pending.ptr(), &worker.local, 4, 2,
                    tag.as_ptr(), tag.len(), channel.ptr()),
                4 => build8_worker_assignment_pending_v2_finish(pending.ptr(), &worker.local, 4, 2,
                    tag.as_ptr(), tag.len(), channel.ptr()),
                _ => build8_worker_journal_pending_v2_finish(pending.ptr(), &local, 4, 2,
                    tag.as_ptr(), tag.len(), channel.ptr()),
            }};
            assert_eq!(result, 0); assert!(pending.cleared()); assert!(channel.0.iter().all(|word| *word == 0));
        }
        worker.assert_birth_unchanged();
    }
    journal.policy.active_raw = Some(a.encode().unwrap());
    // Gate changed during slow begin work must clear the generated private
    // pending state rather than publish a hello under stale authority.
    journal.policy.active_deny_at = Some(journal.policy.active_calls + 4);
    let mut pending = Pending::new(); let mut hello = vec![7; 1722];
    assert_eq!(unsafe { build8_worker_journal_pending_v2_begin(pending.ptr(), &local, 4, 2, hello.as_mut_ptr()) }, 0);
    assert!(pending.cleared()); assert!(hello.iter().all(|b| *b == 0)); worker.assert_birth_unchanged();
}

#[test]
fn journal_bounds_aliases_orphan_markers_and_read_faults_preserve_existing_records() {
    let (worker, _, _, a) = component(); let mut journal = Journal::model(&worker, 2);
    assert_eq!(journal.put(&a).0, STORED); let records = journal.records(); let raw = a.encode().unwrap();
    for slots in [0, 33] {
        journal.backend.slots = slots;
        let mut id = [7; 32];
        assert_eq!(unsafe { build8_v2_assignment_journal_put(&*journal.backend, &*journal.authority,
            raw.as_ptr(), raw.len(), build8_v2_mbed_hash256, build8_release_mbed_hash512,
            journal.scratch.as_mut_ptr().cast(), 4127, id.as_mut_ptr()) }, FAULT);
        assert_eq!(id, [7; 32]); // invalid parameters refuse before any output writes
        assert_eq!(journal.records(), records);
    }
    journal.backend.slots = 2;
    let mut aliased = raw.clone();
    assert_eq!(unsafe { build8_v2_assignment_journal_put(&*journal.backend, &*journal.authority,
        aliased.as_ptr(), aliased.len(), build8_v2_mbed_hash256, build8_release_mbed_hash512,
        journal.scratch.as_mut_ptr().cast(), 4127, aliased.as_mut_ptr()) }, FAULT);
    assert_eq!(aliased, raw); assert_eq!(journal.records(), records);
    let mut id = [7; 32];
    assert_eq!(unsafe { build8_v2_assignment_journal_put(&*journal.backend, &*journal.authority,
        raw.as_ptr(), raw.len(), build8_v2_mbed_hash256, build8_release_mbed_hash512,
        journal.scratch.as_mut_ptr().cast(), 4126, id.as_mut_ptr()) }, FAULT);
    assert_eq!(id, [7; 32]); // rejected buffers are never cleared through an alias
    journal.rows.read_fault = Some(1); assert_eq!(journal.put(&a).0, FAULT); assert_eq!(journal.records(), records);
    journal.rows.read_fault = None; journal.rows.markers[1] = Some(vec![0; 40]);
    assert_eq!(journal.put(&a).0, FAULT); assert_eq!(journal.records(), records); worker.assert_birth_unchanged();
}

// SOURCE PROPOSAL ONLY: append inside journal_fixture.rs in a NEW successor.
// No compile/runtime claim. PUBLIC RAM cardinality, not 32 certified epochs,
// physical flash endurance/atomicity, rollback protection or candidate finality.
#[test]
fn journal_full_32_signed_rows_refuses_33rd_and_restores_final_slot_without_pruning() {
    let (mut worker, owner, _, original) = component();
    let mut journal = Journal::model(&worker, 32);
    let mut accepted = Vec::new();
    let mut unique_ids = std::collections::BTreeSet::new();
    let started = std::time::Instant::now();
    for index in 0..32u64 {
        // Delivery terms are different; identity/sequence remain the same
        // never-activated birth Worker. Local RAM policy admits one exact term
        // at a time; this is NOT a replacement for the own-chain adapter.
        let mut binding = worker.binding.clone();
        binding.effective_epoch = 2 + index;
        binding.valid_until_height = 2 + index;
        let unsigned = binding.bytes().unwrap();
        assert_eq!(Binding::decode(&unsigned).unwrap(), binding);
        journal.set_model_candidate(&binding, &original.owner_descriptor);
        let (status, proof) = journal.reprove(&mut worker, &binding, &original.owner_descriptor);
        assert_eq!(status, 1, "real Worker proof at occupied row {index}");
        assert_eq!(&proof.unsigned[..proof.un], unsigned.as_slice());
        binding.verify_worker_possession(&proof.proof).unwrap();
        let record = Assignment {
            enrollment: Enrollment {
                owner_signature: owner.sign(Domain::MinerEnrollment, &unsigned).unwrap(),
                worker_signature: proof.proof, binding,
            },
            owner_descriptor: original.owner_descriptor.clone(),
            node_descriptor: original.node_descriptor.clone(),
        };
        record.verify_signatures().unwrap();
        let raw = record.encode().unwrap();
        let id = mutiny_consensus_v8::op_envelope_v1::assignment_id(&record).unwrap();
        assert!(unique_ids.insert(id));
        assert_eq!(journal.put(&record), (STORED, id));
        assert_eq!(journal.rows.records[index as usize].as_deref(), Some(raw.as_slice()));
        accepted.push(record);
    }
    assert_eq!(unique_ids.len(), 32);
    assert!(journal.rows.records.iter().all(Option::is_some));
    assert!(journal.rows.markers.iter().all(Option::is_none));
    assert_eq!(journal.rows.writes, 32);
    let retained = journal.records();

    // Generate a genuinely valid distinct 33rd candidate BEFORE activating
    // any identity. Its signatures and current model permission pass; only
    // capacity refuses. Do not reuse an activated key as a fresh candidate.
    let mut binding = worker.binding.clone();
    binding.effective_epoch = 34; binding.valid_until_height = 34;
    journal.set_model_candidate(&binding, &original.owner_descriptor);
    let (status, proof) = journal.reprove(&mut worker, &binding, &original.owner_descriptor);
    assert_eq!(status, 1);
    let record33 = Assignment {
        enrollment: Enrollment {
            owner_signature: owner.sign(Domain::MinerEnrollment, &binding.bytes().unwrap()).unwrap(),
            worker_signature: proof.proof, binding,
        }, ..original
    };
    record33.verify_signatures().unwrap();
    let incoming33 = record33.encode().unwrap(); // retain rejected exact public bytes locally
    assert!(!unique_ids.contains(&mutiny_consensus_v8::op_envelope_v1::assignment_id(&record33).unwrap()));
    assert_eq!(journal.put(&record33), (FULL, [0; 32]));
    assert_eq!(journal.records(), retained);
    assert_eq!(journal.rows.writes, 32);
    assert!(journal.rows.markers.iter().all(Option::is_none));

    // Only the last exact row becomes current in the RAM model. Work height
    // is beyond its delivery deadline, which is not active-session expiry.
    let last = accepted.last().unwrap();
    let last_raw = last.encode().unwrap();
    journal.policy.active_raw = Some(last_raw.clone());
    assert_eq!(journal.restore(last, 34, 33).0, PENDING);
    assert_eq!(journal.activate(last, 34, 33), ACTIVE);
    assert_eq!(journal.restore(last, 34, 33), (ACTIVE, last_raw.clone()));
    assert_eq!(journal.records(), retained);
    assert_eq!(journal.rows.writes, 33);
    assert!(journal.rows.markers[..31].iter().all(Option::is_none));
    assert_eq!(journal.rows.markers[31].as_ref().unwrap().len(), 40);
    let markers = journal.rows.markers.clone();
    let mut reopened = Journal::model(&worker, 32);
    reopened.rows.records = retained.clone(); reopened.rows.markers = markers.clone();
    reopened.policy.active_raw = Some(last_raw.clone());
    assert_eq!(reopened.restore(last, 34, 33), (ACTIVE, last_raw));
    let first_id = mutiny_consensus_v8::op_envelope_v1::assignment_id(&accepted[0]).unwrap();
    assert_eq!(reopened.put(&accepted[0]), (STORED, first_id));
    assert_eq!(reopened.rows.writes, 0);
    reopened.policy.active_raw = None;
    assert_eq!(reopened.restore(last, 34, 33).0, DENIED);
    assert_eq!(reopened.records(), retained);
    assert_eq!(reopened.rows.markers, markers);
    assert_eq!(incoming33, record33.encode().unwrap());
    worker.assert_birth_unchanged();
    eprintln!("PUBLIC RAM journal cardinality: 32 signed rows, distinct 33rd FULL, last-slot ACTIVE/reopen, 32 retained; elapsed_ms={}", started.elapsed().as_millis());
}
