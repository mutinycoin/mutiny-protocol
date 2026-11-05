// Shared synthetic license/enrollment fixtures; never production identities.
use mutiny_consensus_v8::{
    blocks::genesis_license, license_assignment_v2::Assignment, licenses::LicenseRecord,
    work_authority_v2::node_identity,
};
use mutiny_crypto_v2::{
    Domain, HybridKey, Role,
    enrollment::{Binding, Enrollment, owner_descriptor_id},
};
use std::ffi::{c_char, c_void};
unsafe extern "C" {
    fn ossl_ed448_public_from_private(
        ctx: *mut c_void,
        out: *mut u8,
        seed: *const u8,
        prop: *const c_char,
    ) -> i32;
    fn ossl_ed448_sign(
        ctx: *mut c_void,
        out: *mut u8,
        msg: *const u8,
        n: usize,
        pk: *const u8,
        sk: *const u8,
        domain: *const u8,
        domain_n: usize,
        ph: u8,
        prop: *const c_char,
    ) -> i32;
}
// Public deterministic test-only Worker seeds. No miner or production key access.
pub fn worker(seed: u8) -> [u8; 57] {
    let mut public = [0; 57];
    assert_eq!(
        unsafe {
            ossl_ed448_public_from_private(
                std::ptr::null_mut(),
                public.as_mut_ptr(),
                [seed; 57].as_ptr(),
                std::ptr::null(),
            )
        },
        1
    );
    public
}
pub fn sign(binding: Binding, owner: &HybridKey, node: &[u8], seed: u8) -> Assignment {
    let mut sig = [0; 114];
    let intent = binding.possession_intent().unwrap();
    assert_eq!(worker(seed), binding.worker_public);
    assert_eq!(
        unsafe {
            ossl_ed448_sign(
                std::ptr::null_mut(),
                sig.as_mut_ptr(),
                intent.as_ptr(),
                64,
                binding.worker_public.as_ptr(),
                [seed; 57].as_ptr(),
                std::ptr::null(),
                0,
                0,
                std::ptr::null(),
            )
        },
        1
    );
    let owner_signature = owner
        .sign(Domain::MinerEnrollment, &binding.bytes().unwrap())
        .unwrap();
    let owner_descriptor = owner.public().descriptor(binding.owner_generation).unwrap();
    Assignment {
        enrollment: Enrollment {
            binding,
            owner_signature,
            worker_signature: sig,
        },
        owner_descriptor,
        node_descriptor: node.to_vec(),
    }
}
pub fn fixtures() -> (
    HybridKey,
    Vec<Assignment>,
    Vec<Binding>,
    Vec<LicenseRecord>,
    HybridKey,
) {
    let owner =
        HybridKey::wallet_restore(&format!("{}art", "abandon ".repeat(23)), Role::WalletOwner)
            .unwrap();
    let node = HybridKey::generate(Role::Node).unwrap();
    let descriptor = node.public().descriptor(1).unwrap();
    let mut assignments = Vec::new();
    let mut expected = Vec::new();
    let mut licenses = Vec::new();
    for i in 0..12 {
        let id = genesis_license([1; 32], i).unwrap();
        let mut b = Binding {
            genesis: [1; 32],
            fingerprint: [2; 32],
            license: id,
            owner_descriptor: owner_descriptor_id(owner.public(), 1).unwrap(),
            owner_generation: 1,
            worker_public: worker(i as u8 + 1),
            worker_id: [0; 32],
            coordinator: node_identity(&descriptor).unwrap(),
            configuration_generation: 1,
            device_mac: [2, 0, 0, 0, 0, i as u8 + 1],
            assignment_generation: 1,
            effective_epoch: 0,
            valid_until_height: 0,
        };
        b.worker_id = b.derived_worker_id();
        assignments.push(sign(b.clone(), &owner, &descriptor, i as u8 + 1));
        expected.push(b);
        licenses.push(LicenseRecord {
            id,
            genesis: [1; 32],
            owner: owner.public().address_id(1).unwrap(),
            issuance: [8; 32],
            index: i,
            issue_height: 0,
            active_worker: None,
            assignment_sequence: 0,
        });
    }
    (owner, assignments, expected, licenses, node)
}
