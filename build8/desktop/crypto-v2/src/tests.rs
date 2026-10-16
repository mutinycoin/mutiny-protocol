use super::*;
#[test]
fn os_provider_partial_failure_erases_entire_output() {
    let mut output = [0xa5; 64];
    assert_eq!(
        checked_fill(&mut output, |bytes| {
            bytes[..32].fill(9);
            Err(Error::Entropy)
        }),
        Err(Error::Entropy)
    );
    assert_eq!(output, [0; 64]);
    ENTROPY_FAIL.set(true);
    output.fill(0xa5);
    assert_eq!(fill_os_random(&mut output), Err(Error::Entropy));
    ENTROPY_FAIL.set(false);
    assert_eq!(output, [0; 64]);
}
#[test]
fn wallet_generation_cannot_bypass_recoverable_mnemonic_path() {
    assert!(matches!(HybridKey::generate(Role::WalletOwner), Err(Error::Role)));
    assert!(matches!(HybridKey::generate(Role::WalletRecovery), Err(Error::Role)));
}
#[test]
#[cfg(feature = "qualification")]
fn native_ed448_hash_faults_clean_up_and_fail_without_signature() {
    unsafe extern "C" {
        fn build8_qual_fail_final(nth: u32);
        fn build8_qual_scalar_cleanses() -> u32;
        fn build8_qual_hash_contexts_used() -> u32;
    }
    // Public synthetic material; direct native invocation keeps fault injection
    // on this thread. Production private operations remain on private_job.
    let seed = [7u8; 57];
    let mut public = [0; 57];
    unsafe {
        build8_qual_fail_final(0);
        assert_eq!(
            ossl_ed448_public_from_private(
                std::ptr::null_mut(),
                public.as_mut_ptr(),
                seed.as_ptr(),
                std::ptr::null()
            ),
            1
        );
        for failure in 1..=3 {
            build8_qual_fail_final(failure);
            let mut signature = [0xa5; 114];
            assert_eq!(
                ossl_ed448_sign(
                    std::ptr::null_mut(),
                    signature.as_mut_ptr(),
                    [3u8; 64].as_ptr(),
                    64,
                    public.as_ptr(),
                    seed.as_ptr(),
                    std::ptr::null(),
                    0,
                    0,
                    std::ptr::null()
                ),
                0
            );
            assert_eq!(signature, [0xa5; 114]);
            assert_eq!(build8_qual_hash_contexts_used(), 0);
            assert!(build8_qual_scalar_cleanses() >= 3);
        }
        build8_qual_fail_final(0);
        let mut signature = [0; 114];
        assert_eq!(
            ossl_ed448_sign(
                std::ptr::null_mut(),
                signature.as_mut_ptr(),
                [3u8; 64].as_ptr(),
                64,
                public.as_ptr(),
                seed.as_ptr(),
                std::ptr::null(),
                0,
                0,
                std::ptr::null()
            ),
            1
        );
        assert_eq!(build8_qual_hash_contexts_used(), 0);
    }
}
#[test]
fn numeric_wallet_descriptor_suite_policy_and_role_are_explicit() {
    let key = synthetic(Role::WalletOwner);
    let bytes = key.public().descriptor(1).unwrap();
    let (public, generation) = PublicKey::decode_descriptor(&bytes).unwrap();
    assert_eq!(&public, key.public());
    assert_eq!(generation, 1);
    let mut d = minicbor::Decoder::new(&bytes);
    assert_eq!(d.array().unwrap(), Some(9));
    for _ in 0..4 {
        d.skip().unwrap();
    }
    let suite_at = d.position();
    assert_eq!(d.u16().unwrap(), 1);
    let policy_at = d.position();
    assert_eq!(d.u8().unwrap(), 1);
    for at in [suite_at, policy_at] {
        let mut bad = bytes.clone();
        bad[at] = 2;
        assert!(PublicKey::decode_descriptor(&bad).is_err());
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(PublicKey::decode_descriptor(&extra).is_err());
    // The superseded eight-field descriptor has no compatibility acceptance path.
    let mut old = minicbor::Encoder::new(Vec::new());
    old.array(8)
        .unwrap()
        .u8(1)
        .unwrap()
        .u32(NETWORK)
        .unwrap()
        .u8(1)
        .unwrap()
        .u64(1)
        .unwrap()
        .str(Role::WalletOwner.suite())
        .unwrap()
        .str(PROFILE)
        .unwrap()
        .bytes(&public.ed448)
        .unwrap()
        .bytes(&public.fndsa)
        .unwrap();
    assert!(PublicKey::decode_descriptor(&old.into_writer()).is_err());
}
use std::cell::Cell;
thread_local! {pub(super) static ENTROPY_FAIL:Cell<bool>=const{Cell::new(false)};}
fn synthetic(role: Role) -> HybridKey {
    HybridKey::from_seeds(role, Zeroizing::new([92; 57]), Zeroizing::new([93; 32])).unwrap()
}
#[test]
fn enrollment_v2_dual_owner_and_complete_worker_possession() {
    use crate::enrollment::*;
    let owner = synthetic(Role::WalletOwner);
    // Explicit public test seed. Production Worker generation belongs on device.
    let seed = std::array::from_fn::<u8, 57, _>(|i| i as u8);
    let mut worker = [0; 57];
    assert_eq!(
        unsafe {
            ossl_ed448_public_from_private(
                std::ptr::null_mut(),
                worker.as_mut_ptr(),
                seed.as_ptr(),
                std::ptr::null(),
            )
        },
        1
    );
    let mut binding = Binding {
        genesis: [1; 32],
        fingerprint: [2; 32],
        license: [3; 32],
        owner_descriptor: owner_descriptor_id(owner.public(), 1).unwrap(),
        owner_generation: 1,
        worker_public: worker,
        worker_id: [0; 32],
        coordinator: [4; 32],
        configuration_generation: 1,
        device_mac: [0xa4, 0xf0, 0x0f, 0x8f, 0x99, 0xf4],
        assignment_generation: 1,
        effective_epoch: 0,
        valid_until_height: 0,
    };
    binding.worker_id = binding.derived_worker_id();
    let unsigned = binding.bytes().unwrap();
    let intent = binding.possession_intent().unwrap();
    let mut worker_signature = [0; 114];
    assert_eq!(
        unsafe {
            ossl_ed448_sign(
                std::ptr::null_mut(),
                worker_signature.as_mut_ptr(),
                intent.as_ptr(),
                64,
                worker.as_ptr(),
                seed.as_ptr(),
                std::ptr::null(),
                0,
                0,
                std::ptr::null(),
            )
        },
        1
    );
    // The public-only seam is usable before an owner signature exists.
    binding.verify_worker_possession(&worker_signature).unwrap();
    for i in 0..worker_signature.len() {
        let mut bad = worker_signature; bad[i] ^= 1;
        assert!(binding.verify_worker_possession(&bad).is_err(), "Worker signature byte {i}");
    }
    // A signature by this same Worker over the owner's existing domain cannot
    // be imported as possession: the two intents are distinct.
    let wrong_intent = crate::intent(Domain::MinerEnrollment, &unsigned).unwrap();
    assert_ne!(intent, wrong_intent);
    let mut wrong_domain_signature = [0;114];
    assert_eq!(unsafe { ossl_ed448_sign(std::ptr::null_mut(), wrong_domain_signature.as_mut_ptr(),
        wrong_intent.as_ptr(), 64, worker.as_ptr(), seed.as_ptr(), std::ptr::null(), 0, 0, std::ptr::null()) }, 1);
    assert!(binding.verify_worker_possession(&wrong_domain_signature).is_err());
    let enrollment = Enrollment {
        binding: binding.clone(),
        owner_signature: owner.sign(Domain::MinerEnrollment, &unsigned).unwrap(),
        worker_signature,
    };
    enrollment.verify_genesis(&binding, owner.public()).unwrap();
    let raw = enrollment.bytes().unwrap();
    Enrollment::decode(&raw)
        .unwrap()
        .verify_genesis(&binding, owner.public())
        .unwrap();
    for i in 0..raw.len() {
        let mut bad = raw.clone();
        bad[i] ^= 1;
        assert!(
            Enrollment::decode(&bad)
                .and_then(|e| e.verify_genesis(&binding, owner.public()))
                .is_err(),
            "byte {i}"
        );
    }
    for n in 0..raw.len() {
        assert!(Enrollment::decode(&raw[..n]).is_err());
    }
    let mut trailing = raw.clone();
    trailing.push(0);
    assert!(Enrollment::decode(&trailing).is_err());
    let mut nonminimal = vec![0x98, 4];
    nonminimal.extend_from_slice(&raw[1..]);
    assert!(Enrollment::decode(&nonminimal).is_err());
    for field in 0..13 {
        let mut b = binding.clone();
        match field {
            0 => b.genesis[0] ^= 1,
            1 => b.fingerprint[0] ^= 1,
            2 => b.license[0] ^= 1,
            3 => b.owner_descriptor[0] ^= 1,
            4 => b.owner_generation += 1,
            5 => b.worker_public[0] ^= 1,
            6 => b.worker_id[0] ^= 1,
            7 => b.coordinator[0] ^= 1,
            8 => b.configuration_generation += 1,
            9 => b.device_mac[0] ^= 1,
            10 => b.assignment_generation += 1,
            11 => b.effective_epoch += 1,
            _ => b.valid_until_height += 1,
        };
        assert!(b.verify_worker_possession(&worker_signature).is_err(), "Worker binding field {field}");
        assert!(enrollment.verify_genesis(&b, owner.public()).is_err());
    }
    let mut bad = Enrollment::decode(&raw).unwrap();
    bad.owner_signature.ed448.fill(0);
    assert!(bad.verify_genesis(&binding, owner.public()).is_err());
    let mut bad = Enrollment::decode(&raw).unwrap();
    bad.owner_signature.fndsa.fill(0);
    assert!(bad.verify_genesis(&binding, owner.public()).is_err());
    let mut bad = Enrollment::decode(&raw).unwrap();
    bad.worker_signature.fill(0);
    assert!(bad.verify_genesis(&binding, owner.public()).is_err());
    assert!(
        owner
            .public()
            .verify(Domain::Transaction, &unsigned, &enrollment.owner_signature)
            .is_err()
    );
    if std::env::var("BUILD8_EXPORT_PUBLIC_ENROLLMENT").as_deref() == Ok("1") {
        let fixture = serde_json::json!({"schema":"BUILD8-SYNTHETIC-ENROLLMENT-V2","synthetic":true,
            "production_authorized":false,"owner_descriptor":hex::encode(owner.public().descriptor(1).unwrap()),
            "owner_descriptor_id":hex::encode(binding.owner_descriptor),"worker_id":hex::encode(binding.worker_id),
            "unsigned":hex::encode(unsigned),"owner_intent":hex::encode(crate::intent(Domain::MinerEnrollment,&binding.bytes().unwrap()).unwrap()),
            "possession_intent":hex::encode(intent),"enrollment":hex::encode(raw)});
        std::fs::write(
            "../qualification/enrollment-v2-public-fixture-v3.json",
            serde_json::to_string_pretty(&fixture).unwrap() + "\n",
        )
        .unwrap();
    }
}
#[test]
fn both_required_role_bound_fault_checked_signing() {
    let key = synthetic(Role::Release);
    let p = key.public();
    let payload = b"SYNTHETIC QUALIFICATION ONLY";
    let s = key.sign(Domain::ReleaseApproval, payload).unwrap();
    p.verify(Domain::ReleaseApproval, payload, &s).unwrap();
    for half in 0..2 {
        let mut bad = s.clone();
        if half == 0 {
            bad.ed448.fill(0)
        } else {
            bad.fndsa.fill(0)
        };
        assert_eq!(
            p.verify(Domain::ReleaseApproval, payload, &bad),
            Err(Error::Signature)
        );
    }
    assert_eq!(
        p.verify(Domain::ReleasePossession, payload, &s),
        Err(Error::Signature)
    );
    assert!(matches!(
        key.sign(Domain::Transaction, payload),
        Err(Error::Role)
    ));
    assert_eq!(p.verify(Domain::Transaction, payload, &s), Err(Error::Role));
    assert_eq!(
        p.verify(Domain::ReleaseApproval, b"wrong manifest", &s),
        Err(Error::Signature)
    );
    let mut bad = synthetic(Role::Release);
    bad.fn_secret[2305] ^= 1;
    assert!(matches!(
        bad.sign(Domain::ReleaseApproval, payload),
        Err(Error::Key)
    ));
}
#[test]
fn entropy_failure_never_uses_a_fallback() {
    let key = synthetic(Role::Release);
    ENTROPY_FAIL.set(true);
    assert!(matches!(
        HybridKey::generate(Role::Release),
        Err(Error::Entropy)
    ));
    assert!(matches!(
        key.sign(Domain::ReleaseApproval, b"test"),
        Err(Error::Entropy)
    ));
    assert!(matches!(create_wallet_phrase(), Err(Error::Entropy)));
    assert!(matches!(
        key.seal("public test password", 1),
        Err(Error::Entropy)
    ));
    ENTROPY_FAIL.set(false);
}

#[test]
fn every_hybrid_intent_domain_rejects_cross_domain_and_role_relabeling() {
    // Deliberately reuse PUBLIC FIXTURE seed values between roles to prove
    // separation does not rely only on the descriptor's mutable role label.
    // Production key generation always keeps independent role roots.
    let cases = [
        (Domain::Transaction, Role::WalletOwner),
        (Domain::WalletRotate, Role::WalletOwner),
        (Domain::WalletRotatePossession, Role::WalletOwner),
        (Domain::MinerEnrollment, Role::WalletOwner),
        (Domain::PhysicalAdmission, Role::WalletOwner),
        (Domain::RecoveryAuthorize, Role::WalletRecovery),
        (Domain::ReleaseApproval, Role::Release),
        (Domain::ReleasePossession, Role::Release),
        (Domain::ReleaseRotation, Role::Release),
        (Domain::ContinuityVote, Role::Continuity),
        (Domain::ContinuityWorkProbe, Role::Continuity),
        (Domain::ContinuityPossession, Role::Continuity),
        (Domain::TransportResponder, Role::Transport),
        (Domain::TransportInitiator, Role::Transport),
        (Domain::NodeWork, Role::Node),
        (Domain::NodeWorkerSession, Role::Node),
        (Domain::NodeObservation, Role::Node),
        (Domain::ContinuityExitOwner, Role::WalletOwner),
        (Domain::ContinuityExitNode, Role::Node),
        (Domain::NodeAdmissionPossession, Role::Node),
        (Domain::BondCreate, Role::WalletOwner),
        (Domain::BondUnbond, Role::WalletOwner),
        (Domain::BondWithdraw, Role::WalletOwner),
        (Domain::NodeKeyRotateOwner, Role::WalletOwner),
        (Domain::NodeKeyRotateNode, Role::Node),
        (Domain::NodeKeyRotatePossession, Role::Node),
        (Domain::TreasuryProofOfControl, Role::WalletOwner),
        (Domain::TradeOffer, Role::WalletOwner),
        (Domain::TradeFill, Role::WalletOwner),
    ];
    let mut seen = std::collections::BTreeSet::new();
    let payload = b"SYNTHETIC DOMAIN SEPARATION QUALIFICATION V1";
    let mut vectors = Vec::new();
    for (i, (domain, role)) in cases.iter().enumerate() {
        assert_eq!(domain.role(), *role);
        assert!(seen.insert(domain.bytes()));
        assert!(!domain.bytes().contains(&0));
        let key = synthetic(*role);
        let signature = key.sign(*domain, payload).unwrap();
        for (j, (other_domain, other_role)) in cases.iter().enumerate() {
            let mut relabeled = key.public().clone();
            relabeled.role = *other_role;
            assert_eq!(relabeled.verify(*other_domain, payload, &signature).is_ok(), i == j);
        }
        let mut changed = payload.to_vec(); changed.push(0);
        assert!(key.public().verify(*domain, &changed, &signature).is_err());
        vectors.push(serde_json::json!({
            "domain":std::str::from_utf8(domain.bytes()).unwrap(),"role":*role as u8,
            "payload":hex::encode(payload),"intent":hex::encode(intent(*domain,payload).unwrap()),
            "ed448_public":hex::encode(key.public().ed448),"fndsa_public":hex::encode(key.public().fndsa),
            "ed448_signature":hex::encode(signature.ed448),"fndsa_signature":hex::encode(signature.fndsa)
        }));
    }
    if let Ok(path)=std::env::var("BUILD8_PUBLIC_DOMAIN_VECTORS") {
        let public=serde_json::json!({"synthetic_only":true,"production_authorized":false,"domains":vectors});
        std::fs::write(path,serde_json::to_string_pretty(&public).unwrap()+"\n").unwrap();
    }
}
#[test]
fn fresh_nonproduction_wallet_restores_public_identity_without_secret_evidence() {
    let phrase = create_wallet_phrase().unwrap();
    let key = HybridKey::wallet_restore(&phrase, Role::WalletOwner).unwrap();
    let expected = key.public().clone();
    let descriptor = expected.descriptor(1).unwrap();
    let address = expected.address_id(1).unwrap();
    drop(key);
    let restored = HybridKey::wallet_restore(&phrase, Role::WalletOwner).unwrap();
    assert_eq!(restored.public(), &expected);
    assert_eq!(restored.public().descriptor(1).unwrap(), descriptor);
    assert_eq!(restored.public().address_id(1).unwrap(), address);
    let recovery = HybridKey::wallet_restore(&phrase, Role::WalletRecovery).unwrap();
    assert_ne!(recovery.public().ed448, expected.ed448);
    assert_ne!(recovery.public().fndsa, expected.fndsa);
    assert!(matches!(
        HybridKey::wallet_restore(&phrase, Role::Release),
        Err(Error::Role)
    ));
}
#[test]
fn encrypted_custody_roundtrip_tamper_wrong_password_and_role() {
    let key = synthetic(Role::Release);
    let expected = key.public().clone();
    let password = "PUBLIC TEST PASSWORD ONLY";
    let envelope = key.seal(password, 7).unwrap();
    let other = key.seal(password, 7).unwrap();
    assert_ne!(envelope, other);
    assert!(
        HybridKey::open_for(
            Role::Release,
            password,
            b"different custody context",
            &envelope
        )
        .is_err()
    );
    assert!(!envelope.windows(57).any(|w| w == key.ed_seed.as_ref()));
    drop(key);
    let (restored, generation) = HybridKey::open(Role::Release, password, &envelope).unwrap();
    assert_eq!(restored.public(), &expected);
    assert_eq!(generation, 7);
    assert!(HybridKey::open(Role::Release, "wrong password", &envelope).is_err());
    assert!(HybridKey::open(Role::WalletOwner, password, &envelope).is_err());
    let mut bad = envelope.clone();
    let n = bad.len();
    bad[n - 1] ^= 1;
    assert!(HybridKey::open(Role::Release, password, &bad).is_err());
    let mut extra = envelope.clone();
    extra.push(0);
    assert!(HybridKey::open(Role::Release, password, &extra).is_err());
    assert!(HybridKey::open(Role::Release, password, &envelope[..n - 1]).is_err());
    restored
        .sign(Domain::ReleasePossession, b"SYNTHETIC RESTORE CHECK")
        .unwrap();
}
#[cfg(feature = "qualification")]
#[test]
fn changed_native_rounding_fails_closed() {
    unsafe extern "C" {
        fn build8_crypto_test_rounding_down() -> i32;
        fn build8_crypto_test_rounding_restore() -> i32;
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            unsafe {
                build8_crypto_test_rounding_restore();
            }
        }
    }
    let key = synthetic(Role::Continuity);
    let _reset = Reset;
    assert_eq!(unsafe { build8_crypto_test_rounding_down() }, 0);
    assert!(matches!(
        key.sign(Domain::ContinuityVote, b"test"),
        Err(Error::Rounding)
    ));
}

#[cfg(all(feature="qualification",target_arch="x86_64"))]
#[test]
fn changed_sse_rounding_flush_modes_and_exception_masks_fail_before_signing() {
    unsafe extern "C" {
        fn build8_crypto_test_mxcsr_get()->u32;
        fn build8_crypto_test_mxcsr_set(value:u32);
    }
    struct Reset(u32);
    impl Drop for Reset {
        fn drop(&mut self){unsafe{build8_crypto_test_mxcsr_set(self.0);}}
    }
    let key=synthetic(Role::Continuity);
    let saved=unsafe{build8_crypto_test_mxcsr_get()};
    let _reset=Reset(saved);
    for changed in [saved|0x8000,saved|0x0040,(saved&!0x6000)|0x2000,
                    (saved&!0x6000)|0x4000,(saved&!0x6000)|0x6000,
                    (saved&!0x0080)&!0x003f] {
        unsafe{build8_crypto_test_mxcsr_set(changed);}
        let result=key.sign(Domain::ContinuityVote,b"SYNTHETIC FP ENVIRONMENT TEST");
        unsafe{build8_crypto_test_mxcsr_set(saved);}
        assert!(matches!(result,Err(Error::Rounding)));
    }
    // Harmless accumulated exception status is not a configuration change.
    unsafe{build8_crypto_test_mxcsr_set(saved|0x20);}
    key.sign(Domain::ContinuityVote,b"SYNTHETIC RESTORED FP ENVIRONMENT").unwrap();
}
