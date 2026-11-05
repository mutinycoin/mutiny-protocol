//! Source-only public-vector timing probe. No signing, key generation or custody.
//! Run ONLY this ignored integration test in Root's later serialized TEST lane.
use mutiny_crypto_v2::{Domain, Error, HybridSignature, PublicKey, Role, PROFILE};
use sha2::{Digest, Sha256, Sha512};
use std::{hint::black_box, time::Instant};

const BASELINE: &str = "b24da23e1c1120e8726c0599d48109d197cebb87c7116b176d53f5fea98600e0";
const CANDIDATE: &str = "d342215fa4c81322c9c6b6371f18f58cc1fa5184a13790e088a4ecc042c26d31";
const FIXTURE_SHA: &str = "45c04c4be24d430e170cb42e1fe380bc9da51e495228abb238f485e495e3779f";
const FIXTURE: &[u8] = include_bytes!(
    "../../qualification/TREASURY-PROOF-OF-CONTROL-VECTORS-V1.json"
);
const ROUNDS: usize = 4;
const REPETITIONS: usize = 2;

fn sha(bytes: &[u8]) -> String { hex::encode(Sha256::digest(bytes)) }

// All files are embedded from the SAME staged source tree as this integration
// test. These pins supplement, and do not replace, existing build.rs guards.
fn pinned_context() -> serde_json::Value {
    let files: &[(&str, &[u8], &str)] = &[
        ("crypto-v2/Cargo.toml", include_bytes!("../Cargo.toml"),
         "492e3f34572b0a58dfb3c0d97a6c940cbff15b3cf16e1b2fdd6c6a600b9b6214"),
        ("crypto-v2/Cargo.lock", include_bytes!("../Cargo.lock"),
         "136ac79f91838326aa9da6e3f8f68818b33807d02b0d1ec807d537ba9d74d1a6"),
        ("crypto-v2/build.rs", include_bytes!("../build.rs"),
         "0b3e67580f48cadacecb6beb672c33cf40568cf1ee967c16cbe633f7280bde7d"),
        ("crypto-v2/src/platform.c", include_bytes!("../src/platform.c"),
         "844a863f7469675e01026993974dea4159631d99595bd51666b0b1044a542c53"),
        ("qualification/FNDSA-CUSTODY-SOURCE-LOCK-V2.json",
         include_bytes!("../../qualification/FNDSA-CUSTODY-SOURCE-LOCK-V2.json"),
         "faee911a167243859cbcb0d04e2e9bfb1189559e93b07d8c9f3313bea8b483cb"),
        ("qualification/OPENSSL-CURVE448-SOURCE-LOCK-V1.json",
         include_bytes!("../../qualification/OPENSSL-CURVE448-SOURCE-LOCK-V1.json"),
         "6018b2eaa1947f2919a30dc748d57bbc54e6e246b0aa1fd301076ed12dd4ca18"),
        ("qualification/OPENSSL-CURVE448-CUSTODY-SOURCE-LOCK-V1.json",
         include_bytes!("../../qualification/OPENSSL-CURVE448-CUSTODY-SOURCE-LOCK-V1.json"),
         "336226e8249d6ad08d0e77f2fc05547fac8dfe49190caea6011322b2687b1cdc"),
        ("qualification/CRYPTO-CANDIDATE-SOURCE-LOCK-V1.json",
         include_bytes!("../../qualification/CRYPTO-CANDIDATE-SOURCE-LOCK-V1.json"),
         "e89e30c491549c3b5cc1d51719891a661f54e5bd8fd7318fb63eac540751a0a1"),
        ("qualification/openssl-curve448-port/profile_adapter.c",
         include_bytes!("../../qualification/openssl-curve448-port/profile_adapter.c"),
         "bccc5bb667695ba5aac7e1f2f2e2e3f23a261c6f6c44c14ebc59ad71ff8e329d"),
        ("qualification/openssl-curve448-port/shake_adapter.c",
         include_bytes!("../../qualification/openssl-curve448-port/shake_adapter.c"),
         "e35aece6103b22d3757a0d3123163a5e3f3f58bc86cc467338f0c12a142f0694"),
        ("qualification/crypto-v2-sources/rust-fn-dsa-custody-v2/fn-dsa/Cargo.toml",
         include_bytes!("../../qualification/crypto-v2-sources/rust-fn-dsa-custody-v2/fn-dsa/Cargo.toml"),
         "009b82734b320007cadfeed0cdbfa197eb641e58bfdeeba706f0f2833563bb9c"),
        ("qualification/crypto-v2-sources/rust-fn-dsa-custody-v2/fn-dsa-vrfy/src/lib.rs",
         include_bytes!("../../qualification/crypto-v2-sources/rust-fn-dsa-custody-v2/fn-dsa-vrfy/src/lib.rs"),
         "11d57abc85de40af5f79a24bc5b8d439994c72f8ed3eb4923562db142d371916"),
    ];
    let rows: Vec<_> = files.iter().map(|(path, bytes, expected)| {
        assert_eq!(sha(bytes), *expected, "context preimage changed: {path}");
        serde_json::json!({"path": path, "bytes": bytes.len(), "sha256": expected})
    }).collect();
    serde_json::json!(rows)
}

struct Vector {
    public: PublicKey,
    payload: Vec<u8>,
    signature: HybridSignature,
    descriptor_sha256: String,
    challenge_sha256: String,
    signature_sha256: String,
}

fn raw(value: &serde_json::Value) -> Vec<u8> {
    hex::decode(value.as_str().expect("public hex string")).expect("public hex")
}

fn vectors() -> Vec<Vector> {
    assert_eq!(sha(FIXTURE), FIXTURE_SHA);
    let fixture: serde_json::Value = serde_json::from_slice(FIXTURE).unwrap();
    assert_eq!(fixture["schema"], "BUILD8-TREASURY-PROOF-OF-CONTROL-VECTORS-V1");
    assert_eq!(fixture["synthetic_only"], true);
    assert_eq!(fixture["test_value"], true);
    assert_eq!(fixture["production_authorized"], false);
    let entries = fixture["vectors"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    entries.iter().map(|entry| {
        assert_eq!(entry["class"], "TEST-VALUE");
        assert_eq!(entry["domain"], std::str::from_utf8(Domain::TreasuryProofOfControl.bytes()).unwrap());
        let descriptor = raw(&entry["descriptor"]);
        assert_eq!(sha(&descriptor), entry["descriptor_sha256"].as_str().unwrap());
        let (public, generation) = PublicKey::decode_descriptor(&descriptor).unwrap();
        assert_eq!(generation, entry["generation"].as_u64().unwrap());
        assert_eq!(public.role, Role::WalletOwner);
        let payload = raw(&entry["challenge"]);
        let mut intent = Sha512::new();
        intent.update(Domain::TreasuryProofOfControl.bytes());
        intent.update([0u8]);
        intent.update(&payload);
        assert_eq!(intent.finalize().as_slice(), raw(&entry["intent"]));
        let ed448 = raw(&entry["ed448_signature"]);
        let fndsa = raw(&entry["fndsa_signature"]);
        assert_eq!(ed448.len(), 114);
        assert_eq!(fndsa.len(), 1280);
        let signature_sha256 = sha(&[ed448.as_slice(), fndsa.as_slice()].concat());
        let signature = HybridSignature {
            ed448: ed448.try_into().unwrap(), fndsa: fndsa.try_into().unwrap(),
        };
        // Untimed successful warmup plus actual native rejection controls. No
        // changed verifier, foreign C call, fault injection or fabricated result.
        assert_eq!(public.validate(), Ok(()));
        assert_eq!(public.verify(Domain::TreasuryProofOfControl, &payload, &signature), Ok(()));
        assert_eq!(public.verify(Domain::TreasuryProofOfControl,
                                &raw(&entry["negative_flipped_challenge"]), &signature),
                   Err(Error::Signature));
        let mut changed = signature.clone();
        changed.ed448.fill(0);
        assert_eq!(public.verify(Domain::TreasuryProofOfControl, &payload, &changed),
                   Err(Error::Signature));
        let mut changed = signature.clone();
        changed.fndsa[17] ^= 1;
        assert_eq!(changed.fndsa[0], 0x3a);
        assert_eq!(changed.ed448, signature.ed448);
        assert_eq!(public.verify(Domain::TreasuryProofOfControl, &payload, &changed),
                   Err(Error::Signature));
        assert_eq!(public.verify(Domain::ContinuityVote, &payload, &signature), Err(Error::Role));
        Vector { public, challenge_sha256: sha(&payload), payload, signature,
                 descriptor_sha256: sha(&descriptor), signature_sha256 }
    }).collect()
}

#[derive(Clone, Copy)]
enum Phase { Validate, Verify }

fn sample(vector: &Vector, phase: Phase) -> u64 {
    // Fixed buffer, no allocation/JSON/descriptor decode in the timed window.
    let mut results = [const { None }; REPETITIONS];
    let start = Instant::now();
    for result in &mut results {
        *result = Some(black_box(match phase {
            Phase::Validate => black_box(&vector.public).validate(),
            Phase::Verify => black_box(&vector.public).verify(
                black_box(Domain::TreasuryProofOfControl),
                black_box(vector.payload.as_slice()), black_box(&vector.signature)),
        }));
    }
    let elapsed: u64 = start.elapsed().as_nanos().try_into().unwrap();
    for result in results { assert_eq!(result.unwrap(), Ok(())); }
    elapsed
}

#[test]
#[ignore = "Root serialized public-vector timing only, after active producer closes"]
fn public_verification_timing_probe_v1() {
    let source_sha256 = sha(include_bytes!("../src/lib.rs"));
    let variant = if source_sha256 == BASELINE { "baseline" }
                  else if source_sha256 == CANDIDATE { "parsed_reuse_candidate_r1" }
                  else { panic!("unrecognized crypto source preimage: {source_sha256}") };
    // Pinned crypto lib.rs already has its unchanged compile-time assertion of
    // fn_dsa::BUILD8_INTEGER_BACKEND. No new direct dependency/features here.
    assert!(!mutiny_crypto_v2::PRODUCTION_SECURITY_QUALIFIED);
    assert_eq!(PROFILE, "MUTINY-FNDSA1024-PORNIN-20260722-V1");
    let context = pinned_context();
    let vectors = vectors();
    println!("PUBLIC_VERIFY_TIMING_V1 {}", serde_json::json!({
        "record": "context", "variant": variant, "crypto_source_sha256": source_sha256,
        "probe_sha256": sha(include_bytes!("public_verification_timing_probe_v1.rs")),
        "fixture_sha256": FIXTURE_SHA, "source_context": context,
        "profile": PROFILE, "integer_backend": true,
        "fn_no_avx2": "integer_backend transitively selects no_avx2 in pinned Cargo.toml",
        "native_provider": "unchanged pinned profile_adapter.c: ossl_ed448_verify(NULL,...,NULL)",
        "target_os": std::env::consts::OS, "target_arch": std::env::consts::ARCH,
        "debug_assertions": cfg!(debug_assertions),
        "effective_build_profile_and_flags": "REQUIRED in separate actual Root build receipt",
        "embedded_source_pin_is_binary_attestation": false,
        "linked_dependency_source_identity": "REQUIRED in actual Root build/source-closure receipt",
        "embedded_crate_lock_is_effective_build_lock": "must be established by actual build receipt",
        "rounds": ROUNDS, "repetitions_per_phase_per_vector": REPETITIONS,
        "vector_count": vectors.len(), "timed_calls": ROUNDS * REPETITIONS * 2 * vectors.len(),
        "untimed_explicit_public_calls": 12,
        "untimed_descriptor_decode": 2,
        "clock": "std::time::Instant monotonic; aggregate elapsed ns per fixed batch",
        "phase_scope": "whole public API; verify includes its own key admission",
    }));
    let mut rows = 0;
    for round in 0..ROUNDS {
        let phases = if round % 2 == 0 { [Phase::Validate, Phase::Verify] }
                     else { [Phase::Verify, Phase::Validate] };
        for (index, vector) in vectors.iter().enumerate() {
            for (position, phase) in phases.into_iter().enumerate() {
                let elapsed_ns = sample(vector, phase);
                let name = match phase { Phase::Validate => "PublicKey.validate", Phase::Verify => "PublicKey.verify" };
                println!("PUBLIC_VERIFY_TIMING_V1 {}", serde_json::json!({
                    "record": "sample", "variant": variant, "round": round,
                    "position": position, "vector": index, "phase": name,
                    "repetitions": REPETITIONS, "elapsed_ns": elapsed_ns,
                    "all_results": "Ok(())", "descriptor_sha256": vector.descriptor_sha256,
                    "challenge_sha256": vector.challenge_sha256,
                    "signature_sha256_ed448_then_fndsa": vector.signature_sha256,
                }));
                rows += 1;
            }
        }
    }
    assert_eq!(rows, 16);
    println!("PUBLIC_VERIFY_TIMING_V1 {}", serde_json::json!({
        "record": "complete", "variant": variant, "sample_rows": rows,
        "timed_validate_calls": 16, "timed_verify_calls": 16,
        "all_expected_outputs_verified": true,
        "meaning": "diagnosis only; no internal attribution, speed claim or Node ETA",
    }));
}
