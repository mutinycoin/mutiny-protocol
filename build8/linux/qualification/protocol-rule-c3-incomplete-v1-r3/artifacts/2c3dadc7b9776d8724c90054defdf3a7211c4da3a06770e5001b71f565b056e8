use sha2::{Digest, Sha256};
use std::path::{Component, Path};
fn main() {
    let aead_source =
        Path::new("../qualification/crypto-v2-sources/mbedtls-chachapoly-upstream-3.6.7");
    let aead_root = aead_source.canonicalize().unwrap();
    let aead_lock_path = Path::new("../qualification/MBEDTLS-CHACHAPOLY-SOURCE-LOCK-V2.json");
    let aead_lock: serde_json::Value =
        serde_json::from_slice(&std::fs::read(aead_lock_path).unwrap()).unwrap();
    assert_eq!(
        aead_lock["commit"],
        "068ff080b369adfac81509f9b57b2afabaf82dc5"
    );
    for (name, hash) in aead_lock["files"].as_object().unwrap() {
        assert!(
            Path::new(name)
                .components()
                .all(|x| matches!(x, Component::Normal(_)))
        );
        let path = aead_root.join(name).canonicalize().unwrap();
        assert!(path.starts_with(&aead_root));
        assert_eq!(
            format!("{:x}", Sha256::digest(std::fs::read(&path).unwrap())),
            hash.as_str().unwrap()
        );
        println!("cargo:rerun-if-changed={}", path.display());
    }
    let mut aead = cc::Build::new();
    aead.include("embedded")
        .include(aead_source.join("include"))
        .include(aead_source.join("library"))
        .define("MBEDTLS_CONFIG_FILE", "\"mbedtls_frame_config.h\"")
        .flag_if_supported("/std:c11")
        .file("embedded/aead_mbedtls_v1.c")
        .file("embedded/worker_finished_v2.c")
        .file("embedded/worker_frame_v2.c");
    for name in [
        "chacha20.c",
        "poly1305.c",
        "chachapoly.c",
        "constant_time.c",
        "platform_util.c",
    ] {
        aead.file(aead_source.join("library").join(name));
    }
    aead.compile("build8_frame_mbedtls_aead");
    for name in [
        "embedded/mbedtls_frame_config.h",
        "embedded/frame_namespace_v2.h",
        "embedded/aead_mbedtls_v1.c",
        "embedded/aead_mbedtls_v1.h",
        "embedded/worker_frame_v2.c",
        "embedded/worker_frame_v2.h",
        "embedded/worker_finished_v2.c",
        "embedded/worker_finished_v2.h",
    ] {
        println!("cargo:rerun-if-changed={name}");
    }
    println!("cargo:rerun-if-changed={}", aead_lock_path.display());
    // Allocation-free receive candidate, tested against the host wire codec.
    // No embedded driver or production session activation is linked here.
    cc::Build::new()
        .include("embedded")
        .flag_if_supported("/std:c11")
        .file("embedded/frame_v2.c")
        .file("embedded/handshake_frames_v2.c")
        .file("embedded/object_control_v2.c")
        .compile("build8_embedded_frame_v2");
    println!("cargo:rerun-if-changed=embedded/frame_v2.c");
    println!("cargo:rerun-if-changed=embedded/frame_v2.h");
    println!("cargo:rerun-if-changed=embedded/handshake_frames_v2.c");
    println!("cargo:rerun-if-changed=embedded/handshake_frames_v2.h");
    println!("cargo:rerun-if-changed=embedded/object_control_v2.c");
    println!("cargo:rerun-if-changed=embedded/object_control_v2.h");
    let source = Path::new("../qualification/crypto-v2-sources/mlkem-native-2.0.0");
    let root = source.canonicalize().unwrap();
    let lock_path = Path::new("../qualification/MLKEM-NATIVE-SOURCE-LOCK-V1.json");
    println!("cargo:rerun-if-changed={}", lock_path.display());
    let lock: serde_json::Value =
        serde_json::from_slice(&std::fs::read(lock_path).unwrap()).unwrap();
    assert_eq!(lock["commit"], "d1b2fe782888bdb761a50336012923180be7f502");
    for (name, hash) in lock["files"].as_object().unwrap() {
        assert!(
            Path::new(name)
                .components()
                .all(|x| matches!(x, Component::Normal(_)))
        );
        let p = root.join(name).canonicalize().unwrap();
        assert!(p.starts_with(&root));
        println!("cargo:rerun-if-changed={}", p.display());
        assert_eq!(
            format!("{:x}", Sha256::digest(std::fs::read(p).unwrap())),
            hash.as_str().unwrap()
        );
    }
    cc::Build::new()
        .include(".")
        .include(source.join("mlkem"))
        .define("MLK_CONFIG_FILE", "\"mlkem_config.h\"")
        .flag_if_supported("/std:c11")
        .file(source.join("mlkem/mlkem_native.c"))
        .compile("build8_transport_mlkem1024");
    println!("cargo:rerun-if-changed=mlkem_config.h");
}
