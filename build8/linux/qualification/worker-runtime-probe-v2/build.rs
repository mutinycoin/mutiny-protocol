use sha2::{Digest, Sha256};
use std::path::Path;
fn lock(file: &str, root: &str, entry: Option<&str>) {
    let value: serde_json::Value = serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
    let files = if let Some(e) = entry {
        &value["sources"][e]["files"]
    } else {
        &value["files"]
    };
    for (n, h) in files.as_object().unwrap() {
        let p = Path::new(root).join(n);
        assert_eq!(
            format!("{:x}", Sha256::digest(std::fs::read(&p).unwrap())),
            h.as_str().unwrap()
        );
        println!("cargo:rerun-if-changed={}", p.display());
    }
    println!("cargo:rerun-if-changed={file}");
}
fn main() {
    println!("cargo:rerun-if-changed=../../transport-v2/embedded/hash_namespace_v2.h");
    lock(
        "../worker-runtime-candidate-v2/qualification/ESP-ROM-CRC-QUALIFICATION-SOURCE-LOCK-V1.json",
        "../worker-runtime-candidate-v2/qualification/observation-compact-probe-v1/vendor",
        None,
    );
    let kdf = "../worker-runtime-candidate-v2/qualification/crypto-v2-sources/mbedtls-kdf-custody-v1";
    lock("../worker-runtime-candidate-v2/qualification/EMBEDDED-KDF-CUSTODY-SOURCE-LOCK-V1.json", kdf, None);
    let mut k = cc::Build::new();
    k.include("../../transport-v2/embedded")
        .include(format!("{kdf}/include"))
        .include(format!("{kdf}/library"))
        .define("MBEDTLS_CONFIG_FILE", "\"kdf_config_v1.h\"")
        .flag_if_supported("/std:c11")
        .flag_if_supported("/experimental:c11atomics")
        .file("../../transport-v2/embedded/worker_kdf_v2.c");
    for n in ["hkdf.c", "md.c", "sha512.c", "platform_util.c"] {
        k.file(format!("{kdf}/library/{n}"));
    }
    let hash = "../worker-runtime-candidate-v2/qualification/crypto-v2-sources/mbedtls-sha512-3.6.6";
    lock("../worker-runtime-candidate-v2/qualification/MBEDTLS-SHA512-SOURCE-LOCK-V1.json", hash, None);
    lock("../worker-runtime-candidate-v2/qualification/MBEDTLS-HASH-SOURCE-LOCK-V2.json", hash, None);
    cc::Build::new()
        .include(format!("{hash}/include"))
        .include("../worker-runtime-candidate-v2/qualification/enrollment-verifier-port")
        .define("MBEDTLS_CONFIG_FILE", "\"hash_config.h\"")
        .file(format!("{hash}/library/sha512.c"))
        .file(format!("{hash}/library/sha256.c"))
        .file("../worker-runtime-candidate-v2/qualification/enrollment-verifier-port/hash_adapter.c")
        .compile("build8_pending_public_hash");
    let cfn = "../../qualification/crypto-v2-sources/c-fn-dsa";
    lock(
        "../../qualification/CRYPTO-CANDIDATE-SOURCE-LOCK-V1.json",
        cfn,
        Some("c-fn-dsa"),
    );
    let mut c = cc::Build::new();
    c.include("../worker-runtime-candidate-v2/miner")
        .include("stubs")
        .include("../../transport-v2/embedded")
        .include(cfn)
        .define("FNDSA_AVX2", "0")
        .define("FNDSA_UNALIGNED_64", "0")
        .define("FNDSA_UNALIGNED_16", "0")
        .define("FNDSA_SSE2", "0")
        .flag_if_supported("/experimental:c11atomics")
        .flag_if_supported("/std:c11");
    for n in [
        "enrollment_v2",
        "enrollment_v2_store",
        "assignment_journal_v2",
        "worker_v2_candidate",
        "worker_session_auth_v2",
        "worker_handshake_v2",
        "worker_receive_v2",
        "work_v2",
        "mining_control_v2",
        "observation_v2",
        "observation_store_v2",
        "worker_accounting_v2",
    ] {
        c.file(format!("../worker-runtime-candidate-v2/miner/{n}.c"));
        println!("cargo:rerun-if-changed=../worker-runtime-candidate-v2/miner/{n}.c");
        println!("cargo:rerun-if-changed=../worker-runtime-candidate-v2/miner/{n}.h");
    }
    for n in ["codec", "mq", "util", "vrfy"] {
        c.file(format!("{cfn}/{n}.c"));
    }
    c.file("nvs_bridge.c");
    c.file("../worker-runtime-candidate-v2/miner/idf/main/worker_connection_v2.c");
    c.file("../worker-runtime-candidate-v2/miner/idf/main/worker_runtime_guard_v2.c");
    c.file("../worker-runtime-candidate-v2/miner/idf/main/worker_journal_runtime_v2.c");
    c.file("../worker-runtime-candidate-v2/miner/idf/main/worker_stream_v2.c");
    c.file("runtime_guard_bridge.c");
    c.file("journal_runtime_bridge.c");
    c.file("maintenance_accounting_bridge.c");
    c.include("../worker-runtime-candidate-v2/qualification/observation-compact-probe-v1/vendor")
        .file("../worker-runtime-candidate-v2/qualification/observation-compact-probe-v1/vendor/esp_rom_crc.c")
        .file("../worker-runtime-candidate-v2/miner/idf/main/observation_v2_nvs.c")
        .file("../worker-runtime-candidate-v2/miner/idf/main/worker_maintenance_v2.c");
    for name in [
        "maintenance_accounting_bridge.c",
        "../worker-runtime-candidate-v2/miner/idf/main/observation_v2_nvs.c",
        "../worker-runtime-candidate-v2/miner/idf/main/observation_v2_nvs.h",
        "../worker-runtime-candidate-v2/miner/idf/main/worker_maintenance_v2.c",
        "../worker-runtime-candidate-v2/miner/idf/main/worker_maintenance_v2.h",
        "../worker-runtime-candidate-v2/miner/pow_core.c",
        "../worker-runtime-candidate-v2/miner/pow_core.h",
        "../worker-runtime-candidate-v2/miner/pow_work.h",
        "../worker-runtime-candidate-v2/qualification/pow_accounting_host_bridge.c",
        "../worker-runtime-candidate-v2/qualification/observation-compact-probe-v1/vendor/esp_rom_crc.c",
        "../worker-runtime-candidate-v2/qualification/observation-compact-probe-v1/vendor/esp_rom_crc.h",
    ] {
        println!("cargo:rerun-if-changed={name}");
    }
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        c.include("stubs-posix")
            .define("BUILD8_QUAL_POSIX_SOCKET", "1")
            .file("../worker-runtime-candidate-v2/miner/idf/main/worker_socket_io_v2.c");
        c.file("../worker-runtime-candidate-v2/miner/idf/main/worker_socket_owner_v2.c");
        println!("cargo:rerun-if-changed=../worker-runtime-candidate-v2/miner/idf/main/worker_socket_owner_v2.c");
        println!("cargo:rerun-if-changed=../worker-runtime-candidate-v2/miner/idf/main/worker_socket_owner_v2.h");
        println!("cargo:rerun-if-changed=stubs-posix");
        println!("cargo:rerun-if-changed=../worker-runtime-candidate-v2/miner/idf/main/worker_socket_io_v2.c");
        println!("cargo:rerun-if-changed=../worker-runtime-candidate-v2/miner/idf/main/worker_socket_io_v2.h");
    }
    println!("cargo:rerun-if-changed=runtime_guard_bridge.c");
    println!("cargo:rerun-if-changed=journal_runtime_bridge.c");
    println!("cargo:rerun-if-changed=../worker-runtime-candidate-v2/miner/idf/main/worker_stream_v2.c");
    println!("cargo:rerun-if-changed=../worker-runtime-candidate-v2/miner/idf/main/worker_stream_v2.h");
    println!("cargo:rerun-if-changed=../worker-runtime-candidate-v2/miner/idf/main/worker_runtime_guard_v2.c");
    println!("cargo:rerun-if-changed=../worker-runtime-candidate-v2/miner/idf/main/worker_runtime_guard_v2.h");
    println!("cargo:rerun-if-changed=../worker-runtime-candidate-v2/miner/idf/main/worker_journal_runtime_v2.c");
    println!("cargo:rerun-if-changed=../worker-runtime-candidate-v2/miner/idf/main/worker_journal_runtime_v2.h");
    println!("cargo:rerun-if-changed=../worker-runtime-candidate-v2/miner/idf/main/worker_connection_v2.c");
    println!("cargo:rerun-if-changed=../worker-runtime-candidate-v2/miner/idf/main/worker_connection_v2.h");
    println!("cargo:rerun-if-changed=nvs_bridge.c");
    println!("cargo:rerun-if-changed=stubs");
    println!("cargo:rerun-if-changed=../worker-runtime-candidate-v2/miner/idf/main/worker_v2_nvs.c");
    println!("cargo:rerun-if-changed=../worker-runtime-candidate-v2/miner/idf/main/worker_v2_nvs.h");
    println!("cargo:rerun-if-changed=../worker-runtime-candidate-v2/miner/idf/main/enrollment_v2_nvs.c");
    println!("cargo:rerun-if-changed=../worker-runtime-candidate-v2/miner/idf/main/enrollment_v2_nvs.h");
    c.compile("build8_pending_authority");
    cc::Build::new()
        .include(format!("{hash}/include"))
        .include("../worker-runtime-candidate-v2/qualification/enrollment-verifier-port")
        .define("MBEDTLS_CONFIG_FILE", "\"hash_config.h\"")
        .file("../worker-runtime-candidate-v2/qualification/pow_accounting_host_bridge.c")
        .compile("build8_pending_pow_accounting");
    // Static archive users must precede their providers on ELF linkers.
    k.compile("build8_pending_kdf");
    for n in [
        "worker_kdf_v2.c",
        "worker_kdf_v2.h",
        "kdf_config_v1.h",
        "kdf_namespace_v1.h",
    ] {
        println!("cargo:rerun-if-changed=../../transport-v2/embedded/{n}");
    }
    println!("cargo:rerun-if-changed=../worker-runtime-candidate-v2/qualification/enrollment-verifier-port");
}
