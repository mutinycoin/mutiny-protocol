//! Synthetic qualification only. Secrets travel in anonymous pipes, never files,
//! arguments, environment, stdout, logs, or final evidence. Not a wallet UI.
use mutiny_crypto_v2::{HybridKey, Role, create_wallet_phrase};
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
use zeroize::Zeroizing;
fn public(key: &HybridKey) -> serde_json::Value {
    let p = key.public();
    serde_json::json!({"ed448":hex::encode(p.ed448),"fndsa":hex::encode(p.fndsa),"descriptor":hex::encode(p.descriptor(1).unwrap()),"address_id":hex::encode(p.address_id(1).unwrap())})
}
fn clean() -> bool {
    std::fs::read_dir(std::env::current_dir().unwrap())
        .unwrap()
        .next()
        .is_none()
}
fn child(mut command: Command, dir: &Path, secret: &[u8]) -> serde_json::Value {
    command
        .current_dir(dir)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(root) = std::env::var_os("SystemRoot") {
        command.env("SystemRoot", root);
    }
    let mut process = command.spawn().expect("Qualification process launch");
    process
        .stdin
        .take()
        .unwrap()
        .write_all(secret)
        .expect("Qualification pipe");
    let result = process
        .wait_with_output()
        .expect("Qualification process wait");
    assert!(
        result.status.success(),
        "Qualification child failed; no secret-bearing diagnostics forwarded"
    );
    assert!(
        result.stdout.len() < 16384 && result.stderr.is_empty(),
        "Unexpected qualification output"
    );
    serde_json::from_slice(&result.stdout).expect("Public result encoding")
}
fn main() {
    mutiny_crypto_v2::protect_process().expect("Process custody protection");
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--reference-keygen"] {
        let mut seed = Zeroizing::new([0u8; 32]);
        std::io::stdin()
            .read_exact(seed.as_mut())
            .expect("Reference input");
        let mut extra = [0];
        assert_eq!(
            std::io::stdin().read(&mut extra).unwrap(),
            0,
            "Reference input bound"
        );
        let pk = mutiny_crypto_v2::qualification_reference_fndsa_public(&seed);
        println!("{}", serde_json::json!({"fndsa":hex::encode(pk)}));
        return;
    }
    if args == ["--restore-child"] {
        assert!(clean(), "Restore working directory must be empty");
        let mut phrase = Zeroizing::new(String::new());
        std::io::stdin()
            .take(513)
            .read_to_string(&mut phrase)
            .expect("Restore input");
        assert!(phrase.len() <= 512, "Restore input bound");
        let key = HybridKey::wallet_restore(&phrase, Role::WalletOwner).expect("Synthetic restore");
        let p = public(&key);
        drop(key);
        drop(phrase);
        println!(
            "{}",
            serde_json::json!({"public":p,"empty_directory":clean()})
        );
        return;
    }
    assert_eq!(
        args,
        ["--qualify"],
        "Explicit synthetic qualification mode required"
    );
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let q = root.join("qualification");
    let exe = std::env::current_exe().unwrap();
    let phrase = create_wallet_phrase().expect("Mandatory OS and available TPM entropy");
    let key = HybridKey::wallet_restore(&phrase, Role::WalletOwner).expect("Synthetic creation");
    let expected = public(&key);
    drop(key);
    let mut tag = [0u8; 16];
    mutiny_crypto_v2::fill_os_random(&mut tag).expect("Directory entropy");
    let isolation = q.join(format!("restore-isolation-{}", hex::encode(tag)));
    std::fs::create_dir(&isolation).unwrap();
    let rust_dir = isolation.join("rust");
    let reference_dir = isolation.join("reference");
    std::fs::create_dir(&rust_dir).unwrap();
    std::fs::create_dir(&reference_dir).unwrap();
    let mut cmd = Command::new(&exe);
    cmd.arg("--restore-child");
    let rust = child(cmd, &rust_dir, phrase.as_bytes());
    let mut cmd = Command::new("D:\\Mutiny\\tools\\build8-wallet-verifier\\Scripts\\python.exe");
    cmd.arg(q.join("wallet_hybrid_restore_reference_v1.py"))
        .arg(&exe);
    let reference = child(cmd, &reference_dir, phrase.as_bytes());
    drop(phrase);
    assert_eq!(rust["public"], expected);
    assert_eq!(reference["public"], expected);
    assert_eq!(rust["empty_directory"], true);
    assert_eq!(reference["empty_directory"], true);
    // Only empty, newly created directories are removed; no recursive deletion.
    std::fs::remove_dir(&rust_dir).unwrap();
    std::fs::remove_dir(&reference_dir).unwrap();
    std::fs::remove_dir(&isolation).unwrap();
    let report = serde_json::json!({"schema":"BUILD8-HYBRID-CLEAN-RESTORE-V1","result":"SYNTHETIC_ISOLATED_RESTORE_PASS","production_qualified":false,"public":expected,"source_instance_destroyed_before_restore":true,"restored_in_fresh_processes":true,"empty_working_directories":true,"application_private_files_written":false,"private_data_in_arguments_or_environment":false,"mnemonic_in_evidence":false,"reference":"Python PBKDF2/HMAC-HKDF, Python/OpenSSL Ed448, pristine C FN-DSA keygen","executable_sha256":hex::encode(Sha256::digest(std::fs::read(&exe).unwrap())),"limitations":["Synthetic wallet only; no real Architect wallet accessed","Process/directory isolation is not a VM or hardware custody boundary","Python reference is test-only and cannot guarantee complete memory erasure","OS pagefile/hibernation and privileged memory inspection require deployment custody controls","Production dependency, UI/custody and whole-protocol qualification remain pending"]});
    std::fs::write(
        q.join("wallet-hybrid-clean-restore-v3.json"),
        serde_json::to_vec_pretty(&report).unwrap(),
    )
    .unwrap();
    println!("SYNTHETIC_ISOLATED_RESTORE_PASS; public-only evidence written");
}
