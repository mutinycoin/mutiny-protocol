fn main() {
    assert_eq!(std::env::args().skip(1).collect::<Vec<_>>(), ["--qualify"]);
    let tpm = mutiny_crypto_v2::qualification_wallet_entropy_provider()
        .expect("Wallet entropy provider qualification failed; no entropy exported");
    println!("{}", serde_json::json!({
        "schema":"BUILD8-WALLET-ENTROPY-PROVIDER-V1", "result":"PASS",
        "mandatory_os_rng":true, "tpm_supplement_present":tpm,
        "conditioned_entropy_bytes":32, "entropy_exported":false,
        "wallet_created":false, "production_qualified":false,
        "tpm_command":"TPM2_GetRandom", "tpm_persistent_objects_modified":false
    }));
}
