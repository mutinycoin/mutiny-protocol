use mutiny_crypto_v2::{HybridKey,Role,Error};
#[test]
#[cfg(not(feature="wallet-custody"))]
fn default_build_cannot_import_wallet_private_material() {
    assert!(!mutiny_crypto_v2::WALLET_CUSTODY_ENABLED);
    for role in [Role::WalletOwner,Role::WalletRecovery] {
        assert!(matches!(HybridKey::generate(role),Err(Error::Role)));
        // Role rejection happens before envelope parsing/password processing.
        assert!(matches!(HybridKey::open(role,"not a secret",&[]),Err(Error::Role)));
    }
}
#[test]
#[cfg(not(feature="release-custody"))]
fn default_build_cannot_import_or_generate_release_private_material() {
    assert!(!mutiny_crypto_v2::RELEASE_CUSTODY_ENABLED);
    assert!(matches!(HybridKey::generate(Role::Release),Err(Error::Role)));
    assert!(matches!(HybridKey::open(Role::Release,"not a secret",&[]),Err(Error::Role)));
}
