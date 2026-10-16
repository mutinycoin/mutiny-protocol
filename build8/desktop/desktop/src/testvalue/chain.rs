//! Public deterministic TEST-VALUE Genesis. No peer claim is a verified wallet view.
use crate::{
    store_v2::Store,
    verified_sync_v2::Replica,
    wallet_controller_v2::{Controller, VaultRoot},
    wallet_v2::{RestoredKey, Session},
};
use mutiny_consensus_v8::{
    Hash,
    anchors::FinalizedAnchor,
    canonical_store_v2::CanonicalStore,
    dividend_state_v1::DividendState,
    execution::State,
    mempool_v2::Mempool,
    transactions::{Coin, OutPoint, Output},
    treasury_v1::{Class, Treasury},
};
use mutiny_wallet_core_v8::{ChainClass, profile::TreasuryDeclaration};
use std::path::Path;
pub const PASSWORD: &str = "PUBLIC NONSHIPPING TESTVALUE PASSWORD";
pub fn phrase(treasury: bool) -> String {
    if treasury {
        format!("{}vote", "zoo ".repeat(23))
    } else {
        format!("{}art", "abandon ".repeat(23))
    }
}
/// A fixed public BIP39 test vector; no entropy or user recovery material is requested.
pub fn rotation_phrase() -> &'static str {
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless"
}
pub fn open(
    root: &VaultRoot,
    treasury: bool,
    genesis: &FinalizedAnchor,
    state: &State,
) -> Result<Controller, String> {
    if state.dividends.treasury().map(|t| t.class()) != Some(Class::TestValue) {
        return Err("Only the driver's exact public TEST-VALUE initial state is permitted".into());
    }
    let a = Session::restore_initial(&phrase(false)).map_err(str::to_owned)?;
    let b = Session::restore_initial(&phrase(true)).map_err(str::to_owned)?;
    let verified_root = state.root().map_err(|_| "Public state root")?;
    let chain = CanonicalStore::open_trusted_genesis(
        &root.path().join("public-chain.sqlite"),
        genesis,
        state,
        verified_root,
        1000,
        [255; 32],
    )
    .map_err(|e| format!("Public chain refuses: {e:?}"))?;
    let replica = Replica::from_pinned_chain(chain)?;
    if replica
        .verified()?
        .1
        .dividends
        .treasury()
        .map(|t| t.class())
        != Some(Class::TestValue)
    {
        return Err("Only TEST-VALUE chain is permitted".into());
    }
    let mut store = Store::open(&root.vault()).map_err(|e| e.to_string())?;
    let expected = if treasury { &b } else { &a };
    if let Some(status) = store.status().map_err(str::to_owned)? {
        let authority: Hash = hex::decode(&expected.identity().authority_id)
            .map_err(|_| "Public authority")?
            .try_into()
            .map_err(|_| "Public authority length")?;
        let restored = RestoredKey::restore(rotation_phrase(), 2, None).map_err(str::to_owned)?;
        let descriptor = restored.descriptor().to_vec();
        let rotated =
            Session::restore_rotated(restored, authority, &descriptor).map_err(str::to_owned)?;
        let known = |identity: &crate::wallet_v2::Identity| {
            identity == expected.identity() || identity == rotated.identity()
        };
        let (_, state) = replica.verified()?;
        let current = state.wallets.current(authority).unwrap_or(&[]);
        if !known(&status.active)
            || status
                .staged
                .as_ref()
                .is_some_and(|identity| !known(identity))
            || status
                .superseded
                .as_ref()
                .is_some_and(|identity| !known(identity))
            || (status.active.generation == 2 && current != descriptor.as_slice())
        {
            return Err("This rehearsal permits only its exact public test identity; existing vault preserved".into());
        }
    } else {
        store
            .save_initial(expected, PASSWORD)
            .map_err(str::to_owned)?;
    }
    drop(store);
    let pool = Mempool::open(
        &root.path().join("public-payment-pool.sqlite"),
        genesis.genesis,
        genesis.fingerprint,
        65536,
    )
    .map_err(|e| format!("Public pool: {e:?}"))?;
    // The Treasury rehearsal host offers both R1 (authority rotation) and R2 (destination rotation of
    // the trading Treasury this TEST-VALUE state records under the same id), so its explicit
    // declaration names both roles; wallet-core checks each claim against the verified chain.
    let declaration = match state.dividends.treasury() {
        Some(record) if treasury => Some(
            TreasuryDeclaration::new(genesis.genesis, ChainClass::TestValue)
                .with_authority()
                .with_destination_of(record.authority()),
        ),
        _ => None,
    };
    let mut controller = Controller::open(root, replica, pool, declaration)?;
    controller.unlock(PASSWORD)?;
    Ok(controller)
}
pub fn marker(root: &Path, treasury: bool) -> Result<(), String> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../qualification/hybrid-canonical-store-public-v1.json"
    ))
    .map_err(|_| "Public fixture JSON")?;
    let anchor = FinalizedAnchor::decode(
        &hex::decode(fixture["genesis"].as_str().ok_or("Fixture Genesis")?)
            .map_err(|_| "Fixture Genesis hex")?,
    )
    .map_err(|_| "Fixture Genesis decode")?;
    let chain_identity = serde_json::json!({"network":anchor.network,"genesis":hex::encode(anchor.genesis),"fingerprint":hex::encode(anchor.fingerprint),"class":"TEST-VALUE","synthetic_genesis_block":hex::encode(mutiny_consensus_v8::domain_hash(b"MUTINY-WALLET-V8-TESTVALUE-GENESIS-V1",&anchor.genesis))});
    let marker = root.join("TEST-VALUE-VAULT-ROOT.marker");
    if root.exists() {
        let metadata = root
            .symlink_metadata()
            .map_err(|_| "Rehearsal root metadata")?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("Rehearsal root is not a plain directory".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("Rehearsal root is a reparse point".into());
            }
        }
        let marker_metadata = marker
            .symlink_metadata()
            .map_err(|_| "Existing folder has no TEST-VALUE marker; preserved")?;
        if !marker_metadata.is_file()
            || marker_metadata.len() > 2048
            || marker_metadata.file_type().is_symlink()
        {
            return Err("TEST-VALUE marker is not a bounded plain file".into());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if marker_metadata.file_attributes() & 0x400 != 0 {
                return Err("TEST-VALUE marker is a reparse point".into());
            }
        }
        let value: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&marker).map_err(|_| "TEST-VALUE marker read")?)
                .map_err(|_| "TEST-VALUE marker invalid")?;
        if value["format"] != "MUTINY-WALLET-V8-TESTVALUE-ROOT-V1"
            || value["treasury"] != treasury
            || value["synthetic_only"] != true
            || value["production_authorized"] != false
            || value["chain_identity"] != chain_identity
            || value["identifier"]
                .as_str()
                .is_none_or(|s| s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err("TEST-VALUE marker identity mismatch".into());
        }
        for entry in std::fs::read_dir(root).map_err(|_| "Rehearsal root read")? {
            let entry = entry.map_err(|_| "Rehearsal entry")?;
            let name = entry.file_name();
            let name = name.to_str().ok_or("Rehearsal filename")?;
            if ![
                "TEST-VALUE-VAULT-ROOT.marker",
                "WalletCustodyV2",
                "public-chain.sqlite",
                "public-chain.sqlite-wal",
                "public-chain.sqlite-shm",
                "public-payment-pool.sqlite",
                "public-payment-pool.sqlite-wal",
                "public-payment-pool.sqlite-shm",
            ]
            .contains(&name)
            {
                return Err("Existing folder contains unrelated files; preserved".into());
            }
            let metadata = entry
                .path()
                .symlink_metadata()
                .map_err(|_| "Rehearsal entry metadata")?;
            if metadata.file_type().is_symlink() {
                return Err("Rehearsal entry is a symbolic link".into());
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 {
                    return Err("Rehearsal entry is a reparse point".into());
                }
            }
        }
    } else {
        if !mutiny_consensus_v8::submission_pool_v1::private_directory(root)
            .map_err(|e| format!("Private rehearsal root: {e:?}"))?
        {
            return Err("Rehearsal root was not newly created by this invocation".into());
        }
        let mut identifier = [0; 32];
        mutiny_crypto_v2::fill_os_random(&mut identifier)
            .map_err(|_| "TEST-VALUE identifier entropy")?;
        let value = serde_json::json!({"format":"MUTINY-WALLET-V8-TESTVALUE-ROOT-V1","identifier":hex::encode(identifier),"treasury":treasury,"synthetic_only":true,"production_authorized":false,"chain_identity":chain_identity});
        std::fs::write(
            marker,
            serde_json::to_vec(&value).map_err(|_| "Marker encoding")?,
        )
        .map_err(|_| "Marker write")?;
    }
    crate::custody_format::check_vault_root(root).map_err(|e| e.to_string())
}
