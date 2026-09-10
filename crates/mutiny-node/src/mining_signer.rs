//! Operational signing safety; not consensus or chain state.
use super::*;
use std::fs::{File, OpenOptions};
use std::io::Write;

pub(super) trait MiningAuthority {
    fn public_key(&self) -> [u8; 32];
    fn presence(
        &self,
        state: &DevnetState,
        li: usize,
        epoch: u64,
    ) -> Result<ProtocolOperationV1, String>;
    fn sign_candidate(
        &self,
        state: &DevnetState,
        height: u64,
        core: &[u8; 208],
    ) -> Result<[u8; 64], String>;
}
impl MiningAuthority for SigningKey {
    fn public_key(&self) -> [u8; 32] {
        self.verifying_key().to_bytes()
    }
    fn presence(
        &self,
        state: &DevnetState,
        li: usize,
        epoch: u64,
    ) -> Result<ProtocolOperationV1, String> {
        presence::create_operation(state, li, epoch, self)
    }
    fn sign_candidate(
        &self,
        state: &DevnetState,
        _height: u64,
        core: &[u8; 208],
    ) -> Result<[u8; 64], String> {
        // Raw authority exists only for inherited Devnet paths and explicitly controlled unit fixtures.
        if state.network_id != DEVNET_NETWORK_ID && !cfg!(test) {
            return Err("Mainnet block signing requires durable MiningSigner".into());
        }
        Ok(self.sign(&block_signing_digest(core).0).to_bytes())
    }
}

pub(super) struct MiningSigner {
    key: SigningKey,
    binding: Vec<u8>,
    store: Mutex<Store>,
}
struct Store {
    root: PathBuf,
    _lock: File,
    // A durability error permanently disables block authorization in this instance.
    failed: bool,
}
const BINDING_MAGIC: &[u8; 8] = b"MUTMSB01";
const RECORD_MAGIC: &[u8; 8] = b"MUTMSA01";
const BINDING_LEN: usize = 8 + 4 + 32 + 32 + 32;
const RECORD_LEN: usize = 8 + BINDING_LEN + 8 + 208 + 32;
fn io_error(e: impl std::fmt::Display) -> String {
    format!("LOCAL_MINING_SIGNER: {e}")
}
fn binding(state: &DevnetState, li: usize, public: &[u8; 32]) -> Result<Vec<u8>, String> {
    validate_runtime_tuple(state, RuntimeNetwork::Mainnet)?;
    let license = state.licenses.get(li).ok_or("signer license missing")?;
    if decode32(&license.mining_public_key)? != *public {
        return Err("signer public key/license mismatch".into());
    }
    let mut b = BINDING_MAGIC.to_vec();
    b.extend_from_slice(&state.network_id.to_be_bytes());
    b.extend_from_slice(&decode32(&state.genesis_hash)?);
    b.extend_from_slice(&decode32(&license.license_id)?);
    b.extend_from_slice(public);
    Ok(b)
}
fn scope(binding: &[u8], core: &[u8]) -> String {
    // Tier-3 collision predicate: parent and height MUST NOT split this scope.
    let mut bytes = b"MUTINY-MINING-SCOPE-V1".to_vec();
    bytes.extend_from_slice(binding);
    bytes.extend_from_slice(&core[6..14]);
    bytes.extend_from_slice(&core[110..208]);
    hex::encode(Sha256::digest(bytes))
}
fn record(binding: &[u8], height: u64, core: &[u8; 208]) -> Vec<u8> {
    let mut b = RECORD_MAGIC.to_vec();
    b.extend_from_slice(binding);
    b.extend_from_slice(&height.to_be_bytes());
    b.extend_from_slice(core);
    let checksum = Sha256::digest(&b);
    b.extend_from_slice(&checksum);
    b
}
fn validate_record(bytes: &[u8], expected: &[u8]) -> Result<String, String> {
    if bytes.len() != RECORD_LEN
        || &bytes[..8] != RECORD_MAGIC
        || &bytes[8..8 + BINDING_LEN] != expected
    {
        return Err("signer record format/authority mismatch".into());
    }
    if Sha256::digest(&bytes[..RECORD_LEN - 32]).as_slice() != &bytes[RECORD_LEN - 32..] {
        return Err("signer record checksum mismatch".into());
    }
    let core = &bytes[16 + BINDING_LEN..RECORD_LEN - 32];
    if core[2..6] != expected[8..12] || core[142..174] != expected[44..76] {
        return Err("signer record core binding mismatch".into());
    }
    Ok(scope(expected, core))
}
#[cfg(windows)]
fn durable_publish(from: &Path, to: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(from: *const u16, to: *const u16, flags: u32) -> i32;
    }
    let a = from
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let b = to
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    // WRITE_THROUGH, deliberately without REPLACE_EXISTING.
    if unsafe { MoveFileExW(a.as_ptr(), b.as_ptr(), 8) } == 0 {
        return Err(io_error(std::io::Error::last_os_error()));
    }
    Ok(())
}
#[cfg(not(windows))]
fn durable_publish(from: &Path, to: &Path) -> Result<(), String> {
    fs::hard_link(from, to).map_err(io_error)?;
    #[cfg(test)]
    commit_fault("before_publish_directory_sync")?;
    File::open(to.parent().ok_or("missing parent")?)
        .and_then(|f| f.sync_all())
        .map_err(io_error)?;
    fs::remove_file(from).map_err(io_error)?;
    #[cfg(test)]
    commit_fault("before_cleanup_directory_sync")?;
    File::open(to.parent().ok_or("missing parent")?)
        .and_then(|f| f.sync_all())
        .map_err(io_error)
}
#[cfg(test)]
thread_local! {
    static COMMIT_FAULT: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}
#[cfg(test)]
fn commit_fault(stage: &'static str) -> Result<(), String> {
    COMMIT_FAULT.with(|fault| {
        if fault.get() == Some(stage) {
            fault.set(None);
            Err(io_error(format!("injected commit failure: {stage}")))
        } else {
            Ok(())
        }
    })
}
fn commit(root: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    let pending = root.join(format!("{name}.pending"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&pending)
        .map_err(io_error)?;
    #[cfg(test)]
    commit_fault("after_pending_create")?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(io_error)?;
    drop(file);
    #[cfg(test)]
    commit_fault("after_file_sync")?;
    durable_publish(&pending, &root.join(name))?;
    #[cfg(test)]
    commit_fault("after_publish")?;
    Ok(())
}
impl MiningSigner {
    pub(super) fn open(
        state: &DevnetState,
        li: usize,
        key: SigningKey,
        root: &Path,
        initialize: bool,
    ) -> Result<Self, String> {
        let binding = binding(state, li, &key.verifying_key().to_bytes())?;
        if !root.is_dir() {
            return Err("anti-equivocation directory must be provisioned explicitly".into());
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join("signer.lock"))
            .map_err(io_error)?;
        lock.try_lock().map_err(io_error)?;
        let authority = root.join("authority.v1");
        if initialize {
            let existing = fs::read_dir(root)
                .map_err(io_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(io_error)?;
            if existing.iter().any(|e| e.file_name() != "signer.lock") {
                return Err("refusing to initialize nonempty signer history".into());
            }
            commit(root, "authority.v1", &binding)?;
        }
        if fs::read(&authority).map_err(io_error)? != binding {
            return Err("signer authority binding mismatch".into());
        }
        for entry in fs::read_dir(root).map_err(io_error)? {
            let entry = entry.map_err(io_error)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "signer.lock" || name == "authority.v1" {
                continue;
            }
            if !name.ends_with(".authorization") {
                return Err("signer contains incomplete or unknown record; fail closed".into());
            }
            let bytes = fs::read(entry.path()).map_err(io_error)?;
            if format!("{}.authorization", validate_record(&bytes, &binding)?) != name {
                return Err("signer record scope filename mismatch".into());
            }
        }
        Ok(Self {
            key,
            binding,
            store: Mutex::new(Store {
                root: root.to_path_buf(),
                _lock: lock,
                failed: false,
            }),
        })
    }
    fn check(&self, state: &DevnetState, li: usize) -> Result<(), String> {
        if binding(state, li, &self.public_key())? != self.binding {
            return Err("signer runtime/license binding mismatch".into());
        }
        Ok(())
    }
    fn authorize(&self, state: &DevnetState, height: u64, core: &[u8; 208]) -> Result<(), String> {
        let li = state
            .licenses
            .iter()
            .position(|l| decode32(&l.license_id).is_ok_and(|id| id == core[142..174]))
            .ok_or("candidate license missing")?;
        self.check(state, li)?;
        if core[0..2] != 1u16.to_be_bytes()
            || core[2..6] != state.network_id.to_be_bytes()
            || core[14..46] != decode32(&state.tip_hash)?
            || height != state.height.checked_add(1).ok_or("height overflow")?
        {
            return Err("candidate network/parent/height binding mismatch".into());
        }
        let expected = record(&self.binding, height, core);
        let name = format!("{}.authorization", scope(&self.binding, core));
        let mut store = self.store.lock().map_err(|_| "signer mutex poisoned")?;
        if store.failed {
            return Err(
                "LOCAL_MINING_SIGNER: signer disabled after durability failure; reopen required"
                    .into(),
            );
        }
        let path = store.root.join(&name);
        match fs::read(&path) {
            Ok(existing) => {
                validate_record(&existing, &self.binding)?;
                if existing != expected {
                    return Err("conflicting same-scope mining authorization refused".into());
                }
                // Ensure an exact retry never relies on an unflushed record.
                let flushed = OpenOptions::new()
                    .write(true)
                    .open(&path)
                    .and_then(|f| f.sync_all())
                    .map_err(io_error);
                #[cfg(test)]
                let flushed = flushed.and_then(|_| commit_fault("retry_file_sync"));
                if let Err(error) = flushed {
                    store.failed = true;
                    return Err(error);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Err(error) = commit(&store.root, &name, &expected) {
                    store.failed = true;
                    return Err(error);
                }
            }
            Err(e) => return Err(io_error(e)),
        }
        Ok(())
    }
}
impl MiningAuthority for MiningSigner {
    fn public_key(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
    fn presence(
        &self,
        state: &DevnetState,
        li: usize,
        epoch: u64,
    ) -> Result<ProtocolOperationV1, String> {
        self.check(state, li)?;
        presence::create_operation(state, li, epoch, &self.key)
    }
    fn sign_candidate(
        &self,
        state: &DevnetState,
        height: u64,
        core: &[u8; 208],
    ) -> Result<[u8; 64], String> {
        self.authorize(state, height, core)?;
        Ok(self.key.sign(&block_signing_digest(core).0).to_bytes())
    }
}

pub(super) fn load(
    state: &DevnetState,
    li: usize,
    args: &[String],
    initialize: bool,
) -> Result<MiningSigner, String> {
    let chosen = required_option(args, "--mining-license-id")?;
    if state.licenses.get(li).ok_or("license missing")?.license_id != chosen {
        return Err("selected LicenseID mismatch".into());
    }
    let custody = Path::new(required_option(args, "--mining-custody-dir")?);
    let pass = read_required_wallet_passphrase_file(args)?;
    let key = load_mining_key_for_license(
        custody,
        state,
        li,
        required_option(args, "--mining-key-label")?,
        &pass,
    )?;
    MiningSigner::open(
        state,
        li,
        key,
        Path::new(required_option(args, "--anti-equivocation-dir")?),
        initialize,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};
    fn setup(tag: &str) -> (DevnetState, SigningKey, PathBuf, [u8; 208]) {
        let (state, key) = crate::tests::ordinary_mainnet_synthetic_parent();
        let root = env::temp_dir().join(format!(
            "mutiny-signer-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let mut core = [0u8; 208];
        core[..2].copy_from_slice(&1u16.to_be_bytes());
        core[2..6].copy_from_slice(&MAINNET_NETWORK_ID.to_be_bytes());
        core[6..14].copy_from_slice(&(state.tip_epoch + 1).to_be_bytes());
        core[14..46].copy_from_slice(&decode32(&state.tip_hash).unwrap());
        core[142..174].copy_from_slice(&decode32(&state.licenses[0].license_id).unwrap());
        (state, key, root, core)
    }
    #[test]
    fn build68_signer_commit_faults_disable_same_instance() {
        let mut stages = vec!["after_pending_create", "after_file_sync", "after_publish"];
        if cfg!(not(windows)) {
            stages.extend([
                "before_publish_directory_sync",
                "before_cleanup_directory_sync",
            ]);
        }
        for stage in stages {
            let (state, key, root, core) = setup(stage);
            let height = state.height + 1;
            let signer = MiningSigner::open(&state, 0, key.clone(), &root, true).unwrap();
            // Baseline bytes remain identical to ordinary deterministic Ed25519 signing.
            let expected = key.sign(&block_signing_digest(&core).0).to_bytes();
            assert_eq!(
                signer.sign_candidate(&state, height, &core).unwrap(),
                expected
            );
            let mut request = core;
            request[6..14].copy_from_slice(&(state.tip_epoch + 2).to_be_bytes());
            COMMIT_FAULT.with(|fault| fault.set(Some(stage)));
            let result = signer.sign_candidate(&state, height, &request);
            assert!(result.unwrap_err().contains(stage)); // Err carries no signature.
            COMMIT_FAULT.with(|fault| assert_eq!(fault.get(), None));
            let mut conflict = request;
            conflict[46] ^= 1;
            let mut next = request;
            next[6..14].copy_from_slice(&(state.tip_epoch + 3).to_be_bytes());
            for retry in [&request, &conflict, &next, &core] {
                assert!(signer
                    .sign_candidate(&state, height, retry)
                    .unwrap_err()
                    .contains("disabled after durability failure"));
            }
            drop(signer);
            let reopened = MiningSigner::open(&state, 0, key.clone(), &root, false);
            if matches!(stage, "after_publish" | "before_cleanup_directory_sync") {
                // These hooks run only after durable final-name publication succeeded.
                let reopened = reopened.unwrap();
                assert!(reopened
                    .sign_candidate(&state, height, &conflict)
                    .unwrap_err()
                    .contains("conflicting"));
                assert_eq!(
                    reopened.sign_candidate(&state, height, &request).unwrap(),
                    key.sign(&block_signing_digest(&request).0).to_bytes()
                );
            } else {
                assert!(reopened.is_err()); // Pending/torn history is never repaired here.
            }
            println!("durability fault {stage}: no signature; same-instance retries refused; reopen checked");
            fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn build68_signer_retry_flush_failure_disables_instance() {
        let (state, key, root, core) = setup("retry-flush");
        let height = state.height + 1;
        let signer = MiningSigner::open(&state, 0, key.clone(), &root, true).unwrap();
        let expected = signer.sign_candidate(&state, height, &core).unwrap();
        COMMIT_FAULT.with(|fault| fault.set(Some("retry_file_sync")));
        assert!(signer
            .sign_candidate(&state, height, &core)
            .unwrap_err()
            .contains("retry_file_sync"));
        assert!(signer
            .sign_candidate(&state, height, &core)
            .unwrap_err()
            .contains("disabled after durability failure"));
        drop(signer);
        let signer = MiningSigner::open(&state, 0, key, &root, false).unwrap();
        let mut conflict = core;
        conflict[46] ^= 1;
        assert!(signer.sign_candidate(&state, height, &conflict).is_err());
        assert_eq!(
            signer.sign_candidate(&state, height, &core).unwrap(),
            expected
        );
        drop(signer);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn hotfix1_signer_first_duplicate_conflict_next_scope() {
        let (state, key, root, core) = setup("duplicate");
        let height = state.height + 1;
        let signer = MiningSigner::open(&state, 0, key, &root, true).unwrap();
        let sig = signer.sign_candidate(&state, height, &core).unwrap();
        assert_eq!(sig, signer.sign_candidate(&state, height, &core).unwrap());
        let mut conflict = core;
        conflict[46] ^= 1;
        assert!(signer
            .sign_candidate(&state, height, &conflict)
            .unwrap_err()
            .contains("conflicting"));
        let mut next = core;
        next[6..14].copy_from_slice(&(state.tip_epoch + 2).to_be_bytes());
        assert!(signer.sign_candidate(&state, height, &next).is_ok());
        drop(signer);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn hotfix1_signer_restart_and_committed_before_signature_crash_reopen() {
        let (state, key, root, core) = setup("reopen");
        let height = state.height + 1;
        let signer = MiningSigner::open(&state, 0, key.clone(), &root, true).unwrap();
        // Exact crash boundary: commit completed, no signature has been requested/emitted.
        signer.authorize(&state, height, &core).unwrap();
        drop(signer);
        let signer = MiningSigner::open(&state, 0, key.clone(), &root, false).unwrap();
        let mut conflict = core;
        conflict[46] ^= 1;
        assert!(signer.sign_candidate(&state, height, &conflict).is_err());
        let sig = signer.sign_candidate(&state, height, &core).unwrap();
        drop(signer);
        let signer = MiningSigner::open(&state, 0, key, &root, false).unwrap();
        assert_eq!(sig, signer.sign_candidate(&state, height, &core).unwrap());
        assert!(signer.sign_candidate(&state, height, &conflict).is_err());
        drop(signer);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn hotfix1_signer_parent_and_height_cannot_split_consensus_scope() {
        let (state, key, root, core) = setup("parent");
        let signer = MiningSigner::open(&state, 0, key, &root, true).unwrap();
        signer
            .sign_candidate(&state, state.height + 1, &core)
            .unwrap();
        let mut reorg = state.clone();
        reorg.tip_hash = hex::encode([9u8; 32]);
        reorg.height += 1;
        let mut conflicting = core;
        conflicting[14..46].copy_from_slice(&[9; 32]);
        assert!(signer
            .sign_candidate(&reorg, reorg.height + 1, &conflicting)
            .unwrap_err()
            .contains("conflicting"));
        drop(signer);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn hotfix1_signer_network_license_public_key_fail_closed() {
        let (state, key, root, core) = setup("identity");
        let signer = MiningSigner::open(&state, 0, key.clone(), &root, true).unwrap();
        let mut devnet = state.clone();
        devnet.network_id = DEVNET_NETWORK_ID;
        assert!(signer
            .sign_candidate(&devnet, state.height + 1, &core)
            .is_err());
        let mut wrong = core;
        wrong[142] ^= 1;
        assert!(signer
            .sign_candidate(&state, state.height + 1, &wrong)
            .is_err());
        let mut changed = state.clone();
        changed.licenses[0].mining_public_key = hex::encode([7u8; 32]);
        assert!(signer
            .sign_candidate(&changed, state.height + 1, &core)
            .is_err());
        drop(signer);
        assert!(MiningSigner::open(&devnet, 0, key.clone(), &root, false).is_err());
        assert!(
            MiningSigner::open(&state, 0, SigningKey::from_bytes(&[3; 32]), &root, false).is_err()
        );
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn hotfix1_signer_exclusive_lock_and_corrupt_incomplete_history_fail_closed() {
        let (state, key, root, core) = setup("lock");
        let signer = MiningSigner::open(&state, 0, key.clone(), &root, true).unwrap();
        assert!(MiningSigner::open(&state, 0, key.clone(), &root, false).is_err());
        signer
            .sign_candidate(&state, state.height + 1, &core)
            .unwrap();
        drop(signer);
        let path = fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().path())
            .find(|p| p.extension().is_some_and(|v| v == "authorization"))
            .unwrap();
        let exact = fs::read(&path).unwrap();
        fs::write(&path, b"torn").unwrap();
        assert!(MiningSigner::open(&state, 0, key.clone(), &root, false).is_err());
        fs::write(&path, exact).unwrap();
        fs::write(root.join("interrupted.pending"), b"partial").unwrap();
        assert!(MiningSigner::open(&state, 0, key, &root, false).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn hotfix1_signer_keystore_role_network_passphrase_and_devnet_substitution() {
        let key = SigningKey::from_bytes(&[0x57; 32]);
        let pass = b"synthetic signer test passphrase";
        let file = mutiny_keystore::seal_seed(
            &key.to_bytes(),
            KeyRole::LicenseMining,
            MAINNET_NETWORK_ID,
            pass,
        )
        .unwrap();
        assert_eq!(
            mutiny_keystore::open(&file, KeyRole::LicenseMining, MAINNET_NETWORK_ID, pass)
                .unwrap()
                .verifying_key(),
            key.verifying_key()
        );
        assert!(
            mutiny_keystore::open(&file, KeyRole::LicenseOwner, MAINNET_NETWORK_ID, pass).is_err()
        );
        assert!(
            mutiny_keystore::open(&file, KeyRole::LicenseMining, DEVNET_NETWORK_ID, pass).is_err()
        );
        assert!(mutiny_keystore::open(
            &file,
            KeyRole::LicenseMining,
            MAINNET_NETWORK_ID,
            b"wrong test passphrase"
        )
        .is_err());
        let dev = mutiny_keystore::seal_seed(
            &key.to_bytes(),
            KeyRole::LicenseMining,
            DEVNET_NETWORK_ID,
            pass,
        )
        .unwrap();
        assert!(
            mutiny_keystore::open(&dev, KeyRole::LicenseMining, MAINNET_NETWORK_ID, pass).is_err()
        );
    }
    #[test]
    #[ignore = "explicit production credential authentication, never signs"]
    fn hotfix1_signer_production_custody_authentication() {
        let state = load_state(Path::new(
            &env::var("MUTINY_SIGNER_CANONICAL_BLOCK1_DIR").unwrap(),
        ))
        .unwrap();
        validate_runtime_tuple(&state, RuntimeNetwork::Mainnet).unwrap();
        assert_eq!(state.height, 1);
        let id = "080139e853eee69fb808a09127596052cbbcc626a1aa9b7b52eea0a29911bde7";
        let expected = "fc91a3012dd25cf50331d3c3d77b3c255ea209095b07b117ad115d51352d8974";
        let li = state
            .licenses
            .iter()
            .position(|l| l.license_id == id)
            .unwrap();
        assert_eq!(state.licenses[li].mining_public_key, expected);
        let custody_path = PathBuf::from(
            env::var_os("MUTINY_PROOF_MINING_CUSTODY_DIR")
                .expect("explicit external mining custody directory"),
        );
        let custody = custody_path.as_path();
        let pass_path = PathBuf::from(
            env::var_os("MUTINY_PROOF_MINING_PASSPHRASE_FILE")
                .expect("explicit external mining passphrase file"),
        );
        let pass = read_passphrase_path(&pass_path).unwrap();
        let key = load_mining_key_for_license(custody, &state, li, "license-01", &pass).unwrap();
        assert_eq!(hex::encode(key.verifying_key().to_bytes()), expected);
        let path = custody.join("secrets").join("mining-license-01.msk");
        let valid =
            mutiny_keystore::load_file(&path, KeyRole::LicenseMining, MAINNET_NETWORK_ID, &pass)
                .unwrap();
        assert_eq!(valid.verifying_key(), key.verifying_key());
        assert!(mutiny_keystore::load_file(
            &path,
            KeyRole::LicenseOwner,
            MAINNET_NETWORK_ID,
            &pass
        )
        .is_err());
        assert!(mutiny_keystore::load_file(
            &path,
            KeyRole::LicenseMining,
            DEVNET_NETWORK_ID,
            &pass
        )
        .is_err());
        assert!(mutiny_keystore::load_file(
            &path,
            KeyRole::LicenseMining,
            MAINNET_NETWORK_ID,
            b"deliberately wrong test passphrase"
        )
        .is_err());
        let other = (li + 1) % state.licenses.len();
        assert!(load_mining_key_for_license(custody, &state, other, "license-01", &pass).is_err());
        println!("Authenticated production LicenseID: {id}; derived mining public key: {expected}; CLI license number: {}",li+1);
    }
    #[test]
    #[ignore = "child process crash hook; synthetic authority only"]
    fn hotfix1_signer_crash_child() {
        let root = PathBuf::from(
            env::var("MUTINY_SIGNER_CRASH_TEST_ROOT").expect("explicit synthetic child root"),
        );
        let (state, key) = crate::tests::ordinary_mainnet_synthetic_parent();
        let core: [u8; 208] = fs::read(root.join("request.test"))
            .unwrap()
            .try_into()
            .unwrap();
        let store = root.join("store");
        let signer = MiningSigner::open(&state, 0, key, &store, false).unwrap();
        signer.authorize(&state, state.height + 1, &core).unwrap();
        std::process::exit(86); // No destructors or signature: abrupt process termination.
    }
    #[test]
    fn hotfix1_signer_native_crash_after_commit_rejects_conflict() {
        let (state, key, root, core) = setup("native-crash");
        let store = root.join("store");
        fs::create_dir(&store).unwrap();
        fs::write(root.join("request.test"), core).unwrap();
        drop(MiningSigner::open(&state, 0, key.clone(), &store, true).unwrap());
        let out = std::process::Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "mining_signer::tests::hotfix1_signer_crash_child",
                "--ignored",
                "--nocapture",
            ])
            .env("MUTINY_SIGNER_CRASH_TEST_ROOT", &root)
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(86),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let signer = MiningSigner::open(&state, 0, key, &store, false).unwrap();
        let mut conflict = core;
        conflict[46] ^= 1;
        assert!(signer
            .sign_candidate(&state, state.height + 1, &conflict)
            .is_err());
        assert!(signer
            .sign_candidate(&state, state.height + 1, &core)
            .is_ok());
        println!("Abrupt signer child native exit 86; reopened conflict refused");
        drop(signer);
        fs::remove_dir_all(root).unwrap();
    }
}
