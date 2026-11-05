//! NON-SHIPPING original public TEST-VALUE replay and exact-wire verifier.
//! No fixture(), replacement Genesis, certifier private capability or transport key.
use crate::wallet_controller_v2::VaultRoot;
use mutiny_consensus_v8::{Hash, anchors::FinalizedAnchor,
    canonical_store_v2::{CanonicalStore, Head}, execution::State,
    treasury_v1::Class};
use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, io::Read, path::{Component, Path, PathBuf}};
type Result<T> = std::result::Result<T, String>;
const MAX_RECEIPT: usize = 16 * 1024 * 1024;
const MAX_ROWS: usize = 4096;
const MAX_VALUE: usize = 1024 * 1024;
const MAX_VALUES: usize = 8 * 1024 * 1024;

pub(super) fn plain_original(path: &Path, directory: bool) -> Result<()> {
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir)) {
        return Err("Original path must be absolute without traversal".into());
    }
    for ancestor in path.ancestors() {
        let m = std::fs::symlink_metadata(ancestor).map_err(|e| format!("Missing original path: {e}"))?;
        if m.file_type().is_symlink() { return Err("Original symlink refused".into()); }
        #[cfg(windows)] {
            use std::os::windows::fs::MetadataExt;
            if m.file_attributes() & 0x400 != 0 { return Err("Original reparse ancestor refused".into()); }
        }
    }
    let m = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if if directory { !m.is_dir() } else { !m.is_file() } {
        return Err("Original path type mismatch".into());
    }
    Ok(())
}
pub(super) fn read_bounded(path: &Path, max: usize) -> Result<Vec<u8>> {
    plain_original(path, false)?;
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    if file.metadata().map_err(|e| e.to_string())?.len() > max as u64 {
        return Err("Original public receipt allocation bound".into());
    }
    let mut raw = Vec::new();
    file.take(max as u64 + 1).read_to_end(&mut raw).map_err(|e| e.to_string())?;
    if raw.len() > max { return Err("Original public receipt grew past bound".into()); }
    Ok(raw)
}
fn str_field<'a>(v: &'a serde_json::Value, key: &str) -> Result<&'a str> {
    v.get(key).and_then(|s| s.as_str()).ok_or_else(|| format!("Original receipt field {key}"))
}
fn u64_field(v: &serde_json::Value, key: &str) -> Result<u64> {
    v.get(key).and_then(|s| s.as_u64()).ok_or_else(|| format!("Original receipt integer {key}"))
}
pub(super) fn hash(raw: &str) -> Result<Hash> {
    if raw.len() != 64 { return Err("Original hash width".into()); }
    hex::decode(raw).map_err(|_| "Original hash hex")?.try_into().map_err(|_| "Original hash width".into())
}
pub(super) fn pinned_file(path: &Path, expected: Hash, limit: usize) -> Result<Vec<u8>> {
    let raw = read_bounded(path, limit)?;
    if Hash::from(Sha256::digest(&raw)) != expected { return Err("Original externally pinned bytes mismatch".into()); }
    Ok(raw)
}

pub struct OriginalReplay {
    pub genesis: FinalizedAnchor,
    pub initial: State,
    pub initial_root: Hash,
    pub original_source_manifest: Hash,
    pub original_exe: Hash,
    pub driver_root: PathBuf,
    pub head: Head,
    // Keep the four actual replay-verified original stores live.
    stores: Vec<CanonicalStore>,
}
impl OriginalReplay {
    /// Caller supplies the independently recorded H0 receipt SHA from BEFORE H1.
    /// Existing originals are mandatory. This never provisions/repairs old permissions.
    pub fn open(receipt_path: &Path, expected_receipt: Hash,
        driver_root: &Path, vault_root: &VaultRoot) -> Result<Self> {
        let raw = pinned_file(receipt_path, expected_receipt, MAX_RECEIPT)?;
        let v: serde_json::Value = serde_json::from_slice(&raw).map_err(|_| "Original receipt JSON")?;
        if str_field(&v, "format")? != "MUTINY-WALLET-V8-PUBLIC-ORIGINAL-H0-ROWS-V1" {
            return Err("Original public H0 format".into());
        }
        plain_original(driver_root, true)?;
        plain_original(vault_root.path(), true)?;
        let original_driver = PathBuf::from(str_field(&v, "original_driver_root")?);
        if driver_root != original_driver { return Err("Original driver root mismatch".into()); }
        let started_path = PathBuf::from(str_field(&v, "started_receipt")?);
        let started_raw = pinned_file(&started_path, hash(str_field(&v, "started_receipt_sha256")?)?, MAX_RECEIPT)?;
        let started: serde_json::Value = serde_json::from_slice(&started_raw).map_err(|_| "Original start receipt JSON")?;
        if Path::new(str_field(&started, "driver_root")?) != driver_root
            || Path::new(str_field(&started, "vault_root")?) != vault_root.path() {
            return Err("Original started roots mismatch".into());
        }
        let original_exe = hash(str_field(&v, "original_exe_sha256")?)?;
        let exe = PathBuf::from(str_field(&started, "exe")?);
        plain_original(&exe, false)?;
        if exe.parent() != driver_root.parent()
            || hash(str_field(&started, "exe_sha256")?)? != original_exe {
            return Err("Original executable association mismatch".into());
        }
        // Hash the existing original executable without an unbounded allocation.
        let mut f = std::fs::File::open(&exe).map_err(|e| e.to_string())?;
        if f.metadata().map_err(|e| e.to_string())?.len() > 512 * 1024 * 1024 {
            return Err("Original executable verification bound".into());
        }
        let mut digest = Sha256::new(); let mut buffer = [0u8; 65536];
        loop { let n = f.read(&mut buffer).map_err(|e| e.to_string())?; if n == 0 { break; } digest.update(&buffer[..n]); }
        if Hash::from(digest.finalize()) != original_exe { return Err("Original executable hash mismatch".into()); }
        let original_source_manifest = hash(str_field(&v, "original_source_manifest_sha256")?)?;
        if hash(str_field(&started, "build_manifest_sha256")?)? != original_source_manifest {
            return Err("Original source manifest association mismatch".into());
        }
        pinned_file(Path::new(str_field(&started, "build_manifest")?), original_source_manifest, MAX_RECEIPT)?;
        let identity_raw = pinned_file(&driver_root.join("public-driver-identity.json"),
            hash(str_field(&v, "original_driver_identity_sha256")?)?, MAX_RECEIPT)?;
        let identity: serde_json::Value = serde_json::from_slice(&identity_raw).map_err(|_| "Original driver identity JSON")?;
        if identity != *v.get("original_driver_identity").ok_or("Missing original driver identity")?
            || str_field(&identity, "driver")? != "MUTINY-WALLET-V8-TESTVALUE-NATIVE-DRIVER-V1" {
            return Err("Original driver identity mismatch".into());
        }
        let genesis_hex = str_field(&v, "genesis")?;
        if genesis_hex.len() > 8192 || genesis_hex.len() % 2 != 0 { return Err("Original Genesis bound".into()); }
        let genesis_bytes = hex::decode(genesis_hex).map_err(|_| "Original Genesis hex")?;
        let genesis = FinalizedAnchor::decode(&genesis_bytes).map_err(|e| format!("Original Genesis: {e:?}"))?;
        let initial_root = hash(str_field(&v, "original_root")?)?;
        let head = v.get("head").ok_or("Missing original H0 head")?;
        let t0 = u64_field(head, "timestamp")?;
        let target = hash(str_field(head, "target")?)?;
        if genesis.height != 0 || u64_field(head, "height")? != 0
            || hash(str_field(head, "root")?)? != initial_root
            || hash(str_field(head, "block")?)? != genesis.block
            || str_field(&identity, "genesis")? != str_field(&v, "genesis")?
            || hash(str_field(&identity, "initial_root")?)? != initial_root
            || t0 != 1000 || target != [255;32] {
            return Err("Original TEST-VALUE H0 context mismatch".into());
        }
        let records = v.get("records").and_then(|r| r.as_array()).ok_or("Original record array")?;
        if records.is_empty() || records.len() > MAX_ROWS || u64_field(&v, "row_count")? != records.len() as u64 {
            return Err("Original row count bound".into());
        }
        let mut total = 0usize;
        for row in records {
            let text = str_field(row, "record")?;
            if text.len() % 2 != 0 || text.len() > MAX_VALUE * 2 { return Err("Original value bound".into()); }
            total = total.checked_add(text.len()/2).ok_or("Original total overflow")?;
            if total > MAX_VALUES { return Err("Original total value bound".into()); }
        }
        if u64_field(&v, "total_record_bytes")? != total as u64 { return Err("Original total bytes mismatch".into()); }
        let mut unique = BTreeSet::new();
        let mut rows = Vec::with_capacity(records.len());
        for row in records {
            let key = hash(str_field(row, "key")?)?;
            if !unique.insert(key) { return Err("Duplicate original state key".into()); }
            rows.push((key, hex::decode(str_field(row, "record")?).map_err(|_| "Original state value hex")?));
        }
        let initial = State::from_records(&rows, initial_root).map_err(|e| format!("Original typed state: {e:?}"))?;
        if initial.dividends.treasury().map(|t| t.class()) != Some(Class::TestValue) {
            return Err("Original state is not explicit TEST-VALUE".into());
        }
        let paths = [driver_root.join("certifier.sqlite"), driver_root.join("local-node-chain.sqlite"),
            driver_root.join("remote-node-chain.sqlite"), vault_root.path().join("public-chain.sqlite")];
        if Path::new(str_field(&v, "original_certifier_path")?) != paths[0] {
            return Err("Original certifier path mismatch".into());
        }
        // Require every original store to exist and already contain its pinned
        // canonical H0 before opening any of them. CanonicalStore can initialize
        // an empty SQLite file; this verifier must never use that capability.
        for path in &paths {
            plain_original(path, false)?;
            let db = rusqlite::Connection::open_with_flags(path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(|e| format!("Original existing-store read-only preflight: {e}"))?;
            let version: i64 = db.pragma_query_value(None, "user_version", |r| r.get(0))
                .map_err(|e| format!("Original existing-store version: {e}"))?;
            if version != 4 { return Err("Original store must already use the preserved version-4 canonical schema".into()); }
            let original_root: Vec<u8> = db.query_row(
                "SELECT root FROM canonical_v2 WHERE height=?1",
                [0u64.to_be_bytes().as_slice()], |r| r.get(0))
                .map_err(|e| format!("Original existing-store canonical H0: {e}"))?;
            if original_root.as_slice() != initial_root {
                return Err("Original existing-store H0 root mismatch".into());
            }
        }
        let mut stores = Vec::new();
        let mut common = None;
        for path in &paths {
            plain_original(path, false)?;
            let store = CanonicalStore::open_trusted_genesis(path, &genesis, &initial, initial_root, t0, target)
                .map_err(|e| format!("Original full canonical replay: {e:?}"))?;
            let (head, state) = store.load().map_err(|e| format!("Original current state: {e:?}"))?;
            if state.root().map_err(|e| format!("Original current root: {e:?}"))? != head.root
                || common.as_ref().is_some_and(|h| h != &head) {
                return Err("Original independent canonical stores disagree".into());
            }
            common = Some(head); stores.push(store);
        }
        let head = common.ok_or("Missing original replay head")?;
        Ok(Self { genesis, initial, initial_root, original_source_manifest, original_exe,
            driver_root: driver_root.to_owned(), head, stores })
    }
    /// Exact ID records must agree across each store's full own-Genesis replay.
    /// Empty IDs provide only head/state agreement, never an operation-confirmation PASS.
    pub fn verify_ids(&self, ids: &[Hash]) -> Result<serde_json::Value> {
        if ids.len() > 64 || ids.iter().copied().collect::<BTreeSet<_>>().len() != ids.len() {
            return Err("Original confirmation ID batch bound".into());
        }
        let mut agreed = None;
        for store in &self.stores {
            if store.load().map_err(|e| format!("Original replay head: {e:?}"))?.0 != self.head {
                return Err("Original head changed during restart verification".into());
            }
            let records = if ids.is_empty() { std::collections::BTreeMap::new() } else {
                store.verified_operation_records_many(ids)
                    .map_err(|e| format!("Original own replay indexes: {e:?}"))?
            };
            if ids.iter().any(|id| records.get(id).is_none_or(|rows| rows.is_empty()))
                || agreed.as_ref().is_some_and(|expected| expected != &records) {
                return Err("Original canonical operation records absent or unequal".into());
            }
            agreed = Some(records);
        }
        let records = agreed.ok_or("Missing original operation replay")?;
        let result = ids.iter().map(|id| {
            let row = &records[id][0];
            serde_json::json!({"id":hex::encode(id),"own_confirmed_height":row.height,
                "own_wire_commitment":hex::encode(row.wire),"list":row.list,"kind":row.kind,"matching_independent_stores":4})
        }).collect::<Vec<_>>();
        for store in &self.stores {
            if store.load().map_err(|e| format!("Original final replay head: {e:?}"))?.0 != self.head {
                return Err("Original head changed after restart verification".into());
            }
        }
        Ok(serde_json::json!({"action":"original four histories independently replayed",
            "height":self.head.height,"block":hex::encode(self.head.block),"root":hex::encode(self.head.root),
            "original_root":hex::encode(self.initial_root),"original_exe_sha256":hex::encode(self.original_exe),
            "original_source_manifest_sha256":hex::encode(self.original_source_manifest),
            "own_confirmations":result,"operation_confirmation_scope":!ids.is_empty(),
            "custody_or_physical_backup_qualification":false}))
    }
}

/// Verify the original signed payment against full own replay of all four original
/// stores. The already-failed mounted scenario remains partial; this is separately
/// reported authentication of its retained exact signed bytes, not a replacement UI run.
impl OriginalReplay {
    pub fn verify_exact_payment(&self, expected_id: Hash, raw: &[u8]) -> Result<serde_json::Value> {
        let (kind, id) = mutiny_consensus_v8::operation_index_v2::operation_id(0, raw)
            .map_err(|e| format!("Original exact payment identity: {e:?}"))?;
        if kind != 1 || id != expected_id { return Err("Original exact payment ID/carrier mismatch".into()); }
        let mut result = self.verify_ids(&[id])?;
        let commitment = hex::encode(mutiny_consensus_v8::domain_hash(
            mutiny_consensus_v8::operation_index_v2::WIRE_DOMAIN, raw));
        let row = &result["own_confirmations"][0];
        if row["list"] != 0 || row["kind"] != 1 || row["own_wire_commitment"] != commitment {
            return Err("Original own replay record does not authenticate exact signed payment bytes".into());
        }
        result["exact_signed_wire_sha256"] = serde_json::json!(hex::encode(Sha256::digest(raw)));
        result["exact_signed_wire_bytes"] = serde_json::json!(raw.len());
        result["previous_mounted_scenario_reclassified"] = serde_json::json!(false);
        Ok(result)
    }
}

/// Exact explicit alternative entry of the NON-SHIPPING wallet binary only.
/// No new binary target/feature; it never initializes a certifier or enters App::run.
/// Caller runs the successor executable, not the preserved original executable.
pub fn run_if_requested() -> Option<Result<()>> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.first().is_none_or(|a| a != "--verify-original-payment") { return None; }
    Some((|| {
        if args.len() != 14 { return Err("Exact original-payment verifier requires seven argument pairs".into()); }
        let flags = ["--verify-original-payment", "--h0-sha256", "--driver-root", "--vault-root",
            "--operation-id", "--wire-path", "--receipt-output"];
        for (i, expected) in flags.iter().enumerate() {
            if args[i*2] != *expected { return Err("Unexpected original-payment verifier arguments".into()); }
        }
        let text = |i: usize| args[i].to_str().ok_or("Verifier argument Unicode");
        let receipt = PathBuf::from(&args[1]);
        let receipt_sha = hash(text(3)?)?;
        let driver = PathBuf::from(&args[5]);
        let vault = VaultRoot::new(Path::new(&args[7])).map_err(|e| e.to_string())?;
        let expected_id = hash(text(9)?)?;
        let wire_path = PathBuf::from(&args[11]);
        let output = PathBuf::from(&args[13]);
        if !output.is_absolute() || output.components().any(|c| matches!(c, Component::ParentDir | Component::CurDir))
            || output.starts_with(&driver) || output.starts_with(vault.path()) {
            return Err("Verifier output must be a new separate absolute evidence path".into());
        }
        plain_original(output.parent().ok_or("Verifier output parent")?, true)?;
        // Reserve only the new report, never overwrite an earlier result or original.
        use std::io::Write;
        let mut report = std::fs::OpenOptions::new().write(true).create_new(true).open(&output)
            .map_err(|e| format!("Verifier new receipt: {e}"))?;
        let checked = (|| {
            if wire_path != driver.join(format!("wire-{}.bin", hex::encode(expected_id))) {
                return Err("Exact original wire must be the retained driver ID path".into());
            }
            let raw = read_bounded(&wire_path, 2*1024*1024)?;
            let original = OriginalReplay::open(&receipt, receipt_sha, &driver, &vault)?;
            original.verify_exact_payment(expected_id, &raw)
        })();
        let value = match &checked {
            Ok(value) => serde_json::json!({"format":"MUTINY-W15-ORIGINAL-PAYMENT-REPLAY-V1",
                "scope":"full own canonical replay of four pinned original stores and exact payment wire; not mounted UI/restart/custody/physical qualification",
                "original_h0_receipt":receipt,"original_h0_receipt_sha256":hex::encode(receipt_sha),
                "exact_wire_path":wire_path,"result":value,"refused":false}),
            Err(error) => serde_json::json!({"format":"MUTINY-W15-ORIGINAL-PAYMENT-REPLAY-V1",
                "scope":"refused; no confirmation qualification","original_h0_receipt":receipt,
                "original_h0_receipt_sha256":hex::encode(receipt_sha),"refusal":error,"refused":true}),
        };
        report.write_all(&serde_json::to_vec_pretty(&value).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        report.write_all(b"\n").map_err(|e| e.to_string())?;
        report.sync_all().map_err(|e| e.to_string())?;
        checked.map(|_| ())
    })())
}
