//! Durable V2 Genesis identity freeze (Lane A1, Order A9/A10; PROPOSED / UNFROZEN). TEST-VALUE only in
//! this candidate: the store never seals or launches Genesis and opens no production gate.
//!
//! It applies the public-ceremony persistence rule (`GENESIS-CEREMONY-PERSISTENCE-V1`) to V2: the
//! exact canonical GenesisInputsV2 bytes are committed before enrollment may use the returned
//! GenesisID (the V2 Node and Continuity keys are generated after it). Before any file exists, the
//! inputs must match the independently approved trust (class, manifest, initial target) and pass every
//! input rule, so a Production-class freeze fails until real endorsement roots exist and a manifest
//! commits to them. Changed inputs or an incomplete existing store fail; there is no replacement API.
use mutiny_consensus_v8::{
    Hash,
    genesis_v2::{self, Approved, Inputs},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::path::Path;
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Debug) -> String {
    format!("Genesis V2 ceremony: {e:?}")
}
pub struct CeremonyV2 {
    db: Connection,
    bytes: Vec<u8>,
    identity: Hash,
}
impl CeremonyV2 {
    /// Validate against `approved`, then commit the immutable identity row (or reopen it unchanged).
    /// The class comes only from the input bytes; the file name and location are never inputs.
    pub fn freeze(path: &Path, inputs: &Inputs, approved: &Approved) -> Result<Self> {
        genesis_v2::check_approved(inputs, approved).map_err(err)?;
        let identity = inputs.identity().map_err(err)?;
        let bytes = inputs.encode().map_err(err)?;
        let created = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            Ok(file) => {
                file.sync_all().map_err(err)?;
                true
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if !std::fs::symlink_metadata(path).map_err(err)?.is_file() {
                    return Err("Genesis V2 ceremony must be a regular file".into());
                }
                false
            }
            Err(e) => return Err(err(e)),
        };
        let mut db = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE)
            .map_err(err)?;
        db.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; PRAGMA foreign_keys=ON;",
        )
        .map_err(err)?;
        if created {
            db.execute_batch(&format!(
                "CREATE TABLE ceremony_identity_v2 (id INTEGER PRIMARY KEY CHECK(id=1), inputs BLOB NOT NULL CHECK(length(inputs)<={}));",
                genesis_v2::MAX_INPUTS
            ))
            .map_err(err)?;
        }
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(err)?;
        let existing: Option<Vec<u8>> = tx
            .query_row("SELECT inputs FROM ceremony_identity_v2 WHERE id=1", [], |r| r.get(0))
            .optional()
            .map_err(err)?;
        match existing {
            Some(stored) if stored != bytes => {
                return Err("Frozen V2 Genesis identity differs; a fresh ceremony is required".into());
            }
            Some(_) => {}
            None if !created => {
                return Err("Incomplete V2 ceremony identity; use a fresh ceremony".into());
            }
            None => {
                tx.execute(
                    "INSERT INTO ceremony_identity_v2(id,inputs) VALUES(1,?1)",
                    params![bytes],
                )
                .map_err(err)?;
            }
        }
        tx.commit().map_err(err)?;
        Ok(Self {
            db,
            bytes,
            identity,
        })
    }
    /// GenesisID V2 of the frozen inputs (enrollment signs over it).
    pub fn identity(&self) -> Hash {
        self.identity
    }
    /// The frozen inputs, re-read from the store; a changed row fails.
    pub fn inputs(&self) -> Result<Inputs> {
        let stored: Vec<u8> = self
            .db
            .query_row("SELECT inputs FROM ceremony_identity_v2 WHERE id=1", [], |r| r.get(0))
            .map_err(err)?;
        if stored != self.bytes {
            return Err("Frozen V2 ceremony identity changed".into());
        }
        Inputs::decode(&stored).map_err(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mutiny_consensus_v8::{
        genesis_v2::{GenesisClass, GenesisV2Error, binding_entries},
        protocol_manifest::RuleManifest,
    };
    fn fixture() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "../../qualification/GENESIS-V2-TEST-VALUE-FIXTURE-V1.json"
        ))
        .unwrap()
    }
    fn raw(v: &serde_json::Value) -> Vec<u8> {
        hex::decode(v.as_str().unwrap()).unwrap()
    }
    fn test_value() -> (Inputs, Approved) {
        let f = fixture();
        let inputs = Inputs::decode(&raw(&f["inputs"])).unwrap();
        let approved = Approved {
            manifest: RuleManifest::decode(&raw(&f["approved_manifest"])).unwrap(),
            class: GenesisClass::TestValue,
            initial_target: raw(&f["initial_target"]).try_into().unwrap(),
        };
        (inputs, approved)
    }
    /// A fresh, uniquely named directory (atomic create; the test deletes only what it created).
    fn fresh_dir(tag: &str) -> std::path::PathBuf {
        loop {
            let mut salt = [0; 8];
            getrandom::getrandom(&mut salt).unwrap();
            let dir = std::env::temp_dir().join(format!("build8-genesis-v2-{tag}-{}", hex::encode(salt)));
            match std::fs::create_dir(&dir) {
                Ok(()) => return dir,
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => panic!("{e}"),
            }
        }
    }
    fn remove(dir: &Path, names: &[&str]) {
        for name in names {
            for suffix in ["", "-wal", "-shm"] {
                let path = dir.join(format!("{name}{suffix}"));
                if path.exists() {
                    std::fs::remove_file(path).unwrap();
                }
            }
        }
        std::fs::remove_dir(dir).unwrap();
    }

    /// A TEST-VALUE identity freezes, reopens unchanged under the same bytes, refuses different bytes,
    /// and the file NAME or location never changes the identity or the class.
    #[test]
    fn test_value_identity_freezes_durably_and_the_file_name_changes_nothing() {
        let (inputs, approved) = test_value();
        let dir = fresh_dir("ceremony");
        let names = ["production-genesis.sqlite", "ceremony.sqlite"];
        let first = CeremonyV2::freeze(&dir.join(names[0]), &inputs, &approved).unwrap();
        let second = CeremonyV2::freeze(&dir.join(names[1]), &inputs, &approved).unwrap();
        assert_eq!(first.identity(), inputs.identity().unwrap());
        assert_eq!(second.identity(), first.identity());
        assert_eq!(first.inputs().unwrap(), inputs);
        assert_eq!(second.inputs().unwrap().class(), GenesisClass::TestValue);
        drop(first);
        let reopened = CeremonyV2::freeze(&dir.join(names[0]), &inputs, &approved).unwrap();
        assert_eq!(reopened.identity(), inputs.identity().unwrap());
        drop(reopened);
        // Different bytes (one nonce bit) are a different identity: never a replacement.
        let mut other = inputs.clone();
        other.nonce[0] ^= 1;
        let refused = CeremonyV2::freeze(&dir.join(names[0]), &other, &approved);
        assert_eq!(
            refused.err().unwrap(),
            "Frozen V2 Genesis identity differs; a fresh ceremony is required"
        );
        drop(second);
        remove(&dir, &names);
    }

    /// Production class: refused BEFORE any file exists, whatever trust the caller supplies. The
    /// binary-supported V2 trust (V9 manifest, Production) refuses the TEST-VALUE inputs on class; a
    /// Production-class rebuild of the same inputs (manifest recomputed) is refused by its TEST-VALUE
    /// roots even when the caller approves exactly its own manifest.
    #[test]
    fn production_class_freeze_is_refused_before_any_file_exists() {
        let (inputs, _) = test_value();
        let dir = fresh_dir("ceremony-production");
        let path = dir.join("genesis.sqlite");
        let supported = crate::genesis_artifact_v2::supported_trust_v2([0; 32], [0; 32]).unwrap();
        assert_eq!(
            CeremonyV2::freeze(&path, &inputs, &supported.approved).err().unwrap(),
            err(GenesisV2Error::ClassMismatch)
        );
        assert!(!path.exists());
        let mut production = inputs.clone();
        production.parameters.class = GenesisClass::Production;
        let mut commitments: Vec<(Vec<u8>, Hash)> = production
            .parameters
            .rules
            .commitments
            .iter()
            .filter(|(n, _)| {
                ![
                    genesis_v2::CLASS_ENTRY,
                    genesis_v2::ROOT_SET_ENTRY,
                    genesis_v2::PCR_SET_ENTRY,
                    genesis_v2::IDENTITY_CLASSES_ENTRY,
                ]
                .contains(&n.as_slice())
            })
            .cloned()
            .collect();
        commitments.extend(
            binding_entries(
                GenesisClass::Production,
                &production.parameters.roots,
                &production.parameters.pcr_profiles,
                &production.parameters.identity_classes,
            )
            .unwrap(),
        );
        commitments.sort();
        production.parameters.rules = RuleManifest { commitments };
        let own = Approved {
            manifest: production.parameters.rules.clone(),
            class: GenesisClass::Production,
            initial_target: production.parameters.initial_target,
        };
        assert_eq!(
            CeremonyV2::freeze(&path, &production, &own).err().unwrap(),
            err(GenesisV2Error::TestValueRootInProduction)
        );
        assert!(!path.exists());
        std::fs::remove_dir(&dir).unwrap();
    }

    /// Order A9: the V1 ceremony refuses a Production freeze with the fixed message before any file is
    /// created (the V1 Test freeze is unchanged; `genesis_ceremony` tests cover it).
    #[test]
    fn v1_production_ceremony_freeze_is_refused_with_the_order_a9_message() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/COMPLETE-GENESIS-VECTORS-V1.json"
        ))
        .unwrap();
        let descriptor = mutiny_consensus_v8::blocks::GenesisDescriptor::decode(&raw(&vectors["descriptor"])).unwrap();
        let rules = RuleManifest::decode(&raw(&vectors["locked_rules"])).unwrap();
        let target: Hash = raw(&vectors["qualified_target"]).try_into().unwrap();
        let dir = fresh_dir("ceremony-v1");
        let path = dir.join("v1.sqlite");
        let refused = crate::genesis_ceremony::Ceremony::freeze_qualified_inputs(
            &path,
            &descriptor,
            &rules,
            target,
            mutiny_consensus_v8::genesis_inputs::GenesisProfile::Production,
        );
        assert_eq!(
            refused.err().unwrap(),
            "V1 is not a Production Genesis implementation (Order A9)"
        );
        assert!(!path.exists(), "no ceremony file for a refused V1 Production freeze");
        std::fs::remove_dir(&dir).unwrap();
    }
}
