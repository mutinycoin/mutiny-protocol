//! Durable public identity and binding phases; this store never seals Genesis.
//! Production callers must pass the separately qualified descriptor/fingerprint.
use mutiny_consensus_v8::{
    Hash,
    blocks::GenesisDescriptor,
    genesis::GenesisIdentity,
    licenses::{BindWorker, LicenseBook},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use std::path::Path;
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Debug) -> String {
    format!("Genesis ceremony: {e:?}")
}
pub struct Ceremony {
    db: Connection,
    identity: GenesisIdentity,
}
impl Ceremony {
    /// Freeze only inputs that pass the validation of the declared Genesis profile. Production is
    /// refused before any file is created (Order A9: V1 is not a Production Genesis implementation;
    /// V2 freezes through `genesis_ceremony_v2`); Test requires the Legacy/Test admission class.
    pub fn freeze_qualified_inputs(
        path: &Path,
        descriptor: &GenesisDescriptor,
        locked_rules: &mutiny_consensus_v8::protocol_manifest::RuleManifest,
        qualified_target: Hash,
        profile: mutiny_consensus_v8::genesis_inputs::GenesisProfile,
    ) -> Result<Self> {
        use mutiny_consensus_v8::genesis_inputs::{self as inputs, GenesisProfile};
        match profile {
            GenesisProfile::Production => {
                // Order A9: V1 is not a Production Genesis implementation; refused before any
                // ceremony file is created.
                return Err(inputs::V1_PRODUCTION_REFUSAL.into());
            }
            GenesisProfile::Test => {
                let (_, input) =
                    inputs::validate_descriptor(descriptor, locked_rules, qualified_target)
                        .map_err(err)?;
                inputs::genesis_admission_class(descriptor, &input, GenesisProfile::Test)
                    .map_err(err)?;
            }
        }
        Self::freeze(path, descriptor, locked_rules.fingerprint().map_err(err)?)
    }
    /// The immutable row is committed before enrollment may use the returned ID.
    /// Existing conflicting or incomplete state fails; no replacement/repair API.
    pub fn freeze(
        path: &Path,
        descriptor: &GenesisDescriptor,
        expected_fingerprint: Hash,
    ) -> Result<Self> {
        if descriptor.fingerprint != expected_fingerprint {
            return Err("Ceremony fingerprint differs from locked rules".into());
        }
        let identity = GenesisIdentity::new(descriptor.clone()).map_err(err)?;
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
                    return Err("Ceremony must be a regular file".into());
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
            db.execute_batch("CREATE TABLE ceremony_identity (id INTEGER PRIMARY KEY CHECK(id=1), descriptor BLOB NOT NULL CHECK(length(descriptor)<=1048576));
                CREATE TABLE ceremony_bindings (id INTEGER PRIMARY KEY CHECK(id=1), bindings BLOB NOT NULL CHECK(length(bindings)<=196608), FOREIGN KEY(id) REFERENCES ceremony_identity(id));").map_err(err)?;
        }
        let tx = db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(err)?;
        let existing: Option<Vec<u8>> = tx.query_row("SELECT CASE WHEN length(descriptor)<=1048576 THEN descriptor ELSE NULL END FROM ceremony_identity WHERE id=1", [], |r|r.get(0)).optional().map_err(err)?;
        if let Some(bytes) = existing {
            if bytes != identity.bytes() {
                return Err("Frozen Genesis identity differs; a fresh ceremony is required".into());
            }
        } else {
            if !created {
                return Err("Incomplete ceremony identity; use a fresh ceremony".into());
            }
            tx.execute(
                "INSERT INTO ceremony_identity(id,descriptor) VALUES(1,?1)",
                params![identity.bytes()],
            )
            .map_err(err)?;
        }
        tx.commit().map_err(err)?;
        let this = Self { db, identity };
        // Revalidate any persisted owner/Worker authorizations on every reopen.
        this.bindings()?;
        Ok(this)
    }
    pub fn identity(&self) -> &GenesisIdentity {
        &self.identity
    }
    fn check_identity(&self) -> Result<()> {
        let bytes:Vec<u8> = self.db.query_row("SELECT CASE WHEN length(descriptor)<=1048576 THEN descriptor ELSE NULL END FROM ceremony_identity WHERE id=1", [], |r|r.get(0)).map_err(err)?;
        if bytes != self.identity.bytes() {
            return Err("Frozen ceremony identity changed".into());
        }
        Ok(())
    }
    pub fn bindings(&self) -> Result<Option<LicenseBook>> {
        self.check_identity()?;
        let bytes:Option<Vec<u8>> = self.db.query_row("SELECT CASE WHEN length(bindings)<=196608 THEN bindings ELSE NULL END FROM ceremony_bindings WHERE id=1", [], |r|r.get(0)).optional().map_err(err)?;
        bytes
            .map(|b| self.identity.bind_workers(&decode(&b)?).map_err(err))
            .transpose()
    }
    pub fn commit_bindings(&mut self, bindings: &[BindWorker]) -> Result<LicenseBook> {
        self.check_identity()?;
        let book = self.identity.bind_workers(bindings).map_err(err)?;
        // Fixed LicenseID order makes upload arrival order immaterial.
        let mut ordered = bindings.to_vec();
        ordered.sort_by_key(|b| b.license);
        let mut e = minicbor::Encoder::new(Vec::new());
        e.array(12).map_err(err)?;
        for b in &ordered {
            e.bytes(&b.encode()).map_err(err)?;
        }
        let bytes = e.into_writer();
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(err)?;
        let descriptor: Vec<u8> = tx
            .query_row(
                "SELECT CASE WHEN length(descriptor)<=1048576 THEN descriptor ELSE NULL END FROM ceremony_identity WHERE id=1",
                [],
                |r| r.get(0),
            )
            .map_err(err)?;
        if descriptor != self.identity.bytes() {
            return Err("Frozen ceremony identity changed".into());
        }
        let old: Option<Vec<u8>> = tx
            .query_row(
                "SELECT CASE WHEN length(bindings)<=196608 THEN bindings ELSE NULL END FROM ceremony_bindings WHERE id=1",
                [],
                |r| r.get(0),
            )
            .optional()
            .map_err(err)?;
        if let Some(old) = old {
            if old != bytes {
                return Err("Initial binding set already committed; refusing replacement".into());
            }
        } else {
            tx.execute(
                "INSERT INTO ceremony_bindings(id,bindings) VALUES(1,?1)",
                params![bytes],
            )
            .map_err(err)?;
        }
        tx.commit().map_err(err)?;
        Ok(book)
    }
}
fn decode(raw: &[u8]) -> Result<Vec<BindWorker>> {
    mutiny_consensus_v8::blocks::canonical(raw, 196608).map_err(err)?;
    let mut d = minicbor::Decoder::new(raw);
    if d.array().map_err(err)? != Some(12) {
        return Err("Exactly twelve initial bindings required".into());
    }
    let mut all = Vec::new();
    for _ in 0..12 {
        all.push(BindWorker::decode(d.bytes().map_err(err)?).map_err(err)?);
    }
    if all.windows(2).any(|p| p[0].license >= p[1].license) {
        return Err("Noncanonical initial binding order".into());
    }
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restart_cannot_redefine_identity_or_replace_authorized_workers() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/GENESIS-BINDING-VECTORS-STATE-V2.json"
        ))
        .unwrap();
        let descriptor = GenesisDescriptor::decode(
            &hex::decode(vectors["descriptor_hex"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let sets: Vec<Vec<BindWorker>> = vectors["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|case| {
                case["bindings"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|b| {
                        BindWorker::decode(
                            &hex::decode(b["binding_hex"].as_str().unwrap()).unwrap(),
                        )
                        .unwrap()
                    })
                    .collect()
            })
            .collect();
        assert!(sets.len() >= 2);
        let mut salt = [0; 8];
        getrandom::getrandom(&mut salt).unwrap();
        let path =
            std::env::temp_dir().join(format!("build8-ceremony-{}.sqlite", hex::encode(salt)));
        assert!(Ceremony::freeze(&path, &descriptor, [0; 32]).is_err());
        assert!(!path.exists());
        let mut first = Ceremony::freeze(&path, &descriptor, descriptor.fingerprint).unwrap();
        assert_eq!(first.identity().id(), descriptor.id().unwrap());
        assert!(first.bindings().unwrap().is_none());
        let mut wrong = descriptor.clone();
        wrong.nonce[0] ^= 1;
        assert!(Ceremony::freeze(&path, &wrong, wrong.fingerprint).is_err());
        let mut invalid = sets[0].clone();
        invalid[0].owner_signature[0] ^= 1;
        assert!(first.commit_bindings(&invalid).is_err());
        assert!(first.bindings().unwrap().is_none());
        let book = first.commit_bindings(&sets[0]).unwrap();
        let mut second = Ceremony::freeze(&path, &descriptor, descriptor.fingerprint).unwrap();
        assert!(second.commit_bindings(&sets[1]).is_err());
        let mut reordered = sets[0].clone();
        reordered.reverse();
        assert_eq!(second.commit_bindings(&reordered).unwrap(), book);
        drop(first);
        drop(second);
        let resumed = Ceremony::freeze(&path, &descriptor, descriptor.fingerprint).unwrap();
        assert_eq!(resumed.bindings().unwrap(), Some(book));
        drop(resumed);
        let db = Connection::open(&path).unwrap();
        db.execute("DELETE FROM ceremony_bindings", []).unwrap();
        db.execute("DELETE FROM ceremony_identity", []).unwrap();
        drop(db);
        assert!(Ceremony::freeze(&path, &wrong, wrong.fingerprint).is_err());
        std::fs::remove_file(path).unwrap();
    }
}
