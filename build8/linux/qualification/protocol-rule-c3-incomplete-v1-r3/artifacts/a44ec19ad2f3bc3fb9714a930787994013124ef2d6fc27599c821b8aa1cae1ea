//! Verify an independently pinned sealed artifact before any chain database opens.
use mutiny_consensus_v8::{
    Hash, admission::ApprovedProfile, blocks::GenesisDescriptor, execution::State, genesis_inputs,
    genesis_inputs::GenesisProfile, licenses::BindWorker, protocol_manifest::RuleManifest,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{io::Read, path::Path};
type Result<T> = std::result::Result<T, String>;
fn err(e: impl std::fmt::Debug) -> String {
    format!("Sealed Genesis: {e:?}")
}
pub struct Trust {
    pub artifact_sha256: Hash,
    pub genesis_block_hash: Hash,
    pub rules: RuleManifest,
    pub qualified_target: Hash,
    /// `Production` is refused before parsing (Order A9: V1 is not a Production Genesis
    /// implementation; V2 artifacts verify through `genesis_artifact_v2`). Only tests construct
    /// `Test` (test/replay compatibility).
    pub profile: GenesisProfile,
}
/// Binary-supported rules are independent of supplied artifact/configuration.
/// The release ceremony must lock this candidate before actual deployment.
pub fn supported_trust(artifact_sha256: Hash, genesis_block_hash: Hash) -> Result<Trust> {
    let supported: Value = serde_json::from_str(include_str!(
        "../../qualification/protocol-rule-c3-incomplete-v1-r3/PROTOCOL-FINGERPRINT-CANDIDATE-C3-INCOMPLETE-V1.json"
    ))
    .map_err(err)?;
    Ok(Trust {
        artifact_sha256,
        genesis_block_hash,
        rules: RuleManifest::decode(&raw(&supported["manifest_hex"])?).map_err(err)?,
        qualified_target: hex::decode(
            "00000350e94ccd16c4d5661eafcd07f2f220b12f07c24ab8f8b90a0f2c131b43",
        )
        .map_err(err)?
        .try_into()
        .map_err(|_| "Qualified target length")?,
        // Fail closed: a deployed binary accepts Production only, and V1 Production is refused
        // (Order A9), so this trust verifies no V1 artifact.
        profile: GenesisProfile::Production,
    })
}
pub struct VerifiedGenesis {
    pub descriptor: GenesisDescriptor,
    pub initial: State,
    pub target: Hash,
    pub artifact_sha256: Hash,
}
fn raw(v: &Value) -> Result<Vec<u8>> {
    hex::decode(v.as_str().ok_or("Genesis hex string required")?).map_err(err)
}
fn hash(v: &Value) -> Result<Hash> {
    raw(v)?.try_into().map_err(|_| "Genesis hash length".into())
}
impl VerifiedGenesis {
    pub fn load(path: &Path, trust: &Trust) -> Result<Self> {
        let mut bytes = Vec::new();
        std::fs::File::open(path)
            .map_err(err)?
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(err)?;
        Self::verify(&bytes, trust)
    }
    pub fn verify(bytes: &[u8], trust: &Trust) -> Result<Self> {
        // Order A9: the V1 sealed artifact is not a Production Genesis implementation. Every
        // Production trust (`supported_trust`: --verify-sealed-genesis, --run) refuses it first.
        if trust.profile == GenesisProfile::Production {
            return Err(mutiny_consensus_v8::genesis_inputs::V1_PRODUCTION_REFUSAL.into());
        }
        if bytes.len() > 4 * 1024 * 1024 {
            return Err("Sealed Genesis artifact exceeds 4 MiB".into());
        }
        let artifact_sha256: Hash = Sha256::digest(bytes).into();
        if artifact_sha256 != trust.artifact_sha256 {
            return Err("Pinned sealed artifact hash mismatch".into());
        }
        let v: Value = serde_json::from_slice(bytes).map_err(err)?;
        if serde_json::to_vec(&v).map_err(err)? != bytes {
            return Err(
                "Sealed artifact requires compact sorted JSON without duplicate fields".into(),
            );
        }
        let object = v.as_object().ok_or("Sealed Genesis object required")?;
        let fields = [
            "schema",
            "descriptor",
            "bindings",
            "approved_profile",
            "supervised_nonce",
            "evidence",
            "records",
            "state_root",
            "genesis_block",
            "genesis_block_hash",
        ];
        if object.len() != fields.len()
            || !fields.iter().all(|x| object.contains_key(*x))
            || v["schema"] != "BUILD8-SEALED-GENESIS-V1"
        {
            return Err("Sealed Genesis schema mismatch".into());
        }
        let descriptor = GenesisDescriptor::decode(&raw(&v["descriptor"])?).map_err(err)?;
        let list = v["bindings"].as_array().ok_or("Genesis bindings array")?;
        if list.len() != 12 {
            return Err("Exactly twelve Genesis bindings required".into());
        }
        let bindings = list
            .iter()
            .map(|b| BindWorker::decode(&raw(b)?).map_err(err))
            .collect::<Result<Vec<_>>>()?;
        let approved = ApprovedProfile::decode(&raw(&v["approved_profile"])?).map_err(err)?;
        let initial = genesis_inputs::initial_state(
            &descriptor,
            &trust.rules,
            trust.qualified_target,
            &bindings,
            &approved,
            hash(&v["supervised_nonce"])?,
            &raw(&v["evidence"])?,
            trust.profile,
        )
        .map_err(err)?;
        let supplied = v["records"].as_array().ok_or("Genesis records array")?;
        let expected = initial.records().map_err(err)?;
        if supplied.len() != expected.len() {
            return Err("Sealed initial record count differs from reconstruction".into());
        }
        for (record, (key, value)) in supplied.iter().zip(expected) {
            let fields = record.as_array().ok_or("Genesis record pair")?;
            if fields.len() != 2 || hash(&fields[0])? != key || raw(&fields[1])? != value {
                return Err("Sealed initial state differs from reconstruction".into());
            }
        }
        let root = initial.root().map_err(err)?;
        let block = descriptor.block(root).map_err(err)?;
        let block_hash = descriptor.block_hash(root).map_err(err)?;
        if hash(&v["state_root"])? != root
            || raw(&v["genesis_block"])? != block
            || hash(&v["genesis_block_hash"])? != block_hash
            || trust.genesis_block_hash != block_hash
        {
            return Err("Sealed Genesis bytes/root/hash disagree with independent pin".into());
        }
        Ok(Self {
            descriptor,
            initial,
            target: trust.qualified_target,
            artifact_sha256,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn outer_file_pin_cannot_bypass_full_initial_state_verification() {
        let vector: Value = serde_json::from_str(include_str!(
            "../../qualification/COMPLETE-GENESIS-VECTORS-V1.json"
        ))
        .unwrap();
        let mut artifact = serde_json::Map::new();
        for field in [
            "descriptor",
            "bindings",
            "approved_profile",
            "supervised_nonce",
            "evidence",
            "records",
            "state_root",
            "genesis_block",
            "genesis_block_hash",
        ] {
            artifact.insert(field.into(), vector[field].clone());
        }
        artifact.insert(
            "schema".into(),
            Value::String("BUILD8-SEALED-GENESIS-V1".into()),
        );
        let artifact = Value::Object(artifact);
        let bytes = serde_json::to_vec(&artifact).unwrap();
        let mut trust = Trust {
            artifact_sha256: Sha256::digest(&bytes).into(),
            genesis_block_hash: hash(&vector["genesis_block_hash"]).unwrap(),
            rules: RuleManifest::decode(&raw(&vector["locked_rules"]).unwrap()).unwrap(),
            qualified_target: hash(&vector["qualified_target"]).unwrap(),
            profile: GenesisProfile::Test, // legacy treasury-less vector: Test profile only
        };
        let verified = VerifiedGenesis::verify(&bytes, &trust).unwrap();
        assert!(verified.initial.coins.is_empty());
        for case in 0..6 {
            let mut bad = artifact.clone();
            match case {
                0 => {
                    bad["bindings"].as_array_mut().unwrap().pop();
                }
                1 => {
                    bad["records"].as_array_mut().unwrap().pop();
                }
                2 => bad["state_root"] = Value::String("00".repeat(32)),
                3 => bad["supervised_nonce"] = Value::String("01".repeat(32)),
                4 => bad["genesis_block_hash"] = Value::String("00".repeat(32)),
                _ => {
                    let mut b = BindWorker::decode(&raw(&bad["bindings"][0]).unwrap()).unwrap();
                    b.owner_signature[0] ^= 1;
                    bad["bindings"][0] = Value::String(hex::encode(b.encode()));
                }
            }
            let bytes = serde_json::to_vec(&bad).unwrap();
            trust.artifact_sha256 = Sha256::digest(&bytes).into();
            assert!(VerifiedGenesis::verify(&bytes, &trust).is_err());
        }
    }
    /// T12 (iii) and the B6 invariant at the sealed-open boundary: an edited approved profile
    /// cannot open even when the operator re-pins the artifact hash, and a Production trust profile
    /// only ever yields a Production-class state: the legacy vector (no committed trust-root set,
    /// Legacy/Test class) is refused under `GenesisProfile::Production` while it still verifies
    /// under `Test`.
    #[test]
    fn production_trust_requires_production_class_and_edited_profiles_never_open() {
        let vector: Value = serde_json::from_str(include_str!(
            "../../qualification/COMPLETE-GENESIS-VECTORS-V1.json"
        ))
        .unwrap();
        let mut artifact = serde_json::Map::new();
        for field in [
            "descriptor",
            "bindings",
            "approved_profile",
            "supervised_nonce",
            "evidence",
            "records",
            "state_root",
            "genesis_block",
            "genesis_block_hash",
        ] {
            artifact.insert(field.into(), vector[field].clone());
        }
        artifact.insert("schema".into(), Value::String("BUILD8-SEALED-GENESIS-V1".into()));
        let artifact = Value::Object(artifact);
        let bytes = serde_json::to_vec(&artifact).unwrap();
        let mut trust = Trust {
            artifact_sha256: Sha256::digest(&bytes).into(),
            genesis_block_hash: hash(&vector["genesis_block_hash"]).unwrap(),
            rules: RuleManifest::decode(&raw(&vector["locked_rules"]).unwrap()).unwrap(),
            qualified_target: hash(&vector["qualified_target"]).unwrap(),
            profile: GenesisProfile::Test,
        };
        let verified = VerifiedGenesis::verify(&bytes, &trust).unwrap();
        assert_eq!(
            verified.initial.admission_class().unwrap(),
            mutiny_consensus_v8::provenance::AdmissionClass::LegacyTest
        );
        trust.profile = GenesisProfile::Production;
        assert!(VerifiedGenesis::verify(&bytes, &trust).is_err());
        trust.profile = GenesisProfile::Test;
        let mut edited = artifact.clone();
        let mut approved = ApprovedProfile::decode(&raw(&edited["approved_profile"]).unwrap()).unwrap();
        approved.profile[40] ^= 1;
        edited["approved_profile"] = Value::String(hex::encode(approved.encode().unwrap()));
        let bytes = serde_json::to_vec(&edited).unwrap();
        trust.artifact_sha256 = Sha256::digest(&bytes).into(); // the operator re-pins the edit
        assert!(VerifiedGenesis::verify(&bytes, &trust).is_err());
    }
}
