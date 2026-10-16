//! Candidate recovery-authority record and checkpoint authorization only.
//! A valid signature is NOT verified loss, physical admission or recovery.
use crate::{Error, Hash, NETWORK_ID, Result, anchors::FinalizedAnchor, blocks, domain_hash};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, PublicKey, Role};

pub const MAX_AUTHORITY_BYTES: usize = 4096;
pub const MAX_AUTHORIZATION_BYTES: usize = 8192;
pub fn key() -> Hash {
    domain_hash(b"MUTINY-BUILD8-BOOTSTRAP-RECOVERY-AUTHORITY-KEY-V2", &[])
}
pub(crate) fn is_record(record_key: Hash, raw: &[u8]) -> bool {
    let mut d = Decoder::new(raw);
    record_key == key()
        || (d.array().ok().flatten().is_some() && d.u8().ok() == Some(2) && d.u8().ok() == Some(57))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authority {
    pub genesis: Hash,
    pub fingerprint: Hash,
    pub descriptor: Vec<u8>,
}
impl Authority {
    /// State reconstruction authenticates the caller's whole-StateRoot first.
    /// This validates context/role separation, not initial ceremony authority.
    pub(crate) fn validate_state_roles(&self, state: &crate::execution::State) -> Result<()> {
        let registry = state
            .continuity
            .as_ref()
            .ok_or(Error::UnqualifiedPhysical)?;
        if (self.genesis, self.fingerprint) != (registry.genesis, registry.fingerprint) {
            return Err(Error::WrongAnchor);
        }
        let recovery = self.public()?;
        self.reject_aliases(state.wallets.public_descriptors())?;
        if let Some(policy) = &state.admission_policy_v2 {
            self.reject_aliases([policy.initial().owner_descriptor.as_slice()])?;
        }
        for binding in state.continuity_keys_v2.bindings() {
            self.reject_aliases([
                binding.owner_descriptor(),
                binding.admission().continuity_descriptor.as_slice(),
            ])?;
        }
        for control in state.membership_v2.controls() {
            self.reject_aliases([
                control.binding().node_descriptor.as_slice(),
                control.current_node_descriptor(),
            ])?;
        }
        for retired in state.retired_continuity_v2.entries() {
            self.reject_aliases([
                retired.owner_descriptor.as_slice(),
                retired.binding.node_descriptor.as_slice(),
                retired.binding.signer_descriptor(),
                retired.binding.admission.continuity_descriptor.as_slice(),
            ])?;
        }
        for history in state.node_key_history_v2.entries() {
            let op = &history.operation;
            self.reject_aliases([
                op.current.as_slice(),
                op.proposed.as_slice(),
                op.authorizer.as_slice(),
            ])?;
        }
        for assignment in state.licenses_v2.assignments() {
            self.reject_aliases([
                assignment.owner_descriptor.as_slice(),
                assignment.node_descriptor.as_slice(),
            ])?;
            if assignment.enrollment.binding.worker_public == recovery.ed448 {
                return Err(Error::Duplicate);
            }
        }
        for record in state.recovery_history_v2.entries() {
            let m = &record.material;
            let retained = record.witnesses.verify(
                &m.parent,
                m.root,
                m.old_node,
                m.old_hardware_generation,
                m.old_key_generation,
                m.commitment()?,
            )?;
            self.reject_aliases([
                record.policy.owner_descriptor.as_slice(),
                m.binding.node_descriptor.as_slice(),
                m.binding.admission.continuity_descriptor.as_slice(),
                retained.terminal.owner_descriptor.as_slice(),
                retained.terminal.binding.node_descriptor.as_slice(),
                retained.terminal.binding.signer_descriptor(),
                retained
                    .terminal
                    .binding
                    .admission
                    .continuity_descriptor
                    .as_slice(),
                retained.node_current.as_slice(),
            ])?;
        }
        Ok(())
    }
    fn public(&self) -> Result<PublicKey> {
        let (public, generation) =
            PublicKey::decode_descriptor(&self.descriptor).map_err(|_| Error::Codec)?;
        // The Genesis recovery authority is immutable. No authority rotation,
        // re-enablement or role relabeling is introduced by this codec.
        if public.role != Role::WalletRecovery
            || generation != 1
            || self.genesis == [0; 32]
            || self.fingerprint == [0; 32]
        {
            return Err(Error::WrongGeneration);
        }
        Ok(public)
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        self.public()?;
        let mut e = Encoder::new(Vec::new());
        e.array(6)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(57)
            .unwrap()
            .u32(NETWORK_ID)
            .unwrap()
            .bytes(&self.genesis)
            .unwrap()
            .bytes(&self.fingerprint)
            .unwrap()
            .bytes(&self.descriptor)
            .unwrap();
        let bytes = e.into_writer();
        if bytes.len() > MAX_AUTHORITY_BYTES {
            return Err(Error::Oversize);
        }
        Ok(bytes)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        blocks::canonical(raw, MAX_AUTHORITY_BYTES)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(|_| Error::Codec)? != Some(6)
            || d.u8().map_err(|_| Error::Codec)? != 2
            || d.u8().map_err(|_| Error::Codec)? != 57
            || d.u32().map_err(|_| Error::Codec)? != NETWORK_ID
        {
            return Err(Error::Codec);
        }
        let result = Self {
            genesis: hash(&mut d)?,
            fingerprint: hash(&mut d)?,
            descriptor: d.bytes().map_err(|_| Error::Codec)?.to_vec(),
        };
        if d.position() != raw.len() || result.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(result)
    }
    pub fn commitment(&self) -> Result<Hash> {
        Ok(domain_hash(
            b"MUTINY-BUILD8-BOOTSTRAP-RECOVERY-AUTHORITY-V2",
            &self.encode()?,
        ))
    }
    /// Initial ceremony must check every existing role, both constituent keys.
    /// This helper does not prove the caller supplied the complete role set.
    pub fn reject_aliases<'a>(
        &self,
        descriptors: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<()> {
        let recovery = self.public()?;
        for raw in descriptors {
            let (other, _) = PublicKey::decode_descriptor(raw).map_err(|_| Error::Codec)?;
            if recovery.ed448 == other.ed448 || recovery.fndsa == other.fndsa {
                return Err(Error::Duplicate);
            }
        }
        Ok(())
    }
}
fn hash(d: &mut Decoder<'_>) -> Result<Hash> {
    d.bytes()
        .map_err(|_| Error::Codec)?
        .try_into()
        .map_err(|_| Error::Codec)
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    pub parent: FinalizedAnchor,
    pub state_root: Hash,
    pub membership_root: Hash,
    pub sequence: u64,
    /// Must commit to the entire canonical replacement, native proofs and
    /// supervised loss set. Caller must validate that typed transition later.
    pub transition: Hash,
}
impl Intent {
    pub fn encode(&self, authority: &Authority) -> Result<Vec<u8>> {
        self.parent
            .validate_context(authority.genesis, authority.fingerprint)?;
        self.parent.height.checked_add(1).ok_or(Error::Overflow)?;
        if self.parent.block == [0; 32]
            || self.state_root == [0; 32]
            || self.membership_root == [0; 32]
            || self.transition == [0; 32]
            || self.sequence == 0
        {
            return Err(Error::InvalidCounter);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(8)
            .unwrap()
            .u8(2)
            .unwrap()
            .u8(57)
            .unwrap()
            .bytes(&authority.commitment()?)
            .unwrap()
            .bytes(&self.parent.encode())
            .unwrap()
            .bytes(&self.state_root)
            .unwrap()
            .bytes(&self.membership_root)
            .unwrap()
            .u64(self.sequence)
            .unwrap()
            .bytes(&self.transition)
            .unwrap();
        Ok(e.into_writer())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorization {
    pub intent: Intent,
    pub signature: HybridSignature,
}
impl Authorization {
    pub fn sign(intent: Intent, authority: &Authority, key: &HybridKey) -> Result<Self> {
        if key.public() != &authority.public()? {
            return Err(Error::UnknownSigner);
        }
        let signature = key
            .sign(Domain::RecoveryAuthorize, &intent.encode(authority)?)
            .map_err(|_| Error::BadSignature)?;
        Ok(Self { intent, signature })
    }
    /// Checks only dual recovery authorization for an independently supplied
    /// exact expected intent and pinned authority. No installable token results.
    pub fn verify_signature_only(&self, authority: &Authority, expected: &Intent) -> Result<()> {
        if &self.intent != expected {
            return Err(Error::WrongAnchor);
        }
        authority
            .public()?
            .verify(
                Domain::RecoveryAuthorize,
                &self.intent.encode(authority)?,
                &self.signature,
            )
            .map_err(|_| Error::BadSignature)
    }
    pub fn encode(&self, authority: &Authority) -> Result<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(&self.intent.encode(authority)?)
            .unwrap()
            .bytes(&self.signature.ed448)
            .unwrap()
            .bytes(&self.signature.fndsa)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_AUTHORIZATION_BYTES {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8], authority: &Authority) -> Result<Self> {
        blocks::canonical(raw, MAX_AUTHORIZATION_BYTES)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(|_| Error::Codec)? != Some(4) || d.u8().map_err(|_| Error::Codec)? != 2
        {
            return Err(Error::Codec);
        }
        let intent = d.bytes().map_err(|_| Error::Codec)?;
        let mut i = Decoder::new(intent);
        if i.array().map_err(|_| Error::Codec)? != Some(8)
            || i.u8().map_err(|_| Error::Codec)? != 2
            || i.u8().map_err(|_| Error::Codec)? != 57
            || hash(&mut i)? != authority.commitment()?
        {
            return Err(Error::WrongAnchor);
        }
        let intent_value = Intent {
            parent: FinalizedAnchor::decode(i.bytes().map_err(|_| Error::Codec)?)?,
            state_root: hash(&mut i)?,
            membership_root: hash(&mut i)?,
            sequence: i.u64().map_err(|_| Error::Codec)?,
            transition: hash(&mut i)?,
        };
        if i.position() != intent.len() || intent_value.encode(authority)? != intent {
            return Err(Error::NonCanonical);
        }
        let result = Self {
            intent: intent_value,
            signature: HybridSignature {
                ed448: d
                    .bytes()
                    .map_err(|_| Error::Codec)?
                    .try_into()
                    .map_err(|_| Error::Codec)?,
                fndsa: d
                    .bytes()
                    .map_err(|_| Error::Codec)?
                    .try_into()
                    .map_err(|_| Error::Codec)?,
            },
        };
        if d.position() != raw.len() || result.encode(authority)? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod state_tests {
    use super::*;
    use crate::{execution::State, state_tree::StateTree};
    #[test]
    fn hybrid_recovery_authority_typed_state_rejects_hidden_context_and_role_mutations() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/hybrid-canonical-store-public-v1.json"
        ))
        .unwrap();
        let recovery: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/bootstrap-recovery-authority-public-v1.json"
        ))
        .unwrap();
        for f in [&fixture, &recovery] {
            assert_eq!(f["synthetic_only"], true);
            assert_eq!(f["production_authorized"], false);
        }
        let raw = |v: &serde_json::Value| hex::decode(v.as_str().unwrap()).unwrap();
        let original: Hash = raw(&fixture["root"]).try_into().unwrap();
        let rows: Vec<_> = fixture["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (raw(&r["key"]).try_into().unwrap(), raw(&r["record"])))
            .collect();
        let mut state = State::from_records(&rows, original).unwrap();
        let parent = FinalizedAnchor::decode(&raw(&fixture["genesis"])).unwrap();
        let mut authority = Authority::decode(&raw(&recovery["authority"])).unwrap();
        authority.genesis = parent.genesis;
        authority.fingerprint = parent.fingerprint;
        state.recovery_authority_v2 = Some(authority.clone());
        let root = state.root().unwrap();
        assert_ne!(root, original);
        let records = state.records().unwrap();
        let restored = State::from_records(&records, root).unwrap();
        assert_eq!(restored.recovery_authority_v2, Some(authority.clone()));
        assert!(State::from_records(&records, original).is_err());
        // Authority metadata adds no voting weight or signer by itself.
        let before = crate::votes_v2::HeightAuthority::from_state(
            &State::from_records(&rows, original).unwrap(),
            parent.clone(),
            original,
        )
        .unwrap();
        let after =
            crate::votes_v2::HeightAuthority::from_state(&restored, parent.clone(), root).unwrap();
        assert_eq!(before, after);
        let mut tree = StateTree::default();
        for (k, v) in &records {
            tree.insert(*k, v.clone()).unwrap();
        }
        assert_eq!(tree.root(), root);
        let proof = tree.proof(parent.clone(), key());
        proof.verify(&parent, root, key()).unwrap();
        let mut changed = records.clone();
        let at = changed.iter().position(|(k, _)| *k == key()).unwrap();
        changed[at].0 = [254; 32];
        changed.sort_by_key(|(k, _)| *k);
        let changed_root = crate::state_tree::full_root(&changed).unwrap();
        assert!(State::from_records(&changed, changed_root).is_err());
        changed = records.clone();
        changed[at].1 = vec![0x82, 2, 0x18, 57];
        let changed_root = crate::state_tree::full_root(&changed).unwrap();
        assert!(State::from_records(&changed, changed_root).is_err());
        let mut hidden = State::from_records(&rows, original).unwrap();
        hidden
            .protocol_records
            .insert([254; 32], authority.encode().unwrap());
        assert!(hidden.root().is_err());
        let mut wrong = state.clone();
        wrong.recovery_authority_v2.as_mut().unwrap().genesis[0] ^= 1;
        assert!(wrong.root().is_err());
        wrong = state.clone();
        wrong.continuity = None;
        assert!(wrong.root().is_err());
        let binding = state.continuity_keys_v2.bindings().next().unwrap();
        let (owner, _) = PublicKey::decode_descriptor(binding.owner_descriptor()).unwrap();
        for half in 0..2 {
            let mut alias = authority.public().unwrap();
            if half == 0 {
                alias.ed448 = owner.ed448;
            } else {
                alias.fndsa = owner.fndsa;
            }
            wrong = state.clone();
            wrong.recovery_authority_v2.as_mut().unwrap().descriptor = alias.descriptor(1).unwrap();
            assert!(wrong.root().is_err());
        }
        let worker = state
            .licenses_v2
            .assignments()
            .next()
            .unwrap()
            .enrollment
            .binding
            .worker_public;
        let mut alias = authority.public().unwrap();
        alias.ed448 = worker;
        wrong = state.clone();
        wrong.recovery_authority_v2.as_mut().unwrap().descriptor = alias.descriptor(1).unwrap();
        assert!(wrong.root().is_err());
        if let Ok(path) = std::env::var("BUILD8_PUBLIC_RECOVERY_STATE_VECTOR") {
            let value = serde_json::json!({"synthetic_only":true,"production_authorized":false,"root":hex::encode(root),"parent":hex::encode(parent.encode()),"authority_key":hex::encode(key()),"authority":hex::encode(authority.encode().unwrap()),"proof":hex::encode(proof.encode().unwrap()),"records":records.iter().map(|(k,v)|serde_json::json!({"key":hex::encode(k),"record":hex::encode(v)})).collect::<Vec<_>>()});
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(path)
                .unwrap();
            file.write_all((serde_json::to_string_pretty(&value).unwrap() + "\n").as_bytes())
                .unwrap();
        }
    }
}
