//! Initial node-authentication binding to a supervised hybrid physical admission.
//! Node authentication is separate from Continuity voting and wallet custody.
use crate::{
    Error, Hash, NETWORK_ID, Result,
    admission_v2::{Admission, Expected, Policy, VerifiedAdmission},
    domain_hash,
    wallet_authority_v1::WalletBook,
};
use minicbor::{Decoder, Encoder};
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, PublicKey, Role};
pub const MAX_BINDING_BYTES: usize = 16 * 1024;
/// A Continuity NodeID is network-generation-bound. It is distinct from the
/// coordinator descriptor identity used by the Worker work-authorization codec.
pub fn node_id(genesis: Hash, descriptor: &[u8]) -> Result<Hash> {
    let (key, _) = PublicKey::decode_descriptor(descriptor).map_err(|_| Error::Codec)?;
    if genesis == [0; 32] || key.role != Role::Node {
        return Err(Error::WrongGeneration);
    }
    let mut e = Encoder::new(Vec::new());
    e.array(4)
        .unwrap()
        .u8(2)
        .unwrap()
        .u32(NETWORK_ID)
        .unwrap()
        .bytes(&genesis)
        .unwrap()
        .bytes(descriptor)
        .unwrap();
    Ok(domain_hash(
        b"MUTINY-BUILD8-PHYSICAL-NODE-ID-V2",
        &e.into_writer(),
    ))
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Binding {
    pub admission: Admission,
    pub node_descriptor: Vec<u8>,
    /// Historical signer from authenticated Node-key history; identity stays original.
    pub node_signer: Option<Vec<u8>>,
    pub possession: HybridSignature,
}
pub struct VerifiedBinding {
    admission: VerifiedAdmission,
    node_descriptor: Vec<u8>,
}
impl VerifiedBinding {
    pub fn admission(&self) -> &VerifiedAdmission {
        &self.admission
    }
    pub fn node_descriptor(&self) -> &[u8] {
        &self.node_descriptor
    }
}
impl Binding {
    pub fn signer_descriptor(&self) -> &[u8] {
        self.node_signer.as_deref().unwrap_or(&self.node_descriptor)
    }
    /// Only for typed reconstruction against the matching authenticated key
    /// record. It does not authorize a fresh admission or revive an old owner.
    pub(crate) fn verify_stored(&self, stored: &crate::continuity_keys_v2::Binding) -> Result<()> {
        self.encode()?;
        if &self.admission != stored.admission() {
            return Err(Error::WrongAnchor);
        }
        stored.verify_historical_evidence()?;
        let (node, _) =
            PublicKey::decode_descriptor(self.signer_descriptor()).map_err(|_| Error::Codec)?;
        let (owner, _) =
            PublicKey::decode_descriptor(stored.owner_descriptor()).map_err(|_| Error::Codec)?;
        let continuity = stored.public()?;
        if node.ed448 == owner.ed448
            || node.fndsa == owner.fndsa
            || node.ed448 == continuity.ed448
            || node.fndsa == continuity.fndsa
        {
            return Err(Error::Duplicate);
        }
        node.verify(
            Domain::NodeAdmissionPossession,
            &self.body()?,
            &self.possession,
        )
        .map_err(|_| Error::BadSignature)
    }
    pub fn body(&self) -> Result<Vec<u8>> {
        if node_id(self.admission.genesis, &self.node_descriptor)? != self.admission.node {
            return Err(Error::WrongAnchor);
        }
        if let Some(signer) = &self.node_signer {
            let (origin, initial) =
                PublicKey::decode_descriptor(&self.node_descriptor).map_err(|_| Error::Codec)?;
            let (current, generation) =
                PublicKey::decode_descriptor(signer).map_err(|_| Error::Codec)?;
            if initial != 1
                || generation <= 1
                || current.role != Role::Node
                || current.ed448 == origin.ed448
                || current.fndsa == origin.fndsa
            {
                return Err(Error::WrongGeneration);
            }
        }
        let mut e = Encoder::new(Vec::new());
        e.array(if self.node_signer.is_some() { 4 } else { 3 })
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(&self.admission.encode()?)
            .unwrap()
            .bytes(&self.node_descriptor)
            .unwrap();
        if let Some(signer) = &self.node_signer {
            e.bytes(signer).unwrap();
        }
        let raw = e.into_writer();
        // Reserve exact room for the outer array/version and two signatures.
        if raw.len() + 1404 > MAX_BINDING_BYTES {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn sign(&mut self, node: &HybridKey) -> Result<()> {
        let (expected, _) =
            PublicKey::decode_descriptor(self.signer_descriptor()).map_err(|_| Error::Codec)?;
        if node.public() != &expected {
            return Err(Error::BadSignature);
        }
        self.possession = node
            .sign(Domain::NodeAdmissionPossession, &self.body()?)
            .map_err(|_| Error::BadSignature)?;
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut e = Encoder::new(Vec::new());
        e.array(4)
            .unwrap()
            .u8(2)
            .unwrap()
            .bytes(&self.body()?)
            .unwrap()
            .bytes(&self.possession.ed448)
            .unwrap()
            .bytes(&self.possession.fndsa)
            .unwrap();
        let raw = e.into_writer();
        if raw.len() > MAX_BINDING_BYTES {
            return Err(Error::Oversize);
        }
        Ok(raw)
    }
    pub fn decode(raw: &[u8]) -> Result<Self> {
        crate::blocks::canonical(raw, MAX_BINDING_BYTES)?;
        let mut d = Decoder::new(raw);
        if d.array().map_err(|_| Error::Codec)? != Some(4) || d.u8().map_err(|_| Error::Codec)? != 2
        {
            return Err(Error::Codec);
        }
        let body = d.bytes().map_err(|_| Error::Codec)?;
        let possession = HybridSignature {
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
        };
        let mut b = Decoder::new(body);
        let fields = b.array().map_err(|_| Error::Codec)?;
        if !matches!(fields, Some(3 | 4)) || b.u8().map_err(|_| Error::Codec)? != 2 {
            return Err(Error::Codec);
        }
        let value = Self {
            admission: Admission::decode(b.bytes().map_err(|_| Error::Codec)?)?,
            node_descriptor: b.bytes().map_err(|_| Error::Codec)?.to_vec(),
            node_signer: if fields == Some(4) {
                Some(b.bytes().map_err(|_| Error::Codec)?.to_vec())
            } else {
                None
            },
            possession,
        };
        if d.position() != raw.len() || b.position() != body.len() || value.encode()? != raw {
            return Err(Error::NonCanonical);
        }
        Ok(value)
    }
    pub(crate) fn verify_admission_material(
        &self,
        policy: &Policy,
        expected: &Expected,
        wallets: &WalletBook,
        class: crate::provenance::AdmissionClass,
    ) -> Result<VerifiedAdmission> {
        self.encode()?;
        let admission = self.admission.verify(policy, expected, wallets, class)?;
        let (node, _) =
            PublicKey::decode_descriptor(self.signer_descriptor()).map_err(|_| Error::Codec)?;
        let (owner, _) =
            PublicKey::decode_descriptor(&policy.owner_descriptor).map_err(|_| Error::Codec)?;
        let continuity = admission.continuity();
        if node.ed448 == owner.ed448
            || node.fndsa == owner.fndsa
            || node.ed448 == continuity.ed448
            || node.fndsa == continuity.fndsa
        {
            return Err(Error::Duplicate);
        }
        Ok(admission)
    }
    /// `class` comes from the same parent state as `policy` (`State::admission_class`).
    pub fn verify(
        &self,
        policy: &Policy,
        expected: &Expected,
        wallets: &WalletBook,
        class: crate::provenance::AdmissionClass,
    ) -> Result<VerifiedBinding> {
        let admission = self.verify_admission_material(policy, expected, wallets, class)?;
        let (node, _) =
            PublicKey::decode_descriptor(self.signer_descriptor()).map_err(|_| Error::Codec)?;
        node.verify(
            Domain::NodeAdmissionPossession,
            &self.body()?,
            &self.possession,
        )
        .map_err(|_| Error::BadSignature)?;
        Ok(VerifiedBinding {
            admission,
            node_descriptor: self.node_descriptor.clone(),
        })
    }
}
