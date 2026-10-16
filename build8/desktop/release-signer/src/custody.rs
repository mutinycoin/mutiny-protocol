use super::*;
use minicbor::Decoder;

impl Custodian {
    pub(crate) fn public(&self) -> Result<PublicKey> {
        Ok(PublicKey {
            role: Role::Release,
            ed448: self
                .ed
                .as_slice()
                .try_into()
                .map_err(|_| "Ed448 key length")?,
            fndsa: self
                .fndsa
                .as_slice()
                .try_into()
                .map_err(|_| "FN-DSA key length")?,
        })
    }
}
fn context(role: u8, generation: u64) -> Result<Vec<u8>> {
    check(
        (1..=3).contains(&role) && generation > 0,
        "custodian context",
    )?;
    let mut e = Encoder::new(Vec::new());
    e.array(5)
        .unwrap()
        .u8(1)
        .unwrap()
        .u32(NETWORK)
        .unwrap()
        .u8(role)
        .unwrap()
        .u64(generation)
        .unwrap()
        .bool(true)
        .unwrap();
    Ok(e.into_writer())
}
fn possession_payload(c: &Custodian) -> Result<Vec<u8>> {
    let mut e = Encoder::new(Vec::new());
    e.array(4)
        .unwrap()
        .u8(1)
        .unwrap()
        .u32(NETWORK)
        .unwrap()
        .bool(true)
        .unwrap()
        .bytes(&c.bytes()?)
        .unwrap();
    Ok(e.into_writer())
}
pub struct CustodianSession {
    key: HybridKey,
    custodian: Custodian,
}

pub fn inspect_synthetic_descriptor(encoded: &[u8]) -> Result<String> {
    let c = descriptor(encoded)?;
    Ok(format!("SYNTHETIC DESCRIPTOR — DUAL POSSESSION PASS\nCustodian role: {}\nCustodianID: {}\nGeneration: {}\nSuite: {}\nEd448 key bytes: {}\nFN-DSA key bytes: {}", c.role, hex::encode(c.id()?), c.generation, Role::Release.suite(), c.ed.len(), c.fndsa.len()))
}
impl CustodianSession {
    pub fn approve_rotation(&self, review: &RotationReview, proposed: bool) -> Result<Vec<u8>> {
        let policy = if proposed { &review.new } else { &review.old };
        let id = self.custodian.id()?;
        check(
            policy.custodians.iter().any(|c| c.id().ok() == Some(id)),
            "custodian not active in selected rotation policy",
        )?;
        let mut a = Approval {
            policy: policy.id()?,
            generation: policy.generation,
            custodian: id,
            manifest: rotation_digest(&review.old, &review.new, review.fingerprint)?,
            suite: SUITE,
            ed: vec![],
            fndsa: vec![],
        };
        let signature = self
            .key
            .sign(Domain::ReleaseApproval, &a.payload()?)
            .map_err(|_| "dual rotation approval failed")?;
        a.ed = signature.ed448.to_vec();
        a.fndsa = signature.fndsa.to_vec();
        verify_hybrid(&self.custodian, &a)?;
        a.bytes()
    }
    pub fn create_synthetic(role: u8, password: &str) -> Result<(Vec<u8>, Vec<u8>)> {
        let binding = context(role, 1)?;
        let key = HybridKey::generate(Role::Release)
            .map_err(|_| "local release key generation failed")?;
        let custodian = Custodian {
            role,
            generation: 1,
            suite: SUITE,
            ed: key.public().ed448.to_vec(),
            fndsa: key.public().fndsa.to_vec(),
        };
        let encrypted = key
            .seal_for(password, 1, &binding)
            .map_err(|_| "encrypted custody failed")?;
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(1)
            .unwrap()
            .bool(true)
            .unwrap()
            .u8(role)
            .unwrap()
            .u64(1)
            .unwrap()
            .bytes(&encrypted)
            .unwrap();
        let session = Self { key, custodian };
        Ok((e.into_writer(), session.public_descriptor()?))
    }
    pub fn open_synthetic(password: &str, vault: &[u8]) -> Result<Self> {
        check(vault.len() <= 8192, "vault bound")?;
        let mut d = Decoder::new(vault);
        check(
            d.array().map_err(|_| "vault")? == Some(5)
                && d.u8().map_err(|_| "vault")? == 1
                && d.bool().map_err(|_| "vault")?,
            "synthetic vault required",
        )?;
        let role = d.u8().map_err(|_| "role")?;
        let generation = d.u64().map_err(|_| "generation")?;
        let encrypted = d.bytes().map_err(|_| "encrypted vault")?;
        check(d.position() == vault.len(), "trailing vault bytes")?;
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(1)
            .unwrap()
            .bool(true)
            .unwrap()
            .u8(role)
            .unwrap()
            .u64(generation)
            .unwrap()
            .bytes(encrypted)
            .unwrap();
        check(e.into_writer() == vault, "noncanonical vault")?;
        let (key, inside_generation) = HybridKey::open_for(
            Role::Release,
            password,
            &context(role, generation)?,
            encrypted,
        )
        .map_err(|_| "custody unlock failed")?;
        check(generation == inside_generation, "custody generation")?;
        let custodian = Custodian {
            role,
            generation,
            suite: SUITE,
            ed: key.public().ed448.to_vec(),
            fndsa: key.public().fndsa.to_vec(),
        };
        Ok(Self { key, custodian })
    }
    pub fn public_descriptor(&self) -> Result<Vec<u8>> {
        let proof = self
            .key
            .sign(
                Domain::ReleasePossession,
                &possession_payload(&self.custodian)?,
            )
            .map_err(|_| "dual possession signing failed")?;
        let mut e = Encoder::new(Vec::new());
        e.array(5)
            .unwrap()
            .u8(1)
            .unwrap()
            .bool(true)
            .unwrap()
            .bytes(&self.custodian.bytes()?)
            .unwrap()
            .bytes(&proof.ed448)
            .unwrap()
            .bytes(&proof.fndsa)
            .unwrap();
        Ok(e.into_writer())
    }
    pub fn approve_review(&self, review: &ReleaseReview) -> Result<Vec<u8>> {
        let id = self.custodian.id()?;
        check(
            review
                .policy
                .custodians
                .iter()
                .any(|c| c.id().ok() == Some(id)),
            "custodian not active in reviewed policy",
        )?;
        let mut a = Approval {
            policy: review.policy.id()?,
            generation: review.policy.generation,
            custodian: id,
            manifest: review.manifest.digest()?,
            suite: SUITE,
            ed: vec![],
            fndsa: vec![],
        };
        let signature = self
            .key
            .sign(Domain::ReleaseApproval, &a.payload()?)
            .map_err(|_| "dual approval signing failed")?;
        a.ed = signature.ed448.to_vec();
        a.fndsa = signature.fndsa.to_vec();
        verify_hybrid(&self.custodian, &a)?;
        a.bytes()
    }
}
fn descriptor(encoded: &[u8]) -> Result<Custodian> {
    check(encoded.len() <= 3400, "descriptor package bound")?;
    let mut d = Decoder::new(encoded);
    check(
        d.array().map_err(|_| "descriptor")? == Some(5)
            && d.u8().map_err(|_| "descriptor")? == 1
            && d.bool().map_err(|_| "synthetic marker")?,
        "synthetic descriptor required",
    )?;
    let raw = d.bytes().map_err(|_| "custodian")?;
    let c = Custodian::decode(raw)?;
    let ed = d.bytes().map_err(|_| "Ed448 possession")?;
    let fndsa = d.bytes().map_err(|_| "FN-DSA possession")?;
    check(d.position() == encoded.len(), "descriptor trailing data")?;
    let signature = HybridSignature {
        ed448: ed.try_into().map_err(|_| "Ed448 length")?,
        fndsa: fndsa.try_into().map_err(|_| "FN-DSA length")?,
    };
    c.public()?
        .verify(
            Domain::ReleasePossession,
            &possession_payload(&c)?,
            &signature,
        )
        .map_err(|_| "dual possession proof")?;
    let mut e = Encoder::new(Vec::new());
    e.array(5)
        .unwrap()
        .u8(1)
        .unwrap()
        .bool(true)
        .unwrap()
        .bytes(raw)
        .unwrap()
        .bytes(ed)
        .unwrap()
        .bytes(fndsa)
        .unwrap();
    check(
        e.into_writer() == encoded,
        "noncanonical descriptor package",
    )?;
    Ok(c)
}
pub fn combine_synthetic_descriptors(descriptors: &[Vec<u8>], generation: u64) -> Result<Vec<u8>> {
    check(descriptors.len() == 3, "exactly three descriptors required")?;
    let mut custodians = descriptors
        .iter()
        .map(|d| descriptor(d))
        .collect::<Result<Vec<_>>>()?;
    custodians.sort_by_key(|c| c.id().unwrap());
    Policy {
        generation,
        synthetic: true,
        custodians,
    }
    .bytes()
}
pub struct ReleaseReview {
    policy: Policy,
    manifest: Manifest,
}
impl ReleaseReview {
    pub fn from_bytes(policy: &[u8], manifest: &[u8], image: &[u8]) -> Result<Self> {
        let policy = Policy::decode(policy)?;
        let manifest = Manifest::decode(manifest)?;
        check(policy.synthetic, "production root gate remains closed")?;
        check(
            manifest.policy == policy.id()? && manifest.policy_generation == policy.generation,
            "manifest policy",
        )?;
        check(
            image.len() == manifest.length as usize
                && Sha512::digest(image).as_slice() == manifest.image,
            "candidate artifact hash/length mismatch",
        )?;
        Ok(Self { policy, manifest })
    }
    pub fn summary(&self) -> Result<String> {
        let m = &self.manifest;
        Ok(format!(
            "SYNTHETIC QUALIFICATION ONLY — NOT PRODUCTION AUTHORITY\nNetwork: {:#010x}\nGenesis compatibility: {}\nProtocolFingerprint: {}\nBoard profile: {}\nApplication version: {}\nSecurity version: {}\nImage length: {}\nImage SHA-512: {}\nTarget: INACTIVE_APPLICATION\nStorage schema: {}..={}\nReleasePolicyID: {}\nReleasePolicy generation: {}\nAntiRollbackGeneration: {}\nFlags: {}\nManifest intent SHA-512: {}\n",
            m.network,
            m.genesis
                .map(hex::encode)
                .unwrap_or_else(|| "UNENROLLED / PRE-GENESIS ONLY".into()),
            hex::encode(m.fingerprint),
            hex::encode(m.board),
            m.application,
            m.security,
            m.length,
            hex::encode(m.image),
            m.schema_min,
            m.schema_max,
            hex::encode(m.policy),
            m.policy_generation,
            m.rollback,
            m.flags,
            hex::encode(m.digest()?)
        ))
    }
    pub fn confirmation(&self) -> Result<String> {
        Ok(format!(
            "APPROVE {}",
            hex::encode(&self.manifest.digest()?[..8])
        ))
    }
}
pub fn verify_synthetic_release(
    policy: &[u8],
    manifest: &[u8],
    approvals: &[Vec<u8>],
) -> Result<()> {
    check(approvals.len() <= 3, "approval count")?;
    let p = Policy::decode(policy)?;
    let m = Manifest::decode(manifest)?;
    let a = approvals
        .iter()
        .map(|a| Approval::decode(a))
        .collect::<Result<Vec<_>>>()?;
    verify_release(&p, &m, &a, false)
}
pub struct RotationReview {
    old: Policy,
    new: Policy,
    fingerprint: Hash,
}
impl RotationReview {
    pub fn from_bytes(old: &[u8], new: &[u8], fingerprint: [u8; 32]) -> Result<Self> {
        let old = Policy::decode(old)?;
        let new = Policy::decode(new)?;
        check(
            old.synthetic && new.synthetic,
            "production rotation gate remains closed",
        )?;
        rotation_digest(&old, &new, fingerprint)?;
        Ok(Self {
            old,
            new,
            fingerprint,
        })
    }
    pub fn confirmation(&self) -> Result<String> {
        Ok(format!(
            "APPROVE ROTATION {}",
            hex::encode(&rotation_digest(&self.old, &self.new, self.fingerprint)?[..8])
        ))
    }
    pub fn summary(&self) -> Result<String> {
        let mut s = format!(
            "SYNTHETIC POLICY ROTATION — NO DEVICE ACTIVATION\nNetwork: {NETWORK:#010x}\nProtocolFingerprint: {}\nCurrent policy: {} generation {}\nProposed policy: {} generation {}\nRequired: current 2-of-3 dual quorum AND proposed 2-of-3 dual possession quorum\n",
            hex::encode(self.fingerprint),
            hex::encode(self.old.id()?),
            self.old.generation,
            hex::encode(self.new.id()?),
            self.new.generation
        );
        for (label, policy) in [("CURRENT", &self.old), ("PROPOSED", &self.new)] {
            for c in &policy.custodians {
                s.push_str(&format!("{label} custodian role {} ID {} key-generation {}\n  Suite: {} (wire {})\n  Ed448: {}\n  FN-DSA-1024 public-key SHA-256: {}\n",c.role,hex::encode(c.id()?),c.generation,Role::Release.suite(),c.suite,hex::encode(&c.ed),hex::encode(Sha256::digest(&c.fndsa))));
            }
        }
        Ok(s)
    }
}
pub fn verify_synthetic_rotation(
    old: &[u8],
    new: &[u8],
    fingerprint: [u8; 32],
    old_approvals: &[Vec<u8>],
    new_proofs: &[Vec<u8>],
) -> Result<Vec<u8>> {
    check(
        old_approvals.len() <= 3 && new_proofs.len() <= 3,
        "rotation count bound",
    )?;
    let review = RotationReview::from_bytes(old, new, fingerprint)?;
    let old = old_approvals
        .iter()
        .map(|b| Approval::decode(b))
        .collect::<Result<Vec<_>>>()?;
    let new = new_proofs
        .iter()
        .map(|b| Approval::decode(b))
        .collect::<Result<Vec<_>>>()?;
    let mut current = review.old;
    rotate(&mut current, &review.new, review.fingerprint, &old, &new)?;
    current.bytes()
}
