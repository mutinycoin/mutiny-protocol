//! Offline release authority core. Production enablement remains gated by crypto qualification.
use minicbor::Encoder;
use mutiny_crypto_v2::{Domain, HybridKey, HybridSignature, PublicKey, Role};
use sha2::{Digest, Sha256, Sha512};
use std::collections::BTreeSet;
type Hash = [u8; 32];
type Intent = [u8; 64];
pub type Result<T> = std::result::Result<T, &'static str>;
const SUITE: u16 = 1;
const NETWORK: u32 = 0x4d555401;
fn check(ok: bool, error: &'static str) -> Result<()> {
    if ok { Ok(()) } else { Err(error) }
}
fn id(domain: &[u8], bytes: &[u8]) -> Hash {
    Sha256::digest([domain, b"\0", bytes].concat()).into()
}
fn intent(domain: &[u8], bytes: &[u8]) -> Intent {
    Sha512::digest([domain, b"\0", bytes].concat()).into()
}
#[derive(Clone)]
pub struct Custodian {
    role: u8,
    generation: u64,
    suite: u16,
    ed: Vec<u8>,
    fndsa: Vec<u8>,
}
impl Custodian {
    fn bytes(&self) -> Result<Vec<u8>> {
        check(
            (1..=3).contains(&self.role) && self.generation > 0 && self.suite == SUITE,
            "custodian context",
        )?;
        check(
            self.ed.len() == 57 && self.fndsa.len() == 1793,
            "key length",
        )?;
        self.public()?.validate().map_err(|_| "hybrid public key")?;
        let mut e = Encoder::new(Vec::new());
        e.array(6)
            .unwrap()
            .u8(1)
            .unwrap()
            .u8(self.role)
            .unwrap()
            .u64(self.generation)
            .unwrap()
            .u16(self.suite)
            .unwrap()
            .bytes(&self.ed)
            .unwrap()
            .bytes(&self.fndsa)
            .unwrap();
        Ok(e.into_writer())
    }
    fn id(&self) -> Result<Hash> {
        Ok(id(b"MUTINY-BUILD8-RELEASE-CUSTODIAN-ID-V1", &self.bytes()?))
    }
}
#[derive(Clone)]
pub struct Policy {
    generation: u64,
    synthetic: bool,
    custodians: Vec<Custodian>,
}
impl Policy {
    fn bytes(&self) -> Result<Vec<u8>> {
        check(
            self.generation > 0 && self.custodians.len() == 3,
            "policy shape",
        )?;
        let mut roles = BTreeSet::new();
        let mut eds = BTreeSet::new();
        let mut fns = BTreeSet::new();
        let mut last = None;
        let mut bodies = Vec::new();
        for custodian in &self.custodians {
            let cid = custodian.id()?;
            check(
                last.is_none_or(|old| old < cid),
                "custodian ordering/duplicate",
            )?;
            last = Some(cid);
            check(
                roles.insert(custodian.role)
                    && eds.insert(custodian.ed.clone())
                    && fns.insert(custodian.fndsa.clone()),
                "shared role/key",
            )?;
            bodies.push(custodian.bytes()?);
        }
        let mut e = Encoder::new(Vec::new());
        e.array(6)
            .unwrap()
            .u8(1)
            .unwrap()
            .u32(NETWORK)
            .unwrap()
            .u64(self.generation)
            .unwrap()
            .bool(self.synthetic)
            .unwrap()
            .u8(2)
            .unwrap()
            .array(3)
            .unwrap();
        for b in bodies {
            e.bytes(&b).unwrap();
        }
        Ok(e.into_writer())
    }
    fn id(&self) -> Result<Hash> {
        Ok(id(
            b"MUTINY-BUILD8-FIRMWARE-RELEASE-POLICY-V1",
            &self.bytes()?,
        ))
    }
}
#[path = "release_wire.rs"]
mod wire;
#[derive(Clone)]
pub struct Manifest {
    network: u32,
    genesis: Option<Hash>,
    fingerprint: Hash,
    board: Hash,
    application: u64,
    security: u64,
    length: u32,
    image: [u8;64],
    schema_min: u16,
    schema_max: u16,
    policy: Hash,
    policy_generation: u64,
    rollback: u64,
    flags: u32,
}
impl Manifest {
    fn bytes(&self) -> Result<Vec<u8>> {
        check(
            self.network == NETWORK
                && self.application > 0
                && self.security > 0
                && self.rollback > 0,
            "manifest context",
        )?;
        check(
            self.length > 0
                && self.length <= 0x1e0000
                && self.schema_min > 0
                && self.schema_min <= self.schema_max,
            "manifest bounds",
        )?;
        check(
            self.flags == 0 && self.policy_generation > 0,
            "manifest flags/policy",
        )?;
        let mut e = Encoder::new(Vec::new());
        e.array(16)
            .unwrap()
            .u8(2)
            .unwrap()
            .u32(self.network)
            .unwrap();
        match self.genesis {
            None => {
                e.array(1).unwrap().u8(0).unwrap();
            }
            Some(g) => {
                e.array(2).unwrap().u8(1).unwrap().bytes(&g).unwrap();
            }
        }
        e.bytes(&self.fingerprint)
            .unwrap()
            .bytes(&self.board)
            .unwrap()
            .u64(self.application)
            .unwrap()
            .u64(self.security)
            .unwrap()
            .u32(self.length)
            .unwrap()
            .array(2).unwrap().u8(2).unwrap()
            .bytes(&self.image)
            .unwrap()
            .u8(1)
            .unwrap()
            .u16(self.schema_min)
            .unwrap()
            .u16(self.schema_max)
            .unwrap()
            .bytes(&self.policy)
            .unwrap()
            .u64(self.policy_generation)
            .unwrap()
            .u64(self.rollback)
            .unwrap()
            .u32(self.flags)
            .unwrap();
        Ok(e.into_writer())
    }
    fn digest(&self) -> Result<Intent> {
        Ok(intent(b"MUTINY-BUILD8-UPDATE-MANIFEST-V2", &self.bytes()?))
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct Approval {
    policy: Hash,
    generation: u64,
    custodian: Hash,
    manifest: Intent,
    suite: u16,
    ed: Vec<u8>,
    fndsa: Vec<u8>,
}
impl Approval {
    fn payload(&self) -> Result<Vec<u8>> {
        check(
            self.suite == SUITE && self.generation > 0,
            "approval suite/generation",
        )?;
        let mut e = Encoder::new(Vec::new());
        e.array(6)
            .unwrap()
            .u8(1)
            .unwrap()
            .bytes(&self.policy)
            .unwrap()
            .u64(self.generation)
            .unwrap()
            .bytes(&self.custodian)
            .unwrap()
            .bytes(&self.manifest)
            .unwrap()
            .u16(self.suite)
            .unwrap();
        Ok(e.into_writer())
    }
}
fn verify_hybrid(c: &Custodian, a: &Approval) -> Result<()> {
    let signature = HybridSignature {
        ed448: a.ed.as_slice().try_into().map_err(|_| "Ed448 length")?,
        fndsa: a.fndsa.as_slice().try_into().map_err(|_| "FN-DSA length")?,
    };
    c.public()?
        .verify(Domain::ReleaseApproval, &a.payload()?, &signature)
        .map_err(|_| "dual release signature")
}
fn quorum(policy: &Policy, digest: Intent, approvals: &[Approval], production: bool) -> Result<()> {
    let pid = policy.id()?;
    check(!production, "production security gate not qualified")?;
    check(policy.synthetic, "synthetic qualification policy required")?;
    check(approvals.len() <= 3, "approval bound")?;
    let mut seen = BTreeSet::new();
    for a in approvals {
        check(
            a.policy == pid && a.generation == policy.generation && a.manifest == digest,
            "approval context",
        )?;
        let custodian = policy
            .custodians
            .iter()
            .find(|c| c.id().ok() == Some(a.custodian))
            .ok_or("unknown custodian")?;
        verify_hybrid(custodian, a)?;
        seen.insert(a.custodian);
    }
    check(seen.len() >= 2, "release quorum")
}
fn verify_release(
    policy: &Policy,
    m: &Manifest,
    approvals: &[Approval],
    production: bool,
) -> Result<()> {
    check(
        m.policy == policy.id()? && m.policy_generation == policy.generation,
        "manifest policy",
    )?;
    quorum(policy, m.digest()?, approvals, production)
}
fn rotation_digest(old: &Policy, new: &Policy, fingerprint: Hash) -> Result<Intent> {
    check(
        new.generation > old.generation,
        "non-increasing policy generation",
    )?;
    check(old.synthetic == new.synthetic, "environment transition")?;
    let mut e = Encoder::new(Vec::new());
    e.array(6)
        .unwrap()
        .u8(1)
        .unwrap()
        .u32(NETWORK)
        .unwrap()
        .bytes(&fingerprint)
        .unwrap()
        .bytes(&old.id()?)
        .unwrap()
        .u64(old.generation)
        .unwrap()
        .bytes(&new.bytes()?)
        .unwrap();
    Ok(intent(
        b"MUTINY-BUILD8-FIRMWARE-POLICY-ROTATE-V1",
        &e.into_writer(),
    ))
}
fn rotate(
    active: &mut Policy,
    new: &Policy,
    fp: Hash,
    old_approvals: &[Approval],
    new_proofs: &[Approval],
) -> Result<()> {
    let digest = rotation_digest(active, new, fp)?;
    quorum(active, digest, old_approvals, false)?;
    quorum(new, digest, new_proofs, false)?;
    *active = new.clone();
    Ok(())
}
mod custody;
pub use custody::*;
#[cfg(test)]
mod tests;
