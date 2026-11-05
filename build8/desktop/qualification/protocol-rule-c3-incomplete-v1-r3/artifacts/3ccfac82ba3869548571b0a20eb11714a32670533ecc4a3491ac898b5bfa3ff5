//! Bounded pre-Genesis Worker handshake context candidate.
//! This codec authenticates nothing by itself and cannot construct a Session.
//! The caller supplies a previously verified, currently active V2 binding and
//! independently pinned Node descriptor. Authentication, primitive validation,
//! key confirmation and device integration remain separate requirements.
use crate::{Error, Result};
use mutiny_crypto_v2::{Domain, HybridSignature, NETWORK, PublicKey, Role, enrollment::Binding};
use sha2::{Digest, Sha256, Sha512};

pub const HELLO_LEN: usize = 2 + 64 + 32 + 56 + 1568;
pub const RESPONSE_BODY_LEN: usize = 32 + 56 + 1568;
const CONTEXT_DOMAIN: &[u8] = b"MUTINY-BUILD8-WORKER-SESSION-CONTEXT-V2";
const TRANSCRIPT_DOMAIN: &[u8] = b"MUTINY-BUILD8-WORKER-SESSION-TRANSCRIPT-V2";
const VERSION: u8 = 2;
// Candidate X448 + ML-KEM-1024 profile. No alternate suite acceptance.
const SUITE: u8 = 1;

#[derive(Clone)]
pub struct Context {
    binding: Binding,
    node_descriptor: Vec<u8>,
    id: [u8; 64],
}
impl Context {
    pub(crate) fn worker_public(&self) -> [u8; 57] {
        self.binding.worker_public
    }
    pub(crate) fn node_matches(&self, node: &PublicKey) -> bool {
        PublicKey::decode_descriptor(&self.node_descriptor).is_ok_and(|(p, _)| &p == node)
    }
    pub(crate) fn validate_hello(&self, hello: &[u8]) -> Result<()> {
        if hello.len() != HELLO_LEN {
            return Err(Error::Encoding);
        }
        if hello[..2] != [VERSION, SUITE]
            || hello[2..66] != self.id
            || hello[66..98] == [0; 32]
            || hello[98..154] == [0; 56]
        {
            return Err(Error::Context);
        }
        Ok(())
    }
    /// Verifies only the Node's transcript authentication. It does not establish
    /// shared keys, Finished confirmation, current work authority or a session.
    pub fn verify_coordinator(
        &self,
        hello: &[u8],
        response_body: &[u8],
        signature: &HybridSignature,
    ) -> Result<[u8; 64]> {
        let transcript = self.transcript(hello, response_body)?;
        let (node, _) =
            PublicKey::decode_descriptor(&self.node_descriptor).map_err(|_| Error::Crypto)?;
        node.verify(Domain::NodeWorkerSession, &transcript, signature)
            .map_err(|_| Error::Crypto)?;
        Ok(transcript)
    }
    /// Verification of the enrolled Ed448 Worker key, never a hybrid wallet key.
    pub fn verify_worker(
        &self,
        hello: &[u8],
        response_body: &[u8],
        signature: &[u8; 114],
    ) -> Result<[u8; 64]> {
        let transcript = self.transcript(hello, response_body)?;
        mutiny_crypto_v2::worker_session_auth::verify(
            &self.binding.worker_public,
            &transcript,
            signature,
        )
        .map_err(|_| Error::Crypto)?;
        Ok(transcript)
    }
    pub fn pinned(binding: &Binding, node: &PublicKey, generation: u64) -> Result<Self> {
        if node.role != Role::Node
            || generation == 0
            || binding.genesis == [0; 32]
            || binding.fingerprint == [0; 32]
        {
            return Err(Error::Context);
        }
        let unsigned = binding.bytes().map_err(|_| Error::Encoding)?;
        let descriptor = node.descriptor(generation).map_err(|_| Error::Crypto)?;
        if unsigned.len() > 512 || descriptor.len() > 2048 {
            return Err(Error::Limit);
        }
        let mut identity = Sha256::new();
        identity.update(b"MUTINY-BUILD8-NODE-AUTHORITY-IDENTITY-V2\0");
        identity.update(&descriptor);
        let id: [u8; 32] = identity.finalize().into();
        if id != binding.coordinator {
            return Err(Error::Context);
        }
        let mut h = Sha512::new();
        h.update(CONTEXT_DOMAIN);
        h.update([0, VERSION, SUITE]);
        h.update(NETWORK.to_be_bytes());
        h.update((unsigned.len() as u16).to_be_bytes());
        h.update(&unsigned);
        h.update((descriptor.len() as u16).to_be_bytes());
        h.update(&descriptor);
        Ok(Self {
            binding: binding.clone(),
            node_descriptor: descriptor,
            id: h.finalize().into(),
        })
    }
    pub fn id(&self) -> [u8; 64] {
        self.id
    }
    /// Parent churn alone does not change this context; reassignment, configuration
    /// or Node key generation must be checked against fresh state. The binding's
    /// `valid_until_height` is the assignment operation's INCLUSION deadline in
    /// consensus (`license_assignment_v2::verify_next_epoch`), not a session expiry:
    /// a canonical active assignment stays mining-valid after it, and so does its
    /// session (Order Q17; P-LANE-DESIGN-V1 11.2 b). Sessions remain bounded by the
    /// channel lifetime and end at the first current-authority check that differs.
    pub fn matches_current(
        &self,
        binding: &Binding,
        node: &PublicKey,
        generation: u64,
        height: u64,
        epoch: u64,
    ) -> bool {
        height > 0
            && epoch >= binding.effective_epoch
            && binding == &self.binding
            && node
                .descriptor(generation)
                .is_ok_and(|d| d == self.node_descriptor)
    }
    /// Inputs are public ephemeral material. Nonzero checks are structural;
    /// X448 agreement and ML-KEM validation must still run in the handshake.
    pub fn hello(
        &self,
        nonce: &[u8; 32],
        x448: &[u8; 56],
        kem: &[u8; 1568],
    ) -> Result<[u8; HELLO_LEN]> {
        if *nonce == [0; 32] || *x448 == [0; 56] {
            return Err(Error::Context);
        }
        let mut out = [0; HELLO_LEN];
        out[..2].copy_from_slice(&[VERSION, SUITE]);
        out[2..66].copy_from_slice(&self.id);
        out[66..98].copy_from_slice(nonce);
        out[98..154].copy_from_slice(x448);
        out[154..].copy_from_slice(kem);
        Ok(out)
    }
    pub fn transcript(&self, hello: &[u8], response_body: &[u8]) -> Result<[u8; 64]> {
        if hello.len() != HELLO_LEN || response_body.len() != RESPONSE_BODY_LEN {
            return Err(Error::Encoding);
        }
        if hello[..2] != [VERSION, SUITE]
            || hello[2..66] != self.id
            || hello[66..98] == [0; 32]
            || hello[98..154] == [0; 56]
            || response_body[..32] == [0; 32]
            || response_body[32..88] == [0; 56]
            || hello[66..98] == response_body[..32]
        {
            return Err(Error::Context);
        }
        let mut h = Sha512::new();
        h.update(TRANSCRIPT_DOMAIN);
        h.update([0]);
        h.update(hello);
        h.update(response_body);
        Ok(h.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mutiny_crypto_v2::HybridKey;
    #[test]
    fn worker_coordinator_requires_both_node_signatures_and_dedicated_domain() {
        let (mut b, _) = fixture();
        let node = HybridKey::generate(Role::Node).unwrap();
        let mut h = Sha256::new();
        h.update(b"MUTINY-BUILD8-NODE-AUTHORITY-IDENTITY-V2\0");
        h.update(node.public().descriptor(1).unwrap());
        b.coordinator = h.finalize().into();
        let c = Context::pinned(&b, node.public(), 1).unwrap();
        let hello = c.hello(&[1; 32], &[2; 56], &[3; 1568]).unwrap();
        let response = [4; RESPONSE_BODY_LEN];
        let th = c.transcript(&hello, &response).unwrap();
        let signature = node.sign(Domain::NodeWorkerSession, &th).unwrap();
        if let Ok(path) = std::env::var("BUILD8_PUBLIC_WORKER_NODE_AUTH_VECTOR") {
            use std::io::Write;
            let mut wire = response.to_vec();
            wire.extend_from_slice(&signature.ed448);
            wire.extend_from_slice(&signature.fndsa);
            let value = serde_json::json!({"synthetic_only":true,
                "unsigned_binding":hex::encode(b.bytes().unwrap()),
                "node_descriptor":hex::encode(node.public().descriptor(1).unwrap()),
                "hello":hex::encode(hello),"response":hex::encode(wire),
                "context":hex::encode(c.id()),"transcript":hex::encode(th)});
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .unwrap();
            writeln!(file, "{}", serde_json::to_string_pretty(&value).unwrap()).unwrap();
        }
        assert_eq!(
            c.verify_coordinator(&hello, &response, &signature).unwrap(),
            th
        );
        let ed_only = HybridSignature {
            ed448: signature.ed448,
            fndsa: [0; 1280],
        };
        let fn_only = HybridSignature {
            ed448: [0; 114],
            fndsa: signature.fndsa,
        };
        for wrong in [ed_only, fn_only, node.sign(Domain::NodeWork, &th).unwrap()] {
            assert!(c.verify_coordinator(&hello, &response, &wrong).is_err());
        }
        let mut changed = response;
        changed[88] ^= 1;
        assert!(c.verify_coordinator(&hello, &changed, &signature).is_err());
        let other = HybridKey::generate(Role::Node).unwrap();
        assert!(
            c.verify_coordinator(
                &hello,
                &response,
                &other.sign(Domain::NodeWorkerSession, &th).unwrap()
            )
            .is_err()
        );
        assert!(
            c.verify_worker(&hello, &response, &signature.ed448)
                .is_err()
        );
    }
    fn fixture() -> (Binding, PublicKey) {
        let f: serde_json::Value = serde_json::from_str(include_str!(
            "../../qualification/enrollment-v2-public-fixture-v3.json"
        ))
        .unwrap();
        assert_eq!(f["synthetic"], true);
        let mut b =
            Binding::decode(&hex::decode(f["unsigned"].as_str().unwrap()).unwrap()).unwrap();
        let key = HybridKey::generate(Role::Node).unwrap();
        let public = key.public().clone();
        drop(key);
        let mut h = Sha256::new();
        h.update(b"MUTINY-BUILD8-NODE-AUTHORITY-IDENTITY-V2\0");
        h.update(public.descriptor(1).unwrap());
        b.coordinator = h.finalize().into();
        (b, public)
    }
    #[test]
    fn worker_context_binds_every_active_assignment_field_and_node_generation() {
        let (b, node) = fixture();
        let c = Context::pinned(&b, &node, 1).unwrap();
        assert!(c.matches_current(&b, &node, 1, 1, 0));
        assert!(!c.matches_current(&b, &node, 2, 1, 0));
        assert!(Context::pinned(&b, &node, 2).is_err());
        assert!(!c.matches_current(&b, &node, 1, 0, 0));
        let mutations: Vec<Box<dyn Fn(&mut Binding)>> = vec![
            Box::new(|b| b.genesis[0] ^= 1),
            Box::new(|b| b.fingerprint[0] ^= 1),
            Box::new(|b| b.license[0] ^= 1),
            Box::new(|b| b.owner_descriptor[0] ^= 1),
            Box::new(|b| b.owner_generation += 1),
            Box::new(|b| b.worker_public[0] ^= 1),
            Box::new(|b| b.worker_id[0] ^= 1),
            Box::new(|b| b.coordinator[0] ^= 1),
            Box::new(|b| b.configuration_generation += 1),
            Box::new(|b| b.device_mac[0] ^= 1),
            Box::new(|b| b.assignment_generation += 1),
            Box::new(|b| b.effective_epoch += 1),
            Box::new(|b| b.valid_until_height = 1),
        ];
        for mutate in mutations {
            let mut changed = b.clone();
            mutate(&mut changed);
            assert!(!c.matches_current(&changed, &node, 1, 1, 1));
            if let Ok(other) = Context::pinned(&changed, &node, 1) {
                assert_ne!(c.id(), other.id());
            }
        }
        // `valid_until_height` is the inclusion deadline, not a session expiry (Order Q17;
        // P-LANE-DESIGN-V1 11.2 b): the session of the active assignment continues past it.
        let mut scheduled = b;
        scheduled.effective_epoch = 3;
        scheduled.valid_until_height = 60;
        let c = Context::pinned(&scheduled, &node, 1).unwrap();
        assert!(!c.matches_current(&scheduled, &node, 1, 60, 2));
        assert!(c.matches_current(&scheduled, &node, 1, 60, 3));
        assert!(c.matches_current(&scheduled, &node, 1, 61, 3));
    }
    #[test]
    fn valid_until_height_does_not_end_active_session() {
        // Consensus uses `valid_until_height` only as the inclusion deadline of the assignment
        // operation and cannot schedule 0, so every post-Genesis assignment carries one; the
        // assignment stays canonical and mining-valid after it. Authority changes still end
        // the session at the first check, before and after that height.
        let (genesis, node) = fixture();
        assert_eq!(
            (genesis.assignment_generation, genesis.effective_epoch, genesis.valid_until_height),
            (1, 0, 0)
        );
        let mut active = genesis.clone();
        active.assignment_generation = 2;
        active.configuration_generation = 2;
        active.effective_epoch = 3;
        active.valid_until_height = 60;
        let c = Context::pinned(&active, &node, 1).unwrap();
        for height in [1, 59, 60, 61, 1_000, u64::MAX] {
            assert!(c.matches_current(&active, &node, 1, height, 3), "height {height}");
            assert!(c.matches_current(&active, &node, 1, height, u64::MAX), "height {height}");
            assert!(!c.matches_current(&active, &node, 1, height, 2), "height {height}: before effective epoch");
        }
        assert!(!c.matches_current(&active, &node, 1, 0, 3));
        // Stale sequence: the License was reassigned or sold, so the current binding carries a
        // later assignment generation.
        let mut reassigned = active.clone();
        reassigned.assignment_generation = 3;
        // Wrong owner: the current binding is authorized by another owner.
        let mut other_owner = active.clone();
        other_owner.owner_descriptor = [0x5a; 32];
        let mut other_generation = active.clone();
        other_generation.owner_generation = 2;
        for height in [30, 60, 61, 1_000] {
            for current in [&reassigned, &other_owner, &other_generation] {
                assert!(!c.matches_current(current, &node, 1, height, 3), "height {height}");
            }
        }
        // Genesis bindings (deadline 0) are unaffected.
        let g = Context::pinned(&genesis, &node, 1).unwrap();
        for height in [1, 61, u64::MAX] {
            assert!(g.matches_current(&genesis, &node, 1, height, 0), "height {height}");
        }
    }
    #[test]
    fn worker_transcript_exact_bounds_reflection_and_ephemeral_commitment() {
        let (b, node) = fixture();
        let c = Context::pinned(&b, &node, 1).unwrap();
        let hello = c.hello(&[1; 32], &[2; 56], &[3; 1568]).unwrap();
        let mut response = [4; RESPONSE_BODY_LEN];
        response[32..88].fill(5);
        response[88..].fill(6);
        let original = c.transcript(&hello, &response).unwrap();
        for n in [0, 1, HELLO_LEN - 1] {
            assert!(c.transcript(&hello[..n], &response).is_err());
        }
        let mut trailing = hello.to_vec();
        trailing.push(0);
        assert!(c.transcript(&trailing, &response).is_err());
        for n in [0, 1, RESPONSE_BODY_LEN - 1] {
            assert!(c.transcript(&hello, &response[..n]).is_err());
        }
        let mut trailing = response.to_vec();
        trailing.push(0);
        assert!(c.transcript(&hello, &trailing).is_err());
        for i in 0..66 {
            let mut bad = hello;
            bad[i] ^= 1;
            assert!(c.transcript(&bad, &response).is_err());
        }
        for i in 66..HELLO_LEN {
            let mut bad = hello;
            bad[i] ^= 1;
            assert_ne!(c.transcript(&bad, &response).unwrap(), original);
        }
        for i in 0..RESPONSE_BODY_LEN {
            let mut bad = response;
            bad[i] ^= 1;
            assert_ne!(c.transcript(&hello, &bad).unwrap(), original);
        }
        let mut bad = response;
        bad[..32].fill(1);
        assert!(c.transcript(&hello, &bad).is_err());
        bad[..32].fill(0);
        assert!(c.transcript(&hello, &bad).is_err());
        assert!(c.hello(&[0; 32], &[2; 56], &[3; 1568]).is_err());
        assert!(c.hello(&[1; 32], &[0; 56], &[3; 1568]).is_err());
        if let Ok(path) = std::env::var("BUILD8_PUBLIC_WORKER_CONTEXT_VECTOR") {
            let vector = serde_json::json!({"synthetic_only":true,"production_authorized":false,
                "unsigned_binding":hex::encode(b.bytes().unwrap()),"node_descriptor":hex::encode(node.descriptor(1).unwrap()),
                "context":hex::encode(c.id()),"hello":hex::encode(hello),"response_body":hex::encode(response),
                "transcript":hex::encode(original)});
            use std::io::Write;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .unwrap()
                .write_all(serde_json::to_string_pretty(&vector).unwrap().as_bytes())
                .unwrap();
        }
    }
}
