//! Shared helpers for the Treasury ceremony tests (declared once at FILE scope by each test file).
//! SIMULATED / TEST-VALUE: every key derives from a public label; every file lives in a unique,
//! atomically created temp directory that the test deletes.
#![allow(dead_code)]
use crate::{
    Hash, NETWORK_ID,
    dividend_state_v1::DividendState,
    execution::State,
    treasury_rehearsal_v1::{self as r, CeremonyConfig, TrustedChain},
    treasury_v1::{Class, Treasury},
    wallet_rotation_v1::Rotation,
};
use mutiny_crypto_v2::{
    HybridKey, HybridSignature, NETWORK, fill_os_random,
    rehearsal_keys_v1::Credential,
    treasury_proof_v1::{self as proof, Challenge},
};
use sha2::{Digest, Sha256};

pub fn h32(tag: &str) -> Hash {
    Sha256::digest(tag.as_bytes()).into()
}

/// A unique directory created atomically (retry on collision); the caller deletes only it.
pub fn scratch_dir(tag: &str) -> std::path::PathBuf {
    loop {
        let mut n = [0u8; 8];
        fill_os_random(&mut n).unwrap();
        let dir = std::env::temp_dir().join(format!("build8-c3-{tag}-{}", hex::encode(n)));
        match std::fs::create_dir(&dir) {
            Ok(()) => return dir,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("cannot create scratch dir: {e}"),
        }
    }
}

/// Trusted chain identity a rehearsal rotation plan is authorized for (public TEST-VALUE values).
pub fn plan_genesis() -> Hash {
    h32("c3-rehearsal-plan-genesis")
}
pub fn plan_fingerprint() -> Hash {
    h32("c3-rehearsal-plan-fingerprint")
}
/// The trusted rehearsal chain at `height` (plans of these tests are valid for heights 1 to 100).
pub fn trusted_chain(height: u64) -> TrustedChain {
    TrustedChain { network: NETWORK, genesis: plan_genesis(), fingerprint: plan_fingerprint(), height }
}
/// The trusted height the configurations of these tests use.
pub const TRUSTED_HEIGHT: u64 = 50;

fn empty() -> HybridSignature {
    HybridSignature { ed448: [0; 114], fndsa: [0; 1280] }
}

/// The exact rotation plan `from` (generation of `current`) -> `to` (descriptor `proposed`) for the
/// Treasury authority, signed by both keys (current-key authorization, new-key possession).
pub fn rotation_plan(authority: Hash, from: &HybridKey, current: Vec<u8>, to: &HybridKey, proposed: Vec<u8>, genesis: Hash, fingerprint: Hash) -> Rotation {
    let mut plan = Rotation {
        network: NETWORK_ID,
        genesis,
        fingerprint,
        authority,
        current,
        proposed,
        created_height: 1,
        expiry_height: 100,
        authorization: empty(),
        possession: empty(),
    };
    plan.sign(from, to).expect("plan signs");
    plan
}

/// (records, StateRoot) of a canonical state whose wallet book registered `register` (generation one)
/// and then applied each plan in order through the canonical `WalletBook::apply` transition.
pub fn lineage_state(register: &[u8], plans: &[Rotation]) -> (Vec<(Hash, Vec<u8>)>, Hash) {
    lineage_state_with(None, register, plans)
}
/// As [`lineage_state`], with the dividend component activated by `treasury` (its Treasury record
/// then enters the StateRoot).
pub fn lineage_state_with(treasury: Option<&Treasury>, register: &[u8], plans: &[Rotation]) -> (Vec<(Hash, Vec<u8>)>, Hash) {
    let mut state = State::default();
    if let Some(t) = treasury {
        state.dividends = DividendState::genesis(t.clone());
    }
    state.wallets.register(register).expect("register");
    for plan in plans {
        state.wallets.apply(plan, plan.genesis, plan.fingerprint, plan.created_height).expect("canonical rotation");
    }
    (state.records().expect("records"), state.root().expect("root"))
}

/// A rehearsal ceremony: Treasury record from K1, the authorized successor K2 (generation 2), an
/// impostor K3 (generation 2) and a stranger S (generation 1) that is not the Treasury key.
pub struct Ceremony {
    pub k1: Credential,
    pub k2: Credential,
    pub k3: Credential,
    pub stranger: Credential,
    pub treasury: Treasury,
    pub config: CeremonyConfig,
    pub label: String,
}
impl Ceremony {
    pub fn new(tag: &str) -> Self {
        let k1 = Credential::from_label(&format!("{tag}-k1"), 1).unwrap();
        let k2 = Credential::from_label(&format!("{tag}-k2"), 2).unwrap();
        let k3 = Credential::from_label(&format!("{tag}-k3"), 2).unwrap();
        let stranger = Credential::from_label(&format!("{tag}-stranger"), 1).unwrap();
        let treasury = Treasury::new(Class::TestValue, k1.descriptor().unwrap()).unwrap();
        let label = format!("{tag}-ceremony");
        let config = CeremonyConfig::rehearsal(NETWORK, treasury.clone(), &label).unwrap();
        Self { k1, k2, k3, stranger, treasury, config, label }
    }
    /// The authorized plan K1 -> K2 (fresh signatures each call; the identity is always the same).
    pub fn plan(&self) -> Rotation {
        rotation_plan(
            self.treasury.authority(),
            self.k1.key(),
            self.k1.descriptor().unwrap(),
            self.k2.key(),
            self.k2.descriptor().unwrap(),
            plan_genesis(),
            plan_fingerprint(),
        )
    }
    /// The trusted configuration that pins the plan K1 -> K2 on the trusted chain at TRUSTED_HEIGHT.
    pub fn plan_config(&self) -> CeremonyConfig {
        self.config.clone().with_trusted_chain(trusted_chain(TRUSTED_HEIGHT)).unwrap().with_authorized_plan(self.plan().identity().unwrap()).unwrap()
    }
    /// The canonical lineage after the plan K1 -> K2: (records, StateRoot).
    pub fn lineage(&self) -> (Vec<(Hash, Vec<u8>)>, Hash) {
        lineage_state(&self.k1.descriptor().unwrap(), &[self.plan()])
    }
    /// The trusted configuration that names the StateRoot of `lineage()`.
    pub fn lineage_config(&self) -> (CeremonyConfig, Vec<(Hash, Vec<u8>)>) {
        let (records, root) = self.lineage();
        (self.config.clone().with_canonical_root(root).unwrap(), records)
    }
}

/// A complete proof by `signer` under `config` (challenge built by the ceremony layer).
pub fn proof_for(config: &CeremonyConfig, signer: &Credential, nonce: Hash) -> (Vec<u8>, Vec<u8>, HybridSignature) {
    let descriptor = signer.descriptor().unwrap();
    let challenge = r::build_challenge(config, &descriptor, nonce).unwrap();
    let signature = proof::sign_challenge(signer.key(), &descriptor, &challenge).unwrap();
    (descriptor, challenge.encode().unwrap(), signature)
}

/// A proof for an explicitly assembled challenge (internally consistent, signed by `signer`).
pub fn signed(signer: &Credential, challenge: &Challenge) -> (Vec<u8>, Vec<u8>, HybridSignature) {
    let descriptor = signer.descriptor().unwrap();
    let signature = proof::sign_challenge(signer.key(), &descriptor, challenge).unwrap();
    (descriptor, challenge.encode().unwrap(), signature)
}

pub fn file_sha256(path: &std::path::Path) -> Hash {
    Sha256::digest(std::fs::read(path).unwrap()).into()
}
